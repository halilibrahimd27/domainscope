// Unit tests for the discovery-engine-v2 additions to assets/js/lib/scanner.js:
// DNS record mining, the wordlist / permutation / recursive stages, multi-level
// wildcard filtering (NODATA + CNAME), and the origin-hunting hints
// (resolver-leak + same-network → originNetworks / cliSuggestion). No network:
// an emulated authoritative zone sits behind every DoH resolver (optionally a
// different zone per resolver, to model a GeoDNS / split-horizon origin leak),
// and the passive sources are mocked with the real payload shapes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { runScan, SCAN_STAGES, learnedLabelsFromScan, estimateQueries } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { AbortError } from '../../assets/js/lib/util.js';
import { WORDLIST_SMALL, clearWordlistCache, loadWordlist } from '../../assets/js/lib/wordlist.js';
import { readFile } from 'node:fs/promises';

/* ------------------------------------------------------------------------ */
/* Mock world (per-resolver zones supported)                                */
/* ------------------------------------------------------------------------ */

// A fixed, out-of-scope SOA so negative / empty answers never inject synthetic
// in-domain names into the mining step (a real zone's SOA sits at its apex; the
// master name here is deliberately on an unrelated domain).
const OUT_SOA = { mname: 'ns-hidden.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

/** Resolve `name`/`type` against a flat zone map, following CNAMEs and `*.parent` wildcards. */
function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 10; hop += 1) {
    let node = zone[current];
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`) && !k.startsWith('*.'));
      if (!exists && zone[`*.${parent}`]) node = zone[`*.${parent}`];
      else return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: current, type: 'SOA', ttl: 300, data: OUT_SOA }] };
    }
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: current, type: 'CNAME', ttl: 300, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: current, type, ttl: 300, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: current, type: 'SOA', ttl: 300, data: OUT_SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

/**
 * @param {object} opts
 * @param {object} opts.zone base zone served by every resolver
 * @param {Object<string,object>} [opts.zonesByResolver] per-resolver name overrides (merged over base)
 * @param {Object<string,Function>} [opts.sources] mocked source handlers by URL prefix
 * @param {number} [opts.dohDelay] ms delay per DoH answer
 * @param {Function} [opts.answer] (name, type, resolverId) → { rcode, answers } to answer a
 *   query dynamically (a wildcard whose answer varies per label), or undefined for the zone
 */
function mkWorld({ zone, zonesByResolver = {}, sources = {}, dohDelay = 0, answer = null } = {}) {
  const log = { doh: [], http: [] };
  const fetchImpl = async (url, init = {}) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (resolver) {
      const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
      log.doh.push({ name: q.name, type: q.type, resolver: resolver.id });
      if (dohDelay) await new Promise((r) => setTimeout(r, dohDelay));
      const z = zonesByResolver[resolver.id] ? { ...zone, ...zonesByResolver[resolver.id] } : zone;
      const out = (answer && answer(q.name, q.type, resolver.id)) || zoneAnswer(z, q.name, q.type);
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
      }));
    }
    log.http.push(url);
    for (const [prefix, handler] of Object.entries(sources)) {
      if (url.startsWith(prefix)) {
        const out = await handler(url, init);
        return out instanceof Response ? out : Response.json(out);
      }
    }
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

const crtsh = (names, apex) => ({
  'https://crt.sh/': () => [{
    issuer_ca_id: 1, issuer_name: 'C=US, CN=Test CA', common_name: apex,
    name_value: names.join('\n'), id: 1, not_before: '2026-01-01T00:00:00', not_after: '2034-01-01T00:00:00',
    serial_number: 'aa'
  }]
});
const anubis = (names) => ({ 'https://anubisdb.com/': () => names });
const byName = (scan) => new Map(scan.hosts.map((h) => [h.name, h]));

/* ------------------------------------------------------------------------ */

describe('discovery engine v2: stages + wordlist levels', () => {
  test('SCAN_STAGES lists the v2 stages in execution order', () => {
    assert.deepEqual([...SCAN_STAGES], ['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints', 'done']);
  });

  test('wildcard-cert domain: CT gives only *.apex; wordlist finds www/api/app/blog; permutation finds app2', async () => {
    const A = 'example.net';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.14'] },
      [`app.${A}`]: { A: ['203.0.113.12'] },
      [`app2.${A}`]: { A: ['203.0.113.13'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      [`blog.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: crtsh([`*.${A}`], A) });
    const stages = [];
    const scan = await runScan({
      domains: [A], sources: ['crtsh'], bruteforce: 'small', wordlist: ['www', 'api', 'app', 'blog'],
      mine: false, permutationBudget: 200, recursive: false, originHints: true, balance: false, dns, fetchImpl
    }, { onStage: (s) => stages.push(s) });

    assert.deepEqual(stages, [...SCAN_STAGES]);
    const h = byName(scan);
    for (const n of [A, `api.${A}`, `app.${A}`, `www.${A}`, `blog.${A}`, `app2.${A}`]) assert.ok(h.has(n), n);
    assert.ok(h.get(`api.${A}`).origins.includes('wordlist'));
    assert.ok(h.get(`app.${A}`).origins.includes('wordlist'));
    assert.deepEqual(h.get(`app2.${A}`).origins, ['permutation']);
    assert.equal(h.get(`www.${A}`).classification.kind, 'cloudflare');
    assert.equal(h.get(`www.${A}`).classification.hidesOrigin, true);
    assert.equal(h.get(`api.${A}`).classification.kind, 'direct');
    assert.equal(scan.stats.wordlistFound, 4);
    assert.equal(scan.stats.permutationFound, 1);
    assert.equal(scan.stats.bruteforceFound, 4, 'bruteforce* mirrors the wordlist stage');
  });

  test('numbered sibling: a discovered name yields its numbered sibling via permutation', async () => {
    const A = 'example.org';
    const zone = {
      [A]: { A: ['203.0.113.10'] },
      [`shop.${A}`]: { A: ['203.0.113.20'] },
      [`shop2.${A}`]: { A: ['203.0.113.21'] } // the old cert still lives on shop2
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['shop'],
      mine: false, permutationBudget: 300, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.get(`shop.${A}`).origins.includes('wordlist'));
    assert.deepEqual(h.get(`shop2.${A}`).origins, ['permutation']);
    assert.equal(scan.stats.permutationFound, 1);
    assert.ok(scan.stats.permutationTried > 0);
  });

  test('custom wordlist overrides the level and is the only thing tried', async () => {
    const A = 'custom.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`foo.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'smart', wordlist: ['foo', 'bar'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.stats.bruteforceTried, 2, 'only foo + bar under the apex');
    assert.ok(byName(scan).get(`foo.${A}`).origins.includes('wordlist'));
    assert.ok(!byName(scan).has(`bar.${A}`), 'bar does not resolve');
  });

  test('permutations disabled: the permutations stage is skipped and finds nothing', async () => {
    const A = 'noperm.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] }, [`api2.${A}`]: { A: ['203.0.113.3'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const stages = [];
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    }, { onStage: (s, info) => stages.push([s, info.skipped]) });
    assert.deepEqual(stages.find((s) => s[0] === 'permutations'), ['permutations', true]);
    assert.equal(scan.stats.permutationFound, 0);
    assert.equal(scan.stats.recursiveFound, 0);
    assert.ok(!byName(scan).has(`api2.${A}`), 'no permutation ran, so api2 stays hidden');
  });

  test('bulk sweep raises the client concurrency for the probe stages and restores it', async () => {
    const A = 'sweep.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const before = dns.concurrency; // real DohClient default (12)
    const seen = [];
    const raw = dns.setConcurrency.bind(dns);
    let duringBruteforce = null;
    dns.setConcurrency = (n) => { seen.push(n); raw(n); };
    await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'admin'],
      mine: false, permutationBudget: 300, recursive: true, originHints: false, balance: true, dns, fetchImpl
    }, { onStage: (s) => { if (s === 'bruteforce') duringBruteforce = dns.concurrency; } });
    assert.ok(before < 24, `default client concurrency ${before} is below the sweep level`);
    assert.equal(duringBruteforce, 24, 'concurrency raised to PROBE_CONCURRENCY during the sweep');
    assert.ok(seen.includes(24) && seen[seen.length - 1] === before, 'raised then restored');
    assert.equal(dns.concurrency, before, 'client concurrency restored after the scan');
  });

  test('bulk sweep restores the client concurrency even when the scan aborts', async () => {
    const A = 'sweepabort.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns } = mkWorld({ zone, dohDelay: 20 });
    const before = dns.concurrency;
    const ctl = new AbortController();
    const p = runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'admin', 'panel'],
      mine: false, permutationBudget: 300, recursive: false, originHints: false, balance: true,
      dns, fetchImpl, signal: ctl.signal
    }, { onStage: (s) => { if (s === 'bruteforce') setTimeout(() => ctl.abort(), 5); } });
    await assert.rejects(p, (e) => e instanceof AbortError);
    assert.equal(dns.concurrency, before, 'concurrency restored despite the abort');
  });
});

describe('discovery engine v2: DNS record mining', () => {
  test('mines MX / NS / SPF hosts from the zone and tags their origin dns-mine:<record>', async () => {
    const A = 'mine.example';
    const zone = {
      [A]: {
        A: ['203.0.113.1'],
        MX: [{ preference: 10, exchange: `mail.${A}` }],
        NS: [`ns1.${A}`, `ns2.${A}`],
        TXT: [[`v=spf1 a:vpn.${A} ip4:203.0.113.9 -all`]]
      },
      [`mail.${A}`]: { A: ['203.0.113.2'] },
      [`ns1.${A}`]: { A: ['203.0.113.3'] },
      [`ns2.${A}`]: { A: ['203.0.113.4'] },
      [`vpn.${A}`]: { A: ['203.0.113.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'off', mine: true, permutationBudget: 0, recursive: false,
      originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.get(`mail.${A}`).origins.includes('dns-mine:MX'));
    assert.ok(h.get(`ns1.${A}`).origins.includes('dns-mine:NS'));
    assert.ok(h.get(`vpn.${A}`).origins.includes('dns-mine:SPF'));
    assert.ok(scan.stats.mineFound >= 4);
    assert.ok(scan.stats.fromDns >= 4);
    assert.ok(scan.mineEvidence.some((e) => e.name === `mail.${A}` && e.from === 'MX'));
  });

  test('a hosted-DMARC CNAME (TXT-only target) is not a host, so no false dangling alert', async () => {
    const A = 'mine.example';
    const vendor = `${A}._d.dmarcvendor.example`;
    const zone = {
      [A]: { A: ['203.0.113.1'], TXT: [[`v=spf1 include:_spf.${A} -all`]] },
      [`_dmarc.${A}`]: { CNAME: vendor },
      [vendor]: { TXT: [['v=DMARC1; p=reject']] },
      [`_spf.${A}`]: { TXT: [['v=spf1 ip4:203.0.113.9 -all']] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'off', mine: true, permutationBudget: 0, recursive: false,
      originHints: false, balance: false, dns, fetchImpl
    });
    const serviceLabel = (n) => n.split('.').some((l) => l.startsWith('_'));
    assert.deepEqual(scan.hosts.filter((x) => serviceLabel(x.name)).map((x) => x.name), []);
    assert.ok(scan.hosts.every((x) => !x.classification.dangling));
    assert.equal(scan.stats.dangling, 0);
  });
});

describe('discovery engine v2: multi-level wildcard filtering', () => {
  test('NODATA wildcard at a sub-level: real child kept, empty child flagged, guesses not invented', async () => {
    const A = 'example.com';
    const SUB = `int.${A}`;
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [SUB]: { A: ['203.0.113.2'] },
      [`*.${SUB}`]: {}, // any label under int.* answers NOERROR-empty (NODATA)
      [`api.${SUB}`]: { A: ['10.0.0.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`api.${SUB}`, `ghost.${SUB}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: true,
      originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.wildcards[SUB].kind, 'NODATA');
    assert.equal(scan.wildcards[SUB].wildcard, true);
    const h = byName(scan);
    assert.equal(h.get(`api.${SUB}`).wildcardSuspect, false);
    assert.equal(h.get(`ghost.${SUB}`).wildcardSuspect, true, 'the empty passive name is a wildcard look-alike');
    // the recursive round under the NODATA sub-level invents no false hits
    assert.equal(scan.stats.recursiveFound, 0);
  });

  test('CNAME wildcard at a sub-level: look-alikes flagged, a distinct answer kept', async () => {
    const A = 'cn.example';
    const SUB = `svc.${A}`;
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`*.${SUB}`]: { CNAME: 'edge.fastly.net' },
      'edge.fastly.net': { A: ['151.101.1.1'] },
      [`real.${SUB}`]: { A: ['192.0.2.50'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`real.${SUB}`, `app.${SUB}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false,
      originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.wildcards[SUB].kind, 'CNAME');
    assert.deepEqual(scan.wildcards[SUB].cnames, ['edge.fastly.net']);
    const h = byName(scan);
    assert.equal(h.get(`app.${SUB}`).wildcardSuspect, true);
    assert.equal(h.get(`real.${SUB}`).wildcardSuspect, false);
  });
});

describe('discovery engine v2: recursive round', () => {
  test('a discovered parent with children is swept with the small wordlist', async () => {
    const A = 'example.com';
    const SUB = `svc.${A}`;
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [SUB]: { A: ['203.0.113.2'] },
      [`api.${SUB}`]: { A: ['203.0.113.3'] },
      [`www.${SUB}`]: { A: ['203.0.113.4'] } // found only by the recursive small-wordlist round
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([SUB, `api.${SUB}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: true,
      recursiveParents: 8, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.has(`www.${SUB}`), 'recursive round found www.svc');
    assert.deepEqual(h.get(`www.${SUB}`).origins, ['recursive']);
    assert.equal(scan.stats.recursiveFound, 1);
    assert.ok(scan.stats.recursiveTried > 0);
  });
});

describe('discovery engine v2: origin hints', () => {
  test('resolver-leak: a proxied host that leaks its origin on another resolver becomes a hint', async () => {
    const A = 'web.example';
    const zone = {
      [A]: { A: ['203.0.113.5'] }, // the apex points straight at the origin /24
      [`app.${A}`]: { CNAME: 'edge.cdn.cloudflare.net' },
      'edge.cdn.cloudflare.net': { A: ['104.16.9.9'] }
    };
    // On the "google" resolver the name leaks its real origin (203.0.113.77).
    const zonesByResolver = { google: { [`app.${A}`]: { A: ['203.0.113.77'] } } };
    const { fetchImpl, dns } = mkWorld({ zone, zonesByResolver });
    const scan = await runScan({
      domains: [A], extraNames: [`app.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: true, balance: false, dns, fetchImpl
    });
    assert.equal(byName(scan).get(`app.${A}`).classification.hidesOrigin, true);
    const leak = scan.originHints.find((x) => x.ip === '203.0.113.77');
    assert.ok(leak, 'the leaked origin is an origin hint');
    assert.ok(leak.reasons.some((r) => r.kind === 'resolver-leak'));
    assert.deepEqual(leak.hosts, [`app.${A}`]);
    // and it seeds an origin network + a ready-to-run CLI command
    assert.ok(scan.originNetworks.some((n) => n.cidr === '203.0.113.0/24'));
    assert.equal(scan.cliSuggestion, `python3 cli/ssl_origin_scan.py -t 203.0.113.0/24 -n app.${A}`);
    assert.deepEqual(byName(scan).get(`app.${A}`).candidateNetworks, ['203.0.113.0/24']);
  });

  test('resolverLeak disabled: proxied hosts are not re-resolved through other resolvers', async () => {
    const A = 'web.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`app.${A}`]: { CNAME: 'edge.cdn.cloudflare.net' },
      'edge.cdn.cloudflare.net': { A: ['104.16.9.9'] }
    };
    const zonesByResolver = { google: { [`app.${A}`]: { A: ['203.0.113.77'] } } };
    const { fetchImpl, dns, log } = mkWorld({ zone, zonesByResolver });
    const scan = await runScan({
      domains: [A], extraNames: [`app.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.ok(!scan.originHints.some((x) => x.ip === '203.0.113.77'), 'no leaked origin hint');
    const others = log.doh.filter((q) => q.name === `app.${A}` && q.resolver !== 'cloudflare');
    assert.deepEqual(others, [], 'the proxied host was never re-resolved through another resolver');
  });

  test('wildcard suspects are no origin evidence: no leak queries, no network, not in the CLI names', async () => {
    const A = 'wild.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`*.${A}`]: { CNAME: 'edge.cdn.cloudflare.net' }, // every unknown label is proxied
      'edge.cdn.cloudflare.net': { A: ['104.16.9.9'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' }, // a real proxied host (distinct answer)
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] },
      [`dev.${A}`]: { A: ['203.0.113.3'] },
      [`*.dev.${A}`]: { A: ['198.51.100.50'] } // a direct wildcard one level down
    };
    // Were the suspect re-resolved elsewhere, this resolver would "leak" an origin for it.
    const zonesByResolver = { google: { [`ghost.${A}`]: { A: ['198.51.100.77'] } } };
    const { fetchImpl, dns, log } = mkWorld({ zone, zonesByResolver, sources: anubis([`ghost.${A}`, `www.${A}`, `dev.${A}`, `x.dev.${A}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false,
      originHints: true, resolverLeak: true, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.equal(h.get(`ghost.${A}`).wildcardSuspect, true);
    assert.equal(h.get(`ghost.${A}`).classification.hidesOrigin, true);
    assert.equal(h.get(`x.dev.${A}`).wildcardSuspect, true);
    assert.equal(h.get(`www.${A}`).wildcardSuspect, false);
    assert.deepEqual(log.doh.filter((q) => q.name === `ghost.${A}` && q.resolver !== 'cloudflare'), [], 'no resolver-leak query for the suspect');
    assert.ok(!scan.originHints.some((x) => x.ip === '198.51.100.77'), 'no leaked origin for the suspect');
    assert.deepEqual(scan.originNetworks.map((n) => n.cidr), ['203.0.113.0/24'], 'the direct wildcard target is not an origin network');
    assert.deepEqual(h.get(`ghost.${A}`).candidateNetworks, []);
    assert.deepEqual(h.get(`www.${A}`).candidateNetworks, ['203.0.113.0/24']);
    assert.equal(scan.cliSuggestion, `python3 cli/ssl_origin_scan.py -t 203.0.113.0/24 -n www.${A}`);
  });

  test('same-network: direct hosts cluster into origin /24 blocks with a CLI sweep command', async () => {
    const A = 'sn.example';
    const zone = {
      [A]: { A: ['198.51.100.5'] },
      [`api.${A}`]: { A: ['198.51.100.6'] },
      [`app.${A}`]: { A: ['198.51.100.7'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`www.${A}`], sources: [], bruteforce: 'small', wordlist: ['api', 'app'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.originNetworks.length, 1);
    const net = scan.originNetworks[0];
    assert.equal(net.cidr, '198.51.100.0/24');
    assert.deepEqual(net.ips, ['198.51.100.5', '198.51.100.6', '198.51.100.7']);
    assert.deepEqual(net.hosts, [A, `api.${A}`, `app.${A}`]);
    assert.deepEqual(byName(scan).get(`www.${A}`).candidateNetworks, ['198.51.100.0/24']);
    assert.equal(scan.cliSuggestion, `python3 cli/ssl_origin_scan.py -t 198.51.100.0/24 -n www.${A}`);
  });

  test('no proxied hosts: no candidate networks are attached and there is no CLI suggestion', async () => {
    const A = 'plain.example';
    const zone = { [A]: { A: ['198.51.100.5'] }, [`api.${A}`]: { A: ['198.51.100.6'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'], mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.cliSuggestion, null);
    assert.ok(scan.hosts.every((x) => x.candidateNetworks.length === 0));
  });
});

describe('discovery engine v2: per-technique stats', () => {
  test('byTechnique-style counts add up across sources, mining, wordlist, permutation, recursive', async () => {
    const A = 'stats.example';
    const SUB = `svc.${A}`;
    const zone = {
      [A]: { A: ['203.0.113.1'], MX: [{ preference: 10, exchange: `mail.${A}` }] },
      [`mail.${A}`]: { A: ['203.0.113.2'] },
      [`api.${A}`]: { A: ['203.0.113.3'] },
      [`api2.${A}`]: { A: ['203.0.113.4'] }, // permutation of api
      [SUB]: { A: ['203.0.113.5'] },
      [`x.${SUB}`]: { A: ['203.0.113.6'] },
      [`www.${SUB}`]: { A: ['203.0.113.7'] } // recursive under svc
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([SUB, `x.${SUB}`]) });
    const scan = await runScan({
      // 'www' rides in the wordlist so the recursive round (which reuses a custom
      // wordlist) can find www.svc one level down.
      domains: [A], sources: ['anubis'], bruteforce: 'small', wordlist: ['api', 'www'],
      mine: true, permutationBudget: 300, recursive: true, recursiveParents: 8,
      originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.get(`mail.${A}`).origins.includes('dns-mine:MX'));
    assert.ok(h.get(`api.${A}`).origins.includes('wordlist'));
    assert.deepEqual(h.get(`api2.${A}`).origins, ['permutation']);
    assert.deepEqual(h.get(`www.${SUB}`).origins, ['recursive']);
    assert.ok(scan.stats.fromSources >= 2, 'svc + x.svc from anubis');
    assert.equal(scan.stats.mineFound >= 1, true);
    assert.equal(scan.stats.wordlistFound, 1);
    assert.equal(scan.stats.permutationFound, 1);
    assert.equal(scan.stats.recursiveFound, 1);
    assert.ok(scan.stats.fromDns >= 4);
  });
});

describe('discovery engine v2: origin-hint correctness (v2 fixes)', () => {
  test('resolver-leak: a CNAME-only CDN (Akamai) with a different edge IP per resolver is NOT a false origin', async () => {
    const A = 'example.net';
    const zone = {
      [A]: { A: ['203.0.113.5'] }, // a real direct origin so there IS one network
      [`www.${A}`]: { CNAME: `www.${A}.edgekey.net` },
      [`www.${A}.edgekey.net`]: { CNAME: 'e1234.a.akamaiedge.net' },
      'e1234.a.akamaiedge.net': { A: ['23.50.1.1'] } // cloudflare (default) edge
    };
    // GeoDNS / ECS: every resolver returns a different Akamai edge address.
    const zonesByResolver = {
      google: { 'e1234.a.akamaiedge.net': { A: ['23.60.77.88'] } },
      dnssb: { 'e1234.a.akamaiedge.net': { A: ['2.16.40.9'] } },
      cznic: { 'e1234.a.akamaiedge.net': { A: ['96.7.8.9'] } }
    };
    const { fetchImpl, dns } = mkWorld({ zone, zonesByResolver });
    const scan = await runScan({
      domains: [A], extraNames: [`www.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: true, balance: false, dns, fetchImpl
    });
    assert.equal(byName(scan).get(`www.${A}`).classification.hidesOrigin, true);
    assert.ok(!scan.originHints.some((x) => x.reasons.some((r) => r.kind === 'resolver-leak')), 'no resolver-leak hint for a CNAME CDN');
    // the edge /24s must not appear as origin networks
    for (const bad of ['23.60.77.0/24', '2.16.40.0/24', '96.7.8.0/24', '23.50.1.0/24']) {
      assert.ok(!scan.originNetworks.some((n) => n.cidr === bad), `edge network ${bad} leaked`);
    }
    assert.deepEqual(scan.originNetworks.map((n) => n.cidr), ['203.0.113.0/24']);
    assert.ok(!/23\.60\.77|2\.16\.40|96\.7\.8|23\.50\.1/.test(scan.cliSuggestion || ''), 'no edge network in the CLI command');
  });

  test('cliSuggestion never contains an IPv6 /48 (ssl_origin_scan.py rejects it); the exact address is used', async () => {
    const A = 'dual.example';
    const zone = {
      [A]: { A: ['203.0.113.1'], AAAA: ['2001:db8:1234::1'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`www.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    // the /48 is kept as display-only context
    assert.ok(scan.originNetworks.some((n) => n.cidr === '2001:db8:1234::/48'));
    const targets = (scan.cliSuggestion.match(/-t\s+(.*?)\s+-n/)[1]).split(/\s+/);
    assert.ok(!targets.some((t) => t.includes('/48')), `no /48 in ${scan.cliSuggestion}`);
    assert.ok(targets.includes('2001:db8:1234::1'), 'the exact IPv6 origin is swept instead');
    // no CIDR token larger than a /24 (2^8) for v4 or a single IP for v6
    for (const t of targets) {
      if (t.includes('/')) assert.ok(/\/(2[4-9]|3[0-2]|1[0-2][0-9])$/.test(t), `token ${t} too large`);
    }
  });

  test('same-network: an in-zone name that CNAMEs out to third-party SaaS is not treated as an origin', async () => {
    const A = 'm365.example';
    const zone = {
      [A]: { A: ['198.51.100.5'] },
      [`autodiscover.${A}`]: { CNAME: 'autodiscover.outlook.com' },
      'autodiscover.outlook.com': { A: ['52.97.1.10', '52.98.2.20'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`autodiscover.${A}`, `www.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    // autodiscover resolves and is classed direct, but its answer leaves the zone
    assert.equal(byName(scan).get(`autodiscover.${A}`).classification.kind, 'direct');
    assert.deepEqual(scan.originNetworks.map((n) => n.cidr), ['198.51.100.0/24']);
    assert.ok(!/52\.97|52\.98/.test(scan.cliSuggestion || ''), 'no Microsoft /24 in the CLI command');
    assert.ok(!scan.originHints.some((x) => x.ip === '52.97.1.10' || x.ip === '52.98.2.20'), 'no third-party sibling hint');
  });

  test('a single direct origin with no inventory is swept as an exact IP, not a whole /24', async () => {
    const A = 'solo.example';
    const zone = {
      [A]: { A: ['203.0.113.10'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`www.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.deepEqual(scan.originNetworks.map((n) => n.cidr), ['203.0.113.0/24']); // /24 kept for display
    assert.equal(scan.cliSuggestion, `python3 cli/ssl_origin_scan.py -t 203.0.113.10 -n www.${A}`);
  });
});

describe('discovery engine v2: permutation wildcard safety + compact denial', () => {
  test('a per-host wildcard (*.api) under a found parent yields no false permutation hits (recursive off)', async () => {
    const A = 'example.net';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`*.api.${A}`]: { A: ['203.0.113.99'] } // every dev.api / us.api-style (prefix) insertion resolves here
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'www'],
      mine: false, permutationBudget: 1500, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.stats.permutationFound, 0, 'level-insertion permutations under *.api are wildcard-dropped');
    assert.ok(!scan.hosts.some((h) => h.origins.includes('permutation') && h.name.endsWith(`.api.${A}`)));
    assert.equal(scan.wildcards[`api.${A}`] && scan.wildcards[`api.${A}`].wildcard, true, 'the found parent was wildcard-checked');
  });

  test('environment wildcards (*.staging, *.dev) do not turn suffix level-insertions (api.staging) into permutation hits', async () => {
    const A = 'example.org';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`shop.${A}`]: { A: ['203.0.113.3'] },
      [`*.staging.${A}`]: { A: ['198.51.100.77'] },
      [`*.dev.${A}`]: { CNAME: 'dev-lb.example-hosting.net' },
      'dev-lb.example-hosting.net': { A: ['192.0.2.55'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`api.${A}`, `shop.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 1500, recursive: false, originHints: true, balance: false, dns, fetchImpl
    });
    assert.equal(scan.stats.permutationFound, 0);
    assert.ok(!scan.hosts.some((h) => h.name.endsWith(`.staging.${A}`) || h.name.endsWith(`.dev.${A}`)),
      scan.hosts.map((h) => h.name).join(', '));
    assert.equal(scan.wildcards[`staging.${A}`].wildcard, true);
    assert.equal(scan.wildcards[`staging.${A}`].kind, 'A');
    assert.equal(scan.wildcards[`dev.${A}`].kind, 'CNAME');
    assert.ok(scan.stats.permutationWildcardDropped >= 4, String(scan.stats.permutationWildcardDropped));
    assert.ok(!scan.originNetworks.some((n) => n.cidr === '198.51.100.0/24'));
  });

  test('DNSSEC compact denial (Cloudflare) is not a wildcard and does not flag typed NXDOMAIN-equivalent names', async () => {
    const A = 'cf.example';
    const zone = { [A]: { A: ['203.0.113.1'] } };
    const fetchImpl = async (url) => {
      const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
      if (!resolver) throw new TypeError(`unexpected URL ${url}`);
      const msg = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns')));
      const q = msg.questions[0];
      const dnssec = !!(msg.edns && msg.edns.dnssecOk);
      let answers = [];
      let authorities;
      if (zone[q.name]) {
        answers = (zone[q.name][q.type] || []).map((d) => ({ name: q.name, type: q.type, ttl: 300, data: d }));
        authorities = [];
      } else {
        // compact denial of existence: NOERROR-empty, DNSSEC proves non-existence with NXNAME
        authorities = dnssec
          ? [{ name: q.name, type: 'NSEC', ttl: 300, data: { nextDomain: `\\000.${q.name}`, types: ['RRSIG', 'NSEC', 'NXNAME'] } }]
          : [{ name: q.name, type: 'SOA', ttl: 300, data: OUT_SOA }];
      }
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: 'NOERROR',
        questions: [{ name: q.name, type: q.type }], answers, authorities, edns: {}
      }));
    };
    const dns = new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 });
    const scan = await runScan({
      domains: [A], extraNames: [`gone.${A}`, `old.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.wildcards[A].wildcard, false, 'compact denial is not reported as a wildcard');
    assert.equal(scan.stats.wildcardParents, 0);
    const h = byName(scan);
    assert.equal(h.get(`gone.${A}`).wildcardSuspect, false, 'a typed non-existent name is not a wildcard suspect');
    assert.equal(h.get(`old.${A}`).wildcardSuspect, false);
  });
});

describe('discovery engine v2: sources do not block the DNS sweep', () => {
  test('the wildcard/brute-force sweep starts before a slow source settles, and late names are still merged', async () => {
    const A = 'slow.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`late.${A}`]: { A: ['203.0.113.3'] } // only the slow source reports this
    };
    let anubisResolvedAt = 0;
    let bruteforceAt = 0;
    const sources = {
      'https://anubisdb.com/': () => new Promise((resolve) => {
        setTimeout(() => { anubisResolvedAt = Date.now(); resolve([`late.${A}`]); }, 300);
      })
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'small', wordlist: ['api'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false,
      sourceGraceMs: 15, dns, fetchImpl
    }, { onStage: (s) => { if (s === 'bruteforce' && !bruteforceAt) bruteforceAt = Date.now(); } });
    assert.ok(bruteforceAt > 0 && anubisResolvedAt > 0, 'both events happened');
    assert.ok(bruteforceAt < anubisResolvedAt, `bruteforce (${bruteforceAt}) started before the slow source settled (${anubisResolvedAt})`);
    const h = byName(scan);
    assert.ok(h.has(`api.${A}`), 'wordlist hit found during the grace window');
    assert.ok(h.has(`late.${A}`), 'the late source name was merged before resolve');
  });
});

describe('discovery engine v2: dead resolver pool fails fast', () => {
  test('after a long failure streak the bulk stages stop and a DNS_UNREACHABLE warning is pushed', async () => {
    const A = 'dead.example';
    // Every DoH request throws (blocked DoH / offline).
    let calls = 0;
    const fetchImpl = async (url) => {
      const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
      if (resolver) { calls += 1; throw new TypeError('Failed to fetch'); }
      throw new TypeError(`unexpected URL ${url}`);
    };
    const dns = new DohClient({ fetchImpl, baseDelayMs: 0, maxDelayMs: 1, retries: 0, timeoutMs: 50 });
    const words = Array.from({ length: 120 }, (_, i) => `h${i}`);
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: words,
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.ok(scan.warnings.some((w) => w.code === 'DNS_UNREACHABLE'), 'the dead pool is reported');
    // The sweep stopped early instead of probing all 120 candidates.
    assert.ok(scan.stats.bruteforceErrors < 120, `stopped early (${scan.stats.bruteforceErrors} errors)`);
  });
});

describe('discovery engine v2: passive sources are throttled across domains', () => {
  test('at most a couple of domains hit the quota-limited sources at once', async () => {
    const domains = Array.from({ length: 6 }, (_, i) => `ex${i}.example`);
    const zone = {};
    for (const d of domains) zone[d] = { A: ['203.0.113.1'] };
    let active = 0;
    let maxActive = 0;
    const sources = {
      'https://anubisdb.com/': async () => {
        active += 1; maxActive = Math.max(maxActive, active);
        await new Promise((r) => setTimeout(r, 20));
        active -= 1;
        return [];
      }
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources });
    await runScan({
      domains, sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0,
      recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.ok(maxActive <= 2, `expected ≤ 2 domains querying sources at once, saw ${maxActive}`);
  });
});

describe('discovery engine v2: cancellation on the new stages', () => {
  for (const stageName of ['mining', 'permutations']) {
    test(`aborting during "${stageName}" rejects promptly with AbortError`, async () => {
      const A = 'abort.example';
      const zone = {
        [A]: { A: ['203.0.113.1'], MX: [{ preference: 10, exchange: `mail.${A}` }], NS: [`ns1.${A}`] },
        [`mail.${A}`]: { A: ['203.0.113.2'] },
        [`ns1.${A}`]: { A: ['203.0.113.3'] },
        [`api.${A}`]: { A: ['203.0.113.4'] }
      };
      const { fetchImpl, dns } = mkWorld({ zone, dohDelay: 20 });
      const ctl = new AbortController();
      let abortedAt = 0;
      const p = runScan({
        domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'],
        mine: true, permutationBudget: 300, recursive: false, originHints: false, balance: false,
        dns, fetchImpl, signal: ctl.signal
      }, {
        onStage: (s) => { if (s === stageName) setTimeout(() => { abortedAt = Date.now(); ctl.abort(); }, 5); }
      });
      await assert.rejects(p, (e) => e instanceof AbortError);
      assert.ok(abortedAt > 0, 'the stage was reached');
      assert.ok(Date.now() - abortedAt < 1000, `prompt (${Date.now() - abortedAt} ms)`);
    });
  }
});

/* ------------------------------------------------------------------------ */
/* Wordlist wiring: levels, locale packs, custom / learned labels           */
/* ------------------------------------------------------------------------ */

// Every DoH request throws, so the bulk sweep fails fast (DNS_UNREACHABLE)
// after PROBE_DEAD_STREAK. Lets a real level's list be BUILT (proving the size /
// locale wiring) without probing thousands of candidates against a mock.
function deadWorld() {
  const fetchImpl = async (url) => {
    if (RESOLVERS.some((r) => url.startsWith(`${r.url}?`))) throw new TypeError('Failed to fetch');
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, dns: new DohClient({ fetchImpl, baseDelayMs: 0, maxDelayMs: 1, retries: 0, timeoutMs: 40 }) };
}

describe('discovery engine v2: wordlist wiring', () => {
  test('custom labels are tried before learned; both are attributed in options.wordlist', async () => {
    const A = 'attr.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`billing.${A}`]: { A: ['203.0.113.2'] }, // a custom-label hit
      [`legacy.${A}`]: { A: ['203.0.113.3'] }   // a learned-label hit
    };
    const { fetchImpl, dns, log } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small',
      customWordlist: ['billing', 'zzzznope'], learnedLabels: ['legacy', 'billing'],
      // one query in flight at a time: the probes start in list order, so the log shows the order
      maxConcurrency: 1,
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.deepEqual(h.get(`billing.${A}`).origins, ['wordlist']);
    assert.deepEqual(h.get(`legacy.${A}`).origins, ['wordlist']);
    // Order of the first A query per name: custom (billing, zzzznope), then learned (legacy),
    // then the level's own list — a per-domain cap must cut the list's tail, never the custom labels.
    const firstA = (label) => log.doh.findIndex((q) => q.type === 'A' && q.name === `${label}.${A}`);
    const firstListLabel = WORDLIST_SMALL.find((l) => !['billing', 'zzzznope', 'legacy'].includes(l));
    assert.ok(firstA('billing') >= 0 && firstA('zzzznope') >= 0 && firstA('legacy') >= 0 && firstA(firstListLabel) >= 0);
    assert.ok(firstA('billing') < firstA('legacy'), 'a custom label is probed before a learned one');
    assert.ok(firstA('zzzznope') < firstA('legacy'), 'every custom label is probed before a learned one');
    assert.ok(firstA('legacy') < firstA(firstListLabel), `a learned label is probed before the list (${firstListLabel})`);
    const wl = scan.options.wordlist;
    assert.equal(wl.level, 'small');
    assert.equal(wl.customTried, 2);
    assert.equal(wl.learnedTried, 1, 'a learned label already in custom is not double-counted');
    assert.equal(wl.customFound, 1);
    assert.equal(wl.learnedFound, 1);
    assert.deepEqual(wl.localePacks, [], 'the small level uses no locale packs');
    assert.equal(wl.perDomain[0].domain, A);
    assert.equal(wl.perDomain[0].customTried, 2);
  });

  test('config.wordlist (legacy) replaces the list — custom / learned are ignored', async () => {
    const A = 'legacy.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] }, [`billing.${A}`]: { A: ['203.0.113.3'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'],
      customWordlist: ['billing'], learnedLabels: ['legacy'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.stats.bruteforceTried, 1, 'only the override label is tried');
    assert.ok(byName(scan).has(`api.${A}`));
    assert.ok(!byName(scan).has(`billing.${A}`), 'the custom label is not tried under an override');
    assert.equal(scan.options.wordlist.customTried, 0);
    assert.equal(scan.options.wordlist.learnedTried, 0);
  });

  test('locale packs auto-select from the TLD (smart level, dead pool)', async () => {
    const { fetchImpl, dns } = deadWorld();
    const scan = await runScan({
      domains: ['example.com.tr'], sources: [], bruteforce: 'smart',
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.options.wordlist.level, 'smart');
    assert.deepEqual(scan.options.wordlist.localePacks, ['tr']);
    assert.deepEqual(scan.options.wordlist.perDomain[0].locales, ['tr']);
    // what was really BUILT, not what the config asked for: the smart base plus the tr pack
    const withPack = await loadWordlist('smart', { domain: 'example.com.tr' });
    const baseOnly = await loadWordlist('smart', {});
    assert.ok(withPack.length > baseOnly.length, 'the tr pack adds labels to the smart base');
    assert.equal(scan.options.wordlist.perDomain[0].words, withPack.length, 'the smart base + tr pack were built');
    assert.ok(scan.warnings.some((w) => w.code === 'DNS_UNREACHABLE'));
  });

  test('a label only the auto-selected locale pack has is probed and found; locales: [] never tries it', async () => {
    const A = 'example.com.tr';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`yonetimpanel.${A}`]: { A: ['203.0.113.2'] } };
    assert.ok(!(await loadWordlist('smart', {})).includes('yonetimpanel'), 'precondition: not in the global smart list');
    const run = (extra) => {
      const { fetchImpl, dns } = mkWorld({ zone });
      return runScan({
        domains: [A], sources: [], bruteforce: 'smart', ...extra,
        mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
      });
    };
    const auto = await run({});
    assert.deepEqual(byName(auto).get(`yonetimpanel.${A}`)?.origins, ['wordlist'], 'found through the tr pack');
    const none = await run({ locales: [] });
    assert.ok(!byName(none).has(`yonetimpanel.${A}`), 'no pack, no pack-only label');
  });

  test('locales: [] disables packs; an explicit list forces exactly those (unknown codes dropped)', async () => {
    {
      const { fetchImpl, dns } = deadWorld();
      const scan = await runScan({
        domains: ['example.com.tr'], sources: [], bruteforce: 'smart', locales: [],
        mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
      });
      assert.deepEqual(scan.options.wordlist.localePacks, []);
      assert.equal(scan.options.wordlist.perDomain[0].words, (await loadWordlist('smart', {})).length, 'the smart base only');
    }
    {
      const { fetchImpl, dns } = deadWorld();
      const scan = await runScan({
        domains: ['example.net'], sources: [], bruteforce: 'smart', locales: ['de', 'xx'],
        mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
      });
      assert.deepEqual(scan.options.wordlist.localePacks, ['de']);
      const withDe = await loadWordlist('smart', { domain: 'example.net', locales: ['de'] });
      assert.ok(withDe.length > (await loadWordlist('smart', {})).length);
      assert.equal(scan.options.wordlist.perDomain[0].words, withDe.length, 'the smart base + de pack were built');
    }
  });

  test('the huge level (~130k) is reachable for a single apex', async () => {
    const { fetchImpl, dns } = deadWorld();
    const scan = await runScan({
      domains: ['example.net'], sources: [], bruteforce: 'huge', locales: [],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.options.wordlist.level, 'huge');
    assert.ok(scan.stats.bruteforceTried > 120000, `huge reachable per apex (${scan.stats.bruteforceTried})`);
  });

  test('permutations seed from the learned / custom vocabulary (learned only when a level is on)', async () => {
    const A = 'perm.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`billingz.${A}`]: { A: ['203.0.113.3'] },   // only a sibling-swap of api → billingz reaches it
      [`api.svc.${A}`]: { A: ['203.0.113.4'] },
      [`billingz.svc.${A}`]: { A: ['203.0.113.5'] } // a swap one level down (the brute force never probes it)
    };
    const opts = {
      domains: [A], extraNames: [`api.${A}`], sources: [], bruteforce: 'off',
      mine: false, permutationBudget: 1500, recursive: false, originHints: false, balance: false
    };
    const w1 = mkWorld({ zone });
    const withCustom = await runScan({ ...opts, customWordlist: ['billingz'], dns: w1.dns, fetchImpl: w1.fetchImpl });
    assert.ok(byName(withCustom).has(`billingz.${A}`), 'this scan’s custom label enables the api → billingz swap, even at off');
    assert.deepEqual(byName(withCustom).get(`billingz.${A}`).origins, ['permutation']);

    const w2 = mkWorld({ zone });
    const learnedOff = await runScan({ ...opts, learnedLabels: ['billingz'], dns: w2.dns, fetchImpl: w2.fetchImpl });
    assert.ok(!byName(learnedOff).has(`billingz.${A}`), 'learned labels are never sent at level off');

    const w3 = mkWorld({ zone });
    const learnedOn = await runScan({
      ...opts, bruteforce: 'small', extraNames: [`api.svc.${A}`], learnedLabels: ['billingz'], dns: w3.dns, fetchImpl: w3.fetchImpl
    });
    assert.deepEqual(byName(learnedOn).get(`billingz.svc.${A}`)?.origins, ['permutation'], 'the learned label seeds a swap one level down');

    const w4 = mkWorld({ zone });
    const without = await runScan({ ...opts, bruteforce: 'small', extraNames: [`api.svc.${A}`], dns: w4.dns, fetchImpl: w4.fetchImpl });
    assert.ok(!byName(without).has(`billingz.svc.${A}`), 'without the learned label billingz is never generated');
  });
});

describe('discovery engine v2: maxConcurrency ceiling', () => {
  test('the sweep raise is capped at min(PROBE_CONCURRENCY, maxConcurrency)', async () => {
    const A = 'mc.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const before = dns.concurrency; // 12
    let during = null;
    await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'admin', 'panel'],
      mine: false, permutationBudget: 200, recursive: false, originHints: false, balance: true,
      maxConcurrency: 16, dns, fetchImpl
    }, { onStage: (s) => { if (s === 'bruteforce') during = dns.concurrency; } });
    assert.equal(during, 16, 'raised to the ceiling, not the full PROBE_CONCURRENCY (24)');
    assert.equal(dns.concurrency, before, 'restored afterwards');
  });

  test('maxConcurrency below the client concurrency prevents any raise', async () => {
    const A = 'mc2.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`api.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns } = mkWorld({ zone });
    const before = dns.concurrency; // 12
    let during = null;
    await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'admin'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: true,
      maxConcurrency: 8, dns, fetchImpl
    }, { onStage: (s) => { if (s === 'bruteforce') during = dns.concurrency; } });
    assert.equal(during, before, 'the ceiling (8) is below the client limit (12): no raise');
  });
});

describe('discovery engine v2: learnedLabelsFromScan', () => {
  test('returns left-most labels of resolving, non-wildcard hosts — never full names or IPs', async () => {
    const A = 'learn.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`dev.api.${A}`]: { A: ['203.0.113.3'] },
      [`*.wild.${A}`]: { A: ['203.0.113.9'] },   // wildcard: ghost.wild is a look-alike
      [`down.${A}`]: { A: [] }                    // exists but NODATA (unresolved)
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`ghost.wild.${A}`]) });
    const scan = await runScan({
      domains: [A], extraNames: [`api.${A}`, `dev.api.${A}`, `down.${A}`], sources: ['anubis'],
      bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const labels = learnedLabelsFromScan(scan);
    assert.deepEqual([...labels].sort(), ['api', 'dev'], 'apex, wildcard look-alike and unresolved hosts contribute nothing');
    assert.ok(!labels.some((l) => l.includes('.')), 'no full names');
    assert.ok(!labels.some((l) => /\d+\.\d+/.test(l)), 'no IPs');
    assert.equal(byName(scan).get(`ghost.wild.${A}`).wildcardSuspect, true);
  });

  test('is pure and tolerant of a missing / empty scan', () => {
    assert.deepEqual(learnedLabelsFromScan(null), []);
    assert.deepEqual(learnedLabelsFromScan({}), []);
    assert.deepEqual(learnedLabelsFromScan({ hosts: [], domains: [] }), []);
  });
});

describe('discovery engine v2: structured origin hints + CLI outputs', () => {
  test('resolver-leak reasons carry { host, resolver }; result exposes cliTargets / cliNames', async () => {
    const A = 'web.example';
    const zone = {
      [A]: { A: ['203.0.113.5'] },
      [`app.${A}`]: { CNAME: 'edge.cdn.cloudflare.net' },
      'edge.cdn.cloudflare.net': { A: ['104.16.9.9'] }
    };
    const zonesByResolver = { google: { [`app.${A}`]: { A: ['203.0.113.77'] } } };
    const { fetchImpl, dns } = mkWorld({ zone, zonesByResolver });
    const scan = await runScan({
      domains: [A], extraNames: [`app.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: true, balance: false, dns, fetchImpl
    });
    const leak = scan.originHints.find((x) => x.ip === '203.0.113.77');
    const reason = leak.reasons.find((r) => r.kind === 'resolver-leak');
    assert.equal(reason.host, `app.${A}`);
    assert.ok(typeof reason.resolver === 'string' && reason.resolver.length > 0, 'the leaking resolver id is recorded');
    assert.equal(reason.detail, `app.${A} via ${reason.resolver}`, 'the detail string is still there for logs');
    // cliTargets / cliNames report exactly what the command swept
    assert.deepEqual(scan.cliTargets, ['203.0.113.0/24']);
    assert.deepEqual(scan.cliNames, [`app.${A}`]);
    assert.equal(scan.cliSuggestion, `python3 cli/ssl_origin_scan.py -t 203.0.113.0/24 -n app.${A}`);
  });
});

/* ------------------------------------------------------------------------ */
/* Review fixes: recursion core, wordlist accounting, re-probes, privacy     */
/* ------------------------------------------------------------------------ */

/** Log every A query name sent while the scan is in one of the bulk probe stages. */
function logProbeQueries(dns, stages = ['bruteforce', 'permutations']) {
  const state = { stage: null, names: [] };
  const orig = dns.query.bind(dns);
  dns.query = (name, type, opts) => {
    if (type === 'A' && stages.includes(state.stage)) state.names.push(name);
    return orig(name, type, opts);
  };
  return { state, onStage: (s) => { state.stage = s; } };
}

describe('discovery engine v2: recursive round keeps the core list', () => {
  test('300 learned labels do not crowd the built-in core out of the recursive round', async () => {
    const A = 'example.com';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`v1.api.${A}`]: { A: ['203.0.113.3'] },
      [`grafana.api.${A}`]: { A: ['203.0.113.4'] } // a core label, reachable only by recursion
    };
    const learned = Array.from({ length: 300 }, (_, i) => `site${String(i).padStart(3, '0')}`);
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`api.${A}`, `v1.api.${A}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', learnedLabels: learned,
      mine: false, permutationBudget: 0, recursive: true, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.has(`grafana.api.${A}`), 'the core label grafana is still tried under api');
    assert.deepEqual(h.get(`grafana.api.${A}`).origins, ['recursive']);
    assert.ok(scan.stats.recursiveTried <= 100 + WORDLIST_SMALL.length, `bounded (${scan.stats.recursiveTried})`);
    assert.ok(scan.stats.recursiveTried >= WORDLIST_SMALL.length, 'the whole core plus a share of learned labels');
  });
});

describe('discovery engine v2: honest custom / learned accounting', () => {
  test('a custom label resolving under two domains reads 1 found of 1 tried (distinct labels)', async () => {
    const zone = {
      'attr.example': { A: ['203.0.113.1'] },
      'attr2.example': { A: ['203.0.113.5'] },
      'billing.attr.example': { A: ['203.0.113.2'] },
      'billing.attr2.example': { A: ['203.0.113.6'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: ['attr.example', 'attr2.example'], sources: [], bruteforce: 'small', customWordlist: ['billing'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const wl = scan.options.wordlist;
    assert.equal(wl.customTried, 1);
    assert.equal(wl.customFound, 1, 'found never exceeds tried');
    assert.deepEqual(wl.perDomain.map((d) => [d.domain, d.customTried, d.customFound]), [
      ['attr.example', 1, 1], ['attr2.example', 1, 1]
    ], 'per domain the counts stay per base');
  });

  test('a custom list larger than the level cap is tried in full, AND the level list still runs', async () => {
    const A = 'cap.example';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`www.${A}`]: { A: ['203.0.113.2'] }, [`mail.${A}`]: { A: ['203.0.113.3'] } };
    const custom = Array.from({ length: 4500 }, (_, i) => `zc${i}`);
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', customWordlist: custom, learnedLabels: ['zzlearned'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.ok(h.has(`www.${A}`) && h.has(`mail.${A}`), 'the Small list itself was probed');
    assert.equal(scan.stats.bruteforceTried, 4500 + 1 + WORDLIST_SMALL.length);
    const wl = scan.options.wordlist;
    assert.equal(wl.customTried, 4500);
    assert.equal(wl.learnedTried, 1);
    assert.ok(!scan.warnings.some((w) => w.code === 'BRUTEFORCE_TRUNCATED'), 'nothing was cut');
  });

  test('bruteforce off: no custom / learned label is reported as tried', async () => {
    const { fetchImpl, dns } = mkWorld({ zone: { 'off.example': { A: ['203.0.113.1'] } } });
    const scan = await runScan({
      domains: ['off.example'], sources: [], bruteforce: 'off', customWordlist: ['billing'], learnedLabels: ['legacy'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.options.wordlist.customTried, 0);
    assert.equal(scan.options.wordlist.learnedTried, 0);
  });

  test('a per-base cap that cuts the list raises BRUTEFORCE_TRUNCATED naming the base', async () => {
    const { fetchImpl, dns } = deadWorld();
    const words = Array.from({ length: 60010 }, (_, i) => `w${i}`);
    const scan = await runScan({
      domains: ['example.net'], sources: [], bruteforce: 'small', wordlist: words,
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.stats.bruteforceTried, 60000);
    const w = scan.warnings.find((x) => x.code === 'BRUTEFORCE_TRUNCATED');
    assert.ok(w, 'the per-base cut is surfaced');
    assert.equal(w.detail, '60000 (example.net)');
  });
});

describe('discovery engine v2: no name is probed twice', () => {
  test('permutations and the recursive round never re-send a brute-force (or permutation) miss', async () => {
    const A = 'perm2.example';
    const seeds = ['api', 'portal', 'billing', 'shop', 'crm', 'vpn', 'mail', 'dev', 'admin', 'panel', 'cdn', 'static'];
    const zone = { [A]: { A: ['203.0.113.1'] } };
    seeds.forEach((s, i) => { zone[`${s}.${A}`] = { A: [`203.0.113.${100 + i}`] }; });
    zone[`v2.api.${A}`] = { A: ['203.0.113.60'] }; // gives the recursive round a parent
    const learned = [...seeds, ...Array.from({ length: 60 }, (_, i) => `svc${i}`)];
    const { fetchImpl, dns } = mkWorld({ zone });
    const log = logProbeQueries(dns);
    const scan = await runScan({
      domains: [A], extraNames: [...seeds.map((s) => `${s}.${A}`), `v2.api.${A}`], sources: [], bruteforce: 'small',
      learnedLabels: learned, mine: false, permutationBudget: 1500, recursive: true,
      originHints: false, balance: false, dns, fetchImpl
    }, { onStage: log.onStage });
    const counts = new Map();
    for (const n of log.state.names) counts.set(n, (counts.get(n) || 0) + 1);
    const dups = [...counts].filter(([, c]) => c > 1).map(([n]) => n);
    assert.deepEqual(dups, [], 'every probe name is sent once');
    assert.equal(scan.stats.permutationTried, 1500, 'the freed budget goes to new names');
    assert.ok(scan.stats.recursiveTried > 0);
  });
});

describe('discovery engine v2: wordlist entries that are full hostnames', () => {
  test('a pasted full hostname is used as its label, never doubled, and skipped under other zones', async () => {
    const zone = {
      'example.com': { A: ['203.0.113.1'] },
      'example.net': { A: ['203.0.113.5'] },
      'zqx-intranet.example.com': { A: ['203.0.113.2'] },
      'qqv-vpn.example.com': { A: ['203.0.113.3'] }
    };
    const { fetchImpl, dns, log } = mkWorld({ zone });
    const scan = await runScan({
      domains: ['example.com', 'example.net'], sources: [], bruteforce: 'small',
      customWordlist: 'zqx-intranet.example.com\nqqv-vpn.example.com\nexample.com',
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.deepEqual(h.get('zqx-intranet.example.com').origins, ['wordlist']);
    assert.deepEqual(h.get('qqv-vpn.example.com').origins, ['wordlist']);
    const asked = log.doh.map((q) => q.name);
    assert.ok(!asked.some((n) => /example\.com\.example\.(com|net)$/.test(n)), 'no doubled / cross-zone name was queried');
    const wl = scan.options.wordlist;
    assert.equal(wl.customTried, 2, 'the apex itself is no label');
    assert.equal(wl.customFound, 2);
    assert.deepEqual(wl.perDomain.map((d) => [d.domain, d.customTried]), [['example.com', 2], ['example.net', 0]]);
  });
});

describe('discovery engine v2: the tab-only custom list is never learned', () => {
  test('hosts only the custom list uncovered (and their probe-derived variants) contribute no label', async () => {
    const A = 'priv.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`zzsecretlabel.${A}`]: { A: ['203.0.113.2'] },  // custom-only
      [`zzsecretlabel2.${A}`]: { A: ['203.0.113.3'] }, // its permutation
      [`www.${A}`]: { A: ['203.0.113.4'] },            // a core label in the custom list
      [`crm.${A}`]: { A: ['203.0.113.5'] }             // found by a passive source
    };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`crm.${A}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'small', customWordlist: ['zzsecretlabel', 'www'],
      mine: false, permutationBudget: 200, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.equal(h.get(`zzsecretlabel.${A}`).customOnly, true);
    assert.deepEqual(h.get(`zzsecretlabel2.${A}`).origins, ['permutation']);
    assert.equal(h.get(`www.${A}`).customOnly, false, 'a core label is public vocabulary');
    assert.equal(h.get(`crm.${A}`).customOnly, false);
    const labels = learnedLabelsFromScan(scan);
    assert.ok(!labels.some((l) => l.includes('zzsecretlabel')), `no private label learned: ${labels.join(',')}`);
    assert.ok(labels.includes('www') && labels.includes('crm'), 'public evidence is still learned');
  });

  test('learnedLabelsFromScan never returns an IP written into a label', () => {
    const res = (ip) => ({ ipv4: [ip], ipv6: [], cnames: [] });
    const scan = {
      domains: ['example.com'],
      hosts: [
        { name: '198-51-100-7.example.com', origins: ['anubis'], resolution: res('198.51.100.7') },
        { name: 'ip-192-0-2-10.example.com', origins: ['anubis'], resolution: res('192.0.2.10') },
        { name: '203-0-113-9-static.example.com', origins: ['anubis'], resolution: res('203.0.113.9') },
        { name: 'api.example.com', origins: ['anubis'], resolution: res('203.0.113.20') },
        { name: 'web-01.example.com', origins: ['anubis'], resolution: res('203.0.113.21') }
      ]
    };
    assert.deepEqual(learnedLabelsFromScan(scan), ['api', 'web-01']);
  });
});

describe('discovery engine v2: locale packs are reported as loaded, not as requested', () => {
  test('a locale pack that fails to load is not claimed, and a warning says so', async () => {
    clearWordlistCache(); // an earlier test cached locale/tr.txt from disk
    const { dns: deadDns, fetchImpl: deadFetch } = deadWorld();
    const fetchImpl = async (url, init) => {
      const u = String(url);
      if (u.startsWith('file:')) {
        if (u.endsWith('/locale/tr.txt')) return new Response('', { status: 404 });
        return new Response(await readFile(new URL(u)));
      }
      return deadFetch(u, init);
    };
    try {
      const scan = await runScan({
        domains: ['example.com.tr'], sources: [], bruteforce: 'smart', wordlistPreferFetch: true,
        mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns: deadDns, fetchImpl
      });
      const wl = scan.options.wordlist;
      assert.equal(wl.level, 'smart');
      assert.deepEqual(wl.localePacks, [], 'the tr pack is not claimed');
      assert.deepEqual(wl.perDomain[0].locales, []);
      assert.deepEqual(wl.localesMissing, ['tr']);
      const w = scan.warnings.find((x) => x.code === 'WORDLIST_DEGRADED');
      assert.ok(w && w.detail.includes('locale:tr'), JSON.stringify(scan.warnings));
      assert.deepEqual(wl.degraded, [], 'the level itself did not degrade');
    } finally {
      clearWordlistCache();
    }
  });
});

describe('discovery engine v2: learned labels and wildcards stay in scope (defence in depth)', () => {
  test('level off: learned labels reach neither permutations nor the recursive round', async () => {
    const A = 'customer-b.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`api.${A}`]: { A: ['203.0.113.2'] },
      [`www.api.${A}`]: { A: ['203.0.113.3'] } // api has children → the recursive round runs under it
    };
    const { fetchImpl, dns, log } = mkWorld({ zone, sources: anubis([`api.${A}`, `www.api.${A}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', learnedLabels: ['zzlearnedone', 'zzlearnedtwo'],
      mine: false, permutationBudget: 500, recursive: true, originHints: false, balance: false, dns, fetchImpl
    });
    assert.ok(byName(scan).has(`www.api.${A}`));
    const sent = log.doh.filter((q) => q.name.includes('zzlearned')).map((q) => q.name);
    assert.deepEqual(sent, [], 'no learned label is queried at level off');
    assert.equal(scan.options.wordlist.learnedTried || 0, 0);
  });

  test('learnedLabelsFromScan ignores hosts under no scanned domain (another organisation’s names)', () => {
    const res = (ip) => ({ ipv4: [ip], ipv6: [], cnames: [] });
    const scan = {
      domains: ['example.com'],
      hosts: [
        { name: 'api.example.com', origins: ['cert'], resolution: res('203.0.113.20') },
        { name: 'portal.acmebrand.org', origins: ['cert'], resolution: res('203.0.113.21') },
        { name: 'acmebrand.org', origins: ['input'], resolution: res('203.0.113.22') }
      ]
    };
    assert.deepEqual(learnedLabelsFromScan(scan), ['api']);
  });

  test('a wildcard on a public suffix (*.com.tr) is never brute-forced nor a scope root', async () => {
    const A = 'example-test.com.tr';
    const zone = { [A]: { A: ['203.0.113.1'] }, [`www.${A}`]: { A: ['203.0.113.2'] } };
    const { fetchImpl, dns, log } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: ['*.com.tr'], sources: [], bruteforce: 'small',
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.ok(byName(scan).has(`www.${A}`), 'the real target is still swept');
    const underSuffix = log.doh.filter((q) => q.name.endsWith('.com.tr') && !q.name.endsWith(`.${A}`) && q.name !== A);
    assert.deepEqual(underSuffix.map((q) => q.name), [], 'nothing is probed directly under the public suffix');
    assert.ok(!(scan.wildcardBases || []).includes('com.tr'));
    assert.ok(scan.warnings.some((w) => w.code === 'PUBLIC_SUFFIX' && w.detail === 'com.tr'), JSON.stringify(scan.warnings));
    assert.ok(!scan.warnings.some((w) => w.code === 'INVALID_NAME'), 'the wildcard is recognised, not rejected as invalid');
  });
});

/* ------------------------------------------------------------------------ */
/* Engine v3: sibling-domain hint, per-host candidates, network ownership,  */
/* streaming, stage honesty, query estimate                                 */
/* ------------------------------------------------------------------------ */

describe('discovery engine v3: sibling-domain origin hint (cross-brand)', () => {
  test('a proxied X.<d1> whose exact label X is DNS-only under sibling <d2> gets an exact host-specific candidate', async () => {
    const A = 'brand-a.example';
    const B = 'brand-b.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`ticket.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' }, // proxied on brand A
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] },
      [B]: { A: ['203.0.113.10'] },
      [`ticket.${B}`]: { A: ['203.0.113.50'] } // the real origin, published in the open on brand B
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A, B], sources: [], bruteforce: 'small', wordlist: ['ticket'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan);
    assert.equal(h.get(`ticket.${A}`).classification.hidesOrigin, true);
    // the hint
    const hint = scan.originHints.find((x) => x.ip === '203.0.113.50');
    assert.ok(hint, 'the sibling origin is an origin hint');
    const sib = hint.reasons.find((r) => r.kind === 'sibling-domain');
    assert.ok(sib, 'a sibling-domain reason');
    assert.equal(sib.host, `ticket.${A}`);
    assert.equal(sib.sibling, `ticket.${B}`);
    // the per-host candidate list: exact sibling IP first, then its network
    const cand = h.get(`ticket.${A}`).originCandidates;
    assert.equal(cand[0].ip, '203.0.113.50');
    assert.equal(cand[0].kind, 'sibling-domain');
    assert.ok(cand[0].score > (cand.find((c) => c.cidr) || { score: 0 }).score, 'the exact IP ranks above the network');
    assert.deepEqual(h.get(`ticket.${A}`).candidateNetworks, ['203.0.113.0/24']);
    // the sibling IP is swept: its /24 (2 IPs) is a CLI target
    assert.ok(scan.cliTargets.includes('203.0.113.0/24'));
    assert.ok(scan.cliNames.includes(`ticket.${A}`));
  });

  test('no sibling hint from the SAME brand, and none for a single-apex scan', async () => {
    const A = 'solo-brand.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`ticket.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      [`ticket2.${A}`]: { A: ['192.0.2.6'] }, // same brand, different label
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['ticket', 'ticket2'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.ok(!scan.originHints.some((x) => x.reasons.some((r) => r.kind === 'sibling-domain')), 'no sibling-domain hint in a single-apex scan');
  });
});

describe('discovery engine v3: per-host candidate networks (noise capped)', () => {
  test('only the main cluster / related networks are attached; a lone 1-IP mail or dev network is not', async () => {
    const A = 'estate.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`api.${A}`]: { A: ['192.0.2.6'] },
      [`app.${A}`]: { A: ['192.0.2.7'] },
      [`crm.${A}`]: { A: ['192.0.2.8'] },
      [`mail.${A}`]: { A: ['198.51.100.9'] },
      [`webmail.${A}`]: { A: ['198.51.100.9'] }, // same single IP as mail (a shared mail server)
      [`dev.${A}`]: { A: ['203.0.113.10'] }, // a lone box in another /24
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'app', 'crm', 'mail', 'webmail', 'dev', 'www'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    // all three networks exist for display
    assert.deepEqual(scan.originNetworks.map((n) => n.cidr).sort(),
      ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']);
    // but the proxied host only gets the multi-IP main cluster, not the 1-IP noise
    assert.deepEqual(byName(scan).get(`www.${A}`).candidateNetworks, ['192.0.2.0/24']);
    // the CLI sweeps the /24 whole for the cluster, exact IPs for the singletons
    const byCidr = new Map(scan.originNetworks.map((n) => [n.cidr, n]));
    assert.equal(byCidr.get('192.0.2.0/24').sweep, 'cidr');
    assert.equal(byCidr.get('198.51.100.0/24').sweep, 'ips');
    assert.equal(byCidr.get('203.0.113.0/24').sweep, 'ips');
    assert.ok(scan.cliTargets.includes('192.0.2.0/24'));
    assert.ok(scan.cliTargets.includes('198.51.100.9'));
    assert.ok(scan.cliTargets.includes('203.0.113.10'));
    assert.ok(!scan.cliTargets.includes('198.51.100.0/24'), 'a 1-IP network is not widened to its /24');
  });

  test('each origin network carries a shared flag (offline) and a sweep decision', async () => {
    const A = 'flags.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`api.${A}`]: { A: ['192.0.2.6'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    const net = scan.originNetworks.find((n) => n.cidr === '192.0.2.0/24');
    assert.equal(net.shared, false, 'documentation space is not a known shared provider range');
    assert.equal(net.sweep, 'cidr');
    assert.equal(net.provider, null);
  });
});

describe('discovery engine v3: streaming onFound', () => {
  test('every wordlist / permutation hit is streamed the moment it resolves, with a cheap classification', async () => {
    const A = 'stream.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`api.${A}`]: { A: ['192.0.2.6'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const found = [];
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api', 'www', 'nope'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    }, { onFound: (p) => found.push(p) });
    const byNameFound = new Map(found.map((p) => [p.name, p]));
    assert.ok(byNameFound.has(`api.${A}`) && byNameFound.has(`www.${A}`), 'both hits streamed');
    assert.ok(!byNameFound.has(`nope.${A}`), 'an NXDOMAIN candidate is not streamed');
    assert.equal(byNameFound.get(`api.${A}`).origin, 'wordlist');
    assert.deepEqual(byNameFound.get(`api.${A}`).ipv4, ['192.0.2.6']);
    assert.equal(byNameFound.get(`api.${A}`).classification.kind, 'direct');
    assert.equal(byNameFound.get(`www.${A}`).classification.kind, 'cloudflare');
    // the final result is unchanged: the same hosts arrive as full records
    assert.ok(byName(scan).has(`api.${A}`) && byName(scan).has(`www.${A}`));
    // a hook that throws never breaks the scan
    const scan2 = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['api'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    }, { onFound: () => { throw new Error('boom'); } });
    assert.ok(byName(scan2).has(`api.${A}`));
  });
});

describe('discovery engine v3: stage honesty', () => {
  test('the grace window reports which passive sources were still fetching', async () => {
    const A = 'grace.example';
    const zone = { [A]: { A: ['192.0.2.5'] } };
    const sources = { 'https://anubisdb.com/': async () => { await new Promise((r) => setTimeout(r, 120)); return [`api.${A}`]; } };
    const { fetchImpl, dns } = mkWorld({ zone, sources });
    const stageInfo = {};
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0,
      recursive: false, originHints: false, balance: false, sourceGraceMs: 5, dns, fetchImpl
    }, { onStage: (s, info) => { stageInfo[s] = info; } });
    assert.deepEqual(scan.sourceGrace.stillRunning, ['anubis']);
    assert.equal(scan.sourceGrace.cutOff, true);
    assert.deepEqual(stageInfo.wildcard.sourcesStillRunning, ['anubis'], 'the wildcard stage carries the snapshot');
    assert.equal(stageInfo.wildcard.sourcesCutOff, true);
    // the source is still awaited before resolve, so its late name is not lost
    assert.ok(byName(scan).has(`api.${A}`), 'the slow source name is folded in');
  });

  test('a source that settles inside the grace window leaves stillRunning empty', async () => {
    const A = 'settled.example';
    const zone = { [A]: { A: ['192.0.2.5'] } };
    const { fetchImpl, dns } = mkWorld({ zone, sources: anubis([`api.${A}`]) });
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0,
      recursive: false, originHints: false, balance: false, sourceGraceMs: 12000, dns, fetchImpl
    });
    assert.deepEqual(scan.sourceGrace.stillRunning, []);
    assert.equal(scan.sourceGrace.cutOff, false);
  });

  test('the hints stage has determinate progress that reaches its total', async () => {
    const A = 'hintsprog.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const progress = [];
    let hintsInfo = null;
    await runScan({
      domains: [A], extraNames: [`www.${A}`], sources: [], bruteforce: 'off', mine: false,
      permutationBudget: 0, recursive: false, originHints: true, resolverLeak: true, balance: false, dns, fetchImpl
    }, { onStage: (s, info) => { if (s === 'hints') hintsInfo = info; }, onProgress: (p) => { if (p.stage === 'hints') progress.push(p); } });
    assert.ok(hintsInfo.total > 0, 'a determinate total is announced');
    const last = progress[progress.length - 1];
    assert.ok(last && last.done === last.total && last.total > 0, `hints progress reaches ${last && last.total}`);
  });
});

describe('discovery engine v3: query estimate', () => {
  test('counts every stage; the range brackets a real run (Smart + Turkish, one apex)', () => {
    const est = estimateQueries({ bruteforce: 'smart', domains: ['example-test.com.tr'], locales: ['tr'] });
    assert.equal(est.breakdown.wordlist, 7000 + 283, 'smart base + the Turkish pack');
    assert.equal(est.breakdown.permutation, 1500, 'the permutation budget is counted (the old plan missed it)');
    assert.ok(est.breakdown.mining > 0 && est.breakdown.hintsMax > 0);
    assert.ok(est.min <= 8952 && est.max >= 8952, `real 8,952 should fall in [${est.min}, ${est.max}]`);
    assert.ok(est.min <= est.max);
  });

  test('off means no wordlist queries; disabling stages drops their terms', () => {
    const est = estimateQueries({ bruteforce: 'off', domains: ['example.com'], permutationBudget: 0, recursive: false, mine: false, originHints: false });
    assert.equal(est.breakdown.wordlist, 0);
    assert.equal(est.breakdown.permutation, 0);
    assert.equal(est.breakdown.recursive, 0);
    assert.equal(est.breakdown.mining, 0);
    assert.equal(est.breakdown.hintsMax, 0);
  });

  test('several apexes sum, under the total brute-force cap; auto locale applies per domain', () => {
    const est = estimateQueries({ bruteforce: 'smart', domains: ['a.com.tr', 'b.de'], locales: null });
    // a.com.tr adds the tr pack, b.de adds the de pack, both on top of the 7,000 smart base
    assert.ok(est.breakdown.wordlist > 7000 * 2, 'both apexes counted');
    assert.ok(est.breakdown.wordlist <= 200000, 'under the total cap');
    assert.equal(est.breakdown.bases, 2);
  });
});

/* ------------------------------------------------------------------------ */
/* Review fixes (engine v3 + zone hand-off)                                 */
/* ------------------------------------------------------------------------ */

describe('engine v3 review fixes', () => {
  test('nested apexes are one brand: no cross-brand sibling-domain hint between shop.X and X', async () => {
    const A = 'nest.example';
    const S = `shop.${A}`;
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [S]: { A: ['192.0.2.6'] },
      [`api.${S}`]: { CNAME: 'proxy.cdn.cloudflare.net' }, // proxied under the nested apex
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] },
      [`api.${A}`]: { A: ['203.0.113.50'] } // same label, same organisation, DNS-only
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A, S], sources: [], bruteforce: 'small', wordlist: ['api'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    assert.equal(byName(scan).get(`api.${S}`).classification.hidesOrigin, true);
    assert.ok(!scan.originHints.some((x) => x.reasons.some((r) => r.kind === 'sibling-domain')),
      'a nested apex of the same organisation is not a sister brand');
  });

  test('an IP named by two host-specific kinds is ONE candidate (the strongest), not a duplicate row', async () => {
    const A = 'dupe-a.example';
    const B = 'dupe-b.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`ticket.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' },
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] },
      [B]: { A: ['203.0.113.10'] },
      [`ticket.${B}`]: { A: ['203.0.113.50'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A, B], sources: [], bruteforce: 'small', wordlist: ['ticket'],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl,
      zone: { v: 1, origin: A, names: [`ticket.${A}`], wildcardBases: [], proxied: [{ name: `ticket.${A}`, ips: ['203.0.113.50'], host: null }] }
    });
    const cand = byName(scan).get(`ticket.${A}`).originCandidates.filter((c) => c.ip === '203.0.113.50');
    assert.equal(cand.length, 1, JSON.stringify(cand));
    assert.equal(cand[0].kind, 'zone', 'the zone file (score 110) outranks the sibling-domain match');
  });

  test('candidate networks per host are capped: the weakest band (unrelated clusters) keeps at most 3', async () => {
    const A = 'many.example';
    const zone = { [A]: { A: ['192.0.2.5'] }, [`www.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' }, 'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] } };
    const words = ['www'];
    const extraNames = [];
    // 8 unrelated 2-IP clusters, one IPv6 documentation /48 each (AAAA-only: given as names)
    for (let i = 0; i < 8; i += 1) {
      for (const j of [1, 2]) {
        zone[`n${i}x${j}.${A}`] = { AAAA: [`2001:db8:${i + 1}::${j}`] };
        extraNames.push(`n${i}x${j}.${A}`);
      }
    }
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: words, extraNames,
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    const www = byName(scan).get(`www.${A}`);
    assert.ok(scan.originNetworks.length >= 8, `networks: ${scan.originNetworks.length}`);
    const bands = www.originCandidates.filter((c) => c.kind === 'network').map((c) => c.evidence.relation);
    assert.ok(bands.filter((r) => r === 'cluster').length <= 3, JSON.stringify(bands));
    assert.equal(bands.filter((r) => r === 'main-cluster').length, 1, 'the main cluster is always kept');
    assert.deepEqual(www.candidateNetworks, www.originCandidates.filter((c) => c.kind === 'network').map((c) => c.cidr));
  });

  test('no onFound row is streamed once the scan is aborted (even when the DNS client ignores the signal)', async () => {
    const A = 'abort-stream.example';
    const zone = { [A]: { A: ['192.0.2.5'] } };
    const words = [];
    for (let i = 0; i < 40; i += 1) { zone[`h${i}.${A}`] = { A: [`192.0.2.${10 + i}`] }; words.push(`h${i}`); }
    const { fetchImpl, dns: inner } = mkWorld({ zone });
    // a client that does not race the abort signal: answers already in flight still land
    const dns = {
      query: (n, t, o = {}) => inner.query(n, t, { ...o, signal: undefined }),
      resolveHost: (n, o = {}) => inner.resolveHost(n, { ...o, signal: undefined }),
      detectWildcard: (...a) => inner.detectWildcard(...a),
      chain: inner.chain
    };
    const ctl = new AbortController();
    const late = [];
    let seen = 0;
    await assert.rejects(runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: words,
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: true, dns, fetchImpl, signal: ctl.signal
    }, {
      onFound: (p) => {
        if (ctl.signal.aborted) late.push(p.name);
        seen += 1;
        if (seen === 1) ctl.abort();
      }
    }), (err) => err.name === 'AbortError');
    assert.deepEqual(late, [], 'rows streamed after the abort');
  });

  test('estimate: mining runs per registrable domain (a subdomain target is not mined twice); cert wildcard bases add no hint zone', () => {
    const one = estimateQueries({ domains: ['example.com'], bruteforce: 'off', originHints: true });
    const sub = estimateQueries({ domains: ['shop.example.com'], bruteforce: 'off', originHints: true });
    assert.equal(sub.breakdown.mining, one.breakdown.mining, 'runScan mines example.com once for shop.example.com');
    const wc = estimateQueries({ domains: ['example.com'], wildcardBases: ['apps.example.com'], bruteforce: 'off', originHints: true });
    assert.equal(wc.breakdown.mining, one.breakdown.mining);
    assert.equal(wc.breakdown.hintsMin, one.breakdown.hintsMin, 'SPF / MX run for the scanned domains only');
    assert.equal(wc.breakdown.bases, 2, 'the wildcard base is still a brute-force / wildcard base');
  });
});

describe('engine v3 review fixes: related-parent networks', () => {
  test('a network holding a DNS-only sibling under the same parent (db.shop for a proxied api.shop) is a related candidate', async () => {
    const A = 'parent-rel.example';
    const zone = {
      [A]: { A: ['192.0.2.5'] },
      [`www.${A}`]: { A: ['192.0.2.6'] }, // the main cluster (2 IPs)
      [`api.shop.${A}`]: { CNAME: 'proxy.cdn.cloudflare.net' }, // proxied
      'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] },
      [`db.shop.${A}`]: { A: ['198.51.100.9'] }, // DNS-only sibling under the same parent, a lone IP
      [`mail.${A}`]: { A: ['203.0.113.10'] } // a lone unrelated box: still noise
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'off', extraNames: [`www.${A}`, `api.shop.${A}`, `db.shop.${A}`, `mail.${A}`],
      mine: false, permutationBudget: 0, recursive: false, originHints: true, resolverLeak: false, balance: false, dns, fetchImpl
    });
    const host = byName(scan).get(`api.shop.${A}`);
    assert.equal(host.classification.hidesOrigin, true);
    const nets = host.originCandidates.filter((c) => c.kind === 'network');
    assert.deepEqual(nets.map((c) => [c.cidr, c.evidence.relation]), [
      ['198.51.100.0/24', 'related-parent'],
      ['192.0.2.0/24', 'main-cluster']
    ]);
    assert.deepEqual(host.candidateNetworks, ['198.51.100.0/24', '192.0.2.0/24']);
  });
});

describe('discovery review fixes: wildcards whose answer varies', () => {
  /** Small deterministic string hash (FNV-1a) to pick a per-label answer. */
  const hash = (s) => {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i += 1) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
    return h;
  };
  const run = (A, world, extra = {}) => runScan({
    domains: [A], sources: [], bruteforce: 'small', mine: false, permutationBudget: 0, recursive: false,
    originHints: false, balance: true, dns: world.dns, fetchImpl: world.fetchImpl, ...extra
  });
  const wordlistHosts = (scan) => scan.hosts.filter((x) => x.origins.includes('wordlist')).map((x) => x.name);

  test('a wildcard answering each resolver differently (GeoDNS / CDN alias) invents no host in balance mode', async () => {
    const A = 'geo-wc.example';
    const zone = {
      [A]: { A: ['203.0.113.10'] },
      [`*.${A}`]: { A: ['198.51.100.10', '198.51.100.11'] },
      [`www.${A}`]: { A: ['203.0.113.20'] }
    };
    const world = mkWorld({ zone, zonesByResolver: { google: { [`*.${A}`]: { A: ['192.0.2.20', '192.0.2.21'] } } } });
    const scan = await run(A, world);
    assert.deepEqual(wordlistHosts(scan), [`www.${A}`]);
    assert.equal(scan.stats.wordlistFound, 1);
    assert.equal(scan.wildcards[A].kind, 'A');
    assert.equal(scan.wildcards[A].variable, true);
    assert.deepEqual([...scan.wildcards[A].ipv4].sort(), ['192.0.2.20', '192.0.2.21', '198.51.100.10', '198.51.100.11']);
  });

  test('a multivalue wildcard (another pair of a 12-address pool per label) invents no host; a real one outside it is kept', async () => {
    const A = 'pool-wc.example';
    const pool = Array.from({ length: 12 }, (_, i) => `198.51.100.${40 + i}`);
    const zone = { [A]: { A: ['203.0.113.10'] }, [`www.${A}`]: { A: ['203.0.113.20'] } };
    const answer = (name, type) => {
      if (!name.endsWith(`.${A}`) || zone[name]) return undefined;
      const h = hash(name);
      const data = type === 'A' ? [...new Set([pool[h % 12], pool[(h >>> 8) % 12]])] : [];
      return { rcode: 'NOERROR', answers: data.map((d) => ({ name, type: 'A', ttl: 60, data: d })) };
    };
    const scan = await run(A, mkWorld({ zone, answer }));
    assert.equal(scan.wildcards[A].wildcard, true);
    assert.equal(scan.wildcards[A].kind, 'A');
    assert.deepEqual(wordlistHosts(scan), [`www.${A}`]);
  });

  test('a CNAME wildcard whose target varies per label (PaaS ingress) invents no host', async () => {
    const A = 'paas-wc.example';
    const targets = ['va01', 'va02', 'ie01', 'ie02'].map((p) => `${p}.ingress.paas.example.net`);
    const zone = { [A]: { A: ['203.0.113.10'] }, [`www.${A}`]: { A: ['203.0.113.20'] } };
    const answer = (name, type) => {
      if (!name.endsWith(`.${A}`) || zone[name]) return undefined;
      const t = targets[hash(name) % targets.length];
      const answers = [{ name, type: 'CNAME', ttl: 60, data: t }];
      if (type === 'A') answers.push({ name: t, type: 'A', ttl: 60, data: '192.0.2.9' });
      return { rcode: 'NOERROR', answers };
    };
    const scan = await run(A, mkWorld({ zone, answer }));
    assert.equal(scan.wildcards[A].kind, 'CNAME');
    assert.deepEqual(wordlistHosts(scan), [`www.${A}`]);
  });

  test('flood guard: most guesses resolving under a parent re-samples it and drops the look-alikes', async () => {
    const A = 'flood-wc.example';
    const zone = { [A]: { A: ['203.0.113.10'] }, [`shop.${A}`]: { A: ['203.0.113.30'] } };
    // every label gets its own address, each in another /24: no sample can list them
    const answer = (name, type) => {
      if (!name.endsWith(`.${A}`) || zone[name]) return undefined;
      const h = hash(name);
      const answers = type === 'A' ? [{ name, type: 'A', ttl: 60, data: `10.${h % 200}.${(h >>> 8) % 250}.7` }] : [];
      return { rcode: 'NOERROR', answers };
    };
    const scan = await run(A, mkWorld({ zone, answer }), { extraNames: [`shop.${A}`] });
    assert.equal(scan.wildcards[A].flooded, true);
    assert.deepEqual(wordlistHosts(scan), []);
    assert.equal(scan.stats.wordlistFound, 0);
    assert.ok(scan.stats.bruteforceWildcardDropped > 100, String(scan.stats.bruteforceWildcardDropped));
    assert.ok(byName(scan).has(`shop.${A}`), 'a typed name is never dropped');
  });
});

describe('discovery review fixes: probes keep dangling aliases', () => {
  test('a wordlist probe answering NXDOMAIN with a CNAME chain (target gone) is a dangling host, streamed as such', async () => {
    const A = 'dangle.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`blog.${A}`]: { CNAME: 'dangle-example.ghost.io' }, // the target no longer exists
      [`www.${A}`]: { A: ['203.0.113.2'] }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const found = [];
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['www', 'blog', 'nope'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    }, { onFound: (p) => found.push(p) });
    const blog = byName(scan).get(`blog.${A}`);
    assert.ok(blog, 'the dangling alias is found');
    assert.deepEqual(blog.origins, ['wordlist']);
    assert.equal(blog.resolution.status, 'NXDOMAIN');
    assert.deepEqual(blog.resolution.cnames, ['dangle-example.ghost.io']);
    assert.equal(blog.classification.dangling, true);
    assert.equal(blog.classification.reasonKey, 'class.dangling.nxdomain');
    assert.equal(scan.stats.dangling, 1);
    assert.equal(scan.stats.bruteforceFound, 2);
    const streamed = found.find((p) => p.name === `blog.${A}`);
    assert.equal(streamed.status, 'NXDOMAIN');
    assert.equal(streamed.classification.dangling, true);
    assert.ok(!byName(scan).has(`nope.${A}`), 'a plain NXDOMAIN is still no hit');
  });

  test('a wildcard CNAME to a gone target: look-alikes are still dropped', async () => {
    const A = 'dangle-wc.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`*.${A}`]: { CNAME: 'gone.azurewebsites.net' }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], sources: [], bruteforce: 'small', wordlist: ['www', 'blog', 'shop'],
      mine: false, permutationBudget: 0, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.equal(scan.wildcards[A].kind, 'CNAME');
    assert.ok(scan.hosts.every((x) => !x.origins.includes('wordlist')));
    assert.equal(scan.stats.bruteforceWildcardDropped, 3);
    assert.equal(scan.stats.dangling, 0);
  });

  test('the permutation stage finds a dangling alias too', async () => {
    const A = 'dangle-perm.example';
    const zone = {
      [A]: { A: ['203.0.113.1'] },
      [`blog.${A}`]: { A: ['203.0.113.3'] },
      [`blog2.${A}`]: { CNAME: 'blog2-example.ghost.io' }
    };
    const { fetchImpl, dns } = mkWorld({ zone });
    const scan = await runScan({
      domains: [A], extraNames: [`blog.${A}`], sources: [], bruteforce: 'off',
      mine: false, permutationBudget: 200, recursive: false, originHints: false, balance: false, dns, fetchImpl
    });
    const h = byName(scan).get(`blog2.${A}`);
    assert.ok(h);
    assert.deepEqual(h.origins, ['permutation']);
    assert.equal(h.classification.dangling, true);
  });
});
