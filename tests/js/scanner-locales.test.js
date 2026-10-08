// Unit tests for the adaptive locale packs in assets/js/lib/scanner.js: a scanned domain whose TLD
// names no market gets the locale packs the evidence the scan has gathered by its wordlist stage
// points to (lib/localeevidence.js) — the words of the names found, the countries of the zone's
// NS / MX hosts — and the result says how each domain's packs were chosen. No network: an
// emulated zone answers every DoH resolver and the passive source (Anubis) is mocked.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runScan, estimateQueries } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { clearWordlistCache, loadWordlist, wordlistInfo, LOCALE_EVIDENCE_MAX_PACKS } from '../../assets/js/lib/wordlist.js';
import { evidencePackMax } from '../../assets/js/lib/scanplan.js';

const OUT_SOA = { mname: 'ns-hidden.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

/** Answer `name`/`type` from a flat zone map (CNAMEs followed); NXDOMAIN outside it. */
function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 10; hop += 1) {
    const node = zone[current];
    if (!node) {
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: current, type: 'SOA', ttl: 300, data: OUT_SOA }] };
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
 * A world: the zone behind every DoH resolver, Anubis answering `anubis[domain]`, and the data
 * files (wordlist tiers, locale packs) read from disk when the scan loads them over fetch
 * (`wordlistPreferFetch`), each logged in `log.files`.
 */
function mkWorld({ zone, anubis = {} }) {
  const log = { files: [], doh: 0 };
  const fetchImpl = async (input) => {
    const url = String(input && input.href ? input.href : input);
    if (url.startsWith('file:')) {
      log.files.push(url.slice(url.indexOf('/assets/data/') + '/assets/data/'.length));
      try {
        return new Response(await readFile(fileURLToPath(url)));
      } catch {
        return new Response('', { status: 404 });
      }
    }
    if (RESOLVERS.some((r) => url.startsWith(`${r.url}?`))) {
      log.doh += 1;
      const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
      const out = zoneAnswer(zone, q.name, q.type);
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
      }));
    }
    if (url.startsWith('https://anubisdb.com/')) {
      const domain = decodeURIComponent(url.split('/').pop());
      return Response.json(anubis[domain] || []);
    }
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

const QUIET = { permutationBudget: 0, recursive: false, originHints: false, balance: false };
const localeFiles = (log) => log.files.filter((f) => f.startsWith('locale/')).sort();

describe('adaptive locale packs in the scan', () => {
  test('Turkish words among the names a source found give a .com the Turkish pack, and its labels are tried', async () => {
    clearWordlistCache();
    const A = 'example.com';
    const zone = {
      [A]: { A: ['203.0.113.10'] },
      [`destek.${A}`]: { A: ['203.0.113.11'] },
      [`yonetimpanel.${A}`]: { A: ['203.0.113.12'] } // a label only the tr pack has
    };
    assert.ok(!(await loadWordlist('smart', { domain: A })).includes('yonetimpanel'), 'precondition: not in the global list');
    const { fetchImpl, dns, log } = mkWorld({ zone, anubis: { [A]: [`destek.${A}`, `bayi.${A}`, `kampanya.${A}`, `www.${A}`] } });
    const stages = {};
    const scan = await runScan({
      domains: [A], sources: ['anubis'], bruteforce: 'smart', mine: false, wordlistPreferFetch: true, ...QUIET, dns, fetchImpl
    }, { onStage: (s, info) => { stages[s] = info; } });
    const wl = scan.options.wordlist;
    assert.deepEqual(wl.localePacks, ['tr']);
    const pd = wl.perDomain[0];
    assert.equal(pd.localeSource, 'evidence');
    assert.deepEqual(pd.locales, ['tr']);
    assert.deepEqual(pd.localeEvidence.locales, ['tr']);
    const tr = pd.localeEvidence.signals.find((s) => s.locale === 'tr');
    assert.deepEqual(tr.words, ['bayi', 'destek', 'kampanya']);
    assert.ok(scan.hosts.find((h) => h.name === `yonetimpanel.${A}`)?.origins.includes('wordlist'), 'found through the tr pack');
    // The wordlist stage says so while it runs.
    assert.deepEqual(stages.bruteforce.locales.map((c) => [c.domain, c.source, c.locales]), [[A, 'evidence', ['tr']]]);
    assert.deepEqual(stages.bruteforce.locales[0].evidence.locales, ['tr']);
    // Every pack was read (the vocabulary), and the tr pack served the list.
    assert.equal(localeFiles(log).filter((f, i, all) => all.indexOf(f) === i).length, 12, 'the twelve packs, once each');
    assert.deepEqual(scan.warnings.filter((w) => w.code === 'WORDLIST_DEGRADED'), []);
  });

  test('the mail servers alone: a .com whose MX hosts are in .com.tr gets Turkish, and no pack is read for words', async () => {
    clearWordlistCache();
    const A = 'example.com';
    const zone = {
      [A]: { A: ['203.0.113.10'], MX: [{ preference: 10, exchange: 'mx1.example.com.tr' }, { preference: 20, exchange: 'mx2.example.com.tr' }], NS: ['ns1.example.net'] },
      [`yonetimpanel.${A}`]: { A: ['203.0.113.12'] }
    };
    const { fetchImpl, dns, log } = mkWorld({ zone });
    const scan = await runScan({ domains: [A], sources: [], bruteforce: 'smart', mine: true, wordlistPreferFetch: true, ...QUIET, dns, fetchImpl });
    const pd = scan.options.wordlist.perDomain[0];
    assert.equal(pd.localeSource, 'evidence');
    assert.deepEqual(pd.locales, ['tr']);
    const tr = pd.localeEvidence.signals.find((s) => s.locale === 'tr');
    assert.deepEqual([tr.points.mx, tr.points.ns, tr.points.words], [2, 0, 0]);
    assert.deepEqual(tr.mx, ['.com.tr']);
    assert.equal(pd.localeEvidence.ns, 1, 'one name-server domain read');
    assert.ok(scan.hosts.some((h) => h.name === `yonetimpanel.${A}`));
    assert.deepEqual(localeFiles(log), ['locale/tr.txt'], 'no name to read: only the picked pack is loaded');
  });

  test('an English zone keeps the global list and says why ("none", with what was read)', async () => {
    clearWordlistCache();
    const A = 'example.net';
    const zone = { [A]: { A: ['203.0.113.20'] }, [`www.${A}`]: { A: ['203.0.113.20'] } };
    const { fetchImpl, dns } = mkWorld({ zone, anubis: { [A]: [`www.${A}`, `shop.${A}`, `support.${A}`, `hotel.${A}`] } });
    const scan = await runScan({ domains: [A], sources: ['anubis'], bruteforce: 'smart', mine: false, ...QUIET, dns, fetchImpl });
    const pd = scan.options.wordlist.perDomain[0];
    assert.equal(pd.localeSource, 'none');
    assert.deepEqual(pd.locales, []);
    assert.deepEqual(pd.localeEvidence.locales, []);
    assert.equal(pd.localeEvidence.names, 5, 'the domain and the four names');
    assert.deepEqual(scan.options.wordlist.localePacks, []);
  });

  test('a TLD with packs, an explicit choice, Small and an override read no evidence', async () => {
    clearWordlistCache();
    const zone = { 'example.com.tr': { A: ['203.0.113.30'] }, 'example.com': { A: ['203.0.113.10'] } };
    const names = { 'example.com.tr': ['kunden.example.com.tr', 'rechnung.example.com.tr'], 'example.com': ['destek.example.com', 'kampanya.example.com'] };
    const run = async (extra) => {
      const { fetchImpl, dns, log } = mkWorld({ zone, anubis: names });
      const scan = await runScan({ sources: ['anubis'], mine: false, wordlistPreferFetch: true, ...QUIET, dns, fetchImpl, ...extra });
      return { pd: scan.options.wordlist.perDomain[0], log };
    };
    const tld = await run({ domains: ['example.com.tr'], bruteforce: 'smart' });
    assert.deepEqual([tld.pd.localeSource, tld.pd.locales, tld.pd.localeEvidence], ['tld', ['tr'], null], 'German words cannot move a .com.tr');
    assert.deepEqual(localeFiles(tld.log), ['locale/tr.txt']);
    const chosen = await run({ domains: ['example.com'], bruteforce: 'smart', locales: [] });
    assert.deepEqual([chosen.pd.localeSource, chosen.pd.locales, chosen.pd.localeEvidence], ['chosen', [], null]);
    const forced = await run({ domains: ['example.com'], bruteforce: 'smart', locales: ['de'] });
    assert.deepEqual([forced.pd.localeSource, forced.pd.locales], ['chosen', ['de']]);
    const small = await run({ domains: ['example.com'], bruteforce: 'small' });
    assert.deepEqual([small.pd.localeSource, small.pd.locales, small.pd.localeEvidence], [null, [], null], 'Small is language-neutral');
    assert.deepEqual(localeFiles(small.log), []);
    const override = await run({ domains: ['example.com'], bruteforce: 'smart', wordlist: ['www'] });
    assert.deepEqual([override.pd.localeSource, override.pd.localeEvidence], [null, null]);
  });

  test('several domains: each gets the packs its own evidence points to', async () => {
    clearWordlistCache();
    const zone = { 'example.com': { A: ['203.0.113.10'] }, 'example.net': { A: ['203.0.113.20'] }, 'example.org': { A: ['203.0.113.40'] } };
    const { fetchImpl, dns } = mkWorld({
      zone,
      anubis: {
        'example.com': ['destek.example.com', 'bayi.example.com', 'kampanya.example.com'],
        'example.net': ['kundenportal.example.net', 'rechnung.example.net', 'karriere.example.net'],
        'example.org': ['www.example.org']
      }
    });
    const scan = await runScan({
      domains: ['example.com', 'example.net', 'example.org'], sources: ['anubis'], bruteforce: 'smart', mine: false, ...QUIET, dns, fetchImpl
    });
    const by = new Map(scan.options.wordlist.perDomain.map((d) => [d.domain, d]));
    assert.deepEqual(by.get('example.com').locales, ['tr']);
    assert.deepEqual(by.get('example.net').locales, ['de']);
    assert.deepEqual([by.get('example.org').localeSource, by.get('example.org').locales], ['none', []]);
    assert.deepEqual(scan.options.wordlist.localePacks, ['de', 'tr']);
  });

  test('a locale pack the evidence picked that fails to load is reported as missing, not as used', async () => {
    clearWordlistCache();
    const A = 'example.com';
    const zone = { [A]: { A: ['203.0.113.10'], MX: [{ preference: 10, exchange: 'mx.example.com.tr' }] } };
    const { fetchImpl: inner, dns } = mkWorld({ zone });
    const fetchImpl = (input, init) => (String(input && input.href ? input.href : input).endsWith('/locale/tr.txt')
      ? Promise.resolve(new Response('', { status: 404 })) : inner(input, init));
    const scan = await runScan({ domains: [A], sources: [], bruteforce: 'smart', mine: true, wordlistPreferFetch: true, ...QUIET, dns, fetchImpl });
    const pd = scan.options.wordlist.perDomain[0];
    assert.deepEqual([pd.localeSource, pd.locales], ['evidence', []], 'chosen from evidence, not loaded');
    assert.deepEqual(scan.options.wordlist.localesMissing, ['tr']);
    assert.ok(scan.warnings.some((w) => w.code === 'WORDLIST_DEGRADED' && w.detail.includes('locale:tr')));
    clearWordlistCache();
  });
});

describe('the query estimate counts what the evidence may add', () => {
  test('evidencePackMax: the three largest packs', () => {
    const sizes = Object.values(wordlistInfo().locales).map((l) => l.approxCount).sort((a, b) => b - a);
    assert.equal(LOCALE_EVIDENCE_MAX_PACKS, 3);
    assert.equal(evidencePackMax(), sizes[0] + sizes[1] + sizes[2]);
  });

  test('only the ceiling grows, only for a domain whose TLD names no market under the automatic choice', () => {
    const generic = estimateQueries({ bruteforce: 'smart', domains: ['example.com'] });
    assert.equal(generic.breakdown.localeEvidence, evidencePackMax());
    const forced = estimateQueries({ bruteforce: 'smart', domains: ['example.com'], locales: [] });
    assert.equal(forced.breakdown.localeEvidence, 0);
    assert.equal(generic.min, forced.min, 'the floor is the same');
    assert.ok(generic.max > forced.max, 'the ceiling counts the packs the evidence may add');
    assert.equal(estimateQueries({ bruteforce: 'smart', domains: ['example.com.tr'] }).breakdown.localeEvidence, 0, 'the TLD decides');
    assert.equal(estimateQueries({ bruteforce: 'small', domains: ['example.com'] }).breakdown.localeEvidence, 0, 'Small is language-neutral');
    assert.equal(estimateQueries({ bruteforce: 'off', domains: ['example.com'] }).breakdown.localeEvidence, 0);
    const two = estimateQueries({ bruteforce: 'smart', domains: ['example.com', 'example.de', 'example.net'] });
    assert.equal(two.breakdown.localeEvidence, 2 * evidencePackMax(), 'per domain without TLD packs');
  });
});
