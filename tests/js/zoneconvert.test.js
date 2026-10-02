// Unit tests for assets/js/lib/zoneconvert.js — a zone written as BIND, a Route 53 change batch,
// octoDNS YAML and DNSControl (Zone File › Convert). No network. Every output is pinned by the
// goldens of tests/fixtures/zoneconvert/gen-convert-golden.mjs, and every one reads back: the BIND,
// Route 53 and octoDNS files through lib/zoneparse.js, dnsconfig.js by running it against stub
// DNSControl functions; lib/zonediff.js then finds the same record sets, less what the pitfalls say
// was left out or written differently. Documentation data only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseZone } from '../../assets/js/lib/zoneparse.js';
import { diffZones } from '../../assets/js/lib/zonediff.js';
import {
  convertZone, convertFilename, pitfallKey, pitfallKeys, route53String, route53Name, yamlString, octodnsTxt, naturalCompare,
  CONVERT_TARGETS, TARGET_TYPES, TARGET_BY_HAND, TARGET_NAMES, CONVERT_MIME, PITFALL_CODES, PITFALL_SEVERITY, PITFALL_VARIANTS, ROUTE53_BATCH_MAX,
  ROUTE53_ROUTING, DNSSEC_TYPES, PSEUDO_TYPES, CAA_COMMON_TAGS, OCTODNS_SVC_KEYS
} from '../../assets/js/lib/zoneconvert.js';
import { CASES, caseGolden, caseZone, goldenPath, CONVERT_DIR } from '../fixtures/zoneconvert/gen-convert-golden.mjs';

const ZONES = join(CONVERT_DIR, '..', 'zones');
const bind = (text, origin = 'example.com') => parseZone(`$ORIGIN ${origin}.\n$TTL 3600\n${text}\n`, { format: 'bind' });
const codes = (res) => res.pitfalls.map((p) => `${p.severity}:${p.code}`);
const pit = (res, code) => res.pitfalls.find((p) => p.code === code) || null;
/** The targets that keep a TXT value as one text and split it again every 255 bytes. */
const JOINS_TXT = ['octodns', 'dnscontrol'];

/** Every parseable zone fixture: tests/fixtures/zones (one per format and dialect), the pitfalls zone, the diff pair. */
function fixtureZones() {
  const out = [];
  for (const f of readdirSync(ZONES)) {
    if (!/\.(txt|json|yaml)$/.test(f) || /^cloudflare-api-page/.test(f)) continue;
    const z = parseZone(readFileSync(join(ZONES, f), 'utf8').replace(/\r\n/g, '\n'), { filename: f });
    if (!z.fatal && z.origin) out.push([f, z]);
  }
  for (const c of CASES.slice(0, 1)) out.push([c.name, caseZone(c)]);
  for (const f of ['before.zone.txt', 'after.route53.json']) {
    out.push([f, parseZone(readFileSync(join(CONVERT_DIR, '..', 'zonediff', f), 'utf8').replace(/\r\n/g, '\n'), { filename: f })]);
  }
  return out;
}

/**
 * The source as a target should give it back: what was left out removed; an apex CNAME or a
 * provider's ANAME written as ALIAS (octoDNS, DNSControl) as an ALIAS record, which the parser keeps
 * as text; for a format that merges routing variants (any but a Route 53 policy it writes), the
 * routing dropped; the DNS-only records of a mixed set proxied (octoDNS); CAA flags other than
 * 0 / 128 as 0 (DNSControl).
 */
function expected(zone, res, target) {
  const gone = new Set(res.omitted.map((x) => x.id));
  const asAlias = new Set(res.changed.filter((x) => x.code === 'cname-apex' || x.code === 'alias-record').map((x) => x.id));
  const mixed = new Set(res.changed.filter((x) => x.code === 'proxied-mixed').map((x) => x.id));
  // The routing a format keeps: Route 53's own policies in a change batch, every AWS policy in a BIND comment (cli53 syntax).
  const keeps = { route53: ROUTE53_ROUTING, bind: [...ROUTE53_ROUTING, 'ip-based', 'geoproximity'] }[target] || [];
  const records = zone.records.filter((r) => !gone.has(r.id)).map((r) => {
    const x = { ...r };
    if (asAlias.has(r.id)) Object.assign(x, { type: 'ALIAS', data: null, text: r.type === 'CNAME' ? `${r.data}.` : r.text });
    if (r.routing && !keeps.includes(r.routing.policy)) delete x.routing;
    if (mixed.has(r.id)) x.proxied = true;
    if (target === 'dnscontrol' && r.type === 'CAA' && r.data && ![0, 128].includes(r.data.flags)) x.data = { ...r.data, flags: 0 };
    return x;
  });
  // One TTL per record set outside BIND: the lowest of its values.
  if (target !== 'bind') {
    const key = (r) => `${r.name}|${r.type}|${r.routing ? r.routing.id : ''}`;
    const low = new Map();
    for (const r of records) if (Number.isFinite(r.ttl)) low.set(key(r), Math.min(low.get(key(r)) ?? Infinity, r.ttl));
    for (const r of records) if (low.has(key(r)) && Number.isFinite(r.ttl)) r.ttl = low.get(key(r));
  }
  return { ...zone, records };
}

/* ------------------------------------------------------------------------ */
/* DNSControl: dnsconfig.js run against stub functions                      */
/* ------------------------------------------------------------------------ */

const RECORD_FNS = ['A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'DNAME', 'DS', 'HTTPS', 'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'RP', 'SMIMEA', 'SRV',
  'SSHFP', 'SVCB', 'TLSA', 'TXT', 'R53_ALIAS'];

/** Run a dnsconfig.js: { domain, registrar, provider, defaultTtl, records: [{ fn, args, mods }] }. */
function runDnsconfig(text) {
  const out = { domains: [] };
  const rec = (fn) => (...args) => {
    const mods = args.filter((a) => a && typeof a === 'object' && a.mod);
    return { fn, args: args.filter((a) => !(a && typeof a === 'object' && a.mod)), mods };
  };
  const api = {
    NewRegistrar: (name) => ({ registrar: name }),
    NewDnsProvider: (name) => ({ provider: name }),
    DnsProvider: (p) => ({ dsp: p }),
    DefaultTTL: (n) => ({ defaultTtl: n }),
    TTL: (n) => ({ mod: 'ttl', n }),
    R53_ZONE: (id) => ({ mod: 'zone', id }),
    R53_EVALUATE_TARGET_HEALTH: (on) => ({ mod: 'eth', on }),
    CF_PROXY_ON: { mod: 'proxied' },
    CAA_CRITICAL: { mod: 'critical' },
    DISABLE_REPEATED_DOMAIN_CHECK: { mod: 'repeat' },
    END: { end: true },
    D: (name, registrar, ...items) => {
      const dom = { name, registrar, provider: null, defaultTtl: null, records: [] };
      for (const it of items) {
        if (it && it.dsp) dom.provider = it.dsp.provider;
        else if (it && it.defaultTtl) dom.defaultTtl = it.defaultTtl;
        else if (it && it.fn) dom.records.push(it);
        else if (!it || !it.end) throw new Error(`unexpected item ${JSON.stringify(it)}`);
      }
      out.domains.push(dom);
    }
  };
  for (const fn of RECORD_FNS) api[fn] = rec(fn);
  // eslint-disable-next-line no-new-func
  new Function(...Object.keys(api), text)(...Object.values(api));
  return out;
}

/** A BIND string for a DNSControl string argument (TXT data, CAA value …). */
const q = (s) => `"${String(s).replace(/[\\"]/g, (c) => `\\${c}`)}"`;

/**
 * DNSControl's TXT(): a list of strings is joined into one text (pkg/js/helpers.js), which it
 * splits again every 255 bytes; here as the quoted strings of a BIND line, bytes past ASCII as \DDD.
 */
function dnscontrolTxt(arg) {
  const bytes = new TextEncoder().encode(Array.isArray(arg) ? arg.join('') : String(arg));
  const out = [];
  for (let i = 0; i < Math.max(bytes.length, 1); i += 255) {
    let s = '';
    for (const b of bytes.subarray(i, i + 255)) {
      s += b === 0x22 || b === 0x5c ? `\\${String.fromCharCode(b)}` : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\${String(b).padStart(3, '0')}`;
    }
    out.push(`"${s}"`);
  }
  return out.join(' ');
}

/** The DNSControl records as a zone (BIND lines read by the parser); Route 53 aliases counted, not parsed. */
function dnscontrolZone(text, origin) {
  const { domains } = runDnsconfig(text);
  assert.equal(domains.length, 1, 'one D()');
  const d = domains[0];
  assert.equal(d.name, origin);
  assert.equal(d.registrar.registrar, 'none');
  const lines = [];
  let aliases = 0;
  for (const r of d.records) {
    const ttl = (r.mods.find((m) => m.mod === 'ttl') || { n: d.defaultTtl }).n;
    const [name, ...a] = r.args;
    let rdata;
    switch (r.fn) {
      case 'R53_ALIAS': aliases += 1; continue;
      case 'TXT': rdata = dnscontrolTxt(a[0]); break;
      case 'CAA': rdata = `${r.mods.some((m) => m.mod === 'critical') ? 128 : 0} ${a[0]} ${q(a[1])}`; break;
      case 'NAPTR': rdata = `${a[0]} ${a[1]} ${q(a[2])} ${q(a[3])} ${q(a[4])} ${a[5]}`; break;
      case 'HTTPS': case 'SVCB': rdata = `${a[0]} ${a[1]} ${a[2]}`; break;
      default: rdata = a.join(' ');
    }
    // CF_PROXY_ON or not: DNSControl's Cloudflare provider turns the proxy off where a call has none.
    const proxied = ['A', 'AAAA', 'CNAME'].includes(r.fn) ? ` ; cf_tags=cf-proxied:${r.mods.some((m) => m.mod === 'proxied')}` : '';
    lines.push(`${name} ${ttl} IN ${r.fn} ${rdata}${proxied}`);
  }
  return { zone: bind(lines.join('\n'), origin), aliases, domain: d };
}

/* ------------------------------------------------------------------------ */

describe('vocabulary', () => {
  test('targets, names, media types, file names', () => {
    assert.deepEqual(CONVERT_TARGETS, ['bind', 'route53', 'octodns', 'dnscontrol']);
    assert.deepEqual(TARGET_NAMES, { bind: 'BIND', route53: 'Route 53', octodns: 'octoDNS', dnscontrol: 'DNSControl' });
    for (const t of CONVERT_TARGETS) assert.ok(CONVERT_MIME[t].endsWith('charset=utf-8'), t);
    assert.deepEqual(CONVERT_TARGETS.map((t) => convertFilename('Example.COM.', t)), ['example.com.zone', 'example.com.route53.json', 'example.com.yaml', 'dnsconfig.js']);
  });

  test('record types per target: CAA, SRV, TLSA, HTTPS and SVCB everywhere; what each has besides; DNSSEC and pseudo types nowhere', () => {
    assert.equal(TARGET_TYPES.bind, null);
    for (const target of ['route53', 'octodns', 'dnscontrol']) {
      for (const t of ['CAA', 'SRV', 'TLSA', 'HTTPS', 'SVCB', 'SSHFP', 'DS', 'NAPTR']) assert.ok(TARGET_TYPES[target].includes(t), `${target} ${t}`);
      for (const t of [...DNSSEC_TYPES, ...PSEUDO_TYPES, 'SOA']) assert.ok(!TARGET_TYPES[target].includes(t), `${target} ${t}`);
      for (const t of TARGET_BY_HAND[target]) assert.ok(!TARGET_TYPES[target].includes(t), `${target} ${t}: written or by hand, not both`);
    }
    assert.deepEqual(['URI', 'OPENPGPKEY', 'DNAME', 'RP', 'SMIMEA'].filter((t) => TARGET_TYPES.octodns.includes(t)), ['URI', 'OPENPGPKEY', 'DNAME']);
    assert.deepEqual(['URI', 'OPENPGPKEY', 'DNAME', 'RP', 'SMIMEA'].filter((t) => TARGET_TYPES.dnscontrol.includes(t)), ['OPENPGPKEY', 'DNAME', 'RP', 'SMIMEA']);
    assert.deepEqual(TARGET_BY_HAND, { bind: [], route53: [], octodns: ['LOC', 'URLFWD'], dnscontrol: ['DHCID', 'LOC'] });
    assert.deepEqual(CAA_COMMON_TAGS, ['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone']);
    assert.deepEqual(OCTODNS_SVC_KEYS, ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ipv6hint'], 'not ech: octoDNS\'s check of it fails');
  });

  test('pitfalls: a severity per target; worded per target where the target differs; every key listed', () => {
    assert.deepEqual(PITFALL_CODES, Object.keys(PITFALL_SEVERITY));
    for (const code of PITFALL_CODES) {
      for (const [target, sev] of Object.entries(PITFALL_SEVERITY[code])) {
        assert.ok(CONVERT_TARGETS.includes(target), `${code}: ${target}`);
        assert.ok(['error', 'warn', 'info'].includes(sev), `${code} ${target}: ${sev}`);
      }
    }
    for (const [code, targets] of Object.entries(PITFALL_VARIANTS)) {
      for (const t of targets) assert.ok(PITFALL_SEVERITY[code][t], `${code}.${t} has a severity`);
    }
    assert.equal(pitfallKey('cname-apex', 'route53'), 'zconv.pit.cname-apex.route53');
    assert.equal(pitfallKey('caa-flags', 'route53'), 'zconv.pit.caa-flags');
    assert.equal(pitfallKey('caa-flags', 'dnscontrol'), 'zconv.pit.caa-flags.dnscontrol');
    const keys = pitfallKeys();
    assert.ok(keys.includes('zconv.pit.wildcard') && keys.includes('zconv.pit.wildcard.route53') && keys.includes('zconv.pit.batch-size'));
    assert.equal(new Set(keys).size, keys.length);
  });

  test('a target it does not know, or a zone without a name, is refused', () => {
    assert.throws(() => convertZone(bind('@ A 192.0.2.1'), 'terraform'), RangeError);
    assert.throws(() => convertZone(parseZone(''), 'bind'), TypeError);
    assert.throws(() => convertZone({ ...bind('@ A 192.0.2.1'), origin: null }, 'bind'), TypeError);
  });
});

describe('strings', () => {
  test('Route 53: octal escapes for bytes outside printable ASCII, quotes and backslashes escaped', () => {
    assert.equal(route53String('say "hi"\\'), '"say \\"hi\\"\\\\"');
    assert.equal(route53String('käse'), '"k\\303\\244se"');
    assert.equal(route53Name('a\\032b.example.com'), 'a\\040b.example.com.');
    assert.equal(route53Name('*.apps.example.com'), '*.apps.example.com.');
    assert.equal(route53Name('a.*.inner.example.com'), 'a.\\052.inner.example.com.', 'an inner * is a literal character');
    assert.equal(route53Name('dot\\.label.example.com'), 'dot\\056label.example.com.');
    assert.equal(route53Name('example.com.'), 'example.com.');
  });

  test('YAML: plain, single-quoted, double-quoted with escapes for control characters', () => {
    assert.equal(yamlString('mail.example.com.'), 'mail.example.com.');
    assert.equal(yamlString('192.0.2.10'), "'192.0.2.10'");
    for (const s of ['null', 'yes', 'on', '1e5', '']) assert.equal(yamlString(s), `'${s}'`, s);
    assert.equal(yamlString("it's"), "'it''s'");
    assert.equal(yamlString('a\tb'), '"a\\x09b"');
    assert.equal(yamlString('*'), "'*'");
  });

  test('YAML: whatever PyYAML would read as a number or a date is quoted (octoDNS reads its files with it)', () => {
    for (const s of ['0x1f', '0b101', '1_000', '017', '10', '1.5', '1_0.5', '2026-10-02', '0XFF']) assert.equal(yamlString(s), `'${s}'`, s);
    for (const s of ['20260601._domainkey', '1a', 'e5', '_443._tcp', 'ns1', '0xzz']) assert.equal(yamlString(s), s, s);
  });

  test('octoDNS TXT: joined, the raw text with ; escaped and nothing else (octoDNS to_raw_text undoes only \\;)', () => {
    assert.equal(octodnsTxt(['v=DKIM1; ', 'p=abc']), 'v=DKIM1\\; p=abc');
    assert.equal(octodnsTxt('a\\b;'), 'a\\b\\;');
  });

  test('octoDNS: what its own checks refuse is written lenient (TXT outside ASCII or \\ before ;, SRV / URI off a _service._proto name)', () => {
    const z = bind([
      'cafe TXT "caf\\195\\169"', 'semi TXT "a\\\\;b"', 'plain TXT "v=spf1 -all"',
      '_sip._tcp SRV 10 60 5060 sip.example.com.', 'sip SRV 10 60 5060 sip.example.com.', '*.wild SRV 1 1 443 www.example.com.', 'u URI 10 1 "https://www.example.com/"'
    ].join('\n'));
    const res = convertZone(z, 'octodns');
    assert.deepEqual([pit(res, 'txt-lenient').names, pit(res, 'name-lenient').names, pit(res, 'name-lenient').params.types], [['cafe', 'semi'], ['sip', 'u'], ['SRV', 'URI']]);
    assert.match(res.text, /^cafe:\n {2}octodns:\n {4}lenient: true\n {2}ttl: 3600\n {2}type: TXT\n {2}value: 'café'$/m);
    assert.match(res.text, /^semi:\n {2}octodns:\n {4}lenient: true\n {2}ttl: 3600\n {2}type: TXT\n {2}value: 'a\\\\;b'$/m);
    assert.match(res.text, /^plain:\n {2}ttl: 3600\n/m);
    assert.match(res.text, /^_sip\._tcp:\n {2}ttl: 3600\n/m);
    assert.match(res.text, /^sip:\n {2}octodns:\n {4}lenient: true\n/m);
    const back = parseZone(res.text, { filename: res.filename });
    assert.deepEqual(diffZones(z, back).rows.filter((r) => r.status !== 'same').map((r) => r.key), []);
  });

  test('natural order as octoDNS checks it (natsort): digits as numbers, a prefix first', () => {
    const keys = ['www', 'ns10', '', 'ns2', '_dmarc', '*.apps', 'a1', 'a', '_443._tcp', 'null'];
    assert.deepEqual([...keys].sort(naturalCompare), ['', '*.apps', '_443._tcp', '_dmarc', 'a', 'a1', 'ns2', 'ns10', 'null', 'www']);
  });

  test('natural order: text before numbers at the start, numbers of any size, leading zeros equal (their order kept)', () => {
    assert.deepEqual(['b', '10', '9', 'a', '1a'].sort(naturalCompare), ['1a', '9', '10', 'a', 'b'], "'' (a key that starts with a digit) sorts before any text");
    const big = ['h12345678901234567891', 'h12345678901234567890', 'h99'];
    assert.deepEqual([...big].sort(naturalCompare), ['h99', 'h12345678901234567890', 'h12345678901234567891'], 'past 2^53, still in order');
    assert.equal(naturalCompare('ns01', 'ns1'), 0);
    assert.deepEqual(['ns1', 'ns01', 'ns001'].sort(naturalCompare), ['ns1', 'ns01', 'ns001'], 'equal keys keep their order, as Python\'s sorted() does');
    assert.deepEqual(['key65000', 'key7', 'ipv6hint', 'ipv4hint', 'alpn'].sort(naturalCompare), ['alpn', 'ipv4hint', 'ipv6hint', 'key7', 'key65000']);
  });
});

describe('goldens (node tests/fixtures/zoneconvert/gen-convert-golden.mjs --write after a deliberate change)', () => {
  test('each input in every format matches its golden', () => {
    for (const c of CASES) {
      const want = readFileSync(goldenPath(c.id), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(caseGolden(c), want, c.id);
    }
  });

  test('the outputs are deterministic', () => {
    const z = caseZone(CASES[0]);
    for (const t of CONVERT_TARGETS) assert.deepEqual(convertZone(z, t), convertZone(z, t), t);
  });
});

describe('round trips: every file reads back to the same record sets', () => {
  const zones = fixtureZones();

  test('the fixtures cover every format the parser reads', () => {
    const formats = new Set(zones.map(([, z]) => z.format));
    for (const f of ['bind', 'route53', 'octodns', 'cloudflare-api', 'plesk-info']) assert.ok(formats.has(f), f);
    assert.ok(zones.length >= 15, `${zones.length} zones`);
  });

  for (const target of ['bind', 'route53', 'octodns']) {
    test(`${target}: lib/zoneparse.js reads the file back; lib/zonediff.js finds no difference`, () => {
      for (const [file, zone] of zones) {
        const res = convertZone(zone, target);
        const back = parseZone(res.text, { origin: zone.origin, filename: res.filename });
        assert.equal(back.fatal, null, `${file} → ${target}: ${back.fatal && back.fatal.code}`);
        assert.equal(back.format, target === 'route53' ? 'route53' : target === 'octodns' ? 'octodns' : 'bind', `${file} → ${target}: format`);
        const loud = back.warnings.filter((w) => w.severity === 'error' || (w.severity === 'warn' && w.code !== 'OUT_OF_ZONE'));
        assert.deepEqual(loud.map((w) => w.code), [], `${file} → ${target}: issues reading it back`);
        const d = diffZones(expected(zone, res, target), back, { joinTxt: JOINS_TXT.includes(target) });
        const bad = d.rows.filter((r) => r.status !== 'same').map((r) => `${r.status} ${r.rel} ${r.type} ${r.reasons}`);
        assert.deepEqual(bad, [], `${file} → ${target}`);
        // Strings exactly, not only the joined text, wherever the format keeps them (BIND, Route 53).
        if (!JOINS_TXT.includes(target)) assert.equal(diffZones(expected(zone, res, target), back, { joinTxt: false }).counts.changed, 0, `${file} → ${target}: TXT strings`);
      }
    });
  }

  test('dnscontrol: dnsconfig.js runs against DNSControl\'s functions and gives the same record sets', () => {
    for (const [file, zone] of zones) {
      const res = convertZone(zone, 'dnscontrol');
      const { zone: back, aliases, domain } = dnscontrolZone(res.text, zone.origin);
      assert.equal(domain.provider, 'main', file);
      assert.ok(Number.isInteger(domain.defaultTtl), `${file}: DefaultTTL`);
      assert.equal(aliases, zone.records.filter((r) => r.alias && r.duplicateOf === undefined).length, `${file}: R53_ALIAS`);
      const want = expected(zone, res, 'dnscontrol');
      const d = diffZones({ ...want, records: want.records.filter((r) => !r.alias) }, back, { joinTxt: true });
      const bad = d.rows.filter((r) => r.status !== 'same').map((r) => `${r.status} ${r.rel} ${r.type} ${r.reasons}`);
      assert.deepEqual(bad, [], `${file} → dnscontrol`);
    }
  });

  test('octoDNS HTTPS / SVCB, URI and OPENPGPKEY read back; parameters octoDNS has no name for go by number', () => {
    const z = bind([
      'svc HTTPS 1 svc.example.net. mandatory=alpn,port alpn=h2,h3 no-default-alpn port=8443 ipv4hint=192.0.2.10 ipv6hint=2001:db8::10 ech=AEX+/w==',
      'doh SVCB 1 doh.example.net. mandatory=dohpath alpn=h2 dohpath=/dns-query{?dns} ohttp tls-supported-groups=29,23 key65000=a\\032b',
      'alias HTTPS 0 svc.example.net.',
      'uri URI 10 1 "https://www.example.com/"',
      'pgp OPENPGPKEY mQENBFtestAAEC'
    ].join('\n'));
    assert.deepEqual(z.records.map((r) => !!r.invalid), [false, false, false, false, false]);
    const res = convertZone(z, 'octodns');
    assert.match(res.text, /^doh:\n {2}ttl: 3600\n {2}type: SVCB\n {2}value:\n {4}svcparams:\n {6}alpn:\n {8}- h2\n {6}key7: '\/dns-query\{\?dns\}'\n {6}key8: null\n {6}key9: '29,23'\n {6}key65000: 'a\\032b'\n {6}mandatory:\n {8}- key7\n {4}svcpriority: 1\n {4}targetname: doh\.example\.net\.$/m);
    assert.match(res.text, /^ {6}ipv6hint:\n {8}- '2001:db8::10'\n {6}key5: 'AEX\+\/w=='\n {6}mandatory:\n {8}- alpn\n {8}- port\n {6}no-default-alpn: null\n {6}port: 8443\n {4}svcpriority: 1\n {4}targetname: svc\.example\.net\.$/m,
      'ech by number: octoDNS\'s check of a valid ech value fails');
    assert.match(res.text, /^alias:\n {2}ttl: 3600\n {2}type: HTTPS\n {2}value:\n {4}svcpriority: 0\n {4}targetname: svc\.example\.net\.$/m, 'AliasMode: no svcparams');
    assert.match(res.text, /^uri:\n {2}octodns:\n {4}lenient: true\n {2}ttl: 3600\n {2}type: URI\n {2}value:\n {4}priority: 10\n {4}target: 'https:\/\/www\.example\.com\/'\n {4}weight: 1$/m);
    assert.deepEqual([pit(res, 'svc-key').names, pit(res, 'svc-key').params.keys], [['svc', 'doh'], ['ech', 'dohpath', 'ohttp', 'tls-supported-groups']]);
    assert.equal(pit(res, 'unsupported-type'), null);
    const back = parseZone(res.text, { filename: res.filename });
    assert.deepEqual(back.warnings.filter((w) => w.severity !== 'info').map((w) => w.code), []);
    assert.deepEqual(diffZones(z, back).rows.filter((r) => r.status !== 'same').map((r) => r.key), []);
  });

  test('a Route 53 change batch is a format of its own: CREATE / UPSERT read, a DELETE left out and said', () => {
    const batch = JSON.stringify({ Comment: 'x', Changes: [
      { Action: 'UPSERT', ResourceRecordSet: { Name: 'www.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.10' }] } },
      { Action: 'CREATE', ResourceRecordSet: { Name: 'api.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.14' }] } },
      { Action: 'DELETE', ResourceRecordSet: { Name: 'old.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.50' }] } }
    ] });
    for (const text of [batch, JSON.stringify({ HostedZoneId: 'Z0EXAMPLE', ChangeBatch: JSON.parse(batch) })]) {
      const z = parseZone(text, { origin: 'example.com' });
      assert.equal(z.format, 'route53');
      assert.deepEqual(z.records.map((r) => `${r.name} ${r.type} ${r.text}`), ['www.example.com A 192.0.2.10', 'api.example.com A 192.0.2.14']);
      assert.deepEqual(z.warnings.filter((w) => w.code === 'CHANGE_BATCH').map((w) => w.params), [{ upserts: 2, deletes: 1 }]);
      assert.ok(z.markers.includes('Changes'));
    }
  });
});

describe('pitfalls', () => {
  test('a CNAME at the apex: commented out in BIND, left out of Route 53 (error), ALIAS in octoDNS and DNSControl', () => {
    const z = bind('@ SOA ns1 host 1 2 3 4 5\n@ NS ns1\n@ 300 CNAME target.example.net.\nns1 A 192.0.2.53');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.match(out.bind.text, /^; CNAME at the apex: [^\n]+\n; @ +300 IN CNAME target\.example\.net\.$/m);
    assert.deepEqual(pit(out.bind, 'cname-apex'), { code: 'cname-apex', severity: 'warn', count: 1, names: ['@'], params: { target: 'BIND' } });
    assert.equal(pit(out.route53, 'cname-apex').severity, 'error');
    assert.ok(!out.route53.text.includes('target.example.net'));
    assert.match(out.octodns.text, /^'':\n {2}ttl: 300\n {2}type: ALIAS\n {2}value: target\.example\.net\.$/m);
    assert.match(out.dnscontrol.text, /^ {4}ALIAS\("@", "target\.example\.net\."(, TTL\(300\))?\),$/m);
    for (const t of ['octodns', 'dnscontrol']) assert.deepEqual([pit(out[t], 'cname-apex').severity, out[t].changed.length], ['info', 1], t);
  });

  test('TXT over 255 bytes: several strings in BIND, one value of several strings in Route 53, one text in octoDNS and DNSControl', () => {
    const long = 'v=DKIM1; p='.padEnd(300, 'A');
    const z = parseZone(JSON.stringify({ ResourceRecordSets: [{ Name: 'k._domainkey.example.com.', Type: 'TXT', TTL: 300, ResourceRecords: [{ Value: `"${long.slice(0, 255)}" "${long.slice(255)}"` }] }] }), { origin: 'example.com' });
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    for (const t of CONVERT_TARGETS) assert.deepEqual([pit(out[t], 'txt-long').severity, pit(out[t], 'txt-long').names], ['info', ['k._domainkey']], t);
    assert.ok(out.bind.text.includes(`"${long.slice(0, 255)}" "${long.slice(255)}"`));
    assert.equal(JSON.parse(out.route53.text).Changes[0].ResourceRecordSet.ResourceRecords[0].Value, `"${long.slice(0, 255)}" "${long.slice(255)}"`);
    assert.ok(out.octodns.text.includes(`value: '${long.replace(';', '\\;')}'`));
    assert.ok(out.dnscontrol.text.includes(`TXT("k._domainkey", "${long}")`), 'DNSControl joins a list anyway and splits it again');
    for (const t of CONVERT_TARGETS) assert.equal(pit(out[t], 'txt-split'), null, `${t}: split every 255 bytes, as the targets split it`);
  });

  test('TXT split elsewhere than every 255 bytes: octoDNS and DNSControl split the text again (the strings change, not the text)', () => {
    const z = bind('split TXT "v=spf1 " "include:_spf.example.net " "-all"');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.deepEqual(CONVERT_TARGETS.map((t) => (pit(out[t], 'txt-split') || {}).severity || null), [null, null, 'info', 'info']);
    assert.ok(out.bind.text.includes('"v=spf1 " "include:_spf.example.net " "-all"'));
    assert.ok(out.dnscontrol.text.includes('TXT("split", "v=spf1 include:_spf.example.net -all")'));
  });

  test('Route 53 aliases: kept in Route 53, R53_ALIAS in DNSControl, commented out in BIND, left out of octoDNS', () => {
    const z = caseZone(CASES.find((c) => c.id === 'route53'));
    const n = z.records.filter((r) => r.alias).length;
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.equal(JSON.parse(out.route53.text).Changes.filter((c) => c.ResourceRecordSet.AliasTarget).length, n);
    assert.equal(pit(out.route53, 'r53-alias'), null);
    assert.equal((out.dnscontrol.text.match(/^ {4}R53_ALIAS\(/gm) || []).length, n);
    assert.equal(pit(out.dnscontrol, 'r53-alias').severity, 'info');
    assert.equal((out.bind.text.match(/^; Route 53 alias, no equivalent here/gm) || []).length, n);
    assert.ok(!/^\S+\s+\S*\s*AWS ALIAS/m.test(out.bind.text), 'no cli53 line a name server cannot read');
    assert.deepEqual([pit(out.bind, 'r53-alias').severity, pit(out.octodns, 'r53-alias').severity], ['warn', 'warn']);
  });

  test('Cloudflare proxy: cf_tags comments in BIND, lost in Route 53 (warn), octodns.cloudflare.proxied, CF_PROXY_ON', () => {
    const z = bind('www 300 A 192.0.2.10 ; cf_tags=cf-proxied:true\napi 300 A 192.0.2.14 ; cf_tags=cf-proxied:false');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.match(out.bind.text, /^www +300 IN A +192\.0\.2\.10 ; cf_tags=cf-proxied:true$/m);
    assert.deepEqual(CONVERT_TARGETS.map((t) => pit(out[t], 'proxied').severity), ['info', 'warn', 'info', 'info']);
    assert.deepEqual(pit(out.route53, 'proxied').names, ['www']);
    assert.ok(!out.route53.text.includes('proxied'));
    assert.match(out.octodns.text, /^www:\n {2}octodns:\n {4}cloudflare:\n {6}proxied: true\n/m);
    assert.match(out.octodns.text, /^api:\n {2}octodns:\n {4}cloudflare:\n {6}proxied: false\n/m);
    assert.ok(out.dnscontrol.text.includes('A("www", "192.0.2.10", TTL(300), CF_PROXY_ON)') || out.dnscontrol.text.includes('A("www", "192.0.2.10", CF_PROXY_ON)'));
  });

  test('CAA: flags other than 0 / 128 and unknown tags flagged outside BIND; 128 is CAA_CRITICAL; DNSControl comments out a tag it refuses', () => {
    const z = bind('@ CAA 128 issue "ca.example.net"\n@ CAA 1 issuewild ";"\n@ CAA 0 policy "x"\n@ CAA 0 contactemail "security@example.com"');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.deepEqual(codes(out.bind).filter((c) => c.includes('caa')), [], 'BIND writes any CAA record');
    for (const t of ['route53', 'octodns', 'dnscontrol']) {
      assert.deepEqual([pit(out[t], 'caa-flags').params.flags, pit(out[t], 'caa-tag').params.tags], [[1], ['policy']], t);
    }
    assert.deepEqual(['route53', 'octodns', 'dnscontrol'].map((t) => pit(out[t], 'caa-tag').severity), ['info', 'info', 'warn']);
    assert.ok(out.dnscontrol.text.includes('CAA("@", "issue", "ca.example.net", CAA_CRITICAL)'));
    assert.ok(out.dnscontrol.text.includes('CAA("@", "issuewild", ";")'), 'flag 1 is lost (and said so)');
    assert.ok(out.dnscontrol.text.includes('CAA("@", "contactemail", "security@example.com")'), 'a tag DNSControl knows');
    assert.match(out.dnscontrol.text, /^ {4}\/\/ not written \(a CAA tag DNSControl refuses\): @ CAA 0 policy "x"$/m);
    assert.deepEqual(out.dnscontrol.omitted.map((x) => x.code), ['caa-tag']);
    assert.ok(JSON.parse(out.route53.text).Changes[0].ResourceRecordSet.ResourceRecords.some((v) => v.Value === '0 policy "x"'), 'Route 53 gets it (it may refuse it)');
    assert.equal(pitfallKey('caa-flags', 'dnscontrol'), 'zconv.pit.caa-flags.dnscontrol');
    assert.equal(pitfallKey('caa-tag', 'dnscontrol'), 'zconv.pit.caa-tag.dnscontrol');
  });

  test('unsupported types are marked, never dropped silently: commented in BIND / DNSControl, listed for every target', () => {
    const z = bind('svc HTTPS 1 . alpn=h2\nx ALIAS target.example.net.\nu URI 10 1 "https://www.example.com/"\nr RP hostmaster.example.com. .');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.deepEqual(pit(out.bind, 'unsupported-type').params.types, ['ALIAS']);
    assert.match(out.bind.text, /^; x +3600 IN ALIAS target\.example\.net\.$/m);
    assert.deepEqual(pit(out.route53, 'unsupported-type').params.types, ['ALIAS', 'URI', 'RP']);
    assert.deepEqual(pit(out.octodns, 'unsupported-type').params.types, ['ALIAS', 'RP'], 'octoDNS: ALIAS only at the apex, no RP');
    assert.deepEqual(pit(out.dnscontrol, 'unsupported-type').params.types, ['URI']);
    assert.match(out.dnscontrol.text, /^ {4}\/\/ not written \(not a record type this format holds\): u URI 10 1 "https:\/\/www\.example\.com\/"$/m);
    assert.ok(out.dnscontrol.text.includes('    RP("r", "hostmaster.example.com.", "."),'));
    for (const t of CONVERT_TARGETS) {
      const listed = out[t].omitted.length;
      assert.equal(listed, pit(out[t], 'unsupported-type').count, `${t}: every one left out is counted`);
    }
  });

  test('a CNAME not alone at its name (next to other records, or two CNAMEs) is an error for every target; its DNSSEC records may stay', () => {
    const z = bind('www CNAME host.example.net.\nwww A 192.0.2.17\ntwo CNAME a.example.net.\ntwo CNAME b.example.net.\nok CNAME host.example.net.\nsig CNAME host.example.net.\nsig NSEC sig2.example.com. CNAME RRSIG NSEC');
    for (const t of CONVERT_TARGETS) {
      const p = pit(convertZone(z, t), 'cname-alone');
      assert.deepEqual([p.severity, p.names, p.count], ['error', ['www', 'two'], 2], t);
    }
    assert.equal(pit(convertZone(bind('ok CNAME host.example.net.'), 'route53'), 'cname-alone'), null);
    const routed = caseZone(CASES.find((c) => c.id === 'route53'));
    assert.equal(pit(convertZone(routed, 'route53'), 'cname-alone'), null, 'weighted CNAMEs of one name are sets of their own in Route 53');
  });

  test('DNSControl: a name that repeats the zone name gets DISABLE_REPEATED_DOMAIN_CHECK (it refuses it otherwise), and a warning', () => {
    const z = bind('example.com TXT "x"\nwww.example.com A 192.0.2.1\nwww A 192.0.2.2');
    const res = convertZone(z, 'dnscontrol');
    assert.ok(res.text.includes('    TXT("example.com", "x", DISABLE_REPEATED_DOMAIN_CHECK),'));
    assert.ok(res.text.includes('    A("www.example.com", "192.0.2.1", DISABLE_REPEATED_DOMAIN_CHECK),'));
    assert.ok(res.text.includes('    A("www", "192.0.2.2"),'));
    assert.deepEqual([pit(res, 'repeated-domain').severity, pit(res, 'repeated-domain').names, pit(res, 'repeated-domain').params.zone], ['warn', ['example.com', 'www.example.com'], 'example.com']);
    for (const t of ['bind', 'route53', 'octodns']) assert.equal(pit(convertZone(z, t), 'repeated-domain'), null, t);
  });

  test('a type the target has but DomainScope cannot write (LOC, DHCID, URLFWD) is left out "by hand", never called unsupported', () => {
    const z = bind('geo LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m\nd DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.deepEqual(codes(out.bind), ['warn:no-soa'], 'BIND writes them as the file has them');
    assert.match(out.bind.text, /^geo +3600 IN LOC +52 22 23\.000 N/m);
    assert.deepEqual([pit(out.octodns, 'by-hand').params.types, pit(out.octodns, 'unsupported-type').params.types], [['LOC'], ['DHCID']]);
    assert.deepEqual([pit(out.dnscontrol, 'by-hand').params.types, pit(out.dnscontrol, 'unsupported-type')], [['LOC', 'DHCID'], null]);
    assert.match(out.dnscontrol.text, /^ {4}\/\/ not written \(DomainScope cannot write this record type for this format: add it by hand\): geo LOC /m);
    assert.equal(pit(out.route53, 'by-hand'), null);
    assert.deepEqual(pit(out.route53, 'unsupported-type').params.types, ['LOC', 'DHCID']);
  });

  test('a provider\'s ALIAS / ANAME: DNSControl ALIAS(…) at any name, octoDNS an ALIAS record at the apex', () => {
    const z = bind('@ ANAME lb.example.net.\nwww ALIAS @\napi ALIAS lb\nbad ALIAS "two words"');
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    assert.match(out.dnscontrol.text, /^ {4}ALIAS\("@", "lb\.example\.net\."\),\n {4}ALIAS\("www", "example\.com\."\),\n {4}ALIAS\("api", "lb\.example\.com\."\),$/m);
    assert.deepEqual([pit(out.dnscontrol, 'alias-record').names, pit(out.dnscontrol, 'unreadable').names], [['@', 'www', 'api'], ['bad']]);
    assert.deepEqual(out.dnscontrol.changed, [{ id: 0, code: 'alias-record' }], 'an ANAME becomes an ALIAS');
    assert.match(out.octodns.text, /^'':\n {2}ttl: 3600\n {2}type: ALIAS\n {2}value: lb\.example\.net\.$/m);
    assert.deepEqual([pit(out.octodns, 'alias-record').names, pit(out.octodns, 'unsupported-type').names], [['@'], ['www', 'api', 'bad']]);
    for (const t of ['bind', 'route53']) assert.deepEqual(pit(out[t], 'unsupported-type').names, ['@', 'www', 'api', 'bad'], t);
  });

  test('wildcards, a * inside a name, duplicates, mixed TTLs, routing, names outside the zone, DNSSEC records', () => {
    const z = caseZone(CASES[0]);
    const out = Object.fromEntries(CONVERT_TARGETS.map((t) => [t, convertZone(z, t)]));
    for (const t of CONVERT_TARGETS) {
      assert.deepEqual(pit(out[t], 'wildcard').names, ['*.apps'], t);
      assert.equal(pit(out[t], 'wildcard-inner').severity, 'warn', t);
      assert.deepEqual([pit(out[t], 'duplicate').count, pit(out[t], 'dnssec').severity, pit(out[t], 'out-of-zone').severity], [1, 'warn', 'warn'], t);
    }
    assert.equal(pit(out.bind, 'ttl-mixed'), null, 'BIND keeps a TTL per record');
    for (const t of ['route53', 'octodns', 'dnscontrol']) assert.deepEqual(pit(out[t], 'ttl-mixed').names, ['ttls'], t);
    assert.equal(JSON.parse(out.route53.text).Changes.find((c) => c.ResourceRecordSet.Name === 'ttls.example.com.').ResourceRecordSet.TTL, 300, 'the lowest');
    const routed = caseZone(CASES.find((c) => c.id === 'route53'));
    const r53 = convertZone(routed, 'route53');
    assert.equal(pit(r53, 'routing'), null, 'Route 53 keeps its own policies');
    assert.ok(JSON.parse(r53.text).Changes.some((c) => c.ResourceRecordSet.SetIdentifier && c.ResourceRecordSet.Weight !== undefined));
    for (const t of ['bind', 'octodns', 'dnscontrol']) assert.equal(pit(convertZone(routed, t), 'routing').severity, 'warn', t);
  });

  test('octoDNS: one proxy flag per set, a mixed set becomes proxied and says which records changed', () => {
    const z = bind('m 300 A 192.0.2.1 ; cf_tags=cf-proxied:true\nm 300 A 192.0.2.2 ; cf_tags=cf-proxied:false');
    const res = convertZone(z, 'octodns');
    assert.deepEqual([pit(res, 'proxied-mixed').names, res.changed.map((x) => x.code)], [['m'], ['proxied-mixed']]);
    assert.equal(pit(convertZone(z, 'dnscontrol'), 'proxied-mixed'), null, 'DNSControl flags each record');
  });

  test('a source without an SOA (a provider export): BIND says to add one; SOA and apex NS left out elsewhere', () => {
    const api = caseZone({ file: join(ZONES, 'cloudflare-api.json'), name: 'cloudflare-api.json' });
    assert.equal(pit(convertZone(api, 'bind'), 'no-soa').severity, 'warn');
    const z = bind('@ SOA ns1 host 1 2 3 4 5\n@ NS ns1\n@ NS ns2.example.net.\nsub NS ns1.example.net.\nns1 A 192.0.2.53');
    for (const t of ['route53', 'octodns', 'dnscontrol']) {
      const res = convertZone(z, t);
      assert.deepEqual([pit(res, 'soa').count, pit(res, 'apex-ns').count], [1, 2], t);
      assert.ok(res.text.includes('ns1.example.net'), `${t}: a delegation below the apex stays`);
    }
    assert.equal(pit(convertZone(z, 'bind'), 'apex-ns'), null);
  });

  test('records without a TTL get the zone\'s default where the target needs one; a big zone needs several change batches', () => {
    const plesk = caseZone({ file: join(ZONES, 'plesk-info.txt'), name: 'plesk-info.txt' });
    if (plesk.records.some((r) => r.ttl === null)) {
      const res = convertZone(plesk, 'route53');
      assert.deepEqual(pit(res, 'ttl-default').params.ttl, 3600);
      assert.ok(JSON.parse(res.text).Changes.every((c) => Number.isInteger(c.ResourceRecordSet.TTL)));
    }
    const many = bind(Array.from({ length: ROUTE53_BATCH_MAX + 1 }, (_, i) => `h${i} A 192.0.2.${i % 250}`).join('\n'));
    const res = convertZone(many, 'route53');
    assert.deepEqual(pit(res, 'batch-size').params, { target: 'Route 53', max: ROUTE53_BATCH_MAX, records: ROUTE53_BATCH_MAX + 1 });
  });

  test('BIND: an owner that looks like a whole domain name is written absolute; $TTL is the zone\'s', () => {
    const z = bind('example.com.example.com. A 192.0.2.1\nwww A 192.0.2.2');
    const res = convertZone(z, 'bind');
    assert.match(res.text, /^example\.com\.example\.com\. +3600 IN A +192\.0\.2\.1$/m);
    assert.match(res.text, /^www +3600 IN A/m);
    assert.match(res.text, /^\$ORIGIN example\.com\.\n\$TTL 3600$/m);
    assert.deepEqual(parseZone(res.text, { format: 'bind' }).warnings.map((w) => w.code), []);
  });

  test('every pitfall a conversion raises has a text key in both languages\' table of keys', () => {
    const z = caseZone(CASES[0]);
    const all = new Set(pitfallKeys());
    for (const t of CONVERT_TARGETS) for (const p of convertZone(z, t).pitfalls) assert.ok(all.has(pitfallKey(p.code, t)), `${t} ${p.code}`);
  });
});
