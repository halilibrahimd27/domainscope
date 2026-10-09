/**
 * The headless runner's `watch` (tools/ds/watch.mjs, watchdiff.mjs, authoritative.mjs): its command
 * line and inputs, the change table (every tag, a CDN's rotating edges, the flapping window, TTLs
 * ignored without --ttl, what a failed lookup carries), the report target (flips, markers, carry),
 * offline nights of main() over tests/js/ds-fake-doh.mjs watchZone (a registrar change and a lock
 * removed in the registry's answers, an MX and a provider move, a CDN rotation, a registry outage, a
 * DS withdrawn), the name servers asked directly — fake authoritative servers on 127.0.0.1 and
 * 127.0.0.2 over UDP and TCP (a truncated answer, a lame server, a lagging secondary, servers out of
 * sync, port 53 blocked, an IPv6 address without a route, the query budget) —, PagerDuty's standings
 * and a spawned run with DS_FAKE_DOH=watch. Documentation names and addresses only.
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import dgram from 'node:dgram';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  parseCommandLine, UsageError, DS_TOOL, DS_VERSION, EXIT, USAGE, COMMAND_SPECS, WATCH_TYPES, WATCH_MAX_NAMES, WATCH_DEFAULT_QUERIES, watchTypesOption
} from '../../tools/ds/args.mjs';
import { baselineProblem, baselineNotes, diffReports, notableChanges } from '../../tools/ds/diff.mjs';
import { setupStrings, renderChangesMarkdown, CHANGE_TAGS } from '../../tools/ds/render.mjs';
import { watchInputs, watchNames, watchTarget, watchDoc, watchWarnings, classOf, readRecords, registrationPart } from '../../tools/ds/watch.mjs';
import { recordTone, txtKind, displayValue, cdnRotation, recentFlips, rrsetOf, FLAP_CHANGES, FLAP_RUNS } from '../../tools/ds/watchdiff.mjs';
import { askServer, checkAuthoritative, soaStanding } from '../../tools/ds/authoritative.mjs';
import { problemStanding } from '../../tools/ds/states.mjs';
import { eventSeverity, pagerDutyPlan } from '../../tools/ds/notify.mjs';
import { main, skippedWarnings } from '../../tools/ds.mjs';
import { renderPlainText } from '../../assets/js/lib/summary.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { watchZone, createWatchFetch, startAuthServer, CF_EDGES_V4 } from './ds-fake-doh.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DS = join(ROOT, 'tools', 'ds.mjs');
const NOW = new Date('2026-10-09T03:00:00Z');
const DAY = 86400000;
const t = await setupStrings();

const tmp = () => mkdtempSync(join(tmpdir(), 'ds-watch-'));
function sink() {
  return { text: '', isTTY: false, write(s) { this.text += s; return true; } };
}
const tags = (changes) => changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.target}${c.item ? ` ${c.item}` : ''} ${c.tone}`);
const text = (c) => c.parts.map((p) => (typeof p === 'string' ? p : p.code ?? p.strong ?? '')).join('');

/* ------------------------------------------------------------------------ */
/* Hand-made reports                                                        */
/* ------------------------------------------------------------------------ */

const APEX_TYPES = [...WATCH_TYPES];
/** A record set as the report keeps it. */
const rec = (name, type, values, extra = {}) => ({ key: `${name}|${type}`, name, type, values, ...extra });
/** A watch target as the report keeps it. */
function target(extra = {}) {
  return {
    target: 'example.com',
    checkedAt: '2026-10-08T03:00:00.000Z',
    runs: ['2026-10-08T03:00:00.000Z'],
    registration: {
      state: 'ok', registrar: 'Example Registrar, Inc.', ianaId: '9999', statuses: ['client delete prohibited', 'client transfer prohibited'],
      expires: '2027-11-13', daysLeft: 400, nameservers: ['ns1.example.net', 'ns2.example.net'], dnssecSigned: true
    },
    delegation: { ns: ['ns1.example.net', 'ns2.example.net'], ds: ['12345 13 2'], signed: 'validated' },
    names: ['example.com', 'www.example.com', '_dmarc.example.com', 'shop.example.com'],
    types: APEX_TYPES,
    delegated: [],
    nxdomain: [],
    classes: { 'example.com': 'cloudflare:cloudflare', 'www.example.com': 'cloudflare:cloudflare', 'shop.example.com': 'direct' },
    records: [
      rec('example.com', 'A', [CF_EDGES_V4[0], CF_EDGES_V4[1]]),
      rec('example.com', 'MX', ['10 mx.example.com']),
      rec('example.com', 'TXT', ['token google 0123456789ab', 'txt "v=spf1 include:_spf.example.net -all"']),
      rec('example.com', 'CAA', ['0 issue letsencrypt.org']),
      rec('example.com', 'SOA', ['ns1.example.net'], { serial: 2026100901 }),
      rec('example.com', 'DNSKEY', ['256 3 13 ZSKone', '257 3 13 KSKone']),
      rec('www.example.com', 'CNAME', ['example.com.cdn.cloudflare.net']),
      rec('shop.example.com', 'A', ['192.0.2.10']),
      rec('_dmarc.example.com', 'TXT', ['txt "v=DMARC1; p=reject"'])
    ],
    failures: [],
    ...extra
  };
}
const report = (targets, extra = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command: 'watch', startedAt: '2026-10-08T03:00:00.000Z', finishedAt: '2026-10-08T03:01:00.000Z',
  options: { types: APEX_TYPES, names: null, ttl: false, authoritative: false, resolvers: ['cloudflare'] }, targets, ...extra
});
/** This run's target: the baseline's with what `fn` changes (a deep copy). */
const next = (fn, base = target()) => {
  const x = structuredClone(base);
  x.checkedAt = '2026-10-09T03:00:00.000Z';
  x.runs = [...x.runs, '2026-10-09T03:00:00.000Z'];
  fn(x);
  return x;
};
const setRec = (x, name, type, values, extra = {}) => {
  x.records = x.records.filter((r) => r.key !== `${name}|${type}`);
  if (values) x.records.push(rec(name, type, values, extra));
};
const diff = (b, a, opts = {}) => diffReports('watch', report([b], opts.before || {}), report([a], opts.after || {}), { t });

/* ------------------------------------------------------------------------ */
/* Command line                                                             */
/* ------------------------------------------------------------------------ */

describe('watch: command line and inputs', () => {
  test('registrable domains (as audit), every record type by default, the options of a direct look', () => {
    const cl = parseCommandLine(['watch', 'www.Example.COM', 'https://shop.example.org/x', 'example.com']);
    assert.deepEqual(cl.targets, ['example.com', 'example.org']);
    assert.deepEqual([cl.options.types, cl.options.ttl, cl.options.authoritative, cl.options.names], [[...WATCH_TYPES], false, false, null]);
    assert.deepEqual(COMMAND_SPECS.watch.options, ['list', 'names', 'types', 'ttl', 'authoritative', 'max-queries']);
    const full = parseCommandLine(['watch', '--list', 'domains.txt', '--names', 'hosts.txt', '--types', 'mx,a,MX,txt', '--authoritative', '--ttl', '--max-queries', '500']);
    assert.deepEqual([full.options.types, full.options.ttl, full.options.authoritative, full.options.maxQueries, full.options.names], [['A', 'MX', 'TXT'], true, true, 500, 'hosts.txt']);
    assert.equal(parseCommandLine(['watch', 'example.com', '--authoritative']).options.maxQueries, WATCH_DEFAULT_QUERIES);
    assert.deepEqual(watchTypesOption(undefined), [...WATCH_TYPES]);
    assert.match(USAGE, /\n {2}watch DOMAIN\.\.\. {16}the registration, delegation and record change watch/);
  });

  test('refused before anything is sent', () => {
    const refused = [
      [['watch', 'example.com', '--types', 'A,PTR'], /--types: not a type the watch reads: "PTR" \(one of A, AAAA, CNAME/],
      [['watch', 'example.com', '--types', ' , '], /--types needs at least one record type/],
      [['watch', 'example.com', '--ttl'], /--ttl compares the TTLs the name servers give: it needs --authoritative \(a resolver's cache counts TTLs down\)/],
      [['watch', 'example.com', '--max-queries', '100'], /--max-queries bounds the questions to the name servers: it needs --authoritative/],
      [['watch', 'example.com', '--authoritative', '--max-queries', '20000'], /--max-queries takes a whole number from 1 to 10000/],
      [['watch', 'example.com', '--names', '-'], /--names takes a file, not "-"/],
      [['watch', 'example.com', '--names', 'hosts.txt', '--json', 'hosts.txt'], /--json names the same file as --names \(hosts\.txt\)/],
      [['watch', 'example.com', '--from-subdomains', 's.json'], /--from-subdomains applies to tls and takeover only, not to watch/],
      [['health', 'example.com', '--types', 'A'], /--types applies to watch only, not to health/],
      [['health', 'example.com', '--authoritative'], /--authoritative applies to watch only, not to health/],
      [['watch', 'not a domain'], /not a domain name: "not a domain"/],
      [['watch'], /watch needs at least one domain \(or --list FILE\)/]
    ];
    for (const [argv, re] of refused) assert.throws(() => parseCommandLine(argv), (err) => err instanceof UsageError && re.test(err.message), argv.join(' '));
    assert.throws(() => parseCommandLine(['drift', 'z.zone', '--types', 'A']), /--types applies to watch only/);
    assert.doesNotThrow(() => parseCommandLine(['drift', 'example.com.zone', '--max-queries', '100']), 'drift keeps its own budget');
  });

  test('--names: host names, read and checked before anything is sent; at most 200; the apex, www and _dmarc always', async () => {
    const files = { 'hosts.txt': 'shop.example.com\n_mta-sts.example.com # comment\nnot a host!\n', 'empty.txt': '# none\n', 'many.txt': Array.from({ length: WATCH_MAX_NAMES + 1 }, (_, i) => `h${i}.example.com`).join('\n') };
    const warned = [];
    const io = { read: async (path) => files[path], warn: (w) => warned.push(w), skipped: skippedWarnings };
    assert.deepEqual(await watchInputs({ names: 'hosts.txt' }, io), { file: 'hosts.txt', names: ['_mta-sts.example.com', 'shop.example.com'] });
    assert.deepEqual(warned, ['--names hosts.txt: skipped "not": not a host name', '--names hosts.txt: skipped "a": not a host name', '--names hosts.txt: skipped "host!": not a host name']);
    await assert.rejects(watchInputs({ names: 'empty.txt' }, io), /--names: empty\.txt lists no host name/);
    await assert.rejects(watchInputs({ names: 'many.txt' }, io), (err) => err instanceof UsageError && /lists 201 host names, at most 200: split the list/.test(err.message));
    assert.deepEqual(await watchInputs({ names: null }, io), { file: null, names: [] });
    assert.deepEqual(watchNames('example.com', ['shop.example.com', 'www.example.com', 'other.example.org']),
      ['example.com', 'www.example.com', '_dmarc.example.com', 'shop.example.com'], 'the fixed ones first, a name under another domain left out');
  });
});

/* ------------------------------------------------------------------------ */
/* Records: values and tones                                                */
/* ------------------------------------------------------------------------ */

describe('watch: what a value is and how a change is weighed', () => {
  test('a record set: its own records (a CNAME target\'s are another name\'s), lib/zonediff.js valueKey, the SOA as its primary name and serial, a token as a digest', () => {
    const zone = watchZone({ now: NOW.getTime() });
    const msg = decodeMessage(encodeMessage({
      answers: [
        { name: 'www.example.com', type: 'CNAME', ttl: 300, data: 'example.com.cdn.cloudflare.net' },
        { name: 'example.com.cdn.cloudflare.net', type: 'A', ttl: 60, data: CF_EDGES_V4[0] },
        { name: 'example.com', type: 'AAAA', ttl: 300, data: '2001:DB8:0:0::1' },
        { name: 'example.com', type: 'TXT', ttl: 300, data: [zone.token] },
        { name: 'example.com', type: 'TXT', ttl: 120, data: ['v=spf1 include:_spf.example.net', ' -all'] },
        { name: 'example.com', type: 'CAA', ttl: 300, data: { flags: 0, tag: 'Issue', value: 'LetsEncrypt.org' } },
        { name: 'example.com', type: 'SOA', ttl: 300, data: { mname: 'NS1.example.net', rname: 'hostmaster.example.com', serial: 7, refresh: 1, retry: 1, expire: 1, minimum: 1 } }
      ]
    }));
    assert.deepEqual(rrsetOf('www.example.com', 'A', msg.answers), { values: [], ttl: null }, 'the CNAME\'s target answers for itself');
    assert.deepEqual(rrsetOf('www.example.com', 'CNAME', msg.answers).values, ['example.com.cdn.cloudflare.net']);
    assert.deepEqual(rrsetOf('example.com', 'AAAA', msg.answers).values, ['2001:db8::1'], 'IPv6 canonical');
    const txt = rrsetOf('example.com', 'TXT', msg.answers);
    assert.equal(txt.ttl, 120, 'the smallest TTL');
    assert.equal(txt.values.length, 2);
    assert.match(txt.values[0], /^token google [0-9a-f]{12}$/, 'a verification token is kept as a digest');
    assert.ok(!JSON.stringify(txt).includes('e2e-token'), 'the token itself is never kept');
    assert.equal(txt.values[1], 'txt "v=spf1 include:_spf.example.net -all"', 'TXT strings joined');
    assert.deepEqual(rrsetOf('example.com', 'CAA', msg.answers).values, ['0 issue letsencrypt.org'], 'CAA in lower case');
    assert.deepEqual(rrsetOf('example.com', 'SOA', msg.answers), { values: ['ns1.example.net'], serial: 7, ttl: 300 });
    assert.equal(txtKind('example.com', txt.values[0]), 'token:google');
    assert.equal(txtKind('example.com', txt.values[1]), 'spf');
    assert.equal(txtKind('_dmarc.example.com', 'txt "v=DMARC1; p=none"'), 'dmarc');
    assert.equal(txtKind('example.com', 'txt "v=DMARC1; p=none"'), 'other', 'a DMARC record only at _dmarc');
    assert.equal(displayValue('TXT', txt.values[0]), 'Google verification (google-site-verification…)', 'named by its service, never its token');
    assert.equal(displayValue('TXT', 'txt "Ã§aÄ\u009f"'), 'çağ', 'a TXT value read as UTF-8');
    assert.equal(displayValue('DNSKEY', '257 3 13 AAAA'), '257 3 13 (key-signing key)');
  });

  test('the tone of a change, by type, by the name\'s provider class, a CDN\'s rotating edges, a zone-signing key rolling', () => {
    const tone = (c) => recordTone({ before: ['a'], after: ['b'], ...c });
    for (const type of ['MX', 'NS', 'CAA']) assert.equal(tone({ type }).tone, 'bad', type);
    assert.equal(tone({ type: 'TXT', kind: 'spf' }).tone, 'bad');
    assert.equal(tone({ type: 'TXT', kind: 'dmarc' }).tone, 'bad');
    assert.equal(tone({ type: 'TXT', kind: 'token:google' }).tone, 'info');
    assert.equal(tone({ type: 'TXT', kind: 'other' }).tone, 'info');
    assert.deepEqual(tone({ type: 'A', before: ['192.0.2.10'], after: ['192.0.2.20'], classBefore: 'direct', classAfter: 'direct' }), { tone: 'info', why: null });
    assert.deepEqual(tone({ type: 'CNAME', classBefore: 'cloudflare:cloudflare', classAfter: 'direct' }), { tone: 'bad', why: 'class' }, 'off its CDN: the origin exposed');
    assert.deepEqual(tone({ type: 'CNAME', classBefore: 'cdn:fastly', classAfter: 'dangling' }), { tone: 'bad', why: 'class' }, 'a CNAME left dangling');
    assert.deepEqual(tone({ type: 'A', classBefore: 'none', classAfter: 'direct' }), { tone: 'info', why: null }, 'a name that had no address is no class move');
    assert.deepEqual(tone({ type: 'A', before: [CF_EDGES_V4[0], CF_EDGES_V4[1]], after: [CF_EDGES_V4[1], CF_EDGES_V4[2]] }), { tone: 'quiet', why: 'cdn' });
    assert.equal(cdnRotation('A', [CF_EDGES_V4[0]], ['192.0.2.1']), null, 'an edge and a direct address: no rotation');
    assert.equal(cdnRotation('A', [CF_EDGES_V4[0]], []), null);
    assert.equal(cdnRotation('MX', ['x'], ['y']), null);
    assert.deepEqual(tone({ type: 'DNSKEY', before: ['256 3 13 old', '257 3 13 KSK'], after: ['256 3 13 new', '257 3 13 KSK'] }), { tone: 'quiet', why: 'zsk' });
    assert.equal(tone({ type: 'DNSKEY', before: ['257 3 13 KSK'], after: ['257 3 13 other'] }).tone, 'info');
    assert.equal(tone({ type: 'DS', before: ['1 13 2'], after: ['1 13 2', '2 13 2'] }).tone, 'info', 'a DS added under a name');
    assert.equal(tone({ type: 'DS', before: ['1 13 2'], after: [] }).tone, 'bad');
    assert.equal(tone({ type: 'HTTPS' }).tone, 'info');
  });
});

/* ------------------------------------------------------------------------ */
/* The changes                                                              */
/* ------------------------------------------------------------------------ */

describe('watch: changes since the baseline', () => {
  test('nothing moved: none; a domain new or no longer watched', () => {
    assert.deepEqual(diff(target(), next(() => {})), []);
    const c = diffReports('watch', report([target()]), report([next((x) => { x.target = 'example.org'; })]), { t });
    assert.deepEqual(tags(c), ['NEW example.org info', 'GONE example.com info']);
    assert.match(text(c[0]), /^example\.org: now watched: registrar Example Registrar, Inc\., 9 record sets$/);
  });

  test('REGISTRAR, LOCK, STATUS, NS (the registry\'s and the zone\'s), DS and EXPIRY', () => {
    const c = diff(target(), next((x) => {
      Object.assign(x.registration, { registrar: 'Other Registrar LLC', ianaId: '1068', statuses: ['client hold', 'server transfer prohibited'], expires: '2028-11-13', nameservers: ['ns1.example.org'] });
      x.delegation.ns = ['ns1.example.org'];
      x.delegation.ds = [];
    }));
    assert.deepEqual(tags(c), [
      'REGISTRAR example.com registrar bad',
      'LOCK example.com client transfer prohibited bad',
      'LOCK example.com server transfer prohibited good',
      'STATUS example.com client hold bad',
      'STATUS example.com client delete prohibited info',
      'NS example.com registry bad',
      'DS example.com ds bad',
      'EXPIRY example.com expiry good',
      'NS example.com zone bad'
    ]);
    const words = c.map(text);
    assert.equal(words[0], 'example.com: registrar Example Registrar, Inc. (IANA 9999) → Other Registrar LLC (IANA 1068)');
    assert.equal(words[1], 'example.com: client transfer prohibited removed: whoever has the transfer code can move the domain to another registrar');
    assert.equal(words[3], 'example.com: client hold added');
    assert.equal(words[4], 'example.com: client delete prohibited removed');
    assert.equal(words[5], 'example.com: the registry\'s name servers (RDAP) ns1.example.net, ns2.example.net → ns1.example.org');
    assert.equal(words[6], 'example.com: DS removed at the parent (12345 13 2): DNSSEC is off for the domain');
    assert.equal(words[7], 'example.com: renewed: expires 2028-11-13 (was 2027-11-13)');
    assert.equal(words[8], 'example.com: the zone\'s name servers (NS at the apex) ns1.example.net, ns2.example.net → ns1.example.org');
    assert.equal(notableChanges(c).length, c.length, 'every one counts');
    // PagerDuty: registrar, lock, name servers and DS are critical by tag; a hold by its item
    assert.deepEqual(c.filter((x) => x.tone === 'bad').map((x) => eventSeverity(x, 'watch')), ['critical', 'critical', 'critical', 'critical', 'critical', 'critical']);
    assert.equal(eventSeverity({ tag: 'RECORD', item: 'example.com|MX' }, 'watch'), 'error');
  });

  test('the registrar\'s name under the same IANA ID is info; an expiry earlier is info; DS added is info, replaced bad', () => {
    assert.deepEqual(tags(diff(target(), next((x) => { x.registration.registrar = 'Example Holdings Ltd'; }))), ['REGISTRAR example.com registrar info']);
    assert.deepEqual(tags(diff(target(), next((x) => { x.registration.expires = '2027-01-01'; }))), ['EXPIRY example.com expiry info']);
    assert.deepEqual(tags(diff(target(), next((x) => { x.delegation.ds = ['12345 13 2', '23456 13 2']; }))), ['DS example.com ds info']);
    assert.deepEqual(tags(diff(target(), next((x) => { x.delegation.ds = ['23456 13 2']; }))), ['DS example.com ds bad']);
  });

  test('EXPIRY: not renewed with fewer than 30 days left is bad, said once (the report\'s mark)', () => {
    const soon = next((x) => Object.assign(x.registration, { expires: '2026-10-29', daysLeft: 20, soon: '2026-10-29' }), target({ registration: { ...target().registration, expires: '2026-10-29', daysLeft: 21 } }));
    const c = diff(target({ registration: { ...target().registration, expires: '2026-10-29', daysLeft: 21 } }), soon);
    assert.deepEqual(tags(c), ['EXPIRY example.com expiry bad']);
    assert.equal(text(c[0]), 'example.com: expires 2026-10-29 (20 days left) and has not been renewed');
    assert.deepEqual(diff(soon, next((x) => { x.registration.daysLeft = 19; }, soon)), [], 'said once');
    const now = new Date('2026-10-09T03:00:00Z');
    const facts = { registration: { state: 'ok', registrar: 'R', ianaId: '1', statuses: [], expires: new Date('2026-10-29T12:00:00Z'), daysLeft: 20, nameservers: [] } };
    assert.equal(registrationPart(facts, null, null, now).soon, undefined, 'no baseline: whether it moved is not known');
    assert.equal(registrationPart(facts, { registration: { state: 'ok', expires: '2026-10-29' } }, null, now).soon, '2026-10-29');
    assert.equal(registrationPart(facts, { registration: { state: 'ok', expires: '2026-09-29' } }, null, now).soon, undefined, 'it moved: renewed');
  });

  test('the registry losing the domain is bad; a night the registry could not be read is said once and compares nothing; DS still compares', () => {
    assert.deepEqual(tags(diff(target(), next((x) => { x.registration = { state: 'not-found' }; }))), ['STATUS example.com registration bad']);
    const carried = next((x) => {
      x.registration = { ...target().registration, registrar: 'Other Registrar LLC', ianaId: '1068', carried: { from: '2026-10-08T03:00:00.000Z' }, error: 'HTTP 503' };
      x.delegation.ds = [];
    });
    const c = diff(target(), carried);
    assert.deepEqual(tags(c), ['DS example.com ds bad', 'FAILED? example.com rdap quiet'], 'the carried fields are the last read: never a change; what counts first');
    assert.match(text(c[1]), /the registry could not be read this run \(HTTP 503\)/);
    assert.deepEqual(tags(diff(carried, next((x) => { x.delegation.ds = []; }, carried))), [], 'a second night: not said again');
  });

  test('RECORD: MX, CAA, a delegation\'s NS, SPF and DMARC are bad; A, AAAA and CNAME info unless the provider class moves; a token is named, never printed', () => {
    const c = diff(target(), next((x) => {
      setRec(x, 'example.com', 'MX', ['10 mx2.example.net']);
      setRec(x, 'example.com', 'CAA', ['0 issue example.net']);
      setRec(x, 'example.com', 'TXT', ['token google fedcba987654', 'txt "v=spf1 -all"', 'txt "hello"']);
      setRec(x, '_dmarc.example.com', 'TXT', ['txt "v=DMARC1; p=none"']);
      setRec(x, 'shop.example.com', 'A', ['192.0.2.20']);
      setRec(x, 'www.example.com', 'CNAME', null);
      setRec(x, 'www.example.com', 'A', ['192.0.2.30']);
      x.classes['www.example.com'] = 'direct';
    }));
    assert.deepEqual(tags(c), [
      'RECORD example.com _dmarc.example.com|TXT|dmarc bad',
      'RECORD example.com example.com|CAA bad',
      'RECORD example.com example.com|MX bad',
      'RECORD example.com example.com|TXT info',
      'RECORD example.com example.com|TXT|spf bad',
      'RECORD example.com example.com|TXT|token:google info',
      'RECORD example.com shop.example.com|A info',
      'RECORD example.com www.example.com|A bad',
      'RECORD example.com www.example.com|CNAME bad'
    ]);
    const by = Object.fromEntries(c.map((x) => [x.item, text(x)]));
    assert.equal(by['example.com|MX'], 'example.com: example.com MX: 10 mx.example.com → 10 mx2.example.net');
    assert.equal(by['example.com|TXT|spf'], 'example.com: example.com TXT (SPF): v=spf1 include:_spf.example.net -all → v=spf1 -all');
    assert.equal(by['_dmarc.example.com|TXT|dmarc'], 'example.com: _dmarc.example.com TXT (DMARC): v=DMARC1; p=reject → v=DMARC1; p=none');
    assert.equal(by['example.com|TXT|token:google'], 'example.com: example.com TXT: Google verification (google-site-verification…) → Google verification (google-site-verification…)');
    assert.equal(by['example.com|TXT'], 'example.com: example.com TXT: added hello');
    assert.equal(by['www.example.com|CNAME'], 'example.com: www.example.com CNAME: removed example.com.cdn.cloudflare.net; it now points to a direct address (was Cloudflare)');
    assert.equal(by['www.example.com|A'], 'example.com: www.example.com A: added 192.0.2.30; it now points to a direct address (was Cloudflare)');
    assert.equal(by['shop.example.com|A'], 'example.com: shop.example.com A: 192.0.2.10 → 192.0.2.20');
    for (const x of c) assert.ok(!text(x).includes('0123456789ab') && !text(x).includes('fedcba'), 'no digest printed either');
    assert.equal(notableChanges(c).length, 9, 'every one counts');
  });

  test('not counted: a CDN\'s edges rotating, a new SOA serial, a zone-signing key rolling; TTLs ignored without --ttl', () => {
    const c = diff(target(), next((x) => {
      setRec(x, 'example.com', 'A', [CF_EDGES_V4[1], CF_EDGES_V4[2]]);
      setRec(x, 'example.com', 'SOA', ['ns1.example.net'], { serial: 2026100902 });
      setRec(x, 'example.com', 'DNSKEY', ['256 3 13 ZSKtwo', '257 3 13 KSKone']);
      setRec(x, 'example.com', 'MX', ['10 mx.example.com'], { ttl: 60 });
    }));
    assert.deepEqual(tags(c), ['RECORD? example.com example.com|A quiet', 'RECORD? example.com example.com|DNSKEY quiet', 'SERIAL? example.com example.com|SOA quiet']);
    assert.match(text(c[0]), /\(the CDN's edges rotate: not counted\)$/);
    assert.match(text(c[1]), /\(a zone-signing key rolled: not counted\)$/);
    assert.equal(text(c[2]), 'example.com: example.com SOA: serial 2026100901 → 2026100902');
    assert.deepEqual(notableChanges(c), []);
    const md = renderChangesMarkdown({ command: 'watch', baseline: { file: 'w.json', finishedAt: '2026-10-08T03:01:00.000Z' }, changes: c, notes: [] });
    assert.match(md, /- 3 listed only \(a CDN's edges rotating, new SOA serials, a zone-signing key rolling, record sets that keep changing, lagging secondaries, what could not be read this run\)/);
  });

  test('TTLs compare when both runs asked for them (--ttl)', () => {
    const withTtl = { options: { ...report([]).options, ttl: true, authoritative: true } };
    const b = target({ records: [rec('example.com', 'MX', ['10 mx.example.com'], { ttl: 3600 })] });
    const a = next((x) => setRec(x, 'example.com', 'MX', ['10 mx.example.com'], { ttl: 300 }), b);
    assert.deepEqual(tags(diff(b, a)), [], 'one run without --ttl: ignored');
    const c = diff(b, a, { before: withTtl, after: withTtl });
    assert.deepEqual(tags(c), ['RECORD example.com example.com|MX info']);
    assert.equal(text(c[0]), 'example.com: example.com MX: TTL 3600 → 300');
  });

  test('FLAPPING: said once when a record set starts to keep changing; its info changes then not listed; a bad change still is', () => {
    const runs = ['2026-10-03T03:00:00.000Z', '2026-10-04T03:00:00.000Z', '2026-10-05T03:00:00.000Z', '2026-10-06T03:00:00.000Z', '2026-10-07T03:00:00.000Z', '2026-10-08T03:00:00.000Z'];
    const b = target({ runs, records: [rec('shop.example.com', 'A', ['192.0.2.10'], { flips: ['2026-10-05T03:00:00.000Z', '2026-10-07T03:00:00.000Z'] }), rec('example.com', 'MX', ['10 mx.example.com'])] });
    const a = next((x) => setRec(x, 'shop.example.com', 'A', ['192.0.2.11'], { flips: ['2026-10-05T03:00:00.000Z', '2026-10-07T03:00:00.000Z', '2026-10-09T03:00:00.000Z'], flapping: true }), b);
    const c = diff(b, a);
    assert.deepEqual(tags(c), ['FLAPPING? example.com shop.example.com|A quiet']);
    assert.equal(text(c[0]), 'example.com: shop.example.com A: changed 3 times in the last 7 runs: its changes are not listed while it keeps changing (a bad one still is)');
    const a2 = next((x) => {
      setRec(x, 'shop.example.com', 'A', ['192.0.2.12'], { flips: [...a.records.find((r) => r.name === 'shop.example.com').flips, '2026-10-10T03:00:00.000Z'], flapping: true });
      setRec(x, 'example.com', 'MX', ['10 mx2.example.net'], { flips: ['2026-10-10T03:00:00.000Z'] });
    }, a);
    assert.deepEqual(tags(diff(a, a2)), ['RECORD example.com example.com|MX bad'], 'said once; the MX change is not silenced');
    const flappingMx = next((x) => setRec(x, 'example.com', 'MX', ['10 mx3.example.net'], { flapping: true, flips: ['x', 'y', 'z'] }), a2);
    assert.deepEqual(tags(diff(a2, flappingMx)), ['RECORD example.com example.com|MX bad', 'FLAPPING? example.com example.com|MX quiet'], 'an MX that flaps is still bad: a monitor that goes quiet is what an attacker wants');
  });

  test('a lookup that failed carries its last read: never a change; a name gone (NXDOMAIN) is one line, as bad as the worst it had', () => {
    const failed = next((x) => {
      x.failures = [{ name: 'shop.example.com', type: 'A', error: 'SERVFAIL', errorKind: null }];
      setRec(x, 'shop.example.com', 'A', ['192.0.2.10'], { carried: { from: '2026-10-08T03:00:00.000Z' } });
    });
    assert.deepEqual(diff(target(), failed), []);
    const back = next((x) => setRec(x, 'shop.example.com', 'A', ['192.0.2.20']), failed);
    back.failures = [];
    assert.deepEqual(tags(diff(failed, back)), ['RECORD example.com shop.example.com|A info'], 'compared with the carried read');
    const gone = diff(target(), next((x) => {
      x.records = x.records.filter((r) => r.name !== 'www.example.com' && r.name !== 'shop.example.com');
      x.nxdomain = ['www.example.com', 'shop.example.com'];
      delete x.classes['www.example.com'];
    }));
    assert.deepEqual(tags(gone), ['RECORD example.com shop.example.com info', 'RECORD example.com www.example.com info']);
    assert.equal(text(gone[1]), 'example.com: www.example.com: no longer exists (NXDOMAIN); it had CNAME');
    const apexGone = diff(target(), next((x) => { x.records = x.records.filter((r) => r.name !== 'example.com'); x.nxdomain = ['example.com']; }));
    assert.deepEqual(tags(apexGone), ['RECORD example.com example.com bad']);
  });

  test('only what both runs asked compares: other names or types are no change, and the notes say why', () => {
    const fewer = next((x) => {
      x.names = x.names.filter((n) => n !== 'shop.example.com');
      x.types = ['A', 'MX'];
      x.records = x.records.filter((r) => r.name !== 'shop.example.com' && ['A', 'MX'].includes(r.type));
    });
    assert.deepEqual(diff(target(), fewer), []);
    const notes = baselineNotes('watch', report([target()]), report([fewer], { options: { types: ['A', 'MX'], names: { file: 'hosts.txt', count: 1 }, ttl: true, authoritative: true } }));
    assert.deepEqual(notes, [
      'The record types differ from the baseline\'s (A,AAAA,CNAME,MX,NS,TXT,CAA,SOA,DS,DNSKEY,HTTPS → A,MX): only the types both runs asked are compared.',
      'The names file differs from the baseline\'s (none → hosts.txt (1)): only the names both runs asked are compared.',
      'TTLs were compared in one run only (--ttl): their changes are compared when both runs ask.',
      'The name servers were asked directly in one run only (--authoritative): SYNC and LAME compare runs that both asked.'
    ]);
  });

  test('SYNC and LAME, when both runs asked the name servers', () => {
    const server = (address, status, extra = {}) => ({ address, family: 4, hosts: [address === '198.51.100.53' ? 'ns1.example.net' : 'ns2.example.net'], status, reason: null, serial: 5, transport: 'udp', ...extra });
    const auth = (extra = {}) => ({ view: 'authoritative', servers: [server('198.51.100.53', 'ok'), server('198.51.100.54', 'ok')], serial: 5, lagging: [], mismatches: [],
      compared: ['example.com|MX', 'example.com|A'], ttls: {}, queries: 6, cut: 0, unresolved: [], ...extra });
    const b = target({ authoritative: auth() });
    const a = next((x) => {
      x.authoritative = auth({
        servers: [server('198.51.100.53', 'lame', { reason: 'refused', serial: null }), server('198.51.100.54', 'ok', { serial: 6 }), server('198.51.100.55', 'ok', { serial: 5 })],
        serial: 6, lagging: ['198.51.100.55'], mismatches: [{ key: 'example.com|MX', servers: { '198.51.100.54': ['10 mx.example.com'], '198.51.100.56': ['10 mx.example.org'] } }]
      });
    }, b);
    const c = diff(b, a);
    assert.deepEqual(tags(c), ['LAME example.com 198.51.100.53 bad', 'SYNC example.com example.com|MX bad', 'SYNC? example.com 198.51.100.55 info']);
    assert.equal(text(c[0]), 'example.com: ns1.example.net (198.51.100.53): it answers REFUSED');
    assert.equal(text(c[1]), 'example.com: example.com MX: the name servers answer it differently at serial 6: 198.51.100.54 10 mx.example.com; 198.51.100.56 10 mx.example.org');
    assert.match(text(c[2]), /: a lagging secondary \(serial 5, the others 6\)$/);
    const fixed = next((x) => { x.authoritative = auth({ serial: 6 }); }, a);
    assert.deepEqual(tags(diff(a, fixed)), ['LAME example.com 198.51.100.53 good', 'SYNC example.com example.com|MX good']);
    assert.deepEqual(tags(diff(b, next((x) => { x.authoritative = { view: 'recursive', servers: [] }; }, b))), ['FAILED? example.com authoritative quiet']);
    assert.deepEqual(diff(target(), next((x) => { x.authoritative = auth({ mismatches: [{ key: 'example.com|MX', servers: {} }] }); })), [], 'no earlier direct look: nothing to compare');
  });

  test('a baseline the comparison cannot walk is refused, naming what', () => {
    const bad = (x) => baselineProblem(report([x]), 'watch');
    assert.equal(bad(target()), null);
    assert.equal(bad({ ...target(), names: 'x' }), 'targets[0] has no "names" list');
    assert.equal(bad({ ...target(), registration: null }), 'targets[0] has no "registration" with a "state"');
    assert.equal(bad({ ...target(), records: [{ key: 'a|A', name: 'a', type: 'A', values: [1] }] }), 'targets[0] records[0] has "values" that are not a list of text');
    assert.equal(bad({ ...target(), records: [{ ...rec('a', 'A', ['x']), carried: true }] }), 'targets[0] records[0] has a "carried" without a "from"');
    assert.equal(bad({ ...target(), authoritative: { view: 'authoritative', servers: [{ address: 1 }] } }), 'targets[0] has "authoritative" servers without an address and a status');
    assert.equal(bad({ ...target(), delegation: { ns: 'ns1' } }), 'targets[0] has a delegation "ns" that is not a list of text');
    assert.ok(CHANGE_TAGS.every((tag) => tag.length <= 9), 'the CLI\'s column');
    for (const tag of ['REGISTRAR', 'LOCK', 'STATUS', 'NS', 'DS', 'EXPIRY', 'RECORD', 'SERIAL', 'FLAPPING', 'SYNC', 'LAME']) assert.ok(CHANGE_TAGS.includes(tag), tag);
  });
});

/* ------------------------------------------------------------------------ */
/* The report target                                                        */
/* ------------------------------------------------------------------------ */

describe('watch: the report target', () => {
  const facts = {
    registration: { state: 'ok', registrar: 'Example Registrar, Inc.', ianaId: '9999', statuses: ['client transfer prohibited'], expires: new Date('2027-11-13T12:00:00Z'), daysLeft: 400, nameservers: ['ns1.example.net'], delegationSigned: false },
    ns: { state: 'ok', hosts: ['ns1.example.net'] },
    dnssec: { state: 'unsigned', ds: [] }
  };
  const read = (sets, extra = {}) => ({
    sets: new Map(sets.map((s) => [`${s.name}|${s.type}`, s])), failures: [], nxdomain: [], delegated: [], classes: {}, keys: [], ...extra
  });
  const names = ['example.com', 'www.example.com', '_dmarc.example.com', 'shop.example.com'];
  const night = (prev, values, i, extra = {}) => watchTarget('example.com', { facts, read: read([{ name: 'shop.example.com', type: 'A', values }], extra), names, types: APEX_TYPES },
    { prev, runAt: new Date(NOW.getTime() + i * DAY), now: new Date(NOW.getTime() + i * DAY) });

  test('flips: the times of a record set\'s value changes; 3 within the last 7 runs is flapping; it calms down as the window passes', () => {
    let x = night(null, ['192.0.2.1'], 0);
    assert.equal(x.records.find((r) => r.name === 'shop.example.com').flips, undefined, 'the first read is no change');
    const seq = ['192.0.2.2', '192.0.2.2', '192.0.2.3', '192.0.2.4'];
    seq.forEach((v, i) => { x = night(x, [v], i + 1); });
    const r = x.records.find((y) => y.name === 'shop.example.com');
    assert.equal(r.flips.length, 3);
    assert.equal(r.flapping, true);
    assert.equal(recentFlips(r.flips, x.runs), 3);
    assert.equal(x.runs.length, 5);
    for (let i = 0; i < FLAP_RUNS; i += 1) x = night(x, ['192.0.2.4'], 5 + i);
    const calm = x.records.find((y) => y.name === 'shop.example.com');
    assert.equal(calm.flapping, undefined, `calm after ${FLAP_RUNS} quiet runs`);
    assert.equal(calm.flips.length, 3, 'the flips are kept (the last 10)');
    assert.equal(x.runs.length, FLAP_RUNS);
    assert.ok(FLAP_CHANGES === 3);
  });

  test('a CDN\'s rotating edges are no flip; an empty set that changed lately is kept; a failed lookup carries the last read', () => {
    const cf = (v, i, prev) => watchTarget('example.com', { facts, read: read([{ name: 'example.com', type: 'A', values: v }]), names, types: APEX_TYPES },
      { prev, runAt: new Date(NOW.getTime() + i * DAY), now: new Date(NOW.getTime() + i * DAY) });
    let x = cf([CF_EDGES_V4[0]], 0, null);
    x = cf([CF_EDGES_V4[1]], 1, x);
    assert.equal(x.records.find((r) => r.key === 'example.com|A').flips, undefined, 'a rotation is no change');
    let y = night(null, ['192.0.2.1'], 0);
    y = night(y, [], 1);
    assert.deepEqual(y.records.find((r) => r.name === 'shop.example.com'), { key: 'shop.example.com|A', name: 'shop.example.com', type: 'A', values: [], flips: [new Date(NOW.getTime() + DAY).toISOString()] },
      'gone tonight: kept empty while its change is recent');
    const failed = night(y, [], 2, { failures: [{ name: 'shop.example.com', type: 'A', error: 'SERVFAIL', errorKind: null }] });
    assert.deepEqual(failed.records.find((r) => r.name === 'shop.example.com').carried, { from: y.checkedAt });
  });

  test('the registration not read: the last read carried with why; the zone\'s NS and the DS too', () => {
    const prev = night(null, ['192.0.2.1'], 0);
    const down = watchTarget('example.com', {
      facts: { registration: { state: 'failed', failure: { kind: 'http', params: { status: 503 }, detail: 'HTTP 503' } }, ns: { state: 'failed' }, dnssec: { state: null } },
      read: read([]), names, types: APEX_TYPES
    }, { prev, runAt: new Date(NOW.getTime() + DAY), now: new Date(NOW.getTime() + DAY) });
    assert.equal(down.registration.registrar, 'Example Registrar, Inc.');
    assert.deepEqual([down.registration.carried, down.registration.error, down.registration.daysLeft], [{ from: prev.checkedAt }, 'HTTP 503', 399]);
    assert.deepEqual([down.delegation.ns, down.delegation.nsCarried, down.delegation.ds, down.delegation.dsCarried], [['ns1.example.net'], { from: prev.checkedAt }, [], { from: prev.checkedAt }]);
    const unsupported = watchTarget('example-test.com.tr', { facts: { registration: { state: 'unsupported', tld: 'tr' }, ns: { state: 'ok', hosts: [] }, dnssec: { state: null } }, read: read([]), names: ['example-test.com.tr'], types: APEX_TYPES },
      { runAt: NOW, now: NOW });
    assert.deepEqual(unsupported.registration, { state: 'unsupported', error: 'no RDAP for .tr' });
  });

  test('a name\'s provider class from its A and AAAA answers', () => {
    const res = (name, type, answers, rcode = 'NOERROR') => ({ ok: true, rcode, answers, name, type });
    const a = (name, ip, chain = []) => res(name, 'A', [...chain.map(([n, d]) => ({ name: n, type: 'CNAME', ttl: 1, data: d })), ...(ip ? [{ name: chain.length ? chain.at(-1)[1] : name, type: 'A', ttl: 1, data: ip }] : [])]);
    const empty = (name) => res(name, 'AAAA', []);
    assert.equal(classOf('example.com', a('example.com', CF_EDGES_V4[0]), empty('example.com')), 'cloudflare:cloudflare');
    assert.equal(classOf('shop.example.com', a('shop.example.com', '192.0.2.10'), empty('shop.example.com')), 'direct');
    assert.equal(classOf('db.example.com', a('db.example.com', '10.0.0.5'), empty('db.example.com')), 'private');
    assert.equal(classOf('old.example.com', res('old.example.com', 'A', [{ name: 'old.example.com', type: 'CNAME', ttl: 1, data: 'gone.example.net' }], 'NXDOMAIN'), res('old.example.com', 'AAAA', [{ name: 'old.example.com', type: 'CNAME', ttl: 1, data: 'gone.example.net' }], 'NXDOMAIN')), 'dangling');
    assert.equal(classOf('none.example.com', res('none.example.com', 'A', [], 'NXDOMAIN'), res('none.example.com', 'AAAA', [], 'NXDOMAIN')), 'none');
    assert.equal(classOf('x.example.com', { ok: false, error: 'timeout' }, empty('x.example.com')), null, 'not known');
    assert.equal(classOf('shop.example.com', a('shop.example.com', '192.0.2.10'), null), 'direct', 'A alone (--types without AAAA)');
    assert.equal(classOf('shop.example.com', null, null), null);
  });
});

/* ------------------------------------------------------------------------ */
/* Offline nights of main()                                                 */
/* ------------------------------------------------------------------------ */

async function runMain(argv, { fetchImpl, now = NOW, authoritative = null } = {}) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now, ...(authoritative ? { authoritative } : {}) });
  return { code, out: stdout.text, err: stderr.text };
}

test('watch over five nights: a registrar change and a lock removed, an MX and a provider move, a CDN rotation, a registry outage, a DS withdrawn', async () => {
  const dir = tmp();
  try {
    const zone = watchZone({ now: NOW.getTime() });
    const log = [];
    const rdapLog = [];
    const rcodes = {};
    const rdapStatus = {};
    const fetchImpl = createWatchFetch(zone, { log, rdapLog, rcodes, rdapStatus });
    const json = join(dir, 'watch.json');
    const md = join(dir, 'watch.md');
    const names = join(dir, 'hosts.txt');
    writeFileSync(names, 'shop.example.com\nother.example.net\n');
    const argv = ['watch', 'example.com', 'example.org', '--names', names, '--baseline', json, '--json', json, '--md', md, '--fail-on-change', '--no-color'];
    const night = (n) => runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + n * DAY) });

    // Night 1: no baseline yet.
    const first = await night(0);
    assert.equal(first.code, EXIT.OK, first.err);
    assert.match(first.out, /^Baseline watch\.json does not exist yet/);
    assert.match(first.out, /\nDomain watch · example\.com\n- Registrar: Example Registrar, Inc\. \(IANA 9999\) · expires 2027-11-13 \(400 days left\)\n- Statuses: client delete prohibited, client transfer prohibited\n- Name servers \(the registry and the zone agree\): ns1\.example\.net, ns2\.example\.net\n- DS at the parent \(key tag, algorithm, digest type\): \d+ 13 2 · validated\n- Records: \d+ record sets at 4 names \(SOA serial 2026100901\)\n- First run for this domain: the next run compares with this one\n/);
    assert.match(first.err, /ds: warning: 1 name of hosts\.txt under none of the domains left out \(never sent\)/);
    assert.ok(!log.some((q) => q.name.endsWith('example.net') && q.name !== 'example.com.cdn.cloudflare.net'), 'a name under none of the domains is never sent');
    assert.deepEqual([...new Set(rdapLog)].sort(), ['example.com', 'example.org'], 'RDAP for the domains only: never their name servers\' domain');
    for (const q of ['example.com|SOA', 'example.com|DNSKEY', 'www.example.com|CNAME', 'shop.example.com|A', '_dmarc.example.com|TXT', 'example.com|DS', 'example.com|NS']) {
      assert.ok(log.some((x) => `${x.name}|${x.type}` === q), q);
    }
    assert.ok(!log.some((x) => x.name === 'www.example.com' && x.type === 'SOA'), 'SOA, DS and DNSKEY at the apex (and a delegation) only');
    assert.ok(!log.some((x) => x.name === '_dmarc.example.com' && x.type !== 'TXT'), '_dmarc: TXT only');
    const doc1 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(doc1.options, { types: [...WATCH_TYPES], names: { file: 'hosts.txt', count: 2 }, ttl: false, authoritative: false, resolvers: ['cloudflare', 'google', 'dnssb'] });
    const x1 = doc1.targets[0];
    assert.deepEqual(x1.classes, { 'example.com': 'cloudflare:cloudflare', 'www.example.com': 'cloudflare:cloudflare', 'shop.example.com': 'direct' });
    assert.ok(!readFileSync(json, 'utf8').includes(zone.token) && !first.out.includes(zone.token), 'the verification token is never written or printed');

    // Night 2: another registrar, the transfer lock removed, the MX moved, www off Cloudflare.
    zone.registry['example.com'] = zone.rdapJson('example.com', { status: ['client delete prohibited'], registrar: 'Other Registrar LLC', ianaId: '1068', signed: true });
    zone.table['example.com'].MX = [{ preference: 10, exchange: 'mx.example.net' }];
    zone.table['www.example.com'] = { A: ['192.0.2.30'] };
    const second = await night(1);
    assert.equal(second.code, EXIT.CHANGED, second.err);
    assert.match(second.out, /^Changes since the baseline \(watch\.json, run of 2026-10-09 03:00 UTC\): 5\n/);
    assert.match(second.out, /\n {2}REGISTRAR {2}example\.com: registrar Example Registrar, Inc\. \(IANA 9999\) → Other Registrar LLC \(IANA 1068\)\n/);
    assert.match(second.out, /\n {2}LOCK {7}example\.com: client transfer prohibited removed/);
    assert.match(second.out, /\n {2}RECORD {5}example\.com: example\.com MX: 10 mx\.example\.com → 10 mx\.example\.net\n/);
    assert.match(second.out, /\n {2}RECORD {5}example\.com: www\.example\.com A: added 192\.0\.2\.30; it now points to a direct address \(was Cloudflare\)\n/);
    assert.match(second.out, /\n {2}RECORD {5}example\.com: www\.example\.com CNAME: removed example\.com\.cdn\.cloudflare\.net; it now points to a direct address \(was Cloudflare\)\n/);
    assert.match(readFileSync(md, 'utf8'), /- \*\*REGISTRAR\*\* `example\.com`: registrar `Example Registrar, Inc\.` \(IANA 9999\) → `Other Registrar LLC` \(IANA 1068\)/);

    // Night 3: the apex rotates among Cloudflare's edges and its serial moves: listed, not counted.
    zone.table['example.com'].A = [CF_EDGES_V4[1], CF_EDGES_V4[2]];
    zone.table['example.com'].SOA = [{ ...zone.table['example.com'].SOA[0], serial: 2026101001 }];
    const third = await night(2);
    assert.equal(third.code, EXIT.OK, third.out + third.err);
    assert.match(third.out, /^Changes since the baseline \(watch\.json, run of 2026-10-10 03:00 UTC\): 2\n {2}RECORD {5}example\.com: example\.com A: 104\.16\.1\.1 → 104\.16\.3\.3 \(the CDN's edges rotate: not counted\)\n {2}SERIAL {5}example\.com: example\.com SOA: serial 2026100901 → 2026101001\n {2}Not counted: 2 /);

    // Night 4: the registry does not answer and one lookup fails: carried, nothing counted.
    rdapStatus['example.com'] = 503;
    rcodes['shop.example.com|A'] = 'SERVFAIL';
    zone.table['shop.example.com'].A = ['192.0.2.99'];
    const fourth = await night(3);
    assert.equal(fourth.code, EXIT.OK, fourth.out + fourth.err);
    assert.match(fourth.out, /^Changes since the baseline \(watch\.json, run of 2026-10-11 03:00 UTC\): 1\n {2}FAILED {5}example\.com: the registry could not be read this run \(HTTP 503\)/);
    assert.match(fourth.out, /- Registrar: Other Registrar LLC \(IANA 1068\) · expires 2027-11-13 \(397 days left\) \(carried from 2026-10-11: the registry could not be read this run: HTTP 503\)/);
    assert.match(fourth.err, /ds: warning: example\.com: the registry could not be read \(HTTP 503\): the last read is kept for the next comparison/);
    assert.match(fourth.err, /ds: warning: example\.com: no answer for shop\.example\.com A: the last read is kept for the next comparison/);
    const x4 = JSON.parse(readFileSync(json, 'utf8')).targets[0];
    assert.deepEqual(x4.records.find((r) => r.key === 'shop.example.com|A'), { key: 'shop.example.com|A', name: 'shop.example.com', type: 'A', values: ['192.0.2.10'], carried: { from: '2026-10-11T03:00:00.000Z' } });

    // Night 5: everything answers; the DS is withdrawn at the parent; shop moved meanwhile.
    delete rdapStatus['example.com'];
    delete rcodes['shop.example.com|A'];
    delete zone.table['example.com'].DS;
    const fifth = await night(4);
    assert.equal(fifth.code, EXIT.CHANGED, fifth.out + fifth.err);
    assert.match(fifth.out, /^Changes since the baseline \(watch\.json, run of 2026-10-12 03:00 UTC\): 2\n {2}DS {9}example\.com: DS removed at the parent \(\d+ 13 2\): DNSSEC is off for the domain\n {2}RECORD {5}example\.com: shop\.example\.com A: 192\.0\.2\.10 → 192\.0\.2\.99\n/);
    assert.ok(!JSON.parse(readFileSync(json, 'utf8')).targets[0].registration.carried, 'read again: nothing carried');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('with --notify-bad to PagerDuty: a lock removed pages critical once, and is resolved when the lock is back', async () => {
  const dir = tmp();
  try {
    const zone = watchZone({ now: NOW.getTime() });
    const base = createWatchFetch(zone);
    const sent = [];
    // a credential: built in parts, never written whole
    const url = 'https://events.pagerduty.com/v2/enqueue?routing_key=' + 'R0UT1NGKEY' + 'w'.repeat(22);
    const fetchImpl = (target, init) => {
      if (!String(target).startsWith('https://events.pagerduty.com/')) return base(target, init);
      sent.push(JSON.parse(init.body));
      return Promise.resolve(new Response('{"status":"success"}', { status: 202 }));
    };
    const json = join(dir, 'watch.json');
    const argv = ['watch', 'example.com', '--types', 'A,MX', '--baseline', json, '--json', json, '--notify-bad', url, '--fail-on-notify-error', '--no-color'];
    const night = (n) => runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + n * DAY) });
    const kinds = () => sent.splice(0).map((e) => [e.event_action, e.payload ? `${e.payload.custom_details.tag} ${e.payload.severity}` : null]);
    assert.equal((await night(0)).code, EXIT.OK);
    zone.registry['example.com'] = zone.rdapJson('example.com', { status: ['client delete prohibited'], signed: true });
    assert.equal((await night(1)).code, EXIT.OK);
    assert.deepEqual(kinds(), [['trigger', 'LOCK critical']]);
    assert.equal((await night(2)).code, EXIT.OK);
    assert.deepEqual(kinds(), [], 'still unlocked: nothing new, the incident stays open');
    zone.registry['example.com'] = zone.rdapJson('example.com', { signed: true });
    assert.equal((await night(3)).code, EXIT.OK);
    assert.deepEqual(kinds(), [['resolve', null]], 'locked again: resolved');
    assert.equal(JSON.parse(readFileSync(json, 'utf8')).notify, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('watch: where a paged problem stands (PagerDuty)', () => {
  const x = (extra = {}) => ({ ...target(), ...extra });
  test('LOCK, STATUS, EXPIRY, LAME and SYNC are over when the report says so; events stay open; a registration not read says nothing', () => {
    assert.equal(problemStanding('watch', x(), { tag: 'LOCK', item: 'client transfer prohibited' }), 'over');
    assert.equal(problemStanding('watch', x({ registration: { ...target().registration, statuses: [] } }), { tag: 'LOCK', item: 'client transfer prohibited' }), 'bad');
    assert.equal(problemStanding('watch', x({ registration: { ...target().registration, statuses: [], carried: { from: null } } }), { tag: 'LOCK', item: 'x' }), 'unknown');
    assert.equal(problemStanding('watch', x(), { tag: 'STATUS', item: 'client hold' }), 'over');
    assert.equal(problemStanding('watch', x({ registration: { ...target().registration, statuses: ['client hold'] } }), { tag: 'STATUS', item: 'client hold' }), 'bad');
    assert.equal(problemStanding('watch', x({ registration: { state: 'not-found' } }), { tag: 'STATUS', item: 'registration' }), 'bad');
    assert.equal(problemStanding('watch', x(), { tag: 'STATUS', item: 'registration' }), 'over');
    assert.equal(problemStanding('watch', x({ registration: { ...target().registration, soon: '2026-10-29' } }), { tag: 'EXPIRY', item: 'expiry' }), 'bad');
    assert.equal(problemStanding('watch', x(), { tag: 'EXPIRY', item: 'expiry' }), 'over');
    const auth = { view: 'authoritative', servers: [{ address: '198.51.100.53', status: 'lame' }], mismatches: [{ key: 'example.com|MX' }], compared: ['example.com|MX', 'example.com|A'] };
    assert.equal(problemStanding('watch', x({ authoritative: auth }), { tag: 'LAME', item: '198.51.100.53' }), 'bad');
    assert.equal(problemStanding('watch', x({ authoritative: { ...auth, servers: [{ address: '198.51.100.53', status: 'ok' }] } }), { tag: 'LAME', item: '198.51.100.53' }), 'over');
    assert.equal(problemStanding('watch', x({ authoritative: auth }), { tag: 'SYNC', item: 'example.com|MX' }), 'bad');
    assert.equal(problemStanding('watch', x({ authoritative: auth }), { tag: 'SYNC', item: 'example.com|A' }), 'over');
    assert.equal(problemStanding('watch', x({ authoritative: { view: 'recursive' } }), { tag: 'SYNC', item: 'example.com|A' }), 'unknown');
    for (const tag of ['REGISTRAR', 'NS', 'DS', 'RECORD']) assert.equal(problemStanding('watch', x(), { tag, item: 'registrar' }), 'unknown', tag);
    const plan = pagerDutyPlan(report([target()]), report([target()], { notify: { open: [{ key: 'a'.repeat(32), target: 'example.com', item: 'registrar', tag: 'REGISTRAR', since: null }] } }));
    assert.deepEqual(plan.resolves, [], 'another registrar stays open until someone resolves it');
  });
});

/* ------------------------------------------------------------------------ */
/* The name servers asked directly                                          */
/* ------------------------------------------------------------------------ */

describe('watch --authoritative: the name servers asked directly', () => {
  const servers = [];
  after(async () => {
    for (const s of servers) await s.close();
  });
  const start = async (opts) => {
    const s = await startAuthServer(opts);
    servers.push(s);
    return s;
  };
  const fast = { timeoutMs: 400, tries: 1 };

  test('askServer: UDP with EDNS0 and the DO bit for DNSKEY; a truncated answer asked again over TCP; a lame server; the SOA read for its serial', async () => {
    const zone = watchZone({ now: NOW.getTime() });
    zone.table['big.example.com'] = { TXT: [['x'.repeat(250)]] };
    const s = await start({ address: '127.0.0.1', table: zone.table, behave: { udpLimit: 200 } });
    const soa = await askServer({ address: s.address, port: s.port, name: 'example.com', type: 'SOA', ...fast });
    assert.equal(soa.ok, true);
    assert.equal(soa.transport, 'udp');
    assert.deepEqual(soaStanding(soa.message, 'example.com'), { status: 'ok', reason: null, serial: 2026100901, mname: 'ns1.example.net' });
    const key = await askServer({ address: s.address, port: s.port, name: 'example.com', type: 'DNSKEY', ...fast });
    assert.equal(key.transport, 'udp');
    assert.deepEqual(s.log.filter((q) => q.type === 'DNSKEY').map((q) => [q.transport, q.do]), [['udp', true]], 'the DO bit for DS and DNSKEY');
    assert.deepEqual(s.log.filter((q) => q.type === 'SOA').map((q) => q.do), [false]);
    const big = await askServer({ address: s.address, port: s.port, name: 'big.example.com', type: 'TXT', ...fast });
    assert.equal(big.transport, 'tcp', 'too large for 200 bytes: TC=1, then TCP');
    assert.deepEqual(s.log.filter((q) => q.name === 'big.example.com').map((q) => q.transport), ['udp', 'tcp']);
    assert.equal(big.message.answers[0].data[0].length, 250, 'the whole answer, over TCP');
    s.behave.rcode = 'REFUSED';
    const refused = await askServer({ address: s.address, port: s.port, name: 'example.com', type: 'SOA', ...fast });
    assert.deepEqual(soaStanding(refused.message, 'example.com'), { status: 'lame', reason: 'refused', serial: null, mname: null });
    delete s.behave.rcode;
    s.behave.aa = false;
    const noAa = await askServer({ address: s.address, port: s.port, name: 'example.com', type: 'SOA', ...fast });
    assert.equal(soaStanding(noAa.message, 'example.com').reason, 'no-aa');
    s.behave.aa = true;
    s.behave.silent = true;
    const silent = await askServer({ address: s.address, port: s.port, name: 'example.com', type: 'SOA', ...fast });
    assert.deepEqual([silent.ok, /no answer/.test(silent.error)], [false, true]);
    s.behave.silent = false;
  });

  test('an IPv6 address this machine has no route to is skipped, never lame', async () => {
    const unreachable = (code) => Object.assign(new Error('network unreachable'), { code });
    const transport = {
      createSocket: (type) => {
        if (type !== 'udp6') return dgram.createSocket(type);
        const sock = new EventEmitter();
        sock.send = (q, port, address, cb) => setImmediate(() => cb(unreachable('ENETUNREACH')));
        sock.close = () => {};
        return sock;
      },
      connect: (o) => {
        if (net.isIP(o.host) !== 6) return net.connect(o);
        const sock = new EventEmitter();
        sock.write = () => {};
        sock.destroy = () => {};
        setImmediate(() => sock.emit('error', unreachable('ENETUNREACH')));
        return sock;
      }
    };
    const r = await askServer({ address: '2001:db8::53', name: 'example.com', type: 'SOA', transport, ...fast });
    assert.deepEqual(r, { ok: false, skipped: 'no-ipv6-route', error: 'no IPv6 route from this machine' });
  });

  test('checkAuthoritative: in sync, a lagging secondary, servers out of sync at one serial, a lame one, the budget; port 53 blocked falls back', async () => {
    const zone = watchZone({ now: NOW.getTime() });
    const a = await start({ address: '127.0.0.1', table: zone.table });
    const b = await start({ address: '127.0.0.2', table: zone.table });
    const ports = { [a.address]: a.port, [b.address]: b.port };
    const dns = new DohClient({ chain: ['cloudflare'], fetchImpl: createWatchFetch(zone) });
    const keys = [{ name: 'example.com', type: 'MX' }, { name: 'example.com', type: 'A' }, { name: 'example.com', type: 'DS' }, { name: 'sub.example.com', type: 'A' }];
    const check = (extra = {}) => checkAuthoritative('example.com', { nsHosts: ['ns1.example.net', 'ns2.example.net'], keys, delegated: ['sub.example.com'], dns, maxQueries: 100, port: (x) => ports[x], ...fast, ...extra });
    const ok = await check();
    assert.equal(ok.view, 'authoritative');
    assert.deepEqual(ok.servers.map((s) => [s.hosts[0], s.address, s.status, s.serial]), [['ns1.example.net', '127.0.0.1', 'ok', 2026100901], ['ns2.example.net', '127.0.0.2', 'ok', 2026100901]]);
    assert.deepEqual([ok.compared, ok.mismatches, ok.lagging], [['example.com|MX', 'example.com|A'], [], []], 'the apex DS is the parent\'s, a delegated name the child\'s');
    b.behave.serial = 2026100800;
    const lag = await check();
    assert.deepEqual([lag.serial, lag.lagging, lag.mismatches], [2026100901, ['127.0.0.2'], []]);
    b.behave.serial = 2026100901;
    b.behave.table = structuredClone(zone.table);
    b.behave.table['example.com'].MX = [{ preference: 20, exchange: 'mx.example.org' }];
    const split = await check();
    assert.deepEqual(split.mismatches, [{ key: 'example.com|MX', servers: { '127.0.0.1': ['10 mx.example.com'], '127.0.0.2': ['20 mx.example.org'] } }]);
    delete b.behave.table;
    a.behave.rcode = 'SERVFAIL';
    const lame = await check();
    assert.deepEqual(lame.servers.map((s) => [s.status, s.reason]), [['lame', 'servfail'], ['ok', null]]);
    delete a.behave.rcode;
    const cut = await check({ maxQueries: 4 });
    assert.deepEqual([cut.compared, cut.cut], [['example.com|MX'], 1], 'two SOA questions, then one record set each');
    a.behave.silent = true;
    b.behave.silent = true;
    const blocked = await check();
    assert.equal(blocked.view, 'recursive', 'the first two servers answer nothing over UDP or TCP');
    a.behave.silent = false;
    b.behave.silent = false;
    assert.equal((await checkAuthoritative('example.com', { nsHosts: ['nowhere.example.org'], keys, dns, maxQueries: 10 })).view, 'none');
  });

  test('main(): a lame server and servers out of sync counted, back in sync the night after; --ttl compares their TTLs', async () => {
    const dir = tmp();
    try {
      const zone = watchZone({ now: NOW.getTime() });
      const a = await start({ address: '127.0.0.1', table: zone.table });
      const b = await start({ address: '127.0.0.2', table: zone.table, behave: { udpLimit: 150 } });
      const ports = { [a.address]: a.port, [b.address]: b.port };
      const fetchImpl = createWatchFetch(zone);
      const json = join(dir, 'watch.json');
      const argv = ['watch', 'example.com', '--authoritative', '--ttl', '--types', 'A,MX,NS,TXT,SOA', '--baseline', json, '--json', json, '--fail-on-change', '--no-color'];
      const night = (n) => runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + n * DAY), authoritative: { port: (x) => ports[x], ...fast } });
      const first = await night(0);
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.out, /- Name servers asked directly: 2 servers answer for the zone, serial 2026100901, in sync\n/);
      const doc1 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc1.options, { types: ['A', 'MX', 'NS', 'TXT', 'SOA'], names: null, ttl: true, authoritative: true, maxQueries: 2000, resolvers: ['cloudflare', 'google', 'dnssb'] });
      assert.equal(doc1.targets[0].records.find((r) => r.key === 'example.com|MX').ttl, 3600, 'the TTL the name servers agree on');
      assert.ok(b.log.some((q) => q.transport === 'tcp'), 'the truncated answers went over TCP');
      assert.ok(doc1.targets[0].authoritative.compared.includes('example.com|NS'), 'the zone\'s own NS set compared across the servers');
      // Night 2: ns1 refuses, ns2 answers the MX differently at the same serial, and the TTLs drop.
      a.behave.rcode = 'REFUSED';
      b.behave.table = structuredClone(zone.table);
      b.behave.table['example.com'].MX = [{ preference: 20, exchange: 'mx.example.org' }];
      a.behave.ttl = 300;
      b.behave.ttl = 300;
      const second = await night(1);
      assert.equal(second.code, EXIT.CHANGED, second.err);
      assert.match(second.out, /\n {2}LAME {7}example\.com: ns1\.example\.net \(127\.0\.0\.1\): it answers REFUSED\n/);
      assert.match(second.out, /\n {2}RECORD {5}example\.com: example\.com (A|MX|TXT): TTL 3600 → 300\n/);
      assert.match(second.out, /- Lame: ns1\.example\.net \(127\.0\.0\.1\): it answers REFUSED\n/);
      // Night 3: both answer, the same again (the zone's MX at both).
      delete a.behave.rcode;
      delete b.behave.table;
      const third = await night(2);
      assert.match(third.out, /\n {2}LAME {7}example\.com: ns1\.example\.net \(127\.0\.0\.1\): answers with authority again\n/);
      // Night 4: the two disagree at one serial: SYNC.
      b.behave.table = structuredClone(zone.table);
      b.behave.table['example.com'].MX = [{ preference: 20, exchange: 'mx.example.org' }];
      const fourth = await night(3);
      assert.equal(fourth.code, EXIT.CHANGED, fourth.err);
      assert.match(fourth.out, /\n {2}SYNC {7}example\.com: example\.com MX: the name servers answer it differently at serial 2026100901: 127\.0\.0\.1 10 mx\.example\.com; 127\.0\.0\.2 20 mx\.example\.org\n/);
      assert.match(fourth.out, /- Out of sync: example\.com MX: 127\.0\.0\.1 10 mx\.example\.com; 127\.0\.0\.2 20 mx\.example\.org\n/);
      delete b.behave.table;
      const fifth = await night(4);
      assert.match(fifth.out, /\n {2}SYNC {7}example\.com: example\.com MX: the name servers agree again\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test('readRecords: a delegated name gets its SOA, DS and DNSKEY asked; NXDOMAIN names; failures', async () => {
  const zone = watchZone({ now: NOW.getTime() });
  zone.table['dev.example.com'] = { NS: ['ns1.example.org'], DS: [{ keyTag: 7, algorithm: 13, digestType: 2, digest: 'cd'.repeat(32) }] };
  const log = [];
  const dns = new DohClient({ chain: ['cloudflare'], fetchImpl: createWatchFetch(zone, { log, rcodes: { 'shop.example.com|AAAA': 'SERVFAIL' } }) });
  const got = await readRecords('example.com', ['example.com', 'dev.example.com', 'gone.example.com', 'shop.example.com'], [...WATCH_TYPES], { dns });
  assert.deepEqual(got.delegated, ['dev.example.com']);
  assert.ok(log.some((q) => q.name === 'dev.example.com' && q.type === 'DS'), 'the delegation\'s DS');
  assert.ok(!log.some((q) => q.name === 'shop.example.com' && q.type === 'SOA'), 'not at a name that is no delegation');
  assert.deepEqual(got.nxdomain, ['gone.example.com']);
  assert.deepEqual(got.failures.map((f) => `${f.name} ${f.type} ${f.error}`), ['shop.example.com AAAA SERVFAIL']);
  assert.equal(got.classes['shop.example.com'], undefined, 'a class whose AAAA lookup failed is not known');
  assert.deepEqual(got.sets.get('dev.example.com|NS').values, ['ns1.example.org']);
});

test('the program itself: a spawned watch whose fetch is the fake DoH and RDAP (node --import, DS_FAKE_DOH=watch)', () => {
  const dir = tmp();
  try {
    const logFile = join(dir, 'requests.json');
    const res = spawnSync(process.execPath, ['--import', pathToFileURL(join(ROOT, 'tests', 'js', 'ds-fake-doh.mjs')).href, DS, 'watch', 'example.com', '--types', 'A,MX,TXT',
      '--json', join(dir, 'w.json'), '--no-color'], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, DS_FAKE_DOH: 'watch', DS_FAKE_DOH_LOG: logFile, NO_COLOR: '1' }, timeout: 60000
    });
    assert.equal(res.status, EXIT.OK, res.stderr);
    assert.match(res.stdout, /^Domain watch · example\.com\n- Registrar: Example Registrar, Inc\. \(IANA 9999\)/);
    const requests = JSON.parse(readFileSync(logFile, 'utf8'));
    assert.deepEqual(requests.rdap, ['example.com']);
    assert.deepEqual([...new Set(requests.dns.map((q) => q.type))].sort(), ['A', 'DNSKEY', 'DS', 'MX', 'NS', 'TXT'], 'the types asked, and the delegation\'s NS, DS and DNSKEY');
    assert.equal(JSON.parse(readFileSync(join(dir, 'w.json'), 'utf8')).command, 'watch');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the warnings: a registry without RDAP or not read, lookups without an answer, port 53 blocked, a lagging secondary, the budget', () => {
  const server = (address, extra = {}) => ({ address, family: 4, hosts: [`ns-${address.split('.').pop()}.example.net`], status: 'ok', reason: null, serial: 6, transport: 'udp', ...extra });
  assert.deepEqual(watchWarnings(target({ registration: { state: 'unsupported', error: 'no RDAP for .tr' } })), ['example.com: no RDAP for .tr: the registration is not watched (the registry\'s WHOIS has it)']);
  assert.deepEqual(watchWarnings(target({ registration: { ...target().registration, carried: { from: null }, error: 'HTTP 503' } })),
    ['example.com: the registry could not be read (HTTP 503): the last read is kept for the next comparison']);
  assert.deepEqual(watchWarnings(target({ failures: [{ name: 'www.example.com', type: 'A', error: 'SERVFAIL' }] })),
    ['example.com: no answer for www.example.com A: the last read is kept for the next comparison']);
  assert.deepEqual(watchWarnings(target({ authoritative: { view: 'recursive', servers: [] } })),
    ['example.com: the name servers answer nothing over UDP or TCP port 53 from this machine: asked through DoH only']);
  assert.deepEqual(watchWarnings(target({ authoritative: { view: 'authoritative', serial: 6, servers: [server('198.51.100.53'), server('198.51.100.54', { serial: 5 })], lagging: ['198.51.100.54'], cut: 3 } })), [
    'example.com: ns-54.example.net (198.51.100.54) is a lagging secondary: serial 5, the others 6',
    'example.com: 3 record sets not asked of the name servers: over the query budget (--max-queries)'
  ]);
});

test('the summary of a domain whose registry has no RDAP', () => {
  const x = target({ target: 'example-test.com.tr', registration: { state: 'unsupported', error: 'no RDAP for .tr' }, records: [], classes: {}, delegation: { ns: ['ns1.example.net'], ds: null } });
  const doc = watchDoc(x, { t, now: NOW });
  assert.match(renderPlainText(doc), /^Domain watch · example-test\.com\.tr\n- Registration not known: no RDAP for \.tr\n- Name servers \(the zone's NS records\): ns1\.example\.net\n- Records: 0 record sets at 0 names\n/);
});
