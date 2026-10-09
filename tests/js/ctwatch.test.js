/**
 * tests/js/ctwatch.test.js — lib/ctwatch.js: the portfolio's CT watchlist. Cert Spotter rows are
 * the shape the live API returned on 2026-10-08 (`expand=dns_names&expand=issuer&expand=cert_der`),
 * with crafted DER (a precertificate carries the CT poison extension); crt.sh rows are the shape
 * lib/sources.js parses. No network: every request goes to a fake fetch.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  fnv64, dnValue, caName, certId, parseRadarDays, radarBand, createSpotterBudget, spotterWatchUrl, fromSpotterItems, fromCrtshCerts,
  readDomainCt, readPortfolioCt, analyzeCt, matchesCtFilter, expiryEntries, exportCtRow, CT_EXPORT_COLUMNS, emptySeen, readSeen,
  updateSeen, seenText, currentDue, CT_SEEN_MAX_DUE, CT_WATCH_FILTERS, CT_WATCH_FLAGS, CT_WATCH_NOTES, CT_WATCH_STATES, CT_WATCH_SPOTTER_MIN,
  CT_WATCH_MAX_DOMAINS
} from '../../assets/js/lib/ctwatch.js';
import * as ctseen from '../../assets/js/lib/ctseen.js';
import { CERTSPOTTER_ISSUANCES } from '../../assets/js/lib/ctcert.js';
import { sourceStatus } from '../../assets/js/lib/sourcestatus.js';
import { CT_ISSUER as ISSUER, spotterRow as issuance, crtshRow as crtRow, lastSpotterId } from './ct-fake.mjs';

const NOW = new Date('2026-10-08T12:00:00Z');

/* ---- fakes ---------------------------------------------------------------------------- */

const json = (body, { status = 200, headers = {} } = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/** Fake fetch: Cert Spotter (`spotter(url, n)`) and crt.sh (`crtsh(url, n)`); records calls and the concurrency of Cert Spotter's. */
function fakeFetch({ spotter = () => json([]), crtsh = () => json([]) } = {}) {
  const calls = [];
  let s = 0;
  let c = 0;
  let inFlight = 0;
  const impl = async (url, init) => {
    const u = String(url);
    calls.push({ url: u, init });
    if (u.startsWith(CERTSPOTTER_ISSUANCES)) {
      inFlight += 1;
      impl.maxSpotter = Math.max(impl.maxSpotter, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight -= 1;
      return spotter(u, s++);
    }
    if (u.startsWith('https://crt.sh/')) return crtsh(u, c++);
    throw new TypeError(`unexpected fetch ${u}`);
  };
  impl.maxSpotter = 0;
  impl.calls = calls;
  impl.spotterCalls = () => calls.filter((x) => x.url.startsWith(CERTSPOTTER_ISSUANCES));
  impl.crtshCalls = () => calls.filter((x) => x.url.startsWith('https://crt.sh/'));
  return impl;
}

const pagesOf = (...pages) => (url, n) => json(pages[n] || []);
const fakeSleep = () => {
  const waits = [];
  const fn = async (ms, signal) => {
    if (signal && signal.aborted) throw signal.reason;
    waits.push(ms);
  };
  fn.waits = waits;
  return fn;
};
/** A clock that the budget and the reads share. */
const clock = (start = NOW.getTime()) => {
  let t = start;
  const now = () => t;
  now.advance = (ms) => { t += ms; };
  return now;
};
const opts = (extra = {}) => {
  const now = extra.now || clock();
  return { now, budget: extra.budget || createSpotterBudget({ now }), sleepImpl: fakeSleep(), crtshRetryDelayMs: 0, ...extra };
};

/* ---- tests ----------------------------------------------------------------------------- */

describe('helpers', () => {
  test('FNV-1a 64: the published test vectors', () => {
    assert.equal(fnv64(''), 'cbf29ce484222325');
    assert.equal(fnv64('a'), 'af63dc4c8601ec8c');
    assert.equal(fnv64('foobar'), '85944171f73967e8');
  });

  test('a certificate id: the intermediate CN (any case) and the serial (leading 00 bytes ignored); a fallback key without a serial', () => {
    assert.equal(certId({ intermediate: 'Example CA R1', serialHex: '0a' }), certId({ intermediate: 'example ca r1', serialHex: '000A' }));
    assert.notEqual(certId({ intermediate: 'Example CA R1', serialHex: '0a' }), certId({ intermediate: 'Example CA R2', serialHex: '0a' }));
    assert.notEqual(certId({ intermediate: 'Example CA R1', fallback: 'tbs:ab' }), certId({ intermediate: 'Example CA R1', fallback: 'tbs:cd' }));
    assert.match(certId({ serialHex: '01' }), /^[0-9a-f]{16}$/);
  });

  test('the CA of an issuer DN: the known CA, else O, else CN', () => {
    assert.equal(dnValue(ISSUER, 'CN'), 'Example CA R1');
    assert.equal(caName("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt");
    assert.equal(caName(ISSUER), 'Example Trust');
    assert.equal(caName('CN=Internal Root'), 'Internal Root');
  });

  test('the radar thresholds: whole days, largest first, duplicates dropped; anything else is null', () => {
    assert.deepEqual(parseRadarDays('30, 14, 7'), [30, 14, 7]);
    assert.deepEqual(parseRadarDays('7 30;14 14'), [30, 14, 7]);
    assert.deepEqual(parseRadarDays('60'), [60]);
    for (const bad of ['', '  ', '0', '399', '7.5', '-3', 'x', '1,2,3,4,5,6']) assert.equal(parseRadarDays(bad), null, bad);
  });

  test('the radar band: the smallest threshold a certificate is within', () => {
    assert.equal(radarBand(5, [30, 14, 7]), 2);
    assert.equal(radarBand(7, [30, 14, 7]), 2);
    assert.equal(radarBand(10, [30, 14, 7]), 1);
    assert.equal(radarBand(30, [30, 14, 7]), 0);
    assert.equal(radarBand(31, [30, 14, 7]), null);
    assert.equal(radarBand(-1, [30]), 0, 'expired today');
  });

  test('the Cert Spotter quota: counted per hour, a 429 stops it until its reset', () => {
    const now = clock();
    const b = createSpotterBudget({ limit: 3, now });
    assert.equal(b.left(), 3);
    assert.ok(b.take() && b.take() && b.take());
    assert.equal(b.take(), false);
    assert.equal(b.used(), 3);
    assert.equal(b.resetAt().getTime(), NOW.getTime() + 3600000);
    now.advance(3600001);
    assert.equal(b.left(), 3, 'the hour has passed');
    b.exhaust(now() + 600000);
    assert.equal(b.left(), 0);
    assert.ok(b.blocked());
    assert.equal(b.resetAt().getTime(), now() + 600000);
  });

  test('the subdomain search URL expands the names, the issuer, the DER, the revocation and the CA’s problem reporting', () => {
    const u = new URL(spotterWatchUrl('example.com', { after: '123' }));
    assert.equal(u.origin + u.pathname, CERTSPOTTER_ISSUANCES);
    assert.equal(u.searchParams.get('domain'), 'example.com');
    assert.equal(u.searchParams.get('include_subdomains'), 'true');
    assert.deepEqual(u.searchParams.getAll('expand'), ['dns_names', 'issuer', 'cert_der', 'revocation', 'problem_reporting']);
    assert.equal(u.searchParams.get('after'), '123');
  });
});

describe('the two sources read the same certificate the same way', () => {
  test('Cert Spotter rows: names under the domain only, the serial and the precertificate flag from the DER', () => {
    const rows = [
      issuance({ names: ['example.com', 'www.example.com', 'example.net'], serial: 10 }),
      issuance({ names: ['*.example.com'], serial: 11, precert: true }),
      issuance({ names: ['shop.example.com'], serial: 12, revoked: true }),
      issuance({ names: ['example.org'], serial: 13 }),
      issuance({ names: ['old.example.com'], serial: 14, notAfter: '2026-10-01T00:00:00Z' })
    ];
    const certs = fromSpotterItems(rows, 'example.com', { now: NOW });
    assert.equal(certs.length, 3, 'another domain only and an expired one are left out');
    assert.deepEqual(certs[0].names, ['example.com', 'www.example.com']);
    assert.equal(certs[0].serialHex, '0a');
    assert.equal(certs[0].precert, false);
    assert.equal(certs[0].ca, 'Example Trust');
    assert.equal(certs[0].intermediate, 'Example CA R1');
    assert.match(certs[0].url, /^https:\/\/crt\.sh\/\?q=[0-9a-f]{64}$/);
    assert.equal(certs[1].precert, true);
    assert.equal(certs[1].wildcard, true);
    assert.equal(certs[2].revoked, true);
  });

  test('Cert Spotter rows: when and why a certificate was revoked, and the CA’s problem-reporting contact', () => {
    const rows = [
      issuance({ names: ['shop.example.com'], serial: 20, revokedAt: '2026-09-21T10:15:00Z', reason: 1, checkedAt: '2026-10-08T05:00:00Z' }),
      issuance({ names: ['www.example.com'], serial: 21 }),
      issuance({ names: ['api.example.com'], serial: 22, revokedAt: '2026-09-22T00:00:00Z', reason: null }),
      issuance({ names: ['old.example.com'], serial: 23, problemReporting: null }),
      { ...issuance({ names: ['odd.example.com'], serial: 24 }), problem_reporting: 'Report‮ it\r\n\r\n\r\n\r\nhere\u0007', revocation: 'no' }
    ];
    const certs = fromSpotterItems(rows, 'example.com', { now: NOW });
    const by = (name) => certs.find((c) => c.names.includes(name));
    const shop = by('shop.example.com');
    assert.equal(shop.revoked, true);
    assert.deepEqual(shop.revocation, { time: new Date('2026-09-21T10:15:00Z'), reasonCode: 1, reason: 'keyCompromise', checkedAt: new Date('2026-10-08T05:00:00Z') });
    assert.match(shop.problemReporting, /^To revoke a certificate issued by Example Trust/);
    assert.ok(shop.problemReporting.includes('\n  · https://revoke.example.com/portal\n'), 'its line breaks kept');
    assert.deepEqual(by('www.example.com').revocation, { time: null, reasonCode: null, reason: null, checkedAt: new Date('2026-10-08T06:00:00Z') });
    assert.deepEqual([by('api.example.com').revoked, by('api.example.com').revocation.reason], [true, null], 'revoked without a reason given');
    assert.deepEqual([by('old.example.com').revocation, by('old.example.com').problemReporting], [null, null], 'no expansion: not known');
    assert.equal(by('odd.example.com').problemReporting, 'Report it\n\nhere', 'controls and bidi overrides out, blank lines folded');
    assert.equal(by('odd.example.com').revocation, null, 'a revocation that is no object is not read');
    // the CSV says when and why
    const analysis = analyzeCt([{ domain: 'example.com', at: NOW, state: 'ok', source: 'certspotter', certs, failures: [], notes: [], requests: { certspotter: 1, crtsh: 0 } }], { now: NOW });
    const csv = (name) => exportCtRow(analysis.rows.find((r) => r.names.includes(name)));
    assert.deepEqual([csv('shop.example.com').revokedAt, csv('shop.example.com').revocationReason], ['2026-09-21T10:15:00.000Z', 'keyCompromise']);
    assert.deepEqual([csv('www.example.com').revokedAt, csv('www.example.com').revocationReason], ['', '']);
    // crt.sh's twin of a certificate takes Cert Spotter's revocation when the two are merged (crt.sh read last)
    const [twin] = fromCrtshCerts([{ key: 'crtsh:1:14', id: 9, serialHex: '14', issuer: ISSUER, notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2026-10-30T00:00:00Z'), names: ['shop.example.com'], url: 'https://crt.sh/?id=9' }], 'example.com', { now: NOW });
    assert.deepEqual([twin.revocation, twin.problemReporting], [null, null]);
  });

  test('an unreadable DER: no serial, not known whether it is a precertificate, a stable fallback id', () => {
    const row = { ...issuance({ names: ['www.example.com'] }), cert_der: 'not base64 !' };
    const [c] = fromSpotterItems([row], 'example.com', { now: NOW });
    assert.equal(c.serialHex, null);
    assert.equal(c.precert, null);
    assert.equal(c.id, certId({ fallback: 'tbs:' + 'ab'.repeat(32) }));
  });

  test('crt.sh rows (lib/sources.js CtCert): the same id as Cert Spotter’s row of that certificate; precertificate and revocation unknown', () => {
    const spotted = fromSpotterItems([issuance({ names: ['www.example.com'], serial: 10 })], 'example.com', { now: NOW })[0];
    const [c] = fromCrtshCerts([{ key: 'crtsh:7:0a', id: 5, serialHex: '0a', issuer: ISSUER, notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2026-10-30T00:00:00Z'), names: ['www.example.com'], url: 'https://crt.sh/?id=5' }], 'example.com', { now: NOW });
    assert.equal(c.id, spotted.id);
    assert.equal(c.precert, null);
    assert.equal(c.revoked, null);
    assert.equal(c.url, 'https://crt.sh/?id=5');
  });
});

describe('reading a domain', () => {
  test('Cert Spotter in full: its page, then the empty one; nothing goes to crt.sh', async () => {
    const f = fakeFetch({ spotter: pagesOf([issuance({ names: ['www.example.com'], serial: 3 })]) });
    const o = opts();
    const r = await readDomainCt('Example.COM', { ...o, fetchImpl: f });
    assert.equal(r.domain, 'example.com');
    assert.equal(r.state, 'ok');
    assert.equal(r.source, 'certspotter');
    assert.equal(r.certs.length, 1);
    assert.deepEqual(r.requests, { certspotter: 2, crtsh: 0 });
    assert.equal(f.crtshCalls().length, 0);
    assert.equal(new URL(f.spotterCalls()[1].url).searchParams.get('after'), lastSpotterId());
    assert.equal(o.budget.used(), 2);
    assert.equal(f.calls[0].init.credentials, 'omit');
    assert.ok(f.calls[0].init.signal, 'every request has a signal (the timeout)');
  });

  test('fewer than two Cert Spotter requests left: crt.sh only, with the note', async () => {
    const now = clock();
    const budget = createSpotterBudget({ limit: CT_WATCH_SPOTTER_MIN - 1, now });
    const f = fakeFetch({ crtsh: () => json([crtRow({ id: 9, names: ['www.example.com'] })]) });
    const r = await readDomainCt('example.com', { ...opts({ now, budget }), fetchImpl: f });
    assert.equal(f.spotterCalls().length, 0);
    assert.equal(r.source, 'crtsh');
    assert.equal(r.state, 'ok');
    assert.deepEqual(r.notes, ['spotter-quota']);
    assert.equal(r.certs[0].names[0], 'www.example.com');
    assert.equal(new URL(f.crtshCalls()[0].url).searchParams.get('q'), '%.example.com');
  });

  test('a 429 from Cert Spotter: the quota stops for an hour, crt.sh answers, and its list is merged with the pages read', async () => {
    const first = issuance({ names: ['a.example.com'], serial: 20 });
    const f = fakeFetch({
      spotter: (url, n) => (n === 0 ? json([first]) : json({ message: 'rate limited' }, { status: 429 })),
      crtsh: () => json([crtRow({ id: 1, names: ['a.example.com'], serial: '14' }), crtRow({ id: 2, names: ['b.example.com'], serial: '15' })])
    });
    const o = opts();
    const r = await readDomainCt('example.com', { ...o, fetchImpl: f });
    assert.equal(r.state, 'ok');
    assert.equal(r.source, 'crtsh');
    assert.deepEqual(r.notes, ['spotter-quota']);
    assert.equal(r.certs.length, 2, 'the certificate both listed is one');
    assert.equal(r.certs.find((c) => c.names[0] === 'a.example.com').precert, false, 'Cert Spotter’s row kept its flag');
    assert.ok(o.budget.blocked());
    assert.equal(o.budget.left(), 0);
    const f2 = fakeFetch({ crtsh: () => json([]) });
    const r2 = await readDomainCt('example.org', { ...o, fetchImpl: f2 });
    assert.equal(f2.spotterCalls().length, 0, 'the next domain goes straight to crt.sh');
    assert.equal(r2.state, 'ok');
  });

  test('both sources fail: failed, with each source’s failure as sourceStatus reads it', async () => {
    const f = fakeFetch({ spotter: () => json({ message: 'boom' }, { status: 500 }), crtsh: () => new Response('<html>502</html>', { status: 502 }) });
    const r = await readDomainCt('example.com', { ...opts(), fetchImpl: f });
    assert.equal(r.state, 'failed');
    assert.deepEqual(r.failures.map((x) => x.source), ['certspotter', 'crtsh']);
    assert.deepEqual(r.notes, ['spotter-failed']);
    assert.equal(sourceStatus(r.failures[0]).reason, 'http-status');
    assert.equal(sourceStatus(r.failures[1]).kind, 'unavailable');
    assert.equal(f.spotterCalls().length, 1, 'a server error is not retried on Cert Spotter');
  });

  test('crt.sh fails while Cert Spotter’s quota is used up: the n/a names both reasons', async () => {
    const now = clock();
    const budget = createSpotterBudget({ limit: 0, now });
    const f = fakeFetch({ crtsh: () => new Response('busy', { status: 503 }) });
    const r = await readDomainCt('example.com', { ...opts({ now, budget }), fetchImpl: f });
    assert.equal(r.state, 'failed');
    assert.deepEqual(r.failures.map((x) => [x.source, x.errorKind]), [['certspotter', 'rate-limit'], ['crtsh', 'unavailable']]);
    assert.equal(sourceStatus(r.failures[0]).reason, 'rate-limit-hour');
  });

  test('more issuances than the page cap: partial, the note, and crt.sh is not asked', async () => {
    const f = fakeFetch({ spotter: (url, n) => json([issuance({ names: [`h${n}.example.com`], serial: 30 + n })]) });
    const r = await readDomainCt('example.com', { ...opts(), fetchImpl: f, maxPages: 3 });
    assert.equal(r.state, 'partial');
    assert.deepEqual(r.notes, ['truncated']);
    assert.equal(r.certs.length, 3);
    assert.equal(f.crtshCalls().length, 0);
  });

  test('paced: a gap between two Cert Spotter requests', async () => {
    const f = fakeFetch({ spotter: pagesOf([issuance({ names: ['www.example.com'] })]) });
    const o = opts();
    await readDomainCt('example.com', { ...o, fetchImpl: f, spacingMs: 1500 });
    assert.deepEqual(o.sleepImpl.waits, [1500]);
  });

  test('an abort rejects; nothing else does', async () => {
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(readDomainCt('example.com', { ...opts(), fetchImpl: fakeFetch(), signal: ctl.signal }), { name: 'AbortError' });
    await assert.rejects(readDomainCt('not a domain', { ...opts(), fetchImpl: fakeFetch() }), TypeError);
  });

  test('the portfolio: each read lands as it comes, Cert Spotter one request at a time, the list capped', async () => {
    const f = fakeFetch({ spotter: (url) => (url.includes('after=') ? json([]) : json([issuance({ names: [`www.${new URL(url).searchParams.get('domain')}`] })])) });
    const landed = [];
    const now = clock();
    const reads = await readPortfolioCt(['example.com', 'example.org', 'example.net', 'example.com'], { ...opts({ now, budget: createSpotterBudget({ limit: 100, now }) }), fetchImpl: f, onRead: (r) => landed.push(r.domain) });
    assert.deepEqual(reads.map((r) => r.domain), ['example.com', 'example.org', 'example.net']);
    assert.deepEqual([...landed].sort(), ['example.com', 'example.net', 'example.org']);
    assert.equal(f.maxSpotter, 1);
    assert.ok(reads.every((r) => r.state === 'ok' && r.certs.length === 1));
    assert.equal(CT_WATCH_MAX_DOMAINS, 50);
  });
});

describe('the analysis', () => {
  const read = (certs, extra = {}) => ({ domain: 'example.com', at: NOW, state: 'ok', source: 'certspotter', certs, failures: [], notes: [], requests: {}, ...extra });
  const spotted = (rows) => fromSpotterItems(rows, 'example.com', { now: NOW });

  test('the newest of each name set; one renewed with more names supersedes the old; the radar watches the current ones', () => {
    const certs = spotted([
      issuance({ names: ['www.example.com'], serial: 1, notBefore: '2026-07-15T00:00:00Z', notAfter: '2026-10-13T00:00:00Z' }),
      issuance({ names: ['www.example.com'], serial: 2, notBefore: '2026-09-10T00:00:00Z', notAfter: '2026-12-09T00:00:00Z' }),
      issuance({ names: ['api.example.com'], serial: 3, notBefore: '2026-07-20T00:00:00Z', notAfter: '2026-10-18T00:00:00Z' }),
      issuance({ names: ['mail.example.com'], serial: 4, notBefore: '2026-07-11T00:00:00Z', notAfter: '2026-10-11T00:00:00Z' }),
      issuance({ names: ['mail.example.com', 'smtp.example.com'], serial: 5, notBefore: '2026-09-01T00:00:00Z', notAfter: '2026-11-30T00:00:00Z' }),
      issuance({ names: ['*.example.com'], serial: 6, notBefore: '2026-08-01T00:00:00Z', notAfter: '2026-10-16T00:00:00Z', precert: true })
    ]);
    const { rows, counts, first } = analyzeCt([read(certs)], { now: NOW, days: [30, 14, 7] });
    const by = (serial) => rows.find((r) => r.serialHex === serial.toString(16).padStart(2, '0'));
    assert.equal(by(1).superseded, true);
    assert.equal(by(1).newest, false);
    assert.equal(by(2).current, true);
    assert.equal(by(3).current, true, 'the wildcard covers api, but expires before it');
    assert.equal(by(4).current, false, 'renewed with smtp added');
    assert.equal(by(4).newest, true, 'still the newest of its own name set');
    assert.equal(by(4).superseded, true);
    assert.equal(by(6).precert, true);
    assert.equal(by(6).current, true);
    assert.deepEqual(by(6).flags, ['precert', 'wildcard']);
    assert.equal(by(6).band, 2, '7 days left: within 7');
    assert.equal(by(3).band, 1, '9 days left: within 14');
    assert.equal(by(2).band, null, 'two months left');
    assert.equal(by(1).band, null, 'a superseded certificate is not on the radar');
    assert.deepEqual(first, ['example.com']);
    assert.equal(counts.all, 6);
    assert.equal(counts.precert, 1);
    assert.equal(counts.wildcard, 1);
    assert.equal(counts.new, 0, 'no earlier check: nothing is "new"');
    assert.ok(rows.every((r) => r.isNew === null));
    assert.deepEqual(rows.map((r) => r.domain + ' ' + r.notAfter.toISOString().slice(0, 10)).slice(0, 2), ['example.com 2026-10-11', 'example.com 2026-10-13'], 'soonest expiry first');
  });

  test('a wildcard that expires later supersedes the name it covers; a revoked certificate supersedes nothing and is never the newest', () => {
    const certs = spotted([
      issuance({ names: ['api.example.com'], serial: 1, notAfter: '2026-10-15T00:00:00Z' }),
      issuance({ names: ['*.example.com'], serial: 2, notAfter: '2026-12-15T00:00:00Z' }),
      issuance({ names: ['shop.eu.example.com'], serial: 3, notAfter: '2026-10-15T00:00:00Z' }),
      issuance({ names: ['shop.eu.example.com', 'www.eu.example.com'], serial: 4, notAfter: '2026-12-15T00:00:00Z', revoked: true })
    ]);
    const { rows } = analyzeCt([read(certs)], { now: NOW });
    const by = (s) => rows.find((r) => r.serialHex === `0${s}`);
    assert.equal(by(1).superseded, true);
    assert.equal(by(3).superseded, false);
    assert.equal(by(3).current, true);
    assert.equal(by(4).newest, false);
    assert.deepEqual(by(4).flags, ['revoked']);
  });

  test('new since the last check, unexpected CAs, and a failed read left out', () => {
    const certs = spotted([
      issuance({ names: ['www.example.com'], serial: 1 }),
      issuance({ names: ['new.example.com'], serial: 2, issuer: 'C=US, O=Other CA Inc, CN=Other CA 1' })
    ]);
    const seen = updateSeen(emptySeen(), [read([certs[0]], { at: new Date('2026-10-01T00:00:00Z') })], { now: new Date('2026-10-01T00:00:00Z') });
    const { rows, counts, first } = analyzeCt([read(certs), { domain: 'example.org', state: 'failed', certs: [] }], { now: NOW, seen, expected: ['Example Trust'] });
    assert.deepEqual(Object.fromEntries(rows.map((r) => [r.names[0], [r.isNew, r.unexpected]])), { 'www.example.com': [false, false], 'new.example.com': [true, true] });
    assert.equal(counts.new, 1);
    assert.equal(counts.unexpected, 1);
    assert.deepEqual(first, []);
    assert.deepEqual(rows.find((r) => r.isNew).flags, ['new', 'unexpected']);
    const none = analyzeCt([read(certs)], { now: NOW, expected: [] });
    assert.ok(none.rows.every((r) => r.unexpected === null), 'no expected CAs: no flag');
  });

  test('a known certificate (lib/waivers.js, kind cert: its key\'s SHA-256, or its own) is never new nor unexpected while its waiver lasts', () => {
    const KEY = '9a'.repeat(32);
    const certs = spotted([
      issuance({ names: ['www.example.com'], serial: 1 }),
      { ...issuance({ names: ['cdn.example.com'], serial: 2, issuer: 'C=US, O=Other CA Inc, CN=Other CA 1' }), pubkey_sha256: KEY.toUpperCase() },
      issuance({ names: ['shop.example.com'], serial: 3, issuer: 'C=US, O=Other CA Inc, CN=Other CA 1' })
    ]);
    assert.equal(certs[1].spkiSha256, KEY, 'Cert Spotter\'s pubkey_sha256, in lower case');
    assert.match(certs[0].spkiSha256, /^[0-9a-f]{64}$/);
    const seen = updateSeen(emptySeen(), [read([certs[0]], { at: new Date('2026-10-01T00:00:00Z') })], { now: new Date('2026-10-01T00:00:00Z') });
    const known = [
      { id: 'w-key', kind: 'cert', domain: 'example.com', ref: KEY, reason: 'Our CDN', owner: 'Web team', created: null, expires: '2026-12-31' },
      { id: 'w-old', kind: 'cert', domain: 'example.com', ref: certs[2].sha256, reason: 'Shop vendor', owner: '', created: null, expires: '2026-10-01' },
      { id: 'w-other', kind: 'cert', domain: 'example.org', ref: certs[0].spkiSha256, reason: 'elsewhere', owner: '', created: null, expires: '2026-12-31' }
    ];
    const { rows, counts } = analyzeCt([read(certs)], { now: NOW, seen, expected: ['Example Trust'], known });
    const by = (name) => rows.find((r) => r.names[0] === name);
    assert.deepEqual([by('cdn.example.com').isNew, by('cdn.example.com').unexpected, by('cdn.example.com').flags], [false, false, ['known']]);
    assert.deepEqual(by('cdn.example.com').known, { id: 'w-key', expires: '2026-12-31', reason: 'Our CDN', owner: 'Web team' });
    // the shop certificate's waiver is over: flagged as before, and it says so
    assert.deepEqual([by('shop.example.com').flags, by('shop.example.com').known, by('shop.example.com').knownExpired.id], [['new', 'unexpected'], null, 'w-old']);
    assert.deepEqual([by('www.example.com').known, by('www.example.com').flags], [null, []], 'another domain\'s waiver covers nothing here');
    assert.deepEqual([counts.new, counts.unexpected, counts.known], [1, 1, 1]);
    assert.equal(matchesCtFilter(by('cdn.example.com'), 'new'), false);
    assert.equal(matchesCtFilter(by('cdn.example.com'), 'unexpected'), false);
    const csv = exportCtRow(by('cdn.example.com'));
    assert.deepEqual([csv.publicKeySha256, csv.knownUntil, csv.new, csv.unexpectedCa], [KEY, '2026-12-31', 'no', 'no']);
    // without waivers, the same rows are flagged
    assert.deepEqual(analyzeCt([read(certs)], { now: NOW, seen, expected: ['Example Trust'] }).rows.find((r) => r.names[0] === 'cdn.example.com').flags, ['new', 'unexpected']);
    // crt.sh says no key: such a row has none to match
    const [crt] = fromCrtshCerts([{ key: 'crtsh:1:1', id: 1, serialHex: '01', issuer: ISSUER, notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2026-10-30T00:00:00Z'), names: ['www.example.com'] }], 'example.com', { now: NOW });
    assert.equal(crt.spkiSha256, null);
    // a check read before the waiver's end and shown after it: the waivers are matched when the rows are drawn (`knownAt`), the days left at the read
    const ending = [{ ...known[0], expires: '2026-10-09' }];
    const shown = analyzeCt([read(certs)], { now: NOW, knownAt: new Date('2026-10-10T12:00:00Z'), seen, expected: ['Example Trust'], known: ending });
    const cdn = shown.rows.find((r) => r.names[0] === 'cdn.example.com');
    assert.deepEqual([cdn.known, cdn.knownExpired.expires, cdn.flags], [null, '2026-10-09', ['new', 'unexpected']]);
    assert.equal(cdn.daysLeft, by('cdn.example.com').daysLeft, 'the days left as at the read');
    assert.deepEqual(analyzeCt([read(certs)], { now: NOW, seen, expected: ['Example Trust'], known: ending }).rows.find((r) => r.names[0] === 'cdn.example.com').flags, ['known'],
      'without knownAt, matched at the read');
  });

  test('the filters', () => {
    const row = { current: true, daysLeft: 10, isNew: true, unexpected: false, wildcard: false, precert: null };
    assert.deepEqual(CT_WATCH_FILTERS.filter((f) => matchesCtFilter(row, f, { radar: 30 })), ['current', 'all', 'new', 'expiring']);
    assert.equal(matchesCtFilter({ ...row, current: false }, 'expiring', { radar: 30 }), false);
    assert.equal(matchesCtFilter(row, 'expiring', { radar: 7 }), false);
  });

  test('the exports: a CSV row per certificate, a calendar entry per current name set with a UID that survives a renewal', () => {
    const before = spotted([issuance({ names: ['www.example.com'], serial: 1, notAfter: '2026-10-30T00:00:00Z' })]);
    const after = spotted([issuance({ names: ['www.example.com'], serial: 2, notBefore: '2026-10-05T00:00:00Z', notAfter: '2027-01-03T00:00:00Z' })]);
    const a = expiryEntries(analyzeCt([read(before)], { now: NOW }).rows);
    const b = expiryEntries(analyzeCt([read(after)], { now: NOW }).rows);
    assert.equal(a.length, 1);
    assert.equal(a[0].uid, b[0].uid);
    assert.match(a[0].uid, /^ct-[0-9a-f]{16}@domainscope$/);
    assert.notEqual(a[0].date.getTime(), b[0].date.getTime());
    const row = exportCtRow(analyzeCt([read(before)], { now: NOW }).rows[0]);
    assert.deepEqual(Object.keys(row), [...CT_EXPORT_COLUMNS]);
    assert.equal(row.names, 'www.example.com');
    assert.equal(row.new, '', 'unknown without an earlier check');
    assert.equal(row.precertificateOnly, 'no');
    assert.equal(row.daysLeft, 21);
  });
});

describe('the baseline', () => {
  const c = (id, notAfter) => ({ id, notAfter: new Date(notAfter) });

  test('update: the ids of each read domain added to those seen before, expired ones dropped, a failed domain untouched', () => {
    let seen = updateSeen(emptySeen(), [
      { domain: 'example.com', at: new Date('2026-10-01T00:00:00Z'), state: 'ok', certs: [c('0000000000000001', '2026-10-05T00:00:00Z'), c('0000000000000002', '2026-12-01T00:00:00Z')] },
      { domain: 'example.org', at: new Date('2026-10-01T00:00:00Z'), state: 'ok', certs: [c('0000000000000003', '2026-12-01T00:00:00Z')] }
    ], { now: new Date('2026-10-01T00:00:00Z') });
    seen = updateSeen(seen, [
      { domain: 'example.com', at: NOW, state: 'partial', certs: [c('0000000000000004', '2026-12-02T00:00:00Z')] },
      { domain: 'example.org', at: NOW, state: 'failed', certs: [] }
    ], { now: NOW });
    // these test certificates carry no names or issue date: none is current, `due` is empty
    assert.deepEqual(seen.domains['example.com'], { at: NOW.toISOString(), ids: { '0000000000000002': '2026-12-01', '0000000000000004': '2026-12-02' }, due: [] });
    assert.equal(seen.domains['example.org'].at, '2026-10-01T00:00:00.000Z');
  });

  test('due: the expiry days of the check\'s current certificates — never one its renewal replaced, a revoked one or one not issued yet', () => {
    const cert = (id, names, notBefore, notAfter, extra = {}) => ({ id, names, notBefore: new Date(notBefore), notAfter: new Date(notAfter), ...extra });
    const read = {
      domain: 'example.com', at: NOW, state: 'ok', certs: [
        // the renewal of www and the apex replaced the old one: only the renewal is due
        cert('0000000000000011', ['example.com', 'www.example.com'], '2026-07-01T00:00:00Z', '2026-10-15T00:00:00Z'),
        cert('0000000000000012', ['example.com', 'www.example.com'], '2026-09-20T00:00:00Z', '2026-12-19T00:00:00Z'),
        // a name set of its own (two labels down: the wildcard below does not cover it), current
        cert('0000000000000013', ['api.eu.example.com'], '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z'),
        // revoked: never current
        cert('0000000000000014', ['mail.example.com'], '2026-08-01T00:00:00Z', '2026-10-20T00:00:00Z', { revoked: true }),
        // logged ahead of its validity: not current yet
        cert('0000000000000015', ['shop.example.com'], '2026-12-01T00:00:00Z', '2027-03-01T00:00:00Z'),
        // a wildcard covers an older single name: the single name is superseded
        cert('0000000000000016', ['cdn.example.com'], '2026-06-01T00:00:00Z', '2026-10-12T00:00:00Z'),
        cert('0000000000000017', ['*.example.com'], '2026-09-01T00:00:00Z', '2026-11-30T00:00:00Z')
      ]
    };
    const seen = updateSeen(emptySeen(), [read], { now: NOW });
    assert.deepEqual(seen.domains['example.com'].due, ['2026-10-30', '2026-11-30', '2026-12-19']);
    assert.deepEqual(currentDue(read, NOW), ['2026-10-30', '2026-11-30', '2026-12-19']);
    // what analyzeCt calls current is what `due` keeps, one day per certificate
    const rows = analyzeCt([read], { now: NOW }).rows;
    assert.deepEqual(rows.filter((r) => r.current).map((r) => r.notAfter.toISOString().slice(0, 10)).sort(), seen.domains['example.com'].due);
    // a second current certificate that ends the same day as another counts as one more
    const twin = { ...read, certs: [...read.certs, cert('0000000000000018', ['vpn.eu.example.com'], '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z')] };
    assert.deepEqual(currentDue(twin, NOW), ['2026-10-30', '2026-10-30', '2026-11-30', '2026-12-19']);
    // the baseline's ids keep every certificate seen (the replaced one too): Home never counts them
    assert.ok('0000000000000011' in seen.domains['example.com'].ids);
  });

  test('the baseline lives in lib/ctseen.js (Home reads it without the watch): ctwatch re-exports the same functions', () => {
    for (const name of ['emptySeen', 'readSeen', 'updateSeen', 'seenText', 'currentDue', 'certStanding', 'CT_SEEN_VERSION', 'CT_SEEN_MAX_CHARS', 'CT_SEEN_MAX_DUE']) {
      assert.ok(name in ctseen, name);
    }
    assert.equal(readSeen, ctseen.readSeen);
    assert.equal(updateSeen, ctseen.updateSeen);
    assert.equal(currentDue, ctseen.currentDue);
    assert.deepEqual(ctseen.certStanding([], NOW), []);
    assert.deepEqual(ctseen.certStanding(null, NOW), []);
    assert.deepEqual(currentDue(null, NOW), []);
  });

  test('due is kept by readSeen when it is a list of days (sorted, one per certificate); an older baseline has none', () => {
    const at = NOW.toISOString();
    const text = JSON.stringify({ v: 1, domains: {
      'example.com': { at, ids: {}, due: ['2026-12-01', 'soon', '2026-10-20', '2026-12-01', 7] },
      'example.org': { at, ids: {} },
      'example.net': { at, ids: {}, due: 'not a list' }
    } });
    const seen = readSeen(text);
    assert.deepEqual(seen.domains['example.com'].due, ['2026-10-20', '2026-12-01', '2026-12-01'], 'two certificates that end the same day count twice');
    assert.equal('due' in seen.domains['example.org'], false, 'written before `due` existed');
    assert.equal('due' in seen.domains['example.net'], false);
    assert.deepEqual(readSeen(seenText(seen)), seen, 'round-trips');
    const many = Array.from({ length: CT_SEEN_MAX_DUE + 10 }, (_, i) => new Date(Date.UTC(2027, 0, 1 + i)).toISOString().slice(0, 10));
    assert.equal(readSeen(JSON.stringify({ v: 1, domains: { 'example.com': { at, ids: {}, due: many } } })).domains['example.com'].due.length, CT_SEEN_MAX_DUE);
  });

  test('the text round-trips; junk is dropped entry by entry; another version is no baseline', () => {
    const seen = updateSeen(emptySeen(), [{ domain: 'example.com', at: NOW, state: 'ok', certs: [c('00000000000000aa', '2026-12-01T00:00:00Z')] }], { now: NOW });
    const text = seenText(seen);
    assert.deepEqual(readSeen(text), seen);
    const junk = JSON.stringify({ v: 1, domains: { 'example.com': { at: NOW.toISOString(), ids: { '00000000000000aa': '2026-12-01', nothex: '2026-12-01', '00000000000000bb': 'soon' } }, 'Not A Domain!': { at: NOW.toISOString(), ids: {} }, 'example.org': { at: 'never', ids: {} } } });
    assert.deepEqual(Object.keys(readSeen(junk).domains), ['example.com']);
    assert.deepEqual(readSeen(junk).domains['example.com'].ids, { '00000000000000aa': '2026-12-01' });
    assert.deepEqual(readSeen(JSON.stringify({ v: 2, domains: {} })), emptySeen());
    assert.deepEqual(readSeen('{ broken'), emptySeen());
    assert.deepEqual(readSeen(''), emptySeen());
    assert.equal(seenText(emptySeen()), '');
  });

  test('a baseline that would not fit leaves out the domains read longest ago', () => {
    const seen = { v: 1, domains: { 'example.com': { at: '2026-10-08T00:00:00.000Z', ids: { '0000000000000001': '2026-12-01' } }, 'example.org': { at: '2026-09-01T00:00:00.000Z', ids: { '0000000000000002': '2026-12-01' } } } };
    const full = seenText(seen);
    const cut = seenText(seen, { maxChars: full.length - 1 });
    assert.deepEqual(Object.keys(readSeen(cut).domains), ['example.com']);
  });
});

test('the codes the UI words are enumerable', () => {
  assert.deepEqual([...CT_WATCH_FLAGS], ['new', 'unexpected', 'precert', 'wildcard', 'revoked', 'superseded', 'known']);
  assert.deepEqual([...CT_WATCH_STATES], ['ok', 'partial', 'failed']);
  assert.deepEqual([...CT_WATCH_NOTES], ['spotter-quota', 'spotter-failed', 'crtsh-partial', 'truncated', 'first']);
  for (const list of [CT_WATCH_FLAGS, CT_WATCH_FILTERS, CT_WATCH_STATES, CT_WATCH_NOTES]) assert.ok(Object.isFrozen(list));
});
