/**
 * lib/ctcert.js — the public certificate of a host name from Certificate Transparency.
 * Pure Node, no network: Cert Spotter and crt.sh are mocked `fetchImpl`s answering with the
 * shapes probed live on 2026-09-27 (see the module header). Certificates are crafted DER
 * (unsigned: the parser does not verify signatures) with documentation names only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CERTSPOTTER_ISSUANCES, CT_COOLDOWN_MS, CT_LOOKUP_STATUSES, CT_MAX_PAGES, CT_PAGE_SIZE, CT_SPOTTER_STATES,
  certspotterUrl, coversCtHost, createCtCooldown, crtshSearchUrls, lookupCtCertificate, normalizeCtHost,
  selectCrtshEntry, selectIssuance
} from '../../assets/js/lib/ctcert.js';
import { sourceQuota } from '../../assets/js/lib/sources.js';
import { parseCertificates, computeFingerprints } from '../../assets/js/lib/x509.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const NOW = new Date('2026-09-27T12:00:00Z');

/* ---- crafted certificates ------------------------------------------------------ */

const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const ctx = (n, constructed, ...p) => tlv(0x80 | (constructed ? 0x20 : 0) | n, ...p);
const oid = (s) => {
  const arcs = s.split('.').map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const a of arcs.slice(2)) {
    const bytes = [a & 0x7f];
    for (let x = a >> 7; x > 0; x >>= 7) bytes.unshift((x & 0x7f) | 0x80);
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
};
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const cn = (value) => seq(set(seq(oid('2.5.4.3'), utf8(value))));
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
const SPKI = Buffer.from(parseCertificates(readFileSync(join(FIX, 'rsa_multi_san.der'))).leaf.spkiDer);
/** 'YYMMDDhhmmssZ' UTCTime of a Date. */
const utcTime = (d) => d.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z');

/**
 * DER of a certificate for `names` (dNSName SANs), valid notBefore → notAfter; `precert` adds the
 * critical CT poison extension.
 */
function certDer({ names, notBefore, notAfter, serial = 1, precert = false }) {
  const exts = [seq(oid('2.5.29.17'), tlv(0x04, seq(...names.map((n) => ctx(2, false, Buffer.from(n, 'latin1'))))))];
  if (precert) exts.push(seq(oid('1.3.6.1.4.1.11129.2.4.3'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, Buffer.from([0x05, 0x00]))));
  const tbs = seq(
    ctx(0, true, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([serial])),
    SHA256_RSA,
    cn('Test CA'),
    seq(tlv(0x17, Buffer.from(utcTime(new Date(notBefore)))), tlv(0x17, Buffer.from(utcTime(new Date(notAfter))))),
    cn(names[0].replace(/^\*\./, 'wild.')),
    SPKI,
    ctx(3, true, seq(...exts))
  );
  return seq(tbs, SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0xab)])));
}

let nextId = 17000000000;
/** A Cert Spotter issuance (JSON row) with its DER, as `expand=dns_names&expand=cert_der` returns it. */
function issuance({ names, notBefore = '2026-08-01T00:00:00Z', notAfter = '2026-10-30T00:00:00Z', precert = false, revoked = false, serial, id, der } = {}) {
  nextId += 1;
  const bytes = der || certDer({ names, notBefore, notAfter, precert, serial: serial ?? (nextId % 250) + 1 });
  return {
    id: String(id ?? nextId),
    tbs_sha256: 'ab'.repeat(32),
    cert_sha256: 'cd'.repeat(32),
    dns_names: names,
    pubkey_sha256: 'ef'.repeat(32),
    not_before: notBefore,
    not_after: notAfter,
    revoked,
    cert_der: Buffer.from(bytes).toString('base64')
  };
}

/* ---- mocked services -------------------------------------------------------------- */

const json = (body, { status = 200, headers = {} } = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*', ...headers }
});

/**
 * fetchImpl answering Cert Spotter (`spotter(url, n)`, n = its 0-based call number) and crt.sh
 * (`crtsh(url, n)`); records every call.
 */
function mockFetch({ spotter = () => json([]), crtsh = () => json([]) } = {}) {
  const calls = [];
  let s = 0;
  let c = 0;
  const impl = async (url, init) => {
    const u = String(url);
    calls.push({ url: u, init });
    if (u.startsWith(CERTSPOTTER_ISSUANCES)) return spotter(u, s++);
    if (u.startsWith('https://crt.sh/')) return crtsh(u, c++);
    throw new TypeError(`unexpected fetch ${u}`);
  };
  impl.calls = calls;
  impl.spotterCalls = () => calls.filter((x) => x.url.startsWith(CERTSPOTTER_ISSUANCES));
  impl.crtshCalls = () => calls.filter((x) => x.url.startsWith('https://crt.sh/'));
  return impl;
}

/** Cert Spotter answering `pages` in turn, then the empty last page. */
const pagesOf = (...pages) => (url, n) => json(pages[n] || []);

/** A crt.sh row. */
function crtRow({ id, names, notBefore = '2026-08-01T00:00:00', notAfter = '2026-10-30T00:00:00', serial = '0a0b0c', ca = 1, cn = null }) {
  return {
    issuer_ca_id: ca,
    issuer_name: 'C=US, O=Example Trust, CN=Example CA R1',
    common_name: cn ?? names[0],
    name_value: names.join('\n'),
    id,
    not_before: notBefore,
    not_after: notAfter,
    serial_number: serial,
    result_count: 1
  };
}

const lookup = (input, fetchImpl, opts = {}) => lookupCtCertificate(input, { fetchImpl, now: NOW, cooldown: createCtCooldown(), crtshRetryDelayMs: 0, ...opts });

/* ---- tests ------------------------------------------------------------------------ */

describe('names and URLs', () => {
  test('normalizeCtHost: host names, URLs and wildcards; IPs, single labels and *.<public suffix> refused', () => {
    assert.equal(normalizeCtHost('https://WWW.Example.com:443/login?x=1'), 'www.example.com');
    assert.equal(normalizeCtHost('  shop.example.net. '), 'shop.example.net');
    assert.equal(normalizeCtHost('*.example.com'), '*.example.com');
    assert.equal(normalizeCtHost('bücher.example.com'), 'xn--bcher-kva.example.com');
    for (const bad of ['', '   ', '192.0.2.1', '[2001:db8::1]', 'localhost', '*.com', '*.co.uk', 'a b.example.com', 'x.*.example.com', null]) {
      assert.equal(normalizeCtHost(bad), null, String(bad));
    }
  });

  test('coversCtHost: RFC 6125 for a host, the very name for a wildcard query', () => {
    assert.ok(coversCtHost(['*.example.com'], 'www.example.com'));
    assert.ok(!coversCtHost(['*.example.com'], 'example.com'));
    assert.ok(!coversCtHost(['*.example.com'], 'a.b.example.com'));
    assert.ok(coversCtHost(['example.com', 'www.example.com'], 'www.example.com'));
    assert.ok(coversCtHost(['*.example.com', 'example.com'], '*.example.com'));
    assert.ok(!coversCtHost(['www.example.com'], '*.example.com'), 'a wildcard query wants the wildcard name itself');
    assert.ok(!coversCtHost(null, 'www.example.com'));
  });

  test('certspotterUrl: single-host query with wildcard matching, names and DER expanded, paging', () => {
    assert.equal(certspotterUrl('www.example.com'),
      `${CERTSPOTTER_ISSUANCES}?domain=www.example.com&match_wildcards=true&expand=dns_names&expand=cert_der`);
    assert.equal(certspotterUrl('*.example.com', { after: '17000000001' }),
      `${CERTSPOTTER_ISSUANCES}?domain=*.example.com&expand=dns_names&expand=cert_der&after=17000000001`);
    assert.ok(!certspotterUrl('www.example.com').includes('include_subdomains'), 'never the 10-per-hour full-domain query');
  });

  test('crtshSearchUrls: the name, plus its parent wildcard below a registrable domain', () => {
    const q = (url) => new URL(url).searchParams.get('q');
    assert.deepEqual(crtshSearchUrls('www.example.com').map(q), ['www.example.com', '*.example.com']);
    assert.deepEqual(crtshSearchUrls('a.b.example.co.uk').map(q), ['a.b.example.co.uk', '*.b.example.co.uk']);
    assert.deepEqual(crtshSearchUrls('example.com').map(q), ['example.com'], 'no *.com');
    assert.deepEqual(crtshSearchUrls('example.co.uk').map(q), ['example.co.uk'], 'no *.co.uk');
    assert.deepEqual(crtshSearchUrls('*.example.com').map(q), ['*.example.com']);
    for (const url of crtshSearchUrls('www.example.com')) {
      const p = new URL(url).searchParams;
      assert.equal(p.get('output'), 'json');
      assert.equal(p.get('exclude'), 'expired');
      assert.equal(p.get('deduplicate'), null, 'both rows of a certificate are kept');
    }
  });

  test('constants and vocabularies', () => {
    assert.equal(CT_PAGE_SIZE, 100);
    assert.equal(CT_MAX_PAGES, 5);
    assert.equal(CT_COOLDOWN_MS, 3600000);
    assert.deepEqual(CT_LOOKUP_STATUSES, ['found', 'manual', 'not-found', 'error']);
    assert.deepEqual(CT_SPOTTER_STATES, ['ok', 'partial', 'failed', 'skipped']);
    assert.ok(Object.isFrozen(CT_LOOKUP_STATUSES) && Object.isFrozen(CT_SPOTTER_STATES));
  });
});

describe('selectIssuance', () => {
  const host = 'www.example.com';

  test('the newest valid, non-revoked certificate that covers the host; ties go to the higher id', async () => {
    const older = issuance({ names: ['*.example.com', 'example.com'], notBefore: '2026-07-01T00:00:00Z', id: '17000000100' });
    const newest = issuance({ names: ['www.example.com'], notBefore: '2026-09-01T00:00:00Z', id: '17000000050' });
    const twin = issuance({ names: ['www.example.com', 'example.com'], notBefore: '2026-09-01T00:00:00Z', id: '17000000060' });
    const r = selectIssuance([older, newest, twin], host, { now: NOW });
    assert.equal(r.issuance.id, '17000000060', 'same not_before: higher id wins');
    assert.deepEqual(r.issuance.dnsNames, ['example.com', 'www.example.com']);
    assert.equal(r.issuance.notBefore.toISOString(), '2026-09-01T00:00:00.000Z');
    assert.equal(r.issuance.sha256, 'cd'.repeat(32));
    assert.equal(r.issuance.url, `https://crt.sh/?q=${'cd'.repeat(32)}`);
    assert.equal(r.candidates, 3);
    assert.equal(r.precertificate, false);
    assert.equal(r.newerPrecertificate, null);
    assert.ok(r.der instanceof Uint8Array);
    assert.deepEqual(r.certificate.dnsNames, ['www.example.com', 'example.com']);
    assert.equal((await computeFingerprints(r.der)).sha256, (await computeFingerprints(Buffer.from(twin.cert_der, 'base64'))).sha256);
  });

  test('skips what does not cover the host, is not valid now, is revoked or cannot be read', () => {
    const rows = [
      issuance({ names: ['api.example.com'] }),
      issuance({ names: ['*.example.com'], notBefore: '2026-10-01T00:00:00Z', notAfter: '2026-12-30T00:00:00Z' }),
      issuance({ names: ['*.example.com'], notBefore: '2026-01-01T00:00:00Z', notAfter: '2026-03-01T00:00:00Z' }),
      issuance({ names: ['*.example.com'], notBefore: '2026-09-10T00:00:00Z', revoked: true }),
      { ...issuance({ names: ['*.example.com'], notBefore: '2026-09-20T00:00:00Z' }), cert_der: '%%% not base64' },
      // Cert Spotter's names say "covers", the DER does not: never trusted over the certificate.
      issuance({ names: ['www.example.com'], notBefore: '2026-09-15T00:00:00Z', der: certDer({ names: ['other.example.net'], notBefore: '2026-09-15T00:00:00Z', notAfter: '2026-12-01T00:00:00Z' }) }),
      { ...issuance({ names: ['*.example.com'] }), not_before: 'yesterday' },
      issuance({ names: ['*.example.com'], notBefore: '2026-08-15T00:00:00Z' }),
      null,
      'garbage'
    ];
    const r = selectIssuance(rows, host, { now: NOW });
    assert.equal(r.issuance.notBefore.toISOString(), '2026-08-15T00:00:00.000Z');
    assert.deepEqual(r.skipped, { notCovering: 1, notYetValid: 1, expired: 1, revoked: 1, unreadable: 3 });
    assert.equal(r.candidates, 3, 'the undecodable, mismatching and good issuance were current');
  });

  test('a newer issuance logged only as a precertificate: the older final certificate, with a note', () => {
    const final = issuance({ names: ['*.example.com'], notBefore: '2026-08-01T00:00:00Z' });
    const pre = issuance({ names: ['*.example.com'], notBefore: '2026-09-20T00:00:00Z', precert: true });
    const r = selectIssuance([final, pre], host, { now: NOW });
    assert.equal(r.issuance.id, final.id);
    assert.equal(r.precertificate, false);
    assert.equal(r.certificate.isPrecertificate, false);
    assert.equal(r.newerPrecertificate.id, pre.id);
    assert.equal(r.newerPrecertificate.notBefore.toISOString(), '2026-09-20T00:00:00.000Z');
  });

  test('only a precertificate logged: it is returned, flagged', () => {
    const pre = issuance({ names: ['www.example.com'], precert: true });
    const r = selectIssuance([pre], host, { now: NOW });
    assert.equal(r.issuance.id, pre.id);
    assert.equal(r.precertificate, true);
    assert.equal(r.certificate.isPrecertificate, true);
    assert.equal(r.newerPrecertificate, null);
  });

  test('a wildcard query wants certificates holding that name', () => {
    const exact = issuance({ names: ['www.example.com'], notBefore: '2026-09-20T00:00:00Z' });
    const wild = issuance({ names: ['*.example.com', 'example.com'], notBefore: '2026-08-01T00:00:00Z' });
    assert.equal(selectIssuance([exact, wild], '*.example.com', { now: NOW }).issuance.id, wild.id);
  });

  test('nothing to pick', () => {
    const r = selectIssuance([], host, { now: NOW });
    assert.equal(r.issuance, null);
    assert.equal(r.der, null);
    assert.equal(r.candidates, 0);
    assert.equal(selectIssuance('not an array', host).issuance, null);
  });
});

describe('selectCrtshEntry', () => {
  test('rows of one serial and issuer are one certificate; the newest current one covering the host wins', () => {
    const rows = [
      crtRow({ id: 900, names: ['*.example.com', 'example.com'], serial: '00aa01', notBefore: '2026-06-01T00:00:00' }),
      crtRow({ id: 1001, names: ['*.example.com'], serial: '0bb2', notBefore: '2026-09-01T10:00:00' }),
      crtRow({ id: 1000, names: ['*.example.com'], serial: '0bb2', notBefore: '2026-09-01T10:00:00' }),
      crtRow({ id: 1200, names: ['api.example.com'], serial: 'cc03', notBefore: '2026-09-20T00:00:00' }),
      crtRow({ id: 1300, names: ['*.example.com'], serial: 'dd04', notBefore: '2026-01-01T00:00:00', notAfter: '2026-04-01T00:00:00' }),
      crtRow({ id: 1400, names: ['*.example.com'], serial: 'ee05', notBefore: '2026-12-01T00:00:00', notAfter: '2027-03-01T00:00:00' }),
      { id: 'x', name_value: 'www.example.com' },
      null
    ];
    const { entry, candidates } = selectCrtshEntry(rows, 'www.example.com', { now: NOW });
    assert.equal(candidates, 2);
    assert.deepEqual(entry.ids, ['1000', '1001']);
    assert.equal(entry.serialHex, '0bb2');
    assert.equal(entry.issuer, 'C=US, O=Example Trust, CN=Example CA R1');
    assert.equal(entry.notBefore.toISOString(), '2026-09-01T10:00:00.000Z', 'crt.sh dates are UTC without a zone');
    assert.deepEqual(entry.names, ['*.example.com']);
    assert.deepEqual(entry.downloads, [
      { id: '1000', url: 'https://crt.sh/?d=1000' },
      { id: '1001', url: 'https://crt.sh/?d=1001' }
    ], 'both: crt.sh does not say which one is the precertificate');
    assert.equal(entry.pageUrl, 'https://crt.sh/?id=1000');
  });

  test('the same serial from another CA is another certificate; the common name counts as a name', () => {
    const rows = [
      crtRow({ id: 10, names: ['www.example.com'], serial: '01', ca: 1, notBefore: '2026-09-01T00:00:00' }),
      crtRow({ id: 11, names: ['www.example.com'], serial: '01', ca: 2, notBefore: '2026-09-02T00:00:00' }),
      crtRow({ id: 12, names: ['shop.example.com'], cn: 'www.example.com', serial: '02', ca: 3, notBefore: '2026-08-01T00:00:00' })
    ];
    const r = selectCrtshEntry(rows, 'www.example.com', { now: NOW });
    assert.equal(r.candidates, 3);
    assert.deepEqual(r.entry.ids, ['11']);
  });

  test('nothing current', () => {
    assert.deepEqual(selectCrtshEntry([], 'www.example.com', { now: NOW }), { entry: null, candidates: 0 });
    assert.deepEqual(selectCrtshEntry({ error: 'x' }, 'www.example.com', { now: NOW }), { entry: null, candidates: 0 });
  });
});

describe('lookupCtCertificate', () => {
  test('found on Cert Spotter: pages until the empty page, a plain GET without credentials', async () => {
    const page1 = [issuance({ names: ['*.example.com'], notBefore: '2026-07-01T00:00:00Z' })];
    const page2 = [issuance({ names: ['www.example.com'], notBefore: '2026-09-01T00:00:00Z' })];
    const f = mockFetch({ spotter: pagesOf(page1, page2) });
    const r = await lookup('https://www.example.com/', f);
    assert.equal(r.status, 'found');
    assert.equal(r.provider, 'certspotter');
    assert.equal(r.host, 'www.example.com');
    assert.equal(r.issuance.id, page2[0].id);
    assert.equal(r.certificate.subjectCN, 'www.example.com');
    assert.equal(r.requests, 3);
    assert.equal(r.truncated, false);
    assert.deepEqual(r.certspotter, { state: 'ok', error: null, errorKind: null, quota: null });
    assert.equal(r.crtsh, null);
    const urls = f.calls.map((c) => c.url);
    assert.deepEqual(urls, [
      certspotterUrl('www.example.com'),
      certspotterUrl('www.example.com', { after: page1[0].id }),
      certspotterUrl('www.example.com', { after: page2[0].id })
    ]);
    const init = f.calls[0].init;
    assert.equal(init.credentials, 'omit');
    assert.equal(init.referrerPolicy, 'no-referrer');
    assert.equal(init.method, undefined, 'GET');
    assert.deepEqual(Object.keys(init.headers), ['accept'], 'only a CORS-safelisted header: no preflight');
  });

  test('nothing current on Cert Spotter: not-found, and crt.sh (the same logs) is not asked', async () => {
    const f = mockFetch({ spotter: pagesOf([issuance({ names: ['www.example.com'], revoked: true })]) });
    const r = await lookup('www.example.com', f);
    assert.equal(r.status, 'not-found');
    assert.equal(r.provider, 'certspotter');
    assert.equal(r.skipped.revoked, 1);
    assert.equal(f.crtshCalls().length, 0);
    const empty = await lookup('www.example.com', mockFetch());
    assert.equal(empty.status, 'not-found');
    assert.equal(empty.requests, 1);
  });

  test('page cap: a list that never ends is read up to maxPages and marked truncated', async () => {
    const f = mockFetch({ spotter: () => json([issuance({ names: ['www.example.com'] })]) });
    const r = await lookup('www.example.com', f, { maxPages: 3 });
    assert.equal(r.status, 'found');
    assert.equal(r.truncated, true);
    assert.equal(f.spotterCalls().length, 3);
  });

  test('page cap with nothing current among the pages read: not-found, truncated, crt.sh not asked', async () => {
    const f = mockFetch({ spotter: () => json([issuance({ names: ['www.example.com'], revoked: true })]) });
    const r = await lookup('www.example.com', f, { maxPages: 2 });
    assert.equal(r.status, 'not-found');
    assert.equal(r.truncated, true, 'the views hedge the note: the unread issuances are the newest');
    assert.equal(r.skipped.revoked, 2);
    assert.equal(r.crtsh, null);
    assert.equal(f.crtshCalls().length, 0);
  });

  test('a later page that fails: the pages read so far still count (partial, truncated)', async () => {
    const f = mockFetch({
      spotter: (url, n) => (n === 0 ? json([issuance({ names: ['www.example.com'] })]) : json({ code: 'rate_limited' }, { status: 429 }))
    });
    const cooldown = createCtCooldown();
    const r = await lookup('www.example.com', f, { cooldown });
    assert.equal(r.status, 'found');
    assert.equal(r.truncated, true);
    assert.equal(r.certspotter.state, 'partial');
    assert.equal(r.certspotter.errorKind, 'rate-limit');
    assert.equal(r.certspotter.quota.hintKey, 'source.quota.hour');
    assert.ok(cooldown.get(NOW.getTime()), 'the 429 still starts the cool-down');
    assert.equal(f.crtshCalls().length, 0);
  });

  test('Cert Spotter 429: crt.sh finds the certificate (manual download), and later lookups skip Cert Spotter for an hour', async () => {
    const rows = [
      crtRow({ id: 2001, names: ['*.example.com', 'example.com'], serial: '0123' }),
      crtRow({ id: 2000, names: ['*.example.com', 'example.com'], serial: '0123' })
    ];
    const f = mockFetch({
      spotter: () => json({ code: 'rate_limited', message: 'Rate limit exceeded' }, { status: 429 }),
      crtsh: (url) => json(new URL(url).searchParams.get('q') === '*.example.com' ? rows : [])
    });
    const cooldown = createCtCooldown();
    const r = await lookup('www.example.com', f, { cooldown });
    assert.equal(r.status, 'manual');
    assert.equal(r.provider, 'crtsh');
    assert.equal(r.der, null);
    assert.deepEqual(r.crtsh.entry.ids, ['2000', '2001']);
    assert.equal(r.crtsh.partial, false);
    assert.equal(r.certspotter.state, 'failed');
    assert.equal(r.certspotter.errorKind, 'rate-limit');
    assert.equal(r.certspotter.quota.limited, true);
    assert.equal(r.certspotter.quota.period, 'hour');
    assert.equal(r.certspotter.quota.resetAt.getTime(), NOW.getTime() + CT_COOLDOWN_MS);
    assert.deepEqual(f.crtshCalls().map((c) => new URL(c.url).searchParams.get('q')), ['www.example.com', '*.example.com']);
    assert.ok(f.crtshCalls().every((c) => !c.url.includes('?d=')), 'never the CORS-less download');
    assert.equal(r.requests, 3);

    const again = await lookup('www.example.com', f, { cooldown });
    assert.equal(again.certspotter.state, 'skipped');
    assert.equal(again.certspotter.quota.hintKey, 'source.quota.hour');
    assert.equal(f.spotterCalls().length, 1, 'no second request inside the cool-down');
    assert.equal(again.status, 'manual');

    const later = await lookup('www.example.com', f, { cooldown, now: new Date(NOW.getTime() + CT_COOLDOWN_MS + 1000) });
    assert.equal(later.certspotter.state, 'failed', 'asked again after the cool-down');
    assert.equal(f.spotterCalls().length, 2);
  });

  test('a readable Retry-After (Node) sets a shorter cool-down', async () => {
    const f = mockFetch({ spotter: () => json({}, { status: 429, headers: { 'retry-after': '120' } }) });
    const cooldown = createCtCooldown();
    await lookup('www.example.com', f, { cooldown });
    assert.ok(cooldown.get(NOW.getTime() + 119000));
    assert.equal(cooldown.get(NOW.getTime() + 121000), null);
  });

  test('Cert Spotter down (5xx, network, bad JSON): crt.sh; a crt.sh error page is retried once', async () => {
    for (const spotter of [
      () => json({ message: 'oops' }, { status: 503 }),
      () => { throw new TypeError('Failed to fetch'); },
      () => new Response('<html>maintenance</html>', { status: 200 }),
      () => json({ not: 'an array' })
    ]) {
      const f = mockFetch({
        spotter,
        crtsh: (url, n) => (n === 0 ? new Response('bad gateway', { status: 502 }) : json([crtRow({ id: 7, names: ['www.example.com'] })]))
      });
      const r = await lookup('www.example.com', f);
      assert.equal(r.status, 'manual', String(spotter));
      assert.equal(r.certspotter.state, 'failed');
      assert.notEqual(r.certspotter.errorKind, 'rate-limit');
      assert.equal(r.certspotter.quota, null);
      assert.deepEqual(r.crtsh.entry.ids, ['7']);
    }
  });

  test('both down: status error with the crt.sh error; crt.sh finding nothing: not-found', async () => {
    const down = mockFetch({
      spotter: () => json({}, { status: 500 }),
      crtsh: () => { throw new TypeError('Failed to fetch'); }
    });
    const r = await lookup('*.example.com', down);
    assert.equal(r.status, 'error');
    assert.equal(r.errorKind, 'network');
    assert.equal(r.crtsh.errorKind, 'network');
    assert.equal(down.crtshCalls().length, 2, 'one search (wildcard input), retried once');

    const none = await lookup('www.example.com', mockFetch({ spotter: () => json({}, { status: 500 }) }));
    assert.equal(none.status, 'not-found');
    assert.equal(none.provider, 'crtsh');
    assert.equal(none.crtsh.entry, null);
  });

  test('Cert Spotter 429 and crt.sh down: error with the crt.sh error, the quota and its reset time kept', async () => {
    const f = mockFetch({
      spotter: () => json({ code: 'rate_limited', message: 'Rate limit exceeded' }, { status: 429 }),
      crtsh: () => new Response('bad gateway', { status: 502 })
    });
    const cooldown = createCtCooldown();
    const r = await lookup('www.example.com', f, { cooldown });
    assert.equal(r.status, 'error');
    assert.equal(r.errorKind, 'http');
    assert.deepEqual([r.certspotter.state, r.certspotter.errorKind], ['failed', 'rate-limit']);
    assert.equal(r.certspotter.quota.resetAt.getTime(), NOW.getTime() + CT_COOLDOWN_MS);
    assert.equal(f.crtshCalls().length, 4, 'two searches, each retried once');

    const again = await lookup('www.example.com', f, { cooldown });
    assert.deepEqual([again.status, again.certspotter.state, again.certspotter.errorKind], ['error', 'skipped', 'rate-limit']);
    assert.equal(again.certspotter.quota.resetAt.getTime(), NOW.getTime() + CT_COOLDOWN_MS, 'the cool-down keeps the reset time');
    assert.equal(f.spotterCalls().length, 1);
  });

  test('one crt.sh search failing leaves the other one\'s rows (partial)', async () => {
    const f = mockFetch({
      spotter: () => json({}, { status: 500 }),
      crtsh: (url) => (new URL(url).searchParams.get('q') === 'www.example.com'
        ? json([crtRow({ id: 5, names: ['www.example.com'] })])
        : new Response('slow', { status: 504 }))
    });
    const r = await lookup('www.example.com', f);
    assert.equal(r.status, 'manual');
    assert.equal(r.crtsh.partial, true);
    assert.equal(r.crtsh.errorKind, 'http');
  });

  test('crtsh: false never asks crt.sh', async () => {
    const f = mockFetch({ spotter: () => json({}, { status: 429 }) });
    const r = await lookup('www.example.com', f, { crtsh: false });
    assert.equal(r.status, 'error');
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(f.crtshCalls().length, 0);
  });

  test('unreadable certificates on Cert Spotter: crt.sh is asked', async () => {
    const f = mockFetch({
      spotter: pagesOf([{ ...issuance({ names: ['www.example.com'] }), cert_der: 'AAAA' }]),
      crtsh: () => json([crtRow({ id: 3, names: ['www.example.com'] })])
    });
    const r = await lookup('www.example.com', f);
    assert.equal(r.status, 'manual');
    assert.equal(r.certspotter.state, 'ok');
    assert.equal(r.skipped.unreadable, 1);
  });

  test('an invalid name throws before any request; an abort rejects', async () => {
    const f = mockFetch();
    await assert.rejects(lookup('192.0.2.1', f), TypeError);
    await assert.rejects(lookup('', f), TypeError);
    assert.equal(f.calls.length, 0);

    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(lookup('www.example.com', f, { signal: ctl.signal }), { name: 'AbortError' });

    const hang = new AbortController();
    const slow = mockFetch({ spotter: (url) => new Promise(() => {}) });
    const p = lookup('www.example.com', slow, { signal: hang.signal });
    setTimeout(() => hang.abort(), 10);
    await assert.rejects(p, { name: 'AbortError' });

    const inCrtsh = new AbortController();
    const f2 = mockFetch({ spotter: () => json({}, { status: 500 }), crtsh: () => new Promise(() => {}) });
    const p2 = lookup('www.example.com', f2, { signal: inCrtsh.signal });
    setTimeout(() => inCrtsh.abort(), 10);
    await assert.rejects(p2, { name: 'AbortError' });
  });

  test('the real Cert Spotter row shape: DER of a fixture round-trips', async () => {
    const pem = readFileSync(join(FIX, 'ec_wildcard.pem'), 'utf8');
    const der = parseCertificates(pem).leaf.der;
    const sha = (await computeFingerprints(der)).sha256;
    const row = {
      id: '16142101677', tbs_sha256: 'ab'.repeat(32), cert_sha256: sha, dns_names: ['*.wild.example.net', 'wild.example.net'],
      pubkey_sha256: 'ef'.repeat(32), not_before: '2025-01-01T00:00:00Z', not_after: '2051-01-01T00:00:00Z', revoked: false,
      cert_der: Buffer.from(der).toString('base64')
    };
    const r = await lookup('shop.wild.example.net', mockFetch({ spotter: pagesOf([row]) }));
    assert.equal(r.status, 'found');
    assert.equal((await computeFingerprints(r.der)).sha256, sha);
    assert.equal(r.issuance.url, `https://crt.sh/?q=${sha}`);
  });
});

describe('sources.sourceQuota (shared quota policy)', () => {
  test('the hint and period of a source\'s rate limit; null when not limited', () => {
    const q = sourceQuota('certspotter', { limited: true, retryAfterMs: 60000 });
    assert.equal(q.limited, true);
    assert.equal(q.period, 'hour');
    assert.equal(q.hintKey, 'source.quota.hour');
    assert.equal(q.retryAfterMs, 60000);
    assert.equal(sourceQuota('crtsh', { limited: true }).hintKey, 'source.quota.minutes');
    assert.equal(sourceQuota('nope', { limited: true }).hintKey, 'source.quota.later');
    assert.equal(sourceQuota('certspotter'), null);
  });

  test('createCtCooldown: set, expire, clear', () => {
    const c = createCtCooldown();
    assert.equal(c.get(0), null);
    c.set({ limited: true }, 1000);
    assert.deepEqual(c.get(999), { limited: true });
    assert.equal(c.get(1000), null);
    c.set({ limited: true }, 5000);
    c.clear();
    assert.equal(c.get(0), null);
  });
});
