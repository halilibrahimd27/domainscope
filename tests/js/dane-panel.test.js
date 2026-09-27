/**
 * ui/dane-panel.js (the DANE / TLSA tab of the Certificate view and SSL Targets) — its pure
 * helpers: wait and record formatting, the explanation / record-state keys, the tab badge, the
 * export block, the CSV columns and the holder-owned job with its Stop (the real DohClient over
 * a mock fetch).
 * No DOM: the panel itself is exercised in a real browser by tests/e2e/dane.e2e.mjs.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { setLang, t, hasString } from '../../assets/js/i18n.js';
import {
  waitText, shortRecord, recordMnemonic, whyKey, recordStateKey, daneTabBadge, daneExport, startDane, cancelDane, DANE_CSV_COLUMNS
} from '../../assets/js/ui/dane-panel.js';
import { DANE_STATUSES } from '../../assets/js/lib/dane.js';
import { toCsv } from '../../assets/js/lib/export.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';

setLang('en');

const NEW = parseCertificates(readFileSync(new URL('../fixtures/cli_renewed_wild.pem', import.meta.url))).leaf;

/**
 * A DoH server with one MX and one TLSA record set that pins another key (AD set). `hang`: TLSA
 * queries never get an answer (the request ends only when it is aborted); `seen` records them.
 */
function fakeDns({ hang = false, seen = [] } = {}) {
  const fetchImpl = async (url, init = {}) => {
    const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
    if (hang && q.type === 'TLSA') {
      seen.push(q.name);
      return new Promise((resolve, reject) => {
        const signal = init.signal;
        const stop = () => reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
        if (signal && signal.aborted) stop();
        else if (signal) signal.addEventListener('abort', stop, { once: true });
      });
    }
    const answers = q.type === 'MX' ? [{ name: q.name, type: 'MX', ttl: 300, data: { preference: 10, exchange: 'mail.wild.example.net' } }]
      : q.name === '_25._tcp.mail.wild.example.net' ? [{ name: q.name, type: 'TLSA', ttl: 600, data: { usage: 3, selector: 1, matchingType: 1, data: 'ab'.repeat(32) } }]
        : [];
    const bytes = encodeMessage({
      flags: { qr: true, rd: true, ra: true, ad: true }, rcode: answers.length || q.type === 'MX' ? 'NOERROR' : 'NXDOMAIN',
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    });
    return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
  };
  return new DohClient({ chain: ['cloudflare'], fetchImpl, cache: false, retries: 0, timeoutMs: 60000 });
}

const until = async (cond, ms = 5000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
};

describe('formatting', () => {
  test('waitText: seconds to a short human wait', () => {
    assert.equal(waitText(45), '45 s');
    assert.equal(waitText(600), '10 min');
    assert.equal(waitText(7200), '2 h');
    assert.equal(waitText(5400), '1 h 30 min');
    assert.equal(waitText(172800), '2 d');
    assert.equal(waitText(216000), '2 d 12 h');
    assert.equal(waitText(-1), '—');
    assert.equal(waitText(Number.NaN), '—');
    setLang('tr');
    try {
      assert.equal(waitText(5400), '1 sa 30 dk');
    } finally {
      setLang('en');
    }
  });

  test('shortRecord / recordMnemonic', () => {
    assert.equal(shortRecord({ usage: 3, selector: 1, matchingType: 1, data: '0123456789abcdef'.repeat(4) }), '3 1 1 01234567…ABCDEF');
    assert.equal(shortRecord({ usage: 3, selector: 1, matchingType: 1, data: 'abcd' }), '3 1 1 ABCD');
    assert.equal(recordMnemonic({ usage: 3, selector: 1, matchingType: 1 }), 'DANE-EE · SPKI · SHA2-256');
    assert.equal(recordMnemonic({ usage: 2, selector: 0, matchingType: 2 }), 'DANE-TA · Cert · SHA2-512');
    assert.equal(recordMnemonic({ usage: 9, selector: 1, matchingType: 0 }), '? · SPKI · Full');
  });
});

describe('keys', () => {
  test('whyKey: service-specific sentences for danger / unusable, the MX variant of insecure', () => {
    assert.equal(whyKey({ status: 'danger', service: 'smtp' }), 'dane.why.danger.smtp');
    assert.equal(whyKey({ status: 'danger', service: 'https' }), 'dane.why.danger.https');
    assert.equal(whyKey({ status: 'unusable', service: 'https' }), 'dane.why.unusable.https');
    assert.equal(whyKey({ status: 'insecure', service: 'smtp', notes: [{ code: 'mx-insecure' }] }), 'dane.why.insecure.mx');
    assert.equal(whyKey({ status: 'insecure', service: 'smtp', notes: [] }), 'dane.why.insecure');
    assert.equal(whyKey({ status: 'bogus-status', service: 'smtp' }), 'dane.why.error');
    for (const s of DANE_STATUSES) for (const service of ['smtp', 'https']) assert.ok(hasString(whyKey({ status: s, service })), `${s}/${service}`);
  });

  test('recordStateKey', () => {
    assert.equal(recordStateKey({ usable: true, matches: true, matchedBy: 'leaf' }), 'dane.rec.match');
    assert.equal(recordStateKey({ usable: true, matches: true, matchedBy: 'chain' }), 'dane.rec.matchChain');
    assert.equal(recordStateKey({ usable: true, matches: false }), 'dane.rec.noMatch');
    assert.equal(recordStateKey({ usable: true, matches: null }), 'dane.rec.unknown');
    assert.equal(recordStateKey({ usable: false, issue: 'pkix-smtp' }), 'dane.issue.pkix-smtp');
    assert.equal(t('dane.rec.matchChain', { name: 'CA' }), 'Matches CA in the chain');
  });
});

describe('the job on its holder', () => {
  test('nothing before a check; a finished check sets the badge, the export and the CSV', async () => {
    const holder = {};
    assert.equal(daneTabBadge(holder), null);
    assert.equal(daneExport(holder, 'x'), null);
    const dns = fakeDns();
    let asked = 0;
    const ctx = { getDns: async () => { asked += 1; return dns; } };
    const job = startDane(holder, { certs: { leaf: NEW }, ctx });
    assert.equal(holder.dane, job);
    assert.equal(job.status, 'running');
    assert.equal(startDane(holder, { certs: { leaf: NEW }, ctx }), job, 'a running check is joined, not restarted');
    while (job.status === 'running') await new Promise((r) => setTimeout(r, 5));
    assert.equal(asked, 1);
    assert.equal(job.status, 'done');
    assert.deepEqual(daneTabBadge(holder), { value: 1, variant: 'error' });
    const json = daneExport(holder, '1.0.0');
    assert.equal(json.schema, 'domainscope.dane/1');
    assert.equal(json.version, '1.0.0');
    const csv = toCsv(job.report.endpoints, DANE_CSV_COLUMNS, { bom: false }).split('\r\n');
    assert.equal(csv[0], 'tlsa_name,service,port,host,via,status,dnssec,records,add_records,wait_seconds');
    assert.match(csv[1], /^_25\._tcp\.mail\.wild\.example\.net,smtp,25,mail\.wild\.example\.net,example\.net,danger,true,3 1 1 (ab){32},_25\._tcp\.mail\.wild\.example\.net\. IN TLSA 3 1 1 [0-9A-F]{64},1200$/);
  });

  test('Stop mid-flight: the check ends as cancelled, with no badge and no export; a finished check stays', async () => {
    const holder = {};
    const seen = [];
    const job = startDane(holder, { certs: { leaf: NEW }, ctx: { getDns: async () => fakeDns({ hang: true, seen }) } });
    // The MX answer came back; the TLSA queries hang.
    await until(() => seen.length > 0);
    assert.equal(job.status, 'running');
    assert.equal(job.progress.phase, 'tlsa');
    cancelDane(holder);
    await until(() => job.status !== 'running');
    assert.equal(job.status, 'cancelled');
    assert.equal(job.error.name, 'AbortError');
    assert.equal(job.report, null);
    assert.equal(daneTabBadge(holder), null);
    assert.equal(daneExport(holder, 'x'), null);
    // Nothing to stop: no job, or a finished one.
    cancelDane(null);
    cancelDane({});
    const done = startDane(holder, { certs: { leaf: NEW }, ctx: { getDns: async () => fakeDns() } });
    assert.notEqual(done, job, 'a cancelled check is replaced by a new one');
    await until(() => done.status !== 'running');
    cancelDane(holder);
    assert.equal(done.status, 'done');
    assert.equal(done.controller.signal.aborted, false);
  });

  test('Stop while the DNS client is still loading: cancelled, nothing sent', async () => {
    const holder = {};
    const seen = [];
    let release;
    const gate = new Promise((r) => { release = r; });
    const job = startDane(holder, { certs: { leaf: NEW }, ctx: { getDns: async () => { await gate; return fakeDns({ hang: true, seen }); } } });
    cancelDane(holder);
    release();
    await until(() => job.status !== 'running');
    assert.equal(job.status, 'cancelled');
    assert.deepEqual(seen, []);
  });

  test('a failed DNS client load ends as an error, never a hang', async () => {
    const holder = {};
    const job = startDane(holder, { certs: { leaf: NEW }, ctx: { getDns: async () => { throw new TypeError('offline'); } } });
    while (job.status === 'running') await new Promise((r) => setTimeout(r, 5));
    assert.equal(job.status, 'error');
    assert.equal(job.error.message, 'offline');
    assert.equal(daneTabBadge(holder), null);
  });
});
