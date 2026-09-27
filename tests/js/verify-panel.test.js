/**
 * ui/verify-panel.js (the Verify tab of SSL Targets) — its pure helpers: the tab badge, headline
 * parameters, result ranking and badge choice, which rows a click sends, the plan and cost
 * preview, the not-checkable line, the run-owned job's public API, and app.js getGlobalping().
 * No DOM, no network: the panel itself is exercised in a real browser by tests/e2e/verify.e2e.mjs.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { setLang, t, hasString } from '../../assets/js/i18n.js';
import {
  badgeFromSummary, headlineParams, resultRank, statusBadgeSpec, targetRows, planCounts, batchCost, notHereText,
  isHintRow, verifyTabBadge, verifyExport, cancelVerify, GP_CREDITS_URL,
  verifyRowClass, runOrder, notHereSentence, emptyKey, liveQuota, quotaOutActive, planText, verifyCliSweep, errorText,
  verifyJob, launchVerify, setOriginOptIn, setVerifyScope
} from '../../assets/js/ui/verify-panel.js';
import {
  createVerifyRows, summarizeVerify, verifyHeadline, buildVerifyPairs, applyOriginOptIn, classifyTest, aggregateVerdicts,
  exposureOf, recheckRows, VERIFY_WARNINGS, EXPOSURES, VERIFY_REUSE_WINDOW_MS, VERIFY_MAX_RETRIES
} from '../../assets/js/lib/verify.js';
import { getGlobalping } from '../../assets/js/app.js';
import { state } from '../../assets/js/state.js';
import '../../assets/js/views/about.js'; // registers about.priv6 (privacy copy test)

setLang('en');

/** A done row with a verdict (enough for lib/verify.summarizeVerify). */
function doneRow({ ip = '1.2.3.4', name = 'www.example.com', server = { id: 's1', name: 'web01' }, status = 'UPDATED',
  reason = 'new-cert', warnings = [], via = 'dns', proxied = false, exposure = null, newCertCovers = true } = {}) {
  const served = status === 'UPDATED' || status === 'NEEDS_UPDATE' || status === 'NOT_HOSTED'
    ? { sha256: 'aa', hostnames: [name], dnsNames: [name] } : null;
  return {
    key: `${ip}|443|${name}`, ip, port: 443, name, server, alsoServers: [], via, proxied, provider: proxied ? 'Cloudflare' : null,
    needsCert: true, newCertCovers, skip: null, state: 'done', notRun: null, status, reason, warnings, exposure,
    verdict: { status, reason, served, warnings, probes: [{ status, reason, served, probe: { asn: 1 } }] },
    served, tests: [], measurementId: 'abcdefgh12', measurementDone: true, measurementAt: null, reuseAttempts: 0,
    cost: 1, retries: 0, checkedAt: new Date('2026-09-24T07:00:00Z'), stale: false, error: null, httpStatus: 200
  };
}

function pendingRow(extra = {}) {
  return { key: 'k', ip: '5.6.7.8', port: 443, name: 'api.example.com', server: null, alsoServers: [], via: 'dns', proxied: false,
    skip: null, state: 'pending', notRun: null, verdict: null, status: null, warnings: [], measurementId: null,
    measurementDone: false, measurementAt: null, reuseAttempts: 0, ...extra };
}

describe('tab badge', () => {
  test('null without a summary or without servers to count', () => {
    assert.equal(badgeFromSummary(null), null);
    assert.equal(badgeFromSummary({ servers: { total: 0, filteredOrigins: 0 } }), null);
  });

  test('"live/total" with warn while a server is still old, misses its intermediate or exposes its origin', () => {
    assert.deepEqual(badgeFromSummary({ servers: { total: 3, base: 3, live: 1, old: 1, chain: 0 }, exposed: 0 }), { value: '1/3', variant: 'warn' });
    assert.deepEqual(badgeFromSummary({ servers: { total: 2, base: 2, live: 2, old: 0, chain: 1 }, exposed: 0 }), { value: '2/2', variant: 'warn' });
    assert.deepEqual(badgeFromSummary({ servers: { total: 2, base: 2, live: 2, old: 0, chain: 0 }, exposed: 1 }), { value: '2/2', variant: 'warn' });
  });

  test('ok only when every counted server is live and complete; filtered origins are not counted (critic C.6)', () => {
    assert.deepEqual(badgeFromSummary({ servers: { total: 4, filteredOrigins: 1, live: 3, old: 0, chain: 0 }, exposed: 0 }), { value: '3/3', variant: 'ok' });
    assert.deepEqual(badgeFromSummary({ servers: { total: 3, base: 3, live: 2, old: 0, chain: 0 }, exposed: 0 }), { value: '2/3', variant: null });
    assert.deepEqual(badgeFromSummary({ servers: { total: 2, base: 2, live: 2, old: 0, chain: 0, incomplete: 1 }, exposed: 0 }).variant, null);
  });

  test('a hand-built summary without `base` also leaves origin candidates that do not host the name out', () => {
    assert.deepEqual(badgeFromSummary({ servers: { total: 4, filteredOrigins: 1, notHostingOrigins: 1, live: 2, old: 0, chain: 0 }, exposed: 0 }),
      { value: '2/2', variant: 'ok' });
  });

  test('verifyTabBadge is null before the first batch, then follows lib/verify.summarizeVerify', () => {
    assert.equal(verifyTabBadge(null), null);
    assert.equal(verifyTabBadge({ verify: { runs: 0, rows: [doneRow()] } }), null);
    const rows = [
      doneRow({ ip: '1.2.3.4', name: 'a.example.com' }),
      doneRow({ ip: '1.2.3.4', name: 'b.example.com', status: 'NEEDS_UPDATE', reason: 'old-cert' }),
      doneRow({ ip: '5.6.7.8', name: 'api.example.com', server: null })
    ];
    assert.deepEqual(verifyTabBadge({ verify: { runs: 1, rows } }), { value: '1/2', variant: 'warn' });
  });
});

describe('headline parameters', () => {
  test('lib params are kept; notHere gets the view-built list', () => {
    const summary = { servers: { checked: 3, base: 3, live: 1, old: 1 } };
    assert.deepEqual(headlineParams({ key: 'vfy.head.some', params: { live: 1, total: 3, old: 1 } }, summary), { live: 1, total: 3, old: 1 });
    assert.deepEqual(headlineParams({ key: 'vfy.head.notHere', params: {} }, summary, '1 private address'), { list: '1 private address' });
  });

  test('a {count} or {total} the entry lacks is filled from the summary, so no placeholder shows raw', () => {
    const summary = { servers: { checked: 4, base: 3, filteredOrigins: 1, live: 3, old: 0, chain: 2, incomplete: 1 }, exposed: 5 };
    assert.equal(headlineParams({ key: 'vfy.head.all' }, summary).count, 3);
    assert.equal(headlineParams({ key: 'vfy.head.chain' }, summary).count, 2);
    assert.equal(headlineParams({ key: 'vfy.head.incomplete' }, summary).count, 1);
    assert.deepEqual(headlineParams({ key: 'vfy.head.partial' }, summary), { total: 3, live: 3 });
  });

  test('every headline entry lib/verify can return renders without a raw key or placeholder, in both languages', () => {
    const rows = [
      doneRow({ ip: '1.2.3.4', name: 'a.example.com', warnings: ['chain-incomplete'] }),
      doneRow({ ip: '1.2.3.4', name: 'b.example.com', status: 'NEEDS_UPDATE', reason: 'old-cert' }),
      doneRow({ ip: '5.6.7.8', name: 'c.example.com', server: null, status: 'TIMEOUT', reason: 'connect-timeout' }),
      doneRow({ ip: '5.6.7.9', name: 'd.example.com', server: { id: 's2', name: 'origin' }, via: 'hint', proxied: true, status: 'UPDATED', exposure: 'exposed' }),
      { ...pendingRow({ ip: '10.0.0.5', name: 'vpn.example.com', skip: 'private', state: 'skipped' }) }
    ];
    const summary = summarizeVerify(rows);
    const entries = verifyHeadline(summary, { proxiedNoOrigin: 2, managed: 1, skipped: { 'over-cap': 0 } });
    assert.ok(entries.length >= 4, JSON.stringify(entries.map((e) => e.key)));
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      for (const entry of entries) {
        const id = entry.key.replace('vfy.head.', '');
        const list = id === 'notHere' ? notHereText(rows, null, entry.parts) : '';
        const text = t(entry.key, headlineParams(entry, summary, list));
        assert.ok(!/\{[A-Za-z]+\}/.test(text) && !text.startsWith('vfy.'), `${lang} ${entry.key}: ${text}`);
      }
    }
    setLang('en');
  });
});

describe('rows: rank, badge, what a click sends', () => {
  test('problems sort first: old certificate, TLS error or live-with-notice, name not served, no answer, …, skipped', () => {
    const order = [
      doneRow({ status: 'NEEDS_UPDATE', reason: 'old-cert' }),
      doneRow({ status: 'TLS_ERROR', reason: 'sni-refused' }),
      doneRow({ status: 'UPDATED', warnings: ['chain-incomplete'] }),
      doneRow({ status: 'NOT_HOSTED', reason: 'not-covered' }),
      doneRow({ status: 'TIMEOUT', reason: 'connect-timeout' }),
      { ...doneRow(), state: 'error' },
      pendingRow(),
      doneRow({ status: 'UPDATED' }),
      // runVerify sets `exposure` (lib exposureOf): one probe without a TCP answer is 'no-answer'.
      doneRow({ status: 'TIMEOUT', reason: 'connect-timeout', proxied: true, via: 'hint', exposure: 'no-answer' }),
      pendingRow({ state: 'skipped', skip: 'private' })
    ].map(resultRank);
    assert.deepEqual(order, [0, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert.equal(resultRank(doneRow({ status: 'NEEDS_UPDATE', newCertCovers: false })), 2, 'own certificate is not "still old"');
    assert.equal(resultRank(doneRow({ status: 'NEEDS_UPDATE', warnings: ['origin-ca'] })), 2);
    assert.equal(resultRank(pendingRow({ via: 'hint', state: 'not-run', notRun: 'optional' })), 7, 'an origin check left out is not a problem');
    assert.equal(resultRank(pendingRow({ state: 'not-run', notRun: 'quota' })), 4);
  });

  test('an origin-hint candidate that is not the origin of this name ranks as expected, whatever its status (lib isExpectedOrigin)', () => {
    const hint = (status, reason) => doneRow({ status, reason, via: 'hint', proxied: true, exposure: 'not-this-host' });
    assert.equal(resultRank(hint('TLS_ERROR', 'sni-refused')), 7, 'a refused SNI on a general hint (MX, SPF) is not a problem');
    assert.equal(resultRank(hint('NOT_HOSTED', 'not-covered')), 7);
    assert.equal(resultRank(hint('TIMEOUT', 'refused-name')), 7, 'a works-rule refusal on the same ip:port');
    assert.equal(resultRank(doneRow({ status: 'TLS_ERROR', reason: 'sni-refused', proxied: true, exposure: 'not-this-host' })), 1,
      'a DNS-matched server refusing its own name stays a TLS error (CLI parity)');
    assert.equal(resultRank(doneRow({ status: 'TLS_ERROR', reason: 'reset', via: 'hint', proxied: true, exposure: 'unknown' })), 1);
  });

  test('status badges: icon + text keys, variants per spec §8.5', () => {
    assert.deepEqual(statusBadgeSpec(doneRow()), { key: 'vfy.st.UPDATED', variant: 'ok', icon: 'check-circle' });
    assert.equal(statusBadgeSpec(doneRow({ status: 'NEEDS_UPDATE', newCertCovers: false })).key, 'vfy.st.NEEDS_UPDATE.other');
    assert.equal(statusBadgeSpec(doneRow({ status: 'NEEDS_UPDATE', reason: 'no-new-cert' })).key, 'vfy.st.NEEDS_UPDATE.nocert');
    assert.equal(statusBadgeSpec(doneRow({ status: 'NOT_HOSTED' })).variant, 'warn', 'a DNS match serves visitors');
    assert.equal(statusBadgeSpec(doneRow({ status: 'NOT_HOSTED', via: 'hint' })).variant, 'neutral');
    assert.equal(statusBadgeSpec(doneRow({ status: 'TIMEOUT', reason: 'connect-timeout', proxied: true })).key, 'vfy.st.TIMEOUT.origin');
    assert.equal(statusBadgeSpec(doneRow({ status: 'CLOSED' })).icon, 'x-circle');
    assert.equal(statusBadgeSpec(pendingRow()), null);
    for (const spec of ['UPDATED', 'NEEDS_UPDATE', 'NOT_HOSTED', 'TLS_ERROR', 'TIMEOUT', 'CLOSED'].map((status) => statusBadgeSpec({ status }))) {
      assert.ok(hasString(spec.key, 'en') && hasString(spec.key, 'tr'), spec.key);
    }
  });

  test('before the first batch a click sends the pending rows; afterwards recheckRows minus opted-out origin rows', () => {
    const pairs = [
      { key: 'a', ip: '1.2.3.4', port: 443, name: 'www.example.com', server: { id: 's1', name: 'web01' }, via: 'dns', skip: null },
      { key: 'b', ip: '1.2.3.4', port: 443, name: 'shop.example.com', server: { id: 's1', name: 'web01' }, via: 'hint', proxied: true, skip: null },
      { key: 'c', ip: '10.0.0.5', port: 443, name: 'vpn.example.com', server: { id: 's2', name: 'db01' }, via: 'dns', skip: 'private' }
    ];
    const rows = createVerifyRows(pairs, { origins: false });
    assert.deepEqual(targetRows(rows, { ran: false, origins: false }).map((r) => r.key), ['a']);
    assert.ok(isHintRow(rows[1]) && !isHintRow(rows[0]));
    const withOrigins = createVerifyRows(pairs, { origins: true });
    assert.deepEqual(targetRows(withOrigins, { ran: false, origins: true }).map((r) => r.key), ['a', 'b']);
    // After a batch: only what recheckRows returns, and never an origin row while the opt-in is off.
    const recheck = () => [withOrigins[0], withOrigins[1]];
    assert.deepEqual(targetRows(withOrigins, { ran: true, origins: false, recheck }).map((r) => r.key), ['a']);
    assert.deepEqual(targetRows(withOrigins, { ran: true, origins: true, recheck }).map((r) => r.key), ['a', 'b']);
  });

  test('a zone-file origin is an origin check for the opt-in, yet judged like a DNS match, not a hint', () => {
    const pairs = [
      { key: 'a', ip: '1.2.3.4', port: 443, name: 'www.example.com', server: { id: 's1', name: 'web01' }, via: 'zone', proxied: true, skip: null },
      { key: 'b', ip: '5.6.7.8', port: 443, name: 'api.example.com', server: null, via: 'dns', skip: null }
    ];
    const rows = createVerifyRows(pairs, { origins: false });
    assert.deepEqual(targetRows(rows, { ran: false, origins: false }).map((r) => r.key), ['b']);
    assert.deepEqual(targetRows(createVerifyRows(pairs, { origins: true }), { ran: false, origins: true }).map((r) => r.key), ['a', 'b']);
    assert.deepEqual(planCounts(rows), { checks: 1, servers: 1, origins: 1, originsOn: false });
    const wrong = doneRow({ status: 'NOT_HOSTED', reason: 'not-covered', via: 'zone', proxied: true });
    assert.ok(!isHintRow(wrong));
    assert.equal(resultRank(wrong), 2, 'the zone file says this is the origin: another certificate there is a problem');
    assert.equal(statusBadgeSpec(wrong).variant, 'warn');
  });

  test('plan: checks, servers (a shared VIP counts for each server) and optional origin checks', () => {
    const rows = [
      pendingRow({ server: { id: 's1', name: 'web01' }, alsoServers: [{ id: 's3', name: 'web02' }] }),
      pendingRow({ ip: '5.6.7.8' }),
      pendingRow({ ip: '5.6.7.8', name: 'www.example.com' }),
      pendingRow({ via: 'hint', state: 'not-run', notRun: 'optional', server: { id: 's1', name: 'web01' } }),
      pendingRow({ state: 'skipped', skip: 'private' })
    ];
    assert.deepEqual(planCounts(rows), { checks: 3, servers: 3, origins: 1, originsOn: false });
  });

  test('cost preview: a recent, paid, unfinished measurement is polled for free; everything else costs a probe', () => {
    const now = Date.parse('2026-09-24T07:00:00Z');
    const rows = [
      pendingRow(),
      { ...doneRow(), measurementDone: false, measurementAt: now - 30000, reuseAttempts: 0 },
      { ...doneRow(), measurementDone: false, measurementAt: now - 300000, reuseAttempts: 0 },
      { ...doneRow(), measurementDone: false, measurementAt: now - 30000, reuseAttempts: 1 },
      doneRow()
    ];
    assert.equal(batchCost(rows, { now }), 4);
    assert.equal(rows[1].state, 'done', 'the preview never mutates the rows');
  });

  test('not-checkable line: unique private addresses, names, proxied and provider-managed names', () => {
    const rows = [
      pendingRow({ ip: '10.0.0.5', name: 'vpn.example.com', state: 'skipped', skip: 'private' }),
      pendingRow({ ip: '10.0.0.5', name: 'shop.example.com', state: 'skipped', skip: 'private' }),
      pendingRow({ ip: '5.6.7.8', name: 'x_y.example.com', state: 'skipped', skip: 'bad-name' }),
      pendingRow()
    ];
    assert.equal(notHereText(rows, { proxiedNoOrigin: 2, managed: 1 }),
      '1 private address, 1 name Globalping does not accept, 2 names behind a CDN with no known origin, 1 name whose certificate the CDN or platform manages');
    assert.equal(notHereText([pendingRow()], {}), '');
  });
});

describe('strings the panel builds from codes', () => {
  test('every warning and exposure has a label and a tooltip in both languages', () => {
    for (const w of VERIFY_WARNINGS) for (const k of [`vfy.warn.${w}`, `vfy.warn.${w}.title`]) assert.ok(hasString(k, 'en') && hasString(k, 'tr'), k);
    for (const x of EXPOSURES) for (const k of [`vfy.exp.${x}`, `vfy.exp.${x}.title`]) assert.ok(hasString(k, 'en') && hasString(k, 'tr'), k);
  });

  test('privacy copy names the recipient, the public measurement id, its lifetime and the probe User-Agent, in both languages', () => {
    const expect = {
      en: { privacy: [/Globalping/, /measurement ID/, /six months/, /globalping probe/, /Only check servers you operate/],
        hint: [/public by measurement ID/], about: [/Globalping/, /measurement ID/, /six months/, /origin check/] },
      tr: { privacy: [/Globalping/, /[Öö]lçüm kimli/, /altı ay/, /globalping probe/, /yönettiğiniz sunucular/],
        hint: [/ölçüm kimli.*herkese açık/], about: [/Globalping/, /[Öö]lçüm kimli/, /altı ay/, /asıl sunucu kontrolü/] }
    };
    for (const [lang, want] of Object.entries(expect)) {
      setLang(lang);
      for (const re of want.privacy) assert.match(t('vfy.privacy'), re, `${lang} vfy.privacy`);
      for (const re of want.hint) assert.match(t('vfy.origins.hint'), re, `${lang} vfy.origins.hint`);
      for (const re of want.about) assert.match(t('about.priv6'), re, `${lang} about.priv6`);
      assert.match(t('about.privacyDesc'), /Verify|Doğrula/, `${lang} about.privacyDesc names the one exception`);
      assert.match(t('shell.privacyLong'), /Globalping/);
    }
    setLang('en');
    assert.equal(GP_CREDITS_URL, 'https://globalping.io/credits');
  });

  test('the CLI card text promises the verdicts, not an import that does not exist yet (critic C.2.12)', () => {
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      assert.match(t('vfy.cli.desc'), /verify-cli\.json/);
      assert.doesNotMatch(t('vfy.cli.desc'), /next to this table/);
    }
    setLang('en');
  });
});

describe('job owned by the scan run', () => {
  test('cancelVerify aborts a running batch and tolerates runs without one', () => {
    const controller = new AbortController();
    cancelVerify({ verify: { controller } });
    assert.equal(controller.signal.aborted, true);
    assert.doesNotThrow(() => cancelVerify(null));
    assert.doesNotThrow(() => cancelVerify({}));
    assert.doesNotThrow(() => cancelVerify({ verify: { controller: null } }));
  });

  test('verifyExport is null until something was checked, then a domainscope.verify/1 document', () => {
    assert.equal(verifyExport(null, '1.0.0'), null);
    assert.equal(verifyExport({ verify: { runs: 0, rows: [] } }, '1.0.0'), null);
    const doc = verifyExport({ verify: { runs: 1, rows: [doneRow()], expectValue: null } }, '1.0.0');
    assert.equal(doc.schema, 'domainscope.verify/1');
    assert.equal(doc.version, '1.0.0');
    assert.equal(doc.rows.length, 1);
    assert.equal(doc.rows[0].status, 'UPDATED');
  });
});

/* ------------------------------------------------------------------------ */
/* Review fixes (GP-1, GP-6, VFY-UI-01…09, F3, F8)                           */
/* ------------------------------------------------------------------------ */

/** A finished scan run with a certificate (lib/scanner ScanResult shape, trimmed to what buildVerifyPairs reads). */
function scanRun({ servers = [], unmatchedIps = [], hosts = [] } = {}) {
  return { result: { hosts, servers, unmatchedIps }, config: { cert: { hostnames: [] }, domains: ['example.com'] } };
}

/**
 * Fake Globalping client (no network): /limits can be held until `gate` resolves (and rejects on
 * abort like fetch); every POST is recorded as "target host"; every poll answers ECONNREFUSED.
 */
function fakeGp({ remaining = 250, gate = null } = {}) {
  const posts = [];
  const polls = [];
  let n = 0;
  return {
    posts,
    polls,
    quota: null,
    async limits({ signal } = {}) {
      if (gate) {
        await new Promise((resolve, reject) => {
          gate.then(resolve);
          if (signal) signal.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')), { once: true });
        });
      }
      return { limit: 250, remaining, consumed: 250 - remaining, resetAt: new Date(Date.now() + 3600e3), type: 'ip', source: 'limits', at: new Date() };
    },
    async create(body) {
      posts.push(`${body.target} ${body.measurementOptions.request.host}`);
      n += 1;
      return { id: `fakeMeas${String(n).padStart(8, '0')}`, cost: 1 };
    },
    async poll(id) {
      polls.push(id);
      return {
        id, status: 'finished', createdAt: new Date().toISOString(),
        results: [{ probe: { country: 'DE', city: 'Falkenstein', asn: 24940, network: 'Hetzner Online GmbH', tags: [] },
          result: { status: 'failed', rawOutput: 'connect ECONNREFUSED 5.6.7.8:443', statusCode: null, tls: null, timings: { total: 5 } } }]
      };
    }
  };
}

const ctxFor = (gp) => ({ getGlobalping: async () => gp });
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
function whenEnded(job) {
  return new Promise((resolve) => {
    const fn = (type) => {
      if (type !== 'end') return;
      job.listeners.delete(fn);
      resolve();
    };
    job.listeners.add(fn);
  });
}
function held() {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  return { gate, release };
}

describe('launch: only the confirmed batch is sent', () => {
  test('a Stop or a new scan while /limits is pending sends nothing; `starting` ends with an event (VFY-UI-01, VFY-UI-04)', async () => {
    const run = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: ['api.example.com'] }] });
    const job = verifyJob(run);
    const { gate, release } = held();
    const gp = fakeGp({ gate });
    const events = [];
    job.listeners.add((type) => events.push([type, job.starting]));
    const confirms = [];
    const launched = launchVerify(run, ctxFor(gp), { confirm: async (o) => { confirms.push(o); return true; } });
    assert.equal(job.starting, true);
    assert.deepEqual(events[0], ['change', true], 'a mounted (or re-mounted) panel learns about the launch');
    assert.equal(await launchVerify(run, ctxFor(gp)), false, 're-entrancy guard on the job');
    await tick();
    cancelVerify(run); // scan.js start() and "Delete all local data" both end up here
    release();
    assert.equal(await launched, false);
    assert.deepEqual([gp.posts.length, confirms.length, job.status, job.starting], [0, 0, 'idle', false]);
    assert.deepEqual(events.at(-1), ['change', false], 'the listener of whichever panel is mounted re-renders the button');
  });

  test('a launch refused for the quota also ends with `starting` false and an event', async () => {
    const run = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: ['api.example.com'] }] });
    const job = verifyJob(run);
    const gp = fakeGp({ remaining: 0 });
    const events = [];
    job.listeners.add((type) => events.push([type, job.starting]));
    assert.equal(await launchVerify(run, ctxFor(gp), { confirm: async () => true }), false);
    assert.equal(gp.posts.length, 0);
    assert.equal(job.quotaOut.count, 1);
    assert.deepEqual(events.at(-1), ['change', false]);
  });

  test('when /limits fails, a quota reading whose window has ended is not used: the hour starts over (unknown)', async () => {
    state.clearAll();
    const reading = (remaining, resetInMs) => ({ limit: 250, remaining, consumed: 250 - remaining, resetAt: new Date(Date.now() + resetInMs),
      type: 'ip', source: 'create', at: new Date(Date.now() - 3600e3) });
    const failing = (quota) => ({ ...fakeGp(), quota, async limits() { throw new TypeError('Failed to fetch'); } });
    const runOf = (count) => {
      const run = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: Array.from({ length: count }, (_, i) => `q${i}.example.com`) }] });
      verifyJob(run);
      return run;
    };
    // Used up an hour ago: the click is not silently dropped, the batch is offered with the default limit.
    const asked = [];
    const confirm = (answer) => async (o) => { asked.push([o.checks, o.fit, o.remaining, o.unknown]); return answer; };
    const spent = runOf(1);
    const gp = failing(reading(0, -30 * 60e3));
    const ended = whenEnded(spent.verify);
    assert.equal(await launchVerify(spent, ctxFor(gp), { confirm: confirm(true) }), true);
    await ended;
    assert.deepEqual(asked, [[1, 1, 250, true]]);
    assert.equal(spent.verify.quotaOut, null);
    assert.deepEqual(gp.posts, ['5.6.7.8 q0.example.com']);
    // 3 probes left in the old window: not a partial batch of 3.
    const big = runOf(60);
    assert.equal(await launchVerify(big, ctxFor(failing(reading(3, -30 * 60e3))), { confirm: confirm(false) }), false);
    assert.deepEqual(asked.at(-1), [60, 60, 250, true]);
    // A reading whose window is still open is kept: nothing fits, nothing is sent, the reset is shown.
    const out = runOf(1);
    const gpOut = failing(reading(0, 30 * 60e3));
    assert.equal(await launchVerify(out, ctxFor(gpOut), { confirm: confirm(true) }), false);
    assert.equal(asked.length, 2);
    assert.deepEqual([gpOut.posts.length, quotaOutActive(out.verify.quotaOut)], [0, true]);
    state.clearAll();
  });

  test('the origin opt-in and the scope are frozen while starting; an origin row opted out meanwhile is never sent (GP-1)', async () => {
    const run = scanRun({
      servers: [{ server: { id: 's1', name: 'web01' }, needsCert: true, hosts: [
        { name: 'www.example.com', ip: '1.2.3.4', via: 'dns', covered: true },
        { name: 'shop.example.com', ip: '1.2.3.4', via: 'hint', covered: true }] }],
      hosts: [{ name: 'shop.example.com', classification: { hidesOrigin: true, provider: { name: 'Cloudflare' } } }]
    });
    const job = verifyJob(run);
    assert.equal(setOriginOptIn(run, true), true);
    const shop = job.rows.find((r) => r.name === 'shop.example.com');
    assert.equal(shop.state, 'pending');
    const { gate, release } = held();
    const gp = fakeGp({ gate });
    const launched = launchVerify(run, ctxFor(gp), { confirm: async () => true });
    assert.equal(setOriginOptIn(run, false), false, 'the opt-in cannot change during the launch');
    assert.equal(setVerifyScope(run, 'perIp'), false, 'nor the scope');
    assert.deepEqual([job.origins, shop.state], [true, 'pending']);
    // Even when the rows change under the launch by another path, the opt-out wins: the rows are
    // re-derived after the wait and the batch keeps only what is confirmed.
    job.origins = false;
    applyOriginOptIn(job.rows, false);
    const ended = whenEnded(job);
    release();
    assert.equal(await launched, true);
    await ended;
    assert.deepEqual(gp.posts, ['1.2.3.4 www.example.com'], 'the origin IP + proxied name pair never went out');
    assert.deepEqual([shop.state, shop.notRun], ['not-run', 'optional']);
    assert.equal(setOriginOptIn(run, true), true, 'usable again once the batch ended');
  });

  test('a partial batch spends the quota on DNS rows of servers that need the certificate before origin checks (F3)', async () => {
    const run = scanRun({
      servers: [
        { server: { id: 's1', name: 'web01' }, needsCert: true, hosts: [{ name: 'www.example.com', ip: '1.2.3.4', via: 'dns', covered: true }] },
        { server: { id: 's2', name: 'web02' }, needsCert: false, hosts: [{ name: 'maybe.example.com', ip: '1.2.3.5', via: 'hint', covered: true }] }
      ],
      unmatchedIps: [{ ip: '5.6.7.8', hosts: ['api.example.com'] }]
    });
    const job = verifyJob(run);
    setOriginOptIn(run, true);
    assert.deepEqual(job.rows.map((r) => r.name), ['www.example.com', 'maybe.example.com', 'api.example.com'], 'table order');
    const gp = fakeGp({ remaining: 2 });
    const confirms = [];
    const ended = whenEnded(job);
    assert.equal(await launchVerify(run, ctxFor(gp), { confirm: async (o) => { confirms.push(o); return true; } }), true);
    await ended;
    assert.deepEqual(confirms.map((o) => [o.checks, o.fit, o.origins]), [[3, 2, 1]], 'the partial dialog, always shown');
    assert.deepEqual(gp.posts.sort(), ['1.2.3.4 www.example.com', '5.6.7.8 api.example.com']);
    const maybe = job.rows[1];
    assert.deepEqual([maybe.state, maybe.notRun], ['not-run', 'budget']);
  });

  test('the 500-check cap applies to the chosen scope and never gives a server past it the green badge', () => {
    const names = Array.from({ length: 500 }, (_, i) => `n${i}.example.com`);
    const run = scanRun({ servers: [
      { server: { id: 's1', name: 'web01' }, needsCert: true, hosts: names.map((name) => ({ name, ip: '1.2.3.4', via: 'dns', covered: true })) },
      { server: { id: 's2', name: 'web02' }, needsCert: true, hosts: [{ name: 'api.example.com', ip: '1.2.3.5', via: 'dns', covered: true }] }
    ] });
    const job = verifyJob(run);
    const over = () => job.rows.filter((r) => r.skip === 'over-cap').map((r) => r.name);
    assert.deepEqual([job.rows.length, planCounts(job.rows).checks, planCounts(job.rows).servers], [501, 500, 2]);
    assert.deepEqual(over(), ['n499.example.com'], 'web02 keeps its check');
    assert.equal(setVerifyScope(run, 'perIp'), true);
    assert.deepEqual([job.rows.map((r) => r.name), over()], [['n0.example.com', 'api.example.com'], []]);
    assert.equal(setVerifyScope(run, 'all'), true);
    for (const r of job.rows.filter((x) => x.state === 'pending')) {
      const d = doneRow({ ip: r.ip, name: r.name, server: r.server });
      Object.assign(r, { state: 'done', status: d.status, reason: d.reason, verdict: d.verdict, served: d.served });
    }
    job.runs = 1;
    assert.deepEqual(verifyTabBadge(run), { value: '1/2', variant: null });
    assert.match(notHereSentence(job.rows, job.stats), /1 check over the 500 limit/);
  });

  test('a server known only as a zone-file origin keeps its check past 500 names, and the badge never goes green', () => {
    const names = Array.from({ length: 500 }, (_, i) => `n${i}.example.com`);
    const zone = ['shop', 'blog', 'docs'].map((l) => `${l}.example.com`);
    const run = scanRun({
      servers: [
        { server: { id: 's1', name: 'web01' }, needsCert: true, hosts: names.map((name) => ({ name, ip: '1.2.3.4', via: 'dns', covered: true })) },
        { server: { id: 's2', name: 'web02' }, needsCert: true, hosts: zone.map((name) => ({ name, ip: '1.2.3.5', via: 'zone', covered: true })) }
      ],
      hosts: zone.map((name) => ({ name, cert: { covered: true }, classification: { hidesOrigin: true, provider: { name: 'Cloudflare' } } }))
    });
    const job = verifyJob(run);
    const web02 = () => job.rows.filter((r) => r.server.id === 's2').map((r) => `${r.name} ${r.state} ${r.skip ?? r.notRun}`);
    // Off: web02 waits for the opt-in, and its pairs past the cap count nowhere (not over the cap, not an origin check to offer).
    assert.deepEqual(web02(), ['blog.example.com not-run optional', 'docs.example.com not-run optional', 'shop.example.com not-run optional']);
    assert.deepEqual(planCounts(job.rows), { checks: 499, servers: 1, origins: 1, originsOn: false });
    assert.match(notHereSentence(job.rows, job.stats), /: 1 check over the 500 limit/);
    // On: web02's first name takes a place before web01's other names; the rest of web02 is over the cap.
    assert.equal(setOriginOptIn(run, true), true);
    assert.deepEqual(web02(), ['blog.example.com pending null', 'docs.example.com skipped over-cap', 'shop.example.com skipped over-cap']);
    assert.deepEqual(planCounts(job.rows), { checks: 500, servers: 2, origins: 1, originsOn: true });
    assert.match(notHereSentence(job.rows, job.stats), /: 3 checks over the 500 limit/);
    for (const r of job.rows.filter((x) => x.state === 'pending')) {
      const d = doneRow({ ip: r.ip, name: r.name, server: r.server });
      Object.assign(r, { state: 'done', status: d.status, reason: d.reason, verdict: d.verdict, served: d.served });
    }
    job.runs = 1;
    assert.deepEqual(verifyTabBadge(run), { value: '0/2', variant: null }, 'neither server had every name checked');
  });

  test('runOrder: batch rows first (needs-cert DNS, other DNS, origin checks, each in table order), then the rest', () => {
    const r = (name, extra) => ({ name, via: 'dns', needsCert: true, ...extra });
    const rows = [r('a', { via: 'hint' }), r('b', { needsCert: false }), r('c'), r('d'), r('e')];
    const order = runOrder(rows, [rows[0], rows[1], rows[2], rows[4]]).map((x) => x.name);
    assert.deepEqual(order, ['c', 'e', 'b', 'a', 'd']);
  });

  test('a paid measurement about to lapse is priced as a new probe, so no confirmed row ends "not in this batch" (GP-6)', async () => {
    const names = Array.from({ length: 60 }, (_, i) => `n${String(i).padStart(2, '0')}.example.com`);
    const run = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: names }] });
    const job = verifyJob(run);
    const T0 = Date.parse('2026-09-24T07:00:00Z');
    let clock = T0;
    job.runs = 1;
    job.rows.forEach((row, i) => {
      row.state = 'error';
      row.error = { code: i < 8 ? 'deadline' : 'network', message: '' };
      if (i < 8) Object.assign(row, { measurementId: `paidMeas${String(i).padStart(4, '0')}`, measurementDone: false, measurementAt: T0 - 90000, reuseAttempts: 0 });
    });
    const gp = fakeGp();
    const confirms = [];
    const ended = whenEnded(job);
    const started = await launchVerify(run, ctxFor(gp), {
      now: () => clock,
      confirm: async (o) => {
        confirms.push(o.checks);
        clock += 40000; // the user reads the dialog for 40 s
        return true;
      }
    });
    assert.equal(started, true);
    await ended;
    assert.deepEqual(confirms, [60], 'the 8 lapsing measurements were priced as paid');
    assert.equal(gp.posts.length, 60);
    assert.equal(job.rows.filter((row) => row.notRun === 'budget').length, 0);
  });

  test('when the price rises while the dialog is open, the dialog is shown again with the new price (GP-6)', async () => {
    const names = Array.from({ length: 60 }, (_, i) => `m${String(i).padStart(2, '0')}.example.com`);
    const run = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: names }] });
    const job = verifyJob(run);
    const T0 = Date.parse('2026-09-24T07:00:00Z');
    let clock = T0;
    job.runs = 1;
    job.rows.forEach((row, i) => {
      row.state = 'error';
      row.error = { code: 'deadline', message: '' };
      if (i < 8) Object.assign(row, { measurementId: `paidMeas${String(i).padStart(4, '0')}`, measurementDone: false, measurementAt: T0 - 60000, reuseAttempts: 0 });
    });
    const gp = fakeGp();
    const confirms = [];
    const ended = whenEnded(job);
    await launchVerify(run, ctxFor(gp), {
      now: () => clock,
      confirm: async (o) => {
        confirms.push(o.checks);
        clock += 40000;
        return true;
      }
    });
    await ended;
    assert.deepEqual(confirms, [52, 60], 'free at the first look, paid by the time the user said yes: asked again');
    assert.equal(gp.posts.length, 60);
    assert.equal(job.rows.filter((row) => row.notRun === 'budget').length, 0);
  });

  test('after consent a small batch that fits runs without the dialog; more than 50 checks always asks (F3)', async () => {
    const one = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: ['one.example.com'] }] });
    verifyJob(one);
    const gp = fakeGp();
    let ended = whenEnded(one.verify);
    assert.equal(await launchVerify(one, ctxFor(gp), { confirm: async () => true }), true);
    await ended;
    const two = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: ['two.example.com'] }] });
    verifyJob(two);
    const asked = [];
    ended = whenEnded(two.verify);
    assert.equal(await launchVerify(two, ctxFor(gp), { confirm: async (o) => { asked.push(o); return true; } }), true);
    await ended;
    assert.equal(asked.length, 0, 'consent given in this page session and the batch fits');
    const big = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: Array.from({ length: 51 }, (_, i) => `b${i}.example.com`) }] });
    verifyJob(big);
    assert.equal(await launchVerify(big, ctxFor(gp), { confirm: async (o) => { asked.push(o); return false; } }), false);
    assert.deepEqual(asked.map((o) => [o.first, o.checks]), [[false, 51]], 'soft confirm above 50 checks');
    assert.equal(big.verify.starting, false);
  });

  test('after consent without origin checks, the first batch with one asks again with the origin sentence (critic C.3.1)', async () => {
    state.clearAll(); // "Delete all local data": consent for this page session starts over
    const gp = fakeGp();
    const asked = [];
    const confirm = async (o) => { asked.push([o.first, o.checks, o.origins]); return true; };
    const plain = scanRun({ unmatchedIps: [{ ip: '5.6.7.8', hosts: ['plain.example.com'] }] });
    verifyJob(plain);
    let ended = whenEnded(plain.verify);
    assert.equal(await launchVerify(plain, ctxFor(gp), { confirm }), true);
    await ended;
    const withOrigin = () => {
      const run = scanRun({
        servers: [{ server: { id: 's1', name: 'web01' }, needsCert: true, hosts: [
          { name: 'www.example.com', ip: '1.2.3.4', via: 'dns', covered: true },
          { name: 'shop.example.com', ip: '1.2.3.4', via: 'hint', covered: true }] }],
        hosts: [{ name: 'shop.example.com', classification: { hidesOrigin: true, provider: { name: 'Cloudflare' } } }]
      });
      verifyJob(run);
      assert.equal(setOriginOptIn(run, true), true);
      return run;
    };
    const first = withOrigin();
    ended = whenEnded(first.verify);
    assert.equal(await launchVerify(first, ctxFor(gp), { confirm }), true);
    await ended;
    const second = withOrigin();
    ended = whenEnded(second.verify);
    assert.equal(await launchVerify(second, ctxFor(gp), { confirm }), true);
    await ended;
    assert.deepEqual(asked, [[true, 1, 0], [false, 2, 1]], 'consent, then once more for the first origin check; not again after that');
    assert.ok(gp.posts.includes('1.2.3.4 shop.example.com'));
    state.clearAll();
    const third = withOrigin();
    assert.equal(await launchVerify(third, ctxFor(gp), { confirm: async (o) => { asked.push([o.first, o.checks, o.origins]); return false; } }), false);
    assert.deepEqual(asked.at(-1), [true, 2, 1], '"Delete all local data" resets the origin consent too');
  });

  test('a zone-file origin (origin IP + proxied name) waits for the opt-in and is named in the dialog', async () => {
    state.clearAll();
    const zoneRun = () => {
      const run = scanRun({
        servers: [{ server: { id: 's1', name: 'web01' }, needsCert: true, hosts: [{ name: 'www.example.com', ip: '1.2.3.4', via: 'zone', covered: true }] }],
        unmatchedIps: [{ ip: '5.6.7.8', hosts: ['api.example.com'] }],
        hosts: [{ name: 'www.example.com', classification: { hidesOrigin: true, provider: { name: 'Cloudflare' } } }]
      });
      verifyJob(run);
      return run;
    };
    const gp = fakeGp();
    const asked = [];
    const confirm = async (o) => { asked.push([o.first, o.checks, o.origins]); return true; };
    const first = zoneRun();
    const www = first.verify.rows.find((r) => r.name === 'www.example.com');
    assert.deepEqual([www.via, www.proxied, www.state, www.notRun], ['zone', true, 'not-run', 'optional']);
    let ended = whenEnded(first.verify);
    assert.equal(await launchVerify(first, ctxFor(gp), { confirm }), true);
    await ended;
    assert.deepEqual(gp.posts, ['5.6.7.8 api.example.com'], 'the origin pair stayed in the browser');
    const second = zoneRun();
    assert.equal(setOriginOptIn(second, true), true);
    ended = whenEnded(second.verify);
    assert.equal(await launchVerify(second, ctxFor(gp), { confirm }), true);
    await ended;
    assert.deepEqual(asked, [[true, 1, 0], [false, 2, 1]], 'consent given, yet asked again with the origin sentence');
    assert.ok(gp.posts.includes('1.2.3.4 www.example.com'));
    state.clearAll();
  });
});

describe('rows and copy (review fixes)', () => {
  /** A proxied origin row judged by the real lib from one probe's raw output. */
  function proxiedFrom(raw) {
    const v = aggregateVerdicts([classifyTest({ probe: { asn: 1 }, result: { status: 'failed', rawOutput: raw, tls: null } }, { name: 'shop.example.com' })]);
    const row = { ...doneRow({ name: 'shop.example.com', via: 'hint', proxied: true, status: v.status, reason: v.reason }), verdict: v, served: null };
    row.exposure = exposureOf(row);
    return row;
  }

  test('an origin that connected but timed out the handshake, or an unreachable network, is not "filtered as expected" (VFY-UI-02)', () => {
    const tls = proxiedFrom('Request timed out.');
    assert.deepEqual([tls.status, tls.reason, tls.exposure], ['TIMEOUT', 'tls-timeout', 'unknown']);
    assert.equal(statusBadgeSpec(tls).key, 'vfy.st.TIMEOUT');
    assert.equal(resultRank(tls), 3);
    assert.ok(recheckRows([tls]).length === 1, 'and Check again still includes it, consistently');
    const unreach = proxiedFrom('connect ENETUNREACH 203.0.113.9:443');
    assert.deepEqual([unreach.status, unreach.exposure], ['CLOSED', 'unknown']);
    assert.equal(resultRank(unreach), 3);
    const filtered = proxiedFrom('Request timed out while establishing the TCP connection.');
    assert.deepEqual([filtered.exposure, statusBadgeSpec(filtered).key, resultRank(filtered)], ['no-answer', 'vfy.st.TIMEOUT.origin', 7]);
    const refused = proxiedFrom('connect ECONNREFUSED 203.0.113.9:443');
    assert.deepEqual([refused.exposure, resultRank(refused)], ['closed', 7]);
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      assert.doesNotMatch(t('vfy.exp.unknown'), /disagree|farklı sonuç/, 'one probe cannot disagree');
      assert.doesNotMatch(t('vfy.exp.unknown.title'), /did not agree|uyuşmadı/);
    }
    setLang('en');
  });

  test('a Cloudflare Origin CA row is neither "Old certificate" nor highlighted as old (VFY-UI-06)', () => {
    const ca = doneRow({ status: 'NEEDS_UPDATE', reason: 'old-cert', warnings: ['origin-ca'] });
    const spec = statusBadgeSpec(ca);
    assert.equal(spec.key, 'vfy.st.NEEDS_UPDATE.origin');
    assert.notEqual(spec.variant, 'warn');
    assert.ok(hasString(spec.key, 'en') && hasString(spec.key, 'tr'));
    assert.equal(verifyRowClass(ca)['vfy-row-old'], false);
    assert.equal(verifyRowClass(doneRow({ status: 'NEEDS_UPDATE', reason: 'old-cert' }))['vfy-row-old'], true);
    assert.equal(verifyRowClass(doneRow({ status: 'NEEDS_UPDATE', newCertCovers: false }))['vfy-row-old'], false);
  });

  test('every name behind a CDN and no inventory: no "CLI below" when no CLI card renders (VFY-UI-05)', () => {
    const cdn = { hidesOrigin: true, provider: { name: 'Cloudflare' } };
    const { pairs, stats } = buildVerifyPairs({
      hosts: ['a', 'b', 'c'].map((l) => ({ name: `${l}.example.com`, classification: cdn, cert: { covered: true } })), servers: [], unmatchedIps: []
    });
    assert.equal(pairs.length, 0);
    assert.equal(emptyKey(pairs, []), 'vfy.empty.none');
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      assert.doesNotMatch(t(emptyKey(pairs, [])), /CLI/);
      assert.doesNotMatch(notHereSentence([], stats), /CLI/);
    }
    setLang('en');
    assert.equal(notHereSentence([], stats), 'Not checkable from the internet: 3 names behind a CDN with no known origin.');
    // Private addresses are what the CLI card is for: the sentence points to it.
    const priv = [pendingRow({ ip: '10.0.0.5', name: 'vpn.example.com', state: 'skipped', skip: 'private' })];
    assert.match(notHereSentence(priv, stats), /CLI below/);
    assert.equal(emptyKey([{ skip: 'private' }], priv), 'vfy.empty');
    assert.equal(emptyKey([{ skip: 'cdn-edge' }], [pendingRow({ state: 'skipped', skip: 'cdn-edge' })]), 'vfy.empty.noCli');
    assert.doesNotMatch(t('vfy.empty.noCli'), /CLI/);
  });

  test('a quota reading or a "used up" note whose window has ended is not shown (VFY-UI-07)', () => {
    const now = Date.parse('2026-09-24T12:00:00Z');
    const q = { limit: 250, remaining: 0, resetAt: new Date(now - 3600e3) };
    assert.equal(liveQuota(q, now), null);
    assert.equal(liveQuota({ ...q, resetAt: new Date(now + 60e3) }, now).remaining, 0);
    assert.equal(liveQuota({ ...q, resetAt: null }, now).limit, 250, 'an unopened window has no reset yet');
    assert.equal(liveQuota(null, now), null);
    assert.equal(quotaOutActive({ resetAt: new Date(now - 1500e3), count: 3 }, now), false);
    assert.equal(quotaOutActive({ resetAt: new Date(now + 1500e3), count: 3 }, now), true);
    assert.equal(quotaOutActive({ resetAt: null, at: now - 2 * 3600e3, count: 1 }, now), false);
    assert.equal(quotaOutActive({ resetAt: null, at: now - 60e3, count: 1 }, now), true);
    assert.equal(quotaOutActive(null, now), false);
    // The plan line falls back to the anonymous limit instead of a stale reading.
    assert.match(planText([pendingRow()], { quota: { limit: 500, remaining: 0, resetAt: new Date(Date.now() - 60e3) } }), /free: 250 per hour/);
    assert.match(planText([pendingRow()], { quota: { limit: 500, remaining: 9, resetAt: new Date(Date.now() + 60e3) } }), /free: 500 per hour/);
  });

  test('the free re-fetch is promised only within the reuse window (VFY-UI-08)', () => {
    const minutes = String(VERIFY_REUSE_WINDOW_MS / 60000);
    const row = { state: 'error', error: { code: 'deadline' } };
    setLang('en');
    assert.match(errorText(row), new RegExp(`within ${minutes} minutes`));
    assert.match(t('vfy.stopped', { minutes }), new RegExp(`within ${minutes} minutes.*sent again`));
    setLang('tr');
    assert.match(errorText(row), new RegExp(`${minutes} dakika içinde`));
    assert.match(t('vfy.stopped', { minutes }), new RegExp(`${minutes} dakika içinde`));
    setLang('en');
    assert.doesNotMatch(errorText({ state: 'error', error: { code: 'network' } }), /\{/);
  });

  test('a long CLI name list goes to verify-names.txt, not the Behind CDN card\'s proxied-names.txt (VFY-UI-09)', () => {
    const names = Array.from({ length: 201 }, (_, i) => `h${i}.example.com`);
    const sweep = verifyCliSweep({ targets: ['10.0.0.5'], names }, 'posix');
    assert.equal(sweep.namesInline, false);
    assert.equal(sweep.namesFile, 'verify-names.txt');
    assert.match(sweep.command, / -n verify-names\.txt --cert new-cert\.pem --json verify-cli\.json$/);
    assert.equal(verifyCliSweep({ targets: ['10.0.0.5'], names: ['a.example.com'] }, 'posix').namesInline, true);
  });

  test('the plan line counts the probe-fault retries in its cost (F8)', () => {
    setLang('en');
    const text = planText([pendingRow(), pendingRow({ ip: '5.6.7.9' })]);
    assert.match(text, new RegExp(`up to 2 probes, plus up to ${VERIFY_MAX_RETRIES} retries if a probe fails`));
    setLang('tr');
    assert.match(planText([pendingRow()]), new RegExp(`en fazla ${VERIFY_MAX_RETRIES} yeniden deneme`));
    setLang('en');
  });
});

describe('app.js getGlobalping()', () => {
  test('one shared client; a failed load is not cached', async () => {
    let made = 0;
    const load = async () => ({ createGlobalping: () => ({ id: ++made }) });
    await assert.rejects(getGlobalping(async () => { throw new Error('offline'); }), /offline/);
    const a = await getGlobalping(load);
    const b = await getGlobalping(load);
    assert.equal(a, b);
    assert.equal(made, 1);
  });
});
