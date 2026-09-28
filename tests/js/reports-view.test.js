/**
 * views/reports.js — the pure parts of the DMARC & TLS reports view: how much of a source's mail
 * passed aligned, the parameters of a fix text, the facts Copy summary gets (the domain on screen,
 * the TLS summary of the same domain, whether the classes rest on the current SPF), and that
 * every source class, SPF line state and advice link has its look. The module is DOM-free at
 * import. Pure Node, no network; documentation data only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  id, titleKey, icon, alignedState, fixParams, headlineShare, summaryFacts, verdictLook, CLASS_STYLE, TLS_TOOLS, SPF_LINE_STATES, VERDICT_EXTRA_KEYS,
  INTEL_MAX, FIX_FIRST_MAX, result
} from '../../assets/js/views/reports.js';
import { SOURCE_CLASSES, FIX_CODES, DMARC_VERDICTS } from '../../assets/js/lib/dmarcreport.js';
import { TLS_RESULT_TYPES, tlsAdvice } from '../../assets/js/lib/tlsrpt.js';
import { reportsSummary } from '../../assets/js/lib/reportsummary.js';

test('the view interface; nothing kept before reports were read', () => {
  assert.deepEqual([id, titleKey, icon], ['reports', 'nav.reports', 'inbox']);
  assert.equal(result(), null);
  assert.ok(INTEL_MAX > 0 && INTEL_MAX <= 50, 'a click never sends a whole table to the IP data services');
  assert.ok(FIX_FIRST_MAX >= 3);
});

test('alignedState: all, none or a part of the messages', () => {
  assert.deepEqual(alignedState(10, 10), { state: 'pass', ratio: 1 });
  assert.deepEqual(alignedState(0, 10), { state: 'fail', ratio: 0 });
  assert.deepEqual(alignedState(4, 10), { state: 'part', ratio: 0.4 });
  assert.equal(alignedState(0, 0).state, 'fail', 'no message is no pass');
});

test('fixParams: the policy domain, and the other domain an alignment fix names', () => {
  const row = {
    dkimAuth: [{ domain: 'example.com', result: 'fail' }, { domain: 'mailer.example.net', result: 'pass' }],
    spfAuth: [{ domain: 'bounces.mailer.example.net', result: 'pass' }, { domain: 'mail.example.com', result: 'pass' }]
  };
  assert.deepEqual(fixParams(row, 'dkim-align', 'example.com'), { domain: 'example.com', other: 'mailer.example.net' });
  assert.deepEqual(fixParams(row, 'spf-align', 'example.com'), { domain: 'example.com', other: 'bounces.mailer.example.net' });
  assert.deepEqual(fixParams(row, 'dkim-sign', 'example.com'), { domain: 'example.com', other: '' });
  // a subdomain of the policy domain is the same organisation, never "another domain"
  assert.deepEqual(fixParams({ dkimAuth: [], spfAuth: [{ domain: 'mail.example.com', result: 'pass' }] }, 'spf-align', 'example.com').other, '');
  for (const code of FIX_CODES) assert.equal(typeof fixParams(row, code, 'example.com').domain, 'string');
  // a broken record is named by the domain that holds it (a bounce subdomain's own record, say)
  assert.equal(fixParams({ ...row, spfDomain: 'bounce.example.com' }, 'spf-permerror', 'example.com').domain, 'bounce.example.com');
  assert.equal(fixParams(row, 'spf-permerror', 'example.com').domain, 'example.com');
});

test('headlineShare: the number Copy summary says, one decimal, never all or none unless it is', () => {
  const said = (ratio) => {
    const x = headlineShare(ratio);
    return [Math.round(x.value * 1000) / 10, x.digits];
  };
  assert.deepEqual(said(4913 / 5175), [94.9, 1], 'the page said 95% while the summary said 94.9%');
  assert.deepEqual(said(0.95), [95, 0]);
  assert.deepEqual(said(1), [100, 0]);
  assert.deepEqual(said(0.99996), [99.9, 1]);
});

test('verdictLook: p=reject in force turns a verdict about the future into mail refused now', () => {
  const look = (verdict, over = {}) => verdictLook({ verdict, enforced: false, blockers: [], ...over });
  assert.deepEqual(look('fix-first', { blockers: [{}] }), { key: 'fix-first', variant: 'warn' });
  assert.deepEqual(look('enforced', { enforced: true }), { key: 'enforced', variant: 'ok' });
  assert.deepEqual(look('enforced', { enforced: true, blockers: [{}] }), { key: 'enforcedLosing', variant: 'error' });
  assert.deepEqual(look('spf-broken'), { key: 'spf-broken', variant: 'warn' });
  // p=reject at 100 %, and the SPF record now gives a permerror (one include too many): refused now, never "not ready yet"
  assert.deepEqual(look('spf-broken', { enforced: true }), { key: 'enforcedSpfBroken', variant: 'error' });
  const keys = new Set([...DMARC_VERDICTS.map((v) => look(v).key), ...DMARC_VERDICTS.map((v) => look(v, { enforced: true, blockers: [{}] }).key)]);
  assert.deepEqual([...keys].filter((k) => !DMARC_VERDICTS.includes(k)).sort(), [...VERDICT_EXTRA_KEYS].sort(), 'every text key is listed');
  for (const v of DMARC_VERDICTS) assert.ok(['info', 'ok', 'warn', 'error'].includes(look(v).variant), v);
});

test('summaryFacts: the DMARC domain on screen with the TLS summary it is given; the SPF basis said', () => {
  const agg = { domain: 'example.com', policy: { p: 'none', pct: 100, sp: 'none' }, reports: 2, begin: new Date('2026-09-25T00:00:00Z'), end: new Date('2026-09-26T23:59:59Z') };
  const overview = { compliance: 0.5, messages: 10, verdict: 'ready', blockers: [], blocked: 0, unknown: [], unknownFail: 5 };
  const tls = { domain: 'example.com', success: 9, failure: 1, rate: 0.9, reports: 1, byType: [{ type: 'certificate-expired', sessions: 1 }], orgs: [] };
  const f = summaryFacts({ agg, overview, spfState: 'ok', tls, problems: 1, at: new Date(0) });
  assert.deepEqual(f.dmarc.policy, { p: 'none', pct: 100, testing: null });
  assert.equal(f.dmarc.spf, 'checked');
  assert.equal(f.dmarc.spfErrorKey, null);
  const broken = summaryFacts({ agg, overview: { ...overview, spfError: { domain: 'example.com', reason: 'void-limit', sources: 2 } }, spfState: 'ok', tls: null, problems: 0, at: null });
  assert.equal(broken.dmarc.spfErrorKey, 'rpt.spfError.void-limit', 'the view\'s own words ride in the facts');
  assert.deepEqual(f.tls, { success: 9, failure: 1, rate: 0.9, reports: 1, byType: tls.byType });
  assert.equal(f.domain, 'example.com');
  assert.equal(summaryFacts({ agg, overview, spfState: 'offline', tls: null, problems: 0, at: null }).dmarc.spf, 'skipped');
  for (const st of ['none', 'multiple']) assert.equal(summaryFacts({ agg, overview, spfState: st, tls: null, problems: 0, at: null }).dmarc.spf, 'checked', st);
  for (const st of ['failed', 'loading', null]) assert.equal(summaryFacts({ agg, overview, spfState: st, tls: null, problems: 0, at: null }).dmarc.spf, 'failed', String(st));
  const tlsOnly = summaryFacts({ agg: null, overview: null, spfState: null, tls, problems: 0, at: null });
  assert.deepEqual([tlsOnly.domain, tlsOnly.dmarc], ['example.com', null]);
  assert.equal(summaryFacts({ agg: null, overview: null, spfState: null, tls: null, problems: 0, at: null }), null);
  // the builder takes them as they are
  const doc = reportsSummary(f, { t: (k) => k, lang: 'en', now: new Date(0) });
  assert.equal(doc.kind, 'reports');
});

test('every source class has a badge and a tile look; every advice link is drawn', () => {
  assert.deepEqual(Object.keys(CLASS_STYLE).sort(), [...SOURCE_CLASSES].sort());
  for (const c of SOURCE_CLASSES) assert.ok(CLASS_STYLE[c].variant && CLASS_STYLE[c].icon, c);
  const tools = new Set(TLS_RESULT_TYPES.flatMap((ty) => tlsAdvice(ty).tools));
  assert.deepEqual([...tools].sort(), [...TLS_TOOLS].sort());
  assert.ok(SPF_LINE_STATES.includes('offline') && SPF_LINE_STATES.includes('failed'));
});
