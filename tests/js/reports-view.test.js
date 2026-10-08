/**
 * views/reports.js — the pure parts of the DMARC & TLS reports view: how much of a source's mail
 * passed aligned, the parameters of a fix text, the facts Copy summary gets (the domain on screen,
 * the TLS summary of the same domain, whether the classes rest on the current SPF), and that
 * every source class, SPF line state and advice link has its look, and which rows of the sources
 * table a new classification redraws; the service line's words and the service view's groups,
 * in English and Turkish, why a source has no service yet, what an Identify senders lookup keeps
 * and whom its button says it asks. The module is DOM-free at import. Pure Node, no network;
 * documentation data only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  id, titleKey, icon, alignedState, fixParams, headlineShare, summaryFacts, verdictLook, CLASS_STYLE, TLS_TOOLS, SPF_LINE_STATES, VERDICT_EXTRA_KEYS,
  INTEL_MAX, FIX_FIRST_MAX, IDENTIFY_CONCURRENCY, GROUP_LIST_MAX, SOURCE_VIEWS, result, sourceRowChanged, serviceLabel, serviceHow, groupName, ptrFact,
  unnamedHint
} from '../../assets/js/views/reports.js';
import { SOURCE_CLASSES, FIX_CODES, DMARC_VERDICTS, aggregateDmarc, parseAggregateReport, classifySources } from '../../assets/js/lib/dmarcreport.js';
import { buildIpIndex, parseInventory } from '../../assets/js/lib/inventory.js';
import { TLS_RESULT_TYPES, tlsAdvice } from '../../assets/js/lib/tlsrpt.js';
import { reportsSummary } from '../../assets/js/lib/reportsummary.js';
import { identifySource, groupSources, spfPathOf, SENDER_TYPES, SENDER_VIAS, IDENTIFY_MAX } from '../../assets/js/lib/senders.js';
import { FCRDNS_STATUSES } from '../../assets/js/lib/ptrsweep.js';
import { t, setLang } from '../../assets/js/i18n.js';

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

test('sourceRowChanged: a row is drawn again only when its class, why, servers, current SPF or fixes changed', () => {
  const base = { ip: '192.0.2.1', messages: 3, cls: 'unknown', reason: 'none', detail: null, servers: [], spfDomain: null, spfNow: null, spfListed: null, atRisk: 0, fixes: [] };
  const verdict = { result: 'pass', term: 'ip4:192.0.2.0/24', holder: 'example.com', path: ['example.com'], via: null, reason: null };
  assert.equal(sourceRowChanged(base, { ...base, servers: [], fixes: [] }), false, 'equal lists, other arrays');
  for (const change of [{ cls: 'yours' }, { reason: 'spf' }, { detail: 'ip4:192.0.2.0/24' }, { servers: ['mail01'] }, { spfDomain: 'example.com' },
    { atRisk: 2 }, { fixes: ['dkim-sign'] }, { spfNow: verdict }, { spfListed: verdict }]) {
    assert.equal(sourceRowChanged(base, { ...base, ...change }), true, JSON.stringify(change));
  }
  const withVerdict = { ...base, spfNow: verdict };
  assert.equal(sourceRowChanged(withVerdict, { ...base, spfNow: { ...verdict, path: [...verdict.path] } }), false, 'the same verdict in another object');
  for (const change of [{ result: 'fail' }, { term: '~all' }, { holder: '_spf.example.com' }, { reason: 'lookup-limit' }, { path: ['example.com', '_spf.example.com'] },
    { via: { host: 'mx1.example.com', address: '192.0.2.1' } }]) {
    assert.equal(sourceRowChanged(withVerdict, { ...base, spfNow: { ...verdict, ...change } }), true, JSON.stringify(change));
  }
});

test('sourceRowChanged over classifySources: the same evidence redraws nothing, a server added redraws its row only', () => {
  const rec = (ip) => `<record><row><source_ip>${ip}</source_ip><count>2</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>fail</result></spf></auth_results></record>`;
  const xml = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>1</report_id>
    <date_range><begin>1790294400</begin><end>1790899200</end></date_range></report_metadata>
    <policy_published><domain>example.com</domain><p>none</p></policy_published>${['192.0.2.1', '192.0.2.2', '198.51.100.7'].map(rec).join('')}</feedback>`;
  const agg = aggregateDmarc([parseAggregateReport(xml).report]).domains[0];
  const changed = (a, b) => b.filter((r, i) => sourceRowChanged(a[i], r)).map((r) => r.ip);
  const before = classifySources(agg, {});
  assert.deepEqual(changed(before, classifySources(agg, {})), [], 'classified again on the same evidence (the SPF lookup starting)');
  const index = buildIpIndex(parseInventory('mail01 192.0.2.2').servers);
  assert.deepEqual(changed(before, classifySources(agg, { index })), ['192.0.2.2']);
  assert.deepEqual(changed(before, classifySources(agg, { spf: new Map([['example.com', { status: 'none' }]]) })).length, 3, 'the SPF landed: every row');
});

/* ---- the service behind each source (lib/senders.js) ---------------------------------------- */

const srcRow = (over = {}) => ({
  ip: '192.0.2.10', private: false, messages: 10, pass: 10, fail: 0, spfAligned: 0, dkimAligned: 10, cls: 'third-party',
  headerFrom: ['example.com'], dkimAuth: [], spfAuth: [], spfNow: null, spfListed: null, ...over
});
const inLang = (lang, fn) => {
  setLang(lang);
  try {
    return fn();
  } finally {
    setLang('en');
  }
};

test('the Service column: the name, its type and evidence, "not confirmed" for a hint, an ISP or home network, in English and Turkish', () => {
  const byDkim = identifySource(srcRow({ dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }));
  const maps = { ptr: new Map(), isp: new Set(['broadband.example.net']) };
  const isp = identifySource(srcRow({ cls: 'unknown' }), { ptrName: 'dsl-7.broadband.example.net', maps });
  const byPtr = identifySource(srcRow(), { ptrName: 'a8-31.smtp-out.amazonses.com', ptrConfirmed: true });
  const network = identifySource(srcRow(), { holder: { name: 'Example Hosting Ltd', asn: 64496 } });
  assert.deepEqual(inLang('en', () => serviceLabel(byDkim, t)), { name: 'SendGrid', meta: 'Transactional email · DKIM' });
  assert.deepEqual(inLang('tr', () => serviceLabel(byDkim, t)), { name: 'SendGrid', meta: 'İşlemsel e-posta · DKIM' });
  assert.deepEqual(inLang('en', () => serviceLabel(isp, t)), { name: 'ISP or home network', meta: 'broadband.example.net · reverse DNS, not confirmed' });
  assert.deepEqual(inLang('tr', () => serviceLabel(isp, t)), { name: 'İSS ya da ev ağı', meta: 'broadband.example.net · ters DNS, doğrulanmadı' });
  assert.deepEqual(inLang('en', () => serviceLabel(byPtr, t)), { name: 'Amazon SES', meta: 'Transactional email · reverse DNS' });
  assert.deepEqual(inLang('en', () => serviceLabel(network, t)), { name: 'Example Hosting Ltd', meta: 'AS64496 · RIPEstat' });
  assert.equal(serviceLabel(null, t), null);
  // how it was named, as a sentence
  assert.equal(inLang('en', () => serviceHow(byDkim, t)), 'Named from its DKIM signature, which verified: d=sendgrid.net');
  assert.equal(inLang('tr', () => serviceHow(byDkim, t)), 'Doğrulanan DKIM imzasından: d=sendgrid.net');
  assert.equal(inLang('en', () => serviceHow(byPtr, t)), 'Named from its reverse DNS: a8-31.smtp-out.amazonses.com (the name resolves back to the address)');
  assert.match(inLang('en', () => serviceHow(isp, t)), /^An ISP or home network by its reverse DNS \(dsl-7\.broadband\.example\.net\): spoofing, or a user forwarding their own mail \(the name does not resolve back/);
  assert.equal(inLang('en', () => serviceHow(network, t)), 'Only its network is known: AS64496 Example Hosting Ltd');
  assert.equal(serviceHow(null, t), '');
  // every type and evidence has its words in both languages
  for (const lang of ['en', 'tr']) {
    inLang(lang, () => {
      for (const ty of SENDER_TYPES) assert.ok(!t(`rpt.svcType.${ty}`).startsWith('rpt.'), `${lang} ${ty}`);
      for (const v of SENDER_VIAS) assert.ok(!t(`rpt.svcVia.${v}`).startsWith('rpt.'), `${lang} ${v}`);
    });
  }
});

test('the service view: the groups named in English and Turkish, the unnamed last; the view constants', () => {
  const rows = [
    srcRow({ ip: '192.0.2.1', messages: 100, dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }),
    srcRow({ ip: '192.0.2.3', messages: 5, cls: 'unknown' }),
    srcRow({ ip: '198.51.100.4', messages: 7, cls: 'unknown' })
  ];
  const maps = { ptr: new Map(), isp: new Set(['broadband.example.net']) };
  const ptr = { '192.0.2.3': 'a.broadband.example.net' };
  const { groups, totals } = groupSources(rows, (r) => identifySource(r, { ptrName: ptr[r.ip], maps }));
  assert.deepEqual(groups.map((g) => inLang('en', () => groupName(g, t))), ['SendGrid', 'ISP or home networks', 'Not identified']);
  assert.deepEqual(groups.map((g) => inLang('tr', () => groupName(g, t))), ['SendGrid', 'İSS’ler ya da ev ağları', 'Tanımlanamadı']);
  assert.deepEqual([totals.services, totals.addresses, totals.unnamedAddresses], [2, 3, 1]);
  assert.equal(inLang('tr', () => t('rpt.grp.unnamedLine', { count: 1, messages: t('rpt.det.count', { count: 7 }) })), '1 adres tanımlanamadı (7 e-posta)');
  assert.equal(inLang('en', () => t('rpt.grp.unnamedLine', { count: 1, messages: t('rpt.det.count', { count: 7 }) })), '1 address not identified (7 messages)');
  assert.deepEqual(SOURCE_VIEWS, ['address', 'service']);
  assert.ok(IDENTIFY_CONCURRENCY > 0 && IDENTIFY_CONCURRENCY <= 12, 'never more lookups at once than the DohClient\'s limiter');
  assert.ok(GROUP_LIST_MAX >= 10);
  assert.equal(IDENTIFY_MAX, 200);
  // a guide in both languages names the service and the domain
  assert.ok(inLang('en', () => t('rpt.guide.transactional', { service: 'Example ESP', domain: 'example.com' })).startsWith('Example ESP sends mail for your applications'));
  assert.match(inLang('tr', () => t('rpt.guide.sendgrid', { domain: 'example.com' })), /example\.com alan adını Settings › Sender Authentication altında doğrulayın/);
});

test('ptrFact: the name that points back first, its status, an unknown status as an error', () => {
  assert.deepEqual(ptrFact({ status: 'confirmed', names: ['a.example.net', 'b.example.net'], confirmed: ['b.example.net'] }),
    { status: 'confirmed', name: 'b.example.net', confirmed: true });
  assert.deepEqual(ptrFact({ status: 'mismatch', names: ['a.example.net'], confirmed: [] }), { status: 'mismatch', name: 'a.example.net', confirmed: false });
  assert.deepEqual(ptrFact({ status: 'nxdomain', names: [], confirmed: [] }), { status: 'nxdomain', name: null, confirmed: false });
  assert.deepEqual(ptrFact({ status: 'odd' }), { status: 'error', name: null, confirmed: false });
  assert.deepEqual(ptrFact(null), { status: 'error', name: null, confirmed: false });
  for (const st of FCRDNS_STATUSES) assert.equal(ptrFact({ status: st }).status, st);
});

test('the words a service rests on: the SPF term as it is, a forwarder\'s guide that credits no one, every recipient of Identify senders', () => {
  // the a / mx host that matched (or a redirect) is no include
  const viaHost = { result: 'pass', term: 'a:mail.zendesk.com', holder: 'example.com', path: ['example.com'], via: { host: 'mail.zendesk.com', address: '192.0.2.10' } };
  const byHost = identifySource(srcRow({ spfNow: viaHost }), { spfPath: spfPathOf(srcRow({ spfNow: viaHost })) });
  assert.equal(byHost.via, 'spf-include');
  assert.equal(inLang('en', () => serviceHow(byHost, t)), 'Named from your SPF, which authorizes it through mail.zendesk.com');
  assert.equal(inLang('tr', () => serviceHow(byHost, t)), 'Adresi mail.zendesk.com üzerinden yetkilendiren SPF kaydınızdan');
  for (const lang of ['en', 'tr']) {
    inLang(lang, () => {
      // a forwarder only relayed the mail: its guide names no service as the sender
      const fwd = t('rpt.guide.forwarded', { service: 'Example Mailbox', domain: 'example.com' });
      assert.ok(!fwd.includes('Example Mailbox') && fwd.includes('example.com') && fwd.includes('DKIM'), `${lang}: ${fwd}`);
      const authorized = t('rpt.guide.authorized', { service: 'Example Mail Hosting', domain: 'example.com' });
      assert.ok(authorized.includes('Example Mail Hosting') && authorized.includes('example.com') && !/spoof|sahte/i.test(authorized), `${lang}: ${authorized}`);
      // the button names every service the network lookup may ask, as Look up's does
      const bulk = t('rpt.id.bulkTitle', { max: '200', intel: '25' });
      for (const who of ['RIPEstat', 'ipwho.is']) {
        assert.ok(bulk.includes(who), `${lang}: ${who} in ${bulk}`);
        assert.ok(t('rpt.intel.bulkTitle', { max: '25' }).includes(who), `${lang}: ${who} in Look up's`);
      }
    });
  }
});

test('unnamedHint: why a source has no service yet', () => {
  inLang('en', () => {
    assert.equal(unnamedHint(srcRow({ cls: 'unknown' }), {}, t), 'Not named by the reports: Identify senders looks up its reverse DNS.');
    assert.equal(unnamedHint(srcRow({ cls: 'yours' }), {}, t), 'Your own server: Identify senders leaves it out.');
    assert.equal(unnamedHint(srcRow({ ip: '10.1.2.3', private: true, cls: 'unknown' }), {}, t), 'A private address: Identify senders leaves it out.');
    assert.equal(unnamedHint(srcRow({ cls: 'yours' }), { looked: true }, t), 'Neither the reports nor its reverse DNS name the service behind this address.');
    assert.equal(unnamedHint(srcRow({ cls: 'unknown' }), { failed: true }, t), 'Reverse DNS: could not be looked up');
  });
  assert.equal(inLang('tr', () => unnamedHint(srcRow({ cls: 'yours' }), {}, t)), 'Kendi sunucunuz: Göndericileri tanımla ona bakmaz.');
  assert.equal(inLang('tr', () => unnamedHint(srcRow({ ip: '10.1.2.3', private: true }), {}, t)), 'Özel bir adres: Göndericileri tanımla ona bakmaz.');
});
