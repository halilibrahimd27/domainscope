/**
 * lib/report.js — the customer report (one self-contained HTML file) of the Domain overview and
 * Domain Health: the one escaping helper against injection payloads, the serializer's allow-lists,
 * the file's structure (CSP, no script, problems first, times, version, what was checked, the
 * re-run link), both languages, failures as statuses, and the permalink inputs.
 * No network: a table-driven fake DoH client (real wire records) and a fake fetch for RDAP; the
 * overview's cards and Health's report come from the real lib/passport.js and lib/health.js.
 */
import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as i18n from '../../assets/js/i18n.js';
import { HEALTH_GROUPS } from '../../assets/js/views/health.js';
import '../../assets/js/views/domain.js';
// DMARC & TLS reports: its `rpt.*` keys and `.rpt-` classes must stay clear of the customer report's.
import '../../assets/js/views/reports.js';
import {
  REPORT_CSP, REPORT_CSS, REPORT_I18N, REPORT_KINDS, REPORT_SEVERITIES, REPORT_FILE_BASES, buildReport, domainReport, el, escapeHtml,
  healthReport, isWebUrl, renderHtml, reportBody, reportHtml, reportLinkParams, utcDay, utcTime
} from '../../assets/js/lib/report.js';
import { PASSPORT_CARDS, buildPassport, passportCards } from '../../assets/js/lib/passport.js';
import { LOOKUP_FAILED_PARAM, domainHealth } from '../../assets/js/lib/health.js';
import { PERMALINK_PARAMS, permalinkParams } from '../../assets/js/lib/summarycore.js';
import { statusText } from '../../assets/js/ui/source-status.js';
import { clearRdapCache } from '../../assets/js/lib/rdap.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';

const NOW = new Date('2026-09-28T12:00:00Z');
const GENERATED = new Date('2026-10-08T13:47:00Z');
const XSS = '<script>alert(1)</script>';
const ATTR = '"><img src=x onerror=alert(2)>';
const TOKEN = 'TOKENVALUEsecret123';
const LINK = 'https://example.github.io/domainscope/#/domain?name=example.com';
const SRC = readFileSync(new URL('../../assets/js/lib/report.js', import.meta.url), 'utf8');

/* --- fakes ------------------------------------------------------------------------- */

const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const rrs = (list) => (list.length ? decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers : []);

/** A zone map { name: { TYPE: value | value[], CNAME } } answered as a DohClient (NXDOMAIN outside it). */
function fakeDns(zone) {
  const base = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  return {
    async query(qname, type = 'A') {
      const name = String(qname).toLowerCase().replace(/\.$/, '');
      const answers = [];
      let cur = name;
      let rcode = 'NOERROR';
      for (let i = 0; i < 8; i += 1) {
        const node = zone[cur];
        if (!node) {
          rcode = 'NXDOMAIN';
          break;
        }
        if (node.CNAME && type !== 'CNAME') {
          answers.push({ name: cur, type: 'CNAME', data: node.CNAME });
          cur = node.CNAME;
          continue;
        }
        for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' && typeof data === 'string' ? [data] : data });
        break;
      }
      return base(name, type, { rcode, answers: rrs(answers) });
    }
  };
}

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const RDAP_BASE = 'https://rdap.example.net/';

/** RDAP through a bootstrap that names .com; the registrar's name is a payload. `status`: the registry's HTTP status. */
function fakeFetch({ status = 200 } = {}) {
  return async (url) => {
    const u = String(url);
    if (u.startsWith('https://data.iana.org/rdap/dns.json')) return json({ services: [[['com', 'net', 'org'], [RDAP_BASE]]] });
    if (u.startsWith(RDAP_BASE) || u.startsWith('https://rdap.org/')) {
      if (status !== 200) return json({ errorCode: status }, status);
      return json({
        objectClassName: 'domain', ldhName: 'EXAMPLE.COM', status: ['active'],
        events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }],
        entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', `Evil <b>Registrar</b> "x" & 'y'`]]] }],
        nameservers: [{ ldhName: 'NS1.EXAMPLE.NET' }, { ldhName: 'NS2.EXAMPLE.NET' }],
        secureDNS: { delegationSigned: false }
      });
    }
    throw new TypeError(`unexpected fetch ${u}`);
  };
}

/** example.com with a crafted SPF record, a CAA value that tries to break out of an attribute and a verification token. */
const ZONE = {
  'example.com': {
    SOA: { mname: 'ns1.example.net', rname: 'hostmaster.example.com', serial: 2026092801, refresh: 3600, retry: 600, expire: 1209600, minimum: 300 },
    NS: ['ns1.example.net', 'ns2.example.net'],
    A: ['192.0.2.10'],
    MX: [{ preference: 10, exchange: 'mx.example.net' }],
    TXT: [`v=spf1 ${XSS} -all`, `google-site-verification=${TOKEN}`],
    CAA: [{ flags: 0, tag: 'issue', value: ATTR }]
  },
  'www.example.com': { CNAME: 'example.com' },
  '_dmarc.example.com': { TXT: ['v=DMARC1; p=none'] },
  'mx.example.net': { A: ['198.51.100.25'] },
  'ns1.example.net': { A: ['198.51.100.53'] },
  'ns2.example.net': { A: ['203.0.113.53'] }
};

/** The words of a language (i18n's t with REPORT_I18N and the views' strings registered). */
const words = (lang) => {
  i18n.setLang(lang);
  return { t: i18n.t, lang, has: (k) => i18n.hasString(k, lang), statusText, version: '9.9.9', generatedAt: GENERATED };
};

let domainInput = null;
/** Keys of REPORT_I18N some other module had registered before the report's. */
let taken = null;
let healthInput = null;

before(async () => {
  taken = Object.keys(REPORT_I18N.en).filter((k) => i18n.hasString(k, 'en') || i18n.hasString(k, 'tr'));
  i18n.registerStrings('en', REPORT_I18N.en);
  i18n.registerStrings('tr', REPORT_I18N.tr);
  clearRdapCache();
  const raw = await buildPassport('example.com', { dns: fakeDns(ZONE), fetchImpl: fakeFetch(), now: NOW });
  domainInput = { cards: passportCards(raw, { now: NOW }), domain: 'example.com', host: 'www.example.com', at: NOW };
  clearRdapCache();
  const report = await domainHealth('example.com', { dns: fakeDns(ZONE), fetchImpl: fakeFetch(), now: NOW });
  healthInput = { report, selectors: ['mailgun', 's1024'] };
});
beforeEach(() => i18n.setLang('en'));
after(() => i18n.setLang('en'));

/** Every tag of a serialized report: [name, attribute names]. Text `<` is always escaped, so each `<` opens a tag. */
function tagsOf(html) {
  const out = [];
  for (const m of html.replace(/^<!doctype html>\n/, '').matchAll(/<\/?([a-zA-Z][\w-]*)([^>]*)>/g)) {
    out.push([m[1].toLowerCase(), [...m[2].matchAll(/\s([^\s="]+)(?:="[^"]*")?/g)].map((a) => a[1].toLowerCase())]);
  }
  return out;
}
const ALLOWED_TAGS = new Set(['html', 'head', 'meta', 'title', 'style', 'body', 'header', 'main', 'section', 'footer', 'div', 'h1', 'h2', 'h3',
  'p', 'ul', 'ol', 'li', 'table', 'tbody', 'tr', 'th', 'td', 'span', 'strong', 'code', 'a', 'time']);
const ALLOWED_ATTRS = new Set(['class', 'lang', 'charset', 'name', 'content', 'http-equiv', 'href', 'rel', 'title', 'scope', 'datetime']);

/** No script, no handler, nothing outside the allow-lists; nothing but the one stylesheet. */
function assertInert(html) {
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /<(img|svg|iframe|object|embed|link|base|form|input)\b/i);
  assert.doesNotMatch(html, /javascript:/i);
  for (const [tag, attrs] of tagsOf(html)) {
    assert.ok(ALLOWED_TAGS.has(tag), `tag ${tag}`);
    for (const a of attrs) assert.ok(ALLOWED_ATTRS.has(a) || /^data-[a-z][a-z0-9-]*$/.test(a), `attribute ${a} on ${tag}`);
  }
  assert.equal(html.match(/<style>/g).length, 1, 'one stylesheet');
  assert.ok(html.includes(`<style>${REPORT_CSS}</style>`), 'the stylesheet is REPORT_CSS');
}

/* --- escaping ----------------------------------------------------------------------- */

describe('escapeHtml: the one escaping helper', () => {
  test('markup, attribute breakouts and entities come out as text', () => {
    const cases = [
      [XSS, '&lt;script&gt;alert(1)&lt;/script&gt;'],
      [ATTR, '&quot;&gt;&lt;img src=x onerror=alert(2)&gt;'],
      ["' onmouseover='alert(3)", '&#39; onmouseover=&#39;alert(3)'],
      ['`${alert(4)}`', '&#96;${alert(4)}&#96;'],
      ['</style><script>alert(5)</script>', '&lt;/style&gt;&lt;script&gt;alert(5)&lt;/script&gt;'],
      ['<!-- x --><![CDATA[y]]>', '&lt;!-- x --&gt;&lt;![CDATA[y]]&gt;'],
      ['&lt;b&gt; & &amp;', '&amp;lt;b&amp;gt; &amp; &amp;amp;'],
      ['Ünlü · İstanbul’da “alıntı”', 'Ünlü · İstanbul’da “alıntı”']
    ];
    for (const [input, out] of cases) assert.equal(escapeHtml(input), out, input);
  });

  test('control and bidi characters cannot hide or reorder text; null and numbers', () => {
    assert.equal(escapeHtml('a\u0000b\u202ecba\u2066c\u200fd\ufeffe'), 'a\ufffdb\ufffdcba\ufffdc\ufffdd\ufffde');
    assert.equal(escapeHtml('tab\there\nline'), 'tab\there\nline');
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
    assert.equal(escapeHtml(42), '42');
    assert.equal(escapeHtml({ toString: () => '<x>' }), '&lt;x&gt;');
  });
});

describe('renderHtml: the serializer escapes every value and refuses what is not on its lists', () => {
  test('text and attribute values go through escapeHtml', () => {
    assert.equal(renderHtml(el('p', { title: ATTR, 'data-x': XSS }, XSS, 7)),
      `<p title="${escapeHtml(ATTR)}" data-x="${escapeHtml(XSS)}">${escapeHtml(XSS)}7</p>`);
    assert.equal(renderHtml(el('ul', null, [el('li', null, 'a'), null, false, '', [el('li', null, 'b')]])), '<ul><li>a</li><li>b</li></ul>');
  });

  test('a script, a frame, an image, a handler or a style attribute cannot be written', () => {
    for (const tag of ['script', 'iframe', 'img', 'svg', 'object', 'link', 'base', 'form']) assert.throws(() => renderHtml(el(tag, null)), TypeError, tag);
    for (const attr of ['onclick', 'onerror', 'style', 'src', 'srcdoc', 'formaction', 'data-X']) {
      assert.throws(() => renderHtml(el('div', { [attr]: 'x' })), TypeError, attr);
    }
    assert.throws(() => renderHtml(el('style', null, 'body{background:url(https://example.net/x)}')), TypeError);
    assert.throws(() => renderHtml(el('style', null, REPORT_CSS, 'p{}')), TypeError);
    assert.ok(renderHtml(el('style', null, REPORT_CSS)).startsWith('<style>.crep{'));
    assert.doesNotMatch(REPORT_CSS, /<\/|url\(|@import|expression\(/i, 'the stylesheet loads nothing and never closes its element');
  });

  test('a link keeps only an http(s) URL', () => {
    assert.equal(renderHtml(el('a', { href: 'javascript:alert(1)' }, 'x')), '<a>x</a>');
    assert.equal(renderHtml(el('a', { href: 'data:text/html,<b>' }, 'x')), '<a>x</a>');
    assert.equal(renderHtml(el('a', { href: ' JaVaScRiPt:alert(1)' }, 'x')), '<a>x</a>');
    assert.equal(renderHtml(el('a', { href: '#/domain' }, 'x')), '<a>x</a>', 'a relative link means nothing in a file');
    assert.equal(renderHtml(el('a', { href: 'https://example.com/?a=1&b="2"', rel: 'noreferrer' }, 'x')), '<a href="https://example.com/?a=1&amp;b=&quot;2&quot;" rel="noreferrer">x</a>');
    assert.deepEqual(['https://example.com/', 'http://example.com/', 'ftp://example.com/', 'mailto:a@example.com', 'nope'].map(isWebUrl), [true, true, false, false, false]);
  });

  test('dates are UTC, the same for every reader', () => {
    assert.equal(utcDay(new Date('2026-10-08T23:59:00-05:00')), '2026-10-09');
    assert.equal(utcTime('2026-10-08T13:47:31Z'), '2026-10-08 13:47 UTC');
    assert.equal(utcTime(null), '');
    assert.equal(utcDay('not a date'), '');
  });
});

/* --- the Domain overview's report --------------------------------------------------- */

describe('domainReport: the overview as one inert file', () => {
  test('the file: doctype, the CSP before anything loads, no script, one stylesheet, the title', () => {
    const { html } = buildReport('domain', domainInput, { ...words('en'), link: LINK });
    assert.ok(html.startsWith('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
      + `<meta http-equiv="Content-Security-Policy" content="${escapeHtml(REPORT_CSP)}">`), html.slice(0, 300));
    assert.equal(REPORT_CSP, "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'");
    assert.ok(html.includes('<meta name="referrer" content="no-referrer">'));
    assert.ok(html.includes('<meta name="generator" content="DomainScope 9.9.9">'));
    assert.ok(html.includes('<title>Domain overview · example.com</title>'));
    assertInert(html);
  });

  test('crafted values (the SPF record, the registrar, a CAA value) are escaped; the TXT token is never there', () => {
    const { html } = buildReport('domain', domainInput, words('en'));
    assertInert(html);
    assert.ok(html.includes('Invalid terms: &lt;script&gt;alert(1)&lt;/script&gt;.'), 'the SPF token, escaped, in its advice');
    assert.ok(html.includes('Evil &lt;b&gt;Registrar&lt;/b&gt; &quot;x&quot; &amp; &#39;y&#39;'), 'the registrar');
    assert.ok(html.includes('&quot;&gt;&lt;img src=x onerror=alert(2)&gt;'), 'the CAA value');
    assert.ok(!html.includes(TOKEN), 'no verification token');
    assert.ok(html.includes('Google'), 'the vendor is named');
  });

  test('problems and their advice first, then the seven cards, what was checked; times, version, re-run link', () => {
    const { doc, html } = buildReport('domain', domainInput, { ...words('en'), link: LINK });
    const order = [...html.matchAll(/data-section="([a-z]+)"/g)].map((m) => m[1]);
    assert.deepEqual(order, ['problems', ...PASSPORT_CARDS, 'method']);
    assert.deepEqual(doc.sections.map((s) => s.id), [...PASSPORT_CARDS]);
    assert.equal(doc.problems[0].severity, 'error');
    assert.ok(doc.problems.every((p, i, all) => i === 0 || REPORT_SEVERITIES.indexOf(all[i - 1].severity) <= REPORT_SEVERITIES.indexOf(p.severity)), 'worst first');
    assert.ok(doc.problems.some((p) => p.title === 'SPF syntax error' && /Receivers return "permerror"/.test(p.detail)), 'with its advice');
    assert.ok(html.includes('Overview of example.com, the registrable domain of www.example.com.'));
    assert.ok(html.includes('<time datetime="2026-09-28T12:00:00.000Z">2026-09-28 12:00 UTC</time>'), 'the result time');
    assert.ok(html.includes('<time datetime="2026-10-08T13:47:00.000Z">2026-10-08 13:47 UTC</time>'), 'the report time');
    assert.ok(html.includes('DomainScope 9.9.9'), 'the version');
    assert.ok(html.includes('What was checked') && html.includes('RDAP service'), 'the methodology');
    assert.ok(html.includes(`<a href="${escapeHtml(LINK)}" rel="noreferrer">`), 'the re-run link');
    assert.ok(html.includes('never a result'), 'says what the link carries');
    assert.match(html, /data-light="error" data-score="\d+"/);
    const reg = doc.sections.find((s) => s.id === 'registration');
    assert.deepEqual(reg.rows.find((r) => r.label === 'Expires'), { label: 'Expires', value: '2027-08-13 · 318 days left', severity: 'ok' });
    assert.equal(reg.rows.find((r) => r.label === 'Transfer lock').value, 'Off');
    const certs = doc.sections.find((s) => s.id === 'certs');
    assert.ok(certs.rows.some((r) => r.value === REPORT_I18N.en['crep.ctNotAsked']), 'CT not asked: said so');
  });

  test('without a link (or with one that is not http(s)) the footer has none', () => {
    for (const link of [null, 'javascript:alert(1)', '#/domain?name=example.com']) {
      const { html } = buildReport('domain', domainInput, { ...words('en'), link });
      assert.ok(!html.includes('Run it again'), String(link));
      assert.doesNotMatch(html, /<a /);
    }
  });

  test('Turkish: the language of the file, the frame and the cards', () => {
    const { html } = buildReport('domain', domainInput, { ...words('tr'), link: LINK });
    assert.ok(html.startsWith('<!doctype html>\n<html lang="tr">'));
    for (const s of ['Sorunlar ve öneriler', 'Alan adı özeti', 'Neler kontrol edildi', 'Raporun hazırlandığı zaman', 'Yeniden çalıştır', 'Geçersiz ifadeler: &lt;script&gt;']) {
      assert.ok(html.includes(s), s);
    }
    for (const s of ['Problems and advice', 'What was checked', 'Report made', 'Run it again']) assert.ok(!html.includes(s), s);
    assertInert(html);
  });

  test('a failed lookup is a status with its reason, never an empty cell', async () => {
    clearRdapCache();
    const raw = await buildPassport('example.com', { dns: fakeDns(ZONE), fetchImpl: fakeFetch({ status: 503 }), now: NOW });
    const doc = domainReport({ cards: passportCards(raw, { now: NOW }), domain: 'example.com', at: NOW }, words('en'));
    const reg = doc.sections.find((s) => s.id === 'registration');
    assert.equal(reg.rows.length, 4);
    for (const r of reg.rows) assert.match(r.value, /^⚠ n\/a — RDAP: .*503/, r.label);
  });

  test('a stopped build says what was not looked up; without health checks, problems are not known', () => {
    const doc = domainReport({ cards: passportCards({ domain: 'example.com' }, { now: NOW }), domain: 'example.com', at: NOW }, words('en'));
    for (const s of doc.sections) assert.equal(s.notes[0].text, 'Not looked up: the build was stopped.', s.id);
    assert.equal(doc.verdict, null);
    assert.ok(reportHtml(doc, words('en')).includes(REPORT_I18N.en['crep.problemsUnknown']));
  });
});

/* --- Domain Health's report --------------------------------------------------------- */

describe('healthReport: the checks with their problems and advice first', () => {
  test('the verdict, the problems first, then notes, passed checks and the records read; the selectors', () => {
    const { doc, html } = buildReport('health', healthInput, { ...words('en'), link: 'https://example.github.io/domainscope/#/health?domain=example.com' });
    assertInert(html);
    assert.ok(html.includes('<title>Domain Health report · example.com</title>'));
    const order = [...html.matchAll(/data-section="([a-z]+)"/g)].map((m) => m[1]);
    assert.equal(order[0], 'problems');
    assert.equal(order[order.length - 1], 'method');
    assert.ok(order.includes('records') && order.includes('passed'), order.join());
    const s = healthInput.report.summary;
    assert.equal(doc.verdict.light, s.error ? 'error' : s.warn ? 'warn' : 'ok');
    assert.equal(doc.verdict.score, Math.max(0, 100 - 20 * s.error - 6 * s.warn));
    assert.equal(doc.problems.length, s.error + s.warn);
    const rank = (p) => REPORT_SEVERITIES.indexOf(p.severity) * 10 + HEALTH_GROUPS.indexOf(healthInput.report.checks.find((c) => c.titleKey && i18n.t(c.titleKey) === p.title)?.group || 'dns');
    assert.ok(doc.problems.every((p, i, all) => i === 0 || rank(all[i - 1]) <= rank(p)), 'errors, then warnings, in group order');
    assert.ok(doc.problems.every((p) => p.detail && p.group), 'each with its advice and its group');
    const records = doc.sections.find((x) => x.id === 'records');
    assert.equal(records.rows.find((r) => r.label === 'SPF').value, `v=spf1 ${XSS} -all`);
    assert.ok(html.includes(`v=spf1 ${escapeHtml(XSS)} -all`), 'the record, escaped');
    assert.ok(html.includes('0 issue &quot;&quot;&gt;&lt;img src=x onerror=alert(2)&gt;&quot;'), 'the CAA record, escaped');
    assert.ok(html.includes('DKIM: the common selectors and the ones added to the check: mailgun, s1024.'));
    assert.ok(!html.includes(TOKEN), 'the TXT records are not listed, only SPF');
  });

  test('Turkish', () => {
    const { html } = buildReport('health', healthInput, words('tr'));
    assert.ok(html.startsWith('<!doctype html>\n<html lang="tr">'));
    for (const s of ['Alan adı sağlığı raporu · example.com', 'Sorunlar ve öneriler', 'Okunan kayıtlar', 'SPF sözdizimi hatası']) assert.ok(html.includes(s), s);
    assert.ok(!html.includes('Records read'));
  });

  test('accepted risks (lib/waivers.js): out of the problems and the counts, "N accepted risks excluded", and listed with their reason, owner and end date', () => {
    const accepted = healthInput.report.checks.find((c) => c.severity === 'error' || c.severity === 'warn');
    const waived = { applied: [{ id: accepted.id, reason: 'Moving in Q1 <b>', owner: 'Mail team', expires: '2026-12-31' }] };
    const { doc, html } = buildReport('health', { ...healthInput, waived }, words('en'));
    const s = healthInput.report.summary;
    const same = healthInput.report.checks.filter((c) => c.id === accepted.id && (c.severity === 'error' || c.severity === 'warn'));
    assert.equal(doc.problems.length, s.error + s.warn - same.length);
    const less = { error: same.filter((c) => c.severity === 'error').length, warn: same.filter((c) => c.severity === 'warn').length };
    assert.equal(doc.verdict.score, Math.max(0, 100 - 20 * (s.error - less.error) - 6 * (s.warn - less.warn)));
    assert.deepEqual(doc.verdict.counts.at(-1), { severity: 'info', text: same.length === 1 ? '1 accepted risk excluded' : `${same.length} accepted risks excluded` });
    const section = doc.sections.find((x) => x.id === 'accepted');
    assert.equal(section.items.length, same.length);
    assert.ok(section.items[0].detail.startsWith('Accepted until 2026-12-31 by Mail team: Moving in Q1 <b>'), section.items[0].detail);
    assert.ok(html.includes('Accepted until 2026-12-31 by Mail team: Moving in Q1 &lt;b&gt;'), 'escaped');
    assertInert(html);
    const tr = buildReport('health', { ...healthInput, waived }, words('tr')).html;
    assert.ok(tr.includes('kabul edilen risk hariç tutuldu') && tr.includes('2026-12-31 tarihine kadar Mail team tarafından kabul edildi'), 'Turkish');
    assert.ok(!buildReport('health', healthInput, words('en')).doc.sections.some((x) => x.id === 'accepted'), 'none without waivers');
  });

  test('a lookup that failed reads as one, not as "none"', () => {
    const report = { ...healthInput.report, failedLookups: ['mx', 'txt'] };
    const doc = healthReport({ report }, words('en'));
    const rows = doc.sections.find((x) => x.id === 'records').rows;
    for (const label of ['MX', 'SPF']) assert.equal(rows.find((r) => r.label === label).value, '⚠ n/a — the lookup failed', label);
  });

  test("lib/health's words for a failed lookup and for yes / no are put in the UI language", () => {
    assert.ok(SRC.includes(`const LOOKUP_FAILED = '${LOOKUP_FAILED_PARAM}';`), 'the same constant as lib/health.js');
    const check = { id: 'x.y', severity: 'warn', titleKey: 'crep.test.title', detailKey: 'crep.test.detail', params: { a: LOOKUP_FAILED_PARAM, b: 'yes' }, group: 'dns' };
    i18n.registerStrings('en', { 'crep.test.title': 'T', 'crep.test.detail': '{a} / {b}' });
    i18n.registerStrings('tr', { 'crep.test.title': 'T', 'crep.test.detail': '{a} / {b}' });
    const doc = healthReport({ report: { domain: 'example.com', checks: [check], summary: { ok: 0, info: 0, warn: 1, error: 0 } } }, words('tr'));
    assert.equal(doc.problems[0].detail, 'sorgu başarısız oldu / Evet');
  });
});

/* --- the permalink, the kinds, the texts -------------------------------------------- */

describe('the re-run link carries the inputs only', () => {
  test('the overview: its domain; Health: its domain and extra selectors — the permalink keys, never a result', () => {
    assert.deepEqual(reportLinkParams('domain', domainInput), { name: 'example.com' });
    assert.deepEqual(reportLinkParams('health', healthInput), { domain: 'example.com', selectors: 'mailgun,s1024' });
    assert.deepEqual(reportLinkParams('health', { report: healthInput.report }), { domain: 'example.com' });
    assert.deepEqual(reportLinkParams('nope', domainInput), {});
    for (const kind of REPORT_KINDS) {
      const p = reportLinkParams(kind, kind === 'domain' ? domainInput : healthInput);
      assert.deepEqual(permalinkParams(kind, p), p, kind);
      for (const k of Object.keys(p)) assert.ok(PERMALINK_PARAMS[kind].includes(k), `${kind}: ${k}`);
    }
  });

  test('the kinds and their file names', () => {
    assert.deepEqual([...REPORT_KINDS], ['domain', 'health']);
    assert.deepEqual(Object.keys(REPORT_FILE_BASES), [...REPORT_KINDS]);
    assert.throws(() => buildReport('zone', {}, words('en')), TypeError);
    assert.throws(() => domainReport(domainInput, {}), TypeError, 'opts.t is required');
  });

  test('the body alone (what the app prints) is the same tree as the file', () => {
    const opts = { ...words('en'), link: LINK };
    const doc = domainReport(domainInput, opts);
    const body = renderHtml(reportBody(doc, opts));
    assert.ok(reportHtml(doc, opts).includes(body));
    assert.ok(body.startsWith('<body class="crep crep-domain"><div class="crep-page">'));
  });
});

describe('texts', () => {
  test('no other view registers a key of the report (the DMARC & TLS reports view owns rpt.*)', () => {
    assert.deepEqual(taken, []);
    assert.ok(Object.keys(REPORT_I18N.en).every((k) => k.startsWith('crep.')));
    assert.doesNotMatch(REPORT_CSS, /\.rpt-/);
  });

  test('English and Turkish have the same keys and placeholders, none empty', () => {
    assert.deepEqual(Object.keys(REPORT_I18N.tr).sort(), Object.keys(REPORT_I18N.en).sort());
    const ph = (v) => [...JSON.stringify(v).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().filter((x, i, a) => a.indexOf(x) === i).join();
    for (const [k, v] of Object.entries(REPORT_I18N.en)) {
      assert.equal(ph(REPORT_I18N.tr[k]), ph(v), k);
      assert.ok(JSON.stringify(REPORT_I18N.tr[k]).length > 2, k);
    }
    assert.doesNotMatch(JSON.stringify(REPORT_I18N.tr), /'|\.\.\./, 'Turkish: ’ and …');
  });

  test('every key the builders ask for exists in both languages', () => {
    const literal = [...SRC.matchAll(/\bt\('((?:crep|dov|common)\.[A-Za-z0-9.?~+-]+)'/g)].map((m) => m[1]);
    const built = [
      ...REPORT_KINDS.map((k) => `crep.kind.${k}`), ...REPORT_SEVERITIES.map((s) => `crep.sev.${s}`), ...REPORT_SEVERITIES.map((s) => `crep.count.${s}`),
      ...['ok', 'warn', 'error'].flatMap((l) => [`crep.light.${l}`, `crep.light.${l}Body`]),
      ...PASSPORT_CARDS.map((c) => `dov.card.${c}`), ...['validated', 'signed', 'failing', 'unsigned'].map((s) => `dov.dns.dnssec.${s}`),
      ...['-', '~', '?', '+', 'none', 'many', 'invalid'].map((s) => `dov.mail.spf.${s}`), ...['reject', 'quarantine', 'none', 'many', 'invalid'].map((s) => `dov.mail.dmarc.${s}`),
      ...['gateway', 'forwarding', 'sending'].map((k) => `dov.mail.kind.${k}`)
    ];
    assert.ok(literal.length > 60, `found ${literal.length} literal keys`);
    for (const k of [...literal, ...built]) for (const lang of ['en', 'tr']) assert.ok(i18n.hasString(k, lang), `${k} [${lang}]`);
  });
});
