/**
 * ui/health-v2.js — Domain Health v2 (SPEC §5.78), loaded by views/health.js with its first
 * report:
 *
 * - {@link addWeb}: the Web step of a check (lib/healthweb.js: www and the bare domain, the HTTPS
 *   record), run after lib/health's checks, on the same DNS client;
 * - {@link ProblemsPanel}: problems first — the errors, then the warnings, by category with
 *   counts, each with "Show the fix" (the view's toggle, lib/fixes.js) or a line of advice
 *   (lib/healthadvice.js), under the score of every category (lib/healthscore.js); each with
 *   "Accept this risk…" (lib/waivers.js: the view opens ui/waivers.js's dialog), the accepted
 *   ones listed apart with their reason, owner and end date and a Remove, and the what-if
 *   planner: tick the problems to fix, see the score and grade they would give;
 * - {@link WebPanel}: the Web category: the HTTPS record, www against the bare domain, the HSTS
 *   preload list (a link: it has no CORS) and the HTTP security grade of Mozilla's HTTP
 *   Observatory. That one is ONE request on a click (lib/observatory.js), never on arrival; a
 *   failure is a status with Retry, never a grade; a new check or leaving the view aborts it.
 */

import { h } from './dom.js';
import { Badge, Button, Card, Disclosure, ExternalLink, Icon, KeyValueList, SeverityIcon, announce, checkbox, setButtonBusy } from './components.js';
import { registerStrings, t, formatNumber, formatDateTime, formatRelative } from '../i18n.js';
import { HEALTH_SCORE_GROUPS, SCORE_CAPS, problemsFirst, scoreHealth, whatIfHealth } from '../lib/healthscore.js';
import { WAIVERS_I18N, isWaivableCheck } from '../lib/waivers.js';
import { HEALTH_ADVICE_I18N, adviceKey } from '../lib/healthadvice.js';
import { HEALTH_WEB_I18N, addWebChecks, hstsPreloadUrl, withObservatory } from '../lib/healthweb.js';
import { OBSERVATORY_SKIP_REASONS, observatoryEligible, observatoryScan } from '../lib/observatory.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { NaMark, RetryButton, statusText } from './source-status.js';
import { mergeSignals } from '../lib/util.js';

registerStrings('en', HEALTH_WEB_I18N.en);
registerStrings('tr', HEALTH_WEB_I18N.tr);
registerStrings('en', HEALTH_ADVICE_I18N.en);
registerStrings('tr', HEALTH_ADVICE_I18N.tr);
registerStrings('en', WAIVERS_I18N.en);
registerStrings('tr', WAIVERS_I18N.tr);

registerStrings('en', {
  'hv2.problems.title': 'Problems first',
  'hv2.problems.none': 'No errors or warnings: nothing to fix.',
  'hv2.problems.error': { one: '{count} error', other: '{count} errors' },
  'hv2.problems.warn': { one: '{count} warning', other: '{count} warnings' },
  'hv2.problems.groupCount': '{group} · {count}',
  'hv2.advice': 'What to do',
  'hv2.scoreHow': 'Each category starts at 100 and loses 40 per error and 15 per warning; the score is their weighted mean (DNS 30, Email 25, Certificates & DNSSEC 20, Web 15, Registration 10). An error caps it at {error}, a warning at {warn}; a name that does not exist scores 0. A from 90, B from 80, C from 70, D from 60, E from 50, F below.',
  'hv2.cap.fatal': 'The name does not exist: the score is 0.',
  'hv2.cap.error': 'An error caps the score at {cap} (the categories alone would give {raw}).',
  'hv2.cap.warn': 'A warning caps the score at {cap} (the categories alone would give {raw}).',
  'hv2.web.title': 'Web',
  'hv2.web.https': 'HTTPS record',
  'hv2.web.httpsNone': 'None (optional)',
  'hv2.web.httpsFailed': 'Lookup failed',
  'hv2.web.ech': 'ECH',
  'hv2.web.www': 'www',
  'hv2.web.apex': 'Bare domain',
  'hv2.web.none': 'No address',
  'hv2.web.wwwFailed': 'Lookup failed: {error}',
  'hv2.web.wwwSkipped.not-apex': 'Not compared: {domain} is not a zone apex.',
  'hv2.web.wwwSkipped.is-www': 'Not compared: {domain} is itself a www name.',
  'hv2.web.wwwSkipped.no-domain': 'Not compared: the name does not exist.',
  'hv2.web.wwwNotRun': 'Not compared (the Web step did not run).',
  'hv2.web.hsts': 'HSTS preload list',
  'hv2.web.hstsBody': 'Whether browsers ship {domain} as HTTPS-only. The list cannot be read from this page (it sends no CORS headers), so the link opens its status page; nothing is sent from here.',
  'hv2.web.hstsLink': 'Look up on hstspreload.org',
  'hv2.obs.title': 'HTTP security grade (Mozilla HTTP Observatory)',
  'hv2.obs.what': 'Mozilla’s HTTP Observatory loads the site from its own servers and grades the security headers it sends: Content-Security-Policy, Strict-Transport-Security, cookies, framing (X-Frame-Options), X-Content-Type-Options, Referrer-Policy, the redirect to HTTPS, Subresource Integrity and cross-origin access. It does not grade the certificate or DNS.',
  'hv2.obs.notSent': 'Nothing has been sent yet. “{button}” sends the host name {host} to Mozilla (one request).',
  'hv2.obs.check': 'Check HTTP security',
  'hv2.obs.again': 'Check again',
  'hv2.obs.running': 'Mozilla is scanning {host}…',
  'hv2.obs.result': '{score}/100 · {failed} of {total} tests failed',
  'hv2.obs.scanned': 'Scanned {time}',
  'hv2.obs.report': 'The failing tests, one by one (MDN)',
  'hv2.obs.cached': 'Mozilla answers a scan of the last few minutes from its cache.',
  'hv2.obs.done': 'HTTP security grade of {host}: {grade}',
  'hv2.obs.failed': 'The HTTP security check of {host} failed',
  'hv2.obs.skip.invalid': 'Not sent: {host} is not a host name.',
  'hv2.obs.skip.internal-name': 'Not sent: {host} is an internal name, which never leaves this page.',
  'hv2.obs.skip.no-address': 'Not sent: {host} has no address, so there is no site to scan.',
  'hv2.obs.skip.private-address': 'Not sent: {host} has only private or reserved addresses, which never leave this page.'
});

registerStrings('tr', {
  'hv2.problems.title': 'Önce sorunlar',
  'hv2.problems.none': 'Hata ya da uyarı yok: düzeltilecek bir şey yok.',
  'hv2.problems.error': { one: '{count} hata', other: '{count} hata' },
  'hv2.problems.warn': { one: '{count} uyarı', other: '{count} uyarı' },
  'hv2.problems.groupCount': '{group} · {count}',
  'hv2.advice': 'Ne yapmalı',
  'hv2.scoreHow': 'Her kategori 100 puanla başlar; hata başına 40, uyarı başına 15 puan kaybeder. Puan, kategorilerin ağırlıklı ortalamasıdır (DNS 30, E-posta 25, Sertifika ve DNSSEC 20, Web 15, Alan adı kaydı 10). Bir hata puanı en fazla {error}, bir uyarı en fazla {warn} yapar; var olmayan bir ad 0 alır. 90 ve üstü A, 80 B, 70 C, 60 D, 50 E, altı F.',
  'hv2.cap.fatal': 'Ad mevcut değil: puan 0.',
  'hv2.cap.error': 'Bir hata puanı en fazla {cap} yapar (kategoriler tek başına {raw} verirdi).',
  'hv2.cap.warn': 'Bir uyarı puanı en fazla {cap} yapar (kategoriler tek başına {raw} verirdi).',
  'hv2.web.title': 'Web',
  'hv2.web.https': 'HTTPS kaydı',
  'hv2.web.httpsNone': 'Yok (isteğe bağlı)',
  'hv2.web.httpsFailed': 'Sorgulanamadı',
  'hv2.web.ech': 'ECH',
  'hv2.web.www': 'www',
  'hv2.web.apex': 'Çıplak alan adı',
  'hv2.web.none': 'Adres yok',
  'hv2.web.wwwFailed': 'Sorgulanamadı: {error}',
  'hv2.web.wwwSkipped.not-apex': 'Karşılaştırılmadı: {domain} bir zone tepesi (apex) değil.',
  'hv2.web.wwwSkipped.is-www': 'Karşılaştırılmadı: {domain} zaten bir www adı.',
  'hv2.web.wwwSkipped.no-domain': 'Karşılaştırılmadı: ad mevcut değil.',
  'hv2.web.wwwNotRun': 'Karşılaştırılmadı (Web adımı çalışmadı).',
  'hv2.web.hsts': 'HSTS ön yükleme listesi',
  'hv2.web.hstsBody': 'Tarayıcıların {domain} adını yalnızca HTTPS olarak tanıyıp tanımadığı. Liste bu sayfadan okunamaz (CORS başlığı göndermez); bağlantı listenin durum sayfasını açar, buradan hiçbir şey gönderilmez.',
  'hv2.web.hstsLink': 'hstspreload.org’da bak',
  'hv2.obs.title': 'HTTP güvenlik notu (Mozilla HTTP Observatory)',
  'hv2.obs.what': 'Mozilla HTTP Observatory siteyi kendi sunucularından açar ve gönderdiği güvenlik başlıklarını notlar: Content-Security-Policy, Strict-Transport-Security, çerezler, çerçeveleme (X-Frame-Options), X-Content-Type-Options, Referrer-Policy, HTTPS’e yönlendirme, Subresource Integrity ve kaynaklar arası erişim. Sertifikayı ya da DNS’i notlamaz.',
  'hv2.obs.notSent': 'Henüz hiçbir şey gönderilmedi. “{button}” düğmesi {host} host adını Mozilla’ya gönderir (tek istek).',
  'hv2.obs.check': 'HTTP güvenliğini kontrol et',
  'hv2.obs.again': 'Yeniden kontrol et',
  'hv2.obs.running': 'Mozilla {host} adresini tarıyor…',
  'hv2.obs.result': '{score}/100 · {total} testten {failed} tanesi başarısız',
  'hv2.obs.scanned': 'Tarama: {time}',
  'hv2.obs.report': 'Başarısız testler tek tek (MDN)',
  'hv2.obs.cached': 'Mozilla son birkaç dakikanın taramasını önbelleğinden yanıtlar.',
  'hv2.obs.done': '{host} için HTTP güvenlik notu: {grade}',
  'hv2.obs.failed': '{host} için HTTP güvenlik kontrolü başarısız oldu',
  'hv2.obs.skip.invalid': 'Gönderilmedi: {host} bir host adı değil.',
  'hv2.obs.skip.internal-name': 'Gönderilmedi: {host} bir iç ad; iç adlar bu sayfadan çıkmaz.',
  'hv2.obs.skip.no-address': 'Gönderilmedi: {host} adının adresi yok, taranacak bir site yok.',
  'hv2.obs.skip.private-address': 'Gönderilmedi: {host} adının yalnızca özel ya da ayrılmış adresleri var; bunlar bu sayfadan çıkmaz.'
});

/**
 * Every i18n key this module builds from a code (for the coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...['not-apex', 'is-www', 'no-domain'].map((r) => `hv2.web.wwwSkipped.${r}`),
    ...OBSERVATORY_SKIP_REASONS.map((r) => `hv2.obs.skip.${r}`),
    ...['fatal', 'error', 'warn'].map((c) => `hv2.cap.${c}`),
    ...['error', 'warn'].map((s) => `hv2.problems.${s}`),
    ...HEALTH_SCORE_GROUPS.map((g) => `health.group.${g}`)
  ];
}

/**
 * The Web step of a check: www against the bare domain and the HTTPS record, merged into the
 * report (lib/healthweb.js addWebChecks).
 * @param {object} report
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<object>}
 */
export function addWeb(report, opts) {
  return addWebChecks(report, opts);
}

const groupName = (g) => t(`health.group.${g}`);

/**
 * Why the total is what it is: the cap an error or a warning puts on it, and how the score is
 * made (the accepted risks left out). The score of every category is the result header's metric
 * strip (views/health.js, docs/DESIGN.md §5.6).
 * @param {object} report
 * @param {{ waived?: Set<string>|null }} [opts] the check ids accepted as risks
 * @returns {HTMLElement}
 */
export function ScoreBreakdown(report, { waived = null } = {}) {
  const graded = scoreHealth(report.checks, { waived });
  const cap = graded.cap ? t(`hv2.cap.${graded.cap}`, { cap: graded.score, raw: Math.round(graded.raw) }) : null;
  return h('div', { class: 'hv2-breakdown', dataset: { grade: graded.grade, score: graded.score } },
    cap ? h('p', { class: 'muted text-xs hv2-cap', dataset: { cap: graded.cap } }, cap) : null,
    h('p', { class: 'muted text-xs hv2-how' }, t('hv2.scoreHow', { error: SCORE_CAPS.error, warn: SCORE_CAPS.warn })));
}

/**
 * The accepted risks of a report as the view hands them over (lib/waivers.js healthWaivers).
 * @typedef {{ ids: Set<string>, byId: Map<string, object>, expired: Array<{ check: object, waiver: object }> }} ReportWaivers
 */

/** The errors and warnings of a report a waiver can accept, one per check id, in report order. */
function waivableChecks(report, keep) {
  const seen = new Set();
  return (report.checks || []).filter((c) => {
    if (!isWaivableCheck(c) || !keep(c) || seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });
}

/**
 * The what-if planner: tick the open problems one plans to fix, read the score and grade they
 * would give by the same formula (lib/healthscore.js whatIfHealth). Nothing is saved.
 * @param {object} report
 * @param {Set<string>} waived the accepted risks (already left out)
 * @param {(c: object) => string} checkTitle
 * @returns {HTMLElement|null}
 */
export function WhatIfPanel(report, waived, checkTitle) {
  const open = waivableChecks(report, (c) => !waived.has(c.id));
  if (!open.length) return null;
  const ticked = new Set();
  const out = h('p', { class: 'hv2-whatif-out text-sm', dataset: { role: 'whatif-result' }, attrs: { 'aria-live': 'polite' } }, t('wvr.whatIfNone'));
  const update = () => {
    if (!ticked.size) {
      out.textContent = t('wvr.whatIfNone');
      delete out.dataset.score;
      delete out.dataset.grade;
      return;
    }
    const r = whatIfHealth(report.checks, ticked, { waived });
    out.textContent = t('wvr.whatIfResult', { count: ticked.size, from: r.now.score, fromGrade: r.now.grade, to: r.then.score, toGrade: r.then.grade });
    out.dataset.score = String(r.then.score);
    out.dataset.grade = r.then.grade;
  };
  const boxes = open.map((c) => {
    const box = checkbox({
      label: h('span', { class: 'hv2-whatif-label' }, SeverityIcon(c.severity, { size: 14 }), ' ', checkTitle(c)),
      value: c.id,
      className: 'hv2-whatif-item',
      onChange: (on) => {
        if (on) ticked.add(c.id);
        else ticked.delete(c.id);
        update();
      }
    });
    box.el.dataset.check = c.id;
    return box.el;
  });
  return Disclosure({
    summary: t('wvr.whatIf'),
    className: 'hv2-whatif',
    children: h('div', { class: 'stack-sm' }, h('p', { class: 'muted text-xs' }, t('wvr.whatIfHint')), h('div', { class: 'stack-xs hv2-whatif-list' }, boxes), out)
  });
}

/**
 * Problems first: the errors, then the warnings, by category with counts. Each problem has
 * "Show the fix" when lib/fixes.js has one, else a line of advice, and "Accept this risk…" (a
 * problem whose waiver is over says so: it counts again). The accepted risks are listed apart,
 * each with its reason, owner and end date and a Remove; the what-if planner closes the card.
 * @param {object} report
 * @param {{ checkTitle: Function, checkDetail: Function, fixToggle: Function, fixable: (c: object) => boolean,
 *   waivers?: ReportWaivers|null, onAccept?: ((check: object, expired: object|null) => void)|null,
 *   onRemove?: ((waiver: object, check: object) => void)|null }} hooks
 * @returns {HTMLElement}
 */
export function ProblemsPanel(report, { checkTitle, checkDetail, fixToggle, fixable, waivers = null, onAccept = null, onRemove = null }) {
  const ids = waivers ? waivers.ids : new Set();
  const expiredById = new Map((waivers ? waivers.expired : []).map((e) => [e.check.id, e.waiver]));
  const { total, sections } = problemsFirst(report.checks, { waived: ids });
  const acceptPart = (c) => {
    if (!onAccept || !isWaivableCheck(c)) return null;
    const gone = expiredById.get(c.id) || null;
    return h('div', { class: 'hv2-accept' },
      gone ? h('p', { class: 'hv2-waiver-expired text-xs', dataset: { role: 'waiver-expired' } }, Icon('clock', { size: 13 }), ' ', t('wvr.expiredLine', { date: gone.expires })) : null,
      Button({
        label: t(gone ? 'wvr.acceptAgain' : 'wvr.accept'), icon: 'shield', size: 'sm', variant: 'ghost', className: 'hv2-accept-btn',
        dataset: { action: 'hv2-accept', check: c.id }, onClick: () => onAccept(c, gone)
      }));
  };
  const accepted = waivableChecks(report, (c) => ids.has(c.id));
  const body = !total
    ? h('p', { class: 'hv2-none text-sm' }, Icon('check-circle', { size: 16 }), ' ', t(accepted.length ? 'wvr.noneOpen' : 'hv2.problems.none'))
    : h('div', { class: 'stack hv2-sections' }, sections.map((s) => h('section', { class: ['hv2-section', `hv2-section-${s.severity}`], dataset: { severity: s.severity, count: s.count } },
      h('h3', { class: 'hv2-section-title' }, SeverityIcon(s.severity, { size: 16 }), ' ', t(`hv2.problems.${s.severity}`, { count: s.count })),
      s.groups.map((g) => h('div', { class: 'hv2-group', dataset: { group: g.group, count: g.checks.length } },
        h('h4', { class: 'hv2-group-title muted text-xs' }, t('hv2.problems.groupCount', { group: groupName(g.group), count: formatNumber(g.checks.length) })),
        h('ul', { class: 'hv2-list' }, g.checks.map((c) => {
          const key = adviceKey(c.id);
          const fix = fixable(c) ? fixToggle(c, report) : null;
          return h('li', { class: ['hv2-problem', `hlt-sev-${c.severity}`], dataset: { id: c.id, severity: c.severity, advice: fix ? 'fix' : key ? 'text' : 'none' } },
            h('span', { class: 'hv2-problem-icon' }, SeverityIcon(c.severity, { size: 16 })),
            h('div', { class: 'hv2-problem-body' },
              h('div', { class: 'hv2-problem-title' }, checkTitle(c)),
              h('div', { class: 'hv2-problem-detail muted text-sm' }, checkDetail(c)),
              key && !fix ? h('p', { class: 'hv2-advice text-sm' }, Icon('lightbulb', { size: 14 }), ' ', h('span', { class: 'hv2-advice-label' }, `${t('hv2.advice')}: `), t(key)) : null,
              fix,
              acceptPart(c)));
        })))))));
  const acceptedEl = accepted.length ? h('section', { class: 'hv2-section hv2-section-accepted', dataset: { severity: 'accepted', count: accepted.length } },
    h('h3', { class: 'hv2-section-title' }, Icon('shield', { size: 16 }), ' ', t('wvr.section', { count: accepted.length })),
    h('ul', { class: 'hv2-list' }, accepted.map((c) => {
      const w = waivers.byId.get(c.id);
      const title = checkTitle(c);
      return h('li', { class: ['hv2-problem', 'hv2-accepted'], dataset: { id: c.id, severity: c.severity, waiver: w.id } },
        h('span', { class: 'hv2-problem-icon' }, SeverityIcon(c.severity, { size: 16 })),
        h('div', { class: 'hv2-problem-body' },
          h('div', { class: 'hv2-problem-title' }, title),
          h('p', { class: 'hv2-waiver text-sm', dataset: { role: 'waiver-line' } }, Icon('shield', { size: 14 }), ' ',
            t(w.owner ? 'wvr.lineOwner' : 'wvr.line', { date: w.expires, owner: w.owner, reason: w.reason })),
          onRemove ? h('div', { class: 'hv2-accept' }, Button({
            label: t('wvr.remove'), icon: 'x', size: 'sm', variant: 'ghost', title: t('wvr.removeTitle', { subject: String(title) }),
            dataset: { action: 'hv2-waiver-remove', check: c.id }, onClick: () => onRemove(w, c)
          })) : null));
    }))) : null;
  const counts = sections.map((s) => Badge(t(`hv2.problems.${s.severity}`, { count: s.count }), { variant: s.severity }));
  if (accepted.length) counts.push(Badge(t('wvr.section', { count: accepted.length }), { variant: 'neutral', icon: 'shield' }));
  return Card({
    title: t('hv2.problems.title'), icon: 'alert', className: 'hlt-card hv2-problems',
    actions: sections.length || accepted.length ? h('div', { class: 'cluster' }, counts) : Badge(t('severity.ok'), { variant: 'ok', icon: 'check' }),
    children: h('div', { class: 'stack' }, ScoreBreakdown(report, { waived: ids }), body, acceptedEl, WhatIfPanel(report, ids, checkTitle))
  });
}

/** The addresses (or CNAME) a name answered, or "No address". */
function addressValue(ips, cnames) {
  const parts = [];
  if (cnames && cnames.length) parts.push(h('span', { class: 'mono text-sm' }, `CNAME → ${cnames.join(' → ')}`));
  if (ips.length) parts.push(h('span', { class: 'cluster hv2-ips' }, ips.map((ip) => h('span', { class: 'mono text-sm' }, ip))));
  return parts.length ? h('div', { class: 'stack-xs' }, parts) : h('span', { class: 'muted text-sm' }, t('hv2.web.none'));
}

/**
 * The Web category: the HTTPS record, www against the bare domain, the HSTS preload list (a
 * link) and the Observatory's HTTP security grade (one request per click).
 * @param {object} report
 * @param {{ ctx: object, state: object, onReport: (report: object) => void }} opts `state` is the
 *   view's check (its `observatory` run lives there, so a new check can abort it); `onReport`
 *   takes the report with the grade
 * @returns {HTMLElement}
 */
export function WebPanel(report, { ctx, state, onReport }) {
  const domain = report.domain;
  const rec = report.records || {};
  const web = report.web || {};
  const failed = (report.failedLookups || []).includes('https');
  const https = rec.https || [];
  const alpn = [...new Set(https.flatMap((x) => (x.params && x.params.alpn) || []))];
  const ech = https.some((x) => x.params && x.params.ech);
  const httpsValue = failed ? h('span', { class: 'hv2-failed text-sm' }, Icon('alert', { size: 14 }), ' ', t('hv2.web.httpsFailed'))
    : https.length ? h('span', { class: 'cluster' }, [...alpn.map((a) => Badge(a, { mono: true })), ech ? Badge(t('hv2.web.ech'), { variant: 'ok' }) : null].filter(Boolean))
      : h('span', { class: 'muted text-sm' }, t('hv2.web.httpsNone'));
  const www = web.www || null;
  let wwwValue;
  if (!www) wwwValue = h('span', { class: 'muted text-sm' }, t('hv2.web.wwwNotRun'));
  else if (www.skipped) wwwValue = h('span', { class: 'muted text-sm' }, t(`hv2.web.wwwSkipped.${www.skipped}`, { domain }));
  else if (www.error) wwwValue = h('span', { class: 'hv2-failed text-sm' }, Icon('alert', { size: 14 }), ' ', t('hv2.web.wwwFailed', { error: www.error }));
  else wwwValue = addressValue([...www.ipv4, ...www.ipv6], www.cnames);
  const rows = [
    { key: t('hv2.web.https'), value: httpsValue },
    { key: www && www.name ? www.name : t('hv2.web.www'), value: wwwValue },
    { key: t('hv2.web.apex'), value: addressValue([...(rec.a || []), ...(rec.aaaa || [])], []) }
  ];
  const hsts = h('div', { class: 'hv2-hsts stack-xs', dataset: { hsts: 'link' } },
    h('h3', { class: 'hv2-sub' }, t('hv2.web.hsts')),
    h('p', { class: 'muted text-sm' }, t('hv2.web.hstsBody', { domain })),
    ExternalLink(hstsPreloadUrl(domain), t('hv2.web.hstsLink'), { className: 'hv2-hsts-link text-sm' }));
  return Card({
    title: t('hv2.web.title'), icon: 'lock', className: 'hlt-card hv2-web',
    children: h('div', { class: 'stack' },
      KeyValueList(rows, { className: 'hlt-kv hv2-kv' }),
      hsts,
      ObservatoryBlock(report, { ctx, state, onReport }))
  });
}

/** The Observatory part of the Web card: what it measures, the button, the grade or the status. */
function ObservatoryBlock(report, { ctx, state, onReport }) {
  const domain = report.domain;
  const rec = report.records || {};
  const addresses = [...(rec.a || []), ...(rec.aaaa || [])];
  const allowed = observatoryEligible(domain, { addresses });
  const result = report.web && report.web.observatory && report.web.observatory.host === domain ? report.web.observatory : null;
  const running = state && state.observatory && state.observatory.host === domain && state.observatory.controller ? state.observatory : null;
  const host = h('div', { class: 'hv2-obs stack-sm', dataset: { obs: running ? 'running' : result ? (result.ok ? 'done' : 'failed') : allowed.ok ? 'idle' : 'skipped' } });
  host.append(h('h3', { class: 'hv2-sub' }, t('hv2.obs.title')), h('p', { class: 'muted text-sm hv2-obs-what' }, t('hv2.obs.what')));
  if (!allowed.ok) {
    host.append(h('p', { class: 'text-sm hv2-obs-skip', dataset: { reason: allowed.reason } }, Icon('lock', { size: 14 }), ' ', t(`hv2.obs.skip.${allowed.reason}`, { host: domain })));
    return host;
  }
  const label = result ? t('hv2.obs.again') : t('hv2.obs.check');
  const btn = Button({
    label, icon: result ? 'refresh' : 'shield', size: 'sm', variant: result ? 'secondary' : 'primary',
    dataset: { action: 'observatory-check' }, onClick: () => run()
  });
  if (running) setButtonBusy(btn, true);
  async function run() {
    if (state && state.observatory && state.observatory.controller) return;
    if (!ctx.requireOnline()) return;
    const controller = new AbortController();
    if (state) state.observatory = { host: domain, controller };
    setButtonBusy(btn, true);
    announce(t('hv2.obs.running', { host: domain }));
    let res;
    try {
      res = await observatoryScan(domain, { addresses, signal: mergeSignals(ctx.signal, controller.signal) });
    } catch {
      // Aborted (only an abort rejects): a new check or leaving the view; nothing to show.
      if (state && state.observatory && state.observatory.controller === controller) state.observatory = null;
      if (btn.isConnected) setButtonBusy(btn, false);
      return;
    }
    if (!state || !state.observatory || state.observatory.controller !== controller) return;
    state.observatory = null;
    announce(res.ok ? t('hv2.obs.done', { host: domain, grade: res.grade }) : t('hv2.obs.failed', { host: domain }));
    onReport(withObservatory(report, res));
  }
  if (running) {
    host.append(h('p', { class: 'text-sm hv2-obs-running', attrs: { role: 'status' } }, t('hv2.obs.running', { host: domain })), h('div', { class: 'cluster' }, btn));
    return host;
  }
  if (!result) {
    host.append(h('p', { class: 'muted text-sm hv2-obs-notsent' }, t('hv2.obs.notSent', { button: t('hv2.obs.check'), host: domain })), h('div', { class: 'cluster' }, btn));
    return host;
  }
  if (result.ok) {
    const sev = { A: 'ok', B: 'info', C: 'info' }[result.grade[0]] || 'warn';
    const fmt = (v) => (Number.isFinite(v) ? formatNumber(v) : '?');
    host.append(
      h('div', { class: 'cluster hv2-obs-result', dataset: { grade: result.grade } },
        h('span', { class: ['hv2-grade', `hv2-grade-${sev}`], attrs: { 'aria-label': result.grade } }, result.grade),
        h('span', { class: 'text-sm' }, t('hv2.obs.result', { score: fmt(result.score), failed: fmt(result.testsFailed), total: fmt(result.testsQuantity) })),
        result.scannedAt ? h('span', { class: 'muted text-xs', title: formatDateTime(new Date(result.scannedAt)) }, t('hv2.obs.scanned', { time: formatRelative(new Date(result.scannedAt)) })) : null),
      h('div', { class: 'cluster' }, ExternalLink(result.reportUrl, t('hv2.obs.report'), { className: 'hv2-obs-report text-sm' }), btn),
      h('p', { class: 'muted text-xs' }, t('hv2.obs.cached')));
    return host;
  }
  const status = sourceStatus({ source: 'observatory', error: result.error, errorKind: result.errorKind, status: result.httpStatus, retryAfterMs: result.retryAfterMs, at: result.at });
  const retry = RetryButton({ sources: ['observatory'], onClick: () => run() });
  retry.dataset.action = 'observatory-check';
  host.append(h('p', { class: 'text-sm hv2-obs-status', dataset: { reason: status.reason } }, NaMark([status]), ' ', h('span', null, statusText(status))), h('div', { class: 'cluster' }, retry));
  return host;
}
