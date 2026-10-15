/**
 * ui/sct-panel.js — Certificate › Transparency: the Signed Certificate Timestamps a certificate
 * carries, the CT logs that issued them and whether Chrome's and Apple's CT policies look met.
 *
 * The logic is lib/sct.js; this module renders it. Loaded on the first open of the tab. Google's
 * CT log list is read once per page session, on that first open and only for a certificate that
 * carries SCTs (the same file for everyone: nothing about the certificate is sent); when it
 * cannot be read this site's own copy is used and the panel says so. A file holds only the
 * SCTs embedded in the certificate: those a server sends in the TLS handshake or a stapled OCSP
 * response are not in it, so a missing count is "cannot tell", never "fails".
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, DataTable, Spinner } from './components.js';
import { statusText } from './source-status.js';
import { t, registerStrings, formatDateTime, formatNumber } from '../i18n.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { errorKind } from '../lib/util.js';
import {
  CT_POLICIES, CT_REASONS, CT_VERDICTS, LOG_STATES, SCT_PROBLEMS, SCT_STATUSES,
  certificateScts, evaluateCtPolicies, indexLogs, loadCtLogList
} from '../lib/sct.js';

registerStrings('en', {
  'sct.intro': 'A public CA logs every certificate it issues in Certificate Transparency logs and embeds the logs\' receipts (SCTs) in the certificate. Browsers require them: Chrome and Apple refuse a certificate without enough receipts from the logs they trust.',
  'sct.loading': 'Reading the CT log list…',
  'sct.listLive': 'Log list: Google\'s, read now ({count} logs, dated {date}).',
  'sct.listBundled': 'Log list: this site\'s own copy, dated {date}; it may not know the newest logs.',
  'sct.listBundledWhy': 'Log list: this site\'s own copy, dated {date}; it may not know the newest logs. {why}',
  'sct.listNone': 'The CT log list could not be read, so the logs cannot be named and the policies cannot be checked.',
  'sct.none.title': 'No SCTs in this certificate',
  'sct.none.body': 'Nothing is embedded. A server can also send its SCTs in the TLS handshake or in a stapled OCSP response; a certificate file holds neither, so this does not mean the site fails the policies.',
  'sct.precert.title': 'A precertificate',
  'sct.precert.body': 'A precertificate is what a CA logs before it issues the real certificate; it carries no SCTs. Look at the certificate that was issued.',
  'sct.malformed.title': 'The SCT list could not be read',
  'sct.malformed.body': 'The extension is there but damaged ({problem}). What could be read is shown below.',
  'sct.problem.truncated': 'it ends early',
  'sct.problem.trailing-data': 'bytes follow the list',
  'sct.problem.empty': 'it is empty',
  'sct.problem.not-der': 'it is not a certificate',
  'sct.problem.unknown-version': 'an SCT of an unknown version',
  'sct.problem.bad-timestamp': 'a timestamp that is not a date',
  'sct.ca': 'A CA certificate is not logged with SCTs of its own; the check applies to the server certificate.',
  'sct.table': 'Embedded SCTs',
  'sct.col.log': 'Log',
  'sct.col.operator': 'Operator',
  'sct.col.time': 'Logged at',
  'sct.col.delivery': 'Delivery',
  'sct.col.standing': 'Counts?',
  'sct.delivery.embedded': 'Embedded in the certificate',
  'sct.unknownLog': 'Unknown log',
  'sct.logState': 'Log state: {state}',
  'sct.state.pending': 'pending',
  'sct.state.qualified': 'qualified',
  'sct.state.usable': 'usable',
  'sct.state.readonly': 'read-only',
  'sct.state.retired': 'retired',
  'sct.state.rejected': 'rejected',
  'sct.standing.current': 'Yes, the log is trusted',
  'sct.standing.retired': 'Yes, issued before the log retired',
  'sct.standing.after-retirement': 'No, issued after the log retired',
  'sct.standing.not-approved': 'No, the log is not approved',
  'sct.standing.unknown-log': 'Not in the list',
  'sct.standing.future': 'No, dated in the future',
  'sct.standing.unreadable': 'No, unreadable',
  'sct.standing.no-list': 'Cannot tell, no log list',
  'sct.policies': 'CT policies',
  'sct.policy.chrome': 'Chrome',
  'sct.policy.apple': 'Apple (Safari, iOS, macOS)',
  'sct.verdict.compliant': 'looks compliant',
  'sct.verdict.not-compliant': 'does not meet the policy',
  'sct.verdict.cannot-tell': 'cannot tell from the file',
  'sct.policy.counts': '{counted} of {required} needed SCTs count, from {operators} operator(s).',
  'sct.policy.over': 'The lifetime of {days} days is over what Apple accepts at all (398).',
  'sct.policy.approx': 'An approximation of the published policies from this file; the browsers\' own checks decide.',
  'sct.reason.no-scts': 'The certificate embeds no SCTs.',
  'sct.reason.precertificate': 'This is a precertificate, which carries no SCTs.',
  'sct.reason.malformed-list': 'The SCT list is damaged.',
  'sct.reason.no-log-list': 'No log list was available to check the logs against.',
  'sct.reason.too-few-logs': 'Too few distinct trusted logs signed it.',
  'sct.reason.one-operator': 'All its logs belong to one operator; two are needed.',
  'sct.reason.no-current-log': 'None of its SCTs is from a log that is trusted today.',
  'sct.reason.no-rfc6962-log': 'Apple wants at least one SCT from a classic (RFC 6962) log.',
  'sct.reason.lifetime-over-398': 'The certificate lives longer than 398 days.',
  'sct.reason.unknown-logs-bundled': 'Some logs are missing from this site\'s older copy of the list; the live list may know them.',
  'sct.lifetime': 'Lifetime {days} days, checked as of today.',
  'sct.expired': 'The certificate has expired; the check is still made as of today.'
});

registerStrings('tr', {
  'sct.intro': 'Herkese açık bir CA, verdiği her sertifikayı Certificate Transparency kayıtlarına (log) yazar ve kayıtların makbuzlarını (SCT) sertifikaya gömer. Tarayıcılar bunları ister: Chrome ve Apple, güvendikleri kayıtlardan yeterince makbuzu olmayan sertifikayı kabul etmez.',
  'sct.loading': 'CT kayıt listesi okunuyor…',
  'sct.listLive': 'Kayıt listesi: Google\'ınki, şimdi okundu ({count} kayıt, tarihi {date}).',
  'sct.listBundled': 'Kayıt listesi: bu sitedeki kopya, tarihi {date}; en yeni kayıtları bilmeyebilir.',
  'sct.listBundledWhy': 'Kayıt listesi: bu sitedeki kopya, tarihi {date}; en yeni kayıtları bilmeyebilir. {why}',
  'sct.listNone': 'CT kayıt listesi okunamadı; bu yüzden kayıtlar adlandırılamıyor ve politikalar kontrol edilemiyor.',
  'sct.none.title': 'Bu sertifikada SCT yok',
  'sct.none.body': 'Hiçbiri gömülü değil. Sunucu SCT\'lerini TLS el sıkışmasında ya da zımbalanmış bir OCSP yanıtında da gönderebilir; sertifika dosyası bunların hiçbirini taşımaz, yani bu sitenin politikalara uymadığı anlamına gelmez.',
  'sct.precert.title': 'Bir ön sertifika',
  'sct.precert.body': 'Ön sertifika, CA\'nın gerçek sertifikayı vermeden önce kayda geçirdiği belgedir; SCT taşımaz. Asıl verilen sertifikaya bakın.',
  'sct.malformed.title': 'SCT listesi okunamadı',
  'sct.malformed.body': 'Uzantı var ama bozuk ({problem}). Okunabilen kısım aşağıda.',
  'sct.problem.truncated': 'erken bitiyor',
  'sct.problem.trailing-data': 'listenin ardında fazladan bayt var',
  'sct.problem.empty': 'boş',
  'sct.problem.not-der': 'bir sertifika değil',
  'sct.problem.unknown-version': 'bilinmeyen sürümde bir SCT',
  'sct.problem.bad-timestamp': 'tarih olmayan bir zaman damgası',
  'sct.ca': 'Bir CA sertifikasının kendi SCT\'si olmaz; kontrol sunucu sertifikası içindir.',
  'sct.table': 'Gömülü SCT\'ler',
  'sct.col.log': 'Kayıt (log)',
  'sct.col.operator': 'İşletmeci',
  'sct.col.time': 'Kayda geçtiği an',
  'sct.col.delivery': 'Teslim',
  'sct.col.standing': 'Sayılır mı?',
  'sct.delivery.embedded': 'Sertifikaya gömülü',
  'sct.unknownLog': 'Bilinmeyen kayıt',
  'sct.logState': 'Kayıt durumu: {state}',
  'sct.state.pending': 'beklemede',
  'sct.state.qualified': 'onaylı',
  'sct.state.usable': 'kullanılabilir',
  'sct.state.readonly': 'salt okunur',
  'sct.state.retired': 'emekli',
  'sct.state.rejected': 'reddedilmiş',
  'sct.standing.current': 'Evet, kayda güveniliyor',
  'sct.standing.retired': 'Evet, kayıt emekli olmadan önce verilmiş',
  'sct.standing.after-retirement': 'Hayır, kayıt emekli olduktan sonra verilmiş',
  'sct.standing.not-approved': 'Hayır, kayıt onaylı değil',
  'sct.standing.unknown-log': 'Listede yok',
  'sct.standing.future': 'Hayır, tarihi gelecekte',
  'sct.standing.unreadable': 'Hayır, okunamıyor',
  'sct.standing.no-list': 'Söylenemez, kayıt listesi yok',
  'sct.policies': 'CT politikaları',
  'sct.policy.chrome': 'Chrome',
  'sct.policy.apple': 'Apple (Safari, iOS, macOS)',
  'sct.verdict.compliant': 'uygun görünüyor',
  'sct.verdict.not-compliant': 'politikayı karşılamıyor',
  'sct.verdict.cannot-tell': 'dosyadan söylenemiyor',
  'sct.policy.counts': '{required} SCT gerekiyor, {counted} tanesi sayılıyor ({operators} işletmeci).',
  'sct.policy.over': '{days} günlük ömür, Apple\'ın hiçbir koşulda kabul etmediği sınırın (398 gün) üstünde.',
  'sct.policy.approx': 'Yayımlanmış politikaların bu dosyadan yapılan bir yaklaşımıdır; son kararı tarayıcıların kendi kontrolü verir.',
  'sct.reason.no-scts': 'Sertifikada gömülü SCT yok.',
  'sct.reason.precertificate': 'Bu bir ön sertifika; SCT taşımaz.',
  'sct.reason.malformed-list': 'SCT listesi bozuk.',
  'sct.reason.no-log-list': 'Kayıtları karşılaştıracak bir kayıt listesi yoktu.',
  'sct.reason.too-few-logs': 'Güvenilen farklı kayıtlardan yeterince imza yok.',
  'sct.reason.one-operator': 'Kayıtların hepsi tek işletmecinin; iki işletmeci gerekir.',
  'sct.reason.no-current-log': 'SCT\'lerin hiçbiri bugün güvenilen bir kayıttan değil.',
  'sct.reason.no-rfc6962-log': 'Apple, klasik (RFC 6962) bir kayıttan en az bir SCT ister.',
  'sct.reason.lifetime-over-398': 'Sertifikanın ömrü 398 günden uzun.',
  'sct.reason.unknown-logs-bundled': 'Bazı kayıtlar bu sitedeki eski liste kopyasında yok; canlı liste bunları bilebilir.',
  'sct.lifetime': 'Ömür {days} gün, bugünün tarihine göre kontrol edildi.',
  'sct.expired': 'Sertifikanın süresi dolmuş; kontrol yine bugünün tarihine göre yapıldı.'
});

/** The log list: once per page session (the same file for everyone), kept for every certificate and re-mount. */
let listLoad = null;
/** Forget the kept list (tests). */
export function resetSctList() {
  listLoad = null;
}

/**
 * The keys this module builds from lib/sct.js codes (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...SCT_PROBLEMS.map((p) => `sct.problem.${p}`),
    ...LOG_STATES.map((s) => `sct.state.${s}`),
    ...SCT_STATUSES.map((s) => `sct.standing.${s}`),
    ...CT_POLICIES.map((p) => `sct.policy.${p}`),
    ...CT_VERDICTS.map((v) => `sct.verdict.${v}`),
    ...CT_REASONS.map((r) => `sct.reason.${r}`)
  ];
}

const verdictVariant = { compliant: 'ok', 'not-compliant': 'error', 'cannot-tell': 'info' };

/**
 * @param {{ cert: object, ctx?: { signal?: AbortSignal }, now?: () => number }} opts
 * @returns {HTMLElement}
 */
export function SctPanel({ cert, ctx = {}, now = Date.now }) {
  const root = h('div', { class: 'stack sct-panel', dataset: { role: 'sct-panel' } });
  const embedded = certificateScts(cert);
  const body = h('div', { class: 'stack' });
  root.append(h('p', { class: 'muted text-sm' }, t('sct.intro')), body);

  if (cert.isCA) {
    body.append(Alert({ variant: 'info', compact: true, message: t('sct.ca') }));
    return root;
  }
  if (embedded.status === 'precertificate') {
    body.append(Alert({ variant: 'info', compact: true, title: t('sct.precert.title'), message: t('sct.precert.body') }));
    return root;
  }
  if (embedded.status === 'none') {
    body.append(Alert({ variant: 'info', compact: true, title: t('sct.none.title'), message: t('sct.none.body') }));
    return root;
  }

  body.append(Spinner({ label: t('sct.loading'), showLabel: true }));
  if (!listLoad) {
    // Not the view's signal: the read is shared and outlives this tab's re-mount.
    listLoad = loadCtLogList({ live: typeof navigator === 'undefined' || navigator.onLine !== false, now }).catch((err) => {
      listLoad = null;
      throw err;
    });
  }
  listLoad.then((load) => {
    if (ctx.signal && ctx.signal.aborted) return;
    show(load);
  }, (err) => {
    if (errorKind(err) === 'abort') return;
    show({ source: 'none', list: null, failure: null });
  });

  function show(load) {
    clear(body);
    const logs = load.list ? indexLogs(load.list) : null;
    const at = now();
    const result = evaluateCtPolicies(cert, embedded, logs, { now: at, listSource: load.source });
    const date = load.list ? formatDateTime(load.list.timestamp, { utc: true }) : '';
    if (load.source === 'live') {
      body.append(h('p', { class: 'muted text-sm', dataset: { sctList: 'live' } }, t('sct.listLive', { count: formatNumber(logs.size), date })));
    } else if (load.source === 'bundled') {
      const why = load.failure ? statusText(sourceStatus(load.failure, { now: at })) : '';
      body.append(h('p', { class: 'muted text-sm', dataset: { sctList: 'bundled' } }, why ? t('sct.listBundledWhy', { date, why }) : t('sct.listBundled', { date })));
    } else {
      body.append(Alert({ variant: 'warn', compact: true, message: t('sct.listNone') }));
    }

    if (embedded.status === 'malformed') {
      body.append(Alert({
        variant: 'warn', compact: true, title: t('sct.malformed.title'),
        message: t('sct.malformed.body', { problem: t(`sct.problem.${embedded.error || 'truncated'}`) })
      }));
    }
    if (embedded.scts.length) {
      const rows = embedded.scts.map((sct, i) => ({ sct, standing: result.standings[i] }));
      body.append(DataTable({
        caption: t('sct.table'),
        rows,
        dense: true,
        rowKey: (r) => `${r.sct.index}`,
        columns: [
          {
            key: 'log', label: t('sct.col.log'), wrap: true, sortable: true,
            sortValue: (r) => (r.standing.log ? r.standing.log.name : t('sct.unknownLog')),
            exportValue: (r) => (r.standing.log ? r.standing.log.name : r.sct.logIdHex),
            render: (r) => h('div', null,
              r.standing.log ? r.standing.log.name : t('sct.unknownLog'),
              h('div', { class: 'muted text-sm mono' }, `${r.sct.logIdHex.slice(0, 16)}…`),
              r.standing.log ? h('div', { class: 'muted text-sm' }, t('sct.logState', { state: t(`sct.state.${r.standing.log.state}`) })) : null)
          },
          {
            key: 'operator', label: t('sct.col.operator'), wrap: true, sortable: true,
            sortValue: (r) => (r.standing.log ? r.standing.log.operator : ''),
            exportValue: (r) => (r.standing.log ? r.standing.log.operator : ''),
            render: (r) => (r.standing.log ? r.standing.log.operator : '—')
          },
          {
            key: 'time', label: t('sct.col.time'), sortable: true, sortValue: (r) => r.sct.timestamp,
            exportValue: (r) => new Date(r.sct.timestamp).toISOString(),
            render: (r) => formatDateTime(r.sct.timestamp, { utc: true, seconds: true })
          },
          { key: 'delivery', label: t('sct.col.delivery'), exportValue: () => 'embedded', render: () => t('sct.delivery.embedded') },
          {
            key: 'standing', label: t('sct.col.standing'), wrap: true, sortable: true,
            sortValue: (r) => r.standing.status, exportValue: (r) => r.standing.status,
            render: (r) => Badge(t(`sct.standing.${r.standing.status}`), {
              variant: r.standing.status === 'current' || r.standing.status === 'retired' ? 'ok' : (r.standing.status === 'no-list' ? 'neutral' : 'warn')
            })
          }
        ]
      }).el);
    }

    body.append(h('h3', { class: 'section-title' }, t('sct.policies')),
      ...['chrome', 'apple'].map((name) => policyAlert(name, result.policies[name], result)),
      h('p', { class: 'muted text-sm' }, `${t('sct.lifetime', { days: formatNumber(Math.round(result.lifetimeDays)) })}${result.expired ? ` ${t('sct.expired')}` : ''}`),
      h('p', { class: 'muted text-sm' }, t('sct.policy.approx')));
  }

  return root;
}

function policyAlert(name, p, result) {
  const lines = [];
  if (p.verdict !== 'compliant') for (const code of p.reasons) lines.push(h('li', null, t(`sct.reason.${code}`)));
  const detail = [];
  if (p.required && p.verdict !== 'cannot-tell') {
    detail.push(h('p', { class: 'text-sm' }, t('sct.policy.counts', { counted: p.counted, required: p.required, operators: p.operators })));
  }
  if (name === 'apple' && p.required === null) detail.push(h('p', { class: 'text-sm' }, t('sct.policy.over', { days: Math.round(result.lifetimeDays) })));
  return Alert({
    variant: verdictVariant[p.verdict] || 'info',
    title: `${t(`sct.policy.${name}`)}: ${t(`sct.verdict.${p.verdict}`)}`,
    children: [...detail, lines.length ? h('ul', null, ...lines) : null],
    compact: true
  });
}
