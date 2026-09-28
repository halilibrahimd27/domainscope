/**
 * views/renew.js — "Renewal readiness": will the next ACME renewal of these names validate?
 *
 * The names come from the box (one per line, `*.` for a wildcard) or from a certificate — a file,
 * the public certificate of a host name from Certificate Transparency or the sample (the
 * Certificate view's loaders; the loaded certificate is shared with Certificate and SSL Targets
 * for the page session) — which also sets the CA from its issuer. With the CA and the ACME
 * challenge chosen, "Check readiness" runs lib/renewal.js checkRenewal over DNS-over-HTTPS only:
 * CAA (+ RFC 8657) against the CA and challenge, the same CAA lookup on four public resolvers,
 * `_acme-challenge`, DNSSEC, the DNS provider's DNS-01 plugin and the HTTP-01 / TLS-ALPN-01
 * prerequisites. Each name gets a verdict (ready / ready with warnings / will fail) with its
 * findings grouped by area; the summary has Copy summary, CSV and JSON.
 *
 * HTTP-01 reachability: "Test …" sends, only after that click, a plain-HTTP GET of a made-up
 * token under /.well-known/acme-challenge/ from one Globalping probe on each of three continents
 * (per address family) through ui/globalping-gate.js (its own consent, the quota shared with the
 * other Globalping features). A measurement already paid for that could not be read yet (the view
 * was left, Stop, an error) is read again for free; a family whose measurement was never created
 * reads "not tested".
 *
 * Shareable: `#/renew?names=example.com,*.example.com&ca=letsencrypt&challenge=dns-01` runs on
 * open; with `run=0` (Certificate, SSL Targets, a carried target) it only fills the form. The
 * finished report is kept for the page session (`result()` / `snapshot()`).
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, Disclosure, EmptyState, ErrorBanner, ExternalLink, Icon, KeyValueList, ProgressBar,
  SeverityIcon, Spinner, TruncatedList, announce, describeError, select, textarea
} from '../ui/components.js';
import { registerStrings, formatNumber, formatRelative, formatDateTime, formatDuration } from '../i18n.js';
import {
  RENEWAL_I18N, RENEWAL_CHALLENGES, RENEWAL_CAS, RENEWAL_LIMITS, RENEWAL_AREAS, RENEWAL_VERDICTS, RENEWAL_CSV_COLUMNS,
  HTTP01_PATH_PREFIX, HTTP01_LOCATIONS, parseRenewalNames, renewalCa, caForIssuer, checkRenewal,
  http01Plan, http01Request, http01Token, interpretHttp01, http01Families, applyHttp01, renewalSummary, renewalRows, renewalExport
} from '../lib/renewal.js';
import { GP_LIMITS } from '../lib/globalping.js';
import { getResolver } from '../lib/resolvers.js';
import { toCsv, toJson } from '../lib/export.js';
import { permalinkParams } from '../lib/summary.js';
import { errorKind, mergeSignals } from '../lib/util.js';
import { fillReplaces, isFillOnly, commonTarget } from '../lib/session.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from '../ui/globalping-gate.js';
import { SummaryButton } from '../ui/summary-button.js';
import { CertLoader, CertAlternatives, CertSummary, CertSourceNote, certWarningAlerts, getCurrentCert, setCurrentCert } from './cert.js';

/** Route id (`#/renew`). */
export const id = 'renew';
/** i18n key of the page title. */
export const titleKey = 'nav.renew';
/** Icon name (ui/components.js Icon). */
export const icon = 'refresh';

/** The Globalping consent purpose of the HTTP-01 test (ui/globalping-gate.js). */
export const HTTP01_PURPOSE = 'renew-http01';

// Finding, outcome, verdict, headline, challenge and area texts ship with lib/renewal.js.
registerStrings('en', RENEWAL_I18N.en);
registerStrings('tr', RENEWAL_I18N.tr);

registerStrings('en', {
  'rnw.names': 'Names to renew',
  'rnw.namesHint': 'One per line, or separated by spaces or commas; *.example.com for a wildcard. Up to {max} names.',
  'rnw.invalid': { one: 'Not a host name, left out: {list}', other: 'Not host names, left out: {list}' },
  'rnw.overCap': 'Only the first {max} names are checked; {count} more are left out.',
  'rnw.noNames': 'Enter at least one host name, or take the names from a certificate.',
  'rnw.fromCert': 'Take the names from a certificate',
  'rnw.certUse': 'Use its names',
  'rnw.certRemove': 'Remove',
  'rnw.certAnother': 'Load another certificate',
  'rnw.certNoNames': 'This certificate names no host, so there is nothing to renew here.',
  'rnw.ca': 'Certificate authority',
  'rnw.caUnknown': 'Not known',
  'rnw.caHint': 'Checked against the CAA records. A certificate you load sets it from its issuer.',
  'rnw.caDetected': 'Set from the certificate’s issuer ({issuer}).',
  'rnw.caNotDetected': 'The certificate’s issuer ({issuer}) is not in the list: choose the CA that renews it.',
  'rnw.challenge': 'ACME challenge',
  'rnw.challengeHint': 'How your ACME client proves control of the names. Not sure: every method is checked, and what would stop one reads as a warning.',
  'rnw.run': 'Check readiness',
  'rnw.privacy': 'Only DNS queries — names and record types — go to public DNS-over-HTTPS resolvers, four of them for the CAA comparison. Your servers are not contacted; the HTTP-01 test is optional and asks first.',
  'rnw.progress': 'Checking {done} of {total} names…',
  'rnw.emptyTitle': 'Will the next renewal validate?',
  'rnw.emptyBody': 'Enter the names of a certificate, or load it, and choose the CA and the ACME challenge. Each name gets a verdict — ready, ready with warnings, or will fail — with what to fix.',
  'rnw.failed': 'The check could not be completed',
  'rnw.checkedAt': 'Checked {time}',
  'rnw.setup': 'CA: {ca} · challenge: {challenge}',
  'rnw.setupNoCa': 'CA not chosen · challenge: {challenge}',
  'rnw.resolvers': 'Resolvers asked for CAA: {resolvers}.',
  'rnw.namesTitle': 'Names',
  'rnw.kv.caaAt': 'CAA record set at',
  'rnw.kv.records': 'Records',
  'rnw.kv.none': 'none',
  'rnw.kv.owner': 'Name',
  'rnw.kv.target': 'Delegated to',
  'rnw.kv.txt': 'TXT records',
  'rnw.kv.zone': 'Zone',
  'rnw.kv.ns': 'Name servers',
  'rnw.kv.addresses': 'Addresses',
  'rnw.kv.cname': 'CNAME',
  'rnw.rs.records': { one: '{count} record at {at}', other: '{count} records at {at}' },
  'rnw.rs.none': 'no CAA records',
  'rnw.rs.error': 'no answer',
  'rnw.h01.title': 'HTTP-01 reachability from three continents',
  'rnw.h01.intro': 'A made-up token is requested at http://<name>/.well-known/acme-challenge/ by one probe in Europe, one in North America and one in Asia — over IPv6 too where a name has IPv6 addresses — much as the CA’s validation perspectives will. A 404 from your web server is the good answer: the path reaches it. Timeouts, refused connections, 5xx answers and redirect loops are what fail a renewal.',
  'rnw.h01.run': { one: 'Test {count} name ({probes} probes)', other: 'Test {count} names ({probes} probes)' },
  'rnw.h01.runOne': 'Test this name ({probes} probes)',
  'rnw.h01.capped': 'At most {max} names are tested at once: the first {max} that can be tested.',
  'rnw.h01.none': 'No name here can be tested: a wildcard, a name without a public address, or one Globalping does not accept.',
  'rnw.h01.privacy': 'The test runs through Globalping, a free probe network run by jsDelivr and volunteers. These host names go to Globalping: {names}. For each, one probe in Europe, one in North America and one in Asia sends one plain-HTTP GET request for {path}<made-up token> (User-Agent “globalping probe”), over IPv4 and, for a name with IPv6 addresses, over IPv6 too. Anyone with a measurement ID can read its result, the server’s response headers included, for about six months. Nothing else is sent.',
  'rnw.h01.running': 'Testing through Globalping…',
  'rnw.h01.quota': 'This hour’s free Globalping quota cannot cover the test; it resets {when}. No probe was used.',
  'rnw.h01.failed': 'The HTTP-01 test could not be completed',
  'rnw.h01.paid': 'The probes were already used: reading the results again uses the same measurements and costs nothing.',
  'rnw.h01.reread': 'Read the results again (no new probe)',
  'rnw.h01.family': '{family} · tested {time}',
  'rnw.h01.measurement': 'Measurement',
  'rnw.h01.done': { one: 'HTTP-01 reachability tested for {count} name.', other: 'HTTP-01 reachability tested for {count} names.' },
  'rnw.h01.donePartial': {
    one: 'HTTP-01 reachability tested for {count} name, but not completely: the test stopped before all its measurements were created. Test again for what is missing.',
    other: 'HTTP-01 reachability tested for {count} names, but not completely: the test stopped before all its measurements were created. Test again for what is missing.'
  },
  'rnw.h01.untested': '{family} · not tested',
  'rnw.h01.stopped': 'Stopped. The probes were already used: reading the results again uses the same measurements and costs nothing.'
});

registerStrings('tr', {
  'rnw.names': 'Yenilenecek adlar',
  'rnw.namesHint': 'Her satıra bir tane ya da boşluk veya virgülle ayırarak; joker ad için *.example.com. En fazla {max} ad.',
  'rnw.invalid': 'Host adı değil, dışarıda bırakıldı: {list}',
  'rnw.overCap': 'Yalnızca ilk {max} ad kontrol edilir; {count} ad dışarıda kaldı.',
  'rnw.noNames': 'En az bir host adı girin ya da adları bir sertifikadan alın.',
  'rnw.fromCert': 'Adları bir sertifikadan al',
  'rnw.certUse': 'Adlarını kullan',
  'rnw.certRemove': 'Kaldır',
  'rnw.certAnother': 'Başka bir sertifika yükle',
  'rnw.certNoNames': 'Bu sertifika hiçbir host adı içermiyor; burada yenilenecek bir şey yok.',
  'rnw.ca': 'Sertifika otoritesi',
  'rnw.caUnknown': 'Bilinmiyor',
  'rnw.caHint': 'CAA kayıtlarıyla karşılaştırılır. Bir sertifika yüklerseniz, onu veren otoriteye göre seçilir.',
  'rnw.caDetected': 'Sertifikayı veren otoriteye göre seçildi ({issuer}).',
  'rnw.caNotDetected': 'Sertifikayı veren ({issuer}) listede yok: onu yenileyen otoriteyi seçin.',
  'rnw.challenge': 'ACME doğrulama yöntemi',
  'rnw.challengeHint': 'ACME istemcinizin adların denetimini nasıl kanıtladığı. Emin değilseniz her yöntem kontrol edilir; birini engelleyecek bir şey uyarı olarak gösterilir.',
  'rnw.run': 'Hazırlığı kontrol et',
  'rnw.privacy': 'Yalnızca DNS sorguları — adlar ve kayıt türleri — genel DNS-over-HTTPS çözümleyicilerine gider; CAA karşılaştırması için dört tanesine. Sunucularınıza bağlanılmaz; HTTP-01 testi isteğe bağlıdır ve önce sorar.',
  'rnw.progress': '{total} addan {done} tanesi kontrol ediliyor…',
  'rnw.emptyTitle': 'Bir sonraki yenileme doğrulanacak mı?',
  'rnw.emptyBody': 'Bir sertifikanın adlarını girin ya da sertifikayı yükleyin; otoriteyi ve ACME doğrulama yöntemini seçin. Her ad bir sonuç alır — hazır, uyarılarla hazır ya da başarısız olacak — ve neyin düzeltileceği söylenir.',
  'rnw.failed': 'Kontrol tamamlanamadı',
  'rnw.checkedAt': 'Kontrol: {time}',
  'rnw.setup': 'Otorite: {ca} · doğrulama: {challenge}',
  'rnw.setupNoCa': 'Otorite seçilmedi · doğrulama: {challenge}',
  'rnw.resolvers': 'CAA için sorulan çözümleyiciler: {resolvers}.',
  'rnw.namesTitle': 'Adlar',
  'rnw.kv.caaAt': 'CAA kayıt kümesinin yeri',
  'rnw.kv.records': 'Kayıtlar',
  'rnw.kv.none': 'yok',
  'rnw.kv.owner': 'Ad',
  'rnw.kv.target': 'Devredildiği ad',
  'rnw.kv.txt': 'TXT kayıtları',
  'rnw.kv.zone': 'Alan',
  'rnw.kv.ns': 'Ad sunucuları',
  'rnw.kv.addresses': 'Adresler',
  'rnw.kv.cname': 'CNAME',
  'rnw.rs.records': '{at} üzerinde {count} kayıt',
  'rnw.rs.none': 'CAA kaydı yok',
  'rnw.rs.error': 'yanıt yok',
  'rnw.h01.title': 'Üç kıtadan HTTP-01 erişilebilirliği',
  'rnw.h01.intro': 'Otoritenin doğrulama noktalarının yapacağına benzer biçimde, Avrupa’da, Kuzey Amerika’da ve Asya’da birer ölçüm noktası http://<ad>/.well-known/acme-challenge/ altında uydurma bir değer ister; bir adın IPv6 adresleri varsa IPv6 üzerinden de. Web sunucunuzdan gelen 404 iyi yanıttır: yol ona ulaşıyor demektir. Zaman aşımları, reddedilen bağlantılar, 5xx yanıtları ve yönlendirme döngüleri yenilemeyi başarısız kılar.',
  'rnw.h01.run': '{count} adı test et ({probes} ölçüm)',
  'rnw.h01.runOne': 'Bu adı test et ({probes} ölçüm)',
  'rnw.h01.capped': 'Bir seferde en fazla {max} ad test edilir: test edilebilen ilk {max} ad.',
  'rnw.h01.none': 'Buradaki hiçbir ad test edilemez: joker ad, genel adresi olmayan ya da Globalping’in kabul etmediği bir ad.',
  'rnw.h01.privacy': 'Test, jsDelivr ve gönüllülerin işlettiği ücretsiz bir ölçüm ağı olan Globalping üzerinden yapılır. Şu host adları Globalping’e gider: {names}. Her biri için Avrupa’da, Kuzey Amerika’da ve Asya’da birer ölçüm noktası {path}<uydurma değer> için tek bir düz HTTP GET isteği gönderir (User-Agent “globalping probe”); IPv4 üzerinden, IPv6 adresleri olan bir ad için IPv6 üzerinden de. Ölçüm kimliğini bilen herkes sonucunu, sunucunun yanıt başlıkları dahil, yaklaşık altı ay okuyabilir. Başka hiçbir şey gönderilmez.',
  'rnw.h01.running': 'Globalping üzerinden test ediliyor…',
  'rnw.h01.quota': 'Bu saatin ücretsiz Globalping kotası testi karşılamıyor; {when} sıfırlanır. Hiçbir ölçüm harcanmadı.',
  'rnw.h01.failed': 'HTTP-01 testi tamamlanamadı',
  'rnw.h01.paid': 'Ölçümler zaten harcandı: sonuçları yeniden okumak aynı ölçümleri kullanır ve ek maliyeti yoktur.',
  'rnw.h01.reread': 'Sonuçları yeniden oku (yeni ölçüm yok)',
  'rnw.h01.family': '{family} · test: {time}',
  'rnw.h01.measurement': 'Ölçüm',
  'rnw.h01.done': 'HTTP-01 erişilebilirliği {count} ad için test edildi.',
  'rnw.h01.donePartial': 'HTTP-01 erişilebilirliği {count} ad için test edildi, ama eksik: test, tüm ölçümleri oluşturulmadan durdu. Eksik kalanlar için yeniden test edin.',
  'rnw.h01.untested': '{family} · test edilmedi',
  'rnw.h01.stopped': 'Durduruldu. Ölçümler zaten harcandı: sonuçları yeniden okumak aynı ölçümleri kullanır ve ek maliyeti yoktur.'
});

/** Verdict → Badge variant and icon. */
const VERDICT_STYLE = Object.freeze({ fail: ['error', 'x-circle'], warnings: ['warn', 'alert'], ready: ['ok', 'check-circle'] });
/** Finding severities, worst first. */
const SEVERITIES = ['error', 'warn', 'info', 'ok'];

/**
 * The names a route param holds (comma-separated), one per line for the box.
 * @param {unknown} value
 * @returns {string}
 */
export function namesText(value) {
  return String(value ?? '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean).join('\n');
}

/**
 * The route params of a check (what a shared link runs): its names comma-joined, the CA id and
 * the challenge ('unknown' is the default and left out).
 * @param {{ names: Array<{ name: string }>, ca: { id: string }|null, challenge: string }} check
 * @returns {{ names: string, ca: string|null, challenge: string|null }}
 */
export function checkParams(check) {
  return {
    names: check.names.map((n) => n.name).join(','),
    ca: check.ca ? check.ca.id : null,
    challenge: check.challenge && check.challenge !== 'unknown' ? check.challenge : null
  };
}

/**
 * Names in the order the results list shows them: will fail, then with warnings, then ready,
 * each in the order they were entered.
 * @param {Array<{ verdict: string }>} names
 * @returns {object[]}
 */
export function namesByVerdict(names) {
  return (names || []).map((r, i) => ({ r, i }))
    .sort((a, b) => RENEWAL_VERDICTS.indexOf(a.r.verdict) - RENEWAL_VERDICTS.indexOf(b.r.verdict) || a.i - b.i).map((x) => x.r);
}

/**
 * A finding's params for display in `lang`: the challenge as its label, outcome codes as their
 * texts (lib/renewal.js keeps both language-neutral).
 * @param {{ params: object }} f
 * @param {(key: string, params?: object) => string} t
 * @returns {object}
 */
export function localParams(f, t) {
  const p = { ...f.params };
  if (typeof p.challenge === 'string' && RENEWAL_CHALLENGES.includes(p.challenge)) p.challenge = t(`renew.ch.${p.challenge}`);
  for (const key of ['outcomes', 'answers']) {
    if (typeof p[key] === 'string') p[key] = p[key].split(', ').map((o) => (/^\d+$/.test(o) ? o : t(`renew.o.${o}`))).join(', ');
  }
  return p;
}

let active = null;

/**
 * Mount the Renewal readiness view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;
  const routeNames = namesText(ctx.params.names ?? ctx.params.name ?? '');
  const routeCa = renewalCa(ctx.params.ca) ? ctx.params.ca : null;
  const routeChallenge = RENEWAL_CHALLENGES.includes(ctx.params.challenge) ? ctx.params.challenge : null;

  /* --- form ------------------------------------------------------------------------ */
  const namesField = textarea({
    label: t('rnw.names'),
    rows: 4,
    value: restored ? restored.text : routeNames,
    placeholder: 'example.com\n*.example.com\nwww.example.com',
    hint: t('rnw.namesHint', { max: formatNumber(RENEWAL_LIMITS.names) }),
    attrs: { 'data-role': 'renew-names', 'data-shortcut': 'focus' },
    onInput: () => {
      namesField.setError(null);
      renderNamesNote();
    }
  });
  const namesNote = h('div', { class: 'rnw-names-note', attrs: { 'aria-live': 'polite' } });
  const caField = select({
    label: t('rnw.ca'),
    options: [{ value: '', label: t('rnw.caUnknown') }, ...RENEWAL_CAS.map((c) => ({ value: c.id, label: c.name }))],
    value: restored ? restored.ca : routeCa || '',
    hint: t('rnw.caHint'),
    className: 'rnw-ca',
    onChange: () => setCaHint(null)
  });
  caField.input.dataset.role = 'renew-ca';
  const challengeField = select({
    label: t('rnw.challenge'),
    options: RENEWAL_CHALLENGES.map((c) => ({ value: c, label: t(`renew.ch.${c}`) })),
    value: restored ? restored.challenge : routeChallenge || 'unknown',
    hint: t('rnw.challengeHint'),
    className: 'rnw-challenge'
  });
  challengeField.input.dataset.role = 'renew-challenge';
  /**
   * How the CA was set — `{ key, issuer }` when a certificate's issuer set it, null for the plain
   * hint — kept over a re-mount and worded in the language on screen.
   */
  let caHint = restored && restored.caHint ? restored.caHint : null;
  const setCaHint = (spec) => {
    caHint = spec;
    caField.setHint(spec ? t(spec.key, { issuer: spec.issuer }) : t('rnw.caHint'));
  };
  setCaHint(caHint);
  /** Set the CA from a route or a rerun: a hint about another certificate's issuer no longer applies. */
  const setCa = (value) => {
    if (caField.value === value) return;
    caField.value = value;
    setCaHint(null);
  };

  const runBtn = Button({ label: t('rnw.run'), icon: 'check-circle', variant: 'primary', dataset: { action: 'renew-run', shortcut: 'submit' }, onClick: () => start() });
  const stopBtn = Button({
    label: t('common.stop'), icon: 'stop', dataset: { action: 'renew-stop', shortcut: 'cancel' },
    onClick: () => { if (current && current.controller) current.controller.abort(); }
  });
  stopBtn.hidden = true;

  const certHost = h('div', { class: 'stack-sm rnw-cert' });
  const certBlock = Disclosure({ summary: t('rnw.fromCert'), className: 'rnw-cert-block', open: !!getCurrentCert(ctx.state), children: certHost });
  const formCard = Card({
    className: 'rnw-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'stack-sm' }, namesField.el, namesNote),
      certBlock,
      h('div', { class: 'rnw-options' }, caField.el, challengeField.el),
      h('div', { class: 'rnw-form-foot' },
        h('p', { class: 'muted text-sm rnw-privacy' }, Icon('lock', { size: 14 }), ' ', t('rnw.privacy')),
        h('div', { class: 'rnw-buttons' }, stopBtn, runBtn)))
  });

  /* --- results skeleton ------------------------------------------------------------ */
  const progress = ProgressBar({ label: t('rnw.progress', { done: 0, total: 0 }) });
  progress.el.hidden = true;
  const errorEl = h('div', { class: 'rnw-error' });
  const emptyEl = h('div', { class: 'card rnw-empty' }, EmptyState({ icon: 'refresh', title: t('rnw.emptyTitle'), message: t('rnw.emptyBody') }));
  const heroEl = h('div', { class: 'rnw-hero-wrap' });
  const testEl = h('div', { class: 'rnw-test-wrap' });
  const listEl = h('div', { class: 'stack rnw-names' });
  // A form of its own for the shell's Ctrl/Cmd+Enter: nothing in the results starts a new check.
  const results = h('div', { class: 'stack-lg rnw-results', hidden: true, dataset: { shortcutScope: 'results' } },
    heroEl, testEl,
    h('section', { class: 'stack rnw-names-section' }, h('h2', { class: 'section-title' }, t('rnw.namesTitle')), listEl));
  container.append(h('div', { class: 'stack-lg rnw-view' }, formCard, progress.el, errorEl, emptyEl, results));

  /* --- state ----------------------------------------------------------------------- */
  // current = { names, ca, challenge, text, controller, report, finishedAt, test }
  //   test = { status: 'running'|'done'|'quota'|'error'|'stopped', phase: 'gate'|'fetch', names, controller,
  //     pending: [{ name, host, path, planned, families }], stopped, tested, partial, error, resetAt }
  let current = null;
  /** The Copy summary of the hero (disabled while a check runs). */
  let heroSummary = null;
  /**
   * The button a running test was started from (`{ action, name }`, keyboard or click): every state
   * change of the test rebuilds it, and the consent dialog closes onto what had focus before it.
   */
  let testFocus = null;
  /** Names whose details the user opened or closed (name → open), kept across re-renders. */
  const openState = new Map(restored && Array.isArray(restored.open) ? restored.open : []);
  const boxNames = (text) => parseRenewalNames(text, { max: Infinity }).names.map((n) => n.name);
  /**
   * The text the box last took from a carried target: a newer one replaces it while the box still
   * holds it (lib/session.js fillReplaces). A re-mount keeps it (snapshot); a check forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null)
    : (isFillOnly(ctx.params) && routeNames) || null;

  function renderNamesNote() {
    clear(namesNote);
    const parsed = parseRenewalNames(namesField.value);
    const lines = [];
    if (parsed.invalid.length) lines.push(t('rnw.invalid', { count: parsed.invalid.length, list: parsed.invalid.slice(0, 6).join(', ') + (parsed.invalid.length > 6 ? ' …' : '') }));
    if (parsed.overCap) lines.push(t('rnw.overCap', { max: formatNumber(RENEWAL_LIMITS.names), count: parsed.overCap }));
    for (const line of lines) namesNote.append(h('p', { class: 'text-sm rnw-note-warn' }, Icon('alert', { size: 14 }), ' ', line));
  }

  /* --- the certificate block ------------------------------------------------------- */
  const certHostnames = (leaf) => (leaf.hostnames.length ? leaf.hostnames : leaf.dnsNames);
  const certKey = (leaf) => `${leaf.issuerDN || ''}|${leaf.serialHex || ''}`;
  const sameNames = (a, b) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);
  /**
   * The certificate whose issuer last set the CA (its issuer DN and serial), kept over a re-mount:
   * the same certificate shared again leaves a CA chosen since then alone.
   */
  let caCert = restored && typeof restored.caCert === 'string' ? restored.caCert : null;

  /** The CA of a certificate's issuer into the CA field, and the hint says where it came from. */
  function takeCa(leaf) {
    const issuer = leaf.issuer && Object.keys(leaf.issuer).length ? leaf.issuer : leaf.issuerDN;
    const ca = caForIssuer(issuer);
    const issuerName = leaf.issuer && (leaf.issuer.O || leaf.issuer.CN) ? [leaf.issuer.O, leaf.issuer.CN].filter(Boolean).join(' · ') : leaf.issuerDN;
    // A CA outside the list leaves "Not known": the choice made for another certificate would not apply.
    caField.value = ca || '';
    setCaHint({ key: ca ? 'rnw.caDetected' : 'rnw.caNotDetected', issuer: issuerName || '—' });
    caCert = certKey(leaf);
  }

  /**
   * The CA of the certificate shared by Certificate and SSL Targets, when the box holds exactly its
   * names: their "Renewal readiness" links carry the names only. Taken when the box has just taken
   * those names, or when the certificate is not the one the CA was last set from — never over a CA
   * the user chose since for the same names and certificate.
   * @param {boolean} boxChanged
   */
  function takeSharedCa(boxChanged) {
    const load = getCurrentCert(ctx.state);
    const leaf = load && load.result ? load.result.leaf : null;
    if (!leaf || (!boxChanged && certKey(leaf) === caCert)) return;
    if (sameNames(boxNames(certHostnames(leaf).join('\n')), boxNames(namesField.value))) takeCa(leaf);
  }

  /** A certificate's names into the box (replacing it: the user asked for them) and its CA. */
  function useCert(load) {
    const leaf = load && load.result ? load.result.leaf : null;
    if (!leaf) return;
    const hostnames = certHostnames(leaf);
    if (!hostnames.length) {
      namesField.setError(t('rnw.certNoNames'));
      return;
    }
    namesField.value = hostnames.join('\n');
    namesField.setError(null);
    // Not a draft of the user's: a certificate shared later (its link) may replace these names.
    carried = namesField.value;
    takeCa(leaf);
    renderNamesNote();
  }

  function onCertLoad(load) {
    setCurrentCert(ctx.state, load);
    if (load) useCert(load);
    renderCert();
  }

  function renderCert() {
    clear(certHost);
    const load = getCurrentCert(ctx.state);
    const leaf = load && load.result ? load.result.leaf : null;
    const alternatives = () => CertAlternatives({
      onLoad: onCertLoad,
      signal: ctx.signal,
      onBusy: ctx.setBusy,
      onStale: ctx.checkOutdated,
      requireOnline: ctx.requireOnline,
      focusTarget: () => certHost.querySelector('.cert-source-note') || certHost.querySelector('.cert-summary')
    }).el;
    if (!load) {
      certHost.append(CertLoader({ onLoad: onCertLoad, compact: true }).el, alternatives());
      return;
    }
    certHost.append(...certWarningAlerts(load.result, { name: load.name }));
    if (leaf) {
      certHost.append(CertSummary(load, {
        maxNames: 4,
        actions: [
          Button({ label: t('rnw.certUse'), icon: 'arrow-up', size: 'sm', variant: 'ghost', dataset: { action: 'renew-cert-use' }, onClick: () => { useCert(load); namesField.focus(); } }),
          Button({ label: t('rnw.certRemove'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'renew-cert-remove' }, onClick: () => onCertLoad(null) })
        ]
      }));
      const note = CertSourceNote(load);
      if (note) certHost.append(note);
    }
    certHost.append(Disclosure({
      summary: t('rnw.certAnother'),
      className: 'rnw-cert-another',
      children: h('div', { class: 'stack-sm' }, CertLoader({ onLoad: onCertLoad, compact: true }).el, alternatives())
    }));
  }

  /* --- hero -------------------------------------------------------------------------- */
  function setupText(report) {
    const challenge = t(`renew.ch.${report.challenge}`);
    return report.ca ? t('rnw.setup', { ca: report.ca.name, challenge }) : t('rnw.setupNoCa', { challenge });
  }

  function summaryFacts(report) {
    return {
      names: report.names.map((r) => ({
        name: r.name,
        verdict: r.verdict,
        problems: r.findings.filter((f) => f.severity === 'error' || f.severity === 'warn')
          .map((f) => ({ severity: f.severity, key: `renew.f.${f.id}.title`, params: localParams(f, t) }))
      })),
      ca: report.ca ? report.ca.name : null,
      challenge: report.challenge,
      tested: renewalSummary(report).tested,
      at: report.finishedAt
    };
  }

  function renderHero(report) {
    clear(heroEl);
    const s = renewalSummary(report);
    const variant = { fail: 'error', warnings: 'warn', ready: 'ok' }[s.headline] || 'info';
    const headline = Alert({ variant, compact: true, message: t(`renew.head.${s.headline}`) });
    headline.dataset.renewHeadline = s.headline;
    const counts = h('div', { class: 'cluster rnw-counts' }, RENEWAL_VERDICTS.filter((v) => s.counts[v]).map((v) => {
      const b = Badge(t(`sum.renew.${v}`, { count: s.counts[v] }), { variant: VERDICT_STYLE[v][0], icon: VERDICT_STYLE[v][1] });
      b.dataset.count = v;
      return b;
    }));
    heroSummary = SummaryButton({
      kind: 'renew',
      facts: () => (current && current.report ? summaryFacts(current.report) : null),
      url: () => ctx.shareUrl(permalinkParams('renew', checkParams(report)))
    });
    const subject = commonTarget(report.names.map((r) => r.base));
    const file = (ext) => timestampedName('renewal-readiness', ext, subject ? subject.value : null, report.finishedAt);
    heroEl.append(h('div', { class: ['card', 'rnw-hero', `rnw-hero-${s.headline}`], dataset: { renew: 'summary', headline: s.headline } },
      headline,
      counts,
      h('p', { class: 'text-sm rnw-setup' }, setupText(report)),
      h('p', { class: 'muted text-xs rnw-meta' },
        h('span', { title: formatDateTime(report.finishedAt) }, t('rnw.checkedAt', { time: formatRelative(report.finishedAt) })), ' · ',
        t('rnw.resolvers', { resolvers: report.resolvers.map((x) => (getResolver(x) ? getResolver(x).name : x)).join(', ') })),
      h('div', { class: 'rnw-hero-actions' },
        heroSummary,
        Button({
          label: t('common.exportCsv'), icon: 'download', size: 'sm', dataset: { action: 'renew-csv' },
          onClick: () => downloadText(file('csv'), toCsv(renewalRows(current.report), RENEWAL_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8')
        }),
        Button({
          label: t('common.exportJson'), icon: 'download', size: 'sm', dataset: { action: 'renew-json' },
          onClick: () => downloadText(file('json'), toJson(renewalExport(current.report, { version: ctx.version })), 'application/json;charset=utf-8')
        }))));
  }

  /* --- HTTP-01 reachability (Globalping, after a click) ----------------------------- */
  const testable = (report) => report && (report.challenge === 'http-01' || report.challenge === 'unknown');
  /** The names a test of `list` would send, with their families (capped), and its cost in probes. */
  function testPlan(list) {
    const plans = list.map((r) => ({ r, plan: http01Plan(r) })).filter((x) => x.plan.ok);
    const sent = plans.slice(0, RENEWAL_LIMITS.http01Names);
    return { sent, capped: plans.length > sent.length, probes: sent.reduce((n, x) => n + x.plan.families.length * HTTP01_LOCATIONS.length, 0) };
  }
  const testRunning = () => !!(current && current.test && current.test.status === 'running');

  /**
   * A test button. While a test runs, the buttons of what it tests say they are busy but stay
   * focusable (aria-disabled: a disabled button would drop the keyboard focus to the page, and a
   * click is ignored anyway); the others are disabled.
   */
  function testButton(list, { single = false } = {}) {
    const plan = testPlan(list);
    const btn = Button({
      label: single ? t('rnw.h01.runOne', { probes: formatNumber(plan.probes) }) : t('rnw.h01.run', { count: plan.sent.length, probes: formatNumber(plan.probes) }),
      icon: 'globe', size: 'sm', variant: single ? 'secondary' : 'primary',
      dataset: { action: single ? 'renew-http01-name' : 'renew-http01', probes: String(plan.probes) },
      onClick: () => testHttp01(list)
    });
    const job = testRunning() ? current.test : null;
    if (job && plan.sent.length && (!single || job.names.includes(list[0].name))) {
      btn.classList.add('is-busy');
      btn.setAttribute('aria-busy', 'true');
      btn.setAttribute('aria-disabled', 'true');
      btn.prepend(h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }));
    } else {
      btn.disabled = !plan.sent.length || !!job || !!(current && current.controller);
    }
    return btn;
  }

  function renderTest() {
    clear(testEl);
    const report = current && current.report;
    if (!testable(report)) return;
    const job = current.test;
    const plan = testPlan(report.names);
    const body = h('div', { class: 'stack-sm rnw-test', dataset: { state: job ? job.status : 'idle' } });
    body.append(h('p', { class: 'muted text-sm' }, t('rnw.h01.intro')));
    if (!plan.sent.length) body.append(Alert({ variant: 'info', compact: true, message: t('rnw.h01.none') }));
    if (plan.capped) body.append(h('p', { class: 'muted text-sm' }, t('rnw.h01.capped', { max: formatNumber(RENEWAL_LIMITS.http01Names) })));
    const paid = !!job && (job.status === 'error' || job.status === 'stopped') && job.pending.length > 0;
    if (job && job.status === 'quota') {
      body.append(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('rnw.h01.quota', { when: whenText(job.resetAt) }) }));
    } else if (job && job.status === 'error') {
      const banner = ErrorBanner(job.error, { title: t('rnw.h01.failed'), compact: true });
      if (paid) banner.querySelector('.alert-body').append(h('p', { class: 'text-sm' }, t('rnw.h01.paid')));
      body.append(banner);
    } else if (job && job.status === 'stopped') {
      body.append(Alert({ variant: 'info', compact: true, message: t('rnw.h01.stopped') }));
    } else if (job && job.status === 'done' && job.names.length) {
      const count = Number.isInteger(job.tested) ? job.tested : job.names.length;
      body.append(h('p', { class: ['text-sm', 'rnw-test-done', { 'rnw-test-partial': !!job.partial }], attrs: { role: 'status' } },
        Icon(job.partial ? 'alert' : 'check', { size: 14 }), ' ', t(job.partial ? 'rnw.h01.donePartial' : 'rnw.h01.done', { count })));
    }
    const actions = h('div', { class: 'rnw-test-actions' });
    if (paid) actions.append(Button({ label: t('rnw.h01.reread'), icon: 'refresh', size: 'sm', dataset: { action: 'renew-http01-reread' }, onClick: () => rereadTest() }));
    if (plan.sent.length) actions.append(testButton(report.names));
    if (testRunning()) {
      // Once the probes are being sent (the consent dialog is behind): what was paid for can still be read.
      if (job.phase === 'fetch') actions.append(Button({ label: t('common.stop'), icon: 'stop', size: 'sm', dataset: { action: 'renew-http01-stop' }, onClick: () => stopTest() }));
      actions.append(h('span', { class: 'muted text-sm', attrs: { role: 'status' } }, t('rnw.h01.running')));
    }
    body.append(actions);
    testEl.append(Card({ title: t('rnw.h01.title'), icon: 'globe', className: 'rnw-test-card', children: body }));
  }

  /**
   * "Test HTTP-01 reachability": the shared Globalping gate (free /limits read, the consent +
   * cost dialog on this purpose's first send of the page session), one measurement per name and
   * address family (every measurement is created first: each is paid once created), then read.
   * @param {object[]} list NameResults to test (the untestable ones and those past the cap are left out)
   */
  async function testHttp01(list) {
    const s = current;
    if (!s || !s.report || s.controller || testRunning() || !ctx.requireOnline()) return;
    const { sent, probes } = testPlan(list);
    if (!sent.length) return;
    const prev = s.test;
    const job = { status: 'running', phase: 'gate', names: sent.map((x) => x.r.name), controller: new AbortController(), pending: [], error: null, resetAt: null };
    testFocus = focusKeyOf(globalThis.document && globalThis.document.activeElement);
    s.test = job;
    renderReport();
    ctx.setBusy(true);
    const signal = mergeSignals(ctx.signal, job.controller.signal);
    const live = () => current === s && s.test === job;
    try {
      const privacy = t('rnw.h01.privacy', { names: sent.map((x) => x.r.base).join(', '), path: HTTP01_PATH_PREFIX });
      const gate = await gateProbes(ctx, { purpose: HTTP01_PURPOSE, probes, privacy, signal });
      if (!live()) return;
      if (gate.status === 'cancelled') {
        s.test = prev;
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(job, { status: 'quota', resetAt: gate.resetAt });
        announce(t('rnw.h01.quota', { when: whenText(job.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') throw gate.error;
      job.phase = 'fetch';
      keepFocus(renderTest);
      for (const { r, plan } of sent) {
        const token = http01Token();
        // `planned`: a family whose measurement is never created (the test stopped) reads "not tested".
        const entry = { name: r.name, host: r.base, path: `${HTTP01_PATH_PREFIX}${token}`, planned: [...plan.families], families: [] };
        job.pending.push(entry);
        for (const family of plan.families) {
          const body = http01Request(r.base, { token, ipVersion: family });
          const created = await gate.client.create(body, { signal });
          noteQuota(created.quota);
          entry.families.push({ ipVersion: family, id: created.id, deadlineAt: Date.now() + (body.timeout + GP_LIMITS.clientSlackS) * 1000 });
        }
      }
      if (!live()) return;
      await readTest(job, gate.client, signal);
    } catch (err) {
      failTest(job, err, signal, live);
    } finally {
      finishTest(job, prev, s);
    }
  }

  /**
   * Read every created measurement of a test and merge the results into the report. A test that
   * stopped before all its measurements were created (the quota, the view left) is partial: a
   * planned family never measured reads "not tested", and a name with none keeps what it had.
   */
  async function readTest(job, client, signal) {
    job.pending = job.pending.filter((e) => e.families.length);
    const results = await Promise.all(job.pending.map(async (entry) => ({
      entry,
      families: await Promise.all(entry.families.map(async (f) => {
        const m = await client.poll(f.id, f.deadlineAt ? { signal, deadlineAt: f.deadlineAt } : { signal });
        return interpretHttp01(m, { host: entry.host, path: entry.path, ipVersion: f.ipVersion });
      }))
    })));
    if (current.test !== job) return;
    let report = current.report;
    const at = new Date();
    let partial = results.length < job.names.length;
    for (const { entry, families } of results) {
      const all = http01Families(entry.planned || [], families, { path: entry.path });
      partial = partial || all.length > families.length;
      report = applyHttp01(report, entry.name, { at, families: all });
    }
    current.report = report;
    Object.assign(job, { status: 'done', pending: [], tested: results.length, partial });
    announce(t(partial ? 'rnw.h01.donePartial' : 'rnw.h01.done', { count: results.length }));
  }

  /** Stop a running test: the measurements already paid for can still be read ("Read the results again"). */
  function stopTest() {
    const job = current && current.test;
    if (!job || job.status !== 'running' || !job.controller) return;
    job.stopped = true;
    job.controller.abort();
  }

  function failTest(job, err, signal, live) {
    // An abort means a new check or leaving the view: that state is someone else's now.
    if (!live() || signal.aborted || errorKind(err) === 'abort') return;
    if (err && (err.code === 'rate-limit' || err.code === 'insufficient-credits')) {
      noteQuota(err.quota);
      Object.assign(job, { status: job.pending.some((e) => e.families.length) ? 'error' : 'quota', resetAt: err.resetAt || null, error: err });
      announce(t('rnw.h01.quota', { when: whenText(job.resetAt) }));
      return;
    }
    // A measurement Globalping no longer knows cannot be read again: the next try creates new ones.
    if (err && err.code === 'not-found') job.pending = [];
    Object.assign(job, { status: 'error', error: err });
    announce(`${t('rnw.h01.failed')}: ${describeError(err).message}`);
  }

  function finishTest(job, prev, s) {
    job.controller = null;
    const ours = !ctx.signal.aborted && current === s && (s.test === job || s.test === prev);
    if (ours && s.test === job && job.status === 'running') {
      if (!job.stopped) {
        Object.assign(job, { status: 'error', error: job.error || new Error(t('rnw.h01.failed')) });
      } else if (job.pending.some((e) => e.families.length)) {
        // Stopped by the user: what was paid for can still be read, for free.
        Object.assign(job, { status: 'stopped', stopped: false });
        announce(t('rnw.h01.stopped'));
      } else {
        // Stopped before a probe was used: as before the click.
        s.test = prev === job ? null : prev;
      }
    }
    // A check started meanwhile (it stopped this test) keeps the page busy.
    if (!ctx.signal.aborted && !(current && current.controller)) ctx.setBusy(false);
    if (ours) renderReport();
    if (!testRunning()) testFocus = null;
  }

  /**
   * Read again the measurements of a test that failed after they were paid for (no new probe).
   * `auto`: a test the view was left in the middle of, resumed on return (offline: no toast).
   */
  async function rereadTest({ auto = false } = {}) {
    const s = current;
    const job = s && s.test;
    if (!job || job.status === 'running' || !job.pending.length || !ctx.requireOnline({ quiet: auto })) return;
    if (!auto) testFocus = focusKeyOf(globalThis.document && globalThis.document.activeElement);
    Object.assign(job, { status: 'running', phase: 'fetch', controller: new AbortController(), error: null, stopped: false });
    renderReport();
    ctx.setBusy(true);
    const signal = mergeSignals(ctx.signal, job.controller.signal);
    const live = () => current === s && s.test === job;
    try {
      await readTest(job, await ctx.getGlobalping(), signal);
    } catch (err) {
      failTest(job, err, signal, live);
    } finally {
      finishTest(job, job, s);
    }
  }

  /* --- names ------------------------------------------------------------------------ */
  function findingItem(f) {
    const p = localParams(f, t);
    return h('li', { class: ['rnw-finding', `rnw-sev-${f.severity}`], dataset: { id: f.id, severity: f.severity } },
      h('span', { class: 'rnw-finding-icon' }, SeverityIcon(f.severity, { size: 16 })),
      h('div', { class: 'rnw-finding-body' },
        h('div', { class: 'rnw-finding-title' }, t(`renew.f.${f.id}.title`, p)),
        h('div', { class: 'rnw-finding-detail' }, t(`renew.f.${f.id}.detail`, p))));
  }

  const mono = (text) => h('span', { class: 'mono' }, text);
  const list = (items, max = 4) => TruncatedList(items, { max });

  /** The DNS data an area's findings rest on, or null. */
  function areaData(area, r) {
    if (area === 'caa' && r.caa && !r.caa.error) {
      return KeyValueList([
        { key: t('rnw.kv.caaAt'), value: r.caa.foundAt ? mono(r.caa.foundAt) : t('rnw.kv.none') },
        r.caa.records.length ? { key: t('rnw.kv.records'), value: list(r.caa.records) } : null
      ], { className: 'rnw-kv' });
    }
    // Only when they do not all agree: four identical lines would say nothing the finding does not.
    if (area === 'resolvers' && r.findings.some((f) => f.area === 'resolvers' && f.id !== 'resolvers.agree')) {
      return h('ul', { class: 'rnw-resolvers' }, r.resolvers.map((x) => {
        let text;
        if (x.state === 'servfail') text = x.rcode || 'SERVFAIL';
        else if (x.state === 'error') text = t('rnw.rs.error');
        else text = x.records.length ? t('rnw.rs.records', { count: x.records.length, at: x.foundAt }) : t('rnw.rs.none');
        const name = getResolver(x.id) ? getResolver(x.id).name : x.id;
        return h('li', { class: ['rnw-resolver', `rnw-rs-${x.state}`], dataset: { resolver: x.id, state: x.state } },
          h('span', { class: 'rnw-resolver-name' }, name), h('span', { class: 'rnw-resolver-state' }, text),
          x.records.length ? h('span', { class: 'rnw-resolver-records' }, TruncatedList(x.records, { max: 3 })) : null);
      }));
    }
    // A delegation's target; leftover TXT values only past the three the finding quotes.
    if (area === 'acme' && r.acme && (r.acme.target || r.acme.txt.length > 3)) {
      return KeyValueList([
        { key: t('rnw.kv.owner'), value: mono(r.acme.owner) },
        r.acme.target ? { key: t('rnw.kv.target'), value: mono(r.acme.target) } : null,
        r.acme.txt.length ? { key: t('rnw.kv.txt'), value: list(r.acme.txt, 3) } : null
      ], { className: 'rnw-kv' });
    }
    if (area === 'provider' && r.dnsHost && r.dnsHost.ns.length) {
      return KeyValueList([
        { key: t('rnw.kv.zone'), value: mono(r.dnsHost.zone) },
        { key: t('rnw.kv.ns'), value: list(r.dnsHost.ns) }
      ], { className: 'rnw-kv' });
    }
    // The CNAME chain the addresses come through (the findings quote the addresses themselves).
    if (area === 'http' && r.address && !r.address.error && r.address.cnames.length) {
      return KeyValueList([
        { key: t('rnw.kv.cname'), value: list(r.address.cnames) },
        { key: t('rnw.kv.addresses'), value: list([...r.address.ipv4, ...r.address.ipv6]) }
      ], { className: 'rnw-kv' });
    }
    if (area === 'http01' && r.http01) {
      return h('div', { class: 'stack-sm rnw-probes' }, r.http01.families.map((fam) => {
        if (fam.verdict === 'untested') {
          return h('div', { class: 'rnw-family', dataset: { family: String(fam.ipVersion), verdict: fam.verdict } },
            h('div', { class: 'muted text-xs rnw-family-head' }, t('rnw.h01.untested', { family: `IPv${fam.ipVersion}` })));
        }
        const link = measurementUrl(fam.measurementId);
        return h('div', { class: 'rnw-family', dataset: { family: String(fam.ipVersion), verdict: fam.verdict } },
          h('div', { class: 'muted text-xs rnw-family-head' },
            t('rnw.h01.family', { family: `IPv${fam.ipVersion}`, time: formatRelative(r.http01.at) }),
            link ? [' · ', ExternalLink(link, t('rnw.h01.measurement'), { className: 'rnw-measurement' })] : null),
          h('ul', { class: 'rnw-probe-list' }, fam.probes.map((p) => h('li', { class: ['rnw-probe', `rnw-probe-${p.outcome === 'not-found' || p.outcome === 'redirect' ? 'good' : p.outcome === 'probe' ? 'neutral' : 'bad'}`], dataset: { outcome: p.outcome } },
            h('span', { class: 'rnw-probe-place' }, [p.place || '—', p.probe && p.probe.network ? ` (${p.probe.network})` : ''].join('')),
            h('span', { class: 'rnw-probe-answer' }, [p.status ? `${p.status} · ` : '', t(`renew.o.${p.outcome}`)].join('')),
            p.location ? h('span', { class: 'mono text-xs rnw-probe-extra' }, `→ ${p.location}`) : null,
            p.failure ? h('span', { class: 'mono text-xs rnw-probe-extra' }, p.failure) : null,
            !p.location && !p.failure && p.address ? h('span', { class: 'mono text-xs rnw-probe-addr' }, p.address) : null))));
      }));
    }
    return null;
  }

  function nameCard(r, report) {
    const counts = SEVERITIES.slice(0, 2).map((sev) => [sev, r.findings.filter((f) => f.severity === sev).length]).filter(([, n]) => n);
    const [variant, vIcon] = VERDICT_STYLE[r.verdict];
    const summary = h('span', { class: 'rnw-name-head' },
      h('span', { class: 'mono rnw-name-text' }, r.name),
      Badge(t(`renew.v.${r.verdict}`), { variant, icon: vIcon, className: 'rnw-verdict' }),
      counts.length ? h('span', { class: 'muted text-xs rnw-name-counts' }, counts.map(([sev, n]) => t(`sum.count.${sev}`, { count: n })).join(' · ')) : null);
    const body = h('div', { class: 'stack-sm rnw-name-body' });
    for (const area of RENEWAL_AREAS) {
      const findings = r.findings.filter((f) => f.area === area);
      if (!findings.length) continue;
      body.append(h('section', { class: 'rnw-area', dataset: { area } },
        h('h4', { class: 'rnw-area-title' }, t(`renew.area.${area}`)),
        h('ul', { class: 'rnw-findings' }, findings.map(findingItem)),
        areaData(area, r)));
    }
    if (testable(report) && http01Plan(r).ok) {
      const btn = testButton([r], { single: true });
      if (testRunning() && current.test.names.includes(r.name)) {
        body.append(h('div', { class: 'rnw-name-actions' }, btn, Spinner({ size: 'sm', label: t('rnw.h01.running'), showLabel: true })));
      } else body.append(h('div', { class: 'rnw-name-actions' }, btn));
    }
    const open = openState.has(r.name) ? openState.get(r.name) : r.verdict !== 'ready' || report.names.length <= 2;
    const card = Disclosure({ summary, children: body, open, className: `rnw-name rnw-name-${r.verdict}`, heading: 3 });
    card.dataset.name = r.name;
    card.dataset.verdict = r.verdict;
    card.addEventListener('toggle', () => openState.set(r.name, card.open));
    return card;
  }

  /* --- keyboard focus over re-renders ------------------------------------------------ */
  /** Did focus fall to the page (never pull it away from where the user or a dialog put it)? */
  const focusDropped = () => {
    const doc = globalThis.document;
    const active = doc ? doc.activeElement : null;
    return !active || active === doc.body || active === doc.documentElement || !active.isConnected;
  };

  /** The results' button `node` is (or is in), as `{ action, name }` (name: its name card's), or null. */
  function focusKeyOf(node) {
    const btn = node && results.contains(node) ? node.closest('[data-action]') : null;
    if (!btn || !results.contains(btn)) return null;
    const card = btn.closest('.rnw-name');
    return { action: btn.dataset.action, name: card ? card.dataset.name : '' };
  }

  /**
   * Focus the button `key` names. A test-card button that went with its state (Stop, Read the
   * results again) hands focus on to the next action there.
   * @returns {boolean}
   */
  function focusKeyed(key) {
    const scope = key.name ? listEl.querySelector(`.rnw-name[data-name="${CSS.escape(key.name)}"]`) : results;
    const actions = !key.name && key.action.startsWith('renew-http01') ? [key.action, 'renew-http01-reread', 'renew-http01'] : [key.action];
    for (const action of actions) {
      const btn = scope && scope.querySelector(`[data-action="${CSS.escape(action)}"]`);
      if (btn && !btn.disabled) {
        btn.focus({ preventScroll: true });
        return true;
      }
    }
    return false;
  }

  /**
   * Re-render with keyboard focus kept on the button it was on (rebuilt), or — while a test runs —
   * on the button the test was started from when it fell to the page (a dialog closing onto a
   * button that is gone).
   */
  function keepFocus(render) {
    const doc = globalThis.document;
    const key = focusKeyOf(doc && doc.activeElement);
    render();
    if (!focusDropped()) return;
    if (!(key && focusKeyed(key)) && testFocus) focusKeyed(testFocus);
  }

  /** Re-render the results of the report on screen (keyboard focus on a button is put back). */
  function renderReport() {
    const report = current && current.report;
    results.hidden = !report;
    emptyEl.hidden = !!report || !!(current && current.controller);
    if (!report) return;
    keepFocus(() => {
      renderHero(report);
      if (heroSummary) heroSummary.setDisabled(!!current.controller);
      renderTest();
      clear(listEl);
      listEl.append(...namesByVerdict(report.names).map((r) => nameCard(r, report)));
    });
  }

  /* --- run --------------------------------------------------------------------------- */
  function setRunning(on) {
    // Keyboard focus follows Check ⇄ Stop instead of falling to <body> when one is hidden.
    const doc = globalThis.document;
    const moveFocus = !!doc && doc.activeElement === (on ? runBtn : stopBtn);
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    if (moveFocus) (on ? stopBtn : runBtn).focus({ preventScroll: true });
    namesField.input.readOnly = on;
    // The report on screen belongs to the previous check until this one finishes.
    if (heroSummary) heroSummary.setDisabled(on);
    ctx.setBusy(on);
  }

  function setShareAction() {
    ctx.setActions(CopyButton(() => ctx.shareUrl(current && current.report ? checkParams(current.report) : ctx.params),
      { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  /**
   * A name list carried over from another tool (`run=0`) goes into the box while it is empty or
   * still holds the report's names (all of them, past the cap too) or the names carried before —
   * never over a draft — and nothing runs; the report stays.
   * @param {string} text
   * @returns {boolean} whether the box now holds other names than before
   */
  function takeCarried(text) {
    const last = current && current.report ? boxNames(typeof current.text === 'string' ? current.text : current.report.names.map((r) => r.name).join('\n')) : null;
    if (!fillReplaces(namesField.value, last, boxNames, carried)) return false;
    const changed = !sameNames(boxNames(namesField.value), boxNames(text));
    namesField.value = text;
    namesField.setError(null);
    carried = text;
    renderNamesNote();
    return changed;
  }

  /**
   * Names carried from another tool (`run=0`), with the CA the link names, else the CA of the
   * shared certificate that names them.
   * @param {string} text
   * @param {{ ca?: string|null, keepCa?: boolean }} [opts] `ca`: a valid CA id to set; `keepCa`: the
   *   form keeps its own CA (a link back to the kept report names the report's)
   */
  function takeCarriedTarget(text, { ca = null, keepCa = false } = {}) {
    const boxChanged = takeCarried(text);
    if (ca) setCa(ca);
    else if (!keepCa) takeSharedCa(boxChanged);
  }

  /** Run the checks. `auto`: a shared link's run on arrival (offline: no toast). */
  function start({ auto = false } = {}) {
    namesField.setError(null);
    const parsed = parseRenewalNames(namesField.value);
    if (!parsed.names.length) {
      namesField.setError(t('rnw.noNames'));
      namesField.focus();
      return;
    }
    if (testRunning() && current.test.controller) current.test.controller.abort();
    const ca = caField.value || null;
    const challenge = RENEWAL_CHALLENGES.includes(challengeField.value) ? challengeField.value : 'unknown';
    if (!ctx.requireOnline({ quiet: auto })) return;
    carried = null;
    // `text`: the box as it was run (past the cap too), for a carried target to tell from a draft.
    const check = { names: parsed.names, ca: renewalCa(ca), challenge, text: namesField.value };
    ctx.setParams(checkParams(check));
    setShareAction();
    const subject = commonTarget(parsed.names.map((n) => n.base));
    ctx.runStarted(subject ? subject.value : null);
    run(check);
  }

  async function run(check) {
    if (current && current.controller) current.controller.abort();
    const controller = new AbortController();
    const s = { ...check, controller, report: current ? current.report : null, finishedAt: null, test: null };
    current = s;
    clear(errorEl);
    progress.el.hidden = false;
    progress.setVariant('default');
    progress.setLabel(t('rnw.progress', { done: 0, total: formatNumber(check.names.length) }));
    progress.set(0, check.names.length);
    emptyEl.hidden = true;
    setRunning(true);
    const startedAt = performance.now();
    try {
      const dns = await ctx.getDns();
      const report = await checkRenewal({ names: check.names, ca: check.ca ? check.ca.id : null, challenge: check.challenge }, {
        dns,
        signal: mergeSignals(ctx.signal, controller.signal),
        // A check right after fixing a record asks the resolvers again, not this page's cache.
        noCache: true,
        onProgress: ({ done, total }) => {
          if (current !== s) return;
          progress.set(done, total);
          progress.setLabel(t('rnw.progress', { done: formatNumber(done), total: formatNumber(total) }));
        }
      });
      if (current !== s) return;
      s.report = report;
      s.finishedAt = report.finishedAt;
      progress.done(`${t('common.done')} · ${formatDuration(performance.now() - startedAt)}`);
      setTimeout(() => { if (current === s) progress.el.hidden = true; }, 1200);
      const summary = renewalSummary(report);
      announce(t(`renew.head.${summary.headline}`));
    } catch (err) {
      if (current !== s) return;
      progress.el.hidden = true;
      if (err && err.name === 'AbortError') {
        // Stopped: the previous report (if any) stays on screen.
        return;
      }
      errorEl.append(Alert({ variant: 'error', title: t('rnw.failed'), message: err && err.message ? err.message : String(err) }));
    } finally {
      if (current === s) {
        s.controller = null;
        if (!ctx.signal.aborted) {
          setRunning(false);
          renderReport();
        }
      }
    }
  }

  /* --- initial state ----------------------------------------------------------------- */
  renderNamesNote();
  renderCert();
  if (restored && restored.report) {
    const test = restored.test || null;
    // A test that was reading its paid measurements when the view was left stands as interrupted
    // until they are read again (offline, its "Read the results again" is offered).
    const interrupted = !!(test && test.status === 'running' && test.pending && test.pending.length);
    current = {
      names: restored.report.names.map((r) => ({ name: r.name, base: r.base, wildcard: r.wildcard })),
      ca: restored.report.ca, challenge: restored.report.challenge, controller: null,
      report: restored.report, finishedAt: restored.report.finishedAt, text: typeof restored.ranText === 'string' ? restored.ranText : null,
      test: test ? { ...test, controller: null, ...(interrupted ? { status: 'error', error: new DOMException('Interrupted', 'AbortError') } : {}) } : null
    };
    renderReport();
    setShareAction();
    // GETs are free: read them now.
    if (interrupted) rereadTest({ auto: true });
    // A link back to the kept report names the report's CA: the form keeps its own.
    if (isFillOnly(ctx.params) && routeNames) takeCarriedTarget(routeNames, { keepCa: !!routeCa });
  } else if (!restored) {
    // The certificate loaded in Certificate or SSL Targets: its names and CA, nothing sent. Their
    // "Renewal readiness" links carry its names only; the CA then comes from the same certificate.
    const load = getCurrentCert(ctx.state);
    const leaf = load && load.result ? load.result.leaf : null;
    if (leaf && !routeNames) useCert(load);
    else if (!routeCa) takeSharedCa(true);
    // Shared link: run immediately. Names carried over from another tool (`run=0`) only fill the form.
    if (routeNames && !isFillOnly(ctx.params)) Promise.resolve().then(() => start({ auto: true }));
  }

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
      if (current && current.test && current.test.controller) current.test.controller.abort();
    },
    snapshot() {
      const report = current && !current.controller ? current.report : null;
      const job = report && current.test ? current.test : null;
      let test = null;
      // A finished (or failed) test stays; one in flight is carried only once its measurements
      // are paid for (a test still at the consent dialog is simply dropped).
      if (job && job.status !== 'running') test = { ...job, controller: null };
      else if (job && job.pending.some((e) => e.families.length)) test = { status: 'running', names: job.names, pending: job.pending, error: null, resetAt: null };
      return {
        text: namesField.value,
        carried,
        ca: caField.value,
        caHint,
        caCert,
        challenge: challengeField.value,
        report,
        ranText: report && typeof current.text === 'string' ? current.text : null,
        test,
        open: [...openState]
      };
    },
    result() {
      if (!current || current.controller || !current.report) return null;
      const subject = commonTarget(current.report.names.map((r) => r.base));
      return { subject: subject ? subject.value : current.report.names[0].name, at: current.report.finishedAt, params: checkParams(current.report) };
    },
    rerun() {
      if (current && current.report) {
        namesField.value = current.report.names.map((r) => r.name).join('\n');
        setCa(current.report.ca ? current.report.ca.id : '');
        challengeField.value = current.report.challenge;
        renderNamesNote();
      }
      start();
    },
    update(params) {
      const text = namesText(params.names ?? params.name ?? '');
      if (!text) return false;
      if (isFillOnly(params)) {
        takeCarriedTarget(text, { ca: renewalCa(params.ca) ? params.ca : null });
        if (RENEWAL_CHALLENGES.includes(params.challenge)) challengeField.value = params.challenge;
        return true;
      }
      // A shared link runs what it says, as on arrival: without a CA in it, none is chosen (unless
      // the shared certificate names exactly these names); without a challenge, "Not sure".
      namesField.value = text;
      setCa(renewalCa(params.ca) ? params.ca : '');
      if (!renewalCa(params.ca)) takeSharedCa(true);
      challengeField.value = RENEWAL_CHALLENGES.includes(params.challenge) ? params.challenge : 'unknown';
      renderNamesNote();
      start();
      return true;
    }
  };
}

/** Abort a running check or test. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * Form + finished report (and its HTTP-01 tests) carried over a language re-mount and kept for the
 * next visit (no new check).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The finished report on screen (kept by the shell when the view is left), or null.
 * @returns {{ subject: string, at: Date, params: object }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: check the report's names again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take new route params (a link from Certificate or SSL Targets while the view is open) without a
 * re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
