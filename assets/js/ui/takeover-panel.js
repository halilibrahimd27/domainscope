/**
 * ui/takeover-panel.js — Subdomains › Overview › "Takeover risks", and Domain Health ›
 * Dependencies (the same audit for one domain).
 *
 * An on-demand audit of the scanned hosts and domains for names someone else could claim
 * (lib/takeover.js auditTakeover): CNAME chains that end at a released service resource, and the
 * targets of the domains' CNAME, NS, MX, SPF (include, redirect, a, mx, exists, ptr), DMARC report
 * address, DKIM CNAME, CAA iodef, MTA-STS, SRV, HTTPS and `_acme-challenge` records in a
 * registrable domain nobody holds (or one pending deletion, expired or about to expire). Nothing
 * is sent before the click: the card says what goes where (DNS queries to the resolver, RDAP
 * lookups to the registries of the domains the records name). The results: one row per reference
 * at risk with its severity, host, record, chain, service, evidence and fix, a CSV export, a note
 * when nothing is at risk (and how many SPF terms built from a macro were not checked), and "⚠ n/a"
 * with a Retry (only the failed lookups are asked again) for every lookup that gave no answer.
 *
 * For the hosts whose service's page decides (S3, GitHub Pages, Heroku …), an optional page check
 * asks Globalping (ui/globalping-gate.js, with its consent) for one HTTP GET per host and
 * compares the page with the service's "no such site" text (lib/takeover.js httpCheckOutcome).
 *
 * {@link TakeoverPanel}: loaded by views/subdomains.js with its results, its state kept per scan
 * run. {@link DependencyPanel}: mounted by views/health.js on "Check dependencies (RDAP)", its
 * state the holder the view keeps with the report on screen ({@link freshDependencies}). Either
 * way lib/takeover.js and lib/rdap.js load on the first click, ui/globalping-gate.js and
 * lib/globalping.js on the first page check, and a language switch (a re-mount) shows the same
 * results; a check in flight draws into the panel mounted last.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Card, DataTable, ExternalLink, ProgressBar, announce } from './components.js';
import { NaMark, RetryButton, setRetryBusy } from './source-status.js';
import { registerRunning } from './jobs.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { dohStatus, rdapStatus } from '../lib/sourcestatus.js';
import { errorKind, mergeSignals, onceAsync } from '../lib/util.js';

registerStrings('en', {
  'tko.title': 'Takeover risks',
  'tko.hint': 'Looks for names someone else could claim: a CNAME whose service resource is gone, and the targets of CNAME, NS, MX, SPF, DMARC, DKIM, CAA iodef, MTA-STS, SRV, HTTPS and _acme-challenge records in a domain nobody holds.',
  'tko.sends': 'Runs only when you click: DNS queries go to your resolver, and RDAP lookups of the domains these records name go to their registries.',
  'tko.notSent': 'Nothing has been sent yet.',
  'tko.run': 'Check takeover risks',
  'tko.again': 'Check again',
  'tko.runBusy': 'Available when this scan has ended',
  'tko.stop': 'Stop',
  'tko.progress': 'Checking the references…',
  'tko.stopped': 'The check was stopped; nothing more was sent.',
  'tko.failed': 'The check could not run: {error}',
  'tko.switchRunning': 'Takeover risks check',
  'tko.none': { one: 'Nothing at risk: {count} reference checked, {domains}.', other: 'Nothing at risk: {count} references checked, {domains}.' },
  'tko.found': { one: '{count} reference at risk ({checked}).', other: '{count} references at risk ({checked}).' },
  'tko.toCheck': { one: '{count} more points to a service whose page decides: see the page check below.', other: '{count} more point to services whose page decides: see the page check below.' },
  'tko.checked': { one: '{count} reference checked', other: '{count} references checked' },
  'tko.domains': { one: '{count} registrable domain looked up', other: '{count} registrable domains looked up' },
  'tko.macros': {
    one: '{count} SPF term builds its domain from a macro (%{…}), known only per message: it was not checked.',
    other: '{count} SPF terms build their domain from a macro (%{…}), known only per message: they were not checked.'
  },
  'tko.failures': 'These lookups gave no answer, so their names have no verdict yet:',
  'tko.sev.critical': 'Critical',
  'tko.sev.high': 'High',
  'tko.sev.medium': 'Medium',
  'tko.sev.low': 'Low',
  'tko.sev.info': 'To check',
  'tko.kind.cname': 'CNAME',
  'tko.kind.ns': 'NS',
  'tko.kind.mx': 'MX',
  'tko.kind.spf': 'SPF include',
  'tko.kind.spf-host': 'SPF host',
  'tko.kind.dmarc': 'DMARC',
  'tko.kind.dkim': 'DKIM CNAME',
  'tko.kind.caa': 'CAA iodef',
  'tko.kind.mta-sts': 'MTA-STS CNAME',
  'tko.kind.srv': 'SRV',
  'tko.kind.https': 'HTTPS record',
  'tko.kind.acme': '_acme-challenge CNAME',
  'tko.col.severity': 'Severity',
  'tko.col.host': 'Host',
  'tko.col.kind': 'Record',
  'tko.col.chain': 'Points to',
  'tko.col.service': 'Service',
  'tko.col.status': 'Service status',
  'tko.col.evidence': 'Evidence',
  'tko.col.fix': 'Fix',
  'tko.col.ref': 'Reference',
  'tko.status.vulnerable': 'claimable',
  'tko.status.edge': 'edge case',
  'tko.status.safe': 'verified by the service',
  'tko.ref': 'Reference',
  'tko.reason.unregistered': '{domain} looks unregistered: its registry has no record of it (RDAP) and DNS says it does not exist. Anyone may be able to register it — check at a registrar.',
  'tko.reason.unregistered-dns': '{domain} does not exist in DNS and its registry publishes no RDAP: possibly registrable — check at a registrar.',
  'tko.reason.pending-delete': '{domain} is pending deletion at its registry: once released, anyone can register it.',
  'tko.reason.expired': 'The registration of {domain} expired on {date}.',
  'tko.reason.expiring': 'The registration of {domain} ends on {date}.',
  'tko.reason.nxdomain': '{name} does not exist (NXDOMAIN).',
  'tko.reason.fingerprint': 'The page says the {service} resource does not exist.',
  'tko.reason.check-http': 'Points to {service}, where only the page tells whether the resource still exists.',
  'tko.fix.register.cname': 'Remove the CNAME record, or register {domain} yourself.',
  'tko.fix.register.ns': 'Remove the name server {target} from the delegation (at the registrar and in the zone), or register {domain} yourself.',
  'tko.fix.register.mx': 'Remove the MX record for {target}, or register {domain} yourself.',
  'tko.fix.register.spf': 'Remove include:{target} from the SPF record, or register {domain} yourself.',
  'tko.fix.register.spf-host': 'Remove {term} from the SPF record, or register {domain} yourself.',
  'tko.fix.register.dmarc': 'Remove the report address at {target} from the DMARC record ({term}), or register {domain} yourself.',
  'tko.fix.register.caa': 'Remove the iodef address at {target} from the CAA record, or register {domain} yourself.',
  'tko.fix.register.srv': 'Remove the SRV record {host}, or register {domain} yourself.',
  'tko.fix.register.https': 'Remove the HTTPS record of {host} that points to {target}, or register {domain} yourself.',
  'tko.fix.lapsing.cname': 'Renew {domain} if it is yours; otherwise remove the CNAME record before the domain is released.',
  'tko.fix.lapsing.ns': 'Renew {domain} if it is yours; otherwise remove the name server {target} from the delegation before the domain is released.',
  'tko.fix.lapsing.mx': 'Renew {domain} if it is yours; otherwise remove the MX record for {target} before the domain is released.',
  'tko.fix.lapsing.spf': 'Renew {domain} if it is yours; otherwise remove include:{target} from the SPF record before the domain is released.',
  'tko.fix.lapsing.spf-host': 'Renew {domain} if it is yours; otherwise remove {term} from the SPF record before the domain is released.',
  'tko.fix.lapsing.dmarc': 'Renew {domain} if it is yours; otherwise remove the report address at {target} from the DMARC record ({term}) before the domain is released.',
  'tko.fix.lapsing.caa': 'Renew {domain} if it is yours; otherwise remove the iodef address at {target} from the CAA record before the domain is released.',
  'tko.fix.lapsing.srv': 'Renew {domain} if it is yours; otherwise remove the SRV record {host} before the domain is released.',
  'tko.fix.lapsing.https': 'Renew {domain} if it is yours; otherwise remove the HTTPS record of {host} that points to {target} before the domain is released.',
  'tko.fix.nxdomain.cname': 'Remove the record, or create the {service} resource it points to again under your account.',
  'tko.fix.nxdomain.unknown': 'Remove the record, or point it to a name that exists.',
  'tko.fix.nxdomain.ns': 'Remove the name server {target} from the delegation.',
  'tko.fix.nxdomain.mx': 'Remove the MX record for {target}.',
  'tko.fix.nxdomain.spf-host': 'Remove {term} from the SPF record.',
  'tko.fix.nxdomain.dmarc': 'Remove the report address at {target} from the DMARC record ({term}): reports sent there are lost.',
  'tko.fix.nxdomain.caa': 'Remove the iodef address at {target} from the CAA record.',
  'tko.fix.nxdomain.srv': 'Remove the SRV record {host}, or point it to a host that exists.',
  'tko.fix.nxdomain.https': 'Remove the HTTPS record of {host}, or point it to a name that exists.',
  'tko.fix.fingerprint': 'Remove the record, or claim the {service} resource again under your own account.',
  'tko.fix.check-http': 'Run the page check below, or open http://{host}/ and compare it with the service’s “not found” page.',
  'tko.http.title': 'Page check (HTTP)',
  'tko.http.hint': {
    one: '{count} host points to a service where only its page tells whether the resource still exists. The check asks one Globalping probe per host to fetch http://<host>/ and compares the page with the service’s “not found” text.',
    other: '{count} hosts point to services where only the page tells whether the resource still exists. The check asks one Globalping probe per host to fetch http://<host>/ and compares the page with the service’s “not found” text.'
  },
  'tko.http.button': { one: 'Check the page ({count} probe)', other: 'Check the pages ({count} probes)' },
  'tko.http.privacy': 'Globalping probes will fetch http://<host>/ for these host names: {hosts}. The names go to Globalping and to the servers that answer them.',
  'tko.http.running': 'Fetching the pages…',
  'tko.http.done': 'Pages checked: {claimable} with the “not found” text, {inUse} in use, {noAnswer} without a usable answer.',
  'tko.http.quota': 'Not enough Globalping quota is left for this check: try again {when}.',
  'tko.http.failed': 'The page check failed: {error}',
  'tko.http.outcome.claimable': 'Page check: the “not found” text (HTTP {status}).',
  'tko.http.outcome.no-answer': 'Page check: no usable answer.'
});

registerStrings('tr', {
  'tko.title': 'Ele geçirme riskleri',
  'tko.hint': 'Başkasının sahiplenebileceği adları arar: hizmetteki kaynağı silinmiş bir CNAME ile CNAME, NS, MX, SPF, DMARC, DKIM, CAA iodef, MTA-STS, SRV, HTTPS ve _acme-challenge kayıtlarının kimsenin elinde olmayan bir alan adındaki hedefleri.',
  'tko.sends': 'Yalnızca tıkladığınızda çalışır: DNS sorguları çözümleyicinize, bu kayıtlarda geçen alan adlarının RDAP sorguları da kayıt kuruluşlarına gider.',
  'tko.notSent': 'Henüz hiçbir şey gönderilmedi.',
  'tko.run': 'Ele geçirme risklerini kontrol et',
  'tko.again': 'Yeniden kontrol et',
  'tko.runBusy': 'Bu tarama bittiğinde kullanılabilir',
  'tko.stop': 'Durdur',
  'tko.progress': 'Referanslar kontrol ediliyor…',
  'tko.stopped': 'Kontrol durduruldu; başka bir şey gönderilmedi.',
  'tko.failed': 'Kontrol çalıştırılamadı: {error}',
  'tko.switchRunning': 'Ele geçirme riskleri kontrolü',
  'tko.none': 'Risk bulunmadı: {count} referans kontrol edildi, {domains}.',
  'tko.found': '{count} referans risk altında ({checked}).',
  'tko.toCheck': '{count} referans daha, sayfasına bakılması gereken bir hizmete gidiyor: aşağıdaki sayfa kontrolüne bakın.',
  'tko.checked': '{count} referans kontrol edildi',
  'tko.domains': '{count} alan adı sorgulandı',
  'tko.macros': '{count} SPF terimi alan adını bir makrodan (%{…}) oluşturuyor; ad yalnızca ileti başına belli olduğu için kontrol edilmedi.',
  'tko.failures': 'Bu sorgular yanıt vermedi; bu adlar için henüz sonuç yok:',
  'tko.sev.critical': 'Kritik',
  'tko.sev.high': 'Yüksek',
  'tko.sev.medium': 'Orta',
  'tko.sev.low': 'Düşük',
  'tko.sev.info': 'Kontrol edilmeli',
  'tko.kind.cname': 'CNAME',
  'tko.kind.ns': 'NS',
  'tko.kind.mx': 'MX',
  'tko.kind.spf': 'SPF include',
  'tko.kind.spf-host': 'SPF host',
  'tko.kind.dmarc': 'DMARC',
  'tko.kind.dkim': 'DKIM CNAME',
  'tko.kind.caa': 'CAA iodef',
  'tko.kind.mta-sts': 'MTA-STS CNAME',
  'tko.kind.srv': 'SRV',
  'tko.kind.https': 'HTTPS kaydı',
  'tko.kind.acme': '_acme-challenge CNAME',
  'tko.col.severity': 'Önem',
  'tko.col.host': 'Host',
  'tko.col.kind': 'Kayıt',
  'tko.col.chain': 'Hedef',
  'tko.col.service': 'Hizmet',
  'tko.col.status': 'Hizmet durumu',
  'tko.col.evidence': 'Kanıt',
  'tko.col.fix': 'Çözüm',
  'tko.col.ref': 'Kaynak',
  'tko.status.vulnerable': 'sahiplenilebilir',
  'tko.status.edge': 'özel durum',
  'tko.status.safe': 'hizmet doğruluyor',
  'tko.ref': 'Kaynak',
  'tko.reason.unregistered': '{domain} kayıtlı görünmüyor: kayıt kuruluşunda kaydı yok (RDAP) ve DNS’te de bulunmuyor. Herkes kaydedebilir — bir kayıt firmasından kontrol edin.',
  'tko.reason.unregistered-dns': '{domain} DNS’te bulunmuyor ve kayıt kuruluşu RDAP yayımlamıyor: kaydedilebilir olabilir — bir kayıt firmasından kontrol edin.',
  'tko.reason.pending-delete': '{domain} kayıt kuruluşunda silinmeyi bekliyor: serbest kaldığında herkes kaydedebilir.',
  'tko.reason.expired': '{domain} alan adının kaydı {date} tarihinde sona erdi.',
  'tko.reason.expiring': '{domain} alan adının kaydı {date} tarihinde sona eriyor.',
  'tko.reason.nxdomain': '{name} adı yok (NXDOMAIN).',
  'tko.reason.fingerprint': 'Sayfa, {service} kaynağının bulunmadığını söylüyor.',
  'tko.reason.check-http': '{service} hizmetine gidiyor; kaynağın hâlâ var olup olmadığını yalnızca sayfası söyler.',
  'tko.fix.register.cname': 'CNAME kaydını kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.ns': '{target} ad sunucusunu yetkilendirmeden (kayıt firmasında ve zone’da) kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.mx': '{target} için MX kaydını kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.spf': 'SPF kaydından include:{target} ifadesini kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.spf-host': 'SPF kaydından {term} ifadesini kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.dmarc': 'DMARC kaydından ({term}) {target} üzerindeki rapor adresini kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.caa': 'CAA kaydından {target} üzerindeki iodef adresini kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.srv': '{host} SRV kaydını kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.register.https': '{host} için {target} adına işaret eden HTTPS kaydını kaldırın ya da {domain} alan adını kendiniz kaydedin.',
  'tko.fix.lapsing.cname': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce CNAME kaydını kaldırın.',
  'tko.fix.lapsing.ns': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce {target} ad sunucusunu yetkilendirmeden kaldırın.',
  'tko.fix.lapsing.mx': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce {target} için MX kaydını kaldırın.',
  'tko.fix.lapsing.spf': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce SPF kaydından include:{target} ifadesini kaldırın.',
  'tko.fix.lapsing.spf-host': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce SPF kaydından {term} ifadesini kaldırın.',
  'tko.fix.lapsing.dmarc': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce DMARC kaydından ({term}) {target} üzerindeki rapor adresini kaldırın.',
  'tko.fix.lapsing.caa': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce CAA kaydından {target} üzerindeki iodef adresini kaldırın.',
  'tko.fix.lapsing.srv': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce {host} SRV kaydını kaldırın.',
  'tko.fix.lapsing.https': '{domain} sizinse yenileyin; değilse alan adı serbest kalmadan önce {host} için {target} adına işaret eden HTTPS kaydını kaldırın.',
  'tko.fix.nxdomain.cname': 'Kaydı kaldırın ya da gösterdiği {service} kaynağını kendi hesabınızda yeniden oluşturun.',
  'tko.fix.nxdomain.unknown': 'Kaydı kaldırın ya da var olan bir ada yönlendirin.',
  'tko.fix.nxdomain.ns': '{target} ad sunucusunu yetkilendirmeden kaldırın.',
  'tko.fix.nxdomain.mx': '{target} için MX kaydını kaldırın.',
  'tko.fix.nxdomain.spf-host': 'SPF kaydından {term} ifadesini kaldırın.',
  'tko.fix.nxdomain.dmarc': 'DMARC kaydından ({term}) {target} üzerindeki rapor adresini kaldırın: oraya gönderilen raporlar kaybolur.',
  'tko.fix.nxdomain.caa': 'CAA kaydından {target} üzerindeki iodef adresini kaldırın.',
  'tko.fix.nxdomain.srv': '{host} SRV kaydını kaldırın ya da var olan bir host’a yönlendirin.',
  'tko.fix.nxdomain.https': '{host} için HTTPS kaydını kaldırın ya da var olan bir ada yönlendirin.',
  'tko.fix.fingerprint': 'Kaydı kaldırın ya da {service} kaynağını kendi hesabınızda yeniden sahiplenin.',
  'tko.fix.check-http': 'Aşağıdaki sayfa kontrolünü çalıştırın ya da http://{host}/ adresini açıp hizmetin “bulunamadı” sayfasıyla karşılaştırın.',
  'tko.http.title': 'Sayfa kontrolü (HTTP)',
  'tko.http.hint': '{count} host, kaynağın hâlâ var olup olmadığını yalnızca sayfasının söylediği bir hizmete gidiyor. Kontrol, her host için bir Globalping ölçümüyle http://<host>/ adresini getirir ve sayfayı hizmetin “bulunamadı” metniyle karşılaştırır.',
  'tko.http.button': { one: 'Sayfayı kontrol et ({count} ölçüm)', other: 'Sayfaları kontrol et ({count} ölçüm)' },
  'tko.http.privacy': 'Globalping ölçümleri şu host adları için http://<host>/ adresini getirecek: {hosts}. Bu adlar Globalping’e ve onlara yanıt veren sunuculara gider.',
  'tko.http.running': 'Sayfalar getiriliyor…',
  'tko.http.done': 'Sayfalar kontrol edildi: {claimable} sayfada “bulunamadı” metni var, {inUse} sayfa kullanımda, {noAnswer} sayfadan kullanılabilir yanıt gelmedi.',
  'tko.http.quota': 'Bu kontrol için yeterli Globalping kotası kalmadı: {when} yeniden deneyin.',
  'tko.http.failed': 'Sayfa kontrolü başarısız oldu: {error}',
  'tko.http.outcome.claimable': 'Sayfa kontrolü: “bulunamadı” metni (HTTP {status}).',
  'tko.http.outcome.no-answer': 'Sayfa kontrolü: kullanılabilir yanıt yok.'
});

/** lib/takeover.js once loaded (every result of this page session was made with it). */
let engine = null;
/** The audit engine, loaded on the first click. */
const loadEngine = onceAsync(() => Promise.all([import('../lib/takeover.js'), import('../lib/rdap.js')]).then((mods) => {
  engine = mods[0];
  return mods;
}));
/** The Globalping gate and request builders, loaded on the first page check. */
const loadGlobalping = onceAsync(() => Promise.all([import('./globalping-gate.js'), import('../lib/globalping.js')]));

/** Severity → badge variant. */
const SEVERITY_BADGE = Object.freeze({ critical: 'error', high: 'error', medium: 'warn', low: 'info', info: 'neutral' });
const SEVERITY_ORDER = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
/** Every reference kind (lib/takeover.js TAKEOVER_REF_KINDS; the panel loads before the engine). */
const KINDS = Object.freeze(['cname', 'ns', 'mx', 'spf', 'spf-host', 'dmarc', 'dkim', 'caa', 'mta-sts', 'srv', 'https', 'acme']);
/** Kinds whose fix is worded per kind; the CNAME chains (dkim, mta-sts, acme, a `_dmarc` delegation) are worded as a CNAME. */
const FIX_KINDS = Object.freeze(['cname', 'ns', 'mx', 'spf', 'spf-host', 'dmarc', 'caa', 'srv', 'https']);

/**
 * The i18n keys this module builds from codes (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...SEVERITY_ORDER.map((s) => `tko.sev.${s}`),
    ...KINDS.map((k) => `tko.kind.${k}`),
    ...['vulnerable', 'edge', 'safe'].map((s) => `tko.status.${s}`),
    ...['unregistered', 'unregistered-dns', 'pending-delete', 'expired', 'expiring', 'nxdomain', 'fingerprint', 'check-http'].map((r) => `tko.reason.${r}`),
    ...['register', 'lapsing'].flatMap((g) => FIX_KINDS.map((k) => `tko.fix.${g}.${k}`)),
    ...['cname', 'unknown', ...FIX_KINDS.filter((k) => k !== 'cname' && k !== 'spf')].map((k) => `tko.fix.nxdomain.${k}`),
    'tko.fix.fingerprint', 'tko.fix.check-http', 'tko.http.outcome.claimable', 'tko.http.outcome.no-answer'
  ];
}

/** The kind a finding's fix is worded as: a CNAME chain of any kind as a CNAME. */
function fixKind(f) {
  if (f.kind === 'dmarc' && !f.term) return 'cname';
  return FIX_KINDS.includes(f.kind) ? f.kind : 'cname';
}

/**
 * The i18n key of a finding's fix.
 * @param {object} f a TakeoverFinding
 * @returns {string}
 */
export function fixKey(f) {
  const code = f.fix;
  const kind = fixKind(f);
  if (code === 'unregistered' || code === 'unregistered-dns') return `tko.fix.register.${kind}`;
  if (code === 'pending-delete' || code === 'expired' || code === 'expiring') return `tko.fix.lapsing.${kind}`;
  if (code === 'nxdomain') return kind === 'cname' ? (f.service ? 'tko.fix.nxdomain.cname' : 'tko.fix.nxdomain.unknown') : `tko.fix.nxdomain.${kind}`;
  return `tko.fix.${code}`;
}

/** The domain a finding's fix names (its first registration reason's). */
const fixDomain = (f) => (f.reasons.find((r) => r.domain) || {}).domain || '';

/**
 * The evidence of a finding, worded.
 * @param {object} f a TakeoverFinding
 * @returns {string}
 */
export function evidenceText(f) {
  const service = f.service ? f.service.name : '';
  const parts = f.reasons.map((r) => t(`tko.reason.${r.code}`, { domain: r.domain || '', date: r.expires ? formatDate(r.expires) : '', name: r.name || f.target, service }));
  if (f.http && f.http.outcome !== 'in-use') parts.push(t(`tko.http.outcome.${f.http.outcome}`, { status: f.http.httpStatus ?? '' }));
  return parts.join(' ');
}

/**
 * The fix of a finding, worded.
 * @param {object} f a TakeoverFinding
 * @returns {string}
 */
export function fixText(f) {
  return t(fixKey(f), { domain: fixDomain(f), target: f.target, service: f.service ? f.service.name : '', host: f.host, term: f.term || '' });
}

/** Findings worst first, then by host and target (lib/takeover.js order). */
function sortFindings(list) {
  return list.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    || a.host.localeCompare(b.host) || a.target.localeCompare(b.target) || KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind));
}

/**
 * A state nothing has been sent for. `view` is the panel that draws it (the one mounted last).
 * @param {object} [extra]
 * @returns {object}
 */
function freshState(extra = {}) {
  return { status: 'idle', result: null, findings: [], known: null, outcomes: new Map(), error: null, controller: null, done: 0, total: 0, http: null, view: null, ...extra };
}

/**
 * The state of Domain Health › Dependencies for one report (views/health.js keeps it with the
 * report on screen, so a re-render mounts the panel on it again).
 * @param {string} domain
 * @param {string[]} [selectors] the extra DKIM selectors the report was checked with
 * @returns {object}
 */
export function freshDependencies(domain, selectors = []) {
  return freshState({ domain, selectors: [...selectors] });
}

/** States with a check in flight (a workspace switch names it, ui/jobs.js). */
const running = new Set();
registerRunning('tko.switchRunning', () => running.size > 0);

/** Draw a state again in the panel mounted last, if that one still shows it (a check outlives a re-mount). */
function paint(s) {
  if (s.view && s.view.shows(s)) s.view.render();
}

/**
 * The audit inside a card: what it sends, the run, its progress and its results.
 * @param {object} ctx the view's context
 * @param {{ input: () => { hosts: object[], domains: string[], extraDkimSelectors?: string[] }, blocked?: () => boolean, runKey?: string }} opts
 *   `blocked`: the run waits (a scan still running); `runKey`: the run button's label before the first check
 * @returns {{ el: HTMLElement, show: (state: object) => void, render: () => void, refresh: () => void, start: () => void }}
 */
function auditView(ctx, { input, blocked = () => false, runKey = 'tko.run' }) {
  const body = h('div', { class: 'stack-sm' });
  let state = null;
  let progress = null;
  let drawnBlocked = null;
  const view = {
    render: () => render(),
    shows: (s) => s === state && body.isConnected,
    progress: (done, total) => progress && progress.set(done, Math.max(total, 1))
  };

  async function start({ retry = false } = {}) {
    const s = state;
    if (!s || s.status === 'running' || blocked()) return;
    if (!ctx.requireOnline()) return;
    const controller = new AbortController();
    const signal = mergeSignals(ctx.signal, controller.signal);
    const job = input();
    Object.assign(s, { status: 'running', controller, error: null, done: 0, total: 0, http: retry ? s.http : null });
    // Check again starts afresh; a Retry keeps the registrations and the page checks it has.
    if (!retry) Object.assign(s, { known: null, outcomes: new Map() });
    running.add(s);
    render();
    try {
      const [{ auditTakeover }, { rdapDomain }] = await loadEngine().catch((err) => {
        ctx.checkOutdated();
        throw err;
      });
      const dns = await ctx.getDns();
      const result = await auditTakeover({ hosts: job.hosts, domains: job.domains }, {
        dns, signal, known: s.known, extraDkimSelectors: job.extraDkimSelectors || [],
        rdap: (domain, opts) => rdapDomain(domain, opts),
        onProgress: (done, total) => {
          s.done = done;
          s.total = total;
          if (s.view && s.view.shows(s)) s.view.progress(done, total);
        }
      });
      const findings = [];
      for (const f of result.findings) {
        const o = s.outcomes.get(f.id);
        const after = o ? engine.applyHttpCheck(f, o) : f;
        if (after) findings.push(after);
      }
      Object.assign(s, { status: 'done', result, findings: sortFindings(findings), known: result.registrations });
      const atRisk = result.findings.filter((f) => f.severity !== 'info').length;
      announce(atRisk ? t('tko.found', { count: atRisk, checked: t('tko.checked', { count: result.references }) })
        : t('tko.none', { count: result.references, domains: t('tko.domains', { count: result.checked }) }));
    } catch (err) {
      // A stopped Retry keeps the results it was retrying.
      if (errorKind(err) === 'abort' || signal.aborted) s.status = s.result ? 'done' : 'stopped';
      else Object.assign(s, { status: 'error', error: err });
    } finally {
      s.controller = null;
      running.delete(s);
      paint(s);
    }
  }

  async function checkPages(candidates) {
    const s = state;
    if (!s || !s.result || (s.http && s.http.status === 'running') || !ctx.requireOnline()) return;
    const controller = new AbortController();
    const signal = mergeSignals(ctx.signal, controller.signal);
    const prev = s.http;
    s.http = { status: 'running', controller, counts: null, error: null, resetAt: null };
    running.add(s);
    render();
    try {
      const [[gate, gp], [takeover]] = await Promise.all([loadGlobalping(), loadEngine()]).catch((err) => {
        ctx.checkOutdated();
        throw err;
      });
      const list = candidates.filter((f) => gp.isProbeableHost(f.host));
      if (!list.length) {
        s.http = prev;
        return;
      }
      const hosts = list.map((f) => f.host);
      const g = await gate.gateProbes(ctx, {
        purpose: takeover.TAKEOVER_PURPOSE, probes: list.length, privacy: t('tko.http.privacy', { hosts: hosts.join(', ') }), signal, confirmAbove: 3
      });
      if (g.status === 'cancelled') {
        s.http = prev;
        return;
      }
      if (g.status === 'quota') {
        s.http = { status: 'quota', resetAt: g.resetAt, whenText: gate.whenText };
        return;
      }
      if (g.status === 'unreachable') throw g.error;
      const counts = { claimable: 0, inUse: 0, noAnswer: 0 };
      const checks = new Map();
      for (const f of list) {
        const created = await g.client.create(gp.httpGetRequest({ host: f.host, path: '/', probes: 1 }), { signal });
        gate.noteQuota(created.quota);
        checks.set(f.id, created.id);
      }
      const outcomes = new Map();
      await Promise.all(list.map(async (f) => {
        const m = await g.client.poll(checks.get(f.id), { signal });
        outcomes.set(f.id, takeover.httpCheckOutcome(m, f.service));
      }));
      const next = [];
      for (const f of s.findings) {
        const o = outcomes.get(f.id);
        if (!o) {
          next.push(f);
          continue;
        }
        if (o.outcome === 'claimable') counts.claimable += 1;
        else if (o.outcome === 'in-use') counts.inUse += 1;
        else counts.noAnswer += 1;
        s.outcomes.set(f.id, o);
        const after = takeover.applyHttpCheck(f, o);
        if (after) next.push(after);
      }
      s.findings = sortFindings(next);
      s.http = { status: 'done', counts };
      announce(t('tko.http.done', counts));
    } catch (err) {
      if (errorKind(err) === 'abort' || signal.aborted) s.http = prev;
      else if (err && (err.code === 'rate-limit' || err.code === 'insufficient-credits')) s.http = { status: 'quota', resetAt: err.resetAt || null, whenText: null };
      else s.http = { status: 'error', error: err };
    } finally {
      running.delete(s);
      paint(s);
    }
  }

  function renderFailures(s) {
    const failures = s.result ? s.result.failures : [];
    if (!failures.length) return null;
    const items = failures.map((f) => {
      const st = f.source === 'rdap' ? rdapStatus(f.response) : dohStatus(f.response);
      return h('li', { class: 'cluster', dataset: { failed: f.name } }, h('span', { class: 'mono' }, f.name), st ? NaMark([st]) : null);
    });
    const retry = RetryButton({
      sources: [...new Set(failures.map((f) => f.source))],
      dataset: { action: 'tko-retry' },
      onClick: (e) => {
        setRetryBusy(e.currentTarget);
        start({ retry: true });
      }
    });
    return Alert({ variant: 'warn', compact: true, children: [h('p', { class: 'text-sm' }, t('tko.failures')), h('ul', { class: 'stack-sm text-sm' }, ...items)], actions: [retry] });
  }

  function renderTable(findings) {
    return DataTable({
      columns: [
        {
          key: 'severity', label: t('tko.col.severity'), sortable: true, sortValue: (f) => SEVERITY_ORDER.indexOf(f.severity),
          exportValue: (f) => f.severity, render: (f) => Badge(t(`tko.sev.${f.severity}`), { variant: SEVERITY_BADGE[f.severity] || 'neutral' })
        },
        { key: 'host', label: t('tko.col.host'), sortable: true, mono: true, render: (f) => f.host },
        { key: 'kind', label: t('tko.col.kind'), sortable: true, exportValue: (f) => f.kind, render: (f) => t(`tko.kind.${f.kind}`) },
        { key: 'chain', label: t('tko.col.chain'), mono: true, wrap: true, exportValue: (f) => f.chain.join(' → '), searchValue: (f) => f.chain.join(' '), render: (f) => f.chain.join(' → ') },
        {
          key: 'service', label: t('tko.col.service'), sortable: true, sortValue: (f) => (f.service ? f.service.name : ''), exportValue: (f) => (f.service ? f.service.name : ''),
          render: (f) => (f.service ? h('span', { class: 'stack-sm' },
            h('span', null, f.service.name),
            Badge(t(`tko.status.${f.service.status}`), { variant: f.service.status === 'vulnerable' ? 'error' : f.service.status === 'edge' ? 'warn' : 'ok' }),
            ExternalLink(f.service.ref, t('tko.ref'))) : '—')
        },
        { key: 'status', label: t('tko.col.status'), display: false, exportValue: (f) => (f.service ? f.service.status : '') },
        { key: 'evidence', label: t('tko.col.evidence'), wrap: true, exportValue: evidenceText, searchValue: evidenceText, render: evidenceText },
        { key: 'fix', label: t('tko.col.fix'), wrap: true, exportValue: fixText, searchValue: fixText, render: fixText },
        { key: 'ref', label: t('tko.col.ref'), display: false, exportValue: (f) => (f.service ? f.service.ref : '') }
      ],
      rows: findings,
      rowKey: (f) => f.id,
      search: findings.length > 8,
      cellLabels: true,
      export: { filename: 'takeover-risks', formats: ['csv'] },
      className: 'tko-table'
    }).el;
  }

  function renderHttp(s, candidates) {
    if (!candidates.length && !(s.http && s.http.status === 'done')) return null;
    const children = [h('h4', { class: 'card-title' }, t('tko.http.title'))];
    const http = s.http;
    if (candidates.length) children.push(h('p', { class: 'muted text-sm' }, t('tko.http.hint', { count: candidates.length })));
    if (http && http.status === 'running') children.push(h('p', { class: 'text-sm', attrs: { role: 'status' } }, t('tko.http.running')));
    else if (http && http.status === 'done') children.push(h('p', { class: 'text-sm', attrs: { role: 'status' } }, t('tko.http.done', http.counts)));
    else if (http && http.status === 'quota') {
      children.push(Alert({ variant: 'warn', compact: true, message: t('tko.http.quota', { when: http.whenText && http.resetAt ? http.whenText(http.resetAt) : '—' }) }));
    } else if (http && http.status === 'error') {
      children.push(Alert({ variant: 'error', compact: true, message: t('tko.http.failed', { error: (http.error && http.error.message) || String(http.error) }) }));
    }
    if (candidates.length && !(http && http.status === 'running')) {
      children.push(h('div', { class: 'cluster' }, Button({
        label: t('tko.http.button', { count: candidates.length }), icon: 'globe', size: 'sm', dataset: { action: 'tko-http' },
        disabled: !!(state && state.status === 'running'), onClick: () => checkPages(candidates)
      })));
    }
    return h('section', { class: 'stack-sm', dataset: { part: 'tko-http' } }, ...children);
  }

  function render() {
    clear(body);
    progress = null;
    if (!state) return;
    const s = state;
    drawnBlocked = blocked();
    const { hosts, domains } = input();
    const nothing = !hosts.length && !domains.length;
    const actions = h('div', { class: 'cluster' });
    if (s.status === 'running') {
      progress = ProgressBar({ label: t('tko.progress'), value: s.done, max: Math.max(s.total, 1) });
      body.append(progress.el);
      actions.append(Button({ label: t('tko.stop'), icon: 'x', size: 'sm', dataset: { action: 'tko-stop', shortcut: 'cancel' }, onClick: () => s.controller && s.controller.abort() }));
      body.append(actions);
      return;
    }
    const runBtn = Button({
      label: t(s.status === 'idle' || s.status === 'stopped' ? runKey : 'tko.again'), icon: 'shield', size: 'sm',
      variant: s.status === 'idle' ? 'primary' : 'secondary', disabled: drawnBlocked || nothing || !!(s.http && s.http.status === 'running'),
      title: drawnBlocked ? t('tko.runBusy') : null, dataset: { action: 'tko-run' }, onClick: () => start()
    });
    actions.append(runBtn);
    if (s.status === 'idle') {
      body.append(h('p', { class: 'text-sm' }, t('tko.sends')), h('p', { class: 'muted text-sm', dataset: { part: 'tko-not-sent' } }, t('tko.notSent')), actions);
      return;
    }
    if (s.status === 'stopped') {
      body.append(Alert({ variant: 'info', compact: true, message: t('tko.stopped') }), actions);
      return;
    }
    if (s.status === 'error') {
      body.append(Alert({ variant: 'error', compact: true, message: t('tko.failed', { error: (s.error && s.error.message) || String(s.error) }) }), actions);
      return;
    }
    const result = s.result;
    const atRisk = s.findings.filter((f) => f.severity !== 'info');
    const candidates = s.findings.filter((f) => f.reasons.some((r) => r.code === 'check-http'));
    const counts = SEVERITY_ORDER.filter((sev) => sev !== 'info').map((sev) => [sev, atRisk.filter((f) => f.severity === sev).length]).filter(([, n]) => n > 0);
    const summary = atRisk.length
      ? h('div', { class: 'cluster', attrs: { role: 'status' }, dataset: { part: 'tko-summary', risks: String(atRisk.length) } },
        h('span', { class: 'text-sm' }, t('tko.found', { count: atRisk.length, checked: t('tko.checked', { count: result.references }) })),
        ...counts.map(([sev, n]) => Badge(`${t(`tko.sev.${sev}`)} ${formatNumber(n)}`, { variant: SEVERITY_BADGE[sev] })))
      : h('p', { class: 'text-sm', attrs: { role: 'status' }, dataset: { part: 'tko-summary', risks: '0' } },
        t('tko.none', { count: result.references, domains: t('tko.domains', { count: result.checked }) }));
    body.append(summary);
    if (!atRisk.length && candidates.length) body.append(h('p', { class: 'muted text-sm' }, t('tko.toCheck', { count: candidates.length })));
    if (result.spfMacros) body.append(h('p', { class: 'muted text-sm', dataset: { part: 'tko-macros' } }, t('tko.macros', { count: result.spfMacros })));
    const failures = renderFailures(s);
    if (failures) body.append(failures);
    if (s.findings.length) body.append(renderTable(s.findings));
    const http = renderHttp(s, engine ? engine.httpCandidates(s.findings) : []);
    if (http) body.append(http);
    body.append(actions);
  }

  return {
    el: body,
    show(s) {
      state = s;
      s.view = view;
      render();
    },
    render,
    // Only the run's own state and the wait matter here: a source event of a running scan draws nothing.
    refresh() {
      if (state && state.status !== 'running' && blocked() !== drawnBlocked) render();
    },
    start: () => start()
  };
}

/** State per scan run: survives a re-mount (a language switch) of the same results. */
const states = new WeakMap();

/** The run's hosts and scanned domains. */
function runInput(run) {
  const hosts = (run && run.result && run.result.hosts) || (run && run.hosts) || [];
  const domains = (run && run.config && run.config.domains) || [];
  return { hosts, domains };
}

/**
 * The "Takeover risks" card of Subdomains › Overview.
 * @param {import('../app.js').ViewContext} ctx
 * @returns {{ el: HTMLElement, update: (run: object) => void }}
 */
export function TakeoverPanel(ctx) {
  let run = null;
  const audit = auditView(ctx, { input: () => runInput(run), blocked: () => !!run && run.status === 'running' });
  const el = Card({
    title: t('tko.title'), icon: 'shield', className: 'tko', children: [
      h('p', { class: 'muted text-sm' }, t('tko.hint')),
      audit.el
    ]
  });
  el.dataset.part = 'takeover';
  return {
    el,
    update(next) {
      if (!next) return;
      if (next !== run) {
        run = next;
        let s = states.get(next);
        if (!s) {
          s = freshState();
          states.set(next, s);
        }
        audit.show(s);
        return;
      }
      audit.refresh();
    }
  };
}

/**
 * Domain Health › Dependencies: the same audit for the report's domain alone (its records, no
 * hosts), the extra DKIM selectors it was checked with included.
 * @param {{ ctx: object, holder: object, start?: boolean, runKey?: string }} opts `holder`: {@link freshDependencies};
 *   `start`: run at once (the card's first click); `runKey`: the run button's label after a stopped check (the card's own)
 * @returns {HTMLElement}
 */
export function DependencyPanel({ ctx, holder, start = false, runKey = 'tko.run' }) {
  const audit = auditView(ctx, { input: () => ({ hosts: [], domains: [holder.domain], extraDkimSelectors: holder.selectors || [] }), runKey });
  audit.el.dataset.part = 'dependencies';
  audit.show(holder);
  if (start && holder.status !== 'running') audit.start();
  return audit.el;
}
