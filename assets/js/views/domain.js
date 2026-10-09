/**
 * views/domain.js — "Domain overview" (`#/domain?name=example.com`): one page per domain for a
 * migration or a customer takeover, the facts otherwise gathered from five or six tools by hand.
 * lib/passport.js runs the lookups and turns them into card data; this view draws the cards:
 *
 * - Registration (RDAP: registrar, dates with a countdown, status flags with the transfer lock,
 *   DNSSEC delegation; a TLD without RDAP names the registry's WHOIS instead);
 * - DNS hosting (name servers → provider, the registry's delegation when it differs, SOA,
 *   DNSSEC); Mail (MX → platform, SPF and DMARC in one line each); Web (apex and www → CDN /
 *   platform / direct, HTTPS records); Certificates (the CAs CAA allows, and on a click the
 *   issuers of the current certificates in Certificate Transparency compared with CAA);
 *   SaaS verifications (services named by TXT tokens, never the tokens); Health (Domain Health's
 *   score and worst problems, the workspace's accepted risks left out as Domain Health leaves them
 *   out — lib/waivers.js — and said, so both pages show the same number).
 * - Each card links to the tool that goes deeper, carrying the name.
 *
 * Nothing is sent until "Build overview" is pressed: a route (a shared link, a carried target,
 * `run=0` or not) only fills the box and says so. The cards fill as their lookups land; a lookup
 * that failed shows "⚠ n/a" with the reason and a Retry that asks only that card's failed
 * lookups again (past the DNS cache), at once, even while the rest of the build still runs. A
 * stopped build keeps what landed, and each unfinished card offers to look it up. The CT lookup
 * is one Cert Spotter request (crt.sh when Cert Spotter cannot answer), only on its button.
 *
 * Lookalike domains (ui/lookalike-panel.js over lib/lookalike.js, loaded on the first click of
 * "Find lookalikes"): the typosquats of the overview's domain, checked only on the panel's button.
 *
 * "Copy summary" (lib/summary.js domainSummary) and the print stylesheet work on the finished
 * overview. It is kept for the page session (`result()` / `snapshot()`), so coming back shows it
 * again with no request.
 */

import { h, clear, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, ExternalLink, Icon, KeyValueList, KindBadge, ProgressBar, RelativeTime, SeverityIcon,
  announce, textInput
} from '../ui/components.js';
import { registerStrings, hasString, formatNumber, formatDate, formatRelative, getLang } from '../i18n.js';
import {
  PASSPORT_CARDS, PASSPORT_LOOKUPS, CARD_LOOKUPS, HEALTH_LOOKUPS, passportDomain, passportCards, cardsOfLookup, buildPassport,
  lookupCtIssuers, passportSummaryFacts, passportStatus
} from '../lib/passport.js';
import {
  EmptyState, PrivacyNote, RelatedLinks, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput, withSubject
} from '../ui/template.js';
import { inputCompact, templateState } from '../lib/template.js';
import { HEALTH_I18N, LOOKUP_FAILED_PARAM } from '../lib/health.js';
import { WAIVERS_I18N, readWaivers } from '../lib/waivers.js';
import { NaMark, RetryButton, setRetryBusy, statusText } from '../ui/source-status.js';
import { SummaryButton } from '../ui/summary-button.js';
import { ReportButton } from '../ui/report-button.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { mergeSignals, onceAsync } from '../lib/util.js';

/** Route id (`#/domain`). */
export const id = 'domain';
/** i18n key of the page title. */
export const titleKey = 'nav.domain';
/** Icon name (ui/components.js Icon). */
export const icon = 'id-card';

/** The lookalike panel, loaded on the first click of Find lookalikes. */
const loadLookalikes = onceAsync(() => import('../ui/lookalike-panel.js'));

/** Card icons. */
export const CARD_ICONS = Object.freeze({
  registration: 'calendar', dns: 'server', mail: 'mail', web: 'globe', certs: 'shield', saas: 'key', health: 'activity'
});

// The health card shows Domain Health's check titles (health.<id>.title), and its accepted risks
// in Domain Health's words (wvr.*, lib/waivers.js).
registerStrings('en', HEALTH_I18N.en);
registerStrings('tr', HEALTH_I18N.tr);
registerStrings('en', WAIVERS_I18N.en);
registerStrings('tr', WAIVERS_I18N.tr);

registerStrings('en', {
  'dov.domain': 'Domain',
  'dov.placeholder': 'example.com',
  'dov.run': 'Build overview',
  'dov.invalid': 'Enter a domain name such as example.com (not an IP address or a bare ending such as com.tr).',
  'dov.privacy': 'Nothing is sent until you press Build overview: then DNS questions go to your DoH resolvers and one RDAP lookup to the registry.',
  'dov.linkPrompt': 'Opened from a link: press Build overview to look up {domain}. Nothing has been sent yet.',
  'dov.emptyLine': 'Cards that fill in as their lookups land, each with a link to the tool that goes deeper.',
  'dov.status.na': { one: '{count} card could not be read', other: '{count} cards could not be read' },
  'dov.progress': 'Building the overview of {domain}',
  'dov.progressCount': '{done} of {total} lookups',
  'dov.builtAt': 'Built {time}',
  'dov.stoppedAt': 'Stopped {time}: some parts were not looked up',
  'dov.reduced': 'Overview of {domain}, the registrable domain of {host}.',
  'dov.resultsTitle': 'Overview of {domain}',
  'dov.done': 'Overview of {domain} ready',
  'dov.stopped': 'Stopped: the parts that landed are shown',
  'dov.openIn': 'Open in {tool}',
  'dov.openInTitle': 'Opens {tool} with {domain}',
  'dov.pending': 'Looking up…',
  'dov.updating': 'Updating…',
  'dov.notLooked': 'Not looked up: the build was stopped.',
  'dov.retried': '{card}: updated',
  'dov.failedPart': 'Could not be read',
  'dov.none': 'none',

  'dov.card.registration': 'Registration',
  'dov.card.dns': 'DNS hosting',
  'dov.card.mail': 'Mail',
  'dov.card.web': 'Web',
  'dov.card.certs': 'Certificates',
  'dov.card.saas': 'SaaS verifications',
  'dov.card.health': 'Health',

  'dov.reg.registrar': 'Registrar',
  'dov.reg.ianaId': 'IANA ID {id}',
  'dov.reg.created': 'Registered',
  'dov.reg.expires': 'Expires',
  'dov.reg.daysLeft': { zero: 'expires today', one: '{count} day left', other: '{count} days left' },
  'dov.reg.daysAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'dov.reg.status': 'Status',
  'dov.reg.lock': 'Transfer lock',
  'dov.reg.lockOn': 'On',
  'dov.reg.lockOff': 'Off',
  'dov.reg.lockOffNote': 'Without clientTransferProhibited, anyone with the transfer code can move the domain to another registrar. Keep it on except during a planned transfer.',
  'dov.reg.lockUnknown': 'the registry reports no status',
  'dov.reg.dnssec': 'DNSSEC delegation',
  'dov.reg.signed': 'Signed',
  'dov.reg.unsigned': 'Not signed',
  'dov.reg.nameservers': 'Name servers (registry)',
  'dov.reg.registryDomain': 'Registered as',
  'dov.reg.unsupported': 'The .{tld} registry publishes no RDAP service, so the registrar and the dates cannot be read from the browser.',
  'dov.reg.whois': 'Look it up in the registry’s WHOIS: {registry}',
  'dov.reg.iana': 'The .{tld} registry and its WHOIS server (IANA)',
  'dov.reg.notFound': 'Not registered: the registry has no record of {domain}.',
  'dov.reg.invalid': 'Not a domain a registry holds.',
  'dov.reg.failed': 'Registration data could not be read',

  'dov.dns.provider': 'DNS provider',
  'dov.dns.own': 'Own name servers',
  'dov.dns.other': 'Other',
  'dov.dns.multi': 'Name servers of {count} providers: a multi-provider setup, or a move that is half done.',
  'dov.dns.nameservers': 'Name servers',
  'dov.dns.noNs': 'No NS records at this name: it is not the apex of a zone.',
  'dov.dns.delegation': 'The registry delegates to {registry}, but the zone lists {zone}. Until they match, resolvers may use either set.',
  'dov.dns.soa': 'SOA',
  'dov.dns.soaValue': 'primary {mname} · serial {serial}',
  'dov.dns.serialDate': 'changed {date}',
  'dov.dns.contact': 'Contact',
  'dov.dns.dnssec': 'DNSSEC',
  'dov.dns.dnssec.validated': 'Signed and validated',
  'dov.dns.dnssec.signed': 'Signed (DS at the parent)',
  'dov.dns.dnssec.failing': 'Signed, but the keys could not be validated: see Domain Health',
  'dov.dns.dnssec.unsigned': 'Not signed',
  'dov.nxdomain': 'The domain does not exist in DNS (NXDOMAIN).',

  'dov.mail.receives': 'Receives mail at',
  'dov.mail.noMx': 'No MX record: senders fall back to the domain’s own address.',
  'dov.mail.nullMx': 'Accepts no mail (null MX).',
  'dov.mail.hosts': 'MX hosts',
  'dov.mail.kind.gateway': 'filtering gateway',
  'dov.mail.kind.forwarding': 'forwarding',
  'dov.mail.kind.sending': 'sending service',
  'dov.mail.own': 'this domain',
  'dov.mail.spf': 'SPF',
  'dov.mail.spf.-': 'Hard fail (-all): only the listed senders may send.',
  'dov.mail.spf.~': 'Soft fail (~all): unlisted senders are marked, not refused.',
  'dov.mail.spf.?': 'Neutral (?all): says nothing about unlisted senders.',
  'dov.mail.spf.+': 'Pass (+all): anyone may send as this domain.',
  'dov.mail.spf.redirect': 'Redirected to {domain}.',
  'dov.mail.spf.noAll': 'No “all” at the end: unlisted senders are neutral.',
  'dov.mail.spf.none': 'No SPF record.',
  'dov.mail.spf.many': '{count} SPF records: receivers treat that as an error (permerror).',
  'dov.mail.spf.invalid': 'The SPF record is not valid.',
  'dov.mail.senders': 'Sends through',
  'dov.mail.dmarc': 'DMARC',
  'dov.mail.dmarc.reject': 'Reject (p=reject)',
  'dov.mail.dmarc.quarantine': 'Quarantine (p=quarantine)',
  'dov.mail.dmarc.none': 'Monitor only (p=none)',
  'dov.mail.dmarc.pct': '{pct}% of failing mail',
  'dov.mail.dmarc.reports': { one: 'reports to {count} address', other: 'reports to {count} addresses' },
  'dov.mail.dmarc.missing': 'No DMARC record.',
  'dov.mail.dmarc.many': '{count} DMARC records: receivers ignore them all.',
  'dov.mail.dmarc.invalid': 'The DMARC record is not valid.',

  'dov.web.alias': 'alias of {domain}',
  'dov.web.same': 'same addresses as {domain}',
  'dov.web.nxdomain': 'Not configured (NXDOMAIN)',
  'dov.web.nodata': 'No address',
  'dov.web.https': 'HTTPS record',
  'dov.web.httpsNone': 'none',

  'dov.certs.caa': 'CAA',
  'dov.certs.caaNone': 'No CAA record: any CA may issue certificates for this domain.',
  'dov.certs.caaDeny': 'CAA allows no CA to issue certificates.',
  'dov.certs.caaCritical': {
    one: 'CAA has an unknown tag marked critical ({tags}): CAs must refuse to issue certificates for this domain.',
    other: 'CAA has unknown tags marked critical ({tags}): CAs must refuse to issue certificates for this domain.'
  },
  'dov.certs.anyCa': 'any CA (CAA has no issue property)',
  'dov.certs.allowed': 'Allowed CAs',
  'dov.certs.wildcard': 'Wildcard certificates',
  'dov.certs.wildNone': 'no CA',
  'dov.certs.restricted': 'restricted',
  'dov.certs.restrictedTitle': 'Limited by RFC 8657 parameters (validation methods or one ACME account): see Domain Health’s CAA card.',
  'dov.certs.inherited': 'Published at {name}.',
  'dov.certs.ct': 'Issuers in Certificate Transparency',
  'dov.certs.ctRun': 'Look up issuers',
  'dov.certs.ctHint': 'One request to Cert Spotter (crt.sh only if Cert Spotter cannot answer), sending only {domain}.',
  'dov.certs.ctRunning': 'Asking Certificate Transparency…',
  'dov.certs.ctAgain': 'Look up again',
  'dov.certs.ctCount': { one: '{count} certificate', other: '{count} certificates' },
  'dov.certs.ctNewest': 'newest {date}',
  'dov.certs.ctAllowed': 'allowed by CAA',
  'dov.certs.ctRestricted': 'allowed by CAA, with restrictions',
  'dov.certs.ctDenied': 'not allowed by CAA',
  'dov.certs.ctUnknown': 'CA not known',
  'dov.certs.ctDeniedNote': {
    one: 'CAA does not allow {list}: its next renewal of these certificates will fail until CAA names it.',
    other: 'CAA does not allow {list}: their next renewal of these certificates will fail until CAA names them.'
  },
  'dov.certs.ctCriticalNote': {
    one: 'CAA’s critical flag blocks {list}: its next renewal of these certificates will fail as long as an unknown tag is marked critical.',
    other: 'CAA’s critical flag blocks {list}: their next renewal of these certificates will fail as long as an unknown tag is marked critical.'
  },
  'dov.certs.ctIssueNote': {
    one: 'CAA’s issue property does not allow {list} for {domain} itself: its next renewal of these certificates will fail until issue names it.',
    other: 'CAA’s issue property does not allow {list} for {domain} itself: their next renewal of these certificates will fail until issue names them.'
  },
  'dov.certs.ctFirstPage': 'From Cert Spotter’s first page of current certificates ({count} read); a longer list continues on later pages.',
  'dov.certs.ctCrtsh': 'From crt.sh ({count} current certificates), because Cert Spotter could not answer.',
  'dov.certs.ctEmpty': 'No current certificate for {domain} in Certificate Transparency.',

  'dov.saas.none': 'No service verification records in TXT.',
  'dov.saas.other': { one: '{count} other TXT record', other: '{count} other TXT records' },
  'dov.saas.note': 'The tokens themselves are not shown; DNS Lookup lists the records.',
  'dov.saas.chip': '{name} ×{count}',

  'dov.health.score': 'Score {score}/100',
  'dov.health.light.error': 'Problems found',
  'dov.health.light.warn': 'Needs attention',
  'dov.health.light.ok': 'Healthy',
  'dov.health.count.error': { one: '{count} error', other: '{count} errors' },
  'dov.health.count.warn': { one: '{count} warning', other: '{count} warnings' },
  'dov.health.count.info': { one: '{count} note', other: '{count} notes' },
  'dov.health.noProblems': 'No errors or warnings.',
  'dov.health.more': { one: '+{count} more in Domain Health', other: '+{count} more in Domain Health' },
  'dov.health.failed': 'The health checks could not run',
  'dov.lookupFailed': 'lookup failed',

  'dov.lk.title': 'Lookalike domains',
  'dov.lk.body': 'Typosquats of {domain} — misspellings, keyboard slips, lookalike letters, other endings — and which of them exist, when they were registered and whether they can take mail. The names are made in your browser; nothing is sent until you check them.',
  'dov.lk.open': 'Find lookalikes',
  'dov.lk.failed': 'The lookalike panel could not be loaded.'
});

registerStrings('tr', {
  'dov.domain': 'Alan adı',
  'dov.placeholder': 'example.com',
  'dov.run': 'Özeti oluştur',
  'dov.invalid': 'example.com gibi bir alan adı girin (IP adresi ya da com.tr gibi yalın bir uzantı değil).',
  'dov.privacy': 'Özeti oluştur’a basana kadar hiçbir şey gönderilmez: sonra DNS soruları DoH çözümleyicilerinize, tek bir RDAP sorgusu da kayıt kuruluşuna gider.',
  'dov.linkPrompt': 'Bir bağlantıdan açıldı: {domain} için Özeti oluştur’a basın. Henüz hiçbir şey gönderilmedi.',
  'dov.emptyLine': 'Sorguları geldikçe dolan kartlar; her birinde daha ayrıntılı araca bir bağlantı var.',
  'dov.status.na': '{count} kart okunamadı',
  'dov.progress': '{domain} özeti oluşturuluyor',
  'dov.progressCount': '{done}/{total} sorgu',
  'dov.builtAt': 'Oluşturuldu: {time}',
  'dov.stoppedAt': 'Durduruldu: {time} — bazı bölümler sorgulanmadı',
  'dov.reduced': '{host} adının kayıtlı alan adı olan {domain} özeti.',
  'dov.resultsTitle': '{domain} özeti',
  'dov.done': '{domain} özeti hazır',
  'dov.stopped': 'Durduruldu: gelen bölümler gösteriliyor',
  'dov.openIn': '{tool} aracında aç',
  'dov.openInTitle': '{tool} aracını {domain} ile açar',
  'dov.pending': 'Sorgulanıyor…',
  'dov.updating': 'Güncelleniyor…',
  'dov.notLooked': 'Sorgulanmadı: oluşturma durduruldu.',
  'dov.retried': '{card}: güncellendi',
  'dov.failedPart': 'Okunamadı',
  'dov.none': 'yok',

  'dov.card.registration': 'Kayıt',
  'dov.card.dns': 'DNS barındırma',
  'dov.card.mail': 'E-posta',
  'dov.card.web': 'Web',
  'dov.card.certs': 'Sertifikalar',
  'dov.card.saas': 'SaaS doğrulamaları',
  'dov.card.health': 'Sağlık',

  'dov.reg.registrar': 'Kayıt firması',
  'dov.reg.ianaId': 'IANA kimliği {id}',
  'dov.reg.created': 'Kayıt tarihi',
  'dov.reg.expires': 'Bitiş',
  'dov.reg.daysLeft': { zero: 'bugün sona eriyor', other: '{count} gün kaldı' },
  'dov.reg.daysAgo': '{count} gün önce sona erdi',
  'dov.reg.status': 'Durum',
  'dov.reg.lock': 'Transfer kilidi',
  'dov.reg.lockOn': 'Etkin',
  'dov.reg.lockOff': 'Yok',
  'dov.reg.lockOffNote': 'clientTransferProhibited olmadan, transfer kodunu bilen herkes alan adını başka bir kayıt firmasına taşıyabilir. Planlı bir transfer dışında etkin tutun.',
  'dov.reg.lockUnknown': 'kayıt kuruluşu durum bildirmiyor',
  'dov.reg.dnssec': 'DNSSEC yetkilendirmesi',
  'dov.reg.signed': 'İmzalı',
  'dov.reg.unsigned': 'İmzasız',
  'dov.reg.nameservers': 'Ad sunucuları (kayıt kuruluşu)',
  'dov.reg.registryDomain': 'Kayıtlı ad',
  'dov.reg.unsupported': '.{tld} kayıt kuruluşu RDAP hizmeti sunmuyor; kayıt firması ve tarihler tarayıcıdan okunamıyor.',
  'dov.reg.whois': 'Kayıt kuruluşunun WHOIS hizmetine bakın: {registry}',
  'dov.reg.iana': '.{tld} kayıt kuruluşu ve WHOIS sunucusu (IANA)',
  'dov.reg.notFound': 'Kayıtlı değil: kayıt kuruluşunda {domain} için kayıt yok.',
  'dov.reg.invalid': 'Bir kayıt kuruluşunun tuttuğu bir alan adı değil.',
  'dov.reg.failed': 'Kayıt bilgileri okunamadı',

  'dov.dns.provider': 'DNS sağlayıcısı',
  'dov.dns.own': 'Kendi ad sunucuları',
  'dov.dns.other': 'Diğer',
  'dov.dns.multi': '{count} sağlayıcının ad sunucuları: ya çoklu sağlayıcılı bir yapı ya da yarım kalmış bir taşıma.',
  'dov.dns.nameservers': 'Ad sunucuları',
  'dov.dns.noNs': 'Bu adda NS kaydı yok: bir zone’un tepesi (apex) değil.',
  'dov.dns.delegation': 'Kayıt kuruluşu {registry} sunucularına yönlendiriyor, ama zone {zone} listeliyor. Eşleşene kadar çözümleyiciler ikisinden birini kullanabilir.',
  'dov.dns.soa': 'SOA',
  'dov.dns.soaValue': 'birincil {mname} · seri {serial}',
  'dov.dns.serialDate': '{date} tarihinde değişti',
  'dov.dns.contact': 'İletişim',
  'dov.dns.dnssec': 'DNSSEC',
  'dov.dns.dnssec.validated': 'İmzalı ve doğrulanıyor',
  'dov.dns.dnssec.signed': 'İmzalı (üst zone’da DS var)',
  'dov.dns.dnssec.failing': 'İmzalı, ama anahtarlar doğrulanamadı: Alan Adı Sağlığı’na bakın',
  'dov.dns.dnssec.unsigned': 'İmzasız',
  'dov.nxdomain': 'Alan adı DNS’te mevcut değil (NXDOMAIN).',

  'dov.mail.receives': 'E-postayı alan',
  'dov.mail.noMx': 'MX kaydı yok: gönderenler alan adının kendi adresine yönelir.',
  'dov.mail.nullMx': 'E-posta kabul etmiyor (null MX).',
  'dov.mail.hosts': 'MX sunucuları',
  'dov.mail.kind.gateway': 'filtreleme ağ geçidi',
  'dov.mail.kind.forwarding': 'yönlendirme',
  'dov.mail.kind.sending': 'gönderim hizmeti',
  'dov.mail.own': 'bu alan adı',
  'dov.mail.spf': 'SPF',
  'dov.mail.spf.-': 'Kesin ret (-all): yalnızca listelenen göndericiler gönderebilir.',
  'dov.mail.spf.~': 'Yumuşak ret (~all): listede olmayan göndericiler işaretlenir, reddedilmez.',
  'dov.mail.spf.?': 'Nötr (?all): listede olmayan göndericiler hakkında bir şey söylemez.',
  'dov.mail.spf.+': 'Geçer (+all): herkes bu alan adı adına gönderebilir.',
  'dov.mail.spf.redirect': '{domain} adresine yönlendiriliyor.',
  'dov.mail.spf.noAll': 'Sonunda “all” yok: listede olmayan göndericiler nötr sayılır.',
  'dov.mail.spf.none': 'SPF kaydı yok.',
  'dov.mail.spf.many': '{count} SPF kaydı: alıcılar bunu hata (permerror) sayar.',
  'dov.mail.spf.invalid': 'SPF kaydı geçerli değil.',
  'dov.mail.senders': 'Gönderim hizmetleri',
  'dov.mail.dmarc': 'DMARC',
  'dov.mail.dmarc.reject': 'Reddet (p=reject)',
  'dov.mail.dmarc.quarantine': 'Karantina (p=quarantine)',
  'dov.mail.dmarc.none': 'Yalnızca izleme (p=none)',
  'dov.mail.dmarc.pct': 'başarısız postanın %{pct} kadarı',
  'dov.mail.dmarc.reports': 'raporlar {count} adrese gidiyor',
  'dov.mail.dmarc.missing': 'DMARC kaydı yok.',
  'dov.mail.dmarc.many': '{count} DMARC kaydı: alıcılar hepsini yok sayar.',
  'dov.mail.dmarc.invalid': 'DMARC kaydı geçerli değil.',

  'dov.web.alias': '{domain} adının takma adı',
  'dov.web.same': '{domain} ile aynı adresler',
  'dov.web.nxdomain': 'Yapılandırılmamış (NXDOMAIN)',
  'dov.web.nodata': 'Adres yok',
  'dov.web.https': 'HTTPS kaydı',
  'dov.web.httpsNone': 'yok',

  'dov.certs.caa': 'CAA',
  'dov.certs.caaNone': 'CAA kaydı yok: her CA bu alan adı için sertifika verebilir.',
  'dov.certs.caaDeny': 'CAA hiçbir CA’nın sertifika vermesine izin vermiyor.',
  'dov.certs.caaCritical': 'CAA’da kritik işaretli bilinmeyen etiket var ({tags}): otoriteler bu alan adı için sertifika vermeyi reddetmelidir.',
  'dov.certs.anyCa': 'her CA (CAA’da issue özelliği yok)',
  'dov.certs.allowed': 'İzinli CA’lar',
  'dov.certs.wildcard': 'Joker (wildcard) sertifikalar',
  'dov.certs.wildNone': 'hiçbir CA',
  'dov.certs.restricted': 'kısıtlı',
  'dov.certs.restrictedTitle': 'RFC 8657 parametreleriyle sınırlı (doğrulama yöntemleri ya da tek bir ACME hesabı): Alan Adı Sağlığı’nın CAA kartına bakın.',
  'dov.certs.inherited': '{name} adında yayımlanmış.',
  'dov.certs.ct': 'Certificate Transparency’deki sertifika sağlayıcıları',
  'dov.certs.ctRun': 'Sağlayıcıları sorgula',
  'dov.certs.ctHint': 'Cert Spotter’a tek istek (crt.sh yalnızca Cert Spotter yanıt veremezse); yalnızca {domain} gönderilir.',
  'dov.certs.ctRunning': 'Certificate Transparency sorgulanıyor…',
  'dov.certs.ctAgain': 'Yeniden sorgula',
  'dov.certs.ctCount': '{count} sertifika',
  'dov.certs.ctNewest': 'en yenisi {date}',
  'dov.certs.ctAllowed': 'CAA izin veriyor',
  'dov.certs.ctRestricted': 'CAA kısıtlarla izin veriyor',
  'dov.certs.ctDenied': 'CAA izin vermiyor',
  'dov.certs.ctUnknown': 'CA bilinmiyor',
  'dov.certs.ctDeniedNote': 'CAA {list} için izin vermiyor: CAA kaydına eklenene kadar bu sertifikaların bir sonraki yenilemesi başarısız olur.',
  'dov.certs.ctCriticalNote': 'CAA’daki kritik işaret {list} için engel oluşturuyor: bilinmeyen bir etiket kritik işaretli olduğu sürece bu sertifikaların bir sonraki yenilemesi başarısız olur.',
  'dov.certs.ctIssueNote': 'CAA’nın issue özelliği {domain} adının kendisi için şunlara izin vermiyor: {list}. issue bunları adlandırana kadar bu sertifikaların bir sonraki yenilemesi başarısız olur.',
  'dov.certs.ctFirstPage': 'Cert Spotter’ın geçerli sertifikalar listesinin ilk sayfasından ({count} okundu); daha uzun bir liste sonraki sayfalarda sürer.',
  'dov.certs.ctCrtsh': 'crt.sh’ten ({count} geçerli sertifika), çünkü Cert Spotter yanıt veremedi.',
  'dov.certs.ctEmpty': 'Certificate Transparency’de {domain} için geçerli sertifika yok.',

  'dov.saas.none': 'TXT’de hizmet doğrulama kaydı yok.',
  'dov.saas.other': '{count} başka TXT kaydı',
  'dov.saas.note': 'Doğrulama değerleri burada gösterilmez; kayıtları DNS Sorgulama listeler.',
  'dov.saas.chip': '{name} ×{count}',

  'dov.health.score': 'Puan {score}/100',
  'dov.health.light.error': 'Sorun bulundu',
  'dov.health.light.warn': 'İlgilenilmesi gerekiyor',
  'dov.health.light.ok': 'Sağlıklı',
  'dov.health.count.error': '{count} hata',
  'dov.health.count.warn': '{count} uyarı',
  'dov.health.count.info': '{count} bilgi',
  'dov.health.noProblems': 'Hata ya da uyarı yok.',
  'dov.health.more': 'Alan Adı Sağlığı’nda {count} tane daha',
  'dov.health.failed': 'Sağlık kontrolleri çalışamadı',
  'dov.lookupFailed': 'sorgu başarısız',

  'dov.lk.title': 'Benzer alan adları',
  'dov.lk.body': '{domain} adının yazım hatası taklitleri — yanlış yazımlar, klavye kaymaları, benzer harfler, başka uzantılar — ve bunlardan hangilerinin var olduğu, ne zaman kaydedildiği, posta alıp alamayacağı. Adlar tarayıcınızda üretilir; siz kontrol edene kadar hiçbir şey gönderilmez.',
  'dov.lk.open': 'Benzerleri bul',
  'dov.lk.failed': 'Benzer alan adları paneli yüklenemedi.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Where each card's "Open in <tool>" link goes, with the name filled in: Domain Health for the
 * registration, mail and health cards, DNS Lookup for the name servers and the TXT records, Global
 * DNS for the website, the Certificate view's "No file?" field (filled, not loaded) for the
 * certificates.
 * @param {string} card
 * @param {string} domain
 * @returns {{ view: string, params: Record<string, string> }}
 */
export function cardLink(card, domain) {
  switch (card) {
    case 'dns': return { view: 'lookup', params: { name: domain, type: 'NS,SOA,DS,DNSKEY' } };
    case 'web': return { view: 'global', params: { name: domain, type: 'A' } };
    case 'certs': return { view: 'cert', params: { host: domain, run: '0' } };
    case 'saas': return { view: 'lookup', params: { name: domain, type: 'TXT' } };
    default: return { view: 'health', params: { domain } };
  }
}

/**
 * The badge variant of an RDAP status flag (lib/passport.js rdapStatusFlags kind).
 * @param {'lock'|'hold'|'pending'|'ok'|'other'} kind
 * @returns {string}
 */
export function flagVariant(kind) {
  return kind === 'lock' ? 'ok' : kind === 'hold' || kind === 'pending' ? 'error' : 'neutral';
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * The note under the CT issuers CAA does not allow: a critical unknown tag blocks every CA; with
 * issuewild naming CAs and issue none, only the name itself is refused (the verdicts judge the
 * name, not wildcard certificates); else CAA names none of them.
 * @param {object|null} caa the Certificates card's `caa` (lib/passport.js certsCard)
 * @returns {string} an i18n key
 */
export function ctNoteKey(caa) {
  if (caa && caa.state === 'critical') return 'dov.certs.ctCriticalNote';
  if (caa && caa.state === 'present' && !caa.issue.length && caa.issuewild.length) return 'dov.certs.ctIssueNote';
  return 'dov.certs.ctDeniedNote';
}

let active = null;

/**
 * Mount the Domain overview view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;
  const routeName = ctx.params.name || '';
  const initialName = restored ? restored.name ?? '' : routeName;
  /** The name the last route carried (a link's, a carried target's): the prompt says it waits for a click. */
  let linkName = routeName;
  /** A link opened while a build runs: it goes into the box when the build ends or is stopped. */
  let waitingLink = null;

  /** The overview on screen: { domain, host, raw, controller, at, stopped, retrying: Set, ct: 'running'|null, ctController }. */
  let current = null;

  /* --- helpers ----------------------------------------------------------------------- */
  const tr = (key, params, fallback) => (hasString(key, getLang()) || hasString(key, 'en') ? t(key, params) : fallback);
  const localWords = { yes: 'common.yes', no: 'common.no', [LOOKUP_FAILED_PARAM]: 'dov.lookupFailed' };
  const localParams = (params) => Object.fromEntries(Object.entries(params || {})
    .map(([k, v]) => [k, typeof v === 'string' && Object.hasOwn(localWords, v) ? t(localWords[v]) : v]));
  const mono = (text) => h('span', { class: 'mono dov-break' }, text);
  const hostLink = (host, type = 'A,AAAA') => h('a', { class: 'mono dov-break', href: ctx.href('lookup', { name: host, type }) }, host);
  const ipLink = (ip) => h('a', { class: 'mono dov-ip', href: ctx.href('ip', { ips: ip }) }, ip);
  const chips = (items) => h('span', { class: 'cluster dov-chips' }, items);
  const na = (status) => NaMark([status]);
  const hostList = (hosts, render = mono) => h('span', { class: 'dov-list' }, hosts.map((x) => h('span', { class: 'dov-list-item' }, render(x))));

  /* --- region 2: the input (ui/template.js ToolInput) ----------------------------------- */
  const nameField = textInput({
    label: t('dov.domain'),
    value: initialName,
    placeholder: t('dov.placeholder'),
    mono: true,
    className: 'dov-name',
    attrs: { 'data-role': 'dov-name', 'data-shortcut': 'focus', inputmode: 'url', enterkeyhint: 'go' },
    onInput: () => syncRunBar(),
    onEnter: () => start()
  });
  const runBar = RunBar({
    label: t('dov.run'),
    dataset: { action: 'dov-run', shortcut: 'submit' },
    stopDataset: { action: 'dov-stop', shortcut: 'cancel' },
    onRun: () => start(),
    onStop: () => stop(),
    hasValue: () => !!nameField.value.trim()
  });
  const input = ToolInput({
    className: 'dov-form-card',
    fieldsClass: 'dov-form',
    label: t('nav.domain'),
    primary: nameField.el,
    run: runBar,
    privacy: PrivacyNote({ text: t('dov.privacy'), className: 'dov-sends' })
  });

  /* --- regions 4 and 8: the ready prompt, the result header, the cards -------------------- */
  const progress = ProgressBar({ format: (v, max) => t('dov.progressCount', { done: formatNumber(v), total: formatNumber(max) }) });
  /** A shared link waits for a click ("Opened from a link …"): above the result header, or in its place. */
  const prompt = ResultHeader({ className: 'result-ready dov-prompt' });
  prompt.setState('ready');
  const promptSlot = h('div', { class: 'dov-prompt-slot' });
  /** The overview's result header: in the page only while there is an overview (its `.dov-head` says so). */
  const head = ResultHeader({ className: 'dov-head' });
  const headSlot = h('div', { class: 'dov-head-wrap' });
  const emptyEl = h('div', { class: 'dov-empty' }, EmptyState({
    icon: 'id-card',
    message: t('dov.emptyLine'),
    checks: PASSPORT_CARDS.map((c) => t(`dov.card.${c}`))
  }));
  const lookalikeSlot = h('div', { class: 'dov-lookalike' });
  const slots = Object.fromEntries(PASSPORT_CARDS.map((c) => [c, h('div', { class: 'dov-slot', dataset: { card: c } })]));
  // No part of the form: Ctrl/Cmd+Enter on a card's button starts no new build.
  const results = h('div', { class: 'dov-results', hidden: true, dataset: { shortcutScope: 'results' } },
    h('div', { class: 'dov-grid' }, PASSPORT_CARDS.map((c) => slots[c])),
    lookalikeSlot);
  container.append(h('div', { class: 'dov-view' }, input.el, promptSlot, headSlot, emptyEl, results, runBar.float));
  ctx.onCleanup(() => runBar.dispose());

  /** The overview's actions (ResultActions: Copy summary, Report, Copy link), disabled while a build runs. */
  let actions = null;

  /* --- rendering ---------------------------------------------------------------------- */
  // The health card leaves the workspace's accepted risks out, read now (lib/waivers.js), as Domain Health does.
  const cardsOf = () => {
    const now = new Date();
    return passportCards(current ? current.raw : {}, { now, waivers: readWaivers(ctx.state.workspaceData('waivers'), { now }) });
  };

  /** The run bar and the input follow the state: compact once a build starts, "Run again" while the box asks for the overview on screen. */
  function syncRunBar() {
    const state = templateState({ running: !!(current && current.controller), result: !!current, ready: !promptSlot.hidden && !!promptSlot.firstChild });
    const box = passportDomain(nameField.value);
    runBar.setState(state);
    runBar.setRerun(state === 'done' && !!box && box.domain === current.domain);
    input.setCompact(inputCompact(state));
  }

  /** Bring a card into view with the keyboard focus on it (its Retry, when it has one): a status item's press. */
  function focusCard(cardId) {
    const card = slots[cardId] && slots[cardId].querySelector('.dov-card');
    if (!card) return;
    const retry = card.querySelector('[data-action="retry-source"]');
    card.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    if (retry) retry.focus({ preventScroll: true });
    else {
      card.setAttribute('tabindex', '-1');
      card.focus({ preventScroll: true });
    }
  }

  function renderHead() {
    if (!current) {
      head.el.remove();
      return;
    }
    if (!head.el.isConnected) headSlot.append(head.el);
    const { domain, host } = current;
    const running = !!current.controller;
    const cards = cardsOf();
    head.el.dataset.domain = domain;
    head.setState(running ? 'running' : 'done');
    head.set('title', ResultTitle({
      running,
      text: withSubject((p) => t(running ? 'dov.progress' : 'dov.resultsTitle', p), domain, { name: 'domain', className: 'dov-break' })
    }));
    const hc = cards.health;
    head.set('key', !running && hc.state === 'ready' && hc.grade
      ? h('span', { class: 'result-score', title: t('dov.health.score', { score: hc.score }) },
        h('span', { class: 'result-grade', dataset: { severity: hc.light } }, hc.grade),
        h('span', { class: 'result-score-value num' }, String(hc.score)), h('span', { class: 'result-score-max' }, '/100'))
      : null);
    head.set('meta', [
      host ? h('span', { class: 'dov-reduced' }, t('dov.reduced', { domain, host })) : null,
      !running && current.at ? RelativeTime(current.at, {
        className: 'dov-built',
        text: t(current.stopped ? 'dov.stoppedAt' : 'dov.builtAt', { time: formatRelative(current.at) })
      }) : null
    ]);
    head.set('progress', running ? progress.el : null);
    const status = !running ? passportStatus(cards).map((item) => ({
      ...item,
      text: item.key === 'na' ? t('dov.status.na', { count: item.count }) : t(`dov.health.count.${item.key}`, { count: item.count }),
      onPress: () => focusCard(item.key === 'na' ? item.cards[0] : 'health')
    })) : [];
    head.set('status', status.length ? StatusSummary({ items: status }).el : null);
    if (actions) actions.dispose();
    const summary = SummaryButton({
      kind: 'domain',
      plainLabel: t('result.plainTitle'),
      facts: () => (current && current.at && !current.controller ? passportSummaryFacts(cardsOf(), { domain: current.domain, host: current.host, at: current.at }) : null),
      url: () => (current ? ctx.shareUrl(permalinkParams('domain', { name: current.domain })) : null)
    });
    actions = ResultActions({
      summary,
      report: ReportButton(ctx, 'domain', () => current && current.at && !current.controller && { cards: cardsOf(), domain: current.domain, host: current.host, at: current.at }),
      // Copy link shares the overview on screen (not the box, which may hold a carried name).
      link: () => (current ? ctx.shareUrl({ name: current.domain }) : null)
    });
    actions.setDisabled(running);
    head.set('actions', actions.el);
    head.set('related', running ? null : RelatedLinks({
      self: 'domain',
      links: [
        { view: 'health', icon: 'activity', label: t('nav.health'), href: ctx.href('health', { domain }) },
        { view: 'lookup', icon: 'search', label: t('nav.lookup'), href: ctx.href('lookup', { name: domain, type: 'A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS' }) },
        { view: 'subdomains', icon: 'layers', label: t('nav.subdomains'), href: ctx.href('subdomains', { domain }) }
      ]
    }));
  }

  /** The "Open in <tool>" link of a card. */
  function openLink(card, domain) {
    const { view, params } = cardLink(card, domain);
    const tool = t(`nav.${view}`);
    return h('a', {
      class: 'btn btn-ghost btn-sm dov-open', href: ctx.href(view, params), title: t('dov.openInTitle', { tool, domain }), dataset: { open: view }
    }, h('span', { class: 'btn-label' }, t('dov.openIn', { tool })), Icon('arrow-right', { size: 14 }));
  }

  /** A card's Retry: its failed lookups (or, after a stop, its Look up: the ones never run). */
  function retryButton(card, lookups, { first = false } = {}) {
    const sources = [...new Set(lookups.map((l) => (l === 'rdap' ? 'rdap' : 'doh')))];
    const btn = RetryButton({ sources, first, target: t(`dov.card.${card.id}`), dataset: { card: card.id }, onClick: (e) => retryCard(card.id, lookups, e.currentTarget) });
    if (current && lookups.some((l) => current.retrying.has(l))) setRetryBusy(btn);
    return btn;
  }

  /** What the keyboard focus is on inside a card, to find it again in the card drawn next. */
  function focusKey(el, card) {
    if (el === card) return null;
    if (el.dataset.action) return `[data-action="${CSS.escape(el.dataset.action)}"]`;
    if (el.dataset.open) return `[data-open="${CSS.escape(el.dataset.open)}"]`;
    return null;
  }

  function renderCard(cardId, cards = cardsOf()) {
    const slot = slots[cardId];
    const card = cards[cardId];
    const running = !!(current && current.controller);
    const actions = [];
    let body;
    if (card.state === 'pending' && running) {
      body = h('p', { class: 'dov-pending muted text-sm', attrs: { 'aria-busy': 'true' } }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), ' ', t('dov.pending'));
    } else if (card.state === 'pending') {
      // A stopped build: what landed is shown, the rest offers to be looked up.
      body = h('div', { class: 'stack-sm' },
        h('p', { class: 'muted text-sm dov-not-looked' }, t('dov.notLooked')),
        partialBody(cardId, card));
      actions.push(retryButton(card, [...new Set([...card.retry, ...card.pending, ...(cardId === 'health' && current && current.raw.rdap === undefined ? ['rdap'] : [])])], { first: true }));
    } else {
      body = BODIES[cardId](card);
      // A Retry (or the health checks run again after one) is on its way: the answers on screen
      // stay until the new ones land.
      if (current && CARD_LOOKUPS[cardId].some((l) => current.retrying.has(l))) {
        body = h('div', { class: 'stack-sm' },
          h('p', { class: 'dov-updating muted text-sm', attrs: { 'aria-busy': 'true' } }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('dov.updating')),
          body);
      }
      // Offered as soon as the card is complete, while the rest of the build may still run.
      if (card.retry.length) actions.push(retryButton(card, card.retry));
    }
    if (current) actions.push(openLink(cardId, current.domain));
    const el = Card({
      title: t(`dov.card.${cardId}`),
      icon: CARD_ICONS[cardId],
      className: `dov-card dov-card-${cardId}`,
      actions: h('div', { class: 'dov-card-actions' }, actions),
      children: body
    });
    el.dataset.state = card.state === 'pending' && !running ? 'stopped' : card.state;
    el.dataset.failed = card.failures.length ? card.failures.map((f) => f.lookup).join(' ') : '';
    // A card redrawn under the keyboard focus (another of its lookups landed, a Retry ended) keeps
    // it: on the same control when the new card has one, else on the card itself.
    const old = slot.firstElementChild;
    const focused = old && old.contains(document.activeElement) ? document.activeElement : null;
    const key = focused ? focusKey(focused, old) : null;
    clear(slot);
    slot.append(el);
    if (focused) {
      const target = (key && el.querySelector(key)) || el;
      if (target === el) el.setAttribute('tabindex', '-1');
      target.focus({ preventScroll: true });
    }
  }

  /** What a stopped card can still show: nothing but the failures of what landed. */
  function partialBody(cardId, card) {
    return card.failures.length ? h('p', { class: 'text-sm dov-status' }, Icon('alert', { size: 14 }), ' ', card.failures.map((f) => statusText(f)).join(' · ')) : null;
  }

  function renderCards(ids = PASSPORT_CARDS) {
    const cards = cardsOf();
    for (const c of ids) renderCard(c, cards);
  }

  function renderAll() {
    const has = !!current;
    emptyEl.hidden = has || !promptSlot.hidden;
    results.hidden = !has;
    renderHead();
    if (has) renderCards();
    renderLookalike();
    syncRunBar();
  }

  /* --- lookalike domains (ui/lookalike-panel.js, loaded on the first click) ---------------- */
  /** The open panel ({ domain, panel }), and the domain whose panel a re-mount opens again. */
  let lookalike = null;
  let lookalikeWanted = restored && typeof restored.lookalike === 'string' ? restored.lookalike : null;

  function renderLookalike() {
    const domain = current ? current.domain : null;
    if (lookalike && lookalike.domain === domain) return;
    if (lookalike) lookalike.panel.destroy();
    lookalike = null;
    clear(lookalikeSlot);
    if (!domain) return;
    const open = Button({ label: t('dov.lk.open'), icon: 'eye', dataset: { action: 'lk-open' }, onClick: () => openLookalikes(domain, open) });
    lookalikeSlot.append(Card({
      title: t('dov.lk.title'), icon: 'eye', className: 'dov-lk-hook',
      children: h('div', { class: 'stack-sm' }, h('p', { class: 'text-sm muted dov-lk-body' }, t('dov.lk.body', { domain })), h('div', null, open))
    }));
    if (lookalikeWanted === domain) openLookalikes(domain, open, { focus: false });
  }

  /** Load the panel (once) in place of its hook; the panel sends nothing before its own Check. */
  function openLookalikes(domain, btn, { focus = true } = {}) {
    btn.disabled = true;
    loadLookalikes().then((m) => {
      if (ctx.signal.aborted || !current || current.domain !== domain || (lookalike && lookalike.domain === domain)) return;
      lookalike = { domain, panel: m.LookalikePanel({ ctx, domain }) };
      lookalikeWanted = domain;
      clear(lookalikeSlot);
      lookalikeSlot.append(lookalike.panel.el);
      const first = lookalike.panel.el.querySelector('[data-action="lk-check"]:not([hidden])') || lookalike.panel.el.querySelector('[data-role="lk-budget"]');
      if (focus && first) first.focus();
    }, () => {
      ctx.checkOutdated();
      if (ctx.signal.aborted) return;
      btn.disabled = false;
      ctx.toast(t('dov.lk.failed'), { type: 'error' });
    });
  }

  /* --- card bodies ------------------------------------------------------------------------ */
  const statusLine = (failures) => (failures.length
    ? h('p', { class: 'text-sm dov-status', dataset: { reason: failures[0].reason } }, Icon('alert', { size: 14 }), h('span', null, failures.map((f) => statusText(f)).join(' · ')))
    : null);
  const kv = (items) => KeyValueList(items.filter(Boolean), { className: 'dov-kv' });
  const failureFor = (card, lookup) => card.failures.find((f) => f.lookup === lookup) || null;

  function registrationBody(card) {
    const d = current.domain;
    if (card.outcome === 'unsupported') {
      const w = card.whois;
      return Alert({
        variant: 'info', compact: true, message: t('dov.reg.unsupported', { tld: card.tld || '' }),
        children: w ? h('p', { class: 'text-sm dov-whois' }, ExternalLink(w.url, w.iana ? t('dov.reg.iana', { tld: card.tld || '' }) : t('dov.reg.whois', { registry: w.name }))) : null
      });
    }
    if (card.outcome === 'not-found') return Alert({ variant: 'warn', compact: true, message: t('dov.reg.notFound', { domain: card.domain || d }) });
    if (card.outcome === 'invalid') return Alert({ variant: 'info', compact: true, message: t('dov.reg.invalid') });
    if (card.outcome === 'failed') {
      const f = card.failures[0];
      return h('div', { class: 'stack-sm' },
        statusLine(card.failures),
        kv([
          { key: t('dov.reg.registrar'), value: na(f) },
          { key: t('dov.reg.expires'), value: na(f) },
          { key: t('dov.reg.status'), value: na(f) },
          { key: t('dov.reg.nameservers'), value: na(f) }
        ]));
    }
    const daysBadge = card.daysLeft === null ? null : card.daysLeft < 0
      ? Badge(t('dov.reg.daysAgo', { count: -card.daysLeft }), { variant: 'error', icon: 'x-circle' })
      : Badge(t('dov.reg.daysLeft', { count: card.daysLeft }), { variant: card.expiry === 'ok' ? 'ok' : card.expiry, icon: 'clock' });
    const lock = card.transferLock === true
      ? Badge(t('dov.reg.lockOn'), { variant: 'ok', icon: 'lock' })
      : card.transferLock === false
        ? h('span', { class: 'stack-xs' }, Badge(t('dov.reg.lockOff'), { variant: 'warn', icon: 'unlock' }), h('span', { class: 'text-xs muted dov-note' }, t('dov.reg.lockOffNote')))
        : h('span', { class: 'muted' }, t('dov.reg.lockUnknown'));
    return kv([
      card.domain && card.domain !== d ? { key: t('dov.reg.registryDomain'), value: mono(card.domain) } : null,
      {
        key: t('dov.reg.registrar'),
        value: card.registrar ? h('span', null, card.registrarUrl ? ExternalLink(card.registrarUrl, card.registrar) : card.registrar,
          card.ianaId ? h('span', { class: 'muted text-xs' }, ` · ${t('dov.reg.ianaId', { id: card.ianaId })}`) : null) : null
      },
      { key: t('dov.reg.created'), value: card.created ? formatDate(card.created) : null },
      { key: t('dov.reg.expires'), value: card.expires ? h('span', { class: 'dov-expiry', dataset: { days: card.daysLeft, expiry: card.expiry } }, h('strong', null, formatDate(card.expires)), ' ', daysBadge) : null },
      { key: t('dov.reg.lock'), value: h('span', { class: 'dov-lock', dataset: { lock: String(card.transferLock) } }, lock) },
      { key: t('dov.reg.status'), value: card.flags.length ? chips(card.flags.map((x) => Badge(x.code, { variant: flagVariant(x.kind), icon: x.kind === 'lock' ? 'lock' : null }))) : null },
      { key: t('dov.reg.dnssec'), value: card.dnssec === null ? null : card.dnssec ? Badge(t('dov.reg.signed'), { variant: 'ok', icon: 'shield' }) : Badge(t('dov.reg.unsigned')) },
      { key: t('dov.reg.nameservers'), value: card.nameservers.length ? hostList(card.nameservers) : null }
    ]);
  }

  function dnsBody(card) {
    if (!card.exists) return Alert({ variant: 'error', compact: true, message: t('dov.nxdomain') });
    const { providers, self, other } = card.hosting;
    const nsFailure = failureFor(card, 'ns');
    const who = [
      ...providers.map((p) => Badge(p.name, { variant: 'accent', title: p.hosts.join(', ') })),
      self.length ? Badge(t('dov.dns.own'), { title: self.join(', ') }) : null,
      other.length ? Badge(`${t('dov.dns.other')} (${formatNumber(other.length)})`, { title: other.join(', ') }) : null
    ].filter(Boolean);
    const soa = card.soa;
    const soaFailure = failureFor(card, 'soa');
    const dsFailure = failureFor(card, 'ds') || (card.dnssec === 'failing' ? null : failureFor(card, 'dnskey'));
    const dnssecVariant = { validated: 'ok', signed: 'info', failing: 'error', unsigned: 'neutral' }[card.dnssec];
    return h('div', { class: 'stack-sm' },
      statusLine(card.failures),
      kv([
        { key: t('dov.dns.provider'), value: nsFailure ? na(nsFailure) : who.length ? chips(who) : null },
        { key: t('dov.dns.nameservers'), value: nsFailure ? na(nsFailure) : card.nameservers.length ? hostList(card.nameservers, (x) => hostLink(x)) : card.noNs ? h('span', { class: 'muted text-sm' }, t('dov.dns.noNs')) : null },
        {
          key: t('dov.dns.soa'),
          value: soaFailure ? na(soaFailure) : soa ? h('span', { class: 'stack-xs' },
            h('span', { class: 'mono text-sm dov-break' }, t('dov.dns.soaValue', { mname: soa.mname, serial: String(soa.serial) })),
            soa.serialDate ? h('span', { class: 'muted text-xs' }, t('dov.dns.serialDate', { date: soa.serialDate })) : null) : null
        },
        soa && soa.email ? { key: t('dov.dns.contact'), value: mono(soa.email) } : null,
        { key: t('dov.dns.dnssec'), value: card.dnssec ? Badge(t(`dov.dns.dnssec.${card.dnssec}`), { variant: dnssecVariant, icon: card.dnssec === 'validated' ? 'shield' : card.dnssec === 'failing' ? 'x-circle' : null }) : dsFailure ? na(dsFailure) : null }
      ]),
      providers.length > 1 ? h('p', { class: 'text-sm muted dov-note', dataset: { note: 'multi' } }, t('dov.dns.multi', { count: providers.length })) : null,
      card.delegation ? Alert({
        variant: 'warn', compact: true,
        message: t('dov.dns.delegation', { registry: card.delegation.registry.join(', '), zone: card.nameservers.join(', ') })
      }) : null);
  }

  function mailBody(card) {
    if (!card.exists) return Alert({ variant: 'error', compact: true, message: t('dov.nxdomain') });
    const mxFailure = failureFor(card, 'mx');
    const mx = card.mx;
    let receives = null;
    if (mxFailure) receives = na(mxFailure);
    else if (mx && mx.state === 'none') receives = h('span', { class: 'text-sm' }, t('dov.mail.noMx'));
    else if (mx && mx.state === 'null') receives = h('span', { class: 'text-sm' }, t('dov.mail.nullMx'));
    else if (mx) {
      receives = chips([
        ...mx.platforms.map((p) => Badge(p.kind === 'mailbox' ? p.name : `${p.name} · ${t(`dov.mail.kind.${p.kind}`)}`, { variant: 'accent', title: p.hosts.join(', ') })),
        ...(mx.other.length ? [Badge(`${t('dov.dns.other')} (${formatNumber(mx.other.length)})`, { title: mx.other.join(', ') })] : [])
      ]);
    }
    const txtFailure = failureFor(card, 'txt');
    const spf = card.spf;
    let spfValue = null;
    if (txtFailure) spfValue = na(txtFailure);
    else if (spf) {
      let line;
      if (spf.state === 'ok') line = spf.all ? t(`dov.mail.spf.${spf.all}`) : spf.redirect ? t('dov.mail.spf.redirect', { domain: spf.redirect }) : t('dov.mail.spf.noAll');
      else line = t(`dov.mail.spf.${spf.state}`, { count: spf.count });
      spfValue = h('span', { class: 'text-sm', dataset: { spf: spf.state === 'ok' ? spf.all || (spf.redirect ? 'redirect' : 'noall') : spf.state } }, line);
    }
    const dmarcFailure = failureFor(card, 'dmarc');
    const dm = card.dmarc;
    let dmarcValue = null;
    if (dmarcFailure) dmarcValue = na(dmarcFailure);
    else if (dm) {
      if (dm.state === 'ok') {
        const extra = [dm.pct < 100 ? t('dov.mail.dmarc.pct', { pct: dm.pct }) : null, dm.reports ? t('dov.mail.dmarc.reports', { count: dm.reports }) : null].filter(Boolean);
        dmarcValue = h('span', { class: 'text-sm', dataset: { dmarc: dm.policy || 'none' } },
          Badge(t(`dov.mail.dmarc.${dm.policy || 'none'}`), { variant: dm.policy === 'reject' ? 'ok' : dm.policy === 'quarantine' ? 'info' : 'warn' }),
          extra.length ? h('span', { class: 'muted text-xs' }, ` ${extra.join(' · ')}`) : null);
      } else dmarcValue = h('span', { class: 'text-sm', dataset: { dmarc: dm.state } }, t(dm.state === 'none' ? 'dov.mail.dmarc.missing' : `dov.mail.dmarc.${dm.state}`, { count: dm.count }));
    }
    const senders = spf && spf.state === 'ok' && (spf.senders.length || spf.other.length) ? chips([
      ...spf.senders.map((s) => Badge(s.name)),
      ...spf.other.slice(0, 3).map((o) => Badge(o, { mono: true })),
      spf.other.length > 3 ? h('span', { class: 'muted text-xs' }, t('common.moreCount', { count: spf.other.length - 3 })) : null
    ].filter(Boolean)) : null;
    return h('div', { class: 'stack-sm' },
      statusLine(card.failures),
      kv([
        { key: t('dov.mail.receives'), value: receives },
        mx && mx.hosts.length ? {
          key: t('dov.mail.hosts'),
          value: hostList(mx.hosts, (m) => h('span', null, h('span', { class: 'muted text-xs num' }, `${m.preference} `), hostLink(m.exchange), m.own ? h('span', { class: 'muted text-xs' }, ` · ${t('dov.mail.own')}`) : null))
        } : null,
        { key: t('dov.mail.spf'), value: spfValue },
        senders ? { key: t('dov.mail.senders'), value: senders } : null,
        { key: t('dov.mail.dmarc'), value: dmarcValue }
      ]));
  }

  function webHostValue(x) {
    if (x.state === 'failed') return na(x.failure);
    if (x.state === 'pending') return h('span', { class: 'muted' }, t('dov.pending'));
    if (x.state === 'nxdomain') return h('span', { class: 'text-sm muted' }, t('dov.web.nxdomain'));
    if (x.state === 'nodata') return h('span', { class: 'text-sm muted' }, t('dov.web.nodata'));
    const ips = [...x.ipv4, ...x.ipv6];
    const target = x.cnames.length ? x.cnames[x.cnames.length - 1] : null;
    return h('span', { class: 'stack-xs dov-webhost' },
      h('span', { class: 'cluster' }, KindBadge(x.classification),
        x.aliasOfApex ? h('span', { class: 'muted text-xs' }, t('dov.web.alias', { domain: current.domain }))
          : x.sameAsApex ? h('span', { class: 'muted text-xs' }, t('dov.web.same', { domain: current.domain })) : null),
      target && !x.aliasOfApex ? h('span', { class: 'text-xs muted dov-cname' }, 'CNAME → ', hostLink(target, 'CNAME')) : null,
      ips.length ? h('span', { class: 'cluster dov-ips' }, ips.slice(0, 3).map(ipLink), ips.length > 3 ? h('span', { class: 'muted text-xs' }, t('common.moreCount', { count: ips.length - 3 })) : null) : null);
  }

  function webBody(card) {
    if (!card.exists) return Alert({ variant: 'error', compact: true, message: t('dov.nxdomain') });
    const httpsText = (x, failure) => {
      if (failure) return na(failure);
      if (!x) return null;
      return x.present ? chips([Badge(t('common.yes'), { variant: 'ok', icon: 'check' }), ...x.alpn.map((a) => Badge(a, { mono: true }))]) : h('span', { class: 'muted text-sm' }, t('dov.web.httpsNone'));
    };
    const [apex, www] = card.hosts;
    return h('div', { class: 'stack-sm' },
      statusLine(card.failures),
      kv([
        { key: mono(apex.name), value: webHostValue(apex) },
        { key: mono(www.name), value: webHostValue(www) },
        { key: `${t('dov.web.https')} · ${apex.name}`, value: httpsText(card.https.apex, failureFor(card, 'https')) },
        { key: `${t('dov.web.https')} · ${www.name}`, value: httpsText(card.https.www, failureFor(card, 'wwwHttps')) }
      ]));
  }

  function caEntry(e) {
    return Badge(e.ca ? e.ca.name : e.issuer, {
      variant: 'accent', icon: e.restricted ? 'lock' : null,
      title: e.restricted ? `${e.issuer} · ${t('dov.certs.restrictedTitle')}` : e.issuer
    });
  }

  function ctSection(card) {
    const d = current.domain;
    const head = h('div', { class: 'dov-subtitle' }, t('dov.certs.ct'));
    if (current.ct === 'running') {
      return h('div', { class: 'stack-sm dov-ct', dataset: { ct: 'running' } }, head,
        h('p', { class: 'muted text-sm', attrs: { 'aria-busy': 'true' } }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), ' ', t('dov.certs.ctRunning')));
    }
    const run = (label, variant = 'secondary') => Button({ label, icon: 'search', size: 'sm', variant, dataset: { action: 'dov-ct' }, onClick: (e) => lookupCt(e.currentTarget) });
    const ct = card.ct;
    if (!ct) {
      return h('div', { class: 'stack-sm dov-ct', dataset: { ct: 'idle' } }, head,
        h('p', { class: 'muted text-xs' }, t('dov.certs.ctHint', { domain: d })),
        h('div', null, run(t('dov.certs.ctRun'))));
    }
    if (ct.state === 'failed') {
      const sources = ct.failures.map((f) => f.source);
      return h('div', { class: 'stack-sm dov-ct', dataset: { ct: 'failed' } }, head,
        h('p', { class: 'text-sm dov-status', dataset: { reason: ct.failures[0] ? ct.failures[0].reason : '' } },
          Icon('alert', { size: 14 }), h('span', null, ct.failures.map((f) => statusText(f)).join(' · '))),
        h('div', null, RetryButton({ sources, target: t('dov.certs.ct'), dataset: { action: 'dov-ct-retry' }, onClick: (e) => lookupCt(e.currentTarget) })));
    }
    const verdictBadge = (v) => {
      if (v === 'allowed') return Badge(t('dov.certs.ctAllowed'), { variant: 'ok', icon: 'check' });
      if (v === 'restricted') return Badge(t('dov.certs.ctRestricted'), { variant: 'info', icon: 'lock' });
      if (v === 'denied') return Badge(t('dov.certs.ctDenied'), { variant: 'error', icon: 'x-circle' });
      if (v === 'unknown') return Badge(t('dov.certs.ctUnknown'));
      return null;
    };
    const rows = ct.issuers.map((i) => h('li', { class: 'dov-issuer', dataset: { verdict: i.verdict || '' } },
      h('span', { class: 'dov-issuer-name', title: i.intermediates.join(', ') }, i.name),
      h('span', { class: 'muted text-xs' }, `${t('dov.certs.ctCount', { count: i.count })} · ${t('dov.certs.ctNewest', { date: formatDate(i.newest) })}`),
      verdictBadge(i.verdict)));
    const source = ct.provider === 'crtsh' ? t('dov.certs.ctCrtsh', { count: formatNumber(ct.certificates) }) : t('dov.certs.ctFirstPage', { count: formatNumber(ct.certificates) });
    return h('div', { class: 'stack-sm dov-ct', dataset: { ct: 'ok', provider: ct.provider } }, head,
      rows.length ? h('ul', { class: 'dov-issuers' }, rows) : h('p', { class: 'text-sm muted' }, t('dov.certs.ctEmpty', { domain: d })),
      // Behind a critical unknown tag no CA may issue, the ones CAA names too: adding them fixes nothing.
      // With issuewild naming CAs and issue none, the verdict is about the name itself, not wildcards.
      ct.notAllowed.length ? Alert({
        variant: 'warn', compact: true,
        message: t(ctNoteKey(card.caa), { list: ct.notAllowed.join(', '), count: ct.notAllowed.length, domain: d })
      }) : null,
      h('p', { class: 'muted text-xs' }, source),
      h('div', null, run(t('dov.certs.ctAgain'), 'ghost')));
  }

  function certsBody(card) {
    const caa = card.caa;
    const caaFailure = failureFor(card, 'caa');
    let caaPart;
    // A domain that does not exist has no CAA to read; CT may still list certificates issued for it.
    if (!card.exists) caaPart = Alert({ variant: 'error', compact: true, message: t('dov.nxdomain') });
    else if (caaFailure) caaPart = kv([{ key: t('dov.certs.caa'), value: na(caaFailure) }]);
    else if (!caa) caaPart = null;
    else if (caa.state === 'none') caaPart = h('p', { class: 'text-sm', dataset: { caa: 'none' } }, t('dov.certs.caaNone'));
    else {
      const noCa = () => h('span', { class: 'muted text-sm' }, t('dov.certs.wildNone'));
      let rows;
      if (caa.state === 'critical') {
        rows = Alert({ variant: 'error', compact: true, message: t('dov.certs.caaCritical', { tags: caa.criticalTags.join(', '), count: caa.criticalTags.length }) });
      } else if (caa.state === 'deny-all') rows = Alert({ variant: 'error', compact: true, message: t('dov.certs.caaDeny') });
      else {
        // 'unrestricted': no issue property, so any CA for the name itself; issuewild may still limit wildcards.
        const allowed = caa.state === 'unrestricted' ? h('span', { class: 'text-sm' }, t('dov.certs.anyCa')) : caa.issue.length ? chips(caa.issue.map(caEntry)) : noCa();
        rows = kv([
          { key: t('dov.certs.allowed'), value: allowed },
          caa.wildcardOnly ? { key: t('dov.certs.wildcard'), value: caa.issuewild.length ? chips(caa.issuewild.map(caEntry)) : noCa() } : null
        ]);
      }
      caaPart = h('div', { class: 'stack-xs', dataset: { caa: caa.state } }, rows,
        caa.foundAt && caa.foundAt !== current.domain ? h('p', { class: 'muted text-xs' }, t('dov.certs.inherited', { name: caa.foundAt })) : null);
    }
    return h('div', { class: 'stack-sm' }, statusLine(card.failures), caaPart, ctSection(card));
  }

  function saasBody(card) {
    if (!card.exists) return Alert({ variant: 'error', compact: true, message: t('dov.nxdomain') });
    const txtFailure = failureFor(card, 'txt');
    if (txtFailure) return h('div', { class: 'stack-sm' }, statusLine(card.failures), kv([{ key: 'TXT', value: na(txtFailure) }]));
    const s = card.saas;
    if (!s) return null;
    return h('div', { class: 'stack-sm' },
      s.vendors.length
        ? h('ul', { class: 'dov-vendors', attrs: { 'aria-label': t('dov.card.saas') } }, s.vendors.map((v) => h('li', { class: 'dov-vendor', dataset: { vendor: v.id }, title: v.key },
          Badge(v.count > 1 ? t('dov.saas.chip', { name: v.name, count: v.count }) : v.name, { variant: 'accent' }))))
        : h('p', { class: 'text-sm muted' }, t('dov.saas.none')),
      s.other ? h('p', { class: 'text-xs muted' }, t('dov.saas.other', { count: s.other })) : null,
      h('p', { class: 'text-xs muted' }, t('dov.saas.note')));
  }

  function healthBody(card) {
    if (card.failures.length) return h('div', { class: 'stack-sm' }, Alert({ variant: 'error', compact: true, title: t('dov.health.failed') }), statusLine(card.failures));
    const s = card.summary;
    // The count says the severity itself ("5 errors"): its icon is not read out.
    const counts = ['error', 'warn', 'info'].filter((k) => s[k]).map((k) => h('span', { class: ['dov-count', `dov-count-${k}`] },
      h('span', { class: 'dov-count-icon', attrs: { 'aria-hidden': 'true' } }, SeverityIcon(k, { size: 14 })), ' ', t(`dov.health.count.${k}`, { count: s[k] })));
    return h('div', { class: 'stack-sm' },
      h('div', { class: ['dov-score', `dov-score-${card.light}`], dataset: { light: card.light, score: card.score } },
        h('span', { class: ['dov-lamp', `dov-lamp-${card.light}`], attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'dov-score-verdict' }, t(`dov.health.light.${card.light}`)),
        h('span', { class: 'dov-score-value num' }, t('dov.health.score', { score: card.score }))),
      counts.length ? h('div', { class: 'cluster text-sm' }, counts) : null,
      waivedLines(card),
      card.problems.length
        ? h('ul', { class: 'dov-problems' }, card.problems.map((p) => h('li', { class: ['dov-problem', `dov-sev-${p.severity}`], dataset: { id: p.id } },
          SeverityIcon(p.severity, { size: 15 }), h('span', null, tr(p.titleKey, localParams(p.params), p.id)))))
        : h('p', { class: 'text-sm muted' }, t(card.waived ? 'wvr.noneOpen' : 'dov.health.noProblems')),
      card.moreProblems ? h('p', { class: 'text-xs muted' }, t('dov.health.more', { count: card.moreProblems })) : null);
  }

  /** The accepted risks the score leaves out and the score with them, and those whose waiver is over, in Domain Health's words. */
  function waivedLines(card) {
    const w = card.waived;
    if (!w && !card.expired) return null;
    return h('div', { class: 'dov-waived text-sm', dataset: { role: 'dov-waived', count: String(w ? w.count : 0) } },
      w ? h('p', null, Icon('shield', { size: 14 }), ' ', t('wvr.count', { count: w.count, date: w.until }), ' ',
        h('span', { class: 'muted', dataset: { role: 'dov-with-waived', score: String(w.score) } }, t('wvr.withThem', { count: w.count, score: w.score, grade: w.grade }))) : null,
      card.expired ? h('p', { dataset: { role: 'dov-waived-expired' } }, Icon('clock', { size: 14 }), ' ', t('wvr.expiredCount', { count: card.expired })) : null);
  }

  const BODIES = { registration: registrationBody, dns: dnsBody, mail: mailBody, web: webBody, certs: certsBody, saas: saasBody, health: healthBody };

  /* --- the box and the link prompt -------------------------------------------------- */
  /** The domains the box holds, as a build reads them (what a carried target may replace). */
  const boxDomains = (text) => {
    const p = passportDomain(text);
    return [p ? p.domain : String(text).trim()];
  };

  /**
   * The domain the box last took from a carried target: a newer one replaces it while the box
   * still holds it (lib/session.js fillReplaces). A re-mount keeps it; a build forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null) : (isFillOnly(ctx.params) && routeName) || null;

  /**
   * "Opened from a link …" (the template's ready state, DESIGN §5.2): the box holds a name no
   * overview on screen is about, and nothing runs.
   */
  function renderPrompt() {
    const p = passportDomain(nameField.value);
    const linked = linkName ? passportDomain(linkName) : null;
    const fromRoute = !!p && !!linked && linked.domain === p.domain;
    const show = fromRoute && !(current && (current.controller || current.domain === p.domain));
    clear(promptSlot);
    promptSlot.hidden = !show;
    if (show) {
      prompt.set('title', ResultTitle({ icon: 'link', text: h('span', { dataset: { prompt: 'link' } }, t('dov.linkPrompt', { domain: p.domain })) }));
      promptSlot.append(prompt.el);
    }
    emptyEl.hidden = !!current || show;
    syncRunBar();
  }

  /** A name from a route: into the box while it is empty or holds the last build or the last carried name. */
  function takeName(name, { fillOnly }) {
    const last = current ? [current.domain] : null;
    if (fillReplaces(nameField.value, last, boxDomains, carried)) {
      nameField.value = name;
      nameField.setError(null);
      carried = fillOnly ? name : null;
    }
  }

  /* --- run ------------------------------------------------------------------------------ */
  function setRunning(on) {
    // The keyboard focus follows the button it was on (Build ⇄ Stop), never falling to <body>.
    runBar.setRunning(on);
    nameField.input.readOnly = on;
    if (actions) actions.setDisabled(on);
    ctx.setBusy(on);
    syncRunBar();
  }

  function abortAll() {
    if (!current) return;
    for (const c of [current.controller, current.ctController, ...current.retryControllers]) if (c) c.abort();
  }

  function stop() {
    if (current && current.controller) current.controller.abort();
  }

  /** Build the overview of the box's domain (a click, Enter, Ctrl/Cmd+Enter or Run again). */
  function start() {
    nameField.setError(null);
    const parsed = passportDomain(nameField.value);
    if (!parsed) {
      nameField.setError(t('dov.invalid'));
      nameField.focus();
      return;
    }
    if (!ctx.requireOnline()) return;
    nameField.value = parsed.domain;
    carried = null;
    waitingLink = null;
    ctx.setParams({ name: parsed.domain });
    ctx.runStarted(parsed.domain);
    run(parsed);
  }

  async function run({ domain, host }) {
    abortAll();
    const controller = new AbortController();
    const state = {
      domain, host, raw: { domain }, controller, at: null, stopped: false,
      retrying: new Set(), retryControllers: new Set(), ct: null, ctController: null, healthStale: false
    };
    current = state;
    progress.setVariant('default');
    progress.setLabel(t('dov.progress', { domain }));
    progress.set(0, PASSPORT_LOOKUPS.length);
    renderPrompt();
    renderAll();
    setRunning(true);
    let done = 0;
    try {
      const dns = await ctx.getDns();
      await buildPassport(domain, {
        dns,
        signal: mergeSignals(ctx.signal, controller.signal),
        onLookup: (lookup, result) => {
          if (current !== state) return;
          state.raw[lookup] = result;
          done += 1;
          progress.set(done, PASSPORT_LOOKUPS.length);
          renderCards(cardsOfLookup(lookup));
          // A Retry replaced an answer this health run had read: it runs again on the new one.
          if (lookup === 'health' && state.healthStale) {
            state.healthStale = false;
            refreshHealth(state);
          }
        }
      });
      if (current !== state) return;
      state.at = new Date();
      progress.done(t('common.done'));
      announce(t('dov.done', { domain }));
    } catch (err) {
      if (current !== state) return;
      state.at = new Date();
      if (err && err.name === 'AbortError') {
        state.stopped = true;
        if (!ctx.signal.aborted) announce(t('dov.stopped'));
      } else {
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
    } finally {
      if (current === state) {
        state.controller = null;
        if (!ctx.signal.aborted) {
          setRunning(false);
          renderHead();
          renderCards();
          if (waitingLink) {
            takeName(waitingLink.name, { fillOnly: waitingLink.fillOnly });
            waitingLink = null;
          }
          renderPrompt();
        }
      }
    }
  }

  /**
   * A card's Retry (or, after a stop, its Look up): only those lookups again, past the DNS
   * cache. The content stays until the answers land; the keyboard focus stays on the card. It
   * runs on its own controller, so a Retry pressed while the build still runs asks at once (Stop
   * ends the build, not the Retry).
   */
  async function retryCard(cardId, lookups, btn) {
    const state = current;
    if (!state || lookups.some((l) => state.retrying.has(l))) return;
    if (!ctx.requireOnline()) return;
    const controller = new AbortController();
    state.retryControllers.add(controller);
    for (const l of lookups) state.retrying.add(l);
    setRetryBusy(btn);
    let landed = false;
    try {
      const dns = await ctx.getDns();
      await buildPassport(state.domain, {
        dns,
        lookups,
        noCache: true,
        signal: mergeSignals(ctx.signal, controller.signal),
        onLookup: (lookup, result) => {
          if (current !== state) return;
          state.raw[lookup] = result;
          state.retrying.delete(lookup);
          // The build's health run shares the build's answers, the failed one too: once it lands
          // it runs again (a health result already on screen is refreshed below).
          if (state.controller && HEALTH_LOOKUPS.includes(lookup) && state.raw.health === undefined) state.healthStale = true;
          renderCards(cardsOfLookup(lookup));
        }
      });
      landed = true;
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      state.retryControllers.delete(controller);
      for (const l of lookups) state.retrying.delete(l);
    }
    if (current !== state || ctx.signal.aborted) return;
    // Every card the lookups feed, drawn once more without the busy Retry (after a failure too).
    renderCards(PASSPORT_CARDS.filter((c) => lookups.some((l) => cardsOfLookup(l).includes(c))));
    if (!landed) return;
    // While the build runs, it stamps the overview and draws the head when it ends.
    if (!state.controller) {
      if (state.stopped && PASSPORT_LOOKUPS.every((l) => state.raw[l] !== undefined)) state.stopped = false;
      state.at = new Date();
      renderHead();
    }
    // The keyboard focus stays on the card (renderCard kept it there): on its Retry when a lookup
    // still failed, else on the card; unless it has moved on meanwhile.
    const card = slots[cardId].querySelector('.dov-card');
    const again = card && card.querySelector('[data-action="retry-source"]');
    const active = document.activeElement;
    if (card && (!active || active === document.body || card.contains(active))) {
      if (again) again.focus();
      else if (active !== card) {
        card.setAttribute('tabindex', '-1');
        card.focus({ preventScroll: true });
      }
    }
    const failures = cardsOf()[cardId].failures;
    announce(failures.length ? failures.map((f) => statusText(f)).join(' · ') : t('dov.retried', { card: t(`dov.card.${cardId}`) }));
    if (lookups.some((l) => HEALTH_LOOKUPS.includes(l)) && state.raw.health && !state.retrying.has('health')) refreshHealth(state);
  }

  /**
   * The health checks again after a Retry of a DNS lookup they share: the retried answers are in
   * the resolver's cache now, and so is every other one, so this costs little; the card says
   * "Updating…" meanwhile and keeps the score it had.
   */
  async function refreshHealth(state) {
    const controller = new AbortController();
    state.retryControllers.add(controller);
    state.retrying.add('health');
    renderCard('health');
    try {
      const dns = await ctx.getDns();
      await buildPassport(state.domain, {
        dns,
        lookups: ['health'],
        signal: mergeSignals(ctx.signal, controller.signal),
        onLookup: (lookup, result) => { if (current === state) state.raw.health = result; }
      });
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      state.retryControllers.delete(controller);
      state.retrying.delete('health');
    }
    if (current === state && !ctx.signal.aborted) renderCard('health');
  }

  /** The certificates card's CT lookup: one Cert Spotter request (crt.sh as its fallback). */
  async function lookupCt(btn) {
    const state = current;
    if (!state || state.ct === 'running') return;
    if (!ctx.requireOnline()) return;
    const controller = new AbortController();
    state.ctController = controller;
    state.ct = 'running';
    renderCard('certs');
    try {
      const result = await lookupCtIssuers(state.domain, { signal: mergeSignals(ctx.signal, controller.signal) });
      if (current !== state) return;
      state.raw.ct = result;
      const ct = cardsOf().certs.ct;
      announce(ct.state === 'ok' ? `${t('dov.certs.ct')}: ${ct.issuers.map((i) => i.name).join(', ') || t('dov.none')}` : ct.failures.map((f) => statusText(f)).join(' · '));
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      if (state.ctController === controller) state.ctController = null;
      if (state.ct === 'running') state.ct = null;
      if (current === state && !ctx.signal.aborted) {
        renderCard('certs');
        // The button pressed was redrawn: the focus goes to the new one, if it was still on the card.
        const again = slots.certs.querySelector('[data-action="dov-ct"], [data-action="dov-ct-retry"]');
        const active = document.activeElement;
        if (again && btn && !btn.isConnected && (!active || active === document.body || slots.certs.contains(active))) again.focus();
      }
    }
  }

  /* --- initial state ------------------------------------------------------------------- */
  if (restored && restored.run) {
    const r = restored.run;
    current = {
      domain: r.domain, host: r.host || null, raw: r.raw, controller: null, at: r.at ? new Date(r.at) : new Date(), stopped: !!r.stopped,
      retrying: new Set(), retryControllers: new Set(), ct: null, ctController: null
    };
  }
  // A route's name only fills the box: a shared link, a carried target (`run=0`) or a nav link
  // alike. Nothing is sent before Build overview.
  if (routeName && !restored) takeName(routeName, { fillOnly: isFillOnly(ctx.params) });
  else if (routeName && isFillOnly(ctx.params)) takeName(routeName, { fillOnly: true });
  renderAll();
  renderPrompt();

  // The health card follows the workspace's accepted risks (Domain Health, the Workspaces dialog, another tab).
  ctx.onCleanup(ctx.state.subscribe((change) => {
    const workspace = change.key === 'workspace' || change.key === 'cleared';
    const waivers = change.key === 'workspaceData' && !!(change.value && Array.isArray(change.value.parts) && change.value.parts.includes('waivers'));
    if ((workspace || waivers) && current) {
      renderCard('health');
      // The head's grade and counts leave the accepted risks out too.
      if (!current.controller) renderHead();
    }
  }));

  active = {
    teardown() {
      abortAll();
      if (lookalike) lookalike.panel.destroy();
    },
    snapshot() {
      const r = current && !current.controller && current.at ? current : null;
      return {
        name: nameField.value,
        carried,
        lookalike: lookalike ? lookalike.domain : null,
        run: r ? { domain: r.domain, host: r.host, raw: r.raw, at: r.at, stopped: r.stopped } : null
      };
    },
    result() {
      if (!current || current.controller || !current.at) return null;
      return { subject: current.domain, at: current.at, params: { name: current.domain } };
    },
    rerun() {
      if (current) nameField.value = current.domain;
      start();
    },
    update(params) {
      const name = params.name;
      if (!name) return false;
      linkName = name;
      if (current && current.controller) {
        // A running build keeps its box; the link fills it when the build ends.
        waitingLink = { name, fillOnly: isFillOnly(params) };
        return true;
      }
      takeName(name, { fillOnly: isFillOnly(params) });
      renderPrompt();
      return true;
    }
  };
}

/** Abort a running build, retry or CT lookup. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * The box and the finished (or stopped) overview, carried over a language re-mount and kept for
 * the next visit (no new lookups).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The overview on screen (kept by the shell when the view is left), or null while none is or a
 * build runs.
 * @returns {{ subject: string, at: Date, params: { name: string } }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: build the overview of the same domain again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take a new route's name without a re-mount: it only fills the box (never runs).
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
