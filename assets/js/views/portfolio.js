/**
 * views/portfolio.js — "Domain portfolio" (`#/portfolio?domains=a,b`): many domains, one row each,
 * and the policy audit of the workspace. lib/portfolio.js runs the lookups and turns them into
 * facts; lib/policy.js reads the policy and evaluates it; this view draws them:
 *
 * - The list: pasted domains (host names and URLs give their registrable domain), filled in from
 *   the workspace's recent domains while the box is empty; nothing is sent until Check portfolio.
 * - The table (Domains tab): per domain the expiry with its countdown (coloured by the days left),
 *   the registry status flags read for risk, the registrar, DNSSEC, the name servers' own domains
 *   with their expiry, CAA and the mail posture (SPF, DMARC, DKIM, MTA-STS / TLS-RPT, the
 *   lock-down of a domain that takes no mail). Rows fill as the lookups land; a lookup that
 *   failed is "⚠ n/a" in its cell with a Retry of that cell's lookups only. Tiles and a filter pick
 *   out what needs a look; columns sort. Exports: CSV, JSON and an .ics calendar of every expiry.
 * - Domain security tab: CSC's eight measures per domain with a 0–8 score, the portfolio's
 *   adoption of each measure and a CSV (ui/secscore-panel.js over lib/secscore.js, loaded with
 *   the tab on its first use): computed from the check on screen, nothing more is sent.
 * - The policy (Policy audit tab): presets, one row per rule and the JSON (kept in step), kept in
 *   the workspace; the matrix domain × rule with the evidence of each cell, CSV and JSON. A failed
 *   cell offers "Accept…" (ui/waivers.js: a reason, an owner and an end date, kept in the
 *   workspace's waivers, lib/waivers.js): an accepted rule is "Accepted" — neither a pass nor a
 *   fail, counted on its own — until its end date.
 * - Certificates (CT) tab: the CT watchlist of the same domains (ui/ctwatch-panel.js over
 *   lib/ctwatch.js, loaded with the tab on its first use).
 *
 * The run belongs to the module: it keeps going on another view (the tab title, the nav entry and
 * the favicon show its progress), a language switch keeps it, and another workspace or "Delete all
 * local data" drops it. Copy summary: lib/portfoliosummary.js.
 */

import { h, clear, debounce } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, EmptyState, ErrorBanner, ExternalLink, Icon, ProgressBar, Spinner, StatCard, Tabs,
  announce, checkbox, select, textInput, textarea, toast
} from '../ui/components.js';
import { registerStrings, formatBytes, formatNumber, formatDate, formatDateTime, formatRelative, t as translate } from '../i18n.js';
import {
  PORTFOLIO_CELLS, CELL_LOOKUPS, LOOKUP_SOURCES, PORTFOLIO_MAX_DOMAINS, PORTFOLIO_DKIM_SELECTORS, PORTFOLIO_LOOKUPS, CRITICAL_STATUSES,
  parsePortfolioInput, createPortfolio, cellFailures, rowRisk, unregisteredNsDomains, expiryEvents, expiryUid, exportRow, EXPORT_COLUMNS, portfolioSummaryFacts
} from '../lib/portfolio.js';
import {
  POLICY_RULES, POLICY_PRESET_IDS, POLICY_OPS, POLICY_I18N, POLICY_MAX_CHARS, parsePolicy, policyText, presetPolicy, auditPortfolio, auditCsv,
  auditJson, evidenceText, policyRule, waiverText
} from '../lib/policy.js';
import { WAIVERS_I18N, readWaivers } from '../lib/waivers.js';
import { corporateRegistrar } from '../lib/registrars.js';
import { buildCalendar } from '../lib/ics.js';
import { toCsv, toJson } from '../lib/export.js';
import { registerSummaryBuilder, permalinkParams } from '../lib/summarycore.js';
import { portfolioSummary, PORTFOLIO_SUMMARY_I18N } from '../lib/portfoliosummary.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { mergeSignals, onceAsync } from '../lib/util.js';
import { NaMark, RetryButton, setRetryBusy, statusText } from '../ui/source-status.js';
import { SummaryButton } from '../ui/summary-button.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { startJob, NotifyButton } from '../ui/jobs.js';
import { workspaceLabel, storageErrorText } from '../ui/workspace-ui.js';
import { state as stateSingleton } from '../state.js';

/** Route id (`#/portfolio`). */
export const id = 'portfolio';
/** i18n key of the page title. */
export const titleKey = 'nav.portfolio';
/** Icon name (ui/components.js Icon). */
export const icon = 'box';

/** The table's filters, in the select's order. */
export const PORTFOLIO_FILTERS = Object.freeze(['all', 'attention', 'expiring', 'critical', 'unlocked', 'ns', 'nordap', 'failed', 'policy']);
/** The tiles above the table: each one a filter. */
export const PORTFOLIO_TILES = Object.freeze(['expiring', 'critical', 'unlocked', 'ns', 'failed']);
/** The risks a domain cell names (lib/portfolio.js rowRisk), 'ok' left out. */
export const RISK_BADGES = Object.freeze(['critical', 'ns-unregistered', 'pending-transfer', 'expired', 'expiring', 'ns-expiring', 'hijack', 'warn']);
/** A link carries the list only up to this many domains (a summary's link too). */
export const MAX_LINK_DOMAINS = 50;
/** The views' tabs. */
export const PORTFOLIO_TABS = Object.freeze(['domains', 'security', 'policy', 'ct']);
/** The Certificates (CT) tab's panel (with lib/ctwatch.js), on the tab's first use. */
const loadCtPanel = onceAsync(() => import('../ui/ctwatch-panel.js'));
/** The Domain security tab's panel (with lib/secscore.js), on the tab's first use. */
const loadSecurityPanel = onceAsync(() => import('../ui/secscore-panel.js'));
/** ui/waivers.js: the "Accept…" dialog of a failed rule, on its first click. */
const loadWaivers = onceAsync(() => import('../ui/waivers.js'));

registerSummaryBuilder('portfolio', portfolioSummary);
registerStrings('en', PORTFOLIO_SUMMARY_I18N.en);
registerStrings('tr', PORTFOLIO_SUMMARY_I18N.tr);
registerStrings('en', POLICY_I18N.en);
registerStrings('tr', POLICY_I18N.tr);
registerStrings('en', WAIVERS_I18N.en);
registerStrings('tr', WAIVERS_I18N.tr);

registerStrings('en', {
  'pf.domains': 'Domains',
  'pf.placeholder': 'example.com\nexample.org',
  'pf.hint': 'One or more per line; a host name or a URL counts as its registrable domain. At most {max}.',
  'pf.count': { one: '{count} domain', other: '{count} domains' },
  'pf.invalid': 'Not a domain, left out: {list}',
  'pf.capped': { one: 'Only the first {max} domains are checked: {count} more is left out.', other: 'Only the first {max} domains are checked: {count} more are left out.' },
  'pf.prefilled': 'Filled in from this workspace’s recent domains: edit the list, then press Check portfolio.',
  'pf.linkPrompt': { one: 'Opened from a link: press Check portfolio to look up {count} domain. Nothing has been sent yet.', other: 'Opened from a link: press Check portfolio to look up {count} domains. Nothing has been sent yet.' },
  'pf.run': 'Check portfolio',
  'pf.dkim': 'Look for DKIM keys at {count} common selectors',
  'pf.dkimHint': '{queries} more DNS questions per domain. Off, the DKIM column and rule say “not checked”.',
  'pf.sends': 'Nothing is sent until you press Check portfolio. Then each domain’s DNS questions go to your DoH resolvers and its registration lookup to the registry’s RDAP server (rdap.org only when the registry cannot be reached, at most one request a second). The name servers’ own domains are looked up the same way, once each.',
  'pf.needOne': 'Enter at least one domain such as example.com.',
  'pf.emptyTitle': 'Every domain of a customer in one table',
  'pf.emptyBody': 'Expiry with a countdown, registry status flags (a missing transfer lock, holds, pending deletes), the registrar, DNSSEC, the name servers’ own domains and their expiry, CAA and the mail posture — then an expiry calendar and a policy audit.',
  'pf.progress': { one: 'Checking {count} domain', other: 'Checking {count} domains' },
  'pf.progressCount': '{done} of {total} domains',
  'pf.resultsTitle': { one: 'Portfolio of {count} domain', other: 'Portfolio of {count} domains' },
  'pf.checkedAt': 'Checked {time}',
  'pf.stoppedAt': { one: 'Stopped {time}: {count} domain not looked up in full', other: 'Stopped {time}: {count} domains not looked up in full' },
  'pf.runningNow': 'Looking up…',
  'pf.done': { one: 'Portfolio of {count} domain checked', other: 'Portfolio of {count} domains checked' },
  'pf.stopped': 'Stopped: the lookups that landed are shown',
  'pf.doneToast': { zero: 'Portfolio checked: nothing needs a look.', one: 'Portfolio checked: {count} domain needs a look.', other: 'Portfolio checked: {count} domains need a look.' },
  'pf.showResults': 'Show results',
  'pf.retried': '{domain}: updated',

  'pf.tab.domains': 'Domains',
  'pf.tab.security': 'Domain security',
  'pf.tab.policy': 'Policy audit',
  'pf.tab.ct': 'Certificates (CT)',
  'pf.ct.failed': 'The Certificates (CT) tab could not be loaded',
  'pf.sec.failed': 'The Domain security tab could not be loaded',

  'pf.tile.domains': 'Domains',
  'pf.tile.expiring': 'Expire < 30 days',
  'pf.tile.critical': 'Critical status',
  'pf.tile.unlocked': 'No transfer lock',
  'pf.tile.ns': 'Name server domain at risk',
  'pf.tile.failed': 'Lookups failed',
  'pf.tile.filterHint': 'Show only these',

  'pf.filter.label': 'Show',
  'pf.filter.all': 'All domains ({count})',
  'pf.filter.attention': 'Needs a look ({count})',
  'pf.filter.expiring': 'Expire within 30 days ({count})',
  'pf.filter.critical': 'Critical registry status ({count})',
  'pf.filter.unlocked': 'No transfer lock ({count})',
  'pf.filter.ns': 'Name server domain expiring or not registered ({count})',
  'pf.filter.nordap': 'No RDAP ({count})',
  'pf.filter.failed': 'A lookup failed ({count})',
  'pf.filter.policy': 'Fail the policy ({count})',
  'pf.search': 'Filter domains, registrars, name servers…',

  'pf.col.domain': 'Domain',
  'pf.col.expiry': 'Expires',
  'pf.col.status': 'Registry status',
  'pf.col.registrar': 'Registrar',
  'pf.col.dnssec': 'DNSSEC',
  'pf.col.ns': 'Name server domains',
  'pf.col.caa': 'CAA',
  'pf.col.spf': 'SPF',
  'pf.col.dmarc': 'DMARC',
  'pf.col.dkim': 'DKIM',
  'pf.col.mtaSts': 'MTA-STS · TLS-RPT',
  'pf.col.parked': 'No-mail lock-down',
  'pf.col.policy': 'Policy',

  'pf.risk.critical': 'Critical status',
  'pf.risk.ns-unregistered': 'NS domain not registered',
  'pf.risk.pending-transfer': 'Transfer pending',
  'pf.risk.expired': 'Expired',
  'pf.risk.expiring': 'Expires soon',
  'pf.risk.ns-expiring': 'NS domain expires soon',
  'pf.risk.hijack': 'No transfer lock',
  'pf.risk.warn': 'Under 60 days',

  'pf.pending': 'Looking up…',
  'pf.notLooked': 'not looked up',
  'pf.daysLeft': { zero: 'today', one: '{count} day left', other: '{count} days left' },
  'pf.daysAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'pf.days': { zero: 'today', one: '{count} day', other: '{count} days' },
  'pf.noRdap': 'No RDAP',
  'pf.noRdapTitle': 'The .{tld} registry publishes no RDAP: the dates and the registrar are in its WHOIS.',
  'pf.partial': 'Partial: no RDAP',
  'pf.partialTitle': 'The .{tld} registry publishes no RDAP, so the expiry, the status flags and the registrar are not known here: its WHOIS has them. DNSSEC, the name servers, CAA and mail are checked as for any domain.',
  'pf.whois': 'WHOIS: {registry}',
  'pf.whoisIana': '.{tld} registry (IANA)',
  'pf.notRegistered': 'Not registered',
  'pf.invalidReg': 'not a registry domain',
  'pf.noExpiry': 'no date given',
  'pf.lockOn': 'Transfer lock',
  'pf.lockOnTitle': 'Transfers are prohibited ({codes}): the domain cannot be moved to another registrar until that is lifted.',
  'pf.registryLock': 'Registry lock',
  'pf.registryLockTitle': 'Server transfer, update and delete prohibited: the registry itself refuses a transfer, a change and deletion (RFC 5731) until the registrar asks it to lift them, out of band — the strongest lock, which a hijacked registrar account cannot lift.',
  'pf.lock.full': 'Registrar lock',
  'pf.lock.fullTitle': 'Client transfer, update and delete prohibited: the registrar refuses a transfer, a change and deletion until it lifts them. A registry lock (the server prohibitions) is stronger: only the registry can lift it.',
  'pf.lock.partial': 'Partial registry lock',
  'pf.lock.partialTitle': 'Set by the registry: {codes}. A registry lock is server transfer, update and delete prohibited together.',
  'pf.lock.transferOnly': 'transfer only — also what a registry sets during a dispute or the 60-day lock after a transfer',
  'pf.lock.partialCodes': '{codes} only: a registry lock is server transfer, update and delete prohibited together',
  'pf.corporate': 'Corporate',
  'pf.corporateTitle': 'A corporate registrar by its IANA ID {id} ({brand}): brand protection, registry locks and change control.',
  'pf.lockOff': 'No transfer lock',
  'pf.lockOffTitle': 'No transfer prohibition (clientTransferProhibited or serverTransferProhibited): anyone with the transfer code can move the domain to another registrar (a hijack risk).',
  'pf.noStatus': 'no status reported',
  'pf.criticalTitle': 'A hold takes the domain out of DNS; redemption and pending delete mean it is being lost.',
  'pf.pendingTitle': 'A registry operation is under way. A pending transfer that nobody here asked for is a hijack in progress: ask the registrar to stop it.',
  'pf.dnssec.validated': 'Validated',
  'pf.dnssec.signed': 'Signed',
  'pf.dnssec.failing': 'Broken',
  'pf.dnssec.unsigned': 'Not signed',
  'pf.dnssec.title': 'DS at the parent: {ds} · the resolver validated: {ad}',
  'pf.ns.own': 'own',
  'pf.ns.ownTitle': 'Name servers under the domain itself: their domain expires with it.',
  'pf.ns.none': 'no NS records',
  'pf.ns.notRegistered': 'Not registered',
  'pf.ns.notRegisteredTitle': 'The registry has no record of this domain: anyone can register it and answer DNS for every zone on these name servers.',
  'pf.nxdomain': 'Does not exist (NXDOMAIN)',
  'pf.caa.none': 'None: any CA',
  'pf.caa.unrestricted': 'No issue property: any CA',
  'pf.caa.deny-all': 'No CA',
  'pf.caa.critical': 'Critical tag: no CA',
  'pf.caa.wild': 'wildcard: {list}',
  'pf.spf.none': 'No SPF',
  'pf.spf.many': '{count} records',
  'pf.spf.invalid': 'Not valid',
  'pf.spf.lookups': '{count}/10 lookups',
  'pf.spf.lookupsPartial': 'at least {count}/10 lookups',
  'pf.spf.redirect': 'redirect',
  'pf.spf.noAll': 'no all',
  'pf.dmarc.none': 'No DMARC',
  'pf.dmarc.many': '{count} records',
  'pf.dmarc.invalid': 'Not valid',
  'pf.dkim.none': { one: 'none at {count} selector', other: 'none at {count} selectors' },
  'pf.dkim.off': 'Not checked',
  'pf.rec.present': 'yes',
  'pf.rec.none': 'no',
  'pf.rec.invalid': 'not valid',
  'pf.parked.mail': 'Receives mail',
  'pf.parked.locked': 'Locked down',
  'pf.parked.open': 'Missing: {list}',
  'pf.parked.title': 'A domain that takes no mail should say so: null MX, “v=spf1 -all” and DMARC p=reject, so nobody can send mail as it.',
  'pf.policy.pass': 'All pass',
  'pf.policy.fail': { one: '{count} rule fails', other: '{count} rules fail' },
  'pf.policy.unknown': { one: '{count} rule not known', other: '{count} rules not known' },
  'pf.policy.waived': { one: '{count} rule accepted', other: '{count} rules accepted' },
  'pf.matrix.waived': { one: '{count} failed rule is an accepted risk', other: '{count} failed rules are accepted risks' },

  'pf.export.csv': 'CSV',
  'pf.export.json': 'JSON',
  'pf.export.ics': 'Calendar (.ics)',
  'pf.export.title': 'The domains the table shows (its filter and search applied)',
  'pf.export.icsTitle': 'One all-day event per expiry (the domains the table shows and their name servers’ domains), with reminders 30 and 7 days before; importing a newer file updates the events.',
  'pf.ics.name': 'DomainScope: domain expiry',
  'pf.ics.summary': '{domain} expires',
  'pf.ics.summaryNs': '{domain} expires (name servers of {list})',
  'pf.ics.registrar': 'Registrar: {registrar}',
  'pf.ics.renew': 'Renew it before this date.',
  'pf.ics.ns': {
    one: 'The name servers of {list} are under this domain: if it lapses, whoever registers it answers for that zone.',
    other: 'The name servers of {list} are under this domain: if it lapses, whoever registers it answers for those zones.'
  },
  'pf.ics.alarm': '{domain} expires on {date}',
  'pf.ics.none': 'No expiry date is known for the domains shown.',
  'pf.exported': 'Saved {file}',

  'pf.pol.title': 'Policy of this workspace',
  'pf.pol.intro': 'The rules every domain must meet. Pick a preset, tick rules or edit the JSON: they stay in step, and the policy is kept in this workspace.',
  'pf.pol.saved': 'Kept in the workspace {workspace}',
  'pf.pol.presets': 'Presets',
  'pf.pol.presetApplied': 'Preset applied: {name}',
  'pf.pol.name': 'Policy name',
  'pf.pol.rules': 'Rules',
  'pf.pol.op': 'Comparison',
  'pf.pol.value': 'Value',
  'pf.pol.yes': 'yes',
  'pf.pol.no': 'no',
  'pf.pol.listHint': 'separated by semicolons',
  'pf.pol.json': 'Policy as JSON',
  'pf.pol.export': 'Export policy',
  'pf.pol.import': 'Open a policy file',
  'pf.pol.importFailed': 'The file could not be read.',
  'pf.pol.importTooLarge': 'This file is too large for a policy (at most {size}).',
  'pf.pol.clear': 'Clear',
  'pf.pol.empty': 'No policy yet: pick a preset or tick a rule.',
  'pf.pol.leftOut': 'Left out of the policy:',
  'pf.matrix.title': 'Pass / fail by domain and rule',
  'pf.matrix.noRun': 'Check a portfolio first: the matrix uses its results and sends nothing more.',
  'pf.matrix.noRules': 'The policy has no rule to check yet.',
  'pf.matrix.failing': { zero: 'None of the {total} domains fails the policy', one: '{count} of {total} domains fails the policy', other: '{count} of {total} domains fail the policy' },
  'pf.matrix.unknown': '{count} could not be checked in full',
  'pf.matrix.passing': { one: '{count} meets every rule', other: '{count} meet every rule' },
  'pf.matrix.allPass': { one: 'The domain meets every rule', other: 'All {count} domains meet every rule' },
  'pf.matrix.result': 'Result',
  'pf.matrix.csv': 'Matrix CSV',
  'pf.matrix.json': 'Matrix JSON',
  'pf.matrix.running': 'The portfolio is still being checked: the matrix fills as the lookups land.'
});

registerStrings('tr', {
  'pf.domains': 'Alan adları',
  'pf.placeholder': 'example.com\nexample.org',
  'pf.hint': 'Satır başına bir ya da daha fazla; host adı ya da URL kayıtlı alan adı olarak okunur. En fazla {max}.',
  'pf.count': '{count} alan adı',
  'pf.invalid': 'Alan adı değil, dışarıda bırakıldı: {list}',
  'pf.capped': 'Yalnızca ilk {max} alan adı kontrol edilir: {count} tanesi dışarıda kalır.',
  'pf.prefilled': 'Bu çalışma alanında son kullanılan alan adlarıyla dolduruldu: listeyi düzenleyip Portföyü kontrol et’e basın.',
  'pf.linkPrompt': 'Bir bağlantıdan açıldı: {count} alan adını sorgulamak için Portföyü kontrol et’e basın. Henüz hiçbir şey gönderilmedi.',
  'pf.run': 'Portföyü kontrol et',
  'pf.dkim': 'DKIM anahtarlarını yaygın {count} seçicide ara',
  'pf.dkimHint': 'Alan adı başına {queries} DNS sorgusu daha. Kapalıyken DKIM sütunu ve kuralı “kontrol edilmedi” der.',
  'pf.sends': 'Portföyü kontrol et’e basana kadar hiçbir şey gönderilmez. Sonra her alan adının DNS sorguları DoH çözümleyicilerinize, kayıt sorgusu kayıt kuruluşunun RDAP sunucusuna gider (rdap.org yalnızca kayıt kuruluşuna ulaşılamazsa, saniyede en fazla bir istekle). Ad sunucularının kendi alan adları da aynı yolla, her biri bir kez sorgulanır.',
  'pf.needOne': 'example.com gibi en az bir alan adı girin.',
  'pf.emptyTitle': 'Bir müşterinin bütün alan adları tek tabloda',
  'pf.emptyBody': 'Geri sayımlı bitiş tarihi, kayıt durumu işaretleri (eksik transfer kilidi, askıya alma, silinme bekleyenler), kayıt firması, DNSSEC, ad sunucularının kendi alan adları ve bitişleri, CAA ve e-posta ayarları — ardından bitiş takvimi ve politika denetimi.',
  'pf.progress': '{count} alan adı kontrol ediliyor',
  'pf.progressCount': '{done}/{total} alan adı',
  'pf.resultsTitle': '{count} alan adlık portföy',
  'pf.checkedAt': 'Kontrol edildi: {time}',
  'pf.stoppedAt': 'Durduruldu: {time} — {count} alan adı tam sorgulanmadı',
  'pf.runningNow': 'Sorgulanıyor…',
  'pf.done': '{count} alan adlık portföy kontrol edildi',
  'pf.stopped': 'Durduruldu: gelen sorgular gösteriliyor',
  'pf.doneToast': { zero: 'Portföy kontrol edildi: bakılması gereken bir şey yok.', other: 'Portföy kontrol edildi: {count} alan adına bakmak gerekiyor.' },
  'pf.showResults': 'Sonuçları göster',
  'pf.retried': '{domain}: güncellendi',

  'pf.tab.domains': 'Alan adları',
  'pf.tab.security': 'Alan adı güvenliği',
  'pf.tab.policy': 'Politika denetimi',
  'pf.tab.ct': 'Sertifikalar (CT)',
  'pf.ct.failed': 'Sertifikalar (CT) sekmesi yüklenemedi',
  'pf.sec.failed': 'Alan adı güvenliği sekmesi yüklenemedi',

  'pf.tile.domains': 'Alan adları',
  'pf.tile.expiring': '< 30 günde doluyor',
  'pf.tile.critical': 'Kritik durum',
  'pf.tile.unlocked': 'Transfer kilidi yok',
  'pf.tile.ns': 'Riskli ad sunucusu alan adı',
  'pf.tile.failed': 'Başarısız sorgu',
  'pf.tile.filterHint': 'Yalnızca bunları göster',

  'pf.filter.label': 'Göster',
  'pf.filter.all': 'Bütün alan adları ({count})',
  'pf.filter.attention': 'Bakılması gerekenler ({count})',
  'pf.filter.expiring': '30 gün içinde süresi dolanlar ({count})',
  'pf.filter.critical': 'Kritik kayıt durumu ({count})',
  'pf.filter.unlocked': 'Transfer kilidi olmayanlar ({count})',
  'pf.filter.ns': 'Ad sunucusu alan adının süresi dolan ya da kayıtlı olmayanlar ({count})',
  'pf.filter.nordap': 'RDAP’ı olmayanlar ({count})',
  'pf.filter.failed': 'Sorgusu başarısız olanlar ({count})',
  'pf.filter.policy': 'Politikayı karşılamayanlar ({count})',
  'pf.search': 'Alan adı, kayıt firması, ad sunucusu süz…',

  'pf.col.domain': 'Alan adı',
  'pf.col.expiry': 'Bitiş',
  'pf.col.status': 'Kayıt durumu',
  'pf.col.registrar': 'Kayıt firması',
  'pf.col.dnssec': 'DNSSEC',
  'pf.col.ns': 'Ad sunucusu alan adları',
  'pf.col.caa': 'CAA',
  'pf.col.spf': 'SPF',
  'pf.col.dmarc': 'DMARC',
  'pf.col.dkim': 'DKIM',
  'pf.col.mtaSts': 'MTA-STS · TLS-RPT',
  'pf.col.parked': 'E-posta almayan alan adı kilidi',
  'pf.col.policy': 'Politika',

  'pf.risk.critical': 'Kritik durum',
  'pf.risk.ns-unregistered': 'NS alan adı kayıtlı değil',
  'pf.risk.pending-transfer': 'Transfer bekliyor',
  'pf.risk.expired': 'Süresi doldu',
  'pf.risk.expiring': 'Süresi yakında doluyor',
  'pf.risk.ns-expiring': 'NS alan adının süresi doluyor',
  'pf.risk.hijack': 'Transfer kilidi yok',
  'pf.risk.warn': '60 günden az kaldı',

  'pf.pending': 'Sorgulanıyor…',
  'pf.notLooked': 'sorgulanmadı',
  'pf.daysLeft': { zero: 'bugün', other: '{count} gün kaldı' },
  'pf.daysAgo': '{count} gün önce doldu',
  'pf.days': { zero: 'bugün', other: '{count} gün' },
  'pf.noRdap': 'RDAP yok',
  'pf.noRdapTitle': '.{tld} kayıt kuruluşu RDAP sunmuyor: tarihler ve kayıt firması WHOIS hizmetinde.',
  'pf.partial': 'Kısmi: RDAP yok',
  'pf.partialTitle': '.{tld} kayıt kuruluşu RDAP sunmadığı için bitiş tarihi, durum işaretleri ve kayıt firması burada bilinmiyor; bunlar kayıt kuruluşunun WHOIS hizmetinde. DNSSEC, ad sunucuları, CAA ve e-posta her alan adında olduğu gibi kontrol edilir.',
  'pf.whois': 'WHOIS: {registry}',
  'pf.whoisIana': '.{tld} kayıt kuruluşu (IANA)',
  'pf.notRegistered': 'Kayıtlı değil',
  'pf.invalidReg': 'kayıt kuruluşunun tuttuğu bir alan adı değil',
  'pf.noExpiry': 'tarih verilmiyor',
  'pf.lockOn': 'Transfer kilidi',
  'pf.lockOnTitle': 'Transfer yasak ({codes}): bu kaldırılmadan alan adı başka bir kayıt firmasına taşınamaz.',
  'pf.registryLock': 'Kayıt kuruluşu kilidi',
  'pf.registryLockTitle': 'Server transfer, update ve delete prohibited: kayıt firması bant dışından kaldırılmasını isteyene kadar transferi, değişikliği ve silmeyi kayıt kuruluşunun kendisi reddeder (RFC 5731). En güçlü kilit budur; ele geçirilmiş bir kayıt firması hesabı bunu kaldıramaz.',
  'pf.lock.full': 'Kayıt firması kilidi',
  'pf.lock.fullTitle': 'Client transfer, update ve delete prohibited: kayıt firması bunları kaldırana kadar transferi, değişikliği ve silmeyi reddeder. Kayıt kuruluşu kilidi (server durumları) daha güçlüdür: onu yalnızca kayıt kuruluşu kaldırabilir.',
  'pf.lock.partial': 'Kısmi kayıt kuruluşu kilidi',
  'pf.lock.partialTitle': 'Kayıt kuruluşunun koyduğu: {codes}. Kayıt kuruluşu kilidi, server transfer, update ve delete prohibited durumlarının üçü birdendir.',
  'pf.lock.transferOnly': 'yalnızca transfer — kayıt kuruluşları bunu bir anlaşmazlık sırasında ya da transferden sonraki 60 günlük kilitte de koyar',
  'pf.lock.partialCodes': 'yalnızca {codes}: kayıt kuruluşu kilidi server transfer, update ve delete prohibited durumlarının üçü birdendir',
  'pf.corporate': 'Kurumsal',
  'pf.corporateTitle': 'IANA kimliği {id} olan kurumsal bir kayıt firması ({brand}): marka koruması, kayıt kuruluşu kilidi ve değişiklik denetimi.',
  'pf.lockOff': 'Transfer kilidi yok',
  'pf.lockOffTitle': 'Transfer yasağı yok (clientTransferProhibited ya da serverTransferProhibited): transfer kodunu bilen herkes alan adını başka bir kayıt firmasına taşıyabilir (ele geçirme riski).',
  'pf.noStatus': 'durum bildirilmiyor',
  'pf.criticalTitle': 'Askıya alınan alan adı DNS’ten çıkar; geri alma süresi ve silinme bekleme, alan adının kaybedilmekte olduğunu gösterir.',
  'pf.pendingTitle': 'Kayıt kuruluşunda bir işlem sürüyor. Sizin istemediğiniz bir transfer bekliyorsa alan adı ele geçirilmek üzeredir: kayıt firmanızdan transferi durdurmasını isteyin.',
  'pf.dnssec.validated': 'Doğrulanıyor',
  'pf.dnssec.signed': 'İmzalı',
  'pf.dnssec.failing': 'Bozuk',
  'pf.dnssec.unsigned': 'İmzasız',
  'pf.dnssec.title': 'Üst zone’da DS: {ds} · çözümleyici doğruladı: {ad}',
  'pf.ns.own': 'kendisi',
  'pf.ns.ownTitle': 'Ad sunucuları alan adının kendi altında: alan adı ne zaman biterse onlarınki de o zaman biter.',
  'pf.ns.none': 'NS kaydı yok',
  'pf.ns.notRegistered': 'Kayıtlı değil',
  'pf.ns.notRegisteredTitle': 'Kayıt kuruluşunda bu alan adının kaydı yok: herkes onu kaydedip bu ad sunucularındaki bütün zone’lar adına DNS yanıtı verebilir.',
  'pf.nxdomain': 'Mevcut değil (NXDOMAIN)',
  'pf.caa.none': 'Yok: her CA',
  'pf.caa.unrestricted': 'issue özelliği yok: her CA',
  'pf.caa.deny-all': 'Hiçbir CA',
  'pf.caa.critical': 'Kritik etiket: hiçbir CA',
  'pf.caa.wild': 'joker: {list}',
  'pf.spf.none': 'SPF yok',
  'pf.spf.many': '{count} kayıt',
  'pf.spf.invalid': 'Geçersiz',
  'pf.spf.lookups': '{count}/10 sorgu',
  'pf.spf.lookupsPartial': 'en az {count}/10 sorgu',
  'pf.spf.redirect': 'yönlendirme',
  'pf.spf.noAll': 'all yok',
  'pf.dmarc.none': 'DMARC yok',
  'pf.dmarc.many': '{count} kayıt',
  'pf.dmarc.invalid': 'Geçersiz',
  'pf.dkim.none': '{count} seçicinin hiçbirinde yok',
  'pf.dkim.off': 'Kontrol edilmedi',
  'pf.rec.present': 'var',
  'pf.rec.none': 'yok',
  'pf.rec.invalid': 'geçersiz',
  'pf.parked.mail': 'E-posta alıyor',
  'pf.parked.locked': 'Kilitli',
  'pf.parked.open': 'Eksik: {list}',
  'pf.parked.title': 'E-posta almayan bir alan adı bunu açıkça söylemeli: null MX, “v=spf1 -all” ve DMARC p=reject; böylece kimse onun adına e-posta gönderemez.',
  'pf.policy.pass': 'Hepsi geçti',
  'pf.policy.fail': '{count} kural karşılanmadı',
  'pf.policy.unknown': '{count} kural bilinmiyor',
  'pf.policy.waived': '{count} kural kabul edildi',
  'pf.matrix.waived': '{count} karşılanmayan kural kabul edilen risk',

  'pf.export.csv': 'CSV',
  'pf.export.json': 'JSON',
  'pf.export.ics': 'Takvim (.ics)',
  'pf.export.title': 'Tablonun gösterdiği alan adları (filtre ve arama uygulanmış)',
  'pf.export.icsTitle': 'Her bitiş tarihi için tam günlük bir etkinlik (tablonun gösterdiği alan adları ve ad sunucularının alan adları), 30 ve 7 gün önce hatırlatmalı; daha yeni bir dosya içe aktarıldığında etkinlikler güncellenir.',
  'pf.ics.name': 'DomainScope: alan adı bitişleri',
  'pf.ics.summary': '{domain} alan adının süresi doluyor',
  'pf.ics.summaryNs': { one: '{domain} alan adının süresi doluyor ({list} alan adının ad sunucuları)', other: '{domain} alan adının süresi doluyor ({list} alan adlarının ad sunucuları)' },
  'pf.ics.registrar': 'Kayıt firması: {registrar}',
  'pf.ics.renew': 'Bu tarihten önce yenileyin.',
  'pf.ics.ns': {
    one: '{list} alan adının ad sunucuları bu alan adının altında: süresi dolarsa, onu yeniden kaydeden herkes bu zone adına yanıt verebilir.',
    other: '{list} alan adlarının ad sunucuları bu alan adının altında: süresi dolarsa, onu yeniden kaydeden herkes bu zone’lar adına yanıt verebilir.'
  },
  'pf.ics.alarm': '{domain} alan adının süresi {date} tarihinde doluyor',
  'pf.ics.none': 'Gösterilen alan adları için bilinen bir bitiş tarihi yok.',
  'pf.exported': '{file} kaydedildi',

  'pf.pol.title': 'Bu çalışma alanının politikası',
  'pf.pol.intro': 'Her alan adının uyması gereken kurallar. Hazır bir politika seçin, kuralları işaretleyin ya da JSON’u düzenleyin: ikisi birbirini izler ve politika bu çalışma alanında saklanır.',
  'pf.pol.saved': '{workspace} çalışma alanında saklanıyor',
  'pf.pol.presets': 'Hazır politikalar',
  'pf.pol.presetApplied': 'Hazır politika uygulandı: {name}',
  'pf.pol.name': 'Politika adı',
  'pf.pol.rules': 'Kurallar',
  'pf.pol.op': 'Karşılaştırma',
  'pf.pol.value': 'Değer',
  'pf.pol.yes': 'evet',
  'pf.pol.no': 'hayır',
  'pf.pol.listHint': 'noktalı virgülle ayırın',
  'pf.pol.json': 'JSON olarak politika',
  'pf.pol.export': 'Politikayı dışa aktar',
  'pf.pol.import': 'Politika dosyası aç',
  'pf.pol.importFailed': 'Dosya okunamadı.',
  'pf.pol.importTooLarge': 'Bu dosya bir politika için fazla büyük (en fazla {size}).',
  'pf.pol.clear': 'Temizle',
  'pf.pol.empty': 'Henüz politika yok: hazır bir politika seçin ya da bir kural işaretleyin.',
  'pf.pol.leftOut': 'Politikaya alınmayanlar:',
  'pf.matrix.title': 'Alan adı ve kurala göre geçti / kaldı',
  'pf.matrix.noRun': 'Önce bir portföyü kontrol edin: matris onun sonuçlarını kullanır ve başka bir şey göndermez.',
  'pf.matrix.noRules': 'Politikada henüz kontrol edilecek kural yok.',
  'pf.matrix.failing': { zero: '{total} alan adından politikaya uymayan yok', other: '{total} alan adından {count} tanesi politikaya uymuyor' },
  'pf.matrix.unknown': '{count} tanesi tam kontrol edilemedi',
  'pf.matrix.passing': '{count} tanesi bütün kurallara uyuyor',
  'pf.matrix.allPass': { one: 'Alan adı bütün kurallara uyuyor', other: '{count} alan adının tamamı bütün kurallara uyuyor' },
  'pf.matrix.result': 'Sonuç',
  'pf.matrix.csv': 'Matris CSV',
  'pf.matrix.json': 'Matris JSON',
  'pf.matrix.running': 'Portföy hâlâ kontrol ediliyor: matris, sorgular geldikçe dolar.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/** A registry status as one token ('client transfer prohibited' and 'clientTransferProhibited' alike). */
const squashStatus = (s) => String(s ?? '').trim().toLowerCase().replace(/[\s_-]+/g, '');

/**
 * The list of a route's `domains` param (comma- or space-separated), as the box shows it: one per line.
 * @param {string} param
 * @returns {string}
 */
export function linkText(param) {
  return String(param || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean).join('\n');
}

/**
 * The route params of a run: its domains, comma-joined, while there are at most
 * {@link MAX_LINK_DOMAINS} (a longer list stays out of the URL: the link opens the bare view).
 * @param {string[]} domains
 * @returns {Record<string, string>}
 */
export function shareParams(domains) {
  return domains.length && domains.length <= MAX_LINK_DOMAINS ? { domains: domains.join(',') } : {};
}

/**
 * Does a row pass a filter of {@link PORTFOLIO_FILTERS}?
 * @param {object} facts lib/portfolio.js portfolioFacts
 * @param {string} filter
 * @param {{ policyFails?: (domain: string) => boolean }} [opts]
 * @returns {boolean}
 */
export function matchesFilter(facts, filter, { policyFails = () => false } = {}) {
  if (!facts) return false;
  const reg = facts.registration || {};
  const failed = PORTFOLIO_CELLS.some((c) => cellFailures(facts, c).length);
  // a name server domain that expires within 30 days, or that nobody has registered at all
  const nsSoon = (!!facts.ns && facts.ns.domains.some((d) => !d.own && Number.isFinite(d.daysLeft) && d.daysLeft < 30)) || unregisteredNsDomains(facts).length > 0;
  switch (filter) {
    case 'all': return true;
    case 'expiring': return reg.state === 'ok' && Number.isFinite(reg.daysLeft) && reg.daysLeft < 30;
    case 'critical': return (reg.critical || []).length > 0;
    case 'unlocked': return reg.state === 'ok' && reg.transferLock === false;
    case 'ns': return nsSoon;
    case 'nordap': return reg.state === 'unsupported';
    case 'failed': return failed;
    case 'policy': return policyFails(facts.domain);
    case 'attention': {
      const risk = rowRisk(facts);
      return (risk && risk !== 'ok') || failed || reg.state === 'not-found' || policyFails(facts.domain)
        || (!!facts.spf && facts.spf.over) || (!!facts.parked && facts.parked.complete === false);
    }
    default: return true;
  }
}

/**
 * The line above the matrix: how many domains fail the policy (none too), could not be checked in
 * full and meet every rule, those two left out when empty ("All 3 domains meet every rule" when
 * every domain does).
 * @param {{ domains: number, failing: number, unknown: number, passing: number }} counts lib/policy.js auditPortfolio counts
 * @param {Function} t
 * @returns {string}
 */
export function matrixCountsText(counts, t) {
  const c = counts || { domains: 0, failing: 0, unknown: 0, passing: 0 };
  // the failed rules a waiver accepts, counted on their own
  const waived = c.waived ? ` · ${t('pf.matrix.waived', { count: c.waived })}` : '';
  if (c.domains && c.passing === c.domains) return `${t('pf.matrix.allPass', { count: c.domains })}${waived}`;
  return [
    t('pf.matrix.failing', { count: c.failing, total: c.domains }),
    c.unknown ? t('pf.matrix.unknown', { count: c.unknown }) : null,
    c.passing ? t('pf.matrix.passing', { count: c.passing }) : null,
    c.waived ? t('pf.matrix.waived', { count: c.waived }) : null
  ].filter(Boolean).join(' · ');
}

/**
 * The calendar events of the rows shown: one per domain (the expiry events of lib/portfolio.js),
 * worded in the UI language.
 * @param {object[]} factsList
 * @param {Function} t
 * @returns {Array<{ uid: string, date: Date, summary: string, description: string, alarm: string }>}
 */
export function calendarEvents(factsList, t) {
  return expiryEvents(factsList).map((e) => {
    const list = e.nsOf.join(', ');
    const count = e.nsOf.length;
    const summary = count && !e.portfolio ? t('pf.ics.summaryNs', { domain: e.domain, list, count }) : t('pf.ics.summary', { domain: e.domain });
    const description = [
      e.registrar ? t('pf.ics.registrar', { registrar: e.registrar }) : null,
      t('pf.ics.renew'),
      count ? t('pf.ics.ns', { list, count }) : null
    ].filter(Boolean).join('\n');
    // the local day, as the event (lib/ics.js) and the table show it
    const day = `${e.expires.getFullYear()}-${String(e.expires.getMonth() + 1).padStart(2, '0')}-${String(e.expires.getDate()).padStart(2, '0')}`;
    return { uid: expiryUid(e.domain), date: e.expires, summary, description, alarm: t('pf.ics.alarm', { domain: e.domain, date: day }) };
  });
}

/* ------------------------------------------------------------------------ */
/* The run (module state: it outlives the view)                             */
/* ------------------------------------------------------------------------ */

/**
 * The page session of the view: the box, the options, the last run.
 * `text` null: the box was never touched (it is filled in from the recent domains).
 */
const session = { text: null, prefilled: false, carried: null, link: null, dkim: true, job: null, tab: 'domains', filter: 'all' };
let jobCounter = 0;
let active = null;

const running = () => !!(session.job && session.job.status === 'running');

// Another workspace (another customer's domains) or "Delete all local data": the run, the box and
// the options go; a running run stops.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared' && key !== 'workspace') return;
  if (running()) session.job.controller.abort();
  Object.assign(session, { text: null, prefilled: false, carried: null, link: null, dkim: true, job: null, tab: 'domains', filter: 'all' });
});

function emit(job, type, payload) {
  for (const fn of [...job.listeners]) {
    try {
      fn(type, payload);
    } catch (err) {
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

/** Start a run over the shared DohClient; its events go to the job's listeners (the view on screen). */
function startRun({ domains, reduced, dkim, dns }) {
  jobCounter += 1;
  const job = {
    id: jobCounter, domains, reduced, dkim, status: 'running', startedAt: new Date(), finishedAt: null,
    controller: new AbortController(), listeners: new Set(), handle: startJob({ view: 'portfolio' }), done: 0, busy: new Map()
  };
  job.run = createPortfolio({
    domains, dns, dkim,
    onEvent: (e) => {
      if (e.type === 'row' && e.state === 'done') {
        job.done = job.run.domains().filter((d) => job.run.row(d).state === 'done').length;
        job.handle.update(job.done / Math.max(1, domains.length));
      }
      emit(job, 'event', e);
    }
  });
  job.run.start({ signal: job.controller.signal }).then(() => {
    job.status = 'done';
  }, (err) => {
    job.status = err && err.name === 'AbortError' ? 'stopped' : 'error';
    job.error = err;
  }).then(() => {
    job.finishedAt = new Date();
    job.handle.finish({ status: job.status === 'done' ? 'done' : job.status === 'error' ? 'error' : 'cancelled' });
    emit(job, job.status, null);
    if (job.status === 'done' && !active && session.job === job) {
      const facts = job.run.allFacts();
      const need = facts.filter((f) => matchesFilter(f, 'attention')).length;
      toast(translate('pf.doneToast', { count: need }), {
        type: need ? 'warn' : 'success',
        timeout: 10000,
        action: { label: translate('pf.showResults'), onClick: () => { globalThis.location.hash = '#/portfolio'; } }
      });
    }
  });
  return job;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Domain portfolio view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  const cleanups = [];
  /** The current job's rows for the table: one object per domain, stable (updateRows redraws them). */
  let rows = [];
  let byDomain = new Map();
  let attached = null;
  /** The policy as the editor holds it, and what lib/policy.js reads of it. */
  let policyTextNow = state.workspaceData('policy') || '';
  let parsed = policyTextNow.trim() ? parsePolicy(policyTextNow) : { policy: null, errors: [] };
  let audit = null;
  /** The Certificates (CT) tab's panel, once its module is loaded. */
  let ctPanel = null;

  /* --- the box ---------------------------------------------------------------------- */
  const routeText = ctx.params.domains ? linkText(ctx.params.domains) : '';
  if (routeText) {
    const last = session.job ? session.job.domains : null;
    if (fillReplaces(session.text || '', last, (x) => parsePortfolioInput(x).domains, session.carried)) {
      session.text = routeText;
      session.carried = isFillOnly(ctx.params) ? routeText : null;
      session.prefilled = false;
    }
    session.link = routeText;
  } else if (session.text === null) {
    // The workspace's recent domains, while the box was never touched in this page session.
    const recent = (state.workspaceData('recent') || []).map((r) => r.value);
    const p = parsePortfolioInput(recent.join('\n'));
    session.text = p.domains.join('\n');
    session.prefilled = p.domains.length > 0;
  }

  const box = textarea({
    label: t('pf.domains'),
    value: session.text || '',
    rows: 6,
    placeholder: t('pf.placeholder'),
    className: 'pf-box',
    attrs: { 'data-role': 'pf-domains', 'data-shortcut': 'focus', 'aria-describedby': 'pf-box-status' },
    onInput: (v) => {
      session.text = v;
      session.prefilled = false;
      session.carried = null;
      renderBoxStatus();
      renderPrompt();
      if (ctPanel) ctPanel.refresh();
    }
  });
  const boxStatus = h('div', { class: 'pf-box-status text-sm', id: 'pf-box-status', attrs: { 'aria-live': 'polite' } });
  const dkimBox = checkbox({
    label: t('pf.dkim', { count: PORTFOLIO_DKIM_SELECTORS.length }),
    checked: session.dkim,
    hint: t('pf.dkimHint', { queries: PORTFOLIO_DKIM_SELECTORS.length + 1 }),
    className: 'pf-dkim',
    onChange: (on) => { session.dkim = on; }
  });
  const runBtn = Button({ label: t('pf.run'), icon: 'search', variant: 'primary', dataset: { action: 'pf-run', shortcut: 'submit' }, onClick: () => start() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', dataset: { action: 'pf-stop', shortcut: 'cancel' }, onClick: () => stop() });
  const promptEl = h('div', { class: 'pf-prompt' });
  const formCard = h('div', { class: 'card pf-form-card' },
    h('div', { class: 'card-body stack' },
      box.el,
      boxStatus,
      dkimBox.el,
      h('div', { class: 'pf-buttons' }, stopBtn, runBtn),
      h('p', { class: 'muted text-sm pf-sends' }, t('pf.sends')),
      promptEl));

  function renderBoxStatus() {
    clear(boxStatus);
    const p = parsePortfolioInput(box.value);
    const bits = [h('span', { class: 'pf-count' }, t('pf.count', { count: p.domains.length })), h('span', { class: 'muted' }, ` · ${t('pf.hint', { max: formatNumber(PORTFOLIO_MAX_DOMAINS) })}`)];
    boxStatus.append(h('p', null, bits));
    if (p.invalid.length) boxStatus.append(h('p', { class: 'pf-invalid', dataset: { issue: 'invalid' } }, t('pf.invalid', { list: p.invalid.slice(0, 8).join(', ') + (p.invalid.length > 8 ? ` ${t('common.moreCount', { count: p.invalid.length - 8 })}` : '') })));
    if (p.capped) boxStatus.append(h('p', { class: 'pf-invalid', dataset: { issue: 'capped' } }, t('pf.capped', { max: formatNumber(PORTFOLIO_MAX_DOMAINS), count: p.capped })));
    if (session.prefilled && box.value === session.text) boxStatus.append(h('p', { class: 'muted', dataset: { note: 'prefilled' } }, t('pf.prefilled')));
  }

  /** "Opened from a link …": the box holds the link's list, which no run on screen is about. */
  function renderPrompt() {
    clear(promptEl);
    if (!session.link || running()) return;
    const p = parsePortfolioInput(box.value);
    const linked = parsePortfolioInput(session.link).domains;
    if (!p.domains.length || p.domains.join(',') !== linked.join(',')) return;
    if (session.job && session.job.domains.join(',') === linked.join(',')) return;
    const el = Alert({ variant: 'info', compact: true, message: t('pf.linkPrompt', { count: p.domains.length }) });
    el.dataset.prompt = 'link';
    promptEl.append(el);
  }

  /* --- results skeleton -------------------------------------------------------------- */
  const progress = ProgressBar({ format: (v, max) => t('pf.progressCount', { done: formatNumber(v), total: formatNumber(max) }) });
  /** "Notify me when done" of the running check (ui/jobs.js: offered once it has run 30 s). */
  const notifyHost = h('div', { class: 'pf-notify' });
  const progressRow = h('div', { class: 'pf-progress', hidden: true }, progress.el, notifyHost);
  const showProgress = (on) => {
    progressRow.hidden = !on;
  };
  const emptyEl = h('div', { class: 'card pf-empty' }, EmptyState({ icon: 'box', title: t('pf.emptyTitle'), message: t('pf.emptyBody') }));
  const headEl = h('div', { class: 'pf-head-wrap' });
  const tiles = Object.fromEntries(['domains', ...PORTFOLIO_TILES].map((k) => [k, StatCard({
    label: t(`pf.tile.${k}`),
    value: 0,
    onClick: k === 'domains' ? () => setFilter('all') : () => setFilter(session.filter === k ? 'all' : k),
    pressed: false
  })]));
  for (const [k, tile] of Object.entries(tiles)) {
    tile.el.dataset.tile = k;
    if (k !== 'domains') tile.el.title = t('pf.tile.filterHint');
  }
  const tilesEl = h('div', { class: 'pf-tiles' }, Object.values(tiles).map((x) => x.el));

  /** The head's summary button (disabled while a run is going). */
  let summary = null;

  /* --- cells ------------------------------------------------------------------------- */
  const mono = (text) => h('span', { class: 'mono pf-break' }, text);
  const muted = (text) => h('span', { class: 'muted text-sm' }, text);
  const pendingCell = () => h('span', { class: 'pf-pending muted text-sm', attrs: { 'aria-busy': 'true' } }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), ' ', t('pf.pending'));
  const stack = (...children) => h('span', { class: 'pf-cell' }, children.filter(Boolean));
  const daysBadge = (days, band) => (days < 0
    ? Badge(t('pf.daysAgo', { count: -days }), { variant: 'error', icon: 'x-circle' })
    : Badge(t('pf.daysLeft', { count: days }), { variant: band === 'ok' ? 'ok' : band === 'warn' ? 'warn' : 'error', icon: 'clock' }));

  /**
   * A cell's content when its lookups have not all landed, or failed: a spinner while the run
   * goes on, "not looked up" after a stop, else "⚠ n/a" with the reasons and a Retry of exactly
   * those lookups. Null: the cell has its answer.
   */
  function cellState(row, column) {
    const f = row.facts;
    const failures = cellFailures(f, column);
    const lookups = CELL_LOOKUPS[column];
    const job = session.job;
    const pending = job ? lookups.filter((l) => job.run.row(row.domain).raw[l] === undefined) : [];
    const busy = job && job.busy.get(row.domain);
    const retrying = !!busy && busy.has(column);
    if (pending.length && !failures.length) {
      if (job.status === 'running' || retrying) return pendingCell();
      return muted(t('pf.notLooked'));
    }
    if (!failures.length) return null;
    const btn = RetryButton({
      sources: [...new Set(failures.map((x) => LOOKUP_SOURCES[x.lookup]))],
      target: `${row.domain} · ${t(`pf.col.${column}`)}`,
      dataset: { cell: column, domain: row.domain },
      onClick: (e) => retryCell(row.domain, column, failures, e.currentTarget)
    });
    if (retrying) setRetryBusy(btn);
    return { failures, el: h('span', { class: 'pf-na', dataset: { failed: failures.map((x) => x.nsDomain ? `rdap:${x.nsDomain}` : x.lookup).join(' ') } }, NaMark(failures.map((x) => x.status)), btn) };
  }

  /** Render a column: the waiting / failed state first, else the answer. */
  const cell = (column, render) => (row) => {
    const s = cellState(row, column);
    if (s && !s.failures) return s;
    if (s && column !== 'ns') return s.el;
    const body = render(row.facts, row);
    return s ? stack(body, s.el) : body;
  };

  function domainCell(row) {
    const f = row.facts;
    const risk = rowRisk(f);
    const job = session.job;
    const r = job ? job.run.row(row.domain) : null;
    const stopped = r && r.state === 'stopped' && job.status !== 'running' && job.run.pending(row.domain).length;
    const lookUp = stopped ? RetryButton({
      sources: ['doh', 'rdap'], first: true, target: row.domain, dataset: { row: row.domain },
      onClick: (e) => lookUpRow(row.domain, e.currentTarget)
    }) : null;
    if (lookUp && job.busy.get(row.domain) && job.busy.get(row.domain).has('*')) setRetryBusy(lookUp);
    const reduced = job ? job.reduced.filter((x) => x.domain === row.domain).map((x) => x.input) : [];
    // A registry without RDAP: the row says it is partial, never that the registration is fine.
    const partial = f.registration.state === 'unsupported'
      ? h('span', { class: 'pf-partial', dataset: { partial: 'no-rdap' }, title: t('pf.partialTitle', { tld: f.registration.tld || '' }) }, Badge(t('pf.partial'), { icon: 'info' }))
      : null;
    return stack(
      h('strong', { class: 'mono pf-break pf-domain' }, row.domain),
      risk && RISK_BADGES.includes(risk) ? Badge(t(`pf.risk.${risk}`), { variant: risk === 'warn' || risk === 'hijack' ? 'warn' : 'error', className: 'pf-risk' }) : null,
      partial,
      reduced.length ? muted(reduced.join(', ')) : null,
      lookUp);
  }

  function expiryCell(f) {
    const reg = f.registration;
    if (reg.state === 'unsupported') {
      const w = reg.whois;
      return stack(h('span', { title: t('pf.noRdapTitle', { tld: reg.tld || '' }), dataset: { rdap: 'unsupported' } }, Badge(t('pf.noRdap'))),
        w ? ExternalLink(w.url, w.iana ? t('pf.whoisIana', { tld: reg.tld || '' }) : t('pf.whois', { registry: w.name }), { className: 'text-xs pf-whois' }) : null);
    }
    if (reg.state === 'not-found') return Badge(t('pf.notRegistered'), { variant: 'error', icon: 'x-circle' });
    if (reg.state === 'invalid') return muted(t('pf.invalidReg'));
    if (!reg.expires) return muted(t('pf.noExpiry'));
    return h('span', { class: 'pf-cell pf-expiry', dataset: { days: reg.daysLeft, expiry: reg.expiry } },
      h('span', { class: 'num' }, formatDate(reg.expires)), daysBadge(reg.daysLeft, reg.expiry));
  }

  /**
   * The lock of a registration by its depth (lib/portfolio.js lockLevel): a registry lock (all
   * three server prohibitions), a partial one — with what it is, since serverTransferProhibited
   * alone is also a dispute's or a recent transfer's —, the registrar's full lock, its transfer
   * lock, or none at all (any transfer prohibition locks transfers: never "no lock" with one).
   */
  function lockBadge(reg) {
    const level = reg.lockLevel;
    const badge = (text, title, variant, icon) => h('span', { title, dataset: { lockLevel: level || 'none' } }, Badge(text, { variant, icon }));
    if (reg.transferLock === false) return badge(t('pf.lockOff'), t('pf.lockOffTitle'), 'warn', 'unlock');
    if (!level || reg.transferLock !== true) return muted(t('pf.noStatus'));
    if (level === 'registry') return badge(t('pf.registryLock'), t('pf.registryLockTitle'), 'ok', 'lock');
    if (level === 'registrar-full') return badge(t('pf.lock.full'), t('pf.lock.fullTitle'), 'ok', 'lock');
    if (level === 'registry-partial') {
      const codes = (reg.serverLocks || []).join(', ');
      const transferOnly = (reg.serverLocks || []).length === 1 && squashStatus(reg.serverLocks[0]) === 'servertransferprohibited';
      return h('span', { class: 'pf-lock' }, badge(t('pf.lock.partial'), t('pf.lock.partialTitle', { codes }), 'ok', 'lock'),
        h('span', { class: 'muted text-xs pf-lock-note' }, transferOnly ? t('pf.lock.transferOnly') : t('pf.lock.partialCodes', { codes })));
    }
    return badge(t('pf.lockOn'), t('pf.lockOnTitle', { codes: (reg.transferCodes || []).join(', ') }), 'ok', 'lock');
  }

  function statusCell(f) {
    const reg = f.registration;
    if (reg.state !== 'ok') return reg.state === 'unsupported' ? muted(t('pf.noRdap')) : null;
    const lock = lockBadge(reg);
    const critical = (reg.critical || []).map((c) => h('span', { title: t('pf.criticalTitle') }, Badge(c, { variant: 'error', icon: 'alert', mono: true })));
    // The flags not said yet: the critical ones and the transfer prohibitions have their badges above,
    // as have the prohibitions the lock's badge names (a registry lock's server ones, the registrar's
    // full lock's client ones); an operation under way (a pending transfer, renewal, update) is a
    // badge of its own.
    const lockCodes = reg.lockLevel === 'registry' || reg.lockLevel === 'registry-partial' ? reg.serverLocks || []
      : reg.lockLevel === 'registrar-full' ? ['client update prohibited', 'client delete prohibited', 'update prohibited', 'delete prohibited'] : [];
    const said = new Set([...CRITICAL_STATUSES, ...(reg.transferCodes || []), ...lockCodes].map(squashStatus));
    const rest = (reg.flags || []).filter((x) => !said.has(squashStatus(x.code)));
    const pending = rest.filter((x) => x.kind === 'pending')
      .map((x) => h('span', { title: t('pf.pendingTitle'), dataset: { flag: squashStatus(x.code) } }, Badge(x.code, { variant: 'warn', icon: 'clock', mono: true })));
    const other = rest.filter((x) => x.kind !== 'pending');
    return h('span', { class: 'pf-cell pf-status', dataset: { risk: reg.risk || '', lock: String(reg.transferLock) } },
      critical, pending, lock,
      other.length ? h('span', { class: 'muted text-xs pf-flags', title: other.map((x) => x.code).join('\n') }, other.slice(0, 2).map((x) => x.code).join(', ')
        + (other.length > 2 ? ` ${t('common.moreCount', { count: other.length - 2 })}` : '')) : null);
  }

  function registrarCell(f) {
    const reg = f.registration;
    if (reg.state !== 'ok') return reg.state === 'unsupported' ? muted(t('pf.noRdap')) : null;
    // A corporate registrar by its IANA ID (lib/registrars.js), never by the name it writes.
    const corp = reg.registrarClass === 'corporate' ? corporateRegistrar(reg.ianaId) : null;
    const name = reg.registrar ? h('span', { class: 'pf-registrar' }, reg.registrar) : null;
    if (!corp) return name;
    return stack(name, h('span', { title: t('pf.corporateTitle', { id: corp.id, brand: corp.brand }), dataset: { registrarClass: 'corporate' } },
      Badge(t('pf.corporate'), { variant: 'ok', icon: 'shield' })));
  }

  function dnssecCell(f) {
    const d = f.dnssec;
    if (!d.state) return null;
    const variant = { validated: 'ok', signed: 'info', failing: 'error', unsigned: 'neutral' }[d.state];
    const yes = t('common.yes');
    const no = t('common.no');
    return h('span', { dataset: { dnssec: d.state }, title: t('pf.dnssec.title', { ds: d.dsCount ? yes : no, ad: d.state === 'validated' ? yes : no }) },
      Badge(t(`pf.dnssec.${d.state}`), { variant, icon: d.state === 'validated' ? 'shield' : d.state === 'failing' ? 'x-circle' : null }));
  }

  /**
   * A name server domain whose RDAP never landed (the run was stopped while it was asked): "Look
   * up" asks it, for every row whose name servers are under it.
   */
  function nsPending(row, nsDomain) {
    const job = session.job;
    const busy = job && job.busy.get(row.domain);
    if (!job || job.status === 'running' || (busy && busy.has('ns'))) return muted('…');
    return RetryButton({
      sources: ['rdap'], first: true, target: nsDomain, dataset: { cell: 'ns', domain: row.domain, nsLookup: nsDomain },
      onClick: (e) => retryCell(row.domain, 'ns', [{ lookup: 'rdap', nsDomain }], e.currentTarget)
    });
  }

  function nsCell(f, row) {
    const ns = f.ns;
    if (ns.state === 'nxdomain') return Badge(t('pf.nxdomain'), { variant: 'error' });
    if (ns.state === 'none') return muted(t('pf.ns.none'));
    if (ns.state !== 'ok') return null;
    return h('span', { class: 'pf-cell pf-ns' }, ns.domains.map((d) => h('span', { class: 'pf-ns-domain', dataset: { ns: d.domain, own: String(d.own), days: d.daysLeft ?? '' }, title: d.hosts.join('\n') },
      mono(d.domain), ' ',
      d.own ? h('span', { title: t('pf.ns.ownTitle') }, Badge(t('pf.ns.own'))) : Number.isFinite(d.daysLeft) ? daysBadge(d.daysLeft, d.expiry)
        : d.state === 'not-found' ? h('span', { title: t('pf.ns.notRegisteredTitle'), dataset: { nsState: 'not-found' } }, Badge(t('pf.ns.notRegistered'), { variant: 'error', icon: 'alert' }))
          : d.state === 'unsupported' ? Badge(t('pf.noRdap')) : d.state === 'pending' ? nsPending(row, d.domain) : null)));
  }

  function caaCell(f) {
    const c = f.caa;
    if (!c.state) return null;
    if (c.state !== 'present') return h('span', { dataset: { caa: c.state } }, Badge(t(`pf.caa.${c.state}`), { variant: c.state === 'none' || c.state === 'unrestricted' ? 'neutral' : c.state === 'critical' ? 'error' : 'info' }));
    // one issuer a line: a CA's domain never breaks in its middle
    return h('span', { class: 'pf-cell pf-caa', dataset: { caa: 'present' } },
      c.issuers.map((x) => h('span', { class: 'mono pf-caa-issuer' }, x)),
      c.wildIssuers.length ? muted(t('pf.caa.wild', { list: c.wildIssuers.join(', ') })) : null);
  }

  function spfCell(f) {
    const s = f.spf;
    if (!s.state) return null;
    if (s.state !== 'ok') return h('span', { dataset: { spf: s.state } }, Badge(t(`pf.spf.${s.state}`, { count: s.count || 0 }), { variant: s.state === 'none' ? 'warn' : 'error' }));
    const all = s.all ? `${s.all}all` : s.redirect ? t('pf.spf.redirect') : t('pf.spf.noAll');
    const lookups = Number.isFinite(s.lookups)
      ? Badge(t(s.lookupsState === 'partial' ? 'pf.spf.lookupsPartial' : 'pf.spf.lookups', { count: s.lookups }), { variant: s.over ? 'error' : s.lookups >= 9 ? 'warn' : 'neutral' })
      : null;
    return h('span', { class: 'pf-cell', dataset: { spf: 'ok', all: s.all || '' } }, Badge(all, { mono: true, variant: s.all === '+' ? 'error' : s.all === '?' ? 'warn' : 'neutral' }), lookups);
  }

  function dmarcCell(f) {
    const d = f.dmarc;
    if (!d.state) return null;
    if (d.state !== 'ok') return h('span', { dataset: { dmarc: d.state } }, Badge(t(`pf.dmarc.${d.state}`, { count: d.count || 0 }), { variant: d.state === 'none' ? 'warn' : 'error' }));
    return h('span', { dataset: { dmarc: d.policy } }, Badge(`p=${d.policy}${d.pct < 100 ? ` pct=${d.pct}` : ''}`, { mono: true, variant: d.policy === 'reject' ? 'ok' : d.policy === 'quarantine' ? 'info' : 'warn' }));
  }

  function dkimCell(f) {
    const d = f.dkim;
    if (!d.state) return null;
    if (d.state === 'off') return muted(t('pf.dkim.off'));
    if (d.state === 'none') return h('span', { dataset: { dkim: 'none' } }, Badge(t('pf.dkim.none', { count: d.asked || 0 })));
    return h('span', { class: 'pf-cell', dataset: { dkim: 'found' } }, d.selectors.map((s) => Badge(s, { mono: true, variant: 'ok' })));
  }

  function mtaStsCell(f) {
    const rec = (label, part) => (part.state ? h('span', { class: 'pf-rec', dataset: { rec: label, state: part.state } }, `${label} `,
      Badge(t(`pf.rec.${part.state}`), { variant: part.state === 'present' ? 'ok' : part.state === 'invalid' ? 'error' : 'neutral' })) : null);
    if (!f.mtaSts.state && !f.tlsRpt.state) return null;
    return h('span', { class: 'pf-cell' }, rec('MTA-STS', f.mtaSts), rec('TLS-RPT', f.tlsRpt));
  }

  function parkedCell(f) {
    const p = f.parked;
    if (p.parked === null) return null;
    if (!p.parked) return muted(t('pf.parked.mail'));
    if (p.complete) return h('span', { dataset: { parked: 'locked' }, title: t('pf.parked.title') }, Badge(t('pf.parked.locked'), { variant: 'ok', icon: 'lock' }));
    const missing = [p.nullMx ? null : 'null MX', p.spfFail === false ? '-all' : null, p.dmarcReject === false ? 'p=reject' : null].filter(Boolean);
    if (!missing.length) return null;
    // each value whole: a narrow card would break "-all" after its hyphen
    return h('span', { dataset: { parked: 'open' }, title: t('pf.parked.title') },
      Badge(keepWhole(t('pf.parked.open', { list: missing.join(', ') }), /(null MX|-all|p=reject)/), { variant: 'warn', icon: 'unlock' }));
  }

  function policyCell(row) {
    const r = audit ? audit.rows.find((x) => x.domain === row.domain) : null;
    if (!r) return null;
    const accepted = r.waived ? Badge(t('pf.policy.waived', { count: r.waived }), { icon: 'shield' }) : null;
    if (!r.fail && !r.unknown) return h('span', { class: 'pf-cell', dataset: { policy: 'pass' } }, Badge(t('pf.policy.pass'), { variant: 'ok', icon: 'check' }), accepted);
    return h('span', { class: 'pf-cell', dataset: { policy: r.fail ? 'fail' : 'unknown' } },
      r.fail ? Badge(t('pf.policy.fail', { count: r.fail }), { variant: 'error', icon: 'x-circle' }) : null,
      r.unknown ? Badge(t('pf.policy.unknown', { count: r.unknown })) : null,
      accepted);
  }

  /** A text with what `re` matches (one capture group) kept on one line, each match in a .pf-nowrap. */
  const keepWhole = (text, re) => String(text).split(re).map((part, i) => (i % 2 ? h('span', { class: 'pf-nowrap' }, part) : part)).filter((x) => x !== '');
  /** A text with its ISO dates kept on one line (a narrow card would break one at its hyphens). */
  const keepDates = (text) => keepWhole(text, /(\d{4}-\d{2}-\d{2})/);

  /** Sort values: what a column orders by (empty last in both directions). */
  const sortOf = {
    expiry: (r) => (r.facts.registration.state === 'ok' && Number.isFinite(r.facts.registration.daysLeft) ? r.facts.registration.daysLeft : null),
    status: (r) => (r.facts.registration.risk ? { critical: 0, 'pending-transfer': 1, hijack: 2, ok: 3 }[r.facts.registration.risk] : null),
    registrar: (r) => r.facts.registration.registrar || null,
    dnssec: (r) => ({ failing: 0, unsigned: 1, signed: 2, validated: 3 }[r.facts.dnssec.state] ?? null),
    ns: (r) => (unregisteredNsDomains(r.facts).length ? -Infinity : Number.isFinite(r.facts.ns.minDaysLeft) ? r.facts.ns.minDaysLeft : null),
    caa: (r) => r.facts.caa.state,
    spf: (r) => (Number.isFinite(r.facts.spf.lookups) ? r.facts.spf.lookups : r.facts.spf.state),
    dmarc: (r) => ({ none: 0, quarantine: 1, reject: 2 }[r.facts.dmarc.policy] ?? (r.facts.dmarc.state ? -1 : null)),
    dkim: (r) => r.facts.dkim.state,
    mtaSts: (r) => (r.facts.mtaSts.state === 'present' ? 1 : r.facts.mtaSts.state ? 0 : null),
    parked: (r) => (r.facts.parked.parked === null ? null : r.facts.parked.parked ? (r.facts.parked.complete ? 2 : 1) : 0)
  };
  const searchOf = (r) => {
    const f = r.facts;
    return [r.domain, f.registration.registrar, ...(f.ns.hosts || []), ...(f.caa.issuers || [])].filter(Boolean).join(' ');
  };

  const filterSelect = select({
    label: t('pf.filter.label'),
    options: PORTFOLIO_FILTERS.map((f) => ({ value: f, label: t(`pf.filter.${f}`, { count: 0 }) })),
    value: session.filter,
    size: 'sm',
    className: 'pf-filter',
    onChange: (v) => setFilter(v)
  });
  filterSelect.input.dataset.role = 'pf-filter';

  const table = DataTable({
    columns: domainColumns(),
    rowKey: (r) => r.domain,
    search: { placeholder: t('pf.search') },
    sort: { key: 'domain', dir: 'asc' },
    toolbar: filterSelect.el,
    filter: (r) => matchesFilter(r.facts, session.filter, { policyFails }),
    export: false,
    cellLabels: true,
    pageSize: 100,
    maxHeight: null,
    caption: t('pf.tab.domains'),
    className: 'pf-table',
    rowClass: (r) => {
      const risk = rowRisk(r.facts);
      return risk && risk !== 'ok' ? `pf-risk-${risk}` : null;
    }
  });

  const policyPanel = h('div', { class: 'stack-lg pf-policy' });
  // The CT tab reads the domains of the check on screen, else the box's.
  const ctHost = h('div', { class: 'pf-ct-host' });
  let ctLoading = false;
  function openCt() {
    if (ctPanel || ctLoading) return;
    ctLoading = true;
    ctHost.append(h('div', { class: 'pf-ct-loading' }, Spinner({ showLabel: true })));
    loadCtPanel().then((mod) => {
      clear(ctHost);
      if (ctx.signal.aborted) return;
      ctPanel = mod.mountCtWatch(ctHost, { ctx, domains: () => (session.job ? session.job.domains : parsePortfolioInput(box.value).domains) });
    }).catch((err) => {
      ctLoading = false;
      clear(ctHost);
      ctHost.append(ErrorBanner(err, { title: t('pf.ct.failed'), compact: true }));
      ctx.checkOutdated();
    });
  }
  cleanups.push(() => { if (ctPanel) ctPanel.destroy(); });
  // The Domain security tab reads the facts of the check on screen: it sends nothing.
  const securityHost = h('div', { class: 'pf-sec-host' });
  let securityPanel = null;
  let securityLoading = false;
  function openSecurity() {
    if (securityPanel) {
      securityPanel.refresh();
      return;
    }
    if (securityLoading) return;
    securityLoading = true;
    securityHost.append(h('div', { class: 'pf-sec-loading' }, Spinner({ showLabel: true })));
    loadSecurityPanel().then((mod) => {
      clear(securityHost);
      if (ctx.signal.aborted) return;
      securityPanel = mod.mountSecurity(securityHost, {
        ctx,
        source: () => (session.job ? { facts: rows.map((r) => r.facts), status: session.job.status } : null),
        subject: () => subject()
      });
    }).catch((err) => {
      securityLoading = false;
      clear(securityHost);
      securityHost.append(ErrorBanner(err, { title: t('pf.sec.failed'), compact: true }));
      ctx.checkOutdated();
    });
  }
  cleanups.push(() => { if (securityPanel) securityPanel.destroy(); });
  const tabs = Tabs([
    { id: 'domains', label: t('pf.tab.domains'), content: () => h('div', { class: 'stack pf-domains' }, emptyEl, tilesEl, table.el) },
    { id: 'security', label: t('pf.tab.security'), content: () => securityHost },
    { id: 'policy', label: t('pf.tab.policy'), content: () => policyPanel },
    { id: 'ct', label: t('pf.tab.ct'), content: () => ctHost }
  ], {
    selected: session.tab,
    label: t('nav.portfolio'),
    onChange: (tab) => {
      session.tab = tab;
      if (tab === 'security') openSecurity();
      if (tab === 'policy') renderPolicyMatrix();
      if (tab === 'ct') openCt();
    }
  });
  if (session.tab === 'security') openSecurity();
  if (session.tab === 'ct') openCt();

  // No part of the form: Ctrl/Cmd+Enter in a table filter or the policy editor starts no new run.
  const results = h('div', { class: 'stack-lg pf-results', dataset: { shortcutScope: 'results' } }, headEl, tabs.el);
  container.append(h('div', { class: 'stack-lg pf-view' }, formCard, progressRow, results));

  function domainColumns() {
    const renders = {
      expiry: expiryCell, status: statusCell, registrar: registrarCell, dnssec: dnssecCell, ns: nsCell, caa: caaCell,
      spf: spfCell, dmarc: dmarcCell, dkim: dkimCell, mtaSts: mtaStsCell, parked: parkedCell
    };
    const cols = [
      { key: 'domain', label: t('pf.col.domain'), sortable: true, sortValue: (r) => r.domain, searchValue: searchOf, render: domainCell, className: 'pf-col-domain' },
      ...PORTFOLIO_CELLS.map((c) => ({
        key: c, label: t(`pf.col.${c}`), sortable: true, sortValue: sortOf[c], searchable: false, render: cell(c, renders[c]), className: `pf-col pf-col-${c}`
      }))
    ];
    if (parsed.policy && parsed.policy.rules.length) {
      cols.push({ key: 'policy', label: t('pf.col.policy'), sortable: true, searchable: false, render: policyCell, className: 'pf-col pf-col-policy',
        sortValue: (r) => { const a = audit && audit.rows.find((x) => x.domain === r.domain); return a ? -(a.fail * 100 + a.unknown) : null; } });
    }
    return cols;
  }

  /* --- head, tiles, filter ----------------------------------------------------------- */
  const allFacts = () => rows.map((r) => r.facts);
  const policyFails = (domain) => !!audit && audit.rows.some((r) => r.domain === domain && r.fail > 0);

  function renderHead() {
    const old = headEl.firstElementChild;
    const focused = old && old.contains(document.activeElement) ? document.activeElement : null;
    const focusAction = focused && focused.dataset ? focused.dataset.action : null;
    clear(headEl);
    const job = session.job;
    if (!job) return;
    const notLooked = job.domains.filter((d) => job.run.pending(d).length).length;
    summary = SummaryButton({
      kind: 'portfolio',
      facts: () => (session.job && session.job.status !== 'running'
        ? portfolioSummaryFacts(allFacts(), { at: session.job.finishedAt, stopped: session.job.status === 'stopped', notLooked: session.job.domains.filter((d) => session.job.run.pending(d).length).length, audit })
        : null),
      url: () => (session.job ? ctx.shareUrl(permalinkParams('portfolio', shareParams(session.job.domains))) : null),
      disabled: job.status === 'running'
    });
    const meta = job.status === 'running'
      ? h('span', { class: 'muted text-xs' }, t('pf.runningNow'))
      : h('span', { class: 'muted text-xs', title: job.finishedAt ? formatDateTime(job.finishedAt) : null },
        job.status === 'stopped' && notLooked ? t('pf.stoppedAt', { time: formatRelative(job.finishedAt), count: notLooked }) : t('pf.checkedAt', { time: formatRelative(job.finishedAt) }));
    const exportBtn = (label, action, onClick, title) => Button({ label, icon: 'download', size: 'sm', dataset: { action }, title, onClick });
    headEl.append(h('div', { class: 'card pf-head', dataset: { status: job.status } },
      h('div', { class: 'pf-head-main' },
        h('h2', { class: 'pf-head-title' }, t('pf.resultsTitle', { count: job.domains.length })),
        meta),
      h('div', { class: 'pf-head-actions' },
        summary.el,
        h('div', { class: 'pf-exports', attrs: { role: 'group', 'aria-label': t('table.exportLabel') } },
          exportBtn(t('pf.export.csv'), 'pf-csv', () => exportRows('csv'), t('pf.export.title')),
          exportBtn(t('pf.export.json'), 'pf-json', () => exportRows('json'), t('pf.export.title')),
          exportBtn(t('pf.export.ics'), 'pf-ics', () => exportCalendar(), t('pf.export.icsTitle'))))));
    if (focusAction) {
      const target = headEl.querySelector(`[data-action="${CSS.escape(focusAction)}"]`);
      if (target && !target.disabled) target.focus({ preventScroll: true });
    }
  }

  function renderTiles() {
    const list = allFacts();
    const count = (f) => list.filter((x) => matchesFilter(x, f, { policyFails })).length;
    tiles.domains.set({ value: list.length, pressed: session.filter === 'all' });
    const variants = { expiring: 'error', critical: 'error', unlocked: 'warn', ns: 'error', failed: 'warn' };
    for (const k of PORTFOLIO_TILES) {
      const n = count(k);
      tiles[k].set({ value: n, variant: n ? variants[k] : 'default', pressed: session.filter === k });
    }
    filterSelect.setOptions(PORTFOLIO_FILTERS.filter((f) => f !== 'policy' || (parsed.policy && parsed.policy.rules.length))
      .map((f) => ({ value: f, label: t(`pf.filter.${f}`, { count: count(f) }) })));
    filterSelect.value = session.filter;
  }

  function setFilter(f) {
    // "Fail the policy" while the policy has no rule (cleared, or another workspace's): every domain.
    const noPolicy = f === 'policy' && !(parsed.policy && parsed.policy.rules.length);
    session.filter = PORTFOLIO_FILTERS.includes(f) && !noPolicy ? f : 'all';
    table.setFilter((r) => matchesFilter(r.facts, session.filter, { policyFails }));
    renderTiles();
  }

  /* --- rows and the run -------------------------------------------------------------- */
  let pendingRedraw = new Set();
  let redrawTimer = null;
  /** Redraw the rows of `domains` (batched: at most one table update per 120 ms). */
  function redraw(domains) {
    for (const d of domains) pendingRedraw.add(d);
    if (redrawTimer) return;
    redrawTimer = setTimeout(flush, 120);
  }
  function flush() {
    redrawTimer = null;
    const job = session.job;
    if (!job) return;
    const changed = [];
    for (const d of pendingRedraw) {
      const row = byDomain.get(d);
      if (!row) continue;
      row.facts = job.run.facts(d);
      changed.push(row);
    }
    pendingRedraw = new Set();
    recomputeAudit();
    if (changed.length) table.updateRows(changed);
    renderTiles();
    progressUpdate();
    // The matrix and the security scores redraw every row: only while on screen (and once the run ends).
    if (tabs.getSelected() === 'policy' || job.status !== 'running') renderPolicyMatrix();
    if (securityPanel && (tabs.getSelected() === 'security' || job.status !== 'running')) securityPanel.refresh();
  }

  function progressUpdate() {
    const job = session.job;
    if (!job || job.status !== 'running') return;
    progress.set(job.done, job.domains.length);
  }

  function setRunning(on) {
    const hadFocus = document.activeElement === (on ? runBtn : stopBtn);
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    box.input.readOnly = on;
    if (summary) summary.setDisabled(on);
    ctx.setBusy(on);
    if (hadFocus) (on ? stopBtn : runBtn).focus();
  }

  /** Bind the view to a job: its rows into the table, its events to redraws. */
  function attach(job) {
    if (attached && attached !== job) attached.listeners.delete(onJob);
    attached = job;
    rows = job.domains.map((d) => ({ domain: d, facts: job.run.facts(d) }));
    byDomain = new Map(rows.map((r) => [r.domain, r]));
    recomputeAudit();
    table.setColumns(domainColumns());
    table.setRows(rows);
    job.listeners.add(onJob);
    emptyEl.hidden = true;
    tilesEl.hidden = false;
    table.el.hidden = false;
    renderHead();
    renderTiles();
    setFilter(session.filter);
    renderPolicy();
    if (ctPanel) ctPanel.refresh();
    if (securityPanel) securityPanel.refresh();
    clear(notifyHost);
    if (job.status === 'running') {
      showProgress(true);
      progress.setLabel(t('pf.progress', { count: job.domains.length }));
      progress.set(job.done, job.domains.length);
      notifyHost.append(NotifyButton(job.handle));
      setRunning(true);
    } else {
      showProgress(false);
      setRunning(false);
    }
  }

  function onJob(type, e) {
    const job = session.job;
    if (!job || attached !== job) return;
    if (type === 'event') {
      if (e.type === 'rdap') redraw(job.run.affectedBy(e.domain));
      else if (e.domain) redraw([e.domain]);
      return;
    }
    // done / stopped / error
    flush();
    if (type === 'done') {
      progress.done(t('common.done'));
      setTimeout(() => { if (session.job === job && job.status !== 'running') showProgress(false); }, 1200);
      announce(t('pf.done', { count: job.domains.length }));
    } else {
      showProgress(false);
      if (type === 'stopped' && !ctx.signal.aborted) announce(t('pf.stopped'));
      if (type === 'error') ctx.toast(`${t('error.title')}: ${job.error && job.error.message ? job.error.message : String(job.error)}`, { type: 'error' });
    }
    setRunning(false);
    table.refresh();
    renderHead();
    renderPrompt();
  }

  function stop() {
    if (running()) session.job.controller.abort();
  }

  async function start() {
    const p = parsePortfolioInput(box.value);
    box.setError(null);
    if (!p.domains.length) {
      box.setError(t('pf.needOne'));
      box.focus();
      return;
    }
    if (running()) return;
    if (!ctx.requireOnline()) return;
    let dns;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      return;
    }
    if (ctx.signal.aborted) return;
    session.text = box.value;
    session.prefilled = false;
    session.carried = null;
    session.link = null;
    ctx.setParams(shareParams(p.domains));
    ctx.runStarted(p.domains.length === 1 ? p.domains[0] : null);
    session.job = startRun({ domains: p.domains, reduced: p.reduced, dkim: session.dkim, dns });
    renderBoxStatus();
    renderPrompt();
    setShareAction();
    attach(session.job);
  }

  /** A column's Retry: its failed lookups of that row only (an NS domain's RDAP: every row reading it). */
  async function retryCell(domain, column, failures, btn) {
    const job = session.job;
    if (!job) return;
    if (!ctx.requireOnline()) return;
    if (!job.busy.has(domain)) job.busy.set(domain, new Set());
    const busy = job.busy.get(domain);
    if (busy.has(column)) return;
    busy.add(column);
    if (btn) setRetryBusy(btn);
    const lookups = [...new Set(failures.filter((x) => !x.nsDomain).map((x) => x.lookup))];
    // A new TXT answer means a new SPF count too.
    if (lookups.includes('txt')) lookups.push('spf');
    const nsDomains = [...new Set(failures.filter((x) => x.nsDomain).map((x) => x.nsDomain))];
    try {
      await Promise.all([
        lookups.length ? job.run.retry(domain, lookups, { signal: mergeSignals(ctx.signal) }) : null,
        ...nsDomains.map((d) => job.run.retryRdap(d, { signal: mergeSignals(ctx.signal) }))
      ]);
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      busy.delete(column);
    }
    if (session.job !== job || ctx.signal.aborted) return;
    const hadFocus = !document.activeElement || document.activeElement === document.body || table.el.contains(document.activeElement) || (btn && !btn.isConnected);
    redraw([domain, ...nsDomains.flatMap((d) => job.run.affectedBy(d))]);
    flush();
    if (hadFocus) focusRow(domain, column);
    const left = cellFailures(byDomain.get(domain).facts, column);
    announce(left.length ? left.map((x) => statusText(x.status)).join(' · ') : t('pf.retried', { domain }));
  }

  /**
   * The keyboard focus after a row was redrawn under it: the column's Retry when its lookup still
   * failed, else the row's domain (never lost to the page).
   */
  function focusRow(domain, column) {
    // The table draws updated rows on the next frame: the focus goes to the row drawn then.
    const raf = globalThis.requestAnimationFrame || ((fn) => setTimeout(fn, 16));
    raf(() => setTimeout(() => focusRowNow(domain, column), 0));
  }

  function focusRowNow(domain, column) {
    const active = document.activeElement;
    // the user moved on meanwhile: leave the focus where it is
    if (active && active !== document.body && !table.el.contains(active)) return;
    const tr = [...table.el.querySelectorAll('tbody tr.dt-row')].find((r) => r.querySelector('.pf-domain')?.textContent === domain);
    if (!tr) return;
    const again = tr.querySelector(`[data-cell="${CSS.escape(column)}"]`);
    if (again) {
      again.focus({ preventScroll: true });
      return;
    }
    const name = tr.querySelector('.pf-domain');
    name.setAttribute('tabindex', '-1');
    name.focus({ preventScroll: true });
  }

  /** "Look up" of a row a stopped run left: the lookups it never ran. */
  async function lookUpRow(domain, btn) {
    const job = session.job;
    if (!job || running()) return;
    if (!ctx.requireOnline()) return;
    if (!job.busy.has(domain)) job.busy.set(domain, new Set());
    const busy = job.busy.get(domain);
    if (busy.has('*')) return;
    busy.add('*');
    for (const c of PORTFOLIO_CELLS) busy.add(c);
    if (btn) setRetryBusy(btn);
    redraw([domain]);
    flush();
    try {
      await job.run.retry(domain, job.run.pending(domain).length ? job.run.pending(domain) : [...PORTFOLIO_LOOKUPS], { signal: mergeSignals(ctx.signal) });
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      busy.clear();
    }
    if (session.job !== job || ctx.signal.aborted) return;
    // Every row looked up after the stop: the portfolio is complete again.
    if (job.status === 'stopped' && job.domains.every((d) => !job.run.pending(d).length)) {
      job.status = 'done';
      job.finishedAt = new Date();
    }
    redraw([domain]);
    flush();
    renderHead();
    focusRow(domain, '*');
    announce(t('pf.retried', { domain }));
  }

  function setShareAction() {
    const job = session.job;
    ctx.setActions(CopyButton(() => ctx.shareUrl(job ? shareParams(job.domains) : ctx.params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  /* --- exports ----------------------------------------------------------------------- */
  const shown = () => table.getVisibleRows().map((r) => r.facts);
  const subject = () => (session.job && session.job.domains.length === 1 ? session.job.domains[0] : `${session.job ? session.job.domains.length : 0}-domains`);
  function saved(file) {
    toast(t('pf.exported', { file }), { type: 'success', timeout: 2500 });
  }

  function exportRows(format) {
    const list = shown().map(exportRow);
    if (format === 'csv') {
      const file = downloadText(timestampedName('domain-portfolio', 'csv', subject()), toCsv(list, EXPORT_COLUMNS.map((key) => ({ key }))), 'text/csv;charset=utf-8');
      saved(file);
      return;
    }
    const doc = { format: 'domainscope-portfolio', v: 1, app: 'DomainScope', version: ctx.version, at: new Date().toISOString(), checkedAt: session.job && session.job.finishedAt, domains: list, facts: shown() };
    saved(downloadText(timestampedName('domain-portfolio', 'json', subject()), `${toJson(doc)}\n`, 'application/json'));
  }

  function exportCalendar() {
    const events = calendarEvents(shown(), t);
    if (!events.length) {
      toast(t('pf.ics.none'), { type: 'info' });
      return;
    }
    const text = buildCalendar(events, { now: new Date(), name: t('pf.ics.name') });
    saved(downloadText(timestampedName('domain-expiry', 'ics', subject()), text, 'text/calendar;charset=utf-8'));
  }

  /* --- the policy -------------------------------------------------------------------- */
  const policyStatus = h('div', { class: 'pf-pol-status text-sm', attrs: { 'aria-live': 'polite' } });
  const jsonBox = textarea({
    label: t('pf.pol.json'),
    value: policyTextNow,
    rows: 10,
    className: 'pf-pol-json',
    attrs: { 'data-role': 'pf-policy-json', spellcheck: 'false' },
    onInput: (v) => {
      policyTextNow = v;
      parsed = v.trim() ? parsePolicy(v) : { policy: null, errors: [] };
      if (parsed.policy) syncRuleControls(parsed.policy);
      savePolicy();
      policyChanged();
    }
  });
  const nameField = textInput({
    label: t('pf.pol.name'),
    value: parsed.policy && parsed.policy.name ? parsed.policy.name : '',
    className: 'pf-pol-name',
    attrs: { 'data-role': 'pf-policy-name' },
    onInput: () => fromControls()
  });
  /** One row of controls per rule. */
  const ruleRows = new Map();

  /** A list rule's control: its entries one after another, ';' between them (a registrar's name has commas). */
  const LIST_SEPARATOR = '; ';
  const listEntries = (text) => String(text || '').split(';').map((s) => s.trim()).filter(Boolean);

  function ruleControls(r) {
    const on = checkbox({ label: h('span', null, t(`pol.rule.${r.id}`), ' ', h('code', { class: 'pf-pol-id' }, r.id)), className: 'pf-pol-on', onChange: () => fromControls() });
    on.input.dataset.rule = r.id;
    const parts = { on };
    const label = t(`pol.rule.${r.id}`);
    // A value changed on a rule that is off turns it on: the value is what the user wants checked.
    const touched = () => {
      if (!on.checked) on.checked = true;
      fromControls();
    };
    const sel = (options, value, aria) => {
      const s = h('select', { class: 'select select-sm', attrs: { 'aria-label': aria }, on: { change: touched } },
        options.map((o) => h('option', { value: String(o.value) }, o.label)));
      s.value = String(value);
      return s;
    };
    if (r.kind === 'number' || r.kind === 'ordered') {
      parts.op = sel(POLICY_OPS.map((o) => ({ value: o, label: o })), r.op, `${label} · ${t('pf.pol.op')}`);
    }
    if (r.kind === 'number') {
      parts.value = h('input', { type: 'number', class: 'input input-sm pf-pol-num', min: r.min, max: r.max, value: String(parseInt(String(r.example).replace(/\D+/g, ''), 10) || 0),
        attrs: { 'aria-label': `${label} · ${t('pf.pol.value')}`, inputmode: 'numeric' }, on: { input: touched } });
    } else if (r.kind === 'ordered') {
      parts.value = sel(r.levels.map((l) => ({ value: l, label: l })), String(r.example).replace(/^[<>=!]+\s*/, ''), `${label} · ${t('pf.pol.value')}`);
    } else if (r.kind === 'bool') {
      parts.value = sel([{ value: 'true', label: t('pf.pol.yes') }, { value: 'false', label: t('pf.pol.no') }], String(r.example), `${label} · ${t('pf.pol.value')}`);
    } else if (r.kind === 'enum') {
      parts.value = sel(r.values.map((v) => ({ value: v, label: v })), r.example, `${label} · ${t('pf.pol.value')}`);
    } else {
      parts.value = h('input', { type: 'text', class: 'input input-sm mono pf-pol-list', value: (r.example || []).join(LIST_SEPARATOR), placeholder: t('pf.pol.listHint'),
        attrs: { 'aria-label': `${label} · ${t('pf.pol.value')} (${t('pf.pol.listHint')})`, spellcheck: 'false' }, on: { input: touched } });
    }
    parts.el = h('div', { class: 'pf-pol-rule', dataset: { rule: r.id } }, on.el, h('div', { class: 'pf-pol-value' }, parts.op || null, parts.value));
    return parts;
  }

  for (const r of POLICY_RULES) ruleRows.set(r.id, ruleControls(r));

  /** The controls show a policy (a preset, the JSON read back). */
  function syncRuleControls(policy) {
    const by = new Map((policy ? policy.rules : []).map((e) => [e.id, e]));
    for (const [rid, c] of ruleRows) {
      const e = by.get(rid);
      c.on.checked = !!e;
      c.el.classList.toggle('is-on', !!e);
      if (!e) continue;
      const r = policyRule(rid);
      if (c.op) c.op.value = e.op;
      if (r.kind === 'number' || r.kind === 'ordered' || r.kind === 'enum') c.value.value = String(e.value);
      else if (r.kind === 'bool') c.value.value = String(e.value);
      else c.value.value = e.value.join(LIST_SEPARATOR);
    }
    if (document.activeElement !== nameField.input) nameField.value = policy && policy.name ? policy.name : '';
  }

  /** The JSON the controls describe (the editor's other half). */
  function fromControls() {
    const rules = {};
    for (const [rid, c] of ruleRows) {
      c.el.classList.toggle('is-on', c.on.checked);
      if (!c.on.checked) continue;
      const r = policyRule(rid);
      if (r.kind === 'number') rules[rid] = `${c.op.value} ${c.value.value === '' ? 0 : c.value.value}`;
      else if (r.kind === 'ordered') rules[rid] = `${c.op.value} ${c.value.value}`;
      else if (r.kind === 'bool') rules[rid] = c.value.value === 'true';
      else if (r.kind === 'enum') rules[rid] = c.value.value;
      else rules[rid] = listEntries(c.value.value);
    }
    const name = nameField.value.trim() || null;
    const result = parsePolicy({ name, rules });
    const text = Object.keys(rules).length || name ? policyText(result.policy || { name, rules: [] }) : '';
    policyTextNow = text;
    parsed = text ? (result.errors.length ? { policy: result.policy, errors: result.errors } : result) : { policy: null, errors: [] };
    jsonBox.value = text;
    savePolicy();
    policyChanged();
  }

  const savePolicy = debounce(() => {
    state.setWorkspaceData('policy', policyTextNow);
  }, 400);
  cleanups.push(() => savePolicy.flush());

  function applyPreset(pid) {
    const p = presetPolicy(pid);
    policyTextNow = policyText(p);
    parsed = { policy: p, errors: [] };
    jsonBox.value = policyTextNow;
    syncRuleControls(p);
    state.setWorkspaceData('policy', policyTextNow);
    policyChanged();
    announce(t('pf.pol.presetApplied', { name: t(`pol.preset.${pid}`) }));
  }

  function clearPolicy() {
    policyTextNow = '';
    parsed = { policy: null, errors: [] };
    jsonBox.value = '';
    syncRuleControls(null);
    state.setWorkspaceData('policy', '');
    policyChanged();
  }

  const fileInput = h('input', {
    type: 'file', class: 'sr-only', attrs: { accept: '.json,application/json', tabindex: '-1', 'aria-hidden': 'true' },
    on: {
      change: async () => {
        const file = fileInput.files && fileInput.files[0];
        fileInput.value = '';
        if (!file) return;
        // A policy is a few hundred bytes: a file far past the editor's limit is never read whole.
        const tooLarge = () => toast(t('pf.pol.importTooLarge', { size: formatBytes(POLICY_MAX_CHARS) }), { type: 'error' });
        if (file.size > POLICY_MAX_CHARS * 4) {
          tooLarge();
          return;
        }
        try {
          const text = (await file.text()).replace(/^\uFEFF/, '');
          if (text.length > POLICY_MAX_CHARS) {
            tooLarge();
            return;
          }
          jsonBox.value = text;
          policyTextNow = text;
          parsed = parsePolicy(text);
          if (parsed.policy) syncRuleControls(parsed.policy);
          state.setWorkspaceData('policy', text);
          policyChanged();
        } catch {
          toast(t('pf.pol.importFailed'), { type: 'error' });
        }
      }
    }
  });

  function exportPolicy() {
    const policy = parsed.policy || { name: null, rules: [] };
    const file = downloadText(timestampedName('domainscope-policy', 'json', policy.name ? policy.name.replace(/\s+/g, '-') : null), policyText(policy), 'application/json');
    saved(file);
  }

  const matrixHost = h('div', { class: 'pf-matrix-host' });
  let matrixTable = null;

  /** The workspace's accepted risks, read now (lib/waivers.js). */
  const waiversNow = () => readWaivers(state.workspaceData('waivers'), { now: Date.now() });

  function recomputeAudit() {
    audit = session.job && parsed.policy && parsed.policy.rules.length
      ? auditPortfolio(parsed.policy, rows.map((r) => r.facts), { waivers: waiversNow(), now: Date.now() }) : null;
  }

  /** Where the focus goes once the matrix is drawn again: the cell a click accepted. */
  let matrixFocus = null;

  /** "Accept…" on a failed cell: the dialog, then the waiver into the workspace (the subscription redraws the matrix). */
  async function acceptRule(domain, rule) {
    let ui;
    try {
      ui = await loadWaivers();
    } catch (err) {
      ctx.checkOutdated();
      toast(err && err.message ? err.message : String(err), { type: 'error' });
      return;
    }
    const subject = `${t(`pol.rule.${rule.id}`)} (${rule.id} ${rule.required})`;
    const input = await ui.openWaiverDialog({ kind: 'rule', domain, ref: rule.id, subject });
    if (!input) return;
    try {
      matrixFocus = { domain, rule: rule.id };
      const { waiver, persisted } = await ui.acceptRisk(input, state);
      announce(t('wvr.saved', { date: waiver.expires, subject: `${domain} · ${rule.id}` }));
      if (!persisted) toast(t('wvr.notSaved', { reason: storageErrorText(state.workspaceError) }), { type: 'warn' });
    } catch (err) {
      matrixFocus = null;
      toast(err && err.code ? ui.waiverErrorText(err.code) : String(err && err.message ? err.message : err), { type: 'error' });
    }
  }

  function policyChanged() {
    renderPolicyStatus();
    recomputeAudit();
    if (session.job) {
      table.setColumns(domainColumns());
      setFilter(session.filter);
    }
    renderPolicyMatrix({ rebuild: true });
  }

  function renderPolicyStatus() {
    clear(policyStatus);
    policyStatus.append(h('p', { class: 'muted' }, Icon('briefcase', { size: 14 }), ' ', t('pf.pol.saved', { workspace: workspaceLabel(state.workspace) })));
    if (!parsed.policy || !parsed.policy.rules.length) {
      if (!parsed.errors.length || parsed.errors.every((e) => e.code === 'empty')) policyStatus.append(h('p', { class: 'muted', dataset: { policy: 'empty' } }, t('pf.pol.empty')));
    }
    const errs = parsed.errors.filter((e) => e.code !== 'empty');
    if (errs.length) {
      policyStatus.append(Alert({
        variant: 'warn', compact: true, title: t('pf.pol.leftOut'),
        children: h('ul', { class: 'pf-pol-errors' }, errs.map((e) => h('li', { dataset: { code: e.code } }, t(`pol.err.${e.code}`, e))))
      }));
    }
  }

  function renderPolicy() {
    if (policyPanel.childElementCount) {
      renderPolicyMatrix({ rebuild: true });
      return;
    }
    const presets = h('div', { class: 'cluster pf-presets', attrs: { role: 'group', 'aria-label': t('pf.pol.presets') } },
      h('span', { class: 'text-sm muted' }, `${t('pf.pol.presets')}:`),
      POLICY_PRESET_IDS.map((pid) => Button({ label: t(`pol.preset.${pid}`), size: 'sm', dataset: { preset: pid }, onClick: () => applyPreset(pid) })));
    const editor = Card({
      title: t('pf.pol.title'),
      icon: 'list',
      className: 'pf-pol-card',
      actions: h('div', { class: 'cluster pf-pol-actions' },
        Button({ label: t('pf.pol.export'), icon: 'download', size: 'sm', dataset: { action: 'pf-policy-export' }, onClick: exportPolicy }),
        Button({ label: t('pf.pol.import'), icon: 'upload', size: 'sm', dataset: { action: 'pf-policy-import' }, onClick: () => fileInput.click() }),
        Button({ label: t('pf.pol.clear'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'pf-policy-clear' }, onClick: clearPolicy }),
        fileInput),
      children: h('div', { class: 'stack' },
        h('p', { class: 'text-sm muted' }, t('pf.pol.intro')),
        presets,
        nameField.el,
        h('fieldset', { class: 'fieldset pf-pol-rules' }, h('legend', { class: 'field-label' }, t('pf.pol.rules')), [...ruleRows.values()].map((c) => c.el)),
        jsonBox.el,
        policyStatus)
    });
    policyPanel.append(editor, Card({ title: t('pf.matrix.title'), icon: 'check-circle', className: 'pf-matrix-card', children: matrixHost }));
    syncRuleControls(parsed.policy);
    renderPolicyStatus();
    renderPolicyMatrix({ rebuild: true });
  }

  function matrixColumns() {
    const cols = [
      { key: 'domain', label: t('pf.col.domain'), sortable: true, sortValue: (r) => r.domain, render: (r) => h('strong', { class: 'mono pf-break' }, r.domain), className: 'pf-mx-domain' },
      {
        key: 'result', label: t('pf.matrix.result'), sortable: true, sortValue: (r) => -(r.fail * 100 + r.unknown),
        render: (r) => h('span', { class: 'pf-cell', dataset: { result: r.fail ? 'fail' : r.unknown ? 'unknown' : 'pass' } },
          r.fail ? Badge(t('pf.policy.fail', { count: r.fail }), { variant: 'error', icon: 'x-circle' }) : null,
          r.unknown ? Badge(t('pf.policy.unknown', { count: r.unknown })) : null,
          !r.fail && !r.unknown ? Badge(t('pf.policy.pass'), { variant: 'ok', icon: 'check' }) : null,
          r.waived ? Badge(t('pf.policy.waived', { count: r.waived }), { icon: 'shield' }) : null)
      }
    ];
    (audit ? audit.rules : []).forEach((rule, i) => cols.push({
      key: `rule-${rule.id}`,
      label: `${rule.id} ${rule.required}`,
      title: t(`pol.rule.${rule.id}`),
      sortable: true,
      wrap: true,
      sortValue: (r) => ({ fail: 0, unknown: 1, waived: 2, pass: 3 }[r.cells[i].status]),
      searchValue: (r) => `${evidenceText(r.cells[i], t)} ${waiverText(r.cells[i], t)}`,
      className: 'pf-mx-cell',
      render: (r) => {
        const c = r.cells[i];
        const variant = c.status === 'pass' ? 'ok' : c.status === 'fail' ? 'error' : c.status === 'waived' ? 'info' : 'neutral';
        const icon = { pass: 'check', fail: 'x-circle', waived: 'shield' }[c.status] || 'help';
        const waiver = waiverText(c, t);
        // a failed rule can be accepted as a risk (an owner, a reason, an end date): it is then neither a pass nor a fail
        const accept = c.status === 'fail' ? Button({
          label: t('wvr.acceptRule'), size: 'sm', variant: 'ghost', className: 'pf-accept', title: t('wvr.acceptRuleTitle', { domain: r.domain, rule: rule.id }),
          // not data-rule: that names the cell itself
          dataset: { action: 'pf-accept', waive: rule.id }, onClick: () => acceptRule(r.domain, rule)
        }) : null;
        return h('span', { class: 'pf-cell', dataset: { status: c.status, rule: c.id, domain: r.domain }, attrs: c.status === 'waived' ? { tabindex: '-1' } : {} },
          Badge(t(`pol.st.${c.status}`), { variant, icon }),
          h('span', { class: 'text-xs pf-evidence' }, keepDates(evidenceText(c, t))),
          waiver ? h('span', { class: ['text-xs', 'pf-waiver', { 'is-expired': !c.waiver }], dataset: { role: 'pf-waiver' } }, keepDates(waiver)) : null,
          accept);
      }
    }));
    return cols;
  }

  function renderPolicyMatrix({ rebuild = false } = {}) {
    if (!policyPanel.childElementCount) return;
    const job = session.job;
    if (!job) {
      clear(matrixHost);
      matrixTable = null;
      matrixHost.append(h('p', { class: 'muted text-sm', dataset: { matrix: 'no-run' } }, t('pf.matrix.noRun')));
      return;
    }
    if (!audit) {
      clear(matrixHost);
      matrixTable = null;
      matrixHost.append(h('p', { class: 'muted text-sm', dataset: { matrix: 'no-rules' } }, t('pf.matrix.noRules')));
      return;
    }
    if (!matrixTable || rebuild) {
      clear(matrixHost);
      matrixTable = DataTable({
        columns: matrixColumns(),
        rowKey: (r) => r.domain,
        rows: audit.rows,
        search: true,
        sort: { key: 'result', dir: 'asc' },
        export: false,
        cellLabels: true,
        maxHeight: null,
        caption: t('pf.matrix.title'),
        className: 'pf-matrix',
        toolbar: h('div', { class: 'cluster' },
          Button({ label: t('pf.matrix.csv'), icon: 'download', size: 'sm', dataset: { action: 'pf-matrix-csv' }, onClick: () => exportMatrix('csv') }),
          Button({ label: t('pf.matrix.json'), icon: 'download', size: 'sm', dataset: { action: 'pf-matrix-json' }, onClick: () => exportMatrix('json') }))
      });
      matrixHost.append(h('p', { class: 'text-sm pf-matrix-counts', dataset: { matrix: 'counts' } }), matrixTable.el);
    } else {
      matrixTable.setRows(audit.rows);
    }
    const counts = matrixHost.querySelector('.pf-matrix-counts');
    clear(counts);
    counts.append(matrixCountsText(audit.counts, t));
    if (job.status === 'running') counts.append(h('span', { class: 'muted' }, ` · ${t('pf.matrix.running')}`));
    if (matrixFocus) {
      // the cell just accepted (the table draws its rows on the next frame)
      const want = matrixFocus;
      matrixFocus = null;
      requestAnimationFrame(() => requestAnimationFrame(() => {
        const cell = [...matrixHost.querySelectorAll('.pf-cell[data-status="waived"]')].find((el) => el.dataset.rule === want.rule && el.dataset.domain === want.domain);
        if (cell) cell.focus();
      }));
    }
  }

  function exportMatrix(format) {
    if (!audit) return;
    if (format === 'csv') {
      saved(downloadText(timestampedName('policy-audit', 'csv', subject()), auditCsv(audit, { t }), 'text/csv;charset=utf-8'));
      return;
    }
    const doc = auditJson(audit, { t, policy: parsed.policy, version: ctx.version });
    saved(downloadText(timestampedName('policy-audit', 'json', subject()), `${toJson(doc)}\n`, 'application/json'));
  }

  /* --- initial state ------------------------------------------------------------------ */
  stopBtn.hidden = true;
  renderBoxStatus();
  renderPrompt();
  if (session.job) {
    setShareAction();
    attach(session.job);
  } else {
    // Without a run the Domains tab says what the table will hold; the policy tab edits the
    // workspace's policy all the same.
    tilesEl.hidden = true;
    table.el.hidden = true;
    renderPolicy();
  }
  // The accepted risks changed (an "Accept…" here, the Workspaces dialog, another tab): the matrix follows.
  cleanups.push(state.subscribe(({ key, value }) => {
    if (key !== 'workspaceData' || !value || !Array.isArray(value.parts) || !value.parts.includes('waivers')) return;
    policyChanged();
  }));
  // The policy changed in another tab or by an imported workspace.
  cleanups.push(state.subscribe(({ key, value }) => {
    if (key !== 'workspaceData' || !value || !Array.isArray(value.parts) || !value.parts.includes('policy')) return;
    const text = state.workspaceData('policy') || '';
    if (text === policyTextNow) return;
    policyTextNow = text;
    parsed = text.trim() ? parsePolicy(text) : { policy: null, errors: [] };
    jsonBox.value = text;
    syncRuleControls(parsed.policy);
    policyChanged();
  }));

  active = {
    teardown() {
      if (attached) attached.listeners.delete(onJob);
      if (redrawTimer) clearTimeout(redrawTimer);
      for (const fn of cleanups) {
        try {
          fn();
        } catch {
          // a cleanup never blocks the others
        }
      }
    },
    result() {
      const job = session.job;
      if (!job || job.status === 'running' || !job.finishedAt) return null;
      return { subject: job.domains.length === 1 ? job.domains[0] : null, at: job.finishedAt, params: shareParams(job.domains) };
    },
    rerun() {
      if (session.job) box.value = session.job.domains.join('\n');
      start();
    },
    update(params) {
      const text = params.domains ? linkText(params.domains) : '';
      if (!text) return true;
      session.link = text;
      if (!running() && fillReplaces(box.value, session.job ? session.job.domains : null, (x) => parsePortfolioInput(x).domains, session.carried)) {
        box.value = text;
        session.text = text;
        session.prefilled = false;
        session.carried = isFillOnly(params) ? text : null;
        renderBoxStatus();
      }
      renderPrompt();
      return true;
    }
  };
}

/** Detach the view (a running check goes on: the module keeps it). */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * The portfolio on screen (kept by the shell when the view is left), or null while none is
 * finished or a run goes on.
 * @returns {{ subject: string|null, at: Date, params: object }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: the same domains again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take a new route's list without a re-mount: it only fills the box (never runs).
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, result, rerun, update };
