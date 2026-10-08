/**
 * views/health.js — "Domain Health": one click runs lib/health.domainHealth (NS, SOA, MX,
 * SPF with the recursive 10-lookup budget, DMARC, DKIM, CAA, DNSSEC, wildcard, MTA-STS,
 * TLS-RPT, BIMI, IPv6, HTTPS records and RDAP registration / expiry) and shows:
 *
 * - a summary with a traffic light, a score and ok / info / warning / error counts;
 * - every check grouped (DNS · Email security · Certificates & DNSSEC · Registration),
 *   worst first, each with a severity icon and a translated title + explanation;
 * - detail panels: registration (RDAP, expiry countdown), DNSSEC, email security (SPF tree
 *   with lookup meter, DMARC tags, DKIM selectors), MTA-STS, CAA ("which CAs may issue", with
 *   the RFC 8657 restrictions and what they mean for the next renewal) and the DNS records
 *   that were read.
 * - MTA-STS policy: the DNS check reads the `_mta-sts` TXT record only. "Check the policy" fetches
 *   https://mta-sts.<domain>/.well-known/mta-sts.txt through ONE Globalping probe (a browser
 *   cannot read it: no CORS) and validates it with lib/mtasts.js. Nothing is sent before that
 *   click; the first send of a page session shows the consent + cost dialog of
 *   ui/globalping-gate.js (its own consent, the quota shared with SSL Targets › Verify). The
 *   result belongs to the report on screen: a language switch keeps it (a fetch in flight goes
 *   on polling its paid measurement), a new check drops it, and "Report (JSON)" carries it.
 *
 * "Copy summary" in the hero (ui/summary-button.js): the verdict, score, counts and the worst
 * problems as Markdown for Jira / Slack, or plain text; the score and the traffic light come from
 * lib/summary.js, which the summary shares. Its link is the report's (domain and the selectors it
 * was checked with), never the route's: a new check changes the route before its report replaces
 * the one on screen, and one stopped or failed leaves the old report there. It is disabled while a
 * check runs.
 *
 * Shareable: `#/health?domain=example.com` (also `name=`) runs on open; with `run=0` (a domain
 * carried over from another tool, lib/session.js) it is only filled in. The finished report is
 * kept for the page session (`result()` / `snapshot()`): coming back shows it without a new check.
 */

import { h, clear, uid } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, CopyButton, Disclosure, EmptyState, ErrorBanner, ExternalLink, Icon, KeyValueList, KindBadge,
  ProgressBar, SegmentedControl, SeverityIcon, announce, describeError, setButtonBusy, textInput
} from '../ui/components.js';
import {
  registerStrings, hasString, formatNumber, formatDate, formatDateTime, formatDuration, formatRelative, formatRegion, daysUntil, getLang
} from '../i18n.js';
import {
  domainHealth, applyRdap, caaRestrictionNotes, DEFAULT_DKIM_SELECTORS, HEALTH_I18N, SPF_LOOKUP_LIMIT, SPF_VOID_LIMIT, CAA_ISSUERS,
  LOOKUP_FAILED_PARAM
} from '../lib/health.js';
import { rdapDomain } from '../lib/rdap.js';
import { rdapStatus } from '../lib/sourcestatus.js';
import { NaMark, RetryButton, statusText } from '../ui/source-status.js';
import {
  MTA_STS_I18N, MTA_STS_PATH, mtaStsPolicyHost, mtaStsPolicyUrl, mtaStsPolicyRequest, interpretPolicyFetch, validateMtaSts, mtaStsExport
} from '../lib/mtasts.js';
import { GP_LIMITS } from '../lib/globalping.js';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from '../lib/dnswire.js';
import { classifyResolution, ipVersion, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { toJson } from '../lib/export.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from '../ui/globalping-gate.js';
import { SummaryButton } from '../ui/summary-button.js';
import { ReportButton } from '../ui/report-button.js';
import { ExpectedCaaBadge, expectedCasChanged } from '../ui/expected-ca.js';
import { healthScore, trafficLight, permalinkParams } from '../ui/view-summaries.js';
import { errorKind, mergeSignals, onceAsync, splitList } from '../lib/util.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { scoreHealth } from '../lib/healthscore.js';

/** Route id (`#/health`). */
export const id = 'health';
/** i18n key of the page title. */
export const titleKey = 'nav.health';
/** Icon name (ui/components.js Icon). */
export const icon = 'activity';

/** Check groups in display order (lib/health HEALTH_CATEGORIES values). */
export const HEALTH_GROUPS = Object.freeze(['dns', 'email', 'security', 'registration', 'web']);
/** Severity order, worst first. */
export const SEVERITY_ORDER = Object.freeze(['error', 'warn', 'info', 'ok']);

/**
 * The checks with a "Show the fix" (lib/fixes.js HEALTH_FIX_IDS; a unit test keeps the two equal):
 * the panel and its libraries load on the first click, so the list lives here.
 */
export const FIXABLE_CHECKS = Object.freeze(['caa.cert-denied', 'caa.critical-unknown', 'caa.missing', 'dmarc.missing', 'dmarc.multiple', 'dmarc.pct',
  'dmarc.policy-none', 'dmarc.rua-missing', 'dmarc.sp-none', 'mx.none', 'mx.null-mixed', 'spf.after-all', 'spf.all-missing', 'spf.all-neutral',
  'spf.all-pass', 'spf.lookups-exceeded', 'spf.lookups-high', 'spf.missing', 'spf.multiple', 'spf.null-mx', 'spf.ptr', 'spf.redirect-ignored',
  'tls-rpt.missing']);

/** ui/fix-panel.js with lib/fixes.js (the zone parser and linter come along), on the first "Show the fix". */
const loadFixPanel = onceAsync(() => import('../ui/fix-panel.js'));
/** ui/delegation-panel.js with lib/delegation.js, on the first "Check the delegation" (the Delegation card). */
const loadDelegation = onceAsync(() => import('../ui/delegation-panel.js'));
/** ui/takeover-panel.js, on the first "Check dependencies (RDAP)" (the Dependencies card); lib/takeover.js and lib/rdap.js load with its check. */
const loadDependencies = onceAsync(() => import('../ui/takeover-panel.js'));
/** ui/health-v2.js (SPEC §5.78): the Web step, problems first and the Web card, with the first report. */
const loadV2 = onceAsync(() => import('../ui/health-v2.js'));

// Every health.<id>.title / .detail string (EN + TR) ships with lib/health.js, every
// mtasts.<finding>.title / .detail and mtasts.head.<key> with lib/mtasts.js.
registerStrings('en', HEALTH_I18N.en);
registerStrings('tr', HEALTH_I18N.tr);
registerStrings('en', MTA_STS_I18N.en);
registerStrings('tr', MTA_STS_I18N.tr);

registerStrings('en', {
  'hlt.domain': 'Domain',
  'hlt.placeholder': 'example.com',
  'hlt.run': 'Check health',
  'hlt.options': 'Options',
  'hlt.dkimExtra': 'Extra DKIM selectors',
  'hlt.dkimExtraHint': '{count} common selectors are always tried. Add your own (e.g. from a DKIM-Signature “s=” tag), comma-separated.',
  'hlt.invalid': 'Enter a domain name such as example.com.',
  'hlt.examples': 'Try:',
  'hlt.emptyTitle': 'Check a domain’s DNS, email and registration health',
  'hlt.emptyBody': 'Name servers, SOA, MX, SPF (with the 10-lookup limit), DMARC, DKIM, CAA, DNSSEC, wildcard DNS and RDAP expiry — in one go, from your browser.',
  'hlt.progress': 'Checking {domain}',
  'hlt.step.records': 'DNS records',
  'hlt.step.ns': 'Name servers',
  'hlt.step.mx': 'Mail servers',
  'hlt.step.spf': 'SPF',
  'hlt.step.dmarc': 'DMARC',
  'hlt.step.dkim': 'DKIM selectors',
  'hlt.step.caa': 'CAA',
  'hlt.step.dnssec': 'DNSSEC',
  'hlt.step.wildcard': 'Wildcard test',
  'hlt.step.rdap': 'Registration (RDAP)',
  'hlt.failed': 'The health check could not run',

  'hlt.light.error': 'Problems found',
  'hlt.light.warn': 'Needs attention',
  'hlt.light.ok': 'Healthy',
  'hlt.light.errorBody': 'Fix the errors first — they break mail delivery, resolution or security for real users.',
  'hlt.light.warnBody': 'Nothing is broken, but some settings are weak or risky.',
  'hlt.light.okBody': 'No problems found in {count} checks.',
  'hlt.score': 'Score',
  'hlt.scoreTitle': 'Each category loses 40 per error and 15 per warning; the score is their weighted mean, at most 79 with an error and 89 with a warning. Info items do not count.',
  'hlt.grade': 'Grade {grade}',
  'hlt.step.web': 'www and the HTTPS record',
  'hlt.checkedAt': 'Checked {time}',
  'hlt.zone': 'Zone: {zone}',
  'hlt.checkZone': 'Check {zone}',
  'hlt.download': 'Report (JSON)',
  'hlt.count.error': { one: '{count} error', other: '{count} errors' },
  'hlt.count.warn': { one: '{count} warning', other: '{count} warnings' },
  'hlt.count.info': { one: '{count} note', other: '{count} notes' },
  'hlt.count.ok': { one: '{count} passed', other: '{count} passed' },
  'hlt.filter': 'Show',
  'hlt.filter.all': 'All checks',
  'hlt.filter.problems': 'Warnings & errors',
  'hlt.noProblems': 'No warnings or errors in this group.',
  'hlt.fix.show': 'Show the fix',
  'hlt.fix.hide': 'Hide the fix',
  'hlt.checksTitle': 'Checks',
  'hlt.detailsTitle': 'Details',
  'hlt.links': 'More about this domain:',

  'hlt.rdap.title': 'Registration (RDAP)',
  'hlt.rdap.registrar': 'Registrar',
  'hlt.rdap.ianaId': 'IANA ID {id}',
  'hlt.rdap.created': 'Registered',
  'hlt.rdap.updated': 'Last changed',
  'hlt.rdap.expires': 'Expires',
  'hlt.rdap.daysLeft': { zero: 'expires today', one: '{count} day left', other: '{count} days left' },
  'hlt.rdap.daysAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'hlt.rdap.status': 'Status',
  'hlt.rdap.nameservers': 'Name servers (registry)',
  'hlt.rdap.dnssec': 'DNSSEC delegation',
  'hlt.rdap.signed': 'signed',
  'hlt.rdap.unsigned': 'not signed',
  'hlt.rdap.server': 'RDAP server',
  'hlt.rdap.abuse': 'Abuse contact',
  'hlt.rdap.domain': 'Registered domain',
  'hlt.rdap.unsupported': 'The .{tld} registry offers no RDAP service, so registration and expiry dates cannot be read from the browser.',
  'hlt.rdap.unsupportedTr': 'For .tr domains use the registry’s own WHOIS: nic.tr / TRABİS.',
  'hlt.rdap.notFound': '{domain} is not registered (the registry answered “not found”).',
  'hlt.rdap.error': 'Registration data could not be retrieved.',
  'hlt.rdap.skipped': 'Not checked.',
  'hlt.rdap.retried': 'Registration data loaded.',

  'hlt.dnssec.title': 'DNSSEC',
  'hlt.dnssec.broken': 'Broken — validating resolvers fail',
  'hlt.dnssec.validated': 'Signed and validated',
  'hlt.dnssec.signed': 'Signed, not validated',
  'hlt.dnssec.unsigned': 'Not signed',
  'hlt.dnssec.unknown': 'Unknown',
  'hlt.dnssec.fromZone': 'Not a zone apex: this is the state of the zone {zone}.',
  'hlt.dnssec.ds': 'DS records (at the parent)',
  'hlt.dnssec.dnskey': 'DNSKEY records (in the zone)',
  'hlt.dnssec.algorithms': 'Algorithms',
  'hlt.dnssec.ede': 'Resolver errors',
  'hlt.dnssec.ksk': 'KSK',
  'hlt.dnssec.zsk': 'ZSK',
  'hlt.col.keyTag': 'Key tag',
  'hlt.col.algorithm': 'Algorithm',
  'hlt.col.digest': 'Digest',
  'hlt.col.role': 'Role',

  'hlt.mail.title': 'Email security',
  'hlt.spf': 'SPF',
  'hlt.spf.none': 'No SPF record.',
  'hlt.spf.lookups': 'DNS lookups: {count} of {limit}',
  'hlt.spf.void': 'Void lookups: {count} of {limit}',
  'hlt.spf.tree': 'Include tree',
  'hlt.spf.lookupCount': { one: '{count} lookup', other: '{count} lookups' },
  'hlt.spf.voidBadge': 'void',
  'hlt.spf.truncated': 'The tree is incomplete (too many nested lookups to follow).',
  'hlt.dmarc': 'DMARC',
  'hlt.dmarc.none': 'No DMARC record.',
  'hlt.dmarc.inherited': 'Inherited from {org}',
  'hlt.dmarc.foundAt': 'Published at _dmarc.{domain}',
  'hlt.dmarc.p': 'Policy (p)',
  'hlt.dmarc.sp': 'Subdomain policy (sp)',
  'hlt.dmarc.pct': 'Applies to (pct)',
  'hlt.dmarc.rua': 'Aggregate reports (rua)',
  'hlt.dmarc.ruf': 'Failure reports (ruf)',
  'hlt.dmarc.align': 'Alignment DKIM / SPF',
  'hlt.dmarc.strict': 'strict',
  'hlt.dmarc.relaxed': 'relaxed',
  'hlt.dkim': 'DKIM',
  'hlt.dkim.none': 'No DKIM key found at the {count} selectors tried.',
  'hlt.dkim.selector': 'Selector',
  'hlt.dkim.key': 'Key',
  'hlt.dkim.state': 'State',
  'hlt.dkim.revoked': 'revoked',
  'hlt.dkim.testing': 'test mode',
  'hlt.dkim.active': 'active',
  'hlt.dkim.wildcard': 'wildcard',
  'hlt.mail.extras': 'MTA-STS · TLS-RPT · BIMI',
  'hlt.present': 'present',
  'hlt.missing': 'not published',
  'hlt.lookupFailed': 'lookup failed',
  'hlt.fcrdns': 'Reverse DNS of the mail servers (FCrDNS)',
  'hlt.fcrdns.hint': 'Receivers check that a sending server’s PTR name resolves back to its address. MX hosts receive mail, so this stands in for your sending servers when they are the same machines.',
  'hlt.fcrdns.col.host': 'MX host',
  'hlt.fcrdns.col.ip': 'Address',
  'hlt.fcrdns.col.ptr': 'PTR name',
  'hlt.fcrdns.col.status': 'Forward check',
  'hlt.fcrdns.st.confirmed': 'confirmed',
  'hlt.fcrdns.st.mismatch': 'does not resolve back',
  'hlt.fcrdns.st.no-ptr': 'no PTR record',
  'hlt.fcrdns.st.nxdomain': 'no reverse DNS',
  'hlt.fcrdns.st.servfail': 'SERVFAIL',
  'hlt.fcrdns.st.error': 'lookup failed',
  'hlt.fcrdns.provider': 'provider',
  'hlt.fcrdns.providerTitle': 'This MX host belongs to another domain (your mail provider), which sets its reverse DNS.',
  'hlt.fcrdns.generic': 'generic name',
  'hlt.fcrdns.sweep': 'Reverse DNS',
  'hlt.fcrdns.sweepTitle': 'Open {ip} in the Reverse DNS view',
  'hlt.fcrdns.capped': 'The first {checked} of {total} addresses were checked.',

  'hlt.caa.title': 'Which CAs may issue certificates?',
  'hlt.caa.none': 'No CAA record — any certificate authority may issue certificates for this domain.',
  'hlt.caa.foundAt': 'CAA set found at {name}',
  'hlt.caa.issue': 'Certificates',
  'hlt.caa.issuewild': 'Wildcard certificates',
  'hlt.caa.sameAsIssue': 'same as above',
  'hlt.caa.nobody': 'nobody (issuance forbidden)',
  'hlt.caa.anyone': 'any CA',
  'hlt.caa.iodef': 'Violation reports',
  'hlt.caa.records': 'CAA records',
  'hlt.caa.distrusted': 'distrusted since {year}',
  'hlt.caa.error': 'The CAA lookup failed: {error}',
  'hlt.caa.onlyMethods': 'only {methods}',
  'hlt.caa.accountOnly': 'one ACME account only',
  'hlt.caa.unusable': 'never usable',
  'hlt.caa.malformed': 'malformed',
  'hlt.caa.rfc8657': 'accounturi and validationmethods (RFC 8657) limit a CA to one ACME account or to some validation methods. They bind only CAs that support RFC 8657; the others may ignore them.',

  'hlt.mtasts.title': 'MTA-STS policy',
  'hlt.dlg.title': 'Delegation',
  'hlt.dlg.intro': 'Asks every name server of {zone} directly, through Globalping: lame servers, SOA serial drift, NS sets, glue, open recursion and the Sitting Ducks risk. Nothing is sent before the click.',
  'hlt.dlg.check': 'Check the delegation',
  'hlt.dlg.cost': { one: 'About {count} Globalping probe.', other: 'About {count} Globalping probes.' },
  'hlt.dlg.loadFailed': 'The delegation check could not be loaded',
  'hlt.dep.title': 'Dependencies',
  'hlt.dep.intro': 'The domains {domain} depends on through its records: its name servers and mail servers, the domains its SPF record names, its DMARC report addresses, the DKIM keys at the common selectors and at the ones you added, the CAA iodef addresses, MTA-STS, the Autodiscover and SIP SRV records, the HTTPS record and the _acme-challenge delegation. Whoever registers one that lapses can answer for the zone, receive the mail or the reports, send or sign as {domain}, or get certificates for it.',
  'hlt.dep.sends': 'Runs only when you click: DNS queries go to your resolver, and RDAP lookups of those domains go to their registries.',
  'hlt.dep.check': 'Check dependencies (RDAP)',
  'hlt.dep.loadFailed': 'The dependency check could not be loaded',
  'hlt.mtasts.txt': 'TXT record',
  'hlt.mtasts.txtInvalid': 'not valid: senders ignore it',
  'hlt.mtasts.url': 'Policy URL',
  'hlt.mtasts.intro': 'Sending mail servers that support MTA-STS read the policy at this URL. This page cannot read another site’s file itself, so one Globalping probe can fetch it for you, only when you click. Its HTTP answer and certificate are then checked, and its mx lines are compared with the domain’s MX hosts.',
  'hlt.mtasts.noHost': 'Globalping does not accept the host name {host}, so the policy cannot be fetched from here.',
  'hlt.mtasts.check': 'Check the policy (1 Globalping probe)',
  'hlt.mtasts.again': 'Check again (1 probe)',
  'hlt.mtasts.fetching': 'Fetching the policy through Globalping…',
  'hlt.mtasts.privacy': 'The policy is fetched through Globalping, a free probe network run by jsDelivr and volunteers. The host name {host} goes to Globalping, and one probe sends one HTTPS GET request for {path} to it (User-Agent “globalping probe”). Anyone who has the measurement ID can read the result, including the policy and the server’s response headers, for about six months. The MX hosts are compared in this browser; nothing else is sent.',
  'hlt.mtasts.quota': 'This hour’s free Globalping quota is used up; it resets {when}. No probe was used.',
  'hlt.mtasts.failed': 'The policy could not be checked',
  'hlt.mtasts.paid': 'The probe was already used: reading the result again uses the same measurement and costs nothing.',
  'hlt.mtasts.reread': 'Read the result again (no new probe)',
  'hlt.mtasts.mode': 'Mode',
  'hlt.mtasts.maxAge': 'max_age',
  'hlt.mtasts.maxAgeValue': { zero: '{seconds} s (under a day)', one: '{seconds} s ({count} day)', other: '{seconds} s ({count} days)' },
  'hlt.mtasts.http': 'HTTP answer',
  'hlt.mtasts.cert': 'Certificate',
  'hlt.mtasts.certValue': '{issuer} · valid until {date}',
  'hlt.mtasts.col.host': 'MX host',
  'hlt.mtasts.col.pattern': 'Matched by',
  'hlt.mtasts.noMatch': 'no mx pattern',
  'hlt.mtasts.policy': 'Policy file',
  'hlt.mtasts.meta': 'Fetched by a probe in {place} ({when}).',
  'hlt.mtasts.measurement': 'Measurement',
  'hlt.mtasts.smtpNote': 'A probe cannot open SMTP connections, so the certificates the MX hosts present over STARTTLS are not checked here.',

  'hlt.dns.title': 'DNS records',
  'hlt.dns.ns': 'Name servers',
  'hlt.dns.soa': 'SOA',
  'hlt.dns.soaValue': '{mname} · {email} · serial {serial}',
  'hlt.dns.mx': 'Mail servers (MX)',
  'hlt.dns.nullMx': 'null MX — accepts no email',
  'hlt.dns.a': 'IPv4 (A)',
  'hlt.dns.aaaa': 'IPv6 (AAAA)',
  'hlt.dns.txt': 'TXT records',
  'hlt.dns.txtCount': { zero: 'none', one: '{count} record', other: '{count} records' },
  'hlt.dns.https': 'HTTPS record',
  'hlt.dns.wildcard': 'Wildcard DNS',
  'hlt.dns.wildcardYes': 'yes → {values}',
  'hlt.dns.wildcardNo': 'no',
  'hlt.dns.lookupAll': 'Open in DNS Lookup'
});

registerStrings('tr', {
  'hlt.domain': 'Alan adı',
  'hlt.placeholder': 'ornek.com.tr',
  'hlt.run': 'Sağlığı kontrol et',
  'hlt.options': 'Seçenekler',
  'hlt.dkimExtra': 'Ek DKIM seçicileri',
  'hlt.dkimExtraHint': '{count} yaygın seçici her zaman denenir. Kendi seçicilerinizi (ör. DKIM-Signature başlığındaki “s=” değeri) virgülle ayırarak ekleyin.',
  'hlt.invalid': 'ornek.com.tr gibi bir alan adı girin.',
  'hlt.examples': 'Deneyin:',
  'hlt.emptyTitle': 'Bir alan adının DNS, e-posta ve kayıt sağlığını kontrol edin',
  'hlt.emptyBody': 'Ad sunucuları, SOA, MX, SPF (10 sorgu sınırıyla), DMARC, DKIM, CAA, DNSSEC, joker (wildcard) DNS ve RDAP bitiş tarihi — tek seferde, tarayıcınızdan.',
  'hlt.progress': '{domain} kontrol ediliyor',
  'hlt.step.records': 'DNS kayıtları',
  'hlt.step.ns': 'Ad sunucuları',
  'hlt.step.mx': 'E-posta sunucuları',
  'hlt.step.spf': 'SPF',
  'hlt.step.dmarc': 'DMARC',
  'hlt.step.dkim': 'DKIM seçicileri',
  'hlt.step.caa': 'CAA',
  'hlt.step.dnssec': 'DNSSEC',
  'hlt.step.wildcard': 'Joker kayıt testi',
  'hlt.step.rdap': 'Kayıt bilgisi (RDAP)',
  'hlt.failed': 'Sağlık kontrolü çalıştırılamadı',

  'hlt.light.error': 'Sorun bulundu',
  'hlt.light.warn': 'İlgilenilmesi gerekiyor',
  'hlt.light.ok': 'Sağlıklı',
  'hlt.light.errorBody': 'Önce hataları giderin — gerçek kullanıcılar için e-posta teslimini, çözümlemeyi ya da güvenliği bozuyorlar.',
  'hlt.light.warnBody': 'Bozuk bir şey yok ama bazı ayarlar zayıf ya da riskli.',
  'hlt.light.okBody': '{count} kontrolde sorun bulunmadı.',
  'hlt.score': 'Puan',
  'hlt.scoreTitle': 'Her kategori hata başına 40, uyarı başına 15 puan kaybeder; puan kategorilerin ağırlıklı ortalamasıdır, hatayla en fazla 79, uyarıyla en fazla 89 olur. Bilgi maddeleri sayılmaz.',
  'hlt.grade': 'Not {grade}',
  'hlt.step.web': 'www ve HTTPS kaydı',
  'hlt.checkedAt': '{time} kontrol edildi',
  'hlt.zone': 'Bölge: {zone}',
  'hlt.checkZone': '{zone} alan adını kontrol et',
  'hlt.download': 'Rapor (JSON)',
  'hlt.count.error': '{count} hata',
  'hlt.count.warn': '{count} uyarı',
  'hlt.count.info': '{count} bilgi',
  'hlt.count.ok': '{count} başarılı',
  'hlt.filter': 'Göster',
  'hlt.filter.all': 'Tüm kontroller',
  'hlt.filter.problems': 'Uyarılar ve hatalar',
  'hlt.noProblems': 'Bu grupta uyarı ya da hata yok.',
  'hlt.fix.show': 'Düzeltmeyi göster',
  'hlt.fix.hide': 'Düzeltmeyi gizle',
  'hlt.checksTitle': 'Kontroller',
  'hlt.detailsTitle': 'Ayrıntılar',
  'hlt.links': 'Bu alan adı hakkında daha fazlası:',

  'hlt.rdap.title': 'Kayıt bilgisi (RDAP)',
  'hlt.rdap.registrar': 'Kayıt firması',
  'hlt.rdap.ianaId': 'IANA no {id}',
  'hlt.rdap.created': 'Kayıt tarihi',
  'hlt.rdap.updated': 'Son değişiklik',
  'hlt.rdap.expires': 'Bitiş tarihi',
  'hlt.rdap.daysLeft': { zero: 'bugün sona eriyor', other: '{count} gün kaldı' },
  'hlt.rdap.daysAgo': '{count} gün önce sona erdi',
  'hlt.rdap.status': 'Durum',
  'hlt.rdap.nameservers': 'Ad sunucuları (kayıt kuruluşu)',
  'hlt.rdap.dnssec': 'DNSSEC yetkilendirmesi',
  'hlt.rdap.signed': 'imzalı',
  'hlt.rdap.unsigned': 'imzasız',
  'hlt.rdap.server': 'RDAP sunucusu',
  'hlt.rdap.abuse': 'Kötüye kullanım iletişimi',
  'hlt.rdap.domain': 'Kayıtlı alan adı',
  'hlt.rdap.unsupported': '.{tld} kayıt kuruluşu RDAP hizmeti sunmuyor; kayıt ve bitiş tarihleri tarayıcıdan okunamıyor.',
  'hlt.rdap.unsupportedTr': '.tr alan adları için kayıt kuruluşunun kendi WHOIS hizmetini kullanın: nic.tr / TRABİS.',
  'hlt.rdap.notFound': '{domain} kayıtlı değil (kayıt kuruluşu “bulunamadı” yanıtı verdi).',
  'hlt.rdap.error': 'Kayıt bilgileri alınamadı.',
  'hlt.rdap.skipped': 'Kontrol edilmedi.',
  'hlt.rdap.retried': 'Kayıt bilgileri alındı.',

  'hlt.dnssec.title': 'DNSSEC',
  'hlt.dnssec.broken': 'Bozuk — doğrulayan çözümleyiciler başarısız',
  'hlt.dnssec.validated': 'İmzalı ve doğrulandı',
  'hlt.dnssec.signed': 'İmzalı, doğrulanmadı',
  'hlt.dnssec.unsigned': 'İmzasız',
  'hlt.dnssec.unknown': 'Bilinmiyor',
  'hlt.dnssec.fromZone': 'Bölge kökü değil: bu, {zone} bölgesinin durumu.',
  'hlt.dnssec.ds': 'DS kayıtları (üst bölgede)',
  'hlt.dnssec.dnskey': 'DNSKEY kayıtları (bölgede)',
  'hlt.dnssec.algorithms': 'Algoritmalar',
  'hlt.dnssec.ede': 'Çözümleyici hataları',
  'hlt.dnssec.ksk': 'KSK',
  'hlt.dnssec.zsk': 'ZSK',
  'hlt.col.keyTag': 'Anahtar etiketi',
  'hlt.col.algorithm': 'Algoritma',
  'hlt.col.digest': 'Özet',
  'hlt.col.role': 'Rol',

  'hlt.mail.title': 'E-posta güvenliği',
  'hlt.spf': 'SPF',
  'hlt.spf.none': 'SPF kaydı yok.',
  'hlt.spf.lookups': 'DNS sorgusu: {count} / {limit}',
  'hlt.spf.void': 'Boş sorgu: {count} / {limit}',
  'hlt.spf.tree': 'Include ağacı',
  'hlt.spf.lookupCount': '{count} sorgu',
  'hlt.spf.voidBadge': 'boş',
  'hlt.spf.truncated': 'Ağaç eksik (izlenecek iç içe sorgu sayısı çok fazla).',
  'hlt.dmarc': 'DMARC',
  'hlt.dmarc.none': 'DMARC kaydı yok.',
  'hlt.dmarc.inherited': '{org} alan adından devralındı',
  'hlt.dmarc.foundAt': '_dmarc.{domain} adresinde yayınlanıyor',
  'hlt.dmarc.p': 'Politika (p)',
  'hlt.dmarc.sp': 'Alt alan adı politikası (sp)',
  'hlt.dmarc.pct': 'Uygulama oranı (pct)',
  'hlt.dmarc.rua': 'Toplu raporlar (rua)',
  'hlt.dmarc.ruf': 'Hata raporları (ruf)',
  'hlt.dmarc.align': 'Hizalama DKIM / SPF',
  'hlt.dmarc.strict': 'katı',
  'hlt.dmarc.relaxed': 'esnek',
  'hlt.dkim': 'DKIM',
  'hlt.dkim.none': 'Denenen {count} seçicide DKIM anahtarı bulunamadı.',
  'hlt.dkim.selector': 'Seçici',
  'hlt.dkim.key': 'Anahtar',
  'hlt.dkim.state': 'Durum',
  'hlt.dkim.revoked': 'iptal edilmiş',
  'hlt.dkim.testing': 'test modu',
  'hlt.dkim.active': 'etkin',
  'hlt.dkim.wildcard': 'joker',
  'hlt.mail.extras': 'MTA-STS · TLS-RPT · BIMI',
  'hlt.present': 'var',
  'hlt.missing': 'yayınlanmamış',
  'hlt.lookupFailed': 'sorgu başarısız',
  'hlt.fcrdns': 'E-posta sunucularının ters DNS’i (FCrDNS)',
  'hlt.fcrdns.hint': 'Alıcılar, gönderen sunucunun PTR adının yine onun adresine çözüldüğüne bakar. MX sunucuları e-posta alır; gönderen sunucularınız aynı makinelerse bu kontrol onların yerine geçer.',
  'hlt.fcrdns.col.host': 'MX sunucusu',
  'hlt.fcrdns.col.ip': 'Adres',
  'hlt.fcrdns.col.ptr': 'PTR adı',
  'hlt.fcrdns.col.status': 'İleri doğrulama',
  'hlt.fcrdns.st.confirmed': 'doğrulandı',
  'hlt.fcrdns.st.mismatch': 'adrese geri çözülmüyor',
  'hlt.fcrdns.st.no-ptr': 'PTR kaydı yok',
  'hlt.fcrdns.st.nxdomain': 'ters DNS yok',
  'hlt.fcrdns.st.servfail': 'SERVFAIL',
  'hlt.fcrdns.st.error': 'sorgu başarısız',
  'hlt.fcrdns.provider': 'sağlayıcı',
  'hlt.fcrdns.providerTitle': 'Bu MX sunucusu başka bir alan adına (e-posta sağlayıcınıza) ait; ters DNS’ini sağlayıcı ayarlar.',
  'hlt.fcrdns.generic': 'şablon ad',
  'hlt.fcrdns.sweep': 'Ters DNS',
  'hlt.fcrdns.sweepTitle': '{ip} adresini Ters DNS görünümünde aç',
  'hlt.fcrdns.capped': '{total} adresin ilk {checked} tanesi kontrol edildi.',

  'hlt.caa.title': 'Hangi sertifika otoriteleri sertifika verebilir?',
  'hlt.caa.none': 'CAA kaydı yok — herhangi bir sertifika otoritesi bu alan adı için sertifika verebilir.',
  'hlt.caa.foundAt': 'CAA kümesi {name} adresinde bulundu',
  'hlt.caa.issue': 'Sertifikalar',
  'hlt.caa.issuewild': 'Joker (wildcard) sertifikalar',
  'hlt.caa.sameAsIssue': 'yukarıdakiyle aynı',
  'hlt.caa.nobody': 'hiçbiri (sertifika verilmesi yasak)',
  'hlt.caa.anyone': 'herhangi bir CA',
  'hlt.caa.iodef': 'İhlal bildirimleri',
  'hlt.caa.records': 'CAA kayıtları',
  'hlt.caa.distrusted': '{year} yılından beri güvenilmiyor',
  'hlt.caa.error': 'CAA sorgusu başarısız oldu: {error}',
  'hlt.caa.onlyMethods': 'yalnızca {methods}',
  'hlt.caa.accountOnly': 'yalnızca bir ACME hesabı',
  'hlt.caa.unusable': 'hiç kullanılamaz',
  'hlt.caa.malformed': 'hatalı',
  'hlt.caa.rfc8657': 'accounturi ve validationmethods (RFC 8657) bir otoriteyi tek bir ACME hesabıyla ya da belirli doğrulama yöntemleriyle sınırlar. Yalnızca RFC 8657’yi destekleyen otoriteleri bağlarlar; diğerleri bunları yok sayabilir.',

  'hlt.mtasts.title': 'MTA-STS politikası',
  'hlt.dlg.title': 'Delegasyon',
  'hlt.dlg.intro': '{zone} zone’unun her ad sunucusunu Globalping üzerinden doğrudan sorar: bozuk sunucular, SOA seri numarası kayması, NS kümeleri, glue kayıtları, açık özyineleme ve Sitting Ducks riski. Tıklamadan önce hiçbir şey gönderilmez.',
  'hlt.dlg.check': 'Delegasyonu kontrol et',
  'hlt.dlg.cost': 'Yaklaşık {count} Globalping ölçümü.',
  'hlt.dlg.loadFailed': 'Delegasyon kontrolü yüklenemedi',
  'hlt.dep.title': 'Bağımlılıklar',
  'hlt.dep.intro': '{domain} alan adının kayıtları aracılığıyla bağlı olduğu alan adları: ad sunucuları ve posta sunucuları, SPF kaydında geçen alan adları, DMARC rapor adresleri, yaygın seçicilerdeki ve kendi eklediğiniz seçicilerdeki DKIM anahtarları, CAA iodef adresleri, MTA-STS, Autodiscover ve SIP SRV kayıtları, HTTPS kaydı ve _acme-challenge yetkilendirmesi. Süresi dolan birini kaydeden kişi zone adına yanıt verebilir, postayı ya da raporları alabilir, {domain} adına e-posta gönderebilir ya da imzalayabilir veya onun için sertifika alabilir.',
  'hlt.dep.sends': 'Yalnızca tıkladığınızda çalışır: DNS sorguları çözümleyicinize, bu alan adlarının RDAP sorguları da kayıt kuruluşlarına gider.',
  'hlt.dep.check': 'Bağımlılıkları kontrol et (RDAP)',
  'hlt.dep.loadFailed': 'Bağımlılık kontrolü yüklenemedi',
  'hlt.mtasts.txt': 'TXT kaydı',
  'hlt.mtasts.txtInvalid': 'geçersiz: gönderenler yok sayar',
  'hlt.mtasts.url': 'Politika adresi',
  'hlt.mtasts.intro': 'MTA-STS destekleyen gönderen e-posta sunucuları politikayı bu adresten okur. Bu sayfa başka bir sitenin dosyasını kendisi okuyamaz; bu yüzden yalnızca siz tıkladığınızda tek bir Globalping ölçüm noktası dosyayı sizin için alabilir. Ardından HTTP yanıtı ve sertifikası kontrol edilir, mx satırları da alan adının MX sunucularıyla karşılaştırılır.',
  'hlt.mtasts.noHost': 'Globalping {host} host adını kabul etmiyor; bu yüzden politika buradan alınamıyor.',
  'hlt.mtasts.check': 'Politikayı kontrol et (1 Globalping ölçümü)',
  'hlt.mtasts.again': 'Yeniden kontrol et (1 ölçüm)',
  'hlt.mtasts.fetching': 'Politika Globalping üzerinden alınıyor…',
  'hlt.mtasts.privacy': 'Politika, jsDelivr ve gönüllülerin işlettiği ücretsiz bir ölçüm ağı olan Globalping üzerinden alınır. {host} host adı Globalping’e gider; bir ölçüm noktası ona {path} için tek bir HTTPS GET isteği gönderir (User-Agent “globalping probe”). Ölçüm kimliğini bilen herkes sonucu, politika ve sunucunun yanıt başlıkları dahil, yaklaşık altı ay okuyabilir. MX sunucuları bu tarayıcıda karşılaştırılır; başka hiçbir şey gönderilmez.',
  'hlt.mtasts.quota': 'Bu saatin ücretsiz Globalping kotası doldu; {when} sıfırlanır. Hiçbir ölçüm harcanmadı.',
  'hlt.mtasts.failed': 'Politika kontrol edilemedi',
  'hlt.mtasts.paid': 'Ölçüm zaten harcandı: sonucu yeniden okumak aynı ölçümü kullanır ve ek maliyeti yoktur.',
  'hlt.mtasts.reread': 'Sonucu yeniden oku (yeni ölçüm yok)',
  'hlt.mtasts.mode': 'Mod',
  'hlt.mtasts.maxAge': 'max_age',
  'hlt.mtasts.maxAgeValue': { zero: '{seconds} sn (bir günden kısa)', other: '{seconds} sn ({count} gün)' },
  'hlt.mtasts.http': 'HTTP yanıtı',
  'hlt.mtasts.cert': 'Sertifika',
  'hlt.mtasts.certValue': '{issuer} · {date} tarihine kadar geçerli',
  'hlt.mtasts.col.host': 'MX sunucusu',
  'hlt.mtasts.col.pattern': 'Eşleşen kalıp',
  'hlt.mtasts.noMatch': 'mx kalıbı yok',
  'hlt.mtasts.policy': 'Politika dosyası',
  'hlt.mtasts.meta': '{place} konumundaki bir ölçüm noktası tarafından alındı ({when}).',
  'hlt.mtasts.measurement': 'Ölçüm',
  'hlt.mtasts.smtpNote': 'Bir ölçüm noktası SMTP bağlantısı açamaz; bu yüzden MX sunucularının STARTTLS üzerinden sunduğu sertifikalar burada kontrol edilmez.',

  'hlt.dns.title': 'DNS kayıtları',
  'hlt.dns.ns': 'Ad sunucuları',
  'hlt.dns.soa': 'SOA',
  'hlt.dns.soaValue': '{mname} · {email} · seri {serial}',
  'hlt.dns.mx': 'E-posta sunucuları (MX)',
  'hlt.dns.nullMx': 'null MX — e-posta kabul etmiyor',
  'hlt.dns.a': 'IPv4 (A)',
  'hlt.dns.aaaa': 'IPv6 (AAAA)',
  'hlt.dns.txt': 'TXT kayıtları',
  'hlt.dns.txtCount': { zero: 'yok', other: '{count} kayıt' },
  'hlt.dns.https': 'HTTPS kaydı',
  'hlt.dns.wildcard': 'Joker (wildcard) DNS',
  'hlt.dns.wildcardYes': 'evet → {values}',
  'hlt.dns.wildcardNo': 'hayır',
  'hlt.dns.lookupAll': 'DNS Sorgulama’da aç'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

// The score (100 − 20 per error − 6 per warning) and the traffic light live in lib/summary.js,
// which "Copy summary" shares; re-exported here for the tests that read them from the view.
export { healthScore, trafficLight };

/**
 * Checks of one group, worst severity first (stable within a severity).
 * @param {Array<{ severity: string, group?: string }>} checks
 * @param {string} group
 * @returns {object[]}
 */
export function groupChecks(checks, group) {
  const rank = (c) => {
    const i = SEVERITY_ORDER.indexOf(c.severity);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  return (Array.isArray(checks) ? checks : [])
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => (c.group || 'dns') === group)
    .sort((a, b) => rank(a.c) - rank(b.c) || a.i - b.i)
    .map(({ c }) => c);
}

/**
 * Extra DKIM selectors typed by the user → valid, lower-case, de-duplicated names that are
 * not already in the default list.
 * @param {string} text
 * @returns {string[]}
 */
export function parseSelectors(text) {
  const out = [];
  for (const token of splitList(text)) {
    const s = token.toLowerCase().replace(/\._domainkey.*$/, '');
    if (/^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/.test(s) && !DEFAULT_DKIM_SELECTORS.includes(s) && !out.includes(s)) out.push(s);
  }
  return out;
}

/**
 * Did the report's lookup of a record fail ('soa', 'ns', 'mx', 'a', 'aaaa', 'txt', 'https' or a
 * mail extra: 'mtaSts', 'tlsRpt', 'bimi')? Its empty value is then "not known".
 */
function lookupFailed(report, key) {
  return Array.isArray(report.failedLookups) && report.failedLookups.includes(key);
}

/** A mail-extra record for lib/mtasts: the record, null when not published, undefined when not known. */
function knownRecord(report, key) {
  return lookupFailed(report, key) ? undefined : report.records[key] ?? null;
}

/**
 * The number of `_mta-sts` "v=STSv1" TXT records when senders reject them (two or more, or one
 * without an id: the report's mta-sts.invalid check), else 0.
 * @param {object} report a lib/health.domainHealth report
 * @returns {number}
 */
export function mtaStsTxtInvalid(report) {
  const check = (report.checks || []).find((c) => c.id === 'mta-sts.invalid');
  return check ? Math.max(1, Number(check.params?.count) || 1) : 0;
}

/**
 * What lib/mtasts.validateMtaSts needs from a health report besides the fetch: the MX exchanges
 * (undefined when the MX lookup failed: not known, never "no MX"), the `_mta-sts` /
 * `_smtp._tls` records (null = not published, undefined = not known; `tlsRpt` is null as well when
 * senders reject the `_smtp._tls` records, the tls-rpt.invalid check: they send no reports) and
 * whether senders reject the `_mta-sts` records (`txtInvalid`, {@link mtaStsTxtInvalid}).
 * @param {object} report a lib/health.domainHealth report
 * @returns {{ mxHosts: string[]|undefined, txt: string|null|undefined, txtInvalid: number, tlsRpt: string|null|undefined }}
 */
export function mtaStsContext(report) {
  const tlsRptInvalid = (report.checks || []).some((c) => c.id === 'tls-rpt.invalid');
  return {
    mxHosts: lookupFailed(report, 'mx') ? undefined : (report.records.mx || []).map((m) => m.exchange),
    txt: knownRecord(report, 'mtaSts'),
    txtInvalid: mtaStsTxtInvalid(report),
    tlsRpt: tlsRptInvalid ? null : knownRecord(report, 'tlsRpt')
  };
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the Domain Health view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;
  const initialDomain = restored?.domain ?? ctx.params.domain ?? ctx.params.name ?? '';

  /* --- helpers ------------------------------------------------------------------ */
  const hostLink = (host, type = 'A,AAAA') => h('a', { class: 'hlt-host mono', href: ctx.href('lookup', { name: host, type }) }, host);
  const ipLink = (ip) => h('a', { class: 'hlt-ip mono', href: ctx.href('ip', { ips: ip }) }, ip);
  /** Translate a check key; fall back to readable text when a key is missing. */
  const tr = (key, params, fallback) => (hasString(key, getLang()) || hasString(key, 'en') ? t(key, params) : fallback);
  // lib/health passes booleans as the English words 'yes' / 'no', and a failed lookup as 'lookup failed':
  // show them in the UI language.
  const localWords = { yes: 'common.yes', no: 'common.no', [LOOKUP_FAILED_PARAM]: 'hlt.lookupFailed' };
  const localParams = (params) => Object.fromEntries(Object.entries(params || {})
    .map(([k, v]) => [k, typeof v === 'string' && Object.hasOwn(localWords, v) ? t(localWords[v]) : v]));
  const checkTitle = (c) => tr(c.titleKey, localParams(c.params), c.id);
  const checkDetail = (c) => tr(c.detailKey, localParams(c.params), Object.entries(c.params || {}).map(([k, v]) => `${k}: ${v}`).join(' · '));
  const caNameFor = (issuer) => {
    const ca = CAA_ISSUERS.find((x) => x.domains.includes(String(issuer).toLowerCase()));
    return ca || null;
  };
  const algName = (n) => (DNSSEC_ALGORITHMS[n] ? `${DNSSEC_ALGORITHMS[n]} (${n})` : String(n));
  const ipList = (ips) => (ips && ips.length ? h('div', { class: 'cluster hlt-ips' }, ips.map(ipLink)) : null);
  const miniTable = (headers, rows, className = '') => h('div', { class: ['dt-scroll', 'dt-scroll-free', 'hlt-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table dt-dense' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => h('td', null, c === null || c === undefined || c === '' ? h('span', { class: 'dt-null' }, '—') : c)))))));

  /* --- form ------------------------------------------------------------------------ */
  const domainField = textInput({
    label: t('hlt.domain'),
    value: initialDomain,
    placeholder: t('hlt.placeholder'),
    mono: true,
    className: 'hlt-domain',
    attrs: { 'data-role': 'health-domain', 'data-shortcut': 'focus', inputmode: 'url', enterkeyhint: 'go' },
    onEnter: () => start()
  });
  const selectorsField = textInput({
    label: t('hlt.dkimExtra'),
    value: restored?.selectors ?? ctx.params.selectors ?? '',
    placeholder: 'mailgun, s1024',
    mono: true,
    attrs: { 'data-role': 'health-selectors' },
    onEnter: () => start()
  });
  selectorsField.setHint(t('hlt.dkimExtraHint', { count: DEFAULT_DKIM_SELECTORS.length }));
  const runBtn = Button({ label: t('hlt.run'), icon: 'activity', variant: 'primary', dataset: { action: 'run', shortcut: 'submit' }, onClick: () => start() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', dataset: { action: 'stop', shortcut: 'cancel' }, onClick: () => { if (current && current.controller) current.controller.abort(); } });
  stopBtn.hidden = true;
  const examples = ['github.com', 'cloudflare.com', 'wikipedia.org', 'example.com'];
  const examplesEl = h('div', { class: 'cluster text-sm hlt-examples' },
    h('span', { class: 'muted' }, t('hlt.examples')),
    examples.map((d) => h('button', {
      type: 'button', class: 'link-btn mono', dataset: { example: d },
      on: { click: () => { domainField.value = d; start(); } }
    }, d)));
  const formCard = Card({
    className: 'hlt-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'hlt-form' }, domainField.el, h('div', { class: 'hlt-buttons' }, stopBtn, runBtn)),
      h('div', { class: 'hlt-form-foot' },
        examplesEl,
        Disclosure({ summary: t('hlt.options'), className: 'hlt-options', open: !!(restored?.selectors || ctx.params.selectors), children: selectorsField.el })))
  });

  /* --- results skeleton ------------------------------------------------------------ */
  const progress = ProgressBar({ label: t('hlt.progress', { domain: '' }) });
  progress.el.hidden = true;
  const errorEl = h('div');
  const heroEl = h('div', { class: 'hlt-hero-wrap' });
  /** Problems first and the Web card (ui/health-v2.js). */
  const v2El = h('div', { class: 'stack-lg hv2' });
  const checksEl = h('div', { class: 'hlt-groups' });
  const detailsEl = h('div', { class: 'hlt-details' });
  let filter = restored?.filter === 'problems' ? 'problems' : 'all';
  const filterCtl = SegmentedControl({
    label: t('hlt.filter'),
    size: 'sm',
    value: filter,
    options: [{ value: 'all', label: t('hlt.filter.all') }, { value: 'problems', label: t('hlt.filter.problems') }],
    onChange: (v) => {
      filter = v;
      if (current && current.report) renderChecks(current.report);
    }
  });
  filterCtl.el.dataset.control = 'health-filter';
  const emptyEl = h('div', { class: 'card hlt-empty' }, EmptyState({ icon: 'activity', title: t('hlt.emptyTitle'), message: t('hlt.emptyBody') }));
  // No part of the form: Ctrl/Cmd+Enter on the checks filter starts no new check.
  /** The hero's Copy summary (disabled while a check runs). */
  let heroSummary = null;
  const results = h('div', { class: 'stack-lg hlt-results', hidden: true, dataset: { shortcutScope: 'results' } },
    heroEl,
    v2El,
    h('section', { class: 'stack hlt-checks-section' },
      h('div', { class: 'hlt-section-head' }, h('h2', { class: 'section-title' }, t('hlt.checksTitle')), filterCtl.el),
      checksEl),
    h('section', { class: 'stack hlt-details-section' }, h('h2', { class: 'section-title' }, t('hlt.detailsTitle')), detailsEl));
  container.append(h('div', { class: 'stack-lg hlt-view' }, formCard, progress, errorEl, emptyEl, results));

  /* --- hero ------------------------------------------------------------------------------ */
  /**
   * @param {object} report
   * @param {string[]} selectors the extra DKIM selectors the report was checked with (its permalink)
   */
  function renderHero(report, selectors) {
    clear(heroEl);
    const s = report.summary;
    const light = trafficLight(s);
    const { score, grade } = scoreHealth(report.checks);
    const total = s.ok + s.info + s.warn + s.error;
    const lightEl = h('div', { class: ['hlt-light', `hlt-light-${light}`], attrs: { role: 'img', 'aria-label': t(`hlt.light.${light}`) } },
      ['error', 'warn', 'ok'].map((k) => h('span', { class: ['hlt-lamp', `hlt-lamp-${k}`, { 'is-on': k === light }] })));
    const counts = h('div', { class: 'hlt-counts' }, SEVERITY_ORDER.map((sev) => h('span', {
      class: ['hlt-count', `hlt-count-${sev}`, { 'is-zero': !s[sev] }], dataset: { severity: sev, count: s[sev] }
    }, SeverityIcon(sev, { size: 15 }), h('span', null, t(`hlt.count.${sev}`, { count: s[sev] })))));
    heroSummary = SummaryButton({
      kind: 'health',
      facts: () => ({ report }),
      url: () => ctx.shareUrl(permalinkParams('health', checkParams({ domain: report.domain, selectors })))
    });
    const zoneLink = report.zone && report.zone !== report.domain
      ? h('a', { class: 'btn btn-secondary btn-sm', href: ctx.href('health', { domain: report.zone }) }, Icon('arrow-right', { size: 14 }), h('span', { class: 'btn-label' }, t('hlt.checkZone', { zone: report.zone })))
      : null;
    heroEl.append(h('div', { class: ['card', 'hlt-hero', `hlt-hero-${light}`], dataset: { light, score, grade } },
      lightEl,
      h('div', { class: 'hlt-hero-main' },
        h('div', { class: 'hlt-hero-domain mono' }, report.domain),
        h('div', { class: 'hlt-hero-verdict' }, t(`hlt.light.${light}`)),
        h('p', { class: 'hlt-hero-body' }, light === 'ok' ? t('hlt.light.okBody', { count: formatNumber(total) }) : t(`hlt.light.${light}Body`)),
        counts,
        h('div', { class: 'hlt-hero-meta muted text-xs' },
          h('span', { title: formatDateTime(report.checkedAt) }, t('hlt.checkedAt', { time: formatRelative(report.checkedAt) })),
          report.zone ? h('span', null, t('hlt.zone', { zone: report.zone })) : null)),
      h('div', { class: 'hlt-hero-side' },
        h('div', { class: 'hlt-score', title: t('hlt.scoreTitle') },
          h('span', { class: ['hlt-grade', `hlt-grade-${grade}`], attrs: { role: 'img', 'aria-label': t('hlt.grade', { grade }) } }, grade),
          h('span', { class: 'hlt-score-value num' }, String(score)),
          h('span', { class: 'hlt-score-max' }, '/100'),
          h('span', { class: 'hlt-score-label' }, t('hlt.score'))),
        h('div', { class: 'hlt-hero-actions' },
          zoneLink,
          heroSummary,
          ReportButton(ctx, 'health', () => ({ report, selectors })),
          Button({
            label: t('hlt.download'), icon: 'download', size: 'sm', dataset: { action: 'download' },
            onClick: () => downloadText(timestampedName('domain-health', 'json', report.domain), toJson(exportReport(report)), 'application/json;charset=utf-8')
          })))));
    heroEl.append(h('div', { class: 'cluster text-sm hlt-links' },
      h('span', { class: 'muted' }, t('hlt.links')),
      h('a', { href: ctx.href('lookup', { name: report.domain, type: 'A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS' }) }, Icon('search', { size: 14 }), ' ', t('nav.lookup')),
      h('a', { href: ctx.href('global', { name: report.domain, type: 'A' }) }, Icon('globe', { size: 14 }), ' ', t('nav.global')),
      h('a', { href: ctx.href('scan', { domain: report.domain }) }, Icon('target', { size: 14 }), ' ', t('nav.scan'))));
  }

  /* --- checks ----------------------------------------------------------------------------- */
  function renderCheck(c, report) {
    const fixable = c.severity !== 'ok' && FIXABLE_CHECKS.includes(c.id);
    return h('li', { class: ['hlt-check', `hlt-sev-${c.severity}`], dataset: { id: c.id, severity: c.severity } },
      h('span', { class: 'hlt-check-icon' }, SeverityIcon(c.severity, { size: 18 })),
      h('div', { class: 'hlt-check-body' },
        h('div', { class: 'hlt-check-title' }, checkTitle(c)),
        h('div', { class: 'hlt-check-detail' }, checkDetail(c)),
        fixable ? fixToggle(c, report) : null));
  }

  /**
   * "Show the fix" of a check: the records (or the advice) that fix it, in every format, with the
   * check link. Nothing is sent: the panel is built from the report; only a missing CAA record
   * offers a Certificate Transparency lookup, on its own click.
   */
  function fixToggle(c, report) {
    const hostId = uid('hlt-fix');
    const host = h('div', { class: 'fix-host', id: hostId, hidden: true, dataset: { fixFor: c.id } });
    const btn = Button({
      label: t('hlt.fix.show'), icon: 'chevron-right', size: 'sm', variant: 'ghost', className: 'fix-toggle',
      attrs: { 'aria-expanded': 'false', 'aria-controls': hostId }, dataset: { action: 'health-fix', check: c.id },
      onClick: async () => {
        const open = btn.getAttribute('aria-expanded') !== 'true';
        btn.setAttribute('aria-expanded', String(open));
        btn.querySelector('.btn-label').textContent = t(open ? 'hlt.fix.hide' : 'hlt.fix.show');
        host.hidden = !open;
        if (!open || host.firstChild) return;
        try {
          const { HealthFixPanel } = await loadFixPanel();
          if (!host.firstChild) host.append(HealthFixPanel(c, report, { ctx }));
        } catch (err) {
          ctx.checkOutdated();
          host.append(ErrorBanner(err, { compact: true }));
        }
      }
    });
    return h('div', { class: 'hlt-fix' }, btn, host);
  }

  function renderChecks(report) {
    clear(checksEl);
    for (const group of HEALTH_GROUPS) {
      const all = groupChecks(report.checks, group);
      if (!all.length) continue;
      const shown = filter === 'problems' ? all.filter((c) => c.severity === 'error' || c.severity === 'warn') : all;
      const counts = SEVERITY_ORDER.filter((sev) => sev !== 'ok' && all.some((c) => c.severity === sev))
        .map((sev) => Badge(formatNumber(all.filter((c) => c.severity === sev).length), { variant: sev, icon: sev === 'error' ? 'x-circle' : sev === 'warn' ? 'alert' : 'info', title: t(`hlt.count.${sev}`, { count: all.filter((c) => c.severity === sev).length }) }));
      const worst = all[0].severity;
      checksEl.append(Card({
        title: t(`health.group.${group}`),
        icon: { dns: 'globe', email: 'mail', security: 'shield', registration: 'calendar', web: 'lock' }[group],
        className: ['hlt-group', `hlt-group-${worst}`].join(' '),
        actions: counts.length ? h('div', { class: 'cluster' }, counts) : Badge(t('severity.ok'), { variant: 'ok', icon: 'check' }),
        padded: false,
        children: shown.length
          ? h('ul', { class: 'hlt-check-list' }, shown.map((c) => renderCheck(c, report)))
          : h('p', { class: 'hlt-none muted text-sm' }, t('hlt.noProblems'))
      }));
      checksEl.lastChild.dataset.group = group;
    }
  }

  /* --- detail panels ------------------------------------------------------------------ */
  function rdapCard(report) {
    const r = report.rdap;
    const failed = rdapStatus(r);
    let body;
    let actions = null;
    if (!r) body = h('p', { class: 'muted text-sm' }, t('hlt.rdap.skipped'));
    else if (failed) {
      // No silent dashes: every field RDAP would have filled says "n/a" and why, and Retry asks RDAP alone again.
      const na = () => NaMark([failed]);
      body = h('div', { class: 'stack-sm' },
        h('p', { class: 'hlt-rdap-status text-sm', dataset: { reason: failed.reason } }, Icon('alert', { size: 14 }), h('span', null, statusText(failed))),
        KeyValueList([
          { key: t('hlt.rdap.domain'), value: r.domain, mono: true },
          { key: t('hlt.rdap.registrar'), value: na() },
          { key: t('hlt.rdap.created'), value: na() },
          { key: t('hlt.rdap.expires'), value: na() },
          { key: t('hlt.rdap.status'), value: na() },
          { key: t('hlt.rdap.nameservers'), value: na() }
        ]));
      actions = RetryButton({ sources: ['rdap'], onClick: (e) => retryRdap(e.currentTarget) });
    }
    else if (r.unsupportedTld) {
      body = Alert({
        variant: 'info', compact: true,
        message: [t('hlt.rdap.unsupported', { tld: r.tld || '' }), r.tld === 'tr' ? t('hlt.rdap.unsupportedTr') : null].filter(Boolean).join(' ')
      });
    } else if (r.notFound) body = Alert({ variant: 'warn', compact: true, message: t('hlt.rdap.notFound', { domain: r.domain }) });
    else if (!r.ok) {
      body = Alert({
        variant: 'error', compact: true, title: t('hlt.rdap.error'),
        message: r.errorKind && hasString(`error.kind.${r.errorKind}`, 'en') ? t(`error.kind.${r.errorKind}`) : r.error
      });
    } else {
      const days = r.expires ? daysUntil(r.expires) : null;
      const daysBadge = days === null ? null : days < 0
        ? Badge(t('hlt.rdap.daysAgo', { count: -days }), { variant: 'error', icon: 'x-circle' })
        : Badge(t('hlt.rdap.daysLeft', { count: days }), { variant: days < 30 ? 'error' : days < 60 ? 'warn' : 'ok', icon: 'clock' });
      const locked = (s) => /prohibited|lock/.test(s);
      body = KeyValueList([
        { key: t('hlt.rdap.domain'), value: r.domain, mono: true },
        {
          key: t('hlt.rdap.registrar'),
          value: r.registrar ? h('span', { class: 'hlt-registrar' },
            r.registrarUrl ? ExternalLink(r.registrarUrl, r.registrar) : r.registrar,
            r.registrarIanaId ? h('span', { class: 'muted text-xs' }, ` · ${t('hlt.rdap.ianaId', { id: r.registrarIanaId })}`) : null) : null
        },
        { key: t('hlt.rdap.created'), value: r.created ? `${formatDate(r.created)} · ${formatRelative(r.created)}` : null },
        { key: t('hlt.rdap.updated'), value: r.updated ? formatDate(r.updated) : null },
        { key: t('hlt.rdap.expires'), value: r.expires ? h('span', { class: 'hlt-expiry', dataset: { days } }, h('strong', null, formatDate(r.expires)), ' ', daysBadge) : null },
        { key: t('hlt.rdap.status'), value: r.status.length ? h('div', { class: 'cluster' }, r.status.map((s) => Badge(s, { variant: locked(s) ? 'ok' : /hold|delete|redemption/.test(s) ? 'error' : 'neutral', icon: locked(s) ? 'lock' : null }))) : null },
        { key: t('hlt.rdap.nameservers'), value: r.nameservers.length ? h('div', { class: 'cluster' }, r.nameservers.map((n) => hostLink(n))) : null },
        { key: t('hlt.rdap.dnssec'), value: r.dnssecSigned === null ? null : r.dnssecSigned ? Badge(t('hlt.rdap.signed'), { variant: 'ok', icon: 'shield' }) : Badge(t('hlt.rdap.unsigned')) },
        { key: t('hlt.rdap.abuse'), value: r.abuseEmail, mono: true, copy: true },
        { key: t('hlt.rdap.server'), value: r.url ? ExternalLink(r.url, r.rdapServer || r.url) : r.rdapServer }
      ].filter((it) => it.value !== null && it.value !== undefined && it.value !== ''));
    }
    const card = Card({ title: t('hlt.rdap.title'), icon: 'calendar', className: 'hlt-card hlt-rdap', actions, children: body });
    card.dataset.rdap = !r ? 'skipped' : failed ? 'failed' : r.ok ? 'ok' : 'answer';
    return card;
  }

  /**
   * The RDAP card's Retry: asks RDAP alone again (the DNS part of the report is kept) and puts
   * the new registration data, its checks and the new score on screen. Keyboard focus stays on
   * the card.
   * @param {HTMLButtonElement} btn
   */
  async function retryRdap(btn) {
    const state = current;
    if (!state || !state.report || state.rdapRetry) return;
    const controller = new AbortController();
    state.rdapRetry = controller;
    setButtonBusy(btn, true);
    try {
      const rdap = await rdapDomain(state.report.domain, { signal: mergeSignals(ctx.signal, controller.signal) });
      if (current !== state) return;
      state.report = applyRdap(state.report, rdap);
      renderReport(state.report, state.selectors);
      const card = detailsEl.querySelector('.hlt-rdap');
      const again = card && card.querySelector('[data-action="retry-source"]');
      if (again) again.focus();
      else if (card) {
        card.setAttribute('tabindex', '-1');
        card.focus({ preventScroll: true });
      }
      const st = rdapStatus(rdap);
      announce(st ? statusText(st) : t('hlt.rdap.retried'));
    } catch (err) {
      if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      if (state.rdapRetry === controller) state.rdapRetry = null;
      if (btn.isConnected) setButtonBusy(btn, false);
    }
  }

  function dnssecCard(report) {
    const d = report.dnssec;
    const state = d.broken ? 'broken' : d.signed && d.validated ? 'validated' : d.signed ? 'signed' : d.signed === false ? 'unsigned' : 'unknown';
    const variant = { broken: 'error', validated: 'ok', signed: 'warn', unsigned: 'neutral', unknown: 'neutral' }[state];
    const ds = report.records.ds || [];
    const keys = report.records.dnskey || [];
    const children = [
      h('div', { class: 'cluster' }, Badge(t(`hlt.dnssec.${state}`), { variant, icon: state === 'validated' ? 'shield' : state === 'broken' ? 'x-circle' : null })),
      // Below the apex lib/health reports the enclosing zone's state (its DS, and the AD bit).
      report.zone && report.zone !== report.domain && d.signed !== null ? h('p', { class: 'muted text-sm' }, t('hlt.dnssec.fromZone', { zone: report.zone })) : null,
      d.ede && d.ede.length ? Alert({ variant: 'error', compact: true, title: t('hlt.dnssec.ede'), message: d.ede.join(' · ') }) : null,
      d.algorithms && d.algorithms.length ? h('div', { class: 'text-sm' }, h('span', { class: 'muted' }, `${t('hlt.dnssec.algorithms')}: `), d.algorithms.join(', ')) : null,
      ds.length ? h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.dnssec.ds')),
        miniTable([t('hlt.col.keyTag'), t('hlt.col.algorithm'), t('hlt.col.digest')], ds.map((x) => [h('span', { class: 'mono' }, String(x.keyTag)), algName(x.algorithm), DS_DIGEST_TYPES[x.digestType] || String(x.digestType)]))) : null,
      keys.length ? h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.dnssec.dnskey')),
        miniTable([t('hlt.col.keyTag'), t('hlt.col.role'), t('hlt.col.algorithm')], keys.map((k) => [h('span', { class: 'mono' }, String(k.keyTag)),
          Badge(k.sep ? t('hlt.dnssec.ksk') : t('hlt.dnssec.zsk'), { variant: k.sep ? 'accent' : 'neutral', icon: 'key' }), algName(k.algorithm)]))) : null
    ];
    return Card({ title: t('hlt.dnssec.title'), icon: 'shield', className: 'hlt-card hlt-dnssec', children: h('div', { class: 'stack-sm' }, children) });
  }

  /**
   * SPF include tree: DNS-querying terms (include, redirect, a, mx, exists, ptr) are tree items
   * (with their nested records); address terms (ip4/ip6) and "all" are one compact chip row.
   */
  function spfTree(node, depth = 0) {
    if (!node || depth > 12) return null;
    const terms = node.terms || [];
    const lookups = terms.filter((x) => x.lookup);
    const statics = terms.filter((x) => !x.lookup);
    const head = h('div', { class: 'hlt-spf-head' },
      hostLink(node.domain, 'TXT'),
      Badge(t('hlt.spf.lookupCount', { count: node.count }), { variant: node.count > SPF_LOOKUP_LIMIT ? 'error' : 'neutral' }),
      node.void ? Badge(t('hlt.spf.voidBadge'), { variant: 'warn' }) : null,
      ...(node.errors || []).filter((e) => e.domain === node.domain).map((e) => Badge(e.code, { variant: 'error', title: e.detail || null })));
    const items = lookups.map((term) => h('li', { class: 'hlt-spf-term' },
      h('span', { class: 'hlt-spf-term-head' },
        h('span', { class: 'mono hlt-spf-raw' }, term.term),
        h('span', { class: 'muted text-xs' }, '+1'),
        term.void ? Badge(t('hlt.spf.voidBadge'), { variant: 'warn' }) : null,
        term.error ? Badge(term.error, { variant: 'error' }) : null),
      term.child ? spfTree(term.child, depth + 1) : null));
    return h('div', { class: 'hlt-spf-node' }, head,
      statics.length ? h('div', { class: 'hlt-spf-static' }, statics.map((x) => h('span', { class: ['mono', 'hlt-spf-chip', { 'is-all': x.mechanism === 'all' }] }, x.term))) : null,
      items.length ? h('ul', { class: 'hlt-spf-terms' }, items) : null);
  }

  function mailCard(report) {
    const spf = report.spf || {};
    const lookups = spf.lookups;
    const dmarc = report.dmarc || {};
    const p = dmarc.parsed;
    const dkim = report.records.dkim || [];
    const selectorsTried = (current && current.selectorCount) || DEFAULT_DKIM_SELECTORS.length;

    const meter = lookups ? h('div', { class: 'hlt-meter-wrap' },
      h('div', { class: 'hlt-meter-label text-sm' }, t('hlt.spf.lookups', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }),
        lookups.voidCount ? h('span', { class: 'muted' }, ` · ${t('hlt.spf.void', { count: lookups.voidCount, limit: SPF_VOID_LIMIT })}`) : null),
      h('div', { class: ['hlt-meter', lookups.count > SPF_LOOKUP_LIMIT ? 'is-error' : lookups.count >= SPF_LOOKUP_LIMIT - 1 ? 'is-warn' : 'is-ok'], attrs: { role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': SPF_LOOKUP_LIMIT, 'aria-valuenow': lookups.count, 'aria-label': t('hlt.spf.lookups', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }) } },
        h('span', { class: 'hlt-meter-fill', style: { width: `${Math.min(100, (lookups.count / SPF_LOOKUP_LIMIT) * 100)}%` } }))) : null;

    const spfBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'spf' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.spf')),
      spf.record ? CodeBlock(spf.record, { wrap: true, label: 'TXT' }) : h('p', { class: 'muted text-sm' }, t('hlt.spf.none')),
      meter,
      lookups && lookups.truncated ? h('p', { class: 'muted text-xs' }, t('hlt.spf.truncated')) : null,
      lookups && lookups.tree ? Disclosure({ summary: t('hlt.spf.tree'), className: 'hlt-spf', open: lookups.count >= SPF_LOOKUP_LIMIT - 2, children: spfTree(lookups.tree) }) : null);

    const align = (v) => (v === 's' ? t('hlt.dmarc.strict') : t('hlt.dmarc.relaxed'));
    const dmarcBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'dmarc' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.dmarc'),
        dmarc.inherited ? Badge(t('hlt.dmarc.inherited', { org: dmarc.foundAt }), { variant: 'info' }) : null),
      dmarc.record ? CodeBlock(dmarc.record, { wrap: true, label: dmarc.foundAt ? `_dmarc.${dmarc.foundAt}` : 'TXT' }) : h('p', { class: 'muted text-sm' }, t('hlt.dmarc.none')),
      p && p.valid ? KeyValueList([
        { key: t('hlt.dmarc.p'), value: Badge(p.policy, { variant: p.policy === 'none' ? 'warn' : 'ok', mono: true }) },
        { key: t('hlt.dmarc.sp'), value: p.subdomainPolicy ? Badge(p.subdomainPolicy, { variant: p.subdomainPolicy === 'none' ? 'warn' : 'ok', mono: true }) : null },
        { key: t('hlt.dmarc.pct'), value: `${p.pct}%` },
        { key: t('hlt.dmarc.rua'), value: p.rua.length ? h('div', { class: 'stack-sm' }, p.rua.map((u) => h('span', { class: 'mono text-sm' }, u))) : null },
        { key: t('hlt.dmarc.ruf'), value: p.ruf.length ? h('div', { class: 'stack-sm' }, p.ruf.map((u) => h('span', { class: 'mono text-sm' }, u))) : null },
        { key: t('hlt.dmarc.align'), value: `${align(p.adkim)} / ${align(p.aspf)}` }
      ], { className: 'hlt-kv' }) : null);

    const dkimBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'dkim' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.dkim')),
      dkim.length ? miniTable([t('hlt.dkim.selector'), t('hlt.dkim.key'), t('hlt.dkim.state')], dkim.map((k) => [
        k.selector === '*' ? Badge(t('hlt.dkim.wildcard'), { variant: 'info' }) : hostLink(`${k.selector}._domainkey.${report.domain}`, 'TXT'),
        k.revoked ? '—' : `${String(k.keyType).toUpperCase()}${k.keyBits ? ` · ${k.keyBits} bit` : ''}`,
        k.revoked ? Badge(t('hlt.dkim.revoked'), { variant: 'neutral' }) : k.testing ? Badge(t('hlt.dkim.testing'), { variant: 'warn' })
          : Badge(t('hlt.dkim.active'), { variant: k.keyBits && k.keyBits < 1024 ? 'error' : k.keyBits && k.keyBits < 2048 ? 'info' : 'ok', icon: 'key' })
      ])) : h('p', { class: 'muted text-sm' }, t('hlt.dkim.none', { count: selectorsTried })));

    const extra = (label, key) => h('div', { class: 'hlt-extra' },
      h('span', { class: 'hlt-extra-label' }, label),
      report.records[key] ? h('span', { class: 'mono text-xs hlt-extra-value' }, report.records[key])
        : h('span', { class: 'muted text-xs' }, t(lookupFailed(report, key) ? 'hlt.lookupFailed' : 'hlt.missing')));
    const extrasBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'extras' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.mail.extras')),
      extra('MTA-STS', 'mtaSts'),
      extra('TLS-RPT', 'tlsRpt'),
      extra('BIMI', 'bimi'));

    return Card({
      title: t('hlt.mail.title'), icon: 'mail', className: 'hlt-card hlt-mail',
      children: h('div', { class: 'hlt-mail-grid' }, spfBlock, dmarcBlock, dkimBlock, extrasBlock, fcrdnsBlock(report))
    });
  }

  /**
   * Reverse DNS of the MX addresses (lib/health mailIdentity): host, address, PTR name and the
   * forward check, a provider's host marked as such; each address opens in the Reverse DNS view.
   */
  function fcrdnsBlock(report) {
    const mi = report.mailIdentity;
    if (!mi || !mi.addresses.length) return null;
    const variant = { confirmed: 'ok', mismatch: 'warn', 'no-ptr': 'neutral', nxdomain: 'neutral', servfail: 'error', error: 'error' };
    const status = (a, className) => Badge(t(`hlt.fcrdns.st.${a.status}`), {
      variant: variant[a.status] || 'neutral', icon: a.status === 'confirmed' ? 'check' : null, title: a.error || null, className
    });
    // On a phone the verdict sits under the address (hlt-fcrdns-st-inline) and its own column is
    // hidden; each row is a card whose lines carry the column headers as labels (data-label).
    const headers = [t('hlt.fcrdns.col.host'), t('hlt.fcrdns.col.ip'), t('hlt.fcrdns.col.ptr'), t('hlt.fcrdns.col.status')];
    const rows = mi.addresses.map((a) => [
      h('span', { class: 'hlt-fcrdns-host' }, hostLink(a.host),
        a.own ? null : Badge(t('hlt.fcrdns.provider'), { title: t('hlt.fcrdns.providerTitle') })),
      h('span', { class: 'hlt-fcrdns-ip' }, ipLink(a.ip),
        h('a', { class: 'hlt-fcrdns-sweep text-xs', href: ctx.href('ptr', { target: a.ip, focus: report.domain }), title: t('hlt.fcrdns.sweepTitle', { ip: a.ip }) }, t('hlt.fcrdns.sweep')),
        status(a, 'hlt-fcrdns-st-inline')),
      a.names.length ? h('span', { class: 'hlt-fcrdns-ptr' }, h('span', { class: 'mono' }, a.names[0]),
        a.generic ? Badge(t('hlt.fcrdns.generic'), { variant: 'info' }) : null) : null,
      status(a, 'hlt-fcrdns-st')
    ]);
    const block = h('div', { class: 'stack-sm hlt-mail-block hlt-fcrdns', dataset: { block: 'fcrdns' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.fcrdns')),
      h('p', { class: 'muted text-xs hlt-fcrdns-hint' }, t('hlt.fcrdns.hint')),
      miniTable(headers, rows, 'hlt-fcrdns-table'),
      mi.total > mi.checked ? h('p', { class: 'muted text-xs' }, t('hlt.fcrdns.capped', { checked: formatNumber(mi.checked), total: formatNumber(mi.total) })) : null);
    [...block.querySelectorAll('tbody tr')].forEach((tr, i) => {
      tr.dataset.status = mi.addresses[i].status;
      [...tr.cells].forEach((td, j) => { td.dataset.label = headers[j]; });
    });
    return block;
  }

  /* --- MTA-STS policy (one Globalping probe, only after a click) --------------------------- */
  // current.policy = { domain, host, status: 'running'|'done'|'quota'|'error', phase: 'gate'|'fetch',
  //   controller, pendingId (a paid measurement not read yet), fetch, validation, checkedAt, resetAt, error }
  /** Body of the MTA-STS card on screen (null when the report has no card). */
  let policyEl = null;
  /**
   * A check started from the card (keyboard or click) wants focus back on the card's button:
   * every state change rebuilds the card, the busy button cannot hold focus, and the consent
   * dialog closes onto a node that is gone.
   */
  let policyFocus = false;

  /** Is keyboard focus inside the card? */
  const focusInPolicy = () => {
    const doc = globalThis.document;
    return !!(policyEl && doc && doc.activeElement && policyEl.contains(doc.activeElement));
  };
  /** Did focus fall to the page (never pull it away from where the user or a dialog put it)? */
  const focusDropped = () => {
    const doc = globalThis.document;
    const active = doc ? doc.activeElement : null;
    return !active || active === doc.body || active === doc.documentElement || !active.isConnected;
  };

  /** The card: shown when the domain receives mail or publishes an `_mta-sts` record. */
  function mtaStsCard(report) {
    const hasMail = (report.records.mx || []).some((m) => m.exchange && m.exchange !== '.');
    if (!hasMail && !report.records.mtaSts) {
      policyEl = null;
      return null;
    }
    policyEl = h('div', { class: 'stack hlt-mtasts-body', dataset: { mtasts: 'card' } });
    renderPolicy();
    return Card({ title: t('hlt.mtasts.title'), icon: 'lock', className: 'hlt-card hlt-mtasts', children: policyEl });
  }

  /** Severity of a finding, worst first (stable), like the checks. */
  const bySeverity = (list) => list.map((x, i) => ({ x, i }))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.x.severity) - SEVERITY_ORDER.indexOf(b.x.severity) || a.i - b.i).map(({ x }) => x);

  function renderFinding(f) {
    // Numbers of seconds read like the max_age row above ('1.209.600'); a max_age as written
    // in the policy is a string and stays as it is.
    const params = { ...f.params };
    for (const k of ['value', 'max']) if (typeof params[k] === 'number') params[k] = formatNumber(params[k]);
    return h('li', { class: ['hlt-finding', `hlt-sev-${f.severity}`], dataset: { id: f.id, severity: f.severity } },
      h('span', { class: 'hlt-check-icon' }, SeverityIcon(f.severity, { size: 16 })),
      h('div', { class: 'hlt-check-body' },
        h('div', { class: 'hlt-finding-title' }, t(`mtasts.${f.id}.title`, params)),
        h('div', { class: 'hlt-check-detail' }, t(`mtasts.${f.id}.detail`, params))));
  }

  /** A finished check: headline, what came back, the MX cross-check, the findings and the file. */
  function policyResult(job) {
    const v = job.validation;
    const f = job.fetch;
    const p = v.policy;
    // Green only for 'ok'; a policy that is off or had no MX hosts to compare is information.
    const variant = { error: 'error', warn: 'warn' }[v.severity] || (v.headline === 'ok' ? 'ok' : 'info');
    const headline = Alert({ variant, compact: true, message: t(`mtasts.head.${v.headline}`) });
    headline.dataset.mtastsHeadline = v.headline;
    const items = [];
    if (p && p.mode) {
      items.push({ key: t('hlt.mtasts.mode'), value: Badge(p.mode, { variant: { enforce: 'ok', testing: 'info' }[p.mode] || 'neutral', mono: true }) });
    }
    if (p && Number.isInteger(p.maxAge)) {
      items.push({ key: t('hlt.mtasts.maxAge'), value: t('hlt.mtasts.maxAgeValue', { count: Math.floor(p.maxAge / 86400), seconds: formatNumber(p.maxAge) }) });
    }
    if (f.finished) items.push({ key: t('hlt.mtasts.http'), value: [String(f.httpStatus), f.contentType].filter(Boolean).join(' · '), mono: true });
    if (f.tls && f.tls.authorized && f.tls.notAfter) {
      items.push({ key: t('hlt.mtasts.cert'), value: t('hlt.mtasts.certValue', { issuer: f.tls.issuer || '—', date: formatDate(f.tls.notAfter) }) });
    }
    const mxTable = v.usable && v.mode !== 'none' && v.mx.length
      ? miniTable([t('hlt.mtasts.col.host'), t('hlt.mtasts.col.pattern')], v.mx.map((x) => [
        h('span', { class: 'mono', dataset: { mx: x.host, matched: x.matchedBy ? 'true' : 'false' } }, x.host),
        x.matchedBy ? h('span', { class: 'mono' }, x.matchedBy)
          : Badge(t('hlt.mtasts.noMatch'), { variant: v.mode === 'enforce' ? 'error' : 'warn', icon: 'x-circle' })
      ]), 'hlt-mtasts-mx') : null;
    const probe = f.probe;
    const where = probe ? [probe.city, probe.country ? formatRegion(probe.country) : null].filter(Boolean).join(', ') : '';
    const place = [where, probe && probe.network ? `(${probe.network})` : null].filter(Boolean).join(' ');
    const link = measurementUrl(f.measurementId);
    return [
      headline,
      items.length ? KeyValueList(items, { className: 'hlt-kv' }) : null,
      mxTable,
      h('ul', { class: 'hlt-finding-list', dataset: { mtasts: 'findings' } }, bySeverity(v.findings).map(renderFinding)),
      typeof f.body === 'string' && f.body
        ? Disclosure({ summary: t('hlt.mtasts.policy'), className: 'hlt-mtasts-file', children: CodeBlock(f.body, { wrap: true, label: MTA_STS_PATH, maxHeight: '18rem' }) })
        : null,
      h('p', { class: 'muted text-xs hlt-mtasts-meta' },
        t('hlt.mtasts.meta', { when: formatRelative(job.checkedAt), place: place || '—' }),
        link ? [' ', ExternalLink(link, t('hlt.mtasts.measurement'), { className: 'hlt-mtasts-link' })] : null),
      h('p', { class: 'muted text-xs hlt-mtasts-note' }, t('hlt.mtasts.smtpNote'))
    ];
  }

  /** Re-render the card body for the report on screen. */
  function renderPolicy() {
    if (!policyEl || !current || !current.report) return;
    const report = current.report;
    const host = mtaStsPolicyHost(report.domain);
    const url = mtaStsPolicyUrl(report.domain) || `https://mta-sts.${report.domain}${MTA_STS_PATH}`;
    const job = current.policy && current.policy.domain === report.domain ? current.policy : null;
    const status = job ? job.status : 'idle';
    const hadFocus = focusInPolicy();
    clear(policyEl);
    policyEl.dataset.state = status;
    policyEl.append(KeyValueList([
      {
        key: t('hlt.mtasts.txt'),
        value: report.records.mtaSts
          ? h('span', { class: 'hlt-mtasts-txt' }, h('span', { class: 'mono text-sm hlt-extra-value' }, report.records.mtaSts),
            mtaStsTxtInvalid(report) ? Badge(t('hlt.mtasts.txtInvalid'), { variant: 'warn', className: 'hlt-mtasts-txt-invalid' }) : null)
          : h('span', { class: 'muted text-sm' }, t(lookupFailed(report, 'mtaSts') ? 'hlt.lookupFailed' : 'hlt.missing'))
      },
      { key: t('hlt.mtasts.url'), value: h('span', { class: 'mono text-sm hlt-mtasts-url' }, url), copy: url }
    ], { className: 'hlt-kv' }));
    if (!host) {
      policyEl.append(Alert({ variant: 'info', compact: true, message: t('hlt.mtasts.noHost', { host: `mta-sts.${report.domain}` }) }));
      return;
    }
    const done = status === 'done';
    // A paid measurement that could not be read yet is read again for free (no dialog, no probe).
    const reread = status === 'error' && !!job.pendingId;
    const btn = Button({
      label: t(done ? 'hlt.mtasts.again' : reread ? 'hlt.mtasts.reread' : 'hlt.mtasts.check'), icon: reread ? 'refresh' : 'globe', size: 'sm',
      variant: done ? 'secondary' : 'primary', dataset: { action: 'mtasts-check', reread: reread ? 'true' : null }, onClick: () => checkPolicy()
    });
    if (status === 'running') setButtonBusy(btn, true);
    if (status === 'idle' || status === 'running') policyEl.append(h('p', { class: 'muted text-sm hlt-mtasts-intro' }, t('hlt.mtasts.intro')));
    if (status === 'quota') {
      policyEl.append(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('hlt.mtasts.quota', { when: whenText(job.resetAt) }) }));
    } else if (status === 'error') {
      const banner = ErrorBanner(job.error, { title: t('hlt.mtasts.failed'), compact: true });
      if (job.pendingId) banner.querySelector('.alert-body').append(h('p', { class: 'text-sm hlt-mtasts-paid' }, t('hlt.mtasts.paid')));
      policyEl.append(banner);
    } else if (done) {
      policyEl.append(...policyResult(job).filter(Boolean));
    }
    policyEl.append(h('div', { class: 'hlt-mtasts-actions' }, btn,
      status === 'running' && job.phase === 'fetch' ? h('span', { class: 'muted text-sm', attrs: { role: 'status' } }, t('hlt.mtasts.fetching')) : null));
    if ((hadFocus || policyFocus) && !btn.disabled && btn.isConnected && focusDropped()) btn.focus({ preventScroll: true });
  }

  /**
   * "Check the policy": the shared Globalping gate (free /limits read, consent + cost dialog on
   * this purpose's first send of the page session), one measurement, then lib/mtasts. A paid
   * measurement that could not be read yet (`pending`, or the last failed job's) is polled again
   * instead of creating a new one.
   * @param {{ pendingId: string }|null} [pending] a fetch carried over a language re-mount
   */
  async function checkPolicy(pending = null) {
    const s = current;
    if (!s || !s.report || s.controller) return;
    const report = s.report;
    const domain = report.domain;
    const host = mtaStsPolicyHost(domain);
    const prev = s.policy && s.policy.domain === domain ? s.policy : null;
    if (!host || (prev && prev.status === 'running') || !ctx.requireOnline()) return;
    policyFocus = !pending && focusInPolicy();
    const job = {
      domain, host, status: 'running', phase: 'gate', controller: new AbortController(),
      pendingId: pending ? pending.pendingId : (prev && prev.status === 'error' ? prev.pendingId : null),
      deadlineAt: null, fetch: null, validation: null, checkedAt: null, resetAt: null, error: null
    };
    s.policy = job;
    renderPolicy();
    const signal = mergeSignals(ctx.signal, job.controller.signal);
    const live = () => current === s && s.policy === job;
    try {
      let client;
      if (job.pendingId) {
        client = await ctx.getGlobalping();
      } else {
        const gate = await gateProbes(ctx, { purpose: 'mta-sts', probes: 1, privacy: t('hlt.mtasts.privacy', { host, path: MTA_STS_PATH }), signal });
        if (!live()) return;
        if (gate.status === 'cancelled') {
          s.policy = prev;
          return;
        }
        if (gate.status === 'quota') {
          Object.assign(job, { status: 'quota', resetAt: gate.resetAt });
          announce(t('hlt.mtasts.quota', { when: whenText(job.resetAt) }));
          return;
        }
        if (gate.status === 'unreachable') throw gate.error;
        client = gate.client;
        const body = mtaStsPolicyRequest(domain);
        job.phase = 'fetch';
        renderPolicy();
        const created = await client.create(body, { signal });
        noteQuota(created.quota);
        job.pendingId = created.id;
        job.deadlineAt = Date.now() + (body.timeout + GP_LIMITS.clientSlackS) * 1000;
      }
      if (!live()) return;
      job.phase = 'fetch';
      renderPolicy();
      const measurement = await client.poll(job.pendingId, job.deadlineAt ? { signal, deadlineAt: job.deadlineAt } : { signal });
      if (!live()) return;
      const fetch = interpretPolicyFetch(measurement, { host });
      const validation = validateMtaSts({ domain, fetch, ...mtaStsContext(report) });
      Object.assign(job, { status: 'done', pendingId: null, fetch, validation, checkedAt: new Date() });
      announce(t(`mtasts.head.${validation.headline}`));
    } catch (err) {
      // An abort means a new check or leaving the view: that state is someone else's now.
      if (!live() || signal.aborted || errorKind(err) === 'abort') return;
      if (err && (err.code === 'rate-limit' || err.code === 'insufficient-credits')) {
        noteQuota(err.quota);
        Object.assign(job, { status: 'quota', resetAt: err.resetAt || null, pendingId: null });
        announce(t('hlt.mtasts.quota', { when: whenText(job.resetAt) }));
        return;
      }
      // A measurement Globalping no longer knows cannot be read again: the next try creates one.
      const pendingId = err && err.code === 'not-found' ? null : (err && err.measurementId) || job.pendingId;
      Object.assign(job, { status: 'error', error: err, pendingId });
      announce(`${t('hlt.mtasts.failed')}: ${describeError(err).message}`);
    } finally {
      job.controller = null;
      if (current === s && (s.policy === job || s.policy === prev)) renderPolicy();
      policyFocus = false;
    }
  }

  /** The report as downloaded: plus the MTA-STS policy check when one finished for it. */
  function exportReport(report) {
    const p = current && current.report === report && current.policy && current.policy.status === 'done' && current.policy.domain === report.domain
      ? current.policy : null;
    return p ? { ...report, mtaStsPolicy: mtaStsExport({ domain: p.domain, fetch: p.fetch, validation: p.validation, checkedAt: p.checkedAt }) } : report;
  }

  function caaCard(report) {
    const caa = report.caa;
    const children = [];
    if (!caa) {
      children.push(h('p', { class: 'muted text-sm' }, '—'));
    } else if (caa.error) {
      children.push(Alert({ variant: 'warn', compact: true, message: t('hlt.caa.error', { error: caa.error }) }));
    } else if (!caa.foundAt) {
      children.push(Alert({ variant: 'info', compact: true, icon: 'info', message: t('hlt.caa.none') }));
    } else {
      const p = caa.parsed;
      const caLabel = (issuer) => {
        const ca = caNameFor(issuer);
        return [
          h('span', { class: 'hlt-ca-name' }, ca ? ca.name : issuer),
          ca ? h('span', { class: 'muted mono text-xs' }, issuer) : null,
          ca && ca.distrusted ? Badge(t('hlt.caa.distrusted', { year: ca.distrusted }), { variant: 'error', icon: 'alert' }) : null,
          // Against the workspace's expected CAs: a CAA value that lets another CA issue is flagged.
          ExpectedCaaBadge(issuer)
        ];
      };
      // One entry per issue / issuewild value: usable (optionally restricted by RFC 8657
      // parameters, with what that means for the next renewal), unsatisfiable or malformed.
      const caItem = (x, wildcard) => {
        const problem = x.valid ? x.problem : x.error;
        const state = problem ? (x.valid ? 'unusable' : 'malformed') : x.restricted ? 'restricted' : 'allowed';
        const badges = [];
        if (x.restricted && x.methods) badges.push(Badge(t('hlt.caa.onlyMethods', { methods: x.methods.join(', ') }), { variant: 'info', icon: 'shield' }));
        if (x.restricted && x.accountUri) badges.push(Badge(t('hlt.caa.accountOnly'), { variant: 'info', icon: 'key' }));
        if (state === 'unusable') badges.push(Badge(t('hlt.caa.unusable'), { variant: 'error', icon: 'x-circle' }));
        if (state === 'malformed') badges.push(Badge(t('hlt.caa.malformed'), { variant: 'error', icon: 'x-circle' }));
        const notes = x.restricted ? caaRestrictionNotes([x], { wildcard }) : [];
        const body = [
          x.restricted && x.accountUri ? h('div', { class: 'hlt-ca-account mono text-xs' }, x.accountUri) : null,
          problem ? h('div', { class: 'hlt-ca-problem text-sm' }, t(`health.caa.problem.${problem}`)) : null,
          notes.length ? h('ul', { class: 'hlt-ca-notes' }, notes.map((n) => h('li', { class: 'hlt-ca-note text-sm', dataset: { note: n.code } },
            Icon('info', { size: 13, className: 'hlt-ca-note-icon' }), h('span', null, t(n.key, n.params))))) : null
        ].filter(Boolean);
        return h('li', { class: ['hlt-ca', `hlt-ca-${state}`], dataset: { caa: state, issuer: x.issuer } },
          h('div', { class: 'hlt-ca-head' },
            Icon(problem ? 'x-circle' : 'check-circle', { size: 15, className: 'hlt-ca-icon' }),
            x.valid ? caLabel(x.issuer) : h('span', { class: 'hlt-ca-raw mono text-sm' }, x.raw),
            badges),
          body.length ? h('div', { class: 'hlt-ca-body' }, body) : null);
      };
      const list = (entries, wildcard) => {
        // An unrestricted value repeated for the same CA adds nothing; ";" values authorize nobody.
        const seen = new Set();
        const shown = entries.filter((x) => {
          if (x.valid && !x.issuer) return false;
          const plain = x.valid && !x.problem && !x.restricted;
          if (plain && seen.has(x.issuer)) return false;
          if (plain) seen.add(x.issuer);
          return true;
        });
        const usable = shown.some((x) => x.valid && !x.problem);
        return h('div', { class: 'stack-sm' },
          usable ? null : h('p', { class: 'hlt-caa-deny text-sm' }, Icon('x-circle', { size: 14 }), ' ', t('hlt.caa.nobody')),
          shown.length ? h('ul', { class: 'hlt-ca-list' }, shown.map((x) => caItem(x, wildcard))) : null);
      };
      children.push(h('p', { class: 'muted text-sm' }, t('hlt.caa.foundAt', { name: caa.foundAt })));
      children.push(h('div', { class: 'stack-sm', dataset: { caaProperty: 'issue' } }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.issue')),
        p.issue.length ? list(p.issue, false) : h('p', { class: 'text-sm' }, t('hlt.caa.anyone'))));
      children.push(h('div', { class: 'stack-sm', dataset: { caaProperty: 'issuewild' } }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.issuewild')),
        p.issuewild.length ? list(p.issuewild, true) : h('p', { class: 'muted text-sm' }, t('hlt.caa.sameAsIssue'))));
      if ([...p.issue, ...p.issuewild].some((x) => x.valid && (x.accountUri !== null || x.methods !== null))) {
        children.push(h('p', { class: 'muted text-xs hlt-caa-rfc' }, t('hlt.caa.rfc8657')));
      }
      if (p.iodef.length) {
        children.push(h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.iodef')),
          h('div', { class: 'stack-sm' }, p.iodef.map((x) => (/^https?:/i.test(x.url) ? ExternalLink(x.url, x.url) : h('span', { class: 'mono text-sm' }, x.url))))));
      }
      children.push(Disclosure({
        summary: `${t('hlt.caa.records')} (${formatNumber(caa.records.length)})`,
        children: CodeBlock(caa.records.map((rr) => `${rr.name}. ${rr.ttl} IN CAA ${rr.text}`).join('\n'), { wrap: true })
      }));
    }
    return Card({ title: t('hlt.caa.title'), icon: 'certificate', className: 'hlt-card hlt-caa', children: h('div', { class: 'stack' }, children) });
  }

  function dnsCard(report) {
    const rec = report.records;
    const failedText = () => h('span', { class: 'muted text-sm', dataset: { lookup: 'failed' } }, t('hlt.lookupFailed'));
    /** A record's value, or "lookup failed" when its query got no usable answer (never a bare dash). */
    const known = (key, value) => (lookupFailed(report, key) ? failedText() : value);
    const classify = (ip) => classifyResolution({ status: 'NOERROR', ipv4: ipVersion(ip) === 4 ? [ip] : [], ipv6: ipVersion(ip) === 6 ? [ip] : [] });
    const addrList = (ips) => (ips && ips.length ? h('div', { class: 'stack-sm' }, ips.map((ip) => h('span', { class: 'cluster' }, ipLink(ip), KindBadge(classify(ip))))) : null);
    const nsValue = rec.ns.length ? h('div', { class: 'stack-sm' }, rec.ns.map((ns) => h('div', { class: 'hlt-ns' },
      hostLink(ns), ipList((report.nsAddresses || {})[ns] || [])))) : null;
    const mxHosts = report.mxHosts || {};
    const nullMx = rec.mx.length === 1 && rec.mx[0].exchange === '.';
    const mxValue = nullMx ? Badge(t('hlt.dns.nullMx'), { variant: 'info' }) : rec.mx.length ? h('div', { class: 'stack-sm' }, rec.mx.map((m) => h('div', { class: 'hlt-ns' },
      h('span', { class: 'num muted' }, String(m.preference)), ' ', hostLink(m.exchange),
      ipList(mxHosts[m.exchange] ? [...mxHosts[m.exchange].ipv4, ...mxHosts[m.exchange].ipv6] : []))))
      : lookupFailed(report, 'mx') ? failedText() : null;
    const w = report.wildcard;
    const https = rec.https || [];
    const alpn = [...new Set(https.flatMap((x) => (x.params && x.params.alpn) || []))];
    return Card({
      title: t('hlt.dns.title'), icon: 'globe', className: 'hlt-card hlt-dns',
      actions: h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('lookup', { name: report.domain, type: 'A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS' }) }, Icon('search', { size: 14 }), h('span', { class: 'btn-label' }, t('hlt.dns.lookupAll'))),
      children: KeyValueList([
        { key: t('hlt.dns.ns'), value: known('ns', nsValue) },
        { key: t('hlt.dns.soa'), value: known('soa', rec.soa ? h('span', { class: 'mono text-sm' }, t('hlt.dns.soaValue', { mname: rec.soa.mname, email: rec.soa.email || rec.soa.rname, serial: rec.soa.serial })) : null) },
        { key: t('hlt.dns.mx'), value: mxValue },
        { key: t('hlt.dns.a'), value: known('a', addrList(rec.a)) },
        { key: t('hlt.dns.aaaa'), value: known('aaaa', addrList(rec.aaaa)) },
        { key: t('hlt.dns.https'), value: known('https', https.length ? h('span', { class: 'cluster' }, alpn.map((a) => Badge(a, { mono: true }))) : null) },
        { key: t('hlt.dns.txt'), value: known('txt', h('a', { href: ctx.href('lookup', { name: report.domain, type: 'TXT' }) }, t('hlt.dns.txtCount', { count: rec.txt.length }))) },
        // No wildcard probe answered: not known, never "No".
        { key: t('hlt.dns.wildcard'), value: w ? (w.wildcard ? h('span', { class: 'mono text-sm' }, t('hlt.dns.wildcardYes', { values: [...w.cnames, ...w.ipv4, ...w.ipv6].join(', ') })) : w.error ? failedText() : t('hlt.dns.wildcardNo')) : null }
      ], { className: 'hlt-kv' })
    });
  }

  /**
   * The Delegation card: every name server of the report's zone asked through Globalping
   * (ui/delegation-panel.js, loaded on the first click). The job is the holder kept with the
   * report on screen (`current.delegation`): a re-render mounts the panel on it again.
   */
  function delegationCard(report) {
    const zone = report.zone;
    if (!zone || !current || current.report !== report) return null;
    const s = current;
    const body = h('div', { class: 'stack-sm hlt-dlg-body', dataset: { delegation: 'card' } });
    const mountPanel = async (start) => {
      try {
        const { DelegationPanel, freshDelegation } = await loadDelegation();
        if (s.delegation?.zone !== zone) s.delegation = freshDelegation(zone);
        clear(body);
        body.append(DelegationPanel({ ctx, holder: s.delegation, start }));
      } catch (err) {
        ctx.checkOutdated();
        clear(body);
        body.append(ErrorBanner(err, { title: t('hlt.dlg.loadFailed'), compact: true }));
      }
    };
    if (s.delegation?.zone === zone) mountPanel(false);
    else {
      const count = Math.min(8, report.records.ns.length || 2) * 3 + 1;
      body.append(h('p', { class: 'muted text-sm' }, t('hlt.dlg.intro', { zone }), ' ', t('hlt.dlg.cost', { count })), h('div', null, Button({
        label: t('hlt.dlg.check'), icon: 'globe', size: 'sm', variant: 'primary', dataset: { action: 'dlg-open' },
        onClick: (e) => { setButtonBusy(e.currentTarget, true); mountPanel(true); }
      })));
    }
    return Card({ title: t('hlt.dlg.title'), icon: 'server', className: 'hlt-card hlt-dlg', children: body });
  }

  /**
   * The Dependencies card: the domains the report's records point to, looked up in their
   * registries — the Takeover risks audit of Subdomains for this domain alone (ui/takeover-panel.js
   * DependencyPanel, loaded on the first click, with the report's extra DKIM selectors). The job
   * is the holder kept with the report on screen (`current.dependencies`): a re-render mounts the
   * panel on it again.
   */
  function dependencyCard(report) {
    if (!current || current.report !== report) return null;
    const s = current;
    const domain = report.domain;
    const body = h('div', { class: 'stack-sm hlt-dep-body', dataset: { dependencies: 'card' } });
    const mountPanel = async (start) => {
      try {
        const { DependencyPanel, freshDependencies } = await loadDependencies();
        if (s.dependencies?.domain !== domain) s.dependencies = freshDependencies(domain, s.selectors || []);
        clear(body);
        body.append(DependencyPanel({ ctx, holder: s.dependencies, start, runKey: 'hlt.dep.check' }));
      } catch (err) {
        ctx.checkOutdated();
        clear(body);
        body.append(ErrorBanner(err, { title: t('hlt.dep.loadFailed'), compact: true }));
      }
    };
    if (s.dependencies?.domain === domain) mountPanel(false);
    else {
      body.append(h('p', { class: 'text-sm' }, t('hlt.dep.sends')), h('div', null, Button({
        label: t('hlt.dep.check'), icon: 'shield', size: 'sm', variant: 'primary', dataset: { action: 'dep-open' },
        onClick: (e) => { setButtonBusy(e.currentTarget, true); mountPanel(true); }
      })));
    }
    return Card({
      title: t('hlt.dep.title'), icon: 'shield', className: 'hlt-card hlt-dep',
      children: [h('p', { class: 'muted text-sm' }, t('hlt.dep.intro', { domain })), body]
    });
  }

  function renderDetails(report) {
    clear(detailsEl);
    detailsEl.append(...[rdapCard, dnssecCard, mailCard, mtaStsCard, caaCard, dnsCard, delegationCard, dependencyCard].map((card) => card(report)).filter(Boolean));
  }

  /**
   * Problems first and the Web card, once ui/health-v2.js is loaded (the latest call wins). The
   * Web card's Observatory grade comes back as a new report, which is drawn again.
   */
  let v2Token = 0;
  function renderV2(report, selectors) {
    const token = ++v2Token;
    loadV2().then((v2) => {
      if (token !== v2Token) return;
      clear(v2El);
      const onReport = (next) => {
        if (!current || current.report !== report || current.controller) return;
        current.report = next;
        renderReport(next, selectors);
      };
      v2El.append(
        v2.ProblemsPanel(report, { checkTitle, checkDetail, fixToggle, fixable: (c) => c.severity !== 'ok' && FIXABLE_CHECKS.includes(c.id) }),
        v2.WebPanel(report, { ctx, state: current, onReport }));
    }).catch((err) => {
      if (token !== v2Token) return;
      ctx.checkOutdated();
      clear(v2El);
      v2El.append(ErrorBanner(err, { compact: true }));
    });
  }

  function renderReport(report, selectors) {
    emptyEl.hidden = true;
    results.hidden = false;
    renderHero(report, selectors);
    renderV2(report, selectors);
    renderChecks(report);
    renderDetails(report);
  }

  /* --- run -------------------------------------------------------------------------------- */
  let current = null;

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    domainField.input.readOnly = on;
    // The report on screen belongs to the previous check until this one finishes.
    if (heroSummary) heroSummary.setDisabled(on);
    ctx.setBusy(on);
  }

  /** The route params of a check: its domain and extra selectors (what a shared link runs). */
  function checkParams(check) {
    const selectors = check.selectors || [];
    return { domain: check.domain, selectors: selectors.length ? selectors.join(',') : null };
  }

  /** "Copy link" shares the check on screen (not the box, which may hold a carried domain). */
  function setShareAction() {
    ctx.setActions(CopyButton(() => ctx.shareUrl(current ? checkParams(current) : ctx.params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  /** The domains the box holds, as a check reads them (what a carried domain may replace). */
  const boxDomains = (text) => {
    const raw = String(text).trim();
    return [normalizeHostname(raw.replace(/^\*\./, '')) || raw];
  };

  /**
   * The domain the box last took from a carried target: a newer one replaces it while the box
   * still holds it (lib/session.js fillReplaces). A re-mount keeps it (snapshot); a check forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null)
    : (isFillOnly(ctx.params) && initialDomain) || null;

  /**
   * A domain carried over from another tool (`run=0`) goes into the box while it is empty or still
   * holds the report's domain or the domain carried before — never over a draft — and nothing
   * runs; the report stays.
   */
  function takeCarried(domain) {
    const last = current && current.report ? [current.report.domain] : null;
    if (fillReplaces(domainField.value, last, boxDomains, carried)) {
      domainField.value = domain;
      domainField.setError(null);
      carried = domain;
    }
  }

  /** Run the checks. `auto`: a shared link's run on arrival (offline: no toast, see lookup.js). */
  function start({ auto = false } = {}) {
    domainField.setError(null);
    const raw = domainField.value.trim();
    const domain = normalizeHostname(raw.replace(/^\*\./, ''));
    if (!domain || normalizeIP(raw)) {
      domainField.setError(t('hlt.invalid'));
      domainField.focus();
      return;
    }
    domainField.value = domain;
    carried = null;
    const extra = parseSelectors(selectorsField.value);
    if (!ctx.requireOnline({ quiet: auto })) return;
    ctx.setParams({ domain, selectors: extra.length ? extra.join(',') : null });
    setShareAction();
    ctx.runStarted(domain);
    run(domain, extra);
  }

  /**
   * A check stopped or failed: the report on screen is still `shown`'s, so its controls (the
   * filter, RDAP Retry, the policy check), Copy link and the kept result read that check again.
   * Its policy check, stopped with the new check, starts over (a paid measurement is read again).
   */
  function showAgain(shown) {
    current = shown;
    const p = shown.policy;
    if (p && p.status === 'running') {
      shown.policy = null;
      if (p.pendingId) checkPolicy({ pendingId: p.pendingId });
      else renderPolicy();
    }
  }

  async function run(domain, extraSelectors) {
    // The check whose report stays on screen until this one's replaces it.
    const shown = current && current.report ? current : (current && current.shown) || null;
    if (current && current.controller) current.controller.abort();
    if (current && current.policy && current.policy.controller) current.policy.controller.abort();
    if (current && current.rdapRetry) current.rdapRetry.abort();
    if (current && current.delegation && current.delegation.controller) current.delegation.controller.abort();
    if (current && current.dependencies && current.dependencies.controller) current.dependencies.controller.abort();
    if (current && current.observatory && current.observatory.controller) current.observatory.controller.abort();
    const controller = new AbortController();
    const state = {
      domain, selectors: extraSelectors.slice(), controller, report: null, finishedAt: null,
      selectorCount: DEFAULT_DKIM_SELECTORS.length + extraSelectors.length, policy: null, shown
    };
    current = state;
    clear(errorEl);
    progress.el.hidden = false;
    progress.setVariant('default');
    progress.setLabel(t('hlt.progress', { domain }));
    progress.set(0, 10);
    setRunning(true);
    const startedAt = performance.now();
    try {
      const dns = await ctx.getDns();
      const signal = mergeSignals(ctx.signal, controller.signal);
      let report = await domainHealth(domain, {
        dns,
        signal,
        dkimSelectors: [...DEFAULT_DKIM_SELECTORS, ...extraSelectors],
        onProgress: ({ step, done, total }) => {
          if (current !== state) return;
          progress.set(done, total);
          progress.setLabel(`${t('hlt.progress', { domain })} · ${t(`hlt.step.${step}`)}`);
        }
      });
      if (current !== state) return;
      // The Web step (SPEC §5.78): www and the bare domain, the HTTPS record; same DNS client.
      try {
        progress.setLabel(`${t('hlt.progress', { domain })} · ${t('hlt.step.web')}`);
        report = await (await loadV2()).addWeb(report, { dns, signal });
      } catch (err) {
        if (err && err.name === 'AbortError') throw err;
        ctx.checkOutdated();
      }
      if (current !== state) return;
      state.report = report;
      state.finishedAt = new Date();
      progress.done(`${t('common.done')} · ${formatDuration(performance.now() - startedAt)}`);
      renderReport(report, state.selectors);
      setTimeout(() => { if (current === state) progress.el.hidden = true; }, 1200);
    } catch (err) {
      if (current !== state) return;
      progress.el.hidden = true;
      if (err && err.name === 'AbortError') return;
      errorEl.append(Alert({ variant: 'error', title: t('hlt.failed'), message: err && err.message ? err.message : String(err) }));
    } finally {
      if (current === state) {
        state.controller = null;
        state.shown = null;
        if (!ctx.signal.aborted) {
          setRunning(false);
          if (!state.report && shown) showAgain(shown);
        }
      }
    }
  }

  /* --- initial state ----------------------------------------------------------------- */
  if (restored && restored.report) {
    const policy = restored.policy && restored.policy.domain === restored.report.domain ? restored.policy : null;
    current = {
      domain: restored.report.domain, selectors: Array.isArray(restored.runSelectors) ? restored.runSelectors : [],
      controller: null, report: restored.report, selectorCount: restored.selectorCount,
      finishedAt: restored.at ? new Date(restored.at) : new Date(),
      policy: policy && policy.status !== 'running' ? policy : null,
      delegation: restored.delegation && restored.delegation.zone === restored.report.zone ? restored.delegation : null,
      dependencies: restored.dependencies && restored.dependencies.domain === restored.report.domain ? restored.dependencies : null
    };
    renderReport(restored.report, current.selectors);
    // A policy fetch that was in flight: its measurement is paid for, so read it (GETs are free).
    if (policy && policy.status === 'running') checkPolicy(policy);
    // The kept report under a domain carried over from another tool: the box takes the domain.
    if (isFillOnly(ctx.params) && (ctx.params.domain || ctx.params.name)) takeCarried(ctx.params.domain || ctx.params.name);
  } else if (!restored && initialDomain && !isFillOnly(ctx.params)) {
    // Shared link: run immediately. A re-mounted draft (typed, never run) or a domain carried over
    // from another tool (`run=0`) only fills the form.
    Promise.resolve().then(() => start({ auto: true }));
  }
  if (restored && restored.report) setShareAction();

  // The CAA card's expected / unexpected CA badges follow the workspace's expected CAs.
  ctx.onCleanup(ctx.state.subscribe((change) => {
    if (change.key === 'workspaceData' && expectedCasChanged(change) && current && current.report && !current.controller) {
      renderReport(current.report, current.selectors);
    }
  }));

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
      if (current && current.policy && current.policy.controller) current.policy.controller.abort();
      if (current && current.rdapRetry) current.rdapRetry.abort();
      if (current && current.observatory && current.observatory.controller) current.observatory.controller.abort();
    },
    snapshot() {
      const report = current && !current.controller ? current.report : null;
      const p = report && current.policy ? current.policy : null;
      let policy = null;
      // A finished (or failed) check stays; one in flight is carried only once its measurement
      // is paid for (the dialog of a check still at the gate is simply closed).
      if (p && p.status !== 'running') policy = { ...p, controller: null };
      else if (p && p.pendingId) policy = { domain: p.domain, status: 'running', pendingId: p.pendingId };
      return {
        domain: domainField.value,
        carried,
        selectors: selectorsField.value,
        filter,
        report,
        at: report ? current.finishedAt : null,
        runSelectors: report ? current.selectors : null,
        selectorCount: current ? current.selectorCount : null,
        policy,
        // A finished delegation check stays with its report; one in flight stops with the view.
        delegation: report && current.delegation && !current.delegation.controller ? { ...current.delegation, view: null } : null,
        // The same for the dependency check (its page check too: one in flight stops with the view).
        dependencies: report && current.dependencies && !current.dependencies.controller
          ? { ...current.dependencies, view: null, http: current.dependencies.http && current.dependencies.http.status === 'running' ? null : current.dependencies.http } : null
      };
    },
    result() {
      if (!current || current.controller || !current.report) return null;
      return { subject: current.report.domain, at: current.finishedAt, params: checkParams(current) };
    },
    rerun() {
      if (current && current.report) {
        domainField.value = current.report.domain;
        selectorsField.value = current.selectors.join(', ');
      }
      start();
    },
    update(params) {
      const domain = params.domain || params.name;
      if (!domain) return false;
      if (isFillOnly(params)) {
        takeCarried(domain);
        return true;
      }
      domainField.value = domain;
      if (params.selectors !== undefined) selectorsField.value = params.selectors;
      start();
      return true;
    }
  };
}

/** Abort a running check. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * Form + finished report carried over a language re-mount and kept for the next visit (no re-check).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The finished report on screen (kept by the shell when the view is left), or null.
 * @returns {{ subject: string, at: Date }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: check the report's domain again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take new route params (e.g. "Check <zone>" links) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
