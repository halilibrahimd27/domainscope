/**
 * views/reports.js — "DMARC & TLS reports" (`#/reports`): the DMARC aggregate (rua) and SMTP TLS
 * (TLS-RPT) reports a domain receives, dropped in many at once (zip, gzip, XML, JSON; up to
 * lib/dmarcreport.js MAX_REPORT_FILES a drop) and read in the browser, with the files read so far
 * counted and a Stop; files dropped while it reads are read next. lib/dmarcreport.js,
 * lib/tlsrpt.js and lib/zipread.js do the work; this view draws:
 *
 * - DMARC: the headline (compliance, the published policy, whether p=reject can come and which
 *   sources to fix first, the unknown senders), the four source classes as filter tiles (your
 *   servers, authorized third parties, forwarders, unknown senders), one row per sending address
 *   with the service behind it (lib/senders.js: named from its DKIM signature, its return-path or
 *   the SPF include that authorizes it, with no lookup), its SPF / DKIM alignment, disposition and
 *   why it is in its class, or the same sources folded per service with totals and how to align
 *   each service; **Identify senders** looks up what no report names; the reporters;
 * - TLS-RPT: the success rate, the policies senders found, the failures by type with advice and
 *   a link to the check that goes deeper (Domain Health's MTA-STS card, TLSA records in DNS
 *   Lookup, the MX host's certificate and its DANE tab), every failure detail.
 *
 * Privacy: the files are read and kept in this module's memory only (never uploaded, stored or put
 * in a URL); a reload, Forget, another workspace or "Delete all local data" drops them. After a
 * drop, the reported domains' SPF is looked up over the DoH resolvers (names and types only) to
 * tell your servers from third parties; an address's reverse DNS and network (lib/ipintel.js) only
 * on a click, at most {@link INTEL_MAX} per click. **Identify senders**, on a click only: the
 * reverse DNS of at most lib/senders.js IDENTIFY_MAX addresses no report names, each name checked
 * forward (lib/ptrsweep.js checkFcrdns, through the view's DohClient and its limiter), matched
 * against the sender lists this site bundles (read from assets/data/senders on that click), then
 * the network of those still unnamed as Look up asks it. Offline, the reports are still read and
 * classified from their own evidence and the server list, and the SPF line says it was not checked.
 *
 * The page session keeps only the fact that reports were read (`result()`, no subject); a drop
 * makes the busiest reported domain the current target. Pure helpers are exported for
 * tests/js/reports-view.test.js; the module is DOM-free at import time.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, DataTable, Disclosure, EmptyState, FileDrop, Icon, KeyValueList, ProgressBar, SegmentedControl, StatCard, Tabs,
  announce, ipSortValue, select, toast
} from '../ui/components.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { registerStrings, formatNumber, formatPercent, formatDate, formatDateTime } from '../i18n.js';
import {
  readReportFiles, aggregateDmarc, spfDomainsFor, loadSpfContext, classifySources, dmarcOverview, dmarcCsvRows,
  DMARC_CSV_COLUMNS, SOURCE_CLASSES, DISPOSITIONS, MAX_REPORT_FILES
} from '../lib/dmarcreport.js';
import { summarizeTls, tlsAdvice, tlsCsvRows, TLS_CSV_COLUMNS, TLS_RESULT_TYPES, TLS_POLICY_TYPES } from '../lib/tlsrpt.js';
import { createIpIntel } from '../lib/ipintel.js';
import {
  identifySource, spfPathOf, senderGuide, groupGuide, identifyCandidates, groupSources, serviceCsvRows, loadSenderMaps, IDENTIFY_MAX, SERVICE_CSV_COLUMNS
} from '../lib/senders.js';
import { checkFcrdns, FCRDNS_STATUSES } from '../lib/ptrsweep.js';
import { ipFieldStatus } from '../lib/sourcestatus.js';
import { registrableDomain } from '../lib/domain.js';
import { toCsv } from '../lib/export.js';
import { mergeSignals, sharePercent } from '../lib/util.js';
import { registerSummaryBuilder } from '../lib/summarycore.js';
import { reportsSummary, REPORTS_SUMMARY_I18N } from '../lib/reportsummary.js';
import { NaMark } from '../ui/source-status.js';
import { SummaryButton } from '../ui/summary-button.js';

/** Route id (`#/reports`). */
export const id = 'reports';
/** i18n key of the page title. */
export const titleKey = 'nav.reports';
/** Icon name (ui/components.js Icon). */
export const icon = 'inbox';

/** Files the drop zone offers (the content decides what a file is, never its name). */
const ACCEPT = '.xml,.gz,.zip,.json';
/** Largest dropped file read (a month of a busy domain's reports, zipped, is a few MB). */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
/** Most addresses one "Look up" click sends to the IP data services (RIPEstat fair use). */
export const INTEL_MAX = 25;
/** Known sources the headline lists under "Fix first" (the table has the rest). */
export const FIX_FIRST_MAX = 5;
/** Files that could not be used listed by name (the rest counted: "+1,800 more"). */
export const PROBLEMS_MAX = 200;
/** Addresses an Identify senders click looks up at once (the DohClient's limiter caps the HTTP requests). */
export const IDENTIFY_CONCURRENCY = 8;
/** Addresses a service group's details list (the rest counted). */
export const GROUP_LIST_MAX = 20;
/** The two views of the sending addresses: one row per address, or per service. */
export const SOURCE_VIEWS = Object.freeze(['address', 'service']);

/** Badge / tile look of each source class. */
export const CLASS_STYLE = Object.freeze({
  yours: Object.freeze({ variant: 'ok', icon: 'server' }),
  'third-party': Object.freeze({ variant: 'info', icon: 'briefcase' }),
  forwarder: Object.freeze({ variant: 'neutral', tile: 'private', icon: 'share' }),
  unknown: Object.freeze({ variant: 'warn', icon: 'alert' })
});
/** Links of a TLS failure's advice (lib/tlsrpt.js tlsAdvice `tools`). */
export const TLS_TOOLS = Object.freeze(['health', 'tlsa', 'cert']);
/** States of the SPF line (`rpt.spf.<state>`). */
export const SPF_LINE_STATES = Object.freeze(['loading', 'ok', 'none', 'multiple', 'failed', 'offline']);

// Copy summary's builder and texts load with this view, not on the start route (lib/reportsummary.js).
registerSummaryBuilder('reports', reportsSummary);
registerStrings('en', REPORTS_SUMMARY_I18N.en);
registerStrings('tr', REPORTS_SUMMARY_I18N.tr);

registerStrings('en', {
  'rpt.privacyTitle': 'Everything stays in this browser',
  'rpt.privacy': 'The report files are read and unpacked here, never uploaded or saved: a reload, Forget or “Delete all local data” drops them. To tell your servers from third parties, the page then looks up the current SPF record of each reported domain over your DoH resolvers (domain names only); an address’s reverse DNS and network only when you press Look up or Identify senders.',
  'rpt.drop.title': 'Drop DMARC and TLS reports here, or choose them',
  'rpt.drop.more': 'Add more reports',
  'rpt.drop.hint': 'Up to {max} files at once: .xml, .xml.gz, .zip (a zipped mailbox folder too), .json, .json.gz',
  'rpt.choose': 'Choose files',
  'rpt.folder': 'Choose a folder',
  'rpt.forget': 'Forget reports',
  'rpt.forgotten': 'The reports were forgotten.',
  'rpt.busy': 'Reading the reports…',
  'rpt.reading': { one: 'Reading {count} file…', other: 'Reading {count} files…' },
  'rpt.queued': { one: '{count} more file will be read next.', other: '{count} more files will be read next.' },
  'rpt.stop': 'Stop reading',
  'rpt.stopped': 'Reading stopped.',
  'rpt.stoppedKept': { one: 'Reading stopped. The report read before it is kept.', other: 'Reading stopped. The {count} reports read before it are kept.' },
  'rpt.stoppedNone': 'Reading stopped. No report had been read yet.',
  'rpt.loaded': 'Read: {dmarc} DMARC and {tls} TLS reports',
  'rpt.noneRead': 'No DMARC or TLS report in these files.',
  'rpt.kept': 'Reports read at {time}',
  'rpt.count.files': { one: '{count} file', other: '{count} files' },
  'rpt.count.dmarc': { one: '{count} DMARC report', other: '{count} DMARC reports' },
  'rpt.count.tls': { one: '{count} TLS report', other: '{count} TLS reports' },
  'rpt.count.duplicates': { one: '{count} report dropped twice counts once', other: '{count} reports dropped twice count once' },
  'rpt.count.problems': { one: '{count} could not be used', other: '{count} could not be used' },
  'rpt.problems': 'What could not be used',
  'rpt.problem.not-zip': 'not a zip archive',
  'rpt.problem.truncated': 'the file is cut short (an incomplete download?)',
  'rpt.problem.multi-disk': 'a zip split over several files',
  'rpt.problem.encrypted': 'an encrypted (password-protected) entry',
  'rpt.problem.method': 'packed with a method browsers cannot unpack ({detail})',
  'rpt.problem.crc': 'damaged: its checksum does not match',
  'rpt.problem.too-large': 'too large to read here',
  'rpt.problem.too-many': 'more entries than one drop reads ({detail})',
  'rpt.problem.corrupt': 'damaged: it could not be unpacked',
  'rpt.problem.overlap': 'entries that share their bytes: an archive built to unpack far more than it holds',
  'rpt.problem.nested': 'an archive inside an archive inside an archive: unpack it first',
  'rpt.problem.unsupported': 'this browser cannot unpack it',
  'rpt.problem.not-report': 'neither a DMARC nor a TLS report',
  'rpt.problem.xml': 'XML that could not be read ({detail})',
  'rpt.problem.not-dmarc': 'XML, but no DMARC aggregate report',
  'rpt.problem.incomplete': 'a report without its {detail}',
  'rpt.problem.not-json': 'JSON that could not be read',
  'rpt.problem.not-tlsrpt': 'JSON, but no TLS report',
  'rpt.problem.empty': 'an empty file',
  'rpt.emptyTitle': 'Read the reports your domain receives',
  'rpt.emptyBody': 'Receivers such as Google and Microsoft mail a DMARC aggregate report (rua) every day, and TLS-RPT reports about the TLS sessions to your MX hosts. Drop them here — many at once, zipped or not — to see who sends mail as your domain, what fails, and what to fix before p=reject.',
  'rpt.tab.dmarc': 'DMARC',
  'rpt.tab.tls': 'TLS-RPT',
  'rpt.tabs': 'Report types',
  'rpt.domain': 'Domain',
  'rpt.domainOption': { one: '{domain} — {count} message', other: '{domain} — {count} messages' },
  'rpt.tls.domainOption': { one: '{domain} — {count} TLS session', other: '{domain} — {count} TLS sessions' },
  'rpt.resultsOne': 'Reports for {domain}',
  'rpt.resultsMany': { one: 'Reports for {count} domain', other: 'Reports for {count} domains' },
  'rpt.period': '{from} → {to}',
  'rpt.reportsFrom': { one: '{count} report from {reporters}', other: '{count} reports from {reporters}' },
  'rpt.stat.compliance': 'DMARC compliance',
  'rpt.stat.complianceHint': '{pass} of {total} messages pass',
  'rpt.stat.messages': 'Messages',
  'rpt.stat.sources': 'Sending addresses',
  'rpt.stat.failing': 'Failing DMARC',
  'rpt.stat.failingHint': 'messages neither SPF nor DKIM aligned',
  'rpt.policy': 'Published policy',
  'rpt.verdict.no-mail.title': 'No message in these reports',
  'rpt.verdict.no-mail.body': 'The reports list no mail sent as the domain in this period.',
  'rpt.verdict.enforced.title': 'p=reject is in force',
  'rpt.verdict.enforced.body': 'Every source you use passes DMARC; receivers refuse what fails.',
  'rpt.verdict.enforcedLosing.title': 'p=reject is in force, and mail you send is being refused',
  'rpt.verdict.enforcedLosing.body': { one: '{count} source you use fails DMARC for {messages} messages: receivers refuse that mail now. Fix it first:', other: '{count} sources you use fail DMARC for {messages} messages: receivers refuse that mail now. Fix them first, the most mail first:' },
  'rpt.verdict.ready.title': 'Ready for p=reject',
  'rpt.verdict.ready.body': 'Every source you use passes DMARC. With p=reject, receivers would refuse the {messages} failing messages of unknown senders — which is the point, if none of them is yours.',
  'rpt.verdict.fix-first.title': 'Not ready for p=reject yet',
  'rpt.verdict.fix-first.body': { one: '{count} source you use fails DMARC for {messages} messages. With p=reject, receivers would refuse that mail. Fix it first:', other: '{count} sources you use fail DMARC for {messages} messages. With p=reject, receivers would refuse that mail. Fix them first, the most mail first:' },
  'rpt.verdict.spf-broken.title': 'Not ready for p=reject: the SPF record gives a permanent error',
  'rpt.verdict.spf-broken.body': { one: '{count} source you use passed DMARC through SPF alone ({messages} messages in these reports). Receivers now get a permanent error from the SPF record, so that mail fails DMARC. Repair the record, or sign that mail with DKIM:', other: '{count} sources you use passed DMARC through SPF alone ({messages} messages in these reports). Receivers now get a permanent error from the SPF record, so that mail fails DMARC. Repair the record, or sign that mail with DKIM:' },
  'rpt.verdict.enforcedSpfBroken.title': 'p=reject is in force, and the SPF record now gives a permanent error',
  'rpt.verdict.enforcedSpfBroken.body': { one: '{count} source you use passed DMARC through SPF alone ({messages} messages in these reports). Receivers now get a permanent error from the SPF record, so that mail fails DMARC and p=reject refuses it. Repair the record, or sign that mail with DKIM:', other: '{count} sources you use passed DMARC through SPF alone ({messages} messages in these reports). Receivers now get a permanent error from the SPF record, so that mail fails DMARC and p=reject refuses it. Repair the record, or sign that mail with DKIM:' },
  'rpt.fixFirst': 'Fix first',
  'rpt.fix.failing': '{fail} of {messages} messages fail',
  'rpt.fix.spfOnly': '{count} of {messages} messages passed through SPF alone',
  'rpt.fix.spf-permerror': 'Repair the SPF record of {domain}: receivers get a permanent error from it ({why}), so SPF fails for this address whatever the record lists.',
  'rpt.fix.dkim-sign': 'Sign its mail with DKIM for {domain}: publish the public key under a selector (<selector>._domainkey.{domain}) and turn signing on.',
  'rpt.fix.dkim-align': 'It signs DKIM only as {other}: set up DKIM for {domain} in that service (often called a custom or branded sending domain).',
  'rpt.fix.dkim-fix': 'A DKIM signature for {domain} is there but does not verify: check the selector’s public key in DNS, and that nothing changes the message after signing.',
  'rpt.fix.spf-add': 'Add it to the SPF record of {domain} (ip4: / ip6:, or the service’s include:), within the limit of 10 lookups.',
  'rpt.fix.spf-align': 'SPF passes only for {other}, the return-path it bounces through: use a return-path under {domain}, or rely on DKIM.',
  'rpt.fix.more': { one: '+{count} more source to fix (in the table below)', other: '+{count} more sources to fix (in the table below)' },
  'rpt.unknownLine': { one: '{count} unknown sender, {messages} failing messages: spoofing, or a service nobody has set up yet? Look it up in the table.', other: '{count} unknown senders, {messages} failing messages: spoofing, or services nobody has set up yet? Look them up in the table.' },
  'rpt.note.short-range': { one: 'The reports cover {count} day: a sender that mails once a week or a month may be missing. Collect at least two weeks before p=reject.', other: 'The reports cover {count} days: a sender that mails once a week or a month may be missing. Collect at least two weeks before p=reject.' },
  'rpt.note.pct': 'pct={pct}: the policy applies to part of the failing mail only.',
  'rpt.note.testing': 't=y: the policy is published in test mode, and receivers are asked to apply the next lower one (reject as quarantine, quarantine as none).',
  'rpt.note.mixed-policy': 'The policy changed during this period ({policies}); the latest one is shown.',
  'rpt.note.spf-unknown': 'The current SPF could not be checked: sources the reports saw pass SPF count as yours, and only your server list tells your servers from third parties.',
  'rpt.note.spf-permerror': { one: 'Receivers get a permanent error from the current SPF of {domain} for {count} sending address: {why}. For it SPF fails, whatever the record lists.', other: 'Receivers get a permanent error from the current SPF of {domain} for {count} sending addresses: {why}. For them SPF fails, whatever the record lists.' },
  'rpt.note.quarantine': 'p=quarantine, and every source you use passes: the next step is p=reject.',
  'rpt.note.rejected-now': 'Receivers already rejected mail from sources you use (disposition reject).',
  'rpt.note.spf-all': 'The SPF record passes every address (+all, or a /0 range such as ip4:0.0.0.0/0): it tells no sender apart, and anyone can pass SPF as the domain. List your own servers instead, and end the record with ~all or -all.',
  'rpt.spf.label': 'Current SPF of {domain}',
  'rpt.spf.loading': 'looking up…',
  'rpt.spf.ok': 'checked {time}',
  'rpt.spf.none': 'no SPF record',
  'rpt.spf.multiple': 'several SPF records (a permanent error for receivers)',
  'rpt.spf.failed': 'could not be read ({error})',
  'rpt.spf.offline': 'not checked: the browser is offline',
  'rpt.spf.retry': 'Check again',
  'rpt.spf.broken': 'a permanent error for receivers: {why}',
  'rpt.spfError.syntax': 'a syntax error',
  'rpt.spfError.multiple-records': 'more than one SPF record',
  'rpt.spfError.no-record': 'an include or redirect to a domain without SPF',
  'rpt.spfError.loop': 'an include loop',
  'rpt.spfError.depth': 'includes nested too deep',
  'rpt.spfError.too-many-mx': 'an mx term with more than 10 hosts',
  'rpt.spfError.lookup-limit': 'more than 10 DNS lookups before the address is reached',
  'rpt.spfError.void-limit': 'more than 2 lookups that find nothing',
  'rpt.cls.yours': 'Your servers',
  'rpt.cls.third-party': 'Authorized third parties',
  'rpt.cls.forwarder': 'Forwarders',
  'rpt.cls.unknown': 'Unknown senders',
  'rpt.clsOne.yours': 'Your server',
  'rpt.clsOne.third-party': 'Third party',
  'rpt.clsOne.forwarder': 'Forwarder',
  'rpt.clsOne.unknown': 'Unknown',
  'rpt.clsDesc.yours': 'In your server list, or authorized by the domain’s own SPF terms.',
  'rpt.clsDesc.third-party': 'Authorized by an SPF include of another organisation, or signing with your DKIM from its own bounce domain.',
  'rpt.clsDesc.forwarder': 'DKIM passes, SPF does not: mail forwarded or relayed by a mailing list.',
  'rpt.clsDesc.unknown': 'Nothing authenticates it as the domain: spoofing, or a service not set up yet.',
  'rpt.clsHint': { one: '{count} address · {pct} pass', other: '{count} addresses · {pct} pass' },
  'rpt.clsFilter': 'Show only {cls}',
  'rpt.filterClear': 'Show every class',
  'rpt.sources': 'Sending addresses',
  'rpt.sourcesCaption': 'Sending addresses of {domain}',
  'rpt.col.ip': 'Address',
  'rpt.col.cls': 'Class',
  'rpt.col.messages': 'Messages',
  'rpt.col.pass': 'DMARC pass',
  'rpt.col.spf': 'SPF aligned',
  'rpt.col.dkim': 'DKIM aligned',
  'rpt.col.disposition': 'Applied',
  'rpt.col.why': 'Why',
  'rpt.col.network': 'Network',
  'rpt.aligned.pass': 'pass',
  'rpt.aligned.fail': 'fail',
  'rpt.aligned.part': '{pct} pass',
  'rpt.why.inventory': 'In your server list: {detail}',
  'rpt.why.spf': 'Your SPF authorizes it: {detail}',
  'rpt.why.spf-listed': 'Listed by your SPF ({detail}), but receivers get a permanent error from the record first',
  'rpt.why.spf-report': 'Passed SPF aligned in the reports (the current SPF could not tell)',
  'rpt.why.spf-include': 'Authorized through include:{detail}',
  'rpt.why.include-listed': 'Listed through include:{detail}, but receivers get a permanent error from the record first',
  'rpt.why.dkim-signed': 'Signs with your DKIM, and all its mail passed SPF aligned in the reports',
  'rpt.why.dkim-service': 'Signs with your DKIM, bounces through {detail}',
  'rpt.why.forwarded': 'The receiver says it was forwarded ({detail})',
  'rpt.why.dkim-forwarded': 'Carries the DKIM signature your senders make (selector {detail}): forwarded mail',
  'rpt.why.dkim-only': 'DKIM passes, SPF does not: forwarded or relayed mail',
  'rpt.why.spf-removed': 'Passed SPF in the reports, but the current SPF no longer authorizes it ({detail})',
  'rpt.why.foreign': 'Authenticates only as {detail}',
  'rpt.why.none': 'Neither SPF nor DKIM authenticates it as the domain',
  'rpt.det.headerFrom': 'Header From',
  'rpt.det.envelopeFrom': 'Envelope From',
  'rpt.det.spfAuth': 'SPF checks',
  'rpt.det.dkimAuth': 'DKIM signatures',
  'rpt.det.overrides': 'Policy overrides',
  'rpt.det.spfNow': 'Current SPF',
  'rpt.det.reporters': 'Reported by',
  'rpt.det.seen': 'Seen',
  'rpt.det.fixes': 'To fix',
  'rpt.det.ptr': 'Reverse DNS',
  'rpt.det.network': 'Network',
  'rpt.det.openIp': 'Open in IP Intel',
  'rpt.det.notChecked': 'not checked',
  'rpt.det.count': { one: '{count} message', other: '{count} messages' },
  'rpt.spfNow.pass': 'pass',
  'rpt.spfNow.fail': 'fail',
  'rpt.spfNow.softfail': 'softfail',
  'rpt.spfNow.neutral': 'neutral',
  'rpt.spfNow.none': 'no SPF record',
  'rpt.spfNow.permerror': 'permanent error',
  'rpt.spfNow.temperror': 'temporary error',
  'rpt.spfNow.unknown': 'cannot tell from here',
  'rpt.spfNow.by': '{result} by {term} in {holder}',
  'rpt.spfUnknown.macro': 'a macro that needs the sender',
  'rpt.spfUnknown.ptr': 'a ptr mechanism',
  'rpt.spfUnknown.lookup-failed': 'a lookup that failed here',
  'rpt.spfUnknown.skipped': 'the query cap stopped it',
  'rpt.intel.one': 'Look up',
  'rpt.intel.oneLabel': 'Look up the reverse DNS and network of {ip}',
  'rpt.intel.private': 'private',
  'rpt.intel.bulk': { one: 'Look up {count} address', other: 'Look up {count} addresses' },
  'rpt.intel.bulkTitle': 'Reverse DNS and network (RIPEstat, ipwho.is) of the addresses shown that are not looked up yet, at most {max} per click',
  'rpt.intel.done': { one: 'Looked up {count} address', other: 'Looked up {count} addresses' },
  'rpt.intel.none': 'none',
  'rpt.reporters': 'Reporters',
  'rpt.rep.org': 'Reporter',
  'rpt.rep.reports': 'Reports',
  'rpt.rep.messages': 'Messages',
  'rpt.rep.pass': 'DMARC pass',
  'rpt.rep.period': 'Period',
  'rpt.errors': 'The reporters noted',
  'rpt.skipped': { one: '{count} record in the reports could not be read (no address or count)', other: '{count} records in the reports could not be read (no address or count)' },
  'rpt.tls.stat.rate': 'TLS success',
  'rpt.tls.stat.rateHint': '{ok} of {total} sessions',
  'rpt.tls.stat.sessions': 'Sessions',
  'rpt.tls.stat.failed': 'Failed sessions',
  'rpt.tls.stat.senders': 'Sending organisations',
  'rpt.tls.policies': 'Policies the senders found',
  'rpt.tls.policy.sts': 'MTA-STS',
  'rpt.tls.policy.tlsa': 'DANE (TLSA)',
  'rpt.tls.policy.no-policy-found': 'No MTA-STS or DANE policy',
  'rpt.tls.policySessions': '{ok} succeeded · {failed} failed',
  'rpt.tls.allOk': 'Every reported TLS session succeeded.',
  'rpt.tls.noSessions': 'The reports list no TLS session.',
  'rpt.tls.failTitle': 'Failures by type',
  'rpt.tls.typeFacts': { one: '{count} failed session · MX {mx} · reported by {orgs}', other: '{count} failed sessions · MX {mx} · reported by {orgs}' },
  'rpt.tls.reasons': 'Reason given: {reasons}',
  'rpt.tls.type.starttls-not-supported': 'STARTTLS not offered',
  'rpt.tls.type.certificate-host-mismatch': 'Certificate does not name the MX host',
  'rpt.tls.type.certificate-expired': 'Certificate expired',
  'rpt.tls.type.certificate-not-trusted': 'Certificate not trusted',
  'rpt.tls.type.validation-failure': 'Certificate chain did not validate',
  'rpt.tls.type.tlsa-invalid': 'TLSA records do not match',
  'rpt.tls.type.dnssec-invalid': 'TLSA records failed DNSSEC',
  'rpt.tls.type.dane-required': 'DANE required, no usable TLSA record',
  'rpt.tls.type.sts-policy-fetch-error': 'MTA-STS policy could not be fetched',
  'rpt.tls.type.sts-policy-invalid': 'MTA-STS policy is invalid',
  'rpt.tls.type.sts-webpki-invalid': 'The MTA-STS host’s certificate is invalid',
  'rpt.tls.type.other': 'Another failure',
  'rpt.tls.advice.starttls-not-supported': 'The MX host did not offer STARTTLS, or the connection was cut before it. Check that the mail server advertises STARTTLS on port 25 — backup MX hosts too — and that no firewall or proxy strips it.',
  'rpt.tls.advice.certificate-host-mismatch': 'The MX host’s certificate does not name the host senders connect to. Install one whose names include every MX host name: MTA-STS and DANE senders check it.',
  'rpt.tls.advice.certificate-expired': 'The MX host served an expired certificate. Renew it and restart or reload the mail server so it serves the new one.',
  'rpt.tls.advice.certificate-not-trusted': 'The certificate is not signed by a CA the sender trusts (self-signed or a private CA). MTA-STS needs a publicly trusted certificate.',
  'rpt.tls.advice.validation-failure': 'The certificate chain could not be validated, most often a missing intermediate. Serve the full chain on port 25.',
  'rpt.tls.advice.tlsa-invalid': 'The TLSA records match neither the certificate nor its key. Publish the record of the certificate the server serves, wait two TTLs, then remove the old one.',
  'rpt.tls.advice.dnssec-invalid': 'The TLSA records did not validate with DNSSEC. Check the zone’s DNSSEC chain: the DS at the parent and the signatures.',
  'rpt.tls.advice.dane-required': 'The sender requires DANE, but the MX host has no usable TLSA record.',
  'rpt.tls.advice.sts-policy-fetch-error': 'The sender could not fetch https://mta-sts.{domain}/.well-known/mta-sts.txt: no answer, an HTTP error or a certificate problem on that host.',
  'rpt.tls.advice.sts-policy-invalid': 'The MTA-STS policy file could not be read: check its version, mode, max_age and mx lines.',
  'rpt.tls.advice.sts-webpki-invalid': 'The certificate of mta-sts.{domain} failed validation: senders then ignore the policy.',
  'rpt.tls.advice.other': 'A result type this page does not know; the reporter’s own reason is below.',
  'rpt.tls.tool.health': 'Check MTA-STS in Domain Health',
  'rpt.tls.tool.tlsa': 'TLSA records of {mx}',
  'rpt.tls.tool.cert': 'Certificate of {mx} (DANE / TLSA tab)',
  'rpt.tls.failures': 'Failure details',
  'rpt.tls.failuresCaption': 'TLS failures of {domain}',
  'rpt.tls.col.type': 'Result',
  'rpt.tls.col.mx': 'MX host',
  'rpt.tls.col.rip': 'Receiving IP',
  'rpt.tls.col.org': 'Sender',
  'rpt.tls.col.sip': 'Sending MTA',
  'rpt.tls.col.sessions': 'Sessions',
  'rpt.tls.col.reason': 'Reason code',
  'rpt.tls.col.policy': 'Policy',
  'rpt.tls.senders': 'Sending organisations',
  'rpt.tls.col.ok': 'Succeeded',
  'rpt.tls.col.failed': 'Failed',
  'rpt.col.service': 'Service',
  'rpt.view.label': 'Show the sending addresses',
  'rpt.view.address': 'By address',
  'rpt.view.service': 'By service',
  'rpt.svc.none': 'not identified',
  'rpt.svc.noneTitle': 'Neither the reports nor its reverse DNS name the service behind this address.',
  'rpt.svc.unchecked': 'Not named by the reports: Identify senders looks up its reverse DNS.',
  'rpt.svc.yours': 'Your own server: Identify senders leaves it out.',
  'rpt.svc.private': 'A private address: Identify senders leaves it out.',
  'rpt.svc.unconfirmed': 'not confirmed',
  'rpt.svcType.mailbox': 'Mailbox provider',
  'rpt.svcType.security': 'Email security',
  'rpt.svcType.forwarding': 'Forwarding',
  'rpt.svcType.transactional': 'Transactional email',
  'rpt.svcType.marketing': 'Email marketing',
  'rpt.svcType.saas': 'Software service',
  'rpt.svcType.cloud': 'Cloud platform',
  'rpt.svcType.hosting': 'Web hosting',
  'rpt.svcType.msp': 'Managed IT provider',
  'rpt.svcType.technology': 'Technology company',
  'rpt.svcType.isp': 'ISP or home network',
  'rpt.svcType.network': 'Network',
  'rpt.svcVia.dkim': 'DKIM',
  'rpt.svcVia.return-path': 'return-path',
  'rpt.svcVia.spf-include': 'SPF include',
  'rpt.svcVia.ptr': 'reverse DNS',
  'rpt.svcVia.isp': 'reverse DNS',
  'rpt.svcVia.asn': 'RIPEstat',
  'rpt.svcHow.dkim': 'Named from its DKIM signature, which verified: d={detail}',
  'rpt.svcHow.return-path': 'Named from its return-path, which passed SPF: {detail}',
  'rpt.svcHow.spf-include': 'Named from your SPF, which authorizes it through {detail}',
  'rpt.svcHow.ptr': 'Named from its reverse DNS: {detail}',
  'rpt.svcHow.isp': 'An ISP or home network by its reverse DNS ({detail}): spoofing, or a user forwarding their own mail',
  'rpt.svcHow.asn': 'Only its network is known: {detail}',
  'rpt.svcHow.confirmed': 'the name resolves back to the address',
  'rpt.svcHow.unconfirmed': 'the name does not resolve back to the address, so this is a hint only',
  'rpt.guide.microsoft365': 'Microsoft 365: turn on DKIM for {domain} in the Microsoft Defender portal (Email authentication settings) and publish the selector1 and selector2 CNAMEs it shows; keep include:spf.protection.outlook.com in SPF.',
  'rpt.guide.google': 'Google Workspace: in the Admin console (Apps › Google Workspace › Gmail › Authenticate email) generate a DKIM key for {domain}, publish it as the google._domainkey TXT record and start authentication; keep include:_spf.google.com in SPF.',
  'rpt.guide.amazonses': 'Amazon SES: verify {domain} with Easy DKIM (three CNAMEs to dkim.amazonses.com) and set a custom MAIL FROM domain, a subdomain of {domain} with its MX and SPF records, so SPF aligns too.',
  'rpt.guide.sendgrid': 'SendGrid: authenticate {domain} under Settings › Sender Authentication and publish the CNAMEs it gives: DKIM then signs as {domain} and the return-path is a subdomain of it.',
  'rpt.guide.mailchimp': 'Mailchimp: authenticate {domain} under Domains and publish the k2 and k3 DKIM CNAMEs (to dkim2.mcsv.net and dkim3.mcsv.net).',
  'rpt.guide.mandrill': 'Mailchimp Transactional (Mandrill): add {domain} as a sending domain, publish its DKIM CNAMEs and set a custom return-path domain under {domain}.',
  'rpt.guide.mailgun': 'Mailgun: send from a domain verified in Mailgun, such as mg.{domain} with its DKIM TXT and its MX and SPF records; the return-path then stays under {domain}.',
  'rpt.guide.postmark': 'Postmark: verify {domain} (its DKIM TXT record) and add the Return-Path CNAME (pm-bounces.{domain} to pm.mtasv.net) so SPF aligns too.',
  'rpt.guide.sparkpost': 'SparkPost: verify {domain} as a sending domain (its DKIM TXT record) and add a bounce domain under {domain} (a CNAME to sparkpostmail.com).',
  'rpt.guide.brevo': 'Brevo: authenticate {domain} under Senders, domains & dedicated IPs and publish the DKIM records and the brevo-code TXT record it gives.',
  'rpt.guide.salesforce': 'Salesforce: create a DKIM key for {domain} (Setup › DKIM Keys), publish the two CNAMEs it shows, then activate the key.',
  'rpt.guide.hubspot': 'HubSpot: connect {domain} as an email sending domain (Settings › Domains & URLs) and publish the DKIM CNAMEs it gives.',
  'rpt.guide.zendesk': 'Zendesk: turn on digital signatures for {domain} (the zendesk1 and zendesk2 DKIM CNAMEs) and keep include:mail.zendesk.com in SPF.',
  'rpt.guide.mailbox': '{service} hosts mailboxes. Turn on DKIM signing for {domain} in its admin settings, publish the record it gives and keep its SPF include.',
  'rpt.guide.security': '{service} filters mail on its way out. Keep its SPF include, and have it sign DKIM as {domain} or pass your own signature through unchanged.',
  'rpt.guide.forwarding': '{service} forwards mail. Forwarding breaks SPF; mail stays aligned when it carries a DKIM signature of {domain} that survives the relay.',
  'rpt.guide.transactional': '{service} sends mail for your applications. Authenticate {domain} in it: DKIM as {domain} (the records it gives) and a custom return-path (bounce) domain under {domain}, so SPF aligns too.',
  'rpt.guide.marketing': '{service} sends your campaigns. Authenticate {domain} in it so DKIM signs as {domain} (the records it gives), and use a custom return-path where it offers one.',
  'rpt.guide.saas': '{service} sends mail as you. Look for its email or sender domain settings: DKIM for {domain} (often CNAME records) and, where it offers one, a custom return-path.',
  'rpt.guide.cloud': 'A server in {service}’s cloud. If it is yours, authorize its address in SPF and sign its mail with DKIM for {domain}; if not, it is spoofing.',
  'rpt.guide.hosting': 'A server at {service}, a web host: often a site’s contact form or a script. Send through your mail service over SMTP instead, or authorize the server in SPF and sign its mail with DKIM for {domain}.',
  'rpt.guide.msp': 'A server of {service}, a managed IT provider. Ask them what sends as {domain} from there, then authorize it in SPF and sign it with DKIM.',
  'rpt.guide.technology': 'Mail from {service}’s own servers. If you use one of its services, set up its domain authentication for {domain}; if not, it is spoofing.',
  'rpt.guide.isp': 'An ISP or home network: spoofing, or a user forwarding their own mail. Nothing to authorize; p=reject turns spoofed mail away.',
  'rpt.guide.network': 'Only the network is known ({service}). If no server of yours is there, this is spoofing; p=reject turns it away.',
  'rpt.guide.forwarded': 'Forwarded mail: a mailbox or a mailing list relayed messages of {domain} to another address. Forwarding breaks SPF; mail stays aligned when it carries a DKIM signature of {domain} that survives the relay. Nothing to authorize: sign all your mail with DKIM.',
  'rpt.guide.authorized': 'An authorized sender ({service}): have it sign its mail with DKIM as {domain} and, where it can, use a return-path under {domain}, so SPF aligns too.',
  'rpt.det.service': 'Service',
  'rpt.det.serviceHow': 'How it was named',
  'rpt.det.guide': 'To align it',
  'rpt.ptrState.confirmed': '{name} (resolves back to the address)',
  'rpt.ptrState.mismatch': '{name} (does not resolve back to the address)',
  'rpt.ptrState.no-ptr': 'no reverse name',
  'rpt.ptrState.nxdomain': 'no reverse name',
  'rpt.ptrState.servfail': 'the reverse zone did not answer (SERVFAIL)',
  'rpt.ptrState.error': 'could not be looked up',
  'rpt.id.bulk': { one: 'Identify {count} sender', other: 'Identify {count} senders' },
  'rpt.id.bulkTitle': 'Looks up the reverse DNS of up to {max} sending addresses that no report names (not your own servers), over your DoH resolvers, checks that each name points back to its address and matches it against the sender lists this site bundles; then the network (RIPEstat, ipwho.is) of at most {intel} still unnamed.',
  'rpt.id.busy': 'Identifying… {done} / {total}',
  'rpt.id.started': { one: 'Identifying {count} sender…', other: 'Identifying {count} senders…' },
  'rpt.id.done': { one: 'Identified {named} of {count} sender.', other: 'Identified {named} of {count} senders.' },
  'rpt.id.mapsFailed': 'The sender lists this site bundles could not be loaded ({error}): only the services DomainScope knows itself were matched.',
  'rpt.grp.caption': 'Senders of {domain} by service',
  'rpt.grp.col.addresses': 'Addresses',
  'rpt.grp.col.classes': 'Classes',
  'rpt.grp.isp': 'ISP or home networks',
  'rpt.grp.unnamed': 'Not identified',
  'rpt.grp.unnamedHint': 'Neither the reports nor a reverse DNS lookup name these addresses yet. Identify senders looks them up; what stays unknown and fails DMARC is most likely spoofing.',
  'rpt.grp.services': { one: '{count} service', other: '{count} services' },
  'rpt.grp.addresses': { one: '{count} address', other: '{count} addresses' },
  'rpt.grp.unnamedLine': { one: '{count} address not identified ({messages})', other: '{count} addresses not identified ({messages})' },
  'rpt.grp.via': 'Named from',
  'rpt.grp.evidence': 'Evidence',
  'rpt.grp.list': 'Addresses'
});

registerStrings('tr', {
  'rpt.privacyTitle': 'Her şey bu tarayıcıda kalır',
  'rpt.privacy': 'Rapor dosyaları burada okunur ve açılır; hiçbir yere yüklenmez ya da kaydedilmez: sayfayı yenilemek, Unut ya da “Tüm yerel verileri sil” onları siler. Sunucularınızı üçüncü taraflardan ayırmak için sayfa ardından raporlanan her alan adının güncel SPF kaydını DoH çözümleyicileriniz üzerinden sorgular (yalnızca alan adları); bir adresin ters DNS ve ağ bilgisi ise yalnızca Sorgula’ya ya da Göndericileri tanımla’ya bastığınızda sorulur.',
  'rpt.drop.title': 'DMARC ve TLS raporlarını buraya bırakın ya da seçin',
  'rpt.drop.more': 'Daha fazla rapor ekleyin',
  'rpt.drop.hint': 'Aynı anda en fazla {max} dosya: .xml, .xml.gz, .zip (zip’lenmiş bir posta klasörü de), .json, .json.gz',
  'rpt.choose': 'Dosya seçin',
  'rpt.folder': 'Klasör seçin',
  'rpt.forget': 'Raporları unut',
  'rpt.forgotten': 'Raporlar unutuldu.',
  'rpt.busy': 'Raporlar okunuyor…',
  'rpt.reading': '{count} dosya okunuyor…',
  'rpt.queued': 'Sırada {count} dosya daha var; ardından okunacak.',
  'rpt.stop': 'Okumayı durdur',
  'rpt.stopped': 'Okuma durduruldu.',
  'rpt.stoppedKept': 'Okuma durduruldu. O ana kadar okunan {count} rapor korundu.',
  'rpt.stoppedNone': 'Okuma durduruldu. Henüz hiçbir rapor okunmamıştı.',
  'rpt.loaded': 'Okundu: {dmarc} DMARC ve {tls} TLS raporu',
  'rpt.noneRead': 'Bu dosyalarda DMARC ya da TLS raporu yok.',
  'rpt.kept': 'Raporlar {time} okundu',
  'rpt.count.files': '{count} dosya',
  'rpt.count.dmarc': '{count} DMARC raporu',
  'rpt.count.tls': '{count} TLS raporu',
  'rpt.count.duplicates': 'iki kez bırakılan {count} rapor bir kez sayıldı',
  'rpt.count.problems': '{count} tanesi kullanılamadı',
  'rpt.problems': 'Kullanılamayanlar',
  'rpt.problem.not-zip': 'zip arşivi değil',
  'rpt.problem.truncated': 'dosya eksik (yarım kalmış bir indirme mi?)',
  'rpt.problem.multi-disk': 'birden çok dosyaya bölünmüş bir zip',
  'rpt.problem.encrypted': 'şifreli (parola korumalı) bir girdi',
  'rpt.problem.method': 'tarayıcıların açamadığı bir yöntemle sıkıştırılmış ({detail})',
  'rpt.problem.crc': 'bozuk: sağlama toplamı tutmuyor',
  'rpt.problem.too-large': 'burada okunamayacak kadar büyük',
  'rpt.problem.too-many': 'bir bırakmada okunandan fazla girdi ({detail})',
  'rpt.problem.corrupt': 'bozuk: açılamadı',
  'rpt.problem.overlap': 'baytlarını paylaşan girdiler: tuttuğundan çok daha fazlasını açmak için yapılmış bir arşiv',
  'rpt.problem.nested': 'arşiv içinde arşiv içinde arşiv: önce açın',
  'rpt.problem.unsupported': 'bu tarayıcı açamıyor',
  'rpt.problem.not-report': 'ne DMARC ne de TLS raporu',
  'rpt.problem.xml': 'okunamayan XML ({detail})',
  'rpt.problem.not-dmarc': 'XML, ama DMARC toplu raporu değil',
  'rpt.problem.incomplete': '{detail} bölümü olmayan bir rapor',
  'rpt.problem.not-json': 'okunamayan JSON',
  'rpt.problem.not-tlsrpt': 'JSON, ama TLS raporu değil',
  'rpt.problem.empty': 'boş bir dosya',
  'rpt.emptyTitle': 'Alan adınıza gelen raporları okuyun',
  'rpt.emptyBody': 'Google ve Microsoft gibi alıcılar her gün bir DMARC toplu raporu (rua), MX sunucularınıza kurulan TLS oturumları hakkında da TLS-RPT raporları gönderir. Onları buraya bırakın — aynı anda birden çok, zip’li ya da değil — adınıza kimlerin e-posta gönderdiğini, neyin geçmediğini ve p=reject’ten önce neyi düzeltmeniz gerektiğini görün.',
  'rpt.tab.dmarc': 'DMARC',
  'rpt.tab.tls': 'TLS-RPT',
  'rpt.tabs': 'Rapor türleri',
  'rpt.domain': 'Alan adı',
  'rpt.domainOption': '{domain} — {count} e-posta',
  'rpt.tls.domainOption': '{domain} — {count} TLS oturumu',
  'rpt.resultsOne': '{domain} raporları',
  'rpt.resultsMany': '{count} alan adının raporları',
  'rpt.period': '{from} → {to}',
  'rpt.reportsFrom': '{reporters} kaynağından {count} rapor',
  'rpt.stat.compliance': 'DMARC uyumu',
  'rpt.stat.complianceHint': '{total} e-postanın {pass} tanesi geçiyor',
  'rpt.stat.messages': 'E-postalar',
  'rpt.stat.sources': 'Gönderen adresler',
  'rpt.stat.failing': 'DMARC’den geçmeyen',
  'rpt.stat.failingHint': 'ne SPF ne DKIM ile hizalı geçen e-posta',
  'rpt.policy': 'Yayınlanan politika',
  'rpt.verdict.no-mail.title': 'Bu raporlarda e-posta yok',
  'rpt.verdict.no-mail.body': 'Raporlar bu dönemde alan adı adına gönderilmiş bir e-posta listelemiyor.',
  'rpt.verdict.enforced.title': 'p=reject yürürlükte',
  'rpt.verdict.enforced.body': 'Kullandığınız her kaynak DMARC’den geçiyor; alıcılar geçmeyenleri reddediyor.',
  'rpt.verdict.enforcedLosing.title': 'p=reject yürürlükte ve gönderdiğiniz e-postalar reddediliyor',
  'rpt.verdict.enforcedLosing.body': 'Kullandığınız {count} kaynak {messages} e-postada DMARC’den geçmiyor: alıcılar geçmeyen e-postayı şu anda reddediyor. Önce düzeltin (en çok e-posta gönderen başta):',
  'rpt.verdict.ready.title': 'p=reject için hazır',
  'rpt.verdict.ready.body': 'Kullandığınız her kaynak DMARC’den geçiyor. p=reject ile alıcılar bilinmeyen göndericilerin geçmeyen {messages} e-postasını reddeder — hiçbiri sizin değilse amaç da budur.',
  'rpt.verdict.fix-first.title': 'Henüz p=reject için hazır değil',
  'rpt.verdict.fix-first.body': 'Kullandığınız {count} kaynak {messages} e-postada DMARC’den geçmiyor. p=reject ile alıcılar geçmeyen e-postayı reddederdi. Önce düzeltin (en çok e-posta gönderen başta):',
  'rpt.verdict.spf-broken.title': 'Henüz p=reject için hazır değil: SPF kaydı kalıcı hata veriyor',
  'rpt.verdict.spf-broken.body': 'Kullandığınız {count} kaynağın e-postası DMARC’den yalnızca SPF ile geçti (bu raporlarda {messages} e-posta). Alıcılar artık SPF kaydından kalıcı hata alıyor: SPF ile geçen e-posta bundan sonra DMARC’den geçmiyor. Kaydı onarın ya da o e-postayı DKIM ile imzalayın:',
  'rpt.verdict.enforcedSpfBroken.title': 'p=reject yürürlükte ve SPF kaydı artık kalıcı hata veriyor',
  'rpt.verdict.enforcedSpfBroken.body': 'Kullandığınız {count} kaynağın e-postası DMARC’den yalnızca SPF ile geçti (bu raporlarda {messages} e-posta). Alıcılar artık SPF kaydından kalıcı hata alıyor: SPF ile geçen e-posta DMARC’den geçmiyor ve p=reject ile reddediliyor. Kaydı onarın ya da o e-postayı DKIM ile imzalayın:',
  'rpt.fixFirst': 'Önce düzeltin',
  'rpt.fix.failing': '{messages} e-postanın {fail} tanesi geçmiyor',
  'rpt.fix.spfOnly': '{messages} e-postanın {count} tanesi yalnızca SPF ile geçti',
  'rpt.fix.spf-permerror': '{domain} SPF kaydını onarın: alıcılar ondan kalıcı hata alıyor ({why}); bu yüzden kayıt ne listelerse listelesin bu adres için SPF geçmiyor.',
  'rpt.fix.dkim-sign': 'E-postalarını {domain} için DKIM ile imzalayın: genel anahtarı bir seçici altında yayınlayın (<seçici>._domainkey.{domain}) ve imzalamayı açın.',
  'rpt.fix.dkim-align': 'DKIM’i yalnızca {other} olarak imzalıyor: o hizmette {domain} için DKIM kurun (çoğunlukla özel ya da markalı gönderim alan adı diye geçer).',
  'rpt.fix.dkim-fix': '{domain} için bir DKIM imzası var ama doğrulanmıyor: seçicinin DNS’teki genel anahtarını ve imzadan sonra iletinin değiştirilmediğini kontrol edin.',
  'rpt.fix.spf-add': 'Adresi {domain} SPF kaydına ekleyin (ip4: / ip6: ya da hizmetin include: terimi), 10 sorgu sınırını aşmadan.',
  'rpt.fix.spf-align': 'SPF yalnızca geri dönüşlerin geçtiği return-path olan {other} için geçiyor: {domain} altında bir return-path kullanın ya da DKIM’e güvenin.',
  'rpt.fix.more': 'düzeltilecek +{count} kaynak daha (aşağıdaki tabloda)',
  'rpt.unknownLine': '{count} bilinmeyen gönderici, geçmeyen {messages} e-posta: sahte gönderim mi, yoksa henüz kimsenin kurmadığı bir hizmet mi? Tabloda sorgulayın.',
  'rpt.note.short-range': 'Raporlar {count} günü kapsıyor: haftada ya da ayda bir gönderen bir kaynak eksik olabilir. p=reject’ten önce en az iki haftalık rapor toplayın.',
  'rpt.note.pct': 'pct={pct}: politika geçmeyen e-postaların yalnızca bir kısmına uygulanıyor.',
  'rpt.note.testing': 't=y: politika test kipinde yayınlanmış; alıcılardan bir alt düzeyi uygulamaları isteniyor (reject yerine quarantine, quarantine yerine none).',
  'rpt.note.mixed-policy': 'Politika bu dönemde değişti ({policies}); en son olanı gösteriliyor.',
  'rpt.note.spf-unknown': 'Güncel SPF kontrol edilemedi: raporlarda SPF’ten geçen kaynaklar sizin sayılır ve sunucularınızı üçüncü taraflardan yalnızca sunucu listeniz ayırır.',
  'rpt.note.spf-permerror': 'Alıcılar {domain} alan adının güncel SPF kaydından {count} gönderen adres için kalıcı hata alıyor: {why}. Kayıt ne listelerse listelesin SPF geçmiyor.',
  'rpt.note.quarantine': 'p=quarantine ve kullandığınız her kaynak geçiyor: sıradaki adım p=reject.',
  'rpt.note.rejected-now': 'Alıcılar kullandığınız kaynaklardan gelen e-postaları zaten reddetti (disposition reject).',
  'rpt.note.spf-all': 'SPF kaydı her adresi geçiriyor (+all ya da ip4:0.0.0.0/0 gibi bir /0 aralığı): hiçbir göndericiyi ayırt etmez ve herkes alan adı olarak SPF’ten geçebilir. Bunun yerine kendi sunucularınızı listeleyin ve kaydı ~all ya da -all ile bitirin.',
  'rpt.spf.label': '{domain} alan adının güncel SPF kaydı',
  'rpt.spf.loading': 'sorgulanıyor…',
  'rpt.spf.ok': '{time} kontrol edildi',
  'rpt.spf.none': 'SPF kaydı yok',
  'rpt.spf.multiple': 'birden çok SPF kaydı (alıcılar için kalıcı hata)',
  'rpt.spf.failed': 'okunamadı ({error})',
  'rpt.spf.offline': 'kontrol edilmedi: tarayıcı çevrimdışı',
  'rpt.spf.retry': 'Yeniden kontrol et',
  'rpt.spf.broken': 'alıcılar için kalıcı hata: {why}',
  'rpt.spfError.syntax': 'bir sözdizimi hatası',
  'rpt.spfError.multiple-records': 'birden çok SPF kaydı',
  'rpt.spfError.no-record': 'SPF kaydı olmayan bir alan adına include ya da redirect',
  'rpt.spfError.loop': 'bir include döngüsü',
  'rpt.spfError.depth': 'çok derin iç içe include’lar',
  'rpt.spfError.too-many-mx': '10’dan fazla sunucusu olan bir mx terimi',
  'rpt.spfError.lookup-limit': 'adrese ulaşmadan önce 10’dan fazla DNS sorgusu',
  'rpt.spfError.void-limit': 'hiçbir şey bulamayan 2’den fazla sorgu',
  'rpt.cls.yours': 'Sunucularınız',
  'rpt.cls.third-party': 'Yetkili üçüncü taraflar',
  'rpt.cls.forwarder': 'Yönlendiren sunucular',
  'rpt.cls.unknown': 'Bilinmeyen göndericiler',
  'rpt.clsOne.yours': 'Sunucunuz',
  'rpt.clsOne.third-party': 'Üçüncü taraf',
  'rpt.clsOne.forwarder': 'Yönlendiren',
  'rpt.clsOne.unknown': 'Bilinmeyen',
  'rpt.clsDesc.yours': 'Sunucu listenizde ya da alan adının kendi SPF terimleriyle yetkili.',
  'rpt.clsDesc.third-party': 'Başka bir kuruluşun SPF include’u ile yetkili ya da kendi geri dönüş alan adından DKIM’inizle imzalıyor.',
  'rpt.clsDesc.forwarder': 'DKIM geçiyor, SPF geçmiyor: yönlendirilen ya da bir e-posta listesinin aktardığı e-posta.',
  'rpt.clsDesc.unknown': 'Hiçbir şey onu alan adı olarak doğrulamıyor: sahte gönderim ya da henüz kurulmamış bir hizmet.',
  'rpt.clsHint': '{count} adres · {pct} geçiyor',
  'rpt.clsFilter': 'Yalnızca bu sınıfı göster: {cls}',
  'rpt.filterClear': 'Her sınıfı göster',
  'rpt.sources': 'Gönderen adresler',
  'rpt.sourcesCaption': '{domain} alan adının gönderen adresleri',
  'rpt.col.ip': 'Adres',
  'rpt.col.cls': 'Sınıf',
  'rpt.col.messages': 'E-posta',
  'rpt.col.pass': 'DMARC geçen',
  'rpt.col.spf': 'Hizalı SPF',
  'rpt.col.dkim': 'Hizalı DKIM',
  'rpt.col.disposition': 'Uygulanan',
  'rpt.col.why': 'Neden',
  'rpt.col.network': 'Ağ',
  'rpt.aligned.pass': 'geçti',
  'rpt.aligned.fail': 'geçmedi',
  'rpt.aligned.part': '{pct} geçti',
  'rpt.why.inventory': 'Sunucu listenizde: {detail}',
  'rpt.why.spf': 'SPF kaydınız yetkilendiriyor: {detail}',
  'rpt.why.spf-listed': 'SPF kaydınızda listeli ({detail}), ama alıcılar önce kayıttan kalıcı hata alıyor',
  'rpt.why.spf-report': 'Raporlarda hizalı SPF’ten geçti (güncel SPF bunu söyleyemedi)',
  'rpt.why.spf-include': 'include:{detail} üzerinden yetkili',
  'rpt.why.include-listed': 'include:{detail} üzerinden listeli, ama alıcılar önce kayıttan kalıcı hata alıyor',
  'rpt.why.dkim-signed': 'DKIM’inizle imzalıyor ve tüm e-postaları raporlarda hizalı SPF’ten geçti',
  'rpt.why.dkim-service': 'DKIM’inizle imzalıyor, geri dönüşler {detail} üzerinden',
  'rpt.why.forwarded': 'Alıcı yönlendirildiğini bildiriyor ({detail})',
  'rpt.why.dkim-forwarded': 'Göndericilerinizin attığı DKIM imzasını taşıyor (seçici {detail}): yönlendirilmiş e-posta',
  'rpt.why.dkim-only': 'DKIM geçiyor, SPF geçmiyor: yönlendirilmiş ya da aktarılmış e-posta',
  'rpt.why.spf-removed': 'Raporlarda SPF’ten geçti, ama güncel SPF artık yetkilendirmiyor ({detail})',
  'rpt.why.foreign': 'Yalnızca {detail} olarak doğrulanıyor',
  'rpt.why.none': 'Ne SPF ne DKIM onu alan adı olarak doğruluyor',
  'rpt.det.headerFrom': 'Header From',
  'rpt.det.envelopeFrom': 'Envelope From',
  'rpt.det.spfAuth': 'SPF kontrolleri',
  'rpt.det.dkimAuth': 'DKIM imzaları',
  'rpt.det.overrides': 'Politika istisnaları',
  'rpt.det.spfNow': 'Güncel SPF',
  'rpt.det.reporters': 'Raporlayan',
  'rpt.det.seen': 'Görüldüğü dönem',
  'rpt.det.fixes': 'Düzeltmek için',
  'rpt.det.ptr': 'Ters DNS',
  'rpt.det.network': 'Ağ',
  'rpt.det.openIp': 'IP Bilgisi’nde aç',
  'rpt.det.notChecked': 'kontrol edilmedi',
  'rpt.det.count': '{count} e-posta',
  'rpt.spfNow.pass': 'geçti (pass)',
  'rpt.spfNow.fail': 'geçmedi (fail)',
  'rpt.spfNow.softfail': 'softfail',
  'rpt.spfNow.neutral': 'neutral',
  'rpt.spfNow.none': 'SPF kaydı yok',
  'rpt.spfNow.permerror': 'kalıcı hata (permerror)',
  'rpt.spfNow.temperror': 'geçici hata (temperror)',
  'rpt.spfNow.unknown': 'buradan anlaşılamıyor',
  'rpt.spfNow.by': '{holder} içindeki {term} ile {result}',
  'rpt.spfUnknown.macro': 'göndericiye bağlı bir makro',
  'rpt.spfUnknown.ptr': 'bir ptr mekanizması',
  'rpt.spfUnknown.lookup-failed': 'burada başarısız olan bir sorgu',
  'rpt.spfUnknown.skipped': 'sorgu sınırı durdurdu',
  'rpt.intel.one': 'Sorgula',
  'rpt.intel.oneLabel': '{ip} için ters DNS ve ağ bilgisini sorgula',
  'rpt.intel.private': 'özel',
  'rpt.intel.bulk': '{count} adresi sorgula',
  'rpt.intel.bulkTitle': 'Gösterilen ve henüz sorgulanmamış adreslerin ters DNS ve ağ bilgisi (RIPEstat, ipwho.is), tıklama başına en fazla {max}',
  'rpt.intel.done': '{count} adres sorgulandı',
  'rpt.intel.none': 'yok',
  'rpt.reporters': 'Rapor gönderenler',
  'rpt.rep.org': 'Raporlayan',
  'rpt.rep.reports': 'Rapor',
  'rpt.rep.messages': 'E-posta',
  'rpt.rep.pass': 'DMARC geçen',
  'rpt.rep.period': 'Dönem',
  'rpt.errors': 'Raporlayanların notları',
  'rpt.skipped': 'Raporlardaki {count} kayıt okunamadı (adres ya da sayı yok)',
  'rpt.tls.stat.rate': 'TLS başarısı',
  'rpt.tls.stat.rateHint': '{total} oturumun {ok} tanesi',
  'rpt.tls.stat.sessions': 'Oturumlar',
  'rpt.tls.stat.failed': 'Başarısız oturumlar',
  'rpt.tls.stat.senders': 'Gönderen kuruluşlar',
  'rpt.tls.policies': 'Göndericilerin bulduğu politikalar',
  'rpt.tls.policy.sts': 'MTA-STS',
  'rpt.tls.policy.tlsa': 'DANE (TLSA)',
  'rpt.tls.policy.no-policy-found': 'MTA-STS ya da DANE politikası yok',
  'rpt.tls.policySessions': '{ok} başarılı · {failed} başarısız',
  'rpt.tls.allOk': 'Raporlanan her TLS oturumu başarılı.',
  'rpt.tls.noSessions': 'Raporlar hiçbir TLS oturumu listelemiyor.',
  'rpt.tls.failTitle': 'Türe göre hatalar',
  'rpt.tls.typeFacts': '{count} başarısız oturum · MX {mx} · raporlayan: {orgs}',
  'rpt.tls.reasons': 'Bildirilen neden: {reasons}',
  'rpt.tls.type.starttls-not-supported': 'STARTTLS sunulmadı',
  'rpt.tls.type.certificate-host-mismatch': 'Sertifika MX sunucusunun adını içermiyor',
  'rpt.tls.type.certificate-expired': 'Sertifikanın süresi dolmuş',
  'rpt.tls.type.certificate-not-trusted': 'Sertifikaya güvenilmiyor',
  'rpt.tls.type.validation-failure': 'Sertifika zinciri doğrulanamadı',
  'rpt.tls.type.tlsa-invalid': 'TLSA kayıtları eşleşmiyor',
  'rpt.tls.type.dnssec-invalid': 'TLSA kayıtları DNSSEC doğrulamasından geçmedi',
  'rpt.tls.type.dane-required': 'DANE gerekli, kullanılabilir TLSA kaydı yok',
  'rpt.tls.type.sts-policy-fetch-error': 'MTA-STS politikası alınamadı',
  'rpt.tls.type.sts-policy-invalid': 'MTA-STS politikası geçersiz',
  'rpt.tls.type.sts-webpki-invalid': 'MTA-STS sunucusunun sertifikası geçersiz',
  'rpt.tls.type.other': 'Başka bir hata',
  'rpt.tls.advice.starttls-not-supported': 'MX sunucusu STARTTLS sunmadı ya da bağlantı ondan önce kesildi. Posta sunucusunun 25. portta STARTTLS’i duyurduğunu — yedek MX sunucularında da — ve hiçbir güvenlik duvarının ya da proxy’nin onu silmediğini kontrol edin.',
  'rpt.tls.advice.certificate-host-mismatch': 'MX sunucusunun sertifikası göndericilerin bağlandığı sunucu adını içermiyor. Adları her MX sunucusunu kapsayan bir sertifika kurun: MTA-STS ve DANE kullanan göndericiler bunu kontrol eder.',
  'rpt.tls.advice.certificate-expired': 'MX sunucusu süresi dolmuş bir sertifika sundu. Sertifikayı yenileyin ve posta sunucusunu yeniden başlatın ya da yeniden yükleyin ki yenisini sunsun.',
  'rpt.tls.advice.certificate-not-trusted': 'Sertifika göndericinin güvendiği bir CA tarafından imzalanmamış (kendinden imzalı ya da özel bir CA). MTA-STS herkesin güvendiği bir sertifika ister.',
  'rpt.tls.advice.validation-failure': 'Sertifika zinciri doğrulanamadı; çoğunlukla bir ara sertifika eksiktir. 25. portta tam zinciri sunun.',
  'rpt.tls.advice.tlsa-invalid': 'TLSA kayıtları ne sertifikayla ne de anahtarıyla eşleşiyor. Sunucunun sunduğu sertifikanın kaydını yayınlayın, iki TTL bekleyin, sonra eskisini kaldırın.',
  'rpt.tls.advice.dnssec-invalid': 'TLSA kayıtları DNSSEC ile doğrulanamadı. Zone’un DNSSEC zincirini kontrol edin: üst bölgedeki DS ve imzalar.',
  'rpt.tls.advice.dane-required': 'Gönderici DANE istiyor, ama MX sunucusunun kullanılabilir bir TLSA kaydı yok.',
  'rpt.tls.advice.sts-policy-fetch-error': 'Gönderici https://mta-sts.{domain}/.well-known/mta-sts.txt dosyasını alamadı: yanıt yok, bir HTTP hatası ya da o sunucuda bir sertifika sorunu.',
  'rpt.tls.advice.sts-policy-invalid': 'MTA-STS politika dosyası okunamadı: version, mode, max_age ve mx satırlarını kontrol edin.',
  'rpt.tls.advice.sts-webpki-invalid': 'mta-sts.{domain} sertifikası doğrulanamadı: göndericiler bu durumda politikayı yok sayar.',
  'rpt.tls.advice.other': 'Bu sayfanın tanımadığı bir sonuç türü; raporlayanın kendi nedeni aşağıda.',
  'rpt.tls.tool.health': 'Alan Adı Sağlığı’nda MTA-STS’i kontrol edin',
  'rpt.tls.tool.tlsa': '{mx} TLSA kayıtları',
  'rpt.tls.tool.cert': '{mx} sertifikası (DANE / TLSA sekmesi)',
  'rpt.tls.failures': 'Hata ayrıntıları',
  'rpt.tls.failuresCaption': '{domain} TLS hataları',
  'rpt.tls.col.type': 'Sonuç',
  'rpt.tls.col.mx': 'MX sunucusu',
  'rpt.tls.col.rip': 'Alıcı IP',
  'rpt.tls.col.org': 'Gönderici',
  'rpt.tls.col.sip': 'Gönderen MTA',
  'rpt.tls.col.sessions': 'Oturum',
  'rpt.tls.col.reason': 'Neden kodu',
  'rpt.tls.col.policy': 'Politika',
  'rpt.tls.senders': 'Gönderen kuruluşlar',
  'rpt.tls.col.ok': 'Başarılı',
  'rpt.tls.col.failed': 'Başarısız',
  'rpt.col.service': 'Hizmet',
  'rpt.view.label': 'Gönderen adresleri göster',
  'rpt.view.address': 'Adrese göre',
  'rpt.view.service': 'Hizmete göre',
  'rpt.svc.none': 'tanımlanamadı',
  'rpt.svc.noneTitle': 'Bu adresin arkasındaki hizmeti ne raporlar ne de ters DNS kaydı söylüyor.',
  'rpt.svc.unchecked': 'Raporlar hizmetini söylemiyor: Göndericileri tanımla, ters DNS kaydına bakar.',
  'rpt.svc.yours': 'Kendi sunucunuz: Göndericileri tanımla ona bakmaz.',
  'rpt.svc.private': 'Özel bir adres: Göndericileri tanımla ona bakmaz.',
  'rpt.svc.unconfirmed': 'doğrulanmadı',
  'rpt.svcType.mailbox': 'E-posta sağlayıcısı',
  'rpt.svcType.security': 'E-posta güvenliği',
  'rpt.svcType.forwarding': 'Yönlendirme',
  'rpt.svcType.transactional': 'İşlemsel e-posta',
  'rpt.svcType.marketing': 'E-posta pazarlaması',
  'rpt.svcType.saas': 'Yazılım hizmeti',
  'rpt.svcType.cloud': 'Bulut platformu',
  'rpt.svcType.hosting': 'Web barındırma',
  'rpt.svcType.msp': 'Yönetilen BT hizmeti',
  'rpt.svcType.technology': 'Teknoloji şirketi',
  'rpt.svcType.isp': 'İSS ya da ev ağı',
  'rpt.svcType.network': 'Ağ',
  'rpt.svcVia.dkim': 'DKIM',
  'rpt.svcVia.return-path': 'return-path',
  'rpt.svcVia.spf-include': 'SPF include',
  'rpt.svcVia.ptr': 'ters DNS',
  'rpt.svcVia.isp': 'ters DNS',
  'rpt.svcVia.asn': 'RIPEstat',
  'rpt.svcHow.dkim': 'Doğrulanan DKIM imzasından: d={detail}',
  'rpt.svcHow.return-path': 'SPF’ten geçen return-path adresinden: {detail}',
  'rpt.svcHow.spf-include': 'Adresi {detail} üzerinden yetkilendiren SPF kaydınızdan',
  'rpt.svcHow.ptr': 'Ters DNS kaydından: {detail}',
  'rpt.svcHow.isp': 'Ters DNS kaydına göre bir İSS ya da ev ağı ({detail}): sahte gönderim ya da kendi e-postasını yönlendiren bir kullanıcı',
  'rpt.svcHow.asn': 'Yalnızca ağı biliniyor: {detail}',
  'rpt.svcHow.confirmed': 'ad, adrese geri çözümleniyor',
  'rpt.svcHow.unconfirmed': 'ad adrese geri çözümlenmiyor; bu yüzden yalnızca bir ipucu',
  'rpt.guide.microsoft365': 'Microsoft 365: Microsoft Defender portalında (E-posta kimlik doğrulama ayarları) {domain} için DKIM’i açın ve gösterdiği selector1 ile selector2 CNAME kayıtlarını yayınlayın; SPF’te include:spf.protection.outlook.com kalsın.',
  'rpt.guide.google': 'Google Workspace: Yönetici konsolunda (Uygulamalar › Google Workspace › Gmail › E-postanın kimliğini doğrula) {domain} için bir DKIM anahtarı oluşturun, google._domainkey TXT kaydı olarak yayınlayın ve kimlik doğrulamayı başlatın; SPF’te include:_spf.google.com kalsın.',
  'rpt.guide.amazonses': 'Amazon SES: {domain} alan adını Easy DKIM ile doğrulayın (dkim.amazonses.com’a giden üç CNAME kaydı) ve SPF de hizalansın diye özel bir MAIL FROM alan adı belirleyin: MX ve SPF kayıtlarıyla {domain} altında bir alt alan adı.',
  'rpt.guide.sendgrid': 'SendGrid: {domain} alan adını Settings › Sender Authentication altında doğrulayın ve verdiği CNAME kayıtlarını yayınlayın: DKIM böylece {domain} olarak imzalar, return-path de onun bir alt alan adı olur.',
  'rpt.guide.mailchimp': 'Mailchimp: {domain} alan adını Domains altında doğrulayın ve k2 ile k3 DKIM CNAME kayıtlarını (dkim2.mcsv.net ve dkim3.mcsv.net’e) yayınlayın.',
  'rpt.guide.mandrill': 'Mailchimp Transactional (Mandrill): {domain} alan adını gönderim alan adı olarak ekleyin, DKIM CNAME kayıtlarını yayınlayın ve {domain} altında özel bir return-path alan adı belirleyin.',
  'rpt.guide.mailgun': 'Mailgun: Mailgun’da doğrulanmış bir alan adından gönderin, örneğin DKIM TXT kaydı ile MX ve SPF kayıtları olan mg.{domain}; return-path böylece {domain} altında kalır.',
  'rpt.guide.postmark': 'Postmark: {domain} alan adını doğrulayın (DKIM TXT kaydı) ve SPF de hizalansın diye Return-Path CNAME kaydını ekleyin (pm-bounces.{domain}, pm.mtasv.net’e).',
  'rpt.guide.sparkpost': 'SparkPost: {domain} alan adını gönderim alan adı olarak doğrulayın (DKIM TXT kaydı) ve {domain} altında bir bounce alan adı ekleyin (sparkpostmail.com’a bir CNAME).',
  'rpt.guide.brevo': 'Brevo: {domain} alan adını Senders, domains & dedicated IPs altında doğrulayın; verdiği DKIM kayıtlarını ve brevo-code TXT kaydını yayınlayın.',
  'rpt.guide.salesforce': 'Salesforce: {domain} için bir DKIM anahtarı oluşturun (Setup › DKIM Keys), gösterdiği iki CNAME kaydını yayınlayın, ardından anahtarı etkinleştirin.',
  'rpt.guide.hubspot': 'HubSpot: {domain} alan adını e-posta gönderim alan adı olarak bağlayın (Settings › Domains & URLs) ve verdiği DKIM CNAME kayıtlarını yayınlayın.',
  'rpt.guide.zendesk': 'Zendesk: {domain} için dijital imzaları açın (zendesk1 ve zendesk2 DKIM CNAME kayıtları); SPF’te include:mail.zendesk.com kalsın.',
  'rpt.guide.mailbox': '{service} posta kutularınızı barındırıyor. Yönetim ayarlarından {domain} için DKIM imzalamayı açın, verdiği kaydı yayınlayın ve SPF include’unu koruyun.',
  'rpt.guide.security': '{service} giden e-postanızı süzüp iletiyor. SPF include’unu koruyun; DKIM’i {domain} olarak imzalamasını ya da kendi imzanızı değiştirmeden geçirmesini sağlayın.',
  'rpt.guide.forwarding': '{service} e-postayı yönlendiriyor. Yönlendirme SPF’i bozar; aktarımda bozulmayan bir {domain} DKIM imzası taşıyan e-posta hizalı kalır.',
  'rpt.guide.transactional': '{service} uygulamalarınızın e-postasını gönderiyor. {domain} alan adını orada doğrulayın: DKIM {domain} olarak imzalasın (verdiği kayıtlar), SPF de hizalansın diye {domain} altında özel bir return-path (bounce) alan adı kullanın.',
  'rpt.guide.marketing': '{service} kampanyalarınızı gönderiyor. {domain} alan adını orada doğrulayın ki DKIM {domain} olarak imzalasın (verdiği kayıtlar); sunuyorsa özel bir return-path kullanın.',
  'rpt.guide.saas': '{service} sizin adınıza e-posta gönderiyor. E-posta ya da gönderici alan adı ayarlarına bakın: {domain} için DKIM (çoğunlukla CNAME kayıtları) ve sunuyorsa özel bir return-path.',
  'rpt.guide.cloud': '{service} bulutunda bir sunucu. Sizinse adresini SPF’te yetkilendirin ve e-postasını {domain} için DKIM ile imzalayın; değilse bu sahte gönderimdir.',
  'rpt.guide.hosting': 'Bir web barındırma hizmetinde ({service}) bir sunucu: çoğunlukla bir sitenin iletişim formu ya da bir betik. Bunun yerine e-posta hizmetiniz üzerinden SMTP ile gönderin ya da sunucuyu SPF’te yetkilendirip e-postasını {domain} için DKIM ile imzalayın.',
  'rpt.guide.msp': 'Yönetilen BT hizmeti veren {service} firmasının bir sunucusu. Oradan {domain} adına neyin gönderdiğini sorun, ardından onu SPF’te yetkilendirip DKIM ile imzalayın.',
  'rpt.guide.technology': '{service} şirketinin kendi sunucularından gelen e-posta. Onun bir hizmetini kullanıyorsanız {domain} için alan adı doğrulamasını kurun; kullanmıyorsanız bu sahte gönderimdir.',
  'rpt.guide.isp': 'Bir İSS ya da ev ağı: sahte gönderim ya da kendi e-postasını yönlendiren bir kullanıcı. Yetkilendirilecek bir şey yok; p=reject sahte e-postayı geri çevirir.',
  'rpt.guide.network': 'Yalnızca ağ biliniyor ({service}). Orada sizin bir sunucunuz yoksa bu sahte gönderimdir; p=reject onu geri çevirir.',
  'rpt.guide.forwarded': 'Yönlendirilen e-posta: bir posta kutusu ya da e-posta listesi {domain} adına gönderilen iletileri başka bir adrese aktarmış. Yönlendirme SPF’i bozar; aktarımda bozulmayan bir {domain} DKIM imzası taşıyan e-posta hizalı kalır. Yetkilendirilecek bir şey yok: tüm e-postanızı DKIM ile imzalayın.',
  'rpt.guide.authorized': 'Yetkili bir gönderici ({service}): e-postasını DKIM ile {domain} olarak imzalamasını ve mümkünse {domain} altında bir return-path kullanmasını sağlayın; böylece SPF de hizalanır.',
  'rpt.det.service': 'Hizmet',
  'rpt.det.serviceHow': 'Nasıl adlandırıldı',
  'rpt.det.guide': 'Hizalamak için',
  'rpt.ptrState.confirmed': '{name} (adrese geri çözümleniyor)',
  'rpt.ptrState.mismatch': '{name} (adrese geri çözümlenmiyor)',
  'rpt.ptrState.no-ptr': 'ters DNS adı yok',
  'rpt.ptrState.nxdomain': 'ters DNS adı yok',
  'rpt.ptrState.servfail': 'ters bölge yanıt vermedi (SERVFAIL)',
  'rpt.ptrState.error': 'sorgulanamadı',
  'rpt.id.bulk': '{count} göndericiyi tanımla',
  'rpt.id.bulkTitle': 'Hiçbir raporun adını vermediği en fazla {max} gönderen adresin (kendi sunucularınız dışında) ters DNS kaydını DoH çözümleyicileriniz üzerinden sorgular, her adın kendi adresine geri çözümlendiğini kontrol eder ve bu sitenin paketle getirdiği gönderici listeleriyle eşleştirir; ardından hâlâ adı bilinmeyenlerden en fazla {intel} tanesinin ağını (RIPEstat, ipwho.is) sorar.',
  'rpt.id.busy': 'Tanımlanıyor… {done} / {total}',
  'rpt.id.started': '{count} gönderici tanımlanıyor…',
  'rpt.id.done': '{count} göndericiden {named} tanesi tanımlandı.',
  'rpt.id.mapsFailed': 'Bu sitenin paketle getirdiği gönderici listeleri yüklenemedi ({error}): yalnızca DomainScope’un kendi bildiği hizmetler eşleştirildi.',
  'rpt.grp.caption': '{domain} göndericileri, hizmete göre',
  'rpt.grp.col.addresses': 'Adres',
  'rpt.grp.col.classes': 'Sınıflar',
  'rpt.grp.isp': 'İSS’ler ya da ev ağları',
  'rpt.grp.unnamed': 'Tanımlanamadı',
  'rpt.grp.unnamedHint': 'Bu adreslerin adını henüz ne raporlar ne de bir ters DNS sorgusu veriyor. Göndericileri tanımla onlara bakar; bilinmeyen kalıp DMARC’den geçmeyen e-posta büyük olasılıkla sahte gönderimdir.',
  'rpt.grp.services': '{count} hizmet',
  'rpt.grp.addresses': '{count} adres',
  'rpt.grp.unnamedLine': '{count} adres tanımlanamadı ({messages})',
  'rpt.grp.via': 'Neye göre adlandırıldı',
  'rpt.grp.evidence': 'Kanıt',
  'rpt.grp.list': 'Adresler'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (tests/js/reports-view.test.js)                             */
/* ------------------------------------------------------------------------ */

/**
 * How much of a source's mail passed one mechanism aligned: all, none or a part.
 * @param {number} passed messages
 * @param {number} total messages
 * @returns {{ state: 'pass'|'fail'|'part', ratio: number }}
 */
export function alignedState(passed, total) {
  const ratio = total > 0 ? passed / total : 0;
  return { state: passed >= total && total > 0 ? 'pass' : passed <= 0 ? 'fail' : 'part', ratio };
}

/**
 * The parameters of a fix text (`rpt.fix.<code>`): the policy domain (for `spf-permerror`, the
 * domain whose record gives the permerror) and, for the alignment fixes, the other domain the
 * source authenticates as. The view adds `why`, the permerror's reason in words.
 * @param {{ dkimAuth: Array<{ domain: string, result: string }>, spfAuth: Array<{ domain: string, result: string }>, spfDomain?: string|null }} row
 * @param {string} code a lib/dmarcreport.js FIX_CODES value
 * @param {string} domain the policy domain
 * @returns {{ domain: string, other: string }}
 */
export function fixParams(row, code, domain) {
  const org = registrableDomain(domain) || domain;
  const foreign = (list) => (list || []).find((a) => a.result === 'pass' && (registrableDomain(a.domain) || a.domain) !== org);
  const other = code === 'dkim-align' ? foreign(row.dkimAuth) : code === 'spf-align' ? foreign(row.spfAuth) : null;
  return { domain: code === 'spf-permerror' && row.spfDomain ? row.spfDomain : domain, other: other ? other.domain : '' };
}

/** Look of each lib/dmarcreport.js DMARC_VERDICTS value, p=reject not in force (see {@link verdictLook}). */
const VERDICT_VARIANTS = Object.freeze({ 'no-mail': 'info', enforced: 'ok', ready: 'ok', 'fix-first': 'warn', 'spf-broken': 'warn' });
/** Verdict texts beyond DMARC_VERDICTS: p=reject in force while mail is refused ({@link verdictLook}). */
export const VERDICT_EXTRA_KEYS = Object.freeze(['enforcedLosing', 'enforcedSpfBroken']);

/**
 * The verdict alert of the DMARC head: its texts (`rpt.verdict.<key>.title` / `.body`) and its
 * look. With `p=reject` in force a verdict about the future is mail refused now: known sources
 * that fail (`enforcedLosing`) or mail that passed through SPF alone while the SPF record gives a
 * permerror (`enforcedSpfBroken`), both an error.
 * @param {{ verdict: string, enforced?: boolean, blockers: object[] }} o lib/dmarcreport.js dmarcOverview
 * @returns {{ key: string, variant: 'info'|'ok'|'warn'|'error' }}
 */
export function verdictLook(o) {
  if (o.verdict === 'enforced' && o.blockers.length) return { key: 'enforcedLosing', variant: 'error' };
  if (o.verdict === 'spf-broken' && o.enforced) return { key: 'enforcedSpfBroken', variant: 'error' };
  return { key: o.verdict, variant: VERDICT_VARIANTS[o.verdict] || 'info' };
}

/**
 * A share as the headline says it (lib/util.js sharePercent: one decimal, never 100 % or 0 %
 * unless exactly so), the same number Copy summary gives.
 * @param {number} ratio
 * @returns {{ value: number, digits: 0|1 }} `value` 0 … 1 for formatPercent
 */
export function headlineShare(ratio) {
  const v = sharePercent(ratio);
  return { value: v / 100, digits: Number.isInteger(v) ? 0 : 1 };
}

const sameList = (a, b) => a === b || (!!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]));
const sameVerdict = (a, b) => a === b || (!!a && !!b && a.result === b.result && a.term === b.term && a.holder === b.holder
  && a.reason === b.reason && sameList(a.path, b.path) && (a.via === b.via || (!!a.via && !!b.via && a.via.host === b.via.host && a.via.address === b.via.address)));

/**
 * Whether a source's row, classified again (the SPF landed, the server list changed), draws
 * differently: its class, why, servers, the current SPF's verdicts or the fixes. The rest of a
 * row comes from the reports, which did not change; an unchanged row keeps its drawn <tr>, its
 * search text and its open details, so a table of 60,000 addresses redraws only what moved.
 * @param {object} a the row drawn (lib/dmarcreport.js classifySources)
 * @param {object} b the same address classified again
 * @returns {boolean}
 */
export function sourceRowChanged(a, b) {
  return a.cls !== b.cls || a.reason !== b.reason || a.detail !== b.detail || a.spfDomain !== b.spfDomain || a.atRisk !== b.atRisk
    || !sameList(a.servers, b.servers) || !sameList(a.fixes, b.fixes) || !sameVerdict(a.spfNow, b.spfNow) || !sameVerdict(a.spfListed, b.spfListed);
}

/**
 * The facts of Copy summary (lib/reportsummary.js reportsSummary) for the DMARC domain on screen and the
 * TLS summary of the same domain (or the TLS domain on screen when there is no DMARC report).
 * @param {{ agg: object|null, overview: object|null, spfState: string|null, tls: object|null, problems: number, at: Date|null }} s
 * @returns {object|null}
 */
export function summaryFacts({ agg, overview, spfState, tls, problems, at }) {
  if (!agg && !tls) return null;
  const dmarc = agg && overview ? {
    overview,
    policy: { p: agg.policy.p, pct: agg.policy.pct, testing: agg.policy.testing || null },
    reports: agg.reports,
    begin: agg.begin,
    end: agg.end,
    // No SPF record, or several, is an answer too: the classes rest on it.
    spf: ['ok', 'none', 'multiple'].includes(spfState) ? 'checked' : spfState === 'offline' ? 'skipped' : 'failed',
    // Why the SPF errs, as this view words it (its strings are registered once the view is loaded).
    spfErrorKey: overview.spfError ? `rpt.spfError.${overview.spfError.reason}` : null
  } : null;
  return {
    domain: agg ? agg.domain : tls.domain,
    dmarc,
    tls: tls ? { success: tls.success, failure: tls.failure, rate: tls.rate, reports: tls.reports, byType: tls.byType } : null,
    problems,
    at
  };
}

/**
 * The service line of a source (under its address; a service group's name): the name, and under
 * it the type and the evidence ("not confirmed" for a reverse name that does not point back); an
 * ISP or home network is named so, with its base domain under it. Null when nothing names the
 * source.
 * @param {import('../lib/senders.js').SenderIdentification|null} ident
 * @param {(key: string, params?: object) => string} t
 * @returns {{ name: string, meta: string }|null}
 */
export function serviceLabel(ident, t) {
  if (!ident) return null;
  const via = t(`rpt.svcVia.${ident.via}`);
  const how = ident.confidence === 'low' && (ident.via === 'ptr' || ident.via === 'isp') ? `${via}, ${t('rpt.svc.unconfirmed')}` : via;
  if (ident.via === 'isp') return { name: t('rpt.svcType.isp'), meta: `${ident.service} · ${how}` };
  // Only the network: its AS says more than the word "network".
  if (ident.via === 'asn') return { name: ident.service, meta: [ident.domain, via].filter(Boolean).join(' · ') };
  return { name: ident.service, meta: `${t(`rpt.svcType.${ident.type}`)} · ${how}` };
}

/**
 * How a source was named, as a sentence (its details, and the service line's tooltip).
 * @param {import('../lib/senders.js').SenderIdentification|null} ident
 * @param {(key: string, params?: object) => string} t
 * @returns {string}
 */
export function serviceHow(ident, t) {
  if (!ident) return '';
  const detail = ident.via === 'asn' ? [ident.domain, ident.service].filter(Boolean).join(' ') : ident.domain;
  const text = t(`rpt.svcHow.${ident.via}`, { detail });
  if (ident.via !== 'ptr' && ident.via !== 'isp') return text;
  return `${text} (${t(ident.confidence === 'low' ? 'rpt.svcHow.unconfirmed' : 'rpt.svcHow.confirmed')})`;
}

/**
 * Why a source has no service yet (its service line's tooltip and its details): looked up in vain,
 * a lookup that got no answer (the next click asks again), an address Identify senders leaves out
 * (a private one, your own server), or not looked up yet.
 * @param {{ private?: boolean, cls?: string }} r a lib/dmarcreport.js classifySources row
 * @param {{ looked?: boolean, failed?: boolean }} state
 * @param {(key: string, params?: object) => string} t
 * @returns {string}
 */
export function unnamedHint(r, { looked = false, failed = false } = {}, t) {
  if (looked) return t('rpt.svc.noneTitle');
  if (failed) return `${t('rpt.det.ptr')}: ${t('rpt.ptrState.error')}`;
  if (r && r.private) return t('rpt.svc.private');
  if (r && r.cls === 'yours') return t('rpt.svc.yours');
  return t('rpt.svc.unchecked');
}

/**
 * The name of a group of the service view: the service's, "ISP or home networks" or "Not identified".
 * @param {{ key: string, service: string|null }} group lib/senders.js groupSources
 * @param {(key: string) => string} t
 * @returns {string}
 */
export function groupName(group, t) {
  return group.key === 'isp' ? t('rpt.grp.isp') : group.key === 'unnamed' ? t('rpt.grp.unnamed') : group.service;
}

/**
 * What an Identify senders lookup keeps of lib/ptrsweep.js checkFcrdns: its status, the name
 * shown (the first that points back, else the first) and whether it was confirmed.
 * @param {{ status: string, names?: string[], confirmed?: string[] }} v
 * @returns {{ status: string, name: string|null, confirmed: boolean }}
 */
export function ptrFact(v) {
  const confirmed = (v && v.confirmed) || [];
  const names = (v && v.names) || [];
  return { status: FCRDNS_STATUSES.includes(v && v.status) ? v.status : 'error', name: confirmed[0] || names[0] || null, confirmed: confirmed.length > 0 };
}

/* ------------------------------------------------------------------------ */
/* Module state: the reports of this tab (memory only)                      */
/* ------------------------------------------------------------------------ */

const fresh = () => ({
  files: 0,
  dmarcReports: [],
  tlsReports: [],
  problems: [],
  loadedAt: null,
  dmarc: null,
  tls: null,
  domain: null,
  tlsDomain: null,
  tab: 'dmarc',
  cls: null,
  spf: new Map(),
  // Bumped with every SPF answer stored: the classes rest on them.
  spfVersion: 0,
  spfState: new Map(),
  intel: new Map(),
  // Identify senders: ip → what its reverse DNS lookup found (ptrFact), and the click in flight ({ done, total }).
  ptr: new Map(),
  identifying: null,
  // The sending addresses one per address, or folded per service (SOURCE_VIEWS).
  view: 'address'
});

let S = fresh();
let subscribed = false;
let rerender = null;
/** The sender lists this site bundles (lib/senders.js loadSenderMaps), once an Identify click read them. */
let senderMaps = null;
let intelService = null;
/** The DohClient intelService asks: a new one (another resolver chain) gets a new service. */
let intelDns = null;
let active = null;

/** Forget every report (Forget, another workspace, "Delete all local data"). */
function resetReports() {
  S = fresh();
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the DMARC & TLS reports view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  if (!subscribed) {
    subscribed = true;
    state.subscribe(({ key }) => {
      // The reports are a customer's: another workspace forgets them like "Delete all local data".
      if (key === 'cleared' || key === 'workspace') {
        resetReports();
        if (rerender) rerender();
      } else if (key === 'inventory' && rerender && S.dmarc) {
        rerender({ keep: true });
      }
    });
  }
  // Forget stops what runs for the reports it drops (their SPF and IP lookups); the view's own
  // signal stops everything when it is left.
  let work = new AbortController();
  const signal = () => mergeSignals(ctx.signal, work.signal);
  const root = h('div', { class: 'rpt-page stack' });
  root.append(Alert({ variant: 'ok', icon: 'lock', title: t('rpt.privacyTitle'), message: t('rpt.privacy'), compact: true }));
  container.append(root);

  let busy = false;
  // While reading: the files still to read (a drop in the meantime joins them), the Stop, the bar.
  let queue = [];
  let reading = null;
  let progress = null;
  // The bar: files read of the files known; a dropped archive counts as the files inside it once unpacked.
  let readDone = 0;
  let readTotal = 0;
  let sourcesTable = null;
  let bulkBtn = null;
  // The service view of the sources (S.view 'service'): its table and totals line; Identify senders' button.
  let groupTable = null;
  let groupTotalsEl = null;
  let identifyBtn = null;
  let sourcesBody = null;
  let groupRefreshQueued = false;
  const num = (n) => formatNumber(n);
  // Every share as the headline says it: one decimal when it has one, never all or none unless it is.
  const share = (ratio) => {
    const x = headlineShare(ratio);
    return formatPercent(x.value, x.digits);
  };
  const day = (d) => formatDate(d, { utc: true, dateStyle: 'medium' });

  /* --- reading ----------------------------------------------------------------------- */
  const showProgress = () => {
    if (progress) progress.set(readDone, Math.max(readTotal, 1));
  };

  /** Read dropped files; a drop while reading joins the queue and is read next. */
  async function load(files) {
    if (!files.length) return;
    queue.push(...files);
    readTotal += files.length;
    if (busy) {
      showProgress();
      announce(t('rpt.queued', { count: files.length }));
      return;
    }
    busy = true;
    reading = new AbortController();
    readDone = 0;
    readTotal = queue.length;
    ctx.setBusy(true);
    renderAll();
    announce(t('rpt.reading', { count: readTotal }));
    const mine = S;
    const got = { files: 0, dmarc: [], tls: [], problems: [] };
    try {
      let cut = false;
      while (queue.length && mine === S && !cut) {
        const batch = queue;
        queue = [];
        const before = readDone;
        let batchTotal = batch.length;
        const r = await readReportFiles(batch.map((f) => ({ name: f.name, bytes: new Uint8Array(f.buffer) })), {
          signal: mergeSignals(signal(), reading.signal),
          onProgress: (done, total) => {
            readDone = before + done;
            readTotal += total - batchTotal;
            batchTotal = total;
            showProgress();
          }
        });
        readDone = before + batchTotal;
        // A Stop ends the read with what it read before, the reports of an archive it cut included.
        got.files += r.files;
        got.dmarc.push(...r.dmarc);
        got.tls.push(...r.tls);
        got.problems.push(...r.problems);
        cut = r.stopped;
      }
    } catch (err) {
      if (!ctx.signal.aborted) toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    }
    const stopped = reading.signal.aborted && !ctx.signal.aborted;
    busy = false;
    queue = [];
    reading = null;
    progress = null;
    readTotal = 0;
    if (ctx.signal.aborted) return;
    ctx.setBusy(false);
    // Another workspace (or "Delete all local data") came while the files were read: they belonged to the one left.
    const kept = mine === S ? got.dmarc.length + got.tls.length : 0;
    if (stopped) toast(mine !== S ? t('rpt.stopped') : kept ? t('rpt.stoppedKept', { count: kept }) : t('rpt.stoppedNone'), { type: 'info' });
    if (mine !== S || !got.files) {
      renderAll();
      if (stopped) focusDrop();
      return;
    }
    S.files += got.files;
    S.dmarcReports.push(...got.dmarc);
    S.tlsReports.push(...got.tls);
    S.problems.push(...got.problems);
    analyse();
    if (kept) {
      S.loadedAt = new Date();
      ctx.resultChanged();
      const target = S.domain || S.tlsDomain;
      if (target) ctx.runStarted(target);
      if (!got.dmarc.length && got.tls.length) S.tab = 'tls';
      else if (got.dmarc.length) S.tab = 'dmarc';
      // After a Stop its toast says what was kept.
      if (!stopped) announce(t('rpt.loaded', { dmarc: num(got.dmarc.length), tls: num(got.tls.length) }));
    } else if (!stopped) {
      toast(t('rpt.noneRead'), { type: 'warn' });
    }
    renderAll();
    const head = root.querySelector('.rpt-results-title');
    // A Stop gives the focus back to the drop zone, as its button is gone; a read to the end, to the results.
    if (stopped) focusDrop();
    else if (head && kept) head.focus({ preventScroll: true });
    checkSpf();
  }

  /** Stop reading (the Stop button, Esc): the queue is dropped; the reports read before stay, those of an archive it cut too. */
  function stopReading() {
    queue = [];
    if (reading) reading.abort();
  }

  function focusDrop() {
    const drop = root.querySelector('.rpt-load .filedrop');
    if (drop) drop.focus();
  }

  /** Aggregate what is loaded; keep the chosen domains when they are still there. */
  function analyse() {
    S.dmarc = aggregateDmarc(S.dmarcReports);
    S.tls = summarizeTls(S.tlsReports);
    if (!S.dmarc.domains.some((d) => d.domain === S.domain)) S.domain = S.dmarc.domains[0] ? S.dmarc.domains[0].domain : null;
    if (!S.tls.domains.some((d) => d.domain === S.tlsDomain)) {
      const same = S.tls.domains.find((d) => d.domain === S.domain);
      S.tlsDomain = same ? same.domain : S.tls.domains[0] ? S.tls.domains[0].domain : null;
    }
  }

  function forget() {
    work.abort();
    work = new AbortController();
    resetReports();
    ctx.resultChanged();
    toast(t('rpt.forgotten'), { type: 'info' });
    renderAll();
    focusDrop();
  }

  const aggOf = (domain) => (S.dmarc ? S.dmarc.domains.find((d) => d.domain === domain) || null : null);
  const tlsOf = (domain) => (S.tls ? S.tls.domains.find((d) => d.domain === domain) || null : null);

  /* --- the current SPF ---------------------------------------------------------------- */
  /** The SPF line's state of a domain: its own context, or the lookup's progress. */
  function spfStateOf(domain) {
    const st = S.spfState.get(domain);
    if (st === 'loading' || st === 'offline') return st;
    const c = S.spf.get(domain);
    if (!c) return null;
    return c.status;
  }

  async function checkSpf({ force = false, loud = false } = {}) {
    const agg = aggOf(S.domain);
    if (!agg) return;
    const domain = agg.domain;
    if (!force && S.spfState.get(domain) === 'loading') return;
    const missing = spfDomainsFor(agg).filter((d) => !S.spf.has(d));
    const wanted = force ? spfDomainsFor(agg) : missing;
    // Every SPF record the classes need is in memory (checked before going offline): none is "not checked".
    if (!wanted.length) {
      if (S.spfState.get(domain) === 'offline') {
        S.spfState.set(domain, 'done');
        refreshDmarc();
      }
      return;
    }
    if (!(loud ? ctx.requireOnline() : ctx.requireOnline({ quiet: true }))) {
      if (missing.length) {
        S.spfState.set(domain, 'offline');
        refreshDmarc();
      }
      return;
    }
    const mine = S;
    mine.spfState.set(domain, 'loading');
    refreshDmarc();
    try {
      const dns = await ctx.getDns();
      const sig = signal();
      // "Check again" asks past the resolver's cache: a record fixed a minute ago shows at once.
      for (const d of wanted) {
        mine.spf.set(d, await loadSpfContext(d, { dns, signal: sig, noCache: force }));
        mine.spfVersion += 1;
      }
      mine.spfState.set(domain, 'done');
    } catch (err) {
      mine.spfState.delete(domain);
      if (!(err && err.name === 'AbortError')) toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    }
    // Forget (or another workspace) dropped these reports meanwhile: nothing to draw.
    if (!ctx.signal.aborted && mine === S) refreshDmarc();
  }

  // The last classification: the same reports, server list and SPF answers give the same rows (the
  // SPF line going to "looking up…" right after a drop redraws the head, never classifies again).
  let classified = null;

  /** Rows, overview and SPF line state of the DMARC domain on screen. */
  function dmarcModel() {
    const agg = aggOf(S.domain);
    if (!agg) return null;
    const index = ctx.getInventoryIndex();
    if (!classified || classified.agg !== agg || classified.index !== index || classified.spf !== S.spf || classified.spfVersion !== S.spfVersion) {
      classified = { agg, index, spf: S.spf, spfVersion: S.spfVersion, rows: classifySources(agg, { spf: S.spf, index }) };
    }
    const { rows } = classified;
    const line = spfStateOf(agg.domain);
    const spfChecked = line === 'loading' || line === 'ok' || line === 'none' || line === 'multiple';
    return { agg, rows, overview: dmarcOverview(agg, rows, { spfChecked }), line };
  }

  /* --- IP data on a click ------------------------------------------------------------- */
  async function lookUp(ips) {
    const todo = ips.filter((ip) => !S.intel.has(ip)).slice(0, INTEL_MAX);
    if (!todo.length || !ctx.requireOnline()) return;
    const mine = S;
    const sig = signal();
    for (const ip of todo) mine.intel.set(ip, { loading: true });
    refreshRows(todo);
    const dns = await ctx.getDns();
    if (!intelService || intelDns !== dns) {
      intelService = createIpIntel({ dns, concurrency: 3 });
      intelDns = dns;
    }
    const intel = intelService;
    let done = 0;
    await Promise.all(todo.map(async (ip) => {
      try {
        mine.intel.set(ip, { info: await intel.info(ip, { signal: sig }) });
        done += 1;
      } catch (err) {
        mine.intel.delete(ip);
        if (!(err && err.name === 'AbortError')) toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
      if (!ctx.signal.aborted && mine === S) refreshRows([ip]);
    }));
    if (!ctx.signal.aborted && done > 1) announce(t('rpt.intel.done', { count: done }));
  }

  function refreshRows(ips) {
    if (sourcesTable) {
      const set = new Set(ips);
      sourcesTable.updateRows(sourcesTable.getRows().filter((row) => set.has(row.ip)));
    }
    queueGroupRefresh();
    updateBulk();
  }

  function updateBulk() {
    if (!bulkBtn || !sourcesTable) return;
    const open = sourcesTable.getVisibleRows().filter((r) => !r.private && !S.intel.has(r.ip)).length;
    const n = Math.min(open, INTEL_MAX);
    bulkBtn.hidden = n === 0;
    bulkBtn.querySelector('.btn-label').textContent = t('rpt.intel.bulk', { count: n });
  }

  /* --- the service behind each source (lib/senders.js) ------------------------------------- */
  // Per row object: the identification and what it rests on (a reverse DNS lookup, Look up's data,
  // the bundled lists). A source classified again is a new object, so it is named again too.
  const identCache = new WeakMap();

  /**
   * The service behind a source of the domain on screen, from the reports and the current SPF
   * (no lookup), then — once asked — its reverse DNS, the bundled lists and Look up's network.
   */
  function identOf(r) {
    const fact = S.ptr.get(r.ip) || null;
    const got = S.intel.get(r.ip);
    const info = got && got.info ? got.info : null;
    const cached = identCache.get(r);
    if (cached && cached.fact === fact && cached.info === info && cached.maps === senderMaps) return cached.ident;
    const looked = info && Array.isArray(info.ptr) && info.ptr.length ? info.ptr[0] : null;
    const ident = identifySource(r, {
      domain: S.domain,
      spfPath: spfPathOf(r),
      ptrName: fact && fact.name ? fact.name : looked,
      ptrConfirmed: !!(fact && fact.confirmed),
      maps: senderMaps,
      holder: info && info.holder ? { name: info.holder, asn: info.asn } : null
    });
    identCache.set(r, { fact, info, maps: senderMaps, ident });
    return ident;
  }

  /** The rows of the domain on screen that the class tiles let through. */
  function classRows() {
    const m = dmarcModel();
    return m ? m.rows.filter((r) => !S.cls || r.cls === S.cls) : [];
  }

  /** The sources an Identify click would look up: those the table shows (the service view: the class's). */
  function identifyScope() {
    if (S.view === 'address' && sourcesTable) return sourcesTable.getVisibleRows();
    return classRows();
  }

  /** The addresses a click looked up for good: a lookup that got no answer is asked again by the next click. */
  const lookedUp = { has: (ip) => !!S.ptr.get(ip) && S.ptr.get(ip).status !== 'error' };

  function updateIdentify() {
    if (!identifyBtn) return;
    const label = identifyBtn.querySelector('.btn-label');
    const run = S.identifying;
    identifyBtn.classList.toggle('is-busy', !!run);
    if (run) {
      identifyBtn.hidden = false;
      identifyBtn.setAttribute('aria-busy', 'true');
      identifyBtn.setAttribute('aria-disabled', 'true');
      label.textContent = t('rpt.id.busy', { done: num(run.done), total: num(run.total) });
      return;
    }
    identifyBtn.removeAttribute('aria-busy');
    identifyBtn.removeAttribute('aria-disabled');
    const n = identifyCandidates(identifyScope(), { identOf, checked: lookedUp, max: IDENTIFY_MAX }).length;
    identifyBtn.hidden = n === 0;
    label.textContent = t('rpt.id.bulk', { count: n });
  }

  /**
   * Identify senders: the reverse DNS of the sources no report names (at most IDENTIFY_MAX),
   * each name checked forward, through the view's DohClient (its limiter caps the requests);
   * the bundled lists read meanwhile; then Look up's network of those still unnamed.
   */
  async function identify() {
    if (S.identifying) return;
    const todo = identifyCandidates(identifyScope(), { identOf, checked: lookedUp, max: IDENTIFY_MAX });
    if (!todo.length || !ctx.requireOnline()) return;
    const mine = S;
    const sig = signal();
    const ips = todo.map((r) => r.ip);
    // This click's progress: a later visit's click has its own (the view left stops this one).
    const run = { done: 0, total: ips.length };
    const settle = () => {
      if (mine.identifying === run) mine.identifying = null;
    };
    mine.identifying = run;
    updateIdentify();
    announce(t('rpt.id.started', { count: ips.length }));
    let mapsFailed = null;
    const maps = loadSenderMaps({ signal: sig }).then((x) => { senderMaps = x; }, (err) => {
      if (err && err.name === 'AbortError') throw err;
      mapsFailed = err;
    });
    // Awaited after the lookups; a Stop before then rejects it unseen.
    maps.catch(() => {});
    try {
      const dns = await ctx.getDns();
      let next = 0;
      const worker = async () => {
        while (next < ips.length) {
          const ip = ips[next];
          next += 1;
          // checkFcrdns never rejects but with an AbortError: a failed lookup is its 'error' verdict.
          const v = await checkFcrdns(ip, { dns, signal: sig });
          mine.ptr.set(ip, ptrFact(v));
          run.done += 1;
          if (mine === S && !ctx.signal.aborted) {
            refreshRows([ip]);
            updateIdentify();
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(IDENTIFY_CONCURRENCY, ips.length) }, worker));
      await maps;
    } catch (err) {
      settle();
      if (!(err && err.name === 'AbortError') && !ctx.signal.aborted) toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      if (mine === S && !ctx.signal.aborted) updateIdentify();
      return;
    }
    settle();
    if (mine !== S || ctx.signal.aborted) return;
    if (mapsFailed) toast(t('rpt.id.mapsFailed', { error: mapsFailed.message || String(mapsFailed) }), { type: 'warn' });
    // The lists may name sources the reports named nothing for: every row is looked at again.
    if (sourcesTable) sourcesTable.refresh();
    queueGroupRefresh();
    updateIdentify();
    // The rows as classified now (an SPF answer may have landed meanwhile), by address.
    const rowsByIp = () => new Map((dmarcModel() || { rows: [] }).rows.map((r) => [r.ip, r]));
    const before = rowsByIp();
    const still = ips.filter((ip) => before.has(ip) && !identOf(before.get(ip)));
    // Look up's network (RIPEstat, ipwho.is) for what is still unnamed, at most INTEL_MAX as a Look up click.
    if (still.length) await lookUp(still);
    if (mine !== S || ctx.signal.aborted) return;
    const rows = rowsByIp();
    const named = ips.filter((ip) => {
      const id = rows.has(ip) ? identOf(rows.get(ip)) : null;
      return id && id.via !== 'asn';
    }).length;
    announce(t('rpt.id.done', { named, count: ips.length }));
    updateIdentify();
  }

  /* --- the service view ---------------------------------------------------------------------- */
  /** The groups of the domain on screen, the class tiles applied. */
  function currentGroups() {
    return groupSources(classRows(), identOf);
  }

  function queueGroupRefresh() {
    if (!groupTable || groupRefreshQueued) return;
    groupRefreshQueued = true;
    requestAnimationFrame(() => {
      groupRefreshQueued = false;
      refreshGroups();
    });
  }

  /** The service view drawn again (new names, classes or a class filter): an open group stays open. */
  function refreshGroups() {
    if (!groupTable) return;
    const { groups, totals } = currentGroups();
    const drawn = new Set(groupTable.getRows().map((g) => g.key));
    if (groups.length === drawn.size && groups.every((g) => drawn.has(g.key))) groupTable.updateRows(groups);
    else groupTable.setRows(groups);
    fillTotals(totals);
    updateIdentify();
  }

  function fillTotals(totals) {
    if (!groupTotalsEl) return;
    const bits = [t('rpt.grp.services', { count: totals.services }), t('rpt.grp.addresses', { count: totals.addresses }), t('rpt.det.count', { count: totals.messages })];
    if (totals.unnamedAddresses) bits.push(t('rpt.grp.unnamedLine', { count: totals.unnamedAddresses, messages: t('rpt.det.count', { count: totals.unnamedMessages }) }));
    groupTotalsEl.textContent = bits.join(' · ');
  }

  /** The class tiles changed: the table shown follows them. */
  function applyClassFilter() {
    if (sourcesTable) sourcesTable.setFilter(S.cls ? (r) => r.cls === S.cls : null);
    if (groupTable) refreshGroups();
    updateIdentify();
  }

  /* --- rendering --------------------------------------------------------------------- */
  const loadEl = h('div');
  // A form of its own for the shell's shortcuts, without a submit: nothing in the results runs the view.
  const resultsEl = h('div', { class: 'stack', dataset: { shortcutScope: 'results' } });
  root.append(loadEl, resultsEl);
  let summaryBtn = null;
  let dmarcPanel = null;
  let tabs = null;

  function renderAll() {
    renderLoad();
    renderResults();
  }

  function hasReports() {
    return !!(S.dmarcReports.length || S.tlsReports.length);
  }

  function renderLoad() {
    clear(loadEl);
    const drop = FileDrop({
      onFiles: (files) => load(files),
      accept: ACCEPT,
      multiple: true,
      directory: true,
      maxBytes: MAX_FILE_BYTES,
      // A month of daily reports from a few receivers, or a mailbox folder: as many as one read takes.
      maxFiles: MAX_REPORT_FILES,
      // The reports are read from their bytes (zip, gzip, the XML's own encoding): no text decoded here.
      text: false,
      paste: false,
      icon: 'inbox',
      title: hasReports() ? t('rpt.drop.more') : t('rpt.drop.title'),
      hint: t('rpt.drop.hint', { max: num(MAX_REPORT_FILES) }),
      compact: hasReports()
    });
    // '/' focuses the drop zone; Ctrl/Cmd+Enter (the shell's run shortcut) chooses files.
    drop.el.dataset.shortcut = 'focus';
    // Choosing more while it reads is fine: they are read next.
    const actions = [Button({
      label: t('rpt.choose'), icon: 'upload', size: 'sm', variant: hasReports() ? 'secondary' : 'primary',
      dataset: { action: 'rpt-choose', shortcut: 'submit' }, onClick: () => drop.open()
    })];
    if (drop.openFolder) actions.push(Button({ label: t('rpt.folder'), icon: 'folder', size: 'sm', variant: 'secondary', onClick: () => drop.openFolder() }));
    // Files that were no report are listed too: Forget drops that list as well.
    if (hasReports() || S.problems.length) {
      actions.push(Button({ label: t('rpt.forget'), icon: 'trash', size: 'sm', variant: 'ghost', disabled: busy, dataset: { action: 'rpt-forget' }, onClick: forget }));
    }
    const body = h('div', { class: 'stack-sm' }, drop.el);
    if (busy) {
      progress = ProgressBar({ label: t('rpt.busy'), value: readDone, max: Math.max(readTotal, 1) });
      const stop = Button({ label: t('rpt.stop'), icon: 'stop', size: 'sm', variant: 'secondary', dataset: { action: 'rpt-stop', shortcut: 'cancel' }, onClick: stopReading });
      body.append(h('div', { class: 'rpt-busy stack-sm', dataset: { role: 'rpt-busy' } }, progress.el, stop));
    }
    if (hasReports() || S.problems.length) body.append(filesLine());
    if (S.problems.length) body.append(problemsList());
    loadEl.append(Card({ className: 'rpt-load', children: body, footer: actions.length ? h('div', { class: 'cluster rpt-load-actions' }, actions) : null }));
  }

  function filesLine() {
    const dup = (S.dmarc ? S.dmarc.duplicates : 0) + (S.tls ? S.tls.duplicates : 0);
    const bits = [
      t('rpt.count.files', { count: S.files }),
      t('rpt.count.dmarc', { count: S.dmarcReports.length }),
      t('rpt.count.tls', { count: S.tlsReports.length })
    ];
    if (dup) bits.push(t('rpt.count.duplicates', { count: dup }));
    if (S.problems.length) bits.push(t('rpt.count.problems', { count: S.problems.length }));
    return h('p', { class: 'text-sm muted rpt-files', dataset: { role: 'rpt-files' } }, bits.join(' · '));
  }

  function problemsList() {
    const shown = S.problems.slice(0, PROBLEMS_MAX);
    const rest = S.problems.length - shown.length;
    return Disclosure({
      summary: `${t('rpt.problems')} (${num(S.problems.length)})`,
      className: 'rpt-problems',
      children: [
        h('ul', { class: 'rpt-problem-list' }, shown.map((p) => h('li', { dataset: { code: p.code } },
          h('span', { class: 'mono rpt-problem-path' }, p.path), ' — ',
          h('span', null, t(`rpt.problem.${p.code}`, { detail: p.detail || '' }))))),
        rest > 0 ? h('p', { class: 'text-sm muted rpt-problem-more' }, t('common.moreCount', { count: num(rest) })) : null
      ]
    });
  }

  function renderResults() {
    clear(resultsEl);
    sourcesTable = null;
    bulkBtn = null;
    groupTable = null;
    groupTotalsEl = null;
    identifyBtn = null;
    sourcesBody = null;
    dmarcPanel = null;
    tabs = null;
    if (!hasReports()) {
      if (!busy) resultsEl.append(EmptyState({ icon: 'inbox', title: t('rpt.emptyTitle'), message: t('rpt.emptyBody') }));
      return;
    }
    summaryBtn = SummaryButton({
      kind: 'reports',
      facts: () => {
        const m = dmarcModel();
        const tlsSummary = tlsOf(m ? m.agg.domain : S.tlsDomain) || (m ? null : tlsOf(S.tlsDomain));
        return summaryFacts({
          agg: m ? m.agg : null,
          overview: m ? m.overview : null,
          spfState: m ? m.line : null,
          tls: tlsSummary,
          problems: S.problems.length,
          at: S.loadedAt
        });
      },
      url: () => ctx.shareUrl({})
    });
    const domains = new Set([...S.dmarc.domains, ...S.tls.domains].map((d) => d.domain));
    const title = domains.size === 1 ? t('rpt.resultsOne', { domain: [...domains][0] }) : t('rpt.resultsMany', { count: domains.size });
    resultsEl.append(h('div', { class: 'rpt-results-head' },
      h('h2', { class: 'rpt-results-title', attrs: { tabindex: -1 } }, title),
      summaryBtn.el));
    const items = [];
    const dmarcContent = () => {
      dmarcPanel = h('div', { class: 'stack rpt-dmarc' });
      fillDmarc();
      return dmarcPanel;
    };
    if (S.dmarcReports.length) items.push({ id: 'dmarc', label: t('rpt.tab.dmarc'), icon: 'mail', badge: S.dmarcReports.length, content: dmarcContent });
    if (S.tlsReports.length) items.push({ id: 'tls', label: t('rpt.tab.tls'), icon: 'lock', badge: S.tlsReports.length, content: () => tlsPanel() });
    tabs = Tabs(items, { selected: items.some((i) => i.id === S.tab) ? S.tab : items[0].id, label: t('rpt.tabs'), className: 'rpt-tabs', onChange: (tab) => { S.tab = tab; } });
    resultsEl.append(tabs.el);
  }

  /** The DMARC panel after SPF, the server list or the domain changed; the table keeps its search and sort. */
  function refreshDmarc() {
    if (!dmarcPanel) return;
    fillDmarc({ keepTable: true });
  }

  function domainPicker(list, value, onPick, count, key) {
    if (list.length < 2) return null;
    const field = select({
      label: t('rpt.domain'),
      size: 'sm',
      className: 'rpt-domain',
      value,
      options: list.map((d) => ({ value: d.domain, label: t(key, { domain: d.domain, count: count(d) }) })),
      onChange: onPick
    });
    return field.el;
  }

  /**
   * Run `fn`, which redraws part of `scope`, and put the keyboard focus back on the control it was
   * on (the redrawn copy: a button by its action, a class tile, the domain picker).
   */
  function keepFocus(scope, fn) {
    const a = document.activeElement;
    const inside = a && a !== scope && scope.contains(a) ? a : null;
    let key = null;
    if (inside && inside.dataset.action) key = `[data-action="${inside.dataset.action}"]${inside.dataset.ip ? `[data-ip="${inside.dataset.ip}"]` : ''}`;
    else if (inside && inside.dataset.cls) key = `.stat-button[data-cls="${inside.dataset.cls}"]`;
    else if (inside && inside.matches('.rpt-domain select')) key = '.rpt-domain select';
    else if (inside && inside.matches('.rpt-view .seg-btn')) key = `.rpt-view .seg-btn[data-value="${inside.dataset.value}"]`;
    fn();
    if (key && !inside.isConnected) {
      const again = scope.querySelector(key);
      if (again) again.focus({ preventScroll: true });
    }
  }

  /* --- DMARC ------------------------------------------------------------------------- */
  let dmarcParts = null;

  /**
   * The DMARC panel of the domain on screen. `keepTable`: the same reports with new classes (the
   * SPF landed, the server list changed): the head and the tiles are drawn again, and the table's
   * rows that changed ({@link sourceRowChanged}) are replaced in place in one batch, so its search,
   * sort, open details and the keyboard focus stay, and a big table is not searched per row.
   */
  function fillDmarc({ keepTable = false } = {}) {
    const m = dmarcModel();
    if (!m) return;
    const { agg, rows, overview } = m;
    if (keepTable && (sourcesTable || groupTable) && dmarcParts && dmarcParts.agg === agg) {
      keepFocus(dmarcPanel, () => {
        const head = dmarcHead(m);
        const tiles = classTiles(overview);
        dmarcParts.head.replaceWith(head);
        dmarcParts.tiles.replaceWith(tiles);
        dmarcParts = { agg, head, tiles };
        if (sourcesTable) {
          const drawn = new Map(sourcesTable.getRows().map((r) => [r.ip, r]));
          sourcesTable.updateRows(rows.filter((r) => {
            const old = drawn.get(r.ip);
            // A row whose SPF verdict changed may be named by another include too (its service is part of the row).
            return !old || sourceRowChanged(old, r);
          }));
        }
        if (groupTable) refreshGroups();
        updateIdentify();
      });
      return;
    }
    clear(dmarcPanel);
    const picker = domainPicker(S.dmarc.domains, agg.domain, (v) => {
      S.domain = v;
      S.cls = null;
      keepFocus(dmarcPanel, () => fillDmarc());
      checkSpf();
    }, (d) => d.messages, 'rpt.domainOption');
    if (picker) dmarcPanel.append(picker);
    const head = dmarcHead(m);
    const tiles = classTiles(overview);
    dmarcParts = { agg, head, tiles };
    dmarcPanel.append(head, tiles, sourcesSection(agg, rows), reportersSection(agg));
  }

  function dmarcHead({ agg, overview: o, line }) {
    const reporters = agg.reporters.map((r) => r.org);
    const shown = reporters.slice(0, 3).join(', ') + (reporters.length > 3 ? ` ${t('common.moreCount', { count: reporters.length - 3 })}` : '');
    const complianceVariant = o.compliance === null ? 'default' : o.compliance >= 0.98 ? 'ok' : o.compliance >= 0.9 ? 'warn' : 'error';
    const stats = h('div', { class: 'stat-grid rpt-stats' },
      StatCard({ label: t('rpt.stat.compliance'), value: o.compliance === null ? '—' : share(o.compliance), variant: complianceVariant,
        hint: t('rpt.stat.complianceHint', { pass: num(o.pass), total: num(o.messages) }) }).el,
      StatCard({ label: t('rpt.stat.messages'), value: o.messages }).el,
      StatCard({ label: t('rpt.stat.sources'), value: agg.sources.length }).el,
      StatCard({ label: t('rpt.stat.failing'), value: o.fail, variant: o.fail ? 'warn' : 'ok', hint: t('rpt.stat.failingHint') }).el);
    stats.querySelector('.stat .stat-value').classList.add('rpt-compliance');
    const p = agg.policy;
    const policy = h('p', { class: 'rpt-policy text-sm' }, h('span', { class: 'muted' }, `${t('rpt.policy')}: `),
      h('code', { class: 'mono' }, `p=${p.p}`), ' ', h('code', { class: 'mono' }, `sp=${p.sp}`),
      p.np ? [' ', h('code', { class: 'mono' }, `np=${p.np}`)] : null,
      ' ', h('code', { class: 'mono' }, `pct=${p.pct}`), p.testing ? [' ', h('code', { class: 'mono' }, `t=${p.testing}`)] : null,
      ' ', h('code', { class: 'mono' }, `adkim=${p.adkim}`), ' ', h('code', { class: 'mono' }, `aspf=${p.aspf}`));
    const look = verdictLook(o);
    const counts = o.verdict === 'spf-broken' ? { count: o.atRisk.length, messages: num(o.atRiskMessages) }
      : { count: o.blockers.length, messages: num(o.verdict === 'ready' ? o.unknownFail : o.blocked) };
    const verdict = Alert({ variant: look.variant, title: t(`rpt.verdict.${look.key}.title`), message: t(`rpt.verdict.${look.key}.body`, counts) });
    verdict.classList.add('rpt-verdict');
    verdict.dataset.verdict = o.verdict;
    verdict.dataset.look = look.key;
    const body = h('div', { class: 'stack' }, stats, policy, verdict);
    if (o.blockers.length || o.atRisk.length) body.append(fixFirst(agg, o));
    if (o.unknown.length) body.append(h('p', { class: 'rpt-unknown-line text-sm' }, Icon('alert', { size: 14 }), ' ', t('rpt.unknownLine', { count: o.unknown.length, messages: num(o.unknownFail) })));
    body.append(spfLine(agg, line, o));
    const noteParams = (n) => (n === 'spf-permerror'
      ? { count: o.spfError.sources, domain: o.spfError.domain, why: spfErrorText(o.spfError.reason) }
      : { count: agg.days, pct: p.pct, policies: agg.policies.map((x) => `p=${x}`).join(', ') });
    const notes = o.notes.filter((n) => n !== 'spf-unknown' || line !== null).map((n) => h('li', { dataset: { note: n } }, t(`rpt.note.${n}`, noteParams(n))));
    if (agg.skipped) notes.push(h('li', { dataset: { note: 'skipped' } }, t('rpt.skipped', { count: agg.skipped })));
    if (notes.length) body.append(h('ul', { class: 'rpt-notes text-sm muted' }, notes));
    if (agg.errors.length) body.append(Disclosure({ summary: t('rpt.errors'), className: 'rpt-reporter-errors', children: h('ul', null, agg.errors.slice(0, 20).map((e) => h('li', { class: 'mono text-sm' }, e))) }));
    return Card({
      className: 'rpt-head',
      title: h('span', { class: 'mono' }, agg.domain),
      subtitle: `${t('rpt.period', { from: day(agg.begin), to: day(agg.end) })} · ${t('rpt.reportsFrom', { count: agg.reports, reporters: shown })}`,
      icon: 'mail',
      children: body
    });
  }

  /** The words of a permerror's reason (health.SPF_PERMERROR_REASONS). */
  function spfErrorText(reason) {
    return t(`rpt.spfError.${reason || 'syntax'}`);
  }

  function fixText(r, f, domain) {
    return t(`rpt.fix.${f}`, { ...fixParams(r, f, domain), why: r.spfNow && r.spfNow.reason ? spfErrorText(r.spfNow.reason) : '' });
  }

  function fixFirst(agg, o) {
    // The sources that fail first, then those whose mail passed through SPF alone while the record now errs.
    const all = [...o.blockers, ...o.atRisk];
    const list = h('ol', { class: 'rpt-fix' }, all.slice(0, FIX_FIRST_MAX).map((r) => {
      const style = CLASS_STYLE[r.cls];
      const count = r.fail ? t('rpt.fix.failing', { fail: num(r.fail), messages: num(r.messages) }) : t('rpt.fix.spfOnly', { count: num(r.atRisk), messages: num(r.messages) });
      const svc = serviceLabel(identOf(r), t);
      return h('li', { class: 'rpt-fix-item', dataset: { ip: r.ip, cls: r.cls } },
        h('div', { class: 'rpt-fix-head' },
          h('span', { class: 'mono rpt-fix-ip' }, r.ip), ' ',
          svc ? [h('span', { class: 'rpt-fix-svc' }, svc.name), ' '] : null,
          Badge(t(`rpt.clsOne.${r.cls}`), { variant: style.variant, icon: style.icon }), ' ',
          h('span', { class: 'rpt-fix-why text-sm' }, whyText(r)), ' ',
          h('span', { class: 'rpt-fix-count text-sm' }, count)),
        r.fixes.length ? h('ul', { class: 'rpt-fix-steps text-sm' }, r.fixes.map((f) => h('li', { dataset: { fix: f } }, fixText(r, f, agg.domain)))) : null);
    }));
    const more = all.length > FIX_FIRST_MAX ? h('p', { class: 'text-sm muted' }, t('rpt.fix.more', { count: all.length - FIX_FIRST_MAX })) : null;
    return h('section', { class: 'rpt-fix-first', attrs: { 'aria-label': t('rpt.fixFirst') } }, h('h3', { class: 'rpt-subtitle' }, t('rpt.fixFirst')), list, more);
  }

  function spfLine(agg, line, o) {
    const c = S.spf.get(agg.domain);
    // The domain's own record gives receivers a permerror (for the most mail): the line says so and why.
    const broken = line === 'ok' && o.spfError && o.spfError.domain === agg.domain ? o.spfError.reason : null;
    let text;
    if (line === 'loading') text = t('rpt.spf.loading');
    else if (line === 'offline') text = t('rpt.spf.offline');
    else if (line === 'ok') text = [t('rpt.spf.ok', { time: formatDateTime(c.at) }), broken ? t('rpt.spf.broken', { why: spfErrorText(broken) }) : null].filter(Boolean).join(' · ');
    else if (line === 'none' || line === 'multiple') text = t(`rpt.spf.${line}`);
    else if (line === 'failed') text = t('rpt.spf.failed', { error: (c && c.error) || '' });
    else text = t('rpt.det.notChecked');
    // Busy, never disabled, while the lookup runs: the keyboard focus stays on it across the redraws.
    const loading = line === 'loading';
    const retry = Button({
      label: t('rpt.spf.retry'), icon: 'refresh', size: 'sm', variant: 'ghost', dataset: { action: 'rpt-spf-retry' },
      attrs: { 'aria-disabled': loading ? 'true' : null, 'aria-busy': loading ? 'true' : null },
      onClick: () => { if (!loading) checkSpf({ force: true, loud: true }); }
    });
    return h('div', { class: 'rpt-spf text-sm', dataset: { state: line || 'none-yet', error: broken } },
      h('span', { class: 'rpt-spf-label' }, Icon(line === 'ok' && !broken ? 'check-circle' : line === 'loading' ? 'clock' : 'alert', { size: 14 }), ' ', `${t('rpt.spf.label', { domain: agg.domain })}: `),
      h('span', null, text),
      c && c.record ? h('code', { class: 'mono rpt-spf-record' }, c.record) : null,
      retry);
  }

  function classTiles(o) {
    const tiles = SOURCE_CLASSES.map((cls) => {
      const b = o.byClass[cls];
      const style = CLASS_STYLE[cls];
      const tile = StatCard({
        label: t(`rpt.cls.${cls}`),
        value: b.messages,
        icon: style.icon,
        variant: style.tile || style.variant,
        hint: t('rpt.clsHint', { count: b.sources, pct: b.messages ? share(b.pass / b.messages) : '—' }),
        pressed: S.cls === cls,
        onClick: () => {
          S.cls = S.cls === cls ? null : cls;
          for (const el of grid.querySelectorAll('.stat-button')) el.setAttribute('aria-pressed', String(el.dataset.cls === S.cls));
          applyClassFilter();
          clearBtn.hidden = !S.cls;
        }
      });
      tile.el.dataset.cls = cls;
      tile.el.title = t(`rpt.clsDesc.${cls}`);
      tile.el.setAttribute('aria-label', `${t('rpt.clsFilter', { cls: t(`rpt.cls.${cls}`) })}: ${formatNumber(b.messages)}`);
      return tile.el;
    });
    const grid = h('div', { class: 'stat-grid rpt-cls' }, tiles);
    const clearBtn = Button({
      label: t('rpt.filterClear'), size: 'sm', variant: 'ghost', icon: 'x',
      dataset: { action: 'rpt-cls-clear' },
      onClick: () => {
        S.cls = null;
        for (const el of grid.querySelectorAll('.stat-button')) el.setAttribute('aria-pressed', 'false');
        applyClassFilter();
        clearBtn.hidden = true;
      }
    });
    clearBtn.hidden = !S.cls;
    return h('div', { class: 'stack-sm' }, grid, h('div', null, clearBtn));
  }

  function whyText(r) {
    return t(`rpt.why.${r.reason}`, { detail: r.detail || '' });
  }

  function alignedCell(passed, total) {
    const a = alignedState(passed, total);
    if (a.state === 'pass') return Badge(t('rpt.aligned.pass'), { variant: 'ok' });
    if (a.state === 'fail') return Badge(t('rpt.aligned.fail'), { variant: 'error' });
    return Badge(t('rpt.aligned.part', { pct: share(a.ratio) }), { variant: 'warn' });
  }

  function networkCell(r) {
    if (r.private) return h('span', { class: 'muted' }, t('rpt.intel.private'));
    const got = S.intel.get(r.ip);
    if (!got) {
      return Button({
        label: t('rpt.intel.one'), size: 'sm', variant: 'ghost', icon: 'search',
        dataset: { action: 'rpt-intel', ip: r.ip },
        ariaLabel: t('rpt.intel.oneLabel', { ip: r.ip }),
        onClick: () => lookUp([r.ip])
      });
    }
    if (got.loading) return h('span', { class: 'spinner spinner-inline', attrs: { role: 'status', 'aria-label': t('common.loading') } });
    const info = got.info;
    const parts = [];
    if (info.ptr && info.ptr.length) parts.push(h('span', { class: 'mono rpt-ptr' }, info.ptr[0]));
    else {
      const st = ipFieldStatus(info, 'ptr');
      parts.push(st ? NaMark(st.statuses) : h('span', { class: 'muted' }, `${t('rpt.det.ptr')}: ${t('rpt.intel.none')}`));
    }
    if (info.asn) parts.push(h('span', { class: 'rpt-asn text-sm' }, `AS${info.asn}${info.holder ? ` ${info.holder}` : ''}`));
    else {
      const st = ipFieldStatus(info, 'network');
      if (st) parts.push(NaMark(st.statuses));
    }
    return h('div', { class: 'rpt-net', dataset: { intel: 'done' } }, parts);
  }

  function dispositionText(r) {
    return DISPOSITIONS.filter((k) => r.dispositions[k]).map((k) => `${k} ${num(r.dispositions[k])}`).join(' · ');
  }

  function details(agg, r) {
    const auth = (list, fmt) => (list.length ? h('ul', { class: 'rpt-auth' }, list.map((a) => h('li', null, fmt(a), ' · ', t('rpt.det.count', { count: a.messages }))))
      : null);
    const verdict = r.spfNow;
    let spfNow = t('rpt.det.notChecked');
    if (verdict) {
      const result = t(`rpt.spfNow.${verdict.result}`);
      spfNow = verdict.term ? t('rpt.spfNow.by', { result, term: verdict.term, holder: verdict.holder || r.spfDomain || '' }) : result;
      if (verdict.result === 'unknown' && verdict.reason) spfNow = `${spfNow} (${t(`rpt.spfUnknown.${verdict.reason}`)})`;
      else if (verdict.result === 'permerror') spfNow = `${spfNow} (${spfErrorText(verdict.reason)})`;
    }
    const items = [
      ...serviceItems(agg, r),
      [t('rpt.det.headerFrom'), r.headerFrom.join(', ')],
      [t('rpt.det.envelopeFrom'), r.envelopeFrom.join(', ')],
      [t('rpt.det.spfAuth'), auth(r.spfAuth, (a) => h('span', null, h('span', { class: 'mono' }, a.domain), a.scope ? ` (${a.scope})` : '', ': ', h('b', null, a.result)))],
      [t('rpt.det.dkimAuth'), auth(r.dkimAuth, (a) => h('span', null, h('span', { class: 'mono' }, a.domain), a.selector ? h('span', { class: 'mono muted' }, ` / ${a.selector}`) : '', ': ', h('b', null, a.result)))],
      r.overrides.length ? [t('rpt.det.overrides'), auth(r.overrides, (o) => h('span', null, h('span', { class: 'mono' }, o.type), o.comment ? ` — ${o.comment}` : ''))] : null,
      [t('rpt.det.spfNow'), spfNow],
      [t('rpt.det.reporters'), r.reporters.join(', ')],
      [t('rpt.det.seen'), t('rpt.period', { from: day(r.begin), to: day(r.end) })],
      r.fixes.length ? [t('rpt.det.fixes'), h('ul', { class: 'rpt-auth' }, r.fixes.map((f) => h('li', null, fixText(r, f, agg.domain))))] : null
    ];
    return h('div', { class: 'stack-sm rpt-details' },
      KeyValueList(items.filter(Boolean)),
      r.private ? null : h('a', { class: 'text-sm', href: ctx.href('ip', { ips: r.ip, run: '0' }) }, Icon('network', { size: 14 }), ' ', t('rpt.det.openIp')));
  }

  /** A source's details on the service behind it: its name, how it was named, how to align it, its reverse DNS. */
  function serviceItems(agg, r) {
    const ident = identOf(r);
    const fact = S.ptr.get(r.ip);
    const ptr = fact ? [t('rpt.det.ptr'), t(`rpt.ptrState.${fact.status}`, { name: fact.name || '' })] : null;
    if (!ident) return [[t('rpt.det.service'), h('span', { class: 'muted' }, unnamedHint(r, unnamedState(r), t))], ptr].filter(Boolean);
    const label = serviceLabel(ident, t);
    const guide = senderGuide(ident, r);
    return [
      [t('rpt.det.service'), h('span', { class: 'rpt-det-svc', dataset: { service: ident.id || '', via: ident.via } }, `${label.name} — ${t(`rpt.svcType.${ident.type}`)}`)],
      [t('rpt.det.serviceHow'), serviceHow(ident, t)],
      guide ? [t('rpt.det.guide'), h('span', { class: 'rpt-guide', dataset: { guide } }, t(`rpt.guide.${guide}`, { service: ident.service, domain: agg.domain }))] : null,
      ptr
    ].filter(Boolean);
  }

  /** Whether a source's reverse DNS was looked up for good, or got no answer (the next click asks again). */
  function unnamedState(r) {
    const looked = lookedUp.has(r.ip);
    return { looked, failed: !looked && S.ptr.has(r.ip) };
  }

  /** The service line under an address: the name, its type and evidence under it; "not identified" once looked up in vain. */
  function serviceCell(r) {
    const ident = identOf(r);
    if (!ident) {
      // Looked up for good: "not identified"; never, or a lookup that got no answer: "—", the next click asks.
      const state = unnamedState(r);
      return h('span', { class: 'rpt-svc-none text-sm', dataset: { service: 'none' }, title: unnamedHint(r, state, t) },
        state.looked ? t('rpt.svc.none') : '—');
    }
    const label = serviceLabel(ident, t);
    return h('div', { class: 'rpt-svc', dataset: { service: ident.id || '', via: ident.via, confidence: ident.confidence }, title: serviceHow(ident, t) },
      h('span', { class: 'rpt-svc-name' }, label.name),
      h('span', { class: 'rpt-svc-meta' }, label.meta));
  }

  /** The sending addresses: one row per address, or folded per service. */
  function sourcesSection(agg, rows) {
    const view = SegmentedControl({
      label: t('rpt.view.label'),
      size: 'sm',
      className: 'rpt-view',
      value: S.view,
      options: SOURCE_VIEWS.map((v) => ({ value: v, label: t(`rpt.view.${v}`), icon: v === 'address' ? 'server' : 'layers' })),
      onChange: (v) => {
        S.view = v;
        keepFocus(dmarcPanel, () => fillSources(agg));
      }
    });
    sourcesBody = h('div', { class: 'stack-sm' });
    fillSources(agg, rows);
    return h('section', { class: 'stack-sm rpt-sources-section', attrs: { 'aria-label': t('rpt.sources') } },
      h('div', { class: 'rpt-sources-head' }, h('h3', { class: 'rpt-subtitle' }, t('rpt.sources')), view.el), sourcesBody);
  }

  function identifyButton() {
    identifyBtn = Button({
      label: t('rpt.id.bulk', { count: 0 }), size: 'sm', variant: 'secondary', icon: 'id-card',
      title: t('rpt.id.bulkTitle', { max: num(IDENTIFY_MAX), intel: num(INTEL_MAX) }),
      dataset: { action: 'rpt-identify' },
      onClick: () => identify()
    });
    return identifyBtn;
  }

  function fillSources(agg, rows = null) {
    if (!sourcesBody) return;
    clear(sourcesBody);
    sourcesTable = null;
    bulkBtn = null;
    groupTable = null;
    groupTotalsEl = null;
    if (S.view === 'service') sourcesBody.append(...servicesView(agg));
    else sourcesBody.append(addressTable(agg, rows || (dmarcModel() || { rows: [] }).rows));
    updateIdentify();
  }

  /** The service view: the totals, then one row per service with its sources, how it was named and how to align it. */
  function servicesView(agg) {
    const { groups, totals } = currentGroups();
    groupTotalsEl = h('p', { class: 'text-sm muted rpt-grp-totals', dataset: { role: 'rpt-grp-totals' } });
    fillTotals(totals);
    groupTable = DataTable({
      caption: t('rpt.grp.caption', { domain: agg.domain }),
      className: 'rpt-services',
      rowKey: (g) => g.key,
      rows: groups,
      search: true,
      // groupSources' order until a header is clicked: the services with the most mail first, "Not identified" last.
      sort: null,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      toolbar: identifyButton(),
      details: (g) => groupDetails(agg, g),
      onChange: () => updateIdentify(),
      export: {
        formats: ['csv'],
        onExport: (_format, shown) => {
          const file = downloadText(timestampedName('dmarc-services', 'csv', agg.domain),
            toCsv(serviceCsvRows(shown), SERVICE_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      rowClass: (g) => `rpt-grp-${g.key === 'unnamed' ? 'unnamed' : g.key === 'isp' ? 'isp' : 'named'}`,
      columns: [
        { key: 'service', label: t('rpt.col.service'), sortable: true, wrap: true,
          sortValue: (g) => (g.key === 'unnamed' ? null : groupName(g, t).toLowerCase()),
          searchValue: (g) => [groupName(g, t), g.type ? t(`rpt.svcType.${g.type}`) : '', ...g.evidence, ...g.rows.map((r) => r.ip)].join(' '),
          render: (g) => h('div', { class: 'rpt-svc', dataset: { group: g.key } },
            h('span', { class: g.key === 'unnamed' ? 'rpt-svc-name muted' : 'rpt-svc-name' }, groupName(g, t)),
            g.key === 'unnamed' ? null : h('span', { class: 'rpt-svc-meta' }, g.key === 'isp'
              ? g.evidence.slice(0, 3).join(', ') + (g.evidence.length > 3 ? ` ${t('common.moreCount', { count: g.evidence.length - 3 })}` : '')
              : `${t(`rpt.svcType.${g.type}`)} · ${g.vias.map((v) => t(`rpt.svcVia.${v}`)).join(', ')}`)) },
        { key: 'addresses', label: t('rpt.grp.col.addresses'), sortable: true, defaultDir: 'desc', align: 'end', className: 'rpt-grp-addr' },
        { key: 'messages', label: t('rpt.col.messages'), sortable: true, defaultDir: 'desc', align: 'end' },
        { key: 'pass', label: t('rpt.col.pass'), sortable: true, defaultDir: 'desc', align: 'end', sortValue: (g) => (g.messages ? g.pass / g.messages : 0),
          render: (g) => h('span', { class: ['rpt-pct', `rpt-pct-${alignedState(g.pass, g.messages).state}`] }, g.messages ? share(g.pass / g.messages) : '—') },
        { key: 'spf', label: t('rpt.col.spf'), sortable: true, sortValue: (g) => (g.messages ? g.spfAligned / g.messages : 0), render: (g) => alignedCell(g.spfAligned, g.messages) },
        { key: 'dkim', label: t('rpt.col.dkim'), sortable: true, sortValue: (g) => (g.messages ? g.dkimAligned / g.messages : 0), render: (g) => alignedCell(g.dkimAligned, g.messages) },
        { key: 'classes', label: t('rpt.grp.col.classes'), wrap: true, searchValue: (g) => Object.keys(g.classes).map((c) => t(`rpt.cls.${c}`)).join(' '),
          render: (g) => h('div', { class: 'rpt-grp-classes' }, SOURCE_CLASSES.filter((c) => g.classes[c]).map((c) => {
            const b = Badge(`${t(`rpt.clsOne.${c}`)} ${num(g.classes[c])}`, { variant: CLASS_STYLE[c].variant, icon: CLASS_STYLE[c].icon, title: t(`rpt.clsDesc.${c}`) });
            b.dataset.cls = c;
            return b;
          })) }
      ]
    });
    return [groupTotalsEl, groupTable.el];
  }

  /** A service group's details: how to align it, what named it, and its sending addresses. */
  function groupDetails(agg, g) {
    // From the classes of its sources: none when every one is yours (lib/senders.js groupGuide).
    const guide = groupGuide(g);
    const shown = g.rows.slice(0, GROUP_LIST_MAX);
    const items = [
      g.key === 'unnamed'
        ? [t('rpt.det.guide'), h('span', { class: 'rpt-guide', dataset: { guide: 'unnamed' } }, t('rpt.grp.unnamedHint'))]
        : guide ? [t('rpt.det.guide'), h('span', { class: 'rpt-guide', dataset: { guide } }, t(`rpt.guide.${guide}`, { service: g.service || '', domain: agg.domain }))] : null,
      g.vias.length ? [t('rpt.grp.via'), g.vias.map((v) => t(`rpt.svcVia.${v}`)).join(', ')] : null,
      g.evidence.length ? [t('rpt.grp.evidence'), h('span', { class: 'mono text-sm' }, g.evidence.slice(0, 8).join(', '), g.evidence.length > 8 ? ` ${t('common.moreCount', { count: g.evidence.length - 8 })}` : '')] : null,
      [t('rpt.grp.list'), h('ul', { class: 'rpt-grp-list' }, shown.map((r) => h('li', { dataset: { ip: r.ip } },
        h('span', { class: 'mono' }, r.ip), ' ',
        Badge(t(`rpt.clsOne.${r.cls}`), { variant: CLASS_STYLE[r.cls].variant, icon: CLASS_STYLE[r.cls].icon }), ' ',
        h('span', { class: 'text-sm muted' }, t('rpt.det.count', { count: r.messages })))),
      g.rows.length > shown.length ? h('li', { class: 'text-sm muted' }, t('common.moreCount', { count: num(g.rows.length - shown.length) })) : null)]
    ];
    return h('div', { class: 'stack-sm rpt-details' }, KeyValueList(items.filter(Boolean)));
  }

  /** The address view: one row per sending address. */
  function addressTable(agg, rows) {
    bulkBtn = Button({
      label: t('rpt.intel.bulk', { count: 0 }), size: 'sm', variant: 'secondary', icon: 'search',
      title: t('rpt.intel.bulkTitle', { max: INTEL_MAX }),
      dataset: { action: 'rpt-intel-all' },
      onClick: () => lookUp(sourcesTable.getVisibleRows().filter((r) => !r.private).map((r) => r.ip))
    });
    sourcesTable = DataTable({
      caption: t('rpt.sourcesCaption', { domain: agg.domain }),
      className: 'rpt-sources',
      rowKey: (r) => r.ip,
      rows,
      search: true,
      sort: { key: 'messages', dir: 'desc' },
      filter: S.cls ? (r) => r.cls === S.cls : null,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      toolbar: [bulkBtn, identifyButton()],
      details: (r) => details(agg, r),
      onChange: () => {
        updateBulk();
        updateIdentify();
      },
      export: {
        formats: ['csv'],
        onExport: (_format, shown) => {
          const file = downloadText(timestampedName('dmarc-sources', 'csv', agg.domain),
            toCsv(dmarcCsvRows(agg, shown, { serviceOf: identOf }), DMARC_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      rowClass: (r) => `rpt-row-${r.cls}`,
      columns: [
        // The service behind the address under it, in the same cell: a column of its own made the table some 220 px wider,
        // Network off the screen even at 1920 px.
        { key: 'ip', label: t('rpt.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip),
          searchValue: (r) => {
            const label = serviceLabel(identOf(r), t);
            return [r.ip, ...r.servers, label ? `${label.name} ${label.meta}` : ''].join(' ');
          },
          render: (r) => h('div', { class: 'rpt-addr' }, h('span', { class: 'mono rpt-ip', dataset: { ip: r.ip } }, r.ip), serviceCell(r)) },
        { key: 'cls', label: t('rpt.col.cls'), sortable: true, sortValue: (r) => SOURCE_CLASSES.indexOf(r.cls), searchValue: (r) => t(`rpt.cls.${r.cls}`),
          render: (r) => {
            const b = Badge(t(`rpt.clsOne.${r.cls}`), { variant: CLASS_STYLE[r.cls].variant, icon: CLASS_STYLE[r.cls].icon, title: t(`rpt.clsDesc.${r.cls}`) });
            b.dataset.cls = r.cls;
            return b;
          } },
        { key: 'messages', label: t('rpt.col.messages'), sortable: true, defaultDir: 'desc', align: 'end' },
        { key: 'pass', label: t('rpt.col.pass'), sortable: true, defaultDir: 'desc', align: 'end', sortValue: (r) => (r.messages ? r.pass / r.messages : 0),
          render: (r) => h('span', { class: ['rpt-pct', `rpt-pct-${alignedState(r.pass, r.messages).state}`] }, r.messages ? share(r.pass / r.messages) : '—') },
        { key: 'spf', label: t('rpt.col.spf'), sortable: true, sortValue: (r) => (r.messages ? r.spfAligned / r.messages : 0), render: (r) => alignedCell(r.spfAligned, r.messages) },
        { key: 'dkim', label: t('rpt.col.dkim'), sortable: true, sortValue: (r) => (r.messages ? r.dkimAligned / r.messages : 0), render: (r) => alignedCell(r.dkimAligned, r.messages) },
        { key: 'disposition', label: t('rpt.col.disposition'), searchValue: (r) => dispositionText(r), render: (r) => h('span', { class: 'mono text-sm' }, dispositionText(r)) },
        { key: 'why', label: t('rpt.col.why'), wrap: true, searchValue: (r) => whyText(r), render: (r) => h('span', { class: 'rpt-why text-sm' }, whyText(r)) },
        { key: 'network', label: t('rpt.col.network'), searchable: false, wrap: true, render: (r) => networkCell(r) }
      ]
    });
    updateBulk();
    return sourcesTable.el;
  }

  function reportersSection(agg) {
    const table = DataTable({
      caption: t('rpt.reporters'),
      className: 'rpt-reporters',
      rows: agg.reporters,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      sort: { key: 'messages', dir: 'desc' },
      columns: [
        { key: 'org', label: t('rpt.rep.org'), sortable: true },
        { key: 'reports', label: t('rpt.rep.reports'), sortable: true, align: 'end' },
        { key: 'messages', label: t('rpt.rep.messages'), sortable: true, align: 'end', defaultDir: 'desc' },
        { key: 'pass', label: t('rpt.rep.pass'), align: 'end', render: (r) => (r.messages ? share(r.pass / r.messages) : '—') },
        { key: 'period', label: t('rpt.rep.period'), render: (r) => t('rpt.period', { from: day(r.begin), to: day(r.end) }) }
      ]
    });
    return Disclosure({ summary: `${t('rpt.reporters')} (${num(agg.reporters.length)})`, className: 'rpt-reporters-box', children: table.el });
  }

  /* --- TLS-RPT ----------------------------------------------------------------------- */
  function tlsPanel() {
    const panel = h('div', { class: 'stack rpt-tls' });
    const fill = () => {
      clear(panel);
      const s = tlsOf(S.tlsDomain);
      if (!s) return;
      const picker = domainPicker(S.tls.domains, s.domain, (v) => {
        S.tlsDomain = v;
        keepFocus(panel, fill);
      }, (d) => d.success + d.failure, 'rpt.tls.domainOption');
      if (picker) panel.append(picker);
      panel.append(tlsHead(s));
      if (s.byType.length) panel.append(tlsTypes(s), tlsFailures(s));
      panel.append(tlsSenders(s));
    };
    fill();
    return panel;
  }

  function tlsHead(s) {
    const total = s.success + s.failure;
    const variant = s.rate === null ? 'default' : s.rate >= 0.99 ? 'ok' : s.rate >= 0.9 ? 'warn' : 'error';
    const stats = h('div', { class: 'stat-grid rpt-stats' },
      StatCard({ label: t('rpt.tls.stat.rate'), value: s.rate === null ? '—' : share(s.rate), variant, hint: t('rpt.tls.stat.rateHint', { ok: num(s.success), total: num(total) }) }).el,
      StatCard({ label: t('rpt.tls.stat.sessions'), value: total }).el,
      StatCard({ label: t('rpt.tls.stat.failed'), value: s.failure, variant: s.failure ? 'warn' : 'ok' }).el,
      StatCard({ label: t('rpt.tls.stat.senders'), value: s.orgs.length }).el);
    stats.querySelector('.stat .stat-value').classList.add('rpt-tls-rate');
    const policies = h('ul', { class: 'rpt-tls-policies' }, s.policies.map((p) => h('li', { dataset: { policy: p.type } },
      Badge(TLS_POLICY_TYPES.includes(p.type) ? t(`rpt.tls.policy.${p.type}`) : p.type, { variant: p.type === 'no-policy-found' ? 'neutral' : 'accent', icon: p.type === 'no-policy-found' ? null : 'lock' }),
      p.mode ? [' ', h('code', { class: 'mono' }, `mode: ${p.mode}`)] : null,
      ' ', h('span', { class: 'text-sm muted' }, t('rpt.tls.policySessions', { ok: num(p.success), failed: num(p.failure) })))));
    const body = h('div', { class: 'stack' }, stats,
      h('div', { class: 'stack-sm' }, h('h3', { class: 'rpt-subtitle' }, t('rpt.tls.policies')), policies));
    if (!total) body.append(Alert({ variant: 'info', message: t('rpt.tls.noSessions') }));
    else if (!s.failure) body.append(Alert({ variant: 'ok', message: t('rpt.tls.allOk') }));
    return Card({
      className: 'rpt-tls-head',
      title: h('span', { class: 'mono' }, s.domain),
      subtitle: `${t('rpt.period', { from: day(s.begin), to: day(s.end) })} · ${t('rpt.reportsFrom', { count: s.reports, reporters: s.orgs.map((o) => o.org).join(', ') })}`,
      icon: 'lock',
      children: body
    });
  }

  function toolLink(tool, s, type) {
    const mx = type.mx[0] || null;
    if (tool === 'health') return h('a', { href: ctx.href('health', { domain: s.domain, run: '0' }), dataset: { tool } }, t('rpt.tls.tool.health'));
    if (!mx || mx.startsWith('*.')) return null;
    if (tool === 'tlsa') return h('a', { href: ctx.href('lookup', { name: `_25._tcp.${mx}`, type: 'TLSA', dnssec: '1' }), dataset: { tool } }, t('rpt.tls.tool.tlsa', { mx }));
    return h('a', { href: ctx.href('cert', { host: mx, run: '0' }), dataset: { tool } }, t('rpt.tls.tool.cert', { mx }));
  }

  function tlsTypes(s) {
    return h('section', { class: 'stack-sm', attrs: { 'aria-label': t('rpt.tls.failTitle') } },
      h('h3', { class: 'rpt-subtitle' }, t('rpt.tls.failTitle')),
      h('div', { class: 'rpt-tls-types' }, s.byType.map((ty) => {
        const advice = tlsAdvice(ty.type);
        const known = TLS_RESULT_TYPES.includes(ty.type);
        const links = advice.tools.filter((x) => TLS_TOOLS.includes(x)).map((tool) => toolLink(tool, s, ty)).filter(Boolean);
        return h('article', { class: 'rpt-tls-type', dataset: { type: ty.type } },
          h('div', { class: 'rpt-tls-type-head' },
            Icon('alert', { size: 16, className: 'rpt-tls-type-icon' }),
            h('h4', { class: 'rpt-tls-type-title' }, known ? t(`rpt.tls.type.${ty.type}`) : t('rpt.tls.type.other')),
            h('code', { class: 'mono text-sm muted' }, ty.type)),
          h('p', { class: 'text-sm rpt-tls-facts' }, t('rpt.tls.typeFacts', { count: ty.sessions, mx: ty.mx.join(', ') || '—', orgs: ty.orgs.join(', ') })),
          h('p', { class: 'text-sm' }, t(`rpt.tls.advice.${advice.type}`, { domain: s.domain })),
          ty.reasons.length ? h('p', { class: 'text-sm muted' }, t('rpt.tls.reasons', { reasons: ty.reasons.slice(0, 3).join(' · ') })) : null,
          links.length ? h('p', { class: 'rpt-tls-links text-sm' }, links.flatMap((a, i) => (i ? [' · ', a] : [a]))) : null);
      })));
  }

  function tlsFailures(s) {
    const table = DataTable({
      caption: t('rpt.tls.failuresCaption', { domain: s.domain }),
      className: 'rpt-tls-failures',
      rows: s.failures,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      search: true,
      sort: { key: 'failed_sessions', dir: 'desc' },
      export: {
        formats: ['csv'],
        onExport: (_format, shown) => {
          const file = downloadText(timestampedName('tls-rpt-failures', 'csv', s.domain),
            toCsv(tlsCsvRows({ failures: shown }), TLS_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      columns: [
        { key: 'result_type', label: t('rpt.tls.col.type'), sortable: true, mono: true },
        { key: 'receiving_mx', label: t('rpt.tls.col.mx'), sortable: true, mono: true },
        { key: 'receiving_ip', label: t('rpt.tls.col.rip'), sortable: true, mono: true, sortValue: (r) => ipSortValue(r.receiving_ip) },
        { key: 'organization', label: t('rpt.tls.col.org'), sortable: true },
        { key: 'sending_mta_ip', label: t('rpt.tls.col.sip'), mono: true },
        { key: 'failed_sessions', label: t('rpt.tls.col.sessions'), sortable: true, align: 'end', defaultDir: 'desc' },
        { key: 'policy_type', label: t('rpt.tls.col.policy'), mono: true },
        { key: 'failure_reason_code', label: t('rpt.tls.col.reason'), wrap: true, mono: true }
      ]
    });
    return h('section', { class: 'stack-sm', attrs: { 'aria-label': t('rpt.tls.failures') } }, h('h3', { class: 'rpt-subtitle' }, t('rpt.tls.failures')), table.el);
  }

  function tlsSenders(s) {
    const table = DataTable({
      caption: t('rpt.tls.senders'),
      className: 'rpt-tls-senders',
      rows: s.orgs,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      columns: [
        { key: 'org', label: t('rpt.rep.org') },
        { key: 'reports', label: t('rpt.rep.reports'), align: 'end' },
        { key: 'success', label: t('rpt.tls.col.ok'), align: 'end' },
        { key: 'failure', label: t('rpt.tls.col.failed'), align: 'end' }
      ]
    });
    return Disclosure({ summary: `${t('rpt.tls.senders')} (${num(s.orgs.length)})`, className: 'rpt-tls-senders-box', children: table.el });
  }

  rerender = ({ keep = false } = {}) => {
    if (keep) refreshDmarc();
    else renderAll();
  };
  renderAll();
  // Coming back with reports read before: the SPF of a domain not looked up yet, or not while offline
  // (quietly again: nothing is said when the browser still is).
  if (hasReports() && S.domain && (!S.spfState.has(S.domain) || S.spfState.get(S.domain) === 'offline')) checkSpf();

  active = {
    teardown() {
      work.abort();
      stopReading();
      rerender = null;
      // A lookup the unmount stopped is not "loading" any more: the next visit asks again.
      for (const [d, st] of S.spfState) if (st === 'loading') S.spfState.delete(d);
      for (const [ip, got] of S.intel) if (got.loading) S.intel.delete(ip);
      // Identify senders stops with the view; what it looked up stays (S.ptr).
      S.identifying = null;
    }
  };
}

/** Detach the view (the reports stay in this module's memory). */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * That reports were read, or null. They stay in this module, so the shell keeps only the fact
 * (lib/session.js); no subject and no route params: nothing about them goes into a URL. Its note
 * says "Reports read at <time>", with no "Run again" (there is nothing to run).
 * @returns {{ subject: null, at: Date, rerun: false, label: string }|null}
 */
export function result() {
  return S.loadedAt && (S.dmarcReports.length || S.tlsReports.length) ? { subject: null, at: S.loadedAt, rerun: false, label: 'rpt.kept' } : null;
}

export default { id, titleKey, icon, mount, unmount, result };
