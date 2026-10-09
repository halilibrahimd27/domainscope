/**
 * views/monitor.js — "Monitoring": the headless runner's results (tools/ds.mjs) over time — the
 * `--json` reports a nightly repository commits (results/NAME.json) and the history it keeps with
 * `--history results/history` (one line per target and check a night, YYYY-MM.jsonl) — as one row
 * per target, the counts that need a look, the change timeline and its CSV.
 *
 * - Sources: files or the results folder (a drop zone and a folder picker: read in the browser,
 *   never uploaded), or the repository itself on GitHub (lib/monitorfetch.js: the user's
 *   fine-grained token, read from its password field once per click and emptied then, sent to
 *   api.github.com only; never stored, logged or put in a URL). Nothing is sent before a click,
 *   and nothing at all from the files.
 * - lib/monitor.js does the work: the reports are checked with the runner's own shape rules,
 *   the history lines parsed (a bad line skipped and counted), merged and read into the rows
 *   (monitorRows), the tiles (monitorTiles), the timeline (timelineEntries) and the sparklines.
 * - The page, on the page template (docs/DESIGN.md §5; ui/template.js, a "File" tool): the source
 *   card (region 2: the drop zone with its pickers and how-to while nothing is open, then one row —
 *   what was read, Add files, the folder picker, Forget —, or the GitHub form; the privacy note),
 *   then the result header (`.mon-summary`: the targets and the last check, the status summary —
 *   lib/monitor.js monitorStatus: targets with bad changes in 7 days, certificates under 21 days,
 *   checks that did not complete, each a filter of the targets —, Copy summary with ¶
 *   (lib/monitorsummary.js: names only), the timeline's CSV, the links to the nightly issue and the
 *   run) and two tabs: Targets (the counts as a read-only metric strip, the target table with a
 *   sparkline of the health score and of the soonest certificate expiry, and its Show select) and
 *   Changes (the timeline filtered by command, target and tone; the CSV is of what it shows).
 * - The results are kept in this module's memory only: a reload, Forget, another workspace or
 *   "Delete all local data" drops them; leaving the view stops a GitHub read. What Home counts of
 *   them — the tiles' numbers, when the newest check ran and the import time, never a target — goes
 *   to the workspace part `digests` after each import ({@link monitorDigestOf}, lib/digests.js);
 *   Forget removes it.
 *
 * Pure helpers are exported for the unit tests (tests/js/monitor-view.test.js); the module is
 * DOM-free at import time.
 */

import { h, append, clear, svg } from '../ui/dom.js';
import {
  Alert, Badge, Button, CodeBlock, DataTable, Disclosure, ExternalLink, FileDrop, Icon, IconButton, RelativeTime, SegmentedControl, Spinner, Tabs,
  announce, checkbox, select, textInput, toast
} from '../ui/components.js';
import { EmptyState, MetricStrip, PrivacyNote, ResultActions, ResultHeader, ResultTitle, StatusSummary } from '../ui/template.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { registerSummaryBuilder } from '../lib/summarycore.js';
import { monitorSummary, MONITOR_SUMMARY_I18N } from '../lib/monitorsummary.js';
import { formatDate, formatDateTime, formatNumber, formatRelative, registerStrings } from '../i18n.js';
import {
  MONITOR_COMMANDS, MONITOR_FILE_ERRORS, MONITOR_MAX_BYTES, MONITOR_RECENT_DAYS, MONITOR_WARN_DAYS, TIMELINE_TONES, TLS_WORST, commandOrder,
  emptyMonitor, filterTimeline, latestRun, monitorRows, monitorStatus, monitorSummaryFacts, monitorTiles, readMonitorFiles, repoOfRun, rowMatches,
  sparkPoints, timelineCsv, timelineEntries
} from '../lib/monitor.js';
import { monitorDigest, withDigest } from '../lib/digests.js';
import {
  GITHUB_FETCH_ERRORS, GITHUB_HISTORY_MONTHS, GITHUB_MAX_FILES, GITHUB_MONTH_CHOICES, GITHUB_TOKEN_DOCS, GITHUB_TOKEN_URL, GITHUB_WEB, cleanToken, fetchResults, parseRepo,
  repoLinks
} from '../lib/monitorfetch.js';

/** Route id (`#/monitor`). */
export const id = 'monitor';
/** i18n key of the page title. */
export const titleKey = 'nav.monitor';
/** Nav/page icon. */
export const icon = 'eye';

/** The tile filters of the target table. */
export const MONITOR_FILTERS = Object.freeze(['all', 'bad', 'expiring', 'incomplete']);
/** The sources of the results. */
export const MONITOR_SOURCES = Object.freeze(['files', 'github']);
/** The change tags the runner writes (tools/ds/render.mjs CHANGE_TAGS): each has a tooltip in both languages. */
export const MONITOR_TAGS = Object.freeze(['NEW', 'GONE', 'WORSE', 'BETTER', 'CHANGED', 'FAILED', 'RECOVERED', 'FAILING', 'SCORE', 'ISSUER', 'NAME', 'CERT', 'CA',
  'EXPIRING', 'REVOKED', 'EXPOSED', 'DANGLING', 'RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'RISK', 'WAIVED', 'LAPSED',
  'EXPIRED', 'UNTRUSTED', 'MISMATCH', 'NOT-LIVE', 'HTTP', 'REDIRECT', 'HSTS',
  'REGISTRAR', 'LOCK', 'STATUS', 'NS', 'DS', 'EXPIRY', 'RECORD', 'SERIAL', 'FLAPPING', 'SYNC', 'LAME']);
/** Timeline entries shown at first, and per "Show more". */
export const TIMELINE_PAGE = 100;
/** Files one drop or folder reads at most (a year of month files and every report, with room). */
const MAX_FILES = 200;
/** The command the template offers (the history the trends are drawn from). */
export const HISTORY_EXAMPLE = 'node tools/ds.mjs health --list domains.txt --baseline results/health.json --json results/health.json --history results/history';

// Copy summary's builder and texts load with this view, not on the start route (lib/monitorsummary.js).
registerSummaryBuilder('monitor', monitorSummary);
registerStrings('en', MONITOR_SUMMARY_I18N.en);
registerStrings('tr', MONITOR_SUMMARY_I18N.tr);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'mon.privacy': 'The results are read here and kept only in this tab: nothing is uploaded or stored, and a reload, Forget, another workspace or “Delete all local data” clears them.',
  'mon.source.title': 'Results',
  'mon.source.label': 'Where the results come from',
  'mon.source.files': 'Files or folder',
  'mon.source.github': 'GitHub',
  'mon.drop.title': 'Drop the nightly results here',
  'mon.drop.hint': 'or click to choose · the results folder of your nightly repository: results/*.json and results/history/*.jsonl',
  'mon.choose': 'Choose files',
  'mon.folder': 'Choose the results folder',
  'mon.how.summary': 'Where the results come from',
  'mon.how.body': 'The nightly template (docs/examples/nightly-domainscope.yml) runs the headless runner every night and commits its reports to the results folder of your repository. With --history results/history it also keeps one line per domain and check a night, 13 months of them: the trends here are drawn from those lines. Open the folder from a copy of the repository, or read it from GitHub.',
  'mon.forget': 'Forget',
  'mon.forgotten': 'Results forgotten',
  'mon.read': 'Read: {reports} · {months} · {lines}',
  'mon.read.reports': { one: '{count} report', other: '{count} reports' },
  'mon.read.months': { one: '{count} month of history', other: '{count} months of history' },
  'mon.read.lines': { one: '{count} line', other: '{count} lines' },
  'mon.imported': { one: '{count} file read', other: '{count} files read' },
  'mon.duplicate': '{name}: the same report is already open',
  'mon.tooMany': 'Too many reports at once: the rest were not read.',
  'mon.skippedLines': { one: '{count} line of the history was not one the runner writes and was skipped.', other: '{count} lines of the history were not ones the runner writes and were skipped.' },
  'mon.errorsTitle': 'Not read',
  'mon.error.too-large': '{name}: larger than {max}',
  'mon.error.not-json': '{name}: not JSON. Choose the results/NAME.json the runner wrote with --json.',
  'mon.error.not-report': '{name}: not a report of the headless runner (tools/ds.mjs)',
  'mon.error.version': '{name}: written by version {detail} of the runner, which this page cannot read',
  'mon.error.damaged': '{name}: a damaged report ({detail})',
  'mon.error.not-results': '{name}: neither a report (.json) nor a history file (.jsonl)',
  'mon.error.empty-history': '{name}: no line of it is a history line ({detail} skipped)',
  'mon.emptyLine': 'A row per target with its trends, the counts that need a look and every night’s changes.',
  'mon.addFiles': 'Add files',
  'mon.addHint': 'or drop them here',
  'mon.resultsTitle': { one: 'Nightly results · {count} target', other: 'Nightly results · {count} targets' },
  'mon.lastCheck': 'Last check {time}',
  'mon.tabs': 'The results',
  'mon.tab.targets': 'Targets',
  'mon.status.bad': { one: '{count} target with bad changes', other: '{count} targets with bad changes' },
  'mon.status.expiring': { one: '{count} certificate under {days} days', other: '{count} certificates under {days} days' },
  'mon.status.incomplete': { one: '{count} check did not complete', other: '{count} checks did not complete' },
  'mon.status.targets': { one: '{count} target', other: '{count} targets' },
  'mon.filter.label': 'Show',
  'mon.filter.all': 'All targets ({count})',
  'mon.filter.bad': 'With bad changes in {days} days ({count})',
  'mon.filter.expiring': 'With a certificate under {days} days ({count})',
  'mon.filter.incomplete': 'With a check that did not complete ({count})',
  'mon.gh.intro': 'Read the results straight from the repository the nightly template commits to, with a fine-grained token of yours. It only reads.',
  'mon.gh.repo': 'Repository',
  'mon.gh.token': 'Fine-grained token',
  'mon.gh.months': 'History',
  'mon.gh.monthsOption': { one: 'the last month', other: 'the last {count} months' },
  'mon.gh.issue': 'Also read the open nightly issue (the token needs Issues: read-only)',
  'mon.gh.how': 'Make the token with Repository access: only this repository, and Repository permissions: Contents read-only (Issues read-only for the issue). An expiry of a few days is enough.',
  'mon.gh.link.token': 'New fine-grained token',
  'mon.gh.link.docs': 'How fine-grained tokens work',
  'mon.gh.privacy': 'Your token is sent only to api.github.com, in a request header, for this one read of at most {max} files. It stays in this tab’s memory for that read only: it is never saved (not in the browser, not in a workspace), never logged, and this field is emptied as soon as you press Load from GitHub.',
  'mon.gh.go': 'Load from GitHub',
  'mon.gh.stop': 'Stop',
  'mon.gh.running': 'Reading the results of {repo}…',
  'mon.gh.progress.list': 'Listing results/',
  'mon.gh.progress.file': 'File {done} of {total}',
  'mon.gh.progress.issue': 'Looking for the open issue',
  'mon.gh.stopped': 'Stopped. Nothing was read.',
  'mon.gh.done': { one: '{count} file read from {repo}.', other: '{count} files read from {repo}.' },
  'mon.gh.skipped': { one: '{count} file was left out (at most {max} a read, or too large).', other: '{count} files were left out (at most {max} a read, or too large).' },
  'mon.gh.rate': '{count} GitHub API requests left this hour.',
  'mon.gh.issueError.forbidden': 'The open issue could not be read: the token has no Issues permission.',
  'mon.gh.issueError.other': 'The open issue could not be read.',
  'mon.gh.err.title': 'The results could not be read',
  'mon.gh.err.repo': 'Enter the repository as owner/repo, for example example-org/nightly.',
  'mon.gh.err.token': 'Paste the token: one line without spaces, 20 to 255 characters.',
  'mon.gh.err.auth': 'GitHub did not accept the token (HTTP 401): it is wrong, expired or revoked. Make a new one and paste it again.',
  'mon.gh.err.forbidden': 'GitHub refused (HTTP 403): the token is not allowed to read this repository’s contents. Give it access to this repository with Contents read-only.',
  'mon.gh.err.not-found': 'GitHub found no results folder (HTTP 404): the repository does not exist, the token cannot see it, or nothing was committed to results/ yet.',
  'mon.gh.err.rate-limited': 'GitHub is limiting this token’s requests. Try again after {time}.',
  'mon.gh.err.rateLater': 'GitHub is limiting this token’s requests. Try again later.',
  'mon.gh.err.http': 'GitHub answered HTTP {status}.',
  'mon.gh.err.network': 'GitHub could not be reached. The network, a firewall or a browser extension may be blocking api.github.com.',
  'mon.gh.err.timeout': 'GitHub did not answer in time. Try again.',
  'mon.gh.err.response': 'GitHub sent something that is not a folder listing.',
  'mon.gh.err.empty': 'The results folder holds no report (.json) and no history (results/history/*.jsonl).',
  'mon.gh.err.detail': 'GitHub said: “{detail}”',
  'mon.gh.err.again': 'The token field was emptied: paste the token again to retry.',
  'mon.stat.bad': 'Bad changes',
  'mon.stat.badHint': { one: '{count} target, last {days} days', other: '{count} targets, last {days} days' },
  'mon.stat.expiring': 'Certificates under {days} days',
  'mon.stat.expiringHint': 'soonest: {name}',
  'mon.stat.expiringNone': 'none expires that soon',
  'mon.stat.incomplete': 'Did not complete',
  'mon.stat.incompleteHint': 'checks, latest runs',
  'mon.stat.targets': 'Targets',
  'mon.stat.targetsHint': { one: 'from {count} report', other: 'from {count} reports' },
  'mon.stat.targetsHistory': 'from the history',
  'mon.stat.label': 'The targets in numbers',
  'mon.link.issue': 'Nightly issue #{number}',
  'mon.link.issues': 'Open nightly issues',
  'mon.link.run': 'Latest run',
  'mon.link.actions': 'Actions runs',
  'mon.table.caption': 'Targets',
  'mon.search': 'Filter targets',
  'mon.noMatch': 'No target passes this filter.',
  'mon.col.target': 'Target',
  'mon.col.trend': 'Trend',
  'mon.col.health': 'Health',
  'mon.col.certs': 'Certificates',
  'mon.col.problems': 'Takeover · audit',
  'mon.col.changes': 'Last {days} days',
  'mon.col.status': 'Checks',
  'mon.spark.score': { one: 'Health score, {count} night: {last}', other: 'Health score over {count} nights: {first} → {last}' },
  'mon.spark.days': { one: 'Soonest certificate expiry, {count} night: {last} days', other: 'Soonest certificate expiry over {count} nights: {first} → {last} days' },
  'mon.days': { one: '{count} day left', other: '{count} days left' },
  'mon.expiredAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'mon.newIssuers': { one: '{count} new issuer', other: '{count} new issuers' },
  'mon.unexpected': { one: '{count} unexpected CA', other: '{count} unexpected CAs' },
  'mon.revoked': { one: '{count} revoked', other: '{count} revoked' },
  'mon.risks': { one: '{count} takeover risk', other: '{count} takeover risks' },
  'mon.risksNone': 'no takeover risk',
  'mon.auditFail': { one: '{count} rule fails', other: '{count} rules fail' },
  'mon.auditPass': 'every rule passes',
  'mon.security': 'security {score}/{max}',
  'mon.badChanges': { one: '{count} bad change', other: '{count} bad changes' },
  'mon.noBad': 'no bad change',
  'mon.lastChange': 'last: {tag} · {when}',
  'mon.completed': 'completed',
  'mon.incompleteCheck': 'did not complete',
  'mon.staleCheck': 'not run since {date}',
  'mon.checkedAt': 'checked {when}',
  'mon.fromHistory': 'from the history',
  'mon.showChanges': 'Show the changes of {target}',
  'mon.d.command': 'Check',
  'mon.d.when': 'Last run',
  'mon.d.state': 'State',
  'mon.d.facts': 'Found',
  'mon.d.changes': 'Changes',
  'mon.d.changesValue': '{bad} bad · {info} other',
  'mon.d.report': 'report {name}',
  'mon.f.score': 'score {score}',
  'mon.f.errors': { one: '{count} error', other: '{count} errors' },
  'mon.f.warnings': { one: '{count} warning', other: '{count} warnings' },
  'mon.f.current': { one: '{count} current certificate', other: '{count} current certificates' },
  'mon.f.endpoints': { one: '{count} address', other: '{count} addresses' },
  'mon.f.verdict': 'verdict {verdict}',
  'mon.tl.title': 'Changes',
  'mon.tl.command': 'Check',
  'mon.tl.target': 'Target',
  'mon.tl.tone': 'Show',
  'mon.tl.allCommands': 'All checks',
  'mon.tl.allTargets': 'All targets',
  'mon.tl.none': 'No change matches this filter.',
  'mon.tl.empty': 'No change recorded: the history is quiet, or the runs had no baseline to compare with.',
  'mon.tl.more': 'Show {count} more',
  'mon.tl.run': 'run',
  'mon.tl.counted': 'counted',
  'mon.tl.countedTitle': 'It counted: it opened or updated the nightly issue (--fail-on-change)',
  'mon.csvTitle': 'The changes this filter shows, one row each',
  'mon.csvDone': '{file} downloaded',
  'mon.tone.all': 'All',
  'mon.tone.bad': 'Bad',
  'mon.tone.good': 'Good',
  'mon.tone.info': 'Other',
  'mon.cmd.health': 'Health',
  'mon.cmd.ct': 'CT',
  'mon.cmd.tls': 'TLS',
  'mon.cmd.takeover': 'Takeover',
  'mon.cmd.audit': 'Policy',
  'mon.cmd.subdomains': 'Subdomains',
  'mon.cmd.drift': 'Zone drift',
  'mon.cmd.renew': 'Renewal',
  'mon.cmd.dane': 'DANE',
  'mon.cmd.watch': 'Change watch',
  'mon.tls.EXPIRED': 'expired',
  'mon.tls.UNTRUSTED': 'untrusted',
  'mon.tls.NAME_MISMATCH': 'name mismatch',
  'mon.tls.NOT_DEPLOYED': 'renewal not installed',
  'mon.tls.EXPIRING': 'expiring',
  'mon.tls.TLS_ERROR': 'TLS error',
  'mon.tls.TIMEOUT': 'timed out',
  'mon.tls.CLOSED': 'closed',
  'mon.tls.OK': 'served fine',
  'mon.tls.SKIPPED': 'skipped',
  'mon.tag.NEW': 'Appeared since the night before',
  'mon.tag.GONE': 'Gone since the night before',
  'mon.tag.WORSE': 'Got worse',
  'mon.tag.BETTER': 'Got better',
  'mon.tag.CHANGED': 'Changed',
  'mon.tag.FAILED': 'A lookup or a check started failing',
  'mon.tag.RECOVERED': 'Answers again after a failure',
  'mon.tag.FAILING': 'Still failing, in another way',
  'mon.tag.SCORE': 'The health score moved',
  'mon.tag.ISSUER': 'A certificate issuer new to Certificate Transparency for the domain',
  'mon.tag.NAME': 'A name new to Certificate Transparency for the domain',
  'mon.tag.CERT': 'Another certificate',
  'mon.tag.CA': 'A certificate from a CA that was not expected',
  'mon.tag.EXPIRING': 'A current certificate crossed an expiry radar threshold',
  'mon.tag.REVOKED': 'A certificate was revoked',
  'mon.tag.EXPOSED': 'A host behind a CDN now answers directly',
  'mon.tag.DANGLING': 'A CNAME points at nothing',
  'mon.tag.RENEW-NOW': 'The CA’s renewal window (ARI) opened',
  'mon.tag.MOVED-UP': 'The CA moved its renewal window earlier',
  'mon.tag.CA-NOTICE': 'The CA published an explanation for its renewal window',
  'mon.tag.RISK': 'A new takeover risk',
  'mon.tag.WAIVED': 'A problem was accepted as a risk until an end date (listed only)',
  'mon.tag.LAPSED': 'An accepted risk ended: the problem counts again',
  'mon.tag.EXPIRED': 'A served certificate has expired',
  'mon.tag.UNTRUSTED': 'A host serves a certificate chain that clients do not trust',
  'mon.tag.MISMATCH': 'A host serves a certificate without its name',
  'mon.tag.NOT-LIVE': 'A renewal was issued but the host still serves the older certificate',
  'mon.tag.HTTP': 'GET / now answers with a server error',
  'mon.tag.REDIRECT': 'Plain HTTP no longer redirects to HTTPS',
  'mon.tag.HSTS': 'The HSTS header got weaker',
  'mon.tag.REGISTRAR': 'The domain moved to another registrar',
  'mon.tag.LOCK': 'A transfer lock was removed or added',
  'mon.tag.STATUS': 'A registry status changed: a hold, a pending delete or transfer, a redemption period',
  'mon.tag.NS': 'The name servers changed',
  'mon.tag.DS': 'The DS records at the parent changed',
  'mon.tag.EXPIRY': 'The registration’s expiry changed',
  'mon.tag.RECORD': 'A DNS record set changed',
  'mon.tag.SERIAL': 'The SOA serial moved',
  'mon.tag.FLAPPING': 'A record set keeps changing',
  'mon.tag.SYNC': 'Name servers answer one serial differently',
  'mon.tag.LAME': 'A name server does not answer with authority'
});

registerStrings('tr', {
  'mon.privacy': 'Sonuçlar burada okunur ve yalnızca bu sekmede tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler.',
  'mon.source.title': 'Sonuçlar',
  'mon.source.label': 'Sonuçların kaynağı',
  'mon.source.files': 'Dosya ya da klasör',
  'mon.source.github': 'GitHub',
  'mon.drop.title': 'Gece kontrollerinin sonuçlarını buraya bırakın',
  'mon.drop.hint': 'ya da seçmek için tıklayın · gece kontrollerini çalıştıran deponuzdaki results klasörü: results/*.json ve results/history/*.jsonl',
  'mon.choose': 'Dosya seç',
  'mon.folder': 'results klasörünü seç',
  'mon.how.summary': 'Sonuçlar nereden gelir',
  'mon.how.body': 'Gece şablonu (docs/examples/nightly-domainscope.yml) headless çalıştırıcıyı her gece çalıştırır ve raporlarını deponuzun results klasörüne commit’ler. --history results/history ile her gece her alan adı ve kontrol için bir satır da tutar (13 aylık): buradaki eğilimler bu satırlardan çizilir. Klasörü deponun bir kopyasından açın ya da GitHub’dan okuyun.',
  'mon.forget': 'Unut',
  'mon.forgotten': 'Sonuçlar unutuldu',
  'mon.read': 'Okunan: {reports} · {months} · {lines}',
  'mon.read.reports': { other: '{count} rapor' },
  'mon.read.months': { other: '{count} aylık geçmiş' },
  'mon.read.lines': { other: '{count} satır' },
  'mon.imported': { other: '{count} dosya okundu' },
  'mon.duplicate': '{name}: aynı rapor zaten açık',
  'mon.tooMany': 'Aynı anda çok fazla rapor: kalanlar okunmadı.',
  'mon.skippedLines': { other: 'Geçmişin çalıştırıcının yazdığı türden olmayan {count} satırı atlandı.' },
  'mon.errorsTitle': 'Okunmadı',
  'mon.error.too-large': '{name}: {max} boyutundan büyük',
  'mon.error.not-json': '{name}: JSON değil. Çalıştırıcının --json ile yazdığı results/AD.json dosyasını seçin.',
  'mon.error.not-report': '{name}: headless çalıştırıcının (tools/ds.mjs) bir raporu değil',
  'mon.error.version': '{name}: çalıştırıcının bu sayfanın okuyamadığı {detail} sürümüyle yazılmış',
  'mon.error.damaged': '{name}: bozuk bir rapor ({detail})',
  'mon.error.not-results': '{name}: ne bir rapor (.json) ne de bir geçmiş dosyası (.jsonl)',
  'mon.error.empty-history': '{name}: hiçbir satırı bir geçmiş satırı değil ({detail} satır atlandı)',
  'mon.emptyLine': 'Hedef başına eğilimleriyle bir satır, bakılması gereken sayılar ve her gecenin değişiklikleri.',
  'mon.addFiles': 'Dosya ekle',
  'mon.addHint': 'ya da buraya bırakın',
  'mon.resultsTitle': 'Gece sonuçları · {count} hedef',
  'mon.lastCheck': 'Son kontrol: {time}',
  'mon.tabs': 'Sonuçlar',
  'mon.tab.targets': 'Hedefler',
  'mon.status.bad': '{count} hedefte kötü değişiklik',
  'mon.status.expiring': '{days} günden az kalan {count} sertifika',
  'mon.status.incomplete': '{count} kontrol tamamlanmadı',
  'mon.status.targets': '{count} hedef',
  'mon.filter.label': 'Göster',
  'mon.filter.all': 'Bütün hedefler ({count})',
  'mon.filter.bad': '{days} günde kötü değişikliği olanlar ({count})',
  'mon.filter.expiring': '{days} günden az kalan sertifikası olanlar ({count})',
  'mon.filter.incomplete': 'Tamamlanmayan kontrolü olanlar ({count})',
  'mon.gh.intro': 'Sonuçları, gece şablonunun commit’lediği depodan doğrudan, size ait ince ayarlı (fine-grained) bir anahtarla okuyun. Bu sayfa yalnızca okur.',
  'mon.gh.repo': 'Depo',
  'mon.gh.token': 'İnce ayarlı (fine-grained) anahtar',
  'mon.gh.months': 'Geçmiş',
  'mon.gh.monthsOption': { one: 'son ay', other: 'son {count} ay' },
  'mon.gh.issue': 'Açık gece issue’sunu da oku (anahtarın Issues: read-only izni olmalı)',
  'mon.gh.how': 'Anahtarı Repository access: yalnızca bu depo ve Repository permissions: Contents read-only (issue için Issues read-only) ile oluşturun. Birkaç günlük geçerlilik süresi yeterli.',
  'mon.gh.link.token': 'Yeni ince ayarlı anahtar',
  'mon.gh.link.docs': 'İnce ayarlı anahtarlar nasıl çalışır',
  'mon.gh.privacy': 'Anahtarınız bir istek başlığında, en fazla {max} dosyalık bu tek okuma için yalnızca api.github.com adresine gönderilir. Okuma sürdükçe bu sekmenin belleğinde durur: hiçbir yere kaydedilmez (ne tarayıcıya ne bir çalışma alanına), günlüğe yazılmaz ve GitHub’dan yükle’ye bastığınız anda bu alan boşaltılır.',
  'mon.gh.go': 'GitHub’dan yükle',
  'mon.gh.stop': 'Durdur',
  'mon.gh.running': '{repo} sonuçları okunuyor…',
  'mon.gh.progress.list': 'results/ listeleniyor',
  'mon.gh.progress.file': 'Dosya {done} / {total}',
  'mon.gh.progress.issue': 'Açık issue aranıyor',
  'mon.gh.stopped': 'Durduruldu. Hiçbir şey okunmadı.',
  'mon.gh.done': { other: '{repo} deposundan {count} dosya okundu.' },
  'mon.gh.skipped': { other: '{count} dosya dışarıda kaldı (bir okumada en fazla {max} dosya, ya da çok büyük).' },
  'mon.gh.rate': 'Bu saat için {count} GitHub API isteği kaldı.',
  'mon.gh.issueError.forbidden': 'Açık issue okunamadı: anahtarın Issues izni yok.',
  'mon.gh.issueError.other': 'Açık issue okunamadı.',
  'mon.gh.err.title': 'Sonuçlar okunamadı',
  'mon.gh.err.repo': 'Depoyu sahip/depo olarak girin, örneğin example-org/nightly.',
  'mon.gh.err.token': 'Anahtarı yapıştırın: boşluksuz tek satır, 20 ile 255 karakter arası.',
  'mon.gh.err.auth': 'GitHub anahtarı kabul etmedi (HTTP 401): anahtar yanlış, süresi dolmuş ya da iptal edilmiş. Yeni bir anahtar oluşturup yeniden yapıştırın.',
  'mon.gh.err.forbidden': 'GitHub reddetti (HTTP 403): anahtarın bu deponun içeriğini okuma izni yok. Anahtara bu depoya erişim ve Contents read-only izni verin.',
  'mon.gh.err.not-found': 'GitHub results klasörünü bulamadı (HTTP 404): depo yok, anahtar onu göremiyor ya da results/ klasörüne henüz bir şey commit’lenmedi.',
  'mon.gh.err.rate-limited': 'GitHub bu anahtarın isteklerini sınırlıyor. {time} sonrasında yeniden deneyin.',
  'mon.gh.err.rateLater': 'GitHub bu anahtarın isteklerini sınırlıyor. Daha sonra yeniden deneyin.',
  'mon.gh.err.http': 'GitHub HTTP {status} ile yanıt verdi.',
  'mon.gh.err.network': 'GitHub’a ulaşılamadı. Ağ, bir güvenlik duvarı ya da bir tarayıcı eklentisi api.github.com adresini engelliyor olabilir.',
  'mon.gh.err.timeout': 'GitHub zamanında yanıt vermedi. Yeniden deneyin.',
  'mon.gh.err.response': 'GitHub klasör listesi olmayan bir yanıt gönderdi.',
  'mon.gh.err.empty': 'results klasöründe ne bir rapor (.json) ne de geçmiş (results/history/*.jsonl) var.',
  'mon.gh.err.detail': 'GitHub yanıtı: “{detail}”',
  'mon.gh.err.again': 'Anahtar alanı boşaltıldı: tekrar denemek için anahtarı yeniden yapıştırın.',
  'mon.stat.bad': 'Kötü değişiklikler',
  'mon.stat.badHint': { other: '{count} hedef, son {days} gün' },
  'mon.stat.expiring': '{days} günden az kalan sertifikalar',
  'mon.stat.expiringHint': 'ilk dolacak: {name}',
  'mon.stat.expiringNone': 'bu kadar yakında dolan yok',
  'mon.stat.incomplete': 'Tamamlanmayan',
  'mon.stat.incompleteHint': 'kontrol, son çalışmalar',
  'mon.stat.targets': 'Hedefler',
  'mon.stat.targetsHint': { other: '{count} rapordan' },
  'mon.stat.targetsHistory': 'geçmişten',
  'mon.stat.label': 'Sayılarla hedefler',
  'mon.link.issue': 'Gece issue’su #{number}',
  'mon.link.issues': 'Açık gece issue’ları',
  'mon.link.run': 'Son çalışma',
  'mon.link.actions': 'Actions çalışmaları',
  'mon.table.caption': 'Hedefler',
  'mon.search': 'Hedefleri süz',
  'mon.noMatch': 'Bu süzgece uyan hedef yok.',
  'mon.col.target': 'Hedef',
  'mon.col.trend': 'Eğilim',
  'mon.col.health': 'Sağlık',
  'mon.col.certs': 'Sertifikalar',
  'mon.col.problems': 'Ele geçirme · politika',
  'mon.col.changes': 'Son {days} gün',
  'mon.col.status': 'Kontroller',
  'mon.spark.score': { one: 'Sağlık puanı, {count} gece: {last}', other: '{count} gece boyunca sağlık puanı: {first} → {last}' },
  'mon.spark.days': { one: 'İlk dolacak sertifika, {count} gece: {last} gün', other: '{count} gece boyunca ilk dolacak sertifika: {first} → {last} gün' },
  'mon.days': { other: '{count} gün kaldı' },
  'mon.expiredAgo': { other: '{count} gün önce doldu' },
  'mon.newIssuers': { other: '{count} yeni sertifika sağlayıcısı' },
  'mon.unexpected': { other: '{count} beklenmeyen CA' },
  'mon.revoked': { other: '{count} iptal edilmiş' },
  'mon.risks': { other: '{count} ele geçirme riski' },
  'mon.risksNone': 'ele geçirme riski yok',
  'mon.auditFail': { other: '{count} kural geçmiyor' },
  'mon.auditPass': 'her kural geçiyor',
  'mon.security': 'güvenlik {score}/{max}',
  'mon.badChanges': { other: '{count} kötü değişiklik' },
  'mon.noBad': 'kötü değişiklik yok',
  'mon.lastChange': 'son: {tag} · {when}',
  'mon.completed': 'tamamlandı',
  'mon.incompleteCheck': 'tamamlanmadı',
  'mon.staleCheck': '{date} tarihinden beri çalışmadı',
  'mon.checkedAt': 'kontrol: {when}',
  'mon.fromHistory': 'geçmişten',
  'mon.showChanges': '{target} değişikliklerini göster',
  'mon.d.command': 'Kontrol',
  'mon.d.when': 'Son çalışma',
  'mon.d.state': 'Durum',
  'mon.d.facts': 'Bulunan',
  'mon.d.changes': 'Değişiklikler',
  'mon.d.changesValue': '{bad} kötü · {info} diğer',
  'mon.d.report': '{name} raporu',
  'mon.f.score': 'puan {score}',
  'mon.f.errors': { other: '{count} hata' },
  'mon.f.warnings': { other: '{count} uyarı' },
  'mon.f.current': { other: '{count} geçerli sertifika' },
  'mon.f.endpoints': { other: '{count} adres' },
  'mon.f.verdict': 'sonuç {verdict}',
  'mon.tl.title': 'Değişiklikler',
  'mon.tl.command': 'Kontrol',
  'mon.tl.target': 'Hedef',
  'mon.tl.tone': 'Göster',
  'mon.tl.allCommands': 'Tüm kontroller',
  'mon.tl.allTargets': 'Tüm hedefler',
  'mon.tl.none': 'Bu süzgece uyan değişiklik yok.',
  'mon.tl.empty': 'Kayıtlı değişiklik yok: geçmiş sakin ya da çalışmaların karşılaştıracağı bir önceki rapor yoktu.',
  'mon.tl.more': '{count} tane daha göster',
  'mon.tl.run': 'çalışma',
  'mon.tl.counted': 'sayıldı',
  'mon.tl.countedTitle': 'Sayıldı: gece issue’sunu açtı ya da güncelledi (--fail-on-change)',
  'mon.csvTitle': 'Bu süzgecin gösterdiği değişiklikler, her biri bir satır',
  'mon.csvDone': '{file} indirildi',
  'mon.tone.all': 'Tümü',
  'mon.tone.bad': 'Kötü',
  'mon.tone.good': 'İyi',
  'mon.tone.info': 'Diğer',
  'mon.cmd.health': 'Sağlık',
  'mon.cmd.ct': 'CT',
  'mon.cmd.tls': 'TLS',
  'mon.cmd.takeover': 'Ele geçirme',
  'mon.cmd.audit': 'Politika',
  'mon.cmd.subdomains': 'Alt alan adları',
  'mon.cmd.drift': 'Zone sapması',
  'mon.cmd.renew': 'Yenileme',
  'mon.cmd.dane': 'DANE',
  'mon.cmd.watch': 'Değişiklik izleme',
  'mon.tls.EXPIRED': 'süresi dolmuş',
  'mon.tls.UNTRUSTED': 'güvenilmiyor',
  'mon.tls.NAME_MISMATCH': 'ad uyuşmuyor',
  'mon.tls.NOT_DEPLOYED': 'yenileme kurulmadı',
  'mon.tls.EXPIRING': 'süresi doluyor',
  'mon.tls.TLS_ERROR': 'TLS hatası',
  'mon.tls.TIMEOUT': 'zaman aşımı',
  'mon.tls.CLOSED': 'bağlantı kapandı',
  'mon.tls.OK': 'sorunsuz sunuluyor',
  'mon.tls.SKIPPED': 'atlandı',
  'mon.tag.NEW': 'Önceki geceden bu yana ortaya çıktı',
  'mon.tag.GONE': 'Önceki geceden bu yana kayboldu',
  'mon.tag.WORSE': 'Kötüleşti',
  'mon.tag.BETTER': 'İyileşti',
  'mon.tag.CHANGED': 'Değişti',
  'mon.tag.FAILED': 'Bir sorgu ya da kontrol başarısız olmaya başladı',
  'mon.tag.RECOVERED': 'Bir hatadan sonra yeniden yanıt veriyor',
  'mon.tag.FAILING': 'Hâlâ başarısız, başka bir şekilde',
  'mon.tag.SCORE': 'Sağlık puanı değişti',
  'mon.tag.ISSUER': 'Alan adı için Sertifika Şeffaflığı’nda yeni bir sertifika sağlayıcısı',
  'mon.tag.NAME': 'Alan adı için Sertifika Şeffaflığı’nda yeni bir ad',
  'mon.tag.CERT': 'Başka bir sertifika',
  'mon.tag.CA': 'Beklenmeyen bir CA’dan bir sertifika',
  'mon.tag.EXPIRING': 'Geçerli bir sertifika bir bitiş eşiğini geçti',
  'mon.tag.REVOKED': 'Bir sertifika iptal edildi',
  'mon.tag.EXPOSED': 'CDN arkasındaki bir host artık doğrudan yanıt veriyor',
  'mon.tag.DANGLING': 'Bir CNAME hiçbir şeyi göstermiyor',
  'mon.tag.RENEW-NOW': 'CA’nın yenileme penceresi (ARI) açıldı',
  'mon.tag.MOVED-UP': 'CA yenileme penceresini öne çekti',
  'mon.tag.CA-NOTICE': 'CA yenileme penceresi için bir açıklama yayımladı',
  'mon.tag.RISK': 'Yeni bir ele geçirme riski',
  'mon.tag.WAIVED': 'Bir sorun bir bitiş tarihine kadar risk olarak kabul edildi (yalnızca listelenir)',
  'mon.tag.LAPSED': 'Kabul edilen riskin süresi doldu: sorun yeniden sayılıyor',
  'mon.tag.EXPIRED': 'Sunulan bir sertifikanın süresi doldu',
  'mon.tag.UNTRUSTED': 'Bir host istemcilerin güvenmediği bir sertifika zinciri sunuyor',
  'mon.tag.MISMATCH': 'Bir host adını taşımayan bir sertifika sunuyor',
  'mon.tag.NOT-LIVE': 'Bir yenileme alındı ama host hâlâ eski sertifikayı sunuyor',
  'mon.tag.HTTP': 'GET / artık sunucu hatasıyla yanıt veriyor',
  'mon.tag.REDIRECT': 'Düz HTTP artık HTTPS’ye yönlendirmiyor',
  'mon.tag.HSTS': 'HSTS başlığı zayıfladı',
  'mon.tag.REGISTRAR': 'Alan adı başka bir kayıt firmasına geçti',
  'mon.tag.LOCK': 'Bir transfer kilidi kaldırıldı ya da eklendi',
  'mon.tag.STATUS': 'Kayıt kuruluşundaki bir durum değişti: askıya alma, bekleyen silme ya da transfer, geri alma dönemi',
  'mon.tag.NS': 'Ad sunucuları değişti',
  'mon.tag.DS': 'Üst zone’daki DS kayıtları değişti',
  'mon.tag.EXPIRY': 'Kaydın bitiş tarihi değişti',
  'mon.tag.RECORD': 'Bir DNS kayıt kümesi değişti',
  'mon.tag.SERIAL': 'SOA seri numarası ilerledi',
  'mon.tag.FLAPPING': 'Bir kayıt kümesi sürekli değişiyor',
  'mon.tag.SYNC': 'Ad sunucuları aynı seri numarasında farklı yanıt veriyor',
  'mon.tag.LAME': 'Bir ad sunucusu yetkiyle yanıt vermiyor'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/** Every i18n key this module builds from a library code (for the coverage test). */
export function generatedKeys() {
  return [
    ...MONITOR_FILE_ERRORS.map((c) => `mon.error.${c}`),
    ...GITHUB_FETCH_ERRORS.map((c) => `mon.gh.err.${c}`),
    ...MONITOR_COMMANDS.map((c) => `mon.cmd.${c}`),
    ...TLS_WORST.map((s) => `mon.tls.${s}`),
    ...TIMELINE_TONES.map((s) => `mon.tone.${s}`),
    ...MONITOR_TAGS.map((s) => `mon.tag.${s}`),
    ...['list', 'file', 'issue'].map((p) => `mon.gh.progress.${p}`),
    ...['forbidden', 'other'].map((c) => `mon.gh.issueError.${c}`),
    ...['files', 'github'].map((s) => `mon.source.${s}`)
  ];
}

/**
 * The open results with files read into them (lib/monitor.js readMonitorFiles): what was added, what
 * could not be read and the duplicates, for the toasts and the error list.
 * @param {{ reports: object[], lines: object[], files: object[] }|null} data
 * @param {Array<{ name: string, text: string|null, source?: string }>} files
 */
export function importFiles(data, files) {
  return readMonitorFiles(data || emptyMonitor(), files);
}

/**
 * What the page draws of the open results, days counted from `now`.
 * @param {{ reports: object[], lines: object[] }} data
 * @param {number} [now]
 * @returns {{ rows: object[], tiles: object, entries: object[] }|null} null: nothing open
 */
export function viewOf(data, now = Date.now()) {
  if (!data || (!data.reports.length && !data.lines.length)) return null;
  const rows = monitorRows(data, { now });
  return { rows, tiles: monitorTiles(rows), entries: timelineEntries(data) };
}

/**
 * What Home counts of the open results (the workspace part `digests`, lib/digests.js): the tiles'
 * numbers — targets, targets with a bad change in the last MONITOR_RECENT_DAYS days, certificates
 * under MONITOR_WARN_DAYS days, checks that did not complete —, when the newest check ran and when
 * they were opened here. Counts only: no target is named.
 * @param {{ rows: object[], tiles: object }|null} view {@link viewOf}
 * @param {{ reports: object[], lines: object[] }} data
 * @param {number} [now]
 * @returns {object|null} null when nothing is open
 */
export function monitorDigestOf(view, data, now = Date.now()) {
  if (!view || !data) return null;
  const facts = monitorSummaryFacts(view.rows, view.tiles, data);
  return monitorDigest({
    at: facts.at || new Date(now), imported: new Date(now),
    targets: view.tiles.targets, bad: view.tiles.bad.length, expiring: view.tiles.expiring.length, incomplete: view.tiles.incomplete.length
  });
}

/** Badge variant of a number of days left. */
export function daysVariant(days) {
  if (days === null || days === undefined) return 'neutral';
  if (days < 7) return 'error';
  if (days < MONITOR_WARN_DAYS) return 'warn';
  return 'ok';
}

/** Badge variant of a health grade. */
export function gradeVariant(grade) {
  return { A: 'ok', B: 'ok', C: 'info', D: 'warn', E: 'error', F: 'error' }[grade] || 'neutral';
}

/** Badge variant of a change's tone. */
export function toneVariant(tone) {
  return { bad: 'error', good: 'ok', info: 'info' }[tone] || 'neutral';
}

/** Badge variant of a `tls` status. */
export function tlsVariant(status) {
  if (status === 'OK') return 'ok';
  if (status === 'SKIPPED' || !status) return 'neutral';
  if (['EXPIRING', 'TLS_ERROR', 'TIMEOUT', 'CLOSED'].includes(status)) return 'warn';
  return 'error';
}

/** The repository the results came from: GitHub's, else the one a run link of the history names on github.com. */
export function repoOf(source, data) {
  if (source) return source;
  const run = repoOfRun(latestRun(data));
  return run && run.server === GITHUB_WEB ? { owner: run.owner, repo: run.repo } : null;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Page-session state (module memory only; see the module comment). `gh`: the repository typed
 * (never the token), the months and issue choices, the running read and its outcome.
 */
const S = {
  data: null, problems: [], skippedLines: 0, source: 'files', filter: 'all', tab: 'targets', tl: { command: '', target: '', tone: 'all', shown: TIMELINE_PAGE },
  repo: null, issue: null, issueError: null,
  gh: { repo: '', months: GITHUB_HISTORY_MONTHS, issue: false, job: null, error: null, notice: null }
};
let subscribed = false;
let rerender = null;
/** What the page draws of the open results ({@link viewOf}), computed once per dataset and minute: a tile, a filter or "Show more" redraws without it. */
let drawn = { data: null, minute: -1, view: null };

/** The view of the open results now (days and the 7-day window counted from this minute). */
function currentView() {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  if (drawn.data !== S.data || drawn.minute !== minute) drawn = { data: S.data, minute, view: viewOf(S.data, now) };
  return drawn.view;
}

/** Stop a running GitHub read. */
function stopRead() {
  if (S.gh.job) S.gh.job.controller.abort();
  S.gh.job = null;
}

function forgetAll() {
  stopRead();
  drawn = { data: null, minute: -1, view: null };
  S.data = null;
  S.problems = [];
  S.skippedLines = 0;
  S.filter = 'all';
  S.tab = 'targets';
  S.tl = { command: '', target: '', tone: 'all', shown: TIMELINE_PAGE };
  S.repo = null;
  S.issue = null;
  S.issueError = null;
  S.gh = { ...S.gh, repo: '', job: null, error: null, notice: null };
}

/**
 * Mount the view.
 * @param {HTMLElement} container
 * @param {object} ctx view context (app.js)
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  if (!subscribed && state && typeof state.subscribe === 'function') {
    subscribed = true;
    state.subscribe(({ key }) => {
      // The results are the customer's: another workspace forgets them like "Delete all local data".
      if (key === 'cleared' || key === 'workspace') {
        forgetAll();
        if (rerender) rerender();
      }
    });
  }
  // Region 2 (the source card: files or GitHub) and the result (the empty state, or the result
  // header and the tabs): drawn apart, so a source switch or a GitHub read in progress leaves the
  // table as it is.
  const sourceHost = h('div', { class: 'mon-source-host' });
  const resultsHost = h('div', { class: 'mon-results-host' });
  const root = h('div', { class: 'mon-page' }, sourceHost, resultsHost);
  container.append(root);
  rerender = () => render();
  ctx.onCleanup(() => {
    rerender = null;
    // leaving the view stops a GitHub read (the repository typed stays for this page session)
    stopRead();
  });

  const num = (n) => formatNumber(n);
  /** The GitHub panel on the page now repaints its status line (progress) without a rebuild that would take the focus from Stop. */
  let paintGhStatus = null;
  const cmdName = (c) => (MONITOR_COMMANDS.includes(c) ? t(`mon.cmd.${c}`) : c);
  const when = (ms) => formatDateTime(new Date(ms), { utc: true });
  const day = (ms) => formatDate(new Date(ms), { utc: true });
  const daysText = (d) => (d < 0 ? t('mon.expiredAgo', { count: -d }) : t('mon.days', { count: d }));

  /* --- region 4: the result header (one for the life of the view; `.mon-summary`) ---------- */
  const head = ResultHeader({ className: 'mon-summary' });
  // The counts as filters of the Targets table: a press shows that tab filtered; a second press shows every target.
  const status = StatusSummary({ items: [] });
  head.set('status', status.el);
  /** The head's actions (Copy summary with ¶, the timeline's CSV): drawn with the result. */
  let actions = null;
  ctx.onCleanup(() => { if (actions) actions.dispose(); });
  /** The result's tabs (Targets · Changes), the targets table and its Show select, while results are open. */
  let tabs = null;
  let table = null;
  let filterSelect = null;
  /** The Changes tab's panel: its filters, the timeline and "Show more" (drawn again on its own). */
  const timelineHost = h('div', { class: 'mon-timeline', dataset: { role: 'mon-timeline' } });

  function importAndShow(files, { replace = false } = {}) {
    const result = importFiles(replace ? null : S.data, files);
    S.data = result.data;
    S.problems = result.problems;
    S.skippedLines = (replace ? 0 : S.skippedLines) + result.skippedLines;
    for (const name of result.duplicates) toast(t('mon.duplicate', { name }), { type: 'info' });
    if (result.capped) toast(t('mon.tooMany'), { type: 'warn' });
    const read = result.added.reports + result.added.history;
    if (read) {
      const msg = t('mon.imported', { count: read });
      announce(msg);
      toast(msg, { type: 'success', timeout: 2500 });
    }
    render();
    keepDigest();
    // The keyboard focus goes to the result (its title), or back to the drop zone when nothing was read.
    if (read && head.el.isConnected) head.focusTitle();
    else focus('.mon-drop');
  }

  /** Home's counts of the open results go to the workspace (none when nothing is open). */
  function keepDigest() {
    if (!state || typeof state.setWorkspaceData !== 'function') return;
    const before = state.workspaceData('digests') || '';
    const next = withDigest(before, 'monitor', monitorDigestOf(currentView(), S.data));
    if (next !== before) Promise.resolve(state.setWorkspaceData('digests', next)).catch(() => {});
  }

  function forget() {
    forgetAll();
    keepDigest();
    toast(t('mon.forgotten'), { type: 'info' });
    render();
    const target = root.querySelector('.mon-drop, [data-role="mon-gh-repo"]');
    if (target) target.focus({ preventScroll: true });
  }

  /** The status item that stands for a filter (pressed while it applies): none for every target. */
  const statusOfFilter = (f) => (f !== 'all' && MONITOR_FILTERS.includes(f) ? f : null);

  /** The targets table follows the filter (the status summary and the Show select say it). */
  function setFilter(filter) {
    S.filter = MONITOR_FILTERS.includes(filter) ? filter : 'all';
    if (table) table.setFilter((r) => rowMatches(r, S.filter));
    status.setPressed(statusOfFilter(S.filter));
    if (filterSelect) filterSelect.value = S.filter;
  }

  /** A status item pressed: the Targets tab with its filter (pressed again, or the targets: every target). */
  function pressStatus(item) {
    setFilter(item.filter === 'all' || S.filter === item.filter ? 'all' : item.filter);
    if (tabs && tabs.getSelected() !== 'targets') tabs.select('targets');
  }

  /* --- render ------------------------------------------------------------ */
  function render() {
    renderSource();
    renderResults();
  }

  /* --- region 2: the source (DESIGN §5.5, a "File" tool) ---------------------------- */
  /**
   * One card: where the results come from (files or GitHub). While nothing is open the files
   * source is a drop zone with its pickers and how-to; once results are open it is one row — what
   * was read, Add files (a small drop zone: a click chooses, a drop reads), the folder picker and
   * Forget. The privacy note closes the card.
   */
  function renderSource() {
    clear(sourceHost);
    const has = !!S.data;
    const sourceControl = SegmentedControl({
      label: t('mon.source.label'),
      size: 'sm',
      value: S.source,
      className: 'mon-source',
      options: MONITOR_SOURCES.map((s) => ({ value: s, label: t(`mon.source.${s}`), icon: s === 'files' ? 'folder' : 'git-branch' })),
      onChange: (v) => {
        S.source = v;
        renderSource();
      }
    });
    const errors = S.problems.length ? Alert({
      variant: 'warn',
      title: t('mon.errorsTitle'),
      children: h('ul', { class: 'mon-errors' }, S.problems.map((p) => h('li', null, t(`mon.error.${p.error}`, {
        name: p.name, detail: p.detail || '?', max: `${Math.round(MONITOR_MAX_BYTES / 1048576)} MB`
      }))))
    }) : null;
    const compact = has && S.source === 'files';
    sourceHost.append(h('div', {
      class: ['tool-input', 'card', 'file-input', 'mon-source-card', { 'is-compact': compact }],
      attrs: { role: 'group', 'aria-label': t('mon.source.title') }
    },
    sourceControl.el,
    has ? readRow() : null,
    S.source === 'github' ? githubPanel() : compact ? null : filesPanel(),
    errors,
    h('div', { class: 'tool-input-foot' }, PrivacyNote({ text: t('mon.privacy') }))));
  }

  /** The files read, with Add files and the folder picker (the files source) and Forget: the compact row. */
  function readRow() {
    const files = S.source === 'files';
    const drop = files ? fileDrop({ compact: true }) : null;
    return h('div', { class: 'file-input-row' },
      h('p', { class: 'file-input-summary' }, Icon('folder', { size: 16 }), h('span', { class: 'mon-read', dataset: { role: 'mon-read' } }, t('mon.read', {
        reports: t('mon.read.reports', { count: S.data.reports.length }),
        months: t('mon.read.months', { count: S.data.files.filter((f) => f.kind === 'history').length }),
        lines: t('mon.read.lines', { count: S.data.lines.length })
      }))),
      h('div', { class: 'file-input-actions' },
        drop ? drop.el : null,
        drop && drop.openFolder ? Button({ label: t('mon.folder'), icon: 'folder', size: 'sm', variant: 'secondary', dataset: { action: 'mon-folder' }, onClick: () => drop.openFolder() }) : null,
        Button({ label: t('mon.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'mon-forget' }, onClick: forget })));
  }

  /** The drop zone of the results folder: full while nothing is open, "Add files" in the compact row. */
  function fileDrop({ compact = false } = {}) {
    const drop = FileDrop({
      accept: '.json,.jsonl',
      multiple: true,
      directory: true,
      maxFiles: MAX_FILES,
      maxBytes: MONITOR_MAX_BYTES,
      compact,
      icon: compact ? 'upload' : 'folder',
      title: compact ? t('mon.addFiles') : t('mon.drop.title'),
      hint: compact ? t('mon.addHint') : t('mon.drop.hint'),
      className: 'mon-drop',
      paste: true,
      onFiles: (files) => importAndShow(files)
    });
    // '/' focuses it (the shell's focus shortcut).
    drop.el.dataset.shortcut = 'focus';
    return drop;
  }

  function filesPanel() {
    const drop = fileDrop();
    const buttons = [Button({ label: t('mon.choose'), icon: 'upload', size: 'sm', variant: 'primary', dataset: { action: 'mon-choose' }, onClick: () => drop.open() })];
    if (drop.openFolder) buttons.push(Button({ label: t('mon.folder'), icon: 'folder', size: 'sm', variant: 'secondary', dataset: { action: 'mon-folder' }, onClick: () => drop.openFolder() }));
    const how = Disclosure({
      summary: t('mon.how.summary'),
      className: 'mon-how',
      open: true,
      children: h('div', { class: 'stack-sm' }, h('p', { class: 'text-sm' }, t('mon.how.body')), CodeBlock(HISTORY_EXAMPLE, { label: 'ds', wrap: true }))
    });
    return h('div', { class: 'stack-sm mon-files' }, drop.el, h('div', { class: 'file-input-buttons' }, buttons), how);
  }

  function githubPanel() {
    const gh = S.gh;
    const running = !!gh.job;
    const body = h('div', { class: 'stack-sm mon-gh', dataset: { shortcutScope: 'mon-gh' } });
    const repoField = textInput({
      label: t('mon.gh.repo'),
      value: gh.repo,
      placeholder: 'example-org/nightly',
      mono: true,
      attrs: { 'data-role': 'mon-gh-repo', inputmode: 'url' },
      onInput: (v) => {
        gh.repo = String(v || '');
      },
      onEnter: () => start()
    });
    // A password field: never echoed, never autofilled or offered for saving; read once on Load.
    const tokenField = textInput({
      label: t('mon.gh.token'),
      type: 'password',
      mono: true,
      autocomplete: 'off',
      attrs: { 'data-role': 'mon-gh-token', 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-form-type': 'other' },
      onEnter: () => start()
    });
    const months = select({
      label: t('mon.gh.months'),
      size: 'sm',
      className: 'mon-gh-months',
      value: String(gh.months),
      options: GITHUB_MONTH_CHOICES.map((n) => ({ value: String(n), label: t('mon.gh.monthsOption', { count: n }) })),
      onChange: (v) => {
        gh.months = Number(v) || GITHUB_HISTORY_MONTHS;
      }
    });
    const issue = checkbox({ label: t('mon.gh.issue'), checked: gh.issue, className: 'mon-gh-issue', onChange: (v) => { gh.issue = v; } });
    const go = Button({ label: t('mon.gh.go'), icon: 'download', variant: 'primary', size: 'sm', disabled: running, dataset: { action: 'mon-gh-load', shortcut: 'submit' }, onClick: () => start() });
    const stop = running ? Button({
      label: t('mon.gh.stop'), icon: 'x', size: 'sm', dataset: { action: 'mon-gh-stop', shortcut: 'cancel' },
      onClick: () => {
        stopRead();
        gh.notice = t('mon.gh.stopped');
        renderSource();
        focus('[data-action="mon-gh-load"]');
      }
    }) : null;

    /** Read the fields, empty the token field at once, and run one read. */
    function start() {
      if (gh.job) return;
      // Offline nothing is read or sent: the token stays in its field for when the connection is back.
      if (!ctx.requireOnline()) return;
      const raw = tokenField.value;
      tokenField.value = '';
      // "emptied" only when something was in the field
      const cleared = raw.length > 0;
      gh.repo = repoField.value.trim();
      gh.error = null;
      gh.notice = null;
      if (!parseRepo(gh.repo)) {
        gh.error = { code: 'repo', params: {}, cleared };
        renderSource();
        focus('[data-role="mon-gh-repo"]');
        return;
      }
      // an empty or malformed token is said at once: no read starts, nothing is sent
      if (!cleanToken(raw)) {
        gh.error = { code: 'token', params: {}, cleared };
        renderSource();
        focus('[data-role="mon-gh-token"]');
        return;
      }
      const controller = new AbortController();
      const job = { controller, progress: null, repo: gh.repo };
      gh.job = job;
      renderSource();
      focus('[data-action="mon-gh-stop"]');
      announce(t('mon.gh.running', { repo: gh.repo }));
      fetchResults(gh.repo, raw, {
        signal: controller.signal,
        months: gh.months,
        issue: gh.issue,
        onProgress: (p) => {
          job.progress = p;
          if (gh.job === job && paintGhStatus) paintGhStatus();
        }
      }).then((out) => {
        if (gh.job !== job) return;
        gh.job = null;
        const where = `${out.owner}/${out.repo}`;
        const left = out.skipped.tooLarge.length + out.skipped.overCap.length;
        gh.notice = [
          t('mon.gh.done', { count: out.files.length, repo: where }),
          left ? t('mon.gh.skipped', { count: left, max: GITHUB_MAX_FILES }) : '',
          out.rate.remaining !== null ? t('mon.gh.rate', { count: out.rate.remaining }) : ''
        ].filter(Boolean).join(' ');
        S.repo = { owner: out.owner, repo: out.repo };
        S.issue = out.issue;
        S.issueError = out.issueError;
        announce(gh.notice);
        importAndShow(out.files, { replace: true });
      }, (err) => {
        if (gh.job !== job) return;
        gh.job = null;
        if (err && err.name === 'AbortError') return;
        gh.error = { code: err && err.code ? err.code : 'network', params: (err && err.params) || {}, cleared };
        if (rerender) {
          renderSource();
          focus('[data-role="mon-gh-token"]');
        }
        announce(t('mon.gh.err.title'));
      });
    }

    const statusEl = h('div', { class: 'mon-gh-status', dataset: { role: 'mon-gh-status' } });
    function paintStatus() {
      clear(statusEl);
      statusEl.hidden = false;
      const job = gh.job;
      if (job) {
        const p = job.progress;
        const line = !p ? '' : p.phase === 'file' ? t('mon.gh.progress.file', { done: num(Math.min(p.done + 1, p.total)), total: num(p.total) }) : t(`mon.gh.progress.${p.phase}`);
        statusEl.dataset.state = 'running';
        statusEl.append(Spinner({ label: t('mon.gh.running', { repo: job.repo }) }), h('div', { class: 'stack-xs' },
          h('span', null, t('mon.gh.running', { repo: job.repo })), line ? h('span', { class: 'muted' }, line) : null));
        return;
      }
      if (gh.error) {
        const e = gh.error;
        const extra = [];
        if (e.params.detail) extra.push(h('p', { class: 'text-sm' }, t('mon.gh.err.detail', { detail: e.params.detail })));
        if (e.cleared) extra.push(h('p', { class: 'text-sm muted' }, t('mon.gh.err.again')));
        const message = e.code === 'rate-limited'
          ? (e.params.resetAt ? t('mon.gh.err.rate-limited', { time: formatDateTime(new Date(e.params.resetAt)) }) : t('mon.gh.err.rateLater'))
          : t(`mon.gh.err.${e.code}`, { status: e.params.status ?? '' });
        statusEl.dataset.state = 'error';
        statusEl.dataset.code = e.code;
        statusEl.append(Alert({ variant: 'error', title: t('mon.gh.err.title'), message, children: extra.length ? h('div', { class: 'stack-xs' }, extra) : null }));
        return;
      }
      if (gh.notice) {
        statusEl.dataset.state = 'notice';
        append(statusEl, h('p', { class: 'text-sm muted' }, gh.notice),
          S.issueError ? h('p', { class: 'text-sm muted' }, t(S.issueError === 'forbidden' ? 'mon.gh.issueError.forbidden' : 'mon.gh.issueError.other')) : null);
        return;
      }
      statusEl.dataset.state = '';
      statusEl.hidden = true;
    }

    body.append(
      h('p', { class: 'text-sm' }, t('mon.gh.intro')),
      h('div', { class: 'mon-gh-fields' }, repoField.el, tokenField.el),
      h('div', { class: 'cluster mon-gh-options' }, months.el, issue.el),
      h('p', { class: 'text-sm muted' }, t('mon.gh.how')),
      h('div', { class: 'cluster mon-gh-links' }, ExternalLink(GITHUB_TOKEN_URL, t('mon.gh.link.token')), ExternalLink(GITHUB_TOKEN_DOCS, t('mon.gh.link.docs'))),
      // The token's own privacy note, next to its Load (DESIGN §5.5: a panel that sends something says so).
      PrivacyNote({ text: t('mon.gh.privacy', { max: GITHUB_MAX_FILES }), className: 'mon-gh-privacy' }),
      h('div', { class: 'cluster' }, go, stop),
      statusEl);
    if (running) {
      repoField.input.disabled = true;
      tokenField.input.disabled = true;
    }
    paintStatus();
    paintGhStatus = () => {
      if (statusEl.isConnected) paintStatus();
    };
    return body;
  }

  function focus(selector) {
    const el = root.querySelector(selector);
    if (el && !el.disabled) el.focus();
  }

  /* --- the result: the empty state, or the result header (region 4) and the tabs ------------- */
  function renderResults() {
    const view = currentView();
    clear(resultsHost);
    if (actions) actions.dispose();
    actions = null;
    tabs = null;
    table = null;
    filterSelect = null;
    if (!view) {
      resultsHost.append(h('div', { class: 'mon-empty' }, EmptyState({
        icon: 'eye',
        message: t('mon.emptyLine'),
        checks: ['health', 'ct', 'tls', 'takeover', 'audit', 'watch'].map(cmdName)
      })));
      return;
    }
    renderHead(view);
    const targets = h('div', { class: 'mon-targets' }, metricStrip(view), targetTable(view));
    tabs = Tabs([
      { id: 'targets', label: t('mon.tab.targets'), badge: view.rows.length, content: () => targets },
      { id: 'changes', label: t('mon.tl.title'), content: () => timelineHost }
    ], { selected: S.tab, label: t('mon.tabs'), className: 'mon-tabs', onChange: (tab) => { S.tab = tab; } });
    renderTimeline();
    resultsHost.append(h('div', { class: 'mon-results', dataset: { shortcutScope: 'results' } }, head.el, tabs.el));
    setFilter(S.filter);
  }

  /** The result header: what is open and when it was checked, the counts, the actions and the links. */
  function renderHead(view) {
    const facts = monitorSummaryFacts(view.rows, view.tiles, S.data);
    head.setState('done');
    head.set('title', ResultTitle({ text: t('mon.resultsTitle', { count: view.rows.length }) }));
    head.set('meta', facts.at ? RelativeTime(facts.at, { className: 'mon-checked', text: t('mon.lastCheck', { time: formatRelative(facts.at) }) }) : null);
    // what the read left out of the history: said with the result it is about
    const skipped = S.skippedLines ? Alert({ variant: 'info', compact: true, message: t('mon.skippedLines', { count: S.skippedLines }) }) : null;
    if (skipped) skipped.classList.add('mon-skipped');
    head.set('notes', skipped);
    status.update(monitorStatus(view.tiles).map((item) => ({
      ...item,
      text: t(`mon.status.${item.key}`, { count: item.count, days: MONITOR_WARN_DAYS }),
      // the targets open the table with every target; the other three filter it
      filter: item.filter !== 'all',
      onPress: () => pressStatus(item)
    })), { pressed: statusOfFilter(S.filter) });
    const summary = SummaryButton({
      kind: 'monitor',
      plainLabel: t('result.plainTitle'),
      facts: () => {
        const v = currentView();
        return v ? monitorSummaryFacts(v.rows, v.tiles, S.data) : null;
      },
      // the view's bare link: the results never go into a URL
      url: () => ctx.shareUrl({})
    });
    actions = ResultActions({
      summary,
      // One file, no menu (DESIGN §5.3): the changes the Changes tab's filters show. Its data-export
      // is what setExportsDisabled reaches (renderTimeline: it waits while they show nothing).
      exports: [{ label: t('result.export'), title: t('mon.csvTitle'), dataset: { action: 'mon-csv', export: 'csv' }, onSelect: () => exportCsv() }]
    });
    head.set('actions', actions.el);
    head.set('next', linksOf());
  }

  /** The changes the Changes tab's filters show, as CSV. */
  function exportCsv() {
    const view = currentView();
    const filtered = view ? filterTimeline(view.entries, S.tl) : [];
    if (!filtered.length) return;
    const file = downloadText(timestampedName('monitor-changes', 'csv'), timelineCsv(filtered), 'text/csv;charset=utf-8');
    toast(t('mon.csvDone', { file }), { type: 'success', timeout: 2500 });
  }

  /* --- links ------------------------------------------------------------- */
  function linksOf() {
    const links = [];
    const repo = repoOf(S.repo, S.data);
    const pages = repoLinks(repo);
    if (S.issue && S.issue.url) {
      links.push(ExternalLink(S.issue.url, t('mon.link.issue', { number: S.issue.number }), { title: S.issue.title || null, className: 'mon-link-issue' }));
    } else if (pages) {
      links.push(ExternalLink(pages.issues, t('mon.link.issues'), { className: 'mon-link-issues' }));
    }
    const run = latestRun(S.data);
    if (run) links.push(ExternalLink(run, t('mon.link.run'), { className: 'mon-link-run' }));
    else if (pages) links.push(ExternalLink(pages.actions, t('mon.link.actions'), { className: 'mon-link-actions' }));
    return links.length ? h('div', { class: 'cluster mon-links' }, links) : null;
  }

  /* --- the Targets tab: the metric strip (region 6, read-only) and the table ----------- */
  function metricStrip(view) {
    const { tiles, rows } = view;
    const first = tiles.expiring[0];
    const strip = MetricStrip({ className: 'mon-stats', label: t('mon.stat.label') });
    strip.update([
      {
        id: 'all', label: t('mon.stat.targets'), value: rows.length,
        hint: S.data.reports.length ? t('mon.stat.targetsHint', { count: S.data.reports.length }) : t('mon.stat.targetsHistory')
      },
      {
        id: 'bad', label: t('mon.stat.bad'), value: tiles.bad.length, severity: tiles.bad.length ? 'error' : null,
        hint: t('mon.stat.badHint', { count: tiles.bad.length, days: MONITOR_RECENT_DAYS })
      },
      {
        id: 'expiring', label: t('mon.stat.expiring', { days: MONITOR_WARN_DAYS }), value: tiles.expiring.length, severity: tiles.expiring.length ? 'warn' : null,
        hint: first ? t('mon.stat.expiringHint', { name: `${first.name} (${daysText(first.daysLeft)})` }) : t('mon.stat.expiringNone')
      },
      {
        id: 'incomplete', label: t('mon.stat.incomplete'), value: tiles.incomplete.length, severity: tiles.incomplete.length ? 'warn' : null,
        hint: t('mon.stat.incompleteHint')
      }
    ], { foldable: [] });
    return strip.el;
  }

  function spark(points, kind) {
    if (!points.length) return null;
    const values = points.map((p) => p.value);
    const { points: line, last } = sparkPoints(values, { width: 96, height: 24, domain: kind === 'score' ? [0, 100] : null });
    const label = t(`mon.spark.${kind}`, { count: values.length, first: num(values[0]), last: num(values[values.length - 1]) });
    const lastValue = values[values.length - 1];
    const tone = kind === 'days' ? daysVariant(lastValue) : lastValue >= 80 ? 'ok' : lastValue >= 60 ? 'warn' : 'error';
    return h('span', { class: ['mon-spark', `mon-spark-${kind}`, `mon-spark-${tone}`], title: label },
      svg('svg', { class: 'mon-spark-svg', attrs: { viewBox: '0 0 96 24', width: 96, height: 24, role: 'img', 'aria-label': label, focusable: 'false' } },
        values.length > 1 ? svg('polyline', { class: 'mon-spark-line', attrs: { points: line } }) : null,
        last ? svg('circle', { class: 'mon-spark-dot', attrs: { cx: last.x, cy: last.y, r: 2.5 } }) : null),
      h('span', { class: 'mon-spark-value num' }, num(lastValue)));
  }

  function healthCell(row) {
    const c = row.cells.health;
    if (!c) return h('span', { class: 'muted' }, '—');
    return h('div', { class: 'mon-cell' },
      c.grade ? Badge(c.grade, { variant: gradeVariant(c.grade), className: 'mon-grade' }) : null,
      Number.isFinite(c.score) ? h('span', { class: 'num' }, `${num(c.score)}/100`) : null,
      c.ok === false ? Badge(t('mon.incompleteCheck'), { variant: 'warn' }) : null);
  }

  function certsCell(row) {
    const tls = row.cells.tls;
    const ct = row.cells.ct;
    if (!tls && !ct) return h('span', { class: 'muted' }, '—');
    const days = row.minDaysLeft;
    return h('div', { class: 'mon-cell' },
      days !== null ? Badge(daysText(days), { variant: daysVariant(days), className: 'mon-days' }) : null,
      tls && tls.worst && tls.worst !== 'OK' ? Badge(t(`mon.tls.${tls.worst}`), { variant: tlsVariant(tls.worst), title: tls.worst, className: 'mon-tls' }) : null,
      ct && ct.newIssuers && ct.newIssuers.length ? Badge(t('mon.newIssuers', { count: ct.newIssuers.length }), { variant: 'warn', title: ct.newIssuers.join(', '), className: 'mon-issuers' }) : null,
      ct && ct.unexpected ? Badge(t('mon.unexpected', { count: ct.unexpected }), { variant: 'warn' }) : null,
      ct && ct.revoked ? Badge(t('mon.revoked', { count: ct.revoked }), { variant: 'error' }) : null);
  }

  function problemsCell(row) {
    const tk = row.cells.takeover;
    const au = row.cells.audit;
    if (!tk && !au) return h('span', { class: 'muted' }, '—');
    return h('div', { class: 'mon-cell' },
      tk && Number.isFinite(tk.risks) ? (tk.risks
        ? Badge(t('mon.risks', { count: tk.risks }), { variant: tk.worst === 'critical' || tk.worst === 'high' ? 'error' : 'warn', className: 'mon-risks' })
        : Badge(t('mon.risksNone'), { variant: 'ok', className: 'mon-risks' })) : null,
      au && Number.isFinite(au.fail) ? (au.fail
        ? Badge(t('mon.auditFail', { count: au.fail }), { variant: 'error', className: 'mon-audit' })
        : Badge(t('mon.auditPass'), { variant: 'ok', className: 'mon-audit' })) : null,
      au && au.security ? h('span', { class: 'muted text-xs' }, t('mon.security', { score: num(au.security.score), max: num(au.security.max) })) : null);
  }

  function changesCell(row) {
    return h('div', { class: 'mon-cell' },
      row.bad7 ? Badge(t('mon.badChanges', { count: row.bad7 }), { variant: 'error', className: 'mon-bad' }) : h('span', { class: 'muted text-sm' }, t('mon.noBad')),
      row.lastChange ? h('span', { class: 'muted text-xs' }, t('mon.lastChange', { tag: row.lastChange.tag, when: day(row.lastChange.ms) })) : null);
  }

  function statusCell(row) {
    const bad = row.incomplete.map((c) => Badge(row.cells[c].stale ? `${cmdName(c)}: ${t('mon.staleCheck', { date: day(row.cells[c].ms) })}` : `${cmdName(c)}: ${t('mon.incompleteCheck')}`,
      { variant: 'warn', className: 'mon-incomplete', title: row.cells[c].stale ? null : t('mon.incompleteCheck') }));
    return h('div', { class: 'mon-cell' },
      bad.length ? bad : Badge(t('mon.completed'), { variant: 'ok' }),
      h('span', { class: 'muted text-xs nowrap' }, t('mon.checkedAt', { when: day(row.ms) })));
  }

  function cellFactsText(cell) {
    const bits = [];
    if (cell.command === 'health') {
      if (cell.grade) bits.push(cell.grade);
      if (Number.isFinite(cell.score)) bits.push(t('mon.f.score', { score: num(cell.score) }));
      if (Number.isFinite(cell.errors)) bits.push(t('mon.f.errors', { count: cell.errors }), t('mon.f.warnings', { count: cell.warnings }));
    }
    if (cell.command === 'ct' && Number.isFinite(cell.current)) bits.push(t('mon.f.current', { count: cell.current }));
    if (cell.command === 'tls' && Number.isFinite(cell.endpoints)) bits.push(t('mon.f.endpoints', { count: cell.endpoints }), t(`mon.tls.${cell.worst || 'SKIPPED'}`));
    if (Number.isFinite(cell.minDaysLeft)) bits.push(daysText(cell.minDaysLeft));
    if (cell.command === 'takeover' && Number.isFinite(cell.risks)) bits.push(cell.risks ? t('mon.risks', { count: cell.risks }) : t('mon.risksNone'));
    if (cell.command === 'audit' && Number.isFinite(cell.fail)) bits.push(cell.fail ? t('mon.auditFail', { count: cell.fail }) : t('mon.auditPass'));
    if (cell.from === 'history') bits.push(t('mon.fromHistory'));
    return bits.join(' · ') || '—';
  }

  function rowDetails(row) {
    return h('div', { class: 'mon-details' },
      h('table', { class: 'mon-d-table' },
        h('thead', null, h('tr', null, ['mon.d.command', 'mon.d.when', 'mon.d.state', 'mon.d.facts', 'mon.d.changes'].map((k) => h('th', { attrs: { scope: 'col' } }, t(k))))),
        h('tbody', null, row.commands.map((c) => {
          const cell = row.cells[c];
          const state = cell.stale ? t('mon.staleCheck', { date: day(cell.ms) }) : cell.ok === false ? t('mon.incompleteCheck') : t('mon.completed');
          return h('tr', { dataset: { command: c } },
            h('th', { attrs: { scope: 'row' } }, cmdName(c)),
            h('td', { class: 'nowrap' }, when(cell.ms)),
            h('td', null, state),
            h('td', null, cellFactsText(cell), cell.report ? h('span', { class: 'muted text-xs mon-d-report' }, ` · ${t('mon.d.report', { name: cell.report })}`) : null),
            h('td', { class: 'nowrap' }, t('mon.d.changesValue', { bad: num(cell.changes.bad), info: num(cell.changes.info) })));
        }))));
  }

  function targetTable(view) {
    // The Show select: the same filters as the status summary, every target counted once.
    filterSelect = select({
      label: t('mon.filter.label'),
      size: 'sm',
      className: 'mon-filter',
      value: S.filter,
      options: MONITOR_FILTERS.map((f) => ({
        value: f,
        label: t(`mon.filter.${f}`, { count: view.rows.filter((r) => rowMatches(r, f)).length, days: f === 'bad' ? MONITOR_RECENT_DAYS : MONITOR_WARN_DAYS })
      })),
      onChange: (v) => setFilter(v)
    });
    filterSelect.input.dataset.role = 'mon-filter';
    table = DataTable({
      caption: t('mon.table.caption'),
      rows: view.rows,
      rowKey: (r) => r.target,
      search: { placeholder: t('mon.search'), label: t('mon.search') },
      toolbar: filterSelect.el,
      filter: (r) => rowMatches(r, S.filter),
      noMatch: t('mon.noMatch'),
      cellLabels: true,
      maxHeight: null,
      className: 'mon-table',
      rowClass: (r) => ({ 'mon-row-attention': r.incomplete.length > 0 || r.bad7 > 0 || (r.minDaysLeft !== null && r.minDaysLeft < MONITOR_WARN_DAYS) }),
      details: (r) => rowDetails(r),
      export: false,
      columns: [
        {
          key: 'target', label: t('mon.col.target'), sortable: true, wrap: true, sortValue: (r) => r.target,
          searchValue: (r) => [r.target, ...r.commands].join(' '),
          render: (r) => h('div', { class: 'mon-target' },
            h('div', { class: 'mon-target-head' },
              h('span', { class: 'mon-target-name mono' }, r.target),
              // a target with no change recorded has nothing to show in the timeline
              r.lastChange ? IconButton({ icon: 'filter', label: t('mon.showChanges', { target: r.target }), size: 'sm', className: 'mon-target-filter', onClick: () => showChangesOf(r.target) }) : null),
            h('span', { class: 'muted text-xs' }, r.commands.map(cmdName).join(' · ')))
        },
        {
          key: 'trend', label: t('mon.col.trend'), searchable: false, className: 'mon-col-trend',
          render: (r) => (r.series.score.length || r.series.days.length ? h('div', { class: 'mon-trend' }, spark(r.series.score, 'score'), spark(r.series.days, 'days')) : h('span', { class: 'muted' }, '—'))
        },
        { key: 'health', label: t('mon.col.health'), sortable: true, searchable: false, sortValue: (r) => (r.cells.health && Number.isFinite(r.cells.health.score) ? r.cells.health.score : 1000), render: healthCell },
        { key: 'certs', label: t('mon.col.certs'), sortable: true, searchable: false, sortValue: (r) => r.minDaysLeft ?? Number.MAX_SAFE_INTEGER, render: certsCell },
        { key: 'problems', label: t('mon.col.problems'), searchable: false, render: problemsCell },
        { key: 'changes', label: t('mon.col.changes', { days: MONITOR_RECENT_DAYS }), sortable: true, searchable: false, defaultDir: 'desc', sortValue: (r) => r.bad7, render: changesCell },
        { key: 'status', label: t('mon.col.status'), sortable: true, searchable: false, sortValue: (r) => -r.incomplete.length, render: statusCell }
      ]
    });
    return table.el;
  }

  /** A row's "Show the changes of …": the Changes tab, filtered by that target. */
  function showChangesOf(target) {
    S.tl = { ...S.tl, target, shown: TIMELINE_PAGE };
    if (tabs) tabs.select('changes');
    renderTimeline();
    const el = root.querySelector('[data-role="mon-tl-target"]');
    if (el) {
      el.focus({ preventScroll: true });
      el.scrollIntoView({ block: 'nearest' });
    }
  }

  /* --- the Changes tab: the timeline ------------------------------------------------ */
  function renderTimeline() {
    const view = currentView();
    clear(timelineHost);
    if (!view) return;
    const all = view.entries;
    const filtered = filterTimeline(all, S.tl);
    const commands = [...new Set(all.map((e) => e.command))].sort(commandOrder);
    const targets = [...new Set(all.map((e) => e.target))].sort();
    if (S.tl.command && !commands.includes(S.tl.command)) S.tl.command = '';
    if (S.tl.target && !targets.includes(S.tl.target)) S.tl.target = '';
    const commandSel = select({
      label: t('mon.tl.command'), size: 'sm', className: 'mon-tl-filter', value: S.tl.command,
      options: [{ value: '', label: t('mon.tl.allCommands') }, ...commands.map((c) => ({ value: c, label: cmdName(c) }))],
      onChange: (v) => {
        S.tl = { ...S.tl, command: v, shown: TIMELINE_PAGE };
        renderTimeline();
        focus('[data-role="mon-tl-command"]');
      }
    });
    commandSel.input.dataset.role = 'mon-tl-command';
    const targetSel = select({
      label: t('mon.tl.target'), size: 'sm', className: 'mon-tl-filter', value: S.tl.target,
      options: [{ value: '', label: t('mon.tl.allTargets') }, ...targets.map((x) => ({ value: x, label: x }))],
      onChange: (v) => {
        S.tl = { ...S.tl, target: v, shown: TIMELINE_PAGE };
        renderTimeline();
        focus('[data-role="mon-tl-target"]');
      }
    });
    targetSel.input.dataset.role = 'mon-tl-target';
    const tone = SegmentedControl({
      label: t('mon.tl.tone'), size: 'sm', value: S.tl.tone, className: 'mon-tl-tone',
      options: TIMELINE_TONES.map((x) => ({ value: x, label: t(`mon.tone.${x}`) })),
      onChange: (v) => {
        S.tl = { ...S.tl, tone: v, shown: TIMELINE_PAGE };
        renderTimeline();
        focus(`.mon-tl-tone .seg-btn[data-value="${v}"]`);
      }
    });
    const shown = filtered.slice(0, S.tl.shown);
    const list = [];
    let lastDay = '';
    for (const e of shown) {
      const d = e.at.slice(0, 10);
      if (d !== lastDay) {
        lastDay = d;
        list.push(h('li', { class: 'mon-tl-day' }, h('h3', { class: 'mon-tl-date' }, day(e.ms))));
      }
      list.push(h('li', { class: ['mon-tl-entry', `mon-tl-${e.tone}`], dataset: { tag: e.tag, tone: e.tone, command: e.command } },
        h('div', { class: 'mon-tl-head' },
          h('span', { class: 'mon-tl-time num muted text-xs' }, `${e.at.slice(11, 16)} UTC`),
          Badge(e.tag, { variant: toneVariant(e.tone), mono: true, title: MONITOR_TAGS.includes(e.tag) ? t(`mon.tag.${e.tag}`) : null, className: 'mon-tl-tag' }),
          h('span', { class: 'mon-tl-target mono' }, e.target),
          h('span', { class: 'muted text-sm' }, cmdName(e.command)),
          e.counts ? Badge(t('mon.tl.counted'), { variant: 'neutral', title: t('mon.tl.countedTitle') }) : null,
          e.run ? ExternalLink(e.run, t('mon.tl.run'), { className: 'mon-tl-run text-xs' }) : null),
        e.text ? h('div', { class: 'mon-tl-text text-sm' }, e.text) : e.item ? h('div', { class: 'mon-tl-item mono text-xs' }, e.item) : null));
    }
    const more = filtered.length > shown.length ? Button({
      label: t('mon.tl.more', { count: num(Math.min(TIMELINE_PAGE, filtered.length - shown.length)) }), size: 'sm', variant: 'secondary', dataset: { action: 'mon-tl-more' },
      onClick: () => {
        S.tl = { ...S.tl, shown: S.tl.shown + TIMELINE_PAGE };
        renderTimeline();
        focus('[data-action="mon-tl-more"]');
      }
    }) : null;
    const empty = !all.length ? EmptyState({ icon: 'clock', message: t('mon.tl.empty') })
      : !filtered.length ? EmptyState({ icon: 'filter', message: t('mon.tl.none') }) : null;
    timelineHost.append(
      h('div', { class: 'cluster mon-tl-filters' }, commandSel.el, targetSel.el, tone.el),
      empty || h('ol', { class: 'mon-tl-list' }, list),
      more);
    // The tab says how many changes the filters show; the head's CSV waits while there are none.
    if (tabs) tabs.setBadge('changes', filtered.length);
    if (actions) actions.setExportsDisabled(!filtered.length);
  }

  render();
}

/** Stop re-rendering for state changes of an unmounted view. */
export function unmount() {
  rerender = null;
}

export default { id, titleKey, icon, mount, unmount };
