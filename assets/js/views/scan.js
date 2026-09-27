/**
 * views/scan.js — "SSL Targets" (the default view and the flagship flow).
 *
 * A renewed certificate arrives (e.g. *.example.com) and the question is: which names
 * exist, where do they point, and which of *my* servers need the new certificate?
 *
 *   1. Certificate (optional) — its names seed the search; every host is checked against it
 *   2. Domains — auto-filled from the certificate (registrable domains), editable
 *   3. Inventory — the saved server list (state.inventory) used to match IPs to machines
 *   4. Options — passive sources (with quota notes), expired certificates, brute force,
 *      origin hints and extra names
 *
 * Run starts lib/scanner.runScan(); stages, per-source status and hosts stream into the
 * page. Results: stat cards, then tabs Hosts / Servers / Behind CDN / Verify (only with a
 * certificate: ui/verify-panel.js checks it from the internet) / Sources / CT certificates,
 * plus exports (hosts CSV, servers CSV, full JSON, names.txt, targets.txt) and the ready-to-run command for the companion CLI (cli/ssl_origin_scan.py), which
 * confirms origins behind Cloudflare from inside the network.
 *
 * A running scan is owned by this module, not by the mounted view: navigating to another
 * tool keeps it running (the results are there when you come back, and a toast says when
 * it finished). Everything stays in memory; nothing is uploaded except the DNS / CT
 * queries themselves.
 *
 * Route params: `#/scan?domain=example.com` (repeatable or comma-separated) pre-fills the
 * domains; `&run=1` (a shared link) also shows a note to press "Start scan" — a link never
 * starts the scan on its own.
 */

import { h, clear, append } from '../ui/dom.js';
import {
  Alert, Badge, Button, ButtonLink, Card, CodeBlock, DataTable, Disclosure, EmptyState, ErrorBanner, ExternalLink,
  Icon, KeyValueList, KindBadge, ProgressBar, SegmentedControl, StatCard, Tabs, TruncatedList, announce, checkbox,
  checkboxGroup, ipSortValue, radioGroup, select, textInput, textarea, toast
} from '../ui/components.js';
import { downloadText, timestampedName } from '../ui/download.js';
import {
  t, registerStrings, formatNumber, formatDate, formatDateTime, formatDuration, formatRelative, daysUntil
} from '../i18n.js';
import { parseHostList, baseDomainsFromNames, isPublicSuffix, stripWildcard } from '../lib/domain.js';
import { SOURCES, sourceHealthSummary } from '../lib/sources.js';
import { runScan, SCAN_STAGES } from '../lib/scanner.js';
import {
  toCsv, toJson, scanHostRows, scanServerRows, namesForCli, targetsForCli, cliCommand, HOST_COLUMNS, SERVER_COLUMNS
} from '../lib/export.js';
import { getResolver } from '../lib/resolvers.js';
import { pemEncode } from '../lib/x509.js';
import { errorKind, splitList } from '../lib/util.js';
import {
  CertLoader, CertSummary, certWarningAlerts, getCurrentCert, setCurrentCert, normalizeCertLoad,
  PENDING_CERT, CURRENT_CERT, EXPIRING_DAYS
} from './cert.js';
// Shared with the Subdomains view: wordlist sizes / estimates, source status texts, technique counts.
import {
  LEGACY_BRUTEFORCE, PERMUTATION_BUDGETS, DEFAULT_PERMUTATION_BUDGET, PYTHON_FOR_SHELL, SHELLS, WARNING_CODES, LEARNED_TRY_MAX,
  applyProgress, applyStage, bruteforceBases, ensureSmartCount, estimateText, languageName, levelPacks, levelSize, linkAction, localeSummary,
  liveHosts, originOverview, originSweep, partialHostRecord, planQueryRange,
  realOriginNetworks, reasonText, rememberLearned, scanConcurrency, sharedVocabulary, sourceHealthText, stopStages, techniqueCounts,
  wordlistCount, wordlistPlan, wordlistPlanText, wordlistScanConfig,
  ZoneChip, isResolving, validZoneIntent, zoneForDomains, zoneScanOverrides
} from './subdomains.js';
import { describeNetwork } from '../lib/ipintel.js';
// The Verify tab (Globalping check from the internet); the job it runs lives on the scan run.
import { VerifyPanel, verifyTabBadge, cancelVerify, verifyExport } from '../ui/verify-panel.js';

/** Route id. */
export const id = 'scan';
/** i18n key of the page title. */
export const titleKey = 'nav.scan';
/** Nav/page icon. */
export const icon = 'target';

/** Companion CLI, relative to the site root (published with the Pages site). */
export const CLI_PATH = 'cli/ssl_origin_scan.py';
/** localStorage key for the last used scan options (a per-browser convenience). */
export const OPTIONS_KEY = 'ssds.scan.options';
/** Brute-force modes offered in the options (a stored legacy 'medium' loads as 'smart'). */
export const BRUTEFORCE_MODES = Object.freeze(['off', 'small', 'smart', 'large', 'huge']);
/**
 * Sources that existed before `knownSources` was stored: a saved selection without it only
 * gains the sources added after them (e.g. ip.thc.org), never ones the user had unticked.
 */
const LEGACY_KNOWN_SOURCES = Object.freeze(['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx']);
/** Classification order used for sorting (most interesting first). */
const KIND_ORDER = ['dangling', 'cloudflare', 'cdn', 'platform', 'direct', 'private', 'unresolved', 'nxdomain'];
/** Host filter values of the "Show" select. */
export const KIND_FILTERS = Object.freeze(['all', 'hidden', 'cloudflare', 'cdn', 'platform', 'cdnplatform', 'direct', 'private', 'unresolved', 'dangling']);
const SOURCE_NAMES = Object.fromEntries(SOURCES.map((s) => [s.id, s.name]));
/** Origin-hint kinds with a localized label (scan.hint.<kind>). */
export const HINT_KINDS = Object.freeze(['resolver-leak', 'spf', 'mx', 'direct-sibling', 'sibling-domain', 'history', 'zone']);
const CHIP_ERRORS = ['abort', 'timeout', 'rate-limit', 'http', 'network', 'parse', 'unknown'];

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'source.crtsh.note': 'Certificate Transparency search. Free, but slow for large domains (a minute or more) and sometimes briefly unavailable.',
  'source.certspotter.note': 'Certificate Transparency API. About 10 requests per hour per IP without a key; unexpired certificates only.',
  'source.hackertarget.note': 'Host search with current IPs. About 50 requests per day per IP (shared with reverse IP lookups).',
  'source.anubis.note': 'Subdomain database. Free, no key.',
  'source.otx.note': 'Passive DNS with historical IPs — often the server from before Cloudflare. Anonymous access is often rate-limited.',
  'source.thc.note': 'Subdomain database with last-seen dates. Free, no key; up to 1,000 names per domain, fetched politely 2 seconds apart.',

  'scan.step.cert': 'Certificate',
  'scan.step.certDesc': 'Its names seed the search and every host is checked against it',
  'scan.step.domains': 'Domains',
  'scan.step.domainsDesc': 'Their subdomains are discovered from DNS records, wordlists and variations, plus CT logs and passive DNS',
  'scan.step.inventory': 'Your servers',
  'scan.step.inventoryDesc': 'Tells which of your machines the names point to',
  'scan.step.options': 'Options',
  'scan.step.optionsDesc': 'Where to look and how thoroughly',
  'scan.optional': 'optional',
  'scan.stepDone': 'ready',

  'scan.cert.details': 'Details',
  'scan.cert.remove': 'Remove',
  'scan.cert.another': 'Use another certificate',
  'scan.cert.none': 'Optional: without a certificate the scan still finds hosts, IPs and servers — only coverage is not checked.',
  'scan.cert.isCA': 'This is a CA certificate, not a server certificate. Load the certificate issued for your domain.',
  'scan.cert.taken': 'Certificate taken over from the Certificate view.',

  'scan.domains.label': 'Target domains',
  'scan.domains.placeholder': 'example.com\nexample.org',
  'scan.domains.hint': 'One per line, or separated by spaces or commas. URLs are fine.',
  'scan.domains.fromCert': 'From the certificate: {domains}',
  'scan.domains.useCert': 'Use these',
  'scan.domains.invalid': 'Not a valid domain: {list}',
  'scan.domains.publicSuffix': '{list}: a public suffix such as co.uk cannot be scanned — enter a registered domain like example.com.',
  'scan.domains.required': 'Enter at least one domain or load a certificate.',

  'scan.inv.servers': { one: '{count} server saved', other: '{count} servers saved' },
  'scan.inv.ips': { one: '{count} IP address', other: '{count} IP addresses' },
  'scan.inv.updated': 'updated {when}',
  'scan.inv.edit': 'Edit servers',
  'scan.inv.emptyTitle': 'No servers saved yet',
  'scan.inv.emptyBody': 'The scan still lists every host and IP, but only your inventory tells which servers need the certificate. Paste it once — it stays in this browser.',
  'scan.inv.add': 'Add servers',
  'scan.inv.privacy': 'Matching happens in your browser; the inventory is never sent anywhere.',

  'scan.opt.sources': 'Passive sources',
  'scan.opt.sourcesHint': 'Queried directly from your browser. Free tiers have limits; a failed source never stops the scan.',
  'scan.opt.bruteforce': 'Brute force (wordlist)',
  'scan.opt.bf.off': 'Off',
  'scan.opt.bf.small': 'Small · {count} names',
  'scan.opt.bf.smart': 'Smart · {count} names (recommended)',
  'scan.opt.bf.large': 'Large · {count} names',
  'scan.opt.bf.huge': 'Huge · {count} names',
  'scan.opt.bf.smallHint': 'The most common names only · {time} per domain.',
  'scan.opt.bf.smartHint': 'The most common names worldwide, ranked from open subdomain lists · {time} per domain.',
  'scan.opt.bf.largeHint': 'A much longer tail of the same ranking, loaded from this site when the scan starts ({size}) · {time} per domain.',
  'scan.opt.bf.hugeHint': 'The whole ranking, loaded from this site when the scan starts ({size}) · many minutes: {time} per domain. For a domain you own and want mapped thoroughly.',
  'scan.opt.bfHint': 'Tries names (www, mail, vpn, panel, support, …) under each domain through public DoH resolvers — finds hosts that never appeared in a public certificate. Your browser never connects to the servers; the resolvers ask the domain’s authoritative DNS about names they have not cached.',
  'scan.opt.perm': 'Try variations of the names found (permutations)',
  'scan.opt.permHint': 'api → api2, api-dev; shop → shopapi … plus one deeper round under discovered parents.',
  'scan.opt.permBudget': 'Up to',
  'scan.opt.permBudgetValue': { one: '{count} variation', other: '{count} variations' },
  'scan.opt.includeExpired': 'Include expired certificates',
  'scan.opt.includeExpiredHint': 'Older names from crt.sh too. Slower; for large domains crt.sh may only return unexpired certificates.',
  'scan.opt.originHints': 'Look for origin hints',
  'scan.opt.originHintsHint': 'Other public resolvers, the /24 network of the non-proxied names, SPF, MX and historical DNS can point to the servers behind Cloudflare — DNS only.',
  'scan.opt.extra': 'Extra hostnames',
  'scan.opt.extraPlaceholder': 'intranet.example.com\nold-shop.example.com',
  'scan.opt.extraHint': 'Names you already know about; they are always resolved.',
  'scan.opt.doh': 'DNS over HTTPS: {chain}',
  'scan.opt.dohSpread': 'A bulk scan spreads its queries across these resolvers — this is not a strict failover order.',
  'scan.opt.dohChange': 'Change',
  'scan.vocab.langs': 'Languages / markets: {summary}',
  'scan.vocab.custom': { one: '{count} custom name', other: '{count} custom names' },
  'scan.vocab.learned': { zero: 'no learned names yet', one: '{count} learned name first', other: '{count} learned names first' },
  'scan.vocab.learnedOff': 'learned names off',
  'scan.vocab.shared': 'Shared with Subdomains › Advanced options (languages, custom wordlist, learned names).',
  'scan.vocab.change': 'Change in Subdomains',

  'scan.run': 'Start scan',
  'scan.runAgain': 'Scan again',
  'scan.cancel': 'Cancel',
  'scan.link.prompt': 'This link opens a scan of {domains}. Press “Start scan” when you are ready — it queries the passive sources and public DNS resolvers from your browser.',
  'scan.summary.domains': { one: '{count} domain', other: '{count} domains' },
  'scan.summary.domainsCert': 'domains from the certificate',
  'scan.summary.noDomains': 'no domain yet',
  'scan.summary.sources': { zero: 'no passive sources', one: '{count} source', other: '{count} sources' },
  'scan.summary.bf.off': 'no brute force',
  'scan.summary.bf.small': 'small wordlist',
  'scan.summary.bf.smart': 'smart wordlist',
  'scan.summary.bf.large': 'large wordlist',
  'scan.summary.bf.huge': 'huge wordlist',
  'scan.summary.perm': 'permutations',
  'scan.summary.cert': 'with certificate',
  'scan.summary.noCert': 'no certificate',
  'scan.busy': 'Scanning…',

  'scan.run.title': 'Scanning {domains}',
  'scan.run.titleDone': 'Scan of {domains}',
  'scan.run.elapsed': 'elapsed {time}',
  'scan.run.finished': 'Finished in {time} · {queries} DNS queries',
  'scan.run.finishedAt': 'Finished {when}',
  'scan.run.cancelled': 'Cancelled after {time}. The hosts found so far are listed; servers, origin hints and CT certificates need a complete scan.',
  'scan.run.cancelledShort': 'Cancelled',
  'scan.run.failed': 'The scan could not run',
  'scan.stage.sources': 'Sources',
  'scan.stage.mining': 'DNS records',
  'scan.stage.wildcard': 'Wildcard DNS',
  'scan.stage.bruteforce': 'Brute force',
  'scan.stage.permutations': 'Permutations',
  'scan.stage.resolve': 'Resolve',
  'scan.stage.hints': 'Origin hints',
  'scan.stage.done': 'Done',
  'scan.stage.skipped': 'skipped',
  'scan.stage.found': '+{count}',
  'scan.stage.candidates': { one: '{count} name', other: '{count} names' },
  'scan.progress.sources': 'Querying passive sources and the domain’s DNS records',
  'scan.progress.mining': 'Mining the domain’s own DNS records (MX, NS, SPF, SRV …)',
  'scan.progress.wildcard': 'Checking for wildcard DNS',
  'scan.progress.bruteforce': 'Trying wordlist names',
  'scan.progress.permutations': 'Trying variations of the names found',
  'scan.progress.resolve': 'Resolving hostnames',
  'scan.progress.hints': 'Collecting origin hints (other resolvers, networks, SPF, MX, history)',
  'scan.progress.done': 'Done',
  'scan.progress.starting': 'Starting…',
  'scan.chip.names': { zero: 'no names', one: '{count} name', other: '{count} names' },
  'scan.chip.waiting': 'waiting…',
  'scan.chip.partial': 'partial',
  'scan.chip.error.abort': 'cancelled',
  'scan.chip.error.timeout': 'timed out',
  'scan.chip.error.rate-limit': 'rate limited',
  'scan.chip.error.http': 'HTTP error',
  'scan.chip.error.network': 'network error',
  'scan.chip.error.parse': 'bad response',
  'scan.chip.error.unknown': 'failed',
  'scan.doneToast': { one: 'Scan finished: {count} host', other: 'Scan finished: {count} hosts' },
  'scan.showResults': 'Show results',
  'scan.cancelledToast': 'Scan cancelled',

  'scan.results': 'Results',
  'scan.stat.hosts': 'Hosts',
  'scan.stat.hostsHint': '{count} resolving',
  'scan.stat.cloudflare': 'Behind Cloudflare',
  'scan.stat.cloudflareHint': 'origin hidden',
  'scan.stat.cdn': 'CDN / platform',
  'scan.stat.cdnHint': 'managed elsewhere',
  'scan.stat.direct': 'Direct IP',
  'scan.stat.directHint': { zero: 'no match in your servers', one: '{count} on your servers', other: '{count} on your servers' },
  'scan.stat.covered': 'Covered by certificate',
  'scan.stat.coveredHint': 'of {total} hosts',
  'scan.stat.servers': 'Servers to update',
  'scan.stat.serversNoCert': 'Matched servers',
  'scan.stat.serversHint': { zero: 'no other candidates', one: '+{count} possible via hints', other: '+{count} possible via hints' },
  'scan.stat.serversNoInv': 'no inventory saved',
  'scan.stat.unresolved': 'Not resolving',
  'scan.stat.unresolvedHint': { zero: 'no dangling CNAME', one: '{count} dangling CNAME', other: '{count} dangling CNAMEs' },
  'scan.stat.filterHint': 'Show these hosts',

  'scan.sum.needs': { one: '{count} of your servers needs the new certificate.', other: '{count} of your servers need the new certificate.' },
  'scan.sum.needsNone': 'None of your saved servers serves a name the certificate covers.',
  'scan.sum.matched': { one: 'The names point to {count} of your servers.', other: 'The names point to {count} of your servers.' },
  'scan.sum.hidden': { one: '{count} host is behind a CDN / proxy, so its origin server is hidden — see “Behind CDN”.', other: '{count} hosts are behind a CDN / proxy, so their origin servers are hidden — see “Behind CDN”.' },
  'scan.sum.unmatched': { one: '{count} public IP is not in your inventory.', other: '{count} public IPs are not in your inventory.' },
  'scan.sum.noInventory': 'Add your server inventory to see which servers need the certificate.',
  'scan.sum.dangling': { one: '{count} dangling CNAME — possible subdomain takeover.', other: '{count} dangling CNAMEs — possible subdomain takeover.' },
  'scan.sum.wildcard': 'Wildcard DNS on {list}: every name there resolves, so wordlist-only hits were dropped and look-alikes are marked “wildcard?”.',
  'scan.sum.sourcesFailed': { one: '{count} source failed — see “Sources”. The results are still valid.', other: '{count} sources failed — see “Sources”. The results are still valid.' },
  'scan.sum.discovery': 'Found through DNS: {dns} · from passive sources: {sources}',
  'scan.sum.discoveryZone': 'Found through DNS: {dns} · from passive sources: {sources} · from your zone file: {zone}',
  'scan.sum.networks': { one: 'Candidate origin network {list}: the non-proxied names live there, and the proxied ones may too. See “Behind CDN”.', other: 'Candidate origin networks {list}: the non-proxied names live there, and the proxied ones may too. See “Behind CDN”.' },
  'scan.warn.PUBLIC_SUFFIX': '{detail} is a public suffix and was skipped.',
  'scan.warn.INVALID_DOMAIN': 'Invalid domain skipped: {detail}',
  'scan.warn.INVALID_NAME': 'Invalid hostname skipped: {detail}',
  'scan.warn.TRUNCATED': 'Too many names — only the first ones were resolved ({detail}).',
  'scan.warn.BRUTEFORCE_TRUNCATED': 'The wordlist was cut at {detail} candidates.',
  'scan.warn.RECURSIVE_TRUNCATED': 'The deeper round was cut at {detail} candidates.',
  'scan.warn.WILDCARD_PARENTS_TRUNCATED': 'Wildcard DNS was checked for the first {detail} parent names only.',
  'scan.warn.WORDLIST_DEGRADED': 'The chosen wordlist could not be loaded, so a smaller one was used ({detail}).',
  'scan.warn.DNS_UNREACHABLE': 'The public DNS resolvers stopped answering ({detail} guesses in a row failed), so the wordlist and variations were stopped early. Check your connection, or whether DNS-over-HTTPS is blocked on this network.',
  'scan.warn.ZONE_OUT_OF_SCOPE': '{detail} names from your zone file are outside the scanned domain and were skipped.',
  'scan.origin.zone': 'Zone file',
  'scan.hint.zone': 'Zone file',
  'scan.hint.zone.title': 'Your zone file names this address as the real server behind the proxied name',
  'scan.srv.via.zone': 'Zone file',
  'scan.cdn.zoneTitle': 'Exact origins from your zone file',
  'scan.cdn.zoneDesc': 'Your zone file names the real server behind these proxied names. The command below probes these exact addresses and never widens them to a /24.',
  'scan.cdn.col.zoneOrigin': 'Origin from the zone file',

  'scan.tab.hosts': 'Hosts',
  'scan.tab.servers': 'Servers',
  'scan.tab.cdn': 'Behind CDN',
  'scan.tab.sources': 'Sources',
  'scan.tab.ct': 'CT certificates',
  'scan.pending': 'Available when the scan finishes.',
  'scan.notAvailable': 'Not available: the scan did not complete.',

  'scan.col.name': 'Hostname',
  'scan.col.status': 'Classification',
  'scan.col.ips': 'IP addresses',
  'scan.col.cname': 'CNAME',
  'scan.col.cert': 'Certificate',
  'scan.col.servers': 'Your servers',
  'scan.col.origins': 'Found by',
  'scan.host.covered': 'covered',
  'scan.host.coveredBy': 'Covered by {name}',
  'scan.host.notCovered': 'not covered',
  'scan.host.wildcard': 'wildcard?',
  'scan.host.wildcardTitle': 'Resolves exactly like the wildcard DNS record of its parent — it may not really exist.',
  'scan.host.inCert': 'in cert',
  'scan.host.inCertTitle': 'Listed in the certificate',
  'scan.filter.kind': 'Show',
  'scan.filter.all': 'All hosts',
  'scan.filter.hidden': 'Behind CDN / proxy',
  'scan.filter.cloudflare': 'Cloudflare',
  'scan.filter.cdn': 'CDN / WAF',
  'scan.filter.platform': 'Platform',
  'scan.filter.cdnplatform': 'CDN or platform',
  'scan.filter.direct': 'Direct IP',
  'scan.filter.private': 'Private IP',
  'scan.filter.unresolved': 'Not resolving',
  'scan.filter.dangling': 'Dangling CNAME',
  'scan.filter.covered': 'Covered only',
  'scan.filter.resolving': 'Resolving only',
  'scan.filter.hideWildcard': 'Hide wildcard suspects',
  'scan.filter.matched': 'My servers only',
  'scan.hosts.empty': 'Hosts appear here as they are resolved.',
  'scan.hosts.caption': 'Hosts found by the scan',
  'scan.d.dns': 'DNS answer',
  'scan.d.dnsValue': '{status} · {resolver} · TTL {ttl}',
  'scan.d.reason': 'Why',
  'scan.d.cnames': 'CNAME chain',
  'scan.d.ipv4': 'IPv4',
  'scan.d.ipv6': 'IPv6',
  'scan.d.history': 'Historical IPs',
  'scan.d.servers': 'Your servers',
  'scan.d.origins': 'Found by',
  'scan.d.tools': 'Open in',
  'scan.d.error': 'Error',
  'scan.origin.input': 'Your input',
  'scan.origin.cert': 'Certificate',
  'scan.origin.bruteforce': 'Wordlist',
  'scan.origin.wordlist': 'Wordlist',
  'scan.origin.permutation': 'Permutation',
  'scan.origin.recursive': 'Deeper level',
  'scan.origin.dnsmine': '{record} record',

  'scan.srv.intro': 'Servers from your inventory that the names resolve to (DNS) or that origin hints point at. Servers that need the certificate come first.',
  'scan.srv.verifyHint': 'Installed it? Check from the internet which certificate each server really serves.',
  'scan.sum.verify': 'After installing the certificate, open the Verify tab to check it from the internet.',
  'scan.srv.col.server': 'Server',
  'scan.srv.col.status': 'Action',
  'scan.srv.col.ips': 'Server IPs',
  'scan.srv.col.hosts': 'Hostnames',
  'scan.srv.col.count': 'Names',
  'scan.srv.col.host': 'Hostname',
  'scan.srv.col.ip': 'IP address',
  'scan.srv.col.via': 'Matched via',
  'scan.srv.col.covered': 'Certificate',
  'scan.srv.needs': 'Install the certificate',
  'scan.srv.serves': 'Serves these names',
  'scan.srv.maybe': 'Possible origin (hint)',
  'scan.srv.none': 'Nothing to install',
  'scan.srv.via.dns': 'DNS',
  'scan.srv.via.hint': 'Origin hint',
  'scan.srv.empty': 'None of the resolved IPs belongs to your saved servers.',
  'scan.srv.noInventory': 'No servers saved — add your inventory to match IPs to machines. Until then, the IPs are listed below.',
  'scan.srv.unmatchedTitle': 'IPs not in your inventory',
  'scan.srv.unmatchedDesc': 'Direct IPs the names resolve to that none of your saved servers has — someone else’s server, or missing from your inventory.',
  'scan.srv.col.owner': 'Type',
  'scan.srv.private': 'private',
  'scan.srv.public': 'public',
  'scan.srv.unmatchedEmpty': 'Every direct IP belongs to one of your servers.',

  'scan.cdn.whyTitle': 'Why the real servers are hidden',
  'scan.cdn.why1': 'These names point to Cloudflare (the orange cloud) or another CDN / WAF. Public DNS only shows the proxy’s addresses, so no online tool can see which of your servers sits behind them — that is why scanners disagree.',
  'scan.cdn.why2': 'The proxy still connects to your origin servers, and they need the certificate too (unless the proxy uses its own certificate with “Flexible” TLS). The reliable way to find them is to ask each server directly: connect to its IP and request the hostname via SNI. The companion CLI does exactly that from inside your network.',
  'scan.cdn.hostsTitle': 'Proxied hosts',
  'scan.cdn.hostsEmpty': 'No host is behind a CDN or proxy — every resolving name points straight at an IP.',
  'scan.cdn.col.provider': 'Provider',
  'scan.cdn.col.edge': 'Edge IPs',
  'scan.cdn.hintsTitle': 'Origin hints',
  'scan.cdn.hintsDesc': 'IP addresses that may be the origin: answers of other public resolvers for the proxied names, SPF and MX records, non-proxied sibling names and historical DNS. Confirm them with the CLI.',
  'scan.cdn.col.networks': 'Same network as',
  'scan.cdn.netTitle': 'Origin networks',
  'scan.cdn.netDesc': 'Public DNS never publishes a proxied record’s origin. The non-proxied names of the domain live in these networks, so the proxied hosts may share one — candidates to check with the CLI, not proof. Sweep only networks you operate or are authorised to test.',
  'scan.cdn.netEmpty': 'No non-proxied name with a public IP was found, so there is no network to sweep.',
  'scan.cdn.col.cidr': 'Network',
  'scan.cdn.col.netHosts': 'Non-proxied names',
  'scan.cdn.col.netIps': 'IPs',
  'scan.cdn.col.sweep': 'Sweep',
  'scan.cdn.col.owner': 'Owner',
  'scan.cdn.quickTitle': 'Quick check: sweep the origin networks',
  'scan.cdn.quickDesc': 'Connects to every address of these networks with each proxied name (TLS SNI) — no input files needed. Run it inside the network; IPv6 networks are tried at their known addresses only.',
  'scan.cdn.shell': 'Shell',
  'scan.cdn.shell.posix': 'Linux / macOS',
  'scan.cdn.shell.powershell': 'Windows PowerShell',
  'scan.cdn.shellTitle.posix': 'For bash, zsh or sh (python3)',
  'scan.cdn.shellTitle.powershell': 'For PowerShell on Windows (python)',
  'scan.cdn.hintsEmpty': 'No origin hints found.',
  'scan.cdn.hintsOff': 'Origin hints were turned off for this scan.',
  'scan.cdn.col.ip': 'IP address',
  'scan.cdn.col.reasons': 'Evidence',
  'scan.cdn.col.servers': 'Your server',
  'scan.cdn.col.hosts': 'About',
  'scan.hint.spf': 'SPF',
  'scan.hint.mx': 'MX',
  'scan.hint.direct-sibling': 'Sibling',
  'scan.hint.sibling-domain': 'Sibling domain',
  'scan.hint.history': 'History',
  'scan.hint.resolver-leak': 'Resolver leak',
  'scan.hint.spf.title': 'Allowed to send mail for the domain (SPF record)',
  'scan.hint.mx.title': 'Mail server (MX) of the domain',
  'scan.hint.direct-sibling.title': 'Public IP of a non-proxied name of the same domain',
  'scan.hint.sibling-domain.title': 'The same name is a DNS-only host on a sister domain scanned with this one',
  'scan.hint.history.title': 'Seen in historical DNS (possibly before the proxy was enabled)',
  'scan.hint.resolver-leak.title': 'Another public resolver answered the proxied name with this non-CDN address',
  'scan.cli.title': 'Confirm from inside your network',
  'scan.cli.desc': 'ssl_origin_scan.py connects to every target IP with every name (SNI) and reports which server serves which certificate — and whether it is already the new one.',
  'scan.cli.step1': 'Download the input files',
  'scan.cli.step2': 'Download the CLI (Python 3.8+, no dependencies)',
  'scan.cli.step3': 'Run it on a machine inside your network (e.g. a jump host)',
  'scan.cli.step4': 'Read the result',
  'scan.cli.names': { zero: 'names.txt (empty)', one: 'names.txt · {count} name', other: 'names.txt · {count} names' },
  'scan.cli.targets': { zero: 'targets.txt (empty)', one: 'targets.txt · {count} target', other: 'targets.txt · {count} targets' },
  'scan.cli.certFile': 'new-cert.pem',
  'scan.cli.onlyCovered': 'Only names the certificate covers',
  'scan.cli.targetsNote': 'targets.txt = every saved server + origin hints + unknown direct IPs.',
  'scan.cli.noInventoryNote': 'Without an inventory, targets.txt only holds origin hints and direct IPs — add your servers for a complete check.',
  'scan.cli.result': 'UPDATED: already serves the new certificate · NEEDS_UPDATE: serves a certificate for the name, but not the new one — install it there · NOT_HOSTED: the name is not served there.',
  'scan.cli.download': 'ssl_origin_scan.py',
  'scan.cli.command': 'Command',

  'scan.src.col.source': 'Source',
  'scan.src.col.domain': 'Domain',
  'scan.src.col.status': 'Status',
  'scan.src.col.names': 'Names',
  'scan.src.col.ips': 'IP hints',
  'scan.src.col.certs': 'Certificates',
  'scan.src.col.time': 'Time',
  'scan.src.col.error': 'Details',
  'scan.src.ok': 'OK',
  'scan.src.partial': 'Partial',
  'scan.src.failed': 'Failed',
  'scan.src.healthTitle': 'Source status',
  'scan.src.retryHint': 'A failed source can simply be tried again later; the other results are still valid.',
  'scan.src.empty': 'Source results appear here as they arrive.',
  'scan.src.none': 'No passive source was selected for this scan.',

  'scan.ct.intro': 'Certificates for these domains in Certificate Transparency logs (crt.sh, Cert Spotter). Expiring ones are highlighted.',
  'scan.ct.col.status': 'Status',
  'scan.ct.col.issuer': 'Issuer',
  'scan.ct.col.from': 'Valid from',
  'scan.ct.col.to': 'Valid until',
  'scan.ct.col.names': 'Names',
  'scan.ct.col.serial': 'Serial',
  'scan.ct.col.sources': 'Seen in',
  'scan.ct.this': 'This certificate',
  'scan.ct.expired': 'expired',
  'scan.ct.expiring': { one: 'expires in {count} day', other: 'expires in {count} days' },
  'scan.ct.valid': 'valid',
  'scan.ct.empty': 'No certificates from CT sources (crt.sh / Cert Spotter were not used or found nothing).',
  'scan.ct.hideExpired': 'Hide expired',
  'scan.ct.match': 'The loaded certificate is in the CT logs.',
  'scan.ct.noMatch': 'The loaded certificate is not among them (private CA, or not indexed yet).',

  'scan.export.hosts': 'Hosts CSV',
  'scan.export.servers': 'Servers CSV',
  'scan.export.json': 'Full JSON',
  'scan.export.names': 'names.txt',
  'scan.export.targets': 'targets.txt',
  'scan.export.label': 'Export results',
  'scan.exported': '{file} downloaded'
});

registerStrings('tr', {
  'source.crtsh.note': 'Certificate Transparency araması. Ücretsiz; ama büyük alan adlarında yavaş (bir dakika veya daha uzun) ve zaman zaman kısa süre erişilemez olabilir.',
  'source.certspotter.note': 'Certificate Transparency API’si. Anahtarsız kullanımda IP başına saatte yaklaşık 10 istek; yalnızca süresi dolmamış sertifikalar.',
  'source.hackertarget.note': 'Güncel IP’leriyle host araması. IP başına günde yaklaşık 50 istek (ters IP sorgularıyla ortak).',
  'source.anubis.note': 'Alt alan adı veritabanı. Ücretsiz, anahtar gerekmez.',
  'source.otx.note': 'Geçmiş IP’leriyle pasif DNS — çoğu zaman Cloudflare öncesindeki sunucu. Anonim erişim sık sık hız sınırına takılır.',
  'source.thc.note': 'Son görülme tarihleriyle alt alan adı veritabanı. Ücretsiz, anahtar gerekmez; alan adı başına en fazla 1.000 ad, nazikçe 2 saniye arayla alınır.',

  'scan.step.cert': 'Sertifika',
  'scan.step.certDesc': 'Adları aramayı başlatır; her host bu sertifikaya göre kontrol edilir',
  'scan.step.domains': 'Alan adları',
  'scan.step.domainsDesc': 'Alt alan adları DNS kayıtları, kelime listeleri ve varyasyonlarla, ayrıca CT kayıtları ve pasif DNS’ten keşfedilir',
  'scan.step.inventory': 'Sunucularınız',
  'scan.step.inventoryDesc': 'Adların hangi makinelerinize işaret ettiğini gösterir',
  'scan.step.options': 'Seçenekler',
  'scan.step.optionsDesc': 'Nerede ve ne kadar kapsamlı aranacağı',
  'scan.optional': 'isteğe bağlı',
  'scan.stepDone': 'hazır',

  'scan.cert.details': 'Ayrıntılar',
  'scan.cert.remove': 'Kaldır',
  'scan.cert.another': 'Başka sertifika kullan',
  'scan.cert.none': 'İsteğe bağlı: sertifika olmadan da tarama host’ları, IP’leri ve sunucuları bulur — yalnızca kapsama kontrol edilmez.',
  'scan.cert.isCA': 'Bu bir CA sertifikası, sunucu sertifikası değil. Alan adınız için verilen sertifikayı yükleyin.',
  'scan.cert.taken': 'Sertifika, Sertifika görünümünden aktarıldı.',

  'scan.domains.label': 'Hedef alan adları',
  'scan.domains.placeholder': 'example.com.tr\nexample.com',
  'scan.domains.hint': 'Her satıra bir tane, ya da boşluk veya virgülle ayırın. URL de yazabilirsiniz.',
  'scan.domains.fromCert': 'Sertifikadan: {domains}',
  'scan.domains.useCert': 'Bunları kullan',
  'scan.domains.invalid': 'Geçerli bir alan adı değil: {list}',
  'scan.domains.publicSuffix': '{list}: com.tr gibi bir genel sonek taranamaz — example.com.tr gibi kayıtlı bir alan adı girin.',
  'scan.domains.required': 'En az bir alan adı girin veya bir sertifika yükleyin.',

  'scan.inv.servers': { one: '{count} sunucu kayıtlı', other: '{count} sunucu kayıtlı' },
  'scan.inv.ips': { one: '{count} IP adresi', other: '{count} IP adresi' },
  'scan.inv.updated': '{when} güncellendi',
  'scan.inv.edit': 'Sunucuları düzenle',
  'scan.inv.emptyTitle': 'Henüz kayıtlı sunucu yok',
  'scan.inv.emptyBody': 'Tarama yine de tüm host’ları ve IP’leri listeler; ama sertifikanın hangi sunuculara kurulacağını yalnızca envanteriniz söyleyebilir. Bir kez yapıştırın — bu tarayıcıda kalır.',
  'scan.inv.add': 'Sunucu ekle',
  'scan.inv.privacy': 'Eşleştirme tarayıcınızda yapılır; envanter hiçbir yere gönderilmez.',

  'scan.opt.sources': 'Pasif kaynaklar',
  'scan.opt.sourcesHint': 'Doğrudan tarayıcınızdan sorgulanır. Ücretsiz katmanların sınırları vardır; başarısız bir kaynak taramayı durdurmaz.',
  'scan.opt.bruteforce': 'Kaba kuvvet (kelime listesi)',
  'scan.opt.bf.off': 'Kapalı',
  'scan.opt.bf.small': 'Küçük · {count} ad',
  'scan.opt.bf.smart': 'Akıllı · {count} ad (önerilen)',
  'scan.opt.bf.large': 'Büyük · {count} ad',
  'scan.opt.bf.huge': 'Dev · {count} ad',
  'scan.opt.bf.smallHint': 'Yalnızca en yaygın adlar · alan adı başına {time}.',
  'scan.opt.bf.smartHint': 'Açık subdomain listelerinden sıralanmış, dünyada en yaygın adlar · alan adı başına {time}.',
  'scan.opt.bf.largeHint': 'Aynı sıralamanın çok daha uzun kuyruğu; tarama başlarken bu siteden yüklenir ({size}) · alan adı başına {time}.',
  'scan.opt.bf.hugeHint': 'Sıralamanın tamamı; tarama başlarken bu siteden yüklenir ({size}) · dakikalar sürer: alan adı başına {time}. Sahibi olduğunuz ve ayrıntılı haritalamak istediğiniz bir alan adı için.',
  'scan.opt.bfHint': 'Her alan adının altında adları (www, mail, vpn, panel, destek, …) genel DoH çözümleyicileriyle dener — hiçbir genel sertifikada geçmemiş host’ları bulur. Tarayıcınız sunuculara hiç bağlanmaz; çözümleyiciler önbellekte olmayan adları alan adının yetkili DNS sunucularına sorar.',
  'scan.opt.perm': 'Bulunan adların varyasyonlarını dene (permütasyon)',
  'scan.opt.permHint': 'api → api2, api-dev; shop → shopapi … ayrıca bulunan üst adların altında bir seviye daha.',
  'scan.opt.permBudget': 'En fazla',
  'scan.opt.permBudgetValue': '{count} varyasyon',
  'scan.opt.includeExpired': 'Süresi dolmuş sertifikaları da dahil et',
  'scan.opt.includeExpiredHint': 'crt.sh’teki eski adları da getirir. Daha yavaştır; büyük alan adlarında crt.sh yalnızca süresi dolmamış sertifikaları döndürebilir.',
  'scan.opt.originHints': 'Asıl sunucu ipuçlarını ara',
  'scan.opt.originHintsHint': 'Diğer genel çözümleyiciler, proxy’lenmeyen adların /24 ağı, SPF, MX ve geçmiş DNS kayıtları Cloudflare’in arkasındaki sunuculara işaret edebilir — yalnızca DNS ile.',
  'scan.opt.extra': 'Ek host adları',
  'scan.opt.extraPlaceholder': 'intranet.example.com.tr\neski-magaza.example.com.tr',
  'scan.opt.extraHint': 'Zaten bildiğiniz adlar; her zaman çözümlenir.',
  'scan.opt.doh': 'DNS over HTTPS: {chain}',
  'scan.opt.dohSpread': 'Toplu tarama sorgularını bu çözümleyicilere dağıtır — kesin bir yedekleme (failover) sırası değildir.',
  'scan.opt.dohChange': 'Değiştir',
  'scan.vocab.langs': 'Diller / pazarlar: {summary}',
  'scan.vocab.custom': '{count} özel ad',
  'scan.vocab.learned': { zero: 'henüz öğrenilen ad yok', other: 'önce {count} öğrenilen ad' },
  'scan.vocab.learnedOff': 'öğrenilen adlar kapalı',
  'scan.vocab.shared': 'Subdomain Tarama › Gelişmiş seçenekler ile ortaktır (diller, özel kelime listesi, öğrenilen adlar).',
  'scan.vocab.change': 'Subdomain Tarama’da değiştir',

  'scan.run': 'Taramayı başlat',
  'scan.runAgain': 'Yeniden tara',
  'scan.cancel': 'İptal et',
  'scan.link.prompt': 'Bu bağlantı {domains} için bir tarama açar. Hazır olduğunuzda “Taramayı başlat”a basın — pasif kaynaklar ve genel DNS çözümleyicileri tarayıcınızdan sorgulanır.',
  'scan.summary.domains': { one: '{count} alan adı', other: '{count} alan adı' },
  'scan.summary.domainsCert': 'alan adları sertifikadan',
  'scan.summary.noDomains': 'henüz alan adı yok',
  'scan.summary.sources': { zero: 'pasif kaynak yok', one: '{count} kaynak', other: '{count} kaynak' },
  'scan.summary.bf.off': 'kaba kuvvet yok',
  'scan.summary.bf.small': 'küçük kelime listesi',
  'scan.summary.bf.smart': 'akıllı kelime listesi',
  'scan.summary.bf.large': 'büyük kelime listesi',
  'scan.summary.bf.huge': 'çok büyük kelime listesi',
  'scan.summary.perm': 'varyasyonlar',
  'scan.summary.cert': 'sertifikalı',
  'scan.summary.noCert': 'sertifikasız',
  'scan.busy': 'Taranıyor…',

  'scan.run.title': '{domains} taranıyor',
  'scan.run.titleDone': '{domains} taraması',
  'scan.run.elapsed': 'geçen süre {time}',
  'scan.run.finished': '{time} içinde tamamlandı · {queries} DNS sorgusu',
  'scan.run.finishedAt': '{when} tamamlandı',
  'scan.run.cancelled': '{time} sonra iptal edildi. Şu ana kadar bulunan host’lar listelendi; sunucular, asıl sunucu ipuçları ve CT sertifikaları için taramanın tamamlanması gerekir.',
  'scan.run.cancelledShort': 'İptal edildi',
  'scan.run.failed': 'Tarama çalıştırılamadı',
  'scan.stage.sources': 'Kaynaklar',
  'scan.stage.mining': 'DNS kayıtları',
  'scan.stage.wildcard': 'Wildcard DNS',
  'scan.stage.bruteforce': 'Kaba kuvvet',
  'scan.stage.permutations': 'Varyasyonlar',
  'scan.stage.resolve': 'Çözümleme',
  'scan.stage.hints': 'Asıl sunucu ipuçları',
  'scan.stage.done': 'Bitti',
  'scan.stage.skipped': 'atlandı',
  'scan.stage.found': '+{count}',
  'scan.stage.candidates': '{count} ad',
  'scan.progress.sources': 'Pasif kaynaklar ve alan adının DNS kayıtları sorgulanıyor',
  'scan.progress.mining': 'Alan adının kendi DNS kayıtları taranıyor (MX, NS, SPF, SRV …)',
  'scan.progress.wildcard': 'Wildcard DNS kontrol ediliyor',
  'scan.progress.bruteforce': 'Kelime listesindeki adlar deneniyor',
  'scan.progress.permutations': 'Bulunan adların varyasyonları deneniyor',
  'scan.progress.resolve': 'Host adları çözümleniyor',
  'scan.progress.hints': 'Asıl sunucu ipuçları toplanıyor (diğer çözümleyiciler, ağlar, SPF, MX, geçmiş)',
  'scan.progress.done': 'Tamamlandı',
  'scan.progress.starting': 'Başlatılıyor…',
  'scan.chip.names': { zero: 'ad yok', one: '{count} ad', other: '{count} ad' },
  'scan.chip.waiting': 'bekleniyor…',
  'scan.chip.partial': 'eksik',
  'scan.chip.error.abort': 'iptal edildi',
  'scan.chip.error.timeout': 'zaman aşımı',
  'scan.chip.error.rate-limit': 'hız sınırı',
  'scan.chip.error.http': 'HTTP hatası',
  'scan.chip.error.network': 'ağ hatası',
  'scan.chip.error.parse': 'hatalı yanıt',
  'scan.chip.error.unknown': 'başarısız',
  'scan.doneToast': { one: 'Tarama bitti: {count} host', other: 'Tarama bitti: {count} host' },
  'scan.showResults': 'Sonuçları göster',
  'scan.cancelledToast': 'Tarama iptal edildi',

  'scan.results': 'Sonuçlar',
  'scan.stat.hosts': 'Host’lar',
  'scan.stat.hostsHint': '{count} tanesi çözümleniyor',
  'scan.stat.cloudflare': 'Cloudflare arkasında',
  'scan.stat.cloudflareHint': 'asıl sunucu gizli',
  'scan.stat.cdn': 'CDN / platform',
  'scan.stat.cdnHint': 'başka yerde yönetiliyor',
  'scan.stat.direct': 'Doğrudan IP',
  'scan.stat.directHint': { zero: 'sunucularınızda eşleşme yok', one: '{count} tanesi sunucularınızda', other: '{count} tanesi sunucularınızda' },
  'scan.stat.covered': 'Sertifika kapsamında',
  'scan.stat.coveredHint': '{total} host’tan',
  'scan.stat.servers': 'Güncellenecek sunucular',
  'scan.stat.serversNoCert': 'Eşleşen sunucular',
  'scan.stat.serversHint': { zero: 'başka aday yok', one: 'ipuçlarıyla +{count} olası', other: 'ipuçlarıyla +{count} olası' },
  'scan.stat.serversNoInv': 'kayıtlı envanter yok',
  'scan.stat.unresolved': 'Çözümlenmeyen',
  'scan.stat.unresolvedHint': { zero: 'sahipsiz CNAME yok', one: '{count} sahipsiz CNAME', other: '{count} sahipsiz CNAME' },
  'scan.stat.filterHint': 'Bu host’ları göster',

  'scan.sum.needs': { one: '{count} sunucunuza yeni sertifika kurulmalı.', other: '{count} sunucunuza yeni sertifika kurulmalı.' },
  'scan.sum.needsNone': 'Kayıtlı sunucularınızın hiçbiri sertifikanın kapsadığı bir adı sunmuyor.',
  'scan.sum.matched': { one: 'Adlar {count} sunucunuza işaret ediyor.', other: 'Adlar {count} sunucunuza işaret ediyor.' },
  'scan.sum.hidden': { one: '{count} host bir CDN / proxy arkasında; asıl sunucusu gizli — “CDN arkası” sekmesine bakın.', other: '{count} host bir CDN / proxy arkasında; asıl sunucuları gizli — “CDN arkası” sekmesine bakın.' },
  'scan.sum.unmatched': { one: '{count} genel IP envanterinizde yok.', other: '{count} genel IP envanterinizde yok.' },
  'scan.sum.noInventory': 'Sertifikanın hangi sunuculara kurulacağını görmek için sunucu envanterinizi ekleyin.',
  'scan.sum.dangling': { one: '{count} sahipsiz CNAME — olası alt alan adı ele geçirme riski.', other: '{count} sahipsiz CNAME — olası alt alan adı ele geçirme riski.' },
  'scan.sum.wildcard': '{list} üzerinde wildcard DNS var: oradaki her ad çözümlenir; bu yüzden yalnızca kelime listesiyle bulunanlar atıldı, benzerleri “wildcard?” olarak işaretlendi.',
  'scan.sum.sourcesFailed': { one: '{count} kaynak başarısız oldu — “Kaynaklar” sekmesine bakın. Sonuçlar yine de geçerli.', other: '{count} kaynak başarısız oldu — “Kaynaklar” sekmesine bakın. Sonuçlar yine de geçerli.' },
  'scan.sum.discovery': 'DNS ile bulunan: {dns} · pasif kaynaklardan: {sources}',
  'scan.sum.discoveryZone': 'DNS ile bulunan: {dns} · pasif kaynaklardan: {sources} · zone dosyanızdan: {zone}',
  'scan.sum.networks': 'Aday asıl sunucu ağı {list}: proxy’lenmeyen adlar burada; proxy’lenenler de burada olabilir. “CDN arkası” sekmesine bakın.',
  'scan.warn.PUBLIC_SUFFIX': '{detail} bir genel sonek olduğu için atlandı.',
  'scan.warn.INVALID_DOMAIN': 'Geçersiz alan adı atlandı: {detail}',
  'scan.warn.INVALID_NAME': 'Geçersiz host adı atlandı: {detail}',
  'scan.warn.TRUNCATED': 'Çok fazla ad var — yalnızca ilkleri çözümlendi ({detail}).',
  'scan.warn.BRUTEFORCE_TRUNCATED': 'Kelime listesi {detail} adayda kesildi.',
  'scan.warn.RECURSIVE_TRUNCATED': 'Alt seviye turu {detail} adayda kesildi.',
  'scan.warn.WILDCARD_PARENTS_TRUNCATED': 'Wildcard DNS yalnızca ilk {detail} üst ad için kontrol edildi.',
  'scan.warn.WORDLIST_DEGRADED': 'Seçilen kelime listesi yüklenemedi; daha küçük bir liste kullanıldı ({detail}).',
  'scan.warn.DNS_UNREACHABLE': 'Genel DNS çözümleyicileri yanıt vermeyi bıraktı (art arda {detail} tahmin başarısız oldu); bu yüzden kelime listesi ve varyasyonlar erken durduruldu. Bağlantınızı ya da bu ağda DNS-over-HTTPS’in engellenip engellenmediğini kontrol edin.',
  'scan.warn.ZONE_OUT_OF_SCOPE': 'Zone dosyanızdaki {detail} ad taranan alan adının dışında kaldığı için atlandı.',
  'scan.origin.zone': 'Zone dosyası',
  'scan.hint.zone': 'Zone dosyası',
  'scan.hint.zone.title': 'Zone dosyanız bu adresi proxy’li adın arkasındaki gerçek sunucu olarak gösteriyor',
  'scan.srv.via.zone': 'Zone dosyası',
  'scan.cdn.zoneTitle': 'Zone dosyanızdaki kesin originler',
  'scan.cdn.zoneDesc': 'Zone dosyanız bu proxy’li adların arkasındaki gerçek sunucuyu gösteriyor. Aşağıdaki komut bu kesin adresleri yoklar; onları asla bir /24’e genişletmez.',
  'scan.cdn.col.zoneOrigin': 'Zone dosyasındaki origin',

  'scan.tab.hosts': 'Host’lar',
  'scan.tab.servers': 'Sunucular',
  'scan.tab.cdn': 'CDN arkası',
  'scan.tab.sources': 'Kaynaklar',
  'scan.tab.ct': 'CT sertifikaları',
  'scan.pending': 'Tarama bitince görüntülenecek.',
  'scan.notAvailable': 'Görüntülenemiyor: tarama tamamlanmadı.',

  'scan.col.name': 'Host adı',
  'scan.col.status': 'Sınıflandırma',
  'scan.col.ips': 'IP adresleri',
  'scan.col.cname': 'CNAME',
  'scan.col.cert': 'Sertifika',
  'scan.col.servers': 'Sunucularınız',
  'scan.col.origins': 'Bulan',
  'scan.host.covered': 'kapsanıyor',
  'scan.host.coveredBy': '{name} kapsıyor',
  'scan.host.notCovered': 'kapsanmıyor',
  'scan.host.wildcard': 'wildcard?',
  'scan.host.wildcardTitle': 'Üst alan adının wildcard DNS kaydıyla birebir aynı çözümleniyor — gerçekte var olmayabilir.',
  'scan.host.inCert': 'sertifikada',
  'scan.host.inCertTitle': 'Sertifikada listelenmiş',
  'scan.filter.kind': 'Göster',
  'scan.filter.all': 'Tüm host’lar',
  'scan.filter.hidden': 'CDN / proxy arkasındakiler',
  'scan.filter.cloudflare': 'Cloudflare',
  'scan.filter.cdn': 'CDN / WAF',
  'scan.filter.platform': 'Platform',
  'scan.filter.cdnplatform': 'CDN veya platform',
  'scan.filter.direct': 'Doğrudan IP',
  'scan.filter.private': 'Özel IP',
  'scan.filter.unresolved': 'Çözümlenmeyenler',
  'scan.filter.dangling': 'Sahipsiz CNAME',
  'scan.filter.covered': 'Yalnızca kapsananlar',
  'scan.filter.resolving': 'Yalnızca çözümlenenler',
  'scan.filter.hideWildcard': 'Wildcard şüphelilerini gizle',
  'scan.filter.matched': 'Yalnızca sunucularım',
  'scan.hosts.empty': 'Host’lar çözümlendikçe burada görünür.',
  'scan.hosts.caption': 'Taramada bulunan host’lar',
  'scan.d.dns': 'DNS yanıtı',
  'scan.d.dnsValue': '{status} · {resolver} · TTL {ttl}',
  'scan.d.reason': 'Neden',
  'scan.d.cnames': 'CNAME zinciri',
  'scan.d.ipv4': 'IPv4',
  'scan.d.ipv6': 'IPv6',
  'scan.d.history': 'Geçmiş IP’ler',
  'scan.d.servers': 'Sunucularınız',
  'scan.d.origins': 'Bulan',
  'scan.d.tools': 'Şurada aç',
  'scan.d.error': 'Hata',
  'scan.origin.input': 'Sizin girdiniz',
  'scan.origin.cert': 'Sertifika',
  'scan.origin.bruteforce': 'Kelime listesi',
  'scan.origin.wordlist': 'Kelime listesi',
  'scan.origin.permutation': 'Varyasyon',
  'scan.origin.recursive': 'Alt seviye',
  'scan.origin.dnsmine': '{record} kaydı',

  'scan.srv.intro': 'Envanterinizdeki, adların çözümlendiği (DNS) veya asıl sunucu ipuçlarının işaret ettiği sunucular. Sertifika kurulması gerekenler en üstte.',
  'scan.srv.verifyHint': 'Kurdunuz mu? Her sunucunun gerçekte hangi sertifikayı sunduğunu internetten kontrol edin.',
  'scan.sum.verify': 'Sertifikayı kurduktan sonra internetten kontrol etmek için Doğrula sekmesini açın.',
  'scan.srv.col.server': 'Sunucu',
  'scan.srv.col.status': 'Yapılacak',
  'scan.srv.col.ips': 'Sunucu IP’leri',
  'scan.srv.col.hosts': 'Host adları',
  'scan.srv.col.count': 'Ad',
  'scan.srv.col.host': 'Host adı',
  'scan.srv.col.ip': 'IP adresi',
  'scan.srv.col.via': 'Eşleşme',
  'scan.srv.col.covered': 'Sertifika',
  'scan.srv.needs': 'Sertifikayı kurun',
  'scan.srv.serves': 'Bu adları sunuyor',
  'scan.srv.maybe': 'Olası asıl sunucu (ipucu)',
  'scan.srv.none': 'Kurulacak bir şey yok',
  'scan.srv.via.dns': 'DNS',
  'scan.srv.via.hint': 'Asıl sunucu ipucu',
  'scan.srv.empty': 'Çözümlenen IP’lerin hiçbiri kayıtlı sunucularınıza ait değil.',
  'scan.srv.noInventory': 'Kayıtlı sunucu yok — IP’leri makinelerle eşleştirmek için envanterinizi ekleyin. O zamana kadar IP’ler aşağıda listelenir.',
  'scan.srv.unmatchedTitle': 'Envanterinizde olmayan IP’ler',
  'scan.srv.unmatchedDesc': 'Adların çözümlendiği ama kayıtlı sunucularınızın hiçbirinde olmayan doğrudan IP’ler — başkasının sunucusu ya da envanterinizde eksik.',
  'scan.srv.col.owner': 'Tür',
  'scan.srv.private': 'özel',
  'scan.srv.public': 'genel',
  'scan.srv.unmatchedEmpty': 'Her doğrudan IP sunucularınızdan birine ait.',

  'scan.cdn.whyTitle': 'Asıl sunucular neden gizli',
  'scan.cdn.why1': 'Bu adlar Cloudflare’e (turuncu bulut) ya da başka bir CDN / WAF’a işaret ediyor. Genel DNS yalnızca proxy’nin adreslerini gösterir; bu yüzden hiçbir çevrimiçi araç arkada hangi sunucunuzun olduğunu göremez — tarayıcıların birbirini tutmamasının nedeni budur.',
  'scan.cdn.why2': 'Proxy yine de asıl (origin) sunucularınıza bağlanır ve onlara da sertifika gerekir (proxy “Flexible” TLS ile kendi sertifikasını kullanmıyorsa). Onları bulmanın güvenilir yolu her sunucuya doğrudan sormaktır: IP’sine bağlanıp host adını SNI ile istemek. Yardımcı CLI aracı bunu ağınızın içinden yapar.',
  'scan.cdn.hostsTitle': 'Proxy arkasındaki host’lar',
  'scan.cdn.hostsEmpty': 'Hiçbir host CDN veya proxy arkasında değil — çözümlenen her ad doğrudan bir IP’ye işaret ediyor.',
  'scan.cdn.col.provider': 'Sağlayıcı',
  'scan.cdn.col.edge': 'Uç (edge) IP’ler',
  'scan.cdn.hintsTitle': 'Asıl sunucu ipuçları',
  'scan.cdn.hintsDesc': 'Asıl sunucu olabilecek IP adresleri: diğer genel çözümleyicilerin proxy’lenen adlar için verdiği yanıtlardan, SPF ve MX kayıtlarından, proxy’lenmeyen kardeş adlardan ve geçmiş DNS’ten. CLI ile doğrulayın.',
  'scan.cdn.col.networks': 'Aynı ağda',
  'scan.cdn.netTitle': 'Asıl sunucu ağları',
  'scan.cdn.netDesc': 'Genel DNS, proxy’lenen bir kaydın asıl sunucusunu hiçbir zaman yayınlamaz. Alan adının proxy’lenmeyen adları bu ağlarda; proxy’lenen host’lar da bunlardan birinde olabilir — kanıt değil, CLI ile kontrol edilecek adaylar. Yalnızca işlettiğiniz ya da test etme yetkiniz olan ağları tarayın.',
  'scan.cdn.netEmpty': 'Genel IP’li proxy’lenmeyen bir ad bulunamadı; bu yüzden taranacak bir ağ yok.',
  'scan.cdn.col.cidr': 'Ağ',
  'scan.cdn.col.netHosts': 'Proxy’lenmeyen adlar',
  'scan.cdn.col.netIps': 'IP’ler',
  'scan.cdn.col.sweep': 'Tarama',
  'scan.cdn.col.owner': 'Sahip',
  'scan.cdn.quickTitle': 'Hızlı kontrol: asıl sunucu ağlarını tara',
  'scan.cdn.quickDesc': 'Bu ağlardaki her adrese her proxy’lenen adla (TLS SNI) bağlanır — girdi dosyası gerekmez. Ağın içinden çalıştırın; IPv6 ağlarında yalnızca bilinen adresler denenir.',
  'scan.cdn.shell': 'Kabuk',
  'scan.cdn.shell.posix': 'Linux / macOS',
  'scan.cdn.shell.powershell': 'Windows PowerShell',
  'scan.cdn.shellTitle.posix': 'bash, zsh ya da sh için (python3)',
  'scan.cdn.shellTitle.powershell': 'Windows’ta PowerShell için (python)',
  'scan.cdn.hintsEmpty': 'Asıl sunucu ipucu bulunamadı.',
  'scan.cdn.hintsOff': 'Bu taramada asıl sunucu ipuçları kapalıydı.',
  'scan.cdn.col.ip': 'IP adresi',
  'scan.cdn.col.reasons': 'Kanıt',
  'scan.cdn.col.servers': 'Sunucunuz',
  'scan.cdn.col.hosts': 'İlgili adlar',
  'scan.hint.spf': 'SPF',
  'scan.hint.mx': 'MX',
  'scan.hint.direct-sibling': 'Kardeş ad',
  'scan.hint.sibling-domain': 'Kardeş alan adı',
  'scan.hint.history': 'Geçmiş',
  'scan.hint.resolver-leak': 'Çözümleyici sızıntısı',
  'scan.hint.spf.title': 'Alan adı adına e-posta göndermeye yetkili (SPF kaydı)',
  'scan.hint.mx.title': 'Alan adının e-posta sunucusu (MX)',
  'scan.hint.direct-sibling.title': 'Aynı alan adındaki proxy’lenmeyen bir adın genel IP’si',
  'scan.hint.sibling-domain.title': 'Aynı ad, bu taramadaki bir kardeş alan adında DNS-only bir host',
  'scan.hint.history.title': 'Geçmiş DNS kayıtlarında görülmüş (muhtemelen proxy açılmadan önce)',
  'scan.hint.resolver-leak.title': 'Başka bir genel çözümleyici proxy’lenen adı bu CDN dışı adresle yanıtladı',
  'scan.cli.title': 'Ağınızın içinden doğrulayın',
  'scan.cli.desc': 'ssl_origin_scan.py her hedef IP’ye her adla (SNI) bağlanır ve hangi sunucunun hangi sertifikayı sunduğunu — yenisinin kurulu olup olmadığını da — raporlar.',
  'scan.cli.step1': 'Girdi dosyalarını indirin',
  'scan.cli.step2': 'CLI aracını indirin (Python 3.8+, bağımlılık yok)',
  'scan.cli.step3': 'Ağınızın içindeki bir makinede çalıştırın (ör. atlama sunucusu)',
  'scan.cli.step4': 'Sonucu okuyun',
  'scan.cli.names': { zero: 'names.txt (boş)', one: 'names.txt · {count} ad', other: 'names.txt · {count} ad' },
  'scan.cli.targets': { zero: 'targets.txt (boş)', one: 'targets.txt · {count} hedef', other: 'targets.txt · {count} hedef' },
  'scan.cli.certFile': 'new-cert.pem',
  'scan.cli.onlyCovered': 'Yalnızca sertifikanın kapsadığı adlar',
  'scan.cli.targetsNote': 'targets.txt = kayıtlı tüm sunucular + asıl sunucu ipuçları + bilinmeyen doğrudan IP’ler.',
  'scan.cli.noInventoryNote': 'Envanter olmadan targets.txt yalnızca ipuçlarını ve doğrudan IP’leri içerir — eksiksiz kontrol için sunucularınızı ekleyin.',
  'scan.cli.result': 'UPDATED: yeni sertifikayı zaten sunuyor · NEEDS_UPDATE: ad için bir sertifika sunuyor ama yenisini değil — buraya kurun · NOT_HOSTED: ad orada sunulmuyor.',
  'scan.cli.download': 'ssl_origin_scan.py',
  'scan.cli.command': 'Komut',

  'scan.src.col.source': 'Kaynak',
  'scan.src.col.domain': 'Alan adı',
  'scan.src.col.status': 'Durum',
  'scan.src.col.names': 'Adlar',
  'scan.src.col.ips': 'IP ipuçları',
  'scan.src.col.certs': 'Sertifikalar',
  'scan.src.col.time': 'Süre',
  'scan.src.col.error': 'Ayrıntılar',
  'scan.src.ok': 'Tamam',
  'scan.src.partial': 'Eksik',
  'scan.src.failed': 'Başarısız',
  'scan.src.healthTitle': 'Kaynak durumu',
  'scan.src.retryHint': 'Başarısız bir kaynak daha sonra yeniden denenebilir; diğer sonuçlar yine de geçerlidir.',
  'scan.src.empty': 'Kaynak sonuçları geldikçe burada görünür.',
  'scan.src.none': 'Bu taramada pasif kaynak seçilmedi.',

  'scan.ct.intro': 'Bu alan adları için Certificate Transparency kayıtlarındaki (crt.sh, Cert Spotter) sertifikalar. Süresi dolmak üzere olanlar vurgulanır.',
  'scan.ct.col.status': 'Durum',
  'scan.ct.col.issuer': 'Veren',
  'scan.ct.col.from': 'Başlangıç',
  'scan.ct.col.to': 'Bitiş',
  'scan.ct.col.names': 'Adlar',
  'scan.ct.col.serial': 'Seri no',
  'scan.ct.col.sources': 'Görüldüğü yer',
  'scan.ct.this': 'Bu sertifika',
  'scan.ct.expired': 'süresi dolmuş',
  'scan.ct.expiring': { one: '{count} gün içinde doluyor', other: '{count} gün içinde doluyor' },
  'scan.ct.valid': 'geçerli',
  'scan.ct.empty': 'CT kaynaklarından sertifika yok (crt.sh / Cert Spotter kullanılmadı veya bir şey bulamadı).',
  'scan.ct.hideExpired': 'Süresi dolanları gizle',
  'scan.ct.match': 'Yüklenen sertifika CT kayıtlarında var.',
  'scan.ct.noMatch': 'Yüklenen sertifika bunların arasında yok (özel CA ya da henüz dizine eklenmemiş).',

  'scan.export.hosts': 'Host’lar CSV',
  'scan.export.servers': 'Sunucular CSV',
  'scan.export.json': 'Tam JSON',
  'scan.export.names': 'names.txt',
  'scan.export.targets': 'targets.txt',
  'scan.export.label': 'Sonuçları dışa aktar',
  'scan.exported': '{file} indirildi'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for the E2E checks)                               */
/* ------------------------------------------------------------------------ */

/**
 * Parse the "Target domains" field.
 * @param {string} text
 * @returns {{ domains: string[], invalid: string[], publicSuffixes: string[] }} domains are
 *   normalized, wildcard-stripped and de-duplicated (input order)
 */
export function parseDomainsInput(text) {
  const { valid, invalid } = parseHostList(String(text ?? ''), { allowWildcard: true });
  const domains = [];
  const publicSuffixes = [];
  for (const v of valid) {
    const { base } = stripWildcard(v);
    if (!base) continue;
    if (isPublicSuffix(base)) {
      if (!publicSuffixes.includes(base)) publicSuffixes.push(base);
    } else if (!domains.includes(base)) {
      domains.push(base);
    }
  }
  return { domains, invalid, publicSuffixes };
}

/**
 * Domains from route params (`domain` repeatable / comma-separated, alias `domains`).
 * @param {URLSearchParams|null} searchParams
 * @param {Record<string, string>} [params]
 * @returns {string[]}
 */
export function routeDomains(searchParams, params = {}) {
  const raw = [];
  if (searchParams && typeof searchParams.getAll === 'function') {
    raw.push(...searchParams.getAll('domain'), ...searchParams.getAll('domains'));
  }
  if (!raw.length) raw.push(params.domain || '', params.domains || '');
  return parseDomainsInput(splitList(raw.join('\n')).join('\n')).domains;
}

/**
 * Validate stored scan options; unknown values fall back to defaults (smart wordlist,
 * permutations with a 1,500 budget, origin hints on). A legacy 'medium' level loads as
 * 'smart' (its superset). A v1.0 save (no `knownSources`: v1.0 stored the whole options object
 * on any change, with brute force 'off' — its default then) loads 'off' as 'smart' once;
 * every later save carries `knownSources`, so a deliberate 'off' stays off.
 * @param {any} input
 * @returns {{ sources: string[], knownSources: string[], includeExpired: boolean,
 *   bruteforce: 'off'|'small'|'smart'|'large', permutations: boolean, permutationBudget: number, originHints: boolean }}
 */
export function sanitizeOptions(input) {
  const src = input && typeof input === 'object' ? input : {};
  const ids = SOURCES.map((s) => s.id);
  const defaults = SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const hasStored = Array.isArray(src.sources);
  const sources = hasStored ? [...new Set(src.sources.filter((x) => ids.includes(x)))] : [...defaults];
  // Migration: surface newly-added default sources (e.g. ip.thc.org) once, so a
  // returning user's saved selection still gains them — while a source they later
  // untick stays unticked (tracked via `knownSources`; saves from before it existed
  // knew the original five).
  const known = new Set((Array.isArray(src.knownSources) ? src.knownSources : LEGACY_KNOWN_SOURCES).filter((x) => ids.includes(x)));
  if (hasStored) for (const sid of defaults) if (!known.has(sid) && !sources.includes(sid)) sources.push(sid);
  const legacySave = hasStored && !Array.isArray(src.knownSources);
  const bf0 = legacySave && src.bruteforce === 'off' ? 'smart' : src.bruteforce;
  const bf = Object.prototype.hasOwnProperty.call(LEGACY_BRUTEFORCE, bf0) ? LEGACY_BRUTEFORCE[bf0] : bf0;
  const budget = Number(src.permutationBudget);
  return {
    sources,
    knownSources: [...ids],
    includeExpired: src.includeExpired === true,
    bruteforce: BRUTEFORCE_MODES.includes(bf) ? bf : 'smart',
    permutations: src.permutations !== false,
    permutationBudget: PERMUTATION_BUDGETS.includes(budget) ? budget : DEFAULT_PERMUTATION_BUDGET,
    originHints: src.originHints !== false
  };
}

function loadOptions() {
  try {
    const raw = globalThis.localStorage && globalThis.localStorage.getItem(OPTIONS_KEY);
    return sanitizeOptions(raw ? JSON.parse(raw) : null);
  } catch {
    return sanitizeOptions(null);
  }
}

function saveOptions(options) {
  try {
    if (globalThis.localStorage) globalThis.localStorage.setItem(OPTIONS_KEY, JSON.stringify(sanitizeOptions(options)));
  } catch {
    // private mode / quota: the options simply are not remembered
  }
}

/**
 * Does a host match a "Show" filter value?
 * @param {{ classification: { kind: string, dangling: boolean, hidesOrigin: boolean } }} host
 * @param {string} filter one of {@link KIND_FILTERS}
 * @returns {boolean}
 */
export function kindMatches(host, filter) {
  const c = host.classification || {};
  switch (filter) {
    case 'hidden': return !!c.hidesOrigin;
    case 'cdnplatform': return c.kind === 'cdn' || c.kind === 'platform';
    case 'unresolved': return c.kind === 'unresolved' || c.kind === 'nxdomain';
    case 'dangling': return !!c.dangling;
    case 'cloudflare':
    case 'cdn':
    case 'platform':
    case 'direct':
    case 'private':
      return c.kind === filter;
    default:
      return true;
  }
}

/**
 * Combined predicate of the Hosts tab filters.
 * @param {{ kind?: string, covered?: boolean, resolving?: boolean, hideWildcard?: boolean, matched?: boolean }} f
 * @returns {((host: object) => boolean)|null} null when nothing filters
 */
export function hostFilter({ kind = 'all', covered = false, resolving = false, hideWildcard = false, matched = false } = {}) {
  if (kind === 'all' && !covered && !resolving && !hideWildcard && !matched) return null;
  return (host) => kindMatches(host, kind)
    && (!covered || !!(host.cert && host.cert.covered))
    && (!resolving || host.resolution.ipv4.length > 0 || host.resolution.ipv6.length > 0)
    && (!hideWildcard || !host.wildcardSuspect)
    && (!matched || host.servers.length > 0);
}

/**
 * Live statistics over streamed HostRecords (the final numbers come from ScanResult.stats).
 * @param {object[]} hosts
 * @returns {{ total: number, resolved: number, cloudflare: number, cdn: number, platform: number, direct: number,
 *   private: number, unresolved: number, nxdomain: number, dangling: number, covered: number, hidden: number, onServers: number }}
 */
export function countHosts(hosts) {
  const s = { total: 0, resolved: 0, cloudflare: 0, cdn: 0, platform: 0, direct: 0, private: 0, unresolved: 0, nxdomain: 0, dangling: 0, covered: 0, hidden: 0, onServers: 0 };
  for (const x of hosts || []) {
    s.total += 1;
    const c = x.classification || {};
    if (x.resolution && (x.resolution.ipv4.length || x.resolution.ipv6.length)) s.resolved += 1;
    if (s[c.kind] !== undefined && c.kind !== 'total') s[c.kind] += 1;
    if (c.dangling) s.dangling += 1;
    if (c.hidesOrigin) s.hidden += 1;
    if (x.cert && x.cert.covered) s.covered += 1;
    if (x.servers && x.servers.length && (c.kind === 'direct' || c.kind === 'private')) s.onServers += 1;
  }
  return s;
}

/**
 * Aggregate the per-domain SourceResults of one source into a status chip state.
 * @param {object[]} results SourceResults received so far
 * @param {string} sourceId
 * @param {number} expected number of domains queried
 * @returns {{ state: 'pending'|'ok'|'partial'|'error', names: number, done: number, expected: number,
 *   errorKind: string|null, error: string|null }}
 */
export function sourceChipState(results, sourceId, expected) {
  const mine = (results || []).filter((r) => r.source === sourceId);
  const names = new Set();
  mine.forEach((r) => r.names.forEach((n) => names.add(n)));
  const failed = mine.filter((r) => !r.ok);
  const partial = mine.some((r) => r.ok && r.partial);
  let st = 'pending';
  if (mine.length >= expected && expected > 0) {
    if (failed.length === mine.length) st = 'error';
    else if (failed.length || partial) st = 'partial';
    else st = 'ok';
  }
  const err = failed[0] || mine.find((r) => r.partial) || null;
  return {
    state: st,
    names: names.size,
    done: mine.length,
    expected,
    errorKind: err ? err.errorKind : null,
    error: err ? err.error : null
  };
}

/**
 * CT certificate status at `now`.
 * @param {{ notAfter: Date|null }} cert
 * @param {Date|number} [now]
 * @returns {{ state: 'expired'|'expiring'|'valid'|'unknown', days: number|null }}
 */
export function ctStatus(cert, now = Date.now()) {
  if (!(cert && cert.notAfter instanceof Date) || Number.isNaN(cert.notAfter.getTime())) return { state: 'unknown', days: null };
  const days = daysUntil(cert.notAfter, now);
  if (cert.notAfter.getTime() < (now instanceof Date ? now.getTime() : now)) return { state: 'expired', days };
  return { state: days <= EXPIRING_DAYS ? 'expiring' : 'valid', days };
}

/** Sort key that groups siblings like sortHostnames (reversed labels). */
function hostSortKey(name) {
  return String(name || '').split('.').reverse().join('.');
}

function kindRank(host) {
  const c = host.classification || {};
  const k = c.dangling ? 'dangling' : c.kind;
  const i = KIND_ORDER.indexOf(k);
  return i === -1 ? KIND_ORDER.length : i;
}

/**
 * Localized label of an origin id ('input', 'cert', 'wordlist', 'dns-mine:MX', a source id …).
 * @param {string} origin
 * @returns {string}
 */
export function originLabel(origin) {
  if (typeof origin === 'string' && origin.startsWith('dns-mine:')) {
    return t('scan.origin.dnsmine', { record: origin.slice('dns-mine:'.length) });
  }
  if (origin === 'input' || origin === 'cert' || origin === 'bruteforce'
    || origin === 'wordlist' || origin === 'permutation' || origin === 'recursive' || origin === 'zone') {
    return t(`scan.origin.${origin}`);
  }
  return SOURCE_NAMES[origin] || origin;
}

/* ------------------------------------------------------------------------ */
/* Scan runs (module-owned: they outlive a mounted view)                    */
/* ------------------------------------------------------------------------ */

/** Current / last scan and the setup fields, kept for this page session. */
const session = {
  domainsText: '',
  domainsFromCert: false,
  certKeyForDomains: null,
  extraText: '',
  cdnShell: 'posix',
  /** Results tab shown when the run UI is rebuilt (null = Hosts); the Verify toast sets it. */
  scanTab: null,
  run: null
};

/**
 * How the next scan uses each imported zone ('exact' | 'discover' | 'off'), keyed by the zone
 * object in state.session.zone (a forgotten zone drops out with its key).
 */
const zoneModes = new WeakMap();
let runCounter = 0;
/** The mounted view (null when another tool is shown). */
let active = null;

/**
 * @typedef {object} ScanRun
 * @property {number} id
 * @property {object} config summary of what was scanned
 * @property {AbortController} controller
 * @property {'running'|'done'|'cancelled'|'error'} status
 * @property {Record<string, { state: 'pending'|'active'|'done'|'skipped'|'stopped', info: object|null, candidates?: number }>} stages
 *   ('stopped': the stage that was running when the scan was cancelled or failed)
 * @property {{ stage: string|null, done: number, total: number }} progress
 * @property {{ done: number, total: number }|null} miningProgress DNS-record mining reported while the sources ran
 * @property {object|null} rounds permutation rounds seen so far (keeps the bar moving forward)
 * @property {object[]} sourceResults
 * @property {{ domains: string[], sources: string[] }} sourcePlan
 * @property {object[]} hosts streamed HostRecords
 * @property {object|null} result ScanResult
 * @property {unknown} error
 * @property {Date} startedAt
 * @property {Date|null} finishedAt
 * @property {number|null} queriesAtStart DohClient query counter when the run started
 * @property {Set<(type: string, payload: any) => void>} listeners
 */

function createRun(config) {
  runCounter += 1;
  const stages = {};
  for (const s of SCAN_STAGES) stages[s] = { state: 'pending', info: null };
  return {
    id: runCounter,
    config,
    controller: new AbortController(),
    status: 'running',
    stages,
    progress: { stage: null, done: 0, total: 0 },
    miningProgress: null,
    rounds: null,
    sourceResults: [],
    sourcePlan: { domains: [], sources: [] },
    hosts: [],
    // Streamed probe partials (hooks.onFound), keyed by name; superseded by the full record.
    found: new Map(),
    sourceWait: null,
    result: null,
    error: null,
    startedAt: new Date(),
    finishedAt: null,
    queriesAtStart: null,
    listeners: new Set()
  };
}

function emit(run, type, payload) {
  for (const fn of [...run.listeners]) {
    try {
      fn(type, payload);
    } catch (err) {
      // A rendering bug must not stop the scan; surface it to the shell's error handler.
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

/**
 * Start lib/scanner.runScan for a run; events are recorded on the run and re-emitted to
 * the mounted view (if any).
 */
function startRun(run, scanConfig, appState) {
  const hooks = {
    onStage(stage, info = {}) {
      // Shared with the Subdomains view (parallel mining, wordlist size, source plan).
      applyStage(run, stage, info);
      emit(run, 'stage', { stage, info });
    },
    onSource(result) {
      run.sourceResults.push(result);
      emit(run, 'source', result);
    },
    onHost(record) {
      run.hosts.push(record);
      if (run.found.has(record.name)) run.found.delete(record.name);
      emit(run, 'host', record);
    },
    onFound(partial) {
      if (!partial || !partial.name) return;
      if (run.hosts.some((x) => x.name === partial.name)) return;
      const record = partialHostRecord(partial);
      run.found.set(partial.name, record);
      emit(run, 'found', record);
    },
    onProgress(p) {
      const pills = applyProgress(run, p);
      emit(run, 'progress', { ...run.progress, pills });
    }
  };
  runScan({ ...scanConfig, signal: run.controller.signal }, hooks).then((result) => {
    run.result = result;
    run.status = 'done';
    run.finishedAt = new Date();
    // Hand the names to Bulk Resolve ("Use the names of the last scan").
    appState.setSession('scanHosts', {
      domains: result.domains,
      names: result.hosts.filter((x) => !x.wildcardSuspect).map((x) => x.name),
      resolving: result.hosts.filter((x) => !x.wildcardSuspect && isResolving(x)).map((x) => x.name),
      finishedAt: run.finishedAt
    });
    // Learn the naming vocabulary like Subdomains does (opt-in; bare labels of in-scope names only,
    // stored in this browser — later scans send them as DNS lookups).
    if (rememberLearned(result, run.config && run.config.learned) && active && active.refreshVocab) active.refreshVocab();
    emit(run, 'done', result);
    if (!active) {
      toast(t('scan.doneToast', { count: result.hosts.length }), {
        type: 'success',
        timeout: 10000,
        action: {
          label: t('scan.showResults'),
          onClick: () => {
            globalThis.location.hash = '#/scan';
          }
        }
      });
    }
  }, (err) => {
    run.finishedAt = new Date();
    stopStages(run);
    if (errorKind(err) === 'abort') {
      run.status = 'cancelled';
      emit(run, 'cancelled', null);
    } else {
      run.status = 'error';
      run.error = err;
      emit(run, 'error', err);
    }
  });
}

/** Schedule `fn` at most once per animation frame. */
function frameThrottle(fn) {
  let queued = false;
  const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
  const wrapped = () => {
    if (queued) return;
    queued = true;
    raf(() => {
      queued = false;
      fn();
    });
  };
  return wrapped;
}

/**
 * Call `fn` at most every `ms` milliseconds (the last call always runs). Used for work that
 * walks every streamed host, so thousands of hosts do not cost a full pass per frame.
 */
function timeThrottle(fn, ms) {
  let timer = null;
  let last = 0;
  return () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      last = Date.now();
      fn();
    }, Math.max(0, ms - (Date.now() - last)));
  };
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the SSL Targets view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  const cleanups = [];
  let options = loadOptions();

  /* --- certificate hand-over / shared certificate ------------------------ */
  const pending = normalizeCertLoad(state.takeSession(PENDING_CERT));
  let takenOver = false;
  if (pending) {
    setCurrentCert(state, pending);
    takenOver = true;
    // An explicit hand-over ("Find servers for this certificate") fills in its domains even
    // when the field holds older text; route params below still win.
    session.domainsFromCert = true;
    session.certKeyForDomains = null;
  }
  let certLoad = getCurrentCert(state);

  /* --- route params -------------------------------------------------------- */
  const fromRoute = routeDomains(ctx.searchParams, ctx.params);
  if (fromRoute.length) {
    session.domainsText = fromRoute.join('\n');
    session.domainsFromCert = false;
  }

  /* --- Zone File hand-off ("Find certificate targets") ---------------------- */
  // A one-shot intent pre-fills step 2 with the zone's domain and presets exact mode; it never
  // starts the scan (the Run button does).
  const zoneIntent = state.takeSession('zoneScanIntent');
  if (validZoneIntent(zoneIntent, 'scan', state.getSession('zone'))) {
    if (!fromRoute.length && zoneIntent.domain) {
      session.domainsText = String(zoneIntent.domain);
      session.domainsFromCert = false;
    }
    zoneModes.set(state.getSession('zone'), zoneIntent.mode === 'discover' ? 'discover' : 'exact');
  }

  /* --- step 1: certificate --------------------------------------------------- */
  const certBody = h('div', { class: 'stack-sm' });
  const certStatus = h('span', { class: 'scan-step-status' });

  function certLeaf() {
    return certLoad && certLoad.result.leaf ? certLoad.result.leaf : null;
  }

  function renderCertStep() {
    clear(certBody);
    clear(certStatus);
    const leaf = certLeaf();
    certStatus.append(leaf
      ? Badge(t('scan.stepDone'), { variant: 'ok', icon: 'check' })
      : Badge(t('scan.optional'), { variant: 'neutral' }));
    if (!certLoad) {
      certBody.append(CertLoader({ onLoad: onCertLoad }).el,
        h('p', { class: 'muted text-sm' }, t('scan.cert.none')));
      return;
    }
    if (takenOver) certBody.append(Alert({ variant: 'info', compact: true, icon: 'arrow-right', message: t('scan.cert.taken'), dismissible: true, onDismiss: () => { takenOver = false; } }));
    certBody.append(...certWarningAlerts(certLoad.result, { name: certLoad.name }));
    if (leaf) {
      if (leaf.isCA) certBody.append(Alert({ variant: 'warn', compact: true, message: t('scan.cert.isCA') }));
      certBody.append(CertSummary(certLoad, {
        maxNames: 6,
        actions: [
          Button({ label: t('scan.cert.details'), icon: 'eye', size: 'sm', variant: 'ghost', dataset: { action: 'cert-details' }, onClick: () => ctx.navigate('cert') }),
          Button({ label: t('scan.cert.remove'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'cert-remove' }, onClick: () => onCertLoad(null) })
        ]
      }));
      certBody.append(Disclosure({
        summary: t('scan.cert.another'),
        className: 'scan-cert-another',
        children: CertLoader({ onLoad: onCertLoad, compact: true }).el
      }));
    } else {
      certBody.append(CertLoader({ onLoad: onCertLoad, compact: true }).el);
    }
  }

  function onCertLoad(load) {
    takenOver = false;
    certLoad = load;
    setCurrentCert(state, load);
    autoFillDomains();
    renderCertStep();
    renderDomainsHint();
    renderRunSummary();
  }

  /* --- step 2: domains ------------------------------------------------------ */
  const domainsField = textarea({
    label: t('scan.domains.label'),
    rows: 3,
    placeholder: t('scan.domains.placeholder'),
    hint: t('scan.domains.hint'),
    value: session.domainsText,
    attrs: { 'data-role': 'scan-domains' },
    onInput: (value) => {
      session.domainsText = value;
      session.domainsFromCert = false;
      domainsField.setError(null);
      hideLinkPrompt();
      renderDomainsHint();
      renderRunSummary();
    }
  });
  const domainsHint = h('div', { class: 'scan-domains-cert' });
  // "Zone file loaded" chip (shared with Subdomains): shown while the imported zone belongs to a
  // domain of step 2.
  const zoneHost = h('div', { class: 'sub-zone-host scan-zone-host', hidden: true });
  const activeZone = () => zoneForDomains(state.getSession('zone'), parseDomainsInput(domainsField.value).domains);
  let zoneShown = null;
  function renderZoneChip() {
    const zone = activeZone();
    if (zone === zoneShown && (zone ? !zoneHost.hidden : zoneHost.hidden)) return;
    zoneShown = zone;
    clear(zoneHost);
    zoneHost.hidden = !zone;
    if (!zone) return;
    zoneHost.append(ZoneChip({
      zone,
      mode: zoneModes.get(zone) || 'discover',
      href: ctx.href('zone'),
      onMode: (m) => {
        zoneModes.set(zone, m);
        renderRunSummary();
      }
    }));
  }
  const domainsStatus = h('span', { class: 'scan-step-status' });

  function certDomains() {
    const leaf = certLeaf();
    return leaf ? baseDomainsFromNames(leaf.hostnames) : [];
  }

  function autoFillDomains() {
    const leaf = certLeaf();
    if (!leaf) return;
    const key = `${leaf.serialHex}|${leaf.issuerDN}`;
    if (session.certKeyForDomains === key) return;
    session.certKeyForDomains = key;
    const list = certDomains();
    if (!list.length) return;
    if (!session.domainsText.trim() || session.domainsFromCert) {
      session.domainsText = list.join('\n');
      session.domainsFromCert = true;
      domainsField.value = session.domainsText;
      domainsField.setError(null);
    }
  }

  function renderDomainsHint() {
    renderZoneChip();
    clear(domainsHint);
    clear(domainsStatus);
    const parsed = parseDomainsInput(domainsField.value);
    domainsStatus.append(parsed.domains.length
      ? Badge(t('scan.summary.domains', { count: parsed.domains.length }), { variant: 'ok', icon: 'check' })
      : Badge(t('scan.optional'), { variant: 'neutral' }));
    const list = certDomains();
    if (!list.length) return;
    const same = list.length === parsed.domains.length && list.every((d) => parsed.domains.includes(d));
    if (same) return;
    domainsHint.append(Icon('certificate', { size: 14 }),
      h('span', { class: 'text-sm' }, t('scan.domains.fromCert', { domains: list.join(', ') })),
      h('button', {
        type: 'button',
        class: 'link-btn',
        dataset: { action: 'use-cert-domains' },
        on: {
          click: () => {
            session.domainsText = list.join('\n');
            session.domainsFromCert = true;
            domainsField.value = session.domainsText;
            domainsField.setError(null);
            renderDomainsHint();
            renderRunSummary();
          }
        }
      }, t('scan.domains.useCert')));
  }

  /* --- step 3: inventory ------------------------------------------------------ */
  const invBody = h('div', { class: 'stack-sm' });
  const invStatus = h('span', { class: 'scan-step-status' });

  function renderInventoryStep() {
    clear(invBody);
    clear(invStatus);
    const inv = state.inventory;
    const servers = inv.servers.length;
    if (!servers) {
      invStatus.append(Badge(t('scan.optional'), { variant: 'neutral' }));
      invBody.append(EmptyState({
        compact: true,
        icon: 'server',
        title: t('scan.inv.emptyTitle'),
        message: t('scan.inv.emptyBody'),
        action: h('a', { class: 'btn btn-secondary btn-sm', href: ctx.href('inventory'), dataset: { action: 'add-servers' } },
          Icon('plus', { size: 14 }), h('span', { class: 'btn-label' }, t('scan.inv.add')))
      }));
      return;
    }
    const ips = new Set(inv.servers.flatMap((s) => s.ips)).size;
    invStatus.append(Badge(t('scan.stepDone'), { variant: 'ok', icon: 'check' }));
    invBody.append(h('div', { class: 'scan-inv' },
      h('span', { class: 'scan-inv-icon' }, Icon('server', { size: 18 })),
      h('div', { class: 'scan-inv-text' },
        h('div', { class: 'scan-inv-count', dataset: { servers: servers } }, t('scan.inv.servers', { count: servers })),
        h('div', { class: 'muted text-sm' }, t('scan.inv.ips', { count: ips }),
          inv.updatedAt ? ` · ${t('scan.inv.updated', { when: formatRelative(inv.updatedAt) })}` : '')),
      h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('inventory') }, Icon('sliders', { size: 14 }), h('span', { class: 'btn-label' }, t('scan.inv.edit')))),
    h('p', { class: 'muted text-sm scan-privacy' }, Icon('lock', { size: 13 }), ' ', t('scan.inv.privacy')));
  }

  /* --- step 4: options -------------------------------------------------------- */
  const sourcesGroup = checkboxGroup({
    legend: t('scan.opt.sources'),
    name: 'scan-sources',
    selectAll: true,
    hint: t('scan.opt.sourcesHint'),
    values: options.sources,
    options: SOURCES.map((s) => ({ value: s.id, label: s.name, hint: t(s.noteKey) })),
    onChange: (values) => {
      options = { ...options, sources: values };
      saveOptions(options);
      renderRunSummary();
    },
    className: 'scan-sources'
  });
  // Labels / hints are live nodes: the smart list's real size arrives asynchronously.
  const bfLabels = {};
  const bfHints = {};
  const bfGroup = radioGroup({
    legend: t('scan.opt.bruteforce'),
    name: 'scan-bruteforce',
    value: options.bruteforce,
    hint: t('scan.opt.bfHint'),
    options: BRUTEFORCE_MODES.map((mode) => {
      bfLabels[mode] = h('span', { dataset: { level: mode } });
      bfHints[mode] = mode === 'off' ? null : h('span');
      return { value: mode, label: bfLabels[mode], hint: bfHints[mode] };
    }),
    onChange: (value) => {
      options = { ...options, bruteforce: value };
      saveOptions(options);
      renderRunSummary();
    },
    className: 'scan-bf'
  });
  const sweepWidth = () => scanConcurrency(state.settings.concurrency);
  // The shared vocabulary (languages, custom wordlist, learned names — set in Subdomains ›
  // Advanced) and the wordlist plan for the domains typed here, like the Subdomains page shows.
  const vocabLine = h('div', { class: 'scan-vocab text-sm', dataset: { role: 'scan-vocab' } });
  const planLine = h('div', { class: 'scan-wl-plan text-sm', dataset: { role: 'scan-wl-plan' }, attrs: { 'aria-live': 'polite' } });
  /**
   * The bases the scan brute-forces, as lib/scanner builds them: the typed domains (or, with none
   * typed, the registrable domains of the certificate + extra names) plus the base of every
   * wildcard among them — `*.api.example.com` gets the level list again under api.example.com —
   * so the plan and its time estimate count what really runs. (The extra names come from the
   * session copy: this runs before the field exists.)
   */
  function planDomains() {
    const leaf = certLeaf();
    const extras = parseHostList(session.extraText || '', { allowWildcard: true }).valid;
    return bruteforceBases(parseDomainsInput(domainsField.value).domains, [...(leaf ? leaf.hostnames : []), ...extras]);
  }
  function renderVocab() {
    renderBfOptions();
    clear(vocabLine);
    clear(planLine);
    const vocab = sharedVocabulary();
    const domains = planDomains();
    vocabLine.hidden = options.bruteforce === 'off';
    if (options.bruteforce === 'off') {
      planLine.append(Icon('info', { size: 13 }), h('span', null, t('sub.plan.off')));
      return;
    }
    const parts = [t('scan.vocab.langs', { summary: localeSummary(vocab.locales, domains) })];
    if (vocab.custom.length) parts.push(t('scan.vocab.custom', { count: vocab.custom.length }));
    parts.push(vocab.learnedOn ? t('scan.vocab.learned', { count: Math.min(vocab.learned.length, LEARNED_TRY_MAX) }) : t('scan.vocab.learnedOff'));
    vocabLine.append(Icon('list', { size: 14 }),
      h('span', { class: 'scan-vocab-text' }, parts.join(' · ')),
      h('span', { class: 'scan-vocab-shared' }, t('scan.vocab.shared'), ' ',
        h('a', { href: ctx.href('subdomains'), class: 'scan-vocab-change', dataset: { action: 'scan-vocab-change' } }, t('scan.vocab.change'))));
    if (!domains.length) {
      planLine.append(Icon('info', { size: 13 }), h('span', null, t('sub.plan.none')));
      return;
    }
    const learnedCount = vocab.learnedOn ? Math.min(vocab.learned.length, LEARNED_TRY_MAX) : 0;
    const plan = wordlistPlan({
      level: options.bruteforce,
      domains,
      locales: vocab.locales,
      custom: vocab.custom.length,
      learned: learnedCount
    });
    // The honest whole-scan query estimate (wordlist + variations + deeper round + origin hints),
    // so the plan line does not under-count like a wordlist-only figure would.
    const certNames = certLeaf() ? certLeaf().hostnames : [];
    const extraNames = parseHostList(session.extraText || '', { allowWildcard: true }).valid;
    const queries = planQueryRange({
      level: options.bruteforce, domains, locales: vocab.locales, custom: vocab.custom.length, learned: learnedCount,
      permutations: options.permutations, permutationBudget: options.permutationBudget, originHints: options.originHints,
      certNames, extraNames
    });
    planLine.dataset.total = String(plan.total);
    planLine.dataset.queriesMin = String(queries.min);
    planLine.dataset.queriesMax = String(queries.max);
    planLine.append(Icon('search', { size: 13 }), h('span', null, wordlistPlanText(plan, sweepWidth(), queries)));
  }
  function renderBfOptions() {
    // From Smart up, the locale packs the domains get are added on top (like Subdomains shows).
    const domains = planDomains();
    const { locales } = sharedVocabulary();
    for (const mode of BRUTEFORCE_MODES) {
      clear(bfLabels[mode]);
      if (mode === 'off') {
        bfLabels[mode].append(t('scan.opt.bf.off'));
        continue;
      }
      const wc = wordlistCount(mode);
      const packs = levelPacks(mode, domains, locales);
      bfLabels[mode].append(t(`scan.opt.bf.${mode}`, { count: wc.text }));
      if (packs.length) {
        bfLabels[mode].append(h('span', { class: 'scan-bf-packs' },
          packs.map((p) => t('sub.plan.pack', { count: formatNumber(p.count), language: languageName(p.code) })).join(', ')));
      }
      clear(bfHints[mode]);
      const extra = packs.reduce((a, p) => a + p.count, 0);
      bfHints[mode].append(t(`scan.opt.bf.${mode}Hint`, { time: estimateText(wc.count + extra, 1, sweepWidth()), size: levelSize(mode) }));
    }
  }
  renderBfOptions();
  ensureSmartCount().then(() => {
    if (!ctx.signal.aborted) renderBfOptions();
  });
  const permBox = checkbox({
    label: t('scan.opt.perm'),
    hint: t('scan.opt.permHint'),
    checked: options.permutations,
    className: 'scan-perm',
    onChange: (on) => {
      options = { ...options, permutations: on };
      saveOptions(options);
      budgetSelect.input.disabled = !on;
      renderRunSummary();
    }
  });
  permBox.input.dataset.role = 'scan-permutations';
  const budgetSelect = select({
    label: t('scan.opt.permBudget'),
    size: 'sm',
    className: 'scan-perm-budget',
    value: String(options.permutationBudget),
    options: PERMUTATION_BUDGETS.map((n) => ({ value: String(n), label: t('scan.opt.permBudgetValue', { count: n }) })),
    onChange: (v) => {
      options = { ...options, permutationBudget: Number(v) };
      saveOptions(options);
    }
  });
  budgetSelect.input.disabled = !options.permutations;
  const expiredBox = checkbox({
    label: t('scan.opt.includeExpired'),
    hint: t('scan.opt.includeExpiredHint'),
    checked: options.includeExpired,
    onChange: (on) => {
      options = { ...options, includeExpired: on };
      saveOptions(options);
    }
  });
  const hintsBox = checkbox({
    label: t('scan.opt.originHints'),
    hint: t('scan.opt.originHintsHint'),
    checked: options.originHints,
    onChange: (on) => {
      options = { ...options, originHints: on };
      saveOptions(options);
    }
  });
  const extraField = textarea({
    label: t('scan.opt.extra'),
    optional: true,
    rows: 3,
    placeholder: t('scan.opt.extraPlaceholder'),
    hint: t('scan.opt.extraHint'),
    value: session.extraText,
    attrs: { 'data-role': 'scan-extra' },
    onInput: (value) => {
      session.extraText = value;
      extraField.setError(null);
      // A wildcard extra name (`*.api.example.com`) is one more base the wordlist runs under.
      renderVocab();
    }
  });
  const dohLine = h('div', { class: 'scan-doh text-sm' });
  function renderDoh() {
    clear(dohLine);
    const chain = state.settings.chain.map((rid) => (getResolver(rid) || { name: rid }).name).join(' → ');
    dohLine.append(Icon('globe', { size: 14 }), h('span', null, t('scan.opt.doh', { chain })),
      h('button', {
        type: 'button',
        class: 'link-btn',
        on: { click: () => globalThis.document.querySelector('[data-control="settings"]')?.click() }
      }, t('scan.opt.dohChange')),
      h('span', { class: 'scan-doh-spread' }, t('scan.opt.dohSpread')));
  }

  /* --- run bar ----------------------------------------------------------------- */
  const runBtn = Button({ label: t('scan.run'), icon: 'play', variant: 'primary', size: 'lg', dataset: { action: 'scan-run' }, onClick: () => start() });
  const cancelBtn = Button({ label: t('scan.cancel'), icon: 'stop', variant: 'secondary', size: 'lg', dataset: { action: 'scan-cancel' }, onClick: () => cancel() });
  const runSummary = h('div', { class: 'scan-runbar-summary text-sm' });
  const runError = h('div', { class: 'scan-runbar-error', attrs: { 'aria-live': 'polite' } });
  const linkPrompt = h('div', { class: 'scan-link-prompt', hidden: true });

  function showLinkPrompt(domains) {
    clear(linkPrompt);
    linkPrompt.hidden = !domains.length;
    if (!domains.length) return;
    linkPrompt.append(Alert({ variant: 'info', icon: 'link', compact: true, message: t('scan.link.prompt', { domains: domains.join(', ') }) }));
  }

  function hideLinkPrompt() {
    clear(linkPrompt);
    linkPrompt.hidden = true;
  }

  function renderRunSummary() {
    renderVocab();
    const parsed = parseDomainsInput(domainsField.value);
    let domainsText = t('scan.summary.noDomains');
    if (parsed.domains.length) domainsText = t('scan.summary.domains', { count: parsed.domains.length });
    else if (certLeaf() && certLeaf().hostnames.length) domainsText = t('scan.summary.domainsCert');
    clear(runSummary);
    // Exact zone mode (one run): the zone's names only — no sources, wordlist or permutations.
    const zone = activeZone();
    const exact = !!zone && zoneModes.get(zone) === 'exact';
    // dom.js append(): the parts left out are null, which Element.append would print as "null".
    append(runSummary,
      h('span', null, domainsText),
      h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('span', null, t('scan.summary.sources', { count: exact ? 0 : options.sources.length })),
      h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('span', null, t(`scan.summary.bf.${exact ? 'off' : options.bruteforce}`)),
      options.permutations && !exact ? h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·') : null,
      options.permutations && !exact ? h('span', null, t('scan.summary.perm')) : null,
      zone && zoneModes.get(zone) !== 'off' ? h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·') : null,
      zone && zoneModes.get(zone) !== 'off' ? h('span', { dataset: { zoneMode: exact ? 'exact' : 'discover' } }, t('sub.origin.zone')) : null,
      h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('span', null, certLeaf() ? t('scan.summary.cert') : t('scan.summary.noCert')));
  }

  function setRunning(on) {
    runBtn.hidden = on;
    cancelBtn.hidden = !on;
    runBtn.querySelector('.btn-label').textContent = session.run && !on ? t('scan.runAgain') : t('scan.run');
    if (on) ctx.setBusy(t('scan.busy'));
    else ctx.setBusy(false);
  }

  /* --- layout ------------------------------------------------------------------ */
  const step = (n, key, iconName, status, body, className = '') => h('section', {
    class: ['scan-step', 'card', className],
    dataset: { step: key },
    attrs: { 'aria-labelledby': `scan-step-${key}` }
  },
  h('div', { class: 'scan-step-head' },
    h('span', { class: 'scan-step-num num', attrs: { 'aria-hidden': 'true' } }, String(n)),
    h('div', { class: 'scan-step-titles' },
      h('h2', { class: 'scan-step-title', id: `scan-step-${key}` }, Icon(iconName, { size: 15 }), h('span', null, t(`scan.step.${key}`))),
      h('p', { class: 'scan-step-desc' }, t(`scan.step.${key}Desc`))),
    status),
  h('div', { class: 'scan-step-body' }, body));

  const setup = h('div', { class: 'scan-setup' },
    step(1, 'cert', 'certificate', certStatus, certBody, 'scan-step-cert'),
    step(2, 'domains', 'globe', domainsStatus, h('div', { class: 'stack-sm' }, domainsField.el, domainsHint, zoneHost), 'scan-step-domains'),
    step(3, 'inventory', 'server', invStatus, invBody, 'scan-step-inventory'),
    step(4, 'options', 'sliders', null, h('div', { class: 'scan-options' },
      sourcesGroup.el,
      h('div', { class: 'stack' }, bfGroup.el, planLine, vocabLine,
        h('div', { class: 'scan-perm-row' }, permBox.el, budgetSelect.el),
        h('div', { class: 'stack-sm' }, expiredBox.el, hintsBox.el)),
      h('div', { class: 'stack-sm' }, extraField.el, dohLine)), 'scan-step-options'));

  const runbar = h('div', { class: 'scan-runbar card' },
    h('div', { class: 'scan-runbar-buttons' }, runBtn, cancelBtn),
    h('div', { class: 'scan-runbar-info' }, runSummary, linkPrompt, runError));
  cancelBtn.hidden = true;

  const resultsHost = h('div', { class: 'scan-results-host' });
  container.append(h('div', { class: 'scan-view stack-lg' }, setup, runbar, resultsHost));

  renderCertStep();
  autoFillDomains();
  renderDomainsHint();
  renderInventoryStep();
  renderDoh();
  renderRunSummary();

  /* --- state subscriptions ---------------------------------------------------- */
  cleanups.push(state.subscribe(({ key, value }) => {
    if (key === 'inventory') renderInventoryStep();
    if (key === 'settings') {
      renderDoh();
      renderBfOptions(); // a concurrency change moves the per-domain time estimate
      renderVocab();
    }
    if (key === 'cleared') renderVocab();
    // A zone imported, replaced or forgotten (Zone File view / "Delete all local data").
    if ((key === 'session' && value && value.name === 'zone') || key === 'cleared') renderZoneChip();
    if (key === 'session' && value && value.name === CURRENT_CERT) {
      const next = normalizeCertLoad(value.value);
      if (next !== certLoad) {
        certLoad = next;
        autoFillDomains();
        renderCertStep();
        renderDomainsHint();
        renderRunSummary();
      }
    }
  }));

  /* --- run control -------------------------------------------------------------- */
  let ui = null;

  function validate() {
    clear(runError);
    domainsField.setError(null);
    extraField.setError(null);
    const parsed = parseDomainsInput(domainsField.value);
    let ok = true;
    if (parsed.invalid.length) {
      domainsField.setError(t('scan.domains.invalid', { list: parsed.invalid.slice(0, 5).join(', ') }));
      ok = false;
    } else if (parsed.publicSuffixes.length) {
      domainsField.setError(t('scan.domains.publicSuffix', { list: parsed.publicSuffixes.join(', ') }));
      ok = false;
    }
    const extras = parseHostList(extraField.value, { allowWildcard: true });
    if (extras.invalid.length) {
      extraField.setError(t('scan.domains.invalid', { list: extras.invalid.slice(0, 5).join(', ') }));
      ok = false;
    }
    const leaf = certLeaf();
    const certNames = leaf ? leaf.hostnames.length : 0;
    if (ok && !parsed.domains.length && !certNames && !extras.valid.length) {
      domainsField.setError(t('scan.domains.required'));
      ok = false;
    }
    if (!ok) {
      domainsField.input.focus();
      return null;
    }
    return { domains: parsed.domains, extraNames: extras.valid, cert: leaf };
  }

  let starting = false;
  async function start() {
    // `starting` covers the await below, so a double click cannot start two scans.
    if (starting || (session.run && session.run.status === 'running')) return;
    const v = validate();
    if (!v) return;
    let dns;
    starting = true;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      clear(runError);
      runError.append(ErrorBanner(err, { title: t('scan.run.failed'), compact: true }));
      return;
    } finally {
      starting = false;
    }
    if (ctx.signal.aborted) return;
    const shownDomains = v.domains.length ? v.domains : baseDomainsFromNames([...(v.cert ? v.cert.hostnames : []), ...v.extraNames]);
    const permutationBudget = options.permutations ? options.permutationBudget : 0;
    // The per-browser vocabulary shared with Subdomains › Advanced: languages, this tab's custom
    // wordlist and (when switched on there) the learned labels of earlier scans.
    const vocab = sharedVocabulary();
    const wlConfig = wordlistScanConfig(
      { bruteforce: options.bruteforce, locales: vocab.locales, learned: vocab.learnedOn },
      { custom: vocab.custom, learned: vocab.learned }
    );
    // Zone File hand-off (one run only, never saved to the stored options).
    const zone = activeZone();
    const zoneMode = zone ? (zoneModes.get(zone) || 'discover') : 'off';
    const zoneCfg = zoneScanOverrides(zone, zoneMode);
    const exact = zoneCfg.exact === true;
    const run = createRun({
      domains: shownDomains,
      sources: exact ? [] : [...options.sources],
      bruteforce: exact ? 'off' : options.bruteforce,
      permutationBudget: exact ? 0 : permutationBudget,
      zoneMode: zoneCfg.zone ? zoneMode : null,
      includeExpired: options.includeExpired,
      originHints: options.originHints,
      // The finished scan records its labels into the learned store only when that switch is on.
      learned: vocab.learnedOn,
      cert: v.cert,
      certName: certLoad ? certLoad.name : '',
      inventoryServers: state.inventory.servers.length
    });
    // The DohClient counts queries for its whole life; remember where this run started.
    run.queriesAtStart = typeof dns.stats === 'function' ? dns.stats().queries : null;
    if (session.run) cancelVerify(session.run);
    session.scanTab = null;
    session.run = run;
    hideLinkPrompt();
    ctx.setParams(v.domains.length ? { domain: v.domains.join(',') } : {});
    attach(run);
    startRun(run, {
      domains: v.domains,
      cert: v.cert,
      extraNames: v.extraNames,
      sources: [...options.sources],
      includeExpired: options.includeExpired,
      // Level + locales / custom / learned (lib/wordlist assembles the per-apex list from them).
      ...wlConfig,
      permutationBudget,
      recursive: options.permutations,
      inventory: state.inventory.servers,
      originHints: options.originHints,
      resolverLeak: options.originHints,
      // The Settings parallelism caps the scan: `concurrency` is the requested pool, and
      // `maxConcurrency` the hard ceiling derived from the same Settings value (never above 24).
      concurrency: scanConcurrency(state.settings.concurrency),
      maxConcurrency: scanConcurrency(state.settings.concurrency),
      dns,
      ...zoneCfg
    }, state);
    resultsHost.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }

  function cancel() {
    if (session.run && session.run.status === 'running') session.run.controller.abort();
  }

  function attach(run) {
    if (ui) ui.dispose();
    clear(resultsHost);
    ui = buildRunUI(run, ctx, { onFinish: () => setRunning(false) });
    resultsHost.append(ui.el);
    setRunning(run.status === 'running');
  }

  if (session.run) attach(session.run);

  // A link with `&run=1` pre-fills the form and asks for one click: a link alone never starts
  // the scan's DNS queries and third-party source calls.
  const linkDomains = parseDomainsInput(domainsField.value).domains;
  if (linkAction(ctx.params, linkDomains, session.run) === 'prompt') showLinkPrompt(linkDomains);

  active = {
    // A finished scan grew the learned store (startRun): refresh the vocabulary line + plan live.
    refreshVocab() {
      renderVocab();
    },
    applyParams(p, sp) {
      const list = routeDomains(sp, p);
      if (list.length) {
        session.domainsText = list.join('\n');
        session.domainsFromCert = false;
        domainsField.value = session.domainsText;
        domainsField.setError(null);
        renderDomainsHint();
        renderRunSummary();
      }
      const domains = parseDomainsInput(domainsField.value).domains;
      if (linkAction(p, domains, session.run) === 'prompt') showLinkPrompt(domains);
      else hideLinkPrompt();
    }
  };

  return () => {
    cleanups.forEach((fn) => fn());
    if (ui) ui.dispose();
    ui = null;
    active = null;
  };
}

/**
 * Take new route params without re-mounting (e.g. `#/scan?domain=x` typed into the URL bar).
 * @param {Record<string, string>} params
 * @param {import('../app.js').ViewContext} ctx
 * @returns {boolean}
 */
export function update(params, ctx) {
  if (!active) return false;
  active.applyParams(params, new URLSearchParams(params), ctx);
  return true;
}

/** Nothing else to clean up (mount returns its own cleanup; a running scan continues). */
export function unmount() {}

export default { id, titleKey, icon, mount, unmount, update };

/* ------------------------------------------------------------------------ */
/* Run UI: progress + results                                               */
/* ------------------------------------------------------------------------ */

/**
 * Build the progress panel and the results for one run, replay what the run already has
 * and follow it live. Returns `{ el, dispose }`.
 */
function buildRunUI(run, ctx, { onFinish }) {
  const { state } = ctx;
  const cert = run.config.cert;
  const domainsLabel = run.config.domains.join(', ') || '—';
  // Behind-CDN origin-panel state: the exclude tokens and an on-demand network-owner cache.
  const cdnExclude = { raw: '', tokens: [] };
  const cdnOwnerCache = new Map();
  const cdnOwnerCtl = new AbortController();

  /* --- progress panel --------------------------------------------------------- */
  const title = h('h2', { class: 'scan-run-title' });
  const meta = h('div', { class: 'scan-run-meta text-sm' });
  const stageList = h('ol', { class: 'scan-stages', attrs: { 'aria-label': t('progress.label') } });
  const stageEls = {};
  for (const s of SCAN_STAGES) {
    const el = h('li', { class: 'scan-stage', dataset: { stage: s, state: 'pending' } },
      h('span', { class: 'scan-stage-dot', attrs: { 'aria-hidden': 'true' } }),
      h('span', { class: 'scan-stage-label' }, t(`scan.stage.${s}`)),
      h('span', { class: 'scan-stage-note' }));
    stageEls[s] = el;
    stageList.append(el);
  }
  const progress = ProgressBar({ label: t('scan.progress.starting'), indeterminate: true });
  const chips = h('div', { class: 'scan-chips', attrs: { 'aria-label': t('scan.tab.sources') } });
  const chipEls = new Map();
  // "crt.sh still fetching (up to 12 s)" while the DNS sweep already runs (honest stage reporting).
  const sourceWaitNote = h('div', { class: 'scan-src-wait', attrs: { 'aria-live': 'polite' }, hidden: true });
  const runNotice = h('div', { class: 'scan-run-notice' });
  // The ProgressBar has its own throttled live region; the panel itself is not live (too chatty).
  // How this run used an imported zone file (exact: its names only; discover: added as seeds).
  const zoneBanner = run.config.zoneMode === 'exact' || run.config.zoneMode === 'discover'
    ? Alert({ variant: 'info', compact: true, icon: 'file-text', message: t(`sub.zone.${run.config.zoneMode}`) })
    : null;
  if (zoneBanner) {
    zoneBanner.classList.add('sub-zone-banner');
    zoneBanner.dataset.zoneMode = run.config.zoneMode;
  }
  const panel = h('section', { class: 'scan-run card', dataset: { status: run.status }, attrs: { 'aria-label': t('progress.label') } },
    h('div', { class: 'scan-run-head' }, h('div', { class: 'scan-run-titles' }, title, meta)),
    zoneBanner, stageList, progress, sourceWaitNote, chips, runNotice);

  const SOURCE_GRACE_SECONDS = 12;
  function renderSourceWait() {
    clear(sourceWaitNote);
    const waiting = run.status === 'running' && run.sourceWait && Array.isArray(run.sourceWait.sources)
      ? run.sourceWait.sources.filter((sid) => sourceChipState(run.sourceResults, sid, Math.max(1, run.sourcePlan.domains.length || run.config.domains.length)).state === 'pending')
      : [];
    sourceWaitNote.hidden = !waiting.length;
    if (!waiting.length) return;
    const list = waiting.map((sid) => SOURCE_NAMES[sid] || sid).join(', ');
    sourceWaitNote.append(Icon('clock', { size: 14 }), h('span', null, t('sub.srcWait', { list, seconds: SOURCE_GRACE_SECONDS, count: waiting.length })));
  }

  function renderTitle() {
    title.textContent = run.status === 'running' ? t('scan.run.title', { domains: domainsLabel }) : t('scan.run.titleDone', { domains: domainsLabel });
    panel.dataset.status = run.status;
  }

  function renderMeta() {
    const end = run.finishedAt || new Date();
    const elapsed = formatDuration(end - run.startedAt);
    if (run.status === 'running') meta.textContent = t('scan.run.elapsed', { time: elapsed });
    else if (run.status === 'done') {
      const total = run.result && run.result.stats ? run.result.stats.dnsQueries : null;
      const q = Number.isFinite(total) && Number.isFinite(run.queriesAtStart) ? total - run.queriesAtStart : total;
      meta.textContent = `${Number.isFinite(q) ? t('scan.run.finished', { time: elapsed, queries: formatNumber(q) }) : elapsed} · ${t('scan.run.finishedAt', { when: formatDateTime(end) })}`;
    } else if (run.status === 'cancelled') meta.textContent = t('scan.run.cancelledShort');
    else meta.textContent = '';
  }

  /** Stage → new names it found (known once the scan is done). */
  const FOUND_BY_STAGE = { mining: (c) => c.mine, bruteforce: (c) => c.wordlist, permutations: (c) => c.permutation + c.recursive };
  function renderStages() {
    const tech = run.result ? techniqueCounts(run.result.hosts) : null;
    // Mining may run next to the sources: only the first running stage is the "current step".
    const current = SCAN_STAGES.find((s) => run.stages[s].state === 'active');
    for (const s of SCAN_STAGES) {
      const st = run.stages[s];
      const el = stageEls[s];
      el.dataset.state = st.state;
      el.classList.toggle('is-active', st.state === 'active');
      const note = el.querySelector('.scan-stage-note');
      // bruteforce: the stage info carries the total; permutations: learned from its progress.
      const total = Number(st.info && st.info.total) || Number(st.candidates) || 0;
      let text = '';
      if (st.state === 'skipped') text = t('scan.stage.skipped');
      else if (st.state === 'active' && (s === 'bruteforce' || s === 'permutations') && total > 0) {
        // Candidate count + a live "hits" count (names resolved so far, streamed via onFound).
        const hits = liveHosts(run).length;
        text = t('scan.stage.candidates', { count: total }) + (hits > 0 ? ` ${t('sub.stage.liveHits', { count: hits })}` : '');
      } else if (tech && st.state === 'done' && FOUND_BY_STAGE[s]) text = t('scan.stage.found', { count: formatNumber(FOUND_BY_STAGE[s](tech)) });
      note.textContent = text;
      if (s === current) el.setAttribute('aria-current', 'step');
      else el.removeAttribute('aria-current');
    }
  }

  const renderProgress = frameThrottle(() => {
    const p = run.progress;
    if (run.status !== 'running') return;
    if (!p.stage) {
      progress.setIndeterminate(true);
      return;
    }
    progress.setLabel(t(`scan.progress.${p.stage}`));
    if (p.total > 0) progress.set(p.done, p.total);
    else progress.setIndeterminate(true);
  });

  function chipFor(sourceId) {
    let el = chipEls.get(sourceId);
    if (!el) {
      el = h('span', { class: 'scan-chip', dataset: { source: sourceId, state: 'pending' } });
      chipEls.set(sourceId, el);
      chips.append(el);
    }
    return el;
  }

  function renderChips() {
    const plan = run.sourcePlan;
    const ids = plan.sources.length ? plan.sources : run.config.sources;
    const expected = Math.max(1, plan.domains.length);
    chips.hidden = ids.length === 0;
    const health = new Map(sourceHealthSummary(run.sourceResults).map((x) => [x.source, x]));
    for (const sid of ids) {
      const s = sourceChipState(run.sourceResults, sid, expected);
      // A finished (cancelled / failed) run has no pending sources left: nothing will arrive.
      if (run.status !== 'running' && s.state === 'pending') s.state = run.sourceResults.some((r) => r.source === sid) ? 'partial' : 'cancelled';
      const el = chipFor(sid);
      clear(el);
      const hl = health.get(sid);
      let state = s.state;
      let value;
      let tip = s.error || '';
      if (s.state === 'pending') value = s.done ? `${s.done}/${s.expected}` : t('scan.chip.waiting');
      else if (s.state === 'cancelled') value = t('scan.chip.error.abort');
      else if (hl && !(s.state === 'error' && s.errorKind === 'abort')) {
        // Every domain answered: the clear, localized health text (quota used up, down + CT fallback …).
        const text = sourceHealthText(hl);
        value = text.short;
        tip = text.detail;
        if (text.tone === 'limited') state = 'limited';
        el.dataset.health = hl.state;
      } else if (s.state === 'error') value = t(`scan.chip.error.${CHIP_ERRORS.includes(s.errorKind) ? s.errorKind : 'unknown'}`);
      else value = `${t('scan.chip.names', { count: s.names })}${s.state === 'partial' ? ` · ${t('scan.chip.partial')}` : ''}`;
      el.dataset.state = state;
      const iconName = { ok: 'check-circle', partial: 'alert', limited: 'clock', error: 'x-circle', cancelled: 'minus-circle' }[state];
      el.append(iconName ? Icon(iconName, { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'scan-chip-name' }, SOURCE_NAMES[sid] || sid),
        h('span', { class: 'scan-chip-value' }, value));
      el.title = tip;
    }
  }

  /* --- results ---------------------------------------------------------------- */
  const statsGrid = h('div', { class: 'stat-grid scan-stats' });
  const summaryHost = h('div', { class: 'stack-sm scan-summary' });
  const exportBar = h('div', { class: 'scan-exports', attrs: { role: 'group', 'aria-label': t('scan.export.label') } });
  const filters = { kind: 'all', covered: false, resolving: false, hideWildcard: false, matched: false };

  const stat = {
    hosts: StatCard({ label: t('scan.stat.hosts'), icon: 'globe', variant: 'accent', onClick: () => applyKind('all'), pressed: true }),
    cloudflare: StatCard({ label: t('scan.stat.cloudflare'), icon: 'cloud', variant: 'cloudflare', onClick: () => applyKind('cloudflare'), pressed: false }),
    cdn: StatCard({ label: t('scan.stat.cdn'), icon: 'zap', variant: 'cdn', onClick: () => applyKind('cdnplatform'), pressed: false }),
    direct: StatCard({ label: t('scan.stat.direct'), icon: 'server', variant: 'direct', onClick: () => applyKind('direct'), pressed: false }),
    covered: cert ? StatCard({ label: t('scan.stat.covered'), icon: 'shield', variant: 'ok', onClick: () => applyCovered(), pressed: false }) : null,
    servers: StatCard({ label: cert ? t('scan.stat.servers') : t('scan.stat.serversNoCert'), icon: 'server', variant: 'warn', onClick: () => tabs.select('servers', { focus: true }) }),
    unresolved: StatCard({ label: t('scan.stat.unresolved'), icon: 'x-circle', variant: 'nxdomain', onClick: () => applyKind('unresolved'), pressed: false })
  };
  Object.entries(stat).forEach(([k, s]) => {
    if (!s) return;
    s.el.dataset.stat = k;
    if (k !== 'servers') s.el.title = t('scan.stat.filterHint');
    statsGrid.append(s.el);
  });

  const statKinds = { hosts: 'all', cloudflare: 'cloudflare', cdn: 'cdnplatform', direct: 'direct', unresolved: 'unresolved' };
  function syncStatPressed() {
    for (const [k, kind] of Object.entries(statKinds)) stat[k].set({ pressed: filters.kind === kind && !(k === 'hosts' && filters.covered) });
    if (stat.covered) stat.covered.set({ pressed: filters.covered });
  }

  const renderStats = timeThrottle(() => {
    // Live view includes streamed partials (task: stat cards update during the wordlist stage).
    const live = liveHosts(run);
    const c = run.result ? { ...countHosts(run.result.hosts), ...pickStats(run.result.stats) } : countHosts(live);
    stat.hosts.set({ value: c.total, hint: t('scan.stat.hostsHint', { count: formatNumber(c.resolved) }) });
    stat.cloudflare.set({ value: c.cloudflare, hint: t('scan.stat.cloudflareHint') });
    stat.cdn.set({ value: c.cdn + c.platform, hint: providerHint(run.result ? run.result.hosts : live) || t('scan.stat.cdnHint') });
    stat.direct.set({ value: c.direct + c.private, hint: state.inventory.servers.length || run.config.inventoryServers ? t('scan.stat.directHint', { count: c.onServers }) : null });
    if (stat.covered) stat.covered.set({ value: c.covered, hint: t('scan.stat.coveredHint', { total: formatNumber(c.total) }) });
    if (run.result) {
      const st = run.result.stats;
      const inv = run.config.inventoryServers > 0;
      stat.servers.set({
        value: inv ? (cert ? st.needsCert : st.matchedServers) : '—',
        hint: inv ? t('scan.stat.serversHint', { count: st.hintedServers }) : t('scan.stat.serversNoInv'),
        variant: inv && (cert ? st.needsCert : st.matchedServers) ? 'warn' : 'default'
      });
    } else {
      stat.servers.set({ value: '…', hint: run.status === 'running' ? t('scan.pending') : null, variant: 'default' });
    }
    stat.unresolved.set({ value: c.unresolved + c.nxdomain, hint: t('scan.stat.unresolvedHint', { count: c.dangling }), variant: c.dangling ? 'dangling' : 'nxdomain' });
  }, 150);

  /* Hosts tab */
  const kindSelect = select({
    label: t('scan.filter.kind'),
    size: 'sm',
    className: 'scan-filter-kind',
    value: 'all',
    options: KIND_FILTERS.map((k) => ({ value: k, label: t(`scan.filter.${k}`) })),
    onChange: (v) => applyKind(v, false)
  });
  kindSelect.input.dataset.role = 'scan-filter-kind';
  const mkFilter = (key, labelKey, disabled = false) => {
    const cb = checkbox({
      label: t(labelKey),
      checked: filters[key],
      disabled,
      onChange: (on) => {
        filters[key] = on;
        applyFilters();
      }
    });
    cb.input.dataset.filter = key;
    return cb;
  };
  const fCovered = mkFilter('covered', 'scan.filter.covered', !cert);
  const fResolving = mkFilter('resolving', 'scan.filter.resolving');
  const fWildcard = mkFilter('hideWildcard', 'scan.filter.hideWildcard');
  const fMatched = mkFilter('matched', 'scan.filter.matched', !run.config.inventoryServers);

  const hostsTable = DataTable({
    caption: t('scan.hosts.caption'),
    search: true,
    pageSize: 200,
    sort: { key: 'name', dir: 'asc' },
    empty: t('scan.hosts.empty'),
    rowKey: (host) => host.name,
    rowClass: (host) => ({ 'scan-row-wildcard': host.wildcardSuspect, 'scan-row-dangling': host.classification.dangling }),
    className: 'scan-hosts',
    toolbar: h('div', { class: 'scan-filters' }, kindSelect.el, fCovered.el, fResolving.el, fWildcard.el, fMatched.el),
    details: (host) => hostDetails(host, ctx),
    export: {
      filename: 'hosts',
      subject: run.config.domains[0],
      onExport: (format, rows) => exportHosts(format, rows)
    },
    columns: [
      {
        key: 'name',
        label: t('scan.col.name'),
        sortable: true,
        sortValue: (x) => hostSortKey(x.name),
        searchValue: (x) => [x.name, ...x.resolution.cnames, ...x.origins.map(originLabel), x.classification.provider ? x.classification.provider.name : ''].join(' '),
        render: (x) => h('div', { class: 'scan-host' },
          h('span', { class: 'scan-host-name mono' }, x.name),
          x.origins.includes('cert') ? Badge(t('scan.host.inCert'), { variant: 'accent', title: t('scan.host.inCertTitle'), className: 'scan-mini-badge' }) : null,
          x.wildcardSuspect ? Badge(t('scan.host.wildcard'), { variant: 'warn', title: t('scan.host.wildcardTitle'), className: 'scan-mini-badge' }) : null)
      },
      {
        key: 'kind',
        label: t('scan.col.status'),
        sortable: true,
        sortValue: (x) => kindRank(x),
        searchValue: (x) => `${t(`kind.${x.classification.dangling ? 'dangling' : x.classification.kind}`)} ${x.resolution.status}`,
        render: (x) => h('div', { class: 'cluster scan-kind' }, KindBadge(x.classification),
          // A streamed partial is "resolving…" only while the run lives (a cancelled run never resolves it).
          x._partial && run.status === 'running' ? Badge(t('sub.host.resolving'), { variant: 'neutral', icon: 'clock', title: t('sub.host.resolvingTitle'), className: 'scan-mini-badge' }) : null,
          x.resolution.status !== 'NOERROR' && x.resolution.status !== 'NXDOMAIN'
            ? Badge(x.resolution.status, { variant: 'error', title: x.resolution.error || '', mono: true }) : null)
      },
      {
        key: 'ips',
        label: t('scan.col.ips'),
        sortable: true,
        sortValue: (x) => ipSortValue(x.resolution.ipv4[0] || x.resolution.ipv6[0]),
        searchValue: (x) => [...x.resolution.ipv4, ...x.resolution.ipv6].join(' '),
        render: (x) => {
          const ips = [...x.resolution.ipv4, ...x.resolution.ipv6];
          return ips.length ? TruncatedList(ips, { max: 3 }) : null;
        }
      },
      {
        key: 'cname',
        label: t('scan.col.cname'),
        sortable: true,
        sortValue: (x) => x.resolution.cnames[x.resolution.cnames.length - 1] || '',
        searchValue: (x) => x.resolution.cnames.join(' '),
        render: (x) => (x.resolution.cnames.length ? TruncatedList(x.resolution.cnames, { max: 2 }) : null)
      },
      cert ? {
        key: 'cert',
        label: t('scan.col.cert'),
        sortable: true,
        sortValue: (x) => (x.cert && x.cert.covered ? 1 : 0),
        searchValue: (x) => (x.cert && x.cert.covered ? t('scan.host.covered') : t('scan.host.notCovered')),
        render: (x) => (x.cert && x.cert.covered
          ? Badge(t('scan.host.covered'), { variant: 'ok', icon: 'check', title: t('scan.host.coveredBy', { name: x.cert.by }) })
          : Badge(t('scan.host.notCovered'), { variant: 'neutral', icon: 'x' }))
      } : null,
      {
        key: 'servers',
        label: t('scan.col.servers'),
        sortable: true,
        sortValue: (x) => (x.servers[0] ? x.servers[0].name : ''),
        searchValue: (x) => x.servers.map((s) => `${s.name} ${s.ip}`).join(' '),
        render: (x) => (x.servers.length
          ? TruncatedList(x.servers, { max: 2, mono: false, render: (s) => h('span', { class: 'scan-server-ref', title: s.ip }, Icon('server', { size: 12 }), ' ', s.name) })
          : null)
      },
      {
        key: 'origins',
        label: t('scan.col.origins'),
        sortable: true,
        sortValue: (x) => x.origins.length,
        defaultDir: 'desc',
        searchable: false,
        render: (x) => h('div', { class: 'scan-origins' }, x.origins.map((o) => h('span', { class: 'scan-origin', dataset: { origin: o } }, originLabel(o))))
      }
    ].filter(Boolean)
  });
  hostsTable.setLoading(run.status === 'running');

  function applyFilters() {
    hostsTable.setFilter(hostFilter(filters));
    syncStatPressed();
  }
  function applyKind(kind, selectTab = true) {
    filters.kind = kind;
    kindSelect.value = kind;
    if (kind === 'all') {
      filters.covered = false;
      fCovered.checked = false;
    }
    applyFilters();
    if (selectTab) tabs.select('hosts');
  }
  function applyCovered() {
    filters.covered = !filters.covered;
    fCovered.checked = filters.covered;
    applyFilters();
    tabs.select('hosts');
  }

  const hostsPanel = h('div', { class: 'stack scan-tab-hosts' }, hostsTable.el);
  const serversPanel = h('div', { class: 'stack scan-tab-servers' });
  const cdnPanel = h('div', { class: 'stack scan-tab-cdn' });
  const sourcesPanel = h('div', { class: 'stack scan-tab-sources' });
  const ctPanel = h('div', { class: 'stack scan-tab-ct' });
  // Verify (only with a certificate): checks from the internet which certificate each server serves.
  const verifyPanel = cert ? h('div', { class: 'stack scan-tab-verify' }) : null;
  let verifyUi = null;

  const tabs = Tabs([
    { id: 'hosts', label: t('scan.tab.hosts'), icon: 'list', content: hostsPanel },
    { id: 'servers', label: t('scan.tab.servers'), icon: 'server', content: serversPanel },
    { id: 'cdn', label: t('scan.tab.cdn'), icon: 'cloud', content: cdnPanel },
    cert ? { id: 'verify', label: t('vfy.tab'), icon: 'check-circle', content: verifyPanel } : null,
    { id: 'sources', label: t('scan.tab.sources'), icon: 'database', content: sourcesPanel },
    { id: 'ct', label: t('scan.tab.ct'), icon: 'certificate', content: ctPanel }
  ].filter(Boolean), {
    label: t('scan.results'), className: 'scan-tabs', selected: session.scanTab,
    onChange: (tabId) => {
      session.scanTab = tabId;
    }
  });

  /* Sources tab (live) */
  const sourcesTable = DataTable({
    caption: t('scan.tab.sources'),
    rows: [],
    dense: true,
    empty: t('scan.src.empty'),
    rowKey: (r) => `${r.source}|${r.domain}`,
    className: 'scan-sources-table',
    columns: [
      {
        key: 'source', label: t('scan.src.col.source'), sortable: true,
        sortValue: (r) => SOURCE_NAMES[r.source] || r.source,
        render: (r) => {
          const def = SOURCES.find((s) => s.id === r.source);
          return def ? ExternalLink(def.homepage, def.name) : r.source;
        }
      },
      { key: 'domain', label: t('scan.src.col.domain'), sortable: true, mono: true },
      {
        key: 'status', label: t('scan.src.col.status'), sortable: true,
        sortValue: (r) => (r.ok ? (r.partial ? 1 : 0) : 2),
        exportValue: (r) => (r.ok ? (r.partial ? 'partial' : 'ok') : `failed:${r.errorKind}`),
        render: (r) => {
          let b;
          if (r.ok) b = r.partial ? Badge(t('scan.src.partial'), { variant: 'warn', icon: 'alert' }) : Badge(t('scan.src.ok'), { variant: 'ok', icon: 'check' });
          else if (r.errorKind === 'rate-limit') b = Badge(t('source.state.rate-limited'), { variant: 'warn', icon: 'clock' });
          else if (r.errorKind === 'unavailable') b = Badge(t('source.state.unavailable'), { variant: 'error', icon: 'x-circle' });
          else if (r.errorKind === 'timeout') b = Badge(t('source.state.timeout'), { variant: 'error', icon: 'clock' });
          else b = Badge(t('scan.src.failed'), { variant: 'error', icon: 'x-circle' });
          b.dataset.status = r.ok ? (r.partial ? 'partial' : 'ok') : 'failed';
          return b;
        }
      },
      { key: 'names', label: t('scan.src.col.names'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.names.length, render: (r) => formatNumber(r.names.length) },
      { key: 'ips', label: t('scan.src.col.ips'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.ipHints.length, render: (r) => formatNumber(r.ipHints.length) },
      { key: 'certs', label: t('scan.src.col.certs'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.certs.length, render: (r) => formatNumber(r.certs.length) },
      { key: 'time', label: t('scan.src.col.time'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.elapsedMs, render: (r) => formatDuration(r.elapsedMs) },
      {
        key: 'error', label: t('scan.src.col.error'), wrap: true,
        sortValue: (r) => r.error || '',
        render: (r) => (r.error ? h('div', { class: 'stack-sm scan-src-error' },
          // A used-up quota says when it resets ("… resets within 24 hours") instead of a generic error.
          h('span', null, r.errorKind === 'rate-limit' && r.quota && r.quota.hintKey
            ? t(r.quota.hintKey)
            : t(`error.kind.${CHIP_ERRORS.includes(r.errorKind) || r.errorKind === 'unavailable' ? r.errorKind : 'unknown'}`)),
          h('code', { class: 'mono text-xs muted' }, r.error)) : null)
      }
    ]
  });
  const sourcesNote = h('p', { class: 'muted text-sm' }, t('scan.src.retryHint'));
  const wildcardNote = h('div');
  /** One clear line per source that did not simply work (quota, down + CT fallback, page limit). */
  const healthNote = h('div', { class: 'scan-src-health' });
  function renderSourceHealth() {
    clear(healthNote);
    const lines = sourceHealthSummary(run.sourceResults)
      .filter((hl) => hl.errorKind !== 'abort' && !(hl.state === 'empty' || (hl.state === 'ok' && !(hl.truncated && hl.available > hl.names))))
      .map((hl) => {
        const text = sourceHealthText(hl);
        return h('li', { class: 'scan-src-health-line', dataset: { source: hl.source, tone: text.tone, health: hl.state } },
          Icon({ ok: 'info', warn: 'alert', limited: 'clock', error: 'x-circle' }[text.tone] || 'info', { size: 14 }), h('span', null, text.detail));
      });
    if (lines.length) healthNote.append(h('div', { class: 'scan-src-health-title' }, t('scan.src.healthTitle')), h('ul', { class: 'scan-src-health-list' }, lines));
  }
  sourcesPanel.append(healthNote,
    run.config.sources.length ? sourcesTable.el : EmptyState({ compact: true, icon: 'database', message: t('scan.src.none') }),
    sourcesNote, wildcardNote);

  const pendingState = () => EmptyState({ compact: true, icon: 'clock', message: t('scan.pending') });
  const unavailableState = () => EmptyState({ compact: true, icon: 'minus-circle', message: t('scan.notAvailable') });
  for (const p of [serversPanel, cdnPanel, ctPanel, verifyPanel]) if (p) p.append(pendingState());

  const results = h('section', { class: 'scan-results stack', attrs: { 'aria-labelledby': `scan-results-${run.id}` } },
    h('div', { class: 'scan-results-head' },
      h('h2', { class: 'scan-results-title', id: `scan-results-${run.id}` }, t('scan.results')),
      exportBar),
    statsGrid,
    summaryHost,
    tabs);

  const el = h('div', { class: 'stack-lg scan-run-ui', dataset: { run: run.id } }, panel, results);

  /* --- exports ------------------------------------------------------------------ */
  const subject = run.config.domains[0] || '';
  const saveFile = (base, ext, text, mime) => {
    const file = downloadText(timestampedName(base, ext, subject), text, mime);
    toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
    return file;
  };
  const exportScan = () => ({ hosts: run.result ? run.result.hosts : run.hosts });
  function exportHosts(format, rows) {
    const list = rows || exportScan().hosts;
    if (format === 'json') saveFile('hosts', 'json', `${toJson(list)}\n`, 'application/json;charset=utf-8');
    else saveFile('hosts', 'csv', toCsv(scanHostRows({ hosts: list }), HOST_COLUMNS), 'text/csv;charset=utf-8');
  }
  const exportButtons = {
    hosts: Button({ label: t('scan.export.hosts'), icon: 'download', size: 'sm', dataset: { export: 'hosts-csv' }, onClick: () => exportHosts('csv') }),
    servers: Button({
      label: t('scan.export.servers'), icon: 'download', size: 'sm', dataset: { export: 'servers-csv' },
      onClick: () => saveFile('servers', 'csv', toCsv(scanServerRows(run.result), SERVER_COLUMNS), 'text/csv;charset=utf-8')
    }),
    json: Button({
      label: t('scan.export.json'), icon: 'download', size: 'sm', dataset: { export: 'json' },
      onClick: () => saveFile('scan', 'json', `${toJson(fullJson())}\n`, 'application/json;charset=utf-8')
    }),
    names: Button({
      label: t('scan.export.names'), icon: 'file-text', size: 'sm', dataset: { export: 'names' },
      onClick: () => downloadNames()
    }),
    targets: Button({
      label: t('scan.export.targets'), icon: 'file-text', size: 'sm', dataset: { export: 'targets' },
      onClick: () => downloadTargets()
    })
  };
  exportBar.append(...Object.values(exportButtons));

  function fullJson() {
    return {
      generator: 'DomainScope',
      version: ctx.version,
      exportedAt: new Date(),
      certificate: cert ? {
        subject: cert.subjectDN,
        issuer: cert.issuerDN,
        serialHex: cert.serialHex,
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        hostnames: cert.hostnames
      } : null,
      scan: run.result,
      verification: verifyExport(run, ctx.version)
    };
  }

  let onlyCovered = !!cert;
  const namesText = () => namesForCli(run.result || { hosts: run.hosts }, { onlyCovered });
  const targetsText = () => targetsForCli([
    ...state.inventory.servers,
    ...(run.result ? run.result.originHints : []),
    ...(run.result ? run.result.unmatchedIps : [])
  ]);
  const lineCount = (text) => (text ? text.split('\n').filter(Boolean).length : 0);
  function downloadNames() {
    const file = downloadText('names.txt', namesText(), 'text/plain;charset=utf-8');
    toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
  }
  function downloadTargets() {
    const file = downloadText('targets.txt', targetsText(), 'text/plain;charset=utf-8');
    toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
  }

  function syncExports() {
    const done = !!run.result;
    const anyHosts = run.hosts.length > 0 || (run.result && run.result.hosts.length > 0);
    exportButtons.hosts.disabled = !anyHosts;
    exportButtons.names.disabled = !anyHosts;
    exportButtons.servers.disabled = !done;
    exportButtons.json.disabled = !done;
    exportButtons.targets.disabled = !done;
  }

  /* --- finish: servers / CDN / CT tabs ---------------------------------------------- */
  function renderSummary() {
    clear(summaryHost);
    const r = run.result;
    if (!r) return;
    const st = r.stats;
    const inv = run.config.inventoryServers > 0;
    const add = (variant, message, iconName = null, key = '') => {
      const a = Alert({ variant, compact: true, message, icon: iconName || undefined });
      a.dataset.summary = key;
      summaryHost.append(a);
    };
    if (inv) {
      if (cert) {
        if (st.needsCert) add('warn', t('scan.sum.needs', { count: st.needsCert }), 'server', 'needs');
        else add('ok', t('scan.sum.needsNone'), 'check-circle', 'needs-none');
      } else if (st.matchedServers) {
        add('info', t('scan.sum.matched', { count: st.matchedServers }), 'server', 'matched');
      }
    } else {
      add('info', t('scan.sum.noInventory'), 'server', 'no-inventory');
    }
    // Pairs to check exist for needs-cert servers and for public IPs outside the inventory.
    if (cert && (st.needsCert || r.unmatchedIps.some((u) => !u.private))) add('info', t('scan.sum.verify'), 'check-circle', 'verify');
    if (st.hiddenOrigin) add('info', t('scan.sum.hidden', { count: st.hiddenOrigin }), 'cloud', 'hidden');
    const nets = (r.originNetworks || []).map((n) => n.cidr);
    if (st.hiddenOrigin && nets.length) {
      add('info', t('scan.sum.networks', { count: nets.length, list: nets.slice(0, 3).join(', ') + (nets.length > 3 ? '…' : '') }), 'network', 'networks');
    }
    const tech = techniqueCounts(r.hosts);
    // A zone-file run names where its hosts came from too (an exact run finds none by DNS or sources).
    if (tech.total) {
      const found = { dns: formatNumber(tech.dns), sources: formatNumber(tech.sources), zone: formatNumber(tech.zone || 0) };
      add('info', t(tech.zone ? 'scan.sum.discoveryZone' : 'scan.sum.discovery', found), 'search', 'discovery');
    }
    if (inv && st.unmatchedIps) add('info', t('scan.sum.unmatched', { count: st.unmatchedIps }), 'help', 'unmatched');
    if (st.dangling) add('error', t('scan.sum.dangling', { count: st.dangling }), 'unlink', 'dangling');
    const wild = Object.entries(r.wildcards || {}).filter(([, w]) => w && w.wildcard).map(([d]) => `*.${d}`);
    if (wild.length) add('info', t('scan.sum.wildcard', { list: wild.join(', ') }), 'layers', 'wildcard');
    const failedSources = sourceHealthSummary(r.sources || run.sourceResults).filter((x) => !x.ok && x.errorKind !== 'abort').length;
    if (failedSources) add('warn', t('scan.sum.sourcesFailed', { count: failedSources }), 'alert', 'sources-failed');
    // A code without a sentence (a newer scanner) still reads as `CODE: detail`, never as a raw key.
    for (const w of r.warnings || []) add('warn', WARNING_CODES.includes(w.code) ? t(`scan.warn.${w.code}`, { detail: w.detail }) : `${w.code}: ${w.detail}`, 'alert', w.code);
  }

  function renderServersTab() {
    clear(serversPanel);
    const r = run.result;
    if (!r) {
      serversPanel.append(run.status === 'running' ? pendingState() : unavailableState());
      return;
    }
    const inv = run.config.inventoryServers > 0;
    serversPanel.append(h('p', { class: 'muted text-sm' }, t('scan.srv.intro')));
    if (cert && (r.servers.length || r.unmatchedIps.length)) {
      serversPanel.append(h('div', { class: 'cluster vfy-hint' },
        h('span', { class: 'muted text-sm' }, t('scan.srv.verifyHint')),
        Button({ size: 'sm', variant: 'ghost', icon: 'check-circle', label: t('vfy.tab'), dataset: { action: 'scan-open-verify' }, onClick: () => tabs.select('verify', { focus: true }) })));
    }
    if (!inv) {
      serversPanel.append(Alert({
        variant: 'info', compact: true, icon: 'server', message: t('scan.srv.noInventory'),
        actions: [h('a', { class: 'btn btn-secondary btn-sm', href: ctx.href('inventory') }, Icon('plus', { size: 14 }), h('span', { class: 'btn-label' }, t('scan.inv.add')))]
      }));
    } else {
      const statusOf = (g) => {
        if (g.needsCert) return cert ? 'needs' : 'serves';
        if (g.maybeNeedsCert) return 'maybe';
        return 'none';
      };
      serversPanel.append(DataTable({
        caption: t('scan.tab.servers'),
        rows: r.servers,
        search: r.servers.length > 8,
        empty: t('scan.srv.empty'),
        rowKey: (g) => String(g.server.id),
        rowClass: (g) => ({ 'scan-row-needs': g.needsCert }),
        className: 'scan-servers-table',
        details: (g) => serverDetails(g),
        export: {
          filename: 'servers',
          subject,
          onExport: (format, rows) => {
            const scanLike = { servers: rows, unmatchedIps: [], hosts: r.hosts };
            if (format === 'json') saveFile('servers', 'json', `${toJson(rows)}\n`, 'application/json;charset=utf-8');
            else saveFile('servers', 'csv', toCsv(scanServerRows(scanLike), SERVER_COLUMNS), 'text/csv;charset=utf-8');
          }
        },
        columns: [
          {
            key: 'server', label: t('scan.srv.col.server'), sortable: true,
            sortValue: (g) => g.server.name,
            searchValue: (g) => [g.server.name, ...(g.server.groups || [])].join(' '),
            render: (g) => h('div', { class: 'scan-srv' },
              h('span', { class: 'scan-srv-name' }, g.server.name),
              g.server.groups && g.server.groups.length ? h('span', { class: 'cluster scan-srv-groups' }, g.server.groups.map((x) => Badge(x))) : null)
          },
          {
            key: 'status', label: t('scan.srv.col.status'), sortable: true,
            sortValue: (g) => ({ needs: 0, serves: 0, maybe: 1, none: 2 })[statusOf(g)],
            searchValue: (g) => t(`scan.srv.${statusOf(g)}`),
            exportValue: (g) => statusOf(g),
            render: (g) => {
              const s = statusOf(g);
              const variant = { needs: 'warn', serves: 'info', maybe: 'info', none: 'neutral' }[s];
              const ic = { needs: 'alert', serves: 'server', maybe: 'help', none: 'minus-circle' }[s];
              const b = Badge(t(`scan.srv.${s}`), { variant, icon: ic });
              b.dataset.status = s;
              return b;
            }
          },
          {
            key: 'ips', label: t('scan.srv.col.ips'), sortable: true, mono: true,
            sortValue: (g) => ipSortValue(g.server.ips[0]),
            searchValue: (g) => g.server.ips.join(' '),
            render: (g) => TruncatedList(g.server.ips, { max: 2 })
          },
          {
            key: 'hosts', label: t('scan.srv.col.hosts'),
            searchValue: (g) => g.hosts.map((x) => x.name).join(' '),
            exportValue: (g) => [...new Set(g.hosts.map((x) => x.name))].join(' '),
            render: (g) => TruncatedList([...new Map(g.hosts.map((x) => [x.name, x])).values()], {
              max: 3,
              render: (x) => h('span', { class: ['scan-srv-host', { 'is-hint': x.via === 'hint', 'is-zone': x.via === 'zone' }] }, x.name,
                x.via === 'hint' || x.via === 'zone' ? h('span', { class: 'muted' }, ` · ${t(`scan.srv.via.${x.via}`)}`) : null)
            })
          },
          {
            key: 'count', label: t('scan.srv.col.count'), sortable: true, align: 'end', className: 'num', defaultDir: 'desc',
            sortValue: (g) => new Set(g.hosts.map((x) => x.name)).size,
            render: (g) => formatNumber(new Set(g.hosts.map((x) => x.name)).size)
          }
        ]
      }).el);
    }
    // Direct IPs that are not in the inventory.
    serversPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.srv.unmatchedTitle')),
      h('p', { class: 'muted text-sm' }, t('scan.srv.unmatchedDesc')),
      DataTable({
        caption: t('scan.srv.unmatchedTitle'),
        rows: r.unmatchedIps,
        dense: true,
        empty: t('scan.srv.unmatchedEmpty'),
        rowKey: (u) => u.ip,
        className: 'scan-unmatched-table',
        export: { filename: 'unmatched-ips', subject },
        columns: [
          { key: 'ip', label: t('scan.srv.col.ip'), sortable: true, mono: true, sortValue: (u) => ipSortValue(u.ip) },
          {
            key: 'owner', label: t('scan.srv.col.owner'), sortable: true,
            sortValue: (u) => (u.private ? 0 : 1),
            exportValue: (u) => (u.private ? 'private' : (u.provider ? u.provider.name : 'public')),
            render: (u) => (u.private ? Badge(t('scan.srv.private'), { variant: 'private', icon: 'lock' })
              : u.provider ? Badge(u.provider.name, { variant: 'platform' }) : Badge(t('scan.srv.public'), { variant: 'direct', icon: 'server' }))
          },
          {
            key: 'hosts', label: t('scan.srv.col.hosts'),
            searchValue: (u) => u.hosts.join(' '),
            exportValue: (u) => u.hosts.join(' '),
            render: (u) => TruncatedList(u.hosts, { max: 3 })
          }
        ]
      }).el);
  }

  function serverDetails(g) {
    return DataTable({
      rows: g.hosts,
      dense: true,
      maxHeight: null,
      rowKey: (x) => `${x.name}|${x.ip}|${x.via}`,
      columns: [
        { key: 'name', label: t('scan.srv.col.host'), mono: true },
        { key: 'ip', label: t('scan.srv.col.ip'), mono: true },
        { key: 'via', label: t('scan.srv.col.via'), render: (x) => Badge(t(`scan.srv.via.${x.via}`), { variant: x.via === 'dns' ? 'direct' : x.via === 'zone' ? 'ok' : 'info' }) },
        cert ? {
          key: 'covered', label: t('scan.srv.col.covered'),
          render: (x) => (x.covered ? Badge(t('scan.host.covered'), { variant: 'ok', icon: 'check' }) : Badge(t('scan.host.notCovered'), { variant: 'neutral', icon: 'x' }))
        } : null
      ].filter(Boolean)
    }).el;
  }

  function renderCdnTab() {
    clear(cdnPanel);
    const r = run.result;
    if (!r) {
      cdnPanel.append(run.status === 'running' ? pendingState() : unavailableState());
      return;
    }
    const hidden = r.hosts.filter((x) => x.classification.hidesOrigin);
    // Origin networks without wildcard suspects (and a CLI command the CLI accepts), shared with Subdomains.
    const overview = originOverview(r);
    const { networks: cdnNetworks, dropped: cdnDropped } = realOriginNetworks(r.originNetworks, r.hosts);
    const cdnProxiedNames = overview.proxied.map((p) => p.name);
    const netCidrs = new Set(overview.networks.map((n) => n.cidr));
    const sameNetworks = (x) => (x.candidateNetworks || []).filter((c) => netCidrs.has(c));
    // The AS owner of a network for a table cell: the offline provider at once, else an on-demand
    // RIPEstat lookup (one request per /24 · /48, cached).
    const ownerCell = (net) => {
      const el = h('span', { class: 'scan-net-owner', attrs: { 'aria-live': 'polite' } });
      const fill = (d) => {
        clear(el);
        if (d && !d.error && d.asn) el.append(h('span', { class: ['scan-net-owner-as', { 'is-shared': d.shared }] }, t('sub.org.owner.as', { asn: d.asn, holder: d.holder || d.asName || '' })));
        else el.append(h('span', { class: 'muted' }, t('sub.org.owner.error')));
      };
      if (net.provider) { el.append(h('span', null, net.provider.name)); return el; }
      if (cdnOwnerCache.has(net.cidr)) { fill(cdnOwnerCache.get(net.cidr)); return el; }
      el.append(Button({
        label: t('sub.org.owner.lookup'), icon: 'search', size: 'sm', variant: 'ghost', dataset: { action: 'scan-net-owner', cidr: net.cidr },
        ariaLabel: t('sub.org.owner.lookupFor', { cidr: net.cidr }), title: t('sub.org.owner.lookupFor', { cidr: net.cidr }),
        onClick: async () => {
          clear(el);
          el.append(h('span', { class: 'muted' }, t('sub.org.owner.looking')));
          try {
            const d = await describeNetwork(net.cidr, { signal: cdnOwnerCtl.signal });
            cdnOwnerCache.set(net.cidr, d);
            fill(d);
          } catch (err) {
            if (errorKind(err) === 'abort') return;
            clear(el);
            el.append(h('span', { class: 'muted' }, t('sub.org.owner.error')));
          }
        }
      }));
      return el;
    };
    cdnPanel.append(Alert({
      variant: 'info',
      icon: 'cloud',
      title: t('scan.cdn.whyTitle'),
      children: h('div', { class: 'stack-sm scan-why' }, h('p', null, t('scan.cdn.why1')), h('p', null, t('scan.cdn.why2')))
    }));

    // Exact origins from the imported zone file (Zone File hand-off): authoritative, so first. A
    // zone origin may be a private address: plain text, never an IP Intel link.
    const zoned = overview.proxied.filter((p) => p.zone.length);
    if (zoned.length) {
      cdnPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.cdn.zoneTitle')),
        h('p', { class: 'muted text-sm' }, t('scan.cdn.zoneDesc')),
        DataTable({
          caption: t('scan.cdn.zoneTitle'),
          rows: zoned,
          dense: true,
          rowKey: (p) => p.name,
          sort: { key: 'name', dir: 'asc' },
          className: 'scan-zone-origins',
          columns: [
            { key: 'name', label: t('scan.col.name'), mono: true, sortable: true, sortValue: (p) => hostSortKey(p.name), searchValue: (p) => p.name, render: (p) => p.name },
            {
              key: 'origin', label: t('scan.cdn.col.zoneOrigin'), mono: true,
              searchValue: (p) => p.zone.map((z) => z.ip).join(' '),
              render: (p) => h('div', { class: 'cluster' }, Badge(t('scan.hint.zone'), { variant: 'ok', title: t('scan.hint.zone.title') }),
                TruncatedList(p.zone.map((z) => z.ip), { max: 3, inline: true }))
            }
          ]
        }).el);
    }

    cdnPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.cdn.hostsTitle')), DataTable({
      caption: t('scan.cdn.hostsTitle'),
      rows: hidden,
      dense: true,
      search: hidden.length > 10,
      empty: t('scan.cdn.hostsEmpty'),
      rowKey: (x) => x.name,
      sort: { key: 'name', dir: 'asc' },
      className: 'scan-cdn-hosts',
      export: { filename: 'proxied-hosts', subject },
      columns: [
        { key: 'name', label: t('scan.col.name'), mono: true, sortable: true, sortValue: (x) => hostSortKey(x.name), searchValue: (x) => x.name },
        {
          key: 'provider', label: t('scan.cdn.col.provider'), sortable: true,
          sortValue: (x) => (x.classification.provider ? x.classification.provider.name : ''),
          exportValue: (x) => (x.classification.provider ? x.classification.provider.name : ''),
          render: (x) => KindBadge(x.classification)
        },
        {
          key: 'edge', label: t('scan.cdn.col.edge'), mono: true,
          searchValue: (x) => [...x.resolution.ipv4, ...x.resolution.ipv6].join(' '),
          render: (x) => TruncatedList([...x.resolution.ipv4, ...x.resolution.ipv6], { max: 2 })
        },
        {
          key: 'networks', label: t('scan.cdn.col.networks'), mono: true,
          searchValue: (x) => sameNetworks(x).join(' '),
          exportValue: (x) => sameNetworks(x).join(' '),
          render: (x) => (sameNetworks(x).length ? TruncatedList(sameNetworks(x), { max: 2 }) : null)
        },
        cert ? {
          key: 'cert', label: t('scan.col.cert'), sortable: true,
          sortValue: (x) => (x.cert && x.cert.covered ? 1 : 0),
          exportValue: (x) => !!(x.cert && x.cert.covered),
          render: (x) => (x.cert && x.cert.covered ? Badge(t('scan.host.covered'), { variant: 'ok', icon: 'check' }) : Badge(t('scan.host.notCovered'), { variant: 'neutral', icon: 'x' }))
        } : null
      ].filter(Boolean)
    }).el);

    // Origin networks: the /24 · /48 blocks the non-proxied names live in, plus a ready-to-run
    // CLI sweep of those blocks with the proxied names (no input files needed).
    if (hidden.length) {
      cdnPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.cdn.netTitle')),
        h('p', { class: 'muted text-sm' }, t('scan.cdn.netDesc')));
      // Warn about shared cloud / hosting space before the table (guarded: native append('null')).
      if (overview.shared) cdnPanel.append(Alert({ variant: 'warn', compact: true, icon: 'alert', message: t('sub.org.warnShared') }));
      cdnPanel.append(
        DataTable({
          caption: t('scan.cdn.netTitle'),
          rows: overview.networks,
          dense: true,
          empty: t('scan.cdn.netEmpty'),
          rowKey: (n) => n.cidr,
          className: 'scan-networks-table',
          export: { filename: 'origin-networks', subject },
          columns: [
            { key: 'cidr', label: t('scan.cdn.col.cidr'), mono: true, sortable: true, sortValue: (n) => ipSortValue(n.cidr.split('/')[0]) },
            {
              key: 'hosts', label: t('scan.cdn.col.netHosts'), mono: true, sortable: true,
              sortValue: (n) => n.hosts.length, defaultDir: 'desc',
              searchValue: (n) => n.hosts.join(' '), exportValue: (n) => n.hosts.join(' '),
              render: (n) => TruncatedList(n.hosts, { max: 3 })
            },
            {
              key: 'ips', label: t('scan.cdn.col.netIps'), mono: true,
              searchValue: (n) => n.ips.join(' '), exportValue: (n) => n.ips.join(' '),
              render: (n) => TruncatedList(n.ips, { max: 3 })
            },
            {
              // Whether the command sweeps the whole /24 or only its known addresses, plus a
              // shared-space flag — so the reader knows what the command actually probes and why.
              key: 'sweep', label: t('scan.cdn.col.sweep'),
              exportValue: (n) => (n.sweep === 'cidr' ? 'cidr' : 'ips') + (n.shared ? ' shared' : ''),
              render: (n) => h('div', { class: 'cluster scan-net-sweep', dataset: { sweep: n.sweep, shared: n.shared ? '1' : '0' } },
                h('span', { class: 'scan-net-sweep-label', title: n.sweep === 'cidr' ? t('sub.org.sweep.cidrTitle') : t('sub.org.sweep.ipsTitle') },
                  n.sweep === 'cidr' ? t('sub.org.sweep.cidr') : t('sub.org.sweep.ips', { count: n.ips.length })),
                n.shared ? Badge(t('sub.org.shared'), { variant: 'warn', icon: 'alert', title: t('sub.org.sharedTitle') }) : null)
            },
            {
              key: 'owner', label: t('scan.cdn.col.owner'),
              exportValue: (n) => (n.provider ? n.provider.name : ''),
              render: (n) => ownerCell(n)
            }
          ]
        }).el);
      if (overview.command) {
        // The sweep command in either shell (built by lib/cmdline so every token is quoted), plus
        // an "exclude" box that feeds --exclude (a mail server, a shared address, an octet to skip).
        const quickHost = h('div', { class: 'scan-cli-quick-cmd' });
        const quickReport = h('div', { class: 'scan-cli-exclude-report text-sm', attrs: { 'aria-live': 'polite' } });
        const renderQuick = () => {
          clear(quickHost);
          clear(quickReport);
          const shell = SHELLS.includes(session.cdnShell) ? session.cdnShell : 'posix';
          const sweep = originSweep(r, {
            names: cdnProxiedNames, networks: cdnNetworks, dropped: cdnDropped, shell,
            exclude: cdnExclude.tokens.length ? cdnExclude.tokens : null
          });
          if (sweep.command) quickHost.append(CodeBlock(sweep.command, { label: t('scan.cli.command'), wrap: true }));
          const nf = sweep.command && sweep.namesFile ? { file: sweep.namesFile, text: sweep.namesText, count: sweep.count } : null;
          if (nf) {
            quickHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: nf.file } },
              h('p', { class: 'muted text-sm' }, t('sub.org.namesFile', { file: nf.file, count: formatNumber(nf.count) })),
              Button({
                label: t('sub.org.namesFileDownload', { file: nf.file }), icon: 'download', size: 'sm', dataset: { export: 'names-file' },
                onClick: () => {
                  const file = downloadText(nf.file, nf.text, 'text/plain;charset=utf-8');
                  toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
                }
              })));
          }
          // A target list too long even then: the command reads the targets from a file too.
          if (sweep.command && sweep.targetsFile) {
            quickHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: sweep.targetsFile } },
              h('p', { class: 'muted text-sm' }, t('sub.org.targetsFile', { file: sweep.targetsFile, count: formatNumber(sweep.targetCount) })),
              Button({
                label: t('sub.org.namesFileDownload', { file: sweep.targetsFile }), icon: 'download', size: 'sm', dataset: { export: 'targets-file' },
                onClick: () => {
                  const file = downloadText(sweep.targetsFile, sweep.targetsText, 'text/plain;charset=utf-8');
                  toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
                }
              })));
          }
          const invalid = sweep.excludeDropped || [];
          const unused = sweep.excludeUnused || [];
          const droppedTargets = sweep.droppedTargets || 0;
          const lines = [];
          if (sweep.overLength) lines.push(h('div', { class: 'scan-cli-exclude-invalid', dataset: { role: 'over-length' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.overLength', { count: formatNumber(sweep.command.length) }))));
          if (invalid.length) lines.push(h('div', { class: 'scan-cli-exclude-invalid', dataset: { role: 'exclude-invalid' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.exclude.invalid', { count: invalid.length, list: invalid.slice(0, 5).join(', ') }))));
          if (droppedTargets) lines.push(h('div', { dataset: { role: 'exclude-applied' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.applied', { count: droppedTargets }))));
          if (unused.length) lines.push(h('div', { dataset: { role: 'exclude-unused' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.unused', { count: unused.length, list: unused.slice(0, 5).join(', ') }))));
          quickReport.append(...lines);
        };
        const quickShell = SegmentedControl({
          label: t('scan.cdn.shell'),
          size: 'sm',
          className: 'scan-cli-shell',
          value: SHELLS.includes(session.cdnShell) ? session.cdnShell : 'posix',
          options: SHELLS.map((sh) => ({ value: sh, label: t(`scan.cdn.shell.${sh}`), title: t(`scan.cdn.shellTitle.${sh}`) })),
          onChange: (sh) => {
            session.cdnShell = SHELLS.includes(sh) ? sh : 'posix';
            renderQuick();
          }
        });
        const excludeField = textInput({
          label: t('sub.org.exclude.label'),
          value: cdnExclude.raw,
          placeholder: t('sub.org.exclude.placeholder'),
          hint: t('sub.org.exclude.hint'),
          mono: true,
          className: 'scan-cli-exclude',
          attrs: { 'data-role': 'scan-cdn-exclude', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off' },
          onInput: (value) => {
            cdnExclude.raw = value;
            cdnExclude.tokens = value.split(/[\s,]+/).filter(Boolean);
            renderQuick();
          }
        });
        renderQuick();
        cdnPanel.append(Card({
          title: t('scan.cdn.quickTitle'),
          subtitle: t('scan.cdn.quickDesc'),
          icon: 'terminal',
          className: 'scan-cli-quick',
          children: h('div', { class: 'stack-sm' }, quickShell.el, excludeField.el, quickHost, quickReport)
        }));
      }
    }

    cdnPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.cdn.hintsTitle')),
      h('p', { class: 'muted text-sm' }, t('scan.cdn.hintsDesc')));
    if ((!r.options || r.options.originHints === false) && !(r.originHints || []).length) {
      cdnPanel.append(EmptyState({ compact: true, icon: 'minus-circle', message: t('scan.cdn.hintsOff') }));
    } else {
      cdnPanel.append(DataTable({
        caption: t('scan.cdn.hintsTitle'),
        rows: r.originHints,
        dense: true,
        search: r.originHints.length > 10,
        empty: t('scan.cdn.hintsEmpty'),
        rowKey: (o) => o.ip,
        className: 'scan-hints-table',
        export: { filename: 'origin-hints', subject },
        columns: [
          { key: 'ip', label: t('scan.cdn.col.ip'), mono: true, sortable: true, sortValue: (o) => ipSortValue(o.ip) },
          {
            key: 'reasons', label: t('scan.cdn.col.reasons'), wrap: true,
            searchValue: (o) => o.reasons.map((x) => `${x.kind} ${reasonText(x)}`).join(' '),
            exportValue: (o) => o.reasons.map((x) => `${x.kind}: ${x.detail}`).join(' | '),
            render: (o) => h('div', { class: 'stack-sm scan-hint-reasons' }, o.reasons.slice(0, 4).map((x) => h('div', { class: 'scan-hint-reason' },
              Badge(HINT_KINDS.includes(x.kind) ? t(`scan.hint.${x.kind}`) : x.kind, { variant: 'info', title: HINT_KINDS.includes(x.kind) ? t(`scan.hint.${x.kind}.title`) : null }),
              h('span', { class: 'mono text-xs scan-hint-detail' }, reasonText(x)))),
            o.reasons.length > 4 ? h('span', { class: 'muted text-xs' }, t('common.moreCount', { count: o.reasons.length - 4 })) : null)
          },
          {
            key: 'servers', label: t('scan.cdn.col.servers'), sortable: true,
            sortValue: (o) => (o.servers[0] ? o.servers[0].name : ''),
            searchValue: (o) => o.servers.map((s) => s.name).join(' '),
            exportValue: (o) => o.servers.map((s) => s.name).join(' '),
            render: (o) => (o.servers.length
              ? h('div', { class: 'cluster' }, o.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' })))
              : (o.provider ? Badge(o.provider.name, { variant: 'platform' }) : null))
          },
          {
            key: 'hosts', label: t('scan.cdn.col.hosts'), mono: true,
            searchValue: (o) => (o.hosts || []).join(' '),
            exportValue: (o) => (o.hosts || []).join(' '),
            render: (o) => ((o.hosts || []).length ? TruncatedList(o.hosts, { max: 2 }) : null)
          }
        ]
      }).el);
    }
    cdnPanel.append(cliCard());
  }

  function cliCard() {
    const namesBtn = Button({ icon: 'download', label: 'names.txt', dataset: { action: 'cli-names' }, onClick: () => downloadNames() });
    const targetsBtn = Button({ icon: 'download', label: 'targets.txt', dataset: { action: 'cli-targets' }, onClick: () => downloadTargets() });
    const refreshCounts = () => {
      const names = lineCount(namesText());
      const targets = lineCount(targetsText());
      namesBtn.querySelector('.btn-label').textContent = t('scan.cli.names', { count: names });
      targetsBtn.querySelector('.btn-label').textContent = t('scan.cli.targets', { count: targets });
      namesBtn.dataset.count = String(names);
      targetsBtn.dataset.count = String(targets);
    };
    refreshCounts();
    const covered = cert ? checkbox({
      label: t('scan.cli.onlyCovered'),
      checked: onlyCovered,
      onChange: (on) => {
        onlyCovered = on;
        refreshCounts();
      }
    }) : null;
    const certBtn = cert ? Button({
      icon: 'download', label: t('scan.cli.certFile'), dataset: { action: 'cli-cert' },
      onClick: () => {
        const file = downloadText('new-cert.pem', pemEncode(cert.der), 'application/x-pem-file');
        toast(t('scan.exported', { file }), { type: 'success', timeout: 2500 });
      }
    }) : null;
    const command = cliCommand({ certFile: cert ? 'new-cert.pem' : null });
    const inv = state.inventory.servers.length > 0;
    return Card({
      title: t('scan.cli.title'),
      subtitle: t('scan.cli.desc'),
      icon: 'terminal',
      className: 'scan-cli',
      children: h('ol', { class: 'scan-cli-steps' },
        h('li', null,
          h('div', { class: 'scan-cli-step-title' }, t('scan.cli.step1')),
          h('div', { class: 'cluster' }, namesBtn, targetsBtn, certBtn),
          covered ? covered.el : null,
          h('p', { class: 'muted text-sm' }, inv ? t('scan.cli.targetsNote') : t('scan.cli.noInventoryNote'))),
        h('li', null,
          h('div', { class: 'scan-cli-step-title' }, t('scan.cli.step2')),
          ButtonLink({ href: CLI_PATH, label: t('scan.cli.download'), icon: 'download', download: 'ssl_origin_scan.py' })),
        h('li', null,
          h('div', { class: 'scan-cli-step-title' }, t('scan.cli.step3')),
          CodeBlock(command, { label: t('scan.cli.command'), wrap: true })),
        h('li', null,
          h('div', { class: 'scan-cli-step-title' }, t('scan.cli.step4')),
          h('p', { class: 'text-sm text-2' }, t('scan.cli.result'))))
    });
  }

  function renderVerifyTab() {
    if (!verifyPanel) return;
    if (verifyUi) verifyUi.dispose();
    verifyUi = null;
    clear(verifyPanel);
    if (!run.result) {
      verifyPanel.append(run.status === 'running' ? pendingState() : unavailableState());
      return;
    }
    verifyUi = VerifyPanel({
      run,
      ctx,
      onShowTab: (tabId) => tabs.select(tabId, { focus: true }),
      onChange: renderBadgesSoon,
      rememberTab: (tabId) => {
        session.scanTab = tabId;
      },
      // The CDN card and this one share the shell choice and the CLI download.
      cli: {
        path: CLI_PATH,
        shells: SHELLS,
        pythonFor: PYTHON_FOR_SHELL,
        getShell: () => session.cdnShell,
        setShell: (sh) => {
          session.cdnShell = sh;
        }
      }
    });
    verifyPanel.append(verifyUi.el);
  }

  let hideExpired = false;
  function renderCtTab() {
    clear(ctPanel);
    const r = run.result;
    if (!r) {
      ctPanel.append(run.status === 'running' ? pendingState() : unavailableState());
      return;
    }
    const now = Date.now();
    ctPanel.append(h('p', { class: 'muted text-sm' }, t('scan.ct.intro')));
    if (cert && r.ctCerts.length) {
      const found = r.ctCerts.some((c) => c.matchesCert);
      const a = Alert({ variant: found ? 'ok' : 'info', compact: true, message: found ? t('scan.ct.match') : t('scan.ct.noMatch') });
      a.dataset.ctMatch = String(found);
      ctPanel.append(a);
    }
    const hideBox = checkbox({
      label: t('scan.ct.hideExpired'),
      checked: hideExpired,
      onChange: (on) => {
        hideExpired = on;
        table.setFilter(on ? (c) => ctStatus(c, now).state !== 'expired' : null);
      }
    });
    const table = DataTable({
      caption: t('scan.tab.ct'),
      rows: r.ctCerts,
      search: true,
      dense: true,
      empty: t('scan.ct.empty'),
      rowKey: (c) => c.key,
      sort: { key: 'to', dir: 'desc' },
      filter: hideExpired ? (c) => ctStatus(c, now).state !== 'expired' : null,
      rowClass: (c) => ({ 'scan-ct-match': c.matchesCert, [`scan-ct-${ctStatus(c, now).state}`]: true }),
      toolbar: hideBox.el,
      className: 'scan-ct-table',
      export: { filename: 'ct-certificates', subject },
      columns: [
        {
          key: 'status', label: t('scan.ct.col.status'), sortable: true,
          sortValue: (c) => ({ expiring: 0, valid: 1, expired: 2, unknown: 3 })[ctStatus(c, now).state],
          exportValue: (c) => ctStatus(c, now).state,
          render: (c) => {
            const s = ctStatus(c, now);
            return h('div', { class: 'cluster' },
              c.matchesCert ? Badge(t('scan.ct.this'), { variant: 'accent', icon: 'certificate' }) : null,
              s.state === 'expired' ? Badge(t('scan.ct.expired'), { variant: 'neutral' })
                : s.state === 'expiring' ? Badge(t('scan.ct.expiring', { count: Math.max(0, s.days) }), { variant: 'warn', icon: 'clock' })
                  : s.state === 'valid' ? Badge(t('scan.ct.valid'), { variant: 'ok' }) : null);
          }
        },
        { key: 'issuer', label: t('scan.ct.col.issuer'), sortable: true, wrap: true },
        { key: 'from', label: t('scan.ct.col.from'), sortable: true, sortValue: (c) => c.notBefore, exportValue: (c) => c.notBefore, render: (c) => formatDate(c.notBefore) },
        { key: 'to', label: t('scan.ct.col.to'), sortable: true, sortValue: (c) => c.notAfter, exportValue: (c) => c.notAfter, render: (c) => formatDate(c.notAfter) },
        {
          key: 'names', label: t('scan.ct.col.names'), mono: true,
          searchValue: (c) => c.names.join(' '),
          exportValue: (c) => c.names.join(' '),
          render: (c) => TruncatedList(c.names, { max: 3 })
        },
        {
          key: 'serial', label: t('scan.ct.col.serial'), mono: true, sortable: true,
          render: (c) => (c.serialHex ? h('span', { class: 'scan-serial', title: c.serialHex }, c.serialHex.length > 20 ? `${c.serialHex.slice(0, 20)}…` : c.serialHex) : null),
          exportValue: (c) => c.serialHex
        },
        {
          key: 'sources', label: t('scan.ct.col.sources'),
          searchValue: (c) => (c.sources || [c.source]).join(' '),
          exportValue: (c) => (c.sources || [c.source]).join(' '),
          render: (c) => h('div', { class: 'cluster' },
            (c.sources || [c.source]).map((s) => (c.url && s === 'crtsh' ? ExternalLink(c.url, SOURCE_NAMES[s] || s, { className: 'text-sm' }) : h('span', { class: 'text-sm' }, SOURCE_NAMES[s] || s))))
        }
      ]
    });
    ctPanel.append(table.el);
  }

  function renderWildcards() {
    clear(wildcardNote);
    const r = run.result;
    if (!r) return;
    const wild = Object.entries(r.wildcards || {}).filter(([, w]) => w && w.wildcard);
    if (!wild.length) return;
    wildcardNote.append(Alert({
      variant: 'info', compact: true, icon: 'layers',
      message: t('scan.sum.wildcard', { list: wild.map(([d]) => `*.${d}`).join(', ') })
    }));
  }

  function renderTabBadges() {
    const r = run.result;
    const hostsCount = r ? r.hosts.length : liveHosts(run).length;
    tabs.setBadge('hosts', hostsCount);
    if (r) {
      const inv = run.config.inventoryServers > 0;
      const need = r.servers.filter((g) => g.needsCert).length;
      tabs.setBadge('servers', inv ? r.servers.length : r.unmatchedIps.length, need ? 'warn' : null);
      tabs.setBadge('cdn', r.stats.hiddenOrigin || null, r.stats.hiddenOrigin ? 'warn' : null);
      tabs.setBadge('ct', r.ctCerts.length || null);
    }
    if (verifyPanel) {
      const b = verifyTabBadge(run);
      tabs.setBadge('verify', b ? b.value : null, b ? b.variant : null);
    }
    const failed = run.sourceResults.filter((x) => !x.ok).length;
    tabs.setBadge('sources', run.sourceResults.length || null, failed ? 'error' : null);
  }

  function finish() {
    renderTitle();
    renderMeta();
    renderStages();
    renderChips();
    renderSourceWait();
    clear(runNotice);
    if (run.status === 'done') {
      const n = run.result.hosts.length;
      progress.set(n, Math.max(1, n));
      progress.done(t('scan.progress.done'));
      progress.setVariant('ok');
      hostsTable.setLoading(false);
      hostsTable.setRows(run.result.hosts);
      announce(t('scan.doneToast', { count: run.result.hosts.length }));
    } else if (run.found && run.found.size) {
      // Cancelled / failed: redraw the streamed partials without their "resolving…" badge
      // (updateRow drops the table's cached row, which setRows with the same objects would keep).
      for (const partial of run.found.values()) hostsTable.updateRow(partial);
    }
    if (run.status === 'cancelled') {
      progress.setVariant('warn');
      progress.setIndeterminate(false);
      progress.setLabel(t('scan.run.cancelledShort'));
      hostsTable.setLoading(false);
      runNotice.append(Alert({ variant: 'warn', compact: true, message: t('scan.run.cancelled', { time: formatDuration(run.finishedAt - run.startedAt) }) }));
    } else if (run.status === 'error') {
      progress.setVariant('error');
      progress.setIndeterminate(false);
      hostsTable.setLoading(false);
      runNotice.append(ErrorBanner(run.error, { title: t('scan.run.failed') }));
    }
    renderStats();
    renderSummary();
    renderSourceHealth();
    renderServersTab();
    renderCdnTab();
    renderVerifyTab();
    renderCtTab();
    renderWildcards();
    renderTabBadges();
    syncExports();
    stopTicker();
    onFinish();
  }

  /* --- live updates ------------------------------------------------------------------ */
  let ticker = null;
  function stopTicker() {
    if (ticker) clearInterval(ticker);
    ticker = null;
  }
  const renderBadgesSoon = frameThrottle(renderTabBadges);
  const syncExportsSoon = frameThrottle(syncExports);

  // Per-hit updates are batched per frame (a big wordlist streams thousands of hits); rows of
  // names shown as a streamed partial are replaced in place, other full records appended.
  const renderStagesSoon = frameThrottle(renderStages);
  const partialShown = new Set(run.found ? run.found.keys() : []);
  const listener = (type, payload) => {
    switch (type) {
      case 'stage':
        renderStages();
        renderProgress();
        renderSourceWait();
        if (payload.stage === 'sources') renderChips();
        // Announce a stage that really runs; a skipped one (exact zone mode, no wordlist…) stays silent.
        if (SCAN_STAGES.includes(payload.stage) && payload.stage !== 'done'
          && run.stages[payload.stage] && run.stages[payload.stage].state === 'active') announce(t(`scan.progress.${payload.stage}`));
        break;
      case 'progress':
        if (payload && payload.pills) renderStages();
        renderProgress();
        break;
      case 'source':
        renderChips();
        renderSourceWait();
        sourcesTable.addRows([payload]);
        renderSourceHealth();
        renderBadgesSoon();
        break;
      case 'found':
        partialShown.add(payload.name);
        hostsTable.upsertRow(payload);
        renderStats();
        renderStagesSoon();
        renderBadgesSoon();
        syncExportsSoon();
        break;
      case 'host':
        if (partialShown.delete(payload.name)) hostsTable.upsertRow(payload);
        else hostsTable.addRows([payload]);
        renderStats();
        renderStagesSoon();
        renderBadgesSoon();
        syncExportsSoon();
        break;
      case 'done':
      case 'cancelled':
      case 'error':
        finish();
        break;
      default:
        break;
    }
  };

  // Replay what the run already has, then follow it.
  renderTitle();
  renderMeta();
  renderStages();
  renderChips();
  if (run.sourceResults.length) sourcesTable.setRows(run.sourceResults);
  renderSourceHealth();
  renderSourceWait();
  const replayHosts = liveHosts(run);
  if (replayHosts.length && !run.result) hostsTable.setRows(replayHosts);
  renderStats();
  renderTabBadges();
  syncExports();
  applyFilters();
  if (run.status === 'running') {
    renderProgress();
    ticker = setInterval(renderMeta, 1000);
    run.listeners.add(listener);
  } else {
    finish();
  }

  return {
    el,
    dispose() {
      run.listeners.delete(listener);
      stopTicker();
      try {
        cdnOwnerCtl.abort();
      } catch {
        // already aborted / unsupported
      }
      // Detaches the panel only: a running verification keeps going on the run.
      if (verifyUi) verifyUi.dispose();
    }
  };
}

/** Numbers from ScanResult.stats that the live counters cannot know. */
function pickStats(st) {
  if (!st) return {};
  return { total: st.total, resolved: st.resolved, covered: st.covered, dangling: st.dangling };
}

/** "Fastly, Vercel" — providers of CDN / platform hosts (at most 3). */
function providerHint(hosts) {
  const names = [];
  for (const x of hosts || []) {
    const c = x.classification;
    if ((c.kind === 'cdn' || c.kind === 'platform') && c.provider && !names.includes(c.provider.name)) names.push(c.provider.name);
    if (names.length > 3) break;
  }
  if (!names.length) return null;
  return names.length > 3 ? `${names.slice(0, 3).join(', ')}…` : names.join(', ');
}

/** Expanded row of the Hosts table. */
function hostDetails(host, ctx) {
  const res = host.resolution;
  const c = host.classification;
  const resolver = res.resolver ? (getResolver(res.resolver) || { name: res.resolver }).name : '—';
  const items = [
    { key: t('scan.d.dns'), value: t('scan.d.dnsValue', { status: res.status, resolver, ttl: Number.isFinite(res.ttl) ? formatNumber(res.ttl) : '—' }), mono: false },
    { key: t('scan.d.reason'), value: t(c.reasonKey, { provider: c.provider ? c.provider.name : t('common.unknown') }) },
    res.cnames.length ? { key: t('scan.d.cnames'), value: res.cnames.join(' → '), mono: true, copy: true } : null,
    res.ipv4.length ? { key: t('scan.d.ipv4'), value: res.ipv4.join(', '), mono: true, copy: true } : null,
    res.ipv6.length ? { key: t('scan.d.ipv6'), value: res.ipv6.join(', '), mono: true, copy: true } : null,
    host.servers.length ? { key: t('scan.d.servers'), value: host.servers.map((s) => `${s.name} (${s.ip})`).join(', ') } : null,
    host.ipHints.length ? {
      key: t('scan.d.history'),
      value: h('div', { class: 'stack-sm' }, host.ipHints.slice(0, 12).map((x) => h('span', { class: 'mono text-sm' },
        `${x.ip} · ${SOURCE_NAMES[x.source] || x.source}${x.lastSeen instanceof Date ? ` · ${formatDate(x.lastSeen)}` : ''}`)))
    } : null,
    { key: t('scan.d.origins'), value: host.origins.map(originLabel).join(', ') },
    res.error ? { key: t('scan.d.error'), value: res.error, mono: true } : null,
    {
      key: t('scan.d.tools'),
      value: h('div', { class: 'cluster' },
        h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('global', { name: host.name, type: 'A' }) }, Icon('globe', { size: 14 }), h('span', { class: 'btn-label' }, t('nav.global'))),
        h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('lookup', { name: host.name, type: 'A' }) }, Icon('search', { size: 14 }), h('span', { class: 'btn-label' }, t('nav.lookup'))))
    }
  ];
  return KeyValueList(items, { className: 'scan-host-details' });
}
