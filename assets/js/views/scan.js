/**
 * views/scan.js — "SSL Targets" (the default view and the flagship flow).
 *
 * A renewed certificate arrives (e.g. *.example.com.tr) and the question is: which names
 * exist, where do they point, and which of *my* servers need the new certificate?
 *
 *   1. Certificate (optional) — its names seed the search; every host is checked against it
 *   2. Domains — auto-filled from the certificate (registrable domains), editable
 *   3. Inventory — the saved server list (state.inventory) used to match IPs to machines
 *   4. Options — passive sources (with quota notes), expired certificates, brute force,
 *      origin hints and extra names
 *
 * Run starts lib/scanner.runScan(); stages, per-source status and hosts stream into the
 * page. Results: stat cards, then tabs Hosts / Servers / Behind CDN / Sources /
 * CT certificates, plus exports (hosts CSV, servers CSV, full JSON, names.txt, targets.txt)
 * and the ready-to-run command for the companion CLI (cli/ssl_origin_scan.py), which
 * confirms origins behind Cloudflare from inside the network.
 *
 * A running scan is owned by this module, not by the mounted view: navigating to another
 * tool keeps it running (the results are there when you come back, and a toast says when
 * it finished). Everything stays in memory; nothing is uploaded except the DNS / CT
 * queries themselves.
 *
 * Route params: `#/scan?domain=example.com` (repeatable or comma-separated) pre-fills the
 * domains; `&run=1` also starts the scan.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, ButtonLink, Card, CodeBlock, DataTable, Disclosure, EmptyState, ErrorBanner, ExternalLink,
  Icon, KeyValueList, KindBadge, ProgressBar, StatCard, Tabs, TruncatedList, announce, checkbox,
  checkboxGroup, ipSortValue, radioGroup, select, textarea, toast
} from '../ui/components.js';
import { downloadText, timestampedName } from '../ui/download.js';
import {
  t, registerStrings, formatNumber, formatDate, formatDateTime, formatDuration, formatRelative, daysUntil
} from '../i18n.js';
import { parseHostList, baseDomainsFromNames, isPublicSuffix, stripWildcard } from '../lib/domain.js';
import { SOURCES } from '../lib/sources.js';
import { runScan, SCAN_STAGES } from '../lib/scanner.js';
import { WORDLIST_SMALL, WORDLIST_MEDIUM } from '../lib/wordlist.js';
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
/** Brute-force modes offered in the options. */
export const BRUTEFORCE_MODES = Object.freeze(['off', 'small', 'medium']);
/** Classification order used for sorting (most interesting first). */
const KIND_ORDER = ['dangling', 'cloudflare', 'cdn', 'platform', 'direct', 'private', 'unresolved', 'nxdomain'];
/** Host filter values of the "Show" select. */
export const KIND_FILTERS = Object.freeze(['all', 'hidden', 'cloudflare', 'cdn', 'platform', 'cdnplatform', 'direct', 'private', 'unresolved', 'dangling']);
const SOURCE_NAMES = Object.fromEntries(SOURCES.map((s) => [s.id, s.name]));
const HINT_KINDS = ['spf', 'mx', 'direct-sibling', 'history'];
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

  'scan.step.cert': 'Certificate',
  'scan.step.certDesc': 'Its names seed the search and every host is checked against it',
  'scan.step.domains': 'Domains',
  'scan.step.domainsDesc': 'Every subdomain of these is collected from CT logs and passive DNS',
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
  'scan.domains.placeholder': 'example.com.tr\nexample.com',
  'scan.domains.hint': 'One per line, or separated by spaces or commas. URLs are fine.',
  'scan.domains.fromCert': 'From the certificate: {domains}',
  'scan.domains.useCert': 'Use these',
  'scan.domains.invalid': 'Not a valid domain: {list}',
  'scan.domains.publicSuffix': '{list}: a public suffix such as com.tr cannot be scanned — enter a registered domain like example.com.tr.',
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
  'scan.opt.bf.medium': 'Medium · {count} names',
  'scan.opt.bfHint': 'Tries common names (www, mail, vpn, panel, destek, …) under each domain through DNS — finds hosts that never appeared in a public certificate.',
  'scan.opt.includeExpired': 'Include expired certificates',
  'scan.opt.includeExpiredHint': 'Older names from crt.sh too. Slower; for large domains crt.sh may only return unexpired certificates.',
  'scan.opt.originHints': 'Look for origin hints',
  'scan.opt.originHintsHint': 'SPF, MX, non-proxied sibling names and historical DNS often reveal the servers behind Cloudflare.',
  'scan.opt.extra': 'Extra hostnames',
  'scan.opt.extraPlaceholder': 'intranet.example.com.tr\nold-shop.example.com.tr',
  'scan.opt.extraHint': 'Names you already know about; they are always resolved.',
  'scan.opt.doh': 'DNS over HTTPS: {chain}',
  'scan.opt.dohChange': 'Change',

  'scan.run': 'Start scan',
  'scan.runAgain': 'Scan again',
  'scan.cancel': 'Cancel',
  'scan.summary.domains': { one: '{count} domain', other: '{count} domains' },
  'scan.summary.domainsCert': 'domains from the certificate',
  'scan.summary.noDomains': 'no domain yet',
  'scan.summary.sources': { zero: 'no passive sources', one: '{count} source', other: '{count} sources' },
  'scan.summary.bf.off': 'no brute force',
  'scan.summary.bf.small': 'small wordlist',
  'scan.summary.bf.medium': 'medium wordlist',
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
  'scan.stage.wildcard': 'Wildcard DNS',
  'scan.stage.bruteforce': 'Brute force',
  'scan.stage.resolve': 'Resolve',
  'scan.stage.hints': 'Origin hints',
  'scan.stage.done': 'Done',
  'scan.stage.skipped': 'skipped',
  'scan.progress.sources': 'Querying passive sources',
  'scan.progress.wildcard': 'Checking for wildcard DNS',
  'scan.progress.bruteforce': 'Trying wordlist names',
  'scan.progress.resolve': 'Resolving hostnames',
  'scan.progress.hints': 'Collecting origin hints (SPF, MX, siblings, history)',
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
  'scan.warn.PUBLIC_SUFFIX': '{detail} is a public suffix and was skipped.',
  'scan.warn.INVALID_DOMAIN': 'Invalid domain skipped: {detail}',
  'scan.warn.INVALID_NAME': 'Invalid hostname skipped: {detail}',
  'scan.warn.TRUNCATED': 'Too many names — only the first ones were resolved ({detail}).',
  'scan.warn.BRUTEFORCE_TRUNCATED': 'The wordlist was cut at {detail} candidates.',

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

  'scan.srv.intro': 'Servers from your inventory that the names resolve to (DNS) or that origin hints point at. Servers that need the certificate come first.',
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
  'scan.cdn.hintsDesc': 'IP addresses that may be the origin: from SPF and MX records, non-proxied sibling names and historical DNS. Confirm them with the CLI.',
  'scan.cdn.hintsEmpty': 'No origin hints found.',
  'scan.cdn.hintsOff': 'Origin hints were turned off for this scan.',
  'scan.cdn.col.ip': 'IP address',
  'scan.cdn.col.reasons': 'Evidence',
  'scan.cdn.col.servers': 'Your server',
  'scan.cdn.col.hosts': 'About',
  'scan.hint.spf': 'SPF',
  'scan.hint.mx': 'MX',
  'scan.hint.direct-sibling': 'Sibling',
  'scan.hint.history': 'History',
  'scan.hint.spf.title': 'Allowed to send mail for the domain (SPF record)',
  'scan.hint.mx.title': 'Mail server (MX) of the domain',
  'scan.hint.direct-sibling.title': 'Public IP of a non-proxied name of the same domain',
  'scan.hint.history.title': 'Seen in historical DNS (possibly before the proxy was enabled)',
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

  'scan.step.cert': 'Sertifika',
  'scan.step.certDesc': 'Adları aramayı başlatır; her host bu sertifikaya göre kontrol edilir',
  'scan.step.domains': 'Alan adları',
  'scan.step.domainsDesc': 'Bunların tüm alt alan adları CT kayıtlarından ve pasif DNS’ten toplanır',
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
  'scan.opt.bf.medium': 'Orta · {count} ad',
  'scan.opt.bfHint': 'Her alan adının altında yaygın adları (www, mail, vpn, panel, destek, …) DNS ile dener — hiçbir genel sertifikada geçmemiş host’ları bulur.',
  'scan.opt.includeExpired': 'Süresi dolmuş sertifikaları da dahil et',
  'scan.opt.includeExpiredHint': 'crt.sh’teki eski adları da getirir. Daha yavaştır; büyük alan adlarında crt.sh yalnızca süresi dolmamış sertifikaları döndürebilir.',
  'scan.opt.originHints': 'Asıl sunucu ipuçlarını ara',
  'scan.opt.originHintsHint': 'SPF, MX, proxy’lenmeyen kardeş adlar ve geçmiş DNS kayıtları çoğu zaman Cloudflare’in arkasındaki sunucuları ele verir.',
  'scan.opt.extra': 'Ek host adları',
  'scan.opt.extraPlaceholder': 'intranet.example.com.tr\neski-magaza.example.com.tr',
  'scan.opt.extraHint': 'Zaten bildiğiniz adlar; her zaman çözümlenir.',
  'scan.opt.doh': 'DNS over HTTPS: {chain}',
  'scan.opt.dohChange': 'Değiştir',

  'scan.run': 'Taramayı başlat',
  'scan.runAgain': 'Yeniden tara',
  'scan.cancel': 'İptal et',
  'scan.summary.domains': { one: '{count} alan adı', other: '{count} alan adı' },
  'scan.summary.domainsCert': 'alan adları sertifikadan',
  'scan.summary.noDomains': 'henüz alan adı yok',
  'scan.summary.sources': { zero: 'pasif kaynak yok', one: '{count} kaynak', other: '{count} kaynak' },
  'scan.summary.bf.off': 'kaba kuvvet yok',
  'scan.summary.bf.small': 'küçük kelime listesi',
  'scan.summary.bf.medium': 'orta kelime listesi',
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
  'scan.stage.wildcard': 'Wildcard DNS',
  'scan.stage.bruteforce': 'Kaba kuvvet',
  'scan.stage.resolve': 'Çözümleme',
  'scan.stage.hints': 'Asıl sunucu ipuçları',
  'scan.stage.done': 'Bitti',
  'scan.stage.skipped': 'atlandı',
  'scan.progress.sources': 'Pasif kaynaklar sorgulanıyor',
  'scan.progress.wildcard': 'Wildcard DNS kontrol ediliyor',
  'scan.progress.bruteforce': 'Kelime listesindeki adlar deneniyor',
  'scan.progress.resolve': 'Host adları çözümleniyor',
  'scan.progress.hints': 'Asıl sunucu ipuçları toplanıyor (SPF, MX, kardeş adlar, geçmiş)',
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
  'scan.warn.PUBLIC_SUFFIX': '{detail} bir genel sonek olduğu için atlandı.',
  'scan.warn.INVALID_DOMAIN': 'Geçersiz alan adı atlandı: {detail}',
  'scan.warn.INVALID_NAME': 'Geçersiz host adı atlandı: {detail}',
  'scan.warn.TRUNCATED': 'Çok fazla ad var — yalnızca ilkleri çözümlendi ({detail}).',
  'scan.warn.BRUTEFORCE_TRUNCATED': 'Kelime listesi {detail} adayda kesildi.',

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

  'scan.srv.intro': 'Envanterinizdeki, adların çözümlendiği (DNS) veya asıl sunucu ipuçlarının işaret ettiği sunucular. Sertifika kurulması gerekenler en üstte.',
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
  'scan.cdn.hintsDesc': 'Asıl sunucu olabilecek IP adresleri: SPF ve MX kayıtlarından, proxy’lenmeyen kardeş adlardan ve geçmiş DNS’ten. CLI ile doğrulayın.',
  'scan.cdn.hintsEmpty': 'Asıl sunucu ipucu bulunamadı.',
  'scan.cdn.hintsOff': 'Bu taramada asıl sunucu ipuçları kapalıydı.',
  'scan.cdn.col.ip': 'IP adresi',
  'scan.cdn.col.reasons': 'Kanıt',
  'scan.cdn.col.servers': 'Sunucunuz',
  'scan.cdn.col.hosts': 'İlgili adlar',
  'scan.hint.spf': 'SPF',
  'scan.hint.mx': 'MX',
  'scan.hint.direct-sibling': 'Kardeş ad',
  'scan.hint.history': 'Geçmiş',
  'scan.hint.spf.title': 'Alan adı adına e-posta göndermeye yetkili (SPF kaydı)',
  'scan.hint.mx.title': 'Alan adının e-posta sunucusu (MX)',
  'scan.hint.direct-sibling.title': 'Aynı alan adındaki proxy’lenmeyen bir adın genel IP’si',
  'scan.hint.history.title': 'Geçmiş DNS kayıtlarında görülmüş (muhtemelen proxy açılmadan önce)',
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
 * Validate stored scan options; unknown values fall back to defaults.
 * @param {any} input
 * @returns {{ sources: string[], includeExpired: boolean, bruteforce: 'off'|'small'|'medium', originHints: boolean }}
 */
export function sanitizeOptions(input) {
  const src = input && typeof input === 'object' ? input : {};
  const ids = SOURCES.map((s) => s.id);
  const sources = Array.isArray(src.sources)
    ? [...new Set(src.sources.filter((x) => ids.includes(x)))]
    : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  return {
    sources,
    includeExpired: src.includeExpired === true,
    bruteforce: BRUTEFORCE_MODES.includes(src.bruteforce) ? src.bruteforce : 'off',
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

function originLabel(origin) {
  if (origin === 'input' || origin === 'cert' || origin === 'bruteforce') return t(`scan.origin.${origin}`);
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
  run: null
};
let runCounter = 0;
/** The mounted view (null when another tool is shown). */
let active = null;

/**
 * @typedef {object} ScanRun
 * @property {number} id
 * @property {object} config summary of what was scanned
 * @property {AbortController} controller
 * @property {'running'|'done'|'cancelled'|'error'} status
 * @property {Record<string, { state: 'pending'|'active'|'done'|'skipped', info: object|null }>} stages
 * @property {{ stage: string|null, done: number, total: number }} progress
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
    sourceResults: [],
    sourcePlan: { domains: [], sources: [] },
    hosts: [],
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
      for (const s of SCAN_STAGES) if (run.stages[s].state === 'active') run.stages[s].state = 'done';
      run.stages[stage] = { state: stage === 'done' ? 'done' : info.skipped ? 'skipped' : 'active', info };
      if (stage === 'sources') run.sourcePlan = { domains: info.domains || [], sources: info.sources || [] };
      run.progress = { stage, done: 0, total: Number(info.total) || 0 };
      emit(run, 'stage', { stage, info });
    },
    onSource(result) {
      run.sourceResults.push(result);
      emit(run, 'source', result);
    },
    onHost(record) {
      run.hosts.push(record);
      emit(run, 'host', record);
    },
    onProgress(p) {
      run.progress = { stage: p.stage, done: p.done, total: p.total };
      emit(run, 'progress', run.progress);
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
      finishedAt: run.finishedAt
    });
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
      renderDomainsHint();
      renderRunSummary();
    }
  });
  const domainsHint = h('div', { class: 'scan-domains-cert' });
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
  const bfGroup = radioGroup({
    legend: t('scan.opt.bruteforce'),
    name: 'scan-bruteforce',
    value: options.bruteforce,
    hint: t('scan.opt.bfHint'),
    options: [
      { value: 'off', label: t('scan.opt.bf.off') },
      { value: 'small', label: t('scan.opt.bf.small', { count: formatNumber(WORDLIST_SMALL.length) }) },
      { value: 'medium', label: t('scan.opt.bf.medium', { count: formatNumber(WORDLIST_MEDIUM.length) }) }
    ],
    onChange: (value) => {
      options = { ...options, bruteforce: value };
      saveOptions(options);
      renderRunSummary();
    },
    className: 'scan-bf'
  });
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
      }, t('scan.opt.dohChange')));
  }

  /* --- run bar ----------------------------------------------------------------- */
  const runBtn = Button({ label: t('scan.run'), icon: 'play', variant: 'primary', size: 'lg', dataset: { action: 'scan-run' }, onClick: () => start() });
  const cancelBtn = Button({ label: t('scan.cancel'), icon: 'stop', variant: 'secondary', size: 'lg', dataset: { action: 'scan-cancel' }, onClick: () => cancel() });
  const runSummary = h('div', { class: 'scan-runbar-summary text-sm' });
  const runError = h('div', { class: 'scan-runbar-error', attrs: { 'aria-live': 'polite' } });

  function renderRunSummary() {
    const parsed = parseDomainsInput(domainsField.value);
    let domainsText = t('scan.summary.noDomains');
    if (parsed.domains.length) domainsText = t('scan.summary.domains', { count: parsed.domains.length });
    else if (certLeaf() && certLeaf().hostnames.length) domainsText = t('scan.summary.domainsCert');
    clear(runSummary);
    runSummary.append(
      h('span', null, domainsText),
      h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('span', null, t('scan.summary.sources', { count: options.sources.length })),
      h('span', { class: 'scan-dot', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('span', null, t(`scan.summary.bf.${options.bruteforce}`)),
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
    step(2, 'domains', 'globe', domainsStatus, h('div', { class: 'stack-sm' }, domainsField.el, domainsHint), 'scan-step-domains'),
    step(3, 'inventory', 'server', invStatus, invBody, 'scan-step-inventory'),
    step(4, 'options', 'sliders', null, h('div', { class: 'scan-options' },
      sourcesGroup.el,
      h('div', { class: 'stack' }, bfGroup.el, h('div', { class: 'stack-sm' }, expiredBox.el, hintsBox.el)),
      h('div', { class: 'stack-sm' }, extraField.el, dohLine)), 'scan-step-options'));

  const runbar = h('div', { class: 'scan-runbar card' },
    h('div', { class: 'scan-runbar-buttons' }, runBtn, cancelBtn),
    h('div', { class: 'scan-runbar-info' }, runSummary, runError));
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
    if (key === 'settings') renderDoh();
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
    const run = createRun({
      domains: shownDomains,
      sources: [...options.sources],
      bruteforce: options.bruteforce,
      includeExpired: options.includeExpired,
      originHints: options.originHints,
      cert: v.cert,
      certName: certLoad ? certLoad.name : '',
      inventoryServers: state.inventory.servers.length
    });
    // The DohClient counts queries for its whole life; remember where this run started.
    run.queriesAtStart = typeof dns.stats === 'function' ? dns.stats().queries : null;
    session.run = run;
    ctx.setParams(v.domains.length ? { domain: v.domains.join(',') } : {});
    attach(run);
    startRun(run, {
      domains: v.domains,
      cert: v.cert,
      extraNames: v.extraNames,
      sources: [...options.sources],
      includeExpired: options.includeExpired,
      bruteforce: options.bruteforce,
      inventory: state.inventory.servers,
      originHints: options.originHints,
      dns
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

  const params = new URLSearchParams(ctx.searchParams);
  if (params.get('run') === '1' && (!session.run || session.run.status !== 'running')) {
    queueMicrotask(() => {
      if (!ctx.signal.aborted) start();
    });
  }

  active = {
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
      if (p.run === '1') start();
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
  const runNotice = h('div', { class: 'scan-run-notice' });
  // The ProgressBar has its own throttled live region; the panel itself is not live (too chatty).
  const panel = h('section', { class: 'scan-run card', dataset: { status: run.status }, attrs: { 'aria-label': t('progress.label') } },
    h('div', { class: 'scan-run-head' }, h('div', { class: 'scan-run-titles' }, title, meta)),
    stageList, progress, chips, runNotice);

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

  function renderStages() {
    for (const s of SCAN_STAGES) {
      const st = run.stages[s];
      const el = stageEls[s];
      el.dataset.state = st.state;
      el.classList.toggle('is-active', st.state === 'active');
      const note = el.querySelector('.scan-stage-note');
      note.textContent = st.state === 'skipped' ? t('scan.stage.skipped') : '';
      if (st.state === 'active') el.setAttribute('aria-current', 'step');
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
    for (const sid of ids) {
      const s = sourceChipState(run.sourceResults, sid, expected);
      // A finished (cancelled / failed) run has no pending sources left: nothing will arrive.
      if (run.status !== 'running' && s.state === 'pending') s.state = run.sourceResults.some((r) => r.source === sid) ? 'partial' : 'cancelled';
      const el = chipFor(sid);
      el.dataset.state = s.state;
      clear(el);
      const iconName = { ok: 'check-circle', partial: 'alert', error: 'x-circle', cancelled: 'minus-circle' }[s.state];
      el.append(iconName ? Icon(iconName, { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'scan-chip-name' }, SOURCE_NAMES[sid] || sid),
        h('span', { class: 'scan-chip-value' }, s.state === 'pending'
          ? (s.done ? `${s.done}/${s.expected}` : t('scan.chip.waiting'))
          : s.state === 'cancelled' ? t('scan.chip.error.abort')
            : s.state === 'error' ? t(`scan.chip.error.${CHIP_ERRORS.includes(s.errorKind) ? s.errorKind : 'unknown'}`)
              : `${t('scan.chip.names', { count: s.names })}${s.state === 'partial' ? ` · ${t('scan.chip.partial')}` : ''}`));
      el.title = s.error || '';
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
    const c = run.result ? { ...countHosts(run.result.hosts), ...pickStats(run.result.stats) } : countHosts(run.hosts);
    stat.hosts.set({ value: c.total, hint: t('scan.stat.hostsHint', { count: formatNumber(c.resolved) }) });
    stat.cloudflare.set({ value: c.cloudflare, hint: t('scan.stat.cloudflareHint') });
    stat.cdn.set({ value: c.cdn + c.platform, hint: providerHint(run.result ? run.result.hosts : run.hosts) || t('scan.stat.cdnHint') });
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

  const tabs = Tabs([
    { id: 'hosts', label: t('scan.tab.hosts'), icon: 'list', content: hostsPanel },
    { id: 'servers', label: t('scan.tab.servers'), icon: 'server', content: serversPanel },
    { id: 'cdn', label: t('scan.tab.cdn'), icon: 'cloud', content: cdnPanel },
    { id: 'sources', label: t('scan.tab.sources'), icon: 'database', content: sourcesPanel },
    { id: 'ct', label: t('scan.tab.ct'), icon: 'certificate', content: ctPanel }
  ], { label: t('scan.results'), className: 'scan-tabs' });

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
        render: (r) => (r.ok
          ? (r.partial ? Badge(t('scan.src.partial'), { variant: 'warn', icon: 'alert' }) : Badge(t('scan.src.ok'), { variant: 'ok', icon: 'check' }))
          : Badge(t('scan.src.failed'), { variant: 'error', icon: 'x-circle' }))
      },
      { key: 'names', label: t('scan.src.col.names'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.names.length, render: (r) => formatNumber(r.names.length) },
      { key: 'ips', label: t('scan.src.col.ips'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.ipHints.length, render: (r) => formatNumber(r.ipHints.length) },
      { key: 'certs', label: t('scan.src.col.certs'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.certs.length, render: (r) => formatNumber(r.certs.length) },
      { key: 'time', label: t('scan.src.col.time'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.elapsedMs, render: (r) => formatDuration(r.elapsedMs) },
      {
        key: 'error', label: t('scan.src.col.error'), wrap: true,
        sortValue: (r) => r.error || '',
        render: (r) => (r.error ? h('div', { class: 'stack-sm scan-src-error' },
          h('span', null, t(`error.kind.${r.errorKind || 'unknown'}`)),
          h('code', { class: 'mono text-xs muted' }, r.error)) : null)
      }
    ]
  });
  const sourcesNote = h('p', { class: 'muted text-sm' }, t('scan.src.retryHint'));
  const wildcardNote = h('div');
  sourcesPanel.append(run.config.sources.length ? sourcesTable.el : EmptyState({ compact: true, icon: 'database', message: t('scan.src.none') }),
    sourcesNote, wildcardNote);

  const pendingState = () => EmptyState({ compact: true, icon: 'clock', message: t('scan.pending') });
  const unavailableState = () => EmptyState({ compact: true, icon: 'minus-circle', message: t('scan.notAvailable') });
  for (const p of [serversPanel, cdnPanel, ctPanel]) p.append(pendingState());

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
      generator: 'Subdomain Scanner',
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
      scan: run.result
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
    if (st.hiddenOrigin) add('info', t('scan.sum.hidden', { count: st.hiddenOrigin }), 'cloud', 'hidden');
    if (inv && st.unmatchedIps) add('info', t('scan.sum.unmatched', { count: st.unmatchedIps }), 'help', 'unmatched');
    if (st.dangling) add('error', t('scan.sum.dangling', { count: st.dangling }), 'unlink', 'dangling');
    const wild = Object.entries(r.wildcards || {}).filter(([, w]) => w && w.wildcard).map(([d]) => `*.${d}`);
    if (wild.length) add('info', t('scan.sum.wildcard', { list: wild.join(', ') }), 'layers', 'wildcard');
    if (st.sourcesFailed) add('warn', t('scan.sum.sourcesFailed', { count: st.sourcesFailed }), 'alert', 'sources-failed');
    for (const w of r.warnings || []) add('warn', t(`scan.warn.${w.code}`, { detail: w.detail }), 'alert', w.code);
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
              render: (x) => h('span', { class: ['scan-srv-host', { 'is-hint': x.via === 'hint' }] }, x.name,
                x.via === 'hint' ? h('span', { class: 'muted' }, ` · ${t('scan.srv.via.hint')}`) : null)
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
        { key: 'via', label: t('scan.srv.col.via'), render: (x) => Badge(t(`scan.srv.via.${x.via}`), { variant: x.via === 'dns' ? 'direct' : 'info' }) },
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
    cdnPanel.append(Alert({
      variant: 'info',
      icon: 'cloud',
      title: t('scan.cdn.whyTitle'),
      children: h('div', { class: 'stack-sm scan-why' }, h('p', null, t('scan.cdn.why1')), h('p', null, t('scan.cdn.why2')))
    }));

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
        cert ? {
          key: 'cert', label: t('scan.col.cert'), sortable: true,
          sortValue: (x) => (x.cert && x.cert.covered ? 1 : 0),
          exportValue: (x) => !!(x.cert && x.cert.covered),
          render: (x) => (x.cert && x.cert.covered ? Badge(t('scan.host.covered'), { variant: 'ok', icon: 'check' }) : Badge(t('scan.host.notCovered'), { variant: 'neutral', icon: 'x' }))
        } : null
      ].filter(Boolean)
    }).el);

    cdnPanel.append(h('h3', { class: 'scan-subtitle' }, t('scan.cdn.hintsTitle')),
      h('p', { class: 'muted text-sm' }, t('scan.cdn.hintsDesc')));
    if (!r.options || r.options.originHints === false) {
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
            searchValue: (o) => o.reasons.map((x) => `${x.kind} ${x.detail}`).join(' '),
            exportValue: (o) => o.reasons.map((x) => `${x.kind}: ${x.detail}`).join(' | '),
            render: (o) => h('div', { class: 'stack-sm scan-hint-reasons' }, o.reasons.slice(0, 4).map((x) => h('div', { class: 'scan-hint-reason' },
              Badge(HINT_KINDS.includes(x.kind) ? t(`scan.hint.${x.kind}`) : x.kind, { variant: 'info', title: HINT_KINDS.includes(x.kind) ? t(`scan.hint.${x.kind}.title`) : null }),
              h('span', { class: 'mono text-xs scan-hint-detail' }, x.detail))),
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
    const hostsCount = r ? r.hosts.length : run.hosts.length;
    tabs.setBadge('hosts', hostsCount);
    if (r) {
      const inv = run.config.inventoryServers > 0;
      const need = r.servers.filter((g) => g.needsCert).length;
      tabs.setBadge('servers', inv ? r.servers.length : r.unmatchedIps.length, need ? 'warn' : null);
      tabs.setBadge('cdn', r.stats.hiddenOrigin || null, r.stats.hiddenOrigin ? 'warn' : null);
      tabs.setBadge('ct', r.ctCerts.length || null);
    }
    const failed = run.sourceResults.filter((x) => !x.ok).length;
    tabs.setBadge('sources', run.sourceResults.length || null, failed ? 'error' : null);
  }

  function finish() {
    renderTitle();
    renderMeta();
    renderStages();
    renderChips();
    clear(runNotice);
    if (run.status === 'done') {
      const n = run.result.hosts.length;
      progress.set(n, Math.max(1, n));
      progress.done(t('scan.progress.done'));
      progress.setVariant('ok');
      hostsTable.setLoading(false);
      hostsTable.setRows(run.result.hosts);
      announce(t('scan.doneToast', { count: run.result.hosts.length }));
    } else if (run.status === 'cancelled') {
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
    renderServersTab();
    renderCdnTab();
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

  const listener = (type, payload) => {
    switch (type) {
      case 'stage':
        renderStages();
        renderProgress();
        if (payload.stage === 'sources') renderChips();
        break;
      case 'progress':
        renderProgress();
        break;
      case 'source':
        renderChips();
        sourcesTable.addRows([payload]);
        renderBadgesSoon();
        break;
      case 'host':
        hostsTable.addRows([payload]);
        renderStats();
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
  if (run.hosts.length && !run.result) hostsTable.setRows(run.hosts);
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
