/**
 * views/subdomains.js — "Subdomains": the search-first page for the most common question,
 * "which subdomains does this domain have, and where do they point?".
 *
 * - Hero: one large domain box (URLs, hostnames and several domains are accepted; a leading
 *   `www.` is dropped, any other subdomain is kept and scopes the scan to that branch), a
 *   prominent Scan button (Enter works too), example chips, a "try a wordlist" switch and an
 *   "Advanced" disclosure (passive sources with quota notes, wordlist level Off / Small /
 *   Smart / Large / Huge with exact candidate counts, the locale packs the typed domain gets and
 *   a time estimate, languages / markets (automatic from the domain ending or chosen), a custom
 *   wordlist (paste or .txt, this tab only), learned names of earlier scans (opt-in; bare labels
 *   of in-scope names, stored in this browser and tried as DNS lookups under later targets —
 *   never at level Off), permutations + budget, origin hints, expired certificates, extra
 *   hostnames; the plan counts every wildcard base too).
 *   The options are remembered per browser (a stored legacy 'medium' level loads as 'smart').
 * - Runs lib/scanner.runScan (the DNS-first discovery engine) without a certificate: stages
 *   (sources, DNS records, wildcard, wordlist, permutations, resolve, origin hints), per-source
 *   chips with clear status texts (quota used up, temporarily down + CT fallback …) and a
 *   progress bar while it runs; hosts stream into the table as they resolve. Cancel aborts
 *   through an AbortController.
 * - Results in tabs under the run's header (title, time, progress bar), with live counts on the
 *   tab labels (lib/subtabs): Overview — stat cards (click to filter the hosts), the summary
 *   alerts, "found through DNS / from sources" technique chips and a hand-over to "SSL Targets";
 *   Hosts — copy / names.txt / CSV / JSON exports, a filter bar (All / Resolving / Cloudflare /
 *   Direct / Not resolving + search) and the table (subdomain → DNS lookup, IPs → IP Intel,
 *   classification with the translated reason, CNAME chain, how each name was found, matching
 *   inventory server; wildcard suspects hidden by default; on a phone each row is a card whose
 *   names wrap only after a dot and whose IPs never break); Origins — the ORIGIN panel for
 *   proxied (orange-cloud) hosts: origin networks (/24), resolver-leak and history candidates
 *   (structured reason fields) and a ready-to-copy CLI sweep command for POSIX shells or
 *   PowerShell (lib/cmdline quotes every token); Sources — the stage pills, per-source chips,
 *   status lines and free limits. Hosts is the automatic tab once a host is listed (Sources
 *   before that while the run is live, Overview when it ended empty); a tab the user picks stays.
 *
 * Like the SSL Targets scan, a running scan belongs to this module, not to the mounted view:
 * opening a subdomain in DNS Lookup and coming back keeps the results (a toast says when a
 * scan finished in the background).
 *
 * Route params: `#/subdomains?domain=example.com` (comma-separated or repeated) pre-fills the
 * box. A shared link with `&run=1` (the header's "Copy link") pre-fills it and offers a one-click
 * "Start scan" prompt — a link never starts a scan (third-party quotas, thousands of DNS
 * queries) on its own. Starting a scan writes only `domain` into the URL (replaceState), so a
 * reload or a restored tab pre-fills the box instead of silently scanning again. Picking a results
 * tab adds `tab=overview|hosts|origins|sources` (replaceState); a re-mount (a language switch,
 * Back from another view) opens that tab again. A domain carried over from another tool (`run=0`,
 * lib/session.js) fills the box only while it is empty or still holds the last scan's domains or
 * the domain carried before. "Delete all local data" forgets the box and the last scan (a running
 * one is stopped), whether or not the view is mounted.
 */

import { h, clear, uid, debounce, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, ButtonLink, CodeBlock, CopyButton, DataTable, Disclosure, EmptyState, ErrorBanner, Icon, KindBadge,
  ProgressBar, SegmentedControl, StatCard, Tabs, TruncatedList, announce, checkbox, checkboxGroup, decodeText, ipSortValue,
  radioGroup, select, textInput, textarea, toast
} from '../ui/components.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { t, registerStrings, hasString, formatNumber, formatDuration, formatDate, formatDateTime, formatBytes } from '../i18n.js';
import {
  normalizeHostname, stripWildcard, registrableDomain, isPublicSuffix, isSubdomainOf, parseHostList, sortHostnames,
  baseDomainsFromNames
} from '../lib/domain.js';
import { normalizeIP } from '../lib/netinfo.js';
import { describeNetwork } from '../lib/ipintel.js';
import { SOURCES, sourceHealthSummary } from '../lib/sources.js';
import { runScan, learnedLabelsFromScan, estimateQueries, SCAN_STAGES, HOST_SPECIFIC_HINT_KINDS } from '../lib/scanner.js';
import {
  WORDLIST_SMALL, LOCALE_PACK_CODES, localesForDomain, parseCustomWordlist, wordlistInfo
} from '../lib/wordlist.js';
import { createLearnedStore } from '../lib/learned.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { state as stateSingleton } from '../state.js';
import { buildFittedSweepCommand, validateTargets, validateNames } from '../lib/cmdline.js';
import { toCsv, toJson, scanHostRows } from '../lib/export.js';
import { SUB_TABS, parseSubTab, initialSubTab, nextAutoTab, summaryAlerts, subTabBadges, hostSegments } from '../lib/subtabs.js';
import { getResolver } from '../lib/resolvers.js';
import { errorKind, splitList } from '../lib/util.js';

/** Route id. */
export const id = 'subdomains';
/** i18n key of the page title. */
export const titleKey = 'nav.subdomains';
/** Nav/page icon. */
export const icon = 'layers';

/** localStorage key for the remembered options (a per-browser convenience). */
export const OPTIONS_KEY = 'ssds.subdomains.options';
/** Wordlist levels offered (lib/wordlist.loadWordlist levels + off). */
export const BRUTEFORCE_MODES = Object.freeze(['off', 'small', 'smart', 'large', 'huge']);
/** Stored levels of older versions → current level ('medium' ⊂ 'smart'). */
export const LEGACY_BRUTEFORCE = Object.freeze({ medium: 'smart' });
/** Permutation budgets offered (candidates; the scanner default is 1,500). */
export const PERMUTATION_BUDGETS = Object.freeze([500, 1500, 5000]);
/** Default permutation budget. */
export const DEFAULT_PERMUTATION_BUDGET = 1500;
/**
 * Rough throughput of the courteous bulk DNS probes in a browser at the full sweep width
 * ({@link MAX_SWEEP_CONCURRENCY} queries in flight over the balanced DoH pool at ~0.2 s each):
 * the one rate every time estimate uses, scaled down for a lower Settings value. Deliberately
 * conservative — resolvers with a warm cache answer faster, a slow self-hosted nameserver slower.
 */
export const PROBE_RATE_QPS = 120;
/**
 * Candidates the scanner tries per scanned domain at each level at most (mirrors
 * lib/scanner MAX_BRUTEFORCE_PER_BASE; a unit test keeps the two in step) and across all
 * domains of one scan (MAX_BRUTEFORCE_TOTAL). Custom and learned names count towards the cap.
 */
export const BRUTEFORCE_CAPS = Object.freeze({ small: 4000, smart: 20000, large: 80000, huge: 160000 });
export const BRUTEFORCE_TOTAL_CAP = 200000;
/** Locale packs the user can choose (lib/wordlist LOCALE_PACK_CODES). */
export const LOCALE_CODES = LOCALE_PACK_CODES;
/** Learned labels tried per scan at most (the most frequent first). */
export const LEARNED_TRY_MAX = 1000;
/** sessionStorage key of the pasted / uploaded custom wordlist (raw text, this tab only). */
export const CUSTOM_WORDLIST_KEY = 'ssds.wordlist.custom';
/** Longest custom wordlist kept in sessionStorage (characters); a longer one stays in memory. */
export const CUSTOM_WORDLIST_MAX_CHARS = 2000000;
/** Largest .txt file the custom-wordlist upload reads. */
export const CUSTOM_FILE_MAX_BYTES = 5 * 1024 * 1024;
/** Shells the origin sweep command is offered for. */
export const SHELLS = Object.freeze(['posix', 'powershell']);
/** Python launcher per shell (the CLI needs Python 3.8+). */
export const PYTHON_FOR_SHELL = Object.freeze({ posix: 'python3', powershell: 'python' });
/** Every table filter (stat cards can pick the last two too). */
export const FILTERS = Object.freeze(['all', 'resolving', 'cloudflare', 'direct', 'unresolved', 'cdn', 'dangling']);
/** Filters offered in the segmented control. */
export const SEGMENT_FILTERS = Object.freeze(['all', 'resolving', 'cloudflare', 'direct', 'unresolved']);
/** Example chips under the search box. */
export const EXAMPLES = Object.freeze(['github.com', 'cloudflare.com', 'wikipedia.org']);
/** Companion CLI, relative to the site root (published with the Pages site). */
export const CLI_PATH = 'cli/ssl_origin_scan.py';
/**
 * Largest block the CLI sweeps without --allow-large: 2^16 addresses (cli CIDR_LIMIT). An IPv4
 * /24 fits; an IPv6 /48 never does (the CLI refuses it and scans nothing), so IPv6 networks go
 * into the command as their known addresses.
 */
export const CLI_MAX_BLOCK_BITS = 16;
/** Most parallel DNS queries a scan's bulk sweep may use (lib/scanner PROBE_CONCURRENCY). */
export const MAX_SWEEP_CONCURRENCY = 24;

/** Stages shown as pills ("done" is the panel state). */
export const SHOWN_STAGES = Object.freeze(SCAN_STAGES.filter((s) => s !== 'done'));
/** Origin-hint kinds with a localized label (sub.hint.<kind>). */
export const HINT_KINDS = Object.freeze(['resolver-leak', 'history', 'sibling-domain', 'direct-sibling', 'spf', 'mx', 'zone']);
/** DNS record types lib/dnsmine can tag names with ('dns-mine:<record>'). */
export const MINE_RECORDS = Object.freeze(['MX', 'NS', 'SOA', 'SPF', 'DMARC', 'SRV', 'CNAME', 'CAA', 'HTTPS', 'PTR']);
const CHIP_ERRORS = ['abort', 'timeout', 'rate-limit', 'http', 'network', 'parse', 'unknown'];
/** ScanResult warning codes with a localized sentence (sub.warn.<code> / scan.warn.<code>); others show as `code: detail`. */
export const WARNING_CODES = Object.freeze(['INVALID_DOMAIN', 'INVALID_NAME', 'PUBLIC_SUFFIX', 'TRUNCATED', 'BRUTEFORCE_TRUNCATED', 'WILDCARD_PARENTS_TRUNCATED', 'WORDLIST_DEGRADED', 'DNS_UNREACHABLE', 'RECURSIVE_TRUNCATED', 'ZONE_OUT_OF_SCOPE']);
const SOURCE_NAMES = Object.fromEntries(SOURCES.map((s) => [s.id, s.name]));
/** DNS-discovery origin ids (anything a source did not report). */
const DNS_ORIGINS = new Set(['wordlist', 'bruteforce', 'permutation', 'recursive']);
/**
 * Build-time sizes of the levels and locale packs (lib/wordlist.wordlistInfo; a unit test there
 * asserts they match the data files), so every label is exact without downloading anything.
 */
const WORDLIST_INFO = wordlistInfo();
/** Stat card → filter. */
const STAT_FILTERS = {
  found: 'all', resolving: 'resolving', cloudflare: 'cloudflare', cdn: 'cdn', direct: 'direct', unresolved: 'unresolved', dangling: 'dangling'
};

/** CSV columns (English headers, like the other exports). */
const CSV_COLUMNS = Object.freeze([
  { key: 'name', header: 'Subdomain' },
  { key: 'status', header: 'DNS status' },
  { key: 'kind', header: 'Classification' },
  { key: 'provider', header: 'Provider' },
  { key: 'hidesOrigin', header: 'Origin hidden' },
  { key: 'dangling', header: 'Dangling CNAME' },
  { key: 'ipv4', header: 'IPv4' },
  { key: 'ipv6', header: 'IPv6' },
  { key: 'cnames', header: 'CNAME chain' },
  { key: 'ttl', header: 'TTL' },
  { key: 'servers', header: 'Servers' },
  { key: 'origins', header: 'Found by' },
  { key: 'wildcardSuspect', header: 'Wildcard suspect' },
  { key: 'resolver', header: 'Resolver' },
  { key: 'error', header: 'Error' }
]);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'sub.hero.title': 'Which domain should we scan?',
  'sub.hero.desc': 'DNS first: the domain’s own records, a smart wordlist and variations of every name found are checked over DNS-over-HTTPS, then Certificate Transparency and passive DNS fill the gaps — right in your browser, which never connects to the domain’s servers.',
  'sub.input.placeholder': 'example.com',
  'sub.input.hint': 'A domain, a URL or a subdomain. Separate several domains with spaces or commas.',
  'sub.run': 'Scan',
  'sub.cancel': 'Cancel',
  'sub.link.prompt': 'This link opens a scan of {domains}. It starts when you click — it queries the passive sources and public DNS resolvers from your browser.',
  'sub.link.start': 'Start scan',
  'sub.examples': 'Try:',
  'sub.scope': 'Only names under {name} are listed.',
  'sub.scopeAll': 'Scan all of {domain}',
  'sub.err.required': 'Enter a domain, e.g. example.com.',
  'sub.err.invalid': 'Not a valid domain: {list}',
  'sub.err.ip': '{list} is an IP address — use IP Intel for addresses, or enter a domain here.',
  'sub.err.publicSuffix': '{list} is a public suffix — enter a registered domain such as example.com.',

  'sub.opt.wordlist': 'Guess names over DNS ({size} wordlist · {count} names)',
  'sub.opt.wordlistPacks': 'Guess names over DNS ({size} wordlist · {count} names {packs})',
  'sub.bf.small': 'small',
  'sub.bf.smart': 'smart',
  'sub.bf.large': 'large',
  'sub.bf.huge': 'huge',
  'sub.opt.advanced': 'Advanced options',
  'sub.opt.sources': 'Passive sources',
  'sub.opt.sourcesHint': 'Queried straight from your browser. Free tiers have limits; a failed source never stops the scan — the DNS discovery does not depend on them.',
  'sub.src.crtsh': 'Certificate Transparency search. Free; slow for big domains (a minute or more).',
  'sub.src.certspotter': 'Certificate Transparency API · about 10 requests per hour per IP; unexpired certificates only.',
  'sub.src.hackertarget': 'Host search with current IPs · about 50 requests per day per IP.',
  'sub.src.anubis': 'Subdomain database · free, no key.',
  'sub.src.otx': 'Passive DNS · anonymous access is often rate-limited.',
  'sub.src.thc': 'Subdomain database with last-seen dates · free, no key; up to 1,000 names per domain.',
  'sub.opt.bruteforce': 'Wordlist (guess names over DNS)',
  'sub.opt.bf.off': 'Off',
  'sub.opt.bf.offHint': 'Only the domain’s own DNS records and the passive sources.',
  'sub.opt.bf.small': 'Small · {count} names',
  'sub.opt.bf.smallHint': 'The most common names only · {time} per domain.',
  'sub.opt.bf.smart': 'Smart · {count} names',
  'sub.opt.bf.smartHint': 'Recommended. The most common names worldwide, ranked from open subdomain lists · {time} per domain.',
  'sub.opt.bf.large': 'Large · {count} names',
  'sub.opt.bf.largeHint': 'A much longer tail of the same ranking, loaded from this site when the scan starts ({size}) · {time} per domain.',
  'sub.opt.bf.huge': 'Huge · {count} names',
  'sub.opt.bf.hugeHint': 'The whole ranking, loaded from this site when the scan starts ({size}) · many minutes: {time} per domain. For a domain you own and want mapped thoroughly.',
  'sub.opt.bf.recommended': 'recommended',
  'sub.opt.bfHint': 'Each name is one A query to public DoH resolvers — your browser never contacts the domain’s web servers. Names a resolver has not cached are passed on to the domain’s authoritative nameservers, so a self-hosted nameserver sees the burst. Wildcard DNS is detected at every level, so fake hits are dropped. Times are rough.',
  'sub.opt.bf.counting': '…',
  'sub.est.seconds': '≈ {n} s',
  'sub.est.minutes': { one: '≈ {count} min', other: '≈ {count} min' },
  'sub.plan.none': 'Type a domain above to see how many names the wordlist will try.',
  'sub.plan.off': 'No names are guessed: only the domain’s own DNS records and the passive sources.',
  'sub.plan.line': '≈ {queries} DNS queries for {domains} ({parts}) · {time}',
  'sub.plan.queriesRange': '{min}–{max}',
  'sub.plan.zoneExact': { one: 'Exact mode: only the {count} name from your zone file is resolved; the wordlist, variations and passive sources are not used for this scan.', other: 'Exact mode: only the {count} names from your zone file are resolved; the wordlist, variations and passive sources are not used for this scan.' },
  'sub.plan.perDomain': 'per domain: {parts}',
  'sub.plan.domains': { one: '{count} domain', other: '{count} domains' },
  'sub.plan.level': '{count} {level}',
  'sub.plan.pack': '+{count} {language}',
  'sub.plan.custom': '+{count} yours',
  'sub.plan.learned': '+{count} learned',
  'sub.plan.capped': 'capped at {count} per domain',

  'sub.lang.legend': 'Languages / markets',
  'sub.lang.hint': 'Adds local-language names (e.g. Turkish destek, German kunden) to the global list for the domain’s market — from the Smart level up.',
  'sub.lang.auto': 'Choose from the domain ending',
  'sub.lang.autoPick': 'Auto: {list}',
  'sub.lang.autoItem': '{language} ({suffix})',
  'sub.lang.autoNone': 'Auto: none — {suffix} has no market pack, so the global list is used',
  'sub.lang.autoEmpty': 'Auto: picked from the domain ending (e.g. .de → German, .com.tr → Turkish)',
  'sub.lang.manualNone': 'None: the global list only',
  'sub.lang.manual': 'Chosen: {list}',
  'sub.lang.option': '{language} · {count}',
  'sub.lang.tr': 'Turkish',
  'sub.lang.de': 'German',
  'sub.lang.fr': 'French',
  'sub.lang.es': 'Spanish',
  'sub.lang.pt': 'Portuguese',
  'sub.lang.it': 'Italian',
  'sub.lang.nl': 'Dutch',
  'sub.lang.pl': 'Polish',
  'sub.lang.ru': 'Russian',
  'sub.lang.ar': 'Arabic',
  'sub.lang.ja': 'Japanese',
  'sub.lang.zh': 'Chinese',

  'sub.custom.label': 'Custom wordlist',
  'sub.custom.placeholder': 'api\nbilling\ndev.api',
  'sub.custom.hint': 'Your own names, one per line or separated by commas / spaces (dev.api tries a deeper name). They are tried first. Kept in this browser tab only (session storage) and gone when the tab closes; never uploaded.',
  'sub.custom.upload': 'Load .txt',
  'sub.custom.uploadLabel': 'Adds the names of a .txt file — read in your browser, never uploaded',
  'sub.custom.clear': 'Clear',
  'sub.custom.empty': 'No custom names.',
  'sub.custom.count': { one: '{count} name accepted', other: '{count} names accepted' },
  'sub.custom.rejected': { one: '{count} rejected: {list}', other: '{count} rejected: {list}' },
  'sub.custom.memory': 'Too long for session storage — kept until you leave this page.',
  'sub.custom.loaded': '{name} added ({size}).',
  'sub.custom.tooLarge': '{name} is too large ({size}; at most {max}).',
  'sub.custom.readError': '{name} could not be read.',

  'sub.learned.label': { zero: 'Try names found in your earlier scans first (none yet)', one: 'Try names found in your earlier scans first ({count})', other: 'Try names found in your earlier scans first ({count})' },
  'sub.learned.hint': 'Off by default. When on, each finished scan saves only the left-most labels of the resolving names under the scanned domains (api, vpn, panel …) in this browser’s local storage — never full hostnames or IP addresses. Later scans of any domain try them first (at every wordlist level except Off) as DNS lookups such as label.domain, so the DNS resolvers and that domain’s nameservers see these labels. Keep it off when you scan unrelated organisations. When off, nothing is saved or tried.',
  'sub.learned.clear': 'Forget learned names',
  'sub.learned.cleared': 'Learned names forgotten.',

  'sub.wl.usage': 'Wordlist: {level}',
  'sub.wl.packs': 'with {list}',
  'sub.wl.custom': 'your list: {found} of {tried} found',
  'sub.wl.learned': 'learned names: {found} of {tried} found',
  'sub.wl.degraded': 'fell back to {level}',
  'sub.wl.packsMissing': 'not loaded: {list}',
  'sub.opt.perm': 'Try variations of the names found (permutations)',
  'sub.opt.permHint': 'api → api2, api-dev, apitest; shop → shopapi … plus one deeper round under discovered parents. Finds the siblings a wildcard certificate hides.',
  'sub.opt.permBudget': 'Up to',
  'sub.opt.permBudgetValue': { one: '{count} variation', other: '{count} variations' },
  'sub.opt.origin': 'Look for the origin of proxied hosts',
  'sub.opt.originHint': 'DNS only: asks other public resolvers again, groups the direct IPs by network (/24) and reads SPF / MX. Never connects to the servers.',
  'sub.opt.expired': 'Include expired certificates',
  'sub.opt.expiredHint': 'Older names from crt.sh too — often retired hosts. Slower.',
  'sub.opt.extra': 'Extra hostnames',
  'sub.opt.extraPlaceholder': 'intranet.example.com\nold-shop.example.com',
  'sub.opt.extraHint': 'Names you already know about; they are always resolved and listed.',
  'sub.opt.doh': 'DNS over HTTPS: {chain}',
  'sub.opt.dohSpread': 'A bulk scan spreads its queries across these resolvers — this is not a strict failover order.',
  'sub.opt.dohChange': 'Change',
  'sub.sum.sources': { zero: 'no passive sources', one: '{count} source', other: '{count} sources' },
  'sub.sum.bf.off': 'no wordlist',
  'sub.sum.bf.small': 'small wordlist',
  'sub.sum.bf.smart': 'smart wordlist',
  'sub.sum.bf.large': 'large wordlist',
  'sub.sum.bf.huge': 'huge wordlist',
  'sub.sum.perm': 'permutations',
  'sub.sum.origin': 'origin hints',
  'sub.sum.expired': 'with expired certificates',
  'sub.sum.extra': { one: '+{count} extra name', other: '+{count} extra names' },
  'sub.sum.langs': '+{list}',
  'sub.sum.custom': { one: '{count} custom name', other: '{count} custom names' },
  'sub.sum.learned': { one: '{count} learned name', other: '{count} learned names' },

  'sub.intro.title': 'Where do the subdomains come from?',
  'sub.intro.dnsfirst.title': 'DNS first',
  'sub.intro.dnsfirst.body': 'The domain’s own records (MX, NS, SPF, SRV …), a smart wordlist and variations of every name found (api → api2, shop → shopapi) are checked over DNS. No quota, and it finds names hidden behind wildcard certificates.',
  'sub.intro.ct.title': 'Certificate Transparency logs',
  'sub.intro.ct.body': 'Every public TLS certificate is logged. crt.sh and Cert Spotter list the names in certificates issued for the domain.',
  'sub.intro.dns.title': 'Passive DNS',
  'sub.intro.dns.body': 'HackerTarget, Anubis, AlienVault OTX and ip.thc.org remember names they have seen resolving — including ones that never had a certificate.',
  'sub.intro.cf': 'Behind Cloudflare? Proxied (orange-cloud) subdomains resolve to Cloudflare’s IP addresses and public DNS never shows their origin. The scan lists origin candidates to check (the networks of the DNS-only records, resolver leaks) and the CLI command to confirm them from inside your network.',
  'sub.intro.privacy': 'Runs in your browser: only the source APIs and the DoH resolvers see the domain.',
  'sub.intro.limits': 'No outside scan can promise every name: one that lives only inside the zone and appears in no certificate, passive database or wordlist stays hidden. For a complete list, export the zone from your DNS provider.',
  'sub.intro.more': 'How it works, sources and quotas',

  'sub.busy': 'Scanning subdomains…',
  'sub.run.title': 'Scanning {domains}',
  'sub.run.titleDone': 'Subdomains of {domains}',
  'sub.run.elapsed': 'elapsed {time}',
  'sub.run.finished': 'Finished in {time} · {queries} DNS queries',
  'sub.run.finishedShort': 'Finished in {time}',
  'sub.run.cancelled': 'Cancelled after {time} — the subdomains found so far are listed.',
  'sub.run.cancelledShort': 'Cancelled',
  'sub.run.failed': 'The scan could not run',
  'sub.stage.sources': 'Sources',
  'sub.stage.mining': 'DNS records',
  'sub.stage.wildcard': 'Wildcard DNS',
  'sub.stage.bruteforce': 'Wordlist',
  'sub.stage.permutations': 'Permutations',
  'sub.stage.resolve': 'Resolve',
  'sub.stage.hints': 'Origin hints',
  'sub.stage.skipped': 'skipped',
  'sub.stage.candidates': { one: '{count} name', other: '{count} names' },
  'sub.stage.found': '+{count}',
  'sub.stage.liveHits': { one: '· {count} hit', other: '· {count} hits' },
  'sub.stage.foundTitle': { zero: 'nothing new found', one: '{count} new name found', other: '{count} new names found' },
  'sub.progress.starting': 'Starting…',
  'sub.progress.sources': 'Asking the passive sources and reading the domain’s DNS records (crt.sh can take a few minutes)',
  'sub.progress.mining': 'Reading the domain’s own DNS records (MX, NS, SPF, SRV …)',
  'sub.progress.wildcard': 'Checking for wildcard DNS at every level',
  'sub.progress.bruteforce': 'Trying wordlist names over DNS',
  'sub.progress.permutations': 'Trying variations of the names found',
  'sub.progress.resolve': 'Resolving subdomains',
  'sub.progress.hints': 'Looking for the origin of proxied hosts',
  'sub.progress.done': 'Done',
  'sub.chip.names': { zero: 'no names', one: '{count} name', other: '{count} names' },
  'sub.chip.waiting': 'waiting…',
  'sub.chip.partial': 'partial',
  'sub.srcWait': { one: '{list} still fetching (up to {seconds} s) — the DNS sweep runs meanwhile.', other: '{list} still fetching (up to {seconds} s) — the DNS sweep runs meanwhile.' },
  'sub.srcnote.title': 'Source status',
  'sub.srcnote.ok': { zero: '{name}: no names', one: '{name}: {count} name', other: '{name}: {count} names' },
  'sub.srcnote.truncated': '{name}: the first {count} of {available} names (page limit)',
  'sub.srcnote.empty': '{name}: no names for this domain',
  'sub.srcnote.partial': { one: '{name}: {count} name, incomplete — {reason}', other: '{name}: {count} names, incomplete — {reason}' },
  'sub.srcnote.limited': '{name}: {reason}',
  'sub.srcnote.unavailable': '{name} is temporarily down.',
  'sub.srcnote.timeout': '{name} did not answer in time.',
  'sub.srcnote.error': '{name} failed: {reason}',
  'sub.srcnote.dnsFound': { zero: 'Passive sources are optional here — the DNS discovery ran regardless.', one: 'Passive sources are optional here — the DNS discovery found {count} name on its own.', other: 'Passive sources are optional here — the DNS discovery found {count} names on its own.' },
  'sub.chip.err.abort': 'cancelled',
  'sub.chip.err.timeout': 'timed out',
  'sub.chip.err.rate-limit': 'rate limited',
  'sub.chip.err.http': 'HTTP error',
  'sub.chip.err.network': 'network error',
  'sub.chip.err.parse': 'bad response',
  'sub.chip.err.unknown': 'failed',
  'sub.doneToast': { one: 'Subdomain scan finished: {count} name', other: 'Subdomain scan finished: {count} names' },
  'sub.showResults': 'Show results',

  'sub.results': 'Subdomain list',
  'sub.tab.overview': 'Overview',
  'sub.tab.hosts': 'Hosts',
  'sub.tab.origins': 'Origins',
  'sub.tab.sources': 'Sources',
  'sub.stages.title': 'Stages',
  'sub.sources.none': 'This scan asked no passive source.',
  'sub.sources.quotas': 'Free limits',
  'sub.org.pending': { zero: 'Origin candidates for proxied hosts are looked for at the end of the scan and listed here.', one: '{count} proxied host so far. Its origin candidates are looked for at the end of the scan and listed here.', other: '{count} proxied hosts so far. Their origin candidates are looked for at the end of the scan and listed here.' },
  'sub.org.none': 'No host is behind a proxy that hides its origin (such as Cloudflare’s orange cloud), so there is no origin server to look for.',
  'sub.org.unfinished': 'The scan did not finish, so no origin candidates were looked for. Run it again to see them.',
  'sub.stat.found': 'Found',
  'sub.stat.foundDomains': { one: 'under {count} domain', other: 'under {count} domains' },
  'sub.stat.wildcardHidden': { one: '+{count} wildcard suspect hidden', other: '+{count} wildcard suspects hidden' },
  'sub.stat.resolving': 'Resolving',
  'sub.stat.resolvingHint': 'have an IP address',
  'sub.stat.cloudflare': 'Behind Cloudflare',
  'sub.stat.cloudflareHint': 'origin IP hidden',
  'sub.stat.cdn': 'Other CDN / platform',
  'sub.stat.cdnHint': 'served by a provider',
  'sub.stat.direct': 'Direct IP',
  'sub.stat.directHint': 'point straight at a server',
  'sub.stat.directPrivate': { one: '{count} with a private IP', other: '{count} with private IPs' },
  'sub.stat.directServers': { zero: 'none on your servers', one: '{count} on your servers', other: '{count} on your servers' },
  'sub.stat.unresolved': 'Not resolving',
  'sub.stat.unresolvedHint': 'NXDOMAIN or no address',
  'sub.stat.dangling': 'Dangling CNAME',
  'sub.stat.danglingHint': 'possible takeover risk',
  'sub.stat.filterHint': 'Show only these',

  'sub.filter.label': 'Show',
  'sub.filter.all': 'All',
  'sub.filter.resolving': 'Resolving',
  'sub.filter.cloudflare': 'Cloudflare',
  'sub.filter.direct': 'Direct',
  'sub.filter.unresolved': 'Not resolving',
  'sub.filter.wildcard': { one: 'Show {count} wildcard suspect', other: 'Show {count} wildcard suspects' },
  'sub.filter.wildcardHint': 'They resolve exactly like the wildcard DNS record of their parent domain — they may not really exist.',
  'sub.search': 'Filter by name, IP or provider…',
  'sub.searchLabel': 'Filter the subdomain list',

  'sub.caption': 'Subdomains found',
  'sub.col.name': 'Subdomain',
  'sub.col.ips': 'IP addresses',
  'sub.col.kind': 'Classification',
  'sub.col.cname': 'CNAME chain',
  'sub.col.origins': 'Found by',
  'sub.col.servers': 'Your server',
  'sub.empty': 'Subdomains appear here as they are resolved.',
  'sub.noMatch': 'No subdomain matches this filter.',
  'sub.origin.input': 'Input',
  'sub.origin.cert': 'Certificate',
  'sub.origin.bruteforce': 'Wordlist',
  'sub.origin.wordlist': 'Wordlist',
  'sub.origin.permutation': 'Permutation',
  'sub.origin.recursive': 'Deeper level',
  'sub.origin.dnsmine': '{record} record',
  'sub.origin.dnsmineTitle': 'Named in the domain’s own {record} record',
  'sub.origin.dnsTitle': 'Found by DNS discovery (wordlist, variations or a deeper level)',
  'sub.host.wildcard': 'wildcard?',
  'sub.host.resolving': 'resolving…',
  'sub.host.resolvingTitle': 'Found by a probe; the full classification arrives at the resolve stage.',
  'sub.host.lookup': 'Look up the DNS records of {name}',
  'sub.host.originHint': 'origin?',
  'sub.host.originHintTitle': 'Origin candidates found — open them in the Origins tab',
  'sub.ip.intel': 'IP Intel for {ip}',

  'sub.tech.label': 'How the names were found',
  'sub.tech.summary': 'Found through DNS: {dns} · from passive sources: {sources}',
  'sub.tech.dnsOnly': { one: '{count} of them only through DNS — none of the passive sources queried in this scan returned it.', other: '{count} of them only through DNS — none of the passive sources queried in this scan returned them.' },
  'sub.tech.dnsOnlyIncomplete': { one: '{count} of them only through DNS (some passive sources were limited or unavailable, so they may know it too).', other: '{count} of them only through DNS (some passive sources were limited or unavailable, so they may know them too).' },
  'sub.tech.mine': 'DNS records',
  'sub.tech.wordlist': 'Wordlist',
  'sub.tech.permutation': 'Permutations',
  'sub.tech.recursive': 'Deeper level',
  'sub.tech.chipTitle': { one: '{count} name found by {what}', other: '{count} names found by {what}' },

  'sub.org.title': 'Origin servers behind the proxy',
  'sub.org.lead': { one: '{count} host is proxied (orange cloud / CDN). Public DNS never publishes a proxied record’s origin — these are candidates to check, found with DNS only. Confirm them with the CLI from inside your network.', other: '{count} hosts are proxied (orange cloud / CDN). Public DNS never publishes a proxied record’s origin — these are candidates to check, found with DNS only. Confirm them with the CLI from inside your network.' },
  'sub.org.networks': 'Origin networks',
  'sub.org.networksHint': 'The DNS-only (grey-cloud) records of the same domain live here, so proxied hosts may share one of these networks (/24 for IPv4, /48 for IPv6). Each network below shows whether the command sweeps the whole /24 or only its known addresses, and why.',
  'sub.org.net.hosts': { one: '{count} DNS-only host', other: '{count} DNS-only hosts' },
  'sub.org.net.ips': { one: '{count} IP', other: '{count} IPs' },
  'sub.org.sweep.cidr': 'sweeps the whole /24',
  'sub.org.sweep.cidrTitle': 'Several hosts of yours already live in this /24, so the command scans all 256 addresses.',
  'sub.org.sweep.ips': { one: 'sweeps 1 address', other: 'sweeps {count} addresses' },
  'sub.org.sweep.ipsTitle': 'Only the known addresses are scanned (a lone host, shared provider space, or an IPv6 block), not the whole block.',
  'sub.org.shared': 'shared hosting / cloud',
  'sub.org.sharedTitle': 'This block belongs to a provider whose address space many unrelated customers share — only sweep addresses you operate.',
  'sub.org.owner.lookup': 'Look up owner',
  'sub.org.owner.lookupFor': 'Look up the owner of {cidr} (asks RIPEstat)',
  'sub.org.owner.looking': 'Looking up…',
  'sub.org.owner.as': 'AS{asn} {holder}',
  'sub.org.owner.error': 'owner lookup failed',
  'sub.org.warnShared': 'Some of these networks are shared hosting / cloud space. Only sweep addresses you operate or are authorised to test.',
  'sub.org.exclude.label': 'Exclude addresses',
  'sub.org.exclude.placeholder': '203.0.113.9, 198.51.100.0/28',
  'sub.org.exclude.hint': 'IPs or CIDRs the command must never probe (a mail server, a shared address). Added as --exclude; a fully-covered network drops out of the sweep.',
  'sub.org.exclude.invalid': { one: '{count} entry is not a valid IP or CIDR: {list}', other: '{count} entries are not valid IPs or CIDRs: {list}' },
  'sub.org.exclude.unused': { one: 'Not in any swept network: {list}', other: 'Not in any swept network: {list}' },
  'sub.org.exclude.applied': { one: '{count} network dropped by the exclusions.', other: '{count} networks dropped by the exclusions.' },
  'sub.org.siblingSuggest': 'A company with several domains? Scan them together — the same name on a sibling domain can point at the real server.',
  'sub.org.cand.sibling': 'Sibling domain',
  'sub.org.cand.siblingTitle': 'The same name is a DNS-only host on a sister domain scanned with this one — often the real origin.',
  'sub.org.cand.siblingVia': 'same name as {sibling}',
  'sub.org.cand.network': 'Same network',
  'sub.org.cand.networkTitle': 'A /24 or /48 where the domain’s DNS-only records live; the origin may sit here too.',
  'sub.org.noNetworks': 'No DNS-only records with a public IP were found, so there is no network to sweep yet. Add known names under “Extra hostnames” or try the Large wordlist.',
  'sub.org.leaks': 'Direct answers for proxied names',
  'sub.org.leaksHint': 'Another public resolver answered these proxied names with a non-CDN address — the strongest origin evidence DNS can give.',
  'sub.org.leakVia': 'answered by {resolver}',
  'sub.org.history': 'Seen before the proxy',
  'sub.org.historyHint': 'Historical DNS remembers these addresses for the proxied names.',
  'sub.org.historyVia': 'seen by {source}',
  'sub.org.historyViaDate': 'seen by {source} · last {date}',
  'sub.org.cli': 'Confirm from inside your network',
  'sub.org.cliHint': 'The CLI connects to every target of the command below (a whole /24, or only the known addresses — each network above says which) and asks for each proxied name via TLS SNI; the server that answers with a matching certificate is the origin. Run it on a machine inside the network that hosts the servers (Python 3.8+, no dependencies). Sweep only networks you operate or are authorised to test — some may belong to a hosting, mail or SaaS provider.',
  'sub.org.cliNone': 'The CLI sweeps networks or IP lists: once an origin network or candidate IP is known it confirms the origin via TLS SNI from inside your network.',
  'sub.org.cliDownload': 'Download ssl_origin_scan.py',
  'sub.org.namesFile': 'Too many names to fit on one command line: the command reads the {count} proxied names from {file}. Download it and save it next to ssl_origin_scan.py.',
  'sub.org.namesFileDownload': 'Download {file}',
  'sub.org.targetsFile': 'Too many targets to fit on one command line: the command reads the {count} targets from {file}. Download it and save it next to ssl_origin_scan.py.',
  'sub.org.overLength': 'This command is {count} characters long, more than some shells accept (Windows especially): list fewer exclusions.',
  'sub.org.command': 'Command',
  'sub.org.shell': 'Shell',
  'sub.org.shell.posix': 'Linux / macOS',
  'sub.org.shell.powershell': 'Windows PowerShell',
  'sub.org.shellTitle.posix': 'For bash, zsh or sh (python3)',
  'sub.org.shellTitle.powershell': 'For PowerShell on Windows (python)',
  'sub.org.dropped': { one: '{count} entry was left out of the command because it is not a valid IP, network or hostname.', other: '{count} entries were left out of the command because they are not valid IPs, networks or hostnames.' },
  'sub.reason.leak': '{host} answered by {resolver}',
  'sub.reason.history': '{host} · seen by {source}',
  'sub.reason.historyDate': '{host} · seen by {source} · last {date}',
  'sub.org.hosts': { one: 'Proxied host ({count})', other: 'Proxied hosts ({count})' },
  'sub.org.col.host': 'Proxied host',
  'sub.org.col.edge': 'Proxy / edge',
  'sub.org.col.candidates': 'Origin candidates',
  'sub.org.candNetworks': 'same network: {list}',
  'sub.org.candNone': 'no candidate yet',
  'sub.org.other': 'Other origin hints',
  'sub.org.otherHint': 'Addresses from SPF / MX records and the non-proxied siblings of the same domain.',
  'sub.org.col.ip': 'IP address',
  'sub.org.col.evidence': 'Evidence',
  'sub.org.col.about': 'About',
  'sub.hint.resolver-leak': 'Resolver leak',
  'sub.hint.resolver-leak.title': 'Another public resolver answered the proxied name with this non-CDN address',
  'sub.hint.history': 'History',
  'sub.hint.history.title': 'Seen in historical DNS (possibly before the proxy was enabled)',
  'sub.hint.sibling-domain': 'Sibling domain',
  'sub.hint.sibling-domain.title': 'The same name is a DNS-only host on a sister domain scanned with this one',
  'sub.hint.direct-sibling': 'Sibling',
  'sub.hint.direct-sibling.title': 'Public IP of a non-proxied name of the same domain',
  'sub.hint.spf': 'SPF',
  'sub.hint.spf.title': 'Allowed to send mail for the domain (SPF record)',
  'sub.hint.mx': 'MX',
  'sub.hint.mx.title': 'Mail server (MX) of the domain',

  'sub.act.label': 'Copy or download the list',
  'sub.act.copy': 'Copy all subdomains',
  'sub.act.resolvingOnly': 'Resolving only',
  'sub.act.names': 'names.txt',

  'sub.sum.noneFound': 'No subdomains found. Check the spelling — or try a larger wordlist.',
  'sub.sum.sourcesFailed': { one: '{count} passive source did not answer (see the Sources tab). The DNS discovery does not depend on it, but a few names may be missing.', other: '{count} passive sources did not answer (see the Sources tab). The DNS discovery does not depend on them, but a few names may be missing.' },
  'sub.sum.sourcesLink': 'Show the source status',
  'sub.sum.wildcard': 'Wildcard DNS on {list}: every name there resolves, so look-alike names are hidden as “wildcard?”.',
  'sub.sum.cloudflare': { one: '{count} subdomain is behind Cloudflare: the IPs shown belong to Cloudflare and the origin server is hidden.', other: '{count} subdomains are behind Cloudflare: the IPs shown belong to Cloudflare and the origin servers are hidden.' },
  'sub.sum.originLink': 'See the origin candidates',
  'sub.sum.dangling': { one: '{count} dangling CNAME — possible subdomain takeover.', other: '{count} dangling CNAMEs — possible subdomain takeover.' },
  'sub.warn.INVALID_DOMAIN': 'Invalid domain skipped: {detail}',
  'sub.warn.INVALID_NAME': 'Invalid hostname skipped: {detail}',
  'sub.warn.PUBLIC_SUFFIX': '{detail} is a public suffix and was skipped.',
  'sub.warn.TRUNCATED': 'Too many names — only the first ones were resolved ({detail}).',
  'sub.warn.BRUTEFORCE_TRUNCATED': 'The wordlist was cut at {detail} candidates.',
  'sub.warn.RECURSIVE_TRUNCATED': 'The deeper round was cut at {detail} candidates.',
  'sub.warn.WILDCARD_PARENTS_TRUNCATED': 'Wildcard DNS was checked for the first {detail} parent names only.',
  'sub.warn.WORDLIST_DEGRADED': 'The chosen wordlist could not be loaded, so a smaller one was used ({detail}).',
  'sub.warn.DNS_UNREACHABLE': 'The public DNS resolvers stopped answering ({detail} guesses in a row failed), so the wordlist and variations were stopped early. Check your connection, or whether DNS-over-HTTPS is blocked on this network.',
  'sub.warn.ZONE_OUT_OF_SCOPE': '{detail} names from your zone file are outside the scanned domain and were skipped.',

  'sub.origin.zone': 'Zone file',
  'sub.origin.zoneTitle': 'Named in the zone file you imported (Zone File)',
  'sub.tech.zone': 'Zone file',
  'sub.hint.zone': 'Zone file',
  'sub.hint.zone.title': 'Your zone file names this address as the real server behind the proxied name',
  'sub.reason.zone': '{host} · from your zone file',
  'sub.zone.chip': { one: 'Zone file loaded: {count} name, {origins} exact origins', other: 'Zone file loaded: {count} names, {origins} exact origins' },
  'sub.zone.mode': 'How this scan uses the zone file',
  'sub.zone.mode.exact': 'Scan exactly these names',
  'sub.zone.mode.exactTitle': 'Only the names in your zone file: no passive sources, wordlist or permutations, so no quota is used.',
  'sub.zone.mode.discover': 'Include in discovery',
  'sub.zone.mode.discoverTitle': 'Add the zone’s names to a normal discovery scan as starting names.',
  'sub.zone.mode.off': 'Leave out',
  'sub.zone.mode.offTitle': 'Scan without the zone file (it stays loaded in this tab).',
  'sub.zone.note.exact': 'Exact mode: only the names from your zone file are resolved; nothing is guessed and no passive source is asked.',
  'sub.zone.note.discover': 'The zone’s names are added as starting names; the passive sources, wordlist and variations run as usual.',
  'sub.zone.note.off': 'This scan ignores the zone file.',
  'sub.zone.privacy': 'Each name is sent to your DNS resolvers as a normal lookup. Names found only in your zone file are not added to learned names. Exports of this scan include the zone’s origin addresses.',
  'sub.zone.open': 'Open Zone File',
  'sub.zone.exact': 'Exact mode: only the names from your zone file; no passive sources, wordlist or permutations for this scan.',
  'sub.zone.discover': 'Zone file included: its names were added to this scan as starting names.',
  'sub.zone.busy': 'A scan of {running} is still running. The scan of your zone file ({domain}) starts when it ends.',
  'sub.zone.busy.cancel': 'Cancel it and scan the zone',
  'sub.zone.busy.dismiss': 'Don’t start',
  'sub.org.zone': 'Exact origins from your zone file',
  'sub.org.zoneHint': 'Your zone file names the real server behind these proxied names. The command below probes these exact addresses and never widens them to a /24.',
  'sub.org.ptr': 'Reverse DNS sweep',
  'sub.org.ptrIps': { one: 'Reverse DNS of its address', other: 'Reverse DNS of its {count} addresses' },
  'sub.org.ptrIpsTitle': 'Shared cloud / hosting space: the rest of this block belongs to other customers, so only the addresses your names resolve to are looked up (opens the Reverse DNS view, you press Sweep)',
  'sub.org.ptrTitle': 'Look up the reverse DNS (PTR) of every address in {cidr}: other hosts of yours often live next to the origin (opens the Reverse DNS view, you press Sweep)',
  'sub.handoff.chip': { one: '{count} name from the reverse DNS sweep of {label}', other: '{count} names from the reverse DNS sweep of {label}' },
  'sub.handoff.mode': 'How this scan uses these names',
  'sub.handoff.mode.exact': 'Scan exactly these names',
  'sub.handoff.mode.exactTitle': 'Only these names and the domains in the box: no passive sources, wordlist or permutations, so no quota is used.',
  'sub.handoff.mode.discover': 'Include in discovery',
  'sub.handoff.mode.discoverTitle': 'Add these names to a normal discovery scan as starting names.',
  'sub.handoff.mode.off': 'Leave out',
  'sub.handoff.mode.offTitle': 'Scan without these names (they stay here until you remove them).',
  'sub.handoff.note.exact': 'Exact mode: only these names and the domains in the box are resolved; nothing is guessed and no passive source is asked.',
  'sub.handoff.note.discover': 'The names are added as starting names; the passive sources, wordlist and variations run as usual.',
  'sub.handoff.note.off': 'This scan ignores these names.',
  'sub.handoff.open': 'Back to Reverse DNS',
  'sub.handoff.remove': 'Remove these names',
  'sub.handoff.elsewhere': 'Not used for the domains in the box: these names are under {domains}. Type one of those to scan them.',
  'sub.handoff.partial': { one: '{count} of {total} names is under the domains in the box: this scan uses only that one.', other: '{count} of {total} names are under the domains in the box: this scan uses only those.' },
  'sub.handoff.exact': 'Exact mode: only the names from the reverse DNS sweep; no passive sources, wordlist or permutations for this scan.',
  'sub.handoff.discover': 'Names from the reverse DNS sweep were added to this scan as starting names.',
  'sub.plan.handoffExact': { one: 'Exact mode: only the {count} name from the reverse DNS sweep (and the domains in the box) is resolved; the wordlist, variations and passive sources are not used for this scan.', other: 'Exact mode: only the {count} names from the reverse DNS sweep (and the domains in the box) are resolved; the wordlist, variations and passive sources are not used for this scan.' },

  'sub.cta.title': 'Which servers need the certificate for this domain?',
  'sub.cta.body': 'SSL Targets matches these names to your servers, checks certificate coverage and finds origin servers hidden behind Cloudflare.',
  'sub.cta.button': 'Open in SSL Targets'
});

registerStrings('tr', {
  'sub.hero.title': 'Hangi alan adını tarayalım?',
  'sub.hero.desc': 'Önce DNS: alan adının kendi kayıtları, akıllı kelime listesi ve bulunan her adın varyasyonları DNS-over-HTTPS ile denenir; Certificate Transparency ve pasif DNS boşlukları doldurur — hepsi tarayıcınızda; tarayıcınız alan adının sunucularına hiç bağlanmaz.',
  'sub.input.placeholder': 'ornek.com.tr',
  'sub.input.hint': 'Alan adı, URL ya da bir subdomain yazın. Birden fazla alan adını boşluk veya virgülle ayırın.',
  'sub.run': 'Tara',
  'sub.cancel': 'İptal et',
  'sub.link.prompt': 'Bu bağlantı {domains} için bir tarama açar. Siz tıklayınca başlar — pasif kaynaklar ve genel DNS çözümleyicileri tarayıcınızdan sorgulanır.',
  'sub.link.start': 'Taramayı başlat',
  'sub.examples': 'Deneyin:',
  'sub.scope': 'Yalnızca {name} altındaki adlar listelenir.',
  'sub.scopeAll': '{domain} alan adının tamamını tara',
  'sub.err.required': 'Bir alan adı girin, ör. ornek.com.tr.',
  'sub.err.invalid': 'Geçerli bir alan adı değil: {list}',
  'sub.err.ip': '{list} bir IP adresi — IP adresleri için IP Bilgisi aracını kullanın ya da buraya bir alan adı girin.',
  'sub.err.publicSuffix': '{list} bir genel sonek — ornek.com.tr gibi kayıtlı bir alan adı girin.',

  'sub.opt.wordlist': 'Adları DNS ile tahmin et ({size} liste · {count} ad)',
  'sub.opt.wordlistPacks': 'Adları DNS ile tahmin et ({size} liste · {count} ad {packs})',
  'sub.bf.small': 'küçük',
  'sub.bf.smart': 'akıllı',
  'sub.bf.large': 'büyük',
  'sub.bf.huge': 'çok büyük',
  'sub.opt.advanced': 'Gelişmiş seçenekler',
  'sub.opt.sources': 'Pasif kaynaklar',
  'sub.opt.sourcesHint': 'Doğrudan tarayıcınızdan sorgulanır. Ücretsiz katmanların sınırları vardır; başarısız bir kaynak taramayı durdurmaz — DNS keşfi onlara bağlı değildir.',
  'sub.src.crtsh': 'Certificate Transparency araması. Ücretsiz; büyük alan adlarında yavaş (bir dakika veya daha uzun).',
  'sub.src.certspotter': 'Certificate Transparency API’si · IP başına saatte yaklaşık 10 istek; yalnızca süresi dolmamış sertifikalar.',
  'sub.src.hackertarget': 'Güncel IP’leriyle host araması · IP başına günde yaklaşık 50 istek.',
  'sub.src.anubis': 'Subdomain veritabanı · ücretsiz, anahtar gerekmez.',
  'sub.src.otx': 'Pasif DNS · anonim erişim sık sık hız sınırına takılır.',
  'sub.src.thc': 'Son görülme tarihleriyle subdomain veritabanı · ücretsiz, anahtar gerekmez; alan adı başına en fazla 1.000 ad.',
  'sub.opt.bruteforce': 'Kelime listesi (adları DNS ile tahmin et)',
  'sub.opt.bf.off': 'Kapalı',
  'sub.opt.bf.offHint': 'Yalnızca alan adının kendi DNS kayıtları ve pasif kaynaklar.',
  'sub.opt.bf.small': 'Küçük · {count} ad',
  'sub.opt.bf.smallHint': 'Yalnızca en yaygın adlar · alan adı başına {time}.',
  'sub.opt.bf.smart': 'Akıllı · {count} ad',
  'sub.opt.bf.smartHint': 'Önerilen. Açık subdomain listelerinden sıralanmış, dünyada en yaygın adlar · alan adı başına {time}.',
  'sub.opt.bf.large': 'Büyük · {count} ad',
  'sub.opt.bf.largeHint': 'Aynı sıralamanın çok daha uzun kuyruğu; tarama başlarken bu siteden yüklenir ({size}) · alan adı başına {time}.',
  'sub.opt.bf.huge': 'Çok büyük · {count} ad',
  'sub.opt.bf.hugeHint': 'Sıralamanın tamamı; tarama başlarken bu siteden yüklenir ({size}) · dakikalar sürer: alan adı başına {time}. Sahibi olduğunuz ve ayrıntılı haritalamak istediğiniz bir alan adı için.',
  'sub.opt.bf.recommended': 'önerilen',
  'sub.opt.bfHint': 'Her ad, genel DoH çözümleyicilerine tek bir A sorgusudur — tarayıcınız alan adının web sunucularına hiç bağlanmaz. Çözümleyicinin önbelleğinde olmayan adlar alan adının yetkili ad sunucularına iletilir; bu yüzden kendi ad sunucusunu işleten bir alan adı bu yoğunluğu görür. Wildcard DNS her seviyede tespit edildiği için sahte eşleşmeler elenir. Süreler kabacadır.',
  'sub.opt.bf.counting': '…',
  'sub.est.seconds': '≈ {n} sn',
  'sub.est.minutes': '≈ {count} dk',
  'sub.plan.none': 'Kelime listesinin kaç ad deneyeceğini görmek için yukarıya bir alan adı yazın.',
  'sub.plan.off': 'Ad tahmin edilmez: yalnızca alan adının kendi DNS kayıtları ve pasif kaynaklar.',
  'sub.plan.line': '{domains} için ≈ {queries} DNS sorgusu ({parts}) · {time}',
  'sub.plan.queriesRange': '{min}–{max}',
  'sub.plan.zoneExact': 'Kesin mod: yalnızca zone dosyanızdaki {count} ad çözümlenir; bu taramada kelime listesi, varyasyonlar ve pasif kaynaklar kullanılmaz.',
  'sub.plan.handoffExact': 'Kesin mod: yalnızca ters DNS taramasından gelen {count} ad (ve kutudaki alan adları) çözümlenir; bu taramada kelime listesi, varyasyonlar ve pasif kaynaklar kullanılmaz.',
  'sub.plan.perDomain': 'alan adı başına: {parts}',
  'sub.plan.domains': '{count} alan adı',
  'sub.plan.level': '{count} {level}',
  'sub.plan.pack': '+{count} {language}',
  'sub.plan.custom': '+{count} sizin',
  'sub.plan.learned': '+{count} öğrenilen',
  'sub.plan.capped': 'alan adı başına {count} ile sınırlı',

  'sub.lang.legend': 'Diller / pazarlar',
  'sub.lang.hint': 'Alan adının pazarına ait yerel dildeki adları (ör. Türkçe destek, Almanca kunden) küresel listeye ekler — Akıllı seviyeden itibaren.',
  'sub.lang.auto': 'Alan adı uzantısına göre seç',
  'sub.lang.autoPick': 'Otomatik: {list}',
  'sub.lang.autoItem': '{language} ({suffix})',
  'sub.lang.autoNone': 'Otomatik: yok — {suffix} için pazar paketi yok, küresel liste kullanılır',
  'sub.lang.autoEmpty': 'Otomatik: alan adı uzantısından seçilir (ör. .de → Almanca, .com.tr → Türkçe)',
  'sub.lang.manualNone': 'Hiçbiri: yalnızca küresel liste',
  'sub.lang.manual': 'Seçilen: {list}',
  'sub.lang.option': '{language} · {count}',
  'sub.lang.tr': 'Türkçe',
  'sub.lang.de': 'Almanca',
  'sub.lang.fr': 'Fransızca',
  'sub.lang.es': 'İspanyolca',
  'sub.lang.pt': 'Portekizce',
  'sub.lang.it': 'İtalyanca',
  'sub.lang.nl': 'Felemenkçe',
  'sub.lang.pl': 'Lehçe',
  'sub.lang.ru': 'Rusça',
  'sub.lang.ar': 'Arapça',
  'sub.lang.ja': 'Japonca',
  'sub.lang.zh': 'Çince',

  'sub.custom.label': 'Özel kelime listesi',
  'sub.custom.placeholder': 'api\nfatura\ndev.api',
  'sub.custom.hint': 'Kendi adlarınız; her satıra bir tane ya da virgül / boşlukla ayrılmış (dev.api bir alt seviyeyi dener). Önce bunlar denenir. Yalnızca bu tarayıcı sekmesinde tutulur (oturum deposu), sekme kapanınca silinir; hiçbir yere gönderilmez.',
  'sub.custom.upload': '.txt ekle',
  'sub.custom.uploadLabel': 'Bir .txt dosyasındaki adları ekler — tarayıcınızda okunur, hiçbir yere gönderilmez',
  'sub.custom.clear': 'Temizle',
  'sub.custom.empty': 'Özel ad yok.',
  'sub.custom.count': '{count} ad kabul edildi',
  'sub.custom.rejected': '{count} tanesi reddedildi: {list}',
  'sub.custom.memory': 'Oturum deposu için fazla uzun — bu sayfadan ayrılana kadar tutulur.',
  'sub.custom.loaded': '{name} eklendi ({size}).',
  'sub.custom.tooLarge': '{name} çok büyük ({size}; en fazla {max}).',
  'sub.custom.readError': '{name} okunamadı.',

  'sub.learned.label': { zero: 'Önceki taramalarınızda bulunan adları önce dene (henüz yok)', other: 'Önceki taramalarınızda bulunan adları önce dene ({count})' },
  'sub.learned.hint': 'Varsayılan olarak kapalıdır. Açıkken her tamamlanan tarama, taranan alan adlarının altında çözümlenen adların yalnızca en soldaki etiketlerini (api, vpn, panel …) bu tarayıcının yerel deposuna kaydeder — asla tam host adlarını ya da IP adreslerini değil. Sonraki taramalar, hangi alan adı olursa olsun, bunları önce (Kapalı dışındaki her kelime listesi seviyesinde) etiket.alanadı biçiminde DNS sorgusu olarak dener; yani DNS çözümleyicileri ve o alan adının ad sunucuları bu etiketleri görür. Birbiriyle ilgisiz kurumları tarıyorsanız kapalı bırakın. Kapalıyken hiçbir şey kaydedilmez ya da denenmez.',
  'sub.learned.clear': 'Öğrenilen adları unut',
  'sub.learned.cleared': 'Öğrenilen adlar silindi.',

  'sub.wl.usage': 'Kelime listesi: {level}',
  'sub.wl.packs': '{list} ile',
  'sub.wl.custom': 'sizin listeniz: {tried} addan {found} tanesi bulundu',
  'sub.wl.learned': 'öğrenilen adlar: {tried} addan {found} tanesi bulundu',
  'sub.wl.degraded': '{level} listesine düşüldü',
  'sub.wl.packsMissing': 'yüklenemedi: {list}',
  'sub.opt.perm': 'Bulunan adların varyasyonlarını dene (permütasyon)',
  'sub.opt.permHint': 'api → api2, api-dev, apitest; shop → shopapi … ayrıca bulunan üst adların altında bir seviye daha. Wildcard sertifikanın gizlediği kardeş adları bulur.',
  'sub.opt.permBudget': 'En fazla',
  'sub.opt.permBudgetValue': '{count} varyasyon',
  'sub.opt.origin': 'Proxy’lenen host’ların asıl sunucusunu ara',
  'sub.opt.originHint': 'Yalnızca DNS: diğer genel çözümleyicilere tekrar sorar, doğrudan IP’leri ağa (/24) göre gruplar, SPF / MX kayıtlarını okur. Sunuculara asla bağlanmaz.',
  'sub.opt.expired': 'Süresi dolmuş sertifikaları da dahil et',
  'sub.opt.expiredHint': 'crt.sh’teki eski adları da getirir — çoğu zaman kullanımdan kalkmış host’lar. Daha yavaştır.',
  'sub.opt.extra': 'Ek host adları',
  'sub.opt.extraPlaceholder': 'intranet.ornek.com.tr\neski-magaza.ornek.com.tr',
  'sub.opt.extraHint': 'Zaten bildiğiniz adlar; her zaman çözümlenir ve listelenir.',
  'sub.opt.doh': 'DNS over HTTPS: {chain}',
  'sub.opt.dohSpread': 'Toplu tarama sorgularını bu çözümleyicilere dağıtır — kesin bir yedekleme (failover) sırası değildir.',
  'sub.opt.dohChange': 'Değiştir',
  'sub.sum.sources': { zero: 'pasif kaynak yok', other: '{count} kaynak' },
  'sub.sum.bf.off': 'kelime listesi yok',
  'sub.sum.bf.small': 'küçük kelime listesi',
  'sub.sum.bf.smart': 'akıllı kelime listesi',
  'sub.sum.bf.large': 'büyük kelime listesi',
  'sub.sum.bf.huge': 'dev kelime listesi',
  'sub.sum.perm': 'varyasyonlar',
  'sub.sum.origin': 'asıl sunucu ipuçları',
  'sub.sum.expired': 'süresi dolmuş sertifikalar dahil',
  'sub.sum.extra': '+{count} ek ad',
  'sub.sum.langs': '+{list}',
  'sub.sum.custom': '{count} özel ad',
  'sub.sum.learned': '{count} öğrenilen ad',

  'sub.intro.title': 'Subdomain’ler nereden geliyor?',
  'sub.intro.dnsfirst.title': 'Önce DNS',
  'sub.intro.dnsfirst.body': 'Alan adının kendi kayıtları (MX, NS, SPF, SRV …), akıllı kelime listesi ve bulunan her adın varyasyonları (api → api2, shop → shopapi) DNS ile denenir. Kota yok; wildcard sertifikanın gizlediği adları da bulur.',
  'sub.intro.ct.title': 'Certificate Transparency kayıtları',
  'sub.intro.ct.body': 'Her genel TLS sertifikası kayda geçer. crt.sh ve Cert Spotter, alan adı için verilmiş sertifikalardaki adları listeler.',
  'sub.intro.dns.title': 'Pasif DNS',
  'sub.intro.dns.body': 'HackerTarget, Anubis, AlienVault OTX ve ip.thc.org daha önce çözümlendiğini gördükleri adları hatırlar — hiç sertifikası olmayanlar dahil.',
  'sub.intro.cf': 'Cloudflare arkasında mı? Proxy’lenen (turuncu bulut) subdomain’ler Cloudflare’in IP adreslerine çözümlenir; genel DNS asıl sunucuyu hiçbir zaman göstermez. Tarama kontrol edilecek asıl sunucu adaylarını (DNS-only kayıtların ağları, çözümleyici sızıntıları) ve bunları ağınızın içinden doğrulayacak CLI komutunu listeler.',
  'sub.intro.privacy': 'Tarayıcınızda çalışır: alan adını yalnızca kaynak API’leri ve DoH çözümleyicileri görür.',
  'sub.intro.limits': 'Hiçbir dış tarama her adı garanti edemez: yalnızca bölge (zone) içinde yaşayan ve hiçbir sertifikada, pasif veritabanında ya da kelime listesinde geçmeyen bir ad gizli kalır. Eksiksiz liste için bölgeyi DNS sağlayıcınızdan dışa aktarın.',
  'sub.intro.more': 'Nasıl çalışır, kaynaklar ve kotalar',

  'sub.busy': 'Subdomain’ler taranıyor…',
  'sub.run.title': '{domains} taranıyor',
  'sub.run.titleDone': '{domains} için bulunan subdomain’ler',
  'sub.run.elapsed': 'geçen süre {time}',
  'sub.run.finished': '{time} içinde tamamlandı · {queries} DNS sorgusu',
  'sub.run.finishedShort': '{time} içinde tamamlandı',
  'sub.run.cancelled': '{time} sonra iptal edildi — o ana kadar bulunan subdomain’ler listelendi.',
  'sub.run.cancelledShort': 'İptal edildi',
  'sub.run.failed': 'Tarama çalıştırılamadı',
  'sub.stage.sources': 'Kaynaklar',
  'sub.stage.mining': 'DNS kayıtları',
  'sub.stage.wildcard': 'Wildcard DNS',
  'sub.stage.bruteforce': 'Kelime listesi',
  'sub.stage.permutations': 'Varyasyonlar',
  'sub.stage.resolve': 'Çözümleme',
  'sub.stage.hints': 'Asıl sunucu ipuçları',
  'sub.stage.skipped': 'atlandı',
  'sub.stage.candidates': '{count} ad',
  'sub.stage.found': '+{count}',
  'sub.stage.liveHits': { one: '· {count} bulundu', other: '· {count} bulundu' },
  'sub.stage.foundTitle': { zero: 'yeni ad bulunamadı', other: '{count} yeni ad bulundu' },
  'sub.progress.starting': 'Başlatılıyor…',
  'sub.progress.sources': 'Pasif kaynaklara soruluyor ve alan adının DNS kayıtları okunuyor (crt.sh birkaç dakika sürebilir)',
  'sub.progress.mining': 'Alan adının kendi DNS kayıtları okunuyor (MX, NS, SPF, SRV …)',
  'sub.progress.wildcard': 'Her seviyede wildcard DNS kontrol ediliyor',
  'sub.progress.bruteforce': 'Kelime listesindeki adlar DNS ile deneniyor',
  'sub.progress.permutations': 'Bulunan adların varyasyonları deneniyor',
  'sub.progress.resolve': 'Subdomain’ler çözümleniyor',
  'sub.progress.hints': 'Proxy’lenen host’ların asıl sunucusu aranıyor',
  'sub.progress.done': 'Tamamlandı',
  'sub.chip.names': { zero: 'ad yok', other: '{count} ad' },
  'sub.chip.waiting': 'bekleniyor…',
  'sub.chip.partial': 'eksik',
  'sub.srcWait': { one: '{list} bekleniyor (en fazla {seconds} sn) — DNS taraması bu sırada sürüyor.', other: '{list} bekleniyor (en fazla {seconds} sn) — DNS taraması bu sırada sürüyor.' },
  'sub.srcnote.title': 'Kaynak durumu',
  'sub.srcnote.ok': { zero: '{name}: ad yok', other: '{name}: {count} ad' },
  'sub.srcnote.truncated': '{name}: {available} addan ilk {count} tanesi (sayfa sınırı)',
  'sub.srcnote.empty': '{name}: bu alan adı için ad yok',
  'sub.srcnote.partial': '{name}: {count} ad, eksik — {reason}',
  'sub.srcnote.limited': '{name}: {reason}',
  'sub.srcnote.unavailable': '{name} geçici olarak çalışmıyor.',
  'sub.srcnote.timeout': '{name} zamanında yanıt vermedi.',
  'sub.srcnote.error': '{name} başarısız oldu: {reason}',
  'sub.srcnote.dnsFound': { zero: 'Pasif kaynaklar burada isteğe bağlı — DNS keşfi yine de çalıştı.', other: 'Pasif kaynaklar burada isteğe bağlı — DNS keşfi kendi başına {count} ad buldu.' },
  'sub.chip.err.abort': 'iptal edildi',
  'sub.chip.err.timeout': 'zaman aşımı',
  'sub.chip.err.rate-limit': 'hız sınırı',
  'sub.chip.err.http': 'HTTP hatası',
  'sub.chip.err.network': 'ağ hatası',
  'sub.chip.err.parse': 'hatalı yanıt',
  'sub.chip.err.unknown': 'başarısız',
  'sub.doneToast': 'Subdomain taraması bitti: {count} ad',
  'sub.showResults': 'Sonuçları göster',

  'sub.results': 'Subdomain listesi',
  'sub.tab.overview': 'Genel bakış',
  'sub.tab.hosts': 'Host’lar',
  'sub.tab.origins': 'Origin’ler',
  'sub.tab.sources': 'Kaynaklar',
  'sub.stages.title': 'Aşamalar',
  'sub.sources.none': 'Bu tarama hiçbir pasif kaynağa sormadı.',
  'sub.sources.quotas': 'Ücretsiz kullanım sınırları',
  'sub.org.pending': { zero: 'Proxy’lenen host’ların asıl sunucu adayları taramanın sonunda aranır ve burada listelenir.', other: 'Şu ana kadar {count} proxy’lenen host var. Asıl sunucu adayları taramanın sonunda aranır ve burada listelenir.' },
  'sub.org.none': 'Asıl sunucusunu gizleyen bir proxy’nin (Cloudflare’in turuncu bulutu gibi) arkasında hiçbir host yok; bu yüzden aranacak bir asıl sunucu yok.',
  'sub.org.unfinished': 'Tarama bitmediği için asıl sunucu adayları aranmadı. Görmek için taramayı yeniden çalıştırın.',
  'sub.stat.found': 'Bulunan',
  'sub.stat.foundDomains': '{count} alan adı altında',
  'sub.stat.wildcardHidden': '+{count} wildcard şüphelisi gizli',
  'sub.stat.resolving': 'Çözümlenen',
  'sub.stat.resolvingHint': 'IP adresi olanlar',
  'sub.stat.cloudflare': 'Cloudflare arkasında',
  'sub.stat.cloudflareHint': 'asıl sunucu IP’si gizli',
  'sub.stat.cdn': 'Diğer CDN / platform',
  'sub.stat.cdnHint': 'bir sağlayıcı üzerinden sunuluyor',
  'sub.stat.direct': 'Doğrudan IP',
  'sub.stat.directHint': 'doğrudan bir sunucuya gidiyor',
  'sub.stat.directPrivate': '{count} tanesi özel IP’li',
  'sub.stat.directServers': { zero: 'sunucularınızda eşleşme yok', other: '{count} tanesi sunucularınızda' },
  'sub.stat.unresolved': 'Çözümlenmeyen',
  'sub.stat.unresolvedHint': 'NXDOMAIN ya da adres yok',
  'sub.stat.dangling': 'Sahipsiz CNAME',
  'sub.stat.danglingHint': 'olası ele geçirme riski',
  'sub.stat.filterHint': 'Yalnızca bunları göster',

  'sub.filter.label': 'Göster',
  'sub.filter.all': 'Tümü',
  'sub.filter.resolving': 'Çözümlenen',
  'sub.filter.cloudflare': 'Cloudflare',
  'sub.filter.direct': 'Doğrudan',
  'sub.filter.unresolved': 'Çözümlenmeyen',
  'sub.filter.wildcard': '{count} wildcard şüphelisini göster',
  'sub.filter.wildcardHint': 'Üst alan adının wildcard DNS kaydıyla birebir aynı çözümleniyorlar — gerçekte var olmayabilirler.',
  'sub.search': 'Ad, IP veya sağlayıcıya göre filtrele…',
  'sub.searchLabel': 'Subdomain listesini filtrele',

  'sub.caption': 'Bulunan subdomain’ler',
  'sub.col.name': 'Subdomain',
  'sub.col.ips': 'IP adresleri',
  'sub.col.kind': 'Sınıflandırma',
  'sub.col.cname': 'CNAME zinciri',
  'sub.col.origins': 'Bulan',
  'sub.col.servers': 'Sunucunuz',
  'sub.empty': 'Subdomain’ler çözümlendikçe burada görünür.',
  'sub.noMatch': 'Bu filtreyle eşleşen subdomain yok.',
  'sub.origin.input': 'Girdi',
  'sub.origin.cert': 'Sertifika',
  'sub.origin.bruteforce': 'Kelime listesi',
  'sub.origin.wordlist': 'Kelime listesi',
  'sub.origin.permutation': 'Varyasyon',
  'sub.origin.recursive': 'Alt seviye',
  'sub.origin.dnsmine': '{record} kaydı',
  'sub.origin.dnsmineTitle': 'Alan adının kendi {record} kaydında geçiyor',
  'sub.origin.dnsTitle': 'DNS keşfiyle bulundu (kelime listesi, varyasyon ya da alt seviye)',
  'sub.host.wildcard': 'wildcard?',
  'sub.host.resolving': 'çözümleniyor…',
  'sub.host.resolvingTitle': 'Bir sonda ile bulundu; tam sınıflandırma çözümleme aşamasında gelir.',
  'sub.host.lookup': '{name} için DNS kayıtlarını sorgula',
  'sub.host.originHint': 'asıl sunucu?',
  'sub.host.originHintTitle': 'Asıl sunucu adayları bulundu — Origin’ler sekmesinde görün',
  'sub.ip.intel': '{ip} için IP Bilgisi',

  'sub.tech.label': 'Adlar nasıl bulundu',
  'sub.tech.summary': 'DNS ile bulunan: {dns} · pasif kaynaklardan: {sources}',
  'sub.tech.dnsOnly': '{count} tanesi yalnızca DNS ile bulundu — bu taramada sorgulanan pasif kaynakların hiçbiri döndürmedi.',
  'sub.tech.dnsOnlyIncomplete': '{count} tanesi yalnızca DNS ile bulundu (bazı pasif kaynaklar sınırlı ya da erişilemezdi; onlarda da olabilir).',
  'sub.tech.mine': 'DNS kayıtları',
  'sub.tech.wordlist': 'Kelime listesi',
  'sub.tech.permutation': 'Varyasyonlar',
  'sub.tech.recursive': 'Alt seviye',
  'sub.tech.chipTitle': '{what} ile {count} ad bulundu',

  'sub.org.title': 'Proxy arkasındaki asıl sunucular',
  'sub.org.lead': '{count} host proxy’leniyor (turuncu bulut / CDN). Genel DNS, proxy’lenen bir kaydın asıl sunucusunu hiçbir zaman yayınlamaz — bunlar yalnızca DNS ile bulunmuş, kontrol edilecek adaylar. Ağınızın içinden CLI ile doğrulayın.',
  'sub.org.networks': 'Asıl sunucu ağları',
  'sub.org.networksHint': 'Aynı alan adının DNS-only (gri bulut) kayıtları burada; proxy’lenen host’lar da bu ağlardan birinde olabilir (IPv4 için /24, IPv6 için /48). Her ağ, komutun /24’ün tamamını mı yoksa yalnızca bilinen adresleri mi taradığını ve nedenini gösterir.',
  'sub.org.net.hosts': '{count} gri bulut kaydı',
  'sub.org.net.ips': '{count} IP',
  'sub.org.sweep.cidr': '/24’ün tamamını tarar',
  'sub.org.sweep.cidrTitle': 'Bu /24 içinde birden fazla kaydınız var; komut 256 adresin tümünü tarar.',
  'sub.org.sweep.ips': { one: '1 adres taranır', other: '{count} adres taranır' },
  'sub.org.sweep.ipsTitle': 'Yalnızca bilinen adresler taranır (tek bir host, paylaşımlı sağlayıcı alanı ya da bir IPv6 bloğu); tüm blok değil.',
  'sub.org.shared': 'paylaşımlı barındırma / bulut',
  'sub.org.sharedTitle': 'Bu blok, adres alanını birçok ilgisiz müşterinin paylaştığı bir sağlayıcıya ait — yalnızca işlettiğiniz adresleri tarayın.',
  'sub.org.owner.lookup': 'Sahibini bul',
  'sub.org.owner.lookupFor': '{cidr} ağının sahibini bul (RIPEstat’a sorar)',
  'sub.org.owner.looking': 'Aranıyor…',
  'sub.org.owner.as': 'AS{asn} {holder}',
  'sub.org.owner.error': 'sahip sorgusu başarısız',
  'sub.org.warnShared': 'Bu ağların bazıları paylaşımlı barındırma / bulut alanıdır. Yalnızca işlettiğiniz ya da test etme yetkiniz olan adresleri tarayın.',
  'sub.org.exclude.label': 'Hariç tutulacak adresler',
  'sub.org.exclude.placeholder': '203.0.113.9, 198.51.100.0/28',
  'sub.org.exclude.hint': 'Komutun asla taramaması gereken IP’ler ya da CIDR’ler (bir e-posta sunucusu, paylaşımlı bir adres). --exclude olarak eklenir; tamamı kapsanan bir ağ taramadan çıkarılır.',
  'sub.org.exclude.invalid': { one: '{count} girdi geçerli bir IP ya da CIDR değil: {list}', other: '{count} girdi geçerli bir IP ya da CIDR değil: {list}' },
  'sub.org.exclude.unused': { one: 'Hiçbir taranan ağda değil: {list}', other: 'Hiçbir taranan ağda değil: {list}' },
  'sub.org.exclude.applied': { one: 'Hariç tutma ile {count} ağ çıkarıldı.', other: 'Hariç tutma ile {count} ağ çıkarıldı.' },
  'sub.org.siblingSuggest': 'Bir şirketin birden fazla alan adı varsa birlikte tara — kardeş alan adındaki aynı ad asıl sunucuyu gösterebilir.',
  'sub.org.cand.sibling': 'Kardeş alan adı',
  'sub.org.cand.siblingTitle': 'Aynı ad, bu taramadaki bir kardeş alan adında DNS-only bir host — çoğu zaman asıl sunucudur.',
  'sub.org.cand.siblingVia': '{sibling} ile aynı ad',
  'sub.org.cand.network': 'Aynı ağ',
  'sub.org.cand.networkTitle': 'Alan adının DNS-only kayıtlarının bulunduğu bir /24 ya da /48; asıl sunucu da burada olabilir.',
  'sub.org.noNetworks': 'Genel IP’li bir DNS-only kayıt bulunamadı; bu yüzden henüz taranacak bir ağ yok. Bildiğiniz adları “Ek host adları”na ekleyin ya da Büyük kelime listesini deneyin.',
  'sub.org.leaks': 'Proxy’lenen adlar için doğrudan yanıtlar',
  'sub.org.leaksHint': 'Başka bir genel çözümleyici bu proxy’lenen adları CDN dışı bir adresle yanıtladı — DNS’in verebileceği en güçlü asıl sunucu kanıtı.',
  'sub.org.leakVia': '{resolver} yanıtladı',
  'sub.org.history': 'Proxy’den önce görülenler',
  'sub.org.historyHint': 'Geçmiş DNS kayıtları proxy’lenen adlar için bu adresleri hatırlıyor.',
  'sub.org.historyVia': '{source} gördü',
  'sub.org.historyViaDate': '{source} gördü · son {date}',
  'sub.org.shell': 'Kabuk',
  'sub.org.shell.posix': 'Linux / macOS',
  'sub.org.shell.powershell': 'Windows PowerShell',
  'sub.org.shellTitle.posix': 'bash, zsh ya da sh için (python3)',
  'sub.org.shellTitle.powershell': 'Windows’ta PowerShell için (python)',
  'sub.org.dropped': '{count} girdi geçerli bir IP, ağ ya da host adı olmadığı için komuta eklenmedi.',
  'sub.reason.leak': '{host} için {resolver} yanıtı',
  'sub.reason.history': '{host} · {source} gördü',
  'sub.reason.historyDate': '{host} · {source} gördü · son {date}',
  'sub.org.cli': 'Ağınızın içinden doğrulayın',
  'sub.org.cliHint': 'CLI aşağıdaki komutun her hedefine bağlanır (bir /24’ün tamamı ya da yalnızca bilinen adresler — yukarıdaki her ağ hangisi olduğunu gösterir) ve her proxy’lenen adı TLS SNI ile ister; eşleşen sertifikayla yanıt veren sunucu asıl sunucudur. Sunucuların bulunduğu ağın içindeki bir makinede çalıştırın (Python 3.8+, bağımlılık yok). Yalnızca işlettiğiniz ya da test etme yetkiniz olan ağları tarayın — bazıları bir barındırma, e-posta ya da SaaS sağlayıcısına ait olabilir.',
  'sub.org.cliNone': 'CLI ağları ya da IP listelerini tarar: bir asıl sunucu ağı ya da aday IP bilindiğinde, asıl sunucuyu ağınızın içinden TLS SNI ile doğrular.',
  'sub.org.cliDownload': 'ssl_origin_scan.py dosyasını indir',
  'sub.org.namesFile': 'Adlar tek bir komut satırına sığmıyor: komut {count} proxy’lenen adı {file} dosyasından okur. Dosyayı indirip ssl_origin_scan.py ile aynı klasöre kaydedin.',
  'sub.org.namesFileDownload': '{file} dosyasını indir',
  'sub.org.targetsFile': 'Hedefler tek bir komut satırına sığmıyor: komut {count} hedefi {file} dosyasından okur. Dosyayı indirip ssl_origin_scan.py ile aynı klasöre kaydedin.',
  'sub.org.overLength': 'Bu komut {count} karakter uzunluğunda; bazı kabuklar (özellikle Windows) bu kadar uzun bir komutu kabul etmez: daha az hariç tutma girin.',
  'sub.org.command': 'Komut',
  'sub.org.hosts': 'Proxy’lenen host’lar ({count})',
  'sub.org.col.host': 'Proxy’lenen host',
  'sub.org.col.edge': 'Proxy / uç',
  'sub.org.col.candidates': 'Asıl sunucu adayları',
  'sub.org.candNetworks': 'aynı ağ: {list}',
  'sub.org.candNone': 'henüz aday yok',
  'sub.org.other': 'Diğer asıl sunucu ipuçları',
  'sub.org.otherHint': 'SPF / MX kayıtlarından ve aynı alan adının proxy’lenmeyen kardeş adlarından gelen adresler.',
  'sub.org.col.ip': 'IP adresi',
  'sub.org.col.evidence': 'Kanıt',
  'sub.org.col.about': 'İlgili adlar',
  'sub.hint.resolver-leak': 'Çözümleyici sızıntısı',
  'sub.hint.resolver-leak.title': 'Başka bir genel çözümleyici proxy’lenen adı bu CDN dışı adresle yanıtladı',
  'sub.hint.history': 'Geçmiş',
  'sub.hint.history.title': 'Geçmiş DNS kayıtlarında görülmüş (muhtemelen proxy açılmadan önce)',
  'sub.hint.sibling-domain': 'Kardeş alan adı',
  'sub.hint.sibling-domain.title': 'Aynı ad, bu taramadaki bir kardeş alan adında DNS-only bir host',
  'sub.hint.direct-sibling': 'Kardeş ad',
  'sub.hint.direct-sibling.title': 'Aynı alan adındaki proxy’lenmeyen bir adın genel IP’si',
  'sub.hint.spf': 'SPF',
  'sub.hint.spf.title': 'Alan adı adına e-posta göndermeye yetkili (SPF kaydı)',
  'sub.hint.mx': 'MX',
  'sub.hint.mx.title': 'Alan adının e-posta sunucusu (MX)',

  'sub.act.label': 'Listeyi kopyala veya indir',
  'sub.act.copy': 'Tüm subdomain’leri kopyala',
  'sub.act.resolvingOnly': 'Yalnızca çözümlenenler',
  'sub.act.names': 'names.txt',

  'sub.sum.noneFound': 'Hiç subdomain bulunamadı. Yazımı kontrol edin — ya da daha büyük bir kelime listesi deneyin.',
  'sub.sum.sourcesFailed': '{count} pasif kaynak yanıt vermedi (Kaynaklar sekmesine bakın). DNS keşfi onlara bağlı değildir ama birkaç ad eksik olabilir.',
  'sub.sum.sourcesLink': 'Kaynak durumunu göster',
  'sub.sum.wildcard': '{list} üzerinde wildcard DNS var: oradaki her ad çözümlenir; bu yüzden benzer adlar “wildcard?” olarak gizlendi.',
  'sub.sum.cloudflare': '{count} subdomain Cloudflare arkasında: gösterilen IP’ler Cloudflare’e ait, asıl sunucu gizli.',
  'sub.sum.originLink': 'Asıl sunucu adaylarını göster',
  'sub.sum.dangling': '{count} sahipsiz CNAME — olası subdomain ele geçirme (takeover) riski.',
  'sub.warn.INVALID_DOMAIN': 'Geçersiz alan adı atlandı: {detail}',
  'sub.warn.INVALID_NAME': 'Geçersiz host adı atlandı: {detail}',
  'sub.warn.PUBLIC_SUFFIX': '{detail} bir genel sonek olduğu için atlandı.',
  'sub.warn.TRUNCATED': 'Çok fazla ad var — yalnızca ilkleri çözümlendi ({detail}).',
  'sub.warn.BRUTEFORCE_TRUNCATED': 'Kelime listesi {detail} adayda kesildi.',
  'sub.warn.RECURSIVE_TRUNCATED': 'Alt seviye turu {detail} adayda kesildi.',
  'sub.warn.WILDCARD_PARENTS_TRUNCATED': 'Wildcard DNS yalnızca ilk {detail} üst ad için kontrol edildi.',
  'sub.warn.WORDLIST_DEGRADED': 'Seçilen kelime listesi yüklenemedi; daha küçük bir liste kullanıldı ({detail}).',
  'sub.warn.DNS_UNREACHABLE': 'Genel DNS çözümleyicileri yanıt vermeyi bıraktı (art arda {detail} tahmin başarısız oldu); bu yüzden kelime listesi ve varyasyonlar erken durduruldu. Bağlantınızı ya da bu ağda DNS-over-HTTPS’in engellenip engellenmediğini kontrol edin.',
  'sub.warn.ZONE_OUT_OF_SCOPE': 'Zone dosyanızdaki {detail} ad taranan alan adının dışında kaldığı için atlandı.',

  'sub.origin.zone': 'Zone dosyası',
  'sub.origin.zoneTitle': 'İçe aktardığınız zone dosyasında geçiyor (Zone Dosyası)',
  'sub.tech.zone': 'Zone dosyası',
  'sub.hint.zone': 'Zone dosyası',
  'sub.hint.zone.title': 'Zone dosyanız bu adresi proxy’li adın arkasındaki gerçek sunucu olarak gösteriyor',
  'sub.reason.zone': '{host} · zone dosyanızdan',
  'sub.zone.chip': { one: 'Zone dosyası yüklü: {count} ad, {origins} kesin origin', other: 'Zone dosyası yüklü: {count} ad, {origins} kesin origin' },
  'sub.zone.mode': 'Bu tarama zone dosyasını nasıl kullansın',
  'sub.zone.mode.exact': 'Yalnızca bu adları tara',
  'sub.zone.mode.exactTitle': 'Yalnızca zone dosyanızdaki adlar: pasif kaynak, kelime listesi ya da permütasyon yok; kota harcanmaz.',
  'sub.zone.mode.discover': 'Keşfe dahil et',
  'sub.zone.mode.discoverTitle': 'Zone’daki adları normal bir keşif taramasına başlangıç adı olarak ekler.',
  'sub.zone.mode.off': 'Dışarıda bırak',
  'sub.zone.mode.offTitle': 'Zone dosyası olmadan tara (dosya bu sekmede yüklü kalır).',
  'sub.zone.note.exact': 'Kesin mod: yalnızca zone dosyanızdaki adlar çözümlenir; hiçbir ad tahmin edilmez, hiçbir pasif kaynağa sorulmaz.',
  'sub.zone.note.discover': 'Zone’daki adlar başlangıç adı olarak eklenir; pasif kaynaklar, kelime listesi ve varyasyonlar her zamanki gibi çalışır.',
  'sub.zone.note.off': 'Bu tarama zone dosyasını kullanmaz.',
  'sub.zone.privacy': 'Her ad, DNS çözümleyicilerinize normal bir sorgu olarak gönderilir. Yalnızca zone dosyanızda bulunan adlar öğrenilen adlara eklenmez. Bu taramanın dışa aktarımları zone’daki origin adreslerini içerir.',
  'sub.zone.open': 'Zone Dosyası’nı aç',
  'sub.zone.exact': 'Kesin mod: yalnızca zone dosyanızdaki adlar; bu taramada pasif kaynak, kelime listesi ya da permütasyon yok.',
  'sub.zone.discover': 'Zone dosyası dahil: adları bu taramaya başlangıç adı olarak eklendi.',
  'sub.zone.busy': '{running} taraması hâlâ sürüyor. Zone dosyanızın taraması ({domain}) o bitince başlar.',
  'sub.zone.busy.cancel': 'Onu iptal et, zone’u tara',
  'sub.zone.busy.dismiss': 'Vazgeç',
  'sub.org.zone': 'Zone dosyanızdaki kesin originler',
  'sub.org.zoneHint': 'Zone dosyanız bu proxy’li adların arkasındaki gerçek sunucuyu gösteriyor. Aşağıdaki komut bu kesin adresleri yoklar; onları asla bir /24’e genişletmez.',
  'sub.org.ptr': 'Ters DNS taraması',
  'sub.org.ptrIps': '{count} adresinin ters DNS’i',
  'sub.org.ptrIpsTitle': 'Paylaşımlı bulut / barındırma alanı: bu bloğun geri kalanı başka müşterilerin, bu yüzden yalnızca adlarınızın çözümlendiği adreslere bakılır (Ters DNS görünümünü açar, Tara’ya siz basarsınız)',
  'sub.org.ptrTitle': '{cidr} içindeki her adresin ters DNS (PTR) kaydına bak: sizin diğer sunucularınız çoğu zaman origin’in yanında durur (Ters DNS görünümünü açar, Tara’ya siz basarsınız)',
  'sub.handoff.chip': { one: '{label} ters DNS taramasından {count} ad', other: '{label} ters DNS taramasından {count} ad' },
  'sub.handoff.mode': 'Bu tarama bu adları nasıl kullansın',
  'sub.handoff.mode.exact': 'Yalnızca bu adları tara',
  'sub.handoff.mode.exactTitle': 'Yalnızca bu adlar ve kutudaki alan adları: pasif kaynak, kelime listesi ya da permütasyon yok; kota harcanmaz.',
  'sub.handoff.mode.discover': 'Keşfe dahil et',
  'sub.handoff.mode.discoverTitle': 'Bu adları normal bir keşif taramasına başlangıç adı olarak ekler.',
  'sub.handoff.mode.off': 'Dışarıda bırak',
  'sub.handoff.mode.offTitle': 'Bu adlar olmadan tara (siz kaldırana kadar burada kalırlar).',
  'sub.handoff.note.exact': 'Kesin mod: yalnızca bu adlar ve kutudaki alan adları çözümlenir; hiçbir ad tahmin edilmez, hiçbir pasif kaynağa sorulmaz.',
  'sub.handoff.note.discover': 'Adlar başlangıç adı olarak eklenir; pasif kaynaklar, kelime listesi ve varyasyonlar her zamanki gibi çalışır.',
  'sub.handoff.note.off': 'Bu tarama bu adları kullanmaz.',
  'sub.handoff.open': 'Ters DNS’e dön',
  'sub.handoff.remove': 'Bu adları kaldır',
  'sub.handoff.elsewhere': 'Kutudaki alan adları için kullanılmaz: bu adlar {domains} altında. Taramak için bunlardan birini yazın.',
  'sub.handoff.partial': '{total} addan {count} tanesi kutudaki alan adlarının altında: bu tarama yalnızca onları kullanır.',
  'sub.handoff.exact': 'Kesin mod: yalnızca ters DNS taramasından gelen adlar; bu taramada pasif kaynak, kelime listesi ya da permütasyon yok.',
  'sub.handoff.discover': 'Ters DNS taramasından gelen adlar bu taramaya başlangıç adı olarak eklendi.',

  'sub.cta.title': 'Bu alan adının sertifikası hangi sunuculara kurulacak?',
  'sub.cta.body': 'SSL Hedefleri bu adları sunucularınızla eşleştirir, sertifika kapsamını kontrol eder ve Cloudflare arkasında gizlenen asıl sunucuları bulur.',
  'sub.cta.button': 'SSL Hedefleri’nde aç'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for the tests)                                    */
/* ------------------------------------------------------------------------ */

/**
 * Parse the search box: URLs and hostnames become scan targets. A leading `www.` of a
 * registrable domain is dropped (`https://www.example.com/x` → `example.com`); any other
 * subdomain is kept (`shop.example.com` scans that branch only). Targets inside another
 * target are dropped. IP addresses and public suffixes are reported separately.
 * @param {string} text
 * @returns {{ domains: string[], invalid: string[], ips: string[], publicSuffixes: string[] }}
 */
export function parseTargets(text) {
  const out = { domains: [], invalid: [], ips: [], publicSuffixes: [] };
  const seen = new Set();
  for (const token of splitList(String(text ?? ''))) {
    const ip = normalizeIP(token.replace(/^\[|\]$/g, ''));
    if (ip) {
      if (!out.ips.includes(ip)) out.ips.push(ip);
      continue;
    }
    const n = normalizeHostname(token, { allowWildcard: true });
    if (!n) {
      if (!out.invalid.includes(token)) out.invalid.push(token);
      continue;
    }
    const { base } = stripWildcard(n);
    if (isPublicSuffix(base)) {
      if (!out.publicSuffixes.includes(base)) out.publicSuffixes.push(base);
      continue;
    }
    const reg = registrableDomain(base);
    const target = reg && base === `www.${reg}` ? reg : base;
    if (!seen.has(target)) {
      seen.add(target);
      out.domains.push(target);
    }
  }
  out.domains = out.domains.filter((d) => !out.domains.some((o) => o !== d && isSubdomainOf(d, o)));
  return out;
}

/**
 * Targets from route params (`domain` repeatable / comma-separated, alias `domains`).
 * @param {URLSearchParams|null} searchParams
 * @param {Record<string, string>} [params]
 * @returns {string[]}
 */
export function routeTargets(searchParams, params = {}) {
  const raw = [];
  if (searchParams && typeof searchParams.getAll === 'function') {
    raw.push(...searchParams.getAll('domain'), ...searchParams.getAll('domains'));
  }
  if (!raw.length) raw.push(params.domain || '', params.domains || '');
  return parseTargets(raw.join('\n')).domains;
}

/**
 * Validate remembered options; unknown values fall back to the defaults (every
 * default-enabled source, smart wordlist, permutations with a 1,500 budget, origin hints on,
 * no expired certificates). A legacy 'medium' level loads as 'smart' (its superset). Sources
 * added to the app after the options were saved are switched on once (`knownSources` tracks
 * which ones the user has already seen, so an unticked source stays unticked). `locales` is
 * null for "choose from the domain ending" or the chosen pack codes ([] = the global list only);
 * `learned` (default OFF, opt-in) tries and remembers the labels of earlier scans: they are sent
 * as DNS lookups under every domain scanned later, so one organisation's naming vocabulary would
 * otherwise reach another's nameservers without the user choosing that.
 * @param {any} input
 * @returns {{ sources: string[], knownSources: string[], bruteforce: 'off'|'small'|'smart'|'large'|'huge',
 *   permutations: boolean, permutationBudget: number, originHints: boolean, includeExpired: boolean,
 *   locales: string[]|null, learned: boolean }}
 */
export function sanitizeOptions(input) {
  const src = input && typeof input === 'object' ? input : {};
  const ids = SOURCES.map((s) => s.id);
  const defaults = SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const hasStored = Array.isArray(src.sources);
  const sources = hasStored ? [...new Set(src.sources.filter((x) => ids.includes(x)))] : [...defaults];
  if (hasStored && Array.isArray(src.knownSources)) {
    for (const sid of defaults) if (!src.knownSources.includes(sid) && !sources.includes(sid)) sources.push(sid);
  }
  const bf = Object.prototype.hasOwnProperty.call(LEGACY_BRUTEFORCE, src.bruteforce) ? LEGACY_BRUTEFORCE[src.bruteforce] : src.bruteforce;
  const budget = Number(src.permutationBudget);
  return {
    sources,
    knownSources: [...ids],
    bruteforce: BRUTEFORCE_MODES.includes(bf) ? bf : 'smart',
    permutations: src.permutations !== false,
    permutationBudget: PERMUTATION_BUDGETS.includes(budget) ? budget : DEFAULT_PERMUTATION_BUDGET,
    originHints: src.originHints !== false,
    includeExpired: src.includeExpired === true,
    locales: sanitizeLocales(src.locales),
    learned: src.learned === true
  };
}

/**
 * A stored locale choice: null (automatic, from the domain ending) or the known pack codes in
 * pack order, without duplicates ([] = none).
 * @param {any} value
 * @returns {string[]|null}
 */
export function sanitizeLocales(value) {
  if (!Array.isArray(value)) return null;
  const set = new Set(value.map((x) => String(x).toLowerCase()));
  return LOCALE_CODES.filter((cc) => set.has(cc));
}

/**
 * Bulk-probe width a scan uses for a Settings value (see {@link scanConcurrency}) as a share of
 * the full width, for the time estimates.
 * @param {number} [sweep] parallel probes (default: the full {@link MAX_SWEEP_CONCURRENCY})
 * @returns {number} queries per second
 */
export function probeRate(sweep = MAX_SWEEP_CONCURRENCY) {
  const n = Math.max(1, Math.min(MAX_SWEEP_CONCURRENCY, Math.floor(Number(sweep)) || MAX_SWEEP_CONCURRENCY));
  return PROBE_RATE_QPS * (n / MAX_SWEEP_CONCURRENCY);
}

/**
 * Rough wall-clock estimate of probing `candidates` names under `domains` domains at
 * {@link probeRate}: '≈ 50 s', '≈ 3 min'. Rounded up to 10 s below two minutes.
 * @param {number} candidates
 * @param {number} [domains=1]
 * @param {number} [sweep] parallel probes of the scan ({@link scanConcurrency} of the Settings value)
 * @returns {string}
 */
export function estimateText(candidates, domains = 1, sweep = MAX_SWEEP_CONCURRENCY) {
  const n = Math.max(0, Number(candidates) || 0) * Math.max(1, Number(domains) || 1);
  const sec = n / probeRate(sweep);
  if (sec < 120) return t('sub.est.seconds', { n: formatNumber(Math.max(10, Math.ceil(sec / 10) * 10)) });
  return t('sub.est.minutes', { count: Math.round(sec / 60) });
}

/**
 * Number of names in a wordlist level (build-time counts; 0 for 'off').
 * @param {string} level
 * @returns {number}
 */
export function levelCount(level) {
  if (level === 'small') return WORDLIST_SMALL.length;
  const info = WORDLIST_INFO.levels[level];
  return info ? Number(info.approxCount) || 0 : 0;
}

/**
 * Candidate count of a wordlist level for the labels.
 * @param {string} level
 * @returns {{ count: number, text: string }}
 */
export function wordlistCount(level) {
  const count = levelCount(level);
  return { count, text: formatNumber(count) };
}

/**
 * Download size of a level's self-hosted file ('183 KB'); '' for the built-in small list.
 * @param {string} level
 * @returns {string}
 */
export function levelSize(level) {
  const info = WORDLIST_INFO.levels[level];
  return info && info.bytes > 0 ? formatBytes(info.bytes) : '';
}

/**
 * Names in a locale pack (build-time count).
 * @param {string} code
 * @returns {number}
 */
export function localePackCount(code) {
  const info = WORDLIST_INFO.locales[code];
  return info ? Number(info.approxCount) || 0 : 0;
}

/** Localized language name of a pack code ('Turkish' / 'Türkçe'). */
export function languageName(code) {
  return LOCALE_CODES.includes(code) ? t(`sub.lang.${code}`) : String(code);
}

/**
 * The public suffix a domain's market is read from: `example.com.tr` → '.com.tr',
 * `shop.example.de` → '.de'.
 * @param {string} domain
 * @returns {string}
 */
export function domainSuffix(domain) {
  const d = String(domain || '').toLowerCase().replace(/\.+$/, '');
  const reg = registrableDomain(d);
  if (reg && reg.includes('.')) return reg.slice(reg.indexOf('.'));
  const dot = d.lastIndexOf('.');
  return dot === -1 ? (d ? `.${d}` : '') : d.slice(dot);
}

/**
 * Locale packs the automatic choice picks for each typed domain (lib/wordlist.localesForDomain).
 * @param {string[]} domains
 * @returns {Array<{ domain: string, suffix: string, codes: string[] }>}
 */
export function autoLocales(domains) {
  return (domains || []).map((domain) => ({ domain, suffix: domainSuffix(domain), codes: localesForDomain(domain) }));
}

/**
 * Locale packs a scan of `domain` uses: the automatic choice, or the chosen packs.
 * @param {string[]|null} choice options.locales
 * @param {string} domain
 * @returns {string[]}
 */
export function effectiveLocales(choice, domain) {
  return Array.isArray(choice) ? sanitizeLocales(choice) : localesForDomain(domain);
}

/**
 * One line describing the locale choice for the typed domains: "Auto: Turkish (.com.tr)",
 * "Auto: none — .com has no market pack …", "Chosen: German, French", "None: the global list only".
 * @param {string[]|null} choice options.locales
 * @param {string[]} domains
 * @returns {string}
 */
export function localeSummary(choice, domains) {
  if (Array.isArray(choice)) {
    const codes = sanitizeLocales(choice);
    return codes.length ? t('sub.lang.manual', { list: codes.map(languageName).join(', ') }) : t('sub.lang.manualNone');
  }
  const picks = autoLocales(domains);
  if (!picks.length) return t('sub.lang.autoEmpty');
  const items = [];
  for (const p of picks) {
    for (const cc of p.codes) {
      const item = t('sub.lang.autoItem', { language: languageName(cc), suffix: p.suffix });
      if (!items.includes(item)) items.push(item);
    }
  }
  if (!items.length) return t('sub.lang.autoNone', { suffix: [...new Set(picks.map((p) => p.suffix))].join(', ') });
  return t('sub.lang.autoPick', { list: items.join(', ') });
}

/**
 * What the wordlist stage of a scan will try, per typed domain: the level's names, the locale
 * packs (from Smart up), the custom and learned names — capped like lib/scanner caps them
 * ({@link BRUTEFORCE_CAPS} per domain, {@link BRUTEFORCE_TOTAL_CAP} in all). Custom and learned
 * names that are already in the list add nothing, so their share is an upper bound.
 * @param {{ level: string, domains: string[], locales?: string[]|null, custom?: number, learned?: number }} opts
 * @returns {{ level: string, perDomain: Array<{ domain: string, level: number, packs: Array<{ code: string, count: number }>,
 *   custom: number, learned: number, total: number, capped: boolean }>, total: number }}
 */
export function wordlistPlan({ level, domains = [], locales = null, custom = 0, learned = 0 }) {
  const lvl = BRUTEFORCE_MODES.includes(level) ? level : 'off';
  if (lvl === 'off') return { level: lvl, perDomain: [], total: 0 };
  const cap = BRUTEFORCE_CAPS[lvl] || BRUTEFORCE_CAPS.smart;
  const perDomain = (domains.length ? domains : ['']).map((domain) => {
    // Packs apply from Smart up; with no domain typed yet only a manual choice is known.
    const packs = lvl === 'small' || (!domain && !Array.isArray(locales))
      ? []
      : effectiveLocales(locales, domain).map((code) => ({ code, count: localePackCount(code) }));
    const extra = Math.max(0, Number(custom) || 0) + Math.max(0, Number(learned) || 0);
    const raw = levelCount(lvl) + packs.reduce((a, p) => a + p.count, 0) + extra;
    return {
      domain,
      level: levelCount(lvl),
      packs,
      custom: Math.max(0, Number(custom) || 0),
      learned: Math.max(0, Number(learned) || 0),
      total: Math.min(raw, cap),
      capped: raw > cap
    };
  });
  const total = Math.min(perDomain.reduce((a, d) => a + d.total, 0), BRUTEFORCE_TOTAL_CAP);
  return { level: lvl, perDomain, total };
}

/**
 * The bases the wordlist stage brute-forces, built like lib/scanner builds them: the scanned
 * domains (with none given, the registrable domains of the certificate / extra names, as the
 * scanner derives its targets) plus the base of every wildcard name — `*.api.example.com` gets
 * the whole level list again under api.example.com. Each once, in first-seen order; a public
 * suffix is never a base. The wordlist plan and its time estimate count these, not only the
 * typed domains.
 * @param {string[]} domains the typed / scanned domains
 * @param {string[]} [names] certificate hostnames and extra names (wildcards allowed)
 * @returns {string[]}
 */
export function bruteforceBases(domains, names = []) {
  const out = [];
  const add = (d) => {
    if (d && !isPublicSuffix(d) && !out.includes(d)) out.push(d);
  };
  const list = Array.isArray(domains) ? domains : [];
  const nameList = Array.isArray(names) ? names.filter((n) => typeof n === 'string') : [];
  if (list.length) {
    for (const d of list) add(normalizeHostname(String(d ?? '')));
  } else {
    for (const d of baseDomainsFromNames(nameList)) add(d);
  }
  for (const raw of nameList) {
    const n = normalizeHostname(raw, { allowWildcard: true });
    if (!n) continue;
    const { base, wildcard } = stripWildcard(n);
    if (wildcard) add(base);
  }
  return out;
}

/**
 * The locale packs a Smart / Large / Huge scan of the typed domains adds on top of the level
 * (the automatic pick per domain, or the chosen packs), each once with its build-time size.
 * Small is language-neutral, so nothing is added there.
 * @param {string} level
 * @param {string[]} domains
 * @param {string[]|null} locales options.locales
 * @returns {Array<{ code: string, count: number }>}
 */
export function levelPacks(level, domains, locales) {
  if (level === 'small' || !BRUTEFORCE_CAPS[level]) return [];
  const seen = new Map();
  for (const d of wordlistPlan({ level, domains, locales }).perDomain) for (const p of d.packs) if (!seen.has(p.code)) seen.set(p.code, p.count);
  return [...seen].map(([code, count]) => ({ code, count }));
}

/**
 * One sentence for a {@link wordlistPlan}: "≈ 7,450 DNS queries for 1 domain (7,000 smart,
 * +450 Turkish) · ≈ 1 min". With several domains the breakdown is per domain and lists every
 * locale pack any of them gets. Empty for an off / empty plan.
 * @param {ReturnType<typeof wordlistPlan>} plan
 * @param {number} [sweep] parallel probes of the scan ({@link scanConcurrency} of the Settings value)
 * @returns {string}
 */
export function wordlistPlanText(plan, sweep = MAX_SWEEP_CONCURRENCY, queries = null) {
  const list = plan && Array.isArray(plan.perDomain) ? plan.perDomain : [];
  if (!list.length || !BRUTEFORCE_CAPS[plan.level]) return '';
  const pd = list[0];
  const parts = [t('sub.plan.level', { count: formatNumber(pd.level), level: t(`sub.bf.${plan.level}`) })];
  const packs = new Map();
  for (const d of list) for (const p of d.packs) if (!packs.has(p.code)) packs.set(p.code, p.count);
  for (const [code, count] of packs) parts.push(t('sub.plan.pack', { count: formatNumber(count), language: languageName(code) }));
  if (pd.custom) parts.push(t('sub.plan.custom', { count: formatNumber(pd.custom) }));
  if (pd.learned) parts.push(t('sub.plan.learned', { count: formatNumber(pd.learned) }));
  if (list.some((d) => d.capped)) parts.push(t('sub.plan.capped', { count: formatNumber(BRUTEFORCE_CAPS[plan.level]) }));
  const joined = parts.join(', ');
  // The query estimate covers the whole scan (wordlist + variations + deeper round + origin
  // hints), so it is honest about how many DNS queries run — not just the wordlist size.
  const range = queries && Number.isFinite(queries.min) ? queries : { min: plan.total, max: plan.total };
  return t('sub.plan.line', {
    queries: queryRangeText(range),
    domains: t('sub.plan.domains', { count: list.length }),
    parts: list.length > 1 ? t('sub.plan.perDomain', { parts: joined }) : joined,
    time: estimateText(plan.total, 1, sweep)
  });
}

/**
 * The honest DNS-query estimate range for a planned scan, from lib/scanner.estimateQueries: the
 * wordlist plus permutations, the deeper round and the origin-hint queries — the numbers the old
 * wordlist-only plan under-counted. Pure.
 * @param {{ level: string, domains: string[], locales?: string[]|null, custom?: number, learned?: number,
 *   permutations?: boolean, permutationBudget?: number, originHints?: boolean, certNames?: string[],
 *   extraNames?: string[], wildcardBases?: string[] }} opts
 * @returns {{ min: number, max: number, breakdown: object }}
 */
export function planQueryRange({
  level = 'smart', domains = [], locales = null, custom = 0, learned = 0,
  permutations = true, permutationBudget = DEFAULT_PERMUTATION_BUDGET, originHints = true,
  certNames = [], extraNames = [], wildcardBases = []
} = {}) {
  return estimateQueries({
    bruteforce: level,
    domains,
    wildcardBases,
    certNames,
    extraNames,
    locales,
    customCount: Math.max(0, Number(custom) || 0),
    learnedCount: Math.max(0, Number(learned) || 0),
    permutationBudget: permutations ? permutationBudget : 0,
    recursive: permutations,
    originHints,
    resolverLeak: originHints
  });
}

/**
 * A localized DNS-query range for the plan line: "7,300–11,500" (an en dash), or a single number
 * when min and max coincide.
 * @param {{ min: number, max: number }} range
 * @returns {string}
 */
export function queryRangeText(range) {
  const min = Math.max(0, Number(range && range.min) || 0);
  const max = Math.max(min, Number(range && range.max) || 0);
  return min === max ? formatNumber(min) : t('sub.plan.queriesRange', { min: formatNumber(min), max: formatNumber(max) });
}

/**
 * A 'YYYY-MM-DD' last-seen day in the reader's locale ("Jan 2, 2024" / "2 Oca 2024"); anything
 * else is shown as given.
 * @param {string} day
 * @returns {string}
 */
export function dayText(day) {
  const s = String(day ?? '');
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? formatDate(s, { utc: true }) : s;
}

/**
 * A localized line for one origin-hint reason, built from its structured fields: "app.example.com
 * answered by Google" (resolver leak), "app.example.com · seen by AlienVault OTX · last Jan 2,
 * 2024" (history). SPF / MX / sibling reasons carry only their display `detail`.
 * @param {{ kind?: string, host?: string, resolver?: string, source?: string, lastSeen?: string, detail?: string }} reason
 * @returns {string}
 */
export function reasonText(reason) {
  const r = reason || {};
  const f = reasonHost(r);
  if (r.kind === 'resolver-leak' && f.host) {
    return t('sub.reason.leak', { host: f.host, resolver: (getResolver(f.resolver) || { name: f.resolver || '?' }).name });
  }
  if (r.kind === 'history' && f.host) {
    const source = SOURCE_NAMES[f.source] || f.source || '?';
    return t(f.lastSeen ? 'sub.reason.historyDate' : 'sub.reason.history', { host: f.host, source, date: dayText(f.lastSeen) });
  }
  if (r.kind === 'zone' && f.host) return t('sub.reason.zone', { host: f.host });
  return String(r.detail ?? '');
}

/**
 * The wordlist part of a runScan config for the chosen options: locales (undefined = automatic
 * per domain), the custom labels (tried first) and the learned labels (only when switched on
 * AND a wordlist level is chosen; the {@link LEARNED_TRY_MAX} most frequent). At level Off the
 * learned labels are never passed: lib/scanner would still feed them to the permutation words
 * and the deeper (recursive) round, so a scan the user set to "guess nothing" would send
 * another target's vocabulary as DNS lookups.
 * @param {{ bruteforce: string, locales: string[]|null, learned: boolean }} options
 * @param {{ custom?: string[], learned?: string[] }} [labels]
 * @returns {{ bruteforce: string, locales?: string[], customWordlist?: string[], learnedLabels?: string[] }}
 */
export function wordlistScanConfig(options, { custom = [], learned = [] } = {}) {
  const o = options || {};
  const out = { bruteforce: BRUTEFORCE_MODES.includes(o.bruteforce) ? o.bruteforce : 'smart' };
  if (Array.isArray(o.locales)) out.locales = sanitizeLocales(o.locales);
  if (Array.isArray(custom) && custom.length) out.customWordlist = [...custom];
  if (o.learned === true && out.bruteforce !== 'off' && Array.isArray(learned) && learned.length) {
    out.learnedLabels = learned.slice(0, LEARNED_TRY_MAX);
  }
  return out;
}

/* ---- per-browser vocabulary: learned labels (localStorage), custom list (sessionStorage) ---- */

let memoryLearned = null;

/** localStorage, or null where it is missing or throws (private mode, sandbox). */
function localStore() {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

/** sessionStorage, or null where it is missing or throws. */
function sessionStore() {
  try {
    return globalThis.sessionStorage || null;
  } catch {
    return null;
  }
}

/**
 * The learned-labels store of this browser (lib/learned.js over localStorage). Read afresh on
 * every call, so another tab's scan or "Delete all local data" is always reflected; without
 * usable storage an in-memory store serves this page.
 * @returns {ReturnType<typeof createLearnedStore>}
 */
export function learnedStore() {
  const storage = localStore();
  if (storage) {
    try {
      return createLearnedStore(storage);
    } catch {
      // fall through to memory
    }
  }
  if (!memoryLearned) memoryLearned = createLearnedStore(null);
  return memoryLearned;
}

/**
 * The hosts of a scan result that sit under one of its scanned domains (the apex itself
 * included). A certificate SAN or an "extra hostname" of another organisation (`acmebrand.org`)
 * is left out, so its brand label is never learned and probed under later targets.
 * @param {object} result ScanResult
 * @returns {object[]} HostRecords
 */
function inScopeHosts(result) {
  const roots = Array.isArray(result.domains) ? result.domains.filter(Boolean) : [];
  const hosts = Array.isArray(result.hosts) ? result.hosts : [];
  return hosts.filter((x) => x && roots.some((root) => isSubdomainOf(x.name, root)));
}

/**
 * After a finished scan: remember the bare left-most labels of the names that resolved under the
 * scanned domains (lib/scanner.learnedLabelsFromScan — never full names or IPs; names outside
 * every scanned domain contribute nothing). Never throws.
 * @param {object} result ScanResult
 * @param {boolean} enabled the "learned names" switch of the scan
 * @param {() => object} [store]
 * @returns {number} labels newly added
 */
export function rememberLearned(result, enabled, store = learnedStore) {
  if (!enabled || !result) return 0;
  try {
    const labels = learnedLabelsFromScan({ ...result, hosts: inScopeHosts(result) });
    return labels.length ? store().record(labels) : 0;
  } catch {
    return 0;
  }
}

/** The pasted / uploaded custom wordlist of this tab: raw text + where it is kept. */
const custom = { text: null, parsed: null, parsedFor: null, stored: 'session' };

/**
 * The custom wordlist text of this tab (sessionStorage; memory when that is unavailable or
 * the list is too long for it). While it is kept in sessionStorage the storage is the truth and
 * is read afresh every time, so "Delete all local data" (which empties it) takes effect whatever
 * view is mounted; a memory-only copy is dropped through the 'cleared' state event instead.
 * @returns {string}
 */
export function loadCustomWordlist() {
  if (custom.text === null || custom.stored === 'session') {
    let text = '';
    const s = sessionStore();
    try {
      text = (s && s.getItem(CUSTOM_WORDLIST_KEY)) || '';
    } catch {
      text = '';
    }
    custom.text = typeof text === 'string' ? text : '';
  }
  return custom.text;
}

/**
 * Keep the custom wordlist text for this tab.
 * @param {string} text
 * @returns {'session'|'memory'} where it is kept
 */
export function saveCustomWordlist(text) {
  const value = String(text ?? '');
  custom.text = value;
  const s = sessionStore();
  let stored = 'memory';
  try {
    if (s) {
      if (!value.trim()) {
        s.removeItem(CUSTOM_WORDLIST_KEY);
        stored = 'session';
      } else if (value.length <= CUSTOM_WORDLIST_MAX_CHARS) {
        s.setItem(CUSTOM_WORDLIST_KEY, value);
        stored = 'session';
      } else {
        s.removeItem(CUSTOM_WORDLIST_KEY);
      }
    }
  } catch {
    // A failed write (quota, private mode) must not leave an older, replaced list behind that a
    // reload of this tab would bring back.
    if (s) {
      try {
        s.removeItem(CUSTOM_WORDLIST_KEY);
      } catch {
        // storage unusable: nothing of ours can be read back from it either
      }
    }
    stored = 'memory';
  }
  custom.stored = stored;
  return stored;
}

/** Forget the in-memory copy (after "Delete all local data" cleared the storage). */
export function resetCustomWordlist() {
  custom.text = null;
  custom.parsed = null;
  custom.parsedFor = null;
  custom.stored = 'session';
}

// "Delete all local data" (About, or Settings on any view) must also drop the copies this module
// keeps in memory — the custom list when it was too long for sessionStorage, the learned store of
// a browser without localStorage, the names a Reverse DNS sweep handed over, the search box and
// the last scan (a running one is stopped) — whether or not the Subdomains view is mounted: the
// module stays loaded (SSL Targets imports it) and would otherwise keep probing the old names.
// The shell opens the view again when it is on screen.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared') return;
  resetCustomWordlist();
  session.handoff = null;
  if (memoryLearned) {
    try {
      memoryLearned.clear();
    } catch {
      memoryLearned = null;
    }
  }
  forgetRuns();
});

/**
 * The custom wordlist of this tab, parsed with lib/wordlist.parseCustomWordlist (cached per text).
 * @returns {{ labels: string[], rejected: string[], stored: 'session'|'memory' }}
 */
export function customWordlist() {
  const text = loadCustomWordlist();
  if (custom.parsedFor !== text) {
    custom.parsed = parseCustomWordlist(text);
    custom.parsedFor = text;
  }
  return { ...custom.parsed, stored: custom.stored };
}

/**
 * The per-browser wordlist vocabulary both scan views use: the language choice and the
 * "learned names" switch of the Subdomains options (Advanced), this tab's custom wordlist and,
 * when the switch is on, the learned labels (most frequent first). Never throws.
 * @returns {{ locales: string[]|null, learnedOn: boolean, custom: string[], learned: string[] }}
 */
export function sharedVocabulary() {
  const o = loadOptions();
  let learned = [];
  if (o.learned) {
    try {
      learned = learnedStore().labels();
    } catch {
      learned = [];
    }
  }
  let custom = [];
  try {
    custom = customWordlist().labels;
  } catch {
    custom = [];
  }
  return { locales: o.locales, learnedOn: o.learned, custom, learned };
}

/**
 * How the names of a host list were found (wildcard suspects left out, like the table):
 * DNS discovery (records, wordlist, permutations, deeper level) versus passive sources.
 * @param {object[]} hosts HostRecords
 * @returns {{ total: number, dns: number, sources: number, dnsOnly: number, mine: number, wordlist: number,
 *   permutation: number, recursive: number, bySource: Record<string, number>, byRecord: Record<string, number> }}
 */
export function techniqueCounts(hosts) {
  const c = { total: 0, dns: 0, sources: 0, dnsOnly: 0, mine: 0, wordlist: 0, permutation: 0, recursive: 0, zone: 0, bySource: {}, byRecord: {} };
  for (const x of hosts || []) {
    if (!x || x.wildcardSuspect) continue;
    c.total += 1;
    const origins = Array.isArray(x.origins) ? x.origins : [];
    const records = new Set();
    const seen = new Set();
    let fromSource = false;
    // Named in the imported zone file (Zone File hand-off): its own bucket, neither DNS nor a source.
    if (origins.includes('zone')) c.zone += 1;
    for (const o of origins) {
      const id = String(o);
      if (id.startsWith('dns-mine:')) records.add(id.slice('dns-mine:'.length));
      else if (DNS_ORIGINS.has(id)) seen.add(id === 'bruteforce' ? 'wordlist' : id);
      else if (SOURCE_NAMES[id]) {
        fromSource = true;
        c.bySource[id] = (c.bySource[id] || 0) + 1;
      }
    }
    if (records.size) {
      c.mine += 1;
      for (const r of records) c.byRecord[r] = (c.byRecord[r] || 0) + 1;
    }
    for (const k of seen) c[k] += 1;
    const byDns = records.size > 0 || seen.size > 0;
    if (byDns) c.dns += 1;
    if (fromSource) c.sources += 1;
    if (byDns && !fromSource) c.dnsOnly += 1;
  }
  return c;
}

/**
 * Localized label of an origin id ('input', 'wordlist', 'dns-mine:MX', a source id …).
 * @param {string} origin
 * @returns {string}
 */
export function originLabel(origin) {
  const o = String(origin ?? '');
  if (o.startsWith('dns-mine:')) return t('sub.origin.dnsmine', { record: o.slice('dns-mine:'.length) });
  if (['input', 'cert', 'bruteforce', 'wordlist', 'permutation', 'recursive', 'zone'].includes(o)) return t(`sub.origin.${o}`);
  return SOURCE_NAMES[o] || o;
}

/** Tooltip of an origin chip (null when the label says it all). */
function originTitle(origin) {
  const o = String(origin ?? '');
  if (o.startsWith('dns-mine:')) return t('sub.origin.dnsmineTitle', { record: o.slice('dns-mine:'.length) });
  if (DNS_ORIGINS.has(o)) return t('sub.origin.dnsTitle');
  if (o === 'zone') return t('sub.origin.zoneTitle');
  return null;
}

/**
 * A clear, localized status line for one entry of lib/sources.sourceHealthSummary():
 * `short` for a chip ("12 names", "Quota used up"), `detail` for a sentence ("HackerTarget:
 * The daily free quota … resets in about 24 hours.", "crt.sh is temporarily down. Cert
 * Spotter was used instead.") and `tone` for styling.
 * @param {object} health SourceHealth
 * @returns {{ tone: 'ok'|'warn'|'limited'|'error', short: string, detail: string }}
 */
export function sourceHealthText(health) {
  const hl = health || {};
  const name = hl.name || SOURCE_NAMES[hl.source] || String(hl.source || '');
  const count = Number(hl.names) || 0;
  const twin = hl.fallback ? ` ${t('source.fallback', { name: SOURCE_NAMES[hl.fallback] || hl.fallback })}` : '';
  const reason = t(`error.kind.${CHIP_ERRORS.includes(hl.errorKind) || hl.errorKind === 'unavailable' ? hl.errorKind : 'unknown'}`);
  switch (hl.state) {
    case 'ok': {
      const truncated = hl.truncated && Number.isFinite(hl.available) && hl.available > count;
      return {
        tone: 'ok',
        short: t('sub.chip.names', { count }),
        detail: truncated
          ? t('sub.srcnote.truncated', { name, count: formatNumber(count), available: formatNumber(hl.available) })
          : t('sub.srcnote.ok', { name, count })
      };
    }
    case 'empty':
      return { tone: 'ok', short: t('sub.chip.names', { count: 0 }), detail: t('sub.srcnote.empty', { name }) };
    case 'partial':
      return {
        tone: 'warn',
        short: `${t('sub.chip.names', { count })} · ${t('sub.chip.partial')}`,
        detail: t('sub.srcnote.partial', { name, count, reason: hl.errorKind === 'rate-limit' && hl.quota && hl.quota.hintKey ? t(hl.quota.hintKey) : reason })
      };
    case 'rate-limited':
      return {
        tone: 'limited',
        short: t('source.state.rate-limited'),
        detail: t('sub.srcnote.limited', { name, reason: t((hl.quota && hl.quota.hintKey) || 'source.quota.later') }) + twin
      };
    case 'unavailable':
      return { tone: 'error', short: t('source.state.unavailable'), detail: t('sub.srcnote.unavailable', { name }) + twin };
    case 'timeout':
      return { tone: 'error', short: t('source.state.timeout'), detail: t('sub.srcnote.timeout', { name }) + twin };
    default:
      return { tone: 'error', short: t('source.state.error'), detail: t('sub.srcnote.error', { name, reason }) + twin };
  }
}

/**
 * Can the companion CLI sweep this `-t` target as written? A single IP always; a CIDR only
 * when it holds at most 2^{@link CLI_MAX_BLOCK_BITS} addresses (an IPv4 /24 yes, an IPv6 /48 no).
 * @param {string} target
 * @returns {boolean}
 */
export function sweepableTarget(target) {
  const s = String(target ?? '').trim();
  const m = /^([^/\s]+)\/(\d{1,3})$/.exec(s);
  if (!m) return !!normalizeIP(s);
  const ip = normalizeIP(m[1]);
  if (!ip) return false;
  const bits = ip.includes(':') ? 128 : 32;
  const prefix = Number(m[2]);
  return prefix <= bits && bits - prefix <= CLI_MAX_BLOCK_BITS;
}

/**
 * The origin networks without wildcard suspects: a suspect only resolves like its parent's
 * wildcard record, so it is no evidence of where servers live. A network whose members are all
 * suspects is dropped; otherwise its suspect members (and addresses only they use) are left out.
 * @param {object[]} networks ScanResult.originNetworks
 * @param {object[]} hosts ScanResult.hosts
 * @returns {{ networks: object[], dropped: Set<string> }} `dropped`: CIDRs and IPs of dropped networks
 */
export function realOriginNetworks(networks, hosts) {
  const list = Array.isArray(networks) ? networks : [];
  const suspects = new Set();
  const suspectIps = new Set();
  const realIps = new Set();
  for (const x of Array.isArray(hosts) ? hosts : []) {
    if (!x) continue;
    if (x.wildcardSuspect) suspects.add(x.name);
    const res = x.resolution || {};
    for (const ip of [...(res.ipv4 || []), ...(res.ipv6 || [])]) (x.wildcardSuspect ? suspectIps : realIps).add(ip);
  }
  const dropped = new Set();
  const kept = [];
  for (const n of list) {
    if (!n || typeof n.cidr !== 'string') continue;
    const members = Array.isArray(n.hosts) ? n.hosts : [];
    const real = members.filter((name) => !suspects.has(name));
    if (real.length === members.length) {
      kept.push(n);
    } else if (!real.length) {
      dropped.add(n.cidr);
      for (const ip of n.ips || []) dropped.add(ip);
    } else {
      const ips = (n.ips || []).filter((ip) => !suspectIps.has(ip) || realIps.has(ip));
      kept.push({ ...n, hosts: real, ips: ips.length ? ips : [...(n.ips || [])] });
    }
  }
  return { networks: kept, dropped };
}

/**
 * The raw `-t` / `-n` tokens the scanner proposed: the structured `result.cliTargets` /
 * `result.cliNames`. The `cliSuggestion` string is display text and never parsed.
 * @param {object} result ScanResult
 * @returns {{ targets: string[], names: string[] }}
 */
export function rawSweepTokens(result) {
  const r = result || {};
  return {
    targets: Array.isArray(r.cliTargets) ? r.cliTargets.map(String) : [],
    names: Array.isArray(r.cliNames) ? r.cliNames.map(String) : []
  };
}

/**
 * The `-t` targets and `-n` names of a ScanResult's CLI sweep, ready for lib/cmdline buildSweepCommand:
 * `-n` keeps only the proxied names the panel lists (no wildcard suspects); `-t` keeps what the
 * CLI can sweep — an IPv6 /48 (which the CLI refuses, failing the whole run) becomes the network's
 * known addresses, and networks of wildcard suspects are left out.
 *
 * Read from the structured `result.cliTargets` / `result.cliNames` only.
 * @param {object} result ScanResult
 * @param {{ names?: Iterable<string>|null, networks?: object[], dropped?: Set<string> }} [opts]
 * @returns {{ targets: string[], names: string[] }}
 */
export function originSweepTokens(result, { names = null, networks = [], dropped = new Set() } = {}) {
  const r = result || {};
  const allowed = names ? new Set(names) : null;
  const byCidr = new Map((networks || []).map((n) => [n.cidr, n]));
  // Zone File hand-off: the zone's exact origins are authoritative — never dropped with a wildcard
  // suspect's network, never widened — and its proxied names stay even when they are not a host
  // of this scan (a `*.x` name is no host). Empty without a zone, so the tokens are unchanged.
  const zone = zoneOfResult(r);
  const zoneTargets = new Set(zone ? zone.cliTargets : []);
  const zoneNames = new Set(zone ? zone.cliNames : []);
  const expandTarget = (tok) => {
    if (zoneTargets.has(tok)) return [tok];
    const ip = normalizeIP(tok);
    if (dropped.has(tok) || (ip && dropped.has(ip))) return [];
    if (sweepableTarget(tok)) return [tok];
    return ((byCidr.get(tok) || {}).ips || []).filter(sweepableTarget);
  };
  const raw = rawSweepTokens(r);
  const rawTargets = raw.targets;
  const rawNames = raw.names;
  const targets = [];
  const seenT = new Set();
  for (const tok of rawTargets) {
    for (const x of expandTarget(tok)) if (!seenT.has(x)) { seenT.add(x); targets.push(x); }
  }
  // The zone's host-name origins (`origin-lb.example.net`): exact host targets, after the addresses.
  for (const tok of zone ? zone.hostTargets : []) if (!seenT.has(tok)) { seenT.add(tok); targets.push(tok); }
  const outNames = [];
  const seenN = new Set();
  for (const name of rawNames) {
    if (allowed && !allowed.has(name) && !zoneNames.has(name)) continue;
    if (!seenN.has(name)) { seenN.add(name); outNames.push(name); }
  }
  return { targets, names: outNames };
}

/**
 * The CLI sweep command of a ScanResult, made safe to paste. Every token is validated and
 * shell-quoted by lib/cmdline.buildOriginSweepCommand — never string-glued — so a hostile name
 * can neither inject a shell command nor be read as a flag. The program is the downloaded file
 * (`python3 ssl_origin_scan.py`, or `python ssl_origin_scan.py` for PowerShell). Null when no
 * valid target or no valid name is left.
 * @param {object|null} result ScanResult
 * @param {{ names?: Iterable<string>|null, networks?: object[], dropped?: Set<string>,
 *   shell?: 'posix'|'powershell' }} [opts]
 * @returns {string|null}
 */
export function originCliCommand(result, { names = null, networks = [], dropped = new Set(), shell = 'posix' } = {}) {
  return originSweep(result, { names, networks, dropped, shell }).command;
}

/**
 * {@link originCliCommand} plus the files it may need. Above 200 names (or an 8,000-character
 * command) lib/cmdline puts `-n proxied-names.txt` in the command instead of the names; `namesFile`
 * is then that file's name and `namesText` its content (the validated proxied names, one per line)
 * for a download. When the targets alone still keep the command over 8,000 characters they go to
 * `proxied-targets.txt` as well (lib/cmdline buildFittedSweepCommand): `targetsFile`, `targetsText`
 * and `targetCount` are then present, likewise for a download. Only a command still over the cap
 * after that (very many exclusions) carries `overLength: true`, for a warning.
 * @param {object|null} result ScanResult
 * @param {{ names?: Iterable<string>|null, networks?: object[], dropped?: Set<string>,
 *   shell?: 'posix'|'powershell', exclude?: string[]|null }} [opts]
 * @returns {{ command: string|null, namesFile: string|null, namesText: string, count: number,
 *   targetsFile?: string, targetsText?: string, targetCount?: number, overLength?: true }}
 */
export function originSweep(result, { names = null, networks = [], dropped = new Set(), shell = 'posix', exclude = null } = {}) {
  const sh = SHELLS.includes(shell) ? shell : 'posix';
  const { targets, names: outNames } = originSweepTokens(result, { names, networks, dropped });
  // `exclude` (IPs / CIDRs the user pasted) is handed to lib/cmdline verbatim: it validates and
  // shell-quotes every token, emits `--exclude …`, drops a fully-covered target and reports an
  // exclusion that touches nothing. When null (the default) the command is byte-identical to before.
  const withExclude = exclude !== null && exclude !== undefined;
  const opts = { targets, names: outNames, script: 'ssl_origin_scan.py', shell: sh };
  // A zone run keeps its host targets and `*.x` names (lib/cmdline opt-ins, off otherwise).
  if (zoneOfResult(result)) Object.assign(opts, { allowHostTargets: true, allowWildcardNames: true });
  if (withExclude) opts.exclude = exclude;
  const sweep = buildFittedSweepCommand(opts);
  // Report the exclusions' effect only when they were requested, so a call without `exclude` keeps
  // its earlier return shape byte-for-byte.
  const report = withExclude ? {
    // `emitted`: excludes written as `--exclude …` (they overlap a remaining target);
    // `excluded`: targets a rule covered entirely, so they dropped out of `-t`;
    // `excludeUnused`: rules that touched no target; `excludeDropped`: invalid tokens.
    emitted: sweep.exclude || [],
    excluded: sweep.excluded || [],
    excludeUnused: sweep.excludeUnused || [],
    excludeDropped: (sweep.dropped && sweep.dropped.exclude) || [],
    droppedTargets: Math.max(0, targets.length - sweep.targets.length)
  } : {};
  if (!sweep.command) return { command: null, namesFile: null, namesText: '', count: 0, ...report };
  // Present only when the targets went to a file or the command is still too long, so a command
  // that fits keeps its earlier return shape.
  const targetsFile = sweep.targetsInline === false && sweep.targetsFile
    ? { targetsFile: sweep.targetsFile, targetsText: `${sweep.targets.join('\n')}\n`, targetCount: sweep.targets.length }
    : {};
  return {
    command: `${PYTHON_FOR_SHELL[sh]} ${sweep.command}`,
    namesFile: sweep.namesInline ? null : sweep.namesFile,
    namesText: sweep.namesInline ? '' : `${sweep.names.join('\n')}\n`,
    count: sweep.names.length,
    ...targetsFile,
    ...(sweep.overLength ? { overLength: true } : {}),
    ...report
  };
}

/** A host the ORIGIN panel lists: its origin is hidden (a proxy / CDN), and it is no wildcard suspect. */
const isProxiedOriginHost = (x) => !!(x && !x.wildcardSuspect && x.classification && x.classification.hidesOrigin);

/**
 * Everything the ORIGIN panel shows, derived from a ScanResult: per proxied host its
 * resolver-leak and history candidates (from the structured reason fields, never parsed text)
 * and the origin networks, the origin networks themselves (without wildcard suspects), the other
 * (general) origin hints and the ready-to-run CLI sweep command in both shells.
 * @param {object|null} result ScanResult
 * @returns {{ proxied: Array<{ name: string, host: object, leaks: Array<{ ip: string, resolver: string }>,
 *   history: Array<{ ip: string, source: string, lastSeen: string }>, networks: string[] }>, networks: object[],
 *   leakCount: number, historyCount: number, general: object[], command: string|null,
 *   commands: { posix: string|null, powershell: string|null },
 *   namesFiles: { posix: { file: string, text: string, count: number }|null, powershell: object|null },
 *   droppedCount: number }}
 */
export function originOverview(result) {
  const r = result || {};
  const hosts = Array.isArray(r.hosts) ? r.hosts : [];
  const hints = Array.isArray(r.originHints) ? r.originHints : [];
  const { networks, dropped } = realOriginNetworks(r.originNetworks, hosts);
  const cidrs = new Set(networks.map((n) => n.cidr));
  const proxied = hosts.filter(isProxiedOriginHost).map((host) => {
    const zone = [];
    const leaks = [];
    const history = [];
    for (const hint of hints) {
      for (const reason of hint.reasons || []) {
        const fields = reasonHost(reason);
        if (!fields.host || fields.host !== host.name) continue;
        if (reason.kind === 'zone') {
          // The imported zone file's exact origin of this host: shown first, before any candidate.
          if (!zone.some((z) => z.ip === hint.ip)) zone.push({ ip: hint.ip });
        } else if (reason.kind === 'resolver-leak') {
          if (!leaks.some((l) => l.ip === hint.ip)) {
            leaks.push({ ip: hint.ip, resolver: (getResolver(fields.resolver) || { name: fields.resolver || '' }).name });
          }
        } else if (reason.kind === 'history') {
          if (!history.some((x) => x.ip === hint.ip)) {
            history.push({ ip: hint.ip, source: fields.source || '', lastSeen: fields.lastSeen || '' });
          }
        }
      }
    }
    const candidates = Array.isArray(host.candidateNetworks) ? host.candidateNetworks.filter((c) => cidrs.has(c)) : [];
    // Cross-brand candidates (engine v3): the exact same left-most label published as a DNS-only
    // host on a sister domain scanned together. Read from the structured originCandidates, never
    // parsed from text; deduped by IP.
    const siblings = [];
    for (const c of Array.isArray(host.originCandidates) ? host.originCandidates : []) {
      if (c && c.kind === 'sibling-domain' && c.ip && !siblings.some((s) => s.ip === c.ip)) {
        siblings.push({ ip: c.ip, sibling: (c.evidence && c.evidence.sibling) || '' });
      }
    }
    return { name: host.name, host, zone, leaks, history, siblings, networks: candidates };
  });
  const inNetworks = new Set(networks.flatMap((n) => (Array.isArray(n.ips) ? n.ips : [])));
  // General hints (SPF / MX / siblings). A sibling-only hint whose IP an origin network already
  // lists adds nothing: the network card shows it with its names.
  const general = hints.filter((hint) => {
    // Host-specific kinds (resolver-leak / history / sibling-domain / zone) are shown per proxied
    // host, not as a general candidate for every host.
    const kinds = (hint.reasons || []).map((x) => x.kind).filter((k) => !HOST_SPECIFIC_HINT_KINDS.has(k));
    if (!kinds.length) return false;
    return !(kinds.every((k) => k === 'direct-sibling') && inNetworks.has(hint.ip));
  });
  const proxiedNames = proxied.map((p) => p.name);
  const sweeps = Object.fromEntries(SHELLS.map((sh) => [sh, originSweep(r, { names: proxiedNames, networks, dropped, shell: sh })]));
  const commands = Object.fromEntries(SHELLS.map((sh) => [sh, sweeps[sh].command]));
  // The names file a long command reads its `-n` names from (null when they are inline).
  const namesFiles = Object.fromEntries(SHELLS.map((sh) => [sh, sweeps[sh].namesFile
    ? { file: sweeps[sh].namesFile, text: sweeps[sh].namesText, count: sweeps[sh].count } : null]));
  // Honest "left out because invalid" count: tokens the scanner proposed that are not a valid
  // IP / CIDR / hostname (a defence-in-depth signal — the scanner should never emit any).
  const raw = rawSweepTokens(r);
  const droppedCount = validateTargets(raw.targets).dropped.length
    + validateNames(raw.names, { allowWildcard: !!zoneOfResult(r) }).dropped.length;
  return {
    proxied,
    networks,
    zoneCount: proxied.filter((p) => p.zone.length).length,
    leakCount: proxied.filter((p) => p.leaks.length).length,
    historyCount: proxied.filter((p) => p.history.length).length,
    siblingCount: proxied.filter((p) => p.siblings.length).length,
    // Any candidate network in known shared cloud / hosting / CDN space (offline provider check):
    // the panel warns the user to sweep only addresses they operate.
    shared: networks.some((n) => n.shared),
    general,
    command: commands.posix,
    commands,
    namesFiles,
    droppedCount
  };
}

/**
 * The sweep the ORIGIN panel shows: {@link originOverview}'s proxied names and origin networks,
 * for one shell, with the exclusions typed into the panel (null: none — the command is then
 * originOverview's, byte for byte). The JSON export reads the same, so the two never drift apart.
 * @param {object|null} result ScanResult
 * @param {{ shell?: 'posix'|'powershell', exclude?: string[]|null }} [opts]
 * @returns {ReturnType<typeof originSweep>}
 */
export function originSweepFor(result, { shell = 'posix', exclude = null } = {}) {
  const r = result || {};
  const hosts = Array.isArray(r.hosts) ? r.hosts : [];
  const { networks, dropped } = realOriginNetworks(r.originNetworks, hosts);
  return originSweep(r, { names: hosts.filter(isProxiedOriginHost).map((x) => x.name), networks, dropped, shell, exclude });
}

/**
 * The `origin` block of the JSON export: the networks and the POSIX command the ORIGIN panel shows
 * (no wildcard suspects, no IPv6 /48), with the panel's exclusions applied — whoever runs the
 * exported command never probes an address the user excluded — and what they did (`exclude`).
 * @param {object|null} result ScanResult
 * @param {string[]} [exclude] the tokens typed into the panel's Exclude box
 * @returns {{ networks: object[], hints: object[], cliSuggestion: string|null,
 *   exclude: { requested: string[], emitted: string[], excluded: string[], unused: string[], invalid: string[] }|null }}
 */
export function originExport(result, exclude = []) {
  const r = result || {};
  const tokens = Array.isArray(exclude) && exclude.length ? exclude.map(String) : null;
  const sweep = originSweepFor(r, { shell: 'posix', exclude: tokens });
  return {
    networks: realOriginNetworks(r.originNetworks, r.hosts).networks,
    hints: r.originHints || [],
    cliSuggestion: sweep.command,
    exclude: tokens
      ? { requested: tokens, emitted: sweep.emitted, excluded: sweep.excluded, unused: sweep.excludeUnused, invalid: sweep.excludeDropped }
      : null
  };
}

/**
 * The zone part of a ScanResult (Zone File hand-off), normalised: the zone's exact origin
 * addresses, host-name origins and proxied names that went into the CLI command. Null for a
 * scan without a zone.
 * @param {object|null} result ScanResult
 * @returns {{ cliTargets: string[], cliNames: string[], hostTargets: string[], exact: boolean }|null}
 */
export function zoneOfResult(result) {
  const z = result && result.zone;
  if (!z || typeof z !== 'object') return null;
  const list = (v) => (Array.isArray(v) ? v.map(String) : []);
  return {
    cliTargets: list(z.cliTargets),
    cliNames: list(z.cliNames),
    hostTargets: list(Array.isArray(result.cliHostTargets) ? result.cliHostTargets : z.cliHostTargets),
    exact: z.exact === true
  };
}

/** How a scan uses an imported zone file: its names only, added to discovery, or not at all. */
export const ZONE_MODES = Object.freeze(['exact', 'discover', 'off']);

/** A Zone File hand-off intent is honoured this long after its click (ms). */
export const ZONE_INTENT_MAX_AGE = 60000;

/**
 * The imported zone (`state.session.zone`, published by the Zone File view) when it belongs to
 * the typed domains: its origin equals one of them or sits under one. Null otherwise, and for
 * anything that is not the v1 zone scan-input shape.
 * @param {unknown} zone
 * @param {string[]} domains
 * @returns {object|null}
 */
export function zoneForDomains(zone, domains) {
  if (!zone || typeof zone !== 'object' || zone.v !== 1 || typeof zone.origin !== 'string') return null;
  const origin = normalizeHostname(zone.origin);
  if (!origin) return null;
  return (Array.isArray(domains) ? domains : []).some((d) => isSubdomainOf(origin, d)) ? zone : null;
}

/**
 * The name / exact-origin counts a zone chip shows.
 * @param {object} zone
 * @returns {{ names: number, origins: number }}
 */
export function zoneChipCounts(zone) {
  const z = zone || {};
  const c = z.counts && typeof z.counts === 'object' ? z.counts : {};
  const len = (v) => (Array.isArray(v) ? v.length : 0);
  return {
    names: Number.isFinite(c.names) ? c.names : len(z.names) + len(z.wildcardBases),
    origins: Number.isFinite(c.origins) ? c.origins : len(z.proxied)
  };
}

/**
 * Is a one-shot Zone File intent (`state.session.zoneScanIntent`) meant for this view and still
 * fresh, with the zone it refers to still loaded?
 * @param {unknown} intent
 * @param {'subdomains'|'scan'} target
 * @param {unknown} zone state.session.zone
 * @param {number} [now]
 * @returns {boolean}
 */
export function validZoneIntent(intent, target, zone, now = Date.now()) {
  if (!intent || typeof intent !== 'object' || intent.v !== 1 || intent.target !== target) return false;
  const age = now - Number(intent.at);
  if (!Number.isFinite(age) || age < 0 || age > ZONE_INTENT_MAX_AGE) return false;
  return !!(zone && typeof zone === 'object' && zone.v === 1);
}

/**
 * The runScan config of a zone mode, for ONE run (never saved to the stored options). `exact`:
 * the zone's names are the only seeds — no passive sources, wordlist, custom / learned labels,
 * permutations, deeper round or mining, so no quota is used. `discover`: the zone's names join a
 * normal scan as seeds. `off` / no zone: nothing (the scan runs exactly as before).
 * @param {object|null} zone
 * @param {string} mode one of {@link ZONE_MODES}
 * @returns {object}
 */
export function zoneScanOverrides(zone, mode) {
  if (!zone || !ZONE_MODES.includes(mode) || mode === 'off') return {};
  if (mode === 'discover') return { zone };
  return {
    zone, exact: true, sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false,
    learnedLabels: null, customWordlist: null
  };
}

/**
 * The "Zone file loaded" chip of Subdomains and SSL Targets: the counts, how this scan uses the
 * zone (scan exactly these names / include in discovery / leave out), a link to the Zone File
 * view and what the scan sends. The note follows the chosen mode in place (no re-render, so the
 * pressed button keeps focus).
 * @param {{ zone: object, mode: string, onMode: (mode: string) => void, href: string, className?: string }} opts
 * @returns {HTMLElement}
 */
export function ZoneChip({ zone, mode, onMode, href, className = '' }) {
  const counts = zoneChipCounts(zone);
  const note = h('p', { class: 'sub-zone-note text-sm', attrs: { 'aria-live': 'polite' } });
  const setNote = (m) => {
    note.textContent = t(`sub.zone.note.${m}`);
    note.dataset.mode = m;
  };
  const current = ZONE_MODES.includes(mode) ? mode : 'discover';
  const seg = SegmentedControl({
    label: t('sub.zone.mode'),
    size: 'sm',
    className: 'sub-zone-mode',
    value: current,
    options: ZONE_MODES.map((m) => ({ value: m, label: t(`sub.zone.mode.${m}`), title: t(`sub.zone.mode.${m}Title`) })),
    onChange: (m) => {
      setNote(m);
      if (onMode) onMode(m);
    }
  });
  setNote(current);
  const label = typeof zone.label === 'string' && zone.label ? zone.label : '';
  return h('div', { class: ['sub-zone', className], dataset: { role: 'zone-chip', origin: String(zone.origin || '') } },
    h('div', { class: 'sub-zone-head' },
      Icon('file-text', { size: 15 }),
      h('span', { class: 'sub-zone-title', title: label || null }, t('sub.zone.chip', { count: counts.names, origins: counts.origins })),
      h('a', { class: 'sub-zone-open', href, dataset: { action: 'zone-open' } }, t('sub.zone.open'))),
    seg.el,
    note,
    h('p', { class: 'sub-zone-privacy text-xs' }, Icon('lock', { size: 12 }), h('span', null, t('sub.zone.privacy'))));
}

/** A names hand-off (Reverse DNS → "Add names to a scan") is honoured this long after its click (ms). */
export const NAMES_INTENT_MAX_AGE = 60000;
/** Most names one hand-off brings (a /22 sweep has at most 1,024 addresses, a few names each). */
export const NAMES_HANDOFF_MAX = 4000;

/**
 * The names a one-shot hand-off (`state.session.namesScanIntent`, set by the Reverse DNS view)
 * brings to this view, or null when the intent is stale, meant for another view or holds no
 * valid host name. The names are re-validated here (they come from PTR records, untrusted).
 * @param {unknown} intent `{ v: 1, target: 'subdomains', source, names, domains, label, mode, at }`
 * @param {number} [now]
 * @returns {{ names: string[], domains: string[], label: string, source: string, mode: 'exact'|'discover' }|null}
 */
export function namesFromIntent(intent, now = Date.now()) {
  if (!intent || typeof intent !== 'object' || intent.v !== 1 || intent.target !== 'subdomains') return null;
  const age = now - Number(intent.at);
  if (!Number.isFinite(age) || age < 0 || age > NAMES_INTENT_MAX_AGE) return null;
  const names = parseHostList(Array.isArray(intent.names) ? intent.names.map(String).join('\n') : '').valid.slice(0, NAMES_HANDOFF_MAX);
  if (!names.length) return null;
  const domains = parseTargets(Array.isArray(intent.domains) ? intent.domains.map(String).join('\n') : '').domains;
  return {
    names,
    domains,
    label: String(intent.label || '').replace(/[\r\n]+/g, ' ').slice(0, 160),
    source: String(intent.source || 'ptr'),
    mode: intent.mode === 'discover' ? 'discover' : 'exact'
  };
}

/**
 * The runScan config of a names hand-off, for ONE run: `exact` resolves the names (and the
 * typed domains) only — no passive sources, wordlist, custom / learned labels, permutations or
 * mining, so no quota is used; `discover` adds them as starting names; `off` / none: nothing.
 * @param {{ names: string[], mode: string }|null} handoff
 * @returns {object}
 */
export function handoffScanOverrides(handoff) {
  if (!handoff || !ZONE_MODES.includes(handoff.mode) || handoff.mode === 'off') return {};
  if (handoff.mode === 'discover') return {};
  return {
    exact: true, sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false,
    learnedLabels: null, customWordlist: null
  };
}

/**
 * The part of a names hand-off that belongs to the typed domains: its names equal to or under
 * one of them. A scan of another domain never gets these names, nor their exact mode (like the
 * Zone File chip, {@link zoneForDomains}). Null when no name belongs to the typed domains.
 * @param {{ names: string[], mode: string }|null} handoff `session.handoff` ({@link namesFromIntent})
 * @param {string[]} domains the typed domains (parseTargets().domains)
 * @returns {{ names: string[], mode: string, total: number }|null} `names`: the ones this scan uses,
 *   `total`: all the hand-off holds (the rest wait for their own domains)
 */
export function handoffForDomains(handoff, domains) {
  if (!handoff || !Array.isArray(handoff.names)) return null;
  const typed = (Array.isArray(domains) ? domains : []).filter((d) => typeof d === 'string' && d);
  const names = handoff.names.filter((n) => typed.some((d) => isSubdomainOf(n, d)));
  return names.length ? { ...handoff, names, total: handoff.names.length } : null;
}

/**
 * The "names from the reverse DNS sweep" chip: the count, how this scan uses them (exactly these
 * names / include in discovery / leave out, ZONE_MODES), a way back to the Reverse DNS view and a
 * remove button. The note follows the chosen mode in place. `applied` ({@link handoffForDomains}
 * for the typed domains): null says the names wait for their own domains (this scan does not use
 * them), fewer names than the chip holds say how many this scan uses.
 * @param {{ handoff: { names: string[], domains?: string[], label: string, mode: string }, applied?: { names: string[] }|null,
 *   onMode: (mode: string) => void, onRemove: () => void, href: string }} opts
 * @returns {HTMLElement}
 */
export function NamesChip({ handoff, applied = null, onMode, onRemove, href }) {
  const note = h('p', { class: 'sub-zone-note text-sm', attrs: { 'aria-live': 'polite' } });
  const setNote = (m) => {
    note.textContent = t(`sub.handoff.note.${m}`);
    note.dataset.mode = m;
  };
  const current = ZONE_MODES.includes(handoff.mode) ? handoff.mode : 'exact';
  const seg = SegmentedControl({
    label: t('sub.handoff.mode'),
    size: 'sm',
    className: 'sub-zone-mode',
    value: current,
    options: ZONE_MODES.map((m) => ({ value: m, label: t(`sub.handoff.mode.${m}`), title: t(`sub.handoff.mode.${m}Title`) })),
    onChange: (m) => {
      setNote(m);
      if (onMode) onMode(m);
    }
  });
  setNote(current);
  const domains = Array.isArray(handoff.domains) && handoff.domains.length
    ? handoff.domains
    : [...new Set(handoff.names.map((n) => registrableDomain(n) || n))].slice(0, 5);
  let scope = null;
  if (!applied) {
    scope = h('p', { class: 'sub-handoff-scope text-sm', dataset: { scope: 'elsewhere' } }, Icon('info', { size: 13 }),
      h('span', null, t('sub.handoff.elsewhere', { domains: domains.join(', ') })));
  } else if (applied.names.length < handoff.names.length) {
    scope = h('p', { class: 'sub-handoff-scope text-sm', dataset: { scope: 'partial' } }, Icon('info', { size: 13 }),
      h('span', null, t('sub.handoff.partial', { count: applied.names.length, total: formatNumber(handoff.names.length) })));
  }
  return h('div', { class: 'sub-zone sub-handoff', dataset: { role: 'names-chip', count: String(handoff.names.length), applies: applied ? '1' : '0' } },
    h('div', { class: 'sub-zone-head' },
      Icon('swap', { size: 15 }),
      h('span', { class: 'sub-zone-title', title: handoff.names.slice(0, 20).join(', ') }, t('sub.handoff.chip', { count: handoff.names.length, label: handoff.label || '—' })),
      h('a', { class: 'sub-zone-open', href, dataset: { action: 'names-open' } }, t('sub.handoff.open')),
      Button({ label: t('sub.handoff.remove'), icon: 'x', size: 'sm', variant: 'ghost', className: 'sub-handoff-remove', dataset: { action: 'names-remove' }, onClick: () => onRemove && onRemove() })),
    scope,
    seg.el,
    note);
}

/**
 * The structured fields of an origin-hint reason: the proxied host it is about, and the
 * resolver (resolver-leak) or the source and last-seen date (history). The human-readable
 * `detail` is display text for logs and is never parsed.
 * @param {{ kind?: string, host?: string, resolver?: string, source?: string, lastSeen?: string, detail?: string }} reason
 * @returns {{ host: string|null, resolver: string|null, source: string|null, lastSeen: string|null }}
 */
export function reasonHost(reason) {
  const r = reason || {};
  const str = (v) => (typeof v === 'string' && v ? v : null);
  return { host: str(r.host), resolver: str(r.resolver), source: str(r.source), lastSeen: str(r.lastSeen) };
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
    // private mode / quota: the options are simply not remembered
  }
}

/**
 * Parallel-query limit handed to runScan for the Settings value: the bulk sweep rotates over
 * several resolvers, so it may use up to twice the setting (at most {@link MAX_SWEEP_CONCURRENCY};
 * the default 12 keeps the tested 24). A lower setting always means a gentler scan.
 * @param {number} setting state.settings.concurrency
 * @returns {number}
 */
export function scanConcurrency(setting) {
  const n = Math.floor(Number(setting));
  return Math.max(1, Math.min(MAX_SWEEP_CONCURRENCY, (Number.isFinite(n) && n > 0 ? n : 12) * 2));
}

/**
 * Which "only through DNS" sentence the technique summary may show (i18n key), or null. The
 * plain claim (no queried source returned the names) needs every selected source to have
 * answered completely; with a source off-quota, down, cut at its page limit or partial the
 * qualified sentence is used, and with no passive source at all nothing is claimed.
 * @param {number} count names found only by DNS discovery
 * @param {string[]} sources source ids selected for the scan
 * @param {object[]} health lib/sources.sourceHealthSummary() of the scan
 * @returns {'sub.tech.dnsOnly'|'sub.tech.dnsOnlyIncomplete'|null}
 */
export function dnsOnlyNoteKey(count, sources, health) {
  if (!(Number(count) > 0) || !Array.isArray(sources) || !sources.length) return null;
  const list = Array.isArray(health) ? health : [];
  const complete = sources.every((sid) => {
    const hl = list.find((x) => x && x.source === sid);
    return !!hl && (hl.state === 'ok' || hl.state === 'empty') && !hl.truncated;
  });
  return complete ? 'sub.tech.dnsOnly' : 'sub.tech.dnsOnlyIncomplete';
}

/**
 * Row predicate of the subdomain table for a filter, or null when nothing is hidden. Whether
 * wildcard suspects are shown is read from `prefs.showWildcard` for every row, so suspects that
 * stream in after the filter was chosen are hidden like the ones already listed.
 * @param {string} filter one of {@link FILTERS}
 * @param {{ showWildcard: boolean }} prefs live preferences (the session)
 * @param {object[]} hosts the hosts listed so far
 * @returns {((host: object) => boolean)|null}
 */
export function hostTableFilter(filter, prefs, hosts) {
  const f = FILTERS.includes(filter) ? filter : 'all';
  if (f === 'all' && (prefs.showWildcard || !(hosts || []).some((x) => x && x.wildcardSuspect))) return null;
  return (x) => (prefs.showWildcard || !x.wildcardSuspect) && matchesFilter(x, f);
}

/**
 * Record a scanner stage event on a run (shared by Subdomains and SSL Targets): the running
 * stage is done, the new one active (or skipped). DNS-record mining runs alongside the passive
 * sources; when it already finished while they ran, its pill stays done.
 * @param {{ stages: object, progress: object, config?: object, sourcePlan?: object, miningProgress?: object }} run
 * @param {string} stage
 * @param {object} [info]
 */
export function applyStage(run, stage, info = {}) {
  for (const s of SCAN_STAGES) if (s !== stage && run.stages[s] && run.stages[s].state === 'active') run.stages[s].state = 'done';
  const early = stage === 'mining' ? run.miningProgress : null;
  const finishedEarly = !!(early && early.total > 0 && early.done >= early.total);
  run.stages[stage] = { state: stage === 'done' || finishedEarly ? 'done' : info.skipped ? 'skipped' : 'active', info };
  if (stage === 'sources') run.sourcePlan = { domains: info.domains || [], sources: info.sources || [] };
  // Honesty (task 6, engine v3): the DNS sweep starts (wildcard stage) while slow passive sources
  // (crt.sh can back off for a while) may still be fetching. Record them so the UI can say
  // "crt.sh still fetching" instead of painting the grace wait as another stage. Cleared at finish.
  if (stage === 'wildcard') {
    run.sourceWait = Array.isArray(info.sourcesStillRunning) && info.sourcesStillRunning.length
      ? { sources: [...info.sourcesStillRunning], cutOff: !!info.sourcesCutOff }
      : null;
  }
  run.rounds = null;
  run.progress = early ? { stage, done: early.done, total: early.total } : { stage, done: 0, total: Number(info.total) || 0 };
}

/**
 * Record a scanner progress event on a run. While the passive sources run, the parallel
 * DNS-record mining only moves its own pill (the bar keeps showing the sources instead of
 * jumping to "100 %" and back). The deeper (recursive) round reports as 'permutations' again
 * from 0: the finished rounds are added so the bar never runs backwards, and the permutation
 * pill learns its candidate count from the total.
 * @param {object} run
 * @param {{ stage: string, done: number, total: number }} p
 * @returns {boolean} true when a stage pill changed (re-render the pills)
 */
export function applyProgress(run, p) {
  const stage = p && p.stage;
  const done = Math.max(0, Number(p && p.done) || 0);
  const total = Math.max(0, Number(p && p.total) || 0);
  if (stage === 'mining' && run.stages.sources && run.stages.sources.state === 'active') {
    run.miningProgress = { done, total };
    const next = total > 0 && done >= total ? 'done' : 'active';
    const changed = !run.stages.mining || run.stages.mining.state !== next;
    run.stages.mining = { state: next, info: run.stages.mining ? run.stages.mining.info : null };
    return changed;
  }
  let shown = { stage, done, total };
  if (stage === 'permutations') {
    const r = run.rounds && run.rounds.stage === stage ? run.rounds : { stage, base: 0, lastDone: 0, lastTotal: total };
    if (total !== r.lastTotal || done < r.lastDone) r.base += r.lastTotal;
    r.lastDone = done;
    r.lastTotal = total;
    run.rounds = r;
    shown = { stage, done: r.base + done, total: r.base + total };
  }
  run.progress = shown;
  const st = run.stages[stage];
  if (stage === 'permutations' && st && st.state === 'active' && st.candidates !== shown.total) {
    st.candidates = shown.total;
    return true;
  }
  return false;
}

/**
 * A cancelled or failed run: the stage that was running is marked 'stopped' (no pulsing dot,
 * no aria-current) instead of staying 'active' forever.
 * @param {{ stages: object }} run
 */
export function stopStages(run) {
  for (const s of SCAN_STAGES) if (run.stages[s] && run.stages[s].state === 'active') run.stages[s].state = 'stopped';
}

/** Does the host have at least one IP address? */
export function isResolving(host) {
  const r = host && host.resolution;
  return !!(r && ((r.ipv4 && r.ipv4.length) || (r.ipv6 && r.ipv6.length)));
}

/**
 * Does a host match a table filter?
 * @param {object} host HostRecord
 * @param {string} filter one of {@link FILTERS}
 * @returns {boolean}
 */
export function matchesFilter(host, filter) {
  const c = (host && host.classification) || {};
  switch (filter) {
    case 'resolving': return isResolving(host);
    case 'cloudflare': return c.kind === 'cloudflare';
    case 'cdn': return c.kind === 'cdn' || c.kind === 'platform';
    case 'direct': return c.kind === 'direct' || c.kind === 'private';
    case 'unresolved': return c.kind === 'unresolved' || c.kind === 'nxdomain';
    case 'dangling': return !!c.dangling;
    default: return true;
  }
}

/**
 * Counters for the stat cards. Wildcard suspects are counted separately (`wildcard`) and,
 * unless `includeWildcard`, left out of every other number.
 * @param {object[]} hosts
 * @param {{ includeWildcard?: boolean }} [opts]
 * @returns {{ found: number, resolving: number, cloudflare: number, cdn: number, direct: number, private: number,
 *   unresolved: number, dangling: number, onServers: number, wildcard: number }}
 */
export function countHosts(hosts, { includeWildcard = false } = {}) {
  const c = { found: 0, resolving: 0, cloudflare: 0, cdn: 0, direct: 0, private: 0, unresolved: 0, dangling: 0, onServers: 0, wildcard: 0 };
  for (const x of hosts || []) {
    if (x.wildcardSuspect) {
      c.wildcard += 1;
      if (!includeWildcard) continue;
    }
    c.found += 1;
    if (isResolving(x)) c.resolving += 1;
    for (const f of ['cloudflare', 'cdn', 'direct', 'unresolved', 'dangling']) if (matchesFilter(x, f)) c[f] += 1;
    if (x.classification && x.classification.kind === 'private') c.private += 1;
    if (matchesFilter(x, 'direct') && x.servers && x.servers.length) c.onServers += 1;
  }
  return c;
}

/**
 * Aggregate the per-domain SourceResults of one source into a chip state.
 * @param {object[]} results
 * @param {string} sourceId
 * @param {number} expected number of domains queried
 * @returns {{ state: 'pending'|'ok'|'partial'|'error', names: number, done: number, expected: number,
 *   errorKind: string|null, error: string|null }}
 */
export function sourceChipState(results, sourceId, expected) {
  const mine = (results || []).filter((r) => r.source === sourceId);
  const names = new Set();
  mine.forEach((r) => (r.names || []).forEach((n) => names.add(n)));
  const failed = mine.filter((r) => !r.ok);
  const partial = mine.some((r) => r.ok && r.partial);
  let state = 'pending';
  if (expected > 0 && mine.length >= expected) {
    if (failed.length === mine.length) state = 'error';
    else if (failed.length || partial) state = 'partial';
    else state = 'ok';
  }
  const err = failed[0] || mine.find((r) => r.partial) || null;
  return { state, names: names.size, done: mine.length, expected, errorKind: err ? err.errorKind : null, error: err ? err.error : null };
}

/**
 * The hostnames of a list, one per line, sorted like the table (siblings together), with a
 * trailing newline ('' for an empty list).
 * @param {object[]} hosts
 * @returns {string}
 */
export function namesText(hosts) {
  const list = sortHostnames([...new Set((hosts || []).map((x) => x && x.name).filter(Boolean))]);
  return list.length ? `${list.join('\n')}\n` : '';
}

/** Sort key that groups siblings (reversed labels). */
function hostSortKey(name) {
  return String(name || '').split('.').reverse().join('.');
}

/**
 * A host name as text runs that wrap only after a dot (lib/subtabs.hostSegments): each label is
 * one unbreakable run (`.sub-seg`) with a <wbr> before the next, so a narrow cell never splits
 * `old-shop` at its hyphen. A label too long to keep is plain text, which the name's
 * `overflow-wrap: anywhere` breaks where it must. The text (and a copy of it) is the name, unchanged.
 * @param {string} name
 * @returns {Array<Node|string>}
 */
export function hostNameNodes(name) {
  const out = [];
  for (const seg of hostSegments(name)) {
    if (out.length) out.push(h('wbr'));
    out.push(seg.keep ? h('span', { class: 'sub-seg' }, seg.text) : seg.text);
  }
  return out;
}

function sourceNote(source) {
  const key = `sub.src.${source.id}`;
  return hasString(key, 'en') ? t(key) : source.quota || '';
}

function sameTargets(a, b) {
  return [...(a || [])].sort().join(',') === [...(b || [])].sort().join(',');
}

/**
 * What a route does on arrival: a shared link (`run=1`) with targets gets the one-click
 * "Start scan" prompt — never an automatic scan — unless this page is scanning already or
 * already has that scan; anything else only pre-fills the box.
 * @param {Record<string, string>} params route params
 * @param {string[]} targets domains from the route
 * @param {{ status: string, config: { domains: string[] } }|null} run the page's current run
 * @returns {'prompt'|null}
 */
export function linkAction(params, targets, run) {
  if (!params || params.run !== '1' || !Array.isArray(targets) || !targets.length) return null;
  if (run && (run.status === 'running' || sameTargets(run.config.domains, targets))) return null;
  return 'prompt';
}

/**
 * What the Zone File view's "Scan now" does on arrival: start the zone scan, or — while another
 * scan runs — wait for it ('wait': the page says so and offers to cancel it). Null when that very
 * zone scan is the one running: same domains, same mode and the same imported zone (a zone file
 * imported again is another scan).
 * @param {{ status: string, zone?: object|null, config: { domains: string[], zoneMode?: string|null } }|null} run the page's current run
 * @param {string[]} domains the domains of the zone scan
 * @param {string} mode its zone mode (one of {@link ZONE_MODES})
 * @param {object|null} [zone] the zone it scans (state.session.zone)
 * @returns {'start'|'wait'|null}
 */
export function zoneStartAction(run, domains, mode, zone = null) {
  if (!run || run.status !== 'running') return 'start';
  const same = sameTargets(run.config.domains, domains) && (run.config.zoneMode || 'off') === mode
    && (run.zone || null) === (mode === 'off' ? null : zone || null);
  return same ? null : 'wait';
}

/** "Fastly, Vercel" — providers of the CDN / platform hosts (at most 3). */
function providerHint(hosts) {
  const names = [];
  for (const x of hosts || []) {
    const c = x.classification || {};
    if (x.wildcardSuspect || !(c.kind === 'cdn' || c.kind === 'platform') || !c.provider) continue;
    if (!names.includes(c.provider.name)) names.push(c.provider.name);
    if (names.length > 3) break;
  }
  if (!names.length) return null;
  return names.length > 3 ? `${names.slice(0, 3).join(', ')}…` : names.join(', ');
}

/** Schedule `fn` at most once per animation frame. */
function frameThrottle(fn) {
  let queued = false;
  const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
  return () => {
    if (queued) return;
    queued = true;
    raf(() => {
      queued = false;
      fn();
    });
  };
}

/** Call `fn` at most every `ms` milliseconds (the last call always runs). */
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
/* Scan runs (module-owned: they outlive a mounted view)                    */
/* ------------------------------------------------------------------------ */

/**
 * Search box, filters and the current / last run, kept for this page session. `carried`: the text
 * the box last took from a target carried over from another tool (a newer one replaces it while
 * the box still holds it, lib/session.js fillReplaces); a scan forgets it.
 */
const session = {
  text: '',
  carried: null,
  extraText: '',
  advancedOpen: false,
  filter: 'all',
  showWildcard: false,
  resolvingOnly: false,
  originShell: 'posix',
  // The results tab the user chose for the current run (null: automatic, lib/subtabs.autoSubTab).
  tab: null,
  run: null,
  /** Names handed over by the Reverse DNS view ({@link namesFromIntent}), kept until removed. */
  handoff: null
};

/**
 * The ORIGIN panel's exclusions of each run (`{ raw, tokens }`), kept for the page session so a
 * re-mount (another view and back, a language switch) keeps them; keyed by the run object, so a
 * new scan starts without any and an old run goes with its own.
 */
const originExcludes = new WeakMap();

/**
 * How the next scan uses each imported zone ('exact' | 'discover' | 'off'), keyed by the zone
 * object in state.session.zone — a forgotten zone drops out with its key (nothing kept by value).
 */
const zoneModes = new WeakMap();
let runCounter = 0;
/** The mounted view (null while another tool is shown). */
let active = null;

/** The domains of the page's last scan, or null (what a carried domain may replace, lib/session.js). */
const lastRunDomains = () => (session.run ? session.run.config.domains : null);
/** The domains the search box holds, as a scan reads them. */
const boxDomains = (text) => parseTargets(text).domains;

/** Forget the search box and the last scan, stopping one that runs ("Delete all local data"). */
function forgetRuns() {
  const run = session.run;
  if (run && run.status === 'running') run.controller.abort();
  session.run = null;
  session.text = '';
  session.carried = null;
  session.extraText = '';
}

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
    // Streaming partials from hooks.onFound (a probe hit before the resolve stage builds the full
    // HostRecord). Keyed by name; a name is deleted here once its full record arrives via onHost,
    // so the two never double-count. Survives a view re-mount like `hosts` does.
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

/**
 * A cheap partial HostRecord for a streamed probe hit (hooks.onFound): enough for the results
 * table and the stat cards to show it live, marked `_partial` until the resolve stage replaces it
 * with the full record. AAAA, servers, origin candidates and inventory come with the full record.
 * @param {{ name: string, origin: string, status?: string, ipv4: string[], cnames: string[], classification: object }} p
 *   status: the probe's rcode (a dangling alias streams NXDOMAIN with its chain); NOERROR when absent
 * @returns {object} HostRecord-shaped
 */
export function partialHostRecord(p) {
  return {
    name: p.name,
    resolution: { ipv4: [...(p.ipv4 || [])], ipv6: [], cnames: [...(p.cnames || [])], status: p.status || 'NOERROR', resolver: null, ttl: null, error: null },
    classification: p.classification || { kind: 'direct', provider: null, dangling: false, hidesOrigin: false, reasonKey: 'class.direct' },
    origins: p.origin ? [p.origin] : [],
    servers: [],
    ipHints: [],
    candidateNetworks: [],
    originCandidates: [],
    wildcardSuspect: false,
    customOnly: false,
    _partial: true
  };
}

/**
 * The hosts to show while a run is live: the full records plus any streamed partials not yet
 * superseded by a full record of the same name (full always wins). After the run finishes the
 * result's hosts are authoritative.
 * @param {object} run
 * @returns {object[]}
 */
export function liveHosts(run) {
  if (run.result) return run.result.hosts;
  if (!run.found || !run.found.size) return run.hosts;
  const names = new Set(run.hosts.map((x) => x.name));
  const extra = [...run.found.values()].filter((x) => !names.has(x.name));
  return extra.length ? [...run.hosts, ...extra] : run.hosts;
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
 * Level counts are build-time constants now (lib/wordlist.wordlistInfo, verified against the
 * data files by a unit test there), so nothing needs to be loaded to show them; this resolves
 * immediately with the smart size. Kept as the shared entry point both views call once.
 * @returns {Promise<number>}
 */
export function ensureSmartCount() {
  return Promise.resolve(levelCount('smart'));
}

/**
 * Did a scan get less wordlist than it asked for (a tier or a locale pack failed to load)? In a
 * tab left open across a deploy the data files under v/<version>/ are gone, so both scan views
 * then ask the shell (ctx.checkOutdated) whether the page needs a reload.
 * @param {object} result runScan result
 * @returns {boolean}
 */
export function wordlistFellShort(result) {
  return !!result && Array.isArray(result.warnings) && result.warnings.some((w) => w && w.code === 'WORDLIST_DEGRADED');
}

/**
 * Start lib/scanner.runScan for a run; events are recorded on the run and re-emitted to the
 * mounted view (if any). `onDataMissing` (ctx.checkOutdated) runs when the wordlist fell short.
 */
function startRun(run, scanConfig, appState, onDataMissing) {
  const hooks = {
    onStage(stage, info = {}) {
      applyStage(run, stage, info);
      emit(run, 'stage', { stage, info });
    },
    onSource(result) {
      run.sourceResults.push(result);
      emit(run, 'source', result);
    },
    onHost(record) {
      run.hosts.push(record);
      // The full record supersedes any streamed partial of the same name.
      if (run.found.has(record.name)) run.found.delete(record.name);
      emit(run, 'host', record);
    },
    onFound(partial) {
      if (!partial || !partial.name) return;
      // Ignore a partial once the full record is in (a late duplicate); otherwise stream it live.
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
    if (wordlistFellShort(result) && onDataMissing) onDataMissing();
    // Bulk Resolve offers "use the names of the last scan".
    appState.setSession('scanHosts', {
      domains: result.domains,
      names: result.hosts.filter((x) => !x.wildcardSuspect).map((x) => x.name),
      // The names that really resolve (A/AAAA, no wildcard look-alike): the Zone File view's
      // "live, not in the file" comparison reads these.
      resolving: result.hosts.filter((x) => !x.wildcardSuspect && isResolving(x)).map((x) => x.name),
      finishedAt: run.finishedAt
    });
    // Learn the naming vocabulary of this scan (labels only, in this browser) so the next scan
    // tries it first; the mounted view refreshes its "learned names" count. Never throws.
    if (rememberLearned(result, run.config && run.config.learned) && active && active.refreshLearned) active.refreshLearned();
    emit(run, 'done', result);
    if (!active && session.run === run) {
      const count = result.hosts.filter((x) => !x.wildcardSuspect).length;
      toast(t('sub.doneToast', { count }), {
        type: 'success',
        timeout: 10000,
        action: {
          label: t('sub.showResults'),
          onClick: () => {
            globalThis.location.hash = '#/subdomains';
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

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Subdomains view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  const cleanups = [];
  let options = loadOptions();
  let lastBf = options.bruteforce !== 'off' ? options.bruteforce : 'smart';

  /* --- route params -------------------------------------------------------- */
  const fromRoute = routeTargets(ctx.searchParams, ctx.params);
  // A domain carried over from another tool (`run=0`) never replaces what the user typed: only an
  // empty box, the last scan's domains or the domain carried before.
  if (fromRoute.length && (!isFillOnly(ctx.params) || fillReplaces(session.text, lastRunDomains(), boxDomains, session.carried))) {
    session.text = fromRoute.join(', ');
    session.carried = isFillOnly(ctx.params) ? session.text : null;
  }

  /* --- Zone File hand-off ------------------------------------------------------ */
  // A one-shot intent from the Zone File view ("Scan now"): pre-fill the zone's domain, preset how
  // the zone is used and, for that in-app click, start the scan. Stale or foreign intents are
  // ignored; the zone itself stays in state.session.zone (memory only).
  const zoneIntent = state.takeSession('zoneScanIntent');
  const intentOk = validZoneIntent(zoneIntent, 'subdomains', state.getSession('zone'));
  if (intentOk) {
    if (!fromRoute.length && zoneIntent.domain) session.text = String(zoneIntent.domain);
    zoneModes.set(state.getSession('zone'), zoneIntent.mode === 'discover' ? 'discover' : 'exact');
  }

  /* --- names hand-off (Reverse DNS → "Add names to a scan") ------------------- */
  // A one-shot intent in memory only: the names, and how the next scans use them (exactly these
  // names by default). Nothing starts here — the user presses Scan; the chip stays until removed.
  const namesIntent = namesFromIntent(state.takeSession('namesScanIntent'));
  if (namesIntent) {
    session.handoff = namesIntent;
    if (!fromRoute.length && namesIntent.domains.length) session.text = namesIntent.domains.join(', ');
  }

  /* --- hero: search box ------------------------------------------------------ */
  const inputId = uid('sub-domain');
  const titleId = `${inputId}-title`;
  const domainField = textInput({
    id: inputId,
    value: session.text,
    placeholder: t('sub.input.placeholder'),
    hint: t('sub.input.hint'),
    mono: true,
    className: 'sub-search-field',
    attrs: { 'data-role': 'sub-domain', 'data-shortcut': 'focus', inputmode: 'url', enterkeyhint: 'search' },
    onInput: (value) => {
      session.text = value;
      domainField.setError(null);
      hideLinkPrompt();
      renderScope();
      renderZoneChip();
      renderDomainDependent();
    },
    onEnter: () => start()
  });
  // The plan count, the auto-locale line and the Advanced summary all follow the typed domain;
  // recompute them (debounced) on every keystroke without walking the whole thing per character.
  const renderDomainDependent = debounce(() => {
    renderPlan();
    renderWordlistLabel();
    if (options.locales === null) renderLangs();
    renderAdvSummary();
  }, 120);
  const runBtn = Button({ label: t('sub.run'), icon: 'search', variant: 'primary', size: 'lg', className: 'sub-run-btn', dataset: { action: 'sub-run', shortcut: 'submit' }, onClick: () => start() });
  const cancelBtn = Button({ label: t('sub.cancel'), icon: 'stop', variant: 'secondary', size: 'lg', className: 'sub-run-btn', dataset: { action: 'sub-cancel', shortcut: 'cancel' }, onClick: () => cancel() });
  cancelBtn.hidden = true;
  const scopeNote = h('div', { class: 'sub-scope text-sm', hidden: true });
  const formError = h('div', { class: 'sub-form-error' });
  // A shared link (`&run=1`) pre-fills the box and waits for one click: a link alone never
  // starts the scan's thousands of DNS queries and third-party source calls.
  const linkPrompt = h('div', { class: 'sub-link-prompt', hidden: true });
  // A Zone File "Scan now" that arrived while another scan was running waits for it, with its
  // prompt in the same place: `{ zone }` (the zone it scans), null when none waits. Hiding the
  // prompt drops it.
  let zoneStartAfter = null;

  function showLinkPrompt(domains) {
    clear(linkPrompt);
    linkPrompt.hidden = false;
    linkPrompt.append(Alert({
      variant: 'info',
      icon: 'link',
      compact: true,
      message: t('sub.link.prompt', { domains: domains.join(', ') }),
      actions: [Button({ label: t('sub.link.start'), icon: 'search', variant: 'primary', size: 'sm', dataset: { action: 'sub-link-start' }, onClick: () => start() })]
    }));
  }

  function showZoneBusyPrompt(zone) {
    zoneStartAfter = { zone };
    clear(linkPrompt);
    linkPrompt.hidden = false;
    const alert = Alert({
      variant: 'info',
      icon: 'file-text',
      compact: true,
      message: t('sub.zone.busy', { running: session.run.config.domains.join(', '), domain: parseTargets(domainField.value).domains.join(', ') }),
      actions: [
        Button({ label: t('sub.zone.busy.cancel'), icon: 'stop', variant: 'primary', size: 'sm', dataset: { action: 'sub-zone-cancel' }, onClick: () => cancel() }),
        Button({ label: t('sub.zone.busy.dismiss'), variant: 'secondary', size: 'sm', dataset: { action: 'sub-zone-dismiss' }, onClick: () => hideLinkPrompt() })
      ]
    });
    alert.dataset.prompt = 'zone-busy';
    linkPrompt.append(alert);
  }

  function hideLinkPrompt() {
    zoneStartAfter = null;
    clear(linkPrompt);
    linkPrompt.hidden = true;
  }

  // "Zone file loaded" chip: shown while the imported zone belongs to a typed domain.
  const zoneHost = h('div', { class: 'sub-zone-host', hidden: true });
  const activeZone = () => zoneForDomains(state.getSession('zone'), parseTargets(domainField.value).domains);
  let zoneShown = null;
  function renderZoneChip() {
    const zone = activeZone();
    // Unchanged zone: keep the chip (and the focus on its buttons) while the user types.
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
        renderPlan();
      }
    }));
  }

  // "Names from the reverse DNS sweep" chip: shown while a hand-off is kept; it says when the
  // typed domains use none or only some of its names (a scan uses only the names under them).
  const handoffHost = h('div', { class: 'sub-zone-host', hidden: true });
  const activeHandoff = () => handoffForDomains(session.handoff, parseTargets(domainField.value).domains);
  let handoffShown = null;
  function renderHandoff({ force = true } = {}) {
    const ho = session.handoff;
    const applied = activeHandoff();
    // Unchanged while the user types: keep the chip (and the focus on its buttons).
    const key = ho ? `${applied ? applied.names.length : -1}` : null;
    if (!force && handoffShown && handoffShown.ho === ho && handoffShown.key === key) return;
    handoffShown = { ho, key };
    clear(handoffHost);
    handoffHost.hidden = !ho;
    if (!ho) return;
    handoffHost.append(NamesChip({
      handoff: ho,
      applied,
      href: ctx.href('ptr'),
      onMode: (m) => {
        ho.mode = ZONE_MODES.includes(m) ? m : 'exact';
        renderPlan();
      },
      onRemove: () => {
        session.handoff = null;
        renderHandoff();
        renderPlan();
        domainField.focus();
      }
    }));
  }

  function renderScope() {
    renderZoneChip();
    renderHandoff({ force: false });
    clear(scopeNote);
    const { domains } = parseTargets(domainField.value);
    const scoped = domains.filter((d) => registrableDomain(d) && registrableDomain(d) !== d);
    scopeNote.hidden = !scoped.length;
    if (!scoped.length) return;
    const name = scoped[0];
    const reg = registrableDomain(name);
    scopeNote.append(Icon('filter', { size: 14 }), h('span', null, t('sub.scope', { name })),
      h('button', {
        type: 'button',
        class: 'link-btn',
        dataset: { action: 'sub-scope-all' },
        on: {
          click: () => {
            domainField.value = domainField.value.split(/([\s,;]+)/).map((part) => {
              const n = parseTargets(part).domains[0];
              return n === name ? reg : part;
            }).join('');
            session.text = domainField.value;
            renderScope();
            domainField.focus();
          }
        }
      }, t('sub.scopeAll', { domain: reg })));
  }

  const examples = h('div', { class: 'sub-examples' },
    h('span', { class: 'sub-examples-label' }, t('sub.examples')),
    EXAMPLES.map((d) => h('button', {
      type: 'button',
      class: 'sub-example mono',
      dataset: { example: d },
      on: {
        click: () => {
          if (isRunning()) return;
          domainField.value = d;
          session.text = d;
          domainField.setError(null);
          renderScope();
          start();
        }
      }
    }, d)));

  /* --- quick toggle + advanced options ---------------------------------------- */
  const wordlistLabel = h('span');
  const wordlistSwitch = checkbox({
    label: wordlistLabel,
    switch: true,
    checked: options.bruteforce !== 'off',
    className: 'sub-wordlist',
    onChange: (on) => setBruteforce(on ? lastBf : 'off')
  });
  wordlistSwitch.input.dataset.role = 'sub-wordlist';

  const sourcesGroup = checkboxGroup({
    legend: t('sub.opt.sources'),
    name: 'sub-sources',
    selectAll: true,
    hint: t('sub.opt.sourcesHint'),
    values: options.sources,
    options: SOURCES.map((s) => ({ value: s.id, label: s.name, hint: sourceNote(s) })),
    onChange: (values) => {
      options = { ...options, sources: values };
      saveOptions(options);
      renderAdvSummary();
    },
    className: 'sub-sources'
  });
  // Wordlist levels: labels / hints are live nodes so the real candidate count (smart loads
  // its vendored lists asynchronously) and the time estimate can be filled in later.
  const bfLabels = {};
  const bfHints = {};
  const bfGroup = radioGroup({
    legend: t('sub.opt.bruteforce'),
    name: 'sub-bruteforce',
    value: options.bruteforce,
    hint: t('sub.opt.bfHint'),
    options: BRUTEFORCE_MODES.map((mode) => {
      bfLabels[mode] = h('span', { class: 'sub-bf-label', dataset: { level: mode } });
      bfHints[mode] = h('span', { class: 'sub-bf-hint' });
      return { value: mode, label: bfLabels[mode], hint: bfHints[mode] };
    }),
    onChange: (value) => setBruteforce(value),
    className: 'sub-bf'
  });
  const permBox = checkbox({
    label: t('sub.opt.perm'),
    hint: t('sub.opt.permHint'),
    checked: options.permutations,
    className: 'sub-perm',
    onChange: (on) => {
      options = { ...options, permutations: on };
      saveOptions(options);
      budgetSelect.input.disabled = !on;
      renderAdvSummary();
    }
  });
  permBox.input.dataset.role = 'sub-permutations';
  const budgetSelect = select({
    label: t('sub.opt.permBudget'),
    size: 'sm',
    className: 'sub-perm-budget',
    value: String(options.permutationBudget),
    options: PERMUTATION_BUDGETS.map((n) => ({ value: String(n), label: t('sub.opt.permBudgetValue', { count: n }) })),
    onChange: (v) => {
      options = { ...options, permutationBudget: Number(v) };
      saveOptions(options);
    }
  });
  budgetSelect.input.dataset.role = 'sub-perm-budget';
  budgetSelect.input.disabled = !options.permutations;
  const originBox = checkbox({
    label: t('sub.opt.origin'),
    hint: t('sub.opt.originHint'),
    checked: options.originHints,
    onChange: (on) => {
      options = { ...options, originHints: on };
      saveOptions(options);
      renderAdvSummary();
    }
  });
  originBox.input.dataset.role = 'sub-origin-hints';
  const expiredBox = checkbox({
    label: t('sub.opt.expired'),
    hint: t('sub.opt.expiredHint'),
    checked: options.includeExpired,
    onChange: (on) => {
      options = { ...options, includeExpired: on };
      saveOptions(options);
      renderAdvSummary();
    }
  });
  expiredBox.input.dataset.role = 'sub-expired';

  /* --- wordlist plan (candidate count + estimate for the typed domains) --------- */
  const planLine = h('div', { class: 'sub-wl-plan text-sm', attrs: { 'aria-live': 'polite' } });

  /* --- languages / markets --------------------------------------------------------- */
  const langAutoBox = checkbox({
    label: t('sub.lang.auto'),
    switch: true,
    checked: options.locales === null,
    className: 'sub-lang-auto-toggle',
    onChange: (on) => {
      if (on) {
        options = { ...options, locales: null };
      } else {
        // Seed the manual choice from the auto pick of the typed domains, so it starts sensibly.
        const seed = new Set(autoLocales(parseTargets(domainField.value).domains).flatMap((p) => p.codes));
        options = { ...options, locales: LOCALE_CODES.filter((cc) => seed.has(cc)) };
        setLangValues(options.locales);
      }
      saveOptions(options);
      renderLangs();
      renderPlan();
      renderAdvSummary();
    }
  });
  langAutoBox.input.dataset.role = 'sub-lang-auto';
  const langAutoLine = h('div', { class: 'sub-lang-line text-sm' });
  // Manual pack checkboxes (one fieldset, no nesting): the legend labels the whole control.
  const onLangPackChange = () => {
    options = { ...options, locales: langValues() };
    saveOptions(options);
    renderPlan();
    renderAdvSummary();
  };
  const langInputs = LOCALE_CODES.map((cc) => {
    const cb = checkbox({
      label: t('sub.lang.option', { language: languageName(cc), count: formatNumber(localePackCount(cc)) }),
      value: cc,
      name: 'sub-lang',
      checked: Array.isArray(options.locales) && options.locales.includes(cc),
      onChange: onLangPackChange
    });
    cb.input.dataset.role = 'sub-lang-pack';
    return { cc, cb };
  });
  const langValues = () => langInputs.filter((x) => x.cb.checked).map((x) => x.cc);
  const setLangValues = (codes) => {
    const s = new Set(codes || []);
    langInputs.forEach((x) => { x.cb.checked = s.has(x.cc); });
  };
  const langList = h('div', { class: 'sub-lang-list choice-list' }, langInputs.map((x) => x.cb.el));
  const langControl = h('fieldset', { class: 'fieldset sub-langs' },
    h('legend', { class: 'field-label' }, t('sub.lang.legend')),
    h('div', { class: 'field-hint' }, t('sub.lang.hint')),
    langAutoBox.el, langAutoLine, langList);

  /* --- custom wordlist (paste / upload; kept in this browser tab only) ------------- */
  const customField = textarea({
    label: t('sub.custom.label'),
    optional: true,
    rows: 3,
    placeholder: t('sub.custom.placeholder'),
    hint: t('sub.custom.hint'),
    value: loadCustomWordlist(),
    attrs: { 'data-role': 'sub-custom' },
    onInput: (value) => {
      saveCustomWordlist(value);
      renderCustom();
      renderPlan();
      renderAdvSummary();
    }
  });
  const customFileInput = h('input', {
    type: 'file',
    class: 'sub-file-input',
    attrs: { accept: '.txt,text/plain', 'aria-hidden': 'true', tabindex: -1, 'data-role': 'sub-custom-file' },
    on: { change: () => onCustomFile() }
  });
  const customUploadBtn = Button({
    label: t('sub.custom.upload'), icon: 'upload', size: 'sm', variant: 'secondary',
    title: t('sub.custom.uploadLabel'), dataset: { action: 'sub-custom-upload' }, onClick: () => customFileInput.click()
  });
  const customClearBtn = Button({
    label: t('sub.custom.clear'), icon: 'x', size: 'sm', variant: 'ghost', dataset: { action: 'sub-custom-clear' },
    onClick: () => {
      customField.value = '';
      saveCustomWordlist('');
      renderCustom();
      renderPlan();
      renderAdvSummary();
    }
  });
  const customStatus = h('div', { class: 'sub-custom-status text-sm', attrs: { 'aria-live': 'polite' } });
  const customControl = h('div', { class: 'sub-custom stack-sm' },
    customField.el,
    h('div', { class: 'cluster sub-custom-actions' }, customUploadBtn, customClearBtn, customFileInput),
    customStatus);

  async function onCustomFile() {
    const file = customFileInput.files && customFileInput.files[0];
    customFileInput.value = '';
    if (!file) return;
    if (file.size > CUSTOM_FILE_MAX_BYTES) {
      toast(t('sub.custom.tooLarge', { name: file.name, size: formatBytes(file.size), max: formatBytes(CUSTOM_FILE_MAX_BYTES) }), { type: 'error' });
      return;
    }
    let text;
    try {
      text = decodeText(new Uint8Array(await file.arrayBuffer()));
    } catch {
      toast(t('sub.custom.readError', { name: file.name }), { type: 'error' });
      return;
    }
    const merged = customField.value.trim() ? `${customField.value.replace(/\s*$/, '')}\n${text}` : text;
    customField.value = merged;
    saveCustomWordlist(merged);
    renderCustom();
    renderPlan();
    renderAdvSummary();
    toast(t('sub.custom.loaded', { name: file.name, size: formatBytes(file.size) }), { type: 'success', timeout: 3000 });
  }

  /* --- learned names (per-browser vocabulary from earlier scans) ------------------- */
  const learnedLabel = h('span');
  const learnedBox = checkbox({
    label: learnedLabel,
    switch: true,
    checked: options.learned,
    hint: t('sub.learned.hint'),
    className: 'sub-learned',
    onChange: (on) => {
      options = { ...options, learned: on };
      saveOptions(options);
      renderLearned();
      renderPlan();
      renderAdvSummary();
    }
  });
  learnedBox.input.dataset.role = 'sub-learned';
  const learnedClearBtn = Button({
    label: t('sub.learned.clear'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'sub-learned-clear' },
    onClick: () => {
      try {
        learnedStore().clear();
      } catch {
        // storage may be unavailable; the label simply stays at 0
      }
      renderLearned();
      renderPlan();
      // The summary sits in the disclosure's <summary>, visible right above this button.
      renderAdvSummary();
      toast(t('sub.learned.cleared'), { type: 'success', timeout: 2500 });
    }
  });
  const learnedControl = h('div', { class: 'sub-learned-control stack-sm' }, learnedBox.el, h('div', { class: 'cluster' }, learnedClearBtn));

  const extraField = textarea({
    label: t('sub.opt.extra'),
    optional: true,
    rows: 3,
    placeholder: t('sub.opt.extraPlaceholder'),
    hint: t('sub.opt.extraHint'),
    value: session.extraText,
    attrs: { 'data-role': 'sub-extra' },
    onInput: (value) => {
      session.extraText = value;
      extraField.setError(null);
      renderPlan();
      renderAdvSummary();
    }
  });
  const dohLine = h('div', { class: 'sub-doh text-sm' });
  const advSummary = h('span', { class: 'sub-adv-summary' });
  const advanced = Disclosure({
    summary: h('span', { class: 'sub-adv-head' }, h('span', { class: 'sub-adv-label' }, Icon('sliders', { size: 14 }), ' ', t('sub.opt.advanced')), advSummary),
    className: 'sub-advanced',
    open: session.advancedOpen,
    children: h('div', { class: 'sub-adv' },
      h('div', { class: 'stack' }, bfGroup.el, planLine, langControl, customControl, learnedControl,
        h('div', { class: 'sub-perm-row' }, permBox.el, budgetSelect.el),
        originBox.el),
      h('div', { class: 'stack' }, sourcesGroup.el, expiredBox.el, extraField.el, dohLine))
  });
  advanced.addEventListener('toggle', () => {
    session.advancedOpen = advanced.open;
  });

  function setBruteforce(value) {
    const bf = BRUTEFORCE_MODES.includes(value) ? value : 'off';
    options = { ...options, bruteforce: bf };
    if (bf !== 'off') lastBf = bf;
    saveOptions(options);
    wordlistSwitch.checked = bf !== 'off';
    bfGroup.value = bf;
    renderWordlistLabel();
    renderPlan();
    renderAdvSummary();
  }

  function renderWordlistLabel() {
    // From Smart up, name the locale packs the typed domain adds ("+283 Turkish"), so the quick
    // switch matches the Advanced summary instead of showing only the base count.
    const packs = lastBf === 'small' ? [] : levelPacks(lastBf, planBases(), options.locales);
    const size = t(`sub.bf.${lastBf}`);
    const count = wordlistCount(lastBf).text;
    if (packs.length) {
      const list = packs.map((p) => t('sub.plan.pack', { count: formatNumber(p.count), language: languageName(p.code) })).join(', ');
      wordlistLabel.textContent = t('sub.opt.wordlistPacks', { size, count, packs: list });
    } else {
      wordlistLabel.textContent = t('sub.opt.wordlist', { size, count });
    }
  }

  /** The parallel sweep width for the time estimates (follows Settings). */
  const sweepWidth = () => scanConcurrency(state.settings.concurrency);

  /**
   * The bases a scan of the typed domains + extra hostnames brute-forces ({@link bruteforceBases});
   * none until a domain is typed (this page never scans without one).
   */
  function planBases() {
    const typed = parseTargets(domainField.value).domains;
    return typed.length ? bruteforceBases(typed, parseHostList(extraField.value, { allowWildcard: true }).valid) : [];
  }

  /** Learned names the next scan tries: none when switched off, else at most LEARNED_TRY_MAX. */
  function learnedTryCount() {
    if (!options.learned) return 0;
    try {
      return Math.min(learnedStore().size(), LEARNED_TRY_MAX);
    } catch {
      return 0;
    }
  }

  /**
   * Radio labels: exact candidate counts (plus the locale packs the typed domain gets from Smart
   * up), the download size and a time estimate per domain.
   */
  function renderBfOptions() {
    const domains = planBases();
    for (const mode of BRUTEFORCE_MODES) {
      clear(bfLabels[mode]);
      clear(bfHints[mode]);
      if (mode === 'off') {
        bfLabels[mode].append(t('sub.opt.bf.off'));
        bfHints[mode].append(t('sub.opt.bf.offHint'));
        continue;
      }
      const wc = wordlistCount(mode);
      const packs = levelPacks(mode, domains, options.locales);
      const extra = packs.reduce((a, p) => a + p.count, 0);
      // (Node.append would turn a null into the text "null": add the badge only where it belongs.)
      bfLabels[mode].append(t(`sub.opt.bf.${mode}`, { count: wc.text }));
      if (packs.length) {
        bfLabels[mode].append(h('span', { class: 'sub-bf-packs' },
          packs.map((p) => t('sub.plan.pack', { count: formatNumber(p.count), language: languageName(p.code) })).join(', ')));
      }
      if (mode === 'smart') bfLabels[mode].append(Badge(t('sub.opt.bf.recommended'), { variant: 'accent', className: 'sub-bf-rec' }));
      bfHints[mode].append(t(`sub.opt.bf.${mode}Hint`, { time: estimateText(wc.count + extra, 1, sweepWidth()), size: levelSize(mode) }));
    }
  }

  /** The one-line wordlist plan for the typed domains: candidate count, breakdown and estimate. */
  function renderPlan() {
    // The level labels follow the typed domain too (its locale packs and their time).
    renderBfOptions();
    clear(planLine);
    // Exact zone mode (one run): the plan is the zone's names, not the stored wordlist options.
    const zone = activeZone();
    planLine.dataset.zoneExact = zone && zoneModes.get(zone) === 'exact' ? '1' : '0';
    if (planLine.dataset.zoneExact === '1') {
      planLine.append(Icon('file-text', { size: 13 }), h('span', null, t('sub.plan.zoneExact', { count: zoneChipCounts(zone).names })));
      return;
    }
    // Exact mode of a names hand-off (Reverse DNS) whose names belong to the typed domains: the
    // plan is those names, not the wordlist.
    const ho = activeHandoff();
    planLine.dataset.handoffExact = ho && ho.mode === 'exact' ? '1' : '0';
    if (planLine.dataset.handoffExact === '1') {
      planLine.append(Icon('swap', { size: 13 }), h('span', null, t('sub.plan.handoffExact', { count: ho.names.length })));
      return;
    }
    if (options.bruteforce === 'off') {
      planLine.append(Icon('info', { size: 13 }), h('span', null, t('sub.plan.off')));
      return;
    }
    // Every base the scanner brute-forces: the typed domains plus the base of each wildcard in
    // "Extra hostnames" (`*.api.example.com` gets the level list again under api.example.com).
    const domains = planBases();
    if (!domains.length) {
      planLine.append(Icon('info', { size: 13 }), h('span', null, t('sub.plan.none')));
      return;
    }
    const cw = customWordlist();
    const learnedCount = learnedTryCount();
    const extraNames = parseHostList(extraField.value, { allowWildcard: true }).valid;
    const plan = wordlistPlan({ level: options.bruteforce, domains, locales: options.locales, custom: cw.labels.length, learned: learnedCount });
    // The full-scan query estimate (wordlist + variations + deeper round + origin hints), not just
    // the wordlist size — so the plan line does not under-count the real number of DNS queries.
    const queries = planQueryRange({
      level: options.bruteforce, domains, locales: options.locales, custom: cw.labels.length, learned: learnedCount,
      permutations: options.permutations, permutationBudget: options.permutationBudget, originHints: options.originHints,
      extraNames
    });
    planLine.dataset.total = String(plan.total);
    planLine.dataset.queriesMin = String(queries.min);
    planLine.dataset.queriesMax = String(queries.max);
    planLine.append(Icon('search', { size: 13 }), h('span', null, wordlistPlanText(plan, sweepWidth(), queries)));
  }

  /** Languages / markets: the auto pick line, or the manual pack checkboxes. */
  function renderLangs() {
    const auto = options.locales === null;
    langAutoBox.checked = auto;
    langAutoLine.textContent = auto ? localeSummary(null, parseTargets(domainField.value).domains) : '';
    langAutoLine.hidden = !auto;
    langList.hidden = auto;
    if (!auto) setLangValues(Array.isArray(options.locales) ? options.locales : []);
  }

  /** Custom wordlist: accepted / rejected counts and where the list is kept. */
  function renderCustom() {
    clear(customStatus);
    const cw = customWordlist();
    customClearBtn.disabled = !cw.labels.length && !cw.rejected.length;
    if (!cw.labels.length && !cw.rejected.length) {
      customStatus.append(t('sub.custom.empty'));
      return;
    }
    const lines = [h('span', { class: 'sub-custom-ok' }, Icon('check', { size: 13 }), ' ', t('sub.custom.count', { count: cw.labels.length }))];
    if (cw.rejected.length) {
      lines.push(h('span', { class: 'sub-custom-rejected' }, t('sub.custom.rejected', { count: cw.rejected.length, list: cw.rejected.slice(0, 5).join(', ') })));
    }
    if (cw.stored === 'memory') lines.push(h('span', { class: 'sub-custom-memory' }, t('sub.custom.memory')));
    customStatus.append(...lines);
  }

  /** Learned names: the switch label with the current count, and whether Forget is enabled. */
  function renderLearned() {
    let size = 0;
    try {
      size = learnedStore().size();
    } catch {
      size = 0;
    }
    learnedLabel.textContent = t('sub.learned.label', { count: size });
    learnedClearBtn.disabled = size === 0;
  }

  function renderAdvSummary() {
    const extras = parseHostList(extraField.value, { allowWildcard: true }).valid.length;
    const cw = customWordlist();
    // What a scan really tries (at most LEARNED_TRY_MAX), like the plan line — and only with a
    // wordlist level: at Off no learned name is sent.
    const learnedCount = learnedTryCount();
    const wordlistOn = options.bruteforce !== 'off';
    // Languages only matter from Smart up (Small is language-neutral).
    const langs = wordlistOn && options.bruteforce !== 'small'
      ? (Array.isArray(options.locales) ? sanitizeLocales(options.locales) : autoLocales(planBases()).flatMap((p) => p.codes))
      : [];
    const uniqueLangs = [...new Set(langs)];
    advSummary.textContent = [
      t('sub.sum.sources', { count: options.sources.length }),
      t(`sub.sum.bf.${options.bruteforce}`),
      wordlistOn && uniqueLangs.length ? t('sub.sum.langs', { list: uniqueLangs.map(languageName).join(', ') }) : null,
      wordlistOn && cw.labels.length ? t('sub.sum.custom', { count: cw.labels.length }) : null,
      wordlistOn && options.learned && learnedCount ? t('sub.sum.learned', { count: learnedCount }) : null,
      options.permutations ? t('sub.sum.perm') : null,
      options.originHints ? t('sub.sum.origin') : null,
      options.includeExpired ? t('sub.sum.expired') : null,
      extras ? t('sub.sum.extra', { count: extras }) : null
    ].filter(Boolean).join(' · ');
  }

  function renderDoh() {
    clear(dohLine);
    const chain = state.settings.chain.map((rid) => (getResolver(rid) || { name: rid }).name).join(' → ');
    dohLine.append(Icon('globe', { size: 14 }), h('span', null, t('sub.opt.doh', { chain })),
      h('button', {
        type: 'button',
        class: 'link-btn',
        on: { click: () => globalThis.document.querySelector('[data-control="settings"]')?.click() }
      }, t('sub.opt.dohChange')),
      // The scan spreads its many guesses across these resolvers; the arrows are not a strict order.
      h('span', { class: 'sub-doh-spread' }, t('sub.opt.dohSpread')));
  }

  const hero = h('section', { class: 'sub-hero card', attrs: { 'aria-labelledby': titleId } },
    h('div', { class: 'sub-hero-head' },
      h('h2', { class: 'sub-hero-title', id: titleId }, h('label', { for: inputId }, t('sub.hero.title'))),
      h('p', { class: 'sub-hero-desc' }, t('sub.hero.desc'))),
    h('div', { class: 'sub-search' },
      h('div', { class: 'sub-search-box' }, Icon('search', { size: 18, className: 'sub-search-icon' }), domainField.el),
      h('div', { class: 'sub-search-buttons' }, runBtn, cancelBtn)),
    scopeNote,
    zoneHost,
    handoffHost,
    formError,
    linkPrompt,
    h('div', { class: 'sub-hero-foot' }, examples, wordlistSwitch.el),
    advanced);

  /* --- intro (before the first scan) ---------------------------------------- */
  const introId = uid('sub-intro');
  const intro = h('section', { class: 'sub-intro card', attrs: { 'aria-labelledby': introId } },
    h('h2', { class: 'sub-intro-title', id: introId }, t('sub.intro.title')),
    h('div', { class: 'sub-intro-grid' }, [['network', 'dnsfirst'], ['certificate', 'ct'], ['database', 'dns']].map(([ic, key]) => h('div', { class: 'sub-intro-item', dataset: { source: key } },
      h('span', { class: 'sub-intro-icon', attrs: { 'aria-hidden': 'true' } }, Icon(ic, { size: 18 })),
      h('div', { class: 'sub-intro-text' },
        h('h3', { class: 'sub-intro-item-title' }, t(`sub.intro.${key}.title`)),
        h('p', { class: 'sub-intro-item-body' }, t(`sub.intro.${key}.body`)))))),
    Alert({ variant: 'info', icon: 'cloud', compact: true, message: t('sub.intro.cf') }),
    h('p', { class: 'sub-intro-foot sub-intro-limits' }, Icon('info', { size: 13 }), h('span', null, t('sub.intro.limits'))),
    h('p', { class: 'sub-intro-foot' }, Icon('lock', { size: 13 }), h('span', null, t('sub.intro.privacy')),
      h('a', { href: ctx.href('about'), dataset: { action: 'sub-about' } }, t('sub.intro.more'))));

  // The scan's results are no part of the form: Ctrl/Cmd+Enter in a filter there starts no new scan.
  const resultsHost = h('div', { class: 'sub-results-host', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'sub-view stack-lg' }, hero, intro, resultsHost));

  renderScope();
  renderZoneChip();
  renderHandoff();
  renderWordlistLabel();
  renderBfOptions();
  renderLangs();
  renderCustom();
  renderLearned();
  renderPlan();
  renderAdvSummary();
  renderDoh();

  cleanups.push(state.subscribe(({ key, value }) => {
    // A zone imported, replaced or forgotten (Zone File view / "Delete all local data").
    if ((key === 'session' && value && value.name === 'zone') || key === 'cleared') {
      renderZoneChip();
      renderPlan();
      // A zone scan waiting for the running one goes with its zone.
      if (zoneStartAfter && activeZone() !== zoneStartAfter.zone) hideLinkPrompt();
    }
    if (key === 'settings') {
      // A concurrency change moves the time estimates; the chain moves the DoH line.
      renderDoh();
      renderBfOptions();
      renderPlan();
    }
    // "Delete all local data" clears the learned store (localStorage) too; keep the count honest.
    if (key === 'inventory' || key === 'settings') renderLearned();
    // ... and this tab's custom wordlist (sessionStorage): forget the in-memory copy as well.
    if (key === 'cleared') {
      session.handoff = null;
      renderHandoff();
      resetCustomWordlist();
      customField.value = loadCustomWordlist();
      renderCustom();
      renderLearned();
      renderPlan();
      renderAdvSummary();
    }
  }));

  /* --- run control ------------------------------------------------------------ */
  let ui = null;
  let starting = false;
  const isRunning = () => !!(session.run && session.run.status === 'running');

  function validate() {
    clear(formError);
    domainField.setError(null);
    extraField.setError(null);
    const parsed = parseTargets(domainField.value);
    let message = null;
    if (parsed.ips.length) message = t('sub.err.ip', { list: parsed.ips.slice(0, 3).join(', ') });
    else if (parsed.invalid.length) message = t('sub.err.invalid', { list: parsed.invalid.slice(0, 5).join(', ') });
    else if (parsed.publicSuffixes.length) message = t('sub.err.publicSuffix', { list: parsed.publicSuffixes.join(', ') });
    else if (!parsed.domains.length) message = t('sub.err.required');
    if (message) {
      domainField.setError(message);
      domainField.focus();
      return null;
    }
    const extras = parseHostList(extraField.value, { allowWildcard: true });
    if (extras.invalid.length) {
      extraField.setError(t('sub.err.invalid', { list: extras.invalid.slice(0, 5).join(', ') }));
      advanced.open = true;
      extraField.focus();
      return null;
    }
    return { domains: parsed.domains, extraNames: extras.valid };
  }

  async function start() {
    // `starting` covers the await below, so a double click cannot start two scans.
    if (starting || isRunning()) return;
    const v = validate();
    if (!v) return;
    domainField.value = v.domains.join(', ');
    session.text = domainField.value;
    renderScope();
    let dns;
    starting = true;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      clear(formError);
      formError.append(ErrorBanner(err, { title: t('sub.run.failed'), compact: true }));
      return;
    } finally {
      starting = false;
    }
    if (ctx.signal.aborted) return;
    const permutationBudget = options.permutations ? options.permutationBudget : 0;
    // Per-browser vocabulary: the pasted / uploaded list (tried first) and the learned labels
    // of earlier scans (only when the opt-in switch is on and a wordlist level is chosen —
    // wordlistScanConfig). Both are sent as DNS lookups under the scanned domains.
    const customLabels = customWordlist().labels;
    const learnedLabels = options.learned ? learnedStore().labels() : [];
    const wlConfig = wordlistScanConfig(options, { custom: customLabels, learned: learnedLabels });
    // Zone File hand-off (one run only, never saved to the stored options): the zone's names as
    // seeds, and in exact mode nothing else — no sources, wordlist, permutations or mining.
    const zone = activeZone();
    const zoneMode = zone ? (zoneModes.get(zone) || 'discover') : 'off';
    const zoneCfg = zoneScanOverrides(zone, zoneMode);
    // Names handed over by the Reverse DNS view (one run's config, never stored): the ones under
    // the scanned domains as extra names, and in exact mode nothing else is guessed or asked.
    const applied = handoffForDomains(session.handoff, v.domains);
    const handoff = applied && applied.mode !== 'off' ? applied : null;
    const handoffCfg = handoffScanOverrides(handoff);
    const extraNames = handoff ? [...new Set([...v.extraNames, ...handoff.names])] : v.extraNames;
    const exact = zoneCfg.exact === true || handoffCfg.exact === true;
    session.carried = null;
    const run = createRun({
      domains: v.domains,
      extraNames: v.extraNames,
      handoff: handoff ? { mode: handoff.mode, count: handoff.names.length, label: handoff.label } : null,
      sources: exact ? [] : [...options.sources],
      bruteforce: exact ? 'off' : options.bruteforce,
      permutations: exact ? false : options.permutations,
      permutationBudget: exact ? 0 : permutationBudget,
      originHints: options.originHints,
      includeExpired: options.includeExpired,
      // Remember the "learned names" switch so the finished scan records into the store.
      learned: options.learned,
      inventoryServers: state.inventory.servers.length,
      zoneMode: zoneCfg.zone ? zoneMode : null
    });
    // The DohClient counts queries for its whole life; remember where this run started.
    run.queriesAtStart = typeof dns.stats === 'function' ? dns.stats().queries : null;
    run.zone = zoneCfg.zone || null; // the imported zone it scans (zoneStartAction)
    session.run = run;
    session.filter = 'all';
    // A new run opens on the automatic tab (lib/subtabs.autoSubTab); setParams below drops `tab=`.
    session.tab = null;
    hideLinkPrompt();
    // Only `domain`: a reload or a restored tab pre-fills the box instead of scanning again
    // (the header's "Copy link" adds `run=1` for a shared link).
    ctx.setParams({ domain: v.domains.join(',') });
    ctx.runStarted(v.domains[0]);
    attach(run);
    startRun(run, {
      domains: v.domains,
      cert: null,
      extraNames,
      sources: [...options.sources],
      includeExpired: options.includeExpired,
      // The wordlist config: level plus locales / custom / learned (loadWordlist assembles the
      // per-apex list from them). locales undefined = auto per domain from its TLD.
      ...wlConfig,
      // Permutations and the deeper (recursive) round go together behind one switch.
      permutationBudget,
      recursive: options.permutations,
      inventory: state.inventory.servers,
      originHints: options.originHints,
      resolverLeak: options.originHints,
      // The Settings parallelism caps the scan: `concurrency` is the requested pool (the sweep
      // rotates over the balance pool), `maxConcurrency` the hard ceiling derived from the same
      // Settings value, so a lower setting genuinely means a gentler sweep (never above 24).
      concurrency: scanConcurrency(state.settings.concurrency),
      maxConcurrency: scanConcurrency(state.settings.concurrency),
      dns,
      ...zoneCfg,
      ...handoffCfg
    }, state, ctx.checkOutdated);
    const r = resultsHost.getBoundingClientRect();
    if (r.top > globalThis.innerHeight - 120) resultsHost.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
  }

  function cancel() {
    if (isRunning()) session.run.controller.abort();
  }

  function setRunning(on) {
    runBtn.hidden = on;
    cancelBtn.hidden = !on;
    domainField.input.readOnly = on;
    ctx.setBusy(on ? t('sub.busy') : false);
    renderHeaderActions();
  }

  /** Scan the last run's domains again (the header's Re-run). */
  function rerunLast() {
    const run = session.run;
    if (!run || isRunning()) return;
    domainField.value = run.config.domains.join(', ');
    session.text = domainField.value;
    start();
  }

  function renderHeaderActions() {
    const run = session.run;
    if (!run) {
      ctx.setActions();
      return;
    }
    const params = { domain: run.config.domains.join(','), run: '1' };
    ctx.setActions(
      CopyButton(() => ctx.shareUrl(params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }),
      Button({
        label: t('common.rerun'), icon: 'refresh', size: 'sm', dataset: { action: 'sub-rerun' }, disabled: run.status === 'running',
        onClick: rerunLast
      }));
  }

  function attach(run) {
    if (ui) ui.dispose();
    clear(resultsHost);
    intro.hidden = true;
    ui = buildRunUI(run, ctx, {
      onFinish: () => {
        setRunning(false);
        startWaitingZoneScan();
      }
    });
    resultsHost.append(ui.el);
    setRunning(run.status === 'running');
  }

  /** The scan a Zone File "Scan now" waited for has ended (done, cancelled or failed): start it now. */
  function startWaitingZoneScan() {
    const waiting = zoneStartAfter;
    if (!waiting) return;
    hideLinkPrompt();
    // Only while that zone is still the box's (a Forget or another zone drops the request).
    if (!ctx.signal.aborted && activeZone() === waiting.zone) start();
  }

  if (session.run) attach(session.run);
  else renderHeaderActions();

  // A shared link (`&run=1`) offers a one-click start — unless this page already has that scan.
  if (linkAction(ctx.params, fromRoute, session.run) === 'prompt') {
    showLinkPrompt(fromRoute);
  } else if (!session.run && !fromRoute.length) {
    // Search-first: put the cursor in the box on devices with a real keyboard. (After a
    // navigation the shell moves focus to the page title right after this.)
    const fine = globalThis.matchMedia && globalThis.matchMedia('(hover: hover) and (pointer: fine)').matches;
    if (fine) queueMicrotask(() => domainField.input.focus({ preventScroll: true }));
  }
  // The Zone File view's "Scan now" click starts the scan once this view is built: that in-app
  // click is the consent (the one-shot intent lives in memory only and is never in the URL, so a
  // route link alone still only prompts). A scan still running (started before, on this page)
  // is never dropped silently: the zone scan waits for it, and the prompt offers to cancel it.
  const startFromZoneClick = () => {
    if (ctx.signal.aborted) return;
    const zone = activeZone();
    const action = zoneStartAction(session.run, parseTargets(domainField.value).domains, zone ? (zoneModes.get(zone) || 'discover') : 'off', zone);
    if (action === 'wait') showZoneBusyPrompt(zone);
    else if (action === 'start') start();
  };
  if (intentOk && zoneIntent.autostart === true) queueMicrotask(startFromZoneClick);

  active = {
    applyParams(params) {
      // A new `tab=` (an edited or pasted URL) opens that results tab.
      const tab = parseSubTab(params.tab);
      if (tab && ui) ui.showTab(tab);
      const list = routeTargets(new URLSearchParams(params), params);
      if (!list.length) return;
      if (isFillOnly(params) && !fillReplaces(domainField.value, lastRunDomains(), boxDomains, session.carried)) return;
      domainField.value = list.join(', ');
      session.text = domainField.value;
      session.carried = isFillOnly(params) ? session.text : null;
      domainField.setError(null);
      renderScope();
      renderZoneChip();
      renderPlan();
      if (options.locales === null) renderLangs();
      renderAdvSummary();
      if (linkAction(params, list, session.run) === 'prompt') showLinkPrompt(list);
      else hideLinkPrompt();
    },
    // A finished background scan grew the learned store: refresh the count + plan live.
    refreshLearned() {
      renderLearned();
      renderPlan();
      renderAdvSummary();
    }
  };

  return () => {
    renderDomainDependent.cancel();
    cleanups.forEach((fn) => fn());
    if (ui) ui.dispose();
    ui = null;
    active = null;
  };
}

/**
 * Take new route params without re-mounting (e.g. a pasted share link, or another `tab=`).
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  if (!active) return false;
  active.applyParams(params || {});
  return true;
}

/** Nothing else to clean up (mount returns its own cleanup; a running scan continues). */
export function unmount() {}

/**
 * The page's last scan once it has ended (done, cancelled or failed), or null while none has or
 * one runs. It stays in this module, so the shell keeps only the fact (lib/session.js). No
 * `rerun()`: the page header has the scan's own Re-run.
 * @returns {{ subject: string, at: Date }|null}
 */
export function result() {
  const run = session.run;
  if (!run || run.status === 'running' || !run.finishedAt) return null;
  return { subject: run.config.domains.join(', '), at: run.finishedAt };
}

export default { id, titleKey, icon, mount, unmount, update, result };

/* ------------------------------------------------------------------------ */
/* Run UI: progress + results                                               */
/* ------------------------------------------------------------------------ */

/**
 * Build the progress panel and the results for one run, replay what the run already has
 * and follow it live. Returns `{ el, dispose }`.
 */
function buildRunUI(run, ctx, { onFinish }) {
  const domainsLabel = run.config.domains.join(', ');
  const inventory = run.config.inventoryServers > 0;
  const subject = run.config.domains[0] || '';
  // Live view of the hosts: full records plus streamed partials (task: rows appear during the
  // wordlist / permutation stages, not only once resolve starts). The final result reconciles.
  const listHosts = () => liveHosts(run);
  /** Proxied host names with a host-specific origin candidate (resolver leak / history / sibling). */
  let originCandidates = new Set();

  /* --- progress panel --------------------------------------------------------- */
  const title = h('h2', { class: 'sub-run-title' });
  const meta = h('div', { class: 'sub-run-meta' });
  const stageList = h('ol', { class: 'sub-stages', attrs: { 'aria-label': t('progress.label') } });
  const stageEls = {};
  for (const s of SHOWN_STAGES) {
    const el = h('li', { class: 'sub-stage', dataset: { stage: s, state: 'pending' } },
      h('span', { class: 'sub-stage-dot', attrs: { 'aria-hidden': 'true' } }),
      h('span', { class: 'sub-stage-label' }, t(`sub.stage.${s}`)),
      h('span', { class: 'sub-stage-note' }));
    stageEls[s] = el;
    stageList.append(el);
  }
  const progress = ProgressBar({ label: t('sub.progress.starting'), indeterminate: true });
  progress.el.classList.add('sub-progress');
  const chips = h('div', { class: 'sub-chips', attrs: { role: 'group', 'aria-label': t('sub.opt.sources') } });
  const chipEls = new Map();
  // "crt.sh still fetching (up to 12 s)" while the DNS sweep already runs — so the wait is not
  // mistaken for another stage (task 3). Live region: it is news worth announcing.
  const sourceWaitNote = h('div', { class: 'sub-src-wait', attrs: { 'aria-live': 'polite' }, hidden: true });
  const sourceNotes = h('div', { class: 'sub-src-notes', attrs: { 'aria-live': 'polite' } });
  const notice = h('div', { class: 'sub-run-notice' });
  // How this run used an imported zone file (exact: its names only; discover: added as seeds).
  const zoneBanner = run.config.zoneMode === 'exact' || run.config.zoneMode === 'discover'
    ? Alert({ variant: 'info', compact: true, icon: 'file-text', message: t(`sub.zone.${run.config.zoneMode}`) })
    : null;
  if (zoneBanner) {
    zoneBanner.classList.add('sub-zone-banner');
    zoneBanner.dataset.zoneMode = run.config.zoneMode;
  }
  // How this run used names handed over by the Reverse DNS view.
  const handoffMode = run.config.handoff ? run.config.handoff.mode : null;
  const handoffBanner = handoffMode === 'exact' || handoffMode === 'discover'
    ? Alert({ variant: 'info', compact: true, icon: 'swap', message: t(`sub.handoff.${handoffMode}`) })
    : null;
  if (handoffBanner) {
    handoffBanner.classList.add('sub-zone-banner');
    handoffBanner.dataset.handoffMode = handoffMode;
  }
  // The run's header stays above the tabs: its title, time and progress bar (whose label names
  // the current stage) are in view whichever tab is open; the stage pills and the per-source
  // chips are in the Sources tab.
  const panel = h('section', { class: 'sub-run card', dataset: { status: run.status }, attrs: { 'aria-label': t('progress.label') } },
    h('div', { class: 'sub-run-head' },
      h('span', { class: 'sub-run-icon', attrs: { 'aria-hidden': 'true' } }, Icon('layers', { size: 18 })),
      h('div', { class: 'sub-run-titles' }, title, meta)),
    progress, zoneBanner, handoffBanner, notice);

  /** Grace-window default (lib/scanner DEFAULT_SOURCE_GRACE_MS); only the wording seconds. */
  const SOURCE_GRACE_SECONDS = 12;
  function renderSourceWait() {
    clear(sourceWaitNote);
    // Only while running, and only for sources the scanner said were still fetching that have not
    // settled since (the chip is still pending / spinning).
    const waiting = run.status === 'running' && run.sourceWait && Array.isArray(run.sourceWait.sources)
      ? run.sourceWait.sources.filter((sid) => sourceChipState(run.sourceResults, sid, Math.max(1, run.sourcePlan.domains.length || run.config.domains.length)).state === 'pending')
      : [];
    sourceWaitNote.hidden = !waiting.length;
    if (!waiting.length) return;
    const list = waiting.map((sid) => SOURCE_NAMES[sid] || sid).join(', ');
    sourceWaitNote.append(Icon('clock', { size: 14 }),
      h('span', null, t('sub.srcWait', { list, seconds: SOURCE_GRACE_SECONDS, count: waiting.length })));
  }

  function renderTitle() {
    title.textContent = run.status === 'running' ? t('sub.run.title', { domains: domainsLabel }) : t('sub.run.titleDone', { domains: domainsLabel });
    panel.dataset.status = run.status;
    root.dataset.status = run.status;
  }

  function renderMeta() {
    const end = run.finishedAt || new Date();
    const elapsed = formatDuration(end - run.startedAt);
    if (run.status === 'running') {
      meta.textContent = t('sub.run.elapsed', { time: elapsed });
    } else if (run.status === 'done') {
      const total = run.result && run.result.stats ? run.result.stats.dnsQueries : null;
      const q = Number.isFinite(total) && Number.isFinite(run.queriesAtStart) ? total - run.queriesAtStart : total;
      meta.textContent = `${Number.isFinite(q) ? t('sub.run.finished', { time: elapsed, queries: formatNumber(q) }) : t('sub.run.finishedShort', { time: elapsed })} · ${formatDateTime(end)}`;
    } else if (run.status === 'cancelled') {
      meta.textContent = t('sub.run.cancelledShort');
    } else {
      meta.textContent = '';
    }
  }

  /** Stage → new names it found (only known once the scan is done). */
  const FOUND_BY_STAGE = { mining: (c) => c.mine, bruteforce: (c) => c.wordlist, permutations: (c) => c.permutation + c.recursive };
  function renderStages() {
    const tech = run.result ? techniqueCounts(run.result.hosts) : null;
    // Mining may run next to the sources: only the first running stage is the "current step".
    const current = SHOWN_STAGES.find((s) => run.stages[s].state === 'active');
    for (const s of SHOWN_STAGES) {
      const st = run.stages[s];
      const el = stageEls[s];
      el.dataset.state = st.state;
      const note = el.querySelector('.sub-stage-note');
      let text = '';
      let noteTitle = '';
      // bruteforce: the stage info carries the total; permutations: learned from its progress.
      const total = Number(st.info && st.info.total) || Number(st.candidates) || 0;
      if (st.state === 'skipped') text = t('sub.stage.skipped');
      else if (st.state === 'active' && (s === 'bruteforce' || s === 'permutations') && total > 0) {
        // Candidate count plus a live "hits" count (names that resolved so far, streamed via
        // onFound) — so the pill shows progress, not just how many names will be tried.
        const hits = listHosts().length;
        text = t('sub.stage.candidates', { count: total }) + (hits > 0 ? ` ${t('sub.stage.liveHits', { count: hits })}` : '');
      } else if (tech && st.state === 'done' && FOUND_BY_STAGE[s]) {
        const n = FOUND_BY_STAGE[s](tech);
        text = t('sub.stage.found', { count: formatNumber(n) });
        noteTitle = t('sub.stage.foundTitle', { count: n });
        el.dataset.found = String(n);
      }
      note.textContent = text;
      el.title = noteTitle;
      if (s === current) el.setAttribute('aria-current', 'step');
      else el.removeAttribute('aria-current');
    }
  }

  const PROGRESS_KEYS = { sources: 1, mining: 1, wildcard: 1, bruteforce: 1, permutations: 1, resolve: 1, hints: 1, done: 1 };
  const renderProgress = frameThrottle(() => {
    if (run.status !== 'running') return;
    const p = run.progress;
    if (!p.stage) {
      progress.setIndeterminate(true);
      return;
    }
    progress.setLabel(PROGRESS_KEYS[p.stage] ? t(`sub.progress.${p.stage}`) : t('sub.progress.starting'));
    if (p.total > 0) progress.set(p.done, p.total);
    else progress.setIndeterminate(true);
  });

  function chipFor(sourceId) {
    let el = chipEls.get(sourceId);
    if (!el) {
      el = h('span', { class: 'sub-chip', dataset: { source: sourceId, state: 'pending' } });
      chipEls.set(sourceId, el);
      chips.append(el);
    }
    return el;
  }

  /** The passive sources this run asks (the scanner's plan once it started, else the config). */
  const sourceIds = () => (run.sourcePlan.sources.length ? run.sourcePlan.sources : run.config.sources);

  function renderChips() {
    const plan = run.sourcePlan;
    const ids = sourceIds();
    const expected = Math.max(1, plan.domains.length || run.config.domains.length);
    chips.hidden = ids.length === 0;
    sourcesNone.hidden = ids.length > 0;
    renderQuotas(ids);
    const health = new Map(sourceHealthSummary(run.sourceResults).map((x) => [x.source, x]));
    for (const sid of ids) {
      const s = sourceChipState(run.sourceResults, sid, expected);
      // A finished (cancelled / failed) run has no pending sources left: nothing will arrive.
      if (run.status !== 'running' && s.state === 'pending') s.state = run.sourceResults.some((r) => r.source === sid) ? 'partial' : 'cancelled';
      const el = chipFor(sid);
      clear(el);
      let value;
      let tip = s.error || '';
      let state = s.state;
      const hl = health.get(sid);
      if (s.state === 'pending') value = s.done ? `${s.done}/${s.expected}` : t('sub.chip.waiting');
      else if (s.state === 'cancelled') value = t('sub.chip.err.abort');
      else if (hl && !(s.state === 'error' && s.errorKind === 'abort')) {
        // Every domain answered: the clear, localized health text (quota, down + fallback …).
        const text = sourceHealthText(hl);
        value = text.short;
        tip = text.detail;
        if (text.tone === 'limited') state = 'limited';
        el.dataset.health = hl.state;
      } else if (s.state === 'error') value = t(`sub.chip.err.${CHIP_ERRORS.includes(s.errorKind) ? s.errorKind : 'unknown'}`);
      else value = `${t('sub.chip.names', { count: s.names })}${s.state === 'partial' ? ` · ${t('sub.chip.partial')}` : ''}`;
      el.dataset.state = state;
      const iconName = { ok: 'check-circle', partial: 'alert', limited: 'clock', error: 'x-circle', cancelled: 'minus-circle' }[state];
      el.append(iconName ? Icon(iconName, { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'sub-chip-name' }, SOURCE_NAMES[sid] || sid),
        h('span', { class: 'sub-chip-value' }, value));
      el.title = tip;
    }
    renderSourceNotes(ids, expected, health);
    renderBadges();
  }

  /** The free limits of the sources this run asks (the same notes as Advanced options). */
  function renderQuotas(ids) {
    clear(quotaList);
    quotaBox.hidden = ids.length === 0;
    for (const sid of ids) {
      const def = SOURCES.find((x) => x.id === sid);
      const note = def ? sourceNote(def) : '';
      if (!note) continue;
      quotaList.append(h('li', { class: 'sub-src-quota', dataset: { source: sid } },
        h('span', { class: 'sub-src-quota-name' }, SOURCE_NAMES[sid] || sid), h('span', { class: 'sub-src-quota-note' }, note)));
    }
  }

  /**
   * One clear line per source that did not simply work (quota used up, temporarily down with
   * the CT fallback, timed out, page limit) — shown once that source has answered for every
   * domain. After the scan, a reassuring line tells how much DNS found on its own.
   */
  function renderSourceNotes(ids, expected, health) {
    clear(sourceNotes);
    const lines = [];
    for (const sid of ids) {
      const hl = health.get(sid);
      if (!hl || sourceChipState(run.sourceResults, sid, expected).state === 'pending') continue;
      if (hl.state === 'empty' || (hl.state === 'ok' && !(hl.truncated && hl.available > hl.names))) continue;
      if (hl.errorKind === 'abort') continue;
      const text = sourceHealthText(hl);
      lines.push(h('li', { class: 'sub-src-note', dataset: { source: sid, tone: text.tone, health: hl.state } },
        Icon({ ok: 'info', warn: 'alert', limited: 'clock', error: 'x-circle' }[text.tone] || 'info', { size: 14 }),
        h('span', null, text.detail)));
    }
    if (!lines.length) return;
    const failed = [...health.values()].some((x) => !x.ok);
    const tail = run.result && failed
      ? h('p', { class: 'sub-src-dns' }, t('sub.srcnote.dnsFound', { count: techniqueCounts(run.result.hosts).dnsOnly }))
      : null;
    sourceNotes.append(h('div', { class: 'sub-src-notes-title' }, t('sub.srcnote.title')), h('ul', { class: 'sub-src-list' }, lines));
    if (tail) sourceNotes.append(tail);
  }

  /* --- stats -------------------------------------------------------------------- */
  // A stat card (Overview) filters the host table and opens it; the keyboard focus goes to the
  // Hosts tab, since the card itself is hidden with its panel.
  const stat = {
    found: StatCard({ label: t('sub.stat.found'), icon: 'layers', variant: 'accent', onClick: () => pickFilter('all'), pressed: false }),
    resolving: StatCard({ label: t('sub.stat.resolving'), icon: 'check-circle', variant: 'ok', onClick: () => pickFilter('resolving'), pressed: false }),
    cloudflare: StatCard({ label: t('sub.stat.cloudflare'), icon: 'cloud', variant: 'cloudflare', onClick: () => pickFilter('cloudflare'), pressed: false }),
    cdn: StatCard({ label: t('sub.stat.cdn'), icon: 'zap', variant: 'cdn', onClick: () => pickFilter('cdn'), pressed: false }),
    direct: StatCard({ label: t('sub.stat.direct'), icon: 'server', variant: 'direct', onClick: () => pickFilter('direct'), pressed: false }),
    unresolved: StatCard({ label: t('sub.stat.unresolved'), icon: 'x-circle', variant: 'nxdomain', onClick: () => pickFilter('unresolved'), pressed: false }),
    dangling: StatCard({ label: t('sub.stat.dangling'), icon: 'unlink', variant: 'dangling', onClick: () => pickFilter('dangling'), pressed: false })
  };
  const statsGrid = h('div', { class: 'stat-grid sub-stats' });
  for (const [k, s] of Object.entries(stat)) {
    s.el.dataset.stat = k;
    s.el.title = t('sub.stat.filterHint');
    statsGrid.append(s.el);
  }
  stat.dangling.el.hidden = true;

  /* --- filters + table ------------------------------------------------------------ */
  const seg = SegmentedControl({
    label: t('sub.filter.label'),
    size: 'sm',
    className: 'sub-filter',
    value: session.filter,
    options: SEGMENT_FILTERS.map((f) => ({ value: f, label: t(`sub.filter.${f}`) })),
    onChange: (v) => setFilter(v)
  });
  const wildLabel = h('span');
  const wildBox = checkbox({
    label: wildLabel,
    checked: session.showWildcard,
    className: 'sub-wild-toggle',
    onChange: (on) => {
      session.showWildcard = on;
      applyFilter();
      renderStatsNow();
    }
  });
  wildBox.input.dataset.role = 'sub-show-wildcard';
  wildBox.el.title = t('sub.filter.wildcardHint');
  wildBox.el.hidden = true;

  const ipLink = (ip) => h('a', { class: 'sub-ip', href: ctx.href('ip', { ip }), title: t('sub.ip.intel', { ip }) }, ip);
  const table = DataTable({
    caption: t('sub.caption'),
    search: { placeholder: t('sub.search'), label: t('sub.searchLabel') },
    pageSize: 200,
    sort: { key: 'name', dir: 'asc' },
    empty: t('sub.empty'),
    noMatch: t('sub.noMatch'),
    rowKey: (x) => x.name,
    rowClass: (x) => ({ 'sub-row-wildcard': x.wildcardSuspect, 'sub-row-dangling': x.classification.dangling }),
    className: 'sub-table',
    toolbar: [seg.el, wildBox.el],
    filter: filterFn(),
    columns: [
      {
        key: 'name',
        label: t('sub.col.name'),
        sortable: true,
        sortValue: (x) => hostSortKey(x.name),
        searchValue: (x) => [x.name, ...x.resolution.cnames, x.classification.provider ? x.classification.provider.name : ''].join(' '),
        render: (x) => h('div', { class: 'sub-host' },
          h('a', { class: 'sub-host-name mono', href: ctx.href('lookup', { name: x.name }), title: t('sub.host.lookup', { name: x.name }) }, hostNameNodes(x.name)),
          x.wildcardSuspect ? Badge(t('sub.host.wildcard'), { variant: 'warn', title: t('sub.filter.wildcardHint'), className: 'sub-mini-badge' }) : null)
      },
      {
        key: 'ips',
        label: t('sub.col.ips'),
        sortable: true,
        sortValue: (x) => ipSortValue(x.resolution.ipv4[0] || x.resolution.ipv6[0]),
        searchValue: (x) => [...x.resolution.ipv4, ...x.resolution.ipv6].join(' '),
        render: (x) => {
          const ips = [...x.resolution.ipv4, ...x.resolution.ipv6];
          return ips.length ? h('div', { class: 'sub-ips' }, TruncatedList(ips, { max: 3, inline: true, render: ipLink })) : null;
        }
      },
      {
        key: 'kind',
        label: t('sub.col.kind'),
        sortable: true,
        sortValue: (x) => `${x.classification.dangling ? '0' : '1'}${x.classification.kind}${x.classification.provider ? x.classification.provider.name : ''}`,
        searchValue: (x) => `${t(`kind.${x.classification.dangling ? 'dangling' : x.classification.kind}`)} ${x.classification.provider ? x.classification.provider.name : ''} ${x.resolution.status}`,
        render: (x) => h('div', { class: 'cluster sub-kind' }, KindBadge(x.classification),
          // A streamed partial is "resolving…" only while the run lives (a cancelled run never resolves it).
          x._partial && run.status === 'running' ? Badge(t('sub.host.resolving'), { variant: 'neutral', icon: 'clock', title: t('sub.host.resolvingTitle'), className: 'sub-mini-badge' }) : null,
          x.resolution.status !== 'NOERROR' && x.resolution.status !== 'NXDOMAIN'
            ? Badge(x.resolution.status, { variant: 'error', title: x.resolution.error || null, mono: true }) : null,
          originCandidates.has(x.name) ? h('button', {
            type: 'button',
            class: 'sub-origin-hint',
            title: t('sub.host.originHintTitle'),
            dataset: { action: 'sub-origin-jump' },
            on: { click: () => jumpToOrigin() }
          }, Icon('target', { size: 12 }), t('sub.host.originHint')) : null)
      },
      {
        key: 'cname',
        label: t('sub.col.cname'),
        sortable: true,
        sortValue: (x) => x.resolution.cnames[x.resolution.cnames.length - 1] || '',
        searchValue: (x) => x.resolution.cnames.join(' '),
        render: (x) => (x.resolution.cnames.length
          ? TruncatedList(x.resolution.cnames, {
            max: 2,
            render: (c) => h('span', { class: 'sub-cname', title: x.resolution.cnames.join(' → ') }, h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'), c)
          })
          : null)
      },
      {
        key: 'origins',
        label: t('sub.col.origins'),
        sortable: true,
        sortValue: (x) => x.origins.length,
        defaultDir: 'desc',
        searchValue: (x) => x.origins.map(originLabel).join(' '),
        render: (x) => h('div', { class: 'sub-origins' }, x.origins.map((o) => h('span', {
          class: 'sub-origin',
          dataset: { origin: o, tech: o.startsWith('dns-mine:') ? 'mine' : DNS_ORIGINS.has(o) ? 'dns' : null },
          title: originTitle(o)
        }, originLabel(o))))
      },
      inventory ? {
        key: 'servers',
        label: t('sub.col.servers'),
        sortable: true,
        sortValue: (x) => (x.servers[0] ? x.servers[0].name : ''),
        searchValue: (x) => x.servers.map((s) => `${s.name} ${s.ip}`).join(' '),
        render: (x) => {
          const byName = new Map();
          for (const s of x.servers) byName.set(s.name, [...(byName.get(s.name) || []), s.ip]);
          return byName.size
            ? h('div', { class: 'cluster sub-servers' }, [...byName].map(([name, ips]) => Badge(name, { variant: 'direct', icon: 'server', title: ips.join(', ') })))
            : null;
        }
      } : null
    ].filter(Boolean)
  });
  table.setLoading(run.status === 'running');

  // Without wildcard suspects 'all' needs no filter (keeps the row count simple); the predicate
  // reads showWildcard per row, so suspects streaming in later are hidden under any filter.
  let tableFiltered = false;
  function filterFn() {
    return hostTableFilter(session.filter, session, listHosts());
  }
  function applyFilter() {
    const fn = filterFn();
    tableFiltered = !!fn;
    table.setFilter(fn);
    for (const [k, s] of Object.entries(stat)) s.set({ pressed: STAT_FILTERS[k] === session.filter });
    seg.setValue(session.filter);
  }
  function setFilter(f) {
    session.filter = FILTERS.includes(f) ? f : 'all';
    applyFilter();
  }
  function pickFilter(f) {
    setFilter(f);
    showTab('hosts', { focus: true });
  }

  /* --- actions: copy / download ------------------------------------------------------ */
  const exportList = () => listHosts().filter((x) => (session.showWildcard || !x.wildcardSuspect) && (!session.resolvingOnly || isResolving(x)));
  const countEl = h('span', { class: 'sub-act-count num' });
  const copyBtn = CopyButton(() => namesText(exportList()), { label: t('sub.act.copy'), size: 'sm', variant: 'secondary', className: 'sub-copy' });
  copyBtn.dataset.action = 'sub-copy';
  copyBtn.append(countEl);
  const resolvingBox = checkbox({
    label: t('sub.act.resolvingOnly'),
    checked: session.resolvingOnly,
    className: 'sub-resolving-only',
    onChange: (on) => {
      session.resolvingOnly = on;
      syncActions();
    }
  });
  resolvingBox.input.dataset.role = 'sub-resolving-only';
  const saved = (file) => toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  const exportRows = () => scanHostRows({ hosts: exportList() }).map(({ covered: _c, coveredBy: _b, ...row }) => row);
  const namesBtn = Button({
    label: t('sub.act.names'), icon: 'file-text', size: 'sm', dataset: { export: 'names' },
    onClick: () => saved(downloadText('names.txt', namesText(exportList()), 'text/plain;charset=utf-8'))
  });
  const csvBtn = Button({
    label: t('common.exportCsv'), icon: 'download', size: 'sm', dataset: { export: 'csv' },
    onClick: () => saved(downloadText(timestampedName('subdomains', 'csv', subject), toCsv(exportRows(), CSV_COLUMNS), 'text/csv;charset=utf-8'))
  });
  const jsonBtn = Button({
    label: t('common.exportJson'), icon: 'download', size: 'sm', dataset: { export: 'json' },
    onClick: () => saved(downloadText(timestampedName('subdomains', 'json', subject), `${toJson({
      generator: 'DomainScope',
      version: ctx.version,
      exportedAt: new Date(),
      domains: run.config.domains,
      options: {
        sources: run.config.sources,
        bruteforce: run.config.bruteforce,
        permutationBudget: run.config.permutationBudget,
        originHints: run.config.originHints,
        includeExpired: run.config.includeExpired,
        // The wordlist the scan actually served: level (after any degrade), locale packs and
        // the custom / learned tried-vs-found counts (result.options.wordlist, engine v2).
        wordlist: run.result && run.result.options ? run.result.options.wordlist || null : null
      },
      complete: run.status === 'done',
      discovery: run.result ? techniqueCounts(run.result.hosts) : null,
      sourceHealth: sourceHealthSummary(run.sourceResults).map(({ domains: _d, ...x }) => x),
      // The networks and the POSIX command the ORIGIN panel shows, with its exclusions applied.
      origin: run.result ? originExport(run.result, originExclude.tokens) : null,
      subdomains: exportRows()
    })}\n`, 'application/json;charset=utf-8'))
  });
  const actions = h('div', { class: 'sub-actions', attrs: { role: 'group', 'aria-label': t('sub.act.label') } },
    h('div', { class: 'sub-actions-main' }, copyBtn, resolvingBox.el),
    h('div', { class: 'sub-actions-files' }, namesBtn, csvBtn, jsonBtn));

  function syncActions() {
    const n = exportList().length;
    countEl.textContent = formatNumber(n);
    for (const b of [copyBtn, namesBtn, csvBtn, jsonBtn]) b.disabled = n === 0;
  }

  /* --- how the names were found (technique chips) ---------------------------------------- */
  const techHost = h('div', { class: 'sub-tech', attrs: { role: 'group', 'aria-label': t('sub.tech.label') } });
  function renderTechniques() {
    clear(techHost);
    const hosts = listHosts();
    const c = techniqueCounts(hosts);
    techHost.hidden = c.total === 0;
    if (!c.total) return;
    const chip = (key, label, n, what = label) => (n ? h('span', {
      class: 'sub-tech-chip',
      dataset: { tech: key },
      title: t('sub.tech.chipTitle', { count: n, what })
    }, h('span', { class: 'sub-tech-name' }, label), h('span', { class: 'sub-tech-count num' }, formatNumber(n))) : null);
    const dnsChips = [
      chip('zone', t('sub.tech.zone'), c.zone),
      chip('mine', t('sub.tech.mine'), c.mine),
      chip('wordlist', t('sub.tech.wordlist'), c.wordlist),
      chip('permutation', t('sub.tech.permutation'), c.permutation),
      chip('recursive', t('sub.tech.recursive'), c.recursive)
    ].filter(Boolean);
    const srcChips = SOURCES.map((s) => chip(`source:${s.id}`, s.name, c.bySource[s.id] || 0)).filter(Boolean);
    // "Only through DNS" claims nothing about sources that were off, limited or down.
    const onlyKey = run.status !== 'running'
      ? dnsOnlyNoteKey(c.dnsOnly, run.config.sources, sourceHealthSummary(run.result ? run.result.sources || run.sourceResults : run.sourceResults))
      : null;
    // h() skips null children; Node.append would print "null", so it only gets real nodes.
    techHost.append(h('div', { class: 'sub-tech-head' },
      Icon('network', { size: 15 }),
      h('span', { class: 'sub-tech-summary', dataset: { dns: c.dns, sources: c.sources, dnsOnly: c.dnsOnly } },
        t('sub.tech.summary', { dns: formatNumber(c.dns), sources: formatNumber(c.sources) })),
      onlyKey ? h('span', { class: 'sub-tech-only', dataset: { note: onlyKey === 'sub.tech.dnsOnly' ? 'complete' : 'incomplete' } }, t(onlyKey, { count: c.dnsOnly })) : null));
    if (dnsChips.length || srcChips.length) {
      techHost.append(h('div', { class: 'sub-tech-chips' },
        dnsChips.length ? h('div', { class: 'sub-tech-group', dataset: { group: 'dns' } }, dnsChips) : null,
        srcChips.length ? h('div', { class: 'sub-tech-group', dataset: { group: 'sources' } }, srcChips) : null));
    }
    const wl = usage();
    if (wl) techHost.append(wl);
  }

  /**
   * The wordlist-usage line from result.options.wordlist (structured fields, engine v2): the
   * served level (after any degrade), the locale packs applied, and how many custom / learned
   * names were tried vs found. Null when no wordlist ran or the result predates the field.
   */
  function usage() {
    const wl = run.result && run.result.options && run.result.options.wordlist;
    if (!wl || !wl.level || wl.level === 'off') return null;
    const level = hasString(`sub.bf.${wl.level}`, 'en') ? t(`sub.bf.${wl.level}`) : wl.level;
    const parts = [h('span', { class: 'sub-wl-level' }, t('sub.wl.usage', { level }))];
    if (Array.isArray(wl.localePacks) && wl.localePacks.length) {
      parts.push(h('span', null, t('sub.wl.packs', { list: wl.localePacks.map(languageName).join(', ') })));
    }
    if (Array.isArray(wl.localesMissing) && wl.localesMissing.length) {
      parts.push(h('span', { class: 'sub-wl-degraded' }, t('sub.wl.packsMissing', { list: wl.localesMissing.map(languageName).join(', ') })));
    }
    if (wl.customTried) parts.push(h('span', null, t('sub.wl.custom', { found: formatNumber(wl.customFound || 0), tried: formatNumber(wl.customTried) })));
    if (wl.learnedTried) parts.push(h('span', null, t('sub.wl.learned', { found: formatNumber(wl.learnedFound || 0), tried: formatNumber(wl.learnedTried) })));
    if (Array.isArray(wl.degraded) && wl.degraded.length) parts.push(h('span', { class: 'sub-wl-degraded' }, t('sub.wl.degraded', { level })));
    const line = h('div', { class: 'sub-wl-usage', dataset: { level: wl.level } }, Icon('list', { size: 13 }));
    parts.forEach((p, i) => {
      if (i) line.append(h('span', { class: 'sub-wl-sep', attrs: { 'aria-hidden': 'true' } }, '·'));
      line.append(p);
    });
    return line;
  }
  const renderTechniquesSoon = timeThrottle(renderTechniques, 400);

  /* --- ORIGIN panel: where proxied hosts really live ------------------------------------ */
  const originHost = h('div', { class: 'sub-origin-host' });
  function jumpToOrigin() {
    const target = originHost.querySelector('.sub-org');
    if (!target) return;
    showTab('origins');
    target.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    const heading = target.querySelector('.sub-org-title');
    if (heading) heading.focus({ preventScroll: true });
  }
  /** Render the sweep command for the chosen shell into `host` (a CodeBlock, or the "none" hint). */
  // Origin-panel state that survives its own re-renders: the exclude tokens the user pasted (kept
  // per run, so a re-mount keeps them too) and a per-network owner-lookup cache (one RIPEstat
  // request per /24 · /48, on demand).
  let originExclude = originExcludes.get(run);
  if (!originExclude) {
    originExclude = { raw: '', tokens: [] };
    originExcludes.set(run, originExclude);
  }
  const ownerCache = new Map();
  const ownerCtl = new AbortController();

  function renderOrigin() {
    clear(originHost);
    const r = run.result;
    originCandidates = new Set();
    if (!r) return;
    const o = originOverview(r);
    if (!o.proxied.length) return;
    // Hosts with any host-specific candidate (resolver leak / history / sibling-domain) get the
    // "origin?" jump badge in the results table.
    originCandidates = new Set(o.proxied.filter((p) => p.zone.length || p.leaks.length || p.history.length || p.siblings.length).map((p) => p.name));
    const titleId = uid('sub-org');
    const ipLinkOrg = (ip) => h('a', { class: 'sub-ip mono', href: ctx.href('ip', { ip }), title: t('sub.ip.intel', { ip }) }, ip);
    const blocks = [];
    // A zone file's origin may be a private address: plain text, never an IP Intel link (that
    // view asks third-party services about the address as soon as it opens).
    const zoneIpEl = (ip) => h('span', { class: 'sub-ip mono' }, ip);

    // 0. Exact origins from the imported zone file (Zone File hand-off): authoritative, so first.
    const zoned = o.proxied.filter((p) => p.zone.length);
    if (zoned.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'zone' } },
        h('h4', { class: 'sub-org-sub' }, Icon('file-text', { size: 14 }), t('sub.org.zone')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.zoneHint')),
        h('ul', { class: 'sub-org-list' }, zoned.flatMap((p) => p.zone.map((z) => h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: z.ip, kind: 'zone' } },
          h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
          zoneIpEl(z.ip)))))));
    }

    /** The sweep for a shell with the current exclusions applied (the JSON export reads the same). */
    const currentSweep = (shell) => originSweepFor(r, { shell, exclude: originExclude.tokens.length ? originExclude.tokens : null });

    // 1. Origin networks (/24 · /48 clusters of the DNS-only records). Each card says whether the
    //    command sweeps the whole /24 or only its known addresses (and why), flags shared cloud /
    //    hosting space, and offers an on-demand owner (AS) lookup.
    if (o.networks.length) {
      const netEls = o.networks.map((net) => {
        const sweepWhole = net.sweep === 'cidr';
        // Polite live region: the owner replaces the button when the on-demand lookup answers.
        const ownerEl = h('span', { class: 'sub-org-owner', attrs: { 'aria-live': 'polite' } });
        renderOwner(ownerEl, net);
        // An IPv4 network can be swept for reverse DNS (a /48 cannot): other hosts of the same
        // owner often sit next to the origin. In shared cloud / hosting space the rest of the /24
        // is other customers' (provider-generated names), so only its own addresses are offered.
        // The link only fills the form; the user presses Sweep.
        const focusDomain = registrableDomain(net.hosts[0] || '') || run.config.domains[0] || '';
        const ownV4 = net.ips.filter((ip) => !ip.includes(':'));
        const ptrTarget = net.shared ? ownV4.join(',') : net.cidr;
        const ptrLink = net.cidr.includes(':') || !ptrTarget ? null : h('a', {
          class: 'sub-org-ptr',
          href: ctx.href('ptr', { target: ptrTarget, focus: focusDomain }),
          title: net.shared ? t('sub.org.ptrIpsTitle') : t('sub.org.ptrTitle', { cidr: net.cidr }),
          dataset: { action: 'sub-org-ptr', cidr: net.cidr, target: net.shared ? 'ips' : 'cidr' }
        }, Icon('swap', { size: 13 }), h('span', null, net.shared ? t('sub.org.ptrIps', { count: ownV4.length }) : t('sub.org.ptr')));
        return h('li', { class: 'sub-org-net', dataset: { cidr: net.cidr, sweep: net.sweep, shared: net.shared ? '1' : '0' } },
          h('div', { class: 'sub-org-net-head' },
            h('span', { class: 'sub-org-cidr mono' }, net.cidr),
            CopyButton(net.cidr, { iconOnly: true, size: 'sm' }),
            h('span', { class: 'sub-org-net-meta' },
              t('sub.org.net.hosts', { count: net.hosts.length }), ' · ', t('sub.org.net.ips', { count: net.ips.length })),
            h('span', {
              class: 'sub-org-sweep',
              dataset: { sweep: net.sweep },
              title: sweepWhole ? t('sub.org.sweep.cidrTitle') : t('sub.org.sweep.ipsTitle')
            }, Icon(sweepWhole ? 'network' : 'server', { size: 12 }),
            sweepWhole ? t('sub.org.sweep.cidr') : t('sub.org.sweep.ips', { count: net.ips.length })),
            net.shared ? Badge(t('sub.org.shared'), { variant: 'warn', icon: 'alert', title: t('sub.org.sharedTitle'), className: 'sub-org-shared-badge' }) : null,
            ownerEl,
            ptrLink),
          h('div', { class: 'sub-org-net-body' },
            TruncatedList(net.hosts.map((name) => {
              const host = r.hosts.find((x) => x.name === name);
              const ip = host ? [...host.resolution.ipv4, ...host.resolution.ipv6].find((a) => net.ips.includes(a)) : null;
              return { name, ip };
            }), {
              max: 6,
              inline: true,
              render: (x) => h('span', { class: 'sub-org-member' },
                h('a', { class: 'mono', href: ctx.href('lookup', { name: x.name }) }, hostNameNodes(x.name)),
                x.ip ? h('span', { class: 'sub-org-member-ip mono' }, x.ip) : null)
            })));
      });
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'networks' } },
        h('h4', { class: 'sub-org-sub' }, Icon('network', { size: 14 }), t('sub.org.networks')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.networksHint')),
        o.shared ? Alert({ variant: 'warn', compact: true, icon: 'alert', message: t('sub.org.warnShared') }) : null,
        h('ul', { class: 'sub-org-nets' }, netEls)));
    } else {
      blocks.push(Alert({ variant: 'info', compact: true, icon: 'info', message: t('sub.org.noNetworks') }));
    }

    // 2. Direct answers for proxied names (resolver leak) and pre-proxy history.
    const leaks = o.proxied.filter((p) => p.leaks.length);
    if (leaks.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'leaks' } },
        h('h4', { class: 'sub-org-sub' }, Icon('zap', { size: 14 }), t('sub.org.leaks')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.leaksHint')),
        h('ul', { class: 'sub-org-list' }, leaks.flatMap((p) => p.leaks.map((l) => h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: l.ip } },
          h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
          ipLinkOrg(l.ip), h('span', { class: 'sub-org-via' }, t('sub.org.leakVia', { resolver: l.resolver }))))))));
    }
    const hist = o.proxied.filter((p) => p.history.length);
    if (hist.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'history' } },
        h('h4', { class: 'sub-org-sub' }, Icon('clock', { size: 14 }), t('sub.org.history')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.historyHint')),
        h('ul', { class: 'sub-org-list' }, hist.flatMap((p) => p.history.map((x) => {
          // Structured fields (no text parsing): the source id and the last-seen date.
          const source = SOURCE_NAMES[x.source] || x.source || '';
          const via = source ? t(x.lastSeen ? 'sub.org.historyViaDate' : 'sub.org.historyVia', { source, date: dayText(x.lastSeen) }) : '';
          return h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: x.ip } },
            h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
            ipLinkOrg(x.ip), via ? h('span', { class: 'sub-org-via' }, via) : null);
        })))));
    }

    // 3. Confirm with the CLI (TLS + SNI sweep from inside the network). The command is offered
    //    for both shells (POSIX / PowerShell), built by lib/cmdline so every token is quoted, and
    //    an "exclude" box feeds --exclude (a mail server, a shared address, an octet to leave alone).
    const codeHost = h('div', { class: 'sub-org-command-host' });
    const excludeReport = h('div', { class: 'sub-org-exclude-report text-sm', attrs: { 'aria-live': 'polite' } });
    const renderCommand = () => {
      clear(codeHost);
      clear(excludeReport);
      const shell = SHELLS.includes(session.originShell) ? session.originShell : 'posix';
      const sweep = currentSweep(shell);
      if (sweep.command) codeHost.append(CodeBlock(sweep.command, { label: t('sub.org.command'), wrap: true, className: 'sub-org-command' }));
      const nf = sweep.command && sweep.namesFile ? { file: sweep.namesFile, text: sweep.namesText, count: sweep.count } : null;
      if (nf) {
        codeHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: nf.file } },
          h('p', { class: 'sub-org-hint' }, t('sub.org.namesFile', { file: nf.file, count: formatNumber(nf.count) })),
          Button({
            label: t('sub.org.namesFileDownload', { file: nf.file }), icon: 'download', size: 'sm', dataset: { export: 'names-file' },
            onClick: () => saved(downloadText(nf.file, nf.text, 'text/plain;charset=utf-8'))
          })));
      }
      // A target list too long even then: the command reads the targets from a file too.
      if (sweep.command && sweep.targetsFile) {
        codeHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: sweep.targetsFile } },
          h('p', { class: 'sub-org-hint' }, t('sub.org.targetsFile', { file: sweep.targetsFile, count: formatNumber(sweep.targetCount) })),
          Button({
            label: t('sub.org.namesFileDownload', { file: sweep.targetsFile }), icon: 'download', size: 'sm', dataset: { export: 'targets-file' },
            onClick: () => saved(downloadText(sweep.targetsFile, sweep.targetsText, 'text/plain;charset=utf-8'))
          })));
      }
      // Report what the exclusions did: invalid tokens, ones that touched nothing, networks dropped,
      // and a command they keep too long for a shell.
      const invalid = sweep.excludeDropped || [];
      const unused = sweep.excludeUnused || [];
      const droppedTargets = sweep.droppedTargets || 0;
      const lines = [];
      if (sweep.overLength) lines.push(h('div', { class: 'sub-org-exclude-invalid', dataset: { role: 'over-length' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.overLength', { count: formatNumber(sweep.command.length) }))));
      if (invalid.length) lines.push(h('div', { class: 'sub-org-exclude-invalid', dataset: { role: 'exclude-invalid' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.exclude.invalid', { count: invalid.length, list: invalid.slice(0, 5).join(', ') }))));
      if (droppedTargets) lines.push(h('div', { class: 'sub-org-exclude-applied', dataset: { role: 'exclude-applied' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.applied', { count: droppedTargets }))));
      if (unused.length) lines.push(h('div', { class: 'sub-org-exclude-unused', dataset: { role: 'exclude-unused' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.unused', { count: unused.length, list: unused.slice(0, 5).join(', ') }))));
      excludeReport.append(...lines);
    };
    const shellSeg = o.command ? SegmentedControl({
      label: t('sub.org.shell'),
      size: 'sm',
      className: 'sub-org-shell',
      value: SHELLS.includes(session.originShell) ? session.originShell : 'posix',
      options: SHELLS.map((sh) => ({ value: sh, label: t(`sub.org.shell.${sh}`), title: t(`sub.org.shellTitle.${sh}`) })),
      onChange: (sh) => {
        session.originShell = SHELLS.includes(sh) ? sh : 'posix';
        renderCommand();
      }
    }) : null;
    const excludeField = o.command ? textInput({
      label: t('sub.org.exclude.label'),
      value: originExclude.raw || '',
      placeholder: t('sub.org.exclude.placeholder'),
      hint: t('sub.org.exclude.hint'),
      mono: true,
      className: 'sub-org-exclude',
      attrs: { 'data-role': 'sub-org-exclude', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off' },
      onInput: (value) => {
        originExclude.raw = value;
        originExclude.tokens = value.split(/[\s,]+/).filter(Boolean);
        renderCommand();
      }
    }) : null;
    renderCommand();
    blocks.push(h('div', { class: 'sub-org-block sub-org-cli', dataset: { block: 'cli' } },
      h('h4', { class: 'sub-org-sub' }, Icon('terminal', { size: 14 }), t('sub.org.cli')),
      h('p', { class: 'sub-org-hint' }, o.command ? t('sub.org.cliHint') : t('sub.org.cliNone')),
      shellSeg ? shellSeg.el : null,
      excludeField ? excludeField.el : null,
      codeHost,
      excludeReport,
      o.droppedCount ? h('p', { class: 'sub-org-dropped text-sm' }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.dropped', { count: o.droppedCount }))) : null,
      h('div', { class: 'cluster' },
        ButtonLink({ href: CLI_PATH, label: t('sub.org.cliDownload'), icon: 'download', size: 'sm', download: 'ssl_origin_scan.py' }))));

    // 4. Every proxied host with its candidates, and the general hints (SPF / MX / siblings).
    const hostTable = DataTable({
      caption: t('sub.org.hosts', { count: o.proxied.length }),
      rows: o.proxied,
      dense: true,
      search: o.proxied.length > 10,
      rowKey: (p) => p.name,
      sort: { key: 'name', dir: 'asc' },
      className: 'sub-org-table',
      columns: [
        { key: 'name', label: t('sub.org.col.host'), sortable: true, mono: true, sortValue: (p) => hostSortKey(p.name), searchValue: (p) => p.name, render: (p) => hostNameNodes(p.name) },
        {
          key: 'candidates', label: t('sub.org.col.candidates'), wrap: true, sortable: true,
          // Rank: exact host-specific evidence (leak / sibling / history) above candidate networks.
          sortValue: (p) => (p.zone.length ? -1 : p.leaks.length ? 0 : p.siblings.length ? 1 : p.history.length ? 2 : p.networks.length ? 3 : 4),
          searchValue: (p) => [...p.zone.map((z) => z.ip), ...p.leaks.map((l) => l.ip), ...p.siblings.map((s) => `${s.ip} ${s.sibling}`), ...p.history.map((x) => x.ip), ...p.networks].join(' '),
          render: (p) => {
            const items = [
              ...p.zone.map((z) => h('span', { class: 'sub-org-cand', dataset: { kind: 'zone' } },
                Badge(t('sub.hint.zone'), { variant: 'ok', title: t('sub.hint.zone.title') }), zoneIpEl(z.ip))),
              ...p.leaks.map((l) => h('span', { class: 'sub-org-cand', dataset: { kind: 'resolver-leak' } },
                Badge(t('sub.hint.resolver-leak'), { variant: 'warn', title: t('sub.hint.resolver-leak.title') }), ipLinkOrg(l.ip))),
              ...p.siblings.map((s) => h('span', { class: 'sub-org-cand', dataset: { kind: 'sibling-domain' } },
                Badge(t('sub.org.cand.sibling'), { variant: 'accent', title: t('sub.org.cand.siblingTitle') }), ipLinkOrg(s.ip),
                s.sibling ? h('span', { class: 'sub-org-via' }, t('sub.org.cand.siblingVia', { sibling: s.sibling })) : null)),
              ...p.history.map((x) => h('span', { class: 'sub-org-cand', dataset: { kind: 'history' } },
                Badge(t('sub.hint.history'), { variant: 'info', title: t('sub.hint.history.title') }), ipLinkOrg(x.ip))),
              p.networks.length ? h('span', { class: 'sub-org-cand muted', dataset: { kind: 'network' } },
                Badge(t('sub.org.cand.network'), { variant: 'neutral', title: t('sub.org.cand.networkTitle') }),
                h('span', { class: 'sub-org-cand-nets mono' }, p.networks.join(', '))) : null
            ].filter(Boolean);
            return items.length ? h('div', { class: 'sub-org-cands' }, items) : h('span', { class: 'muted' }, t('sub.org.candNone'));
          }
        },
        {
          key: 'edge', label: t('sub.org.col.edge'),
          searchValue: (p) => [...p.host.resolution.ipv4, ...p.host.resolution.ipv6].join(' '),
          render: (p) => h('div', { class: 'cluster' }, KindBadge(p.host.classification),
            TruncatedList([...p.host.resolution.ipv4, ...p.host.resolution.ipv6], { max: 1, inline: true }))
        }
      ]
    });
    const generalTable = o.general.length ? DataTable({
      caption: t('sub.org.other'),
      rows: o.general,
      dense: true,
      rowKey: (x) => x.ip,
      className: 'sub-org-hints',
      columns: [
        { key: 'ip', label: t('sub.org.col.ip'), sortable: true, sortValue: (x) => ipSortValue(x.ip), render: (x) => ipLinkOrg(x.ip) },
        {
          key: 'reasons', label: t('sub.org.col.evidence'), wrap: true,
          searchValue: (x) => x.reasons.map((y) => `${y.kind} ${reasonText(y)}`).join(' '),
          render: (x) => h('div', { class: 'stack-sm' }, x.reasons.slice(0, 3).map((y) => h('div', { class: 'sub-org-reason' },
            Badge(HINT_KINDS.includes(y.kind) ? t(`sub.hint.${y.kind}`) : y.kind, { variant: 'info', title: HINT_KINDS.includes(y.kind) ? t(`sub.hint.${y.kind}.title`) : null }),
            h('span', { class: 'mono text-xs sub-org-detail' }, reasonText(y)))))
        },
        { key: 'hosts', label: t('sub.org.col.about'), mono: true, render: (x) => ((x.hosts || []).length ? TruncatedList(x.hosts, { max: 2 }) : null) }
      ]
    }) : null;
    blocks.push(Disclosure({
      summary: t('sub.org.hosts', { count: o.proxied.length }),
      className: 'sub-org-more',
      open: o.proxied.length <= 8,
      children: h('div', { class: 'stack' }, hostTable.el,
        generalTable ? h('div', { class: 'stack-sm' }, h('h4', { class: 'sub-org-sub' }, t('sub.org.other')), h('p', { class: 'sub-org-hint' }, t('sub.org.otherHint')), generalTable.el) : null)
    }));

    originHost.append(h('section', { class: 'sub-org card', attrs: { 'aria-labelledby': titleId }, dataset: { proxied: o.proxied.length, networks: o.networks.length } },
      h('div', { class: 'sub-org-head' },
        h('span', { class: 'sub-org-icon', attrs: { 'aria-hidden': 'true' } }, Icon('cloud', { size: 18 })),
        h('div', { class: 'sub-org-titles' },
          h('h3', { class: 'sub-org-title', id: titleId, attrs: { tabindex: '-1' } }, t('sub.org.title')),
          h('p', { class: 'sub-org-lead' }, t('sub.org.lead', { count: o.proxied.length })),
          // Suggest scanning sibling domains together: the same label on a sister brand often sits
          // in the open at the real origin (engine v3 raises it to an exact candidate).
          h('p', { class: 'sub-org-suggest' }, Icon('info', { size: 13 }), h('span', null, t('sub.org.siblingSuggest'))))),
      blocks));
  }

  /** The AS owner of a network: the offline provider at once, else an on-demand RIPEstat lookup. */
  function renderOwner(el, net) {
    clear(el);
    if (net.provider) { el.append(h('span', { class: 'sub-org-owner-prov' }, net.provider.name)); return; }
    const cached = ownerCache.get(net.cidr);
    if (cached) { fillOwner(el, cached); return; }
    el.append(Button({
      label: t('sub.org.owner.lookup'), icon: 'search', size: 'sm', variant: 'ghost',
      // Several networks carry the same button: name the network (and the service it asks).
      ariaLabel: t('sub.org.owner.lookupFor', { cidr: net.cidr }), title: t('sub.org.owner.lookupFor', { cidr: net.cidr }),
      dataset: { action: 'sub-org-owner', cidr: net.cidr },
      onClick: async () => {
        clear(el);
        el.append(h('span', { class: 'sub-org-owner-looking' }, t('sub.org.owner.looking')));
        try {
          const d = await describeNetwork(net.cidr, { signal: ownerCtl.signal });
          ownerCache.set(net.cidr, d);
          fillOwner(el, d);
        } catch (err) {
          if (errorKind(err) === 'abort') return;
          clear(el);
          el.append(h('span', { class: 'sub-org-owner-error' }, t('sub.org.owner.error')));
        }
      }
    }));
  }
  function fillOwner(el, d) {
    clear(el);
    if (d && !d.error && d.asn) {
      el.append(h('span', {
        class: ['sub-org-owner-as', { 'is-shared': d.shared }],
        dataset: { asn: String(d.asn), shared: d.shared ? '1' : '0' }
      }, t('sub.org.owner.as', { asn: d.asn, holder: d.holder || d.asName || '' })));
    } else {
      el.append(h('span', { class: 'sub-org-owner-error' }, t('sub.org.owner.error')));
    }
  }

  /* --- summary + CTA ------------------------------------------------------------------ */
  const summaryHost = h('div', { class: 'stack-sm sub-summary' });
  /** The Overview's alerts of the ended run (lib/subtabs.summaryAlerts); its tab badge counts them. */
  let alerts = [];
  function renderSummary() {
    clear(summaryHost);
    const r = run.result;
    alerts = summaryAlerts({
      status: run.status,
      counts: countHosts(listHosts()),
      failedSources: sourceHealthSummary(run.sourceResults).filter((x) => !x.ok && x.errorKind !== 'abort').length,
      wildcards: r ? Object.entries(r.wildcards || {}).filter(([, w]) => w && w.wildcard).map(([d]) => `*.${d}`) : [],
      warnings: r ? r.warnings || [] : []
    });
    const link = (action, label, onClick) => [h('button', { type: 'button', class: 'link-btn', dataset: { action }, on: { click: onClick } }, label)];
    for (const a of alerts) {
      let message;
      let iconName = 'alert';
      let actions = null;
      switch (a.key) {
        case 'none':
          message = t('sub.sum.noneFound');
          iconName = 'search';
          break;
        case 'sources-failed':
          message = t('sub.sum.sourcesFailed', { count: a.count });
          actions = link('sub-sources-link', t('sub.sum.sourcesLink'), () => showTab('sources', { focus: true }));
          break;
        case 'dangling':
          message = t('sub.sum.dangling', { count: a.count });
          iconName = 'unlink';
          break;
        case 'cloudflare':
          message = t('sub.sum.cloudflare', { count: a.count });
          iconName = 'cloud';
          if (originHost.querySelector('.sub-org')) actions = link('sub-origin-link', t('sub.sum.originLink'), () => jumpToOrigin());
          break;
        case 'wildcard':
          message = t('sub.sum.wildcard', { list: a.list.join(', ') });
          iconName = 'layers';
          break;
        default:
          message = WARNING_CODES.includes(a.key) ? t(`sub.warn.${a.key}`, { detail: a.detail }) : `${a.key}: ${a.detail}`;
      }
      const alert = Alert({ variant: a.variant, compact: true, message, icon: iconName, actions });
      alert.dataset.summary = a.key;
      summaryHost.append(alert);
    }
    renderBadges();
  }

  const cta = h('section', { class: 'sub-cta card', dataset: { cta: 'scan' } },
    h('span', { class: 'sub-cta-icon', attrs: { 'aria-hidden': 'true' } }, Icon('target', { size: 20 })),
    h('div', { class: 'sub-cta-text' },
      h('h3', { class: 'sub-cta-title' }, t('sub.cta.title')),
      h('p', { class: 'sub-cta-body' }, t('sub.cta.body'))),
    Button({
      label: t('sub.cta.button'), iconRight: 'arrow-right', variant: 'primary', className: 'sub-cta-btn', dataset: { action: 'sub-cta' },
      onClick: () => ctx.navigate('scan', { domain: run.config.domains.join(',') })
    }));

  /* --- Origins tab: the ORIGIN panel, or why there is none (yet) ---------------------------- */
  const originEmpty = h('div', { class: 'sub-org-empty' });
  let originEmptyText = null;
  function renderOriginEmpty() {
    let text = null;
    if (!originHost.querySelector('.sub-org')) {
      if (run.status === 'running') text = t('sub.org.pending', { count: listHosts().filter(isProxiedOriginHost).length });
      else text = run.result ? t('sub.org.none') : t('sub.org.unfinished');
    }
    if (text === originEmptyText) return;
    originEmptyText = text;
    clear(originEmpty);
    originEmpty.hidden = !text;
    if (text) originEmpty.append(EmptyState({ icon: 'cloud', message: text, compact: true }));
  }

  /* --- Sources tab: the stage pills, the per-source chips and notes, the free limits --------- */
  const stagesId = uid('sub-stages');
  const sourcesId = uid('sub-sources');
  const sourcesNone = h('p', { class: 'sub-src-none', hidden: true }, t('sub.sources.none'));
  const quotaList = h('ul', { class: 'sub-src-list sub-src-quotas' });
  const quotaBox = h('div', { class: 'sub-src-quota-box' }, h('div', { class: 'sub-src-notes-title' }, t('sub.sources.quotas')), quotaList);
  const sourcesPanel = h('div', { class: 'stack sub-tab-sources' },
    h('section', { class: 'sub-src-section card', dataset: { part: 'stages' }, attrs: { 'aria-labelledby': stagesId } },
      h('h3', { class: 'sub-src-heading', id: stagesId }, t('sub.stages.title')),
      stageList),
    h('section', { class: 'sub-src-section card', dataset: { part: 'sources' }, attrs: { 'aria-labelledby': sourcesId } },
      h('h3', { class: 'sub-src-heading', id: sourcesId }, t('sub.opt.sources')),
      h('p', { class: 'sub-src-hint' }, t('sub.opt.sourcesHint')),
      sourcesNone, sourceWaitNote, chips, sourceNotes, quotaBox));

  /* --- tabs ----------------------------------------------------------------------------------- */
  // Overview: counts and alerts; Hosts: the table (the automatic tab once there is a host);
  // Origins: the ORIGIN panel with the sweep command; Sources: stages, sources and their limits.
  // Every panel is built up front, so a live run updates them all whichever one is shown.
  const opening = initialSubTab({
    route: ctx.params.tab,
    chosen: session.tab,
    hosts: countHosts(listHosts(), { includeWildcard: session.showWildcard }).found,
    running: run.status === 'running'
  });
  if (opening.chosen) session.tab = opening.tab;
  const tabs = Tabs(SUB_TABS.map((tabId) => ({ id: tabId, label: t(`sub.tab.${tabId}`) })), {
    selected: opening.tab,
    label: t('sub.results'),
    className: 'sub-tabs',
    onChange: (tabId) => remember(tabId)
  });
  const panels = {
    overview: h('div', { class: 'stack sub-tab-overview' }, statsGrid, summaryHost, techHost, cta),
    hosts: h('div', { class: 'stack sub-tab-hosts' }, actions, table.el),
    origins: h('div', { class: 'stack sub-tab-origins' }, originEmpty, originHost),
    sources: sourcesPanel
  };
  for (const tabId of SUB_TABS) tabs.panel(tabId).append(panels[tabId]);

  /** A tab the user picked (a click, the arrow keys, a stat card, a link): kept for this run and in the URL. */
  function remember(tabId) {
    session.tab = tabId;
    ctx.setParams({ tab: tabId }, { merge: true });
  }
  /** Open a tab for the user (it counts as their choice). */
  function showTab(tabId, { focus = false } = {}) {
    if (!SUB_TABS.includes(tabId)) return;
    tabs.select(tabId, { focus, silent: true });
    remember(tabId);
  }
  /**
   * An automatic choice follows the run: Sources → Hosts with the first host, Overview when the
   * run ends empty (lib/subtabs.nextAutoTab) — never a tab the user chose, never under the focus.
   */
  function followRun(found) {
    const doc = globalThis.document;
    const next = nextAutoTab(tabs.getSelected(), {
      chosen: session.tab !== null,
      focusInside: !!(doc && doc.activeElement && tabs.el.contains(doc.activeElement)),
      hosts: found,
      running: run.status === 'running'
    });
    if (next) tabs.select(next, { silent: true });
  }
  /** The live counts on the tab labels (lib/subtabs.subTabBadges). */
  let lastCounts = null;
  function renderBadges() {
    const hosts = listHosts();
    const c = lastCounts || countHosts(hosts, { includeWildcard: session.showWildcard });
    const b = subTabBadges({
      found: c.found,
      running: run.status === 'running',
      proxied: hosts.filter(isProxiedOriginHost).length,
      sources: sourceIds().length,
      health: sourceHealthSummary(run.sourceResults),
      alerts
    });
    for (const tabId of SUB_TABS) tabs.setBadge(tabId, b[tabId] ? b[tabId].value : null, b[tabId] ? b[tabId].variant : null);
  }

  const results = h('div', { class: 'sub-results' }, tabs.el);
  const root = h('div', { class: 'stack sub-run-ui', dataset: { run: run.id, status: run.status } }, panel, results);

  /* --- stats rendering ----------------------------------------------------------------- */
  function renderStatsNow() {
    const hosts = listHosts();
    const c = countHosts(hosts, { includeWildcard: session.showWildcard });
    const waiting = run.status === 'running' && hosts.length === 0;
    const v = (n) => (waiting ? '…' : n);
    const hiddenWild = c.wildcard && !session.showWildcard ? t('sub.stat.wildcardHidden', { count: c.wildcard }) : null;
    stat.found.set({ value: v(c.found), hint: hiddenWild || (run.config.domains.length > 1 ? t('sub.stat.foundDomains', { count: run.config.domains.length }) : null) });
    stat.resolving.set({ value: v(c.resolving), hint: t('sub.stat.resolvingHint') });
    stat.cloudflare.set({ value: v(c.cloudflare), hint: t('sub.stat.cloudflareHint') });
    stat.cdn.set({ value: v(c.cdn), hint: providerHint(hosts) || t('sub.stat.cdnHint') });
    stat.direct.set({
      value: v(c.direct),
      hint: inventory ? t('sub.stat.directServers', { count: c.onServers })
        : c.private ? t('sub.stat.directPrivate', { count: c.private }) : t('sub.stat.directHint')
    });
    stat.unresolved.set({ value: v(c.unresolved), hint: t('sub.stat.unresolvedHint') });
    stat.dangling.set({ value: c.dangling, hint: t('sub.stat.danglingHint') });
    stat.dangling.el.hidden = c.dangling === 0 && session.filter !== 'dangling';
    wildLabel.textContent = t('sub.filter.wildcard', { count: c.wildcard });
    wildBox.el.hidden = c.wildcard === 0;
    syncActions();
    lastCounts = c;
    renderBadges();
    renderOriginEmpty();
    followRun(c.found);
  }
  /** Streaming: at most every 150 ms (every host would otherwise walk the whole list). */
  const renderStats = timeThrottle(renderStatsNow, 150);

  /* --- finish ---------------------------------------------------------------------------- */
  function finish() {
    renderTitle();
    renderMeta();
    renderStages();
    renderChips();
    renderSourceWait();
    clear(notice);
    progress.el.hidden = true;
    table.setLoading(false);
    if (run.status === 'done') {
      // The origin panel first: it decides which rows get the "origin?" jump badge.
      renderOrigin();
      table.setRows(run.result.hosts);
      // Rows streamed during resolve were drawn (and cached per object) before renderOrigin filled
      // originCandidates, and setRows keeps that cache: redraw them so their badges appear now.
      table.refresh();
      applyFilter();
      announce(t('sub.doneToast', { count: countHosts(run.result.hosts).found }));
    } else if (run.found && run.found.size) {
      // Cancelled / failed: redraw the streamed partials without their "resolving…" badge
      // (updateRow drops the table's cached row, which setRows with the same objects would keep).
      for (const partial of run.found.values()) table.updateRow(partial);
    }
    if (run.status === 'cancelled') {
      notice.append(Alert({ variant: 'warn', compact: true, message: t('sub.run.cancelled', { time: formatDuration(run.finishedAt - run.startedAt) }) }));
    } else if (run.status === 'error') {
      notice.append(ErrorBanner(run.error, { title: t('sub.run.failed') }));
    }
    renderStatsNow();
    renderTechniques();
    renderSummary();
    stopTicker();
    onFinish();
  }

  /* --- live updates ------------------------------------------------------------------------ */
  let ticker = null;
  function stopTicker() {
    if (ticker) clearInterval(ticker);
    ticker = null;
  }

  // Per-hit updates are batched per frame: a big wordlist streams thousands of hits, and each
  // pill render walks every host. Rows of names shown as a streamed partial are replaced in
  // place; any other full record is appended in a batch (no per-row scan of the table).
  const renderStagesSoon = frameThrottle(renderStages);
  const partialShown = new Set(run.found ? run.found.keys() : []);
  const listener = (type, payload) => {
    switch (type) {
      case 'stage':
        renderStages();
        renderProgress();
        renderSourceWait();
        if (payload.stage === 'sources') renderChips();
        // Announce the stage promptly (not only on the progress bar's 25 % buckets) so a screen
        // reader hears each step change as it happens.
        // A skipped stage (exact zone mode, no wordlist…) is not announced: nothing runs there.
        if (PROGRESS_KEYS[payload.stage] && payload.stage !== 'done'
          && run.stages[payload.stage] && run.stages[payload.stage].state === 'active') announce(t(`sub.progress.${payload.stage}`));
        break;
      case 'progress':
        if (payload && payload.pills) renderStages();
        renderProgress();
        break;
      case 'source':
        renderChips();
        renderSourceWait();
        break;
      case 'found':
        // A streamed probe hit (before the resolve stage): show it live, replaced by the full
        // record when 'host' arrives for the same name.
        partialShown.add(payload.name);
        table.upsertRow(payload);
        renderStats();
        renderStagesSoon();
        break;
      case 'host':
        // The full record replaces any partial of the same name (rowKey = name).
        if (partialShown.delete(payload.name)) table.upsertRow(payload);
        else table.addRows([payload]);
        // The first suspect needs a filter where there was none; afterwards the predicate hides them.
        if (payload.wildcardSuspect && !session.showWildcard && !tableFiltered) applyFilter();
        renderStats();
        renderStagesSoon();
        renderTechniquesSoon();
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
  renderSourceWait();
  const replayHosts = listHosts();
  if (replayHosts.length && !run.result) table.setRows(replayHosts);
  applyFilter();
  renderStatsNow();
  renderTechniques();
  if (run.status === 'running') {
    renderProgress();
    ticker = setInterval(renderMeta, 1000);
    run.listeners.add(listener);
  } else {
    finish();
  }

  return {
    el: root,
    /** Open a results tab (the route's `tab=` changed). */
    showTab,
    dispose() {
      run.listeners.delete(listener);
      stopTicker();
      // Abandon any in-flight network-owner lookups when the panel is torn down.
      try {
        ownerCtl.abort();
      } catch {
        // already aborted / unsupported
      }
    }
  };
}
