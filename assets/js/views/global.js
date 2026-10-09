/**
 * views/global.js — "Global DNS": ask one question to every public DNS-over-HTTPS resolver
 * and — through EDNS Client Subnet (ECS) — on behalf of ~30 locations around the world.
 *
 * - Results stream in (lib/propagation.checkPropagation `onResult`) into two tables that are
 *   pre-filled with "querying…" rows, so the user sees every source from the start.
 * - Identical answers are grouped; every group gets a letter (A, B, C …) and a colour, so the
 *   information never depends on colour alone, and shows who operates its addresses. Clicking a
 *   group filters both tables.
 * - The summary says why answers differ (lib/propagation.propagationVerdict): CDN / GeoDNS edges
 *   differ by design, and so do names before the CDN that lead to the same CDN names (weighted
 *   records) or CNAME chains without records of the type anywhere; NXDOMAIN, SERVFAIL, private
 *   or direct addresses among CDN edges, a CNAME that differs before the CDN and a name that
 *   points to different providers are named as propagation or a misconfiguration; a name nobody
 *   resolves (SERVFAIL everywhere) is an error. A filtering resolver's SafeSearch rewrite is its
 *   policy.
 * - "IP addresses worldwide" lists every address any source returned, who operates it
 *   (Cloudflare / CDN / platform / direct / private) and whether it is one of the user's
 *   servers (inventory) — the "Global DNS should give us the IPs too" request.
 * - The page template (ui/template.js, docs/DESIGN.md §5): the input card (compact once a check
 *   runs: the name box, the options off their default in one line with Edit, Run), the result
 *   header `.glb-summary` — the verdict as its title (lib/propagation.js propagationOutcome), the
 *   record type and the time, what the verdict rests on, the status summary (DNS errors, failed
 *   queries, different answers — by design or not —, blocked answers, how many answered; the
 *   first and the blocked ones filter the tables), Copy summary, Export (the IP addresses as CSV /
 *   JSON) and Copy link, "Also check:" DNS Lookup · Domain Health —, then three tabs: Answer
 *   groups (the figures as a metric strip, the findings as a list, the groups), IP addresses,
 *   Resolvers & locations (the public resolvers, the locations, mainland China, ISP resolvers).
 * - "Copy summary" in the result header (ui/summary-button.js): the verdict, the answers and who
 *   operates them, and the findings, as Markdown for Jira / Slack or plain text.
 * - "ISP resolvers" (ui/isp-resolvers.js, loaded on first use): Globalping probes ask their own
 *   resolvers — the ISPs' — for the same name and type; their rows join the check (kind 'isp'),
 *   so the groups, the IP table and the verdict (stale at these ISPs) take them in.
 * - "Expected value" (lib/expected.js): exact, contains or regex against every answer — each row
 *   says whether it serves the value yet (and until when it may keep the old one), a card counts
 *   them and gives the worst-case wait after a change (the old answer's TTL; for a name that did
 *   not exist, the zone's negative-cache time) — an estimate from cached TTLs, which count down,
 *   until one Globalping question to the zone's own name server (the record's own type, or the SOA
 *   for a new name; ui/soa-probe.js, loaded on first use, on a click) makes it exact — with the
 *   public resolvers' cache-flush pages. Editing it asks nothing again: the answers on screen are
 *   judged anew.
 * - Shareable: `#/global?name=www.example.com&type=A` (optional `geo=0`, `expect=` and
 *   `match=contains|regex`) runs on open — a link's regex is only filled in until the user presses
 *   Enter in the field or edits it; with `run=0` (a name carried over from another tool,
 *   lib/session.js) it is only filled in. The finished check is kept for the page session
 *   (`result()` / `snapshot()`).
 */

import { h, clear, append, debounce, scrollBehavior, uid } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, Disclosure, ErrorBanner, ExternalLink, Icon, KindBadge, ProgressBar, RelativeTime,
  Section, SeverityIcon, Tabs, TruncatedList, announce, checkbox, ipSortValue, select, setButtonBusy, textInput
} from '../ui/components.js';
import { registerStrings, hasString, formatNumber, formatDuration, formatRegion, formatDateTime, formatRelative, localeTag } from '../i18n.js';
import {
  EmptyState, ExampleChips, MetricStrip, PrivacyNote, RelatedLinks, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput, withSubject
} from '../ui/template.js';
import { inputCompact, optionsSummary, statusItems, templateState, toggleStatus } from '../lib/template.js';
import {
  EXPECT_MAX_LENGTH, EXPECT_MODES, FLUSH_LINKS, cacheEnd, expectedEta, expectedTally, expectedVerdict, parseExpected, probeQuestion
} from '../lib/expected.js';
import { RESOLVERS, GEO_VANTAGES, getAnyResolver } from '../lib/resolvers.js';
import { Flag } from '../ui/flag.js';
import {
  checkPropagation, propagationVerdict, propagationOutcome, propagationStatus, propagationStatusMatch, splitChain
} from '../lib/propagation.js';
import { classifyResolution, ipVersion, isPrivateIP, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { mergeSignals, onceAsync } from '../lib/util.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { SummaryButton } from '../ui/summary-button.js';

/** Route id (`#/global`). */
export const id = 'global';
/** i18n key of the page title. */
export const titleKey = 'nav.global';
/** Icon name (ui/components.js Icon). */
export const icon = 'globe';

/** Record types offered (spec §6.3). */
export const GLOBAL_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'HTTPS', 'SOA']);

/** Number of distinct group colours defined in global.css (.glb-g0 … .glb-g7). */
export const GROUP_COLORS = 8;

/** Per-request timeout of the comparison queries (each source is asked once, no retry). */
export const QUERY_TIMEOUT_MS = 5000;

/** Example queries shown under the form. */
const EXAMPLES = [
  { name: 'www.amazon.com', type: 'A' },
  { name: 'www.microsoft.com', type: 'A' },
  { name: 'github.com', type: 'MX' },
  { name: 'cloudflare.com', type: 'NS' }
];

registerStrings('en', {
  'glb.name': 'Host name',
  'glb.namePlaceholder': 'www.example.com',
  'glb.type': 'Record type',
  'glb.geo': 'Also ask on behalf of {count} locations (EDNS Client Subnet)',
  'glb.run': 'Check worldwide',
  'glb.invalidName': 'Enter a valid host name, e.g. www.example.com.',
  'glb.ipGiven': 'That is an IP address. Use IP Intel for addresses, or enter a host name here.',
  'glb.progress': 'Asking resolvers and locations',
  'glb.cancelled': 'Stopped — showing the answers received so far.',
  'glb.how.title': 'Why can answers differ?',
  'glb.how.ecs': 'Locations use EDNS Client Subnet (ECS): Google Public DNS — AliDNS for the mainland China ones — is asked on behalf of a typical home-internet subnet in each place, so the authoritative server answers as if a user there had asked.',
  'glb.how.geo': 'CDNs and GeoDNS services (Cloudflare, Akamai, CloudFront …) deliberately hand out different, nearby servers per region — different IPs per location are normal for them.',
  'glb.how.anycast': 'Public resolvers are anycast: you reach the nearest point of presence (PoP, shown when the resolver reports its NSID). Each PoP has its own cache and its own view of GeoDNS.',
  'glb.how.ttl': 'Right after a DNS change, resolvers keep the old answer until its TTL expires — that is what “DNS propagation” means.',
  'glb.how.filter': 'Filtering resolvers (Quad9, Cloudflare Family, CleanBrowsing) may block a name on purpose; that is shown as “Blocked”, not as a different answer. A SafeSearch rewrite (a search engine’s name sent to its safe-search name, such as forcesafesearch.google.com) is their policy too and is not counted as a difference.',
  'glb.how.browser': 'A web page can only read resolvers that send a CORS header. Quad9 leaves it out over HTTP/3 — which Chrome, Edge and other browsers use for Quad9 — so its rows usually show “Not readable in browsers” instead of an answer.',
  'glb.emptyLine': 'Every answer with its TTL and DNSSEC flag, grouped by what it says and who operates its addresses — and why they differ.',
  'glb.check.locations': 'Locations (ECS)',
  'glb.privacy': 'Sends the name and the record type, from your browser, to {count} public resolvers and — with a client subnet per location — to Google Public DNS and AliDNS. Globalping only from its own buttons.',
  'glb.optNoGeo': 'without the locations',
  'glb.optExpect': 'expected: {value}',
  'glb.checkedAt': 'Checked {time}',
  'glb.typeMeta': '{type} records',
  'glb.metricsLabel': 'The check in numbers',
  'glb.count.servfail': { one: '{count} source answered SERVFAIL', other: '{count} sources answered SERVFAIL' },
  'glb.count.rcode': { one: '{count} source answered with an error ({rcodes})', other: '{count} sources answered with an error ({rcodes})' },
  'glb.count.failed': { one: '{count} query failed', other: '{count} queries failed' },
  'glb.count.differ': '{count} different answers',
  'glb.count.design': '{count} answers, different by design',
  'glb.count.blocked': { one: '{count} answer blocked', other: '{count} answers blocked' },
  'glb.count.answered': '{count} of {total} answered',
  'glb.statusFilterOn': 'Filter: {what}',
  'glb.tab.groups': 'Answer groups',
  'glb.tab.ips': 'IP addresses',
  'glb.tab.resolvers': 'Resolvers & locations',
  'glb.findings.label': 'Why the answers differ',
  'glb.findings.more': 'Show {count} more',
  'glb.export.ipsCsv': 'IP addresses (CSV)',
  'glb.export.ipsJson': 'IP addresses (JSON)',

  'glb.sum.running': 'Collecting answers…',
  'glb.sum.stoppedTitle': 'Stopped',
  'glb.sum.agreeTitle': 'All answers agree',
  'glb.sum.agreeBody': { one: 'The source returned this answer.', other: 'All {count} resolvers and locations returned the same answer.' },
  'glb.sum.geoTitle': 'Resolvers agree — locations differ',
  'glb.sum.geoBody': 'The locations see {groups} different answers. That is normal for CDNs and GeoDNS: every region is sent to nearby servers.',
  'glb.sum.geoTitleUnsure': 'Resolvers agree — locations differ, most likely by GeoDNS',
  'glb.sum.geoBodyUnsure': 'The locations see {groups} different answers. CDNs and GeoDNS send every region to nearby servers, but one difference is not certain:',
  'glb.sum.designTitle': 'Differs by design: CDN / GeoDNS edges ({operators})',
  'glb.sum.designTitleUnsure': 'Most likely by design: CDN / GeoDNS edges ({operators})',
  'glb.sum.designBody': 'Every answer is an edge of a known CDN, platform or DNS steering service, and the CNAME chains agree up to it. Such operators hand out different, nearby servers per region and resolver — this is not propagation.',
  'glb.sum.designSteered': 'Every answer is an edge of a known CDN, platform or DNS steering service. On the way, {owner} sends sources to different names ({targets}), but they lead to the same CDN names: weighted or load-balanced records in the name’s own DNS, not a change. Such operators hand out different, nearby servers per region and resolver — this is not propagation.',
  'glb.sum.designGeo': 'Every answer is an edge of a known CDN, platform or DNS steering service. {owner} sends {sources} to {targets}, unlike every other source. Asked on behalf of a subnet outside China, AliDNS gives the rest of the world’s answer: the name’s own DNS answers the resolvers in mainland China from a line of its own (typically for a CDN there), not a change. Such operators hand out different, nearby servers per region and resolver — this is not propagation.',
  'glb.sum.designGeoUnsure': 'Every answer is an edge of a known CDN, platform or DNS steering service. {owner} sends {sources} to {targets}, unlike every other source: either the name’s own DNS answers the resolvers in mainland China from a line of its own (typically for a CDN there), or AliDNS still holds an older answer — that would expire within {ttl}. AliDNS asked on behalf of a subnet outside China could not tell the two apart.',
  'glb.sum.nodataTitle': 'No {type} records anywhere — the CNAME chains differ by design ({operators})',
  'glb.sum.nodataTitleUnsure': 'No {type} records anywhere — the CNAME chains most likely differ by design ({operators})',
  'glb.sum.nodataBody': 'No source returns {type} records for this name. The CNAME chains differ only by steering (CDN / GeoDNS, weighted or load-balanced records) and all lead to {operators} — this is not propagation.',
  'glb.sum.nodataNone': 'No source returns {type} records for this name.',
  'glb.sum.designMulti': 'More than one operator answers (multi-CDN steering). If you are moving from one to the other, answers that point to the old one stay cached until their TTL expires.',
  'glb.sum.designPart': 'The differences between {operators} edges are by design; these are not:',
  'glb.sum.differTitle': 'Answers differ',
  'glb.sum.differBody': 'The sources return {groups} different answers.',
  'glb.sum.unresolvedTitle': 'No source could resolve the name',
  'glb.sum.failedTitle': 'No answers',
  'glb.sum.failedBody': 'Every query failed. Check your connection, or whether a browser extension or firewall blocks DNS-over-HTTPS.',
  'glb.sum.errors': { one: '{count} query failed (not counted as a difference).', other: '{count} queries failed (not counted as a difference).' },
  'glb.sum.blocked': { one: '{count} answer was blocked by a filtering resolver.', other: '{count} answers were blocked by filtering resolvers.' },
  'glb.sum.rewritten': '{names}: a SafeSearch rewrite ({targets}), the policy of these filtering resolvers — not counted as a difference.',
  'glb.sum.unavailable': '{names}: not readable from a browser (HTTP/3 without a CORS header) — not counted as a failure.',
  'glb.sum.notAsked': '{names}: not asked for {type} — AliDNS’s JSON API cuts large answers short without saying so, so the mainland China rows ask only for A, AAAA, CNAME and HTTPS.',

  'glb.find.rcode': '{sources}: {rcode} — the question was refused or could not be answered. Not a propagation delay.',
  'glb.find.servfail': '{sources}: SERVFAIL — no answer at all, typically a DNSSEC validation failure or name servers that cannot be reached. A fault, not a propagation delay.',
  'glb.find.servfailNoDnssec': '{sources}: SERVFAIL — no answer at all. AliDNS does not validate DNSSEC, so this is no signature problem: from there, the name servers could not be reached or did not answer in time. A fault, not a propagation delay.',
  'glb.find.filtering': 'Only filtering resolvers give this answer, so they may also be blocking the name.',
  'glb.find.nxdomain': '{sources}: NXDOMAIN (the name does not exist), unlike the other answers. The name was created or deleted recently — each answer stays cached until its TTL expires (for NXDOMAIN, the zone’s SOA minimum) — or its name servers disagree.',
  'glb.find.nodata': '{sources}: an empty answer (no {type} records). A record added or removed recently (the empty answer stays cached for the zone’s SOA minimum), or a CNAME target without {type} records there.',
  'glb.find.private': '{sources}: private addresses ({ips}) — an internal (split-horizon) answer or a mistake in the record; nobody on the internet can reach them.',
  'glb.find.mixed': {
    one: '{sources}: a direct address ({ips}) that is not on {operators}. If the name moved onto or off the provider recently, one side is an old answer that stays cached until its TTL expires; otherwise these sources are steered around the provider on purpose.',
    other: '{sources}: direct addresses ({ips}) that are not on {operators}. If the name moved onto or off the provider recently, one side is an old answer that stays cached until its TTL expires; otherwise these sources are steered around the provider on purpose.'
  },
  'glb.find.cname': 'The record at {owner} differs between sources: {targets}. Either it changed recently and the old answer stays cached until its TTL expires, or its DNS sends sources to different names on purpose (GeoDNS, weighted or load-balanced records), or its name servers disagree.',
  'glb.find.cnameMove': 'The record at {owner} points to different providers depending on the source ({operators}): {targets}. A move between them that is still propagating — the old answer stays cached until its TTL expires — unless you steer between providers on purpose.',
  'glb.find.cnameGeo': '{owner} sends {sources} to {targets}, unlike every other source. Asked on behalf of a subnet outside China, AliDNS gives the rest of the world’s answer: the name’s own DNS answers the resolvers in mainland China from a line of its own (typically for a CDN there) — by design, not a change.',
  'glb.find.cnameGeoUnsure': '{owner} sends {sources} to {targets}, unlike every other source: either a line of its own for the resolvers in mainland China (typically for a CDN there), or an older answer AliDNS still holds — that would expire within {ttl}. AliDNS asked on behalf of a subnet outside China could not tell the two apart.',
  'glb.find.operators': 'The {type} records of {name} point to different providers depending on the source ({operators}). A move between them that is still propagating — the old answer stays cached until its TTL expires — unless you steer between providers on purpose.',
  'glb.find.addressRecords': '{type} records',
  'glb.find.noRecords': 'no CNAME and no {type} records',
  'glb.find.direct': 'Different addresses, none on a CDN, platform or steering service this tool knows: typically a recent change that is still propagating (old answers stay cached until their TTL expires), or GeoDNS / round-robin by an operator it does not recognise.',
  'glb.find.records': 'Different records: typically a recent change that is still propagating (old answers stay cached until their TTL expires), or name servers that disagree.',
  'glb.find.more': '+{count} more',
  'glb.find.partner': '{sources}: the China answer ends at a cache name this tool does not recognise ({names}), after {cdn}; it may be the CDN’s partner. It is not counted as the CDN’s own edge, so the answers still differ.',

  'glb.stat.answered': 'Answered',
  'glb.stat.failed': '{count} failed',
  'glb.stat.unavailable': '{count} not readable in browsers',
  'glb.stat.notAsked': '{count} not asked',
  'glb.stat.groups': 'Distinct answers',
  'glb.stat.ips': 'IP addresses',
  'glb.stat.latency': 'Median latency',
  'glb.stat.latencyHint': 'resolvers only',
  'glb.stat.inventory': { zero: 'none of your servers', one: '{count} of your servers', other: '{count} of your servers' },

  'glb.groups.title': 'Answer groups',
  'glb.groups.desc': 'Identical answers share a letter and a colour. Click a group to show only its rows.',
  'glb.group.label': 'Group {letter}',
  'glb.group.members': { one: '{count} source', other: '{count} sources' },
  'glb.group.error': 'Failed',
  'glb.group.blocked': 'Blocked',
  'glb.group.filterOn': 'Showing group {letter} only',
  'glb.group.showAll': 'Show all',

  'glb.ips.title': 'IP addresses worldwide',
  'glb.ips.desc': 'Every address any resolver or location returned — who operates it and whether it is one of your servers.',
  'glb.ips.col.ip': 'IP address',
  'glb.ips.col.owner': 'Operator',
  'glb.ips.col.seen': 'Returned by',
  'glb.ips.col.where': 'Where',
  'glb.ips.col.server': 'Your server',
  'glb.ips.seen': '{count} of {total}',
  'glb.ips.resolvers': { one: '{count} resolver', other: '{count} resolvers' },
  'glb.ips.intel': 'Open in IP Intel',
  'glb.ips.copy': 'Copy IPs',
  'glb.ips.none': 'No A/AAAA addresses in these answers.',

  'glb.res.title': 'Public resolvers',
  'glb.res.desc': '{count} DNS-over-HTTPS resolvers, each asked directly (no failover). Anycast resolvers answer from the PoP nearest to you.',
  'glb.geo.title': 'Locations — GeoDNS via EDNS Client Subnet',
  'glb.geo.desc': 'Google Public DNS asked on behalf of a home-internet subnet in {count} locations: roughly what users there get.',
  'glb.cn.title': 'Mainland China',
  'glb.isp.title': 'ISP resolvers',
  'glb.isp.desc': 'What the resolvers of real ISPs answer, through Globalping probes in the countries and networks you pick — with the TTL each one still caches its answer for.',
  'glb.isp.open': 'Ask ISP resolvers…',
  'glb.cn.desc': 'AliDNS (Alibaba Cloud) asked on behalf of {count} mainland ISPs, each with the /24 of its own DNS servers in Beijing, Shanghai and Guangzhou: roughly what their users get, also for names whose GeoDNS ignores Google’s subnet. Only A, AAAA, CNAME and HTTPS are asked: AliDNS’s JSON API cuts larger answers short without saying so. For A and AAAA it is also asked once on behalf of a US subnet, to tell a China line from an older answer. AliDNS reports no ECS scope and does not validate DNSSEC.',
  'glb.col.resolver': 'Resolver',
  'glb.col.location': 'Location',
  'glb.col.filtering': 'Filtering',
  'glb.col.group': 'Group',
  'glb.col.answer': 'Answer',
  'glb.col.ttl': 'TTL',
  'glb.col.status': 'Status',
  'glb.col.dnssec': 'DNSSEC',
  'glb.col.latency': 'Latency',
  'glb.col.isp': 'ISP',
  'glb.col.subnet': 'Client subnet',
  'glb.col.scope': 'Scope',
  'glb.col.operator': 'Operator',
  'glb.anycast': 'Anycast',
  'glb.pop': 'PoP {id}',
  'glb.popTitle': 'Point of presence that answered (NSID)',
  'glb.adYes': 'Validated',
  'glb.adTitle': 'The resolver validated this answer with DNSSEC (AD flag).',
  'glb.adNo': 'Not validated (unsigned zone, or the resolver did not set AD).',
  'glb.pending': 'Querying…',
  'glb.value.nodata': 'No records',
  'glb.value.nodataTitle': 'The name exists but has no records of this type (NODATA).',
  'glb.value.failed': 'Query failed',
  'glb.value.blocked': 'Blocked',
  'glb.value.blockedTitle': 'This filtering resolver blocks the name (malware or content filter).',
  'glb.value.unavailable': 'Not readable in browsers',
  'glb.value.unavailableShort': 'HTTP/3 without CORS',
  'glb.value.unavailableTitle': '{name} answers browsers over HTTP/3 without a CORS header, so the browser discards the reply. This says nothing about the name — ask {name} from a terminal to see its answer.',
  'glb.value.notAsked': 'Not asked',
  'glb.value.notAskedShort': 'AliDNS’s JSON API cuts large answers short without saying so: only A, AAAA, CNAME and HTTPS are asked.',
  'glb.value.terminal': 'In a terminal:',
  'glb.value.aliasOf': 'alias',
  'glb.scopeTitle': 'ECS scope returned by the authoritative server: /24 means the answer is specific to this subnet, /0 means everyone gets the same answer.',
  'glb.scopeNone': 'Not reported',
  'glb.ttlTitle': 'Cached for {human}',

  'glb.exp.label': 'Expected value (optional)',
  'glb.exp.placeholder': '198.51.100.20 — or NXDOMAIN, or text with Contains',
  'glb.exp.hint': 'After a DNS change: each answer is marked as serving it or not yet, with the worst-case wait. Exact compares the records (several separated by commas; NXDOMAIN or NODATA for none); contains and regex read the whole answer, the CNAME chain too.',
  'glb.exp.held': 'A regular expression from a link is applied only once you press Enter in the field or edit it: a pattern written by someone else could stall this page.',
  'glb.exp.mode': 'Match',
  'glb.exp.mode.exact': 'Exact',
  'glb.exp.mode.contains': 'Contains',
  'glb.exp.mode.regex': 'Regex',
  'glb.exp.err.regex': 'Not a valid regular expression: {detail}',
  'glb.exp.err.long': 'At most {max} characters.',
  'glb.exp.err.address': 'An exact {type} value is an {family} address — {value} is not one. To check the host name the name points to, choose Contains or the CNAME type.',
  'glb.exp.match': 'Matches',
  'glb.exp.mismatch': 'Not yet',
  'glb.exp.mismatchTitle': 'Another answer than the expected value: this source may keep it cached until {time}.',
  'glb.exp.mismatchTitleNoTtl': 'Another answer than the expected value.',
  'glb.exp.mismatchTitleExpired': 'Another answer than the expected value; this source’s cached copy has expired since — check again to see it now.',
  'glb.exp.col': 'Expected value',
  'glb.exp.title': 'Expected value',
  'glb.exp.count': { one: 'Served by {match} of {judged} source', other: 'Served by {match} of {judged} sources' },
  'glb.exp.failed': { one: '{count} failed', other: '{count} failed' },
  'glb.exp.done': 'Every source that answered serves the expected value.',
  'glb.exp.none': 'No source has answered yet.',
  'glb.exp.notYet': {
    one: '{count} source still gives another answer; its cached copy expires by {time} ({left}).',
    other: '{count} sources still give another answer; the last of their cached copies expires by {time} ({left}).'
  },
  'glb.exp.notYetNoTtl': { one: '{count} source still gives another answer.', other: '{count} sources still give another answer.' },
  'glb.exp.worst': 'Worst case for any resolver in the world: {duration} after the change was published.',
  'glb.exp.estimate': 'Worst case for any resolver in the world: at least {least} after the change was published, most likely {duration}.',
  'glb.exp.estimateLikely': 'Worst case for any resolver in the world: most likely {duration} after the change was published.',
  'glb.exp.estimateHint': 'Cached TTLs count down, so this is an estimate: the zone’s name server can give the exact figure.',
  'glb.exp.worstRecord': 'The old answer’s TTL is most likely {ttl} s (the highest an answer here still carried was {seen} s).',
  'glb.exp.recordNs': 'The record’s TTL at the zone’s name server {ns}: {ttl} s.',
  'glb.exp.recordLower': 'The zone’s name server {ns} now serves a TTL of {ttl} s, lower than the old answer’s: it was most likely lowered with the change.',
  'glb.exp.negAnswers': 'Where the name or record did not exist before, a resolver that asked then keeps that “no such record” answer for the zone’s negative-cache time: most likely {ttl} s, read from the SOA in their answers.',
  'glb.exp.negNs': 'Where the name or record did not exist before, a resolver that asked then keeps that “no such record” answer for the zone’s negative-cache time: {ttl} s, as the zone’s name server {ns} serves it.',
  'glb.exp.worstUnknown': 'The old answer carried no TTL, so there is no worst case to give.',
  'glb.exp.flush': 'Speed it up: ask the public resolvers to drop their cached copy —',
  'glb.exp.onlyMissing': { one: 'Show only the source not there yet', other: 'Show only the {count} sources not there yet' },
  'glb.exp.filterOn': 'Showing only the sources that do not serve the expected value yet',
  'glb.exp.expired': {
    one: '{count} source gave another answer; its cached copy has expired since — check again to see it now.',
    other: '{count} sources gave another answer; their cached copies have expired since — check again to see them now.'
  },
  'glb.exp.probe': 'Ask the zone’s name server (1 Globalping probe)',
  'glb.exp.probeHint': 'One Globalping probe asks the zone’s own name server this check’s question: the record’s TTL there (for a name that did not exist, the zone’s negative-cache time) and whether the name exists there. Nothing is sent before you press it.',
  'glb.exp.probeLoadFailed': 'The name server check could not be loaded.'
});

registerStrings('tr', {
  'glb.name': 'Host adı',
  'glb.namePlaceholder': 'www.ornek.com.tr',
  'glb.type': 'Kayıt türü',
  'glb.geo': '{count} konum adına da sor (EDNS Client Subnet)',
  'glb.run': 'Dünya genelinde kontrol et',
  'glb.invalidName': 'Geçerli bir host adı girin, ör. www.ornek.com.tr.',
  'glb.ipGiven': 'Bu bir IP adresi. Adresler için IP Bilgisi aracını kullanın ya da buraya bir host adı girin.',
  'glb.progress': 'Çözümleyicilere ve konumlara soruluyor',
  'glb.cancelled': 'Durduruldu — o ana kadar gelen yanıtlar gösteriliyor.',
  'glb.how.title': 'Yanıtlar neden farklı olabilir?',
  'glb.how.ecs': 'Konumlar EDNS Client Subnet (ECS) kullanır: Google Public DNS’e — anakara Çin’dekiler için AliDNS’e — her yerdeki tipik bir ev interneti alt ağı adına sorulur; yetkili sunucu, oradaki bir kullanıcı sormuş gibi yanıt verir.',
  'glb.how.geo': 'CDN’ler ve GeoDNS hizmetleri (Cloudflare, Akamai, CloudFront …) her bölgeye bilerek farklı ve yakın sunucular verir — konuma göre farklı IP’ler onlar için normaldir.',
  'glb.how.anycast': 'Genel çözümleyiciler anycast’tir: size en yakın erişim noktasına (PoP; çözümleyici NSID bildiriyorsa gösterilir) bağlanırsınız. Her PoP’un kendi önbelleği ve kendi GeoDNS görünümü vardır.',
  'glb.how.ttl': 'Bir DNS değişikliğinden hemen sonra çözümleyiciler eski yanıtı TTL süresi dolana kadar tutar — “DNS yayılması” (propagation) budur.',
  'glb.how.filter': 'Filtreleyen çözümleyiciler (Quad9, Cloudflare Family, CleanBrowsing) bir adı bilerek engelleyebilir; bu farklı bir yanıt olarak değil “Engellendi” olarak gösterilir. SafeSearch yönlendirmesi de (bir arama motorunun adının forcesafesearch.google.com gibi güvenli arama adına gönderilmesi) onların politikasıdır ve farklılık sayılmaz.',
  'glb.how.browser': 'Bir web sayfası yalnızca CORS başlığı gönderen çözümleyicileri okuyabilir. Quad9 bu başlığı HTTP/3’te göndermiyor — Chrome, Edge ve diğer tarayıcılar Quad9 için HTTP/3 kullanıyor — bu yüzden satırlarında genellikle yanıt yerine “Tarayıcıda okunamıyor” görünür.',
  'glb.emptyLine': 'Her yanıt TTL’i ve DNSSEC bayrağıyla; söylediğine ve adreslerini kimin işlettiğine göre gruplanmış — ve neden farklı oldukları.',
  'glb.check.locations': 'Konumlar (ECS)',
  'glb.privacy': 'Adı ve kayıt türünü tarayıcınızdan {count} genel çözümleyiciye ve — her konum için bir istemci alt ağıyla — Google Public DNS ile AliDNS’e gönderir. Globalping’e yalnızca kendi düğmelerinden.',
  'glb.optNoGeo': 'konumlar olmadan',
  'glb.optExpect': 'beklenen: {value}',
  'glb.checkedAt': 'Kontrol: {time}',
  'glb.typeMeta': '{type} kayıtları',
  'glb.metricsLabel': 'Sayılarla kontrol',
  'glb.count.servfail': '{count} kaynak SERVFAIL yanıtı verdi',
  'glb.count.rcode': '{count} kaynak hata yanıtı verdi ({rcodes})',
  'glb.count.failed': '{count} sorgu başarısız oldu',
  'glb.count.differ': '{count} farklı yanıt',
  'glb.count.design': '{count} yanıt, tasarım gereği farklı',
  'glb.count.blocked': '{count} yanıt engellendi',
  'glb.count.answered': '{total} kaynaktan {count} tanesi yanıtladı',
  'glb.statusFilterOn': 'Filtre: {what}',
  'glb.tab.groups': 'Yanıt grupları',
  'glb.tab.ips': 'IP adresleri',
  'glb.tab.resolvers': 'Çözümleyiciler ve konumlar',
  'glb.findings.label': 'Yanıtlar neden farklı',
  'glb.findings.more': '{count} tane daha göster',
  'glb.export.ipsCsv': 'IP adresleri (CSV)',
  'glb.export.ipsJson': 'IP adresleri (JSON)',

  'glb.sum.running': 'Yanıtlar toplanıyor…',
  'glb.sum.stoppedTitle': 'Durduruldu',
  'glb.sum.agreeTitle': 'Tüm yanıtlar aynı',
  'glb.sum.agreeBody': { one: 'Kaynak bu yanıtı döndürdü.', other: '{count} çözümleyici ve konumun hepsi aynı yanıtı döndürdü.' },
  'glb.sum.geoTitle': 'Çözümleyiciler aynı — konumlar farklı',
  'glb.sum.geoBody': 'Konumlar {groups} farklı yanıt görüyor. CDN ve GeoDNS için bu normaldir: her bölge yakınındaki sunuculara yönlendirilir.',
  'glb.sum.geoTitleUnsure': 'Çözümleyiciler aynı — konumlar büyük olasılıkla GeoDNS yüzünden farklı',
  'glb.sum.geoBodyUnsure': 'Konumlar {groups} farklı yanıt görüyor. CDN ve GeoDNS her bölgeyi yakınındaki sunuculara yönlendirir, ama farklardan biri kesin değil:',
  'glb.sum.designTitle': 'Tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators})',
  'glb.sum.designTitleUnsure': 'Büyük olasılıkla tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators})',
  'glb.sum.designBody': 'Her yanıt bilinen bir CDN’in, platformun ya da DNS yönlendirme hizmetinin uç sunucusu ve CNAME zincirleri ona kadar aynı. Bu sağlayıcılar her bölgeye ve çözümleyiciye farklı, yakın sunucular verir — bu bir yayılma (propagation) sorunu değil.',
  'glb.sum.designSteered': 'Her yanıt bilinen bir CDN’in, platformun ya da DNS yönlendirme hizmetinin uç sunucusu. Yol üzerinde {owner} kaynakları farklı adlara gönderiyor ({targets}), ama bunlar aynı CDN adlarına çıkıyor: adın kendi DNS’indeki ağırlıklı ya da yük dengeleyen kayıtlar, bir değişiklik değil. Bu sağlayıcılar her bölgeye ve çözümleyiciye farklı, yakın sunucular verir — bu bir yayılma (propagation) sorunu değil.',
  'glb.sum.designGeo': 'Her yanıt bilinen bir CDN’in, platformun ya da DNS yönlendirme hizmetinin uç sunucusu. {owner}, {sources} konumlarını diğer tüm kaynaklardan farklı bir yere ({targets}) gönderiyor. Anakara Çin dışındaki bir alt ağ adına sorulduğunda AliDNS dünyanın geri kalanının yanıtını veriyor: adın kendi DNS’i anakara Çin’deki çözümleyicilere ayrı bir hattan yanıt veriyor (genellikle oradaki bir CDN için), bu bir değişiklik değil. Bu sağlayıcılar her bölgeye ve çözümleyiciye farklı, yakın sunucular verir — bu bir yayılma (propagation) sorunu değil.',
  'glb.sum.designGeoUnsure': 'Her yanıt bilinen bir CDN’in, platformun ya da DNS yönlendirme hizmetinin uç sunucusu. {owner}, {sources} konumlarını diğer tüm kaynaklardan farklı bir yere ({targets}) gönderiyor: ya adın kendi DNS’i anakara Çin’deki çözümleyicilere ayrı bir hattan yanıt veriyor (genellikle oradaki bir CDN için) ya da AliDNS hâlâ eski bir yanıtı tutuyor — o yanıt en geç {ttl} içinde sona erer. Anakara Çin dışındaki bir alt ağ adına AliDNS’e sormak bu ikisini ayırt edemedi.',
  'glb.sum.nodataTitle': 'Hiçbir kaynakta {type} kaydı yok — CNAME zincirleri tasarım gereği farklı ({operators})',
  'glb.sum.nodataTitleUnsure': 'Hiçbir kaynakta {type} kaydı yok — CNAME zincirleri büyük olasılıkla tasarım gereği farklı ({operators})',
  'glb.sum.nodataBody': 'Hiçbir kaynak bu ad için {type} kaydı döndürmüyor. CNAME zincirleri yalnızca yönlendirme (CDN / GeoDNS, ağırlıklı ya da yük dengeleyen kayıtlar) yüzünden farklı ve hepsi {operators} adlarına çıkıyor — bu bir yayılma (propagation) sorunu değil.',
  'glb.sum.nodataNone': 'Hiçbir kaynak bu ad için {type} kaydı döndürmüyor.',
  'glb.sum.designMulti': 'Birden fazla sağlayıcı yanıt veriyor (çoklu CDN yönlendirmesi). Birinden diğerine geçiyorsanız, eskisini gösteren yanıtlar TTL süresi dolana kadar önbellekte kalır.',
  'glb.sum.designPart': '{operators} uç sunucuları arasındaki farklar tasarım gereği; şunlar öyle değil:',
  'glb.sum.differTitle': 'Yanıtlar farklı',
  'glb.sum.differBody': 'Kaynaklar {groups} farklı yanıt döndürüyor.',
  'glb.sum.unresolvedTitle': 'Hiçbir kaynak adı çözümleyemedi',
  'glb.sum.failedTitle': 'Yanıt alınamadı',
  'glb.sum.failedBody': 'Tüm sorgular başarısız oldu. Bağlantınızı ya da bir tarayıcı eklentisinin veya güvenlik duvarının DNS-over-HTTPS’i engelleyip engellemediğini kontrol edin.',
  'glb.sum.errors': '{count} sorgu başarısız oldu (farklılık sayılmadı).',
  'glb.sum.blocked': '{count} yanıt filtreleyen çözümleyiciler tarafından engellendi.',
  'glb.sum.rewritten': '{names}: SafeSearch yönlendirmesi ({targets}); bu filtreleyen çözümleyicilerin politikası — farklılık sayılmadı.',
  'glb.sum.unavailable': '{names}: tarayıcıdan okunamıyor (HTTP/3’te CORS başlığı yok) — başarısız sayılmadı.',
  'glb.sum.notAsked': '{names}: {type} için sorulmadı — AliDNS’in JSON API’si büyük yanıtları haber vermeden kırpıyor; bu yüzden anakara Çin satırları yalnızca A, AAAA, CNAME ve HTTPS sorar.',

  'glb.find.rcode': '{sources}: {rcode} — soru reddedildi ya da yanıtlanamadı. Bu bir yayılma gecikmesi değil.',
  'glb.find.servfail': '{sources}: SERVFAIL — hiç yanıt yok; genellikle DNSSEC doğrulama hatası ya da ulaşılamayan ad sunucuları. Bu bir arıza, yayılma gecikmesi değil.',
  'glb.find.servfailNoDnssec': '{sources}: SERVFAIL — hiç yanıt yok. AliDNS DNSSEC doğrulaması yapmadığı için bu bir imza sorunu değil: oradan ad sunucularına ulaşılamadı ya da zamanında yanıt vermediler. Bu bir arıza, yayılma gecikmesi değil.',
  'glb.find.filtering': 'Bu yanıtı yalnızca filtreleyen çözümleyiciler veriyor; adı engelliyor da olabilirler.',
  'glb.find.nxdomain': '{sources}: NXDOMAIN (ad mevcut değil), diğer yanıtlardan farklı olarak. Ad yakın zamanda oluşturuldu ya da silindi — her yanıt TTL süresi dolana kadar önbellekte kalır (NXDOMAIN için bölgenin SOA minimum değeri) — ya da ad sunucuları birbiriyle çelişiyor.',
  'glb.find.nodata': '{sources}: boş yanıt ({type} kaydı yok). Yakın zamanda eklenen ya da silinen bir kayıt (boş yanıt, bölgenin SOA minimum süresi boyunca önbellekte kalır) ya da orada {type} kaydı olmayan bir CNAME hedefi.',
  'glb.find.private': '{sources}: özel adresler ({ips}) — iç ağa ait bir yanıt (split-horizon) ya da kayıtta bir hata; internetten kimse bu adreslere ulaşamaz.',
  'glb.find.mixed': {
    one: '{sources}: {operators} üzerinde olmayan doğrudan bir adres ({ips}). Ad yakın zamanda sağlayıcıya taşındıysa ya da sağlayıcıdan çıkarıldıysa taraflardan biri, TTL süresi dolana kadar önbellekte kalan eski yanıttır; değilse bu kaynaklar bilerek sağlayıcının dışına yönlendiriliyor.',
    other: '{sources}: {operators} üzerinde olmayan doğrudan adresler ({ips}). Ad yakın zamanda sağlayıcıya taşındıysa ya da sağlayıcıdan çıkarıldıysa taraflardan biri, TTL süresi dolana kadar önbellekte kalan eski yanıttır; değilse bu kaynaklar bilerek sağlayıcının dışına yönlendiriliyor.'
  },
  'glb.find.cname': '{owner} kaydı kaynaklara göre farklı: {targets}. Ya kayıt yakın zamanda değişti ve eski yanıt TTL süresi dolana kadar önbellekte kalıyor, ya adın DNS’i kaynakları bilerek farklı adlara gönderiyor (GeoDNS, ağırlıklı ya da yük dengeleyen kayıtlar), ya da ad sunucuları birbiriyle çelişiyor.',
  'glb.find.cnameMove': '{owner} kaydı kaynağa göre farklı sağlayıcıları gösteriyor ({operators}): {targets}. Sağlayıcılar arasında bilerek yönlendirme yapmıyorsanız bu, hâlâ yayılmakta olan bir taşıma — eski yanıt TTL süresi dolana kadar önbellekte kalır.',
  'glb.find.cnameGeo': '{owner}, {sources} konumlarını diğer tüm kaynaklardan farklı bir yere ({targets}) gönderiyor. Anakara Çin dışındaki bir alt ağ adına sorulduğunda AliDNS dünyanın geri kalanının yanıtını veriyor: adın kendi DNS’i anakara Çin’deki çözümleyicilere ayrı bir hattan yanıt veriyor (genellikle oradaki bir CDN için) — tasarım gereği, bir değişiklik değil.',
  'glb.find.cnameGeoUnsure': '{owner}, {sources} konumlarını diğer tüm kaynaklardan farklı bir yere ({targets}) gönderiyor: ya anakara Çin’deki çözümleyiciler için ayrı bir hat (genellikle oradaki bir CDN için) ya da AliDNS’in hâlâ tuttuğu eski bir yanıt — o yanıt en geç {ttl} içinde sona erer. Anakara Çin dışındaki bir alt ağ adına AliDNS’e sormak bu ikisini ayırt edemedi.',
  'glb.find.operators': '{name} adının {type} kayıtları kaynağa göre farklı sağlayıcıları gösteriyor ({operators}). Sağlayıcılar arasında bilerek yönlendirme yapmıyorsanız bu, hâlâ yayılmakta olan bir taşıma — eski yanıt TTL süresi dolana kadar önbellekte kalır.',
  'glb.find.addressRecords': '{type} kayıtları',
  'glb.find.noRecords': 'CNAME ve {type} kaydı yok',
  'glb.find.direct': 'Farklı adresler; hiçbiri bu aracın tanıdığı bir CDN’de, platformda ya da yönlendirme hizmetinde değil: genellikle hâlâ yayılmakta olan yeni bir değişiklik (eski yanıtlar TTL dolana kadar önbellekte kalır) ya da tanımadığı bir sağlayıcının GeoDNS / round-robin dağıtımı.',
  'glb.find.records': 'Farklı kayıtlar: genellikle hâlâ yayılmakta olan yeni bir değişiklik (eski yanıtlar TTL dolana kadar önbellekte kalır) ya da birbiriyle çelişen ad sunucuları.',
  'glb.find.more': '+{count} tane daha',
  'glb.find.partner': '{sources}: Çin’deki yanıt, {cdn} üzerinden geçtikten sonra bu aracın tanımadığı bir önbellek adında ({names}) bitiyor; bu CDN’in iş ortağı olabilir. CDN’in kendi uç sunucusu sayılmadığı için yanıtlar yine farklı görünüyor.',

  'glb.stat.answered': 'Yanıtlanan',
  'glb.stat.failed': '{count} başarısız',
  'glb.stat.unavailable': '{count} tanesi tarayıcıda okunamıyor',
  'glb.stat.notAsked': '{count} tanesi sorulmadı',
  'glb.stat.groups': 'Farklı yanıt',
  'glb.stat.ips': 'IP adresi',
  'glb.stat.latency': 'Ortanca gecikme',
  'glb.stat.latencyHint': 'yalnızca çözümleyiciler',
  'glb.stat.inventory': { zero: 'sunucularınızdan hiçbiri değil', other: '{count} tanesi sizin sunucunuz' },

  'glb.groups.title': 'Yanıt grupları',
  'glb.groups.desc': 'Aynı yanıtlar aynı harfi ve rengi paylaşır. Yalnızca o grubun satırlarını görmek için gruba tıklayın.',
  'glb.group.label': '{letter} grubu',
  'glb.group.members': '{count} kaynak',
  'glb.group.error': 'Başarısız',
  'glb.group.blocked': 'Engellendi',
  'glb.group.filterOn': 'Yalnızca {letter} grubu gösteriliyor',
  'glb.group.showAll': 'Tümünü göster',

  'glb.ips.title': 'Dünya genelindeki IP adresleri',
  'glb.ips.desc': 'Herhangi bir çözümleyicinin ya da konumun döndürdüğü tüm adresler — kimin işlettiği ve sizin sunucularınızdan biri olup olmadığı.',
  'glb.ips.col.ip': 'IP adresi',
  'glb.ips.col.owner': 'İşleten',
  'glb.ips.col.seen': 'Döndüren',
  'glb.ips.col.where': 'Nerede',
  'glb.ips.col.server': 'Sunucunuz',
  'glb.ips.seen': '{total} kaynaktan {count}',
  'glb.ips.resolvers': '{count} çözümleyici',
  'glb.ips.intel': 'IP Bilgisi’nde aç',
  'glb.ips.copy': 'IP’leri kopyala',
  'glb.ips.none': 'Bu yanıtlarda A/AAAA adresi yok.',

  'glb.res.title': 'Genel çözümleyiciler',
  'glb.res.desc': '{count} DNS-over-HTTPS çözümleyicisi; her birine doğrudan (yedeğe geçmeden) soruldu. Anycast çözümleyiciler size en yakın PoP’tan yanıt verir.',
  'glb.geo.title': 'Konumlar — EDNS Client Subnet ile GeoDNS',
  'glb.geo.desc': 'Google Public DNS’e {count} konumdaki bir ev interneti alt ağı adına soruldu: oradaki kullanıcıların aldığı yanıta yakındır.',
  'glb.cn.title': 'Anakara Çin',
  'glb.isp.title': 'İSS çözümleyicileri',
  'glb.isp.desc': 'Gerçek İSS’lerin çözümleyicilerinin verdiği yanıtlar: seçtiğiniz ülke ve ağlardaki Globalping ölçüm noktalarıyla, her birinin yanıtı önbellekte daha ne kadar tutacağıyla birlikte.',
  'glb.isp.open': 'İSS çözümleyicilerine sor…',
  'glb.cn.desc': 'AliDNS’e (Alibaba Cloud) {count} anakara Çin internet sağlayıcısı adına, her birinin Pekin, Şanghay ve Guangzhou’daki kendi DNS sunucularının /24’üyle soruldu: o sağlayıcıların kullanıcılarının aldığı yanıta yakındır — GeoDNS’i Google’ın gönderdiği alt ağı dikkate almayan adlarda da. Yalnızca A, AAAA, CNAME ve HTTPS sorulur: AliDNS’in JSON API’si daha büyük yanıtları haber vermeden kırpıyor. A ve AAAA için ayrıca bir kez ABD’deki bir alt ağ adına sorulur: Çin’e özel bir hattı eski bir yanıttan ayırt etmek için. AliDNS ECS kapsamı bildirmez ve DNSSEC doğrulaması yapmaz.',
  'glb.col.resolver': 'Çözümleyici',
  'glb.col.location': 'Konum',
  'glb.col.filtering': 'Filtreleme',
  'glb.col.group': 'Grup',
  'glb.col.answer': 'Yanıt',
  'glb.col.ttl': 'TTL',
  'glb.col.status': 'Durum',
  'glb.col.dnssec': 'DNSSEC',
  'glb.col.latency': 'Gecikme',
  'glb.col.isp': 'İnternet sağlayıcı',
  'glb.col.subnet': 'İstemci alt ağı',
  'glb.col.scope': 'Kapsam',
  'glb.col.operator': 'İşleten',
  'glb.anycast': 'Anycast',
  'glb.pop': 'PoP {id}',
  'glb.popTitle': 'Yanıt veren erişim noktası (NSID)',
  'glb.adYes': 'Doğrulandı',
  'glb.adTitle': 'Çözümleyici bu yanıtı DNSSEC ile doğruladı (AD bayrağı).',
  'glb.adNo': 'Doğrulanmadı (imzasız bölge ya da çözümleyici AD bayrağını koymadı).',
  'glb.pending': 'Sorgulanıyor…',
  'glb.value.nodata': 'Kayıt yok',
  'glb.value.nodataTitle': 'Ad mevcut ama bu türde kaydı yok (NODATA).',
  'glb.value.failed': 'Sorgu başarısız',
  'glb.value.blocked': 'Engellendi',
  'glb.value.blockedTitle': 'Bu filtreleyen çözümleyici adı engelliyor (zararlı yazılım ya da içerik filtresi).',
  'glb.value.unavailable': 'Tarayıcıda okunamıyor',
  'glb.value.unavailableShort': 'HTTP/3’te CORS yok',
  'glb.value.unavailableTitle': '{name}, tarayıcılara HTTP/3 üzerinden CORS başlığı olmadan yanıt veriyor; tarayıcı da bu yüzden yanıtı atıyor. Bu, sorgulanan adla ilgili bir sorun değil — {name} yanıtını görmek için terminalden sorun.',
  'glb.value.notAsked': 'Sorulmadı',
  'glb.value.notAskedShort': 'AliDNS’in JSON API’si büyük yanıtları haber vermeden kırpıyor: yalnızca A, AAAA, CNAME ve HTTPS sorulur.',
  'glb.value.terminal': 'Terminalde:',
  'glb.value.aliasOf': 'takma ad',
  'glb.scopeTitle': 'Yetkili sunucunun döndürdüğü ECS kapsamı: /24 yanıtın bu alt ağa özel olduğunu, /0 herkesin aynı yanıtı aldığını gösterir.',
  'glb.scopeNone': 'Bildirilmedi',
  'glb.ttlTitle': '{human} boyunca önbellekte tutulur',

  'glb.exp.label': 'Beklenen değer (isteğe bağlı)',
  'glb.exp.placeholder': '198.51.100.20 — ya da NXDOMAIN, ya da İçerir ile bir metin',
  'glb.exp.hint': 'Bir DNS değişikliğinden sonra: her yanıt, beklenen değeri döndürüyor ya da henüz döndürmüyor olarak işaretlenir; en kötü durumda ne kadar bekleneceği de gösterilir. Tam eşleşme kayıtları karşılaştırır (birden fazlasını virgülle ayırın; hiç kayıt yoksa NXDOMAIN ya da NODATA); içerir ve regex, CNAME zinciri dahil yanıtın tamamını okur.',
  'glb.exp.held': 'Bağlantıyla gelen bir düzenli ifade, ancak alanda Enter’a bastığınızda ya da onu düzenlediğinizde uygulanır: başkasının yazdığı bir ifade bu sayfayı kilitleyebilir.',
  'glb.exp.mode': 'Eşleşme',
  'glb.exp.mode.exact': 'Tam',
  'glb.exp.mode.contains': 'İçerir',
  'glb.exp.mode.regex': 'Regex',
  'glb.exp.err.regex': 'Geçerli bir düzenli ifade değil: {detail}',
  'glb.exp.err.long': 'En fazla {max} karakter.',
  'glb.exp.err.address': 'Tam eşleşmede bir {type} değeri {family} adresi olmalı; {value} bir {family} adresi değil. Adın işaret ettiği host adını denetlemek için İçerir’i ya da CNAME türünü seçin.',
  'glb.exp.match': 'Eşleşiyor',
  'glb.exp.mismatch': 'Henüz değil',
  'glb.exp.mismatchTitle': 'Beklenen değerden farklı bir yanıt: bu kaynak onu {time} saatine kadar önbellekte tutabilir.',
  'glb.exp.mismatchTitleNoTtl': 'Beklenen değerden farklı bir yanıt.',
  'glb.exp.mismatchTitleExpired': 'Beklenen değerden farklı bir yanıt; bu kaynağın önbellekteki kopyasının süresi o zamandan beri doldu — güncel hâlini görmek için yeniden kontrol edin.',
  'glb.exp.col': 'Beklenen değer',
  'glb.exp.title': 'Beklenen değer',
  'glb.exp.count': '{judged} kaynaktan {match} tanesi döndürüyor',
  'glb.exp.failed': '{count} tanesi başarısız',
  'glb.exp.done': 'Yanıt veren her kaynak beklenen değeri döndürüyor.',
  'glb.exp.none': 'Henüz yanıt veren kaynak yok.',
  'glb.exp.notYet': '{count} kaynak hâlâ başka bir yanıt veriyor; önbellekteki kopyalarının sonuncusunun süresi en geç {time} saatinde ({left}) doluyor.',
  'glb.exp.notYetNoTtl': '{count} kaynak hâlâ başka bir yanıt veriyor.',
  'glb.exp.worst': 'Dünyadaki herhangi bir çözümleyici için en kötü durum: değişiklik yayımlandıktan {duration} sonra.',
  'glb.exp.estimate': 'Dünyadaki herhangi bir çözümleyici için en kötü durum: değişiklik yayımlandıktan en az {least}, büyük olasılıkla {duration} sonra.',
  'glb.exp.estimateLikely': 'Dünyadaki herhangi bir çözümleyici için en kötü durum: değişiklik yayımlandıktan büyük olasılıkla {duration} sonra.',
  'glb.exp.estimateHint': 'Önbellekteki TTL değerleri geri sayar; bu yüzden bu bir tahmin. Kesin değeri bölgenin ad sunucusu verebilir.',
  'glb.exp.worstRecord': 'Eski yanıtın TTL değeri büyük olasılıkla {ttl} sn (buradaki bir yanıtın hâlâ taşıdığı en yüksek değer {seen} sn).',
  'glb.exp.recordNs': 'Kaydın, bölgenin ad sunucusu {ns} üzerindeki TTL değeri: {ttl} sn.',
  'glb.exp.recordLower': 'Bölgenin ad sunucusu {ns} artık {ttl} sn’lik bir TTL veriyor; bu eski yanıtınkinden düşük, yani TTL büyük olasılıkla değişiklikle birlikte düşürüldü.',
  'glb.exp.negAnswers': 'Ad ya da kayıt daha önce yoksa, o zaman soran bir çözümleyici bu “kayıt yok” yanıtını bölgenin negatif önbellek süresi boyunca tutar: büyük olasılıkla {ttl} sn (yanıtlarındaki SOA kaydından okundu).',
  'glb.exp.negNs': 'Ad ya da kayıt daha önce yoksa, o zaman soran bir çözümleyici bu “kayıt yok” yanıtını bölgenin negatif önbellek süresi boyunca tutar: {ttl} sn (bölgenin ad sunucusu {ns} böyle bildiriyor).',
  'glb.exp.worstUnknown': 'Eski yanıtta TTL değeri yoktu; bu yüzden bir en kötü durum verilemiyor.',
  'glb.exp.flush': 'Hızlandırmak için genel çözümleyicilerden önbellekteki kopyayı silmelerini isteyin —',
  'glb.exp.onlyMissing': 'Yalnızca değişikliğin henüz ulaşmadığı {count} kaynağı göster',
  'glb.exp.filterOn': 'Yalnızca beklenen değeri henüz döndürmeyen kaynaklar gösteriliyor',
  'glb.exp.expired': '{count} kaynak başka bir yanıt vermişti; önbellekteki kopyalarının süresi o zamandan beri doldu — güncel hâlini görmek için yeniden kontrol edin.',
  'glb.exp.probe': 'Bölgenin ad sunucusuna sor (1 Globalping ölçümü)',
  'glb.exp.probeHint': 'Tek bir Globalping ölçüm noktası, bölgenin kendi ad sunucusuna bu kontrolün sorusunu sorar: kaydın oradaki TTL değeri (daha önce olmayan bir ad için bölgenin negatif önbellek süresi) ve adın orada olup olmadığı. Düğmeye basana kadar hiçbir şey gönderilmez.',
  'glb.exp.probeLoadFailed': 'Ad sunucusu kontrolü yüklenemedi.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Spreadsheet-style group letter: 0 → 'A', 25 → 'Z', 26 → 'AA', 27 → 'AB' …
 * @param {number} index
 * @returns {string}
 */
export function groupLetter(index) {
  let n = Math.max(0, Math.floor(Number(index) || 0));
  let out = '';
  do {
    out = String.fromCharCode(65 + (n % 26)) + out;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return out;
}

const isErrorValues = (values) => Array.isArray(values) && values.length === 1 && values[0] === 'ERROR';

/** Classic-DNS address of the resolvers browsers cannot read, for a copyable terminal command. */
const TERMINAL_DNS = Object.freeze({ quad9: '9.9.9.9', 'quad9-ecs': '9.9.9.11' });

/**
 * Is a finished row a resolver that browsers cannot read (resolvers.js `browserReliable: false`;
 * Quad9 answers over HTTP/3 without a CORS header) whose query failed at transport level?
 * Such rows are shown muted as "Not readable in browsers": they are not failures, get no answer
 * group and are not counted as errors. When such a resolver does answer (e.g. on a network that
 * blocks QUIC, so the browser falls back to HTTP/2), the row is an ordinary answer.
 * @param {{ kind?: string, pending?: boolean, values?: string[]|null, resolver?: object|null }|null} row
 * @returns {boolean}
 */
export function isBrowserBlocked(row) {
  return !!row && !row.pending && row.kind !== 'geo' && !!row.resolver
    && row.resolver.browserReliable === false && isErrorValues(row.values);
}

/**
 * Is a finished row a location that was not asked for this record type (lib/propagation.js
 * `notAsked`: the mainland China rows' AliDNS cuts large answers short, so it is asked only for A,
 * AAAA, CNAME and HTTPS)? Such rows are shown muted with the reason, get no answer group and are
 * neither answers nor failures.
 * @param {{ pending?: boolean, notAsked?: boolean }|null} row
 * @returns {boolean}
 */
export function isNotAsked(row) {
  return !!row && !row.pending && !!row.notAsked;
}

/** A row that is no answer to compare: unreadable in browsers, or not asked. */
const isSkipped = (row) => isBrowserBlocked(row) || isNotAsked(row);

/**
 * `dig` command that asks a browser-unreadable resolver over classic DNS (null when unknown).
 * @param {string} resolverId
 * @param {string} name
 * @param {string} [type='A']
 * @returns {string|null}
 */
export function terminalCommand(resolverId, name, type = 'A') {
  const ip = TERMINAL_DNS[resolverId];
  return ip && name ? `dig @${ip} ${name} ${type}` : null;
}

/**
 * Group finished rows by identical answer values. Real answers come first (largest group
 * first, ties by first appearance) and get letters A, B, C … and a colour index; failed and
 * blocked groups come last and get no letter.
 * @param {Array<{ key: string, pending?: boolean, values?: string[], filtered?: boolean }>} rows
 * @returns {Array<{ key: string, values: string[], members: string[], error: boolean, filtered: boolean,
 *   letter: string|null, color: number|null }>}
 */
export function groupAnswers(rows) {
  const map = new Map();
  let order = 0;
  for (const row of rows) {
    if (!row || row.pending || !Array.isArray(row.values)) continue;
    const key = row.values.join('\n');
    let g = map.get(key);
    if (!g) {
      g = { key, values: row.values, members: [], error: isErrorValues(row.values), filtered: true, order: order++ };
      map.set(key, g);
    }
    g.members.push(row.key);
    if (!row.filtered) g.filtered = false;
  }
  const rank = (g) => (g.error ? 2 : g.filtered ? 1 : 0);
  const list = [...map.values()].sort((a, b) => rank(a) - rank(b) || b.members.length - a.members.length || a.order - b.order);
  let next = 0;
  return list.map(({ order: _o, ...g }) => {
    if (g.error || g.filtered) return { ...g, letter: null, color: null };
    const idx = next;
    next += 1;
    return { ...g, letter: groupLetter(idx), color: idx % GROUP_COLORS };
  });
}

/** Split answer values into record values and the CNAME chain (lib/propagation.js). */
export { splitChain };

/**
 * Median of finite numbers (null for an empty list).
 * @param {number[]} values
 * @returns {number|null}
 */
export function median(values) {
  const list = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!list.length) return null;
  const mid = Math.floor(list.length / 2);
  return list.length % 2 ? list[mid] : Math.round((list[mid - 1] + list[mid]) / 2);
}

/**
 * Minimum TTL of a response's answer records (null when there are none).
 * @param {object|null} response DnsResponse
 * @returns {number|null}
 */
export function minAnswerTtl(response) {
  let min = null;
  for (const rr of (response && Array.isArray(response.answers) ? response.answers : [])) {
    if (rr && Number.isFinite(rr.ttl) && (min === null || rr.ttl < min)) min = rr.ttl;
  }
  return min;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the Global DNS view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const lang = ctx.lang;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;

  /* --- small render helpers ----------------------------------------------- */
  const ms = (v) => (Number.isFinite(v) ? formatDuration(v) : '—');
  const humanTtl = (s) => {
    if (!Number.isFinite(s)) return '—';
    if (s < 120) return t('time.s', { n: formatNumber(s) });
    if (s < 7200) return `${formatNumber(Math.round(s / 60))} min`;
    if (s < 172800) return `${formatNumber(Math.round(s / 3600))} h`;
    return `${formatNumber(Math.round(s / 86400))} d`;
  };
  /** A wait in words, in the UI language (Intl unit names): '45 seconds', '15 minutes', '1 hour', '2 days'. */
  const waitText = (s) => {
    const unit = (n, name) => {
      try {
        return new Intl.NumberFormat(localeTag(), { style: 'unit', unit: name, unitDisplay: 'long', maximumFractionDigits: 1 }).format(n);
      } catch {
        return `${formatNumber(n)} ${name}`;
      }
    };
    if (s < 120) return unit(s, 'second');
    if (s < 3600) return unit(Math.round(s / 60), 'minute');
    if (s < 172800) return unit(Math.round(s / 360) / 10, 'hour');
    return unit(Math.round(s / 8640) / 10, 'day');
  };
  /** A time of day in the UI language ('15:42'), with its date when it is not today. */
  const clockTime = (ms, now = Date.now()) => {
    const d = new Date(ms);
    if (new Date(now).toDateString() !== d.toDateString()) return formatDateTime(d);
    return new Intl.DateTimeFormat(localeTag(), { hour: '2-digit', minute: '2-digit' }).format(d);
  };
  const hostLink = (host) => h('a', { class: 'glb-host mono', href: ctx.href('lookup', { name: host }) }, host);
  const ipLink = (ip) => h('a', { class: 'glb-ip mono', href: ctx.href('ip', { ips: ip }) }, ip);
  const flag = (cc, title = null) => Flag(cc, { className: 'glb-flag', title });
  const vantageName = (v) => (lang === 'tr' ? v.nameTr : v.nameEn);
  /**
   * Operator of one answer address. The CNAME chain of the same answer is taken into account,
   * so CDNs recognised by CNAME only (Akamai: *.akamaiedge.net …) are not shown as "Direct".
   */
  const classifyIp = (ip, chain = []) => classifyResolution({
    status: 'NOERROR',
    ipv4: ipVersion(ip) === 4 ? [ip] : [],
    ipv6: ipVersion(ip) === 6 ? [ip] : [],
    cnames: chain
  });

  /* --- form -------------------------------------------------------------- */
  const initialName = restored?.draft ?? restored?.name ?? ctx.params.name ?? '';
  const initialType = GLOBAL_TYPES.includes(String(restored?.type ?? ctx.params.type ?? '').toUpperCase())
    ? String(restored?.type ?? ctx.params.type).toUpperCase() : 'A';
  const initialGeo = restored ? restored.geo !== false : ctx.params.geo !== '0';

  const nameField = textInput({
    label: t('glb.name'),
    value: initialName,
    placeholder: t('glb.namePlaceholder'),
    mono: true,
    className: 'glb-name',
    attrs: { 'data-role': 'global-name', 'data-shortcut': 'focus', inputmode: 'url', enterkeyhint: 'go' },
    onEnter: () => start()
  });
  const typeField = select({
    label: t('glb.type'),
    options: GLOBAL_TYPES,
    value: initialType,
    className: 'glb-type'
  });
  typeField.input.dataset.role = 'global-type';
  const geoField = checkbox({ label: t('glb.geo', { count: formatNumber(GEO_VANTAGES.length) }), checked: initialGeo });
  geoField.input.dataset.role = 'global-geo';
  // The expected value (lib/expected.js): judged against the answers on screen, never a new question.
  const initialMatch = EXPECT_MODES.includes(restored?.match ?? ctx.params.match) ? (restored?.match ?? ctx.params.match) : 'exact';
  const initialExpect = restored?.expect ?? ctx.params.expect ?? '';
  /**
   * A regular expression that came with a link is shown but held — applied once the user edits it
   * or presses Enter in the field (or picks a mode): it would run against answers the link's author
   * may write (a TXT record), and a pattern that backtracks without end stalls the page.
   */
  let expectHeld = restored ? restored.expectHeld === true : initialMatch === 'regex' && !!String(initialExpect).trim();
  const expectField = textInput({
    label: t('glb.exp.label'),
    value: initialExpect,
    placeholder: t('glb.exp.placeholder'),
    hint: t(expectHeld ? 'glb.exp.held' : 'glb.exp.hint'),
    mono: true,
    className: 'glb-expect-value',
    attrs: { 'data-role': 'global-expect', maxlength: String(EXPECT_MAX_LENGTH), enterkeyhint: 'done' },
    onInput: () => expectSoon(),
    onEnter: () => applyExpected()
  });
  /** Whether the field's hint says how to apply a held regex now. */
  let heldHintShown = expectHeld;
  const matchField = select({
    label: t('glb.exp.mode'),
    options: EXPECT_MODES.map((m) => ({ value: m, label: t(`glb.exp.mode.${m}`) })),
    value: initialMatch,
    className: 'glb-expect-mode',
    onChange: () => applyExpected()
  });
  matchField.input.dataset.role = 'global-match';
  /** The expected value of the check on screen, parsed for its record type (null: none typed, or not usable). */
  let expectedNow = null;
  /** Show only the rows that do not serve the expected value yet (the card's toggle). */
  let missingOnly = false;
  /** The zone's own name server's answer (ui/soa-probe.js) for the check on screen, or null. */
  let soaResult = null;
  /** Whether the tables carry the export-only "Expected value" column now. */
  let columnsWithExpected = false;
  const expectSoon = debounce(() => applyExpected(), 250);
  // Region 3: Run and Stop take turns in one slot (the keyboard focus goes with them).
  const runBar = RunBar({
    label: t('glb.run'),
    dataset: { action: 'run', shortcut: 'submit' },
    stopDataset: { action: 'stop', shortcut: 'cancel' },
    onRun: () => start(),
    onStop: () => stop(),
    hasValue: () => !!nameField.value.trim()
  });
  const runBtn = runBar.run;
  // An example fills the form and leaves the keyboard on Run: nothing is sent before that click.
  const examples = ExampleChips({
    className: 'glb-examples',
    examples: EXAMPLES.map((ex) => ({ value: ex.name, label: `${ex.name} ${ex.type}`, ex })),
    onPick: (value, { ex }) => {
      nameField.value = ex.name;
      typeField.value = ex.type;
      nameField.setError(null);
      syncRunBar();
    },
    focus: () => runBtn
  });

  const how = Disclosure({
    summary: t('glb.how.title'),
    className: 'glb-how',
    children: h('ul', { class: 'glb-how-list' },
      ['ecs', 'geo', 'anycast', 'ttl', 'filter', 'browser'].map((k) => h('li', null, t(`glb.how.${k}`))))
  });

  /** The compact card's line: the choices off their default (the record type, no locations, an expected value). */
  const optionsLine = () => {
    const expect = String(expectField.value || '').trim();
    return optionsSummary([
      { label: typeField.value, isDefault: typeField.value === 'A' },
      { label: t('glb.optNoGeo'), isDefault: geoField.checked },
      { label: t('glb.optExpect', { value: expect.length > 40 ? `${expect.slice(0, 39)}…` : expect }), isDefault: !expect }
    ]);
  };
  // Region 2: one card — the name box with the type and Run on its row, the expected value, the
  // locations and the examples behind Edit once a check ran, what is sent in its footer.
  const input = ToolInput({
    className: 'glb-form-card',
    fieldsClass: 'glb-form',
    label: t('nav.global'),
    primary: nameField.el,
    inline: [typeField.el],
    run: runBar,
    more: [h('div', { class: 'glb-expect' }, expectField.el, matchField.el), geoField.el],
    extras: [examples, how],
    privacy: PrivacyNote({ text: t('glb.privacy', { count: formatNumber(RESOLVERS.length) }), className: 'glb-privacy' }),
    summary: optionsLine
  });
  // Any change of the form: Run is the verb (and primary) again, or "Run again" while it asks for the check on screen.
  input.el.addEventListener('input', () => syncRunBar());
  input.el.addEventListener('change', () => syncRunBar());

  /* --- results skeleton ------------------------------------------------- */
  const progress = ProgressBar({ label: t('glb.progress') });
  progress.el.classList.add('glb-progress');
  /**
   * The result header (region 4): the verdict as its title, the record type and the time, what the
   * verdict rests on, the status summary, the actions and "Also check". Not a live region: the
   * totals are said once, when the check ends.
   */
  const head = ResultHeader({ className: 'glb-summary' });
  const status = StatusSummary({ className: 'glb-status' });
  head.set('status', status.el);
  /** The status item whose sources the tables show (rcode, failed, blocked), or null. */
  let statusFilter = null;
  /** Region 6 of the Answer groups tab: the figures, read-only. */
  const metrics = MetricStrip({ className: 'glb-stats metric-surface', label: t('glb.metricsLabel') });
  /** Region 7 of the Answer groups tab: why the answers differ, one row per finding (the stacked alert's list before). */
  const findingsEl = h('div', { class: 'glb-findings-host' });
  /** The findings list shows them all once "Show n more" was pressed (until the next check). */
  let findingsOpen = false;
  const legendEl = h('div', { class: 'glb-legend', attrs: { role: 'group', 'aria-label': t('glb.groups.title') } });
  const filterNote = h('div', { class: 'glb-filter-note filter-note', hidden: true });

  /* --- the expected value's card (lib/expected.js; the name server probe: ui/soa-probe.js) ---- */
  const expValueEl = h('p', { class: 'glb-exp-value' });
  const expCountEl = h('div', { class: 'glb-exp-count', dataset: { role: 'exp-count' } });
  const expNoteEl = h('div', { class: 'glb-exp-note' });
  const expLastEl = h('p', { class: 'glb-exp-line', hidden: true, dataset: { role: 'exp-last' } });
  const expWorstEl = h('p', { class: 'glb-exp-line', hidden: true, dataset: { role: 'exp-worst' } });
  const expFlushEl = h('p', { class: 'muted text-sm glb-exp-flush', hidden: true, dataset: { role: 'exp-flush' } }, t('glb.exp.flush'), ' ',
    FLUSH_LINKS.flatMap((l, i) => [i ? ' · ' : null, ExternalLink(l.url, l.name)]).filter(Boolean));
  const expToggle = Button({
    label: t('glb.exp.onlyMissing', { count: 0 }), icon: 'filter', size: 'sm', variant: 'ghost', dataset: { action: 'exp-missing' },
    onClick: () => setMissingOnly(!missingOnly)
  });
  expToggle.setAttribute('aria-pressed', 'false');
  const soaOpen = Button({
    label: t('glb.exp.probe'), icon: 'server', size: 'sm', variant: 'secondary', title: t('glb.exp.probeHint'), dataset: { action: 'soa-open' },
    onClick: () => openSoa(null, { run: true })
  });
  const soaBody = h('div', { class: 'glb-exp-soa-body' });
  const soaSlot = h('div', { class: 'stack-sm glb-exp-soa', hidden: true, dataset: { role: 'soa-slot' } }, soaOpen, soaBody);
  const expectCard = h('section', { class: 'card glb-exp', hidden: true, dataset: { role: 'expected' }, attrs: { 'aria-labelledby': 'glb-exp-title' } },
    h('div', { class: 'glb-exp-head' },
      h('h2', { class: 'glb-exp-title', id: 'glb-exp-title' }, Icon('target', { size: 16 }), h('span', null, t('glb.exp.title'))), expValueEl),
    expCountEl, expNoteEl, expLastEl, expWorstEl, expFlushEl, h('div', { class: 'cluster glb-exp-actions' }, expToggle), soaSlot);

  let filterKey = null;
  let groups = [];
  let groupByKey = new Map();
  /** propagationVerdict of the finished rows, and its groups (operators) by answer key. */
  let verdict = null;
  let verdictByKey = new Map();

  const groupClass = (g) => {
    if (!g) return null;
    if (g.error) return 'glb-gerr';
    if (g.filtered) return 'glb-gblk';
    return `glb-g${g.color}`;
  };
  const unavailableMark = (key = 'glb.value.unavailable') => h('span', { class: 'glb-mark-wrap', title: t(key) },
    h('span', { class: 'glb-mark glb-mark-pending', attrs: { 'aria-hidden': 'true' } }, '–'),
    h('span', { class: 'sr-only' }, t(key)));
  const groupMark = (g, { withLabel = false } = {}) => {
    if (!g) return h('span', { class: 'glb-mark glb-mark-pending', attrs: { 'aria-hidden': 'true' } }, '·');
    const text = g.letter || (g.error ? '!' : '⊘');
    const label = g.letter ? t('glb.group.label', { letter: g.letter }) : t(g.error ? 'glb.group.error' : 'glb.group.blocked');
    return h('span', { class: ['glb-mark-wrap', groupClass(g)], title: label },
      h('span', { class: 'glb-mark', attrs: { 'aria-hidden': 'true' } }, text),
      withLabel ? h('span', { class: 'glb-mark-label' }, label) : h('span', { class: 'sr-only' }, label));
  };
  const rowGroup = (row) => (row.pending || isSkipped(row) ? null : groupByKey.get(row.values.join('\n')) || null);
  const operatorName = (op) => op.name || t(`kind.${op.kind}`);
  /** Who operates an answer group's addresses ("Amazon CloudFront", "Direct" …), at most two labels. */
  function operatorLabels(ops) {
    const shown = ops.slice(0, 2).map((op) => h('span', {
      class: ['glb-prov', `glb-prov-${op.kind}`],
      title: t(op.reasonKey, { provider: op.name || t('common.unknown') })
    }, operatorName(op)));
    if (ops.length > 2) shown.push(h('span', { class: 'glb-prov', title: ops.slice(2).map(operatorName).join(', ') }, `+${ops.length - 2}`));
    return h('span', { class: 'glb-chip-ops' }, shown);
  }

  /** One compact line for the CNAME chain: "alias → a.example.net → b.cdn.net". */
  function chainLine(chain) {
    const parts = [h('span', { class: 'glb-chain-label' }, t('glb.value.aliasOf'))];
    chain.forEach((target) => parts.push(h('span', { class: 'glb-chain-arrow', attrs: { 'aria-hidden': 'true' } }, '→'), hostLink(target)));
    return h('div', { class: 'glb-chain', title: chain.join(' → ') }, parts);
  }

  /** Render one answer value (IP, host name, text record or status marker). */
  function renderValue(value, chain = []) {
    if (value.startsWith('CNAME ')) return chainLine([value.slice(6)]);
    const ip = normalizeIP(value);
    if (ip) {
      const cls = classifyIp(ip, chain);
      return h('span', { class: 'glb-ipval' }, ipLink(ip),
        cls.provider && cls.kind !== 'direct' ? h('span', { class: ['glb-prov', `glb-prov-${cls.kind}`], title: t(cls.reasonKey, { provider: cls.provider.name }) }, cls.provider.name) : null,
        cls.kind === 'private' ? h('span', { class: 'glb-prov glb-prov-private' }, t('kind.private')) : null);
    }
    // NS / CNAME / PTR targets ('ns1.example.com.') and MX ('10 mx.example.com.') become lookup links.
    const fqdn = /^([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.$/i.exec(value);
    if (fqdn) return hostLink(fqdn[1].toLowerCase());
    const mx = /^(\d+) ([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.$/i.exec(value);
    if (mx) return h('span', { class: 'glb-mx' }, h('span', { class: 'muted num' }, mx[1]), ' ', hostLink(mx[2].toLowerCase()));
    return h('span', { class: 'glb-text mono' }, value);
  }

  /** Answer cell: values, or a status badge for failures / markers. */
  function renderAnswer(row) {
    if (row.pending) {
      // A stopped run leaves unanswered rows: say so instead of spinning forever.
      if (current && current.cancelled) return h('span', { class: 'dt-null', title: t('glb.cancelled') }, '—');
      return h('span', { class: 'glb-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('glb.pending'));
    }
    const v = row.values;
    if (isNotAsked(row)) {
      // Not a failure: AliDNS is asked only for the types it answers whole.
      return h('div', { class: 'glb-skip' },
        h('span', { class: 'cluster' }, Badge(t('glb.value.notAsked'), { variant: 'neutral', icon: 'minus-circle' })),
        h('span', { class: 'muted text-xs' }, t('glb.value.notAskedShort')));
    }
    if (isBrowserBlocked(row)) {
      // Not an error: the browser cannot read this resolver (HTTP/3 without CORS). Say so calmly
      // and give a way to get its answer anyway.
      const res = row.response || {};
      const cmd = current ? terminalCommand(row.resolver.id, current.name, current.type) : null;
      return h('div', { class: 'glb-skip', title: [t('glb.value.unavailableTitle', { name: row.resolver.name }), res.error].filter(Boolean).join('\n') },
        h('span', { class: 'cluster' },
          Badge(t('glb.value.unavailable'), { variant: 'neutral', icon: 'minus-circle' }),
          h('span', { class: 'muted text-xs' }, t('glb.value.unavailableShort'))),
        cmd ? h('span', { class: 'glb-skip-cmd text-xs' },
          Icon('terminal', { size: 12 }), h('span', { class: 'muted' }, t('glb.value.terminal')), h('code', { class: 'mono' }, cmd)) : null);
    }
    if (isErrorValues(v)) {
      const res = row.response || {};
      const kind = res.errorKind && res.errorKind !== 'unknown' && hasString(`error.kind.${res.errorKind}`, 'en') ? t(`error.kind.${res.errorKind}`) : '';
      const unreliable = row.resolver && row.resolver.browserReliable === false;
      const tip = [res.error, unreliable ? t('settings.unreliable') : null].filter(Boolean).join('\n') || null;
      return h('div', { class: 'glb-fail', title: tip },
        h('span', { class: 'cluster' },
          Badge(t('glb.value.failed'), { variant: 'error', icon: 'x-circle' }),
          unreliable ? Badge('HTTP/3', { variant: 'warn', icon: 'alert', title: t('settings.unreliable') }) : null),
        kind ? h('span', { class: 'muted text-xs glb-fail-text' }, kind) : null);
    }
    const parts = [];
    const mark = expectedMark(row);
    if (mark) parts.push(mark);
    if (row.filtered) parts.push(Badge(t('glb.value.blocked'), { variant: 'warn', icon: 'filter', title: t('glb.value.blockedTitle') }));
    if (v.length === 1 && v[0] === 'NXDOMAIN') parts.push(Badge('NXDOMAIN', { variant: 'nxdomain', icon: 'x-circle', title: t('class.nxdomain') }));
    else if (v.length === 1 && v[0] === 'NODATA') parts.push(Badge(t('glb.value.nodata'), { variant: 'unresolved', title: t('glb.value.nodataTitle') }));
    else if (v.length === 1 && /^[A-Z]+\d*$/.test(v[0]) && !normalizeIP(v[0])) parts.push(Badge(v[0], { variant: 'error', icon: 'alert' }));
    else {
      const { plain, chain } = splitChain(v);
      if (plain.length) parts.push(TruncatedList(plain, { max: 3, render: (value) => renderValue(value, chain), mono: false }));
      if (chain.length) parts.push(chainLine(chain));
    }
    return h('div', { class: 'glb-answer' }, parts);
  }

  /**
   * The expected value's mark on an answer (lib/expected.js): "Matches", or "Not yet" with, in its
   * tooltip, until when this source may keep the answer it gave. None without an expected value.
   */
  function expectedMark(row) {
    const verdict = expectedNow ? expectedVerdict(row, expectedNow) : null;
    if (verdict !== 'match' && verdict !== 'mismatch') return null;
    const end = verdict === 'mismatch' ? cacheEnd(row) : null;
    const badge = verdict === 'match'
      ? Badge(t('glb.exp.match'), { variant: 'ok', icon: 'check', className: 'glb-exp-mark' })
      : Badge(t('glb.exp.mismatch'), {
        variant: 'warn', icon: 'clock', className: 'glb-exp-mark',
        title: !end ? t('glb.exp.mismatchTitleNoTtl') : end <= Date.now() ? t('glb.exp.mismatchTitleExpired') : t('glb.exp.mismatchTitle', { time: clockTime(end) })
      });
    badge.dataset.exp = verdict;
    return badge;
  }

  function renderStatus(row) {
    if (row.pending) return null;
    const res = row.response;
    if (!res || !res.ok) return null; // the answer cell explains the failure
    const rc = res.rcode;
    const variant = rc === 'NOERROR' ? 'ok' : rc === 'NXDOMAIN' ? 'nxdomain' : 'error';
    return Badge(rc, { variant, mono: true, title: (res.ede || []).map((e) => `EDE ${e.code} ${e.name}${e.text ? `: ${e.text}` : ''}`).join('\n') || null });
  }

  function renderAd(row) {
    if (row.pending || !row.response || !row.response.ok) return null;
    return row.response.ad
      ? Badge(t('glb.adYes'), { variant: 'ok', icon: 'shield', title: t('glb.adTitle') })
      : h('span', { class: 'dt-null', title: t('glb.adNo') }, '—');
  }

  function renderLatency(row) {
    if (row.pending || !row.response || isSkipped(row)) return null;
    const v = row.response.ok ? row.response.elapsedMs : row.response.totalMs;
    if (!Number.isFinite(v)) return null;
    const speed = v < 120 ? 'fast' : v < 400 ? 'ok' : v < 1500 ? 'slow' : 'very-slow';
    return h('span', { class: ['glb-ms', `glb-ms-${speed}`, 'num'] }, ms(v));
  }

  function renderTtl(row) {
    if (row.pending) return null;
    const ttl = minAnswerTtl(row.response);
    return ttl === null ? null : h('span', { class: 'num', title: t('glb.ttlTitle', { human: humanTtl(ttl) }) }, formatNumber(ttl));
  }

  // Export options are read at export time, so the subject (queried name) is filled in per run.
  const exportOpts = {
    resolvers: { filename: 'global-dns-resolvers', subject: '' },
    geo: { filename: 'global-dns-locations', subject: '' },
    cn: { filename: 'global-dns-china', subject: '' },
    ips: { filename: 'global-dns-ips', subject: '' }
  };
  const latencyValue = (row) => (row.pending || !row.response ? null : (row.response.ok ? row.response.elapsedMs : row.response.totalMs));
  const groupSort = (row) => {
    if (isSkipped(row)) return '3';
    const g = rowGroup(row);
    if (!g) return null;
    return g.letter ? `0${g.letter.padStart(3, ' ')}` : g.filtered ? '1' : '2';
  };
  const answerText = (row) => (row.pending ? '' : isNotAsked(row) ? 'NOT ASKED' : isBrowserBlocked(row) ? 'UNAVAILABLE' : row.values.join(' '));
  const rowClass = (row) => {
    const exp = expectedNow ? expectedVerdict(row, expectedNow) : null;
    return ['glb-row', groupClass(rowGroup(row)), {
      'is-pending': row.pending, 'is-unavailable': isSkipped(row), 'glb-exp-match': exp === 'match', 'glb-exp-miss': exp === 'mismatch'
    }];
  };
  /** The expected value's verdict as an export-only column (CSV / JSON), present while there is one. */
  const expectedColumn = {
    key: 'expected', label: t('glb.exp.col'), display: false,
    exportValue: (r) => (expectedNow ? expectedVerdict(r, expectedNow) || '' : '')
  };

  /* --- resolvers table ------------------------------------------------------ */
  const resolverColumns = [
    {
      key: 'group', label: t('glb.col.group'), sortable: true, sortValue: groupSort, width: '4rem',
      render: (r) => (isBrowserBlocked(r) ? unavailableMark() : groupMark(rowGroup(r))),
      exportValue: (r) => rowGroup(r)?.letter || (r.pending ? '' : isBrowserBlocked(r) ? 'UNAVAILABLE' : rowGroup(r)?.error ? 'ERROR' : 'BLOCKED')
    },
    {
      key: 'resolver', label: t('glb.col.resolver'), sortable: true, sortValue: (r) => r.resolver.name,
      exportValue: (r) => r.resolver.name,
      render: (r) => h('div', { class: 'glb-res' },
        h('span', { class: 'glb-res-name' }, r.resolver.name),
        h('span', { class: 'muted text-xs' }, r.resolver.operator))
    },
    {
      key: 'location', label: t('glb.col.location'), sortable: true,
      sortValue: (r) => r.resolver.countryCode || '',
      exportValue: (r) => [r.resolver.countryCode ? formatRegion(r.resolver.countryCode, r.resolver.location) : t('glb.anycast'), r.response?.nsid || ''].filter(Boolean).join(' '),
      render: (r) => h('div', { class: 'glb-loc' },
        h('span', null, flag(r.resolver.countryCode), ' ', r.resolver.countryCode ? formatRegion(r.resolver.countryCode, r.resolver.location) : t('glb.anycast')),
        r.response && r.response.nsid ? h('span', { class: 'glb-pop mono text-xs', title: `${t('glb.popTitle')}: ${r.response.nsid}` }, t('glb.pop', { id: r.response.nsid })) : null)
    },
    {
      key: 'filtering', label: t('glb.col.filtering'), sortable: true, sortValue: (r) => r.resolver.filtering || '',
      exportValue: (r) => r.resolver.filtering || '',
      render: (r) => (r.resolver.filtering ? Badge(t(`settings.filter.${r.resolver.filtering}`), { icon: 'filter' }) : null)
    },
    { key: 'ttl', label: t('glb.col.ttl'), sortable: true, align: 'end', sortValue: (r) => (r.pending ? null : minAnswerTtl(r.response)), render: renderTtl },
    { key: 'status', label: t('glb.col.status'), sortable: true, sortValue: (r) => (r.pending ? null : r.response?.rcode || 'ERROR'), render: renderStatus, exportValue: (r) => (r.pending ? '' : r.response?.rcode || (isBrowserBlocked(r) ? 'UNAVAILABLE' : 'ERROR')) },
    { key: 'ad', label: t('glb.col.dnssec'), sortable: true, sortValue: (r) => (r.pending || !r.response?.ok ? null : r.response.ad), render: renderAd, exportValue: (r) => (r.response?.ad ? 'AD' : '') },
    { key: 'latency', label: t('glb.col.latency'), sortable: true, align: 'end', sortValue: latencyValue, render: renderLatency, exportValue: latencyValue },
    { key: 'answer', label: t('glb.col.answer'), render: renderAnswer, searchValue: answerText, exportValue: answerText }
  ];
  const resolverTable = DataTable({
    caption: t('glb.res.title'),
    rowKey: (r) => r.key,
    rowClass,
    dense: true,
    maxHeight: null,
    export: exportOpts.resolvers,
    columns: resolverColumns
  });

  /* --- geo tables: the locations Google is asked for, and mainland China (AliDNS) ---------- */
  /** The resolver a location is asked through (its own, else Google). */
  const resolverOf = (row) => getAnyResolver(row.vantage.resolver || 'google') || { name: row.vantage.resolver || '' };
  const geoColumns = ({ withResolver = false } = {}) => [
    {
      key: 'group', label: t('glb.col.group'), sortable: true, sortValue: groupSort, width: '4rem',
      render: (r) => (isNotAsked(r) ? unavailableMark('glb.value.notAsked') : groupMark(rowGroup(r))),
      exportValue: (r) => (isNotAsked(r) ? 'NOT ASKED' : rowGroup(r)?.letter || '')
    },
    {
      key: 'location', label: t('glb.col.location'), sortable: true,
      sortValue: (r) => `${r.vantage.countryCode} ${r.vantage.city || ''}`,
      exportValue: (r) => vantageName(r.vantage),
      render: (r) => h('span', { class: 'glb-loc-geo' }, flag(r.vantage.countryCode, formatRegion(r.vantage.countryCode)), ' ', vantageName(r.vantage))
    },
    {
      key: 'isp', label: t('glb.col.isp'), sortable: true, sortValue: (r) => r.vantage.isp,
      exportValue: (r) => `${r.vantage.isp} AS${r.vantage.asn}`,
      render: (r) => h('div', { class: 'glb-isp' }, h('span', null, r.vantage.isp), h('span', { class: 'muted text-xs mono' }, `AS${r.vantage.asn}`))
    },
    ...(withResolver ? [{
      key: 'via', label: t('glb.col.resolver'), sortable: true, sortValue: (r) => resolverOf(r).name, exportValue: (r) => resolverOf(r).name,
      render: (r) => h('span', { class: 'glb-via' }, resolverOf(r).name)
    }] : []),
    { key: 'subnet', label: t('glb.col.subnet'), mono: true, sortable: true, sortValue: (r) => ipSortValue(r.vantage.subnet.split('/')[0]), render: (r) => r.vantage.subnet, exportValue: (r) => r.vantage.subnet },
    {
      key: 'scope', label: t('glb.col.scope'), sortable: true, align: 'end',
      title: t('glb.scopeTitle'),
      sortValue: (r) => (r.pending ? null : r.scopePrefix),
      exportValue: (r) => (Number.isFinite(r.scopePrefix) ? `/${r.scopePrefix}` : ''),
      render: (r) => (r.pending || isNotAsked(r) ? null : Number.isFinite(r.scopePrefix)
        ? h('span', { class: ['mono', { muted: r.scopePrefix === 0 }], title: t('glb.scopeTitle') }, `/${r.scopePrefix}`)
        : h('span', { class: 'dt-null', title: t('glb.scopeNone') }, '—'))
    },
    { key: 'latency', label: t('glb.col.latency'), sortable: true, align: 'end', sortValue: latencyValue, render: renderLatency, exportValue: latencyValue },
    {
      key: 'operator', label: t('glb.col.operator'),
      exportValue: (r) => operatorsOf(r).map((c) => c.provider?.name || c.kind).join(' '),
      render: (r) => {
        const kinds = operatorsOf(r);
        return kinds.length ? h('div', { class: 'cluster glb-ops' }, kinds.map((c) => KindBadge(c))) : null;
      }
    },
    { key: 'answer', label: t('glb.col.answer'), render: renderAnswer, searchValue: answerText, exportValue: answerText }
  ];
  const geoTable = DataTable({
    caption: t('glb.geo.title'),
    rowKey: (r) => r.key,
    rowClass,
    dense: true,
    maxHeight: null,
    export: exportOpts.geo,
    columns: geoColumns()
  });
  // A row group of its own: the locations asked through another resolver (mainland China, AliDNS).
  const chinaTable = DataTable({
    caption: t('glb.cn.title'),
    rowKey: (r) => r.key,
    rowClass,
    dense: true,
    maxHeight: null,
    export: exportOpts.cn,
    columns: geoColumns({ withResolver: true })
  });
  const CHINA = GEO_VANTAGES.filter((v) => v.group === 'cn');
  const isChinaRow = (r) => r.kind === 'geo' && r.vantage.group === 'cn';
  const chinaGroup = h('div', { class: 'glb-geo-group stack-sm', dataset: { group: 'cn' } },
    // The heading names the region: its flag is decorative.
    h('h4', { class: 'glb-geo-group-title' }, flag('CN'), h('span', null, t('glb.cn.title'))),
    h('p', { class: 'section-desc' }, t('glb.cn.desc', { count: formatNumber(CHINA.length) })),
    chinaTable.el || chinaTable);

  /** Operators of a row's answer IPs (Cloudflare, CDN · X, Direct …): those of its verdict group. */
  function operatorsOf(row) {
    if (row.pending || row.filtered || !Array.isArray(row.values)) return [];
    const g = verdictByKey.get(row.values.join('\n'));
    return g ? g.operators : [];
  }

  /* --- IP table ----------------------------------------------------------------- */
  const ipIntelBtn = Button({
    label: t('glb.ips.intel'), icon: 'network', size: 'sm', dataset: { action: 'ip-intel' },
    onClick: () => {
      const ips = ipTable.getVisibleRows().map((r) => r.ip).slice(0, 100);
      if (ips.length) ctx.navigate('ip', { ips: ips.join(',') });
    }
  });
  const ipCopyBtn = CopyButton(() => ipTable.getVisibleRows().map((r) => r.ip).join('\n'), { label: t('glb.ips.copy'), size: 'sm', variant: 'secondary' });
  const ipTable = DataTable({
    caption: t('glb.ips.title'),
    rowKey: (r) => r.ip,
    dense: true,
    maxHeight: null,
    pageSize: 15,
    search: true,
    sort: { key: 'seen', dir: 'desc' },
    toolbar: [ipIntelBtn, ipCopyBtn],
    empty: t('glb.ips.none'),
    export: exportOpts.ips,
    columns: [
      { key: 'ip', label: t('glb.ips.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip), searchValue: (r) => r.ip, exportValue: (r) => r.ip, render: (r) => ipLink(r.ip) },
      { key: 'version', label: 'IPv', sortable: true, align: 'center', render: (r) => h('span', { class: 'muted text-xs' }, `v${r.version}`), exportValue: (r) => r.version },
      {
        key: 'owner', label: t('glb.ips.col.owner'), sortable: true,
        sortValue: (r) => r.classification.kind,
        searchValue: (r) => `${r.classification.kind} ${r.classification.provider ? r.classification.provider.name : ''}`,
        exportValue: (r) => (r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`)),
        render: (r) => KindBadge(r.classification)
      },
      {
        key: 'seen', label: t('glb.ips.col.seen'), sortable: true, defaultDir: 'desc', sortValue: (r) => r.members.size,
        exportValue: (r) => r.members.size,
        render: (r) => {
          const total = Math.max(1, answeredCount());
          const pct = Math.min(100, Math.round((r.members.size / total) * 100));
          return h('div', { class: 'glb-seen' },
            h('span', { class: 'num' }, t('glb.ips.seen', { count: formatNumber(r.members.size), total: formatNumber(total) })),
            h('span', { class: 'glb-bar', attrs: { 'aria-hidden': 'true' } }, h('span', { class: 'glb-bar-fill', style: { width: `${pct}%` } })));
        }
      },
      {
        key: 'where', label: t('glb.ips.col.where'),
        searchValue: (r) => whereOf(r).countries.join(' '),
        exportValue: (r) => [...whereOf(r).vantages.map((v) => v.id), ...whereOf(r).resolvers].join(' '),
        render: (r) => {
          const w = whereOf(r);
          // One flag per country; its tooltip lists the locations (several vantages share a country).
          const byCountry = new Map();
          for (const v of w.vantages) byCountry.set(v.countryCode, [...(byCountry.get(v.countryCode) || []), vantageName(v)]);
          const countries = [...byCountry.entries()];
          return h('div', { class: 'glb-where' },
            countries.length ? h('span', { class: 'glb-flags' }, countries.slice(0, 16).map(([cc, names]) => flag(cc, names.join(' · '))),
              countries.length > 16 ? h('span', { class: 'muted text-xs' }, ` +${countries.length - 16}`) : null) : null,
            w.resolvers.length ? h('span', { class: 'muted text-xs' }, t('glb.ips.resolvers', { count: w.resolvers.length })) : null);
        }
      },
      {
        key: 'server', label: t('glb.ips.col.server'), sortable: true,
        sortValue: (r) => (r.servers.length ? r.servers[0].name : null),
        searchValue: (r) => r.servers.map((s) => s.name).join(' '),
        exportValue: (r) => r.servers.map((s) => s.name).join(' '),
        render: (r) => (r.servers.length ? h('div', { class: 'cluster' }, r.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null)
      }
    ]
  });

  const vantageById = new Map(GEO_VANTAGES.map((v) => [v.id, v]));
  function whereOf(ipRow) {
    const vantages = [];
    const resolvers = [];
    for (const key of ipRow.members) {
      if (key.startsWith('geo:')) {
        const v = vantageById.get(key.slice(4));
        if (v) vantages.push(v);
      } else if (key.startsWith('isp:')) {
        // An ISP resolver (ui/isp-resolvers.js): a flag of its probe's country, like a location.
        const row = current && current.rowByKey.get(key);
        if (row && row.isp && row.isp.country) vantages.push({ id: key, countryCode: row.isp.country, nameEn: ispName(row), nameTr: ispName(row) });
      } else {
        resolvers.push(key.slice(9));
      }
    }
    return { vantages, resolvers, countries: [...new Set(vantages.map((v) => v.countryCode))] };
  }

  /* --- sections (in the tabs' panels: regions 6–8 sit with the data they count) ------------ */
  const legendCard = Card({
    title: t('glb.groups.title'), subtitle: t('glb.groups.desc'), icon: 'layers', className: 'glb-legend-card',
    children: h('div', { class: 'stack-sm' }, legendEl)
  });
  const ipSection = Section({ title: t('glb.ips.title'), description: t('glb.ips.desc'), className: 'glb-ips', level: 3, children: ipTable });
  const resSection = Section({
    title: t('glb.res.title'),
    description: t('glb.res.desc', { count: formatNumber(RESOLVERS.length) }),
    className: 'glb-resolvers',
    level: 3,
    children: resolverTable
  });
  const geoSection = Section({
    title: t('glb.geo.title'),
    description: t('glb.geo.desc', { count: formatNumber(GEO_VANTAGES.length - CHINA.length) }),
    className: 'glb-geo',
    level: 3,
    children: [geoTable.el || geoTable, CHINA.length ? chinaGroup : null]
  });
  /* --- ISP resolvers: ui/isp-resolvers.js, loaded on first use (Globalping) ---------- */
  const loadIsp = onceAsync(() => import('../ui/isp-resolvers.js'));
  /** The mounted panel (null until first use): refresh / setFilter / reset / staleSummary / note / snapshot. */
  let ispPanel = null;
  const ispBody = h('div', { class: 'glb-isp-body' });
  const ispOpen = Button({ label: t('glb.isp.open'), icon: 'globe', dataset: { action: 'isp-open' }, onClick: () => openIsp() });
  const ispSection = Section({ title: t('glb.isp.title'), description: t('glb.isp.desc'), className: 'glb-isp-section', level: 3, children: [ispOpen, ispBody] });
  const ispRows = () => (current ? current.rows.filter((r) => r.kind === 'isp') : []);
  const ispName = (row) => (ispPanel ? ispPanel.label(row) : [row.isp && row.isp.network, row.isp && row.isp.city].filter(Boolean).join(', ') || row.key);
  /** What the panel may do to the check on screen: its rows are a row group of the check. */
  const ispHost = {
    ctx,
    check: () => (current ? { name: current.name, type: current.type, busy: !!current.controller } : null),
    rows: ispRows,
    setRows(rows) {
      if (!current) return;
      const keep = new Set(rows);
      const dropped = ispRows().filter((r) => !keep.has(r));
      for (const r of dropped) current.rowByKey.delete(r.key);
      current.rows = [...current.rows.filter((r) => r.kind !== 'isp'), ...rows];
      for (const r of rows) current.rowByKey.set(r.key, r);
      // Addresses only a dropped row returned leave the IP table with it.
      if (dropped.some((r) => r.addresses.length)) {
        for (const r of dropped) {
          for (const ip of r.addresses) {
            const entry = current.ips.get(ip);
            if (entry && entry.members.delete(r.key) && !entry.members.size) current.ips.delete(ip);
          }
        }
        ipTable.setRows([...current.ips.values()]);
      }
      scheduleRender();
    },
    apply: (item) => applyItem(item),
    cells: {
      group: (r) => groupMark(rowGroup(r)), answer: renderAnswer, status: renderStatus, ad: renderAd, latency: renderLatency, rowClass, groupSort, answerText
    }
  };
  async function openIsp(meta = null) {
    if (ispPanel) return ispPanel;
    setButtonBusy(ispOpen, true);
    try {
      const mod = await loadIsp();
      if (ctx.signal.aborted) return null;
      if (!ispPanel) {
        clear(ispBody);
        ispPanel = mod.mountIspPanel(ispBody, ispHost, { restored: meta });
      }
      ispOpen.hidden = true;
      if (current) renderAll();
      return ispPanel;
    } catch (err) {
      ctx.checkOutdated();
      clear(ispBody);
      ispBody.append(ErrorBanner(err, { compact: true, onRetry: () => openIsp(meta) }));
      return null;
    } finally {
      setButtonBusy(ispOpen, false);
    }
  }

  /* --- the zone's own name server: ui/soa-probe.js, loaded on first use (Globalping) ---------- */
  const loadSoa = onceAsync(() => import('../ui/soa-probe.js'));
  /** The mounted probe panel (null until first use): run / reset / refresh / busy / snapshot / teardown. */
  let soaPanel = null;
  /**
   * What the panel may read of the check on screen — `ask`: the question for the name server
   * (lib/expected.js probeQuestion: the check's type, or the SOA for a new name) — and where its
   * answer goes (the card's worst case).
   */
  const soaHost = {
    ctx,
    check: () => (current ? {
      name: current.name, type: current.type, ask: probeQuestion(current.rows, expectedNow, current.type), busy: !!current.controller
    } : null),
    expected: () => expectedNow,
    onResult(result) {
      soaResult = result || null;
      if (current) renderExpected();
    }
  };
  /** Load and mount the probe panel (`meta`: its snapshot after a re-mount); `run`: send the probe (after the gate). */
  async function openSoa(meta = null, { run = false } = {}) {
    if (soaPanel) {
      if (run) soaPanel.run();
      return soaPanel;
    }
    setButtonBusy(soaOpen, true);
    try {
      const mod = await loadSoa();
      if (ctx.signal.aborted) return null;
      if (!soaPanel) {
        clear(soaBody);
        soaPanel = mod.mountSoaProbe(soaBody, soaHost, { restored: meta });
      }
      soaOpen.hidden = true;
      if (run) soaPanel.run();
      return soaPanel;
    } catch (err) {
      ctx.checkOutdated();
      clear(soaBody);
      soaBody.append(ErrorBanner(err, { compact: true, title: t('glb.exp.probeLoadFailed'), onRetry: () => openSoa(meta, { run }) }));
      return null;
    } finally {
      setButtonBusy(soaOpen, false);
    }
  }

  // The empty result region: what a check gives and what it asks, no card (DESIGN §5.2).
  const emptyWrap = h('div', { class: 'glb-empty' }, EmptyState({
    icon: 'globe',
    message: t('glb.emptyLine'),
    checks: [t('glb.res.title'), t('glb.check.locations'), t('glb.cn.title'), t('glb.isp.title'), t('glb.exp.title')]
  }));
  // No part of the form: Ctrl/Cmd+Enter in a table's filter here starts no new check.
  // "Copy summary": the verdict, the answer groups and their operators, the findings (lib/summary.js).
  const summaryFacts = () => {
    if (!current || (!current.done && !current.cancelled)) return null;
    const finished = current.rows.filter((r) => !r.pending && !isNotAsked(r));
    const unavailable = finished.filter(isBrowserBlocked).length;
    const failed = finished.filter((r) => isErrorValues(r.values)).length - unavailable;
    return {
      name: current.name,
      type: current.type,
      verdict,
      total: current.rows.filter((r) => !isNotAsked(r)).length,
      answered: finished.length - failed - unavailable,
      failed,
      cancelled: !current.done,
      addresses: current.ips.size,
      at: current.finishedAt,
      expected: expectedNow ? { pattern: expectedNow.pattern, mode: expectedNow.mode, ...expectedTally(current.rows, expectedNow) } : null
    };
  };
  const summary = SummaryButton({
    kind: 'global',
    plainLabel: t('result.plainTitle'),
    facts: summaryFacts,
    disabled: true,
    url: () => (current ? ctx.shareUrl(permalinkParams('global', checkParams(current))) : null)
  });
  /** One of the IP table's own files (its filter and order), from the result header's Export menu. */
  const ipExport = (format) => () => {
    const btn = ipTable.el.querySelector(`.dt-export [data-export="${format}"]`);
    if (btn) btn.click();
  };
  // The standard actions (DESIGN §5.3): Copy summary with ¶, Export ▾ (the IP addresses), Copy link.
  const actions = ResultActions({
    summary,
    exports: [
      { label: t('glb.export.ipsCsv'), icon: 'download', dataset: { export: 'ips-csv' }, onSelect: ipExport('csv') },
      { label: t('glb.export.ipsJson'), icon: 'download', dataset: { export: 'ips-json' }, onSelect: ipExport('json') }
    ],
    // Copy link shares the check on screen (its name, type, locations and expected value), not the box.
    link: () => (current ? ctx.shareUrl(checkParams(current)) : null)
  });
  head.set('actions', actions.el);

  /** Region 5: three tabs; every section stays in the page, only the panels of the others hide. */
  const TAB_IDS = ['groups', 'ips', 'resolvers'];
  let tabNow = TAB_IDS.includes(restored?.tab) ? restored.tab : 'groups';
  const tabs = Tabs([
    { id: 'groups', label: t('glb.tab.groups') },
    { id: 'ips', label: t('glb.tab.ips') },
    { id: 'resolvers', label: t('glb.tab.resolvers') }
  ], { selected: tabNow, label: t('nav.global'), className: 'glb-tabs', onChange: (tabId) => { tabNow = tabId; } });
  tabs.panel('groups').append(h('div', { class: 'glb-panel tool-stack' }, metrics.el, findingsEl, legendCard));
  tabs.panel('ips').append(h('div', { class: 'glb-panel tool-stack' }, ipSection));
  tabs.panel('resolvers').append(h('div', { class: 'glb-panel tool-stack' }, resSection, geoSection, ispSection));
  const results = h('div', { class: 'glb-results tool-stack', hidden: true, dataset: { shortcutScope: 'results' } },
    head.el, expectCard, filterNote, tabs.el);

  container.append(h('div', { class: 'glb-view tool-stack' }, input.el, emptyWrap, results, runBar.float));
  // Their phone-layout listeners would keep this page alive once it is left.
  ctx.onCleanup(() => {
    runBar.dispose();
    actions.dispose();
  });

  /* --- run state ----------------------------------------------------------------- */
  /** @type {null|{ name: string, type: string, geo: boolean, rows: object[], rowByKey: Map, ips: Map,
   *   controller: AbortController|null, done: boolean, cancelled: boolean, total: number }} */
  let current = null;
  let renderTimer = null;

  function answeredCount() {
    return current ? current.rows.filter((r) => !r.pending && !isNotAsked(r) && !isErrorValues(r.values)).length : 0;
  }

  function makeRows(geo) {
    const res = RESOLVERS.map((r) => ({ kind: 'resolver', key: `resolver:${r.id}`, resolver: r, vantage: null, pending: true, values: null, response: null, filtered: false, addresses: [], scopePrefix: null }));
    const g = geo ? GEO_VANTAGES.map((v) => ({ kind: 'geo', key: `geo:${v.id}`, resolver: null, vantage: v, pending: true, values: null, response: null, filtered: false, addresses: [], scopePrefix: null })) : [];
    return [...res, ...g];
  }

  function applyItem(item) {
    if (!current) return;
    if (item.kind === 'control') {
      // AliDNS asked on behalf of a subnet outside China: no row, only the verdict reads it.
      current.controls = [...current.controls.filter((c) => c.key !== item.key), { kind: 'control', key: item.key, resolver: item.resolver, values: item.values }];
      scheduleRender();
      return;
    }
    const row = current.rowByKey.get(item.key);
    if (!row) return;
    row.pending = false;
    row.notAsked = !!item.notAsked;
    row.response = item.response;
    row.values = item.values;
    row.filtered = !!item.filtered;
    row.addresses = Array.isArray(item.addresses) ? item.addresses : [];
    row.scopePrefix = Number.isFinite(item.scopePrefix) ? item.scopePrefix : null;
    // When it answered (its cached copy's countdown starts then), and whether it is no answer to judge.
    row.at = Number.isFinite(Number(item.at)) && item.at !== null ? Number(item.at) : Date.now();
    row.skipped = isBrowserBlocked(row);
    if (!row.filtered) {
      const index = ctx.getInventoryIndex();
      const { chain } = splitChain(row.values);
      for (const ip of row.addresses) {
        let entry = current.ips.get(ip);
        const classification = classifyIp(ip, chain);
        if (entry && entry.classification.kind === 'direct' && classification.kind !== 'direct') {
          entry.classification = classification; // a later answer revealed the CDN via its CNAME chain
        }
        if (!entry) {
          entry = {
            ip,
            version: ipVersion(ip),
            classification,
            private: isPrivateIP(ip),
            members: new Set(),
            servers: lookupServers([ip], index).map((m) => m.server)
          };
          current.ips.set(ip, entry);
          ipTable.addRows([entry]);
        }
        entry.members.add(row.key);
      }
    }
    scheduleRender();
  }

  function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => {
      renderTimer = null;
      renderAll();
    }, 120);
  }

  /** Recompute groups and refresh every derived piece of UI (cheap: ≤ 43 rows). */
  function renderAll() {
    if (!current) return;
    const readable = current.rows.filter((r) => !isSkipped(r));
    groups = groupAnswers(readable);
    groupByKey = new Map(groups.map((g) => [g.key, g]));
    verdict = propagationVerdict(readable, { type: current.type, controls: current.controls });
    verdictByKey = new Map(verdict.groups.map((g) => [g.key, g]));
    if (filterKey && !groupByKey.has(filterKey)) setFilter(null);
    resolverTable.refresh();
    geoTable.refresh();
    chinaTable.refresh();
    ipTable.refresh();
    if (ispPanel) ispPanel.refresh();
    renderLegend();
    renderStats();
    renderHead();
    renderExpected();
    const done = current.rows.filter((r) => !r.pending).length;
    if (!current.done) progress.set(done, current.rows.length);
  }

  /**
   * The run bar and the input follow the state: compact from the moment a check starts and while
   * one is on screen; "Run again" while the form asks for the check on screen (its name, type and
   * locations).
   */
  function syncRunBar() {
    const running = !!(current && current.controller);
    const stateNow = templateState({ running, result: !!current });
    let same = false;
    if (stateNow === 'done') {
      const name = normalizeHostname(nameField.value.trim(), { allowSingleLabel: true });
      same = name === current.name && typeField.value === current.type && geoField.checked === current.geo;
    }
    runBar.setState(stateNow);
    runBar.setRerun(same);
    input.setCompact(inputCompact(stateNow));
    input.refresh();
  }

  /* --- the expected value ------------------------------------------------------------- */

  /** The expected value as the fields hold it, for a record type (the check's); why not, at the field. */
  function readExpected(type = current ? current.type : (GLOBAL_TYPES.includes(typeField.value) ? typeField.value : 'A')) {
    // A link's regex waits for the user (see expectHeld): the field says how to apply it.
    if (heldHintShown !== expectHeld) {
      heldHintShown = expectHeld;
      expectField.setHint(t(expectHeld ? 'glb.exp.held' : 'glb.exp.hint'));
    }
    if (expectHeld) {
      expectField.setError(null);
      return null;
    }
    const parsed = parseExpected({ mode: matchField.value, pattern: expectField.value, type });
    let error = null;
    if (parsed.error === 'regex') error = t('glb.exp.err.regex', { detail: parsed.detail || '' });
    else if (parsed.error === 'long') error = t('glb.exp.err.long', { max: formatNumber(EXPECT_MAX_LENGTH) });
    else if (parsed.error === 'address') error = t('glb.exp.err.address', { type, family: type === 'AAAA' ? 'IPv6' : 'IPv4', value: parsed.detail || '' });
    expectField.setError(error);
    return parsed.ok ? parsed : null;
  }

  /**
   * The route params of the expected value (none without one; `match` only when it is not exact);
   * a held regex from a link stays in it.
   */
  const expectParams = () => {
    const held = expectHeld ? String(expectField.value || '').trim() : '';
    if (held) return { expect: held, match: 'regex' };
    return expectedNow ? { expect: expectedNow.pattern, match: expectedNow.mode === 'exact' ? null : expectedNow.mode } : {};
  };

  /** The export-only "Expected value" column, while there is one (the tables are redrawn only when that changes). */
  function syncExpectedColumns() {
    if (columnsWithExpected === !!expectedNow) return;
    columnsWithExpected = !!expectedNow;
    const extra = expectedNow ? [expectedColumn] : [];
    resolverTable.setColumns([...resolverColumns, ...extra]);
    geoTable.setColumns([...geoColumns(), ...extra]);
    chinaTable.setColumns([...geoColumns({ withResolver: true }), ...extra]);
  }

  /**
   * The fields changed (an edit, Enter, a mode picked — the user's own action, which also applies a
   * held regex): judge the answers on screen again (nothing is asked) and keep the value in the link.
   */
  function applyExpected() {
    expectHeld = false;
    expectedNow = readExpected();
    syncExpectedColumns();
    if (!expectedNow && missingOnly) setMissingOnly(false);
    else if (missingOnly) applyFilters();
    if (!current) return;
    ctx.setParams(checkParams(current));
    renderAll();
  }

  /** Show only the rows that do not serve the expected value yet (or every row again), on the Resolvers & locations tab. */
  function setMissingOnly(on) {
    missingOnly = !!on && !!expectedNow;
    if (missingOnly) {
      filterKey = null;
      statusFilter = null;
      showFiltered();
    }
    applyFilters();
    if (current) renderExpected();
  }

  /**
   * A filter turned on: the tab of the rows it filters (Resolvers & locations), as a status item
   * opens it. The keyboard goes with them when the control pressed sat on a panel that now hides
   * (an answer group's chip): to that tab, never to the page's body.
   */
  function showFiltered() {
    const doc = globalThis.document;
    const fromPanel = !!(doc && doc.activeElement && tabs.el.contains(doc.activeElement));
    tabs.select('resolvers', { focus: fromPanel });
  }

  /**
   * The worst case anywhere in words (lib/expected.js expectedEta): a worst case only when it rests
   * on the zone's name server, else an estimate with its lower bound (cached TTLs count down); then
   * what it rests on — the record's TTL (the name server's, or read from the copies here), the
   * negative-cache time — and, before the name server was asked, that it can make it exact.
   */
  function worstLines(eta) {
    let head = t('glb.exp.worstUnknown');
    if (eta.seconds !== null && eta.exact) head = t('glb.exp.worst', { duration: waitText(eta.seconds) });
    else if (eta.seconds !== null && eta.least > 0 && eta.least < eta.seconds) {
      head = t('glb.exp.estimate', { least: waitText(eta.least), duration: waitText(eta.seconds) });
    } else if (eta.seconds !== null) head = t('glb.exp.estimateLikely', { duration: waitText(eta.seconds) });
    const lines = [head];
    const ns = soaResult ? soaResult.ns : '';
    if (eta.positive && eta.recordFrom === 'name-server') lines.push(t('glb.exp.recordNs', { ns, ttl: formatNumber(eta.recordTtl) }));
    else if (eta.positive && eta.recordTtl !== null) {
      lines.push(t('glb.exp.worstRecord', { ttl: formatNumber(eta.recordTtl), seen: formatNumber(eta.observedTtl) }));
      if (eta.serverTtl !== null) lines.push(t('glb.exp.recordLower', { ns, ttl: formatNumber(eta.serverTtl) }));
    }
    if (eta.negative && eta.negativeTtl !== null) {
      lines.push(eta.negativeFrom === 'name-server' ? t('glb.exp.negNs', { ttl: formatNumber(eta.negativeTtl), ns })
        : t('glb.exp.negAnswers', { ttl: formatNumber(eta.negativeTtl) }));
    }
    if (eta.seconds !== null && !eta.exact && !soaResult) lines.push(t('glb.exp.estimateHint'));
    return lines;
  }

  /**
   * Re-render the expected value's card: the value, how many sources serve it, until when the
   * others may keep the old answer, the worst case anywhere, the flush pages and the name server
   * probe. Hidden without an expected value or a check.
   */
  function renderExpected() {
    const show = !!(current && expectedNow);
    expectCard.hidden = !show;
    if (!show) return;
    const rows = current.rows;
    const tally = expectedTally(rows, expectedNow);
    const running = !current.done && !current.cancelled;
    const eta = expectedEta(rows, expectedNow, { authoritative: soaResult && soaResult.state === 'ok' ? soaResult : null });
    expectCard.dataset.state = !tally.judged ? (running ? 'running' : 'none') : tally.done ? 'done' : 'pending';
    clear(expValueEl);
    expValueEl.append(h('code', { class: 'mono glb-exp-pattern' }, expectedNow.pattern), ' ',
      h('span', { class: 'muted text-sm glb-exp-mode' }, t(`glb.exp.mode.${expectedNow.mode}`)));
    clear(expCountEl);
    Object.assign(expCountEl.dataset, { match: String(tally.match), mismatch: String(tally.mismatch), judged: String(tally.judged) });
    if (tally.judged) {
      const pct = Math.round((tally.match / tally.judged) * 100);
      append(expCountEl,
        h('span', { class: 'glb-exp-count-text' }, t('glb.exp.count', { count: tally.judged, match: formatNumber(tally.match), judged: formatNumber(tally.judged) })),
        tally.failed ? h('span', { class: 'muted text-sm' }, t('glb.exp.failed', { count: tally.failed })) : null,
        h('span', { class: 'glb-bar glb-exp-bar', attrs: { 'aria-hidden': 'true' } }, h('span', { class: 'glb-bar-fill', style: { width: `${pct}%` } })));
    } else {
      expCountEl.append(h('span', { class: 'muted text-sm' }, running ? t('glb.sum.running') : t('glb.exp.none')));
    }
    // The "every source serves it" note (a status) is kept while it holds, not inserted again on every redraw.
    const doneNote = tally.done && !running;
    if (doneNote !== !!expNoteEl.firstChild) {
      clear(expNoteEl);
      if (doneNote) expNoteEl.append(Alert({ variant: 'ok', compact: true, message: t('glb.exp.done') }));
    }
    const pending = eta.mismatched > 0;
    const now = Date.now();
    expLastEl.hidden = !pending;
    expWorstEl.hidden = !pending;
    expFlushEl.hidden = !pending;
    if (pending) {
      expLastEl.textContent = !eta.last ? t('glb.exp.notYetNoTtl', { count: eta.mismatched })
        : eta.last <= now ? t('glb.exp.expired', { count: eta.mismatched })
          : t('glb.exp.notYet', { count: eta.mismatched, time: clockTime(eta.last, now), left: formatRelative(eta.last, now) });
      expWorstEl.textContent = worstLines(eta).join(' ');
      expWorstEl.dataset.seconds = eta.seconds === null ? '' : String(eta.seconds);
      expWorstEl.dataset.exact = String(eta.exact);
    }
    expToggle.hidden = !pending && !missingOnly;
    expToggle.querySelector('.btn-label').textContent = missingOnly ? t('glb.group.showAll') : t('glb.exp.onlyMissing', { count: eta.mismatched });
    expToggle.setAttribute('aria-pressed', String(missingOnly));
    // The name server probe: once the check has ended, while some answer is not there yet — or to
    // keep its result (or its run) on screen.
    const kept = !!soaResult || !!(soaPanel && soaPanel.busy());
    soaSlot.hidden = running || !(pending || kept);
    soaOpen.hidden = !!soaPanel;
    if (soaPanel) soaPanel.refresh();
  }

  function renderLegend() {
    clear(legendEl);
    if (!groups.length) {
      legendEl.append(h('span', { class: 'muted text-sm' }, t('glb.sum.running')));
      return;
    }
    for (const g of groups) {
      const ops = g.filtered ? [] : verdictByKey.get(g.key)?.operators || [];
      const { plain, chain } = splitChain(g.values);
      const values = g.error ? [t('glb.value.failed')] : (plain.length ? plain : chain.map((c) => `→ ${c}`));
      const shown = values.slice(0, 3).join(', ') + (values.length > 3 ? ` +${values.length - 3}` : '') + (plain.length && chain.length ? ' ↪' : '');
      legendEl.append(h('button', {
        type: 'button',
        class: ['glb-chip', groupClass(g), { 'is-active': filterKey === g.key }],
        title: g.values.join('\n'),
        dataset: { group: g.letter || (g.error ? 'error' : 'blocked') },
        attrs: { 'aria-pressed': String(filterKey === g.key) },
        on: { click: () => setFilter(filterKey === g.key ? null : g.key) }
      },
      groupMark(g, { withLabel: !g.letter }),
      g.error ? null : h('span', { class: 'glb-chip-values mono' }, g.values.length === 1 && g.values[0] === 'NODATA' ? t('glb.value.nodata') : shown),
      ops.length ? operatorLabels(ops) : null,
      h('span', { class: 'glb-chip-count' }, t('glb.group.members', { count: g.members.length }))));
    }
  }

  /** Show only the rows of one answer group (or every row again), on the Resolvers & locations tab: the other filters go. */
  function setFilter(key) {
    filterKey = key;
    if (key) {
      missingOnly = false;
      statusFilter = null;
      showFiltered();
    }
    applyFilters();
    if (key && current) renderExpected();
  }

  /**
   * A status item pressed (lib/propagation.js propagationStatusMatch): the tables show the sources
   * it counts, on the Resolvers & locations tab; pressed again, every source. The other filters go.
   */
  function setStatusFilter(key) {
    statusFilter = key;
    if (key) {
      filterKey = null;
      missingOnly = false;
      tabs.select('resolvers');
    }
    status.setPressed(key);
    applyFilters();
    if (current) renderExpected();
  }

  /** The tables' filter: one answer group's rows, the rows not serving the expected value yet, a status item's rows, or none. */
  function applyFilters() {
    const g = filterKey ? groupByKey.get(filterKey) : null;
    let fn = null;
    let ipFn = null;
    const rowsOf = (test) => (ipRow) => [...ipRow.members].some((k) => {
      const row = current && current.rowByKey.get(k);
      return !!row && test(row);
    });
    if (g) {
      fn = (row) => !row.pending && !isSkipped(row) && row.values.join('\n') === filterKey;
      ipFn = (ipRow) => [...ipRow.members].some((k) => g.members.includes(k));
    } else if (missingOnly && expectedNow) {
      fn = (row) => expectedVerdict(row, expectedNow) === 'mismatch';
      ipFn = rowsOf(fn);
    } else if (statusFilter) {
      fn = (row) => propagationStatusMatch(statusFilter, row);
      ipFn = rowsOf(fn);
    }
    resolverTable.setFilter(fn);
    geoTable.setFilter(fn);
    chinaTable.setFilter(fn);
    if (ispPanel) ispPanel.setFilter(fn);
    ipTable.setFilter(ipFn);
    clear(filterNote);
    filterNote.hidden = !fn;
    if (g) {
      filterNote.append(
        Icon('filter', { size: 14 }),
        h('span', null, g.letter ? t('glb.group.filterOn', { letter: g.letter }) : t(g.error ? 'glb.group.error' : 'glb.group.blocked')),
        Button({ label: t('glb.group.showAll'), size: 'sm', variant: 'ghost', onClick: () => setFilter(null) }));
    } else if (missingOnly && fn) {
      filterNote.append(
        Icon('filter', { size: 14 }),
        h('span', null, t('glb.exp.filterOn')),
        Button({ label: t('glb.group.showAll'), size: 'sm', variant: 'ghost', onClick: () => setMissingOnly(false) }));
    } else if (fn) {
      const item = status.el.querySelector(`[data-status="${statusFilter}"] .status-text`);
      filterNote.append(
        Icon('filter', { size: 14 }),
        h('span', null, t('glb.statusFilterOn', { what: item ? item.textContent : statusFilter })),
        Button({ label: t('glb.group.showAll'), size: 'sm', variant: 'ghost', dataset: { action: 'glb-filter-clear' }, onClick: () => setStatusFilter(null) }));
    }
    legendEl.querySelectorAll('.glb-chip').forEach((b) => {
      const on = b.title === (g ? g.values.join('\n') : null) && !!g;
      b.setAttribute('aria-pressed', String(on));
      b.classList.toggle('is-active', on);
    });
  }

  /** The figures of the check (the Answer groups tab's metric strip): read-only, only an error or warning coloured. */
  function renderStats() {
    const rows = current.rows;
    const notAsked = rows.filter(isNotAsked).length;
    const finished = rows.filter((r) => !r.pending && !isNotAsked(r));
    const unavailable = finished.filter(isBrowserBlocked).length;
    const failed = finished.filter((r) => isErrorValues(r.values)).length - unavailable;
    const answerGroups = groups.filter((g) => g.letter).length;
    // Several answers are a warning only when they are not explained (by design, GeoDNS, or a
    // filtering resolver's own answer next to answers that agree).
    const explained = verdict && ['agree', 'by-design', 'geo'].includes(verdict.state);
    const ipRows = [...current.ips.values()];
    const mine = ipRows.filter((r) => r.servers.length).length;
    const kinds = new Map();
    for (const r of ipRows) {
      const label = r.classification.kind === 'cloudflare' ? 'Cloudflare' : r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`);
      kinds.set(label, (kinds.get(label) || 0) + 1);
    }
    const ipHint = [...kinds.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, n]) => `${formatNumber(n)} ${k}`).join(' · ');
    const lat = median(rows.filter((r) => r.kind === 'resolver' && !r.pending && r.response && r.response.ok).map((r) => r.response.elapsedMs));
    metrics.update([
      {
        id: 'answered',
        label: t('glb.stat.answered'),
        value: `${formatNumber(finished.length - failed - unavailable)} / ${formatNumber(rows.length - notAsked)}`,
        severity: failed && failed + unavailable === finished.length && current.done ? 'error' : null,
        hint: [
          failed ? t('glb.stat.failed', { count: failed }) : null,
          unavailable ? t('glb.stat.unavailable', { count: unavailable }) : null,
          notAsked ? t('glb.stat.notAsked', { count: notAsked }) : null
        ].filter(Boolean).join(' · ') || null
      },
      {
        id: 'groups',
        label: t('glb.stat.groups'),
        value: answerGroups,
        severity: verdict && verdict.state === 'unresolved' ? 'error' : answerGroups > 1 && !explained ? 'warn' : null
      },
      { id: 'ips', label: t('glb.stat.ips'), value: ipRows.length, hint: mine ? `${ipHint} · ${t('glb.stat.inventory', { count: mine })}` : (ipHint || null) },
      { id: 'latency', label: t('glb.stat.latency'), value: lat === null ? '—' : ms(lat), hint: t('glb.stat.latencyHint') }
    ]);
    tabs.setBadge('groups', answerGroups || null, verdict && verdict.state === 'unresolved' ? 'error' : answerGroups > 1 && !explained ? 'warn' : null);
    tabs.setBadge('ips', ipRows.length || null);
  }

  /**
   * What the verdict says of the check on screen (lib/propagation.js propagationVerdict and
   * propagationOutcome): the title's words, what it rests on (the body), what else is worth saying
   * (failed queries, blocked or rewritten answers, sources not readable or not asked, ISP answers
   * that linger, a stop) and the findings — or the ISP lines of the 'stale' state.
   * @param {ReturnType<typeof propagationOutcome>} outcome
   * @returns {{ state: string, title: string|null, body: string[], extra: string[], findings: object[], ispLines: string[] }}
   */
  function verdictParts(outcome) {
    const rows = current.rows;
    const finished = rows.filter((r) => !r.pending);
    const unavailable = finished.filter(isBrowserBlocked);
    const notAsked = finished.filter(isNotAsked);
    const usable = finished.filter((r) => !r.filtered && !isNotAsked(r) && !isErrorValues(r.values));
    const distinct = (list) => new Set(list.map((r) => r.values.join('\n'))).size;
    const extra = [
      outcome.failed ? t('glb.sum.errors', { count: outcome.failed }) : null,
      outcome.blocked ? t('glb.sum.blocked', { count: outcome.blocked }) : null,
      verdict.rewritten.length ? t('glb.sum.rewritten', { names: sourceNames(verdict.rewritten), targets: verdict.rewriteTargets.join(', ') }) : null,
      unavailable.length ? t('glb.sum.unavailable', { names: unavailable.map((r) => r.resolver.name).join(', ') }) : null,
      notAsked.length ? t('glb.sum.notAsked', { names: sourceNames(notAsked.map((r) => r.key)), type: current.type }) : null,
      ispPanel ? ispPanel.note(verdict, { shortList }) : null,
      current.cancelled ? t('glb.cancelled') : null
    ].filter(Boolean);
    const operators = shortList(verdict.operators.map((op) => op.name));
    const out = { state: outcome.state, title: null, body: [], extra, findings: [], ispLines: [] };
    switch (outcome.state) {
      case 'running':
        break;
      case 'stopped':
        out.title = t('glb.sum.stoppedTitle');
        break;
      case 'failed':
        out.title = t('glb.sum.failedTitle');
        out.body = [t('glb.sum.failedBody')];
        break;
      case 'none':
        out.title = t('glb.sum.differTitle');
        break;
      case 'agree':
        out.title = t('glb.sum.agreeTitle');
        out.body = [t('glb.sum.agreeBody', { count: usable.length - verdict.rewritten.length })];
        break;
      case 'unresolved':
        out.title = t('glb.sum.unresolvedTitle');
        out.findings = verdict.findings;
        break;
      case 'by-design': {
        // No records of the type anywhere (AAAA of an IPv4-only CDN name): only the chains differ.
        const type = current.type;
        const steered = verdict.steering[0];
        const { split, unsure } = splitOfVerdict();
        const body = verdict.noRecords
          ? (unsure ? [t('glb.sum.nodataNone', { type }), splitText(split)] : [t('glb.sum.nodataBody', { type, operators }), split ? splitText(split) : null]).filter(Boolean).join(' ')
          : split ? t(split.line ? 'glb.sum.designGeo' : 'glb.sum.designGeoUnsure', splitParams(split))
            : steered ? t('glb.sum.designSteered', { owner: steered.owner || current.name, targets: shortList(steered.targets) })
              : t('glb.sum.designBody');
        // An operator only those locations get is explained above: "multi-CDN" only for the others.
        const away = new Set(verdict.geoSplits.flatMap((s) => s.members));
        const multi = verdict.operators.filter((op) => !op.members.every((m) => away.has(m))).length > 1;
        out.title = verdict.noRecords ? t(unsure ? 'glb.sum.nodataTitleUnsure' : 'glb.sum.nodataTitle', { type, operators })
          : t(unsure ? 'glb.sum.designTitleUnsure' : 'glb.sum.designTitle', { operators });
        out.body = [body, multi ? t('glb.sum.designMulti') : null].filter(Boolean);
        break;
      }
      case 'geo': {
        const geoGroups = distinct(usable.filter((r) => r.kind === 'geo'));
        const { split, unsure } = splitOfVerdict();
        out.title = t(unsure ? 'glb.sum.geoTitleUnsure' : 'glb.sum.geoTitle');
        out.body = [t(unsure ? 'glb.sum.geoBodyUnsure' : 'glb.sum.geoBody', { groups: formatNumber(geoGroups) }), split ? splitText(split) : null].filter(Boolean);
        break;
      }
      default:
        if (outcome.state === 'stale' && ispPanel) {
          // Only ISP resolvers (ui/isp-resolvers.js) still give an answer: when it expires there.
          const stale = ispPanel.staleSummary(verdict, { shortList });
          out.title = stale.title;
          out.body = stale.body;
          out.ispLines = stale.lines;
          break;
        }
        out.title = t('glb.sum.differTitle');
        out.body = [
          t('glb.sum.differBody', { groups: formatNumber(verdict.groups.filter((g) => !g.rewritten).length) }),
          verdict.designPart ? t('glb.sum.designPart', { operators }) : null
        ].filter(Boolean);
        out.findings = verdict.findings;
    }
    return out;
  }

  /** A status item's words: "2 sources answered SERVFAIL", "1 query failed", "46 of 46 answered" … */
  function statusText(item) {
    if (item.key === 'rcode') {
      return item.rcodes.length === 1 && item.rcodes[0] === 'SERVFAIL' ? t('glb.count.servfail', { count: item.count })
        : t('glb.count.rcode', { count: item.count, rcodes: item.rcodes.join(', ') });
    }
    if (item.key === 'answered') return t('glb.count.answered', { count: item.count, total: formatNumber(item.total) });
    return t(`glb.count.${item.key}`, { count: item.count });
  }

  /** The check whose totals were said (once, when it ended: the status summary is no live region). */
  let announcedFor = null;

  /**
   * The result header of the check on screen (region 4): while it runs "Checking <name>…" with the
   * progress and the counts so far; then the verdict and the name, the record type and the time,
   * what the verdict rests on, the status summary — the DNS errors, the failed queries and the
   * blocked answers filter the tables, the different answers open their groups —, the actions and
   * "Also check". Region 7, the findings, goes with it.
   */
  function renderHead() {
    const running = !current.done && !current.cancelled;
    const outcome = propagationOutcome(current.rows, verdict, { done: current.done, cancelled: current.cancelled });
    const parts = verdictParts(outcome);
    head.setState(running ? 'running' : 'done');
    head.el.dataset.verdict = outcome.state;
    head.set('title', running
      ? ResultTitle({ running: true, text: withSubject((p) => t('result.checking', p), current.name) })
      // The dot stays with the verdict when the title wraps on a phone (a no-break space before it).
      : ResultTitle({ severity: outcome.severity, text: [h('span', { class: 'glb-verdict' }, parts.title), ' · ', h('span', { class: 'result-subject mono' }, current.name)] }));
    head.set('meta', [
      h('span', { class: 'glb-meta-type' }, t('glb.typeMeta', { type: current.type })),
      !running && current.finishedAt ? RelativeTime(current.finishedAt, { text: t('glb.checkedAt', { time: formatRelative(current.finishedAt) }) }) : null
    ]);
    head.set('progress', running ? progress.el : null);
    head.set('notes', running ? null : [
      parts.body.length ? h('p', { class: 'glb-verdict-body' }, parts.body.join(' ')) : null,
      parts.extra.length ? h('p', { class: 'glb-verdict-extra' }, parts.extra.join(' ')) : null
    ]);
    const items = propagationStatus(outcome).map((item) => ({
      ...item,
      text: statusText(item),
      ...(item.key === 'rcode' || item.key === 'failed' || item.key === 'blocked'
        ? { filter: true, onPress: (key) => setStatusFilter(toggleStatus(statusFilter, key)) }
        : item.key === 'differ' || item.key === 'design'
          ? { onPress: () => openGroups() }
          : {})
    }));
    if (statusFilter && !items.some((x) => x.key === statusFilter && x.count > 0)) {
      statusFilter = null;
      applyFilters();
    }
    status.update(items, { pressed: statusFilter });
    head.set('related', RelatedLinks({
      self: 'global',
      links: [
        { view: 'lookup', icon: 'search', label: t('nav.lookup'), href: ctx.href('lookup', { name: current.name, type: current.type }) },
        { view: 'health', icon: 'activity', label: t('nav.health'), href: ctx.href('health', { domain: current.name }) }
      ]
    }));
    actions.setDisabled(running);
    actions.setExportsDisabled(!current.ips.size);
    renderFindings(running ? [] : parts.findings, running ? [] : parts.ispLines);
    if (!running && announcedFor !== current) {
      announcedFor = current;
      announce([`${parts.title} · ${current.name}`, ...statusItems(items).map((x) => x.text)].join(' · '));
    }
  }

  /** "n different answers": the Answer groups tab, its groups in view. */
  function openGroups() {
    tabs.select('groups');
    legendEl.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
    const first = legendEl.querySelector('.glb-chip');
    if (first) first.focus({ preventScroll: true });
  }

  /** How bad a finding is: its icon in the list (an rcode is a fault, a regional line by design is a fact). */
  const findingSeverity = (f) => (f.partner || (f.code === 'cname' && f.byLocation) ? 'info' : f.code === 'rcode' ? 'error' : 'warn');

  /**
   * Region 7: the findings, one row each (the warning alert's list before): at most three, then
   * "Show n more". The ISP answers that linger are its rows in the 'stale' state.
   */
  function renderFindings(findings, ispLines = []) {
    clear(findingsEl);
    const rows = [
      ...findings.map((f) => renderFinding(f, findingSeverity(f))),
      ...ispLines.map((text) => h('li', { class: 'finding glb-finding', dataset: { finding: 'isp-stale' } },
        h('span', { class: 'finding-icon glb-finding-icon' }, SeverityIcon('warn')), h('span', { class: 'finding-text glb-finding-text' }, text)))
    ];
    if (!rows.length) return;
    const limit = findingsOpen ? rows.length : 3;
    const titleId = uid('glb-findings');
    const more = rows.length > limit ? Button({
      label: t('glb.findings.more', { count: rows.length - limit }), size: 'sm', variant: 'ghost', icon: 'chevron-down', dataset: { action: 'glb-findings-more' },
      onClick: () => {
        findingsOpen = true;
        renderFindings(findings, ispLines);
        const next = findingsEl.querySelectorAll('.glb-finding')[limit];
        if (next) {
          next.setAttribute('tabindex', '-1');
          next.focus({ preventScroll: true });
        }
      }
    }) : null;
    findingsEl.append(h('section', { class: 'card finding-card glb-findings-card', attrs: { 'aria-labelledby': titleId } },
      h('h3', { class: 'finding-title glb-findings-title', id: titleId }, t('glb.findings.label')),
      h('ul', { class: 'glb-findings finding-list' }, rows.slice(0, limit)),
      more));
  }

  /** "a, b, c +2 more" — the first `max` entries of a list. */
  function shortList(list, max = 3, separator = ', ') {
    return list.length > max ? `${list.slice(0, max).join(separator)} ${t('glb.find.more', { count: list.length - max })}` : list.join(separator);
  }

  /** Where a location split sends its locations: "CNAME x", or the address records (null). */
  const splitTargets = (split) => shortList(split.targets.map((x) => (x === null ? t('glb.find.addressRecords', { type: current.type }) : `CNAME ${x}`)), 3, ' · ');

  const canonicalOwner = (n) => String(n || '').toLowerCase().replace(/\.$/, '');

  /**
   * The longest an older answer could still be held for the locations of a split: the TTL of the
   * CNAME record they got at the split's owner (else their answers' shortest TTL).
   */
  function splitTtl(split) {
    const owner = canonicalOwner(split.owner || current.name);
    let ttl = null;
    for (const key of split.members) {
      const res = current.rowByKey.get(key)?.response;
      const answers = res && Array.isArray(res.answers) ? res.answers : [];
      const rr = answers.find((x) => x && x.type === 'CNAME' && canonicalOwner(x.name) === owner);
      const v = rr && Number.isFinite(rr.ttl) ? rr.ttl : minAnswerTtl(res);
      if (Number.isFinite(v) && (ttl === null || v > ttl)) ttl = v;
    }
    return ttl;
  }

  /** The words of a split (lib/propagation.js geoSplits): who goes where, and the TTL when it is unsure. */
  const splitParams = (split) => ({
    owner: split.owner || current.name, sources: sourceNames(split.members), targets: splitTargets(split), ttl: humanTtl(splitTtl(split))
  });

  /** A split told on its own: the region's line (the control confirms it), or either that or an older answer. */
  const splitText = (split) => t(split.line ? 'glb.find.cnameGeo' : 'glb.find.cnameGeoUnsure', splitParams(split));

  /**
   * The branch only the locations asked through a resolver of their own (mainland China) take, the
   * one the control could not confirm first: a verdict that rests on it is told as likely, never certain.
   */
  function splitOfVerdict() {
    const split = verdict.geoSplits.find((s) => !s.line) || verdict.geoSplits[0] || null;
    return { split, unsure: !!split && !split.line };
  }

  /**
   * Display names of answer sources (resolver names, location names), de-duplicated. Joined
   * with "; ": a location name has a comma of its own ("Istanbul, Türkiye").
   */
  function sourceNames(keys) {
    // In table order (resolvers, then locations as listed), not in the order answers arrived.
    const order = (key) => {
      const i = current.rows.findIndex((r) => r.key === key);
      return i === -1 ? Infinity : i;
    };
    const names = [...keys].sort((a, b) => order(a) - order(b)).map((key) => {
      const row = current.rowByKey.get(key);
      if (!row) return key;
      return row.kind === 'geo' ? vantageName(row.vantage) : row.kind === 'isp' ? ispName(row) : row.resolver.name;
    });
    return shortList([...new Set(names)], 3, '; ');
  }

  /** One verdict finding, a row of the findings list: its icon, the groups it is about (letter marks) and what it most likely means. */
  function renderFinding(f, severity = 'warn') {
    const sources = sourceNames(f.members);
    const providers = shortList((f.operators || []).map((op) => op.name));
    let text;
    switch (f.partner ? 'partner' : f.code) {
      case 'partner':
        // A China answer whose chain enters a CDN this tool knows and only its last name is unknown
        // (lib/propagation.js `partner`): likely the CDN's partner cache; the verdict stays.
        text = t('glb.find.partner', { sources: sourceNames(f.partner.members), names: shortList(f.partner.names), cdn: shortList(f.partner.cdns) });
        break;
      case 'rcode':
        // SERVFAIL is a failure to resolve; REFUSED and the rest a resolver's own choice.
        // Only sources that do not validate DNSSEC (AliDNS) give it: no signature problem then.
        text = f.rcode === 'SERVFAIL' ? t(f.noDnssec ? 'glb.find.servfailNoDnssec' : 'glb.find.servfail', { sources })
          : t('glb.find.rcode', { sources, rcode: f.rcode });
        break;
      case 'nxdomain': text = t('glb.find.nxdomain', { sources }); break;
      case 'nodata': text = t('glb.find.nodata', { sources, type: current.type }); break;
      case 'private': text = t('glb.find.private', { sources, ips: shortList(f.ips) }); break;
      case 'mixed':
        text = t('glb.find.mixed', { count: f.ips.length, sources, ips: shortList(f.ips), operators: shortList(verdict.operators.map((op) => op.name)) });
        break;
      case 'cname': {
        const owner = f.owner || current.name;
        if (f.byLocation) {
          // Only the locations asked through a resolver of their own take this branch: by design.
          text = splitText(f.byLocation);
          break;
        }
        // null: the chain ends there — in address records, or with no records at all.
        const end = verdict.noRecords ? t('glb.find.noRecords', { type: current.type }) : t('glb.find.addressRecords', { type: current.type });
        const targets = f.targets.map((x) => (x === null ? end : `CNAME ${x}`)).join(' · ');
        text = f.operators.length > 1 ? t('glb.find.cnameMove', { owner, targets, operators: providers }) : t('glb.find.cname', { owner, targets });
        break;
      }
      case 'operators': text = t('glb.find.operators', { type: current.type, name: current.name, operators: providers }); break;
      default: text = t(`glb.find.${f.code}`);
    }
    if (f.filtering) text = `${text} ${t('glb.find.filtering')}`;
    // Marks in legend order; none when the finding is about every answer group ('direct',
    // 'records', a CNAME that differs everywhere), where they would only repeat the legend.
    const keys = groups.filter((g) => (f.partner ? f.partner.groups : f.groups).includes(g.key)).map((g) => g.key);
    const everyGroup = f.code === 'direct' || f.code === 'records' || keys.length === groups.filter((g) => g.letter).length;
    const marks = everyGroup ? [] : keys.slice(0, 4).map((key) => groupMark(groupByKey.get(key)));
    if (!everyGroup && keys.length > 4) marks.push(h('span', { class: 'glb-finding-more' }, `+${keys.length - 4}`));
    return h('li', { class: 'finding glb-finding', dataset: f.partner ? { finding: f.code, partner: 'true', severity } : { finding: f.code, severity } },
      h('span', { class: 'finding-icon glb-finding-icon' }, SeverityIcon(severity)),
      marks.length ? h('span', { class: 'glb-finding-marks' }, marks) : null,
      h('span', { class: 'finding-text glb-finding-text' }, text));
  }

  /** A check starts (true) or ends: Stop takes Run's slot (the keyboard focus goes with it); the form waits. */
  function setRunning(on) {
    runBar.setRunning(on);
    nameField.input.readOnly = on;
    typeField.input.disabled = on;
    geoField.input.disabled = on;
    ctx.setBusy(on ? t('glb.progress') : false);
    syncRunBar();
  }

  /** The route params of a check (what a shared link runs), with the expected value judged against it. */
  function checkParams(check) {
    return { name: check.name, type: check.type, geo: check.geo ? null : '0', ...expectParams() };
  }

  /** Re-run: the check on screen again (its name, type and locations), not what the box holds now. */
  function rerunCheck() {
    if (current) {
      nameField.value = current.name;
      typeField.value = current.type;
      geoField.checked = current.geo;
    }
    start();
  }

  /** The names the box holds, as a check reads them (what a carried name may replace). */
  const boxNames = (text) => {
    const raw = String(text).trim();
    return [normalizeHostname(raw, { allowSingleLabel: true }) || raw];
  };

  /**
   * The name the box last took from a carried target: a newer one replaces it while the box still
   * holds it (lib/session.js fillReplaces). A re-mount keeps it (snapshot); a check forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null)
    : (isFillOnly(ctx.params) && initialName) || null;

  /**
   * A name carried over from another tool (`run=0`) goes into the box while it is empty or still
   * holds the finished check's name or the name carried before — never over a draft — and nothing
   * is queried; the check stays.
   */
  function takeCarried(name) {
    const last = current && !current.controller ? [current.name] : null;
    if (fillReplaces(nameField.value, last, boxNames, carried)) {
      nameField.value = name;
      nameField.setError(null);
      carried = name;
    }
  }

  /** Validate the form and run a new check. `auto`: a shared link's run on arrival (offline: no toast, see lookup.js). */
  async function start({ auto = false } = {}) {
    const raw = nameField.value.trim();
    nameField.setError(null);
    if (normalizeIP(raw)) {
      nameField.setError(t('glb.ipGiven'));
      nameField.focus();
      return;
    }
    const name = normalizeHostname(raw, { allowSingleLabel: true });
    if (!name) {
      nameField.setError(t('glb.invalidName'));
      nameField.focus();
      return;
    }
    nameField.value = name;
    carried = null;
    const type = GLOBAL_TYPES.includes(typeField.value) ? typeField.value : 'A';
    const geo = geoField.checked;
    if (!ctx.requireOnline({ quiet: auto })) return;
    // The expected value is read for the type this check asks (an exact value splits per type).
    expectedNow = readExpected(type);
    ctx.setParams({ name, type, geo: geo ? null : '0', ...expectParams() });
    ctx.runStarted(name);
    await runCheck(name, type, geo);
  }

  function stop() {
    if (current && current.controller) {
      current.cancelled = true;
      current.controller.abort();
    }
  }

  function prepare(name, type, geo) {
    if (current && current.controller) current.controller.abort();
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    const rows = makeRows(geo);
    current = {
      name, type, geo, rows, rowByKey: new Map(rows.map((r) => [r.key, r])), ips: new Map(), controller: null, done: false, cancelled: false,
      finishedAt: null, // when the check ended (the summary's time, the kept result's age)
      controls: [] // AliDNS's answers on behalf of a subnet outside China (lib/propagation.js)
    };
    filterKey = null;
    missingOnly = false;
    statusFilter = null;
    findingsOpen = false;
    groups = [];
    groupByKey = new Map();
    // The expected value for this check's type; the name server's answer belonged to the last one.
    expectedNow = readExpected(type);
    syncExpectedColumns();
    soaResult = null;
    if (soaPanel) soaPanel.reset();
    resolverTable.setFilter(null);
    geoTable.setFilter(null);
    chinaTable.setFilter(null);
    ipTable.setFilter(null);
    ipTable.setSearch('');
    clear(filterNote);
    filterNote.hidden = true;
    status.setPressed(null);
    resolverTable.setRows(rows.filter((r) => r.kind === 'resolver'));
    geoTable.setRows(rows.filter((r) => r.kind === 'geo' && !isChinaRow(r)));
    chinaTable.setRows(rows.filter(isChinaRow));
    ipTable.setRows([]);
    if (ispPanel) ispPanel.reset();
    geoSection.hidden = !geo;
    for (const o of Object.values(exportOpts)) o.subject = name;
    emptyWrap.hidden = true;
    results.hidden = false;
    actions.setDisabled(true);
  }

  async function runCheck(name, type, geo) {
    prepare(name, type, geo);
    const run = current;
    const controller = new AbortController();
    run.controller = controller;
    progress.setVariant('default');
    progress.setLabel(t('glb.progress'));
    progress.set(0, run.rows.length);
    setRunning(true);
    renderAll();
    try {
      const shared = await ctx.getDns();
      // A one-shot comparison: ask every source once, with a short timeout, so an unreachable
      // resolver costs seconds instead of two full app timeouts (a resolver unreachable from the
      // user's network: ~16 s → 5 s). Healthy DoH answers arrive well under 1.5 s (browser-doh-matrix).
      const dns = { query: (qname, qtype, opts = {}) => shared.query(qname, qtype, { ...opts, timeoutMs: QUERY_TIMEOUT_MS, retries: 0 }) };
      await checkPropagation(name, type, {
        dns,
        vantages: geo ? GEO_VANTAGES : [],
        signal: mergeSignals(ctx.signal, controller.signal),
        onResult: (item) => {
          if (current === run) applyItem(item);
        }
      });
      if (current !== run) return;
      run.done = true;
    } catch (err) {
      if (current !== run) return;
      if (!(err && err.name === 'AbortError')) {
        run.cancelled = true;
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
      if (ctx.signal.aborted) return;
    } finally {
      if (current === run) {
        run.controller = null;
        run.finishedAt = new Date();
        if (!ctx.signal.aborted) setRunning(false);
      }
    }
    if (ctx.signal.aborted || current !== run) return;
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    // The progress goes with the run (the result header's meta held it); the totals are said once.
    renderAll();
    syncRunBar();
  }

  /** Re-render a finished run kept across a language re-mount (no network). */
  function restore(snap) {
    prepare(snap.name, snap.type, snap.geo);
    // The ISP resolver rows of the check (ui/isp-resolvers.js) come back with their probes.
    const isp = snap.items.filter((item) => item.kind === 'isp');
    for (const item of isp) {
      const row = {
        kind: 'isp', key: item.key, isp: item.isp, ttl: item.ttl ?? null, expiresAt: item.expiresAt ?? null, status: item.status,
        resolver: null, vantage: null, pending: true, values: null, response: null, filtered: false, addresses: [], scopePrefix: null
      };
      current.rows.push(row);
      current.rowByKey.set(row.key, row);
    }
    if (isp.length || snap.isp) openIsp(snap.isp || null);
    // An answer kept from before keeps its time (its cached copy's countdown); an older snapshot's: the check's end.
    const endedAt = snap.at ? new Date(snap.at).getTime() : null;
    for (const item of [...snap.items, ...(Array.isArray(snap.controls) ? snap.controls : [])]) applyItem({ ...item, at: item.at ?? endedAt });
    current.done = !!snap.done;
    current.cancelled = !snap.done;
    current.finishedAt = snap.at ? new Date(snap.at) : new Date();
    // The name server's answer of this check (ui/soa-probe.js): shown again, nothing sent.
    if (snap.soa) openSoa(snap.soa);
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    // Shown again, not run: its totals were said when it ended.
    announcedFor = current;
    renderAll();
    syncRunBar();
  }

  /* --- initial state --------------------------------------------------------- */
  // An expected value from a link or a re-mount: its export column from the start.
  expectedNow = readExpected();
  syncExpectedColumns();
  // "Expires by 15:42 (in 25 minutes)" ages: the card is drawn again while a source is not there yet.
  const expTicker = setInterval(() => {
    if (current && !expectCard.hidden && expectCard.dataset.state === 'pending' && !current.controller) renderExpected();
  }, 30000);
  if (restored && Array.isArray(restored.items) && restored.items.length && restored.name) {
    restore(restored);
    // The kept check under a name carried over from another tool: the box takes the name.
    if (isFillOnly(ctx.params) && ctx.params.name) takeCarried(ctx.params.name);
  } else if (!restored && initialName && !isFillOnly(ctx.params)) {
    // Shared link: run immediately. A re-mounted draft (typed, never run) or a name carried over
    // from another tool (`run=0`) only fills the form.
    Promise.resolve().then(() => start({ auto: true }));
  }
  syncRunBar();

  active = {
    teardown() {
      if (renderTimer) clearTimeout(renderTimer);
      renderTimer = null;
      clearInterval(expTicker);
      if (current && current.controller) current.controller.abort();
      if (ispPanel) ispPanel.teardown();
      if (soaPanel) soaPanel.teardown();
    },
    snapshot() {
      const expect = { expect: expectField.value, match: matchField.value, expectHeld };
      if (!current) return { name: nameField.value, type: typeField.value, geo: geoField.checked, carried, ...expect };
      const items = current.rows.filter((r) => !r.pending).map((r) => ({
        key: r.key, response: r.response, values: r.values, filtered: r.filtered, addresses: r.addresses, scopePrefix: r.scopePrefix, notAsked: !!r.notAsked,
        at: r.at ?? null,
        ...(r.kind === 'isp' ? { kind: 'isp', isp: r.isp, ttl: r.ttl, expiresAt: r.expiresAt, status: r.status } : {})
      }));
      return {
        name: current.name, type: current.type, geo: current.geo, items, controls: current.controls, done: current.done, at: current.finishedAt,
        draft: nameField.value, carried, isp: ispPanel ? ispPanel.snapshot() : null, soa: soaPanel ? soaPanel.snapshot() : null, tab: tabNow, ...expect
      };
    },
    result() {
      if (!current || current.controller || !current.finishedAt || !current.rows.some((r) => !r.pending)) return null;
      // Its note sits in the result header and offers "Run again": the same name, type and locations.
      return { subject: current.name, at: current.finishedAt, params: checkParams(current) };
    },
    rerun() {
      rerunCheck();
    },
    update(params) {
      const name = params.name || '';
      if (!name) return false;
      if (isFillOnly(params)) {
        takeCarried(name);
        return true;
      }
      nameField.value = name;
      const type = String(params.type || 'A').toUpperCase();
      typeField.value = GLOBAL_TYPES.includes(type) ? type : 'A';
      geoField.checked = params.geo !== '0';
      // A link's expected value replaces the fields' (a link without one clears them); its regex is held.
      expectField.value = params.expect || '';
      matchField.value = EXPECT_MODES.includes(params.match) ? params.match : 'exact';
      expectHeld = matchField.value === 'regex' && !!String(expectField.value).trim();
      start();
      return true;
    }
  };
}

/** Abort a running check and drop timers. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * State carried over a language re-mount and kept for the next visit: the query and the answers
 * received (no re-query).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The finished (or stopped) check on screen (kept by the shell when the view is left), or null.
 * Its note ("Result from …") sits in the result header and offers "Run again" ({@link rerun}).
 * @returns {{ subject: string, at: Date, params: Record<string, string> }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of a note whose result was too large to keep: the same name, type and locations again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take new route params (e.g. a pasted share link) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
