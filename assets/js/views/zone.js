/**
 * views/zone.js — "Zone File": import a DNS zone export (Cloudflare, Route 53, BIND, cPanel,
 * GoDaddy, octoDNS, Plesk…) and see every record, the mistakes in it, the real origin behind
 * each proxied name, the exact CLI sweep command and (on an explicit click) drift from live DNS.
 *
 * Privacy (zone spec D6 / D7):
 * - the file is read in the browser and kept in this module's memory only: nothing goes to
 *   localStorage / sessionStorage, and the route carries only `tab=`;
 * - nothing touches the network before a click: parsing, lint, the origin map and the command
 *   are offline; the live check runs only from its own button and sends names + types only;
 * - `state.session.zone` (in memory; cleared by "Delete all local data") is the scan input the
 *   Subdomains / SSL Targets views read; it is published only for a confirmed origin.
 *
 * Hand-off contracts (read by views/subdomains.js and views/scan.js):
 * - `state.session.zone` = zoneorigins.zoneScanInput(zone, { skipPrivate }) plus
 *   `{ label: string, counts: { names, origins, skipped } }`;
 * - `state.session.zoneScanIntent` (one-shot) = `{ v: 1, target: 'subdomains'|'scan', domain,
 *   mode: 'exact'|'discover', autostart: boolean, at: Date.now() }`; exact mode = only the zone
 *   names as seeds (no passive sources, no wordlist, no permutations: quota-free).
 *
 * Pure helpers are exported for the unit tests (tests/js/zone-view.test.js); the module is
 * DOM-free at import time.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, DataTable, Disclosure, EmptyState, FileDrop, Icon, ProgressBar,
  SegmentedControl, SeverityIcon, Spinner, StatCard, Tabs, announce, checkbox, copyText, radioGroup, select,
  textInput, textarea, toast
} from '../ui/components.js';
import { downloadText } from '../ui/download.js';
import { formatBytes, formatNumber, registerStrings, t as tt } from '../i18n.js';
import {
  parseZone, mergeZones, detectZoneFormat, zoneNames, ZONE_FORMATS, ZONE_DIALECTS, ZONE_LIMITS, ISSUE_CODES,
  NOT_A_ZONE_HINTS
} from '../lib/zoneparse.js';
import { lintZone, LINT_RULES } from '../lib/zonelint.js';
import {
  proxiedOriginMap, addressMap, zoneSweep, handoffFiles, zoneScanInput, privateLookingNames, ORIGIN_KINDS,
  ZONE_NAMES_FILE, ZONE_TARGETS_FILE
} from '../lib/zoneorigins.js';
import { planDrift, driftZone, DRIFT_STATUSES, DRIFT_REASONS, DRIFT_SEVERITY } from '../lib/zonedrift.js';
import { buildSweepCommand, quoteArg } from '../lib/cmdline.js';
import { getResolver } from '../lib/resolvers.js';
import { normalizeIP } from '../lib/netinfo.js';

/** Route id. */
export const id = 'zone';
/** i18n key of the page title. */
export const titleKey = 'nav.zone';
/** Nav/page icon. */
export const icon = 'file-text';

/** Tabs of a parsed zone (the route carries only `tab=`). */
export const ZONE_TABS = Object.freeze(['overview', 'records', 'origins', 'problems', 'live']);
/** Record type filter groups of the Records tab. */
export const TYPE_GROUPS = Object.freeze(['all', 'addr', 'CNAME', 'MX', 'TXT', 'NS', 'other']);
/** Files accepted by the importer. */
const ACCEPT = '.txt,.zone,.db,.bind,.json,.yaml,.yml,.hosts';
/** At most this many files in one drop (critic B3). */
export const MAX_FILES = 20;
/** Label used for the CLI program per shell (same as the other views). */
const PYTHON = Object.freeze({ posix: 'python3', powershell: 'python' });
/** Placeholder written instead of an origin in exports. */
export const REDACTED = '[origin hidden]';

/* ------------------------------------------------------------------------ */
/* Samples (documentation data only: example.com, 192.0.2.0/24, 198.51.100.0/24) */
/* ------------------------------------------------------------------------ */

export const SAMPLES = Object.freeze([
  {
    id: 'cloudflare',
    file: 'example.com.txt',
    text: [
      ';;',
      ';; Domain:     example.com.',
      ';; Exported:   2026-09-24 08:00:00',
      ';;',
      ';; SOA Record',
      'example.com\t3600\tIN\tSOA\tada.ns.cloudflare.com. dns.cloudflare.com. 2051234567 10000 2400 604800 3600',
      ';; NS Records',
      'example.com.\t86400\tIN\tNS\tada.ns.cloudflare.com.',
      'example.com.\t86400\tIN\tNS\tbob.ns.cloudflare.com.',
      ';; A Records',
      'example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:true',
      'api.example.com.\t1\tIN\tA\t192.0.2.14 ; cf_tags=cf-proxied:true',
      'ftp.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
      'mail.example.com.\t1\tIN\tA\t198.51.100.25 ; cf_tags=cf-proxied:false',
      ';; CNAME Records',
      'www.example.com.\t1\tIN\tCNAME\texample.com. ; cf_tags=cf-proxied:true',
      'app.example.com.\t1\tIN\tCNAME\torigin-lb.example.net. ; cf_tags=cf-proxied:true',
      ';; MX Records',
      'example.com.\t1\tIN\tMX\t10 mail.example.com.',
      ';; TXT Records',
      'example.com.\t1\tIN\tTXT\t"v=spf1 ip4:192.0.2.10 mx -all"',
      ''
    ].join('\n')
  },
  {
    id: 'route53',
    file: 'example.com.json',
    text: `${JSON.stringify({
      ResourceRecordSets: [
        { Name: 'example.com.', Type: 'SOA', TTL: 900, ResourceRecords: [{ Value: 'ns-1.awsdns-01.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400' }] },
        { Name: 'example.com.', Type: 'NS', TTL: 172800, ResourceRecords: [{ Value: 'ns-1.awsdns-01.org.' }, { Value: 'ns-2.awsdns-02.co.uk.' }] },
        { Name: 'example.com.', Type: 'A', AliasTarget: { HostedZoneId: 'Z2FDTNDATAQYW2', DNSName: 'd111111abcdef8.cloudfront.net.', EvaluateTargetHealth: false } },
        { Name: 'www.example.com.', Type: 'CNAME', TTL: 300, ResourceRecords: [{ Value: 'example.com' }] },
        { Name: 'app.example.com.', Type: 'A', TTL: 60, ResourceRecords: [{ Value: '192.0.2.21' }, { Value: '192.0.2.22' }] },
        { Name: 'example.com.', Type: 'MX', TTL: 300, ResourceRecords: [{ Value: '10 mail.example.com.' }] },
        { Name: 'mail.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '198.51.100.25' }] }
      ]
    }, null, 2)}\n`
  },
  {
    id: 'bind',
    file: 'db.example.com',
    text: [
      '$ORIGIN example.com.',
      '$TTL 3600',
      '@\tIN\tSOA\tns1.example.com. hostmaster.example.com. ( 2026092401 7200 3600 1209600 3600 )',
      '@\tIN\tNS\tns1.example.com.',
      'ns1\tIN\tA\t198.51.100.53',
      '@\tIN\tA\t198.51.100.80',
      'www\tIN\tCNAME\t@',
      'www\tIN\tA\t198.51.100.80',
      'mail\tIN\tA\t198.51.100.25',
      '@\tIN\tMX\t10 mail.example.com',
      '@\tIN\tTXT\t"v=spf1 mx -all"',
      '@\tIN\tTXT\t"v=spf1 a -all"',
      'intranet\tIN\tA\t10.20.30.40',
      'shop.example.com\tIN\tA\t198.51.100.90',
      ''
    ].join('\n')
  }
]);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

const EN = {
  'zone.privacyTitle': 'Stays in this tab',
  'zone.privacy': 'Read in this browser and kept only in this tab’s memory — nothing is uploaded or saved. A reload forgets it. Only what you click sends anything: the live check, or a scan of these names, sends record names (never the file or its addresses) to your DNS resolvers.',
  'zone.import.title': 'Import a zone file',
  'zone.import.subtitle': 'Drop it, choose it or paste it — the format is detected',
  'zone.drop.title': 'Drop a zone export here, choose a file or paste it',
  'zone.drop.hint': 'BIND / Cloudflare export, Cloudflare API JSON, Route 53 JSON, octoDNS YAML, cPanel, GoDaddy, Plesk',
  'zone.paste.summary': '…or paste the text',
  'zone.paste.label': 'Zone file text',
  'zone.import': 'Import',
  'zone.origin.label': 'Zone (domain)',
  'zone.origin.placeholder': 'detected from the file',
  'zone.format.label': 'Format',
  'zone.format.auto': 'Detect automatically',
  'zone.origin.from.$ORIGIN': 'From $ORIGIN.',
  'zone.origin.from.header': 'Read from the file header — change it if it is wrong.',
  'zone.origin.from.soa': 'From the SOA record.',
  'zone.origin.from.filename': 'Taken from the file name — please check it.',
  'zone.origin.from.records': 'The most common domain in the file — please check it.',
  'zone.origin.from.user': 'Entered by you.',
  'zone.origin.guessed': 'The zone name was guessed — confirm it before scanning.',
  'zone.origin.confirm': 'Confirm',
  'zone.origin.required': 'This file uses relative names and has no $ORIGIN: enter the zone name.',
  'zone.samples': 'Try a sample:',
  'zone.sample.cloudflare': 'Cloudflare export',
  'zone.sample.route53': 'Route 53 JSON',
  'zone.sample.bind': 'BIND with mistakes',
  'zone.sampleBadge': 'Sample',
  'zone.howto': 'How do I export my zone?',
  'zone.howto.cloudflare': 'Cloudflare: Dashboard › DNS › Records › Import and Export › Export. API:',
  'zone.howto.route53': 'AWS Route 53 (no --max-items, so every page is fetched):',
  'zone.howto.panel': 'cPanel / WHM, DirectAdmin: /var/named/example.com.db (shell access). GoDaddy: Domain › DNS › Export Zone File.',
  'zone.howto.bind': 'BIND, PowerDNS, Azure, Google Cloud:',
  'zone.reading': 'Reading {size}…',
  'zone.tooManyFiles': 'At most {max} files at once.',
  'zone.sum.counts': '{records} records · {names} names · {proxied} proxied',
  'zone.sum.zone': 'Zone {origin}',
  'zone.sum.noOrigin': 'Zone (unknown)',
  'zone.sum.files': '{files} · {size}',
  'zone.forget': 'Forget',
  'zone.replace': 'Import another file or change the zone name',
  'zone.forgotten': 'Zone forgotten',
  'zone.imported': 'Zone {origin} imported: {records} records',
  'zone.internalZone': 'This looks like an internal zone ({private} of {total} addresses are private). Public resolvers do not know it: its names will show as missing, and checking sends them to public resolvers.',
  'zone.partial.title': 'This export is incomplete',
  'zone.format.bind': 'BIND zone file',
  'zone.format.cloudflare-api': 'Cloudflare API (JSON)',
  'zone.format.route53': 'AWS Route 53 (JSON)',
  'zone.format.octodns': 'octoDNS (YAML)',
  'zone.format.plesk-info': 'Plesk dns --info (unverified format)',
  'zone.dialect.cloudflare': 'Cloudflare export (BIND)',
  'zone.dialect.cpanel': 'cPanel',
  'zone.dialect.directadmin': 'DirectAdmin',
  'zone.dialect.godaddy': 'GoDaddy',
  'zone.dialect.cli53': 'cli53 (Route 53)',
  'zone.dialect.generic': 'BIND',
  'zone.tab.overview': 'Overview',
  'zone.tab.records': 'Records',
  'zone.tab.origins': 'Origins & servers',
  'zone.tab.problems': 'Problems',
  'zone.tab.live': 'Live check',
  'zone.stat.names': 'Names',
  'zone.stat.proxied': 'Proxied',
  'zone.stat.dnsOnly': 'DNS only',
  'zone.stat.origins': 'Exact origins',
  'zone.stat.errors': 'Errors',
  'zone.stat.warnings': 'Warnings',
  'zone.next.title': 'Next steps',
  'zone.next.sweep.title': 'Sweep the real origins from inside your network',
  'zone.next.sweep.body': '{names} proxied names → {targets} origin addresses taken from your file. No guessing.',
  'zone.next.sweep.none': 'No proxied records with an origin: map every name to its server from inside your network instead.',
  'zone.next.sweep.open': 'Show the command',
  'zone.next.discover.title': 'Scan these names',
  'zone.next.discover.legend': 'What to scan',
  'zone.next.discover.exact': 'Only these names (no guessing, no passive sources, no quota)',
  'zone.next.discover.full': 'These names + discovery',
  'zone.next.discover.note': 'Discovery uses your passive sources (quota) and wordlist settings from Subdomains, and sends every zone name to your DNS resolvers.',
  'zone.next.skipInternal': 'Leave out names that look internal ({count})',
  'zone.next.run': 'Scan now',
  'zone.next.needOrigin': 'Confirm the zone name first.',
  'zone.next.cert.title': 'Find where the new certificate goes',
  'zone.next.cert.body': 'Opens SSL Targets for {origin} with these names; nothing starts until you press Run.',
  'zone.next.cert.run': 'Find certificate targets',
  'zone.next.drift.title': 'Compare with live DNS',
  'zone.next.drift.body': 'About {queries} DNS queries, only after you press Check.',
  'zone.next.drift.open': 'Open the live check',
  'zone.top.title': 'Top problems',
  'zone.top.all': 'See all problems',
  'zone.records.filter': 'Record type',
  'zone.records.all': 'All',
  'zone.records.addr': 'A/AAAA',
  'zone.records.other': 'Other',
  'zone.records.proxiedOnly': 'Proxied only',
  'zone.records.search': 'Search names, values, comments',
  'zone.records.copyNames': 'Copy names',
  'zone.records.namesCopied': '{count} names copied',
  'zone.col.line': 'Line',
  'zone.col.name': 'Name',
  'zone.col.type': 'Type',
  'zone.col.ttl': 'TTL',
  'zone.col.value': 'Value',
  'zone.col.proxy': 'Proxy',
  'zone.col.notes': 'Notes',
  'zone.col.origin': 'Origin (from your file)',
  'zone.col.kind': 'Kind',
  'zone.col.server': 'Your server',
  'zone.col.exposure': 'Exposure',
  'zone.col.ip': 'Address',
  'zone.col.names': 'Names',
  'zone.col.status': 'Status',
  'zone.col.file': 'In the file',
  'zone.col.live': 'Live',
  'zone.col.note': 'Note',
  'zone.ttl.auto': 'Auto',
  'zone.ttl.autoTitle': 'Cloudflare “Auto” = 300 s',
  'zone.proxy.on': 'Proxied',
  'zone.proxy.off': 'DNS only',
  'zone.note.alias': 'alias → {target}',
  'zone.note.routing': 'routing: {policy}',
  'zone.note.flattened': 'flattened',
  'zone.note.generated': 'generated',
  'zone.note.duplicate': 'duplicate',
  'zone.note.invalid': 'invalid',
  'zone.note.intended': 'served as {served}; probably meant {intended}',
  'zone.detail.comment': 'Comment',
  'zone.detail.tags': 'Tags',
  'zone.origins.privacy': 'These are the addresses Cloudflare hides from the internet. They stay in this browser; whatever you copy or download contains them.',
  'zone.origins.lead': 'For a proxied (orange-cloud) record the zone holds the real origin that public DNS hides. These are exact, with no guessing.',
  'zone.origins.title': 'Behind Cloudflare',
  'zone.origins.none': 'No proxied records in this file.',
  'zone.origins.addTitle': 'By address',
  'zone.origins.addSubtitle': 'Every address in the file and the names that use it',
  'zone.origins.addServers': 'Add your servers',
  'zone.kind.ip': 'Origin IP',
  'zone.kind.host': 'Origin host (resolved inside your network)',
  'zone.kind.tunnel': 'Cloudflare Tunnel — no inbound origin',
  'zone.kind.provider': 'Hosted by {provider}; its certificate is managed there',
  'zone.kind.placeholder': 'Placeholder (Worker or redirect) — no server',
  'zone.kind.cloudflare-ip': 'Points at a Cloudflare address — Cloudflare refuses this (error 1000)',
  'zone.kind.unresolved': 'Target not in the file',
  'zone.kind.loop': 'CNAME loop',
  'zone.origin.via': 'via {name}',
  'zone.origin.private': 'private — reachable only inside your network',
  'zone.exposed.sibling': 'published by DNS-only {name}',
  'zone.exposed.spf': 'listed in the SPF of {name}',
  'zone.exposed.mx': 'published by mail host {name}',
  'zone.addr.private': 'private',
  'zone.addr.placeholder': 'placeholder',
  'zone.addr.cloudflare': 'Cloudflare',
  'zone.addr.exposed': 'exposed',
  'zone.sweep.title': 'Sweep from inside your network',
  'zone.sweep.subtitle': 'Exact addresses from your file — never widened to a /24',
  'zone.sweep.scope': 'Scope',
  'zone.sweep.scope.proxied': 'Proxied names and their origins',
  'zone.sweep.scope.all': 'Every name and every address',
  'zone.sweep.shell': 'Shell',
  'zone.sweep.posix': 'Linux / macOS',
  'zone.sweep.powershell': 'PowerShell',
  'zone.sweep.estimate': '{names} SNI names × {targets} targets = {probes} TLS handshakes per port',
  'zone.sweep.estimateAtLeast': '{names} SNI names × {targets} targets = at least {probes} TLS handshakes per port',
  'zone.sweep.fileForm': 'Too long to paste: download the two files and run',
  'zone.sweep.many': 'That is a lot of handshakes: narrow the scope or raise --workers.',
  'zone.sweep.skipped': 'Skipped: {list}',
  'zone.sweep.empty': 'Nothing to sweep in this scope.',
  'zone.sweep.namesFile': 'zone-names.txt',
  'zone.sweep.targetsFile': 'zone-targets.txt',
  'zone.sweep.script': 'Download ssl_origin_scan.py',
  'zone.problems.none': 'No problems found in this zone.',
  'zone.problems.copy': 'Copy as text',
  'zone.problems.copied': 'Problems copied',
  'zone.problems.filter': 'Severity',
  'zone.problems.all': 'All',
  'zone.problems.errors': 'Errors',
  'zone.problems.warnings': 'Warnings',
  'zone.problems.info': 'Info',
  'zone.problems.line': 'line {line}',
  'zone.problems.show': 'Show in Records',
  'zone.live.title': 'Compare with live DNS',
  'zone.live.lead': '{rrsets} record sets → {queries} DNS queries through {resolvers}.',
  'zone.live.sent': 'Only names and record types go to these resolvers. The values in the file and the origin addresses stay here; the hidden targets of proxied, flattened and alias records are never queried.',
  'zone.live.skipPrivate': 'Skip names that look internal ({count})',
  'zone.live.wildcards': 'Probe wildcard records',
  'zone.live.budget': 'The first {max} queries are checked; the rest are marked skipped.',
  'zone.live.run': 'Check {rrsets} record sets',
  'zone.live.rerun': 'Re-run',
  'zone.live.cancel': 'Cancel',
  'zone.live.progress': '{done} / {total} record sets',
  'zone.live.stopped': 'Stopped: {done} of {total} record sets checked',
  'zone.live.failed': 'The live check failed: {message}',
  'zone.live.finished': 'Live check finished: {count} differences',
  'zone.live.soaNewer': 'Live serial {live} is newer than the file’s {file}: this export predates the latest change.',
  'zone.live.nsDisjoint': 'The name servers in this file are not the live ones: the export may come from a provider that is not authoritative any more.',
  'zone.live.noOrigin': 'The zone {origin} does not exist in public DNS (NXDOMAIN).',
  'zone.live.includeOrigins': 'Include origin addresses in exports',
  'zone.live.allStatuses': 'All',
  'zone.live.needOrigin': 'Confirm the zone name first: the live check queries names under it.',
  'zone.drift.match': 'Matches',
  'zone.drift.differs': 'Differs',
  'zone.drift.missing-live': 'Not live',
  'zone.drift.proxied-ok': 'Proxied, origin hidden',
  'zone.drift.origin-exposed': 'Origin exposed: proxy is off',
  'zone.drift.flattened-ok': 'Flattened as expected',
  'zone.drift.alias-ok': 'Alias resolves',
  'zone.drift.routing-ok': 'One routing variant seen',
  'zone.drift.occluded': 'Hidden by a delegation',
  'zone.drift.skipped': 'Skipped',
  'zone.drift.error': 'Could not check',
  'zone.reason.values': 'Values differ.',
  'zone.reason.nxdomain': 'The name does not exist live (NXDOMAIN).',
  'zone.reason.nodata': 'The name exists live but has no record of this type.',
  'zone.reason.cname-live': 'Live DNS answers with a CNAME instead.',
  'zone.reason.proxy-on-live': 'The file says DNS-only, but live answers are Cloudflare addresses. Was the proxy switched on after the export?',
  'zone.reason.proxy-off-live': 'Live DNS returns the origin itself: the proxy is off, so the server is reachable directly.',
  'zone.reason.not-cloudflare': 'Proxied in the file, but live answers are not Cloudflare addresses (BYOIP?).',
  'zone.reason.flatten-mismatch': 'The flattened answer does not match the CNAME target.',
  'zone.reason.alias-disjoint': 'The alias target and the name answer different addresses.',
  'zone.reason.routing-outside': 'The live answer is none of the routing variants in the file.',
  'zone.reason.wildcard': 'Checked through a random name under the wildcard.',
  'zone.reason.servfail': 'The resolver answered SERVFAIL.',
  'zone.reason.refused': 'The resolver refused the query.',
  'zone.reason.transport': 'The resolver could not be reached.',
  'zone.reason.timeout': 'The query timed out.',
  'zone.reason.budget': 'Query budget reached.',
  'zone.reason.private': 'Skipped: looks internal.',
  'zone.reason.unsupported-type': 'This record type cannot be compared.',
  'zone.reason.dnssec-type': 'DNSSEC records are signed live, not compared.',
  'zone.reason.escaped-name': 'The name holds characters that cannot be queried.',
  'zone.reason.cf-synthesized': 'Added by Cloudflare automatically.',
  'zone.reason.txt-chunking': 'Same text, split into strings differently.',
  'zone.reason.ttl-stale': 'Live TTL is longer than the file’s: resolvers still cache an older TTL.',
  'zone.reason.placeholder': 'Placeholder: no server behind this record.',
  'zone.reason.tunnel': 'Cloudflare Tunnel.',
  'zone.reason.provider': 'Hosted by a third party.',
  'zone.reason.cf-caa-added': 'Cloudflare adds CAA records for its CAs automatically.',
  'zone.reason.alias-rotating': 'The AWS service rotates its addresses.',
  'zone.reason.filtered': 'A filtering resolver blocked the answer.',
  'zone.reason.target-hidden': 'The target is hidden like an origin and was not queried.',
  'zone.reason.out-of-zone': 'Outside the zone: name servers ignore it, so it was not queried.',
  'zone.fatal.title': 'This file could not be read',
  'zone.fatal.EMPTY': 'The file is empty.',
  'zone.fatal.TOO_LARGE': 'The file is too large. Export one zone at a time.',
  'zone.fatal.NOT_TEXT': 'This is not a text file (or it is UTF-16 without a byte-order mark).',
  'zone.fatal.NOT_A_ZONE': 'This does not look like a DNS zone export.',
  'zone.fatal.INVALID_JSON': 'This looks like JSON but cannot be read.',
  'zone.fatal.UNSUPPORTED_JSON': 'This JSON is neither a Route 53 nor a Cloudflare record listing.',
  'zone.fatal.YAML_UNSUPPORTED': 'This YAML uses a feature that is not supported. Use octodns-dump to get a flat file.',
  'zone.fatal.ORIGIN_REQUIRED': 'Enter the zone name: this file uses relative names.',
  'zone.fatal.ORIGIN_MISMATCH': 'These files belong to different zones ({origins}). Import one zone at a time.',
  'zone.fatal.API_ERROR': 'This is a Cloudflare API error, not a record listing. Check the API token and try again.',
  'zone.fatal.hint.pem': 'It is a certificate. Open it in Certificate.',
  'zone.fatal.hint.html': 'It is a web page. Save the export itself, not the page around it.',
  'zone.fatal.hint.gzip': 'It is compressed. Unzip it first.',
  'zone.fatal.hint.csv': 'It looks like a server list. Open it in Servers.',
  'zone.fatal.hint.dns-csv': 'It is a CSV listing of records. Export the zone as a BIND file instead.',
  'zone.fatal.hint.inventory': 'It looks like a server list. Open it in Servers.',
  'zone.fatal.hint.names': 'It is a list of names. Use Bulk Resolve for it.',
  'zone.fatal.hint.aws-output-json': 'Run the AWS CLI with --output json.',
  'zone.fatal.hint.unknown': 'Check that you exported the zone as a file.'
};

const TR = {
  'zone.privacyTitle': 'Bu sekmede kalır',
  'zone.privacy': 'Bu tarayıcıda okunur ve yalnızca bu sekmenin belleğinde tutulur — hiçbir şey yüklenmez ya da kaydedilmez. Sayfayı yenilemek onu unutturur. Yalnızca tıkladığınız işlemler bir şey gönderir: canlı kontrol ya da bu adların taranması, kayıt adlarını (dosyayı ya da içindeki adresleri asla) DNS çözümleyicilerinize gönderir.',
  'zone.import.title': 'Zone dosyası içe aktar',
  'zone.import.subtitle': 'Bırakın, seçin ya da yapıştırın — biçim otomatik algılanır',
  'zone.drop.title': 'Zone dışa aktarımını buraya bırakın, dosya seçin ya da yapıştırın',
  'zone.drop.hint': 'BIND / Cloudflare dışa aktarımı, Cloudflare API JSON, Route 53 JSON, octoDNS YAML, cPanel, GoDaddy, Plesk',
  'zone.paste.summary': '…ya da metni yapıştırın',
  'zone.paste.label': 'Zone dosyası metni',
  'zone.import': 'İçe aktar',
  'zone.origin.label': 'Zone (alan adı)',
  'zone.origin.placeholder': 'dosyadan algılanır',
  'zone.format.label': 'Biçim',
  'zone.format.auto': 'Otomatik algıla',
  'zone.origin.from.$ORIGIN': '$ORIGIN satırından.',
  'zone.origin.from.header': 'Dosya başlığından okundu — yanlışsa değiştirin.',
  'zone.origin.from.soa': 'SOA kaydından.',
  'zone.origin.from.filename': 'Dosya adından alındı — lütfen kontrol edin.',
  'zone.origin.from.records': 'Dosyada en sık geçen alan adı — lütfen kontrol edin.',
  'zone.origin.from.user': 'Sizin girdiğiniz.',
  'zone.origin.guessed': 'Zone adı tahmin edildi — taramadan önce onaylayın.',
  'zone.origin.confirm': 'Onayla',
  'zone.origin.required': 'Bu dosya göreli adlar kullanıyor ve $ORIGIN içermiyor: zone adını girin.',
  'zone.samples': 'Örnek deneyin:',
  'zone.sample.cloudflare': 'Cloudflare dışa aktarımı',
  'zone.sample.route53': 'Route 53 JSON',
  'zone.sample.bind': 'Hatalı BIND',
  'zone.sampleBadge': 'Örnek',
  'zone.howto': 'Zone’umu nasıl dışa aktarırım?',
  'zone.howto.cloudflare': 'Cloudflare: Pano › DNS › Kayıtlar › İçe ve Dışa Aktar › Dışa Aktar. API:',
  'zone.howto.route53': 'AWS Route 53 (--max-items olmadan; tüm sayfalar gelir):',
  'zone.howto.panel': 'cPanel / WHM, DirectAdmin: /var/named/example.com.db (kabuk erişimi). GoDaddy: Alan adı › DNS › Zone Dosyasını Dışa Aktar.',
  'zone.howto.bind': 'BIND, PowerDNS, Azure, Google Cloud:',
  'zone.reading': '{size} okunuyor…',
  'zone.tooManyFiles': 'Tek seferde en fazla {max} dosya.',
  'zone.sum.counts': '{records} kayıt · {names} ad · {proxied} proxy’li',
  'zone.sum.zone': '{origin} zone’u',
  'zone.sum.noOrigin': 'Zone (bilinmiyor)',
  'zone.sum.files': '{files} · {size}',
  'zone.forget': 'Unut',
  'zone.replace': 'Başka dosya içe aktar ya da zone adını değiştir',
  'zone.forgotten': 'Zone unutuldu',
  'zone.imported': '{origin} zone’u içe aktarıldı: {records} kayıt',
  'zone.internalZone': 'Bu bir iç zone’a benziyor ({total} adresin {private} tanesi özel). Genel çözümleyiciler onu bilmez: adları “canlıda yok” görünür ve kontrol, bu adları genel çözümleyicilere gönderir.',
  'zone.partial.title': 'Bu dışa aktarım eksik',
  'zone.format.bind': 'BIND zone dosyası',
  'zone.format.cloudflare-api': 'Cloudflare API (JSON)',
  'zone.format.route53': 'AWS Route 53 (JSON)',
  'zone.format.octodns': 'octoDNS (YAML)',
  'zone.format.plesk-info': 'Plesk dns --info (doğrulanmamış biçim)',
  'zone.dialect.cloudflare': 'Cloudflare dışa aktarımı (BIND)',
  'zone.dialect.cpanel': 'cPanel',
  'zone.dialect.directadmin': 'DirectAdmin',
  'zone.dialect.godaddy': 'GoDaddy',
  'zone.dialect.cli53': 'cli53 (Route 53)',
  'zone.dialect.generic': 'BIND',
  'zone.tab.overview': 'Genel bakış',
  'zone.tab.records': 'Kayıtlar',
  'zone.tab.origins': 'Origin’ler ve sunucular',
  'zone.tab.problems': 'Sorunlar',
  'zone.tab.live': 'Canlı kontrol',
  'zone.stat.names': 'Adlar',
  'zone.stat.proxied': 'Proxy’li',
  'zone.stat.dnsOnly': 'Yalnızca DNS',
  'zone.stat.origins': 'Kesin origin’ler',
  'zone.stat.errors': 'Hatalar',
  'zone.stat.warnings': 'Uyarılar',
  'zone.next.title': 'Sonraki adımlar',
  'zone.next.sweep.title': 'Gerçek origin sunucuları ağınızın içinden tarayın',
  'zone.next.sweep.body': '{names} proxy’li ad → dosyanızdan alınan {targets} origin adresi. Tahmin yok.',
  'zone.next.sweep.none': 'Origin’i olan proxy’li kayıt yok: bunun yerine tüm adları ağınızın içinden sunucularına eşleyin.',
  'zone.next.sweep.open': 'Komutu göster',
  'zone.next.discover.title': 'Bu adları tarayın',
  'zone.next.discover.legend': 'Ne taransın',
  'zone.next.discover.exact': 'Yalnızca bu adlar (tahmin yok, pasif kaynak yok, kota yok)',
  'zone.next.discover.full': 'Bu adlar + keşif',
  'zone.next.discover.note': 'Keşif, Subdomain Tarama’daki pasif kaynaklarınızı (kota) ve kelime listesi ayarlarınızı kullanır ve tüm zone adlarını DNS çözümleyicilerinize gönderir.',
  'zone.next.skipInternal': 'İç ağa ait görünen adları dışarıda bırak ({count})',
  'zone.next.run': 'Şimdi tara',
  'zone.next.needOrigin': 'Önce zone adını onaylayın.',
  'zone.next.cert.title': 'Yeni sertifikanın nereye kurulacağını bulun',
  'zone.next.cert.body': '{origin} için SSL Hedefleri’ni bu adlarla açar; Çalıştır’a basana kadar hiçbir şey başlamaz.',
  'zone.next.cert.run': 'Sertifika hedeflerini bul',
  'zone.next.drift.title': 'Canlı DNS ile karşılaştırın',
  'zone.next.drift.body': 'Yaklaşık {queries} DNS sorgusu, yalnızca Kontrol et’e bastıktan sonra.',
  'zone.next.drift.open': 'Canlı kontrolü aç',
  'zone.top.title': 'Öne çıkan sorunlar',
  'zone.top.all': 'Tüm sorunları gör',
  'zone.records.filter': 'Kayıt türü',
  'zone.records.all': 'Tümü',
  'zone.records.addr': 'A/AAAA',
  'zone.records.other': 'Diğer',
  'zone.records.proxiedOnly': 'Yalnızca proxy’li',
  'zone.records.search': 'Ad, değer ve yorumlarda ara',
  'zone.records.copyNames': 'Adları kopyala',
  'zone.records.namesCopied': '{count} ad kopyalandı',
  'zone.col.line': 'Satır',
  'zone.col.name': 'Ad',
  'zone.col.type': 'Tür',
  'zone.col.ttl': 'TTL',
  'zone.col.value': 'Değer',
  'zone.col.proxy': 'Proxy',
  'zone.col.notes': 'Notlar',
  'zone.col.origin': 'Origin (dosyanızdan)',
  'zone.col.kind': 'Tür',
  'zone.col.server': 'Sunucunuz',
  'zone.col.exposure': 'Açıkta mı',
  'zone.col.ip': 'Adres',
  'zone.col.names': 'Adlar',
  'zone.col.status': 'Durum',
  'zone.col.file': 'Dosyada',
  'zone.col.live': 'Canlı',
  'zone.col.note': 'Not',
  'zone.ttl.auto': 'Otomatik',
  'zone.ttl.autoTitle': 'Cloudflare “Otomatik” = 300 sn',
  'zone.proxy.on': 'Proxy’li',
  'zone.proxy.off': 'Yalnızca DNS',
  'zone.note.alias': 'alias → {target}',
  'zone.note.routing': 'yönlendirme: {policy}',
  'zone.note.flattened': 'düzleştirilmiş',
  'zone.note.generated': 'üretilmiş',
  'zone.note.duplicate': 'yinelenen',
  'zone.note.invalid': 'geçersiz',
  'zone.note.intended': '{served} olarak sunuluyor; büyük olasılıkla {intended} kastedildi',
  'zone.detail.comment': 'Yorum',
  'zone.detail.tags': 'Etiketler',
  'zone.origins.privacy': 'Bunlar Cloudflare’in internetten gizlediği adresler. Bu tarayıcıda kalırlar; kopyaladığınız ya da indirdiğiniz her şey onları içerir.',
  'zone.origins.lead': 'Proxy’li (turuncu bulut) bir kaydın zone’daki değeri, genel DNS’in gizlediği gerçek origin’dir. Bunlar kesindir, tahmin içermez.',
  'zone.origins.title': 'Cloudflare arkasında',
  'zone.origins.none': 'Bu dosyada proxy’li kayıt yok.',
  'zone.origins.addTitle': 'Adrese göre',
  'zone.origins.addSubtitle': 'Dosyadaki her adres ve onu kullanan adlar',
  'zone.origins.addServers': 'Sunucularınızı ekleyin',
  'zone.kind.ip': 'Origin IP',
  'zone.kind.host': 'Origin host’u (ağınızın içinde çözümlenir)',
  'zone.kind.tunnel': 'Cloudflare Tunnel — dışarıdan erişilen origin yok',
  'zone.kind.provider': '{provider} üzerinde barındırılıyor; sertifikası orada yönetilir',
  'zone.kind.placeholder': 'Yer tutucu (Worker ya da yönlendirme) — sunucu yok',
  'zone.kind.cloudflare-ip': 'Bir Cloudflare adresine işaret ediyor — Cloudflare bunu reddeder (hata 1000)',
  'zone.kind.unresolved': 'Hedef dosyada yok',
  'zone.kind.loop': 'CNAME döngüsü',
  'zone.origin.via': '{name} üzerinden',
  'zone.origin.private': 'özel — yalnızca ağınızın içinden erişilebilir',
  'zone.exposed.sibling': 'yalnızca DNS olan {name} yayımlıyor',
  'zone.exposed.spf': '{name} SPF kaydında listeleniyor',
  'zone.exposed.mx': '{name} e-posta sunucusu yayımlıyor',
  'zone.addr.private': 'özel',
  'zone.addr.placeholder': 'yer tutucu',
  'zone.addr.cloudflare': 'Cloudflare',
  'zone.addr.exposed': 'açıkta',
  'zone.sweep.title': 'Ağınızın içinden tarayın',
  'zone.sweep.subtitle': 'Dosyanızdaki kesin adresler — asla /24’e genişletilmez',
  'zone.sweep.scope': 'Kapsam',
  'zone.sweep.scope.proxied': 'Proxy’li adlar ve origin’leri',
  'zone.sweep.scope.all': 'Tüm adlar ve tüm adresler',
  'zone.sweep.shell': 'Kabuk',
  'zone.sweep.posix': 'Linux / macOS',
  'zone.sweep.powershell': 'PowerShell',
  'zone.sweep.estimate': '{names} SNI adı × {targets} hedef = port başına {probes} TLS el sıkışması',
  'zone.sweep.estimateAtLeast': '{names} SNI adı × {targets} hedef = port başına en az {probes} TLS el sıkışması',
  'zone.sweep.fileForm': 'Yapıştırmak için çok uzun: iki dosyayı indirip şunu çalıştırın',
  'zone.sweep.many': 'Bu çok sayıda el sıkışması demek: kapsamı daraltın ya da --workers değerini artırın.',
  'zone.sweep.skipped': 'Atlananlar: {list}',
  'zone.sweep.empty': 'Bu kapsamda taranacak bir şey yok.',
  'zone.sweep.namesFile': 'zone-names.txt',
  'zone.sweep.targetsFile': 'zone-targets.txt',
  'zone.sweep.script': 'ssl_origin_scan.py dosyasını indir',
  'zone.problems.none': 'Bu zone’da sorun bulunmadı.',
  'zone.problems.copy': 'Metin olarak kopyala',
  'zone.problems.copied': 'Sorunlar kopyalandı',
  'zone.problems.filter': 'Önem',
  'zone.problems.all': 'Tümü',
  'zone.problems.errors': 'Hatalar',
  'zone.problems.warnings': 'Uyarılar',
  'zone.problems.info': 'Bilgi',
  'zone.problems.line': 'satır {line}',
  'zone.problems.show': 'Kayıtlarda göster',
  'zone.live.title': 'Canlı DNS ile karşılaştırın',
  'zone.live.lead': '{rrsets} kayıt kümesi → {resolvers} üzerinden {queries} DNS sorgusu.',
  'zone.live.sent': 'Bu çözümleyicilere yalnızca adlar ve kayıt türleri gider. Dosyadaki değerler ve origin adresleri burada kalır; proxy’li, düzleştirilmiş ve alias kayıtların gizli hedefleri hiç sorgulanmaz.',
  'zone.live.skipPrivate': 'İç ağa ait görünen adları atla ({count})',
  'zone.live.wildcards': 'Joker kayıtları yokla',
  'zone.live.budget': 'İlk {max} sorgu kontrol edilir; kalanlar atlandı olarak işaretlenir.',
  'zone.live.run': '{rrsets} kayıt kümesini kontrol et',
  'zone.live.rerun': 'Yeniden çalıştır',
  'zone.live.cancel': 'İptal',
  'zone.live.progress': '{done} / {total} kayıt kümesi',
  'zone.live.stopped': 'Durduruldu: {total} kayıt kümesinin {done} tanesi kontrol edildi',
  'zone.live.failed': 'Canlı kontrol başarısız oldu: {message}',
  'zone.live.finished': 'Canlı kontrol bitti: {count} fark',
  'zone.live.soaNewer': 'Canlı seri numarası {live}, dosyadaki {file} değerinden yeni: bu dışa aktarım son değişiklikten önce alınmış.',
  'zone.live.nsDisjoint': 'Bu dosyadaki ad sunucuları canlıdakiler değil: dışa aktarım artık yetkili olmayan bir sağlayıcıdan alınmış olabilir.',
  'zone.live.noOrigin': '{origin} zone’u genel DNS’te yok (NXDOMAIN).',
  'zone.live.includeOrigins': 'Dışa aktarımlara origin adreslerini ekle',
  'zone.live.allStatuses': 'Tümü',
  'zone.live.needOrigin': 'Önce zone adını onaylayın: canlı kontrol onun altındaki adları sorgular.',
  'zone.drift.match': 'Eşleşiyor',
  'zone.drift.differs': 'Farklı',
  'zone.drift.missing-live': 'Canlıda yok',
  'zone.drift.proxied-ok': 'Proxy’li, origin gizli',
  'zone.drift.origin-exposed': 'Origin açıkta: proxy kapalı',
  'zone.drift.flattened-ok': 'Beklendiği gibi düzleştirilmiş',
  'zone.drift.alias-ok': 'Alias çözümleniyor',
  'zone.drift.routing-ok': 'Bir yönlendirme varyantı görüldü',
  'zone.drift.occluded': 'Yetki devri nedeniyle görünmez',
  'zone.drift.skipped': 'Atlandı',
  'zone.drift.error': 'Kontrol edilemedi',
  'zone.reason.values': 'Değerler farklı.',
  'zone.reason.nxdomain': 'Ad canlıda yok (NXDOMAIN).',
  'zone.reason.nodata': 'Ad canlıda var ama bu türde kaydı yok.',
  'zone.reason.cname-live': 'Canlı DNS bunun yerine bir CNAME ile yanıt veriyor.',
  'zone.reason.proxy-on-live': 'Dosyada yalnızca DNS yazıyor, ama canlı yanıtlar Cloudflare adresleri. Proxy dışa aktarımdan sonra mı açıldı?',
  'zone.reason.proxy-off-live': 'Canlı DNS origin’in kendisini döndürüyor: proxy kapalı, sunucuya doğrudan erişilebilir.',
  'zone.reason.not-cloudflare': 'Dosyada proxy’li, ama canlı yanıtlar Cloudflare adresleri değil (BYOIP?).',
  'zone.reason.flatten-mismatch': 'Düzleştirilmiş yanıt CNAME hedefiyle eşleşmiyor.',
  'zone.reason.alias-disjoint': 'Alias hedefi ile ad farklı adresler döndürüyor.',
  'zone.reason.routing-outside': 'Canlı yanıt dosyadaki yönlendirme varyantlarının hiçbiri değil.',
  'zone.reason.wildcard': 'Joker kaydın altındaki rastgele bir adla kontrol edildi.',
  'zone.reason.servfail': 'Çözümleyici SERVFAIL döndürdü.',
  'zone.reason.refused': 'Çözümleyici sorguyu reddetti.',
  'zone.reason.transport': 'Çözümleyiciye ulaşılamadı.',
  'zone.reason.timeout': 'Sorgu zaman aşımına uğradı.',
  'zone.reason.budget': 'Sorgu bütçesi doldu.',
  'zone.reason.private': 'Atlandı: iç ağa ait görünüyor.',
  'zone.reason.unsupported-type': 'Bu kayıt türü karşılaştırılamaz.',
  'zone.reason.dnssec-type': 'DNSSEC kayıtları canlıda imzalanır, karşılaştırılmaz.',
  'zone.reason.escaped-name': 'Ad sorgulanamayan karakterler içeriyor.',
  'zone.reason.cf-synthesized': 'Cloudflare tarafından otomatik eklenir.',
  'zone.reason.txt-chunking': 'Aynı metin, dizelere farklı bölünmüş.',
  'zone.reason.ttl-stale': 'Canlı TTL dosyadakinden uzun: çözümleyiciler hâlâ eski bir TTL’i önbellekte tutuyor.',
  'zone.reason.placeholder': 'Yer tutucu: bu kaydın arkasında sunucu yok.',
  'zone.reason.tunnel': 'Cloudflare Tunnel.',
  'zone.reason.provider': 'Üçüncü tarafta barındırılıyor.',
  'zone.reason.cf-caa-added': 'Cloudflare, kendi CA’ları için CAA kayıtlarını otomatik ekler.',
  'zone.reason.alias-rotating': 'AWS hizmeti adreslerini döndürüyor.',
  'zone.reason.filtered': 'Filtreleyen bir çözümleyici yanıtı engelledi.',
  'zone.reason.target-hidden': 'Hedef bir origin gibi gizli; sorgulanmadı.',
  'zone.reason.out-of-zone': 'Zone dışında: ad sunucuları onu yok sayar, bu yüzden sorgulanmadı.',
  'zone.fatal.title': 'Bu dosya okunamadı',
  'zone.fatal.EMPTY': 'Dosya boş.',
  'zone.fatal.TOO_LARGE': 'Dosya çok büyük. Her seferinde tek bir zone dışa aktarın.',
  'zone.fatal.NOT_TEXT': 'Bu bir metin dosyası değil (ya da bayt sırası işareti olmayan UTF-16).',
  'zone.fatal.NOT_A_ZONE': 'Bu bir DNS zone dışa aktarımına benzemiyor.',
  'zone.fatal.INVALID_JSON': 'JSON’a benziyor ama okunamıyor.',
  'zone.fatal.UNSUPPORTED_JSON': 'Bu JSON, Route 53 ya da Cloudflare kayıt listesi değil.',
  'zone.fatal.YAML_UNSUPPORTED': 'Bu YAML desteklenmeyen bir özellik kullanıyor. Düz bir dosya için octodns-dump kullanın.',
  'zone.fatal.ORIGIN_REQUIRED': 'Zone adını girin: bu dosya göreli adlar kullanıyor.',
  'zone.fatal.ORIGIN_MISMATCH': 'Bu dosyalar farklı zone’lara ait ({origins}). Her seferinde tek zone içe aktarın.',
  'zone.fatal.API_ERROR': 'Bu bir kayıt listesi değil, Cloudflare API hatası. API anahtarını kontrol edip yeniden deneyin.',
  'zone.fatal.hint.pem': 'Bu bir sertifika. Sertifika aracında açın.',
  'zone.fatal.hint.html': 'Bu bir web sayfası. Sayfayı değil, dışa aktarımın kendisini kaydedin.',
  'zone.fatal.hint.gzip': 'Sıkıştırılmış. Önce açın.',
  'zone.fatal.hint.csv': 'Bir sunucu listesine benziyor. Sunucular bölümünde açın.',
  'zone.fatal.hint.dns-csv': 'Kayıtların CSV listesi. Zone’u bunun yerine BIND dosyası olarak dışa aktarın.',
  'zone.fatal.hint.inventory': 'Bir sunucu listesine benziyor. Sunucular bölümünde açın.',
  'zone.fatal.hint.names': 'Bir ad listesi. Bunun için Toplu Çözümleme’yi kullanın.',
  'zone.fatal.hint.aws-output-json': 'AWS CLI’ı --output json ile çalıştırın.',
  'zone.fatal.hint.unknown': 'Zone’u dosya olarak dışa aktardığınızdan emin olun.'
};

/** Parse issue text (`zone.issue.<CODE>`): EN, TR. Params come from lib/zoneparse.js. */
const ISSUE_TEXT = {
  INCLUDE_REJECTED: ['$INCLUDE cannot be followed in the browser. Drop the included file too.', '$INCLUDE tarayıcıda izlenemez. Dahil edilen dosyayı da bırakın.'],
  RELATIVE_WITHOUT_ORIGIN: ['“{name}” is relative, but no origin is known yet; skipped.', '“{name}” göreli, ama henüz bir origin bilinmiyor; atlandı.'],
  UNTERMINATED_QUOTE: ['A quote is never closed; this entry was skipped.', 'Bir tırnak hiç kapanmıyor; bu kayıt atlandı.'],
  UNBALANCED_PAREN: ['A parenthesis is never closed; this entry was skipped.', 'Bir parantez hiç kapanmıyor; bu kayıt atlandı.'],
  'UNBALANCED_PAREN.close': ['A “)” has no matching “(”; it was ignored.', 'Bir “)” için eşleşen “(” yok; yok sayıldı.'],
  LINE_TOO_LONG: ['The line is too long and was skipped.', 'Satır çok uzun; atlandı.'],
  NO_OWNER: ['A record starts with a blank owner before any name.', 'Bir kayıt, henüz hiçbir ad yokken boş sahiple başlıyor.'],
  BAD_NAME: ['Invalid name “{name}”.', 'Geçersiz ad “{name}”.'],
  BAD_RDATA: ['Invalid {type} value.', 'Geçersiz {type} değeri.'],
  BAD_RECORD: ['A record could not be read.', 'Bir kayıt okunamadı.'],
  UNPARSED_LINE: ['This line could not be understood: {snippet}', 'Bu satır anlaşılamadı: {snippet}'],
  PARTIAL_EXPORT: ['Only {have} records are in this export: it is incomplete. Cloudflare: add ?per_page=5000000 or drop every page together. Route 53: run the AWS CLI without --max-items.', 'Bu dışa aktarımda yalnızca {have} kayıt var: eksik. Cloudflare: ?per_page=5000000 ekleyin ya da tüm sayfaları birlikte bırakın. Route 53: AWS CLI’ı --max-items olmadan çalıştırın.'],
  OWNER_MISSING_TRAILING_DOT: ['“{intended}” has no trailing dot in the file, so DNS serves it as {name}, almost certainly not what was meant.', '“{intended}” dosyada sonda nokta olmadan yazılmış; DNS onu {name} olarak sunar, kastedilen büyük olasılıkla bu değil.'],
  RECORDS_TRUNCATED: ['Only the first {max} records were read.', 'Yalnızca ilk {max} kayıt okundu.'],
  'RECORDS_TRUNCATED.entries': ['Only the first {max} entries were read.', 'Yalnızca ilk {max} girdi okundu.'],
  'RECORDS_TRUNCATED.documents': ['Only the first {max} pasted documents were read.', 'Yapıştırılan belgelerin yalnızca ilk {max} tanesi okundu.'],
  GENERATE_TOO_LARGE: ['$GENERATE makes {count} records; the limit is {max}.', '$GENERATE {count} kayıt üretiyor; sınır {max}.'],
  GENERATE_UNSUPPORTED: ['This $GENERATE form ({range}) is not supported.', 'Bu $GENERATE biçimi ({range}) desteklenmiyor.'],
  BAD_TTL: ['Invalid TTL {ttl}; read as 0.', 'Geçersiz TTL {ttl}; 0 olarak okundu.'],
  'BAD_TTL.directive': ['Invalid $TTL {ttl}; the line was ignored.', 'Geçersiz $TTL {ttl}; satır yok sayıldı.'],
  TARGET_MISSING_TRAILING_DOT: ['The target of {name} has no trailing dot, so it points to {target}, probably not the intended {intended}.', '{name} hedefinin sonunda nokta yok; bu yüzden {target} adresine işaret ediyor, kastedilen büyük olasılıkla {intended}.'],
  AT_INSIDE_NAME: ['“{raw}” uses @ inside a name. Read as {name}, but a standard name server would create a literal “@” label.', '“{raw}” adın içinde @ kullanıyor. {name} olarak okundu, ama standart bir ad sunucusu harfiyen “@” etiketi oluşturur.'],
  DUPLICATE_KEY: ['A key appears twice; the last one was used.', 'Bir anahtar iki kez geçiyor; sonuncusu kullanıldı.'],
  OCTODNS_UNESCAPED_SEMICOLON: ['An unescaped “;” in {name} (octoDNS needs \\;).', '{name} içinde kaçışsız “;” var (octoDNS \\; ister).'],
  OUT_OF_ZONE: ['{name} is outside the zone {origin}; name servers ignore it.', '{name}, {origin} zone’unun dışında; ad sunucuları onu yok sayar.'],
  ORIGIN_OVERRIDDEN: ['You entered {user}, but the file says {file}.', '{user} girdiniz, ama dosya {file} diyor.'],
  ORIGIN_INFERRED: ['Zone name {origin} detected.', '{origin} zone adı algılandı.'],
  ORIGIN_CORRECTED: ['The file name suggested {from}; the SOA/NS records say {to}, which is used.', 'Dosya adı {from} gösteriyordu; SOA/NS kayıtları {to} diyor, o kullanıldı.'],
  CF_SOA_OWNER_UNDOTTED: ['Cloudflare writes the SOA owner without a trailing dot; read as the zone apex.', 'Cloudflare SOA sahibini sonda nokta olmadan yazar; zone kökü olarak okundu.'],
  NON_IN_CLASS: ['A record of class {class} was skipped.', '{class} sınıfından bir kayıt atlandı.'],
  GENERATE_EXPANDED: ['$GENERATE {range} made {count} records.', '$GENERATE {range}, {count} kayıt üretti.'],
  UNKNOWN_DIRECTIVE: ['Unknown directive {directive} ignored.', 'Bilinmeyen {directive} yönergesi yok sayıldı.'],
  FORMAT_UNVERIFIED: ['This format is not documented by the vendor; check the results.', 'Bu biçim üretici tarafından belgelenmemiş; sonuçları kontrol edin.'],
  OCTODNS_IGNORED: ['An octoDNS {type} record at {name} was ignored.', '{name} adındaki octoDNS {type} kaydı yok sayıldı.'],
  RDATA_UNPARSED: ['A record value was kept as text (not decoded).', 'Bir kayıt değeri metin olarak tutuldu (çözümlenmedi).'],
  TTL_DEFAULTED: ['Records without a TTL use the SOA minimum.', 'TTL’i olmayan kayıtlar SOA minimumunu kullanır.'],
  NON_ASCII_LABEL: ['{name} was converted to punycode.', '{name} punycode’a dönüştürüldü.'],
  ENCODING_REPLACED: ['{count} characters could not be decoded and were replaced.', '{count} karakter çözülemedi ve değiştirildi.'],
  JSON_PAGES_MERGED: ['{pages} pages merged ({duplicates} duplicates dropped).', '{pages} sayfa birleştirildi ({duplicates} yinelenen atıldı).'],
  PROXY_FLAG_IGNORED: ['A proxy flag on a record type Cloudflare cannot proxy was ignored.', 'Cloudflare’in proxy’leyemediği bir kayıt türündeki proxy işareti yok sayıldı.'],
  WARNINGS_TRUNCATED: ['Too many issues; the rest are not listed.', 'Çok fazla sorun var; kalanlar listelenmedi.'],
  INCLUDE_MERGED: ['The $INCLUDE file was dropped too and merged.', '$INCLUDE dosyası da bırakıldı ve birleştirildi.'],
  NO_PROXY_FLAGS: ['This export has no proxy flags: proxied and DNS-only records cannot be told apart.', 'Bu dışa aktarımda proxy işaretleri yok: proxy’li ve yalnızca DNS kayıtları ayırt edilemiyor.']
};

/** Lint text (`zone.lint.<CODE>` title, `.why`): EN [title, why], TR [title, why]. */
const LINT_TEXT = {
  CNAME_AND_OTHER_DATA: [['CNAME next to other records', '{name} has a CNAME and {types}. A CNAME must be alone at its name; resolvers answer unpredictably and BIND refuses the zone. Keep either the CNAME or the other records.'],
    ['CNAME başka kayıtlarla birlikte', '{name} adında hem CNAME hem {types} var. CNAME kendi adında tek başına olmalı; çözümleyiciler tutarsız yanıt verir, BIND zone’u yüklemez. Ya CNAME’i ya da diğer kayıtları tutun.']],
  CNAME_AT_APEX: [['CNAME at the zone apex', '{name} is a CNAME to {target}. Outside Cloudflare (which flattens it) a CNAME cannot sit next to the SOA and NS records.'],
    ['Zone kökünde CNAME', '{name}, {target} adresine CNAME. Cloudflare dışında (orada düzleştirilir) CNAME, SOA ve NS kayıtlarının yanında duramaz.']],
  MULTIPLE_CNAME: [['Several CNAMEs at one name', '{name} has {count} CNAME records; only one is allowed.'], ['Bir adda birden fazla CNAME', '{name} adında {count} CNAME kaydı var; yalnızca bir tane olabilir.']],
  CNAME_LOOP: [['CNAME loop', '{name} never resolves: {chain}.'], ['CNAME döngüsü', '{name} hiç çözümlenmez: {chain}.']],
  CNAME_CHAIN_LONG: [['Long CNAME chain', '{name} goes through {hops} CNAME hops inside the zone; resolvers may give up.'], ['Uzun CNAME zinciri', '{name} zone içinde {hops} CNAME adımından geçiyor; çözümleyiciler vazgeçebilir.']],
  MX_TO_CNAME: [['MX points to a CNAME', 'The mail host of {name} is a CNAME. RFC 2181 requires an MX target with its own address; some mail servers refuse to deliver.'], ['MX bir CNAME’e işaret ediyor', '{name} adının e-posta sunucusu bir CNAME. RFC 2181’e göre MX hedefinin kendi adresi olmalı; bazı e-posta sunucuları teslim etmeyi reddeder.']],
  NS_TO_CNAME: [['NS points to a CNAME', 'A name server of {name} is a CNAME, which RFC 2181 forbids.'], ['NS bir CNAME’e işaret ediyor', '{name} adının bir ad sunucusu CNAME; RFC 2181 bunu yasaklar.']],
  SRV_TO_CNAME: [['SRV points to a CNAME', 'The SRV target of {name} is a CNAME, which RFC 2782 forbids.'], ['SRV bir CNAME’e işaret ediyor', '{name} adının SRV hedefi bir CNAME; RFC 2782 bunu yasaklar.']],
  TARGET_IS_IP: [['Target is an IP address', 'The target of {name} is {target}, an IP address; this record type needs a host name.'], ['Hedef bir IP adresi', '{name} kaydının hedefi {target}, bir IP adresi; bu kayıt türü host adı ister.']],
  DANGLING_IN_ZONE_TARGET: [['Target has no records', '{name} points to {target}, which has no records in this zone.'], ['Hedefin kaydı yok', '{name}, bu zone’da hiç kaydı olmayan {target} adresine işaret ediyor.']],
  DUPLICATE_RR: [['Duplicate record', 'The same {type} record of {name} is listed twice.'], ['Yinelenen kayıt', '{name} adının aynı {type} kaydı iki kez yazılmış.']],
  OCCLUDED_BY_DELEGATION: [['Record hidden below a delegation', '{name} is under {cut}, which is delegated to other name servers; this zone never serves it. Move it into the child zone or delete it.'], ['Yetki devrinin altında kalmış kayıt', '{name}, başka ad sunucularına devredilen {cut} altında; bu zone onu hiçbir zaman sunmaz. Kaydı alt zone’a taşıyın ya da silin.']],
  OCCLUDED_BY_DNAME: [['Record hidden below a DNAME', '{name} is below the DNAME at {dname}; this zone never serves it.'], ['DNAME altında kalmış kayıt', '{name}, {dname} adındaki DNAME’in altında; bu zone onu hiçbir zaman sunmaz.']],
  PRIVATE_IP: [['Private address in a public zone', '{name} points at {ip}. Public resolvers return it to anyone, which leaks internal addressing. Move internal names to an internal (split-horizon) zone.'], ['Herkese açık zone’da özel adres', '{name}, {ip} adresine işaret ediyor. Genel çözümleyiciler bunu herkese döndürür; iç adresleme sızar. İç adları dahili (split-horizon) bir zone’a taşıyın.']],
  LOCALHOST_RECORD: [['localhost in a public zone', '{name} points at {ip}. Hosting panels add it by default; it lets pages on other subdomains share cookies with a local process. Delete it.'], ['Herkese açık zone’da localhost', '{name}, {ip} adresine işaret ediyor. Barındırma panelleri bunu varsayılan olarak ekler; yerel bir süreçle çerez paylaşımına yol açar. Silin.']],
  NON_GLOBAL_IPV6: [['Non-global IPv6 address', '{name} points at {ip}, outside the global unicast range.'], ['Genel olmayan IPv6 adresi', '{name}, genel tekil yayın aralığı dışındaki {ip} adresine işaret ediyor.']],
  MIXED_PROXY_FLAGS: [['Proxied and DNS-only on one name', '{name} has both. Cloudflare then proxies every A/AAAA of this name, so the DNS-only flag has no effect.'], ['Aynı adda hem proxy’li hem yalnızca DNS', '{name} ikisine de sahip. Cloudflare bu durumda adın tüm A/AAAA kayıtlarını proxy’ler; yalnızca DNS ayarının etkisi olmaz.']],
  ORIGIN_EXPOSED_BY_SIBLING: [['Proxied origin published by a DNS-only name', '{name} is DNS-only and publishes the origin behind proxied {proxied}. Anyone can reach the server directly and bypass Cloudflare’s WAF and DDoS protection. Proxy it too, move it, or allow only Cloudflare’s ranges on the origin firewall.'],
    ['Proxy’li origin, yalnızca DNS olan bir adla yayımlanıyor', '{name} yalnızca DNS ve proxy’li {proxied} adlarının arkasındaki origin’i yayımlıyor. Herkes sunucuya doğrudan ulaşıp Cloudflare’in WAF ve DDoS korumasını atlayabilir. Onu da proxy’leyin, taşıyın ya da origin güvenlik duvarında yalnızca Cloudflare aralıklarına izin verin.']],
  ORIGIN_EXPOSED_BY_SPF: [['SPF reveals a proxied origin', 'The SPF record of {spfName} authorises {ips}, the origin of proxied {proxied}: mail and web share a server, and SPF is public.'], ['SPF proxy’li bir origin’i ele veriyor', '{spfName} SPF kaydı, proxy’li {proxied} adlarının origin’i olan {ips} adresine izin veriyor: e-posta ve web aynı sunucuda ve SPF herkese açık.']],
  PROXIED_PRIVATE_ORIGIN: [['Proxied to a private address', '{name} is proxied to {ip}, which Cloudflare’s edge cannot reach.'], ['Özel bir adrese proxy’lenmiş', '{name}, Cloudflare’in erişemediği {ip} adresine proxy’lenmiş.']],
  PROXIED_TO_CLOUDFLARE_IP: [['Proxied record points at Cloudflare', 'Cloudflare answers {name} ({ip}) with error 1000 “DNS points to prohibited IP”. Point it at your origin server.'], ['Proxy’li kayıt Cloudflare’e işaret ediyor', 'Cloudflare, {name} ({ip}) için 1000 “DNS points to prohibited IP” hatası verir. Kaydı origin sunucunuza yönlendirin.']],
  ORIGINLESS_PLACEHOLDER: [['Placeholder record', '{name} points at {ip}: a Worker or a redirect rule answers it; there is no server behind it.'], ['Yer tutucu kayıt', '{name}, {ip} adresine işaret ediyor: onu bir Worker ya da yönlendirme kuralı yanıtlar; arkasında sunucu yok.']],
  PROXIED_TUNNEL: [['Origin is a Cloudflare Tunnel', '{name} goes through a Tunnel; there is no inbound origin to sweep.'], ['Origin bir Cloudflare Tunnel', '{name} bir Tunnel üzerinden gidiyor; taranacak dışarıdan erişilen origin yok.']],
  PROXIED_PROVIDER: [['Origin is a third party', '{name} points at {provider} ({target}); its certificate is managed there.'], ['Origin üçüncü taraf', '{name}, {provider} ({target}) üzerine işaret ediyor; sertifikası orada yönetilir.']],
  MX_TARGET_PROXIED: [['Mail host is proxied', 'The mail host {target} of {name} is proxied, but Cloudflare’s proxy carries HTTP(S) only: mail to it fails.'], ['E-posta sunucusu proxy’li', '{name} adının e-posta sunucusu {target} proxy’li, ama Cloudflare proxy’si yalnızca HTTP(S) taşır: ona giden e-posta başarısız olur.']],
  SRV_TARGET_PROXIED: [['SRV target is proxied', 'The SRV target {target} of {name} is proxied on port {port}, which Cloudflare’s proxy does not carry.'], ['SRV hedefi proxy’li', '{name} adının SRV hedefi {target}, Cloudflare proxy’sinin taşımadığı {port} portunda proxy’li.']],
  MULTIPLE_SPF: [['More than one SPF record', '{name} has {count} “v=spf1” records. Receivers treat this as a permanent error and SPF fails for all mail. Merge them into one record.'], ['Birden fazla SPF kaydı', '{name} adında {count} adet “v=spf1” kaydı var. Alıcılar bunu kalıcı hata sayar ve tüm e-postalarda SPF başarısız olur. Hepsini tek kayıtta birleştirin.']],
  SPF_INVALID: [['Invalid SPF record', 'The SPF record of {name} has an error ({error}).'], ['Geçersiz SPF kaydı', '{name} SPF kaydında hata var ({error}).']],
  SPF_RR_TYPE: [['Obsolete SPF record type', '{name} uses record type SPF (99); publish the policy as TXT only.'], ['Eskimiş SPF kayıt türü', '{name} SPF (99) kayıt türünü kullanıyor; politikayı yalnızca TXT olarak yayımlayın.']],
  DMARC_INVALID: [['Invalid DMARC record', 'The DMARC record of {name} has an error ({error}).'], ['Geçersiz DMARC kaydı', '{name} DMARC kaydında hata var ({error}).']],
  TXT_STRING_TOO_LONG: [['TXT string too long', 'One string of {name} is {bytes} bytes; the maximum is 255. Split it into several quoted strings.'], ['TXT dizesi çok uzun', '{name} adının bir dizesi {bytes} bayt; en fazla 255 olabilir. Birkaç tırnaklı dizeye bölün.']],
  CAA_UNKNOWN_TAG: [['Unknown CAA tag', 'The CAA record of {name} uses the tag “{tag}”, which CAs ignore.'], ['Bilinmeyen CAA etiketi', '{name} CAA kaydı, CA’ların yok saydığı “{tag}” etiketini kullanıyor.']],
  CAA_FLAGS: [['Unusual CAA flags', 'The CAA record of {name} has flags {flags}; a critical flag on an unknown tag blocks every CA.'], ['Olağan dışı CAA işaretleri', '{name} CAA kaydının işaretleri {flags}; bilinmeyen bir etikette kritik işaret tüm CA’ları engeller.']],
  TTL_OUTLIER: [['Unusually long TTL', '{name} has a TTL of {ttl} s, while {median} s is typical in this zone: a change takes that long to reach everyone.'], ['Alışılmadık uzun TTL', '{name} için TTL {ttl} sn; bu zone’da tipik olan {median} sn: bir değişikliğin herkese ulaşması bu kadar sürer.']],
  TTL_TOO_LOW: [['Very short TTL', '{name} has a TTL of {ttl} s; resolvers query it constantly and some raise it anyway.'], ['Çok kısa TTL', '{name} için TTL {ttl} sn; çözümleyiciler onu sürekli sorgular, bazıları yine de yükseltir.']],
  SOA_NEGATIVE_TTL: [['Long negative-caching TTL', 'The SOA minimum of {name} is {minimum} s: a newly added name may stay “missing” that long.'], ['Uzun negatif önbellek TTL’i', '{name} SOA minimumu {minimum} sn: yeni eklenen bir ad bu kadar süre “yok” görünebilir.']],
  SINGLE_NS: [['Only one name server', '{name} lists a single name server; if it fails the whole zone is unreachable.'], ['Yalnızca bir ad sunucusu', '{name} tek bir ad sunucusu listeliyor; o çökerse tüm zone erişilemez olur.']],
  ALIAS_TARGET_MISSING: [['Alias target not in the file', 'The alias of {name} points to {target} in this zone, which has no such record.'], ['Alias hedefi dosyada yok', '{name} alias’ı bu zone’daki {target} adına işaret ediyor, ama böyle bir kayıt yok.']]
};

/** Origin kind labels are in EN/TR above; the provider names come from netinfo ids. */
function buildDictionaries() {
  const en = { ...EN };
  const tr = { ...TR };
  for (const [code, [e, r]] of Object.entries(ISSUE_TEXT)) {
    en[`zone.issue.${code}`] = e;
    tr[`zone.issue.${code}`] = r;
  }
  for (const [code, [[et, ew], [rt, rw]]] of Object.entries(LINT_TEXT)) {
    en[`zone.lint.${code}`] = et;
    en[`zone.lint.${code}.why`] = ew;
    tr[`zone.lint.${code}`] = rt;
    tr[`zone.lint.${code}.why`] = rw;
  }
  return { en, tr };
}

const DICTS = buildDictionaries();
registerStrings('en', DICTS.en);
registerStrings('tr', DICTS.tr);

/* ------------------------------------------------------------------------ */
/* Pure helpers (unit-tested)                                               */
/* ------------------------------------------------------------------------ */

/**
 * Every i18n key the view can build from a library code (for the coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  const keys = [];
  for (const [code, def] of Object.entries(ISSUE_CODES)) keys.push(def.fatal ? `zone.fatal.${code}` : `zone.issue.${code}`);
  for (const variant of Object.keys(ISSUE_TEXT)) if (variant.includes('.')) keys.push(`zone.issue.${variant}`);
  for (const code of Object.keys(LINT_RULES)) keys.push(`zone.lint.${code}`, `zone.lint.${code}.why`);
  for (const s of DRIFT_STATUSES) keys.push(`zone.drift.${s}`);
  for (const r of DRIFT_REASONS) keys.push(`zone.reason.${r}`);
  for (const k of ORIGIN_KINDS) keys.push(`zone.kind.${k}`);
  for (const f of ZONE_FORMATS) keys.push(`zone.format.${f}`);
  for (const d of ZONE_DIALECTS) keys.push(`zone.dialect.${d}`);
  for (const hnt of NOT_A_ZONE_HINTS) keys.push(`zone.fatal.hint.${hnt}`);
  for (const tab of ZONE_TABS) keys.push(`zone.tab.${tab}`);
  return keys;
}

/** Parse issues whose text depends on a param → the `<CODE>.<variant>` key (texts in ISSUE_TEXT). */
const ISSUE_VARIANTS = Object.freeze({
  UNBALANCED_PAREN: (p) => (p.kind === 'close' ? 'close' : null),
  BAD_TTL: (p) => (p.directive ? 'directive' : null),
  RECORDS_TRUNCATED: (p) => (p.unit === 'entries' || p.unit === 'documents' ? p.unit : null)
});

/**
 * The i18n key of a parse issue: `zone.issue.<CODE>`, or a variant where one sentence cannot fit
 * every case (a stray ")" is ignored but an open "(" drops the entry; an invalid `$TTL` is
 * ignored but a record TTL above 2^31-1 reads as 0; the unit of RECORDS_TRUNCATED).
 * @param {string} code
 * @param {object} [params]
 * @returns {string}
 */
export function issueKey(code, params) {
  const pick = Object.prototype.hasOwnProperty.call(ISSUE_VARIANTS, code) ? ISSUE_VARIANTS[code] : null;
  const variant = pick ? pick(params || {}) : null;
  return variant ? `zone.issue.${code}.${variant}` : `zone.issue.${code}`;
}

/**
 * Type filter group of a record type.
 * @param {string} type
 * @returns {'addr'|'CNAME'|'MX'|'TXT'|'NS'|'other'}
 */
export function typeGroup(type) {
  const tp = String(type || '').toUpperCase();
  if (tp === 'A' || tp === 'AAAA') return 'addr';
  if (tp === 'CNAME' || tp === 'MX' || tp === 'TXT' || tp === 'NS') return tp;
  return 'other';
}

/**
 * Does a record pass the Records filter?
 * @param {object} r ZoneRecord
 * @param {{ group?: string, proxiedOnly?: boolean }} f
 * @returns {boolean}
 */
export function recordMatches(r, { group = 'all', proxiedOnly = false } = {}) {
  if (proxiedOnly && r.proxied !== true) return false;
  return group === 'all' || typeGroup(r.type) === group;
}

/**
 * The name relative to the zone origin: '@' for the apex, 'www' for www.example.com, else the full name.
 * @param {string} name
 * @param {string|null} origin
 * @returns {string}
 */
export function relativeName(name, origin) {
  const n = String(name || '');
  if (!origin) return n;
  if (n === origin) return '@';
  return n.endsWith(`.${origin}`) ? n.slice(0, -origin.length - 1) : n;
}

const SEV_RANK = { error: 0, warn: 1, info: 2 };

/**
 * Parse issues and lint findings as one list, errors first, then by line.
 * @param {object} zone
 * @param {{ findings: object[] }|null} lint
 * @returns {Array<{ source: 'issue'|'lint', code: string, severity: 'error'|'warn'|'info', name: string,
 *   type: string, line: number, params: object }>}
 */
export function problemList(zone, lint) {
  const out = [];
  for (const w of (zone && zone.warnings) || []) {
    out.push({ source: 'issue', code: w.code, severity: w.severity, name: w.name || '', type: w.type || '', line: w.line || 0, params: w.params || {} });
  }
  for (const f of (lint && lint.findings) || []) {
    out.push({ source: 'lint', code: f.code, severity: f.severity, name: f.name || '', type: f.type || '', line: f.line || 0, params: f.params || {} });
  }
  return out.sort((a, b) => (SEV_RANK[a.severity] ?? 3) - (SEV_RANK[b.severity] ?? 3) || a.line - b.line);
}

/**
 * Counts for the summary: records, served names, proxied / DNS-only records, errors, warnings.
 * @param {object} zone
 * @param {object[]} problems {@link problemList}
 * @returns {{ records: number, names: number, proxied: number, dnsOnly: number, errors: number, warnings: number, info: number }}
 */
export function zoneCounts(zone, problems) {
  const recs = (zone && zone.records) || [];
  return {
    records: recs.length,
    names: zone ? zoneNames(zone).length : 0,
    proxied: recs.filter((r) => r.proxied === true).length,
    dnsOnly: recs.filter((r) => r.proxied === false).length,
    errors: problems.filter((p) => p.severity === 'error').length,
    warnings: problems.filter((p) => p.severity === 'warn').length,
    info: problems.filter((p) => p.severity === 'info').length
  };
}

/** Lower-case base name of a path (how an `$INCLUDE` line names a dropped file). */
const baseName = (p) => String(p || '').split(/[\\/]/).pop().toLowerCase();

/**
 * Parse one or several loaded files into one zone (zone spec §6.1.1 multi-file rule): when
 * every file is Cloudflare API JSON (or every one Route 53 JSON) the texts are joined and parsed
 * once (pages merged, PARTIAL_EXPORT over all pages); otherwise each file is parsed alone and
 * the results are merged (same origin required). The lead file (one that `$INCLUDE`s another
 * dropped file, else one whose origin comes from an SOA / `$ORIGIN` / header) goes first
 * whatever the drop order; a part that does not name its own zone is read under its
 * `$INCLUDE` origin, else the lead's, with the lead's `$TTL`.
 * @param {Array<{ name: string, text: string }>} files
 * @param {{ origin?: string|null, format?: string }} [opts]
 * @returns {object} Zone
 */
export function parseFiles(files, { origin = null, format = 'auto' } = {}) {
  const list = (files || []).filter((f) => f && typeof f.text === 'string');
  const o = origin && String(origin).trim() ? String(origin).trim() : null;
  if (list.length <= 1) {
    const f = list[0] || { name: '', text: '' };
    return parseZone(f.text, { origin: o, filename: f.name || null, format });
  }
  const total = list.reduce((n, f) => n + f.text.length, 0);
  if (total > ZONE_LIMITS.maxChars) return parseZone(list.map((f) => f.text).join('\n'), { origin: o, format });
  const formats = list.map((f) => detectZoneFormat(f.text, { filename: f.name }).format);
  if (formats.every((x) => x === 'cloudflare-api') || formats.every((x) => x === 'route53')) {
    return parseZone(list.map((f) => f.text).join('\n'), { origin: o, filename: list[0].name, format });
  }
  // The lead goes first so $INCLUDE fragments inherit its origin (critic B4).
  const alone = list.map((f, i) => parseZone(f.text, { origin: o, filename: f.name, format, source: i }));
  const dropped = new Set(list.map((f) => baseName(f.name)));
  const includesOther = (z) => !z.fatal && z.warnings.some((w) => w.code === 'INCLUDE_REJECTED' && dropped.has(baseName(w.params.path)));
  let li = alone.findIndex(includesOther);
  if (li < 0) li = alone.findIndex((z) => !z.fatal && z.origin && z.originConfidence === 'high');
  if (li < 0) li = 0;
  const lead = alone[li];
  const includeAt = new Map();
  for (const w of lead.warnings) if (w.code === 'INCLUDE_REJECTED' && w.params.at) includeAt.set(baseName(w.params.path), w.params.at);
  // no zone name of its own: a missing origin, or one guessed from the file name / the records
  const adoptable = (z) => (z.fatal ? z.fatal.code === 'ORIGIN_REQUIRED' : z.originConfidence !== 'high' || z.originSource === 'user');
  const zones = [lead];
  list.forEach((f, i) => {
    if (i === li) return;
    const base = { filename: f.name, format, source: i, defaultTtl: lead.defaultTtl ?? null };
    let z = (lead.defaultTtl ?? null) === null ? alone[i] : parseZone(f.text, { ...base, origin: o });
    const at = includeAt.get(baseName(f.name)) || null;
    const want = at || lead.origin;
    if (want && adoptable(z) && z.origin !== want) z = parseZone(f.text, { ...base, origin: want });
    // included below the apex (`$INCLUDE lab lab.example.com.`): still a part of the lead's zone
    if (at && z.origin === at && lead.origin && at.endsWith(`.${lead.origin}`)) {
      z = { ...z, origin: lead.origin, originSource: lead.originSource, originConfidence: lead.originConfidence };
    }
    zones.push(z);
  });
  return mergeZones(zones);
}

/**
 * Is the zone origin trustworthy enough to publish the scan hand-off (critic D5)?
 * @param {object} zone
 * @param {boolean} confirmed the user pressed Confirm
 * @returns {boolean}
 */
export function originConfirmed(zone, confirmed) {
  if (!zone || zone.fatal || !zone.origin) return false;
  return confirmed || zone.originConfidence === 'high' || zone.originSource === 'user';
}

/**
 * The one-shot intent for Subdomains / SSL Targets (`state.session.zoneScanIntent`).
 * @param {{ target: 'subdomains'|'scan', domain: string, mode?: 'exact'|'discover', autostart?: boolean, now?: number }} o
 * @returns {{ v: 1, target: string, domain: string, mode: 'exact'|'discover', autostart: boolean, at: number }}
 */
export function buildIntent({ target, domain, mode = 'exact', autostart = true, now = Date.now() }) {
  return {
    v: 1,
    target: target === 'scan' ? 'scan' : 'subdomains',
    domain: String(domain || ''),
    mode: mode === 'discover' ? 'discover' : 'exact',
    autostart: !!autostart,
    at: now
  };
}

/**
 * The scan input published as `state.session.zone`.
 * @param {object} zone
 * @param {{ skipPrivate?: boolean, label?: string }} [opts]
 * @returns {object}
 */
export function sessionZone(zone, { skipPrivate = true, label = '' } = {}) {
  const input = zoneScanInput(zone, { skipPrivate });
  return {
    ...input,
    label,
    counts: { names: input.names.length + input.wildcardBases.length, origins: input.proxied.length, skipped: input.skipped.length }
  };
}

/**
 * The sweep command for one shell: lib/cmdline.buildSweepCommand when it keeps every token (its
 * zone opt-ins `allowHostTargets` / `allowWildcardNames` / `targetsFile`), else the same tokens —
 * already validated by lib/zoneorigins' injection-safe validators — joined with cmdline.quoteArg.
 * Above the inline limits the file form `-t zone-targets.txt -n zone-names.txt` is used.
 * @param {object} sweep zoneorigins.zoneSweep result
 * @returns {{ command: string|null, fileForm: boolean, via: 'cmdline'|'zone' }}
 */
export function sweepCommand(sweep) {
  const o = sweep && sweep.commandOptions;
  if (!o || !o.targets.length || !o.names.length) return { command: null, fileForm: false, via: 'zone' };
  const sh = o.shell === 'powershell' ? 'powershell' : 'posix';
  let built = null;
  try {
    built = buildSweepCommand(o);
  } catch {
    built = null;
  }
  const complete = built && typeof built.command === 'string'
    && built.targets.length === o.targets.length && built.names.length === o.names.length
    && (!sweep.fileForm || built.namesInline === false);
  if (complete && (!sweep.fileForm || / -t \S*zone-targets\.txt/.test(built.command))) {
    return { command: `${PYTHON[sh]} ${built.command}`, fileForm: built.namesInline === false || built.targetsInline === false, via: 'cmdline' };
  }
  const q = (v) => quoteArg(v, sh);
  const body = sweep.fileForm
    ? `${q(o.script)} -t ${q(ZONE_TARGETS_FILE)} -n ${q(ZONE_NAMES_FILE)}`
    : `${q(o.script)} -t ${o.targets.map(q).join(' ')} -n ${o.names.map(q).join(' ')}`;
  return { command: `${PYTHON[sh]} ${body}`, fileForm: !!sweep.fileForm, via: 'zone' };
}

/**
 * The SNI names the CLI sends to each target (a `*.x` name is probed as `x` and as `*.x`), so
 * "names × targets = handshakes" adds up on screen.
 * @param {{ names: string[], probes: number }} sweep zoneorigins.zoneSweep result
 * @param {number} targetCount address + host targets
 * @returns {number}
 */
export function sweepProbeNames(sweep, targetCount) {
  const names = sweep && Array.isArray(sweep.names) ? sweep.names.length : 0;
  return targetCount > 0 && sweep && Number.isFinite(sweep.probes) ? Math.round(sweep.probes / targetCount) : names;
}

/** Is `s` (any case, trailing dot, any IPv6 spelling) one of the secrets? */
function isSecret(s, secrets) {
  const v = s.toLowerCase().replace(/\.$/, '');
  if (secrets.has(v)) return true;
  const ip = normalizeIP(v);
  return !!ip && secrets.has(ip);
}

/** One whitespace / quote / comma separated token: a bare value, `ip4:` / `a:` / `redirect=` …, a `/len` suffix. */
function redactToken(tok, secrets) {
  if (!tok) return tok;
  const len = /\/\d{1,3}$/.exec(tok);
  const body = len ? tok.slice(0, len.index) : tok;
  const tail = len ? len[0] : '';
  if (isSecret(body, secrets)) return REDACTED + tail;
  const pre = /^[+?~-]?[a-z][a-z0-9-]*[:=]/i.exec(body);
  return pre && isSecret(body.slice(pre[0].length), secrets) ? pre[0] + REDACTED + tail : tok;
}

/**
 * Replace origin addresses / hosts in exported values unless the user opted in (spec D13): a
 * whole value, or a token inside one (an SPF `ip4:` / `ip6:` / `a:` term, an MX or SRV target).
 * @param {string[]} values
 * @param {Set<string>} secrets origin IPs and hosts
 * @param {boolean} include
 * @returns {string[]}
 */
export function redactValues(values, secrets, include) {
  if (include || !secrets || !secrets.size) return [...(values || [])];
  return (values || []).map((v) => {
    const s = String(v);
    if (isSecret(s, secrets)) return REDACTED;
    return s.split(/([\s"',;]+)/).map((part, i) => (i % 2 ? part : redactToken(part, secrets))).join('');
  });
}

/**
 * The origin addresses and hosts of the proxied names (what exports redact).
 * @param {object[]} origins proxiedOriginMap rows
 * @returns {Set<string>}
 */
export function originSecrets(origins) {
  const out = new Set();
  for (const row of origins || []) {
    if (row.kind === 'ip') row.ips.forEach((ip) => out.add(ip));
    if (row.kind === 'host' && row.host) out.add(row.host);
  }
  return out;
}

/**
 * The server columns of the Origins and Records tabs: the proxied-origin map and the address
 * map, matched against an inventory index (`state.getInventoryIndex()`).
 * @param {object} zone
 * @param {Map<string, object[]>|null} inventoryIndex
 * @returns {{ origins: object[], addresses: object[] }}
 */
export function serverColumns(zone, inventoryIndex) {
  return { origins: proxiedOriginMap(zone, { inventoryIndex }), addresses: addressMap(zone, { inventoryIndex }) };
}

/* ------------------------------------------------------------------------ */
/* Module session (memory only, never serialised)                           */
/* ------------------------------------------------------------------------ */

function freshSession() {
  return {
    files: null,
    zone: null,
    lint: null,
    origins: [],
    addresses: [],
    invIndex: null,
    problems: [],
    counts: null,
    originInput: '',
    formatInput: 'auto',
    confirmed: false,
    tab: 'overview',
    rec: { group: 'all', proxiedOnly: false, search: '', line: 0 },
    probFilter: 'all',
    sweep: { scope: 'proxied', shell: 'posix' },
    mode: 'exact',
    skipInternal: true,
    fileError: null,
    busy: false,
    live: { skipPrivate: true, wildcards: true, includeOrigins: false, status: 'idle', rows: [], result: null, done: 0, total: 0, error: null, filter: 'all' }
  };
}

let S = freshSession();
let controller = null;
let rerender = null;
let subscribed = false;
/** The live-check tab currently shown: { render(), progress() } (a run outlives its tab). */
let liveHook = null;

function abortDrift() {
  if (controller) controller.abort();
  controller = null;
}

function resetSession() {
  abortDrift();
  S = freshSession();
}

/**
 * Match the loaded zone against the current servers (edited after the import, here or in
 * another tab). The memoized index is replaced on every inventory change, so its identity
 * tells whether the server columns are stale.
 * @param {Map<string, object[]>} index state.getInventoryIndex()
 * @returns {boolean} true when the columns were rebuilt
 */
function reindexServers(index) {
  if (!S.zone || S.zone.fatal || S.invIndex === index) return false;
  ({ origins: S.origins, addresses: S.addresses } = serverColumns(S.zone, index));
  S.invIndex = index;
  return true;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Zone File view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  if (!subscribed) {
    subscribed = true;
    state.subscribe(({ key }) => {
      if (key === 'cleared') {
        resetSession();
        if (rerender) rerender();
      } else if (key === 'inventory' && reindexServers(state.getInventoryIndex()) && rerender) {
        rerender();
      }
    });
  }
  if (ZONE_TABS.includes(ctx.params.tab)) S.tab = ctx.params.tab;

  const root = h('div', { class: 'zone-page stack' });
  container.append(
    Alert({ variant: 'ok', icon: 'lock', title: t('zone.privacyTitle'), message: t('zone.privacy'), compact: true }),
    root);

  const fmtLabel = (zone) => (zone.format === 'bind' && zone.dialect ? t(`zone.dialect.${zone.dialect}`) : t(`zone.format.${zone.format}`));
  const secrets = () => originSecrets(S.origins);

  /* --- import / analysis ------------------------------------------------ */
  function publish() {
    const z = S.zone;
    if (!originConfirmed(z, S.confirmed)) {
      if (state.getSession('zone') !== undefined) state.setSession('zone', undefined);
      return;
    }
    const label = `${fmtLabel(z)} · ${(S.files || []).map((f) => f.name).join(', ')}`;
    state.setSession('zone', sessionZone(z, { skipPrivate: S.skipInternal, label }));
  }

  function analyse(zone) {
    abortDrift();
    S.zone = zone;
    S.live = { ...freshSession().live, skipPrivate: S.live.skipPrivate, wildcards: S.live.wildcards };
    if (zone.fatal) {
      S.lint = null;
      S.origins = [];
      S.addresses = [];
      S.problems = [];
      S.counts = null;
      publish();
      return;
    }
    const inv = ctx.getInventoryIndex();
    S.lint = lintZone(zone);
    ({ origins: S.origins, addresses: S.addresses } = serverColumns(zone, inv));
    S.invIndex = inv;
    S.problems = problemList(zone, S.lint);
    S.counts = zoneCounts(zone, S.problems);
    publish();
  }

  function parseNow({ announceIt = false } = {}) {
    S.busy = true;
    S.fileError = null;
    render();
    setTimeout(() => {
      const zone = parseFiles(S.files, { origin: S.originInput || null, format: S.formatInput });
      S.busy = false;
      analyse(zone);
      render();
      if (announceIt && !zone.fatal) {
        const msg = t('zone.imported', { origin: zone.origin || '?', records: formatNumber(zone.records.length) });
        announce(msg);
        const head = root.querySelector('.zone-summary-title');
        if (head) head.focus({ preventScroll: true });
      }
    }, 0);
  }

  function importFiles(files) {
    const list = (files || []).slice(0, MAX_FILES).map((f) => ({ name: String(f.name || ''), size: Number(f.size) || (f.text || '').length, text: String(f.text || '') }));
    if ((files || []).length > MAX_FILES) toast(t('zone.tooManyFiles', { max: MAX_FILES }), { type: 'warn' });
    if (!list.length) return;
    S.files = list;
    S.originInput = '';
    S.confirmed = false;
    S.rec = { group: 'all', proxiedOnly: false, search: '', line: 0 };
    S.tab = 'overview';
    ctx.setParams({ tab: null });
    parseNow({ announceIt: true });
  }

  function forget() {
    resetSession();
    state.setSession('zone', undefined);
    ctx.setParams({ tab: null });
    toast(t('zone.forgotten'), { type: 'info' });
    render();
  }

  function goTab(tab) {
    S.tab = tab;
    ctx.setParams({ tab: tab === 'overview' ? null : tab });
    render();
  }

  /* --- render ------------------------------------------------------------ */
  function render() {
    clear(root);
    root.append(importCard());
    if (S.busy) {
      const size = (S.files || []).reduce((n, f) => n + f.size, 0);
      root.append(h('div', { class: 'zone-busy' }, Spinner({ label: t('zone.reading', { size: formatBytes(size) }), showLabel: true })));
      return;
    }
    if (S.fileError) root.append(Alert({ variant: 'error', title: t('zone.fatal.title'), message: S.fileError }));
    const z = S.zone;
    if (!z) return;
    if (z.fatal) {
      root.append(fatalBanner(z.fatal));
      return;
    }
    root.append(summaryBar(z), ...pinnedAlerts(z));
    const tabs = Tabs([
      { id: 'overview', label: t('zone.tab.overview'), content: () => overviewTab(z) },
      { id: 'records', label: t('zone.tab.records'), badge: S.counts.records, content: () => recordsTab(z) },
      { id: 'origins', label: t('zone.tab.origins'), badge: S.origins.length || null, content: () => originsTab(z) },
      { id: 'problems', label: t('zone.tab.problems'), badge: S.counts.errors || null, content: () => problemsTab() },
      { id: 'live', label: t('zone.tab.live'), content: () => liveTab(z) }
    ], {
      selected: S.tab,
      label: t('nav.zone'),
      className: 'zone-tabs',
      onChange: (tab) => {
        S.tab = tab;
        ctx.setParams({ tab: tab === 'overview' ? null : tab });
      }
    });
    if (S.counts.errors) tabs.setBadge('problems', S.counts.errors, 'error');
    root.append(tabs.el);
  }
  rerender = render;

  function importCard() {
    const drop = FileDrop({
      accept: ACCEPT,
      multiple: true,
      compact: !!S.zone,
      icon: 'upload',
      title: t('zone.drop.title'),
      hint: t('zone.drop.hint'),
      maxBytes: ZONE_LIMITS.maxBytes,
      className: 'zone-drop',
      onError: (msg) => {
        S.fileError = msg;
        render();
      },
      onFiles: (files) => importFiles(files)
    });
    const pasteArea = textarea({ label: t('zone.paste.label'), rows: 8, attrs: { 'data-role': 'zone-paste' } });
    const pasteBtn = Button({
      label: t('zone.import'),
      icon: 'arrow-down',
      variant: 'primary',
      size: 'sm',
      dataset: { action: 'zone-paste-import' },
      onClick: () => {
        const text = pasteArea.value;
        if (text.trim()) importFiles([{ name: t('file.pasted'), size: text.length, text }]);
      }
    });
    const originField = textInput({
      label: t('zone.origin.label'),
      value: S.originInput || (S.zone && S.zone.origin) || '',
      placeholder: t('zone.origin.placeholder'),
      mono: true,
      className: 'zone-origin-field',
      attrs: { 'data-role': 'zone-origin' },
      hint: S.zone && S.zone.originSource ? t(`zone.origin.from.${S.zone.originSource}`) : null,
      onChange: (v) => {
        const next = String(v || '').trim();
        if (!S.files || next === (S.originInput || (S.zone && S.zone.origin) || '')) return;
        S.originInput = next;
        S.confirmed = !!next;
        parseNow();
      }
    });
    if (S.zone && S.zone.fatal && S.zone.fatal.code === 'ORIGIN_REQUIRED') originField.setError(t('zone.origin.required'));
    const formatSel = select({
      label: t('zone.format.label'),
      value: S.formatInput,
      className: 'zone-format-field',
      options: [{ value: 'auto', label: t('zone.format.auto') }, ...ZONE_FORMATS.map((f) => ({ value: f, label: t(`zone.format.${f}`) }))],
      onChange: (v) => {
        S.formatInput = v;
        if (S.files) parseNow();
      }
    });
    const samples = h('div', { class: 'zone-samples cluster' },
      h('span', { class: 'muted text-sm' }, t('zone.samples')),
      SAMPLES.map((s) => Button({
        label: t(`zone.sample.${s.id}`),
        size: 'sm',
        variant: 'ghost',
        icon: 'file-text',
        dataset: { sample: s.id },
        onClick: () => importFiles([{ name: s.file, size: s.text.length, text: s.text }])
      })));
    const howto = Disclosure({
      summary: t('zone.howto'),
      className: 'zone-howto',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('zone.howto.cloudflare')),
        CodeBlock('curl -H "Authorization: Bearer $CF_API_TOKEN" https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/export > example.com.txt', { wrap: true }),
        h('p', { class: 'text-sm' }, t('zone.howto.route53')),
        CodeBlock('aws route53 list-resource-record-sets --hosted-zone-id Z0123456789 --output json > example.com.json', { wrap: true }),
        h('p', { class: 'text-sm' }, t('zone.howto.panel')),
        h('p', { class: 'text-sm' }, t('zone.howto.bind')),
        CodeBlock([
          'named-compilezone -o - example.com db.example.com',
          'pdnsutil list-zone example.com',
          'az network dns zone export -g RG -n example.com -f example.com.txt',
          'gcloud dns record-sets export example.com.txt --zone=ZONE --zone-file-format'
        ].join('\n'), { wrap: true }))
    });
    const body = h('div', { class: 'stack-sm' },
      drop.el || drop,
      h('div', { class: 'zone-import-fields' }, originField.el, formatSel.el),
      Disclosure({ summary: t('zone.paste.summary'), className: 'zone-paste', children: h('div', { class: 'stack-sm' }, pasteArea.el, h('div', { class: 'cluster' }, pasteBtn)) }),
      S.zone ? null : samples,
      S.zone ? null : howto);
    // With a zone loaded the importer folds away (open while the zone name still needs a look).
    if (S.zone && !S.zone.fatal) {
      return Disclosure({ summary: t('zone.replace'), className: 'zone-import zone-import-folded card', open: !originConfirmed(S.zone, S.confirmed), children: body });
    }
    return Card({
      title: S.zone ? null : t('zone.import.title'),
      subtitle: S.zone ? null : t('zone.import.subtitle'),
      icon: S.zone ? null : 'file-text',
      className: 'zone-import',
      children: body
    });
  }

  function fatalBanner(fatal) {
    const params = fatal.params || {};
    const hint = fatal.code === 'NOT_A_ZONE' && params.hint ? t(`zone.fatal.hint.${NOT_A_ZONE_HINTS.includes(params.hint) ? params.hint : 'unknown'}`) : null;
    const links = [];
    if (params.hint === 'pem') links.push(h('a', { href: ctx.href('cert'), class: 'link' }, t('nav.cert')));
    if (params.hint === 'csv' || params.hint === 'inventory') links.push(h('a', { href: ctx.href('inventory'), class: 'link' }, t('nav.inventory')));
    if (params.hint === 'names') links.push(h('a', { href: ctx.href('bulk'), class: 'link' }, t('nav.bulk')));
    return h('div', { class: 'zone-fatal', dataset: { code: fatal.code } }, Alert({
      variant: 'error',
      title: t('zone.fatal.title'),
      message: t(`zone.fatal.${fatal.code}`, params),
      children: hint || links.length ? h('div', { class: 'stack-sm' }, hint ? h('p', null, hint) : null, links.length ? h('div', { class: 'cluster' }, links) : null) : null
    }));
  }

  function summaryBar(z) {
    const c = S.counts;
    const files = S.files || [];
    const size = files.reduce((n, f) => n + f.size, 0);
    const lowOrigin = z.origin && !originConfirmed(z, S.confirmed);
    return h('div', { class: 'zone-summary card', dataset: { format: z.format || '', dialect: z.dialect || '' } },
      h('div', { class: 'zone-summary-main' },
        h('h2', { class: 'zone-summary-title', tabindex: -1 }, z.origin ? t('zone.sum.zone', { origin: z.origin }) : t('zone.sum.noOrigin')),
        h('div', { class: 'cluster zone-summary-meta' },
          Badge(fmtLabel(z), { variant: 'accent', title: (z.markers || []).join(' · ') || null, className: 'zone-format-badge' }),
          h('span', { class: 'zone-counts', dataset: { role: 'zone-counts' } },
            t('zone.sum.counts', { records: formatNumber(c.records), names: formatNumber(c.names), proxied: formatNumber(c.proxied) })),
          h('span', { class: 'muted text-sm zone-files' }, t('zone.sum.files', { files: files.map((f) => f.name).join(', '), size: formatBytes(size) })))),
      h('div', { class: 'zone-summary-actions cluster' },
        lowOrigin ? Button({
          label: t('zone.origin.confirm'),
          icon: 'check',
          size: 'sm',
          variant: 'primary',
          dataset: { action: 'zone-confirm' },
          onClick: () => {
            S.confirmed = true;
            publish();
            render();
          }
        }) : null,
        Button({ label: t('zone.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'zone-forget' }, onClick: forget })),
      lowOrigin ? h('p', { class: 'zone-guessed text-sm' }, Icon('alert', { size: 14 }), ' ', t('zone.origin.guessed')) : null);
  }

  function pinnedAlerts(z) {
    const out = [];
    const partial = z.warnings.find((w) => w.code === 'PARTIAL_EXPORT' || w.code === 'RECORDS_TRUNCATED');
    if (partial) {
      out.push(h('div', { class: 'zone-partial' }, Alert({ variant: 'error', title: t('zone.partial.title'), message: t(issueKey(partial.code, partial.params), partial.params) })));
    }
    const priv = S.addresses.filter((a) => a.private).length;
    if (S.addresses.length && priv / S.addresses.length >= 0.5) {
      out.push(Alert({ variant: 'warn', message: t('zone.internalZone', { private: formatNumber(priv), total: formatNumber(S.addresses.length) }) }));
    }
    return out;
  }

  /* --- overview ---------------------------------------------------------- */
  function overviewTab(z) {
    const c = S.counts;
    const exact = S.origins.filter((r) => r.kind === 'ip' || r.kind === 'host').length;
    const stat = (key, label, value, iconName, variant, onClick) => {
      const s = StatCard({ label, value, icon: iconName, variant, onClick });
      s.el.dataset.stat = key;
      return s.el;
    };
    const stats = h('div', { class: 'stat-grid zone-stats' },
      stat('names', t('zone.stat.names'), c.names, 'list', 'accent', () => goTab('records')),
      stat('proxied', t('zone.stat.proxied'), c.proxied, 'cloud', 'default', () => {
        S.rec = { ...S.rec, proxiedOnly: true };
        goTab('records');
      }),
      stat('dnsOnly', t('zone.stat.dnsOnly'), c.dnsOnly, 'globe', 'default', null),
      stat('origins', t('zone.stat.origins'), exact, 'server', exact ? 'ok' : 'default', () => goTab('origins')),
      stat('errors', t('zone.stat.errors'), c.errors, 'x-circle', c.errors ? 'error' : 'default', () => {
        S.probFilter = 'error';
        goTab('problems');
      }),
      stat('warnings', t('zone.stat.warnings'), c.warnings, 'alert', c.warnings ? 'warn' : 'default', () => {
        S.probFilter = 'warn';
        goTab('problems');
      }));

    const confirmed = originConfirmed(z, S.confirmed);
    const priv = privateLookingNames(z);
    const sweep = zoneSweep(z, { origins: S.origins });
    const hasProxied = sweep.names.length > 0;
    const sweepCard = Card({
      title: t('zone.next.sweep.title'),
      icon: 'terminal',
      className: 'zone-next-card',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, hasProxied
          ? t('zone.next.sweep.body', { names: formatNumber(sweep.names.length), targets: formatNumber(sweep.targets.length + sweep.hostTargets.length) })
          : t('zone.next.sweep.none')),
        h('div', { class: 'cluster' }, Button({
          label: t('zone.next.sweep.open'), size: 'sm', iconRight: 'arrow-right', dataset: { action: 'zone-open-origins' },
          onClick: () => {
            if (!hasProxied) S.sweep.scope = 'all';
            goTab('origins');
          }
        })))
    });

    const modeGroup = radioGroup({
      legend: t('zone.next.discover.legend'),
      name: 'zone-mode',
      value: S.mode,
      options: [{ value: 'exact', label: t('zone.next.discover.exact') }, { value: 'discover', label: t('zone.next.discover.full') }],
      onChange: (v) => {
        S.mode = v === 'discover' ? 'discover' : 'exact';
        note.hidden = S.mode !== 'discover';
      }
    });
    const note = h('p', { class: 'muted text-sm', hidden: S.mode !== 'discover' }, t('zone.next.discover.note'));
    const skip = checkbox({
      label: t('zone.next.skipInternal', { count: priv.size }),
      checked: S.skipInternal,
      onChange: (on) => {
        S.skipInternal = !!on;
        S.live.skipPrivate = !!on;
        publish();
      }
    });
    const scanBtn = Button({
      label: t('zone.next.run'), icon: 'play', variant: 'primary', size: 'sm', disabled: !confirmed, dataset: { action: 'zone-scan' },
      onClick: () => {
        publish();
        state.setSession('zoneScanIntent', buildIntent({ target: 'subdomains', domain: z.origin, mode: S.mode, autostart: true }));
        ctx.navigate('subdomains', { domain: z.origin });
      }
    });
    const discoverCard = Card({
      title: t('zone.next.discover.title'),
      icon: 'layers',
      className: 'zone-next-card zone-next-scan',
      children: h('div', { class: 'stack-sm' }, modeGroup.el, note, skip.el,
        h('div', { class: 'cluster' }, scanBtn, confirmed ? null : h('span', { class: 'muted text-sm' }, t('zone.next.needOrigin'))))
    });
    const certCard = Card({
      title: t('zone.next.cert.title'),
      icon: 'target',
      className: 'zone-next-card',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('zone.next.cert.body', { origin: z.origin || '?' })),
        h('div', { class: 'cluster' }, Button({
          label: t('zone.next.cert.run'), size: 'sm', iconRight: 'arrow-right', disabled: !confirmed, dataset: { action: 'zone-cert' },
          onClick: () => {
            publish();
            state.setSession('zoneScanIntent', buildIntent({ target: 'scan', domain: z.origin, mode: 'exact', autostart: false }));
            ctx.navigate('scan', { domain: z.origin });
          }
        })))
    });
    const plan = planDrift(z, { skipPrivate: S.live.skipPrivate, wildcardProbes: S.live.wildcards });
    const driftCard = Card({
      title: t('zone.next.drift.title'),
      icon: 'activity',
      className: 'zone-next-card',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('zone.next.drift.body', { queries: formatNumber(plan.queries) })),
        h('div', { class: 'cluster' }, Button({ label: t('zone.next.drift.open'), size: 'sm', iconRight: 'arrow-right', dataset: { action: 'zone-open-live' }, onClick: () => goTab('live') })))
    });

    const top = S.problems.filter((p) => p.severity !== 'info').slice(0, 3);
    return h('div', { class: 'stack zone-overview' },
      stats,
      h('h3', { class: 'zone-h3' }, t('zone.next.title')),
      h('div', { class: 'zone-next' }, discoverCard, sweepCard, certCard, driftCard),
      top.length ? Card({
        title: t('zone.top.title'),
        icon: 'alert',
        children: h('div', { class: 'stack-sm' }, h('ul', { class: 'zone-problems' }, top.map(problemItem)),
          h('div', { class: 'cluster' }, Button({ label: t('zone.top.all'), size: 'sm', variant: 'ghost', iconRight: 'arrow-right', onClick: () => goTab('problems') })))
      }) : null);
  }

  /* --- records ----------------------------------------------------------- */
  function recordsTab(z) {
    const origin = z.origin;
    const multi = (S.files || []).length > 1;
    const serverOf = (r) => {
      if (r.type !== 'A' && r.type !== 'AAAA') return '';
      const hit = S.addresses.find((a) => a.ip === r.text);
      return hit && hit.servers.length ? hit.servers.map((s) => s.name).join(', ') : '';
    };
    const notes = (r) => {
      const out = [];
      if (r.alias) out.push(t('zone.note.alias', { target: r.alias.target }));
      if (r.routing) out.push(t('zone.note.routing', { policy: r.routing.policy }));
      if (r.flattenCname) out.push(t('zone.note.flattened'));
      if (r.generated) out.push(t('zone.note.generated'));
      if (r.duplicateOf !== undefined) out.push(t('zone.note.duplicate'));
      if (r.invalid) out.push(t('zone.note.invalid'));
      if (r.intendedName) out.push(t('zone.note.intended', { served: r.name, intended: r.intendedName }));
      return out;
    };
    const table = DataTable({
      caption: t('zone.tab.records'),
      search: { placeholder: t('zone.records.search'), label: t('zone.records.search'), value: S.rec.search },
      pageSize: 200,
      rowKey: (r) => String(r.id),
      className: 'zone-records',
      rowClass: (r) => (S.rec.line && r.line === S.rec.line ? 'zone-row-hit' : null),
      filter: (r) => recordMatches(r, S.rec),
      export: { filename: 'zone-records', formats: ['csv', 'json'] },
      details: (r) => {
        const items = [];
        if (r.comment) items.push(h('div', null, h('strong', null, `${t('zone.detail.comment')}: `), r.comment));
        if (r.tags && Object.keys(r.tags).length) {
          items.push(h('div', { class: 'cluster' }, h('strong', null, `${t('zone.detail.tags')}:`),
            Object.keys(r.tags).map((k) => Badge(r.tags[k] ? `${k}: ${r.tags[k]}` : k, { variant: 'neutral', className: 'zone-tag' }))));
        }
        if (r.routing) items.push(h('div', { class: 'mono text-sm' }, JSON.stringify(r.routing)));
        const probs = S.problems.filter((p) => p.name === r.name && (!p.line || p.line === r.line));
        if (probs.length) items.push(h('ul', { class: 'zone-problems' }, probs.map(problemItem)));
        return items.length ? h('div', { class: 'stack-sm' }, items) : null;
      },
      columns: [
        { key: 'line', label: t('zone.col.line'), sortable: true, align: 'end', width: '4.5rem', className: 'num', sortValue: (r) => r.source * 1e7 + r.line,
          render: (r) => (multi ? `${(S.files[r.source] || {}).name || ''}:${r.line}` : String(r.line)), exportValue: (r) => r.line },
        { key: 'name', label: t('zone.col.name'), sortable: true, sortValue: (r) => r.name, searchValue: (r) => `${r.name} ${r.comment || ''}`, exportValue: (r) => r.name,
          render: (r) => {
            const rel = relativeName(r.name, origin);
            return h('span', { class: 'zone-name', title: r.name },
              h('strong', null, rel), rel !== r.name && rel !== '@' ? h('span', { class: 'muted' }, `.${origin}`) : null,
              r.intendedName ? h('span', { class: 'zone-intended', title: t('zone.note.intended', { served: r.name, intended: r.intendedName }) }, ' ', Icon('alert', { size: 13 })) : null);
          } },
        { key: 'type', label: t('zone.col.type'), sortable: true, width: '5.5rem', render: (r) => Badge(r.type, { variant: 'neutral', mono: true }), exportValue: (r) => r.type },
        { key: 'ttl', label: t('zone.col.ttl'), sortable: true, align: 'end', className: 'num', sortValue: (r) => r.ttl ?? -1, exportValue: (r) => (r.ttl ?? ''),
          render: (r) => (r.ttlAuto ? h('span', { title: t('zone.ttl.autoTitle') }, t('zone.ttl.auto')) : r.ttl === null ? '—' : formatNumber(r.ttl)) },
        { key: 'value', label: t('zone.col.value'), wrap: true, mono: true, searchValue: (r) => r.text || (r.alias ? r.alias.target : ''),
          exportValue: (r) => r.text || (r.alias ? `ALIAS ${r.alias.target}` : ''),
          render: (r) => {
            const v = r.text || (r.alias ? r.alias.target : '');
            return h('span', { class: 'zone-value', title: v.length > 120 ? v : null }, v.length > 120 ? `${v.slice(0, 80)}…${v.slice(-30)}` : v);
          } },
        { key: 'proxy', label: t('zone.col.proxy'), sortable: true, sortValue: (r) => (r.proxied === true ? 0 : r.proxied === false ? 1 : 2),
          exportValue: (r) => (r.proxied === true ? 'proxied' : r.proxied === false ? 'dns-only' : ''),
          render: (r) => (r.proxied === true ? Badge(t('zone.proxy.on'), { variant: 'cloudflare' }) : r.proxied === false ? h('span', { class: 'muted text-sm' }, t('zone.proxy.off')) : '') },
        { key: 'server', label: t('zone.col.server'), searchValue: serverOf, exportValue: serverOf, render: (r) => serverOf(r) },
        { key: 'notes', label: t('zone.col.notes'), wrap: true, searchValue: (r) => notes(r).join(' '), exportValue: (r) => notes(r).join('; '),
          render: (r) => h('span', { class: 'text-sm muted' }, notes(r).join(' · ')) }
      ],
      toolbar: [
        Button({
          label: t('zone.records.copyNames'), icon: 'copy', size: 'sm', variant: 'ghost', dataset: { action: 'zone-copy-names' },
          onClick: async () => {
            const names = zoneNames(z);
            const ok = await copyText(`${names.join('\n')}\n`);
            if (ok) toast(t('zone.records.namesCopied', { count: names.length }), { type: 'success' });
          }
        })
      ]
    });
    table.setRows(z.records);
    const typeSeg = SegmentedControl({
      label: t('zone.records.filter'),
      size: 'sm',
      className: 'zone-type-filter',
      value: S.rec.group,
      options: TYPE_GROUPS.map((g) => ({ value: g, label: g === 'all' ? t('zone.records.all') : g === 'addr' ? t('zone.records.addr') : g === 'other' ? t('zone.records.other') : g })),
      onChange: (v) => {
        S.rec = { ...S.rec, group: v, line: 0 };
        table.setFilter((r) => recordMatches(r, S.rec));
      }
    });
    const prox = checkbox({
      label: t('zone.records.proxiedOnly'),
      checked: S.rec.proxiedOnly,
      onChange: (on) => {
        S.rec = { ...S.rec, proxiedOnly: !!on };
        table.setFilter((r) => recordMatches(r, S.rec));
      }
    });
    prox.input.dataset.role = 'zone-proxied-only';
    return h('div', { class: 'stack-sm' }, h('div', { class: 'zone-filterbar cluster' }, typeSeg.el, prox.el), table.el);
  }

  /* --- origins ----------------------------------------------------------- */
  function originsTab(z) {
    const inventoryEmpty = !(state.inventory.servers || []).length;
    const serverCell = (servers) => (servers.length
      ? servers.map((s) => s.name).join(', ')
      : inventoryEmpty ? h('a', { href: ctx.href('inventory'), class: 'link text-sm' }, t('zone.origins.addServers')) : '');
    const kindText = (row) => t(`zone.kind.${row.kind}`, { provider: row.provider || '' });
    const exposure = (row) => row.exposure.map((e) => t(e.by === 'spf' ? 'zone.exposed.spf' : e.by === 'mx' ? 'zone.exposed.mx' : 'zone.exposed.sibling', { name: e.name })).join('; ');
    const originTable = DataTable({
      caption: t('zone.origins.title'),
      rowKey: (r) => r.name,
      className: 'zone-origins-table',
      pageSize: 500,
      export: false,
      rowClass: (r) => (r.exposure.length ? 'zone-row-exposed' : null),
      columns: [
        { key: 'name', label: t('zone.col.name'), sortable: true, render: (r) => h('strong', null, relativeName(r.name, z.origin)), searchValue: (r) => r.name },
        { key: 'origin', label: t('zone.col.origin'), mono: true, wrap: true,
          render: (r) => h('span', { class: 'zone-origin-cell' },
            r.kind === 'ip' ? r.ips.join(' ') : r.host || r.target || (r.ips || []).join(' '),
            r.via.length ? h('span', { class: 'muted text-sm' }, ` ${t('zone.origin.via', { name: r.via.join(' → ') })}`) : null,
            r.private ? h('span', { class: 'text-sm' }, ' ', Badge(t('zone.origin.private'), { variant: 'private' })) : null) },
        { key: 'kind', label: t('zone.col.kind'), wrap: true, render: (r) => h('span', { class: `zone-kind zone-kind-${r.kind}`, dataset: { kind: r.kind } }, kindText(r)) },
        { key: 'server', label: t('zone.col.server'), render: (r) => serverCell(r.servers) },
        { key: 'exposure', label: t('zone.col.exposure'), wrap: true,
          render: (r) => (r.exposure.length ? h('span', { class: 'zone-exposed' }, SeverityIcon('error'), ' ', exposure(r)) : '') }
      ]
    });
    originTable.setRows(S.origins);
    const addrTable = DataTable({
      caption: t('zone.origins.addTitle'),
      rowKey: (r) => r.ip,
      className: 'zone-addr-table',
      pageSize: 200,
      search: true,
      export: false,
      columns: [
        { key: 'ip', label: t('zone.col.ip'), mono: true, sortable: true, render: (r) => r.ip },
        { key: 'server', label: t('zone.col.server'), render: (r) => serverCell(r.servers) },
        { key: 'names', label: t('zone.col.names'), wrap: true, searchValue: (r) => r.names.map((n) => n.name).join(' '),
          render: (r) => h('span', { class: 'zone-addr-names' }, r.names.map((n) => h('span', { class: 'zone-addr-name' },
            relativeName(n.name, z.origin),
            n.proxied === true ? Badge(t('zone.proxy.on'), { variant: 'cloudflare' }) : null,
            n.exposed ? Badge(t('zone.addr.exposed'), { variant: 'error', icon: 'alert' }) : null))) },
        { key: 'flags', label: t('zone.col.notes'),
          render: (r) => h('span', { class: 'cluster' },
            r.private ? Badge(t('zone.addr.private'), { variant: 'private' }) : null,
            r.placeholder ? Badge(t('zone.addr.placeholder'), { variant: 'neutral' }) : null,
            r.provider === 'cloudflare' ? Badge(t('zone.addr.cloudflare'), { variant: 'cloudflare' }) : null) }
      ]
    });
    addrTable.setRows(S.addresses);

    const sweepBox = h('div', { class: 'stack-sm zone-sweep-body' });
    const renderSweep = () => {
      clear(sweepBox);
      const sw = zoneSweep(z, { scope: S.sweep.scope, shell: S.sweep.shell, origins: S.origins });
      const cmd = sweepCommand(sw);
      const targetCount = sw.targets.length + sw.hostTargets.length;
      if (!cmd.command) {
        sweepBox.append(h('p', { class: 'muted text-sm', dataset: { role: 'zone-sweep-empty' } }, t('zone.sweep.empty')));
      } else {
        sweepBox.append(h('p', { class: 'text-sm zone-estimate', dataset: { role: 'zone-estimate' } },
          t(sw.probesAtLeast ? 'zone.sweep.estimateAtLeast' : 'zone.sweep.estimate', {
            // The SNI names the CLI really sends per target (`*.x` is probed as x and as *.x), so
            // the multiplication on screen adds up.
            names: formatNumber(sweepProbeNames(sw, targetCount)), targets: formatNumber(targetCount), probes: formatNumber(sw.probes)
          })));
        if (cmd.fileForm) sweepBox.append(h('p', { class: 'text-sm' }, t('zone.sweep.fileForm')));
        sweepBox.append(CodeBlock(cmd.command, { wrap: true, className: 'zone-command' }));
        if (sw.probes > 20000) sweepBox.append(Alert({ variant: 'warn', compact: true, message: t('zone.sweep.many') }));
        const files = () => handoffFiles(sw, { origin: z.origin, inventoryIndex: ctx.getInventoryIndex() });
        sweepBox.append(h('div', { class: 'cluster' },
          Button({ label: t('zone.sweep.namesFile'), icon: 'download', size: 'sm', variant: cmd.fileForm ? 'primary' : 'secondary', dataset: { action: 'zone-names-file' }, onClick: () => downloadText(ZONE_NAMES_FILE, files().namesTxt) }),
          Button({ label: t('zone.sweep.targetsFile'), icon: 'download', size: 'sm', variant: cmd.fileForm ? 'primary' : 'secondary', dataset: { action: 'zone-targets-file' }, onClick: () => downloadText(ZONE_TARGETS_FILE, files().targetsTxt) }),
          h('a', { class: 'btn btn-ghost btn-sm', href: 'cli/ssl_origin_scan.py', download: 'ssl_origin_scan.py' }, Icon('download', { size: 14 }), h('span', { class: 'btn-label' }, t('zone.sweep.script')))));
      }
      if (sw.skipped.length) {
        sweepBox.append(h('p', { class: 'muted text-sm', dataset: { role: 'zone-skipped' } }, t('zone.sweep.skipped', {
          list: sw.skipped.map((s) => `${relativeName(s.name, z.origin)} (${t(`zone.kind.${s.kind}`, { provider: s.provider || '' })})`).join(' · ')
        })));
      }
    };
    const scopeSeg = SegmentedControl({
      label: t('zone.sweep.scope'), size: 'sm', value: S.sweep.scope, className: 'zone-scope',
      options: [{ value: 'proxied', label: t('zone.sweep.scope.proxied') }, { value: 'all', label: t('zone.sweep.scope.all') }],
      onChange: (v) => {
        S.sweep.scope = v;
        renderSweep();
      }
    });
    const shellSeg = SegmentedControl({
      label: t('zone.sweep.shell'), size: 'sm', value: S.sweep.shell, className: 'zone-shell',
      options: [{ value: 'posix', label: t('zone.sweep.posix') }, { value: 'powershell', label: t('zone.sweep.powershell') }],
      onChange: (v) => {
        S.sweep.shell = v;
        renderSweep();
      }
    });
    renderSweep();
    return h('div', { class: 'stack zone-origins' },
      Alert({ variant: 'warn', compact: true, message: t('zone.origins.privacy') }),
      Card({
        title: t('zone.origins.title'),
        subtitle: t('zone.origins.lead'),
        icon: 'cloud',
        children: S.origins.length ? originTable.el : EmptyState({ icon: 'cloud', title: t('zone.origins.none'), compact: true })
      }),
      Card({
        title: t('zone.sweep.title'),
        subtitle: t('zone.sweep.subtitle'),
        icon: 'terminal',
        className: 'zone-sweep',
        children: h('div', { class: 'stack-sm' }, h('div', { class: 'zone-sweep-controls cluster' }, scopeSeg.el, shellSeg.el), sweepBox)
      }),
      Card({ title: t('zone.origins.addTitle'), subtitle: t('zone.origins.addSubtitle'), icon: 'network', children: addrTable.el }));
  }

  /* --- problems ---------------------------------------------------------- */
  function problemTitle(p) {
    return p.source === 'lint' ? t(`zone.lint.${p.code}`, p.params) : t(issueKey(p.code, p.params), p.params);
  }

  function problemItem(p) {
    const sev = p.severity === 'warn' ? 'warn' : p.severity === 'error' ? 'error' : 'info';
    return h('li', { class: 'zone-problem', dataset: { code: p.code, severity: sev } },
      SeverityIcon(sev),
      h('div', { class: 'zone-problem-body' },
        h('div', { class: 'zone-problem-title' }, problemTitle(p)),
        p.source === 'lint' ? h('div', { class: 'text-sm' }, t(`zone.lint.${p.code}.why`, p.params)) : null,
        p.name || p.line ? h('button', {
          type: 'button',
          class: 'link-btn text-sm zone-problem-link',
          dataset: { name: p.name, line: p.line },
          title: t('zone.problems.show'),
          on: {
            click: () => {
              S.rec = { group: 'all', proxiedOnly: false, search: p.name || '', line: p.line || 0 };
              goTab('records');
            }
          }
        }, [p.name, p.type, p.line ? t('zone.problems.line', { line: p.line }) : ''].filter(Boolean).join(' · ')) : null));
  }

  function problemsTab() {
    if (!S.problems.length) return EmptyState({ icon: 'check-circle', title: t('zone.problems.none') });
    const list = h('ul', { class: 'zone-problems zone-problems-all' });
    const fill = () => {
      clear(list);
      list.append(...S.problems.filter((p) => S.probFilter === 'all' || p.severity === S.probFilter).map(problemItem));
    };
    const seg = SegmentedControl({
      label: t('zone.problems.filter'),
      size: 'sm',
      value: S.probFilter,
      className: 'zone-prob-filter',
      options: [
        { value: 'all', label: `${t('zone.problems.all')} (${S.problems.length})` },
        { value: 'error', label: `${t('zone.problems.errors')} (${S.counts.errors})` },
        { value: 'warn', label: `${t('zone.problems.warnings')} (${S.counts.warnings})` },
        { value: 'info', label: `${t('zone.problems.info')} (${S.counts.info})` }
      ],
      onChange: (v) => {
        S.probFilter = v;
        fill();
      }
    });
    fill();
    const copyBtn = Button({
      label: t('zone.problems.copy'), icon: 'copy', size: 'sm', variant: 'ghost', dataset: { action: 'zone-copy-problems' },
      onClick: async () => {
        const text = S.problems.map((p) => `[${p.severity.toUpperCase()}] ${problemTitle(p)} — ${[p.name, p.type, p.line ? t('zone.problems.line', { line: p.line }) : ''].filter(Boolean).join(' ')}`).join('\n');
        if (await copyText(`${text}\n`)) toast(t('zone.problems.copied'), { type: 'success' });
      }
    });
    return h('div', { class: 'stack-sm' }, h('div', { class: 'zone-filterbar cluster' }, seg.el, copyBtn), list);
  }

  /* --- live check -------------------------------------------------------- */
  function liveTab(z) {
    const box = h('div', { class: 'stack zone-live' });
    const L = S.live;
    const confirmed = originConfirmed(z, S.confirmed);
    const plan = planDrift(z, { skipPrivate: L.skipPrivate, wildcardProbes: L.wildcards });
    const chain = state.settings.chain.map((rid) => (getResolver(rid) || { name: rid }).name);
    const priv = privateLookingNames(z);

    const runDrift = async () => {
      abortDrift();
      const ac = new AbortController();
      controller = ac;
      S.live = { ...L, status: 'running', rows: [], result: null, done: 0, total: plan.rrsets, error: null, filter: 'all' };
      if (liveHook) liveHook.render();
      try {
        const dns = await ctx.getDns();
        const result = await driftZone(z, {
          dns,
          signal: ac.signal,
          skipPrivate: S.live.skipPrivate,
          wildcardProbes: S.live.wildcards,
          onRow: (row) => {
            if (controller !== ac) return;
            S.live.rows.push(row);
          },
          onProgress: ({ done, total }) => {
            if (controller !== ac) return;
            S.live.done = done;
            S.live.total = total;
            if (liveHook) liveHook.progress();
          }
        });
        if (controller !== ac) return;
        controller = null;
        S.live.result = result;
        S.live.rows = result.rows;
        S.live.status = result.aborted ? 'cancelled' : 'done';
        if (!result.aborted) {
          const diffs = result.rows.filter((r) => DRIFT_SEVERITY[r.status] === 'warn' || DRIFT_SEVERITY[r.status] === 'error').length;
          if (!document.querySelector('.zone-live')) {
            toast(t('zone.live.finished', { count: diffs }), { type: diffs ? 'warn' : 'success', action: { label: t('zone.tab.live'), onClick: () => ctx.navigate('zone', { tab: 'live' }) } });
          }
        }
      } catch (err) {
        if (controller !== ac) return;
        controller = null;
        S.live.status = 'failed';
        S.live.error = err && err.message ? err.message : String(err);
      }
      if (liveHook) liveHook.render();
    };

    let progressEl = null;
    const updateProgress = () => {
      if (!progressEl) return;
      // The label carries the count too: keep it in step with the bar (it was frozen at render).
      progressEl.setLabel(t('zone.live.progress', { done: formatNumber(S.live.done), total: formatNumber(S.live.total) }));
      progressEl.set(S.live.done, Math.max(1, S.live.total));
    };
    function renderLiveIfShown() {
      if (!box.isConnected) return;
      clear(box);
      fillLive();
    }

    function fillLive() {
      const cur = S.live;
      if (!confirmed) {
        box.append(Alert({ variant: 'info', message: t('zone.live.needOrigin') }));
        return;
      }
      const skipBox = checkbox({
        label: t('zone.live.skipPrivate', { count: priv.size }),
        checked: cur.skipPrivate,
        onChange: (on) => {
          S.live.skipPrivate = !!on;
          renderLiveIfShown2();
        }
      });
      const wildBox = checkbox({
        label: t('zone.live.wildcards'),
        checked: cur.wildcards,
        onChange: (on) => {
          S.live.wildcards = !!on;
          renderLiveIfShown2();
        }
      });
      skipBox.input.dataset.role = 'zone-live-skip';
      wildBox.input.dataset.role = 'zone-live-wildcards';
      const running = cur.status === 'running';
      const runBtn = Button({
        label: cur.status === 'idle' ? t('zone.live.run', { rrsets: formatNumber(plan.rrsets) }) : t('zone.live.rerun'),
        icon: 'play',
        variant: 'primary',
        disabled: running,
        dataset: { action: 'zone-live-run' },
        onClick: runDrift
      });
      box.append(Card({
        title: t('zone.live.title'),
        icon: 'activity',
        className: 'zone-live-card',
        children: h('div', { class: 'stack-sm' },
          h('p', { class: 'zone-live-lead', dataset: { role: 'zone-live-lead', queries: plan.queries } },
            t('zone.live.lead', { rrsets: formatNumber(plan.rrsets), queries: formatNumber(plan.queries), resolvers: chain.join(', ') })),
          h('p', { class: 'text-sm muted' }, t('zone.live.sent')),
          plan.internalShare >= 0.5 ? Alert({ variant: 'warn', compact: true, message: t('zone.internalZone', { private: formatNumber(Math.round(plan.internalShare * 100)), total: '100' }) }) : null,
          plan.overBudget ? Alert({ variant: 'info', compact: true, message: t('zone.live.budget', { max: formatNumber(plan.maxQueries) }) }) : null,
          h('div', { class: 'cluster' }, skipBox.el, wildBox.el),
          h('div', { class: 'cluster' }, runBtn,
            running ? Button({ label: t('zone.live.cancel'), icon: 'x', variant: 'secondary', dataset: { action: 'zone-live-cancel' }, onClick: () => { if (controller) controller.abort(); } }) : null))
      }));
      if (running) {
        progressEl = ProgressBar({ label: t('zone.live.progress', { done: formatNumber(cur.done), total: formatNumber(cur.total) }), value: cur.done, max: Math.max(1, cur.total) });
        box.append(h('div', { class: 'zone-live-progress', dataset: { status: 'running' } }, progressEl.el || progressEl));
        return;
      }
      progressEl = null;
      if (cur.status === 'failed') box.append(Alert({ variant: 'error', message: t('zone.live.failed', { message: cur.error || '' }) }));
      if (cur.status === 'cancelled') box.append(Alert({ variant: 'info', message: t('zone.live.stopped', { done: formatNumber(cur.done), total: formatNumber(cur.total) }) }));
      if (cur.result || cur.rows.length) box.append(driftResults(z, cur));
    }
    function renderLiveIfShown2() {
      // Options change the plan (counts in the card): rebuild the whole tab, and give the focus
      // back to the option that was toggled (keyboard and screen-reader users keep their place).
      const panel = box.parentElement;
      if (!panel) return;
      const active = document.activeElement;
      const role = active && box.contains(active) ? active.dataset.role : null;
      clear(panel);
      panel.append(liveTab(z));
      const again = role ? panel.querySelector(`[data-role="${role}"]`) : null;
      if (again) again.focus();
    }
    liveHook = { render: renderLiveIfShown, progress: updateProgress };
    fillLive();
    return box;
  }

  function valueLines(values) {
    return h('span', { class: 'zone-values' }, values.map((v) => h('span', null, v)));
  }

  function driftResults(z, cur) {
    const out = h('div', { class: 'stack-sm zone-drift', dataset: { status: cur.status } });
    const pf = cur.result && cur.result.preflight;
    if (pf) {
      if (!pf.originExists) out.append(Alert({ variant: 'error', message: t('zone.live.noOrigin', { origin: z.origin }) }));
      if (pf.serial === 'newer') out.append(Alert({ variant: 'info', compact: true, message: t('zone.live.soaNewer', { live: pf.liveSerial, file: pf.fileSerial }) }));
      if (pf.nsMatch === 'disjoint') out.append(Alert({ variant: 'warn', compact: true, message: t('zone.live.nsDisjoint') }));
    }
    const counts = {};
    for (const r of cur.rows) counts[r.status] = (counts[r.status] || 0) + 1;
    const sevVariant = (s) => ({ ok: 'ok', info: 'info', warn: 'warn', error: 'error' }[DRIFT_SEVERITY[s]] || 'neutral');
    const sec = secrets();
    const table = DataTable({
      caption: t('zone.tab.live'),
      rowKey: (r) => r.key,
      pageSize: 200,
      search: true,
      className: 'zone-drift-table',
      filter: (r) => cur.filter === 'all' || r.status === cur.filter,
      export: { filename: 'zone-drift', formats: ['csv', 'json'] },
      columns: [
        { key: 'status', label: t('zone.col.status'), sortable: true, exportValue: (r) => r.status,
          render: (r) => h('span', { dataset: { status: r.status } }, Badge(t(`zone.drift.${r.status}`), { variant: sevVariant(r.status) })) },
        { key: 'name', label: t('zone.col.name'), sortable: true, render: (r) => h('strong', null, relativeName(r.name, z.origin)), exportValue: (r) => r.name },
        { key: 'type', label: t('zone.col.type'), sortable: true, render: (r) => Badge(r.type, { variant: 'neutral', mono: true }) },
        { key: 'file', label: t('zone.col.file'), mono: true, wrap: true, searchValue: (r) => r.file.join(' '),
          exportValue: (r) => redactValues(r.file, sec, S.live.includeOrigins).join(' '), render: (r) => valueLines(r.file) },
        { key: 'live', label: t('zone.col.live'), mono: true, wrap: true, searchValue: (r) => r.live.join(' '),
          exportValue: (r) => redactValues(r.live, sec, S.live.includeOrigins).join(' '),
          render: (r) => (r.status === 'differs'
            ? h('span', { class: 'zone-diff' }, r.removed.map((v) => h('span', { class: 'zone-diff-del' }, `− ${v}`)), r.added.map((v) => h('span', { class: 'zone-diff-add' }, `+ ${v}`)))
            : valueLines(r.live)) },
        { key: 'note', label: t('zone.col.note'), wrap: true, exportValue: (r) => r.reasons.join(' '),
          render: (r) => h('span', { class: 'text-sm' }, r.reasons.map((x) => t(`zone.reason.${x}`)).join(' ')) }
      ]
    });
    table.setRows(cur.rows);
    const chips = h('div', { class: 'zone-chips cluster', attrs: { role: 'group', 'aria-label': t('zone.col.status') } });
    const chip = (value, label, n) => h('button', {
      type: 'button',
      class: 'zone-chip',
      dataset: { filter: value },
      attrs: { 'aria-pressed': String(cur.filter === value) },
      on: {
        click: () => {
          cur.filter = value;
          chips.querySelectorAll('.zone-chip').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === value)));
          table.setFilter((r) => cur.filter === 'all' || r.status === cur.filter);
        }
      }
    }, value === 'all' ? null : SeverityIcon(DRIFT_SEVERITY[value] === 'unknown' ? 'info' : DRIFT_SEVERITY[value]), `${label} (${n})`);
    chips.append(chip('all', t('zone.live.allStatuses'), cur.rows.length));
    for (const s of DRIFT_STATUSES) if (counts[s]) chips.append(chip(s, t(`zone.drift.${s}`), counts[s]));
    const inc = checkbox({
      label: t('zone.live.includeOrigins'),
      checked: S.live.includeOrigins,
      onChange: (on) => {
        S.live.includeOrigins = !!on;
      }
    });
    inc.input.dataset.role = 'zone-include-origins';
    out.append(chips, inc.el, table.el);
    return out;
  }

  reindexServers(ctx.getInventoryIndex());
  render();

  teardown = () => {
    rerender = null;
    liveHook = null;
  };
}

let teardown = null;

/** Detach the view (the zone and a running live check stay in module memory). */
export function unmount() {
  if (teardown) teardown();
  teardown = null;
}

export default { id, titleKey, icon, mount, unmount };
