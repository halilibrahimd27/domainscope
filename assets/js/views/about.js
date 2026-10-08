/**
 * views/about.js — where to start (the start page's job cards, always listed here), how the
 * toolkit works, data sources & quotas, privacy, what this page sent (the page session's ledger of
 * requests, ui/egress-panel.js), the companion CLI (download + usage), self-hosting on GitHub
 * Pages, credits and license.
 *
 * Route params: `#/about?section=sent` (the footer's "What this page sent") scrolls to that
 * section and puts the focus on its heading, then drops the param so the link works again.
 */

import { h } from '../ui/dom.js';
import {
  Alert, Badge, ButtonLink, Button, CliText, CodeBlock, Disclosure, ExternalLink, Icon, Section, confirmDialog
} from '../ui/components.js';
import { registerStrings, formatDate, formatNumber, formatRegion } from '../i18n.js';
import { RESOLVERS, RESOLVERS_VERIFIED, GEO_VANTAGES, DEFAULT_CHAIN, getResolver } from '../lib/resolvers.js';
import { RANGES_UPDATED, PROVIDERS } from '../lib/netinfo.js';
import { StartTaskList } from '../ui/start-tasks.js';
import { deleteAllLocalData } from '../ui/workspace-ui.js';
import { EgressPanel } from '../ui/egress-panel.js';

/** Route id. */
export const id = 'about';
/** i18n key of the page title. */
export const titleKey = 'nav.about';
/** Nav/page icon. */
export const icon = 'info';

/** Path of the CLI relative to the site root (published by the Pages workflow). */
export const CLI_PATH = 'cli/ssl_origin_scan.py';
/** The DNS provider move's CLI (Zone File › New name servers hands it the zone). */
export const PARITY_CLI_PATH = 'cli/dns_parity.py';
/** The reverse-IP CLI: the names an address serves or served, from inside your network. */
export const IP_INTEL_CLI_PATH = 'cli/ip_intel.py';

/**
 * The wordlist and data licence texts, resolved from this module: the Pages bundle serves assets/ under
 * v/<version>/ (tools/assemble-site.mjs), so a page-relative 'assets/…' link would miss it.
 */
export const LICENSES_URL = new URL('../../data/THIRD_PARTY_LICENSES.txt', import.meta.url).href;

/**
 * Where "View source" opens the CLI: GitHub's file view. GitHub Pages serves .py files as
 * application/octet-stream, so the site's own copy would download instead of showing.
 * @param {string} repoUrl e.g. ctx.repoUrl
 * @returns {string}
 */
export function cliSourceUrl(repoUrl) {
  return `${String(repoUrl).replace(/\/+$/, '')}/blob/main/${CLI_PATH}`;
}

/**
 * "Cloudflare, Google, DNS.SB, CZ.NIC" — the display names of the default resolver chain
 * (lib/resolvers DEFAULT_CHAIN), used in "How it works".
 * @returns {string}
 */
export function defaultChainNames() {
  return DEFAULT_CHAIN.map((rid) => (getResolver(rid) || { name: rid }).name).join(', ');
}

registerStrings('en', {
  'about.heroTitle': 'SSL & DNS toolkit for people who run many servers',
  'about.heroBody': 'A renewed certificate for *.example.com arrives and it has to be installed everywhere it is used. DomainScope discovers the names it covers that DNS and public data reveal, resolves them, recognises Cloudflare and other proxies, and matches the answers to your own server inventory — so you know which machines need the new certificate.',
  'about.heroStatic': 'Everything runs in your browser against public, CORS-enabled APIs. There is no backend and nothing to install; the companion CLI covers the one thing a browser cannot do.',
  'about.start': 'Find subdomains',
  'about.downloadCli': 'Download the CLI',
  'about.source': 'Source code',
  'about.onThisPage': 'On this page',
  'about.toc.how': 'How it works',
  'about.toc.cloudflare': 'Cloudflare & CDNs',
  'about.toc.sources': 'Sources & quotas',
  'about.toc.privacy': 'Privacy',
  'about.toc.sent': 'What this page sent',
  'about.toc.cli': 'CLI',
  'about.toc.selfhost': 'Self-hosting',
  'about.toc.license': 'License',

  'about.howTitle': 'How it works',
  'about.howDesc': 'Five steps, each of which you can also use on its own through the other tools.',
  'about.step1Title': 'Collect names',
  'about.step1Body': 'The domain’s own DNS records (MX, NS, SPF, SRV …), a ranked wordlist — with a word pack for the domain’s market, your own custom list and names learned from your earlier scans if you switch that on — and variations of the names found, plus Certificate Transparency logs (crt.sh, Cert Spotter), passive DNS (HackerTarget, Anubis, AlienVault OTX, ip.thc.org) and the names inside your certificate. Sources disagree, so they are merged. A name that exists only inside the zone and appears nowhere else stays hidden unless it is in your own list; only a zone export is complete, and you can import one under Zone File.',
  'about.step2Title': 'Resolve over HTTPS',
  'about.step2Body': 'Your browser asks public DNS-over-HTTPS resolvers directly ({resolvers} by default; change them in Settings), with automatic failover. Global DNS repeats a query from {count} resolvers and 30+ locations.',
  'about.step3Title': 'Classify',
  'about.step3Body': 'Answer IPs and CNAME chains are compared with the official ranges of Cloudflare, Fastly, CloudFront and others, and with platform domains, so proxies are never mistaken for your servers.',
  'about.step4Title': 'Match your servers',
  'about.step4Body': 'Direct IPs are looked up in your inventory: the result is the list of servers that need the certificate, plus IPs you do not know yet.',
  'about.step5Title': 'Confirm from inside',
  'about.step5Body': 'For names behind a proxy, the CLI connects to your servers’ own IPs with SNI and reads the certificate each one serves — including whether it is already the new one.',

  'about.cfTitle': 'Why Cloudflare hides your servers',
  'about.cfBody1': 'With Cloudflare’s proxy (the orange cloud) — or any CDN/WAF — public DNS answers with the proxy’s addresses, not yours. Every DNS-based tool therefore sees the same edge IPs, and online scanners disagree about the rest.',
  'about.cfBody2': 'The certificate still has to be installed on the origin servers behind the proxy (unless the proxy terminates TLS with its own certificate). The only reliable way to find them is to ask them: connect to each server IP and request the hostname via SNI.',
  'about.cfBody3': 'The browser cannot open raw TLS connections, so this last step is done by the companion CLI, run from a machine inside your network. The web app prepares its input: names.txt and targets.txt.',
  'about.flowPublic': 'What public DNS shows',
  'about.flowCli': 'What the CLI checks',
  'about.flowVisitor': 'Visitor',
  'about.flowEdge': 'Cloudflare edge',
  'about.flowOrigin': 'Your server',
  'about.flowHidden': 'hidden',
  'about.flowJump': 'Jump host',
  'about.flowSni': 'TLS, SNI = name',
  'about.flowCert': 'serves cert ✓',
  'about.cfHints': 'The scan also collects origin hints that can point to the real servers: answers of other public resolvers, the networks of the non-proxied names, SPF records, MX hosts, the same name on a sister domain scanned together and historical DNS from before Cloudflare was enabled — candidates to confirm with the CLI, whose command the page writes for Linux / macOS or Windows PowerShell. An imported zone file gives the exact origins instead of candidates.',

  'about.sourcesTitle': 'Data sources & quotas',
  'about.sourcesDesc': 'Only services that allow browser access (CORS) are used. Free tiers have limits — when one is reached the tool says so and continues with the others.',
  'about.col.source': 'Source',
  'about.col.provides': 'Provides',
  'about.col.limits': 'Limits & notes',
  'about.src.crtsh': 'Certificate Transparency search: every name that appeared in a public certificate. On request, also where to download one host name’s certificate (Certificate, SSL Targets), the issuers of a domain’s current certificates when Cert Spotter cannot answer (Domain overview), the other certificates with the same public key (Certificate › CT logs › Key continuity), and the current certificates of a domain’s top lookalikes (Domain overview › Lookalike domains, one search each).',
  'about.src.crtshLimit': 'Free. Can be slow or briefly unavailable under load: retried with growing pauses, then a lighter search — up to about 3 minutes when it keeps timing out; Cert Spotter covers it meanwhile.',
  'about.src.certspotter': 'Certificate Transparency issuances with names and fingerprints. On request, also one host name’s current certificate (Certificate, SSL Targets) and the issuers of a domain’s current certificates (Domain overview, one request).',
  'about.src.certspotterLimit': 'Small anonymous hourly quotas per IP address (HTTP 429 when used up): about 10 full-domain searches (a scan uses up to 5 per registrable domain) and, separately, 100 single-host requests (one host name’s certificate; about 50 lookups, two requests each).',
  'about.src.hackertarget': 'Host search (names + current IPs) and reverse IP lookup.',
  'about.src.hackertargetLimit': 'About 50 requests per day per IP address, shared by both endpoints.',
  'about.src.anubis': 'Subdomain database.',
  'about.src.anubisLimit': 'Free, no key.',
  'about.src.otx': 'Passive DNS including historical IPs — often the pre-Cloudflare origin — and the names seen on an address (Domains on this IP).',
  'about.src.otxLimit': 'Anonymous access is frequently rate-limited.',
  'about.src.thc': 'Subdomain database with the date each name was last seen, and the names seen on an address (Retire an IP, Domains on this IP).',
  'about.src.robtex': 'Passive DNS: the names seen pointing at an address, with when (Domains on this IP).',
  'about.src.robtexLimit': 'Free, no key; rate-limited.',
  'about.src.shodan': 'InternetDB: the host names, open ports, tags and known vulnerabilities of an address, without a key; the Shodan API’s host names and domains with your own key (Domains on this IP).',
  'about.src.shodanLimit': 'InternetDB is free for non-commercial use, and a burst of requests locks it for about an hour: one request per address, on a click. The API counts against your plan.',
  'about.src.whoisxml': 'Reverse IP with your own key: the domains on an address, with when they were seen (Domains on this IP).',
  'about.src.whoisxmlLimit': 'One credit of your account per address.',
  'about.src.thcLimit': 'Free, no key. About 250 requests per IP, refilling one every 2 s; pages are fetched 2 s apart (up to 1,000 names).',
  'about.src.doh': 'All DNS answers; EDNS Client Subnet for the geographic view.',
  'about.src.dohLimit': 'Public resolvers from your Settings chain; parallelism follows Settings (subdomain scans use up to twice that value, at most 24).',
  'about.src.ripe': 'ASN, prefix, holder, geolocation and reverse DNS of IP addresses; the owner of an origin network when you click “Look up owner”; the prefixes an AS announces when you list them in Reverse DNS; the RPKI validity, routing status and abuse contact of an address when you press “Check routing” in IP Intel.',
  'about.src.peeringdb': 'The network type, name and website of an address’s origin AS, when you press “Check routing” in IP Intel.',
  'about.src.peeringdbLimit': 'Free; anonymous use is throttled, so this page asks about one AS every 4 seconds, each AS once.',
  'about.src.ripeLimit': 'Free, fair use.',
  'about.src.ipwho': 'Fallback geolocation and ASN.',
  'about.src.ipwhoLimit': 'Free tiers with daily limits.',
  'about.src.rdap': 'Domain registration: registrar, dates, status flags, name servers, DNSSEC (Domain Health, Domain overview and its lookalikes in DNS; the Domain portfolio also asks for its name servers’ own domains, once each).',
  'about.src.rdapLimit': 'IANA bootstrap + the registries’ own servers; rdap.org only as the fallback, at most one request a second (left alone for a minute after it answers “rate limited”). Some country TLDs (for example .de, .jp, .tr) publish no RDAP service.',
  'about.src.globalping': 'Globalping (jsDelivr): TLS checks of your public server addresses from probes worldwide (SSL Targets › Verify), and one HTTPS fetch of a domain’s MTA-STS policy (Domain Health).',
  'about.src.globalpingLimit': '250 probes per hour per IP address without an account, shared by Verify and the MTA-STS check; results are public by measurement ID for about six months.',
  'about.resolversTitle': 'The {count} DNS-over-HTTPS resolvers (verified {date})',
  'about.res.name': 'Resolver',
  'about.res.location': 'Location',
  'about.res.features': 'Features',
  'about.rangesNote': 'CDN IP ranges from official sources, updated {date} ({count} providers recognised by IP range or CNAME).',
  'about.vantagesNote': 'Global DNS compares {count} vantage points in {countries} countries via EDNS Client Subnet: Google Public DNS for most of them, AliDNS’s JSON API for the mainland China ones (its standard DoH endpoint cannot be read from a page).',

  'about.privacyTitle': 'Privacy',
  'about.privacyDesc': 'Designed so sensitive data never leaves your machine, except what you choose to check from the internet: the public IP / host name pairs in Verify, a domain’s MTA-STS policy host in Domain Health, a zone’s record names asked at its new name servers and the old and new address of a server you move.',
  'about.privMove': 'Only when you press Compare: Zone File › New name servers sends the record names and types it asks, with the new name servers, to Globalping, whose probes ask those servers directly (the values, the origin addresses and the names that look internal stay here); Retire an IP › Compare the old and the new server sends the two public addresses with the host name, port and path, and one probe sends an HTTPS GET to each. Each asks for consent once per page session, private addresses are never sent (the CLI’s dns_parity.py and ssl_origin_scan.py --compare work from inside your network), and anyone with a measurement ID can read the results for about six months. The comparisons are made here.',
  'about.priv1': 'No backend, no analytics, no cookies, no tracking.',
  'about.priv2': 'Certificates are parsed in your browser. Private keys are never needed; if a file contains one it is ignored and never displayed.',
  'about.privChain': 'A missing intermediate is looked up in this site’s own copy of the CCADB list of public intermediates: the page reads a few small files of the site (usually one or two), each chosen by the first two hex digits of the key identifier of an intermediate it looks for (or, for a certificate that names no key identifier, by the first hex digit of a SHA-256 hash of its issuer’s name), and never sends the certificate anywhere. Those files are not kept for offline use, so a lookup needs a connection.',
  'about.priv3': 'Workspaces: each keeps its own server inventory, learned subdomain names (only if you switch them on: bare labels such as “api”, never full hostnames or IP addresses), custom wordlist, expected CAs, notes, the domains you worked on in it and its origin map. They live in this browser’s IndexedDB (the database “ssds.workspaces”); only a pointer to the workspace you use, the settings and remembered options are in its local storage (keys starting with “ssds.”). Both belong to the site’s origin: on a GitHub Pages project site (<user>.github.io/<repo>/) every other Pages project of the same account shares that origin and could read them, so a copy that keeps customer data should have an origin of its own. A workspace leaves this browser only as a hand-over file you export yourself, encrypted if you give it a password (never stored; the file name then leaves the workspace’s name out too). Learned and custom names are tried as DNS lookups under the domains you scan in their workspace (label.domain), so the DNS resolvers and those domains’ nameservers see them. All of it can be deleted at any time.',
  'about.priv4': 'What third parties see: domain names you scan go to the CT / passive-DNS services and DoH resolvers, and a host name whose certificate you load (Certificate, SSL Targets) or a domain whose certificate issuers you look up (Domain overview) to Cert Spotter and crt.sh, the lookalike names of a domain you check (Domain overview › Lookalike domains) to the DoH resolvers, the ones in DNS to RDAP and, on request, the top ten to crt.sh, and the public-key hash of a certificate whose key you look up (Certificate › CT logs) to crt.sh; IP addresses you inspect go to RIPEstat and ipwho.is, the network addresses whose owner you look up and the AS numbers whose prefixes you list go to RIPEstat, and a reverse DNS sweep sends the reverse names of the addresses and the names found to the DoH resolvers. As with any website, they also see your IP address.',
  'about.priv5': 'Requests carry no referrer, so services do not learn which page you used.',
  'about.privIpEnrich': 'Only when you press “Check routing” in an IP Intel row’s details: the address, its announced prefix and its origin AS number go to RIPEstat (RPKI validation, routing status, abuse contact), and the AS number to PeeringDB. Nothing is sent for a private, reserved or documentation address. The address ranges and which of your servers are in them are worked out in this browser: your server list is never sent.',
  'about.privZone': 'An imported zone file is read in your browser and kept only in this tab’s memory: it is never uploaded or saved, and a reload, Forget or “Delete all local data” clears it. Only what you click sends anything: the Live check, or a scan of the zone’s names that you start, sends record names (and the Live check their types; never the values or origin addresses) to your DNS resolvers — a scan that also runs discovery asks the passive sources about the domain as usual. Names that look internal are skipped by default.',
  'about.privZoneFetch': 'Fetch from deSEC or DigitalOcean (Zone File) sends the zone name and the API token you paste to that provider only, and only from a click. The token stays in this tab’s memory for that one fetch: it is never saved (not in the browser, not in a workspace), never logged or sent anywhere else, and its field is emptied as soon as the fetch starts. Use a read-only token.',
  'about.privRetire': 'Retire an IP compares the addresses in your browser. A check sends the names it looks up to your DNS resolvers: each domain’s own name and records, the host names this page session knows, and the zone file’s records that point at the address (a wildcard record: a random name under it) — never a host name the zone file marks as internal, and its own domain is not filled in when it looks internal; a domain you type in is checked as typed. Only on a click, the passive lookup sends each address to HackerTarget and ip.thc.org (never a private one), and a discovery sends its wordlist guesses as DNS lookups.',
  'about.privReverseIp': 'Only when you press Find domains (IP Intel › Domains on this IP): each public address goes to HackerTarget, ip.thc.org, AlienVault OTX, Robtex and Shodan InternetDB, and with a key you type there to the Shodan API or WhoisXML; its reverse name and the names found go to your DNS resolvers. A key stays in its field in this tab: it is never saved, logged, put in a link or exported. A private or reserved address is never sent anywhere: only what your workspace knows about it is shown. Names that look internal and names only your workspace knows (the origin map) are never sent either.',
  'about.privTakeover': 'Takeover risks (Subdomains › Overview) sends nothing until you press its button. Then it asks your DNS resolvers for the scanned hosts’ CNAME chains and the domains’ NS, MX and SPF records, and sends each registrable domain those records point to, outside the scanned domains, to that domain’s registry over RDAP (to rdap.org only when the registry cannot be reached). The optional page check sends up to ten of the host names to Globalping, whose probes fetch http://<host>/ once each: it asks for consent once per page session, and anyone with a measurement ID can read the results for about six months. The results stay in this tab’s memory.',
  'about.privReports': 'DMARC & TLS reports reads the report files in your browser and keeps them only in this tab’s memory: they are never uploaded or saved, nothing about them goes into a link, and a reload, Forget, another workspace or “Delete all local data” drops them. After a drop it looks up the current SPF record of each reported domain, and what that record includes, over your DNS resolvers (names and types only); the reverse DNS and network of a sending address go to your resolvers and to RIPEstat / ipwho.is only when you press Look up, never for a private address.',
  'about.privOffline': 'The app’s own files — and a wordlist tier once a scan has used it — are kept in this browser’s cache by a service worker, so DomainScope starts without a connection and can be installed as an app; Certificate, Certificate estate, Zone File, DNS change request, DMARC & TLS reports, Servers and About then work offline. The offline copy never holds anything you type, import or look up, nor any answer from a third party.',
  'about.priv6': 'Only when you press “Check from the internet”: each public IP, host name and port pair goes to Globalping, whose results anyone with the measurement ID can read for about six months. Private addresses are never sent. The optional origin check (off by default) also sends an origin IP from your inventory together with the proxied name it serves, so the public measurement shows that this server answers for that name behind the CDN; turn it on only for origins whose address may be known. The certificate never leaves your browser; the comparison is local.',
  'about.priv7': 'Only when you press “Check the policy” on Domain Health’s MTA-STS card: the host name mta-sts.<domain> and the policy path go to Globalping (after a consent dialog, once per page session), one probe fetches the policy over HTTPS, and anyone with the measurement ID can read the result, the policy and the server’s response headers included, for about six months. The comparison with the MX hosts is local.',
  'about.clearData': 'Delete all local data',
  'about.privSession': 'The current target (the domain, host name or IP address you last worked on) and each tool’s last result are kept only in this tab’s memory: never uploaded, and a reload, closing the tab, another workspace or “Delete all local data” forgets them. The domains and host names you work on are also saved in the current workspace’s list of recent domains (IndexedDB), so switching back to it fills the last one in again; the Workspaces dialog clears the list. A tool you open next has the target filled in and sends nothing until you press its button; coming back to a tool shows its last result without querying again.',
  'about.privOrigins': 'The origin map: only once you turn on “Remember origins in this workspace” (Servers › Origin map; off by default), the workspace remembers which of your servers and ports really serves a name behind a CDN: a zone file’s origins when you press Remember these origins, the CLI reports you import there, Verify’s checks of remembered and zone-file origins (never of a mere candidate) and a server comparison you choose to remember. It is kept with the workspace in this browser’s IndexedDB and sent nowhere: scans use it here to rank origins and to write the CLI command. It leaves the browser only inside a workspace hand-over file you export yourself; Forget the origin map, deleting the workspace or “Delete all local data” removes it.',
  'about.clearConfirm': 'Delete every workspace (the IndexedDB database with all their servers, learned names, custom wordlists, expected CAs, notes, recent domains and origin maps), all settings and a loaded zone file from this browser, and forget the current target and the kept results? This cannot be undone: export a workspace first to keep a copy.',

  'about.cliTitle': 'Companion CLI: ssl_origin_scan.py',
  'about.cliDesc': 'Maps hostnames to servers by TLS-probing your inventory IPs with SNI — sees through Cloudflare because it talks to your servers directly. Run it from a machine inside your network (e.g. a jump host).',
  'about.cliReq': 'Python 3.8+, standard library only, a single file. Linux, macOS and Windows.',
  'about.viewSource': 'View source',
  'about.ex1': 'Renewal day — which servers still serve the old certificate?',
  'about.ex2': 'Names and targets exported from this app, ports 443 and 8443',
  'about.ex3': 'Reports for scripts (JSON) and Excel (CSV)',
  'about.ex4': 'A subnet and two names, no certificate (“who hosts these?”)',
  'about.ex5': 'CI / cron — exit code 1 while any server still needs the new certificate',
  'about.ex6': 'Internal hosts signed by your own CA are PRIVATE_CERT, not NEEDS_UPDATE; an address with its own port is scanned on that port',
  'about.ex7': 'Cron — changes since the last run and certificates expiring within 21 days (set DOMAINSCOPE_NOTIFY_URL for Slack, Teams, Discord, Telegram or Google Chat)',
  'about.ex8': 'Before DNS moves a name to a new server: the old and the new server’s answers side by side (private addresses too)',
  'about.exStarttls': 'Mail and database servers — STARTTLS on 25, 587 and 5432, SMTP on 2525 too — with a TLS audit: versions, weak cipher suites, RSA + ECDSA pairs',
  'about.parityDesc': 'Moving DNS to another provider: asks the new name servers for every record set of a zone file, from your machine, and lists what is missing, different or extra there. Python 3.8+, a single file.',
  'about.parityEx': 'Zone File › New name servers downloads the zone and gives this command',
  'about.ipIntelDesc': 'Reverse IP from inside your network: the names an address, a range or a list serves or served — its TLS certificates with and without SNI, PTR, free passive DNS (mnemonic too, which no browser can ask) and the services of your own keys, read from environment variables only — and where each name points now. A private address goes to no third party. Python 3.8+, a single file.',
  'about.ipIntelEx': 'The names of an address and of a range in your network, with a JSON report',
  'about.statusesTitle': 'Result statuses',
  'about.st.UPDATED': 'Serves the new certificate for the name.',
  'about.st.NEEDS_UPDATE': 'Serves a certificate that covers the name, but not the new one — install it here.',
  'about.st.ORIGIN_CERT': 'Serves a Cloudflare Origin CA certificate, which only Cloudflare trusts: right for an origin behind Cloudflare Full (strict) while its names stay proxied. Listed apart, not counted as needing the new certificate (--strict-public counts it).',
  'about.st.PRIVATE_CERT': 'Serves a self-signed certificate, or one issued by a CA you list with --private-ca: usual on internal hosts. Listed apart, not counted as needing the new certificate (--strict-public counts it).',
  'about.st.NOT_HOSTED': 'Answers, but not for this name (only a default certificate).',
  'about.st.TLS_ERROR': 'The TLS handshake failed.',
  'about.st.TIMEOUT': 'No answer within the timeout.',
  'about.st.CLOSED': 'The port is closed.',

  'about.selfhostTitle': 'Run it yourself',
  'about.selfhostBody': 'It is a static site with no build step. To publish your own copy, fork the repository, enable workflows on the fork’s Actions tab, set Settings › Pages › Source to “GitHub Actions”, then push to main or run the “Deploy to GitHub Pages” workflow once (it publishes only after the tests pass). Or serve the folder locally:',

  'about.licenseTitle': 'Credits & license',
  'about.licenseBody': 'Open source under the MIT license. Contributions and issue reports are welcome.',
  'about.thanks': 'Thanks to the operators of the free services listed above, which make a backend-free tool like this possible.',
  'about.version': 'Version {version}',
  'about.wordlistCredits': 'The bundled subdomain wordlists are built from SecLists, bitquark and dnsgen (MIT) and commonspeak2 and altdns (Apache-2.0).',
  'about.ccadbCredits': 'The intermediate certificates and root store data behind the Certificate view’s missing-intermediate repair come from the Common CA Database (CCADB), under the Community Data License Agreement – Permissive 2.0.',
  'about.wordlistLicenses': 'Wordlist and data licences'
});

registerStrings('tr', {
  'about.heroTitle': 'Çok sayıda sunucu yönetenler için SSL & DNS araç kutusu',
  'about.heroBody': '*.example.com için yenilenmiş bir sertifika geldi ve kullanıldığı her yere kurulması gerekiyor. DomainScope sertifikanın kapsadığı ve DNS ile açık verilerde görünen adları bulur, çözümler, Cloudflare ve diğer proxy’leri tanır ve yanıtları kendi sunucu envanterinizle eşleştirir — böylece yeni sertifikanın hangi makinelere kurulacağını bilirsiniz.',
  'about.heroStatic': 'Her şey tarayıcınızda, CORS destekli genel API’lere karşı çalışır. Sunucu yok, kurulacak bir şey yok; tarayıcının yapamadığı tek işi yardımcı CLI aracı üstlenir.',
  'about.start': 'Subdomain’leri bul',
  'about.downloadCli': 'CLI aracını indir',
  'about.source': 'Kaynak kod',
  'about.onThisPage': 'Bu sayfada',
  'about.toc.how': 'Nasıl çalışır',
  'about.toc.cloudflare': 'Cloudflare ve CDN’ler',
  'about.toc.sources': 'Kaynaklar ve kotalar',
  'about.toc.privacy': 'Gizlilik',
  'about.toc.sent': 'Bu sayfa ne gönderdi',
  'about.toc.cli': 'CLI',
  'about.toc.selfhost': 'Kendin barındır',
  'about.toc.license': 'Lisans',

  'about.howTitle': 'Nasıl çalışır',
  'about.howDesc': 'Beş adım; her biri diğer araçlar üzerinden tek başına da kullanılabilir.',
  'about.step1Title': 'Adları topla',
  'about.step1Body': 'Alan adının kendi DNS kayıtları (MX, NS, SPF, SRV …), sıralanmış bir kelime listesi — alan adının pazarına uygun kelime paketi, sizin özel listeniz ve (açarsanız) önceki taramalarınızdan öğrenilen adlarla — ve bulunan adların varyasyonları; ayrıca Certificate Transparency kayıtları (crt.sh, Cert Spotter), pasif DNS (HackerTarget, Anubis, AlienVault OTX, ip.thc.org) ve sertifikanızdaki adlar. Kaynaklar birbirini tutmaz; bu yüzden birleştirilir. Yalnızca bölge (zone) içinde olup başka hiçbir yerde geçmeyen bir ad, kendi listenizde yoksa gizli kalır; eksiksiz olan tek liste bölgenin dışa aktarımıdır, onu da Zone Dosyası’nda içe aktarabilirsiniz.',
  'about.step2Title': 'HTTPS üzerinden çözümle',
  'about.step2Body': 'Tarayıcınız genel DNS-over-HTTPS çözümleyicilerine (varsayılan olarak {resolvers}; Ayarlar’dan değiştirilebilir) doğrudan, otomatik yedeklemeyle sorar. Global DNS aynı sorguyu {count} çözümleyiciden ve 30’dan fazla konumdan tekrarlar.',
  'about.step3Title': 'Sınıflandır',
  'about.step3Body': 'Yanıttaki IP’ler ve CNAME zincirleri Cloudflare, Fastly, CloudFront ve diğerlerinin resmî IP aralıkları ve platform alan adlarıyla karşılaştırılır; böylece proxy’ler asla sizin sunucunuz sanılmaz.',
  'about.step4Title': 'Sunucularınızla eşleştir',
  'about.step4Body': 'Doğrudan IP’ler envanterinizde aranır: sonuç, sertifikanın kurulması gereken sunucuların listesi ve henüz tanımadığınız IP’lerdir.',
  'about.step5Title': 'İçeriden doğrula',
  'about.step5Body': 'Proxy arkasındaki adlar için CLI aracı sunucularınızın kendi IP’lerine SNI ile bağlanır ve her birinin sunduğu sertifikayı okur — yeni sertifikanın kurulup kurulmadığı dahil.',

  'about.cfTitle': 'Cloudflare sunucularınızı neden gizler',
  'about.cfBody1': 'Cloudflare proxy’si (turuncu bulut) — ya da herhangi bir CDN/WAF — açıkken genel DNS sizin değil, proxy’nin adreslerini döndürür. Bu yüzden DNS tabanlı her araç aynı uç (edge) IP’leri görür ve çevrimiçi tarayıcılar gerisinde birbirini tutmaz.',
  'about.cfBody2': 'Sertifikanın yine de proxy’nin arkasındaki asıl (origin) sunuculara kurulması gerekir (proxy TLS’i kendi sertifikasıyla sonlandırmıyorsa). Bunları bulmanın tek güvenilir yolu onlara sormaktır: her sunucu IP’sine bağlanıp host adını SNI ile istemek.',
  'about.cfBody3': 'Tarayıcı ham TLS bağlantısı açamaz; bu son adımı ağınızın içindeki bir makinede çalışan yardımcı CLI aracı yapar. Web uygulaması girdisini hazırlar: names.txt ve targets.txt.',
  'about.flowPublic': 'Genel DNS’in gösterdiği',
  'about.flowCli': 'CLI aracının kontrol ettiği',
  'about.flowVisitor': 'Ziyaretçi',
  'about.flowEdge': 'Cloudflare uç sunucusu',
  'about.flowOrigin': 'Sizin sunucunuz',
  'about.flowHidden': 'gizli',
  'about.flowJump': 'Atlama sunucusu',
  'about.flowSni': 'TLS, SNI = ad',
  'about.flowCert': 'sertifikayı sunar ✓',
  'about.cfHints': 'Tarama ayrıca gerçek sunuculara işaret edebilecek ipuçlarını da toplar: diğer genel çözümleyicilerin yanıtları, proxy’lenmeyen adların ağları, SPF kayıtları, MX sunucuları, birlikte taranan kardeş bir alan adındaki aynı ad ve Cloudflare açılmadan önceki geçmiş DNS kayıtları — CLI ile doğrulanacak adaylar; sayfa bunun komutunu Linux / macOS ya da Windows PowerShell için yazar. İçe aktarılan bir zone dosyası ise aday değil, kesin origin’leri verir.',

  'about.sourcesTitle': 'Veri kaynakları ve kotalar',
  'about.sourcesDesc': 'Yalnızca tarayıcıdan erişime (CORS) izin veren hizmetler kullanılır. Ücretsiz katmanların sınırları vardır — biri dolduğunda araç bunu söyler ve diğerleriyle devam eder.',
  'about.col.source': 'Kaynak',
  'about.col.provides': 'Sağladığı',
  'about.col.limits': 'Sınırlar ve notlar',
  'about.src.crtsh': 'Certificate Transparency araması: genel bir sertifikada geçmiş her ad. İstendiğinde bir host adının sertifikasının nereden indirileceği (Sertifika, SSL Hedefleri), Cert Spotter yanıt veremediğinde bir alan adının geçerli sertifikalarını verenler (Alan adı özeti), aynı açık anahtarı taşıyan diğer sertifikalar (Sertifika › CT kayıtları › Anahtar sürekliliği) ve bir alan adının en riskli benzerlerinin geçerli sertifikaları da (Alan adı özeti › Benzer alan adları, her biri için bir arama).',
  'about.src.crtshLimit': 'Ücretsiz. Yoğunlukta yavaş ya da kısa süre erişilemez olabilir: giderek uzayan aralarla yeniden denenir, sonra daha hafif bir aramaya geçilir — zaman aşımları sürerse yaklaşık 3 dakikaya kadar; bu sırada Cert Spotter devreye girer.',
  'about.src.certspotter': 'Adları ve parmak izleriyle Certificate Transparency kayıtları. İstendiğinde bir host adının geçerli sertifikası (Sertifika, SSL Hedefleri) ve bir alan adının geçerli sertifikalarını verenler de (Alan adı özeti, tek istek).',
  'about.src.certspotterLimit': 'Anonim kullanımda IP adresi başına küçük saatlik kotalar (dolunca HTTP 429): yaklaşık 10 tam alan adı araması (bir tarama her kayıtlı alan adı için en fazla 5 kullanır) ve bundan ayrı olarak tek host için 100 istek (bir host adının sertifikası; her sorgu iki istek, yani saatte yaklaşık 50 sorgu).',
  'about.src.hackertarget': 'Host araması (adlar + güncel IP’ler) ve ters IP sorgusu.',
  'about.src.hackertargetLimit': 'IP adresi başına günde yaklaşık 50 istek; iki uç nokta aynı kotayı paylaşır.',
  'about.src.anubis': 'Alt alan adı veritabanı.',
  'about.src.anubisLimit': 'Ücretsiz, anahtar gerekmez.',
  'about.src.otx': 'Geçmiş IP’ler dahil pasif DNS — çoğu zaman Cloudflare öncesi asıl sunucu — ve bir adreste görülen adlar (Bu IP’deki alan adları).',
  'about.src.otxLimit': 'Anonim erişim sık sık hız sınırına takılır.',
  'about.src.thc': 'Her adın en son ne zaman görüldüğünü de veren alt alan adı veritabanı; bir adreste görülen adlar da (IP emekliye ayırma, Bu IP’deki alan adları).',
  'about.src.robtex': 'Pasif DNS: bir adresi gösterdiği görülen adlar ve ne zaman görüldükleri (Bu IP’deki alan adları).',
  'about.src.robtexLimit': 'Ücretsiz, anahtar gerekmez; hız sınırlı.',
  'about.src.shodan': 'InternetDB: bir adresin host adları, açık portları, etiketleri ve bilinen güvenlik açıkları, anahtarsız; kendi anahtarınızla Shodan API’nin host adları ve alan adları (Bu IP’deki alan adları).',
  'about.src.shodanLimit': 'InternetDB ticari olmayan kullanım için ücretsizdir; art arda istekler onu yaklaşık bir saat kilitler: adres başına bir istek, yalnızca tıklayınca. API, planınızdan düşer.',
  'about.src.whoisxml': 'Kendi anahtarınızla ters IP: bir adresteki alan adları ve ne zaman görüldükleri (Bu IP’deki alan adları).',
  'about.src.whoisxmlLimit': 'Adres başına hesabınızdan bir kredi.',
  'about.src.thcLimit': 'Ücretsiz, anahtar gerekmez. IP başına yaklaşık 250 istek, 2 saniyede bir yenilenir; sayfalar 2 saniye arayla alınır (en fazla 1.000 ad).',
  'about.src.doh': 'Tüm DNS yanıtları; coğrafi görünüm için EDNS Client Subnet.',
  'about.src.dohLimit': 'Ayarlar’daki zincirde bulunan genel çözümleyiciler; paralellik Ayarlar’a göre belirlenir (subdomain taramaları bu değerin en fazla iki katını, en çok 24 kullanır).',
  'about.src.ripe': 'IP adreslerinin ASN, önek, sahip, konum ve ters DNS bilgisi; “Sahibini bul”a tıkladığınızda bir origin ağının sahibi; Ters DNS’te listelediğinizde bir AS’in duyurduğu önekler; IP Bilgisi’nde “Yönlendirmeyi kontrol et”e bastığınızda bir adresin RPKI geçerliliği, yönlendirme durumu ve abuse iletişim adresi.',
  'about.src.peeringdb': 'IP Bilgisi’nde “Yönlendirmeyi kontrol et”e bastığınızda bir adresin kaynak AS’inin ağ türü, adı ve web sitesi.',
  'about.src.peeringdbLimit': 'Ücretsiz; anonim kullanım yavaşlatıldığı için bu sayfa yaklaşık 4 saniyede bir AS sorar, her AS’i bir kez.',
  'about.src.ripeLimit': 'Ücretsiz, adil kullanım.',
  'about.src.ipwho': 'Yedek konum ve ASN bilgisi.',
  'about.src.ipwhoLimit': 'Günlük sınırlı ücretsiz katmanlar.',
  'about.src.rdap': 'Alan adı kaydı: kayıt firması, tarihler, durum işaretleri, ad sunucuları, DNSSEC (Alan Adı Sağlığı, Alan adı özeti ve DNS’te olan benzerleri; Alan adı portföyü ad sunucularının kendi alan adlarını da birer kez sorar).',
  'about.src.rdapLimit': 'IANA bootstrap + kayıt kuruluşlarının kendi sunucuları; rdap.org yalnızca yedek olarak, saniyede en fazla bir istekle (“hız sınırı” yanıtından sonra bir dakika sorulmaz). Bazı ülke uzantılarının (ör. .de, .jp, .tr) RDAP hizmeti yok.',
  'about.src.globalping': 'Globalping (jsDelivr): genel sunucu adreslerinizin dünya çapındaki ölçüm noktalarından TLS kontrolü (SSL Hedefleri › Doğrula) ve bir alan adının MTA-STS politikasının HTTPS ile bir kez alınması (Alan Adı Sağlığı).',
  'about.src.globalpingLimit': 'Hesapsız IP adresi başına saatte 250 ölçüm; Doğrula ve MTA-STS kontrolü bu kotayı paylaşır. Sonuçlar ölçüm kimliğiyle yaklaşık altı ay herkese açık.',
  'about.resolversTitle': '{count} DNS-over-HTTPS çözümleyicisi ({date} tarihinde doğrulandı)',
  'about.res.name': 'Çözümleyici',
  'about.res.location': 'Konum',
  'about.res.features': 'Özellikler',
  'about.rangesNote': 'CDN IP aralıkları resmî kaynaklardan, {date} tarihinde güncellendi (IP aralığı veya CNAME ile tanınan {count} sağlayıcı).',
  'about.vantagesNote': 'Global DNS, EDNS Client Subnet ile {countries} ülkedeki {count} gözlem noktasını karşılaştırır: çoğu için Google Public DNS’e, anakara Çin’dekiler için AliDNS’in JSON API’sine sorar (standart DoH uç noktası bir sayfadan okunamıyor).',

  'about.privacyTitle': 'Gizlilik',
  'about.privacyDesc': 'Hassas verilerin makinenizden hiç çıkmaması için tasarlandı; istisna, internetten kontrol etmeyi seçtiklerinizdir: Doğrula’daki genel IP / host adı çiftleri, Alan Adı Sağlığı’nda bir alan adının MTA-STS politika sunucusu, yeni ad sunucularına sorulan zone kayıt adları ve taşıdığınız bir sunucunun eski ve yeni adresi.',
  'about.privMove': 'Yalnızca Karşılaştır’a bastığınızda: Zone Dosyası › Yeni ad sunucuları, sorduğu kayıt adlarını ve türlerini yeni ad sunucularıyla birlikte Globalping’e gönderir; ölçüm noktaları bu sunuculara doğrudan sorar (değerler, origin adresleri ve iç ağa ait görünen adlar burada kalır). IP emekliye ayırma › Eski ve yeni sunucuyu karşılaştırın ise iki genel adresi host adı, port ve yolla birlikte gönderir; bir ölçüm noktası her adrese bir HTTPS GET isteği yollar. Her ikisi de sayfa oturumu başına bir kez onay ister, özel adresler asla gönderilmez (CLI’daki dns_parity.py ve ssl_origin_scan.py --compare ağınızın içinden çalışır) ve ölçüm kimliğini bilen herkes sonuçları yaklaşık altı ay okuyabilir. Karşılaştırmalar burada yapılır.',
  'about.priv1': 'Sunucu yok, analitik yok, çerez yok, izleme yok.',
  'about.priv2': 'Sertifikalar tarayıcınızda ayrıştırılır. Özel anahtar hiçbir zaman gerekmez; dosyada varsa yok sayılır ve asla gösterilmez.',
  'about.privChain': 'Eksik bir ara sertifika, CCADB’nin herkese açık ara sertifika listesinin bu sitedeki kopyasında aranır: sayfa, aradığı her ara sertifikanın anahtar kimliğinin ilk iki onaltılık basamağına (anahtar kimliği belirtmeyen bir sertifikada, onu verenin adının SHA-256 özetinin ilk onaltılık basamağına) göre seçilen birkaç küçük site dosyasını (çoğunlukla bir ya da iki) okur ve sertifikayı hiçbir yere göndermez. Bu dosyalar çevrimdışı kullanım için saklanmaz; bu yüzden arama için bağlantı gerekir.',
  'about.priv3': 'Çalışma alanları: her biri kendi sunucu envanterini, öğrenilen subdomain adlarını (yalnızca açarsanız: “api” gibi yalın etiketler; asla tam host adları ya da IP adresleri değil), özel kelime listesini, beklenen CA’larını, notlarını, içinde çalıştığınız alan adlarını ve origin haritasını tutar. Bunlar bu tarayıcının IndexedDB deposunda (“ssds.workspaces” veritabanı) durur; yerel depolamada (“ssds.” ile başlayan anahtarlar) yalnızca kullandığınız çalışma alanına bir işaret, ayarlar ve hatırlanan seçenekler bulunur. İkisi de sitenin kaynağına (origin) aittir: bir GitHub Pages proje sitesinde (<kullanıcı>.github.io/<depo>/) aynı hesabın diğer tüm Pages projeleri bu kaynağı paylaşır ve bunları okuyabilir; müşteri verisi tutacak bir kopyanın kendine ait bir kaynağı olmalıdır. Bir çalışma alanı bu tarayıcıdan yalnızca sizin dışa aktardığınız devir dosyası olarak çıkar; parola verirseniz (asla saklanmaz) şifrelenir ve dosya adında da çalışma alanının adı yer almaz. Öğrenilen ve özel adlar, kendi çalışma alanında taradığınız alan adlarının altında DNS sorgusu olarak denenir (etiket.alanadı); yani DNS çözümleyicileri ve o alan adlarının ad sunucuları bunları görür. Hepsi istediğiniz an silinebilir.',
  'about.priv4': 'Üçüncü tarafların gördükleri: taradığınız alan adları CT / pasif DNS hizmetlerine ve DoH çözümleyicilerine, sertifikasını yüklediğiniz host adı (Sertifika, SSL Hedefleri) ya da sertifika sağlayıcılarını sorguladığınız alan adı (Alan adı özeti) Cert Spotter ve crt.sh’e, kontrol ettiğiniz bir alan adının benzer adları (Alan adı özeti › Benzer alan adları) DoH çözümleyicilerine, DNS’te olanlar RDAP’a ve istendiğinde en riskli on tanesi crt.sh’e, anahtarını sorguladığınız bir sertifikanın açık anahtar özeti (Sertifika › CT kayıtları) crt.sh’e; incelediğiniz IP adresleri RIPEstat ve ipwho.is’e, sahibini sorguladığınız ağ adresleri ve öneklerini listelediğiniz AS numaraları RIPEstat’a gider; bir ters DNS taraması ise adreslerin ters adlarını ve bulunan adları DoH çözümleyicilerine gönderir. Her web sitesinde olduğu gibi IP adresinizi de görürler.',
  'about.priv5': 'İstekler referrer bilgisi taşımaz; hizmetler hangi sayfayı kullandığınızı öğrenmez.',
  'about.privIpEnrich': 'Yalnızca IP Bilgisi’nde bir satırın ayrıntılarında “Yönlendirmeyi kontrol et”e bastığınızda: adres, duyurulan öneki ve kaynak AS numarası RIPEstat’a (RPKI doğrulaması, yönlendirme durumu, abuse iletişimi), AS numarası ise PeeringDB’ye gider. Özel, ayrılmış ya da dokümantasyon adresleri için hiçbir şey gönderilmez. Adres aralıkları ve sunucularınızdan hangilerinin bu aralıklarda olduğu bu tarayıcıda hesaplanır: sunucu listeniz asla gönderilmez.',
  'about.privZone': 'İçe aktardığınız zone dosyası tarayıcınızda okunur ve yalnızca bu sekmenin belleğinde tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut ya da “Tüm yerel verileri sil” onu siler. Yalnızca tıkladığınız işlemler bir şey gönderir: Canlı kontrol ya da başlattığınız bir zone adları taraması, DNS çözümleyicilerinize kayıt adlarını (Canlı kontrol türlerini de; değerleri ya da origin adreslerini asla) gönderir — keşfi de çalıştıran bir tarama, her zamanki gibi alan adını pasif kaynaklara sorar. İç ağa ait görünen adlar varsayılan olarak atlanır.',
  'about.privZoneFetch': 'deSEC ya da DigitalOcean’dan getir (Zone Dosyası), zone adını ve yapıştırdığınız API anahtarını yalnızca o sağlayıcıya ve yalnızca bir tıklamayla gönderir. Anahtar yalnızca o tek okuma için bu sekmenin belleğinde durur: hiçbir yere kaydedilmez (ne tarayıcıya ne bir çalışma alanına), günlüğe yazılmaz ya da başka bir yere gönderilmez ve okuma başladığı anda alanı boşaltılır. Salt okunur bir anahtar kullanın.',
  'about.privRetire': 'IP emekliye ayırma adresleri tarayıcınızda karşılaştırır. Bir kontrol, sorguladığı adları DNS çözümleyicilerinize gönderir: her alan adının kendi adı ve kayıtları, bu sayfa oturumunun bildiği host adları ve zone dosyasının adresi gösteren kayıtları (joker bir kayıt için altındaki rastgele bir ad) — zone dosyasının iç ağa ait saydığı bir host adını asla; zone’un kendi alan adı da iç ağa ait görünüyorsa kutuya eklenmez. Kutuya yazdığınız bir alan adı yazdığınız gibi kontrol edilir. Yalnızca tıkladığınızda pasif sorgu her adresi HackerTarget ve ip.thc.org’a gönderir (özel adresleri asla), bir keşif de kelime listesi tahminlerini DNS sorgusu olarak gönderir.',
  'about.privReverseIp': 'Yalnızca Alan adlarını bul’a bastığınızda (IP Bilgisi › Bu IP’deki alan adları): her genel adres HackerTarget, ip.thc.org, AlienVault OTX, Robtex ve Shodan InternetDB’ye, orada yazdığınız bir anahtarla da Shodan API’ye ya da WhoisXML’e gider; ters adı ve bulunan adlar DNS çözümleyicilerinize gönderilir. Anahtar bu sekmede kendi alanında kalır: hiçbir yere kaydedilmez, günlüğe yazılmaz, bir bağlantıya konmaz ya da dışa aktarılmaz. Özel ya da ayrılmış bir adres hiçbir yere gönderilmez: yalnızca çalışma alanınızın onun hakkında bildikleri gösterilir. İç ağa ait görünen adlar ve yalnızca çalışma alanınızın bildiği adlar (origin haritası) da gönderilmez.',
  'about.privTakeover': 'Ele geçirme riskleri (Subdomain Tarama › Genel bakış), düğmesine basana kadar hiçbir şey göndermez. Bastığınızda taranan host’ların CNAME zincirlerini ve alan adlarının NS, MX ve SPF kayıtlarını DNS çözümleyicilerinize sorar; bu kayıtların gösterdiği, taranan alan adları dışındaki her alan adını da RDAP üzerinden kendi kayıt kuruluşuna gönderir (kayıt kuruluşuna ulaşılamazsa yalnızca rdap.org’a). İsteğe bağlı sayfa kontrolü host adlarından en fazla onunu Globalping’e gönderir; ölçüm noktaları her biri için http://<host>/ adresini bir kez getirir. Sayfa oturumu başına bir kez onay ister ve ölçüm kimliğini bilen herkes sonuçları yaklaşık altı ay okuyabilir. Sonuçlar bu sekmenin belleğinde kalır.',
  'about.privReports': 'DMARC ve TLS raporları, rapor dosyalarını tarayıcınızda okur ve yalnızca bu sekmenin belleğinde tutar: hiçbir yere yüklenmez ya da kaydedilmez, hiçbir bağlantıya girmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler. Dosyaları bıraktığınızda raporlanan her alan adının güncel SPF kaydını ve bu kaydın içerdiklerini DNS çözümleyicileriniz üzerinden sorgular (yalnızca adlar ve türler); gönderen bir adresin ters DNS ve ağ bilgisi ise yalnızca Sorgula’ya bastığınızda çözümleyicilerinize ve RIPEstat / ipwho.is’e gider, özel bir adres için asla.',
  'about.privOffline': 'Uygulamanın kendi dosyaları — ve bir taramanın kullandığı kelime listesi katmanları — bir service worker tarafından bu tarayıcının önbelleğinde tutulur; böylece DomainScope bağlantı olmadan açılır ve uygulama olarak yüklenebilir; Sertifika, Sertifika envanteri, Zone Dosyası, DNS değişiklik talebi, DMARC ve TLS raporları, Sunucular ve Hakkında da çevrimdışı çalışır. Çevrimdışı kopya yazdığınız, içe aktardığınız ya da sorguladığınız hiçbir şeyi ve üçüncü tarafların hiçbir yanıtını tutmaz.',
  'about.priv6': 'Yalnızca “İnternetten kontrol et”e bastığınızda: her genel IP, host adı ve port çifti Globalping’e gider; sonuçları ölçüm kimliğini bilen herkes yaklaşık altı ay okuyabilir. Özel adresler asla gönderilmez. İsteğe bağlı asıl sunucu kontrolü (varsayılan olarak kapalı) envanterinizdeki bir asıl sunucu IP’sini proxy’lenen adıyla birlikte de gönderir; böylece herkese açık ölçüm, CDN arkasında o ad için bu sunucunun yanıt verdiğini gösterir. Bunu yalnızca adresi bilinse de sorun olmayan asıl sunucular için açın. Sertifika tarayıcınızdan hiç çıkmaz; karşılaştırma yereldir.',
  'about.priv7': 'Yalnızca Alan Adı Sağlığı’ndaki MTA-STS kartında “Politikayı kontrol et”e bastığınızda: mta-sts.<alan adı> host adı ve politika yolu Globalping’e gider (her sayfa oturumunda bir kez onay istenir), tek bir ölçüm noktası politikayı HTTPS ile alır ve ölçüm kimliğini bilen herkes sonucu, politika ve sunucunun yanıt başlıkları dahil, yaklaşık altı ay okuyabilir. MX sunucularıyla karşılaştırma yereldir.',
  'about.clearData': 'Tüm yerel verileri sil',
  'about.privSession': 'Geçerli hedef (en son üzerinde çalıştığınız alan adı, host adı ya da IP adresi) ve her aracın son sonucu yalnızca bu sekmenin belleğinde tutulur: hiçbir yere yüklenmez; sayfayı yenilemek, sekmeyi kapatmak, başka bir çalışma alanı ya da “Tüm yerel verileri sil” bunları siler. Üzerinde çalıştığınız alan adları ve host adları ayrıca geçerli çalışma alanının son alan adları listesine (IndexedDB) kaydedilir; o alana geri döndüğünüzde sonuncusu yeniden doldurulur; Çalışma alanları penceresi listeyi temizler. Sonra açtığınız araçta hedef doldurulmuş olur ve düğmesine basana kadar hiçbir şey göndermez; bir araca geri döndüğünüzde son sonucu yeniden sorgulanmadan gösterilir.',
  'about.privOrigins': 'Origin haritası: yalnızca “Bu çalışma alanında origin’leri hatırla” seçeneğini açtığınızda (Sunucular › Origin haritası; varsayılan olarak kapalı) çalışma alanı, CDN arkasındaki bir adı gerçekte hangi sunucunuzun ve portun sunduğunu hatırlar: Bu origin’leri hatırla’ya bastığınızda bir zone dosyasının origin’leri, orada içe aktardığınız CLI raporları, Doğrula’nın hatırlanan ve zone dosyasındaki origin’lere yaptığı kontroller (yalnızca aday olan bir adrese asla) ve hatırlamayı seçtiğiniz bir sunucu karşılaştırması. Çalışma alanıyla birlikte bu tarayıcının IndexedDB deposunda tutulur ve hiçbir yere gönderilmez: taramalar onu burada origin’leri sıralamak ve CLI komutunu yazmak için kullanır. Tarayıcıdan yalnızca kendi dışa aktardığınız bir çalışma alanı devir dosyasının içinde çıkar; Origin haritasını unut, çalışma alanını silmek ya da “Tüm yerel verileri sil” onu kaldırır.',
  'about.clearConfirm': 'Tüm çalışma alanları (sunucuları, öğrenilen adları, özel kelime listeleri, beklenen CA’ları, notları, son alan adları ve origin haritalarıyla birlikte IndexedDB veritabanı), tüm ayarlar ve yüklü zone dosyası bu tarayıcıdan silinsin; geçerli hedef ve tutulan sonuçlar da unutulsun mu? Bu işlem geri alınamaz: bir kopyasını saklamak için önce çalışma alanını dışa aktarın.',

  'about.cliTitle': 'Yardımcı CLI aracı: ssl_origin_scan.py',
  'about.cliDesc': 'Envanterinizdeki IP’lere SNI ile TLS bağlantısı yaparak host adlarını sunuculara eşler — sunucularınızla doğrudan konuştuğu için Cloudflare’in arkasını görür. Ağınızın içindeki bir makineden (ör. atlama sunucusu) çalıştırın.',
  'about.cliReq': 'Python 3.8+, yalnızca standart kütüphane, tek dosya. Linux, macOS ve Windows.',
  'about.viewSource': 'Kaynağı görüntüle',
  'about.ex1': 'Yenileme günü — hangi sunucular hâlâ eski sertifikayı sunuyor?',
  'about.ex2': 'Bu uygulamadan dışa aktarılan adlar ve hedefler, 443 ve 8443 portları',
  'about.ex3': 'Betikler (JSON) ve Excel (CSV) için raporlar',
  'about.ex4': 'Bir alt ağ ve iki ad, sertifikasız (“bunları kim barındırıyor?”)',
  'about.ex5': 'CI / cron — yeni sertifikaya ihtiyaç duyan sunucu kaldıkça çıkış kodu 1',
  'about.ex6': 'Kendi CA’nızın imzaladığı iç sunucular NEEDS_UPDATE değil PRIVATE_CERT olur; portuyla yazılan bir adres o porttan taranır',
  'about.ex7': 'Cron — son çalıştırmadan beri değişenler ve 21 gün içinde süresi dolacak sertifikalar (Slack, Teams, Discord, Telegram ya da Google Chat bildirimi için DOMAINSCOPE_NOTIFY_URL ortam değişkenini tanımlayın)',
  'about.ex8': 'DNS bir adı yeni sunucuya taşımadan önce: eski ve yeni sunucunun yanıtları yan yana (özel adresler de olur)',
  'about.exStarttls': 'Posta ve veritabanı sunucuları — 25, 587 ve 5432’de STARTTLS, 2525’te de SMTP — ve TLS denetimi: sürümler, zayıf şifre takımları, RSA + ECDSA ikilileri',
  'about.parityDesc': 'DNS’i başka bir sağlayıcıya taşırken: bir zone dosyasındaki her kayıt kümesini kendi makinenizden yeni ad sunucularına sorar; orada eksik, farklı ya da fazladan olanları listeler. Python 3.8+, tek dosya.',
  'about.parityEx': 'Zone File › Yeni ad sunucuları zone’u indirir ve bu komutu verir',
  'about.ipIntelDesc': 'Ağınızın içinden ters IP: bir adresin, aralığın ya da listenin bugün sunduğu veya geçmişte sunduğu adlar — SNI’li ve SNI’siz TLS sertifikaları, PTR, ücretsiz pasif DNS (hiçbir tarayıcının soramadığı mnemonic dahil) ve yalnızca ortam değişkenlerinden okunan anahtarlarınızla çalışan servisler — ve her adın bugün nereye çözümlendiği. Özel adresler hiçbir üçüncü tarafa gönderilmez. Python 3.8+, tek dosya.',
  'about.ipIntelEx': 'Bir adresin ve ağınızdaki bir aralığın adları, JSON raporuyla',
  'about.statusesTitle': 'Sonuç durumları',
  'about.st.UPDATED': 'Bu ad için yeni sertifikayı sunuyor.',
  'about.st.NEEDS_UPDATE': 'Adı kapsayan bir sertifika sunuyor ama yenisi değil — buraya kurun.',
  'about.st.ORIGIN_CERT': 'Yalnızca Cloudflare’in güvendiği bir Cloudflare Origin CA sertifikası sunuyor: adları proxy arkasında kaldıkça Cloudflare Full (strict) arkasındaki bir asıl sunucu için doğru. Ayrı listelenir, yeni sertifika gerektiren sunucular arasında sayılmaz (--strict-public ile sayılır).',
  'about.st.PRIVATE_CERT': 'Kendinden imzalı ya da --private-ca ile verdiğiniz bir CA’nın imzaladığı sertifika sunuyor: iç sunucularda olağan. Ayrı listelenir, yeni sertifika gerektiren sunucular arasında sayılmaz (--strict-public ile sayılır).',
  'about.st.NOT_HOSTED': 'Yanıt veriyor ama bu ad için değil (yalnızca varsayılan sertifika).',
  'about.st.TLS_ERROR': 'TLS el sıkışması başarısız oldu.',
  'about.st.TIMEOUT': 'Zaman aşımı süresinde yanıt yok.',
  'about.st.CLOSED': 'Port kapalı.',

  'about.selfhostTitle': 'Kendiniz çalıştırın',
  'about.selfhostBody': 'Derleme adımı olmayan statik bir sitedir. Kendi kopyanızı yayınlamak için depoyu çatallayın (fork), fork’un Actions sekmesinde iş akışlarını etkinleştirin, Settings › Pages › Source ayarını “GitHub Actions” yapın, sonra main’e push edin ya da “Deploy to GitHub Pages” iş akışını bir kez elle çalıştırın (yalnızca testler geçince yayınlar). Ya da klasörü yerelde sunun:',

  'about.licenseTitle': 'Katkılar ve lisans',
  'about.licenseBody': 'MIT lisansıyla açık kaynak. Katkılar ve hata bildirimleri memnuniyetle karşılanır.',
  'about.thanks': 'Böyle sunucusuz bir aracı mümkün kılan, yukarıda listelenen ücretsiz hizmetlerin işletmecilerine teşekkürler.',
  'about.version': 'Sürüm {version}',
  'about.wordlistCredits': 'Paketteki subdomain kelime listeleri SecLists, bitquark ve dnsgen (MIT) ile commonspeak2 ve altdns (Apache-2.0) listelerinden üretilir.',
  'about.ccadbCredits': 'Sertifika görünümünün eksik ara sertifika onarımının kullandığı ara sertifikalar ve kök deposu verileri, Community Data License Agreement – Permissive 2.0 ile Common CA Database’den (CCADB) gelir.',
  'about.wordlistLicenses': 'Kelime listesi ve veri lisansları'
});

/** Data sources table rows (static; mirrors spec §3). */
const SOURCES = [
  { name: 'crt.sh', url: 'https://crt.sh/', key: 'crtsh' },
  { name: 'Cert Spotter (SSLMate)', url: 'https://sslmate.com/certspotter/', key: 'certspotter' },
  { name: 'HackerTarget', url: 'https://hackertarget.com/', key: 'hackertarget' },
  { name: 'Anubis', url: 'https://anubisdb.com/', key: 'anubis' },
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com/', key: 'otx' },
  { name: 'ip.thc.org', url: 'https://ip.thc.org/', key: 'thc' },
  { name: 'Robtex', url: 'https://www.robtex.com/', key: 'robtex' },
  { name: 'Shodan (InternetDB, API)', url: 'https://www.shodan.io/', key: 'shodan' },
  { name: 'WhoisXML API', url: 'https://www.whoisxmlapi.com/', key: 'whoisxml' },
  { name: 'DNS-over-HTTPS', url: 'https://datatracker.ietf.org/doc/html/rfc8484', key: 'doh' },
  { name: 'RIPEstat', url: 'https://stat.ripe.net/', key: 'ripe' },
  { name: 'PeeringDB', url: 'https://www.peeringdb.com/', key: 'peeringdb' },
  { name: 'ipwho.is', url: 'https://ipwho.is/', key: 'ipwho' },
  { name: 'RDAP', url: 'https://about.rdap.org/', key: 'rdap' },
  { name: 'Globalping', url: 'https://globalping.io/', key: 'globalping' }
];

const CLI_EXAMPLES = [
  { key: 'about.ex1', cmd: 'python3 ssl_origin_scan.py -t servers.txt --cert new-cert.pem' },
  { key: 'about.ex2', cmd: 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem -p 443,8443' },
  { key: 'about.ex3', cmd: 'python3 ssl_origin_scan.py -t targets.txt --cert new.pem --json report.json --csv report.csv' },
  { key: 'about.ex4', cmd: 'python3 ssl_origin_scan.py -t 10.0.0.0/24 -n www.example.com api.example.com' },
  { key: 'about.ex5', cmd: 'python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --fail-on-needs-update --no-color' },
  { key: 'about.ex6', cmd: 'python3 ssl_origin_scan.py -t hosts.ini -t 10.0.0.5:8443 --cert new.pem --private-ca internal-ca.pem' },
  { key: 'about.ex7', cmd: 'python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --baseline last.json --json last.json --warn-days 21 -q > last.txt' },
  { key: 'about.ex8', cmd: 'python3 ssl_origin_scan.py --compare 10.0.0.5 10.0.0.6 -n www.example.com' },
  { key: 'about.exStarttls', cmd: 'python3 ssl_origin_scan.py -t mail.txt --cert new.pem -p 25,587,993,5432,2525/smtp --tls-audit' }
];

const CLI_STATUSES = [
  { code: 'UPDATED', variant: 'ok', icon: 'check-circle' },
  { code: 'NEEDS_UPDATE', variant: 'warn', icon: 'alert' },
  { code: 'ORIGIN_CERT', variant: 'info', icon: 'cloud' },
  { code: 'PRIVATE_CERT', variant: 'info', icon: 'certificate' },
  { code: 'NOT_HOSTED', variant: 'neutral', icon: 'minus-circle' },
  { code: 'TLS_ERROR', variant: 'error', icon: 'x-circle' },
  { code: 'TIMEOUT', variant: 'error', icon: 'clock' },
  { code: 'CLOSED', variant: 'unresolved', icon: 'lock' }
];

function simpleTable(headers, rows, className = '') {
  return h('div', { class: ['dt-scroll', 'dt-scroll-free', 'about-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => h('td', null, c)))))));
}

function flowNode(iconName, label, sub = null, variant = '') {
  return h('div', { class: ['about-flow-node', variant ? `about-flow-${variant}` : null] },
    h('span', { class: 'about-flow-icon' }, Icon(iconName, { size: 18 })),
    h('span', { class: 'about-flow-text' }, h('span', { class: 'about-flow-label' }, label), sub ? h('span', { class: 'about-flow-sub mono' }, sub) : null));
}

function flowArrow(label = null) {
  return h('div', { class: ['about-flow-arrow', { 'about-flow-arrow-wide': !!label }], attrs: { 'aria-hidden': label ? null : 'true' } },
    label ? h('span', { class: 'about-flow-arrow-label' }, label) : null, h('span', { class: 'about-flow-line' }));
}

/**
 * Mount the About view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const sections = {};
  const section = (key, opts) => {
    sections[key] = Section({ id: `about-${key}`, ...opts });
    return sections[key];
  };
  /** Scroll a section into view and put the focus on its heading (the TOC, `section=`). */
  const goTo = (key) => {
    const target = sections[key];
    if (!target) return false;
    target.scrollIntoView({ block: 'start' });
    const heading = target.querySelector('.section-title');
    if (heading) {
      heading.setAttribute('tabindex', '-1');
      heading.focus({ preventScroll: true });
    }
    return true;
  };

  /* Hero */
  const hero = h('div', { class: 'about-hero card' },
    h('div', { class: 'about-hero-text' },
      h('h2', { class: 'about-hero-title' }, t('about.heroTitle')),
      h('p', null, t('about.heroBody')),
      h('p', { class: 'muted' }, t('about.heroStatic')),
      h('div', { class: 'cluster about-hero-actions' },
        h('a', { class: 'btn btn-primary', href: ctx.href('subdomains') }, Icon('layers'), h('span', { class: 'btn-label' }, t('about.start'))),
        ButtonLink({ href: CLI_PATH, label: t('about.downloadCli'), icon: 'download', download: 'ssl_origin_scan.py' }),
        ButtonLink({ href: ctx.repoUrl, label: t('about.source'), icon: 'code', variant: 'ghost', external: true }))),
    h('img', { class: 'about-hero-logo', src: 'favicon.svg', alt: '', attrs: { width: 96, height: 96 } }));

  /* On this page (buttons, not #anchors — the hash is the router's) */
  const tocItems = ['start', 'how', 'cloudflare', 'sources', 'privacy', 'sent', 'cli', 'selfhost', 'license'];
  // "Where to start" shares its title with the start page's "Hidden" note (a shell string).
  const tocLabel = (key) => (key === 'start' ? t('start.aboutTitle') : t(`about.toc.${key}`));
  const toc = h('nav', { class: 'about-toc', attrs: { 'aria-label': t('about.onThisPage') } },
    h('span', { class: 'about-toc-label' }, t('about.onThisPage')),
    tocItems.map((key) => h('button', {
      type: 'button',
      class: 'about-toc-link',
      dataset: { toc: key },
      on: { click: () => goTo(key) }
    }, tocLabel(key))));

  /* Where to start: the first-visit task picker, reachable after it was dismissed or outgrown */
  const start = section('start', {
    title: t('start.aboutTitle'),
    description: t('start.aboutDesc'),
    children: StartTaskList({ views: ctx.views || [], href: (view) => ctx.href(view) })
  });

  /* How it works */
  const steps = [
    ['search', 'about.step1Title', 'about.step1Body'],
    // The resolver names come from the default chain, so the text cannot go stale again.
    ['globe', 'about.step2Title', 'about.step2Body', { resolvers: defaultChainNames(), count: RESOLVERS.length }],
    ['layers', 'about.step3Title', 'about.step3Body'],
    ['server', 'about.step4Title', 'about.step4Body'],
    ['terminal', 'about.step5Title', 'about.step5Body']
  ];
  const how = section('how', {
    title: t('about.howTitle'),
    description: t('about.howDesc'),
    children: h('ol', { class: 'about-steps' }, steps.map(([ic, title, body, params], i) => h('li', { class: 'about-step card' },
      h('div', { class: 'about-step-head' },
        h('span', { class: 'about-step-num num' }, String(i + 1)),
        h('span', { class: 'about-step-icon' }, Icon(ic, { size: 18 }))),
      h('h3', { class: 'about-step-title' }, t(title)),
      h('p', { class: 'about-step-body' }, t(body, params)))))
  });

  /* Cloudflare */
  const cloudflare = section('cloudflare', {
    title: t('about.cfTitle'),
    children: h('div', { class: 'about-cf' },
      h('div', { class: 'about-cf-text' },
        h('p', null, t('about.cfBody1')),
        h('p', null, t('about.cfBody2')),
        h('p', null, t('about.cfBody3'))),
      h('div', { class: 'about-flows' },
        h('figure', { class: 'about-flow card' },
          h('figcaption', { class: 'about-flow-caption' }, Badge(t('kind.cloudflare'), { variant: 'cloudflare', icon: 'cloud' }), ' ', t('about.flowPublic')),
          h('div', { class: 'about-flow-row' },
            flowNode('users', t('about.flowVisitor')),
            flowArrow(),
            flowNode('cloud', t('about.flowEdge'), '104.21.x.x', 'edge'),
            flowArrow(),
            flowNode('server', t('about.flowOrigin'), `10.0.1.20 · ${t('about.flowHidden')}`, 'hidden'))),
        h('figure', { class: 'about-flow card' },
          h('figcaption', { class: 'about-flow-caption' }, Badge('CLI', { variant: 'accent', icon: 'terminal' }), ' ', t('about.flowCli')),
          h('div', { class: 'about-flow-row' },
            flowNode('terminal', t('about.flowJump'), 'ssl_origin_scan.py'),
            flowArrow(t('about.flowSni')),
            flowNode('server', t('about.flowOrigin'), `10.0.1.20 · ${t('about.flowCert')}`, 'ok')))))
  });
  cloudflare.querySelector('.section-body').append(Alert({ variant: 'info', icon: 'lightbulb', message: t('about.cfHints'), compact: true }));

  /* Sources & quotas */
  const sources = section('sources', {
    title: t('about.sourcesTitle'),
    description: t('about.sourcesDesc'),
    children: h('div', { class: 'stack' },
      simpleTable(
        [t('about.col.source'), t('about.col.provides'), t('about.col.limits')],
        SOURCES.map((s) => [
          ExternalLink(s.url, s.name, { className: 'about-src-name' }),
          t(`about.src.${s.key}`),
          h('span', { class: 'muted' }, t(`about.src.${s.key}Limit`))
        ])),
      Disclosure({
        summary: t('about.resolversTitle', { count: RESOLVERS.length, date: formatDate(`${RESOLVERS_VERIFIED}T12:00:00Z`) }),
        children: simpleTable(
          [t('about.res.name'), t('about.res.location'), t('about.res.features')],
          RESOLVERS.map((r) => [
            h('div', null, h('div', { class: 'about-res-name' }, r.name), h('div', { class: 'muted text-xs' }, r.operator)),
            r.countryCode ? formatRegion(r.countryCode, r.location) : t('settings.anycast'),
            h('div', { class: 'cluster' },
              r.dnssecValidating ? Badge('DNSSEC', { variant: 'ok', icon: 'shield' }) : null,
              r.ecs ? Badge('ECS', { variant: 'info', icon: 'map-pin' }) : null,
              r.filtering ? Badge(t(`settings.filter.${r.filtering}`), { variant: 'neutral', icon: 'filter' }) : null,
              r.browserReliable === false ? Badge('HTTP/3', { variant: 'warn', icon: 'alert', title: t('settings.unreliable') }) : null)
          ]), 'about-resolvers')
      }),
      h('p', { class: 'muted text-sm' },
        t('about.rangesNote', { date: formatDate(`${RANGES_UPDATED}T12:00:00Z`), count: formatNumber(PROVIDERS.length) }),
        ' ',
        t('about.vantagesNote', {
          count: formatNumber(GEO_VANTAGES.length),
          countries: formatNumber(new Set(GEO_VANTAGES.map((g) => g.countryCode)).size)
        })))
  });

  /* Privacy */
  const privacyItems = [
    ['x-circle', 'about.priv1'],
    ['file-text', 'about.priv2'],
    ['git-branch', 'about.privChain'],
    ['server', 'about.priv3'],
    ['map-pin', 'about.privOrigins'],
    ['eye', 'about.priv4'],
    ['network', 'about.privIpEnrich'],
    ['link', 'about.priv5'],
    ['file-text', 'about.privZone'],
    ['key', 'about.privZoneFetch'],
    ['unlink', 'about.privRetire'],
    ['globe', 'about.privReverseIp'],
    ['shield', 'about.privTakeover'],
    ['inbox', 'about.privReports'],
    ['target', 'about.privSession'],
    ['download', 'about.privOffline'],
    ['globe', 'about.priv6'],
    ['mail', 'about.priv7'],
    ['swap', 'about.privMove']
  ];
  const privacy = section('privacy', {
    title: t('about.privacyTitle'),
    description: t('about.privacyDesc'),
    children: h('div', { class: 'stack' },
      h('ul', { class: 'about-privacy' }, privacyItems.map(([ic, key]) => h('li', null,
        h('span', { class: 'about-privacy-icon' }, Icon(ic, { size: 16 })), h('span', null, t(key))))),
      h('div', null, Button({
        label: t('about.clearData'),
        icon: 'trash',
        variant: 'secondary',
        dataset: { action: 'clear-data' },
        onClick: async () => {
          const ok = await confirmDialog({ message: t('about.clearConfirm'), confirmLabel: t('common.delete'), danger: true });
          if (!ok) return;
          await deleteAllLocalData(ctx.state);
        }
      })))
  });

  /* What this page sent: the page session's requests, measured live (ui/egress-panel.js) */
  const ledger = EgressPanel({ repoUrl: ctx.repoUrl, signal: ctx.signal });
  ctx.onCleanup(() => ledger.dispose());
  const sent = section('sent', {
    title: t('egress.title'),
    description: t('egress.desc'),
    children: ledger.el
  });

  /* CLI */
  const cli = section('cli', {
    title: t('about.cliTitle'),
    description: t('about.cliDesc'),
    children: h('div', { class: 'stack' },
      h('div', { class: 'about-cli-bar card' },
        h('span', { class: 'about-cli-icon' }, Icon('terminal', { size: 20 })),
        h('div', { class: 'about-cli-text' },
          h('div', { class: 'about-cli-file mono' }, 'ssl_origin_scan.py'),
          h('div', { class: 'muted text-sm' }, t('about.cliReq'))),
        h('div', { class: 'cluster' },
          ButtonLink({ href: CLI_PATH, label: t('common.download'), icon: 'download', variant: 'primary', download: 'ssl_origin_scan.py' }),
          ButtonLink({ href: cliSourceUrl(ctx.repoUrl), label: t('about.viewSource'), icon: 'eye', variant: 'ghost', external: true }))),
      h('div', { class: 'about-examples' }, CLI_EXAMPLES.map((ex) => CodeBlock(ex.cmd, { label: t(ex.key), wrap: true }))),
      h('h3', { class: 'about-subtitle' }, t('about.statusesTitle')),
      simpleTable([t('common.status'), t('common.details')], CLI_STATUSES.map((s) => [
        Badge(s.code, { variant: s.variant, icon: s.icon, mono: true }),
        CliText(t(`about.st.${s.code}`))
      ]), 'about-statuses'),
      h('div', { class: 'about-cli-bar card' },
        h('span', { class: 'about-cli-icon' }, Icon('server', { size: 20 })),
        h('div', { class: 'about-cli-text' },
          h('div', { class: 'about-cli-file mono' }, 'dns_parity.py'),
          h('div', { class: 'muted text-sm' }, t('about.parityDesc'))),
        h('div', { class: 'cluster' },
          ButtonLink({ href: PARITY_CLI_PATH, label: t('common.download'), icon: 'download', variant: 'secondary', download: 'dns_parity.py' }))),
      CodeBlock('python3 dns_parity.py example.com.parity.zone --ns ns1.example.net ns2.example.net', { label: t('about.parityEx'), wrap: true }),
      h('div', { class: 'about-cli-bar card' },
        h('span', { class: 'about-cli-icon' }, Icon('network', { size: 20 })),
        h('div', { class: 'about-cli-text' },
          h('div', { class: 'about-cli-file mono' }, 'ip_intel.py'),
          h('div', { class: 'muted text-sm' }, t('about.ipIntelDesc'))),
        h('div', { class: 'cluster' },
          ButtonLink({ href: IP_INTEL_CLI_PATH, label: t('common.download'), icon: 'download', variant: 'secondary', download: 'ip_intel.py' }))),
      CodeBlock('python3 ip_intel.py domains 203.0.113.10 10.0.0.0/24 --json names.json', { label: t('about.ipIntelEx'), wrap: true }))
  });

  /* Self-hosting */
  const selfhost = section('selfhost', {
    title: t('about.selfhostTitle'),
    children: h('div', { class: 'stack-sm' },
      h('p', { class: 'text-2' }, t('about.selfhostBody')),
      CodeBlock('git clone https://github.com/halilibrahimd27/domainscope.git\ncd domainscope\nnpm run serve      # or: python -m http.server 8080', { label: 'shell' }))
  });

  /* License */
  const license = section('license', {
    title: t('about.licenseTitle'),
    children: h('div', { class: 'stack-sm' },
      h('p', null, t('about.licenseBody')),
      h('p', { class: 'muted' }, t('about.thanks')),
      h('p', { class: 'muted' }, t('about.wordlistCredits'), ' ', t('about.ccadbCredits'), ' ',
        h('a', { href: LICENSES_URL, target: '_blank', rel: 'noopener' }, t('about.wordlistLicenses'))),
      h('div', { class: 'cluster' },
        Badge('MIT', { variant: 'accent', icon: 'book' }),
        Badge(t('about.version', { version: ctx.version }), { variant: 'neutral' }),
        ExternalLink(ctx.repoUrl, 'GitHub')))
  });

  container.append(hero, toc, start, how, cloudflare, sources, privacy, sent, cli, selfhost, license);

  // `section=sent` (the footer link): after the shell has moved the focus to the page title.
  const openSection = (params) => {
    if (!params || !params.section || !sections[params.section]) return false;
    setTimeout(() => {
      if (!ctx.signal.aborted && goTo(params.section)) ctx.setParams({});
    }, 0);
    return true;
  };
  openSection(ctx.params);
  active = { openSection };
  ctx.onCleanup(() => {
    active = null;
  });
}

/** The mounted view's hooks for {@link update}. */
let active = null;

/**
 * Take new route params without a re-mount: `section=` scrolls to that section.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  if (!active) return false;
  active.openSection(params);
  return true;
}

/** Nothing else to clean up (mount's cleanups stop the ledger). */
export function unmount() {}

export default { id, titleKey, icon, mount, unmount, update };
