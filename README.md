# DomainScope

**Open-source SSL & DNS toolkit that runs entirely in your browser.**
Discover the subdomains of a domain, what they resolve to, which hosts hide behind Cloudflare, and **exactly which of your servers a certificate must be installed on**.

**▶ Use it now: https://halilibrahimd27.github.io/domainscope/**

[![CI](https://github.com/halilibrahimd27/domainscope/actions/workflows/ci.yml/badge.svg)](https://github.com/halilibrahimd27/domainscope/actions/workflows/ci.yml)
[![Deploy](https://github.com/halilibrahimd27/domainscope/actions/workflows/pages.yml/badge.svg)](https://github.com/halilibrahimd27/domainscope/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Türkçe README](README.tr.md)

---

## Why

A customer sends you a renewed certificate for `*.example.com`. You manage hundreds of servers. Which ten of them need it?

- Online subdomain finders disagree with each other (5 results here, 9 there), because each one reads different data sources.
- Hosts behind Cloudflare's orange cloud resolve to Cloudflare IPs, so DNS never tells you which origin server is behind them.
- Your server inventory lives in a hosts file, an Ansible inventory or a spreadsheet, and nothing connects it to DNS.

DomainScope combines several sources, resolves every name, classifies each answer (Cloudflare, other CDN, SaaS platform, direct, private, NXDOMAIN, dangling CNAME), and matches the IPs against **your own inventory**, all inside your browser. For hosts behind a proxy, the bundled Python CLI connects to your servers directly with SNI and reports which servers still serve the old certificate.

## Features

| Tool | What it does |
|---|---|
| **Subdomains** (start page) | Enter a domain and get every subdomain the public internet can reveal, DNS first. It mines the zone's own records (NS, MX, SPF/TXT, SRV, …), tries a self-hosted wordlist — **Off**, **Small** (159 names), **Smart** (≈ 7,000, the default), **Large** (≈ 50,000) or **Huge** (≈ 130,000) — and variations of every name found (`shop` → `shopapi`, `api` → `api2`, `api-dev`; up to 1,500 by default, plus one deeper round under discovered parents). From Smart up it adds a **market word pack** picked from the domain ending (`.de` → German, `.com.tr` → Turkish; 12 markets, or choose them yourself), tries your own **custom wordlist** first and then, if you turn them on, the **names learned** from your earlier scans (see [Wordlists](#wordlists-and-what-dns-guessing-can-find)). Passive sources (Certificate Transparency and passive DNS, see below) run alongside, each with its own status and quota note. Wildcard DNS is detected at every level so look-alike hits are dropped. For hosts behind Cloudflare or another proxy it lists **origin candidates**: the networks (/24 for IPv4, /48 for IPv6) of the domain's DNS-only records, direct answers from other public resolvers, historical DNS, SPF/MX addresses, and a ready-to-run CLI command (Linux/macOS or Windows PowerShell) that sweeps those networks with TLS SNI. Each proxied host gets its own ranked list of candidates: exact addresses first, then the networks related to it. If you scan sister domains together (`example.com example.net`), a proxied `shop.example.com` whose name is a DNS-only host on `shop.example.net` gets that address as a candidate. Networks in shared cloud / hosting / CDN space are marked and swept only by their known addresses, never as a whole /24. The owner (AS) of a network is looked up when you click, and an **Exclude addresses** box adds `--exclude` to the command. Names appear in the table while the wordlist and permutation stages are still running. Copy the list or download `names.txt`. |
| **Zone File** | Drop, choose or paste your DNS zone export and the format is detected: BIND / RFC 1035 (Cloudflare export, cPanel, DirectAdmin, GoDaddy, cli53, `dig AXFR`), Cloudflare API JSON, Route 53 JSON, octoDNS YAML. You get every name without guessing and, for Cloudflare, **the real origin behind each proxied record**, read from the file and matched to your servers. The page offers:<br>• a records table;<br>• a **Problems** list (CNAME conflicts, dangling targets, private addresses in a public zone, origins exposed by a DNS-only sibling / MX / SPF, SPF / DMARC / CAA / TTL mistakes …);<br>• a sweep command that scans exactly those origin addresses and hosts, never a whole /24;<br>• **Scan these names**, which hands the names to Subdomains or SSL Targets. In *exact* mode only the zone names are resolved: no guessing, no passive sources, no quota;<br>• a **Live check** that compares the file with public DNS, and only after you click. |
| **SSL Targets** | Drop in a certificate (PEM, DER, chain or P7B). Uses the same discovery engine (the Smart wordlist is on by default; languages, custom wordlist and learned names are shared with Subdomains › Advanced options), resolves every name over DNS-over-HTTPS, checks which names the certificate covers, and groups the results **by your servers**. Tabs: Hosts, Servers, Behind CDN (with origin hints and the same CLI command for either shell), **Verify**, Sources, CT certificates. **Verify** (with a certificate) checks from the internet which certificate each public server really serves for each name, through [Globalping](https://globalping.io) probes, and gives the CLI's verdicts (new certificate, old certificate, name not served here, TLS error, no answer, port closed) with warnings such as a missing intermediate. It shows the cost and asks for consent once per page session (and again before a batch of more than 50 checks, one larger than the remaining quota, or the first one that includes origin checks); private addresses are never sent and go to a ready CLI command instead. Exports to CSV, JSON, `names.txt` and `targets.txt`. |
| **Certificate** | Full certificate details: SANs, validity, key, fingerprints, chain order and warnings. Also checks whether the domain's **CAA** records allow the issuing CA and looks the certificate up in CT logs. |
| **Global DNS** | Queries one name through **12 public DoH resolvers** plus **31 locations in 27 countries** via EDNS Client Subnet, then groups the answers so you can see GeoDNS and CDN differences and follow propagation. Quad9 and Quad9 (ECS) answer browsers over HTTP/3 without a CORS header, so in Chrome, Edge and most other browsers their rows usually show "Not readable in browsers" with a `dig` command to run instead. |
| **DNS Lookup** | Any record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, HTTPS/SVCB, DS, DNSKEY, TLSA, …), from any resolver, with a DNSSEC (DO/CD) toggle. Records are shown parsed, with the raw text alongside. |
| **Bulk Resolve** | Paste hundreds of hostnames to get IPs, CNAME chains, CDN classification, PTR, ASN and inventory matches, then export. |
| **IP Intel** | For each IP: PTR, ASN and holder, prefix, country and city, CDN or provider, private-range flag, the matching inventory server, and reverse IP (other domains on the same IP). |
| **Domain Health** | NS, SOA, MX, SPF (with the recursive 10-lookup count), DMARC, DKIM selectors, CAA, DNSSEC (signed, validated or broken), MTA-STS, TLS-RPT, BIMI, wildcard DNS and RDAP registration expiry, combined into a score. |
| **Servers** | Paste or import your inventory in any of these formats: `name ip` lines, `/etc/hosts`, CSV/TSV (Excel exports too), Ansible INI or YAML, JSON. The inventory **never leaves your browser**. |

The interface is available in Turkish and English, has light and dark themes, works on mobile, and every view has a shareable URL (for example `#/global?name=example.com&type=A`).

## How it works

DomainScope is a static site with no backend. Everything runs in your browser against public APIs; all of them allow cross-origin requests except where marked:

| Purpose | Services |
|---|---|
| Subdomain sources | [crt.sh](https://crt.sh), [Cert Spotter](https://sslmate.com/certspotter/), [HackerTarget](https://hackertarget.com), [AnubisDB](https://anubisdb.com), [AlienVault OTX](https://otx.alienvault.com), [ip.thc.org](https://ip.thc.org) |
| DNS (RFC 8484 DoH) | Cloudflare, Cloudflare Family, Google Public DNS, Quad9†, Quad9 (ECS)†, Control D, DNS.SB, IIJ Public DNS, CleanBrowsing, Tiarap, seby.io, CZ.NIC ODVR |
| IP data | [RIPEstat](https://stat.ripe.net) (also the owner of an origin network, only when you click "Look up owner"), [ipwho.is](https://ipwho.is), HackerTarget reverse IP |
| Registration | RDAP via the IANA bootstrap (some country TLDs, such as `.de`, `.jp` and `.tr`, publish no RDAP) |
| Certificate check from the internet | [Globalping](https://globalping.io) (jsDelivr's free probe network; SSL Targets › Verify only, and only when you press "Check from the internet") |

† Quad9 answers browsers over HTTP/3 without a CORS header, so Chrome, Edge and most other browsers usually cannot read it; Global DNS shows those rows as "Not readable in browsers" with a `dig` command, and discovery leaves Quad9 out of its default resolver chain. It works from a terminal, and in a browser on networks that block QUIC.

Free tiers have rate limits, and they apply **per visitor IP**, not globally: HackerTarget allows about 50 requests per day, Cert Spotter about 10 full-domain searches per hour (a scan uses up to 5), and anonymous OTX is limited. Globalping allows 250 probes per hour without an account, shared by everyone behind your IP address; each Verify check costs one probe (a check whose probe fails is retried on another probe, at most 5 extra probes per batch), and the tab shows what is left before it sends anything. If a source fails, the scan keeps going: the DNS-first discovery (record mining, wordlist, permutations) needs no third-party quota at all — only public DoH resolvers.

**Privacy.** Certificates and your server inventory are processed locally and never uploaded, except the public IP / host name pairs you choose to check in **Verify** (below). The only data that leaves your browser is what each lookup needs: domain names go to the DNS resolvers and passive sources, and IPs go to the IP data services when you look them up. A custom wordlist stays in the current tab (session storage). An imported **zone file** never leaves the browser and is never saved. It is kept only in the tab's memory: a reload, **Forget** or **Delete all local data** clears it. Its **Live check** sends record names and types only, never values or origin addresses, to your DoH resolvers, and only after you click. Internal-looking names are skipped by default, and the hidden targets of proxied records are never queried. Exact-mode scans of the zone's names use the DoH resolvers only. **Verify** sends something only when you press "Check from the internet" and confirm: each public IP, host name and port pair goes to Globalping, whose results anyone with the measurement ID can read for about six months. Private addresses are never sent. The optional origin check (off by default) also sends an origin IP from your inventory together with the proxied name it serves, so the public measurement shows that this server answers for that name behind the CDN, which is exactly what someone trying to bypass the CDN looks for; turn it on only for origins whose address may be known. The certificate never leaves your browser; the comparison is local. One probe then sends one HTTPS HEAD request to the server (User-Agent "globalping probe"), so only check servers you operate. The consent is asked again in every page session and is never stored. Learned names are off until you turn them on; they are bare labels such as `api`, never full hostnames or IPs, stored only in this browser's local storage — but later scans try them as DNS lookups (`api.<domain>`), so resolvers and that domain's name servers see them; **Delete all local data** (Settings or About) removes them together with the inventory and settings. A private key is never needed; if you paste one by mistake, it is ignored and never displayed.

## Wordlists and what DNS guessing can find

DNS has no "list every record" query, and providers such as Cloudflare refuse zone transfers. So DomainScope rebuilds the list from four kinds of evidence: names in public certificates and passive DNS, names the zone's own records mention, words from a list, and variations of names already found. Every guess is checked with a real DNS answer, and wildcard look-alikes are dropped.

| Level | Names per domain | Download | Rough time per domain* |
|---|---:|---:|---:|
| Off | none (records + passive sources only) | — | — |
| Small | 159 | built in | seconds |
| **Smart** (default) | ≈ 7,000 | 42 kB | ≈ 1 min |
| Large | ≈ 50,000 | 183 kB (gzip) | ≈ 7 min |
| Huge | ≈ 130,000 | 588 kB (gzip) | ≈ 18 min |

\* The page plans with 120 queries per second at the default Settings parallelism (24 queries in flight); a lower Settings value slows the sweep in proportion. The estimate is deliberately cautious; measured throughput is in [docs/RESEARCH.md](docs/RESEARCH.md#measured-results-2026-09-23).

- **One ranked list, three sizes.** Smart, Large and Huge are the top ≈ 7,000, ≈ 50,000 and ≈ 130,000 names of one ranking built from permissively licensed public lists (SecLists, bitquark, commonspeak2, dnsgen, altdns; see [License](#license)). The files are served by this site, so a scan never fetches a wordlist from a third party.
- **Market word packs** (Smart and up): `tr, de, fr, es, pt, it, nl, pl, ru, ar, ja, zh`, 83–283 generic business and public-service words each. **Auto** picks them from the domain ending, including second-level endings such as `.com.tr` and several packs for multilingual countries (`.ch` → German, French, Italian). A `.com` gets none automatically; choose packs yourself (or none) under Advanced options.
- **Custom wordlist.** Paste names or load a `.txt` file — one per line or separated by commas / spaces; `dev.api` tries a deeper name. They are tried first, in every level from Small up. The file is read in your browser and the list is kept only in this tab.
- **Learned names** (opt-in, off by default). When you turn them on, after each finished scan the left-most labels of the names that resolved under the scanned domains are remembered in this browser and tried right after your custom list next time (the 1,000 most frequent). A sister domain that follows the same naming scheme is then covered even if its names are not in any public list. Later scans of *any* domain send these labels as DNS lookups, so keep the switch off when you scan unrelated organisations. They are never used at level **Off**, and **Forget learned names** clears them at any time.
- **Courtesy.** Each guess is one A query to public DoH resolvers, spread over the resolver pool; your browser never contacts the domain's web servers. Names a resolver has not cached are passed on to the domain's authoritative nameservers, so a self-hosted nameserver does see the burst. Per domain at most 4,000 / 20,000 / 80,000 / 160,000 candidates (Small / Smart / Large / Huge), 200,000 per scan.
- **Slow sources never hold up the wordlist sweep.** The wildcard check and the wordlist sweep start when the passive sources have answered or 12 seconds after record mining, whichever comes first. The permutation and final resolve stages then wait for the sources, so names that arrive late are included: while a slow source such as crt.sh is still retrying (its status shows it), the results table can stay empty even after the sweep has finished.

**Limits, honestly.** A name that exists only inside one organisation's zone — a product or project name that never appeared in a certificate or in passive DNS — cannot be found by any global wordlist. Add it to your custom wordlist, let learned names carry it over from a related domain, or import the zone export in **Zone File**: only a zone export is complete. A host that answers exactly like its parent's wildcard record is indistinguishable from the wildcard and is dropped. And a proxied record's origin IP is never published in DNS, so the origin panel gives candidates to confirm with the CLI, not answers. Only a zone export holds the exact origins.

## Finding origins behind Cloudflare: the CLI

A browser cannot open raw TLS connections to arbitrary IPs. [`cli/ssl_origin_scan.py`](cli/ssl_origin_scan.py) can. It is a single file that needs Python 3.8+ and no extra packages. Run it from a machine inside your network, such as a jump host. It connects to every server IP in your inventory, requests each hostname via SNI, and compares the certificate it gets back with the new one.

```bash
# Download it from the site or the repo
curl -O https://halilibrahimd27.github.io/domainscope/cli/ssl_origin_scan.py

# Renewal day: which servers still serve the old certificate?
python3 ssl_origin_scan.py -t servers.txt --cert new-cert.pem

# Use the names/targets exported from the web app, on ports 443 and 8443
python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem -p 443,8443

# Reports for scripts / Excel, and a CI-friendly exit code
python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --json report.json --csv report.csv --fail-on-needs-update

# Find the origin of proxied names: sweep a network the Subdomains page suggested
python3 ssl_origin_scan.py -t 203.0.113.0/24 -n shop.example.com api.example.com

# The same sweep, leaving a mail server and a /28 alone (never connected to)
python3 ssl_origin_scan.py -t 203.0.113.0/24 --exclude 203.0.113.25 203.0.113.64/28 -n shop.example.com

# Exact origins from an imported zone file (Zone File › Origins & servers)
python3 ssl_origin_scan.py -t zone-targets.txt -n zone-names.txt
```

It reports one status per server, port and name:

| Status | Meaning |
|---|---|
| `UPDATED` | The server already serves the new certificate. |
| `NEEDS_UPDATE` | The server hosts the name with a different (old) certificate. **Install the new one here.** |
| `NOT_HOSTED` | The server does not serve this name (it returns its default certificate). |
| `TLS_ERROR` / `TIMEOUT` / `CLOSED` | Unreachable, or the handshake failed. |

Targets can be IPs, CIDRs, ranges, hostnames or inventory files, in the same formats the web app accepts. `--exclude` takes IPs, CIDRs, ranges or a file of them; it is applied after names are resolved and before any connection. Excluded addresses are listed in the summary, the JSON and the CSV (`EXCLUDED`). Numeric "hostnames" such as `2026092401`, `127.1` or `0x7f.0x1` are refused, because the system resolver would read them as an IPv4 address. Addresses with a leading zero (`010.0.0.1`) are refused too. `0.0.0.0/8`, multicast and broadcast addresses are never scanned. Run `python3 ssl_origin_scan.py --help` for everything else.

The origin panel (Subdomains) and the Behind CDN tab (SSL Targets) write the sweep command for you, for **Linux / macOS** (`python3 …`) or **Windows PowerShell** (`python …`). IPv4 networks go in as the /24 when several origins or one of your inventory servers sit in it. Otherwise they go in as the exact addresses, and so does a /24 in shared cloud / hosting / CDN space that holds none of your servers. IPv6 always goes in as exact addresses (a /48 is far too large to sweep). Addresses you enter under **Exclude addresses** become `--exclude`; a network they cover entirely drops out. The Zone File view uses only the exact origins from the file: addresses and host names, never a /24, with `*.x` names quoted. Every target must be an IP address or network and every name a valid hostname: anything else — for example a hostile name taken from a CT log — is left out and counted, never pasted into the command, and the remaining tokens are quoted for the chosen shell.

## A typical SSL rollout

0. **Subdomains (optional):** see everything first — every name, which are proxied, and the origin networks with a sweep command for your shell, e.g. `python3 ssl_origin_scan.py -t 203.0.113.0/24 -n api.example.com shop.example.com`. If you can export the zone, drop it in **Zone File** instead: you get every name and the exact origin of each proxied record, then **Find certificate targets** or copy the exact sweep command.
1. **SSL Targets:** drop in the new certificate, confirm the domain, and scan. Your inventory is matched automatically.
2. **Servers tab:** lists the servers whose DNS points at a covered name. **Behind CDN tab:** lists the proxied hosts, their origin hints, and the CLI command.
3. Install the certificate, then open the **Verify** tab and press **Check from the internet**: every public server is checked for every name it should serve, and "Check again" re-checks only what is not done yet. For private addresses and origins behind a CDN, run the CLI command the tab gives you (`--cert new-cert.pem`). Repeat until every server reports `UPDATED`.

## Run locally / self-host

No build step and no dependencies. Serve the folder with any static server:

```bash
git clone https://github.com/halilibrahimd27/domainscope.git
cd domainscope
npm run serve            # or: python -m http.server 8080
```

To host your own copy, fork the repo and set **Settings → Pages → Source: GitHub Actions**. The included workflow deploys every push to `main`.

## Development

```
index.html               SPA shell (strict CSP, no inline scripts/styles)
assets/js/lib/           DOM-free libraries (run in browsers and Node): x509, dnswire, doh, sources, scanner,
                         wordlist, learned, permute, dnsmine, cmdline, globalping, verify, health,
                         zoneparse / zonelint / zoneorigins / zonedrift (Zone File), …
assets/js/views/         one module per tool (subdomains.js is the start page)
assets/js/ui/            safe DOM builder + component library (+ verify-panel.js, the SSL Targets › Verify tab)
assets/data/             bundled wordlists (Smart plain text, Large + Huge gzip), 12 locale packs, manifest + licences
tools/build-wordlists.mjs  rebuilds assets/data from pinned upstream lists (maintainers only)
cli/ssl_origin_scan.py   companion CLI (stdlib only)
tests/js/                node:test unit tests (no network), incl. a repo-hygiene check for real IPs
tests/python/            CLI tests, including local TLS servers with SNI
tests/e2e/               headless Chrome E2E via the DevTools protocol (no dependencies)
tests/live/              live smoke tests and the discovery benchmark (network; never run in CI; the Globalping smoke never sends your own targets)
docs/                    SPEC (module contracts), ROADMAP, RESEARCH
```

```bash
npm test                 # JavaScript unit tests (node --test "tests/js/*.test.js"; `node --test tests/js/` is equivalent)
npm run test:py          # CLI tests
node tests/e2e/run-all.mjs   # end-to-end, against live APIs (needs Chrome or Edge); the verify suite is offline: 0 Globalping probes
```

Tests and docs use reserved example names (`example.com`, `example.net`) and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); `tests/js/repo-hygiene.test.js` fails on any other IPv4 address that is not well-known public infrastructure. Live scripts read your own targets only from the gitignored `tests/live/targets.local.json`.

Contributions are welcome. Keep it dependency-free, DOM-free in `lib/`, and CSP-safe (never assign untrusted data to `innerHTML`).

## License

[MIT](LICENSE). Data comes from the services listed above, each under its own terms. The bundled subdomain wordlists are built from permissively licensed lists (SecLists, bitquark and dnsgen under MIT; commonspeak2 and altdns under Apache-2.0); sources, pinned versions and licences are listed in [`assets/data/README.md`](assets/data/README.md), and the full licence texts ship in [`assets/data/THIRD_PARTY_LICENSES.txt`](assets/data/THIRD_PARTY_LICENSES.txt) (also linked from the About page). The market word packs and the built-in core list are original DomainScope work under MIT.
