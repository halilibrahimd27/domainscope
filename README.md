# DomainScope

**Open-source SSL & DNS toolkit that runs entirely in your browser.**
Find every subdomain of a domain, what it resolves to, which hosts hide behind Cloudflare, and **exactly which of your servers a certificate must be installed on**.

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
| **SSL Targets** | Drop in a certificate (PEM, DER, chain or P7B). DomainScope collects subdomains from Certificate Transparency and passive DNS, optionally brute-forces a wordlist, resolves every name over DNS-over-HTTPS, checks which names the certificate covers, and groups the results **by your servers**. Tabs: Hosts, Servers, Behind CDN (with origin hints and a ready-to-run CLI command), Sources, CT certificates. Exports to CSV, JSON, `names.txt` and `targets.txt`. |
| **Certificate** | Full certificate details: SANs, validity, key, fingerprints, chain order and warnings. Also checks whether the domain's **CAA** records allow the issuing CA and looks the certificate up in CT logs. |
| **Global DNS** | Queries one name through **12 public DoH resolvers** plus **31 locations worldwide** via EDNS Client Subnet (4 of them in Turkey, across Türk Telekom, Turkcell Superonline and Vodafone), then groups the answers so you can see GeoDNS and CDN differences and follow propagation. |
| **DNS Lookup** | Any record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, HTTPS/SVCB, DS, DNSKEY, TLSA, …), from any resolver, with a DNSSEC (DO/CD) toggle. Records are shown parsed, with the raw text alongside. |
| **Bulk Resolve** | Paste hundreds of hostnames to get IPs, CNAME chains, CDN classification, PTR, ASN and inventory matches, then export. |
| **IP Intel** | For each IP: PTR, ASN and holder, prefix, country and city, CDN or provider, private-range flag, the matching inventory server, and reverse IP (other domains on the same IP). |
| **Domain Health** | NS, SOA, MX, SPF (with the recursive 10-lookup count), DMARC, DKIM selectors, CAA, DNSSEC (signed, validated or broken), MTA-STS, TLS-RPT, BIMI, wildcard DNS and RDAP registration expiry, combined into a score. |
| **Servers** | Paste or import your inventory in any of these formats: `name ip` lines, `/etc/hosts`, CSV/TSV (Excel exports too), Ansible INI or YAML, JSON. The inventory **never leaves your browser**. |

The interface is available in Turkish and English, has light and dark themes, works on mobile, and every view has a shareable URL (for example `#/global?name=example.com&type=A`).

## How it works

DomainScope is a static site with no backend. Everything runs in your browser against public APIs that allow cross-origin requests:

| Purpose | Services |
|---|---|
| Subdomain sources | [crt.sh](https://crt.sh), [Cert Spotter](https://sslmate.com/certspotter/), [HackerTarget](https://hackertarget.com), [AnubisDB](https://anubisdb.com), [AlienVault OTX](https://otx.alienvault.com) |
| DNS (RFC 8484 DoH) | Cloudflare, Cloudflare Family, Google Public DNS, Quad9, Quad9 (ECS), Control D, DNS.SB, IIJ Public DNS, CleanBrowsing, Tiarap, seby.io, CZ.NIC ODVR |
| IP data | [RIPEstat](https://stat.ripe.net), [ipwho.is](https://ipwho.is), HackerTarget reverse IP |
| Registration | RDAP via the IANA bootstrap (`.tr` has no public RDAP) |

Free tiers have rate limits, and they apply **per visitor IP**, not globally: HackerTarget allows about 50 requests per day, Cert Spotter about 10 per hour, and anonymous OTX is limited. If a source fails, the scan keeps going.

**Privacy.** Certificates and your server inventory are processed locally and never uploaded. The only data that leaves your browser is what each lookup needs: domain names go to the DNS resolvers and passive sources, and IPs go to the IP data services when you look them up. A private key is never needed; if you paste one by mistake, it is ignored and never displayed.

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
```

It reports one status per server, port and name:

| Status | Meaning |
|---|---|
| `UPDATED` | The server already serves the new certificate. |
| `NEEDS_UPDATE` | The server hosts the name with a different (old) certificate. **Install the new one here.** |
| `NOT_HOSTED` | The server does not serve this name (it returns its default certificate). |
| `TLS_ERROR` / `TIMEOUT` / `CLOSED` | Unreachable, or the handshake failed. |

Targets can be IPs, CIDRs, ranges, hostnames or inventory files, in the same formats the web app accepts. Run `python3 ssl_origin_scan.py --help` for everything else.

## A typical SSL rollout

1. **SSL Targets:** drop in the new certificate, confirm the domain, and scan. Your inventory is matched automatically.
2. **Servers tab:** lists the servers whose DNS points at a covered name. **Behind CDN tab:** lists the proxied hosts, their origin hints, and the CLI command.
3. Install the certificate, then run the CLI with `--cert new-cert.pem`. Repeat until every server reports `UPDATED`.

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
assets/js/lib/           DOM-free libraries (run in browsers and Node): x509, dnswire, doh, sources, scanner, health, …
assets/js/views/         one module per tool
assets/js/ui/            safe DOM builder + component library
cli/ssl_origin_scan.py   companion CLI (stdlib only)
tests/js/                node:test unit tests (no network)
tests/python/            CLI tests, including local TLS servers with SNI
tests/e2e/               headless Chrome E2E via the DevTools protocol (no dependencies)
```

```bash
npm test                 # JavaScript unit tests (node --test "tests/js/*.test.js")
npm run test:py          # CLI tests
node tests/e2e/run-all.mjs   # end-to-end, against live APIs (needs Chrome or Edge)
```

Contributions are welcome. Keep it dependency-free, DOM-free in `lib/`, and CSP-safe (never assign untrusted data to `innerHTML`).

## License

[MIT](LICENSE). Data comes from the services listed above, each under its own terms.
