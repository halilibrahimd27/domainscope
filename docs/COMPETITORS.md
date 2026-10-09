# Competitors: what paid products sell, and what DomainScope does about it

A summary of the wave 7 competitor research (2026-10-08): about 60 paid products for certificate management, DNS and registrar monitoring, DMARC and security ratings, and about 70 candidate gaps, each compared with the code, the README and the [ROADMAP](ROADMAP.md). Gaps DomainScope already covers, or that break the constraints below, were dropped. The ten that remain are ranked at the end of this page.

**Constraints every item keeps.** The browser side is a static page that calls keyless (or user-keyed) endpoints with CORS and stores nothing on a server. The CLI is Python 3.8, standard library only. The runner (`tools/ds.mjs`) is Node 22 with no dependency and runs in the user's own GitHub Actions. There is no hosted backend, so "monitoring" means that runner, or a check made when you open the page.

## Paid products and their published prices

Prices are the vendors' published list prices as read on **2026-10-08**, in US dollars per month unless stated. They change; check before quoting.

| Product | What it sells | Published price (read 2026-10-08) |
|---|---|---|
| CyberArk Certificate Manager (formerly Venafi) | Enterprise certificate management | Quote; from $1,125 on AWS |
| Keyfactor Command, DigiCert Trust Lifecycle Manager | Enterprise certificate management | Quote (not published) |
| AppViewX AVX ONE | Certificate management | $2,100 for 100 certificates, $4,200 for 250 |
| Sectigo SCM Pro | Certificates with automatic renewal | $25 to $225 (3 to 10 domains) |
| SSLMate Cert Spotter | CT monitoring, certificate expiry | $15 to $500; webhooks from the $100 plan |
| TrackSSL | Certificate expiry monitoring | 2 certificates free; $17 to $136 |
| KeyChest | Certificate tracking, renewal plan | Free for personal use; $10 to $99 |
| Red Sift Certificates | Certificate monitoring | Free up to 250 certificates; from $99 |
| UptimeRobot | Uptime, SSL and DNS monitoring | $9 (Solo), $35 (Team) |
| DNS Spy | DNS record change monitoring | $9 to $49; chat and pager webhooks only at $49 |
| ZoneWatcher | DNS and registrar change monitoring | $1.40 to $4.00 per domain |
| IBM NS1 Alert Center | DNS alerting | $349 (Standard) |
| dmarcian | DMARC reports | $19.99 to $499 |
| EasyDMARC | DMARC and hosted SPF | $35.99 to $71.99 (billed yearly) |
| MxToolbox Delivery Center | Blocklist and mail delivery monitoring | $129 to $399 |
| ZeroHook Business Security | Takeover and blocklist monitoring | $149 |
| UpGuard Vendor Risk | Vendor security ratings | $1,750 for 50 vendors |
| DomainTools Iris | Domain investigation | From about $15,750 a year |
| Bolster CheckPhish | Lookalike domain monitoring | $50 per domain |

## What DomainScope already does better or for free

- **Free and local.** No account, install or server. Server lists, certificates, zone files and DMARC reports never leave the browser; every product above keeps these in its own cloud.
- **"Which server needs the new certificate?"** Paid certificate tools do not answer it from DNS, a server inventory and the real origin behind a CDN together. The Rollout tab and the per-server commands do.
- **Checks before a renewal.** Verification from the internet (Globalping), renewal readiness (CAA, `_acme-challenge`, the DNS-01 plugin), the DANE / TLSA guard, missing-intermediate repair and PFX reading are absent from the competitors or sit in their dearest plans.
- **DNS tools.** Global DNS asks 12 resolvers and 34 locations, mainland China and real ISP resolvers included; the DNSSEC chain is validated in the browser; zones can be compared and converted. That goes further than DNS Spy's or DNSChecker's one-off checks.
- **From inside your network.** The CLI speaks STARTTLS on mail, LDAP and PostgreSQL ports, builds a certificate estate, audits TLS and reverses internal addresses. Cloud products see these only through an agent on the server.
- **Nightly checks in your own repository.** The runner works in the customer's private GitHub repository: results and history stay there, and there is no monthly fee.
- **Portfolio and reports.** The Domain portfolio with a policy audit, the CT watch, the expiry calendar, the Domain Health score and the customer report cover the basics of the "security posture" products. Since 2026-10-09 the portfolio also scores domains the way CSC does, and DMARC reports name the service behind each sender.
- **Local detail.** A Turkish interface, Turkish registrars (Natro, Turhost, İsimtescil), `.com.tr` and Turkish-letter lookalikes, none of which the competitors cover.

## The ten gaps, in build order

Effort: **S** is about one session, **M** two or three. Value is what the item is worth to an engineer or MSP who runs many customers' domains, servers and certificates. Build 1 first; 2 to 6 can then go in parallel, followed by 7 and 8, then 9 and 10. Items 1 to 4 and 7 together make the "monitor that pings you" that Cert Spotter, TrackSSL, UptimeRobot, DNS Spy and ZoneWatcher charge for; items 6 and 9 make the DMARC product that dmarcian, EasyDMARC and PowerDMARC charge for.

| # | Key | Gap | Where | Effort | Value | Status |
|---|---|---|---|---|---|---|
| 1 | `runner-notify` | Alert channels for the runner: Slack, Teams, Discord, Telegram, Google Chat, PagerDuty, ntfy and a signed webhook, where today it only opens one issue. The base for 2 to 4 and 7. | runner, CLI parity | S | high | **shipped** (2026-10-09, [SPEC §9](SPEC.md)) |
| 2 | `runner-tls-monitor` | A nightly check of each public endpoint's served certificate: days left, chain (a missing intermediate named), host name, a changed certificate, and "renewed but not deployed" against CT. The CLI gains full chain validation. | runner, CLI | M | high | in progress |
| 3 | `domain-change-watch` | A hijack watch: registrar, transfer lock, status, name server, DS, MX, SPF, DMARC and expiry changes, optionally every name server asked directly; the portfolio says "changed since your last check". | runner, portfolio | M | high | in progress |
| 4 | `takeover-watch` | A nightly takeover and dependency-expiry watch over every reference kind (SPF includes, DMARC report addresses, DKIM CNAMEs, CAA iodef, MTA-STS), plus a Domain Health button. | runner, Subdomains, Health | S | high | **shipped** (2026-10-09, [SPEC §5.73](SPEC.md)) |
| 5 | `domain-security-score` | Lock depth, registrar class, DNS redundancy and a CSC-style 0 to 8 score, with four policy rules and a Corporate preset. | portfolio, policy, runner `audit` | S | high | **shipped** (2026-10-09, [SPEC §5.92](SPEC.md)) |
| 6 | `dmarc-sender-names` | The service behind every DMARC source, a by-service view with a guide per service, and Identify senders from a bundled list. | DMARC & TLS reports, build script | M | high | **shipped** (2026-10-09, [SPEC §5.93](SPEC.md)) |
| 7 | `monitor-view` | A view over the runner's results: history, trends and open problems, read from a folder or from GitHub with a read-only token that is never stored. | new view, runner | M | high | in progress |
| 8 | `renewal-radar` | ACME renewal windows (ARI) for every CA that publishes them, and certificate revocation status. | runner, CLI, CT tab, Certificate | M | high | **shipped** (2026-10-09, [SPEC §5.94](SPEC.md)) |
| 9 | `dmarc-history` | Opt-in DMARC history, trends and a roll-up across domains, kept in the workspace as daily summaries, never the reports themselves. Competitors price on retention. | DMARC & TLS reports, workspace | M | high | in progress |
| 10 | `waivers` | Accepted risks and known certificates with a reason, an owner and an end date, so a nightly alarm does not stay red for a finding nobody will fix. | Health, portfolio, CT tab, runner | S | medium-high | in progress |

**Shipped in wave 7b.** The security score adds how deep a lock goes (none, the registrar's transfer or full lock, a partial or a full registry lock), the registrar's class by its IANA ID, and the DNS providers behind the name servers; the Domain portfolio's **Domain security** tab scores each domain on CSC's eight measures, and `node tools/ds.mjs audit` writes the same score table into the nightly run, with `--preset corporate` as the policy that asks for all eight measures. The sender names add a table of 72 services, a **By service** view and **Identify senders**, backed by lists built weekly from parsedmarc's reverse DNS map at a pinned Apache-2.0 commit. The runner's alerts post the changes that count to Slack, Teams, Discord, Telegram, Google Chat, ntfy, PagerDuty (an incident per problem, resolved when the report shows it over) or a signed JSON webhook, from Actions secrets the nightly template reads, and the CLI's `--notify` gains PagerDuty, ntfy and the signature. The takeover watch follows every kind of reference (SPF hosts, DMARC report addresses, DKIM CNAMEs, CAA iodef, MTA-STS, SRV, HTTPS, `_acme-challenge`) in Subdomains, in a Domain Health **Dependencies** card and every night in the runner's `takeover`. The renewal radar asks the CAs for their ACME renewal windows and reads the certificates' CRLs, in the CLI (`--ari`, `--revocation`), in the runner's new `tls` and in the CT tab, the Certificate view and Certificate estate. All five are listed in [ROADMAP](ROADMAP.md#wave-7b--competitor-gaps-2026-10-09).

## Not buildable under the constraints

- **Hosted record services** (hosted SPF, DMARC, DKIM and MTA-STS, a vendor-hosted report inbox, agents that push to a cloud, minute-level probing from many regions) need a server. GitHub's scheduler runs at most every 5 minutes and can lag, so the runner offers hourly or nightly checks.
- **Screenshots and HTTP fingerprints of other sites** cannot be read from a page, and the scanner service sends no CORS header. CLI or runner only, and heavy.
- **A public status page** from the runner would need a public repository, which would publish host names.
- **Keyless reverse WHOIS**, peer benchmarking and vendor questionnaires, predictive risk scores at registration time, automated takedown filing and post-quantum detection in the browser need datasets, keys or a backend that do not exist for a static page.

## Next tier

Ranked, not yet specified: certificate policy rules with a 47-day readiness table; a branded customer report; a single `.eml` inspection (DKIM, SPF, DMARC); an SPF lookup budget with a flatten preview; a nightly zone backup from the DNS provider; lookalike domain watch; Zonemaster in Domain Health.
