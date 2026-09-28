# DomainScope — baseline build specification

> Written before implementation to give every module a binding contract. Modules have since been extended (backward-compatibly); **where this document and the code differ, the code is the source of truth.** Last synced with the code on 2026-09-28 (discovery engine v2 and the wired wordlist system — levels up to Huge, locale packs, custom and learned lists, safe sweep command: §1, §2, §3, §5.6, §5.8, §5.9, §5.11, §5.12, §5.17, §6; then SSL Targets › Verify, the Globalping check from the internet, ROADMAP P0.1 Phase A: §1, §2, §3, §4, §5.4, §5.17, §5.18, §5.19, §6, §8; then the Zone File view (ROADMAP P1.2 MVP) with the scanner's zone / exact mode, sibling-domain and per-host origin candidates, network ownership, live rows while scanning and the CLI's `--exclude`: §2, §5.4, §5.12, §5.13, §5.17, §5.20–§5.23, §6, §7; then the CLI's ORIGIN_CERT / PRIVATE_CERT statuses and `ip:port` targets, carried through the web app: §5.5, §5.16, §5.17, §5.19, §6, §7; then the Reverse DNS sweep with forward confirmation (ROADMAP P2.5) and Domain Health's mail identity check (FCrDNS of the MX addresses, part of P1.6): §1, §2, §3, §5.15, §5.28, §6, §8); then the shell's navigation — the phone Tools menu, the first-visit task picker and the shared keyboard shortcuts: §2, §5.29, §6; then the page session — the current target carried across the tools and each tool's kept result: §1, §2, §5.30, §6, §8; then Copy summary for Jira / Slack and the print stylesheet: §2, §5.32, §6, §8; then the installable app — service worker, web app manifests, offline tools — and a start route that loads only what it needs (per-view stylesheets, the discovery engine on the first scan): §1, §2, §5.1, §5.6, §5.11, §5.12, §5.33–§5.35, §6, §8; then, on 2026-09-27, no silent dashes, progress outside the view and a denser DNS Lookup and IP Intel: §2, §5.13–§5.15, §5.36–§5.38, §6, §8; then, on 2026-09-28, customer workspaces in IndexedDB with the hand-over file and expected CAs: §1, §2, §5.6, §5.29, §5.39–§5.42, §6).

## 0. Why this exists (product context — read this)

The primary persona is a DevOps engineer managing **hundreds of servers**. A customer sends a renewed SSL certificate (e.g. `*.example.com`) and they must find **which subdomains exist, what IPs they resolve to, and which of their own servers need the new cert installed** (e.g. 10 of 300 servers). Existing online tools disagree (5 vs 8 vs 9 subdomains) and **Cloudflare's orange cloud (proxy) hides origin IPs**. It is also meant to be a general **DNS toolbox**: global DNS (multi-resolver + geo view), full record lookup, bulk resolve, IP intel, domain health — "everything useful on the DNS side".

Deliverable: an **open-source static web app hosted on GitHub Pages** (no backend; everything runs in the visitor's browser against CORS-enabled public APIs) **plus** a companion stdlib-only Python CLI (`cli/ssl_origin_scan.py`) that is run *inside the user's network* to TLS-probe their server IPs with SNI — the only reliable way to find origins behind Cloudflare.

UI languages: Turkish + English (default by `navigator.language`, toggle). Turkish is first-class; the project is for everyone.

## 1. Hard constraints

- **No dependencies, no build step, no CDN.** Vanilla ES modules (`<script type="module">`), plain CSS. Pure libs must run in both browsers and Node 22 (`package.json` has `"type": "module"`). The Pages deploy only copies files: `tools/assemble-site.mjs` puts `assets/` under `v/<commit>/` (`v/dev-<content digest>/` when assembled without a commit) and points `index.html` there, so every deploy has new module URLs (GitHub Pages caches every file for 10 minutes and views load lazily). Hence every URL inside `assets/` is relative to its module (imports, stylesheets a view injects, and data files through `import.meta.url`); only `index.html`, `sw.js`, `favicon.svg`, the two web app manifests, `icons/` and `cli/` stay at the site root. `sw.js` is the one file written rather than copied: the deploy's precache list goes into it (§5.35). `tests/js/assemble-site.test.js` checks all of it.
- **Libraries in `assets/js/lib/` are DOM-free** (no `document`, `window`, `localStorage`). Use `globalThis.fetch`, `globalThis.crypto` only via injectable options where noted. UI code lives in `assets/js/ui/` and `assets/js/views/`.
- **Dependency injection for I/O:** every network function accepts `{ fetchImpl = globalThis.fetch, signal }` (and DNS-dependent functions accept a `dns` client object). This makes them unit-testable with mocks.
- **Every async network op supports `AbortSignal`** and timeouts.
- **Security:** Untrusted data (subdomains from CT logs, TXT records, RDAP, API responses) must **never** reach `innerHTML`. Build DOM with `textContent`/`createElement` only. `index.html` has a CSP meta: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https:; base-uri 'none'; form-action 'none'; manifest-src 'self'`. No inline `<script>`/`<style>`/`style=""` attributes in HTML (setting `el.style.x` from JS is OK). The service worker needs no CSP change: without `worker-src` / `child-src` the registration falls back to `script-src 'self'`, and `manifest-src 'self'` covers the web app manifests; a view's stylesheets are `<link rel="stylesheet">` elements (`style-src 'self'`), never inline.
- **Privacy:** certificate files and server inventory never leave the browser. The private key must never be needed; if a PEM contains a private key, warn and ignore it (never display it). Two features send user-chosen data to a third party, both through Globalping and both only after a click and a per-page-session consent (`ui/globalping-gate.js`, one consent per feature): SSL Targets › Verify sends only (public IP, host name, port) pairs — never a private address, the certificate or an inventory server name (§3 Globalping, §5.19) — and Domain Health's MTA-STS **Check the policy** sends the host name `mta-sts.<domain>` and the policy path for one probe (§5.24 `lib/mtasts.js`); both results are public by measurement ID for about six months, and both spend the same hourly quota. An imported zone file never leaves the browser and is never persisted; the Zone File live check sends only record names and types to the DoH resolvers, and only after a click (§5.23). A network-owner lookup sends one network address to RIPEstat, only on a click (§5.13). A reverse DNS sweep (Reverse DNS view, §5.28) sends the reverse names of the swept addresses and the PTR names it finds (PTR, then A / AAAA queries) to the DoH resolvers, only on a click, and never a private address; listing an AS's prefixes sends only the AS number to RIPEstat, only on a click; Domain Health adds the PTR and forward queries of the MX addresses to its DNS lookups (§5.15). The DANE / TLSA check sends MX and TLSA queries (names and types, never the certificate) to the DoH resolvers, only on a click (§5.25). The page session (§5.30: the current target and each tool's last result) lives in the tab's memory only; a carried target goes into the hash of the tool the user opens and is filled in there, and nothing is sent until that tool's button is pressed. What the app stores lives with the origin: the customer workspaces (§5.39: inventory text, learned names, custom wordlist, expected CAs, notes, recent domains) in its IndexedDB (database `ssds.workspaces`), the settings, remembered view options and a pointer to the active workspace in its `localStorage`. Every page of that origin can read both: a GitHub Pages project site (`<user>.github.io/<repo>/`) shares its origin with every other Pages site of the same user, so a deployment that keeps inventories should have an origin of its own (a custom domain, or a user / organisation site holding only this app). A workspace leaves the browser only as a hand-over file the user exports (§5.41), sealed with a password if one is given (§5.40; the password is never stored). The service worker of the Pages bundle (§5.35) keeps only the app's own files and the wordlist tiers a scan used in Cache Storage: never a third-party response, a URL with a query string, or anything the user typed, imported or looked up.
- Code style: 2-space indent, semicolons, single quotes, `const`/`let`, JSDoc on every export, small focused functions. Python: PEP 8, type hints, stdlib only, Python ≥ 3.8 compatible.
- Tests: `node --test "tests/js/*.test.js"` (= `npm test`, what CI runs; node:test + node:assert/strict; each file in its own process), `python -m unittest discover -s tests/python -v`. `node --test tests/js/` runs the same files through `tests/js/index.js`, which starts one `node --test` process per file so results never depend on file order. Tests must not hit the network (mock `fetchImpl`). Live/manual checks go in `tests/live/*.mjs` (not run in CI).
- Test data is generic: reserved names (`example.com/.net/.org`, `example-test.com.tr`) and documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). `tests/js/repo-hygiene.test.js` fails on any other IPv4 literal that is not well-known public infrastructure, and (locally) on anything matching the gitignored `.private-denylist`.

## 2. Repository layout

```
index.html                    # SPA shell (CSP meta, the global stylesheet only, web app manifest link, <script type=module src=assets/js/app.js>)
favicon.svg
sw.js                         # the service worker (classic script, scope = the site); BUILD = null here, the deploy's manifest in the bundle (§5.35)
manifest.webmanifest          # web app manifest, English (start_url / scope ./, icons, shortcuts); manifest.tr.webmanifest: the same in Turkish
icons/                        # PNG app icons drawn from favicon.svg by tools/build-icons.mjs (192, 512, maskable 512, apple-touch 180)
.nojekyll
package.json                  # {"name":"domainscope","private":true,"type":"module","scripts":{"test":"node --test \"tests/js/*.test.js\"","test:py":"python -m unittest discover -s tests/python -v","test:e2e:offline":"node tests/e2e/run-all.mjs --only shell,subdomains,zone,verify,dane,global,ptr,carry,ip,lookup,health,workspaces --offline --no-shots","serve":"node tests/e2e/serve.mjs 8080"}}
.github/workflows/ci.yml      # unit (Node 22/24), CLI (Python 3.8/3.12, Linux + Windows) and offline E2E (headless Chrome) jobs; on push to main, pull requests, by hand and workflow_call
.github/workflows/pages.yml   # Deploy to GitHub Pages: runs ci.yml first (`needs: test`), then publishes tools/assemble-site.mjs's bundle; one run at a time, never cancelling a running deployment
assets/css/style.css          # design system (tokens, light/dark, components)
assets/css/views/{subdomains,zone,scan,verify,dane,cert,global,lookup,bulk,ip,ptr,health,inventory,about}.css   # per-view styles (verify, dane: the ui/ panels), injected with their view (app.js VIEWS[].css)
assets/css/workspace.css      # the Workspaces dialog, injected with it on first use
assets/js/app.js              # bootstrap: router, i18n, theme, shared state; VIEWS (css / preload / offline), the offline note, ctx.requireOnline
assets/js/i18n.js             # t(key, params), setLang, registerStrings(lang, dict)
assets/js/state.js            # shared app state: the active workspace (inventory + its other parts, lib/workspace.js over IndexedDB), settings incl. `startTasks` (localStorage), the session; every storage access guarded
assets/js/workspace-db.js     # the IndexedDB backend of the workspaces (browser only; state.js falls back to memory without it)
assets/js/ui/dom.js           # h(tag, attrs, ...children) safe DOM builder, clear(el), etc.
assets/js/ui/components.js    # DataTable, Tabs, ProgressBar, Badge, CopyButton, FileDrop, Toast, Modal, etc.
assets/js/ui/download.js      # downloadText(filename, text, mime)
assets/js/ui/flag.js          # Flag(countryCode) with a globe fallback where the OS has no flag emoji
assets/js/ui/verify-panel.js  # the SSL Targets › Verify tab body (a ui/ module: every views/*.js is a routed view); styles in assets/css/views/verify.css
assets/js/ui/globalping-gate.js  # the page-session Globalping gate every send goes through: consent per purpose, the shared quota, the one-click consent + cost dialog (§6)
assets/js/ui/dane-panel.js    # the DANE / TLSA tab of the Certificate view and SSL Targets (§5.25); styles in assets/css/views/dane.css
assets/js/ui/start-tasks.js   # StartTaskList(): the first-visit task picker's job cards (the start page, About › Where to start; §6)
assets/js/ui/session-ui.js    # the header's current-target chip and the page header's kept-result note (§5.30, §6); styles in style.css
assets/js/ui/summary-button.js  # SummaryButton: Copy summary + Plain text in a view's result header, the clipboard-refused dialog (§5.32, §6)
assets/js/ui/pwa.js           # registers sw.js (Pages bundle only), "Update ready — Reload", reloadPage(), the manifest language (§5.35)
assets/js/ui/source-status.js # "⚠ n/a" marks, status sentences, per-service chips and the Retry of a failed source (§5.36, §6)
assets/js/ui/jobs.js          # a long job's progress outside its view: tab title, nav ring, favicon badge, opt-in notification (§5.38, §6)
assets/js/ui/workspace-ui.js  # the header's workspace switcher, its Tools menu row, a workspace's name, "Delete all local data" with its toast (§6)
assets/js/ui/workspace-panel.js  # the Workspaces dialog: switch / create / rename / delete, recent domains, expected CAs, notes, the hand-over file (loaded on first use, with assets/css/workspace.css)
assets/js/ui/expected-ca.js   # the "Expected CA" / "Unexpected CA" badge next to an issuer or a CAA value (§5.42)
assets/js/views/{subdomains,zone,scan,cert,global,lookup,bulk,ip,ptr,health,inventory,about}.js   # each exports {id, titleKey, icon, mount(container, ctx), unmount?()} + registers its i18n strings; subdomains is the default route
assets/js/lib/util.js
assets/js/lib/x509.js
assets/js/lib/domain.js
assets/js/lib/netinfo.js
assets/js/lib/inventory.js
assets/js/lib/wordlist.js
assets/js/lib/permute.js      # permutations(): alterx/dnsgen-style variants of found names (§5.12)
assets/js/lib/dnsmine.js      # mineDnsNames(): in-domain names from the zone's own records (§5.12)
assets/js/lib/learned.js      # createLearnedStore(): per-browser learned labels (§5.6)
assets/js/lib/cmdline.js      # buildSweepCommand(): validated, shell-quoted ssl_origin_scan.py sweep command (§5.17)
assets/js/lib/globalping.js   # Globalping v1 client: transport, quota, request builder, target prefilters (§5.18)
assets/js/lib/verify.js       # served-certificate verification: classification, CLI roll-up, runner, exports (§5.19)
assets/js/lib/mtasts.js       # MTA-STS policy (RFC 8461): the Globalping fetch request, parser, validator, export (§5.24)
assets/js/lib/zoneparse.js    # zone exports (BIND dialects, Cloudflare API, Route 53, octoDNS, Plesk) → records in dnswire shape (§5.20)
assets/js/lib/zonelint.js     # lintZone(): 38 closed-set rules (§5.21)
assets/js/lib/zoneorigins.js  # zone index, scan seeds, proxied-origin map, address map, CLI hand-off (§5.22)
assets/js/lib/zonedrift.js    # planDrift() / driftZone(): the zone vs live DNS over DoH (§5.23)
assets/js/lib/dane.js         # the DANE / TLSA renewal guard: TLSA association data, planDane() / checkDane() (§5.25)
assets/js/lib/ctcert.js       # lookupCtCertificate(): a host name's newest valid certificate from Certificate Transparency (§5.26)
assets/js/lib/scanform.js     # formProgress() / optionChanges() / barStuck(): the SSL Targets setup form as data (§5.27)
assets/js/lib/ptrsweep.js     # reverse DNS sweep: targets, an AS's prefixes (RIPEstat), FCrDNS verdicts, templated names, rows, exports, hand-offs (§5.28)
assets/js/lib/shellnav.js     # nav groups, first-visit jobs and keyboard shortcuts of the shell as data (§5.29)
assets/js/lib/session.js      # createSessionStore(): the page session — current target, carried routes, kept results (§5.30)
assets/js/lib/subtabs.js      # the Subdomains results tabs as data: the automatic tab, live tab counts, summary alerts, host name wrap points (§5.31)
assets/js/lib/summary.js      # buildSummary() / renderMarkdown() / permalinkParams(): a view's result as a short Markdown summary for Jira / Slack (§5.32)
assets/js/lib/sourcestatus.js # a failed data source as a status, and which empty fields it explains (§5.36)
assets/js/lib/density.js      # lookupLayout() / foldZeroStats(): DNS Lookup's and IP Intel's compact layouts as data (§5.37)
assets/js/lib/jobprogress.js  # a long job's overall progress, the badged favicon, the notification decision (§5.38)
assets/js/lib/workspace.js    # createWorkspaceStore(): customer workspaces over an async key-value backend, the first-run migration, part sanitizers (§5.39)
assets/js/lib/cryptobox.js    # sealText() / openText(): PBKDF2-SHA-256 + AES-GCM password encryption with WebCrypto (§5.40)
assets/js/lib/handover.js     # the workspace hand-over file: versioned JSON, plain or sealed (§5.41)
assets/js/lib/expectedca.js   # expectedCaStatus() / expectedCaaStatus(): an issuer or a CAA domain against the expected CAs (§5.42)
assets/js/lib/dnswire.js
assets/js/lib/resolvers.js
assets/js/lib/doh.js
assets/js/lib/propagation.js
assets/js/lib/sources.js
assets/js/lib/sourceinfo.js   # the source catalogue, quota semantics and sourceHealthSummary, without the fetchers (§5.34)
assets/js/lib/scanner.js
assets/js/lib/scanplan.js     # the pure plan parts of the engine the views use without it: stages, estimateQueries, learned labels (§5.33)
assets/js/lib/ipintel.js
assets/js/lib/rdap.js
assets/js/lib/health.js
assets/js/lib/export.js
assets/js/lib/pwa.js          # bundle / service worker paths, the precache list builder, wordlist cache keys (§5.35)
assets/data/                  # self-hosted wordlist tiers (wordlist-base.txt = smart, wordlist-{large,huge}.txt.gz), locale/<cc>.txt packs, wordlist-manifest.json, README (sources) + THIRD_PARTY_LICENSES.txt;
                              # sample-cert.pem: the "Try a sample" certificate (example.com / example.net, made-up CA; crafted by tests/fixtures/gen_x509_fixtures.mjs)
tools/build-wordlists.mjs     # maintainer tool: rebuilds assets/data from pinned upstream lists (+ tools/locale-data.mjs)
tools/assemble-site.mjs       # the Pages bundle: index.html, sw.js (with the deploy's precache list), favicon, manifests, icons/, .nojekyll and cli/ at the root, assets/ under v/<commit>/ (copies otherwise)
tools/build-icons.mjs         # maintainer tool: renders icons/*.png from favicon.svg in headless Chrome (tests/e2e/cdp.mjs)
cli/ssl_origin_scan.py
tests/fixtures/               # ALREADY EXISTS — see §4 (+ globalping/: trimmed, scrubbed real measurements, README; zones/: one export per format and dialect with parse goldens; zones-analysis/: lint / origin / drift goldens)
tests/js/*.test.js            # + tests/js/index.js (directory form, one process per file)
tests/python/test_ssl_origin_scan.py
tests/live/*.mjs              # manual live smoke scripts + discovery benchmark (network); targets from the gitignored targets.local.json via targets.mjs; globalping-smoke.mjs uses hard-coded public targets only (≤ 10 probes; `--capture` also records the two deliberate charged failures, localtest.me → 127.0.0.1 and `3fff::1`)
tests/e2e/*.mjs               # headless-browser E2E via Chrome DevTools Protocol (no deps; Node 22 global WebSocket); run-all.mjs runs every suite
docs/                         # SPEC (this file), ROADMAP, RESEARCH
```

## 3. Verified external endpoints (probed 2026-09-23 with `Origin: https://example.github.io`)

Only these are browser-usable (return `Access-Control-Allow-Origin`). Do not add endpoints that were not verified to send ACAO.

### Passive subdomain sources
| id | URL | Notes |
|---|---|---|
| `crtsh` | `https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y` (+`&exclude=expired`) | CT logs; slow (up to 60s+) and flaky (502/503, and a backend 404 page while it flaps). Retry plan (code: `sources.js`): the main `%.domain` form up to 4 attempts with 4 / 8 / 16 s backoff (±25 %; a 429 `Retry-After` over 60 s ends the retries), then a 32 s wait and ONE lighter `q=domain` identity search as the fallback (`queryForm: 'identity'`, result `partial`); gives up once another attempt would start after 180 s. Rows: `{issuer_ca_id, issuer_name, common_name, name_value ("a\nb" newline-separated SANs), id, entry_timestamp, not_before, not_after, serial_number, result_count}`. Dates are `YYYY-MM-DDTHH:MM:SS` UTC without Z. Duplicate rows per cert (precert+leaf) → dedupe by serial+issuer. |
| `certspotter` | `https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names` | JSON array `{id, tbs_sha256, cert_sha256, dns_names[], pubkey_sha256, not_before, not_after, revoked}`; paginate with `&after={last id}` (max 5 pages; a non-empty 5th page sets `truncated`: more may be left); unauthenticated quota: about 10 full-domain (`include_subdomains=true`) queries per hour per IP (100/h for single-hostname queries, which the scan never sends); 429 → rate-limit error and later pages are skipped. |
| `hackertarget` | `https://api.hackertarget.com/hostsearch/?q={d}` | text lines `host,ip`. Errors come as 200 text like `API count exceeded - Increase Quota with Membership` or `error ...` → treat as error. Free: ~50 req/day per IP (shared with reverseiplookup). Provides IP hints. |
| `anubis` | `https://anubisdb.com/anubis/subdomains/{d}` | JSON array of names (may contain `*.x`). (`jldc.me` is dead — do not use.) |
| `otx` | `https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns` | JSON `{passive_dns:[{hostname,address,record_type,first,last}]}`. Historical A records = great origin hints (pre-Cloudflare IPs). Anonymous → often 429 `{"detail":"Anonymous access ... limited"}` → rate-limit error, non-fatal. |
| `thc` | `POST https://ip.thc.org/api/v1/lookup/subdomains` body `{domain, limit: 100, page_state}` (sent as `text/plain` → no preflight) | ACAO `*`. JSON `{domains:[{domain, last_seen_on, …}], next_page_state, matching_records}`; 100 names per page, paginate by sending `next_page_state` back as `page_state` (`''` on the last page), max 10 pages (1,000 names) per domain, pages 2 s apart. Anonymous token bucket of about 250 requests per IP refilling 1 every 2 s. Provides `lastSeen` per name; `truncated` / `available` when more records exist. |

NOT usable from browser (no CORS): urlscan.io, subdomain.center, Wayback CDX, threatminer, api.cloudflare.com/client/v4/ips, jldc.me.

### One host name's certificate (verified 2026-09-27; Certificate view and SSL Targets step 1, `lib/ctcert.js`)
| Service | URL | Notes |
|---|---|---|
| Cert Spotter | `https://api.certspotter.com/v1/issuances?domain={host}&match_wildcards=true&expand=dns_names&expand=cert_der` (`*.x` queries leave out `match_wildcards`) | ACAO `*`. `cert_der` is the base64 DER of the final certificate, or of the precertificate while only that one is logged (the CT poison extension tells them apart). Unexpired issuances only, ascending id, 100 per page; `&after={last id}` pages on and an empty page ends the list (the `Link: rel="next"` header is not CORS-exposed). A single-host query counts against the **100 per hour** allowance per IP (`X-Ratelimit-Limit: 100`), not the 10 per hour full-domain one of the scan's source. The rate-limit headers are not CORS-exposed: a browser sees only the 429. |
| crt.sh | `https://crt.sh/?q={name}&output=json&exclude=expired` (the name, plus `*.{parent}`: identity searches match literally) | ACAO `*` on the JSON search, but the download `https://crt.sh/?d={id}` sends **no** ACAO: a page cannot read the certificate. The precertificate and the final certificate are two rows with the same serial that nothing in the JSON tells apart. Used only to *find* the certificate when Cert Spotter cannot answer; the user downloads the file and drops it. |

### DNS-over-HTTPS (RFC 8484 wire format, GET `?dns=<base64url>` + header `accept: application/dns-message`; `accept` is CORS-safelisted → no preflight)
Verified ACAO `*`:
| id | URL | location / notes |
|---|---|---|
| `cloudflare` | `https://cloudflare-dns.com/dns-query` | anycast; validates DNSSEC (AD); no ECS |
| `cloudflare-family` | `https://family.cloudflare-dns.com/dns-query` | anycast; malware+adult filtering |
| `google` | `https://dns.google/dns-query` | anycast; validates DNSSEC; **honours ECS** |
| `quad9` | `https://dns.quad9.net/dns-query` | anycast; malware filtering; validates DNSSEC; needs HTTP/2. **Not readable from browsers**: its HTTP/3 answers lack ACAO and Chrome/Edge use h3 from the first request (HTTPS RR alpn=h3); no endpoint/form workaround (measured 2026-09-23, `tests/live/browser-doh-matrix.mjs`) → `browserReliable:false`, not in DEFAULT_CHAIN / balance pool |
| `quad9-ecs` | `https://dns11.quad9.net/dns-query` | anycast; **ECS-enabled** variant; same HTTP/3-without-CORS limitation as `quad9` |
| `controld` | `https://freedns.controld.com/p0` | unfiltered; unreachable (TCP timeout) from at least one ISP network on 2026-09-23 → not in DEFAULT_CHAIN / balance pool |
| `dnssb` | `https://doh.dns.sb/dns-query` | |
| `iij` | `https://public.dns.iij.jp/dns-query` | Japan |
| `cleanbrowsing` | `https://doh.cleanbrowsing.org/doh/security-filter/` | security filter |
| `tiar` | `https://doh.tiar.app/dns-query` | Singapore |
| `seby` | `https://doh.seby.io/dns-query` | Australia |
| `cznic` | `https://odvr.nic.cz/doh` | Czechia (CZ.NIC ODVR) |
NOT usable (no ACAO): AdGuard, OpenDNS, NextDNS, Mullvad, AliDNS, DNSPod, Wikimedia, dns.sb json, CIRA, HE, SWITCH, LibreDNS, Yandex, 360, etc.
Also verified: Google JSON API `https://dns.google/resolve?name=..&type=..&edns_client_subnet={a.b.c.0/24}` (ACAO *), Cloudflare JSON `https://cloudflare-dns.com/dns-query?name=..&type=..` with `accept: application/dns-json`. Prefer wire format everywhere (one code path, all resolvers).

### IP intelligence / RDAP (all ACAO verified)
- RIPEstat (global data, not just RIPE region; add `&sourceapp=subdomain-scanner`): `https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}` (ASN, holder, prefix), `.../maxmind-geo-lite/data.json?resource={ip}` (country/city), `.../reverse-dns-ip/data.json?resource={ip}`, `.../whois/data.json?resource={ip}`.
- RIPEstat announced-prefixes (re-verified 2026-09-27, ACAO `*` on 200 and on 400): `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=domainscope` → `{ status: 'ok', data: { prefixes: [{ prefix, timelines: [{ starttime, endtime }] }], query_starttime, query_endtime, resource } }` over the last two weeks (a prefix whose last timeline ends before `query_endtime` is no longer announced); IPv4 and IPv6 mixed, unsorted. An unknown AS is `prefixes: []`; `ASxyz` is a 400 with `status: 'error'`. A large national ISP answers about 50 KB (≈ 480 prefixes, most of them /17s) in ~3 s.
- `https://ipwho.is/{ip}` (ACAO *) — fallback geo/ASN. `https://ipinfo.io/{ip}/json` (ACAO *; tokenless quota). `https://ipapi.co/{ip}/json/` (reflects origin; strict daily quota).
- `https://api.hackertarget.com/reverseiplookup/?q={ip}` (ACAO *) — domains on same IP (quota shared with hostsearch).
- RDAP: IANA bootstrap `https://data.iana.org/rdap/dns.json` (ACAO *), registry servers e.g. `https://rdap.verisign.com/com/v1/domain/{d}` (ACAO *), fallback `https://rdap.org/domain/{d}` (ACAO *, redirects). IP RDAP e.g. `https://rdap.db.ripe.net/ip/{ip}`. `.tr` has no RDAP in bootstrap → report `unsupportedTld`.

### CDN IP ranges (fetched 2026-09-23 from official sources — use verbatim)
Cloudflare v4: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
Cloudflare v6: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32
Fastly v4: 23.235.32.0/20, 43.249.72.0/22, 103.244.50.0/24, 103.245.222.0/23, 103.245.224.0/24, 104.156.80.0/20, 140.248.64.0/18, 140.248.128.0/17, 146.75.0.0/17, 151.101.0.0/16, 157.52.64.0/18, 167.82.0.0/17, 167.82.128.0/20, 167.82.160.0/20, 167.82.224.0/20, 172.111.64.0/18, 185.31.16.0/22, 199.27.72.0/21, 199.232.0.0/16
Fastly v6: 2a04:4e40::/32, 2a04:4e42::/32

### Globalping (verified 2026-09-24; the SSL Targets › Verify tab and Domain Health's MTA-STS policy check)
Anonymous use of `https://api.globalping.io/v1` only (never configurable from a URL or a setting). Facts the client and the verdicts rely on (raw evidence in `tests/fixtures/globalping/`, summary in [RESEARCH › Globalping facts](RESEARCH.md#globalping-facts-for-the-verify-tab-verified-2026-09-24)):
- **Endpoints:** `POST /measurements` (202 `{id, probesCount}`), `GET /measurements/{id}` (the whole measurement; `status` goes `in-progress` → `finished`), `GET /limits` (free). Measurement ids are alphanumeric; the client puts nothing else into a request path.
- **Body:** `{type:'http', target:<public IP>, limit:1, timeout:10, measurementOptions:{protocol:'HTTPS', port:443, request:{method:'HEAD', host:<name>, path:'/'}}}`. `request.host` sets both the SNI and the Host header; an IPv6 literal target works (the API picks a v6-capable probe). Always send `port` (the API default is 80) and never `ipVersion` with an IP target (400).
- **JSON only:** `content-type: application/json` is required — a `text/plain` body is ignored (`400 "type" is required`) — so every POST is preflighted (allowed, `Max-Age 600`). GETs send no custom header (simple requests, `cache: 'no-store'`, no ETag).
- **Quota:** `/v1/limits` carries it in the **body only** (`rateLimit.measurements.create {type, limit, remaining, reset}`; `reset` is 0 until the first spend, then a fixed 1-hour window). The POST 202 carries `X-RateLimit-{Limit,Consumed,Remaining,Reset}` and `X-Request-Cost` (= probes allocated), readable under the app CSP. **Remaining is not monotonic across concurrent POSTs** (220, 216, 215, 219, 217, 218 in one window; later 241, 240), so the client keeps the minimum per window. Anonymous: 250 probes per hour, **shared by everyone behind the same egress IP**. A POST 429 (`rate_limit_exceeded` / `insufficient_credits`) was not triggered live.
- **Free errors** (no quota spent): 400 for a private or reserved target (RFC 1918, 127/8, 100.64/10, 169.254/16, 192.0.0/24, TEST-NET-1/2/3, 198.18/15, 224/4, 240/4, 255.255.255.255, 0.0.0.0, `::`, `::1`, fc00::/7, fe80::/10, ff00::/8, 100::/64, 2001:db8::/32, mapped v4), for a host that is an IP, contains `_` or `*`, carries `:port` or a trailing dot, for `timeout` outside 5–30, and for a global `limit` together with `locations[i].limit`; 401 for a bad token (an anonymous retry works); 422 for a location without probes (also a v6 target plus a country without v6 probes).
- **Charged although useless:** port `0` (accepted, charged, treated as 443) and the IPv6 documentation prefix `3fff::/20` (accepted, charged, fails with `connect ENETUNREACH`). The client refuses both itself; `isGloballyRoutable` is an allowlist for IPv6.
- **Polling:** the limit is **per measurement id** (8 parallel GETs on one id gave 3 × `429 too_many_requests` with a readable `Retry-After: 5`; 12 different ids in parallel all got 200). Wait ≥ 500 ms before the first GET and after each response. Client deadline = `(timeout ?? 30) + 10` s; `timeout: 10` makes a filtered target finish in about 11 s; a success finishes in about 0.8 s (median).
- **`result.tls`:** `authorized`, `error` (only when unauthorized; **one** code — chain errors mask name errors), `createdAt`, `expiresAt`, `issuer{C,O,CN}`, `subject{CN, alt}` (Node's `subjectaltname` string, IPv6 SANs uncompressed), `keyType`, `keyBits`, `serialNumber` (colon hex, byte-aligned, no sign byte), `fingerprint256`, `publicKey` (RSA: the full SPKI; EC: the raw point), `protocol`, `cipherName`. Leaf only: no chain and no revocation (revoked.badssl.com is `authorized:true`). Any HTTP status (403, 421, 301) still carries `tls`. A failed test has no `tls`; its cause is in the `rawOutput` text only.
- **Payload:** a finished body is 2–35 KB (the headers appear three times); only a trimmed summary is kept (no headers or body, `rawOutput` for failures ≤ 300 chars, `publicKey` in memory only).
- **Privacy:** results — target IP, host name and the server's response headers — are readable by anyone with the measurement id for about six months. Probes are run by jsDelivr and volunteers (a `u-…` tag marks a probe adopted by a registered user) and send `User-Agent: globalping probe (https://github.com/jsdelivr/globalping)`.
- **HTTPS GET of a path (Domain Health › MTA-STS, verified 2026-09-27, fixtures `m26`, `m27`):** `{type:'http', target:<host name>, limit:1, timeout:10, measurementOptions:{protocol:'HTTPS', port:443, request:{method:'GET', path:'/.well-known/mta-sts.txt'}}}` — a host-name target (no `request.host`): the probe resolves it itself and uses it as SNI and Host header. A finished result carries `statusCode`, `headers` (lowercase names; values may be arrays), `rawBody` **already decoded** (a `content-encoding: br` body arrives as text, CRLF kept), `truncated` (bodies are cut at 10 KB) and the same `tls` object as a HEAD check. A host without an address fails with `rawOutput` `queryA ENODATA <host>` (charged, one probe). The results — the policy included — are public by id like any other.

## 4. Test fixtures (already generated in `tests/fixtures/` — do not regenerate)

`expected.json` holds openssl-derived ground truth per cert: `subjectCN, subjectDN (RFC2253), issuerCN, issuerDN, dnsNames[], ipAddresses[] (IPv6 in RFC 5952 compressed lowercase), emails[], serialHex (lowercase, no leading 00 sign byte), notBefore/notAfter (ISO UTC), sha256, sha1 (lowercase hex, no colons), keyAlgorithm ('RSA'|'EC'), keyBits, curve ('prime256v1' as printed by openssl — map to 'P-256' in our API), isCA, selfSigned`.

Files: `ca.pem` (test root CA), `rsa_multi_san.pem` (leaf signed by CA; SANs: 5 DNS incl. wildcard `*.cdn.example-test.com.tr` and IDN `xn--mnchen-3ya...`, IP 10.0.0.5, IP 2001:db8::1, email), `rsa_multi_san.der`, `rsa_multi_san_crlf.pem` (CRLF endings), `pasted_with_text.txt` (PEM surrounded by Turkish email text), `ec_wildcard.pem` (P-256, `*.wild.example.net` + `wild.example.net`, notAfter 2051 → GeneralizedTime), `cn_only.pem` (no SAN extension; CN=legacy.example.org), `many_sans.pem` (81 SANs → long-form DER lengths; serial 7fffffffffffffff01), `chain.pem` (leaf+CA), `chain_reversed.pem` (CA+leaf), `with_key.pem` (cert + PRIVATE KEY). Private keys `*.key` exist for rsa_multi_san, ec_wildcard, cn_only, many_sans — **test-only**, used by the Python CLI integration test to run local TLS servers.

`tests/fixtures/globalping/*.json` (+ `README.md`: shape, trim rules, scrub map, measurement ids) are real Globalping measurements of public targets (plus the deliberate charged failures m21, localtest.me → 127.0.0.1, and m25, `3fff::1`), trimmed and scrubbed (the badssl.com origin becomes `54.1.2.3`, user tags become `u-probe`), plus the refused-request cases and a few synthetic bodies marked `"synthetic": true`. `real_github.pem` is the certificate served in `m01-github-valid.json`, so the pair is a fully real UPDATED case. It expires on 2026-11-29, so every fixture test classifies with `now = capturedAt`.

## 5. Module contracts (exports are stable — code against them; the code wins where it has moved on)

All hostnames are lowercase ASCII (punycode), no trailing dot. All IPs canonical (`normalizeIP`). Dates are `Date` objects inside libs.

### 5.1 `lib/util.js`
```js
export class AbortError extends Error {}          // name 'AbortError'
export class TimeoutError extends Error {}        // name 'TimeoutError'
export class HttpError extends Error { status; url; body /* first 500 chars */ }
export function sleep(ms, signal) -> Promise<void>                       // rejects AbortError on abort
export function createLimiter(concurrency) -> { run(fn) -> Promise, setConcurrency(n), get active(), get pending(), clear() }
export async function fetchWithTimeout(url, { timeoutMs = 15000, signal, fetchImpl = globalThis.fetch, ...init }) -> Response   // throws TimeoutError / AbortError / TypeError(network)
export async function fetchJson(url, opts) -> any                          // non-2xx → HttpError
export async function fetchText(url, opts) -> string
export async function retry(fn, { retries = 2, baseDelayMs = 500, maxDelayMs = 8000, signal, shouldRetry = defaultShouldRetry }) -> any   // exponential backoff + jitter; never retries AbortError
export function defaultShouldRetry(err) -> bool                            // network TypeError, TimeoutError, HttpError 429/5xx
export function errorKind(err) -> 'abort'|'timeout'|'rate-limit'|'http'|'network'|'parse'|'unknown'
export function uniq(arr) ; export function chunk(arr, n)
export function randomLabel(len = 12) -> string                            // [a-z0-9] via crypto.getRandomValues
export function createCache({ maxEntries = 5000 }) -> { get(k), set(k, v), has(k), delete(k), clear(), size }   // LRU-ish
export function mergeSignals(...signals) -> AbortSignal
export function splitList(text) -> string[]                               // split on whitespace , ; newline; trims; drops empties and '#' comment lines
export function onceAsync(load) -> () => Promise                           // one shared run of an async loader (a module imported on first use); a rejection is forgotten, so the next call retries
```

### 5.2 `lib/x509.js` (pure JS DER/ASN.1; no deps)
```js
export class CertificateParseError extends Error {}
export function parseCertificates(input /* string | ArrayBuffer | Uint8Array */) -> {
  certificates: Certificate[],    // input order
  leaf: Certificate | null,       // non-CA cert that is not the issuer of another cert in the set; else first
  warnings: Array<{ code: 'PRIVATE_KEY_PRESENT'|'NO_CERTIFICATE'|'PKCS12_UNSUPPORTED'|'CSR_NOT_CERT'|'PARSE_ERROR'|'EXPIRED'|'NOT_YET_VALID', detail?: string }>
}   // never throws. Accepts: PEM (one or many blocks, CRLF, surrounding text), raw DER, bare base64 (no headers), PKCS#7/.p7b (PEM "PKCS7" or DER SignedData → extract certificates), detects PKCS#12 (.pfx) → PKCS12_UNSUPPORTED (UI shows `openssl pkcs12 -in file.pfx -nokeys -out cert.pem`), CSR ("CERTIFICATE REQUEST") → CSR_NOT_CERT.
export function parseCertificate(der: Uint8Array) -> Certificate           // throws CertificateParseError
export async function computeFingerprints(der, { subtle = globalThis.crypto?.subtle } = {}) -> { sha256, sha1 }   // lowercase hex
export function pemEncode(der, label = 'CERTIFICATE') -> string
export function formatFingerprint(hex) -> 'AB:CD:...'
Certificate = {
  der: Uint8Array, version: number, serialHex: string, signatureAlgorithm: string /* e.g. 'sha256WithRSAEncryption','ecdsa-with-SHA256' */,
  subject: { CN?, O?, OU?, C?, ST?, L?, ... } (first value per attr), subjectDN: string /* RFC 2253/4514 like openssl -nameopt RFC2253 */, subjectCN: string|null,
  issuer: {...}, issuerDN: string, issuerCN: string|null,
  notBefore: Date, notAfter: Date,
  dnsNames: string[], ipAddresses: string[], emails: string[], uris: string[],
  hostnames: string[],            // dnsNames lowercased; if none, [subjectCN] when CN looks like a hostname (legacy fallback)
  keyAlgorithm: 'RSA'|'EC'|'Ed25519'|'Ed448'|'DSA'|'unknown', keyBits: number|null, curve: 'P-256'|'P-384'|'P-521'|string|null,
  isCA: boolean, pathLen: number|null, keyUsage: string[], extKeyUsage: string[] /* 'serverAuth', ... */,
  selfSigned: boolean, subjectKeyId: string|null, authorityKeyId: string|null,
  ocspUrls: string[], caIssuersUrls: string[], crlUrls: string[], isPrecertificate: boolean, sctCount: number|null
}
```

### 5.3 `lib/domain.js`
```js
export function normalizeHostname(input, { allowWildcard = false } = {}) -> string|null  // trims; strips scheme, userinfo, path, query, port, trailing dot; lowercases; IDN→punycode (via new URL); allows '_' in labels; validates lengths (label 1–63, total ≤253); allowWildcard permits a single leading '*.'
export function parseHostList(text, opts) -> { valid: string[] (deduped, input order), invalid: string[] }
export function registrableDomain(host) -> string|null   // eTLD+1 with an embedded multi-label suffix list: ALL Turkish SLDs (com.tr, net.tr, org.tr, gov.tr, edu.tr, k12.tr, bel.tr, pol.tr, tsk.tr, gen.tr, web.tr, info.tr, biz.tr, name.tr, tel.tr, av.tr, dr.tr, bbs.tr, tv.tr, kep.tr, nc.tr, ...), co.uk family, com.au family, co.jp family, com.br family, co.nz, co.za, com.cn family, com.mx, co.in family, com.sg, com.hk, co.kr/or.kr, com.tw, co.il, com.ar, com.co, co.id, com.my, com.ua, etc. Fallback: last two labels.
export function isSubdomainOf(host, parent) -> bool     // true for equal
export function stripWildcard(name) -> { base: string, wildcard: boolean }
export function wildcardMatches(pattern, host) -> bool  // RFC 6125 §6.4.3: '*' only as the entire left-most label; matches exactly one label; '*.a.com' does NOT match 'a.com' or 'x.y.a.com'
export function certCovers(certHostnames, host) -> { covered: boolean, by: string|null }
export function sortHostnames(names) -> string[]        // by reversed labels so siblings group (apex first)
export function baseDomainsFromNames(names) -> string[] // unique registrable domains (wildcards stripped)
```

### 5.4 `lib/netinfo.js`
```js
export function ipVersion(s) -> 4|6|0
export function normalizeIP(s) -> string|null           // IPv4 dotted; IPv6 RFC 5952 lowercase compressed; strips [] and %zone; IPv4-mapped kept as '::ffff:1.2.3.4'
export function parseCidr(s) -> { version, network: bigint, prefix } | null
export function ipInCidr(ip, cidr) -> bool
export function isPrivateIP(ip) -> bool                 // v4: 0/8,10/8,100.64/10,127/8,169.254/16,172.16/12,192.168/16,192.0.0/24,198.18/15; v6: ::, ::1, fc00::/7, fe80::/10
export function privateRangeOf(ip) -> string|null        // the isPrivateIP range holding ip ('10.0.0.0/8'; mapped v4 → the v4 range), null when public / invalid. No two IPv4
                                                        // ranges touch, so an IPv4 block is all private exactly when one range holds both its ends (ptrsweep's too-large check)
export function isGloballyRoutable(ip) -> bool          // what a probe on the public internet (Globalping, later InternetDB) can reach. v4: false when isPrivateIP or in
                                                        // 192.0.2/24, 198.51.100/24, 203.0.113/24, 192.88.99/24, 224/4, 240/4; v6: ALLOWLIST, true only inside 2000::/3 and
                                                        // outside 2001::/32 (Teredo), 2001:2::/48, 2001:10::/28, 2001:20::/28, 2001:db8::/32, 2002::/16, 3fff::/20;
                                                        // mapped v4 → the v4 rules; invalid → false. isPrivateIP keeps its app-wide meaning ("an internal address")
export function reversePtrName(ip) -> string            // '4.3.2.1.in-addr.arpa' / nibble 'ip6.arpa'
export const RANGES_UPDATED = '2026-09-23'
export const PROVIDERS = [ { id, name, category: 'cdn'|'waf'|'platform'|'loadbalancer'|'hosting', hidesOrigin: boolean, certManagedByProvider: boolean, cidrs: string[], cnameSuffixes: string[] } ]
  // must include: cloudflare (IP ranges above + cname 'cdn.cloudflare.net'), fastly (ranges above + fastly.net, fastlylb.net), cloudfront (cloudfront.net), akamai (akamaiedge.net, akamai.net, edgekey.net, edgesuite.net, akamaized.net, akamaihd.net, akamaitechnologies.com), azure-frontdoor/cdn (azurefd.net, azureedge.net, trafficmanager.net? -> separate), imperva (incapdns.net, impervadns.net + official ranges only if verified), sucuri (sucuri.net cname only unless verified), stackpath, bunny (b-cdn.net), keycdn (kxcdn.com), cdn77 (cdn77.org, cdn77.net), edgio/edgecast (edgecastcdn.net), medianova (mncdn.com, mncdn.net — Turkish CDN), gcore (gcdn.co), and platforms: aws-elb (elb.amazonaws.com), aws-s3 (s3*.amazonaws.com), azure-appservice (azurewebsites.net), azure-trafficmanager (trafficmanager.net), github-pages (github.io), heroku (herokuapp.com, herokudns.com), vercel (vercel-dns.com, vercel.app), netlify (netlify.app, netlify.com), google-hosted (ghs.googlehosted.com, googlehosted.com), firebase (web.app, firebaseapp.com), shopify (myshopify.com), wpengine (wpengine.com), pantheon, render (onrender.com), fly (fly.dev), railway, digitalocean app (ondigitalocean.app). Only add IP ranges you verified from an official source in this session.
export function matchProviderByIP(ip) -> provider|null
export const SHARED_PROVIDER_CATEGORIES = ['cdn', 'waf', 'platform', 'loadbalancer', 'hosting', 'cloud']   // extension
export function isSharedProvider(provider) -> bool      // extension: multi-tenant space (one block serves many unrelated customers); false for a DNS-only steering provider
                                                        // (`dnsOnly`); accepts a PROVIDERS entry or any { category, dnsOnly? } (ipintel INFRA_NETWORKS). Display / sweep-policy hint only
export function matchProviderByCname(hostname) -> provider|null        // suffix match on label boundary
export function classifyResolution({ status, ipv4 = [], ipv6 = [], cnames = [] }) -> {
  kind: 'cloudflare'|'cdn'|'platform'|'direct'|'private'|'unresolved'|'nxdomain',
  provider: provider|null, hidesOrigin: boolean, certManagedByProvider: boolean, dangling: boolean /* CNAME chain present but final target NXDOMAIN/no address */, reasonKey: string /* i18n key e.g. 'class.cloudflare.ip' */
}   // priority: nxdomain(no cname) > dangling(unresolved) > cloudflare > cdn/waf > platform/loadbalancer > private(all IPs private) > direct
```

### 5.5 `lib/inventory.js`
```js
export function parseInventory(text) -> { servers: Server[], warnings: Array<{ line, code: 'NO_IP'|'INVALID_IP'|'DUPLICATE_IP'|'PARSE', text, detail?, reason?: 'port'|'zone'|'hostPort'|'sshPort' }>, stats: { lines, servers, ips } }
export function inventoryFormat(text) -> { format: 'empty'|'json'|'yaml'|'csv'|'ini'|'jsonl'|'lines', data? /* json, yaml: parsed */, delimiter?, header? /* csv: [{ role: 'name'|'ip'|'group'|'other', key }] */, nameColumn? /* csv, -1 without one */ }
  // the reader parseInventory picks (the same detection code); 'ini' = the line reader with an Ansible [group] header, 'jsonl' = every line a JSON object. Never throws.
Server = { id: string /* stable: name or first ip */, name: string, ips: string[], groups: string[], line: number }
  // Accept: "name ip [ip...]", "ip name", bare "ip", /etc/hosts "ip name alias...", CSV/TSV with header (columns like name/host/hostname/server, ip/ip_address/public_ip/private_ip/ipv4/ipv6/address), Ansible INI ("web01 ansible_host=1.2.3.4", [group] headers → groups), simple Ansible YAML (name:\n  ansible_host: 1.2.3.4), JSON (array/object: any string values that are IPs; name from name/hostname/host/Name/tags.Name; a host listed under an Ansible group's `hosts` or in `_meta.hostvars` always names its entry; in a machine record — named, holding an address key (`ip`, `address`, `ansible_host`, `public_ip`…), or an Ansible host's / group's vars — network, management and version attributes (gateway, netmask, dns, ntp, mac, iLO/iDRAC/IPMI/BMC, *_version) are ignored, and a name key holding an IP is read as that IP, never as a server called "name"), comments (#, ;, //). Same name on several lines → merge IPs. Loopback, multicast, broadcast and IPv6 link-local (fe80::/10) addresses never make a server.
export function buildIpIndex(servers) -> Map<string /* ip */, Server[]>
export function lookupServers(ips, index) -> Array<{ server: Server, ip: string }>
export function formatEndpoint(ip, port = null) -> string|null   // '203.0.113.10:8443' / '[2001:db8::1]:8443'; the bare address without a valid port; null for a non-IP
export function addressTargets(server, ip) -> string[]           // the -t tokens of one address: bare, or one ip:port per port it was written with
export function serverTargets(server) -> string[]                // addressTargets of every address, in order, unique
```
**Ports.** An address may carry its own port, as `cli/ssl_origin_scan.py` reads it: `203.0.113.10:8443`, `[2001:db8::1]:8443` (IPv6 needs the brackets; a bracketed IPv4 is accepted), in every format (lines, `NAME=IP`, CSV cells, INI `ansible_host=`, YAML / JSON values). The server then carries `ports: { [ip]: Array<number|null> }` — only when some address has a port, so the result shape is unchanged otherwise — where `null` stands for the CLI's `-p` ports (the same address was also given bare). Merging follows the CLI's `Server.add_ip`: an address first bare and then with a port gets both, and an unnamed line of a named server's address adds its port (or its `-p` ports) to that server, so `serverTargets` / targets.txt scan every ip:port the CLI would scan reading the inventory itself. An empty port (`203.0.113.10:`, "ip: name" lines) is none. A port that is not digits making 1–65535 (`:0`, `:99999`, `:https`) and a CIDR with a port are an `INVALID_IP` warning, never a silently dropped address; so is a bad address or port in a first-token `NAME=IP`, in a JSON / YAML value (`{"web01": "203.0.113.10:99999"}`, `ansible_host:`; a name key holding one names nothing), and a bracketed token that cannot be read (`[2001:db8::1]8443`). When the address itself is fine the warning has `reason: 'port'` (the Servers view then says the port is the problem), or `reason: 'zone'` for an IPv6 zone id with a port (`[fe80::1%eth0]:8443`, which the CLI cannot keep). A host name with a port (`web01.example.net:8443`, also as `NAME=HOST:PORT`, `ansible_host=` or a whole JSON / YAML value with a dotted host where a target is read: `ansible_host` / `ansible_ssh_host`, a name map's entry `{"web01": "web01.example.net:8443"}` or a Terraform output outside any record or vars map, a top-level string — never another attribute of a record or a vars map (`consul_addr`, `db_url`, an RDS `endpoint`, `health_url`), which the CLI does not read either; `"image": "redis:7"` is none) is a `PARSE` warning with the token as `detail` and `reason: 'hostPort'`: servers here are matched by address only (the CLI resolves it on a line of its own, and warns too next to an address).

**Ansible host patterns.** In an Ansible INI context — a line under a `[group]` header, or one with an `ansible_*=` variable — a port on the host pattern, the first token (`203.0.113.11:2222`, `[2001:db8::5]:2222`, `badwolf.example.com:5309`, `web01:2222`), is Ansible's SSH port (`ansible_port`), as Ansible's own INI parser reads it, never a TLS port: the host is kept without it (on `-p`, so targets.txt and the Verify CLI card write it bare) and a `PARSE` warning with `reason: 'sshPort'` says so; the view never suggests moving it onto the address. A later token keeps the TLS meaning (`web02 203.0.113.12:8443` is no valid Ansible anyway), and so does the first token of a plain list, a hosts file or a first-token `NAME=IP:PORT`. A port there that is not 1–65535 is an `INVALID_IP` as anywhere else. **Duplicates** are per endpoint: `DUPLICATE_IP` flags an address on the same port (or bare on both) in several servers, one warning per server and address, with the endpoint in `detail`; one address on different ports (a NAT forwarding each port elsewhere) is none. `stats.ips` still counts addresses. A first-token `NAME=host.name` (a dotted host name, which the CLI resolves) names a server without an IP (`NO_IP`); a value without a dot or port (`user=root`) stays a variable. A time of day (`10:30`, `10:30:00`) is neither a host and its port nor an IPv6 address. `tests/fixtures/inventory-ports.txt` pins the parity with the CLI (the same servers, endpoints and warning lines in `tests/js/inventory.test.js` and `tests/python/test_inventory_targets.py`).

### 5.6 `lib/wordlist.js`
The product is global: every list that is tried on every domain is **language-neutral**. Market vocabulary (Turkish, German, …) lives only in the locale packs, and nothing is ever tuned to one organisation's zone.
```js
export const WORDLIST_SMALL      // 159 labels, no I/O: web/mail/DNS, remote access + platform infra, environments, apps, numbered variants, and the top-ranked SecLists labels (mostly standard Microsoft 365 / cPanel records)
export const WORDLIST_MEDIUM     // 1,146 labels, strict superset of SMALL (SMALL first); kept for the scanner's legacy 'medium' mode
export function getWordlist(size = 'small') -> string[]           // 'small'|'medium'; [] for 'off'/unknown
export const WORDLIST_LEVELS = ['small', 'smart', 'large', 'huge']
export const LOCALE_PACK_CODES = ['tr','de','fr','es','pt','it','nl','pl','ru','ar','ja','zh']
export async function loadWordlist(level = 'small', { domain, locales, extra, fetchImpl, signal, onInfo, preferFetch } = {}) -> string[]
  // Ordered, de-duplicated: extra → WORDLIST_SMALL → locale packs → base (smart, ≈7,000) → large (≈50,000, gzip) → huge (≈130,000, gzip).
  // 'small' does no I/O and loads no locale packs (extra + WORDLIST_SMALL only); an unknown level behaves as 'small'.
  // The tiers are self-hosted in assets/data/ (fetch + DecompressionStream in browsers, fs + zlib in Node).
  // Locale packs: explicit `locales` win ([] disables); otherwise inferred from `domain` via localesForDomain(). Unknown codes are ignored.
  // `extra` (learned / custom labels) is validated and tried first; multi-label prefixes like 'dev.api' are allowed.
  // A tier that fails to load degrades to the next smaller one: onInfo({ type: 'degrade', requested, served, reason });
  // a missing locale pack is skipped: onInfo({ type: 'locale-missing', locale }). AbortError always propagates.
  // preferFetch is test-only (forces the browser path under Node).
export function wordlistInfo() -> { levels: { small, smart, large, huge }, locales: { [cc]: … } }   // each { id, approxCount, bytes, sources, licence }; build-time constants, no download
export function parseCustomWordlist(text) -> { labels: string[], rejected: string[] }   // one entry per line / comma / whitespace, '#' comment lines skipped, lowercased, IDN labels converted to punycode ('şube' → 'xn--ube-rza'), deduped, capped at 200,000
export function localesForDomain(domain) -> string[]   // from the last label (the ccTLD), e.g. 'example.com.tr' → ['tr'], 'example.ch' → ['de','fr','it'], 'example.com' / 'example.co.uk' → []
export function clearWordlistCache()
```
Data files, sources and licences: `assets/data/README.md` (built by `tools/build-wordlists.mjs` from SecLists, bitquark, commonspeak2, dnsgen and altdns; MIT / Apache-2.0; the full licence texts ship as `assets/data/THIRD_PARTY_LICENSES.txt`, linked from About). Build-time sizes (`wordlistInfo()`; `tests/js/wordlist-info.test.js` keeps them equal to the files): small 159 (built in) · smart 7,000 (`wordlist-base.txt`, 42,399 B) · large 50,000 (`wordlist-large.txt.gz`, 182,788 B) · huge 130,000 (`wordlist-huge.txt.gz`, 588,172 B). `wordlist-manifest.json` also carries the SHA-256 of every tier file and locale pack (`sha256`, written by the builder, checked by the same test and again by `tools/assemble-site.mjs`): the service worker caches the wordlists under that hash, so a tier downloaded once is reused across deploys until its content changes (§5.35). The three files are prefixes of one master ranking (base ⊂ large ⊂ huge). Locale packs (original MIT curation, ASCII-folded, 83–283 labels): tr 283, de 181, fr 171, es 180, pt 169, it 152, nl 124, pl 127, ru 126, ar 128, ja 83, zh 93.

`localesForDomain()` reads the last label: `tr` → tr; `de`, `at`, `li` → de; `ch` → de, fr, it; `fr`, `mc` → fr; `be` → fr, nl; `lu` → fr, de; Spanish-speaking ccTLDs (`es`, `mx`, `ar`, `co`, `cl`, `pe`, …) → es; `br`, `pt` → pt; `it`, `sm` → it; `nl`; `pl`; `ru`, `by`, `kz`, `ua`, `kg`, `uz` → ru; Arabic-speaking ccTLDs (`sa`, `ae`, `eg`, `qa`, …) → ar; `jp` → ja; `cn`, `tw`, `hk`, `mo` → zh. Generic TLDs (`.com`, `.net`, `.org`, `.io`, …) get none — the user picks packs manually.

`lib/learned.js` (DOM-free; storage injected, so it never touches `localStorage` itself):
```js
export function createLearnedStore(storage /* localStorage-like { getItem, setItem } | null = memory only */, { key = 'ssds.learned.labels', max = 5000 } = {}) -> {
  labels() -> string[]                 // ranked: most hits first, then most recent, then alphabetical
  record(names, apex?) -> number       // stores the bare label(s) each name contributes relative to `apex`
                                       // ('dev.api.example.com' + 'example.com' → 'dev', 'api'; no apex → the first label only);
                                       // refuses IPs, wildcards, the apex itself, invalid and purely numeric labels; returns how many labels were new
  size() -> number, clear(), export() -> { v: 1, seq, labels: { [label]: [hits, last] } }, import(data)
}
// Privacy: only bare labels are ever stored — never full hostnames, never IP addresses. Every storage access is guarded
// (private mode, quota, corrupt JSON → an in-memory store, never a throw). Over `max`, the fewest-hit / oldest labels are evicted.
```

Current wiring (code wins): the scanner builds each scanned apex's list with `loadWordlist(level, { domain: apex, locales, extra: [...custom, ...learned], fetchImpl, signal, onInfo })` and caches it per (level, locale set) — see §5.12. The Subdomains view offers every level (Off / Small / Smart / Large / Huge), the locale choice (auto from the domain ending / a manual list / none), a custom wordlist (pasted or a `.txt` file read in the browser, files up to 5 MiB; kept in the active workspace, §5.39 part `wordlist`, written once per burst of keystrokes) and the learned store (the workspace's `learned` part through `state.learnedStorage`, a Storage-like view for `createLearnedStore`; **opt-in, off by default**): when switched on, each finished scan records `learnedLabelsFromScan(result)` for the hosts under the scanned domains, and the next scan passes the 1,000 top-ranked labels as `learnedLabels` — never at level Off. The labels stay in the browser, but a later scan sends them as DNS lookups (`label.<domain>`), so resolvers and that domain's name servers see them. SSL Targets reuses the same three settings; a finished scan records into the workspace it started in (`run.config.workspace`), never into one switched to meanwhile. "Delete all local data" (`state.clearAll()`) deletes every workspace (the IndexedDB database) and removes every `ssds.*` key from both storages. Before workspaces the custom list lived in `sessionStorage` (`ssds.wordlist.custom`) and the learned labels in `localStorage` (`ssds.learned.labels`): the first load moves both into Default (§5.39).

### 5.7 `lib/dnswire.js`
```js
export const TYPES = { A:1, NS:2, CNAME:5, SOA:6, PTR:12, MX:15, TXT:16, AAAA:28, SRV:33, NAPTR:35, DS:43, RRSIG:46, NSEC:47, DNSKEY:48, NSEC3:50, TLSA:52, SVCB:64, HTTPS:65, CAA:257, ANY:255 }
export const RCODES = { 0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN', 4:'NOTIMP', 5:'REFUSED', ... }
export function typeToNumber(t) ; export function typeToName(n)          // unknown → 'TYPE123'
export function encodeQuery(name, type, { id = 0, rd = true, cd = false, dnssecOk = false, ecs = null /* { address, sourcePrefix } or 'a.b.c.d/24' */, udpSize = 1232 } = {}) -> Uint8Array   // always adds EDNS0 OPT; ECS option code 8 per RFC 7871 (address truncated to ceil(prefix/8) bytes, host bits zeroed)
export function decodeMessage(bytes) -> {
  id, flags: { qr, opcode, aa, tc, rd, ra, ad, cd }, rcode: number, rcodeName: string,
  questions: [{ name, type, typeNum, class }], answers: RR[], authorities: RR[], additionals: RR[],
  edns: null | { udpSize, version, dnssecOk, extendedRcode, options: [{ code, data: Uint8Array }], ecs: null | { family, sourcePrefix, scopePrefix, address }, ede: [{ code, text }] }
}   // handles name compression (with loop protection), throws DnsWireError on malformed input
RR = { name, type /* name string */, typeNum, class, ttl, data /* parsed, see below */, text /* presentation format rdata */ }
  A/AAAA: data = ip string (canonical) · CNAME/NS/PTR: data = target (lowercase, no trailing dot) · MX: { preference, exchange } · TXT: data = string[] (character-strings, UTF-8 decoded) · SOA: { mname, rname, serial, refresh, retry, expire, minimum } · SRV: { priority, weight, port, target } · CAA: { flags, tag, value } (a tag that is not ASCII letters / digits, RFC 8659, degrades to the generic form with `error`) · DS: { keyTag, algorithm, digestType, digest /* hex */ } · DNSKEY: { flags, protocol, algorithm, publicKey /* base64 */, keyTag /* RFC 4034 App. B */ } · RRSIG: { typeCovered, algorithm, labels, originalTtl, expiration: Date, inception: Date, keyTag, signerName, signature /* base64 */ } · TLSA: { usage, selector, matchingType, data /* hex */ } · SVCB/HTTPS: { priority, target, params: { alpn?: string[], 'no-default-alpn'?: true, port?, ipv4hint?: string[], ech?: base64, ipv6hint?: string[], [key]: hex } } · NAPTR, NSEC, NSEC3: reasonable objects · unknown: data = hex, text = '\\# <len> <hex>'
export class DnsWireError extends Error {}
export function base64UrlEncode(bytes) -> string                          // no padding
```

### 5.8 `lib/resolvers.js`
```js
export const RESOLVERS = [ { id, name, operator, url, location /* e.g. 'Anycast', 'Japan' */, countryCode: string|null, ecs: boolean, dnssecValidating: boolean, filtering: null|'malware'|'security'|'family', homepage } ]   // exactly the 12 verified in §3 (re-verify each live with Node http2 + Origin header; drop any that fail and report)
export const DEFAULT_CHAIN = ['cloudflare', 'google', 'dnssb', 'cznic']   // failover order for general lookups (unfiltered + browser-readable; quad9 dropped 2026-09-23, see §3)
export const GEO_VANTAGES = [ { id /* 'de-ham' */, countryCode: 'DE', city: 'Hamburg'|null, nameTr, nameEn, subnet: 'x.y.z.0/24', isp, asn, verifiedCountry } ]   // 31 vantage points in 27 countries on every inhabited continent (Europe, the Americas, Asia, the Middle East, Africa, Oceania; the US has east + west). Pick big-ISP subnets and VERIFY each with RIPEstat maxmind-geo-lite (record `verifiedCountry`); also verify Google DoH returns an ECS scope for one vantage.
export function getResolver(id) -> resolver|undefined
export function flagEmoji(countryCode) -> string
```

### 5.9 `lib/doh.js`
```js
export class DohClient {
  constructor({ chain = DEFAULT_CHAIN, concurrency = 12, timeoutMs = 8000, retries = 1, fetchImpl = globalThis.fetch, cache = true } = {})
  async query(name, type = 'A', { resolver /* id: query only this one, no failover */, ecs, dnssec = false /* DO bit */, cd = false, signal, noCache = false } = {}) -> DnsResponse
  async resolveHost(name, { signal, resolver } = {}) -> HostResolution          // A + AAAA concurrently
  async detectWildcard(domain, { signal } = {}) -> { wildcard: boolean, ipv4: string[], ipv6: string[], cnames: string[] }   // 2 random labels; a hit = NOERROR with addresses, or a CNAME chain whatever the rcode (a `*` CNAME to a gone target answers NXDOMAIN + CNAME); extensions: probes, ttl, error, dangling (every hit ends in NXDOMAIN with no address)
  async ptr(ip, { signal } = {}) -> string[]
  setConcurrency(n) ; stats() -> { queries, cacheHits, failures, byResolver: { [id]: { ok, fail, avgMs } } }
}
DnsResponse = { name, type, resolver /* id that answered */, ok: boolean /* got a DNS answer (any rcode) */, rcode: 'NOERROR'|'NXDOMAIN'|'SERVFAIL'|..., flags, answers: RR[], authorities: RR[], ecs /* echoed ECS or null */, ede: [], elapsedMs, error: string|null /* transport error message when ok=false */, errorKind }
HostResolution = { name, status: 'NOERROR'|'NXDOMAIN'|'SERVFAIL'|'REFUSED'|'ERROR', cnames: string[] /* chain order */, ipv4: string[], ipv6: string[], ttl: number|null /* min TTL */, resolver, error: string|null }
// Failover (when no explicit resolver): transport error / timeout / HTTP 429/5xx / SERVFAIL|REFUSED → try next in chain. Uses GET ?dns= with id=0 and accept header. Cache key includes name/type/resolver/ecs/dnssec/cd.
```
Current wiring (code wins), v2 extensions:
- `balancePool` constructor option (default `['cloudflare', 'google', 'dnssb']`, filtered to the chain unless given explicitly) and `resolveHost(name, { balance: true })` / `query(…, { balance: true })`: bulk A-only probes rotate over the pool instead of hammering the first resolver; failover still applies. The `balancePool` getter lists the ids the rotation uses (browser-unreliable members, failover only, left out).
- Per-resolver circuit breaker: repeated transport failures open it (the resolver is skipped, `stats().byResolver[id].down`), and after a cool-down one half-open probe decides whether it closes again.
- Per-call `timeoutMs` / `retries` overrides on `query` / `resolveHost`; `concurrency` getter next to `setConcurrency`; `stats()` also reports `requests` and `shared` (in-flight de-duplication).
- `ptr(ip, { throwOnError: true })`: a lookup that got no DNS answer, or an rcode other than NOERROR / NXDOMAIN, rejects with an Error (`kind` = the failure's errorKind, `rcode` = the answer's rcode such as SERVFAIL when there was one) instead of yielding `[]`, so lib/ipintel.js and Bulk Resolve can tell "no PTR record" from "could not ask" (§5.36).
- `export async function detectWildcardDeep(dns, parent, { signal, resolvers = [], probes = 2 })` → `{ wildcard, kind: 'A'|'CNAME'|'NODATA'|null, ipv4, ipv6, cnames, targets, variable, conclusive }`: `probes` random labels on the chain plus one on each resolver of `resolvers` (2.5 s cap, no retry pass); an 'A' or 'CNAME' wildcard needs every chain probe, or at least two probes, to show that kind, and a probe answering NODATA / NXDOMAIN or another kind does not veto it (GeoDNS with no default record, a stale resolver); a kind only one probe showed is re-asked once on the same resolver; with nothing synthesized the chain probes decide (all NOERROR-empty → NODATA, all NXDOMAIN → none, disagreeing → inconclusive); failed probes are skipped. An 'A' wildcard carries the union of the addresses, a 'CNAME' one the first probe's chain in `cnames` and every first target in `targets`; `variable` is set when the values differed (GeoDNS / ECS, a CDN alias, a multivalue pool). NODATA only counts when DNSSEC does not prove non-existence (compact denial). `conclusive` is false when the check proved nothing (too few answers, disagreeing chain probes, an NXDOMAIN next to an answer); an all-NXDOMAIN "no wildcard" and every wildcard are conclusive. The scanner runs it at every level that hosts a discovered name, with its balance pool as `resolvers` (minus any whose breaker is open), and matches a name against its closest checked ancestor (RFC 4592): that level's wildcard applies, a conclusive "no wildcard" there shields the name from any farther wildcard, an inconclusive check is skipped; a stable wildcard is matched exactly, a variable one also by /24 · /48, by its single provider, or by a CNAME target under the same parent; a parent where more than half of at least 50 answered guesses resolved is re-sampled (8 labels): if at least two random labels resolve to values the first check had not seen, or vary with no usable first check, it is marked `flooded` and every answer of its kind is then a look-alike; a stable re-sample with no usable first check becomes the exact fingerprint, and one that adds nothing leaves the hits standing.

### 5.10 `lib/propagation.js`
```js
export async function checkPropagation(name, type, { dns /* DohClient */, resolvers /* ids, default all RESOLVERS */, vantages /* default GEO_VANTAGES */, geoResolver = 'google', signal, onResult /* (item) => void, item = { kind: 'resolver'|'geo', key, response, values } */ } = {}) -> {
  resolverResults: [{ resolver, response, values: string[] }],
  geoResults: [{ vantage, resolver, response, values: string[], scopePrefix }],
  groups: [{ key, values: string[], members: string[] /* 'resolver:<id>' | 'geo:<id>' */ }],   // sorted by members desc
  consistent: boolean
}
export function answerValues(response, type) -> string[]   // sorted canonical rdata text of records of `type` (CNAME chain appended as 'CNAME target' when type != CNAME and chain exists); NXDOMAIN → ['NXDOMAIN']; error → ['ERROR']
```
Current wiring (code wins), extensions:
- `checkPropagation` also returns `resolversConsistent`, `geoConsistent`, `name`, `type`, `startedAt`, `finishedAt`, `addresses` (every IP seen, with provider / private / members) and `verdict` (below, over every result).
- `export function splitChain(values) -> { plain: string[], chain: string[] }`: answer values without / with the 'CNAME target' entries (chain order).
- `export function propagationVerdict(items, { type = 'A', ipInfo = null } = {}) -> Verdict`: why the answers differ. DOM-free and offline — no network call: operators come from netinfo (published ranges, CNAME suffixes, DNS-level steering such as Azure Traffic Manager) and, for addresses netinfo calls direct, from PTR names / origin ASNs a caller already fetched (`ipInfo`: `Map` or object, canonical IP → ipintel IpInfo or `{ ptr, asn, asns }`; a PTR under a provider domain, or an `ipintel.networkHint` 'cdn-edge' AS such as Akamai's). `items` are checkPropagation results or streamed rows (`{ key, kind?, values, filtered?, pending?, resolver? }`); pending, filtered (blocked) and transport-error items are ignored. Operators are judged for A / AAAA only.
  - `VERDICT_STATES = ['none', 'unresolved', 'agree', 'by-design', 'geo', 'differ']`: `unresolved` = every usable answer is an error rcode (SERVFAIL, REFUSED …), so nobody resolves the name — never `agree`; `by-design` = A / AAAA answers that differ, every address an edge of a known operator (netinfo kind cloudflare / cdn / platform, or DNS-level steering), the CNAME chains agree until each enters the operator's name space — through that entry name when both enter the same operator (two CloudFront distributions, two Netlify sites, two GitHub Pages users or two Azure Traffic Manager profiles are a change; only regional load balancers, netinfo category `loadbalancer` without `dnsOnly` such as AWS ELB, may differ there; a provider name equals its `dualstack.` variant) — different operators diverge only behind a name every answer shares (Amazon's `tp.…frontier.amazon.com` steering to CloudFront or Akamai), never at the queried name itself, and no NXDOMAIN / NODATA / rcode / private address anywhere (a private address is never an edge, even behind a CDN's CNAME) — except NODATA whose chain enters the provider through the entry name the addresses come through (its `dualstack.` variant included) while the resolvers agree (www.reddit.com AAAA: every resolver gets `x.map.fastly.net` without AAAA, two locations `dualstack.x.map.fastly.net` with Fastly IPv6 edges; NODATA through another entry name there is `geo`). A name before the entry may still differ when both names lead to the same entry names — every answer through one of them arrives at entry names that answers through the other reach too (weighted or load-balanced records in the name's own DNS: Etsy's `zone1` / `zone2` → one `*.map.fastly.net` name, Pinterest's `gslb` / `gslb2` → Akamai or Fastly); another entry name behind them (d111… vs d222….cloudfront.net) or a direct answer is never that. With no records of the type anywhere (`noRecords`: every non-rcode answer NODATA, e.g. AAAA of an IPv4-only CDN name) the CNAME chains alone are judged the same way, each entering by CNAME (a chain that never enters an operator must then match all the way to the other's entry name); `geo` = only ECS locations differ and nothing looks wrong — a CNAME or provider that differs only between locations while the resolvers agree is GeoDNS by CNAME (geolocation records), as different addresses there are; `differ` = everything else.
  - `VERDICT_FINDINGS = ['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'operators', 'direct', 'records']` (most serious first; only in `differ` and `unresolved`): `{ code, groups: string[] /* group keys */, members: string[] }` plus `rcode` ('rcode'), `filtering` ('rcode', 'nxdomain', 'nodata': only filtering resolvers give it, so it may also be their block — still a difference), `ips` ('private'; 'mixed': direct addresses next to edges), `owner` (null = the queried name) / `targets` (a name, or null = address records — with `noRecords`, no CNAME and no records) ('cname') and `operators` ('cname', 'operators': the managed operators involved when the answers enter different ones — a move between providers unless steered on purpose — else `[]`). `operators` = the queried name's own A / AAAA records name different operators (Netlify's address at the apex on some resolvers, Vercel's on others); `direct` = different public addresses with no known operator; `records` = other record types differ. `nxdomain` / `nodata` are findings only next to another kind of answer (an address, NODATA vs NXDOMAIN), not next to rcode failures alone.
  - `SAFE_SEARCH_TARGETS`: the SafeSearch names filtering resolvers rewrite search engines to (`forcesafesearch.google.com`, `restrict.youtube.com`, `restrictmoderate.youtube.com`, `strict.bing.com`, `safe.duckduckgo.com`, `familysearch.yandex.ru`, `safesearch.pixabay.com`). An answer that only filtering resolvers give while an unfiltered source answers differently is their policy only when its CNAME chain (or, for a CNAME query, its record) reaches one of them: its group is `rewritten`, its sources and targets are listed in `rewritten` / `rewriteTargets`, and the rest is judged without it. Any other answer only they give — an address, NXDOMAIN, NODATA, a CNAME to an ordinary name — stays a difference: a stale cache looks the same. (Blocks need no list: Cloudflare Family's 0.0.0.0 / :: with an EDE is `filtered`; Quad9's and CleanBrowsing's NXDOMAIN stays in.)
```js
Verdict = { state, type /* name */, groups: [{ key, values, members, status: 'answer'|'nxdomain'|'nodata'|'rcode', chain, addresses, operators: Operator[] /* of its addresses; a NODATA group: the provider its chain enters */, managed: boolean, rewritten: boolean }] /* members desc */,
  operators: (Operator & { members: string[] })[] /* managed only, of the judged groups (answers, or the chains with noRecords), most sources first */, findings, resolversAgree, designPart /* differ, but ≥ 2 edge groups differ by design and no 'cname' / 'operators' finding */, multiOperator,
  noRecords /* A / AAAA: every non-rcode answer is NODATA */, steering: { owner /* null = the queried name */, targets: string[] }[] /* names before the entry that lead to the same entry names */, rewritten: string[], rewriteTargets: string[] }
Operator = { id /* provider id, or 'direct' / 'private' … */, name /* provider name, null when not managed */, kind /* netinfo kind */, provider, via: 'ip'|'cname'|'ptr'|'asn'|null, reasonKey /* class.* */, managed, steering }
```

### 5.11 `lib/sources.js`
The catalogue, the quota semantics and the health summary (`SOURCES`, `sourceQuota`, `SOURCE_HEALTH_STATES`, `sourceHealthSummary`) live in `lib/sourceinfo.js` and are re-exported here unchanged (§5.34): the views import them from there, so the fetchers load only with the discovery engine.
```js
export const SOURCES = [ { id, name, homepage, providesIps: boolean, providesCerts: boolean, defaultEnabled: boolean, noteKey, timeoutMs, quota /* short English note */ } ]   // crtsh, certspotter, hackertarget, anubis, otx, thc
export async function fetchSource(id, domain, { fetchImpl, signal, timeoutMs, includeExpired = false, sleepImpl } = {}) -> SourceResult
export async function fetchAllSources(domain, { sources /* ids */, onResult, fetchImpl, signal, includeExpired } = {}) -> { results: SourceResult[], names: Map<string, Set<string>>, ipHints: IpHint[], certs: CtCert[] }
SourceResult = { source, ok, names: string[] /* normalized, only apex+subdomains of domain, wildcards stripped */, wildcardBases: string[], ipHints: IpHint[], certs: CtCert[], error: string|null, errorKind, elapsedMs,
  // extensions
  domain, partial: boolean /* data received, but a later page / the main crt.sh form failed */, rows, attempts /* HTTP requests incl. retries and pages */,
  quota: SourceQuota|null, lastSeen: { [name]: 'YYYY-MM-DD' } /* thc, otx */, truncated: boolean, available: number|null, queryForm: 'history'|'subdomains'|'identity'|null /* crt.sh */ }
  // errorKind: util.errorKind() ('timeout'|'rate-limit'|'network'|'http'|'parse'|…) plus 'unavailable' (every retry got a server error / CORS-less error page)
SourceQuota = { limited: boolean, period: 'day'|'hour'|'minutes'|null, retryAfterMs, resetAt: Date|null, limit, remaining, resetHint, hintKey /* 'source.quota.*' i18n key */ }
  // quota detection: HackerTarget's HTTP-200 'API count exceeded' text (daily, never retried), OTX / Cert Spotter 429, JSON error objects that mention a rate limit
export function sourceQuota(id, { limited = false, retryAfterMs = null } = {}) -> SourceQuota|null   // the same policy (period, hintKey, resetHint) for callers that query a source themselves (lib/ctcert.js); null when not limited
export const SOURCE_HEALTH_STATES = ['ok', 'empty', 'partial', 'rate-limited', 'unavailable', 'timeout', 'error']
export function sourceHealthSummary(results /* SourceResult[] | fetchAllSources() output */) -> SourceHealth[]   // one row per source (SOURCES order), aggregated over domains:
SourceHealth = { source, name, homepage, state, ok, names, ipHints, certs, elapsedMs, attempts, errorKind, error, quota, truncated, available, fallback /* CT twin (crtsh ↔ certspotter) whose data covered a failure */, message, domains: [{ domain, state, names, errorKind, error }] }
IpHint = { name, ip, source, firstSeen?: Date, lastSeen?: Date }
CtCert = { key /* dedupe key */, source, id, serialHex: string|null, issuer: string, notBefore: Date, notAfter: Date, names: string[], sha256: string|null }
```

### 5.12 `lib/scanner.js` — discovery engine v2 + "SSL target finder" orchestration
Used by both the Subdomains view (no certificate / inventory) and SSL Targets, which import it when a scan starts (`views/subdomains.js` `loadScanner` / `runScanner`; the shell modulepreloads it once the page is idle, §6). `SCAN_STAGES`, `HOST_SPECIFIC_HINT_KINDS`, `estimateQueries` and `learnedLabelsFromScan` are defined in `lib/scanplan.js` together with the caps and defaults both use, and re-exported here unchanged (§5.33).
```js
export async function runScan(config, hooks = {}) -> ScanResult
config = {
  domains: string[], cert: Certificate|null, extraNames: string[], sources: string[] /* default: every defaultEnabled source */, includeExpired: boolean,
  bruteforce: 'off'|'small'|'medium'|'smart'|'large'|'huge' = 'smart',   // 'medium' = legacy WORDLIST_MEDIUM; a level whose file cannot load degrades to the next smaller one (one aggregated WORDLIST_DEGRADED warning, detail e.g. 'huge→large')
  mine: boolean = true,                  // mineDnsNames() on every source domain
  permutationBudget: number = 1500,      // permutations() cap (≤ 20,000); 0 disables permutations
  recursive: boolean = true,             // one recursive wordlist round under discovered parents that already have children (independent of the budget; the UI ties both to one switch)
  inventory: Server[], originHints: boolean = true, dns: DohClient, fetchImpl, signal,
  // extensions
  customWordlist: string[]|string|null,  // the user's labels, or raw text (parseCustomWordlist rules; fragments like 'dev.api' allowed); tried FIRST
  learnedLabels: string[]|null,          // labels from earlier scans (learned.js; opt-in in the views); tried after custom (labels already in custom are dropped); ignored entirely at bruteforce 'off'
  locales: string[]|undefined,           // locale packs: undefined = auto per apex (localesForDomain), [] = none, a list = exactly those packs (unknown codes ignored); only from 'smart' up
  wordlist: string[]|null,               // legacy override: REPLACES the level's list for every base, including locale packs, custom and learned (tests, power users)
  wordlistPreferFetch: boolean = false,  // test hook: load the wordlist files through `fetchImpl` even under Node (the browser path)
  balance: boolean = true /* DohClient balance mode for A-only probes */,
  resolverLeak: boolean = true /* re-resolve proxied hosts through other resolvers */, recursiveParents: number = 8, maxHosts: number = 20000,
  concurrency: number = 32,              // final-resolve pool
  maxConcurrency: number|undefined,      // the user's Settings ceiling: caps the final-resolve pool AND the bulk sweep, which otherwise raises the client to PROBE_CONCURRENCY = 24
                                         // (sweep = min(24, pool, maxConcurrency)); the views pass min(24, 2 × Settings concurrency) as both concurrency and maxConcurrency
  sourceGraceMs: number = 12000 /* after mining, wait at most this long for slow passive sources before the DNS sweep starts; later names are still merged (their parents wildcard-checked) before permutations and resolve; 0 = wait for every source */
}
// Brute force: every base (each target apex and each certificate wildcard base) gets its own ordered list —
// custom → learned → WORDLIST_SMALL → that base's locale packs → base (smart) → large → huge tier — capped per base by
// the level cap (small 4,000 · smart 20,000 · large 80,000 · huge 160,000; legacy 'medium' / `wordlist`: 60,000 shared
// by all bases) PLUS the number of custom + learned labels, so a long custom list never pushes the level's own list out,
// and at 200,000 candidates per scan, filled rank-major round-robin across the bases so a later domain is not starved.
// A cut raises BRUTEFORCE_TRUNCATED (a per-base cut with detail '<cap> (<base>[, …])'). A wordlist entry that is a full
// hostname is made relative to the base it ends in (`api.example.com` → `api` under example.com) and skipped under the
// base itself and under every other scanned zone. No probe name is ever sent twice: a `probed` set is shared by the
// brute-force, permutation (`permutations({ exclude })`) and recursive stages. With bruteforce 'off' no list is tried —
// custom included — and learned labels are not used at all; only this scan's custom single labels still join the
// permutation sibling words and the recursive round. The recursive round tries at most 100 custom / learned labels
// (custom first) plus ALL of WORDLIST_SMALL (a legacy `wordlist` override: its first 200) under at most
// `recursiveParents` parents (≤ 20,000 candidates, RECURSIVE_TRUNCATED).
// Seeds: a certificate / extra-name wildcard on a public suffix (`*.com.tr`, `*.github.io`) is neither brute-forced nor
// a scope root (PUBLIC_SUFFIX warning).
// Passive sources run for at most 2 registrable domains at a time (SOURCE_DOMAIN_CONCURRENCY), so a many-domain
// scan does not fire every domain's quota-limited source calls at once. Wildcard suspects are never origin
// evidence: they are left out of the resolver-leak pass, the origin networks and the CLI `-n` names.
// Warning codes (result.warnings[].code): INVALID_DOMAIN, INVALID_NAME, PUBLIC_SUFFIX, WILDCARD_PARENTS_TRUNCATED (> 80
// parents), DNS_UNREACHABLE (50 failed probes in a row — the sweep stops), BRUTEFORCE_TRUNCATED, WORDLIST_DEGRADED
// (detail: level pairs such as 'huge→large' and/or 'locale:<cc>' for a locale pack that failed to load),
// RECURSIVE_TRUNCATED, TRUNCATED (> maxHosts names).
export function learnedLabelsFromScan(result) -> string[]   // bare left-most labels relative to the longest scanned apex, only from hosts that resolved
                                                            // (A/AAAA), sit under a scanned domain (`result.domains`) and are not wildcard suspects;
                                                            // never a full name, an IP or a dash-encoded IP label (`198-51-100-7`, `2001-db8--1`); no
                                                            // numeric-only labels; skips `customOnly` hosts and the probe-derived variants of their
                                                            // private labels (`secret2`, `www.secret`); first-seen order
hooks = { onStage(stage, info /* { skipped?, total?, … } */), onSource(SourceResult), onHost(HostRecord), onProgress({ stage, done, total }) }
export const SCAN_STAGES = ['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints', 'done']   // reporting order; skipped stages are still reported with { skipped: true }
ScanResult = {
  startedAt: Date, finishedAt: Date, domains: string[],
  hosts: HostRecord[] /* sortHostnames order */, sources: SourceResult[],
  wildcards: { [parent]: { wildcard, kind, ipv4, ipv6, cnames } },
  originHints: OriginHint[], servers: ServerGroup[], unmatchedIps: Array<{ ip, hosts: string[], provider: provider|null }>,
  ctCerts: CtCert[],
  stats: { total, resolved, cloudflare, cdn, platform, direct, private, nxdomain, dangling, covered, matchedServers, wildcardSuspects,
    // extensions
    unresolved, hiddenOrigin, needsCert, hintedServers, originHints, unmatchedIps, sourcesOk, sourcesFailed,
    fromSources, fromDns, wildcardParents, mineFound, wordlistFound, permutationFound, recursiveFound,
    bruteforceTried, bruteforceFound, bruteforceWildcardDropped, bruteforceErrors /* = the wordlist stage */,
    permutationTried, permutationWildcardDropped, permutationErrors, recursiveTried, recursiveWildcardDropped, recursiveErrors,
    bruteforceVanished, permutationVanished, recursiveVanished /* probe hits gone by the resolve stage (clean NXDOMAIN / empty
      answer); a resolve-stage failure is re-asked once and the host kept with its error, never dropped */,
    ctCerts, dnsQueries, truncated, elapsedMs },
  // extensions
  sourceDomains, sourceHealth: SourceHealth[] /* §5.11 */, wildcardBases, wildcardParents, mineEvidence, mineExternalRefs, lastSeen, warnings, hintErrors,
  originNetworks: OriginNetwork[], cliSuggestion: string|null /* display only — never parse it */,
  cliTargets: string[] /* the validated `-t` tokens (IPv4 /24 or exact IPs, IPv6 exact IPs) */, cliNames: string[] /* the validated `-n` proxied names */,
  options: { sources, includeExpired, bruteforce /* the level actually served (after a degrade) or 'off' */, mine, permutationBudget, recursive,
    resolverLeak, originHints, cert, inventoryServers,
    wordlist: { requested, level /* served */, degraded: string[] /* 'large→smart' … */, localePacks: string[] /* union over bases */,
      localesMissing: string[] /* requested packs that failed to load (localePacks / perDomain.locales list only the loaded ones) */,
      customTried, customFound, learnedTried, learnedFound,   // distinct list entries actually queued as probes / of those, the ones that found a host
                                                              // (found ≤ tried; 0 / 0 at 'off' or legacy 'medium')
      perDomain: Array<{ domain, level, locales: string[], words /* list length for that base */, customTried, customFound, learnedTried, learnedFound /* per base */ }> } }
}
HostRecord = { name, origins: string[], resolution: HostResolution, classification, cert: { covered, by } | null, servers: Array<{ serverId, name, ip }>, wildcardSuspect: boolean, ipHints: IpHint[],
  candidateNetworks: string[] /* extension: origin-network CIDRs to sweep; empty unless the host hides its origin */,
  customOnly: boolean /* extension: found ONLY through a custom-list label that is not in WORDLIST_SMALL — by the wordlist stage, or a
    probe-only permutation / recursive host whose left-most labels carry such a label (never learned) */ }
  // origins: 'input' | 'cert' | source ids | 'dns-mine:<RR>' (MX|NS|SOA|SPF|DMARC|SRV|CNAME|CAA|HTTPS|PTR) | 'wordlist' | 'permutation' | 'recursive'; legacy results may show 'bruteforce' (= 'wordlist')
OriginHint = { ip, reasons: Reason[], servers: Array<{ serverId, name }>, provider: provider|null, hosts: string[] /* extension */ }
Reason =                                   // `detail` is log text; views read the structured fields only
    { kind: 'resolver-leak', host, resolver /* resolver id that answered with a non-CDN address */, detail }
  | { kind: 'history', host, source /* source id */, lastSeen: 'YYYY-MM-DD'|null, detail }
  | { kind: 'spf'|'mx'|'direct-sibling', detail }
OriginNetwork = { cidr /* /24 IPv4 · /48 IPv6 */, ips: string[], hosts: string[] /* DNS-only names in the block */, provider: provider|null }
ServerGroup = { server: Server, hosts: Array<{ name, ip, covered: boolean|null, via: 'dns'|'hint' }>, needsCert: boolean }
```
Pipeline (v2, DNS first): seeds (domains + cert hostnames with wildcards stripped → wildcard bases + extraNames) → `sources` (passive sources per registrable domain, in parallel with) `mining` (in-domain names from the zone's own MX / NS / SOA / SPF / DMARC / SRV / CNAME / CAA / HTTPS records) → `wildcard` (detectWildcardDeep at the apex, every certificate wildcard base and every level that hosts a discovered name) → `bruteforce` (A-only wordlist sweep of the chosen level under the apex and each wildcard base, balance mode; a probe is a hit when it answers with addresses or a CNAME chain — a dangling alias answering NXDOMAIN with its chain counts, a plain NXDOMAIN does not; wildcard look-alikes dropped) → `permutations` (variants of everything found so far — env / number / region / sibling words and the service-suffix tier `shop → shopapi` — up to `permutationBudget`; every in-scope level above a hit, `dev.x` for `api.dev.x` too, is wildcard-checked before the hit counts, so a level with no hit under it costs no probe; then one recursive wordlist round under discovered parents) → `resolve` (A + AAAA for every surviving name; stream `onHost`) → classify / cert coverage / inventory match → `hints` (DNS only, never a connection to the target: apex SPF `ip4:`/`ip6:`/`a:`/`mx`, MX host IPs, public IPs of non-proxied siblings, historical IP hints from hackertarget/otx that are not CDN IPs, `resolver-leak` = a proxied name answered with a non-CDN address by another public resolver; then the DNS-only hosts and leaks are clustered into `originNetworks` and every proxied host gets them as `candidateNetworks`) → server groups (DNS matches + hint matches) and unmatched direct IPs → `done`.
`cliTargets` / `cliNames` are built for the sweep (IPv4: the /24 when the block holds an inventory server, or at least two origin IPs outside shared provider space (`OriginNetwork.sweep`), otherwise the exact IPs; IPv6: exact addresses only — a /48 is far over the CLI's block limit) and passed through `lib/cmdline.buildSweepCommand` (§5.17), so they hold only what survived validation. `cliSuggestion` is the POSIX form `python3 cli/ssl_origin_scan.py -t <targets> -n <names>`, or null when nothing is left to sweep; the views build their own copy-ready command for POSIX (`python3 ssl_origin_scan.py …`) or PowerShell (`python ssl_origin_scan.py …`) from `cliTargets` / `cliNames`, never from this string. Resolver-leak re-resolves each proxied host through at most 3 other resolvers of the pool (≤ 300 queries per scan, 2.5 s each, no retries, resolvers with an open circuit breaker skipped).
`lib/dnsmine.js`: `mineDnsNames(domain, { dns, signal, onProgress, resolvePtr = false })` → `{ names, evidence: [{ name, from, record }], externalRefs }`; `names` never contains a name with a `_`-prefixed label (service labels such as `_dmarc`, `_sip._tls`, `_spf` are record names, not hosts), so the probed query names themselves are never reported; the SOA mailbox domain honours a `\.` escape in RNAME; `evidence` holds each (name, from, record) once. `SRV_SERVICES` lists the probed `_service._proto` labels. `lib/permute.js`: `permutations(foundNames, domain, { budget = 1500, words, envs, regions, suffixes, exclude })` → ranked, de-duplicated candidates (never the known names, never a name in `exclude` — a Set of names already probed, skipped before it counts toward the budget — never over budget); `DEFAULT_WORDS` / `DEFAULT_ENVS` / `DEFAULT_REGIONS` / `DEFAULT_SUFFIXES` are English-first and global (`DEFAULT_SUFFIXES` = web, api, admin, app, db, ws, service, gw, panel, srv, auth, ranked by how often `<label><suffix>` occurs in the shipped public wordlist).

**Extensions since discovery v2.** These are additive: a run without `zone` or `exact` gives the same result as before, apart from the new fields.
```js
config.zone: null | { v: 1, origin, names: string[], wildcardBases: string[], delegations?: string[], proxied: Array<{ name, ips: string[], host: string|null }> }
  // The zoneorigins.zoneScanInput() shape (§5.22), validated here; the scanner never imports the zone libraries.
  // - Zone names (+ delegations) are seeds with origin 'zone': ranked after 'input' and before 'cert', never truncated.
  // - Names outside every scanned root are dropped with ONE warning ZONE_OUT_OF_SCOPE (detail = count).
  // - With no `domains`, the zone origin is the target.
  // - A zone wildcard base (`*.apps` → apps) is seeded and wildcard-checked, but never brute-forced and never a certificate wildcard base.
  // - Zone names are never wildcard suspects.
  // - Dropped from `proxied`: Cloudflare placeholders (192.0.2.0, 100::), CDN / WAF addresses, and numeric or invalid host origins.
config.exact: boolean = false
  // Resolve the given names only. No passive sources, mining, wordlist, custom / learned labels, permutations, recursive round
  // or wildcard detection (the 'wildcard' stage event carries skipped: true). Quota-free.
  // Origin hints still follow `originHints`; pass false to query the zone names only.
hooks.onFound(partial)
  // Streams a probe hit the moment it resolves in the wordlist / permutation / recursive stages:
  // { name, origin, status /* 'NOERROR', or 'NXDOMAIN' for a dangling alias */, ipv4, cnames, classification } (A only, classified from that answer).
  // The same host arrives again as a full HostRecord through onHost at 'resolve', so dedupe by name. Hook errors never break a scan.
// Stage info: 'wildcard' → { parents, total, sourcesStillRunning: string[], sourcesCutOff: boolean } (the source grace snapshot);
//             'hints' → { skipped, total, leakQueries, zones }
export const HOST_SPECIFIC_HINT_KINDS = Set{'history', 'resolver-leak', 'sibling-domain', 'zone'}   // hints about ONE proxied host; spf / mx / direct-sibling are general
export function estimateQueries({ bruteforce = 'smart', domains, wildcardBases, certNames, extraNames, locales = null, customCount = 0, learnedCount = 0,
                                  permutationBudget = 1500, recursive = true, recursiveParents = 8, mine = true, originHints = true, resolverLeak = true })
  -> { min, max, breakdown: { wordlist, mining, wildcard, permutation, recursive, resolveMin, resolveMax, hintsMin, hintsMax, bases, zones } }
  // Pure (no DNS); every stage is counted with the scan's own caps. `min` is what always fires; `max` adds what depends on the finds.
  // For an exact-mode plan, pass bruteforce 'off', mine false, permutationBudget 0, recursive false and the zone names as extraNames.
HostRecord += {
  originCandidates: Array<{ ip?, cidr?, kind: 'zone'|'resolver-leak'|'sibling-domain'|'history'|'network', score, evidence }>,
    // Proxied hosts only, strongest first:
    // - exact host-specific IPs: zone 110 · resolver-leak 100 · sibling-domain 95 · history 90;
    // - then the networks related to THIS host: a DNS-only sibling with the same label stem 70 · its parent stem 65 ·
    //   the main cluster 60 · another multi-IP cluster 50. A lone 1-IP network unrelated to the host is left out.
    // evidence by kind: resolver-leak { resolver } · history { source, lastSeen } · sibling-domain { sibling } ·
    //   zone { source: 'zone' } · network { relation, ips, sweep, shared }
  zoneOnly: boolean   // only the zone file names it, so its labels are never learned (like customOnly)
}
// candidateNetworks = the CIDRs of the network candidates; `origins` may include 'zone'.
Reason +=
    { kind: 'sibling-domain', host, sibling, detail }
      // Several apexes scanned together: a proxied X.<d1> whose exact left-most label X is a DNS-only, public, non-CDN
      // host X.<d2> under ANOTHER scanned apex → that IP is a host-specific candidate (exact label only, never X vs Xapi).
  | { kind: 'zone', host, detail }
      // The zone file's exact origin of that proxied name. It costs no query, so it runs even with originHints off.
OriginNetwork += {
  shared: boolean,        // offline: the block is in a PROVIDERS range of a shared category (netinfo.isSharedProvider)
  sweep: 'cidr'|'ips'     // IPv6 → 'ips'; a /24 holding an inventory server → 'cidr'; a shared /24 without one → 'ips';
                          // otherwise 'cidr' at ≥ 2 origins, else 'ips'
}
ServerGroup.hosts[].via += 'zone'   // hosts sort dns, zone, hint; needsCert counts dns and zone matches
ScanResult += {
  sourceGrace: { graceMs, cutOff, stillRunning: string[] },
  cliHostTargets: string[],   // zone host origins for the CLI (`-t` host names); [] without a zone
  zone: null | { origin, exact, seeds, wildcardBases: string[], proxied, resolved, outOfScope, cliNames, cliTargets, cliHostTargets }
}
options += { exact: boolean, zone: null | { origin, seeds, wildcardBases /* count */, proxied, resolved, outOfScope } }
stats += { zoneSeeds, zoneResolved }   // present only when a zone is given
```
With a zone:
- the exact origins join the CLI command as exact tokens (private ones kept, never widened to a /24);
- host origins join as host targets, and the proxied names (`*.x` kept) as names;
- hosts the zone already maps skip the resolver-leak pass;
- zone addresses never join `originNetworks`.

### 5.13 `lib/ipintel.js`
```js
export function createIpIntel({ fetchImpl, dns /* DohClient for PTR */, concurrency = 4 } = {}) -> {
  info(ip, { signal }) -> Promise<IpInfo>, reverseIp(ip, { signal }) -> Promise<{ ok, domains: string[], error, limited: boolean }>
}
IpInfo = { ip, version, private: boolean, provider: provider|null, ptr: string[], asn: number|null, asName: string|null, holder: string|null, prefix: string|null, country: string|null, city: string|null, sources: string[], error: string|null }
// Private IPs: no external calls. Order: RIPEstat prefix-overview + maxmind-geo-lite; fallback ipwho.is. Cache per ip.
// Extension: createIpIntel(...).describeNetwork(target, { signal, noCache }) is the same as below and shares the service's limiter.
// Extension: IpInfo.errors[] = { source: 'ptr'|'ripestat'|'ripestat-geo'|'ipwhois', error, errorKind, status /* HTTP */, retryAfterMs, rcode? /* a reverse
//   lookup answered SERVFAIL, REFUSED … */, at /* ms */ } (read by §5.36), and createIpIntel(...).retry(prev, { sources?, signal }) -> Promise<IpInfo>: asks again only the given sources
//   (default: every source in prev.errors), merged like info() does (RIPEstat first; ipwho.is only for what is still missing, and
//   not asked at all when nothing is), replacing the old failures of the sources asked; a result that learned something is cached.
//   Rejects only with an AbortError from `signal`. info() on a cached result whose failures left a field empty runs this retry for
//   those sources (§5.36 ipRetrySources, what the row's Retry asks; shared in flight) instead of returning the old failures, so a
//   later lookup really asks them again; a failure another source made up for (ipwho.is filled the country) leaves the hit complete.
// Extension: IpInfo.filledBy = { network, location }: the service ('ripestat' | 'ipwhois') the AS and the country came from;
//   'ipwhois' leaves `sources` once a retried RIPEstat answer replaced all it gave.
export function describeNetwork(target /* IP or CIDR */, { fetchImpl, signal, noCache = false } = {}) -> Promise<NetworkDescription>
  // Who announces an origin network, ON DEMAND: the views call it on a click, the scanner never does.
  // ONE RIPEstat prefix-overview request for the block's network address; private / reserved space is never looked up.
  // Cached per network for 1 h (failures are not cached) and de-duplicated in flight. Rejects only with AbortError.
NetworkDescription = {
  input, ip, version: 4|6|0, private,
  provider,                  // offline PROVIDERS match
  asn, asName, holder, prefix, announced, asns: [{ asn, holder }], rir,
  infra: { id, name, category }|null,   // well-known operator of the AS
  category,
  shared: boolean|null,      // true: known multi-tenant space; false is NOT proof of single ownership; null: unknown
  coversInput: boolean|null, sources: string[], error, errorKind
}
export function networkQuery(target) -> { input, ip, version, range }|null                  // pure
export function summarizeNetwork(q, prefixOverview|null) -> NetworkDescription              // pure
```

### 5.14 `lib/rdap.js`
```js
export async function rdapDomain(domain, { fetchImpl, signal } = {}) -> { ok, domain, registrar, registrarIanaId, created: Date|null, updated: Date|null, expires: Date|null, status: string[], nameservers: string[], dnssecSigned: boolean|null, rdapServer, unsupportedTld: boolean, error }
export async function rdapIp(ip, { fetchImpl, signal } = {}) -> { ok, name, handle, country, startAddress, endAddress, cidr, org, error }
// Extension: a domain lookup that got no answer (`error` without notFound / unsupportedTld) also carries httpStatus (the last HTTP
// status), retryAfterMs (the Retry-After, when readable) and failedAt (ms) — read by §5.36. `status` stays the domain's EPP status list.
```

### 5.15 `lib/health.js`
```js
export async function domainHealth(domain, { dns, fetchImpl, signal, dkimSelectors = DEFAULT_DKIM_SELECTORS, onProgress } = {}) -> HealthReport
export const DEFAULT_DKIM_SELECTORS = ['default','google','selector1','selector2','k1','k2','s1','s2','dkim','mail','smtp','mandrill','zoho','protonmail','protonmail2','protonmail3','mxvault','everlytic','sig1','amazonses', ...]
export function parseSpf(txt) ; export function parseDmarc(txt) ; export function parseCaa(rrs)
export async function spfLookupCount(domain, { dns, signal }) -> { count, tree, errors }   // RFC 7208 §4.6.4: include, a, mx, ptr, exists, redirect count; max depth guard
export function caaDomainsForIssuer(issuerDN) -> string[]   // map CA → CAA identifiers (Let's Encrypt→letsencrypt.org; DigiCert/GeoTrust/RapidSSL/Thawte→digicert.com; Sectigo/Comodo/ZeroSSL→sectigo.com,comodoca.com; GlobalSign→globalsign.com; GoDaddy/Starfield→godaddy.com,starfieldtech.com; Google Trust Services→pki.goog; Amazon→amazon.com,amazontrust.com,awstrust.com,amazonaws.com; Buypass→buypass.com; SSL.com→ssl.com; Entrust→entrust.net; Certum/Asseco→certum.pl; Microsoft→microsoft.com; Actalis→actalis.it; HARICA→harica.gr; e-Tugra→e-tugra.com.tr (distrusted 2023, flag it))
export function parseCaaIssueValue(value) -> { issuer, params, paramList, valid, error /* malformed: invalid-issuer | invalid-parameter | empty-parameter */,
  accountUri, methods: string[]|null, unknownMethods, otherParams, problem /* unsatisfiable, CAA_PROBLEMS */, restricted }
  // RFC 8659 §4.2 grammar applied strictly (a stray ';' or a parameter that is not tag=value is malformed, and a malformed value forbids issuance);
  // RFC 8657: accounturi (one URI; two, a non-URI, a staging ACME account or another known CA's ACME host → unsatisfiable) and validationmethods
  // (comma-separated labels `(ALPHA / DIGIT) *( *"-" (ALPHA / DIGIT))`, kept as written and compared exactly like a CA does: 'DNS-01' is an unknown label; a malformed
  // list ('-dns-01', an empty label), a second parameter, or no label that
  // validates a domain name → unsatisfiable, 'validationmethods-case' when such a method is named only in the wrong case; unknown labels are ignored)
export function checkCaaAllows(caaRecords, issuerDN, { wildcard, issuerDomains }) -> { allowed: boolean|null, verdict: 'allowed'|'restricted'|'denied'|'unknown', reason /* CAA_REASONS */,
  reasonKey, property: 'issue'|'issuewild'|null, issuerDomains, authorized, matched, distrusted, restricted,
  restrictions: Array<{ issuer, accountUri, methods, unknownMethods, otherParams, raw }>, unusable: Array<{ issuer, raw, problem }> }
  // issuewild takes precedence over issue for a wildcard name when present (RFC 8659 §4.3); authorizations are additive: 'allowed' when one usable value naming
  // the CA has no RFC 8657 parameter, else 'restricted' (allowed stays true) with every distinct alternative (the same issuer + accounturi + methods + CA parameters
  // published twice is one); values naming the CA (a trailing-dot 'letsencrypt.org.' too) that are all malformed ('malformed') or
  // unsatisfiable ('unsatisfiable', incl. validationmethods without dns-01 / ca-… for a wildcard: the CA/B Baseline Requirements let only DNS validation cover one) deny; `issuerDomains` replaces the DN mapping
export function caaRestrictionNotes(restrictions, { wildcard }) -> Array<{ code: 'methods'|'account'|'alternatives'|'unknown-methods'|'ca-params', key /* health.caa.note.<code> */, params }>
  // what the restrictions mean for the next renewal, e.g. methods: "only dns-01 … a renewal that validates with http-01, tls-alpn-01 will fail"
export function caaRestrictionText(r) -> 'letsencrypt.org: validationmethods=dns-01; accounturi=…'   // language-neutral (check params, exports)
export function applyRdap(report, rdap, { now }) -> HealthReport   // pure: the report with new registration data (Domain Health's RDAP Retry asks RDAP alone
  // again): `rdap`, every check that depends on it (rdap.*, ns.rdap-mismatch — compared only at a zone apex, `report.apex`) and the summary are replaced;
  // the DNS part is kept. The given report is not changed.
export const ACME_VALIDATION_METHODS /* the IANA registry */, CAA_PROBLEMS, CAA_NOTES, CAA_REASONS   // health.caa.problem.* / note.* / reason.* in HEALTH_I18N
HealthReport = { domain, zone, apex /* extension: true when the name has its own SOA, null when not known */, records: { ns, soa, mx, a, aaaa, txt, spf, dmarc, dkim: [{ selector, record }], caa, mtaSts, tlsRpt, bimi, ds, dnskey, https }, dnssec: { signed, validated, broken }, rdap, wildcard, failedLookups /* 'soa'|'ns'|'a'|'aaaa'|'txt'|'https' of the name whose query failed (the DNS card says "lookup failed", never a dash or a zero count), 'mx' (the MX query failed: records.mx is empty without meaning "no MX"; the MTA-STS policy check gets mxHosts undefined) and 'mtaSts'|'tlsRpt'|'bimi' whose TXT lookup failed: their null is "not known" (no *.missing check; the policy check gets txt / tlsRpt undefined) */, checks: Check[] }   // zone = the name's own zone (a CNAME's too, not its target's); below the apex dnssec is the enclosing zone's state (signed = a DS at its cut, validated = the AD bit, from the zone's own DNSKEY answer for a CNAME)
Check = { id, severity: 'ok'|'info'|'warn'|'error', titleKey, detailKey, params }   // NXDOMAIN: domain.nxdomain (not delegated) / domain.dangling-cname / domain.name-missing (below a live zone), NS count/diversity, SOA, MX present/resolves/not-CNAME/null-MX, SPF (single record, ≤10 lookups, +all/?all/~all/-all, ptr), DMARC (present, policy, rua, pct, multiple), DKIM found selectors, CAA (present? valid issuers; malformed values authorize no CA; caa.unsatisfiable / caa.restricted for RFC 8657 parameters; caa.cert-restricted / caa.cert-unusable against a certificate's CA), DNSSEC (signed/validated/broken: a zone with a DS whose SOA SERVFAILs with CD=0 but answers with CD=1; one failed DS/DNSKEY lookup is dnssec.error, never a misconfiguration), wildcard DNS, RDAP expiry (<30d error, <60d warn), IPv6 presence, MTA-STS/TLS-RPT/BIMI presence
```
**Mail identity (extension, part of ROADMAP P1.6).** The `mx` step also checks the reverse DNS of the MX hosts' public addresses (private ones are skipped, at most `MAIL_FCRDNS_MAX = 10`, in MX preference order) with `ptrsweep.checkFcrdns` (§5.28) on the same memoised client: PTR, then A / AAAA of each PTR name. `HealthReport.mailIdentity = { addresses: [{ host, ip, status /* FCRDNS_STATUSES */, names, confirmed, forward, own, generic, error }], total, checked }` (null for a name that does not exist); `own` = the MX host is under the checked domain's registrable domain, `generic` = a templated PTR name (`ptrsweep.ptrTemplate`). Category `mail-identity` (group email, right after `mx`):
- `mail-identity.fcrdns-ok` (ok, `{ count, items }`) — the addresses whose PTR name resolves back;
- `mail-identity.fcrdns-missing` / `fcrdns-mismatch` (warn) — the domain's own MX hosts without a PTR (NXDOMAIN / NODATA) or with one that does not resolve back; the advice names the Gmail / Yahoo sender rule (never Microsoft's 2025-05-05 rule, which enforces SPF / DKIM / DMARC) and who sets a PTR;
- `mail-identity.fcrdns-provider` (info) — the same for a provider's MX hosts (another domain): the provider's to set, and receiving servers need none;
- `mail-identity.fcrdns-error` (info) — SERVFAIL or no answer; `mail-identity.ptr-generic` (info) — a generic name on one of the domain's own MX hosts (legitimate relays carry cloud default names too); a provider's host with a generic name is only marked in the table (`generic`), never advised on, since its PTR is the provider's to set; `mail-identity.fcrdns-capped` (info, `{ checked, total }`).
The MX hosts receive mail, so the check stands in for the sending servers; the SPF `ip4:` / `a:` senders of P1.6 are not checked yet.

### 5.16 `lib/export.js`
```js
export function toCsv(rows, columns /* [{ key, header, get?(row) }] */, { bom = true, delimiter = ',' } = {}) -> string   // RFC 4180 quoting; BOM for Excel (Turkish chars)
export function toJson(value) -> string   // Dates ISO, Map→object, Set→array, Uint8Array→omitted, pretty 2 spaces
export function scanHostRows(scan) -> object[] ; export function scanServerRows(scan) -> object[]
export function namesForCli(scan, { onlyCovered = false } = {}) -> string    // newline list
export function targetsForCli(servers) -> string                             // "name ip" lines; an inventory address written with a port keeps it ("web01 203.0.113.10:8443", inventory.addressTargets);
                                                                             // de-duplicated per endpoint: a server sharing an address still writes the ip:port no earlier line has;
                                                                             // an Ansible host pattern's port is its SSH port, never kept (§5.5), so that address is written bare
export function cliServerName(name) -> string   // the name as one -t token: runs of whitespace, control chars, , ; # = / : → '_'; '' for an IP or an IP range (written bare)
export function cliCommand({ namesFile = 'names.txt', targetsFile = 'targets.txt', certFile = 'new-cert.pem' } = {}) -> string
```

### 5.17 `lib/cmdline.js` — the origin-sweep command, safe to paste
The sweep command is shown to the user and pasted into a shell, and its names come from untrusted data (CT logs, passive DNS), so it is never glued together from strings.
```js
export function validateTargets(list) -> { valid: string[], dropped: string[] }   // IPv4/IPv6 address or CIDR only (netinfo.parseCidr / normalizeIP), re-emitted canonical (host bits masked, RFC 5952); deduped
export function validateNames(list) -> { valid: string[], dropped: string[] }     // domain.normalizeHostname output limited to [a-z0-9_.-], never starting with '-'; deduped
export function quoteArg(value, shell = 'posix' /* | 'powershell' */) -> string  // quotes only when needed: POSIX single quotes ('\'' escaping), PowerShell single quotes
                                                                                  // ('' escaping; U+2018–U+201B doubled too); THROWS a TypeError on any character outside printable ASCII (0x20–0x7e)
export function buildSweepCommand({ targets = [], names = [], script = 'ssl_origin_scan.py', shell = 'posix',
                                    namesFile = 'proxied-names.txt', maxInlineNames = 200, maxLength = 8000 } = {})
  -> { command: string|null /* '<script> -t <targets…> -n <names…>' or '… -n <namesFile>'; null when no valid target or no valid name */, targets: string[], names: string[] /* the full validated list */,
       dropped: { targets: string[], names: string[] }, length: number, namesInline: boolean, namesFile: string|null /* set when the names are NOT inline */ }
export function buildOriginSweepCommand(opts) -> string|null                      // buildSweepCommand(opts).command
export function buildFittedSweepCommand(opts, targetsFile = DEFAULT_TARGETS_FILE) -> object  // buildSweepCommand(opts), again with targetsFile when overLength
export const DEFAULT_NAMES_FILE = 'proxied-names.txt', DEFAULT_TARGETS_FILE = 'proxied-targets.txt', MAX_INLINE_NAMES = 200, MAX_INLINE_LENGTH = 8000
```
`buildSweepCommand` also takes `cert = null`, `json = null` and `ports = null` (the Verify tab's CLI card uses the first two): `cert` / `json` must be plain path tokens (the `script` rule) and become `--cert <cert>` / `--json <json>`; `ports` are integers 1–65535 (a single integer is accepted), deduplicated in order, and become `-p 443,8443` — omitted when null, `[]`, exactly `[443]` (the CLI default) or when every value was invalid. The options follow the names (or the names file) in the order `-p`, `--cert`, `--json`, count toward the inline length limit, and PowerShell quotes `'443,8443'`. The result always carries `dropped.options: string[]` (`'cert'`, `'json'`, `'ports:<v>'`; `[]` when nothing was dropped); without the new options every output is byte-identical to before.

An internationalised name is kept in its punycode form (`xn--…`). Anything else that is not a valid target or name (`; rm -rf /`, `$(…)`, backticks, spaces, quotes, newlines, a leading `-`, over-long labels) is dropped and reported — never quoted into the command — so the result is inert in both a POSIX shell and PowerShell and a name can never be read as an option. The caller prefixes the interpreter (`python3` for POSIX, `python` for PowerShell); the views show `dropped` as a count. `script` and `namesFile` must be plain paths (`[A-Za-z0-9_./-]`, not starting with `-`), otherwise the default is used. Over 200 names or 8,000 characters the command reads the names from `namesFile` (the CLI loads a `-n` value that is an existing file, one name per line), so many names never hit the Windows command-line limit; the views then offer that file (`proxied-names.txt`, the validated proxied names) as a download next to the command. The targets stay inline unless `targetsFile` is given (see the opt-ins below), so a very long target list can keep the command over 8,000 characters: the result then carries `overLength: true` (the field is absent otherwise) and the caller should warn or offer the targets file. `buildFittedSweepCommand` does the latter: when the result is `overLength` it builds the command again with `targetsFile` (default `proxied-targets.txt`), and returns the plain result otherwise. The Behind CDN cards (`proxied-targets.txt`), the Verify card (`verify-targets.txt`) and the scanner's `cliSuggestion` use it, and the cards offer the targets file as a download next to the names file. A command still over the cap (thousands of excludes) keeps `overLength`, and the Behind CDN cards show a warning.

**Extensions.** These are additive; without them every output is byte-identical to before.
- **`exclude`** (IPs / CIDRs, or a string split on whitespace and commas) becomes `--exclude a b …` right after the `-t` targets. Excludes are validated like targets.
  - A target that an exclude covers entirely is removed from `-t` and reported in `excluded`.
  - An exclude that overlaps no remaining target is left out of the command and reported in `excludeUnused` — unless a host-name target is kept (below).
  - An invalid exclude is dropped and reported in `dropped.exclude`.
  - An IPv4-mapped IPv6 target or exclude (`::ffff:10.0.0.5`, `::ffff:10.0.0.0/104`) also matches its IPv4 form, as the CLI does; a wider IPv6 range such as `::/0` does not.
  - These four fields appear only when `exclude` is given, and `targets` then lists only what is left in `-t`.
- **Zone hand-off opt-ins**, all off by default:
  - `allowHostTargets` keeps HOST NAME targets (a proxied record's CNAME origin, resolved by the CLI inside the network). Validation: `normalizeHostname`, `[a-z0-9_.-]`, at least one dot, no leading `-`. IP / CIDR targets come first, then the host names.
  - `allowWildcardNames` keeps `*.x` names, always quoted.
  - `targetsFile` and `maxInlineTargets`: when the targets exceed `maxInlineTargets`, the names exceed `maxInlineNames` or the command exceeds `maxLength`, BOTH lists go to files (`-t <targetsFile> … -n <namesFile>`). The result then carries `targetsInline` / `targetsFile`. An invalid `targetsFile` is reported as `'targetsFile'` in `dropped.options`.
  - `validateTargets(list, { allowHostTargets })` and `validateNames(list, { allowWildcard })` expose the same rules.
- **`allowPorts`** (off by default): keeps an `ip:port` / `[v6]:port` target (port 1–65535, the address canonical; an IPv6 address needs the brackets), which the CLI scans on that port instead of `-p`. POSIX and PowerShell quote the bracketed form. An exclude never takes a port (`203.0.113.10:443` there is dropped and reported), and an exclude covering the address removes the `ip:port` target. With `allowHostTargets` the addresses (with or without a port) come before the host names. `validateTargets(list, { allowPorts })` exposes the same rule; the Verify card's CLI command uses it for a pair on another port than 443 (`verify.cliPlan`).
- **Numeric host names:** a host target or name that glibc `inet_aton` would read as an IPv4 address is always dropped (`2026092401`, `0x7f.0x1`, `0177.1`, `10.1`), so it never reaches `getaddrinfo`. `isInetAtonNumeric(s)` is exported for tests.
- **Host targets and excludes:** with a host-name target kept, every valid exclude is emitted and none is reported in `excludeUnused`, because the host's addresses are known only once the CLI resolves it inside the network. Without a host target, the unused rule above applies.

### 5.18 `lib/globalping.js` — the Globalping v1 client (transport only)
DOM-free; knows nothing about certificates (§5.19 interprets results). All I/O goes through `util.fetchWithTimeout` with an injected `fetchImpl` (default: `globalThis.fetch`, looked up at call time), `sleepImpl` and `now`.
```js
export const GLOBALPING_API = 'https://api.globalping.io/v1'
export const GP_LIMITS = { anonymousPerHour: 250, tokenPerHour: 500, maxProbesPerMeasurement: 50, minTimeoutS: 5, maxTimeoutS: 30, clientSlackS: 10, pollIntervalMs: 500, requestTimeoutMs: 15000 }
export const NON_HTTP_TLS_PORTS = [21, 25, 110, 143, 465, 587, 636, 989, 990, 993, 995, 1433, 1521, 3306, 3389, 5432, 5671, 5986, 6379, 8883, 9093, 27017]   // CLI only
export const GP_ERROR_CODES = ['validation','private-target','bad-host','no-probes','rate-limit','insufficient-credits','unauthorized','not-found','poll-rate','server','deadline','bad-response']
export class GlobalpingError extends Error   // (code, message, { status, params, quota, retryAfterMs, resetAt, body ≤ 500 chars, cause }); `kind` is util.errorKind-compatible:
                                              // rate-limit | insufficient-credits → 'rate-limit', deadline → 'timeout', bad-response → 'parse', others → 'http'
export function isMeasurementId(id) -> bool   // /^[A-Za-z0-9]{8,64}$/: nothing else ever shapes a request path
export function isProbeableIP(ip) -> bool     // netinfo.isGloballyRoutable
export function probeTarget(ip) -> string|null   // canonical v4 (also for ::ffff:a.b.c.d) or RFC 5952 v6; null when not probeable
export function isProbeableHost(name) -> bool // normalizeHostname(name) === name, ≥ 2 LDH labels (no '_' or '*'), not an IP, last label has a letter, ≤ 253
export function isProbeablePort(port) -> bool // integer 1–65535, not in NON_HTTP_TLS_PORTS (port 0 is accepted AND charged by the API)
export function httpsCheckRequest({ ip, name, port = 443, timeoutS = 10, probes = 1, locations = null }) -> body
  // TypeError on an unprobeable ip / name / port, probes outside 1..50, `ipVersion` or any unknown option, a non-finite timeout, a bad locations entry.
  // timeout rounded and clamped to 5..30 and always sent; port always sent; ipVersion never; HEAD '/'.
  // locations null → { limit: probes }; an Array → { locations: entries with limit ?? 1 } (no global limit, sum ≤ 50); a measurement id → { locations: id }
export function httpsGetRequest({ host, path = '/', port = 443, timeoutS = 10, probes = 1 }) -> body   // one HTTPS GET of `path` on a host-name target (§3; MTA-STS policy)
  // TypeError on a host Globalping refuses, a path that is not '/' + printable ASCII without spaces, '?' or '#' (≤ 501 chars), an unprobeable port, probes outside 1..50,
  // a non-finite timeout or any unknown option; timeout rounded and clamped to 5..30; never `request.host`, `ipVersion` or a query string
export function probeSummary(probe) -> { continent, country, city, asn, network, kind: 'datacenter'|'eyeball'|null, adopted: bool /* a 'u-' tag */ }   // never lat/long, resolvers or user names
export function quotaFromHeaders(headers, now) -> GpQuota|null ; export function quotaFromLimits(json, now) -> GpQuota|null
export function mergeQuota(prev, next, now) -> GpQuota   // same window (window ends within 60 s, or next has no window while prev's is open) → remaining = min;
                                                         // a later window replaces; source '429' → 0; a reading never raises `remaining` inside a window
// GpQuota = { limit: number|null, remaining, consumed, resetAt: Date|null /* no window yet */, cost, type: 'ip'|'user'|null, source: 'limits'|'create'|'429', at }
export function createGlobalping({ fetchImpl, token = null, baseUrl = GLOBALPING_API, sleepImpl, requestTimeoutMs = 15000, now } = {}) -> {
  quota /* merged, min per window */, tokenState: 'none'|'set'|'rejected', setToken(token|null) /* printable ASCII ≤ 512 */, onQuota(fn) -> off,
  limits({ signal }) -> GpQuota,                // free; returns the MERGED quota; 401 with a token → drop the token and retry anonymously; one retry on 5xx / network
  create(body, { signal }) -> { id, probesCount, cost /* X-Request-Cost || probesCount */, quota },
  get(id, { signal }) -> Measurement,           // one GET, queued per id and ≥ 500 ms after that id's previous response
  poll(id, { signal, deadlineAt /* absolute, preferred */, deadlineMs, intervalMs = 500, onUpdate }) -> Measurement,
  measure(body, { signal, onUpdate }) -> { measurement, id, cost, quota }   // deadlineAt = now() after the 202 + ((body.timeout ?? 30) + 10) s
}
```
Response mapping (every row is unit-tested):
- **create:** 202 → parsed (a missing id → `bad-response`). A 400 whose `params.target` says "private hostname" → `private-target`; a params key containing `request.host` → `bad-host`; any other 400 → `validation` with `params`. 401 with a token → the same request once without it; without a token → `unauthorized`. 422 → `no-probes`. 429 `rate_limit_exceeded` / `insufficient_credits` → `rate-limit` / `insufficient-credits`, quota merged with source `'429'` (remaining 0), `resetAt` from `x-ratelimit-reset` (else one free `limits()`), `retryAfterMs = resetAt − now`. A burst 429 (`too_many_requests`, or `Retry-After` ≤ 60 s without a quota type; *unverified live*) → wait `Retry-After` (default 5 s) and repeat the same POST once; a second one → `poll-rate`. **Only 502 and 503 are retried** (once, after 1 s): 504, other 5xx and any other non-2xx → `server`, and a network `TypeError` or `TimeoutError` is rethrown, because the POST may already be charged. Before sending, a body that is not an object, or a `measurementOptions.port` that is not an integer 1–65535, is a `TypeError`.
- **get:** a malformed id → `validation` before any fetch. 200 → the JSON; 404 → `not-found`; 429 → wait `Retry-After` (default 5 s) and repeat; three in a row, or a `Retry-After` over 30 s → `poll-rate`; 5xx / network → up to 2 retries at 1 s, then `server` (or the network error). A queued caller whose signal aborts rejects at once and its GET is never sent.
- **poll:** sleeps before the first GET and after each response; `onUpdate` after every GET; past the deadline → `deadline`. **measure:** any error after the 202 carries `err.measurementId` and `err.cost` (already paid).

### 5.19 `lib/verify.js` — "is the new certificate live on every server?"
DOM-free; mirrors `cli/ssl_origin_scan.py`, so web and CLI rows mean the same thing. Imports §5.18 (`httpsCheckRequest`, `isProbeableIP/Host/Port`, `probeSummary`, `GlobalpingError`), `domain.certCovers`, `netinfo` and `x509.computeFingerprints`.
```js
// Vocabularies (frozen; tests/js/i18n-coverage.test.js derives the vfy.* keys from them)
export const VERIFY_STATUSES = ['UPDATED','NEEDS_UPDATE','ORIGIN_CERT','PRIVATE_CERT','NOT_HOSTED','TLS_ERROR','TIMEOUT','CLOSED']      // = the CLI's STATUSES
export const CERT_KINDS = ['origin-ca','self-signed','other']   // the CLI's certificate kinds without --private-ca
export const VERIFY_REASONS, VERIFY_ERRORS /* row state 'error' only, never a verdict */, VERIFY_WARNINGS, VERIFY_STATES, SKIP_REASONS,
  NOT_RUN_REASONS /* quota, budget, cancelled, unreachable, optional */, EXPOSURES /* exposed, filtered, no-answer, closed, not-this-host, unknown */,
  FAILURE_KINDS, HEADLINE_KEYS /* incl. 'incomplete' */, NOT_HERE_KEYS /* SKIP_REASONS + 'proxied', 'managed' */
export const VERIFY_PORT = 443, VERIFY_TIMEOUT_S = 10, VERIFY_CONCURRENCY = 4, VERIFY_MAX_ROWS = 500, VERIFY_MAX_RETRIES = 5,
  VERIFY_SOFT_CONFIRM_PROBES = 50, VERIFY_REUSE_WINDOW_MS = 120000, VERIFY_MAX_REUSE = 1
// Result interpretation
export const hexKey, serialKey /* comparison only: leading zeros ignored */, serialDisplay /* byte-aligned = x509.serialHex / the CLI's serial ('07' stays '07') */
export function parseAltNames(alt) -> { dns, ip /* RFC 5952 */, other }
export function servedCert(tls) -> ServedCert|null            // null without fingerprint256; publicKeyHex stays in memory and is never exported
export function parseFailure(result) -> { kind: FAILURE_KINDS, alert, text }   // tolerant rawOutput patterns; the first match wins
export function trimTest(test) -> TrimmedTest                 // no headers or body; rawOutput for failures only, ≤ 300 chars
export async function expectationFor(certs, { subtle }) -> { sha256[], spkiHex[], hostnames[], subjectCN, notAfter, kinds[] /* certKind of each */ }
export function servedKind(served) -> 'origin-ca'|'self-signed'|'other'|null   // a served leaf (below)
export function certKind(cert) -> 'origin-ca'|'self-signed'|'other'           // an x509.js Certificate: issuer O CloudFlare, Inc. + an Origin CA name in OU / CN; selfSigned
export function classifyTest(test, { name, expect, now }) -> ProbeVerdict
export function aggregateVerdicts(verdicts) -> Verdict|null   // the worst verdict WITH a certificate wins (NEEDS_UPDATE > NOT_HOSTED > ORIGIN_CERT > PRIVATE_CERT > UPDATED); failures only
                                                              // when no probe got one (TLS_ERROR > TIMEOUT > CLOSED); 'mixed' when the probes disagree
// Rules over rows
export function applyWorksRule(rows) -> changed[]             // CLI `works`: per ip:port, a row with a certificate turns TLS_ERROR sni-refused / tls-alert / reset
                                                              // into NOT_HOSTED refused-name (alert 120, ALPN, excluded); recomputed from row.verdict every time
export function serverStatus(rows) -> status|null             // CLI server_status() parity (NEEDS_UPDATE > UPDATED > ORIGIN_CERT > PRIVATE_CERT > TLS_ERROR > …);
                                                              // Globalping's TCP-connect TIMEOUT is the CLI's connect-level TIMEOUT; a NEEDS_UPDATE / ORIGIN_CERT /
                                                              // PRIVATE_CERT row with newCertCovers === false counts as NOT_HOSTED
export function exposureOf(row) -> EXPOSURES|null             // proxied rows only; 'filtered' needs ≥ 2 probes from different ASNs, one silent probe is 'no-answer'
export const isOriginPair(pair) -> boolean   // via 'hint' (a candidate) or 'zone' (the zone file's exact origin): an origin IP with a proxied name, opt-in
export function recheckRows(rows), requeueRows(rows), applyOriginOptIn(rows, on),
  verifyCost(rows, { probesPerCheck, now }) -> { checks, reuse, probes, servers, origins, optional }   // a reusable paid id costs 0; origins / optional count origin pairs
// Pairs and the runner
export function buildVerifyPairs(result, { port }) -> { pairs, stats }   // covered, non-wildcard-suspect names × their inventory-server IPs (via dns | zone | hint)
                                                                        // and unmatched public IPs, all of them; skips: private, reserved, cdn-edge, bad-name, bad-port
export function scopePairs(pairs, 'all'|'perIp'), createVerifyRows(pairs, { origins = false, maxRows = VERIFY_MAX_ROWS })
  // origin pairs (hint and zone) start as not-run · optional unless `origins`; perIp keeps one DNS and one origin pair per IP;
  // verdicts still treat zone like DNS. The cap applies to the scope's pairs, whatever the opt-in: skipped pairs cost nothing,
  // then the first DNS or zone pair of every server address, the other DNS pairs, the other zone pairs (so zone origins
  // held back by the opt-in cost at most one place per address), the first hint pair of every address, the other hint pairs. The rest are marked `overCap` and become skipped rows ('over-cap'), except an origin pair
  // while the opt-in is off, which stays not-run · optional (applyOriginOptIn moves it). A row past the cap keeps its server
  // out of `live` (not of `incomplete`: "Check again" cannot finish it).
export function checkCount(pairs, { origins, maxRows }) -> number   // the checks createVerifyRows would make pending (the scope switch)
export async function runVerify(rows, { client, expect, signal, concurrency, timeoutS, probesPerCheck, locationsFor, maxProbes, maxRetries, onRow, onQuota, now })
  -> { spent, retries, stoppedBy: null|'quota'|'budget'|'abort'|'unreachable' }
// Summary, headline and exports
export function summarizeVerify(rows), notHereParts(summary, stats), verifyHeadline(summary, stats) -> [{ key: 'vfy.head.<k>', variant, params, parts? }]
export const VERIFY_CSV_COLUMNS   // the CLI's 17 CSV_COLUMNS in CLI order (a unit test parses them out of the CLI), then source, state, stale, skip, reason,
                                  // warnings, exposure, via, http_status, vantage, measurement_id, checked_at
export function verifyExportRows(rows, { now }), verifyExportJson(rows, { expect, summary, app, version, now })   // schema 'domainscope.verify/1'; rows start with the CLI's _row_dict keys
export function cliPlan(rows) -> { targets, names, rows }   // private / reserved / bad-name / bad-port / over-cap skips + TIMEOUT / CLOSED verdicts (not cdn-edge);
                                                            // a row on another port than 443 is the target ip:port ([v6]:port; cmdline allowPorts); a row on 443
                                                            // whose inventory server wrote the address with a port gives its cliTargets (buildVerifyPairs:
                                                            // inventory.addressTargets of the address, unioned over the servers sharing it)
```
Rules that are easy to get wrong:
- **Identity is `fingerprint256`** (= `computeFingerprints(der).sha256`, 12/12 live). Name **coverage** comes from `certCovers(served.hostnames, name).covered` over `subject.alt` (the CN only when there is no DNS SAN, the x509 rule), **never from `tls.error`**, which holds one code in which chain errors mask name errors. Serials: no `00` sign byte is re-added (neither side has one).
- Verdicts: covered + our fingerprint → UPDATED / `new-cert`; covered + another fingerprint → NEEDS_UPDATE / `old-cert` (`no-new-cert` without an expectation), except a certificate of another kind than every new one (the CLI's `HostedClassifier`): a Cloudflare Origin CA leaf → ORIGIN_CERT / `origin-ca`, a self-signed one (DEPTH_ZERO_SELF_SIGNED_CERT) → PRIVATE_CERT / `self-signed`; without an expectation each keeps its own status. A new certificate of the same family (`expect.kinds`: an Origin CA rollout, a self-signed one) keeps the older ones of that family NEEDS_UPDATE. The CLI's `--private-ca` has no counterpart: a probe reports only the leaf, so a private CA's leaf stays NEEDS_UPDATE (`untrusted-root`), as in the CLI without that option; not covered → NOT_HOSTED / `not-covered`; refused / unreachable → CLOSED; TCP-connect or handshake timeout → TIMEOUT; alert 112 → NOT_HOSTED / `unrecognized-name`; alert 40 → TLS_ERROR / `sni-refused`; any other alert, a reset (an early close too: `socket disconnected before secure TLS`, OpenSSL's `unexpected eof`, as the CLI treats `SSLEOFError`), not TLS or unknown → TLS_ERROR. DNS, private, internal and offline failures, empty results, a `tls` without a fingerprint and a status code without `tls` are **errors** (`dns` / `private` / `probe` / `offline`), never a server verdict; probe-side faults are retried on another probe (at most 5 per run).
- Warnings: `chain-incomplete` (UNABLE_TO_VERIFY_LEAF_SIGNATURE / UNABLE_TO_GET_ISSUER_CERT[_LOCALLY]), `expired` (also `notAfter < now`), `not-yet-valid`, `self-signed`, `untrusted-root`, `untrusted` (other codes), `name-mismatch` (ALTNAME_INVALID while our coverage says covered), `same-key` (NEEDS_UPDATE whose public key of ≥ 32 bytes ends the new SPKI), `http-421`, `mixed`, and `origin-ca` (a Cloudflare Origin CA issuer; it replaces chain-incomplete, untrusted and untrusted-root). Origin CA detection follows what a probe reports: Globalping gives the issuer's C, O and CN only, and the Origin CA's DN has no CN (its name is the OU), so an issuer `O=CloudFlare, Inc.` without a CN on a leaf the probe did not trust is the Origin CA; an issuer CN naming it counts too. Cloudflare's publicly trusted CAs all carry a CN.
- Runner: the probe budget is **reserved before each POST**, so parallel workers never overspend. A paid, unfinished measurement (Stop, deadline) is polled again for free, first, but only within 120 s and once. A re-check keeps the last verdict, marked `stale`, until a new one replaces it, so a stopped or quota-limited re-check never makes a server look live. `TimeoutError` / `TypeError` → `network` (3 → `stoppedBy 'unreachable'`); a quota 429 (`rate_limit_exceeded` / `insufficient_credits`) stops the queue (`not-run · quota`), while any other 429 waits for `Retry-After` (5 s without one, at most 60 s) and repeats the POST once, else `poll-rate`; a free `private-target` / `bad-host` 400 turns the row into a `reserved` / `bad-name` skip; a GP code outside VERIFY_ERRORS becomes `unknown` (the code is kept in `row.error.raw`).
- Headline (servers, not IPs; bare IPs stand for unmatched addresses; a shared VIP counts for every server that lists it): base = total − filtered origins − origin candidates that do not host the name (`notHostingOrigins`). Origin rows that behave as expected (filtered, no answer, closed, or an origin hint answering "not this name") never make a server a problem, and a server leaves the base only once every row of it has a verdict; `all` also needs `incomplete` = 0. The first entry is exactly one of `all` / `some` / `none` / `partial` / `noAnswer`: `none` also when no server is live and a DNS- or zone-matched name gets another certificate or a refusal (`wrongCert`, which makes `other` warn), `partial` with 0 live when a server returned some certificate (`served`, e.g. an Origin CA one), `noAnswer` only when none did; then, when non-zero, `incomplete`, `chain` (servers with an UPDATED row missing its intermediate), `tlsError`, `unreachable`, `other`, `originCert`, `privateCert`, `exposed`, `filtered`, `notHere`. Every counted entry carries `params.count`. ORIGIN_CERT / PRIVATE_CERT servers (`servers.originCert` / `privateCert`) stay in the base — the new certificate is not live there — but are never `old`; their entry is info behind a CDN and warn when such a row is not proxied (`originDirect` / `privateDirect`: visitors reach a certificate no browser trusts). "Check again" re-checks them like any row that is not UPDATED. The JSON export adds `newCertificate.kinds`, `summary.servers.originCert` / `privateCert` and a per-row `certKind`; the CSV keeps the CLI's 17 columns, with the new statuses in `status` and the kind in `reason`.

### 5.20 `lib/zoneparse.js` — zone exports → records (Zone File, ROADMAP P1.2)
Pure, synchronous, DOM-free, no I/O. `parseZone()` never throws: every problem is an issue whose `code` is in the closed set `ISSUE_CODES` (49 codes: fatal, error, warn, info), with `params` for i18n; `detail` is English log text that the UI never parses.
```js
export function parseZone(input /* string | ArrayBuffer | Uint8Array */, { origin, filename, format = 'auto' /* | ZONE_FORMATS */, source, limits, defaultTtl } = {}) -> Zone
export function detectZoneFormat(text, { filename }) -> { format, dialect, markers: string[], confidence: 'high'|'low', notZone, fatal: { code, params }|null }
export function mergeZones(zones, { limits, lead }) -> Zone           // several files of ONE zone (API pages, a $INCLUDE part); different origins → fatal ORIGIN_MISMATCH
export function inferOriginFromFilename(filename) -> string|null      // 'db.example.com', 'example.com.zone.txt' → 'example.com'
export function zoneNames(zone) -> string[] ; export function uniqueRecords(zone) -> ZoneRecord[] ; export function wildcardCovers(zone, name) -> string|null   // RFC 4592
export function rdataKey(type, data) -> string ; export function txtJoinedKey(type, data) -> string   // THE comparison keys (file data and live dnswire rr.data alike)
export function toBindText(zone, { header = true }) -> string          // canonical BIND (cf_tags kept; aliases / routing in cli53 syntax)
export function awsAliasProvider(target, { origin, self }) -> string|null
export const ZONE_FORMATS = ['bind', 'cloudflare-api', 'route53', 'octodns', 'plesk-info'], ZONE_DIALECTS = ['generic', 'cloudflare', 'cli53', 'godaddy', 'cpanel', 'directadmin'],
  ORIGIN_SOURCES = ['user', '$ORIGIN', 'header', 'soa', 'filename', 'records'], NOT_A_ZONE_HINTS, ISSUE_CODES, ZONE_LIMITS, GTLDS, AWS_ALIAS_PROVIDERS
// also exported for tests: tokenizeMaster, parseYamlSubset, decodeUtf8Lenient, presentCharString, presentLabel, decodeEscapes
Zone = {
  format, dialect, markers: string[],
  origin, originSource, originConfidence: 'high'|'low' /* 'low' ⇒ the UI asks the user to confirm */,
  records: ZoneRecord[], warnings: ZoneIssue[], fatal: ZoneIssue|null, partial: boolean,
  sources: [{ name, size, format, dialect }],
  stats: { bytes, lines, entries, records, skipped, generated, proxied, dnsOnly, byType, elapsedMs },
  defaultTtl
}
ZoneRecord = {
  id, name /* served owner, lowercase, '*' kept, no trailing dot */, intendedName?, type,
  ttl: number|null, ttlAuto?, data /* dnswire RR.data shape */, text /* what dnswire prints */,
  targets: string[], intendedTargets?,
  proxied: true|false|null, proxiable?, flattenCname?, alias?: { target, zoneId, evaluateTargetHealth, provider }, routing?,
  occludedBy?, invalid?, unsupported?, generated?, duplicateOf?, comment?, tags?, line, source
}
ZoneIssue = { code, severity: 'error'|'warn'|'info', line, source?, name?, type?, params, detail }
```
Inputs:
- BIND / RFC 1035 master files: `$ORIGIN`, `$TTL`, relative names, parentheses, `$GENERATE` (capped), and `$INCLUDE`, which is refused and merged only when the file is dropped too (in any order, nested parts too; a part that does not name its own zone is read under the `$INCLUDE` origin argument, else the origin in effect at that line: INCLUDE_REJECTED `params.at`, and is as sure of the zone name as the main file; a part with its own sub-block `$ORIGIN` merges under the file that includes it when that file's origin, even a file-name guess, lies at or above it; a file no `$INCLUDE` names keeps its own zone name unless it has none). The zone name comes from the user, else a `$ORIGIN` before the first record, the header, the SOA owner, the NS / other owners or the file name; a later `$ORIGIN` only opens a sub-block (it names the zone, with `low` confidence, when nothing else does or only a low-confidence guess (the file name, the record owners) does and the `$ORIGIN` lies outside it), and `$ORIGIN .` (BIND secondary, `named-compilezone`, `pdnsutil` dumps) never makes the root the zone unless the SOA owner is the root. Dialects:
  - the Cloudflare export (`;; Domain:` header, `cf_tags=cf-proxied:true|false`);
  - cPanel, DirectAdmin and GoDaddy;
  - cli53 (`AWS ALIAS`, `; AWS routing=`);
  - `dig AXFR` output.
- Cloudflare API JSON: one or several pasted pages.
- Route 53 `list-resource-record-sets` JSON: octal escapes, aliases, routing sets.
- An octoDNS YAML subset: a scratch parser with null-prototype maps.
- Plesk `--info` output (marked FORMAT_UNVERIFIED).

Limits: 5 MB per file, 5,000,000 characters, 20,000 records, 200,000 entries and 500 issues.

### 5.21 `lib/zonelint.js` — mistakes in an imported zone
```js
export function lintZone(zone) -> { findings: LintFinding[] /* severity, then line */, occluded: Map<name, 'cut'|'dname'>, occludedIds: Set<number>, proxiedOrigins: Set<string> }
LintFinding = { code /* LINT_RULES */, severity: 'error'|'warn'|'info', name, type, line, source, recordIds: number[], params, detail }
export const LINT_RULES   // 38 codes, each { severity, scopes, severityCf?, severityByFormat? }
export const SEVERITY_ORDER = ['error', 'warn', 'info'], CAA_KNOWN_TAGS, CF_PROXY_PORTS, LONG_CHAIN_HOPS = 8, TTL_LOW = 30, TTL_HIGH = 172800, TTL_OUTLIER_FACTOR = 20, SOA_NEGATIVE_TTL_MAX = 86400
```
The rules:
- CNAME conflicts: CNAME with other data or at the apex, multiple CNAMEs, loops, chains of more than 8 hops. Multiple CNAMEs and multiple SPF records are counted per routing variant (a Route 53 / cli53 SetIdentifier, an octoDNS pool value or geo code), since variants are never served together.
- Targets: MX / NS / SRV pointing to a CNAME, a target that is an IP address, dangling in-zone targets.
- Duplicates and hidden data: DUPLICATE_RR, data occluded by a delegation or a DNAME.
- Addresses: private, localhost and non-global IPv6.
- Cloudflare zones:
  - mixed proxy flags;
  - an origin exposed by a DNS-only sibling or MX (ORIGIN_EXPOSED_BY_SIBLING) or by SPF;
  - a private or Cloudflare-range origin;
  - originless placeholders, Tunnels and SaaS targets;
  - proxied MX targets, and proxied SRV targets off the proxy's ports.
- Mail and certificates: SPF (multiple, invalid, SPF RR type), DMARC, CAA tags and flags.
- TXT strings longer than 255 bytes.
- TTL outliers and very low TTLs, the SOA negative TTL, a single NS.
- Route 53 alias targets missing from the zone.

The zone index is shared with `zoneorigins.js`, so lint findings and the origin map's `exposure` come from one source.

### 5.22 `lib/zoneorigins.js` — seeds, the proxied-origin map and the CLI hand-off
Pure: no network, storage or clock. Origins stay exact: an address is never widened to its /24, and every proxied name keeps its own origin.
```js
export function zoneIndex(zone) -> index            // cached per zone object; shared by lint and drift
export function deriveSeeds(zone, { lint, skip }) -> { names, wildcardBases, delegations, excluded: [{ name, why /* SEED_EXCLUSIONS */ }] }
export function proxiedOriginMap(zone, { inventoryIndex }) -> ProxiedOrigin[]
ProxiedOrigin = { name, kind: 'ip'|'host'|'tunnel'|'provider'|'placeholder'|'cloudflare-ip'|'unresolved'|'loop', ips, ignored, host, via: string[] /* in-zone chain */,
  provider, target, proxiedBy: 'direct'|'chain', private, servers: [{ serverId, name, ip }], exposure: [{ by: 'sibling'|'mx'|'spf', name }], recordIds }
  // Cloudflare rules: one proxied A/AAAA makes the whole name proxied; a DNS-only CNAME to a proxied name is proxied through the chain;
  // 192.0.2.0 / 100:: are originless placeholders; an address in Cloudflare's own ranges is not an origin (error 1000)
export function addressMap(zone, { inventoryIndex }) -> Array<{ ip, names: [{ name, proxied, via?, exposed?, occluded? }], servers, private, provider, placeholder, exposed }>
export function privateLookingNames(zone) -> Set<string>   // private A/AAAA, INTERNAL_LABELS, INTERNAL_SUFFIXES, or a DNS-only CNAME / Route 53 alias into the set
export function handoffNames(zone) -> string[]             // TLS-bearing names for scope 'all'
export function cliHandoff(zone, { origins }) -> { targets, hostTargets, names, skipped, dropped }   // scope 'proxied'; kinds ip / host only
export function zoneSweep(zone, { scope = 'proxied'|'all', shell, script, origins, buildCommand }) -> { scope, targets, hostTargets, names, skipped, dropped, command, tokens, chars,
  probes, probesAtLeast, fileForm /* > 60 tokens or > 2,000 chars */, commandOptions }   // pass cmdline.buildSweepCommand as buildCommand; otherwise command is null
export function handoffFiles(sweep, { origin, inventoryIndex, now }) -> { namesTxt, targetsTxt }   // zone-names.txt / zone-targets.txt ('<server> <ip>' lines, then host targets)
export function zoneScanInput(zone, { skip, skipPrivate = true }) -> { v: 1, origin, names, wildcardBases, delegations, proxied: [{ name, ips, host }], skipped }   // → runScan({ zone })
export function validateHostTargets(list), validateSweepNames(list), isInetAtonNumeric(s)   // the same rules as cmdline's opt-ins
export function isCloudflareIp(ip), isPrivateAddress(ip), isPlaceholder(ip), providerIdOfIp(ip), classifyExternalTarget(target), wildcardCovers(zoneOrIndex, name), sortIps(ips),
  servedTargets(r), effectiveTargets(r), addressOf(r), isSpfRecord(r), proxiedCore(idx), proxiedSets(idx), exposureFacts(idx), zoneConstants()
export const ORIGIN_KINDS, PLACEHOLDERS = ['192.0.2.0', '100::'], TUNNEL_SUFFIX = 'cfargotunnel.com', CF_HOSTED_SUFFIXES, AWS_ORIGIN_PROVIDERS, INTERNAL_LABELS, INTERNAL_SUFFIXES,
  SEED_EXCLUSIONS, SWEEP_INLINE_MAX_TOKENS = 60, SWEEP_INLINE_MAX_CHARS = 2000, ZONE_NAMES_FILE = 'zone-names.txt', ZONE_TARGETS_FILE = 'zone-targets.txt', MAX_CNAME_CHAIN = 16
```

### 5.23 `lib/zonedrift.js` — the zone compared with live DNS
All I/O goes through the injected DohClient (`dns.query` only).

What is sent:
- names and types only, to the resolver chain with failover (or one chosen resolver);
- never through `balance` rotation, never to Globalping or a passive source.

What is never sent:
- names outside the zone origin (the parser's OUT_OF_ZONE: name servers ignore them; `skipped` / `out-of-zone`);
- private-looking names (skipped by default), also as a flattened or alias target;
- the target of a proxied CNAME;
- flattened / alias targets outside the zone, unless `resolveTargets` (a skipped target stays hidden even then);
- types the file does not contain, and HTTPS / SVCB at a proxied name (`cf-synthesized`).

Every (name, type) is queried once.
```js
export function planDrift(zone, { skip, skipPrivate = true, wildcardProbes = true, resolveTargets = false, maxQueries }) -> { rrsets, queries /* EXACTLY what driftZone sends */,
  needed, overBudget, maxQueries, names, skipped: { private, occluded, outOfZone, unsupported, escaped, dnssec, synthesized, wildcard, budget }, targetsHidden, internalShare }
export async function driftZone(zone, { dns, resolver, signal, onRow, onProgress, maxQueries = 2000, concurrency = 6, skip, skipPrivate = true, wildcardProbes = true,
  resolveTargets = false, labelFn, now }) -> { origin, startedAt, finishedAt, aborted, queries, planned, resolverPolicy,
  preflight: { originExists, liveSerial, fileSerial, serial: 'same'|'newer'|'older'|'unknown', fileNs, liveNs, nsMatch: 'same'|'overlap'|'disjoint'|'unknown' }, rows: DriftRow[], counts }
  // Never rejects on DNS failure or cancel (aborted: true). Free rows stream first, then 2 preflight queries (SOA, NS at the origin),
  // then every other RRset. A missing origin (NXDOMAIN) turns every remaining row into error / nxdomain without another query.
DriftRow = { key, name, type, status, reasons: string[], file, live, added, removed, resolver, rcode, fileTtl, liveTtl, proxied, recordIds, probe }
export function classifyExtraNames(zone, liveNames) -> Array<{ name, kind: 'wildcard'|'delegated'|'extra', matchedBy }>   // live names missing from the file
export const DRIFT_STATUSES /* match, differs, missing-live, proxied-ok, origin-exposed, flattened-ok, alias-ok, routing-ok, occluded, skipped, error */, DRIFT_REASONS /* 31 */,
  DRIFT_SEVERITY, DRIFT_DEFAULT_BUDGET = 2000, DRIFT_MAX_BUDGET = 10000, DRIFT_MAX_CONCURRENCY = 8, DRIFT_TTL_FLOOR = 60, CF_CAA_ISSUER_IDS, MANAGED_ALIAS_PROVIDERS
```
How drift reads a zone:
- A proxied name is `proxied-ok` when the live answers are Cloudflare addresses, and `origin-exposed` when the live answer is the origin.
- Flattened CNAMEs, Route 53 aliases (rotating managed ones included) and routing sets have their own `*-ok` statuses.
- `ttl-stale` is reported only when the live TTL is above max(file TTL, 60).
- Filtering resolvers give `filtered`.

### 5.24 `lib/mtasts.js` — the MTA-STS policy (RFC 8461)
DOM-free. A browser cannot read `https://mta-sts.<domain>/.well-known/mta-sts.txt` (no CORS), so Domain Health fetches it through one Globalping probe (§3, §5.18) after an explicit click; this module builds that request and interprets the result. The probe cannot open SMTP: the MX hosts' STARTTLS certificates (RFC 8461 §4.2) are not checked.
```js
export const MTA_STS_PATH = '/.well-known/mta-sts.txt', MTA_STS_MAX_AGE_LIMIT = 31557600, MTA_STS_MODES = ['enforce','testing','none'], MTA_STS_TIMEOUT_S = 10,
  MTA_STS_CERT_WARN_DAYS = 14, MTA_STS_SHORT_MAX_AGE = 86400, MTA_STS_WEEK = 604800, MTA_STS_FINDINGS /* 42 ids */,
  MTA_STS_HEADLINES /* unreachable, invalid, inconclusive, not-published, txt-invalid, wrong-type, problems, warnings, off, no-mx, mx-unknown, ok */
export function mtaStsPolicyHost(domain) -> 'mta-sts.<domain>'|null   // null when Globalping would refuse the host (isProbeableHost)
export function mtaStsPolicyUrl(domain) -> string|null ; export function mtaStsPolicyRequest(domain, { timeoutS = 10 }) -> body   // httpsGetRequest, 1 probe; TypeError without a policy host
export function mxPatternMatches(pattern, host) -> bool   // literal, or '*.' matching exactly one more left-most label (RFC 8461 §4.1); case / trailing dot ignored
export function parseMtaStsPolicy(text) -> { version, mode, maxAge, mx: string[], extensions, issues: Array<{ code, params }>, valid }
  // never throws; LF or CRLF; a leading UTF-8 BOM → bom (fatal; the rest is read without it); case-sensitive field names ('Version:' → field-case);
  // a line that is not `key: value` → syntax (fatal); a blank line → blank-line;
  // duplicates keep the first (duplicate); version STSv1, a known mode, max_age ≤ 10 digits and ≤ 31557600, ≥ 1 valid mx pattern unless mode none
export function interpretPolicyFetch(measurement, { host }) -> { measurementId, probe, finished, failure: { kind /* verify.parseFailure */, text }|null,
  httpStatus, contentType, location, body, truncated, tls: { authorized, error, hostnames, covers /* certCovers(host) */, notAfter, issuer }|null }
export function validateMtaSts({ domain, fetch, mxHosts, txt, txtInvalid, tlsRpt, now }) -> { headline, severity, mode, policy, usable, host, findings: Array<{ id, severity, params }>,
  mx: Array<{ host, matchedBy }>, unusedPatterns }
  // order: transport (fetch.* / tls.* / http.*), grammar (policy.*), mode.*, max-age.*, mx.*, txt.missing / txt.invalid. A policy senders cannot fetch (no answer, a certificate that is
  // not valid for mta-sts.<domain> or is past its notAfter by this clock even when the probe accepted it, a status other than 200, any redirect) or cannot parse stops
  // there ('unreachable' / 'invalid'). A media type other than text/plain (none at all included) is an error, http.content-type, but no stop: RFC 8461 §3.2 says senders
  // SHOULD accept only text/plain and strict ones ignore the policy, while the others still use it (its MX cross-check still runs; `usable` stays true).
  // An MX host no pattern matches is an error in enforce mode, a warning in testing mode; truncation, a short max_age, testing without TLS-RPT (tlsRpt === null) and a
  // missing _mta-sts TXT (txt === null) are warnings, and so is a TXT set senders reject (txtInvalid > 0: two or more "v=STSv1" records, or one without an
  // id; RFC 8461 §3.1 has senders assume no policy then: txt.invalid); `undefined` txt / tlsRpt means "not known" (no finding). A certificate rejected without an error code is tls.rejected.
  // mxHosts: an array (a null MX "." is no host: mx.null; none: mx.none), anything else is "not known" (the MX lookup failed: mx.unknown, nothing compared, no unused pattern).
  // A usable policy's headline: 'wrong-type' (not text/plain, announced by the TXT record or not known, and no other error), else 'off' (mode none), 'not-published'
  // (txt === null: senders never fetch it), 'txt-invalid' (txtInvalid > 0: they never fetch it either), else 'problems' / 'warnings' by the worst finding, else 'ok' only when MX hosts were compared ('no-mx' without any,
  // 'mx-unknown' when not known). Params are language-neutral, pre-joined (numbers raw: the view groups `value` / `max` by locale); tls.expiring and mx.ok carry
  // `count` for their plural texts.
export function mtaStsExport({ domain, fetch, validation, checkedAt }) -> plain JSON (url, checkedAt, measurementId, probe, headline, severity, usable, mode, maxAge,
  mx, unusedPatterns, http, failure, tls, policy, findings)   // Domain Health's "Report (JSON)" `mtaStsPolicy`
export const MTA_STS_I18N = { en, tr }   // mtasts.<finding>.title / .detail and mtasts.head.<headline>
```

### 5.25 `lib/dane.js` — the DANE / TLSA renewal guard
Will the new certificate break DANE? A TLSA record (RFC 6698) that still pins the old certificate or key makes DANE-validating senders queue mail for that host (SMTP, RFC 7672) and DANE-aware clients refuse HTTPS, silently, from the moment the new certificate is installed. DOM-free; the digests come from WebCrypto (`crypto.subtle`, in Node too). All I/O goes through the injected DohClient (`dns.query` only).

What is sent (only by `checkDane`, only after a click):
- one MX query per registrable domain of the certificate's names (`domain.baseDomainsFromNames`), then one TLSA query per endpoint: `_25._tcp.<mx host>` for every MX host (the domain itself when it has no MX, RFC 5321 §5.1; nothing for a null MX, RFC 7505) and `_443._tcp.<name>` for every concrete certificate name;
- every query with the DO bit (for the RRSIG and its original TTL), and with `noCache` from the panel (a check right after publishing a record asks the resolvers again); one more TLSA query with CD set only for an endpoint that answered SERVFAIL (bogus DNSSEC vs broken name servers);
- names and types only, never the certificate. A certificate name is sent only when it already is a clean host name (`normalizeHostname(name) === name`).

Names:
- Wildcard names are skipped, never mapped to the apex: `*.example.com` does not cover `example.com`, and a TLSA record lives at a concrete host name (`_443._tcp.www.example.com`). The caller may add concrete names the certificate covers (`extraNames`; SSL Targets adds the covered, resolving, non-wildcard-suspect hosts of its scan); a name it does not cover is dropped (`skipped.notCovered`).
- Deduplicated (an MX host shared by several domains is one endpoint with every domain in `via`) and capped: `DANE_LIMITS = { mxDomains: 10, mxHosts: 20, httpsNames: 25 }`, the rest counted in `skipped` (`mxHostsOverCap` counts hosts, once however many domains name them).
```js
export const TLSA_USAGES /* 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE */, TLSA_SELECTORS /* 0 Cert, 1 SPKI */, TLSA_MATCHING /* 0 Full, 1 SHA2-256, 2 SHA2-512 */,
  DANE_PORTS = { smtp: 25, https: 443 },
  DANE_STATUSES /* worst first: danger, servfail, ta-mismatch, ta-unchecked, pkix, error, insecure, not-covered, unusable, safe, none */, DANE_SEVERITY,
  DANE_ACTION_STATUSES /* danger, ta-mismatch, ta-unchecked, pkix: publish first */, TLSA_ISSUES /* bad-usage, bad-selector, bad-matching, bad-length, pkix-smtp */,
  DANE_NOTES /* stale-records, spki-match, mx-insecure, ad-unknown, bogus, cname, implicit-mx, ttl-remaining */,
  DANE_HEADLINES /* danger, servfail, warn, error, safe, clear, unused */, DANE_LIMITS
export class DaneError /* code 'no-crypto' | 'bad-input' */
export async function certAssociations(cert, { subtle }) -> Associations   // a[selector][matchingType], lowercase hex; a[1][1] = the data of a `3 1 1` record
export function associationData(assoc, selector, matchingType) -> string|null
export function issuedBy(leaf, ca) -> boolean                    // subject = the leaf's issuer and, when both carry one, SKI = the leaf's AKI
export function tlsaOwner(host, port = 25) -> '_25._tcp.<host>'
export function tlsaRecordText(owner, rec) -> '<owner>. IN TLSA 3 1 1 <HEX>'   // paste-ready, hex in upper case
export function matchRecord(rec, { service, leaf, anchors }) -> { usable, matches: boolean|null, matchedBy: 'leaf'|'chain'|null, anchor, issue }
export function evaluateRecords(records, ctx) -> { verdict: 'none'|'unusable'|'safe'|'ta-unchecked'|'danger'|'ta-mismatch'|'pkix', records }
export function suggestRecords(owner, evaluation, { leaf, issuer }) -> [{ owner, usage, selector, matchingType, data, text }]
export function authenticated(response) -> true /* AD */ | false /* AD clear, validating resolver */ | null /* unknown resolver, no answer */
export function tlsaFromAnswer(response, owner) -> { records, target, cnames, ttl, ttlSource: 'rrsig'|'answer'|null }
export function endpointVerdict(endpoint, { response, cdResponse, mxAuthenticated, leaf, anchors, issuer }) -> { lookup, records, ttl, ttlSource, status, severity, wouldBe, notes, suggestions, waitSeconds }
export function planDane(leaf, { extraNames, mx = true, https = true, limits }) -> { domains, https: [{ host, source: 'cert'|'extra' }], skipped }   // pure: what a check sends
export async function checkDane({ leaf, chain }, { dns, subtle, signal, extraNames, mx, https, limits, noCache, onProgress, now }) -> DaneReport
  // rejects only with AbortError, DaneError 'no-crypto' or a TypeError; a failed lookup is an 'error' endpoint (or domain), never a rejection
DaneReport = { startedAt, finishedAt, leaf: { subjectCN, serialHex, hostnames }, associations: { leaf, anchors: [{ subjectCN, subjectDN, issuer, assoc }] },
  domains: [{ domain, rcode, resolver, authenticated, mx, nullMx, implicit, invalid, error }], endpoints: DaneEndpoint[] /* SMTP in MX order, then HTTPS */,
  skipped: { wildcard, invalid, notCovered, httpsOverCap, domainsOverCap, mxHostsOverCap }, queries }
export function daneSummary(report) -> { total, counts, headline, variant, count, warn, action, waitSeconds, mxFailed, nullMx }
export function daneExportJson(report, { app, version }) -> { schema: 'domainscope.dane/1', … }   // the loaded certificates as digests (matching types 1 and 2), not bytes; a record to add for a published matching-type-0 record (`3 1 0`) carries the full data it must publish
```
Verdicts (per endpoint; a record set matches when ANY usable record matches, RFC 6698 §2.1):
- **none** "DANE not used": no TLSA record (NOERROR / NODATA or NXDOMAIN). **safe**: a usable record matches the new certificate. Other records that no longer match are noted (`stale-records`: remove them after the rollout), and so is a match on the public key only (`spki-match`), because a new key needs a new record.
- **danger**: the DANE-EE (3) records all pin another certificate or key. The suggestion keeps the usage, selector and matching type of each published combination, with the new data. The wait is **2 × TTL**: the RRSIG's original TTL when the answer carries one, else the TTL the resolver returned (`ttl-remaining`: the real one may be longer). The panel's order: publish next to the old records, wait, install, check again, then remove the old records (RFC 7671 §8.1).
- DANE-TA (2) and PKIX-TA (0) are compared with the other certificates of the loaded file: **ta-mismatch** when none matches (the suggestion uses the leaf's issuer from the file), **ta-unchecked** when the file holds only the leaf (the suggestion is `3 1 1` of the leaf). Both are warnings, not a certain break: the server may still send the pinned CA.
- PKIX-EE (1) / PKIX-TA (0): **pkix** for HTTPS when none matches (browsers ignore them). SMTP ignores the PKIX usages (RFC 7672 §3.1.3), so there they are `unusable` (`pkix-smtp`), like unknown parameters and digests of the wrong length. **unusable**: no usable record, so senders still require TLS but do not authenticate it.
- **insecure**: DANE clients ignore TLSA that DNSSEC does not validate (AD clear from a resolver known to validate). Senders also ignore the TLSA of an MX host when no MX record set naming it was validated (RFC 7672 §2.2.1, `mx-insecure`). `wouldBe` keeps the record verdict, so the panel can say what happens once DNSSEC validates them; the suggestions stay available. A resolver not known to validate leaves `authenticated: null` (`ad-unknown`), and the record verdict stands.
- **not-covered**: an MX host the certificate does not name (a provider's mail server). Its records pin that server's own certificate and matter only if this certificate is installed there; a matching record there is still `safe`.
- **servfail**: DANE clients cannot tell whether records exist, so senders already defer mail and clients refuse to connect there, whatever the certificate (`bogus` when the CD re-query resolves). **error**: no DNS answer, or another rcode.
- Headline: danger > servfail > warn (ta-mismatch, ta-unchecked, pkix) > error > safe > unused (every endpoint `none`) > clear. `error` counts the failed endpoint lookups plus the registrable domains whose MX lookup failed, so a failed MX query never reads "DANE not used".

### 5.26 `lib/ctcert.js` — a host name's public certificate from Certificate Transparency
DOM-free. For users without a certificate file (Certificate view, SSL Targets step 1). Every request goes through `util.fetchJson` with an injected `fetchImpl` and the caller's `signal`, as a plain GET (`accept: application/json`, `credentials: 'omit'`, `referrerPolicy: 'no-referrer'`); only the host name is sent. Endpoint facts in §3 ("One host name's certificate").
```js
export const CERTSPOTTER_ISSUANCES, CRTSH_BASE, CT_MAX_PAGES = 5, CT_TIMEOUT_MS = 25000, CRTSH_TIMEOUT_MS = 60000,
  CRTSH_RETRY_DELAY_MS = 4000, CT_COOLDOWN_MS = 3600000
export const CT_LOOKUP_STATUSES = ['found', 'manual', 'not-found', 'error'], CT_SPOTTER_STATES = ['ok', 'partial', 'failed', 'skipped']
export function normalizeCtHost(input) -> string|null     // host, URL or *.domain (IDN → punycode); null for IPs, single labels, *.<public suffix>
export function coversCtHost(names, host) -> bool         // RFC 6125 (domain.certCovers); a *.x query wants that very name
export function certspotterUrl(host, { after }) -> string ; export function crtshSearchUrls(host) -> string[]
export function selectIssuance(issuances, host, { now }) -> { issuance: CtIssuance|null, der, certificate, precertificate, newerPrecertificate, candidates, skipped }
export function selectCrtshEntry(rows, host, { now }) -> { entry: CtCrtshEntry|null, candidates }
export function createCtCooldown() -> { get(now) -> SourceQuota|null, set(quota, untilMs), clear() } ; export const ctCooldown   // the page session's (memory only)
export async function lookupCtCertificate(input, { fetchImpl, signal, now, cooldown = ctCooldown, maxPages = 5, timeoutMs, crtshTimeoutMs, crtshRetryDelayMs, crtsh = true }) -> CtLookup
CtLookup = { host, status, provider: 'certspotter'|'crtsh'|null, der: Uint8Array|null, certificate /* x509 Certificate */, issuance, precertificate, newerPrecertificate,
  candidates, skipped: { notCovering, notYetValid, expired, revoked, unreadable }, truncated, requests,
  certspotter: { state, error, errorKind, quota /* sources.sourceQuota('certspotter') on a 429 */ }, crtsh: { entry, candidates, partial, error, errorKind }|null, error, errorKind }
CtIssuance = { id, notBefore, notAfter, dnsNames, sha256, url /* crt.sh search by SHA-256 */ }
CtCrtshEntry = { ids /* precertificate + certificate, ascending */, serialHex, issuer, notBefore, notAfter, names, downloads: [{ id, url /* crt.sh/?d= */ }], pageUrl }
```
Selection and fallback:
- **Pick:** issuances that cover the host, are valid at `now` and not revoked, newest `not_before` first (then the higher id); the DER is parsed with `x509.parseCertificate` and must cover the host itself. A final certificate wins over a newer issuance that is only logged as a precertificate (reported as `newerPrecertificate`); a precertificate is picked only when no final certificate is logged (`precertificate: true`; the views warn that servers send another fingerprint).
- **Paging:** until an empty page or `maxPages` (then `truncated`); a later page that fails keeps the rows read so far (`certspotter.state 'partial'`, `truncated`). The empty page is the documented end and the page size is no contract, so a short page does not end the list: most names cost two requests, about 50 lookups of the hourly 100.
- **Nothing current in Cert Spotter's answer** → `not-found`, and crt.sh (the same logs) is not asked. A list cut at `maxPages` stays `truncated` and crt.sh is not asked for it either (a name with that many certificates is where its search times out); the views hedge the note instead of saying flatly that nothing is logged, because the unread issuances are the newest.
- **Cert Spotter failed, rate limited or only unreadable rows** → crt.sh identity searches (in parallel, one retry each on a server error, never after a timeout); a match → `manual` (the newest certificate with its `?d=` download links, because a page cannot read crt.sh's download), none → `not-found`, both services down → `error`.
- **Rate limit:** a Cert Spotter 429 starts a cool-down (a readable `Retry-After`, else an hour) in which later lookups of the page session go straight to crt.sh (`certspotter.state 'skipped'`) instead of prolonging the penalty. `certspotter.quota.resetAt` is the cool-down's end: the views say until when only crt.sh is searched, also when crt.sh then fails (`error`).
- Only an abort rejects; an invalid name throws a `TypeError` before any request.

### 5.27 `lib/scanform.js` — the SSL Targets setup form as data
Pure: no DOM, storage, network, clock or i18n; `views/scan.js` turns the results into text, checks and data attributes.
```js
export function formProgress({ cert, certCA, certNames, domains, invalid, publicSuffixes, extraNames, servers }) -> { ready, via: 'domains'|'cert'|'extra'|null,
  steps: { cert, domains, inventory, options: true }, certIssue: 'ca'|'noNames'|null }
  // ready = what Start accepts: typed domains, a loaded certificate's names, or extra hostnames (via names the first, in that order).
  // A step is complete with usable input: a loaded server certificate with at least one DNS name; typed domains with no invalid
  // entry and no public suffix; a saved server. certIssue: why a loaded certificate leaves its step open ('ca' first, then 'noNames').
export function optionChanges(options, defaults, { totalSources, extraNames, locales, custom, learned }) -> Array<{ id, value?, count?, total? }>
  // What differs from defaults (views/scan.sanitizeOptions(null)), in OPTION_CHANGE_IDS order; [] = "recommended defaults".
  // sources: the ticked set (order ignored) → { count, total }; bruteforce, permutations, includeExpired, originHints: the value;
  // permutationBudget only while permutations are on; languages (a manual list, locales !== null) only at Smart / Large / Huge;
  // extraNames always; custom / learned only while a wordlist level tries them.
export function barStuck({ sticky, top, bottom, viewportHeight }) -> boolean
  // The bottom-sticky run bar floats while its container (the form, whose last child it is) ends below the viewport and is on screen.
export const FORM_STEPS = ['cert', 'domains', 'inventory', 'options'], OPTION_CHANGE_IDS
  // FORM_STEPS: page order, which numbers the view's steps.
```

### 5.28 `lib/ptrsweep.js` — reverse DNS sweep with forward confirmation (ROADMAP P2.5)
DOM-free. DNS goes through the injected client (`dns.query(name, type, { signal, balance, noCache })` only: a DohClient, or lib/health's adapter); RIPEstat through `util.fetchJson` with an injected `fetchImpl`. Nothing is sent by importing it.
```js
export const SWEEP_MAX_ADDRESSES = 1024 /* a /22 */, SWEEP_MAX_PREFIX = 22, FCRDNS_MAX_NAMES = 4, SWEEP_MAX_CONCURRENCY = 64
export const FCRDNS_STATUSES = ['confirmed', 'mismatch', 'no-ptr', 'nxdomain', 'servfail', 'error'], FORWARD_STATES = ['match', 'other', 'nodata', 'nxdomain', 'error'],
  TARGET_ISSUES /* invalid, v6-range, reversed, too-large, over-cap, asn-many, asn-mixed, private, reserved, host-bits, nothing */, TARGET_ISSUE_SEVERITY,
  ROW_RANKS = { focus: 0, named: 1, templated: 2, none: 3, failed: 4 }, SWEEP_FILTERS = ['all', 'ptr', 'focus', 'confirmed', 'mismatch', 'none', 'failed'],
  GENERIC_PTR_WORDS, SWEEP_CSV_COLUMNS = ['ip', 'status', 'ptr', 'confirmed', 'forward', 'template', 'operator', 'servers', 'focus', 'error']
export function parseAsn(token) -> number|null              // 'AS64496' / 'as64496' / 'ASN 64496'; a bare number is not an AS; AS0 and > 2^32-1 → null
export function parseSweepTarget(text, { max = 1024 }) -> { kind: 'empty'|'asn'|'addresses', asn, blocks: [{ input, kind: 'cidr'|'range'|'ip', version, label, first, count }],
  addresses /* input order, unique; [] while an error stands */, total, skipped: { private, reserved }, issues: [{ code, severity, params }], ok, label }
  // Tokens split on whitespace / , / ; ('#' comments), after 'AS 64496' / 'ASN 64496' and a range typed with spaces or an en dash ('192.0.2.10 - 192.0.2.20')
  // are joined into one token (two words around a dash only when together they read as a range: '192.0.2.0/24 - 198.51.100.0/24' stays two networks and
  // '192.0.2.1 - 2nd server' keeps its address): IPv4 networks (host bits masked: host-bits info), ranges ('192.0.2.10-192.0.2.50', '192.0.2.10-50'),
  // IPv4 / IPv6 addresses (mapped IPv4 → IPv4, brackets ok), one AS number (alone: asn-many / asn-mixed are errors). An IPv6 network or range is never
  // swept (v6-range warning: 2^64 addresses in a /64, and nothing lists the ones with a reverse record). One block over `max` → too-large (error, params
  // { input, count, max, suggestion, kind, skipped }: `suggestion` = the network's first /22, '' for a range or when that /22 holds nothing to sweep;
  // `skipped` = 'private' / 'reserved' when the whole block is (netinfo.privateRangeOf / 224/3), and then nothing is suggested). `total` counts DISTINCT
  // addresses (overlapping blocks once). Private (netinfo.isPrivateIP) and reserved (224/4, 240/4, ff00::/8) addresses are left out and counted
  // (`skipped`, warnings; IPv4 blocks are intersected with those ranges, never listed, so a pasted list of private /22s costs nothing); the addresses left to
  // look up over `max` → over-cap (error, params { count: those addresses, max }). Nothing left → `nothing` (error). Invalid / reversed tokens are dropped
  // with a warning. `label` names each distinct block once (at most three, then '(+n)').
export function targetTokens(text) -> string[]   // the tokens parseSweepTarget reads (the joins above); linear in the text (a range half is a whole word
  // of at most 64 characters, tried only from its start); stable when joined with ',' — the view's share link and a link's `target` are read with it
export function skipReason(ip) -> 'private'|'reserved'|null ; prefixSize(cidr) -> number|null ; canonicalCidr(cidr) -> string|null ; firstSubnet(cidr, prefix = 22) -> string|null
export function announcedPrefixesUrl(asn) -> string          // §3; TypeError when not an AS number
export function parseAnnouncedPrefixes(json, { asn, max }) -> { asn, prefixes: [{ prefix, version, length, size, current, sweepable, skipped, part }], v4, v6, v4Addresses, sweepable, queryStart, queryEnd }
  // IPv4 first in address order, then IPv6; duplicates merged; `current` = seen until the end of the window; `skipped` = 'private' / 'reserved' when
  // the whole IPv4 prefix is (an AS announcing lab or CGNAT space); `sweepable` = IPv4, ≤ max addresses and not skipped; `part` = the first /22 of a larger
  // public IPv4 prefix (null when that /22 holds nothing to sweep). An error document throws.
export async function announcedPrefixes(asn, { fetchImpl, signal, timeoutMs = 30000 }) -> parseAnnouncedPrefixes()   // ONE GET (one retry on a network error / 5xx); rejects on failure
export function prefixSelection(prefixes, selected, { max }) -> { cidrs, count, addresses, over, max }   // addresses: distinct (a prefix and a more specific one inside it count once)
export function ptrOutcome(response, qname) -> { state: 'names'|'no-ptr'|'nxdomain'|'servfail'|'error', names, rcode, error, delegated /* RFC 2317 CNAME target */ }
export function forwardOutcome(response, name, ip) -> { state: FORWARD_STATES, addresses, rcode, error }   // A for IPv4, AAAA for IPv6, CNAMEs followed
export function fcrdnsVerdict({ ip, ptr, forward, unchecked, resolver }) -> FcrdnsResult     // pure
export async function checkFcrdns(ip, { dns, signal, balance = false, maxNames = 4, noCache }) -> FcrdnsResult
  // PTR, then one forward query per PTR name until one matches (at most maxNames; the rest counted `unchecked`); a PTR value that is no host name is not asked.
  // Never rejects except with AbortError (TypeError for a missing client / not an IP).
FcrdnsResult = { ip, version, query /* reverse name */, status, names, confirmed, forward: [{ name, state, addresses, error }], unchecked, rcode, error, stage: 'ptr'|'forward'|null, delegated, resolver }
  // confirmed: a PTR name resolves back · mismatch: every forward answer is definite and none has the address · no-ptr: NOERROR without PTR ·
  // nxdomain · servfail (the reverse zone) · error: no answer / another rcode (stage 'ptr'), or a forward lookup failed and none matched (stage 'forward')
export function ptrTemplate(name, ip) -> { key, template, kind: 'embedded'|'generic', word }|null
  // embedded: the address written into the name (dashes / dots / underscores, forward or reversed, zero-padded, hex, one decimal number, the last three
  // octets; IPv6 nibbles, groups, the compressed form with '-') → '{ip}'; bounded so it is never part of a longer number. generic: a GENERIC_PTR_WORDS
  // word as a token of its own or with digits after it (dynamic, static, pool, dsl, cable, customer, cpe, cgnat, ftth …: 'dsl-pool-4471', 'dynamic4471'),
  // and left of the registrable domain a number of three digits or more, or two numbers in one label → digits as '{n}'. Names people choose (web10,
  // node-12, and static1, dhcp-01, client2.vpn, cust-web01: a pool word next to one short number) are none.
export function isTemplatedPtr(name, ip) -> boolean
export function sweepClassification(ip, names) -> netinfo.classifyResolution() (+ via 'ptr', reasonKey 'ptr.op.<category>' when a PTR name is under a provider domain)
export async function runPtrSweep(addresses, { dns, signal, concurrency = 12, balance = true, maxNames, noCache, onResult }) -> { results /* address order */, aborted }
  // At most `concurrency` addresses in flight (≤ 64; the DohClient's limiter caps the HTTP requests at its own value); every result streamed with
  // `index`, `template` (of the first PTR name) and `classification`; resolves on abort with the finished results; never rejects on a DNS failure.
export function isFocusName(name, focus) -> boolean
export function sweepRows(results, { focus, collapse = true, minPattern = 2, index }) -> SweepRow[]
  // One row per address, except that addresses whose first PTR name follows one template are one 'pattern' row (≥ minPattern members; a name under
  // the focus domain is never collapsed). Order: ROW_RANKS, then address. SweepRow = { type: 'address'|'pattern', key, rank, sortKey, focus, servers,
  // result? , template?, kind?, members?, counts?, classification? }; `servers` from inventory.lookupServers.
export function sweepResultMatches(result, filter, { focus }) -> boolean   // one address against a SWEEP_FILTERS filter
export function sweepRowMatches(row, filter) -> boolean                     // a pattern row: when one of its members passes
export function sweepRowResults(row, filter, { match }) -> SweepResult[]
  // the addresses a shown row stands for: an address row its address or none, a pattern row only the members that pass the filter and `match` (the
  // view's search) each on its own — what an export of a filtered table writes (one mismatch among eight confirmed names, not the eight)
export function sweepSummary(results, { focus }) -> { done, byStatus, withPtr, noReverse, failed, forwardFailed, templated, patterns, focus, names, v6 }
  // forwardFailed: addresses with PTR names none of which confirmed, where a forward lookup failed (status 'error', stage 'forward')
export function sweepExportRows(results, { focus, index }) -> CSV rows (SWEEP_CSV_COLUMNS)
export function sweepExportJson(results, { exported, filter, target, focus, startedAt, finishedAt, planned, aborted, index, app, version })
  -> { schema: 'domainscope.ptr-sweep/1', app, version, target, focus, startedAt, finishedAt, planned, aborted, filter: { show, search }|null, exported, summary, results }
  // `results` (the argument) = the whole sweep, and `summary` counts it; the file's `results` are `exported` (the rows the table shows, default all), and
  // `filter` records the table's filter (SWEEP_FILTERS) and search text that hid the others (null when nothing was filtered out)
export function sweepNames(results, { focus, templated = false, onlyFocus = false, confirmedOnly = false }) -> string[]   // sortHostnames order
export function inventoryAdditions(results, { servers, index, focus }) -> [{ name, ips }]
  // confirmed, not templated (unless under the focus); neither an address nor a name (or alias) of `servers` (the list they go into; `index` built from it)
export const INVENTORY_GROUP = 'reverse_dns' ; export function inventoryLines(additions) -> string[]   // 'name ip [ip …]'
export function inventoryDraft(base, additions, { label, date }) -> { text: string|null, format /* inventory.inventoryFormat */, reason: null|'format'|'check', group, newGroup, lines }
  // the additions written in the base text's own format: plain lines / empty / a hosts file (`ip name`) under '# reverse DNS sweep of <label> (<date>):
  // forward-confirmed hosts'; Ansible INI: one 'name ansible_host=ip [ips=ip,ip…]' line a host (Ansible keeps one ansible_host; `ips` holds every
  // address, read by this parser and the CLI) under a [reverse_dns] header (a second one when the file has the group, which Ansible
  // merges; `newGroup` false); JSON Lines (a host record alone on one line too): one object per line; a JSON array of objects: one element per host —
  // both with the first record's name / address keys (else name / ip), its addresses as a list when that record holds a list; CSV: a row in the header's
  // column order (name + first address column, no comment row); YAML: an Ansible inventory gets a top-level reverse_dns group, or, when it has one (an
  // earlier addition), the hosts go under that group's `hosts:` wherever it sits (a group whose `hosts:` is a flow value gets reverse_dns_2 …), a list
  // one item per host. `group` = the Ansible group the hosts went into, `newGroup` = the list did not have it. Other shapes (a JSON object that is no
  // host record, another YAML map, a CSV without a name column) → text null, reason 'format'. The text is parsed back: unless its servers are exactly the old
  // ones plus the additions, with no new warning → text null, reason 'check'. The caller then offers `lines` to copy and leaves the editor alone.
  // A base text with CRLF line endings gets its additions with CRLF too.
export function scanHandoff(results, { focus, maxDomains = 5, maxNames = 2000 }) -> { names, domains, moreDomains }   // names under the focus (else all, not templated); the focus, else the most frequent registrable domains
### 5.29 `lib/shellnav.js` — the shell's navigation, first-visit jobs and keyboard shortcuts as data
Pure: no DOM, storage, network, clock or i18n. `app.js` feeds it the view registry (`VIEWS`), storage keys, state changes, key events and element lists (duck-typed objects), and renders and clicks; `ui/start-tasks.js` draws the job cards.
```js
export const NAV_GROUPS = [{ id: 'discover'|'ssl'|'dns'|'ip'|'mail'|'data', labelKey }], OTHER_GROUP = { id: 'other', labelKey: 'nav.groupOther' }
export function groupViews(views, groups = NAV_GROUPS) -> Array<{ id, labelKey, views }>
  // Known groups in table order, registry order inside a group; a missing or unknown `group` lands in a trailing OTHER_GROUP
  // (a new view is never dropped); empty groups are left out. The sidebar and the phone Tools menu both use it.
export const START_TASKS = [{ id: 'subdomains'|'certificate'|'health'|'propagation'|'zone', view }]   // i18n `start.task.<id>`
export function startTasks(views, tasks = START_TASKS) -> Array<{ id, view, icon }>   // jobs whose view exists, with its nav icon
export const RUN_SESSION_KEYS = ['zone', 'currentCert']
export function isRunSignal(stateChange) -> boolean
  // A saved inventory with servers, or a RUN_SESSION_KEYS session value set. (A view going busy is the shell's own signal.)
export const RUN_STORAGE_KEYS = ['ssds.inventory', 'ssds.learned.labels']
export function hasUsedBefore(keys, runKeys = RUN_STORAGE_KEYS) -> boolean
  // One of the keys only a run or a save left before workspaces (saved servers, learned names; §5.39 LEGACY_KEYS): a browser that
  // ran something before the picker existed. The shell reads them before the workspace store moves them into Default, and
  // counts state.migrated too. Remembered view options do not count (a switch flipped on the start page writes them).
export const SHORTCUTS = [{ id: 'submit', keys: ['Mod', 'Enter'] }, { id: 'cancel', keys: ['Esc'] }, { id: 'focus', keys: ['/'] }, { id: 'help', keys: ['?'] }], SHORTCUT_COMMANDS
export function isApplePlatform(platform) -> boolean ; export function keyCaps(keys, { apple }) -> string[]   // 'Mod' → '⌘' / 'Ctrl'
export function isTypingTarget(target) -> boolean   // text-like input, textarea, select, contenteditable
export function isFormField(target) -> boolean      // any input, textarea, select
export function escClearsField(target) -> boolean   // a search field with text: Esc clears it there, not a shortcut
export function isSearchClear(event) -> boolean     // a plain Esc (no modifier, repeat or IME) in such a field: the shell clears it
export function shortcutFor(event) -> 'submit'|'cancel'|'focus'|'help'|null
  // submit: Ctrl+Enter / ⌘+Enter (no Alt / Shift) in a form field; cancel: Esc anywhere, fields included, but not in a search
  // field with text (escClearsField); focus '/' and help '?': only outside typing targets, Shift and AltGr (Ctrl+Alt) allowed,
  // Ctrl / Alt / ⌘ alone not. Auto-repeat and IME composition: null.
export function pickShortcutTarget({ candidates, scopes, contains, usable, strict, from, localOf }) -> candidate|null
  // With `localOf` (submit), only the candidates of the focused element's (`from`) own form: localOf(node) is the sub-form
  // (`data-shortcut-scope` container: a paste box, a host name lookup, a results area) a node is in, null for the view's own
  // form — a paste box's Read answers the paste box, the view's Run every other field, and a sub-form without a submit (a
  // view's results, a DataTable) nothing. Then scopes nearest first (`from`'s ancestors, then the view's root); the first
  // scope holding a candidate decides: its first usable one; with `strict` (submit) null when all of them are unusable (a run
  // in progress) — another form's button never stands in; otherwise (cancel) the search goes on.
export function isPlainClick(event) -> boolean   // main button, no Ctrl / ⌘ / Shift / Alt: the app's; any other click the browser's
```

### 5.30 `lib/session.js` — the page session: the current target and each tool's kept result
Pure and memory-only (no DOM, storage or network; the shell, app.js, owns the one store as `pageSession` and clears it on the `'cleared'` state event, i.e. "Delete all local data" — the tools with module state drop theirs on the same event, and the tool on screen opens again on its bare route — and on `'workspace'`, a switch to another workspace, after which the new workspace's most recent domain becomes the target and the tool on screen opens again with it filled in, §5.39). The current target is the domain, host name or IP address the user last worked on; the nav links carry it into the other tools, filled in and never run. Each tool keeps its last finished result for the page session.
```js
export const TARGET_KINDS = ['domain', 'host', 'ip'], FILL_PARAM = 'run', FILL_VALUE = '0', DEFAULT_LIMITS = { entryBytes: 4 MiB, totalBytes: 16 MiB }
export const TARGET_ROUTES = { subdomains: { param: 'domain', kinds: ['domain','host'] }, scan: same, cert: { param: 'host', … }, global: { param: 'name', kinds: ['domain','host'] },
  lookup: { param: 'name', kinds: ['domain','host','ip'] }, bulk: { param: 'names', … }, ip: { param: 'ips', kinds: ['ip'] }, health: { param: 'domain', … } }
  // The views' existing main-input params. Zone File, Servers and About take none; the Zone File view never sets one either (nothing about a zone reaches a URL).
export function parseTarget(input) -> { value, kind } | null
  // normalizeIP (also an address written with a port or as a URL: `192.0.2.1:443`, `[2001:db8::1]:443`, `http://192.0.2.1/`), else
  // normalizeHostname (URL, port, trailing dot, `*.`, IDN); service labels are dropped (`_dmarc.example.com` → example.com,
  // `_443._tcp.www.example.com` → www.example.com); public suffixes, single labels, `.arpa` names, address ranges and other junk → null.
  // kind 'domain' = registrable.
export function commonTarget(values) -> { value, kind } | null   // a list's only entry, or the registrable domain every name shares; several things → null
export function targetFits(view, target) -> boolean ; fillRoute(view, target) -> { [param]: value, run: '0' } | null ; isFillOnly(params) -> params.run === '0'
export function fillReplaces(text, lastRun, entries, carried = null) -> boolean
  // may a carried target replace a box's text: only an empty box or one that still holds exactly the tool's last run or the text it last took from a
  // carried target (`carried`; entries in any order), never a draft. So the box follows every newer target, not only the first, until the user types in
  // it; each tool remembers `carried` (module state, or its snapshot) until its next run and forgets it on 'cleared'.
export function backToLastRun(text, carried, lastRun, entries) -> boolean
  // a route without a target into a tool that keeps its own state (its nav link back to the kept result): the box goes back to the last finished
  // run's query when it still holds exactly the target it last took from a carry (A, then B, then A again leaves B there otherwise), never over a draft.
export function routeKey(params) -> string   // order-independent, without `run`; '' for a bare route
export function targetSupersedes(target, kept) -> boolean   // the target was set after the result was kept (target.at > kept.at) and is about something else
export function carryRoute(view, { kept, target }) -> params
  // a kept result: its own params + run=0 (bare for a tool that keeps its own state), unless a superseding target fits the tool;
  // else fillRoute(target); else {}. Checking A across the tools, then B, fills B in everywhere, and each tool still shows A's result under B (restorePlan 'carry').
export function restorePlan(params, kept) -> 'restore' | 'carry' | 'dropped' | null
  // a bare route or the kept result's own params (routeKey) bring it back ('restore': the URL shows those params with run=0); a route that only fills the
  // form with something else (run=0, a carried target) brings it back too ('carry': the URL and the box keep the target); 'dropped': too large to keep,
  // the query comes back filled in (run=0) on a bare route or its own params, and a carried target is only filled in (null); any other params: null
export function normalizeResult(res) -> { subject, at: Date, params, rerun, label } | null
  // params: the result's own route params (strings, no run) or null; rerun: res.rerun !== false; label: a translation key for the note's text (with {time}) or null for "Result from {time}"
export function keptNote({ note, plan, kept, result, mountedAt, restorable }) -> { at, dropped, rerun, label } | null
  // the header note after a mount: a language re-mount keeps its note; 'dropped' says so (rerun true only when the kept params bring its query back:
  // IP Intel over 40 entries has none, so the tool opens empty and the note's title says so); a result older than the mount gets one — for a
  // tool without snapshot() (`restorable` false) only the one the shell kept when it was left (kept.at === result.at), never one loaded elsewhere;
  // a fresh mount none
export function estimateSize(value, limit = Infinity) -> number   // rough bytes (UTF-16 strings, 8-byte numbers, buffers, cycles once); stops past `limit`
export function createSessionStore({ now, entryBytes, totalBytes, estimate }) -> {
  target, setTarget(input, { view }) -> target|null, clearTarget() -> boolean,
  keep(view, { params, subject, at, snapshot }) -> KeptResult, kept(view) -> KeptResult|null, drop(view), clear(), usage() -> { entries, bytes },
  subscribe(fn({ type: 'target'|'kept'|'cleared', view })) -> unsubscribe }
  // KeptResult { view, params (no run), subject, at, snapshot, size, dropped }: one per tool (a new one replaces it; kept order = eviction order: a
  // new result goes last, the same result kept again — same at and params, its tool left once more — keeps its place); a snapshot over entryBytes
  // is not kept (dropped: true); past totalBytes the oldest results' snapshots are dropped first. kept() returns a copy whose snapshot is shared.
```
View contract (optional exports, read by app.js): `result()` → `{ subject, at, params?, rerun?, label? }` of the finished result on screen (null while nothing has finished or a run is going: a run in flight is not a result, so the one kept before stays; `rerun: false` when the note should offer no "Run again" — Global DNS, whose page header has Re-run, and a certificate file; `label` when "Result from <time>" would not say which result it is — the Zone File's `'zone.live.kept'`, "Live check from <time>", since its other tabs show the file; `params`: the result's own route params — the query it ran, which may differ from the URL, whose params say what the box holds); `rerun()` → "Run again" of the note (Subdomains exports none: its page header has Re-run); `snapshot()` as before (language re-mount), now also kept on leave. `ctx.runStarted(subject)` reports a run (or a certificate load in the Certificate view): `subject` becomes the target, the nav links follow (the store tells its subscribers only a new value; the same target again is still newer than the other tools' kept results) and the note goes away. `ctx.resultChanged()` removes the note when the result on screen is replaced or dropped without a run (the Zone File's new import or analysis and Forget). A "Run again" that may end without a new result (the Certificate view's CT lookup finding nothing or failing) leaves the note until the new result arrives. A view with `snapshot()` is kept with the result's own params (`result().params`, else its route params) and gets the snapshot back as `ctx.restored`: on a bare route or those params the URL then shows them with `run=0` (`ctx.shareUrl()` drops the marker); under a carried target (`'carry'`) the URL keeps the target and the view's box takes it when it is empty or still holds the result's query or the target it took before (the snapshot keeps it as `carried`; never a draft), the result showing under it. Such a view's Copy link shares the result's params, not the box's, and "Run again" puts the result's query back into the form first; a view that keeps its own module state (Subdomains, SSL Targets, Bulk Resolve, Certificate, Zone File) is kept as a fact only (its nav link opens it bare; a box that holds only a target carried since goes back to the last run's query then — `backToLastRun`, like a snapshot view's 'restore') and forgets that state itself on `'cleared'`. The shell keeps nothing on the way out after "Delete all local data" and opens the tool on screen again on its bare route. Tests: `tests/js/session.test.js`, `tests/e2e/carry.e2e.mjs` (and the kept live check in `zone.e2e.mjs`, the kept CT certificate's Run again in `cert.e2e.mjs`).
### 5.31 `lib/subtabs.js` — the Subdomains results tabs as data
Pure: no DOM, storage, network, clock or i18n; `views/subdomains.js` turns the results into tabs, badges, alerts and text runs.
```js
export const SUB_TABS = ['overview', 'hosts', 'origins', 'sources'], MAX_KEPT_LABEL = 32
export function parseSubTab(value) -> string|null            // a SUB_TABS id from the route's `tab=`, else null
export function autoSubTab({ hosts, running }) -> 'hosts'|'sources'|'overview'
  // The tab while nobody chose one: Hosts once a host is listed; before that Sources while the run is live
  // (its stage pills and source chips are the progress), Overview once it ended (it says why nothing was found).
export function initialSubTab({ route, chosen, hosts, running }) -> { tab, chosen: boolean }
  // A (re-)mounted run: the route's tab, then the tab chosen earlier in the page session, else autoSubTab (chosen: false).
export function subTabParams(tab, { named, domains }) -> { domain?, tab? }
  // What a picked tab merges into the route: `tab`, plus `domain` (the run's domains, comma-joined) when the route
  // names none (`named` false: a return through the nav link), so `tab=` never stands alone; {} for an unknown tab.
export function nextAutoTab(current, { chosen, focusInside, hosts, running }) -> string|null
  // Where an automatic choice moves while the run streams (first host, empty end), null to stay; never a chosen
  // tab, never while the keyboard focus is inside the tabs (hiding its panel would drop the focus).
export function summaryAlerts({ status, counts: { found, dangling, cloudflare }, failedSources, wildcards, warnings })
  -> Array<{ key, variant: 'info'|'warn'|'error', count?, list?, detail? }>
  // The Overview's alerts in order: 'none' (a finished run found nothing), 'sources-failed', 'dangling' (error),
  // 'cloudflare', 'wildcard', then each scanner warning (key = its code, detail as a string); [] while running.
export function subTabBadges({ found, running, proxied, sources, health, alerts }) -> { overview, hosts, origins, sources }
  // Each { value, variant: 'ok'|'warn'|'error'|null } or null (no badge). overview: the warn + error alerts (error
  // when one is); hosts: the Found count (none while a live run has none); origins: hosts whose origin a proxy hides
  // (warn); sources: `worked/asked` from sourceHealthSummary (error when one failed, warn when one is limited or
  // incomplete, ok when every one worked; a cancelled request is neither; null when no source was asked).
export function hostSegments(name, { maxLabel = 32 }) -> Array<{ text, keep }>
  // A host name cut after each dot (a label with its dot; a stray dot stays with the next label); joined, the
  // segments are the name. keep: draw as one unbreakable run — a label longer than maxLabel stays breakable.
```

### 5.32 `lib/summary.js` — "Copy summary" for Jira / Slack
DOM-free and dependency-light (only `netinfo.js`), since every view with a result loads it. Texts come from an injected `t(key, params)` (i18n.js `t`): the `sum.*` keys of `SUMMARY_I18N` (EN / TR, registered by `ui/summary-button.js`), the shell's `nav.<view>`, `severity.*`, `kind.*`, `common.moreCount`, and the keys a fact carries (a health check's `titleKey`, a Verify headline key of `lib/verify.verifyHeadline`).
```js
export function buildSummary(kind /* SUMMARY_KINDS */, facts, { t, lang = 'en', url = null, now = new Date() }) -> SummaryDoc   // RangeError for another view, TypeError without t
export function healthSummary({ report }, opts)            // lib/health report: verdict + score, counts, errors then warnings (≤ 5, then "+N more")
export function globalSummary({ name, type, verdict /* propagationVerdict */, total, answered, failed, cancelled, addresses, at /* when the check ended */ }, opts)   // verdict worded like glb.sum.*Title, answers from how many sources (none answered: only how many failed), operators, ≤ 3 findings
export function subdomainsSummary({ domains, status, counts /* views/subdomains countHosts */, proxied, withCandidates, networks, dangling: string[], failedSources, at }, opts)   // facts: views/subdomains subdomainsSummaryFacts(run);
                                                   // a cancelled run: proxied counted from the hosts found, no candidates / networks, never "no proxied host" or "no dangling CNAME"
export function scanSummary({ domains, cert: { name, issuer, notBefore, notAfter }|null, hosts, covered, failedSources, inventory, needsCert: string[] /* inventory server names */, matched, hiddenOrigin, networks, verify: { key, params }|null, dangling: string[], at }, opts)   // a finished scan (a cancelled one keeps no result);
                                                   // the title names the scanned domains (the certificate is line 1); failedSources: the passive sources that failed, not
                                                   // cancelled (as the results warning counts them), said right under the host count: the host list may be incomplete
export function zoneSummary({ origin, format, counts /* views/zone zoneCounts */, problems: [{ severity, key, params } | { severity, title }] }, opts)   // + "the zone file stays in this browser"
export function certSummary({ name, issuer, dnsNames, notBefore, notAfter, warnings /* CERT_SUMMARY_WARNINGS */, source }, opts)   // + "the certificate file stays in this browser"
export function lookupSummary({ name, ptrFor, types, responses /* DnsResponse in types order */, dnssec, at /* the last answer */ }, opts)   // one line: per type the values (≤ 3 records) or a count / rcode, AD when asked
export function ipSummary({ rows /* views/ip rows */, at /* when the lookup ended */, stopped }, opts)   // one line: one address's AS, place, PTR, operator; or counts (CDN, private, in the server list, networks, countries); never a server name;
                                                   // a failed lookup (info.error: every source failed or was rate-limited; a row a finished lookup left without info): "lookup failed" /
                                                   // "N lookups failed"; a stopped lookup: how many addresses were not looked up (the rows without data); "no network data" only
                                                   // for an address that was looked up and answered
SummaryDoc = { kind, title: Part[], lines: Part[][], inline: boolean /* one line after the title */, footer: { when /* 'checked 2026-09-27 14:03 UTC' */, url } }
Part = string /* Markdown-escaped */ | { code: string } /* an untrusted value: a code span */ | { strong: string }
export function renderMarkdown(doc) / renderPlainText(doc) / renderSummary(doc, 'markdown'|'text') -> string   // "**title**", "- line"…, "DomainScope · <when> · <url>"; trailing newline;
                                                   // Markdown puts an empty line before the footer (CommonMark would continue the last item with it); plain text does not
export function permalinkParams(view, params, { exclude = [] } = {}) -> Record<string, string>   // PERMALINK_PARAMS keys only, never an empty value; zone / cert: none; ip: host names and
                                                                                                   // public addresses not in `exclude` (inventory addresses)
export function healthScore(summary) / trafficLight(summary)   // 100 − 20 per error − 6 per warning (0…100); 'error' | 'warn' | 'ok' (views/health re-exports both)
export function cleanText(v) / mdEscape(v) / mdCode(v) / utcStamp(date)   // control + bidi characters out; \ ` * [ ] < > ~ | escaped, `_` unless between letters / digits; code span ≤ 96 chars, ` → '; 'YYYY-MM-DD HH:MM UTC'
export const SUMMARY_KINDS, SUMMARY_FORMATS, PERMALINK_PARAMS, CERT_SUMMARY_WARNINGS = ['SELF_SIGNED', 'CA', 'NO_SAN', 'PRECERT', 'WEAK'], SUMMARY_I18N
```
A summary is 5–12 lines (title and footer included, Markdown's empty line before the footer not counted) — DNS Lookup and IP Intel are one line plus the footer — and holds only what the result on screen shows. It never reads an absence from an incomplete result: a cancelled Subdomains scan and a stopped Global DNS check or IP Intel lookup say what they got and what was left out, and what failed at a third party is said too (Global DNS: the sources that failed; Subdomains and SSL Targets: the passive sources that failed — "the list may be incomplete"; DNS Lookup: "lookup failed" per type; IP Intel: the failed lookups, rate limits included). The inventory data in it: SSL Targets names the servers that need the certificate, as its Servers tab lists them, and IP Intel says whether (or how many of) its addresses are in the server list, never a name; each button's tooltip says so. The permalink is the shareable route of the result being summarised, built from that result (`ctx.shareUrl(permalinkParams(view, <the result's own params>))`), never from the current route, which a new run changes before its result replaces the one on screen; it never carries inventory data or a file's contents. The timestamp is the result's own time ("checked" / "scanned": a health check, a scan, the end of a Global DNS check, a DNS Lookup's last answer, the end of an IP Intel lookup); Zone File and Certificate say "as of" the copy time. Untrusted values are code spans — host names and domains (titles included), record data, certificate names and issuers, server names, an IP Intel network's AS name and place, and the names and file lines a problem quotes (a problem given as `{ key, params }` is translated with its string params as code spans, its numbers as text) — so no mention (`@here`, `<!channel>`), link or formatting survives a paste into Slack or Jira.

### 5.33 `lib/scanplan.js` — the engine's plan, without the engine
Pure (no DOM, no I/O, no DoH client: `tests/js/start-route.test.js` keeps it off `doh.js`, `sources.js` and the other heavy modules). The Subdomains view is the start route: it shows the plan line and stage names before any scan, so these come from here and `lib/scanner.js` loads only when Start is pressed.
```js
export const SCAN_STAGES = ['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints', 'done']
export const HOST_SPECIFIC_HINT_KINDS = Set(['history', 'resolver-leak', 'sibling-domain', 'zone'])
export function estimateQueries(opts) -> { min, max, breakdown }            // §5.12 (unchanged contract)
export function learnedLabelsFromScan(result) -> string[]                    // §5.6 / §5.12 (unchanged contract)
// Shared with lib/scanner.js, declared once: MAX_BRUTEFORCE_PER_BASE, LEGACY_MAX_BRUTEFORCE, MAX_BRUTEFORCE_TOTAL, MAX_PERMUTATIONS,
// DEFAULT_PERMUTATION_BUDGET, DEFAULT_RECURSIVE_PARENTS, RESOLVER_LEAK_MAX_QUERIES, RECURSIVE_EXTRA_WORDS, RECURSIVE_MAX,
// MAX_SPF_LOOKUPS, MAX_MX, MINE_QUERIES_PER_DOMAIN, WILDCARD_QUERIES_PER_PARENT, KNOWN_LEVELS, PROBE_ORIGINS, CORE_LABELS, leftmostLabels
```

### 5.34 `lib/sourceinfo.js` — the passive sources, without the fetchers
Pure. `SOURCES`, `SourceQuota`, `sourceQuota(id, opts)`, `SOURCE_HEALTH_STATES` and `sourceHealthSummary(results)` exactly as in §5.11, plus `buildQuota(id, { limited, err, rate })` for `lib/sources.js`. The views and `lib/ctcert.js` import from here; `lib/sources.js` re-exports all of it.

### 5.35 `lib/pwa.js`, `sw.js`, `ui/pwa.js` — the installable app
**`lib/pwa.js`** (pure; used by the page, by `tools/assemble-site.mjs` and by the tests):
```js
export const CACHE_PREFIX = 'domainscope-', SERVICE_WORKER_FILE = 'sw.js'
export const MANIFEST_FILES = { en: 'manifest.webmanifest', tr: 'manifest.tr.webmanifest' }, UPDATE_CHECK_MS = 3600000
export const PRECACHE_SKIP = ['data/README.md', 'data/wordlist-manifest.json']      // under assets/, never requested by the app
export function scopeTag(scopePath) -> 8 hex digits                                // FNV-1a (32 bits) of the scope's path
export function cacheNames(scopePath, build = null) -> {
  prefix: 'domainscope-<tag>-',       // every cache of the worker at that scope; it deletes nothing else
  wordlists: '<prefix>wordlists',     // shared by the scope's deploys (entries keyed by content hash)
  shell: '<prefix>shell-<version>-<first 12 hex of build.digest>' | null
}   // per scope: GitHub Pages project sites share <user>.github.io, and two copies of the app there must not delete each
    // other's caches; sw.js has the same two functions (tests/js/sw.test.js holds them equal)
export function bundleInfo(moduleUrl) -> { root, version, assets, serviceWorker } | null
  // a module of the Pages bundle (…/v/<version>/assets/js/…): the site root and sw.js next to it; null in the repository
  // (`npm run serve`) and for anything else — development never runs behind a cache
export function wordlistCacheKey(sha256, file) -> 'wordlists/<sha256>/<file name>'    // relative to the worker's scope
export function wordlistFiles(wordlistManifest) -> Array<{ file, sha256 }>           // tier files, then locale/<cc>.txt
export function buildSwManifest({ version, digest, rootFiles, assetFiles, wordlistManifest }) -> {
  version, digest,                    // digest: tools/assemble-site.mjs contentDigest; with the version it names the shell cache
  precache: string[],                 // './' (index.html) first, the other root files the page loads (favicon, manifests), then every file of
                                      // v/<version>/assets/ except the wordlists and PRECACHE_SKIP — every view opens offline
  wordlists: { [path]: cacheKey }     // v/<version>/assets/data/<tier or locale/cc.txt> → wordlistCacheKey
}   // throws on an invalid version or digest, a wordlist without a SHA-256, a listed one missing from assets/data/, or a wordlist-like
    // file the manifest does not list. No cache names: they depend on the scope, which only the worker knows
export function manifestFor(lang) -> MANIFEST_FILES.tr for 'tr', else MANIFEST_FILES.en
export function updateCheckDue(lastCheckAt, now, everyMs = UPDATE_CHECK_MS) -> boolean
```
**`sw.js`** (a classic script at the site root; data-driven: `tools/assemble-site.mjs` writes `buildSwManifest()` into its `const BUILD = null;` line, and checks every wordlist's SHA-256 against its file first). A browser installs a new worker only when `sw.js` changes byte for byte — until then the installed one answers from its cache — so a bundle's identity is its content: `contentDigest` (SHA-256 over the path and SHA-256 of each precached file as in the repository, and of `sw.js`; not the CLI or the PNG icons) goes into BUILD and the shell cache's name, so any change to those files gives a new `sw.js` and a new cache even under a version used before, and a bundle assembled without a version (no `GITHUB_SHA`: a local preview, a manual deploy) is `dev-<first 12 hex of the digest>`, so its `v/<version>/` URLs change too. Caches are `cacheNames(<scope path>, BUILD)`. In the bundle: **install** fetches every `precache` path into the shell cache — the site-root files past the HTTP cache (`cache: 'reload'`), the `v/<version>/` files (immutable at their URL) through it, so what the page has just downloaded is not fetched twice — and fails when `./` is not this version's index.html yet (a CDN still serving the previous one; the browser retries at its next update check); **activate** deletes this scope's other caches (its `prefix`: earlier versions and builds) and the wordlist entries this version does not list, then claims the open pages; **fetch** handles same-origin GETs inside the scope only — a navigation to the site root or index.html (whatever its query) gets the cached index.html, a `precache` path the cache (else the network, not stored), a `wordlists` path the entry under its hash key (else the network, stored when it is a 200); everything else — third-party APIs, a query string, HEAD (the shell's "is my version still there?" probe) or POST, another version's or another site's files — is not intercepted and never cached; **message** `{ type: 'skip-waiting' }` activates a waiting version. In the repository (BUILD null) it answers nothing; replacing a deployed worker (a checkout served on the origin a bundle was previewed on) it skips waiting and deletes that scope's caches, so the next load is the checkout.
**`ui/pwa.js`**: `registerServiceWorker({ moduleUrl, nav, win, notify })` registers `bundleInfo().serviceWorker` with the site root as scope — only from the Pages bundle, in a secure context, once the first view is up and the browser is idle (app.js), and not when `navigator.connection.saveData` is set and no version controls the page yet (the offline copy is about 0.9 MB gzip in 76 files, of which the start route has already loaded about 0.26 MB); a refused registration is a console warning, never an app error. A version that installs while another controls the page shows the toast **"Update ready — Reload"** (`pwa.updateReady` / `pwa.reload`, `data-toast="pwa-update"`, no timeout, re-shown in the new language on a language switch; a first install says nothing). With several tabs open, the one whose Reload activates the new version reloads; the new worker also takes over the other tabs and deletes their version's cache (views they have not opened yet would then fail offline and be stale online), so a `controllerchange` the page did not ask for — and that is not a first install claiming it — shows the same toast there, whose Reload is then a plain reload into the version in control. `reloadPage()` — the toast's button and the shell's "Reload page" offers — lets the new version take over first, because a plain reload would be answered from the old worker's cache: a waiting or installing worker, else one the browser is asked for now (`registration.update()`; up to 15 s for its install); it posts `skip-waiting` and reloads on `controllerchange` (after 3 s at the latest). Without a newer version, or without a worker, it is a plain reload. While it waits for the download a status toast says so (`pwa.loading`; the "Reload page" button of a view that failed to load turns busy), and a call while one is under way joins it. An open page calls `registration.update()` when it becomes visible or comes back online, at most hourly (a hash-routed app never navigates). `setManifestLang(lang)` switches `<link rel="manifest">` (boot.js does it before the first paint).
**Web app manifests** (`manifest.webmanifest`, `manifest.tr.webmanifest`): the same `start_url` and `scope` (`./`: the directory the manifest is served from, `/<repo>/` on a Pages project site) and no `id`, so the app's identity is its start_url — `<origin>/<repo>/`, a fork's own path (an `id` is resolved against the origin, not the manifest: `"./"` would make the origin root the identity of every app on it, and an installed app's id cannot change later), `display: standalone`, the light theme's colours (index.html's `theme-color` metas follow light / dark at run time and colour an installed window), `favicon.svg` plus the PNG icons (192, 512, maskable 512), and shortcuts to Subdomains, Certificate, Zone File and Servers; names, description and shortcut names in the manifest's language (`tests/js/pwa.test.js` checks them against the nav strings and `VIEWS[].offline`).

### 5.36 `lib/sourcestatus.js` — no silent dashes
When a third-party source answers 429 or fails, the fields it would have filled stay empty, and an empty cell reads as "no data". This module turns a failure into a status that `ui/source-status.js` renders as "⚠ n/a" with the source and the reason, and says which empty fields a failure explains, so a Retry asks exactly that source again. Pure: no DOM, network, storage or i18n (reasons are codes, `srcst.reason.<code>` in the UI); the clock is injectable.
```js
export const STATUS_SOURCES = { ripestat, 'ripestat-geo', ipwhois, ptr, hackertarget, rdap, doh }   // each { period: 'day'|'minutes'|null }: how long a rate limit
  // of the service usually lasts when it does not say itself (a browser reads Retry-After only when the service exposes it to CORS)
export const STATUS_REASONS = ['rate-limit-wait', 'rate-limit-now', 'rate-limit-day', 'rate-limit-minutes', 'rate-limit', 'timeout', 'network', 'unavailable', 'http-status', 'http', 'rcode', 'parse', 'unknown']
export function sourceStatus({ source, error, errorKind, status, retryAfterMs, limited, rcode, at }, { now }) -> SourceStatus
SourceStatus = { source, kind: 'rate-limit'|'timeout'|'network'|'unavailable'|'http'|'rcode'|'parse'|'unknown', reason, params /* { minutes } | { status } | { rcode } */, retryAt: Date|null, detail /* the technical message */ }
  // `rcode`: a DNS lookup answered but not usable (a reverse lookup's SERVFAIL / REFUSED, `ptr(ip, { throwOnError })`) → 'rcode', "answered SERVFAIL"
  // (a broken reverse delegation answers that every time; a bare "failed" would say less)
  // A 429 (status, 'HTTP 429' in the message, errorKind 'rate-limit' or `limited`) is a rate limit: with a Retry-After, "try again in N min" counted
  // from the failure (`at`) and rounded up (never "in 0 min"; once it has run out, 'rate-limit-now'); without one, the service's period
  // ('rate-limit-day' for HackerTarget, 'rate-limit-minutes' for RIPEstat, RDAP, DoH, reverse DNS; 'rate-limit' = "later" for ipwho.is).
export const IP_FIELD_SOURCES = { ptr: ['ptr'], network: ['ripestat', 'ipwhois'], prefix: ['ripestat'], location: ['ripestat-geo', 'ipwhois'] }, IP_FIELDS
export function ipFieldStatus(info /* IpInfo */, field, { now }) -> { field, sources, statuses } | null
  // null when the field has a value, when nothing that feeds it failed (a real "none", e.g. no PTR record), for a private address or a pending row;
  // a failure another source made up for (ipwho.is found the country RIPEstat's geo dataset could not) is not shown
export function ipRetrySources(info) -> string[]   // what a row's Retry asks: every source whose failure left a field empty
export const IP_SOURCE_GROUPS = { ripestat: ['ripestat', 'ripestat-geo'], ipwhois: ['ipwhois'], ptr: ['ptr'] }
export function ipSourceChips(rows /* [{ ip, info, pending }] */, { now }) -> Array<{ id, state: 'pending'|'ok'|'idle'|'failed', rows, failed, ips, sources, status }>
  // one chip per service (the Subdomains source-chip pattern): 'idle' = never needed (the ipwho.is fallback), 'failed' = where its failure left a field
  // empty (`ips`, the `sources` a chip Retry asks, the most recent failure's `status`); 'pending' only while a row is still looked up (`pending`) —
  // a row a stopped run never asked (no info, not pending) counts for nothing
export function sourceGroupOf(source) -> string|null   // IpInfo.sources / errors id → chip id ('dns' → 'ptr')
export function rdapStatus(rdap) -> SourceStatus|null  // Domain Health's RDAP card: null for an answer, a TLD without RDAP, an unregistered domain or bad input
export function dohStatus(response) -> SourceStatus|null   // DNS Lookup: a query that got no DNS answer (an rcode is an answer)
```

### 5.37 `lib/density.js` — compact result layouts
Pure: no DOM, network, clock or i18n.
```js
export const LOOKUP_FLAGS = ['aa', 'tc', 'rd', 'ra', 'ad', 'cd']
export function isNoData(response) -> boolean   // NOERROR with an empty answer section (no record of the type, no alias chain) and no Extended DNS Error
export function lookupLayout(types, responses /* DnsResponse|null per type */) -> {
  cards: string[],      // types that keep a card, in query order: pending, records or an alias chain, an error rcode, a failed query
  noRecords: string[],  // plain NODATA types: one "No records: AAAA, CAA, …" line of the summary instead of a card each
  failed: string[], pending: string[],
  shared: { resolver, nsid, flags: Record<flag, boolean>|null },   // what every DNS answer has in common, said once in the summary (null where they differ)
  own: { [type]: { resolver, nsid, flags } }                        // per card with a DNS answer: what it shows itself because it differs
}
export function foldZeroStats(stats /* [{ id, value }] */, { foldable }) -> { shown: string[], folded: string[] }   // zero counts of `foldable` ids fold into one sentence
```

### 5.38 `lib/jobprogress.js` — a long job's progress outside its view
A Subdomains / SSL Targets scan or a Bulk Resolve run takes minutes, and the user is often elsewhere meanwhile. `ui/jobs.js` shows its progress as a "(62%)" prefix of the tab title, a ring on the running view's navigation entry and a badge on the favicon, and can send a desktop notification when a long job ends. Pure: no DOM, clock, storage or i18n.
```js
export const LONG_JOB_MS = 30000
export const SCAN_STAGE_WEIGHTS = { sources: 10, mining: 0, wildcard: 5, bruteforce: 45, permutations: 20, resolve: 15, hints: 5, done: 0 }   // keys = scanner.SCAN_STAGES
export const ACTIVE_STAGE_CAP = 0.95
export function scanFraction(run /* { stages, progress } as applyStage / applyProgress record them */) -> number|null   // null before the first stage; skipped stages drop out;
  // an active (or stopped) stage counts for its done / total up to ACTIVE_STAGE_CAP of its weight — a stage whose counter is complete can keep running
  // (brute force waits for the passive sources), and one that reads as complete while the job does not move on looks like a hang
export function bulkFraction(job /* { names, done, ipTotal, ipDone, options } */) -> number|null   // names resolved; a quarter for PTR / ASN lookups when asked
export function advance(prev, next) -> number|null   // never below the last value (a stage's total can grow: the scan's recursive round)
export function combineJobs(jobs) -> { count, fraction }   // the least advanced determinate job, null when none is
export function percentOf(fraction) -> number|null        // whole percent, never 100 while running
export function progressTitle(base, label) -> '(62%) Subdomains · DomainScope'   // label null → '(…)'
export function faviconStep(fraction, { reducedMotion }) -> number|null   // 5 % steps, 10 % with reduced motion; never full
export const BRAND_ICON_SVG   // favicon.svg (tests/js/jobprogress.test.js keeps them equal)
export function badgedIcon(fraction, { svg }) -> string    // the icon with a white disc and a green pie in its corner (a dot when not known)
export function svgDataUrl(svg) -> 'data:image/svg+xml,…'  // the CSP allows img-src data:, which covers the favicon
export function pageNotifications({ api, userAgentData, userAgent }) -> boolean   // `new Notification()` usable: not Chromium on Android, tablets included (userAgentData.platform, else the UA string)
export function offerNotify({ elapsedMs, supported, permission, optedIn }) -> boolean   // "Notify me when done" once a job has run LONG_JOB_MS (or the session opted in)
export function shouldNotify({ optedIn, permission, status, durationMs, watching }) -> boolean   // opted in, granted, done or failed (never a cancel), ≥ LONG_JOB_MS, not watched
```

### 5.39 `lib/workspace.js` — customer workspaces
An engineer serving many customers keeps each one's data apart: the inventory (no DUPLICATE_IP across customers), the learned names (never tried under another customer's domains), the custom wordlist, the expected CAs (§5.42), free-text notes and the domains worked on. Settings about the tool (theme, language, resolvers, parallelism) stay global (`state.js`, localStorage). DOM-free and storage-injected: the persistence is an async key-value `WorkspaceBackend` — IndexedDB in the browser (`assets/js/workspace-db.js`, database `ssds.workspaces`, one object store `records`), memory in the tests and where the browser refuses storage. The store keeps the active workspace in memory, so the views read it synchronously; every change is written through.
```js
export const DEFAULT_WORKSPACE_ID = 'default'   // always there; cannot be renamed or deleted (its name is null: the UI says "Default" / "Varsayılan")
export const WORKSPACE_PARTS = ['inventory', 'learned', 'wordlist', 'expectedCas', 'notes', 'recent']
export const WORKSPACE_LIMITS = { count: 100, name: 60, notes: 20000, recent: 20, expectedCas: 30, expectedCa: 120, learned: 5000, inventory: 16 MiB, wordlist: 8 MiB }
export const ACTIVE_WORKSPACE_KEY = 'ssds.workspace'   // the localStorage pointer to the active id: where a new page starts (tabs are independent)
export const LEGACY_KEYS = { inventory: 'ssds.inventory', learned: 'ssds.learned.labels', wordlist: 'ssds.wordlist.custom' }   // before workspaces (the last one in sessionStorage)
export class WorkspaceError { code: 'name-empty'|'name-taken'|'default'|'not-found'|'limit'|'part' }
export function normalizeWorkspaceName(input) -> string          // NFC, controls / zero-width / bidi overrides out, whitespace collapsed, ≤ 60 characters; '' when nothing is left
export function uniqueWorkspaceName(name, taken) -> string       // 'Acme' → 'Acme (2)' → 'Acme (3)' (case-insensitive; a trailing " (n)" is not doubled)
export function sanitizePart(part, value) -> value               // inventory { text, updatedAt } | null · learned { v: 1, seq, labels: { label: [hits, last] } } | null (isStorableLabel only) ·
  // wordlist string · expectedCas string[] (one per line / entry, de-duplicated without case) · notes string · recent [{ value, at }] (lib/session parseTarget: domains / host names only)
export function sanitizeWorkspaceData(data) ; emptyWorkspaceData() ; sanitizeExpectedCas(value) ; sanitizeRecent(value)
export function addRecent(list, value, at) -> list               // to the top; the top entry again changes nothing; IPs and junk never enter
export function readLegacyData({ local, session }) -> { data, present: [{ area, key }] }   // reads only
export function createMemoryBackend(entries?, { persistent = false, exists }) -> WorkspaceBackend & { entries(), fail: Set }   // `fail`: tests make operations reject
export function createWorkspaceStore({ backend, pointer, legacy, channel, now, newId }) -> {
  open() -> Promise<{ active, list, migrated: string[], persistent }>, persistent, lastError, active, data, list(),
  save(part, value) -> Promise<boolean>, recordRecent(value, at?), switchTo(id), create(name, data?) -> { meta, persisted }, rename(id, name),
  remove(id) -> { switched, persisted }, replace(id, data), load(id), destroy() -> Promise<boolean>, idle() -> Promise<void>, subscribe(fn) -> unsubscribe }
WorkspaceBackend = { persistent, exists() -> Promise<boolean|null>, get(keys), list(prefix), write(puts, deletes) /* one transaction */, destroy() }
```
Records: `'meta'` `{ v, createdAt, migrated }` (written with the first write), `'wsmeta/<id>'` `{ id, name, createdAt, updatedAt }`, `'wsdata/<id>/<part>'` (an empty part has no record). **Opening** never creates a database: `exists()` (`indexedDB.databases()` where the browser has it) false means nothing is read either. **First run** (no `'meta'`): the legacy keys that are present move into Default in one transaction with `'meta'`; they are removed only after it committed, so an interrupted migration loses nothing and runs again; without persistent storage the data is read into memory and the keys stay. `migrated` lists the parts that moved (state.js `migrated`; the shell counts it as an earlier visit). **Writes**: `save` updates memory at once; one write per part at a time, and the values saved while it runs are written once after it as the latest (a burst of keystrokes in a long wordlist writes it once per write); a write still waiting is dropped by `destroy()` and by deleting its workspace (it would bring them back); `replace` updates a waiting write to the new value. A failed write keeps memory and sets `lastError`; a backend that cannot be read at all makes the rest of the page work in memory (`persistent` false). `destroy()` resets memory at once (Default only, empty) and deletes the database. **Other tabs**: a BroadcastChannel-like `channel` carries `{ type: 'data', id, parts }`, `{ type: 'list' }` and `{ type: 'destroyed' }` after each committed write; a tab re-reads the parts of its active workspace, the list, and goes on in Default when its workspace was deleted elsewhere. `subscribe` reports only these external changes (`'data' | 'list' | 'switch' | 'destroyed'`). Tests: `tests/js/workspace.test.js`, `tests/js/state-migration.test.js` (through state.js), `tests/e2e/workspaces.e2e.mjs` (real IndexedDB).

`state.js` over the store: `ready` (the shell waits for it before the first view, at most 8 s), `workspace` / `workspaces` (`{ id, name, isDefault, createdAt, updatedAt }`), `workspaceData(part)` (a copy), `setWorkspaceData(part, value)` (not the inventory: `setInventory`), `recordRecent(value)`, `learnedStorage`, `switchWorkspace(id)` (clears `state.session`, emits `'inventory'` then `'workspace'`), `createWorkspace(name, data?)`, `renameWorkspace`, `deleteWorkspace` (the active one: a switch to Default), `replaceWorkspace(id, data)`, `loadWorkspace(id)`, `whenSaved()`, `workspacePersistence`, `workspaceError`, `migrated`. `setInventory()` returns `{ persisted, inventory, done }` (`done`: whether the write succeeded). `clearAll()` returns a promise (true when localStorage was cleaned and the database deleted); memory is reset and `'inventory'`, `'settings'`, `'workspaces'`, `'cleared'` are emitted at once. New state events: `'workspace'` (another workspace is active: the views that keep a customer's results in module state — Subdomains, SSL Targets with Verify / DANE, Bulk Resolve, the Certificate view, Zone File, Reverse DNS — drop them, stopping what runs, as on `'cleared'`), `'workspaces'` (the list or a name changed), `'workspaceData'` (`{ parts }` other than the inventory changed; `origin: 'external'` from another tab). `handleExternalChange` re-reads only the settings now.

### 5.40 `lib/cryptobox.js` — password encryption of a file
WebCrypto only, `crypto` injectable. `sealText(text, password, { iterations = DEFAULT_ITERATIONS, context, crypto })` → `{ kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt }, cipher: { name: 'AES-GCM', iv }, data }` (base64): PBKDF2-HMAC-SHA-256 over the password (NFC, UTF-8) and a random 16-byte salt derives a 256-bit AES key; AES-GCM with a random 12-byte IV encrypts the text, and its additional authenticated data binds the caller's `context` and every parameter, so a changed iteration count, salt, IV or ciphertext fails like a wrong password. `DEFAULT_ITERATIONS` 600,000; `MIN_ITERATIONS` 310,000 (refused below, sealing and opening); `MAX_ITERATIONS` 5,000,000 (refused above on opening); `MIN_PASSWORD_LENGTH` 8 characters. `openText(box, password, { context, crypto })` → the text. `BoxError` codes: `password-required`, `password-short`, `wrong-password` (AES-GCM cannot tell a wrong password from a changed box: the message says both), `damaged` (not a readable box: bad base64, lengths, iteration count), `unsupported` (another KDF / hash / cipher), `crypto-unavailable` (an insecure context). `encodeBase64` / `decodeBase64` (strict, chunked), `checkBox`. The password is never stored. Tests: `tests/js/cryptobox.test.js`.

### 5.41 `lib/handover.js` — the workspace hand-over file
One JSON file with everything of one workspace, to move it to another browser or hand it to a colleague. Plain: `{ format: 'domainscope-workspace', v: 1, encrypted: false, workspace }`; sealed (§5.40, `context` `'domainscope-workspace/1'`): `{ format, v, encrypted: true, kdf, cipher, data }`, whose ciphertext is the JSON of `workspace` — a sealed file shows no name, server or address. `workspace` = `{ name, default, exportedAt, app, parts }` (empty parts left out). `exportWorkspaceFile(ws, { password, iterations, crypto })` → text (indented); `readWorkspaceFile(text)` → `{ encrypted, file }` (the outside only); `openWorkspaceFile(text, { password })` → `{ name, isDefault, exportedAt, app, data, encrypted }`, every part through `sanitizeWorkspaceData` (so an imported file carries no IP-shaped learned label, no IP in the recent list, no tool settings). `HandoverError` codes: `too-large` (over 40 MiB), `not-json`, `not-workspace`, `newer` (a later format version), `damaged`, and §5.40's. Tests: `tests/js/handover.test.js`.

### 5.42 `lib/expectedca.js` — expected CAs
A workspace's `expectedCas` against an issuer. `resolveExpectedCa(entry)` → `{ entry, ca, needle }`: with lib/health.js's `CAA_ISSUERS`, a CA's name, id or CAA identifier (and a brand its regex knows: ZeroSSL → Sectigo, RapidSSL → DigiCert) is that CA; anything else is text to find (a private CA). `expectedCaStatus(issuer /* DN or parsed name */, entries)` → `{ expected, entry, ca }` or null without entries or issuer (no badge); `expectedCaaStatus(domain, entries)` → `{ expected, entry }` or null (a known CA by any identifier; a text entry must equal the domain). `ui/expected-ca.js` draws "Expected CA" / "Unexpected CA" (`data-expected-ca`) next to the issuer of the Certificate view's overview and summary (SSL Targets step 1 shows the summary), the CAA tab's issuer line, SSL Targets › Verify (a served certificate's issuer: only "Unexpected CA" in the table, either in the details) and Domain Health's CAA card (each issue / issuewild CA); the views redraw on a change (`expectedCasChanged`). Tests: `tests/js/expectedca.test.js`.

## 6. UI (views)

Hash routing `#/<view>?param=...` (shareable: e.g. `#/lookup?name=example.com&type=MX`, `#/global?name=www.example.com&type=A`). Navigation groups (`lib/shellnav.js` NAV_GROUPS, §5.29; a view's `group` in app.js `VIEWS`): Discover (subdomains, zone), Certificates (scan, cert), DNS tools (global, lookup, bulk), IP addresses (ip, ptr), Mail & domain (health), Workspace (inventory, about); a view with an unknown group is listed under "More tools". Views load lazily; when a view's module fails to load because the page belongs to an earlier deploy (`confirmStaleModule` in app.js: a missing export, or a failed fetch while the browser is online and this page's own `v/<commit>/assets/js/app.js` answers 404), the page body offers **Reload page**. Offline or on a dropped connection the same fetch failure keeps the plain network error with Retry and never claims an update. A stale DoH / Globalping module, or a scan whose wordlist tier, locale pack or engine module failed to load in a page whose `v/<commit>/` is gone, shows the same hint once as a toast. Every "Reload page" goes through `ui/pwa.js` `reloadPage()` (a waiting service worker takes over first, §5.35).

**Loading.** `index.html` links `style.css` only and modulepreloads app.js's static graph. `VIEWS[]` (app.js) gives each view its stylesheets (`css`, paths under `assets/css/`): they are injected as `<link rel="stylesheet">` resolved against app.js (so they follow `v/<commit>/`), before the view mounts, kept for the page's life and ordered by `VIEW_CSS_ORDER` whatever the visiting order; a sheet that cannot load leaves the view unstyled, never unusable, and a view whose module fails shows its message only once the stylesheets have settled too. The discovery engine (`ENGINE_MODULES`: scanner, sources, doh, dnswire, permute) is imported when a scan starts and modulepreloaded once the browser is idle on Subdomains and SSL Targets (`VIEWS[].preload`; not offline or with Save-Data); `lib/ipintel.js` loads on the first "Look up owner". A module loaded on first use that fails to load (`views/subdomains.js` `loadOnFirstUse`, behind `runScanner` and `networkOwner`) calls `ctx.checkOutdated` first, so a tab left open across a deploy offers the reload instead of only the failed scan or lookup. zoneparse and x509 load with the views that need them (Zone File; Certificate / SSL Targets). `tests/js/start-route.test.js` holds the start route (index.html, boot.js, style.css, app.js's graph, the Subdomains graph and stylesheet) under a gzip budget of 340 KB (≈ 334 KB with wave 2's shell, page session, Copy summary, job progress and Subdomains tabs; ≈ 258 KB before them, ≈ 368 KB before the lazy engine) and keeps the heavy modules out of it.

**Installable app and offline.** The Pages bundle registers `sw.js` (§5.35) and links a web app manifest in the UI language, so browsers offer to install DomainScope; the development checkout registers nothing. With the worker in control every view opens offline. Certificate (parsing, the sample), Zone File (import, lint, origins, the command), Servers and About need no network (`VIEWS[].offline`); offline, every other view shows a note between its header and body ("You are offline", what it needs the network for, links to the tools that work offline), and `ctx.requireOnline()` — called by every network action (Scan, Look up, Check, Run, CT Load, CAA / CT / DANE checks, the Live check, Verify, the MTA-STS check, owner and reverse-IP lookups) — says so in a toast and sends nothing (one such toast at a time: another click replaces it rather than stacking copies). A check a view starts by itself (the Certificate view's CAA check, and its CT search for a public CA, when their tab opens) calls `ctx.requireOnline({ quiet: true })`: offline it sends nothing and the panel says so in place (`cert.caa.offline` / `cert.ct.offline`, `data-offline="auto"`), without the toast — the user clicked nothing; the panel's button then runs it (and warns) as usual. A run on arrival (Lookup, Global DNS, Domain Health, IP Intel: `start({ auto: true })`) — a shared link, or a link from another view that carries params, such as a host name's DNS Lookup link — is quiet the same way: offline it fills the form and sends nothing, and the page's note says why. A click on the view's own button, or a new query on the view already open (`update()`), still gets the toast. Toasts stay at four on screen: past that the oldest timed one goes, never a sticky one (timeout 0, such as "Update ready — Reload"). A new deploy is announced by "Update ready — Reload". About › Privacy says what the worker keeps and what it never caches. Views:
0. **subdomains** "Subdomains" (**default route**, `#/subdomains?domain=…[&tab=overview|hosts|origins|sources]`; the brand link and About's Start button open it): domain(s) in, every discoverable subdomain out. Options: wordlist level **Off / Small / Smart (recommended, default) / Large / Huge** with exact counts (`wordlistInfo()`), the locale packs the typed domain gets and time estimates (candidates ÷ 120 queries/s at the full sweep width of 24, scaled down for a lower Settings value), and a plan line (≈ queries per domain, custom / learned / pack shares, per-domain caps); under Advanced options: languages / markets (auto from the domain ending, a manual pack list, or none; remembered), custom wordlist (textarea + `.txt` file, accepted / rejected counts from `parseCustomWordlist`, this tab only, Clear), learned names (opt-in switch, off by default, with the count, Forget; never used at Off), permutations on/off with a budget (500 / 1,500 / 5,000; the switch also drives the recursive round), origin hints on/off, passive sources with quota notes, include expired, extra hostnames, DoH chain. A shared link (`run=1`) pre-fills the domain and asks before scanning. While running: a progress bar whose label names the stage, and stage pills in `SCAN_STAGES` order with per-stage counts. Results in four tabs (§5.31 `lib/subtabs.js`) under the run's header card (title, time, progress bar, the zone-file banner, the cancelled / failed notice), each tab label with a live count: **Overview** — the stat cards (a click filters the host table and opens Hosts with the keyboard focus on its tab), the summary alerts (nothing found, sources that failed with a link to Sources, dangling CNAMEs, the Cloudflare count with a link to Origins, wildcard parents, scanner warnings; the tab counts the warnings and errors), a technique bar ("how the names were found": DNS records / wordlist / permutations / deeper level / passive sources), a wordlist usage line from `options.wordlist` (served level, packs, custom / learned tried vs found, fallback) and a CTA that opens SSL Targets for the same domain; **Hosts** — copy all names / resolving only / `names.txt` / CSV / JSON and the host table (name → DNS Lookup link, origin badges, classification, IPs; on a phone each row is a card in which a host name wraps only after a dot — `hostNameNodes`: one unbreakable run per label, a `<wbr>` between — or inside a label too long for the line on its own, and an IP never breaks); **Sources** — the stage pills, the per-source status (`sourceHealthSummary`, quota explanations; a screen reader hears each new status line and the “still fetching” note from the run's header whichever tab is open) and the free limit of each source asked; **Origins** — for proxied hosts an **Origin** panel ("Origin servers behind the proxy"), or why there is none (candidates are looked for at the end of the scan, no host hides its origin, the scan did not finish): origin networks (/24 · /48) with their DNS-only hosts, per proxied host its resolver-leak answers ("answered by <resolver>") and history ("seen by <source> · last <date>"), read from the structured reason fields, other SPF / MX / sibling hints, and the sweep command for **Linux / macOS** or **Windows PowerShell** (built from `cliTargets` / `cliNames` with `buildSweepCommand`, dropped entries counted; over 200 names it reads `-n proxied-names.txt`, offered as a download next to the command, and a target list still too long for one line reads `-t proxied-targets.txt`, offered the same way) with copy and a download link for the CLI. Hosts is the automatic tab once a host is listed (Sources before that while the run is live, Overview when it ended empty); an automatic move waits while the keyboard focus is inside the tabs (a focused tab, a tapped panel) and happens once the focus leaves them. A tab the user picks (a click, also on the tab already shown, ←/→/Home/End with a roving tabindex, a stat card, a link) stays for that run, goes into the URL as `tab=` next to `domain` (replaceState; after a return through the nav link, which has no `domain`, the run's domains are written with it) and comes back after a language switch or a visit to another view (the page session keeps it too); a new scan starts on the automatic tab and drops `tab=`, and an edited `tab=` opens that tab without a re-mount (`update`). Every panel is built up front, so a live run fills the hidden ones as well. At ≤ 480 px the four tabs share the row in equal columns with the count under the label.
   Later additions:
   - **Live rows:** while the wordlist, permutation and recursive stages run, `onFound` hits appear at once as "resolving…" rows and are replaced by the full record at the resolve stage.
   - **Stage pills:** they show which passive sources were still fetching when the sweep started (`sourcesStillRunning`).
   - **Plan line:** a query range from `estimateQueries`.
   - **Origin panel:**
     - per proxied host, its `originCandidates` in order: zone file, resolver leak, sibling domain ("same name as <sibling>"), history, then only the related networks;
     - per network, whether the command sweeps the whole /24 or only its addresses (and why), a **shared hosting / cloud** badge with a warning, and **Look up owner** (`describeNetwork`, one RIPEstat request on click);
     - an **Exclude addresses** box (→ `buildSweepCommand({ exclude })`). It is kept per run for the page session, so it survives a re-mount. The JSON export's `origin.cliSuggestion` is the panel's POSIX command with these exclusions (`originExport`), and `origin.exclude` reports what they did;
     - a tip to scan sister domains together;
     - on each IPv4 network, **Reverse DNS sweep**: a link to `#/ptr?target=<network>&focus=<registrable domain of its first host>` that only fills the Reverse DNS form (the user presses Sweep); on a shared cloud / hosting network (whose other addresses are other customers') **Reverse DNS of its N addresses**, with only the network's own IPv4 addresses as the target.
   - **Names from a reverse DNS sweep** (`state.session.namesScanIntent` = `{ v: 1, target: 'subdomains', source: 'ptr', names, domains, label, mode: 'exact', at }`, one-shot, memory only, honoured for `NAMES_INTENT_MAX_AGE` = 60 s): `namesFromIntent` re-validates the names (they come from PTR records; at most `NAMES_HANDOFF_MAX` = 4,000), the box gets the domains, and a chip ("N names from the reverse DNS sweep of <label>", `NamesChip`) offers Scan exactly these names (default) / Include in discovery / Leave out (`ZONE_MODES`), Back to Reverse DNS and Remove. Nothing starts by itself. Exact mode (`handoffScanOverrides`) runs `runScan({ extraNames: typed + names, exact: true, sources: [], bruteforce: 'off', … })` for one run (never stored), the plan line says so, and the results carry a banner; discover adds the names as extra names. The names apply only to a scan of their own domains (`handoffForDomains(handoff, domains)`: the names equal to or under a typed domain, like the Zone File chip's `zoneForDomains`): with another domain in the box the chip says "Not used for the domains in the box: these names are under <domains>", with some of them how many this scan uses, and the plan line, exact mode and the extra names follow. The chip stays for the page session until removed ("Delete all local data" drops it, whether or not the view is mounted).
   - **Zone File "Scan now" during a scan:** the zone scan waits for the running one (`zoneStartAction`). A prompt offers **Cancel it and scan the zone** or **Don't start**. Leaving the page drops the request; the box and the zone mode stay filled in.
0b. **zone** "Zone File" (`#/zone[?tab=overview|records|origins|problems|live]`; only `tab=` ever goes in the URL):
   - **Import:** drop, choose or paste, with format / dialect auto-detection. The zone name override and a Confirm step apply when the name is only guessed; there are 3 built-in samples and "How do I export my zone?".
   - **Summary bar:** a format badge and counts ("39 records · 26 names · 10 proxied"), with Forget. Alerts are pinned for an incomplete export and a mostly-internal zone.
   - **Overview:** stat cards and next steps:
     - Scan these names: exact mode or discovery, with "Leave out names that look internal", on by default;
     - Sweep the real origins;
     - Find certificate targets;
     - Compare with live DNS: shows the planned query count.
   - **Records:** type groups, proxied only, search, CSV / JSON, copy names; an expanded row shows its comment, tags and problems.
   - **Origins & servers:** one row per proxied name (`proxiedOriginMap`), a by-address table (`addressMap`; both re-matched when the Servers list changes) and the sweep command (`zoneSweep` + `cmdline.buildSweepCommand` with the zone opt-ins). The command has a proxied-only / everything scope, POSIX / PowerShell, an "at least N TLS handshakes" estimate and the two-file form with `zone-names.txt` / `zone-targets.txt` downloads. It uses exact tokens only, never a /24.
   - **Problems:** parse issues and lint findings, errors first; a click jumps to the record.
   - **Live check** (`planDrift` / `driftZone`): nothing is sent until you click Check.
     - The card shows the record sets, the query count, the resolvers and what is sent.
     - Internal names are skipped by default, and wildcard probing is optional.
     - Progress, Cancel and Re-run; the check keeps running while you are on another view.
     - Banners: serial, name servers, a zone that does not exist. Status chips filter the rows.
     - CSV / JSON exports redact origins unless opted in, also inside a value (an SPF `ip4:` / `ip6:` / `a:` term, an MX or SRV target).
   - **Hand-off contracts:**
     - `state.session.zone` = `zoneScanInput(...)` + `{ label, counts }`. It is published only once the zone name is confirmed, and cleared by Forget and "Delete all local data".
     - `state.session.zoneScanIntent` = `{ v: 1, target: 'subdomains'|'scan', domain, mode: 'exact'|'discover', autostart, at }`, one-shot. Exact mode maps to `runScan({ zone, exact: true })` and is never written to the stored options.
   - **Privacy:** nothing about the zone is persisted (no storage key, no URL data), and no network request is made before a click.
1. **scan** "SSL Targets": one requirement line above the steps — "A certificate or at least one domain is required" — turns into a check once met (`formProgress`, §5.27; no step is labelled optional), and a completed step shows a check in place of its number (plus "(done)" in its heading for screen readers). A loaded certificate the scan cannot use — a CA certificate, or one without DNS names — leaves step 1 open with a warning sign, a warn badge ("CA certificate" / "no DNS names") and "(needs attention: …)" in its heading; while nothing else meets the requirement the line adds "This certificate has no DNS names: enter at least one domain.", and Start's error says the same instead of "load a certificate"; steps — (1) drop/paste certificate → shows parsed summary; without a file, the same "No file?" block as the Certificate view (a host name's certificate from CT, or **Try a sample**); loading either only fills step 2 like a dropped file and never starts a scan; a CT certificate carries the caveat and points at the Verify tab, which checks what each server really serves; a scan that ends while a lookup still runs hands the busy flag back to it (a language switch waits for the lookup instead of aborting it); (2) target domain(s) (auto-filled from cert via registrableDomain); (3) inventory (uses shared inventory from state; link to inventory view); (4) options, collapsed into one Disclosure line (the Subdomains › Advanced options component, its summary an `<h2>` via `Disclosure({ heading: 2 })` like the other step titles) whose summary lists what differs from the defaults (`optionChanges`) or "recommended defaults"; its open state lasts for the page session, and an invalid extra hostname opens it (sources checkboxes w/ notes about quotas, include expired, wordlist Off/Small/Smart/Large/Huge (default Smart) + permutations, DoH chain; a vocabulary line shows the languages, custom wordlist and learned names shared with Subdomains › Advanced options, with a link there — SSL Targets has no separate controls for them, but records learned labels after its scans too); a run bar with Start/Cancel, the plan line (≈ DNS queries and time; the zone's names in exact zone mode) and a summary — in the flow on wide screens; at ≤ 1100 px it is `position: sticky; bottom: 0` inside the form (edge to edge at ≤ 900 px, side safe-area insets; while it floats (`barStuck` → `data-stuck`) a shadow and the bottom safe-area inset, none of it at rest; no transition with reduced motion), rests at the form's end so it never hides the last field, and the view publishes its height as `--scan-runbar-h` on the root for `scroll-padding-bottom` so a focused field is never behind it (at ≤ 600 px Start goes full width and the summary gives way to the plan line); Run/Cancel with per-source status + progress (the keyboard focus moves from Start to Cancel and back; a cancelled run keeps its streamed hits in Hosts, and the hosts CSV / names.txt exports include them, with certificate coverage). Results: stat cards; tabs Hosts / Servers / Behind CDN / Verify / DANE / Sources / CT: **Hosts** (table: name, origins, status/classification badge incl. 🟠 Cloudflare, IPs, CNAME, cert coverage ✓/✗, matched servers; filters: covered only / resolving only / hide wildcard suspects / by kind; search), **Servers** (grouped: server → hosts; "needs cert" first; unmatched IPs group), **Behind CDN** (proxied hosts + origin hints + explanation + ready-to-run CLI command with the same POSIX / PowerShell toggle & download buttons for names.txt/targets.txt + link to `cli/ssl_origin_scan.py`; one shell choice drives the quick sweep, step 3's command and the Verify CLI card), **Verify** (only with a certificate; `ui/verify-panel.js` over §5.18–§5.19: every covered (public IP, name) pair of the scan checked from the internet through Globalping, with the CLI's verdicts (a Cloudflare Origin CA certificate and a self-signed one are labelled as such — ORIGIN_CERT / PRIVATE_CERT — never "Old certificate"; info behind a CDN, a warning where visitors reach them directly). Nothing is sent when the tab opens, not even `/limits`. Start and "Check again (n)" read the free quota and show the consent + cost dialog on the first send of the page session (consent is never stored; "Delete all local data" resets it); a partial run is offered when the quota does not fit, and a 429 stops cleanly with the reset time. Private, reserved and unaccepted pairs and checks past the 500 cap are listed as skipped and, with every pair the internet could not answer (TIMEOUT / CLOSED), go to a validated CLI command (`--cert new-cert.pem --json verify-cli.json`, POSIX / PowerShell) with a new-cert.pem download; CDN-edge pairs are listed as skipped too but stay out of it, because the CDN serves its own certificate there. Origin pairs (an inventory origin IP with a proxied name, from an origin hint or the zone file) are opt-in, off by default, and the first batch with one always shows the dialog with the origin sentence. The headline counts servers; the tab badge reads `live/total`; warnings carry tooltips; CSV (the CLI's 17 columns first) and JSON exports; the scan's full JSON gains `verification`. The job lives on the scan run: it survives navigation and language changes, toasts when it finishes in the background ("Show results" reopens this tab), and a new scan cancels it), **DANE** (only with a certificate; `ui/dane-panel.js` over §5.25, the panel of the Certificate view's DANE / TLSA tab. Nothing is sent when the tab opens. "Check TLSA records" looks up the MX hosts of the certificate's domains, its concrete names and the covered, resolving hosts the scan found under its wildcard names, with the file's other certificates as the chain. The summary points to the tab when the scan mined in-domain mail servers (`dns-mine:MX`). The tab badge counts the endpoints that would break or fail (error) or need a closer look (warn). The job lives on the scan run like Verify's: Stop ends it ("cancelled"), a new scan cancels it, and the scan's full JSON gains `dane` (`domainscope.dane/1`)), **Sources** (per-source status, counts, errors, timing), **CT certificates** (crt.sh/certspotter certs: issuer, validity, names; highlight the uploaded cert's serial and certs expiring ≤30 days). Exports CSV/JSON.
2. **cert** "Certificate": full parsed details (subject, issuer, validity with days left, SAN list, key, fingerprints, chain order, warnings), CAA check against issuer for each base domain (Allowed / Allowed, with restrictions — each distinct RFC 8657 combination and what it means for the next renewal / Blocked, with each unusable value and why; the Result column comes before Records, and below 600 px the record set moves under the name so the verdict stays in view), CT lookup of this serial via crt.sh, a **DANE / TLSA** tab and a "find targets for this cert" button that opens scan pre-filled. The DANE / TLSA tab (`ui/dane-panel.js` over §5.25) checks the leaf of the file and its chain, whatever certificate is selected, and only on a click. While it runs, Stop takes the place of "Check TLSA records" and ends it ("cancelled"); the keyboard focus moves from the run button to Stop and back, never to `<body>`. It shows the headline, a "Publish before you install" card with the exact records to add and the 2 × TTL wait (error styling when an endpoint would break, warn styling when every item is a warning), the endpoints worst first (DNSSEC state, published records, an expandable explanation), CSV / JSON exports and this certificate's own TLSA values, computed locally. The job is kept per certificate across navigation and language changes. **No file?** (`CertAlternatives`, shared with SSL Targets step 1): a host name field that loads the newest valid certificate covering it from Certificate Transparency (`lib/ctcert.js`, §5.26; only on a click, Cancel while it runs, the outcome kept across a re-mount; any certificate change — the sample, a file, a hand-over, Remove — goes through `setCurrentCert`, which aborts a lookup still running, so its requests, the busy flag and a deferred language switch end at once), and **Try a sample**, which fetches `assets/data/sample-cert.pem` relative to the module (so it moves under `v/<commit>/` in the Pages bundle) and sends nothing to a third party. A CT load is a `CertLoad` with `source: 'ct'` and `ct: { host, provider, issuance, precertificate, newerPrecertificate, truncated }` (`ctCertLoad`); the sample has `source: 'sample'`. Both show a badge in the overview / step-1 summary and a note (`CertSourceNote`): for CT "Loaded from Certificate Transparency — the server may serve a different one", the issue date, a newer precertificate or a partly read list, **Check servers in SSL Targets** (the Certificate view hands the certificate over; the scan there leads to Verify) and the crt.sh page; the Chain tab says a log holds the leaf only instead of blaming a file. A crt.sh-only find (`manual`) lists the `?d=` download links and why the page cannot load them itself (one link when crt.sh holds only one id, and then no "use the other link"); every outcome says why crt.sh was asked (Cert Spotter's hourly limit with the time it is asked again, no answer or a refusal, a partial list, an unreadable copy; `ctOutcomeMessage`). A not-found says flatly that nothing is logged (and that internal names and private CAs never are) only on a complete answer: a list cut at the page cap, or crt.sh leaving some or all of its searches unanswered (`ctCrtshIncomplete`; its literal search misses the `*.parent` certificate when only that search failed), gives a hedged text, with Try again in the crt.sh case; a crt.sh find with a search unanswered adds that a newer certificate may be missing. A precertificate gets a warning (another fingerprint than the served certificate); loaded from CT, its note adds that no final certificate is logged yet, so it has to come from the server or the CA. After a load from the block (Enter, Load, Try a sample) the keyboard focus moves to the new source note (`focusLoadedCert`, tabindex -1) instead of falling to `<body>`; "Try again" hands its focus to Load (then Cancel); the hint below the field is tied to it with `aria-describedby`. The PEM & OpenSSL tab's copy-ready `openssl s_client` line (`sClientCommand`) uses only a certificate name that passes `cmdline.validateNames` unchanged (a `*.x` wildcard as `www.x`, else `example.com`): SAN bytes are not validated by the parser, so a hostile name is skipped, never pasted into the command.
3. **global** "Global DNS": name + type → table of all resolvers (answer, TTL, rcode, AD, latency) + geo table via ECS (flag, country, ISP, answer, scope) + consistency groups with color coding + answer IP classification (CDN badge). Re-run button; share link. Every answer group names the operator of its addresses, and the summary gives `propagationVerdict` (§5.10): "Differs by design: CDN / GeoDNS edges (<operators>)" as info (naming the names before the CDN that steer to the same CDN names, if any; "No <type> records anywhere — the CNAME chains differ by design (<operators>)" when only the chains differ), or a warning with one line per finding (the groups' letters, the sources — joined with "; ", as a location name has a comma of its own — and whether it looks like propagation or a misconfiguration: SERVFAIL as a resolution fault, REFUSED and other rcodes as a refusal, a provider move when the queried name points to different operators, a CNAME that differs as a change, GeoDNS / weighted records or name servers that disagree), or an error "No source could resolve the name" when every answer is an rcode; a SafeSearch rewrite of a filtering resolver is named in the summary and not counted as a difference; the Distinct answers stat warns only when the verdict does.
4. **lookup** "DNS Lookup": name + type(s) (checkbox group or "ALL common"), resolver select, DNSSEC toggle → sections per type with parsed records (SOA fields, MX priority, CAA tags, SVCB params …), flags (AD), raw presentation text, copy buttons. Density (`lookupLayout`, §5.37): a plain NODATA type gets no card but a place in the summary's "No records: AAAA, CAA, …" line (a disclosure with what NODATA means, the negative-caching time and the raw answers); the resolver that answered ("answered by …"), its PoP and the header flags are said once in the summary, and a card repeats only what differs (a failover to another resolver, other flags) plus a failover note or a cache hit; on wide screens the cards flow in CSS columns (`column-width: 480px`), and once every answer is in the first card of each further column is pinned there (`break-before: column`, made again after a Retry or when the width fits another number of columns), so opening a card's raw answer lengthens its own column instead of moving cards between columns; on phones the SOA timers sit two to a row and the TXT list shows four records (SPF / DMARC / DKIM first) before "+N more". The "No records:" label is in the text font, the type list in mono. The summary is updated in place as answers and Retries come in: the line keeps its node while its types do not change (and is drawn anew with the same open state, raw answer included, and keyboard focus when they do). A query that got no DNS answer keeps its card: which resolver failed (or "Every resolver tried") and why (`dohStatus`, §5.36), the attempts de-duplicated, and a Retry that asks that type alone again — at once, also while other types of the lookup still run; a new lookup cancels it (the keyboard focus returns to the card).
5. **bulk** "Bulk Resolve": paste hostnames (hundreds; a text / CSV list, or JSON: an array, name-like fields of objects, JSON lines) → table: name, status, CNAME chain, IPv4, IPv6, classification, PTR (optional), ASN (optional; its PTR queries use the run's resolver too), inventory match; progress (a cancelled run shows unfinished IP lookups as "not looked up"); CSV/JSON export. A PTR or ASN lookup that could not be made says "⚠ n/a" with the source and the reason (§5.36) — with PTR only, the reverse lookup's own failure (`ptr(ip, { throwOnError })`: e.g. "Reverse DNS: answered SERVFAIL"), never a silent empty cell.
6. **ip** "IP Intel": paste IPs → PTR, ASN, holder, prefix, country, provider/CDN, private flag, inventory server, reverse-IP domains (button per row; quota note). No silent dashes (§5.36): a PTR, network, prefix or location cell that a failed source left empty says "⚠ n/a" (tooltip and screen-reader text: each source and why, e.g. "RIPEstat: rate limited — try again in a few minutes"); a chip per service (RIPEstat, ipwho.is, reverse DNS) says how many rows it answered or where it failed; Retry — per row under the address, or per chip for every row its service failed on — asks only those sources again (`retry()`, §5.13) and the cells fill in; a Retry belongs to its run: a new lookup, Stop or leaving the view cancels it, and it never draws over a later run's row for the same address; after Stop, the rows never looked up leave no chip "asking…" (no chips at all when nothing was asked); a reverse lookup answered SERVFAIL / REFUSED says so ("Reverse DNS: answered SERVFAIL"); the row details list each failure in words, the JSON export gains `unavailable` (field → sources) and `sourceErrors`, and the CSV writes "n/a" in every UI language (a stable token for scripts). Stat cards whose count is zero (CDN / proxy, your servers — only with a saved server list —, private) fold into one muted sentence ("None of these addresses is behind a CDN / proxy."; `foldZeroStats`, §5.37).
6b. **ptr** "Reverse DNS" (`#/ptr?target=…&focus=…`; a link only fills the form and says it waits for a click — "Nothing has been sent yet"; the target is read with `targetTokens`, so `192.0.2.10 - 192.0.2.20` stays one range; the target and focus the page last wrote (`routeTarget` / `routeFocus`) are its own URL, so a reload or a re-mount keeps the form, while a link with the same target and another focus domain — or one opened by a hash change while the form holds a draft — fills the form; a link opened while a sweep runs waits until that sweep ends or is stopped — the form keeps the running sweep's target and focus and says which target waits — and then fills the form): the reverse DNS of every address of an IPv4 network up to a /22, a range, a list of IPv4 / IPv6 addresses or an AS's prefixes, forward-confirmed (§5.28).
   - **Form:** the target (the parsed count and each `parseSweepTarget` issue live under it: why IPv6 networks are not swept, a network over the cap with **Use <its first /22>** — or, wholly private or reserved, why it is not swept at all —, private addresses left out), an optional focus domain, Sweep / Stop (keyboard focus moves between them), the Settings parallelism, one example (AS3333), and what is sent. An AS turns the button into **List prefixes**: one RIPEstat request, then a picker (`parseAnnouncedPrefixes`): IPv4 prefixes with their size, ticked up to 1,024 addresses together (the running total, **Sweep selected**, Clear), a larger prefix disabled with **Use <its first /22>** (fills the form), a wholly private or reserved prefix disabled with why ("private space: not swept"), IPv6 prefixes listed but not swept, "no longer announced" marked (on a phone these notes sit under the prefix, their column hidden). **Sweep selected** follows a running sweep (disabled while one runs) and, when the picked prefixes hold nothing to sweep, says why instead of doing nothing. While RIPEstat answers, Stop cancels the lookup, and changing the target to anything but that AS drops it (no prefix list turns up later for an AS the form no longer holds); the busy state follows the sweep and the lookup together. A typed network drops an earlier AS's list. A finished sweep or lookup is announced once, when it ends, never again on a re-mount.
   - **Sweep:** `runPtrSweep` through the shared DohClient with `min(64, 2 × Settings concurrency)` addresses in flight and balance mode; the job belongs to the module (like Bulk Resolve): it keeps running on another view, a toast offers the results, a language switch keeps them. The URL gets `target` (the form's `targetTokens` joined with commas, so a range typed with spaces or an en dash is one `192.0.2.10-192.0.2.20` token; ≤ 400 characters) and `focus` (a focus edited later replaces it, an invalid one never goes in); Copy link in the header reads the focus at the click.
   - **Results:** progress, six stat cards (addresses, with a PTR name / generated, forward-confirmed / not resolving back or could not be checked — "every name resolves back" only when there are names and each does, "no PTR name to check" when there are none —, no reverse DNS (NXDOMAIN · empty), lookup failed (SERVFAIL), names under the focus domain — or the matched servers without one), clickable as filters; the table (`sweepRows`): focus rows first with an accent bar, then named hosts, pattern rows ("8 addresses", the template with an IP chip, "8 of 8 confirm"), addresses without a name, failures; the forward check as a badge with its explanation, the operator (`KindBadge`, from netinfo ranges or a PTR name under a provider's domain), the matching server; a Show filter (`SWEEP_FILTERS`; every sweep starts at "With a PTR name", and one that ends without any PTR name shows all its addresses unless the user picked a filter meanwhile; "Under your domain" is disabled without a focus domain, and clearing the focus while it is shown goes back to "With a PTR name") and **Expand patterns**; the filter and the search judge a pattern's addresses one by one (`sweepRowResults`): a pattern row stays while one of them passes and then says "1 of 8 match"; on a phone the forward check sits under the address (its column hidden); row details: the reverse name, each PTR name's forward answer, an RFC 2317 delegation, the template, the resolver, links to IP Intel and DNS Lookup; a pattern's details list its members.
   - **Exports and hand-offs:** CSV (`SWEEP_CSV_COLUMNS`, one line per address the rows shown stand for: of a pattern row only the members that pass the filter and the search) and JSON (`domainscope.ptr-sweep/1`: the same addresses, with the table's filter and search recorded and the summary of the whole sweep); names.txt (`sweepNames`, generated names left out); **Add names to a scan** (`scanHandoff` → `namesScanIntent`, then `#/subdomains?domain=…`, the user presses Scan); **Add to Servers** (`inventoryAdditions` against the editor's unsaved draft, else the saved text, so a second click adds nothing; `inventoryDraft` writes the hosts in that text's own format as `state.session.inventoryDraft`, then `#/inventory` with a toast that names the group — "in a new reverse_dns group" or "under your reverse_dns group": the user reviews and saves; nothing is saved here. A format it does not write, or an addition that would not read back as expected, leaves the editor alone: a dialog says why and shows the hosts as `name ip` lines with Copy, Download and Open Servers).
7. **health** "Domain Health": domain → checks list grouped with severity icons + record panels + RDAP (registrar, expiry countdown) + DNSSEC + email security. An RDAP lookup that got no answer (`rdapStatus`, §5.36) marks the card's registrar, dates, status and registry name servers "⚠ n/a" with the reason written out above them, and the card's Retry asks RDAP alone again: `applyRdap` (§5.15) puts the registration data, its checks and the new score on screen without a DNS query, and the keyboard focus stays on the card. The CAA card lists every issue / issuewild value: usable, restricted by RFC 8657 (only these methods / one ACME account, with what that means for the next renewal from `caaRestrictionNotes`), unsatisfiable or malformed. The **MTA-STS policy** card (shown when the domain has MX hosts or an `_mta-sts` record) sends nothing until **Check the policy (1 Globalping probe)**: `ui/globalping-gate.js` `gateProbes` (one free `/limits` read; nothing sent when the quota is used up; the consent + cost dialog on the first send of the page session, with its own privacy text: the host name `mta-sts.<domain>` and the path go to Globalping and the result, policy included, is public by id for about six months), then one measurement (`create` + `poll`) read by §5.24 with the report's MX hosts, `_mta-sts` and `_smtp._tls` records (`mtaStsContext`: a failed lookup is passed as not known, and a `_mta-sts` set the report flags as mta-sts.invalid as `txtInvalid`, the card's TXT row then marked "not valid: senders ignore it"): headline, mode, max_age, HTTP answer, certificate, an MX host → pattern table, the findings worst first, the policy file, the probe and a link to the measurement. A failed MX lookup reads "lookup failed" in the DNS card too, as do a failed NS, SOA, A, AAAA, TXT or HTTPS lookup (`failedLookups`) and a wildcard probe no resolver answered (never "No"); in the "Domain resolves" check a family whose lookup failed reads "IPv6: lookup failed" (`LOOKUP_FAILED_PARAM`, worded by the view like the 'yes' / 'no' of boolean parameters), never "IPv6: —". A paid measurement that could not be read is read again for free ("Read the result again"), also across a language re-mount; a new health check drops the result; "Report (JSON)" gains `mtaStsPolicy`. The check never changes the score. The Email security card ends with **Reverse DNS of the mail servers (FCrDNS)** (`report.mailIdentity`, §5.15): MX host (a provider's marked), address (with a Reverse DNS link to `#/ptr?target=<ip>&focus=<domain>`), PTR name (a generic one marked) and the forward check (on a phone it sits under the address, and long names break, so the table fits the card); the mail-identity checks count in the score like any other.
8. **inventory** "Servers": textarea + file import (txt/csv/ini/yaml/json), parsed table, warnings, saved in the active workspace (§5.39; a badge in the editor card names it; a failed write says so in a toast), clear button, privacy note. An address written with a port is shown and exported as `ip:port` and written so to targets.txt (§5.5). The editor opens with `state.session.inventoryDraft` when one is waiting (its own unsaved edits after navigating away, or hosts another view appended, such as Reverse DNS › Add to Servers) and shows "Unsaved changes" until the user saves.
9. **about**: where to start (the first-visit jobs, always listed), how it works, sources & quotas, privacy, CLI download & usage, Cloudflare explanation, GitHub link placeholder.

**Shell navigation (app.js over §5.29).**
- **Sidebar / Tools menu:** above 900 px a sidebar with the group headings (on a screen at most 860 px high the spacing tightens, so every link of the six groups — with room for one more — fits the ~650 px a 1366 × 768 laptop's browser leaves; where the links still do not fit, the sidebar scrolls itself, never the page, just far enough to show the open tool's link), 720–900 px a sticky strip of links (scrolled sideways to the open tool's link); below 720 px the strip gives way to a sticky bar with a **Tools** button (`aria-haspopup="dialog"`, `aria-expanded`) and the current tool's icon and name (`aria-hidden`: the page `<h1>` names it). The button (a 44 px touch target) opens a Modal with every view in its group (`groupViews(VIEWS)`, so a new view appears by itself), two large targets per row, the current tool marked (`aria-current="page"`, a check, focused on open); every other link leads where the sidebar's does (`navHref`: back to the tool's kept result, or with the current target filled in). While the open tool works its entry carries the sidebar's pulsing busy dot. Esc, the close button or the backdrop close it and the focus returns to the button; a link to another tool closes it and the new page title takes the focus, the open tool's own entry only closes it (its params stay); a Ctrl / ⌘ / Shift / Alt click is left to the browser (a new tab) and the menu stays open (`isPlainClick`); a hash change (the phone's Back) closes it, and so does a viewport widened past 720 px (a phone turned sideways: the button is gone, the page title takes the focus).
- **First-visit task picker:** above the start page's header (default route only) a dismissible region (`<section>` named by its title, which is no heading: it comes before the page `<h1>`), "New here? Pick a job to start with", with five job links (`START_TASKS`: Find every subdomain → subdomains, Where must this certificate go? → scan, Check a domain's health → health, Is my DNS change live everywhere? → global, Import a zone file → zone; `ui/start-tasks.js`); below 600 px two columns of short chips (the job alone, the tool's name read out but not shown, no lead line; below 360 px without their icons), so the start page's own field stays near the top. The start page's own job focuses its input instead of navigating (a Ctrl / ⌘ click still opens a new tab). It shows while `settings.startTasks` (state.js, default true, persisted with the other settings) is on. Dismissing sets it off (the focus goes to the page title; a toast names About › Where to start), and so does the first run: a view going busy (`ctx.setBusy`), an imported zone, a loaded certificate or saved servers (`isRunSignal`); a picker already on screen stays until the page is shown again, so nothing jumps under the pointer. A browser with saved servers or learned names at start-up (`hasUsedBefore`) never sees it; remembered view options do not count. "Delete all local data" brings it back. About › **Where to start** always lists the same jobs.
- **Keyboard shortcuts:** one `keydown` listener in app.js (`shortcutFor`); none while a dialog is open or after a handler called `preventDefault` (a field's own Enter). **Ctrl/Cmd+Enter** in a field of the view clicks the `data-shortcut="submit"` control of the field's own form (`pickShortcutTarget`, strict: nothing while the run is in progress): the view's Run for every field of the view's form, and inside a sub-form (`data-shortcut-scope`: the certificate paste box, the CT host name lookup, Zone File's importer — its paste box, zone name and format import the pasted zone — and its live check, whose options start it, Reverse DNS's prefix picker, whose Sweep selected answers its checkboxes) only that sub-form's button — so on SSL Targets the domains field starts the scan, never the paste box's Read. Results are no part of a form: each view marks its results container `data-shortcut-scope="results"` (Subdomains, SSL Targets, Certificate, Global DNS, DNS Lookup, Bulk Resolve, IP Intel, Reverse DNS, Domain Health, Servers, Zone File's analysis) and every DataTable is a `"table"` scope of its own, both without a submit, so a table's filter, a results option or a Verify / DANE panel field starts nothing — a new run from there would drop the results on screen (and a Verify run's spent Globalping quota). The help dialog's note says so. A control counts when it is enabled and visible (`checkVisibility()`, and never inside the collapsed part of a closed `<details>`). **Esc** clicks the nearest visible `data-shortcut="cancel"` control (a view's Stop / Cancel button, the Verify and DANE panels' Stop), else one that only a closed tab panel of the view hides (the Zone File live check or a DANE check running while another tab is open), and does nothing — not even `preventDefault` — when there is none; in a search field with text (a table's filter) Esc clears the field (`isSearchClear`: the shell empties it and fires `input`, as Chrome does by itself and Firefox does not) and the next Esc cancels; **/** outside a field focuses the view's `data-shortcut="focus"` element (Subdomains, SSL Targets, DNS Lookup, Global DNS, Bulk Resolve, IP Intel, Reverse DNS, Domain Health, Servers: the main field; Zone File, Certificate: the drop zone), else its first visible text field; **?** opens the Keyboard shortcuts dialog (also from the footer, whose button — `aria-haspopup="dialog"` — touch-only devices do not show), ⌘ on Apple platforms; the focus returns where it was. Views never bind these keys themselves; they only mark their controls — every view but About a submit, a focus control and a results scope (`tests/js/shellnav.test.js` fails for a view that misses one).

**Page session (`lib/session.js` §5.30, `ui/session-ui.js`, app.js).** A run in any tool (`ctx.runStarted`) sets the **current target**: Subdomains / SSL Targets their first domain, Global DNS, DNS Lookup and Domain Health their name, Bulk Resolve and IP Intel their list's one entry or shared registrable domain (else unchanged), the Certificate view its CT host or first DNS name (the bundled sample sets none). A chip after the brand shows it ("Target example.com ×"; on phones in place of the brand name; a long host name is cut in the middle, "a…example.com", the registrable domain whole and the full value in the text and title), titled with what it does; × clears it (focus moves to the page title, "cleared" is announced). Every `a.nav-link[data-view]` points to `navHref(id)`: the tool on screen to its own URL, a tool with a kept result back to it — unless the target was set after that result and is about something else (then the target, filled in, with the kept result still shown under it) — else the tool with the target filled in (`#/lookup?name=example.com&run=0`), else bare. `run=0` fills the form and runs nothing — the tools that run on a shared link (Global DNS, DNS Lookup, IP Intel, Domain Health) do not run — and every tool's box (Subdomains, SSL Targets, Bulk Resolve, Global DNS, DNS Lookup, IP Intel, Domain Health and the Certificate view's "No file?" field, `?host=`) takes it only while empty or while it still holds exactly the last run's input or the target it took before (never a draft), on arrival and in `update()` — so it follows every newer target, three in a row as well as one, until the user types in it; the Certificate view drops `host` once a certificate loads. Leaving a tool keeps its finished result (`result()` + `snapshot()` for Global DNS, DNS Lookup, IP Intel, Domain Health; the fact for the tools with module state: Subdomains, SSL Targets, Bulk Resolve, the Certificate view and a finished Zone File live check, which has no subject, so nothing about a zone becomes the target or reaches a URL); coming back shows it again with no request — through a bare route or the result's own params, which then go into the URL with `run=0` (a reload or a later Back only fills the form), and under a newer carried target too, which stays in the URL and the box (so after Domain Health for example.com and a lookup of www.example.com, Domain Health opens with www.example.com in the box and the example.com report under it, as Bulk Resolve shows its last job under a new name); Copy link gives the running URL of the result on screen, never the box's — and the page header says "Result from 14:02 Run again" (one run of text that wraps like a sentence; the date too on another day; announced with the tool's name). A tool with module state gets the note only for the result the shell kept when it was left: a certificate loaded in SSL Targets shows in the Certificate view without one. "Run again" calls `rerun()`: the kept query again, the last run's names (Subdomains' is its page-header Re-run, Global DNS's too, so their notes have none), for SSL Targets and Bulk Resolve with the options as set; a certificate from Certificate Transparency is looked up again (a file or the sample has no Run again); the Zone File live check runs again on its tab. A language switch keeps both the result and the note; a new run removes the note, and so does anything that replaces or drops the result (the Zone File's own Run on its Live tab, a new import, Forget), while a Run again that brings nothing new (a CT lookup that finds nothing) leaves it. The Zone File's note reads "Live check from 14:02", so it says what it is about on every tab. IP Intel matches kept rows against the servers as they are on return. A result over the memory bound comes back as its query, filled in, with "The result from <time> was too large to keep" and Run again; one whose query no link carries (IP Intel over 40 entries) opens empty, with the same note and no Run again. The oldest result goes first; a result only looked at again keeps its age. "Delete all local data" forgets the target, the kept results and what the tools with module state hold (Subdomains' and SSL Targets' box and last scan, Bulk Resolve's list and last job — running ones are stopped — the Certificate view's "No file?" field and per-certificate CAA / CT / DANE results, the zone), and the tool on screen opens again, bare; a reload or closing the tab forgets the page session too.

**Copy summary (`ui/summary-button.js` over §5.32).** A finished result has **Copy summary** (Markdown for a Jira ticket or a Slack thread) and a small **Plain text** button next to it (the same lines without Markdown) in its result header: Domain Health's hero next to "Report (JSON)", the Subdomains run's header (above the tabs, so every tab has it), SSL Targets' results head, Global DNS's links row, Zone File's summary bar, the Certificate overview's actions, DNS Lookup's summary card and above IP Intel's stat cards. They are disabled while a run is going (Domain Health's too, while a new check runs over the previous report; a cancelled Subdomains scan copies what it found; SSL Targets waits for a finished scan) and read the view's facts at click time, in the UI language. `SummaryButton({ kind, facts, url, inventory: false | 'names' | 'count', disabled })` returns `{ el, setDisabled, text(format) }`; `url` is the permalink of the result the facts describe (Domain Health: the report's domain and the DKIM selectors it was checked with). The copy reuses `CopyButton` (the "Copied" feedback, a toast naming the format: `toastOnCopy` takes a text) with its `onFail` option: a browser that refuses the clipboard gets the text in a dialog, selected, to copy by hand (Ctrl+C / ⌘C, or touch and hold on a phone). The tooltip says what a summary holds — only what the page shows and a link to the page (Zone File and Certificate: without the file's contents); nothing from the server list, except SSL Targets (`'names'`: the servers that need the certificate, as its Servers tab shows them) and IP Intel (`'count'`: how many addresses are in the list, never a name). `resultPermalink(root)` gives the link of the first shown summary that has a result, for the print header.

**Print.** The dark palette is screen-only (`@media screen` around the dark tokens), so printing from dark mode gives dark text on white paper. The print stylesheet (style.css, plus a block per view for its own form) hides the header, nav, footer, page header, toasts, dialogs, progress bars, every button and form field, segmented controls, file drops, table toolbars / expanders and the tabs that are not selected; it prints scrollers whole, repeats table headers with their labels (a sortable header's `.dt-sort` button is `display: contents` on paper: Chrome leaves buttons out of a repeated header row), keeps rows, alerts, stat cards and key-value rows from breaking across pages, wraps code and tightens tables. What is drawn with backgrounds keeps them on paper (`print-color-adjust: exact`: Domain Health's traffic light, the Certificate overview's lifetime bar). A cell breaks only between words (`overflow-wrap: break-word`, never `anywhere`, which lets a column shrink to one character); addresses and host names stay whole (`nowrap` in the view blocks: SSL Targets' address columns `scan-col-ips`, IP Intel's address, Global DNS's addresses and names, Subdomains' and Domain Health's names and addresses), and IP Intel's operator and network cells drop their screen minimum widths so its table fits the page. On `beforeprint` app.js opens every closed `<details>` of the page (a Disclosure's content belongs on paper) and puts a `.print-head` on top — the app, the page title, "Printed <UTC time>" and the permalink as a link: the one of the result on paper (`resultPermalink`, the link its Copy summary carries), else the route with the view's own shareable params (§5.32 `permalinkParams`); never inventory data or file contents. `afterprint` closes what it opened and removes the header. `Page.printToPDF` fires both events.

**Globalping gate (`ui/globalping-gate.js`).** Every Globalping send of the app goes through it. Consent is kept per purpose (`'verify'`, `'mta-sts'`) for the page session only — each feature sends different data, so each shows its own privacy text once — and is never stored; "Delete all local data" clears it and the shared quota. `sharedQuota()` / `noteQuota(q)` keep the latest reading for every view (the anonymous quota is per IP address), `liveQuota(q)` drops a reading whose window has passed, `whenText(resetAt)` words a reset ("in 42 minutes", never "… ago"), `measurementUrl(id)` is the only public measurement link. `gateProbes(ctx, { purpose, probes, privacy, signal, confirm })` is the flow of a one-click feature: the shared client (`ctx.getGlobalping`), one free `/limits` read (a failed read falls back to the last reading of the open window, else the anonymous limit, and the dialog says so), `{ status: 'quota', resetAt }` without asking when the quota cannot cover the probes, the consent + cost dialog (`confirmProbes`) on the purpose's first send, then `{ status: 'go', client, quota }` — the caller sends. SSL Targets › Verify keeps its batch flow on the same consent and quota.

**Long jobs outside their view (`ui/jobs.js` over §5.38).** A Subdomains or SSL Targets scan and a Bulk Resolve run register a job when they start (`startJob({ view })`, updated from the scanner's stage / progress hooks with `scanFraction`, or from the bulk job's row events with `bulkFraction`) and end it on done / cancel / error. While jobs run: the tab title reads "(62%) <page> · DomainScope" ("(%62)" in Turkish; the least advanced job; the shell sets the page's own title through `setBaseTitle`), the running view's navigation entry carries a progress ring (replacing the busy dot; screen-reader text "running, 62% done") also while another view is open, and the favicon's href is a badged SVG `data:` URL (CSP `img-src data:`), restored when the last job ends. Renders are throttled by timers, not animation frames, so a background tab still updates. Once a job has run 30 s, its panel offers **Notify me when done** (bell): the permission is asked only on that click, the opt-in lasts for the page session (never stored; "Delete all local data" drops it; pressed again it turns off; a toggle whose label stays the same — `aria-pressed` and a pressed look say it is on), a blocked permission is said instead (a refusal on the click moves the keyboard focus to that sentence; while the browser's prompt is open the button is busy — `aria-busy`, `aria-disabled`, a spinner — but never disabled, so the focus stays on it for any other answer), and a desktop notification ("Bulk Resolve finished" + the done-toast text; a failure too, never a cancel) is sent when a job over 30 s ends while its view is not in a visible, focused tab; a click on it focuses the tab and opens the view. Never offered where the page cannot show a notification itself (`pageNotifications`: Chromium on Android — a tablet too, `userAgentData.platform` — has the permission prompt but only a service worker may notify, and the page does not notify through one); a browser whose constructor still throws turns the opt-in off for the page session and says so in a toast. With `prefers-reduced-motion` the ring does not animate and the favicon moves in 10 % steps.

**Workspaces (app.js, `ui/workspace-ui.js`, `ui/workspace-panel.js` over §5.39–§5.42).** The header shows the active workspace after the current-target chip (`data-control="workspace"`: a briefcase, the name cut with an ellipsis, "Default" / "Varsayılan" for Default); below 720 px it sits at the top of the Tools menu instead (`data-control="workspace-menu"`). Either opens the **Workspaces** dialog (its module and `assets/css/workspace.css` load on first use; a failure offers the reload of a stale page like any lazy module): the list (Default first; the active one marked; Switch, Rename inline, Delete with a confirmation — never Default; deleting the active one switches to Default first), a new workspace (created and switched to; empty and taken names — Default's name in the page language included — refused in place); the current workspace's **recent domains** (a click makes one the current target, filled in everywhere, and closes the dialog; Clear the list), **expected CAs** (one per line, each shown as a known CA or as text) and **notes**, both saved as typed (400 ms) into the workspace they were typed in, flushed before a switch or when the dialog closes; and the **hand-over file**: Export with an optional password (twice; ≥ 8 characters; both fields emptied afterwards) downloads `domainscope-workspace-<name>-<stamp>.json` and says whether it is encrypted; Import (a .json read in the browser) asks for the password of a sealed file (a wrong one or a changed file: "Wrong password, or the file was changed after it was exported. Nothing was imported."), then shows what it holds and offers **Import as a new workspace** (a free name, switched to) and, when a workspace of that name exists (Default for a file exported from Default), **Replace "<name>"** after a confirmation. A **switch** asks first when a long job runs (`ui/jobs.js runningJobs`: "Still running here: … Switching to "<name>" stops it"), then forgets the page session and makes the new workspace's most recent domain the current target, and opens the tool on screen again with it filled in (`carryRoute`); every target a tool runs on goes to the top of the active workspace's recent list. The boot waits for `state.ready`; storage unavailable (no localStorage or a memory-only workspace store) is said once in a toast. **Delete all local data** (Settings, About; `deleteAllLocalData`) deletes every workspace with the IndexedDB database and says so ("every workspace (its IndexedDB database too)"), or why not all of it could go. Tests: `tests/e2e/workspaces.e2e.mjs` (offline; 1440 px, 375 px in Turkish and dark, 320 px).

Design: clean, professional dashboard; light/dark via tokens (`prefers-color-scheme` + manual toggle `data-theme`); system font stack + monospace for data; responsive to 360px (tables scroll horizontally inside their container, never the page); visible focus rings; `aria-live` progress; reduced motion honoured (scripted scrolls jump instead of animating: `ui/dom.scrollBehavior()`); keyboard accessible tabs; inline SVG icons (no icon fonts); status colors with text labels (not color-only). Large tables: paginate or incremental render (e.g. 200 rows + "show more").

## 7. CLI `cli/ssl_origin_scan.py` (Python ≥3.8, stdlib only, single file)

Purpose: definitively map hostnames → servers by TLS-probing inventory IPs **with SNI**, bypassing DNS/Cloudflare. Run from a host inside the network (jump box).
```
python3 ssl_origin_scan.py -t targets.txt [-t 10.0.0.0/24 -t web01.internal ...] (-n names.txt | -n host ... | --cert new-cert.pem) [--ports 443,8443] [--workers 64] [--timeout 5] [--json out.json] [--csv out.csv] [--show-all] [--no-color]
    [--baseline previous.json [--fail-on-change]] [--warn-days N] [--notify URL [--notify-format F] [--notify-always] [--fail-on-notify-error]]
```
- targets: same flexible inventory formats as the web app (name+ip lines, `NAME=IP` lines, hosts file, CSV, Ansible INI, JSON) + CIDR ranges (cap e.g. /16 with warning) + hostnames (resolved with getaddrinfo).
  - An address or host name with its own port (`203.0.113.10:8443`, `[2001:db8::1]:8443` — IPv6 needs the brackets —, `web01.example.net:8443`, `NAME=IP:PORT`; in `-t` and in files) is scanned on that port **instead of** `-p`; `-p` applies to every target written without one, and a target listed both ways gets both (`Server.ports`, `None` = the `-p` ports). A port outside 1–65535 or not a number, a bad address in brackets, a bracketed token that is no `[ADDRESS]:PORT` (`[2001:db8::1]8443`), an IPv6 zone id with a port (`[fe80::1%eth0]:8443`) and a CIDR / range with a port are a usage error on the command line and an `INVALID_IP` warning in a file — never silently dropped (in JSON too: such a value is a warning and the object's name is not resolved instead); a server name with a port (`web01.example.net:8443 203.0.113.10`) is a `PARSE` warning and the name is used without it; a host name with a port next to an address (`web01 203.0.113.10 db.example.net:5432`) is a `PARSE` warning and ignored (a host name is resolved only for an entry without an address; without a port there it is a hosts-file alias). A first-token `NAME=HOST[:PORT]` in a file is a target as in `-t` when HOST has a dot or a port is given (`user=root` stays a variable). A time of day in a line (`backup 10:30 203.0.113.10`, `time=10:30`) is ignored, as the web app does. In an Ansible INI context (a line under a `[group]` header or with an `ansible_*=` variable) a port on the first token, the host pattern (`203.0.113.11:2222`, `[2001:db8::5]:2222`, `badwolf.example.com:5309`), is Ansible's SSH port: the host is scanned on `-p` and a `PARSE` warning says so (§5.5, the same rule). `DUPLICATE_IP` compares endpoints, not bare addresses: one address on different ports for different servers is none. The JSON's `servers[].ports` lists the addresses with ports of their own; the "Scanning …" line and the summary header count ip:port endpoints then.
  - CSV headers follow §5.5: the same IP-column rule (`isIpKey`: gateway, DNS, NTP, iLO / iDRAC / IPMI / BMC, MAC, e-mail and URL columns are never server addresses), Turkish name and group headers (`Sunucu Adı`, `IP Adresi`, `Ortam`; accents and `ı` folded), the best-ranked name column, and plain heading lines (`hostname   ip`) skipped. A heading has two or more words and none with a dot or a digit group, so an EC2-style `ip-10-0-1-23.example.net`, `ipv6.example.com` or a lone `node` stays a host name. A value with `@` (an e-mail address) is a `PARSE` warning, never a host to resolve.
  - Unlike the web app, a row with a name but no IP is kept and its name resolved.
- names: from files/args; `--cert FILE` adds the cert's SAN DNS names (wildcards: probe the base domain and any provided names under it) AND enables fingerprint comparison (served cert == new cert → "already updated").
  - `--cert` text (PEM, bare base64) may be UTF-8, UTF-16 with a BOM or UTF-16LE without one, as PowerShell 5.1's `>` writes it, like `-t` / `-n` / `--exclude` files and `lib/x509.js`.
  - Internationalised names (in `-n`, `-t` and inventories) become punycode as in the web app (UTS #46 non-transitional, §5.3): `straße` → `xn--strae-oqa`, never IDNA 2003's `strasse`, which is another registrable name. `ς` stays `ς`; ZWJ / ZWNJ are kept only right after a virama, otherwise the name is invalid (a Persian ZWNJ name is given in its `xn--` form). Ideographic full stops (`。` `．` `｡`) separate labels as in the web app (mapped after lowercasing, so `ΑΣ。x` keeps a final `ς`, and never into a `*.` wildcard); Cherokee letters stay capital as UTS #46 maps them; a label that starts with a combining mark, carries an `xn--` prefix on non-ASCII text or mixes `ß` / `ς` with right-to-left letters is invalid.
- Phase 1: TCP connect check per ip:port (parallel) → skip closed. Phase 2: for each open ip:port × name: TLS handshake with SNI=name, `CERT_NONE`, permissive (`minimum_version` lowest supported, `set_ciphers('ALL:@SECLEVEL=0')` guarded by try), fetch DER via `getpeercert(binary_form=True)`, parse with a built-in minimal DER parser (subject CN, SAN DNS/IP, issuer CN/O, serial, notBefore/notAfter incl. GeneralizedTime, sha256 fingerprint). Also probe once with no SNI to learn the default cert.
  - Handshakes go name by name across the endpoints, and at most `MAX_PER_ENDPOINT` (4) run against one ip:port at a time, whatever `--workers` is: dozens of simultaneous connections from the jump host trip per-client connection limits (nginx stream `limit_conn`, HAProxy `src_conn_cur`, WAF appliances). A handshake waiting for its turn holds no worker thread. An endpoint whose last four handshakes all timed out (a tarpit, a balancer without a backend, an SNI router whose backend for the remaining names hangs) is not held to the cap, so it costs a few timeouts rather than one per four names; the cap is back once a handshake there ends otherwise.
  - Works rule: a name the server refuses (alert, close, reset) while other handshakes on the same ip:port complete is `NOT_HOSTED` "server refused this name". A close, reset or refused connection (no TLS alert) is first retried once, one handshake at a time per endpoint, so a limiter's resets never turn hosted names into `NOT_HOSTED`; a TLS alert is the server's answer and is not retried.
- Status per (server, port, name): `UPDATED` (serves the new cert), `NEEDS_UPDATE` (served cert covers the name but is not the new cert — show its expiry), `ORIGIN_CERT` (… a Cloudflare Origin CA certificate: issuer O `CloudFlare, Inc.` with OU / CN `CloudFlare Origin SSL [ECC ]Certificate Authority`, the real roots' DNs), `PRIVATE_CERT` (… a self-signed certificate — same subject and issuer DN and, when both are present, key identifier — or one issued by a CA given with `--private-ca FILE`: PEM / DER / P7B CA certificates, matched by issuer DN and AKI = SKI; every certificate of each file counts), `NOT_HOSTED` (served cert does not cover the name / only default cert), `TLS_ERROR`, `CLOSED`, `TIMEOUT`.
  - ORIGIN_CERT and PRIVATE_CERT apply only when the certificate is of another kind than every new one (`HostedClassifier`): rolling out an Origin CA (or self-signed / private-CA) certificate keeps the older ones of that family NEEDS_UPDATE, and a certificate with a new one's issuer DN is always NEEDS_UPDATE. `--strict-public` restores the old rule (all of them NEEDS_UPDATE). They are listed in their own summary sections with an explanation, in the JSON (`servers[].originCert` / `privateCert`, `summary.serversWithOriginCert` / `serversWithPrivateCert`, `certificates{}.kind` / `privateCa`, `options.strictPublic` / `privateCa`) and in the CSV `status` column; the roll-up order is NEEDS_UPDATE > UPDATED > ORIGIN_CERT > PRIVATE_CERT > TLS_ERROR > … `CLOSED` comes only from the phase-1 port check; a connection refused during phase 2 (the port was open a moment before: a connection limiter, fail2ban, a restart) is a `TLS_ERROR`, so such a server is listed under handshake errors, never as "not hosting any of the names".
- Output: human-readable summary grouped by server ("servers that need the new certificate: N") with colors (auto-disabled when not a TTY/`--no-color`/`NO_COLOR`), plus `--json` / `--csv`. Exit code 0 unless usage error (2) or a report file that could not be written after the scan (3); `--fail-on-needs-update` → exit 1 when any NEEDS_UPDATE (for CI; ORIGIN_CERT and PRIVATE_CERT servers count only with `--strict-public`); `--fail-on-change` → 4 and `--fail-on-notify-error` → 5 (see Monitoring below). When several apply: 3, then 5, then 4, then 1.
  - A `--json` / `--csv` file that cannot be written (missing directory, read-only, locked by Excel) is a usage error before the scan; the check truncates nothing and leaves no file behind.
  - If a report still cannot be written after the scan, the error is printed, the other report and the summary are still written, and the exit code is 3 (it wins over 1).
- Robust: Ctrl-C handling, per-connection timeout, thread pool, IPv6 support, no stack traces for expected errors.
- Untrusted certificates: any server in a swept range can answer with any certificate.
  - A certificate the parser cannot read (malformed, out-of-range times, oversized OIDs) becomes a `TLS_ERROR` row (`unparseable certificate: ...`), or a `PARSE_ERROR` for `--cert`, never a crash.
  - The summary and the warnings escape control, format and line-separator characters of certificate text and inventory names (`\x1b[2K` is printed as the text `\x1b[2K`), so a subject cannot move the cursor, rewrite lines or set the window title. The JSON keeps the exact values.
  - CSV text cells follow the web app's `toCsv` rule (§5.16): a cell starting with `=` `+` `-` `@` TAB or CR gets a leading `'`, so a CN such as `=HYPERLINK(...)` stays text in Excel. Control characters and bidi embeddings / overrides / isolates are escaped; ZWNJ, ZWJ, the soft hyphen and LRM / RLM of real names stay in a file, and only `--csv -` escapes everything the summary does. Numbers (port, days left) are left as they are.
- `--exclude ADDR [ADDR ...]` (repeatable) takes IPs, CIDRs (v4 / v6), ranges, `-` for stdin, or a file of them (`#` comments).
  - Host names are refused (exit 2).
  - IPv4-mapped addresses match both ways.
  - It is applied after names are resolved and before any connection.
  - Reported in the summary, in the JSON (`excluded[]`, `summary.excludedAddresses`, `options.exclude`) and in the CSV (rows with `probe=excluded`, status `EXCLUDED`). A rule that matches nothing is a warning.
- Numeric "host names" that the resolver would read as IPv4 are refused: all digits, hex, octal, dotted numeric, full-width digits, ideographic dots, a trailing dot (`2026092401`, `127.1`, `0x7f.0x1`).
  - In `-t`, NAME=IP and `-n` this is exit 2; from a file, the entry is skipped with a warning. They never reach the resolver.
  - IPv4 parts with a leading zero (`010.0.0.1`) are refused as ambiguous.
  - A typo'd range or CIDR (`10.0.0.5-300`, `10.0.0.5-9x`, `10.0.0.5-09`, `10.0.0.0/33`) is a valid LDH name but never resolved: exit 2 on the command line ("not a valid IP range / CIDR", not "file not found"), `INVALID_IP` in a file. A name whose last label or range end starts with a letter (`10.0.0.5-web.example.com`, `192.0.2.1-db`) is still a host name.
  - 0.0.0.0/8, multicast and broadcast addresses are never scanned.
- Monitoring between visits, for cron / scheduled tasks (no infrastructure): `load_baseline()`, `compare_reports()`, `expiring_certificates()`, `build_monitor()` → `MonitorResult`, `build_notification()`, `send_notification()`.
  - `--baseline FILE` is a previous `--json` report (UTF-8 or UTF-16 with a BOM), read and checked before the scan: a file that is not JSON, not a report of this tool (`"tool": "ssl_origin_scan"`), written by another major version, or with a malformed row (`ip`, `port`, `status`, `probe`, `certSha256`) or a `names` / `newCertificates` / `options.ports` that is not a list is a usage error (exit 2) naming the problem. `--baseline -` is refused. The same file may be given to `--json`: it is read before the scan and replaced after it (a temporary file in the same directory renamed over it, so a write that fails keeps the last baseline whole; a directory that does not take a new file is exit 2 before the scan), and while it does not exist (the first run) there is nothing to compare (`baseline.missing: true`); a missing baseline that is not also the `--json` file is exit 2. The same file as `--csv` is exit 2 (a CSV would overwrite it and cannot be compared).
  - `compare_reports(before, after)` compares per (ip, port, name); addresses are normalised (`2001:0DB8::5` = `2001:db8::5`), servers sharing an address give one change listing them all. Each change is `{kind, scope, transition, servers, ip, port, probe, name, before, after, certChanged}`:
    - scope `name`: a name probed in only one report (`appeared` / `disappeared`, with its status counts); its rows are not listed one by one;
    - scope `endpoint`: an ip:port scanned in only one report (`after.status: EXCLUDED` when `--exclude` removed it) or whose port state moved (OPEN / CLOSED / TIMEOUT, `transition` as for rows), with the name counts of the open side;
    - scope `row` (endpoint open in both): a status that moved (`status`, `transition` = `failed` to TLS_ERROR / TIMEOUT / CLOSED, `recovered` from one, `failing` from one of them to another, `regressed` UPDATED → another covering status, `updated` the reverse, `unhosted` covering → NOT_HOSTED, `hosted` the reverse, else `changed`), another served certificate with the same status (`cert`, by SHA-256 fingerprint; for covering rows only, the no-SNI probe's included — a NOT_HOSTED row's fallback certificate, with or without SNI, is not a change: proxies such as Traefik or ingress-nginx make theirs anew on every restart, a default vhost often carries another site's certificate that renews on its own schedule), or a row only one report has.
    - "Covering" is UPDATED, NEEDS_UPDATE, ORIGIN_CERT, PRIVATE_CERT and any status this version does not know (a later version's certificate kinds), so reports of other minor versions compare (a report from before ORIGIN_CERT / PRIVATE_CERT compares too: a server that was NEEDS_UPDATE there and is PRIVATE_CERT now is a `changed` status); unknown probe kinds are skipped.
    - A `failing` move (CLOSED ↔ TIMEOUT, TLS_ERROR ↔ TIMEOUT) served nothing either way, and on a sweep with a short `--timeout` a refused connection and a timeout can take turns: it is listed (summary, JSON, message — after the other changes: `build_monitor` orders them once with `order_changes()`, so every cap cuts these moves first) but does not count (`counts_as_change()`, `notable_changes()`): it never triggers `--notify` or `--fail-on-change`, nor holds a baseline back.
  - `--warn-days N` (0–3650, off by default) lists served certificates that cover a probed name (covering rows, also the no-SNI probe) and expire within N days or have expired, soonest first: `{sha256, subjectCN, issuer, serialHex, notAfter, daysLeft, expired, isNewCert, endpoints: [{server, ip, port, names, defaultCert}]}`.
  - Output: the summary opens with "Changes since the baseline (FILE, scan of …): N" (a tag per change — FAILED, REGRESSED, UNHOSTED, GONE in red; RECOVERED, UPDATED in green; HOSTED in green only when the name is now served with the new certificate, else yellow; NEW; CERT, CHANGED in yellow; FAILING dimmed — at most 50 without `--show-all`, plus a note counting the FAILING moves and notes when the ports or the `--cert` differ from the baseline's) and "Served certificates expiring within N days". The `--json` document gains `baseline` (`{file, missing, version, startedAt, finishedAt, portsAdded, portsRemoved, newCertificateChanged}`) and `changes` with `--baseline`, `expiring` and `options.warnDays` with `--warn-days`; without them it is unchanged. `--fail-on-change` (needs `--baseline`) exits 4 when there is any change that counts. A reader of the summary that goes away (`| head`, `| grep -q`) is not an error: the rest of stdout goes to the null device and the notification and the baseline still follow; stdout failing otherwise (a full disk behind `> file`) is an error line and exit 3, after them.
  - `--notify URL`, or `DOMAINSCOPE_NOTIFY_URL` so the URL stays out of the shell history, POSTs a short summary when something changed or expires (after every run with `--notify-always`). The format follows the URL (`--notify-format auto|slack|teams|discord|telegram|googlechat|json` overrides it): Slack incoming webhooks and Discord's `…/slack` endpoint → `{text}` (`& < >` escaped, the lines in a code block, so certificate text never becomes a mention or a link); Slack Workflow Builder webhooks (`hooks.slack.com/triggers/…`) get the same `{text}`, which the workflow reads as a variable named `text`; Teams incoming webhooks (`*.webhook.office.com`, `outlook.office.com`) and Power Automate / Logic Apps workflows (`*.logic.azure.com`, `*.api.powerplatform.com`) → a message with one Adaptive Card of plain TextRuns; Discord `/api/webhooks/` and `/api/v10/webhooks/` → `{content, allowed_mentions: {parse: []}}`; Telegram `https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>` → `{chat_id, text}` with `chat_id` moved from the query into the body; Google Chat space webhooks (`chat.googleapis.com`) → `{text}` like Slack's, but with `<` turned into the lookalike `‹` instead of escaped (Chat reads `<users/all>` as a mention and does not document decoding `&lt;`); any other URL → generic JSON `{tool, version, title, text, finishedAt, summary, baseline (its `file` as a base name, never the local path), changes (≤ 500), changesTotal, warnDays, expiring (≤ 50 certificates, each with ≤ 20 endpoints and `endpointsTotal`), expiringTotal}`. Chat texts fit the service's limit (Discord 2,000, Telegram 4,096) with at most 20 changes and 10 certificates, then "… and N more"; every line is cut at 400 characters and the footer names the ports as ranges (`443,8000-9023`), at most 8 of them, then "+N more".
  - The URL is checked before the scan (http / https, no spaces; a Telegram URL needs `/bot…/sendMessage` and `chat_id`; non-ASCII in its path or query is sent percent-encoded as UTF-8, `ascii_url()`) and is a credential: it is never printed or logged — only its host — and error texts and response bodies are redacted (`redact_url`: the URL with and without its user info, the path, query and fragment, the query values, the path segments that may be tokens — 8+ characters or a digit, other than the services' path words such as `services`, `webhooks`, `sendMessage` and API versions such as `v10`, as written, decoded and percent-encoded, and for Telegram's `bot<token>` also the token alone and its part after the `:` — the user name and password, and the Basic `Authorization` value made of them, base64 included). `user:password@` in the URL is sent as HTTP Basic authentication (`split_credentials`); urllib never sees it, since it would read `password@host` as a port and print it. `http://` to a non-loopback host is a warning. `urllib` only, certificate-verified HTTPS, the system proxy settings, no redirects (a redirected POST would arrive as a GET), 10 s timeout, one retry after 2 s (or a 429's Retry-After, ≤ 10 s) for network errors, 5xx and 429 — a 4xx is the webhook's answer. A failed notification is an `error:` line on stderr (also with `-q`) and changes the exit code only with `--fail-on-notify-error` (5); a delivered one prints "Notification sent (format, host)" unless `-q`.
  - When the `--json` file is also the baseline, the notification goes out before the file is replaced. If a message that carried changes is not delivered (or Ctrl-C stops it), the file keeps the previous report and stderr says so ("kept the previous baseline in FILE …: the N changes will be reported again on the next run"), so an outage of the chat service never loses a change; a message with only expiring certificates does not hold the baseline back, since they are listed again on every run. The cron example writes the summary to a file (`-q > last.txt`), so cron mails only errors.
  - Tests: `BaselineTests`, `ExpiryTests`, `ChangeSummaryTests`, `NotifyFormatTests`, `NotifyDeliveryTests` (a local `http.server` capturing each format's payload, retries, timeouts, redaction, Basic authentication from the URL, a non-ASCII URL, a failed delivery keeping the baseline for the next run), `MonitorCliTests` (exit codes, the same file as baseline and report, a writable directory, usage errors, FAILING moves, a summary reader that goes away, the documented commands) and `MonitorIntegrationTests` (two runs against real local TLS servers sharing one state file).
- The zone hand-off files (`zone-targets.txt` with `server ip` lines and host names, and `zone-names.txt`, both with a `#` header) load as `-t` / `-n` files. A dedicated `--zone FILE` option is not built yet.
- Tests (`tests/python/test_ssl_origin_scan.py`; certificate kinds and ports in `test_cert_kinds_ports.py` with the `cli_*_wild` / `cli_private_ca*` / real Origin CA root fixtures; web parity in `test_inventory_targets.py`): DER parser vs `tests/fixtures/expected.json`; inventory parsing; wildcard matching; **integration**: start local TLS servers on 127.0.0.1 ephemeral ports (threads, `ssl.SSLContext.sni_callback` selecting fixture cert/key by SNI; default cert = cn_only) and assert statuses for names; `--cert` fingerprint UPDATED path.

## 8. Quality bar
- Unit tests for every lib (happy path + edge cases); all green.
- E2E (integrator): headless Edge/Chrome via CDP driving each view on `http://localhost:8080` against live APIs, screenshots saved to `tests/e2e/screenshots/` (gitignored), zero console errors, zero CSP violations. `tests/e2e/verify.e2e.mjs` (run right after `scan` by `run-all.mjs`) is **offline**: a fake DoH zone and a fake Globalping inside the page plus a CDP network guard, so it spends 0 real probes and asserts that nothing leaves the page. The only live Globalping check is the manual `tests/live/globalping-smoke.mjs` (public targets only, ≤ 10 probes; `--dry` spends none). `tests/e2e/dane.e2e.mjs` (right after `cert`) is offline the same way: a fake DoH zone with MX, TLSA, AD and RRSIG answers. `tests/e2e/ptr.e2e.mjs` (right after `ip`) is offline too: a fake DoH table (PTR, A, MX, SERVFAIL), a fake RIPEstat announced-prefixes answer and RDAP bootstrap in the page, and it follows the hand-offs into Servers, Subdomains (the exact scan and its origin panel's link back) and Domain Health's FCrDNS rows. `tests/e2e/carry.e2e.mjs` is offline too (example.com answered in the page, a CDP network guard): the page session across Domain Health, DNS Lookup and the other tools, the kept report and its note (language switch, Run again), a certificate from SSL Targets without a note, a newer target over Domain Health's kept report (the report and its note still shown, Copy link sharing the report, the bare route later bringing it back under its own params), the second round (a newer target over DNS Lookup's and Bulk Resolve's kept results, both still shown; Bulk Resolve's Run again; the same target run again over a job about several names), three targets in a row (every tool's box follows the latest one, a draft stays; DNS Lookup likewise under two Domain Health runs), the chip, "Delete all local data" (Bulk Resolve's job too, also on screen), a carried link in a new tab, and the 375 px layout (a long host name cut in the middle of the chip). CI runs the offline suites (shell, zone, verify, dane, ptr, carry; global with `--offline`: only its fake-DoH verdict steps; subdomains with `--offline`: its emulated-zone groups, the results tabs included, in a browser that resolves no host name but the local server; ip, lookup and health with `--offline`: only their offline groups) on ubuntu-latest with the runner's Chrome (`npm run test:e2e:offline`), and the Pages deploy runs CI first. The shell suite also serves the assembled Pages bundle and checks that a tab left open across a deploy gets the reload offer and then the new version, and that a view failing to load offline (or blocked) gets the plain network error instead (in a tab without service worker); then, on a bundle of its own, that the service worker installs and precaches the version (no CSP violation), that with the network gone (the server drops every request) the app reloads from the cache and Certificate, Zone File and Servers work while DNS Lookup shows the offline note and sends nothing (one toast however often Run is clicked) and a shared Domain Health link only fills the form, that a second deploy brings "Update ready — Reload", which loads it and drops the old version's cache, and that so does the same version assembled again with one file changed. It also prints from dark mode (print media emulated): the light palette, no shell or controls, every Disclosure opened and the print header on `beforeprint`, all of it undone on `afterprint`, and a `Page.printToPDF` PDF. Copy summary is checked offline through a clipboard recorder (`stubClipboard` in scan.e2e.mjs): in `health.e2e.mjs` (Markdown, plain text, Turkish, the clipboard-refused dialog, and a second check stopped at once: the button off while it runs, then the report on screen copied and printed with its own link), in the emulated zone of `subdomains.e2e.mjs`, in `zone.e2e.mjs` (the worst problems as the Problems tab words them, a bare `#/zone` link), `cert.e2e.mjs` (a bare `#/cert` link) and the offline certificate scan of `scan.e2e.mjs` (the servers that need the certificate by name, the inventory tooltip, a link with only the domain; nothing to copy after a cancelled scan; crt.sh answering 400 in the page: the failed passive source said right under the host count), and the offline group of `ip.e2e.mjs` (every source failing: "2 lookups failed" / "Direct · lookup failed", Turkish after a re-mount). The shell suite's gallery checks `CopyButton`'s own toast text and `onFail`, and the table's print styles (header labels, `break-word`). The desktop steps check that the start route links two stylesheets, that the views' sheets end up in cascade order and that the development checkout registers no worker. It also runs a Bulk Resolve against a slow DoH zone answered in the page and checks the signals outside the view (title prefix, nav ring, favicon badge, 10 % steps with reduced motion, the 30 s "Notify me when done" with a fake Notification API: permission asked only on the click, a dismissed prompt not called blocked, a refusal said with the keyboard focus on that sentence, one notification when the job ends elsewhere, a constructor that throws turning the opt-in off with a toast, never offered or asked with `navigator.userAgentData.platform` 'Android' and `mobile` false (Chromium on an Android tablet); a prompt that answers after 300 ms, the focus kept on the button for a dismissed or granted prompt, every signal gone afterwards, no CSP violation for the `data:` favicon). The ip, lookup and health suites have an offline group that always runs (`--offline` skips their live groups): IP Intel with RIPEstat / ipwho.is / reverse DNS answered in the page (429 → "⚠ n/a" cells, chips, row and chip Retry asking only the failed sources, a PTR SERVFAIL, Stop leaving no chip pending, a Retry in flight across a new lookup, the zero-count sentence, exports in English and Turkish), DNS Lookup on an emulated apex (the "No records" line, shared flags and resolver, a 429 from every resolver and its Retry while a slower type still runs), and Domain Health's RDAP card out of reach and retried (RDAP requests only, no DNS query).
- No `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` with dynamic data anywhere (grep-able).
