# DomainScope — baseline build specification

> Written before implementation to give every module a binding contract. Modules have since been extended (backward-compatibly); **where this document and the code differ, the code is the source of truth.** Last synced with the code on 2026-09-24 (discovery engine v2 and the wired wordlist system — levels up to Huge, locale packs, custom and learned lists, safe sweep command: §1, §2, §3, §5.6, §5.8, §5.9, §5.11, §5.12, §5.17, §6; then SSL Targets › Verify, the Globalping check from the internet, ROADMAP P0.1 Phase A: §1, §2, §3, §4, §5.4, §5.17, §5.18, §5.19, §6, §8).

## 0. Why this exists (product context — read this)

The primary persona is a DevOps engineer managing **hundreds of servers**. A customer sends a renewed SSL certificate (e.g. `*.example.com`) and they must find **which subdomains exist, what IPs they resolve to, and which of their own servers need the new cert installed** (e.g. 10 of 300 servers). Existing online tools disagree (5 vs 8 vs 9 subdomains) and **Cloudflare's orange cloud (proxy) hides origin IPs**. It is also meant to be a general **DNS toolbox**: global DNS (multi-resolver + geo view), full record lookup, bulk resolve, IP intel, domain health — "everything useful on the DNS side".

Deliverable: an **open-source static web app hosted on GitHub Pages** (no backend; everything runs in the visitor's browser against CORS-enabled public APIs) **plus** a companion stdlib-only Python CLI (`cli/ssl_origin_scan.py`) that is run *inside the user's network* to TLS-probe their server IPs with SNI — the only reliable way to find origins behind Cloudflare.

UI languages: Turkish + English (default by `navigator.language`, toggle). Turkish is first-class; the project is for everyone.

## 1. Hard constraints

- **No dependencies, no build step, no CDN.** Vanilla ES modules (`<script type="module">`), plain CSS. Pure libs must run in both browsers and Node 22 (`package.json` has `"type": "module"`).
- **Libraries in `assets/js/lib/` are DOM-free** (no `document`, `window`, `localStorage`). Use `globalThis.fetch`, `globalThis.crypto` only via injectable options where noted. UI code lives in `assets/js/ui/` and `assets/js/views/`.
- **Dependency injection for I/O:** every network function accepts `{ fetchImpl = globalThis.fetch, signal }` (and DNS-dependent functions accept a `dns` client object). This makes them unit-testable with mocks.
- **Every async network op supports `AbortSignal`** and timeouts.
- **Security:** Untrusted data (subdomains from CT logs, TXT records, RDAP, API responses) must **never** reach `innerHTML`. Build DOM with `textContent`/`createElement` only. `index.html` has a CSP meta: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https:; base-uri 'none'; form-action 'none'; manifest-src 'self'`. No inline `<script>`/`<style>`/`style=""` attributes in HTML (setting `el.style.x` from JS is OK).
- **Privacy:** certificate files and server inventory never leave the browser. The private key must never be needed; if a PEM contains a private key, warn and ignore it (never display it). The one feature that sends user-chosen data to a third party is SSL Targets › Verify: only after a click and a per-page-session consent, and only (public IP, host name, port) pairs — never a private address, the certificate or an inventory server name (§3 Globalping, §5.19).
- Code style: 2-space indent, semicolons, single quotes, `const`/`let`, JSDoc on every export, small focused functions. Python: PEP 8, type hints, stdlib only, Python ≥ 3.8 compatible.
- Tests: `node --test "tests/js/*.test.js"` (= `npm test`, what CI runs; node:test + node:assert/strict; each file in its own process), `python -m unittest discover -s tests/python -v`. `node --test tests/js/` runs the same files through `tests/js/index.js`, which starts one `node --test` process per file so results never depend on file order. Tests must not hit the network (mock `fetchImpl`). Live/manual checks go in `tests/live/*.mjs` (not run in CI).
- Test data is generic: reserved names (`example.com/.net/.org`, `example-test.com.tr`) and documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). `tests/js/repo-hygiene.test.js` fails on any other IPv4 literal that is not well-known public infrastructure, and (locally) on anything matching the gitignored `.private-denylist`.

## 2. Repository layout

```
index.html                    # SPA shell (CSP meta, tabs, <script type=module src=assets/js/app.js>)
favicon.svg
.nojekyll
package.json                  # {"name":"domainscope","private":true,"type":"module","scripts":{"test":"node --test \"tests/js/*.test.js\"","test:py":"python -m unittest discover -s tests/python -v","serve":"node tests/e2e/serve.mjs 8080"}}
assets/css/style.css          # design system (tokens, light/dark, components)
assets/css/views/{subdomains,scan,cert,global,lookup,bulk,ip,health,inventory,about}.css   # per-view styles
assets/js/app.js              # bootstrap: router, i18n, theme, shared state
assets/js/i18n.js             # t(key, params), setLang, registerStrings(lang, dict)
assets/js/state.js            # shared app state (inventory, settings) + localStorage persistence (try/catch)
assets/js/ui/dom.js           # h(tag, attrs, ...children) safe DOM builder, clear(el), etc.
assets/js/ui/components.js    # DataTable, Tabs, ProgressBar, Badge, CopyButton, FileDrop, Toast, Modal, etc.
assets/js/ui/download.js      # downloadText(filename, text, mime)
assets/js/ui/flag.js          # Flag(countryCode) with a globe fallback where the OS has no flag emoji
assets/js/ui/verify-panel.js  # the SSL Targets › Verify tab body (a ui/ module: every views/*.js is a routed view); styles in assets/css/views/verify.css
assets/js/views/{subdomains,scan,cert,global,lookup,bulk,ip,health,inventory,about}.js   # each exports {id, titleKey, icon, mount(container, ctx), unmount?()} + registers its i18n strings; subdomains is the default route
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
assets/js/lib/dnswire.js
assets/js/lib/resolvers.js
assets/js/lib/doh.js
assets/js/lib/propagation.js
assets/js/lib/sources.js
assets/js/lib/scanner.js
assets/js/lib/ipintel.js
assets/js/lib/rdap.js
assets/js/lib/health.js
assets/js/lib/export.js
assets/data/                  # self-hosted wordlist tiers (wordlist-base.txt = smart, wordlist-{large,huge}.txt.gz), locale/<cc>.txt packs, wordlist-manifest.json, README (sources) + THIRD_PARTY_LICENSES.txt
tools/build-wordlists.mjs     # maintainer tool: rebuilds assets/data from pinned upstream lists (+ tools/locale-data.mjs)
cli/ssl_origin_scan.py
tests/fixtures/               # ALREADY EXISTS — see §4 (+ globalping/: trimmed, scrubbed real measurements, README)
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
| `certspotter` | `https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names` | JSON array `{id, tbs_sha256, cert_sha256, dns_names[], pubkey_sha256, not_before, not_after, revoked}`; paginate with `&after={last id}` (max 5 pages); unauthenticated quota: about 10 full-domain (`include_subdomains=true`) queries per hour per IP (100/h for single-hostname queries, which the scan never sends); 429 → rate-limit error and later pages are skipped. |
| `hackertarget` | `https://api.hackertarget.com/hostsearch/?q={d}` | text lines `host,ip`. Errors come as 200 text like `API count exceeded - Increase Quota with Membership` or `error ...` → treat as error. Free: ~50 req/day per IP (shared with reverseiplookup). Provides IP hints. |
| `anubis` | `https://anubisdb.com/anubis/subdomains/{d}` | JSON array of names (may contain `*.x`). (`jldc.me` is dead — do not use.) |
| `otx` | `https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns` | JSON `{passive_dns:[{hostname,address,record_type,first,last}]}`. Historical A records = great origin hints (pre-Cloudflare IPs). Anonymous → often 429 `{"detail":"Anonymous access ... limited"}` → rate-limit error, non-fatal. |
| `thc` | `POST https://ip.thc.org/api/v1/lookup/subdomains` body `{domain, limit: 100, page_state}` (sent as `text/plain` → no preflight) | ACAO `*`. JSON `{domains:[{domain, last_seen_on, …}], next_page_state, matching_records}`; 100 names per page, paginate by sending `next_page_state` back as `page_state` (`''` on the last page), max 10 pages (1,000 names) per domain, pages 2 s apart. Anonymous token bucket of about 250 requests per IP refilling 1 every 2 s. Provides `lastSeen` per name; `truncated` / `available` when more records exist. |

NOT usable from browser (no CORS): urlscan.io, subdomain.center, Wayback CDX, threatminer, api.cloudflare.com/client/v4/ips, jldc.me.

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
- `https://ipwho.is/{ip}` (ACAO *) — fallback geo/ASN. `https://ipinfo.io/{ip}/json` (ACAO *; tokenless quota). `https://ipapi.co/{ip}/json/` (reflects origin; strict daily quota).
- `https://api.hackertarget.com/reverseiplookup/?q={ip}` (ACAO *) — domains on same IP (quota shared with hostsearch).
- RDAP: IANA bootstrap `https://data.iana.org/rdap/dns.json` (ACAO *), registry servers e.g. `https://rdap.verisign.com/com/v1/domain/{d}` (ACAO *), fallback `https://rdap.org/domain/{d}` (ACAO *, redirects). IP RDAP e.g. `https://rdap.db.ripe.net/ip/{ip}`. `.tr` has no RDAP in bootstrap → report `unsupportedTld`.

### CDN IP ranges (fetched 2026-09-23 from official sources — use verbatim)
Cloudflare v4: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
Cloudflare v6: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32
Fastly v4: 23.235.32.0/20, 43.249.72.0/22, 103.244.50.0/24, 103.245.222.0/23, 103.245.224.0/24, 104.156.80.0/20, 140.248.64.0/18, 140.248.128.0/17, 146.75.0.0/17, 151.101.0.0/16, 157.52.64.0/18, 167.82.0.0/17, 167.82.128.0/20, 167.82.160.0/20, 167.82.224.0/20, 172.111.64.0/18, 185.31.16.0/22, 199.27.72.0/21, 199.232.0.0/16
Fastly v6: 2a04:4e40::/32, 2a04:4e42::/32

### Globalping (verified 2026-09-24; the SSL Targets › Verify tab)
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
export function isGloballyRoutable(ip) -> bool          // what a probe on the public internet (Globalping, later InternetDB) can reach. v4: false when isPrivateIP or in
                                                        // 192.0.2/24, 198.51.100/24, 203.0.113/24, 192.88.99/24, 224/4, 240/4; v6: ALLOWLIST, true only inside 2000::/3 and
                                                        // outside 2001::/32 (Teredo), 2001:2::/48, 2001:10::/28, 2001:20::/28, 2001:db8::/32, 2002::/16, 3fff::/20;
                                                        // mapped v4 → the v4 rules; invalid → false. isPrivateIP keeps its app-wide meaning ("an internal address")
export function reversePtrName(ip) -> string            // '4.3.2.1.in-addr.arpa' / nibble 'ip6.arpa'
export const RANGES_UPDATED = '2026-09-23'
export const PROVIDERS = [ { id, name, category: 'cdn'|'waf'|'platform'|'loadbalancer'|'hosting', hidesOrigin: boolean, certManagedByProvider: boolean, cidrs: string[], cnameSuffixes: string[] } ]
  // must include: cloudflare (IP ranges above + cname 'cdn.cloudflare.net'), fastly (ranges above + fastly.net, fastlylb.net), cloudfront (cloudfront.net), akamai (akamaiedge.net, akamai.net, edgekey.net, edgesuite.net, akamaized.net, akamaihd.net, akamaitechnologies.com), azure-frontdoor/cdn (azurefd.net, azureedge.net, trafficmanager.net? -> separate), imperva (incapdns.net, impervadns.net + official ranges only if verified), sucuri (sucuri.net cname only unless verified), stackpath, bunny (b-cdn.net), keycdn (kxcdn.com), cdn77 (cdn77.org, cdn77.net), edgio/edgecast (edgecastcdn.net), medianova (mncdn.com, mncdn.net — Turkish CDN), gcore (gcdn.co), and platforms: aws-elb (elb.amazonaws.com), aws-s3 (s3*.amazonaws.com), azure-appservice (azurewebsites.net), azure-trafficmanager (trafficmanager.net), github-pages (github.io), heroku (herokuapp.com, herokudns.com), vercel (vercel-dns.com, vercel.app), netlify (netlify.app, netlify.com), google-hosted (ghs.googlehosted.com, googlehosted.com), firebase (web.app, firebaseapp.com), shopify (myshopify.com), wpengine (wpengine.com), pantheon, render (onrender.com), fly (fly.dev), railway, digitalocean app (ondigitalocean.app). Only add IP ranges you verified from an official source in this session.
export function matchProviderByIP(ip) -> provider|null
export function matchProviderByCname(hostname) -> provider|null        // suffix match on label boundary
export function classifyResolution({ status, ipv4 = [], ipv6 = [], cnames = [] }) -> {
  kind: 'cloudflare'|'cdn'|'platform'|'direct'|'private'|'unresolved'|'nxdomain',
  provider: provider|null, hidesOrigin: boolean, certManagedByProvider: boolean, dangling: boolean /* CNAME chain present but final target NXDOMAIN/no address */, reasonKey: string /* i18n key e.g. 'class.cloudflare.ip' */
}   // priority: nxdomain(no cname) > dangling(unresolved) > cloudflare > cdn/waf > platform/loadbalancer > private(all IPs private) > direct
```

### 5.5 `lib/inventory.js`
```js
export function parseInventory(text) -> { servers: Server[], warnings: Array<{ line, code: 'NO_IP'|'INVALID_IP'|'DUPLICATE_IP'|'PARSE', text }>, stats: { lines, servers, ips } }
Server = { id: string /* stable: name or first ip */, name: string, ips: string[], groups: string[], line: number }
  // Accept: "name ip [ip...]", "ip name", bare "ip", /etc/hosts "ip name alias...", CSV/TSV with header (columns like name/host/hostname/server, ip/ip_address/public_ip/private_ip/ipv4/ipv6/address), Ansible INI ("web01 ansible_host=1.2.3.4", [group] headers → groups), simple Ansible YAML (name:\n  ansible_host: 1.2.3.4), JSON (array/object: any string values that are IPs; name from name/hostname/host/Name/tags.Name), comments (#, ;, //). Same name on several lines → merge IPs.
export function buildIpIndex(servers) -> Map<string /* ip */, Server[]>
export function lookupServers(ips, index) -> Array<{ server: Server, ip: string }>
```

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
export function parseCustomWordlist(text) -> { labels: string[], rejected: string[] }   // one entry per line / comma / whitespace, '#' comment lines skipped, lowercased, deduped, capped at 200,000
export function localesForDomain(domain) -> string[]   // from the last label (the ccTLD), e.g. 'example.com.tr' → ['tr'], 'example.ch' → ['de','fr','it'], 'example.com' / 'example.co.uk' → []
export function clearWordlistCache()
```
Data files, sources and licences: `assets/data/README.md` (built by `tools/build-wordlists.mjs` from SecLists, bitquark, commonspeak2, dnsgen and altdns; MIT / Apache-2.0; the full licence texts ship as `assets/data/THIRD_PARTY_LICENSES.txt`, linked from About). Build-time sizes (`wordlistInfo()`; `tests/js/wordlist-info.test.js` keeps them equal to the files): small 159 (built in) · smart 7,000 (`wordlist-base.txt`, 42,399 B) · large 50,000 (`wordlist-large.txt.gz`, 182,788 B) · huge 130,000 (`wordlist-huge.txt.gz`, 588,172 B). The three files are prefixes of one master ranking (base ⊂ large ⊂ huge). Locale packs (original MIT curation, ASCII-folded, 83–283 labels): tr 283, de 181, fr 171, es 180, pt 169, it 152, nl 124, pl 127, ru 126, ar 128, ja 83, zh 93.

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

Current wiring (code wins): the scanner builds each scanned apex's list with `loadWordlist(level, { domain: apex, locales, extra: [...custom, ...learned], fetchImpl, signal, onInfo })` and caches it per (level, locale set) — see §5.12. The Subdomains view offers every level (Off / Small / Smart / Large / Huge), the locale choice (auto from the domain ending / a manual list / none), a custom wordlist (pasted or a `.txt` file read in the browser; kept in `sessionStorage` under `ssds.wordlist.custom`, in memory when longer than 2,000,000 characters; files up to 5 MiB) and the learned store (`localStorage`, `ssds.learned.labels`, **opt-in, off by default**): when switched on, each finished scan records `learnedLabelsFromScan(result)` for the hosts under the scanned domains, and the next scan passes the 1,000 top-ranked labels as `learnedLabels` — never at level Off. The labels stay in the browser, but a later scan sends them as DNS lookups (`label.<domain>`), so resolvers and that domain's name servers see them. SSL Targets reuses the same three settings. "Delete all local data" (`state.clearAll()`) removes every `ssds.*` key from both storages.

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
  A/AAAA: data = ip string (canonical) · CNAME/NS/PTR: data = target (lowercase, no trailing dot) · MX: { preference, exchange } · TXT: data = string[] (character-strings, UTF-8 decoded) · SOA: { mname, rname, serial, refresh, retry, expire, minimum } · SRV: { priority, weight, port, target } · CAA: { flags, tag, value } · DS: { keyTag, algorithm, digestType, digest /* hex */ } · DNSKEY: { flags, protocol, algorithm, publicKey /* base64 */, keyTag /* RFC 4034 App. B */ } · RRSIG: { typeCovered, algorithm, labels, originalTtl, expiration: Date, inception: Date, keyTag, signerName, signature /* base64 */ } · TLSA: { usage, selector, matchingType, data /* hex */ } · SVCB/HTTPS: { priority, target, params: { alpn?: string[], 'no-default-alpn'?: true, port?, ipv4hint?: string[], ech?: base64, ipv6hint?: string[], [key]: hex } } · NAPTR, NSEC, NSEC3: reasonable objects · unknown: data = hex, text = '\\# <len> <hex>'
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
  async detectWildcard(domain, { signal } = {}) -> { wildcard: boolean, ipv4: string[], ipv6: string[], cnames: string[] }   // 2 random labels
  async ptr(ip, { signal } = {}) -> string[]
  setConcurrency(n) ; stats() -> { queries, cacheHits, failures, byResolver: { [id]: { ok, fail, avgMs } } }
}
DnsResponse = { name, type, resolver /* id that answered */, ok: boolean /* got a DNS answer (any rcode) */, rcode: 'NOERROR'|'NXDOMAIN'|'SERVFAIL'|..., flags, answers: RR[], authorities: RR[], ecs /* echoed ECS or null */, ede: [], elapsedMs, error: string|null /* transport error message when ok=false */, errorKind }
HostResolution = { name, status: 'NOERROR'|'NXDOMAIN'|'SERVFAIL'|'REFUSED'|'ERROR', cnames: string[] /* chain order */, ipv4: string[], ipv6: string[], ttl: number|null /* min TTL */, resolver, error: string|null }
// Failover (when no explicit resolver): transport error / timeout / HTTP 429/5xx / SERVFAIL|REFUSED → try next in chain. Uses GET ?dns= with id=0 and accept header. Cache key includes name/type/resolver/ecs/dnssec/cd.
```
Current wiring (code wins), v2 extensions:
- `balancePool` constructor option (default `['cloudflare', 'google', 'dnssb']`, filtered to the chain unless given explicitly) and `resolveHost(name, { balance: true })` / `query(…, { balance: true })`: bulk A-only probes rotate over the pool instead of hammering the first resolver; failover still applies.
- Per-resolver circuit breaker: repeated transport failures open it (the resolver is skipped, `stats().byResolver[id].down`), and after a cool-down one half-open probe decides whether it closes again.
- Per-call `timeoutMs` / `retries` overrides on `query` / `resolveHost`; `concurrency` getter next to `setConcurrency`; `stats()` also reports `requests` and `shared` (in-flight de-duplication).
- `export async function detectWildcardDeep(dns, parent, { signal })` → `{ wildcard, kind: 'A'|'CNAME'|'NODATA'|null, ipv4, ipv6, cnames }`: two random labels must agree; NODATA only counts when DNSSEC does not prove non-existence (compact denial). The scanner runs it at every level that hosts a discovered name.

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

### 5.11 `lib/sources.js`
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
export const SOURCE_HEALTH_STATES = ['ok', 'empty', 'partial', 'rate-limited', 'unavailable', 'timeout', 'error']
export function sourceHealthSummary(results /* SourceResult[] | fetchAllSources() output */) -> SourceHealth[]   // one row per source (SOURCES order), aggregated over domains:
SourceHealth = { source, name, homepage, state, ok, names, ipHints, certs, elapsedMs, attempts, errorKind, error, quota, truncated, available, fallback /* CT twin (crtsh ↔ certspotter) whose data covered a failure */, message, domains: [{ domain, state, names, errorKind, error }] }
IpHint = { name, ip, source, firstSeen?: Date, lastSeen?: Date }
CtCert = { key /* dedupe key */, source, id, serialHex: string|null, issuer: string, notBefore: Date, notAfter: Date, names: string[], sha256: string|null }
```

### 5.12 `lib/scanner.js` — discovery engine v2 + "SSL target finder" orchestration
Used by both the Subdomains view (no certificate / inventory) and SSL Targets.
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
  customOnly: boolean /* extension: found ONLY through a custom-list label that is not in WORDLIST_SMALL (never learned) */ }
  // origins: 'input' | 'cert' | source ids | 'dns-mine:<RR>' (MX|NS|SOA|SPF|DMARC|SRV|CNAME|CAA|HTTPS|PTR) | 'wordlist' | 'permutation' | 'recursive'; legacy results may show 'bruteforce' (= 'wordlist')
OriginHint = { ip, reasons: Reason[], servers: Array<{ serverId, name }>, provider: provider|null, hosts: string[] /* extension */ }
Reason =                                   // `detail` is log text; views read the structured fields only
    { kind: 'resolver-leak', host, resolver /* resolver id that answered with a non-CDN address */, detail }
  | { kind: 'history', host, source /* source id */, lastSeen: 'YYYY-MM-DD'|null, detail }
  | { kind: 'spf'|'mx'|'direct-sibling', detail }
OriginNetwork = { cidr /* /24 IPv4 · /48 IPv6 */, ips: string[], hosts: string[] /* DNS-only names in the block */, provider: provider|null }
ServerGroup = { server: Server, hosts: Array<{ name, ip, covered: boolean|null, via: 'dns'|'hint' }>, needsCert: boolean }
```
Pipeline (v2, DNS first): seeds (domains + cert hostnames with wildcards stripped → wildcard bases + extraNames) → `sources` (passive sources per registrable domain, in parallel with) `mining` (in-domain names from the zone's own MX / NS / SOA / SPF / DMARC / SRV / CNAME / CAA / HTTPS records) → `wildcard` (detectWildcardDeep at the apex, every certificate wildcard base and every level that hosts a discovered name) → `bruteforce` (A-only wordlist sweep of the chosen level under the apex and each wildcard base, balance mode; wildcard look-alikes dropped) → `permutations` (variants of everything found so far — env / number / region / sibling words and the service-suffix tier `shop → shopapi` — up to `permutationBudget`, then one recursive wordlist round under discovered parents) → `resolve` (A + AAAA for every surviving name; stream `onHost`) → classify / cert coverage / inventory match → `hints` (DNS only, never a connection to the target: apex SPF `ip4:`/`ip6:`/`a:`/`mx`, MX host IPs, public IPs of non-proxied siblings, historical IP hints from hackertarget/otx that are not CDN IPs, `resolver-leak` = a proxied name answered with a non-CDN address by another public resolver; then the DNS-only hosts and leaks are clustered into `originNetworks` and every proxied host gets them as `candidateNetworks`) → server groups (DNS matches + hint matches) and unmatched direct IPs → `done`.
`cliTargets` / `cliNames` are built for the sweep (IPv4: the /24 when the block holds at least two origin IPs or an inventory server, otherwise the exact IPs; IPv6: exact addresses only — a /48 is far over the CLI's block limit) and passed through `lib/cmdline.buildSweepCommand` (§5.17), so they hold only what survived validation. `cliSuggestion` is the POSIX form `python3 cli/ssl_origin_scan.py -t <targets> -n <names>`, or null when nothing is left to sweep; the views build their own copy-ready command for POSIX (`python3 ssl_origin_scan.py …`) or PowerShell (`python ssl_origin_scan.py …`) from `cliTargets` / `cliNames`, never from this string. Resolver-leak re-resolves each proxied host through at most 3 other resolvers of the pool (≤ 300 queries per scan, 2.5 s each, no retries, resolvers with an open circuit breaker skipped).
`lib/dnsmine.js`: `mineDnsNames(domain, { dns, signal, onProgress, resolvePtr = false })` → `{ names, evidence: [{ name, from, record }], externalRefs }`; `SRV_SERVICES` lists the probed `_service._proto` labels. `lib/permute.js`: `permutations(foundNames, domain, { budget = 1500, words, envs, regions, suffixes, exclude })` → ranked, de-duplicated candidates (never the known names, never a name in `exclude` — a Set of names already probed, skipped before it counts toward the budget — never over budget); `DEFAULT_WORDS` / `DEFAULT_ENVS` / `DEFAULT_REGIONS` / `DEFAULT_SUFFIXES` are English-first and global (`DEFAULT_SUFFIXES` = web, api, admin, app, db, ws, service, gw, panel, srv, auth, ranked by how often `<label><suffix>` occurs in the shipped public wordlist).

### 5.13 `lib/ipintel.js`
```js
export function createIpIntel({ fetchImpl, dns /* DohClient for PTR */, concurrency = 4 } = {}) -> {
  info(ip, { signal }) -> Promise<IpInfo>, reverseIp(ip, { signal }) -> Promise<{ ok, domains: string[], error, limited: boolean }>
}
IpInfo = { ip, version, private: boolean, provider: provider|null, ptr: string[], asn: number|null, asName: string|null, holder: string|null, prefix: string|null, country: string|null, city: string|null, sources: string[], error: string|null }
// Private IPs: no external calls. Order: RIPEstat prefix-overview + maxmind-geo-lite; fallback ipwho.is. Cache per ip.
```

### 5.14 `lib/rdap.js`
```js
export async function rdapDomain(domain, { fetchImpl, signal } = {}) -> { ok, domain, registrar, registrarIanaId, created: Date|null, updated: Date|null, expires: Date|null, status: string[], nameservers: string[], dnssecSigned: boolean|null, rdapServer, unsupportedTld: boolean, error }
export async function rdapIp(ip, { fetchImpl, signal } = {}) -> { ok, name, handle, country, startAddress, endAddress, cidr, org, error }
```

### 5.15 `lib/health.js`
```js
export async function domainHealth(domain, { dns, fetchImpl, signal, dkimSelectors = DEFAULT_DKIM_SELECTORS, onProgress } = {}) -> HealthReport
export const DEFAULT_DKIM_SELECTORS = ['default','google','selector1','selector2','k1','k2','s1','s2','dkim','mail','smtp','mandrill','zoho','protonmail','protonmail2','protonmail3','mxvault','everlytic','sig1','amazonses', ...]
export function parseSpf(txt) ; export function parseDmarc(txt) ; export function parseCaa(rrs)
export async function spfLookupCount(domain, { dns, signal }) -> { count, tree, errors }   // RFC 7208 §4.6.4: include, a, mx, ptr, exists, redirect count; max depth guard
export function caaDomainsForIssuer(issuerDN) -> string[]   // map CA → CAA identifiers (Let's Encrypt→letsencrypt.org; DigiCert/GeoTrust/RapidSSL/Thawte→digicert.com; Sectigo/Comodo/ZeroSSL→sectigo.com,comodoca.com; GlobalSign→globalsign.com; GoDaddy/Starfield→godaddy.com,starfieldtech.com; Google Trust Services→pki.goog; Amazon→amazon.com,amazontrust.com,awstrust.com,amazonaws.com; Buypass→buypass.com; SSL.com→ssl.com; Entrust→entrust.net; Certum/Asseco→certum.pl; Microsoft→microsoft.com; Actalis→actalis.it; HARICA→harica.gr; e-Tugra→e-tugra.com.tr (distrusted 2023, flag it))
export function checkCaaAllows(caaRecords, issuerDN, { wildcard }) -> { allowed: boolean|null, reason }
HealthReport = { domain, records: { ns, soa, mx, a, aaaa, txt, spf, dmarc, dkim: [{ selector, record }], caa, mtaSts, tlsRpt, bimi, ds, dnskey, https }, dnssec: { signed, validated, broken }, rdap, wildcard, checks: Check[] }
Check = { id, severity: 'ok'|'info'|'warn'|'error', titleKey, detailKey, params }   // NS count/diversity, SOA, MX present/resolves/not-CNAME/null-MX, SPF (single record, ≤10 lookups, +all/?all/~all/-all, ptr), DMARC (present, policy, rua, pct, multiple), DKIM found selectors, CAA (present? issuers), DNSSEC (signed/validated/broken: SERVFAIL with CD=0 but NOERROR with CD=1), wildcard DNS, RDAP expiry (<30d error, <60d warn), IPv6 presence, MTA-STS/TLS-RPT/BIMI presence
```

### 5.16 `lib/export.js`
```js
export function toCsv(rows, columns /* [{ key, header, get?(row) }] */, { bom = true, delimiter = ',' } = {}) -> string   // RFC 4180 quoting; BOM for Excel (Turkish chars)
export function toJson(value) -> string   // Dates ISO, Map→object, Set→array, Uint8Array→omitted, pretty 2 spaces
export function scanHostRows(scan) -> object[] ; export function scanServerRows(scan) -> object[]
export function namesForCli(scan, { onlyCovered = false } = {}) -> string    // newline list
export function targetsForCli(servers) -> string                             // "name ip" lines
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
export const DEFAULT_NAMES_FILE = 'proxied-names.txt', MAX_INLINE_NAMES = 200, MAX_INLINE_LENGTH = 8000
```
`buildSweepCommand` also takes `cert = null`, `json = null` and `ports = null` (the Verify tab's CLI card uses the first two): `cert` / `json` must be plain path tokens (the `script` rule) and become `--cert <cert>` / `--json <json>`; `ports` are integers 1–65535 (a single integer is accepted), deduplicated in order, and become `-p 443,8443` — omitted when null, `[]`, exactly `[443]` (the CLI default) or when every value was invalid. The options follow the names (or the names file) in the order `-p`, `--cert`, `--json`, count toward the inline length limit, and PowerShell quotes `'443,8443'`. The result always carries `dropped.options: string[]` (`'cert'`, `'json'`, `'ports:<v>'`; `[]` when nothing was dropped); without the new options every output is byte-identical to before.

An internationalised name is kept in its punycode form (`xn--…`). Anything else that is not a valid target or name (`; rm -rf /`, `$(…)`, backticks, spaces, quotes, newlines, a leading `-`, over-long labels) is dropped and reported — never quoted into the command — so the result is inert in both a POSIX shell and PowerShell and a name can never be read as an option. The caller prefixes the interpreter (`python3` for POSIX, `python` for PowerShell); the views show `dropped` as a count. `script` and `namesFile` must be plain paths (`[A-Za-z0-9_./-]`, not starting with `-`), otherwise the default is used. Over 200 names or 8,000 characters the command reads the names from `namesFile` (the CLI loads a `-n` value that is an existing file, one name per line), so a large estate never hits the Windows command-line limit; the views then offer that file (`proxied-names.txt`, the validated proxied names) as a download next to the command.

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
export const VERIFY_STATUSES = ['UPDATED','NEEDS_UPDATE','NOT_HOSTED','TLS_ERROR','TIMEOUT','CLOSED']      // = the CLI's STATUSES
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
export async function expectationFor(certs, { subtle }) -> { sha256[], spkiHex[], hostnames[], subjectCN, notAfter }
export function classifyTest(test, { name, expect, now }) -> ProbeVerdict
export function aggregateVerdicts(verdicts) -> Verdict|null   // the worst verdict WITH a certificate wins (NEEDS_UPDATE > NOT_HOSTED > UPDATED); failures only
                                                              // when no probe got one (TLS_ERROR > TIMEOUT > CLOSED); 'mixed' when the probes disagree
// Rules over rows
export function applyWorksRule(rows) -> changed[]             // CLI `works`: per ip:port, a row with a certificate turns TLS_ERROR sni-refused / tls-alert / reset
                                                              // into NOT_HOSTED refused-name (alert 120, ALPN, excluded); recomputed from row.verdict every time
export function serverStatus(rows) -> status|null             // CLI server_status() parity; Globalping's TCP-connect TIMEOUT is the CLI's connect-level TIMEOUT;
                                                              // an origin-ca NEEDS_UPDATE row counts like newCertCovers === false (hosted with its own certificate)
export function exposureOf(row) -> EXPOSURES|null             // proxied rows only; 'filtered' needs ≥ 2 probes from different ASNs, one silent probe is 'no-answer'
export function recheckRows(rows), requeueRows(rows), applyOriginOptIn(rows, on),
  verifyCost(rows, { probesPerCheck, now }) -> { checks, reuse, probes, servers, origins, optional }   // a reusable paid id costs 0
// Pairs and the runner
export function buildVerifyPairs(result, { maxRows, port }) -> { pairs, stats }   // covered, non-wildcard-suspect names × their inventory-server IPs (via dns | zone | hint)
                                                                                  // and unmatched public IPs; skips: private, reserved, cdn-edge, bad-name, bad-port, over-cap
export function scopePairs(pairs, 'all'|'perIp'), createVerifyRows(pairs, { origins = false })   // hint pairs start as not-run · optional unless `origins`
export async function runVerify(rows, { client, expect, signal, concurrency, timeoutS, probesPerCheck, locationsFor, maxProbes, maxRetries, onRow, onQuota, now })
  -> { spent, retries, stoppedBy: null|'quota'|'budget'|'abort'|'unreachable' }
// Summary, headline and exports
export function summarizeVerify(rows), notHereParts(summary, stats), verifyHeadline(summary, stats) -> [{ key: 'vfy.head.<k>', variant, params, parts? }]
export const VERIFY_CSV_COLUMNS   // the CLI's 17 CSV_COLUMNS in CLI order (a unit test parses them out of the CLI), then source, state, stale, skip, reason,
                                  // warnings, exposure, via, http_status, vantage, measurement_id, checked_at
export function verifyExportRows(rows, { now }), verifyExportJson(rows, { expect, summary, app, version, now })   // schema 'domainscope.verify/1'; rows start with the CLI's _row_dict keys
export function cliPlan(rows) -> { targets, names, rows }   // private / reserved / bad-name / bad-port skips + TIMEOUT / CLOSED verdicts (not cdn-edge)
```
Rules that are easy to get wrong:
- **Identity is `fingerprint256`** (= `computeFingerprints(der).sha256`, 12/12 live). Name **coverage** comes from `certCovers(served.hostnames, name).covered` over `subject.alt` (the CN only when there is no DNS SAN, the x509 rule), **never from `tls.error`**, which holds one code in which chain errors mask name errors. Serials: no `00` sign byte is re-added (neither side has one).
- Verdicts: covered + our fingerprint → UPDATED / `new-cert`; covered + another fingerprint → NEEDS_UPDATE / `old-cert` (`no-new-cert` without an expectation); not covered → NOT_HOSTED / `not-covered`; refused / unreachable → CLOSED; TCP-connect or handshake timeout → TIMEOUT; alert 112 → NOT_HOSTED / `unrecognized-name`; alert 40 → TLS_ERROR / `sni-refused`; any other alert, a reset (an early close too: `socket disconnected before secure TLS`, OpenSSL's `unexpected eof`, as the CLI treats `SSLEOFError`), not TLS or unknown → TLS_ERROR. DNS, private, internal and offline failures, empty results, a `tls` without a fingerprint and a status code without `tls` are **errors** (`dns` / `private` / `probe` / `offline`), never a server verdict; probe-side faults are retried on another probe (at most 5 per run).
- Warnings: `chain-incomplete` (UNABLE_TO_VERIFY_LEAF_SIGNATURE / UNABLE_TO_GET_ISSUER_CERT[_LOCALLY]), `expired` (also `notAfter < now`), `not-yet-valid`, `self-signed`, `untrusted-root`, `untrusted` (other codes), `name-mismatch` (ALTNAME_INVALID while our coverage says covered), `same-key` (NEEDS_UPDATE whose public key of ≥ 32 bytes ends the new SPKI), `http-421`, `mixed`, and the *unverified* heuristic `origin-ca` (a Cloudflare Origin CA issuer; it replaces chain-incomplete, untrusted and untrusted-root).
- Runner: the probe budget is **reserved before each POST**, so parallel workers never overspend. A paid, unfinished measurement (Stop, deadline) is polled again for free, first, but only within 120 s and once. A re-check keeps the last verdict, marked `stale`, until a new one replaces it, so a stopped or quota-limited re-check never makes a server look live. `TimeoutError` / `TypeError` → `network` (3 → `stoppedBy 'unreachable'`); a quota 429 (`rate_limit_exceeded` / `insufficient_credits`) stops the queue (`not-run · quota`), while any other 429 waits for `Retry-After` (5 s without one, at most 60 s) and repeats the POST once, else `poll-rate`; a free `private-target` / `bad-host` 400 turns the row into a `reserved` / `bad-name` skip; a GP code outside VERIFY_ERRORS becomes `unknown` (the code is kept in `row.error.raw`).
- Headline (servers, not IPs; bare IPs stand for unmatched addresses; a shared VIP counts for every server that lists it): base = total − filtered origins − origin candidates that do not host the name (`notHostingOrigins`). Origin rows that behave as expected (filtered, no answer, closed, or an origin hint answering "not this name") never make a server a problem, and a server leaves the base only once every row of it has a verdict; `all` also needs `incomplete` = 0. The first entry is exactly one of `all` / `some` / `none` / `partial` / `noAnswer`: `none` also when no server is live and a DNS- or zone-matched name gets another certificate or a refusal (`wrongCert`, which makes `other` warn), `partial` with 0 live when a server returned some certificate (`served`, e.g. an Origin CA one), `noAnswer` only when none did; then, when non-zero, `incomplete`, `chain` (servers with an UPDATED row missing its intermediate), `tlsError`, `unreachable`, `other`, `exposed`, `filtered`, `notHere`. Every counted entry carries `params.count`.

## 6. UI (views)

Hash routing `#/<view>?param=...` (shareable: e.g. `#/lookup?name=example.com&type=MX`, `#/global?name=www.example.com&type=A`). Navigation groups: Discover (subdomains), SSL (scan, cert), DNS (global, lookup, bulk, ip, health), Data (inventory, about). Views:
0. **subdomains** "Subdomains" (**default route**; the brand link and About's Start button open it): domain(s) in, every discoverable subdomain out. Options: wordlist level **Off / Small / Smart (recommended, default) / Large / Huge** with exact counts (`wordlistInfo()`), the locale packs the typed domain gets and time estimates (candidates ÷ 120 queries/s at the full sweep width of 24, scaled down for a lower Settings value), and a plan line (≈ queries per domain, custom / learned / pack shares, per-domain caps); under Advanced options: languages / markets (auto from the domain ending, a manual pack list, or none; remembered), custom wordlist (textarea + `.txt` file, accepted / rejected counts from `parseCustomWordlist`, this tab only, Clear), learned names (opt-in switch, off by default, with the count, Forget; never used at Off), permutations on/off with a budget (500 / 1,500 / 5,000; the switch also drives the recursive round), origin hints on/off, passive sources with quota notes, include expired, extra hostnames, DoH chain. A shared link (`run=1`) pre-fills the domain and asks before scanning. While running: stage pills in `SCAN_STAGES` order with per-stage counts and a progress bar. Results: summary line (sources that failed, wildcard parents, Cloudflare count, dangling CNAMEs), a technique bar ("how the names were found": DNS records / wordlist / permutations / deeper level / passive sources), per-source status (`sourceHealthSummary`, quota explanations), the host table (name → DNS Lookup link, origin badges, classification, IPs), a wordlist usage line from `options.wordlist` (served level, packs, custom / learned tried vs found, fallback), and for proxied hosts an **Origin** panel ("Origin servers behind the proxy"): origin networks (/24 · /48) with their DNS-only hosts, per proxied host its resolver-leak answers ("answered by <resolver>") and history ("seen by <source> · last <date>"), read from the structured reason fields, other SPF / MX / sibling hints, and the sweep command for **Linux / macOS** or **Windows PowerShell** (built from `cliTargets` / `cliNames` with `buildSweepCommand`, dropped entries counted; over 200 names it reads `-n proxied-names.txt`, offered as a download next to the command) with copy and a download link for the CLI. Copy all names / resolving only / `names.txt`; a CTA opens SSL Targets for the same domain.
1. **scan** "SSL Targets": steps — (1) drop/paste certificate (optional) → shows parsed summary; (2) target domain(s) (auto-filled from cert via registrableDomain); (3) inventory (uses shared inventory from state; link to inventory view); (4) options (sources checkboxes w/ notes about quotas, include expired, wordlist Off/Small/Smart/Large/Huge (default Smart) + permutations, DoH chain; a vocabulary line shows the languages, custom wordlist and learned names shared with Subdomains › Advanced options, with a link there — SSL Targets has no separate controls for them, but records learned labels after its scans too); Run/Cancel with per-source status + progress. Results: stat cards; tabs Hosts / Servers / Behind CDN / Verify / Sources / CT: **Hosts** (table: name, origins, status/classification badge incl. 🟠 Cloudflare, IPs, CNAME, cert coverage ✓/✗, matched servers; filters: covered only / resolving only / hide wildcard suspects / by kind; search), **Servers** (grouped: server → hosts; "needs cert" first; unmatched IPs group), **Behind CDN** (proxied hosts + origin hints + explanation + ready-to-run CLI command with the same POSIX / PowerShell toggle & download buttons for names.txt/targets.txt + link to `cli/ssl_origin_scan.py`), **Verify** (only with a certificate; `ui/verify-panel.js` over §5.18–§5.19: every covered (public IP, name) pair of the scan checked from the internet through Globalping, with the CLI's six verdicts. Nothing is sent when the tab opens, not even `/limits`. Start and "Check again (n)" read the free quota and show the consent + cost dialog on the first send of the page session (consent is never stored; "Delete all local data" resets it); a partial run is offered when the quota does not fit, and a 429 stops cleanly with the reset time. Private, reserved and unaccepted pairs are listed as skipped and, with every pair the internet could not answer (TIMEOUT / CLOSED), go to a validated CLI command (`--cert new-cert.pem --json verify-cli.json`, POSIX / PowerShell) with a new-cert.pem download; CDN-edge pairs are listed as skipped too but stay out of it, because the CDN serves its own certificate there. Origin-hint pairs (an inventory origin IP with a proxied name) are opt-in, off by default. The headline counts servers; the tab badge reads `live/total`; warnings carry tooltips; CSV (the CLI's 17 columns first) and JSON exports; the scan's full JSON gains `verification`. The job lives on the scan run: it survives navigation and language changes, toasts when it finishes in the background ("Show results" reopens this tab), and a new scan cancels it), **Sources** (per-source status, counts, errors, timing), **CT certificates** (crt.sh/certspotter certs: issuer, validity, names; highlight the uploaded cert's serial and certs expiring ≤30 days). Exports CSV/JSON.
2. **cert** "Certificate": full parsed details (subject, issuer, validity with days left, SAN list, key, fingerprints, chain order, warnings), CAA check against issuer for each base domain, CT lookup of this serial via crt.sh, and a "find targets for this cert" button that opens scan pre-filled.
3. **global** "Global DNS": name + type → table of all resolvers (answer, TTL, rcode, AD, latency) + geo table via ECS (flag, country, ISP, answer, scope) + consistency groups with color coding + answer IP classification (CDN badge). Re-run button; share link.
4. **lookup** "DNS Lookup": name + type(s) (checkbox group or "ALL common"), resolver select, DNSSEC toggle → sections per type with parsed records (SOA fields, MX priority, CAA tags, SVCB params …), flags (AD), raw presentation text, copy buttons.
5. **bulk** "Bulk Resolve": paste hostnames (hundreds) → table: name, status, CNAME chain, IPv4, IPv6, classification, PTR (optional), ASN (optional), inventory match; progress; CSV/JSON export.
6. **ip** "IP Intel": paste IPs → PTR, ASN, holder, prefix, country, provider/CDN, private flag, inventory server, reverse-IP domains (button per row; quota note). 
7. **health** "Domain Health": domain → checks list grouped with severity icons + record panels + RDAP (registrar, expiry countdown) + DNSSEC + email security.
8. **inventory** "Servers": textarea + file import (txt/csv/ini/yaml/json), parsed table, warnings, persisted in localStorage, clear button, privacy note.
9. **about**: how it works, sources & quotas, privacy, CLI download & usage, Cloudflare explanation, GitHub link placeholder.

Design: clean, professional dashboard; light/dark via tokens (`prefers-color-scheme` + manual toggle `data-theme`); system font stack + monospace for data; responsive to 360px (tables scroll horizontally inside their container, never the page); visible focus rings; `aria-live` progress; keyboard accessible tabs; inline SVG icons (no icon fonts); status colors with text labels (not color-only). Large tables: paginate or incremental render (e.g. 200 rows + "show more").

## 7. CLI `cli/ssl_origin_scan.py` (Python ≥3.8, stdlib only, single file)

Purpose: definitively map hostnames → servers by TLS-probing inventory IPs **with SNI**, bypassing DNS/Cloudflare. Run from a host inside the network (jump box).
```
python3 ssl_origin_scan.py -t targets.txt [-t 10.0.0.0/24 -t web01.internal ...] (-n names.txt | -n host ... | --cert new-cert.pem) [--ports 443,8443] [--workers 64] [--timeout 5] [--json out.json] [--csv out.csv] [--show-all] [--no-color]
```
- targets: same flexible inventory formats as the web app (name+ip lines, hosts file, CSV, Ansible INI, JSON) + CIDR ranges (cap e.g. /16 with warning) + hostnames (resolved with getaddrinfo).
- names: from files/args; `--cert FILE` adds the cert's SAN DNS names (wildcards: probe the base domain and any provided names under it) AND enables fingerprint comparison (served cert == new cert → "already updated").
- Phase 1: TCP connect check per ip:port (parallel) → skip closed. Phase 2: for each open ip:port × name: TLS handshake with SNI=name, `CERT_NONE`, permissive (`minimum_version` lowest supported, `set_ciphers('ALL:@SECLEVEL=0')` guarded by try), fetch DER via `getpeercert(binary_form=True)`, parse with a built-in minimal DER parser (subject CN, SAN DNS/IP, issuer CN/O, serial, notBefore/notAfter incl. GeneralizedTime, sha256 fingerprint). Also probe once with no SNI to learn the default cert.
- Status per (server, port, name): `UPDATED` (serves the new cert), `NEEDS_UPDATE` (served cert covers the name but is not the new cert — show its expiry), `NOT_HOSTED` (served cert does not cover the name / only default cert), `TLS_ERROR`, `CLOSED`, `TIMEOUT`.
- Output: human-readable summary grouped by server ("servers that need the new certificate: N") with colors (auto-disabled when not a TTY/`--no-color`/`NO_COLOR`), plus `--json` / `--csv`. Exit code 0 always unless usage error (2); `--fail-on-needs-update` → exit 1 when any NEEDS_UPDATE (for CI).
- Robust: Ctrl-C handling, per-connection timeout, thread pool, IPv6 support, no stack traces for expected errors.
- Tests (`tests/python/test_ssl_origin_scan.py`): DER parser vs `tests/fixtures/expected.json`; inventory parsing; wildcard matching; **integration**: start local TLS servers on 127.0.0.1 ephemeral ports (threads, `ssl.SSLContext.sni_callback` selecting fixture cert/key by SNI; default cert = cn_only) and assert statuses for names; `--cert` fingerprint UPDATED path.

## 8. Quality bar
- Unit tests for every lib (happy path + edge cases); all green.
- E2E (integrator): headless Edge/Chrome via CDP driving each view on `http://localhost:8080` against live APIs, screenshots saved to `tests/e2e/screenshots/` (gitignored), zero console errors, zero CSP violations. `tests/e2e/verify.e2e.mjs` (run right after `scan` by `run-all.mjs`) is **offline**: a fake DoH zone and a fake Globalping inside the page plus a CDP network guard, so it spends 0 real probes and asserts that nothing leaves the page. The only live Globalping check is the manual `tests/live/globalping-smoke.mjs` (public targets only, ≤ 10 probes; `--dry` spends none).
- No `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` with dynamic data anywhere (grep-able).
