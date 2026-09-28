# Globalping fixtures

Real [Globalping](https://globalping.io) measurements, trimmed and scrubbed, for the unit tests of
`assets/js/lib/globalping.js` (the client) and `assets/js/lib/verify.js` (the certificate verdicts).
No test reads the network: tests replay these bodies through a fake `fetch`.

- **Captured** 2026-09-24, 06:49–06:57 UTC, anonymously, from `https://api.globalping.io/v1`
  (Node 22 `fetch`). Public targets only: github.com, the badssl.com family, www.cloudflare.com,
  1.1.1.1 / one.one.one.one, scanme.nmap.org (Nmap's sanctioned scan target), example.com and
  localtest.me. `m25` was measured by a later review run and re-read with a free `GET` by id.
- **Recapture** (costs probes; public targets, plus the deliberate m21 (localtest.me → 127.0.0.1) and
  m25 (3fff::1) charged-failure cases):
  `node tests/live/globalping-smoke.mjs --capture --budget 23` rewrites the `m*` and the six named
  `v-*` files with the same trim / scrub code (`validation-cases.json`, `create-parallel-quota.json`
  and the synthetic files are not recaptured). m19 is then re-recorded against m15's probe.
- `tests/fixtures/real_github.pem` is **byte for byte the certificate served in m01** (fingerprint,
  serial and public key all match), so m01 + `real_github.pem` is a fully real "new certificate is
  live" case. That certificate expires on **2026-11-29**: every test that classifies a fixture must
  pass `now: Date.parse(fixture.capturedAt)`, never the wall clock.

## Shape

Measurement fixtures (`m*.json`):

```js
{ name, capturedAt,               // ISO; the measurement's createdAt
  reconstructed?: ['request', 'post'],   // m25 only: rebuilt from the measurement echo
  request,                        // the POST body that was sent
  post: { status, headers /* x-ratelimit-*, x-request-cost, retry-after only */, body },
  inProgress?,                    // the first GET while status was 'in-progress' (trimmed)
  final: { status, headers? /* retry-after only */, body /* trimmed measurement */ } }
```

Validation errors on POST (`v-*.json`, `create-401.json`, `create-429.json`): `{ name, capturedAt,
synthetic?, request, post }` with no `final` (nothing was created).

Other GETs (`limits-*.json`, `poll-429.json`, `get-404.json`): `{ name, capturedAt, synthetic,
request: { method, path }, response: { status, headers, body } }`.

`validation-cases.json` collects every refused POST in one table (`cases[]`: `{ name, request,
status, body }`) plus `accepted[]`, the targets the API took **and charged** although no probe can
reach them. `create-parallel-quota.json` holds the `X-RateLimit-*` readings of six concurrent POSTs
in one window (`posts[]`).

## Trim rules

Per test result (`results[i].result`):

- `headers`, `rawHeaders` and `rawBody` are dropped (they repeat the target's response headers:
  15–20 KB per probe);
- `rawOutput` is kept only when `status === 'failed'`, cut to 300 characters;
- `tls.publicKey` is kept **only** in m01 (EC, the raw point) and m02 (RSA, the full SPKI), for the
  same-key tests.

Per probe: `latitude`, `longitude`, `resolvers` and `state` are dropped; `tags` keep only
`datacenter-network` / `eyeball-network`, and any `u-<user>` tag becomes `u-probe` (cloud-region
tags are dropped).

POST headers keep only `x-ratelimit-*`, `x-request-cost` and `retry-after`.

## Scrub map

| Real value | In the fixtures | Why |
|---|---|---|
| the badssl.com origin IPv4 (a cloud address outside `WELL_KNOWN`; deliberately not written here) | `54.1.2.3` | `tests/js/repo-hygiene.test.js`: target, `resolvedAddress` and `rawOutput` |
| `u-<username>` probe tags | `u-probe` | volunteer usernames |

Kept as they are: 140.82.121.4 (GitHub), 104.16.124.96 (Cloudflare), 45.33.32.156 (scanme.nmap.org),
1.1.1.1 / 1.0.0.1 and 162.159.x (Cloudflare) and every IPv6 address. Measurement ids are kept: the
results are public by id on Globalping anyway (retained for about six months).

## Files

| File | Measurement id | Request | Shows |
|---|---|---|---|
| `m01-github-valid.json` | 2BQe3etLekZmRGfMF00021C1L | 140.82.121.4, host github.com, DE + US | 2 probes, `authorized`, EC `publicKey`, cost 2 |
| `m02-wrong-host.json` | 2bFvUjZUuu45tZsL800021C1M | badssl, host wrong.host.badssl.com, `magic: AS24940` | `ERR_TLS_CERT_ALTNAME_INVALID`, RSA `publicKey` |
| `m03-expired.json` | 23fpgzrp0BphToXYO00021C1M | host expired.badssl.com, `asn: 16276` | `CERT_HAS_EXPIRED` |
| `m04-self-signed.json` | 2QHoNfzooEUIzdWvs00021C1M | host self-signed.badssl.com, TR | `DEPTH_ZERO_SELF_SIGNED_CERT` |
| `m05-untrusted-root.json` | 2Kl4uAV6m0k29dnsf00021C1M | host untrusted-root.badssl.com, eyeball | `SELF_SIGNED_CERT_IN_CHAIN` |
| `m06-incomplete-chain.json` | 2yDACOZt5SDtLOrth00021C1M | host incomplete-chain.badssl.com | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` (missing intermediate) |
| `m07-revoked.json` | 2MLvsFC7MW1zT3lmx00021C1M | host revoked.badssl.com | `authorized: true`: revocation is not checked |
| `m08-no-host-421.json` | 2NnmILjPEdypc75QU00021C1M | badssl, no host | fallback certificate, HTTP 421 |
| `m09-closed.json` | 2xomsKL8sFHBSvjMI00021C1N | 45.33.32.156, host scanme.nmap.org | `connect ECONNREFUSED` |
| `m10-filtered-default.json` | 2UMjCb9xRKrfl5riH00021C1N | 140.82.121.4:8443, default timeout | TCP connect timeout after 15 s |
| `m11-filtered-timeout5.json` | 2mxHxVj1O9FiG53XH00021C1N | same, `timeout: 5` | TCP connect timeout after 5 s |
| `m12-sni-refused.json` | 2xRWY3nxugT4lMyRW00021C1N | 104.16.124.96, host github.com | `SSL alert number 40` |
| `m13-cf-8443-403.json` | 2pB6Dzarz9YFBkvue00021C1N | 104.16.124.96:8443, host www.cloudflare.com | `tls` with HTTP 403 |
| `m15-v6-literal.json` | 2vzpn8QVxTcG7Mt5N00021C1N | 2606:4700::6810:7c60, host www.cloudflare.com | IPv6 literal target + host |
| `m17-unknown-vhost.json` | 2T39pc0p1m8zRakPN00021C1N | host no-such-vhost.badssl.com | `CERT_HAS_EXPIRED` masks the name error (HTTP 421) |
| `m19-reuse-probe.json` | 20NxrG4ySQTJSvwo000021C1O | www.cloudflare.com, `locations: <m14 id>` | same probe as an earlier measurement |
| `m20-nxdomain.json` | 2rsxUk4UHpGsgG7bi00021C1O | hostname target gp-test-nonexistent-7q2z.example.com | `queryA ENODATA` |
| `m21-private-resolve.json` | 2Y1DZFQFq8Cn85mv500021C1O | hostname target localtest.me (→ 127.0.0.1) | `Private IP ranges are not allowed.` (charged) |
| `m22-http2.json` | 2AzLmrFa6YOvx76uF00021C1O | 140.82.121.4, host github.com, HTTP2 | HTTP/2 still returns `tls` |
| `m23-ip-san.json` | 21V7t2Vbhc1ZeCrZF00021C1P | 1.1.1.1, host one.one.one.one | IP SANs (IPv6 uncompressed) |
| `m24-not-tls.json` | 243iGekdndBucV9f800021C1P | badssl:80, host http.badssl.com | `wrong version number` |
| `m25-v6-doc-enetunreach.json` | 2pTgtxLlyWvamuItO00021C2q | 3fff::1 (IPv6 documentation prefix) | accepted **and charged**, `connect ENETUNREACH` |
| `m26-mta-sts-policy.json` | 2IuWbVoKnaKkYjabJ00021DDq | hostname target mta-sts.<domain>, HTTPS GET `/.well-known/mta-sts.txt` | an MTA-STS policy: `statusCode` 200, `headers` (`content-type`), the decoded `rawBody` (CRLF lines), `tls` (scrubbed, see below) |
| `m27-mta-sts-no-host.json` | 2JRJUjOJwPhya37ZH00021DDt | the same GET on mta-sts.example.com | `queryA ENODATA`: no policy host |
| `m28-acme-http-404.json` | 2VxnLwVQJ9HR4iB2M00021DR4 | hostname target example.com, plain HTTP GET `/.well-known/acme-challenge/<token>` on port 80, `locations` EU / NA / AS | 3 probes, `statusCode` 404 everywhere: the challenge path reaches the web server |
| `m29-acme-http-redirect.json` | 2bvEIAaztqWqIiYyH00021DR4 | the same GET on a site that sends HTTP to HTTPS (scrubbed, see below) | 301 with `headers.location`: the probe does not follow redirects |
| `m30-acme-http-v6.json` | 2e4Nks2k6ZjJ4SBr200021DR4 | as m28 with `measurementOptions.ipVersion: 6` | the probes resolve AAAA and connect over IPv6 (`resolvedAddress` IPv6) |
| `v-private-target-400.json` | – | 10.0.0.1 | `"target" must not be a private hostname` |
| `v-testnet1-400.json` | – | 192.0.2.1 | same (TEST-NET-1) |
| `v-bad-host-400.json` | – | host github.com:443 | `measurementOptions.request.host` invalid |
| `v-ip-with-ipversion-400.json` | – | IP target + `ipVersion` | `ipVersion` not allowed |
| `v-limit-and-location-limit-400.json` | – | global `limit` + `locations[0].limit` | refused |
| `v-no-probes-422.json` | – | `locations: [{ country: 'AQ' }]` | 422 `no_probes_found` |
| `validation-cases.json` | – | every refused POST (28 saved + 7 from the review) | data for the prefilter tests |
| `create-parallel-quota.json` | 6 ids | six concurrent POSTs | remaining 220, 216, 215, 219, 217, 218 |

**DNS at a chosen name server** (Zone File › New name servers, captured 2026-09-28, one probe
each): `d01`–`d14` are DNS measurements with `measurementOptions.resolver` set to an authoritative
name server, for `lib/nsparity.js`. They keep the whole test result — `answers` (the answer section
in presentation format), `statusCodeName`, `resolver` and the dig text in `rawOutput`, whose flags
line (`aa`) and authority section the module reads — with the NSID lines dropped. Every name was
scrubbed to example.com / example.net / example.org (the resolvers to `ns1.example.net`,
`ns2.example.net`, `ns9.example.org`) and every address to 192.0.2.0/24 and 2001:db8::/32; the
Cloudflare edge addresses of `d07` / `d14` are kept, and the DKIM key of `d03` is replaced by
filler of the same lengths (the split into a 255-character string and the rest is as captured).
`v-dns-cases.json` collects the free 400s of DNS measurements: CAA and TLSA are no query type
Globalping knows, a private or documentation resolver and a resolver with a trailing dot are
refused, a wildcard target too.

| File | Shows |
|---|---|
| `d01-soa.json` | SOA of the zone asked of its own server: NOERROR, `aa`, the serial |
| `d02-a.json` | six A records at TTL 300 |
| `d03-txt-split.json` | one TXT record of two character-strings |
| `d04-cname-chain.json` | A asked of a CNAME name: the CNAME and the in-zone target's A |
| `d05-mx.json` / `d06-srv.json` / `d12-ns.json` | one MX, one SRV at an underscore name, the apex NS set |
| `d07-https.json` | an HTTPS record (alpn, ipv4hint, ipv6hint) |
| `d08-nxdomain.json` | NXDOMAIN, authoritative (the `resolver` field reads the address) |
| `d09-refused.json` | REFUSED without `aa`: the server does not serve the zone |
| `d10-nodata.json` | NOERROR without records of the type |
| `d11-bad-resolver.json` | a resolver name the probe cannot resolve: a failed test, charged |
| `d13-tcp-aaaa.json` | AAAA over TCP (`protocol: 'TCP'`) |
| `d14-proxied-a.json` | A of a proxied name at Cloudflare: edge addresses, no CNAME |

**HTTPS GET at an address** (Retire an IP › old and new server, captured 2026-09-28, 2 probes):
`h01` is a GET of `/` at 140.82.121.3 with `request.host` github.com, `h02` the same at
140.82.121.4 with `locations` = h01's id: the same probe answered both (GitHub's addresses and
names are kept, like `m01`). `rawBody` is cut to its first 1,200 characters (both bodies were equal
over all 10,000 the probe returned); `rawHeaders`, `rawOutput`, the headers other than
content-type, strict-transport-security, server and location, and `tls.publicKey` are dropped.

**HTTP-01 reachability** (Renewal readiness, captured 2026-09-28, 9 probes): `m28`–`m30` keep
`headers.location` (a redirect's target, the one header `lib/renewal.js` reads); `rawHeaders`,
`rawBody`, the other headers and a finished test's `rawOutput` (which repeats the response head
and body) are dropped. The request path is a made-up token, so every server answers for a file that
does not exist. `m29` was a large code-hosting site: its host name became `example.net` (the target
and the `Location` URL) and its three addresses `192.0.2.81`–`192.0.2.83`, as its `scrubbed` field
says. `m28` / `m30` target example.com as it is served (Cloudflare addresses, kept).

**MTA-STS policy fetches** (Domain Health, captured 2026-09-27, 2 probes): `m26` and `m27` keep
what `lib/mtasts.js` reads, so unlike the trim rules above their results keep `rawBody` and the
`content-type` / `content-encoding` headers (`rawHeaders` and the other headers are dropped). `m26`
was a large mailbox provider's live policy: its names (the target, the certificate's names and the
MX names in the policy) became `example.com` and its `resolvedAddress` `192.0.2.80`, as its
`scrubbed` field says; the policy's shape (three `mx` lines, one of them `*.`, CRLF line ends,
`max_age: 86400`) and the certificate's other fields are as captured. The body arrived
`content-encoding: br`: `rawBody` is already decoded.

**Synthetic** (`"synthetic": true`, built from the verbatim bodies recorded on 2026-09-24; no live
429 was provoked, to save quota): `limits-fresh.json` (`reset: 0`, no window open yet),
`limits-used.json` (`reset: 3314`), `create-401.json` (bad token), `create-429.json`
(`rate_limit_exceeded`, `x-ratelimit-remaining: 0`, `x-ratelimit-reset: 1200`), `poll-429.json`
(`too_many_requests`, `retry-after: 5`) and `get-404.json`.
