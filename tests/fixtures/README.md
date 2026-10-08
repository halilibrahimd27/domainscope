# Test fixtures

Self-signed / test-CA certificates generated with OpenSSL for the unit and integration tests.
`expected.json` holds the OpenSSL-derived ground truth that both the JavaScript parser
(`assets/js/lib/x509.js`) and the Python CLI parser are tested against.

The `*.key` files are **throwaway private keys that exist only for tests** (the CLI tests start
local TLS servers with them). They protect nothing and must never be used anywhere else.

A renewal week (several certificates at once, `assets/js/lib/certsets.js`): `gen_x509_fixtures.mjs`
crafted `renew_a_rsa.pem` and `renew_a_ecdsa.pem` (an RSA 2048 + ECDSA P-256 pair for `example.com`
and `*.example.com`) and `renew_b_rsa.pem` (`shop.example.com`, `pay.example.com`), all issued by a
made-up "DomainScope Test Renewal CA" whose key, like the leaves' keys, is never written.

An old and a new certificate (lib/certdiff.js, `tests/js/certdiff.test.js`, the Compare tab in the `cert`
E2E suite): `gen_certdiff_fixtures.mjs` (no OpenSSL) made a throwaway PKI whose keys are never written —
`certdiff_old.pem` (RSA 2048 for `example.com`, `*.example.com`, `legacy.example.net`, `mail.example.org`
and `192.0.2.10`, serverAuth + clientAuth, 3 SCTs, issued by "DomainScope Test Diff CA 1"),
`certdiff_new.pem` (EC P-256 without the wildcard, the `.net` name and the address, plus `www`, `api` and
`shop.example.org`; serverAuth only, 2 SCTs, must-staple, another OCSP host and a CRL, issued by
"DomainScope Test Diff CA 2" under another root) and `certdiff_renewed.pem` (the old one renewed with the
same key, names and issuer, the leaf alone). The old and the new file hold the leaf and its intermediate,
as a server sends them.

Certificate kinds (the CLI's `ORIGIN_CERT` / `PRIVATE_CERT`, lib/verify.js): `gen_cli_kind_fixtures.sh`
made `cli_public_wild` (issued by a CA nobody lists, like a public one), `cli_origin_wild` (the
Cloudflare Origin CA's issuer DN on a **test key**, not Cloudflare's), `cli_private_wild` issued by
`cli_private_ca.pem`, and `cli_private_ca_rekeyed.pem` (the same CA name on another key, so the
key identifiers disagree); all cover `*.wild.example.net`. `cloudflare_origin_ca_rsa.pem` and
`cloudflare_origin_ca_ecc.pem` are the real Origin CA roots (developers.cloudflare.com/ssl/static/,
downloaded 2026-09-27): public certificates, used to check that the issuer DNs are recognised.

`inventory-targets.txt` is the Servers view's `targets.txt` for server names with spaces, `#`,
`//`, `;`, `=`, `:`, a control character, an IP address and an IP range
(`tests/js/ui-dom.test.js` builds it, `tests/python/test_inventory_targets.py` reads it back with
the CLI).

PKCS#12 bundles (lib/pkcs12.js, `tests/js/pkcs12.test.js`, the `pfx` E2E suite): `gen_p12_fixtures.mjs`
made a throwaway PKI — `p12_root.pem`, `p12_inter.pem` and the leaves `p12_rsa.pem` (RSA 2048,
p12.example.com), `p12_ec.pem` (EC P-256, `*.p12.example.net`) and `p12_p384.pem` (EC P-384,
p384.example.org) — and bundled them with `openssl pkcs12 -export` as `p12_*.p12`: OpenSSL 3's AES
default, `-legacy` (RC2-40 + 3DES), RC2-128 + two-key 3DES, AES-128 / AES-192 with a SHA-512 MAC,
PBMAC1, the empty password, no MAC, a Turkish password with an emoji, a password as OpenSSL 1.0.x
encoded it, nothing encrypted, certificates only, and a key that belongs to another certificate
than the leaf. The keys exist only inside the bundles. `p12_expected.json` holds the passwords and
what OpenSSL reads back from each bundle (`openssl pkcs12 -info`, certificate hashes in file
order, whether the key belongs to the leaf); the tests compare against it, never against the code
under test.

bundle-check (the CLI's `bundle-check` subcommand, `tests/python/test_bundle_check.py`):
`gen_bundle_fixtures.sh` made a throwaway PKI — `bundle_root.pem` and `bundle_inter.pem` (EC P-256
CAs whose keys were never kept), `bundle_leaf.pem` (RSA 2048, `www.example.com` and `example.com`,
with an AIA "CA Issuers" URL) with its key as PKCS#8 (`bundle_leaf.key`), PKCS#1
(`bundle_leaf.rsa.key`) and encrypted PKCS#8 (`bundle_leaf.enc.key`, password `bundle-test`) and its
CSR (`bundle_leaf.csr`), `bundle_ec_leaf.pem` (EC P-256, `api.example.net`) with its SEC1 key with
and without the public point (`bundle_ec_leaf.key`, `bundle_ec_leaf.nopub.key`) and its CSR, another
RSA key and a CSR made with it (`bundle_other.key`, `bundle_other.csr`), `bundle_ca_reversed.pem`
(the root before the intermediate, as some CAs ship their bundle), and `bundle_selfsigned_ca.pem`
(P-256, `CN=www.example.com`, what `openssl req -x509` makes with OpenSSL's default configuration:
self-signed and CA:TRUE, without keyUsage or subjectAltName; its key was not kept).

STARTTLS and the TLS audit of the CLI (`tests/python/test_starttls_audit.py`): `gen_starttls_fixtures.sh`
made `starttls_ec_leaf.pem`, a self-signed EC P-256 certificate for `www.example.com` and
`example.com`, with its throwaway key `starttls_ec_leaf.key`: with `bundle_leaf.pem` (RSA, the same
names) a test server serves an RSA + ECDSA pair, the way a dual-certificate nginx or HAProxy does.

An expired cross-sign (the chain check of the CLI's `--tls-audit`, `tests/python/test_tls_audit_fleet.py`):
`gen_cross_fixtures.sh` made a throwaway PKI (EC P-256, valid 2025-01-01 .. 2060-01-01 unless noted, the
CA keys never kept) — `cross_root.pem` (Example Test Cross Root, the root the test client trusts),
`cross_old_root.pem` (an older root, valid from 2010), `cross_root_by_old.pem` (the Cross Root's name and
key cross-signed by the old root, expired on 2024-09-30, the way the AddTrust and DST Root CA X3
cross-signs expired), `cross_inter.pem` (the Issuing CA under the Cross Root) and `cross_inter_old.pem`
(its first copy: the same name and key, expired on 2024-09-30) — and the leaf `cross_leaf.pem`
(`www.example.com`, `example.com`) with its throwaway key `cross_leaf.key`.

`estate/report-a.json` and `estate/report-b.json` are `--estate --json` reports of the CLI over a
made-up network (two sites a week apart; documentation addresses only), written by
`python tests/python/test_estate.py --write-fixtures`: `tests/python/test_estate.py` checks that they
are exactly what the CLI writes, `tests/js/estate.test.js` that lib/estate.js computes the same
`estate` from them, and the `estate` E2E suite imports them in the Certificate estate view.

Missing intermediates and root lifecycle (lib/chainfix.js, `tests/js/chainfix.test.js`, the
`chainfix` E2E suite): `gen_chainfix_fixtures.mjs` (no OpenSSL) made a throwaway PKI whose keys
are never written — `chainfix_root.pem` (a current root every store includes),
`chainfix_old_root.pem` (removed from every store), `chainfix_inter.pem` (the Issuing CA under the
current root) and `chainfix_inter_cross.pem` (the same name and key cross-signed by the old root),
`chainfix_old_root_cross.pem` (the old root's key under the current root), `chainfix_policy.pem`
→ `chainfix_deep_ca.pem` (two levels), `chainfix_bad_root.pem` / `chainfix_bad_ca.pem` (a root
Chrome distrusts after 2026-01-31 and Mozilla after 2026-06-30, expiring 2040-03-01),
`chainfix_mail_ca.pem` / `chainfix_expired_ca.pem` (e-mail only, and expired in 2025: the build
leaves both out) — and the leaves `chainfix_leaf.pem`, `chainfix_leaf_noaki.pem` (no authority
key id), `chainfix_leaf_unknown.pem` (an issuer no list holds), `chainfix_leaf_deep.pem` and
`chainfix_leaf_lifecycle.pem`. From CCADB-shaped report rows, `tools/build-intermediates.mjs`
built the test dataset `intermediates/` (the format of `assets/data/intermediates/`, the shard
files that would be empty left out: the tests answer `{}` for them); as in the real list, the
Deep CA comes from the certificate records and a PEM report row, the others from "Mozilla's
report". `--dataset` rebuilds only the test dataset from the PEM files (after a change to the
builder's output). The shared DER encoder of both generators is `der-builder.mjs`.

Embedded SCTs (lib/sct.js, tests/js/sct.test.js, the Transparency group of the cert E2E suite):
`gen_sct_fixtures.mjs` writes `sct/` with keys it never saves — "DomainScope Test SCT CA"
(`sct_ca.pem`), seven test CT logs that sign real RFC 6962 SCTs over each leaf's precertificate
entry (issuer key hash, the TBS without the SCT extension), and `sct/log_list.json`, a list of
six of them in the format of Google's CT log list v3 (three "Example Log Operator" operators, the
states usable, retired, readonly and pending, two static-ct-api logs whose SCTs carry a
`leaf_index` extension; the seventh log is in no list). The `www.example.com` leaves, issued from
2026-09-01: `sct_compliant.pem` (90 days, two operators), `sct_one_operator.pem` (one operator,
one log retired after the SCT), `sct_long.pem` / `sct_long_ok.pem` (397 days with two and three
SCTs), `sct_unknown.pem` (an unknown and a pending log), `sct_static_only.pem` (no RFC 6962 log,
which Apple wants) and `sct_precert.pem` (a precertificate: the CT poison, no SCTs). `--force`
makes new keys, so the log IDs change: the tests read them from `log_list.json`.

Provider IP ranges (tools/build-ranges.mjs, `tests/js/build-ranges.test.js`): `ranges/` holds one
hand-written answer per published list, each shaped exactly like the real source but with
documentation prefixes only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`)
— `cloudflare-ips-v4.txt` / `cloudflare-ips-v6.txt` (one prefix a line), `fastly.json`, `aws.json`
(CloudFront tagged, plus other services), `github-meta.json` (Pages among other keys), `goog.json`
and `cloud.json`, `oracle.json`, `digitalocean.csv` (an RFC 8805 geofeed) and the two RIPEstat
`ripe-as*.json`. They are a complete offline cache, so `downloadSource(..., { cache: FIX, offline:
true })` reads them; the builder's checks refuse documentation space, so the tests pass a permissive
`routable`. No generator: the fixtures are small enough to edit by hand.

Sender lists (tools/build-senders.mjs, `tests/js/build-senders.test.js`): `senders/` holds a
hand-written `base_reverse_dns_map.csv` shaped like parsedmarc's map with documentation names only —
every mail-relevant type, ISP rows (one with the type in lower case), names with quoted commas and
doubled quotes, a base domain in capitals, one without a dot, a public suffix and a duplicate —, the
first lines of the Apache `LICENSE` and a maps `README.md` without a licence section of its own. The
three form a complete offline cache once copied under the builder's cache names. No generator.

Mail reports (lib/dmarcreport.js, lib/tlsrpt.js, lib/zipread.js, the `reports` E2E suite): `mailreports/src/`
holds hand-written reports in the formats reporters send, with documentation data only — a Google-style
and a Microsoft-style DMARC aggregate report for `example.com`, a DMARCbis-style one (the `dmarc-2.0`
namespace) for `example.net`, and a Google- and a Microsoft-style TLS-RPT report. The reporters keep their
organisation names; their contact addresses and pages are under `example.org`. `mailreports/gen_mailreports.py`
packs them with Python's own `zipfile` and `gzip` (so the zip reader is tested against archives another
implementation wrote): the Google report as a `.zip`, the Microsoft one as `.xml.gz`, the TLS reports as
`.json.gz`, `reports-2026-09.zip` (a mailbox export: those files stored, a `notes.txt` that is no report and
the `__MACOSX/` entries macOS adds) and `descriptor.zip` (sizes in data descriptors, written to a pipe).

IP enrichment (lib/ipenrich.js, `tests/js/ipenrich.test.js`): `ipenrich/ripestat.json` holds RIPEstat answers of
the four data calls IP Intel › Check routing makes (network-info, rpki-validation with each status — valid,
invalid_asn, invalid_length, unknown —, routing-status clean, MOAS with more-specifics and low visibility, and
unannounced, abuse-contact-finder, and an error answer), and `ipenrich/peeringdb.json` a PeeringDB `/api/net`
record and its 404 "Entity not found" body. They are hand-written in the shape of live answers seen on
2026-10-08 (every field the live answer had), with documentation data only: 192.0.2.0/24, 198.51.100.0/24,
AS64496–AS64511 and `example.net`.

DNSSEC chains (lib/dnssec.js, `tests/js/dnssec.test.js`, the DNSSEC chain group of the `lookup` E2E
suite): `dnssec/signed-zones.mjs` signs a small tree under the documentation TLD `example.` with
node:crypto on every run (no key or signature is committed) — a test root (RSA/SHA-256) and
`example` (ECDSA P-256), then `rsa.example`, `ecdsa.example`, `ed.example` (Ed25519), `n3.example`
(NSEC3), `expired.example` (every signature expired a day ago), `rollover.example` (its DS names a
key the zone no longer serves), `gost.example` (algorithm 12, which the validator does not check)
and `unsigned.example` (no DS). Its `resolve()` answers a question the way a resolver asked with
the DO and CD bits would (NSEC / NSEC3 proofs included), `fakeDns()` wraps that as a DohClient,
and `answerTable()` gives the wire answers the E2E suite's in-page DoH serves. The signing input
is built there independently of the validator, so a canonical-form mistake does not cancel out.
