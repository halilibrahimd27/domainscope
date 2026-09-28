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

`estate/report-a.json` and `estate/report-b.json` are `--estate --json` reports of the CLI over a
made-up network (two sites a week apart; documentation addresses only), written by
`python tests/python/test_estate.py --write-fixtures`: `tests/python/test_estate.py` checks that they
are exactly what the CLI writes, `tests/js/estate.test.js` that lib/estate.js computes the same
`estate` from them, and the `estate` E2E suite imports them in the Certificate estate view.
