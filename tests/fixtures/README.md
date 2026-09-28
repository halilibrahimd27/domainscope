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
