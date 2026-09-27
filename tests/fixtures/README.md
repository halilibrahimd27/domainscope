# Test fixtures

Self-signed / test-CA certificates generated with OpenSSL for the unit and integration tests.
`expected.json` holds the OpenSSL-derived ground truth that both the JavaScript parser
(`assets/js/lib/x509.js`) and the Python CLI parser are tested against.

The `*.key` files are **throwaway private keys that exist only for tests** (the CLI tests start
local TLS servers with them). They protect nothing and must never be used anywhere else.

`inventory-targets.txt` is the Servers view's `targets.txt` for server names with spaces, `#`,
`//`, `;`, `=`, `:`, a control character, an IP address and an IP range
(`tests/js/ui-dom.test.js` builds it, `tests/python/test_inventory_targets.py` reads it back with
the CLI).
