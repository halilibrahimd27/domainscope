# Zone fetch fixtures

HTTP answers of the two DNS provider APIs `assets/js/lib/zonefetch.js` reads, as a page in a browser
receives them, for `tests/js/zonefetch.test.js` and the offline `zone` E2E suite. Every name is
`example.com` / `.net`, every address is documentation space, and no file holds a real token: tests
build their made-up tokens from pieces.

`headers` lists only what a page can read: neither API sends `Access-Control-Expose-Headers`
(checked 2026-10-02), so a browser sees `content-type` and `content-length` and never `Link`,
`Retry-After` or `ratelimit-*`.

| File | Answers |
| --- | --- |
| `desec.json` | `pagination`: the 400 deSEC sends for a listing over 500 RRsets without `cursor` (its text from desec-stack `LinkHeaderCursorPagination`). `invalid-token`, `no-credentials`: recorded live on 2026-10-02 (401, made-up token). `not-found`: a domain of another account or none (404, Django REST framework's text). `throttled`: Django REST framework's 429 text (deSEC's GET limit is 10/s and 50/min). The 200 listing is `tests/fixtures/zones/desec-api.json` (a deSEC answer, timestamps included). |
| `digitalocean.json` | `unauthorized`: recorded live on 2026-10-02 (401, made-up token). `forbidden`, `not-found`, `too-many-requests`: the error bodies of DigitalOcean's OpenAPI specification (403 for a token without the `domain:read` scope). The 200 pages are `tests/fixtures/zones/digitalocean-api-page1.json` and `-page2.json`. |
