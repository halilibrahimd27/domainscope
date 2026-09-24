# Zone import fixtures

Inputs for `assets/js/lib/zoneparse.js` (and the zone analysis libraries). Every name is
`example.com` / `.net` / `.org` or `example-test.com.tr`; every address is documentation space
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), private space for the lint cases,
or the fake Cloudflare edge `104.16.1.1`. Cloudflare's originless placeholders `192.0.2.0` and
`100::` appear only in `placeholder.cf.txt`.

| File | Format | What it exercises |
|---|---|---|
| `cloudflare-export.txt` | Cloudflare BIND export | `;; Domain:` header, undotted SOA owner, TTL 1 = Auto, `cf_tags` (quoted values, flatten, a comment containing `cf_tags=`), mixed proxy flags, delegation + occluded name, 255+N DKIM |
| `cloudflare-api.json`, `-page1.json`, `-page2.json` | Cloudflare API JSON | SRV from `data`, MX `priority`, quoted and legacy TXT, `shadowed_by`, `flatten_cname`; the two pages overlap by one id and page 1 alone is a partial export (`gen-parse-golden.mjs --split` rebuilds them) |
| `route53.json` | Route 53 JSON | octal `\052` / `\040` names and TXT escapes, aliases (CloudFront, ELB, S3 website, API Gateway, same zone), routing policies, `IsTruncated` |
| `example.com.yaml` | octoDNS YAML | `? ''` apex, sequences at the parent's indent, `\;`, `proxied` / `auto-ttl`, dynamic pools, `ignored`; the zone name comes from the file name |
| `bind-edge.zone.txt` | generic RFC 1035 | `$ORIGIN` changes, `$TTL` units, blank owners, class/TTL order, decimal `\042` / `\052`, `\.` in a label, `$GENERATE`, `$INCLUDE`, CH class, missing trailing dot, and after the `$INCLUDE`: a TTL above 2^31−1, `999.1.1.1`, an MX without preference, RFC 3597 `\#` data, UTF-8 `\195\164` |
| `cpanel-example.com.db.txt`, `directadmin-example.com.db.txt`, `godaddy.txt`, `cli53.txt`, `plesk-info.txt` | panel / registrar / tool exports | `; Zone file for`, the undotted apex owner, file-name origin correction, `_svc._tcp.@`, `AWS ALIAS` + routing comments, Plesk `dns --info` |
| `internal.zone.txt`, `placeholder.cf.txt`, `axfr-dig.txt` | BIND | a mostly-private zone, the Cloudflare placeholders, `dig AXFR` output (SOA first and last) |
| `bad/*` | — | robustness: unterminated quote, unbalanced parenthesis, `$INCLUDE`, a CSV inventory, a PEM, YAML anchors / block scalars / `__proto__`, JSON `__proto__` |

`expected/<id>.parse.golden.txt` pins the parser output (one line per record and issue). After a
parser change run `node tests/fixtures/zones/gen-parse-golden.mjs` (diff) or `--write` (update),
and rerun the analysis golden generator in the same change.
