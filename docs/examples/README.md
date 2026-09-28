# Examples

## Nightly checks with GitHub Actions

A browser tab that is closed monitors nothing. [`nightly-domainscope.yml`](nightly-domainscope.yml)
runs DomainScope's checks every night on GitHub's runners with the headless runner
[`tools/ds.mjs`](../../tools/ds.mjs) (Node 22+, no dependency: the app's own libraries), commits
what it found and tells you when something changed.

**Use it in a private repository.** The results name your hosts, their addresses and your DNS
records. **Never commit inventories or zone files unless you mean to**: the zone drift step reads
a zone export from the repository, so it stays commented out until that file belongs there (the
origin addresses behind proxied names are hidden in the results unless you add
`--include-origins`). **No secret is needed**: the job uses the workflow's own `GITHUB_TOKEN`, and
the checks ask keyless public services only.

1. Create a private repository with a `domains.txt`: one domain per line, `#` comments.
2. Copy `nightly-domainscope.yml` to its `.github/workflows/`, and pin `ref:` to a DomainScope
   release tag or commit.
3. Switch on the steps you want (health and the Certificate Transparency watch run by default;
   subdomain discovery, an exact host list, zone drift and renewal readiness are commented out).
4. Run it once by hand (Actions › DomainScope nightly › Run workflow): the first night has no
   baseline to compare with, so it only writes `results/`.

Every night after that, each check compares itself with the night before (`results/NAME.json` is
both the baseline and the new report) and:

- commits `results/*.json` (the reports) and `results/*.md` (the summaries), so git history
  keeps every night;
- opens **one** issue labelled `domainscope` when something that counts changed — or updates the
  open one and comments on it — with each changed check's "Changes since the baseline" and
  summary;
- closes that issue on a night with no change;
- fails the job when a check could not run at all (a usage error, a report it could not write).

What counts as a change mirrors the Python CLI's `--baseline`: a new or resolved health finding
and the score, a host that appears, stops resolving, leaves its proxy or becomes a dangling CNAME,
a new certificate issuer or a first certificate for a name, a zone record set whose live state
moved, a renewal verdict. Moves between failure states, what a failed lookup may hide and renewed
certificates from known issuers are listed but never counted. GitHub's hosted runners share their
IP addresses and the anonymous quotas of the passive sources and Cert Spotter are per address, so
a source may be rate limited on some night: the report says so, and nothing it could not read
counts.

### The runner on its own

```sh
node tools/ds.mjs health example.com example.org --json health.json --md health.md
node tools/ds.mjs subdomains example.com --level small --baseline subs.json --json subs.json --fail-on-change
node tools/ds.mjs subdomains example.com --exact hosts.txt
node tools/ds.mjs drift example.com.zone --origin example.com --md drift.md
node tools/ds.mjs ct --list domains.txt --json ct.json
node tools/ds.mjs renew example.com '*.example.com' --ca letsencrypt --challenge dns-01
node tools/ds.mjs dane fullchain.pem
```

`node tools/ds.mjs --help` lists every option. Exit codes: 0 done, 1 the run failed (an
unexpected error, printed), 2 usage error (report files that cannot be written and a baseline
that cannot be compared are refused before anything is sent), 3 a report could not be written
after the run, 4 something changed since `--baseline` (only with `--fail-on-change`), 130
interrupted. DNS goes to the app's DoH resolvers (Cloudflare,
Google, DNS.SB; Quad9 and CZ.NIC answer over HTTP/2 only, which Node's fetch does not speak) with
the app's concurrency; nothing goes to Globalping.
