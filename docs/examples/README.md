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
the checks ask keyless public services only. The checkout keeps no token while the checks run
(`persist-credentials: false`): only the commit step and the issue step are given it.

1. Create a private repository with a `domains.txt`: one domain per line, `#` comments.
2. Copy `nightly-domainscope.yml` to its `.github/workflows/`, and pin `ref:` to a DomainScope
   commit SHA (or to a release tag once there is one).
3. Switch on the steps you want (health and the Certificate Transparency watch run by default;
   subdomain discovery, an exact host list, zone drift, renewal readiness and the policy audit
   are commented out).
4. Run it once by hand (Actions › DomainScope nightly › Run workflow): the first night has no
   baseline to compare with, so it only writes `results/`.

Every night after that, each check compares itself with the night before (`results/NAME.json` is
both the baseline and the new report) and:

- commits `results/*.json` (the reports) and `results/*.md` (the summaries), so git history
  keeps every night;
- opens **one** issue labelled `domainscope` when something that counts changed — or updates the
  open one and comments on it — with each changed check's "Changes since the baseline" and
  summary;
- closes that issue on a night with no change on which every check completed. A check that did
  not complete compared nothing, so on such a night the open issue stays open, with a comment
  naming the check;
- fails the job when a check did not complete: a usage error, a report it could not write, or
  its time limit.

Each check is stopped after `CHECK_MINUTES` (20) and all of them after `RUN_MINUTES` (45), well
inside the job's `timeout-minutes` (60): on a slow night (crt.sh down, a large discovery) that
check fails, keeps last night's files, and the results and the issue still get their turn. Raise
the three together when you switch more checks on.

What counts as a change mirrors the Python CLI's `--baseline`: a new or resolved health finding
and the score, a host that appears, stops resolving, leaves its proxy or becomes a dangling CNAME,
a new certificate issuer or a first certificate for a name, a zone record set whose live state
moved, a renewal verdict. Moves between failure states, Certificate Transparency sources that
could not be read, what a failed lookup or source may hide and renewed certificates from known
issuers are listed but never counted. GitHub's hosted runners share their IP addresses and the
anonymous quotas of the passive sources are per address, so a source may be rate limited on some
night: the report says so, and nothing a source could not read counts as a change.

What a night could not read, its report carries from the last night that read it, so the night
after compares with that read and not with the gap: a certificate from a new certificate
authority issued while crt.sh was down still comes out as a new issuer once crt.sh answers, a
warning of months hidden one night by a failed DMARC lookup is not "new" the night after, and a
host whose lookup failed stays watched and is compared with its last answer (a move off its proxy
meanwhile is said as such). An issuer or a name is new only when a source that lists it has read
the domain in full before, or when its certificate was issued after the first of those full
reads; issuers are named from the certificate's issuer DN, so crt.sh and Cert Spotter name them
alike.

**The policy audit.** `audit` checks each domain of the list against the rules of a policy (a
`policy.json` exported from the app's Domain portfolio, or `--preset baseline`, `strict-mail` or
`parked`): the registration from the registry's RDAP server (expiry, transfer lock, critical
statuses), the name servers' own domains and their expiry, DNSSEC, CAA and the mail posture. It
exits 4 while a rule fails, so the issue stays open with the failing rules until every one
passes; a rule that could not be checked (a TLD without RDAP, a lookup that failed) is no
failure, and the night after compares with the last night that checked it.

**Cert Spotter and more than about 10 domains.** Cert Spotter answers about 10 full-domain queries
an hour per IP address. After its first "rate limited" of a night the runner does not ask it
again until its wait is over (at most an hour), and once crt.sh is down (unavailable, or timed
out on two domains in a row) it is not asked again that night; the domains after that read "not
asked". With more than
about 10 domains most of them are read from crt.sh alone: `--sources crtsh` on the `ct` line
leaves Cert Spotter out altogether.

### The runner on its own

```sh
node tools/ds.mjs health example.com example.org --json health.json --md health.md
node tools/ds.mjs subdomains example.com --level small --baseline subs.json --json subs.json --fail-on-change
node tools/ds.mjs subdomains example.com --exact hosts.txt
node tools/ds.mjs drift example.com.zone --origin example.com --md drift.md
node tools/ds.mjs ct --list domains.txt --json ct.json
node tools/ds.mjs renew example.com '*.example.com' --ca letsencrypt --challenge dns-01
node tools/ds.mjs dane fullchain.pem
node tools/ds.mjs audit --policy policy.json domains.txt --json audit.json --md audit.md
```

`node tools/ds.mjs --help` lists every option. Exit codes: 0 done, 1 the run failed (an
unexpected error, printed), 2 usage error (report files that cannot be written, a report file
that is one of the run's own input files, and a baseline that cannot be compared are refused
before anything is sent), 3 a report could not be written after the run, 4 something changed
since `--baseline` (only with `--fail-on-change`) or a rule of the policy failed (`audit`), 130
interrupted (Ctrl-C, or `timeout -s INT`: nothing is written). DNS goes to the app's DoH resolvers (Cloudflare,
Google, DNS.SB; Quad9 and CZ.NIC answer over HTTP/2 only, which Node's fetch does not speak) with
the app's concurrency; nothing goes to Globalping. A discovery run prints its progress through
the long stages and the scanner's own warnings (a list of names cut at 20,000, resolvers that
stopped answering), which also go into the report and the summary.
