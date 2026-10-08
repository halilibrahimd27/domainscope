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
the checks ask keyless public services only (the alerts below are optional secrets). The checkout
keeps no token while the checks run (`persist-credentials: false`): only the commit step and the
issue step are given it.

1. Create a private repository with a `domains.txt`: one domain per line, `#` comments.
2. Copy `nightly-domainscope.yml` to its `.github/workflows/`, and pin `ref:` to a DomainScope
   commit SHA (or to a release tag once there is one).
3. Switch on the steps you want (health and the Certificate Transparency watch run by default;
   subdomain discovery, an exact host list, zone drift, renewal readiness, the policy audit and
   the served certificates with their renewal windows and revocation are commented out).
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

**Alerts.** The issue keeps the record; an alert reaches you where you already look. Set any of
these Actions secrets in the repository (Settings › Secrets and variables › Actions). A secret that
is not set is empty, and then nothing is sent:

- `DOMAINSCOPE_NOTIFY_URL`: the changes that count, posted on the nights there are any. The URL
  picks the format: a Slack incoming webhook, a Teams or Power Automate workflow, a Discord
  webhook, Telegram (`https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat id>`), a
  Google Chat space webhook, an ntfy topic (`https://ntfy.sh/<topic>`), or any other URL, which
  gets JSON (`tool`, `command`, `run` — the Actions run's link —, `counts`, `changes` …). Several
  URLs: separate them with spaces.
- `DOMAINSCOPE_NOTIFY_BAD_URL`: only the changes that count and are bad, the pager route.
  PagerDuty's Events API (`https://events.pagerduty.com/v2/enqueue?routing_key=<integration key>`)
  gets one incident per problem — its `dedup_key` is the same every night, so a problem pages once
  — and a resolve on the night the check shows the problem over: fixed, back where it was before
  it paged, renewed. A night a lookup fails proves nothing, so the incident stays open. Severity
  is `critical` for registration, delegation, DNSSEC and trust problems — the audit's registrar,
  transfer lock, registry status, DNSSEC and expiry rules, drift's name servers, health's expired,
  held or deleted registration and broken DNSSEC, ct's certificate in use revoked — and `error`
  for the rest. `results/NAME.json` keeps the incidents still open (`notify.open`); at most 50
  events a night.
- `DOMAINSCOPE_NOTIFY_SECRET`: signs the JSON webhook. `X-DomainScope-Timestamp` carries the Unix
  time and `X-DomainScope-Signature` is `sha256=` and the hex HMAC-SHA256 of the timestamp, a dot
  and the body: compute the same over the raw body, compare in constant time, and refuse an old
  timestamp.
- `DOMAINSCOPE_NTFY_TOKEN`: an ntfy access token (`Authorization: Bearer`). The message is plain
  text with a title, priority 4 when a change is bad (else 3) and a tag.

Webhook URLs work as passwords: they are never printed or written, and the log names their hosts
only. https:// only. A notification that is not delivered (after one retry) fails the job — the
check reads `NAME:notify` — while its changes still open the issue (so does a night on which only
a PagerDuty resolve failed, with no change to list), and `results/NAME.json` keeps the night before
— only the PagerDuty incidents still open are updated in it — so the next night sends them again.

Each check is stopped after `CHECK_MINUTES` (20) and all of them after `RUN_MINUTES` (45), well
inside the job's `timeout-minutes` (60): on a slow night (crt.sh down, a large discovery) that
check fails, keeps last night's files, and the results and the issue still get their turn. Raise
the three together when you switch more checks on.

What counts as a change mirrors the Python CLI's `--baseline`: a new or resolved health finding
and the score, a host that appears, stops resolving, leaves its proxy or becomes a dangling CNAME,
a new certificate issuer or a first certificate for a name, a new certificate from a CA you did
not name, a certificate whose renewal is overdue crossing a radar day, a zone record set whose live
state moved, a renewal verdict. Moves between failure states, Certificate Transparency sources that
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
`policy.json` exported from the app's Domain portfolio, or `--preset baseline`, `strict-mail`,
`parked` or `corporate`): the registration from the registry's RDAP server (expiry, transfer lock
and how deep it goes, critical statuses, the registrar's class), the name servers' own domains,
their expiry and DNS providers, DNSSEC, CAA and the mail posture. It
exits 4 while a rule fails, so the issue stays open with the failing rules until every one
passes; a rule that could not be checked (a TLD without RDAP, a lookup that failed) is no
failure, unless it failed when last checked (--baseline): it still counts as failed. The night
after compares with the last night that checked it. Whatever the policy, the summary also lists
each domain's security score on CSC's eight measures as a table (the lowest score first, at most
100 rows); the score never changes the exit code.

**The Certificate Transparency watch.** `ct` raises what the app's Domain portfolio ›
Certificates (CT) tab shows. Each domain's report keeps the ids of the certificates seen (the
next night's baseline, as the app's workspace keeps them), so the summary lists what was logged
since the night before, next to the expiry radar (`--radar`, 30, 14 and 7 days left by default),
the certificates from a CA you did not name with `--expected-ca` (repeat it for each CA you use:
`letsencrypt`, `digicert`, a CAA domain such as `sectigo.com`, or part of a private CA's name),
wildcards and the certificates logged only as a precertificate (Cert Spotter's answers say
which; crt.sh's do not). A new certificate from a CA you did not name counts (`CA`), and so do a
current certificate — the newest of its names — crossing a radar day once its automatic renewal
is overdue (`EXPIRING`: less than a quarter of its lifetime left; ACME clients renew at a third,
so a 90-day certificate crossing 30 days is listed only) and the certificate in use being revoked
(`REVOKED`).

**Served certificates, renewal windows and revocation.** `tls` (commented out: uncomment it and
add a `tls-hosts.txt` with a host or `host:port` per line) connects to every address of each host,
reads the certificate it serves and says whether it expired, is trusted and carries the name. With
`--ari` it asks the issuing CA for its renewal window (ACME Renewal Information: Let's Encrypt,
Google Trust Services, ZeroSSL, Sectigo, SSL.com), and with `--revocation` it reads the CRL the
certificate names. A window that opens (`RENEW-NOW`), one that moves more than a day earlier
(`MOVED-UP`: CAs do that before a mass revocation), a new explanation from the CA (`CA-NOTICE`)
and a revoked certificate still served (`REVOKED`) count, and so do a handshake that stops
completing and another certificate that drops a name or changes the key type or the CA. A CA is
not asked again before the Retry-After of its last answer, and an IPv6 address the runner cannot
reach (GitHub's hosted runners have no IPv6 route) is skipped, never a change. The CA receives
each certificate's CertID (the issuer's key identifier and the serial number, both public).

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
node tools/ds.mjs ct --list domains.txt --expected-ca letsencrypt --radar 21,7 --baseline ct.json --json ct.json
node tools/ds.mjs renew example.com '*.example.com' --ca letsencrypt --challenge dns-01
node tools/ds.mjs dane fullchain.pem
node tools/ds.mjs audit --policy policy.json domains.txt --json audit.json --md audit.md
node tools/ds.mjs tls www.example.com example.com:8443 --ari --revocation --json tls.json
```

Alerts outside the template: put the URLs in the environment rather than on the command line
(where the shell history keeps them), or give them with `--notify URL` / `--notify-bad URL`
(repeatable); `--notify-format` names the format for a self-hosted ntfy server or a
Slack-compatible chat, `--notify-always` posts after every run.

```sh
export DOMAINSCOPE_NOTIFY_URL='https://ntfy.sh/your-topic'
node tools/ds.mjs ct --list domains.txt --baseline ct.json --json ct.json --fail-on-notify-error
```

`node tools/ds.mjs --help` lists every option. Exit codes: 0 done, 1 the run failed (an
unexpected error, printed), 2 usage error (report files that cannot be written, a report file
that is one of the run's own input files, and a baseline that cannot be compared are refused
before anything is sent), 3 a report could not be written after the run, 4 something changed
since `--baseline` (only with `--fail-on-change`) or a rule of the policy failed (`audit`), 5 a
notification was not delivered (only with `--fail-on-notify-error`), 130 interrupted (Ctrl-C, or
`timeout -s INT`: nothing is written, not while the notifications are posted either); when several
apply, 3 comes first, then 5, then 4. DNS goes to the app's DoH resolvers (Cloudflare,
Google, DNS.SB; Quad9 and CZ.NIC answer over HTTP/2 only, which Node's fetch does not speak) with
the app's concurrency; nothing goes to Globalping. A discovery run prints its progress through
the long stages and the scanner's own warnings (a list of names cut at 20,000, resolvers that
stopped answering), which also go into the report and the summary.
