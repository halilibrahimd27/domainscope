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
the checks ask keyless public services only, and the tls check your own hosts (the alerts below
are optional secrets). The checkout
keeps no token while the checks run (`persist-credentials: false`): only the commit step and the
issue step are given it.

1. Create a private repository with a `domains.txt`: one domain per line, `#` comments.
2. Copy `nightly-domainscope.yml` to its `.github/workflows/`, and pin `ref:` to a DomainScope
   commit SHA (or to a release tag once there is one).
3. Switch on the steps you want (health, the Certificate Transparency watch, the takeover watch
   and the change watch run by default, and the served-certificate monitor when the repository
   has a `tls-hosts.txt`; subdomain discovery, an exact host list, the takeover watch over the
   hosts discovery found, the change watch with more names and the name servers asked directly,
   zone drift, renewal readiness, the policy audit and the served certificates' renewal windows,
   revocation and HTTP answers are commented out).
4. Run it once by hand (Actions › DomainScope nightly › Run workflow): the first night has no
   baseline to compare with, so it only writes `results/`.

Every night after that, each check compares itself with the night before (`results/NAME.json` is
both the baseline and the new report) and:

- commits `results/*.json` (the reports) and `results/*.md` (the summaries), so git history
  keeps every night, and `results/history/YYYY-MM.jsonl` (`--history`): one line per domain and
  check a night — whether it completed, the health score and grade, the soonest certificate
  expiry and what changed (each change's tag and item: a finding, a host, a record set, an
  issuer, a certificate, an endpoint's address or a takeover risk; never its words or the values
  before and after) —, 13 months of it. Open the
  `results` folder in DomainScope's **Monitoring** view (read in the browser, nothing uploaded), or
  this repository there with a fine-grained token that can only read its contents: a row per
  domain with its trend, the certificates under 21 days, the checks that did not complete and the
  changes night by night;
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
  held or deleted registration and broken DNSSEC, ct's certificate in use revoked, tls's untrusted
  chain and expired or revoked certificate still served, the change watch's registrar, name
  servers, DS records, a transfer lock removed and a hold — and `error` for the rest. The change
  watch's events (another registrar, other name servers or DS records, a record changed) stay open
  until you resolve them: nothing a later night reads says the change was wanted.
  `results/NAME.json` keeps the incidents still open (`notify.open`); at most 50 events a night.
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
not name, a certificate whose renewal is overdue crossing a radar day, a takeover risk of medium
severity or above that appears, goes or moves, a zone record set whose live state moved, a renewal
verdict, a served certificate whose renewal is overdue entering its warning days or expiring, an
address serving an untrusted chain, a certificate without the name or an older one than the
renewal CT logged. Moves between failure states, Certificate Transparency sources that
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

**The takeover and dependency-expiry watch.** `takeover` checks what the app's Subdomains ›
Takeover risks and Domain Health › Dependencies check, for each domain of the list: the registrable
domains its NS, MX and SPF records (include, redirect, a, mx, exists, ptr), DMARC report addresses,
DKIM CNAMEs (8 common selectors, more with `--dkim-selectors`), CAA iodef addresses, MTA-STS host,
Autodiscover and SIP SRV records, HTTPS record and `_acme-challenge` delegation point to, looked
up over RDAP once a night each. A domain counts as unregistered only when its registry has no
record of it **and** DNS says it does not exist; pending deletion, expired or expiring within 30
days is reported too, and so is a CNAME left on a released service resource. With
`--from-subdomains results/subdomains.json` (after the subdomains line) or `--names hosts.txt` the
CNAME chains of those hosts are asked again too. A new risk of medium severity or above counts
(`RISK`), and so do a risk gone (`GONE`), worse or better (`WORSE`, `BETTER`); a domain that had
lapsed and is registered again while a record still names it is said as such ("make sure it is
yours"). A risk whose lookup gave no answer is carried from the last night that read it, never
gone. Hosts on a service only its page can tell (S3, GitHub Pages …) are listed "to check": the
page check stays in the app, behind a click.

**The registration and record change watch.** `watch` is a hijack watch: for each domain of the list
it reads what the registry says (over RDAP, paced per registry as the audit is) — the registrar and
its IANA ID, the statuses, the expiry, the name servers — and the DS records at the parent, the
zone's own NS records, and the record sets of the domain, its `www` and `_dmarc` (and with `--names
watch-hosts.txt` up to 200 more host names under the domains) of each of `--types` (A, AAAA, CNAME,
MX, NS, TXT, CAA, SOA, DS, DNSKEY and HTTPS by default). Another registrar (`REGISTRAR`), a client
or server transfer prohibition removed (`LOCK`; while another one still blocks transfers it counts
as info), a hold, a pending delete, a redemption period or a pending transfer arriving (`STATUS`),
other name servers (`NS`, the registry's or the zone's), a DS record removed or changed (`DS`), an
expiry not renewed with less than 30 days left (`EXPIRY`, said once; renewed is good news) and an
MX, NS, CAA, SPF or DMARC record that changed (`RECORD`; a hosted DMARC record too: the policy its
`_dmarc` CNAME leads to, and that CNAME) count as bad. An A, AAAA or CNAME change counts as info,
unless the name moved to another kind of provider — off its CDN to a direct address, or to a CNAME
that ends nowhere — which is bad. A verification token (`google-site-verification=` …) is named by
its service, never printed. Not counted: a CDN's edge addresses rotating, a new SOA serial
(`SERIAL`), a zone-signing key rolling, and a record set that changed 3 times or more in the last 7
nights (`FLAPPING`, said once; its later changes are not listed while it keeps changing, unless one
is bad). With `--authoritative` every name server is asked directly over UDP (and TCP when an answer
is truncated) on port 53: servers that answer the same SOA serial differently two nights in a row
(`SYNC`; other edges of one CDN, or an answer a provider picks per query, as weighted records give,
are not) and servers that answer without authority, REFUSED or SERVFAIL, or not at all — or stop
answering after the SOA, then not asked further that night — (`LAME`) count; a secondary still on an
older serial is listed. When port 53 is blocked on the runner's network the report says so and the
record sets come from DoH alone; an IPv6 address the runner cannot reach is skipped. `--ttl`
compares the TTLs the name servers give too (with `--authoritative`: a resolver's cache counts TTLs
down). The app's Domain portfolio says the same of the registration on its next **Check portfolio**:
"Changed since your last check".

**Served certificates: the monitor.** `tls` runs when the repository has a `tls-hosts.txt` (a host
or `host:port` per line). It connects to every address of each host and reads the certificate it
serves: the expiry, whether a client's root store trusts the chain (a missing intermediate is named
from the CCADB list the site ships), whether it carries the name, the chain the server sends, its
OCSP staple (reported only: Let's Encrypt has had no OCSP since August 2025), the protocol and the
key exchange. The template's line reads tonight's ct report (`--ct results/ct.json`, after the ct
line) without a CT query of its own: an address still serving an older certificate than the
renewal CT logged for the name (issued more than 48 hours later, with every name of the served one)
is `NOT_DEPLOYED`. A certificate entering `--warn-days` (21 by default) with its automatic renewal
overdue (`EXPIRING`: less than a quarter of its lifetime left, so a 90-day certificate at 21 days
and a 47-day one at 11; earlier it is listed only), one expired and still served (`EXPIRED`), a host
with an address serving an untrusted chain (`UNTRUSTED`), a certificate without the name
(`MISMATCH`) or an older certificate than the renewal (`NOT-LIVE`) count, once per host and
problem, and so do a handshake that stops completing and another certificate that drops a name or
changes the key type or the CA. `--http` also sends `GET /` over HTTPS (the status and HSTS) and
over HTTP to port 80: a 5xx (`HTTP`) and http:// no longer redirecting to https:// (`REDIRECT`)
count. `--from-subdomains results/subdomains.json` adds the hosts subdomain discovery found
(`--skip-cdn` leaves out the ones behind a CDN), and `--max-endpoints` (500) caps the handshakes of
a night: the hosts past it keep their last check.

**Renewal windows and revocation.** With `--ari` the tls check asks the issuing CA for its renewal
window (ACME Renewal Information: Let's Encrypt, Google Trust Services, ZeroSSL, Sectigo, SSL.com),
and with `--revocation` it reads the CRL the certificate names. A window that opens (`RENEW-NOW`),
one that moves more than a day earlier (`MOVED-UP`: CAs do that before a mass revocation), a new
explanation from the CA (`CA-NOTICE`) and a revoked certificate still served (`REVOKED`) count. A
CA is not asked again before the Retry-After of its last answer, and an IPv6 address the runner
cannot reach (GitHub's hosted runners have no IPv6 route) is skipped, never a change. Your hosts
see a handshake (and with `--http` a GET) from GitHub's runners; the CA receives each certificate's
CertID (the issuer's key identifier and the serial number, both public).

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
node tools/ds.mjs tls --list tls-hosts.txt --ct ct.json --http --warn-days 30 --baseline tls.json --json tls.json
node tools/ds.mjs tls --from-subdomains subs.json --skip-cdn --max-endpoints 200
node tools/ds.mjs takeover --list domains.txt --from-subdomains subs.json --baseline takeover.json --json takeover.json
node tools/ds.mjs watch --list domains.txt --names watch-hosts.txt --authoritative --baseline watch.json --json watch.json
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
