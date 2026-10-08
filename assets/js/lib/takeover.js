/**
 * takeover.js — subdomain takeover and dangling-reference audit (Subdomains › Overview ›
 * "Takeover risks" and Domain Health › Dependencies, ui/takeover-panel.js; the headless runner's
 * `takeover`, tools/ds/takeover.mjs).
 *
 * Three questions about every name a scan found and every name its domains point to:
 *  1. Does a host's CNAME chain end at a service where somebody else can claim the name? The
 *     {@link TAKEOVER_SERVICES} catalogue says, per service, which CNAME targets belong to it,
 *     how a released resource shows (`nxdomain`: the target name no longer exists; `http`: the
 *     service still answers, with a "no such site" page whose text is the fingerprint) and its
 *     status: `vulnerable` (anybody can create a resource with that name), `edge` (possible in
 *     some set-ups only) or `safe` (the service verifies ownership: a stale record to clean up).
 *  2. Does a name the domain depends on sit in a registrable domain that is not registered, about
 *     to be deleted, expired or about to expire? Then whoever registers it serves the host, answers
 *     for the zone, receives the mail or the reports, may send or sign as the domain, or gets
 *     certificates for it. The references ({@link TAKEOVER_REF_KINDS}): CNAME chains, the NS and MX
 *     targets, the SPF include / redirect and a / mx / exists / ptr domains, the DMARC report
 *     addresses, the DKIM selectors' CNAMEs, the CAA iodef addresses, the CNAME chain of
 *     `mta-sts.<domain>`, the Autodiscover and SIP SRV targets, the HTTPS record's TargetName and
 *     the `_acme-challenge` CNAME. Asked through RDAP (lib/rdap.js rdapDomain, injected: paced per
 *     registry there); an RDAP 404 counts only when DNS agrees (NXDOMAIN for the domain's NS), and
 *     a TLD without RDAP is judged by DNS alone, worded as "possibly registrable".
 *  3. For a service whose page decides: does a Globalping HTTP GET of the host return the
 *     service's "no such site" text? ({@link httpCheckOutcome}; the panel asks through
 *     ui/globalping-gate.js, with consent.)
 *
 * The catalogue is our own, written from each provider's documentation and the public
 * discussions collected by the community list "can-i-take-over-xyz" (EdOverflow and
 * contributors, CC BY 4.0, consulted 2026-10-08 — nothing copied or vendored): every entry links
 * the page its status rests on (`ref`). Statuses change as providers add verification; the
 * findings say what to check, never that a takeover has happened.
 *
 * Only an abort rejects: a failed DNS query or RDAP lookup is a failure in the result (with the
 * response, for lib/sourcestatus.js), and Retry passes the registrations already known back in
 * (`known`) so only the failed ones are asked again. Returns codes; the panel words them.
 *
 * DOM-free; runs in browsers and Node 22.
 */

import { normalizeHostname, isPublicSuffix, isSubdomainOf } from './domain.js';
import { createLimiter, throwIfAborted } from './util.js';

/** Catalogue statuses: claimable by anyone, only in some set-ups, or verified by the service. */
export const TAKEOVER_STATUSES = Object.freeze(['vulnerable', 'edge', 'safe']);

/** How a released resource shows: the target name is gone, or the service's page says so. */
export const TAKEOVER_SIGNALS = Object.freeze(['nxdomain', 'http']);

/** Finding severities, most severe first. */
export const TAKEOVER_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

/**
 * The kinds of reference a finding is about: a scanned host's CNAME chain (cname); the domain's
 * name servers (ns), mail servers (mx), SPF include: / redirect= domains (spf) and a: / mx: /
 * exists: / ptr: domains (spf-host); its DMARC report addresses and a `_dmarc` CNAME delegation
 * (dmarc); the CNAME chains of its DKIM selectors (dkim); its CAA iodef addresses (caa); the
 * CNAME chain of `mta-sts.<domain>` (mta-sts); the targets of {@link TAKEOVER_SRV_NAMES} (srv);
 * its HTTPS record's TargetName (https); the CNAME chain of `_acme-challenge.<domain>` (acme).
 */
export const TAKEOVER_REF_KINDS = Object.freeze(['cname', 'ns', 'mx', 'spf', 'spf-host', 'dmarc', 'dkim', 'caa', 'mta-sts', 'srv', 'https', 'acme']);

/**
 * The query a domain's reference of each kind comes from (a failure names it `<owner> <TYPE>`; a
 * scanned host's own chain query is named by the host alone).
 */
export const REFERENCE_QUERIES = Object.freeze({
  ns: 'NS', mx: 'MX', spf: 'TXT', 'spf-host': 'TXT', dmarc: 'TXT', dkim: 'TXT', caa: 'CAA', 'mta-sts': 'A', srv: 'SRV', https: 'HTTPS', acme: 'TXT'
});

/** Kinds whose chain is a host of the domain: a catalogue service at its end can be claimed (nxdomain and the page check by service). */
const HOST_KINDS = new Set(['cname', 'mta-sts']);
/** Kinds where whoever registers an unregistered target serves the domain's names, answers for its zone or gets certificates for it. */
const CRITICAL_KINDS = new Set(['cname', 'ns', 'mta-sts', 'acme']);
/** Kinds whose single target is asked for its own existence (A: NXDOMAIN says it does not exist, whatever the type). */
const EXISTENCE_KINDS = new Set(['ns', 'mx', 'spf-host', 'dmarc', 'caa', 'srv', 'https']);

/**
 * The DKIM selectors whose CNAME is followed: the Domain portfolio's common ones (lib/portfolio.js
 * PORTFOLIO_DKIM_SELECTORS, kept equal by tests/js/takeover.test.js; not imported, so the audit
 * stays light), plus the selectors a caller gives (`extraDkimSelectors`).
 */
export const TAKEOVER_DKIM_SELECTORS = Object.freeze(['google', 'selector1', 'selector2', 'default', 'k1', 's1', 'dkim', 'mail']);

/** The SRV names whose targets are references: Outlook's Autodiscover and SIP (Teams / Skype for Business federation). */
export const TAKEOVER_SRV_NAMES = Object.freeze(['_autodiscover._tcp', '_sip._tls']);

/**
 * Why a reference is at risk (`tko.reason.<code>` in the UI):
 * unregistered (RDAP 404 and NXDOMAIN), unregistered-dns (no RDAP for the TLD, NXDOMAIN),
 * pending-delete (RDAP pending delete / redemption period), expired, expiring (within
 * {@link EXPIRING_DAYS}), nxdomain (the target name does not exist), fingerprint (the service's
 * "no such site" page), check-http (only the page can tell).
 */
export const TAKEOVER_REASONS = Object.freeze([
  'unregistered', 'unregistered-dns', 'pending-delete', 'expired', 'expiring', 'nxdomain', 'fingerprint', 'check-http'
]);

/**
 * What the registration check concluded for one registrable domain: the {@link TAKEOVER_REASONS}
 * it can raise, registered (nothing to report), rdap-404-dns (RDAP 404 but the domain is in DNS:
 * reserved or redacted, not a finding), no-rdap (no RDAP for the TLD and the domain is in DNS),
 * failed (RDAP or the DNS check gave no answer: n/a with Retry).
 */
export const REGISTRATION_VERDICTS = Object.freeze([
  'registered', 'unregistered', 'unregistered-dns', 'pending-delete', 'expired', 'expiring', 'rdap-404-dns', 'no-rdap', 'failed'
]);

/** HTTP check outcomes: the fingerprint matched, the page is something else, or no usable answer. */
export const HTTP_CHECK_OUTCOMES = Object.freeze(['claimable', 'in-use', 'no-answer']);

/** A registration that ends within this many days is reported as expiring. */
export const EXPIRING_DAYS = 30;

/** The Globalping consent purpose of the HTTP check (ui/globalping-gate.js). */
export const TAKEOVER_PURPOSE = 'takeover-http';

/** At most this many hosts are checked over HTTP in one batch (one probe each). */
export const HTTP_CHECK_MAX = 10;

/**
 * Suffixes nobody can register — the special-use names (RFC 2606, 6761, 6762, 7686, 9476), the
 * private-use `.internal` and `.home.arpa` (so all of `.arpa`), and the private TLDs ICANN will not
 * delegate (`.corp`, `.home`, `.lan` …): a name under one is never sent anywhere (no RDAP, no DNS
 * question of its own) and never called registrable.
 */
export const UNREGISTRABLE_TLDS = Object.freeze([
  'test', 'example', 'invalid', 'localhost', 'local', 'onion', 'alt', 'internal', 'arpa', 'corp', 'home', 'lan', 'intranet', 'private'
]);

const DAY = 86400000;
const MAX_CHAIN = 16;

/**
 * @typedef {object} TakeoverService
 * @property {string} id
 * @property {string} name the product name (never translated)
 * @property {'vulnerable'|'edge'|'safe'} status
 * @property {'nxdomain'|'http'} signal
 * @property {string[]} patterns CNAME targets: a name equal to or below a pattern matches; `*`
 *   inside a label stands for any run of letters, digits and hyphens in that label
 * @property {string[]} fingerprints texts of the "no such site" page (any one, case-insensitive)
 * @property {string} ref the page the entry rests on
 */

/** One catalogue entry (frozen). */
function svc(id, name, status, signal, patterns, fingerprints, ref) {
  return Object.freeze({ id, name, status, signal, patterns: Object.freeze(patterns), fingerprints: Object.freeze(fingerprints), ref });
}

const ISSUE = 'https://github.com/EdOverflow/can-i-take-over-xyz/issues/';
const AZURE_REF = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover';

/**
 * The services whose CNAME targets can dangle, most specific patterns first (the first match
 * wins). Statuses and signals as of 2026-10-08.
 * @type {ReadonlyArray<TakeoverService>}
 */
export const TAKEOVER_SERVICES = Object.freeze([
  // Bucket names are global: a CNAME to a deleted bucket's endpoint still resolves (the S3 front
  // ends answer every name) and says NoSuchBucket until anyone creates a bucket of that name.
  svc('aws-s3', 'Amazon S3', 'vulnerable', 'http',
    ['s3.amazonaws.com', 's3.*.amazonaws.com', 's3-*.amazonaws.com', 's3-website.*.amazonaws.com', 's3.dualstack.*.amazonaws.com'],
    ['NoSuchBucket', 'The specified bucket does not exist'], `${ISSUE}36`),
  // An environment's CNAME prefix is free again once the environment is terminated: the name
  // stops resolving, and anyone can create an environment with it in the same region.
  svc('aws-elastic-beanstalk', 'AWS Elastic Beanstalk', 'vulnerable', 'nxdomain', ['elasticbeanstalk.com'], [], `${ISSUE}194`),
  // Load balancer names carry a random part AWS chooses: a deleted one cannot be recreated.
  svc('aws-elb', 'AWS Elastic Load Balancing', 'safe', 'nxdomain', ['elb.amazonaws.com'], [], `${ISSUE}137`),
  // Distribution names are random, and an alternate domain needs a certificate for it.
  svc('aws-cloudfront', 'Amazon CloudFront', 'safe', 'nxdomain', ['cloudfront.net'], [], `${ISSUE}29`),
  // Azure: Microsoft's own guidance lists these resource types. Their DNS names are chosen by the
  // customer and global: when the resource is deleted the name stops resolving, and anyone can
  // create a resource of the same name in their own subscription.
  svc('azure-app-service', 'Azure App Service', 'vulnerable', 'nxdomain', ['azurewebsites.net'], [], AZURE_REF),
  svc('azure-cloud-service', 'Azure Cloud Services / public IP', 'vulnerable', 'nxdomain', ['cloudapp.net', 'cloudapp.azure.com'], [], AZURE_REF),
  svc('azure-traffic-manager', 'Azure Traffic Manager', 'vulnerable', 'nxdomain', ['trafficmanager.net'], [], AZURE_REF),
  svc('azure-storage', 'Azure Storage', 'vulnerable', 'nxdomain', ['blob.core.windows.net', 'web.core.windows.net'], [], AZURE_REF),
  svc('azure-cdn', 'Azure CDN', 'vulnerable', 'nxdomain', ['azureedge.net'], [], AZURE_REF),
  svc('azure-front-door', 'Azure Front Door', 'vulnerable', 'nxdomain', ['azurefd.net'], [], AZURE_REF),
  svc('azure-api-management', 'Azure API Management', 'vulnerable', 'nxdomain', ['azure-api.net'], [], AZURE_REF),
  svc('azure-container-instances', 'Azure Container Instances', 'vulnerable', 'nxdomain', ['azurecontainer.io'], [], AZURE_REF),
  // A custom domain is served by whichever repository names it; GitHub's domain verification
  // stops others from claiming it, so it depends on whether the owner verified the domain.
  svc('github-pages', 'GitHub Pages', 'edge', 'http', ['github.io'],
    ['There isn\'t a GitHub Pages site here', 'There isn&#39;t a GitHub Pages site here'],
    'https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages'),
  // Custom domains now point at per-domain DNS targets Heroku generates; older app-name targets
  // can still say "no such app".
  svc('heroku', 'Heroku', 'edge', 'http', ['herokuapp.com', 'herokudns.com', 'herokussl.com'], ['no-such-app', 'No such app'], `${ISSUE}38`),
  svc('bitbucket', 'Bitbucket Cloud', 'vulnerable', 'http', ['bitbucket.io'], ['Repository not found'], `${ISSUE}97`),
  svc('ghost', 'Ghost(Pro)', 'vulnerable', 'http', ['ghost.io'], ['Failed to resolve DNS path for this host', 'Site unavailable'], `${ISSUE}89`),
  svc('pantheon', 'Pantheon', 'vulnerable', 'http', ['pantheonsite.io'], ['404 error unknown site!'], `${ISSUE}24`),
  svc('readme', 'ReadMe', 'vulnerable', 'http', ['readme.io', 'readmessl.com'],
    ['Project doesnt exist', 'The creators of this project are still working on making everything perfect'], `${ISSUE}41`),
  svc('readthedocs', 'Read the Docs', 'vulnerable', 'http', ['readthedocs.io'],
    ['The link you have followed or the URL that you entered does not exist'], `${ISSUE}160`),
  svc('surge', 'Surge', 'vulnerable', 'http', ['surge.sh'], ['project not found'], `${ISSUE}198`),
  svc('wordpress-com', 'WordPress.com', 'vulnerable', 'http', ['wordpress.com'], ['Do you want to register'], 'https://github.com/EdOverflow/can-i-take-over-xyz/pull/176'),
  svc('youtrack', 'JetBrains YouTrack', 'vulnerable', 'http', ['youtrack.cloud', 'myjetbrains.com'], ['is not a registered InCloud YouTrack'],
    'https://github.com/EdOverflow/can-i-take-over-xyz/pull/107'),
  svc('uberflip', 'Uberflip', 'vulnerable', 'http', ['read.uberflip.com'], ['The URL you\'ve accessed does not provide a hub'], `${ISSUE}150`),
  svc('strikingly', 'Strikingly', 'vulnerable', 'http', ['s.strikinglydns.com'], ['PAGE NOT FOUND'], `${ISSUE}58`),
  svc('uptimerobot', 'UptimeRobot status page', 'vulnerable', 'http', ['stats.uptimerobot.com'], ['page not found'], `${ISSUE}45`),
  svc('pingdom', 'Pingdom status page', 'vulnerable', 'http', ['stats.pingdom.com'], ['Sorry, couldn\'t find the status page'], `${ISSUE}144`),
  svc('campaign-monitor', 'Campaign Monitor', 'vulnerable', 'http', ['createsend.com'], ['Trying to access your account?'], `${ISSUE}275`),
  svc('agile-crm', 'Agile CRM', 'vulnerable', 'http', ['agilecrm.com'], ['Sorry, this page is no longer available'], `${ISSUE}145`),
  // A hosted forum's name is released with the site and stops resolving.
  svc('discourse', 'Discourse (hosted)', 'vulnerable', 'nxdomain', ['trydiscourse.com'], [], `${ISSUE}49`),
  svc('gemfury', 'Gemfury', 'vulnerable', 'http', ['furyns.com'], ['404: This page could not be found'], `${ISSUE}154`),
  svc('anima', 'Anima', 'vulnerable', 'http', ['animaapp.io'], ['The page you were looking for does not exist'], `${ISSUE}126`),
  svc('canny', 'Canny', 'vulnerable', 'http', ['cname.canny.io'], ['There is no such company'], `${ISSUE}114`),
  svc('cargo', 'Cargo', 'vulnerable', 'http', ['cargocollective.com'], ['404 Not Found'], `${ISSUE}152`),
  // Edge cases: the platform verifies the domain or a claim needs more than a free account.
  svc('shopify', 'Shopify', 'edge', 'http', ['myshopify.com'], ['Sorry, this shop is currently unavailable'], `${ISSUE}32`),
  svc('tumblr', 'Tumblr', 'edge', 'http', ['domains.tumblr.com'], ['Whatever you were looking for doesn\'t currently exist at this address'], `${ISSUE}240`),
  svc('webflow', 'Webflow', 'edge', 'http', ['proxy-ssl.webflow.com', 'proxy.webflow.com'], ['The page you are looking for doesn\'t exist or has been moved'], `${ISSUE}44`),
  svc('netlify', 'Netlify', 'edge', 'http', ['netlify.app', 'netlify.com', 'netlifyglobalcdn.com'], ['Not Found - Request ID:'], `${ISSUE}40`),
  svc('vercel', 'Vercel', 'edge', 'http', ['vercel-dns.com', 'vercel.app', 'now.sh'], ['DEPLOYMENT_NOT_FOUND'], `${ISSUE}183`),
  svc('wix', 'Wix', 'edge', 'http', ['wixdns.net'], ['Isn\'t Connected To A Website Yet'], `${ISSUE}231`),
  svc('intercom', 'Intercom Help Center', 'edge', 'http', ['custom.intercom.help'], ['Uh oh. That page doesn\'t exist'], `${ISSUE}69`),
  svc('tilda', 'Tilda', 'edge', 'http', ['tilda.ws'], ['Please renew your subscription'], `${ISSUE}155`),
  // Not claimable: the service verifies the domain (or its names are random); a dangling record
  // there is only clutter to remove.
  svc('fastly', 'Fastly', 'safe', 'http', ['fastly.net', 'fastlylb.net'], [], `${ISSUE}22`),
  svc('akamai', 'Akamai', 'safe', 'nxdomain', ['edgekey.net', 'edgesuite.net', 'akamaiedge.net', 'akamaized.net'], [], `${ISSUE}13`),
  svc('google-cloud-storage', 'Google Cloud Storage', 'safe', 'http', ['c.storage.googleapis.com'], [], 'https://cloud.google.com/storage/docs/domain-name-verification'),
  svc('google-sites', 'Google Sites / App Engine', 'safe', 'http', ['ghs.googlehosted.com'], [], `${ISSUE}277`),
  svc('firebase', 'Firebase Hosting', 'safe', 'http', ['firebaseapp.com', 'web.app'], [], `${ISSUE}128`),
  svc('gitlab-pages', 'GitLab Pages', 'safe', 'http', ['gitlab.io'], [], 'https://hackerone.com/reports/312118'),
  svc('zendesk', 'Zendesk', 'safe', 'http', ['zendesk.com'], [], `${ISSUE}23`),
  svc('freshdesk', 'Freshdesk', 'safe', 'http', ['freshdesk.com'], [], `${ISSUE}214`),
  svc('hubspot', 'HubSpot', 'safe', 'http', ['hubspot.net', 'hs-sites.com'], [], `${ISSUE}59`),
  svc('kinsta', 'Kinsta', 'safe', 'http', ['kinsta.cloud'], [], `${ISSUE}48`),
  svc('unbounce', 'Unbounce', 'safe', 'http', ['unbouncepages.com'], [], `${ISSUE}11`),
  svc('uservoice', 'UserVoice', 'safe', 'http', ['uservoice.com'], [], `${ISSUE}163`)
]);

/* ------------------------------------------------------------------------ */
/* Matching                                                                 */
/* ------------------------------------------------------------------------ */

const labelRes = new Map();

/** Does one pattern label match one name label (`*` = letters, digits, hyphens)? */
function labelMatches(pat, label) {
  if (!pat.includes('*')) return pat === label;
  let re = labelRes.get(pat);
  if (!re) {
    re = new RegExp(`^${pat.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\-]/g, '\\$&')).join('[a-z0-9-]*')}$`);
    labelRes.set(pat, re);
  }
  return re.test(label);
}

/** A DNS name in canonical form (lower case, no trailing dot), or ''. */
function canon(name) {
  return typeof name === 'string' ? name.trim().toLowerCase().replace(/\.$/, '') : '';
}

/**
 * Does `name` equal `pattern` or sit below it (label by label, `*` within a label)?
 * @param {string} pattern
 * @param {string} name
 * @returns {boolean}
 */
export function matchesPattern(pattern, name) {
  const p = canon(pattern).split('.');
  const n = canon(name).split('.');
  if (!p[0] || !n[0] || n.length < p.length) return false;
  const off = n.length - p.length;
  for (let i = 0; i < p.length; i += 1) if (!labelMatches(p[i], n[off + i])) return false;
  return true;
}

/**
 * The catalogue service a CNAME target belongs to.
 * @param {string} target
 * @param {ReadonlyArray<TakeoverService>} [services]
 * @returns {TakeoverService|null}
 */
export function matchService(target, services = TAKEOVER_SERVICES) {
  for (const s of services) if (s.patterns.some((p) => matchesPattern(p, target))) return s;
  return null;
}

/**
 * The first hop of a CNAME chain that belongs to a catalogue service: the resource the record
 * was made for (later hops are the provider's own plumbing).
 * @param {string[]} chain the CNAME targets in order
 * @param {ReadonlyArray<TakeoverService>} [services]
 * @returns {{ service: TakeoverService, hop: string }|null}
 */
export function chainService(chain, services = TAKEOVER_SERVICES) {
  for (const hop of Array.isArray(chain) ? chain : []) {
    const service = matchService(hop, services);
    if (service) return { service, hop: canon(hop) };
  }
  return null;
}

/**
 * Does a page body carry one of the service's "no such site" texts? (case-insensitive)
 * @param {TakeoverService|null} service
 * @param {string|null} body
 * @returns {boolean}
 */
export function fingerprintMatches(service, body) {
  if (!service || typeof body !== 'string' || !body) return false;
  const text = body.toLowerCase();
  return service.fingerprints.some((f) => text.includes(f.toLowerCase()));
}

/**
 * The domain a registry holds for a name (ICANN suffixes only: `user.github.io` → `github.io`,
 * `www.example.com.tr` → `example.com.tr`); null for a public suffix or a non-name.
 * @param {string} name
 * @returns {string|null}
 */
export function registryDomainOf(name) {
  const h = normalizeHostname(canon(name).replace(/^\*\./, ''));
  if (!h || isPublicSuffix(h, { includePrivate: false })) return null;
  const labels = h.split('.');
  for (let i = 0; i < labels.length - 1; i += 1) {
    if (isPublicSuffix(labels.slice(i + 1).join('.'), { includePrivate: false })) return labels.slice(i).join('.');
  }
  return null;
}

/** The registry domains of the catalogue's patterns: well-known providers, never looked up. */
const PROVIDER_DOMAINS = new Set(TAKEOVER_SERVICES.flatMap((s) => s.patterns.map((p) => registryDomainOf(p.replace(/\*/g, 'x'))).filter(Boolean)));

/**
 * The CNAME chain a response gives for `name`, followed from `name` in order (loops cut).
 * @param {{ answers?: object[] }|null} response
 * @param {string} name
 * @returns {string[]}
 */
export function cnameChain(response, name) {
  const answers = response && Array.isArray(response.answers) ? response.answers : [];
  const chain = [];
  let current = canon(name);
  const visited = new Set([current]);
  for (let i = 0; i < MAX_CHAIN; i += 1) {
    const rr = answers.find((a) => a && a.type === 'CNAME' && canon(a.name) === current && typeof a.data === 'string');
    if (!rr) break;
    current = canon(rr.data);
    if (!current || visited.has(current)) break;
    visited.add(current);
    chain.push(current);
  }
  return chain;
}

/** A domain named in a record, or null (lower case, no trailing dot, a valid host name). */
const hostOf = (name) => normalizeHostname(canon(name));

/**
 * What an SPF record names (RFC 7208): the include: and redirect= domains (`includes`), the a:,
 * mx:, exists: and ptr: domains with their term (`hosts`: `{ mechanism, target, term:
 * 'a:mail.example.net' }`, a CIDR length dropped; a bare `a`, `mx` or `ptr` names the domain
 * itself), each once, and how many of those terms build their name from a macro (`%{…}`: known
 * only per message, so never checked; `macros`). `exp=` is not a reference.
 * @param {string} txt
 * @returns {{ includes: string[], hosts: Array<{ mechanism: string, target: string, term: string }>, macros: number }}
 */
export function spfReferences(txt) {
  const out = { includes: [], hosts: [], macros: 0 };
  if (typeof txt !== 'string' || !/^v=spf1(\s|$)/i.test(txt.trim())) return out;
  for (const raw of txt.trim().split(/\s+/).slice(1)) {
    // A domain-spec built from a macro (its delimiters may hold a `/` too): counted, never parsed.
    if (raw.includes('%') && /^(?:[+\-~?]?(?:include|a|mx|exists|ptr):|redirect=)/i.test(raw)) {
      out.macros += 1;
      continue;
    }
    const redirect = /^redirect=(.*)$/i.exec(raw);
    const m = redirect ? null : /^[+\-~?]?(include|a|mx|exists|ptr)(?::([^/]*))?((?:\/\d{1,3})?(?:\/\/\d{1,3})?)$/i.exec(raw);
    if (!redirect && !m) continue;
    const mechanism = redirect ? 'redirect' : m[1].toLowerCase();
    const spec = redirect ? redirect[1] : m[2];
    // a, mx and ptr without a domain name the domain itself; include and exists need one, and take no CIDR length.
    if (spec === undefined || (m && m[3] && (mechanism === 'include' || mechanism === 'exists' || mechanism === 'ptr'))) continue;
    const target = hostOf(spec);
    if (!target) continue;
    if (mechanism === 'include' || mechanism === 'redirect') {
      if (!out.includes.includes(target)) out.includes.push(target);
    } else if (!out.hosts.some((x) => x.target === target)) {
      out.hosts.push({ mechanism, target, term: `${mechanism}:${target}` });
    }
  }
  return out;
}

/**
 * The include: and redirect= domains of an SPF record (macros left out).
 * @param {string} txt
 * @returns {string[]}
 */
export function spfTargets(txt) {
  return spfReferences(txt).includes;
}

/**
 * The hosts of a DMARC record's report addresses (RFC 7489 §6.2): the `mailto:` URIs of rua= and
 * ruf= (a size limit `!10m` and a query dropped), each host once with the tags that name it. A
 * repeated tag counts once, the first (as lib/health.js parseDmarc reads it).
 * @param {string} txt
 * @returns {Array<{ target: string, tags: string[] }>}
 */
export function dmarcTargets(txt) {
  const out = [];
  if (typeof txt !== 'string' || !/^[vV]\s*=\s*DMARC1\s*(?:;|$)/.test(txt.trim())) return out;
  const tagsSeen = new Set();
  for (const part of txt.split(';')) {
    const m = /^\s*(rua|ruf)\s*=\s*(.*)$/i.exec(part);
    if (!m) continue;
    const tag = m[1].toLowerCase();
    if (tagsSeen.has(tag)) continue;
    tagsSeen.add(tag);
    for (const uri of m[2].split(',')) {
      const mail = /^\s*mailto:([^!?\s]+)/i.exec(uri);
      if (!mail) continue;
      let address = mail[1];
      try {
        address = decodeURIComponent(address);
      } catch {
        // a stray % stays as it was
      }
      const at = address.lastIndexOf('@');
      const target = at > 0 ? hostOf(address.slice(at + 1)) : null;
      if (!target) continue;
      const hit = out.find((x) => x.target === target);
      if (!hit) out.push({ target, tags: [tag] });
      else if (!hit.tags.includes(tag)) hit.tags.push(tag);
    }
  }
  return out;
}

/**
 * The hosts of the CAA iodef addresses (RFC 8659 §4.4): a `mailto:` address's mail domain, an
 * `https:` / `http:` URL's host; each once.
 * @param {Array<{ tag?: string, value?: string }>} records CAA record data
 * @returns {string[]}
 */
export function caaIodefTargets(records) {
  const out = [];
  for (const r of Array.isArray(records) ? records : []) {
    if (!r || String(r.tag || '').toLowerCase() !== 'iodef' || typeof r.value !== 'string') continue;
    const value = r.value.trim();
    const mail = /^mailto:([^?\s]+)/i.exec(value);
    let target = null;
    if (mail) {
      const at = mail[1].lastIndexOf('@');
      target = at > 0 ? hostOf(mail[1].slice(at + 1)) : null;
    } else if (/^https?:\/\/[^\s]/i.test(value)) {
      target = normalizeHostname(value);
    }
    if (target && !out.includes(target)) out.push(target);
  }
  return out;
}

const SELECTOR_RE = /^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$/;

/**
 * Is this a DKIM selector a name can be built from (`<selector>._domainkey.<domain>`)? Letters,
 * digits, `_` and `-`, dot-separated labels (as Domain Health's extra selectors).
 * @param {string} selector
 * @returns {boolean}
 */
export function isDkimSelector(selector) {
  const s = String(selector ?? '').toLowerCase();
  return s.length <= 63 && SELECTOR_RE.test(s) && !s.includes('..');
}

/**
 * The selectors the audit follows: {@link TAKEOVER_DKIM_SELECTORS}, then the extra ones (lower
 * case, invalid ones and repeats left out).
 * @param {string[]} [extra]
 * @returns {string[]}
 */
export function dkimSelectorList(extra = []) {
  const out = [...TAKEOVER_DKIM_SELECTORS];
  for (const raw of Array.isArray(extra) ? extra : []) {
    const s = String(raw ?? '').trim().toLowerCase();
    if (isDkimSelector(s) && !out.includes(s)) out.push(s);
  }
  return out;
}

/** A TXT record's text (its strings joined). */
const txtText = (data) => (Array.isArray(data) ? data.join('') : typeof data === 'string' ? data : '');

/* ------------------------------------------------------------------------ */
/* Registration                                                             */
/* ------------------------------------------------------------------------ */

/**
 * The registration verdict of one registrable domain from its RDAP lookup and, when RDAP did
 * not find it (or the TLD has none), the DNS answer for its NS records.
 * @param {object|null} rdap lib/rdap.js rdapDomain() result
 * @param {object|null} ns DnsResponse of `<domain> NS` (asked only after a 404 / no RDAP)
 * @param {{ now?: number, expiringDays?: number }} [opts]
 * @returns {{ verdict: string, expires: Date|null }}
 */
export function registrationVerdict(rdap, ns, { now = Date.now(), expiringDays = EXPIRING_DAYS } = {}) {
  const r = rdap && typeof rdap === 'object' ? rdap : null;
  const expires = r && r.expires instanceof Date && !Number.isNaN(r.expires.getTime()) ? r.expires : null;
  const nx = ns && ns.ok && ns.rcode === 'NXDOMAIN';
  const inDns = ns && ns.ok && ns.rcode === 'NOERROR';
  if (!r) return { verdict: 'failed', expires: null };
  if (r.ok) {
    const status = (Array.isArray(r.status) ? r.status : []).map((s) => String(s).toLowerCase().replace(/[\s_-]/g, ''));
    if (status.some((s) => s === 'pendingdelete' || s === 'redemptionperiod')) return { verdict: 'pending-delete', expires };
    if (expires && expires.getTime() < now) return { verdict: 'expired', expires };
    if (expires && expires.getTime() - now <= expiringDays * DAY) return { verdict: 'expiring', expires };
    return { verdict: 'registered', expires };
  }
  if (r.notFound) return { verdict: nx ? 'unregistered' : inDns ? 'rdap-404-dns' : 'failed', expires: null };
  if (r.unsupportedTld) return { verdict: nx ? 'unregistered-dns' : inDns ? 'no-rdap' : 'failed', expires: null };
  if (r.errorKind === 'invalid') return { verdict: 'registered', expires: null };
  return { verdict: 'failed', expires: null };
}

/* ------------------------------------------------------------------------ */
/* Severity                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The severity of one reason on one kind of reference.
 * @param {string} reason a {@link TAKEOVER_REASONS} code
 * @param {string} kind a {@link TAKEOVER_REF_KINDS} code
 * @param {TakeoverService|null} service the CNAME chain's service, if any
 * @returns {string} a {@link TAKEOVER_SEVERITIES} code
 */
export function reasonSeverity(reason, kind, service = null) {
  switch (reason) {
    // Whoever registers it serves the host (a CNAME, mta-sts), answers for the zone (NS) or passes
    // DNS-01 for the domain and its wildcard (acme): critical. Mail, reports, keys, SRV and HTTPS: high.
    case 'unregistered': return CRITICAL_KINDS.has(kind) ? 'critical' : 'high';
    case 'unregistered-dns':
    case 'pending-delete':
    case 'expired': return 'high';
    case 'expiring': return 'medium';
    case 'nxdomain':
      if (!HOST_KINDS.has(kind)) return 'low';
      if (!service) return 'medium';
      return service.status === 'vulnerable' ? 'high' : service.status === 'edge' ? 'medium' : 'low';
    case 'fingerprint': return service && service.status === 'vulnerable' ? 'high' : 'medium';
    default: return 'info';
  }
}

const rank = (severity) => {
  const i = TAKEOVER_SEVERITIES.indexOf(severity);
  return i === -1 ? TAKEOVER_SEVERITIES.length : i;
};

/**
 * The most severe of several severities.
 * @param {string[]} list
 * @returns {string|null}
 */
export function worstSeverity(list) {
  let best = null;
  for (const s of list) if (best === null || rank(s) < rank(best)) best = s;
  return best;
}

/* ------------------------------------------------------------------------ */
/* The audit                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} TakeoverReason
 * @property {string} code a {@link TAKEOVER_REASONS} code
 * @property {string} severity
 * @property {string} [domain] the registrable domain (registration reasons)
 * @property {string} [name] the name that does not exist (nxdomain)
 * @property {Date|null} [expires]
 */

/**
 * @typedef {object} TakeoverFinding
 * @property {string} id kind + host + target, stable across runs
 * @property {string} severity the worst of its reasons
 * @property {string} kind a {@link TAKEOVER_REF_KINDS} code
 * @property {string} host the scanned host (cname), else the name that holds the record: the scanned domain (ns, mx,
 *   spf, spf-host, caa, https), `_dmarc.<domain>`, `<selector>._domainkey.<domain>`, `mta-sts.<domain>`, the SRV name
 *   (`_sip._tls.<domain>`) or `_acme-challenge.<domain>`
 * @property {string} target the CNAME chain's last name, else the name the record names
 * @property {string[]} chain the CNAME chain (cname, dkim, mta-sts, acme, a `_dmarc` delegation), else [target]
 * @property {string|null} term what in the record names it: the SPF term (`a:mail.example.net`), the DMARC tags
 *   (`rua`, `rua, ruf`); null for the other kinds
 * @property {{ id: string, name: string, status: string, ref: string }|null} service
 * @property {TakeoverReason[]} reasons most severe first
 * @property {string} fix the code of the fix: the first reason's code
 */

/**
 * @typedef {object} TakeoverFailure
 * @property {'doh'|'rdap'} source
 * @property {string} name what was asked: a scanned host, `<name> <TYPE>` (a domain's record, `<domain> NS` after an
 *   RDAP 404), a target (whether it exists), a registrable domain (RDAP)
 * @property {object} response the failed DnsResponse or rdapDomain() result (lib/sourcestatus.js)
 */

/**
 * The lookups a finding rests on, named as {@link auditTakeover} names its failures: the query its
 * reference came from (`<owner> <TYPE>` by {@link REFERENCE_QUERIES}; a scanned host's chain: the
 * host), its target (whether it exists), and every registrable domain its chain names (RDAP, and
 * `<domain> NS` after a 404). While one of them failed, a finding is not known to be gone: the
 * headless runner carries it (tools/ds/carry.mjs carryRisks).
 * @param {{ kind: string, host: string, target?: string, chain?: string[] }} finding
 * @returns {string[]}
 */
export function findingLookups({ kind, host, target, chain }) {
  const out = new Set([kind === 'cname' ? canon(host) : `${canon(host)} ${REFERENCE_QUERIES[kind] || 'A'}`]);
  if (target) out.add(canon(target));
  for (const name of Array.isArray(chain) ? chain : []) {
    const d = registryDomainOf(name);
    if (d) {
      out.add(d);
      out.add(`${d} NS`);
    }
  }
  return [...out];
}

/**
 * Audit the scanned hosts and domains. Only an abort rejects.
 *
 * Steps: each domain's records — NS, MX, TXT (SPF), `_dmarc` TXT, CAA, HTTPS, the
 * {@link TAKEOVER_SRV_NAMES} SRV records, and the CNAME chains of `mta-sts.<domain>` (A),
 * `_acme-challenge.<domain>` (TXT) and every DKIM selector (TXT; {@link TAKEOVER_DKIM_SELECTORS}
 * and `extraDkimSelectors`), the chains asked without the cache; every host asked again (A, no
 * cache: the chain and whether its end exists today); every single target outside the domains
 * (NS, MX, SPF a / mx / exists / ptr, DMARC and iodef hosts, SRV and HTTPS targets) asked for its A
 * record (NXDOMAIN: it does not exist); then the registration of every registrable domain those
 * references name, outside the domains (`domains` and `ownDomains`) and the catalogue's providers,
 * through `rdap` (one lookup per domain; `known` carries earlier verdicts, and only failed ones
 * are asked again).
 *
 * @param {{ hosts?: Array<object|string>, domains?: string[] }} input scan HostRecords (name,
 *   resolution.cnames, wildcardSuspect: the ones with a CNAME chain are asked again) or host names
 *   (each asked, whatever it had: a list of names to watch), and the domains
 * @param {{ dns: { query: Function }, rdap: (domain: string, opts: object) => Promise<object>, signal?: AbortSignal,
 *   now?: () => number, known?: Map<string, object>|null, onProgress?: (done: number, total: number) => void,
 *   concurrency?: number, rdapConcurrency?: number, expiringDays?: number, skipTlds?: ReadonlyArray<string>,
 *   ownDomains?: string[], extraDkimSelectors?: string[] }} opts
 *   `skipTlds`: the suffixes never looked up ({@link UNREGISTRABLE_TLDS}; tests that stand in `.test` for public domains clear it);
 *   `ownDomains`: more domains that are the caller's own (never looked up, their names never asked for their
 *   existence: the headless runner audits a list one domain at a time); `extraDkimSelectors`: DKIM selectors
 *   followed besides the common ones
 * @returns {Promise<{ at: Date, domains: string[], references: number, findings: TakeoverFinding[],
 *   failures: TakeoverFailure[], registrations: Map<string, object>, checked: number, hosts: number, spfMacros: number }>}
 *   `registrations`: domain → { verdict, expires, rdap, ns } (pass back as `known` to retry);
 *   `checked`: registrable domains with a verdict; `hosts`: hosts whose chain was asked;
 *   `spfMacros`: SPF terms that build their domain from a macro (not checked)
 */
export async function auditTakeover({ hosts = [], domains = [] } = {}, {
  dns, rdap, signal, now = Date.now, known = null, onProgress = null, concurrency = 6, rdapConcurrency = 4, expiringDays = EXPIRING_DAYS,
  skipTlds = UNREGISTRABLE_TLDS, ownDomains = [], extraDkimSelectors = []
} = {}) {
  throwIfAborted(signal);
  const unregistrable = (name) => skipTlds.some((s) => isSubdomainOf(name, s));
  const domainsOf = (list) => (Array.isArray(list) ? list : []).map((d) => normalizeHostname(canon(d))).filter(Boolean);
  const apexes = [...new Set(domainsOf(domains))];
  const own = [...new Set([...apexes, ...domainsOf(ownDomains)])];
  const selectors = dkimSelectorList(extraDkimSelectors);
  const failures = [];
  const limiter = createLimiter(concurrency);
  const ask = (name, type, opts = {}) => limiter.run(() => dns.query(name, type, { signal, ...opts }), { signal });
  let done = 0;
  let total = 0;
  const tick = (n = 1) => {
    done += n;
    if (onProgress) onProgress(Math.min(done, total), total);
  };
  const failed = (source, name, response) => failures.push({ source, name, response });

  /** @type {Array<{ kind: string, host: string, chain: string[], target: string, dangling: boolean, check: boolean, term: string|null }>} */
  const refs = [];
  // A target the record names: asked for its existence (EXISTENCE_KINDS) unless it is the domain's own.
  const single = (kind, host, target, term = null) => refs.push({ kind, host, chain: [target], target, dangling: false, check: EXISTENCE_KINDS.has(kind), term });
  // A CNAME chain from one of the domain's names: the chain query says whether its end exists.
  const chained = (kind, host, response) => {
    if (!response.ok) return;
    const chain = cnameChain(response, host);
    if (chain.length) refs.push({ kind, host, chain, target: chain[chain.length - 1], dangling: response.rcode === 'NXDOMAIN', check: false, term: null });
  };

  const cnameHosts = [];
  const hostNames = new Set();
  for (const x of Array.isArray(hosts) ? hosts : []) {
    const entry = typeof x === 'string' ? { name: x, listed: true } : x;
    if (!entry || typeof entry.name !== 'string' || entry.wildcardSuspect) continue;
    const name = canon(entry.name);
    const cnames = entry.resolution && Array.isArray(entry.resolution.cnames) ? entry.resolution.cnames : [];
    if (!name || hostNames.has(name) || !(entry.listed || cnames.length)) continue;
    hostNames.add(name);
    cnameHosts.push({ name, cnames });
  }
  // NS, MX, TXT, _dmarc, CAA, HTTPS, mta-sts, _acme-challenge, the SRV names and the DKIM selectors.
  const perDomain = 8 + TAKEOVER_SRV_NAMES.length + selectors.length;
  total = apexes.length * perDomain + cnameHosts.length;
  if (onProgress) onProgress(0, total);
  let spfMacros = 0;

  // 1. The domains' own records and the references they make.
  const record = (name, type, opts) => ask(name, type, opts).then((r) => {
    tick();
    if (!r.ok) failed('doh', `${name} ${type}`, r);
    return r;
  });
  await Promise.all(apexes.map(async (apex) => {
    const dmarcName = `_dmarc.${apex}`;
    const [ns, mx, txt, dmarc, caa, https, mtaSts, acme, ...rest] = await Promise.all([
      record(apex, 'NS'), record(apex, 'MX'), record(apex, 'TXT'), record(dmarcName, 'TXT'), record(apex, 'CAA'), record(apex, 'HTTPS'),
      record(`mta-sts.${apex}`, 'A', { noCache: true }), record(`_acme-challenge.${apex}`, 'TXT', { noCache: true }),
      ...TAKEOVER_SRV_NAMES.map((s) => record(`${s}.${apex}`, 'SRV')),
      ...selectors.map((s) => record(`${s}._domainkey.${apex}`, 'TXT', { noCache: true }))
    ]);
    const answers = (r, type, owner = apex) => (r.ok && Array.isArray(r.answers) ? r.answers.filter((a) => a && a.type === type && canon(a.name) === owner) : []);
    // The records at the end of the name's CNAME chain (a hosted DMARC record, a delegated SRV name).
    const atEnd = (r, owner, type) => {
      const chain = r.ok ? cnameChain(r, owner) : [];
      return answers(r, type, chain.length ? chain[chain.length - 1] : owner);
    };
    for (const a of answers(ns, 'NS')) if (typeof a.data === 'string' && canon(a.data)) single('ns', apex, canon(a.data));
    for (const a of answers(mx, 'MX')) {
      const x = a.data && typeof a.data.exchange === 'string' ? canon(a.data.exchange) : '';
      if (x && x !== '.') single('mx', apex, x);
    }
    for (const a of answers(txt, 'TXT')) {
      const spf = spfReferences(txtText(a.data));
      spfMacros += spf.macros;
      for (const target of spf.includes) refs.push({ kind: 'spf', host: apex, chain: [target], target, dangling: false, check: false, term: null });
      for (const x of spf.hosts) single('spf-host', apex, x.target, x.term);
    }
    chained('dmarc', dmarcName, dmarc);
    for (const a of atEnd(dmarc, dmarcName, 'TXT')) for (const x of dmarcTargets(txtText(a.data))) single('dmarc', dmarcName, x.target, x.tags.join(', '));
    for (const target of caaIodefTargets(answers(caa, 'CAA').map((a) => a.data))) single('caa', apex, target);
    for (const a of atEnd(https, apex, 'HTTPS')) {
      const target = a.data && typeof a.data.target === 'string' ? canon(a.data.target) : '';
      if (target) single('https', apex, target);
    }
    TAKEOVER_SRV_NAMES.forEach((s, i) => {
      const owner = `${s}.${apex}`;
      for (const a of atEnd(rest[i], owner, 'SRV')) {
        const target = a.data && typeof a.data.target === 'string' ? canon(a.data.target) : '';
        if (target) single('srv', owner, target);
      }
    });
    chained('mta-sts', `mta-sts.${apex}`, mtaSts);
    chained('acme', `_acme-challenge.${apex}`, acme);
    selectors.forEach((s, i) => chained('dkim', `${s}._domainkey.${apex}`, rest[TAKEOVER_SRV_NAMES.length + i]));
  }));

  // 2. Every host's chain again, and whether each single target outside the domains exists (each name once).
  const outside = (name) => !own.some((a) => isSubdomainOf(name, a));
  const existence = new Map();
  for (const ref of refs) {
    if (!ref.check || !outside(ref.target) || unregistrable(ref.target)) continue;
    if (!existence.has(ref.target)) existence.set(ref.target, []);
    existence.get(ref.target).push(ref);
  }
  total += existence.size;
  await Promise.all([
    ...cnameHosts.map(async (x) => {
      const r = await ask(x.name, 'A', { noCache: true });
      tick();
      let chain = x.cnames.map(canon).filter(Boolean);
      let dangling = false;
      if (!r.ok) failed('doh', x.name, r);
      else {
        chain = cnameChain(r, x.name);
        dangling = chain.length > 0 && r.rcode === 'NXDOMAIN';
      }
      if (chain.length) refs.push({ kind: 'cname', host: x.name, chain, target: chain[chain.length - 1], dangling, check: false, term: null });
    }),
    ...[...existence].map(async ([target, list]) => {
      const r = await ask(target, 'A');
      tick();
      if (!r.ok) failed('doh', target, r);
      else for (const ref of list) ref.dangling = r.rcode === 'NXDOMAIN';
    })
  ]);

  // 3. The registration of every registrable domain the references name.
  const registrations = new Map();
  const wanted = new Set();
  for (const ref of refs) {
    for (const name of ref.chain) {
      const d = registryDomainOf(name);
      if (d && outside(d) && !PROVIDER_DOMAINS.has(d) && !unregistrable(d)) wanted.add(d);
    }
  }
  const rdapLimiter = createLimiter(rdapConcurrency);
  const toAsk = [];
  for (const d of [...wanted].sort()) {
    const prev = known && known.get(d);
    if (prev && prev.verdict !== 'failed') registrations.set(d, prev);
    else toAsk.push(d);
  }
  total += toAsk.length;
  await Promise.all(toAsk.map((d) => rdapLimiter.run(async () => {
    const r = await rdap(d, { signal });
    let ns = null;
    if (r && !r.ok && (r.notFound || r.unsupportedTld)) ns = await ask(d, 'NS');
    const v = registrationVerdict(r, ns, { now: now(), expiringDays });
    if (v.verdict === 'failed') {
      if (r && !r.ok && !r.notFound && !r.unsupportedTld) failed('rdap', d, r);
      else if (ns && !ns.ok) failed('doh', `${d} NS`, ns);
      else failed('rdap', d, r || { ok: false, error: 'No answer', errorKind: 'unknown' });
    }
    registrations.set(d, { ...v, rdap: r, ns });
    tick();
  }, { signal })));
  throwIfAborted(signal);

  // 4. The findings.
  const findings = [];
  const seen = new Set();
  for (const ref of refs) {
    const id = `${ref.kind}|${ref.host}|${ref.target}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const match = HOST_KINDS.has(ref.kind) ? chainService(ref.chain) : null;
    const service = match ? match.service : null;
    const reasons = [];
    const domainsSeen = new Set();
    for (const name of ref.chain) {
      const d = registryDomainOf(name);
      if (!d || domainsSeen.has(d)) continue;
      domainsSeen.add(d);
      const reg = registrations.get(d);
      if (reg && TAKEOVER_REASONS.includes(reg.verdict)) {
        reasons.push({ code: reg.verdict, severity: reasonSeverity(reg.verdict, ref.kind, service), domain: d, expires: reg.expires || null });
      }
    }
    if (ref.dangling) reasons.push({ code: 'nxdomain', severity: reasonSeverity('nxdomain', ref.kind, service), name: ref.target });
    else if (service && service.signal === 'http' && service.status !== 'safe' && service.fingerprints.length) {
      reasons.push({ code: 'check-http', severity: 'info' });
    }
    if (!reasons.length) continue;
    reasons.sort((a, b) => rank(a.severity) - rank(b.severity));
    findings.push({
      id, severity: reasons[0].severity, kind: ref.kind, host: ref.host, target: ref.target, chain: ref.chain, term: ref.term,
      service: service ? { id: service.id, name: service.name, status: service.status, ref: service.ref } : null,
      reasons, fix: reasons[0].code
    });
  }
  findings.sort((a, b) => rank(a.severity) - rank(b.severity) || a.host.localeCompare(b.host) || a.target.localeCompare(b.target)
    || TAKEOVER_REF_KINDS.indexOf(a.kind) - TAKEOVER_REF_KINDS.indexOf(b.kind));
  const checked = [...registrations.values()].filter((r) => r.verdict !== 'failed').length;
  return {
    at: new Date(now()), domains: apexes, references: refs.length, findings, failures, registrations, checked, hosts: cnameHosts.length, spfMacros
  };
}

/* ------------------------------------------------------------------------ */
/* The HTTP check                                                           */
/* ------------------------------------------------------------------------ */

/**
 * The findings whose service's page decides (reason check-http), at most {@link HTTP_CHECK_MAX}.
 * @param {TakeoverFinding[]} findings
 * @returns {TakeoverFinding[]}
 */
export function httpCandidates(findings) {
  return (Array.isArray(findings) ? findings : []).filter((f) => f.reasons.some((r) => r.code === 'check-http')).slice(0, HTTP_CHECK_MAX);
}

/**
 * What a Globalping HTTP measurement of the host says: the service's "no such site" text
 * (claimable), another page served with a 2xx (in use) or no usable answer (no-answer: a failed
 * probe, a redirect, an error page without the fingerprint, an empty body).
 * @param {object|null} measurement a finished Globalping measurement (one probe)
 * @param {TakeoverService|{ id: string }|null} service the finding's service
 * @returns {{ outcome: string, httpStatus: number|null, truncated: boolean, measurementId: string|null }}
 */
export function httpCheckOutcome(measurement, service) {
  const m = measurement && typeof measurement === 'object' ? measurement : {};
  const test = Array.isArray(m.results) ? m.results[0] || {} : {};
  const r = test && test.result && typeof test.result === 'object' ? test.result : {};
  const full = service && Array.isArray(service.fingerprints) ? service : TAKEOVER_SERVICES.find((s) => service && s.id === service.id) || null;
  const out = {
    outcome: 'no-answer', httpStatus: Number.isInteger(r.statusCode) ? r.statusCode : null,
    truncated: r.truncated === true, measurementId: typeof m.id === 'string' ? m.id : null
  };
  if (r.status !== 'finished' || out.httpStatus === null) return out;
  const body = typeof r.rawBody === 'string' ? r.rawBody : '';
  // Only a page served as a success counts as in use: an error page without the fingerprint (the
  // service may have reworded it) stays undecided rather than hide a risk.
  if (fingerprintMatches(full, body)) out.outcome = 'claimable';
  else if (out.httpStatus >= 200 && out.httpStatus < 300 && body) out.outcome = 'in-use';
  return out;
}

/**
 * A finding after its HTTP check: a match turns check-http into fingerprint (severity by the
 * service's status); another page drops the finding (null); no answer keeps it as it was.
 * @param {TakeoverFinding} finding
 * @param {{ outcome: string }} check {@link httpCheckOutcome} result
 * @returns {TakeoverFinding|null}
 */
export function applyHttpCheck(finding, check) {
  if (!finding || !check) return finding || null;
  if (check.outcome === 'in-use') {
    const rest = finding.reasons.filter((r) => r.code !== 'check-http');
    return rest.length ? { ...finding, reasons: rest, severity: rest[0].severity, fix: rest[0].code, http: check } : null;
  }
  if (check.outcome !== 'claimable') return { ...finding, http: check };
  const service = finding.service ? TAKEOVER_SERVICES.find((s) => s.id === finding.service.id) || null : null;
  const reasons = finding.reasons.map((r) => (r.code === 'check-http' ? { code: 'fingerprint', severity: reasonSeverity('fingerprint', finding.kind, service) } : r));
  reasons.sort((a, b) => rank(a.severity) - rank(b.severity));
  return { ...finding, reasons, severity: reasons[0].severity, fix: reasons[0].code, http: check };
}
