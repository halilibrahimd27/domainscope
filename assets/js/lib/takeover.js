/**
 * takeover.js — subdomain takeover and dangling-reference audit (Subdomains › Overview ›
 * "Takeover risks", ui/takeover-panel.js).
 *
 * Three questions about every name a scan found and every name its domains point to:
 *  1. Does a host's CNAME chain end at a service where somebody else can claim the name? The
 *     {@link TAKEOVER_SERVICES} catalogue says, per service, which CNAME targets belong to it,
 *     how a released resource shows (`nxdomain`: the target name no longer exists; `http`: the
 *     service still answers, with a "no such site" page whose text is the fingerprint) and its
 *     status: `vulnerable` (anybody can create a resource with that name), `edge` (possible in
 *     some set-ups only) or `safe` (the service verifies ownership: a stale record to clean up).
 *  2. Does a CNAME, NS, MX or SPF include/redirect target sit in a registrable domain that is not
 *     registered, about to be deleted, expired or about to expire? Then whoever registers it
 *     serves the host, answers for the zone, receives the mail or may send as the domain. Asked
 *     through RDAP (lib/rdap.js rdapDomain, injected: paced per registry there); an RDAP 404
 *     counts only when DNS agrees (NXDOMAIN for the domain's NS), and a TLD without RDAP is
 *     judged by DNS alone, worded as "possibly registrable".
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

/** The kinds of reference a finding is about. */
export const TAKEOVER_REF_KINDS = Object.freeze(['cname', 'ns', 'mx', 'spf']);

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

/**
 * The include: and redirect= domains of an SPF record (macros left out).
 * @param {string} txt
 * @returns {string[]}
 */
export function spfTargets(txt) {
  if (typeof txt !== 'string' || !/^v=spf1(\s|$)/i.test(txt.trim())) return [];
  const out = [];
  for (const raw of txt.trim().split(/\s+/)) {
    const m = /^[+\-~?]?include:(.+)$/i.exec(raw) || /^redirect=(.+)$/i.exec(raw);
    if (!m || m[1].includes('%')) continue;
    const name = canon(m[1]);
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

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
    case 'unregistered': return kind === 'cname' || kind === 'ns' ? 'critical' : 'high';
    case 'unregistered-dns':
    case 'pending-delete':
    case 'expired': return 'high';
    case 'expiring': return 'medium';
    case 'nxdomain':
      if (kind !== 'cname') return 'low';
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
 * @property {string} kind cname | ns | mx | spf
 * @property {string} host the scanned host (cname) or the scanned domain (ns, mx, spf)
 * @property {string} target the CNAME chain's last name, or the NS / MX / SPF target
 * @property {string[]} chain the CNAME chain (cname), else [target]
 * @property {{ id: string, name: string, status: string, ref: string }|null} service
 * @property {TakeoverReason[]} reasons most severe first
 * @property {string} fix the code of the fix: the first reason's code
 */

/**
 * @typedef {object} TakeoverFailure
 * @property {'doh'|'rdap'} source
 * @property {string} name what was asked (a host, a domain, `<domain> NS`)
 * @property {object} response the failed DnsResponse or rdapDomain() result (lib/sourcestatus.js)
 */

/**
 * Audit the scanned hosts and domains. Only an abort rejects.
 *
 * Steps: the domains' NS, MX and TXT (SPF) records; every host with a CNAME chain asked again
 * (A, no cache: the chain and whether its end exists today) and every NS / MX target's A record;
 * then the registration of every registrable domain those references name, outside the scanned
 * domains and the catalogue's providers, through `rdap` (one lookup per domain; `known` carries
 * earlier verdicts, and only failed ones are asked again).
 *
 * @param {{ hosts?: object[], domains?: string[] }} input scan HostRecords (name, resolution.cnames,
 *   wildcardSuspect) and the scanned domains
 * @param {{ dns: { query: Function }, rdap: (domain: string, opts: object) => Promise<object>, signal?: AbortSignal,
 *   now?: () => number, known?: Map<string, object>|null, onProgress?: (done: number, total: number) => void,
 *   concurrency?: number, rdapConcurrency?: number, expiringDays?: number, skipTlds?: ReadonlyArray<string> }} opts
 *   `skipTlds`: the suffixes never looked up ({@link UNREGISTRABLE_TLDS}; tests that stand in `.test` for public domains clear it)
 * @returns {Promise<{ at: Date, domains: string[], references: number, findings: TakeoverFinding[],
 *   failures: TakeoverFailure[], registrations: Map<string, object>, checked: number }>}
 *   `registrations`: domain → { verdict, expires, rdap, ns } (pass back as `known` to retry);
 *   `checked`: registrable domains with a verdict
 */
export async function auditTakeover({ hosts = [], domains = [] } = {}, {
  dns, rdap, signal, now = Date.now, known = null, onProgress = null, concurrency = 6, rdapConcurrency = 4, expiringDays = EXPIRING_DAYS,
  skipTlds = UNREGISTRABLE_TLDS
} = {}) {
  throwIfAborted(signal);
  const unregistrable = (name) => skipTlds.some((s) => isSubdomainOf(name, s));
  const apexes = [...new Set((Array.isArray(domains) ? domains : []).map((d) => normalizeHostname(canon(d))).filter(Boolean))];
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

  /** @type {Array<{ kind: string, host: string, chain: string[], target: string, dangling: boolean }>} */
  const refs = [];
  const cnameHosts = (Array.isArray(hosts) ? hosts : [])
    .filter((x) => x && typeof x.name === 'string' && !x.wildcardSuspect && x.resolution && Array.isArray(x.resolution.cnames) && x.resolution.cnames.length);
  total = apexes.length * 3 + cnameHosts.length;
  if (onProgress) onProgress(0, total);

  // 1. The domains' NS, MX and SPF targets.
  await Promise.all(apexes.map(async (apex) => {
    const [ns, mx, txt] = await Promise.all(['NS', 'MX', 'TXT'].map((type) => ask(apex, type).then((r) => {
      tick();
      if (!r.ok) failed('doh', `${apex} ${type}`, r);
      return r;
    })));
    const answers = (r, type) => (r.ok && Array.isArray(r.answers) ? r.answers.filter((a) => a && a.type === type && canon(a.name) === apex) : []);
    for (const a of answers(ns, 'NS')) if (typeof a.data === 'string') refs.push({ kind: 'ns', host: apex, chain: [canon(a.data)], target: canon(a.data), dangling: false });
    for (const a of answers(mx, 'MX')) {
      const x = a.data && typeof a.data.exchange === 'string' ? canon(a.data.exchange) : '';
      if (x && x !== '.') refs.push({ kind: 'mx', host: apex, chain: [x], target: x, dangling: false });
    }
    for (const a of answers(txt, 'TXT')) {
      const text = Array.isArray(a.data) ? a.data.join('') : typeof a.data === 'string' ? a.data : '';
      for (const target of spfTargets(text)) refs.push({ kind: 'spf', host: apex, chain: [target], target, dangling: false });
    }
  }));

  // 2. Every CNAME chain again, and whether each NS / MX target exists.
  const outside = (name) => !apexes.some((a) => isSubdomainOf(name, a));
  const targets = refs.filter((r) => (r.kind === 'ns' || r.kind === 'mx') && outside(r.target) && !unregistrable(r.target));
  total += targets.length;
  await Promise.all([
    ...cnameHosts.map(async (x) => {
      const name = canon(x.name);
      const r = await ask(name, 'A', { noCache: true });
      tick();
      let chain = x.resolution.cnames.map(canon).filter(Boolean);
      let dangling = false;
      if (!r.ok) failed('doh', name, r);
      else {
        chain = cnameChain(r, name);
        dangling = chain.length > 0 && r.rcode === 'NXDOMAIN';
      }
      if (chain.length) refs.push({ kind: 'cname', host: name, chain, target: chain[chain.length - 1], dangling });
    }),
    ...targets.map(async (ref) => {
      const r = await ask(ref.target, 'A');
      tick();
      if (!r.ok) failed('doh', ref.target, r);
      else ref.dangling = r.rcode === 'NXDOMAIN';
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
    const match = ref.kind === 'cname' ? chainService(ref.chain) : null;
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
      id, severity: reasons[0].severity, kind: ref.kind, host: ref.host, target: ref.target, chain: ref.chain,
      service: service ? { id: service.id, name: service.name, status: service.status, ref: service.ref } : null,
      reasons, fix: reasons[0].code
    });
  }
  findings.sort((a, b) => rank(a.severity) - rank(b.severity) || a.host.localeCompare(b.host) || a.target.localeCompare(b.target));
  const checked = [...registrations.values()].filter((r) => r.verdict !== 'failed').length;
  return { at: new Date(now()), domains: apexes, references: refs.length, findings, failures, registrations, checked };
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
