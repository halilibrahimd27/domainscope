/**
 * renewal.js — "Renewal readiness": will the next ACME renewal of these names validate?
 *
 * With 47-day certificates and multi-perspective issuance corroboration (MPIC, CA/B Forum
 * Baseline Requirements §3.2.2.9: the CA repeats every domain validation and CAA lookup from
 * several network perspectives), a renewal that needs a hand is a renewal that fails. For each
 * name this module reads, over DNS-over-HTTPS only:
 *
 * - the CAA record set that applies (lib/health.js findCaa: tree climbing, CNAMEs followed per
 *   RFC 8659 §3) and whether the chosen CA may issue — RFC 8657 `validationmethods` against the
 *   chosen ACME challenge, `accounturi`, `issuewild` for a wildcard (checkCaaAllows);
 * - the same lookup on every resolver of {@link CONSISTENCY_RESOLVERS}: answers that disagree, or
 *   a SERVFAIL, mean a lagging or broken authoritative server that the CA's perspectives may hit;
 * - `_acme-challenge.<name>`: a CNAME delegation (DNS-01 alias mode, acme-dns) with its target,
 *   whether the target exists, and TXT records left behind;
 * - DNSSEC: signed and validated, not signed, or bogus (validating resolvers — the CA's too —
 *   answer SERVFAIL, so every validation method and the CAA lookup fail);
 * - the DNS provider from the zone's NS records → the lego / acme.sh / certbot plugin for DNS-01;
 * - HTTP-01 / TLS-ALPN-01 prerequisites: A / AAAA exist, public, IPv6 (both families must serve
 *   the challenge), a CDN in front (TLS-ALPN-01 cannot pass one).
 *
 * The optional HTTP-01 reachability test (one Globalping measurement per address family, from
 * three continents, only after an explicit click) is built by {@link http01Request} and read by
 * {@link interpretHttp01}; {@link applyHttp01} merges it into a report. A 404 for the made-up
 * token is the good answer: the path reaches the web server.
 *
 * Findings are `{ id, area, severity, params }` with EN / TR texts in {@link RENEWAL_I18N}
 * (`renew.f.<id>.title` / `.detail`, params language-neutral and pre-joined); a name's verdict is
 * 'fail' with any error, 'warnings' with any warning, else 'ready'. DOM-free; runs in browsers and
 * Node 22. All DNS goes through an injected client with the DohClient contract (§5.9): only
 * `query(name, type, { resolver, dnssec, cd, signal, noCache })`.
 */

import { errorKind, throwIfAborted, uniq, randomLabel, createLimiter } from './util.js';
import { normalizeHostname, isSubdomainOf, registrableDomain } from './domain.js';
import { normalizeIP, ipVersion, isPrivateIP, classifyResolution } from './netinfo.js';
import { findCaa, checkCaaAllows, caaIssuerInfo, caaRestrictionText, CAA_ISSUERS } from './health.js';
import { httpGetRequest, isProbeableHost, probeSummary } from './globalping.js';
import { parseFailure } from './verify.js';
import { getResolver } from './resolvers.js';
import { EDE_CODES } from './dnswire.js';

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

/** ACME challenge types the form offers; 'unknown' = the user does not know which one the client uses. */
export const RENEWAL_CHALLENGES = Object.freeze(['http-01', 'dns-01', 'tls-alpn-01', 'unknown']);
/** A name's verdict, worst first. */
export const RENEWAL_VERDICTS = Object.freeze(['fail', 'warnings', 'ready']);
/** At most this many names per check, and per HTTP-01 reachability test. */
export const RENEWAL_LIMITS = Object.freeze({ names: 50, http01Names: 10 });
/**
 * Resolvers the CAA lookup is repeated on: unfiltered, validating and readable from a browser
 * (resolvers.js: DEFAULT_CHAIN). Answers that differ between them are what one of the CA's
 * perspectives may see too.
 */
export const CONSISTENCY_RESOLVERS = Object.freeze(['cloudflare', 'google', 'dnssb', 'cznic']);
/** The DNS-01 label (RFC 8555 §8.4). */
export const ACME_CHALLENGE_LABEL = '_acme-challenge';
/** The HTTP-01 path (RFC 8555 §8.3). */
export const HTTP01_PATH_PREFIX = '/.well-known/acme-challenge/';
/** One probe on each of three continents, per address family. */
export const HTTP01_LOCATIONS = Object.freeze([{ continent: 'EU' }, { continent: 'NA' }, { continent: 'AS' }].map(Object.freeze));
/** Probe-side timeout of the reachability test (seconds). */
export const HTTP01_TIMEOUT_S = 10;
/** Areas a finding belongs to, in display order (the id's part before the first dot). */
export const RENEWAL_AREAS = Object.freeze(['caa', 'resolvers', 'wildcard', 'acme', 'provider', 'dnssec', 'http', 'http01']);

/**
 * CAs the form offers, with their CAA identifiers (lib/health.js CAA_ISSUERS). ZeroSSL issues from
 * Sectigo intermediates and asks for `sectigo.com` in CAA.
 * @type {ReadonlyArray<{ id: string, name: string, domains: ReadonlyArray<string> }>}
 */
export const RENEWAL_CAS = Object.freeze([
  ['letsencrypt'], ['zerossl', 'ZeroSSL', 'sectigo'], ['google'], ['sectigo'], ['digicert'], ['globalsign'], ['buypass'],
  ['actalis'], ['sslcom'], ['amazon'], ['godaddy'], ['harica'], ['certum'], ['entrust'], ['microsoft']
].map(([id, name = null, caa = id]) => {
  const entry = CAA_ISSUERS.find((x) => x.id === caa);
  return Object.freeze({ id, name: name || entry.name, domains: entry.domains });
}));

/**
 * DNS hosting providers by name server, with their DNS-01 plugins: lego's `--dns` code, acme.sh's
 * `--dns` hook and certbot's plugin package (`official`: shipped by the Certbot project). `api:
 * false`: no DNS API client of these three is known, so DNS-01 needs a CNAME delegation of
 * `_acme-challenge`. `ns` entries are name-server suffixes (label boundary) or patterns.
 * @type {ReadonlyArray<{ id: string, name: string, ns: ReadonlyArray<string|RegExp>, api: boolean,
 *   lego: string|null, acmesh: string|null, certbot: { pkg: string, official: boolean }|null }>}
 */
export const DNS_PROVIDERS = Object.freeze([
  ['cloudflare', 'Cloudflare', ['ns.cloudflare.com'], 'cloudflare', 'dns_cf', 'certbot-dns-cloudflare', true],
  ['route53', 'Amazon Route 53', [/^ns-\d+\.awsdns-\d+\.(?:com|net|org|co\.uk)$/], 'route53', 'dns_aws', 'certbot-dns-route53', true],
  ['azure', 'Azure DNS', ['azure-dns.com', 'azure-dns.net', 'azure-dns.org', 'azure-dns.info'], 'azuredns', 'dns_azure', 'certbot-dns-azure', false],
  ['gcloud', 'Google Cloud DNS', [/^ns-cloud-[a-z]\d+\.googledomains\.com$/], 'gcloud', 'dns_gcloud', 'certbot-dns-google', true],
  ['digitalocean', 'DigitalOcean', ['digitalocean.com'], 'digitalocean', 'dns_dgon', 'certbot-dns-digitalocean', true],
  ['hetzner', 'Hetzner DNS', ['ns.hetzner.com', 'ns.hetzner.de'], 'hetzner', 'dns_hetzner', 'certbot-dns-hetzner', false],
  ['ovh', 'OVHcloud', ['ovh.net', 'ovh.ca', 'anycast.me'], 'ovh', 'dns_ovh', 'certbot-dns-ovh', true],
  ['godaddy', 'GoDaddy', ['domaincontrol.com'], 'godaddy', 'dns_gd', 'certbot-dns-godaddy', false],
  ['linode', 'Linode (Akamai Cloud)', ['linode.com'], 'linode', 'dns_linode_v4', 'certbot-dns-linode', true],
  ['vultr', 'Vultr', ['vultr.com'], 'vultr', 'dns_vultr', null],
  ['gandi', 'Gandi', ['gandi.net'], 'gandiv5', 'dns_gandi_livedns', 'certbot-plugin-gandi', false],
  ['namecheap', 'Namecheap', ['registrar-servers.com'], 'namecheap', 'dns_namecheap', null],
  ['ns1', 'NS1', ['nsone.net'], 'ns1', 'dns_nsone', 'certbot-dns-nsone', true],
  ['dnsimple', 'DNSimple', ['dnsimple.com', 'dnsimple-edge.net', 'dnsimple-edge.org'], 'dnsimple', 'dns_dnsimple', 'certbot-dns-dnsimple', true],
  ['dnsmadeeasy', 'DNS Made Easy', ['dnsmadeeasy.com'], 'dnsmadeeasy', 'dns_me', 'certbot-dns-dnsmadeeasy', true],
  ['porkbun', 'Porkbun', ['porkbun.com'], 'porkbun', 'dns_porkbun', 'certbot-dns-porkbun', false],
  ['ionos', 'IONOS', ['ui-dns.com', 'ui-dns.de', 'ui-dns.org', 'ui-dns.biz'], 'ionos', 'dns_ionos', 'certbot-dns-ionos', false],
  ['desec', 'deSEC', ['desec.io', 'desec.org'], 'desec', 'dns_desec', 'certbot-dns-desec', false],
  ['infomaniak', 'Infomaniak', ['infomaniak.ch'], 'infomaniak', 'dns_infomaniak', 'certbot-dns-infomaniak', false],
  ['bunny', 'Bunny DNS', ['bunny.net'], 'bunny', 'dns_bunny', null],
  ['vercel', 'Vercel', ['vercel-dns.com'], 'vercel', 'dns_vercel', null],
  ['cloudns', 'ClouDNS', ['cloudns.net'], 'cloudns', 'dns_cloudns', null],
  ['alidns', 'Alibaba Cloud DNS', ['alidns.com', 'hichina.com'], 'alidns', 'dns_ali', null],
  ['scaleway', 'Scaleway', ['dom.scw.cloud'], 'scaleway', 'dns_scaleway', null],
  ['he', 'Hurricane Electric', ['he.net'], 'hurricane', 'dns_he', null],
  ['akamai', 'Akamai Edge DNS', ['akam.net'], 'edgedns', 'dns_edgedns', null],
  ['ultradns', 'UltraDNS', ['ultradns.net', 'ultradns.com', 'ultradns.org', 'ultradns.biz', 'ultradns.info', 'ultradns.co.uk'], 'ultradns', 'dns_ultra', null],
  ['acme-dns', 'acme-dns', ['acme-dns.io'], 'acme-dns', 'dns_acmedns', null],
  ['natro', 'Natro', ['natrohost.com']],
  ['turhost', 'Turhost', ['turhost.com']],
  ['isimtescil', 'İsimtescil', ['isimtescil.net', 'dnsenable.com']]
].map(([id, name, ns, lego = null, acmesh = null, pkg = null, official = false]) => Object.freeze({
  id, name, ns: Object.freeze(ns), api: !!lego, lego, acmesh, certbot: pkg ? Object.freeze({ pkg, official }) : null
})));

/** Every finding id (`renew.f.<id>.title` / `.detail`). */
export const RENEWAL_FINDINGS = Object.freeze([
  'caa.none', 'caa.open', 'caa.allowed', 'caa.restricted', 'caa.no-ca', 'caa.denied', 'caa.deny-all', 'caa.critical', 'caa.unusable',
  'caa.method-blocked', 'caa.method-check', 'caa.account', 'caa.cname', 'caa.servfail', 'caa.error',
  'resolvers.agree', 'resolvers.differ', 'resolvers.servfail', 'resolvers.unreachable',
  'wildcard.dns01', 'wildcard.unknown', 'wildcard.method',
  'acme.none', 'acme.leftover', 'acme.cname', 'acme.acme-dns', 'acme.dangling', 'acme.servfail', 'acme.bogus', 'acme.error',
  'provider.known', 'provider.no-api', 'provider.target-no-api', 'provider.multiple', 'provider.unknown', 'provider.error',
  'dnssec.secure', 'dnssec.unsigned', 'dnssec.bogus', 'dnssec.servfail', 'dnssec.unknown', 'dnssec.error',
  'http.ok', 'http.ipv6', 'http.cdn', 'http.alpn-cdn', 'http.private', 'http.private-some', 'http.none', 'http.nxdomain', 'http.dangling', 'http.error',
  'http01.ok', 'http01.redirect', 'http01.partial', 'http01.failed', 'http01.catch-all', 'http01.inconclusive', 'http01.untested'
]);

/**
 * What one probe got for the made-up token, good first: 'not-found' (404 / 410: the path reaches
 * the web server), 'redirect' (to port 80 or 443 over HTTP(S) with the token kept: CAs follow it);
 * 'catch-all' (2xx for a file that does not exist); then the failures.
 */
export const HTTP01_OUTCOMES = Object.freeze(['not-found', 'redirect', 'catch-all', 'forbidden', 'server-error', 'status',
  'redirect-loop', 'redirect-port', 'redirect-ip', 'redirect-path', 'redirect-scheme', 'redirect-none',
  'timeout', 'refused', 'dns', 'unreachable', 'private', 'reset', 'unknown', 'probe']);
/**
 * A family's (and a test's) result: every probe good, some, none, a catch-all answer, only
 * probe-side failures, or 'untested' (the test stopped before this family's measurement was created).
 */
export const HTTP01_VERDICTS = Object.freeze(['ok', 'partial', 'failed', 'catch-all', 'inconclusive', 'untested']);

const GOOD_OUTCOMES = new Set(['not-found', 'redirect']);
const FAILURE_OUTCOMES = {
  'connect-timeout': 'timeout', 'tls-timeout': 'timeout', refused: 'refused', dns: 'dns', unreachable: 'unreachable',
  private: 'private', reset: 'reset', offline: 'probe', internal: 'probe'
};
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

const arr = (v) => (Array.isArray(v) ? v : []);
const canonName = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const isAbort = (err) => errorKind(err) === 'abort';
const answered = (res) => !!res && res.ok && (res.rcode === 'NOERROR' || res.rcode === 'NXDOMAIN');
const finding = (id, severity, params = {}) => ({ id, area: id.slice(0, id.indexOf('.')), severity, params });

function records(res, type) {
  return arr(res && res.answers).filter((rr) => rr && rr.type === type);
}

function cnameChain(answers, name) {
  const chain = [];
  let cur = canonName(name);
  for (let i = 0; i < 16; i += 1) {
    const rr = arr(answers).find((r) => r && r.type === 'CNAME' && canonName(r.name) === cur);
    if (!rr) break;
    cur = canonName(rr.data);
    if (chain.includes(cur)) break;
    chain.push(cur);
  }
  return chain;
}

/** Owner of the deepest SOA (answer or authority) at `name` or above it: the name's zone. */
function soaOwner(res, name) {
  const owners = [...arr(res && res.answers), ...arr(res && res.authorities)]
    .filter((rr) => rr && rr.type === 'SOA' && isSubdomainOf(name, canonName(rr.name)))
    .map((rr) => canonName(rr.name));
  return owners.sort((a, b) => b.length - a.length)[0] || null;
}

/** "6 DNSSEC Bogus: signature expired" for each RFC 8914 EDE of a response. */
function edeTexts(res) {
  return uniq(arr(res && res.ede).map((e) => {
    const text = String((e && e.text) || '').trim().replace(/\.+$/, '');
    return `${e.code}${EDE_CODES[e.code] ? ` ${EDE_CODES[e.code]}` : ''}${text ? `: ${text}` : ''}`;
  }));
}

/** A CAA record as `0 issue "letsencrypt.org"` (language-neutral). */
function caaText(rr) {
  const d = rr && rr.data && typeof rr.data === 'object' ? rr.data : rr || {};
  return `${Number(d.flags) || 0} ${String(d.tag ?? '')} "${String(d.value ?? '')}"`;
}

const resolverName = (id) => (getResolver(id) ? getResolver(id).name : String(id));

/**
 * The run's DNS: one memoised query per name / type / resolver / flag set (a parent's CAA record
 * set is shared by every name under it), `noCache` passed through, and "never throws except on
 * abort": a transport failure is a response with `ok: false`.
 */
function dnsRun(dns, { signal, noCache }) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('A DNS client with query(name, type, opts) is required');
  const memo = new Map();
  const query = (name, type, { resolver = null, dnssec = false, cd = false } = {}) => {
    const n = canonName(name);
    const key = `${n}|${type}|${resolver || ''}|${dnssec ? 1 : 0}|${cd ? 1 : 0}`;
    if (!memo.has(key)) {
      const p = (async () => {
        throwIfAborted(signal);
        try {
          const opts = { dnssec, cd, signal, noCache: !!noCache };
          if (resolver) opts.resolver = resolver;
          const res = await dns.query(n, type, opts);
          const ok = !!res && res.ok !== false && typeof res.rcode === 'string';
          return {
            ok, rcode: ok ? res.rcode.toUpperCase() : null, flags: (res && res.flags) || {}, answers: arr(res && res.answers),
            authorities: arr(res && res.authorities), ede: arr(res && (res.ede ?? (res.edns && res.edns.ede))),
            resolver: (res && res.resolver) || resolver || null,
            error: ok ? null : String((res && res.error) || 'DNS query failed'), errorKind: ok ? null : (res && res.errorKind) || 'unknown'
          };
        } catch (err) {
          if (isAbort(err)) throw err;
          return { ok: false, rcode: null, flags: {}, answers: [], authorities: [], ede: [], resolver, error: err && err.message ? err.message : String(err), errorKind: errorKind(err) };
        }
      })();
      memo.set(key, p);
      p.catch(() => memo.delete(key));
    }
    return memo.get(key);
  };
  return {
    query,
    /** A DohClient-shaped client pinned to one resolver (no failover), for findCaa. */
    on(resolver) {
      return { query: (n, t, o = {}) => query(n, t, { ...o, resolver }) };
    },
    chain: { query: (n, t, o = {}) => query(n, t, o) }
  };
}

/* ------------------------------------------------------------------------ */
/* Input                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The names of a renewal: host names and `*.` wildcards, one per line or separated by spaces,
 * commas or semicolons (URLs and a trailing dot are accepted, `#` lines are comments). IP
 * addresses, single labels and names with `_` are invalid; duplicates are dropped; past `max` the rest is counted.
 * @param {string|string[]} input
 * @param {{ max?: number }} [opts]
 * @returns {{ names: Array<{ name: string, base: string, wildcard: boolean }>, invalid: string[], overCap: number }}
 */
export function parseRenewalNames(input, { max = RENEWAL_LIMITS.names } = {}) {
  const tokens = (Array.isArray(input) ? input : String(input ?? '').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n').split(/[\s,;]+/))
    .map((s) => String(s).trim()).filter(Boolean);
  const names = [];
  const invalid = [];
  const seen = new Set();
  let overCap = 0;
  for (const token of tokens) {
    // A certificate names no IP address here and no label with '_' (Baseline Requirements §7.1.2.7.12).
    const host = normalizeIP(token.replace(/^\[|\]$/g, '')) ? null : normalizeHostname(token, { allowWildcard: true });
    const name = host && !host.includes('_') ? host : null;
    if (!name) {
      if (!invalid.includes(token)) invalid.push(token);
      continue;
    }
    if (seen.has(name)) continue;
    seen.add(name);
    if (names.length >= max) {
      overCap += 1;
      continue;
    }
    const wildcard = name.startsWith('*.');
    names.push({ name, base: wildcard ? name.slice(2) : name, wildcard });
  }
  return { names, invalid, overCap };
}

/**
 * A {@link RENEWAL_CAS} entry by id, or null.
 * @param {string|null} id
 * @returns {{ id: string, name: string, domains: ReadonlyArray<string> }|null}
 */
export function renewalCa(id) {
  return RENEWAL_CAS.find((c) => c.id === id) || null;
}

/**
 * The {@link RENEWAL_CAS} id of a certificate's issuer (ZeroSSL before Sectigo, whose intermediates
 * it uses), or null for an issuer the list does not hold (a private CA, e-Tugra).
 * @param {string|object} issuer an issuer DN string or a parsed `{ CN, O }` object
 * @returns {string|null}
 */
export function caForIssuer(issuer) {
  const text = typeof issuer === 'string' ? issuer
    : issuer && typeof issuer === 'object' ? Object.values(issuer).filter((v) => typeof v === 'string').join(', ') : '';
  if (!text) return null;
  if (/zerossl/i.test(text)) return 'zerossl';
  const hit = caaIssuerInfo(text).find((ca) => renewalCa(ca.id));
  return hit ? hit.id : null;
}

/**
 * The providers behind a zone's name servers ({@link DNS_PROVIDERS}); `unmatched` lists the name
 * servers no entry knows.
 * @param {string[]} nsHosts
 * @returns {{ providers: object[], unmatched: string[] }}
 */
export function dnsProvidersFor(nsHosts) {
  const providers = [];
  const unmatched = [];
  for (const raw of arr(nsHosts)) {
    const host = canonName(raw);
    if (!host) continue;
    const p = DNS_PROVIDERS.find((x) => x.ns.some((m) => (m instanceof RegExp ? m.test(host) : host === m || host.endsWith(`.${m}`))));
    if (p) {
      if (!providers.includes(p)) providers.push(p);
    } else if (!unmatched.includes(host)) unmatched.push(host);
  }
  return { providers, unmatched };
}

/**
 * Does a delegation target look like an acme-dns registration (a UUID label under the acme-dns
 * zone, whatever server hosts it)?
 * @param {string} target
 * @returns {boolean}
 */
export function isAcmeDnsTarget(target) {
  const first = canonName(target).split('.')[0];
  return UUID_RE.test(first);
}

/**
 * The DNS-01 plugins of a provider as one language-neutral line:
 * `lego --dns cloudflare · acme.sh --dns dns_cf · certbot-dns-cloudflare`.
 * @param {{ lego: string|null, acmesh: string|null, certbot: { pkg: string }|null }} p
 * @returns {string}
 */
export function pluginText(p) {
  return [p.lego ? `lego --dns ${p.lego}` : null, p.acmesh ? `acme.sh --dns ${p.acmesh}` : null, p.certbot ? p.certbot.pkg : null]
    .filter(Boolean).join(' · ');
}

/* ------------------------------------------------------------------------ */
/* Findings (pure)                                                          */
/* ------------------------------------------------------------------------ */

/** Does the DNS side (`_acme-challenge`, the provider) matter for this name and challenge? */
const dnsMatters = (challenge, wildcard) => wildcard || challenge === 'dns-01' || challenge === 'unknown';
/** Do the address records matter (HTTP-01 / TLS-ALPN-01, or not known)? */
const addressMatters = (challenge, wildcard) => !wildcard && challenge !== 'dns-01';
/** A problem's severity when the method is known ('error') or only possible ('warn'). */
const methodSeverity = (challenge) => (challenge === 'unknown' ? 'warn' : 'error');

function caaFindings(caa, { ca, challenge, wildcard, name }) {
  const out = [];
  if (!caa) return out;
  if (caa.error) {
    const servfail = !!caa.rcode && caa.rcode !== 'NOERROR' && caa.rcode !== 'NXDOMAIN';
    out.push(servfail ? finding('caa.servfail', 'error', { name, rcode: caa.rcode, error: caa.error })
      : finding('caa.error', 'warn', { name, error: caa.error }));
    return out;
  }
  const alias = arr(caa.chain).find((c) => arr(c.cnames).length);
  if (alias) out.push(finding('caa.cname', 'info', { from: alias.name, chain: alias.cnames.join(' → '), name }));
  const check = checkCaaAllows(caa.parsed, null, { wildcard, issuerDomains: ca ? [...ca.domains] : [] });
  const base = {
    ca: ca ? ca.name : '', property: check.property || (wildcard ? 'issuewild' : 'issue'), foundAt: caa.foundAt || '',
    authorized: check.authorized.length ? check.authorized.join(', ') : '—'
  };
  switch (check.reason) {
    case 'none':
      out.push(finding('caa.none', 'ok', { name }));
      return out;
    case 'no-issue-property':
      out.push(finding('caa.open', 'ok', { foundAt: base.foundAt }));
      return out;
    case 'critical-unknown':
      out.push(finding('caa.critical', 'error', { foundAt: base.foundAt, tags: caa.parsed.unknown.filter((u) => u.critical).map((u) => u.tag).join(', ') }));
      return out;
    case 'deny-all':
      out.push(finding('caa.deny-all', 'error', { foundAt: base.foundAt, property: base.property }));
      return out;
    case 'unknown-issuer':
      out.push(finding('caa.no-ca', 'info', base));
      return out;
    case 'not-listed':
      out.push(finding('caa.denied', 'error', { ...base, domain: ca.domains[0] }));
      return out;
    case 'unsatisfiable':
    case 'malformed':
      out.push(finding('caa.unusable', 'error', { ...base, values: check.unusable.map((u) => `${u.raw} (${u.problem})`).join('; ') }));
      return out;
    case 'allowed':
      out.push(finding('caa.allowed', 'ok', base));
      return out;
    default:
      break;
  }
  // 'restricted': the CA may issue under RFC 8657 conditions; a request must satisfy one alternative.
  const restrictions = check.restrictions;
  out.push(finding('caa.restricted', 'info', { ...base, restrictions: restrictions.map(caaRestrictionText).join(' | ') }));
  const allowsMethod = (r) => !Array.isArray(r.methods) || (challenge !== 'unknown' && r.methods.includes(challenge));
  const methods = restrictions.every((r) => Array.isArray(r.methods)) ? uniq(restrictions.flatMap((r) => r.methods)) : null;
  let usable = restrictions;
  if (challenge !== 'unknown') {
    usable = restrictions.filter(allowsMethod);
    if (!usable.length) out.push(finding('caa.method-blocked', 'error', { challenge, methods: methods ? methods.join(', ') : '', foundAt: base.foundAt }));
  } else if (methods) {
    out.push(finding('caa.method-check', 'warn', { methods: methods.join(', '), foundAt: base.foundAt }));
  }
  if (usable.length && usable.every((r) => r.accountUri)) {
    out.push(finding('caa.account', 'info', { accounts: uniq(usable.map((r) => r.accountUri)).join(', ') }));
  }
  return out;
}

function resolverFindings(list, { ca, wildcard }) {
  const out = [];
  if (!arr(list).length) return out;
  const ok = list.filter((r) => r.state === 'ok');
  const servfail = list.filter((r) => r.state === 'servfail');
  const failed = list.filter((r) => r.state === 'error');
  const names = (xs) => xs.map((r) => resolverName(r.id)).join(', ');
  if (servfail.length) {
    out.push(finding('resolvers.servfail', 'warn', { resolvers: names(servfail), rcode: uniq(servfail.map((r) => r.rcode)).join(', '), count: servfail.length }));
  }
  const groups = new Map();
  for (const r of ok) {
    if (!groups.has(r.key)) groups.set(r.key, []);
    groups.get(r.key).push(r);
  }
  if (groups.size > 1) {
    // A variant that denies the chosen CA makes the result depend on which server a perspective reaches.
    const denies = !!ca && [...groups.values()].some((g) => checkCaaAllows(g[0].parsed, null, { wildcard, issuerDomains: [...ca.domains] }).allowed === false);
    const variants = [...groups.values()].map((g) => `${names(g)}: ${g[0].records.length ? `${g[0].records.join(', ')} (${g[0].foundAt})` : 'no CAA'}`).join(' | ');
    out.push(finding('resolvers.differ', denies ? 'error' : 'warn', { variants, count: groups.size }));
  } else if (ok.length >= 2 && !servfail.length) {
    out.push(finding('resolvers.agree', 'ok', { count: ok.length, resolvers: names(ok) }));
  }
  if (failed.length) out.push(finding('resolvers.unreachable', 'info', { resolvers: names(failed), count: failed.length }));
  return out;
}

function acmeFindings(acme, { challenge, wildcard }) {
  const out = [];
  if (!acme) return out;
  const matters = dnsMatters(challenge, wildcard);
  // `challenge` is the effective one: DNS-01 for a wildcard, whatever was chosen.
  const sev = challenge === 'dns-01' ? 'error' : 'warn';
  const p = { owner: acme.owner, target: acme.target || '', count: acme.txt.length };
  switch (acme.state) {
    case 'none':
      if (matters) out.push(finding('acme.none', 'ok', p));
      break;
    case 'txt':
      out.push(finding('acme.leftover', 'info', { ...p, values: acme.txt.slice(0, 3).join(', ') }));
      break;
    case 'cname':
      out.push(finding(acme.acmeDns ? 'acme.acme-dns' : 'acme.cname', 'info', p));
      break;
    case 'dangling':
      // A DNS-01 renewal fails, and whoever can create the target can pass DNS-01 for the name.
      out.push(finding('acme.dangling', sev, p));
      break;
    case 'bogus':
      out.push(finding('acme.bogus', matters ? sev : 'warn', { ...p, ede: acme.ede.join('; ') || '—' }));
      break;
    case 'servfail':
      if (matters) out.push(finding('acme.servfail', sev, { ...p, rcode: acme.rcode || '' }));
      break;
    default:
      if (matters) out.push(finding('acme.error', 'warn', { ...p, error: acme.error || '' }));
  }
  return out;
}

function providerFindings(host, { challenge, wildcard, delegated }) {
  const out = [];
  if (!host || !dnsMatters(challenge, wildcard)) return out;
  const zone = host.zone || '';
  if (host.error) {
    out.push(finding('provider.error', 'info', { zone, error: host.error }));
    return out;
  }
  const certain = challenge === 'dns-01';
  if (host.providers.length > 1) {
    out.push(finding('provider.multiple', certain ? 'warn' : 'info', { zone, providers: host.providers.map((p) => p.name).join(', ') }));
    return out;
  }
  if (!host.providers.length) {
    out.push(finding('provider.unknown', 'info', { zone, ns: host.ns.join(', ') || '—' }));
    return out;
  }
  const p = host.providers[0];
  if (!p.api) {
    // `host` is the zone that takes the TXT record: under a delegation, the target's.
    out.push(finding(delegated ? 'provider.target-no-api' : 'provider.no-api', certain ? 'warn' : 'info', { zone, provider: p.name }));
    return out;
  }
  out.push(finding('provider.known', 'info', { zone, provider: p.name, plugins: pluginText(p) }));
  return out;
}

function dnssecFindings(d, { name }) {
  if (!d) return [];
  switch (d.state) {
    case 'secure': return [finding('dnssec.secure', 'ok', { zone: d.zone || name })];
    case 'unsigned': return [finding('dnssec.unsigned', 'ok', { zone: d.zone || name })];
    case 'bogus': return [finding('dnssec.bogus', 'error', { name, ede: d.ede.join('; ') || '—' })];
    case 'servfail': return [finding('dnssec.servfail', 'error', { name, rcode: d.rcode || 'SERVFAIL' })];
    case 'unknown': return [finding('dnssec.unknown', 'info', { resolver: d.resolver || '' })];
    default: return [finding('dnssec.error', 'warn', { error: d.error || '' })];
  }
}

function wildcardFindings({ wildcard, challenge, base }) {
  if (!wildcard) return [];
  if (challenge === 'dns-01') return [finding('wildcard.dns01', 'ok', { base })];
  if (challenge === 'unknown') return [finding('wildcard.unknown', 'warn', { base })];
  return [finding('wildcard.method', 'error', { base, challenge })];
}

function addressFindings(a, { challenge, wildcard, name, dnsFailed }) {
  const out = [];
  if (!a || !addressMatters(challenge, wildcard)) return out;
  const sev = methodSeverity(challenge);
  if (a.error) {
    // A name whose lookups fail for DNSSEC or at its servers says so once, under DNSSEC.
    if (!dnsFailed) out.push(finding('http.error', 'warn', { name, error: a.error }));
    return out;
  }
  const ips = [...a.ipv4, ...a.ipv6];
  if (!ips.length) {
    if (a.cnames.length) out.push(finding('http.dangling', sev, { name, chain: a.cnames.join(' → '), rcode: a.status }));
    else if (a.status === 'NXDOMAIN') out.push(finding('http.nxdomain', sev, { name }));
    else out.push(finding('http.none', sev, { name }));
    return out;
  }
  const priv = ips.filter(isPrivateIP);
  const pub = ips.filter((ip) => !isPrivateIP(ip));
  if (!pub.length) {
    out.push(finding('http.private', sev, { name, ips: priv.join(', ') }));
    return out;
  }
  const v4 = pub.filter((ip) => ipVersion(ip) === 4);
  const v6 = pub.filter((ip) => ipVersion(ip) === 6);
  out.push(finding('http.ok', 'ok', { name, count4: v4.length, count6: v6.length, ips: pub.slice(0, 6).join(', ') }));
  if (priv.length) out.push(finding('http.private-some', 'warn', { name, ips: priv.join(', ') }));
  if (v6.length) out.push(finding('http.ipv6', 'info', { name, ipv6: v6.slice(0, 4).join(', ') }));
  if (a.hidesOrigin && a.provider) {
    out.push(challenge === 'tls-alpn-01'
      ? finding('http.alpn-cdn', 'error', { name, provider: a.provider })
      : finding('http.cdn', 'info', { name, provider: a.provider }));
  }
  return out;
}

/**
 * The findings of an HTTP-01 reachability test ({@link interpretHttp01} per family): a failure is an
 * error when the renewal uses HTTP-01, a warning when the method is not known. Some regions only:
 * a warning, but an error for HTTP-01 once more than one probe could not reach the server — the
 * CA's multi-perspective validation tolerates one failing remote perspective, two only with six or
 * more (Baseline Requirements §3.2.2.9).
 * @param {{ families: Array<{ ipVersion: 4|6, verdict: string, probes: object[] }> }|null} test
 * @param {{ challenge: string, name: string }} ctx
 * @returns {Array<{ id: string, area: string, severity: string, params: object }>}
 */
export function http01Findings(test, { challenge, name }) {
  if (!test || !arr(test.families).length) return [];
  const out = [];
  const sev = methodSeverity(challenge === 'http-01' ? 'http-01' : 'unknown');
  const places = (fam, pred) => fam.probes.filter(pred).map((p) => p.place).filter(Boolean).join('; ');
  for (const fam of test.families) {
    const family = fam.ipVersion === 6 ? 'IPv6' : 'IPv4';
    const answers = uniq(fam.probes.map((p) => (p.status ? String(p.status) : p.outcome))).join(', ');
    const common = { name, family, answers };
    const bad = (p) => !GOOD_OUTCOMES.has(p.outcome) && p.outcome !== 'probe';
    switch (fam.verdict) {
      case 'ok': {
        const redirect = fam.probes.find((p) => p.outcome === 'redirect');
        const good = { ...common, count: fam.probes.filter((p) => GOOD_OUTCOMES.has(p.outcome)).length, places: places(fam, (p) => GOOD_OUTCOMES.has(p.outcome)) };
        out.push(redirect ? finding('http01.redirect', 'ok', { ...good, location: redirect.location }) : finding('http01.ok', 'ok', good));
        break;
      }
      case 'partial': {
        // A catch-all answer still reached the web server: only what did not counts against the quorum.
        const unreached = fam.probes.filter((p) => bad(p) && p.outcome !== 'catch-all').length;
        out.push(finding('http01.partial', unreached > 1 ? sev : 'warn', { ...common, places: places(fam, bad), outcomes: uniq(fam.probes.filter(bad).map((p) => p.outcome)).join(', ') }));
        break;
      }
      case 'failed':
        out.push(finding('http01.failed', sev, { ...common, outcomes: uniq(fam.probes.filter(bad).map((p) => p.outcome)).join(', ') }));
        break;
      case 'catch-all':
        out.push(finding('http01.catch-all', 'warn', common));
        break;
      case 'untested':
        out.push(finding('http01.untested', 'info', { name, family }));
        break;
      default:
        out.push(finding('http01.inconclusive', 'info', common));
    }
  }
  return out;
}

/**
 * Every finding of one checked name, in area order ({@link RENEWAL_AREAS}), plus the reachability
 * test's when there is one. Pure: the same data always gives the same findings.
 * @param {object} r a NameResult ({@link checkRenewal})
 * @param {{ ca: object|null, challenge: string }} ctx
 * @returns {Array<{ id: string, area: string, severity: string, params: object }>}
 */
export function nameFindings(r, { ca, challenge }) {
  const ctx = { ca, challenge, wildcard: r.wildcard, name: r.name, base: r.base };
  // Only DNS-01 validates a wildcard: what would stop it is certain, whatever was chosen (the
  // wildcard finding says when the chosen method is another one).
  const effective = { ...ctx, challenge: r.wildcard ? 'dns-01' : challenge };
  const dnsFailed = !!r.dnssec && (r.dnssec.state === 'bogus' || r.dnssec.state === 'servfail');
  const list = [
    ...caaFindings(r.caa, effective),
    ...resolverFindings(r.resolvers, ctx),
    ...wildcardFindings(ctx),
    ...acmeFindings(r.acme, effective),
    ...providerFindings(r.dnsHost, { ...effective, delegated: !!r.acme && r.acme.state === 'cname' }),
    ...dnssecFindings(r.dnssec, ctx),
    ...addressFindings(r.address, { ...ctx, name: r.base, dnsFailed }),
    ...http01Findings(r.http01, { challenge, name: r.base })
  ];
  return list.map((f, i) => ({ f, i }))
    .sort((a, b) => RENEWAL_AREAS.indexOf(a.f.area) - RENEWAL_AREAS.indexOf(b.f.area) || a.i - b.i).map((x) => x.f);
}

/**
 * 'fail' with any error, 'warnings' with any warning, else 'ready'.
 * @param {Array<{ severity: string }>} findings
 * @returns {'fail'|'warnings'|'ready'}
 */
export function nameVerdict(findings) {
  if (arr(findings).some((f) => f.severity === 'error')) return 'fail';
  if (arr(findings).some((f) => f.severity === 'warn')) return 'warnings';
  return 'ready';
}

/* ------------------------------------------------------------------------ */
/* DNS gathering                                                            */
/* ------------------------------------------------------------------------ */

/** The effective CAA record set, reduced to what the report keeps. */
function caaResult(found) {
  const last = found.chain[found.chain.length - 1] || null;
  return {
    name: found.name, foundAt: found.foundAt, records: found.records.map(caaText), parsed: found.parsed,
    chain: found.chain.map((c) => ({ name: c.name, rcode: c.rcode, count: c.count, cnames: arr(c.cnames) })),
    error: found.error, rcode: found.error && last ? last.rcode : null
  };
}

async function consistency(base, run, resolvers) {
  return Promise.all(resolvers.map(async (id) => {
    const found = await findCaa(base, { dns: run.on(id) });
    const last = found.chain[found.chain.length - 1] || null;
    if (found.error) {
      const rcode = last ? last.rcode : null;
      return { id, state: rcode ? 'servfail' : 'error', rcode, error: found.error, foundAt: null, records: [], key: null, parsed: null };
    }
    const recs = found.records.map(caaText).sort();
    return { id, state: 'ok', rcode: null, error: null, foundAt: found.foundAt, records: recs, key: `${found.foundAt || ''}|${recs.join('\n')}`, parsed: found.parsed };
  }));
}

async function dnssecOf(base, run) {
  const res = await run.query(base, 'SOA', { dnssec: true });
  if (!res.ok) return { state: 'error', zone: null, ede: [], resolver: null, rcode: null, error: res.error };
  if (res.rcode === 'SERVFAIL') {
    // Validation failure or broken servers: the answer comes back without validation (CD) only for the first.
    const cd = await run.query(base, 'SOA', { cd: true });
    if (answered(cd)) return { state: 'bogus', zone: soaOwner(cd, base), ede: edeTexts(res), resolver: res.resolver, rcode: res.rcode, error: null };
    return { state: 'servfail', zone: null, ede: edeTexts(res), resolver: res.resolver, rcode: res.rcode, error: null };
  }
  if (!answered(res)) return { state: 'servfail', zone: null, ede: edeTexts(res), resolver: res.resolver, rcode: res.rcode, error: null };
  const zone = soaOwner(res, base);
  if (res.flags && res.flags.ad) return { state: 'secure', zone, ede: [], resolver: res.resolver, rcode: res.rcode, error: null };
  const r = res.resolver ? getResolver(res.resolver) : null;
  // AD clear from a validating resolver: nothing is signed up to a trust anchor for this name.
  return { state: r && r.dnssecValidating ? 'unsigned' : 'unknown', zone, ede: [], resolver: res.resolver, rcode: res.rcode, error: null };
}

async function acmeOf(base, run) {
  const owner = `${ACME_CHALLENGE_LABEL}.${base}`;
  const res = await run.query(owner, 'TXT');
  const out = { owner, state: 'none', rcode: res.rcode, cnames: [], target: null, acmeDns: false, txt: [], ede: [], zone: null, error: null };
  if (!res.ok) return { ...out, state: 'error', error: res.error };
  out.cnames = cnameChain(res.answers, owner);
  out.target = out.cnames.length ? out.cnames[out.cnames.length - 1] : null;
  out.acmeDns = !!out.target && isAcmeDnsTarget(out.target);
  out.txt = records(res, 'TXT').map((rr) => (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '')));
  if (res.rcode === 'SERVFAIL') {
    const cd = await run.query(owner, 'TXT', { cd: true });
    if (answered(cd)) {
      const chain = cnameChain(cd.answers, owner);
      return { ...out, state: 'bogus', cnames: chain, target: chain.length ? chain[chain.length - 1] : null, ede: edeTexts(res) };
    }
    return { ...out, state: 'servfail' };
  }
  if (!answered(res)) return { ...out, state: 'servfail' };
  if (out.target) {
    out.zone = soaOwner(res, out.target);
    return { ...out, state: res.rcode === 'NXDOMAIN' ? 'dangling' : 'cname' };
  }
  return { ...out, state: out.txt.length ? 'txt' : 'none' };
}

async function addressOf(base, run) {
  const [a, aaaa] = await Promise.all([run.query(base, 'A'), run.query(base, 'AAAA')]);
  if (!answered(a) && !answered(aaaa)) {
    return { status: a.rcode || 'ERROR', cnames: [], ipv4: [], ipv6: [], error: a.error || a.rcode || 'lookup failed' };
  }
  const ref = answered(a) ? a : aaaa;
  const ipv4 = uniq(records(a, 'A').map((rr) => normalizeIP(rr.data)).filter((ip) => ip && ipVersion(ip) === 4));
  const ipv6 = uniq(records(aaaa, 'AAAA').map((rr) => normalizeIP(rr.data)).filter((ip) => ip && ipVersion(ip) === 6));
  const cnames = cnameChain(ref.answers, base);
  const c = classifyResolution({ status: ref.rcode, ipv4, ipv6, cnames });
  return {
    status: ref.rcode, cnames, ipv4, ipv6, error: null, kind: c.kind,
    provider: c.provider ? c.provider.name : null, hidesOrigin: !!c.hidesOrigin
  };
}

async function dnsHostOf(zone, run) {
  if (!zone) return null;
  const res = await run.query(zone, 'NS');
  if (!answered(res)) return { zone, ns: [], providers: [], unmatched: [], error: res.error || res.rcode || 'lookup failed' };
  const ns = uniq(records(res, 'NS').map((rr) => canonName(rr.data)).filter(Boolean)).sort();
  const { providers, unmatched } = dnsProvidersFor(ns);
  return { zone, ns, providers, unmatched, error: null };
}

/**
 * The zone that takes the DNS-01 TXT record: the delegation target's, else the name's own; null
 * for a delegation whose target does not exist (its finding says what to do).
 */
async function txtZone(r, run) {
  const a = r.acme;
  if (a && a.state === 'dangling') return null;
  if (a && a.state === 'cname' && a.target) {
    if (a.zone) return a.zone;
    const soa = await run.query(a.target, 'SOA');
    return soaOwner(soa, a.target) || registrableDomain(a.target);
  }
  return (r.dnssec && r.dnssec.zone) || registrableDomain(r.base);
}

/**
 * Check one name (see {@link checkRenewal}). Exported for tests.
 * @param {{ name: string, base: string, wildcard: boolean }} entry
 * @param {{ run: object, ca: object|null, challenge: string, resolvers: string[] }} ctx
 * @returns {Promise<object>} NameResult
 */
export async function checkRenewalName(entry, { run, ca, challenge, resolvers }) {
  const { name, base, wildcard } = entry;
  const [found, resolverList, dnssec, acme, address] = await Promise.all([
    findCaa(base, { dns: run.chain }),
    consistency(base, run, resolvers),
    dnssecOf(base, run),
    acmeOf(base, run),
    addressMatters(challenge, wildcard) ? addressOf(base, run) : null
  ]);
  const r = { name, base, wildcard, caa: caaResult(found), resolvers: resolverList, dnssec, acme, address, dnsHost: null, http01: null };
  // An acme-dns registration is updated through the acme-dns API: whoever serves its zone does not matter.
  const viaAcmeDns = acme.state === 'cname' && acme.acmeDns;
  if (dnsMatters(challenge, wildcard) && !viaAcmeDns) r.dnsHost = await dnsHostOf(await txtZone(r, run), run);
  r.findings = nameFindings(r, { ca, challenge });
  r.verdict = nameVerdict(r.findings);
  return r;
}

/**
 * Check every name: CAA (+ the chosen CA and challenge), the CAA lookup on each consistency
 * resolver, `_acme-challenge`, DNSSEC, the DNS provider (when DNS-01 may be used) and the address
 * records (when HTTP-01 / TLS-ALPN-01 may be used). Names run four at a time; the DNS answers of
 * one check are shared between its names. Rejects only on abort (a failed lookup is a finding).
 *
 * @param {{ names: Array<{ name: string, base: string, wildcard: boolean }>, ca?: string|null, challenge?: string }} input
 *   `names` from {@link parseRenewalNames}; `ca` a {@link RENEWAL_CAS} id (null: not known)
 * @param {{ dns: object, signal?: AbortSignal, resolvers?: string[], noCache?: boolean, concurrency?: number,
 *   onProgress?: (p: { done: number, total: number, name: string }) => void, now?: () => Date }} opts
 * @returns {Promise<{ startedAt: Date, finishedAt: Date, ca: object|null, challenge: string, resolvers: string[],
 *   names: object[] }>}
 */
export async function checkRenewal({ names, ca = null, challenge = 'unknown' } = {}, {
  dns, signal, resolvers = CONSISTENCY_RESOLVERS, noCache = false, concurrency = 4, onProgress, now = () => new Date()
} = {}) {
  if (!RENEWAL_CHALLENGES.includes(challenge)) throw new TypeError(`Unknown challenge: ${String(challenge)}`);
  const caEntry = ca ? renewalCa(ca) : null;
  if (ca && !caEntry) throw new TypeError(`Unknown CA: ${String(ca)}`);
  const list = arr(names).filter((n) => n && typeof n.base === 'string' && n.base);
  throwIfAborted(signal);
  const run = dnsRun(dns, { signal, noCache });
  const startedAt = now();
  const limiter = createLimiter(concurrency);
  let done = 0;
  const results = await Promise.all(list.map((entry) => limiter.run(async () => {
    const r = await checkRenewalName(entry, { run, ca: caEntry, challenge, resolvers: [...resolvers] });
    done += 1;
    if (typeof onProgress === 'function') {
      try { onProgress({ done, total: list.length, name: entry.name }); } catch { /* observer errors are ignored */ }
    }
    return r;
  }, { signal })));
  throwIfAborted(signal);
  return { startedAt, finishedAt: now(), ca: caEntry, challenge, resolvers: [...resolvers], names: results };
}

/* ------------------------------------------------------------------------ */
/* HTTP-01 reachability (Globalping, after an explicit click)               */
/* ------------------------------------------------------------------------ */

/**
 * A made-up token: `domainscope-check-<16 random [a-z0-9]>`, so the site's logs say who asked.
 * @returns {string}
 */
export function http01Token() {
  return `domainscope-check-${randomLabel(16)}`;
}

/**
 * Can a name be tested from Globalping, and over which families? A wildcard, a host Globalping
 * refuses, a failed lookup and a name without a public address cannot.
 * @param {object} r a NameResult
 * @returns {{ ok: boolean, families: Array<4|6> }}
 */
export function http01Plan(r) {
  const a = r && r.address;
  if (!r || r.wildcard || !a || a.error || !isProbeableHost(r.base)) return { ok: false, families: [] };
  const families = [];
  if (a.ipv4.some((ip) => !isPrivateIP(ip))) families.push(4);
  if (a.ipv6.some((ip) => !isPrivateIP(ip))) families.push(6);
  return { ok: families.length > 0, families };
}

/**
 * The Globalping body of one family's test: a plain-HTTP GET of `/.well-known/acme-challenge/<token>`
 * on port 80 from one probe on each continent of {@link HTTP01_LOCATIONS}.
 * @param {string} host
 * @param {{ token: string, ipVersion?: 4|6|null }} opts
 * @returns {object}
 */
export function http01Request(host, { token, ipVersion: family = null }) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(token)) throw new TypeError('token must be 1–64 base64url characters');
  return httpGetRequest({
    host, path: `${HTTP01_PATH_PREFIX}${token}`, port: 80, timeoutS: HTTP01_TIMEOUT_S,
    locations: HTTP01_LOCATIONS.map((l) => ({ ...l })), ipVersion: family
  });
}

/**
 * What a redirect of the challenge URL means to a CA that follows it (Let's Encrypt: up to 10
 * redirects, to http or https on port 80 or 443 only, never to an IP address; the certificate of
 * an HTTPS target is not checked).
 * @param {string|null} location
 * @param {{ host: string, path: string }} ctx
 * @returns {string} an {@link HTTP01_OUTCOMES} code
 */
export function redirectOutcome(location, { host, path }) {
  if (!location) return 'redirect-none';
  let u;
  try {
    u = new URL(location, `http://${host}${path}`);
  } catch {
    return 'redirect-none';
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'redirect-scheme';
  if (u.port && u.port !== '80' && u.port !== '443') return 'redirect-port';
  if (ipVersion(u.hostname.replace(/^\[|\]$/g, ''))) return 'redirect-ip';
  const token = path.slice(path.lastIndexOf('/') + 1);
  if (!u.pathname.endsWith(`/${token}`)) return 'redirect-path';
  if (u.protocol === 'http:' && canonName(u.hostname) === canonName(host) && u.pathname === path) return 'redirect-loop';
  return 'redirect';
}

/**
 * One probe's answer as an {@link HTTP01_OUTCOMES} code.
 * @param {object} result a Globalping test `result`
 * @param {{ host: string, path: string }} ctx
 * @returns {{ outcome: string, status: number|null, location: string|null, address: string|null, failure: string|null }}
 */
export function http01Outcome(result, { host, path }) {
  const r = result && typeof result === 'object' ? result : {};
  const address = typeof r.resolvedAddress === 'string' ? r.resolvedAddress : null;
  if (r.status !== 'finished' || !Number.isInteger(r.statusCode)) {
    const f = parseFailure(r);
    return { outcome: FAILURE_OUTCOMES[f.kind] || 'unknown', status: null, location: null, address, failure: f.text || null };
  }
  const status = r.statusCode;
  const headers = r.headers && typeof r.headers === 'object' ? r.headers : {};
  const key = Object.keys(headers).find((k) => k.toLowerCase() === 'location');
  const raw = key === undefined ? null : headers[key];
  const location = Array.isArray(raw) ? String(raw[0] ?? '') || null : raw ? String(raw) : null;
  let outcome;
  if (status === 404 || status === 410) outcome = 'not-found';
  else if (status >= 300 && status < 400) outcome = redirectOutcome(location, { host, path });
  else if (status >= 200 && status < 300) outcome = 'catch-all';
  else if (status === 401 || status === 403) outcome = 'forbidden';
  else if (status >= 500) outcome = 'server-error';
  else outcome = 'status';
  return { outcome, status, location, address, failure: null };
}

/**
 * A family's verdict from its probes' outcomes: 'inconclusive' when only probes failed on their
 * side, 'ok' when every other probe got a good answer, 'catch-all' when the rest answered 2xx,
 * 'failed' when none got a good answer, else 'partial'.
 * @param {Array<{ outcome: string }>} probes
 * @returns {string} an {@link HTTP01_VERDICTS} value
 */
export function http01Verdict(probes) {
  const real = arr(probes).filter((p) => p.outcome !== 'probe');
  if (!real.length) return 'inconclusive';
  const good = real.filter((p) => GOOD_OUTCOMES.has(p.outcome)).length;
  const catchAll = real.filter((p) => p.outcome === 'catch-all').length;
  if (good === real.length) return 'ok';
  if (catchAll && good + catchAll === real.length) return 'catch-all';
  if (!good) return catchAll ? 'partial' : 'failed';
  return 'partial';
}

/**
 * Read one family's measurement: every probe's place and outcome, and the family's verdict.
 * @param {object} measurement the Globalping measurement JSON
 * @param {{ host: string, path: string, ipVersion?: 4|6 }} ctx
 * @returns {{ ipVersion: 4|6, measurementId: string|null, path: string, verdict: string,
 *   probes: Array<{ place: string, probe: object, outcome: string, status: number|null, location: string|null,
 *     address: string|null, failure: string|null }> }}
 */
export function interpretHttp01(measurement, { host, path, ipVersion: family = 4 }) {
  const m = measurement && typeof measurement === 'object' ? measurement : {};
  const probes = arr(m.results).map((test) => {
    const probe = probeSummary(test && test.probe);
    const place = [probe.city, probe.country].filter(Boolean).join(', ') || probe.continent || '';
    return { place, probe, ...http01Outcome(test && test.result, { host, path }) };
  });
  return { ipVersion: family === 6 ? 6 : 4, measurementId: typeof m.id === 'string' ? m.id : null, path, verdict: http01Verdict(probes), probes };
}

/**
 * A name's tested families in plan order ({@link http01Plan}): each one read ({@link interpretHttp01}),
 * and a family planned but never measured — the test stopped before its measurement was created
 * (the quota ran out, the view was left) — as 'untested', so the report does not pass it over.
 * @param {Array<4|6>} planned
 * @param {object[]} read the families read
 * @param {{ path: string }} ctx
 * @returns {object[]}
 */
export function http01Families(planned, read, { path }) {
  const got = arr(read);
  const order = uniq([...arr(planned), ...got.map((f) => f.ipVersion)]);
  return order.map((v) => got.find((f) => f.ipVersion === v) || { ipVersion: v === 6 ? 6 : 4, measurementId: null, path, verdict: 'untested', probes: [] });
}

/**
 * A report with one name's reachability test merged in: its findings and verdict recomputed, the
 * rest untouched (a new report object; the given one is not changed).
 * @param {object} report a {@link checkRenewal} report
 * @param {string} name the NameResult's `name`
 * @param {{ at: Date, families: object[] }|null} test null removes a test
 * @returns {object}
 */
export function applyHttp01(report, name, test) {
  const names = arr(report && report.names).map((r) => {
    if (r.name !== name) return r;
    const next = { ...r, http01: test };
    next.findings = nameFindings(next, { ca: report.ca, challenge: report.challenge });
    next.verdict = nameVerdict(next.findings);
    return next;
  });
  return { ...report, names };
}

/* ------------------------------------------------------------------------ */
/* Summary and exports                                                      */
/* ------------------------------------------------------------------------ */

/**
 * Counts per verdict and the overall headline: 'fail' when a name will fail, 'warnings' when one
 * has warnings, 'ready' when all are ready, 'none' without names.
 * @param {object} report
 * @returns {{ total: number, counts: { ready: number, warnings: number, fail: number }, headline: string, tested: number }}
 */
export function renewalSummary(report) {
  const list = arr(report && report.names);
  const counts = { ready: 0, warnings: 0, fail: 0 };
  for (const r of list) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
  let headline = 'none';
  if (counts.fail) headline = 'fail';
  else if (counts.warnings) headline = 'warnings';
  else if (list.length) headline = 'ready';
  return { total: list.length, counts, headline, tested: list.filter((r) => r.http01).length };
}

/** Columns of the CSV export (one line per name). */
export const RENEWAL_CSV_COLUMNS = Object.freeze(['name', 'verdict', 'caa_at', 'caa_records', 'resolvers', 'acme_challenge', 'dnssec',
  'dns_provider', 'addresses', 'http01', 'errors', 'warnings']);

/**
 * One plain row per name for lib/export.js toCsv (language-neutral: codes and record data).
 * @param {object} report
 * @returns {object[]}
 */
export function renewalRows(report) {
  return arr(report && report.names).map((r) => {
    const ids = (sev) => r.findings.filter((f) => f.severity === sev).map((f) => f.id).join(' ');
    const acme = r.acme ? (r.acme.target ? `${r.acme.state} ${r.acme.target}` : r.acme.state) : '';
    const agree = arr(r.resolvers).filter((x) => x.state === 'ok');
    return {
      name: r.name,
      verdict: r.verdict,
      caa_at: r.caa ? (r.caa.error ? `error: ${r.caa.error}` : r.caa.foundAt || 'none') : '',
      caa_records: r.caa ? r.caa.records.join(' | ') : '',
      resolvers: r.findings.find((f) => f.id === 'resolvers.differ') ? 'differ'
        : r.findings.find((f) => f.id === 'resolvers.servfail') ? 'servfail' : agree.length ? `agree (${agree.length})` : '',
      acme_challenge: acme,
      dnssec: r.dnssec ? r.dnssec.state : '',
      dns_provider: r.dnsHost ? (r.dnsHost.providers.map((p) => p.name).join(', ') || r.dnsHost.ns.join(' ')) : '',
      addresses: r.address && !r.address.error ? [...r.address.ipv4, ...r.address.ipv6].join(' ') : '',
      http01: r.http01 ? r.http01.families.map((f) => `IPv${f.ipVersion} ${f.verdict}`).join(' · ') : '',
      errors: ids('error'),
      warnings: ids('warn')
    };
  });
}

/**
 * The report as plain JSON (`schema: 'domainscope.renewal/1'`): per name its findings, verdict and
 * the DNS data they rest on (parsed CAA objects left out; record data as presentation text).
 * @param {object} report
 * @param {{ app?: string, version?: string|null }} [opts]
 * @returns {object}
 */
export function renewalExport(report, { app = 'DomainScope', version = null } = {}) {
  const iso = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : d || null);
  const summary = renewalSummary(report);
  return {
    schema: 'domainscope.renewal/1',
    app, version,
    startedAt: iso(report.startedAt), finishedAt: iso(report.finishedAt),
    ca: report.ca ? { id: report.ca.id, name: report.ca.name, caa: [...report.ca.domains] } : null,
    challenge: report.challenge,
    resolvers: [...arr(report.resolvers)],
    summary: { total: summary.total, ...summary.counts, headline: summary.headline },
    names: arr(report.names).map((r) => ({
      name: r.name, wildcard: r.wildcard, verdict: r.verdict,
      findings: r.findings.map((f) => ({ id: f.id, severity: f.severity, params: { ...f.params } })),
      caa: r.caa ? { foundAt: r.caa.foundAt, records: [...r.caa.records], chain: r.caa.chain, error: r.caa.error } : null,
      resolvers: arr(r.resolvers).map((x) => ({ id: x.id, state: x.state, foundAt: x.foundAt, records: x.records, rcode: x.rcode, error: x.error })),
      acmeChallenge: r.acme ? { owner: r.acme.owner, state: r.acme.state, target: r.acme.target, acmeDns: r.acme.acmeDns, txt: r.acme.txt, rcode: r.acme.rcode, error: r.acme.error } : null,
      dnssec: r.dnssec ? { state: r.dnssec.state, zone: r.dnssec.zone, ede: r.dnssec.ede, error: r.dnssec.error } : null,
      dnsProvider: r.dnsHost ? {
        zone: r.dnsHost.zone, ns: r.dnsHost.ns, error: r.dnsHost.error,
        providers: r.dnsHost.providers.map((p) => ({ id: p.id, name: p.name, lego: p.lego, acmesh: p.acmesh, certbot: p.certbot ? p.certbot.pkg : null }))
      } : null,
      addresses: r.address ? { status: r.address.status, cnames: r.address.cnames, ipv4: r.address.ipv4, ipv6: r.address.ipv6, provider: r.address.provider || null, error: r.address.error } : null,
      http01: r.http01 ? {
        at: iso(r.http01.at),
        families: r.http01.families.map((f) => ({
          ipVersion: f.ipVersion, measurementId: f.measurementId, path: f.path, verdict: f.verdict,
          probes: f.probes.map((p) => ({ place: p.place, network: p.probe.network, outcome: p.outcome, status: p.status, location: p.location, address: p.address, failure: p.failure }))
        }))
      } : null
    }))
  };
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

// [key, [en, tr]] labels and [key, [en, tr] title, [en, tr] detail] findings, all under `renew.`.
// A text that shows a number is a plural object picked by its `count` param (i18n.js).
const STRINGS = [
  ['v.ready', ['Ready', 'Hazır']],
  ['v.warnings', ['Ready, with warnings', 'Uyarılarla hazır']],
  ['v.fail', ['Will fail', 'Başarısız olacak']],
  ['head.fail', ['At least one name will fail to renew', 'En az bir adın yenilemesi başarısız olacak']],
  ['head.warnings', ['The names should renew, but check the warnings', 'Adlar yenilenebilir, ama uyarılara bakın']],
  ['head.ready', ['Every name is ready to renew', 'Her ad yenilemeye hazır']],
  ['head.none', ['No names were checked', 'Hiçbir ad kontrol edilmedi']],
  ['ch.http-01', ['HTTP-01', 'HTTP-01']],
  ['ch.dns-01', ['DNS-01', 'DNS-01']],
  ['ch.tls-alpn-01', ['TLS-ALPN-01', 'TLS-ALPN-01']],
  ['ch.unknown', ['Not sure', 'Emin değilim']],
  ['area.caa', ['CAA', 'CAA']],
  ['area.resolvers', ['CAA on public resolvers', 'Genel çözümleyicilerde CAA']],
  ['area.wildcard', ['Wildcard', 'Joker ad']],
  ['area.acme', ['_acme-challenge', '_acme-challenge']],
  ['area.provider', ['DNS provider', 'DNS sağlayıcısı']],
  ['area.dnssec', ['DNSSEC', 'DNSSEC']],
  ['area.http', ['HTTP-01 / TLS-ALPN-01 prerequisites', 'HTTP-01 / TLS-ALPN-01 önkoşulları']],
  ['area.http01', ['HTTP-01 reachability', 'HTTP-01 erişilebilirliği']],
  ['o.not-found', ['reaches the web server', 'web sunucusuna ulaşıyor']],
  ['o.redirect', ['redirect CAs follow', 'otoritelerin izlediği yönlendirme']],
  ['o.catch-all', ['answers a made-up token', 'uydurma değeri yanıtlıyor']],
  ['o.forbidden', ['access denied', 'erişim reddedildi']],
  ['o.server-error', ['server error', 'sunucu hatası']],
  ['o.status', ['unexpected status', 'beklenmeyen durum kodu']],
  ['o.redirect-loop', ['redirects to itself', 'kendisine yönlendiriyor']],
  ['o.redirect-port', ['redirect to a port other than 80 / 443', '80 / 443 dışında bir porta yönlendirme']],
  ['o.redirect-ip', ['redirect to an IP address', 'bir IP adresine yönlendirme']],
  ['o.redirect-path', ['redirect that drops the token', 'değeri düşüren yönlendirme']],
  ['o.redirect-scheme', ['redirect to another scheme', 'başka bir şemaya yönlendirme']],
  ['o.redirect-none', ['redirect without a target', 'hedefsiz yönlendirme']],
  ['o.timeout', ['timed out', 'zaman aşımı']],
  ['o.refused', ['connection refused (port 80 closed)', 'bağlantı reddedildi (80 portu kapalı)']],
  ['o.dns', ['the probe could not resolve the name', 'ölçüm noktası adı çözemedi']],
  ['o.unreachable', ['network unreachable', 'ağa ulaşılamıyor']],
  ['o.private', ['resolves to a private address', 'özel bir adrese çözülüyor']],
  ['o.reset', ['connection reset', 'bağlantı sıfırlandı']],
  ['o.unknown', ['failed', 'başarısız']],
  ['o.probe', ['probe problem (not counted)', 'ölçüm noktası sorunu (sayılmadı)']],

  ['f.caa.none', ['No CAA records: any CA may issue', 'CAA kaydı yok: her sertifika otoritesi sertifika verebilir'],
    ['Neither {name} nor its parent domains publish CAA records, so CAA does not stand in the way of the renewal.',
      '{name} ve üst alan adları CAA kaydı yayımlamıyor; CAA yenilemenin önünde bir engel değil.']],
  ['f.caa.open', ['CAA sets no issue rule here', 'CAA burada bir issue kuralı koymuyor'],
    ['The CAA records at {foundAt} hold no issue property that applies to this name, so any CA may issue.',
      '{foundAt} üzerindeki CAA kayıtlarında bu ada uygulanan bir issue özelliği yok; her otorite sertifika verebilir.']],
  ['f.caa.allowed', ['CAA allows {ca}', 'CAA, {ca} otoritesine izin veriyor'],
    ['The {property} records at {foundAt} name {authorized}.', '{foundAt} üzerindeki {property} kayıtlarında adı geçenler: {authorized}.']],
  ['f.caa.restricted', ['CAA allows {ca}, with conditions', 'CAA, {ca} otoritesine koşullu izin veriyor'],
    ['{property} at {foundAt}: {restrictions}. A renewal must meet one of these RFC 8657 conditions.',
      '{foundAt} üzerindeki {property}: {restrictions}. Yenileme bu RFC 8657 koşullarından birini karşılamalı.']],
  ['f.caa.no-ca', ['Choose your CA to check CAA', 'CAA’yı kontrol etmek için otoritenizi seçin'],
    ['The {property} records at {foundAt} allow {authorized}. Choose the CA that renews these names to see whether it may issue.',
      '{foundAt} üzerindeki {property} kayıtlarının izin verdikleri: {authorized}. Sertifika verip veremeyeceğini görmek için bu adları yenileyen otoriteyi seçin.']],
  ['f.caa.denied', ['CAA does not allow {ca}', 'CAA, {ca} otoritesine izin vermiyor'],
    ['Only {authorized} may issue ({property} at {foundAt}). The renewal fails until {foundAt} also publishes 0 {property} "{domain}".',
      'Yalnızca şunlar sertifika verebilir: {authorized} ({foundAt} üzerindeki {property}). {foundAt} için 0 {property} "{domain}" kaydı da yayımlanana kadar yenileme başarısız olur.']],
  ['f.caa.deny-all', ['CAA forbids every CA', 'CAA tüm otoriteleri yasaklıyor'],
    ['The {property} records at {foundAt} authorize no CA (for example {property} ";"), so no renewal can succeed until one is allowed.',
      '{foundAt} üzerindeki {property} kayıtları hiçbir otoriteye izin vermiyor (örneğin {property} ";"); bir otoriteye izin verilene kadar hiçbir yenileme başarılı olamaz.']],
  ['f.caa.critical', ['An unknown critical CAA tag blocks issuance', 'Bilinmeyen kritik bir CAA etiketi sertifika verilmesini engelliyor'],
    ['{foundAt} has a CAA record with the critical flag and a tag CAs do not know ({tags}): every CA must refuse (RFC 8659 §4.1).',
      '{foundAt} üzerinde kritik bayraklı ve otoritelerin tanımadığı bir etiketi olan CAA kaydı var ({tags}): her otorite reddetmek zorunda (RFC 8659 §4.1).']],
  ['f.caa.unusable', ['The CAA values naming {ca} cannot be used', '{ca} otoritesini adlandıran CAA değerleri kullanılamıyor'],
    ['{values}. A malformed or unsatisfiable value authorizes nobody, so the renewal fails.',
      '{values}. Hatalı ya da karşılanamayan bir değer hiçbir otoriteye izin vermez; yenileme başarısız olur.']],
  ['f.caa.method-blocked', ['CAA does not allow {challenge}', 'CAA, {challenge} yöntemine izin vermiyor'],
    ['validationmethods at {foundAt} allows only {methods}: a renewal that validates with {challenge} fails.',
      '{foundAt} üzerindeki validationmethods yalnızca şunlara izin veriyor: {methods}. {challenge} ile doğrulanan bir yenileme başarısız olur.']],
  ['f.caa.method-check', ['CAA allows only {methods}', 'CAA yalnızca şunlara izin veriyor: {methods}'],
    ['validationmethods at {foundAt} limits how the CA may validate. Make sure your ACME client uses one of: {methods}.',
      '{foundAt} üzerindeki validationmethods, otoritenin doğrulama yöntemini sınırlıyor. ACME istemcinizin şunlardan birini kullandığından emin olun: {methods}.']],
  ['f.caa.account', ['CAA pins the ACME account', 'CAA, ACME hesabını sabitliyor'],
    ['Only {accounts} may order. A renewal from any other account — a reinstalled client, a new server, another tool — fails.',
      'Yalnızca şu hesaplar sipariş verebilir: {accounts}. Başka bir hesaptan — yeniden kurulmuş bir istemci, yeni bir sunucu, başka bir araç — yapılan yenileme başarısız olur.']],
  ['f.caa.cname', ['CAA read through a CNAME', 'CAA bir CNAME üzerinden okundu'],
    ['{from} → {chain}: for {from} the CA reads the CAA records of the alias target (RFC 8659 §3), then goes on with the parents of {name}, not those of the target.',
      '{from} → {chain}: otorite {from} için takma adın hedefindeki CAA kayıtlarını okur (RFC 8659 §3), sonra hedefin değil {name} adının üst alan adlarıyla devam eder.']],
  ['f.caa.servfail', ['CAA lookup fails ({rcode})', 'CAA sorgusu başarısız ({rcode})'],
    ['{error}. A CA must not issue when the CAA lookup fails, so the renewal fails until the name servers answer.',
      '{error}. CAA sorgusu başarısız olduğunda otorite sertifika vermemeli; ad sunucuları yanıt verene kadar yenileme başarısız olur.']],
  ['f.caa.error', ['CAA could not be checked', 'CAA kontrol edilemedi'],
    ['{error}. This was the lookup from this browser; the CA’s own lookup may work. Check again.',
      '{error}. Bu, bu tarayıcıdan yapılan sorguydu; otoritenin kendi sorgusu çalışıyor olabilir. Yeniden kontrol edin.']],

  ['f.resolvers.agree', ['{count} resolvers see the same CAA records', '{count} çözümleyici aynı CAA kayıtlarını görüyor'],
    ['{resolvers} give the same answer, so the CA’s lookups from its other network perspectives should too.',
      '{resolvers} aynı yanıtı veriyor; otoritenin başka ağlardan yaptığı sorgular da aynısını görmeli.']],
  ['f.resolvers.differ', ['Resolvers see different CAA records', 'Çözümleyiciler farklı CAA kayıtları görüyor'],
    ['{count} different answers: each resolver’s is listed below. The CA checks CAA from several networks (multi-perspective validation), so a name server that lags behind or answers differently can make it refuse. Check that every name server of the zone serves the same records, and wait out the TTL after a change.',
      '{count} farklı yanıt: her çözümleyicininki aşağıda. Otorite CAA’yı birkaç ağdan kontrol eder (çok noktalı doğrulama); geride kalan ya da farklı yanıt veren bir ad sunucusu reddetmesine yol açabilir. Alanın tüm ad sunucularının aynı kayıtları sunduğunu kontrol edin ve bir değişiklikten sonra TTL süresi kadar bekleyin.']],
  ['f.resolvers.servfail', ['CAA lookup fails on {resolvers}', 'CAA sorgusu şu çözümleyicilerde başarısız: {resolvers}'],
    ['{rcode}: at least one authoritative name server fails the CAA query (some old servers and appliances mishandle type 257). A CA perspective that reaches it cannot finish the CAA check.',
      '{rcode}: en az bir yetkili ad sunucusu CAA sorgusunda hata veriyor (bazı eski sunucular ve cihazlar 257 türünü doğru işlemez). Ona ulaşan bir otorite noktası CAA kontrolünü bitiremez.']],
  ['f.resolvers.unreachable', ['{resolvers} could not be asked', 'Şu çözümleyiciler sorgulanamadı: {resolvers}'],
    ['No answer reached this browser; the comparison uses the other resolvers.', 'Bu tarayıcıya yanıt ulaşmadı; karşılaştırma diğer çözümleyicilerle yapıldı.']],

  ['f.wildcard.dns01', ['Wildcard: validated with DNS-01', 'Joker: DNS-01 ile doğrulanır'],
    ['*.{base} can only be validated with DNS-01, which is what this renewal uses.', '*.{base} yalnızca DNS-01 ile doğrulanabilir; bu yenileme de onu kullanıyor.']],
  ['f.wildcard.unknown', ['A wildcard needs DNS-01', 'Joker ad DNS-01 gerektirir'],
    ['Only DNS-01 can validate *.{base}: an HTTP-01 or TLS-ALPN-01 renewal of it fails.',
      '*.{base} yalnızca DNS-01 ile doğrulanabilir: HTTP-01 ya da TLS-ALPN-01 ile yapılan yenilemesi başarısız olur.']],
  ['f.wildcard.method', ['{challenge} cannot validate a wildcard', '{challenge} bir joker adı doğrulayamaz'],
    ['CAs validate *.{base} with DNS-01 only (Baseline Requirements §3.2.2.4). Switch this renewal to DNS-01.',
      'Otoriteler *.{base} adını yalnızca DNS-01 ile doğrular (Baseline Requirements §3.2.2.4). Bu yenilemeyi DNS-01’e geçirin.']],

  ['f.acme.none', ['Nothing at {owner}', '{owner} altında kayıt yok'],
    ['Normal: a DNS-01 client adds the TXT record when it validates and removes it afterwards.',
      'Normal: DNS-01 istemcisi TXT kaydını doğrularken ekler, sonra kaldırır.']],
  ['f.acme.leftover', [{ one: '{count} TXT record left at {owner}', other: '{count} TXT records left at {owner}' }, '{owner} altında {count} TXT kaydı kalmış'],
    ['{values}. Old validation tokens: the client’s clean-up did not run. They do not block a renewal, but remove them.',
      '{values}. Eski doğrulama değerleri: istemcinin temizliği çalışmamış. Yenilemeyi engellemezler ama kaldırın.']],
  ['f.acme.cname', ['{owner} is delegated to {target}', '{owner}, {target} adına devredilmiş'],
    ['CNAME delegation (DNS-01 alias mode): the CA follows it and reads the TXT record at {target}, so your client must create it there. lego follows the CNAME by itself; acme.sh needs --challenge-alias.',
      'CNAME ile devir (DNS-01 takma ad modu): otorite onu izler ve TXT kaydını {target} üzerinde okur; istemciniz kaydı orada oluşturmalı. lego CNAME’i kendisi izler; acme.sh için --challenge-alias gerekir.']],
  ['f.acme.acme-dns', ['{owner} is delegated to acme-dns', '{owner}, acme-dns’e devredilmiş'],
    ['{target} is an acme-dns registration: the client updates it through the acme-dns API (lego --dns acme-dns, acme.sh --dns dns_acmedns). Keep that registration’s credentials with the renewal.',
      '{target} bir acme-dns kaydı: istemci onu acme-dns API’si üzerinden günceller (lego --dns acme-dns, acme.sh --dns dns_acmedns). O kaydın kimlik bilgilerini yenilemeyle birlikte saklayın.']],
  ['f.acme.dangling', ['{owner} points to a name that does not exist', '{owner} var olmayan bir ada işaret ediyor'],
    ['{owner} → {target} (NXDOMAIN). A DNS-01 renewal fails, and whoever can create {target} can pass DNS-01 validation for this name. Remove the CNAME or restore its target.',
      '{owner} → {target} (NXDOMAIN). DNS-01 ile yenileme başarısız olur ve {target} adını oluşturabilen herkes bu ad için DNS-01 doğrulamasını geçebilir. CNAME’i kaldırın ya da hedefini geri getirin.']],
  ['f.acme.servfail', ['{owner} lookup fails ({rcode})', '{owner} sorgusu başarısız ({rcode})'],
    ['The CA cannot read the DNS-01 record here (a broken delegation target or name server), so a DNS-01 renewal fails.',
      'Otorite DNS-01 kaydını burada okuyamaz (bozuk bir devir hedefi ya da ad sunucusu); DNS-01 ile yenileme başarısız olur.']],
  ['f.acme.bogus', ['{owner} fails DNSSEC validation', '{owner} DNSSEC doğrulamasından geçemiyor'],
    ['Validating resolvers answer SERVFAIL, although the name answers with checking disabled: the CA cannot read the DNS-01 record. {ede}',
      'Doğrulama yapan çözümleyiciler SERVFAIL veriyor, oysa ad doğrulama kapalıyken yanıt veriyor: otorite DNS-01 kaydını okuyamaz. {ede}']],
  ['f.acme.error', ['{owner} could not be checked', '{owner} kontrol edilemedi'],
    ['{error}. Check again.', '{error}. Yeniden kontrol edin.']],

  ['f.provider.known', ['DNS-01 at {provider}', 'DNS-01: {provider}'],
    ['{zone} is served by {provider}: {plugins}.', '{zone} alanını {provider} barındırıyor: {plugins}.']],
  ['f.provider.no-api', ['{provider} has no DNS-01 plugin', '{provider} için DNS-01 eklentisi yok'],
    ['lego, acme.sh and certbot have no plugin for {provider}, so a DNS-01 client cannot create the record in {zone} by itself. Delegate _acme-challenge with a CNAME to a zone they can update (acme-dns, or a zone at a provider with an API), or renew with HTTP-01 (not for a wildcard).',
      'lego, acme.sh ve certbot’un {provider} için eklentisi yok; DNS-01 istemcisi {zone} alanında kaydı kendisi oluşturamaz. _acme-challenge adını bir CNAME ile güncelleyebildikleri bir alana devredin (acme-dns ya da API’si olan bir sağlayıcıdaki bir alan) veya HTTP-01 ile yenileyin (joker ad için olmaz).']],
  ['f.provider.target-no-api', ['{provider} has no DNS-01 plugin', '{provider} için DNS-01 eklentisi yok'],
    ['_acme-challenge is delegated to {zone}, which {provider} serves: lego, acme.sh and certbot have no plugin for it, so a DNS-01 client cannot create the record there by itself. Point the CNAME at a zone they can update (acme-dns, or a zone at a provider with an API).',
      '_acme-challenge, {provider} tarafından barındırılan {zone} alanına devredilmiş: lego, acme.sh ve certbot’un bu sağlayıcı için eklentisi yok; DNS-01 istemcisi kaydı orada kendisi oluşturamaz. CNAME’i güncelleyebildikleri bir alana (acme-dns ya da API’si olan bir sağlayıcıdaki bir alan) yönlendirin.']],
  ['f.provider.multiple', ['{zone} is served by several providers', '{zone} birden fazla sağlayıcıda barındırılıyor'],
    ['{providers}: a DNS-01 record must be published at each of them, or a CA perspective that asks the other provider’s servers fails. Update all of them, or delegate _acme-challenge to one zone.',
      '{providers}: DNS-01 kaydı her birinde yayımlanmalı; yoksa diğer sağlayıcının sunucularına soran bir otorite noktası başarısız olur. Hepsini güncelleyin ya da _acme-challenge adını tek bir alana devredin.']],
  ['f.provider.unknown', ['DNS provider not recognised', 'DNS sağlayıcısı tanınmadı'],
    ['Name servers of {zone}: {ns}. Look the provider up in lego’s, acme.sh’s or certbot’s list of DNS providers; for a name server of your own, RFC 2136 (nsupdate) works with all three.',
      '{zone} ad sunucuları: {ns}. Sağlayıcıyı lego, acme.sh ya da certbot DNS sağlayıcı listelerinde arayın; kendi ad sunucunuz için RFC 2136 (nsupdate) üçüyle de çalışır.']],
  ['f.provider.error', ['The name servers of {zone} could not be read', '{zone} ad sunucuları okunamadı'],
    ['{error}. Check again.', '{error}. Yeniden kontrol edin.']],

  ['f.dnssec.secure', ['DNSSEC signed and validated', 'DNSSEC imzalı ve doğrulanıyor'],
    ['Answers from {zone} validate. Keep them valid: a broken signature (an expired RRSIG, a DS that no longer matches the keys) fails every validation method.',
      '{zone} yanıtları doğrulanıyor. Böyle kalmalı: bozuk bir imza (süresi dolmuş bir RRSIG, anahtarlarla artık eşleşmeyen bir DS) her doğrulama yöntemini başarısız kılar.']],
  ['f.dnssec.unsigned', ['Not signed with DNSSEC', 'DNSSEC ile imzalı değil'],
    ['{zone} is not protected by DNSSEC (or its parent has no DS for it), so there is nothing for validation to break.',
      '{zone} DNSSEC ile korunmuyor (ya da üst alanında onun için DS yok); doğrulamanın bozabileceği bir şey yok.']],
  ['f.dnssec.bogus', ['DNSSEC validation fails (bogus)', 'DNSSEC doğrulaması başarısız (bogus)'],
    ['Validating resolvers — the CA’s included — answer SERVFAIL for {name}, although the name servers answer with checking disabled: the CAA lookup and every validation method fail. {ede}',
      'Doğrulama yapan çözümleyiciler — otoritenin çözümleyicileri de dahil — {name} için SERVFAIL veriyor, oysa ad sunucuları doğrulama kapalıyken yanıt veriyor: CAA sorgusu ve her doğrulama yöntemi başarısız olur. {ede}']],
  ['f.dnssec.servfail', ['Lookups of {name} fail ({rcode})', '{name} sorguları başarısız ({rcode})'],
    ['Not a DNSSEC problem: no answer comes back with checking disabled either. The name servers do not answer, so the CA’s lookups fail too.',
      'Bir DNSSEC sorunu değil: doğrulama kapalıyken de yanıt gelmiyor. Ad sunucuları yanıt vermiyor; otoritenin sorguları da başarısız olur.']],
  ['f.dnssec.unknown', ['DNSSEC state not known', 'DNSSEC durumu bilinmiyor'],
    ['The resolver that answered ({resolver}) is not known to validate DNSSEC.', 'Yanıt veren çözümleyicinin ({resolver}) DNSSEC doğrulaması yaptığı bilinmiyor.']],
  ['f.dnssec.error', ['DNSSEC could not be checked', 'DNSSEC kontrol edilemedi'],
    ['{error}. Check again.', '{error}. Yeniden kontrol edin.']],

  ['f.http.ok', ['{name} resolves to public addresses', '{name} genel adreslere çözülüyor'],
    ['{ips} ({count4} IPv4, {count6} IPv6). The CA connects to these for HTTP-01 (port 80) and TLS-ALPN-01 (port 443).',
      '{ips} ({count4} IPv4, {count6} IPv6). Otorite HTTP-01 (80 portu) ve TLS-ALPN-01 (443 portu) için bunlara bağlanır.']],
  ['f.http.ipv6', ['IPv6 too: both families must serve the challenge', 'IPv6 de var: iki adres ailesi de doğrulamayı sunmalı'],
    ['AAAA {ipv6}: CAs may validate over IPv6, and Let’s Encrypt tries it first. The server behind the AAAA record must answer /.well-known/acme-challenge/ like the IPv4 one; a stale AAAA record is a common cause of failed renewals.',
      'AAAA {ipv6}: otoriteler IPv6 üzerinden doğrulayabilir; Let’s Encrypt önce onu dener. AAAA kaydının arkasındaki sunucu /.well-known/acme-challenge/ yolunu IPv4 sunucusu gibi yanıtlamalı; güncelliğini yitirmiş bir AAAA kaydı başarısız yenilemelerin sık görülen bir nedenidir.']],
  ['f.http.cdn', ['Behind {provider}', '{provider} arkasında'],
    ['HTTP-01 reaches your server through the CDN only if the CDN passes /.well-known/acme-challenge/ over plain HTTP to the origin (or answers it itself).',
      'HTTP-01 sunucunuza CDN üzerinden ancak CDN /.well-known/acme-challenge/ yolunu düz HTTP ile kaynağa iletirse (ya da kendisi yanıtlarsa) ulaşır.']],
  ['f.http.alpn-cdn', ['TLS-ALPN-01 cannot pass {provider}', 'TLS-ALPN-01, {provider} üzerinden geçemez'],
    ['The CDN terminates TLS, so the CA’s TLS-ALPN-01 handshake never reaches your server. Use HTTP-01 or DNS-01 for this name.',
      'CDN TLS bağlantısını kendisi sonlandırır; otoritenin TLS-ALPN-01 el sıkışması sunucunuza hiç ulaşmaz. Bu ad için HTTP-01 ya da DNS-01 kullanın.']],
  ['f.http.private', ['Only private addresses', 'Yalnızca özel adresler'],
    ['{name} resolves to {ips}, which a CA on the internet cannot reach: HTTP-01 and TLS-ALPN-01 fail. Use DNS-01 for an internal name.',
      '{name} şu adreslere çözülüyor: {ips}. İnternetteki bir otorite bunlara ulaşamaz: HTTP-01 ve TLS-ALPN-01 başarısız olur. İç ağdaki bir ad için DNS-01 kullanın.']],
  ['f.http.private-some', ['A private address next to public ones', 'Genel adreslerin yanında özel bir adres'],
    ['{ips}: a CA that picks this address cannot connect. Remove it from the public DNS.',
      '{ips}: bu adresi seçen bir otorite bağlanamaz. Onu genel DNS’ten kaldırın.']],
  ['f.http.none', ['{name} has no A or AAAA record', '{name} için A ya da AAAA kaydı yok'],
    ['HTTP-01 and TLS-ALPN-01 need an address to connect to; DNS-01 does not.', 'HTTP-01 ve TLS-ALPN-01 bağlanacak bir adres ister; DNS-01 istemez.']],
  ['f.http.nxdomain', ['{name} does not exist', '{name} diye bir ad yok'],
    ['NXDOMAIN: HTTP-01 and TLS-ALPN-01 need the name to resolve; DNS-01 needs only the _acme-challenge record.',
      'NXDOMAIN: HTTP-01 ve TLS-ALPN-01 için adın çözülmesi gerekir; DNS-01 yalnızca _acme-challenge kaydını ister.']],
  ['f.http.dangling', ['{name} is a CNAME to a name without addresses', '{name}, adresi olmayan bir ada CNAME'],
    ['{name} → {chain} ({rcode}): HTTP-01 and TLS-ALPN-01 fail until the target resolves.',
      '{name} → {chain} ({rcode}): hedef çözülene kadar HTTP-01 ve TLS-ALPN-01 başarısız olur.']],
  ['f.http.error', ['The addresses of {name} could not be read', '{name} adresleri okunamadı'],
    ['{error}. Check again.', '{error}. Yeniden kontrol edin.']],

  ['f.http01.ok', ['HTTP-01 path reachable over {family}', 'HTTP-01 yoluna {family} üzerinden erişiliyor'],
    [{ one: '{count} probe ({places}) reached the web server: {answers}. A 404 for the made-up token is the expected answer; your ACME client serves the real one there.',
      other: '{count} probes ({places}) reached the web server: {answers}. A 404 for the made-up token is the expected answer; your ACME client serves the real one there.' },
    '{count} ölçüm noktası ({places}) web sunucusuna ulaştı: {answers}. Uydurma değer için 404 beklenen yanıttır; gerçek değeri ACME istemciniz orada sunar.']],
  ['f.http01.redirect', ['HTTP-01 path redirects, over {family}', 'HTTP-01 yolu {family} üzerinden yönlendiriliyor'],
    ['{answers} to {location}. CAs follow it (to port 80 or 443, never to an IP address) and accept any certificate on an HTTPS target, so the site there must serve the token.',
      '{answers}, hedef: {location}. Otoriteler yönlendirmeyi izler (80 ya da 443 portuna, hiçbir zaman bir IP adresine değil) ve HTTPS hedefte her sertifikayı kabul eder; oradaki site değeri sunmalı.']],
  ['f.http01.partial', ['HTTP-01 path reachable from some regions only ({family})', 'HTTP-01 yoluna yalnızca bazı bölgelerden erişiliyor ({family})'],
    ['Failed from {places}: {outcomes}. The CA validates from several regions (multi-perspective validation) and accepts at most one that fails (two when it uses six or more): a geo-block, a firewall rule or a regional outage can fail the renewal.',
      'Başarısız olduğu yerler: {places} ({outcomes}). Otorite birkaç bölgeden doğrular (çok noktalı doğrulama) ve en fazla birinin (altı ya da daha fazla bölge kullanıyorsa ikisinin) başarısız olmasını kabul eder: bir coğrafi engel, bir güvenlik duvarı kuralı ya da bölgesel bir kesinti yenilemeyi başarısız kılabilir.']],
  ['f.http01.failed', ['HTTP-01 path not reachable over {family}', 'HTTP-01 yoluna {family} üzerinden erişilemiyor'],
    ['The probes got: {outcomes}. The CA would get the same, so an HTTP-01 renewal fails.', 'Ölçüm noktalarının aldığı: {outcomes}. Otorite de aynısını alır; HTTP-01 ile yenileme başarısız olur.']],
  ['f.http01.catch-all', ['{answers} for a token that does not exist ({family})', 'Var olmayan bir değer için {answers} yanıtı ({family})'],
    ['Something answers every path under /.well-known/acme-challenge/. Make sure the file your ACME client writes wins over this catch-all (a single-page app, a rewrite rule).',
      '/.well-known/acme-challenge/ altındaki her yolu bir şey yanıtlıyor. ACME istemcinizin yazdığı dosyanın bu genel yanıta (tek sayfalı bir uygulama, bir yeniden yazma kuralı) baskın geldiğinden emin olun.']],
  ['f.http01.inconclusive', ['HTTP-01 test inconclusive ({family})', 'HTTP-01 testi sonuçsuz ({family})'],
    ['The probes failed on their side ({answers}). Test again.', 'Ölçüm noktaları kendi taraflarında başarısız oldu ({answers}). Yeniden test edin.']],
  ['f.http01.untested', ['{family} not tested', '{family} test edilmedi'],
    ['The test stopped before its {family} measurement was created, so nothing is known about {name} over {family}. Test again.',
      'Test, {family} ölçümü oluşturulmadan durdu; {name} adının {family} üzerinden erişilebilirliği bilinmiyor. Yeniden test edin.']]
];

function buildStrings(lang) {
  const out = {};
  for (const [key, title, detail] of STRINGS) {
    if (detail) {
      out[`renew.${key}.title`] = title[lang];
      out[`renew.${key}.detail`] = detail[lang];
    } else {
      out[`renew.${key}`] = title[lang];
    }
  }
  return out;
}

/**
 * English and Turkish texts: `renew.f.<id>.title` / `.detail` for every {@link RENEWAL_FINDINGS}
 * id, `renew.o.<outcome>` for every {@link HTTP01_OUTCOMES} code, `renew.v.<verdict>`,
 * `renew.head.<headline>`, `renew.ch.<challenge>` and `renew.area.<area>`. Placeholders:
 * `{param}`; a text that shows a number is a plural object `{ one, other }` (acme.leftover,
 * http01.ok).
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const RENEWAL_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
