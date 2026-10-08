/**
 * egress.js — the registry of every third party this page may contact, what kind of data each
 * one receives, and the ledger rows of a page session (About › What this page sent).
 *
 * The ledger shows what was measured (lib/egresslog.js through ui/egress-meter.js); this module
 * says what each host is and what it got. The kinds are per endpoint where one service has
 * several (crt.sh receives domain names from a search, a serial number from the Certificate
 * view's lookup and a public-key hash from the key continuity check), so a row says what this
 * session really sent, not everything the service could get. Where the URL cannot tell (one
 * Globalping endpoint takes an address check and a host-name check alike), the sending code's
 * note does (lib/egresslog.js noteRequest).
 *
 * The registry must name every endpoint the code can call: tests/js/egress.test.js scans the
 * sources for network call sites and URL literals and fails on one this registry does not
 * classify, so a new endpoint cannot reach users without a line here. A host the page contacted
 * that is not in the registry (a browser extension's request, or a bug) is still listed, marked
 * as unknown.
 *
 * DOM-free, no I/O.
 */

import { RESOLVERS, ECS_RESOLVERS } from './resolvers.js';
import { requestSignature, requestCount } from './egresslog.js';

/**
 * What a request can carry, in the order the ledger lists them:
 * - appFiles: the app's own files from this site (scripts, styles, wordlists, the sample
 *   certificate) — nothing the user typed;
 * - nothing: a public list or a quota read (the IANA RDAP bootstrap, Globalping's free quota);
 * - dnsQuestions: DNS names and record types (a DoH question, or one a probe asks: Globalping's
 *   DNS check of Zone File › New name servers);
 * - nameServers: the name servers such a probe asks, by host name or address;
 * - domains: domain and host names searched or looked up;
 * - hostnames: host names a check from the internet connects to (Globalping: Domain Health's
 *   MTA-STS policy, Renewal readiness's HTTP-01 test);
 * - ipNamePairs: public IP address, host name and port together (Globalping: SSL Targets › Verify,
 *   Retire an IP › Compare the old and the new server, which also sends the path);
 * - ipAddresses: IP addresses and networks;
 * - asNumbers: AS numbers;
 * - certSerial: a certificate's serial number;
 * - keyHash: the SHA-256 of a certificate's public key;
 * - measurementIds: ids the service gave out, sent back to read the results;
 * - apiToken: the user's own API token for that service, in a request header (Zone File › Fetch
 *   from deSEC / DigitalOcean: for one fetch, never stored) or in the query (IP Intel › Domains on
 *   this IP: Shodan's and WhoisXML's key, for one request per address, never stored).
 */
export const DATA_KINDS = Object.freeze([
  'appFiles', 'nothing', 'dnsQuestions', 'nameServers', 'domains', 'hostnames', 'ipNamePairs', 'ipAddresses', 'asNumbers', 'certSerial',
  'keyHash', 'measurementIds', 'apiToken'
]);

/** What a service is for (the ledger's second line). `dnsHosting`: the user's own DNS provider. */
export const EGRESS_ROLES = Object.freeze(['site', 'dns', 'ct', 'passive', 'ip', 'registration', 'probes', 'dnsHosting', 'ca']);

/**
 * What this page never sends anywhere, whatever the user does (About › What this page sent). The
 * texts (about.js `egress.never.<id>`) say the exceptions each one has.
 */
export const NEVER_SENT = Object.freeze(['certificates', 'keys', 'zone', 'inventory', 'workspace', 'tracking']);

/**
 * @typedef {object} EgressEndpoint
 * @property {string} id
 * @property {string[]} sends {@link DATA_KINDS}
 * @property {string} [path] the signature path it matches: segments equal, '*' any one segment,
 *   '**' any run of segments (lib/egresslog.js requestSignature)
 * @property {string} [param] a query parameter name the request carries
 * @property {Record<string, string[]>} [notes] what a request carried by the note its sender gave
 *   (lib/egresslog.js noteRequest); `sends` holds for a request without one of these notes
 */

/**
 * @typedef {object} EgressService
 * @property {string} id
 * @property {string} name shown as it is (a proper name)
 * @property {string} role {@link EGRESS_ROLES}
 * @property {string[]} hosts exact host names
 * @property {EgressEndpoint[]} endpoints first match wins; one without `path` / `param` matches any request
 * @property {string} [noteHost] also any other https host whose requests the code noted with this word
 *   (lib/rdap.js notes each registry server it asks, one the IANA bootstrap named or rdap.org redirected to)
 */

const ep = (id, sends, { notes, ...match } = {}) => Object.freeze({
  id, sends: Object.freeze([...sends]), ...match,
  ...(notes ? { notes: Object.freeze(Object.fromEntries(Object.entries(notes).map(([n, k]) => [n, Object.freeze([...k])]))) } : {})
});
const service = (s) => Object.freeze({ ...s, hosts: Object.freeze([...s.hosts]), endpoints: Object.freeze([...s.endpoints]) });

/** Host name of a URL (lower case), or null. */
function hostOf(url) {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Every third-party service, in the order the ledger lists them. DNS-over-HTTPS takes its hosts
 * from lib/resolvers.js (the general resolvers and the ones asked only for a location, AliDNS's JSON
 * form included), so a resolver added there is covered here at once.
 * @type {ReadonlyArray<EgressService>}
 */
export const EGRESS_SERVICES = Object.freeze([
  service({
    id: 'doh', name: 'DNS-over-HTTPS', role: 'dns',
    hosts: [...new Set([...RESOLVERS, ...ECS_RESOLVERS].map((r) => hostOf(r.url)).filter(Boolean))],
    endpoints: [ep('query', ['dnsQuestions'])]
  }),
  service({
    id: 'crtsh', name: 'crt.sh', role: 'ct', hosts: ['crt.sh'],
    endpoints: [
      ep('key', ['keyHash'], { param: 'spkisha256' }),
      ep('serial', ['certSerial'], { param: 'serial' }),
      ep('search', ['domains'], { param: 'q' })
    ]
  }),
  service({
    id: 'certspotter', name: 'Cert Spotter', role: 'ct', hosts: ['api.certspotter.com'],
    endpoints: [ep('issuances', ['domains'], { path: '/*/issuances' })]
  }),
  // Certificate › Transparency (lib/sct.js): Google's CT log list, the same file for everyone, read
  // when the tab first opens; nothing about the certificate is sent.
  service({ id: 'ctloglist', name: 'Google CT log list', role: 'ct', hosts: ['www.gstatic.com'], endpoints: [ep('log-list', ['nothing'], { path: '/ct/**' })] }),
  service({
    id: 'hackertarget', name: 'HackerTarget', role: 'passive', hosts: ['api.hackertarget.com'],
    endpoints: [
      ep('hostsearch', ['domains'], { path: '/hostsearch/' }),
      ep('reverseip', ['ipAddresses'], { path: '/reverseiplookup/' })
    ]
  }),
  service({ id: 'anubis', name: 'Anubis', role: 'passive', hosts: ['anubisdb.com'], endpoints: [ep('subdomains', ['domains'], { path: '/anubis/subdomains/*' })] }),
  service({
    id: 'otx', name: 'AlienVault OTX', role: 'passive', hosts: ['otx.alienvault.com'],
    endpoints: [
      ep('passive-dns', ['domains'], { path: '/api/*/indicators/domain/*/passive_dns' }),
      // IP Intel › Domains on this IP (lib/reverseip.js): /api/v1/indicators/IPv4|IPv6/<address>/passive_dns
      ep('address-passive-dns', ['ipAddresses'], { path: '/api/*/indicators/*/*/passive_dns' })
    ]
  }),
  service({
    id: 'thc', name: 'ip.thc.org', role: 'passive', hosts: ['ip.thc.org'],
    endpoints: [
      ep('subdomains', ['domains'], { path: '/api/*/lookup/subdomains' }),
      ep('reverseip', ['ipAddresses'], { path: '/api/*/lookup' })
    ]
  }),
  // IP Intel › Domains on this IP (lib/reverseip.js), one address per request and only on a click:
  // Robtex's free passive DNS, Shodan InternetDB (no key), and with the key the user types there
  // (in the query, for that one request: never stored) Shodan's host lookup and WhoisXML's reverse IP.
  service({ id: 'robtex', name: 'Robtex', role: 'passive', hosts: ['freeapi.robtex.com'], endpoints: [ep('reverse', ['ipAddresses'], { path: '/pdns/reverse/*' })] }),
  service({ id: 'internetdb', name: 'Shodan InternetDB', role: 'ip', hosts: ['internetdb.shodan.io'], endpoints: [ep('address', ['ipAddresses'], { path: '/*' })] }),
  service({ id: 'shodan', name: 'Shodan', role: 'ip', hosts: ['api.shodan.io'], endpoints: [ep('host', ['ipAddresses', 'apiToken'], { path: '/shodan/host/*' })] }),
  service({
    id: 'whoisxml', name: 'WhoisXML API', role: 'passive', hosts: ['reverse-ip.whoisxmlapi.com'],
    endpoints: [ep('reverse-ip', ['ipAddresses', 'apiToken'], { path: '/api/*', param: 'ip' })]
  }),
  service({
    id: 'ripestat', name: 'RIPEstat', role: 'ip', hosts: ['stat.ripe.net'],
    // Each data call by name (lib/ipintel.js, lib/ptrsweep.js), never a catch-all: a new call is an
    // unknown endpoint (listed as everything RIPEstat can get) until it has a line here.
    endpoints: [
      ep('prefixes', ['asNumbers'], { path: '/data/announced-prefixes/*' }),
      ep('prefix-overview', ['ipAddresses'], { path: '/data/prefix-overview/*' }),
      ep('geo', ['ipAddresses'], { path: '/data/maxmind-geo-lite/*' }),
      ep('reverse-dns', ['ipAddresses'], { path: '/data/reverse-dns-ip/*' }),
      // IP Intel › Check routing (lib/ipenrich.js): the address, its announced prefix and origin AS
      ep('network-info', ['ipAddresses'], { path: '/data/network-info/*' }),
      ep('rpki-validation', ['ipAddresses', 'asNumbers'], { path: '/data/rpki-validation/*' }),
      ep('routing-status', ['ipAddresses'], { path: '/data/routing-status/*' }),
      ep('abuse-contact', ['ipAddresses'], { path: '/data/abuse-contact-finder/*' })
    ]
  }),
  // IP Intel › Check routing (lib/ipenrich.js): the origin AS number, paced and once per AS.
  service({ id: 'peeringdb', name: 'PeeringDB', role: 'ip', hosts: ['www.peeringdb.com'], endpoints: [ep('net', ['asNumbers'], { path: '/api/net' })] }),
  // One API, /<address>, with one caller (lib/ipintel.js; the code scan holds it to that).
  service({ id: 'ipwhois', name: 'ipwho.is', role: 'ip', hosts: ['ipwho.is'], endpoints: [ep('address', ['ipAddresses'], { path: '/*' })] }),
  service({ id: 'rdap-bootstrap', name: 'IANA', role: 'registration', hosts: ['data.iana.org'], endpoints: [ep('bootstrap', ['nothing'], { path: '/rdap/*' })] }),
  service({
    // rdap.org (the paced fallback) and the registry server lib/rdap.js RDAP_OVERRIDES names for the
    // TLDs the IANA bootstrap does not list yet (.io, .sh, .ac, .me: the Domain portfolio, any lookup)
    id: 'rdap', name: 'RDAP', role: 'registration', hosts: ['rdap.org', 'rdap.identitydigital.services'], noteHost: 'rdap',
    // RFC 9082 lookup paths under a server's base URL: domain/<name>, ip/<address> or ip/<address>/<length>.
    endpoints: [
      ep('domain', ['domains'], { path: '/**/domain/*' }),
      ep('ip', ['ipAddresses'], { path: '/**/ip/*' }),
      ep('ip-network', ['ipAddresses'], { path: '/**/ip/*/*' })
    ]
  }),
  service({
    id: 'globalping', name: 'Globalping', role: 'probes', hosts: ['api.globalping.io'],
    endpoints: [
      ep('limits', ['nothing'], { path: '/*/limits' }),
      // One endpoint for every check: lib/globalping.js says whether the body sends an address
      // (Verify, the old-versus-new server comparison), a host name alone (MTA-STS, HTTP-01) or a DNS
      // question for a name server (Zone File › New name servers) or for the probes' own resolvers
      // (Global DNS › ISP resolvers); a request without its note may have sent any of them.
      ep('create', ['dnsQuestions', 'nameServers', 'hostnames', 'ipNamePairs'], {
        path: '/*/measurements',
        notes: { 'host-target': ['hostnames'], 'ip-target': ['ipNamePairs'], 'dns-query': ['dnsQuestions', 'nameServers'], 'dns-own': ['dnsQuestions'] }
      }),
      ep('result', ['measurementIds'], { path: '/*/measurements/*' })
    ]
  }),
  // Renewal readiness › Plan (lib/renewalplan.js): the CA's suggested renewal window (ACME ARI,
  // RFC 9773), only after a click; the CertID in the path is the issuer's key identifier and the
  // certificate's serial number.
  service({
    id: 'ari', name: 'Let\'s Encrypt ARI', role: 'ca', hosts: ['acme-v02.api.letsencrypt.org'],
    endpoints: [ep('directory', ['nothing'], { path: '/directory' }), ep('renewal-info', ['certSerial'], { path: '/acme/renewal-info/*' })]
  }),
  // Domain Health › Web (lib/observatory.js): Mozilla's HTTP Observatory scans the site's headers
  // from its servers; one POST per click, the host name in ?host=.
  service({
    id: 'observatory', name: 'Mozilla HTTP Observatory', role: 'probes', hosts: ['observatory-api.mdn.mozilla.net'],
    endpoints: [ep('scan', ['domains'], { path: '/api/*/scan' })]
  }),
  // Zone File › Fetch from deSEC / DigitalOcean (lib/zonefetch.js): the zone name in the path, the
  // user's token in the Authorization header, only after a click.
  service({
    id: 'desec', name: 'deSEC', role: 'dnsHosting', hosts: ['desec.io'],
    endpoints: [ep('rrsets', ['domains', 'apiToken'], { path: '/api/*/domains/*/rrsets/' })]
  }),
  service({
    id: 'digitalocean', name: 'DigitalOcean', role: 'dnsHosting', hosts: ['api.digitalocean.com'],
    endpoints: [ep('records', ['domains', 'apiToken'], { path: '/*/domains/*/records' })]
  })
]);

/** The pseudo-service of the page's own origin (the app's files). */
export const SELF_SERVICE = Object.freeze({
  id: 'self', name: '', role: 'site', hosts: Object.freeze([]), endpoints: Object.freeze([ep('files', ['appFiles'])])
});

const SERVICE_BY_HOST = new Map();
for (const s of EGRESS_SERVICES) for (const host of s.hosts) SERVICE_BY_HOST.set(host, s);
const SERVICE_BY_ID = new Map(EGRESS_SERVICES.map((s) => [s.id, s]));
const RESOLVER_BY_HOST = new Map([...RESOLVERS, ...ECS_RESOLVERS].map((r) => [hostOf(r.url), r]));

/**
 * A registry service by id.
 * @param {string} id
 * @returns {EgressService|null}
 */
export function getEgressService(id) {
  return id === 'self' ? SELF_SERVICE : SERVICE_BY_ID.get(id) || null;
}

/** Does a signature path match an endpoint's path pattern ('*' one segment, '**' any run of them)? */
function pathMatches(pattern, path) {
  const want = String(pattern).split('/').slice(1);
  const have = String(path).split('/').slice(1);
  const walk = (i, j) => {
    if (i === want.length) return j === have.length;
    if (want[i] === '**') {
      for (let k = j; k <= have.length; k += 1) if (walk(i + 1, k)) return true;
      return false;
    }
    if (j === have.length) return false;
    return (want[i] === '*' || want[i] === have[j]) && walk(i + 1, j + 1);
  };
  return walk(0, 0);
}

function endpointMatches(endpoint, sig) {
  if (endpoint.param && !sig.query.split('&').includes(endpoint.param)) return false;
  if (endpoint.path && !pathMatches(endpoint.path, sig.path)) return false;
  return true;
}

/**
 * @typedef {object} EgressClass
 * @property {EgressService|null} service null: a host the registry does not know
 * @property {EgressEndpoint|null} endpoint null: a request of a known service the registry has no endpoint for
 * @property {string[]} sends what it carried ({@link DATA_KINDS}); for an unknown endpoint every
 *   kind the service can receive, for an unknown host []
 * @property {string|null} label the resolver's name for a DoH host, else null
 */

/**
 * What a request of an endpoint carried: by the notes its sender gave, where the endpoint reads
 * them, else everything the endpoint can carry.
 * @param {EgressEndpoint} endpoint
 * @param {string[]} notes
 * @returns {string[]} {@link DATA_KINDS} order
 */
function endpointSends(endpoint, notes) {
  const byNote = endpoint.notes ? notes.filter((n) => Object.hasOwn(endpoint.notes, n)).flatMap((n) => endpoint.notes[n]) : [];
  const kinds = new Set(byNote.length ? byNote : endpoint.sends);
  return DATA_KINDS.filter((k) => kinds.has(k));
}

/**
 * Classify one request signature (lib/egresslog.js) against the registry.
 * @param {{ origin: string, host: string, path: string, query: string, notes?: string[] }} sig
 *   notes: what the sending code said about it (lib/egresslog.js noteRequest)
 * @param {{ origin?: string|null }} [opts] origin: the page's own origin (its requests are the app's files)
 * @returns {EgressClass}
 */
export function classifySignature(sig, { origin = null } = {}) {
  if (origin && sig.origin === origin) {
    return { service: SELF_SERVICE, endpoint: SELF_SERVICE.endpoints[0], sends: ['appFiles'], label: null };
  }
  const host = String(sig.host || '').toLowerCase();
  const notes = Array.isArray(sig.notes) ? sig.notes : [];
  let svc = SERVICE_BY_HOST.get(host) || null;
  if (!svc || sig.origin.startsWith('http:')) {
    // A plain-http request is never one the registry names; a host the code noted (an RDAP server) needs https too.
    svc = sig.origin.startsWith('https:') ? EGRESS_SERVICES.find((s) => s.noteHost && notes.includes(s.noteHost)) || null : null;
  }
  if (!svc) return { service: null, endpoint: null, sends: [], label: null };
  const endpoint = svc.endpoints.find((e) => endpointMatches(e, sig)) || null;
  const sends = endpoint ? endpointSends(endpoint, notes) : serviceSends(svc);
  const resolver = svc.id === 'doh' ? RESOLVER_BY_HOST.get(host) : null;
  return { service: svc, endpoint, sends, label: resolver ? resolver.name : null };
}

/**
 * Classify a request URL (the unit tests' and the code scan's entry point).
 * @param {string} url
 * @param {{ origin?: string|null, notes?: string[] }} [opts] notes: as the sending code would give them
 * @returns {EgressClass|null} null for a URL that is not http(s)
 */
export function classifyUrl(url, { notes = [], ...opts } = {}) {
  const sig = requestSignature(url);
  return sig ? classifySignature({ ...sig, notes }, opts) : null;
}

/**
 * Every kind of data a service can receive, in {@link DATA_KINDS} order.
 * @param {EgressService} svc
 * @returns {string[]}
 */
export function serviceSends(svc) {
  const all = new Set((svc && svc.endpoints ? svc.endpoints : []).flatMap((e) => e.sends));
  return DATA_KINDS.filter((k) => all.has(k));
}

/**
 * @typedef {object} LedgerRow one host this page contacted
 * @property {string} host
 * @property {string} origin
 * @property {'self'|'service'|'unknown'} kind
 * @property {string|null} serviceId
 * @property {string} name the service's name (the resolver's for a DoH host; '' for the page's own origin and an unknown host)
 * @property {string|null} role {@link EGRESS_ROLES}
 * @property {number} requests {@link requestCount} summed over its signatures
 * @property {number} fetch
 * @property {number} resource
 * @property {number} redirect
 * @property {number} failed
 * @property {string[]} sends what this session sent it ({@link DATA_KINDS} order)
 * @property {Array<{ id: string|null, requests: number, sends: string[] }>} endpoints most requests first
 * @property {number} first
 * @property {number} last
 */

/**
 * The ledger: one row per host of a snapshot (lib/egresslog.js), classified against the registry.
 * Order: hosts the registry does not know first (they need a look), then the services in
 * registry order (a service's hosts by requests, most first), then the page's own origin.
 * @param {{ entries: object[] }} snapshot
 * @param {{ origin?: string|null }} [opts] the page's own origin
 * @returns {LedgerRow[]}
 */
export function ledgerRows(snapshot, { origin = null } = {}) {
  const byOrigin = new Map();
  for (const e of (snapshot && Array.isArray(snapshot.entries)) ? snapshot.entries : []) {
    if (!requestCount(e) && !(e.failed > 0)) continue;
    if (!byOrigin.has(e.origin)) byOrigin.set(e.origin, []);
    byOrigin.get(e.origin).push(e);
  }
  const rows = [];
  for (const [entryOrigin, list] of byOrigin) {
    const classes = list.map((e) => classifySignature(e, { origin }));
    // A host is one service only when every request of it is: an unregistered host the code
    // noted as an RDAP server once, with other requests it did not note, stays unknown.
    const svc = classes[0].service;
    const same = !!svc && classes.every((c) => c.service === svc);
    const kind = !same ? 'unknown' : svc === SELF_SERVICE ? 'self' : 'service';
    const row = {
      host: list[0].host,
      origin: entryOrigin,
      kind,
      serviceId: kind === 'unknown' ? null : svc.id,
      name: kind === 'service' ? classes[0].label || svc.name : '',
      role: kind === 'unknown' ? null : svc.role,
      requests: 0,
      fetch: 0,
      resource: 0,
      redirect: 0,
      failed: 0,
      sends: new Set(),
      endpoints: new Map(),
      first: Infinity,
      last: -Infinity
    };
    list.forEach((e, i) => {
      const n = requestCount(e);
      row.requests += n;
      row.fetch += e.fetch || 0;
      row.resource += e.resource || 0;
      row.redirect += e.redirect || 0;
      row.failed += e.failed || 0;
      row.first = Math.min(row.first, e.first);
      row.last = Math.max(row.last, e.last);
      const cls = classes[i];
      const sends = kind === 'unknown' ? [] : cls.sends;
      for (const k of sends) row.sends.add(k);
      const epId = kind === 'unknown' || !cls.endpoint ? null : cls.endpoint.id;
      // One endpoint can come from several signatures (the RDAP servers' lookup paths): their kinds add up.
      const prev = row.endpoints.get(epId) || { id: epId, requests: 0, sends: new Set() };
      prev.requests += n;
      for (const k of sends) prev.sends.add(k);
      row.endpoints.set(epId, prev);
    });
    rows.push({
      ...row,
      sends: DATA_KINDS.filter((k) => row.sends.has(k)),
      endpoints: [...row.endpoints.values()].map((e) => ({ ...e, sends: DATA_KINDS.filter((k) => e.sends.has(k)) }))
        .sort((a, b) => b.requests - a.requests)
    });
  }
  const order = new Map(EGRESS_SERVICES.map((s, i) => [s.id, i]));
  const rank = (r) => (r.kind === 'unknown' ? -1 : r.kind === 'self' ? EGRESS_SERVICES.length : order.get(r.serviceId));
  return rows.sort((a, b) => rank(a) - rank(b) || b.requests - a.requests || (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));
}

/**
 * Totals of a ledger for its summary line.
 * @param {LedgerRow[]} rows
 * @returns {{ requests: number, services: number, hosts: number, self: number, unknown: number, failed: number }}
 *   requests / hosts / failed: third parties (unknown hosts included); services: distinct registry services
 */
export function ledgerTotals(rows) {
  const out = { requests: 0, services: 0, hosts: 0, self: 0, unknown: 0, failed: 0 };
  const services = new Set();
  for (const r of Array.isArray(rows) ? rows : []) {
    if (r.kind === 'self') {
      out.self += r.requests;
      continue;
    }
    out.requests += r.requests;
    out.hosts += 1;
    out.failed += r.failed;
    if (r.kind === 'unknown') out.unknown += 1;
    else services.add(r.serviceId);
  }
  out.services = services.size;
  return out;
}
