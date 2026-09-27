/**
 * dane.js — the DANE / TLSA renewal guard: will the new certificate break DANE?
 * DOM-free; runs in browsers and Node 22.
 *
 * A TLSA record (RFC 6698) pins a certificate or its public key in DNS. When the certificate
 * (or its key) changes, a record that still pins the old one makes DANE-validating senders
 * queue mail for that host (SMTP, RFC 7672) and DANE-aware clients refuse HTTPS — silently,
 * and only once the new certificate is installed. The safe order (RFC 7671 §8.1, key rollover)
 * is: publish a record for the new certificate next to the old one, wait until every cache has
 * dropped the old record set (2 × TTL here, a margin over one TTL), install, then remove the
 * old record.
 *
 * - {@link certAssociations}: the association data of a certificate for selectors 0 / 1 and
 *   matching types 0 / 1 / 2 (SHA-256 and SHA-512 through WebCrypto, in Node too);
 * - {@link planDane}: which TLSA names to ask for: `_25._tcp.<mx>` for every MX host of the
 *   certificate's registrable domains (the domain itself when it has no MX, RFC 5321 §5.1),
 *   and `_443._tcp.<name>` for its names. Wildcard names are skipped, never mapped to the
 *   apex: `*.example.com` does not cover `example.com`, and a TLSA record lives at a concrete
 *   host name (`_443._tcp.www.example.com`). The caller may add concrete names the certificate
 *   covers (SSL Targets adds the covered hosts its scan found). Deduplicated and capped
 *   ({@link DANE_LIMITS});
 * - {@link checkDane}: the MX and TLSA lookups with the DNSSEC OK bit through the injected
 *   DohClient, and a verdict per endpoint ({@link endpointVerdict}) with the exact records to
 *   publish before installing ({@link suggestRecords});
 * - {@link daneSummary} and {@link daneExportJson} for the views.
 *
 * What the verdicts rely on:
 * - A TLSA record set matches when ANY usable record matches (RFC 6698 §2.1). DANE-EE (3) and
 *   PKIX-EE (1) are compared with the leaf, DANE-TA (2) and PKIX-TA (0) with the other
 *   certificates of the loaded file (the chain).
 * - SMTP ignores the PKIX usages 0 and 1 (RFC 7672 §3.1.3); records with unknown parameters or
 *   a digest of the wrong length are unusable everywhere. Without a usable record, senders
 *   still require TLS but do not authenticate it (RFC 7672 §2.2).
 * - TLSA without DNSSEC is ignored (the AD bit of a validating resolver says so), and senders
 *   look up TLSA only for MX hosts they got from a DNSSEC-validated MX record set
 *   (RFC 7672 §2.2.1).
 * - The TTL to wait is the RRSIG's original TTL when the answer carries one (the DO bit asks
 *   for it), else the TTL the resolver returned, which may already have counted down.
 *
 * Nothing is sent by importing this module. checkDane sends only MX and TLSA queries — names
 * and types, never the certificate — to the resolvers of the client it is given.
 */

import { normalizeHostname, baseDomainsFromNames, certCovers } from './domain.js';
import { followCnames } from './doh.js';
import { getResolver } from './resolvers.js';
import { throwIfAborted } from './util.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies (frozen; the i18n coverage test derives keys from them)      */
/* ------------------------------------------------------------------------ */

/** Certificate usage field (RFC 6698 §2.1.1, RFC 7218 mnemonics). */
export const TLSA_USAGES = Object.freeze({ 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' });
/** Selector field: the full certificate or its SubjectPublicKeyInfo. */
export const TLSA_SELECTORS = Object.freeze({ 0: 'Cert', 1: 'SPKI' });
/** Matching type field: the selected bytes as they are, or their SHA-256 / SHA-512. */
export const TLSA_MATCHING = Object.freeze({ 0: 'Full', 1: 'SHA2-256', 2: 'SHA2-512' });
/** The services checked and their ports. */
export const DANE_PORTS = Object.freeze({ smtp: 25, https: 443 });
/** Endpoint statuses, worst first (`dane.st.<status>`). */
export const DANE_STATUSES = Object.freeze(['danger', 'servfail', 'ta-mismatch', 'ta-unchecked', 'pkix', 'error',
  'insecure', 'not-covered', 'unusable', 'safe', 'none']);
/** Severity of each status (the badge / alert variant). */
export const DANE_SEVERITY = Object.freeze({
  danger: 'error',
  servfail: 'error',
  'ta-mismatch': 'warn',
  'ta-unchecked': 'warn',
  pkix: 'warn',
  error: 'warn',
  insecure: 'info',
  'not-covered': 'info',
  unusable: 'info',
  safe: 'ok',
  none: 'neutral'
});
/** Statuses whose records need the new certificate's record published first (the "publish" list). */
export const DANE_ACTION_STATUSES = Object.freeze(['danger', 'ta-mismatch', 'ta-unchecked', 'pkix']);
/** Why a record is unusable (`dane.issue.<code>`). */
export const TLSA_ISSUES = Object.freeze(['bad-usage', 'bad-selector', 'bad-matching', 'bad-length', 'pkix-smtp']);
/** Per-endpoint notes (`dane.note.<code>`). */
export const DANE_NOTES = Object.freeze(['stale-records', 'spki-match', 'mx-insecure', 'ad-unknown', 'bogus', 'cname',
  'implicit-mx', 'ttl-remaining']);
/** Headline keys of {@link daneSummary} (`dane.head.<key>`). */
export const DANE_HEADLINES = Object.freeze(['danger', 'servfail', 'warn', 'error', 'safe', 'clear', 'unused']);
/** Caps: registrable domains whose MX are read, MX hosts and HTTPS names asked for. */
export const DANE_LIMITS = Object.freeze({ mxDomains: 10, mxHosts: 20, httpsNames: 25 });

/** Digest length (hex characters) per matching type; 0 = any length (the full data). */
const DIGEST_HEX = Object.freeze({ 0: 0, 1: 64, 2: 128 });
const DIGEST_ALG = Object.freeze({ 1: 'SHA-256', 2: 'SHA-512' });

/** Thrown by {@link certAssociations} when the digests cannot be computed. */
export class DaneError extends Error {
  /**
   * @param {'no-crypto'|'bad-input'} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'DaneError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------------ */
/* Association data                                                         */
/* ------------------------------------------------------------------------ */

function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Lowercase hex digits only (presentation data may carry spaces or upper case). */
function normHex(value) {
  return String(value ?? '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

function fieldOk(table, n) {
  return Number.isInteger(n) && Object.prototype.hasOwnProperty.call(table, n);
}

/**
 * @typedef {Readonly<{ 0: Readonly<{ 0: string, 1: string, 2: string }>, 1: Readonly<{ 0: string, 1: string, 2: string }> }>} Associations
 *   association data (lowercase hex) by selector, then matching type: `a[1][1]` is the SHA-256
 *   of the SubjectPublicKeyInfo — the data of a `3 1 1` record
 */

/**
 * The TLSA association data of a certificate for every selector and matching type.
 * @param {{ der: Uint8Array, spkiDer: Uint8Array }} cert a lib/x509.js Certificate
 * @param {{ subtle?: SubtleCrypto|null }} [opts] WebCrypto (default: globalThis.crypto.subtle)
 * @returns {Promise<Associations>}
 * @throws {DaneError} 'no-crypto' without WebCrypto (browsers offer it on HTTPS pages and
 *   localhost only), 'bad-input' without DER bytes
 */
export async function certAssociations(cert, { subtle = globalThis.crypto?.subtle } = {}) {
  if (!cert || !(cert.der instanceof Uint8Array) || !(cert.spkiDer instanceof Uint8Array)) {
    throw new DaneError('bad-input', 'certAssociations: expected a parsed certificate (der and spkiDer bytes)');
  }
  if (!subtle || typeof subtle.digest !== 'function') {
    throw new DaneError('no-crypto', 'WebCrypto (crypto.subtle) is not available: TLSA digests need SHA-256 and SHA-512');
  }
  const digest = async (alg, bytes) => toHex(new Uint8Array(await subtle.digest(alg, bytes)));
  const [c1, c2, s1, s2] = await Promise.all([
    digest(DIGEST_ALG[1], cert.der), digest(DIGEST_ALG[2], cert.der),
    digest(DIGEST_ALG[1], cert.spkiDer), digest(DIGEST_ALG[2], cert.spkiDer)
  ]);
  return Object.freeze({
    0: Object.freeze({ 0: toHex(cert.der), 1: c1, 2: c2 }),
    1: Object.freeze({ 0: toHex(cert.spkiDer), 1: s1, 2: s2 })
  });
}

/**
 * The association data for one selector / matching type, or null.
 * @param {Associations|null} assoc
 * @param {number} selector
 * @param {number} matchingType
 * @returns {string|null}
 */
export function associationData(assoc, selector, matchingType) {
  if (!assoc || !fieldOk(TLSA_SELECTORS, selector) || !fieldOk(TLSA_MATCHING, matchingType)) return null;
  return assoc[selector][matchingType] ?? null;
}

/* ------------------------------------------------------------------------ */
/* Records                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The TLSA owner name of a host and port: `_25._tcp.mx.example.com`.
 * @param {string} host
 * @param {number} [port=25]
 * @returns {string}
 */
export function tlsaOwner(host, port = DANE_PORTS.smtp) {
  return `_${port}._tcp.${host}`;
}

/**
 * One TLSA record in zone-file presentation, ready to paste:
 * `_25._tcp.mx.example.com. IN TLSA 3 1 1 <HEX>` (hex in upper case, as dig prints it).
 * @param {string} owner
 * @param {{ usage: number, selector: number, matchingType: number, data: string }} rec
 * @returns {string}
 */
export function tlsaRecordText(owner, rec) {
  return `${owner}. IN TLSA ${rec.usage} ${rec.selector} ${rec.matchingType} ${normHex(rec.data).toUpperCase()}`;
}

/**
 * Does one TLSA record match the new certificate?
 * @param {{ usage: number, selector: number, matchingType: number, data: string }} rec
 * @param {{ service?: 'smtp'|'https', leaf?: Associations|null, anchors?: Array<{ assoc: Associations }> }} ctx
 *   `anchors`: the other certificates of the loaded file (the chain)
 * @returns {{ usable: boolean, matches: boolean|null, matchedBy: 'leaf'|'chain'|null, anchor: number|null,
 *   issue: string|null }} `matches` is null for a DANE-TA / PKIX-TA record when the file holds no chain
 */
export function matchRecord(rec, { service = 'smtp', leaf = null, anchors = [] } = {}) {
  const out = (usable, matches, matchedBy = null, anchor = null, issue = null) => ({ usable, matches, matchedBy, anchor, issue });
  const { usage, selector, matchingType } = rec || {};
  if (!fieldOk(TLSA_USAGES, usage)) return out(false, false, null, null, 'bad-usage');
  if (!fieldOk(TLSA_SELECTORS, selector)) return out(false, false, null, null, 'bad-selector');
  if (!fieldOk(TLSA_MATCHING, matchingType)) return out(false, false, null, null, 'bad-matching');
  if (service === 'smtp' && usage < 2) return out(false, false, null, null, 'pkix-smtp');
  const data = normHex(rec.data);
  if (!data || (DIGEST_HEX[matchingType] && data.length !== DIGEST_HEX[matchingType])) {
    return out(false, false, null, null, 'bad-length');
  }
  if (usage === 1 || usage === 3) {
    const want = associationData(leaf, selector, matchingType);
    return want !== null && want === data ? out(true, true, 'leaf') : out(true, false);
  }
  const list = Array.isArray(anchors) ? anchors : [];
  if (!list.length) return out(true, null);
  const i = list.findIndex((a) => a && associationData(a.assoc, selector, matchingType) === data);
  return i >= 0 ? out(true, true, 'chain', i) : out(true, false);
}

/**
 * The verdict a TLSA record set gives the new certificate, lookup and DNSSEC aside.
 * @param {Array<{ usage: number, selector: number, matchingType: number, data: string }>} records
 * @param {{ service?: 'smtp'|'https', leaf?: Associations|null, anchors?: Array<{ assoc: Associations }> }} ctx
 * @returns {{ verdict: 'none'|'unusable'|'safe'|'ta-unchecked'|'danger'|'ta-mismatch'|'pkix', records: object[] }}
 *   each record with its {@link matchRecord} fields
 */
export function evaluateRecords(records, ctx = {}) {
  const list = (Array.isArray(records) ? records : []).map((r) => ({ ...r, ...matchRecord(r, ctx) }));
  const usable = list.filter((r) => r.usable);
  let verdict;
  if (!list.length) verdict = 'none';
  else if (!usable.length) verdict = 'unusable';
  else if (usable.some((r) => r.matches === true)) verdict = 'safe';
  // A trust-anchor record that could not be compared (no chain loaded) may still match: not a certain break.
  else if (usable.some((r) => r.matches === null)) verdict = 'ta-unchecked';
  else if (usable.some((r) => r.usage === 3)) verdict = 'danger';
  else if (usable.some((r) => r.usage === 2)) verdict = 'ta-mismatch';
  else verdict = 'pkix';
  return { verdict, records: list };
}

/**
 * The records that would make a failing record set match the new certificate: the same
 * usage, selector and matching type as the published records, with the new data.
 * - DANE-EE / PKIX-EE: the leaf's data;
 * - DANE-TA / PKIX-TA: the data of the certificate that issued the leaf, when the file holds
 *   it; otherwise `3 1 1` of the leaf, which DANE clients accept whatever the chain.
 * @param {string} owner TLSA owner name
 * @param {{ verdict: string, records: object[] }} evaluation {@link evaluateRecords} result
 * @param {{ leaf: Associations, issuer?: Associations|null }} certs
 * @returns {Array<{ owner: string, usage: number, selector: number, matchingType: number, data: string, text: string }>}
 */
export function suggestRecords(owner, evaluation, { leaf, issuer = null }) {
  const verdict = evaluation && evaluation.verdict;
  if (!leaf || !DANE_ACTION_STATUSES.includes(verdict)) return [];
  const usable = evaluation.records.filter((r) => r.usable);
  const wanted = verdict === 'danger' ? usable.filter((r) => r.usage === 3)
    : verdict === 'pkix' ? usable.filter((r) => r.usage < 2)
      : usable.filter((r) => r.usage === 2);
  const out = [];
  const add = (usage, selector, matchingType, assoc) => {
    const data = associationData(assoc, selector, matchingType);
    if (!data) return;
    const rec = { owner, usage, selector, matchingType, data };
    rec.text = tlsaRecordText(owner, rec);
    if (!out.some((x) => x.text === rec.text)) out.push(rec);
  };
  for (const r of wanted) {
    if (r.usage === 1 || r.usage === 3) add(r.usage, r.selector, r.matchingType, leaf);
    else if (issuer) add(r.usage, r.selector, r.matchingType, issuer);
  }
  if (!out.length && verdict !== 'pkix') add(3, 1, 1, leaf);
  return out;
}

/* ------------------------------------------------------------------------ */
/* Lookup interpretation                                                    */
/* ------------------------------------------------------------------------ */

function canonName(name) {
  const s = String(name ?? '').trim().toLowerCase();
  return s.length > 1 && s.endsWith('.') ? s.slice(0, -1) : s;
}

/**
 * Did a validating resolver authenticate the answer? true (AD set), false (AD clear on a
 * resolver known to validate), null (no answer, or a resolver not known to validate).
 * @param {object|null} response DnsResponse
 * @returns {boolean|null}
 */
export function authenticated(response) {
  if (!response || !response.ok) return null;
  if (response.flags && response.flags.ad) return true;
  const r = typeof response.resolver === 'string' ? getResolver(response.resolver) : null;
  return r && r.dnssecValidating ? false : null;
}

/**
 * The TLSA records of an answer at `owner` (or at the end of its CNAME chain), and the TTL to wait.
 * @param {object} response DnsResponse
 * @param {string} owner
 * @returns {{ records: Array<{ usage, selector, matchingType, data, text, ttl }>, target: string, cnames: string[],
 *   ttl: number|null, ttlSource: 'rrsig'|'answer'|null }}
 */
export function tlsaFromAnswer(response, owner) {
  const answers = response && Array.isArray(response.answers) ? response.answers : [];
  const chain = followCnames(answers, owner);
  const target = canonName(chain.target);
  const records = [];
  for (const rr of answers) {
    if (!rr || rr.type !== 'TLSA' || canonName(rr.name) !== target || !rr.data || typeof rr.data !== 'object') continue;
    const rec = {
      usage: rr.data.usage, selector: rr.data.selector, matchingType: rr.data.matchingType,
      data: normHex(rr.data.data), text: rr.text || '', ttl: Number.isFinite(rr.ttl) ? rr.ttl : null
    };
    if (!records.some((x) => x.usage === rec.usage && x.selector === rec.selector && x.matchingType === rec.matchingType && x.data === rec.data)) {
      records.push(rec);
    }
  }
  const sig = answers.find((rr) => rr && rr.type === 'RRSIG' && rr.data && rr.data.typeCovered === 'TLSA'
    && canonName(rr.name) === target && Number.isFinite(rr.data.originalTtl));
  let ttl = null;
  let ttlSource = null;
  if (sig) {
    ttl = sig.data.originalTtl;
    ttlSource = 'rrsig';
  } else {
    const ttls = records.map((r) => r.ttl).filter((x) => x !== null);
    if (ttls.length) {
      ttl = Math.max(...ttls);
      ttlSource = 'answer';
    }
  }
  return { records, target, cnames: chain.cnames, ttl, ttlSource };
}

/**
 * @typedef {object} DaneEndpoint
 * @property {string} key `<port>|<host>`
 * @property {'smtp'|'https'} service
 * @property {number} port
 * @property {string} host the TLSA base domain (the MX host, or the certificate name)
 * @property {string} qname `_<port>._tcp.<host>`
 * @property {'mx'|'cert'|'extra'} source
 * @property {string[]} via SMTP: the domains whose MX (or implicit MX) is this host
 * @property {boolean} implicit SMTP: the domain has no MX, mail goes to the domain itself
 * @property {boolean} covered the certificate names this host
 * @property {{ rcode: string|null, resolver: string|null, authenticated: boolean|null, bogus: boolean|null,
 *   cnames: string[], error: string|null, errorKind: string|null }} lookup
 * @property {object[]} records the TLSA records with their {@link matchRecord} fields
 * @property {number|null} ttl
 * @property {'rrsig'|'answer'|null} ttlSource
 * @property {string} status one of {@link DANE_STATUSES}
 * @property {string} severity {@link DANE_SEVERITY}
 * @property {string|null} wouldBe the record verdict an 'insecure' / 'not-covered' status stands for
 * @property {Array<{ code: string, params?: object }>} notes codes of {@link DANE_NOTES}
 * @property {object[]} suggestions {@link suggestRecords}
 * @property {number|null} waitSeconds 2 × TTL when records must be published first
 */

/**
 * The verdict for one endpoint from its TLSA answer (pure).
 * @param {{ service: 'smtp'|'https', host: string, qname: string, covered?: boolean }} endpoint
 * @param {{ response: object|null, cdResponse?: object|null, mxAuthenticated?: boolean|null,
 *   leaf: Associations, anchors?: Array<{ assoc: Associations }>, issuer?: Associations|null }} ctx
 *   `mxAuthenticated` (SMTP): false when no MX record set naming this host was DNSSEC-validated
 * @returns {Pick<DaneEndpoint, 'lookup'|'records'|'ttl'|'ttlSource'|'status'|'severity'|'wouldBe'|'notes'|'suggestions'|'waitSeconds'>}
 */
export function endpointVerdict(endpoint, { response, cdResponse = null, mxAuthenticated = null, leaf, anchors = [], issuer = null }) {
  const notes = [];
  const lookup = {
    rcode: response && response.ok ? response.rcode : null,
    resolver: response ? response.resolver ?? null : null,
    authenticated: authenticated(response),
    bogus: null,
    cnames: [],
    error: null,
    errorKind: null
  };
  const base = { lookup, records: [], ttl: null, ttlSource: null, wouldBe: null, notes, suggestions: [], waitSeconds: null };
  const done = (status, extra = {}) => ({ ...base, ...extra, status, severity: DANE_SEVERITY[status] });

  if (!response || !response.ok) {
    lookup.error = response && response.error ? String(response.error) : 'no answer';
    lookup.errorKind = response && response.errorKind ? response.errorKind : 'unknown';
    return done('error');
  }
  if (response.rcode === 'SERVFAIL') {
    // With checking disabled the records resolve: their signatures are broken (bogus DNSSEC).
    if (cdResponse && cdResponse.ok) {
      lookup.bogus = cdResponse.rcode === 'NOERROR' || cdResponse.rcode === 'NXDOMAIN';
      if (lookup.bogus) notes.push({ code: 'bogus' });
    }
    return done('servfail');
  }
  if (response.rcode !== 'NOERROR' && response.rcode !== 'NXDOMAIN') {
    lookup.error = String(response.rcode);
    lookup.errorKind = 'http';
    return done('error');
  }
  const found = tlsaFromAnswer(response, endpoint.qname);
  lookup.cnames = found.cnames;
  if (found.cnames.length) notes.push({ code: 'cname', params: { target: found.target } });
  const evaluation = evaluateRecords(found.records, { service: endpoint.service, leaf, anchors });
  const extra = { records: evaluation.records, ttl: found.ttl, ttlSource: found.ttlSource };
  if (evaluation.verdict === 'none') return done('none', extra);

  const inner = evaluation.verdict;
  if (inner === 'safe') {
    const usable = evaluation.records.filter((r) => r.usable);
    const stale = usable.filter((r) => r.matches === false).length;
    if (stale) notes.push({ code: 'stale-records', params: { count: stale } });
    const hits = usable.filter((r) => r.matches === true);
    if (hits.every((r) => r.selector === 1 && r.matchedBy === 'leaf')) notes.push({ code: 'spki-match' });
  }
  extra.suggestions = suggestRecords(endpoint.qname, evaluation, { leaf, issuer });
  if (extra.suggestions.length && found.ttl !== null) extra.waitSeconds = 2 * found.ttl;
  if (extra.suggestions.length && found.ttlSource === 'answer') notes.push({ code: 'ttl-remaining' });

  if (lookup.authenticated === null) notes.push({ code: 'ad-unknown', params: { resolver: lookup.resolver || '?' } });
  if (lookup.authenticated === false) return done('insecure', { ...extra, wouldBe: inner });
  if (endpoint.service === 'smtp' && mxAuthenticated === false) {
    notes.push({ code: 'mx-insecure' });
    return done('insecure', { ...extra, wouldBe: inner });
  }
  if (endpoint.covered === false && inner !== 'safe') return done('not-covered', { ...extra, wouldBe: inner });
  return done(inner, extra);
}

/* ------------------------------------------------------------------------ */
/* Plan and run                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Which TLSA names a check asks for (pure; sends nothing).
 * @param {{ hostnames: string[] }} leaf the new certificate (lib/x509.js Certificate)
 * @param {{ extraNames?: string[], mx?: boolean, https?: boolean, limits?: Partial<typeof DANE_LIMITS> }} [opts]
 *   `extraNames`: concrete names to check on port 443 as well; only those the certificate covers are kept
 * @returns {{ domains: string[], https: Array<{ host: string, source: 'cert'|'extra' }>,
 *   skipped: { wildcard: string[], invalid: string[], notCovered: string[], httpsOverCap: number, domainsOverCap: number } }}
 */
export function planDane(leaf, { extraNames = [], mx = true, https = true, limits = {} } = {}) {
  const lim = { ...DANE_LIMITS, ...limits };
  const names = leaf && Array.isArray(leaf.hostnames) ? leaf.hostnames.filter((n) => typeof n === 'string') : [];
  const skipped = { wildcard: [], invalid: [], notCovered: [], httpsOverCap: 0, domainsOverCap: 0 };
  const list = [];
  const seen = new Set();
  const push = (host, source) => {
    if (seen.has(host)) return;
    seen.add(host);
    if (list.length >= lim.httpsNames) skipped.httpsOverCap += 1;
    else list.push({ host, source });
  };
  for (const name of names) {
    if (name.startsWith('*.')) {
      if (!skipped.wildcard.includes(name)) skipped.wildcard.push(name);
      continue;
    }
    // Certificate names are untrusted bytes: only a name that is already a clean hostname is sent.
    const host = normalizeHostname(name);
    if (!host || host !== name) {
      skipped.invalid.push(name);
      continue;
    }
    if (https) push(host, 'cert');
  }
  for (const name of Array.isArray(extraNames) ? extraNames : []) {
    const host = typeof name === 'string' ? normalizeHostname(name) : null;
    if (!host) continue;
    if (!certCovers(names, host).covered) {
      if (!skipped.notCovered.includes(host)) skipped.notCovered.push(host);
      continue;
    }
    if (https) push(host, 'extra');
  }
  const all = mx ? baseDomainsFromNames(names) : [];
  skipped.domainsOverCap = Math.max(0, all.length - lim.mxDomains);
  return { domains: all.slice(0, lim.mxDomains), https: list, skipped };
}

/** Query that never rejects except with AbortError (DohClient.query already behaves so). */
async function ask(dns, name, type, { signal, cd = false, noCache = false }) {
  throwIfAborted(signal);
  try {
    return await dns.query(name, type, { dnssec: true, cd, signal, noCache });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    return { ok: false, rcode: null, flags: {}, answers: [], error: err && err.message ? err.message : String(err), errorKind: 'unknown' };
  }
}

/** One registrable domain's mail servers from its MX answer. */
function mxEntry(domain, response) {
  const entry = {
    domain, rcode: response && response.ok ? response.rcode : null, resolver: response ? response.resolver ?? null : null,
    authenticated: authenticated(response), mx: [], nullMx: false, implicit: false, invalid: [], error: null
  };
  if (!response || !response.ok) {
    entry.error = response && response.error ? String(response.error) : 'no answer';
    return entry;
  }
  if (response.rcode === 'NXDOMAIN') return entry;
  if (response.rcode !== 'NOERROR') {
    entry.error = String(response.rcode);
    return entry;
  }
  const answers = Array.isArray(response.answers) ? response.answers : [];
  const target = canonName(followCnames(answers, domain).target);
  const rrs = answers.filter((rr) => rr && rr.type === 'MX' && canonName(rr.name) === target && rr.data && typeof rr.data === 'object');
  // RFC 7505 null MX: one record "0 ." — the domain accepts no mail.
  if (rrs.length === 1 && canonName(rrs[0].data.exchange) === '.') {
    entry.nullMx = true;
    return entry;
  }
  if (!rrs.length) {
    entry.implicit = true; // RFC 5321 §5.1: no MX → the domain itself is the mail host
    return entry;
  }
  for (const rr of [...rrs].sort((a, b) => (a.data.preference ?? 0) - (b.data.preference ?? 0))) {
    const raw = canonName(rr.data.exchange);
    if (raw === '.') continue;
    const host = normalizeHostname(raw);
    if (!host) entry.invalid.push(raw);
    else if (!entry.mx.some((m) => m.exchange === host)) entry.mx.push({ preference: rr.data.preference, exchange: host });
  }
  return entry;
}

/**
 * @typedef {object} DaneReport
 * @property {Date} startedAt
 * @property {Date} finishedAt
 * @property {{ subjectCN: string|null, serialHex: string, hostnames: string[] }} leaf
 * @property {{ leaf: Associations, anchors: Array<{ subjectCN: string|null, subjectDN: string, issuer: boolean, assoc: Associations }> }} associations
 * @property {Array<{ domain, rcode, resolver, authenticated, mx: Array<{ preference, exchange }>, nullMx, implicit, invalid: string[], error }>} domains
 * @property {DaneEndpoint[]} endpoints SMTP endpoints (MX order) first, then HTTPS names
 * @property {{ wildcard: string[], invalid: string[], notCovered: string[], httpsOverCap: number, domainsOverCap: number, mxHostsOverCap: number }} skipped
 * @property {number} queries DNS queries sent
 */

/**
 * Did `ca` issue `leaf`? Its subject is the leaf's issuer and, when both carry one, its
 * subject key identifier is the leaf's authority key identifier.
 * @param {{ issuerDN: string, authorityKeyId?: string|null }} leaf lib/x509.js Certificate
 * @param {{ subjectDN: string, subjectKeyId?: string|null }} ca
 * @returns {boolean}
 */
export function issuedBy(leaf, ca) {
  if (!leaf || !ca || ca === leaf || ca.subjectDN !== leaf.issuerDN) return false;
  return !leaf.authorityKeyId || !ca.subjectKeyId || leaf.authorityKeyId === ca.subjectKeyId;
}

/**
 * The anchors a DANE-TA record may pin: the other certificates of the file, the leaf's
 * issuer marked ({@link issuedBy}).
 */
async function anchorsOf(leaf, chain, subtle) {
  const list = (Array.isArray(chain) ? chain : []).filter((c) => c && c !== leaf && c.der instanceof Uint8Array && c.spkiDer instanceof Uint8Array);
  const out = [];
  for (const c of list) {
    if (out.some((a) => a.cert.der.length === c.der.length && a.cert.der.every((b, i) => b === c.der[i]))) continue;
    out.push({ cert: c, issuer: issuedBy(leaf, c), assoc: await certAssociations(c, { subtle }) });
  }
  return out;
}

/**
 * Check the TLSA records of a certificate's mail servers and names against it.
 * Sends MX (one per registrable domain) and TLSA queries with the DO bit through `dns`, and one
 * more TLSA query with CD set for an endpoint whose lookup fails (SERVFAIL), to tell broken
 * DNSSEC from broken name servers.
 * @param {{ leaf: object, chain?: object[] }} certs the new certificate and the other certificates of its file
 * @param {{ dns: { query: Function }, subtle?: SubtleCrypto, signal?: AbortSignal, extraNames?: string[],
 *   mx?: boolean, https?: boolean, limits?: Partial<typeof DANE_LIMITS>, noCache?: boolean,
 *   onProgress?: (p: { phase: 'mx'|'tlsa', done: number, total: number }) => void, now?: () => number }} opts
 *   `noCache`: bypass the client's answer cache (a check right after publishing a record must
 *   ask the resolvers again)
 * @returns {Promise<DaneReport>} rejects only with AbortError, a DaneError ('no-crypto') or a TypeError
 */
export async function checkDane({ leaf, chain = [] } = {}, {
  dns, subtle = globalThis.crypto?.subtle, signal, extraNames = [], mx = true, https = true, limits = {},
  noCache = false, onProgress = null, now = Date.now
} = {}) {
  if (!leaf || !Array.isArray(leaf.hostnames)) throw new TypeError('checkDane: a parsed leaf certificate is required');
  if (!dns || typeof dns.query !== 'function') throw new TypeError('checkDane: a DNS client with query(name, type, opts) is required');
  throwIfAborted(signal);
  const lim = { ...DANE_LIMITS, ...limits };
  const startedAt = new Date(now());
  const leafAssoc = await certAssociations(leaf, { subtle });
  const anchors = await anchorsOf(leaf, chain, subtle);
  const issuer = (anchors.find((a) => a.issuer) || {}).assoc || null;
  const plan = planDane(leaf, { extraNames, mx, https, limits: lim });
  let queries = 0;
  const progress = (phase, done, total) => {
    if (typeof onProgress === 'function') {
      try {
        onProgress({ phase, done, total });
      } catch {
        /* a progress hook never breaks the check */
      }
    }
  };

  // 1. MX of every registrable domain.
  let mxDone = 0;
  progress('mx', 0, plan.domains.length);
  const domains = await Promise.all(plan.domains.map(async (domain) => {
    queries += 1;
    const entry = mxEntry(domain, await ask(dns, domain, 'MX', { signal, noCache }));
    progress('mx', ++mxDone, plan.domains.length);
    return entry;
  }));

  // 2. The endpoints: mail hosts (deduplicated across domains, MX order), then the HTTPS names.
  const endpoints = [];
  const smtpByHost = new Map();
  let mxHostsOverCap = 0;
  const covered = (host) => certCovers(leaf.hostnames, host).covered;
  for (const d of domains) {
    const hosts = d.implicit ? [d.domain] : d.mx.map((m) => m.exchange);
    for (const host of hosts) {
      let ep = smtpByHost.get(host);
      if (!ep) {
        if (smtpByHost.size >= lim.mxHosts) {
          mxHostsOverCap += 1;
          continue;
        }
        ep = {
          key: `${DANE_PORTS.smtp}|${host}`, service: 'smtp', port: DANE_PORTS.smtp, host, qname: tlsaOwner(host, DANE_PORTS.smtp),
          source: 'mx', via: [], viaAuth: [], implicit: false, covered: covered(host)
        };
        smtpByHost.set(host, ep);
        endpoints.push(ep);
      }
      if (!ep.via.includes(d.domain)) {
        ep.via.push(d.domain);
        ep.viaAuth.push(d.authenticated);
      }
      if (d.implicit) ep.implicit = true;
    }
  }
  for (const { host, source } of plan.https) {
    endpoints.push({
      key: `${DANE_PORTS.https}|${host}`, service: 'https', port: DANE_PORTS.https, host, qname: tlsaOwner(host, DANE_PORTS.https),
      source, via: [], viaAuth: [], implicit: false, covered: true
    });
  }

  // 3. TLSA of every endpoint (the client throttles), a CD re-query for a SERVFAIL.
  let tlsaDone = 0;
  progress('tlsa', 0, endpoints.length);
  const results = await Promise.all(endpoints.map(async (ep) => {
    queries += 1;
    const response = await ask(dns, ep.qname, 'TLSA', { signal, noCache });
    let cdResponse = null;
    if (response && response.ok && response.rcode === 'SERVFAIL') {
      queries += 1;
      cdResponse = await ask(dns, ep.qname, 'TLSA', { signal, cd: true, noCache });
    }
    // Senders use an MX host's TLSA only when an MX record set naming it was validated.
    const mxAuthenticated = ep.service !== 'smtp' || ep.implicit ? null
      : ep.viaAuth.some((a) => a === true) ? true : ep.viaAuth.every((a) => a === false) ? false : null;
    const verdict = endpointVerdict(ep, { response, cdResponse, mxAuthenticated, leaf: leafAssoc, anchors, issuer });
    if (ep.implicit) verdict.notes.push({ code: 'implicit-mx', params: { domain: ep.via[0] } });
    progress('tlsa', ++tlsaDone, endpoints.length);
    const { viaAuth, ...rest } = ep;
    return { ...rest, ...verdict };
  }));

  return {
    startedAt,
    finishedAt: new Date(now()),
    leaf: { subjectCN: leaf.subjectCN ?? null, serialHex: leaf.serialHex ?? '', hostnames: [...leaf.hostnames] },
    associations: {
      leaf: leafAssoc,
      anchors: anchors.map((a) => ({ subjectCN: a.cert.subjectCN ?? null, subjectDN: a.cert.subjectDN ?? '', issuer: a.issuer, assoc: a.assoc }))
    },
    domains,
    endpoints: results,
    skipped: { ...plan.skipped, mxHostsOverCap },
    queries
  };
}

/* ------------------------------------------------------------------------ */
/* Summary and export                                                       */
/* ------------------------------------------------------------------------ */

/**
 * Counts per status and the headline of a report.
 * A registrable domain whose MX lookup failed counts as a failed lookup: its mail servers were
 * not checked, so the report must not read "DANE not used" or "safe" for them.
 * @param {DaneReport|null} report
 * @returns {{ total: number, counts: Record<string, number>, headline: string|null, variant: string|null, count: number,
 *   warn: number, action: DaneEndpoint[], waitSeconds: number|null, mxFailed: string[], nullMx: string[] }}
 *   `headline` is one of {@link DANE_HEADLINES}; `action` lists the endpoints whose records to
 *   publish first ({@link DANE_ACTION_STATUSES}); `waitSeconds` is the longest of their waits;
 *   `mxFailed` / `nullMx`: the domains whose MX lookup failed / that accept no mail (RFC 7505)
 */
export function daneSummary(report) {
  const counts = Object.fromEntries(DANE_STATUSES.map((s) => [s, 0]));
  const endpoints = report && Array.isArray(report.endpoints) ? report.endpoints : [];
  const domains = report && Array.isArray(report.domains) ? report.domains : [];
  for (const ep of endpoints) if (Object.prototype.hasOwnProperty.call(counts, ep.status)) counts[ep.status] += 1;
  const mxFailed = domains.filter((d) => d && d.error).map((d) => d.domain);
  const nullMx = domains.filter((d) => d && d.nullMx).map((d) => d.domain);
  const warn = counts['ta-mismatch'] + counts['ta-unchecked'] + counts.pkix;
  const failed = counts.error + mxFailed.length;
  let headline = null;
  let variant = null;
  let count = 0;
  if (!endpoints.length && !failed) headline = null;
  else if (counts.danger) [headline, variant, count] = ['danger', 'error', counts.danger];
  else if (counts.servfail) [headline, variant, count] = ['servfail', 'error', counts.servfail];
  else if (warn) [headline, variant, count] = ['warn', 'warn', warn];
  else if (failed) [headline, variant, count] = ['error', 'warn', failed];
  else if (counts.safe) [headline, variant, count] = ['safe', 'ok', counts.safe];
  else if (counts.none === endpoints.length) [headline, variant, count] = ['unused', 'info', endpoints.length];
  else [headline, variant, count] = ['clear', 'info', endpoints.length];
  const action = endpoints.filter((ep) => DANE_ACTION_STATUSES.includes(ep.status) && ep.suggestions.length);
  const waits = action.map((ep) => ep.waitSeconds).filter((w) => Number.isFinite(w));
  return {
    total: endpoints.length, counts, headline, variant, count, warn, action,
    waitSeconds: waits.length ? Math.max(...waits) : null,
    mxFailed, nullMx
  };
}

/**
 * The report as plain JSON (`domainscope.dane/1`): no certificate bytes, association data
 * limited to the digests (matching types 1 and 2).
 * @param {DaneReport} report
 * @param {{ app?: string, version?: string }} [meta]
 * @returns {object}
 */
export function daneExportJson(report, { app = 'DomainScope', version = '' } = {}) {
  const digests = (assoc) => ({
    cert: { sha256: assoc[0][1], sha512: assoc[0][2] },
    spki: { sha256: assoc[1][1], sha512: assoc[1][2] }
  });
  const summary = daneSummary(report);
  return {
    schema: 'domainscope.dane/1',
    generator: app,
    version,
    startedAt: report.startedAt,
    finishedAt: report.finishedAt,
    certificate: { ...report.leaf, tlsa: digests(report.associations.leaf) },
    chain: report.associations.anchors.map((a) => ({ subjectCN: a.subjectCN, subjectDN: a.subjectDN, issuer: a.issuer, tlsa: digests(a.assoc) })),
    summary: { headline: summary.headline, counts: summary.counts, waitSeconds: summary.waitSeconds, mxFailed: summary.mxFailed },
    domains: report.domains,
    endpoints: report.endpoints.map((ep) => ({
      qname: ep.qname, service: ep.service, port: ep.port, host: ep.host, source: ep.source, via: ep.via, implicit: ep.implicit,
      covered: ep.covered, status: ep.status, severity: ep.severity, wouldBe: ep.wouldBe,
      dnssec: ep.lookup.authenticated, rcode: ep.lookup.rcode, resolver: ep.lookup.resolver, bogus: ep.lookup.bogus, error: ep.lookup.error,
      ttl: ep.ttl, ttlSource: ep.ttlSource, waitSeconds: ep.waitSeconds,
      records: ep.records.map((r) => ({
        usage: r.usage, selector: r.selector, matchingType: r.matchingType, data: r.data,
        usable: r.usable, matches: r.matches, matchedBy: r.matchedBy, issue: r.issue
      })),
      add: ep.suggestions.map((s) => s.text),
      notes: ep.notes.map((n) => n.code)
    })),
    skipped: report.skipped,
    queries: report.queries
  };
}
