/**
 * estate.js — the certificate estate of one or more `ssl_origin_scan.py --json` reports: every
 * distinct certificate the scanned servers serve, where and for which names, and what needs a
 * look. DOM-free; runs in browsers and Node 22. Nothing is sent anywhere: a report is read in the
 * browser (the Certificate estate view) and kept only in the tab.
 *
 * - {@link readEstateReport}: one report file's text → the parsed report, or why it is not one
 *   (not JSON, not a report of the CLI, another major version, no result rows, too large). Any
 *   report of the CLI works, with or without `--estate` (which also asks every server for the host
 *   names among its targets); one of an older CLI lacks the public-key hashes, so key reuse cannot
 *   be told for its certificates.
 * - {@link mergeReports}: several reports as one: on an ip:port that more than one report scanned,
 *   each name (and the handshake without SNI) takes the newest report's answer
 *   ({@link MergedReports}.overlaps says which endpoints), names asked are the union, and
 *   {@link MergedReports}.origin names the newest report of each endpoint; a certificate's details
 *   come from the newest report that holds it, with what that one lacks from the others.
 * - {@link estateOf}: the estate of one report dict — the same algorithm as the CLI's
 *   `estate_from_report`, so one report's result equals its `estate` section (tests/fixtures/estate):
 *   expiry buckets ({@link ESTATE_BUCKETS}), kinds ({@link ESTATE_KINDS}), one name served with
 *   different certificates (a load-balancer member or a server the last renewal forgot; `stale`:
 *   the older one of the same key type and kind family), one public key on several hosts (distinct
 *   addresses) or in several certificates ({@link sharedKeyNeedsLook}: only a key in several
 *   certificates or on many addresses flags them), weak keys or signatures ({@link ESTATE_WEAK_REASONS}) and certificates
 *   covering none of the names asked (null when no name was asked).
 * - {@link estateMatches} / {@link estateFilterCounts}: the view's filters ({@link ESTATE_FILTERS}).
 * - {@link estateCsvRows} / {@link estateCsv}: the CSV of the CLI's `--estate --csv`, one row per
 *   certificate, endpoint and server (plus the report's file name when several are merged).
 *
 * Name coverage follows lib/domain.js certCovers (RFC 6125; a wildcard directly on a public suffix
 * covers nothing, as no CA issues one).
 */

import { certCovers } from './domain.js';
import { normalizeIP } from './netinfo.js';
import { toCsv } from './export.js';

/** Expiry buckets by whole days left: expired (< 0), < 7, < 30, < 90 days, later. */
export const ESTATE_BUCKETS = Object.freeze(['expired', '7d', '30d', '90d', 'later']);
/** The CLI's certificate kinds (report `certificates[].kind`). */
export const ESTATE_KINDS = Object.freeze(['origin-ca', 'self-signed', 'private-ca', 'other']);
/** Why a certificate is weak: an RSA key under {@link WEAK_RSA_BITS} bits, a SHA-1 or an MD5 / MD2 signature. */
export const ESTATE_WEAK_REASONS = Object.freeze(['rsa-short', 'sha1', 'md5']);
/**
 * What is odd about a certificate (`certificates[].flags`), in this order; `untrusted`: an endpoint
 * serves it with a chain the CLI's machine does not trust (its trust check, reports that ran it).
 */
export const ESTATE_FLAGS = Object.freeze(['name-conflict', 'stale', 'shared-key', 'weak', 'covers-none', 'untrusted']);
/** RSA keys shorter than this are weak. */
export const WEAK_RSA_BITS = 2048;
/** A key served by this many hosts (distinct addresses), or carried by several certificates, is listed as shared. */
export const SHARED_KEY_MIN_HOSTS = 2;
/**
 * A shared key on this many addresses or more flags its certificates, as one in several certificates
 * does; one certificate on the members of a load-balancer pool is only listed.
 */
export const SHARED_KEY_WIDE_HOSTS = 5;
/**
 * The Certificate estate view's filters, in display order: `expiring` is expired or within 30 days,
 * `expired` and `soon` (within 30 days, not expired) its two halves, the status summary's items.
 */
export const ESTATE_FILTERS = Object.freeze(['all', 'attention', 'expiring', 'expired', 'soon', 'name-conflict', 'shared-key', 'weak',
  'covers-none', 'untrusted', 'private', 'origin-ca']);
/** Why a file is not a report ({@link readEstateReport}). */
export const REPORT_ERRORS = Object.freeze(['too-large', 'not-json', 'not-report', 'version', 'no-results']);
/** A report file larger than this is refused (reading it would hold the tab for long). */
export const ESTATE_MAX_BYTES = 64 * 1024 * 1024;
/** At most this many reports are merged. */
export const ESTATE_MAX_REPORTS = 20;
/** The CLI's major version whose reports this module reads. */
export const REPORT_MAJOR = '1';

const DAY_MS = 86400000;
const SHA256_RE = /^[0-9a-f]{64}$/;
const ROW_PROBES = Object.freeze(['sni', 'wildcard', 'default']);
const EXPIRY_LIMITS = [[0, 'expired'], [7, '7d'], [30, '30d'], [90, '90d']];

/** The CSV columns of the CLI's `--estate --csv` (cli/ssl_origin_scan.py ESTATE_CSV_COLUMNS). */
export const ESTATE_CSV_COLUMNS = Object.freeze(['sha256', 'subject_cn', 'issuer', 'kind', 'not_after', 'days_left',
  'expiry', 'key', 'signature_algorithm', 'spki_sha256', 'hostnames', 'covers_asked', 'server', 'ip', 'port',
  'default_cert', 'served_for', 'flags', 'weak'].map((key) => Object.freeze({ key, header: key })));
/** The columns the CLI's `--ari` adds after them (cli/ssl_origin_scan.py ARI_CSV_COLUMNS). */
export const ESTATE_ARI_COLUMNS = Object.freeze(['ari_start', 'ari_end', 'ari_explanation', 'ari_error'].map((key) => Object.freeze({ key, header: key })));
/** The columns the CLI's `--revocation` adds (cli/ssl_origin_scan.py REVOCATION_CSV_COLUMNS). */
export const ESTATE_REVOCATION_COLUMNS = Object.freeze(['revocation', 'revoked_at', 'revocation_reason', 'revocation_error']
  .map((key) => Object.freeze({ key, header: key })));
/** The columns the CLI's trust check adds, last (cli/ssl_origin_scan.py TRUST_CSV_COLUMNS). */
export const ESTATE_TRUST_COLUMNS = Object.freeze(['cert_trusted', 'trust_detail'].map((key) => Object.freeze({ key, header: key })));
/** OpenSSL's verify codes the CLI's trust check names in words (cli/ssl_origin_scan.py TRUST_DETAILS). */
export const ESTATE_TRUST_CODES = Object.freeze([20, 21, 18, 19, 10, 9, 62]);

/**
 * The verify code of a CLI trust detail (`missing intermediate or private CA (code 20)`) when it is
 * one the CLI names ({@link ESTATE_TRUST_CODES}), so the view can say it in the page's language;
 * null for any other text (shown as it is).
 * @param {string|null|undefined} detail
 * @returns {number|null}
 */
export function trustDetailCode(detail) {
  const m = /\(code (\d{1,3})\)$/.exec(typeof detail === 'string' ? detail.trim() : '');
  const code = m ? Number(m[1]) : null;
  return code !== null && ESTATE_TRUST_CODES.includes(code) ? code : null;
}

/* ------------------------------------------------------------------------ */
/* Small rules shared with the CLI                                          */
/* ------------------------------------------------------------------------ */

/**
 * The {@link ESTATE_BUCKETS} entry of a certificate with `daysLeft` whole days left.
 * @param {number} daysLeft
 * @returns {string}
 */
export function expiryBucket(daysLeft) {
  for (const [limit, bucket] of EXPIRY_LIMITS) if (daysLeft < limit) return bucket;
  return 'later';
}

/**
 * Why a certificate is weak ({@link ESTATE_WEAK_REASONS}; [] when it is not).
 * @param {string|null} keyAlgorithm
 * @param {number|null} keyBits
 * @param {string|null} signatureAlgorithm OpenSSL name, e.g. 'sha1WithRSAEncryption'
 * @returns {string[]}
 */
export function weakReasons(keyAlgorithm, keyBits, signatureAlgorithm) {
  const out = [];
  if (keyAlgorithm === 'RSA' && Number.isInteger(keyBits) && keyBits < WEAK_RSA_BITS) out.push('rsa-short');
  const sig = String(signatureAlgorithm || '').toLowerCase();
  if (sig.includes('sha1')) out.push('sha1');
  if (sig.startsWith('md5') || sig.startsWith('md2')) out.push('md5');
  return out;
}

/**
 * 'RSA 2048', 'EC P-256', 'Ed25519' from a report's certificate fields.
 * @param {string|null} keyAlgorithm
 * @param {number|null} keyBits
 * @param {string|null} curve
 * @returns {string}
 */
export function keyLabel(keyAlgorithm, keyBits, curve) {
  const algorithm = String(keyAlgorithm || 'unknown');
  if (algorithm === 'EC') return curve ? `EC ${curve}` : 'EC';
  if ((algorithm === 'RSA' || algorithm === 'DSA') && Number.isInteger(keyBits)) return `${algorithm} ${keyBits}`;
  return algorithm;
}

/**
 * Does a shared key (an estate `sharedKeys` entry) flag its certificates `shared-key`? When several
 * certificates carry it (a renewal that kept the key, one key for several sites) or it is on
 * {@link SHARED_KEY_WIDE_HOSTS} addresses or more — the CLI's shared_key_needs_look.
 * @param {{ hosts: number, certificates: string[] }} group
 * @returns {boolean}
 */
export function sharedKeyNeedsLook(group) {
  return !!group && (group.certificates.length >= 2 || group.hosts >= SHARED_KEY_WIDE_HOSTS);
}

/** Self-signed and private-CA certificates are one family (lib/verify.js, the CLI's _kind_family). */
const kindFamily = (kind) => (kind === 'self-signed' || kind === 'private-ca' ? 'private' : kind);

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isInt = (v) => Number.isInteger(v);
const endpointKey = (ip, port) => `${ip}|${port}`;

/* ------------------------------------------------------------------------ */
/* Reading report files                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} EstateReport
 * @property {string} name the file name
 * @property {object} doc the report as the CLI wrote it
 * @property {Date|null} startedAt
 * @property {Date|null} finishedAt
 * @property {boolean} estate written with --estate (the host names among the targets were asked too)
 * @property {boolean} keyHashes every certificate has its public-key hash (an older CLI wrote none)
 * @property {string} id the same report read twice has the same id
 */

/**
 * One report file's text → `{ ok: true, report }` or `{ ok: false, error, detail? }` with an
 * {@link REPORT_ERRORS} code. Never throws.
 * @param {string} text
 * @param {{ name?: string }} [opts]
 * @returns {{ ok: true, report: EstateReport } | { ok: false, error: string, detail?: string }}
 */
export function readEstateReport(text, { name = '' } = {}) {
  const source = String(text ?? '');
  if (source.length > ESTATE_MAX_BYTES) return { ok: false, error: 'too-large' };
  let doc;
  try {
    doc = JSON.parse(source.replace(/^﻿/, ''));
  } catch {
    return { ok: false, error: 'not-json' };
  }
  if (!isObject(doc) || doc.tool !== 'ssl_origin_scan') return { ok: false, error: 'not-report' };
  const version = typeof doc.version === 'string' ? doc.version : '';
  if (version.split('.')[0] !== REPORT_MAJOR) return { ok: false, error: 'version', detail: version || '?' };
  if (!Array.isArray(doc.results)) return { ok: false, error: 'no-results' };
  const time = (v) => {
    const ms = typeof v === 'string' ? Date.parse(v) : NaN;
    return Number.isNaN(ms) ? null : new Date(ms);
  };
  const certs = isObject(doc.certificates) ? Object.values(doc.certificates) : [];
  return {
    ok: true,
    report: {
      name: String(name || ''),
      doc,
      startedAt: time(doc.startedAt),
      finishedAt: time(doc.finishedAt),
      estate: isObject(doc.options) && doc.options.estate === true,
      keyHashes: certs.every((c) => isObject(c) && typeof c.spkiSha256 === 'string'),
      id: `${doc.startedAt}|${doc.finishedAt}|${doc.results.length}|${certs.length}`
    }
  };
}

/* ------------------------------------------------------------------------ */
/* Several reports as one                                                   */
/* ------------------------------------------------------------------------ */

/** `(name, sni)` of every name a report asked for: `names`, or what its rows probed. */
function reportProbes(doc) {
  const out = [];
  const seen = new Set();
  const entries = Array.isArray(doc.names) ? doc.names
    : (Array.isArray(doc.results) ? doc.results : [])
      .filter((row) => isObject(row) && (row.probe === 'sni' || row.probe === 'wildcard'))
      .map((row) => ({ name: row.name, sni: row.sni }));
  for (const entry of entries) {
    if (!isObject(entry)) continue;
    const { name, sni } = entry;
    if (typeof name === 'string' && name && !seen.has(name)) {
      seen.add(name);
      out.push({ name, sni: typeof sni === 'string' && sni ? sni : name });
    }
  }
  return out;
}

/** The ip:port key of a row or endpoint entry, or null. */
function keyOf(item) {
  if (!isObject(item) || typeof item.ip !== 'string' || !isInt(item.port)) return null;
  return endpointKey(normalizeIP(item.ip) || item.ip, item.port);
}

/** A certificate's details from `primary`, with the fields it does not have taken from `other`. */
function withGaps(primary, other) {
  if (!isObject(primary) || !isObject(other)) return isObject(primary) ? primary : other;
  const out = { ...primary };
  for (const [field, value] of Object.entries(other)) if (!(field in out)) out[field] = value;
  return out;
}

/**
 * @typedef {object} MergedReports
 * @property {object} doc one report dict: names (union), certificates (each from the newest
 *   report that holds it, the fields it lacks from the others), results (each probe of an ip:port
 *   from the newest report that asked it), endpoints (each ip:port from the newest report that
 *   scanned it), finishedAt (the newest)
 * @property {Map<string, number>} origin `${ip}|${port}` → the index of the newest report that scanned it
 * @property {Map<string, number[]>} sources `${ip}|${port}|${sha256}` → the reports whose answers put
 *   that certificate on that endpoint (several reports only)
 * @property {string[]} overlaps the ip:port keys (`${ip}|${port}`) more than one report scanned
 */

/**
 * Several reports as one report dict. For an ip:port scanned by more than one report, each probe
 * (without SNI, or one name) takes the answer of the newest report that asked it (finishedAt; the
 * later one in the list on a tie), so a name only an older report asked keeps that report's
 * answer; when the newest report found the port closed or silent, the older answers there are
 * dropped. `overlaps` lists these endpoints. One report comes back as it is (only `origin`
 * added). Reports of separate networks with the same private addresses should be viewed one at a
 * time.
 * @param {Array<EstateReport|{ doc: object }>} reports
 * @returns {MergedReports}
 */
export function mergeReports(reports) {
  const list = (Array.isArray(reports) ? reports : []).filter((r) => r && isObject(r.doc));
  const times = list.map((r) => {
    const ms = typeof r.doc.finishedAt === 'string' ? Date.parse(r.doc.finishedAt) : NaN;
    return Number.isNaN(ms) ? -Infinity : ms;
  });
  const keysOf = list.map((r) => {
    const keys = new Set();
    for (const row of Array.isArray(r.doc.results) ? r.doc.results : []) {
      const key = keyOf(row);
      if (key) keys.add(key);
    }
    for (const e of Array.isArray(r.doc.endpoints) ? r.doc.endpoints : []) {
      const key = keyOf(e);
      if (key) keys.add(key);
    }
    return keys;
  });
  const origin = new Map();
  const seenIn = new Map();
  keysOf.forEach((keys, i) => {
    for (const key of keys) {
      seenIn.set(key, (seenIn.get(key) || 0) + 1);
      const owner = origin.get(key);
      if (owner === undefined || times[i] >= times[owner]) origin.set(key, i);
    }
  });
  const overlaps = [...seenIn].filter(([, n]) => n > 1).map(([key]) => key);
  if (list.length === 1) return { doc: list[0].doc, origin, sources: new Map(), overlaps };

  // The newest report that answered each probe of an endpoint (without SNI, or one name), and the
  // endpoints the newest report that scanned them found closed or silent.
  const answerKey = (row, key) => `${key}|${row.probe === 'default' ? '' : `${row.probe}|${row.name}`}`;
  const newest = new Map();
  const closed = new Set();
  list.forEach((r, i) => {
    for (const row of Array.isArray(r.doc.results) ? r.doc.results : []) {
      const key = keyOf(row);
      if (!key) continue;
      if (row.probe === 'connect') {
        if (origin.get(key) === i) closed.add(key);
        continue;
      }
      const answer = answerKey(row, key);
      const had = newest.get(answer);
      if (had === undefined || times[i] >= times[had]) newest.set(answer, i);
    }
  });

  const names = [];
  const named = new Set();
  const certificates = {};
  const certFrom = new Map();
  const results = [];
  const sources = new Map();
  let endpoints = [];
  let latest = null;
  list.forEach((r, i) => {
    const { doc } = r;
    for (const probe of reportProbes(doc)) {
      if (!named.has(probe.name)) {
        named.add(probe.name);
        names.push(probe);
      }
    }
    if (isObject(doc.certificates)) {
      for (const [sha, info] of Object.entries(doc.certificates)) {
        const had = certFrom.get(sha);
        // the newest report's details (the later one on a tie), with what it lacks from the others
        // (an older CLI writes no public-key hashes and no kinds)
        if (had === undefined) certificates[sha] = info;
        else certificates[sha] = times[i] >= times[had] ? withGaps(info, certificates[sha]) : withGaps(certificates[sha], info);
        if (had === undefined || times[i] >= times[had]) certFrom.set(sha, i);
      }
    }
    for (const row of Array.isArray(doc.results) ? doc.results : []) {
      const key = keyOf(row);
      if (!key) continue;
      // an endpoint the newest report found closed keeps only that; else each probe takes the
      // newest report that asked it
      const keep = closed.has(key) || row.probe === 'connect' ? origin.get(key) === i : newest.get(answerKey(row, key)) === i;
      if (!keep) continue;
      results.push(row);
      if (typeof row.certSha256 === 'string') {
        const source = `${key}|${row.certSha256}`;
        if (!sources.has(source)) sources.set(source, []);
        if (!sources.get(source).includes(i)) sources.get(source).push(i);
      }
    }
    if (endpoints && Array.isArray(doc.endpoints)) {
      endpoints.push(...doc.endpoints.filter((e) => origin.get(keyOf(e)) === i));
    } else {
      endpoints = null; // a report without the list: counted from the rows
    }
    if (times[i] > -Infinity && (latest === null || times[i] > times[latest])) latest = i;
  });
  const doc = { tool: 'ssl_origin_scan', names, certificates, results, finishedAt: latest === null ? null : list[latest].doc.finishedAt };
  if (endpoints) doc.endpoints = endpoints;
  return { doc, origin, sources, overlaps };
}

/* ------------------------------------------------------------------------ */
/* The estate                                                               */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} EstateEndpoint
 * @property {string[]} servers inventory servers with this address
 * @property {string} ip
 * @property {number} port
 * @property {boolean} defaultCert served without SNI
 * @property {string[]} names the names asked that got this certificate here (covering them or not)
 * @property {boolean|null} [trusted] a report that checked trust (the CLI's rows carry `certTrusted`): false when
 *   the chain served for a name here is not trusted, true when one is, null when none was asked ({@link endpointTrust})
 * @property {string|null} [trustDetail] why not, as the CLI said it (`missing intermediate or private CA (code 20)`)
 */

/**
 * An endpoint's trust for one certificate from one of its rows, the CLI's `_estate_trust`: not
 * trusted once a name's row is not (its detail kept), trusted once one is, else null.
 * @param {EstateEndpoint} endpoint
 * @param {object} row a report row with `certTrusted`
 */
function endpointTrust(endpoint, row) {
  if (!('trusted' in endpoint)) {
    endpoint.trusted = null;
    endpoint.trustDetail = null;
  }
  if (row.certTrusted === false && endpoint.trusted !== false) {
    endpoint.trusted = false;
    endpoint.trustDetail = typeof row.trustDetail === 'string' ? row.trustDetail : null;
  } else if (row.certTrusted === true && endpoint.trusted === null) {
    endpoint.trusted = true;
  }
}

/**
 * @typedef {object} EstateCertificate
 * @property {string} sha256
 * @property {string|null} subjectCN
 * @property {string|null} subjectDN
 * @property {string|null} issuer the issuer's CN (and O), as the CLI labels it
 * @property {string|null} issuerDN
 * @property {string|null} serialHex
 * @property {string|null} notBefore ISO
 * @property {string|null} notAfter ISO
 * @property {number} daysLeft
 * @property {string} expiry {@link ESTATE_BUCKETS}
 * @property {string[]} hostnames
 * @property {string|null} keyAlgorithm
 * @property {number|null} keyBits
 * @property {string|null} curve
 * @property {string} key {@link keyLabel}
 * @property {string|null} signatureAlgorithm
 * @property {string|null} spkiSha256 null in reports of an older CLI
 * @property {string} kind {@link ESTATE_KINDS}
 * @property {string|null} privateCa the subject DN of the --private-ca that issued it
 * @property {boolean} isCA
 * @property {string[]} weak {@link ESTATE_WEAK_REASONS}
 * @property {string[]} coversAsked the names asked it covers
 * @property {object} [ari] the CA's renewal window, as the CLI's `--ari` wrote it ({ ca, certId, start, end,
 *   explanationURL, checkedAt, retryAfter, status, error, carried? }); only in reports that have it
 * @property {object} [revocation] what its CRL says, as `--revocation` wrote it ({ status: good|revoked|unknown,
 *   reason, reasonCode, time, crl, checkedAt, thisUpdate, nextUpdate, signature, error })
 * @property {{ state: 'before'|'open'|'past', days: number }|null} [ariWindow] where today is in that window
 *   ({@link estateAriWindow}); with `ari` only
 * @property {string[]} flags {@link ESTATE_FLAGS}
 * @property {EstateEndpoint[]} endpoints
 */

/**
 * The estate of one report dict (a report of the CLI, or {@link mergeReports}' doc) — the CLI's
 * `estate_from_report`: `{ namesAsked, counts: { certificates, endpoints, openEndpoints,
 * endpointsWithCertificate, expiry, kinds }, certificates, nameConflicts, sharedKeys, weakKeys,
 * coversNone }` with {@link EstateCertificate} certificates, soonest expiry first.
 * @param {object} doc
 * @param {{ now?: number|Date }} [opts] counts the days left (default: the report's finishedAt)
 * @returns {object}
 */
export function estateOf(doc, { now } = {}) {
  const src = isObject(doc) ? doc : {};
  const nowMs = now === undefined || now === null
    ? (Date.parse(src.finishedAt) || Date.now())
    : Number(now instanceof Date ? now.getTime() : now);
  const probes = reportProbes(src);
  const infoOf = isObject(src.certificates) ? src.certificates : {};
  const entries = new Map();
  const endpointsOf = new Map(); // sha256 → Map(key → EstateEndpoint)
  const served = new Map(); // name → Map(key → sha256)
  const seenEndpoints = new Map(); // key → state
  const ipPort = new Map(); // key → [ip, port]
  for (const row of Array.isArray(src.results) ? src.results : []) {
    if (!isObject(row) || !(ROW_PROBES.includes(row.probe) || row.probe === 'connect')) continue;
    const key = keyOf(row);
    if (!key) continue;
    if (!ipPort.has(key)) ipPort.set(key, [normalizeIP(row.ip) || row.ip, row.port]);
    if (row.probe === 'connect') {
      seenEndpoints.set(key, String(row.status));
      continue;
    }
    if (!seenEndpoints.has(key)) seenEndpoints.set(key, 'OPEN');
    const sha = row.certSha256;
    if (typeof sha !== 'string' || !SHA256_RE.test(sha)) continue;
    let entry = entries.get(sha);
    if (!entry) {
      entry = estateEntry(sha, row, infoOf[sha], probes, nowMs);
      entries.set(sha, entry);
      endpointsOf.set(sha, new Map());
    }
    let endpoint = endpointsOf.get(sha).get(key);
    if (!endpoint) {
      endpoint = { servers: [], ip: ipPort.get(key)[0], port: row.port, defaultCert: false, names: [] };
      endpointsOf.get(sha).set(key, endpoint);
      entry.endpoints.push(endpoint);
    }
    if (typeof row.server === 'string' && row.server && !endpoint.servers.includes(row.server)) endpoint.servers.push(row.server);
    if (Object.prototype.hasOwnProperty.call(row, 'certTrusted')) endpointTrust(endpoint, row);
    const name = row.name;
    if (row.probe === 'default') {
      endpoint.defaultCert = true;
    } else if (typeof name === 'string' && name) {
      if (!endpoint.names.includes(name)) endpoint.names.push(name);
      const sni = typeof row.sni === 'string' ? row.sni : name;
      if (certCovers(entry.hostnames, sni).covered) {
        if (!served.has(name)) served.set(name, new Map());
        if (!served.get(name).has(key)) served.get(name).set(key, sha);
      }
    }
  }
  const certificates = [...entries.values()]
    .sort((a, b) => a.daysLeft - b.daysLeft || (a.sha256 < b.sha256 ? -1 : a.sha256 > b.sha256 ? 1 : 0));

  const conflicts = nameConflicts(probes, served, entries, endpointsOf, ipPort);
  const shared = sharedKeys(certificates);
  const weak = certificates.filter((c) => c.weak.length).map((c) => ({ sha256: c.sha256, reasons: [...c.weak] }));
  const coversNone = probes.length ? certificates.filter((c) => !c.coversAsked.length).map((c) => c.sha256) : null;
  const flags = new Map();
  const flag = (sha, f) => {
    if (!flags.has(sha)) flags.set(sha, new Set());
    flags.get(sha).add(f);
  };
  for (const conflict of conflicts) {
    for (const cert of conflict.certificates) {
      flag(cert.sha256, 'name-conflict');
      if (cert.stale) flag(cert.sha256, 'stale');
    }
  }
  for (const group of shared) if (sharedKeyNeedsLook(group)) for (const sha of group.certificates) flag(sha, 'shared-key');
  for (const item of weak) flag(item.sha256, 'weak');
  for (const sha of coversNone || []) flag(sha, 'covers-none');
  for (const entry of certificates) if (entry.endpoints.some((e) => e.trusted === false)) flag(entry.sha256, 'untrusted');
  for (const entry of certificates) entry.flags = ESTATE_FLAGS.filter((f) => flags.has(entry.sha256) && flags.get(entry.sha256).has(f));

  let endpointCount;
  let openCount;
  if (Array.isArray(src.endpoints)) {
    endpointCount = src.endpoints.length;
    openCount = src.endpoints.filter((e) => isObject(e) && e.state === 'OPEN').length;
  } else {
    endpointCount = seenEndpoints.size;
    openCount = [...seenEndpoints.values()].filter((s) => s === 'OPEN').length;
  }
  const withCert = new Set();
  for (const eps of endpointsOf.values()) for (const key of eps.keys()) withCert.add(key);
  return {
    namesAsked: probes.map((p) => p.name),
    counts: {
      certificates: certificates.length,
      endpoints: endpointCount,
      openEndpoints: openCount,
      endpointsWithCertificate: withCert.size,
      expiry: Object.fromEntries(ESTATE_BUCKETS.map((b) => [b, certificates.filter((c) => c.expiry === b).length])),
      kinds: Object.fromEntries(ESTATE_KINDS.map((k) => [k, certificates.filter((c) => c.kind === k).length]))
    },
    certificates,
    nameConflicts: conflicts,
    sharedKeys: shared,
    weakKeys: weak,
    coversNone
  };
}

/** A certificate of the estate from the report's `certificates` entry (the row's own fields when it lacks one). */
function estateEntry(sha, row, info, probes, nowMs) {
  const data = isObject(info) ? info : {};
  const text = (key, fallback = null) => {
    const value = key in data ? data[key] : fallback;
    return typeof value === 'string' ? value : null;
  };
  const hostnames = (Array.isArray(data.hostnames) ? data.hostnames : []).filter((n) => typeof n === 'string');
  const notAfter = text('notAfter', row.certNotAfter);
  const when = notAfter ? Date.parse(notAfter) : NaN;
  let days = Number.isNaN(when) ? row.certDaysLeft : Math.floor((when - nowMs) / DAY_MS);
  days = isInt(days) ? days : 0;
  let kind = text('kind');
  if (!ESTATE_KINDS.includes(kind)) kind = data.selfSigned === true ? 'self-signed' : 'other';
  const bits = isInt(data.keyBits) ? data.keyBits : null;
  const algorithm = text('keyAlgorithm');
  const signature = text('signatureAlgorithm');
  const spki = text('spkiSha256');
  // --ari / --revocation: carried along only when the report has them (the CLI's _estate_entry alike)
  const extra = Object.fromEntries(['ari', 'revocation'].filter((key) => isObject(data[key])).map((key) => [key, data[key]]));
  if (extra.ari) extra.ariWindow = estateAriWindow(extra.ari, nowMs);
  return {
    sha256: sha,
    subjectCN: text('subjectCN', row.certSubjectCN),
    subjectDN: text('subjectDN'),
    issuer: typeof row.certIssuer === 'string' ? row.certIssuer : null,
    issuerDN: text('issuerDN'),
    serialHex: text('serialHex', row.certSerial),
    notBefore: text('notBefore'),
    notAfter,
    daysLeft: days,
    expiry: expiryBucket(days),
    hostnames,
    keyAlgorithm: algorithm,
    keyBits: bits,
    curve: text('curve'),
    key: keyLabel(algorithm, bits, text('curve')),
    signatureAlgorithm: signature,
    spkiSha256: spki && SHA256_RE.test(spki) ? spki : null,
    kind,
    privateCa: text('privateCa'),
    isCA: data.isCA === true,
    weak: weakReasons(algorithm, bits, signature),
    coversAsked: probes.filter((p) => certCovers(hostnames, p.sni).covered).map((p) => p.name),
    ...extra,
    flags: [],
    endpoints: []
  };
}

/** `a` was issued after `b`: a later notBefore, else a later notAfter (ISO text sorts like the time). */
function issuedAfter(a, b) {
  for (const key of ['notBefore', 'notAfter']) {
    const x = a[key] || '';
    const y = b[key] || '';
    if (x !== y) return x > y;
  }
  return false;
}

function nameConflicts(probes, served, entries, endpointsOf, ipPort) {
  const out = [];
  for (const { name } of probes) {
    const byCert = new Map();
    for (const [key, sha] of served.get(name) || []) {
      if (!byCert.has(sha)) byCert.set(sha, []);
      byCert.get(sha).push(key);
    }
    if (byCert.size < 2) continue;
    const certs = [...byCert.keys()].map((sha) => entries.get(sha));
    const rank = (c) => `${c.notBefore || ''}\u0000${c.notAfter || ''}`;
    certs.sort((a, b) => (rank(a) < rank(b) ? 1 : rank(a) > rank(b) ? -1 : 0));
    out.push({
      name,
      certificates: certs.map((cert) => ({
        sha256: cert.sha256,
        stale: certs.some((other) => other !== cert && other.keyAlgorithm === cert.keyAlgorithm
          && kindFamily(other.kind) === kindFamily(cert.kind) && issuedAfter(other, cert)),
        endpoints: byCert.get(cert.sha256).map((key) => ({
          servers: [...endpointsOf.get(cert.sha256).get(key).servers],
          ip: ipPort.get(key)[0],
          port: ipPort.get(key)[1]
        }))
      }))
    });
  }
  return out;
}

/** Keys on {@link SHARED_KEY_MIN_HOSTS} addresses or more, or in several certificates (the CLI's _shared_keys). */
function sharedKeys(certificates) {
  const groups = new Map();
  for (const entry of certificates) {
    if (!entry.spkiSha256) continue;
    if (!groups.has(entry.spkiSha256)) groups.set(entry.spkiSha256, []);
    groups.get(entry.spkiSha256).push(entry);
  }
  const out = [];
  for (const [spki, certs] of groups) {
    const servers = [];
    const addresses = [];
    const folded = new Set();
    for (const cert of certs) {
      for (const endpoint of cert.endpoints) {
        if (!addresses.includes(endpoint.ip)) addresses.push(endpoint.ip);
        for (const server of endpoint.servers.length ? endpoint.servers : [endpoint.ip]) {
          const key = server.toLowerCase();
          if (!folded.has(key)) {
            folded.add(key);
            servers.push(server);
          }
        }
      }
    }
    // a host is an address: several inventory names of one address (or its ports) are one host
    if (addresses.length >= SHARED_KEY_MIN_HOSTS || certs.length >= 2) {
      out.push({ spkiSha256: spki, key: certs[0].key, hosts: addresses.length, servers, addresses, certificates: certs.map((c) => c.sha256) });
    }
  }
  out.sort((a, b) => b.hosts - a.hosts || b.certificates.length - a.certificates.length
    || (a.spkiSha256 < b.spkiSha256 ? -1 : a.spkiSha256 > b.spkiSha256 ? 1 : 0));
  return out;
}

/* ------------------------------------------------------------------------ */
/* Filters and exports                                                      */
/* ------------------------------------------------------------------------ */

/**
 * Where a moment is in a certificate's ARI renewal window (the CLI's `--ari` record): `before`
 * (`days`: whole days until it opens, rounded up), `open` or `past`; null without a window (no
 * record, an error, a date that does not parse). The CLI's window_state.
 * @param {object|null|undefined} ari
 * @param {number} [nowMs]
 * @returns {{ state: 'before'|'open'|'past', days: number }|null}
 */
export function estateAriWindow(ari, nowMs = Date.now()) {
  if (!isObject(ari) || ari.error) return null;
  const start = typeof ari.start === 'string' ? Date.parse(ari.start) : NaN;
  const end = typeof ari.end === 'string' ? Date.parse(ari.end) : NaN;
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  if (nowMs < start) return { state: 'before', days: Math.ceil((start - nowMs) / DAY_MS) };
  return { state: nowMs <= end ? 'open' : 'past', days: 0 };
}

/**
 * Does a certificate pass a filter ({@link ESTATE_FILTERS})? `attention`: any flag, it expires
 * within 30 days or has expired, its CRL lists it (`--revocation`) or its CA's renewal window is
 * open or past (`--ari`); `expiring`: expired or within 30 days; `private`: self-signed
 * or from a --private-ca; `origin-ca`: a Cloudflare Origin CA certificate; the others: its flag.
 * @param {EstateCertificate} cert
 * @param {string} filter
 * @returns {boolean}
 */
export function estateMatches(cert, filter) {
  if (!cert) return false;
  const soon = cert.expiry === 'expired' || cert.expiry === '7d' || cert.expiry === '30d';
  switch (filter) {
    case 'attention': return soon || cert.flags.length > 0 || (isObject(cert.revocation) && cert.revocation.status === 'revoked')
      || (isObject(cert.ariWindow) && cert.ariWindow.state !== 'before');
    case 'expiring': return soon;
    case 'expired': return cert.expiry === 'expired';
    case 'soon': return cert.expiry === '7d' || cert.expiry === '30d';
    case 'private': return cert.kind === 'self-signed' || cert.kind === 'private-ca';
    case 'origin-ca': return cert.kind === 'origin-ca';
    case 'name-conflict': case 'shared-key': case 'weak': case 'covers-none': case 'untrusted': return cert.flags.includes(filter);
    default: return true;
  }
}

/**
 * How many certificates pass each filter.
 * @param {{ certificates: EstateCertificate[] }} estate
 * @returns {Record<string, number>}
 */
export function estateFilterCounts(estate) {
  const certs = estate && Array.isArray(estate.certificates) ? estate.certificates : [];
  return Object.fromEntries(ESTATE_FILTERS.map((f) => [f, certs.filter((c) => estateMatches(c, f)).length]));
}

/**
 * The status summary of an estate (DESIGN §5.6: "✕ expired ⚠ expiring · name conflicts · shared
 * keys · weak"): certificates that expired (error), that expire within 30 days (warn), and those in
 * a name conflict, with a shared key or weak (neutral), each a filter of the certificate list
 * (`filter`: an {@link ESTATE_FILTERS} value). Not a verdict tool: a zero count is left out.
 * @param {{ certificates: EstateCertificate[] }} estate
 * @returns {Array<{ key: string, severity: string, count: number, filter: string }>}
 */
export function estateStatus(estate) {
  const counts = estateFilterCounts(estate);
  return [
    { key: 'expired', severity: 'error', count: counts.expired, filter: 'expired' },
    { key: 'soon', severity: 'warn', count: counts.soon, filter: 'soon' },
    { key: 'name-conflict', severity: 'neutral', count: counts['name-conflict'], filter: 'name-conflict' },
    { key: 'shared-key', severity: 'neutral', count: counts['shared-key'], filter: 'shared-key' },
    { key: 'weak', severity: 'neutral', count: counts.weak, filter: 'weak' }
  ];
}

/**
 * One CSV row per certificate, endpoint and server, the CLI's `--estate --csv` rows (with its
 * `--ari` / `--revocation` cells when the estate has them, {@link estateStatusColumns}). With
 * `reportName(endpoint, cert)` (several reports merged) each row also names its report (`report`).
 * @param {{ certificates: EstateCertificate[] }} estate
 * @param {{ certificates?: EstateCertificate[], reportName?: (endpoint: EstateEndpoint, cert: EstateCertificate) => string }} [opts]
 *   `certificates`: only these (a filtered view), in their order
 * @returns {object[]}
 */
export function estateCsvRows(estate, { certificates = null, reportName = null } = {}) {
  const rows = [];
  const extra = estateStatusColumns(estate);
  const trust = estateTrustColumns(estate).length > 0;
  for (const cert of certificates || (estate && estate.certificates) || []) {
    const status = statusCells(cert, extra);
    for (const endpoint of cert.endpoints) {
      const verdict = trust ? {
        cert_trusted: endpoint.trusted === true ? 'yes' : endpoint.trusted === false ? 'no' : '',
        trust_detail: typeof endpoint.trustDetail === 'string' ? endpoint.trustDetail : ''
      } : {};
      for (const server of endpoint.servers.length ? endpoint.servers : ['']) {
        const row = {
          sha256: cert.sha256,
          subject_cn: cert.subjectCN || '',
          issuer: cert.issuer || '',
          kind: cert.kind,
          not_after: cert.notAfter || '',
          days_left: cert.daysLeft,
          expiry: cert.expiry,
          key: cert.key,
          signature_algorithm: cert.signatureAlgorithm || '',
          spki_sha256: cert.spkiSha256 || '',
          hostnames: cert.hostnames.join(' '),
          covers_asked: cert.coversAsked.join(' '),
          server,
          ip: endpoint.ip,
          port: endpoint.port,
          default_cert: endpoint.defaultCert ? 'yes' : 'no',
          served_for: endpoint.names.join(' '),
          flags: cert.flags.join(' '),
          weak: cert.weak.join(' '),
          ...status,
          ...verdict
        };
        if (reportName) row.report = reportName(endpoint, cert);
        rows.push(row);
      }
    }
  }
  return rows;
}

/**
 * The columns the CLI's `--ari` / `--revocation` add to the estate CSV, after its own: the ARI
 * ones when a certificate of the estate has an `ari` record, the revocation ones when one has a
 * `revocation` record (cli/ssl_origin_scan.py estate_status_columns).
 * @param {{ certificates?: EstateCertificate[] }} estate
 * @returns {Array<{ key: string, header: string }>}
 */
export function estateStatusColumns(estate) {
  const certs = (estate && estate.certificates) || [];
  return [
    ...(certs.some((c) => isObject(c.ari)) ? ESTATE_ARI_COLUMNS : []),
    ...(certs.some((c) => isObject(c.revocation)) ? ESTATE_REVOCATION_COLUMNS : [])
  ];
}

/**
 * The columns the CLI's trust check adds to the estate CSV, last: {@link ESTATE_TRUST_COLUMNS} when an
 * endpoint of the estate has a verdict (cli/ssl_origin_scan.py estate_trust_columns).
 * @param {{ certificates?: EstateCertificate[] }} estate
 * @returns {Array<{ key: string, header: string }>}
 */
export function estateTrustColumns(estate) {
  const certs = (estate && estate.certificates) || [];
  return certs.some((c) => c.endpoints.some((e) => 'trusted' in e)) ? ESTATE_TRUST_COLUMNS : [];
}

/** Where the certificates are in their ARI windows ({@link estateStatusCounts}; `error`: no window read). */
export const ESTATE_ARI_STATES = Object.freeze(['open', 'past', 'before', 'error']);
/** What their CRLs say ({@link estateStatusCounts}). */
export const ESTATE_REVOCATION_STATES = Object.freeze(['revoked', 'unknown', 'good']);

/**
 * How many certificates are where in their CA's renewal window ({@link ESTATE_ARI_STATES}) and
 * what their CRLs say ({@link ESTATE_REVOCATION_STATES}), the CLI's "Renewal windows and
 * revocation" line; a part is null when no certificate has its record.
 * @param {{ certificates?: EstateCertificate[] }} estate
 * @returns {{ ari: Record<string, number>|null, revocation: Record<string, number>|null }}
 */
export function estateStatusCounts(estate) {
  const certs = (estate && estate.certificates) || [];
  const withAri = certs.filter((c) => isObject(c.ari));
  const withRevocation = certs.filter((c) => isObject(c.revocation));
  const ari = withAri.length ? Object.fromEntries(ESTATE_ARI_STATES.map((s) => [s, 0])) : null;
  for (const c of withAri) ari[isObject(c.ariWindow) ? c.ariWindow.state : 'error'] += 1;
  const revocation = withRevocation.length ? Object.fromEntries(ESTATE_REVOCATION_STATES.map((s) => [s, 0])) : null;
  for (const c of withRevocation) revocation[c.revocation.status === 'good' || c.revocation.status === 'revoked' ? c.revocation.status : 'unknown'] += 1;
  return { ari, revocation };
}

/** A certificate's cells of the {@link estateStatusColumns} (the CLI's status_csv_cells). */
function statusCells(cert, columns) {
  const ari = isObject(cert.ari) ? cert.ari : {};
  const rev = isObject(cert.revocation) ? cert.revocation : {};
  const value = {
    ari_start: ari.start || '', ari_end: ari.end || '', ari_explanation: ari.explanationURL || '', ari_error: ari.error || '',
    revocation: rev.status || '', revoked_at: rev.time || '', revocation_reason: rev.reason || '', revocation_error: rev.error || ''
  };
  return Object.fromEntries(columns.map((c) => [c.key, value[c.key]]));
}

/**
 * The CSV text of {@link estateCsvRows} (lib/export.js toCsv: BOM, CRLF, spreadsheet-safe cells).
 * @param {{ certificates: EstateCertificate[] }} estate
 * @param {{ certificates?: EstateCertificate[], reportName?: (endpoint: EstateEndpoint, cert: EstateCertificate) => string }} [opts]
 * @returns {string}
 */
export function estateCsv(estate, opts = {}) {
  const columns = [...ESTATE_CSV_COLUMNS, ...estateStatusColumns(estate), ...estateTrustColumns(estate),
    ...(opts.reportName ? [{ key: 'report', header: 'report' }] : [])];
  return toCsv(estateCsvRows(estate, opts), columns);
}
