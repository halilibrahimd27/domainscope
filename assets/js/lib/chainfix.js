/**
 * chainfix.js — the missing intermediate, found and added, and what the root at the end of the
 * chain faces in the root stores.
 *
 * The most common installation error is a server that sends its certificate without the
 * intermediate. Browsers often hide it (they cache intermediates or fetch them), while Android,
 * curl, Java and most API clients fail. The browser cannot fetch the certificate's AIA
 * caIssuers URL (plain http, no CORS), so the app ships its own list instead: every current
 * public TLS intermediate of the Common CA Database (CCADB) that a root store trusts, built by
 * tools/build-intermediates.mjs into assets/data/intermediates/ — sharded by subject key
 * identifier, so each issuer looked up reads one file of about 16 KB — plus a table of the roots
 * (which root stores include each one for TLS) and the announced lifecycle events of the roots
 * (distrust dates, expiry).
 *
 * - {@link repairChain}: the file's chain from the leaf; when it stops at an intermediate whose
 *   issuer is neither in the file nor a known root, the issuers are looked up by the authority
 *   key id (the issuer's subject key id; by the issuer DN when the certificate names no key id),
 *   up to {@link MAX_ADDED} of them, until a root is reached. Among several candidates (a
 *   re-issued intermediate, a cross-signed one) the path to the root the most root stores trust
 *   for this certificate wins, then the one with the fewest lifecycle warnings, the shortest,
 *   and the one that expires last. The result is the chain servers must send (fullchain.pem:
 *   the leaf, then each intermediate, never the root) and what was added from where.
 * - {@link chainStanding}: the roots the chain can end at — the last one, and a cross-signed
 *   root inside the chain, where a client that holds it stops — store by store (Chrome,
 *   Mozilla, Apple, Microsoft), with the warnings a certificate under them gets: a store that
 *   distrusts certificates issued after a date (Chrome counts the earliest embedded SCT), a store
 *   that removed the root, a root that expires before the certificate does or has expired.
 *
 * Only files of the app's own site are read, never a certificate or a URL of a third party.
 * DOM-free; the network is `fetchImpl` (tests read the files from disk).
 */

import { parseCertificate, issuedBy } from './x509.js';
import { sha256 } from './sha.js';
import { fetchJson, throwIfAborted } from './util.js';

/** The dataset's manifest, relative to this module (it moves under v/<commit>/ in the Pages bundle). */
export const DATASET_URL = new URL('../../data/intermediates/manifest.json', import.meta.url).href;
/** The dataset format this module reads (manifest.json `format`). */
export const DATASET_FORMAT = 1;
/** The root stores, in display order. */
export const STORES = Object.freeze(['chrome', 'mozilla', 'apple', 'microsoft']);
/**
 * A root's status in one store (roots.json `stores`): `tls` included for server authentication,
 * `other` included for other uses only (Mozilla's e-mail-only roots), `not-before` Microsoft's
 * cut-off for newly issued certificates, `removed` removed or blocked, `absent` never included.
 */
export const STORE_STATUSES = Object.freeze(['tls', 'other', 'not-before', 'removed', 'absent']);
/** Every root-store warning {@link chainStanding} can give ({@link LifecycleWarning} code). */
export const LIFECYCLE_CODES = Object.freeze(['distrusted', 'renewal-distrusted', 'removed', 'not-for-tls', 'cut-off', 'not-included', 'root-expired', 'root-expires']);
/** At most this many intermediates are added to one chain. */
export const MAX_ADDED = 4;
/** Hex digits of a DN hash ({@link dnHash}). */
export const DN_HASH_DIGITS = 16;

const HEX_RE = /^[0-9a-f]+$/;
const DAY_MS = 86400000;

/**
 * The key of a distinguished name in the dataset's DN index: SHA-256 of its RFC 2253 form as
 * lib/x509.js writes it (UTF-8), the first {@link DN_HASH_DIGITS} hex digits. Build and page
 * use the same parser, so the same DN gives the same key.
 * @param {string} dn
 * @returns {string}
 */
export function dnHash(dn) {
  const digest = sha256(new TextEncoder().encode(String(dn ?? '')));
  let hex = '';
  for (const b of digest) hex += b.toString(16).padStart(2, '0');
  return hex.slice(0, DN_HASH_DIGITS);
}

/**
 * The shard file name of a key: its first `digits` hex digits.
 * @param {string} key lowercase hex (a subject key id or a DN hash)
 * @param {number} digits
 * @returns {string|null} null for a key that is not hex or too short
 */
export function shardOf(key, digits) {
  const k = String(key || '').toLowerCase();
  if (!HEX_RE.test(k) || k.length < digits || !Number.isInteger(digits) || digits < 1) return null;
  return k.slice(0, digits);
}

/**
 * A date of the dataset as a Date: 'YYYY-MM-DD' is the end of that day (UTC), so "issued after
 * 2024-11-11" means after 2024-11-11 23:59:59.999; a full ISO time is taken as it is.
 * @param {string|null|undefined} value
 * @returns {Date|null}
 */
export function datasetDate(value) {
  if (typeof value !== 'string' || !value) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const d = m ? new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) + DAY_MS - 1) : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Base64 → bytes (atob is in browsers and in Node). */
function fromBase64(b64) {
  const bin = globalThis.atob(String(b64));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * @typedef {object} RootInfo a root of roots.json
 * @property {string} sha256 lowercase hex fingerprint of the root certificate
 * @property {string} name
 * @property {string} owner CA owner as CCADB names it
 * @property {string|null} ski subject key id (lowercase hex)
 * @property {string|null} dn subject DN (lib/x509.js form) when known
 * @property {Date|null} notAfter
 * @property {Record<string, string>} stores store → {@link STORE_STATUSES}
 * @property {LifecycleEvent[]} events
 */

/**
 * @typedef {object} LifecycleEvent one row of the lifecycle table (roots.json `events`)
 * @property {'distrust-after'|'expiry'} type
 * @property {string|null} store the store a distrust applies to; null for an expiry
 * @property {Date} date distrust-after: certificates issued after it; expiry: the root's end
 * @property {'sct'|'notBefore'|null} basis what "issued" means: the earliest embedded SCT (Chrome) or notBefore
 * @property {string|null} url the announcement, or the CCADB report the date was taken from
 * @property {'announcement'|'ccadb'|null} source what `url` is (null without a url)
 */

/**
 * The roots table of a parsed roots.json: the roots with their lifecycle events, indexed by
 * subject key id and DN.
 * @param {any} json
 * @returns {{ generated: string|null, roots: RootInfo[], bySki: Map<string, RootInfo[]>, byDn: Map<string, RootInfo[]> }}
 */
export function rootTable(json) {
  const data = json && typeof json === 'object' ? json : {};
  const events = new Map();
  for (const e of Array.isArray(data.events) ? data.events : []) {
    if (!e || typeof e.root !== 'string' || !['distrust-after', 'expiry'].includes(e.type)) continue;
    const date = datasetDate(e.date);
    if (!date) continue;
    const key = e.root.toLowerCase();
    const url = typeof e.url === 'string' && /^https:\/\//.test(e.url) ? e.url : null;
    const list = events.get(key) || [];
    list.push({
      type: e.type,
      store: e.type === 'expiry' ? null : (STORES.includes(e.store) ? e.store : null),
      date,
      basis: e.basis === 'sct' ? 'sct' : e.type === 'expiry' ? null : 'notBefore',
      url,
      source: url ? (e.source === 'ccadb' ? 'ccadb' : 'announcement') : null
    });
    events.set(key, list);
  }
  const roots = [];
  const bySki = new Map();
  const byDn = new Map();
  const add = (map, key, root) => {
    if (!key) return;
    const list = map.get(key) || [];
    list.push(root);
    map.set(key, list);
  };
  for (const r of Array.isArray(data.roots) ? data.roots : []) {
    if (!r || typeof r.sha256 !== 'string') continue;
    const stores = {};
    for (const s of STORES) stores[s] = STORE_STATUSES.includes(r.stores && r.stores[s]) ? r.stores[s] : 'absent';
    const root = {
      sha256: r.sha256.toLowerCase(),
      name: String(r.name || ''),
      owner: String(r.owner || ''),
      ski: typeof r.ski === 'string' && HEX_RE.test(r.ski) ? r.ski : null,
      dn: typeof r.dn === 'string' && r.dn ? r.dn : null,
      notAfter: datasetDate(r.notAfter),
      stores,
      events: (events.get(r.sha256.toLowerCase()) || []).sort((a, b) => a.date - b.date)
    };
    roots.push(root);
    add(bySki, root.ski, root);
    add(byDn, root.dn, root);
  }
  return { generated: typeof data.generated === 'string' ? data.generated : null, roots, bySki, byDn };
}

/**
 * The roots of `table` that issued `cert`: by its authority key id (the DN must agree where the
 * table knows it), else by its issuer DN.
 * @param {ReturnType<typeof rootTable>} table
 * @param {import('./x509.js').Certificate} cert
 * @returns {RootInfo[]}
 */
export function rootsIssuing(table, cert) {
  if (!table || !cert) return [];
  if (cert.authorityKeyId) {
    return (table.bySki.get(cert.authorityKeyId) || []).filter((r) => !r.dn || r.dn === cert.issuerDN);
  }
  return (table.byDn.get(cert.issuerDN) || []).slice();
}

/**
 * The entry of `table` for a root certificate the file holds itself (self-signed): by its
 * fingerprint, else by its key id and DN.
 * @param {ReturnType<typeof rootTable>} table
 * @param {import('./x509.js').Certificate} cert
 * @returns {RootInfo|null}
 */
export function rootEntryFor(table, cert) {
  if (!table || !cert || !cert.der) return null;
  const digest = sha256(cert.der);
  let hex = '';
  for (const b of digest) hex += b.toString(16).padStart(2, '0');
  const exact = table.roots.find((r) => r.sha256 === hex);
  return exact || rootsWithKey(table, cert)[0] || null;
}

/**
 * The roots of `table` that `cert` is a copy of: the same subject key id and DN — a cross-signed
 * root, which clients holding that root treat as the end of the chain.
 * @param {ReturnType<typeof rootTable>} table
 * @param {import('./x509.js').Certificate} cert
 * @returns {RootInfo[]}
 */
export function rootsWithKey(table, cert) {
  if (!table || !cert) return [];
  const byKey = cert.subjectKeyId ? (table.bySki.get(cert.subjectKeyId) || []) : (table.byDn.get(cert.subjectDN) || []);
  return byKey.filter((r) => (r.dn ? r.dn === cert.subjectDN : !!cert.subjectKeyId));
}

/**
 * When `cert` was issued as a store counts it: the earliest embedded SCT for Chrome's cut-offs
 * (`basis` 'sct'; notBefore when it has none), else notBefore.
 * @param {import('./x509.js').Certificate} cert
 * @param {'sct'|'notBefore'|null} [basis]
 * @returns {Date}
 */
export function issuedAt(cert, basis = 'notBefore') {
  if (basis === 'sct' && Array.isArray(cert.scts)) {
    const times = cert.scts.map((s) => s && s.timestamp).filter((d) => d instanceof Date && !Number.isNaN(d.getTime()));
    if (times.length) return new Date(Math.min(...times.map((d) => d.getTime())));
  }
  return cert.notBefore;
}

/**
 * One store's view of a root for this certificate: its status from the table, 'distrusted' when
 * the store cut off certificates issued after a date this one is past, 'expired' when the root is.
 */
function storeStatus(root, store, leaf, t) {
  const status = root.stores[store];
  if (status !== 'tls') return { status, event: null };
  const event = root.events.find((e) => e.type === 'distrust-after' && e.store === store && issuedAt(leaf, e.basis).getTime() > e.date.getTime());
  if (event) return { status: 'distrusted', event };
  if (root.notAfter && root.notAfter.getTime() < t) return { status: 'expired', event: null };
  return { status, event: null };
}

/**
 * @typedef {object} LifecycleWarning
 * @property {'distrusted'|'renewal-distrusted'|'removed'|'not-for-tls'|'cut-off'|'not-included'|'root-expired'|'root-expires'} code
 * @property {'error'|'warn'} severity
 * @property {string[]} stores the stores it concerns
 * @property {RootInfo} root the root it is about
 * @property {Date|null} date the cut-off (distrusted, renewal-distrusted) or the root's expiry
 * @property {Date|null} issued distrusted / renewal-distrusted: when the certificate counts as issued
 * @property {string|null} url the announcement, or the CCADB report the date was taken from
 * @property {'announcement'|'ccadb'|null} source what `url` is (null without a url)
 */

/**
 * What a certificate faces in each root store through the roots its chain can end at. `anchors`
 * are those roots, nearest first: a cross-signed root inside the chain (a client that holds it
 * stops there) and the root the chain ends at. Each store trusts the chain through the first
 * anchor it trusts for this certificate; a store that trusts none is judged by the first anchor
 * it knows at all (else the last).
 * Warnings, each naming its root:
 * - distrusted (error): the store cut off certificates of this root issued after a date, and this
 *   one was issued after it (Chrome: its earliest embedded SCT); renewal-distrusted (warn): issued
 *   before, so only the renewal is affected;
 * - removed (error): removed or blocked; not-for-tls (error): kept for other uses only; cut-off
 *   (warn): Microsoft's NotBefore — newer certificates are not trusted; not-included (warn): never
 *   included, while another store does trust the chain;
 * - root-expired (error): the root has expired; root-expires (warn): the lifecycle table's expiry
 *   of a root a store trusts the chain through falls before this certificate's own.
 * @param {RootInfo[]} anchors
 * @param {import('./x509.js').Certificate} leaf
 * @param {Date|number} [now]
 * @returns {{ stores: Record<string, { status: string, root: RootInfo }>, trusted: string[], warnings: LifecycleWarning[] }|null}
 *   stores: each store's status ('tls', 'distrusted', 'expired' or a {@link STORE_STATUSES} value)
 *   and the root it is about; trusted: the stores that trust the chain today; null without anchors
 */
export function chainStanding(anchors, leaf, now = Date.now()) {
  const list = (anchors || []).filter(Boolean);
  if (!list.length || !leaf) return null;
  const t = now instanceof Date ? now.getTime() : Number(now);
  const stores = {};
  const events = {};
  for (const s of STORES) {
    const views = list.map((root) => ({ root, ...storeStatus(root, s, leaf, t) }));
    const pick = views.find((v) => v.status === 'tls') || views.find((v) => v.status !== 'absent') || views[views.length - 1];
    stores[s] = { status: pick.status, root: pick.root };
    events[s] = pick.event;
  }
  const trusted = STORES.filter((s) => stores[s].status === 'tls');
  const warnings = [];
  const grouped = (code, severity, status) => {
    const byRoot = new Map();
    for (const s of STORES) {
      if (stores[s].status !== status) continue;
      const g = byRoot.get(stores[s].root) || [];
      g.push(s);
      byRoot.set(stores[s].root, g);
    }
    for (const [root, group] of byRoot) warnings.push({ code, severity, stores: group, root, date: status === 'expired' ? root.notAfter : null, issued: null, url: null, source: null });
  };
  for (const s of STORES) {
    const { status, root } = stores[s];
    if (status === 'distrusted') {
      const e = events[s];
      warnings.push({ code: 'distrusted', severity: 'error', stores: [s], root, date: e.date, issued: issuedAt(leaf, e.basis), url: e.url, source: e.source });
    } else if (status === 'tls') {
      for (const e of root.events) {
        if (e.type !== 'distrust-after' || e.store !== s) continue;
        warnings.push({ code: 'renewal-distrusted', severity: 'warn', stores: [s], root, date: e.date, issued: issuedAt(leaf, e.basis), url: e.url, source: e.source });
      }
    }
  }
  grouped('removed', 'error', 'removed');
  grouped('not-for-tls', 'error', 'other');
  grouped('root-expired', 'error', 'expired');
  grouped('cut-off', 'warn', 'not-before');
  if (trusted.length) grouped('not-included', 'warn', 'absent');
  const trustedVia = new Map();
  for (const s of trusted) trustedVia.set(stores[s].root, [...(trustedVia.get(stores[s].root) || []), s]);
  for (const [root, group] of trustedVia) {
    for (const e of root.events) {
      if (e.type === 'expiry' && e.date.getTime() >= t && e.date.getTime() < leaf.notAfter.getTime()) {
        warnings.push({ code: 'root-expires', severity: 'warn', stores: group, root, date: e.date, issued: null, url: e.url, source: e.source });
      }
    }
  }
  return { stores, trusted, warnings };
}

/**
 * {@link chainStanding} of a chain that ends at `root` alone.
 * @param {RootInfo} root
 * @param {import('./x509.js').Certificate} leaf
 * @param {Date|number} [now]
 */
export function rootStanding(root, leaf, now = Date.now()) {
  return chainStanding([root], leaf, now);
}

/**
 * The dataset reader: the manifest, the roots table and the intermediates by subject key id or
 * DN, each file fetched once (a failed fetch is forgotten, so the next call tries again).
 * @param {{ url?: string, fetchImpl?: typeof fetch, timeoutMs?: number }} [opts] url: the manifest
 * @returns {{
 *   manifest: () => Promise<object>,
 *   roots: () => Promise<ReturnType<typeof rootTable>>,
 *   bySki: (ski: string) => Promise<Array<{ cert: import('./x509.js').Certificate, owner: string }>>,
 *   byDn: (dn: string) => Promise<Array<{ cert: import('./x509.js').Certificate, owner: string }>>
 * }}
 */
export function createIntermediateStore({ url = DATASET_URL, fetchImpl, timeoutMs = 15000 } = {}) {
  const files = new Map();
  const parsed = new Map();
  const json = (rel) => {
    if (!files.has(rel)) {
      const promise = fetchJson(new URL(rel, url).href, { fetchImpl, timeoutMs, headers: { accept: 'application/json' } });
      files.set(rel, promise);
      promise.catch(() => {
        if (files.get(rel) === promise) files.delete(rel);
      });
    }
    return files.get(rel);
  };
  const manifest = async () => {
    const m = await json('manifest.json');
    if (!m || m.format !== DATASET_FORMAT || !m.shards || !m.shards.ski || !m.shards.dn) {
      throw new Error(`intermediates: unsupported dataset format ${m && m.format}`);
    }
    return m;
  };
  let table = null;
  const roots = async () => {
    const m = await manifest();
    const data = await json(m.roots || 'roots.json');
    if (!table || table.source !== data) table = { source: data, value: rootTable({ ...data, generated: m.generated }) };
    return table.value;
  };
  const shard = async (kind, key) => {
    const m = await manifest();
    const spec = m.shards[kind];
    const name = shardOf(key, spec.digits);
    if (!name) return null;
    return json(`${spec.dir}/${name}.json`);
  };
  const bySki = async (ski) => {
    const key = String(ski || '').toLowerCase();
    if (parsed.has(key)) return parsed.get(key);
    const data = await shard('ski', key);
    const entries = data && Array.isArray(data[key]) ? data[key] : [];
    const out = [];
    for (const e of entries) {
      try {
        out.push({ cert: parseCertificate(fromBase64(e.der)), owner: String(e.owner || '') });
      } catch {
        // a damaged entry is skipped, never fatal
      }
    }
    parsed.set(key, out);
    return out;
  };
  const byDn = async (dn) => {
    const key = dnHash(dn);
    const data = await shard('dn', key);
    const skis = data && Array.isArray(data[key]) ? data[key] : [];
    const lists = await Promise.all(skis.map(bySki));
    return lists.flat().filter((e) => e.cert.subjectDN === dn);
  };
  return { manifest, roots, bySki, byDn };
}

/**
 * The file's chain from `leaf`: each next certificate is the issuer of the one before
 * (lib/x509.js issuedBy), a self-signed issuer ends it as the root the file holds.
 * @param {import('./x509.js').Certificate[]} certs
 * @param {import('./x509.js').Certificate} leaf
 * @returns {{ chain: import('./x509.js').Certificate[], rootCert: import('./x509.js').Certificate|null }}
 *   chain: leaf first, without the root
 */
export function fileChain(certs, leaf) {
  const list = Array.isArray(certs) ? certs.filter(Boolean) : [];
  const chain = [leaf];
  let rootCert = null;
  let cur = leaf;
  while (cur && !cur.selfSigned) {
    const next = list.find((c) => !chain.includes(c) && c !== rootCert && issuedBy(cur, c));
    if (!next) break;
    if (next.selfSigned) {
      rootCert = next;
      break;
    }
    chain.push(next);
    cur = next;
  }
  return { chain, rootCert };
}

/** Valid at `t` (ms). */
const validAt = (cert, t) => cert.notBefore.getTime() <= t && t <= cert.notAfter.getTime();
/** A certificate's identity within one chain search. */
const certId = (c) => `${c.serialHex}|${c.issuerDN}`;

/**
 * How good a path is, for sorting (higher first): the number of stores that trust the
 * certificate through it, then whether it ends at a known root, fewer warnings, fewer added
 * certificates, the later expiry.
 */
function pathKey(path, leaf, t) {
  const standing = chainStanding(path.anchors, leaf, t);
  const expiry = path.certs.length ? Math.min(...path.certs.map((c) => c.notAfter.getTime())) : Infinity;
  return [standing ? standing.trusted.length : -1, path.root ? 1 : 0, standing ? -standing.warnings.length : 0, -path.certs.length, expiry];
}

function comparePaths(a, b, leaf, t) {
  const ka = pathKey(a, leaf, t);
  const kb = pathKey(b, leaf, t);
  for (let i = 0; i < ka.length; i += 1) {
    if (ka[i] !== kb[i]) return kb[i] - ka[i];
  }
  return 0;
}

/**
 * Every way up from `cert` through the dataset: paths of added intermediates ending at a known
 * root (or at an intermediate whose issuer is unknown: root null), each with its anchors (the
 * roots the chain can end at, nearest first). A root trusted by fewer than every store is also
 * looked past: a cross-signed copy of it may reach one more store.
 */
async function pathsFrom(cert, { store, table, leaf, t, depth, seen, anchors, signal }) {
  if (depth >= MAX_ADDED) return [];
  const candidates = cert.authorityKeyId ? await store.bySki(cert.authorityKeyId) : await store.byDn(cert.issuerDN);
  throwIfAborted(signal);
  const out = [];
  for (const { cert: c, owner } of candidates) {
    const id = certId(c);
    if (seen.has(id) || c.selfSigned || !issuedBy(cert, c) || !validAt(c, t)) continue;
    const here = [...anchors, ...rootsWithKey(table, c)];
    const roots = rootsIssuing(table, c);
    for (const root of roots) out.push({ certs: [c], owners: [owner], root, anchors: [...here, root] });
    const partial = !roots.length;
    const complete = roots.some((r) => {
      const standing = chainStanding([...here, r], leaf, t);
      return standing && standing.trusted.length === STORES.length;
    });
    if (complete) continue;
    const next = await pathsFrom(c, { store, table, leaf, t, depth: depth + 1, seen: new Set([...seen, id]), anchors: here, signal });
    for (const p of next) out.push({ certs: [c, ...p.certs], owners: [owner, ...p.owners], root: p.root, anchors: p.anchors });
    if (partial && !next.length) out.push({ certs: [c], owners: [owner], root: null, anchors: here });
  }
  return out;
}

/**
 * @typedef {object} ChainRepair
 * @property {'complete'|'repaired'|'not-found'|'self-signed'|'no-leaf'} status complete: the chain
 *   reaches a root the stores know with what the file holds; repaired: intermediates from the
 *   dataset were added; not-found: the issuer of the file's last certificate is neither a known
 *   root nor in the dataset (a private CA, a very new or an unlisted intermediate); self-signed:
 *   the leaf is its own issuer
 * @property {'missing'|'untrusted-root'|null} reason repaired: an issuer was missing, or the file's
 *   chain ends at a root no store trusts for this certificate and a cross-signed copy leads on
 * @property {import('./x509.js').Certificate|null} leaf
 * @property {import('./x509.js').Certificate[]} chain the file's chain from the leaf, without the root
 * @property {import('./x509.js').Certificate|null} rootCert the root certificate the file holds, if any
 * @property {Array<{ cert: import('./x509.js').Certificate, owner: string }>} added from the dataset, in chain order
 * @property {import('./x509.js').Certificate[]} fullchain what servers send: chain + added (never the root)
 * @property {RootInfo|null} root where the chain ends, when the table knows it
 * @property {RootInfo|null} ownRoot where the file's own chain ends (untrusted-root: the root no store trusts)
 * @property {RootInfo[]} anchors the roots the chain can end at, nearest first ({@link chainStanding})
 * @property {ReturnType<typeof chainStanding>} standing null without anchors
 * @property {{ issuerDN: string, authorityKeyId: string|null }|null} missing not-found: the issuer looked for
 * @property {number} alternatives repaired: the ways to a root the dataset offered (a cross-signed pair counts two)
 * @property {string|null} generated the dataset's date
 */

/**
 * Repair the chain of one loaded file (parseCertificates / loadCertificates result): the file's
 * chain as it is when it reaches a root some store trusts for this certificate (directly or
 * through a cross-signed root it holds), else the best way on through the dataset.
 * @param {{ certificates: import('./x509.js').Certificate[], leaf: import('./x509.js').Certificate|null }} result
 * @param {{ store: ReturnType<typeof createIntermediateStore>, now?: Date|number, signal?: AbortSignal|null }} opts
 * @returns {Promise<ChainRepair>} rejects when the dataset cannot be read (offline, damaged)
 */
export async function repairChain(result, { store, now = Date.now(), signal = null } = {}) {
  const t = now instanceof Date ? now.getTime() : Number(now);
  const leaf = result && result.leaf ? result.leaf : null;
  const manifest = await store.manifest();
  const out = {
    status: 'no-leaf', reason: null, leaf, chain: [], rootCert: null, added: [], fullchain: [], root: null, ownRoot: null, anchors: [], standing: null,
    missing: null, alternatives: 0, generated: typeof manifest.generated === 'string' ? manifest.generated : null
  };
  if (!leaf) return out;
  const table = await store.roots();
  throwIfAborted(signal);
  const { chain, rootCert } = fileChain(result.certificates, leaf);
  Object.assign(out, { chain, rootCert, fullchain: chain.slice() });
  const finish = (status, root, anchors) => {
    out.status = status;
    out.root = root;
    out.anchors = anchors.filter(Boolean);
    out.standing = chainStanding(out.anchors, leaf, t);
    return out;
  };
  if (leaf.selfSigned) {
    const own = rootEntryFor(table, leaf);
    return finish('self-signed', own, [own]);
  }
  const fileAnchors = chain.slice(1).flatMap((c) => rootsWithKey(table, c));
  if (rootCert) {
    const own = rootEntryFor(table, rootCert);
    return finish('complete', own, [...fileAnchors, own]);
  }
  const top = chain[chain.length - 1];
  // The file's own ways to a root: kept unless no store trusts this certificate through them.
  const own = rootsIssuing(table, top).map((root) => ({ certs: [], owners: [], root, anchors: [...fileAnchors, root] }));
  if (!own.length && fileAnchors.length) own.push({ certs: [], owners: [], root: null, anchors: fileAnchors });
  own.sort((a, b) => comparePaths(a, b, leaf, t));
  if (own.length) out.ownRoot = own[0].root || own[0].anchors[own[0].anchors.length - 1];
  const ownStanding = own.length ? chainStanding(own[0].anchors, leaf, t) : null;
  if (ownStanding && ownStanding.trusted.length) return finish('complete', own[0].root, own[0].anchors);
  const seen = new Set(chain.map(certId));
  const found = await pathsFrom(top, { store, table, leaf, t, depth: 0, seen, anchors: fileAnchors, signal });
  const paths = [...own, ...found].sort((a, b) => comparePaths(a, b, leaf, t));
  const best = paths[0];
  if (!best) {
    out.missing = { issuerDN: top.issuerDN, authorityKeyId: top.authorityKeyId || null };
    return finish('not-found', null, []);
  }
  if (!best.certs.length) return finish('complete', best.root, best.anchors);
  out.reason = own.length ? 'untrusted-root' : 'missing';
  out.added = best.certs.map((cert, i) => ({ cert, owner: best.owners[i] }));
  out.fullchain = [...chain, ...best.certs];
  out.alternatives = found.filter((p) => p.root).length;
  return finish('repaired', best.root, best.anchors);
}
