/**
 * certsets.js — several certificates renewed together ("renewal week" in SSL Targets).
 *
 * A renewal week often brings more than one certificate: an RSA + ECDSA pair for the same
 * names, plus a few others. SSL Targets takes them all (several files, a folder, or several PEM
 * blocks pasted at once), scans the union of their names once, and plans which set each server
 * needs:
 *
 *   - {@link renewalBundle}: the end-entity certificates of the loaded files (a chain's CA
 *     certificates are kept apart as `chain`, the same certificate from two files is one leaf,
 *     files without a usable certificate are listed in `skipped`), grouped into sets;
 *   - {@link groupCertSets}: leaves whose name sets are equal form one set (typically an RSA +
 *     ECDSA twin pair), ids 'A', 'B', … in the order they were loaded;
 *   - {@link assignSet}: the set a host name gets — an exact name before a wildcard, the most
 *     specific wildcard, then the set whose certificate expires last;
 *   - {@link planRenewal}: over a lib/scanner ScanResult, the server × set matrix (the names each
 *     server needs from each set) and the names no certificate covers;
 *   - {@link workListRows} (CSV work list) and {@link cliCertFiles} (one `--cert` file per
 *     certificate for the companion CLI).
 *
 * DOM-free and pure (runs in Node); certificates are lib/x509.js objects.
 */

import { certCovers, sortHostnames } from './domain.js';
import { leafCertificates } from './x509.js';

/** Why a loaded file adds no certificate to the renewal. */
export const SKIP_ISSUES = Object.freeze(['no-certificate', 'ca-only', 'no-names']);

/** Tie-break order of how a server reaches a name (lib/scanner ServerGroup.hosts[].via). */
const VIA_RANK = { dns: 0, zone: 1, hint: 2 };

/**
 * @typedef {object} CertFileInput One loaded file: a views/cert.js CertLoad, or its fields.
 * @property {string} [name] file name (the view names pasted text)
 * @property {{ certificates: object[], warnings?: Array<{ code: string }> }} [result]
 *   lib/x509 parseCertificates() result (a bare result is accepted too)
 */

/**
 * @typedef {object} RenewalLeaf
 * @property {string} key identity: the DER as hex, so one certificate from two files is one leaf
 * @property {object} cert x509 Certificate
 * @property {string[]} names its host names (lowercase, deduplicated, sortHostnames order)
 * @property {string[]} files the files it came from, first seen first
 * @property {string} keyType e.g. 'RSA 2048', 'ECDSA P-256', 'Ed25519' (not translated)
 * @property {string} keySlug 'rsa' | 'ecdsa' | 'ed25519' | 'ed448' | 'dsa' | 'cert' (file names)
 */

/**
 * @typedef {object} CertSet
 * @property {string} id 'A', 'B', … 'Z', 'AA', … in load order
 * @property {string[]} names the name set its leaves share
 * @property {RenewalLeaf[]} leaves
 * @property {object[]} certs the leaves' Certificates (lib/verify expectationFor input)
 * @property {string[]} keyTypes distinct, in leaf order
 * @property {string[]} files every file its leaves came from
 * @property {Date|null} notAfter the latest notAfter of its leaves (the assignment tie-break)
 * @property {Date|null} expires the earliest notAfter (when the set runs out)
 */

/**
 * @typedef {object} RenewalBundle
 * @property {RenewalLeaf[]} leaves in load order
 * @property {CertSet[]} sets
 * @property {object[]} chain the other certificates of the files (intermediates, roots), deduplicated
 * @property {Array<{ file: string, index: number, issue: string, codes: string[], subject?: string, count?: number, key?: string }>} skipped
 *   files (or leaves) that add nothing, `index` being the file's position in the input: 'no-certificate'
 *   (a key, a CSR, a PKCS#12 bundle, junk; `codes` are the parser's warning codes), 'ca-only' (CA
 *   certificates only, `count` of them), 'no-names' (a leaf without a DNS name: `subject` its CN or
 *   DN, `key` its {@link leafKey}, for {@link withoutLeaf})
 * @property {number} duplicates leaves that were already loaded from another file
 * @property {string[]} keyFiles files that also held a private key (ignored, never displayed)
 */

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/**
 * A certificate's identity across files ({@link RenewalLeaf} `key`): its DER as hex.
 * @param {object} cert x509 Certificate
 * @returns {string}
 */
export function leafKey(cert) {
  return derKey(cert);
}

/** The DER of a certificate as hex (identity across files). */
function derKey(cert) {
  const der = cert && cert.der;
  if (!der || !Number.isFinite(der.length)) return `${cert && cert.serialHex}|${cert && cert.issuerDN}`;
  let out = '';
  for (let i = 0; i < der.length; i += 1) out += HEX[der[i]];
  return out;
}

/** A certificate's host names: lowercase, deduplicated, in sortHostnames order. */
function namesOf(cert) {
  const list = Array.isArray(cert && cert.hostnames) ? cert.hostnames : [];
  return sortHostnames([...new Set(list.map((n) => String(n).toLowerCase()).filter(Boolean))]);
}

/**
 * The key of a certificate as a short technical label and a file-name slug.
 * @param {object} cert x509 Certificate
 * @returns {{ label: string, slug: string }}
 */
export function keyTypeOf(cert) {
  const bits = cert && Number.isFinite(cert.keyBits) ? cert.keyBits : null;
  switch (cert && cert.keyAlgorithm) {
    case 'RSA': return { label: bits ? `RSA ${bits}` : 'RSA', slug: 'rsa' };
    case 'EC': return { label: cert.curve ? `ECDSA ${cert.curve}` : bits ? `ECDSA ${bits}` : 'ECDSA', slug: 'ecdsa' };
    case 'Ed25519': return { label: 'Ed25519', slug: 'ed25519' };
    case 'Ed448': return { label: 'Ed448', slug: 'ed448' };
    case 'DSA': return { label: bits ? `DSA ${bits}` : 'DSA', slug: 'dsa' };
    default: return { label: String((cert && cert.keyAlgorithm) || 'unknown'), slug: 'cert' };
  }
}

/**
 * Set id of the i-th set: 'A' … 'Z', then 'AA', 'AB', … (spreadsheet columns).
 * @param {number} index 0-based
 * @returns {string}
 */
export function setId(index) {
  let n = Math.max(0, Math.floor(Number(index) || 0)) + 1;
  let out = '';
  while (n > 0) {
    const r = (n - 1) % 26;
    out = String.fromCharCode(65 + r) + out;
    n = Math.floor((n - 1) / 26);
  }
  return out;
}

const time = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.getTime() : null);

/** A set's certificates by key type, whatever the order they were loaded in (a folder lists files by name). */
const KEY_ORDER = ['rsa', 'ecdsa', 'ed25519', 'ed448', 'dsa', 'cert'];
const keyRank = (leaf) => {
  const i = KEY_ORDER.indexOf(leaf.keySlug);
  return i < 0 ? KEY_ORDER.length : i;
};

/**
 * Leaves whose name sets are equal form one set (an RSA + ECDSA pair for the same names is one
 * set with two key types). Sets keep the order their first leaf was loaded in; within a set the
 * certificates go by key type (RSA, ECDSA, Ed25519, Ed448, DSA), then load order, so the list and
 * the CLI's file names do not depend on the order the files came in.
 * @param {RenewalLeaf[]} leaves
 * @returns {CertSet[]}
 */
export function groupCertSets(leaves) {
  const sets = [];
  const byNames = new Map();
  for (const leaf of Array.isArray(leaves) ? leaves : []) {
    if (!leaf || !Array.isArray(leaf.names) || !leaf.names.length) continue;
    const k = leaf.names.join('\n');
    let set = byNames.get(k);
    if (!set) {
      set = { id: setId(sets.length), names: leaf.names.slice(), leaves: [], certs: [], keyTypes: [], files: [], notAfter: null, expires: null };
      sets.push(set);
      byNames.set(k, set);
    }
    set.leaves.push(leaf);
  }
  for (const set of sets) {
    set.leaves = set.leaves.map((leaf, i) => ({ leaf, i })).sort((a, b) => keyRank(a.leaf) - keyRank(b.leaf) || a.i - b.i).map((x) => x.leaf);
    for (const leaf of set.leaves) {
      set.certs.push(leaf.cert);
      if (!set.keyTypes.includes(leaf.keyType)) set.keyTypes.push(leaf.keyType);
      for (const f of leaf.files) if (!set.files.includes(f)) set.files.push(f);
      const end = time(leaf.cert && leaf.cert.notAfter);
      if (end !== null) {
        if (set.notAfter === null || end > set.notAfter.getTime()) set.notAfter = new Date(end);
        if (set.expires === null || end < set.expires.getTime()) set.expires = new Date(end);
      }
    }
  }
  return sets;
}

/**
 * The renewal behind the loaded files: every end-entity certificate (lib/x509 leafCertificates:
 * a chain gives one, several pasted PEM blocks give each), grouped into sets.
 * @param {CertFileInput[]} files in load order
 * @returns {RenewalBundle}
 */
export function renewalBundle(files) {
  const leaves = [];
  const byKey = new Map();
  const chain = [];
  const chainKeys = new Set();
  const noNames = new Set();
  const skipped = [];
  let duplicates = 0;
  const keyFiles = [];
  (Array.isArray(files) ? files : []).forEach((f, index) => {
    if (!f || typeof f !== 'object') return;
    const file = String(f.name ?? '');
    const result = f.result && typeof f.result === 'object' ? f.result : f;
    const certs = Array.isArray(result.certificates) ? result.certificates.filter(Boolean) : [];
    const codes = [...new Set((Array.isArray(result.warnings) ? result.warnings : []).map((w) => w && w.code).filter(Boolean))];
    if (certs.length && codes.includes('PRIVATE_KEY_PRESENT') && !keyFiles.includes(file)) keyFiles.push(file);
    if (!certs.length) {
      skipped.push({ file, index, issue: 'no-certificate', codes });
      return;
    }
    const ends = leafCertificates(certs);
    for (const c of certs) {
      if (ends.includes(c)) continue;
      const k = derKey(c);
      if (!chainKeys.has(k)) {
        chainKeys.add(k);
        chain.push(c);
      }
    }
    if (!ends.length) {
      skipped.push({ file, index, issue: 'ca-only', codes, count: certs.length });
      return;
    }
    for (const cert of ends) {
      const key = derKey(cert);
      const seen = byKey.get(key);
      if (seen) {
        duplicates += 1;
        if (!seen.files.includes(file)) seen.files.push(file);
        continue;
      }
      const names = namesOf(cert);
      if (!names.length) {
        if (!noNames.has(key)) skipped.push({ file, index, issue: 'no-names', codes, subject: cert.subjectCN || cert.subjectDN || '', key });
        noNames.add(key);
        continue;
      }
      const kt = keyTypeOf(cert);
      const leaf = { key, cert, names, files: [file], keyType: kt.label, keySlug: kt.slug };
      byKey.set(key, leaf);
      leaves.push(leaf);
    }
  });
  return { leaves, sets: groupCertSets(leaves), chain, skipped, duplicates, keyFiles };
}

const certsOfFile = (f) => {
  const result = f && f.result && typeof f.result === 'object' ? f.result : f;
  return result && Array.isArray(result.certificates) ? result.certificates.filter(Boolean) : [];
};

/**
 * The files without one certificate of the renewal (its Remove button): every file holding it
 * loses it, and a file left without a leaf is dropped (a fullchain.pem whose leaf is removed
 * would only add its chain). Files that never had a leaf (a key, a CSR) stay until removed
 * themselves. Changed files are shallow copies with a new `result` (`certificates`, `leaf`).
 * @template {CertFileInput} F
 * @param {F[]} files
 * @param {string} key {@link leafKey} of the certificate
 * @returns {F[]}
 */
export function withoutLeaf(files, key) {
  const out = [];
  for (const f of Array.isArray(files) ? files : []) {
    if (!f) continue;
    const certs = certsOfFile(f);
    const kept = certs.filter((c) => derKey(c) !== key);
    if (kept.length === certs.length) {
      out.push(f);
      continue;
    }
    const leaves = leafCertificates(kept);
    if (!leaves.length) continue;
    const result = f.result && typeof f.result === 'object' ? f.result : f;
    const next = { ...result, certificates: kept, leaf: leaves[0] };
    out.push(f.result && typeof f.result === 'object' ? { ...f, result: next } : next);
  }
  return out;
}

/**
 * The file that stands for the renewal where one certificate is shown (the Certificate view):
 * the first file with a leaf certificate, else the first file; null without files.
 * @template {CertFileInput} F
 * @param {F[]} files
 * @returns {F|null}
 */
export function primaryFile(files) {
  const list = (Array.isArray(files) ? files : []).filter(Boolean);
  return list.find((f) => leafCertificates(certsOfFile(f)).length > 0) || list[0] || null;
}

/**
 * A file that shows one certificate of the renewal on its own (Details on it): the file it came
 * from when that file's `leaf` is it, else a copy of that file with it as the leaf, next to the
 * file's CA certificates (its chain) but without the file's other leaves.
 * @template {CertFileInput} F
 * @param {F[]} files
 * @param {string} key {@link leafKey} of the certificate
 * @returns {F|null} null when no file holds it
 */
export function fileForLeaf(files, key) {
  for (const f of Array.isArray(files) ? files : []) {
    if (!f) continue;
    const certs = certsOfFile(f);
    const cert = certs.find((c) => derKey(c) === key);
    if (!cert) continue;
    const result = f.result && typeof f.result === 'object' ? f.result : f;
    if (result.leaf === cert) return f;
    const others = leafCertificates(certs);
    const next = { ...result, certificates: [cert, ...certs.filter((c) => c !== cert && !others.includes(c))], leaf: cert };
    return f.result && typeof f.result === 'object' ? { ...f, result: next } : next;
  }
  return null;
}

/** Number of labels of a name ('*.shop.example.com' → 4). */
const labelCount = (name) => String(name || '').split('.').length;

/**
 * The set a host name gets, of those that cover it: a set naming it exactly before one covering
 * it with a wildcard, then the most specific wildcard (the one with more labels), then the set
 * whose certificate expires last, then the set loaded first.
 * @param {string} name host name
 * @param {CertSet[]} sets
 * @returns {{ set: CertSet, by: string, exact: boolean }|null} null when no set covers it
 */
export function assignSet(name, sets) {
  let best = null;
  (Array.isArray(sets) ? sets : []).forEach((set, index) => {
    if (!set || !Array.isArray(set.names)) return;
    const cov = certCovers(set.names, name);
    if (!cov.covered) return;
    const exact = !String(cov.by).includes('*');
    const cand = { set, by: cov.by, exact, spec: exact ? Infinity : labelCount(cov.by), end: time(set.notAfter) ?? -Infinity, index };
    const better = !best
      || (cand.exact !== best.exact ? cand.exact
        : cand.spec !== best.spec ? cand.spec > best.spec
          : cand.end !== best.end ? cand.end > best.end
            : cand.index < best.index);
    if (better) best = cand;
  });
  return best ? { set: best.set, by: best.by, exact: best.exact } : null;
}

/**
 * {@link assignSet} as a memoised lookup name → set id (null when no set covers the name), for
 * lib/verify buildVerifyPairs({ setOf }).
 * @param {CertSet[]} sets
 * @returns {(name: string) => string|null}
 */
export function setOfName(sets) {
  const memo = new Map();
  return (name) => {
    const k = String(name ?? '');
    if (!memo.has(k)) {
      const a = assignSet(k, sets);
      memo.set(k, a ? a.set.id : null);
    }
    return memo.get(k);
  };
}

const resolves = (host) => !!host && !!host.resolution
  && ((host.resolution.ipv4 || []).length > 0 || (host.resolution.ipv6 || []).length > 0);

/**
 * @typedef {object} PlanEntry
 * @property {string} name
 * @property {string[]} ips the server addresses that serve it
 * @property {'dns'|'zone'|'hint'} via the strongest match (an origin hint is only a candidate)
 */

/**
 * @typedef {object} PlanRow One row of the server × set matrix.
 * @property {string} key 's:<server id>' or 'ip:<address>'
 * @property {{ id: string, name: string, ips: string[], groups: string[] }|null} server null for an
 *   address that is in no inventory server (ScanResult.unmatchedIps)
 * @property {string|null} ip that address (null for a server row)
 * @property {boolean} private the unmatched address is private
 * @property {Record<string, PlanEntry[]>} cells set id → the names it needs from that set
 * @property {boolean} needsCert a DNS or zone-file name needs a certificate here
 * @property {boolean} maybe only origin hints point here
 */

/**
 * @typedef {object} RenewalPlan
 * @property {CertSet[]} sets
 * @property {Map<string, { set: string, by: string, exact: boolean }>} assigned every scanned
 *   host a set covers (wildcard look-alikes left out) → its set
 * @property {Array<{ name: string, servers: Array<{ name: string, ip: string }>, resolving: boolean }>} uncovered
 *   scanned hosts no certificate covers: those on your servers first, then the resolving ones
 * @property {PlanRow[]} rows your servers that need a set (scan order), then addresses outside the inventory
 * @property {Record<string, { names: number, rows: number, servers: number, addresses: number }>} perSet per set:
 *   the names assigned to it and the matrix rows needing it — `servers` of your inventory, `addresses`
 *   outside it (`rows` = both)
 */

/**
 * The server × set matrix of a scan: for each inventory server (and each address outside the
 * inventory) the names it serves from each set, per {@link assignSet}; plus the scanned names no
 * set covers. Wildcard look-alikes (`wildcardSuspect`) are left out, as the Servers tab and
 * Verify do.
 * @param {object} result lib/scanner ScanResult (hosts, servers, unmatchedIps)
 * @param {CertSet[]} sets
 * @returns {RenewalPlan}
 */
export function planRenewal(result, sets) {
  const r = result && typeof result === 'object' ? result : {};
  const list = Array.isArray(sets) ? sets : [];
  const hosts = Array.isArray(r.hosts) ? r.hosts : [];
  const assigned = new Map();
  const uncovered = [];
  for (const host of hosts) {
    if (!host || typeof host.name !== 'string' || host.wildcardSuspect) continue;
    const a = assignSet(host.name, list);
    if (a) assigned.set(host.name, { set: a.set.id, by: a.by, exact: a.exact });
    else {
      uncovered.push({
        name: host.name,
        servers: (host.servers || []).map((s) => ({ name: String(s.name ?? ''), ip: String(s.ip ?? '') })),
        resolving: resolves(host)
      });
    }
  }
  const order = new Map(sortHostnames(uncovered.map((u) => u.name)).map((n, i) => [n, i]));
  uncovered.sort((a, b) => Number(!a.servers.length) - Number(!b.servers.length)
    || Number(!a.resolving) - Number(!b.resolving) || order.get(a.name) - order.get(b.name));

  const sortCells = (cells) => {
    for (const id of Object.keys(cells)) {
      const pos = new Map(sortHostnames(cells[id].map((e) => e.name)).map((n, i) => [n, i]));
      cells[id].sort((a, b) => pos.get(a.name) - pos.get(b.name));
    }
    return cells;
  };
  const addEntry = (cells, name, ip, via) => {
    const a = assigned.get(name);
    if (!a) return;
    const entries = cells[a.set] || (cells[a.set] = []);
    let e = entries.find((x) => x.name === name);
    if (!e) {
      e = { name, ips: [], via: VIA_RANK[via] !== undefined ? via : 'dns' };
      entries.push(e);
    } else if ((VIA_RANK[via] ?? 0) < VIA_RANK[e.via]) e.via = via;
    if (ip && !e.ips.includes(ip)) e.ips.push(String(ip));
  };

  const rows = [];
  for (const g of Array.isArray(r.servers) ? r.servers : []) {
    if (!g || !g.server) continue;
    const cells = {};
    for (const e of Array.isArray(g.hosts) ? g.hosts : []) if (e && e.covered !== false) addEntry(cells, e.name, e.ip, e.via);
    if (!Object.keys(cells).length) continue;
    const all = Object.values(cells).flat();
    const s = g.server;
    rows.push({
      key: `s:${s.id ?? s.name}`,
      server: { id: String(s.id ?? s.name ?? ''), name: String(s.name ?? s.id ?? ''), ips: [...(s.ips || [])], groups: [...(s.groups || [])] },
      ip: null,
      private: false,
      cells: sortCells(cells),
      needsCert: all.some((x) => x.via !== 'hint'),
      maybe: all.every((x) => x.via === 'hint')
    });
  }
  for (const u of Array.isArray(r.unmatchedIps) ? r.unmatchedIps : []) {
    if (!u || !u.ip) continue;
    const cells = {};
    for (const name of Array.isArray(u.hosts) ? u.hosts : []) addEntry(cells, name, u.ip, 'dns');
    if (!Object.keys(cells).length) continue;
    rows.push({ key: `ip:${u.ip}`, server: null, ip: String(u.ip), private: !!u.private, cells: sortCells(cells), needsCert: true, maybe: false });
  }

  const perSet = {};
  for (const s of list) {
    let names = 0;
    for (const a of assigned.values()) if (a.set === s.id) names += 1;
    const needing = rows.filter((row) => row.cells[s.id]);
    const servers = needing.filter((row) => row.server).length;
    perSet[s.id] = { names, rows: needing.length, servers, addresses: needing.length - servers };
  }
  return { sets: list, assigned, uncovered, rows, perSet };
}

/** A list joined with `sep` for a CSV cell (not an array: toCsv would join it with spaces). */
const joined = (key, sep) => (row) => (Array.isArray(row && row[key]) ? row[key].join(sep) : '');

/**
 * Columns of {@link workListRows} for lib/export toCsv (English headers, like HOST_COLUMNS).
 * Names, candidates and addresses never hold a space, so toCsv joins them with spaces as the
 * other exports do; key types ("RSA 2048") and file names ("cert (1).pem") can, so they are
 * joined with " + " and "; ".
 * @type {ReadonlyArray<{ key: string, header: string, get?: (row: object) => string }>}
 */
export const WORKLIST_COLUMNS = Object.freeze([
  { key: 'server', header: 'Server' },
  { key: 'ip', header: 'IP' },
  { key: 'names', header: 'Names' },
  { key: 'candidates', header: 'Possible origin names' },
  { key: 'set', header: 'Certificate set' },
  { key: 'keyTypes', header: 'Key types', get: joined('keyTypes', ' + ') },
  { key: 'expires', header: 'Expires' },
  { key: 'files', header: 'Files', get: joined('files', '; ') }
].map((c) => Object.freeze(c)));

/**
 * The per-server work list: one row per server (or address) and set it needs, in matrix order.
 * `names` are the names DNS or the zone file ties to it, `candidates` those only an origin hint
 * points at (confirm them with the CLI first); `ip` the addresses serving them. List fields stay
 * arrays ({@link WORKLIST_COLUMNS} says how each is joined in the CSV).
 * @param {RenewalPlan} plan
 * @returns {Array<{ server: string, ip: string[], names: string[], candidates: string[], set: string,
 *   setNames: string[], keyTypes: string[], expires: Date|null, files: string[] }>}
 */
export function workListRows(plan) {
  const out = [];
  const sets = plan && Array.isArray(plan.sets) ? plan.sets : [];
  for (const row of plan && Array.isArray(plan.rows) ? plan.rows : []) {
    for (const set of sets) {
      const entries = row.cells[set.id];
      if (!entries || !entries.length) continue;
      const ips = [...new Set(entries.flatMap((e) => e.ips))];
      out.push({
        server: row.server ? row.server.name : '',
        ip: ips.length ? ips : row.ip ? [row.ip] : [],
        names: entries.filter((e) => e.via !== 'hint').map((e) => e.name),
        candidates: entries.filter((e) => e.via === 'hint').map((e) => e.name),
        set: set.id,
        setNames: set.names.slice(),
        keyTypes: set.keyTypes.slice(),
        expires: set.expires,
        files: set.files.slice()
      });
    }
  }
  return out;
}

/**
 * One file per certificate for the companion CLI's repeated `--cert` (a served certificate
 * matching any of them is UPDATED there): `new-cert-<set>-<key>.pem`, e.g. new-cert-a-rsa.pem,
 * new-cert-a-ecdsa.pem, new-cert-b-rsa.pem; a second leaf with the same set and key type gets
 * `-2`. Every name is a plain path token lib/cmdline accepts.
 * @param {CertSet[]} sets
 * @returns {Array<{ file: string, set: string, leaf: RenewalLeaf }>}
 */
export function cliCertFiles(sets) {
  const used = new Set();
  const out = [];
  for (const set of Array.isArray(sets) ? sets : []) {
    for (const leaf of set.leaves || []) {
      const base = `new-cert-${String(set.id).toLowerCase()}-${leaf.keySlug || 'cert'}`;
      let file = `${base}.pem`;
      for (let n = 2; used.has(file); n += 1) file = `${base}-${n}.pem`;
      used.add(file);
      out.push({ file, set: set.id, leaf });
    }
  }
  return out;
}

/**
 * The sets for a JSON export: ids, names, key types and each certificate's identity (never the DER).
 * @param {CertSet[]} sets
 * @returns {object[]}
 */
export function certSetsJson(sets) {
  return (Array.isArray(sets) ? sets : []).map((s) => ({
    id: s.id,
    names: s.names.slice(),
    keyTypes: s.keyTypes.slice(),
    expires: s.expires,
    certificates: s.leaves.map((l) => ({
      subject: l.cert.subjectDN ?? null,
      issuer: l.cert.issuerDN ?? null,
      serialHex: l.cert.serialHex ?? null,
      notBefore: l.cert.notBefore ?? null,
      notAfter: l.cert.notAfter ?? null,
      keyType: l.keyType,
      files: l.files.slice()
    }))
  }));
}
