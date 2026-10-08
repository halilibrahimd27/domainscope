/**
 * certdiff.js — old-vs-new certificate comparison: every difference between the certificate the
 * servers send now and the one replacing it, with what each one means for the rollout, ordered by
 * impact, and a one-line verdict (Certificate › Compare, ui/cert-diff-panel.js).
 *
 * Every difference is a {@link CertChange}: a code, its severity and the values the UI words it
 * with. The severities, most severe first:
 *   - `blocker`: something that works with the old certificate fails with the new one whatever the
 *     servers do (a name or address it no longer covers — a wildcard included —, clientAuth or
 *     serverAuth dropped, a key or signature clients refuse, no SCTs, not valid now, no overlap);
 *   - `action`: it deploys safely only with a change on the servers (another issuer: the bundle of
 *     intermediates must change with it; RSA ↔ EC: the TLS 1.2 cipher list; OCSP must-staple);
 *   - `check`: it may break something the certificates do not show (a new key: TLSA records and key
 *     pins; another root: old trust stores; fewer SCTs than the CT policies ask for; another OCSP
 *     responder: outbound firewalls of servers that staple);
 *   - `info`: a difference without a rollout effect (names added, lifetime, URLs, SCT count, …).
 * The verdict: `identical` (the same certificate), `blocked` (a blocker), `steps` (actions),
 * `check` (checks only) or `safe` ("safe to deploy everywhere the old one is").
 *
 * Only a deployment is judged: the new certificate against the old one, both as parsed by
 * lib/x509.js, with the other certificates of their files (their intermediates) when given. A
 * rule fires only for a regression: a weakness both certificates share is no new blocker.
 * DOM-free, no network: the SPKI SHA-256 of both keys ({@link diffCertificates}) comes from Web
 * Crypto; {@link compareCertificates} is the same comparison, synchronous, for given hashes.
 */

import { certCovers, sortHostnames, wildcardMatches } from './domain.js';
import { computeFingerprints, issuedBy } from './x509.js';

/** Severities, most severe first. */
export const CERTDIFF_SEVERITIES = Object.freeze(['blocker', 'action', 'check', 'info']);

/** What a change is about (the "unchanged" line lists the areas without one, identity and validity aside). */
export const CERTDIFF_AREAS = Object.freeze(['identity', 'names', 'key', 'chain', 'validity', 'signature', 'usage', 'ct', 'revocation', 'subject']);

/** The verdicts: the same certificate, a blocker, server-side steps, things to check, nothing at all. */
export const CERTDIFF_VERDICTS = Object.freeze(['identical', 'blocked', 'steps', 'check', 'safe']);

/**
 * Every change code with its severity and area, in impact order (the list order within a severity).
 * @type {ReadonlyArray<readonly [string, string, string]>}
 */
const CODE_TABLE = Object.freeze([
  // blockers
  ['precert', 'blocker', 'identity'],
  ['new-is-ca', 'blocker', 'identity'],
  ['self-signed', 'blocker', 'chain'],
  ['expired', 'blocker', 'validity'],
  ['not-yet-valid', 'blocker', 'validity'],
  ['gap', 'blocker', 'validity'],
  ['name-removed', 'blocker', 'names'],
  ['wildcard-removed', 'blocker', 'names'],
  ['no-san', 'blocker', 'names'],
  ['eku-server-dropped', 'blocker', 'usage'],
  ['eku-client-dropped', 'blocker', 'usage'],
  ['ku-signature-dropped', 'blocker', 'usage'],
  ['key-unsupported', 'blocker', 'key'],
  ['key-weak', 'blocker', 'key'],
  ['key-curve', 'blocker', 'key'],
  ['sig-weak', 'blocker', 'signature'],
  ['sct-none', 'blocker', 'ct'],
  ['staple-no-ocsp', 'blocker', 'revocation'],
  // actions
  ['issuer-changed', 'action', 'chain'],
  ['issuer-rekeyed', 'action', 'chain'],
  ['chain-changed', 'action', 'chain'],
  ['key-type', 'action', 'key'],
  ['staple-added', 'action', 'revocation'],
  // checks
  ['key-new', 'check', 'key'],
  ['root-changed', 'check', 'chain'],
  ['sct-few', 'check', 'ct'],
  ['ku-encipher-dropped', 'check', 'usage'],
  ['ocsp-changed', 'check', 'revocation'],
  // differences without a rollout effect
  ['old-expired', 'info', 'validity'],
  ['name-added', 'info', 'names'],
  ['name-covered', 'info', 'names'],
  ['key-reused', 'info', 'key'],
  ['key-size', 'info', 'key'],
  ['lifetime', 'info', 'validity'],
  ['expires-sooner', 'info', 'validity'],
  ['sig-changed', 'info', 'signature'],
  ['eku-changed', 'info', 'usage'],
  ['ku-changed', 'info', 'usage'],
  ['sct-count', 'info', 'ct'],
  ['old-precert', 'info', 'ct'],
  ['staple-removed', 'info', 'revocation'],
  ['ocsp-removed', 'info', 'revocation'],
  ['ocsp-added', 'info', 'revocation'],
  ['crl-changed', 'info', 'revocation'],
  ['aia-changed', 'info', 'revocation'],
  ['level-changed', 'info', 'subject'],
  ['subject-changed', 'info', 'subject']
]);

/** Every change code, in impact order. */
export const CERTDIFF_CODES = Object.freeze(CODE_TABLE.map(([code]) => code));
/** The severity of each change code. */
export const CERTDIFF_SEVERITY = Object.freeze(Object.fromEntries(CODE_TABLE.map(([code, severity]) => [code, severity])));
/** The area of each change code. */
export const CERTDIFF_AREA = Object.freeze(Object.fromEntries(CODE_TABLE.map(([code, , area]) => [code, area])));

/** One day in milliseconds. */
const DAY_MS = 86400000;
/** The EC curves current browsers accept for a server key. */
const BROWSER_CURVES = Object.freeze(['P-256', 'P-384']);
/** Key algorithms no current browser accepts in a server certificate. */
const UNSUPPORTED_KEYS = Object.freeze(['Ed25519', 'Ed448', 'DSA', 'unknown']);
/** The extension OIDs whose absence means "no restriction". */
const OID_KU = '2.5.29.15';
const OID_EKU = '2.5.29.37';
/** Chrome's and Apple's CT policies: embedded SCTs a certificate needs for its lifetime (days). */
const SCT_SHORT_DAYS = 180;

/**
 * @typedef {import('./x509.js').Certificate} Certificate
 *
 * @typedef {object} CertSide one certificate of the comparison
 * @property {Certificate} cert the server certificate (a file's leaf)
 * @property {Certificate[]} [chain] every certificate of its file (the leaf may be among them):
 *   its intermediates, and the root when the file has it
 *
 * @typedef {object} CertChange
 * @property {string} code one of {@link CERTDIFF_CODES}
 * @property {'blocker'|'action'|'check'|'info'} severity
 * @property {string} area one of {@link CERTDIFF_AREAS}
 * @property {Object<string, any>} params the values the UI words it with (names, dates, counts)
 * @property {Array<string|{ name: string, by: string }>} items names, addresses or covered names
 *   the change lists one by one (empty for the others)
 *
 * @typedef {object} CertDiff
 * @property {boolean} identical the same certificate (same DER)
 * @property {'identical'|'blocked'|'steps'|'check'|'safe'} verdict
 * @property {CertChange[]} changes ordered by impact: severity, then {@link CERTDIFF_CODES} order
 * @property {{ blocker: number, action: number, check: number, info: number }} counts
 * @property {string[]} unchanged the areas without a change (names, key, chain, signature, usage, ct,
 *   revocation, subject), in {@link CERTDIFF_AREAS} order
 * @property {{ reused: boolean, old: string|null, new: string|null }} key the SPKI SHA-256 of each
 *   key (lowercase hex, null when not computed) and whether they are the same
 * @property {{ now: Date, oldLifetimeDays: number, newLifetimeDays: number, oldDaysLeft: number,
 *   newDaysLeft: number, overlap: { from: Date, to: Date, days: number }|null,
 *   gap: { from: Date, to: Date, days: number }|null }} validity days left are negative once expired
 * @property {{ old: string[], new: string[] }} chain the subject names of each file's
 *   certificates above the leaf, leaf side first (empty for a leaf alone)
 */

const time = (d) => (d instanceof Date ? d.getTime() : Number(d));
const sameBytes = (a, b) => {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};
const hasExt = (cert, oid) => Array.isArray(cert.extensions) && cert.extensions.some((e) => e && e.oid === oid);
const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
const minus = (a, b) => a.filter((x) => !b.includes(x));
const uniq = (a) => [...new Set(a)];
const isWeakSignature = (alg) => /sha1|md5|md2/i.test(String(alg || ''));
/** The issuer as a short label: its CN, else its DN. */
const issuerLabel = (cert) => cert.issuerCN || cert.issuerDN || '';
/** A certificate's subject as a short label: its CN, else its DN. */
const subjectLabel = (cert) => cert.subjectCN || cert.subjectDN || '';
const urlHost = (u) => {
  try {
    return new URL(u).host.toLowerCase();
  } catch {
    return String(u);
  }
};

/**
 * The key as one label: 'RSA 2048', 'EC P-256', 'Ed25519'.
 * @param {Certificate} cert
 * @returns {string}
 */
export function keyLabel(cert) {
  if (!cert) return '';
  if (cert.keyAlgorithm === 'EC') return `EC ${cert.curve || cert.keyBits || ''}`.trim();
  return `${cert.keyAlgorithm}${cert.keyBits ? ` ${cert.keyBits}` : ''}`;
}

/** Does the certificate allow this extended key usage (no EKU extension: any)? */
function ekuAllows(cert, usage) {
  if (!hasExt(cert, OID_EKU)) return true;
  const eku = list(cert.extKeyUsage);
  return eku.includes(usage) || eku.includes('anyExtendedKeyUsage');
}

/** Does the certificate allow this key usage (no key usage extension: any)? */
function kuAllows(cert, usage) {
  return !hasExt(cert, OID_KU) || list(cert.keyUsage).includes(usage);
}

/** Whole days of a certificate's validity period. */
const lifetimeDays = (cert) => Math.max(0, Math.round((time(cert.notAfter) - time(cert.notBefore)) / DAY_MS));

/** SCTs Chrome's and Apple's CT policies ask a certificate of this lifetime to embed. */
const sctsNeeded = (cert) => (lifetimeDays(cert) <= SCT_SHORT_DAYS ? 2 : 3);

/**
 * The certificates above the leaf in its file, leaf side first: each one the issuer of the one
 * before (lib/x509.js issuedBy), up to a self-signed root or the first certificate the file lacks.
 * @param {CertSide} side
 * @returns {Certificate[]}
 */
export function chainAbove(side) {
  const certs = Array.isArray(side && side.chain) ? side.chain.filter(Boolean) : [];
  const out = [];
  let cur = side && side.cert;
  if (!cur || cur.selfSigned) return out;
  const seen = new Set([cur]);
  for (;;) {
    const parent = certs.find((c) => !seen.has(c) && !sameBytes(c.der, cur.der) && issuedBy(cur, c));
    if (!parent) break;
    out.push(parent);
    seen.add(parent);
    if (parent.selfSigned) break;
    cur = parent;
  }
  return out;
}

/** The root a chain ends at (its DN): the file's self-signed root, else the issuer of its last certificate; null for a leaf alone. */
function anchorOf(above) {
  if (!above.length) return null;
  const top = above[above.length - 1];
  return top.selfSigned ? top.subjectDN : top.issuerDN;
}

/** An intermediate's identity across files: its subject, key and serial. */
const certId = (c) => `${c.subjectDN}|${c.subjectKeyId || ''}|${c.serialHex}`;

/** Whole days from `a` to `b` (ms), rounded down; negative when `b` is earlier. */
const daysBetween = (a, b) => Math.floor((b - a) / DAY_MS);

/**
 * Compare the certificate the servers send now with the one replacing it (synchronous; the SPKI
 * hashes come from {@link diffCertificates} or are left out, the key then compared byte for byte).
 * @param {CertSide} oldSide the certificate being replaced
 * @param {CertSide} newSide the certificate replacing it
 * @param {{ now?: Date|number, spki?: { old: string|null, new: string|null }|null }} [opts] now: the
 *   moment of the deployment (validity rules)
 * @returns {CertDiff}
 * @throws {TypeError} without both certificates
 */
export function compareCertificates(oldSide, newSide, { now = Date.now(), spki = null } = {}) {
  const a = oldSide && oldSide.cert;
  const b = newSide && newSide.cert;
  if (!a || !b || !a.notBefore || !b.notBefore) throw new TypeError('compareCertificates: expected two parsed certificates');
  const at = time(now);
  const changes = [];
  const add = (code, params = {}, items = []) => {
    changes.push({ code, severity: CERTDIFF_SEVERITY[code], area: CERTDIFF_AREA[code], params, items });
  };
  const oldAbove = chainAbove(oldSide);
  const newAbove = chainAbove(newSide);
  const hashes = { old: spki && spki.old ? String(spki.old).toLowerCase() : null, new: spki && spki.new ? String(spki.new).toLowerCase() : null };
  const reused = hashes.old && hashes.new ? hashes.old === hashes.new : sameBytes(a.spkiDer, b.spkiDer);
  const validity = {
    now: new Date(at),
    oldLifetimeDays: lifetimeDays(a),
    newLifetimeDays: lifetimeDays(b),
    oldDaysLeft: daysBetween(at, time(a.notAfter)),
    newDaysLeft: daysBetween(at, time(b.notAfter)),
    overlap: null,
    gap: null
  };
  const from = Math.max(time(a.notBefore), time(b.notBefore));
  const to = Math.min(time(a.notAfter), time(b.notAfter));
  if (to > from) validity.overlap = { from: new Date(from), to: new Date(to), days: Math.round((to - from) / DAY_MS) };
  if (time(b.notBefore) > time(a.notAfter)) {
    validity.gap = { from: new Date(time(a.notAfter)), to: new Date(time(b.notBefore)), days: Math.ceil((time(b.notBefore) - time(a.notAfter)) / DAY_MS) };
  }
  const base = {
    key: { reused, old: hashes.old, new: hashes.new },
    validity,
    chain: { old: oldAbove.map(subjectLabel), new: newAbove.map(subjectLabel) }
  };
  if (sameBytes(a.der, b.der)) {
    return { identical: true, verdict: 'identical', changes: [], counts: { blocker: 0, action: 0, check: 0, info: 0 }, unchanged: [], ...base };
  }

  /* --- identity ---------------------------------------------------------- */
  if (b.isPrecertificate) add('precert');
  if (b.isCA && !a.isCA) add('new-is-ca');
  if (b.selfSigned && !a.selfSigned) add('self-signed');

  /* --- validity ---------------------------------------------------------- */
  if (time(b.notAfter) <= at) add('expired', { date: b.notAfter, days: daysBetween(time(b.notAfter), at) });
  else if (time(b.notBefore) > at) add('not-yet-valid', { date: b.notBefore, days: Math.ceil((time(b.notBefore) - at) / DAY_MS) });
  if (validity.gap) add('gap', { ...validity.gap });
  if (time(a.notAfter) <= at) add('old-expired', { date: a.notAfter, days: daysBetween(time(a.notAfter), at) });
  if (Math.abs(validity.newLifetimeDays - validity.oldLifetimeDays) >= 2) {
    add('lifetime', { from: validity.oldLifetimeDays, to: validity.newLifetimeDays, shorter: validity.newLifetimeDays < validity.oldLifetimeDays });
  }
  if (time(b.notAfter) < time(a.notAfter)) add('expires-sooner', { old: a.notAfter, new: b.notAfter });

  /* --- names and addresses ----------------------------------------------- */
  const oldNames = uniq(list(a.hostnames));
  const newNames = uniq(list(b.hostnames));
  const removed = [];
  const covered = [];
  for (const n of sortHostnames(oldNames)) {
    if (newNames.includes(n)) continue;
    if (n.startsWith('*.')) {
      // A wildcard is covered only by the same wildcard: what is left of it are the names directly
      // under it that the new certificate names one by one.
      add('wildcard-removed', { name: n, kept: sortHostnames(newNames.filter((m) => !m.startsWith('*.') && wildcardMatches(n, m))) });
      continue;
    }
    const cov = certCovers(newNames, n);
    if (cov.covered) covered.push({ name: n, by: cov.by });
    else removed.push(n);
  }
  const oldIps = uniq(list(a.ipAddresses));
  const newIps = uniq(list(b.ipAddresses));
  removed.push(...minus(oldIps, newIps));
  const added = [...sortHostnames(newNames.filter((n) => !oldNames.includes(n) && !certCovers(oldNames, n).covered)), ...minus(newIps, oldIps)];
  if (removed.length) add('name-removed', { count: removed.length }, removed);
  const hadSan = list(a.dnsNames).length > 0 || oldIps.length > 0;
  if (hadSan && !list(b.dnsNames).length && !newIps.length) add('no-san');
  if (added.length) add('name-added', { count: added.length }, added);
  if (covered.length) add('name-covered', { count: covered.length }, covered);

  /* --- key --------------------------------------------------------------- */
  const oldKey = keyLabel(a);
  const newKey = keyLabel(b);
  if (reused) add('key-reused', { spki: hashes.new });
  else add('key-new', { from: hashes.old, to: hashes.new });
  if (UNSUPPORTED_KEYS.includes(b.keyAlgorithm) && b.keyAlgorithm !== a.keyAlgorithm) {
    add('key-unsupported', { key: newKey });
  } else if (b.keyAlgorithm === 'RSA' && b.keyBits && b.keyBits < 2048 && !(a.keyAlgorithm === 'RSA' && a.keyBits && a.keyBits <= b.keyBits)) {
    add('key-weak', { key: newKey });
  } else if (b.keyAlgorithm === 'EC' && !BROWSER_CURVES.includes(b.curve) && !(a.keyAlgorithm === 'EC' && a.curve === b.curve)) {
    add('key-curve', { key: newKey, curve: b.curve || '' });
  }
  if (a.keyAlgorithm !== b.keyAlgorithm && ['RSA', 'EC'].includes(a.keyAlgorithm) && ['RSA', 'EC'].includes(b.keyAlgorithm)) {
    add('key-type', { from: oldKey, to: newKey, ec: b.keyAlgorithm === 'EC' });
  } else if (a.keyAlgorithm === b.keyAlgorithm && oldKey !== newKey) {
    add('key-size', { from: oldKey, to: newKey });
  }

  /* --- issuer and intermediates ---------------------------------------- */
  const newInter = newAbove.filter((c) => !c.selfSigned);
  const oldInter = oldAbove.filter((c) => !c.selfSigned);
  if (a.issuerDN !== b.issuerDN) {
    add('issuer-changed', {
      from: issuerLabel(a), to: issuerLabel(b), chain: newInter.map(subjectLabel), missing: !newInter.length && !b.selfSigned
    });
  } else if (a.authorityKeyId && b.authorityKeyId && a.authorityKeyId !== b.authorityKeyId) {
    add('issuer-rekeyed', { issuer: issuerLabel(b), chain: newInter.map(subjectLabel), missing: !newInter.length });
  } else if (oldInter.length && newInter.length) {
    const oldIds = oldInter.map(certId);
    const newIds = newInter.map(certId);
    const gone = oldInter.filter((c) => !newIds.includes(certId(c))).map(subjectLabel);
    const brought = newInter.filter((c) => !oldIds.includes(certId(c))).map(subjectLabel);
    if (gone.length || brought.length) add('chain-changed', { removed: gone, added: brought });
  }
  const oldAnchor = anchorOf(oldAbove);
  const newAnchor = anchorOf(newAbove);
  if (oldAnchor && newAnchor && oldAnchor !== newAnchor) {
    const label = (above) => {
      const top = above[above.length - 1];
      return top.selfSigned ? subjectLabel(top) : issuerLabel(top);
    };
    add('root-changed', { from: label(oldAbove), to: label(newAbove) });
  }

  /* --- signature --------------------------------------------------------- */
  if (isWeakSignature(b.signatureAlgorithm) && !isWeakSignature(a.signatureAlgorithm)) add('sig-weak', { alg: b.signatureAlgorithm });
  else if (a.signatureAlgorithm !== b.signatureAlgorithm) add('sig-changed', { from: a.signatureAlgorithm, to: b.signatureAlgorithm });

  /* --- key usage and extended key usage ---------------------------------- */
  const serverDropped = ekuAllows(a, 'serverAuth') && !ekuAllows(b, 'serverAuth');
  const clientDropped = ekuAllows(a, 'clientAuth') && !ekuAllows(b, 'clientAuth');
  if (serverDropped) add('eku-server-dropped');
  if (clientDropped) add('eku-client-dropped');
  const ekuAdded = minus(list(b.extKeyUsage), list(a.extKeyUsage));
  const ekuRemoved = minus(list(a.extKeyUsage), list(b.extKeyUsage)).filter((u) => !(u === 'serverAuth' && serverDropped) && !(u === 'clientAuth' && clientDropped));
  if (ekuAdded.length || ekuRemoved.length) add('eku-changed', { added: ekuAdded, removed: ekuRemoved });
  const signDropped = kuAllows(a, 'digitalSignature') && !kuAllows(b, 'digitalSignature');
  const encipherDropped = a.keyAlgorithm === 'RSA' && b.keyAlgorithm === 'RSA' && kuAllows(a, 'keyEncipherment') && !kuAllows(b, 'keyEncipherment');
  if (signDropped) add('ku-signature-dropped');
  if (encipherDropped) add('ku-encipher-dropped');
  const kuAdded = minus(list(b.keyUsage), list(a.keyUsage));
  const kuRemoved = minus(list(a.keyUsage), list(b.keyUsage))
    .filter((u) => !(u === 'digitalSignature' && signDropped) && !(u === 'keyEncipherment' && encipherDropped));
  if (kuAdded.length || kuRemoved.length) add('ku-changed', { added: kuAdded, removed: kuRemoved });

  /* --- Certificate Transparency ------------------------------------------ */
  const oldScts = a.sctCount || 0;
  const newScts = b.sctCount || 0;
  if (a.isPrecertificate) {
    add('old-precert');
  } else if (!b.isPrecertificate) {
    if (oldScts > 0 && newScts === 0) add('sct-none', { from: oldScts });
    else if (newScts > 0 && newScts < sctsNeeded(b) && oldScts >= sctsNeeded(a)) add('sct-few', { count: newScts, need: sctsNeeded(b) });
    else if (oldScts !== newScts) add('sct-count', { from: oldScts, to: newScts });
  }

  /* --- revocation: OCSP must-staple, OCSP, CRL, CA Issuers ---------------- */
  const oldOcsp = uniq(list(a.ocspUrls));
  const newOcsp = uniq(list(b.ocspUrls));
  if (b.mustStaple && !newOcsp.length && !(a.mustStaple && !oldOcsp.length)) add('staple-no-ocsp');
  else if (b.mustStaple && !a.mustStaple) add('staple-added', { ocsp: newOcsp });
  else if (a.mustStaple && !b.mustStaple) add('staple-removed');
  if (oldOcsp.length && !newOcsp.length) add('ocsp-removed', { from: oldOcsp });
  else if (!oldOcsp.length && newOcsp.length) add('ocsp-added', { to: newOcsp });
  else if (minus(oldOcsp, newOcsp).length || minus(newOcsp, oldOcsp).length) {
    add('ocsp-changed', { from: oldOcsp, to: newOcsp, hosts: uniq(newOcsp.map(urlHost)).filter((h) => !oldOcsp.map(urlHost).includes(h)) });
  }
  const urlDiff = (code, x, y) => {
    const gone = minus(uniq(list(x)), uniq(list(y)));
    const brought = minus(uniq(list(y)), uniq(list(x)));
    if (gone.length || brought.length) add(code, { removed: gone, added: brought });
  };
  urlDiff('crl-changed', a.crlUrls, b.crlUrls);
  urlDiff('aia-changed', a.caIssuersUrls, b.caIssuersUrls);

  /* --- subject ----------------------------------------------------------- */
  if ((a.validationLevel || null) !== (b.validationLevel || null)) add('level-changed', { from: a.validationLevel || null, to: b.validationLevel || null });
  if (a.subjectDN !== b.subjectDN) add('subject-changed', { from: a.subjectDN, to: b.subjectDN });

  const rank = (c) => CERTDIFF_SEVERITIES.indexOf(c.severity) * 1000 + CERTDIFF_CODES.indexOf(c.code);
  changes.sort((x, y) => rank(x) - rank(y));
  const counts = { blocker: 0, action: 0, check: 0, info: 0 };
  for (const c of changes) counts[c.severity] += 1;
  const touched = new Set(changes.map((c) => c.area));
  const unchanged = CERTDIFF_AREAS.filter((x) => x !== 'identity' && x !== 'validity' && !touched.has(x));
  const verdict = counts.blocker ? 'blocked' : counts.action ? 'steps' : counts.check ? 'check' : 'safe';
  return { identical: false, verdict, changes, counts, unchanged, ...base };
}

/**
 * {@link compareCertificates} with the SPKI SHA-256 of both keys (Web Crypto): whether the key was
 * reused is decided by those hashes, which TLSA `3 1 1` records and key pins are made of.
 * @param {CertSide} oldSide
 * @param {CertSide} newSide
 * @param {{ now?: Date|number, subtle?: SubtleCrypto|null }} [opts] subtle: null hashes in JavaScript
 *   (lib/x509.js computeFingerprints, as on a page without Web Crypto)
 * @returns {Promise<CertDiff>}
 */
export async function diffCertificates(oldSide, newSide, { now = Date.now(), subtle = globalThis.crypto?.subtle } = {}) {
  const hash = async (side) => {
    const der = side && side.cert && side.cert.spkiDer;
    if (!(der instanceof Uint8Array) || !der.length) return null;
    return (await computeFingerprints(der, { subtle })).sha256;
  };
  const [o, n] = await Promise.all([hash(oldSide), hash(newSide)]);
  return compareCertificates(oldSide, newSide, { now, spki: { old: o, new: n } });
}

/**
 * Which of two certificates is the old one: the one issued first (the earlier notBefore; the
 * earlier notAfter on a tie). `swap` turns the answer round (a rollback, or a re-issue dated back).
 * @param {Certificate} x
 * @param {Certificate} y
 * @param {{ swap?: boolean }} [opts]
 * @returns {'x'|'y'} the old one
 */
export function olderOf(x, y, { swap = false } = {}) {
  const dx = time(x.notBefore) - time(y.notBefore) || time(x.notAfter) - time(y.notAfter);
  const xOld = dx <= 0;
  return xOld !== !!swap ? 'x' : 'y';
}
