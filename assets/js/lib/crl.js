/**
 * crl.js — certificate revocation lists (RFC 5280 §5): a DER CRL read without a dependency, and
 * what it says about one certificate. DOM-free; runs in browsers and Node 22.
 *
 * - {@link parseCrl}: the TBSCertList — the issuer, thisUpdate and nextUpdate, every revoked serial
 *   number with its revocationDate and reasonCode (or only the ones asked for: a CA's CRL can list
 *   hundreds of thousands), the CRL number, the authority key identifier, the issuing distribution
 *   point (a partitioned CRL says which certificates it covers), a delta CRL's marker and any
 *   critical extension this module does not know — and what checking its signature takes: the
 *   signed bytes, the signature and the scheme ({@link signatureScheme}). The signature is not
 *   checked here: tools/ds/revocation.mjs does it with node:crypto and the issuer's key from the
 *   handshake chain; the Python CLI cannot (stdlib) and says so.
 * - {@link crlStatus}: is a certificate on it — revoked (with the reason and the time), good, or
 *   unknown with why ({@link CRL_UNKNOWN}: another CA's CRL, a CRL for other certificates, a
 *   delta CRL, one for some reasons only, a stale one, an unknown critical extension).
 * - {@link REVOCATION_REASONS} / {@link reasonName}: the RFC 5280 §5.3.1 CRLReason codes, which
 *   Cert Spotter's `revocation.reason` holds too.
 *
 * Nothing here asks OCSP: Let's Encrypt has been CRL-only since 2025-08-06.
 */

import { DER, CertificateParseError } from './x509.js';

const {
  readNode, childrenOf, parseSingle, contents, tlv, expect, decodeOid, integerHex, integerValue, booleanValue,
  bitString, decodeTime, parseAlgorithm, parseName, firstValues, formatDN, parseGeneralNames, toHex, SIG_ALG_NAMES
} = DER;

/** RFC 5280 §5.3.1 CRLReason: code → name (7 is not used). */
export const REVOCATION_REASONS = Object.freeze({
  0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged', 4: 'superseded',
  5: 'cessationOfOperation', 6: 'certificateHold', 8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise'
});

/** The reason names, in code order (the i18n keys the views build from them). */
export const REVOCATION_REASON_NAMES = Object.freeze(Object.values(REVOCATION_REASONS));

/** Why {@link crlStatus} cannot tell. */
export const CRL_UNKNOWN = Object.freeze(['issuer-mismatch', 'critical-extension', 'delta', 'scope', 'reasons', 'stale']);

/**
 * The name of a CRLReason code ({@link REVOCATION_REASONS}), or null for none or a code the RFC
 * does not define.
 * @param {number|string|null|undefined} code
 * @returns {string|null}
 */
export function reasonName(code) {
  const n = typeof code === 'string' && /^\d{1,2}$/.test(code) ? Number(code) : code;
  return Number.isInteger(n) && Object.prototype.hasOwnProperty.call(REVOCATION_REASONS, n) ? REVOCATION_REASONS[n] : null;
}

/** Thrown by {@link parseCrl} for input that is not a DER CRL. */
export class CrlParseError extends Error {
  /**
   * @param {string} message
   * @param {number|null} [offset]
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, offset = null, options = undefined) {
    super(message, options);
    this.name = 'CrlParseError';
    this.offset = offset;
  }
}

const OID = Object.freeze({
  REASON: '2.5.29.21',
  INVALIDITY: '2.5.29.24',
  AKI: '2.5.29.35',
  CRL_NUMBER: '2.5.29.20',
  IDP: '2.5.29.28',
  DELTA: '2.5.29.27',
  FRESHEST: '2.5.29.46',
  AIA: '1.3.6.1.5.5.7.1.1',
  RSA_PSS: '1.2.840.113549.1.1.10'
});

/** CRL extensions this module reads or may safely leave unread when one is critical. */
const KNOWN_CRL_EXTENSIONS = new Set([OID.AKI, OID.CRL_NUMBER, OID.IDP, OID.DELTA, OID.FRESHEST, OID.AIA]);
/** Entry extensions a status may rest on (reasonCode, invalidityDate; certificateIssuer only in indirect CRLs, which are left out). */
const KNOWN_ENTRY_EXTENSIONS = new Set([OID.REASON, OID.INVALIDITY]);

const fail = (message, offset = null) => {
  throw new CrlParseError(message, offset);
};

/** Converts supported binary inputs to a Uint8Array view (no copy), or null. */
function asBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input == null || typeof input !== 'object') return null;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  const tag = Object.prototype.toString.call(input);
  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(input);
  return null;
}

/**
 * A serial number as lib/x509.js writes it: lowercase hex, no leading zero bytes, or null.
 * @param {unknown} hex
 * @returns {string|null}
 */
export function normalizeSerial(hex) {
  let s = String(hex ?? '').trim().toLowerCase().replace(/^0x/, '').replace(/[\s:]/g, '');
  if (!s || !/^[0-9a-f]+$/.test(s)) return null;
  if (s.length % 2) s = `0${s}`;
  while (s.length > 2 && s.startsWith('00')) s = s.slice(2);
  return s;
}

/** The Extensions of a SEQUENCE OF Extension: `{ oid, critical, value }`. */
function extensionsOf(node) {
  return childrenOf(node).map((ext) => {
    const parts = childrenOf(expect(ext, 0x30, 'Extension'));
    if (parts.length < 2 || parts.length > 3) fail('Malformed Extension', ext.offset);
    return {
      oid: decodeOid(parts[0]),
      critical: parts.length === 3 ? booleanValue(parts[1]) : false,
      value: contents(expect(parts[parts.length - 1], 0x04, 'extnValue'))
    };
  });
}

/** An ENUMERATED (reasonCode) → its number. */
function enumerated(bytes) {
  const node = parseSingle(bytes);
  return integerValue({ ...expect(node, 0x0a, 'ENUMERATED'), id: 0x02 });
}

/** An IMPLICIT [n] BOOLEAN → its value. */
const implicitBoolean = (node) => booleanValue({ ...node, id: 0x01 });

/**
 * IssuingDistributionPoint (RFC 5280 §5.2.5): the URLs of the distribution point it is (a
 * partition), and which certificates it covers.
 */
function parseIdp(value) {
  const out = { urls: [], relativeName: false, onlyUser: false, onlyCA: false, onlySomeReasons: false, indirect: false, onlyAttribute: false };
  for (const node of childrenOf(expect(parseSingle(value), 0x30, 'IssuingDistributionPoint'))) {
    switch (node.id) {
      case 0xa0: // distributionPoint [0] DistributionPointName (a CHOICE: explicitly tagged)
        for (const choice of childrenOf(node)) {
          if (choice.id === 0xa0) { // fullName [0] IMPLICIT GeneralNames
            for (const gn of parseGeneralNames(choice)) if (gn.type === 'uri') out.urls.push(gn.value);
          } else if (choice.id === 0xa1) {
            out.relativeName = true; // nameRelativeToCRLIssuer
          }
        }
        break;
      case 0x81: out.onlyUser = implicitBoolean(node); break;
      case 0x82: out.onlyCA = implicitBoolean(node); break;
      case 0x83: out.onlySomeReasons = true; break;
      case 0x84: out.indirect = implicitBoolean(node); break;
      case 0x85: out.onlyAttribute = implicitBoolean(node); break;
      default: break;
    }
  }
  return out;
}

/** Hash algorithm OIDs → node:crypto / WebCrypto names. */
const HASHES = Object.freeze({
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.4': 'sha224', '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512'
});

/** Signature algorithm OIDs → [scheme, hash]. */
const SCHEMES = Object.freeze({
  '1.2.840.113549.1.1.5': ['rsa-pkcs1', 'sha1'],
  '1.2.840.113549.1.1.14': ['rsa-pkcs1', 'sha224'],
  '1.2.840.113549.1.1.11': ['rsa-pkcs1', 'sha256'],
  '1.2.840.113549.1.1.12': ['rsa-pkcs1', 'sha384'],
  '1.2.840.113549.1.1.13': ['rsa-pkcs1', 'sha512'],
  '1.2.840.10045.4.1': ['ecdsa', 'sha1'],
  '1.2.840.10045.4.3.1': ['ecdsa', 'sha224'],
  '1.2.840.10045.4.3.2': ['ecdsa', 'sha256'],
  '1.2.840.10045.4.3.3': ['ecdsa', 'sha384'],
  '1.2.840.10045.4.3.4': ['ecdsa', 'sha512'],
  '1.3.101.112': ['ed25519', null],
  '1.3.101.113': ['ed448', null]
});

/**
 * How a signature of this algorithm is checked: the scheme ('rsa-pkcs1', 'rsa-pss', 'ecdsa' with a
 * DER signature, 'ed25519', 'ed448'), the hash (null for EdDSA) and, for RSA-PSS, the salt length
 * from its parameters (RFC 4055; the mask uses MGF1 with the same hash). Null for an algorithm this
 * module does not know (DSA, MD5 …).
 * @param {string} oid
 * @param {object|null} [params] the AlgorithmIdentifier's parameters node (lib/x509.js DER)
 * @returns {{ scheme: string, hash: string|null, saltLength?: number }|null}
 */
export function signatureScheme(oid, params = null) {
  if (oid === OID.RSA_PSS) {
    let hash = 'sha1';
    let saltLength = 20;
    if (params && params.id === 0x30) {
      for (const node of childrenOf(params)) {
        const [inner] = childrenOf(node);
        if (!inner) continue;
        if (node.id === 0xa0) hash = HASHES[parseAlgorithm(inner).oid] || null;
        else if (node.id === 0xa2) saltLength = integerValue(inner);
      }
    }
    return hash ? { scheme: 'rsa-pss', hash, saltLength } : null;
  }
  const s = SCHEMES[oid];
  return s ? { scheme: s[0], hash: s[1] } : null;
}

/**
 * @typedef {object} CrlEntry
 * @property {string} serialHex lowercase hex, no leading zero bytes (as lib/x509.js writes a certificate's)
 * @property {Date} revocationDate
 * @property {number|null} reasonCode RFC 5280 CRLReason (null: none given)
 * @property {string|null} reason {@link reasonName}
 * @property {Date|null} invalidityDate
 * @property {string[]} unsupportedCritical critical entry extensions not read
 */

/**
 * @typedef {object} Crl
 * @property {number} version 1 or 2
 * @property {string} issuerDN RFC 2253 (lib/x509.js formatDN, as a certificate's issuerDN)
 * @property {Object<string, string>} issuer first value per attribute ({ CN, O, C, … })
 * @property {Array} issuerRDNs
 * @property {Date} thisUpdate
 * @property {Date|null} nextUpdate
 * @property {CrlEntry[]} revoked every entry, or only those of the serials asked for (`filtered`)
 * @property {number} count every entry the CRL lists
 * @property {Set<string>|null} filtered the serial numbers `revoked` was read for (null: all)
 * @property {string|null} crlNumber lowercase hex
 * @property {string|null} authorityKeyId lowercase hex
 * @property {{ urls: string[], relativeName: boolean, onlyUser: boolean, onlyCA: boolean, onlySomeReasons: boolean,
 *   indirect: boolean, onlyAttribute: boolean }|null} idp the issuing distribution point
 * @property {boolean} deltaCrl a delta CRL (deltaCRLIndicator)
 * @property {string[]} unsupportedCritical critical CRL extensions this module does not read
 * @property {string} signatureAlgorithm OpenSSL name, dotted OID when unknown
 * @property {string} signatureAlgorithmOid
 * @property {{ scheme: string, hash: string|null, saltLength?: number }|null} scheme {@link signatureScheme}
 * @property {Uint8Array} tbsDer the signed bytes (the TBSCertList TLV)
 * @property {Uint8Array} signature
 */

function decodeCrl(bytes, wanted) {
  const root = expect(readNode(bytes, 0, bytes.length), 0x30, 'CertificateList (SEQUENCE)');
  if (root.next !== bytes.length) fail('Unexpected data after the CRL', root.next);
  const top = childrenOf(root);
  if (top.length !== 3) fail('A CRL must contain tbsCertList, signatureAlgorithm and signatureValue', root.offset);
  const [tbsNode, sigAlgNode, sigValueNode] = top;
  expect(tbsNode, 0x30, 'tbsCertList');
  const sigAlg = parseAlgorithm(sigAlgNode);
  const sig = bitString(sigValueNode);
  const f = childrenOf(tbsNode);
  let i = 0;
  const next = (what) => {
    if (i >= f.length) fail(`Missing ${what}`, tbsNode.offset);
    return f[i++];
  };
  let version = 1;
  if (f[0] && f[0].id === 0x02) {
    version = integerValue(f[i++]) + 1;
    if (version !== 2) fail(`Unsupported CRL version ${version}`, f[0].offset);
  }
  const innerAlg = parseAlgorithm(next('signature'));
  if (innerAlg.oid !== sigAlg.oid) fail('The two signature algorithms of the CRL differ', tbsNode.offset);
  const issuerRDNs = parseName(expect(next('issuer'), 0x30, 'issuer Name'));
  const thisUpdate = decodeTime(next('thisUpdate'));
  let nextUpdate = null;
  if (f[i] && (f[i].id === 0x17 || f[i].id === 0x18)) nextUpdate = decodeTime(f[i++]);
  const revoked = [];
  let count = 0;
  if (f[i] && f[i].id === 0x30) {
    const list = f[i++];
    let p = list.start;
    while (p < list.end) {
      const entry = expect(readNode(bytes, p, list.end), 0x30, 'revokedCertificate');
      p = entry.next;
      count += 1;
      // The serial first: reading it costs little; the rest only for the entries kept.
      const serialHex = integerHex(readNode(bytes, entry.start, entry.end));
      if (wanted && !wanted.has(serialHex)) continue;
      const parts = childrenOf(entry);
      if (parts.length < 2 || parts.length > 3) fail('Malformed revokedCertificate entry', entry.offset);
      const out = { serialHex, revocationDate: decodeTime(parts[1]), reasonCode: null, reason: null, invalidityDate: null, unsupportedCritical: [] };
      if (parts[2]) {
        for (const ext of extensionsOf(expect(parts[2], 0x30, 'crlEntryExtensions'))) {
          if (ext.oid === OID.REASON) {
            out.reasonCode = enumerated(ext.value);
            out.reason = reasonName(out.reasonCode);
          } else if (ext.oid === OID.INVALIDITY) {
            out.invalidityDate = decodeTime(parseSingle(ext.value));
          } else if (ext.critical && !KNOWN_ENTRY_EXTENSIONS.has(ext.oid)) {
            out.unsupportedCritical.push(ext.oid);
          }
        }
      }
      revoked.push(out);
    }
  }
  let extNode = null;
  if (f[i] && f[i].id === 0xa0) extNode = f[i++];
  if (i !== f.length) fail(`Unexpected field in tbsCertList (tag 0x${f[i].id.toString(16).padStart(2, '0')})`, f[i].offset);

  let crlNumber = null;
  let authorityKeyId = null;
  let idp = null;
  let deltaCrl = false;
  const unsupportedCritical = [];
  if (extNode) {
    const inner = childrenOf(extNode);
    if (inner.length !== 1) fail('Malformed crlExtensions', extNode.offset);
    for (const ext of extensionsOf(expect(inner[0], 0x30, 'Extensions'))) {
      if (ext.oid === OID.CRL_NUMBER) crlNumber = integerHex(parseSingle(ext.value));
      else if (ext.oid === OID.AKI) {
        const keyId = childrenOf(expect(parseSingle(ext.value), 0x30, 'AuthorityKeyIdentifier')).find((n) => n.id === 0x80);
        authorityKeyId = keyId ? toHex(contents(keyId)) : null;
      } else if (ext.oid === OID.IDP) idp = parseIdp(ext.value);
      else if (ext.oid === OID.DELTA) deltaCrl = true;
      else if (ext.critical && !KNOWN_CRL_EXTENSIONS.has(ext.oid)) unsupportedCritical.push(ext.oid);
    }
  }
  return {
    version,
    issuerDN: formatDN(issuerRDNs),
    issuer: firstValues(issuerRDNs),
    issuerRDNs,
    thisUpdate,
    nextUpdate,
    revoked,
    count,
    filtered: wanted,
    crlNumber,
    authorityKeyId,
    idp,
    deltaCrl,
    unsupportedCritical,
    signatureAlgorithm: SIG_ALG_NAMES[sigAlg.oid] || sigAlg.oid,
    signatureAlgorithmOid: sigAlg.oid,
    scheme: signatureScheme(sigAlg.oid, sigAlg.params),
    tbsDer: tlv(tbsNode),
    signature: sig.bytes
  };
}

/**
 * Parse one DER CRL. With `serials`, only those serial numbers' entries are kept in `revoked` (the
 * others are counted): a large CRL is read once for the certificates a run has.
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} der
 * @param {{ serials?: Iterable<string>|null }} [opts] serial numbers in hex (any case, leading zeros allowed)
 * @returns {Crl}
 * @throws {CrlParseError} input that is not a DER CRL (a PEM file, an HTML error page, a truncated download)
 */
export function parseCrl(der, { serials = null } = {}) {
  const view = asBytes(der);
  if (!view || !view.length) throw new CrlParseError('Expected DER bytes of a CRL');
  const wanted = serials ? new Set([...serials].map(normalizeSerial).filter(Boolean)) : null;
  try {
    return decodeCrl(view, wanted);
  } catch (err) {
    if (err instanceof CrlParseError) throw err;
    const offset = err instanceof CertificateParseError ? err.offset : null;
    throw new CrlParseError(`Malformed CRL: ${err && err.message ? err.message : String(err)}`, offset, { cause: err });
  }
}

/**
 * Was this CRL issued by the certificate's issuer: the same issuer name and, when both say one,
 * the same key identifier (a re-keyed CA with the same name signs another CRL)?
 * @param {Crl} crl
 * @param {{ issuerDN: string, authorityKeyId?: string|null }} cert lib/x509.js Certificate
 * @returns {boolean}
 */
export function crlIssuedFor(crl, cert) {
  if (!crl || !cert || crl.issuerDN !== cert.issuerDN) return false;
  return !crl.authorityKeyId || !cert.authorityKeyId || crl.authorityKeyId === String(cert.authorityKeyId).toLowerCase();
}

/** Two URLs are the same resource (scheme and host case-insensitive, default ports dropped). */
function sameUrl(a, b) {
  try {
    const x = new URL(a);
    const y = new URL(b);
    return x.protocol === y.protocol && x.host === y.host && x.pathname === y.pathname && x.search === y.search;
  } catch {
    return String(a) === String(b);
  }
}

/**
 * The CRL distribution point URLs of a certificate a fetcher can read (http and https; LDAP is
 * left out), in certificate order, each once.
 * @param {{ crlUrls?: string[] }} cert lib/x509.js Certificate
 * @returns {string[]}
 */
export function crlUrlsOf(cert) {
  const out = [];
  for (const u of (cert && Array.isArray(cert.crlUrls) ? cert.crlUrls : [])) {
    if (typeof u === 'string' && /^https?:\/\/[^\s]+$/i.test(u) && !out.includes(u)) out.push(u);
  }
  return out;
}

/**
 * @typedef {object} CrlVerdict
 * @property {'good'|'revoked'|'unknown'} status
 * @property {string|null} code why it is unknown ({@link CRL_UNKNOWN})
 * @property {number|null} reasonCode
 * @property {string|null} reason {@link reasonName}; null when the CA gave none
 * @property {Date|null} time when it was revoked
 * @property {Date} thisUpdate
 * @property {Date|null} nextUpdate
 */

/**
 * What a CRL says about a certificate, in order: a CRL of another issuer, with a critical extension
 * this module does not read, or a delta CRL tells nothing; one whose issuing distribution point
 * covers other certificates (CA or attribute certificates, an indirect CRL, another partition than
 * the URL it was read from) neither; a listed serial is revoked (removeFromCRL excepted), whatever
 * the CRL's age; an unlisted one is good unless the CRL covers some reasons only or its nextUpdate
 * has passed (stale).
 * @param {Crl} crl
 * @param {{ serialHex: string, issuerDN: string, authorityKeyId?: string|null, isCA?: boolean }} cert
 * @param {{ url?: string|null, now?: number|Date }} [opts] `url`: where the CRL was read (checked
 *   against its issuing distribution point)
 * @returns {CrlVerdict}
 * @throws {TypeError|RangeError} a certificate without a serial, or one the CRL was not read for
 */
export function crlStatus(crl, cert, { url = null, now = Date.now() } = {}) {
  const at = now instanceof Date ? now.getTime() : Number(now);
  const serial = normalizeSerial(cert && cert.serialHex);
  if (!serial) throw new TypeError('crlStatus: the certificate has no serial number');
  if (crl.filtered && !crl.filtered.has(serial)) throw new RangeError('crlStatus: the CRL was read for other serial numbers');
  const base = { status: 'unknown', code: null, reasonCode: null, reason: null, time: null, thisUpdate: crl.thisUpdate, nextUpdate: crl.nextUpdate };
  const unknown = (code) => ({ ...base, code });
  if (!crlIssuedFor(crl, cert)) return unknown('issuer-mismatch');
  if (crl.unsupportedCritical.length) return unknown('critical-extension');
  if (crl.deltaCrl) return unknown('delta');
  const idp = crl.idp;
  if (idp && (idp.onlyCA || idp.onlyAttribute || idp.indirect || (idp.onlyUser && cert.isCA === true))) return unknown('scope');
  if (idp && url && idp.urls.length && !idp.urls.some((u) => sameUrl(u, url))) return unknown('scope');
  const entry = crl.revoked.find((e) => e.serialHex === serial);
  if (entry && entry.unsupportedCritical.length) return unknown('critical-extension');
  if (entry && entry.reasonCode !== 8) return { ...base, status: 'revoked', reasonCode: entry.reasonCode, reason: entry.reason, time: entry.revocationDate };
  if (idp && idp.onlySomeReasons) return unknown('reasons');
  if (crl.nextUpdate && crl.nextUpdate.getTime() < at) return unknown('stale');
  return { ...base, status: 'good' };
}
