/**
 * X.509 certificate parser (DER / ASN.1) for the browser and Node.
 *
 * Pure, DOM-free and dependency-free: runs unchanged in browsers and Node 22.
 * Certificates are parsed locally — nothing ever leaves the page.
 *
 * - `parseCertificate(der)` decodes one DER certificate with a strict DER reader:
 *   definite lengths only (short and long form, up to 4 length octets;
 *   non-minimal long forms are tolerated), every read bounds-checked, no
 *   trailing data. Malformed structure raises `CertificateParseError` (never a
 *   RangeError/TypeError). A malformed *extension* or public key does not fail
 *   the whole certificate: it is recorded in `parseErrors` and the affected
 *   fields keep their defaults.
 * - `parseCertificates(input)` is the forgiving front door used by the UI. It
 *   accepts PEM (any number of blocks, CRLF, indentation, e-mail `>` quoting,
 *   JSON escapes such as `\n`, `\/` and `\u002B`, surrounding prose),
 *   raw DER (also several concatenated), bare base64, base64 of a PEM file
 *   (e.g. Kubernetes `tls.crt`), PKCS#7 / .p7b (PEM or DER, BER indefinite
 *   lengths tolerated in the container), and it
 *   recognises PKCS#12, CSRs and private keys (which are reported, never
 *   decoded or returned). It never throws.
 * - `loadCertificates(input, { password })` is the same front door, asynchronous, that also
 *   opens a PKCS#12 (.pfx / .p12) bundle with its password through lib/pkcs12.js: the
 *   certificates join the result, the private keys never do (an opt-in key check says whether
 *   the key belongs to the leaf). It never rejects.
 * - Distinguished names are rendered like `openssl x509 -nameopt RFC2253`:
 *   RDNs in reverse order, OpenSSL short attribute names, RFC 4514 escaping,
 *   unknown attributes (and non-string values) as `OID=#HEXDER`, multi-valued
 *   RDNs joined by '+'. The one difference: non-ASCII characters are kept as
 *   Unicode (exactly `-nameopt RFC2253,-esc_msb`) because Turkish names such as
 *   "Örnek A.Ş." must stay readable; `formatDN(rdns, { escapeNonAscii: true })`
 *   gives the byte-exact OpenSSL default (`\C3\96rnek A.\C5\9E.`).
 */

import { sha1, sha256 } from './sha.js';
import { openPkcs12, Pkcs12Error } from './pkcs12.js';

/** Error thrown by `parseCertificate()` for malformed DER / ASN.1 input. */
export class CertificateParseError extends Error {
  /**
   * @param {string} message
   * @param {number|null} [offset] byte offset of the offending element (when known)
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, offset = null, options = undefined) {
    super(message, options);
    this.name = 'CertificateParseError';
    this.offset = offset;
  }
}

// ---------------------------------------------------------------------------
// OID tables
// ---------------------------------------------------------------------------

/**
 * Distinguished-name attribute types → OpenSSL short names (as printed by
 * `-nameopt RFC2253`). Attributes missing here are printed as `dotted.oid=#HEX`.
 */
const DN_NAMES = Object.freeze({
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L',
  '2.5.4.8': 'ST', '2.5.4.9': 'street', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'title',
  '2.5.4.13': 'description', '2.5.4.14': 'searchGuide', '2.5.4.15': 'businessCategory',
  '2.5.4.16': 'postalAddress', '2.5.4.17': 'postalCode', '2.5.4.18': 'postOfficeBox',
  '2.5.4.19': 'physicalDeliveryOfficeName', '2.5.4.20': 'telephoneNumber', '2.5.4.21': 'telexNumber',
  '2.5.4.22': 'teletexTerminalIdentifier', '2.5.4.23': 'facsimileTelephoneNumber',
  '2.5.4.24': 'x121Address', '2.5.4.25': 'internationaliSDNNumber', '2.5.4.26': 'registeredAddress',
  '2.5.4.27': 'destinationIndicator', '2.5.4.28': 'preferredDeliveryMethod',
  '2.5.4.29': 'presentationAddress', '2.5.4.30': 'supportedApplicationContext', '2.5.4.31': 'member',
  '2.5.4.32': 'owner', '2.5.4.33': 'roleOccupant', '2.5.4.34': 'seeAlso', '2.5.4.35': 'userPassword',
  '2.5.4.36': 'userCertificate', '2.5.4.37': 'cACertificate', '2.5.4.38': 'authorityRevocationList',
  '2.5.4.39': 'certificateRevocationList', '2.5.4.40': 'crossCertificatePair', '2.5.4.41': 'name',
  '2.5.4.42': 'GN', '2.5.4.43': 'initials', '2.5.4.44': 'generationQualifier',
  '2.5.4.45': 'x500UniqueIdentifier', '2.5.4.46': 'dnQualifier', '2.5.4.47': 'enhancedSearchGuide',
  '2.5.4.48': 'protocolInformation', '2.5.4.49': 'distinguishedName', '2.5.4.50': 'uniqueMember',
  '2.5.4.51': 'houseIdentifier', '2.5.4.52': 'supportedAlgorithms', '2.5.4.53': 'deltaRevocationList',
  '2.5.4.54': 'dmdName', '2.5.4.65': 'pseudonym', '2.5.4.72': 'role', '2.5.4.97': 'organizationIdentifier',
  '2.5.4.98': 'c3', '2.5.4.99': 'n3', '2.5.4.100': 'dnsName',
  '1.2.840.113549.1.9.1': 'emailAddress', '1.2.840.113549.1.9.2': 'unstructuredName',
  '1.2.840.113549.1.9.8': 'unstructuredAddress',
  '0.9.2342.19200300.100.1.1': 'UID', '0.9.2342.19200300.100.1.3': 'mail',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
  '1.3.6.1.5.5.7.9.1': 'id-pda-dateOfBirth', '1.3.6.1.5.5.7.9.2': 'id-pda-placeOfBirth',
  '1.3.6.1.5.5.7.9.3': 'id-pda-gender', '1.3.6.1.5.5.7.9.4': 'id-pda-countryOfCitizenship',
  '1.3.6.1.5.5.7.9.5': 'id-pda-countryOfResidence'
});

/** Signature algorithms → OpenSSL names (as printed by `openssl x509 -text`). */
const SIG_ALG_NAMES = Object.freeze({
  '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
  '1.2.840.113549.1.1.3': 'md4WithRSAEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
  '1.2.840.113549.1.1.15': 'sha512-224WithRSAEncryption',
  '1.2.840.113549.1.1.16': 'sha512-256WithRSAEncryption',
  '1.3.14.3.2.29': 'sha1WithRSA',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10040.4.3': 'dsaWithSHA1',
  '2.16.840.1.101.3.4.3.1': 'dsa_with_SHA224',
  '2.16.840.1.101.3.4.3.2': 'dsa_with_SHA256',
  '2.16.840.1.101.3.4.3.9': 'ecdsa_with_SHA3-224',
  '2.16.840.1.101.3.4.3.10': 'ecdsa_with_SHA3-256',
  '2.16.840.1.101.3.4.3.11': 'ecdsa_with_SHA3-384',
  '2.16.840.1.101.3.4.3.12': 'ecdsa_with_SHA3-512',
  '2.16.840.1.101.3.4.3.13': 'RSA-SHA3-224',
  '2.16.840.1.101.3.4.3.14': 'RSA-SHA3-256',
  '2.16.840.1.101.3.4.3.15': 'RSA-SHA3-384',
  '2.16.840.1.101.3.4.3.16': 'RSA-SHA3-512',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
  '1.3.101.112': 'ED25519',
  '1.3.101.113': 'ED448',
  '1.2.156.10197.1.501': 'SM2-with-SM3'
});

/** Public-key algorithm OID → contract family ('RSA' | 'EC' | 'Ed25519' | 'Ed448' | 'DSA'). */
const KEY_FAMILIES = Object.freeze({
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.10': 'RSA',
  '2.5.8.1.1': 'RSA',
  '1.2.840.10045.2.1': 'EC',
  '1.3.132.1.12': 'EC',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '1.2.840.10040.4.1': 'DSA',
  '1.3.14.3.2.12': 'DSA'
});

/** Public-key algorithm OID → OpenSSL name ("Public Key Algorithm:" line). */
const KEY_ALG_NAMES = Object.freeze({
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '2.5.8.1.1': 'rsa',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.3.132.1.12': 'id-ecDH',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448',
  '1.3.101.112': 'ED25519',
  '1.3.101.113': 'ED448',
  '1.2.840.10040.4.1': 'dsaEncryption',
  '1.3.14.3.2.12': 'dsaEncryption-old',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87'
});

/** Named EC curves → [API name, key size in bits]. NIST curves use their FIPS names. */
const CURVES = Object.freeze({
  '1.2.840.10045.3.1.7': ['P-256', 256],
  '1.3.132.0.34': ['P-384', 384],
  '1.3.132.0.35': ['P-521', 521],
  '1.2.840.10045.3.1.1': ['P-192', 192],
  '1.3.132.0.33': ['P-224', 224],
  '1.3.132.0.10': ['secp256k1', 256],
  '1.3.36.3.3.2.8.1.1.7': ['brainpoolP256r1', 256],
  '1.3.36.3.3.2.8.1.1.11': ['brainpoolP384r1', 384],
  '1.3.36.3.3.2.8.1.1.13': ['brainpoolP512r1', 512],
  '1.2.156.10197.1.301': ['SM2', 256]
});

/** Extended key usage OIDs → names (unknown ones are reported as dotted OIDs). */
const EKU_NAMES = Object.freeze({
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.5': 'ipsecEndSystem',
  '1.3.6.1.5.5.7.3.6': 'ipsecTunnel',
  '1.3.6.1.5.5.7.3.7': 'ipsecUser',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  '1.3.6.1.5.5.7.3.17': 'ipsecIKE',
  '2.5.29.37.0': 'anyExtendedKeyUsage',
  '1.3.6.1.4.1.311.10.3.3': 'msSGC',
  '2.16.840.1.113730.4.1': 'nsSGC',
  '1.3.6.1.4.1.311.20.2.2': 'msSmartcardLogin'
});

/** KeyUsage BIT STRING bit positions (RFC 5280 §4.2.1.3). */
const KEY_USAGE_BITS = Object.freeze([
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement',
  'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
]);

const OID = Object.freeze({
  SAN: '2.5.29.17',
  BASIC_CONSTRAINTS: '2.5.29.19',
  KEY_USAGE: '2.5.29.15',
  EXT_KEY_USAGE: '2.5.29.37',
  SKI: '2.5.29.14',
  AKI: '2.5.29.35',
  CRL_DP: '2.5.29.31',
  POLICIES: '2.5.29.32',
  AIA: '1.3.6.1.5.5.7.1.1',
  TLS_FEATURE: '1.3.6.1.5.5.7.1.24',
  CT_POISON: '1.3.6.1.4.1.11129.2.4.3',
  CT_SCTS: '1.3.6.1.4.1.11129.2.4.2',
  AD_OCSP: '1.3.6.1.5.5.7.48.1',
  AD_CA_ISSUERS: '1.3.6.1.5.5.7.48.2',
  PKCS7_DATA: '1.2.840.113549.1.7.1',
  PKCS7_SIGNED_DATA: '1.2.840.113549.1.7.2',
  CN: '2.5.4.3'
});

/** Certificate extension OIDs → display names. */
const EXT_NAMES = Object.freeze({
  '2.5.29.9': 'subjectDirectoryAttributes', '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage',
  '2.5.29.16': 'privateKeyUsagePeriod', '2.5.29.17': 'subjectAltName', '2.5.29.18': 'issuerAltName',
  '2.5.29.19': 'basicConstraints', '2.5.29.30': 'nameConstraints', '2.5.29.31': 'crlDistributionPoints',
  '2.5.29.32': 'certificatePolicies', '2.5.29.33': 'policyMappings', '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.36': 'policyConstraints', '2.5.29.37': 'extendedKeyUsage', '2.5.29.46': 'freshestCRL',
  '2.5.29.54': 'inhibitAnyPolicy',
  '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '1.3.6.1.5.5.7.1.3': 'qcStatements',
  '1.3.6.1.5.5.7.1.11': 'subjectInfoAccess', '1.3.6.1.5.5.7.1.24': 'tlsFeature',
  '1.3.6.1.5.5.7.48.1.5': 'ocspNoCheck',
  '1.3.6.1.4.1.11129.2.4.2': 'ctPrecertificateScts', '1.3.6.1.4.1.11129.2.4.3': 'ctPrecertificatePoison',
  '2.16.840.1.113730.1.1': 'nsCertType', '2.16.840.1.113730.1.13': 'nsComment',
  '1.3.6.1.4.1.311.20.2': 'msCertificateTemplateName', '1.3.6.1.4.1.311.21.1': 'msCaVersion',
  '1.3.6.1.4.1.311.21.2': 'msPreviousCaCertHash', '1.3.6.1.4.1.311.21.7': 'msCertificateTemplate',
  '1.3.6.1.4.1.311.21.10': 'msApplicationPolicies'
});

/** CA/Browser Forum certificate policy OIDs → validation level. */
const VALIDATION_POLICIES = Object.freeze({
  '2.23.140.1.1': 'EV',
  '2.23.140.1.2.2': 'OV',
  '2.23.140.1.2.3': 'IV',
  '2.23.140.1.2.1': 'DV'
});

/**
 * Value tags OpenSSL prints as text in `-nameopt RFC2253` (see tag2nbyte in
 * crypto/asn1/a_strex.c): UTF8String, NumericString, PrintableString,
 * T61String, IA5String, UTCTime, GeneralizedTime, VisibleString,
 * UniversalString, BMPString. Any other value type is dumped as #HEX.
 */
const DN_TEXT_TAGS = new Set([0x0c, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1a, 0x1c, 0x1e]);

// ---------------------------------------------------------------------------
// Byte / text helpers
// ---------------------------------------------------------------------------

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i]];
  return out;
}

function latin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return out;
}

// ignoreBOM keeps a leading U+FEFF inside ASN.1 strings (data fidelity).
const UTF8_DECODER = new TextDecoder('utf-8', { ignoreBOM: true });
const UTF8_ENCODER = new TextEncoder();

function utf16(bytes, littleEndian) {
  let out = '';
  const n = bytes.length - (bytes.length % 2);
  for (let i = 0; i < n; i += 2) {
    out += String.fromCharCode(littleEndian ? bytes[i] | (bytes[i + 1] << 8) : (bytes[i] << 8) | bytes[i + 1]);
  }
  return bytes.length % 2 ? `${out}\uFFFD` : out;
}

function utf32be(bytes) {
  let out = '';
  const n = bytes.length - (bytes.length % 4);
  for (let i = 0; i < n; i += 4) {
    const cp = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    out += cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? '\uFFFD' : String.fromCodePoint(cp);
  }
  return bytes.length % 4 ? `${out}\uFFFD` : out;
}

/**
 * Converts supported binary inputs to a Uint8Array view (no copy).
 * @returns {Uint8Array|null}
 */
function asBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input == null || typeof input !== 'object') return null;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  const tag = Object.prototype.toString.call(input);
  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(input);
  return null;
}

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) table[B64_ALPHABET.charCodeAt(i)] = i;
  table[45] = 62; // '-' (base64url)
  table[95] = 63; // '_' (base64url)
  return table;
})();

/**
 * Decodes standard or URL-safe base64; whitespace is ignored, padding optional.
 * @returns {Uint8Array|null} null when the text is not valid base64
 */
function decodeBase64(text) {
  const s = text.replace(/\s+/g, '');
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--; // '='
  if (s.length - end > 2 || end % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((end * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < end; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64_LOOKUP[c] : -1;
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

function encodeBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64_ALPHABET[n >> 18] + B64_ALPHABET[(n >> 12) & 63] + B64_ALPHABET[(n >> 6) & 63] + B64_ALPHABET[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += `${B64_ALPHABET[n >> 18]}${B64_ALPHABET[(n >> 12) & 63]}==`;
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += `${B64_ALPHABET[n >> 18]}${B64_ALPHABET[(n >> 12) & 63]}${B64_ALPHABET[(n >> 6) & 63]}=`;
  }
  return out;
}

// ---------------------------------------------------------------------------
// DER reader
// ---------------------------------------------------------------------------

/** Maximum nesting depth followed while skipping BER indefinite-length content. */
const MAX_BER_DEPTH = 64;

function fail(message, offset = null) {
  throw new CertificateParseError(message, offset);
}

/**
 * @typedef {object} Asn1Node
 * @property {number} id first identifier octet (class | constructed | tag number < 31)
 * @property {number} cls tag class (0 universal, 1 application, 2 context, 3 private)
 * @property {boolean} constructed
 * @property {number} num tag number
 * @property {number} offset start of the TLV
 * @property {number} start start of the contents
 * @property {number} end end of the contents (exclusive)
 * @property {number} next first byte after the TLV (end + 2 for BER indefinite lengths)
 * @property {Uint8Array} bytes the buffer the offsets refer to
 */

/**
 * Reads one TLV at `pos`. Strict DER unless `ber` is set, in which case
 * constructed values may use indefinite length (used only for container
 * sniffing: PKCS#7 / PKCS#12). Every read is bounds-checked against `limit`.
 * @returns {Asn1Node}
 */
function readNode(bytes, pos, limit, ber = false, depth = 0) {
  const offset = pos;
  if (pos >= limit) fail('Unexpected end of data', pos);
  const id = bytes[pos++];
  const constructed = (id & 0x20) !== 0;
  let num = id & 0x1f;
  if (num === 0x1f) {
    // High-tag-number form: base-128 tag number follows.
    num = 0;
    let b;
    let count = 0;
    do {
      if (pos >= limit) fail('Truncated tag', offset);
      if (++count > 4) fail('Tag number too large', offset);
      b = bytes[pos++];
      num = num * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (pos >= limit) fail('Truncated length', offset);
  let len = bytes[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) {
      if (!ber || !constructed) fail('Indefinite length is not allowed in DER', offset);
      if (depth >= MAX_BER_DEPTH) fail('ASN.1 nesting too deep', offset);
      let p = pos;
      for (;;) {
        if (p + 2 > limit) fail('Missing end-of-contents marker', offset);
        if (bytes[p] === 0 && bytes[p + 1] === 0) break;
        p = readNode(bytes, p, limit, true, depth + 1).next;
      }
      return { id, cls: id >> 6, constructed, num, offset, start: pos, end: p, next: p + 2, bytes };
    }
    if (n > 4) fail('Length field too large', offset);
    if (pos + n > limit) fail('Truncated length', offset);
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[pos++];
  }
  const end = pos + len;
  if (end > limit) fail('Truncated value: length exceeds the available data', offset);
  return { id, cls: id >> 6, constructed, num, offset, start: pos, end, next: end, bytes };
}

/** Parses the children of a constructed node; they must exactly fill its contents. */
function childrenOf(node, ber = false) {
  if (!node.constructed) fail('Expected a constructed ASN.1 value', node.offset);
  const out = [];
  let p = node.start;
  while (p < node.end) {
    const child = readNode(node.bytes, p, node.end, ber);
    out.push(child);
    p = child.next;
  }
  return out;
}

/** Parses a buffer that must hold exactly one TLV (extension values). */
function parseSingle(bytes) {
  const node = readNode(bytes, 0, bytes.length);
  if (node.next !== bytes.length) fail('Unexpected data after ASN.1 value', node.next);
  return node;
}

const contents = (node) => node.bytes.subarray(node.start, node.end);
const tlv = (node) => node.bytes.subarray(node.offset, node.next);

function tagHex(id) {
  return `0x${HEX[id]}`;
}

function expect(node, id, what) {
  if (!node) fail(`Missing ${what}`);
  if (node.id !== id) fail(`Expected ${what} (tag ${tagHex(id)}), found tag ${tagHex(node.id)}`, node.offset);
  return node;
}

function decodeOid(node) {
  const v = contents(expect(node, 0x06, 'OBJECT IDENTIFIER'));
  if (!v.length) fail('Empty OBJECT IDENTIFIER', node.offset);
  if (v[v.length - 1] & 0x80) fail('Truncated OBJECT IDENTIFIER', node.offset);
  const arcs = [];
  let n = 0;
  let big = null; // switches to BigInt for arcs ≥ 2^45 (e.g. 2.25.<uuid>)
  for (const b of v) {
    if (big !== null) big = (big << 7n) | BigInt(b & 0x7f);
    else if (n >= 2 ** 45) big = (BigInt(n) << 7n) | BigInt(b & 0x7f);
    else n = n * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(big !== null ? big : n);
      n = 0;
      big = null;
    }
  }
  // The first subidentifier packs the first two arcs as 40 * X + Y (X ≤ 2).
  const first = arcs[0];
  let head;
  if (typeof first === 'bigint') head = `2.${first - 80n}`;
  else if (first < 40) head = `0.${first}`;
  else if (first < 80) head = `1.${first - 40}`;
  else head = `2.${first - 80}`;
  return arcs.length > 1 ? `${head}.${arcs.slice(1).join('.')}` : head;
}

/** INTEGER → lowercase hex of its content octets without leading 00 (sign) bytes. */
function integerHex(node) {
  const v = contents(expect(node, 0x02, 'INTEGER'));
  if (!v.length) fail('Empty INTEGER', node.offset);
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  return toHex(v.subarray(i));
}

/** INTEGER → Number (signed two's complement; precision loss above 2^53 is acceptable here). */
function integerValue(node) {
  const v = contents(expect(node, 0x02, 'INTEGER'));
  if (!v.length) fail('Empty INTEGER', node.offset);
  if (v.length > 6) {
    let big = 0n;
    for (const b of v) big = (big << 8n) | BigInt(b);
    if (v[0] & 0x80) big -= 1n << BigInt(v.length * 8);
    return Number(big);
  }
  let n = 0;
  for (const b of v) n = n * 256 + b;
  return v[0] & 0x80 ? n - 2 ** (v.length * 8) : n;
}

function booleanValue(node) {
  const v = contents(expect(node, 0x01, 'BOOLEAN'));
  if (v.length !== 1) fail('Invalid BOOLEAN length', node.offset);
  return v[0] !== 0;
}

function bitString(node) {
  const v = contents(expect(node, 0x03, 'BIT STRING'));
  if (!v.length) fail('Empty BIT STRING', node.offset);
  const unusedBits = v[0];
  if (unusedBits > 7 || (v.length === 1 && unusedBits !== 0)) fail('Invalid BIT STRING unused-bits count', node.offset);
  return { bytes: v.subarray(1), unusedBits };
}

function bitLength(intBytes) {
  let i = 0;
  while (i < intBytes.length && intBytes[i] === 0) i++;
  if (i === intBytes.length) return 0;
  return (intBytes.length - i - 1) * 8 + (32 - Math.clz32(intBytes[i]));
}

/**
 * Decodes an ASN.1 character string. Returns null for non-string types.
 * TeletexString is treated as Latin-1 (like OpenSSL), BMPString as UTF-16BE,
 * UniversalString as UTF-32BE.
 */
function decodeString(node) {
  if (node.constructed || node.cls !== 0) return null;
  const v = contents(node);
  switch (node.num) {
    case 0x0c: return UTF8_DECODER.decode(v);
    case 0x1e: return utf16(v, false);
    case 0x1c: return utf32be(v);
    case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17: case 0x18: case 0x19: case 0x1a: case 0x1b:
      return latin1(v);
    default: return null;
  }
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * UTCTime (YY < 50 → 20YY, else 19YY) or GeneralizedTime (fractional seconds
 * allowed) → Date. Accepts the lenient BER forms too (missing seconds, ±hhmm
 * offsets, GeneralizedTime without zone = UTC).
 */
const UTC_TIME_RE = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/;
const GENERALIZED_TIME_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,](\d{1,12}))?(Z|[+-]\d{4})?$/;

function decodeTime(node) {
  const s = latin1(contents(node));
  // Normalised to [year, month, day, hour, minute?, second?, fraction?, zone?]
  let parts;
  if (node.id === 0x17) {
    const m = UTC_TIME_RE.exec(s);
    if (!m) fail(`Invalid UTCTime "${s.slice(0, 32)}"`, node.offset);
    const yy = Number(m[1]);
    parts = [yy < 50 ? 2000 + yy : 1900 + yy, m[2], m[3], m[4], m[5], m[6], undefined, m[7]];
  } else if (node.id === 0x18) {
    const m = GENERALIZED_TIME_RE.exec(s);
    if (!m) fail(`Invalid GeneralizedTime "${s.slice(0, 32)}"`, node.offset);
    parts = [Number(m[1]), m[2], m[3], m[4], m[5], m[6], m[7], m[8]];
  } else {
    fail(`Expected UTCTime or GeneralizedTime, found tag ${tagHex(node.id)}`, node.offset);
  }
  const [year, mm, dd, hh, mi, ss, fraction, zone] = parts;
  const month = Number(mm);
  const day = Number(dd);
  const hour = Number(hh);
  const minute = mi ? Number(mi) : 0;
  const second = ss ? Number(ss) : 0;
  const ms = fraction ? Number(fraction.slice(0, 3).padEnd(3, '0')) : 0; // truncated to milliseconds
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const dim = month === 2 && leap ? 29 : DAYS_IN_MONTH[month - 1];
  if (month < 1 || month > 12 || day < 1 || day > dim || hour > 23 || minute > 59 || second > 60) {
    fail(`Invalid date/time value "${s.slice(0, 32)}"`, node.offset);
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day); // setUTCFullYear keeps years < 100 literal
  date.setUTCHours(hour, minute, second, ms);
  if (zone && zone !== 'Z') {
    const sign = zone[0] === '-' ? -1 : 1;
    const zh = Number(zone.slice(1, 3));
    const zm = Number(zone.slice(3, 5));
    if (zh > 23 || zm > 59) fail(`Invalid time zone offset "${zone}"`, node.offset);
    date.setTime(date.getTime() - sign * (zh * 60 + zm) * 60000);
  }
  return date;
}

function parseAlgorithm(node) {
  const kids = childrenOf(expect(node, 0x30, 'AlgorithmIdentifier'));
  if (kids.length < 1 || kids.length > 2) fail('Malformed AlgorithmIdentifier', node.offset);
  const oid = decodeOid(kids[0]);
  return { oid, params: kids[1] || null };
}

// ---------------------------------------------------------------------------
// Distinguished names
// ---------------------------------------------------------------------------

/**
 * @typedef {object} DnAttribute
 * @property {string} oid dotted attribute type
 * @property {string} shortName OpenSSL short name ('CN', 'O', ...) or the dotted OID when unknown
 * @property {string} value decoded text; '#HEX' (DER of the value) for non-string types
 * @property {number} tag ASN.1 identifier octet of the value (0x0c UTF8String, 0x13 PrintableString, ...)
 * @property {Uint8Array} valueDer DER TLV of the value
 */

/** @returns {DnAttribute[][]} RDNs in DER order (each RDN = one or more attributes) */
function parseName(node) {
  const rdns = [];
  for (const rdnNode of childrenOf(expect(node, 0x30, 'Name'))) {
    const atvs = childrenOf(expect(rdnNode, 0x31, 'RelativeDistinguishedName (SET)'));
    if (!atvs.length) fail('Empty RelativeDistinguishedName', rdnNode.offset);
    rdns.push(atvs.map((atvNode) => {
      const parts = childrenOf(expect(atvNode, 0x30, 'AttributeTypeAndValue'));
      if (parts.length !== 2) fail('Malformed AttributeTypeAndValue', atvNode.offset);
      const oid = decodeOid(parts[0]);
      const valueDer = tlv(parts[1]);
      const text = decodeString(parts[1]);
      return {
        oid,
        shortName: DN_NAMES[oid] || oid,
        value: text !== null ? text : `#${toHex(valueDer).toUpperCase()}`,
        tag: parts[1].id,
        valueDer
      };
    }));
  }
  return rdns;
}

/** First value per attribute short name, e.g. { CN: 'www.example.com', O: 'Example', C: 'TR' }. */
function firstValues(rdns) {
  const out = {};
  for (const rdn of rdns) {
    for (const atv of rdn) {
      if (!Object.prototype.hasOwnProperty.call(out, atv.shortName)) out[atv.shortName] = atv.value;
    }
  }
  return out;
}

// Invisible bidirectional-formatting characters are escaped even in Unicode
// mode so a hostile DN cannot visually reorder itself in the UI.
const BIDI_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

function escapeUtf8Bytes(ch) {
  let out = '';
  for (const b of UTF8_ENCODER.encode(ch)) out += `\\${HEX[b].toUpperCase()}`;
  return out;
}

/**
 * Escapes one attribute value like OpenSSL's RFC 2253 mode (do_esc_char):
 * `"` `+` `,` `;` `<` `>` `\` are backslash-escaped, `#` only as the first
 * character and space only as the first or last character (for a
 * one-character value only the "last" rule applies — an OpenSSL quirk kept for
 * parity), control characters become `\XX`. Non-ASCII characters are kept
 * unless `escapeNonAscii` is set (then each UTF-8 byte becomes `\XX`).
 * @param {string} value
 * @param {{ escapeNonAscii?: boolean }} [options]
 * @returns {string}
 */
export function escapeDNValue(value, { escapeNonAscii = false } = {}) {
  const chars = Array.from(String(value ?? ''));
  let out = '';
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const c = ch.codePointAt(0);
    const last = i === chars.length - 1;
    const first = i === 0 && !last;
    if (c > 0x7f) {
      out += escapeNonAscii || BIDI_CONTROLS.test(ch) ? escapeUtf8Bytes(ch) : ch;
    } else if ('"+,;<>\\'.includes(ch)) {
      out += `\\${ch}`;
    } else if ((ch === '#' && first) || (ch === ' ' && (first || last))) {
      out += `\\${ch}`;
    } else if (c < 0x20 || c === 0x7f) {
      out += `\\${HEX[c].toUpperCase()}`;
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Formats RDNs (as found in `cert.subjectRDNs` / `cert.issuerRDNs`) like
 * `openssl x509 -nameopt RFC2253`: attributes in reverse DER order joined by
 * ',' ('+' inside a multi-valued RDN), OpenSSL short names, unknown attribute
 * types and non-string values as `type=#HEXDER`.
 * @param {DnAttribute[][]} rdns
 * @param {{ escapeNonAscii?: boolean }} [options] escapeNonAscii: true = byte-exact OpenSSL default output
 * @returns {string}
 */
export function formatDN(rdns, { escapeNonAscii = false } = {}) {
  if (!Array.isArray(rdns)) return '';
  const flat = [];
  rdns.forEach((rdn, set) => {
    for (const atv of Array.isArray(rdn) ? rdn : [rdn]) if (atv) flat.push([set, atv]);
  });
  let out = '';
  let prev = -1;
  for (let i = flat.length - 1; i >= 0; i--) {
    const [set, atv] = flat[i];
    if (prev !== -1) out += set === prev ? '+' : ',';
    prev = set;
    const name = Object.prototype.hasOwnProperty.call(DN_NAMES, atv.oid) ? DN_NAMES[atv.oid] : null;
    const key = name || atv.oid || atv.shortName;
    const der = atv.valueDer instanceof Uint8Array && atv.valueDer.length ? atv.valueDer : null;
    if (der && (!name || !DN_TEXT_TAGS.has(atv.tag))) {
      out += `${key}=#${toHex(der).toUpperCase()}`;
    } else {
      out += `${key}=${escapeDNValue(atv.value, { escapeNonAscii })}`;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// General names, IP addresses, host names
// ---------------------------------------------------------------------------

function formatIPv6(b) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push((b[i] << 8) | b[i + 1]);
  // IPv4-mapped addresses keep dotted notation (RFC 5952 §5; same as netinfo.normalizeIP).
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return `::ffff:${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  }
  // RFC 5952 §4.2: compress the longest run (≥ 2) of zero groups, the first one on ties.
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = (list) => list.map((g) => g.toString(16)).join(':');
  if (bestStart < 0) return hex(groups);
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLen))}`;
}

/** iPAddress octets → canonical text (null for lengths other than 4 / 16). */
function formatIpBytes(b) {
  if (b.length === 4) return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
  if (b.length === 16) return formatIPv6(b);
  return null;
}

/**
 * @typedef {{ type: 'dns'|'ip'|'email'|'uri'|'dirName'|'otherName'|'registeredId'|'x400Address'|'ediPartyName'|'unknown', value: string, oid?: string }} GeneralName
 */

/** @returns {GeneralName} */
function parseGeneralName(node) {
  if (node.cls !== 2) return { type: 'unknown', value: `#${toHex(tlv(node))}` };
  const primitive = (what) => {
    if (node.constructed) fail(`${what} must be primitive`, node.offset);
    return contents(node);
  };
  switch (node.num) {
    case 0: { // otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
      const kids = childrenOf(node);
      const oid = decodeOid(kids[0]);
      let value = '';
      if (kids[1] && kids[1].id === 0xa0) {
        const inner = childrenOf(kids[1])[0];
        if (inner) {
          const text = decodeString(inner);
          value = text !== null ? text : `#${toHex(tlv(inner))}`;
        }
      }
      return { type: 'otherName', oid, value };
    }
    case 1: return { type: 'email', value: latin1(primitive('rfc822Name')) };
    case 2: return { type: 'dns', value: latin1(primitive('dNSName')) };
    case 3: return { type: 'x400Address', value: `#${toHex(contents(node))}` };
    case 4: { // directoryName: [4] EXPLICIT Name (Name is a CHOICE)
      const kids = childrenOf(node);
      if (kids.length !== 1) fail('Malformed directoryName', node.offset);
      return { type: 'dirName', value: formatDN(parseName(kids[0])) };
    }
    case 5: return { type: 'ediPartyName', value: `#${toHex(contents(node))}` };
    case 6: return { type: 'uri', value: latin1(primitive('uniformResourceIdentifier')) };
    case 7: {
      const raw = primitive('iPAddress');
      return { type: 'ip', value: formatIpBytes(raw) ?? `#${toHex(raw)}` };
    }
    case 8: {
      primitive('registeredID');
      return { type: 'registeredId', value: decodeOid({ ...node, id: 0x06 }) };
    }
    default: return { type: 'unknown', value: `#${toHex(tlv(node))}` };
  }
}

function parseGeneralNames(node) {
  return childrenOf(node).map(parseGeneralName);
}

/** ASCII characters a name may hold for the IDN conversion: letters, digits, '-', '_', '.' and a leading '*.'. */
const IDN_ASCII_RE = /^(?:\*\.)?[a-z0-9._-]*$/;

/**
 * Lowercase, strip trailing dot(s), IDN → punycode (via WHATWG URL, available everywhere), label
 * by label. Only a name whose ASCII part is label characters is converted: the URL parser would
 * read '@', ':', '/', '\', '?' or '#' as a user name, port or path and keep only part of the name
 * ('ä@victim.example' → 'victim.example'). A non-ASCII label must become one A-label ('xn--…')
 * that decodes back to that very label: the IDNA mapping turns a soft hyphen, a zero-width space,
 * full-width letters or '。' into another name no TLS client would match against this one
 * ('ｖｉｃｔｉｍ.example' → 'victim.example', 'ｍüｎｃｈｅｎ.example' → 'xn--mnchen-3ya.example').
 * Such names stay as they are and never cover anything. Shared with lib/verify.js.
 * @param {string} name
 * @returns {string}
 */
export function normalizeCertHostname(name) {
  const h = String(name).trim().toLowerCase().replace(/\.+$/, '');
  if (!/[^\x00-\x7f]/.test(h) || !IDN_ASCII_RE.test(h.replace(/[^\x00-\x7f]/g, ''))) return h;
  const labels = h.split('.');
  for (let i = 0; i < labels.length; i += 1) {
    if (!/[^\x00-\x7f]/.test(labels[i])) continue;
    let label = null;
    try {
      label = new URL(`http://${labels[i]}/`).hostname;
    } catch {
      /* not a label: keep the lowercase form */
    }
    if (!label || !/^xn--[a-z0-9-]+$/.test(label) || punycodeDecode(label.slice(4)) !== labels[i]) return h;
    labels[i] = label;
  }
  return labels.join('.');
}

/**
 * RFC 3492 decoding of the part of an A-label after 'xn--', or null when it is malformed.
 * @param {string} input
 * @returns {string|null}
 */
function punycodeDecode(input) {
  const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;
  const cut = input.lastIndexOf('-');
  const out = cut > 0 ? [...input.slice(0, cut)].map((c) => c.codePointAt(0)) : [];
  let n = 128;
  let i = 0;
  let bias = 72;
  for (let p = cut > 0 ? cut + 1 : 0; p < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (p >= input.length) return null;
      const c = input.charCodeAt(p++);
      const digit = c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : c >= 65 && c <= 90 ? c - 65 : BASE;
      if (digit >= BASE) return null;
      i += digit * w;
      if (i > 0x10ffff * (out.length + 1)) return null;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = out.length + 1;
    let delta = oldi === 0 ? Math.floor(i / DAMP) : Math.floor((i - oldi) / 2);
    delta += Math.floor(delta / len);
    let k = 0;
    while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
      delta = Math.floor(delta / (BASE - T_MIN));
      k += BASE;
    }
    bias = k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) return null;
    out.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...out);
}

const LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** True for "legacy.example.org" / "*.example.org"; false for "Test Root CA", IPs, single labels. */
function isHostnameLike(h) {
  if (!h || h.length > 253) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  if (labels[0] === '*') labels.shift();
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return false;
  return /[a-z]/.test(labels[labels.length - 1]);
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

function sequenceOf(bytes, what) {
  return childrenOf(expect(parseSingle(bytes), 0x30, what));
}

/**
 * Extension handlers: (extnValue bytes, cert) → void. Each handler computes
 * into locals and assigns at the end so a malformed extension leaves the
 * certificate's defaults untouched.
 */
const EXTENSION_HANDLERS = {
  [OID.SAN](bytes, cert) {
    const names = parseGeneralNames(expect(parseSingle(bytes), 0x30, 'GeneralNames'));
    cert.sans = names.map(({ type, value, oid }) => (oid ? { type, value, oid } : { type, value }));
    cert.dnsNames = names.filter((n) => n.type === 'dns').map((n) => n.value);
    cert.ipAddresses = names.filter((n) => n.type === 'ip' && !n.value.startsWith('#')).map((n) => n.value);
    cert.emails = names.filter((n) => n.type === 'email').map((n) => n.value);
    cert.uris = names.filter((n) => n.type === 'uri').map((n) => n.value);
  },

  [OID.BASIC_CONSTRAINTS](bytes, cert) {
    const kids = sequenceOf(bytes, 'BasicConstraints');
    let i = 0;
    let isCA = false;
    let pathLen = null;
    if (kids[i] && kids[i].id === 0x01) isCA = booleanValue(kids[i++]);
    if (kids[i] && kids[i].id === 0x02) pathLen = integerValue(kids[i++]);
    if (i !== kids.length) fail('Malformed BasicConstraints');
    cert.isCA = isCA;
    cert.pathLen = pathLen;
  },

  [OID.KEY_USAGE](bytes, cert) {
    const { bytes: bits, unusedBits } = bitString(parseSingle(bytes));
    const total = bits.length * 8 - unusedBits;
    const usage = [];
    for (let i = 0; i < total && i < KEY_USAGE_BITS.length; i++) {
      if (bits[i >> 3] & (0x80 >> (i & 7))) usage.push(KEY_USAGE_BITS[i]);
    }
    cert.keyUsage = usage;
  },

  [OID.EXT_KEY_USAGE](bytes, cert) {
    cert.extKeyUsage = sequenceOf(bytes, 'ExtKeyUsageSyntax').map((n) => {
      const oid = decodeOid(n);
      return EKU_NAMES[oid] || oid;
    });
  },

  [OID.SKI](bytes, cert) {
    cert.subjectKeyId = toHex(contents(expect(parseSingle(bytes), 0x04, 'SubjectKeyIdentifier')));
  },

  [OID.AKI](bytes, cert) {
    const keyId = sequenceOf(bytes, 'AuthorityKeyIdentifier').find((n) => n.id === 0x80);
    cert.authorityKeyId = keyId ? toHex(contents(keyId)) : null;
  },

  [OID.AIA](bytes, cert) {
    const ocsp = [];
    const caIssuers = [];
    for (const ad of sequenceOf(bytes, 'AuthorityInfoAccessSyntax')) {
      const [method, location] = childrenOf(expect(ad, 0x30, 'AccessDescription'));
      if (!location) fail('Malformed AccessDescription', ad.offset);
      const oid = decodeOid(method);
      const name = parseGeneralName(location);
      if (name.type !== 'uri') continue;
      if (oid === OID.AD_OCSP) ocsp.push(name.value);
      else if (oid === OID.AD_CA_ISSUERS) caIssuers.push(name.value);
    }
    cert.ocspUrls = ocsp;
    cert.caIssuersUrls = caIssuers;
  },

  [OID.CRL_DP](bytes, cert) {
    const urls = [];
    for (const dp of sequenceOf(bytes, 'CRLDistributionPoints')) {
      // DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, ... }
      const dpName = childrenOf(expect(dp, 0x30, 'DistributionPoint')).find((n) => n.id === 0xa0);
      if (!dpName) continue;
      // DistributionPointName ::= CHOICE { fullName [0] IMPLICIT GeneralNames, nameRelativeToCRLIssuer [1] }
      const fullName = childrenOf(dpName).find((n) => n.id === 0xa0);
      if (!fullName) continue;
      for (const gn of parseGeneralNames(fullName)) if (gn.type === 'uri') urls.push(gn.value);
    }
    cert.crlUrls = urls;
  },

  [OID.POLICIES](bytes, cert) {
    const policies = sequenceOf(bytes, 'CertificatePolicies').map((pi) => {
      const [policyId] = childrenOf(expect(pi, 0x30, 'PolicyInformation'));
      return decodeOid(policyId);
    });
    cert.policies = policies;
    cert.validationLevel = ['EV', 'OV', 'IV', 'DV'].find((lvl) => policies.some((p) => VALIDATION_POLICIES[p] === lvl)) || null;
  },

  [OID.TLS_FEATURE](bytes, cert) {
    const features = sequenceOf(bytes, 'TLSFeature').map(integerValue);
    cert.mustStaple = features.includes(5); // status_request (RFC 7633)
  },

  [OID.CT_POISON](bytes, cert) {
    cert.isPrecertificate = true;
  },

  [OID.CT_SCTS](bytes, cert) {
    // extnValue wraps an OCTET STRING holding the TLS-encoded SignedCertificateTimestampList (RFC 6962 §3.3).
    const list = contents(expect(parseSingle(bytes), 0x04, 'SignedCertificateTimestampList'));
    if (list.length < 2) fail('Truncated SCT list');
    const end = Math.min(2 + ((list[0] << 8) | list[1]), list.length);
    const scts = [];
    let p = 2;
    while (p + 2 <= end) {
      const len = (list[p] << 8) | list[p + 1];
      p += 2;
      if (p + len > end) break;
      const sct = list.subarray(p, p + len);
      p += len;
      const entry = { version: sct.length ? sct[0] + 1 : null, logId: null, timestamp: null };
      if (sct.length >= 41 && sct[0] === 0) {
        entry.logId = encodeBase64(sct.subarray(1, 33));
        let ms = 0;
        for (let i = 33; i < 41; i++) ms = ms * 256 + sct[i];
        entry.timestamp = new Date(ms);
      }
      scts.push(entry);
    }
    cert.scts = scts;
    cert.sctCount = scts.length;
  }
};

function parseExtensions(node, cert) {
  const inner = childrenOf(node);
  if (inner.length !== 1) fail('Malformed extensions field', node.offset);
  const seen = new Set();
  for (const extNode of childrenOf(expect(inner[0], 0x30, 'Extensions'))) {
    const parts = childrenOf(expect(extNode, 0x30, 'Extension'));
    if (parts.length < 2 || parts.length > 3) fail('Malformed Extension', extNode.offset);
    const oid = decodeOid(parts[0]);
    const critical = parts.length === 3 ? booleanValue(parts[1]) : false;
    const value = contents(expect(parts[parts.length - 1], 0x04, 'extnValue'));
    const name = EXT_NAMES[oid] || oid;
    cert.extensions.push({ oid, name, critical, length: value.length });
    if (seen.has(oid)) {
      cert.parseErrors.push({ field: name, oid, message: 'Duplicate extension ignored' });
      continue;
    }
    seen.add(oid);
    const handler = EXTENSION_HANDLERS[oid];
    if (!handler) continue;
    try {
      handler(value, cert);
    } catch (err) {
      cert.parseErrors.push({ field: name, oid, message: err instanceof Error ? err.message : String(err) });
    }
  }
}

// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------

function ecPointBits(point) {
  if (point[0] === 0x04 && point.length > 1) return ((point.length - 1) / 2) * 8;
  if ((point[0] === 0x02 || point[0] === 0x03) && point.length > 1) return (point.length - 1) * 8;
  return null;
}

function parsePublicKey(spkiNode, cert) {
  const kids = childrenOf(spkiNode);
  if (kids.length !== 2) fail('Malformed SubjectPublicKeyInfo', spkiNode.offset);
  const alg = parseAlgorithm(kids[0]);
  const { bytes: key } = bitString(kids[1]);
  cert.keyAlgorithm = KEY_FAMILIES[alg.oid] || 'unknown';
  cert.keyAlgorithmOid = alg.oid;
  cert.keyAlgorithmName = KEY_ALG_NAMES[alg.oid] || alg.oid;
  try {
    switch (cert.keyAlgorithm) {
      case 'RSA': {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        const [modulus, exponent] = sequenceOf(key, 'RSAPublicKey');
        cert.keyBits = bitLength(contents(expect(modulus, 0x02, 'RSA modulus')));
        cert.rsaExponent = integerValue(exponent);
        break;
      }
      case 'EC': {
        if (alg.params && alg.params.id === 0x06) {
          const curveOid = decodeOid(alg.params);
          const known = CURVES[curveOid];
          cert.curve = known ? known[0] : curveOid;
          cert.keyBits = known ? known[1] : ecPointBits(key);
        } else {
          cert.keyBits = ecPointBits(key); // explicit / implicit curve parameters
        }
        break;
      }
      case 'Ed25519': cert.keyBits = 256; break;
      case 'Ed448': cert.keyBits = 456; break;
      case 'DSA': {
        // Dss-Parms ::= SEQUENCE { p INTEGER, q INTEGER, g INTEGER } (may be absent/inherited)
        if (alg.params && alg.params.id === 0x30) {
          const [p] = childrenOf(alg.params);
          cert.keyBits = bitLength(contents(expect(p, 0x02, 'DSA p')));
        }
        break;
      }
      default: break;
    }
  } catch (err) {
    cert.parseErrors.push({ field: 'subjectPublicKey', oid: alg.oid, message: err instanceof Error ? err.message : String(err) });
  }
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/**
 * @typedef {object} Certificate
 * @property {Uint8Array} der exact DER bytes of the certificate (own copy)
 * @property {number} version 1, 2 or 3
 * @property {string} serialHex lowercase hex, no leading 00 sign byte
 * @property {string} signatureAlgorithm OpenSSL name, e.g. 'sha256WithRSAEncryption', 'ecdsa-with-SHA256'; dotted OID when unknown
 * @property {Object<string, string>} subject first value per attribute short name ({ CN, O, OU, C, ST, L, ... })
 * @property {string} subjectDN RFC 2253 string (see formatDN)
 * @property {string|null} subjectCN
 * @property {Object<string, string>} issuer
 * @property {string} issuerDN
 * @property {string|null} issuerCN
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {string[]} dnsNames SAN dNSName values as found in the certificate
 * @property {string[]} ipAddresses SAN iPAddress values (IPv4 dotted, IPv6 RFC 5952)
 * @property {string[]} emails SAN rfc822Name values
 * @property {string[]} uris SAN URI values
 * @property {string[]} hostnames normalized dnsNames (lowercase, punycode, no trailing dot, deduped); [CN] fallback when there are none
 * @property {'RSA'|'EC'|'Ed25519'|'Ed448'|'DSA'|'unknown'} keyAlgorithm
 * @property {number|null} keyBits
 * @property {string|null} curve 'P-256' | 'P-384' | 'P-521' | 'secp256k1' | ... | dotted OID | null
 * @property {boolean} isCA
 * @property {number|null} pathLen
 * @property {string[]} keyUsage e.g. ['digitalSignature', 'keyEncipherment']
 * @property {string[]} extKeyUsage e.g. ['serverAuth', 'clientAuth']; unknown as dotted OIDs
 * @property {boolean} selfSigned subject == issuer (and SKI == AKI when both present)
 * @property {string|null} subjectKeyId lowercase hex
 * @property {string|null} authorityKeyId lowercase hex (keyIdentifier only)
 * @property {string[]} ocspUrls
 * @property {string[]} caIssuersUrls
 * @property {string[]} crlUrls
 * @property {boolean} isPrecertificate CT poison extension present
 * @property {number|null} sctCount embedded SCTs (null when the extension is absent)
 *
 * Extensions to the contract:
 * @property {string} signatureAlgorithmOid
 * @property {string} keyAlgorithmOid
 * @property {string} keyAlgorithmName OpenSSL name, e.g. 'rsaEncryption', 'id-ecPublicKey', 'X25519'
 * @property {number|null} rsaExponent
 * @property {Uint8Array} spkiDer SubjectPublicKeyInfo DER (for key-pinning comparisons)
 * @property {DnAttribute[][]} subjectRDNs
 * @property {DnAttribute[][]} issuerRDNs
 * @property {GeneralName[]} sans every SAN entry in certificate order
 * @property {string[]} policies certificate policy OIDs
 * @property {'EV'|'OV'|'IV'|'DV'|null} validationLevel from CA/B Forum policy OIDs
 * @property {boolean} mustStaple TLS feature status_request (OCSP must-staple)
 * @property {Array<{ version: number|null, logId: string|null, timestamp: Date|null }>} scts logId = base64
 * @property {Array<{ oid: string, name: string, critical: boolean, length: number }>} extensions
 * @property {Array<{ field: string, oid: string|null, message: string }>} parseErrors non-fatal decoding problems
 */

function decodeCertificate(bytes) {
  const root = expect(readNode(bytes, 0, bytes.length), 0x30, 'Certificate (SEQUENCE)');
  if (root.next !== bytes.length) fail('Unexpected data after the certificate', root.next);
  const top = childrenOf(root);
  if (top.length !== 3) fail('A certificate must contain tbsCertificate, signatureAlgorithm and signatureValue', root.offset);
  const [tbsNode, sigAlgNode, sigValueNode] = top;
  const sigAlg = parseAlgorithm(sigAlgNode);
  bitString(sigValueNode);

  const f = childrenOf(expect(tbsNode, 0x30, 'tbsCertificate'));
  let i = 0;
  const next = (what) => {
    if (i >= f.length) fail(`Missing ${what}`, tbsNode.offset);
    return f[i++];
  };
  let version = 1;
  if (f[0] && f[0].id === 0xa0) {
    const v = childrenOf(f[i++]);
    if (v.length !== 1) fail('Malformed version field', f[0].offset);
    version = integerValue(v[0]) + 1;
  }
  const serialHex = integerHex(next('serialNumber'));
  parseAlgorithm(next('signature algorithm'));
  const issuerRDNs = parseName(next('issuer'));
  const validity = childrenOf(expect(next('validity'), 0x30, 'Validity'));
  if (validity.length !== 2) fail('Malformed Validity', f[i - 1].offset);
  const notBefore = decodeTime(validity[0]);
  const notAfter = decodeTime(validity[1]);
  const subjectRDNs = parseName(next('subject'));
  const spkiNode = expect(next('subjectPublicKeyInfo'), 0x30, 'SubjectPublicKeyInfo');
  // issuerUniqueID [1] / subjectUniqueID [2] (v2+): skipped.
  if (f[i] && f[i].cls === 2 && f[i].num === 1) i++;
  if (f[i] && f[i].cls === 2 && f[i].num === 2) i++;
  const extNode = f[i] && f[i].id === 0xa3 ? f[i++] : null;
  if (i !== f.length) fail(`Unexpected field in tbsCertificate (tag ${tagHex(f[i].id)})`, f[i].offset);

  const subject = firstValues(subjectRDNs);
  const issuer = firstValues(issuerRDNs);
  const cert = {
    der: bytes,
    version,
    serialHex,
    signatureAlgorithm: SIG_ALG_NAMES[sigAlg.oid] || sigAlg.oid,
    subject,
    subjectDN: formatDN(subjectRDNs),
    subjectCN: subject.CN ?? null,
    issuer,
    issuerDN: formatDN(issuerRDNs),
    issuerCN: issuer.CN ?? null,
    notBefore,
    notAfter,
    dnsNames: [],
    ipAddresses: [],
    emails: [],
    uris: [],
    hostnames: [],
    keyAlgorithm: 'unknown',
    keyBits: null,
    curve: null,
    isCA: false,
    pathLen: null,
    keyUsage: [],
    extKeyUsage: [],
    selfSigned: false,
    subjectKeyId: null,
    authorityKeyId: null,
    ocspUrls: [],
    caIssuersUrls: [],
    crlUrls: [],
    isPrecertificate: false,
    sctCount: null,
    // --- extensions to the contract ---
    signatureAlgorithmOid: sigAlg.oid,
    keyAlgorithmOid: '',
    keyAlgorithmName: '',
    rsaExponent: null,
    spkiDer: tlv(spkiNode),
    subjectRDNs,
    issuerRDNs,
    sans: [],
    policies: [],
    validationLevel: null,
    mustStaple: false,
    scts: [],
    extensions: [],
    parseErrors: []
  };
  parsePublicKey(spkiNode, cert);
  if (extNode) parseExtensions(extNode, cert);

  const hostnames = new Set();
  for (const name of cert.dnsNames) {
    const h = normalizeCertHostname(name);
    if (h) hostnames.add(h);
  }
  if (!hostnames.size && cert.subjectCN) {
    const cn = normalizeCertHostname(cert.subjectCN);
    if (isHostnameLike(cn)) hostnames.add(cn);
  }
  cert.hostnames = [...hostnames];
  cert.selfSigned = cert.subjectDN === cert.issuerDN
    && (!cert.subjectKeyId || !cert.authorityKeyId || cert.subjectKeyId === cert.authorityKeyId);
  return cert;
}

/**
 * Parses one DER-encoded X.509 certificate.
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} der
 * @returns {Certificate}
 * @throws {CertificateParseError} on malformed input (truncation, indefinite length, wrong structure, trailing data)
 */
export function parseCertificate(der) {
  const view = asBytes(der);
  if (!view) throw new CertificateParseError('Expected DER bytes (Uint8Array or ArrayBuffer)');
  const bytes = new Uint8Array(view); // own copy: decoupled from the caller's buffer
  try {
    return decodeCertificate(bytes);
  } catch (err) {
    if (err instanceof CertificateParseError) throw err;
    throw new CertificateParseError(`Malformed certificate: ${err && err.message}`, null, { cause: err });
  }
}

// ---------------------------------------------------------------------------
// Container sniffing (PKCS#7, PKCS#12, CSR, keys)
// ---------------------------------------------------------------------------

function safeOid(node) {
  try {
    return node && node.id === 0x06 ? decodeOid(node) : null;
  } catch {
    return null;
  }
}

/**
 * Classifies a top-level SEQUENCE by shape (BER-tolerant, never throws).
 * @returns {{ kind: 'certificate'|'pkcs7'|'pkcs12'|'csr'|'crl'|'privateKey'|'publicKey'|'unknown', detail?: string }}
 */
function classifyDer(node) {
  if (node.id !== 0x30) return { kind: 'unknown', detail: `not a SEQUENCE (tag ${tagHex(node.id)})` };
  let kids;
  try {
    kids = childrenOf(node, true);
  } catch (err) {
    return { kind: 'unknown', detail: err.message };
  }
  const id = (list, i) => (list[i] ? list[i].id : -1);
  // Signed structures: SEQUENCE { tbs SEQUENCE, AlgorithmIdentifier, BIT STRING }
  if (kids.length === 3 && id(kids, 0) === 0x30 && id(kids, 1) === 0x30 && id(kids, 2) === 0x03) {
    let info = [];
    try {
      info = childrenOf(kids[0], true);
    } catch {
      /* the strict certificate parser will report the problem */
    }
    if (info.length === 4 && id(info, 0) === 0x02 && id(info, 1) === 0x30 && id(info, 2) === 0x30 && id(info, 3) === 0xa0) {
      return { kind: 'csr' };
    }
    const time = id(info, 3) === 0x17 || id(info, 3) === 0x18;
    if (id(info, 0) === 0x30 || (id(info, 0) === 0x02 && time)) return { kind: 'crl' };
    return { kind: 'certificate' };
  }
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
  if (id(kids, 0) === 0x06) {
    const oid = safeOid(kids[0]);
    if (oid === OID.PKCS7_SIGNED_DATA) return { kind: 'pkcs7' };
    return { kind: 'unknown', detail: `unsupported PKCS#7/CMS content type ${oid}` };
  }
  // PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo, macData OPTIONAL }
  if (id(kids, 0) === 0x02 && id(kids, 1) === 0x30 && kids.length <= 3) {
    const v = contents(kids[0]);
    if (v.length === 1 && v[0] === 3) {
      try {
        const ct = safeOid(childrenOf(kids[1], true)[0]);
        if (ct === OID.PKCS7_DATA || ct === OID.PKCS7_SIGNED_DATA) return { kind: 'pkcs12' };
      } catch {
        /* not a PFX */
      }
    }
  }
  if (kids.length === 2 && id(kids, 0) === 0x30 && id(kids, 1) === 0x04) return { kind: 'privateKey', detail: 'ENCRYPTED PRIVATE KEY (DER)' };
  if (kids.length === 2 && id(kids, 0) === 0x30 && id(kids, 1) === 0x03) return { kind: 'publicKey' };
  if (id(kids, 0) === 0x02 && id(kids, 1) === 0x30 && id(kids, 2) === 0x04) return { kind: 'privateKey', detail: 'PRIVATE KEY (DER)' };
  if (id(kids, 0) === 0x02 && id(kids, 1) === 0x04) return { kind: 'privateKey', detail: 'EC PRIVATE KEY (DER)' };
  if (kids.length >= 6 && kids.slice(0, 6).every((k) => k.id === 0x02)) {
    return { kind: 'privateKey', detail: kids.length >= 9 ? 'RSA PRIVATE KEY (DER)' : 'DSA PRIVATE KEY (DER)' };
  }
  if (kids.length === 2 && id(kids, 0) === 0x02 && id(kids, 1) === 0x02) return { kind: 'publicKey' };
  return { kind: 'unknown' };
}

/** Raw TLVs of the certificates inside a PKCS#7 SignedData ContentInfo (input order). */
function extractPkcs7Certificates(node) {
  const [, content] = childrenOf(node, true);
  if (!content || content.id !== 0xa0) fail('PKCS#7 ContentInfo without content', node.offset);
  const [signedData] = childrenOf(content, true);
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls [1] OPTIONAL, signerInfos SET }
  const certSet = childrenOf(expect(signedData, 0x30, 'SignedData'), true).find((n) => n.id === 0xa0);
  if (!certSet) return [];
  // CertificateChoices: plain certificates are SEQUENCEs; attribute/other certificates are skipped.
  return childrenOf(certSet, true).filter((n) => n.id === 0x30).map(tlv);
}

// ---------------------------------------------------------------------------
// parseCertificates: input sniffing
// ---------------------------------------------------------------------------

/** The OpenSSL command a PKCS#12 bundle that was not opened points to (PKCS12_UNSUPPORTED detail). */
const PKCS12_COMMAND = 'openssl pkcs12 -in file.pfx -nokeys -out cert.pem';

/** PEM labels that are never certificates but are harmless to ignore. */
const IGNORED_LABEL_RE = /PUBLIC KEY|PARAMETERS|CRL|PGP|SIGNATURE|MESSAGE|SESSION/;

function warn(ctx, code, detail) {
  const key = `${code}\u0000${detail ?? ''}`;
  if (ctx.warned.has(key)) return;
  ctx.warned.add(key);
  ctx.warnings.push(detail === undefined ? { code } : { code, detail });
}

/** Parse and add one DER certificate; returns it (or the identical one read before), null when unreadable. */
function addCertificate(bytes, ctx, where) {
  let cert;
  try {
    cert = parseCertificate(bytes);
  } catch (err) {
    warn(ctx, 'PARSE_ERROR', `${where}: ${err.message}`);
    return null;
  }
  const key = latin1(cert.der);
  if (ctx.seen.has(key)) return ctx.seen.get(key); // exact duplicate (e.g. cert + fullchain pasted together)
  ctx.seen.set(key, cert);
  ctx.certificates.push(cert);
  for (const p of cert.parseErrors) warn(ctx, 'PARSE_ERROR', `${where}: ${p.field}: ${p.message}`);
  return cert;
}

function handleDerStructure(blob, node, ctx, where, quiet) {
  const { kind, detail } = classifyDer(node);
  switch (kind) {
    case 'certificate':
      addCertificate(blob, ctx, where);
      return true;
    case 'pkcs7': {
      let certs;
      try {
        certs = extractPkcs7Certificates(node);
      } catch (err) {
        warn(ctx, 'PARSE_ERROR', `${where}: PKCS#7: ${err.message}`);
        return true;
      }
      certs.forEach((c, i) => addCertificate(c, ctx, `${where}, PKCS#7 certificate ${i + 1}`));
      if (!certs.length) ctx.ignored.add('PKCS#7 without certificates');
      return true;
    }
    case 'pkcs12':
      ctx.pkcs12.push(blob); // loadCertificates() opens it with a password
      warn(ctx, 'PKCS12_UNSUPPORTED', PKCS12_COMMAND);
      return true;
    case 'csr':
      warn(ctx, 'CSR_NOT_CERT', 'CERTIFICATE REQUEST');
      return true;
    case 'privateKey':
      warn(ctx, 'PRIVATE_KEY_PRESENT', detail);
      return true;
    case 'publicKey':
      ctx.ignored.add('PUBLIC KEY');
      return true;
    case 'crl':
      ctx.ignored.add('X509 CRL');
      return true;
    default:
      if (!quiet) warn(ctx, 'PARSE_ERROR', `${where}: not a certificate${detail ? ` (${detail})` : ''}`);
      return false;
  }
}

/** Walks one or more concatenated DER structures. */
function ingestDer(bytes, ctx, where, { firstOnly = false, quiet = false } = {}) {
  let pos = 0;
  let index = 0;
  while (pos < bytes.length) {
    // Tolerate trailing NUL padding / whitespace after the last structure.
    if (bytes.subarray(pos).every((b) => b === 0 || b === 0x0a || b === 0x0d || b === 0x20 || b === 0x09)) break;
    let node;
    try {
      node = readNode(bytes, pos, bytes.length, true);
    } catch (err) {
      if (!quiet) warn(ctx, 'PARSE_ERROR', `${where}: ${err.message}`);
      return;
    }
    index++;
    const label = index > 1 ? `${where} #${index}` : where;
    handleDerStructure(bytes.subarray(pos, node.next), node, ctx, label, quiet);
    pos = node.next;
    if (firstOnly) break;
  }
}

/** Heuristic: no C0 control bytes other than TAB/LF/CR/FF/ESC in the first KiB. */
function looksLikeText(bytes) {
  const n = Math.min(bytes.length, 1024);
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d && b !== 0x0c && b !== 0x1b) return false;
  }
  return true;
}

function decodeText(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return utf16(bytes.subarray(2), true);
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return utf16(bytes.subarray(2), false);
  // UTF-16LE without BOM (e.g. PowerShell redirection): ASCII text with NUL high bytes.
  if (bytes.length >= 4 && bytes[0] !== 0 && bytes[1] === 0 && bytes[2] !== 0 && bytes[3] === 0) return utf16(bytes, true);
  return new TextDecoder('utf-8').decode(bytes); // strips a UTF-8 BOM
}

/**
 * JSON string escapes that base64 can carry besides the newline: PHP's json_encode writes every
 * '/' as `\/`, .NET's default encoder writes '+' as `\u002B`.
 */
function unescapeJson(text) {
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))).replace(/\\\//g, '/');
}

function cleanPemBody(body) {
  return unescapeJson(body)
    .replace(/\\r\\n|\\n|\\r/g, '\n') // JSON / YAML escaped newlines
    .split(/\r\n|\r|\n/)
    .map((line) => line.replace(/^[\s>|"']+/, '').replace(/[\s"',\\]+$/, '')) // e-mail quoting, string noise
    .filter((line) => line && !line.includes(':')) // RFC 1421 headers (Proc-Type, DEK-Info)
    .join('');
}

function processPemBlock(label, body, ctx, where, depth) {
  if (label.includes('PRIVATE KEY')) {
    warn(ctx, 'PRIVATE_KEY_PRESENT', label); // never decoded, never returned
    return;
  }
  if (label.includes('CERTIFICATE REQUEST')) {
    warn(ctx, 'CSR_NOT_CERT', label);
    return;
  }
  if (label === 'PKCS12' || label === 'PFX') {
    const bytes = decodeBase64(cleanPemBody(body));
    if (bytes && bytes.length) ctx.pkcs12.push(bytes);
    warn(ctx, 'PKCS12_UNSUPPORTED', PKCS12_COMMAND);
    return;
  }
  if (IGNORED_LABEL_RE.test(label)) {
    ctx.ignored.add(label);
    return;
  }
  const bytes = decodeBase64(cleanPemBody(body));
  if (!bytes || !bytes.length) {
    warn(ctx, 'PARSE_ERROR', `${where}: invalid base64 content`);
    return;
  }
  if (depth < 2 && bytes[0] !== 0x30 && looksLikeText(bytes)) {
    const inner = decodeText(bytes);
    if (inner.includes('-----BEGIN ')) {
      ingestText(inner, ctx, depth + 1);
      return;
    }
  }
  ingestDer(bytes, ctx, where, { firstOnly: label === 'TRUSTED CERTIFICATE' });
}

function ingestText(input, ctx, depth) {
  const text = input.replace(/^\uFEFF/, '');
  const beginRe = /-----BEGIN ([^\r\n]{1,80}?)-----/g;
  const endRe = /-----END [^\r\n]{1,80}?-----/g;
  let blocks = 0;
  let m;
  while ((m = beginRe.exec(text))) {
    blocks++;
    const label = m[1].trim().replace(/\s+/g, ' ').toUpperCase();
    const bodyStart = m.index + m[0].length;
    beginRe.lastIndex = bodyStart;
    const nextBegin = text.indexOf('-----BEGIN ', bodyStart);
    endRe.lastIndex = bodyStart;
    const end = endRe.exec(text);
    let body;
    let where = `PEM block ${blocks} (${label})`;
    if (end && (nextBegin < 0 || end.index < nextBegin)) {
      body = text.slice(bodyStart, end.index);
      beginRe.lastIndex = end.index + end[0].length;
    } else {
      body = text.slice(bodyStart, nextBegin < 0 ? text.length : nextBegin);
      where += ' without END line';
    }
    processPemBlock(label, body, ctx, where, depth);
  }
  if (blocks) return;

  if (/PuTTY-User-Key-File-\d/.test(text)) {
    warn(ctx, 'PRIVATE_KEY_PRESENT', 'PuTTY private key');
    return;
  }
  if (/-{4} BEGIN SSH2 [A-Z ]*PRIVATE KEY -{4}/.test(text)) { // RFC 4716 style (4 dashes)
    warn(ctx, 'PRIVATE_KEY_PRESENT', 'SSH2 PRIVATE KEY');
    return;
  }
  // DER that was read as a "binary string" (e.g. FileReader.readAsBinaryString).
  if (text.charCodeAt(0) === 0x30 && /[\x00-\x08\x0e-\x1f]/.test(text.slice(0, 64))) {
    if (/[^\x00-\xff]/.test(text)) {
      warn(ctx, 'PARSE_ERROR', 'Binary data was decoded as text; read the file as an ArrayBuffer');
    } else {
      ingestDer(Uint8Array.from(text, (ch) => ch.charCodeAt(0)), ctx, 'DER data');
    }
    return;
  }
  const plain = unescapeJson(text);
  const compact = plain.replace(/\s+/g, '').replace(/^["']+|["',]+$/g, '');
  if (compact.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) {
    ingestBase64Token(compact, ctx, depth, false);
    return;
  }
  // Base64 blobs embedded in other text, e.g. `kubectl get secret -o yaml` (tls.crt / tls.key) or JSON.
  for (const token of plain.match(/[A-Za-z0-9+/]{64,}={0,2}/g) || []) ingestBase64Token(token, ctx, depth, true);
}

function ingestBase64Token(token, ctx, depth, quiet) {
  const bytes = decodeBase64(token);
  if (!bytes || !bytes.length) return;
  if (bytes[0] !== 0x30) {
    if (depth < 2 && looksLikeText(bytes)) {
      const inner = decodeText(bytes);
      if (inner.includes('-----BEGIN ')) ingestText(inner, ctx, depth + 1);
    }
    return;
  }
  ingestDer(bytes, ctx, 'Base64 data', { quiet });
}

function ingestBytes(bytes, ctx) {
  if (!bytes.length) return;
  if (bytes[0] === 0x30) {
    if (!looksLikeText(bytes)) {
      ingestDer(bytes, ctx, 'DER data');
      return;
    }
    // Rare: a tiny DER blob without control bytes, or a text file starting with '0'.
    try {
      if (readNode(bytes, 0, bytes.length, true).next === bytes.length) {
        ingestDer(bytes, ctx, 'DER data');
        return;
      }
    } catch {
      /* treat as text */
    }
  }
  ingestText(decodeText(bytes), ctx, 0);
}

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? new Date() : value;
  if (typeof value === 'number' || typeof value === 'string') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? new Date() : d;
  }
  return new Date();
}

/** True when `child` names `parent` as its issuer (DN match; key ids must agree when both exist). */
function issuedBy(child, parent) {
  if (child.issuerDN !== parent.subjectDN) return false;
  return !child.authorityKeyId || !parent.subjectKeyId || child.authorityKeyId === parent.subjectKeyId;
}

/**
 * Every end-entity certificate of one input, in input order: not a CA and not the issuer of
 * another certificate in it (the rule {@link parseCertificates} picks its `leaf` by). A chain
 * gives one; several PEM blocks pasted together (an RSA + ECDSA pair) give each of them; a file
 * of CA certificates only gives none. A self-issued certificate (issuer = subject) names
 * itself as its issuer unless its key ids point at another certificate's key, so two
 * self-signed twins with the same subject (RSA + ECDSA) are both leaves, not each other's CA.
 * @param {Certificate[]} certs
 * @returns {Certificate[]}
 */
export function leafCertificates(certs) {
  const list = Array.isArray(certs) ? certs.filter(Boolean) : [];
  const signedBy = (child, parent) => issuedBy(child, parent) && (child.issuerDN !== child.subjectDN
    || (!!child.authorityKeyId && child.authorityKeyId === parent.subjectKeyId && child.authorityKeyId !== child.subjectKeyId));
  const issuesAnother = (c) => list.some((o) => o !== c && signedBy(o, c));
  return list.filter((c) => !c.isCA && !issuesAnother(c));
}

function pickLeaf(certs) {
  if (!certs.length) return null;
  return leafCertificates(certs)[0] || certs[0];
}

/** The state one parse collects (certificates, warnings, PKCS#12 bundles found). */
function newContext() {
  return { certificates: [], warnings: [], warned: new Set(), seen: new Map(), ignored: new Set(), pkcs12: [] };
}

function ingestInput(input, ctx) {
  if (typeof input === 'string') {
    ingestText(input, ctx, 0);
  } else if (input != null) {
    const bytes = asBytes(input);
    if (bytes) ingestBytes(bytes, ctx);
    else warn(ctx, 'PARSE_ERROR', `Unsupported input type: ${Object.prototype.toString.call(input)}`);
  }
}

/** NO_CERTIFICATE, the leaf and its validity warnings: the end of every parse. */
function finishResult(ctx, options) {
  if (!ctx.certificates.length) {
    warn(ctx, 'NO_CERTIFICATE', ctx.ignored.size ? `Found only: ${[...ctx.ignored].join(', ')}` : undefined);
  }
  const leaf = pickLeaf(ctx.certificates);
  if (leaf) {
    const now = toDate(options?.now); // options may be null: never throw
    if (now < leaf.notBefore) warn(ctx, 'NOT_YET_VALID', leaf.notBefore.toISOString());
    else if (now > leaf.notAfter) warn(ctx, 'EXPIRED', leaf.notAfter.toISOString());
  }
  return leaf;
}

/** Defensive: parsing is designed not to throw, but never let the UI crash. */
function failedResult(ctx, err) {
  warn(ctx, 'PARSE_ERROR', `Unexpected error: ${err && err.message}`);
  if (!ctx.certificates.length) warn(ctx, 'NO_CERTIFICATE');
}

/**
 * Extracts certificates from whatever the user dropped or pasted. Never throws.
 *
 * Accepted: PEM (one or many blocks, CRLF, indentation, surrounding text,
 * e-mail quoting, JSON escapes: newlines, `\/`, `\uXXXX`), raw DER (possibly concatenated), bare
 * base64, base64-encoded PEM, PKCS#7 (PEM "PKCS7"/"CMS" or DER SignedData),
 * UTF-16 text files. Detected and reported: PKCS#12 (PKCS12_UNSUPPORTED: this function takes no
 * password, {@link loadCertificates} opens it), CSRs
 * (CSR_NOT_CERT), private keys (PRIVATE_KEY_PRESENT — never decoded or
 * returned). Exact duplicate certificates are returned once.
 *
 * @param {string|ArrayBuffer|Uint8Array|ArrayBufferView} input
 * @param {{ now?: Date|number|string }} [options] reference time for EXPIRED / NOT_YET_VALID (default: now)
 * @returns {{
 *   certificates: Certificate[],
 *   leaf: Certificate|null,
 *   warnings: Array<{ code: 'PRIVATE_KEY_PRESENT'|'NO_CERTIFICATE'|'PKCS12_UNSUPPORTED'|'CSR_NOT_CERT'|'PARSE_ERROR'|'EXPIRED'|'NOT_YET_VALID', detail?: string }>
 * }}
 */
export function parseCertificates(input, options = {}) {
  const ctx = newContext();
  let leaf = null;
  try {
    ingestInput(input, ctx);
    leaf = finishResult(ctx, options);
  } catch (err) {
    failedResult(ctx, err);
  }
  return { certificates: ctx.certificates, leaf, warnings: ctx.warnings };
}

/**
 * What a PKCS#12 bundle held and how it was protected ({@link loadCertificates}); never a key.
 * @typedef {object} Pkcs12Summary
 * @property {number} certificates certificates in the bundle
 * @property {number} keys private keys in it (never returned or shown)
 * @property {number} unencryptedKeys of those, stored without encryption (plain keyBags)
 * @property {string|null} friendlyName the leaf's friendly name in the bundle
 * @property {{ kind: 'hmac'|'pbmac1', hash: string, iterations: number, kdf: string|null }|null} mac
 *   the integrity check (null: the bundle has none)
 * @property {import('./pkcs12.js').EncryptionInfo[]} encryption of the parts holding certificates
 * @property {import('./pkcs12.js').EncryptionInfo[]} keyEncryption of the private keys (one per scheme)
 * @property {boolean} passwordVerified the MAC matched or something decrypted with the password;
 *   false for a bundle with neither (its certificates were readable without it)
 * @property {null|{ status: 'match'|'mismatch'|'nokey'|'nocert'|'unsupported'|'failed', algorithm: string|null,
 *   owner: Certificate|null }} keyCheck only with `checkKey`: 'match' a private key belongs to the
 *   leaf; 'mismatch' none does (owner: a certificate of the bundle the key belongs to, if any);
 *   'nokey' the bundle holds no key; 'nocert' no certificate was read to check one against;
 *   'unsupported' a key type the browser cannot check (algorithm: its name); 'failed' the key
 *   did not decrypt although the certificates did
 */

/** The {@link Pkcs12Summary} of an opened bundle; `parsed[i]` is the Certificate of its certificate i. */
function pkcs12Summary(opened, parsed, leaf, checkKey) {
  const distinct = (list) => {
    const seen = new Set();
    return list.filter((e) => {
      const key = JSON.stringify(e);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };
  const leafIndex = leaf ? parsed.indexOf(leaf) : -1;
  let keyCheck = null;
  if (checkKey && !leaf) {
    keyCheck = { status: 'nocert', algorithm: null, owner: null }; // nothing to check a key against
  } else if (checkKey) {
    const checks = opened.keys.map((k) => k.check).filter(Boolean);
    const checked = checks.filter((c) => c.status === 'checked');
    const match = checked.find((c) => c.certificates.includes(leafIndex));
    if (!opened.keys.length) {
      keyCheck = { status: 'nokey', algorithm: null, owner: null };
    } else if (match) {
      keyCheck = { status: 'match', algorithm: match.algorithm, owner: leaf };
    } else if (checked.length) {
      const owned = checked.find((c) => c.certificates.length);
      keyCheck = { status: 'mismatch', algorithm: checked[0].algorithm, owner: owned ? parsed[owned.certificates[0]] || null : null };
    } else if (checks.some((c) => c.status === 'failed')) {
      keyCheck = { status: 'failed', algorithm: null, owner: null };
    } else {
      keyCheck = { status: 'unsupported', algorithm: (checks[0] && checks[0].algorithm) || null, owner: null };
    }
  }
  const leafBag = leafIndex >= 0 ? opened.certificates[leafIndex] : null;
  return {
    certificates: opened.certificates.length,
    keys: opened.keys.length,
    unencryptedKeys: opened.keys.filter((k) => !k.encrypted).length,
    friendlyName: (leafBag && leafBag.friendlyName) || null,
    mac: opened.mac,
    encryption: distinct(opened.encryption),
    keyEncryption: distinct(opened.keys.map((k) => k.encryption).filter(Boolean)),
    passwordVerified: opened.passwordVerified,
    keyCheck
  };
}

/**
 * {@link parseCertificates} that also opens a PKCS#12 (.pfx / .p12) bundle with its password
 * (lib/pkcs12.js). Never rejects.
 *
 * - Without a bundle in the input, or without a `password` (null / undefined), the result is
 *   parseCertificates()'s: a bundle stays PKCS12_UNSUPPORTED.
 * - With a password (a string, '' for none) the first bundle is opened: its certificates join the
 *   result in file order and `pkcs12` ({@link Pkcs12Summary}) is added. A bundle that cannot be
 *   opened gives PKCS12_BAD_PASSWORD (detail 'mac': the integrity check does not match; 'no-mac':
 *   nothing decrypts and there is no integrity check to tell a damaged file apart),
 *   PKCS12_DAMAGED (detail: what is wrong) or PKCS12_UNSUPPORTED (detail: the algorithm or mode,
 *   e.g. 'pbeWithSHAAnd128BitRC4', 'envelopedData', 'webcrypto') instead.
 * - Private keys are never returned. `checkKey` decrypts them in memory only to check whether one
 *   belongs to the leaf (`pkcs12.keyCheck`), then drops them.
 *
 * @param {string|ArrayBuffer|Uint8Array|ArrayBufferView} input
 * @param {{ password?: string|null, checkKey?: boolean, now?: Date|number|string, subtle?: SubtleCrypto }} [options]
 * @returns {Promise<{ certificates: Certificate[], leaf: Certificate|null,
 *   warnings: Array<{ code: string, detail?: string }>, pkcs12?: Pkcs12Summary }>}
 *   warning codes: those of parseCertificates plus PKCS12_BAD_PASSWORD and PKCS12_DAMAGED
 */
export async function loadCertificates(input, options = {}) {
  const { password = null, checkKey = false, subtle } = options || {};
  const ctx = newContext();
  let leaf = null;
  let opened = null;
  let parsed = [];
  try {
    ingestInput(input, ctx);
    if (ctx.pkcs12.length && typeof password === 'string') {
      // The bundle is opened now: its "not opened" warning goes.
      ctx.warnings = ctx.warnings.filter((w) => w.code !== 'PKCS12_UNSUPPORTED');
      ctx.warned = new Set([...ctx.warned].filter((k) => !k.startsWith('PKCS12_UNSUPPORTED\u0000')));
      try {
        opened = await openPkcs12(ctx.pkcs12[0], password, subtle === undefined ? { checkKey } : { checkKey, subtle });
      } catch (err) {
        if (!(err instanceof Pkcs12Error)) throw err;
        if (err.code === 'BAD_PASSWORD') warn(ctx, 'PKCS12_BAD_PASSWORD', err.detail || 'mac');
        else if (err.code === 'UNSUPPORTED') warn(ctx, 'PKCS12_UNSUPPORTED', err.detail || err.message);
        else warn(ctx, 'PKCS12_DAMAGED', err.message);
      }
      if (opened) parsed = opened.certificates.map((c, i) => addCertificate(c.der, ctx, `PKCS#12 certificate ${i + 1}`));
      // One bundle per load: any other one in the input is said to be skipped, never dropped silently.
      for (let i = 1; i < ctx.pkcs12.length; i++) warn(ctx, 'PARSE_ERROR', `PKCS#12 bundle ${i + 1}: not opened (one bundle per file; load it on its own)`);
    }
    leaf = finishResult(ctx, options);
  } catch (err) {
    failedResult(ctx, err);
  }
  const result = { certificates: ctx.certificates, leaf, warnings: ctx.warnings };
  if (opened) result.pkcs12 = pkcs12Summary(opened, parsed, leaf, checkKey);
  return result;
}

// ---------------------------------------------------------------------------
// Fingerprints (WebCrypto with a pure-JS fallback for insecure contexts, lib/sha.js)
// ---------------------------------------------------------------------------

/**
 * SHA-256 and SHA-1 fingerprints of a DER certificate (lowercase hex, no
 * colons). Uses WebCrypto when available and falls back to a pure-JS
 * implementation (e.g. pages served over plain http, where `crypto.subtle` is
 * undefined).
 * @param {Uint8Array|ArrayBuffer|Certificate} der DER bytes (a Certificate object is accepted too)
 * @param {{ subtle?: SubtleCrypto|null }} [options] pass `subtle: null` to force the JS fallback
 * @returns {Promise<{ sha256: string, sha1: string }>}
 */
export async function computeFingerprints(der, { subtle = globalThis.crypto?.subtle } = {}) {
  const bytes = asBytes(der && !ArrayBuffer.isView(der) && der.der ? der.der : der);
  if (!bytes) throw new TypeError('computeFingerprints: expected DER bytes (Uint8Array or ArrayBuffer)');
  if (subtle && typeof subtle.digest === 'function') {
    try {
      const [s256, s1] = await Promise.all([subtle.digest('SHA-256', bytes), subtle.digest('SHA-1', bytes)]);
      return { sha256: toHex(new Uint8Array(s256)), sha1: toHex(new Uint8Array(s1)) };
    } catch {
      /* fall back to the JS implementation */
    }
  }
  return { sha256: toHex(sha256(bytes)), sha1: toHex(sha1(bytes)) };
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/**
 * DER → PEM (64-character base64 lines, trailing newline), like OpenSSL.
 * @param {Uint8Array|ArrayBuffer} der
 * @param {string} [label]
 * @returns {string}
 */
export function pemEncode(der, label = 'CERTIFICATE') {
  const bytes = asBytes(der);
  if (!bytes) throw new TypeError('pemEncode: expected DER bytes (Uint8Array or ArrayBuffer)');
  const b64 = encodeBase64(bytes);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}${lines.length ? '\n' : ''}-----END ${label}-----\n`;
}

/**
 * 'a0b856…' → 'A0:B8:56:…' (non-hex characters such as existing colons are ignored).
 * @param {string} hex
 * @returns {string}
 */
export function formatFingerprint(hex) {
  const clean = String(hex ?? '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  return (clean.match(/.{1,2}/g) || []).join(':');
}
