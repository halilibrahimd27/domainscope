/**
 * records.js — readable records for DNS Lookup › Explain (ROADMAP P1.5).
 *
 * - {@link explainDmarc}: a DMARC record tag by tag (RFC 7489, with DMARCbis' `np`, `t` and `psd`),
 *   the defaults of the tags it leaves out, and what applies to the name (its own policy, or the
 *   organizational domain's subdomain policy).
 * - {@link explainCaa}: a CAA record set tag by tag (RFC 8659, RFC 8657 accounturi /
 *   validationmethods), and who may issue — for wildcards too.
 * - {@link explainSvcb}: HTTPS / SVCB records (RFC 9460) parameter by parameter: the protocols, the
 *   port, the address hints against the target's real A / AAAA records (sorted: resolvers order them
 *   differently) and {@link decodeEch}, the Encrypted Client Hello configuration list.
 * - {@link explainName}: what the panel asks, in parallel — the name's TXT (SPF, expanded with
 *   lib/health.js spfLookupCount and laid out by lib/spfexplain.js), the DMARC that applies
 *   (health.findDmarc), the CAA that applies (health.findCaa, climbing the tree) and the HTTPS /
 *   SVCB records with the addresses their hints are compared with; an answer the lookup already has
 *   is used as it is.
 *
 * The parsing is lib/health.js parseDmarc / parseCaa / parseCaaIssueValue: no second parser.
 * DOM-free; texts are codes the view words (`xpl.*`).
 */

import { parseSpf, parseDmarc, parseCaa, parseCaaIssueValue, findCaa, findDmarc, spfLookupCount, spfMxHosts, spfTreeChecks, CAA_ISSUERS } from './health.js';
import { base64Decode, hexEncode } from './dnswire.js';
import { normalizeIP, ipVersion } from './ip.js';
import { registrableDomain } from './domain.js';
import { errorKind, throwIfAborted, uniq } from './util.js';
import { spfPolicy, spfMeter, spfStringIssues, spfFlatten } from './spfexplain.js';

/* ------------------------------------------------------------------------ */
/* DMARC                                                                    */
/* ------------------------------------------------------------------------ */

/** The DMARC tags in the order they are explained (`xpl.dmarc.tag.<tag>`). */
export const DMARC_TAGS = Object.freeze(['v', 'p', 'sp', 'np', 'pct', 't', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 'psd']);
/** Tags a record that leaves them out still has (their default is shown). */
const DMARC_DEFAULTED = Object.freeze(['sp', 'pct', 'adkim', 'aspf']);
/** What each tag's value means (`xpl.dmarc.m.<code>`). */
export const DMARC_MEANINGS = Object.freeze([
  'v', 'p.none', 'p.quarantine', 'p.reject', 'sp.none', 'sp.quarantine', 'sp.reject', 'sp.default',
  'np.none', 'np.quarantine', 'np.reject', 'pct', 'pct.full', 'pct.default', 't.y', 't.n', 'rua', 'ruf',
  'adkim.r', 'adkim.s', 'aspf.r', 'aspf.s', 'adkim.default', 'aspf.default', 'fo', 'rf', 'ri',
  'psd.y', 'psd.n', 'psd.u', 'invalid', 'unknown'
]);
/** What is wrong with a DMARC record (`xpl.dmarc.issue.<code>`): lib/health.js parseDmarc's codes and the policy notes. */
export const DMARC_ISSUES = Object.freeze([
  'missing-p', 'invalid-p', 'invalid-sp', 'invalid-np', 'invalid-pct', 'invalid-adkim', 'invalid-aspf',
  'duplicate-tag', 'unknown-tag', 'invalid-rua', 'invalid-ruf', 'invalid-ri', 'invalid-fo',
  'policy-none', 'sp-none', 'pct-partial', 'testing', 'no-rua', 'multiple'
]);
/** The failure-report options of `fo` (`xpl.dmarc.fo.<code>`). */
export const DMARC_FO = Object.freeze(['0', '1', 'd', 's']);

const LOWER_POLICY = Object.freeze({ reject: 'quarantine', quarantine: 'none', none: 'none' });
const orgOf = (d) => registrableDomain(d) || d;

/**
 * A DMARC record tag by tag.
 * @param {string|string[]} record the TXT value (character-strings joined)
 * @param {{ domain?: string, foundAt?: string|null, inherited?: boolean }} [opts] `domain`: the name the
 *   policy is read for; `foundAt`: the domain whose `_dmarc` holds the record; `inherited`: the
 *   organizational domain's record applies to `domain` (RFC 7489 §6.6.3)
 * @returns {{ valid: boolean, record: string, domain: string|null, foundAt: string|null, inherited: boolean,
 *   applies: string|null, appliesTag: 'p'|'sp', pct: number, testing: boolean,
 *   tags: Array<{ tag: string, value: string|null, given: boolean, meaning: string, params: object, issue: string|null }>,
 *   reports: Array<{ tag: 'rua'|'ruf', uri: string, scheme: string, address: string, domain: string|null, sizeLimit: string|null, external: boolean }>,
 *   issues: Array<{ code: string, token: string, severity: 'error'|'warn'|'info' }> }}
 *   `applies`: the policy for mail from `domain` (its `p`, or the `sp` it inherits) before `pct` / `t`
 */
export function explainDmarc(record, { domain = null, foundAt = null, inherited = false } = {}) {
  const parsed = parseDmarc(record);
  const at = foundAt || domain || null;
  const org = at ? orgOf(at) : null;
  const issueFor = new Map();
  const issues = [];
  const severityOf = (code) => (code.startsWith('invalid-p') || code === 'missing-p' || code === 'invalid-sp' || code === 'invalid-np' || code === 'invalid-pct' || code === 'invalid-adkim' || code === 'invalid-aspf' ? 'error' : 'warn');
  for (const e of [...parsed.errors, ...parsed.warnings]) {
    if (e.code === 'not-dmarc') continue;
    issues.push({ code: e.code, token: e.token, severity: severityOf(e.code) });
    const tag = /^invalid-(.+)$/.exec(e.code);
    if (tag && !issueFor.has(tag[1])) issueFor.set(tag[1], e.code);
  }
  const t = parsed.tags;
  const tags = [];
  const row = (tag, value, given, meaning, params = {}) => tags.push({ tag, value, given, meaning, params, issue: issueFor.get(tag) || null });
  const policyMeaning = (prefix, v) => (['none', 'quarantine', 'reject'].includes(v) ? `${prefix}.${v}` : 'invalid');
  for (const tag of DMARC_TAGS) {
    const given = Object.hasOwn(t, tag);
    const value = given ? t[tag] : null;
    switch (tag) {
      case 'v':
        row('v', value, given, 'v');
        break;
      case 'p':
        if (given) row('p', value, true, policyMeaning('p', String(value).toLowerCase()));
        break;
      case 'sp':
        if (given) row('sp', value, true, policyMeaning('sp', String(value).toLowerCase()));
        else if (parsed.policy) row('sp', null, false, 'sp.default', { policy: parsed.policy });
        break;
      case 'np':
        if (given) row('np', value, true, policyMeaning('np', String(value).toLowerCase()));
        break;
      case 'pct':
        if (given) {
          const pct = issueFor.has('pct') ? null : parsed.pct;
          row('pct', value, true, pct === null ? 'invalid' : pct === 100 ? 'pct.full' : 'pct', {
            pct, rest: pct === null ? null : 100 - pct, lower: parsed.policy ? LOWER_POLICY[parsed.policy] : null
          });
        } else if (DMARC_DEFAULTED.includes(tag)) row('pct', null, false, 'pct.default');
        break;
      case 't':
        if (given) row('t', value, true, String(value).trim().toLowerCase() === 'y' ? 't.y' : String(value).trim().toLowerCase() === 'n' ? 't.n' : 'unknown',
          { lower: parsed.policy ? LOWER_POLICY[parsed.policy] : null });
        break;
      case 'rua':
      case 'ruf': {
        if (!given) break;
        const targets = (tag === 'rua' ? parsed.ruaTargets : parsed.rufTargets).map((x) => ({
          tag, ...x, external: !!(x.domain && org && orgOf(x.domain) !== org)
        }));
        row(tag, value, true, tag, { targets, count: targets.length });
        break;
      }
      case 'adkim':
      case 'aspf': {
        const v = given ? String(value).trim().toLowerCase() : null;
        if (given) row(tag, value, true, v === 'r' || v === 's' ? `${tag}.${v}` : 'invalid');
        else row(tag, null, false, `${tag}.default`);
        break;
      }
      case 'fo':
        if (given) row('fo', value, true, issueFor.has('fo') ? 'invalid' : 'fo', { options: issueFor.has('fo') ? [] : uniq(parsed.fo.split(':')) });
        break;
      case 'rf':
        if (given) row('rf', value, true, 'rf', { format: String(value).trim().toLowerCase() });
        break;
      case 'ri':
        if (given) row('ri', value, true, issueFor.has('ri') ? 'invalid' : 'ri', { seconds: parsed.ri });
        break;
      case 'psd': {
        const v = given ? String(value).trim().toLowerCase() : null;
        if (given) row('psd', value, true, ['y', 'n', 'u'].includes(v) ? `psd.${v}` : 'unknown');
        break;
      }
      default:
        break;
    }
  }
  for (const [tag, value] of Object.entries(t)) {
    if (!DMARC_TAGS.includes(tag)) tags.push({ tag, value, given: true, meaning: 'unknown', params: {}, issue: 'unknown-tag' });
  }
  const applies = inherited ? parsed.subdomainPolicy : parsed.policy;
  const testing = String(t.t || '').trim().toLowerCase() === 'y';
  if (parsed.valid) {
    if (applies === 'none') issues.push({ code: 'policy-none', token: inherited ? `sp=${t.sp ?? t.p}` : `p=${t.p}`, severity: 'warn' });
    if (!inherited && parsed.policy && parsed.policy !== 'none' && parsed.subdomainPolicy === 'none') issues.push({ code: 'sp-none', token: `sp=${t.sp}`, severity: 'warn' });
    if (parsed.pct < 100 && applies !== 'none') issues.push({ code: 'pct-partial', token: `pct=${t.pct}`, severity: 'warn' });
    if (testing && applies !== 'none') issues.push({ code: 'testing', token: 't=y', severity: 'warn' });
    if (!parsed.rua.length) issues.push({ code: 'no-rua', token: '', severity: 'info' });
  }
  const reports = tags.filter((r) => r.tag === 'rua' || r.tag === 'ruf').flatMap((r) => r.params.targets);
  return {
    valid: parsed.valid,
    record: parsed.record,
    domain,
    foundAt: at,
    inherited: !!inherited,
    applies: applies || null,
    appliesTag: inherited ? 'sp' : 'p',
    pct: parsed.pct,
    testing,
    tags,
    reports,
    issues
  };
}

/* ------------------------------------------------------------------------ */
/* CAA                                                                      */
/* ------------------------------------------------------------------------ */

/** The kinds of CAA property (`xpl.caa.kind.<code>`). */
export const CAA_KINDS = Object.freeze(['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone', 'unknown']);

/** The CA that honours an issuer domain (lib/health.js CAA_ISSUERS), or null. */
export function caOfIssuer(issuer) {
  const d = String(issuer ?? '').trim().toLowerCase().replace(/\.$/, '');
  const ca = d ? CAA_ISSUERS.find((x) => x.domains.includes(d)) : null;
  return ca ? { id: ca.id, name: ca.name } : null;
}

/**
 * A CAA record set tag by tag, and who may issue (RFC 8659 §4; RFC 8657). `issuemail` (RFC 9495) and
 * `issuevmc` (Verified Mark Certificates) values read like `issue` (issuer, parameters; an empty issuer
 * forbids those certificates, `deny`) but only their syntax is checked: the RFC 8657 parameters are
 * defined for TLS certificates.
 * @param {Array<object>} records CAA RRs (`rr.data` = { flags, tag, value }) or their data
 * @param {{ name?: string|null, foundAt?: string|null }} [opts] `name`: the name certificates are for;
 *   `foundAt`: where the tree climb found the set (a parent's applies to the name, RFC 8659 §3)
 * @returns {{ name: string|null, foundAt: string|null, inherited: boolean,
 *   rows: Array<{ tag: string, kind: string, value: string, flags: number, critical: boolean, issuer: string|null,
 *     ca: { id: string, name: string }|null, deny: boolean, accountUri: string|null, methods: string[]|null,
 *     otherParams: Array<{ tag: string, value: string }>, problem: string|null, usable: boolean, valid: boolean }>,
 *   anyone: boolean, blocked: boolean, denyAll: boolean, issuers: Array<{ domain: string, ca: object|null }>,
 *   wild: 'same'|'list'|'deny', wildIssuers: Array<{ domain: string, ca: object|null }>, iodef: string[] }}
 *   `anyone`: no issue / issuewild property, so any CA may issue; `blocked`: an unknown critical
 *   property stops every CA; `denyAll`: issue properties authorize no CA; `wild`: wildcards follow
 *   issue (`same`), their own list, or none (`deny`)
 */
export function explainCaa(records, { name = null, foundAt = null } = {}) {
  const list = Array.isArray(records) ? records : [];
  const rows = [];
  for (const rr of list) {
    const p = parseCaa([rr]);
    const d = rr && rr.data && typeof rr.data === 'object' ? rr.data : rr;
    if (!d || typeof d.tag !== 'string') continue;
    const tag = d.tag.toLowerCase();
    const critical = (Number(d.flags) & 128) !== 0;
    const base = {
      tag, value: String(d.value ?? ''), flags: Number(d.flags) || 0, critical, issuer: null, ca: null, deny: false,
      accountUri: null, methods: null, otherParams: [], problem: null, usable: false, valid: true
    };
    if (tag === 'issue' || tag === 'issuewild') {
      const e = p[tag][0];
      const issuer = e.issuer.replace(/\.$/, '');
      rows.push({
        ...base, kind: tag, issuer: issuer || null, ca: issuer ? caOfIssuer(issuer) : null, deny: !issuer && e.valid,
        accountUri: e.accountUri, methods: e.methods, otherParams: e.otherParams,
        problem: e.error || e.problem || null, usable: !!(e.valid && e.issuer && !e.problem), valid: e.valid
      });
    } else if (tag === 'issuemail' || tag === 'issuevmc') {
      const e = parseCaaIssueValue(d.value);
      const issuer = e.issuer.replace(/\.$/, '');
      rows.push({
        ...base, kind: tag, issuer: issuer || null, ca: issuer ? caOfIssuer(issuer) : null, deny: !issuer && e.valid,
        accountUri: e.accountUri, methods: e.methods, otherParams: e.otherParams,
        problem: e.error || null, usable: !!(e.valid && issuer), valid: e.valid
      });
    } else if (tag === 'iodef') {
      rows.push({ ...base, kind: 'iodef', valid: p.iodef[0].valid });
    } else if (CAA_KINDS.includes(tag)) {
      rows.push({ ...base, kind: tag });
    } else {
      rows.push({ ...base, kind: 'unknown' });
    }
  }
  const all = parseCaa(list);
  const named = (domains) => domains.map((x) => ({ domain: x.replace(/\.$/, ''), ca: caOfIssuer(x) }));
  return {
    name: name || null,
    foundAt: foundAt || null,
    inherited: !!(name && foundAt && name !== foundAt),
    rows,
    anyone: !all.issue.length && !all.issuewild.length && !all.unknownCritical,
    blocked: all.unknownCritical,
    denyAll: all.issue.length > 0 && all.issuers.length === 0,
    issuers: named(all.issuers),
    wild: all.issuewild.length ? (all.wildIssuers.length ? 'list' : 'deny') : 'same',
    wildIssuers: named(all.wildIssuers),
    iodef: all.iodef.map((x) => x.url)
  };
}

/* ------------------------------------------------------------------------ */
/* ECH (Encrypted Client Hello)                                             */
/* ------------------------------------------------------------------------ */

/** The ECHConfig version browsers use (draft-ietf-tls-esni-13 and later). */
export const ECH_VERSION = 0xfe0d;
/** HPKE KEM identifiers (RFC 9180 §7.1). */
export const HPKE_KEMS = Object.freeze({
  0x0010: 'DHKEM(P-256, HKDF-SHA256)', 0x0011: 'DHKEM(P-384, HKDF-SHA384)', 0x0012: 'DHKEM(P-521, HKDF-SHA512)',
  0x0020: 'DHKEM(X25519, HKDF-SHA256)', 0x0021: 'DHKEM(X448, HKDF-SHA512)'
});
/** HPKE KDF identifiers (RFC 9180 §7.2). */
export const HPKE_KDFS = Object.freeze({ 0x0001: 'HKDF-SHA256', 0x0002: 'HKDF-SHA384', 0x0003: 'HKDF-SHA512' });
/** HPKE AEAD identifiers (RFC 9180 §7.3). */
export const HPKE_AEADS = Object.freeze({ 0x0001: 'AES-128-GCM', 0x0002: 'AES-256-GCM', 0x0003: 'ChaCha20-Poly1305', 0xffff: 'Export-only' });
/** Why an ech= value could not be read (`xpl.svcb.ech.err.<code>`). */
export const ECH_ERRORS = Object.freeze(['base64', 'empty', 'truncated', 'length']);

const hex4 = (n) => `0x${n.toString(16).padStart(4, '0')}`;

/**
 * Decode an `ech=` SvcParam (base64 ECHConfigList): each ECHConfig's version and, for version
 * 0xfe0d, its config_id, HPKE KEM and public key, cipher suites (KDF + AEAD), maximum name length,
 * public_name and extensions (a mandatory one — the high bit of its type set — makes a client that
 * does not know it skip the config). A config of another version is listed and skipped, as clients do.
 * @param {string} b64
 * @returns {{ ok: boolean, error: string|null, length: number, configs: Array<{ version: number, versionHex: string,
 *   supported: boolean, length: number, configId?: number, kemId?: number, kem?: string|null, publicKeyLength?: number,
 *   publicKey?: string, cipherSuites?: Array<{ kdfId: number, kdf: string|null, aeadId: number, aead: string|null }>,
 *   maxNameLength?: number, publicName?: string, extensions?: Array<{ type: number, mandatory: boolean, length: number }> }> }}
 *   `error`: one of {@link ECH_ERRORS}; what was read before it is kept
 */
export function decodeEch(b64) {
  const out = { ok: false, error: null, length: 0, configs: [] };
  let bytes;
  try {
    bytes = base64Decode(String(b64 ?? '').trim());
  } catch {
    return { ...out, error: 'base64' };
  }
  out.length = bytes.length;
  if (!bytes.length) return { ...out, error: 'empty' };
  let pos = 0;
  const need = (n, end = bytes.length) => {
    if (pos + n > end) throw new RangeError('truncated');
  };
  const u8 = (end) => { need(1, end); return bytes[pos++]; };
  const u16 = (end) => { need(2, end); const v = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; return v; };
  const take = (n, end) => { need(n, end); const v = bytes.subarray(pos, pos + n); pos += n; return v; };
  try {
    const listLen = u16();
    if (listLen + 2 !== bytes.length) {
      out.error = 'length';
      return out;
    }
    while (pos < bytes.length) {
      const version = u16();
      const length = u16();
      const end = pos + length;
      need(length);
      const config = { version, versionHex: hex4(version), supported: version === ECH_VERSION, length };
      if (version === ECH_VERSION) {
        config.configId = u8(end);
        config.kemId = u16(end);
        config.kem = HPKE_KEMS[config.kemId] || null;
        const keyLen = u16(end);
        config.publicKeyLength = keyLen;
        config.publicKey = hexEncode(take(keyLen, end));
        const suitesLen = u16(end);
        const suitesEnd = pos + suitesLen;
        need(suitesLen, end);
        config.cipherSuites = [];
        while (pos + 4 <= suitesEnd) {
          const kdfId = u16(suitesEnd);
          const aeadId = u16(suitesEnd);
          config.cipherSuites.push({ kdfId, kdf: HPKE_KDFS[kdfId] || null, aeadId, aead: HPKE_AEADS[aeadId] || null });
        }
        pos = suitesEnd;
        config.maxNameLength = u8(end);
        const nameLen = u8(end);
        config.publicName = String.fromCharCode(...take(nameLen, end));
        const extLen = u16(end);
        const extEnd = pos + extLen;
        need(extLen, end);
        config.extensions = [];
        while (pos + 4 <= extEnd) {
          const type = u16(extEnd);
          const len = u16(extEnd);
          take(len, extEnd);
          config.extensions.push({ type, mandatory: (type & 0x8000) !== 0, length: len });
        }
        if (pos !== end) {
          out.configs.push(config);
          out.error = 'length';
          return out;
        }
      }
      pos = end;
      out.configs.push(config);
    }
  } catch {
    out.error = 'truncated';
    return out;
  }
  out.ok = true;
  return out;
}

/* ------------------------------------------------------------------------ */
/* HTTPS / SVCB                                                             */
/* ------------------------------------------------------------------------ */

/** Well-known ALPN protocol ids (IANA TLS ALPN registry) and what they are. */
export const ALPN_NAMES = Object.freeze({
  h3: 'HTTP/3 (QUIC)', h2: 'HTTP/2', 'http/1.1': 'HTTP/1.1', h2c: 'HTTP/2 over cleartext TCP',
  dot: 'DNS over TLS', doq: 'DNS over QUIC', 'h3-29': 'HTTP/3 (draft 29)'
});
/** TLS named groups a `tls-supported-groups` SvcParam can name (IANA TLS Supported Groups). */
export const TLS_GROUPS = Object.freeze({
  23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1', 29: 'x25519', 30: 'x448', 256: 'ffdhe2048', 257: 'ffdhe3072',
  258: 'ffdhe4096', 512: 'MLKEM512', 513: 'MLKEM768', 514: 'MLKEM1024', 4587: 'SecP256r1MLKEM768',
  4588: 'X25519MLKEM768', 4589: 'SecP384r1MLKEM1024'
});
/** What a record's notes say (`xpl.svcb.note.<code>`). */
export const SVCB_NOTES = Object.freeze([
  'alias', 'alias-none', 'alias-params', 'mixed-modes', 'other-target', 'h3', 'no-alpn', 'no-default-alpn',
  'no-default-alpn-alone', 'mandatory-missing', 'port', 'ech', 'ech-invalid', 'ech-unsupported', 'ech-mandatory-ext',
  'hint-stale', 'hint-partial', 'hint-unknown', 'hint-no-address', 'dohpath', 'ohttp'
]);
/** How a hint list compares with the target's addresses (`xpl.svcb.hint.<code>`). */
export const HINT_STATUSES = Object.freeze(['match', 'stale', 'partial', 'unknown', 'no-address']);

const ipSort = (list) => uniq((list || []).map((x) => normalizeIP(x)).filter(Boolean)).sort();

/**
 * Address hints against the addresses the target really has, both sorted (resolvers order them
 * differently): `stale` — a hint the name does not have (clients that connect from the hints, as
 * browsers may for HTTP/3, reach the wrong address); `partial` — the name has addresses the hints
 * leave out; `no-address` — the name has none of that family; `unknown` — its addresses could not be asked.
 * @param {string[]} hints
 * @param {string[]|null} actual null when unknown
 * @returns {{ hints: string[], actual: string[]|null, status: string, stale: string[], missing: string[] }}
 */
export function compareHints(hints, actual) {
  const h = ipSort(hints);
  if (!Array.isArray(actual)) return { hints: h, actual: null, status: 'unknown', stale: [], missing: [] };
  const a = ipSort(actual);
  const stale = h.filter((x) => !a.includes(x));
  const missing = a.filter((x) => !h.includes(x));
  const status = !a.length ? 'no-address' : stale.length ? 'stale' : missing.length ? 'partial' : 'match';
  return { hints: h, actual: a, status, stale, missing };
}

/**
 * HTTPS / SVCB records explained (RFC 9460).
 * @param {Array<object>} rrs the records (`rr.data` = { priority, target, params }, `rr.ttl`)
 * @param {{ owner: string, type?: 'HTTPS'|'SVCB', addresses?: Map<string, { ipv4: string[]|null, ipv6: string[]|null }> }} opts
 *   `addresses`: the A / AAAA records of each target name (null for a family whose lookup failed)
 * @returns {Array<{ priority: number, mode: 'alias'|'service', target: string, targetName: string, ttl: number|null,
 *   alpn: Array<{ id: string, name: string|null }>, defaultAlpn: boolean, port: number|null,
 *   hints: { v4: object|null, v6: object|null }, ech: object|null, mandatory: string[], dohpath: string|null,
 *   ohttp: boolean, groups: Array<{ id: number, name: string|null }>, other: Array<{ key: string, value: string }>,
 *   notes: Array<{ code: string, severity: 'error'|'warn'|'info'|'ok', params: object }> }>} by priority
 */
export function explainSvcb(rrs, { owner, type = 'HTTPS', addresses = new Map() } = {}) {
  const list = (Array.isArray(rrs) ? rrs : []).filter((rr) => rr && rr.data && typeof rr.data === 'object');
  const modes = new Set(list.map((rr) => (Number(rr.data.priority) === 0 ? 'alias' : 'service')));
  const ownerName = String(owner ?? '').replace(/\.$/, '');
  return [...list].sort((a, b) => Number(a.data.priority) - Number(b.data.priority)).map((rr) => {
    const d = rr.data;
    const params = d.params && typeof d.params === 'object' ? d.params : {};
    const mode = Number(d.priority) === 0 ? 'alias' : 'service';
    const target = String(d.target ?? '.');
    const targetName = target === '.' ? ownerName : target.replace(/\.$/, '');
    const notes = [];
    const note = (code, severity, p = {}) => notes.push({ code, severity, params: p });
    const keys = Object.keys(params);
    const out = {
      priority: Number(d.priority), mode, target, targetName, ttl: Number.isFinite(rr.ttl) ? rr.ttl : null,
      alpn: (params.alpn || []).map((id) => ({ id, name: ALPN_NAMES[id] || null })),
      defaultAlpn: type === 'HTTPS' && !params['no-default-alpn'],
      port: Number.isInteger(params.port) ? params.port : null,
      hints: { v4: null, v6: null },
      ech: null,
      mandatory: Array.isArray(params.mandatory) ? params.mandatory : [],
      dohpath: typeof params.dohpath === 'string' ? params.dohpath : null,
      ohttp: params.ohttp === true,
      groups: (params['tls-supported-groups'] || []).map((id) => ({ id, name: TLS_GROUPS[id] || null })),
      other: keys.filter((k) => /^key\d+$/.test(k)).map((k) => ({ key: k, value: String(params[k]) })),
      notes
    };
    if (mode === 'alias') {
      if (target === '.') note('alias-none', 'warn');
      else note('alias', 'info', { target: targetName });
      if (keys.length) note('alias-params', 'warn', { keys: keys.join(', ') });
      return out;
    }
    if (modes.has('alias')) note('mixed-modes', 'warn');
    if (targetName && targetName !== ownerName) note('other-target', 'info', { target: targetName });
    if (type === 'HTTPS') {
      if (out.alpn.some((a) => a.id === 'h3')) note('h3', 'info', { port: out.port ?? 443 });
      if (!out.alpn.length && !params['no-default-alpn']) note('no-alpn', 'info');
    }
    if (params['no-default-alpn'] && !out.alpn.length) note('no-default-alpn-alone', 'error');
    else if (params['no-default-alpn']) note('no-default-alpn', 'info', { protocols: out.alpn.map((a) => a.id).join(', ') });
    const absent = out.mandatory.filter((k) => !keys.includes(k));
    if (absent.length) note('mandatory-missing', 'error', { keys: absent.join(', ') });
    if (out.port !== null && out.port !== (type === 'HTTPS' ? 443 : out.port)) note('port', 'info', { port: out.port });
    const known = addresses.get(targetName) || null;
    for (const [fam, key] of [['v4', 'ipv4hint'], ['v6', 'ipv6hint']]) {
      if (!Array.isArray(params[key])) continue;
      const actual = known ? (fam === 'v4' ? known.ipv4 : known.ipv6) : null;
      const cmp = compareHints(params[key], Array.isArray(actual) ? actual.filter((ip) => ipVersion(ip) === (fam === 'v4' ? 4 : 6)) : null);
      out.hints[fam] = cmp;
      if (cmp.status === 'stale') note('hint-stale', 'warn', { family: fam === 'v4' ? 'IPv4' : 'IPv6', stale: cmp.stale.join(', '), actual: cmp.actual.join(', '), target: targetName });
      else if (cmp.status === 'partial') note('hint-partial', 'info', { family: fam === 'v4' ? 'IPv4' : 'IPv6', missing: cmp.missing.join(', '), target: targetName });
      else if (cmp.status === 'no-address') note('hint-no-address', 'warn', { family: fam === 'v4' ? 'IPv4' : 'IPv6', target: targetName, type: fam === 'v4' ? 'A' : 'AAAA' });
      else if (cmp.status === 'unknown') note('hint-unknown', 'info', { family: fam === 'v4' ? 'IPv4' : 'IPv6', target: targetName });
    }
    if (typeof params.ech === 'string') {
      out.ech = decodeEch(params.ech);
      if (!out.ech.ok) note('ech-invalid', 'error', { error: out.ech.error });
      else if (!out.ech.configs.some((c) => c.supported)) note('ech-unsupported', 'warn', { versions: out.ech.configs.map((c) => c.versionHex).join(', ') });
      else {
        const names = uniq(out.ech.configs.filter((c) => c.supported).map((c) => c.publicName));
        note('ech', 'ok', { names: names.join(', ') });
        if (out.ech.configs.some((c) => c.supported && c.extensions.some((x) => x.mandatory))) note('ech-mandatory-ext', 'warn');
      }
    }
    if (out.dohpath !== null) note('dohpath', 'info', { path: out.dohpath });
    if (out.ohttp) note('ohttp', 'info');
    return out;
  });
}

/* ------------------------------------------------------------------------ */
/* What the Explain panel asks                                              */
/* ------------------------------------------------------------------------ */

/** The sections of the Explain panel, in order. */
export const EXPLAIN_SECTIONS = Object.freeze(['spf', 'dmarc', 'caa', 'svcb']);
/** Most mx hosts the SPF section resolves for its flatten preview. */
export const EXPLAIN_MAX_MX_HOSTS = 10;

const isUnderscored = (name) => String(name).split('.').some((l) => l.startsWith('_'));
const isReverse = (name) => /\.(?:in-addr|ip6)\.arpa$/i.test(String(name));
const txtText = (rr) => (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? ''));
const answered = (res) => !!res && res.ok !== false && (res.rcode === 'NOERROR' || res.rcode === 'NXDOMAIN');
const errText = (res) => (!res ? 'no response' : res.ok === false ? String(res.error || 'DNS query failed') : String(res.rcode));
const ofType = (res, type) => (res && Array.isArray(res.answers) ? res.answers.filter((rr) => rr && rr.type === type) : []);

/**
 * Ask one question, a failure kept as a response (only an abort throws).
 * @returns {Promise<object>} a DnsResponse
 */
async function ask(dns, name, type, signal) {
  throwIfAborted(signal);
  try {
    return await dns.query(name, type, { signal });
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    return { name, type, ok: false, rcode: null, answers: [], authorities: [], error: String((err && err.message) || err), errorKind: errorKind(err) };
  }
}

/**
 * The SPF section: the name's SPF record, expanded once and laid out step by step, with Domain
 * Health's findings, the lookup meter, joins that break a term, the flatten preview (the mx hosts
 * resolved for it) and the obsolete SPF record type if the lookup found one.
 */
async function spfSection(name, { dns, signal, txt, spfType, nullMx }) {
  if (!answered(txt)) return { state: 'failed', error: errText(txt), failure: txt };
  const records = ofType(txt, 'TXT').filter((rr) => /^v=spf1(?: |$)/i.test(txtText(rr)));
  const type99 = !!(spfType && answered(spfType) && ofType(spfType, 'SPF').length);
  if (!records.length) return { state: 'none', type99 };
  if (records.length > 1) return { state: 'multiple', count: records.length, records: records.map(txtText), type99 };
  const record = txtText(records[0]);
  const strings = Array.isArray(records[0].data) ? records[0].data.map(String) : [record];
  const parsed = parseSpf(record);
  const lookups = await spfLookupCount(name, { dns, signal, record });
  const mxAddresses = new Map();
  await Promise.all(spfMxHosts(lookups.tree).slice(0, EXPLAIN_MAX_MX_HOSTS).map(async (host) => {
    const [a, aaaa] = await Promise.all([ask(dns, host, 'A', signal), ask(dns, host, 'AAAA', signal)]);
    const ok = answered(a) && answered(aaaa);
    mxAddresses.set(host, ok
      ? { addresses: [...ofType(a, 'A').map((rr) => rr.data), ...ofType(aaaa, 'AAAA').map((rr) => rr.data)], error: null }
      : { addresses: [], error: errText(answered(a) ? aaaa : a) });
  }));
  const checks = spfTreeChecks(name, parsed, lookups, { nullMx });
  return {
    state: 'ok',
    record,
    strings,
    parsed,
    lookups,
    policy: spfPolicy(lookups.tree),
    meter: spfMeter(lookups),
    stringIssues: spfStringIssues(strings),
    checks,
    mxAddresses,
    flatten: spfFlatten(lookups.tree, { mxAddresses }),
    type99
  };
}

/**
 * Everything the Explain panel shows for one name, each section on its own (a failed question
 * fails only its section: `state: 'failed'` with the error and the response, for a "n/a" + Retry).
 *
 * - SPF: the name's TXT records (not for a reverse name, the root or a top-level domain:
 *   check_host() needs two labels, RFC 7208 §4.3).
 * - DMARC: at `_dmarc.<name>` — the record itself when the name is a `_dmarc` name — for a
 *   registrable domain, or a name with SPF or MX records (the names that send mail; its MX is
 *   asked once when the lookup did not, and one that got no answer does not hide DMARC); an
 *   organizational domain's record applies to a subdomain without one (RFC 7489 §6.6.3). Not for
 *   another `_` name (`_spf.<domain>` holds a policy, it sends no mail).
 * - CAA: the set that applies to the name (RFC 8659 tree climbing), not for `_` names.
 * - HTTPS (and SVCB when the lookup asked it): the records, and the A / AAAA records of every
 *   service-mode target, for the address hints; not for `_` names unless the lookup asked.
 *
 * `known` answers (the lookup's own, by type, for the same name) are used as they are and not asked again.
 * @param {string} name a normalized host name
 * @param {{ dns: { query: Function }, signal?: AbortSignal, known?: Map<string, object> }} opts
 * @returns {Promise<{ name: string, spf: object|null, dmarc: object|null, caa: object|null, svcb: object[] }>}
 *   a section is null when it does not apply to the name
 */
export async function explainName(name, { dns, signal, known = new Map() } = {}) {
  const n = String(name ?? '').toLowerCase().replace(/\.$/, '');
  const askKnown = (qname, type) => (qname === n && known.get(type) && answered(known.get(type)) ? Promise.resolve(known.get(type)) : ask(dns, qname, type, signal));
  const underscored = isUnderscored(n);
  // A top-level domain (`com`) has no organizational domain and no CAA tree to climb.
  const singleLabel = !n.includes('.');
  const mailName = n.startsWith('_dmarc.');
  const applies = n && n !== '.' && !isReverse(n);
  if (!applies) return { name: n, spf: null, dmarc: null, caa: null, svcb: [] };
  /** A section that broke on something unexpected says so, alone: the others stay. Only an abort rejects. */
  const safe = (p, extra = {}) => p.catch((err) => {
    if (errorKind(err) === 'abort') throw err;
    return { ...extra, state: 'failed', error: String((err && err.message) || err), failure: null };
  });

  const txtP = singleLabel ? null : askKnown(n, 'TXT');
  const mx = known.get('MX');
  const nullMx = !!(mx && answered(mx) && ofType(mx, 'MX').length === 1 && ofType(mx, 'MX')[0].data && ofType(mx, 'MX')[0].data.exchange === '.');

  const spfP = mailName || singleLabel ? Promise.resolve(null) : safe(txtP.then((txt) => spfSection(n, { dns, signal, txt, spfType: known.get('SPF'), nullMx })));

  const dmarcP = safe((async () => {
    if (mailName) {
      const txt = await txtP;
      const domain = n.slice('_dmarc.'.length);
      if (!answered(txt)) return { state: 'failed', error: errText(txt), failure: txt };
      const recs = ofType(txt, 'TXT').map(txtText).filter((s) => /^v\s*=\s*DMARC1\s*(?:;|$)/i.test(s));
      return dmarcState(recs, { domain, foundAt: domain, inherited: false });
    }
    if (singleLabel || underscored) return null;
    if (registrableDomain(n) !== n) {
      // Below the organizational domain only a name that sends mail: SPF, or MX hosts (not a null MX).
      const spf = await spfP;
      if (!(spf && spf.state === 'ok')) {
        const mxRes = await askKnown(n, 'MX');
        if (answered(mxRes) && !ofType(mxRes, 'MX').some((rr) => rr.data && rr.data.exchange !== '.')) return null;
      }
    }
    const found = await findDmarc(n, { dns, signal });
    if (found.error) return { state: 'failed', error: found.error, failure: found.failure };
    return dmarcState(found.records, { domain: n, foundAt: found.foundAt, inherited: found.inherited });
  })());

  const caaP = safe((async () => {
    if (underscored || singleLabel) return null;
    // The lookup's own CAA answer starts the climb when it has records; otherwise the climb asks.
    const own = known.get('CAA');
    if (own && answered(own) && ofType(own, 'CAA').length) {
      return { state: 'ok', foundAt: n, records: ofType(own, 'CAA'), explained: explainCaa(ofType(own, 'CAA'), { name: n, foundAt: n }) };
    }
    const found = await findCaa(n, { dns, signal });
    if (found.error) return { state: 'failed', error: found.error, failure: null };
    if (!found.records.length) return { state: 'none', chain: found.chain, explained: explainCaa([], { name: n }) };
    return { state: 'ok', foundAt: found.foundAt, records: found.records, chain: found.chain, explained: explainCaa(found.records, { name: n, foundAt: found.foundAt }) };
  })());

  const svcbTypes = [...(underscored && !known.has('HTTPS') ? [] : ['HTTPS']), ...(known.has('SVCB') ? ['SVCB'] : [])];
  const svcbP = Promise.all(svcbTypes.map((type) => safe((async () => {
    const res = await askKnown(n, type);
    if (!answered(res)) return { type, state: 'failed', error: errText(res), failure: res };
    const rrs = ofType(res, type).filter((rr) => !rr.error && rr.data && typeof rr.data === 'object');
    if (!rrs.length) return { type, state: 'none' };
    const targets = uniq(rrs.filter((rr) => Number(rr.data.priority) !== 0).map((rr) => (rr.data.target === '.' ? n : String(rr.data.target).replace(/\.$/, ''))));
    const addresses = new Map();
    await Promise.all(targets.slice(0, 8).map(async (target) => {
      const [a, aaaa] = await Promise.all([askKnown(target, 'A'), askKnown(target, 'AAAA')]);
      addresses.set(target, {
        ipv4: answered(a) ? ofType(a, 'A').map((rr) => rr.data) : null,
        ipv6: answered(aaaa) ? ofType(aaaa, 'AAAA').map((rr) => rr.data) : null
      });
    }));
    return { type, state: 'ok', explained: explainSvcb(rrs, { owner: n, type, addresses }) };
  })(), { type })));

  const [spf, dmarc, caa, svcb] = await Promise.all([spfP, dmarcP, caaP, svcbP]);
  throwIfAborted(signal);
  return { name: n, spf, dmarc, caa, svcb };
}

function dmarcState(records, { domain, foundAt, inherited }) {
  if (!records.length) return { state: 'none', domain };
  if (records.length > 1) return { state: 'multiple', domain, foundAt, count: records.length };
  return { state: 'ok', domain, foundAt, inherited, record: records[0], explained: explainDmarc(records[0], { domain, foundAt, inherited }) };
}
