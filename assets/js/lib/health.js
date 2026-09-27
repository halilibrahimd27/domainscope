/**
 * health.js — domain health checks: NS / SOA / MX, SPF (RFC 7208, including
 * the recursive 10-DNS-lookup budget and void lookups), DMARC (RFC 7489),
 * DKIM (common selectors), CAA (RFC 8659, tree climbing), DNSSEC (DS / DNSKEY
 * / AD flag / broken-chain detection), wildcard DNS, MTA-STS, TLS-RPT, BIMI,
 * HTTPS records, IPv6 and RDAP registration / expiry.
 *
 * Every finding is a Check `{ id, severity, titleKey, detailKey, params }`
 * with i18n keys `health.<id>.title` / `health.<id>.detail`; English and
 * Turkish texts ship in {@link HEALTH_I18N} (placeholders use `{name}`).
 *
 * DNS goes through an injected client with the DohClient contract (spec §5.9):
 * `query(name, type, { dnssec, cd, signal })` → DnsResponse, and optionally
 * `resolveHost`, `detectWildcard` (both emulated with `query` when absent).
 * DOM-free; runs in browsers and Node 22.
 */

import { errorKind, throwIfAborted, randomLabel, uniq } from './util.js';
import { normalizeHostname, registrableDomain, isSubdomainOf } from './domain.js';
import { normalizeIP, ipVersion, isPrivateIP, parseIP } from './netinfo.js';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES, EDE_CODES, base64Decode, rcodeToName } from './dnswire.js';
import { rdapDomain, registryDomain } from './rdap.js';

/**
 * DKIM selectors probed by default: generic ones plus the defaults of large
 * mail providers / ESPs (Google, Microsoft 365, Zoho, Proton, Mailchimp /
 * Mandrill, Amazon SES, SendGrid, Mailgun, Brevo, Postmark, Fastmail …).
 * @type {ReadonlyArray<string>}
 */
export const DEFAULT_DKIM_SELECTORS = Object.freeze([
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
  'mandrill', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'mxvault', 'everlytic', 'sig1',
  'amazonses', 'mailjet', 'sendgrid', 'smtpapi', 'em', 'mg', 'mailo', 'pm', 'fm1', 'fm2', 'fm3',
  'key1', 'key2', 'dkim1', 'mx', 'email', 'cm', 'yandex', 'turbo-smtp', 'brevo', 'sib', 'hs1', 'hs2'
]);

/** Max DNS-querying terms per SPF evaluation (RFC 7208 §4.6.4). */
export const SPF_LOOKUP_LIMIT = 10;
/** Max void lookups (RFC 7208 §4.6.4). */
export const SPF_VOID_LIMIT = 2;

const SPF_MAX_QUERIES = 80; // hard cap on DNS queries made while expanding one SPF tree
const SPF_RECOMMENDED_MAX_LENGTH = 450; // RFC 7208 §3.4: keep the answer within 512 octets
const DAY_MS = 86400000;

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

const isAbort = (err) => errorKind(err) === 'abort';
const arr = (v) => (Array.isArray(v) ? v : []);
const canonName = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const issue = (code, token = '') => ({ code, token: String(token) });

function listParam(values, max = 12) {
  const list = uniq(arr(values).filter((v) => v !== null && v !== undefined && v !== '').map(String));
  if (list.length <= max) return list.join(', ');
  return `${list.slice(0, max).join(', ')} (+${list.length - max})`;
}

function isoDate(d) {
  return d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : '';
}

/** Answer RRs of `type` (owner name optionally filtered). */
function records(res, type, owner = null) {
  return arr(res && res.answers).filter((rr) => rr && rr.type === type && (owner === null || canonName(rr.name) === owner));
}

/** Joined character-strings of every TXT record in an answer. */
function txtStrings(res) {
  return records(res, 'TXT').map((rr) => (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '')));
}

/** Lookup failed (transport error or an rcode other than NOERROR/NXDOMAIN). */
function failed(res) {
  return !res || !res.ok || (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN');
}

function errText(res) {
  if (!res) return 'no response';
  return res.ok ? String(res.rcode) : String(res.error || 'DNS query failed');
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

function normResponse(res) {
  if (!res || typeof res !== 'object') {
    return { ok: false, rcode: null, flags: {}, answers: [], authorities: [], ede: [], error: 'Empty DNS response', errorKind: 'unknown' };
  }
  let rcode = null;
  if (typeof res.rcode === 'string') rcode = res.rcode.toUpperCase();
  else if (typeof res.rcodeName === 'string') rcode = res.rcodeName.toUpperCase();
  else if (Number.isInteger(res.rcode)) rcode = rcodeToName(res.rcode);
  const ok = res.ok === undefined ? rcode !== null : !!res.ok;
  return {
    ok,
    rcode: ok ? rcode || 'NOERROR' : null,
    flags: res.flags && typeof res.flags === 'object' ? res.flags : {},
    answers: arr(res.answers),
    authorities: arr(res.authorities),
    ede: arr(res.ede ?? (res.edns && res.edns.ede)),
    resolver: res.resolver ?? null,
    error: ok ? null : String(res.error || 'DNS query failed'),
    errorKind: ok ? null : res.errorKind || 'unknown'
  };
}

function normHost(r, name) {
  const ips = (list, v) => uniq(arr(list).map(normalizeIP).filter((ip) => ip && ipVersion(ip) === v));
  return {
    name,
    status: typeof r?.status === 'string' ? r.status.toUpperCase() : 'ERROR',
    cnames: arr(r?.cnames).map(canonName).filter(Boolean),
    ipv4: ips(r?.ipv4, 4),
    ipv6: ips(r?.ipv6, 6),
    error: r?.error ? String(r.error) : null
  };
}

const ADAPTED = Symbol('health.dnsAdapter');

/**
 * Wrap a DohClient-like object: per-run memoisation, response normalisation,
 * `resolveHost` / `detectWildcard` emulation, and "never throws except on
 * abort" semantics.
 */
function adaptDns(dns, signal) {
  if (dns && dns[ADAPTED]) return dns;
  if (!dns || typeof dns.query !== 'function') throw new TypeError('A DNS client with query(name, type, opts) is required');
  const memo = new Map();
  const memoize = (key, fn) => {
    if (!memo.has(key)) {
      const p = fn();
      memo.set(key, p);
      p.catch(() => memo.delete(key)); // only aborts reject; do not cache them
    }
    return memo.get(key);
  };

  function query(name, type, { dnssec = false, cd = false } = {}) {
    const n = canonName(name);
    return memoize(`q|${n}|${type}|${dnssec ? 1 : 0}|${cd ? 1 : 0}`, async () => {
      throwIfAborted(signal);
      try {
        return normResponse(await dns.query(n, type, { dnssec, cd, signal }));
      } catch (err) {
        if (isAbort(err)) throw err;
        return normResponse({ ok: false, error: err && err.message ? err.message : String(err), errorKind: errorKind(err) });
      }
    });
  }

  function resolveHost(name) {
    const n = canonName(name);
    return memoize(`h|${n}`, async () => {
      throwIfAborted(signal);
      if (typeof dns.resolveHost === 'function') {
        try {
          return normHost(await dns.resolveHost(n, { signal }), n);
        } catch (err) {
          if (isAbort(err)) throw err;
          return normHost({ status: 'ERROR', error: err && err.message ? err.message : String(err) }, n);
        }
      }
      const [a, aaaa] = await Promise.all([query(n, 'A'), query(n, 'AAAA')]);
      const ref = !failed(a) ? a : aaaa;
      return normHost({
        status: failed(a) && failed(aaaa) ? (a.ok ? a.rcode : 'ERROR') : ref.rcode,
        cnames: cnameChain(ref.answers, n),
        ipv4: records(a, 'A').map((rr) => rr.data),
        ipv6: records(aaaa, 'AAAA').map((rr) => rr.data),
        error: failed(a) && failed(aaaa) ? errText(a) : null
      }, n);
    });
  }

  async function detectWildcard(domain) {
    throwIfAborted(signal);
    if (typeof dns.detectWildcard === 'function') {
      try {
        const r = await dns.detectWildcard(domain, { signal });
        // DohClient extension: `probes: [{ name, status }]`. When no probe got
        // a definite answer (e.g. SERVFAIL from a broken zone) the test is
        // inconclusive rather than "no wildcard".
        const probes = arr(r && r.probes);
        let error = r && r.error ? String(r.error) : null;
        if (!error && !(r && r.wildcard) && probes.length
          && probes.every((p) => p && p.status !== 'NOERROR' && p.status !== 'NXDOMAIN')) {
          error = String(probes[0].status || 'ERROR');
        }
        return {
          wildcard: !!(r && r.wildcard),
          ipv4: uniq(arr(r && r.ipv4)),
          ipv6: uniq(arr(r && r.ipv6)),
          cnames: uniq(arr(r && r.cnames)),
          error
        };
      } catch (err) {
        if (isAbort(err)) throw err;
        return { wildcard: false, ipv4: [], ipv6: [], cnames: [], error: err && err.message ? err.message : String(err) };
      }
    }
    const probes = await Promise.all([randomLabel(16), randomLabel(16)].map((l) => resolveHost(`${l}.${domain}`)));
    const hits = probes.filter((h) => h.ipv4.length || h.ipv6.length || h.cnames.length);
    const errored = probes.filter((h) => h.status !== 'NOERROR' && h.status !== 'NXDOMAIN');
    return {
      wildcard: hits.length === probes.length,
      ipv4: uniq(hits.flatMap((h) => h.ipv4)),
      ipv6: uniq(hits.flatMap((h) => h.ipv6)),
      cnames: uniq(hits.flatMap((h) => h.cnames)),
      error: errored.length === probes.length ? errored[0].error || errored[0].status : null
    };
  }

  return { [ADAPTED]: true, query, resolveHost, detectWildcard };
}

/* ------------------------------------------------------------------------ */
/* SPF (RFC 7208)                                                           */
/* ------------------------------------------------------------------------ */

const SPF_MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const SPF_LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
// RFC 7208 §7.1 macro letters (c, r, t are only meaningful in exp= but are syntactically valid).
const MACRO_RE = /%(?:\{([slodiphcrtvSLODIPHCRTV])(\d*)(r?)([.\-+,/_=]*)\}|(%)|(_)|(-))/g;

/** Does a TXT string start an SPF record ("v=spf1" + SP or end, case-insensitive)? */
function isSpfRecord(s) {
  return /^v=spf1(?: |$)/i.test(String(s));
}

function validDomainSpec(spec) {
  const s = String(spec ?? '');
  if (!s) return false;
  if (s.includes('%')) {
    const stripped = s.replace(MACRO_RE, 'x');
    return !stripped.includes('%') && /^[\x21-\x7e]+$/.test(stripped);
  }
  return normalizeHostname(s.replace(/\.$/, '')) !== null;
}

/**
 * Expand an SPF domain-spec. Only macros that need no sender context
 * (%{d}, %{o}, and the escapes %% %_ %-) can be expanded; anything else
 * (%{i}, %{s}, %{l} …) yields `{ name: null, macro: true }`.
 * %{d} is the current domain (it changes inside include / redirect), %{o}
 * the sender domain (RFC 7208 §7.3), taken to be the checked domain.
 */
function expandDomainSpec(spec, domain, senderDomain = domain) {
  const s = String(spec);
  if (!s.includes('%')) return { name: normalizeHostname(s.replace(/\.$/, '')), macro: false };
  let unresolved = false;
  const out = s.replace(MACRO_RE, (m, letter, digits, rev, delims, pct, us, dash) => {
    if (pct) return '%';
    if (us) return ' ';
    if (dash) return '%20';
    const l = letter.toLowerCase();
    if (l !== 'd' && l !== 'o') {
      unresolved = true;
      return m;
    }
    const splitter = delims ? new RegExp(`[${delims.replace(/[-\\\]^]/g, '\\$&')}]`) : /\./;
    let parts = (l === 'o' ? senderDomain : domain).split(splitter);
    if (rev) parts = parts.reverse();
    if (digits) {
      const n = Number(digits);
      if (n > 0) parts = parts.slice(-n);
    }
    return parts.join('.');
  });
  if (unresolved) return { name: null, macro: true };
  return { name: normalizeHostname(out.replace(/\.$/, '')), macro: true };
}

/**
 * Parse one SPF record (RFC 7208 §4.6 / §5 / §6 syntax).
 *
 * @param {string|string[]} txt the record (TXT character-strings are joined without separator)
 * @returns {{ valid: boolean, record: string, version: 'spf1'|null,
 *   terms: Array<{ qualifier: '+'|'-'|'~'|'?', mechanism: string, value: string|null, cidr4: number|null,
 *     cidr6: number|null, raw: string }>,
 *   modifiers: { redirect: string|null, exp: string|null, other: Object<string, string> },
 *   all: '+'|'-'|'~'|'?'|null, allIndex: number, lookupTerms: number, length: number,
 *   errors: Array<{ code: string, token: string }>, warnings: Array<{ code: string, token: string }> }}
 *   error codes: not-spf, unknown-mechanism, invalid-term, duplicate-modifier, invalid-domain-spec;
 *   warning codes: ptr, terms-after-all, redirect-ignored, broad-range, too-long.
 */
export function parseSpf(txt) {
  const record = Array.isArray(txt) ? txt.map(String).join('') : String(txt ?? '');
  const out = {
    valid: false,
    record,
    version: null,
    terms: [],
    modifiers: { redirect: null, exp: null, other: {} },
    all: null,
    allIndex: -1,
    lookupTerms: 0,
    length: record.length,
    errors: [],
    warnings: []
  };
  const head = /^v=spf1(?= |$)/i.exec(record);
  if (!head) {
    out.errors.push(issue('not-spf', record.slice(0, 32)));
    return out;
  }
  out.version = 'spf1';
  for (const tok of record.slice(head[0].length).split(/[ \t]+/).filter(Boolean)) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(tok);
    if (mod) {
      const name = mod[1].toLowerCase();
      if (name === 'redirect' || name === 'exp') {
        if (out.modifiers[name] !== null) out.errors.push(issue('duplicate-modifier', tok));
        else if (!validDomainSpec(mod[2])) out.errors.push(issue('invalid-domain-spec', tok));
        else out.modifiers[name] = mod[2];
      } else if (!(name in out.modifiers.other)) {
        out.modifiers.other[name] = mod[2]; // unknown modifiers are ignored (RFC 7208 §6)
      }
      continue;
    }
    const q = '+-~?'.includes(tok[0]) ? tok[0] : '';
    const body = q ? tok.slice(1) : tok;
    const nameMatch = /^[a-z0-9]+/i.exec(body);
    const mech = nameMatch ? nameMatch[0].toLowerCase() : '';
    const rest = body.slice(mech.length);
    if (!SPF_MECHANISMS.has(mech)) {
      out.errors.push(issue('unknown-mechanism', tok));
      continue;
    }
    const term = { qualifier: q || '+', mechanism: mech, value: null, cidr4: null, cidr6: null, raw: tok };
    if (!parseSpfTerm(term, rest)) {
      out.errors.push(issue('invalid-term', tok));
      continue;
    }
    if (mech === 'all' && out.allIndex === -1) out.allIndex = out.terms.length;
    out.terms.push(term);
  }

  const evaluated = out.allIndex >= 0 ? out.terms.slice(0, out.allIndex + 1) : out.terms;
  out.all = out.allIndex >= 0 ? out.terms[out.allIndex].qualifier : null;
  out.lookupTerms = evaluated.filter((t) => SPF_LOOKUP_MECHANISMS.has(t.mechanism)).length
    + (out.modifiers.redirect && out.allIndex < 0 ? 1 : 0);
  if (out.allIndex >= 0 && out.allIndex < out.terms.length - 1) {
    out.warnings.push(issue('terms-after-all', out.terms.slice(out.allIndex + 1).map((t) => t.raw).join(' ')));
  }
  if (out.modifiers.redirect && out.allIndex >= 0) out.warnings.push(issue('redirect-ignored', `redirect=${out.modifiers.redirect}`));
  for (const t of out.terms) {
    if (t.mechanism === 'ptr') out.warnings.push(issue('ptr', t.raw));
    // ip4 / ip6 and the dual CIDR length of a / mx (RFC 7208 §5.3, §5.4): a/0 or mx//0 matches every address.
    if ((t.cidr4 !== null && t.cidr4 < 8) || (t.cidr6 !== null && t.cidr6 < 16)) {
      if (t.qualifier === '+') out.warnings.push(issue('broad-range', t.raw));
    }
  }
  if (record.length > SPF_RECOMMENDED_MAX_LENGTH) out.warnings.push(issue('too-long', String(record.length)));
  out.valid = out.errors.length === 0;
  return out;
}

function parseSpfTerm(term, rest) {
  switch (term.mechanism) {
    case 'all':
      return rest === '';
    case 'include':
    case 'exists':
      if (!rest.startsWith(':') || !validDomainSpec(rest.slice(1))) return false;
      term.value = rest.slice(1);
      return true;
    case 'ptr':
      if (rest === '') return true;
      if (!rest.startsWith(':') || !validDomainSpec(rest.slice(1))) return false;
      term.value = rest.slice(1);
      return true;
    case 'a':
    case 'mx': {
      const m = /^(?::([^/]+))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/.exec(rest);
      if (!m) return false;
      if (m[1] !== undefined) {
        if (!validDomainSpec(m[1])) return false;
        term.value = m[1];
      }
      if (m[2] !== undefined) {
        if (Number(m[2]) > 32) return false;
        term.cidr4 = Number(m[2]);
      }
      if (m[3] !== undefined) {
        if (Number(m[3]) > 128) return false;
        term.cidr6 = Number(m[3]);
      }
      return true;
    }
    case 'ip4': {
      const m = /^:([0-9.]+)(?:\/(\d{1,2}))?$/.exec(rest);
      if (!m || ipVersion(m[1]) !== 4 || (m[2] !== undefined && Number(m[2]) > 32)) return false;
      term.value = normalizeIP(m[1]);
      term.cidr4 = m[2] === undefined ? 32 : Number(m[2]);
      return true;
    }
    case 'ip6': {
      const m = /^:([0-9a-f:.]+?)(?:\/(\d{1,3}))?$/i.exec(rest);
      if (!m || ipVersion(m[1]) !== 6 || (m[2] !== undefined && Number(m[2]) > 128)) return false;
      term.value = normalizeIP(m[1]);
      term.cidr6 = m[2] === undefined ? 128 : Number(m[2]);
      return true;
    }
    default:
      return false;
  }
}

/**
 * @typedef {object} SpfNode
 * @property {string} domain
 * @property {string|null} record the SPF record found (null when missing / failed)
 * @property {'+'|'-'|'~'|'?'|null} all
 * @property {number} count DNS-querying terms in this record plus all nested ones
 * @property {number} voidCount void lookups in this subtree (NXDOMAIN / empty answers)
 * @property {boolean} void the TXT lookup for this (included) domain itself was void
 * @property {Array<{ term: string, mechanism: string, qualifier: string, target: string|null, lookup: boolean,
 *   void: boolean, macro: boolean, error: string|null, child: SpfNode|null }>} terms
 * @property {Array<{ code: string, domain: string, target: string|null, detail: string }>} errors
 */

function spfError(ctx, node, code, target = null, detail = '') {
  const e = { code, domain: node.domain, target, detail: String(detail) };
  node.errors.push(e);
  ctx.errors.push(e);
  return code;
}

async function evalSpfNode(domain, ctx, depth, path, knownRecord) {
  const node = { domain, record: null, all: null, count: 0, voidCount: 0, void: false, terms: [], errors: [] };
  let record = knownRecord;
  if (record === undefined || record === null) {
    ctx.queries += 1;
    const res = await ctx.d.query(domain, 'TXT');
    if (failed(res)) {
      spfError(ctx, node, 'dns-error', domain, errText(res));
      return node;
    }
    if (depth > 0 && (res.rcode === 'NXDOMAIN' || records(res, 'TXT').length === 0)) {
      node.void = true;
      node.voidCount += 1;
    }
    const spfs = txtStrings(res).filter(isSpfRecord);
    if (spfs.length === 0) {
      spfError(ctx, node, 'no-record', domain, res.rcode);
      return node;
    }
    if (spfs.length > 1) {
      spfError(ctx, node, 'multiple-records', domain, String(spfs.length));
      return node;
    }
    record = spfs[0];
  }
  node.record = record;
  const parsed = parseSpf(record);
  node.all = parsed.all;
  if (!parsed.valid) spfError(ctx, node, 'syntax', domain, parsed.errors.map((e) => e.token).join(' '));

  const evaluated = parsed.allIndex >= 0 ? parsed.terms.slice(0, parsed.allIndex + 1) : parsed.terms;
  const jobs = evaluated.map((term) => ({ term, kind: term.mechanism }));
  if (parsed.modifiers.redirect && parsed.allIndex < 0) {
    jobs.push({ term: { qualifier: '', mechanism: 'redirect', value: parsed.modifiers.redirect, raw: `redirect=${parsed.modifiers.redirect}` }, kind: 'redirect' });
  }
  node.terms = await Promise.all(jobs.map(({ term }) => evalSpfTerm(term, node, ctx, depth, path)));
  for (const t of node.terms) {
    if (t.lookup) node.count += 1;
    if (t.void) node.voidCount += 1;
    if (t.child) {
      node.count += t.child.count;
      node.voidCount += t.child.voidCount;
    }
  }
  return node;
}

async function evalSpfTerm(term, node, ctx, depth, path) {
  const t = {
    term: term.raw, mechanism: term.mechanism, qualifier: term.qualifier, target: null,
    lookup: false, void: false, macro: false, error: null, child: null
  };
  const recursive = term.mechanism === 'include' || term.mechanism === 'redirect';
  if (!recursive && !SPF_LOOKUP_MECHANISMS.has(term.mechanism)) return t;
  t.lookup = true;
  const expanded = expandDomainSpec(term.value ?? node.domain, node.domain, ctx.sender);
  t.macro = expanded.macro;
  if (!expanded.name) return t; // needs sender context (e.g. %{i}); counted, not evaluated
  t.target = expanded.name;
  if (term.mechanism === 'ptr') return t; // needs the client IP; counted only
  if (ctx.queries >= SPF_MAX_QUERIES) {
    ctx.truncated = true;
    return t;
  }
  if (recursive) {
    if (path.includes(t.target)) {
      t.error = spfError(ctx, node, 'loop', t.target, [...path, t.target].join(' → '));
    } else if (depth + 1 > ctx.maxDepth) {
      t.error = spfError(ctx, node, 'depth', t.target, String(ctx.maxDepth));
    } else {
      t.child = await evalSpfNode(t.target, ctx, depth + 1, [...path, t.target]);
      if (t.child.errors.some((e) => e.domain === t.target && (e.code === 'no-record' || e.code === 'multiple-records'))) {
        t.error = t.child.errors[0].code;
      }
    }
    return t;
  }
  if (term.mechanism === 'a') {
    ctx.queries += 2;
    const h = await ctx.d.resolveHost(t.target);
    if (h.status !== 'NOERROR' && h.status !== 'NXDOMAIN') t.error = spfError(ctx, node, 'dns-error', t.target, h.error || h.status);
    else if (!h.ipv4.length && !h.ipv6.length) t.void = true;
    return t;
  }
  if (term.mechanism === 'mx') {
    ctx.queries += 1;
    const res = await ctx.d.query(t.target, 'MX');
    if (failed(res)) {
      t.error = spfError(ctx, node, 'dns-error', t.target, errText(res));
    } else {
      const mx = records(res, 'MX').filter((rr) => rr.data && rr.data.exchange !== '.');
      if (!mx.length) t.void = true;
      if (mx.length > SPF_LOOKUP_LIMIT) t.error = spfError(ctx, node, 'too-many-mx', t.target, String(mx.length));
    }
    return t;
  }
  // exists
  ctx.queries += 1;
  const res = await ctx.d.query(t.target, 'A');
  if (failed(res)) t.error = spfError(ctx, node, 'dns-error', t.target, errText(res));
  else if (!records(res, 'A').length) t.void = true;
  return t;
}

/**
 * Expand an SPF policy and count its DNS-querying terms (RFC 7208 §4.6.4):
 * include, a, mx, ptr, exists and redirect each cost one lookup, recursively
 * through include / redirect targets. Terms after `all` are not evaluated
 * and `redirect` is ignored when `all` is present. Also counts void lookups,
 * and reports missing / duplicate records in include targets, loops, too many
 * MX names, syntax errors and DNS failures.
 *
 * Counting continues past the limit (to report the real total) but at most
 * ~80 DNS queries are made per tree.
 *
 * @param {string} domain
 * @param {{ dns: object, signal?: AbortSignal, maxDepth?: number, record?: string }} opts
 *   `record` (extension) = the domain's SPF record when already known (skips one TXT query).
 * @returns {Promise<{ count: number, voidCount: number, tree: SpfNode,
 *   errors: Array<{ code: string, domain: string, target: string|null, detail: string }>,
 *   limit: number, exceeded: boolean, truncated: boolean }>}
 *   error codes: dns-error, no-record, multiple-records, syntax, loop, depth, too-many-mx.
 */
export async function spfLookupCount(domain, { dns, signal, maxDepth = 10, record } = {}) {
  const name = normalizeHostname(String(domain ?? ''));
  if (!name) throw new TypeError(`Invalid domain: ${String(domain)}`);
  throwIfAborted(signal);
  const ctx = { d: adaptDns(dns, signal), sender: name, queries: 0, errors: [], maxDepth, truncated: false };
  const tree = await evalSpfNode(name, ctx, 0, [name], record);
  throwIfAborted(signal);
  return {
    count: tree.count,
    voidCount: tree.voidCount,
    tree,
    errors: ctx.errors,
    limit: SPF_LOOKUP_LIMIT,
    exceeded: tree.count > SPF_LOOKUP_LIMIT,
    truncated: ctx.truncated
  };
}

/* ------------------------------------------------------------------------ */
/* DMARC (RFC 7489)                                                         */
/* ------------------------------------------------------------------------ */

const DMARC_POLICIES = new Set(['none', 'quarantine', 'reject']);
const DMARC_KNOWN_TAGS = new Set(['v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 't', 'psd']);

function isDmarcRecord(s) {
  return /^[vV]\s*=\s*DMARC1\s*(?:;|$)/.test(String(s));
}

function parseDmarcUris(value, warnings, tag) {
  const out = [];
  for (const part of String(value).split(',')) {
    const raw = part.trim();
    if (!raw) continue;
    const m = /^([a-z][a-z0-9+.-]*):([^!]+?)(?:!(\d+[kmgt]?))?$/i.exec(raw);
    if (!m) {
      warnings.push(issue(`invalid-${tag}`, raw));
      continue;
    }
    const scheme = m[1].toLowerCase();
    const address = m[2].trim();
    let domain = null;
    if (scheme === 'mailto') {
      const at = address.lastIndexOf('@');
      domain = at > 0 ? normalizeHostname(address.slice(at + 1)) : null;
      if (!domain) warnings.push(issue(`invalid-${tag}`, raw));
    }
    out.push({ uri: `${scheme}:${address}`, scheme, address, domain, sizeLimit: m[3] || null });
  }
  return out;
}

/**
 * Parse a DMARC record.
 * @param {string|string[]} txt
 * @returns {{ valid: boolean, record: string, tags: Object<string, string>, policy: string|null,
 *   subdomainPolicy: string|null, nonexistentPolicy: string|null, pct: number, rua: string[], ruf: string[],
 *   ruaTargets: Array<{ uri: string, scheme: string, address: string, domain: string|null, sizeLimit: string|null }>,
 *   rufTargets: Array<object>, adkim: 'r'|'s', aspf: 'r'|'s', fo: string, ri: number,
 *   errors: Array<{ code: string, token: string }>, warnings: Array<{ code: string, token: string }> }}
 *   error codes: not-dmarc, missing-p, invalid-p, invalid-sp, invalid-np, invalid-pct, invalid-adkim, invalid-aspf;
 *   warning codes: duplicate-tag, unknown-tag, invalid-rua, invalid-ruf, invalid-ri, invalid-fo.
 */
export function parseDmarc(txt) {
  const record = (Array.isArray(txt) ? txt.map(String).join('') : String(txt ?? '')).trim();
  const out = {
    valid: false, record, tags: {}, policy: null, subdomainPolicy: null, nonexistentPolicy: null,
    pct: 100, rua: [], ruf: [], ruaTargets: [], rufTargets: [], adkim: 'r', aspf: 'r', fo: '0', ri: 86400,
    errors: [], warnings: []
  };
  if (!isDmarcRecord(record)) {
    out.errors.push(issue('not-dmarc', record.slice(0, 32)));
    return out;
  }
  for (const part of record.split(';')) {
    const p = part.trim();
    if (!p) continue;
    const m = /^([a-z]+)\s*=\s*(.*)$/i.exec(p);
    if (!m) {
      out.warnings.push(issue('unknown-tag', p));
      continue;
    }
    const tag = m[1].toLowerCase();
    if (tag in out.tags) {
      out.warnings.push(issue('duplicate-tag', p));
      continue;
    }
    out.tags[tag] = m[2].trim();
    if (!DMARC_KNOWN_TAGS.has(tag)) out.warnings.push(issue('unknown-tag', p));
  }
  const t = out.tags;
  const policyTag = (name) => {
    if (!(name in t)) return null;
    const v = t[name].toLowerCase();
    if (DMARC_POLICIES.has(v)) return v;
    out.errors.push(issue(`invalid-${name}`, `${name}=${t[name]}`));
    return null;
  };
  out.policy = policyTag('p');
  if (!('p' in t)) out.errors.push(issue('missing-p', record.slice(0, 32)));
  out.subdomainPolicy = policyTag('sp') ?? out.policy;
  out.nonexistentPolicy = policyTag('np') ?? out.subdomainPolicy;
  if ('pct' in t) {
    if (/^\d{1,3}$/.test(t.pct) && Number(t.pct) <= 100) out.pct = Number(t.pct);
    else out.errors.push(issue('invalid-pct', `pct=${t.pct}`));
  }
  for (const k of ['adkim', 'aspf']) {
    if (!(k in t)) continue;
    const v = t[k].toLowerCase();
    if (v === 'r' || v === 's') out[k] = v;
    else out.errors.push(issue(`invalid-${k}`, `${k}=${t[k]}`));
  }
  if ('fo' in t) {
    if (/^[01ds](?:\s*:\s*[01ds])*$/i.test(t.fo)) out.fo = t.fo.replace(/\s+/g, '').toLowerCase();
    else out.warnings.push(issue('invalid-fo', `fo=${t.fo}`));
  }
  if ('ri' in t) {
    if (/^\d{1,10}$/.test(t.ri)) out.ri = Number(t.ri);
    else out.warnings.push(issue('invalid-ri', `ri=${t.ri}`));
  }
  if ('rua' in t) out.ruaTargets = parseDmarcUris(t.rua, out.warnings, 'rua');
  if ('ruf' in t) out.rufTargets = parseDmarcUris(t.ruf, out.warnings, 'ruf');
  out.rua = out.ruaTargets.map((x) => x.uri);
  out.ruf = out.rufTargets.map((x) => x.uri);
  out.valid = out.errors.length === 0;
  return out;
}

/* ------------------------------------------------------------------------ */
/* DKIM                                                                     */
/* ------------------------------------------------------------------------ */

/** Read one DER TLV header → { tag, start, end } or null. */
function derTlv(bytes, pos) {
  if (pos + 2 > bytes.length) return null;
  const tag = bytes[pos];
  let len = bytes[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || start + n > bytes.length) return null;
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + bytes[start + i];
    start += n;
  }
  const end = start + len;
  return end <= bytes.length ? { tag, start, end } : null;
}

/**
 * RSA modulus size of a base64 public key (SubjectPublicKeyInfo as used by
 * DKIM, or a bare PKCS#1 RSAPublicKey). Returns null when not parseable.
 * @param {string} b64
 * @returns {number|null}
 */
export function rsaKeyBits(b64) {
  let bytes;
  try {
    bytes = base64Decode(String(b64 ?? ''));
  } catch {
    return null;
  }
  const outer = derTlv(bytes, 0);
  if (!outer || outer.tag !== 0x30) return null;
  let first = derTlv(bytes, outer.start);
  if (!first) return null;
  let modulus = null;
  if (first.tag === 0x02) {
    modulus = first; // PKCS#1
  } else if (first.tag === 0x30) {
    const bits = derTlv(bytes, first.end);
    if (!bits || bits.tag !== 0x03) return null;
    const inner = derTlv(bytes, bits.start + 1);
    if (!inner || inner.tag !== 0x30) return null;
    first = derTlv(bytes, inner.start);
    if (first && first.tag === 0x02) modulus = first;
  }
  if (!modulus) return null;
  let i = modulus.start;
  while (i < modulus.end && bytes[i] === 0) i += 1;
  if (i >= modulus.end) return null;
  return (modulus.end - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}

/**
 * Parse a DKIM key record (RFC 6376 §3.6.1).
 * @param {string|string[]} txt
 * @returns {{ valid: boolean, tags: Object<string, string>, keyType: string, keyBits: number|null,
 *   revoked: boolean, testing: boolean, record: string }}
 */
export function parseDkim(txt) {
  const record = (Array.isArray(txt) ? txt.map(String).join('') : String(txt ?? '')).trim();
  const tags = {};
  for (const part of record.split(';')) {
    const m = /^\s*([a-z]+)\s*=\s*([\s\S]*?)\s*$/i.exec(part);
    if (m && !(m[1].toLowerCase() in tags)) tags[m[1].toLowerCase()] = m[2];
  }
  const keyType = (tags.k || 'rsa').toLowerCase();
  const p = (tags.p ?? '').replace(/\s+/g, '');
  let keyBits = null;
  if (p) keyBits = keyType === 'ed25519' ? 256 : rsaKeyBits(p);
  const flags = (tags.t || '').toLowerCase().split(':').map((s) => s.trim());
  const versionOk = !('v' in tags) || tags.v === 'DKIM1';
  return {
    valid: 'p' in tags && versionOk,
    tags,
    keyType,
    keyBits,
    revoked: 'p' in tags && p === '',
    testing: flags.includes('y'),
    record
  };
}

function looksLikeDkim(s) {
  return /(?:^|;)\s*p\s*=/i.test(s) || /^\s*v\s*=\s*DKIM1/i.test(s);
}

/* ------------------------------------------------------------------------ */
/* CAA (RFC 8659)                                                           */
/* ------------------------------------------------------------------------ */

const CAA_LABEL = '[a-z0-9](?:-*[a-z0-9])*';
const CAA_ISSUER_RE = new RegExp(`^${CAA_LABEL}(?:\\.${CAA_LABEL})*$`, 'i');
const CAA_PARAM_RE = /^([a-z0-9](?:-*[a-z0-9])*)\s*=\s*([\x21-\x3a\x3c-\x7e]*)$/i;

/**
 * Parse an issue / issuewild property value: `issuer-domain [; key=value]*`.
 * @param {string} value
 * @returns {{ issuer: string, params: Object<string, string>, valid: boolean, error: string|null }}
 *   `issuer` is '' for a "deny" value such as ";".
 */
export function parseCaaIssueValue(value) {
  const s = String(value ?? '');
  const semi = s.indexOf(';');
  const issuerPart = (semi === -1 ? s : s.slice(0, semi)).trim().toLowerCase();
  const paramPart = semi === -1 ? '' : s.slice(semi + 1);
  const out = { issuer: issuerPart, params: {}, valid: true, error: null };
  if (issuerPart && !CAA_ISSUER_RE.test(issuerPart)) {
    out.valid = false;
    out.error = 'invalid-issuer';
  }
  for (const raw of paramPart.split(';')) {
    const p = raw.trim();
    if (!p) continue;
    const m = CAA_PARAM_RE.exec(p);
    if (!m) {
      out.valid = false;
      out.error = out.error || 'invalid-parameter';
      continue;
    }
    out.params[m[1].toLowerCase()] = m[2];
  }
  return out;
}

function caaItem(r) {
  if (typeof r === 'string') {
    const m = /^\s*(\d{1,3})\s+([a-z0-9]+)\s+(?:"((?:[^"\\]|\\.)*)"|(\S.*?))\s*$/i.exec(r);
    return m ? { flags: Number(m[1]), tag: m[2], value: (m[3] ?? m[4] ?? '').replace(/\\(.)/g, '$1') } : null;
  }
  const d = r && typeof r === 'object' && r.data && typeof r.data === 'object' ? r.data : r;
  return d && typeof d.tag === 'string' ? { flags: Number(d.flags) || 0, tag: d.tag, value: String(d.value ?? '') } : null;
}

/**
 * Parse a CAA RRset.
 * @param {Array<object|string>} rrs CAA RRs (`rr.data` = { flags, tag, value }), bare data objects,
 *   or presentation strings such as `0 issue "letsencrypt.org; validationmethods=dns-01"`
 * @returns {{ issue: Array<{ issuer: string, params: Object<string, string>, valid: boolean, error: string|null,
 *   critical: boolean, raw: string }>, issuewild: Array<object>, iodef: Array<{ url: string, valid: boolean, critical: boolean }>,
 *   other: Array<{ tag: string, value: string, critical: boolean }>, unknown: Array<{ tag: string, value: string, critical: boolean }>,
 *   unknownCritical: boolean, issuers: string[], wildIssuers: string[], count: number }}
 *   `other` holds known non-issuance tags (issuemail, issuevmc, contactemail, contactphone);
 *   `issuers` / `wildIssuers` list the valid, non-empty issuer domains (a malformed value authorizes no CA).
 */
export function parseCaa(rrs) {
  const out = { issue: [], issuewild: [], iodef: [], other: [], unknown: [], unknownCritical: false, issuers: [], wildIssuers: [], count: 0 };
  for (const r of arr(rrs)) {
    const item = caaItem(r);
    if (!item) continue;
    out.count += 1;
    const tag = item.tag.toLowerCase();
    const critical = (item.flags & 128) !== 0;
    if (tag === 'issue' || tag === 'issuewild') {
      out[tag].push({ ...parseCaaIssueValue(item.value), critical, raw: item.value });
    } else if (tag === 'iodef') {
      out.iodef.push({ url: item.value, valid: /^(mailto:\S+@\S+|https?:\/\/\S+)$/i.test(item.value), critical });
    } else if (['issuemail', 'issuevmc', 'contactemail', 'contactphone'].includes(tag)) {
      out.other.push({ tag, value: item.value, critical });
    } else {
      out.unknown.push({ tag, value: item.value, critical });
      if (critical) out.unknownCritical = true;
    }
  }
  out.issuers = uniq(out.issue.filter((x) => x.valid && x.issuer).map((x) => x.issuer));
  out.wildIssuers = uniq(out.issuewild.filter((x) => x.valid && x.issuer).map((x) => x.issuer));
  return out;
}

/**
 * Certificate authorities → the CAA issuer domains they honour. Matched
 * (case-insensitively) against the issuer DN / O / CN text.
 * @type {ReadonlyArray<{ id: string, name: string, match: RegExp, domains: string[], distrusted?: string }>}
 */
export const CAA_ISSUERS = Object.freeze([
  { id: 'letsencrypt', name: "Let's Encrypt", match: /let'?s\s*encrypt|\bISRG\b/i, domains: ['letsencrypt.org'] },
  { id: 'google', name: 'Google Trust Services', match: /google trust services|\bGTS CA\b/i, domains: ['pki.goog'] },
  {
    id: 'digicert',
    name: 'DigiCert',
    // incl. legacy Symantec brands and the DigiCert-operated Cloudflare Inc CAs
    match: /digicert|geotrust|rapidssl|thawte|symantec|verisign|encryption everywhere|cloudflare inc (?:ecc|rsa) ca/i,
    domains: ['digicert.com', 'symantec.com', 'thawte.com', 'geotrust.com', 'rapidssl.com', 'digicert.ne.jp', 'cybertrust.ne.jp']
  },
  {
    id: 'sectigo',
    name: 'Sectigo',
    // ZeroSSL, GoGetSSL and cPanel issue from Sectigo intermediates
    match: /sectigo|comodo|usertrust|zerossl|gogetssl|cpanel/i,
    domains: ['sectigo.com', 'comodoca.com', 'comodo.com', 'usertrust.com', 'trust-provider.com']
  },
  { id: 'globalsign', name: 'GlobalSign', match: /globalsign/i, domains: ['globalsign.com'] },
  { id: 'godaddy', name: 'GoDaddy / Starfield', match: /go\s*daddy|starfield/i, domains: ['godaddy.com', 'starfieldtech.com'] },
  { id: 'amazon', name: 'Amazon', match: /\bamazon\b/i, domains: ['amazon.com', 'amazontrust.com', 'awstrust.com', 'amazonaws.com'] },
  { id: 'buypass', name: 'Buypass', match: /buypass/i, domains: ['buypass.com', 'buypass.no'] },
  { id: 'sslcom', name: 'SSL.com', match: /ssl\.com|ssl corporation/i, domains: ['ssl.com'] },
  { id: 'entrust', name: 'Entrust', match: /entrust/i, domains: ['entrust.net', 'affirmtrust.com'] },
  { id: 'certum', name: 'Certum (Asseco)', match: /certum|asseco|unizeto/i, domains: ['certum.pl', 'certum.eu'] },
  { id: 'microsoft', name: 'Microsoft', match: /microsoft/i, domains: ['microsoft.com'] },
  { id: 'actalis', name: 'Actalis', match: /actalis/i, domains: ['actalis.it'] },
  { id: 'harica', name: 'HARICA', match: /harica|hellenic academic/i, domains: ['harica.gr'] },
  { id: 'etugra', name: 'e-Tugra', match: /e-?tu[gğ]ra/i, domains: ['e-tugra.com.tr'], distrusted: '2023' }
].map((x) => Object.freeze({ ...x, domains: Object.freeze([...x.domains]) })));

function issuerText(issuerDN) {
  if (typeof issuerDN === 'string') return issuerDN;
  if (issuerDN && typeof issuerDN === 'object') return Object.values(issuerDN).filter((v) => typeof v === 'string').join(', ');
  return '';
}

/**
 * CA entries (from {@link CAA_ISSUERS}) that match an issuer DN.
 * @param {string|object} issuerDN e.g. "CN=R11,O=Let's Encrypt,C=US" (or a parsed `{ CN, O }` object)
 * @returns {Array<{ id: string, name: string, domains: string[], distrusted?: string }>}
 */
export function caaIssuerInfo(issuerDN) {
  const text = issuerText(issuerDN);
  if (!text) return [];
  return CAA_ISSUERS.filter((ca) => ca.match.test(text));
}

/**
 * Map a certificate issuer to the CAA identifiers its CA recognises.
 * @param {string|object} issuerDN
 * @returns {string[]} e.g. ['letsencrypt.org']; [] when the CA is unknown
 */
export function caaDomainsForIssuer(issuerDN) {
  return uniq(caaIssuerInfo(issuerDN).flatMap((ca) => ca.domains));
}

/**
 * Would the CAA RRset allow the certificate's CA to issue? (RFC 8659 §4)
 *
 * - no CAA records → allowed (any CA);
 * - an unknown tag with the critical flag → denied;
 * - for a wildcard name `issuewild` takes precedence over `issue` when present;
 * - no relevant issue property → allowed; all relevant values empty (";") → denied;
 * - otherwise allowed iff one relevant, well-formed value names the CA.
 *
 * @param {Array<object|string>|object} caaRecords CAA RRs / data objects / strings, or a {@link parseCaa} result
 * @param {string|object} issuerDN
 * @param {{ wildcard?: boolean }} [opts]
 * @returns {{ allowed: boolean|null, reason: string, reasonKey: string, property: 'issue'|'issuewild'|null,
 *   issuerDomains: string[], authorized: string[], matched: object|null, distrusted: boolean }}
 *   reason codes: none, critical-unknown, no-issue-property, unknown-issuer, allowed, deny-all, not-listed
 *   (reasonKey = `health.caa.reason.<code>`). `allowed` is null when the CA is unknown.
 */
export function checkCaaAllows(caaRecords, issuerDN, { wildcard = false } = {}) {
  const parsed = caaRecords && !Array.isArray(caaRecords) && Array.isArray(caaRecords.issue) ? caaRecords : parseCaa(caaRecords);
  const infos = caaIssuerInfo(issuerDN);
  const issuerDomains = uniq(infos.flatMap((ca) => ca.domains));
  const base = {
    property: null, issuerDomains, authorized: [], matched: null, distrusted: infos.some((ca) => ca.distrusted)
  };
  const result = (allowed, reason, extra = {}) => ({ allowed, reason, reasonKey: `health.caa.reason.${reason}`, ...base, ...extra });
  const total = parsed.issue.length + parsed.issuewild.length + parsed.iodef.length + parsed.other.length + parsed.unknown.length;
  if (total === 0) return result(true, 'none');
  if (parsed.unknownCritical) return result(false, 'critical-unknown');
  const property = wildcard && parsed.issuewild.length ? 'issuewild' : 'issue';
  const relevant = parsed[property];
  if (!relevant.length) return result(true, 'no-issue-property', { property: null });
  const authorized = uniq(relevant.filter((r) => r.valid && r.issuer).map((r) => r.issuer));
  if (!authorized.length) return result(false, 'deny-all', { property, authorized });
  if (!issuerDomains.length) return result(null, 'unknown-issuer', { property, authorized });
  const matched = relevant.find((r) => r.valid && r.issuer && issuerDomains.includes(r.issuer)) || null;
  if (matched) return result(true, 'allowed', { property, authorized, matched });
  return result(false, 'not-listed', { property, authorized });
}

/**
 * Find the CAA RRset that applies to `name` (RFC 8659 §3): query the name,
 * then each parent, stopping at the first non-empty CAA RRset or after the
 * registrable (registry-level) domain. CNAMEs are followed by the resolver.
 *
 * @param {string} name
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<{ name: string, foundAt: string|null, records: object[], parsed: object,
 *   chain: Array<{ name: string, rcode: string|null, count: number }>, error: string|null }>}
 */
export async function findCaa(name, { dns, signal } = {}) {
  const start = normalizeHostname(String(name ?? '').replace(/^\*\./, ''));
  if (!start) throw new TypeError(`Invalid domain: ${String(name)}`);
  const d = adaptDns(dns, signal);
  const stop = registryDomain(start);
  const chain = [];
  let cur = start;
  for (let i = 0; i < 16; i += 1) {
    const res = await d.query(cur, 'CAA');
    throwIfAborted(signal);
    if (failed(res)) {
      chain.push({ name: cur, rcode: res.rcode, count: 0 });
      return { name: start, foundAt: null, records: [], parsed: parseCaa([]), chain, error: `${cur}: ${errText(res)}` };
    }
    const caa = records(res, 'CAA');
    chain.push({ name: cur, rcode: res.rcode, count: caa.length });
    if (caa.length) return { name: start, foundAt: cur, records: caa, parsed: parseCaa(caa), chain, error: null };
    if (cur === stop || !cur.includes('.')) break;
    const parent = cur.slice(cur.indexOf('.') + 1);
    if (stop ? !isSubdomainOf(parent, stop) : !parent.includes('.')) break;
    cur = parent;
  }
  return { name: start, foundAt: null, records: [], parsed: parseCaa([]), chain, error: null };
}

/* ------------------------------------------------------------------------ */
/* Checks                                                                   */
/* ------------------------------------------------------------------------ */

/** Check categories (the part of the id before the first '.') → UI groups. */
export const HEALTH_CATEGORIES = Object.freeze({
  domain: 'dns', soa: 'dns', ns: 'dns', apex: 'dns', ipv6: 'dns', 'https-rr': 'dns', wildcard: 'dns',
  mx: 'email', spf: 'email', dmarc: 'email', dkim: 'email', 'mta-sts': 'email', 'tls-rpt': 'email', bimi: 'email',
  caa: 'security', dnssec: 'security',
  rdap: 'registration'
});
const CATEGORY_ORDER = Object.keys(HEALTH_CATEGORIES);

function paramValue(v) {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return listParam(v);
  if (v instanceof Date) return isoDate(v);
  if (typeof v === 'number' || typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  return String(v);
}

function makeCheck(id, severity, params = {}) {
  const category = id.slice(0, id.indexOf('.'));
  const clean = {};
  for (const [k, v] of Object.entries(params)) clean[k] = paramValue(v);
  return {
    id,
    severity,
    titleKey: `health.${id}.title`,
    detailKey: `health.${id}.detail`,
    params: clean,
    category,
    group: HEALTH_CATEGORIES[category] || 'dns'
  };
}

/** /24 (IPv4) or /48 (IPv6) network of an address, used for NS diversity. */
function networkOf(ip) {
  const p = parseIP(ip);
  if (!p) return null;
  if (p.version === 4) return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
  const groups = (p.value >> 80n).toString(16).padStart(12, '0').match(/.{4}/g).map((g) => g.replace(/^0+(?=.)/, ''));
  return `${groups.join(':')}::/48`;
}

function daysUntil(date, now) {
  return Math.floor((date.getTime() - now.getTime()) / DAY_MS);
}

/* ---- individual analyses: each returns { checks, ...data } ---- */

/**
 * Owner of the deepest SOA (answer or authority section) at `name` or one of
 * its ancestors. An SOA owned by anything else is a CNAME target's zone.
 */
function enclosingSoaOwner(res, name) {
  const owners = [...arr(res && res.answers), ...arr(res && res.authorities)]
    .filter((rr) => rr && rr.type === 'SOA' && isSubdomainOf(name, canonName(rr.name)))
    .map((rr) => canonName(rr.name));
  return owners.sort((a, b) => b.length - a.length)[0] || null;
}

/** Zone of `name` from the SOA answers of its parents (up to the registrable domain), or null. */
async function parentZone(name, d) {
  const stop = registryDomain(name);
  if (!stop || stop === name || !isSubdomainOf(name, stop)) return null;
  let cur = name;
  while (cur !== stop) {
    cur = cur.slice(cur.indexOf('.') + 1);
    const res = await d.query(cur, 'SOA');
    if (failed(res)) return null;
    const zone = enclosingSoaOwner(res, cur);
    if (zone) return zone;
  }
  return null;
}

async function analyzeSoa(name, soaR, d) {
  const checks = [];
  let soa = null;
  let zone = null;
  if (failed(soaR)) {
    checks.push(makeCheck('soa.error', 'warn', { error: errText(soaR) }));
    return { checks, soa, zone, apex: null };
  }
  const own = records(soaR, 'SOA', name)[0];
  if (own) {
    soa = own.data;
    zone = name;
    checks.push(makeCheck('soa.ok', 'ok', { mname: soa.mname, email: soa.email || soa.rname, serial: soa.serial }));
    if (Number.isFinite(soa.retry) && Number.isFinite(soa.refresh) && soa.retry >= soa.refresh) {
      checks.push(makeCheck('soa.retry', 'warn', { retry: soa.retry, refresh: soa.refresh }));
    }
    if (Number.isFinite(soa.expire) && soa.expire < 604800) checks.push(makeCheck('soa.expire', 'warn', { expire: soa.expire }));
    if (Number.isFinite(soa.minimum) && soa.minimum > 86400) checks.push(makeCheck('soa.minimum', 'info', { minimum: soa.minimum }));
    return { checks, soa, zone, apex: true };
  }
  // For an alias (CNAME) the resolver answers with the target's SOA: ask the parents instead.
  zone = enclosingSoaOwner(soaR, name) || await parentZone(name, d);
  if (soaR.rcode === 'NOERROR') checks.push(makeCheck('soa.not-apex', 'warn', { domain: name, zone: zone || '?' }));
  return { checks, soa, zone, apex: false };
}

async function analyzeNs(name, nsR, d, isApex) {
  const checks = [];
  // Owner-filtered: through a CNAME the resolver returns the target zone's name servers.
  const hosts = uniq(records(nsR, 'NS', name).map((rr) => canonName(rr.data)).filter(Boolean));
  const out = { checks, hosts, addresses: {} };
  if (failed(nsR)) {
    checks.push(makeCheck('ns.error', 'error', { error: errText(nsR) }));
    return out;
  }
  if (!hosts.length) {
    if (isApex !== false) checks.push(makeCheck('ns.none', 'error', { domain: name }));
    return out;
  }
  if (hosts.length === 1) checks.push(makeCheck('ns.single', 'warn', { host: hosts[0] }));
  else checks.push(makeCheck('ns.ok', 'ok', { count: hosts.length, hosts }));

  const resolved = await Promise.all(hosts.map((h) => d.resolveHost(h)));
  const unresolvable = [];
  const privateHosts = [];
  const nets = new Set();
  let v6 = 0;
  resolved.forEach((r, i) => {
    const ips = [...r.ipv4, ...r.ipv6];
    out.addresses[hosts[i]] = ips;
    // Only a definite answer (NXDOMAIN / NODATA) proves a host has no address.
    if (!ips.length && (r.status === 'NOERROR' || r.status === 'NXDOMAIN')) unresolvable.push(hosts[i]);
    if (ips.some(isPrivateIP)) privateHosts.push(hosts[i]);
    if (r.ipv6.length) v6 += 1;
    for (const ip of ips) nets.add(networkOf(ip));
  });
  if (unresolvable.length) checks.push(makeCheck('ns.unresolvable', 'error', { hosts: unresolvable }));
  if (privateHosts.length) checks.push(makeCheck('ns.private-ip', 'error', { hosts: privateHosts }));
  if (nets.size === 1 && hosts.length > 1) {
    checks.push(makeCheck('ns.same-subnet', 'warn', { subnet: [...nets][0] }));
  } else if (nets.size > 1) {
    checks.push(makeCheck('ns.diversity', 'ok', { count: nets.size }));
  }
  const providers = uniq(hosts.map((h) => registrableDomain(h) || h));
  if (providers.length === 1 && hosts.length > 1) checks.push(makeCheck('ns.single-provider', 'info', { provider: providers[0] }));
  if (resolved.some((r) => r.ipv4.length || r.ipv6.length) && v6 === 0) checks.push(makeCheck('ns.no-ipv6', 'info', {}));
  return out;
}

async function analyzeMx(name, mxR, d) {
  const checks = [];
  const mx = records(mxR, 'MX').map((rr) => rr.data).filter((x) => x && typeof x === 'object')
    .map((x) => ({ preference: Number(x.preference) || 0, exchange: canonName(x.exchange) || '.' }))
    .sort((a, b) => a.preference - b.preference || a.exchange.localeCompare(b.exchange));
  const out = { checks, mx, nullMx: false, hosts: {} };
  if (failed(mxR)) {
    checks.push(makeCheck('mx.error', 'warn', { error: errText(mxR) }));
    return out;
  }
  if (!mx.length) {
    checks.push(makeCheck('mx.none', 'info', { domain: name }));
    return out;
  }
  const nulls = mx.filter((m) => m.exchange === '.');
  if (nulls.length && nulls.length === mx.length) {
    out.nullMx = true;
    checks.push(makeCheck('mx.null', 'info', { domain: name }));
    return out;
  }
  if (nulls.length) checks.push(makeCheck('mx.null-mixed', 'error', {}));
  const real = mx.filter((m) => m.exchange !== '.');
  const ipLiteral = real.filter((m) => ipVersion(m.exchange) !== 0 || /^\d+(\.\d+){3}$/.test(m.exchange));
  const hostsToResolve = real.filter((m) => !ipLiteral.includes(m));
  const resolved = await Promise.all(hostsToResolve.map((m) => d.resolveHost(m.exchange)));
  const cname = [];
  const unresolvable = [];
  const priv = [];
  resolved.forEach((r, i) => {
    const host = hostsToResolve[i].exchange;
    const ips = [...r.ipv4, ...r.ipv6];
    out.hosts[host] = { ipv4: r.ipv4, ipv6: r.ipv6, cnames: r.cnames, status: r.status };
    if (r.cnames.length) cname.push(host);
    if (!ips.length) {
      if (r.status === 'NOERROR' || r.status === 'NXDOMAIN') unresolvable.push(host);
    } else if (ips.every(isPrivateIP)) {
      priv.push(host);
    }
  });
  if (ipLiteral.length) checks.push(makeCheck('mx.ip-literal', 'error', { hosts: ipLiteral.map((m) => m.exchange) }));
  if (unresolvable.length) checks.push(makeCheck('mx.unresolvable', 'error', { hosts: unresolvable }));
  if (cname.length) checks.push(makeCheck('mx.cname', 'warn', { hosts: cname }));
  if (priv.length) checks.push(makeCheck('mx.private-ip', 'warn', { hosts: priv }));
  if (!ipLiteral.length && !unresolvable.length) {
    checks.push(makeCheck('mx.ok', 'ok', { count: real.length, hosts: real.map((m) => `${m.preference} ${m.exchange}`) }));
  }
  return out;
}

async function analyzeSpf(name, txtR, d, mxInfo) {
  const checks = [];
  const out = { checks, record: null, parsed: null, lookups: null };
  if (failed(txtR)) {
    checks.push(makeCheck('spf.error', 'warn', { error: errText(txtR) }));
    return out;
  }
  const spfs = txtStrings(txtR).filter(isSpfRecord);
  if (!spfs.length) {
    checks.push(makeCheck('spf.missing', mxInfo.nullMx ? 'info' : 'warn', { domain: name }));
    return out;
  }
  if (spfs.length > 1) {
    checks.push(makeCheck('spf.multiple', 'error', { count: spfs.length }));
    return out;
  }
  const record = spfs[0];
  const parsed = parseSpf(record);
  out.record = record;
  out.parsed = parsed;
  checks.push(makeCheck('spf.present', 'ok', { record }));
  if (!parsed.valid) checks.push(makeCheck('spf.syntax', 'error', { errors: parsed.errors.map((e) => e.token) }));
  const allCode = { '-': 'spf.all-fail', '~': 'spf.all-softfail', '?': 'spf.all-neutral', '+': 'spf.all-pass' };
  const allSeverity = { '-': 'ok', '~': 'info', '?': 'warn', '+': 'error' };
  if (parsed.all) checks.push(makeCheck(allCode[parsed.all], allSeverity[parsed.all], { term: parsed.terms[parsed.allIndex].raw }));
  else if (!parsed.modifiers.redirect) checks.push(makeCheck('spf.all-missing', 'warn', {}));
  for (const w of parsed.warnings) {
    if (w.code === 'ptr') checks.push(makeCheck('spf.ptr', 'warn', { term: w.token }));
    else if (w.code === 'terms-after-all') checks.push(makeCheck('spf.after-all', 'warn', { terms: w.token }));
    else if (w.code === 'redirect-ignored') checks.push(makeCheck('spf.redirect-ignored', 'info', { term: w.token }));
    else if (w.code === 'too-long') checks.push(makeCheck('spf.too-long', 'warn', { length: Number(w.token), max: SPF_RECOMMENDED_MAX_LENGTH }));
  }
  const broad = parsed.warnings.filter((w) => w.code === 'broad-range').map((w) => w.token);
  if (broad.length) {
    const open = parsed.terms.some((t) => t.qualifier === '+' && (t.cidr4 === 0 || t.cidr6 === 0)); // ip4/ip6/a/mx with /0
    checks.push(makeCheck('spf.broad', open ? 'error' : 'warn', { terms: broad }));
  }
  if (mxInfo.nullMx && parsed.all !== '-') checks.push(makeCheck('spf.null-mx', 'info', {}));

  const lookups = await spfLookupCount(name, { dns: d, record });
  out.lookups = lookups;
  if (lookups.count > SPF_LOOKUP_LIMIT) {
    checks.push(makeCheck('spf.lookups-exceeded', 'error', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }));
  } else if (lookups.count >= SPF_LOOKUP_LIMIT - 1) {
    checks.push(makeCheck('spf.lookups-high', 'warn', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }));
  } else {
    checks.push(makeCheck('spf.lookups-ok', 'ok', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }));
  }
  if (lookups.voidCount > SPF_VOID_LIMIT) checks.push(makeCheck('spf.void', 'warn', { count: lookups.voidCount, limit: SPF_VOID_LIMIT }));
  const nested = lookups.errors.filter((e) => e.code !== 'syntax' || e.domain !== name);
  const fatal = nested.filter((e) => e.code !== 'dns-error');
  if (fatal.length) {
    checks.push(makeCheck('spf.include-error', 'error', {
      details: fatal.map((e) => `${e.target || e.domain}: ${e.code}${e.detail && e.code !== 'no-record' ? ` (${e.detail})` : ''}`)
    }));
  }
  const temp = nested.filter((e) => e.code === 'dns-error');
  if (temp.length) checks.push(makeCheck('spf.dns-error', 'warn', { details: temp.map((e) => `${e.target || e.domain}: ${e.detail}`) }));
  return out;
}

async function analyzeDmarc(name, dmarcR, d) {
  const checks = [];
  const out = { checks, record: null, parsed: null, foundAt: null, inherited: false };
  let res = dmarcR;
  let at = name;
  if (failed(res)) {
    checks.push(makeCheck('dmarc.error', 'warn', { error: errText(res) }));
    return out;
  }
  let recs = txtStrings(res).filter(isDmarcRecord);
  const org = registrableDomain(name);
  if (!recs.length && org && org !== name) {
    // RFC 7489 §6.6.3: fall back to the organizational domain's policy.
    const orgRes = await d.query(`_dmarc.${org}`, 'TXT');
    if (failed(orgRes)) {
      // Unknown whether a policy is inherited: not the same as "no DMARC record".
      checks.push(makeCheck('dmarc.error', 'warn', { error: `_dmarc.${org}: ${errText(orgRes)}` }));
      return out;
    }
    const orgRecs = txtStrings(orgRes).filter(isDmarcRecord);
    if (orgRecs.length) {
      recs = orgRecs;
      res = orgRes;
      at = org;
      out.inherited = true;
    }
  }
  if (!recs.length) {
    checks.push(makeCheck('dmarc.missing', 'warn', { domain: name }));
    return out;
  }
  if (recs.length > 1) {
    checks.push(makeCheck('dmarc.multiple', 'error', { count: recs.length, domain: at }));
    return out;
  }
  const parsed = parseDmarc(recs[0]);
  out.record = recs[0];
  out.parsed = parsed;
  out.foundAt = at;
  if (out.inherited) checks.push(makeCheck('dmarc.inherited', 'info', { org: at, policy: parsed.subdomainPolicy || '' }));
  if (!parsed.valid) {
    checks.push(makeCheck('dmarc.invalid', 'error', { errors: parsed.errors.map((e) => e.token) }));
    return out;
  }
  const policy = out.inherited ? parsed.subdomainPolicy : parsed.policy;
  const polSeverity = { none: 'warn', quarantine: 'ok', reject: 'ok' };
  checks.push(makeCheck(`dmarc.policy-${policy}`, polSeverity[policy], { policy, record: recs[0] }));
  if (parsed.pct < 100 && policy !== 'none') checks.push(makeCheck('dmarc.pct', 'warn', { pct: parsed.pct }));
  if (!out.inherited && parsed.policy !== 'none' && parsed.subdomainPolicy === 'none') {
    checks.push(makeCheck('dmarc.sp-none', 'warn', { policy: parsed.policy }));
  }
  if (!parsed.rua.length) {
    checks.push(makeCheck('dmarc.rua-missing', 'info', {}));
  } else {
    // RFC 7489 §7.1: an external report receiver must publish
    // <policy-domain>._report._dmarc.<receiver> "v=DMARC1".
    const orgOfPolicy = registrableDomain(at) || at;
    const external = uniq(parsed.ruaTargets
      .filter((x) => x.domain && (registrableDomain(x.domain) || x.domain) !== orgOfPolicy)
      .map((x) => x.domain)).slice(0, 5);
    const verdicts = await Promise.all(external.map(async (rd) => {
      const r = await d.query(`${at}._report._dmarc.${rd}`, 'TXT');
      if (failed(r)) return { rd, ok: null };
      return { rd, ok: txtStrings(r).some(isDmarcRecord) };
    }));
    const unauthorized = verdicts.filter((v) => v.ok === false).map((v) => v.rd);
    if (unauthorized.length) checks.push(makeCheck('dmarc.rua-unauthorized', 'warn', { targets: unauthorized }));
  }
  return out;
}

async function dkimLookup(d, name, selector) {
  const qname = `${selector}._domainkey.${name}`;
  const res = await d.query(qname, 'TXT');
  if (failed(res)) return { selector, error: errText(res) };
  const rec = txtStrings(res).find(looksLikeDkim);
  if (!rec) return { selector, record: null };
  const parsed = parseDkim(rec);
  return {
    selector,
    record: rec,
    keyType: parsed.keyType,
    keyBits: parsed.keyBits,
    revoked: parsed.revoked,
    testing: parsed.testing,
    cname: cnameChain(res.answers, qname)[0] || null
  };
}

async function analyzeDkim(name, selectors, d) {
  const list = uniq(arr(selectors).map((s) => canonName(s)).filter((s) => /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/.test(s)));
  // A random selector detects a wildcard (*._domainkey) record, e.g. the
  // "v=DKIM1; p=" (revoked) wildcard that non-sending domains publish;
  // selectors answering with that same record are not real keys.
  const [probe, ...results] = await Promise.all([
    dkimLookup(d, name, `x${randomLabel(14)}`),
    ...list.map((selector) => dkimLookup(d, name, selector))
  ]);
  const wildcardRecord = probe.record || null;
  const found = results.filter((r) => r.record && r.record !== wildcardRecord);
  const active = found.filter((r) => !r.revoked);
  const checks = [];
  if (active.length) {
    checks.push(makeCheck('dkim.found', 'ok', { count: active.length, selectors: active.map((r) => r.selector) }));
    const weak = active.filter((r) => r.keyType === 'rsa' && r.keyBits !== null && r.keyBits < 1024);
    const small = active.filter((r) => r.keyType === 'rsa' && r.keyBits !== null && r.keyBits >= 1024 && r.keyBits < 2048);
    const testing = active.filter((r) => r.testing);
    if (weak.length) checks.push(makeCheck('dkim.weak', 'error', { selectors: weak.map((r) => `${r.selector} (${r.keyBits})`) }));
    if (small.length) checks.push(makeCheck('dkim.1024', 'info', { selectors: small.map((r) => `${r.selector} (${r.keyBits})`) }));
    if (testing.length) checks.push(makeCheck('dkim.testing', 'info', { selectors: testing.map((r) => r.selector) }));
  } else if (list.length && results.every((r) => r.error)) {
    checks.push(makeCheck('dkim.error', 'info', { error: results[0].error }));
  } else if (!wildcardRecord) {
    checks.push(makeCheck('dkim.none', 'info', { count: list.length }));
  }
  const revoked = found.filter((r) => r.revoked);
  if (revoked.length) checks.push(makeCheck('dkim.revoked', 'info', { selectors: revoked.map((r) => r.selector) }));
  if (wildcardRecord) {
    checks.push(makeCheck('dkim.wildcard', 'info', { revoked: parseDkim(wildcardRecord).revoked ? 'yes' : 'no', record: wildcardRecord }));
  }
  const dkim = found.map(({ error, ...r }) => r);
  if (wildcardRecord) {
    const w = parseDkim(wildcardRecord);
    dkim.push({
      selector: '*', record: wildcardRecord, keyType: w.keyType, keyBits: w.keyBits,
      revoked: w.revoked, testing: w.testing, cname: null
    });
  }
  return { checks, dkim };
}

async function analyzeCaa(name, d, { issuerDN, wildcardCert }) {
  const checks = [];
  const caa = await findCaa(name, { dns: d });
  if (caa.error) {
    checks.push(makeCheck('caa.error', 'warn', { error: caa.error }));
    return { checks, caa };
  }
  const p = caa.parsed;
  if (!caa.foundAt) {
    checks.push(makeCheck('caa.missing', 'info', { domain: name }));
  } else {
    if (p.unknownCritical) {
      checks.push(makeCheck('caa.critical-unknown', 'error', { tags: p.unknown.filter((u) => u.critical).map((u) => u.tag) }));
    }
    const invalid = [...p.issue, ...p.issuewild].filter((x) => !x.valid).map((x) => x.raw);
    if (invalid.length) checks.push(makeCheck('caa.invalid', 'warn', { values: invalid }));
    if (p.issue.length && !p.issuers.length && !p.wildIssuers.length) {
      checks.push(makeCheck('caa.deny-all', 'warn', { foundAt: caa.foundAt }));
    } else {
      checks.push(makeCheck('caa.present', 'ok', {
        foundAt: caa.foundAt,
        issuers: p.issuers.length ? p.issuers : (p.issue.length ? ['—'] : ['*']),
        wildIssuers: p.issuewild.length ? (p.wildIssuers.length ? p.wildIssuers : ['—']) : p.issuers.length ? p.issuers : ['*'],
        iodef: p.iodef.length ? p.iodef.map((x) => x.url) : ['—']
      }));
    }
    const distrusted = CAA_ISSUERS.filter((ca) => ca.distrusted && ca.domains.some((dm) => p.issuers.includes(dm) || p.wildIssuers.includes(dm)));
    if (distrusted.length) {
      checks.push(makeCheck('caa.distrusted', 'warn', { issuers: distrusted.flatMap((ca) => ca.domains), since: distrusted[0].distrusted }));
    }
  }
  let certCheck = null;
  if (issuerDN) {
    certCheck = checkCaaAllows(p, issuerDN, { wildcard: !!wildcardCert });
    const ca = caaIssuerInfo(issuerDN)[0];
    const params = {
      issuer: ca ? ca.name : issuerText(issuerDN), property: certCheck.property || 'issue',
      authorized: certCheck.authorized, reason: certCheck.reason
    };
    if (certCheck.allowed === true) checks.push(makeCheck('caa.cert-allowed', 'ok', params));
    else if (certCheck.reason === 'not-listed') checks.push(makeCheck('caa.cert-denied', 'error', params));
    else if (certCheck.allowed === false) checks.push(makeCheck('caa.cert-blocked', 'error', params)); // deny-all, critical-unknown
    else checks.push(makeCheck('caa.cert-unknown', 'info', params));
  }
  return { checks, caa, certCheck };
}

const DEPRECATED_DNSSEC_ALGS = new Set([1, 3, 5, 6, 7, 12]);
const LOOKUP_FAILURE_IDS = new Set([
  'soa.error', 'ns.error', 'mx.error', 'spf.error', 'dmarc.error', 'dkim.error', 'caa.error', 'wildcard.error', 'dnssec.error'
]);

async function analyzeDnssec(name, d, { dsR, dnskeyR, soaR, isApex }) {
  const checks = [];
  const ds = records(dsR, 'DS', name).map((rr) => rr.data).filter(Boolean);
  const dnskey = records(dnskeyR, 'DNSKEY', name).map((rr) => rr.data).filter(Boolean);
  const out = {
    checks,
    ds,
    dnskey,
    dnssec: {
      signed: failed(dsR) ? null : ds.length > 0,
      validated: null,
      broken: false,
      dsCount: ds.length,
      dnskeyCount: dnskey.length,
      algorithms: [],
      ede: []
    }
  };
  const info = out.dnssec;
  // Broken-chain detection: validating resolvers SERVFAIL, but with CD=1 (no validation) the answer comes back.
  const probe = [soaR, dnskeyR, dsR].find((r) => r && r.ok && r.rcode === 'SERVFAIL');
  if (probe) {
    const cdRes = await d.query(name, 'SOA', { cd: true });
    info.ede = uniq(arr(probe.ede).map((e) => {
      const text = String(e.text || '').trim().replace(/\.+$/, '');
      return `${e.code}${EDE_CODES[e.code] ? ` ${EDE_CODES[e.code]}` : ''}${text ? `: ${text}` : ''}`;
    }));
    if (cdRes.ok && (cdRes.rcode === 'NOERROR' || cdRes.rcode === 'NXDOMAIN')) {
      info.broken = true;
      info.validated = false;
      checks.push(makeCheck('dnssec.broken', 'error', { ede: info.ede.length ? info.ede : ['—'] }));
      return out;
    }
  }
  if (failed(dsR) && failed(dnskeyR)) {
    checks.push(makeCheck('dnssec.error', 'warn', { error: errText(dsR) }));
    return out;
  }
  if (!dnskeyR.ok || dnskeyR.rcode !== 'NOERROR') info.validated = null;
  else info.validated = !!dnskeyR.flags.ad;
  const algNums = uniq([...ds.map((x) => x.algorithm), ...dnskey.map((x) => x.algorithm)].filter(Number.isInteger));
  info.algorithms = algNums.map((n) => DNSSEC_ALGORITHMS[n] || `ALG${n}`);

  if (failed(dsR) || failed(dnskeyR)) {
    // Only one side answered: the other side's empty list is not a proven absence,
    // so no unsigned / no-ds / ds-no-dnskey / ds-mismatch verdict.
    const dsFailed = failed(dsR);
    checks.push(makeCheck('dnssec.error', 'warn', { error: `${dsFailed ? 'DS' : 'DNSKEY'}: ${errText(dsFailed ? dsR : dnskeyR)}` }));
    return out;
  }
  if (!ds.length && !dnskey.length) {
    if (isApex !== false) checks.push(makeCheck('dnssec.unsigned', 'info', { domain: name }));
    return out;
  }
  if (ds.length && !dnskey.length) {
    checks.push(makeCheck('dnssec.ds-no-dnskey', 'error', { tags: ds.map((x) => x.keyTag) }));
    return out;
  }
  if (!ds.length && dnskey.length) {
    checks.push(makeCheck('dnssec.no-ds', 'warn', { domain: name }));
    return out;
  }
  const keyIds = new Set(dnskey.map((k) => `${k.keyTag}/${k.algorithm}`));
  const matching = ds.filter((x) => keyIds.has(`${x.keyTag}/${x.algorithm}`));
  if (!matching.length) {
    checks.push(makeCheck('dnssec.ds-mismatch', 'error', {
      dsTags: ds.map((x) => x.keyTag), keyTags: dnskey.map((k) => k.keyTag)
    }));
  } else if (info.validated) {
    checks.push(makeCheck('dnssec.ok', 'ok', { algorithms: info.algorithms }));
  } else {
    checks.push(makeCheck('dnssec.not-validated', 'warn', {}));
  }
  const deprecated = algNums.filter((n) => DEPRECATED_DNSSEC_ALGS.has(n));
  if (deprecated.length) {
    checks.push(makeCheck('dnssec.algorithm-deprecated', 'warn', { algorithms: deprecated.map((n) => DNSSEC_ALGORITHMS[n] || `ALG${n}`) }));
  }
  if (ds.every((x) => x.digestType === 1)) {
    checks.push(makeCheck('dnssec.ds-sha1', 'info', { digest: DS_DIGEST_TYPES[1] }));
  }
  return out;
}

/**
 * Why a name answers NXDOMAIN: an alias whose target is gone (RFC 6604 keeps
 * the CNAME in the answer), a name missing from a live zone, or a domain that
 * is not delegated at all. `zone` = the enclosing zone found by analyzeSoa.
 */
function analyzeNxdomain(name, zone, aR, soaR) {
  const viaA = cnameChain(aR.answers, name);
  const chain = viaA.length ? viaA : cnameChain(soaR.answers, name);
  if (chain.length) {
    return makeCheck('domain.dangling-cname', 'error', { domain: name, target: chain[chain.length - 1], chain: [name, ...chain].join(' → ') });
  }
  const reg = registryDomain(name);
  if (reg && reg !== name && zone && isSubdomainOf(zone, reg)) return makeCheck('domain.name-missing', 'error', { domain: name, zone });
  return makeCheck('domain.nxdomain', 'error', { domain: name });
}

function analyzeApex(name, aR, aaaaR) {
  const checks = [];
  const a = uniq(records(aR, 'A').map((rr) => rr.data));
  const aaaa = uniq(records(aaaaR, 'AAAA').map((rr) => rr.data));
  const all = [...a, ...aaaa];
  const chain = cnameChain(aR.answers, name);
  if (chain.length) checks.push(makeCheck('apex.cname', 'info', { domain: name, target: chain.join(' → ') }));
  if (!all.length) {
    if (!failed(aR)) checks.push(makeCheck('apex.no-address', 'info', { domain: name }));
  } else {
    checks.push(makeCheck('apex.ok', 'ok', { ipv4: a.length ? a : ['—'], ipv6: aaaa.length ? aaaa : ['—'] }));
    const priv = all.filter(isPrivateIP);
    if (priv.length) checks.push(makeCheck('apex.private-ip', 'warn', { ips: priv }));
    if (aaaa.length) checks.push(makeCheck('ipv6.present', 'ok', { ipv6: aaaa }));
    else checks.push(makeCheck('ipv6.missing', 'info', { domain: name }));
  }
  return { checks, a, aaaa };
}

function analyzeHttps(httpsR) {
  const recs = records(httpsR, 'HTTPS').map((rr) => rr.data).filter(Boolean);
  const checks = [];
  if (recs.length) {
    const alpn = uniq(recs.flatMap((r) => arr(r.params && r.params.alpn)));
    const ech = recs.some((r) => r.params && r.params.ech);
    checks.push(makeCheck('https-rr.present', 'info', { alpn: alpn.length ? alpn : ['—'], ech: ech ? 'yes' : 'no' }));
  }
  return { checks, https: recs };
}

function analyzeMailExtras(mtaR, tlsR, bimiR, { hasMail, dmarcPolicy }) {
  const checks = [];
  const mta = failed(mtaR) ? [] : txtStrings(mtaR).filter((s) => /^v=STSv1\s*(;|$)/i.test(s));
  const tls = failed(tlsR) ? [] : txtStrings(tlsR).filter((s) => /^v=TLSRPTv1\s*(;|$)/i.test(s));
  const bimi = failed(bimiR) ? [] : txtStrings(bimiR).filter((s) => /^v=BIMI1\s*(;|$)/i.test(s));
  const tag = (rec, t) => {
    const m = new RegExp(`(?:^|;)\\s*${t}\\s*=\\s*([^;]*)`, 'i').exec(rec || '');
    return m ? m[1].trim() : '';
  };
  if (mta.length > 1) checks.push(makeCheck('mta-sts.invalid', 'warn', { count: mta.length }));
  else if (mta.length) {
    const id = tag(mta[0], 'id');
    checks.push(id ? makeCheck('mta-sts.present', 'ok', { id }) : makeCheck('mta-sts.invalid', 'warn', { count: 1 }));
  } else if (hasMail) checks.push(makeCheck('mta-sts.missing', 'info', {}));
  if (tls.length) checks.push(makeCheck('tls-rpt.present', 'ok', { rua: tag(tls[0], 'rua') || '—' }));
  else if (hasMail) checks.push(makeCheck('tls-rpt.missing', 'info', {}));
  if (bimi.length) {
    checks.push(makeCheck('bimi.present', 'ok', { logo: tag(bimi[0], 'l') || '—' }));
    if (dmarcPolicy !== 'quarantine' && dmarcPolicy !== 'reject') checks.push(makeCheck('bimi.dmarc-weak', 'warn', { policy: dmarcPolicy || '—' }));
  }
  return { checks, mtaSts: mta[0] || null, tlsRpt: tls[0] || null, bimi: bimi[0] || null };
}

function analyzeRdap(r, now) {
  const checks = [];
  if (!r) return { checks };
  if (r.unsupportedTld) {
    checks.push(makeCheck('rdap.unsupported', 'info', { tld: r.tld || '' }));
    return { checks };
  }
  if (r.notFound) {
    checks.push(makeCheck('rdap.not-found', 'warn', { domain: r.domain }));
    return { checks };
  }
  if (!r.ok) {
    checks.push(makeCheck('rdap.error', 'info', { error: r.error || '' }));
    return { checks };
  }
  const status = arr(r.status);
  if (status.some((s) => /\b(client|server) ?hold\b/.test(s))) checks.push(makeCheck('rdap.hold', 'error', { status }));
  if (status.some((s) => /redemption ?period|pending ?delete/.test(s))) checks.push(makeCheck('rdap.pending-delete', 'error', { status }));
  if (r.expires instanceof Date) {
    const days = daysUntil(r.expires, now);
    const params = { days, date: r.expires, registrar: r.registrar || '' };
    if (days < 0) checks.push(makeCheck('rdap.expired', 'error', { ...params, days: -days }));
    else if (days < 30) checks.push(makeCheck('rdap.expiring', 'error', params));
    else if (days < 60) checks.push(makeCheck('rdap.expiring-soon', 'warn', params));
    else checks.push(makeCheck('rdap.expiry-ok', 'ok', params));
  } else {
    checks.push(makeCheck('rdap.no-expiry', 'info', {}));
  }
  if (status.length && !status.some((s) => /transfer ?prohibited/.test(s))) checks.push(makeCheck('rdap.transfer-unlocked', 'info', {}));
  return { checks };
}

/**
 * @typedef {object} HealthCheck
 * @property {string} id stable code, e.g. 'spf.lookups-exceeded' (category = part before the first '.')
 * @property {'ok'|'info'|'warn'|'error'} severity
 * @property {string} titleKey `health.<id>.title`
 * @property {string} detailKey `health.<id>.detail`
 * @property {Object<string, string|number>} params interpolation values (lists pre-joined with ', ')
 * @property {string} category extension, e.g. 'spf'
 * @property {'dns'|'email'|'security'|'registration'} group extension (i18n: `health.group.<group>`)
 */

/**
 * Run the full domain health check suite.
 *
 * Throws TypeError for an invalid domain or a missing DNS client and
 * AbortError when `signal` aborts; every other failure (DNS errors, RDAP
 * errors) becomes a check / null field, so a report is always produced.
 *
 * @param {string} domain
 * @param {{ dns: object, fetchImpl?: typeof fetch, signal?: AbortSignal, dkimSelectors?: string[],
 *   onProgress?: (p: { step: string, done: number, total: number }) => void,
 *   rdap?: boolean, issuerDN?: string|object|null, wildcardCert?: boolean, now?: Date }} opts
 *   Extensions: rdap (false skips the RDAP lookup), issuerDN + wildcardCert (adds a CAA check for
 *   that certificate's CA), now (clock for expiry maths, tests).
 * @returns {Promise<{ domain: string, checkedAt: Date, zone: string|null,
 *   records: { ns: string[], soa: object|null, mx: Array<{ preference: number, exchange: string }>, a: string[],
 *     aaaa: string[], txt: string[], spf: string|null, dmarc: string|null,
 *     dkim: Array<{ selector: string, record: string, keyType: string, keyBits: number|null, revoked: boolean,
 *       testing: boolean, cname: string|null }>,
 *     caa: Array<{ flags: number, tag: string, value: string }>, mtaSts: string|null, tlsRpt: string|null,
 *     bimi: string|null, ds: object[], dnskey: object[], https: object[] },
 *   dnssec: { signed: boolean|null, validated: boolean|null, broken: boolean, dsCount: number, dnskeyCount: number,
 *     algorithms: string[], ede: string[] },
 *   rdap: object|null, wildcard: { wildcard: boolean, ipv4: string[], ipv6: string[], cnames: string[], error: string|null }|null,
 *   spf: { record: string|null, parsed: object|null, lookups: object|null }, dmarc: { record: string|null, parsed: object|null,
 *     foundAt: string|null, inherited: boolean }, caa: object|null, caaCert: object|null, nsAddresses: Object<string, string[]>,
 *   mxHosts: object, checks: HealthCheck[], summary: { ok: number, info: number, warn: number, error: number } }>}
 */
export async function domainHealth(domain, {
  dns,
  fetchImpl = globalThis.fetch,
  signal,
  dkimSelectors = DEFAULT_DKIM_SELECTORS,
  onProgress,
  rdap = true,
  issuerDN = null,
  wildcardCert = false,
  now = null
} = {}) {
  const name = normalizeHostname(typeof domain === 'string' ? domain : '');
  if (!name) throw new TypeError(`Invalid domain: ${String(domain)}`);
  throwIfAborted(signal);
  const d = adaptDns(dns, signal);
  const clock = now instanceof Date ? now : new Date();

  const steps = ['records', 'ns', 'mx', 'spf', 'dmarc', 'dkim', 'caa', 'dnssec', 'wildcard', 'rdap'];
  let done = 0;
  const progress = (step) => {
    done += 1;
    if (typeof onProgress === 'function') {
      try { onProgress({ step, done, total: steps.length }); } catch { /* observer errors are ignored */ }
    }
  };
  const tracked = (step, p) => p.then((v) => { progress(step); return v; });

  // RDAP is independent network I/O: start it first.
  const rdapPromise = rdap
    ? tracked('rdap', rdapDomain(name, { fetchImpl, signal }))
    : Promise.resolve(null).then((v) => { progress('rdap'); return v; });
  rdapPromise.catch(() => {}); // awaited below; avoid an unhandled rejection if we abort first

  const [soaR, nsR, mxR, aR, aaaaR, txtR, httpsR, dsR, dnskeyR, dmarcR, mtaR, tlsR, bimiR] = await Promise.all([
    d.query(name, 'SOA'),
    d.query(name, 'NS'),
    d.query(name, 'MX'),
    d.query(name, 'A'),
    d.query(name, 'AAAA'),
    d.query(name, 'TXT'),
    d.query(name, 'HTTPS'),
    d.query(name, 'DS', { dnssec: true }),
    d.query(name, 'DNSKEY', { dnssec: true }),
    d.query(`_dmarc.${name}`, 'TXT'),
    d.query(`_mta-sts.${name}`, 'TXT'),
    d.query(`_smtp._tls.${name}`, 'TXT'),
    d.query(`default._bimi.${name}`, 'TXT')
  ]);
  throwIfAborted(signal);
  progress('records');

  const soa = await analyzeSoa(name, soaR, d);
  throwIfAborted(signal);
  const nxdomain = [soaR, nsR, aR].every((r) => r.ok && r.rcode === 'NXDOMAIN');

  const records0 = {
    ns: [], soa: soa.soa, mx: [], a: [], aaaa: [], txt: failed(txtR) ? [] : txtStrings(txtR), spf: null, dmarc: null,
    dkim: [], caa: [], mtaSts: null, tlsRpt: null, bimi: null, ds: [], dnskey: [], https: []
  };

  if (nxdomain) {
    for (const s of ['ns', 'mx', 'spf', 'dmarc', 'dkim', 'caa', 'dnssec', 'wildcard']) progress(s);
    const rdapResult = await rdapPromise;
    throwIfAborted(signal);
    const checks = [analyzeNxdomain(name, soa.zone, aR, soaR), ...analyzeRdap(rdapResult, clock).checks];
    return finishReport({
      domain: name, checkedAt: clock, zone: soa.zone, records: records0,
      dnssec: { signed: null, validated: null, broken: false, dsCount: 0, dnskeyCount: 0, algorithms: [], ede: [] },
      rdap: rdapResult, wildcard: null, spf: { record: null, parsed: null, lookups: null },
      dmarc: { record: null, parsed: null, foundAt: null, inherited: false }, caa: null, caaCert: null,
      nsAddresses: {}, mxHosts: {}, checks
    });
  }

  const [ns, mx, dnssec, wildcard, dkim, caa] = await Promise.all([
    tracked('ns', analyzeNs(name, nsR, d, soa.apex)),
    tracked('mx', analyzeMx(name, mxR, d)),
    tracked('dnssec', analyzeDnssec(name, d, { dsR, dnskeyR, soaR, isApex: soa.apex })),
    tracked('wildcard', d.detectWildcard(name)),
    tracked('dkim', analyzeDkim(name, dkimSelectors, d)),
    tracked('caa', analyzeCaa(name, d, { issuerDN, wildcardCert }))
  ]);
  const [spf, dmarc] = await Promise.all([
    tracked('spf', analyzeSpf(name, txtR, d, mx)),
    tracked('dmarc', analyzeDmarc(name, dmarcR, d))
  ]);
  const rdapResult = await rdapPromise;
  throwIfAborted(signal);

  const apex = analyzeApex(name, aR, aaaaR);
  const https = analyzeHttps(httpsR);
  const hasMail = mx.mx.some((m) => m.exchange !== '.');
  const policy = dmarc.parsed ? (dmarc.inherited ? dmarc.parsed.subdomainPolicy : dmarc.parsed.policy) : null;
  const extras = analyzeMailExtras(mtaR, tlsR, bimiR, { hasMail, dmarcPolicy: policy });
  const rdapChecks = analyzeRdap(rdapResult, clock);

  const wildcardChecks = [];
  if (wildcard.error) wildcardChecks.push(makeCheck('wildcard.error', 'info', { error: wildcard.error }));
  else if (wildcard.wildcard) {
    wildcardChecks.push(makeCheck('wildcard.present', 'info', {
      values: [...wildcard.cnames, ...wildcard.ipv4, ...wildcard.ipv6]
    }));
  } else wildcardChecks.push(makeCheck('wildcard.none', 'ok', {}));

  // Registry (parent) vs DNS (child) name server sets.
  const nsChecks = [...ns.checks];
  if (rdapResult && rdapResult.ok && rdapResult.domain === name && soa.apex && rdapResult.nameservers.length && ns.hosts.length) {
    const reg = [...rdapResult.nameservers].sort();
    const live = [...ns.hosts].sort();
    if (reg.join(' ') !== live.join(' ')) nsChecks.push(makeCheck('ns.rdap-mismatch', 'warn', { registry: reg, dns: live }));
  }

  let checks = [
    ...soa.checks, ...nsChecks, ...apex.checks, ...https.checks, ...wildcardChecks,
    ...mx.checks, ...spf.checks, ...dmarc.checks, ...dkim.checks, ...extras.checks,
    ...caa.checks, ...dnssec.checks, ...rdapChecks.checks
  ];
  if (dnssec.dnssec.broken) {
    // Every validated lookup fails with SERVFAIL: the per-record "lookup
    // failed" checks are consequences of dnssec.broken, not separate findings.
    checks = checks.filter((c) => !LOOKUP_FAILURE_IDS.has(c.id));
  }

  return finishReport({
    domain: name,
    checkedAt: clock,
    zone: soa.zone,
    records: {
      ...records0,
      ns: ns.hosts,
      mx: mx.mx,
      a: apex.a,
      aaaa: apex.aaaa,
      spf: spf.record,
      dmarc: dmarc.record,
      dkim: dkim.dkim,
      caa: caa.caa.records.map((rr) => rr.data),
      mtaSts: extras.mtaSts,
      tlsRpt: extras.tlsRpt,
      bimi: extras.bimi,
      ds: dnssec.ds,
      dnskey: dnssec.dnskey,
      https: https.https
    },
    dnssec: dnssec.dnssec,
    rdap: rdapResult,
    wildcard,
    spf: { record: spf.record, parsed: spf.parsed, lookups: spf.lookups },
    dmarc: { record: dmarc.record, parsed: dmarc.parsed, foundAt: dmarc.foundAt, inherited: dmarc.inherited },
    caa: caa.caa,
    caaCert: caa.certCheck || null,
    nsAddresses: ns.addresses,
    mxHosts: mx.hosts,
    checks
  });
}

function finishReport(report) {
  const order = (c) => {
    const i = CATEGORY_ORDER.indexOf(c.category);
    return i === -1 ? CATEGORY_ORDER.length : i;
  };
  // Stable sort by category order (ties keep insertion order).
  report.checks = report.checks.map((c, i) => ({ c, i })).sort((x, y) => order(x.c) - order(y.c) || x.i - y.i).map((x) => x.c);
  const summary = { ok: 0, info: 0, warn: 0, error: 0 };
  for (const c of report.checks) summary[c.severity] += 1;
  report.summary = summary;
  return report;
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

function buildStrings(lang) {
  const out = {};
  for (const [id, title, detail] of STRINGS) {
    if (detail) {
      out[`health.${id}.title`] = title[lang];
      out[`health.${id}.detail`] = detail[lang];
    } else {
      out[`health.${id}`] = title[lang]; // plain label (groups, CAA reasons)
    }
  }
  return out;
}

// [id, [en, tr] title, [en, tr] detail]; entries without a detail are plain
// labels stored under `health.<id>` (groups, CAA reasons).
const STRINGS = [
  ['group.dns', ['DNS', 'DNS']],
  ['group.email', ['Email security', 'E-posta güvenliği']],
  ['group.security', ['Certificates & DNSSEC', 'Sertifika ve DNSSEC']],
  ['group.registration', ['Registration', 'Alan adı kaydı']],

  ['domain.nxdomain', ['Domain does not exist', 'Alan adı mevcut değil'],
    ['DNS answers NXDOMAIN for {domain}. The name is not delegated (unregistered, expired or suspended), so no other DNS check can run.',
      'DNS, {domain} için NXDOMAIN döndürüyor. Alan adı yetkilendirilmemiş (kayıtsız, süresi dolmuş ya da askıya alınmış); bu yüzden diğer DNS kontrolleri yapılamıyor.']],
  ['domain.dangling-cname', ['Dangling CNAME', 'Sahipsiz CNAME'],
    ['{domain} is an alias (CNAME) of {target}, which does not exist (chain: {chain}). A dangling CNAME can be a subdomain-takeover risk: remove the record or recreate the target.',
      '{domain}, var olmayan {target} adının takma adı (CNAME) (zincir: {chain}). Sahipsiz bir CNAME alt alan adı ele geçirme riski taşıyabilir: kaydı kaldırın ya da hedefi yeniden oluşturun.']],
  ['domain.name-missing', ['Name does not exist', 'Ad mevcut değil'],
    ['{domain} does not exist in the {zone} zone (no such record), so no other DNS check can run.',
      '{domain}, {zone} bölgesinde mevcut değil (böyle bir kayıt yok); bu yüzden diğer DNS kontrolleri yapılamıyor.']],

  ['soa.ok', ['SOA record found', 'SOA kaydı bulundu'],
    ['Primary name server {mname}, contact {email}, serial {serial}.',
      'Birincil ad sunucusu {mname}, iletişim {email}, seri no {serial}.']],
  ['soa.error', ['SOA lookup failed', 'SOA sorgusu başarısız'],
    ['The SOA query failed ({error}). Results below may be incomplete.',
      'SOA sorgusu başarısız oldu ({error}). Aşağıdaki sonuçlar eksik olabilir.']],
  ['soa.not-apex', ['Not a zone apex', 'Bölge (zone) kökü değil'],
    ['{domain} is not the apex of a DNS zone; it belongs to the zone {zone}. Run the check on {zone} for NS, SOA and DNSSEC results.',
      '{domain} bir DNS bölgesinin kökü değil; {zone} bölgesine ait. NS, SOA ve DNSSEC sonuçları için kontrolü {zone} üzerinde çalıştırın.']],
  ['soa.retry', ['SOA retry is not below refresh', 'SOA retry değeri refresh değerinden küçük değil'],
    ['retry ({retry}s) should be lower than refresh ({refresh}s) so secondaries retry a failed transfer sooner than the next regular refresh.',
      'İkincil sunucuların başarısız aktarımı bir sonraki yenilemeden önce tekrar denemesi için retry ({retry} sn), refresh değerinden ({refresh} sn) küçük olmalı.']],
  ['soa.expire', ['SOA expire is short', 'SOA expire değeri kısa'],
    ['expire is {expire}s (under one week). Secondaries stop answering if they cannot reach the primary for that long; 2–4 weeks is usual.',
      'expire {expire} sn (bir haftadan az). İkincil sunucular birincile bu süre ulaşamazsa yanıt vermeyi keser; genellikle 2–4 hafta kullanılır.']],
  ['soa.minimum', ['Long negative-caching TTL', 'Uzun negatif önbellek süresi'],
    ['The SOA minimum (negative caching TTL) is {minimum}s. Newly created names may stay "not found" in resolvers for that long; 1–3 hours is typical (RFC 2308).',
      'SOA minimum (negatif önbellek TTL) değeri {minimum} sn. Yeni eklenen kayıtlar çözümleyicilerde bu süre boyunca "bulunamadı" görünebilir; genellikle 1–3 saat önerilir (RFC 2308).']],

  ['ns.ok', ['Name servers: {count}', 'Ad sunucuları: {count}'],
    ['Delegated to: {hosts}.', 'Yetkili ad sunucuları: {hosts}.']],
  ['ns.single', ['Only one name server', 'Yalnızca bir ad sunucusu'],
    ['The zone is served by a single name server ({host}). RFC 2182 asks for at least two, on different networks, so the domain survives an outage.',
      'Bölge tek bir ad sunucusundan ({host}) yayınlanıyor. RFC 2182, bir kesintide alan adının çalışmaya devam etmesi için farklı ağlarda en az iki sunucu ister.']],
  ['ns.none', ['No NS records', 'NS kaydı yok'],
    ['No NS records were returned for {domain}.', '{domain} için NS kaydı dönmedi.']],
  ['ns.error', ['NS lookup failed', 'NS sorgusu başarısız'],
    ['The NS query failed ({error}).', 'NS sorgusu başarısız oldu ({error}).']],
  ['ns.unresolvable', ['Name servers without an address', 'Adresi çözülemeyen ad sunucuları'],
    ['These name servers have no A/AAAA record: {hosts}. Resolvers cannot reach them (lame delegation).',
      'Bu ad sunucularının A/AAAA kaydı yok: {hosts}. Çözümleyiciler bu sunuculara ulaşamaz (hatalı yetkilendirme).']],
  ['ns.private-ip', ['Name servers with private IPs', 'Özel (private) IP’li ad sunucuları'],
    ['These name servers resolve to private addresses and are unreachable from the Internet: {hosts}.',
      'Bu ad sunucuları özel IP adreslerine çözülüyor ve İnternet’ten erişilemez: {hosts}.']],
  ['ns.same-subnet', ['All name servers in one network', 'Tüm ad sunucuları aynı ağda'],
    ['Every name server address is inside {subnet}. A single network or routing problem would take the whole domain offline.',
      'Tüm ad sunucusu adresleri {subnet} içinde. Tek bir ağ ya da yönlendirme sorunu tüm alan adını erişilemez hale getirir.']],
  ['ns.diversity', ['Name servers on {count} networks', 'Ad sunucuları {count} farklı ağda'],
    ['Name server addresses are spread over {count} different /24 (IPv4) or /48 (IPv6) networks.',
      'Ad sunucusu adresleri {count} farklı /24 (IPv4) veya /48 (IPv6) ağına dağılmış.']],
  ['ns.single-provider', ['All name servers at one provider', 'Tüm ad sunucuları tek sağlayıcıda'],
    ['All name servers belong to {provider}. That is common for managed DNS, but an outage at that provider affects every name server.',
      'Tüm ad sunucuları {provider} alan adı altında. Yönetilen DNS için olağan, ancak sağlayıcıdaki bir kesinti tüm ad sunucularını etkiler.']],
  ['ns.no-ipv6', ['No IPv6 name servers', 'IPv6 ad sunucusu yok'],
    ['None of the name servers has an AAAA record; IPv6-only resolvers cannot reach the zone directly.',
      'Ad sunucularının hiçbirinde AAAA kaydı yok; yalnızca IPv6 kullanan çözümleyiciler bölgeye doğrudan ulaşamaz.']],
  ['ns.rdap-mismatch', ['Registry and DNS name servers differ', 'Kayıt kuruluşu ve DNS ad sunucuları farklı'],
    ['The registry (parent) lists {registry} but the zone itself answers {dns}. Align the delegation at the registrar with the NS records in the zone.',
      'Kayıt kuruluşunda (üst bölge) {registry} tanımlı, ancak bölgenin kendisi {dns} döndürüyor. Kayıt firmasındaki yetkilendirmeyi bölgedeki NS kayıtlarıyla eşitleyin.']],

  ['apex.ok', ['Domain resolves', 'Alan adı çözülüyor'],
    ['IPv4: {ipv4}; IPv6: {ipv6}.', 'IPv4: {ipv4}; IPv6: {ipv6}.']],
  ['apex.cname', ['Name is an alias (CNAME)', 'Ad bir takma addır (CNAME)'],
    ['{domain} is an alias of {target}; the MX, TXT, CAA … results below are those of the target.',
      '{domain}, {target} adresinin takma adıdır; aşağıdaki MX, TXT, CAA … sonuçları hedefe aittir.']],
  ['apex.no-address', ['No address on the bare domain', 'Çıplak alan adında adres yok'],
    ['{domain} has no A/AAAA record, so https://{domain} will not load (subdomains may still work).',
      '{domain} için A/AAAA kaydı yok; https://{domain} açılmaz (alt alan adları yine de çalışabilir).']],
  ['apex.private-ip', ['Domain points to private IPs', 'Alan adı özel IP’lere işaret ediyor'],
    ['Public DNS returns private addresses: {ips}. They are unreachable from the Internet and leak internal addressing.',
      'Genel DNS özel adresler döndürüyor: {ips}. Bu adreslere İnternet’ten erişilemez ve iç ağ yapısı açığa çıkar.']],
  ['ipv6.present', ['IPv6 enabled', 'IPv6 etkin'],
    ['AAAA records: {ipv6}.', 'AAAA kayıtları: {ipv6}.']],
  ['ipv6.missing', ['No IPv6 address', 'IPv6 adresi yok'],
    ['{domain} has no AAAA record; IPv6-only clients reach it only through NAT64.',
      '{domain} için AAAA kaydı yok; yalnızca IPv6 kullanan istemciler siteye ancak NAT64 üzerinden ulaşabilir.']],
  ['https-rr.present', ['HTTPS record published', 'HTTPS kaydı yayınlanmış'],
    ['An HTTPS (SVCB) record advertises ALPN {alpn}; Encrypted Client Hello: {ech}.',
      'HTTPS (SVCB) kaydı ALPN {alpn} bildiriyor; Encrypted Client Hello (ECH): {ech}.']],
  ['wildcard.none', ['No wildcard DNS', 'Joker (wildcard) DNS yok'],
    ['Random subdomains do not resolve, so subdomain discovery results are reliable.',
      'Rastgele alt alan adları çözülmüyor; alt alan adı keşfi sonuçları güvenilir.']],
  ['wildcard.present', ['Wildcard DNS is active', 'Joker (wildcard) DNS etkin'],
    ['Any subdomain resolves (to {values}). Typos and non-existent names still reach a server, and brute-force subdomain discovery cannot tell real names apart.',
      'Her alt alan adı çözülüyor ({values}). Yanlış yazılmış ve var olmayan adlar da bir sunucuya gider; kaba kuvvet (brute force) keşfi gerçek adları ayırt edemez.']],
  ['wildcard.error', ['Wildcard test failed', 'Joker DNS testi başarısız'],
    ['Could not test for wildcard DNS ({error}).', 'Joker DNS testi yapılamadı ({error}).']],

  ['mx.ok', ['Mail servers: {count}', 'E-posta sunucuları: {count}'],
    ['MX: {hosts}.', 'MX: {hosts}.']],
  ['mx.none', ['No MX records', 'MX kaydı yok'],
    ['{domain} publishes no MX; senders fall back to its A/AAAA record. If the domain sends no email, publish a null MX ("0 .") and "v=spf1 -all".',
      '{domain} MX kaydı yayınlamıyor; gönderenler A/AAAA kaydına yönelir. Alan adı e-posta kullanmıyorsa null MX ("0 .") ve "v=spf1 -all" yayınlayın.']],
  ['mx.null', ['Null MX: accepts no email', 'Null MX: e-posta kabul etmiyor'],
    ['{domain} publishes a null MX (RFC 7505): it explicitly accepts no email.',
      '{domain} null MX yayınlıyor (RFC 7505): açıkça hiçbir e-posta kabul etmiyor.']],
  ['mx.null-mixed', ['Null MX mixed with other MX records', 'Null MX başka MX kayıtlarıyla birlikte'],
    ['A null MX ("0 .") must be the only MX record (RFC 7505). Remove it or the other records.',
      'Null MX ("0 .") tek MX kaydı olmalıdır (RFC 7505). Ya onu ya da diğer kayıtları kaldırın.']],
  ['mx.error', ['MX lookup failed', 'MX sorgusu başarısız'],
    ['The MX query failed ({error}).', 'MX sorgusu başarısız oldu ({error}).']],
  ['mx.cname', ['MX points to a CNAME', 'MX bir CNAME’e işaret ediyor'],
    ['These MX targets are aliases: {hosts}. RFC 2181 §10.3 and RFC 5321 forbid MX → CNAME; some senders will refuse to deliver.',
      'Bu MX hedefleri takma ad (CNAME): {hosts}. RFC 2181 §10.3 ve RFC 5321, MX → CNAME kullanımını yasaklar; bazı gönderenler teslimatı reddeder.']],
  ['mx.unresolvable', ['MX host does not resolve', 'MX sunucusu çözülemiyor'],
    ['These mail servers have no A/AAAA record: {hosts}. Mail to them cannot be delivered.',
      'Bu e-posta sunucularının A/AAAA kaydı yok: {hosts}. Bunlara e-posta teslim edilemez.']],
  ['mx.ip-literal', ['MX points to an IP address', 'MX bir IP adresine işaret ediyor'],
    ['MX targets must be host names, not IP addresses: {hosts}.', 'MX hedefleri IP adresi değil, ana makine adı olmalıdır: {hosts}.']],
  ['mx.private-ip', ['MX host has a private IP', 'MX sunucusunun IP’si özel'],
    ['These mail servers resolve only to private addresses: {hosts}. External senders cannot reach them.',
      'Bu e-posta sunucuları yalnızca özel adreslere çözülüyor: {hosts}. Dışarıdan gönderenler ulaşamaz.']],

  ['spf.present', ['SPF record found', 'SPF kaydı bulundu'],
    ['{record}', '{record}']],
  ['spf.missing', ['No SPF record', 'SPF kaydı yok'],
    ['{domain} has no SPF record, so anyone can send email claiming to be from it. If the domain sends no mail, publish "v=spf1 -all".',
      '{domain} için SPF kaydı yok; herkes bu alan adı adına e-posta gönderebilir. Alan adı e-posta göndermiyorsa "v=spf1 -all" yayınlayın.']],
  ['spf.multiple', ['Multiple SPF records', 'Birden fazla SPF kaydı'],
    ['{count} TXT records start with "v=spf1". RFC 7208 treats this as a permanent error: receivers ignore SPF entirely. Merge them into one record.',
      '{count} TXT kaydı "v=spf1" ile başlıyor. RFC 7208’e göre bu kalıcı hatadır (permerror): alıcılar SPF’i tamamen yok sayar. Kayıtları tek kayıtta birleştirin.']],
  ['spf.error', ['SPF lookup failed', 'SPF sorgusu başarısız'],
    ['The TXT query failed ({error}).', 'TXT sorgusu başarısız oldu ({error}).']],
  ['spf.syntax', ['SPF syntax error', 'SPF sözdizimi hatası'],
    ['Invalid terms: {errors}. Receivers return "permerror" and ignore the policy.',
      'Geçersiz ifadeler: {errors}. Alıcılar "permerror" döndürür ve politikayı yok sayar.']],
  ['spf.all-fail', ['SPF ends with -all', 'SPF -all ile bitiyor'],
    ['Mail from unlisted servers fails SPF ({term}). This is the strictest setting.',
      'Listede olmayan sunuculardan gelen e-posta SPF’ten kalır ({term}). En sıkı ayar budur.']],
  ['spf.all-softfail', ['SPF ends with ~all (soft fail)', 'SPF ~all ile bitiyor (soft fail)'],
    ['Unlisted senders soft-fail ({term}): usually accepted but marked. Fine together with an enforcing DMARC policy; use -all once all senders are listed.',
      'Listede olmayan gönderenler "soft fail" alır ({term}): genellikle kabul edilir ama işaretlenir. Zorlayıcı bir DMARC politikasıyla birlikte uygundur; tüm gönderenler eklendiğinde -all kullanın.']],
  ['spf.all-neutral', ['SPF ends with ?all (neutral)', 'SPF ?all ile bitiyor (neutral)'],
    ['"{term}" makes no statement about other senders, so SPF gives no spoofing protection.',
      '"{term}" diğer gönderenler hakkında hiçbir şey söylemez; SPF sahteciliğe karşı koruma sağlamaz.']],
  ['spf.all-pass', ['SPF allows everyone (+all)', 'SPF herkese izin veriyor (+all)'],
    ['"{term}" authorizes every server on the Internet to send as this domain. Replace it with ~all or -all.',
      '"{term}" İnternet’teki tüm sunuculara bu alan adı adına gönderim yetkisi verir. ~all veya -all ile değiştirin.']],
  ['spf.all-missing', ['SPF has no "all" mechanism', 'SPF’te "all" mekanizması yok'],
    ['Without a final all (and no redirect) the default result is neutral, so unlisted senders are not rejected. End the record with ~all or -all.',
      'Sonda all (ve redirect) yoksa varsayılan sonuç "neutral" olur; listede olmayan gönderenler reddedilmez. Kaydı ~all veya -all ile bitirin.']],
  ['spf.redirect-ignored', ['SPF redirect is ignored', 'SPF redirect yok sayılıyor'],
    ['The record has an "all" mechanism, so {term} is never used (RFC 7208 §6.1).',
      'Kayıtta "all" mekanizması olduğu için {term} hiçbir zaman kullanılmaz (RFC 7208 §6.1).']],
  ['spf.after-all', ['Terms after "all" are ignored', '"all" sonrasındaki ifadeler yok sayılıyor'],
    ['Evaluation stops at "all", so these terms never apply: {terms}.', 'Değerlendirme "all" ile durur; bu ifadeler hiç uygulanmaz: {terms}.']],
  ['spf.ptr', ['SPF uses the deprecated ptr mechanism', 'SPF eski (deprecated) ptr mekanizmasını kullanıyor'],
    ['"{term}" is slow, unreliable and "SHOULD NOT be used" (RFC 7208 §5.5); some receivers skip it. Use ip4/ip6/include instead.',
      '"{term}" yavaş ve güvenilmezdir; RFC 7208 §5.5’e göre kullanılmamalıdır ve bazı alıcılar atlar. Yerine ip4/ip6/include kullanın.']],
  ['spf.too-long', ['SPF record is long', 'SPF kaydı uzun'],
    ['The record is {length} characters. Keep SPF under about {max} characters so the DNS answer fits in a single UDP packet (RFC 7208 §3.4).',
      'Kayıt {length} karakter. DNS yanıtının tek UDP paketine sığması için SPF’i yaklaşık {max} karakterin altında tutun (RFC 7208 §3.4).']],
  ['spf.broad', ['SPF authorizes huge IP ranges', 'SPF çok geniş IP aralıklarına izin veriyor'],
    ['These terms allow very large address blocks: {terms}. Anyone using addresses in them can pass SPF.',
      'Bu ifadeler çok büyük adres bloklarına izin veriyor: {terms}. Bu bloklardaki adresleri kullanan herkes SPF’ten geçebilir.']],
  ['spf.null-mx', ['Null MX without "v=spf1 -all"', 'Null MX var ama "v=spf1 -all" yok'],
    ['The domain accepts no email (null MX); it probably sends none either, so "v=spf1 -all" is the safest SPF.',
      'Alan adı e-posta kabul etmiyor (null MX); büyük olasılıkla göndermiyor da. En güvenli SPF "v=spf1 -all" olur.']],
  ['spf.lookups-ok', ['SPF uses {count} of {limit} DNS lookups', 'SPF {limit} DNS sorgusundan {count} tanesini kullanıyor'],
    ['include, a, mx, ptr, exists and redirect terms (recursively) need {count} DNS lookups; the limit is {limit} (RFC 7208 §4.6.4).',
      'include, a, mx, ptr, exists ve redirect ifadeleri (iç içe) {count} DNS sorgusu gerektiriyor; sınır {limit} (RFC 7208 §4.6.4).']],
  ['spf.lookups-high', ['SPF is close to the lookup limit', 'SPF sorgu sınırına yakın'],
    ['{count} of {limit} DNS lookups are used. One more include (or a provider adding one) will break SPF.',
      '{limit} DNS sorgusunun {count} tanesi kullanılıyor. Bir include daha (ya da sağlayıcının eklediği bir tane) SPF’i bozar.']],
  ['spf.lookups-exceeded', ['SPF exceeds the 10-lookup limit', 'SPF 10 sorgu sınırını aşıyor'],
    ['Evaluating the record needs {count} DNS lookups (limit {limit}). Receivers return "permerror" and SPF fails for all your mail. Flatten includes or remove unused ones.',
      'Kaydın değerlendirilmesi {count} DNS sorgusu gerektiriyor (sınır {limit}). Alıcılar "permerror" döndürür ve tüm e-postalarınız SPF’ten kalır. include’ları düzleştirin veya kullanılmayanları kaldırın.']],
  ['spf.void', ['Too many void SPF lookups', 'Çok fazla boş (void) SPF sorgusu'],
    ['{count} lookups return no data (limit {limit}, RFC 7208 §4.6.4); receivers may return "permerror". Remove references to names that do not exist.',
      '{count} sorgu boş yanıt döndürüyor (sınır {limit}, RFC 7208 §4.6.4); alıcılar "permerror" döndürebilir. Var olmayan adlara yapılan atıfları kaldırın.']],
  ['spf.include-error', ['Broken include/redirect in SPF', 'SPF’te hatalı include/redirect'],
    ['Problems in referenced records: {details}. A missing or duplicated SPF record in an include target is a permanent error.',
      'Başvurulan kayıtlarda sorun var: {details}. include hedefinde SPF kaydının olmaması veya birden fazla olması kalıcı hatadır.']],
  ['spf.dns-error', ['SPF lookups failed', 'SPF sorguları başarısız'],
    ['Some lookups failed while expanding SPF: {details}. Receivers would return "temperror" for these.',
      'SPF açılırken bazı sorgular başarısız oldu: {details}. Alıcılar bunlar için "temperror" döndürür.']],

  ['dmarc.missing', ['No DMARC record', 'DMARC kaydı yok'],
    ['_dmarc.{domain} has no DMARC record. Without DMARC, receivers do not act on SPF/DKIM failures and you get no reports. Start with "v=DMARC1; p=none; rua=mailto:…".',
      '_dmarc.{domain} için DMARC kaydı yok. DMARC olmadan alıcılar SPF/DKIM hatalarında işlem yapmaz ve rapor almazsınız. "v=DMARC1; p=none; rua=mailto:…" ile başlayın.']],
  ['dmarc.multiple', ['Multiple DMARC records', 'Birden fazla DMARC kaydı'],
    ['{count} DMARC records at _dmarc.{domain}; receivers then ignore DMARC (RFC 7489 §6.6.3). Keep exactly one.',
      '_dmarc.{domain} altında {count} DMARC kaydı var; bu durumda alıcılar DMARC’ı yok sayar (RFC 7489 §6.6.3). Yalnızca bir kayıt bırakın.']],
  ['dmarc.error', ['DMARC lookup failed', 'DMARC sorgusu başarısız'],
    ['The TXT query for _dmarc failed ({error}).', '_dmarc TXT sorgusu başarısız oldu ({error}).']],
  ['dmarc.invalid', ['Invalid DMARC record', 'Geçersiz DMARC kaydı'],
    ['Problems: {errors}. A DMARC record without a valid p= tag is ignored.', 'Sorunlar: {errors}. Geçerli p= etiketi olmayan DMARC kaydı yok sayılır.']],
  ['dmarc.inherited', ['DMARC inherited from {org}', 'DMARC {org} alan adından devralınıyor'],
    ['No record for this name itself; the organizational domain\'s policy applies (subdomain policy: {policy}).',
      'Bu adın kendi kaydı yok; kurumsal alan adının politikası uygulanır (alt alan adı politikası: {policy}).']],
  ['dmarc.policy-none', ['DMARC policy is "none" (monitor only)', 'DMARC politikası "none" (yalnızca izleme)'],
    ['Failing mail is still delivered. Once reports show all legitimate senders pass, move to p=quarantine and then p=reject.',
      'Doğrulamadan geçemeyen e-postalar yine de teslim edilir. Raporlar tüm meşru gönderenlerin geçtiğini gösterince p=quarantine, ardından p=reject’e geçin.']],
  ['dmarc.policy-quarantine', ['DMARC policy: quarantine', 'DMARC politikası: quarantine'],
    ['Failing mail goes to spam. {record}', 'Doğrulamadan geçemeyen e-postalar spam klasörüne gider. {record}']],
  ['dmarc.policy-reject', ['DMARC policy: reject', 'DMARC politikası: reject'],
    ['Failing mail is rejected — the strongest protection. {record}', 'Doğrulamadan geçemeyen e-postalar reddedilir — en güçlü koruma. {record}']],
  ['dmarc.pct', ['DMARC applies to {pct}% of mail', 'DMARC e-postaların %{pct} kadarına uygulanıyor'],
    ['pct={pct}: the policy covers only part of the failing mail. Raise it to 100 when ready.',
      'pct={pct}: politika başarısız e-postaların yalnızca bir kısmını kapsıyor. Hazır olduğunuzda 100’e çıkarın.']],
  ['dmarc.sp-none', ['Subdomains are not protected', 'Alt alan adları korunmuyor'],
    ['p={policy} but sp=none: spoofed mail from subdomains is still delivered.', 'p={policy} ancak sp=none: alt alan adlarından sahte e-postalar yine teslim edilir.']],
  ['dmarc.rua-missing', ['No DMARC aggregate reports', 'DMARC toplu raporu yok'],
    ['Without rua= you receive no reports about who sends mail as your domain.', 'rua= olmadan alan adınız adına kimlerin e-posta gönderdiğine dair rapor almazsınız.']],
  ['dmarc.rua-unauthorized', ['Report receiver has not authorized reports', 'Rapor alıcısı yetkilendirme yapmamış'],
    ['These external report domains publish no <domain>._report._dmarc authorization record, so reports may not be sent to them: {targets} (RFC 7489 §7.1).',
      'Bu harici rapor alan adları <alanadı>._report._dmarc yetkilendirme kaydı yayınlamıyor; raporlar gönderilmeyebilir: {targets} (RFC 7489 §7.1).']],

  ['dkim.found', ['DKIM keys found', 'DKIM anahtarları bulundu'],
    ['{count} selector(s) publish a key: {selectors}.', '{count} seçici (selector) anahtar yayınlıyor: {selectors}.']],
  ['dkim.none', ['No DKIM key at common selectors', 'Yaygın seçicilerde DKIM anahtarı yok'],
    ['None of the {count} common selectors has a key. Selectors are arbitrary names, so DKIM may still be set up under another selector.',
      '{count} yaygın seçicinin hiçbirinde anahtar yok. Seçici adları serbestçe belirlendiği için DKIM başka bir seçiciyle kurulu olabilir.']],
  ['dkim.error', ['DKIM lookups failed', 'DKIM sorguları başarısız'],
    ['Could not query the DKIM selectors ({error}).', 'DKIM seçicileri sorgulanamadı ({error}).']],
  ['dkim.weak', ['Weak DKIM key', 'Zayıf DKIM anahtarı'],
    ['RSA keys under 1024 bits must not be used (RFC 8301): {selectors}.', '1024 bitten küçük RSA anahtarları kullanılmamalıdır (RFC 8301): {selectors}.']],
  ['dkim.1024', ['1024-bit DKIM key', '1024 bit DKIM anahtarı'],
    ['These keys are shorter than the recommended 2048 bits: {selectors}.', 'Bu anahtarlar önerilen 2048 bitten kısa: {selectors}.']],
  ['dkim.revoked', ['Revoked DKIM key', 'İptal edilmiş DKIM anahtarı'],
    ['These selectors publish an empty key (p=), i.e. revoked: {selectors}.', 'Bu seçiciler boş anahtar (p=) yayınlıyor, yani iptal edilmiş: {selectors}.']],
  ['dkim.wildcard', ['Wildcard DKIM record', 'Joker (wildcard) DKIM kaydı'],
    ['Every selector answers with the same record ({record}); revoked: {revoked}. An empty "p=" wildcard is the recommended setup for domains that send no email.',
      'Her seçici aynı kaydı döndürüyor ({record}); iptal edilmiş: {revoked}. Boş "p=" içeren joker kayıt, e-posta göndermeyen alan adları için önerilen ayardır.']],
  ['dkim.testing', ['DKIM in test mode', 'DKIM test modunda'],
    ['t=y is set for {selectors}; receivers may treat signatures as unverified.', '{selectors} için t=y ayarlı; alıcılar imzaları doğrulanmamış sayabilir.']],

  ['mta-sts.present', ['MTA-STS enabled', 'MTA-STS etkin'],
    ['_mta-sts TXT record found (id={id}). The policy itself lives at https://mta-sts.<domain>/.well-known/mta-sts.txt.',
      '_mta-sts TXT kaydı bulundu (id={id}). Politikanın kendisi https://mta-sts.<alanadı>/.well-known/mta-sts.txt adresindedir.']],
  ['mta-sts.missing', ['No MTA-STS', 'MTA-STS yok'],
    ['MTA-STS (RFC 8461) forces TLS for mail sent to your servers and prevents downgrade attacks.',
      'MTA-STS (RFC 8461), sunucularınıza gelen e-postada TLS’i zorunlu kılar ve düşürme (downgrade) saldırılarını önler.']],
  ['mta-sts.invalid', ['Invalid MTA-STS record', 'Geçersiz MTA-STS kaydı'],
    ['There must be exactly one "v=STSv1; id=…" record ({count} found or id missing).', 'Tam olarak bir adet "v=STSv1; id=…" kaydı olmalıdır ({count} bulundu ya da id eksik).']],
  ['tls-rpt.present', ['TLS reporting enabled', 'TLS raporlama etkin'],
    ['TLS-RPT reports go to {rua}.', 'TLS-RPT raporları {rua} adresine gider.']],
  ['tls-rpt.missing', ['No TLS reporting', 'TLS raporlama yok'],
    ['A _smtp._tls record (RFC 8460) lets senders report TLS delivery problems to you.',
      '_smtp._tls kaydı (RFC 8460), gönderenlerin TLS teslimat sorunlarını size bildirmesini sağlar.']],
  ['bimi.present', ['BIMI record found', 'BIMI kaydı bulundu'],
    ['Logo: {logo}.', 'Logo: {logo}.']],
  ['bimi.dmarc-weak', ['BIMI needs an enforcing DMARC policy', 'BIMI zorlayıcı DMARC politikası gerektirir'],
    ['Mailbox providers show BIMI logos only with p=quarantine or p=reject (current: {policy}).',
      'E-posta sağlayıcıları BIMI logosunu yalnızca p=quarantine veya p=reject ile gösterir (mevcut: {policy}).']],

  ['caa.present', ['CAA restricts certificate issuance', 'CAA sertifika verilmesini kısıtlıyor'],
    ['Found at {foundAt}. Allowed CAs: {issuers}; for wildcard certificates: {wildIssuers}. Violation reports: {iodef}.',
      '{foundAt} üzerinde bulundu. İzin verilen sertifika otoriteleri: {issuers}; joker (wildcard) sertifikalar için: {wildIssuers}. İhlal bildirimleri: {iodef}.']],
  ['caa.missing', ['No CAA record', 'CAA kaydı yok'],
    ['Any certificate authority may issue certificates for {domain}. A CAA record (e.g. 0 issue "letsencrypt.org") limits issuance to the CAs you use.',
      'Herhangi bir sertifika otoritesi {domain} için sertifika verebilir. CAA kaydı (ör. 0 issue "letsencrypt.org") sertifika verilmesini kullandığınız otoritelerle sınırlar.']],
  ['caa.error', ['CAA lookup failed', 'CAA sorgusu başarısız'],
    ['CAs must refuse to issue when the CAA lookup fails ({error}).', 'CAA sorgusu başarısız olduğunda sertifika otoriteleri sertifika vermeyi reddetmelidir ({error}).']],
  ['caa.deny-all', ['CAA forbids all certificates', 'CAA tüm sertifikaları yasaklıyor'],
    ['The CAA set at {foundAt} names no valid CA (its issue values are empty ";" or malformed): no CA may issue certificates.',
      '{foundAt} üzerindeki CAA kayıtları geçerli bir otorite içermiyor (issue değerleri boş ";" ya da hatalı): hiçbir otorite sertifika veremez.']],
  ['caa.invalid', ['Malformed CAA values', 'Hatalı CAA değerleri'],
    ['These values do not follow RFC 8659 and match no CA: {values}.', 'Bu değerler RFC 8659’a uymuyor ve hiçbir otoriteyle eşleşmiyor: {values}.']],
  ['caa.critical-unknown', ['Unknown critical CAA tag', 'Bilinmeyen kritik CAA etiketi'],
    ['Critical flag set on unknown tags ({tags}): every CA must refuse to issue.', 'Bilinmeyen etiketlerde ({tags}) kritik bayrağı ayarlı: tüm otoriteler sertifika vermeyi reddetmelidir.']],
  ['caa.distrusted', ['CAA allows a distrusted CA', 'CAA güvenilmeyen bir otoriteye izin veriyor'],
    ['{issuers} is no longer trusted by browsers (since {since}); its certificates will not work. Update the CAA record.',
      '{issuers} tarayıcılar tarafından artık güvenilir kabul edilmiyor ({since} yılından beri); sertifikaları çalışmaz. CAA kaydını güncelleyin.']],
  ['caa.cert-allowed', ['CAA allows this certificate\'s CA', 'CAA bu sertifikanın otoritesine izin veriyor'],
    ['{issuer} may issue ({property}).', '{issuer} sertifika verebilir ({property}).']],
  ['caa.cert-denied', ['CAA does not allow this certificate\'s CA', 'CAA bu sertifikanın otoritesine izin vermiyor'],
    ['{issuer} is not in the {property} list ({authorized}); renewals from this CA will fail.',
      '{issuer}, {property} listesinde değil ({authorized}); bu otoriteden yenileme başarısız olur.']],
  ['caa.cert-blocked', ['CAA forbids this kind of certificate', 'CAA bu tür sertifikayı yasaklıyor'],
    ['This CAA set lets no CA issue such a certificate, {issuer} included (see the CAA findings above); renewals from this CA will fail.',
      'Bu CAA kümesi hiçbir otoritenin bu tür bir sertifika vermesine izin vermiyor, {issuer} de dahil (yukarıdaki CAA bulgularına bakın); bu otoriteden yenileme başarısız olur.']],
  ['caa.cert-unknown', ['CA not recognised for CAA', 'Otorite CAA için tanınmadı'],
    ['Could not map "{issuer}" to a CAA identifier; check the CA\'s documentation.', '"{issuer}" bir CAA tanımlayıcısıyla eşleştirilemedi; otoritenin belgelerine bakın.']],
  ['caa.reason.none', ['No CAA records: any CA may issue', 'CAA kaydı yok: her otorite sertifika verebilir']],
  ['caa.reason.critical-unknown', ['An unknown critical CAA tag blocks all issuance', 'Bilinmeyen kritik CAA etiketi tüm sertifikaları engelliyor']],
  ['caa.reason.no-issue-property', ['No issue property applies: any CA may issue', 'Uygulanan issue özelliği yok: her otorite sertifika verebilir']],
  ['caa.reason.unknown-issuer', ['The CA could not be identified', 'Sertifika otoritesi belirlenemedi']],
  ['caa.reason.allowed', ['The CA is authorized', 'Otorite yetkili']],
  ['caa.reason.deny-all', ['CAA forbids every CA', 'CAA tüm otoriteleri yasaklıyor']],
  ['caa.reason.not-listed', ['The CA is not in the CAA list', 'Otorite CAA listesinde yok']],

  ['dnssec.ok', ['DNSSEC signed and validated', 'DNSSEC imzalı ve doğrulanıyor'],
    ['DS at the parent matches the zone keys and validating resolvers set the AD flag. Algorithms: {algorithms}.',
      'Üst bölgedeki DS kaydı bölge anahtarlarıyla eşleşiyor ve doğrulayan çözümleyiciler AD bayrağını ayarlıyor. Algoritmalar: {algorithms}.']],
  ['dnssec.unsigned', ['DNSSEC not enabled', 'DNSSEC etkin değil'],
    ['{domain} is not signed. DNSSEC protects answers from forgery (cache poisoning); enable it at your DNS provider and add the DS record at the registrar.',
      '{domain} imzalı değil. DNSSEC yanıtları sahteciliğe (önbellek zehirlemesi) karşı korur; DNS sağlayıcınızda etkinleştirip DS kaydını kayıt firmasına ekleyin.']],
  ['dnssec.broken', ['DNSSEC is broken', 'DNSSEC bozuk'],
    ['Validating resolvers return SERVFAIL, but the data is there when validation is disabled (CD=1). Users of Google, Cloudflare, Quad9… cannot resolve the domain. Extended errors: {ede}.',
      'Doğrulayan çözümleyiciler SERVFAIL döndürüyor, ancak doğrulama kapatıldığında (CD=1) veriler geliyor. Google, Cloudflare, Quad9… kullananlar alan adını çözemez. Genişletilmiş hatalar: {ede}.']],
  ['dnssec.no-ds', ['Signed zone without DS at the parent', 'İmzalı bölge, üst bölgede DS yok'],
    ['The zone publishes DNSKEY records but the parent has no DS record, so nobody validates it. Add the DS record at your registrar.',
      'Bölge DNSKEY kayıtları yayınlıyor, ancak üst bölgede DS kaydı yok; bu yüzden kimse doğrulama yapmıyor. DS kaydını kayıt firmanıza ekleyin.']],
  ['dnssec.ds-no-dnskey', ['DS at the parent but no DNSKEY', 'Üst bölgede DS var ama DNSKEY yok'],
    ['The parent publishes DS (key tags {tags}) but the zone has no DNSKEY: validation fails. Re-sign the zone or remove the DS record.',
      'Üst bölge DS yayınlıyor (anahtar etiketleri {tags}) ancak bölgede DNSKEY yok: doğrulama başarısız olur. Bölgeyi yeniden imzalayın veya DS kaydını kaldırın.']],
  ['dnssec.ds-mismatch', ['DS does not match any DNSKEY', 'DS hiçbir DNSKEY ile eşleşmiyor'],
    ['DS key tags {dsTags} vs DNSKEY key tags {keyTags}. After a key rollover the DS at the registrar must be updated.',
      'DS anahtar etiketleri {dsTags}, DNSKEY anahtar etiketleri {keyTags}. Anahtar değişiminden sonra kayıt firmasındaki DS güncellenmelidir.']],
  ['dnssec.not-validated', ['DNSSEC present but not validated', 'DNSSEC var ama doğrulanmıyor'],
    ['DS and DNSKEY exist but the resolver did not set the AD flag. Check the signatures (expired RRSIGs?).',
      'DS ve DNSKEY mevcut, ancak çözümleyici AD bayrağını ayarlamadı. İmzaları kontrol edin (RRSIG süresi dolmuş olabilir).']],
  ['dnssec.algorithm-deprecated', ['Deprecated DNSSEC algorithm', 'Eskimiş DNSSEC algoritması'],
    ['{algorithms} should no longer be used (RFC 8624). Roll over to ECDSAP256SHA256 (13) or ED25519 (15).',
      '{algorithms} artık kullanılmamalıdır (RFC 8624). ECDSAP256SHA256 (13) veya ED25519’a (15) geçin.']],
  ['dnssec.ds-sha1', ['DS uses SHA-1 only', 'DS yalnızca SHA-1 kullanıyor'],
    ['All DS records use the {digest} digest; publish a SHA-256 DS instead (RFC 8624).', 'Tüm DS kayıtları {digest} özetini kullanıyor; yerine SHA-256 DS yayınlayın (RFC 8624).']],
  ['dnssec.error', ['DNSSEC lookups failed', 'DNSSEC sorguları başarısız'],
    ['DS/DNSKEY queries failed ({error}).', 'DS/DNSKEY sorguları başarısız oldu ({error}).']],

  ['rdap.expiry-ok', ['Registration valid for {days} more days', 'Kayıt {days} gün daha geçerli'],
    ['Expires on {date} (registrar: {registrar}).', '{date} tarihinde sona eriyor (kayıt firması: {registrar}).']],
  ['rdap.expiring-soon', ['Domain expires in {days} days', 'Alan adının süresi {days} gün içinde doluyor'],
    ['Expires on {date}. Renew it (or enable auto-renew) at {registrar}.', '{date} tarihinde sona eriyor. {registrar} üzerinden yenileyin (veya otomatik yenilemeyi açın).']],
  ['rdap.expiring', ['Domain expires in {days} days!', 'Alan adının süresi {days} gün içinde doluyor!'],
    ['Expires on {date}. Renew it now at {registrar}; an expired domain stops resolving and email stops working.',
      '{date} tarihinde sona eriyor. Hemen {registrar} üzerinden yenileyin; süresi dolan alan adı çözülmez ve e-posta çalışmaz.']],
  ['rdap.expired', ['Domain registration expired', 'Alan adı kaydının süresi dolmuş'],
    ['The registration expired {days} days ago ({date}). Renew immediately at {registrar}.', 'Kaydın süresi {days} gün önce ({date}) doldu. Hemen {registrar} üzerinden yenileyin.']],
  ['rdap.no-expiry', ['Expiry date not published', 'Bitiş tarihi yayınlanmıyor'],
    ['The registry\'s RDAP answer contains no expiration date.', 'Kayıt kuruluşunun RDAP yanıtında bitiş tarihi yok.']],
  ['rdap.unsupported', ['RDAP not available for .{tld}', '.{tld} için RDAP yok'],
    ['The .{tld} registry offers no RDAP service, so registration and expiry data cannot be read from the browser. Check the registry\'s own WHOIS service.',
      '.{tld} kayıt kuruluşu RDAP hizmeti sunmuyor; kayıt ve bitiş bilgileri tarayıcıdan okunamıyor. Kayıt kuruluşunun kendi WHOIS hizmetine bakın.']],
  ['rdap.not-found', ['Not found in the registry', 'Kayıt kuruluşunda bulunamadı'],
    ['The registry has no registration for {domain}.', 'Kayıt kuruluşunda {domain} için kayıt yok.']],
  ['rdap.error', ['RDAP lookup failed', 'RDAP sorgusu başarısız'],
    ['Registration data could not be retrieved ({error}).', 'Kayıt bilgileri alınamadı ({error}).']],
  ['rdap.hold', ['Domain is on hold', 'Alan adı askıda (hold)'],
    ['Status: {status}. A domain on hold is removed from DNS.', 'Durum: {status}. Askıdaki (hold) alan adı DNS’ten kaldırılır.']],
  ['rdap.pending-delete', ['Domain is being deleted', 'Alan adı silinme sürecinde'],
    ['Status: {status}. Restore it with the registrar before it is released.', 'Durum: {status}. Serbest bırakılmadan önce kayıt firması üzerinden geri alın.']],
  ['rdap.transfer-unlocked', ['No transfer lock', 'Transfer kilidi yok'],
    ['"client transfer prohibited" is not set; enable the registrar lock to prevent unauthorized transfers.',
      '"client transfer prohibited" ayarlı değil; yetkisiz transferleri önlemek için kayıt firmasında transfer kilidini etkinleştirin.']]
];

/**
 * English and Turkish texts for every check id (`health.<id>.title` /
 * `health.<id>.detail`), CAA reasons (`health.caa.reason.<code>`) and groups
 * (`health.group.<group>`). Placeholders: `{param}`. Register with
 * `registerStrings('en', HEALTH_I18N.en)` / `registerStrings('tr', HEALTH_I18N.tr)`.
 * @type {{ en: Object<string, string>, tr: Object<string, string> }}
 */
export const HEALTH_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });

/**
 * Every check id this module can emit (sorted).
 * @type {ReadonlyArray<string>}
 */
export const HEALTH_CHECK_IDS = Object.freeze(STRINGS
  .map(([id]) => id)
  .filter((id) => !id.startsWith('group.') && !id.startsWith('caa.reason.'))
  .sort());
