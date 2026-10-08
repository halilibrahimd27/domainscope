/**
 * spfexplain.js — an SPF policy in plain words (DNS Lookup › Explain, ROADMAP P1.5).
 *
 * - {@link spfPolicy}: the terms of a record and of every policy it includes or redirects to, in
 *   the order a receiver reads them — what each does (a code and its parameters), the result it
 *   gives where it is written and at the checked domain (inside an include only a pass counts:
 *   lib/retire.js effectiveQualifier), the DNS lookups it costs with what lies below it, and what
 *   could not be read (a macro that needs the sender, a lookup that failed, a loop …).
 * - {@link spfMeter}: the RFC 7208 §4.6.4 budget — DNS-querying terms of 10, void lookups of 2 —
 *   and the branches that spend it, costliest first.
 * - {@link spfStringIssues}: TXT character-strings joined without a space (RFC 7208 §3.3) where the
 *   join breaks a term (`…/24` + `include:…` reads `/24include:…`).
 * - {@link spfFlatten}: a flatten preview — the include, a and mx terms replaced by the addresses
 *   they stand for now, with the record's size, its TXT strings and the lookups left, and every
 *   term it had to keep as it is.
 *
 * Everything works on the tree lib/health.js spfLookupCount expanded: nothing is asked here.
 * DOM-free; texts are codes the view words (`xpl.spf.*`).
 */

import { parseSpf, SPF_LOOKUP_LIMIT, SPF_VOID_LIMIT } from './health.js';
import { effectiveQualifier, rangeOf } from './retire.js';
import { formatIP, ipVersion, normalizeIP } from './ip.js';

/** What a term does (`xpl.spf.kind.<code>`). */
export const SPF_STEP_KINDS = Object.freeze(['ip4', 'ip4-range', 'ip6', 'ip6-range', 'a', 'mx', 'include', 'redirect', 'exists', 'ptr', 'all']);
/** What became of a term's lookup (`xpl.spf.state.<code>`; `ok` is said by the term itself). */
export const SPF_STEP_STATES = Object.freeze(['ok', 'void', 'macro', 'skipped', 'dns-error', 'no-record', 'multiple-records', 'loop', 'depth', 'too-many-mx']);
/** Why a policy has no terms to show (`xpl.spf.policy.<code>`). */
export const SPF_POLICY_STATES = Object.freeze(['ok', 'no-record', 'multiple-records', 'dns-error']);
/** Why the flatten preview kept a term as it is, or is not exact (`xpl.spf.flat.<code>`). */
export const SPF_FLATTEN_NOTES = Object.freeze(['sender', 'failed', 'kept-include', 'exceptions', 'passes-all']);
/** RFC 7208 §3.4: keep the record within about 450 characters so the DNS answer fits 512 octets of UDP. */
export const SPF_UDP_SAFE_LENGTH = 450;
/** The longest TXT character-string (RFC 1035 §3.3). */
export const TXT_STRING_MAX = 255;

const QUALIFIER_RESULT = Object.freeze({ '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' });
const MACRO_LETTER_RE = /%\{([a-zA-Z])/g;
const MAX_DEPTH = 12;

/**
 * The macro letters a term uses (`exists:%{ir}.%{v}._spf.example.com` → ['i', 'v']), lower case, unique.
 * @param {string} text
 * @returns {string[]}
 */
export function macroLetters(text) {
  const out = [];
  for (const m of String(text ?? '').matchAll(MACRO_LETTER_RE)) {
    const l = m[1].toLowerCase();
    if (!out.includes(l)) out.push(l);
  }
  return out;
}

/** An ip4 / ip6 range: its canonical text, first and last address and size (IPv4; IPv6 sizes are not counted). */
function rangeInfo(value, prefix) {
  const r = rangeOf(value, prefix);
  if (!r) return null;
  const bits = r.version === 4 ? 32 : 128;
  const span = 1n << BigInt(bits - r.prefix);
  const network = formatIP(r.network, r.version);
  return {
    version: r.version,
    prefix: r.prefix,
    single: r.prefix === bits,
    range: r.prefix === bits ? network : `${network}/${r.prefix}`,
    first: network,
    last: formatIP(r.network + span - 1n, r.version),
    // Exact for IPv4; an IPv6 network is named by its prefix only.
    size: r.version === 4 ? Number(span) : null,
    // `ip4:192.0.2.10/24` names the whole /24: the address had host bits set.
    hostBits: normalizeIP(value) !== network && r.prefix !== bits
  };
}

/**
 * @typedef {object} SpfStep
 * @property {number} n the term's place in its record (1-based; the redirect comes last)
 * @property {string} term as written
 * @property {string} mechanism
 * @property {string} qualifier '+', '-', '~', '?' ('' for a redirect)
 * @property {string|null} result what a match gives where the term is written (null for a redirect)
 * @property {string|null} effective what a match gives the checked domain: inside an include only a pass
 *   counts (the include then gives its own qualifier's result); null when a match there changes nothing
 * @property {string} kind one of {@link SPF_STEP_KINDS}
 * @property {object} params what the kind's text names: `range`, `first`, `last`, `size`, `prefix`,
 *   `hostBits` (ip4 / ip6), `host`, `cidr4`, `cidr6` (a / mx), `target` (include, redirect, exists, ptr)
 * @property {boolean} lookup the term costs a DNS lookup itself
 * @property {number} cost lookups it costs, with everything below it
 * @property {string|null} target the host name it expanded to (null: a macro that could not be expanded, or none)
 * @property {string[]} macros the macro letters it uses; @property {string[]} missing those it could not expand
 * @property {string[]|null} addresses an `a` term's addresses; @property {string[]|null} hosts an `mx` term's hosts
 * @property {string} state one of {@link SPF_STEP_STATES}
 * @property {string|null} detail the error text of a lookup that failed
 * @property {SpfPolicy|null} child the policy an include or redirect leads to
 */

/**
 * @typedef {object} SpfPolicy
 * @property {string} domain
 * @property {string|null} record
 * @property {string} state one of {@link SPF_POLICY_STATES}
 * @property {string|null} detail why it could not be read (a DNS error)
 * @property {SpfStep[]} steps the terms a receiver reads, up to `all` (and the redirect when there is none)
 * @property {string[]} ignored the terms after `all`, which no receiver reads
 * @property {string|null} redirect the redirect= domain-spec; @property {boolean} redirectIgnored an `all` voids it
 * @property {string|null} exp the exp= domain-spec; @property {Array<[string, string]>} modifiers unknown modifiers
 * @property {string|null} all the qualifier of `all`
 * @property {boolean} implicitNeutral no `all` and no redirect: a sender nothing matches gets neutral
 * @property {number} count lookups of this policy and below; @property {number} voidCount
 * @property {Array<{ code: string, token: string }>} errors the record's syntax errors (lib/health.js parseSpf)
 * @property {Array<{ code: string, token: string }>} warnings its warnings (ptr, broad-range, too-long …)
 * @property {string} scope 'top', 'include' or 'redirect': where the checked domain meets it
 */

function stepParams(t, kind, domain) {
  switch (kind) {
    case 'ip4':
    case 'ip4-range':
    case 'ip6':
    case 'ip6-range': {
      const r = rangeInfo(t.value, t.mechanism === 'ip4' ? t.cidr4 : t.cidr6);
      return r ? { range: r.range, first: r.first, last: r.last, size: r.size, prefix: r.prefix, hostBits: r.hostBits } : {};
    }
    case 'a':
    case 'mx':
      return { host: t.target || t.value || domain, cidr4: t.cidr4 ?? null, cidr6: t.cidr6 ?? null };
    case 'include':
    case 'redirect':
    case 'exists':
    case 'ptr':
      return { target: t.target || t.value || domain };
    default:
      return {};
  }
}

function stepKind(t) {
  if (t.mechanism === 'ip4' || t.mechanism === 'ip6') {
    const single = t.mechanism === 'ip4' ? (t.cidr4 ?? 32) === 32 : (t.cidr6 ?? 128) === 128;
    return single ? t.mechanism : `${t.mechanism}-range`;
  }
  return SPF_STEP_KINDS.includes(t.mechanism) ? t.mechanism : 'all';
}

function stepState(t) {
  if (t.skipped) return 'skipped';
  if (t.error) return SPF_STEP_STATES.includes(t.error) ? t.error : 'dns-error';
  if (t.lookup && !t.target && (t.macro || (t.missing && t.missing.length))) return 'macro';
  if (t.void) return 'void';
  return 'ok';
}

/**
 * An expanded SPF policy as steps (see the module comment).
 * @param {object|null} tree lib/health.js spfLookupCount().tree
 * @param {{ chain?: Array<{ kind: 'include'|'redirect', qualifier: string }>, scope?: 'top'|'include'|'redirect' }} [opts]
 *   `chain`: the includes and redirects from the checked domain to this policy (outermost first)
 * @returns {SpfPolicy|null}
 */
export function spfPolicy(tree, { chain = [], scope = 'top' } = {}) {
  if (!tree || typeof tree !== 'object') return null;
  const own = (code) => (tree.errors || []).find((e) => e.domain === tree.domain && e.code === code) || null;
  const hasRecord = typeof tree.record === 'string';
  const parsed = hasRecord ? parseSpf(tree.record) : null;
  const state = hasRecord ? 'ok' : own('multiple-records') ? 'multiple-records' : own('no-record') ? 'no-record' : 'dns-error';
  const steps = chain.length > MAX_DEPTH ? [] : (tree.terms || []).map((t, i) => {
    const kind = stepKind(t);
    const redirect = t.mechanism === 'redirect';
    const failure = t.error ? (tree.errors || []).find((e) => e.code === t.error && (e.target === t.target || e.target === null)) : null;
    const childChain = [...chain, { kind: redirect ? 'redirect' : 'include', qualifier: t.qualifier || '+' }];
    const eff = redirect ? null : effectiveQualifier(chain, t.qualifier || '+');
    return {
      n: i + 1,
      term: t.term,
      mechanism: t.mechanism,
      qualifier: redirect ? '' : t.qualifier || '+',
      result: redirect ? null : QUALIFIER_RESULT[t.qualifier] || 'pass',
      effective: eff ? QUALIFIER_RESULT[eff] : null,
      kind,
      params: stepParams(t, kind, tree.domain),
      lookup: !!t.lookup,
      cost: (t.lookup ? 1 : 0) + (t.child ? t.child.count || 0 : 0),
      target: t.target || null,
      macros: macroLetters(t.term),
      missing: Array.isArray(t.missing) ? [...t.missing] : [],
      addresses: Array.isArray(t.addresses) ? [...t.addresses] : null,
      hosts: Array.isArray(t.hosts) ? [...t.hosts] : null,
      state: stepState(t),
      detail: failure && failure.detail ? failure.detail : null,
      child: t.child ? spfPolicy(t.child, { chain: childChain, scope: redirect ? 'redirect' : 'include' }) : null
    };
  });
  const redirect = parsed ? parsed.modifiers.redirect : null;
  return {
    domain: tree.domain,
    record: hasRecord ? tree.record : null,
    state,
    detail: state === 'dns-error' && own('dns-error') ? own('dns-error').detail : null,
    steps,
    ignored: parsed && parsed.allIndex >= 0 ? parsed.terms.slice(parsed.allIndex + 1).map((x) => x.raw) : [],
    redirect,
    redirectIgnored: !!(parsed && redirect && parsed.allIndex >= 0),
    exp: parsed ? parsed.modifiers.exp : null,
    modifiers: parsed ? Object.entries(parsed.modifiers.other) : [],
    all: parsed ? parsed.all : null,
    implicitNeutral: !!(parsed && parsed.all === null && !redirect),
    count: Number(tree.count) || 0,
    voidCount: Number(tree.voidCount) || 0,
    errors: parsed ? parsed.errors : [],
    warnings: parsed ? parsed.warnings : [],
    scope
  };
}

/**
 * The RFC 7208 §4.6.4 budget of an expanded policy and the branches that spend it.
 * @param {{ count: number, voidCount: number, tree: object }} lookups lib/health.js spfLookupCount()
 * @returns {{ count: number, limit: number, voidCount: number, voidLimit: number, exceeded: boolean,
 *   high: boolean, voidExceeded: boolean, branches: Array<{ term: string, cost: number }> }}
 *   `branches`: the checked domain's own terms that cost lookups, costliest first (ties in record order)
 */
export function spfMeter(lookups) {
  const count = Number(lookups && lookups.count) || 0;
  const voidCount = Number(lookups && lookups.voidCount) || 0;
  const terms = (lookups && lookups.tree && lookups.tree.terms) || [];
  const branches = terms.map((t, i) => ({ term: t.term, cost: (t.lookup ? 1 : 0) + (t.child ? t.child.count || 0 : 0), i }))
    .filter((b) => b.cost > 0)
    .sort((a, b) => b.cost - a.cost || a.i - b.i)
    .map(({ term, cost }) => ({ term, cost }));
  return {
    count,
    limit: SPF_LOOKUP_LIMIT,
    voidCount,
    voidLimit: SPF_VOID_LIMIT,
    exceeded: count > SPF_LOOKUP_LIMIT,
    high: count >= SPF_LOOKUP_LIMIT - 1 && count <= SPF_LOOKUP_LIMIT,
    voidExceeded: voidCount > SPF_VOID_LIMIT,
    branches
  };
}

/**
 * Where the character-strings of an SPF TXT record join without a space and the join breaks a term:
 * receivers join the strings as they are (RFC 7208 §3.3), so `"… ip4:192.0.2.0/24" "include:…"`
 * reads `ip4:192.0.2.0/24include:…`. A term split in its middle on purpose (`"… inclu" "de:…"`)
 * joins into a valid term and is not reported.
 * @param {string[]} strings the record's character-strings, in order
 * @returns {Array<{ after: number, left: string, right: string, joined: string }>} `after`: the
 *   1-based string the join follows; `left` / `right`: the text on each side of the join in that term
 */
export function spfStringIssues(strings) {
  const list = Array.isArray(strings) ? strings.map((s) => String(s ?? '')) : [];
  if (list.length < 2) return [];
  const record = list.join('');
  const out = [];
  let at = 0;
  for (let i = 0; i < list.length - 1; i += 1) {
    at += list[i].length;
    const before = record[at - 1];
    const after = record[at];
    if (before === undefined || after === undefined || /\s/.test(before) || /\s/.test(after)) continue;
    let start = at;
    while (start > 0 && !/\s/.test(record[start - 1])) start -= 1;
    let end = at;
    while (end < record.length && !/\s/.test(record[end])) end += 1;
    const joined = record.slice(start, end);
    // The version tag glued to its first term ("v=spf1" + "include:…") is no SPF record at all.
    const probe = start === 0 ? joined : `v=spf1 ${joined}`;
    const parsed = parseSpf(probe);
    if (parsed.valid && parsed.version) continue;
    out.push({ after: i + 1, left: record.slice(start, at), right: record.slice(at, end), joined });
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Flatten preview                                                          */
/* ------------------------------------------------------------------------ */

/**
 * A flatten preview: the policy as one record of `ip4:` / `ip6:` terms (RFC 7208 §5.6), the
 * include, a and mx terms replaced by the addresses they stand for now.
 *
 * - The checked domain's own terms keep their order and qualifiers: `a` / `mx` become their
 *   addresses (with the term's CIDR length), an include the addresses its policy passes, with the
 *   include's qualifier; a redirect hands over the whole policy it names, its `all` included.
 * - An include (or redirect) whose policy — or one below it — holds a term that depends on the
 *   sender (`exists`, `ptr`, a macro) or could not be read is kept, named by the domain it expanded
 *   to (`kept-include`); so is such a term of the checked domain's own (`sender`, `failed`). A kept
 *   term still costs its lookups.
 * - Inside an include only passes count: its fail / softfail / neutral terms only stop the include
 *   from matching some addresses, which a flat list cannot say — the preview leaves them out and is
 *   not exact (`exceptions`); an include that passes everyone becomes `all` with its qualifier
 *   (`passes-all`).
 * - A term the same as one before it, or inside an earlier range with the same qualifier, is left out.
 *
 * The addresses are the providers' today: a flattened record must be refreshed when they change.
 * @param {object|null} tree lib/health.js spfLookupCount().tree
 * @param {{ mxAddresses?: Map<string, { addresses: string[], error?: string|null }> }} [opts] the
 *   addresses of the hosts the mx terms name (lib/health.js spfMxHosts)
 * @returns {{ record: string, terms: string[], length: number, strings: number, lookups: number,
 *   addressTerms: number, exact: boolean, fits: boolean, notes: Array<{ code: string, term: string, holder: string }> }|null}
 *   `fits`: within {@link SPF_UDP_SAFE_LENGTH} characters; `strings`: TXT strings of at most 255
 *   characters it needs; `lookups`: DNS-querying terms left (the kept ones and what is below them);
 *   `notes`: {@link SPF_FLATTEN_NOTES} codes with the term and the policy that holds it
 */
export function spfFlatten(tree, { mxAddresses = new Map() } = {}) {
  if (!tree || typeof tree.record !== 'string') return null;
  const out = [];
  const notes = [];
  let lookups = 0;
  let ended = false;
  const note = (code, term, holder) => {
    if (!notes.some((n) => n.code === code && n.term === term && n.holder === holder)) notes.push({ code, term, holder });
  };
  const prefix = (q) => (q === '+' ? '' : q);
  const bitsOf = (v) => (v === 4 ? 32n : 128n);
  /** An address term, unless an earlier one with the same qualifier covers it (that one matches first). */
  const emit = (q, value, cidr) => {
    const r = rangeOf(value, cidr);
    if (!r) return;
    const covered = out.some((x) => x.q === q && x.range && x.range.version === r.version && x.range.prefix <= r.prefix
      && (r.network >> (bitsOf(r.version) - BigInt(x.range.prefix))) === (x.range.network >> (bitsOf(r.version) - BigInt(x.range.prefix))));
    if (covered) return;
    out.push({ q, text: `${prefix(q)}${r.version === 4 ? 'ip4' : 'ip6'}:${rangeInfo(value, cidr).range}`, range: r });
  };
  const keep = (q, text, cost) => {
    out.push({ q, text: `${prefix(q)}${text}`, range: null });
    lookups += cost;
  };
  const mxResolved = (t) => (t.hosts || []).every((h) => mxAddresses.has(h) && !mxAddresses.get(h).error);
  const readable = (t) => !!t.target && !t.error && !t.skipped && !t.forIp;
  const resolved = (t) => readable(t) && (t.mechanism === 'a' ? Array.isArray(t.addresses) : Array.isArray(t.hosts) && mxResolved(t));
  /** Can every term of this policy and below be written as addresses? */
  const flattenable = (node, depth) => {
    if (!node || typeof node.record !== 'string' || depth > MAX_DEPTH) return false;
    return (node.terms || []).every((t) => {
      if (t.mechanism === 'ip4' || t.mechanism === 'ip6' || t.mechanism === 'all') return true;
      if (t.mechanism === 'a' || t.mechanism === 'mx') return resolved(t);
      if (t.mechanism === 'include' || t.mechanism === 'redirect') return readable(t) && flattenable(t.child, depth + 1);
      return false; // exists, ptr: their answer depends on the sender
    });
  };
  const keptReason = (t) => ((t.missing && t.missing.length) || (t.macro && !t.target) ? 'sender'
    : readable(t) && t.child ? 'kept-include' : 'failed');
  const bare = (term) => term.replace(/^[-+~?]/, '');
  /**
   * A kept term as the checked domain must write it: the checked domain's own as written; one from
   * a policy below by the name it expanded to (a bare `mx` or `%{d}` there means that domain).
   */
  const written = (t, depth) => {
    if (depth === 0 || !t.target) return bare(t.term);
    const cidr = (t.cidr4 !== null && t.cidr4 !== undefined ? `/${t.cidr4}` : '') + (t.cidr6 !== null && t.cidr6 !== undefined ? `//${t.cidr6}` : '');
    return `${t.mechanism}:${t.target}${t.mechanism === 'a' || t.mechanism === 'mx' ? cidr : ''}`;
  };

  /**
   * One policy. `q`: the qualifier its matches get at the checked domain, or null for the checked
   * domain's own policy and one it redirects to (each term keeps its own qualifier there).
   */
  const walk = (node, q, depth) => {
    for (const t of node.terms || []) {
      if (ended) return;
      const own = q === null;
      const tq = own ? t.qualifier || '+' : q;
      // Inside an include only a pass reaches the checked domain; the rest only makes exceptions.
      if (!own && t.mechanism !== 'redirect' && (t.qualifier || '+') !== '+') {
        if (t.mechanism !== 'all') note('exceptions', t.term, node.domain);
        continue;
      }
      switch (t.mechanism) {
        case 'ip4':
        case 'ip6':
          emit(tq, t.value, t.mechanism === 'ip4' ? t.cidr4 : t.cidr6);
          break;
        case 'a':
        case 'mx':
          if (!resolved(t)) {
            note(keptReason(t) === 'sender' ? 'sender' : 'failed', t.term, node.domain);
            keep(tq, written(t, depth), 1);
            break;
          }
          for (const a of t.mechanism === 'a' ? t.addresses : t.hosts.flatMap((h) => mxAddresses.get(h).addresses || [])) {
            emit(tq, a, ipVersion(a) === 4 ? t.cidr4 : t.cidr6);
          }
          break;
        case 'include':
          if (readable(t) && flattenable(t.child, depth + 1)) walk(t.child, tq, depth + 1);
          else {
            note(keptReason(t), t.term, node.domain);
            keep(tq, written(t, depth), 1 + (t.child ? Number(t.child.count) || 0 : 0));
          }
          break;
        case 'redirect':
          if (readable(t) && flattenable(t.child, depth + 1)) walk(t.child, q, depth + 1);
          else {
            note(keptReason(t), t.term, node.domain);
            out.push({ q: '+', text: t.target ? `redirect=${t.target}` : t.term, range: null });
            lookups += 1 + (t.child ? Number(t.child.count) || 0 : 0);
            ended = true;
          }
          break;
        case 'all':
          if (!own) note('passes-all', t.term, node.domain);
          out.push({ q: tq, text: `${prefix(tq)}all`, range: null });
          ended = true;
          return;
        default:
          // exists, ptr: their answer depends on the sender, so they stay.
          note('sender', t.term, node.domain);
          keep(tq, written(t, depth), 1);
          break;
      }
    }
  };
  walk(tree, null, 0);
  const parsed = parseSpf(tree.record);
  const mods = [];
  if (parsed.modifiers.exp) mods.push(`exp=${parsed.modifiers.exp}`);
  for (const [k, v] of Object.entries(parsed.modifiers.other)) mods.push(`${k}=${v}`);
  const terms = [...out.map((x) => x.text), ...mods];
  const record = ['v=spf1', ...terms].join(' ');
  return {
    record,
    terms,
    length: record.length,
    strings: Math.max(1, Math.ceil(record.length / TXT_STRING_MAX)),
    lookups,
    addressTerms: out.filter((x) => x.range).length,
    exact: !notes.some((n) => n.code === 'exceptions' || n.code === 'passes-all'),
    fits: record.length <= SPF_UDP_SAFE_LENGTH,
    notes
  };
}
