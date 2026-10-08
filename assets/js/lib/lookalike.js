/**
 * lookalike.js — lookalike and typosquat domains of a domain (Domain overview › Lookalike
 * domains): candidates made the way dnstwist makes them, a DNS check of each, the registration
 * date and registrar of the ones that exist, their current certificates on request, and a risk
 * score that puts the worst first.
 *
 * Candidates ({@link generateLookalikes}) come from the registrable domain's label (`example` of
 * `www.example.com.tr`, an IDN label decoded first), one technique each ({@link
 * LOOKALIKE_TECHNIQUES}): a letter left out, doubled or swapped with the next; a key next to it
 * on a QWERTY or a Turkish Q keyboard typed instead or as well; a vowel for another; a hyphen or
 * a dot (the rest of the name becomes the registrable domain) between two letters; one bit of a
 * letter flipped; a lookalike letter (0 for o, rn for m; the Turkish ı, i̇ (the lower case of İ),
 * ş, ğ, ç, ö and ü; Cyrillic and Greek letters; accented Latin ones; and back to plain letters
 * for a label that has them), written as punycode; a letter or digit added; another ending
 * (.com ⇄ .com.tr, .net, .org, .co and common gTLDs); and words such as login-, secure- or
 * -support around the label. A name made twice keeps its first technique in the order above, the
 * domain itself and invalid labels are left out, and a budget picks the candidates round-robin
 * over the techniques, so a larger budget only adds to a smaller one's list. Names under one of
 * the user's own registrable domains (the workspace's) are marked `own`: never checked, never
 * flagged.
 *
 * The check ({@link checkLookalikes}): NS of the candidate's registrable domain first — NXDOMAIN
 * (or no delegation) says it is not in DNS and nothing more is asked; then A, AAAA and MX of the
 * name; then RDAP (lib/rdap.js, which paces each registry and rdap.org) for the registration date
 * and the registrar. {@link lookupCertificates} asks crt.sh for a name's current certificates,
 * only on request (the top hits). Only an abort rejects: every other failure is a SourceFailure
 * (lib/sourcestatus.js) in the result, for "⚠ n/a" and a Retry.
 *
 * {@link scoreLookalike} weighs what was found ({@link RISK_WEIGHTS}): MX (it can take mail meant
 * for you and send as a lookalike of you), a web host, a registration in the last 30 or 90 days,
 * a current certificate, an IDN; the same name servers or addresses as the domain lower it (often
 * the owner's own defensive registration). {@link lookalikeCsv} exports the rows.
 *
 * DOM-free; the I/O is injected (`dns`, `fetchImpl`, `signal`, `now`). Runs in browsers and Node 22.
 */

import { normalizeHostname, registrableDomain } from './domain.js';
import { rdapDomain } from './rdap.js';
import { createLimiter, errorKind, fetchJson, throwIfAborted } from './util.js';
import { toCsv } from './export.js';
import { punycodeEncode, punycodeDecode } from './punycode.js';

/** Candidates checked by default. */
export const LOOKALIKE_DEFAULT_BUDGET = 300;
/** The most candidates one list holds ("more on demand" grows the budget up to it). */
export const LOOKALIKE_MAX_BUDGET = 2000;
/** The budgets the panel offers. */
export const LOOKALIKE_BUDGETS = Object.freeze([100, 300, 1000, 2000]);
/** Candidates checked at once (each sends up to four DNS questions). */
export const LOOKALIKE_CONCURRENCY = 6;
/** RDAP lookups in flight at once (lib/rdap.js still sends one at a time to each registry server). */
export const LOOKALIKE_RDAP_CONCURRENCY = 3;
/** How many of the worst registered candidates the certificate lookup asks crt.sh about. */
export const LOOKALIKE_CT_TOP = 10;
/** Timeout of one crt.sh search (it is slow). */
export const LOOKALIKE_CT_TIMEOUT_MS = 30000;
/** crt.sh's JSON search. */
export const CRTSH_SEARCH = 'https://crt.sh/';
/** A registration this many days old or younger is "new". */
export const LOOKALIKE_NEW_DAYS = 30;
/** … and this many days old or younger "recent". */
export const LOOKALIKE_RECENT_DAYS = 90;

/** Every technique, in the order a name made twice keeps (and the budget's round-robin order). */
export const LOOKALIKE_TECHNIQUES = Object.freeze([
  'tld-swap', 'homoglyph', 'omission', 'transposition', 'replacement', 'repetition', 'vowel-swap',
  'hyphenation', 'addition', 'dictionary', 'insertion', 'subdomain', 'bitsquatting'
]);
/** What the DNS check found: not checked yet, one of the user's own, not in DNS, in DNS, failed. */
export const LOOKALIKE_STATES = Object.freeze(['pending', 'own', 'free', 'registered', 'failed']);
/** Risk levels, worst first ({@link sortLookalikes} order). */
export const LOOKALIKE_LEVELS = Object.freeze(['high', 'medium', 'low', 'unknown', 'none', 'pending', 'own']);
/** Why a candidate scored what it did (positive weights first, then the mitigating ones). */
export const LOOKALIKE_REASONS = Object.freeze(['mx', 'web', 'new', 'recent', 'cert', 'idn', 'same-ns', 'same-ip']);
/** The registration lookup's outcome (RDAP). */
export const LOOKALIKE_RDAP_STATES = Object.freeze(['ok', 'not-found', 'unsupported', 'failed']);
/** The certificate lookup's outcome (crt.sh). */
export const LOOKALIKE_CT_STATES = Object.freeze(['ok', 'failed']);

/** Score points per reason; `registered` is the base of every name in DNS. */
export const RISK_WEIGHTS = Object.freeze({
  registered: 10, mx: 35, web: 15, new: 30, recent: 20, cert: 15, idn: 5, 'same-ns': -20, 'same-ip': -20
});
/** The lowest score of each level above "low". */
export const RISK_THRESHOLDS = Object.freeze({ high: 60, medium: 35 });

/** Other endings tried for the label, most likely first. */
export const TLD_SWAPS = Object.freeze([
  'com', 'com.tr', 'net', 'org', 'co', 'tr', 'net.tr', 'org.tr', 'io', 'info', 'biz', 'xyz', 'online', 'site', 'shop',
  'store', 'app', 'dev', 'me', 'cc', 'us', 'eu', 'de', 'co.uk', 'cm', 'om'
]);
/** Words put before the label (`login-example`, `loginexample`). */
export const DICTIONARY_PREFIXES = Object.freeze(['login', 'secure', 'my', 'account', 'support', 'verify', 'online', 'mail', 'portal', 'auth', 'giris', 'hesap']);
/** Words put after the label (`example-support`, `examplesupport`). */
export const DICTIONARY_SUFFIXES = Object.freeze(['support', 'login', 'secure', 'account', 'verify', 'online', 'mail', 'help', 'portal', 'app', 'pay', 'service', 'destek', 'giris', 'tr']);

/**
 * Keyboard rows (hostname characters only), each staggered half a key to the right of the one
 * above: QWERTY and the Turkish Q layout (ı where QWERTY has i, then ğ ü, ş i and ö ç).
 */
export const KEYBOARD_ROWS = Object.freeze({
  qwerty: Object.freeze(['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm']),
  'tr-q': Object.freeze(['1234567890', 'qwertyuıopğü', 'asdfghjklşi', 'zxcvbnmöç'])
});

/**
 * Lookalike letters by class, the order a candidate list tries them: ASCII ones (no punycode),
 * the Turkish letters, Cyrillic, Greek and accented Latin ones. Every one is a lower-case letter
 * IDNA2008 allows in a label.
 */
export const HOMOGLYPHS = Object.freeze({
  ascii: Object.freeze({
    o: ['0'], 0: ['o'], l: ['1', 'i'], i: ['1', 'l'], 1: ['l', 'i'], b: ['d'], d: ['b'], c: ['e'], e: ['c'], g: ['q'], q: ['g'],
    m: ['n'], n: ['m', 'r'], r: ['n'], u: ['v'], v: ['u', 'y'], y: ['v'], z: ['2'], 2: ['z']
  }),
  turkish: Object.freeze({ i: ['ı', 'i̇'], s: ['ş'], g: ['ğ'], c: ['ç'], o: ['ö'], u: ['ü'] }),
  cyrillic: Object.freeze({
    a: ['а'], c: ['с'], e: ['е'], o: ['о'], p: ['р'], x: ['х'], y: ['у'], i: ['і'], j: ['ј'], s: ['ѕ'], h: ['һ'],
    d: ['ԁ'], l: ['ӏ'], q: ['ԛ'], w: ['ԝ'], k: ['к']
  }),
  greek: Object.freeze({ a: ['α'], o: ['ο'], p: ['ρ'], v: ['ν'], u: ['υ'], i: ['ι'], k: ['κ'], t: ['τ'], y: ['γ'], n: ['η'], w: ['ω'], x: ['χ'] }),
  latin: Object.freeze({
    a: ['à', 'á', 'â', 'ä', 'å'], e: ['è', 'é', 'ê', 'ë'], i: ['ì', 'í', 'î', 'ï'], o: ['ò', 'ó', 'ô', 'ø'], u: ['ù', 'ú', 'û'],
    n: ['ñ', 'ń'], y: ['ý', 'ÿ'], c: ['ć'], s: ['ś'], z: ['ź', 'ż'], l: ['ł'], r: ['ŕ'], g: ['ģ'], k: ['ķ']
  })
});
/** Lookalike letter pairs (both ways): rn for m, vv for w, cl for d, nn for m. */
export const MULTI_HOMOGLYPHS = Object.freeze([['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['vv', 'w'], ['d', 'cl'], ['cl', 'd'], ['m', 'nn']]);

const DAY = 86400000;
const ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
const HOST_CHARS = new Set(`${ALNUM}-`);
const VOWELS = 'aeiou';
const ASCII_LABEL_RE = /^[a-z0-9-]+$/;
const UNICODE_LABEL_RE = /^[\p{L}\p{M}\p{N}-]+$/u;

/* ------------------------------------------------------------------------ */
/* Punycode (RFC 3492): lib/punycode.js, re-exported for the callers of this module */
/* ------------------------------------------------------------------------ */

export { punycodeEncode, punycodeDecode };

/**
 * A label as DNS carries it: as is when it is ASCII, else `xn--` and its punycode; null when it
 * cannot be a label (empty, a hyphen at either end, `--` in the third and fourth place of an
 * ASCII label, a character no label holds, longer than 63).
 * @param {string} label lower case
 * @returns {string|null}
 */
export function labelToAscii(label) {
  const s = String(label ?? '');
  if (!s || s.startsWith('-') || s.endsWith('-')) return null;
  if (ASCII_LABEL_RE.test(s)) return s.length <= 63 && s.slice(2, 4) !== '--' ? s : null;
  const nfc = s.normalize('NFC');
  if (!UNICODE_LABEL_RE.test(nfc) || /^\p{M}/u.test(nfc) || /\p{Lu}/u.test(nfc)) return null;
  const out = `xn--${punycodeEncode(nfc)}`;
  return out.length <= 63 ? out : null;
}

/**
 * A name as people read it: every `xn--` label decoded (`xn--bcher-kva.example` → `bücher.example`).
 * @param {string} name
 * @returns {string}
 */
export function nameToUnicode(name) {
  return String(name ?? '').split('.').map((l) => {
    if (!l.startsWith('xn--')) return l;
    const u = punycodeDecode(l.slice(4));
    return u === null ? l : u;
  }).join('.');
}

/* ------------------------------------------------------------------------ */
/* Candidates                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} LookalikeTarget
 * @property {string} domain the registrable domain (ASCII)
 * @property {string} label its first label, decoded when it is an IDN (`example`, `türkiye`)
 * @property {string} suffix the public suffix (ASCII: `com.tr`)
 */

/**
 * The registrable domain of a domain or host name, split into the label the candidates vary and
 * its public suffix; null for an IP, a bare suffix or garbage.
 * @param {string} input
 * @returns {LookalikeTarget|null}
 */
export function lookalikeTarget(input) {
  const host = normalizeHostname(String(input ?? ''));
  const domain = host ? registrableDomain(host) : null;
  if (!domain) return null;
  const dot = domain.indexOf('.');
  const ascii = domain.slice(0, dot);
  const label = ascii.startsWith('xn--') ? punycodeDecode(ascii.slice(4)) : ascii;
  if (!label) return null;
  return { domain, label, suffix: domain.slice(dot + 1) };
}

/** Each key's neighbours on one keyboard (same row ±1, the two keys above and the two below). */
function keyboardMap(rows) {
  const map = new Map();
  rows.forEach((row, r) => {
    const keys = Array.from(row);
    keys.forEach((key, c) => {
      const near = [];
      const at = (rr, cc) => (rr >= 0 && rr < rows.length ? Array.from(rows[rr])[cc] : undefined);
      for (const k of [at(r - 1, c), at(r - 1, c + 1), keys[c - 1], keys[c + 1], at(r + 1, c - 1), at(r + 1, c)]) {
        if (k && !near.includes(k)) near.push(k);
      }
      map.set(key, near);
    });
  });
  return map;
}

/** Neighbouring keys per layout ({@link KEYBOARD_ROWS}). */
export const KEYBOARDS = Object.freeze(Object.fromEntries(Object.entries(KEYBOARD_ROWS).map(([id, rows]) => [id, keyboardMap(rows)])));

/**
 * The keys next to `key` on a layout ({@link KEYBOARD_ROWS}), in the order the candidates use.
 * @param {string} key
 * @param {'qwerty'|'tr-q'} [layout]
 * @returns {string[]}
 */
export function adjacentKeys(key, layout = 'qwerty') {
  const map = KEYBOARDS[layout];
  return map && map.has(key) ? [...map.get(key)] : [];
}

/** Plain letters for a label's lookalike ones: ü → u, ı → i, а (Cyrillic) → a … */
const FOLD = (() => {
  const out = new Map();
  for (const cls of ['turkish', 'cyrillic', 'greek', 'latin']) {
    for (const [base, glyphs] of Object.entries(HOMOGLYPHS[cls])) {
      for (const g of glyphs) {
        if (Array.from(g).length !== 1) continue;
        if (!out.has(g)) out.set(g, []);
        if (!out.get(g).includes(base)) out.get(g).push(base);
      }
    }
  }
  return out;
})();

const join = (cs) => cs.join('');
const replaceAt = (cs, i, v) => join([...cs.slice(0, i), v, ...cs.slice(i + 1)]);
const insertAt = (cs, i, v) => join([...cs.slice(0, i), v, ...cs.slice(i)]);

/** The variants of one technique: labels, or { label, suffix } / { left, label } for the two that change the rest. */
const GENERATORS = {
  'tld-swap': (cs, suffix) => TLD_SWAPS.filter((s) => s !== suffix).map((s) => ({ label: join(cs), suffix: s })),
  homoglyph(cs) {
    const out = [];
    // a label with lookalike letters: the plain ones first (türkiye → turkiye)
    cs.forEach((c, i) => { for (const b of FOLD.get(c) || []) out.push(replaceAt(cs, i, b)); });
    for (const cls of ['ascii', 'turkish', 'cyrillic', 'greek', 'latin']) {
      const table = HOMOGLYPHS[cls];
      cs.forEach((c, i) => { for (const g of (Object.hasOwn(table, c) ? table[c] : [])) out.push(replaceAt(cs, i, g)); });
      if (cls !== 'ascii') continue;
      const s = join(cs);
      for (const [from, to] of MULTI_HOMOGLYPHS) {
        for (let at = s.indexOf(from); at !== -1; at = s.indexOf(from, at + 1)) out.push(s.slice(0, at) + to + s.slice(at + from.length));
      }
    }
    return out;
  },
  omission: (cs) => cs.map((_, i) => join([...cs.slice(0, i), ...cs.slice(i + 1)])),
  transposition: (cs) => cs.slice(0, -1).flatMap((c, i) => (c === cs[i + 1] ? [] : [join([...cs.slice(0, i), cs[i + 1], c, ...cs.slice(i + 2)])])),
  replacement: (cs) => Object.keys(KEYBOARDS).flatMap((kb) => cs.flatMap((c, i) => adjacentKeys(c, kb).map((k) => replaceAt(cs, i, k)))),
  repetition: (cs) => cs.flatMap((c, i) => (c === '-' ? [] : [insertAt(cs, i, c)])),
  'vowel-swap': (cs) => cs.flatMap((c, i) => (VOWELS.includes(c) ? Array.from(VOWELS).filter((v) => v !== c).map((v) => replaceAt(cs, i, v)) : [])),
  hyphenation: (cs) => cs.slice(1).flatMap((c, j) => (c === '-' || cs[j] === '-' ? [] : [insertAt(cs, j + 1, '-')])),
  addition: (cs) => Array.from(ALNUM, (c) => join(cs) + c),
  dictionary(cs) {
    const s = join(cs);
    return [...DICTIONARY_PREFIXES.flatMap((w) => [`${w}-${s}`, `${w}${s}`]), ...DICTIONARY_SUFFIXES.flatMap((w) => [`${s}-${w}`, `${s}${w}`])];
  },
  insertion: (cs) => Object.keys(KEYBOARDS).flatMap((kb) => cs.flatMap((c, i) => adjacentKeys(c, kb).flatMap((k) => [insertAt(cs, i, k), insertAt(cs, i + 1, k)]))),
  subdomain: (cs) => cs.slice(1).flatMap((c, j) => (c === '-' || cs[j] === '-' ? [] : [{ left: join(cs.slice(0, j + 1)), label: join(cs.slice(j + 1)) }])),
  bitsquatting: (cs) => cs.flatMap((c, i) => {
    if (c.length !== 1 || c.charCodeAt(0) >= 0x80) return [];
    return [1, 2, 4, 8, 16, 32, 64, 128].map((m) => String.fromCharCode(c.charCodeAt(0) ^ m)).filter((b) => HOST_CHARS.has(b)).map((b) => replaceAt(cs, i, b));
  })
};

/**
 * @typedef {object} LookalikeCandidate
 * @property {string} name the name as DNS carries it (ASCII, punycode for an IDN label)
 * @property {string} unicode the name as people read it
 * @property {string} technique one of {@link LOOKALIKE_TECHNIQUES}
 * @property {string} registrable the registrable domain that holds it (the rest of the name for `subdomain`)
 * @property {boolean} idn a label of it is punycode
 * @property {boolean} own under one of the user's own registrable domains: never checked or flagged
 * @property {number} index its place in the full list (the budget's round-robin order)
 */

/** The user's own registrable domains, from any list of domain or host names. */
function ownSet(own) {
  const out = new Set();
  for (const v of own || []) {
    const host = normalizeHostname(String(v ?? ''));
    const d = host ? registrableDomain(host) : null;
    if (d) out.add(d);
  }
  return out;
}

/**
 * Every candidate of a domain, deduplicated, then picked round-robin over the techniques up to
 * `budget` (a larger budget's list starts with a smaller one's).
 * @param {string} input a domain or host name (its registrable domain is used)
 * @param {{ budget?: number, own?: Iterable<string>, techniques?: string[] }} [opts]
 *   own: the user's own domains or host names (their registrable domains are never flagged);
 *   techniques: a subset of {@link LOOKALIKE_TECHNIQUES}
 * @returns {{ target: LookalikeTarget, candidates: LookalikeCandidate[], total: number,
 *   byTechnique: Record<string, number>, own: number }|null} null for input that is no domain;
 *   `total`: every candidate the techniques make; `byTechnique`: how many each made (deduplicated);
 *   `own`: the candidates in the list that are the user's own
 */
export function generateLookalikes(input, { budget = LOOKALIKE_DEFAULT_BUDGET, own = [], techniques = LOOKALIKE_TECHNIQUES } = {}) {
  const target = lookalikeTarget(input);
  if (!target) return null;
  const mine = ownSet(own);
  mine.add(target.domain);
  const cs = Array.from(target.label);
  const seen = new Set([target.domain]);
  const lists = [];
  for (const technique of LOOKALIKE_TECHNIQUES) {
    if (!techniques.includes(technique)) continue;
    const list = [];
    for (const v of GENERATORS[technique](cs, target.suffix)) {
      const variant = typeof v === 'string' ? { label: v } : v;
      const label = labelToAscii(variant.label);
      const left = variant.left === undefined ? null : labelToAscii(variant.left);
      if (!label || (variant.left !== undefined && !left)) continue;
      const registrable = `${label}.${variant.suffix || target.suffix}`;
      const name = left ? `${left}.${registrable}` : registrable;
      if (seen.has(name) || name.length > 253) continue;
      seen.add(name);
      // A name made of the suffix alone (a dot split leaving a public suffix) holds no domain.
      if (registrableDomain(registrable) !== registrable) continue;
      list.push({
        name, unicode: nameToUnicode(name), technique, registrable, idn: /(^|\.)xn--/.test(name), own: mine.has(registrable), index: 0
      });
    }
    lists.push(list);
  }
  const byTechnique = Object.fromEntries(LOOKALIKE_TECHNIQUES.filter((t) => techniques.includes(t)).map((t, i) => [t, lists[i].length]));
  const total = lists.reduce((n, l) => n + l.length, 0);
  const cap = Math.max(0, Math.min(Number.isFinite(budget) ? Math.floor(budget) : LOOKALIKE_DEFAULT_BUDGET, LOOKALIKE_MAX_BUDGET));
  const candidates = [];
  for (let round = 0; candidates.length < cap && candidates.length < total; round += 1) {
    for (const list of lists) {
      if (round < list.length && candidates.length < cap) candidates.push({ ...list[round], index: candidates.length });
    }
  }
  return { target, candidates, total, byTechnique, own: candidates.filter((c) => c.own).length };
}

/* ------------------------------------------------------------------------ */
/* Checks                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} LookalikeDns
 * @property {'free'|'registered'|'failed'} state
 * @property {string[]} ns the registrable domain's name servers
 * @property {string[]} addresses the name's A and AAAA addresses
 * @property {string[]} mx the name's mail exchangers (none for a null MX)
 * @property {boolean} nullMx the name says it takes no mail (MX ".")
 * @property {Array<object>} failures SourceFailures (`source: 'doh'`), each with the `lookup` it
 *   failed: 'ns' (the whole check) or 'a' / 'aaaa' / 'mx' (that field)
 */

const cleanName = (v) => String(v ?? '').toLowerCase().replace(/\.$/, '');
const uniqSorted = (list) => [...new Set(list)].sort();

/** A DoH answer that is no usable answer (no message, SERVFAIL, REFUSED …), as a SourceFailure. */
function dnsFailure(res, lookup, at) {
  if (!res || res.ok === false) {
    return { source: 'doh', lookup, error: (res && res.error) || 'No DNS answer', errorKind: (res && res.errorKind) || 'unknown', retryAfterMs: (res && res.retryAfterMs) ?? null, at };
  }
  if (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN') return { source: 'doh', lookup, error: `DNS ${res.rcode}`, rcode: res.rcode, at };
  return null;
}

const dataOf = (res, type) => (res && res.ok && res.rcode === 'NOERROR' ? (res.answers || []).filter((a) => a.type === type).map((a) => a.data) : []);

/**
 * The DNS check of one candidate: NS of its registrable domain (NXDOMAIN or no NS: not in DNS,
 * nothing more is asked), then A, AAAA and MX of the name. Only an abort rejects.
 * @param {LookalikeCandidate} candidate
 * @param {{ dns: { query: Function }, signal?: AbortSignal, noCache?: boolean, now?: () => number }} opts
 * @returns {Promise<LookalikeDns>}
 */
export async function checkCandidate(candidate, { dns, signal, noCache = false, now = Date.now }) {
  throwIfAborted(signal);
  const q = (name, type) => dns.query(name, type, { signal, noCache });
  const nsRes = await q(candidate.registrable, 'NS');
  throwIfAborted(signal);
  const failed = dnsFailure(nsRes, 'ns', now());
  const empty = { ns: [], addresses: [], mx: [], nullMx: false };
  if (failed) return { state: 'failed', ...empty, failures: [failed] };
  const ns = uniqSorted(dataOf(nsRes, 'NS').map(cleanName).filter(Boolean));
  if (!ns.length) return { state: 'free', ...empty, failures: [] };
  const [a, aaaa, mx] = await Promise.all([q(candidate.name, 'A'), q(candidate.name, 'AAAA'), q(candidate.name, 'MX')]);
  throwIfAborted(signal);
  const at = now();
  const failures = [dnsFailure(a, 'a', at), dnsFailure(aaaa, 'aaaa', at), dnsFailure(mx, 'mx', at)].filter(Boolean);
  const exchanges = dataOf(mx, 'MX').map((d) => cleanName(d && typeof d === 'object' ? d.exchange : d));
  const nullMx = exchanges.length > 0 && exchanges.every((x) => x === '');
  return {
    state: 'registered',
    ns,
    addresses: [...new Set([...dataOf(a, 'A'), ...dataOf(aaaa, 'AAAA')].map(String))],
    mx: uniqSorted(exchanges.filter(Boolean)),
    nullMx,
    failures
  };
}

/**
 * @typedef {object} LookalikeRdap
 * @property {'ok'|'not-found'|'unsupported'|'failed'} state
 * @property {Date|null} created
 * @property {string|null} registrar
 * @property {object|null} failure a SourceFailure (`source: 'rdap'`) when state is 'failed'
 */

/**
 * The registration date and registrar of a registrable domain (lib/rdap.js, paced per registry).
 * Only an abort rejects.
 * @param {string} domain
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, limit?: Function }} [opts]
 * @returns {Promise<LookalikeRdap>}
 */
export async function lookupRegistration(domain, { fetchImpl = globalThis.fetch, signal, timeoutMs, limit = null } = {}) {
  const r = await rdapDomain(domain, { fetchImpl, signal, limit, ...(timeoutMs ? { timeoutMs } : {}) });
  const out = { state: 'ok', created: null, registrar: null, failure: null };
  if (r.ok) return { ...out, created: r.created || null, registrar: r.registrar || null };
  if (r.notFound) return { ...out, state: 'not-found' };
  if (r.unsupportedTld || r.errorKind === 'unsupported' || r.errorKind === 'invalid') return { ...out, state: 'unsupported' };
  return {
    ...out,
    state: 'failed',
    failure: { source: 'rdap', error: r.error, errorKind: r.errorKind, status: r.httpStatus ?? null, retryAfterMs: r.retryAfterMs ?? null, at: r.failedAt ?? null }
  };
}

/**
 * crt.sh's search for the current certificates naming exactly `name`.
 * @param {string} name
 * @returns {string}
 */
export function crtshLookalikeUrl(name) {
  return `${CRTSH_SEARCH}?q=${encodeURIComponent(name)}&output=json&exclude=expired&deduplicate=Y`;
}

/** The organisation (else the common name) of an issuer DN such as `C=US, O=Let's Encrypt, CN=R11`. */
function issuerName(dn) {
  const s = String(dn ?? '');
  const m = /(?:^|,\s*)O=("([^"]*)"|[^,]*)/.exec(s) || /(?:^|,\s*)CN=("([^"]*)"|[^,]*)/.exec(s);
  return m ? (m[2] ?? m[1]).trim() : '';
}

/**
 * @typedef {object} LookalikeCerts
 * @property {'ok'|'failed'} state
 * @property {number|null} count current certificates (deduplicated by issuer and serial)
 * @property {Date|null} newest the newest one's notBefore
 * @property {string[]} issuers their issuers' organisations, most certificates first (at most 3)
 * @property {object|null} failure a SourceFailure (`source: 'crtsh'`) when state is 'failed'
 */

/**
 * Read crt.sh's JSON rows: current certificates, deduplicated by issuer and serial.
 * @param {unknown} rows
 * @returns {{ count: number, newest: Date|null, issuers: string[] }|null} null when it is no list
 */
export function parseCrtshRows(rows) {
  if (!Array.isArray(rows)) return null;
  const seen = new Set();
  const issuers = new Map();
  let newest = null;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const key = `${r.issuer_ca_id ?? r.issuer_name ?? ''}|${r.serial_number ?? r.id ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const nb = typeof r.not_before === 'string' ? Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(r.not_before) ? r.not_before : `${r.not_before}Z`) : NaN;
    if (Number.isFinite(nb) && (!newest || nb > newest.getTime())) newest = new Date(nb);
    const who = issuerName(r.issuer_name);
    if (who) issuers.set(who, (issuers.get(who) || 0) + 1);
  }
  const top = [...issuers.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 3).map(([k]) => k);
  return { count: seen.size, newest, issuers: top };
}

/**
 * The current certificates of one name in Certificate Transparency (one crt.sh search). Only an
 * abort rejects.
 * @param {string} name
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, now?: () => number }} [opts]
 * @returns {Promise<LookalikeCerts>}
 */
export async function lookupCertificates(name, { fetchImpl = globalThis.fetch, signal, timeoutMs = LOOKALIKE_CT_TIMEOUT_MS, now = Date.now } = {}) {
  const failed = (failure) => ({ state: 'failed', count: null, newest: null, issuers: [], failure });
  try {
    const rows = await fetchJson(crtshLookalikeUrl(name), { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } });
    const parsed = parseCrtshRows(rows === null ? [] : rows);
    if (!parsed) return failed({ source: 'crtsh', error: 'Not a list of certificates', errorKind: 'parse', at: now() });
    return { state: 'ok', ...parsed, failure: null };
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    return failed({
      source: 'crtsh', error: err && err.message ? err.message : String(err), errorKind: errorKind(err),
      status: err && Number.isInteger(err.status) ? err.status : null, retryAfterMs: err && Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : null, at: now()
    });
  }
}

/**
 * The domain's own name servers and addresses, to recognise a candidate that shares them (most
 * often the owner's defensive registration). Failures leave the lists empty.
 * @param {string} domain
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<{ ns: string[], addresses: string[] }>}
 */
export async function targetFootprint(domain, { dns, signal }) {
  throwIfAborted(signal);
  const [ns, a, aaaa] = await Promise.all(['NS', 'A', 'AAAA'].map((type) => dns.query(domain, type, { signal })));
  throwIfAborted(signal);
  return {
    ns: uniqSorted(dataOf(ns, 'NS').map(cleanName).filter(Boolean)),
    addresses: [...new Set([...dataOf(a, 'A'), ...dataOf(aaaa, 'AAAA')].map(String))]
  };
}

/**
 * Check candidates: DNS for each (`concurrency` at a time) and, as each one lands in DNS, RDAP
 * for its registrable domain (once per domain, `rdapConcurrency` at a time; lib/rdap.js paces
 * each registry). Own candidates are skipped. Only an abort rejects.
 * @param {LookalikeCandidate[]} candidates
 * @param {{ dns: { query: Function }, fetchImpl?: typeof fetch, signal?: AbortSignal, noCache?: boolean,
 *   concurrency?: number, rdapConcurrency?: number, rdap?: boolean, now?: () => number,
 *   onDns?: (c: LookalikeCandidate, r: LookalikeDns) => void, onRdap?: (c: LookalikeCandidate, r: LookalikeRdap) => void }} opts
 *   rdap: false skips the registration lookups
 * @returns {Promise<{ checked: number, registered: number, failed: number }>}
 */
export async function checkLookalikes(candidates, {
  dns, fetchImpl = globalThis.fetch, signal, noCache = false, concurrency = LOOKALIKE_CONCURRENCY,
  rdapConcurrency = LOOKALIKE_RDAP_CONCURRENCY, rdap = true, now = Date.now, onDns = null, onRdap = null
}) {
  throwIfAborted(signal);
  const limiter = createLimiter(concurrency);
  const rdapLimiter = createLimiter(rdapConcurrency);
  const registrations = new Map();
  const pendingRdap = [];
  const counts = { checked: 0, registered: 0, failed: 0 };
  const lookUp = (c) => {
    if (!registrations.has(c.registrable)) {
      registrations.set(c.registrable, rdapLimiter.run(() => lookupRegistration(c.registrable, { fetchImpl, signal }), { signal }));
    }
    pendingRdap.push(registrations.get(c.registrable).then((r) => { if (onRdap) onRdap(c, r); }));
  };
  await Promise.all((candidates || []).filter((c) => !c.own).map((c) => limiter.run(async () => {
    const res = await checkCandidate(c, { dns, signal, noCache, now });
    counts.checked += 1;
    if (res.state === 'registered') counts.registered += 1;
    if (res.state === 'failed') counts.failed += 1;
    if (onDns) onDns(c, res);
    if (rdap && res.state === 'registered') lookUp(c);
  }, { signal })));
  await Promise.all(pendingRdap);
  return counts;
}

/* ------------------------------------------------------------------------ */
/* Scoring, order, export                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} LookalikeRow
 * @property {LookalikeCandidate} candidate
 * @property {LookalikeDns|null} dns null until checked
 * @property {LookalikeRdap|null} [rdap]
 * @property {LookalikeCerts|null} [ct]
 */

/**
 * A row's state ({@link LOOKALIKE_STATES}).
 * @param {LookalikeRow} row
 * @returns {string}
 */
export function lookalikeState(row) {
  if (row.candidate.own) return 'own';
  return row.dns ? row.dns.state : 'pending';
}

/**
 * The risk of one row: its level ({@link LOOKALIKE_LEVELS}), its score (0–100; null for a row
 * that is the user's own, not checked yet or failed) and the reasons behind it.
 * @param {LookalikeRow} row
 * @param {{ now?: number, target?: { ns: string[], addresses: string[] }|null }} [opts]
 * @returns {{ level: string, score: number|null, reasons: string[] }}
 */
export function scoreLookalike(row, { now = Date.now(), target = null } = {}) {
  const state = lookalikeState(row);
  if (state === 'own') return { level: 'own', score: null, reasons: [] };
  if (state === 'pending') return { level: 'pending', score: null, reasons: [] };
  if (state === 'failed') return { level: 'unknown', score: null, reasons: [] };
  if (state === 'free') return { level: 'none', score: 0, reasons: [] };
  const { dns, rdap, ct } = row;
  const reasons = [];
  if (dns.mx.length) reasons.push('mx');
  if (dns.addresses.length) reasons.push('web');
  if (rdap && rdap.state === 'ok' && rdap.created instanceof Date) {
    const age = (now - rdap.created.getTime()) / DAY;
    if (age <= LOOKALIKE_NEW_DAYS) reasons.push('new');
    else if (age <= LOOKALIKE_RECENT_DAYS) reasons.push('recent');
  }
  if (ct && ct.state === 'ok' && ct.count > 0) reasons.push('cert');
  if (row.candidate.idn) reasons.push('idn');
  if (target && target.ns.length && dns.ns.length && dns.ns.every((n) => target.ns.includes(n))) reasons.push('same-ns');
  if (target && target.addresses.length && dns.addresses.length && dns.addresses.every((a) => target.addresses.includes(a))) reasons.push('same-ip');
  const raw = reasons.reduce((n, r) => n + RISK_WEIGHTS[r], RISK_WEIGHTS.registered);
  const score = Math.max(1, Math.min(100, raw));
  const level = score >= RISK_THRESHOLDS.high ? 'high' : score >= RISK_THRESHOLDS.medium ? 'medium' : 'low';
  return { level, score, reasons };
}

/**
 * Rows worst first: by level ({@link LOOKALIKE_LEVELS}), then score, then list order.
 * @param {LookalikeRow[]} rows
 * @param {{ now?: number, target?: object|null }} [opts]
 * @returns {LookalikeRow[]} a new array
 */
export function sortLookalikes(rows, opts = {}) {
  const scored = (rows || []).map((row) => ({ row, risk: scoreLookalike(row, opts) }));
  scored.sort((a, b) => LOOKALIKE_LEVELS.indexOf(a.risk.level) - LOOKALIKE_LEVELS.indexOf(b.risk.level)
    || (b.risk.score ?? -1) - (a.risk.score ?? -1)
    || a.row.candidate.index - b.row.candidate.index);
  return scored.map((s) => s.row);
}

/** The CSV columns of {@link lookalikeCsv}. */
export const LOOKALIKE_CSV_COLUMNS = Object.freeze([
  'domain', 'unicode', 'technique', 'state', 'risk', 'score', 'reasons', 'registered', 'registrar', 'addresses', 'mx', 'ns',
  'certificates', 'newestCertificate'
]);

/** The token a failed lookup leaves in an export cell (lib/sourcestatus.js EXPORT_NA). */
const NA = 'n/a';
const day = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : '');

/**
 * One row as the CSV writes it: a failed lookup's cells say "n/a", one never made stays empty.
 * @param {LookalikeRow} row
 * @param {{ now?: number, target?: object|null }} [opts]
 * @returns {Record<string, string|number>}
 */
export function lookalikeExportRow(row, opts = {}) {
  const { candidate: c, dns, rdap, ct } = row;
  const risk = scoreLookalike(row, opts);
  const failedField = (lookup) => !!(dns && dns.failures.some((f) => f.lookup === lookup || f.lookup === 'ns'));
  const reg = dns && dns.state === 'registered';
  const field = (lookups, value) => (dns && dns.state === 'failed' ? NA : lookups.some(failedField) ? NA : value);
  return {
    domain: c.name,
    unicode: c.unicode,
    technique: c.technique,
    state: lookalikeState(row),
    risk: risk.level,
    score: risk.score ?? '',
    reasons: risk.reasons.join(' '),
    registered: rdap ? (rdap.state === 'failed' ? NA : day(rdap.created)) : '',
    registrar: rdap ? (rdap.state === 'failed' ? NA : rdap.registrar || '') : '',
    addresses: reg || (dns && dns.state === 'failed') ? field(['a', 'aaaa'], dns.addresses.join(' ')) : '',
    mx: reg || (dns && dns.state === 'failed') ? field(['mx'], dns.mx.join(' ')) : '',
    ns: dns ? (dns.state === 'failed' ? NA : dns.ns.join(' ')) : '',
    certificates: ct ? (ct.state === 'failed' ? NA : ct.count) : '',
    newestCertificate: ct ? (ct.state === 'failed' ? NA : day(ct.newest)) : ''
  };
}

/**
 * The rows as CSV (lib/export.js toCsv: RFC 4180, a BOM, formula-safe cells), worst first.
 * @param {LookalikeRow[]} rows
 * @param {{ now?: number, target?: object|null }} [opts]
 * @returns {string}
 */
export function lookalikeCsv(rows, opts = {}) {
  return toCsv(sortLookalikes(rows, opts).map((r) => lookalikeExportRow(r, opts)), LOOKALIKE_CSV_COLUMNS.map((key) => ({ key })));
}
