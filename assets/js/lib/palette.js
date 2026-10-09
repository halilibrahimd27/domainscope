/**
 * palette.js — the command palette's search (Ctrl/Cmd+K, ui/palette.js): what a typed text is
 * (a domain or host name, an IP address, a network, an AS number, a pasted certificate), the
 * actions it offers on it, and how the tools rank against the words typed, with a Turkish-safe
 * case folding (`İ`, `I`, `ı` and `i` are one letter; `ç ğ ö ş ü` match `c g o s u`).
 *
 * DOM-free, storage-free and i18n-free: the panel hands in the tools (the view registry with
 * their titles and descriptions in both languages), the actions' labels, the workspace's recent
 * domains and the current target, and turns the codes this returns into words. Every route it
 * builds only fills a tool's form (`run=0`, lib/session.js fillRoute): choosing an entry opens a
 * tool with the value in its box and sends nothing.
 */

import { parseTarget, fillRoute, FILL_PARAM, FILL_VALUE } from './session.js';
import { normalizeIP, parseCidr } from './ip.js';

/** Kinds of subject a typed text can be ({@link parseSubject}). */
export const SUBJECT_KINDS = Object.freeze(['domain', 'host', 'ip', 'cidr', 'asn', 'cert']);

/** Kinds of palette entry: an action on the subject, a tool, a recent domain, the current target. */
export const ENTRY_TYPES = Object.freeze(['action', 'tool', 'recent', 'target']);

/**
 * The actions a subject offers, in display order: `id` names the label key `pal.act.<id>`;
 * `view` is the tool; `kinds` the subjects it takes; `params` extra route params (Lookup's record
 * type); `param` the route param of a tool without a TARGET_ROUTES entry (Reverse DNS's `target`).
 * The Certificate action has no route: the panel reads the pasted text into the Certificate view.
 */
export const PALETTE_ACTIONS = Object.freeze([
  { id: 'subdomains', view: 'subdomains', kinds: ['domain', 'host'] },
  { id: 'domain', view: 'domain', kinds: ['domain', 'host'] },
  { id: 'health', view: 'health', kinds: ['domain', 'host'] },
  { id: 'lookupMx', view: 'lookup', kinds: ['domain', 'host'], params: { type: 'MX' } },
  { id: 'lookupTxt', view: 'lookup', kinds: ['domain', 'host'], params: { type: 'TXT' } },
  { id: 'lookupCaa', view: 'lookup', kinds: ['domain', 'host'], params: { type: 'CAA' } },
  { id: 'global', view: 'global', kinds: ['domain', 'host'] },
  { id: 'renew', view: 'renew', kinds: ['domain', 'host'] },
  { id: 'ip', view: 'ip', kinds: ['ip'] },
  { id: 'reverseIp', view: 'ip', kinds: ['ip'] },
  { id: 'ptr', view: 'ptr', kinds: ['ip'], param: 'target' },
  { id: 'retire', view: 'retire', kinds: ['ip'] },
  { id: 'sweep', view: 'ptr', kinds: ['cidr', 'asn'], param: 'target' },
  { id: 'cert', view: 'cert', kinds: ['cert'] }
].map((a) => Object.freeze({ ...a, kinds: Object.freeze(a.kinds), params: Object.freeze({ ...(a.params || {}) }) })));

/** The action ids (`pal.act.<id>` label keys). */
export const ACTION_IDS = Object.freeze(PALETTE_ACTIONS.map((a) => a.id));

/**
 * Words each tool is also found by, besides its titles and descriptions in both languages: the
 * protocol and command names people type (language-neutral, never shown).
 */
export const TOOL_KEYWORDS = Object.freeze({
  subdomains: 'subdomain crt ct passive enumerate',
  domain: 'overview whois rdap migration takeover',
  zone: 'zone bind axfr import cloudflare route53',
  scan: 'ssl tls targets install',
  cert: 'certificate pem x509 der pfx p12 csr chain',
  renew: 'acme letsencrypt dns-01 http-01 caa renewal',
  estate: 'estate json cli report',
  global: 'propagation resolvers worldwide',
  lookup: 'dig nslookup query record mx txt caa ns soa',
  bulk: 'bulk resolve many hostnames',
  change: 'change request ticket terraform octodns',
  ip: 'ip asn geo owner cdn whois',
  ptr: 'ptr reverse sweep rdns',
  retire: 'retire decommission renumber',
  health: 'health spf dmarc dkim mx dnssec',
  reports: 'dmarc rua tls-rpt reports',
  portfolio: 'portfolio expiry registrar',
  monitor: 'monitor history trend nightly runner github results jsonl',
  inventory: 'servers inventory csv',
  about: 'about help privacy sources cli'
});

/** The most entries {@link paletteResults} returns. */
export const MAX_ENTRIES = 40;

/** A PEM certificate block (the Certificate view reads it; lib/x509.js CERT_PEM_RE). */
const CERT_PEM_RE = /-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----/;
/** An AS number as Reverse DNS takes it (lib/ptrsweep.js parseAsn): AS64496, ASN 64496. */
const ASN_RE = /^AS(?:N)?\s?(\d{1,10})$/i;
const MAX_ASN = 4294967295;

/* ------------------------------------------------------------------------ */
/* Case folding                                                             */
/* ------------------------------------------------------------------------ */

/** Letters whose lower case is wrong for Turkish or English alone: the four i's are one letter. */
const I_LETTERS = new Set(['İ', 'I', 'ı', 'i']);

/**
 * Fold a text for matching, with where each folded character came from: lower case without
 * diacritics, the same in Turkish and English (`İSTANBUL`, `Istanbul` and `ıstanbul` all give
 * `istanbul`; `Sağlığı` gives `sagligi`). `map[i]` is the index in `text` of the character folded
 * character `i` came from, and `map[folded.length]` is `text.length`.
 * @param {unknown} text
 * @returns {{ folded: string, map: number[] }}
 */
export function foldWithMap(text) {
  const s = String(text ?? '');
  let folded = '';
  const map = [];
  let i = 0;
  for (const ch of s) {
    const f = I_LETTERS.has(ch) ? 'i' : ch.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
    for (const c of f) {
      folded += c;
      map.push(i);
    }
    i += ch.length;
  }
  map.push(s.length);
  return { folded, map };
}

/**
 * Fold a text for matching ({@link foldWithMap}).
 * @param {unknown} text
 * @returns {string}
 */
export function foldText(text) {
  return foldWithMap(text).folded;
}

/* ------------------------------------------------------------------------ */
/* Matching                                                                 */
/* ------------------------------------------------------------------------ */

const isWordStart = (text, i) => i === 0 || !/[\p{L}\p{N}]/u.test(text[i - 1]);

/**
 * Where the letters of `word` appear in order in `text`, each as early as possible; with
 * `preferStarts`, a letter skips ahead to the start of a word when one follows (unless it can
 * go right after the previous letter). Null when they do not all appear.
 * @param {string} word
 * @param {string} text
 * @param {boolean} preferStarts
 * @returns {number[]|null}
 */
function subsequence(word, text, preferStarts) {
  const positions = [];
  let from = 0;
  for (const c of word) {
    let hit = -1;
    for (let k = from; k < text.length; k++) {
      if (text[k] !== c) continue;
      if (hit === -1) hit = k;
      if (!preferStarts || isWordStart(text, k)) {
        hit = preferStarts ? k : hit;
        break;
      }
      if (positions.length && k === positions[positions.length - 1] + 1) break;
    }
    if (hit === -1) return null;
    positions.push(hit);
    from = hit + 1;
  }
  return positions;
}

/**
 * How well one folded word matches a folded text, or null: 1 the text starts with it, 0.85 one of
 * its words does, 0.6 it is inside a word (unless `inside` is false: a description, where that
 * finds noise), and for a `fuzzy` text (a title) 0.3–0.55 when its letters appear in order. A
 * one-letter word matches only the start of a word.
 * @param {string} word folded, not empty
 * @param {string} text folded
 * @param {{ fuzzy?: boolean, inside?: boolean }} [opts]
 * @returns {{ score: number, positions: number[] }|null} `positions`: the matched characters of `text`
 */
export function matchWord(word, text, { fuzzy = false, inside: within = true } = {}) {
  if (!word || !text) return null;
  const span = (at) => Array.from({ length: word.length }, (_, k) => at + k);
  if (text.startsWith(word)) return { score: 1, positions: span(0) };
  let at = text.indexOf(word);
  let inside = -1;
  while (at !== -1) {
    if (isWordStart(text, at)) return { score: 0.85, positions: span(at) };
    if (inside === -1) inside = at;
    at = text.indexOf(word, at + 1);
  }
  if (word.length < 2) return null;
  if (inside !== -1 && within) return { score: 0.6, positions: span(inside) };
  if (!fuzzy) return null;
  const positions = subsequence(word, text, true) || subsequence(word, text, false);
  if (!positions) return null;
  const spread = positions[positions.length - 1] - positions[0] + 1;
  const starts = positions.filter((p) => isWordStart(text, p)).length;
  const score = 0.3 + 0.15 * (word.length / spread) + 0.1 * (starts / word.length);
  return { score: Math.min(0.55, score), positions };
}

/**
 * The words of a query, folded, in order, each once.
 * @param {unknown} text
 * @returns {string[]}
 */
export function queryWords(text) {
  return [...new Set(foldText(text).split(/\s+/).filter(Boolean))];
}

/** Field weights: a title in the language on screen counts most, a description in the other least. */
const WEIGHTS = Object.freeze({ title: 1, altTitle: 0.9, keywords: 0.8, desc: 0.5, altDesc: 0.45 });

/**
 * Score a searchable entry against folded words: every word must match one of its fields (a
 * description only at the start of one of its words); the score is the sum of each word's best
 * field match times the field's weight.
 * @param {string[]} words folded ({@link queryWords})
 * @param {{ title?: string, altTitle?: string, keywords?: string, desc?: string, altDesc?: string }} fields
 *   plain texts (folded here)
 * @returns {{ score: number, title: number[] }|null} `title`: the matched characters of the folded title
 */
export function scoreFields(words, fields) {
  const folded = {};
  for (const k of Object.keys(WEIGHTS)) folded[k] = foldText(fields[k] || '');
  let score = 0;
  const title = new Set();
  for (const word of words) {
    let best = null;
    for (const [k, w] of Object.entries(WEIGHTS)) {
      const m = matchWord(word, folded[k], { fuzzy: k === 'title' || k === 'altTitle', inside: k !== 'desc' && k !== 'altDesc' });
      if (m && (!best || m.score * w > best.score)) best = { score: m.score * w, key: k, positions: m.positions };
    }
    if (!best) return null;
    score += best.score;
    if (best.key === 'title') for (const p of best.positions) title.add(p);
  }
  return { score, title: [...title].sort((a, b) => a - b) };
}

/**
 * Turn matched positions of a folded text into ranges of the original text, for highlighting.
 * @param {string} text the original text
 * @param {number[]} positions sorted positions in `foldText(text)`
 * @returns {Array<[number, number]>} [start, end) ranges, merged where they touch
 */
export function highlightRanges(text, positions) {
  const { map } = foldWithMap(text);
  const ranges = [];
  for (const p of positions || []) {
    if (p < 0 || p >= map.length - 1) continue;
    const start = map[p];
    let end = map[p + 1];
    if (end === start) end = start + 1;
    const last = ranges[ranges.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else ranges.push([start, end]);
  }
  return ranges;
}

/* ------------------------------------------------------------------------ */
/* Subjects                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * A network in CIDR notation (`192.0.2.0/24`, `2001:db8::/48`), its address as typed (Reverse DNS
 * says so when host bits are set), or null; a bare address (no prefix) is no network.
 * @param {string} token
 * @returns {string|null}
 */
function cidrOf(token) {
  if (!token.includes('/')) return null;
  const [addr, prefix] = token.split('/');
  const ip = normalizeIP(addr);
  const parsed = ip ? parseCidr(token) : null;
  if (!parsed || !/^\d{1,3}$/.test(prefix)) return null;
  return `${ip}/${parsed.prefix}`;
}

/**
 * An AS number (`AS64496`, `as64496`, `ASN 64496`) as `AS64496`, or null.
 * @param {string} token
 * @returns {string|null}
 */
function asnOf(token) {
  const m = ASN_RE.exec(token.trim());
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isInteger(n) && n > 0 && n <= MAX_ASN ? `AS${n}` : null;
}

/**
 * The one token of a word list that is a subject.
 * @param {string} token
 * @returns {{ kind: string, value: string }|null}
 */
function tokenSubject(token) {
  const cidr = cidrOf(token);
  if (cidr) return { kind: 'cidr', value: cidr };
  const asn = asnOf(token);
  if (asn) return { kind: 'asn', value: asn };
  if (!/[.:]/.test(token)) return null; // a single word is a word, never a name
  const target = parseTarget(token);
  return target ? { kind: target.kind, value: target.value } : null;
}

/**
 * What a typed text is about: a pasted certificate (the whole text), else the first word that is
 * a network, an AS number, an IP address, a domain or a host name (URLs and ports are read as
 * lib/session.js parseTarget reads them); the other words then rank the actions.
 * @param {unknown} text
 * @returns {{ subject: { kind: string, value: string }|null, words: string[] }} `value` of a
 *   certificate is the pasted text; `words` are folded
 */
export function parseSubject(text) {
  const raw = String(text ?? '').trim();
  if (!raw) return { subject: null, words: [] };
  if (CERT_PEM_RE.test(raw)) return { subject: { kind: 'cert', value: raw }, words: [] };
  const whole = asnOf(raw);
  if (whole) return { subject: { kind: 'asn', value: whole }, words: [] };
  const tokens = raw.split(/\s+/);
  for (let i = 0; i < tokens.length; i++) {
    const subject = tokenSubject(tokens[i]);
    if (subject) return { subject, words: queryWords(tokens.filter((_, k) => k !== i).join(' ')) };
  }
  return { subject: null, words: queryWords(raw) };
}

/**
 * The route params that open an action's tool with the subject filled in and nothing run, or
 * null when the tool does not take it (and for the Certificate action, which has no route).
 * @param {{ view: string, kinds: readonly string[], params: Record<string, string>, param?: string }} action
 * @param {{ kind: string, value: string }} subject
 * @returns {Record<string, string>|null}
 */
export function actionRoute(action, subject) {
  if (!action || !subject || !action.kinds.includes(subject.kind) || subject.kind === 'cert') return null;
  const base = action.param ? { [action.param]: subject.value, [FILL_PARAM]: FILL_VALUE } : fillRoute(action.view, subject);
  return base ? { ...base, ...action.params } : null;
}

/* ------------------------------------------------------------------------ */
/* Results                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} PaletteTool
 * @property {string} id the view id
 * @property {string} title its title in the language on screen
 * @property {string} [altTitle] in the other language
 * @property {string} [desc] its description in the language on screen
 * @property {string} [altDesc] in the other language
 */

/**
 * @typedef {object} PaletteEntry
 * @property {'action'|'tool'|'recent'|'target'} type
 * @property {string} key unique among the entries (`action:health`, `tool:lookup`, `recent:example.com`)
 * @property {string} [id] the action's or tool's id
 * @property {string} [view] the tool it opens
 * @property {Record<string, string>|null} [params] the fill-only route params (actions)
 * @property {string} [value] the subject's value (actions), the domain (recent, target)
 * @property {number[]} [title] the matched characters of the folded tool title (tools)
 */

/** The most recent domains an empty box offers. */
export const MAX_RECENT = 5;

/**
 * The palette's entries for a typed text, best first:
 * - a subject ({@link parseSubject}): its actions, those matching the other words first (by their
 *   labels in `actionLabels`, the record type and their tool's titles), each with its fill-only
 *   route;
 * - an empty box: the current target, the recent domains ({@link MAX_RECENT}; choosing one puts
 *   it in the box, and its actions follow), then every tool in registry order;
 * - words: the tools matching them ({@link scoreFields}), then the recent domains that contain
 *   the text.
 * @param {{ query?: string, tools?: PaletteTool[], actionLabels?: Record<string, string[]>,
 *   recent?: string[], target?: { value: string, kind?: string }|null, max?: number }} input
 *   `actionLabels[id]`: the action's label in the language on screen and in the other one,
 *   without the subject
 * @returns {{ subject: { kind: string, value: string }|null, entries: PaletteEntry[] }}
 */
export function paletteResults({ query = '', tools = [], actionLabels = {}, recent = [], target = null, max = MAX_ENTRIES } = {}) {
  const { subject, words } = parseSubject(query);
  const toolById = new Map((tools || []).map((tool) => [tool.id, tool]));
  const entries = [];
  if (subject) {
    const actions = PALETTE_ACTIONS.filter((a) => a.kinds.includes(subject.kind)).map((a, order) => {
      const labels = actionLabels[a.id] || [];
      const tool = toolById.get(a.view) || {};
      const m = words.length ? scoreFields(words, {
        title: labels[0], altTitle: labels[1], keywords: `${a.params.type || ''} ${TOOL_KEYWORDS[a.view] || ''}`, desc: tool.title, altDesc: tool.altTitle
      }) : null;
      return { a, order, score: m ? m.score : 0 };
    });
    actions.sort((x, y) => y.score - x.score || x.order - y.order);
    for (const { a } of actions) {
      entries.push({ type: 'action', key: `action:${a.id}`, id: a.id, view: a.view, params: actionRoute(a, subject), value: subject.value });
    }
  }
  const empty = !subject && !words.length;
  const recentEntries = [];
  if (!subject) {
    const text = foldText(String(query ?? '').trim());
    const seen = new Set();
    if (empty && target && typeof target.value === 'string' && target.value) {
      seen.add(target.value);
      entries.push({ type: 'target', key: `target:${target.value}`, value: target.value });
    }
    for (const value of recent || []) {
      if (typeof value !== 'string' || !value || seen.has(value)) continue;
      seen.add(value);
      if (!empty && !foldText(value).includes(text)) continue;
      recentEntries.push({ type: 'recent', key: `recent:${value}`, value });
    }
    if (empty) entries.push(...recentEntries.splice(0, MAX_RECENT));
  }
  const ranked = [];
  (tools || []).forEach((tool, order) => {
    if (empty) {
      ranked.push({ tool, order, score: 0, title: [] });
      return;
    }
    // Next to a subject the words rank its actions only: a tool opened from here would not take it.
    const m = !subject && words.length ? scoreFields(words, { ...tool, keywords: TOOL_KEYWORDS[tool.id] || '' }) : null;
    if (m) ranked.push({ tool, order, score: m.score, title: m.title });
  });
  ranked.sort((x, y) => y.score - x.score || x.order - y.order);
  for (const { tool, title } of ranked) entries.push({ type: 'tool', key: `tool:${tool.id}`, id: tool.id, view: tool.id, title });
  if (!empty) entries.push(...recentEntries);
  return { subject, entries: entries.slice(0, Math.max(0, max)) };
}
