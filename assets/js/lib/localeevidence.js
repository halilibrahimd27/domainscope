/**
 * localeevidence.js — adaptive locale packs (ROADMAP P1.9): which market wordlist packs
 * (assets/data/locale/<cc>.txt) a domain gets when its TLD names no market (`.com`, `.net`,
 * `.io` …), read from what a scan already knows about it instead of none.
 *
 * The evidence, scored per pack:
 *  - words — the labels of the names found so far (passive sources, the zone's own records, the
 *    certificate, the zone file, the names typed, the domain's own labels) read against each
 *    pack's distinctive vocabulary: its words of four letters or more that are in no global list
 *    (lib/wordlist.js WORDLIST_MEDIUM) and are no English or international word
 *    ({@link NEUTRAL_WORDS}). A label matches whole (`e-fatura`), by its letter runs (`musteri` in
 *    `musteri-portal2`), or as a compound of two pack words or of a pack word and a global one
 *    (`bayisiparis`, `destekapi`, `lohnportal`). Each distinct word counts once — 1 with five
 *    letters or more, ½ with four — shared between the packs that have it; over
 *    {@link LOCALE_EVIDENCE_VOLUME} distinct labels the sum is scaled by VOLUME / labels, so the
 *    chance matches of a large zone stay weak.
 *  - letters — an IDN label (`xn--…`) written in a script or with letters only one pack's
 *    language uses ({@link SCRIPT_HINTS}: Turkish ı ş ğ, German ß ä, Spanish ñ, Portuguese ã õ,
 *    Polish ą ć ę ł ń ś ź ż, French œ, Italian ì ò; Cyrillic → ru, Arabic → ar, kana → ja, Han
 *    without kana → zh): 1 per label, at most {@link LOCALE_EVIDENCE_MAX_LETTERS}; its
 *    ASCII-folded form (`şube` → `sube`) is read as words too.
 *  - name servers, mail servers — the country-code TLD of the zone's NS and MX hosts: 2 when at
 *    least half of their registrable domains are in that market, 1 when some are. Providers that
 *    serve every market from one ccTLD ({@link GLOBAL_HOST_DOMAINS}) and a bare `.co` / `.ly`
 *    ({@link GENERIC_CCTLDS}, used worldwide) say nothing.
 * A pack is picked with {@link LOCALE_EVIDENCE_MIN} points or more and at least
 * {@link LOCALE_EVIDENCE_RELATIVE} of the strongest pack's points; at most
 * LOCALE_EVIDENCE_MAX_PACKS (lib/wordlist.js), strongest first. lib/wordlist.js
 * `localesForDomain(domain, evidence)` applies the choice — the TLD always wins — and
 * lib/scanner.js collects the evidence just before its wordlist stage.
 *
 * DOM-free, no I/O: the packs' labels come in (`packs`, lib/wordlist.js loadLocaleVocabulary).
 */

import { normalizeHostname, registrableDomain, isSubdomainOf, sortHostnames } from './domain.js';
import { WORDLIST_MEDIUM, LOCALE_PACK_CODES, LOCALE_EVIDENCE_MAX_PACKS, localesForDomain } from './wordlist.js';
import { punycodeDecode } from './punycode.js';

/** Points a pack needs to be picked. */
export const LOCALE_EVIDENCE_MIN = 2;
/** Share of the strongest pack's points another pack needs as well. */
export const LOCALE_EVIDENCE_RELATIVE = 0.5;
/** Distinct labels read before the word points are scaled down (VOLUME / labels). */
export const LOCALE_EVIDENCE_VOLUME = 400;
/** Points the letters of IDN labels can give one pack at most. */
export const LOCALE_EVIDENCE_MAX_LETTERS = 2;
/** Examples a signal keeps (words, IDN labels) for the explanation. */
export const LOCALE_EVIDENCE_EXAMPLES = 8;

/**
 * Pack words that are English or international words too (`hotel`, `campus`, `personal`,
 * `planning` …), so they say nothing about a market. With lib/wordlist.js WORDLIST_MEDIUM (the
 * global tech vocabulary: `portal`, `support`, `shop`, `crm` …) they are the "known" words a
 * compound may join a pack word with.
 */
export const NEUTRAL_WORDS = Object.freeze([
  'administration', 'agenda', 'analyses', 'archives', 'assistance', 'basin', 'boutique', 'burger', 'campus', 'candidature',
  'commune', 'consultation', 'contract', 'crmpanel', 'dealer', 'dealers', 'documents', 'dossier', 'dossiers', 'expedition',
  'fare', 'finances', 'formation', 'formations', 'garage', 'holding', 'hotel', 'hurt', 'inscription', 'labor', 'laden', 'lager',
  'marches', 'menu', 'messages', 'mypage', 'notes', 'notifications', 'paragon', 'partnerportal', 'patient', 'patients',
  'personal', 'personnel', 'pieces', 'planning', 'praxis', 'prefecture', 'promotions', 'reclamation', 'rendez-vous',
  'rendezvous', 'reservation', 'reservations', 'restaurant', 'school', 'siege', 'sites', 'stan', 'stocks', 'student',
  'taller', 'tender', 'tickets', 'transport', 'voyage', 'voyages', 'webshop'
]);

/**
 * Registrable domains whose name or mail servers serve customers in every market from one
 * country-code TLD, so their ending says nothing about the domain's market: Proton Mail and Tuta
 * (mail), IONOS's and Hetzner's name servers (every customer gets a `.de` one among them).
 */
export const GLOBAL_HOST_DOMAINS = Object.freeze([
  'protonmail.ch', 'proton.ch', 'tutanota.de', 'ui-dns.de', 'hetzner.de', 'first-ns.de', 'second-ns.de'
]);

/** Country-code TLDs used worldwide as generic endings (a host directly under them says nothing). */
export const GENERIC_CCTLDS = Object.freeze(['co', 'ly']);

/**
 * Letters and scripts of an IDN label that point to one pack's language (`ç`, `ö`, `ü`, `é` …
 * are shared by several and point nowhere). Han without kana is Chinese ({@link labelLetters}).
 */
export const SCRIPT_HINTS = Object.freeze([
  ['tr', /[ışğ]|i\u0307/u],
  ['de', /[ßä]/u],
  ['es', /ñ/u],
  ['pt', /[ãõ]/u],
  ['pl', /[ąćęłńśźż]/u],
  ['fr', /œ/u],
  ['it', /[ìò]/u],
  ['ru', /\p{Script=Cyrillic}/u],
  ['ar', /\p{Script=Arabic}/u],
  ['ja', /[\p{Script=Hiragana}\p{Script=Katakana}]/u]
]);

/** Global words: the known half of a compound, never evidence. */
const KNOWN = new Set([...WORDLIST_MEDIUM, ...NEUTRAL_WORDS]);
const GLOBAL_HOSTS = new Set(GLOBAL_HOST_DOMAINS);
const GENERIC = new Set(GENERIC_CCTLDS);
const ASCII_RE = /^[a-z0-9-]+$/;
const LETTER_RUN_RE = /[a-z]+/g;
const HAN_RE = /\p{Script=Han}/u;
const FOLD_SPECIAL = { ı: 'i', ł: 'l', ß: 'ss', ø: 'o', æ: 'ae', œ: 'oe', đ: 'd', ð: 'd', þ: 'th' };
const round2 = (n) => Math.round(n * 100) / 100;

/* ------------------------------------------------------------------------ */
/* Vocabulary                                                               */
/* ------------------------------------------------------------------------ */

const vocabularyCache = new WeakMap();

/**
 * The distinctive words of the packs: word → the codes of the packs that have it (pack order).
 * Words shorter than four characters, global words (WORDLIST_MEDIUM) and {@link NEUTRAL_WORDS}
 * are left out. Cached per `packs` object.
 * @param {Record<string, string[]>} packs pack code → its labels (lib/wordlist.js loadLocaleVocabulary)
 * @returns {Map<string, string[]>}
 */
export function localeVocabulary(packs) {
  if (!packs || typeof packs !== 'object') return new Map();
  if (vocabularyCache.has(packs)) return vocabularyCache.get(packs);
  const vocab = new Map();
  for (const cc of LOCALE_PACK_CODES) {
    const list = Array.isArray(packs[cc]) ? packs[cc] : [];
    for (const raw of list) {
      const w = String(raw ?? '').trim().toLowerCase();
      if (w.length < 4 || !ASCII_RE.test(w) || KNOWN.has(w)) continue;
      const owners = vocab.get(w);
      if (!owners) vocab.set(w, [cc]);
      else if (!owners.includes(cc)) owners.push(cc);
    }
  }
  vocabularyCache.set(packs, vocab);
  return vocab;
}

/* ------------------------------------------------------------------------ */
/* Labels                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The Unicode form of one label: an `xn--` label decoded (NFC, lower case), any other as is;
 * null for a punycode label that does not decode.
 * @param {string} label
 * @returns {string|null}
 */
export function unicodeLabel(label) {
  const s = String(label ?? '').toLowerCase();
  if (!s.startsWith('xn--')) return s;
  const u = punycodeDecode(s.slice(4));
  return u ? u.normalize('NFC').toLowerCase() : null;
}

/**
 * The ASCII forms a Unicode label is read as, the way the packs are folded: the letters'
 * accents dropped (`şube` → `sube`, `müşteri` → `musteri`) and, when it has ä / ö / ü, the
 * German spelling too (`prüfung` → `pruefung`). Only forms that are a valid ASCII label.
 * @param {string} text a Unicode label
 * @returns {string[]}
 */
export function foldLabel(text) {
  const s = String(text ?? '').toLowerCase();
  const plain = (v) => v.replace(/[ıłßøæœđðþ]/g, (c) => FOLD_SPECIAL[c]).normalize('NFD').replace(/\p{M}/gu, '');
  const out = [plain(s)];
  if (/[äöü]/.test(s)) out.push(plain(s.replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue')));
  return [...new Set(out)].filter((v) => v && ASCII_RE.test(v));
}

/**
 * The packs whose language an IDN label's letters point to ({@link SCRIPT_HINTS}; Han without
 * kana → zh). [] for an ASCII label.
 * @param {string} text a Unicode label
 * @returns {string[]}
 */
export function labelLetters(text) {
  const s = String(text ?? '');
  if (ASCII_RE.test(s)) return [];
  const out = SCRIPT_HINTS.filter(([, re]) => re.test(s)).map(([cc]) => cc);
  if (HAN_RE.test(s) && !out.includes('ja')) out.push('zh');
  return out;
}

/**
 * A run of letters as two parts: two pack words (`bayi` + `siparis`), or a pack word and a
 * global one — the pack word five letters or more next to a global word of three, or both four
 * or more (`destek` + `api`, `lohn` + `portal`, `api` + `destek`). The longest first part wins.
 * [] when there is none.
 * @param {string} token a run of letters
 * @param {Map<string, string[]>} vocab
 * @returns {string[]} the pack words of the split
 */
function splitCompound(token, vocab) {
  const fits = (word, other) => (word.length >= 5 && other.length >= 3) || (word.length >= 4 && other.length >= 4);
  for (let i = token.length - 3; i >= 3; i -= 1) {
    const a = token.slice(0, i);
    const b = token.slice(i);
    const va = vocab.has(a);
    const vb = vocab.has(b);
    if (va && vb) return [a, b];
    if (va && KNOWN.has(b) && fits(a, b)) return [a];
    if (vb && KNOWN.has(a) && fits(b, a)) return [b];
  }
  return [];
}

/**
 * The pack words one ASCII label carries: the whole label, else its letter runs of four or
 * more, each whole or as a compound ({@link splitCompound}). A global word never counts.
 * @param {string} label lower case ASCII
 * @param {Map<string, string[]>} vocab
 * @returns {string[]}
 */
export function labelWords(label, vocab) {
  const s = String(label ?? '').toLowerCase();
  if (!s || !vocab || !vocab.size) return [];
  if (vocab.has(s)) return [s];
  if (KNOWN.has(s)) return [];
  const out = [];
  for (const run of s.match(LETTER_RUN_RE) || []) {
    if (run.length < 4 || KNOWN.has(run)) continue;
    if (vocab.has(run)) out.push(run);
    else if (run.length >= 7) out.push(...splitCompound(run, vocab));
  }
  return [...new Set(out)];
}

/**
 * The labels of a name under `domain` (left of it), or of the domain itself left of its public
 * suffix (`shop.example.com.tr` → shop, example). [] for a name outside the domain.
 * @param {string} name
 * @param {string} domain
 * @returns {string[]}
 */
function ownLabels(name, domain) {
  if (name === domain) {
    const reg = registrableDomain(domain) || domain;
    const dot = reg.indexOf('.');
    const suffix = dot === -1 ? '' : reg.slice(dot + 1);
    const left = suffix && domain.endsWith(`.${suffix}`) ? domain.slice(0, domain.length - suffix.length - 1) : '';
    return left ? left.split('.') : [];
  }
  if (!isSubdomainOf(name, domain)) return [];
  return name.slice(0, name.length - domain.length - 1).split('.');
}

/* ------------------------------------------------------------------------ */
/* Name and mail servers                                                     */
/* ------------------------------------------------------------------------ */

/**
 * The packs a server host's country-code TLD names (lib/wordlist.js localesForDomain of its
 * registrable domain), none for a provider that serves every market ({@link GLOBAL_HOST_DOMAINS})
 * or a host directly under a generic-in-practice ccTLD ({@link GENERIC_CCTLDS}: `dns.example.co`
 * says nothing, `ns1.example.com.co` is Colombian).
 * @param {string} host
 * @returns {string[]}
 */
export function hostLocales(host) {
  const n = normalizeHostname(String(host ?? ''));
  if (!n) return [];
  const reg = registrableDomain(n) || n;
  if (GLOBAL_HOSTS.has(reg)) return [];
  const dot = reg.indexOf('.');
  if (dot !== -1 && GENERIC.has(reg.slice(dot + 1))) return [];
  return localesForDomain(reg);
}

/**
 * The servers of one kind: their distinct registrable domains and, per pack, how many of them
 * are in its market and their endings (`.com.tr`).
 * @param {string[]} hosts
 * @returns {{ domains: string[], byLocale: Map<string, { count: number, endings: string[] }> }}
 */
function serverSignal(hosts) {
  const domains = [];
  for (const raw of Array.isArray(hosts) ? hosts : []) {
    const n = normalizeHostname(String(raw ?? ''));
    if (!n) continue;
    const reg = registrableDomain(n) || n;
    if (!domains.includes(reg)) domains.push(reg);
  }
  const byLocale = new Map();
  for (const reg of domains) {
    const dot = reg.indexOf('.');
    const ending = dot === -1 ? `.${reg}` : reg.slice(dot);
    for (const cc of hostLocales(reg)) {
      if (!byLocale.has(cc)) byLocale.set(cc, { count: 0, endings: [] });
      const entry = byLocale.get(cc);
      entry.count += 1;
      if (!entry.endings.includes(ending)) entry.endings.push(ending);
    }
  }
  return { domains, byLocale };
}

/** 2 when at least half of the servers are in the market, 1 when some are. */
function serverPoints(entry, total) {
  if (!entry || !total) return 0;
  return entry.count / total >= 0.5 ? 2 : 1;
}

/* ------------------------------------------------------------------------ */
/* The choice                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} LocaleSignal
 * @property {string} locale pack code
 * @property {number} score points (two decimals)
 * @property {boolean} picked
 * @property {{ words: number, letters: number, ns: number, mx: number }} points
 * @property {string[]} words the pack words found, first seen first (at most {@link LOCALE_EVIDENCE_EXAMPLES})
 * @property {number} wordCount every distinct pack word found
 * @property {string[]} letters the IDN labels (Unicode) whose letters point to it (at most {@link LOCALE_EVIDENCE_EXAMPLES})
 * @property {string[]} ns endings of the name servers in its market (`.com.tr`)
 * @property {string[]} mx endings of the mail servers in its market
 */

/**
 * @typedef {object} LocaleEvidence
 * @property {string} domain
 * @property {string[]} locales the packs picked, strongest first ([] when none reached the bar)
 * @property {LocaleSignal[]} signals every pack with any evidence, strongest first
 * @property {number} names names read (the domain itself included)
 * @property {number} labels distinct labels read
 * @property {number} ns name-server registrable domains read
 * @property {number} mx mail-server registrable domains read
 */

/**
 * The locale packs the evidence points to for one domain (see the module comment).
 * @param {object} input
 * @param {string} input.domain the domain (the brute-force base) the names sit under
 * @param {string[]} [input.names] names found so far (any; those outside the domain are ignored)
 * @param {string[]} [input.ns] the zone's name-server hosts
 * @param {string[]} [input.mx] the zone's mail-server hosts
 * @param {Record<string, string[]>} [input.packs] pack code → labels; without it the words say nothing
 * @returns {LocaleEvidence}
 */
export function localeEvidence({ domain, names = [], ns = [], mx = [], packs = null } = {}) {
  const apex = normalizeHostname(String(domain ?? ''), { allowSingleLabel: true }) || '';
  const vocab = localeVocabulary(packs);
  const signals = new Map();
  const signal = (cc) => {
    if (!signals.has(cc)) {
      signals.set(cc, { locale: cc, words: [], wordCount: 0, wordPoints: 0, letters: [], letterPoints: 0, ns: [], mx: [] });
    }
    return signals.get(cc);
  };

  // Names: the domain's own labels first, then every name under it in sortHostnames order, so
  // the result does not depend on the order the sources answered in (each distinct label once).
  const seenNames = new Set();
  const seenLabels = new Set();
  const matched = [];
  const matchedSet = new Set();
  const take = (word) => {
    if (!matchedSet.has(word)) { matchedSet.add(word); matched.push(word); }
  };
  const given = (Array.isArray(names) ? names : []).map((n) => normalizeHostname(String(n ?? ''))).filter(Boolean);
  for (const name of apex ? [apex, ...sortHostnames(given)] : []) {
    if (seenNames.has(name)) continue;
    const labels = ownLabels(name, apex);
    if (!labels.length && name !== apex) continue;
    seenNames.add(name);
    for (const label of labels) {
      if (!label || seenLabels.has(label) || /^\d+$/.test(label)) continue;
      seenLabels.add(label);
      if (!label.startsWith('xn--')) {
        for (const w of labelWords(label, vocab)) take(w);
        continue;
      }
      const u = unicodeLabel(label);
      if (!u) continue;
      for (const cc of labelLetters(u)) {
        const s = signal(cc);
        if (s.letterPoints < LOCALE_EVIDENCE_MAX_LETTERS) s.letterPoints += 1;
        if (s.letters.length < LOCALE_EVIDENCE_EXAMPLES && !s.letters.includes(u)) s.letters.push(u);
      }
      for (const form of foldLabel(u)) for (const w of labelWords(form, vocab)) take(w);
    }
  }

  // Word points: each distinct word once, ½ under five letters, shared between its packs, then
  // scaled down for a large zone.
  const scale = Math.min(1, LOCALE_EVIDENCE_VOLUME / Math.max(1, seenLabels.size));
  for (const w of matched) {
    const owners = vocab.get(w) || [];
    const weight = (w.length >= 5 ? 1 : 0.5) / Math.max(1, owners.length);
    for (const cc of owners) {
      const s = signal(cc);
      s.wordPoints += weight * scale;
      s.wordCount += 1;
      if (s.words.length < LOCALE_EVIDENCE_EXAMPLES) s.words.push(w);
    }
  }

  // Name and mail servers.
  const nsSignal = serverSignal(ns);
  const mxSignal = serverSignal(mx);
  for (const [cc, entry] of nsSignal.byLocale) signal(cc).ns = entry.endings;
  for (const [cc, entry] of mxSignal.byLocale) signal(cc).mx = entry.endings;

  const list = [...signals.values()].map((s) => {
    const points = {
      words: round2(s.wordPoints),
      letters: s.letterPoints,
      ns: serverPoints(nsSignal.byLocale.get(s.locale), nsSignal.domains.length),
      mx: serverPoints(mxSignal.byLocale.get(s.locale), mxSignal.domains.length)
    };
    return {
      locale: s.locale,
      score: round2(s.wordPoints + points.letters + points.ns + points.mx),
      picked: false,
      points,
      words: s.words,
      wordCount: s.wordCount,
      letters: s.letters,
      ns: s.ns,
      mx: s.mx
    };
  }).filter((s) => s.score > 0);
  list.sort((a, b) => b.score - a.score || LOCALE_PACK_CODES.indexOf(a.locale) - LOCALE_PACK_CODES.indexOf(b.locale));

  const top = list.length ? list[0].score : 0;
  const locales = [];
  for (const s of list) {
    if (locales.length >= LOCALE_EVIDENCE_MAX_PACKS) break;
    if (s.score >= LOCALE_EVIDENCE_MIN && s.score >= top * LOCALE_EVIDENCE_RELATIVE) {
      s.picked = true;
      locales.push(s.locale);
    }
  }
  return {
    domain: apex,
    locales,
    signals: list,
    names: seenNames.size,
    labels: seenLabels.size,
    ns: nsSignal.domains.length,
    mx: mxSignal.domains.length
  };
}
