/**
 * regwatch.js — the registration watch: what a domain's registry says of it (the registrar and its
 * IANA Registrar ID, the statuses, the expiry, the name servers it delegates to) and the DS records
 * at its parent, compared with the last time they were read. A registrar, name server or lock change
 * that breaks no policy rule is the first sign of a hijack; nothing else in the app would say it.
 *
 * - {@link registrationSnapshot}: what a lib/portfolio.js portfolioFacts row says, each part null
 *   while it is not known (a lookup that failed, a registry without RDAP).
 * - {@link diffRegistration}: two snapshots compared, as change codes with their tone
 *   ({@link REG_CHANGE_CODES}): the registrar (by its IANA ID; its name alone when an ID is missing),
 *   a transfer prohibition removed (bad) or added (good), a hold, a pending delete, a redemption
 *   period or a pending transfer arriving (bad), any other status, the name servers, the DS records
 *   (removed or changed: bad; added: info), the expiry moved later (renewed) or earlier, and the
 *   registry losing or finding the domain. The Domain portfolio (the browser) and the headless
 *   runner's `watch` (tools/ds/watch.mjs) share it.
 * - The baseline of the browser (lib/workspace.js part `rdapSeen`), as lib/ctwatch.js keeps
 *   `ctSeen`: per domain the last snapshot read and when ({@link readRdapSeen},
 *   {@link updateRdapSeen}, {@link rdapSeenText}), and what changed since ({@link seenChanges}).
 *
 * DOM-free and pure: no network, storage or clock beyond what the caller passes.
 */

import { normalizeHostname } from './domain.js';

/** The baseline's format version. */
export const RDAP_SEEN_VERSION = 1;
/** The baseline's text is kept under this many characters (lib/workspace.js WORKSPACE_LIMITS.rdapSeen). */
export const RDAP_SEEN_MAX_CHARS = 524288;
/**
 * Transfer prohibitions, in RDAP's spelling (RFC 8056; RFC 9083's plain one too): one removed is a
 * lock removed (bad: whoever has the transfer code can move the domain), one added a lock added.
 */
export const TRANSFER_LOCK_STATUSES = Object.freeze(['client transfer prohibited', 'server transfer prohibited', 'transfer prohibited']);
/**
 * Statuses whose arrival is bad: a hold takes the domain out of DNS, a pending delete or a redemption
 * period means it is being lost, a pending transfer is a hijack in progress if nobody asked for it.
 */
export const HOLD_STATUSES = Object.freeze(['server hold', 'client hold', 'pending delete', 'redemption period', 'pending transfer']);
/**
 * What can change, in the order a list says them: the registrar (its IANA ID, or its name without
 * one; `registrar-name`: the same ID under another name), a transfer lock removed or added, a hold
 * (or a pending delete, redemption or transfer) arriving, any other status added or removed, the
 * registry's name servers, the DS records removed, changed or added, the expiry moved later
 * (renewed) or earlier, the registry no longer holding the domain (`unregistered`) or holding it
 * again (`registered`).
 */
export const REG_CHANGE_CODES = Object.freeze(['unregistered', 'registered', 'registrar', 'registrar-name', 'lock-removed', 'lock-added', 'hold', 'status', 'ns',
  'ds-removed', 'ds-changed', 'ds-added', 'expiry-later', 'expiry-earlier']);
/** The tone of each code ('status' is info whichever way it moves). */
export const REG_CHANGE_TONES = Object.freeze({
  unregistered: 'bad', registered: 'info', registrar: 'bad', 'registrar-name': 'info', 'lock-removed': 'bad', 'lock-added': 'good', hold: 'bad', status: 'info',
  ns: 'bad', 'ds-removed': 'bad', 'ds-changed': 'bad', 'ds-added': 'info', 'expiry-later': 'good', 'expiry-earlier': 'info'
});

/** At most this many of each list in a stored entry (a registry's answer is small; a hostile one is cut). */
const MAX_STATUSES = 40;
const MAX_NAMESERVERS = 26;
const MAX_DS = 20;
const MAX_TEXT = 200;

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const DS_RE = /^\d{1,5} \d{1,3} \d{1,3}$/;
const IANA_RE = /^\d{1,10}$/;

/* ------------------------------------------------------------------------ */
/* Snapshots                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} RegSnapshot what was read of a domain's registration and delegation
 * @property {'ok'|'not-found'|null} state the registry answered (ok), says it does not hold the
 *   domain (not-found), or null: not known (no RDAP for the TLD, a lookup that failed)
 * @property {string|null} registrar
 * @property {string|null} ianaId the registrar's IANA Registrar ID
 * @property {string[]|null} statuses lower case, RDAP spelling, sorted
 * @property {string|null} expires YYYY-MM-DD (UTC)
 * @property {string[]|null} nameservers the registry's name servers, sorted
 * @property {string[]|null} ds the DS records at the parent as 'keyTag algorithm digestType', sorted;
 *   [] for none; null: not known
 */

/** A status as compared: lower case, spaces collapsed. */
const statusKey = (s) => String(s ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
/** A host name as compared, or null. */
const hostKey = (h) => normalizeHostname(String(h ?? ''));
/** A DS identity as stored. */
export const dsKey = (d) => `${d.keyTag} ${d.algorithm} ${d.digestType}`;

/** A day (YYYY-MM-DD, UTC) of a date, or null. */
function dayOf(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'string' && DAY_RE.test(value)) return value;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/** A sorted list of distinct texts. */
const sortedSet = (list) => [...new Set(list)].sort();

/**
 * What a Domain portfolio row (lib/portfolio.js portfolioFacts) says of the registration and the
 * delegation, as the watch compares it.
 * @param {object} facts portfolioFacts of one domain
 * @returns {RegSnapshot}
 */
export function registrationSnapshot(facts) {
  const reg = (facts && facts.registration) || {};
  const ok = reg.state === 'ok';
  const d = facts && facts.dnssec;
  const dsKnown = !!d && d.state !== null && d.state !== undefined && Array.isArray(d.ds);
  return {
    state: ok ? 'ok' : reg.state === 'not-found' ? 'not-found' : null,
    registrar: ok && reg.registrar ? String(reg.registrar) : null,
    ianaId: ok && reg.ianaId ? String(reg.ianaId) : null,
    statuses: ok ? sortedSet((reg.statuses || []).map(statusKey).filter(Boolean)) : null,
    expires: ok ? dayOf(reg.expires) : null,
    nameservers: ok ? sortedSet((reg.nameservers || []).map(hostKey).filter(Boolean)) : null,
    ds: dsKnown ? sortedSet(d.ds.map((x) => (typeof x === 'string' ? x : dsKey(x))).filter((x) => DS_RE.test(x))) : null
  };
}

/* ------------------------------------------------------------------------ */
/* Changes                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} RegChange
 * @property {string} code one of {@link REG_CHANGE_CODES}
 * @property {'bad'|'good'|'info'} tone
 * @property {string|null} item what moved: a status, else null
 * @property {any} before
 * @property {any} after
 * @property {'added'|'removed'} [how] a status: added or removed
 */

/** A registrar's name as compared: case, punctuation and spacing aside ("Example, Inc." is "example inc"). */
export function registrarKey(name) {
  return String(name ?? '').toLowerCase().normalize('NFKC').replace(/[.,'"`’()]/g, ' ').replace(/\s+/g, ' ').trim();
}

const change = (code, item, before, after, extra = {}) => ({ code, tone: REG_CHANGE_TONES[code], item, before, after, ...extra });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * What changed from one snapshot to the next, in {@link REG_CHANGE_CODES} order (a part not known
 * on either side is not compared). The registrar: another IANA Registrar ID; without an ID on both
 * sides, another name (case, punctuation and spacing aside); the same ID under another name is
 * `registrar-name` (info). A transfer prohibition ({@link TRANSFER_LOCK_STATUSES}) removed is
 * `lock-removed` (bad), added `lock-added` (good); a status of {@link HOLD_STATUSES} arriving is
 * `hold` (bad); any other status added or removed is `status` (info, `how`). The DS records: every one
 * gone `ds-removed`, one gone and others there or new `ds-changed` (both bad), only new ones
 * `ds-added` (info). The expiry: later `expiry-later` (good: renewed), earlier `expiry-earlier`.
 * A domain the registry held and no longer holds is `unregistered` (bad), the reverse `registered`;
 * nothing else of the registration is compared then.
 * @param {RegSnapshot|null} before
 * @param {RegSnapshot|null} after
 * @returns {RegChange[]}
 */
export function diffRegistration(before, after) {
  if (!before || !after) return [];
  const out = [];
  if (before.state === 'ok' && after.state === 'not-found') out.push(change('unregistered', null, 'ok', 'not-found'));
  else if (before.state === 'not-found' && after.state === 'ok') out.push(change('registered', null, 'not-found', 'ok'));
  else if (before.state === 'ok' && after.state === 'ok') {
    // the registrar: its IANA ID says it; a name alone only when an ID is missing
    const idB = before.ianaId;
    const idA = after.ianaId;
    const nameB = before.registrar ? registrarKey(before.registrar) : '';
    const nameA = after.registrar ? registrarKey(after.registrar) : '';
    if (idB && idA && idB !== idA) {
      out.push(change('registrar', null, { name: before.registrar, ianaId: idB }, { name: after.registrar, ianaId: idA }));
    } else if (nameB && nameA && nameB !== nameA) {
      out.push(change(idB && idA ? 'registrar-name' : 'registrar', null, { name: before.registrar, ianaId: idB }, { name: after.registrar, ianaId: idA }));
    }
    if (Array.isArray(before.statuses) && Array.isArray(after.statuses)) {
      const b = new Set(before.statuses);
      const a = new Set(after.statuses);
      for (const s of TRANSFER_LOCK_STATUSES) {
        if (b.has(s) && !a.has(s)) out.push(change('lock-removed', s, s, null));
        else if (a.has(s) && !b.has(s)) out.push(change('lock-added', s, null, s));
      }
      for (const s of HOLD_STATUSES) if (a.has(s) && !b.has(s)) out.push(change('hold', s, null, s));
      const said = new Set([...TRANSFER_LOCK_STATUSES]);
      for (const s of after.statuses) {
        if (!b.has(s) && !said.has(s) && !HOLD_STATUSES.includes(s)) out.push(change('status', s, null, s, { how: 'added' }));
      }
      for (const s of before.statuses) if (!a.has(s) && !said.has(s)) out.push(change('status', s, s, null, { how: 'removed' }));
    }
    if (Array.isArray(before.nameservers) && Array.isArray(after.nameservers) && (before.nameservers.length || after.nameservers.length)
      && !same(before.nameservers, after.nameservers)) {
      out.push(change('ns', null, [...before.nameservers], [...after.nameservers]));
    }
  }
  if (Array.isArray(before.ds) && Array.isArray(after.ds) && !same(before.ds, after.ds)) {
    const a = new Set(after.ds);
    const gone = before.ds.filter((x) => !a.has(x));
    const code = before.ds.length && !after.ds.length ? 'ds-removed' : gone.length ? 'ds-changed' : 'ds-added';
    out.push(change(code, null, [...before.ds], [...after.ds]));
  }
  if (before.state === 'ok' && after.state === 'ok' && before.expires && after.expires && before.expires !== after.expires) {
    out.push(change(after.expires > before.expires ? 'expiry-later' : 'expiry-earlier', null, before.expires, after.expires));
  }
  const rank = (c) => REG_CHANGE_CODES.indexOf(c.code);
  return out.map((c, i) => ({ c, i })).sort((x, y) => rank(x.c) - rank(y.c) || x.i - y.i).map((x) => x.c);
}

/** The worst tone of a list of changes: bad, then info, then good; null for none. */
export function worstTone(changes) {
  const tones = new Set((changes || []).map((c) => c.tone));
  return tones.has('bad') ? 'bad' : tones.has('info') ? 'info' : tones.has('good') ? 'good' : null;
}

/* ------------------------------------------------------------------------ */
/* The baseline (workspace part `rdapSeen`)                                 */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {{ v: number, domains: Record<string, RdapSeenEntry> }} RdapSeen
 * @typedef {{ at: string, state: 'ok'|'not-found', registrar: string|null, ianaId: string|null, statuses: string[]|null,
 *   expires: string|null, nameservers: string[]|null, ds: string[]|null }} RdapSeenEntry
 *   per domain: when the registry was last read, and what it said (a {@link RegSnapshot})
 */

/** @returns {RdapSeen} */
export function emptyRdapSeen() {
  return { v: RDAP_SEEN_VERSION, domains: {} };
}

/** A list of texts each checked by `ok`, at most `max`, or null for anything else. */
function textList(value, ok, max) {
  if (!Array.isArray(value)) return null;
  return sortedSet(value.filter((x) => typeof x === 'string' && ok(x))).slice(0, max);
}

/** A stored entry checked, or null. */
function readEntry(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry.at !== 'string' || Number.isNaN(Date.parse(entry.at))) return null;
  if (entry.state !== 'ok' && entry.state !== 'not-found') return null;
  const ok = entry.state === 'ok';
  const text = (v) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, MAX_TEXT) : null);
  return {
    at: new Date(Date.parse(entry.at)).toISOString(),
    state: entry.state,
    registrar: ok ? text(entry.registrar) : null,
    ianaId: ok && typeof entry.ianaId === 'string' && IANA_RE.test(entry.ianaId) ? entry.ianaId : null,
    statuses: ok ? textList(entry.statuses, (s) => s.length <= 64 && s === statusKey(s), MAX_STATUSES) : null,
    expires: ok && typeof entry.expires === 'string' && DAY_RE.test(entry.expires) ? entry.expires : null,
    nameservers: ok ? textList(entry.nameservers, (h) => hostKey(h) === h, MAX_NAMESERVERS) : null,
    ds: textList(entry.ds, (x) => DS_RE.test(x), MAX_DS)
  };
}

/**
 * The baseline from the workspace's text: anything that is not one (another version, broken JSON,
 * a stray value) is dropped, entry by entry.
 * @param {unknown} text
 * @returns {RdapSeen}
 */
export function readRdapSeen(text) {
  const out = emptyRdapSeen();
  let data = null;
  try {
    data = typeof text === 'string' && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!data || typeof data !== 'object' || data.v !== RDAP_SEEN_VERSION || !data.domains || typeof data.domains !== 'object' || Array.isArray(data.domains)) return out;
  for (const [domain, entry] of Object.entries(data.domains)) {
    if (normalizeHostname(domain) !== domain) continue;
    const e = readEntry(entry);
    if (e) out.domains[domain] = e;
  }
  return out;
}

/**
 * The baseline after a check: each domain whose registry answered (it holds the domain, or says it
 * does not) gets this check's snapshot and time; the DS records of a check that could not read them
 * stay as they were. A domain whose registry could not be read keeps its entry as it was.
 * @param {RdapSeen} seen
 * @param {Array<{ domain: string, snapshot: RegSnapshot }>} reads
 * @param {{ now?: Date|number }} [opts]
 * @returns {RdapSeen} a new object
 */
export function updateRdapSeen(seen, reads, { now = Date.now() } = {}) {
  const at = new Date(now instanceof Date ? now.getTime() : now).toISOString();
  const out = { v: RDAP_SEEN_VERSION, domains: { ...(seen && seen.domains ? seen.domains : {}) } };
  for (const r of reads || []) {
    const domain = r && normalizeHostname(String(r.domain || ''));
    const s = r && r.snapshot;
    if (!domain || !s || (s.state !== 'ok' && s.state !== 'not-found')) continue;
    const prev = out.domains[domain];
    const entry = readEntry({ ...s, at, ds: Array.isArray(s.ds) ? s.ds : prev ? prev.ds : null });
    if (entry) out.domains[domain] = entry;
  }
  return out;
}

/**
 * The baseline as the workspace keeps it: JSON, under {@link RDAP_SEEN_MAX_CHARS} characters (the
 * domains read longest ago are left out first when it would not fit).
 * @param {RdapSeen} seen
 * @param {{ maxChars?: number }} [opts]
 * @returns {string} '' for an empty baseline
 */
export function rdapSeenText(seen, { maxChars = RDAP_SEEN_MAX_CHARS } = {}) {
  const entries = Object.entries(seen && seen.domains ? seen.domains : {}).sort((a, b) => (a[1].at < b[1].at ? 1 : a[1].at > b[1].at ? -1 : 0));
  while (entries.length) {
    const text = JSON.stringify({ v: RDAP_SEEN_VERSION, domains: Object.fromEntries([...entries].sort((a, b) => (a[0] < b[0] ? -1 : 1))) });
    if (text.length <= maxChars) return text;
    entries.pop();
  }
  return '';
}

/**
 * What changed for a domain since the baseline's entry: its time (`at`, the check that read it) and
 * the changes ({@link diffRegistration}); null when the baseline has no entry for it (the first
 * check in this workspace).
 * @param {RdapSeenEntry|null|undefined} entry
 * @param {RegSnapshot} snapshot
 * @returns {{ at: string, changes: RegChange[] }|null}
 */
export function seenChanges(entry, snapshot) {
  if (!entry || !snapshot) return null;
  return { at: entry.at, changes: diffRegistration(entry, snapshot) };
}
