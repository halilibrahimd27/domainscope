/**
 * ctseen.js — the CT watch's baseline (the workspace part `ctSeen`), and which of a domain's
 * certificates are current. Split out of lib/ctwatch.js, which re-exports it, so Home reads the
 * baseline without the watch's sources and lib/x509.js.
 *
 * Per domain the baseline keeps when it was last checked (`at`), every certificate id seen with its
 * expiry day (`ids`: what makes a certificate "new" next time — it keeps a certificate replaced by
 * its renewal until it expires) and the expiry days of that check's current certificates (`due`,
 * additive: written since the redesign's phase 1c; Home counts what expires from it, never from
 * `ids`). A reader of an older baseline finds no `due`.
 *
 * Pure: no DOM, network, clock or i18n.
 */

import { normalizeHostname, certCovers } from './domain.js';

/** The baseline's format version. */
export const CT_SEEN_VERSION = 1;
/** The longest baseline text the workspace keeps (characters). */
export const CT_SEEN_MAX_CHARS = 1048576;
/** The most expiry days kept per domain in `due`. */
export const CT_SEEN_MAX_DUE = 64;

const ID_RE = /^[0-9a-f]{16}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const ms = (now) => (now instanceof Date ? now.getTime() : typeof now === 'function' ? Number(now()) : Number(now));

/** Is `name` covered by a certificate holding `names`? A wildcard needs the same wildcard. */
function coveredBy(name, names) {
  if (names.includes(name)) return true;
  return !name.startsWith('*.') && certCovers(names, name).covered;
}

/**
 * Where each of a domain's certificates stands at `t`: `newest`, the newest valid one of its name
 * set (issued by then, not revoked); `superseded`, another unrevoked one that expires later covers
 * all its names; `current`, newest and not superseded — the certificate the domain uses.
 * @param {Array<{ id: string, names: string[], notBefore: Date, notAfter: Date, revoked?: boolean|null }>} certs
 * @param {number|Date} t
 * @returns {Array<{ newest: boolean, superseded: boolean, current: boolean }>} one per certificate, in order
 */
export function certStanding(certs, t) {
  const at = ms(t);
  const list = Array.isArray(certs) ? certs : [];
  const namesOf = (c) => (Array.isArray(c.names) ? c.names : []);
  const dated = (d) => d instanceof Date && Number.isFinite(d.getTime());
  const groups = new Map();
  for (const c of list) {
    const key = namesOf(c).join(' ');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
  }
  const newestIds = new Set();
  for (const group of groups.values()) {
    const valid = group.filter((c) => c.revoked !== true && dated(c.notBefore) && dated(c.notAfter) && c.notBefore.getTime() <= at)
      .sort((a, b) => b.notBefore - a.notBefore || (a.id < b.id ? -1 : 1));
    if (valid[0]) newestIds.add(valid[0].id);
  }
  return list.map((c) => {
    const superseded = dated(c.notAfter) && list.some((o) => o !== c && o.revoked !== true && dated(o.notAfter) && o.notAfter > c.notAfter
      && namesOf(c).every((n) => coveredBy(n, namesOf(o))));
    const newest = newestIds.has(c.id) && c.revoked !== true;
    return { newest, superseded, current: newest && !superseded };
  });
}

/**
 * The expiry days (YYYY-MM-DD, UTC) of a read's current certificates ({@link certStanding}), one
 * per certificate (two that end the same day are two), soonest first, at most {@link CT_SEEN_MAX_DUE}.
 * @param {{ certs?: object[] }} read
 * @param {number|Date} t
 * @returns {string[]}
 */
export function currentDue(read, t) {
  const certs = (read && read.certs) || [];
  const standing = certStanding(certs, t);
  const days = certs.filter((c, i) => standing[i].current && c.notAfter instanceof Date && Number.isFinite(c.notAfter.getTime()))
    .map((c) => c.notAfter.toISOString().slice(0, 10));
  return days.sort().slice(0, CT_SEEN_MAX_DUE);
}

/**
 * @typedef {{ v: number, domains: Record<string, { at: string, ids: Record<string, string>, due?: string[] }> }} CtSeen
 *   per domain: when it was last read, each certificate id seen with its expiry day (YYYY-MM-DD) and
 *   — written since phase 1c — the expiry days of that read's current certificates
 */

/** @returns {CtSeen} */
export function emptySeen() {
  return { v: CT_SEEN_VERSION, domains: {} };
}

/** A stored `due` list checked: days only, sorted, capped; undefined when it is no list. */
function readDue(value) {
  if (!Array.isArray(value)) return undefined;
  return value.slice(0, CT_SEEN_MAX_DUE * 2).filter((d) => typeof d === 'string' && DAY_RE.test(d)).sort().slice(0, CT_SEEN_MAX_DUE);
}

/**
 * The baseline from the workspace's text: anything that is not one (another version, broken JSON,
 * a stray value) is dropped, entry by entry.
 * @param {unknown} text
 * @returns {CtSeen}
 */
export function readSeen(text) {
  const out = emptySeen();
  let data = null;
  try {
    data = typeof text === 'string' && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!data || typeof data !== 'object' || data.v !== CT_SEEN_VERSION || !data.domains || typeof data.domains !== 'object') return out;
  for (const [domain, entry] of Object.entries(data.domains)) {
    if (normalizeHostname(domain) !== domain || !entry || typeof entry !== 'object' || typeof entry.at !== 'string' || Number.isNaN(Date.parse(entry.at))) continue;
    const ids = {};
    for (const [id, day] of Object.entries(entry.ids && typeof entry.ids === 'object' ? entry.ids : {})) {
      if (ID_RE.test(id) && typeof day === 'string' && DAY_RE.test(day)) ids[id] = day;
    }
    const due = readDue(entry.due);
    out.domains[domain] = due ? { at: new Date(Date.parse(entry.at)).toISOString(), ids, due } : { at: new Date(Date.parse(entry.at)).toISOString(), ids };
  }
  return out;
}

/**
 * The baseline after a check: each domain that was read (in full or in part) gets the ids of its
 * certificates, added to those seen before (a source that missed one this time does not make it
 * "new" next time), the time of the read and the expiry days of its current certificates
 * ({@link currentDue}); ids whose certificate has expired are dropped. A domain that could not be
 * read keeps its entry as it was.
 * @param {CtSeen} seen
 * @param {Array<{ domain: string, at: Date, state: string, certs: object[] }>} reads
 * @param {{ now?: Date|number }} [opts]
 * @returns {CtSeen} a new object
 */
export function updateSeen(seen, reads, { now = Date.now() } = {}) {
  const today = new Date(ms(now)).toISOString().slice(0, 10);
  const out = { v: CT_SEEN_VERSION, domains: { ...(seen && seen.domains ? seen.domains : {}) } };
  for (const read of reads || []) {
    if (!read || read.state === 'failed') continue;
    const prev = out.domains[read.domain];
    const ids = {};
    for (const [id, day] of Object.entries(prev ? prev.ids : {})) if (day >= today) ids[id] = day;
    for (const c of read.certs || []) ids[c.id] = c.notAfter.toISOString().slice(0, 10);
    out.domains[read.domain] = { at: read.at.toISOString(), ids, due: currentDue(read, read.at) };
  }
  return out;
}

/**
 * The baseline as the workspace keeps it: JSON, under {@link CT_SEEN_MAX_CHARS} characters (the
 * domains read longest ago are left out first when it would not fit).
 * @param {CtSeen} seen
 * @param {{ maxChars?: number }} [opts]
 * @returns {string} '' for an empty baseline
 */
export function seenText(seen, { maxChars = CT_SEEN_MAX_CHARS } = {}) {
  const entries = Object.entries(seen && seen.domains ? seen.domains : {}).sort((a, b) => (a[1].at < b[1].at ? 1 : a[1].at > b[1].at ? -1 : 0));
  while (entries.length) {
    const text = JSON.stringify({ v: CT_SEEN_VERSION, domains: Object.fromEntries([...entries].sort((a, b) => (a[0] < b[0] ? -1 : 1))) });
    if (text.length <= maxChars) return text;
    entries.pop();
  }
  return '';
}
