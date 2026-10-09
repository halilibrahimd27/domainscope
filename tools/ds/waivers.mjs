/**
 * tools/ds/waivers.mjs — the runner's accepted risks (`--waivers waivers.json`, lib/waivers.js): the
 * file read and checked before the run, and the summary that says what they did.
 *
 * - {@link readWaiversFile}: the file's waivers, the entries left out (each a warning: an entry
 *   that cannot be read never applies, so its item counts) — a file that is not a waivers file
 *   at all is a usage error, before anything is sent.
 * - {@link waiversDoc}: one summary per run of `health`, `audit` or `ct` with --waivers: the items
 *   a waiver accepted (they do not count for --fail-on-change nor for audit's exit 4), those whose
 *   waiver ends within {@link WAIVER_SOON_DAYS} days, those whose waiver is over (they count again:
 *   WAIVER-EXPIRED in the changes), the waivers whose item this run could not read (a failed
 *   lookup, a registry or CT source that did not answer: kept, never "can go"), and the waivers of
 *   a domain the run checked that matched nothing (the item is fixed, or no longer reported: the
 *   waiver can go).
 * Pure apart from the injected file reader.
 */

import { basename } from 'node:path';
import { parseWaivers, waiverState, waiverEnd, WAIVER_SOON_DAYS, WAIVER_REASON_MAX, WAIVER_OWNER_MAX, WAIVER_MAX_DAYS } from '../../assets/js/lib/waivers.js';
import { UsageError } from './args.mjs';
import { code, strong, summaryDoc } from './render.mjs';

const DAY_MS = 86400000;
/** Items a list of the summary names before "and N more". */
export const WAIVERS_MAX_LINES = 20;
/** Entries left out that the warnings name one by one; the rest are counted. */
const MAX_ENTRY_WARNINGS = 5;
/** The kind of waiver each command reads. */
export const WAIVER_KIND_OF = Object.freeze({ health: 'finding', audit: 'rule', ct: 'cert' });

/** Why an entry of the file was left out, in the runner's words. */
export function entryProblem(e) {
  switch (e.code) {
    case 'not-object': return 'not an object';
    case 'kind': return 'its kind is not finding, rule or cert';
    case 'domain': return 'its domain is not a domain name';
    case 'ref': return 'its ref is not a check id (finding), a rule id (rule) or a SHA-256 (cert)';
    case 'reason': return `it has no reason, or one longer than ${WAIVER_REASON_MAX} characters`;
    case 'owner': return `its owner is longer than ${WAIVER_OWNER_MAX} characters`;
    case 'expires': return 'its expires is not a day (YYYY-MM-DD)';
    case 'too-far': return `it expires more than ${WAIVER_MAX_DAYS} days ahead`;
    case 'created': return 'its created is not a date';
    case 'too-many': return 'more waivers than a file holds';
    default: return e.code;
  }
}

/** Why a whole file was refused. */
function fileProblem(code) {
  switch (code) {
    case 'not-json': return 'not JSON';
    case 'not-waivers': return 'not a waivers file ({ "format": "domainscope-waivers", "v": 1, "waivers": [...] }, or a list of waivers)';
    case 'newer': return 'written by a newer version of DomainScope';
    case 'too-large': return 'too large for a waivers file';
    case 'too-many': return 'more waivers than a file holds';
    default: return code;
  }
}

/**
 * Read `--waivers FILE`: its waivers (read at `now`), and a warning per entry left out.
 * @param {string} path
 * @param {{ read: (path: string, option: string) => Promise<string>, now: Date }} io
 * @returns {Promise<{ file: string, list: object[], warnings: string[] }>}
 * @throws {UsageError} a file that cannot be read or is no waivers file
 */
export async function readWaiversFile(path, { read, now }) {
  const text = await read(path, '--waivers');
  const parsed = parseWaivers(text, { now });
  const label = `--waivers ${path}`;
  if (!parsed.ok) throw new UsageError(`${label}: ${fileProblem(parsed.errors[0].code)}`);
  const warnings = parsed.errors.slice(0, MAX_ENTRY_WARNINGS)
    .map((e) => `${label}: ${e.index === null || e.code === 'too-many' ? '' : `entry ${e.index + 1} `}left out: ${entryProblem(e)} (its item counts)`);
  if (parsed.errors.length > MAX_ENTRY_WARNINGS) warnings.push(`${label}: ${parsed.errors.length - MAX_ENTRY_WARNINGS} more entries left out`);
  return { file: basename(path), list: parsed.waivers, warnings };
}

/** "ends 2026-12-31 (in 9 days)" or "ends 2026-12-31". */
function endsText(w, now) {
  const days = Math.ceil((waiverEnd(w) - now.getTime()) / DAY_MS);
  return waiverState(w, { now }) === 'expiring' ? `until ${w.expires} (ends in ${days} day${days === 1 ? '' : 's'})` : `until ${w.expires}`;
}

/** A waiver's owner and reason as parts: " — Ops: reason". */
const whoParts = (w) => [' — ', ...(w.owner ? [code(w.owner), ': '] : []), code(w.reason)];

/**
 * The summary of what the waivers did in a run.
 * @param {string} command 'health' | 'audit' | 'ct'
 * @param {{ file: string, list: object[] }} waivers the file's (readWaiversFile)
 * @param {{ applied: Array<{ target: string, what: Array, waiver: object }>, expired: Array<{ target: string, what: Array, waiver: object }>,
 *   checked: string[], unread?: ((waiver: object) => boolean)|null }} use what this run's items took: `what` the item as parts;
 *   `checked`: the targets the run read; `unread`: whether a waiver's item could not be read this run (its lookup failed, the
 *   registry or a CT source did not answer in full), so matching nothing says nothing about it
 * @param {{ t: Function, now: Date }} opts
 * @returns {object} a SummaryDoc
 */
export function waiversDoc(command, waivers, use, { t, now }) {
  const kind = WAIVER_KIND_OF[command];
  const lines = [];
  const applied = use.applied || [];
  const expired = use.expired || [];
  const soon = applied.filter((a) => waiverState(a.waiver, { now }) === 'expiring');
  const usedIds = new Set([...applied, ...expired].map((a) => a.waiver.id));
  const checked = new Set(use.checked || []);
  const unread = typeof use.unread === 'function' ? use.unread : () => false;
  const unused = (waivers.list || []).filter((w) => w.kind === kind && checked.has(w.domain) && !usedIds.has(w.id) && waiverState(w, { now }) !== 'expired');
  // an item this run could not read may still be there: its waiver is kept, never "can go"
  const kept = unused.filter((w) => unread(w));
  const idle = unused.filter((w) => !unread(w));
  const ofKind = (waivers.list || []).filter((w) => w.kind === kind).length;
  const total = (waivers.list || []).length;
  lines.push([`${ofKind} of ${total} waiver${total === 1 ? '' : 's'} ${ofKind === 1 ? 'is' : 'are'} for ${command}: `,
    `${applied.length} item${applied.length === 1 ? '' : 's'} accepted (not counted), ${soon.length} ending within ${WAIVER_SOON_DAYS} days, `,
    `${expired.length} expired (counting again)`, kept.length ? `, ${kept.length} not checked this run (kept)` : '']);
  const list = (items, head, each) => {
    if (!items.length) return;
    lines.push([strong(head)]);
    for (const x of items.slice(0, WAIVERS_MAX_LINES)) lines.push(each(x));
    if (items.length > WAIVERS_MAX_LINES) lines.push([`… and ${items.length - WAIVERS_MAX_LINES} more (see the JSON report)`]);
  };
  list(expired, 'Expired, counting again:', (x) => [code(x.target), ': ', ...x.what, ` — expired ${x.waiver.expires}`, ...whoParts(x.waiver)]);
  list(soon, `Ending within ${WAIVER_SOON_DAYS} days:`, (x) => [code(x.target), ': ', ...x.what, ` ${endsText(x.waiver, now)}`, ...whoParts(x.waiver)]);
  list(applied.filter((x) => !soon.includes(x)), 'Accepted:', (x) => [code(x.target), ': ', ...x.what, ` ${endsText(x.waiver, now)}`, ...whoParts(x.waiver)]);
  list(kept, 'Not checked this run (kept: its item could not be read):', (w) => [code(w.domain), ': ', code(w.ref), ` until ${w.expires}`]);
  list(idle, 'Matched nothing this run (fixed, or no longer reported: the waiver can go):', (w) => [code(w.domain), ': ', code(w.ref), ` until ${w.expires}`]);
  return summaryDoc(command, ['Accepted risks · ', code(waivers.file)], lines, { t, now });
}
