/**
 * lib/session.js — the page session's working context, in memory only: the current target (the
 * domain, host name or IP address the user last worked on) and the last finished result of each
 * tool, so moving between tools carries the target along and coming back to a tool shows what it
 * showed before.
 *
 * DOM-free and storage-free: nothing here touches localStorage, sessionStorage or the URL. A
 * reload, the tab closing or "Delete all local data" (the shell calls `clear()`) forgets it all.
 * The shell (app.js) owns the one store of the page:
 *   - a view reports a run with `ctx.runStarted(subject)` → `setTarget()`;
 *   - when a view unmounts, the shell keeps its `result()` (with the result's own route params)
 *     and `snapshot()` → `keep()`;
 *   - the nav links point to `carryRoute(view, { kept, target })`;
 *   - on mount, `restorePlan()` decides whether the kept snapshot comes back as `ctx.restored`,
 *     and `keptNote()` whether the page header says "Result from <time>".
 *
 * Route contract: a carried target goes into the view's main input param (`TARGET_ROUTES`, the
 * params the views already read) together with `run=0` (`FILL_PARAM` = `FILL_VALUE`): the view
 * fills its input (while empty, or while it still holds the tool's last run or the target it took
 * before: {@link fillReplaces}) and never runs, so opening a tool never sends a request by itself.
 * A link back to a kept result carries the result's own params with `run=0` too, so the same link
 * opened in a new tab only fills the form. A target set after the result was kept, about
 * something else, wins the link: the tool opens with the target in its box and its kept result
 * under it (`restorePlan` → 'carry'), as the tools that keep their own state do.
 *
 * @example
 *   const session = createSessionStore();
 *   session.setTarget('https://www.Example.com/login');      // { value: 'www.example.com', kind: 'host', … }
 *   carryRoute('lookup', { target: session.target });         // { name: 'www.example.com', run: '0' }
 *   session.keep('health', { params: { domain: 'example.com' }, subject: 'example.com', at, snapshot });
 *   restorePlan({}, session.kept('health'));                   // 'restore'
 *   restorePlan({ domain: 'www.example.com', run: '0' }, session.kept('health'));   // 'carry'
 */

import { normalizeHostname, registrableDomain, isPublicSuffix } from './domain.js';
import { normalizeIP } from './netinfo.js';

/** Kinds of target: a registrable domain, a host name below one, an IP address. */
export const TARGET_KINDS = Object.freeze(['domain', 'host', 'ip']);

/**
 * Where each tool takes the current target: its main input's route param and the kinds of
 * target that input accepts. Tools that are not listed (Zone File, Servers, About) take none;
 * the Zone File view never publishes one either, so nothing about an imported zone reaches a URL.
 */
export const TARGET_ROUTES = Object.freeze({
  subdomains: Object.freeze({ param: 'domain', kinds: Object.freeze(['domain', 'host']) }),
  scan: Object.freeze({ param: 'domain', kinds: Object.freeze(['domain', 'host']) }),
  cert: Object.freeze({ param: 'host', kinds: Object.freeze(['domain', 'host']) }),
  global: Object.freeze({ param: 'name', kinds: Object.freeze(['domain', 'host']) }),
  lookup: Object.freeze({ param: 'name', kinds: Object.freeze(['domain', 'host', 'ip']) }),
  bulk: Object.freeze({ param: 'names', kinds: Object.freeze(['domain', 'host']) }),
  ip: Object.freeze({ param: 'ips', kinds: Object.freeze(['ip']) }),
  health: Object.freeze({ param: 'domain', kinds: Object.freeze(['domain', 'host']) })
});

/** Route param + value that ask a tool to fill in its form without running (`run=0`). */
export const FILL_PARAM = 'run';
export const FILL_VALUE = '0';

/** Memory bounds of the kept results: one snapshot, and all of them together (estimated bytes). */
export const DEFAULT_LIMITS = Object.freeze({ entryBytes: 4 * 1024 * 1024, totalBytes: 16 * 1024 * 1024 });

/* ------------------------------------------------------------------------ */
/* Targets                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The address of an IP address written as a URL or with a port (`http://192.0.2.1/x`,
 * `192.0.2.1:443`, `[2001:db8::1]:443`), not yet checked; anything else as it is.
 * @param {string} raw
 * @returns {string}
 */
function addressPart(raw) {
  let s = raw;
  const url = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(s);
  if (url) s = url[1].slice(url[1].lastIndexOf('@') + 1);
  const isPort = (p) => p === undefined || Number(p) <= 65535;
  const v6 = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(s);
  if (v6) return isPort(v6[2]) ? v6[1] : s;
  const port = /^([^:[\]]+):(\d{1,5})$/.exec(s);
  return port && isPort(port[2]) ? port[1] : s;
}

/**
 * Read a target from what a tool worked on. URLs, ports, a trailing dot, a leading `*.` and IDNs
 * are normalised (lib/domain.normalizeHostname; an IP address written as a URL or with a port
 * gives the address); service labels name a record, not a host, so `_dmarc.example.com` and
 * `_443._tcp.www.example.com` give `example.com` and `www.example.com`. Public suffixes, `.arpa`
 * names, single labels and address ranges are no target.
 * @param {unknown} input
 * @returns {{ value: string, kind: 'domain'|'host'|'ip' }|null}
 */
export function parseTarget(input) {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048) return null;
  const ip = normalizeIP(raw) || normalizeIP(addressPart(raw));
  if (ip) return { value: ip, kind: 'ip' };
  const host = normalizeHostname(raw, { allowWildcard: true });
  if (!host) return null;
  const labels = host.replace(/^\*\./, '').split('.');
  let service = -1;
  labels.forEach((label, i) => {
    if (label.startsWith('_')) service = i;
  });
  const name = labels.slice(service + 1).join('.');
  if (!name || name.includes('_') || /(^|\.)arpa$/.test(name) || isPublicSuffix(name)) return null;
  const reg = registrableDomain(name);
  if (!reg) return null;
  return { value: name, kind: reg === name ? 'domain' : 'host' };
}

/**
 * The one target of a list a tool worked on (Bulk Resolve's names, IP Intel's addresses): its
 * only entry, or the registrable domain every name shares; null when the list names several
 * things (then the current target is left as it is).
 * @param {Iterable<string>} values
 * @returns {{ value: string, kind: 'domain'|'host'|'ip' }|null}
 */
export function commonTarget(values) {
  const targets = [];
  const seen = new Set();
  for (const v of values || []) {
    const t = parseTarget(v);
    if (t && !seen.has(t.value)) {
      seen.add(t.value);
      targets.push(t);
    }
  }
  if (targets.length === 1) return targets[0];
  if (!targets.length || targets.some((t) => t.kind === 'ip')) return null;
  const regs = new Set(targets.map((t) => registrableDomain(t.value)));
  if (regs.size !== 1) return null;
  const [reg] = regs;
  return { value: reg, kind: 'domain' };
}

/**
 * Does a tool's main input take this target?
 * @param {string} view
 * @param {{ kind: string }|null} target
 * @returns {boolean}
 */
export function targetFits(view, target) {
  const spec = Object.prototype.hasOwnProperty.call(TARGET_ROUTES, view) ? TARGET_ROUTES[view] : null;
  return !!(spec && target && spec.kinds.includes(target.kind));
}

/**
 * Route params that open a tool with the target filled in and nothing run, or null when the
 * tool does not take it.
 * @param {string} view
 * @param {{ value: string, kind: string }|null} target
 * @returns {Record<string, string>|null}
 */
export function fillRoute(view, target) {
  if (!targetFits(view, target)) return null;
  return { [TARGET_ROUTES[view].param]: target.value, [FILL_PARAM]: FILL_VALUE };
}

/**
 * Does a route only fill the form (`run=0`)? A view then never runs on arrival and never
 * replaces a draft of the user's in its input ({@link fillReplaces}).
 * @param {Record<string, string>|null|undefined} params
 * @returns {boolean}
 */
export function isFillOnly(params) {
  return !!params && params[FILL_PARAM] === FILL_VALUE;
}

/**
 * May a carried target (`run=0`) replace the text in a tool's box? Only when the box is empty,
 * still holds exactly what the tool last ran, or still holds exactly what the tool last took from
 * a carried target (the same entries, in any order) — never a draft of the user's. So the box
 * follows every newer target, not only the first one, until the user types in it. The tool
 * remembers `carried` (its box text right after it took a target) until its next run.
 * @param {string} text the box's text
 * @param {string[]|null|undefined} lastRun the entries of the tool's last run (null: none)
 * @param {(text: string) => string[]} entries how the tool reads its box
 * @param {string|null} [carried] the text the tool last took from a carried target (null: none)
 * @returns {boolean}
 */
export function fillReplaces(text, lastRun, entries, carried = null) {
  const s = String(text ?? '');
  if (!s.trim()) return true;
  if (typeof entries !== 'function') return false;
  const box = [...new Set(entries(s))].sort();
  const holds = (list) => {
    const b = [...new Set(list)].sort();
    return b.length > 0 && box.length === b.length && box.every((x, i) => x === b[i]);
  };
  if (Array.isArray(lastRun) && holds(lastRun)) return true;
  return typeof carried === 'string' && !!carried.trim() && holds(entries(carried));
}

/**
 * A tool that keeps its own state, opened on a route without a target (the nav link back to its
 * kept result): does its box go back to the last run's query? Only when it still holds exactly
 * a target it took from a carry since that run — checking A across the tools, then B, then A
 * again leaves B in the box while the chip and the kept result are about A again. Never over a
 * draft of the user's, never without a finished run, never when the box already holds the run.
 * @param {string} text the box's text
 * @param {string|null} carried the text the box last took from a carried target (null: none)
 * @param {string[]|null|undefined} lastRun the entries of the tool's last finished run (null: none)
 * @param {(text: string) => string[]} entries how the tool reads its box
 * @returns {boolean}
 */
export function backToLastRun(text, carried, lastRun, entries) {
  if (typeof carried !== 'string' || !carried.trim() || !Array.isArray(lastRun) || !lastRun.length) return false;
  if (typeof entries !== 'function') return false;
  const set = (list) => [...new Set(list)].sort();
  const same = (a, b) => a.length > 0 && a.length === b.length && a.every((x, i) => x === b[i]);
  const box = set(entries(String(text ?? '')));
  return same(box, set(entries(carried))) && !same(box, set(lastRun));
}

/* ------------------------------------------------------------------------ */
/* Routes                                                                   */
/* ------------------------------------------------------------------------ */

/** String params without the fill marker (a copy). */
function cleanParams(params) {
  const out = {};
  for (const [k, v] of Object.entries(params || {})) {
    if (k === FILL_PARAM || v === null || v === undefined) continue;
    out[k] = String(v);
  }
  return out;
}

/**
 * Order-independent key of route params, without the fill marker: '' for a bare route.
 * @param {Record<string, string>|null|undefined} params
 * @returns {string}
 */
export function routeKey(params) {
  const sp = new URLSearchParams(cleanParams(params));
  sp.sort();
  return sp.toString();
}

/** Milliseconds of a Date, number or date string (NaN when it is none). */
const timeOf = (value) => (value instanceof Date ? value.getTime() : new Date(value ?? NaN).getTime());

/**
 * Was the current target set after a tool's result was kept, and is it about something else
 * than that result? Then the tool's link carries the target instead of leading back to the
 * result (checking A across the tools, then B, fills B in everywhere).
 * @param {{ value: string, at?: Date }|null} target
 * @param {{ subject: string|null, at: Date }|null} kept
 * @returns {boolean}
 */
export function targetSupersedes(target, kept) {
  if (!target || !kept || !(timeOf(target.at) > timeOf(kept.at))) return false;
  const about = parseTarget(kept.subject);
  return !about || about.value !== target.value;
}

/**
 * Where a nav link to a tool leads: back to its kept result (the result's own params, with
 * `run=0` so a new tab only fills the form; a bare route for a tool that keeps its own state),
 * unless a newer target about something else fits the tool ({@link targetSupersedes}); else the
 * tool with the current target filled in (its kept result still shows under it:
 * {@link restorePlan} 'carry'), else the bare tool.
 * @param {string} view
 * @param {{ kept?: { params: Record<string, string>, subject?: string|null, at?: Date }|null,
 *   target?: { value: string, kind: string, at?: Date }|null }} [ctx]
 * @returns {Record<string, string>}
 */
export function carryRoute(view, { kept = null, target = null } = {}) {
  const fill = fillRoute(view, target);
  if (kept && !(fill && targetSupersedes(target, kept))) {
    const params = cleanParams(kept.params);
    if (Object.keys(params).length) params[FILL_PARAM] = FILL_VALUE;
    return params;
  }
  return fill || {};
}

/**
 * Does a route bring a tool's kept result back? A bare route or one with the result's own params
 * does ('restore': the URL then shows those params with `run=0`), and so does a route that only
 * fills the form with something else — a carried target ('carry': the URL and the tool's box keep
 * the target, the kept result shows under it). Any other params are a new query (null).
 * 'dropped' when the result was too large to keep: a bare route or its own params open the tool
 * with its query filled in and nothing run; a carried target then only fills the box (null).
 * @param {Record<string, string>} params the route's params
 * @param {{ params: Record<string, string>, snapshot: any, dropped: boolean }|null} kept
 * @returns {'restore'|'carry'|'dropped'|null}
 */
export function restorePlan(params, kept) {
  if (!kept || !(kept.snapshot || kept.dropped)) return null;
  const key = routeKey(params);
  if (!key || key === routeKey(kept.params)) return kept.snapshot ? 'restore' : 'dropped';
  return isFillOnly(params) && kept.snapshot ? 'carry' : null;
}

/* ------------------------------------------------------------------------ */
/* Results                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * A view's `result()` in the shape the shell uses: `{ subject, at, params, rerun, label }` with a
 * valid Date, or null (no finished result, or not a usable one). `params`: the route params of the
 * result itself (they bring it back, and its Copy link shares them), without `run`; null when the
 * view gives none. They can differ from the URL's, which say what the tool's box holds (a carried
 * target). `rerun` is false when the view says its note offers no "Run again" (`rerun: false`: its
 * own Re-run sits in the page header, or the result cannot be run again, like a certificate file).
 * `label`: the translation key of the note's text (with `{time}`) when "Result from <time>" would
 * not say which result it is, like the Zone File's live check under its other tabs; null for the
 * shell's own wording.
 * @param {unknown} res
 * @returns {{ subject: string|null, at: Date, params: Record<string, string>|null, rerun: boolean, label: string|null }|null}
 */
export function normalizeResult(res) {
  if (!res || typeof res !== 'object') return null;
  const at = res.at instanceof Date ? res.at : new Date(res.at ?? NaN);
  if (!Number.isFinite(at.getTime())) return null;
  return {
    subject: typeof res.subject === 'string' && res.subject ? res.subject : null,
    at,
    params: res.params && typeof res.params === 'object' && !Array.isArray(res.params) ? cleanParams(res.params) : null,
    rerun: res.rerun !== false,
    label: typeof res.label === 'string' && res.label ? res.label : null
  };
}

/**
 * What the page header's kept-result note says after a view mounted, or null for none. A
 * language re-mount keeps the note it had (`note` given, null included); a result too large to
 * keep says so, with "Run again" only when its query came back (the result had route params: an
 * IP Intel run of more than 40 entries has none, so the tool opens empty). Otherwise only a
 * finished result older than this mount gets the note: for a tool with `snapshot()` that is the
 * result it got back; a tool that keeps its own state (`restorable` false) gets it only for the
 * result the shell kept when the tool was left (the same `at`) — never for one that came from
 * elsewhere (a certificate loaded in SSL Targets) or finished while the tool was not shown.
 * `rerun`: the note offers "Run again"; `label`: the result's own wording ({@link normalizeResult}).
 * @param {{ note?: { at: Date, dropped: boolean, rerun: boolean, label?: string|null }|null,
 *   plan?: 'restore'|'carry'|'dropped'|null, kept?: { at: Date, params?: Record<string, string> }|null,
 *   result?: { at: Date, rerun?: boolean, label?: string|null }|null, mountedAt: number, restorable?: boolean }} info
 * @returns {{ at: Date, dropped: boolean, rerun: boolean, label: string|null }|null}
 */
export function keptNote({ note = undefined, plan = null, kept = null, result = null, mountedAt, restorable = true }) {
  if (note !== undefined) return note;
  if (plan === 'dropped' && kept) {
    return { at: kept.at, dropped: true, rerun: Object.keys(cleanParams(kept.params)).length > 0, label: null };
  }
  const at = result ? timeOf(result.at) : NaN;
  if (!(at < mountedAt)) return null;
  if (!restorable && !(kept && timeOf(kept.at) === at)) return null;
  return { at: result.at, dropped: false, rerun: result.rerun !== false, label: result.label || null };
}

/* ------------------------------------------------------------------------ */
/* Memory                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Rough memory size of a value in bytes (UTF-16 strings, 8-byte numbers, binary buffers by
 * length, shared objects and cycles counted once). The walk stops as soon as the total passes
 * `limit`, so measuring a huge result costs no more than the limit.
 * @param {unknown} value
 * @param {number} [limit=Infinity]
 * @returns {number}
 */
export function estimateSize(value, limit = Infinity) {
  const seen = new WeakSet();
  const stack = [value];
  let total = 0;
  while (stack.length && total <= limit) {
    const v = stack.pop();
    switch (typeof v) {
      case 'string':
        total += v.length * 2;
        continue;
      case 'number':
        total += 8;
        continue;
      case 'boolean':
        total += 4;
        continue;
      case 'bigint':
        total += 16;
        continue;
      case 'object':
        break;
      default:
        continue; // undefined, functions, symbols
    }
    if (v === null || seen.has(v)) continue;
    seen.add(v);
    if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer) {
      total += v.byteLength;
    } else if (v instanceof Date) {
      total += 8;
    } else if (v instanceof Map) {
      total += 16 + v.size * 16;
      if (total <= limit) for (const [k, x] of v) stack.push(k, x);
    } else if (v instanceof Set) {
      total += 16 + v.size * 8;
      if (total <= limit) for (const x of v) stack.push(x);
    } else if (Array.isArray(v)) {
      total += 16 + v.length * 8;
      if (total <= limit) for (const x of v) stack.push(x);
    } else {
      const keys = Object.keys(v);
      total += 16;
      for (const k of keys) total += 8 + k.length * 2;
      if (total <= limit) for (const k of keys) stack.push(v[k]);
    }
  }
  return total;
}

/* ------------------------------------------------------------------------ */
/* Store                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SessionTarget
 * @property {string} value normalised domain, host name or IP address
 * @property {'domain'|'host'|'ip'} kind
 * @property {string|null} view the tool that set it
 * @property {Date} at
 */

/**
 * @typedef {object} KeptResult
 * @property {string} view
 * @property {Record<string, string>} params the result's own route params (no `run`): they bring it back
 * @property {string|null} subject what the result is about (a domain, a list's first entry …)
 * @property {Date} at when the result finished
 * @property {any} snapshot the tool's snapshot(), handed back as ctx.restored; null for a tool
 *   that keeps its own state (Subdomains, SSL Targets, Bulk Resolve, Certificate) or when dropped
 * @property {number} size estimated bytes of the snapshot
 * @property {boolean} dropped the snapshot was too large to keep (alone or with the others)
 */

/**
 * Create a page-session store (the shell has one; tests create their own).
 * @param {{ now?: () => Date, entryBytes?: number, totalBytes?: number,
 *   estimate?: (value: unknown, limit: number) => number }} [opts]
 */
export function createSessionStore({
  now = () => new Date(),
  entryBytes = DEFAULT_LIMITS.entryBytes,
  totalBytes = DEFAULT_LIMITS.totalBytes,
  estimate = estimateSize
} = {}) {
  /** @type {SessionTarget|null} */
  let target = null;
  /**
   * Insertion order = the order the results came in (a new result moves its tool to the end; the
   * same result kept again when its tool is left once more stays where it was), so the oldest
   * result is dropped first.
   */
  const kept = new Map();
  const listeners = new Set();

  function emit(type, view = null) {
    for (const fn of [...listeners]) {
      try {
        fn({ type, view });
      } catch (err) {
        setTimeout(() => {
          throw err;
        }, 0);
      }
    }
  }

  const toDate = (value) => {
    const d = value instanceof Date ? value : new Date(value ?? NaN);
    return Number.isFinite(d.getTime()) ? d : now();
  };
  const copy = (entry) => (entry ? { ...entry, params: { ...entry.params } } : null);

  /**
   * Drop the oldest snapshots (their queries stay, marked dropped) until the total fits; a new
   * result (`latest`) goes last, a result kept again (null) in its own turn.
   */
  function trim(latest) {
    let total = 0;
    for (const e of kept.values()) total += e.size;
    for (const e of kept.values()) {
      if (total <= totalBytes) break;
      if (e === latest || !e.snapshot) continue;
      total -= e.size;
      Object.assign(e, { snapshot: null, size: 0, dropped: true });
    }
    if (latest && total > totalBytes && latest.snapshot) Object.assign(latest, { snapshot: null, size: 0, dropped: true });
  }

  const api = {
    /** The current target (a copy), or null. */
    get target() {
      return target ? { ...target } : null;
    },

    /**
     * Make `input` the current target when it is one (see {@link parseTarget}).
     * @param {string} input
     * @param {{ view?: string|null }} [opts] the tool that worked on it
     * @returns {SessionTarget|null} the new target, or null when `input` is none (nothing changes)
     */
    setTarget(input, { view = null } = {}) {
      const parsed = parseTarget(input);
      if (!parsed) return null;
      const changed = !target || target.value !== parsed.value;
      target = { ...parsed, view, at: now() };
      if (changed) emit('target');
      return api.target;
    },

    /** Forget the current target. @returns {boolean} true when there was one */
    clearTarget() {
      if (!target) return false;
      target = null;
      emit('target');
      return true;
    },

    /**
     * Keep a tool's finished result (at most one per tool: it replaces the previous one). A
     * snapshot larger than the entry bound is not kept (the entry is `dropped`); when all of them
     * together pass the total bound, the oldest results' snapshots are dropped first. The same
     * result kept again (the same `at` and params: the tool was left once more without a new run)
     * keeps its age, so a result only looked at again is not taken for the newest.
     * @param {string} view
     * @param {{ params?: Record<string, string>, subject?: string|null, at?: Date|number|string, snapshot?: any }} result
     * @returns {KeptResult} a copy of the entry
     */
    keep(view, { params = {}, subject = null, at = null, snapshot = null } = {}) {
      const has = snapshot !== null && snapshot !== undefined;
      const size = has ? estimate(snapshot, entryBytes) : 0;
      const tooLarge = has && size > entryBytes;
      const entry = {
        view: String(view),
        params: cleanParams(params),
        subject: typeof subject === 'string' && subject ? subject : null,
        at: toDate(at),
        snapshot: has && !tooLarge ? snapshot : null,
        size: has && !tooLarge ? size : 0,
        dropped: tooLarge
      };
      const prev = kept.get(entry.view);
      const again = !!prev && prev.at.getTime() === entry.at.getTime() && routeKey(prev.params) === routeKey(entry.params);
      if (!again) kept.delete(entry.view);
      kept.set(entry.view, entry);
      trim(again ? null : entry);
      emit('kept', entry.view);
      return copy(entry);
    },

    /**
     * The kept result of a tool (a copy; the snapshot itself is shared), or null.
     * @param {string} view
     * @returns {KeptResult|null}
     */
    kept(view) {
      return copy(kept.get(view) || null);
    },

    /** Forget one tool's kept result. @returns {boolean} */
    drop(view) {
      const had = kept.delete(view);
      if (had) emit('kept', view);
      return had;
    },

    /** Forget the target and every kept result ("Delete all local data"). */
    clear() {
      target = null;
      kept.clear();
      emit('cleared');
    },

    /** How much is kept: entries and estimated snapshot bytes. */
    usage() {
      let bytes = 0;
      for (const e of kept.values()) bytes += e.size;
      return { entries: kept.size, bytes };
    },

    /**
     * Subscribe to changes: `{ type: 'target' | 'kept' | 'cleared', view }`.
     * @param {(change: { type: string, view: string|null }) => void} fn
     * @returns {() => void} unsubscribe
     */
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    }
  };
  return api;
}
