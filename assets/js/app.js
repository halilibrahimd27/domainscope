/**
 * app.js — bootstrap: shell (header, nav, footer), hash router, theme, language,
 * settings dialog and the per-view context object.
 *
 * Routes: `#/<view>?key=value` (shareable, e.g. `#/lookup?name=example.com&type=MX`).
 * Unknown views fall back to 'subdomains'. Hashes that do not start with '#/' are in-page
 * anchors and never change the view.
 *
 * View modules (assets/js/views/<id>.js) are loaded lazily on first visit and must export
 * `{ id, titleKey, icon, mount(container, ctx), unmount?() }` — as named exports or as a
 * default-export object with the same shape. The shell renders the page <h1> and
 * description (`nav.<id>` / `nav.<id>.desc`); `mount` fills the page body. See the
 * `ViewContext` typedef below for everything a view receives.
 *
 * Navigation (docs/DESIGN.md §3): one header row at every width; from 1100 px a sidebar, below it
 * a Tools button in the header opening the same groups as a drawer (tablets) or as a full-screen
 * sheet that is also the palette (phones), all built from VIEWS (lib/shellnav.js groupViews). The
 * page header gives each tool one purpose line and an ⓘ for the rest. The start page shows a
 * first-visit task picker until it is dismissed or the visitor runs something.
 *
 * Keyboard shortcuts (one listener here, lib/shellnav.js shortcutFor): Ctrl/Cmd+Enter in a field
 * clicks the `data-shortcut="submit"` control of the field's form (the view's Run; inside a
 * `data-shortcut-scope` sub-form such as a paste box, that sub-form's own button; in one without
 * a submit — a view's results area, a DataTable — nothing), Esc the view's `"cancel"` one (on
 * screen, else in a closed tab; in a search field with text Esc clears it), '/' focuses its
 * `"focus"` input (else its first text field), '?' opens the shortcuts dialog, Ctrl/Cmd+K the palette.
 *
 * Page session (lib/session.js, memory only): a view reports each run with
 * `ctx.runStarted(subject)`, which makes it the current target shown in the header chip; the
 * nav links carry that target into the other tools (`run=0`: filled in, never run). A view that
 * also exports `result()` → `{ subject, at, params?, rerun?, label? } | null` (its finished result;
 * `params`: the result's own route params) keeps it when it is left — with `snapshot()` when it
 * has one — and gets it back as `ctx.restored` when it is opened again, also under a carried
 * target that its box then takes; the page header says "Result from <time>" (or the result's own
 * `label`), with "Run again" calling `rerun(ctx)` unless the result says `rerun: false`. The note goes with
 * the next `runStarted()`, or with `ctx.resultChanged()` when the result is replaced or dropped
 * some other way. "Delete all local data" forgets all of it and opens the tool on screen again,
 * bare.
 *
 * What this page sent: boot() starts ui/egress-meter.js before anything can send (the fetch
 * wrapper and the Resource Timing observer, lib/egresslog.js), and the footer's link, with the
 * count of third-party requests, opens About's ledger (`#/about?section=sent`).
 *
 * Installable app: once the first view is up the shell registers the service worker
 * (ui/pwa.js; Pages bundle only). Offline, a view that needs the network says so above its
 * body, and ctx.requireOnline() stops its network work with a message instead of failing requests.
 *
 * Workspaces (state.js, lib/workspace.js): the first view mounts once `state.ready` has opened the
 * workspace store. The header's switcher (inside the Tools menu below 720 px) opens the
 * Workspaces dialog (ui/workspace-panel.js, loaded on first use). A switch asks first when a long
 * job runs (it stops) or the view on screen has edits it would drop (an optional `unsaved()`
 * export: Servers), forgets the page session, makes the new workspace's most recent domain the
 * current target and opens the tool on screen again with it filled in. Every target a tool runs
 * on goes to the top of the active workspace's recent list.
 */

import {
  t, setLang, getLang, detectLang, onLangChange, formatNumber, formatRegion, hasString
} from './i18n.js';
import { state, CONCURRENCY_RANGE } from './state.js';
import { h, clear, uid } from './ui/dom.js';
import {
  Icon, SegmentedControl, IconButton, Button, Alert, ErrorBanner, Spinner, Modal, toast,
  select, Badge, confirmDialog, announce, describeError, setButtonBusy
} from './ui/components.js';
import { RESOLVERS, getResolver } from './lib/resolvers.js';
import {
  groupViews, isPlainClick, isRunSignal, hasUsedBefore, SHORTCUTS, keyCaps, isApplePlatform, shortcutFor, pickShortcutTarget,
  isTypingTarget, isSearchClear, navMenuMode, aboutSectionOf, paletteKeyHint, PALETTE_KEYSHORTCUTS, SHELL_WIDTHS
} from './lib/shellnav.js';
import { StartTaskList } from './ui/start-tasks.js';
import {
  createSessionStore, carryRoute, restorePlan, normalizeResult, keptNote, FILL_PARAM, FILL_VALUE
} from './lib/session.js';
import { TargetChip, KeptNote } from './ui/session-ui.js';
import { permalinkParams, utcStamp } from './lib/summarycore.js';
import { resultPermalink } from './ui/summary-button.js';
import { registerServiceWorker, reloadPage, setManifestLang } from './ui/pwa.js';
import { setBaseTitle, refreshJobIndicators, runningWork } from './ui/jobs.js';
import { WorkspaceSwitch, WorkspaceMenuEntry, workspaceLabel, deleteAllLocalData, storageErrorText } from './ui/workspace-ui.js';
import { egressLog, startEgressMeter } from './ui/egress-meter.js';
import { countRequests } from './lib/egresslog.js';

/** Repository URL shown in the header/footer. */
export const REPO_URL = 'https://github.com/halilibrahimd27/domainscope';
/** App version (keep in sync with package.json). */
export const APP_VERSION = '1.0.0';
/** Default route. */
export const DEFAULT_VIEW = 'subdomains';
/** The first view waits this long at most for the workspace store (IndexedDB) to open. */
const WORKSPACE_WAIT_MS = 8000;

/**
 * Every per-view stylesheet (paths under assets/css/) in cascade order. index.html links only
 * style.css; a view's sheets are injected when it is first opened and stay, and a sheet
 * injected later goes before the ones that follow it here, so the cascade never depends on the
 * order the views were opened in.
 */
export const VIEW_CSS_ORDER = Object.freeze([
  'views/subdomains.css', 'views/domain.css', 'views/fix.css', 'views/zone.css', 'views/zonetools.css', 'views/scan.css', 'views/verify.css', 'views/dane.css', 'views/cert.css',
  'views/renew.css', 'views/estate.css', 'views/global.css', 'views/lookup.css', 'views/bulk.css', 'views/change.css', 'views/ip.css', 'views/ptr.css', 'views/retire.css',
  'views/health.css', 'views/reports.css', 'views/portfolio.css', 'views/monitor.css', 'views/inventory.css', 'views/topology.css', 'views/about.css'
]);

/**
 * The discovery engine's modules (paths under assets/js/) that the Subdomains and SSL Targets
 * views import only when a scan starts: modulepreloaded once the page is idle, so Start rarely
 * waits for them. A unit test keeps the list equal to what lib/scanner.js adds to the
 * Subdomains view's own imports.
 */
export const ENGINE_MODULES = Object.freeze([
  'lib/scanner.js', 'lib/sources.js', 'lib/doh.js', 'lib/dnswire.js', 'lib/permute.js', 'lib/topology.js', 'lib/netinfo.js',
  'lib/localeevidence.js', 'lib/punycode.js'
]);

/**
 * Navigation table, in navigation order (docs/DESIGN.md §3.1: six groups by job). `group` is one of
 * lib/shellnav.js NAV_GROUPS (the sidebar, the tablet drawer and the phone Tools sheet all list the
 * views by it; an unknown group lands under "More tools").
 * `load` is a lazy import so a view that fails to load (or is still being written) cannot break
 * the rest of the app. `css`: its stylesheets (paths
 * under assets/css/, loaded before it mounts); `preload`: modules it imports on first use
 * (paths under assets/js/, modulepreloaded when the page is idle); `offline`: it needs no
 * network (the service worker keeps it working offline; the other views say they need one).
 */
export const VIEWS = Object.freeze([
  // Investigate a domain: "a customer asks about example.com"
  { id: 'domain', group: 'investigate', icon: 'id-card', css: ['views/domain.css'], load: () => import('./views/domain.js') },
  { id: 'health', group: 'investigate', icon: 'activity', css: ['views/fix.css', 'views/health.css'], load: () => import('./views/health.js') },
  // A scan's progress and results (ui/subdomains-run.js, with the evidence banner it shares with SSL
  // Targets, ui/locale-evidence.js) load with its first scan, after the engine.
  { id: 'subdomains', group: 'investigate', icon: 'layers', css: ['views/subdomains.css'], preload: [...ENGINE_MODULES, 'ui/subdomains-run.js', 'ui/locale-evidence.js', 'lib/export.js', 'lib/subtabs.js', 'lib/originnow.js'], load: () => import('./views/subdomains.js') },
  { id: 'lookup', group: 'investigate', icon: 'search', css: ['views/lookup.css'], load: () => import('./views/lookup.js') },
  // Deploy & renew certificates: the certificate's lifecycle, from the file to every server
  {
    id: 'scan', group: 'certs', icon: 'target', preload: ENGINE_MODULES, load: () => import('./views/scan.js'),
    // the setup form reuses the Subdomains options and the Certificate loader; Verify and DANE are tabs
    css: ['views/subdomains.css', 'views/scan.css', 'views/verify.css', 'views/dane.css', 'views/cert.css', 'views/topology.css']
  },
  { id: 'cert', group: 'certs', icon: 'shield', css: ['views/dane.css', 'views/cert.css'], offline: true, load: () => import('./views/cert.js') },
  // the certificate block reuses the Certificate view's loader (its module graph brings the DANE panel's classes)
  { id: 'renew', group: 'certs', icon: 'refresh', css: ['views/dane.css', 'views/cert.css', 'views/renew.css'], load: () => import('./views/renew.js') },
  // the CLI's --json reports, read in the browser (nothing sent)
  { id: 'estate', group: 'certs', icon: 'certificate', css: ['views/estate.css'], offline: true, load: () => import('./views/estate.js') },
  // Change & migrate DNS: plan a change, check it propagated, move zones, retire addresses
  // the form, its validation and every output need no network; Read and the check page say so in place
  { id: 'change', group: 'change', icon: 'edit', css: ['views/fix.css', 'views/change.css'], offline: true, load: () => import('./views/change.js') },
  { id: 'global', group: 'change', icon: 'globe', css: ['views/global.css'], load: () => import('./views/global.js') },
  // "Show the fix" (ui/fix-panel.js, loaded on first use) is styled by views/fix.css; Compare and Convert
  // (ui/zone-tools.js, loaded on their first use, modulepreloaded when idle) by views/zonetools.css
  {
    id: 'zone', group: 'change', icon: 'file-text', css: ['views/fix.css', 'views/zone.css', 'views/zonetools.css'], offline: true,
    preload: ['ui/zone-tools.js', 'lib/zonediff.js', 'lib/zoneconvert.js', 'lib/zonetext.js'], load: () => import('./views/zone.js')
  },
  { id: 'retire', group: 'change', icon: 'unlink', css: ['views/retire.css'], load: () => import('./views/retire.js') },
  // Map IPs to servers: names → addresses → your machines
  { id: 'ip', group: 'network', icon: 'network', css: ['views/ip.css'], load: () => import('./views/ip.js') },
  { id: 'bulk', group: 'network', icon: 'list', css: ['views/bulk.css'], load: () => import('./views/bulk.js') },
  { id: 'ptr', group: 'network', icon: 'swap', css: ['views/ptr.css'], load: () => import('./views/ptr.js') },
  // Watch & report: many domains over time; customer-facing reports
  // many domains, one row each, and the workspace's policy audit (RDAP and DoH: needs the network)
  { id: 'portfolio', group: 'watch', icon: 'box', css: ['views/portfolio.css'], load: () => import('./views/portfolio.js') },
  // the runner's results and history, read in the browser (GitHub on a click only)
  { id: 'monitor', group: 'watch', icon: 'eye', css: ['views/monitor.css'], offline: true, load: () => import('./views/monitor.js') },
  { id: 'reports', group: 'watch', icon: 'inbox', css: ['views/reports.css'], offline: true, load: () => import('./views/reports.js') },
  // Setup & help: the server list every tool uses; how the app works
  { id: 'inventory', group: 'setup', icon: 'server', css: ['views/inventory.css', 'views/topology.css'], offline: true, load: () => import('./views/inventory.js') },
  { id: 'about', group: 'setup', icon: 'info', css: ['views/about.css'], offline: true, load: () => import('./views/about.js') }
].map((v) => Object.freeze({
  offline: false, ...v, css: Object.freeze([...(v.css || [])]), preload: Object.freeze([...(v.preload || [])])
})));

const VIEW_BY_ID = new Map(VIEWS.map((v) => [v.id, v]));

/* ------------------------------------------------------------------------ */
/* Route helpers (pure — unit-tested)                                        */
/* ------------------------------------------------------------------------ */

/** A view's sub-page ('#/change/check'): one lowercase word, else none. */
const SUB_RE = /^[a-z][a-z0-9-]{0,31}$/;

/**
 * Parse a location hash.
 * @param {string} hash e.g. '#/lookup?name=example.com&type=MX'
 * @returns {{ view: string|null, sub: string, params: Record<string, string>, searchParams: URLSearchParams, isRoute: boolean }}
 *   view is null for unknown views or an empty route; `sub` is a view's sub-page ('#/change/check' → 'check'),
 *   '' when there is none or it is not one word; isRoute is false for non-route anchors ('#main').
 */
export function parseRoute(hash) {
  const raw = String(hash ?? '').replace(/^#/, '');
  if (!raw.startsWith('/')) return { view: null, sub: '', params: {}, searchParams: new URLSearchParams(), isRoute: false };
  const rest = raw.slice(1);
  const q = rest.indexOf('?');
  const path = q === -1 ? rest : rest.slice(0, q);
  const query = q === -1 ? '' : rest.slice(q + 1);
  let id = '';
  let sub = '';
  try {
    const [first, ...more] = path.split('/');
    id = decodeURIComponent(first || '').trim().toLowerCase();
    sub = decodeURIComponent(more.join('/')).trim().toLowerCase();
  } catch {
    id = '';
  }
  const searchParams = new URLSearchParams(query);
  const params = {};
  for (const [k, v] of searchParams) params[k] = v; // repeated keys: last wins (use searchParams.getAll)
  const view = VIEW_BY_ID.has(id) ? id : null;
  return { view, sub: view && SUB_RE.test(sub) ? sub : '', params, searchParams, isRoute: true };
}

/**
 * Build a route hash. null/undefined/''/false values are skipped, true → '1',
 * arrays become repeated keys. A view may name a sub-page: 'change/check'.
 * @param {string} view
 * @param {Record<string, unknown>} [params]
 * @returns {string} e.g. '#/global?name=www.example.com&type=A'
 */
export function buildRoute(view, params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v === null || v === undefined || v === '' || v === false) continue;
    if (Array.isArray(v)) v.filter((x) => x !== null && x !== undefined && x !== '').forEach((x) => sp.append(k, String(x)));
    else sp.set(k, v === true ? '1' : String(v));
  }
  const qs = sp.toString();
  const [id, sub = ''] = String(view || DEFAULT_VIEW).split('/');
  return `#/${encodeURIComponent(id)}${SUB_RE.test(sub) ? `/${sub}` : ''}${qs ? `?${qs}` : ''}`;
}

/**
 * Shallow equality of two param objects (string values).
 * @param {Record<string, string>} a
 * @param {Record<string, string>} b
 * @returns {boolean}
 */
export function sameParams(a, b) {
  const ka = Object.keys(a || {});
  const kb = Object.keys(b || {});
  return ka.length === kb.length && ka.every((k) => String(a[k]) === String((b || {})[k]));
}

/**
 * Do two route queries carry the same params? Unlike {@link sameParams} a repeated key
 * counts (`domain=a&domain=b` ≠ `domain=b`); the order of different keys does not.
 * @param {URLSearchParams} a
 * @param {URLSearchParams} b
 * @returns {boolean}
 */
export function sameSearch(a, b) {
  const norm = (sp) => {
    const sorted = new URLSearchParams(sp || '');
    sorted.sort(); // stable: the values of one key keep their order
    return sorted.toString();
  };
  return norm(a) === norm(b);
}

/**
 * Does a route query repeat a key (`domain=a&domain=b`)? The flat `params` a view's
 * update() receives keep only the last value, so such a route re-mounts the view instead.
 * @param {URLSearchParams} searchParams
 * @returns {boolean}
 */
export function hasRepeatedKeys(searchParams) {
  const keys = [...searchParams.keys()];
  return new Set(keys).size !== keys.length;
}

/**
 * Where a view stylesheet goes among the ones already in the page: before the first that comes
 * later in {@link VIEW_CSS_ORDER} (a sheet missing from it counts as last).
 * @param {string} file the sheet to insert, e.g. 'views/scan.css'
 * @param {string[]} present the sheets already in the page, in document order
 * @returns {string|null} the sheet to insert it before, or null to add it after them all
 */
export function stylesheetBefore(file, present) {
  const rank = (f) => {
    const i = VIEW_CSS_ORDER.indexOf(f);
    return i === -1 ? VIEW_CSS_ORDER.length : i;
  };
  return (present || []).find((p) => rank(p) > rank(file)) ?? null;
}

/* ------------------------------------------------------------------------ */
/* Lazy modules after a deploy                                              */
/* ------------------------------------------------------------------------ */

/** A module fetched now does not match one this page loaded earlier (Chrome, Firefox, Safari). */
const STALE_LINK_RE = /does(?: not|n['’]t) provide an export named|^import not found:|Importing binding name .+ is not found/i;
/** A lazily imported module (or one of its imports) could not be fetched (Chrome, Firefox, Safari). */
const STALE_FETCH_RE = /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed/i;

/** How long the "is this page's version still on the server?" probe may take. */
const PROBE_TIMEOUT_MS = 8000;

/**
 * Could a lazy import have failed because this page belongs to an earlier deploy? Either a module
 * fetched now does not link against the ones already loaded (a missing export, SyntaxError), or
 * it could not be fetched at all (TypeError): the Pages bundle serves each deploy from its own
 * v/<version>/ directory (tools/assemble-site.mjs), so the old one is gone. The fetch case is
 * also what an offline browser or a dropped connection reports, so only
 * {@link confirmStaleModule} decides; this is the message check alone.
 * @param {unknown} err rejection of `import()`
 * @returns {boolean}
 */
export function isStaleModuleError(err) {
  if (!err || typeof err !== 'object') return false;
  const message = typeof err.message === 'string' ? err.message : '';
  if (err.name === 'SyntaxError') return STALE_LINK_RE.test(message);
  if (err.name === 'TypeError') return STALE_FETCH_RE.test(message);
  return false;
}

/**
 * Is this page's own version gone from the server? Only when the browser is online and this
 * module's URL answers 404 (a newer deploy replaced v/<version>/). Offline, a failed or slow
 * probe, or any other status is a network problem, not an update: a reload would then only
 * throw away what the page holds in memory (an imported zone file, scan results).
 * @param {{ online?: boolean, probe?: () => Promise<number> }} [env] tests inject both
 * @returns {Promise<boolean>}
 */
export async function pageIsOutdated({ online = globalThis.navigator?.onLine, probe = probeModule } = {}) {
  if (online === false) return false;
  try {
    return (await probe()) === 404;
  } catch {
    return false;
  }
}

/** HTTP status of a module's URL (this one's by default), past every cache (rejects on a network error or timeout). */
async function probeModule(url = import.meta.url) {
  const res = await fetch(url, { method: 'HEAD', cache: 'no-store', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
  return res.status;
}

/**
 * Did a lazy import really fail because this page belongs to an earlier deploy? A link error
 * says so by itself — retrying in the same document cannot fix it, the browser keeps the modules
 * it already has. A fetch error counts only if {@link pageIsOutdated} confirms it.
 * @param {unknown} err rejection of `import()`
 * @param {{ online?: boolean, probe?: () => Promise<number> }} [env] passed to pageIsOutdated
 * @returns {Promise<boolean>}
 */
export async function confirmStaleModule(err, env) {
  if (!isStaleModuleError(err)) return false;
  if (err.name === 'SyntaxError') return true;
  return pageIsOutdated(env);
}

/**
 * Why only a reload can load a module whose import failed: 'outdated' ({@link confirmStaleModule}),
 * or 'stuck': its URL (in Chrome's and Firefox's message) answers now, but the browser keeps a
 * failed module fetch for the rest of the document. null: a network problem (Retry stays).
 * @param {unknown} err rejection of `import()`
 * @param {{ online?: boolean, probe?: (url?: string) => Promise<number> }} [env] tests inject both
 * @returns {Promise<'outdated'|'stuck'|null>}
 */
export async function moduleReloadReason(err, env = {}) {
  if (await confirmStaleModule(err, env)) return 'outdated';
  const url = isStaleModuleError(err) && /https?:\/\/\S+/.exec(err.message);
  const { online = globalThis.navigator?.onLine, probe = probeModule } = env;
  if (!url || online === false) return null;
  return probe(url[0]).then((status) => (status < 300 ? 'stuck' : null), () => null);
}

let outdatedNoticeShown = false;

/**
 * Something this page loads on demand failed: a shared lazy module (DoH, Globalping) or a data
 * file (a wordlist tier, a locale pack). If `isOutdated` says only a reload helps, say so once,
 * with a reload button; otherwise stay quiet so a later failure can check again.
 * @param {() => Promise<boolean|string|null>} isOutdated moduleReloadReason for a module, pageIsOutdated for a data file
 */
function noticeIfOutdated(isOutdated) {
  if (outdatedNoticeShown) return;
  isOutdated().then((stale) => {
    if (!stale || outdatedNoticeShown) return;
    outdatedNoticeShown = true;
    toast(t(stale === 'stuck' ? 'shell.viewStuck' : 'shell.viewOutdated'), {
      type: 'warn',
      timeout: 0,
      action: { label: t('shell.reload'), onClick: () => reloadPage() }
    });
  });
}

/* ------------------------------------------------------------------------ */
/* Shared DNS client                                                        */
/* ------------------------------------------------------------------------ */

let dnsPromise = null;
let dnsChainKey = '';

/**
 * Resolvers a bulk sweep prefers (the fast, browser-readable anycast pool of lib/doh.js's
 * balance mode). Only the ones the user kept in the Settings chain are ever used.
 */
export const BULK_POOL_PREFERRED = Object.freeze(['cloudflare', 'google', 'dnssb']);

/**
 * The balance pool for bulk scans, derived from the user's resolver chain so a resolver
 * removed in Settings never receives a scan's guesses: the preferred bulk resolvers that are
 * in the chain; otherwise the chain's browser-readable resolvers; otherwise the chain itself.
 * @param {string[]} chain resolver ids in the user's order
 * @returns {string[]}
 */
export function balancePoolFor(chain) {
  const ids = (Array.isArray(chain) ? chain : []).filter((id) => typeof id === 'string');
  const preferred = BULK_POOL_PREFERRED.filter((id) => ids.includes(id));
  if (preferred.length) return preferred;
  const readable = ids.filter((id) => (getResolver(id) || {}).browserReliable !== false);
  return readable.length ? readable : [...ids];
}

/**
 * Shared DohClient (lib/doh.js), created lazily and configured from settings
 * (resolver chain + concurrency; the bulk balance pool comes from the chain too, see
 * {@link balancePoolFor}). A chain change creates a fresh client on the next call;
 * a concurrency change is applied to the existing one.
 * @returns {Promise<import('./lib/doh.js').DohClient>}
 */
export function getDns() {
  const { chain, concurrency } = state.settings;
  const key = chain.join(',');
  if (!dnsPromise || key !== dnsChainKey) {
    dnsChainKey = key;
    const balancePool = balancePoolFor(chain);
    const promise = import('./lib/doh.js').then(({ DohClient }) => new DohClient({ chain, concurrency, balancePool }));
    dnsPromise = promise;
    // A failed import (offline, file missing) must not be cached forever.
    promise.catch((err) => {
      if (dnsPromise === promise) dnsPromise = null;
      noticeIfOutdated(() => moduleReloadReason(err));
    });
  }
  return dnsPromise;
}

state.subscribe(({ key, value }) => {
  if (key !== 'settings' || !dnsPromise) return;
  if (value.chain.join(',') !== dnsChainKey) {
    dnsPromise = null; // recreated with the new chain on next getDns()
    return;
  }
  dnsPromise.then((client) => {
    if (client && typeof client.setConcurrency === 'function') client.setConcurrency(value.concurrency);
  }).catch(() => {});
});

/* ------------------------------------------------------------------------ */
/* Shared Globalping client                                                 */
/* ------------------------------------------------------------------------ */

let gpPromise = null;

/**
 * Shared Globalping client (lib/globalping.js): one instance per page, so every view sees one
 * merged quota (the anonymous hourly quota is per IP address). Creating it sends nothing.
 * A failed load is not cached, so the next call tries again.
 * @param {() => Promise<{ createGlobalping: Function }>} [load] module loader (tests inject one)
 * @returns {Promise<object>} createGlobalping() instance
 */
export function getGlobalping(load = () => import('./lib/globalping.js')) {
  if (!gpPromise) {
    const promise = Promise.resolve().then(load).then(({ createGlobalping }) => createGlobalping());
    gpPromise = promise;
    promise.catch((err) => {
      if (gpPromise === promise) gpPromise = null;
      noticeIfOutdated(() => moduleReloadReason(err));
    });
  }
  return gpPromise;
}

state.subscribe(({ key }) => {
  // "Delete all local data" also forgets a Globalping token (Phase D sets one; the MVP never does).
  if (key !== 'cleared' || !gpPromise) return;
  gpPromise.then((client) => {
    if (client && typeof client.setToken === 'function') client.setToken(null);
  }).catch(() => {});
});

/* ------------------------------------------------------------------------ */
/* Page session: the current target and each tool's kept result             */
/* ------------------------------------------------------------------------ */

/**
 * The page session (lib/session.js): the current target and the last finished result of each
 * tool, in this tab's memory only. "Delete all local data" forgets both.
 */
export const pageSession = createSessionStore();

state.subscribe(({ key }) => {
  if (key === 'cleared') {
    pageSession.clear();
    forgetShown();
  } else if (key === 'workspace') {
    // Another customer: the target, the kept results and what the tool on screen shows were the
    // previous workspace's. Its most recent domain becomes the target, filled in everywhere.
    pageSession.clear();
    const recent = state.workspaceData('recent');
    if (recent.length) pageSession.setTarget(recent[0].value);
    forgetShown({ always: true, carry: true });
  }
});

// Every domain or host name a tool runs on goes to the top of the workspace's recent list.
pageSession.subscribe(({ type }) => {
  const target = type === 'target' ? pageSession.target : null;
  if (target && target.kind !== 'ip') state.recordRecent(target.value);
});

/**
 * "Delete all local data" ran: the tool on screen forgets what it shows too. Its note goes, its
 * result is not kept on the way out, and once every listener has dropped its own state (the
 * tools with module state listen too: Subdomains, SSL Targets, Bulk Resolve, the Certificate
 * view, Zone File), it opens again on its bare route, so nothing runs. After a switch to another
 * workspace (`always`) every tool opens again, with the new current target filled in (`carry`).
 * @param {{ always?: boolean, carry?: boolean }} [opts]
 */
function forgetShown({ always = false, carry = false } = {}) {
  const cur = current;
  if (!cur) return;
  setKeptNote(null);
  if (!always && (!cur.view || typeof cur.view.result !== 'function')) return;
  cur.forget = true;
  queueMicrotask(() => {
    if (current !== cur) return;
    const params = carry ? carryRoute(cur.id, { target: pageSession.target }) : {};
    const hash = buildRoute(cur.id, params);
    if (hash !== currentHash()) globalThis.history.replaceState(null, '', hash);
    showRoute(cur.id, params, { force: true });
  });
}

/**
 * A view's finished result as the shell uses it (`result()` export), or null.
 * @param {object} view the view module
 * @param {ViewContext} ctx
 * @returns {{ subject: string|null, at: Date, params: Record<string, string>|null, rerun: boolean, label: string|null }|null}
 */
function resultOf(view, ctx) {
  if (!view || typeof view.result !== 'function') return null;
  try {
    return normalizeResult(view.result(ctx));
  } catch (err) {
    reportError(err);
    return null;
  }
}

/**
 * Keep the finished result of a view that is being left. A view with `snapshot()` is kept with
 * it and the result's own route params (`result().params`; they bring it back) — not the URL's,
 * which say what the box holds (a carried target, a draft) and fall back only for a view that
 * gives none. Any other view keeps its own state, so only the fact is kept (its nav link then
 * opens it bare). A run still going is not a result: the result kept before stays. Nothing is
 * kept on the way out after "Delete all local data" (`forget`).
 * @param {{ id: string, view: object, ctx: ViewContext, forget?: boolean }} cur
 */
function keepResult(cur) {
  if (cur.forget) return;
  const res = resultOf(cur.view, cur.ctx);
  if (!res) return;
  const restorable = typeof cur.view.snapshot === 'function';
  let snapshot = null;
  if (restorable) {
    try {
      snapshot = cur.view.snapshot(cur.ctx);
    } catch (err) {
      reportError(err);
      return;
    }
  }
  const params = restorable ? res.params || cur.ctx.params : {};
  pageSession.keep(cur.id, { params, subject: res.subject, at: res.at, snapshot });
}

/* ------------------------------------------------------------------------ */
/* View context                                                             */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ViewContext
 * @property {string} id                      current view id
 * @property {string} sub                     the view's sub-page ('#/change/check' → 'check'), '' for its main page;
 *                                            setParams and shareUrl keep it
 * @property {typeof state} state             shared state (inventory, settings, session, subscribe)
 * @property {typeof t} t                     translate
 * @property {'tr'|'en'} lang                 language at mount time (views re-mount on change)
 * @property {Record<string, string>} params  route params (updated by setParams)
 * @property {URLSearchParams} searchParams   raw params (for repeated keys)
 * @property {AbortSignal} signal             aborted when the view unmounts — pass it to every network call
 * @property {any} restored                   value returned by the previous instance's `snapshot()` when the
 *                                            view is re-mounted after a language change, or the one kept when
 *                                            it was last left (lib/session.js), else null
 * @property {(view: string, params?: object, opts?: { replace?: boolean, force?: boolean }) => void} navigate
 * @property {(params: object, opts?: { merge?: boolean }) => void} setParams  update the URL without re-mounting
 * @property {(view: string, params?: object) => string} href  route hash for links ('#/lookup?name=x')
 * @property {(params?: object) => string} shareUrl  absolute URL of this view with params
 * @property {() => Promise<object>} getDns   shared DohClient
 * @property {() => Promise<object>} getGlobalping  shared Globalping client (one quota view; sends nothing by itself)
 * @property {() => void} checkOutdated  a data file (wordlist tier, locale pack) or a module loaded on first use
 *                                         failed to load: if this page belongs to an earlier deploy, the shell
 *                                         offers a reload (once)
 * @property {(opts?: { quiet?: boolean }) => boolean} requireOnline  network work is about to start: false, with
 *                                         a toast saying it needs the network, while the browser is offline (then
 *                                         send nothing); `quiet` for work the view starts by itself, such as
 *                                         a shared link's run (no toast: the page's offline note says it)
 * @property {(busy: boolean|string) => void} setBusy  header activity bar + aria-busy; defers language re-mounts
 * @property {(subject: string|null) => void} runStarted  a run starts (or a certificate loads) for `subject` (a domain,
 *                                         host name or IP address): it becomes the current target, and the
 *                                         header's note about a kept result goes away
 * @property {() => void} resultChanged  the result on screen was replaced or dropped without a run (a new
 *                                         import, Forget): the header's note about a kept result goes away
 * @property {typeof toast} toast
 * @property {(...nodes: any[]) => void} setActions  put buttons into the page header (right side)
 * @property {(fn: () => void) => void} onCleanup  run fn when the view unmounts (e.g. state.subscribe's unsubscribe)
 * @property {() => Map<string, object[]>} getInventoryIndex  memoized IP → servers index
 * @property {ReadonlyArray<{ id: string, group: string, icon: string }>} views  the navigation registry (VIEWS)
 * @property {string} repoUrl
 * @property {string} version
 */

let current = null; // { id, def, view, params, ctx, controller, cleanups[], busy, note, forget? }
let routeToken = 0;
let pendingLangRemount = false;
let firstRouteDone = false;
let offlineNotice = null; // requireOnline's "needs the network" toast (one at a time)
const dom = {};

function currentHash() {
  return globalThis.location ? globalThis.location.hash : '';
}

/**
 * Navigate to a view (or one of its sub-pages: 'change/check').
 * @param {string} view
 * @param {object} [params]
 * @param {{ replace?: boolean, force?: boolean }} [opts] replace: no new history entry; force: re-mount even if unchanged
 */
export function navigate(view, params = {}, { replace = false, force = false } = {}) {
  const target = VIEW_BY_ID.has(String(view).split('/')[0]) ? view : DEFAULT_VIEW;
  const hash = buildRoute(target, params);
  if (hash === currentHash()) {
    if (force) {
      const route = parseRoute(hash);
      showRoute(route.view, route.params, { force: true, searchParams: route.searchParams, sub: route.sub });
    }
    return;
  }
  if (replace) {
    globalThis.history.replaceState(null, '', hash);
    handleRoute();
  } else {
    globalThis.location.hash = hash;
  }
}

function makeContext(id, params, searchParams, controller, restored, sub = '') {
  const cleanups = [];
  const route = sub ? `${id}/${sub}` : id;
  const ctx = {
    id,
    sub,
    state,
    t,
    lang: getLang(),
    params: { ...params },
    searchParams,
    signal: controller.signal,
    restored: restored ?? null,
    repoUrl: REPO_URL,
    version: APP_VERSION,
    views: VIEWS,
    navigate,
    href: buildRoute,
    getDns,
    getGlobalping: () => getGlobalping(),
    checkOutdated: () => noticeIfOutdated(pageIsOutdated),
    requireOnline,
    toast,
    getInventoryIndex: () => state.getInventoryIndex(),
    setParams(next, { merge = false } = {}) {
      if (!isCurrent(ctx)) return;
      const merged = merge ? { ...ctx.params, ...next } : { ...next };
      const hash = buildRoute(route, merged);
      const parsed = parseRoute(hash);
      ctx.params = parsed.params;
      ctx.searchParams = parsed.searchParams;
      current.params = parsed.params;
      if (hash !== currentHash()) globalThis.history.replaceState(null, '', hash);
      updateNavHrefs();
    },
    shareUrl(p = ctx.params) {
      const base = globalThis.location.href.split('#')[0];
      // A shared link shows the result: without the fill-only marker of a kept or carried route.
      const shared = { ...p };
      if (shared[FILL_PARAM] === FILL_VALUE) delete shared[FILL_PARAM];
      return `${base}${buildRoute(route, shared)}`;
    },
    setBusy(busy) {
      if (isCurrent(ctx)) setBusyState(busy);
    },
    runStarted(subject) {
      if (!isCurrent(ctx)) return;
      setKeptNote(null);
      if (!subject) return;
      pageSession.setTarget(subject, { view: id });
      // The store tells only a new value; the same one again is newer than the other tools' kept
      // results now, which decides where their links lead (lib/session.js targetSupersedes).
      updateNavHrefs();
    },
    resultChanged() {
      if (isCurrent(ctx)) setKeptNote(null);
    },
    setActions(...nodes) {
      if (!isCurrent(ctx) || !dom.pageActions) return;
      clear(dom.pageActions);
      dom.pageActions.append(...nodes.flat().filter(Boolean).map((n) => (n.el && !n.nodeType ? n.el : n)));
    },
    onCleanup(fn) {
      if (typeof fn === 'function') cleanups.push(fn);
    }
  };
  return { ctx, cleanups };
}

function isCurrent(ctx) {
  return !!current && current.ctx === ctx;
}

function setBusyState(busy) {
  if (!current) return;
  const on = !!busy;
  current.busy = on;
  dom.header.classList.toggle('is-busy', on);
  dom.main.setAttribute('aria-busy', String(on));
  markBusy(current.id, on);
  // After the view's own start-up: the settings change re-renders what views show of the settings.
  if (on) setTimeout(noteRun, 0);
  if (on && typeof busy === 'string') announce(busy);
  if (!on && pendingLangRemount) {
    pendingLangRemount = false;
    // Let the view finish rendering its final state before the re-mount.
    setTimeout(remountCurrent, 0);
  }
}

/** A view hook (unmount/update/snapshot/cleanup) threw: log it (E2E fails on it) and tell the user. */
function reportError(err) {
  if (err && err.name === 'AbortError') return;
  console.error('[shell] view hook failed', err);
  notifyUnexpected(err);
}

async function unmountCurrent() {
  const cur = current;
  if (!cur) return;
  // Before the abort below: the snapshot describes what is on screen.
  keepResult(cur);
  current = null;
  pendingLangRemount = false; // the next view mounts in the current language anyway
  try {
    cur.controller.abort(new DOMException('View unmounted', 'AbortError'));
  } catch {
    // ignore
  }
  for (const fn of cur.cleanups.splice(0)) {
    try {
      fn();
    } catch (err) {
      reportError(err);
    }
  }
  try {
    if (cur.view && typeof cur.view.unmount === 'function') await cur.view.unmount(cur.ctx);
  } catch (err) {
    reportError(err);
  }
  dom.header.classList.remove('is-busy');
  dom.main.removeAttribute('aria-busy');
  dom.nav.querySelectorAll('.nav-link.is-busy').forEach((l) => l.classList.remove('is-busy'));
  if (dom.navMenuBtn) dom.navMenuBtn.classList.remove('is-busy');
  if (navMenu) navMenu.el.querySelectorAll('.navmenu-link.is-busy').forEach((l) => l.classList.remove('is-busy'));
  if (dom.pageActions) clear(dom.pageActions);
}

const moduleCache = new Map();

function loadView(def) {
  if (!moduleCache.has(def.id)) {
    const p = def.load();
    moduleCache.set(def.id, p);
    p.catch(() => moduleCache.delete(def.id)); // allow a retry
  }
  return moduleCache.get(def.id);
}

/** Injected view stylesheets: file → promise settled when the sheet has loaded (or failed). */
const stylesheets = new Map();
/** A view waits this long for a stalled stylesheet, then mounts (the sheet applies once it arrives). */
const STYLESHEET_WAIT_MS = 8000;

/**
 * Load a view's stylesheets (VIEWS[].css) before it mounts. Each is one `<link rel="stylesheet">`
 * resolved against this module, so it follows the v/<version>/ directory of the Pages bundle
 * (the CSP's style-src 'self' allows it; nothing is inlined), inserted in VIEW_CSS_ORDER and kept
 * for the rest of the page's life. Never rejects: a sheet that cannot load (offline without the
 * service worker, a deploy) leaves the view unstyled rather than unusable, and is tried again the
 * next time the view opens; one that stalls holds the view back STYLESHEET_WAIT_MS at most.
 * @param {{ css: readonly string[] }} def
 * @returns {Promise<void>}
 */
function loadViewCss(def) {
  return Promise.all(def.css.map(loadStylesheet)).then(() => {});
}

function loadStylesheet(file) {
  if (stylesheets.has(file)) return stylesheets.get(file);
  const link = h('link', { attrs: { rel: 'stylesheet', href: new URL(`../css/${file}`, import.meta.url).href }, dataset: { viewCss: file } });
  const settled = new Promise((resolve) => {
    link.addEventListener('load', () => resolve(), { once: true });
    link.addEventListener('error', () => {
      stylesheets.delete(file);
      link.remove();
      resolve();
    }, { once: true });
    setTimeout(resolve, STYLESHEET_WAIT_MS);
  });
  stylesheets.set(file, settled);
  const present = [...document.querySelectorAll('link[data-view-css]')];
  const before = stylesheetBefore(file, present.map((l) => l.dataset.viewCss));
  if (before) present.find((l) => l.dataset.viewCss === before).before(link);
  else (present[present.length - 1] || document.querySelector('link[rel="stylesheet"]') || document.head.lastChild).after(link);
  return settled;
}

/** Run `fn` when the browser is idle (at the latest after a few seconds). */
function whenIdle(fn) {
  if (typeof globalThis.requestIdleCallback === 'function') globalThis.requestIdleCallback(() => fn(), { timeout: 8000 });
  else setTimeout(fn, 2000);
}

const preloaded = new Set();

/**
 * Once the browser is idle, modulepreload what a view imports on first use (VIEWS[].preload), so
 * its first use does not wait for the download. Skipped offline and when the user asked to save
 * data; a module is hinted once per page.
 * @param {{ preload: readonly string[] }} def
 */
function preloadWhenIdle(def) {
  if (!def.preload.length) return;
  whenIdle(() => {
    const nav = globalThis.navigator;
    if (nav && (nav.onLine === false || (nav.connection && nav.connection.saveData))) return;
    for (const file of def.preload) {
      const href = new URL(`./${file}`, import.meta.url).href;
      if (preloaded.has(href)) continue;
      preloaded.add(href);
      document.head.append(h('link', { attrs: { rel: 'modulepreload', href } }));
    }
  });
}

/**
 * The page body of a view whose module failed to load: the error with a Retry, replaced by a
 * "reload page" alert once {@link moduleReloadReason} says only a reload helps (Retry cannot then).
 * A network failure keeps the Retry and never claims an update.
 */
function viewLoadFailure(def, params, sp, err, sub) {
  const maybeStale = isStaleModuleError(err);
  if (maybeStale && err.name === 'SyntaxError') return outdatedAlert(err);
  const banner = ErrorBanner(err, { title: t('shell.viewLoadFailed'), onRetry: () => showRoute(def.id, params, { force: true, searchParams: sp, sub }) });
  if (maybeStale) {
    moduleReloadReason(err).then((reason) => {
      if (reason && banner.isConnected) banner.replaceWith(outdatedAlert(err, reason));
    });
  }
  return banner;
}

/**
 * "This page is older than the site" (or 'stuck': it cannot load the file again): the error's
 * details and a Reload page button (no Retry), busy while the new version downloads (reloadPage may wait for it).
 */
function outdatedAlert(err, reason = 'outdated') {
  const { detail } = describeError(err);
  const reload = Button({
    label: t('shell.reload'), icon: 'refresh', variant: 'primary', size: 'sm',
    dataset: { action: 'reload-page' },
    onClick: () => {
      setButtonBusy(reload, true);
      reloadPage();
    }
  });
  return Alert({
    variant: 'warn',
    title: t('shell.viewLoadFailed'),
    message: t(reason === 'stuck' ? 'shell.viewStuck' : 'shell.viewOutdated'),
    children: detail ? h('details', { class: 'alert-details' }, h('summary', null, t('error.details')), h('code', { class: 'mono' }, detail)) : null,
    actions: [reload]
  });
}

function titleKeyOf(def, view) {
  return (view && typeof view.titleKey === 'string' && view.titleKey) || `nav.${def.id}`;
}

/**
 * The page header (docs/DESIGN.md §5.1, region 1): the tool's icon, its title (the page's <h1>) and
 * one purpose line (`nav.<id>.purpose`). The ⓘ button next to the title opens what the tool does at
 * length (`nav.<id>.desc`) with a link to its section of About (lib/shellnav.js aboutSectionOf).
 * `.page-actions` holds the page's own actions; the kept-result note sits under the purpose line.
 */
function renderPageHeader(def, view = null) {
  const titleKey = titleKeyOf(def, view);
  dom.pageTitle = h('h1', { class: 'page-title', id: 'page-title', attrs: { tabindex: -1 } }, t(titleKey));
  dom.pageActions = h('div', { class: 'page-actions' });
  dom.pageBody = h('div', { class: 'page-body', id: 'page-body', dataset: { view: def.id } });
  dom.keptNote = h('div', { class: 'page-kept', hidden: true });
  dom.offlineNote = h('div', { class: 'page-offline', id: 'page-offline', hidden: true });
  dom.pageDef = def;
  const purposeKey = `nav.${def.id}.purpose`;
  const purpose = hasString(purposeKey) ? t(purposeKey) : t(`nav.${def.id}.desc`);
  const about = pageAbout(def, purpose);
  clear(dom.page);
  // A first-time visitor on the start page gets the task picker above the tool.
  if (def.id === DEFAULT_VIEW && state.settings.startTasks) dom.page.append(startPicker());
  dom.page.append(
    h('header', { class: 'page-header' },
      h('div', { class: 'page-icon', attrs: { 'aria-hidden': 'true' } }, Icon(def.icon, { size: 16 })),
      h('div', { class: 'page-titles' },
        h('div', { class: 'page-title-row' }, dom.pageTitle, about),
        purpose ? h('p', { class: 'page-desc page-purpose' }, purpose) : null,
        dom.pageAboutPanel,
        dom.keptNote),
      dom.pageActions),
    dom.offlineNote,
    dom.pageBody);
  setBaseTitle(`${t(titleKey)} · ${t('app.name')}`);
  renderOfflineNote();
}

/**
 * The page header's ⓘ: a disclosure button (`aria-expanded`) for what the tool does at length
 * (unless the purpose line already says all of it), with the link to its About section; none for
 * About itself. Sets dom.pageAboutPanel (null without one).
 * @param {{ id: string, offline?: boolean }} def
 * @param {string} purpose the purpose line on screen
 * @returns {HTMLButtonElement|null}
 */
function pageAbout(def, purpose) {
  dom.pageAboutPanel = null;
  const section = aboutSectionOf(def);
  if (!section) return null;
  const desc = t(`nav.${def.id}.desc`);
  const panelId = uid('page-about');
  const panel = h('div', { class: 'page-about-panel', id: panelId, hidden: true },
    desc && desc !== purpose ? h('p', { class: 'page-about-desc' }, desc) : null,
    h('p', { class: 'page-about-more' },
      h('a', { href: buildRoute('about', { section }), dataset: { view: 'about', section } }, t(`shell.aboutLink.${section}`))));
  const btn = h('button', {
    type: 'button',
    class: 'page-about',
    title: t('shell.aboutTool'),
    dataset: { action: 'page-about' },
    attrs: { 'aria-expanded': 'false', 'aria-controls': panelId, 'aria-label': t('shell.aboutTool') },
    on: {
      click: () => {
        const open = panel.hidden;
        panel.hidden = !open;
        btn.setAttribute('aria-expanded', String(open));
      }
    }
  }, Icon('info', { size: 16 }));
  dom.pageAboutPanel = panel;
  return btn;
}

/** Is the browser offline? (`onLine` may claim a connection that does not work, never the reverse.) */
function isOffline() {
  return globalThis.navigator?.onLine === false;
}

/**
 * Offline, a view that needs the network says so between its header and body — every view still
 * opens, from the service worker — and names the tools that work without a connection.
 */
function renderOfflineNote() {
  const note = dom.offlineNote;
  const def = dom.pageDef;
  if (!note || !def) return;
  clear(note);
  note.hidden = !isOffline() || def.offline;
  if (note.hidden) return;
  const tools = VIEWS.filter((v) => v.offline).flatMap((v, i) => [
    i ? ' · ' : null,
    h('a', { href: buildRoute(v.id), dataset: { view: v.id } }, t(`nav.${v.id}`))
  ]);
  note.append(Alert({
    variant: 'warn',
    icon: 'cloud-off',
    title: t('shell.offlineTitle'),
    message: t('shell.offlineView', { tool: t(`nav.${def.id}`) }),
    children: h('p', { class: 'page-offline-tools' }, t('shell.offlineTools'), ' ', tools)
  }));
}

/**
 * ctx.requireOnline: true while the browser has a connection; offline it says the work needs
 * the network (a toast) and returns false, so the view sends nothing. `quiet`: work the view
 * starts by itself (a check when a tab opens, a shared link's run) — the user clicked nothing, so
 * no toast; the view says it in place. Another click while the toast is up replaces it (one on
 * screen, its time starting again) rather than stacking copies.
 * @param {{ quiet?: boolean }} [opts]
 * @returns {boolean}
 */
function requireOnline({ quiet = false } = {}) {
  if (!isOffline()) return true;
  if (!quiet) {
    if (offlineNotice && offlineNotice.el) offlineNotice.el.remove();
    offlineNotice = toast(t('shell.offlineAction'), { type: 'warn' });
  }
  return false;
}

/**
 * Show (or hide with null) the page header's note about a kept result: "Result from <time>" (or
 * the result's own `label`), with "Run again" when the view exports `rerun()` and the note offers
 * it (`rerun`). Its keyboard focus goes to the page title when the note goes away under it.
 * @param {{ at: Date, dropped: boolean, rerun?: boolean, label?: string|null }|null} note
 */
function setKeptNote(note) {
  if (!current || !dom.keptNote) return;
  const cur = current;
  cur.note = note;
  const doc = globalThis.document;
  const hadFocus = !!doc && dom.keptNote.contains(doc.activeElement);
  clear(dom.keptNote);
  dom.keptNote.hidden = !note;
  if (note) {
    const rerun = note.rerun !== false && typeof cur.view.rerun === 'function' ? () => {
      try {
        cur.view.rerun(cur.ctx);
      } catch (err) {
        reportError(err);
      }
    } : null;
    dom.keptNote.append(KeptNote({ at: note.at, dropped: note.dropped, label: note.label, onRerun: rerun }));
  } else if (hadFocus && dom.pageTitle) {
    dom.pageTitle.focus({ preventScroll: true });
  }
}

/**
 * @param {string} id
 * @param {Record<string, string>} params
 * @param {{ force?: boolean, restored?: any, searchParams?: URLSearchParams|null, note?: object|null, sub?: string }} [opts]
 *   note: set by a language re-mount (the kept-result note it showed, or null); a mount without it
 *   may bring the view's kept result back (lib/session.js restorePlan); sub: the view's sub-page
 */
async function showRoute(id, params, { force = false, restored = null, searchParams = null, note = undefined, sub = '' } = {}) {
  const def = VIEW_BY_ID.get(id) || VIEW_BY_ID.get(DEFAULT_VIEW);
  if (def.id !== id) sub = '';
  let sp = searchParams || new URLSearchParams(params);
  const sameSub = !!current && current.sub === sub;
  if (!force && current && current.id === def.id && sameSub && sameSearch(current.ctx.searchParams, sp)) return;

  // Same view with new params: let the view take them without a re-mount if it can. A
  // query repeating a key is re-mounted: mount reads every value from ctx.searchParams.
  if (!force && current && current.id === def.id && sameSub && current.view && typeof current.view.update === 'function'
    && !hasRepeatedKeys(sp)) {
    const cur = current;
    const prev = { params: cur.ctx.params, searchParams: cur.ctx.searchParams };
    cur.ctx.params = { ...params };
    cur.ctx.searchParams = sp;
    try {
      const handled = cur.view.update({ ...params }, cur.ctx);
      if (handled === true) {
        cur.params = { ...params };
        updateNavHrefs();
        return;
      }
    } catch (err) {
      reportError(err);
    }
    Object.assign(cur.ctx, prev);
  }

  const token = ++routeToken;
  await unmountCurrent();
  if (token !== routeToken) return;

  // Coming back to a tool (a bare route or its result's own params) brings its kept result back;
  // the URL then shows that result's params with `run=0`, so a reload or a later Back only fills
  // the form (the view's Copy link shares the result's own params). Under a carried target
  // ('carry') the result comes back too and the URL keeps the target, which the view's box takes
  // when it holds nothing of the user's. A language re-mount has its own snapshot.
  const kept = note === undefined && !sub ? pageSession.kept(def.id) : null;
  const plan = restorePlan(params, kept);
  if (plan === 'restore' || plan === 'carry') restored = kept.snapshot;
  if (plan === 'restore' || plan === 'dropped') {
    params = { ...kept.params };
    if (Object.keys(params).length) params[FILL_PARAM] = FILL_VALUE;
    sp = new URLSearchParams(params);
    const hash = buildRoute(def.id, params);
    if (hash !== currentHash()) globalThis.history.replaceState(null, '', hash);
  }

  setNavActive(def.id);
  renderPageHeader(def);
  document.documentElement.dataset.view = def.id;
  dom.main.dataset.view = def.id;
  // Show a spinner only when loading is noticeable.
  const spinnerTimer = setTimeout(() => {
    if (token === routeToken && !dom.pageBody.firstChild) {
      dom.pageBody.append(h('div', { class: 'page-loading' }, Spinner({ size: 'lg', label: t('shell.loadingView'), showLabel: true })));
    }
  }, 150);

  // The module and the stylesheets load side by side; both settle before anything is shown, so
  // a failed view never logs a late stylesheet error after its message is up.
  const [loaded] = await Promise.allSettled([loadView(def), loadViewCss(def)]);
  const mod = loaded.value;
  if (loaded.status === 'rejected') {
    const err = loaded.reason;
    clearTimeout(spinnerTimer);
    if (token !== routeToken) return;
    // Logged on purpose: E2E runs fail on console errors, so a broken view never goes unnoticed.
    console.error(`[view:${def.id}] failed to load`, err);
    clear(dom.pageBody);
    dom.pageBody.append(viewLoadFailure(def, params, sp, err, sub));
    finishRoute(def);
    return;
  }
  clearTimeout(spinnerTimer);
  if (token !== routeToken) return;

  const view = mod && mod.default && typeof mod.default.mount === 'function' ? mod.default : mod;
  if (titleKeyOf(def, view) !== `nav.${def.id}`) {
    dom.pageTitle.textContent = t(titleKeyOf(def, view));
    setBaseTitle(`${t(titleKeyOf(def, view))} · ${t('app.name')}`);
  }
  const controller = new AbortController();
  const { ctx, cleanups } = makeContext(def.id, params, sp, controller, restored, sub);
  current = { id: def.id, sub, def, view, params: { ...params }, ctx, controller, cleanups, busy: false, note: null };
  clear(dom.pageBody);
  const mountedAt = Date.now();
  let mounted = false;
  try {
    if (!view || typeof view.mount !== 'function') throw new TypeError(`View "${def.id}" does not export mount()`);
    const ret = await view.mount(dom.pageBody, ctx);
    if (typeof ret === 'function') {
      if (current && current.ctx === ctx) cleanups.push(ret);
      else ret();
    }
    mounted = true;
  } catch (err) {
    // A kept result the view cannot show is not offered again (Retry mounts it fresh).
    if (plan) pageSession.drop(def.id);
    if (token === routeToken && !(err && err.name === 'AbortError')) {
      clear(dom.pageBody);
      dom.pageBody.append(ErrorBanner(err, {
        title: t('shell.viewCrashed'),
        onRetry: () => showRoute(def.id, params, { force: true, searchParams: sp, sub })
      }));
      console.error(`[view:${def.id}] mount failed`, err);
    }
  }
  if (token !== routeToken) return;
  if (mounted && isCurrent(ctx)) {
    setKeptNote(keptNote({ note, plan, kept, result: resultOf(view, ctx), mountedAt, restorable: typeof view.snapshot === 'function' }));
  }
  finishRoute(def);
  preloadWhenIdle(def);
}

function finishRoute(def) {
  updateNavHrefs();
  if (firstRouteDone) {
    // Move focus to the new page title for keyboard and screen-reader users.
    globalThis.scrollTo(0, 0);
    if (dom.pageTitle) dom.pageTitle.focus({ preventScroll: true });
    // A kept result is said with the tool's name ("Domain Health · Result from 14:02").
    const kept = dom.keptNote && !dom.keptNote.hidden ? dom.keptNote.querySelector('.kept-note-text') : null;
    announce(kept ? `${t(`nav.${def.id}`)} · ${kept.textContent}` : t(`nav.${def.id}`));
  } else {
    // The offline copy is fetched after the first view, never in its way.
    whenIdle(() => registerServiceWorker());
  }
  firstRouteDone = true;
  document.documentElement.dataset.appReady = 'true';
}

function handleRoute() {
  // The phone's Back button while the Tools menu is open (a link in it has closed it already).
  if (navMenu && navMenu.el.open) navMenu.close(null);
  const hash = currentHash();
  if (hash && !hash.startsWith('#/')) {
    // In-page anchor: keep the current view (or show the default on first load).
    if (!current) showRoute(DEFAULT_VIEW, {});
    return;
  }
  const route = parseRoute(hash);
  if (!route.view) {
    if (hash && hash !== '#/' && route.isRoute) globalThis.history.replaceState(null, '', buildRoute(DEFAULT_VIEW));
    showRoute(DEFAULT_VIEW, {});
    return;
  }
  showRoute(route.view, route.params, { searchParams: route.searchParams, sub: route.sub });
}

function remountCurrent() {
  if (!current) return;
  let snapshot = null;
  try {
    if (typeof current.view.snapshot === 'function') snapshot = current.view.snapshot(current.ctx);
  } catch (err) {
    reportError(err);
  }
  showRoute(current.id, current.params, { force: true, restored: snapshot, searchParams: current.ctx.searchParams, note: current.note || null, sub: current.sub });
}

/* ------------------------------------------------------------------------ */
/* Shell rendering                                                          */
/* ------------------------------------------------------------------------ */

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === 'light' || theme === 'dark') root.dataset.theme = theme;
  else delete root.dataset.theme;
  // Browser UI color follows the effective theme.
  const metas = document.querySelectorAll('meta[name="theme-color"]');
  metas.forEach((m) => {
    if (!m.dataset.media) m.dataset.media = m.getAttribute('media') || '';
    if (theme === 'light' || theme === 'dark') {
      m.removeAttribute('media');
      m.setAttribute('content', theme === 'dark' ? '#0d1015' : '#f4f5f7');
    } else if (m.dataset.media) {
      m.setAttribute('media', m.dataset.media);
      m.setAttribute('content', m.dataset.media.includes('dark') ? '#0d1015' : '#f4f5f7');
    }
  });
}

const THEME_ORDER = ['auto', 'light', 'dark'];
const THEME_ICONS = { auto: 'contrast', light: 'sun', dark: 'moon' };
const THEME_LABELS = { auto: 'shell.themeAuto', light: 'shell.themeLight', dark: 'shell.themeDark' };

/** Persist a theme choice; the settings subscription applies it (see syncTheme). */
function chooseTheme(value) {
  state.updateSettings({ theme: value });
  syncTheme(value);
}

/** Apply a theme and bring every theme control in line with it (the header's two, the phone sheet's). */
function syncTheme(value) {
  applyTheme(value);
  if (dom.sheetTheme) dom.sheetTheme.setValue(value);
  if (!dom.headerActions) return;
  // Through the control's API: its click handler ignores a click on the value it holds.
  if (dom.themeSeg) dom.themeSeg.setValue(value);
  const old = dom.headerActions.querySelector('[data-control="theme-cycle"]');
  if (old) {
    const hadFocus = globalThis.document.activeElement === old;
    const fresh = themeCycleButton(value);
    old.replaceWith(fresh);
    if (hadFocus) fresh.focus();
  }
}

/** Phones: one button cycling auto → light → dark replaces the 3-way toggle (CSS decides which shows). */
function themeCycleButton(theme) {
  const btn = IconButton({
    icon: THEME_ICONS[theme] || 'contrast',
    label: `${t('shell.theme')}: ${t(THEME_LABELS[theme] || THEME_LABELS.auto)}`,
    className: 'theme-cycle',
    onClick: () => chooseTheme(THEME_ORDER[(THEME_ORDER.indexOf(state.settings.theme) + 1) % THEME_ORDER.length])
  });
  btn.dataset.control = 'theme-cycle';
  return btn;
}

/** Is this an Apple platform (⌘ in the key hints)? */
function onApple() {
  const nav = globalThis.navigator || {};
  return isApplePlatform((nav.userAgentData && nav.userAgentData.platform) || nav.platform || '');
}

/** The theme as a three-way switch (the header's from 1100 px up; the phone Tools sheet's). */
function themeSwitch(control) {
  const theme = SegmentedControl({
    label: t('shell.theme'),
    size: 'sm',
    className: 'theme-toggle',
    value: state.settings.theme,
    options: THEME_ORDER.map((value) => ({ value, icon: THEME_ICONS[value], title: t(THEME_LABELS[value]) })),
    onChange: chooseTheme
  });
  theme.el.dataset.control = control;
  return theme;
}

/**
 * The header's controls (docs/DESIGN.md §3.2): the search (the palette, Ctrl/⌘+K: a button styled as
 * a field, an icon from 720 to 1100 px, none on a phone, where the Tools sheet holds its box), the
 * language, the theme (three-way from 1100 px, one cycling button below, in the Tools sheet on a
 * phone) and Settings. GitHub is in the footer and About.
 */
function renderHeaderActions() {
  const settings = state.settings;
  const lang = SegmentedControl({
    label: t('shell.language'),
    size: 'sm',
    className: 'lang-toggle',
    value: getLang(),
    options: [
      { value: 'tr', label: 'TR', title: t('lang.tr') },
      { value: 'en', label: 'EN', title: t('lang.en') }
    ],
    onChange: (value) => {
      state.updateSettings({ lang: value });
      setLang(value);
    }
  });
  lang.el.dataset.control = 'lang';
  const theme = themeSwitch('theme');
  dom.themeSeg = theme;
  const settingsBtn = IconButton({ icon: 'sliders', label: t('shell.settings'), onClick: openSettings });
  settingsBtn.dataset.control = 'settings';
  // A button, not a field: its name is the words on it; the long description is its title.
  const search = h('button', {
    type: 'button',
    class: 'header-search',
    title: t('keys.palette'),
    dataset: { control: 'palette' },
    attrs: { 'aria-haspopup': 'dialog', 'aria-keyshortcuts': PALETTE_KEYSHORTCUTS },
    on: { click: openPalette }
  },
  Icon('search', { size: 16, className: 'header-search-icon' }),
  h('span', { class: 'header-search-text' }, t('shell.search')),
  h('kbd', { class: 'header-search-key', attrs: { 'aria-hidden': 'true' } }, paletteKeyHint({ apple: onApple() })));
  clear(dom.headerActions);
  dom.headerActions.append(search, lang.el, theme.el, themeCycleButton(settings.theme), settingsBtn);
}

/**
 * The Tools button of phones and tablets (below 1100 px; the sidebar shows from there): the open
 * tool's name (cut with an ellipsis), read out as "Tools: <tool>"; it opens the Tools sheet on a
 * phone and the drawer on a tablet ({@link openNavMenu}). A pulsing dot while the open tool works.
 */
function renderNavButton() {
  if (!dom.navMenuHost) return;
  dom.navMenuLabel = h('span', { class: 'nav-menu-current-label' });
  dom.navMenuBtn = h('button', {
    type: 'button',
    class: 'btn btn-secondary nav-menu-btn',
    dataset: { control: 'nav-menu' },
    attrs: { 'aria-haspopup': 'dialog', 'aria-expanded': String(!!navMenu) },
    on: { click: openNavMenu }
  },
  Icon('menu', { size: 16 }),
  h('span', { class: 'nav-menu-current' }, h('span', { class: 'sr-only' }, `${t('shell.toolsPrefix')} `), dom.navMenuLabel),
  Icon('chevron-down', { size: 14, className: 'nav-menu-chevron' }));
  clear(dom.navMenuHost);
  dom.navMenuHost.append(dom.navMenuBtn);
  dom.navMenuLabel.textContent = current ? t(`nav.${current.id}`) : t('nav.label');
}

function chainLabel(chain) {
  return chain.map((id) => getResolver(id)?.name || id).join(' → ');
}

/**
 * The sidebar (from 1100 px; the drawer and the phone Tools sheet below): the groups by job, a
 * link per tool (the current one marked with a neutral fill and an accent bar), and a footer of
 * two lines — the saved servers and the DoH chain (each a way to its place), and where it runs.
 */
function renderNav() {
  const activeId = current ? current.id : null;
  const groups = groupViews(VIEWS).map((g) => {
    const labelId = g.labelKey ? uid('navgroup') : null;
    return h('div', { class: 'nav-group', dataset: { group: g.id }, attrs: { role: 'group', 'aria-labelledby': labelId } },
      labelId ? h('div', { class: 'nav-group-label', id: labelId }, t(g.labelKey)) : null,
      h('ul', { class: 'nav-list' }, g.views.map((v) => h('li', null,
        h('a', {
          class: 'nav-link',
          href: navHref(v.id),
          dataset: { view: v.id },
          attrs: { 'aria-current': v.id === activeId ? 'page' : null }
        }, Icon(v.icon, { size: 18 }), h('span', { class: 'nav-label' }, t(`nav.${v.id}`)))))));
  });
  dom.navInventory = h('span');
  dom.navDoh = h('span');
  const foot = h('div', { class: 'nav-foot' },
    h('p', { class: 'nav-foot-line' },
      h('a', { class: 'nav-status', href: buildRoute('inventory'), dataset: { status: 'inventory' } }, Icon('server', { size: 14 }), dom.navInventory),
      h('span', { class: 'nav-foot-sep', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('button', {
        type: 'button',
        class: 'nav-status nav-status-doh link-reset',
        dataset: { status: 'doh' },
        on: { click: openSettings }
      }, dom.navDoh)),
    h('p', { class: 'nav-foot-line nav-status nav-status-privacy' }, Icon('lock', { size: 14 }), h('span', null, t('shell.privacyShort'))));
  clear(dom.nav);
  dom.nav.setAttribute('aria-label', t('nav.label'));
  dom.nav.append(...groups, foot);
  updateNavStatus();
  // The progress rings of jobs running in other views (ui/jobs.js).
  refreshJobIndicators();
}

/**
 * Where a nav link to a tool leads: the page's own URL for the tool on screen, else back to the
 * tool's kept result or to the tool with the current target filled in (lib/session.js carryRoute;
 * nothing runs on arrival). Exported for other navigation surfaces (a tools menu).
 * @param {string} id view id
 * @returns {string} route hash
 */
export function navHref(id) {
  if (current && current.id === id) return buildRoute(id, current.params);
  return buildRoute(id, carryRoute(id, { kept: pageSession.kept(id), target: pageSession.target }));
}

/** Point every nav link (`a.nav-link[data-view]`, wherever it is) at {@link navHref}. */
function updateNavHrefs() {
  const doc = globalThis.document;
  if (!doc) return;
  doc.querySelectorAll('a.nav-link[data-view]').forEach((a) => {
    const href = navHref(a.dataset.view);
    if (a.getAttribute('href') !== href) a.setAttribute('href', href);
  });
}

/** The workspace store has opened: the switcher names the real active workspace (never a flash of Default). */
let workspacesReady = false;

/** The header's workspace switcher with its server count (CSS hides it below 720 px, where the Tools sheet has it). */
function renderWorkspaceSwitch() {
  if (!dom.workspaceHost || !workspacesReady) return;
  const doc = globalThis.document;
  const hadFocus = !!doc && dom.workspaceHost.contains(doc.activeElement);
  clear(dom.workspaceHost);
  const btn = WorkspaceSwitch({ workspace: state.workspace, servers: state.inventory.servers.length, onOpen: openWorkspaces });
  dom.workspaceHost.append(btn);
  if (hadFocus) btn.focus({ preventScroll: true });
}

/** The Workspaces dialog on screen (one at a time), or a pending first load of it. */
let workspacePanel = null;

/** An error in one line for a toast: what failed and why, else the kind of error. */
function errorText(err) {
  const { message, detail } = describeError(err);
  return detail || message;
}

/**
 * Open the Workspaces dialog: its module and stylesheet load on first use (a page left open
 * across a deploy is offered a reload). The focus returns to the switcher, or on a phone to the
 * Tools button.
 */
async function openWorkspaces() {
  if (workspacePanel) return;
  workspacePanel = 'loading';
  let mod;
  try {
    [mod] = await Promise.all([import('./ui/workspace-panel.js'), loadStylesheet('workspace.css')]);
  } catch (err) {
    workspacePanel = null;
    noticeIfOutdated(() => moduleReloadReason(err));
    toast(t('ws.loadFailed', { message: errorText(err) }), { type: 'error' });
    return;
  }
  workspacePanel = mod.openWorkspacePanel({
    state,
    appVersion: APP_VERSION,
    switchTo: switchWorkspace,
    setTarget: (value) => !!pageSession.setTarget(value),
    onClose: () => {
      workspacePanel = null;
      const doc = globalThis.document;
      if (doc.activeElement && doc.activeElement !== doc.body) return;
      const back = [dom.workspaceHost && dom.workspaceHost.querySelector('[data-control="workspace"]'), dom.navMenuBtn, dom.pageTitle]
        .find((el) => el && el.isConnected && el.getClientRects().length);
      if (back) back.focus({ preventScroll: true });
    }
  });
}

/**
 * Work in another workspace. What belongs to this one and would be lost — a long job still
 * running (Subdomains, SSL Targets, Bulk Resolve, a Reverse DNS sweep, a Verify check, a
 * comparison with new name servers or of an old and a new server on Globalping: ui/jobs.js
 * runningWork), which stops, or Servers edits not saved yet (the view's
 * `unsaved()`, or its draft kept in the session) — the user confirms first.
 * @param {string} id
 * @returns {Promise<boolean>} switched
 */
async function switchWorkspace(id) {
  if (id === state.workspace.id) return true;
  const next = state.workspaces.find((w) => w.id === id);
  if (!next) return false;
  const name = workspaceLabel(next);
  const jobs = runningWork();
  let unsaved = !!state.getSession('inventoryDraft');
  try {
    if (current && current.view && typeof current.view.unsaved === 'function' && current.view.unsaved()) unsaved = true;
  } catch (err) {
    reportError(err);
  }
  if (jobs.length || unsaved) {
    const lost = [
      jobs.length ? t('ws.switchJobs', { jobs: jobs.map((key) => t(key)).join(', '), name }) : null,
      unsaved ? t('ws.switchUnsaved', { name }) : null
    ].filter(Boolean);
    const ok = await confirmDialog({
      title: t('ws.switchTitle'),
      message: lost.join(' '),
      confirmLabel: t(jobs.length ? 'ws.switchStop' : 'ws.switchAnyway'),
      danger: true
    });
    if (!ok) return false;
  }
  try {
    await state.switchWorkspace(id);
  } catch (err) {
    toast(t('ws.switchFailed', { reason: storageErrorText(err) }), { type: 'error' });
    return false;
  }
  toast(t('ws.switched', { name: workspaceLabel(state.workspace) }), { type: 'success' });
  return true;
}

/** The header chip with the current target (hidden without one; in the Tools sheet on a phone). */
function renderTargetChip() {
  renderSheetTarget();
  if (!dom.targetHost) return;
  const target = pageSession.target;
  const doc = globalThis.document;
  const hadFocus = !!doc && dom.targetHost.contains(doc.activeElement);
  clear(dom.targetHost);
  dom.targetHost.hidden = !target;
  dom.header.classList.toggle('has-target', !!target);
  if (target) {
    dom.targetHost.append(TargetChip({
      target,
      onClear: () => {
        if (pageSession.clearTarget()) announce(t('session.target.cleared'));
      }
    }));
  } else if (hadFocus) {
    // The chip went away under the keyboard focus (its clear button): continue on the page.
    (dom.pageTitle || dom.main).focus({ preventScroll: true });
  }
}

function updateNavStatus() {
  if (!dom.navInventory) return;
  const count = state.inventory.servers.length;
  dom.navInventory.textContent = t('shell.serverCount', { count });
  const doh = t('shell.dohStatus', { chain: chainLabel(state.settings.chain) });
  dom.navDoh.textContent = doh;
  // The line cuts the chain short: the whole of it, and where it is set, on hover.
  if (dom.navDoh.parentElement) dom.navDoh.parentElement.title = `${doh} · ${t('settings.dohChain')}`;
}

function setNavActive(id) {
  dom.nav.querySelectorAll('.nav-link').forEach((a) => {
    if (a.dataset.view === id) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  const def = VIEW_BY_ID.get(id);
  if (dom.navMenuLabel && def) dom.navMenuLabel.textContent = t(`nav.${def.id}`);
  // The nav is rebuilt on a language change, possibly while the view works: keep its busy dot.
  markBusy(id, !!(current && current.id === id && current.busy));
  scrollNavToActive(id);
}

/** The busy dot of tool `id`: its sidebar link, the Tools button and, while the Tools menu is open, its entry there. */
function markBusy(id, on) {
  const link = dom.nav.querySelector(`.nav-link[data-view="${id}"]`);
  if (link) link.classList.toggle('is-busy', on);
  if (dom.navMenuBtn) dom.navMenuBtn.classList.toggle('is-busy', on);
  const entry = navMenu ? navMenu.el.querySelector(`.navmenu-link[data-view="${id}"]`) : null;
  if (entry) entry.classList.toggle('is-busy', on);
}

/**
 * Bring the active link into view by scrolling the sidebar itself, never the page, when the screen
 * is too short for it — only as far as needed, so a click on a link in view moves nothing. Below
 * 1100 px the sidebar is not shown (the Tools button names the tool).
 */
function scrollNavToActive(id) {
  const nav = dom.nav;
  const link = nav.querySelector(`.nav-link[data-view="${id}"]`);
  if (!link || !link.getClientRects().length || nav.scrollHeight <= nav.clientHeight + 1) return;
  const margin = 8;
  const top = link.getBoundingClientRect().top - nav.getBoundingClientRect().top - nav.clientTop + nav.scrollTop;
  const bottom = top + link.offsetHeight;
  if (top - margin < nav.scrollTop) nav.scrollTop = Math.max(0, top - margin);
  else if (bottom + margin > nav.scrollTop + nav.clientHeight) nav.scrollTop = bottom + margin - nav.clientHeight;
}

function renderFooter() {
  clear(dom.footer);
  dom.sentCount = h('span', { class: 'footer-sent-count' });
  dom.footer.append(
    h('span', null, `${t('app.name')} · ${t('shell.version', { version: APP_VERSION })}`),
    h('span', null, t('shell.footer')),
    h('a', { href: REPO_URL, attrs: { target: '_blank', rel: 'noopener noreferrer' } }, 'GitHub'),
    h('button', {
      type: 'button',
      class: 'footer-button',
      dataset: { control: 'shortcuts' },
      attrs: { 'aria-haspopup': 'dialog' },
      on: { click: openShortcutHelp }
    }, t('keys.title'), ' ', h('kbd', { attrs: { 'aria-hidden': 'true' } }, '?')),
    h('span', { class: 'spacer' }),
    h('span', null, t('shell.privacyLong')),
    // About › What this page sent: the page session's requests, measured (ui/egress-meter.js).
    h('a', { class: 'footer-sent', href: buildRoute('about', { section: 'sent' }), title: t('shell.sentTitle'), dataset: { control: 'sent' } },
      t('shell.sent'), dom.sentCount));
  renderSentCount();
}

/** The footer's count of third-party requests (throttled: a scan sends thousands a minute). */
function renderSentCount() {
  clearTimeout(sentCountTimer);
  sentCountTimer = null;
  if (!dom.sentCount) return;
  const { thirdParty } = countRequests(egressLog.snapshot().entries, globalThis.location ? globalThis.location.origin : '');
  dom.sentCount.textContent = ` · ${t('shell.sentCount', { count: thirdParty })}`;
  dom.sentCount.dataset.count = String(thirdParty);
}

let sentCountTimer = null;
function scheduleSentCount() {
  if (sentCountTimer === null) sentCountTimer = setTimeout(renderSentCount, 1000);
}

/* ------------------------------------------------------------------------ */
/* Tools menu (below 1100 px): the phone sheet and the tablet drawer        */
/* ------------------------------------------------------------------------ */

let navMenu = null;

/**
 * The Tools menu below 1100 px (docs/DESIGN.md §3.3–3.4), in a Modal (focus trap; Esc and a click
 * outside close it):
 * - on a phone (below 720 px), a full-height sheet that is also the palette: the palette's box on
 *   top (ui/palette.js, loaded on the first open, never focused on opening, so no keyboard covers
 *   the tiles) finds a tool, or the actions on a domain, host name, address, network or AS number;
 *   while it is empty every tool shows by group as two columns of tiles; a footer holds the
 *   workspace (switch or manage), the current target (✕) and the theme;
 * - on a tablet, a drawer on the left with the sidebar's groups.
 * The open tool is marked (with the busy dot while it works, and a job's ring on any tool that runs
 * one). The focus goes back to the Tools button, unless a link opened another tool: its page title
 * takes the focus then. A Ctrl/⌘/Shift/Alt click is the browser's (a new tab): the menu stays open.
 */
function openNavMenu() {
  if (navMenu) return;
  const mode = navMenuMode(globalThis.innerWidth) || 'drawer';
  const sheet = mode === 'sheet';
  const openedOn = current ? current.id : null;
  const busy = !!(current && current.busy);
  const tiles = h('div', { class: 'navmenu-groups' }, groupViews(VIEWS).map((g) => {
    const labelId = g.labelKey ? uid('navmenu-group') : null;
    return h('div', { class: 'navmenu-group', dataset: { group: g.id } },
      labelId ? h('h3', { class: 'navmenu-label', id: labelId }, t(g.labelKey)) : null,
      h('ul', { class: 'navmenu-list', attrs: { 'aria-labelledby': labelId } }, g.views.map((v) => {
        const here = v.id === openedOn;
        return h('li', null, h('a', {
          class: ['navmenu-link', { 'is-busy': here && busy }],
          // Like the sidebar's links: to the tool's kept result or with the current target filled in.
          href: navHref(v.id),
          dataset: { view: v.id, autofocus: here ? '1' : null },
          attrs: { 'aria-current': here ? 'page' : null },
          on: {
            click: (event) => {
              if (!isPlainClick(event)) return;
              // The open tool's entry only closes the menu: following it would drop the page's params.
              if (here) event.preventDefault();
              menu.close({ view: v.id });
            }
          }
        }, Icon(v.icon, { size: 18 }), h('span', { class: 'navmenu-name' }, t(`nav.${v.id}`)),
        here ? Icon('check', { size: 16, className: 'navmenu-check' }) : null));
      })));
  }));
  const search = sheet ? h('div', { class: 'navmenu-search' }) : null;
  const content = h('div', { class: ['navmenu', `navmenu-${mode}`] }, search, tiles, sheet ? navMenuFoot(() => menu) : null);
  const menu = Modal({
    title: t('nav.label'),
    size: mode,
    className: 'navmenu-modal',
    content,
    onClose: (value) => {
      navMenu = null;
      dom.sheetTheme = null;
      dom.sheetTarget = null;
      const btn = dom.navMenuBtn;
      if (btn) btn.setAttribute('aria-expanded', 'false');
      // Widened to 1100 px: the button is hidden, so the page title takes the focus.
      if (value && value.wide) {
        if (dom.pageTitle && dom.pageTitle.isConnected) dom.pageTitle.focus({ preventScroll: true });
        return;
      }
      // The Workspaces dialog opens next and takes the focus (and gives it back to this button);
      // a search result opened a tool, whose page title takes it.
      if (value && (value.workspace || value.left)) return;
      if (btn && btn.isConnected && (!value || value.view === openedOn)) btn.focus({ preventScroll: true });
    }
  });
  navMenu = menu;
  if (dom.navMenuBtn) dom.navMenuBtn.setAttribute('aria-expanded', 'true');
  menu.open();
  // The progress rings of running jobs, on the tiles too (ui/jobs.js).
  refreshJobIndicators();
  if (sheet) attachSheetSearch(search, tiles, menu);
}

/**
 * The phone sheet's footer: the workspace with a way to the Workspaces dialog, the current target
 * with its ✕ (the header has no room for either on a phone) and the theme.
 * @param {() => object} menuOf the open menu (its Modal)
 * @returns {HTMLElement}
 */
function navMenuFoot(menuOf) {
  const workspace = WorkspaceMenuEntry({
    workspace: state.workspace,
    onOpen: () => {
      menuOf().close({ workspace: true });
      openWorkspaces();
    }
  });
  dom.sheetTarget = h('div', { class: 'navmenu-row navmenu-target' });
  renderSheetTarget();
  const theme = themeSwitch('sheet-theme');
  dom.sheetTheme = theme;
  const themeLabel = uid('navmenu-theme');
  theme.el.setAttribute('aria-labelledby', themeLabel);
  return h('div', { class: 'navmenu-foot' },
    workspace,
    dom.sheetTarget,
    h('div', { class: 'navmenu-row' }, h('span', { class: 'navmenu-row-label', id: themeLabel }, t('shell.theme')), theme.el));
}

/** The current target in the phone sheet's footer (hidden without one). */
function renderSheetTarget() {
  const host = dom.sheetTarget;
  if (!host) return;
  const target = pageSession.target;
  const doc = globalThis.document;
  const hadFocus = !!doc && host.contains(doc.activeElement);
  clear(host);
  host.hidden = !target;
  if (target) {
    host.append(h('span', { class: 'navmenu-row-label' }, t('session.target.group')),
      TargetChip({ target, onClear: () => { if (pageSession.clearTarget()) announce(t('session.target.cleared')); } }));
  } else if (hadFocus && navMenu) {
    // The ✕ that had the focus is gone with its chip: the sheet keeps the focus.
    const next = navMenu.el.querySelector('[data-control="sheet-theme"] [aria-pressed="true"]');
    if (next) next.focus({ preventScroll: true });
  }
}

/**
 * The palette's box on top of the phone sheet (ui/palette.js and palette.css on the first open):
 * while it holds text its results replace the tiles; a result that opens a tool closes the sheet.
 * Offline before its first load, the tiles alone serve.
 * @param {HTMLElement} host
 * @param {HTMLElement} tiles
 * @param {object} menu the sheet's Modal
 */
async function attachSheetSearch(host, tiles, menu) {
  let mod;
  try {
    [mod] = await Promise.all([import('./ui/palette.js'), loadStylesheet('palette.css')]);
  } catch {
    noticeIfOutdated(pageIsOutdated);
    return;
  }
  if (navMenu !== menu || !host.isConnected) return;
  const box = mod.PaletteBox({
    views: VIEWS,
    navigate,
    href: navHref,
    state,
    session: pageSession,
    onQuery: (text) => {
      tiles.hidden = !!text;
    },
    onLeave: () => {
      if (navMenu === menu) menu.close({ left: true });
    }
  });
  host.append(box.el);
}

/* ------------------------------------------------------------------------ */
/* First-visit task picker                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The visitor ran something (a view went busy, a zone or a certificate was loaded, servers were
 * saved): the start page stops offering the task picker. A picker on screen stays until the page
 * is shown again, so nothing jumps under the pointer.
 */
function noteRun() {
  if (state.settings.startTasks) state.updateSettings({ startTasks: false });
}

/** Keys of this origin's localStorage ([] where it is blocked). */
function storedKeys() {
  try {
    const store = globalThis.localStorage;
    if (!store) return [];
    const keys = [];
    for (let i = 0; i < store.length; i += 1) keys.push(store.key(i));
    return keys;
  } catch {
    return [];
  }
}

/** The dismissible strip of job cards above the start page: a first-time visitor's "where do I begin?". */
function startPicker() {
  const titleId = uid('start-title');
  const hide = IconButton({
    icon: 'x',
    label: t('start.hide'),
    className: 'start-picker-hide',
    onClick: () => {
      state.updateSettings({ startTasks: false });
      strip.remove();
      toast(t('start.hidden', { where: `${t('nav.about')} › ${t('start.aboutTitle')}` }), { type: 'info' });
      // The button that had the focus is gone.
      if (dom.pageTitle) dom.pageTitle.focus({ preventScroll: true });
    }
  });
  hide.dataset.action = 'start-hide';
  const strip = h('section', { class: 'start-picker card', dataset: { role: 'start-picker' }, attrs: { 'aria-labelledby': titleId } },
    h('div', { class: 'start-picker-head' },
      h('div', { class: 'start-picker-titles' },
        // Not a heading: the strip comes before the page's <h1>; its title names the region instead.
        h('p', { class: 'start-picker-title', id: titleId }, t('start.title')),
        h('p', { class: 'start-picker-lead' }, t('start.lead'))),
      hide),
    StartTaskList({
      views: VIEWS,
      href: (view) => buildRoute(view),
      onPick: (task, event) => {
        // The job of the page that is open: go to its input instead of opening it again (a new tab is the browser's).
        if (!current || task.view !== current.id || !isPlainClick(event)) return;
        event.preventDefault();
        focusMainInput();
      }
    }));
  return strip;
}

/* ------------------------------------------------------------------------ */
/* Keyboard shortcuts                                                       */
/* ------------------------------------------------------------------------ */

/**
 * Is the element inside the collapsed part of a closed <details> (its own <summary> excepted)?
 * Chrome keeps boxes for that content (content-visibility: hidden), so a box alone does not show
 * that a control can be seen.
 */
function inClosedDetails(el) {
  for (let node = el; node && node.parentElement; node = node.parentElement) {
    const parent = node.parentElement;
    if (parent.localName === 'details' && !parent.open
      && !(node.localName === 'summary' && node === parent.querySelector(':scope > summary'))) return true;
  }
  return false;
}

/** Can a marked control act now? On the page, enabled, visible (not hidden, not in a closed <details>). */
function usableControl(el) {
  if (!el || !el.isConnected || el.disabled || el.closest('[inert]') || inClosedDetails(el)) return false;
  if (typeof el.checkVisibility === 'function') return el.checkVisibility({ visibilityProperty: true, checkVisibilityCSS: true });
  return el.getClientRects().length > 0;
}

/**
 * Is the element a Stop button that only the view's tabs keep out of sight? Enabled and shown but
 * for one or more closed tab panels (`hidden` [role=tabpanel]) between it and the page body: the
 * Zone File live check or a DANE check running while another tab is open.
 */
function behindClosedTab(el) {
  const root = dom.pageBody;
  if (!el || !root || !root.contains(el) || el.disabled || el.closest('[inert]') || inClosedDetails(el)) return false;
  let tab = false;
  for (let node = el; node && node !== root; node = node.parentElement) {
    if (!node.hidden && globalThis.getComputedStyle(node).display !== 'none') continue;
    if (node.getAttribute('role') !== 'tabpanel') return false;
    tab = true;
  }
  return tab;
}

/** The ancestors of `from` inside `root`, nearest first, then `root` itself. */
function scopesFrom(from, root) {
  const scopes = [];
  for (let el = from && root.contains(from) ? from : null; el && el !== root; el = el.parentElement) scopes.push(el);
  scopes.push(root);
  return scopes;
}

/** The sub-form (`data-shortcut-scope` container) a node of the page body is in, or null. */
function shortcutScopeOf(node) {
  const root = dom.pageBody;
  const scope = node && node.closest ? node.closest('[data-shortcut-scope]') : null;
  return scope && root && root.contains(scope) ? scope : null;
}

/**
 * The current view's control for a shortcut (`data-shortcut="submit"` / `"cancel"`) nearest to
 * the focused element (lib/shellnav.js pickShortcutTarget). A submit answers the field's own
 * form only: a sub-form's action (`data-shortcut-scope`: a paste box's Read) its own fields, the
 * view's Run every other field, and it never falls through to another form's button. A cancel
 * stops whatever runs, nearest first — a Stop button on screen, else one in a closed tab.
 * @param {'submit'|'cancel'} kind
 * @param {Element|null} from
 * @returns {HTMLElement|null}
 */
function shortcutControl(kind, from) {
  const root = dom.pageBody;
  if (!root || !current) return null;
  const submit = kind === 'submit';
  const pick = (usable) => pickShortcutTarget({
    candidates: [...root.querySelectorAll(`[data-shortcut="${kind}"]`)],
    scopes: scopesFrom(from, root),
    contains: (scope, el) => scope.contains(el),
    usable,
    strict: submit,
    from,
    localOf: submit ? shortcutScopeOf : null
  });
  const shown = pick(usableControl);
  return shown || submit ? shown : pick(behindClosedTab);
}

/** The view's main input: the one marked `data-shortcut="focus"`, else its first visible text field. */
function mainInput() {
  const root = dom.pageBody;
  if (!root || !current) return null;
  const marked = [...root.querySelectorAll('[data-shortcut="focus"]')].find(usableControl);
  if (marked) return marked;
  return [...root.querySelectorAll('input, textarea')].find((el) => isTypingTarget(el) && !el.readOnly && usableControl(el)) || null;
}

/** Focus the view's main input; false when it has none. */
function focusMainInput() {
  const el = mainInput();
  if (!el) return false;
  el.focus();
  return true;
}

/** Esc in a search field with text: empty it as Chrome does (with an `input` event), in every browser. */
function clearSearchField(field) {
  field.value = '';
  field.dispatchEvent(new Event('input', { bubbles: true }));
}

/** The app's one keydown listener for the shortcuts (see the module comment). */
function onShortcutKey(event) {
  if (event.defaultPrevented) return; // a field's own Enter handler, a Tabs arrow key, …
  if (isSearchClear(event)) {
    event.preventDefault();
    clearSearchField(event.target);
    return;
  }
  const command = shortcutFor(event);
  if (!command) return;
  // A dialog (settings, a confirmation, the Tools menu, the shortcut list) owns the keyboard; Esc closes it.
  if (globalThis.document.querySelector('dialog[open]')) return;
  const target = event.target && event.target.nodeType === 1 ? event.target : null;
  if (command === 'help' || command === 'palette') {
    event.preventDefault();
    (command === 'help' ? openShortcutHelp : openPalette)();
    return;
  }
  if (command === 'focus') {
    if (focusMainInput()) event.preventDefault();
    return;
  }
  // Submit from a field of the view only; cancel from anywhere.
  if (command === 'submit' && !(target && dom.pageBody && dom.pageBody.contains(target))) return;
  const control = shortcutControl(command, target);
  if (!control) return;
  event.preventDefault();
  control.click();
}

let palette = null;

/** The command palette (ui/palette.js with palette.css, on first use). */
function openPalette() {
  palette = palette || Promise.all([import('./ui/palette.js'), loadStylesheet('palette.css')]).then(([m]) => m.openPalette({
    views: VIEWS, navigate, href: navHref, state, session: pageSession, done: () => { palette = null; }
  })).catch((err) => {
    palette = null;
    noticeIfOutdated(pageIsOutdated);
    toast(errorText(err), { type: 'error' });
  });
}

let shortcutHelp = null;

/** The keyboard shortcuts dialog ('?' or the footer button); the focus returns where it was. */
function openShortcutHelp() {
  if (shortcutHelp) return;
  const doc = globalThis.document;
  const back = doc.activeElement && doc.activeElement !== doc.body ? doc.activeElement : null;
  const nav = globalThis.navigator || {};
  const apple = isApplePlatform((nav.userAgentData && nav.userAgentData.platform) || nav.platform || '');
  const caps = (keys) => keyCaps(keys, { apple }).join('+');
  const combo = (keys) => h('span', { class: 'keys-combo' }, keyCaps(keys, { apple }).map((k, i) => [
    i ? h('span', { class: 'keys-plus', attrs: { 'aria-hidden': 'true' } }, '+') : null,
    h('kbd', null, k)
  ]));
  const content = h('div', { class: 'stack-sm' },
    h('table', { class: 'keys-table' },
      h('tbody', null, SHORTCUTS.map((s) => h('tr', { dataset: { key: s.id } },
        h('th', { attrs: { scope: 'row' } }, combo(s.keys)),
        h('td', null, t(`keys.${s.id}`)))))),
    h('p', { class: 'muted text-sm' }, t('keys.note', { submit: caps(['Mod', 'Enter']), palette: caps(['Mod', 'K']) })));
  const dialog = Modal({
    title: t('keys.title'),
    size: 'sm',
    className: 'keys-modal',
    content,
    actions: [{ label: t('common.close'), variant: 'primary', value: null, autofocus: true }],
    onClose: () => {
      shortcutHelp = null;
      if (back && back.isConnected) back.focus({ preventScroll: true });
    }
  });
  shortcutHelp = dialog;
  dialog.open();
}

function renderChrome() {
  document.documentElement.lang = getLang();
  setManifestLang(getLang());
  dom.brandSub.textContent = t('app.subtitle');
  dom.skip.textContent = t('shell.skip');
  renderHeaderActions();
  renderNavButton();
  renderTargetChip();
  renderWorkspaceSwitch();
  renderNav();
  renderFooter();
  renderOfflineNote();
  if (current) {
    setNavActive(current.id);
    const key = titleKeyOf(current.def, current.view);
    if (dom.pageTitle) dom.pageTitle.textContent = t(key);
    setBaseTitle(`${t(key)} · ${t('app.name')}`);
  }
}

/* ------------------------------------------------------------------------ */
/* Settings dialog                                                          */
/* ------------------------------------------------------------------------ */

/**
 * Resolvers that answer fine in general but could not be reached from every network we tested.
 * Measured 2026-09-23 with tests/live/browser-doh-matrix.mjs (see the entry in lib/resolvers.js):
 * freedns.controld.com timed out on TCP from some networks. Display only — the chain logic
 * fails over on timeouts anyway.
 */
const MAY_BE_UNREACHABLE = Object.freeze(['controld']);

/**
 * i18n key of a short, honest caveat shown under a resolver in the settings dialog, or null.
 * @param {import('./lib/resolvers.js').Resolver} r
 * @returns {string|null}
 */
export function resolverNoteKey(r) {
  if (!r) return null;
  if (r.browserReliable === false && r.issue === 'h3-no-cors') return 'settings.note.h3NoCors';
  if (r.browserReliable === false) return 'settings.unreliable';
  if (MAY_BE_UNREACHABLE.includes(r.id)) return 'settings.note.unreachable';
  return null;
}

/**
 * Which control of a resolver row takes the focus back after the settings list re-renders:
 * the one the user acted on, else its nearest enabled neighbour (a row moved to the top has
 * no enabled "Move up", an unticked row no order buttons at all).
 * @param {'check'|'up'|'down'} kind the control the user acted on
 * @param {number} pos the row's position in the new chain (-1: not in the chain)
 * @param {number} len length of the new chain
 * @returns {'check'|'up'|'down'}
 */
export function settingsFocusAfter(kind, pos, len) {
  if (kind === 'check' || pos < 0) return 'check';
  if (kind === 'up') return pos > 0 ? 'up' : (len > 1 ? 'down' : 'check');
  return pos < len - 1 ? 'down' : (pos > 0 ? 'up' : 'check');
}

function resolverMeta(r) {
  const bits = [Badge(r.countryCode ? formatRegion(r.countryCode, r.location) : t('settings.anycast'), { icon: r.countryCode ? 'map-pin' : 'globe' })];
  if (r.dnssecValidating) bits.push(Badge(t('settings.flagDnssec'), { variant: 'ok', icon: 'shield' }));
  if (r.ecs) bits.push(Badge(t('settings.flagEcs'), { variant: 'info', icon: 'map-pin' }));
  if (r.filtering) bits.push(Badge(`${t('settings.flagFilter')}: ${t(`settings.filter.${r.filtering}`)}`, { variant: 'neutral', icon: 'filter' }));
  if (r.browserReliable === false) bits.push(Badge(t('settings.flagBrowser'), { variant: 'warn', icon: 'alert', title: t('settings.unreliable') }));
  else if (MAY_BE_UNREACHABLE.includes(r.id)) bits.push(Badge(t('settings.flagReach'), { variant: 'warn', icon: 'alert' }));
  const noteKey = resolverNoteKey(r);
  // A flex item of .settings-resolver-meta: long text wraps onto its own line under the badges.
  if (noteKey) bits.push(h('span', { class: 'settings-resolver-note', dataset: { note: r.id } }, t(noteKey)));
  return bits;
}

function openSettings() {
  let chain = state.settings.chain;
  const list = h('ul', { class: 'settings-resolvers', attrs: { 'aria-describedby': 'settings-chain-hint' } });
  const errorEl = h('div', { class: 'field-error', hidden: true, attrs: { 'aria-live': 'polite' } });

  // `focus` ({ id, kind }): the control the user acted on, focused again in the new list.
  const commit = (next, focus = null) => {
    if (!next.length) {
      errorEl.textContent = t('settings.atLeastOne');
      errorEl.hidden = false;
      renderList(focus); // the browser already unticked the refused checkbox: tick it again
      return;
    }
    errorEl.hidden = true;
    chain = state.updateSettings({ chain: next }).chain;
    renderList(focus);
    const pos = focus ? chain.indexOf(focus.id) : -1;
    if (focus && focus.kind !== 'check' && pos !== -1) announce(t('settings.position', { n: pos + 1 }));
  };

  function renderList(focus = null) {
    const ordered = [...chain.map((id) => getResolver(id)).filter(Boolean), ...RESOLVERS.filter((r) => !chain.includes(r.id))];
    clear(list);
    ordered.forEach((r) => {
      const pos = chain.indexOf(r.id);
      const active = pos !== -1;
      const cbId = `settings-res-${r.id}`;
      const move = (dir) => {
        const btn = IconButton({
          icon: `arrow-${dir}`,
          label: `${t(dir === 'up' ? 'common.moveUp' : 'common.moveDown')}: ${r.name}`,
          size: 'sm',
          disabled: dir === 'up' ? pos === 0 : pos === chain.length - 1,
          onClick: () => {
            const next = chain.slice();
            const to = dir === 'up' ? pos - 1 : pos + 1;
            [next[to], next[pos]] = [next[pos], next[to]];
            commit(next, { id: r.id, kind: dir });
          }
        });
        btn.dataset.move = dir;
        return btn;
      };
      list.append(h('li', { class: ['settings-resolver', { 'is-active': active }], dataset: { resolver: r.id } },
        h('input', {
          type: 'checkbox',
          class: 'check-input',
          id: cbId,
          checked: active,
          on: {
            change: (e) => commit(e.target.checked ? [...chain, r.id] : chain.filter((id) => id !== r.id), { id: r.id, kind: 'check' })
          }
        }),
        h('div', { class: 'settings-resolver-main' },
          h('label', { class: 'settings-resolver-name', for: cbId }, r.name, ' ', h('span', { class: 'muted text-xs' }, r.operator)),
          h('div', { class: 'settings-resolver-meta' }, resolverMeta(r))),
        active ? h('div', { class: 'settings-order' },
          h('span', { class: 'settings-pos', title: t('settings.position', { n: pos + 1 }) }, String(pos + 1)),
          move('up'),
          move('down')) : h('span')));
    });
    if (!focus) return;
    // The re-render replaced the focused control: without this, focus falls to <body>.
    const row = [...list.children].find((li) => li.dataset.resolver === focus.id);
    if (!row) return;
    const want = settingsFocusAfter(focus.kind, chain.indexOf(focus.id), chain.length);
    const check = row.querySelector('input[type="checkbox"]');
    const target = want === 'check' ? check : row.querySelector(`[data-move="${want}"]`);
    (target && !target.disabled ? target : check)?.focus();
  }
  renderList();

  const concurrencyOptions = [2, 4, 6, 8, 12, 16, 24, 32]
    .filter((n) => n >= CONCURRENCY_RANGE.min && n <= CONCURRENCY_RANGE.max)
    .map((n) => ({ value: String(n), label: formatNumber(n) }));
  const currentConcurrency = String(state.settings.concurrency);
  if (!concurrencyOptions.some((o) => o.value === currentConcurrency)) {
    concurrencyOptions.push({ value: currentConcurrency, label: currentConcurrency });
  }
  const concurrency = select({
    label: t('settings.concurrency'),
    hint: t('settings.concurrencyHint'),
    options: concurrencyOptions,
    value: currentConcurrency,
    onChange: (v) => state.updateSettings({ concurrency: Number(v) })
  });

  const content = h('div', { class: 'stack' },
    h('div', { class: 'stack-sm' },
      h('div', { class: 'field-label' }, t('settings.dohChain')),
      h('div', { class: 'field-hint', id: 'settings-chain-hint' }, t('settings.dohChainHint')),
      list, errorEl),
    concurrency.el,
    h('div', { class: 'settings-danger' },
      h('div', null, h('div', { class: 'field-label' }, t('settings.clearData')), h('div', { class: 'field-hint' }, t('settings.clearDataHint'))),
      Button({
        label: t('settings.clearData'), icon: 'trash', variant: 'danger', size: 'sm',
        onClick: async () => {
          const ok = await confirmDialog({ message: t('settings.clearDataConfirm'), confirmLabel: t('common.delete'), danger: true });
          if (!ok) return;
          // Memory is cleared at once; the toast waits for the database to be deleted.
          const done = deleteAllLocalData(state);
          modal.close(null);
          await done;
        }
      })));

  const modal = Modal({
    title: t('settings.title'),
    size: 'md',
    className: 'settings-modal',
    content,
    actions: [
      {
        label: t('settings.resetDefaults'),
        icon: 'refresh',
        onClick: () => {
          const s = state.updateSettings({ chain: [], concurrency: NaN });
          chain = s.chain;
          concurrency.value = String(s.concurrency);
          errorEl.hidden = true;
          renderList();
          return false; // keep the dialog open
        }
      },
      { label: t('common.close'), variant: 'primary', value: null, autofocus: true }
    ]
  });
  modal.open();
}

/* ------------------------------------------------------------------------ */
/* Printing                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The permalink printed on top of the page: the link of the result on paper — the one its Copy
 * summary carries (ui/summary-button.resultPermalink), which a new run that was stopped or failed
 * leaves behind the route — else the route with the view's own shareable params only
 * (lib/summary.permalinkParams: never inventory data or a file's contents).
 * @returns {string}
 */
function printPermalink() {
  const base = globalThis.location.href.split('#')[0];
  if (!current) return base;
  const shown = dom.main ? resultPermalink(dom.main) : null;
  if (shown) return shown;
  const params = permalinkParams(current.id, current.params, { exclude: state.getInventoryIndex().keys() });
  return `${base}${buildRoute(current.id, params)}`;
}

/** What `beforeprint` changed, undone by `afterprint`. */
let printState = null;

/**
 * Before printing: open every closed <details> of the page (a Disclosure's content belongs on
 * paper) and put a header on top — the app, the page title, the time (UTC) and the permalink
 * (the print stylesheet hides the page header, the nav and every control).
 */
function beforePrint() {
  if (printState || !dom.page) return;
  const opened = [...dom.main.querySelectorAll('details:not([open])')];
  for (const d of opened) d.open = true;
  const url = printPermalink();
  const title = current ? t(titleKeyOf(current.def, current.view)) : '';
  const head = h('div', { class: 'print-head', attrs: { 'aria-hidden': 'true' } },
    h('div', { class: 'print-head-title' }, h('strong', null, t('app.name')), title ? ` · ${title}` : null),
    h('div', { class: 'print-head-meta' }, t('shell.printed', { time: utcStamp(new Date()) }), ' · ',
      h('a', { class: 'print-permalink', href: url }, url)));
  dom.page.prepend(head);
  printState = { opened, head };
}

/** After printing: close what {@link beforePrint} opened and drop its header. */
function afterPrint() {
  if (!printState) return;
  for (const d of printState.opened) if (d.isConnected) d.open = false;
  printState.head.remove();
  printState = null;
}

/* ------------------------------------------------------------------------ */
/* Global error handling                                                    */
/* ------------------------------------------------------------------------ */

let lastErrorToast = { message: '', at: 0 };

function notifyUnexpected(err) {
  if (!err || err.name === 'AbortError') return;
  const message = String(err.message || err).slice(0, 240);
  const now = Date.now();
  if (message === lastErrorToast.message && now - lastErrorToast.at < 5000) return;
  lastErrorToast = { message, at: now };
  toast(t('shell.unexpectedError', { message }), { type: 'error' });
}

/* ------------------------------------------------------------------------ */
/* Boot                                                                     */
/* ------------------------------------------------------------------------ */

function boot() {
  // Before anything can send a request: About › What this page sent counts from here on (the
  // app's own files loaded before this come from the buffered Resource Timing entries).
  startEgressMeter(globalThis);
  egressLog.subscribe(scheduleSentCount);
  dom.root = document.documentElement;
  dom.header = document.getElementById('app-header');
  dom.headerActions = document.getElementById('header-actions');
  dom.nav = document.getElementById('app-nav');
  dom.main = document.getElementById('main');
  dom.page = document.getElementById('page');
  dom.footer = document.getElementById('app-footer');
  dom.brandSub = document.getElementById('brand-sub');
  dom.skip = document.getElementById('skip-link');
  const brand = document.getElementById('brand');
  if (brand) brand.setAttribute('href', buildRoute(DEFAULT_VIEW));
  // The current target sits between the brand and the header controls, the workspace switcher
  // right after it.
  // After the brand: the Tools button (below 1100 px), the workspace switcher, the current target;
  // then the header's controls (docs/DESIGN.md §3.2).
  dom.navMenuHost = h('div', { class: 'header-tools' });
  dom.header.insertBefore(dom.navMenuHost, dom.headerActions);
  dom.workspaceHost = h('div', { class: 'header-workspace' });
  dom.header.insertBefore(dom.workspaceHost, dom.headerActions);
  dom.targetHost = h('div', { class: 'header-target', hidden: true });
  dom.header.insertBefore(dom.targetHost, dom.headerActions);
  pageSession.subscribe(() => {
    renderTargetChip();
    updateNavHrefs();
  });

  // A browser that used the app before the task picker existed is no first-time visitor (read
  // before the workspace store moves the old keys away; state.migrated says so afterwards too).
  if (state.settings.startTasks && hasUsedBefore(storedKeys())) noteRun();
  const settings = state.settings;
  applyTheme(settings.theme);
  setLang(detectLang({
    saved: settings.lang,
    languages: globalThis.navigator ? globalThis.navigator.languages : undefined,
    language: globalThis.navigator ? globalThis.navigator.language : undefined
  }));
  renderChrome();

  dom.skip.addEventListener('click', (event) => {
    event.preventDefault();
    const target = dom.pageTitle || dom.main;
    target.focus();
  });

  onLangChange(() => {
    renderChrome();
    if (current && current.busy) {
      pendingLangRemount = true;
      toast(t('shell.langDeferred'), { type: 'info' });
    } else {
      remountCurrent();
    }
  });

  state.subscribe((change) => {
    // Once every listener has seen this change (noteRun emits a settings change of its own).
    if (isRunSignal(change)) setTimeout(noteRun, 0);
  });
  state.subscribe(({ key, value, origin }) => {
    if (key === 'inventory') updateNavStatus();
    // The switcher counts the servers too.
    if (key === 'workspace' || key === 'workspaces' || key === 'cleared' || key === 'inventory') renderWorkspaceSwitch();
    if (key === 'settings') {
      updateNavStatus();
      syncTheme(value.theme); // also covers "restore defaults" / "delete all local data" / other tabs
      if (origin === 'external') {
        // Another tab changed language/theme: follow it.
        if (value.lang && value.lang !== getLang()) setLang(value.lang);
        else renderHeaderActions();
      }
    }
  });

  globalThis.addEventListener('hashchange', handleRoute);
  document.addEventListener('keydown', onShortcutKey);
  // Across 720 px the Tools button swaps the sheet for the drawer (a phone turned to landscape), across
  // 1100 px the drawer for the sidebar: an open Tools menu closes — from 1100 px up its button is gone,
  // so the focus goes to the page title — and the sidebar's active link comes into view.
  for (const width of [SHELL_WIDTHS.phone, SHELL_WIDTHS.sidebar]) {
    const list = typeof globalThis.matchMedia === 'function' ? globalThis.matchMedia(`(min-width: ${width}px)`) : null;
    if (!list || typeof list.addEventListener !== 'function') continue;
    list.addEventListener('change', (event) => {
      if (current) scrollNavToActive(current.id);
      if (navMenu) navMenu.close(width === SHELL_WIDTHS.sidebar && event.matches ? { wide: true } : null);
    });
  }
  globalThis.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    if (reason && reason.name === 'AbortError') {
      event.preventDefault(); // cancelled work is expected (navigation, Stop buttons)
      return;
    }
    notifyUnexpected(reason);
  });
  globalThis.addEventListener('error', (event) => {
    if (event.error) notifyUnexpected(event.error);
  });
  globalThis.addEventListener('offline', () => {
    toast(t('shell.offline'), { type: 'warn', timeout: 8000 });
    renderOfflineNote();
  });
  globalThis.addEventListener('online', renderOfflineNote);
  globalThis.addEventListener('beforeprint', beforePrint);
  globalThis.addEventListener('afterprint', afterPrint);

  // The first view mounts once the workspace store is open (its inventory and learned names are
  // read synchronously); a store that never answers holds it back WORKSPACE_WAIT_MS at most.
  let routed = false;
  const start = () => {
    if (routed) return;
    routed = true;
    if (state.settings.startTasks && state.migrated.length) noteRun();
    if (!state.persistence || !state.workspacePersistence) toast(t('shell.storageUnavailable'), { type: 'warn', timeout: 9000 });
    workspacesReady = true;
    renderWorkspaceSwitch();
    handleRoute();
  };
  state.ready.then(start, start);
  setTimeout(start, WORKSPACE_WAIT_MS);
}

if (typeof document !== 'undefined' && document.getElementById('app')) {
  boot();
}
