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
 */

import {
  t, setLang, getLang, detectLang, onLangChange, formatNumber, formatRegion
} from './i18n.js';
import { state, CONCURRENCY_RANGE } from './state.js';
import { h, clear, uid } from './ui/dom.js';
import {
  Icon, SegmentedControl, IconButton, ButtonLink, Button, Alert, ErrorBanner, Spinner, Modal, toast,
  select, Badge, confirmDialog, announce, describeError
} from './ui/components.js';
import { RESOLVERS, getResolver } from './lib/resolvers.js';

/** Repository URL shown in the header/footer. */
export const REPO_URL = 'https://github.com/halilibrahimd27/domainscope';
/** App version (keep in sync with package.json). */
export const APP_VERSION = '1.0.0';
/** Default route. */
export const DEFAULT_VIEW = 'subdomains';

/**
 * Navigation table in spec §6 order. `load` is a lazy import so a view that fails to load
 * (or is still being written) cannot break the rest of the app.
 */
export const VIEWS = Object.freeze([
  { id: 'subdomains', group: 'discover', icon: 'layers', load: () => import('./views/subdomains.js') },
  { id: 'zone', group: 'discover', icon: 'file-text', load: () => import('./views/zone.js') },
  { id: 'scan', group: 'ssl', icon: 'target', load: () => import('./views/scan.js') },
  { id: 'cert', group: 'ssl', icon: 'shield', load: () => import('./views/cert.js') },
  { id: 'global', group: 'dns', icon: 'globe', load: () => import('./views/global.js') },
  { id: 'lookup', group: 'dns', icon: 'search', load: () => import('./views/lookup.js') },
  { id: 'bulk', group: 'dns', icon: 'list', load: () => import('./views/bulk.js') },
  { id: 'ip', group: 'dns', icon: 'network', load: () => import('./views/ip.js') },
  { id: 'health', group: 'dns', icon: 'activity', load: () => import('./views/health.js') },
  { id: 'inventory', group: 'data', icon: 'server', load: () => import('./views/inventory.js') },
  { id: 'about', group: 'data', icon: 'info', load: () => import('./views/about.js') }
].map((v) => Object.freeze(v)));

const NAV_GROUPS = [
  { id: 'discover', labelKey: 'nav.groupDiscover' },
  { id: 'ssl', labelKey: 'nav.groupSsl' },
  { id: 'dns', labelKey: 'nav.groupDns' },
  { id: 'data', labelKey: 'nav.groupData' }
];

const VIEW_BY_ID = new Map(VIEWS.map((v) => [v.id, v]));

/* ------------------------------------------------------------------------ */
/* Route helpers (pure — unit-tested)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Parse a location hash.
 * @param {string} hash e.g. '#/lookup?name=example.com&type=MX'
 * @returns {{ view: string|null, params: Record<string, string>, searchParams: URLSearchParams, isRoute: boolean }}
 *   view is null for unknown views or an empty route; isRoute is false for non-route anchors ('#main').
 */
export function parseRoute(hash) {
  const raw = String(hash ?? '').replace(/^#/, '');
  if (!raw.startsWith('/')) return { view: null, params: {}, searchParams: new URLSearchParams(), isRoute: false };
  const rest = raw.slice(1);
  const q = rest.indexOf('?');
  const path = q === -1 ? rest : rest.slice(0, q);
  const query = q === -1 ? '' : rest.slice(q + 1);
  let id = '';
  try {
    id = decodeURIComponent(path.split('/')[0] || '').trim().toLowerCase();
  } catch {
    id = '';
  }
  const searchParams = new URLSearchParams(query);
  const params = {};
  for (const [k, v] of searchParams) params[k] = v; // repeated keys: last wins (use searchParams.getAll)
  return { view: VIEW_BY_ID.has(id) ? id : null, params, searchParams, isRoute: true };
}

/**
 * Build a route hash. null/undefined/''/false values are skipped, true → '1',
 * arrays become repeated keys.
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
  return `#/${encodeURIComponent(String(view || DEFAULT_VIEW))}${qs ? `?${qs}` : ''}`;
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

/* ------------------------------------------------------------------------ */
/* Lazy modules after a deploy                                              */
/* ------------------------------------------------------------------------ */

/** A module fetched now does not match one this page loaded earlier (Chrome, Firefox, Safari). */
const STALE_LINK_RE = /does(?: not|n['’]t) provide an export named|^import not found:|Importing binding name .+ is not found/i;
/** A lazily imported module (or one of its imports) could not be fetched (Chrome, Firefox, Safari). */
const STALE_FETCH_RE = /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed/i;

/**
 * Did a lazy import fail because this page belongs to an earlier deploy? Either a module fetched
 * now does not link against the ones already loaded (a missing export, SyntaxError), or it could
 * not be fetched at all (TypeError): the Pages bundle serves each deploy from its own
 * v/<version>/ directory (tools/assemble-site.mjs), so the old one is gone. The fetch case is
 * also what an offline browser reports. Retrying in the same document cannot fix a link error —
 * the browser keeps the modules it already has — so the shell offers a page reload.
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

let outdatedNoticeShown = false;

/** A shared lazy module (DoH, Globalping) failed to load after a deploy: say so once, with a reload button. */
function noticeIfOutdated(err) {
  if (outdatedNoticeShown || !isStaleModuleError(err)) return;
  outdatedNoticeShown = true;
  toast(t('shell.viewOutdated'), {
    type: 'warn',
    timeout: 0,
    action: { label: t('shell.reload'), onClick: () => globalThis.location.reload() }
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
      noticeIfOutdated(err);
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
      noticeIfOutdated(err);
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
/* View context                                                             */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ViewContext
 * @property {string} id                      current view id
 * @property {typeof state} state             shared state (inventory, settings, session, subscribe)
 * @property {typeof t} t                     translate
 * @property {'tr'|'en'} lang                 language at mount time (views re-mount on change)
 * @property {Record<string, string>} params  route params (updated by setParams)
 * @property {URLSearchParams} searchParams   raw params (for repeated keys)
 * @property {AbortSignal} signal             aborted when the view unmounts — pass it to every network call
 * @property {any} restored                   value returned by the previous instance's `snapshot()` when the
 *                                            view is re-mounted after a language change, else null
 * @property {(view: string, params?: object, opts?: { replace?: boolean, force?: boolean }) => void} navigate
 * @property {(params: object, opts?: { merge?: boolean }) => void} setParams  update the URL without re-mounting
 * @property {(view: string, params?: object) => string} href  route hash for links ('#/lookup?name=x')
 * @property {(params?: object) => string} shareUrl  absolute URL of this view with params
 * @property {() => Promise<object>} getDns   shared DohClient
 * @property {() => Promise<object>} getGlobalping  shared Globalping client (one quota view; sends nothing by itself)
 * @property {(busy: boolean|string) => void} setBusy  header activity bar + aria-busy; defers language re-mounts
 * @property {typeof toast} toast
 * @property {(...nodes: any[]) => void} setActions  put buttons into the page header (right side)
 * @property {(fn: () => void) => void} onCleanup  run fn when the view unmounts (e.g. state.subscribe's unsubscribe)
 * @property {() => Map<string, object[]>} getInventoryIndex  memoized IP → servers index
 * @property {string} repoUrl
 * @property {string} version
 */

let current = null; // { id, def, view, params, ctx, controller, cleanups[], busy }
let routeToken = 0;
let pendingLangRemount = false;
let firstRouteDone = false;
const dom = {};

function currentHash() {
  return globalThis.location ? globalThis.location.hash : '';
}

/**
 * Navigate to a view.
 * @param {string} view
 * @param {object} [params]
 * @param {{ replace?: boolean, force?: boolean }} [opts] replace: no new history entry; force: re-mount even if unchanged
 */
export function navigate(view, params = {}, { replace = false, force = false } = {}) {
  const target = VIEW_BY_ID.has(view) ? view : DEFAULT_VIEW;
  const hash = buildRoute(target, params);
  if (hash === currentHash()) {
    if (force) {
      const route = parseRoute(hash);
      showRoute(target, route.params, { force: true, searchParams: route.searchParams });
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

function makeContext(id, params, searchParams, controller, restored) {
  const cleanups = [];
  const ctx = {
    id,
    state,
    t,
    lang: getLang(),
    params: { ...params },
    searchParams,
    signal: controller.signal,
    restored: restored ?? null,
    repoUrl: REPO_URL,
    version: APP_VERSION,
    navigate,
    href: buildRoute,
    getDns,
    getGlobalping: () => getGlobalping(),
    toast,
    getInventoryIndex: () => state.getInventoryIndex(),
    setParams(next, { merge = false } = {}) {
      if (!isCurrent(ctx)) return;
      const merged = merge ? { ...ctx.params, ...next } : { ...next };
      const hash = buildRoute(id, merged);
      const parsed = parseRoute(hash);
      ctx.params = parsed.params;
      ctx.searchParams = parsed.searchParams;
      current.params = parsed.params;
      if (hash !== currentHash()) globalThis.history.replaceState(null, '', hash);
    },
    shareUrl(p = ctx.params) {
      const base = globalThis.location.href.split('#')[0];
      return `${base}${buildRoute(id, p)}`;
    },
    setBusy(busy) {
      if (isCurrent(ctx)) setBusyState(busy);
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
  const link = dom.nav.querySelector(`[data-view="${current.id}"]`);
  if (link) link.classList.toggle('is-busy', on);
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

/**
 * The page body of a view whose module failed to load. After a deploy (see isStaleModuleError)
 * the first action reloads the page; Retry stays only where it can help (a fetch failure may be
 * a network blip, a link error never goes away in this document).
 */
function viewLoadFailure(def, params, sp, err) {
  const retry = () => showRoute(def.id, params, { force: true, searchParams: sp });
  if (!isStaleModuleError(err)) return ErrorBanner(err, { title: t('shell.viewLoadFailed'), onRetry: retry });
  const { detail } = describeError(err);
  const reload = Button({
    label: t('shell.reload'), icon: 'refresh', variant: 'primary', size: 'sm',
    dataset: { action: 'reload-page' },
    onClick: () => globalThis.location.reload()
  });
  return Alert({
    variant: 'warn',
    title: t('shell.viewLoadFailed'),
    message: t('shell.viewOutdated'),
    children: detail ? h('details', { class: 'alert-details' }, h('summary', null, t('error.details')), h('code', { class: 'mono' }, detail)) : null,
    actions: err.name === 'SyntaxError' ? [reload] : [reload, Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', onClick: retry })]
  });
}

function titleKeyOf(def, view) {
  return (view && typeof view.titleKey === 'string' && view.titleKey) || `nav.${def.id}`;
}

function renderPageHeader(def, view = null) {
  const titleKey = titleKeyOf(def, view);
  dom.pageTitle = h('h1', { class: 'page-title', id: 'page-title', attrs: { tabindex: -1 } }, t(titleKey));
  dom.pageActions = h('div', { class: 'page-actions' });
  dom.pageBody = h('div', { class: 'page-body', id: 'page-body', dataset: { view: def.id } });
  const desc = t(`nav.${def.id}.desc`);
  clear(dom.page);
  dom.page.append(
    h('header', { class: 'page-header' },
      h('div', { class: 'page-icon', attrs: { 'aria-hidden': 'true' } }, Icon(def.icon, { size: 20 })),
      h('div', { class: 'page-titles' }, dom.pageTitle, desc ? h('p', { class: 'page-desc' }, desc) : null),
      dom.pageActions),
    dom.pageBody);
  document.title = `${t(titleKey)} · ${t('app.name')}`;
}

async function showRoute(id, params, { force = false, restored = null, searchParams = null } = {}) {
  const def = VIEW_BY_ID.get(id) || VIEW_BY_ID.get(DEFAULT_VIEW);
  const sp = searchParams || new URLSearchParams(params);
  if (!force && current && current.id === def.id && sameSearch(current.ctx.searchParams, sp)) return;

  // Same view with new params: let the view take them without a re-mount if it can. A
  // query repeating a key is re-mounted: mount reads every value from ctx.searchParams.
  if (!force && current && current.id === def.id && current.view && typeof current.view.update === 'function'
    && !hasRepeatedKeys(sp)) {
    const cur = current;
    const prev = { params: cur.ctx.params, searchParams: cur.ctx.searchParams };
    cur.ctx.params = { ...params };
    cur.ctx.searchParams = sp;
    try {
      const handled = cur.view.update({ ...params }, cur.ctx);
      if (handled === true) {
        cur.params = { ...params };
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

  let mod;
  try {
    mod = await loadView(def);
  } catch (err) {
    clearTimeout(spinnerTimer);
    if (token !== routeToken) return;
    // Logged on purpose: E2E runs fail on console errors, so a broken view never goes unnoticed.
    console.error(`[view:${def.id}] failed to load`, err);
    clear(dom.pageBody);
    dom.pageBody.append(viewLoadFailure(def, params, sp, err));
    finishRoute(def);
    return;
  }
  clearTimeout(spinnerTimer);
  if (token !== routeToken) return;

  const view = mod && mod.default && typeof mod.default.mount === 'function' ? mod.default : mod;
  if (titleKeyOf(def, view) !== `nav.${def.id}`) {
    dom.pageTitle.textContent = t(titleKeyOf(def, view));
    document.title = `${t(titleKeyOf(def, view))} · ${t('app.name')}`;
  }
  const controller = new AbortController();
  const { ctx, cleanups } = makeContext(def.id, params, sp, controller, restored);
  current = { id: def.id, def, view, params: { ...params }, ctx, controller, cleanups, busy: false };
  clear(dom.pageBody);
  try {
    if (!view || typeof view.mount !== 'function') throw new TypeError(`View "${def.id}" does not export mount()`);
    const ret = await view.mount(dom.pageBody, ctx);
    if (typeof ret === 'function') {
      if (current && current.ctx === ctx) cleanups.push(ret);
      else ret();
    }
  } catch (err) {
    if (token === routeToken && !(err && err.name === 'AbortError')) {
      clear(dom.pageBody);
      dom.pageBody.append(ErrorBanner(err, {
        title: t('shell.viewCrashed'),
        onRetry: () => showRoute(def.id, params, { force: true, searchParams: sp })
      }));
      console.error(`[view:${def.id}] mount failed`, err);
    }
  }
  if (token === routeToken) finishRoute(def);
}

function finishRoute(def) {
  if (firstRouteDone) {
    // Move focus to the new page title for keyboard and screen-reader users.
    globalThis.scrollTo(0, 0);
    if (dom.pageTitle) dom.pageTitle.focus({ preventScroll: true });
    announce(t(`nav.${def.id}`));
  }
  firstRouteDone = true;
  document.documentElement.dataset.appReady = 'true';
}

function handleRoute() {
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
  showRoute(route.view, route.params, { searchParams: route.searchParams });
}

function remountCurrent() {
  if (!current) return;
  let snapshot = null;
  try {
    if (typeof current.view.snapshot === 'function') snapshot = current.view.snapshot(current.ctx);
  } catch (err) {
    reportError(err);
  }
  showRoute(current.id, current.params, { force: true, restored: snapshot, searchParams: current.ctx.searchParams });
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

/** Apply a theme and bring both header theme controls in line with it. */
function syncTheme(value) {
  applyTheme(value);
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
  const theme = SegmentedControl({
    label: t('shell.theme'),
    size: 'sm',
    className: 'theme-toggle',
    value: settings.theme,
    options: THEME_ORDER.map((value) => ({ value, icon: THEME_ICONS[value], title: t(THEME_LABELS[value]) })),
    onChange: chooseTheme
  });
  theme.el.dataset.control = 'theme';
  dom.themeSeg = theme;
  const settingsBtn = IconButton({ icon: 'sliders', label: t('shell.settings'), onClick: openSettings });
  settingsBtn.dataset.control = 'settings';
  const gh = ButtonLink({ href: REPO_URL, label: 'GitHub', icon: 'code', variant: 'ghost', size: 'sm', external: true, title: t('shell.github') });
  gh.classList.add('gh-link');
  clear(dom.headerActions);
  dom.headerActions.append(lang.el, theme.el, themeCycleButton(settings.theme),
    h('span', { class: 'header-sep', attrs: { 'aria-hidden': 'true' } }), settingsBtn, gh);
}

function chainLabel(chain) {
  return chain.map((id) => getResolver(id)?.name || id).join(' → ');
}

function renderNav() {
  const activeId = current ? current.id : null;
  const groups = NAV_GROUPS.map((g) => {
    const labelId = uid('navgroup');
    return h('div', { class: 'nav-group', attrs: { role: 'group', 'aria-labelledby': labelId } },
      h('div', { class: 'nav-group-label', id: labelId }, t(g.labelKey)),
      h('ul', { class: 'nav-list' }, VIEWS.filter((v) => v.group === g.id).map((v) => h('li', null,
        h('a', {
          class: 'nav-link',
          href: buildRoute(v.id),
          dataset: { view: v.id },
          attrs: { 'aria-current': v.id === activeId ? 'page' : null }
        }, Icon(v.icon, { size: 17 }), h('span', { class: 'nav-label' }, t(`nav.${v.id}`)))))));
  });
  dom.navInventory = h('span');
  dom.navDoh = h('span');
  const foot = h('div', { class: 'nav-foot' },
    h('a', { class: 'nav-status', href: buildRoute('inventory'), dataset: { status: 'inventory' } }, Icon('server', { size: 14 }), dom.navInventory),
    h('button', {
      type: 'button',
      class: 'nav-status link-reset',
      dataset: { status: 'doh' },
      title: t('settings.dohChain'),
      on: { click: openSettings }
    }, Icon('globe', { size: 14 }), dom.navDoh),
    h('div', { class: 'nav-status nav-status-privacy' }, Icon('lock', { size: 14 }), h('span', null, t('shell.privacyShort'))));
  clear(dom.nav);
  dom.nav.setAttribute('aria-label', t('nav.label'));
  dom.nav.append(...groups, foot);
  updateNavStatus();
}

function updateNavStatus() {
  if (!dom.navInventory) return;
  const count = state.inventory.servers.length;
  dom.navInventory.textContent = t('shell.inventoryStatus', { count });
  dom.navDoh.textContent = t('shell.dohStatus', { chain: chainLabel(state.settings.chain) });
}

function setNavActive(id) {
  dom.nav.querySelectorAll('.nav-link').forEach((a) => {
    if (a.dataset.view === id) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  // On phones the nav scrolls horizontally: bring the active item into view (no page scroll).
  const link = dom.nav.querySelector(`.nav-link[data-view="${id}"]`);
  if (link && dom.nav.scrollWidth > dom.nav.clientWidth + 1) {
    const left = link.offsetLeft - (dom.nav.clientWidth - link.offsetWidth) / 2;
    dom.nav.scrollLeft = Math.max(0, left);
  }
}

function renderFooter() {
  clear(dom.footer);
  dom.footer.append(
    h('span', null, `${t('app.name')} · ${t('shell.version', { version: APP_VERSION })}`),
    h('span', null, t('shell.footer')),
    h('a', { href: REPO_URL, attrs: { target: '_blank', rel: 'noopener noreferrer' } }, 'GitHub'),
    h('span', { class: 'spacer' }),
    h('span', null, t('shell.privacyLong')));
}

function renderChrome() {
  document.documentElement.lang = getLang();
  dom.brandSub.textContent = t('app.subtitle');
  dom.skip.textContent = t('shell.skip');
  renderHeaderActions();
  renderNav();
  renderFooter();
  if (current) {
    setNavActive(current.id);
    const key = titleKeyOf(current.def, current.view);
    if (dom.pageTitle) dom.pageTitle.textContent = t(key);
    document.title = `${t(key)} · ${t('app.name')}`;
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
          state.clearAll();
          modal.close(null);
          toast(t('settings.dataCleared'), { type: 'success' });
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

  state.subscribe(({ key, value, origin }) => {
    if (key === 'inventory') updateNavStatus();
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
  globalThis.addEventListener('offline', () => toast(t('shell.offline'), { type: 'warn', timeout: 8000 }));

  if (!state.persistence) toast(t('shell.storageUnavailable'), { type: 'warn', timeout: 9000 });

  handleRoute();
}

if (typeof document !== 'undefined' && document.getElementById('app')) {
  boot();
}
