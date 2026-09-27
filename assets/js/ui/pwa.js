/**
 * ui/pwa.js — the installable app on the page side.
 *
 * - registerServiceWorker(): registers sw.js (site root, see lib/pwa.js) — only from the Pages
 *   bundle, never from the repository, so development never runs behind a cache. The shell calls
 *   it once the first view is up and the browser is idle; not at all when the user asked to save
 *   data and no version is installed yet (the offline copy is about 0.9 MB compressed).
 * - When a new version has installed next to the running one it offers "Update ready — Reload";
 *   the click has the waiting worker take over and reloads once it controls the page. When another
 *   tab took the update, this one (whose version is no longer cached) offers the reload as well.
 * - reloadPage(): the shell's other reload buttons ("this page is older than the site") go through
 *   the new version the same way — asking the browser for it first when none has been found yet —
 *   because a plain reload would get the old version back from the old worker's cache. While it
 *   waits for the download it says so, and further clicks join the same reload.
 * - A hash-routed page never navigates, so the browser's own update check would not run while it
 *   stays open: it asks for one when the tab becomes visible or comes back online, at most hourly.
 * - setManifestLang(): links the web app manifest of the UI language (boot.js does it at load).
 *
 * A failed registration (a private window, a browser or policy without service workers) only
 * means no offline copy: the app works online as before.
 */

import { t, registerStrings, onLangChange } from '../i18n.js';
import { toast } from './components.js';
import { bundleInfo, manifestFor, updateCheckDue } from '../lib/pwa.js';

registerStrings('en', {
  'pwa.updateReady': 'Update ready: a new version of DomainScope has been downloaded.',
  'pwa.reload': 'Reload',
  'pwa.loading': 'Getting the new version — the page reloads as soon as it has downloaded.'
});

registerStrings('tr', {
  'pwa.updateReady': 'Güncelleme hazır: DomainScope’un yeni sürümü indirildi.',
  'pwa.reload': 'Yenile',
  'pwa.loading': 'Yeni sürüm alınıyor — indirilir indirilmez sayfa yenilenecek.'
});

/** How long a reload waits for the new version to take control before reloading anyway. */
const TAKEOVER_TIMEOUT_MS = 3000;
/** How long a reload waits for a new version to be found and installed (its app shell downloaded). */
const INSTALL_TIMEOUT_MS = 15000;

let registration = null;
let reloadRequested = false;
/** Another tab activated a newer version: it controls this page, whose own files it deleted. */
let takenOver = false;
let pendingReload = null;
let updateNotice = null;
let relabelOnLangChange = null;

/**
 * Register the service worker of this deploy (Pages bundle only).
 * @param {{ moduleUrl?: string, nav?: Navigator, win?: Window, notify?: (win: Window) => void }} [env]
 *   tests inject these; `notify` shows "Update ready — Reload"
 * @returns {Promise<ServiceWorkerRegistration|null>} null in development, without service workers
 *   or when registration failed
 */
export function registerServiceWorker({
  moduleUrl = import.meta.url, nav = globalThis.navigator, win = globalThis, notify = offerUpdate
} = {}) {
  const info = bundleInfo(moduleUrl);
  const container = nav && nav.serviceWorker;
  if (!info || !container || win.isSecureContext === false) return Promise.resolve(null);
  // Save-Data: no offline copy unasked. An installed version keeps its worker (and its updates).
  if (nav.connection && nav.connection.saveData && !container.controller) return Promise.resolve(null);
  registration = null;
  reloadRequested = false;
  takenOver = false;
  let controlled = !!container.controller;
  container.addEventListener('controllerchange', () => {
    if (reloadRequested) {
      win.location.reload();
      return;
    }
    // Not a first install (that claims a page nothing controlled): "Reload" in another tab
    // activated a newer version, which dropped this version's cache — views not opened yet are
    // gone offline and stale online. Offer the reload here too.
    if (controlled) {
      takenOver = true;
      notify(win);
    }
    controlled = true;
  });
  return container.register(info.serviceWorker, { scope: info.root }).then((reg) => {
    registration = reg;
    reg.addEventListener('updatefound', () => {
      const worker = reg.installing;
      if (!worker) return;
      worker.addEventListener('statechange', () => {
        // Installed while another version controls the page: an update (a first install has no controller).
        if (worker.state === 'installed' && container.controller) notify(win);
      });
    });
    if (reg.waiting && container.controller) notify(win);
    keepChecking(reg, win);
    return reg;
  }, (err) => {
    console.warn('[pwa] no service worker (the app works online only):', (err && err.message) || err);
    return null;
  });
}

/** "Update ready — Reload", once while it is on screen (in the current UI language). */
function offerUpdate(win) {
  if (updateNotice && updateNotice.el && updateNotice.el.isConnected) return;
  updateNotice = toast(t('pwa.updateReady'), {
    type: 'info',
    timeout: 0,
    action: { label: t('pwa.reload'), onClick: () => reloadPage({ win }) }
  });
  if (!updateNotice.el) return;
  updateNotice.el.dataset.toast = 'pwa-update';
  if (!relabelOnLangChange) {
    relabelOnLangChange = onLangChange(() => {
      const shown = updateNotice && updateNotice.el;
      if (!shown || !shown.isConnected) return;
      shown.remove();
      updateNotice = null;
      offerUpdate(win);
    });
  }
}

/**
 * Reload into the newest version. With a service worker in control a plain reload would be
 * answered from its cache, so the new version goes first: one already waiting or installing, else
 * one the browser is asked for now (the shell's "this page is older than the site" offers come
 * before the browser has looked). Once it has installed it takes control and the page reloads;
 * without one (no worker, nothing newer, a timeout) it is a plain reload, and so it is when
 * another tab has already made a newer version take over. While it waits for a download a
 * status toast says so; a call while one is under way joins it (no second update check).
 * @param {{ win?: Window, timeoutMs?: number }} [env]
 * @returns {Promise<void>}
 */
export function reloadPage(env = {}) {
  if (!pendingReload) {
    pendingReload = reloadThroughNewVersion(env).finally(() => {
      pendingReload = null;
    });
  }
  return pendingReload;
}

async function reloadThroughNewVersion({ win = globalThis, timeoutMs = INSTALL_TIMEOUT_MS }) {
  const reg = registration;
  let worker = reg && (reg.waiting || reg.installing);
  let status = null;
  const showStatus = () => {
    if (!status) status = toast(t('pwa.loading'), { type: 'info', timeout: 0 });
  };
  try {
    // After another tab's update the active version is already newer than this page: reload into it.
    if (!worker && reg && reg.active && !takenOver) {
      showStatus();
      await within(reg.update().catch(() => {}), timeoutMs, win);
      worker = reg.waiting || reg.installing;
    }
    if (worker && worker.state !== 'installed') showStatus();
    if (worker && (await installed(worker, timeoutMs, win))) {
      reloadRequested = true;
      worker.postMessage({ type: 'skip-waiting' });
      // controllerchange reloads; should it never come (the worker became redundant), reload anyway.
      win.setTimeout(() => win.location.reload(), TAKEOVER_TIMEOUT_MS);
      return;
    }
  } finally {
    if (status && !reloadRequested) status.close();
  }
  win.location.reload();
}

/** Settle when `promise` does or after `ms`, whichever comes first. */
function within(promise, ms, win) {
  return Promise.race([promise, new Promise((resolve) => win.setTimeout(resolve, ms))]);
}

/** Has `worker` installed (it waits to take over)? False once it failed or after `ms`. */
function installed(worker, ms, win) {
  if (worker.state === 'installed') return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (ok) => {
      worker.removeEventListener?.('statechange', onChange);
      resolve(ok);
    };
    const onChange = () => {
      if (worker.state === 'installed') done(true);
      else if (worker.state === 'redundant' || worker.state === 'activated') done(false);
    };
    worker.addEventListener('statechange', onChange);
    win.setTimeout(() => done(false), ms);
  });
}

/** Ask for a new version when the tab becomes visible or comes back online, at most hourly. */
function keepChecking(reg, win) {
  let last = Date.now();
  const check = () => {
    if ((win.document && win.document.visibilityState === 'hidden') || !updateCheckDue(last, Date.now())) return;
    last = Date.now();
    reg.update().catch(() => {}); // offline or a failed fetch: the next check tries again
  };
  if (win.document) win.document.addEventListener('visibilitychange', check);
  win.addEventListener('online', check);
}

/**
 * Link the web app manifest of the UI language, so an install gets its name and shortcuts in it.
 * @param {string} lang
 * @param {Document} [doc]
 */
export function setManifestLang(lang, doc = globalThis.document) {
  const link = doc && doc.querySelector('link[rel="manifest"]');
  const href = manifestFor(lang);
  if (link && link.getAttribute('href') !== href) link.setAttribute('href', href);
}
