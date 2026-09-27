/**
 * ui/pwa.js — the installable app on the page side.
 *
 * - registerServiceWorker(): registers sw.js (site root, see lib/pwa.js) — only from the Pages
 *   bundle, never from the repository, so development never runs behind a cache. The shell calls
 *   it once the first view is up and the browser is idle.
 * - When a new version has installed next to the running one it offers "Update ready — Reload";
 *   the click has the waiting worker take over and reloads once it controls the page.
 * - reloadPage(): the shell's other reload buttons ("this page is older than the site") go through
 *   a waiting version the same way; a plain reload would get the old version back from the old
 *   worker's cache.
 * - A hash-routed page never navigates, so the browser's own update check would not run while it
 *   stays open: it asks for one when the tab becomes visible or comes back online, at most hourly.
 * - setManifestLang(): links the web app manifest of the UI language (boot.js does it at load).
 *
 * A failed registration (a private window, a browser or policy without service workers) only
 * means no offline copy: the app works online as before.
 */

import { t, registerStrings } from '../i18n.js';
import { toast } from './components.js';
import { bundleInfo, manifestFor, updateCheckDue } from '../lib/pwa.js';

registerStrings('en', {
  'pwa.updateReady': 'Update ready: a new version of DomainScope has been downloaded.',
  'pwa.reload': 'Reload'
});

registerStrings('tr', {
  'pwa.updateReady': 'Güncelleme hazır: DomainScope’un yeni sürümü indirildi.',
  'pwa.reload': 'Yenile'
});

/** How long a reload waits for the new version to take control before reloading anyway. */
const TAKEOVER_TIMEOUT_MS = 3000;

let registration = null;
let reloadRequested = false;
let updateNotice = null;

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
  container.addEventListener('controllerchange', () => {
    if (reloadRequested) win.location.reload();
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

/** "Update ready — Reload", once while it is on screen. */
function offerUpdate(win) {
  if (updateNotice && updateNotice.el && updateNotice.el.isConnected) return;
  updateNotice = toast(t('pwa.updateReady'), {
    type: 'info',
    timeout: 0,
    action: { label: t('pwa.reload'), onClick: () => reloadPage({ win }) }
  });
  if (updateNotice.el) updateNotice.el.dataset.toast = 'pwa-update';
}

/**
 * Reload into the newest version: through a waiting service worker when there is one (it takes
 * control, then the page reloads), else a plain reload.
 * @param {{ win?: Window }} [env]
 */
export function reloadPage({ win = globalThis } = {}) {
  const waiting = registration && registration.waiting;
  if (!waiting) {
    win.location.reload();
    return;
  }
  reloadRequested = true;
  waiting.postMessage({ type: 'skip-waiting' });
  // controllerchange reloads; should it never come (the worker became redundant), reload anyway.
  win.setTimeout(() => win.location.reload(), TAKEOVER_TIMEOUT_MS);
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
