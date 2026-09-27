/**
 * ui/jobs.js — the progress of long jobs outside their view.
 *
 * A Subdomains / SSL Targets scan or a Bulk Resolve run belongs to its module and keeps going
 * while the user works elsewhere; its only signal there used to be the final toast. While a job
 * runs:
 * - the tab title reads "(62%) <page> · DomainScope" (the least advanced job when several run);
 * - the running view's navigation entry carries a small progress ring;
 * - the favicon gets a progress badge (an SVG `data:` URL — the page CSP allows `img-src data:`);
 * - once a job has run 30 s (lib/jobprogress.js LONG_JOB_MS), its panel offers "Notify me when done"
 *   ({@link NotifyButton}): the browser asks for permission only on that click, the choice lasts
 *   for the page session, and a desktop notification is sent when a long job finishes or fails
 *   while the user is not looking at it.
 * With `prefers-reduced-motion` the ring does not spin and the favicon changes in 10 % steps.
 *
 * The shell sets the page's own title through {@link setBaseTitle} and calls
 * {@link refreshJobIndicators} after it re-renders the navigation. The arithmetic and the
 * markup live in lib/jobprogress.js.
 */

import { h, svg } from './dom.js';
import { Button, announce, setButtonBusy } from './components.js';
import { t, registerStrings, formatPercent } from '../i18n.js';
import { state } from '../state.js';
import {
  advance, combineJobs, percentOf, progressTitle, faviconStep, badgedIcon, svgDataUrl, offerNotify, shouldNotify
} from '../lib/jobprogress.js';

registerStrings('en', {
  'jobs.running': 'running',
  'jobs.runningPercent': 'running, {percent} done',
  'jobs.notify': 'Notify me when done',
  'jobs.notifyTitle': 'Sends a desktop notification when a job that ran over 30 seconds finishes while you are elsewhere. Your browser asks for permission first; the choice lasts until you close the page.',
  'jobs.notifyBlocked': 'Desktop notifications are blocked for this site in your browser.',
  'jobs.notifyReady': 'You will get a desktop notification when it finishes.',
  'jobs.notifyOff': 'No desktop notification.',
  'jobs.doneTitle': '{view} finished',
  'jobs.failedTitle': '{view} stopped with an error'
});

registerStrings('tr', {
  'jobs.running': 'çalışıyor',
  'jobs.runningPercent': 'çalışıyor, {percent} tamamlandı',
  'jobs.notify': 'Bitince bildir',
  'jobs.notifyTitle': '30 saniyeden uzun süren bir iş siz başka yerdeyken bitince masaüstü bildirimi gönderilir. Tarayıcınız önce izin ister; seçim sayfayı kapatana kadar geçerlidir.',
  'jobs.notifyBlocked': 'Bu site için masaüstü bildirimleri tarayıcınızda engellenmiş.',
  'jobs.notifyReady': 'Bitince masaüstü bildirimi alacaksınız.',
  'jobs.notifyOff': 'Masaüstü bildirimi yok.',
  'jobs.doneTitle': '{view} tamamlandı',
  'jobs.failedTitle': '{view} bir hatayla durdu'
});

/** Running jobs by id. */
const jobs = new Map();
let counter = 0;
/** The page's own title (the shell's); the progress prefix goes in front of it. */
let baseTitle = null;
/** Opted in to desktop notifications for this page session (never stored). */
let notifyOptIn = false;
/** The favicon <link> and its own href, while a badge replaces it. */
let icon = null;
let shownIcon = undefined;
let renderTimer = null;
const listeners = new Set();

/**
 * @typedef {object} JobHandle
 * @property {number} id
 * @property {string} view
 * @property {Date} startedAt
 * @property {(fraction: number|null) => void} update the job's progress (it never runs backwards)
 * @property {(end: { status: 'done'|'cancelled'|'error', body?: string }) => void} finish
 * @property {() => boolean} running
 */

/**
 * Register a running job of `view` ('subdomains', 'scan', 'bulk').
 * @param {{ view: string }} opts
 * @returns {JobHandle}
 */
export function startJob({ view }) {
  counter += 1;
  const job = { id: counter, view: String(view), startedAt: new Date(), fraction: null };
  jobs.set(job.id, job);
  schedule();
  emit();
  return {
    id: job.id,
    view: job.view,
    startedAt: job.startedAt,
    update(fraction) {
      if (!jobs.has(job.id)) return;
      const next = advance(job.fraction, fraction);
      if (next === job.fraction) return;
      job.fraction = next;
      schedule();
    },
    finish({ status, body = '' } = {}) {
      if (!jobs.delete(job.id)) return;
      render();
      emit();
      notify(job, status, body);
    },
    running: () => jobs.has(job.id)
  };
}

/**
 * The page's own title; while jobs run the progress prefix goes in front of it. The shell calls
 * this instead of setting document.title.
 * @param {string} text
 */
export function setBaseTitle(text) {
  baseTitle = String(text ?? '');
  render();
}

/** Re-draw the rings after the shell re-rendered the navigation (language change). */
export function refreshJobIndicators() {
  render();
}

function emit() {
  for (const fn of [...listeners]) {
    try {
      fn();
    } catch {
      // a listener of a view that is gone
    }
  }
}

function reducedMotion() {
  try {
    return !!(globalThis.matchMedia && globalThis.matchMedia('(prefers-reduced-motion: reduce)').matches);
  } catch {
    return false;
  }
}

/**
 * At most four renders a second — with timers, not animation frames: a tab in the background
 * (the case this is for) gets no frames, only slowed timers.
 */
function schedule() {
  if (renderTimer) return;
  renderTimer = setTimeout(render, 250);
}

function render() {
  clearTimeout(renderTimer);
  renderTimer = null;
  const doc = globalThis.document;
  if (!doc) return;
  const running = [...jobs.values()];
  const combined = combineJobs(running);
  if (baseTitle === null) baseTitle = doc.title;
  const pct = percentOf(combined.fraction);
  doc.title = running.length ? progressTitle(baseTitle, pct === null ? null : formatPercent(pct / 100)) : baseTitle;
  renderNav(doc, running);
  renderFavicon(doc, running.length ? combined.fraction : undefined);
}

function renderNav(doc, running) {
  for (const link of doc.querySelectorAll('#app-nav .nav-link[data-view]')) {
    const job = running.find((j) => j.view === link.dataset.view);
    let ring = link.querySelector(':scope > .nav-job');
    if (!job) {
      if (ring) ring.remove();
      link.classList.remove('has-job');
      continue;
    }
    if (!ring) {
      ring = h('span', { class: 'nav-job' },
        svg('svg', { class: 'nav-job-ring', attrs: { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': 'true', focusable: 'false' } },
          svg('circle', { class: 'nav-job-track', attrs: { cx: 8, cy: 8, r: 6, pathLength: 100 } }),
          svg('circle', { class: 'nav-job-bar', attrs: { cx: 8, cy: 8, r: 6, pathLength: 100, transform: 'rotate(-90 8 8)' } })),
        h('span', { class: 'sr-only' }));
      link.append(ring);
      link.classList.add('has-job');
    }
    const pct = percentOf(job.fraction);
    ring.dataset.percent = pct === null ? '' : String(pct);
    ring.classList.toggle('is-indeterminate', pct === null);
    ring.querySelector('.nav-job-bar').setAttribute('stroke-dasharray', `${pct === null ? 25 : Math.max(pct, 2)} 100`);
    ring.querySelector('.sr-only').textContent = `, ${pct === null ? t('jobs.running') : t('jobs.runningPercent', { percent: formatPercent(pct / 100) })}`;
  }
}

/** `fraction` undefined = no job: the page's own icon again. */
function renderFavicon(doc, fraction) {
  if (!icon || !icon.el.isConnected) {
    const el = doc.querySelector('link[rel~="icon"]');
    if (!el) return;
    icon = { el, href: el.getAttribute('href') };
  }
  const step = fraction === undefined ? undefined : faviconStep(fraction, { reducedMotion: reducedMotion() });
  if (step === shownIcon) return;
  shownIcon = step;
  if (step === undefined) {
    icon.el.setAttribute('href', icon.href);
    icon.el.setAttribute('type', 'image/svg+xml');
  } else {
    icon.el.setAttribute('type', 'image/svg+xml');
    icon.el.setAttribute('href', svgDataUrl(badgedIcon(step)));
  }
}

/* ------------------------------------------------------------------------ */
/* Desktop notification (opt-in, page session)                              */
/* ------------------------------------------------------------------------ */

function notificationApi() {
  const N = globalThis.Notification;
  return typeof N === 'function' ? N : null;
}

function permission() {
  const N = notificationApi();
  return N ? String(N.permission || 'default') : null;
}

function notify(job, status, body) {
  const N = notificationApi();
  const doc = globalThis.document;
  const watching = !!doc && doc.visibilityState === 'visible' && (typeof doc.hasFocus !== 'function' || doc.hasFocus())
    && doc.documentElement.dataset.view === job.view;
  if (!N || !shouldNotify({ optedIn: notifyOptIn, permission: permission(), status, durationMs: Date.now() - job.startedAt, watching })) return;
  const view = t(`nav.${job.view}`);
  try {
    const n = new N(t(status === 'error' ? 'jobs.failedTitle' : 'jobs.doneTitle', { view }), { body: body || '', tag: `domainscope-${job.view}` });
    n.onclick = () => {
      try {
        globalThis.focus();
      } catch {
        // not allowed: the tab is still there
      }
      globalThis.location.hash = `#/${job.view}`;
      n.close();
    };
  } catch {
    // Some browsers only notify from a service worker: the toast of the view still says it.
  }
}

/**
 * "Notify me when done" for a running job's panel. Offered once the job has run
 * 30 s (at once when this page session already opted in); the permission is asked
 * only on a click. A toggle: its label stays, `aria-pressed` (and a pressed look) says it is on,
 * and pressing it again turns the opt-in off. Hidden when the browser has no
 * notifications; a blocked permission is said instead of offering the button.
 * @param {JobHandle|(() => JobHandle|null)|null} source the job, or a getter for one a panel built
 *   just before its job starts
 * @returns {HTMLElement}
 */
export function NotifyButton(source) {
  const el = h('span', { class: 'job-notify', hidden: true });
  const N = notificationApi();
  if (!source || !N) return el;
  const job = typeof source === 'function'
    ? { get startedAt() { return (source() || {}).startedAt || new Date(); }, running: () => { const j = source(); return j ? j.running() : true; } }
    : source;
  const btn = Button({ label: t('jobs.notify'), icon: 'bell', size: 'sm', variant: 'ghost', title: t('jobs.notifyTitle'), dataset: { action: 'job-notify' } });
  const blocked = h('span', { class: 'muted text-xs job-notify-blocked', hidden: true }, t('jobs.notifyBlocked'));
  el.append(btn, blocked);

  const draw = () => {
    const live = job.running();
    const perm = permission();
    // A blocked permission is said (at the same moment the button would appear) rather than offered.
    const offer = offerNotify({ elapsedMs: Date.now() - job.startedAt, supported: true, permission: perm === 'denied' ? 'default' : perm, optedIn: notifyOptIn });
    el.hidden = !live || !offer;
    btn.hidden = perm === 'denied';
    blocked.hidden = perm !== 'denied';
    // One label either way: a screen reader says "pressed" once, not a changed label as well.
    const on = notifyOptIn && perm === 'granted';
    btn.setAttribute('aria-pressed', String(on));
    btn.classList.toggle('is-on', on);
    return live;
  };

  btn.addEventListener('click', async () => {
    if (notifyOptIn && permission() === 'granted') {
      notifyOptIn = false;
      announce(t('jobs.notifyOff'));
      emit();
      return;
    }
    let perm = permission();
    if (perm === 'default') {
      setButtonBusy(btn, true);
      try {
        perm = await N.requestPermission();
      } catch {
        perm = permission();
      } finally {
        setButtonBusy(btn, false);
      }
    }
    notifyOptIn = perm === 'granted';
    // A prompt closed without an answer ('default') blocks nothing: only a refusal is called that.
    announce(t(notifyOptIn ? 'jobs.notifyReady' : perm === 'denied' ? 'jobs.notifyBlocked' : 'jobs.notifyOff'));
    emit();
  });

  // Appear at the 30 s mark and follow opt-in changes made in another panel; stop with the job.
  const onChange = () => {
    if (!el.isConnected && el.dataset.mounted) {
      listeners.delete(onChange);
      clearInterval(timer);
      return;
    }
    if (el.isConnected) el.dataset.mounted = '1';
    if (!draw()) {
      listeners.delete(onChange);
      clearInterval(timer);
    }
  };
  listeners.add(onChange);
  const timer = setInterval(onChange, 1000);
  draw();
  return el;
}

// "Delete all local data" also forgets the opt-in (it is never stored, like the Globalping consent).
state.subscribe(({ key }) => {
  if (key !== 'cleared' || !notifyOptIn) return;
  notifyOptIn = false;
  emit();
});
