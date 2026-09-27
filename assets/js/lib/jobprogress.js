/**
 * jobprogress.js — how far a long job is, for the signals outside its view.
 *
 * A Subdomains / SSL Targets scan or a Bulk Resolve run takes one to several minutes, and the
 * user is often in another view or another tab meanwhile. ui/jobs.js shows the progress as a
 * "(62%)" prefix of the tab title, a ring on the running view's navigation entry and a badge on
 * the favicon, and can send a desktop notification when a job over {@link LONG_JOB_MS} ends.
 * This module is the arithmetic and the markup behind it: the overall fraction of a scan (its
 * stages weighted by how long they usually take) or of a bulk run, the combined progress of
 * several jobs, the badged favicon and the notification decision.
 *
 * Pure: no DOM, clock, storage or i18n.
 */

/** A job that has run this long may end with a desktop notification (opt-in, ui/jobs.js). */
export const LONG_JOB_MS = 30000;

/**
 * Weight of each lib/scanner.js stage in the overall progress of a scan: roughly its share of
 * the time a default (Smart) scan spends there. DNS-record mining runs alongside the passive
 * sources, so it has no weight of its own; 'done' is the end. Skipped stages drop out.
 * (tests/js/jobprogress.test.js keeps the keys equal to scanner.SCAN_STAGES.)
 */
export const SCAN_STAGE_WEIGHTS = Object.freeze({
  sources: 10, mining: 0, wildcard: 5, bruteforce: 45, permutations: 20, resolve: 15, hints: 5, done: 0
});

/**
 * The most of its weight a stage counts for while it is still active (or was stopped there): a
 * stage whose counter is complete can keep running (the brute-force stage waits for the passive
 * sources before it ends), and a stage that reads as complete while the job does not move on
 * looks like a hang.
 */
export const ACTIVE_STAGE_CAP = 0.95;

const clamp01 = (x) => Math.min(1, Math.max(0, x));

/**
 * Overall fraction of a running scan (a Subdomains or SSL Targets run: `stages` as recorded by
 * their applyStage, `progress` the current stage's done / total). A stage counts fully once it is
 * done; while active, for its done / total up to {@link ACTIVE_STAGE_CAP}.
 * @param {{ stages?: Record<string, { state: string }>, progress?: { stage: string|null, done: number, total: number } }} run
 * @returns {number|null} 0…1, or null before the first stage (indeterminate)
 */
export function scanFraction(run) {
  const stages = (run && run.stages) || {};
  const p = (run && run.progress) || {};
  if (stages.done && stages.done.state === 'done') return 1;
  let total = 0;
  let done = 0;
  let started = false;
  for (const [stage, weight] of Object.entries(SCAN_STAGE_WEIGHTS)) {
    const state = stages[stage] ? stages[stage].state : 'pending';
    if (state !== 'pending') started = true;
    if (!weight || state === 'skipped') continue;
    total += weight;
    if (state === 'done') done += weight;
    else if (state === 'active' || state === 'stopped') {
      const part = p.stage === stage && Number(p.total) > 0 ? clamp01(Number(p.done) / Number(p.total)) : 0;
      done += weight * Math.min(ACTIVE_STAGE_CAP, part);
    }
  }
  return started && total ? clamp01(done / total) : null;
}

/**
 * Overall fraction of a Bulk Resolve job: the names resolved, and — when PTR / ASN lookups were
 * asked for — a quarter for the addresses looked up (their total grows while names resolve).
 * @param {{ names?: string[], done?: number, ipTotal?: number, ipDone?: number, options?: { ptr?: boolean, asn?: boolean } }} job
 * @returns {number|null} 0…1, or null without names
 */
export function bulkFraction(job) {
  const n = job && Array.isArray(job.names) ? job.names.length : 0;
  if (!n) return null;
  const resolved = clamp01((Number(job.done) || 0) / n);
  const enrich = !!(job.options && (job.options.ptr || job.options.asn));
  if (!enrich) return resolved;
  const ipTotal = Number(job.ipTotal) || 0;
  const looked = ipTotal ? clamp01((Number(job.ipDone) || 0) / ipTotal) : resolved === 1 ? 1 : 0;
  return 0.75 * resolved + 0.25 * looked * resolved;
}

/**
 * The next progress a job shows: never below the last one. A stage's total can grow while it
 * runs (the scan's recursive round adds permutation candidates, a bulk run finds more addresses
 * to look up), and a signal that runs backwards reads as a fault.
 * @param {number|null} prev what the job shows now (null: nothing yet)
 * @param {number|null} next the new fraction (null: not known)
 * @returns {number|null}
 */
export function advance(prev, next) {
  if (!Number.isFinite(next)) return Number.isFinite(prev) ? prev : null;
  return Number.isFinite(prev) ? Math.max(prev, clamp01(next)) : clamp01(next);
}

/**
 * The progress several running jobs show together: the least advanced determinate one (the
 * signal says "not everything is done yet"), or null when none is determinate.
 * @param {Array<{ fraction: number|null }>} jobs
 * @returns {{ count: number, fraction: number|null }}
 */
export function combineJobs(jobs) {
  const list = Array.isArray(jobs) ? jobs.filter(Boolean) : [];
  const known = list.map((j) => j.fraction).filter((f) => Number.isFinite(f));
  return { count: list.length, fraction: known.length ? clamp01(Math.min(...known)) : null };
}

/**
 * Whole percent of a running job: never 100 while it runs (the title loses its prefix when the
 * job ends), null when indeterminate.
 * @param {number|null} fraction
 * @returns {number|null}
 */
export function percentOf(fraction) {
  return Number.isFinite(fraction) ? Math.min(99, Math.floor(clamp01(fraction) * 100)) : null;
}

/**
 * The tab title while jobs run: `(62%) Subdomains · DomainScope`.
 * @param {string} base the page's own title
 * @param {string|null} label the formatted percent ('62%', '%62'), or null for '…' (indeterminate)
 * @returns {string}
 */
export function progressTitle(base, label) {
  return `(${label || '…'}) ${String(base ?? '')}`;
}

/**
 * The favicon steps a badge moves in: every 5 % (10 % with reduced motion, so the tab strip
 * changes less often), null for indeterminate.
 * @param {number|null} fraction
 * @param {{ reducedMotion?: boolean }} [opts]
 * @returns {number|null} 0…0.95 (never full while running)
 */
export function faviconStep(fraction, { reducedMotion = false } = {}) {
  const pct = percentOf(fraction);
  if (pct === null) return null;
  const step = reducedMotion ? 10 : 5;
  return (Math.floor(pct / step) * step) / 100;
}

/**
 * The brand icon (favicon.svg, kept equal to the file by tests/js/jobprogress.test.js), so a
 * badged copy can be made without a request.
 */
export const BRAND_ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">'
  + '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#4338ca"/></linearGradient></defs>'
  + '<rect width="32" height="32" rx="7.5" fill="url(#bg)"/>'
  + '<g fill="none" stroke="#fff" stroke-linecap="round" stroke-linejoin="round">'
  + '<circle cx="14" cy="14" r="7.6" stroke-width="2.4"/>'
  + '<path d="M6.6 14h14.8M14 6.5c2 2.1 3 4.6 3 7.5s-1 5.4-3 7.5c-2-2.1-3-4.6-3-7.5s1-5.4 3-7.5z" stroke-width="1.4" opacity="0.85"/>'
  + '<path d="M19.8 19.8l5.4 5.4" stroke-width="3.2"/>'
  + '</g></svg>';

/**
 * The brand icon with a progress badge in its lower right corner: a white disc with a green pie
 * for `fraction` of a circle (a pie still reads at 16 px, a thin arc does not), or a solid dot
 * when the progress is not known.
 * @param {number|null} fraction 0…1 (use {@link faviconStep}), null = indeterminate
 * @param {{ svg?: string }} [opts] base icon (default {@link BRAND_ICON_SVG})
 * @returns {string} SVG markup
 */
export function badgedIcon(fraction, { svg = BRAND_ICON_SVG } = {}) {
  const parts = ['<g data-job-badge="1"><circle cx="23" cy="23" r="9" fill="#ffffff" stroke="#1e293b" stroke-opacity="0.3"/>'];
  if (Number.isFinite(fraction)) {
    const p = Math.round(clamp01(fraction) * 100);
    // A stroke as wide as twice its radius draws a pie.
    parts.push('<circle cx="23" cy="23" r="3.6" fill="none" stroke="#cbd5e1" stroke-width="7.2"/>');
    if (p > 0) {
      parts.push(`<circle cx="23" cy="23" r="3.6" fill="none" stroke="#16a34a" stroke-width="7.2" pathLength="100" stroke-dasharray="${p} 100" transform="rotate(-90 23 23)"/>`);
    }
  } else {
    parts.push('<circle cx="23" cy="23" r="5" fill="#2563eb"/>');
  }
  parts.push('</g>');
  const base = String(svg);
  const end = base.lastIndexOf('</svg>');
  return end === -1 ? base : `${base.slice(0, end)}${parts.join('')}${base.slice(end)}`;
}

/**
 * A `data:` URL of SVG markup (the page CSP allows `img-src data:`, which covers the favicon).
 * @param {string} svg
 * @returns {string}
 */
export function svgDataUrl(svg) {
  return `data:image/svg+xml,${encodeURIComponent(String(svg))}`;
}

/**
 * Can the page show a notification itself (`new Notification()`)? Chromium on Android (Chrome,
 * Samsung Internet, Edge, Opera: `navigator.userAgentData.mobile`) has the API and its permission
 * prompt but turns the constructor off ("Illegal constructor. Use
 * ServiceWorkerRegistration.showNotification() instead"). This app has no service worker, so there
 * "Notify me when done" would ask for a permission it can never use. A Chromium without
 * `userAgentData` (older, or a page that is not a secure context) is recognised by its user agent.
 * @param {{ api: unknown, userAgentData?: { mobile?: boolean }|null, userAgent?: string }} env
 * @returns {boolean}
 */
export function pageNotifications({ api, userAgentData = null, userAgent = '' }) {
  if (typeof api !== 'function') return false;
  if (userAgentData && typeof userAgentData.mobile === 'boolean') return !userAgentData.mobile;
  return !/\bAndroid\b.*\bChrome\/\d/.test(String(userAgent || ''));
}

/**
 * May the view offer "Notify me when done" for a running job? Once it has run {@link LONG_JOB_MS}
 * (or the page session already opted in), where the browser has notifications and has not
 * blocked them for the site.
 * @param {{ elapsedMs: number, supported: boolean, permission: string|null, optedIn?: boolean }} s
 * @returns {boolean}
 */
export function offerNotify({ elapsedMs, supported, permission, optedIn = false }) {
  if (!supported || permission === 'denied') return false;
  return optedIn || Number(elapsedMs) >= LONG_JOB_MS;
}

/**
 * Should a job that just ended send a desktop notification? Only when the page session opted in,
 * the permission is granted, the job finished or failed (a cancel was the user's own doing), ran
 * at least {@link LONG_JOB_MS}, and the user is not already looking at it (its view, in a visible,
 * focused tab).
 * @param {{ optedIn: boolean, permission: string|null, status: string, durationMs: number, watching: boolean }} s
 * @returns {boolean}
 */
export function shouldNotify({ optedIn, permission, status, durationMs, watching }) {
  return !!optedIn && permission === 'granted' && (status === 'done' || status === 'error')
    && Number(durationMs) >= LONG_JOB_MS && !watching;
}
