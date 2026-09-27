/**
 * ui/globalping-gate.js — the page-session gate every Globalping send of the app goes through
 * (SSL Targets › Verify, Domain Health › MTA-STS policy).
 *
 * - Consent is kept per purpose ('verify', 'mta-sts'): each feature's first send in a page
 *   session shows a dialog with that feature's own privacy text, because each sends different
 *   data. Consent is never stored; "Delete all local data" resets it.
 * - The latest quota reading is shared ({@link sharedQuota} / {@link noteQuota}): the anonymous
 *   quota is per IP address, so a probe spent in one view shows in the other.
 * - {@link gateProbes} is the flow of a one-click feature with a known, small cost: the shared
 *   client (ctx.getGlobalping), one free /limits read, nothing sent when the quota cannot cover
 *   the probes, the consent + cost dialog when needed; the caller then sends. SSL Targets ›
 *   Verify keeps its own batch flow (ui/verify-panel.js) on the same consent and quota.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Modal } from './components.js';
import { t, registerStrings, formatNumber, formatRelative } from '../i18n.js';
import { state } from '../state.js';
import { errorKind } from '../lib/util.js';
import { GP_LIMITS, isMeasurementId } from '../lib/globalping.js';

/** The only verified public link to a measurement: its raw JSON on the API. */
export const GP_MEASUREMENT_URL = 'https://api.globalping.io/v1/measurements/';

registerStrings('en', {
  'gp.confirm.title': 'Send to Globalping?',
  'gp.confirm.cost': {
    one: 'Cost: {probes} probe of the {remaining} left this hour (resets {when}).',
    other: 'Cost: {probes} probes of the {remaining} left this hour (resets {when}).'
  },
  'gp.confirm.go': 'Send and check',
  'gp.quotaUnknown': 'Globalping: {limit} probes per hour without an account, shared by everyone behind your IP address.'
});

registerStrings('tr', {
  'gp.confirm.title': 'Globalping’e gönderilsin mi?',
  'gp.confirm.cost': 'Maliyet: bu saat kalan {remaining} ölçümden {probes} tanesi ({when} sıfırlanır).',
  'gp.confirm.go': 'Gönder ve kontrol et',
  'gp.quotaUnknown': 'Globalping: hesapsız saatte {limit} ölçüm; IP adresinizin arkasındaki herkesle ortak.'
});

/** Purposes whose consent was given in this page session (never stored). */
const consents = new Set();
/** The latest merged Globalping quota (the client is shared, so is the quota). */
let lastQuota = null;

state.subscribe(({ key }) => {
  if (key !== 'cleared') return;
  consents.clear();
  lastQuota = null;
});

/**
 * Whether this page session already consented to sends of `purpose`.
 * @param {string} purpose
 * @returns {boolean}
 */
export function hasConsent(purpose) {
  return consents.has(purpose);
}

/**
 * Record the consent for `purpose` (after its dialog was confirmed). Page session only.
 * @param {string} purpose
 */
export function grantConsent(purpose) {
  consents.add(purpose);
}

/** @returns {object|null} the latest quota reading (a GpQuota) any view took */
export function sharedQuota() {
  return lastQuota;
}

/**
 * Keep a new quota reading for every view (a null reading is ignored).
 * @param {object|null} q GpQuota
 */
export function noteQuota(q) {
  if (q) lastQuota = q;
}

/**
 * The last quota reading while its window is open; null once `resetAt` has passed (a stale
 * "0 left · resets 1 hour ago" must not show in a later scan).
 * @param {object|null} q GpQuota
 * @param {number} [now]
 * @returns {object|null}
 */
export function liveQuota(q, now = Date.now()) {
  if (!q) return null;
  const reset = q.resetAt ? new Date(q.resetAt).getTime() : NaN;
  return Number.isFinite(reset) && reset <= now ? null : q;
}

/**
 * The public link to a measurement, or null for anything that is not a measurement id (nothing
 * else ever shapes the link).
 * @param {string} id
 * @returns {string|null}
 */
export function measurementUrl(id) {
  return isMeasurementId(id) ? GP_MEASUREMENT_URL + encodeURIComponent(id) : null;
}

/**
 * "in 42 minutes" for a quota reset; an unopened window resets an hour after the first probe.
 * A reset already past reads "now", never "… ago".
 * @param {Date|string|null} resetAt
 * @param {number} [now]
 * @returns {string}
 */
export function whenText(resetAt, now = Date.now()) {
  const d = resetAt instanceof Date ? resetAt : (resetAt ? new Date(resetAt) : null);
  return d && Number.isFinite(d.getTime()) ? formatRelative(Math.max(d.getTime(), now), now) : formatRelative(now + 3600000, now);
}

/**
 * The consent + cost dialog of a one-click send: the purpose's privacy text, the cost and, when
 * /limits could not be read, the hourly limit. An aborted launch closes it unanswered.
 * @param {{ privacy: string|Node, probes: number, remaining: number, limit: number, resetAt: Date|null,
 *   unknown: boolean, signal?: AbortSignal|null, className?: string }} opts
 * @returns {Promise<boolean>}
 */
export async function confirmProbes({ privacy, probes, remaining, limit, resetAt, unknown, signal = null, className = '' }) {
  if (signal && signal.aborted) return false;
  const modal = Modal({
    title: t('gp.confirm.title'),
    size: 'md',
    className: ['gp-confirm', className].filter(Boolean).join(' '),
    content: h('div', { class: 'stack-sm' },
      h('p', { dataset: { gp: 'confirm-privacy' } }, privacy),
      h('p', { dataset: { gp: 'confirm-cost', probes: String(probes) } },
        t('gp.confirm.cost', { count: probes, probes: formatNumber(probes), remaining: formatNumber(remaining), when: whenText(resetAt) })),
      unknown ? h('p', { class: 'muted text-sm', dataset: { gp: 'confirm-quota-unknown' } }, t('gp.quotaUnknown', { limit: formatNumber(limit) })) : null),
    actions: [
      { label: t('common.cancel'), value: false, variant: 'secondary' },
      { label: t('gp.confirm.go'), value: true, variant: 'primary', icon: 'globe', autofocus: true }
    ]
  });
  const onAbort = () => modal.close(null);
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  try {
    const value = await modal.open();
    return value === true && !(signal && signal.aborted);
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Before a one-click send of `probes` probes: the shared client, one free /limits read, then
 * the consent + cost dialog on the purpose's first send of the page session. Sends nothing
 * itself; on 'go' the caller creates the measurement (and passes its quota to {@link noteQuota}).
 *
 * - 'quota': the hour's remaining probes cannot cover `probes` (resetAt from the reading);
 * - 'cancelled': the dialog was cancelled or `signal` aborted;
 * - 'unreachable': the client could not be loaded (a failed /limits read is not fatal: the last
 *   reading of the open window, else the anonymous hourly limit, stands in, and the dialog says so).
 *
 * @param {{ getGlobalping: () => Promise<object> }} ctx
 * @param {{ purpose: string, probes?: number, privacy: string|Node, signal?: AbortSignal,
 *   confirm?: (opts: object) => Promise<boolean>, now?: () => number, className?: string }} opts
 *   `confirm` replaces the dialog (tests)
 * @returns {Promise<{ status: 'go', client: object, quota: object|null }|{ status: 'quota', resetAt: Date|null }
 *   |{ status: 'cancelled' }|{ status: 'unreachable', error: unknown }>}
 */
export async function gateProbes(ctx, { purpose, probes = 1, privacy, signal = undefined, confirm = confirmProbes, now = () => Date.now(), className = '' }) {
  const cancelled = { status: 'cancelled' };
  let client;
  try {
    client = await ctx.getGlobalping();
  } catch (err) {
    return signal && signal.aborted ? cancelled : { status: 'unreachable', error: err };
  }
  if (signal && signal.aborted) return cancelled;
  let q = null;
  let unknown = false;
  try {
    q = await client.limits({ signal });
  } catch (err) {
    if ((signal && signal.aborted) || errorKind(err) === 'abort') return cancelled;
    unknown = true;
    q = liveQuota(client.quota, now());
  }
  if (signal && signal.aborted) return cancelled;
  noteQuota(q);
  const limit = q && Number.isFinite(q.limit) ? q.limit : GP_LIMITS.anonymousPerHour;
  const remaining = q && Number.isFinite(q.remaining) ? Math.max(0, q.remaining) : limit;
  if (remaining < probes) return { status: 'quota', resetAt: q ? q.resetAt : null };
  if (!consents.has(purpose)) {
    const ok = await confirm({ privacy, probes, remaining, limit, resetAt: q ? q.resetAt : null, unknown, signal, className });
    if (!ok || (signal && signal.aborted)) return cancelled;
    consents.add(purpose);
  }
  return { status: 'go', client, quota: q };
}
