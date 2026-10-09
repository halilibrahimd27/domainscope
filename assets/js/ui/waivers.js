/**
 * ui/waivers.js — accepted risks in the page (lib/waivers.js), loaded on first use: the dialog that
 * accepts a risk or marks a known certificate (a reason, an owner and an end date), and the store
 * helpers that keep the waivers in the active workspace's `waivers` part (state.js), so the
 * hand-over file carries them and the Workspaces dialog exports them as waivers.json — the
 * headless runner's `--waivers` input. Domain Health, the Domain portfolio's policy matrix and CT
 * tab open it; nothing here reaches the network.
 */

import { h } from './dom.js';
import { KeyValueList, Modal, textInput, textarea } from './components.js';
import { registerStrings, t } from '../i18n.js';
import {
  WAIVERS_I18N, WAIVER_REASON_MAX, WAIVER_OWNER_MAX, WAIVER_MAX_DAYS, WAIVERS_MAX, WAIVERS_MAX_CHARS, WaiverError, addWaiver, defaultExpiry,
  maxExpiry, readWaivers, removeWaiver, utcDay, validateWaiver, waiversPartText
} from '../lib/waivers.js';
import { state as stateSingleton } from '../state.js';

registerStrings('en', WAIVERS_I18N.en);
registerStrings('tr', WAIVERS_I18N.tr);

/**
 * The words of a waiver error code (lib/waivers.js WAIVER_ERRORS).
 * @param {string} code
 * @returns {string}
 */
export function waiverErrorText(code) {
  return t(`wvr.err.${code}`, { max: code === 'owner' ? WAIVER_OWNER_MAX : code === 'reason' ? WAIVER_REASON_MAX : WAIVERS_MAX,
    size: `${Math.round(WAIVERS_MAX_CHARS / 1024)} KB`, days: WAIVER_MAX_DAYS });
}

/**
 * The active workspace's waivers, read now.
 * @param {object} [state] state.js (the page's by default)
 * @returns {object[]}
 */
export function currentWaivers(state = stateSingleton) {
  return readWaivers(state.workspaceData('waivers'), { now: Date.now() });
}

/**
 * Keep a list as the active workspace's waivers.
 * @param {object[]} list
 * @param {object} [state]
 * @returns {Promise<boolean>} written to the browser's storage (false: this page only)
 * @throws {WaiverError} 'too-large' / 'too-many': nothing is saved
 */
export async function saveWaivers(list, state = stateSingleton) {
  return state.setWorkspaceData('waivers', waiversPartText(list));
}

/**
 * Accept a risk (or mark a known certificate): the waiver is checked, added (replacing the one of
 * the same item) and kept in the workspace.
 * @param {{ kind: string, domain: string, ref: string, reason: string, owner?: string, expires: string }} input
 * @param {object} [state]
 * @returns {Promise<{ waiver: object, persisted: boolean }>}
 * @throws {WaiverError}
 */
export async function acceptRisk(input, state = stateSingleton) {
  const { list, waiver } = addWaiver(currentWaivers(state), input, { now: Date.now() });
  const persisted = await saveWaivers(list, state);
  return { waiver, persisted };
}

/**
 * Remove a waiver from the workspace: its item counts again.
 * @param {string} id
 * @param {object} [state]
 * @returns {Promise<boolean>} written to the browser's storage
 */
export async function removeRisk(id, state = stateSingleton) {
  return saveWaivers(removeWaiver(currentWaivers(state), id), state);
}

/**
 * The dialog that accepts a risk or marks a known certificate. Resolves with the waiver's input
 * (checked: a reason, an optional owner, an end date from today to {@link WAIVER_MAX_DAYS} days
 * ahead), or null when it is closed without saving.
 * @param {{ kind: 'finding'|'rule'|'cert', domain: string, ref: string, subject: string|Node, existing?: object|null }} opts
 *   `subject`: what is accepted, as the view names it (a finding's title, a rule, a certificate's names);
 *   `existing`: the waiver it replaces (its values are offered)
 * @returns {Promise<object|null>}
 */
export function openWaiverDialog({ kind, domain, ref, subject, existing = null }) {
  const now = Date.now();
  const cert = kind === 'cert';
  const reason = textarea({
    label: t('wvr.dialog.reason'),
    value: existing ? existing.reason : cert ? t('wvr.dialog.reasonCert') : '',
    rows: 2,
    mono: false,
    wrap: true,
    required: true,
    hint: t('wvr.dialog.reasonHint', { max: WAIVER_REASON_MAX }),
    attrs: { maxlength: String(WAIVER_REASON_MAX), 'data-role': 'wvr-reason' }
  });
  const owner = textInput({
    label: t('wvr.dialog.owner'),
    value: existing ? existing.owner : '',
    optional: true,
    hint: t('wvr.dialog.ownerHint', { max: WAIVER_OWNER_MAX }),
    attrs: { maxlength: String(WAIVER_OWNER_MAX), 'data-role': 'wvr-owner', autocomplete: 'off' }
  });
  const expires = textInput({
    label: t('wvr.dialog.expires'),
    type: 'date',
    value: existing && existing.expires >= utcDay(now) ? existing.expires : defaultExpiry(now),
    required: true,
    hint: t('wvr.dialog.expiresHint', { days: WAIVER_MAX_DAYS }),
    attrs: { min: utcDay(now), max: maxExpiry(now), 'data-role': 'wvr-expires' }
  });
  const content = h('div', { class: 'stack wvr-dialog', dataset: { kind } },
    h('p', { class: 'muted text-sm' }, t(cert ? 'wvr.dialog.introCert' : 'wvr.dialog.intro')),
    KeyValueList([
      { key: t('wvr.dialog.what'), value: h('div', { class: 'stack-sm' }, h('div', null, subject), h('div', { class: 'mono text-xs muted', dataset: { role: 'wvr-ref' } }, ref)) },
      { key: t('wvr.dialog.domain'), value: domain, mono: true }
    ], { className: 'wvr-what' }),
    reason.el, owner.el, expires.el);
  let result = null;
  const modal = Modal({
    title: t(cert ? 'wvr.dialog.titleCert' : 'wvr.dialog.title'),
    size: 'sm',
    className: 'wvr-modal',
    content,
    actions: [
      { label: t('common.cancel'), value: null, variant: 'secondary', dataset: { action: 'wvr-cancel' } },
      {
        label: t(cert ? 'wvr.dialog.saveCert' : 'wvr.dialog.save'),
        value: true,
        variant: 'primary',
        icon: 'shield',
        dataset: { action: 'wvr-save' },
        onClick: () => {
          for (const f of [reason, owner, expires]) f.setError(null);
          const input = { kind, domain, ref, reason: reason.value, owner: owner.value, expires: expires.value };
          const { error } = validateWaiver(input, { now });
          const late = !error && expires.value < utcDay(now);
          if (error || late) {
            const code = late ? 'expires' : error.code;
            const field = code === 'reason' ? reason : code === 'owner' ? owner : expires;
            field.setError(waiverErrorText(code));
            field.focus();
            return false;
          }
          result = input;
          return true;
        }
      }
    ]
  });
  return modal.open().then((value) => (value === true ? result : null));
}

export { WaiverError };
