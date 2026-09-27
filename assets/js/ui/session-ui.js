/**
 * ui/session-ui.js — the shell's two pieces of the page session (lib/session.js): the "current
 * target" chip in the header and the note over a tool's kept result ("Result from 14:02 · Run
 * again"). app.js builds both; views never use them directly.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Icon } from './components.js';
import { t, registerStrings, formatDateTime, localeTag } from '../i18n.js';
import { registrableDomain } from '../lib/domain.js';

registerStrings('en', {
  'session.target.group': 'Current target',
  'session.target.label': 'Target',
  'session.target.title': 'Current target: {value}. The tools you open next fill it in; nothing runs until you press their button. Kept in this tab only.',
  'session.target.clear': 'Clear the current target ({value})',
  'session.target.cleared': 'Current target cleared',
  'session.kept.from': 'Result from {time}',
  'session.kept.title': 'Kept from your last visit to this tool in this tab. It is not updated until you run it again.',
  'session.kept.dropped': 'The result from {time} was too large to keep',
  'session.kept.droppedTitle': 'This result was too large to keep in memory; its query is filled in again.',
  'session.kept.droppedBareTitle': 'This result was too large to keep in memory, and its query too long to fill in again.',
  'session.kept.rerun': 'Run again'
});

registerStrings('tr', {
  'session.target.group': 'Geçerli hedef',
  'session.target.label': 'Hedef',
  'session.target.title': 'Geçerli hedef: {value}. Sonra açtığınız araçlar bunu doldurur; düğmelerine basana kadar hiçbir şey çalışmaz. Yalnızca bu sekmede tutulur.',
  'session.target.clear': 'Geçerli hedefi temizle ({value})',
  'session.target.cleared': 'Geçerli hedef temizlendi',
  'session.kept.from': 'Önceki sonuç: {time}',
  'session.kept.title': 'Bu sekmede bu araca son girişinizden kalan sonuç. Yeniden çalıştırana kadar güncellenmez.',
  'session.kept.dropped': 'Önceki sonuç ({time}) bellekte tutulamayacak kadar büyüktü',
  'session.kept.droppedTitle': 'Bu sonuç bellekte tutulamayacak kadar büyüktü; sorgusu yeniden dolduruldu.',
  'session.kept.droppedBareTitle': 'Bu sonuç bellekte tutulamayacak kadar büyüktü, sorgusu da yeniden doldurulamayacak kadar uzundu.',
  'session.kept.rerun': 'Yeniden çalıştır'
});

/**
 * When a kept result finished, as the note says it: the time alone on the same day ('14:02'),
 * the date too otherwise.
 * @param {Date|number|string} at
 * @param {Date|number} [now=Date.now()]
 * @returns {string}
 */
export function keptTimeText(at, now = Date.now()) {
  const d = at instanceof Date ? at : new Date(at);
  if (!Number.isFinite(d.getTime())) return '—';
  const n = new Date(now instanceof Date ? now.getTime() : now);
  const sameDay = d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate();
  return sameDay ? new Intl.DateTimeFormat(localeTag(), { timeStyle: 'short' }).format(d) : formatDateTime(d);
}

/**
 * The chip's value in two parts, so that a long host name is cut in the middle: the labels below
 * the registrable domain (they give way first) and the registrable domain, which tells targets
 * apart. A domain or an IP address is all tail.
 * @param {{ value: string, kind: string }} target
 * @returns {[string, string]} [head, tail]; head + tail is the value
 */
export function chipParts(target) {
  const value = String(target.value);
  if (target.kind === 'host') {
    const reg = registrableDomain(value);
    if (reg && value.length > reg.length && value.endsWith(`.${reg}`)) return [value.slice(0, -reg.length), reg];
  }
  return ['', value];
}

/**
 * The header chip: the current target and a button that clears it. The full value is in its
 * text and title; a narrow chip cuts a host name in the middle ({@link chipParts}).
 * @param {{ target: { value: string, kind: string }, onClear: () => void }} opts
 * @returns {HTMLElement}
 */
export function TargetChip({ target, onClear }) {
  const [head, tail] = chipParts(target);
  return h('div', {
    class: 'target-chip',
    title: t('session.target.title', { value: target.value }),
    dataset: { kind: target.kind, role: 'target-chip' },
    attrs: { role: 'group', 'aria-label': t('session.target.group') }
  },
  Icon('target', { size: 14, className: 'target-chip-icon' }),
  h('span', { class: 'target-chip-label' }, t('session.target.label')),
  h('span', { class: 'target-chip-value mono' },
    head ? h('span', { class: 'target-chip-head' }, head) : null,
    h('span', { class: 'target-chip-tail' }, tail)),
  h('button', {
    type: 'button',
    class: 'target-chip-clear',
    title: t('session.target.clear', { value: target.value }),
    dataset: { action: 'target-clear' },
    attrs: { 'aria-label': t('session.target.clear', { value: target.value }) },
    on: { click: () => onClear() }
  }, Icon('x', { size: 13, strokeWidth: 2.2 })));
}

/**
 * The note over a tool's kept result: when it finished and, when the tool offers it, "Run again".
 * `dropped`: the result was too large to keep and only its query came back — or nothing did, when
 * there is no "Run again" (lib/session.js keptNote). `label`: the tool's
 * own translation key for the text (with `{time}`), in place of "Result from {time}". It is one
 * run of text (icon, words, link) that wraps like a sentence on a narrow screen. What the note
 * means (kept, not updated; too large to keep) is its title for a mouse and hidden text after the
 * words for a screen reader, which never gets a title of a plain span.
 * @param {{ at: Date, dropped?: boolean, label?: string|null, onRerun?: (() => void)|null, now?: number }} opts
 * @returns {HTMLElement}
 */
export function KeptNote({ at, dropped = false, label = null, onRerun = null, now = Date.now() }) {
  const time = keptTimeText(at, now);
  let title = 'session.kept.title';
  if (dropped) title = onRerun ? 'session.kept.droppedTitle' : 'session.kept.droppedBareTitle';
  return h('p', { class: 'kept-note', dataset: { kept: dropped ? 'dropped' : 'result' } },
    Icon('clock', { size: 14, className: 'kept-note-icon' }),
    h('span', { class: 'kept-note-text', title: t(title) },
      t(dropped ? 'session.kept.dropped' : label || 'session.kept.from', { time })),
    h('span', { class: 'sr-only' }, `. ${t(title)}`),
    onRerun ? ' ' : null,
    onRerun ? h('button', {
      type: 'button',
      class: 'link-btn kept-note-rerun',
      dataset: { action: 'kept-rerun' },
      on: { click: () => onRerun() }
    }, t('session.kept.rerun')) : null);
}
