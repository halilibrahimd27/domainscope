/**
 * ui/source-status.js — the UI of lib/sourcestatus.js: no silent dashes.
 *
 * - {@link NaMark}: "⚠ n/a" in a cell a failed source left empty, with the source and the reason
 *   as its tooltip and as screen-reader text ("RIPEstat: rate limited — try again in 5 min").
 * - {@link statusText}: that sentence, for notes and chips.
 * - {@link RetryButton}: the per-row / per-card Retry that asks those sources again.
 * - {@link SourceChip}: one status chip per service (the Subdomains source-chip pattern).
 *
 * Used by IP Intel, Domain Health (RDAP) and DNS Lookup (a failed query). Every string is
 * rendered as text.
 */

import { h } from './dom.js';
import { Button, Icon } from './components.js';
import { t, registerStrings, formatNumber } from '../i18n.js';

registerStrings('en', {
  'srcst.na': 'n/a',
  'srcst.naLabel': 'not available',
  'srcst.status': '{source}: {reason}',
  'srcst.retry': 'Retry',
  'srcst.retryTitle': 'Ask {sources} again',
  'srcst.retryFor': 'Retry {target} ({sources})',
  'srcst.source.ripestat': 'RIPEstat',
  'srcst.source.ripestat-geo': 'RIPEstat (location)',
  'srcst.source.ipwhois': 'ipwho.is',
  'srcst.source.ptr': 'Reverse DNS',
  'srcst.source.hackertarget': 'HackerTarget',
  'srcst.source.rdap': 'RDAP',
  'srcst.source.doh': 'DNS resolver',
  'srcst.reason.rate-limit-wait': 'rate limited — try again in {minutes} min',
  'srcst.reason.rate-limit-now': 'was rate limited — you can try again now',
  'srcst.reason.rate-limit-day': 'daily free quota used up — it resets within 24 hours',
  'srcst.reason.rate-limit-minutes': 'rate limited — try again in a few minutes',
  'srcst.reason.rate-limit': 'rate limited — try again later',
  'srcst.reason.timeout': 'no answer in time',
  'srcst.reason.network': 'could not be reached (offline, blocked, or no browser access)',
  'srcst.reason.unavailable': 'temporarily down',
  'srcst.reason.http-status': 'answered HTTP {status}',
  'srcst.reason.http': 'answered with an error',
  'srcst.reason.rcode': 'answered {rcode}',
  'srcst.reason.parse': 'sent an answer that could not be read',
  'srcst.reason.unknown': 'failed',
  'srcst.chip.ok': { one: '{count} answered', other: '{count} answered' },
  'srcst.chip.idle': 'not needed',
  'srcst.chip.pending': 'asking…',
  'srcst.chip.failed': { one: '{count} failed', other: '{count} failed' }
});

registerStrings('tr', {
  'srcst.na': 'alınamadı',
  'srcst.naLabel': 'alınamadı',
  'srcst.status': '{source}: {reason}',
  'srcst.retry': 'Yeniden dene',
  'srcst.retryTitle': '{sources} yeniden sorgulansın',
  'srcst.retryFor': 'Yeniden dene: {target} ({sources})',
  'srcst.source.ripestat': 'RIPEstat',
  'srcst.source.ripestat-geo': 'RIPEstat (konum)',
  'srcst.source.ipwhois': 'ipwho.is',
  'srcst.source.ptr': 'Ters DNS',
  'srcst.source.hackertarget': 'HackerTarget',
  'srcst.source.rdap': 'RDAP',
  'srcst.source.doh': 'DNS çözümleyici',
  'srcst.reason.rate-limit-wait': 'hız sınırı — {minutes} dk sonra tekrar deneyin',
  'srcst.reason.rate-limit-now': 'hız sınırına takılmıştı — şimdi tekrar deneyebilirsiniz',
  'srcst.reason.rate-limit-day': 'günlük ücretsiz kota doldu — 24 saat içinde sıfırlanır',
  'srcst.reason.rate-limit-minutes': 'hız sınırı — birkaç dakika sonra tekrar deneyin',
  'srcst.reason.rate-limit': 'hız sınırı — daha sonra tekrar deneyin',
  'srcst.reason.timeout': 'zamanında yanıt vermedi',
  'srcst.reason.network': 'ulaşılamadı (çevrimdışı, engellenmiş ya da tarayıcı erişimine kapalı)',
  'srcst.reason.unavailable': 'geçici olarak çalışmıyor',
  'srcst.reason.http-status': 'HTTP {status} yanıtı verdi',
  'srcst.reason.http': 'hata yanıtı verdi',
  'srcst.reason.rcode': '{rcode} yanıtı verdi',
  'srcst.reason.parse': 'okunamayan bir yanıt gönderdi',
  'srcst.reason.unknown': 'başarısız oldu',
  'srcst.chip.ok': '{count} yanıt',
  'srcst.chip.idle': 'gerekmedi',
  'srcst.chip.pending': 'soruluyor…',
  'srcst.chip.failed': '{count} başarısız'
});

/**
 * Display name of a source id ('ripestat', 'ptr', 'rdap', …).
 * @param {string} id
 * @returns {string}
 */
export function sourceName(id) {
  return t(`srcst.source.${id}`);
}

/**
 * The reason of a status alone ("rate limited — try again in 5 min").
 * @param {import('../lib/sourcestatus.js').SourceStatus} status
 * @returns {string}
 */
export function reasonText(status) {
  return t(`srcst.reason.${status.reason}`, status.params);
}

/**
 * "RIPEstat: rate limited — try again in 5 min" (`name` overrides the source's name, e.g. the
 * resolver that failed).
 * @param {import('../lib/sourcestatus.js').SourceStatus} status
 * @param {{ name?: string }} [opts]
 * @returns {string}
 */
export function statusText(status, { name = null } = {}) {
  return t('srcst.status', { source: name || sourceName(status.source), reason: reasonText(status) });
}

/**
 * "⚠ n/a" for a field that failed sources left empty. The tooltip and the screen-reader text
 * name each source and why it gave nothing, so the cell never reads as "no data".
 * @param {import('../lib/sourcestatus.js').SourceStatus[]} statuses primary source first
 * @param {{ className?: string }} [opts]
 * @returns {HTMLSpanElement}
 */
export function NaMark(statuses, { className = '' } = {}) {
  const lines = (statuses || []).map((s) => statusText(s));
  return h('span', {
    class: ['na-mark', className],
    title: lines.join('\n'),
    dataset: { na: (statuses || []).map((s) => s.source).join(' '), reason: statuses && statuses[0] ? statuses[0].reason : '' }
  },
  Icon('alert', { size: 12, strokeWidth: 2.2 }),
  h('span', { class: 'na-mark-text', attrs: { 'aria-hidden': 'true' } }, t('srcst.na')),
  h('span', { class: 'sr-only' }, `${t('srcst.naLabel')}: ${lines.join('; ')}`));
}

/**
 * The Retry of a row or card: asks `sources` again (only those). With `target` (the row's address,
 * the card's type) its accessible name says what it retries — "Retry 192.0.2.1 (RIPEstat,
 * ipwho.is)" — so a list of rows is not "Retry, Retry, Retry" to a screen reader.
 * @param {{ sources: string[], onClick: Function, target?: string|null, size?: 'sm'|'md', variant?: string,
 *   dataset?: object }} opts
 * @returns {HTMLButtonElement}
 */
export function RetryButton({ sources, onClick, target = null, size = 'sm', variant = 'ghost', dataset = {} }) {
  const names = [...new Set((sources || []).map(sourceName))].join(', ');
  return Button({
    label: t('srcst.retry'),
    icon: 'refresh',
    size,
    variant,
    title: t('srcst.retryTitle', { sources: names }),
    ariaLabel: target ? t('srcst.retryFor', { target, sources: names }) : null,
    dataset: { action: 'retry-source', sources: (sources || []).join(' '), ...dataset },
    onClick
  });
}

/**
 * A Retry on its way: a spinner and aria-busy, but still focusable (a disabled button would drop
 * the keyboard focus while the row or chip re-renders). A second click does nothing.
 * @param {HTMLButtonElement} btn
 */
export function setRetryBusy(btn) {
  btn.setAttribute('aria-busy', 'true');
  btn.setAttribute('aria-disabled', 'true');
  btn.classList.add('is-busy');
  if (!btn.querySelector('.spinner')) btn.prepend(h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }));
}

const CHIP_ICONS = { ok: 'check-circle', failed: 'alert', idle: 'minus-circle' };

/**
 * One service's status chip (lib/sourcestatus.js ipSourceChips): its name, how many rows it
 * answered or where it failed and why, with a Retry of the failed rows.
 * @param {import('../lib/sourcestatus.js').SourceChip} chip
 * @param {{ onRetry?: Function|null, busy?: boolean }} [opts]
 * @returns {HTMLElement}
 */
export function SourceChip(chip, { onRetry = null, busy = false } = {}) {
  let value;
  if (chip.state === 'failed') value = `${t('srcst.chip.failed', { count: formatNumber(chip.failed) })}${chip.status ? ` · ${reasonText(chip.status)}` : ''}`;
  else if (chip.state === 'pending') value = t('srcst.chip.pending');
  else if (chip.state === 'idle') value = t('srcst.chip.idle');
  else value = t('srcst.chip.ok', { count: chip.rows });
  const icon = CHIP_ICONS[chip.state] ? Icon(CHIP_ICONS[chip.state], { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } });
  const retry = chip.state === 'failed' && onRetry ? RetryButton({ sources: chip.sources, onClick: onRetry, dataset: { chip: chip.id } }) : null;
  if (retry && busy) setRetryBusy(retry);
  return h('span', { class: 'src-chip', dataset: { source: chip.id, state: chip.state } },
    icon,
    h('span', { class: 'src-chip-name' }, sourceName(chip.id)),
    h('span', { class: 'src-chip-value' }, value),
    retry);
}
