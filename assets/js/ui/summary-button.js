/**
 * summary-button.js — "Copy summary" in a view's result header: the finished result as a few
 * lines of Markdown for a Jira ticket or a Slack thread (lib/summary.js), in the UI language,
 * with a small "Plain text" button next to it for tools that do not render Markdown. A browser
 * that blocks the clipboard gets the text in a dialog to copy by hand.
 *
 * The summary holds only what the result on screen shows; the tooltip says so, and says it for
 * the one view whose summary names inventory servers (SSL Targets: the servers that need the
 * certificate). The permalink in it never carries inventory data or a file's contents
 * (lib/summary.permalinkParams).
 *
 * @example
 *   const summary = SummaryButton({
 *     kind: 'health',
 *     facts: () => (current && current.report ? { report: current.report } : null),
 *     url: () => ctx.shareUrl(permalinkParams('health', ctx.params))
 *   });
 *   actions.append(summary.el);   // summary.setDisabled(true) while a run is going
 */

import { h } from './dom.js';
import { CopyButton, Modal } from './components.js';
import { t, getLang, registerStrings } from '../i18n.js';
import { SUMMARY_I18N, buildSummary, renderSummary } from '../lib/summary.js';

registerStrings('en', SUMMARY_I18N.en);
registerStrings('tr', SUMMARY_I18N.tr);

registerStrings('en', {
  'sum.btn.label': 'Summary',
  'sum.btn.copy': 'Copy summary',
  'sum.btn.plain': 'Plain text',
  'sum.btn.tip': 'Copies a short Markdown summary of this result for Jira or Slack. It holds only what this page shows — nothing from your server list — and a link to this page without any file contents.',
  'sum.btn.tipInventory': 'Copies a short Markdown summary of this result for Jira or Slack. It names the servers from your list that need the certificate, as the Servers tab shows them; nothing else from your server list, and the link carries only the domains.',
  'sum.btn.plainTip': 'Copy the same summary without Markdown formatting',
  'sum.copied': 'Summary copied as Markdown — paste it into Jira or Slack.',
  'sum.copiedPlain': 'Summary copied as plain text.',
  'sum.fallback.title': 'Copy the summary',
  'sum.fallback.hint': 'The browser did not allow copying. The text is selected: press Ctrl+C (⌘C on a Mac).',
  'sum.fallback.label': 'Summary text'
});

registerStrings('tr', {
  'sum.btn.label': 'Özet',
  'sum.btn.copy': 'Özeti kopyala',
  'sum.btn.plain': 'Düz metin',
  'sum.btn.tip': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Yalnızca bu sayfada görünenleri içerir — sunucu listenizden hiçbir şey içermez — ve bu sayfaya, dosya içeriği olmadan bir bağlantı ekler.',
  'sum.btn.tipInventory': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Listenizdeki sertifikaya ihtiyacı olan sunucuları, Sunucular sekmesinde göründüğü gibi adlarıyla içerir; sunucu listenizden başka bir şey içermez ve bağlantıda yalnızca alan adları bulunur.',
  'sum.btn.plainTip': 'Aynı özeti Markdown biçimlendirmesi olmadan kopyala',
  'sum.copied': 'Özet Markdown olarak kopyalandı — Jira ya da Slack’e yapıştırın.',
  'sum.copiedPlain': 'Özet düz metin olarak kopyalandı.',
  'sum.fallback.title': 'Özeti kopyalayın',
  'sum.fallback.hint': 'Tarayıcı kopyalamaya izin vermedi. Metin seçili: Ctrl+C’ye (Mac’te ⌘C) basın.',
  'sum.fallback.label': 'Özet metni'
});

/**
 * The summary in a dialog, selected, when the clipboard is blocked (a permissions policy, an
 * insecure context, a browser without execCommand).
 * @param {string} text
 */
export function showSummaryFallback(text) {
  const area = h('textarea', {
    class: 'textarea mono sum-fallback-text',
    value: text,
    attrs: { readonly: true, rows: Math.min(14, Math.max(4, text.split('\n').length + 1)), wrap: 'soft', 'aria-label': t('sum.fallback.label'), spellcheck: 'false' }
  });
  const modal = Modal({
    title: t('sum.fallback.title'),
    size: 'md',
    className: 'sum-fallback',
    content: h('div', { class: 'stack-sm' }, h('p', { class: 'text-sm' }, t('sum.fallback.hint')), area),
    actions: [{ label: t('common.close'), variant: 'primary', value: null }]
  });
  modal.open();
  area.select();
}

/**
 * "Copy summary" (Markdown) + "Plain text" for one view's result.
 * @param {{ kind: string, facts: () => object|null, url?: string|(() => string|null)|null, inventory?: boolean,
 *   disabled?: boolean, size?: 'sm'|'md', className?: string }} opts
 *   `kind`: a lib/summary SUMMARY_KINDS view id; `facts`: the builder's facts, read at click time
 *   (null while there is no finished result: nothing is copied); `url`: the permalink;
 *   `inventory`: the summary names inventory servers (the tooltip says so); `disabled`: the
 *   initial state (the view calls setDisabled as its run starts and finishes)
 * @returns {{ el: HTMLElement, setDisabled(disabled: boolean): void, text(format?: 'markdown'|'text'): string }}
 */
export function SummaryButton({ kind, facts, url = null, inventory = false, disabled = false, size = 'sm', className = '' }) {
  const text = (format = 'markdown') => {
    const f = facts();
    if (!f) return '';
    const link = typeof url === 'function' ? url() : url;
    return renderSummary(buildSummary(kind, f, { t, lang: getLang(), url: link || null, now: new Date() }), format);
  };
  const markdown = CopyButton(() => text('markdown'), {
    label: t('sum.btn.copy'),
    title: t(inventory ? 'sum.btn.tipInventory' : 'sum.btn.tip'),
    size,
    variant: 'secondary',
    toastOnCopy: t('sum.copied'),
    onFail: showSummaryFallback,
    className: 'sum-copy'
  });
  markdown.dataset.action = 'copy-summary';
  const plain = CopyButton(() => text('text'), {
    label: t('sum.btn.plain'),
    title: t('sum.btn.plainTip'),
    size,
    variant: 'ghost',
    toastOnCopy: t('sum.copiedPlain'),
    onFail: showSummaryFallback,
    className: 'sum-copy-plain'
  });
  plain.dataset.action = 'copy-summary-text';
  const el = h('div', { class: ['sum-actions', className], dataset: { summary: kind }, attrs: { role: 'group', 'aria-label': t('sum.btn.label') } }, markdown, plain);
  const api = {
    el,
    setDisabled(disabled) {
      markdown.disabled = !!disabled;
      plain.disabled = !!disabled;
    },
    text
  };
  api.setDisabled(disabled);
  return api;
}
