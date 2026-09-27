/**
 * summary-button.js — "Copy summary" in a view's result header: the finished result as a few
 * lines of Markdown for a Jira ticket or a Slack thread (lib/summary.js), in the UI language,
 * with a small "Plain text" button next to it for tools that do not render Markdown. A browser
 * that blocks the clipboard gets the text in a dialog to copy by hand.
 *
 * The summary holds only what the result on screen shows; the tooltip says so, and says what a
 * summary takes from the server list where it takes something: SSL Targets names the servers
 * that need the certificate, IP Intel says how many of the addresses are in the list. The
 * permalink in it never carries inventory data or a file's contents (lib/summary.permalinkParams);
 * the tooltip of Zone File and Certificate, whose result is a file, says that too.
 * {@link resultPermalink} gives the print header (app.js) the same link: the result's, not the
 * route's, which a new run changes before its result replaces the one on screen.
 *
 * @example
 *   const summary = SummaryButton({
 *     kind: 'health',
 *     facts: () => ({ report }),
 *     // The link of the report on screen (never ctx.params: a new run changes them first).
 *     url: () => ctx.shareUrl(permalinkParams('health', { domain: report.domain, selectors }))
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
  'sum.btn.tip': 'Copies a short Markdown summary of this result for Jira or Slack. It holds only what this page shows — nothing from your server list — and a link to this page.',
  'sum.btn.tipFile': 'Copies a short Markdown summary of this result for Jira or Slack. It holds only what this page shows — nothing from your server list — and a link to this page without any file contents.',
  'sum.btn.tipInventory': 'Copies a short Markdown summary of this result for Jira or Slack. It names the servers from your list that need the certificate, as the Servers tab shows them; nothing else from your server list, and the link carries only the domains.',
  'sum.btn.tipCount': 'Copies a short Markdown summary of this result for Jira or Slack. It says how many of the addresses are in your server list, as this page does, but never a server’s name; the link leaves out private addresses and those of your servers.',
  'sum.btn.plainTip': 'Copy the same summary without Markdown formatting',
  'sum.copied': 'Summary copied as Markdown — paste it into Jira or Slack.',
  'sum.copiedPlain': 'Summary copied as plain text.',
  'sum.fallback.title': 'Copy the summary',
  'sum.fallback.hint': 'The browser did not allow copying. The text is selected: press Ctrl+C (⌘C on a Mac), or on a phone touch and hold it and choose Copy.',
  'sum.fallback.label': 'Summary text'
});

registerStrings('tr', {
  'sum.btn.label': 'Özet',
  'sum.btn.copy': 'Özeti kopyala',
  'sum.btn.plain': 'Düz metin',
  'sum.btn.tip': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Yalnızca bu sayfada görünenleri içerir — sunucu listenizden hiçbir şey içermez — ve bu sayfaya bir bağlantı ekler.',
  'sum.btn.tipFile': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Yalnızca bu sayfada görünenleri içerir — sunucu listenizden hiçbir şey içermez — ve bu sayfaya, dosya içeriği olmadan bir bağlantı ekler.',
  'sum.btn.tipInventory': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Listenizdeki sertifikaya ihtiyacı olan sunucuları, Sunucular sekmesinde göründüğü gibi adlarıyla içerir; sunucu listenizden başka bir şey içermez ve bağlantıda yalnızca alan adları bulunur.',
  'sum.btn.tipCount': 'Bu sonucun Jira ya da Slack için kısa bir Markdown özetini kopyalar. Adreslerden kaçının sunucu listenizde olduğunu bu sayfadaki gibi söyler, ama hiçbir sunucunun adını içermez; bağlantıda özel adresler ve sunucularınızın adresleri yer almaz.',
  'sum.btn.plainTip': 'Aynı özeti Markdown biçimlendirmesi olmadan kopyala',
  'sum.copied': 'Özet Markdown olarak kopyalandı — Jira ya da Slack’e yapıştırın.',
  'sum.copiedPlain': 'Özet düz metin olarak kopyalandı.',
  'sum.fallback.title': 'Özeti kopyalayın',
  'sum.fallback.hint': 'Tarayıcı kopyalamaya izin vermedi. Metin seçili: Ctrl+C’ye (Mac’te ⌘C) basın ya da telefonda metne basılı tutup Kopyala’yı seçin.',
  'sum.fallback.label': 'Özet metni'
});

/** Each SummaryButton's group element → the permalink of the result it copies ({@link resultPermalink}). */
const permalinks = new WeakMap();

/** Tooltip key per `inventory` option of {@link SummaryButton}. */
const TIPS = { names: 'sum.btn.tipInventory', count: 'sum.btn.tipCount' };
/** Views whose result comes from a file the user loaded: their tooltip says the link leaves it out. */
const FILE_KINDS = new Set(['zone', 'cert']);

/**
 * The permalink of the result shown under `root`: the link the first shown SummaryButton (not
 * inside a hidden element) with a result to copy would put in its summary, or null when there is
 * none. The print header uses it, so a paper copy links to what it shows.
 * @param {ParentNode} root
 * @returns {string|null}
 */
export function resultPermalink(root) {
  for (const el of root.querySelectorAll('.sum-actions')) {
    const link = permalinks.get(el);
    if (!link || el.closest('[hidden]')) continue;
    const url = link();
    if (url) return url;
  }
  return null;
}

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
 * @param {{ kind: string, facts: () => object|null, url?: string|(() => string|null)|null, inventory?: false|'names'|'count',
 *   disabled?: boolean, size?: 'sm'|'md', className?: string }} opts
 *   `kind`: a lib/summary SUMMARY_KINDS view id; `facts`: the builder's facts, read at click time
 *   (null while there is no finished result: nothing is copied); `url`: the permalink of that
 *   result (built from the result, not from the route); `inventory`: what the summary takes from
 *   the server list, which the tooltip says — 'names' (servers by name) or 'count' (how many
 *   addresses are in it); `disabled`: the initial state (the view calls setDisabled as its run
 *   starts and finishes)
 * @returns {{ el: HTMLElement, setDisabled(disabled: boolean): void, text(format?: 'markdown'|'text'): string }}
 */
export function SummaryButton({ kind, facts, url = null, inventory = false, disabled = false, size = 'sm', className = '' }) {
  const link = () => (typeof url === 'function' ? url() : url) || null;
  const text = (format = 'markdown') => {
    const f = facts();
    if (!f) return '';
    return renderSummary(buildSummary(kind, f, { t, lang: getLang(), url: link(), now: new Date() }), format);
  };
  const markdown = CopyButton(() => text('markdown'), {
    label: t('sum.btn.copy'),
    title: t(TIPS[inventory] || (FILE_KINDS.has(kind) ? 'sum.btn.tipFile' : 'sum.btn.tip')),
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
  permalinks.set(el, () => (facts() ? link() : null));
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
