/**
 * report.js — the customer report panel, opened by the "Report" button of the Domain overview and
 * Domain Health (ui/report-button.js) and loaded on its first click. A dialog that
 *
 * - downloads the result as ONE self-contained HTML file (lib/report.js: inline CSS, no script, a
 *   strict CSP, every value escaped) in the interface language, through ui/download.js;
 * - prints it ("Print / save as PDF"): the report's body goes into a shadow root under <body>,
 *   styled by lib/report.js REPORT_CSS as a constructed stylesheet, and a second constructed sheet
 *   hides the rest of the page on paper. The app's CSP (`style-src 'self'`, no frames) refuses an
 *   inline <style>, a blob: page that inherits it and every iframe, but not a constructed sheet.
 *   Both go away after printing;
 * - optionally adds the result's permalink, which carries its inputs only (the domain, Health's
 *   extra DKIM selectors: lib/report.js reportLinkParams, lib/summarycore.js permalinkParams),
 *   never a result, so the recipient runs it again; "Copy the link" copies the same link.
 *
 * Nothing is sent: the report is made from the result on screen.
 */

import { h } from './dom.js';
import { CopyButton, Modal, checkbox, toast } from './components.js';
import { downloadText, timestampedName } from './download.js';
import { statusText } from './source-status.js';
import { registerStrings, t, getLang, hasString } from '../i18n.js';
import { permalinkParams } from '../lib/summarycore.js';
import { REPORT_CSS, REPORT_FILE_BASES, REPORT_I18N, buildReport, reportBody, reportLinkParams } from '../lib/report.js';

registerStrings('en', REPORT_I18N.en);
registerStrings('tr', REPORT_I18N.tr);

/** The page while a report prints: only the report on paper, nothing of it on screen. */
const PAGE_CSS = '@media screen{.rpt-print-host{display:none!important}}'
  + '@media print{body>:not(.rpt-print-host){display:none!important}.rpt-print-host{display:block}}'
  + '@page{margin:14mm 12mm}';

/** The print host on the page, and the function that removes it. */
let printing = null;

/** A key the UI language (or English) has: the builders fall back to readable text otherwise. */
const has = (key) => hasString(key, getLang()) || hasString(key, 'en');

/**
 * Can this browser print a report from the page (shadow roots and constructed stylesheets)?
 * @returns {boolean}
 */
export function canPrintReport() {
  const g = globalThis;
  return typeof g.window?.print === 'function' && typeof g.CSSStyleSheet === 'function' && 'replaceSync' in g.CSSStyleSheet.prototype
    && typeof g.Document === 'function' && 'adoptedStyleSheets' in g.Document.prototype && typeof g.HTMLElement?.prototype.attachShadow === 'function';
}

/**
 * A lib/report.js tree as DOM, through h() (text nodes and checked attributes only).
 * @param {import('../lib/report.js').ReportNode|string} node
 * @param {string} [tag] another element for the root (the report's <body> becomes a <div>)
 * @returns {Node|string}
 */
export function reportDom(node, tag = null) {
  if (typeof node === 'string') return node;
  return h(tag || node.tag, { attrs: node.attrs }, node.children.map((c) => reportDom(c)));
}

/** A constructed stylesheet. */
function sheetOf(css) {
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(css);
  return sheet;
}

/** Remove the print host and its page sheet (after printing, or before the next print). */
export function endPrint() {
  if (printing) printing();
}

/**
 * Print a report: its body in a shadow root, the rest of the page hidden on paper, then
 * `window.print()`. The host goes away on `afterprint` (or when print media ends).
 * @param {import('../lib/report.js').ReportNode} body lib/report.js reportBody()
 * @returns {boolean} false when this browser cannot print it from here
 */
export function printReport(body) {
  if (!canPrintReport()) {
    toast(t('rpt.panel.noPrint'), { type: 'warn' });
    return false;
  }
  endPrint();
  const doc = globalThis.document;
  const win = globalThis.window;
  const host = h('div', { class: 'rpt-print-host', dataset: { report: 'print' } });
  const root = host.attachShadow({ mode: 'open' });
  root.adoptedStyleSheets = [sheetOf(REPORT_CSS)];
  root.append(reportDom(body, 'div'));
  const pageSheet = sheetOf(PAGE_CSS);
  doc.body.append(host);
  doc.adoptedStyleSheets = [...doc.adoptedStyleSheets, pageSheet];
  const media = typeof win.matchMedia === 'function' ? win.matchMedia('print') : null;
  const onMedia = (e) => {
    if (!e.matches) done();
  };
  function done() {
    if (printing !== done) return;
    printing = null;
    host.remove();
    doc.adoptedStyleSheets = doc.adoptedStyleSheets.filter((s) => s !== pageSheet);
    win.removeEventListener('afterprint', done);
    if (media && typeof media.removeEventListener === 'function') media.removeEventListener('change', onMedia);
  }
  printing = done;
  win.addEventListener('afterprint', done);
  if (media && typeof media.addEventListener === 'function') media.addEventListener('change', onMedia);
  win.print();
  return true;
}

/**
 * Open the report panel for a result.
 * @param {import('../app.js').ViewContext} ctx the view's context (shareUrl, version)
 * @param {'domain'|'health'} kind
 * @param {object} input lib/report.js domainReport / healthReport input
 * @returns {Promise<void>} when the panel has closed (and the print, if asked, has started)
 */
export async function openReport(ctx, kind, input) {
  const linkParams = reportLinkParams(kind, input);
  const link = () => ctx.shareUrl(permalinkParams(kind, linkParams));
  const linkBox = checkbox({
    label: t('rpt.panel.link'),
    checked: true,
    hint: t('rpt.panel.linkHint', { inputs: Object.values(linkParams).join(' · ') })
  });
  linkBox.input.dataset.role = 'report-link';
  /** The builder's options at the moment of the click: the time, the link if it is wanted. */
  const options = () => ({ t, lang: getLang(), has, statusText, version: ctx.version, generatedAt: new Date(), link: linkBox.input.checked ? link() : null });
  const fail = (err) => {
    toast(t('rpt.panel.failed', { error: err && err.message ? err.message : String(err) }), { type: 'error' });
    return false;
  };
  const modal = Modal({
    title: t('rpt.panel.title'),
    className: 'rpt-modal',
    content: h('div', { class: 'stack' },
      h('p', { class: 'text-sm' }, t('rpt.panel.body')),
      linkBox.el,
      h('div', null, CopyButton(link, { label: t('rpt.panel.copyLink'), size: 'sm', variant: 'ghost' }))),
    actions: [
      { label: t('rpt.panel.print'), icon: 'file', value: 'print', dataset: { action: 'report-print' } },
      {
        label: t('rpt.panel.download'), icon: 'download', variant: 'primary', value: 'download', autofocus: true, dataset: { action: 'report-download' },
        onClick: () => {
          try {
            const { doc, html } = buildReport(kind, input, options());
            const name = downloadText(timestampedName(REPORT_FILE_BASES[kind], 'html', doc.subject), html, 'text/html;charset=utf-8');
            toast(t('rpt.panel.saved', { name }), { type: 'success' });
          } catch (err) {
            return fail(err);
          }
          return true;
        }
      }
    ]
  });
  // Print once the dialog has closed: it must not be on paper.
  if (await modal.open() !== 'print') return;
  try {
    const opts = options();
    printReport(reportBody(buildReport(kind, input, opts).doc, opts));
  } catch (err) {
    fail(err);
  }
}
