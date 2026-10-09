/**
 * report-button.js — the "Report" button of the Domain overview, Domain Health and DMARC & TLS
 * reports (views/domain.js, views/health.js, views/reports.js; one call in each). It carries only
 * its own label: the panel, the report builder and its stylesheet (ui/report.js, lib/report.js)
 * load on the first click, so no view's first load grows by more than this file.
 */

import { Button, toast } from './components.js';
import { registerStrings, t } from '../i18n.js';
import { onceAsync } from '../lib/util.js';

registerStrings('en', {
  'crep.button': 'Report',
  'crep.buttonTitle': 'A customer report of this result: one HTML file, or print / save as PDF',
  'crep.loadFailed': 'The report could not be loaded. Check the connection and try again.'
});
registerStrings('tr', {
  'crep.button': 'Rapor',
  'crep.buttonTitle': 'Bu sonucun müşteri raporu: tek bir HTML dosyası ya da yazdır / PDF olarak kaydet',
  'crep.loadFailed': 'Rapor yüklenemedi. Bağlantıyı kontrol edip yeniden deneyin.'
});

/** The panel, loaded on the first click (a failed load is tried again on the next). */
const loadPanel = onceAsync(() => import('./report.js'));

/**
 * The "Report" button: on a click it reads the result through `input` and opens the report
 * panel (ui/report.js openReport). Disabled while the view's run goes on.
 * @param {import('../app.js').ViewContext} ctx the view's context
 * @param {'domain'|'health'|'dmarc'} kind lib/report.js REPORT_KINDS
 * @param {() => object|null} input the builder's input at click time (lib/report.js domainReport /
 *   healthReport / dmarcReport); null when there is nothing to report
 * @param {{ disabled?: boolean }} [opts]
 * @returns {HTMLButtonElement}
 */
export function ReportButton(ctx, kind, input, { disabled = false } = {}) {
  const btn = Button({
    label: t('crep.button'),
    icon: 'file-text',
    size: 'sm',
    variant: 'secondary',
    title: t('crep.buttonTitle'),
    dataset: { action: 'report', kind },
    onClick: async () => {
      const data = input();
      if (!data) return;
      let panel;
      try {
        panel = await loadPanel();
      } catch {
        ctx.checkOutdated();
        toast(t('crep.loadFailed'), { type: 'error' });
        return;
      }
      panel.openReport(ctx, kind, data);
    }
  });
  btn.disabled = !!disabled;
  return btn;
}
