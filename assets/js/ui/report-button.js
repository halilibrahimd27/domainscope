/**
 * report-button.js — the "Report" button of the Domain overview and Domain Health (views/domain.js,
 * views/health.js; one call in each). It carries only its own label: the panel, the report
 * builder and its stylesheet (ui/report.js, lib/report.js) load on the first click, so neither
 * view's first load grows by more than this file.
 */

import { Button, toast } from './components.js';
import { registerStrings, t } from '../i18n.js';
import { onceAsync } from '../lib/util.js';

registerStrings('en', {
  'rpt.button': 'Report',
  'rpt.buttonTitle': 'A customer report of this result: one HTML file, or print / save as PDF',
  'rpt.loadFailed': 'The report could not be loaded. Check the connection and try again.'
});
registerStrings('tr', {
  'rpt.button': 'Rapor',
  'rpt.buttonTitle': 'Bu sonucun müşteri raporu: tek bir HTML dosyası ya da yazdır / PDF olarak kaydet',
  'rpt.loadFailed': 'Rapor yüklenemedi. Bağlantıyı kontrol edip yeniden deneyin.'
});

/** The panel, loaded on the first click (a failed load is tried again on the next). */
const loadPanel = onceAsync(() => import('./report.js'));

/**
 * The "Report" button: on a click it reads the result through `input` and opens the report
 * panel (ui/report.js openReport). Disabled while the view's run goes on.
 * @param {import('../app.js').ViewContext} ctx the view's context
 * @param {'domain'|'health'} kind lib/report.js REPORT_KINDS
 * @param {() => object|null} input the builder's input at click time (lib/report.js domainReport /
 *   healthReport); null when there is nothing to report
 * @param {{ disabled?: boolean }} [opts]
 * @returns {HTMLButtonElement}
 */
export function ReportButton(ctx, kind, input, { disabled = false } = {}) {
  const btn = Button({
    label: t('rpt.button'),
    icon: 'file-text',
    size: 'sm',
    variant: 'secondary',
    title: t('rpt.buttonTitle'),
    dataset: { action: 'report', kind },
    onClick: async () => {
      const data = input();
      if (!data) return;
      let panel;
      try {
        panel = await loadPanel();
      } catch {
        ctx.checkOutdated();
        toast(t('rpt.loadFailed'), { type: 'error' });
        return;
      }
      panel.openReport(ctx, kind, data);
    }
  });
  btn.disabled = !!disabled;
  return btn;
}
