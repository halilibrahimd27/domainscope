/**
 * ui/report-history.js — DMARC & TLS reports › History: what the workspace kept of the reports
 * dropped before (lib/dmarchistory.js), loaded with the tab on its first use (views/reports.js).
 *
 * - One row of filters above everything it scopes: the domain and the period (30, 90 or 400 days;
 *   a period over three months is drawn one bar per week).
 * - The domain's numbers (messages, DMARC compliance, the unknown senders' share, the days with a
 *   report), then two bar charts in inline SVG coloured by the app's tokens: the messages of each
 *   day stacked by result (passed; failed from unknown senders and forwarders; failed from your
 *   servers and third parties) and the day's compliance banded like the DMARC tab's head (a day of
 *   0 % is a stub in the error band, not a gap: only a day without mail has no bar). A bar answers
 *   the pointer and the arrow keys with its values (a polite live region says them); the same
 *   values are in the table under the charts, which exports as CSV.
 * - The sending addresses with the days they were first and last seen and the service behind
 *   them, "New since <date>" for those that appeared lately (lib/dmarchistory.js newSince).
 * - The roll-up across the workspace's domains (volume, compliance, policy, the unknown senders'
 *   share, the verdict) with a CSV; a row shows its domain's trend.
 * - Forget report history (after a confirmation). "Delete all local data" clears it with the rest.
 *
 * Nothing is sent: everything is read from the workspace part `reportHistory`.
 */

import { h, svg, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, DataTable, Disclosure, EmptyState, SegmentedControl, StatCard, checkbox, confirmDialog, ipSortValue, select, toast
} from './components.js';
import { downloadText, timestampedName } from './download.js';
import { registerStrings, formatNumber, formatPercent, formatDate, hasString } from '../i18n.js';
import { toCsv } from '../lib/export.js';
import { sharePercent } from '../lib/util.js';
import {
  HISTORY_DAYS, HISTORY_PERIODS, NEW_BASELINE_DAYS, ROLLUP_CSV_COLUMNS, TREND_CSV_COLUMNS,
  historyDomains, historySources, newSince, rollup, trend, trendCsvRows, rollupCsvRows
} from '../lib/dmarchistory.js';

/** Height of the two charts' plots, in px. */
export const CHART_HEIGHTS = Object.freeze({ volume: 132, compliance: 84 });
/** Width of the y-axis labels left of a plot, in px. */
const GUTTER = 46;
/** The stacked segments of a day's messages, bottom to top (`rh-seg-<key>`). */
export const VOLUME_SEGMENTS = Object.freeze(['pass', 'other', 'known']);
/** The compliance bands (the DMARC tab's head: 98 % and 90 %). */
export const COMPLIANCE_BANDS = Object.freeze([['ok', 0.98], ['warn', 0.9], ['error', 0]]);
/** The least height of a compliance bar, in px: a day of 0 % (or nearly) is a stub, never a gap. */
export const STUB_PX = 2;
/** The look of a roll-up verdict. */
export const VERDICT_LOOK = Object.freeze({
  'no-mail': 'neutral', enforced: 'ok', 'enforced-losing': 'error', 'fix-first': 'warn', ready: 'info'
});
/** The sources' CSV columns. */
export const SOURCE_CSV_COLUMNS = Object.freeze(['ip', 'class', 'service', 'service_type', 'first_seen', 'last_seen', 'messages', 'dmarc_pass', 'new']);

registerStrings('en', {
  'rpt.hist.period': 'Period',
  'rpt.hist.days': { one: '{count} day', other: '{count} days' },
  'rpt.hist.range': '{from} → {to}',
  'rpt.hist.policy': 'Last published policy: {policy} (seen {date})',
  'rpt.hist.stat.messages': 'Messages',
  'rpt.hist.stat.compliance': 'DMARC compliance',
  'rpt.hist.stat.unknown': 'From unknown senders',
  'rpt.hist.stat.days': 'Days with reports',
  'rpt.hist.stat.daysValue': '{count} of {days}',
  'rpt.hist.stale': 'No report for {domain} in the last {days} days. The last one is from {date}.',
  'rpt.hist.chart.volume.day': 'Messages per day',
  'rpt.hist.chart.volume.week': 'Messages per week',
  'rpt.hist.chart.compliance.day': 'DMARC compliance per day',
  'rpt.hist.chart.compliance.week': 'DMARC compliance per week',
  'rpt.hist.chart.aria': '{title}, {domain}, {from} to {to}. The left and right arrow keys read each bar; the table below has every value.',
  'rpt.hist.seg.pass': 'Passed DMARC',
  'rpt.hist.seg.other': 'Failed: unknown senders, forwarders',
  'rpt.hist.seg.known': 'Failed: your servers, third parties',
  'rpt.hist.band.ok': '{pct} or more',
  'rpt.hist.band.warn': '{low} to {high}',
  'rpt.hist.band.error': 'Under {pct}',
  'rpt.hist.tip.week': '{from} – {to}',
  'rpt.hist.tip.none.day': 'No report for this day',
  'rpt.hist.tip.none.week': 'No report for this week',
  'rpt.hist.tip.pass': '{pct} passed DMARC',
  'rpt.hist.tip.other': { one: '{count} failed from unknown senders or forwarders', other: '{count} failed from unknown senders or forwarders' },
  'rpt.hist.tip.known': { one: '{count} failed from your servers or third parties', other: '{count} failed from your servers or third parties' },
  'rpt.hist.tip.reported': { one: 'Reports on {count} day', other: 'Reports on {count} days' },
  'rpt.hist.table.day': 'The days as a table',
  'rpt.hist.table.week': 'The weeks as a table',
  'rpt.hist.tableCaption': 'DMARC results of {domain}, {from} to {to}',
  'rpt.hist.col.day': 'Day',
  'rpt.hist.col.week': 'Week',
  'rpt.hist.col.quarantine': 'Quarantined',
  'rpt.hist.col.reject': 'Rejected',
  'rpt.hist.col.unknown': 'Unknown senders',
  'rpt.hist.col.knownFail': 'Known, failing',
  'rpt.hist.sources': 'Sending addresses over time',
  'rpt.hist.sourcesSub': { one: '{count} address kept', other: '{count} addresses kept' },
  'rpt.hist.sourcesCaption': 'Sending addresses of {domain} in the history',
  'rpt.hist.newLine': { zero: 'No new sender since {date}.', one: '{count} new sender since {date}.', other: '{count} new senders since {date}.' },
  'rpt.hist.newNotYet': { one: 'A sender is marked new once the history of this domain covers {count} day before it.', other: 'A sender is marked new once the history of this domain covers {count} days before it.' },
  'rpt.hist.onlyNew': 'Only the new ones',
  'rpt.hist.new': 'New since {date}',
  'rpt.hist.col.first': 'First seen',
  'rpt.hist.col.last': 'Last seen',
  'rpt.hist.rollup': 'All domains of this workspace',
  'rpt.hist.rollupSub': { one: 'The last {count} day', other: 'The last {count} days' },
  'rpt.hist.rollupCaption': 'DMARC results of every domain kept',
  'rpt.hist.domains': { one: '{count} domain', other: '{count} domains' },
  'rpt.hist.passShare': '{pct} pass',
  'rpt.hist.col.compliance': 'DMARC compliance',
  'rpt.hist.col.policy': 'Policy',
  'rpt.hist.col.unknownShare': 'Unknown senders',
  'rpt.hist.col.verdict': 'Verdict',
  'rpt.hist.col.lastReport': 'Last report',
  'rpt.hist.notChecked': 'SPF not checked yet: an authorized third party may count as unknown',
  'rpt.hist.show': 'Show the trend of {domain}',
  'rpt.hist.privacy': 'Kept in this workspace, in this browser (IndexedDB), for {days} days: each day’s volume and results, and for every sending address its first and last day, class and service. Never the report files. It leaves the browser only inside a workspace hand-over file you export.',
  'rpt.hist.offNote': 'Keeping is off: new reports are not added. What is kept stays until you forget it.',
  'rpt.hist.forget': 'Forget report history',
  'rpt.hist.forgetConfirm': { one: 'Delete the report history of {count} domain in this workspace? This cannot be undone.', other: 'Delete the report history of {count} domains in this workspace? This cannot be undone.' },
  'rpt.hist.forgotten': 'The report history of this workspace is empty.',
  'rpt.hist.emptyTitle': 'Nothing kept yet',
  'rpt.hist.emptyOn': 'The reports you drop from now on are added here, day by day.'
});

registerStrings('tr', {
  'rpt.hist.period': 'Dönem',
  'rpt.hist.days': '{count} gün',
  'rpt.hist.range': '{from} → {to}',
  'rpt.hist.policy': 'Son yayınlanan politika: {policy} ({date} tarihinde görüldü)',
  'rpt.hist.stat.messages': 'E-postalar',
  'rpt.hist.stat.compliance': 'DMARC uyumu',
  'rpt.hist.stat.unknown': 'Bilinmeyen göndericilerden',
  'rpt.hist.stat.days': 'Raporlu günler',
  'rpt.hist.stat.daysValue': '{count} / {days}',
  'rpt.hist.stale': '{domain} için son {days} günde rapor yok. Sonuncusu {date} tarihli.',
  'rpt.hist.chart.volume.day': 'Günlük e-posta sayısı',
  'rpt.hist.chart.volume.week': 'Haftalık e-posta sayısı',
  'rpt.hist.chart.compliance.day': 'Günlük DMARC uyumu',
  'rpt.hist.chart.compliance.week': 'Haftalık DMARC uyumu',
  'rpt.hist.chart.aria': '{title}, {domain}, {from} – {to}. Sol ve sağ ok tuşları her çubuğu okur; tüm değerler aşağıdaki tablodadır.',
  'rpt.hist.seg.pass': 'DMARC’den geçti',
  'rpt.hist.seg.other': 'Geçmedi: bilinmeyen göndericiler, yönlendirenler',
  'rpt.hist.seg.known': 'Geçmedi: sunucularınız, üçüncü taraflar',
  'rpt.hist.band.ok': '{pct} ve üstü',
  'rpt.hist.band.warn': '{low} ile {high} arası',
  'rpt.hist.band.error': '{pct} altı',
  'rpt.hist.tip.week': '{from} – {to}',
  'rpt.hist.tip.none.day': 'Bu gün için rapor yok',
  'rpt.hist.tip.none.week': 'Bu hafta için rapor yok',
  'rpt.hist.tip.pass': '{pct} DMARC’den geçti',
  'rpt.hist.tip.other': 'Bilinmeyen göndericilerden ya da yönlendirenlerden {count} e-posta geçmedi',
  'rpt.hist.tip.known': 'Sunucularınızdan ya da üçüncü taraflardan {count} e-posta geçmedi',
  'rpt.hist.tip.reported': '{count} günün raporu var',
  'rpt.hist.table.day': 'Günler tablo olarak',
  'rpt.hist.table.week': 'Haftalar tablo olarak',
  'rpt.hist.tableCaption': '{domain} DMARC sonuçları, {from} – {to}',
  'rpt.hist.col.day': 'Gün',
  'rpt.hist.col.week': 'Hafta',
  'rpt.hist.col.quarantine': 'Karantinaya alınan',
  'rpt.hist.col.reject': 'Reddedilen',
  'rpt.hist.col.unknown': 'Bilinmeyen göndericiler',
  'rpt.hist.col.knownFail': 'Bilinen, geçmeyen',
  'rpt.hist.sources': 'Zaman içinde gönderen adresler',
  'rpt.hist.sourcesSub': '{count} adres tutuluyor',
  'rpt.hist.sourcesCaption': '{domain} alan adının geçmişte tutulan gönderen adresleri',
  'rpt.hist.newLine': { zero: '{date} tarihinden bu yana yeni gönderici yok.', other: '{date} tarihinden bu yana {count} yeni gönderici var.' },
  'rpt.hist.newNotYet': 'Bir gönderici, bu alan adının geçmişi ondan önceki {count} günü kapsadığında yeni olarak işaretlenir.',
  'rpt.hist.onlyNew': 'Yalnızca yeniler',
  'rpt.hist.new': '{date} tarihinden beri yeni',
  'rpt.hist.col.first': 'İlk görülme',
  'rpt.hist.col.last': 'Son görülme',
  'rpt.hist.rollup': 'Bu çalışma alanının tüm alan adları',
  'rpt.hist.rollupSub': 'Son {count} gün',
  'rpt.hist.rollupCaption': 'Tutulan her alan adının DMARC sonuçları',
  'rpt.hist.domains': '{count} alan adı',
  'rpt.hist.passShare': '{pct} geçiyor',
  'rpt.hist.col.compliance': 'DMARC uyumu',
  'rpt.hist.col.policy': 'Politika',
  'rpt.hist.col.unknownShare': 'Bilinmeyen göndericiler',
  'rpt.hist.col.verdict': 'Sonuç',
  'rpt.hist.col.lastReport': 'Son rapor',
  'rpt.hist.notChecked': 'SPF henüz kontrol edilmedi: yetkili bir üçüncü taraf bilinmeyen sayılmış olabilir',
  'rpt.hist.show': '{domain} alan adının eğilimini göster',
  'rpt.hist.privacy': 'Bu çalışma alanında, bu tarayıcıda (IndexedDB) {days} gün tutulur: her günün hacmi ve sonuçları, her gönderen adresin de ilk ve son görüldüğü gün, sınıfı ve hizmeti. Rapor dosyaları hiçbir zaman tutulmaz. Tarayıcıdan yalnızca sizin dışa aktardığınız bir çalışma alanı dosyasının içinde çıkar.',
  'rpt.hist.offNote': 'Özet tutma kapalı: yeni raporlar eklenmiyor. Tutulanlar, siz unutana kadar kalır.',
  'rpt.hist.forget': 'Rapor geçmişini unut',
  'rpt.hist.forgetConfirm': 'Bu çalışma alanındaki {count} alan adının rapor geçmişi silinsin mi? Bu işlem geri alınamaz.',
  'rpt.hist.forgotten': 'Bu çalışma alanının rapor geçmişi boş.',
  'rpt.hist.emptyTitle': 'Henüz bir şey tutulmadı',
  'rpt.hist.emptyOn': 'Bundan sonra bıraktığınız raporlar gün gün buraya eklenir.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (tests/js/reports-view.test.js)                             */
/* ------------------------------------------------------------------------ */

/**
 * The band of a day's compliance (the DMARC tab's head: 98 % ok, 90 % warn), null without mail.
 * @param {number|null} compliance
 * @returns {'ok'|'warn'|'error'|null}
 */
export function complianceBand(compliance) {
  if (compliance === null || compliance === undefined || !Number.isFinite(compliance)) return null;
  for (const [band, floor] of COMPLIANCE_BANDS) if (compliance >= floor) return band;
  return 'error';
}

/**
 * A slot's messages as the volume chart stacks them: passed, failed from unknown senders and
 * forwarders (the rest), failed from your servers and third parties.
 * @param {{ msgs: number, dmarcPass: number, knownFail: number }} slot
 * @returns {Array<{ key: 'pass'|'other'|'known', value: number }>}
 */
export function volumeSegments(slot) {
  const known = Math.min(slot.knownFail, Math.max(0, slot.msgs - slot.dmarcPass));
  return [
    { key: 'pass', value: slot.dmarcPass },
    { key: 'other', value: Math.max(0, slot.msgs - slot.dmarcPass - known) },
    { key: 'known', value: known }
  ];
}

/**
 * A slot's bar in the compliance chart: none without mail (no report, or reports of no message),
 * else its compliance in its band's colour, at least {@link STUB_PX} tall (0 % is the worst day,
 * not a day without a report).
 * @param {{ compliance: number|null }} slot
 * @returns {Array<{ key: 'compliance', value: number, cls: string, min: number }>}
 */
export function complianceStack(slot) {
  const band = complianceBand(slot && slot.compliance);
  return band ? [{ key: 'compliance', value: slot.compliance, cls: `rh-band-${band}`, min: STUB_PX }] : [];
}

/**
 * The segments of one bar as drawn, bottom to top, with their heights in px: a segment of no value
 * is left out unless it has a least height (`min`); each is at least 1 px, or its `min`.
 * @param {Array<{ value: number, min?: number }>} segs
 * @param {{ max: number, plot: number }} o the axis top and the plot's height (px)
 * @returns {Array<object & { height: number }>}
 */
export function barHeights(segs, { max, plot }) {
  return segs.filter((s) => s.value > 0 || s.min > 0).map((s) => ({ ...s, height: Math.max(s.min || 1, (s.value / max) * plot) }));
}

/**
 * A clean top for an axis: 1, 2, 2.5 or 5 times a power of ten, at least `v` (1 for nothing).
 * @param {number} v
 * @returns {number}
 */
export function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

/**
 * The bars an axis labels below a chart: at most `max` of them, one every so many bars counted
 * back from the last (today), so the gaps between them are all the same.
 * @param {number} count bars
 * @param {number} max labels that fit
 * @returns {number[]} ascending
 */
export function labelIndexes(count, max) {
  if (count <= 0) return [];
  const m = Math.max(1, Math.min(count, Math.floor(max)));
  if (m === 1) return [count - 1];
  const every = Math.max(1, Math.ceil((count - 1) / (m - 1)));
  const out = [];
  for (let i = count - 1; i >= 0; i -= every) out.unshift(i);
  return out;
}

/** A rectangle with rounded top corners (4 px, square at the baseline), as path data. */
function topRounded(x, y, w, hgt, radius) {
  const r = Math.max(0, Math.min(radius, w / 2, hgt));
  const f = (n) => Math.round(n * 100) / 100;
  return `M${f(x)},${f(y + hgt)}V${f(y + r)}Q${f(x)},${f(y)} ${f(x + r)},${f(y)}H${f(x + w - r)}Q${f(x + w)},${f(y)} ${f(x + w)},${f(y + r)}V${f(y + hgt)}Z`;
}

/* ------------------------------------------------------------------------ */
/* The bar chart                                                            */
/* ------------------------------------------------------------------------ */

/**
 * A bar chart in inline SVG drawn to the width of its box (a ResizeObserver draws it again), its
 * axes in HTML so their text is never stretched. Each bar is a stack of segments ({@link barHeights}:
 * one of no value is drawn only with a least height, `min`); the pointer, a tap or the arrow keys
 * pick a bar and its values show in a tooltip and a polite live region.
 * @param {{ id: string, title: string, aria: string, slots: object[], height: number, max: number,
 *   ticks: number[], tickLabel: (v: number) => string, stack: (slot: object) => Array<{ key: string, value: number, cls: string, min?: number }>,
 *   tip: (slot: object) => string[], xLabel: (slot: object) => string, legend: Node }} o
 * @returns {{ el: HTMLElement, destroy(): void }}
 */
function BarChart(o) {
  const svgEl = svg('svg', { class: 'rh-svg', attrs: { 'aria-hidden': 'true', focusable: 'false', preserveAspectRatio: 'none' } });
  const yAxis = h('div', { class: 'rh-y', attrs: { 'aria-hidden': 'true' } });
  const xAxis = h('div', { class: 'rh-x', attrs: { 'aria-hidden': 'true' } });
  const tipEl = h('div', { class: 'rh-tip', hidden: true });
  const live = h('div', { class: 'sr-only', attrs: { 'aria-live': 'polite' } });
  let active = -1;
  let step = 0;
  const plot = h('div', {
    class: 'rh-plot',
    style: { height: `${o.height}px` },
    attrs: { tabindex: 0, role: 'group', 'aria-label': o.aria },
    on: {
      pointermove: (e) => pick(e),
      pointerdown: (e) => pick(e),
      pointerleave: () => {
        if (document.activeElement !== plot) setActive(-1);
      },
      focus: () => {
        if (active < 0) {
          const last = o.slots.map((s, i) => (s.reportedDays ? i : -1)).filter((i) => i >= 0).pop();
          setActive(last === undefined ? o.slots.length - 1 : last);
        }
      },
      blur: () => setActive(-1),
      keydown: (e) => {
        const n = o.slots.length;
        let next = null;
        if (e.key === 'ArrowLeft') next = Math.max(0, (active < 0 ? n : active) - 1);
        else if (e.key === 'ArrowRight') next = Math.min(n - 1, active + 1);
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = n - 1;
        if (next !== null) {
          e.preventDefault();
          setActive(next);
        }
      }
    }
  }, svgEl, yAxis, tipEl);
  const el = h('figure', { class: 'rh-chart', dataset: { chart: o.id } },
    h('figcaption', { class: 'rh-chart-title' }, o.title), plot, xAxis, o.legend, live);
  const highlight = svg('rect', { class: 'rh-hi', attrs: { x: 0, y: 0, width: 0, height: o.height, visibility: 'hidden' } });

  function pick(e) {
    if (!step) return;
    const box = plot.getBoundingClientRect();
    const i = Math.floor((e.clientX - box.left - GUTTER) / step);
    setActive(i < 0 || i >= o.slots.length ? -1 : i);
  }

  function setActive(i) {
    active = i;
    if (i < 0 || !step) {
      highlight.setAttribute('visibility', 'hidden');
      tipEl.hidden = true;
      return;
    }
    const x = GUTTER + i * step;
    highlight.setAttribute('x', String(Math.round(x * 100) / 100));
    highlight.setAttribute('width', String(Math.round(step * 100) / 100));
    highlight.setAttribute('visibility', 'visible');
    const lines = o.tip(o.slots[i]);
    clear(tipEl);
    tipEl.append(...lines.map((line, k) => h(k ? 'span' : 'strong', { class: k ? 'rh-tip-line' : 'rh-tip-head' }, line)));
    tipEl.hidden = false;
    const width = plot.clientWidth;
    const center = x + step / 2;
    const tipW = Math.min(tipEl.offsetWidth || 180, width);
    const left = center > width / 2 ? Math.max(0, center - 10 - tipW) : Math.min(width - tipW, center + 10);
    tipEl.style.left = `${Math.round(left)}px`;
    live.textContent = lines.join('. ');
  }

  function draw() {
    const width = plot.clientWidth;
    if (!width) return;
    const n = o.slots.length;
    const H = o.height;
    const top = 6;
    const plotH = H - top;
    step = Math.max(0.5, (width - GUTTER - 2) / n);
    const gap = step >= 6 ? 2 : step >= 3 ? 1 : 0;
    const bw = Math.max(0.5, Math.min(24, step - gap));
    svgEl.setAttribute('viewBox', `0 0 ${width} ${H}`);
    clear(svgEl);
    svgEl.append(highlight);
    for (const tick of o.ticks) {
      const y = Math.min(H - 0.5, Math.round(top + (1 - tick / o.max) * plotH) + 0.5);
      svgEl.append(svg('line', { class: tick === 0 ? 'rh-base' : 'rh-grid', attrs: { x1: GUTTER, x2: width, y1: y, y2: y } }));
    }
    o.slots.forEach((slot, i) => {
      const segs = barHeights(o.stack(slot), { max: o.max, plot: plotH - 1 });
      if (!segs.length) return;
      const x = GUTTER + i * step + (step - bw) / 2;
      let bottom = H - 1;
      const g = svg('g', { class: 'rh-bar', dataset: { slot: i, day: slot.day } });
      segs.forEach((s, k) => {
        const hgt = s.height;
        const isTop = k === segs.length - 1;
        // A 2 px surface gap between two segments of a stack, the lower one gives it up (when it can).
        const drawn = !isTop && hgt > 4 ? hgt - 2 : hgt;
        const y = bottom - hgt;
        const yTop = bottom - drawn;
        g.append(isTop && bw >= 4
          ? svg('path', { class: s.cls, dataset: { seg: s.key }, attrs: { d: topRounded(x, y, bw, drawn, 4) } })
          : svg('rect', { class: s.cls, dataset: { seg: s.key }, attrs: { x: Math.round(x * 100) / 100, y: Math.round(yTop * 100) / 100, width: Math.round(bw * 100) / 100, height: Math.round(drawn * 100) / 100 } }));
        bottom = y;
      });
      svgEl.append(g);
    });
    clear(yAxis);
    for (const tick of o.ticks) {
      const y = Math.round(top + (1 - tick / o.max) * plotH);
      yAxis.append(h('span', { class: 'rh-y-label', style: { top: `${y}px` } }, o.tickLabel(tick)));
    }
    clear(xAxis);
    for (const i of labelIndexes(n, Math.max(2, Math.floor((width - GUTTER) / 92)))) {
      const center = GUTTER + (i + 0.5) * step;
      const label = h('span', { class: 'rh-x-label', style: { left: `${Math.round(center)}px` } }, o.xLabel(o.slots[i]));
      if (i === 0) label.classList.add('rh-x-first');
      if (i === n - 1) label.classList.add('rh-x-last');
      xAxis.append(label);
    }
    if (active >= 0) setActive(active);
  }

  const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => draw()) : null;
  if (ro) ro.observe(plot);
  // Drawn as soon as it has a width (a tab shown later draws through the observer).
  requestAnimationFrame(() => draw());
  return {
    el,
    draw,
    destroy() {
      if (ro) ro.disconnect();
    }
  };
}

/* ------------------------------------------------------------------------ */
/* The panel                                                                */
/* ------------------------------------------------------------------------ */

/** The choices of the panel: they outlive a redraw (a drop, a language switch). */
const P = { period: HISTORY_PERIODS[0], domain: null, onlyNew: false };

/**
 * Mount the History tab.
 * @param {HTMLElement} host
 * @param {{ ctx: import('../app.js').ViewContext, read: () => import('../lib/dmarchistory.js').History,
 *   preferred: () => string|null, onForget: () => Promise<void>|void, classStyle: Record<string, { variant: string, icon: string }>,
 *   now?: () => number }} opts `read`: the workspace's history now; `preferred`: the DMARC tab's domain
 * @returns {{ refresh(): void, destroy(): void, domain(): string|null, period(): number }}
 */
export function mountHistory(host, { ctx, read, preferred, onForget, classStyle, now = () => Date.now() }) {
  const { t } = ctx;
  let charts = [];
  const num = (n) => formatNumber(n);
  const share = (ratio) => {
    if (ratio === null || ratio === undefined) return '—';
    const v = sharePercent(ratio);
    return formatPercent(v / 100, Number.isInteger(v) ? 0 : 1);
  };
  const day = (d) => formatDate(`${d}T00:00:00Z`, { utc: true, dateStyle: 'medium' });
  const short = (d) => formatDate(`${d}T00:00:00Z`, { utc: true, month: 'short', day: 'numeric' });
  const slotName = (tr, s) => (tr.bin === 'week' && s.day !== s.to ? t('rpt.hist.tip.week', { from: short(s.day), to: short(s.to) }) : day(s.day));
  const policyText = (p) => (p ? `p=${p.p} sp=${p.sp} pct=${p.pct}${p.testing ? ` t=${p.testing}` : ''}` : '—');

  function destroyCharts() {
    for (const c of charts) c.destroy();
    charts = [];
  }

  function render() {
    destroyCharts();
    clear(host);
    const hist = read();
    const domains = historyDomains(hist);
    if (!domains.length) {
      host.append(EmptyState({ icon: 'activity', title: t('rpt.hist.emptyTitle'), message: t('rpt.hist.emptyOn'), compact: true }));
      return;
    }
    const want = preferred();
    if (!P.domain || !domains.some((d) => d.domain === P.domain)) P.domain = want && domains.some((d) => d.domain === want) ? want : domains[0].domain;
    const nowMs = now();
    const tr = trend(hist, P.domain, { days: P.period, now: nowMs });
    host.append(filters(domains), domainCard(hist, tr), sourcesCard(hist, nowMs), rollupCard(hist, nowMs), footer(hist, domains));
  }

  /* --- one row of filters above everything they scope ------------------------------------ */
  function filters(domains) {
    const picker = select({
      label: t('rpt.domain'),
      size: 'sm',
      className: 'rh-domain',
      value: P.domain,
      options: domains.map((d) => ({ value: d.domain, label: t('rpt.domainOption', { domain: d.domain, count: d.msgs }) })),
      onChange: (v) => {
        P.domain = v;
        redraw('.rh-domain select');
      }
    });
    const period = SegmentedControl({
      label: t('rpt.hist.period'),
      size: 'sm',
      className: 'rh-period',
      value: String(P.period),
      options: HISTORY_PERIODS.map((d) => ({ value: String(d), label: t('rpt.hist.days', { count: d }) })),
      onChange: (v) => {
        P.period = Number(v);
        redraw(`.rh-period .seg-btn[data-value="${v}"]`);
      }
    });
    return h('div', { class: 'rh-filters cluster', dataset: { role: 'rh-filters' } }, picker.el, period.el);
  }

  /** Draw again and put the focus back on the control it was on. */
  function redraw(selector) {
    render();
    const again = selector ? host.querySelector(selector) : null;
    if (again) again.focus({ preventScroll: true });
  }

  /* --- the domain: its numbers, the two charts and their table ---------------------------- */
  function domainCard(hist, tr) {
    const d = hist.domains[P.domain];
    const tot = tr.totals;
    const band = complianceBand(tot.compliance);
    const stats = h('div', { class: 'stat-grid rpt-stats rh-stats' },
      StatCard({ label: t('rpt.hist.stat.messages'), value: tot.msgs }).el,
      StatCard({ label: t('rpt.hist.stat.compliance'), value: share(tot.compliance), variant: band || 'default',
        hint: t('rpt.stat.complianceHint', { pass: num(tot.dmarcPass), total: num(tot.msgs) }) }).el,
      StatCard({ label: t('rpt.hist.stat.unknown'), value: share(tot.unknownShare), hint: t('rpt.det.count', { count: tot.unknownMsgs }) }).el,
      StatCard({ label: t('rpt.hist.stat.days'), value: t('rpt.hist.stat.daysValue', { count: tot.reportedDays, days: num(P.period) }) }).el);
    stats.querySelectorAll('.stat .stat-value')[1].classList.add('rh-compliance');
    const body = h('div', { class: 'stack' }, stats);
    if (!tot.reportedDays && tr.last) {
      body.append(Alert({ variant: 'info', compact: true, message: t('rpt.hist.stale', { domain: P.domain, days: num(P.period), date: day(tr.last) }) }));
    }
    const bin = tr.bin;
    const maxMsgs = niceMax(Math.max(...tr.slots.map((s) => s.msgs), 0));
    const compact = (v) => formatNumber(v, { notation: 'compact', maximumFractionDigits: 1 });
    const volumeTitle = t(`rpt.hist.chart.volume.${bin}`);
    const complianceTitle = t(`rpt.hist.chart.compliance.${bin}`);
    const range = { domain: P.domain, from: day(tr.from), to: day(tr.to) };
    const tip = (s) => {
      const head = slotName(tr, s);
      if (!s.reportedDays) return [head, t(`rpt.hist.tip.none.${bin}`)];
      const segs = volumeSegments(s);
      return [head,
        t('rpt.det.count', { count: s.msgs }),
        t('rpt.hist.tip.pass', { pct: share(s.compliance) }),
        segs[1].value ? t('rpt.hist.tip.other', { count: segs[1].value }) : null,
        segs[2].value ? t('rpt.hist.tip.known', { count: segs[2].value }) : null,
        bin === 'week' ? t('rpt.hist.tip.reported', { count: s.reportedDays }) : null].filter(Boolean);
    };
    const swatch = (cls, label) => h('span', { class: 'rh-legend-item' }, h('span', { class: `rh-swatch ${cls}` }), label);
    const volume = BarChart({
      id: 'volume',
      title: volumeTitle,
      aria: t('rpt.hist.chart.aria', { title: volumeTitle, ...range }),
      slots: tr.slots,
      height: CHART_HEIGHTS.volume,
      max: maxMsgs,
      ticks: [0, maxMsgs / 2, maxMsgs],
      tickLabel: compact,
      stack: (s) => volumeSegments(s).map((g) => ({ ...g, cls: `rh-seg-${g.key}` })),
      tip,
      xLabel: (s) => short(s.day),
      legend: h('div', { class: 'rh-legend text-xs' }, VOLUME_SEGMENTS.map((k) => swatch(`rh-seg-${k}`, t(`rpt.hist.seg.${k}`))))
    });
    const pct = (v) => formatPercent(v);
    const compliance = BarChart({
      id: 'compliance',
      title: complianceTitle,
      aria: t('rpt.hist.chart.aria', { title: complianceTitle, ...range }),
      slots: tr.slots,
      height: CHART_HEIGHTS.compliance,
      max: 1,
      ticks: [0, 0.5, 1],
      tickLabel: pct,
      stack: complianceStack,
      tip,
      xLabel: (s) => short(s.day),
      legend: h('div', { class: 'rh-legend text-xs' },
        swatch('rh-band-ok', t('rpt.hist.band.ok', { pct: pct(0.98) })),
        swatch('rh-band-warn', t('rpt.hist.band.warn', { low: pct(0.9), high: pct(0.98) })),
        swatch('rh-band-error', t('rpt.hist.band.error', { pct: pct(0.9) })))
    });
    charts.push(volume, compliance);
    body.append(h('div', { class: 'rh-charts' }, volume.el, compliance.el), daysTable(tr));
    const subtitle = [t('rpt.hist.range', { from: day(tr.from), to: day(tr.to) }),
      d && d.policy ? t('rpt.hist.policy', { policy: policyText(d.policy), date: day(d.policy.seenAt.slice(0, 10)) }) : null].filter(Boolean).join(' · ');
    return Card({ className: 'rh-domain-card', title: h('span', { class: 'mono' }, P.domain), subtitle, icon: 'activity', children: body });
  }

  /** The table view of the charts: every slot with a report, its counts, a CSV. */
  function daysTable(tr) {
    const rows = tr.slots.filter((s) => s.reportedDays);
    const table = DataTable({
      caption: t('rpt.hist.tableCaption', { domain: P.domain, from: day(tr.from), to: day(tr.to) }),
      className: 'rh-days',
      rows,
      rowKey: (s) => s.day,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      sort: { key: 'day', dir: 'desc' },
      export: {
        formats: ['csv'],
        onExport: () => {
          const file = downloadText(timestampedName('dmarc-history-days', 'csv', P.domain),
            toCsv(trendCsvRows(tr), TREND_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      columns: [
        { key: 'day', label: t(tr.bin === 'week' ? 'rpt.hist.col.week' : 'rpt.hist.col.day'), sortable: true, render: (s) => slotName(tr, s) },
        { key: 'msgs', label: t('rpt.col.messages'), sortable: true, align: 'end', defaultDir: 'desc' },
        { key: 'compliance', label: t('rpt.col.pass'), sortable: true, align: 'end', sortValue: (s) => s.compliance ?? -1,
          render: (s) => h('span', { class: ['rpt-pct', `rh-pct-${complianceBand(s.compliance) || 'none'}`] }, share(s.compliance)) },
        { key: 'spfAligned', label: t('rpt.col.spf'), sortable: true, align: 'end' },
        { key: 'dkimAligned', label: t('rpt.col.dkim'), sortable: true, align: 'end' },
        { key: 'quarantine', label: t('rpt.hist.col.quarantine'), sortable: true, align: 'end' },
        { key: 'reject', label: t('rpt.hist.col.reject'), sortable: true, align: 'end' },
        { key: 'unknownMsgs', label: t('rpt.hist.col.unknown'), sortable: true, align: 'end' },
        { key: 'knownFail', label: t('rpt.hist.col.knownFail'), sortable: true, align: 'end' }
      ]
    });
    return Disclosure({ summary: `${t(tr.bin === 'week' ? 'rpt.hist.table.week' : 'rpt.hist.table.day')} (${num(rows.length)})`, className: 'rh-days-box', children: table.el });
  }

  /* --- the sending addresses, first and last seen, the new ones -------------------------- */
  function sourcesCard(hist, nowMs) {
    const since = newSince(hist, P.domain, { now: nowMs });
    const rows = historySources(hist, P.domain, { since });
    const fresh = rows.filter((r) => r.isNew).length;
    const line = h('p', { class: 'text-sm rh-new-line', dataset: { role: 'rh-new-line', count: fresh } },
      since ? t('rpt.hist.newLine', { count: fresh, date: day(since) }) : t('rpt.hist.newNotYet', { count: NEW_BASELINE_DAYS }));
    const only = checkbox({
      label: t('rpt.hist.onlyNew'),
      checked: P.onlyNew && !!fresh,
      disabled: !fresh,
      className: 'rh-only-new',
      onChange: (on) => {
        P.onlyNew = on;
        table.setFilter(on ? (r) => r.isNew : null);
      }
    });
    only.input.dataset.role = 'rh-only-new';
    // A type this page does not know (a crafted hand-over file) is left out, never asked for.
    const svc = (r) => (r.service ? `${r.service}${r.type && hasString(`rpt.svcType.${r.type}`, 'en') ? ` — ${t(`rpt.svcType.${r.type}`)}` : ''}` : '');
    const table = DataTable({
      caption: t('rpt.hist.sourcesCaption', { domain: P.domain }),
      className: 'rh-sources',
      rows,
      rowKey: (r) => r.ip,
      search: rows.length > 10,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      sort: { key: 'msgs', dir: 'desc' },
      filter: P.onlyNew && fresh ? (r) => r.isNew : null,
      rowClass: (r) => (r.isNew ? 'rh-row-new' : null),
      export: {
        formats: ['csv'],
        onExport: (_format, shown) => {
          const out = shown.map((r) => ({
            ip: r.ip, class: r.cls || '', service: r.service || '', service_type: r.service ? r.type || '' : '', first_seen: r.first, last_seen: r.last,
            messages: r.msgs, dmarc_pass: r.passMsgs, new: r.isNew ? 'yes' : ''
          }));
          const file = downloadText(timestampedName('dmarc-history-sources', 'csv', P.domain),
            toCsv(out, SOURCE_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      columns: [
        { key: 'ip', label: t('rpt.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip), searchValue: (r) => `${r.ip} ${svc(r)}`,
          render: (r) => h('div', { class: 'rpt-addr' }, h('span', { class: 'mono rpt-ip', dataset: { ip: r.ip } }, r.ip),
            r.service ? h('span', { class: 'rpt-svc-meta', dataset: { service: r.service } }, svc(r)) : null) },
        { key: 'cls', label: t('rpt.col.cls'), sortable: true, searchValue: (r) => (r.cls ? t(`rpt.cls.${r.cls}`) : ''),
          render: (r) => {
            if (!r.cls) return h('span', { class: 'muted' }, '—');
            const look = classStyle[r.cls] || { variant: 'neutral', icon: null };
            const b = Badge(t(`rpt.clsOne.${r.cls}`), { variant: look.variant, icon: look.icon, title: t(`rpt.clsDesc.${r.cls}`) });
            b.dataset.cls = r.cls;
            return b;
          } },
        { key: 'first', label: t('rpt.hist.col.first'), sortable: true,
          render: (r) => h('div', { class: 'rh-first' }, h('span', null, day(r.first)),
            r.isNew ? Badge(t('rpt.hist.new', { date: day(r.first) }), { variant: 'accent', icon: 'plus', className: 'rh-new' }) : null) },
        { key: 'last', label: t('rpt.hist.col.last'), sortable: true, render: (r) => day(r.last) },
        { key: 'msgs', label: t('rpt.col.messages'), sortable: true, align: 'end', defaultDir: 'desc' },
        { key: 'passMsgs', label: t('rpt.col.pass'), sortable: true, align: 'end', sortValue: (r) => (r.msgs ? r.passMsgs / r.msgs : 0),
          render: (r) => h('span', { class: 'rpt-pct' }, r.msgs ? share(r.passMsgs / r.msgs) : '—') }
      ]
    });
    return Card({
      className: 'rh-sources-card',
      title: t('rpt.hist.sources'),
      subtitle: t('rpt.hist.sourcesSub', { count: rows.length }),
      icon: 'server',
      children: h('div', { class: 'stack-sm' }, h('div', { class: 'rh-new-head' }, line, only.el), table.el)
    });
  }

  /* --- the roll-up across the workspace's domains --------------------------------------- */
  function rollupCard(hist, nowMs) {
    const r = rollup(hist, { now: nowMs, days: P.period });
    const totals = h('p', { class: 'text-sm muted rh-rollup-totals', dataset: { role: 'rh-rollup-totals' } },
      [t('rpt.hist.domains', { count: r.totals.domains }), t('rpt.det.count', { count: r.totals.msgs }), t('rpt.hist.passShare', { pct: share(r.totals.compliance) })].join(' · '));
    const table = DataTable({
      caption: t('rpt.hist.rollupCaption'),
      className: 'rh-rollup',
      rows: r.rows,
      rowKey: (x) => x.domain,
      dense: true,
      cellLabels: true,
      maxHeight: null,
      sort: null,
      rowClass: (x) => (x.domain === P.domain ? 'rh-row-current' : null),
      export: {
        formats: ['csv'],
        onExport: (_format, shown) => {
          const file = downloadText(timestampedName('dmarc-rollup', 'csv', ''),
            toCsv(rollupCsvRows(shown), ROLLUP_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
          toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
        }
      },
      columns: [
        { key: 'domain', label: t('rpt.domain'), sortable: true,
          render: (x) => h('button', {
            type: 'button', class: 'rh-show mono', dataset: { action: 'rh-show', domain: x.domain },
            attrs: { 'aria-label': t('rpt.hist.show', { domain: x.domain }), 'aria-current': x.domain === P.domain ? 'true' : null },
            on: { click: () => { P.domain = x.domain; redraw(null); const head = host.querySelector('.rh-domain-card .card-title'); if (head) head.scrollIntoView({ block: 'nearest' }); host.querySelector('.rh-domain select')?.focus({ preventScroll: true }); } }
          }, x.domain) },
        { key: 'msgs', label: t('rpt.col.messages'), sortable: true, align: 'end', defaultDir: 'desc' },
        { key: 'compliance', label: t('rpt.hist.col.compliance'), sortable: true, align: 'end', sortValue: (x) => x.compliance ?? -1,
          render: (x) => h('span', { class: ['rpt-pct', `rh-pct-${complianceBand(x.compliance) || 'none'}`] }, share(x.compliance)) },
        { key: 'policy', label: t('rpt.hist.col.policy'), sortValue: (x) => (x.policy ? x.policy.p : ''), sortable: true, searchValue: (x) => policyText(x.policy),
          render: (x) => h('code', { class: 'mono text-sm' }, policyText(x.policy)) },
        { key: 'unknownShare', label: t('rpt.hist.col.unknownShare'), sortable: true, align: 'end', sortValue: (x) => x.unknownShare ?? -1, render: (x) => share(x.unknownShare) },
        { key: 'verdict', label: t('rpt.hist.col.verdict'), sortable: true, wrap: true, sortValue: (x) => ['enforced-losing', 'fix-first', 'ready', 'enforced', 'no-mail'].indexOf(x.verdict),
          searchValue: (x) => t(`rpt.hist.verdict.${x.verdict}`),
          render: (x) => h('div', { class: 'rh-verdict', dataset: { verdict: x.verdict } },
            Badge(t(`rpt.hist.verdict.${x.verdict}`), { variant: VERDICT_LOOK[x.verdict] || 'neutral' }),
            !x.checked && x.msgs ? h('span', { class: 'text-xs muted rh-not-checked' }, t('rpt.hist.notChecked')) : null) },
        { key: 'last', label: t('rpt.hist.col.lastReport'), sortable: true, render: (x) => (x.last ? day(x.last) : '—') }
      ]
    });
    return Card({
      className: 'rh-rollup-card',
      title: t('rpt.hist.rollup'),
      subtitle: t('rpt.hist.rollupSub', { count: P.period }),
      icon: 'layers',
      children: h('div', { class: 'stack-sm' }, totals, table.el)
    });
  }

  /* --- what is kept, and Forget ------------------------------------------------------------ */
  function footer(hist, domains) {
    const forget = Button({
      label: t('rpt.hist.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'rh-forget' },
      onClick: async () => {
        const ok = await confirmDialog({ message: t('rpt.hist.forgetConfirm', { count: domains.length }), confirmLabel: t('rpt.hist.forget'), danger: true });
        if (!ok) return;
        await onForget();
        toast(t('rpt.hist.forgotten'), { type: 'info' });
      }
    });
    return h('div', { class: 'stack-sm rh-footer' },
      hist.keep ? null : Alert({ variant: 'info', compact: true, message: t('rpt.hist.offNote') }),
      h('p', { class: 'text-sm muted rh-privacy' }, t('rpt.hist.privacy', { days: num(HISTORY_DAYS) })),
      h('div', null, forget));
  }

  render();
  return {
    refresh: () => render(),
    destroy: () => {
      destroyCharts();
    },
    domain: () => P.domain,
    period: () => P.period
  };
}

/** Forget the panel's choices (another workspace, "Delete all local data"). */
export function resetHistoryPanel() {
  P.period = HISTORY_PERIODS[0];
  P.domain = null;
  P.onlyNew = false;
}

export default { mountHistory, resetHistoryPanel };
