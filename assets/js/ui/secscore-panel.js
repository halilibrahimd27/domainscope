/**
 * ui/secscore-panel.js — Domain portfolio › Domain security: for every domain of the check on
 * screen, the eight measures of CSC's Domain Security Report (lib/secscore.js: a corporate
 * registrar, a registry lock, CAA, DNS redundancy, DNSSEC, SPF, DKIM, DMARC at quarantine or
 * reject) and a 0–8 score; the portfolio's adoption of each measure as bars (inline SVG); a CSV.
 * Loaded with the tab on its first use (views/portfolio.js).
 *
 * It reads the facts the check already has and sends nothing. A measure that could not be checked
 * is "not known", with its reason: never met, never failed. Every string goes through h() / text
 * nodes; the bars are SVG elements built with svg() (ui/dom.js) and coloured by the stylesheet.
 */

import { h, svg, clear } from './dom.js';
import { Badge, Button, Card, DataTable, toast } from './components.js';
import { registerStrings, formatNumber, formatPercent } from '../i18n.js';
import {
  SECURITY_I18N, SECURITY_MAX, SECURITY_MEASURES, scoreBand, securityAdoption, securityCsv, securityScores, securityTotals
} from '../lib/secscore.js';
import { evidenceText } from '../lib/policy.js';
import { downloadText, timestampedName } from './download.js';

/** A measure's status: its badge's variant and icon. */
const STATUS_LOOK = Object.freeze({ pass: ['ok', 'check'], fail: ['error', 'x-circle'], unknown: ['neutral', 'help'] });
/** The segments of a bar, in order. */
export const BAR_SEGMENTS = Object.freeze(['pass', 'fail', 'unknown']);

registerStrings('en', SECURITY_I18N.en);
registerStrings('tr', SECURITY_I18N.tr);

registerStrings('en', {
  'sec.title': 'Domain security',
  'sec.intro': 'CSC’s Domain Security Report scores companies’ domains on eight measures. Here they are for each domain of the check above: met, not met, or not known when a lookup could not tell (a measure not known never counts as met). Nothing more is sent.',
  'sec.noRun': 'Check a portfolio first: the score uses its results and sends nothing more.',
  'sec.running': 'The portfolio is still being checked: the scores fill as the lookups land.',
  'sec.domains': { one: '{count} domain', other: '{count} domains' },
  'sec.average': 'average score {score} of {max}',
  'sec.full': { zero: 'none meets all eight', one: '{count} meets all eight', other: '{count} meet all eight' },
  'sec.unknownCount': { one: '{count} measure could not be checked', other: '{count} measures could not be checked' },
  'sec.adoption': 'Adoption across the portfolio',
  'sec.adopted': '{count} of {total} ({share})',
  'sec.adoptedUnknown': '{count} not known',
  'sec.barLabel': '{measure}: {pass} met, {fail} not met, {unknown} not known',
  'sec.st.pass': 'Met',
  'sec.st.fail': 'Not met',
  'sec.st.unknown': 'Not known',
  'sec.tableTitle': 'Score by domain',
  'sec.col.domain': 'Domain',
  'sec.col.score': 'Score',
  'sec.scoreTitle': 'Measures met of {max}',
  'sec.scoreUnknown': '{count} not known',
  'sec.search': 'Filter domains…',
  'sec.csv': 'CSV',
  'sec.csvTitle': 'The domains the table shows (its search applied), each measure with its evidence',
  'sec.exported': 'Saved {file}'
});

registerStrings('tr', {
  'sec.title': 'Alan adı güvenliği',
  'sec.intro': 'CSC’nin Domain Security Report çalışması, şirketlerin alan adlarını sekiz ölçüte göre puanlar. Bu ölçütler burada, yukarıdaki kontroldeki her alan adı için gösterilir: karşılanıyor, karşılanmıyor ya da bir sorgu sonuç vermediğinde bilinmiyor (bilinmeyen bir ölçüt hiçbir zaman karşılanmış sayılmaz). Başka hiçbir şey gönderilmez.',
  'sec.noRun': 'Önce bir portföyü kontrol edin: puan onun sonuçlarını kullanır ve başka bir şey göndermez.',
  'sec.running': 'Portföy hâlâ kontrol ediliyor: sorgu sonuçları geldikçe puanlar güncellenir.',
  'sec.domains': '{count} alan adı',
  'sec.average': 'ortalama puan {max} üzerinden {score}',
  'sec.full': { zero: 'sekizini birden karşılayan yok', other: '{count} tanesi sekizini birden karşılıyor' },
  'sec.unknownCount': '{count} ölçüt kontrol edilemedi',
  'sec.adoption': 'Portföyde uygulanma oranı',
  'sec.adopted': '{total} alan adından {count} tanesi ({share})',
  'sec.adoptedUnknown': '{count} tanesi bilinmiyor',
  'sec.barLabel': '{measure}: {pass} karşılanıyor, {fail} karşılanmıyor, {unknown} bilinmiyor',
  'sec.st.pass': 'Karşılanıyor',
  'sec.st.fail': 'Karşılanmıyor',
  'sec.st.unknown': 'Bilinmiyor',
  'sec.tableTitle': 'Alan adına göre puan',
  'sec.col.domain': 'Alan adı',
  'sec.col.score': 'Puan',
  'sec.scoreTitle': '{max} ölçütten karşılananlar',
  'sec.scoreUnknown': '{count} tanesi bilinmiyor',
  'sec.search': 'Alan adı süz…',
  'sec.csv': 'CSV',
  'sec.csvTitle': 'Tablonun gösterdiği alan adları (arama uygulanmış), her ölçüt kanıtıyla',
  'sec.exported': '{file} kaydedildi'
});

/**
 * Every i18n key this panel builds from a library code (the i18n coverage test reads them).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...SECURITY_MEASURES.flatMap((m) => [`sec.m.${m.id}`, `sec.d.${m.id}`]),
    ...BAR_SEGMENTS.map((s) => `sec.st.${s}`)
  ];
}

/**
 * The line above the bars: the domains, the average score, how many meet all eight and how many
 * measures could not be checked (left out when none), in the language `t` speaks.
 * @param {ReturnType<typeof securityTotals>} totals
 * @param {Function} t
 * @returns {string}
 */
export function totalsText(totals, t) {
  const avg = Number.isFinite(totals.average) ? formatNumber(totals.average, { maximumFractionDigits: 1 }) : '—';
  const parts = [
    t('sec.domains', { count: totals.domains }),
    t('sec.average', { score: avg, max: SECURITY_MAX }),
    t('sec.full', { count: totals.full }),
    totals.unknownMeasures ? t('sec.unknownCount', { count: totals.unknownMeasures }) : null
  ].filter(Boolean);
  return parts.join(' · ');
}

/**
 * One measure's bar: its segments as percentages of the domains (met, not met, not known; a part
 * without a domain left out), its text beside the bar and its label for screen readers.
 * @param {{ id: string, pass: number, fail: number, unknown: number, total: number, share: number|null }} a
 *   lib/secscore.js securityAdoption entry
 * @param {Function} t
 * @returns {{ segments: Array<{ kind: string, x: number, width: number, count: number }>, text: string, label: string }}
 */
export function barModel(a, t) {
  const total = a.total || 0;
  const raw = BAR_SEGMENTS.map((kind) => ({ kind, count: a[kind] || 0 }));
  let x = 0;
  const segments = raw.filter((s) => s.count > 0).map((s) => {
    const width = total ? (s.count / total) * 100 : 0;
    const seg = { kind: s.kind, x, width, count: s.count };
    x += width;
    return seg;
  });
  const measure = t(`sec.m.${a.id}`);
  const share = a.share === null || a.share === undefined ? '—' : formatPercent(a.share);
  const text = [t('sec.adopted', { count: a.pass, total, share }), a.unknown ? t('sec.adoptedUnknown', { count: a.unknown }) : null].filter(Boolean).join(' · ');
  return { segments, text, label: t('sec.barLabel', { measure, pass: a.pass, fail: a.fail, unknown: a.unknown }) };
}

/**
 * Mount the Domain security tab's panel.
 * @param {HTMLElement} host
 * @param {{ ctx: import('../app.js').ViewContext, source: () => ({ facts: object[], status: string }|null),
 *   subject: () => string }} opts `source`: the check on screen now (its rows' lib/portfolio.js
 *   facts and its status), null before a check; `subject`: the export files' name part
 * @returns {{ refresh(): void, destroy(): void }}
 */
export function mountSecurity(host, { ctx, source, subject }) {
  const { t } = ctx;
  let rows = [];

  /* --- the portfolio's adoption ---------------------------------------------------------- */
  const totalsEl = h('p', { class: 'text-sm pf-sec-totals', dataset: { role: 'sec-totals' } });
  const barsEl = h('div', { class: 'pf-sec-bars', attrs: { role: 'list' } });
  const legend = h('div', { class: 'pf-sec-legend text-xs', attrs: { 'aria-hidden': 'true' } },
    BAR_SEGMENTS.map((kind) => h('span', { class: 'pf-sec-legend-item' }, h('span', { class: `pf-sec-swatch pf-sec-seg-${kind}` }), t(`sec.st.${kind}`))));
  const noRun = h('p', { class: 'muted text-sm', dataset: { sec: 'no-run' } }, t('sec.noRun'));
  const adoptionTitle = h('h4', { class: 'pf-sec-subtitle' }, t('sec.adoption'));
  const adoptionBody = h('div', { class: 'stack pf-sec-adoption' }, barsEl, legend);
  const overview = Card({
    title: t('sec.title'),
    icon: 'shield',
    className: 'pf-sec-card',
    children: h('div', { class: 'stack' }, h('p', { class: 'text-sm muted pf-sec-intro' }, t('sec.intro')), noRun, totalsEl, adoptionTitle, adoptionBody)
  });

  function bar(a) {
    const m = barModel(a, t);
    const chart = svg('svg', {
      class: 'pf-sec-bar-chart',
      attrs: { viewBox: '0 0 100 10', preserveAspectRatio: 'none', role: 'img', 'aria-label': m.label, focusable: 'false' }
    },
    svg('rect', { class: 'pf-sec-seg-track', attrs: { x: 0, y: 0, width: 100, height: 10 } }),
    m.segments.map((s) => svg('rect', {
      class: `pf-sec-seg-${s.kind}`,
      dataset: { segment: s.kind, count: s.count },
      attrs: { x: s.x.toFixed(3), y: 0, width: s.width.toFixed(3), height: 10 }
    })));
    return h('div', { class: 'pf-sec-bar', dataset: { measure: a.id, pass: a.pass, fail: a.fail, unknown: a.unknown }, attrs: { role: 'listitem' } },
      h('span', { class: 'pf-sec-bar-label', title: t(`sec.d.${a.id}`) }, t(`sec.m.${a.id}`)),
      chart,
      h('span', { class: 'pf-sec-bar-value text-sm' }, m.text));
  }

  /* --- the table --------------------------------------------------------------------------- */
  const cellOf = (row, i) => {
    const c = row.measures[i];
    const [variant, icon] = STATUS_LOOK[c.status] || STATUS_LOOK.unknown;
    return h('span', { class: 'pf-cell', dataset: { status: c.status, measure: c.id } },
      Badge(t(`sec.st.${c.status}`), { variant, icon }),
      h('span', { class: 'text-xs pf-evidence' }, evidenceText(c, t)));
  };
  const scoreCell = (row) => h('span', { class: 'pf-cell pf-sec-score', dataset: { score: row.score, unknown: row.unknown }, title: t('sec.scoreTitle', { max: SECURITY_MAX }) },
    Badge(`${row.score}/${SECURITY_MAX}`, { variant: scoreBand(row.score), mono: true }),
    row.unknown ? h('span', { class: 'muted text-xs' }, t('sec.scoreUnknown', { count: row.unknown })) : null);

  const csvBtn = Button({ label: t('sec.csv'), icon: 'download', size: 'sm', dataset: { action: 'sec-csv' }, title: t('sec.csvTitle'), onClick: () => exportCsv() });
  const table = DataTable({
    columns: [
      { key: 'domain', label: t('sec.col.domain'), sortable: true, sortValue: (r) => r.domain, render: (r) => h('strong', { class: 'mono pf-break pf-domain' }, r.domain), className: 'pf-col-domain' },
      { key: 'score', label: t('sec.col.score'), title: t('sec.scoreTitle', { max: SECURITY_MAX }), sortable: true, searchable: false,
        sortValue: (r) => r.score * 10 + (SECURITY_MAX - r.unknown) / 10, render: scoreCell, className: 'pf-col pf-sec-col-score' },
      ...SECURITY_MEASURES.map((m, i) => ({
        key: m.id,
        label: t(`sec.m.${m.id}`),
        title: t(`sec.d.${m.id}`),
        sortable: true,
        searchable: false,
        wrap: true,
        sortValue: (r) => ({ fail: 0, unknown: 1, pass: 2 }[r.measures[i].status]),
        render: (r) => cellOf(r, i),
        className: `pf-col pf-sec-col pf-sec-col-${m.id}`
      }))
    ],
    rowKey: (r) => r.domain,
    search: { placeholder: t('sec.search') },
    sort: { key: 'score', dir: 'asc' },
    toolbar: csvBtn,
    export: false,
    cellLabels: true,
    pageSize: 100,
    maxHeight: null,
    caption: t('sec.tableTitle'),
    className: 'pf-table pf-sec-table'
  });
  table.el.dataset.role = 'sec-table';
  const tableCard = Card({ title: t('sec.tableTitle'), icon: 'list', className: 'pf-sec-table-card', children: table.el });

  host.append(h('div', { class: 'stack-lg pf-sec' }, overview, tableCard));

  function exportCsv() {
    const shown = table.getVisibleRows();
    if (!shown.length) return;
    const file = downloadText(timestampedName('domain-security', 'csv', subject()), securityCsv(shown, { t }), 'text/csv;charset=utf-8');
    toast(t('sec.exported', { file }), { type: 'success', timeout: 2500 });
  }

  /** Draw the check on screen again (its rows as they are now). */
  function refresh() {
    const src = source();
    const has = !!src;
    noRun.hidden = has;
    totalsEl.hidden = !has;
    adoptionTitle.hidden = !has;
    adoptionBody.hidden = !has;
    tableCard.hidden = !has;
    rows = has ? securityScores(src.facts) : [];
    clear(totalsEl);
    clear(barsEl);
    if (has) {
      totalsEl.append(totalsText(securityTotals(rows), t));
      if (src.status === 'running') totalsEl.append(h('span', { class: 'muted' }, ` · ${t('sec.running')}`));
      barsEl.append(...securityAdoption(rows).map(bar));
    }
    table.setRows(rows);
    csvBtn.disabled = !rows.length;
  }

  refresh();
  return {
    refresh,
    destroy() {
      clear(host);
    }
  };
}

export default { mountSecurity, generatedKeys, totalsText, barModel, BAR_SEGMENTS };
