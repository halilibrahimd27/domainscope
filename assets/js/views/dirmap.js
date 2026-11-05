/**
 * views/dirmap.js — "Endpoint map": the directories and endpoints a web host you own serves,
 * found by cli/dir_scan.py and read here. A browser cannot read a cross-origin response's status
 * code, so the scan runs from a machine that reaches your hosts (dir_scan.py tries a list of
 * common names: /api, /admin, /.well-known…); this view opens its --json report and lists what
 * answered, per host. Nothing is sent from here; the reports live in module memory only.
 *
 * A path that answers is a fact about your site, not a vulnerability: leaked secret files are the
 * Exposure audit's and content_audit.py's job.
 *
 * The page template: the steps schema (ui/cli-steps.js, "the scan does not run in the browser"),
 * the reports' file input (drop zone, paste), the result header (hosts and paths, the verdicts as
 * filters, Copy summary, Export ▾ with the CSV and the answered paths), and the path list grouped
 * by host (DataTable).
 *
 * Pure helpers are exported for the unit tests; the module is DOM-free at import time.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Button, ButtonLink, CodeBlock, CopyButton, DataTable, Disclosure, FileDrop, Icon, IconButton, Tag, announce, select, textarea, toast
} from '../ui/components.js';
import {
  EmptyState, FileInput, PrivacyNote, ResultActions, ResultHeader, ResultTitle, StatusSummary
} from '../ui/template.js';
import { CliSteps } from '../ui/cli-steps.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { formatDateTime, formatNumber, registerStrings } from '../i18n.js';
import { permalinkParams, registerSummaryBuilder } from '../lib/summarycore.js';
import { toCsv } from '../lib/export.js';
import { dirmapSummary, DIRMAP_SUMMARY_I18N } from '../lib/dirmapsummary.js';
import {
  CLI_FILE, CLI_PATH, DIRMAP_CSV_COLUMNS, DIRMAP_FILTERS, DIRMAP_MAX_BYTES, DIRMAP_MAX_REPORTS, DIRMAP_VERDICTS,
  dirMap, dirmapCsvRows, dirmapMatches, dirmapSummaryFacts, foundPaths, readDirReport
} from '../lib/dirmap.js';

/** Route id (`#/dirmap`). */
export const id = 'dirmap';
/** i18n key of the page title. */
export const titleKey = 'nav.dirmap';
/** Nav/page icon. */
export const icon = 'folder';

/** The verdicts the header counts as filters (not-found is a fact the list's Show select has). */
const STATUS_FILTERS = Object.freeze(['found', 'listing', 'protected', 'redirect', 'unchecked']);
/** The command the steps offer. */
export const CLI_EXAMPLE = 'python3 dir_scan.py www.example.com --json map.json';

// Copy summary's builder and texts load with this view, not on the start route (lib/dirmapsummary.js).
registerSummaryBuilder('dirmap', dirmapSummary);
registerStrings('en', DIRMAP_SUMMARY_I18N.en);
registerStrings('tr', DIRMAP_SUMMARY_I18N.tr);

registerStrings('en', {
  'dirmap.steps.title': 'The scan does not run in the browser',
  'dirmap.steps.why': 'A web page cannot read a cross-origin response’s status code, so it cannot tell which paths a host serves. dir_scan.py does it from a machine that reaches your hosts, and this page reads its report. Nothing is sent from here.',
  'dirmap.steps.cannot.status': 'read another host’s response status',
  'dirmap.steps.cannot.reach': 'reach a host behind a firewall or a VPN',
  'dirmap.steps.cannot.rate': 'send hundreds of requests at a polite rate',
  'dirmap.steps.can.list': 'lists every path that answered',
  'dirmap.steps.can.group': 'groups them: found, protected, redirect',
  'dirmap.steps.can.export': 'exports the answered paths and a CSV',
  'dirmap.steps.s1': 'Download dir_scan.py',
  'dirmap.steps.s1Text': 'One Python 3 file, nothing to install.',
  'dirmap.steps.download': 'Download dir_scan.py',
  'dirmap.steps.s2': 'Run it where your hosts are reachable',
  'dirmap.steps.s2Text': 'Give it the hosts you own or may test. It tries about 200 common directory and endpoint names (add your own with --wordlist) at a polite rate, and never sends a payload.',
  'dirmap.steps.s3': 'Open the report here',
  'dirmap.steps.s3Text': 'Drop map.json on the page or choose it; several reports at once are merged.',
  'dirmap.steps.s3Open': 'Open the report',
  'dirmap.steps.tips': 'Also from the command line',
  'dirmap.steps.ext': 'Try each name with extensions too:',
  'dirmap.steps.own': 'Your own wordlist, added to the built-in names:',
  'dirmap.steps.summary': { one: 'Scanned with dir_scan.py · {count} report open', other: 'Scanned with dir_scan.py · {count} reports open' },

  'dirmap.reports.title': 'Scan results',
  'dirmap.reports.sub': 'The JSON files dir_scan.py writes with --json',
  'dirmap.reports.privacy': 'The reports are read here and kept only in this tab: nothing is uploaded or stored, and a reload, Forget, another workspace or “Delete all local data” clears them.',
  'dirmap.drop.title': 'Drop the reports of dir_scan.py here',
  'dirmap.drop.hint': 'or click to choose · several at once · the file written by --json',
  'dirmap.paste.summary': 'Paste a report',
  'dirmap.paste.label': 'Report (JSON, as --json - prints it)',
  'dirmap.paste.read': 'Read report',
  'dirmap.loaded': { one: '{count} report loaded', other: '{count} reports loaded' },
  'dirmap.addFiles': 'Add files',
  'dirmap.forget': 'Forget all',
  'dirmap.forgotten': 'Reports forgotten',
  'dirmap.imported': { one: '{count} report read: {hosts}', other: '{count} reports read: {hosts}' },
  'dirmap.duplicate': '{name}: the same report is already open',
  'dirmap.tooMany': 'At most {max} reports at once: the rest were not read.',
  'dirmap.removed': '{name} removed',
  'dirmap.remove': 'Remove {name}',
  'dirmap.errorsTitle': 'Not read',
  'dirmap.error.too-large': '{name}: larger than {max} — not a report of dir_scan.py',
  'dirmap.error.not-json': '{name}: not JSON. Choose the file dir_scan.py wrote with --json (the --csv file does not open here).',
  'dirmap.error.not-report': '{name}: not a report of dir_scan.py',
  'dirmap.error.version': '{name}: written by version {detail} of dir_scan.py, which this page cannot read',
  'dirmap.error.no-hosts': '{name}: a report without hosts',
  'dirmap.report.meta': 'scanned {when} · {hosts}',
  'dirmap.report.hosts': { one: '{count} host', other: '{count} hosts' },

  'dirmap.emptyLine': 'The directories and endpoints a host serves, from a dir_scan.py report.',
  'dirmap.check.found': 'Found paths',
  'dirmap.check.protected': 'Protected',
  'dirmap.check.redirect': 'Redirects',
  'dirmap.check.listing': 'Open listings',

  'dirmap.headTitle': '{hosts} · {paths}',
  'dirmap.headPaths': { one: '{count} path', other: '{count} paths' },
  'dirmap.scannedAt': 'Scanned {when}',
  'dirmap.reportsCount': { one: '{count} report', other: '{count} reports' },
  'dirmap.st.found': { one: '{count} found', other: '{count} found' },
  'dirmap.st.listing': { one: '{count} open listing', other: '{count} open listings' },
  'dirmap.st.protected': { one: '{count} protected', other: '{count} protected' },
  'dirmap.st.redirect': { one: '{count} redirect', other: '{count} redirects' },
  'dirmap.st.unchecked': { one: '{count} not checked', other: '{count} not checked' },
  'dirmap.stHelp.found': 'A path that answers, unlike a random path: a real directory or endpoint.',
  'dirmap.stHelp.listing': 'A directory listing is served — its files are visible.',
  'dirmap.stHelp.protected': 'The path exists but is behind auth (401 / 403).',
  'dirmap.stHelp.redirect': 'The path redirects elsewhere.',
  'dirmap.stHelp.unchecked': 'Rate limited, timed out or failed: not checked.',

  'dirmap.unreachable': 'unreachable: {error}',
  'dirmap.notMapped': '{note}',
  'dirmap.baselineNote': 'How the host answers an unknown path: {note}',
  'dirmap.found': 'Found',
  'dirmap.foundHint': 'The paths that answer, ready to copy. A path that answers is a fact about your site, not a vulnerability.',
  'dirmap.copyAll': 'Copy all ({count})',
  'dirmap.copyAllDone': { one: '{count} path copied', other: '{count} paths copied' },
  'dirmap.copyOne': 'Copy {path}',
  'dirmap.copiedOne': '{path} copied',
  'dirmap.noneFound': 'No path answered on these hosts.',
  'dirmap.listLabel': 'Paths',
  'dirmap.csv': 'CSV',
  'dirmap.csvTitle': 'The paths this filter shows, with the status and detail',
  'dirmap.foundTxt': 'Answered paths (.txt)',
  'dirmap.foundTxtTitle': 'The paths that answered, one URL a line',
  'dirmap.downloaded': '{file} downloaded',
  'dirmap.noneToExport': 'No answered path to export',

  'dirmap.filter.label': 'Show',
  'dirmap.filter.all': 'All ({count})',
  'dirmap.filter.answered': 'Answered ({count})',
  'dirmap.filter.found': 'Found ({count})',
  'dirmap.filter.listing': 'Open listing ({count})',
  'dirmap.filter.protected': 'Protected ({count})',
  'dirmap.filter.redirect': 'Redirect ({count})',
  'dirmap.filter.unchecked': 'Not checked ({count})',
  'dirmap.filter.not-found': 'Not found ({count})',
  'dirmap.col.host': 'Host',
  'dirmap.col.path': 'Path',
  'dirmap.col.verdict': 'Result',
  'dirmap.col.status': 'Status',
  'dirmap.col.detail': 'Detail',
  'dirmap.v.found': 'Found',
  'dirmap.v.listing': 'Listing',
  'dirmap.v.protected': 'Protected',
  'dirmap.v.redirect': 'Redirect',
  'dirmap.v.not-found': 'Not found',
  'dirmap.v.blocked': 'Blocked',
  'dirmap.v.timeout': 'Timed out',
  'dirmap.v.error': 'Error',
  'dirmap.search': 'Filter paths',
  'dirmap.noMatch': 'No path passes this filter.'
});

registerStrings('tr', {
  'dirmap.steps.title': 'Tarama tarayıcıda çalışmaz',
  'dirmap.steps.why': 'Bir web sayfası başka bir origin’in yanıt kodunu okuyamaz, bu yüzden bir host’un hangi yolları sunduğunu anlayamaz. dir_scan.py bunu host’larınıza erişen bir makinede yapar; bu sayfa da raporunu okur. Buradan hiçbir şey gönderilmez.',
  'dirmap.steps.cannot.status': 'başka bir host’un yanıt kodunu okumak',
  'dirmap.steps.cannot.reach': 'güvenlik duvarı ya da VPN arkasındaki bir host’a erişmek',
  'dirmap.steps.cannot.rate': 'yüzlerce isteği kibar bir hızla göndermek',
  'dirmap.steps.can.list': 'yanıt veren her yolu listeler',
  'dirmap.steps.can.group': 'onları gruplar: bulundu, korumalı, yönlendirme',
  'dirmap.steps.can.export': 'yanıt veren yolları ve bir CSV dışa aktarır',
  'dirmap.steps.s1': 'dir_scan.py’yi indirin',
  'dirmap.steps.s1Text': 'Tek bir Python 3 dosyası, kurulum yok.',
  'dirmap.steps.download': 'dir_scan.py’yi indir',
  'dirmap.steps.s2': 'Host’larınıza erişilen yerde çalıştırın',
  'dirmap.steps.s2Text': 'Sahibi olduğunuz ya da test etmeye yetkili olduğunuz host’ları verin. Yaklaşık 200 yaygın dizin ve endpoint adını (kendinizinkini --wordlist ile ekleyin) kibar bir hızla dener ve hiçbir zaman yük göndermez.',
  'dirmap.steps.s3': 'Raporu burada açın',
  'dirmap.steps.s3Text': 'map.json’u sayfaya bırakın ya da seçin; aynı anda birkaç rapor birleştirilir.',
  'dirmap.steps.s3Open': 'Raporu aç',
  'dirmap.steps.tips': 'Komut satırından ayrıca',
  'dirmap.steps.ext': 'Her adı uzantılarla da deneyin:',
  'dirmap.steps.own': 'Kendi kelime listeniz, yerleşik adlara eklenir:',
  'dirmap.steps.summary': '{count} rapor açık · dir_scan.py ile tarandı',

  'dirmap.reports.title': 'Tarama sonuçları',
  'dirmap.reports.sub': 'dir_scan.py’nin --json ile yazdığı JSON dosyaları',
  'dirmap.reports.privacy': 'Raporlar burada okunur ve yalnızca bu sekmede tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler.',
  'dirmap.drop.title': 'dir_scan.py raporlarını buraya bırakın',
  'dirmap.drop.hint': 'ya da seçmek için tıklayın · aynı anda birkaç dosya · --json ile yazılan dosya',
  'dirmap.paste.summary': 'Bir raporu yapıştırın',
  'dirmap.paste.label': 'Rapor (JSON, --json - çıktısı gibi)',
  'dirmap.paste.read': 'Raporu oku',
  'dirmap.loaded': '{count} rapor yüklendi',
  'dirmap.addFiles': 'Dosya ekle',
  'dirmap.forget': 'Tümünü unut',
  'dirmap.forgotten': 'Raporlar unutuldu',
  'dirmap.imported': { one: '{count} rapor okundu: {hosts}', other: '{count} rapor okundu: {hosts}' },
  'dirmap.duplicate': '{name}: aynı rapor zaten açık',
  'dirmap.tooMany': 'Aynı anda en fazla {max} rapor: kalanlar okunmadı.',
  'dirmap.removed': '{name} kaldırıldı',
  'dirmap.remove': '{name} raporunu kaldır',
  'dirmap.errorsTitle': 'Okunmadı',
  'dirmap.error.too-large': '{name}: {max} boyutundan büyük — dir_scan.py’nin bir raporu değil',
  'dirmap.error.not-json': '{name}: JSON değil. dir_scan.py’nin --json ile yazdığı dosyayı seçin (--csv dosyası burada açılmaz).',
  'dirmap.error.not-report': '{name}: dir_scan.py’nin bir raporu değil',
  'dirmap.error.version': '{name}: dir_scan.py’nin bu sayfanın okuyamadığı {detail} sürümüyle yazılmış',
  'dirmap.error.no-hosts': '{name}: host içermeyen bir rapor',
  'dirmap.report.meta': 'Tarama: {when} · {hosts}',
  'dirmap.report.hosts': { one: '{count} host', other: '{count} host' },

  'dirmap.emptyLine': 'Bir host’un sunduğu dizinler ve endpoint’ler, bir dir_scan.py raporundan.',
  'dirmap.check.found': 'Bulunan yollar',
  'dirmap.check.protected': 'Korumalı',
  'dirmap.check.redirect': 'Yönlendirmeler',
  'dirmap.check.listing': 'Açık listelemeler',

  'dirmap.headTitle': '{hosts} · {paths}',
  'dirmap.headPaths': { one: '{count} yol', other: '{count} yol' },
  'dirmap.scannedAt': 'Tarama: {when}',
  'dirmap.reportsCount': { one: '{count} rapor', other: '{count} rapor' },
  'dirmap.st.found': '{count} bulundu',
  'dirmap.st.listing': '{count} açık listeleme',
  'dirmap.st.protected': '{count} korumalı',
  'dirmap.st.redirect': '{count} yönlendirme',
  'dirmap.st.unchecked': '{count} kontrol edilmedi',
  'dirmap.stHelp.found': 'Rastgele bir yolun aksine yanıt veren bir yol: gerçek bir dizin ya da endpoint.',
  'dirmap.stHelp.listing': 'Bir dizin listelemesi sunuluyor — dosyaları görünüyor.',
  'dirmap.stHelp.protected': 'Yol var ama kimlik doğrulama arkasında (401 / 403).',
  'dirmap.stHelp.redirect': 'Yol başka bir yere yönlendiriyor.',
  'dirmap.stHelp.unchecked': 'Hız sınırı, zaman aşımı ya da hata: kontrol edilmedi.',

  'dirmap.unreachable': 'erişilemedi: {error}',
  'dirmap.notMapped': '{note}',
  'dirmap.baselineNote': 'Host’un bilinmeyen bir yola yanıtı: {note}',
  'dirmap.found': 'Bulundu',
  'dirmap.foundHint': 'Yanıt veren yollar, kopyalamaya hazır. Yanıt veren bir yol sitenizle ilgili bir olgudur, bir güvenlik açığı değil.',
  'dirmap.copyAll': 'Tümünü kopyala ({count})',
  'dirmap.copyAllDone': '{count} yol kopyalandı',
  'dirmap.copyOne': '{path} kopyala',
  'dirmap.copiedOne': '{path} kopyalandı',
  'dirmap.noneFound': 'Bu host’larda hiçbir yol yanıt vermedi.',
  'dirmap.listLabel': 'Yollar',
  'dirmap.csv': 'CSV',
  'dirmap.csvTitle': 'Bu süzgecin gösterdiği yollar, durum ve ayrıntıyla',
  'dirmap.foundTxt': 'Yanıt veren yollar (.txt)',
  'dirmap.foundTxtTitle': 'Yanıt veren yollar, her satırda bir URL',
  'dirmap.downloaded': '{file} indirildi',
  'dirmap.noneToExport': 'Dışa aktarılacak yanıt veren yol yok',

  'dirmap.filter.label': 'Göster',
  'dirmap.filter.all': 'Tümü ({count})',
  'dirmap.filter.answered': 'Yanıt veren ({count})',
  'dirmap.filter.found': 'Bulundu ({count})',
  'dirmap.filter.listing': 'Açık listeleme ({count})',
  'dirmap.filter.protected': 'Korumalı ({count})',
  'dirmap.filter.redirect': 'Yönlendirme ({count})',
  'dirmap.filter.unchecked': 'Kontrol edilmedi ({count})',
  'dirmap.filter.not-found': 'Bulunamadı ({count})',
  'dirmap.col.host': 'Host',
  'dirmap.col.path': 'Yol',
  'dirmap.col.verdict': 'Sonuç',
  'dirmap.col.status': 'Durum',
  'dirmap.col.detail': 'Ayrıntı',
  'dirmap.v.found': 'Bulundu',
  'dirmap.v.listing': 'Listeleme',
  'dirmap.v.protected': 'Korumalı',
  'dirmap.v.redirect': 'Yönlendirme',
  'dirmap.v.not-found': 'Bulunamadı',
  'dirmap.v.blocked': 'Engellendi',
  'dirmap.v.timeout': 'Zaman aşımı',
  'dirmap.v.error': 'Hata',
  'dirmap.search': 'Yolları süz',
  'dirmap.noMatch': 'Bu süzgece uyan yol yok.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Read dropped files into the list of open reports.
 * @param {object[]} open
 * @param {Array<{ name: string, text: string }>} files
 * @returns {{ reports: object[], added: number, errors: object[], duplicates: string[], capped: boolean }}
 */
export function importReports(open, files) {
  const reports = [...(open || [])];
  const errors = [];
  const duplicates = [];
  let added = 0;
  let capped = false;
  for (const file of files || []) {
    const name = String((file && file.name) || '');
    const read = readDirReport(file && file.text, { name });
    if (!read.ok) {
      errors.push({ name, error: read.error, ...(read.detail ? { detail: read.detail } : {}) });
      continue;
    }
    if (reports.some((r) => r.id === read.report.id)) {
      duplicates.push(name);
      continue;
    }
    if (reports.length >= DIRMAP_MAX_REPORTS) {
      capped = true;
      continue;
    }
    reports.push(read.report);
    added += 1;
  }
  return { reports, added, errors, duplicates, capped };
}

/** The Tag variant of a verdict (docs/DESIGN.md §6.2). */
export function verdictVariant(verdict) {
  if (verdict === 'found') return 'ok';
  if (verdict === 'listing') return 'error';
  if (verdict === 'protected' || verdict === 'blocked' || verdict === 'timeout' || verdict === 'error') return 'warn';
  if (verdict === 'redirect') return 'info';
  return 'neutral';
}

/** The rows of the path table: one per path, with its host. */
export function pathRows(entries) {
  const rows = [];
  for (const entry of entries || []) {
    for (const p of entry.paths) rows.push({ ...p, host: entry.host, entryUrl: entry.url });
  }
  return rows;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

const S = { reports: [], errors: [], paste: '', filter: 'answered', stepsOpen: false, importOpen: false };
let subscribed = false;
let rerender = null;

function forgetReports() {
  S.reports = [];
  S.errors = [];
  S.paste = '';
  S.importOpen = false;
}

/**
 * Mount the view.
 * @param {HTMLElement} container
 * @param {object} ctx view context (app.js)
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  if (!subscribed && state && typeof state.subscribe === 'function') {
    subscribed = true;
    state.subscribe(({ key }) => {
      if (key === 'cleared' || key === 'workspace') {
        forgetReports();
        if (rerender) rerender();
      }
    });
  }
  let actions = null;
  let status = null;
  let table = null;
  const disposeActions = () => {
    if (actions) actions.dispose();
    actions = null;
  };
  rerender = () => render();
  ctx.onCleanup(() => {
    rerender = null;
    disposeActions();
  });

  const stepsHost = h('div', { class: 'dirmap-steps-host' });
  const reportsHost = h('div', { class: 'dirmap-reports-host' });
  const resultsHost = h('div', { class: 'dirmap-results-host stack', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'dirmap-view' }, stepsHost, reportsHost, resultsHost));

  /** The drop zone's file picker (step 3's button). */
  let openPicker = null;

  function renderSteps() {
    clear(stepsHost);
    const tips = Disclosure({
      summary: t('dirmap.steps.tips'),
      className: 'dirmap-steps-tips',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm muted' }, t('dirmap.steps.ext')),
        CodeBlock('python3 dir_scan.py www.example.com --extensions php,json,bak --json map.json', { label: 'CLI', wrap: true }),
        h('p', { class: 'text-sm muted' }, t('dirmap.steps.own')),
        CodeBlock('python3 dir_scan.py -t hosts.txt --wordlist my-paths.txt --json map.json', { label: 'CLI', wrap: true }))
    });
    stepsHost.append(CliSteps({
      className: 'dirmap-steps',
      compact: S.reports.length > 0,
      open: S.stepsOpen,
      onToggle: (open) => { S.stepsOpen = open; },
      summary: t('dirmap.steps.summary', { count: S.reports.length }),
      title: t('dirmap.steps.title'),
      why: t('dirmap.steps.why'),
      cannot: ['status', 'reach', 'rate'].map((k) => t(`dirmap.steps.cannot.${k}`)),
      can: ['list', 'group', 'export'].map((k) => t(`dirmap.steps.can.${k}`)),
      steps: [
        { place: 'browser', icon: 'download', title: t('dirmap.steps.s1'), text: t('dirmap.steps.s1Text'),
          action: ButtonLink({ href: CLI_PATH, label: t('dirmap.steps.download'), icon: 'download', variant: 'secondary', size: 'sm', download: CLI_FILE }) },
        { place: 'machine', icon: 'terminal', title: t('dirmap.steps.s2'), text: t('dirmap.steps.s2Text'), code: CLI_EXAMPLE },
        { place: 'browser', icon: 'upload', title: t('dirmap.steps.s3'), text: t('dirmap.steps.s3Text'),
          action: Button({ label: t('dirmap.steps.s3Open'), icon: 'upload', size: 'sm', dataset: { action: 'dirmap-open-report' }, onClick: () => { if (openPicker) openPicker(); } }) }
      ],
      footer: tips
    }));
  }

  function importFiles(files, { pasted = null } = {}) {
    const result = importReports(S.reports, files);
    S.reports = result.reports;
    S.errors = result.errors;
    S.paste = pasted !== null && !result.added ? pasted : '';
    for (const name of result.duplicates) toast(t('dirmap.duplicate', { name }), { type: 'info' });
    if (result.capped) toast(t('dirmap.tooMany', { max: DIRMAP_MAX_REPORTS }), { type: 'warn' });
    if (result.added) {
      const hosts = new Set(S.reports.flatMap((r) => r.hosts.map((x) => x.url))).size;
      const msg = t('dirmap.imported', { count: result.added, hosts: t('dirmap.report.hosts', { count: hosts }) });
      announce(msg);
      toast(msg, { type: 'success', timeout: 2500 });
    }
    S.importOpen = !!(S.paste || S.errors.length);
    render();
    const target = result.added ? resultsHost.querySelector('.dirmap-head .result-title')
      : pasted !== null ? reportsHost.querySelector('[data-role="dirmap-paste"]') : reportsHost.querySelector('.dirmap-drop');
    if (target) target.focus({ preventScroll: true });
  }

  function removeReport(report) {
    S.reports = S.reports.filter((r) => r !== report);
    toast(t('dirmap.removed', { name: report.name }), { type: 'info' });
    render();
    const target = reportsHost.querySelector('.dirmap-report .btn-icon') || reportsHost.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function forget() {
    forgetReports();
    toast(t('dirmap.forgotten'), { type: 'info' });
    render();
    const target = reportsHost.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function renderReports() {
    clear(reportsHost);
    const drop = FileDrop({
      accept: '.json',
      multiple: true,
      compact: S.reports.length > 0,
      icon: 'upload',
      title: t('dirmap.drop.title'),
      hint: t('dirmap.drop.hint'),
      maxBytes: DIRMAP_MAX_BYTES,
      className: 'dirmap-drop',
      paste: true,
      onFiles: (files) => importFiles(files)
    });
    openPicker = () => drop.open();
    drop.el.dataset.shortcut = 'focus';
    const errors = S.errors.length ? Alert({
      variant: 'warn',
      title: t('dirmap.errorsTitle'),
      children: h('ul', { class: 'dirmap-errors' }, S.errors.map((e) => h('li', null, t(`dirmap.error.${e.error}`, {
        name: e.name, detail: e.detail || '?', max: `${Math.round(DIRMAP_MAX_BYTES / 1048576)} MB`
      }))))
    }) : null;
    const list = S.reports.length ? h('ul', { class: 'dirmap-reports' }, S.reports.map((report) => reportItem(report))) : null;
    const pasteArea = textarea({ label: t('dirmap.paste.label'), rows: 6, mono: true, value: S.paste, attrs: { 'data-role': 'dirmap-paste' } });
    const pasteBtn = Button({
      label: t('dirmap.paste.read'),
      icon: 'arrow-down',
      variant: 'primary',
      size: 'sm',
      dataset: { action: 'dirmap-paste-read', shortcut: 'submit' },
      onClick: () => {
        const text = pasteArea.value;
        if (text.trim()) importFiles([{ name: t('file.pasted'), text }], { pasted: text });
      }
    });
    const paste = Disclosure({
      summary: t('dirmap.paste.summary'),
      className: 'dirmap-paste',
      open: !!S.paste,
      children: h('div', { class: 'stack-sm', dataset: { shortcutScope: 'dirmap-paste' } }, pasteArea.el, h('div', { class: 'cluster' }, pasteBtn))
    });
    const privacy = PrivacyNote({ text: t('dirmap.reports.privacy'), className: 'dirmap-reports-privacy' });
    if (!S.reports.length) {
      reportsHost.append(FileInput({
        title: t('dirmap.reports.title'),
        subtitle: t('dirmap.reports.sub'),
        icon: 'file-text',
        className: 'dirmap-import',
        label: t('dirmap.reports.title'),
        body: [drop.el, errors, paste],
        privacy
      }).el);
      return;
    }
    const input = FileInput({
      loaded: true,
      className: 'dirmap-import',
      label: t('dirmap.reports.title'),
      more: t('dirmap.loaded', { count: S.reports.length }),
      moreClass: 'dirmap-import-more',
      moreOpen: S.importOpen,
      body: [list, drop.el, errors, paste],
      actions: [
        Button({ label: t('dirmap.addFiles'), icon: 'plus', size: 'sm', dataset: { action: 'dirmap-add' }, onClick: () => drop.open() }),
        Button({ label: t('dirmap.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'dirmap-forget' }, onClick: forget })
      ],
      privacy
    });
    input.more.addEventListener('toggle', () => { S.importOpen = input.more.open; });
    reportsHost.append(input.el);
  }

  function reportItem(report) {
    return h('li', { class: 'dirmap-report', dataset: { report: report.name } },
      h('div', { class: 'dirmap-report-text' },
        h('span', { class: 'dirmap-report-name mono' }, report.name || '—'),
        h('span', { class: 'dirmap-report-meta muted text-sm' }, t('dirmap.report.meta', {
          when: report.generatedAt ? formatDateTime(report.generatedAt, { utc: true }) : '—',
          hosts: t('dirmap.report.hosts', { count: report.hosts.length })
        }))),
      IconButton({ icon: 'x', label: t('dirmap.remove', { name: report.name }), size: 'sm', onClick: () => removeReport(report) }));
  }

  /* --- result ------------------------------------------------------------- */
  let map = null;

  function setFilter(filter) {
    S.filter = DIRMAP_FILTERS.includes(filter) ? filter : 'all';
    if (status) status.setPressed(STATUS_FILTERS.includes(S.filter) ? S.filter : null);
    if (table) table.setFilter((row) => dirmapMatches(row, S.filter));
    const sel = resultsHost.querySelector('.dirmap-filter select');
    if (sel && sel.value !== S.filter) sel.value = S.filter;
  }

  function render() {
    renderSteps();
    renderReports();
    renderResults();
  }

  function renderResults() {
    disposeActions();
    status = null;
    table = null;
    clear(resultsHost);
    if (!S.reports.length) {
      map = null;
      resultsHost.append(h('div', { class: 'dirmap-empty' }, EmptyState({
        icon: 'folder',
        message: t('dirmap.emptyLine'),
        checks: ['found', 'protected', 'redirect', 'listing'].map((c) => t(`dirmap.check.${c}`))
      })));
      return;
    }
    map = dirMap({ reports: S.reports });
    resultsHost.append(resultHead(map).el);
    for (const note of notesOf(map)) resultsHost.append(note);
    resultsHost.append(foundCard(map));
    resultsHost.append(listPanel(map));
    setFilter(S.filter);
  }

  function resultHead(m) {
    const head = ResultHeader({ className: 'dirmap-head' });
    head.setState('done');
    head.set('title', ResultTitle({
      text: t('dirmap.headTitle', {
        hosts: t('dirmap.report.hosts', { count: m.hosts }),
        paths: t('dirmap.headPaths', { count: m.counts.paths })
      })
    }));
    const times = S.reports.map((r) => r.generatedAt).filter((d) => d instanceof Date);
    const newest = times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null;
    head.set('meta', [
      newest ? h('span', { class: 'dirmap-scanned', title: newest.toISOString() }, t('dirmap.scannedAt', { when: formatDateTime(newest, { utc: true }) })) : null,
      h('span', null, t('dirmap.reportsCount', { count: S.reports.length }))
    ]);
    const severity = { found: 'ok', listing: 'error', protected: 'warn', redirect: 'info', unchecked: 'warn' };
    status = StatusSummary({
      className: 'dirmap-status',
      pressed: STATUS_FILTERS.includes(S.filter) ? S.filter : null,
      items: STATUS_FILTERS.filter((k) => m.counts[k] > 0).map((key) => ({
        key,
        severity: severity[key],
        count: m.counts[key],
        text: t(`dirmap.st.${key}`, { count: m.counts[key] }),
        title: t(`dirmap.stHelp.${key}`),
        filter: true,
        onPress: (k) => setFilter(S.filter === k ? 'all' : k)
      }))
    });
    head.set('status', status.el);
    actions = ResultActions({
      summary: SummaryButton({
        kind: 'dirmap',
        plainLabel: t('result.plainTitle'),
        facts: () => (map ? dirmapSummaryFacts({ map, reports: S.reports }) : null),
        url: () => ctx.shareUrl(permalinkParams('dirmap', {}))
      }),
      exports: [
        { label: t('dirmap.csv'), title: t('dirmap.csvTitle'), icon: 'download', dataset: { export: 'csv' }, onSelect: () => exportCsv() },
        { label: t('dirmap.foundTxt'), title: t('dirmap.foundTxtTitle'), icon: 'download', dataset: { export: 'found' }, onSelect: () => exportFound() }
      ],
      print: true
    });
    head.set('actions', actions.el);
    return head;
  }

  function exportCsv() {
    // The flat table rows carry their host; a filter keeps the current Show selection.
    const match = (p) => dirmapMatches(p, S.filter);
    const rows = dirmapCsvRows(map.entries, match);
    const file = downloadText(timestampedName('endpoint-map', 'csv'),
      toCsv(rows, DIRMAP_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
    toast(t('dirmap.downloaded', { file }), { type: 'success', timeout: 2500 });
  }

  function exportFound() {
    const list = foundPaths(map.entries);
    if (!list.length) {
      toast(t('dirmap.noneToExport'), { type: 'info' });
      return;
    }
    const file = downloadText(timestampedName('answered-paths', 'txt'), `${list.join('\n')}\n`, 'text/plain;charset=utf-8');
    toast(t('dirmap.downloaded', { file }), { type: 'success', timeout: 2500 });
  }

  function notesOf(m) {
    const out = [];
    for (const entry of m.entries) {
      if (!entry.reachable) out.push(note('dirmap-unreachable', { variant: 'warn', compact: true, message: `${entry.url} — ${t('dirmap.unreachable', { error: entry.error })}` }));
      else if (entry.notMapped) out.push(note('dirmap-notmapped', { variant: 'warn', compact: true, message: `${entry.url} — ${entry.notMapped}` }));
    }
    return out.slice(0, 5);
  }

  function note(cls, opts) {
    const el = Alert(opts);
    el.classList.add(cls);
    return el;
  }

  /** The answered paths, ready to copy. */
  function foundCard(m) {
    const found = foundPaths(m.entries);
    const card = h('section', { class: 'card dirmap-found', attrs: { 'aria-labelledby': 'dirmap-found-title' } },
      h('h3', { class: 'dirmap-found-title', id: 'dirmap-found-title' }, Icon('check-circle', { size: 16 }), t('dirmap.found')));
    if (!found.length) {
      card.append(h('p', { class: 'muted text-sm' }, t('dirmap.noneFound')));
      return card;
    }
    card.append(h('p', { class: 'muted text-sm' }, t('dirmap.foundHint')));
    const rows = [];
    for (const entry of m.entries) {
      for (const p of entry.paths) {
        if (p.verdict === 'found' || p.verdict === 'listing') {
          const url = entry.url.replace(/\/$/, '') + p.path;
          rows.push(CopyButton(url, {
            label: `${entry.host}${p.path}`,
            icon: p.verdict === 'listing' ? 'folder' : 'check',
            variant: 'secondary',
            size: 'sm',
            title: t('dirmap.copyOne', { path: url }),
            toastOnCopy: t('dirmap.copiedOne', { path: url }),
            className: ['dirmap-found-path', 'mono', p.verdict === 'listing' ? 'is-listing' : ''].join(' ')
          }));
        }
      }
    }
    card.append(h('div', { class: 'dirmap-found-list cluster' }, rows.slice(0, 60),
      CopyButton(() => `${found.join('\n')}\n`, {
        label: t('dirmap.copyAll', { count: formatNumber(found.length) }),
        variant: 'ghost',
        size: 'sm',
        toastOnCopy: t('dirmap.copyAllDone', { count: found.length }),
        className: 'dirmap-copy-all'
      })));
    return card;
  }

  function listPanel(m) {
    const rows = pathRows(m.entries);
    const counts = Object.fromEntries(DIRMAP_FILTERS.map((f) => [f, rows.filter((r) => dirmapMatches(r, f)).length]));
    const filterSel = select({
      label: t('dirmap.filter.label'),
      value: S.filter,
      options: DIRMAP_FILTERS.filter((f) => f === 'all' || counts[f] > 0 || f === S.filter)
        .map((f) => ({ value: f, label: t(`dirmap.filter.${f}`, { count: formatNumber(counts[f]) }) })),
      className: 'dirmap-filter',
      onChange: (v) => setFilter(v)
    });
    table = DataTable({
      className: 'dirmap-table dt-cards',
      rowKey: (r) => `${r.host}${r.path}`,
      rows,
      pageSize: 200,
      dense: true,
      cellLabels: true,
      search: { label: t('dirmap.search'), placeholder: t('dirmap.search') },
      filter: (r) => dirmapMatches(r, S.filter),
      noMatch: t('dirmap.noMatch'),
      toolbar: filterSel.el,
      export: false,
      columns: [
        { key: 'host', label: t('dirmap.col.host'), sortable: true, mono: true, searchValue: (r) => r.host },
        { key: 'path', label: t('dirmap.col.path'), sortable: true, mono: true, wrap: true,
          render: (r) => (r.verdict === 'found' || r.verdict === 'listing'
            ? h('a', { href: r.entryUrl.replace(/\/$/, '') + r.path, attrs: { target: '_blank', rel: 'noopener noreferrer' } }, r.path)
            : r.path) },
        { key: 'verdict', label: t('dirmap.col.verdict'), sortable: true,
          searchValue: (r) => `${t(`dirmap.v.${r.verdict}`)} ${r.verdict}`,
          render: (r) => Tag(t(`dirmap.v.${r.verdict}`), { variant: verdictVariant(r.verdict) }) },
        { key: 'status', label: t('dirmap.col.status'), sortable: true, align: 'end', mono: true, render: (r) => (r.status === null ? '' : String(r.status)) },
        { key: 'detail', label: t('dirmap.col.detail'), wrap: true,
          searchValue: (r) => `${r.detail} ${r.location}`,
          render: (r) => h('span', { class: 'muted text-xs' }, r.location ? `→ ${r.location}` : r.detail) }
      ]
    });
    return h('div', { class: 'dirmap-list stack-sm' }, table.el);
  }

  render();
}
