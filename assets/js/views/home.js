/**
 * views/home.js — Home (#/home, docs/DESIGN.md §4), the start page. For the active workspace it
 * answers three questions: what needs attention, what was I doing, where do I start.
 *
 * - No network: Home reads `state` (the workspace's parts, its servers, the settings) and the page
 *   session only, never ctx.getDns(), fetch or Globalping; its privacy line says so.
 * - First paint from `state` at once: the title (the workspace's name, Default's "Default
 *   workspace", in the page's <h1> and the tab's title) with its facts, the quick start (the
 *   palette's box: ui/palette.js and lib/palette.js load on its first focus or keystroke, as for
 *   Ctrl/⌘+K), Recent domains, Results in this tab, Start a job and This workspace.
 * - "Needs attention" counts with lib/homedigest.js, a dynamic import() after that first paint
 *   (never on the start route): certificate and registration expiry, registry risks, accepted
 *   risks, rollouts, the nightly results' digest, the jobs running and the server list's warnings;
 *   the DMARC history last, in an idle callback (lib/dmarchistory.js, its own import). Each row is
 *   one link to the tool with the details, filled in, nothing run.
 * - A workspace with nothing in it (no recent domains, CT baseline, registration snapshot, accepted
 *   risks or servers) gets the empty state: the quick start, the job cards and the setup checklist.
 * - Cards with nothing to show are left out. A workspace switch re-mounts the view (app.js).
 *
 * The pure parts are exported for tests/js/home-view.test.js; the module is DOM-free at import time.
 */

import { h, clear, uid, svg } from '../ui/dom.js';
import { Button, Icon, MenuButton, SeverityIcon, Tag, announce } from '../ui/components.js';
import { StartTaskList } from '../ui/start-tasks.js';
import { jobList, onJobs } from '../ui/jobs.js';
import { workspaceLabel } from '../ui/workspace-ui.js';
import { t, registerStrings, formatDate, formatNumber, formatPercent, formatRelative } from '../i18n.js';
import { parseTarget, fillRoute } from '../lib/session.js';

/** Route id (`#/home`). */
export const id = 'home';
/** i18n key of the page title (the shell's; Home puts the workspace's name in its place). */
export const titleKey = 'nav.home';
/** Nav/page icon. */
export const icon = 'home';

/** Recent domains Home lists, newest first. */
export const RECENT_SHOWN = 8;
/** Results in this tab Home lists, newest first. */
export const KEPT_SHOWN = 6;
/** The quick actions of a recent domain, in order (each fills the tool, nothing runs). */
export const RECENT_ACTIONS = Object.freeze(['health', 'domain', 'subdomains', 'lookup']);
/** The setup checklist's items, in order. */
export const SETUP_ITEMS = Object.freeze(['servers', 'cas', 'portfolio', 'workspaces']);
/** The longest first line of the notes This workspace shows. */
const NOTE_CHARS = 120;

registerStrings('en', {
  'home.titleDefault': 'Default workspace',
  'home.factServers': { one: '{count} server', other: '{count} servers' },
  'home.factRecent': { one: '{count} recent domain', other: '{count} recent domains' },
  'home.factActivity': 'last activity {when}',
  'home.emptyLead': 'Everything runs in this browser. Nothing is sent until you run a tool.',
  'home.quickLabel': 'Quick start',
  'home.quick': 'Domain, host name, IP address, network or AS number',
  'home.quickPem': '…or paste a PEM certificate',
  'home.quickHint': 'Opens the tool with it filled in; nothing is sent until you run it.',
  'home.attention': 'Needs attention',
  'home.attentionNone': 'Nothing needs attention.',
  'home.okCt': 'CT checked {when}',
  'home.okReg': 'registrations checked {when}',
  'home.loading': 'Reading this workspace…',
  'home.certs': { one: '{count} certificate expires within {days} days', other: '{count} certificates expire within {days} days' },
  'home.certsExpired': { one: '{count} certificate has expired', other: '{count} certificates have expired' },
  'home.ctFirst': 'CT: check once to see expiries here',
  'home.reg': { one: 'Registration expires in {days} day', other: 'Registration expires in {days} days' },
  'home.regExpired': { one: 'Registration expired {days} day ago', other: 'Registration expired {days} days ago' },
  'home.regGone': { one: 'The registry does not know this domain', other: 'The registry does not know {count} domains' },
  'home.regRisk': 'Registry status: {status}',
  'home.regTransfer': 'Transfer pending: {domain}',
  'home.regNoLock': 'No transfer lock',
  'home.waivers': { one: '{count} accepted risk ends within {days} days', other: '{count} accepted risks end within {days} days' },
  'home.waiversEnded': { one: '{count} accepted risk has ended and counts again', other: '{count} accepted risks have ended and count again' },
  'home.rollout': 'Rollout: {done} of {total} servers updated',
  'home.rolloutTicked': 'Rollout of {label}: {verified} verified, {installed} installed',
  'home.monitorBad': {
    one: 'Monitoring: {count} target had a bad change in the last {days} days',
    other: 'Monitoring: {count} targets had a bad change in the last {days} days'
  },
  'home.monitorExpiring': { one: 'Monitoring: {count} certificate expires within {days} days', other: 'Monitoring: {count} certificates expire within {days} days' },
  'home.monitorIncomplete': { one: 'Monitoring: {count} check did not complete', other: 'Monitoring: {count} checks did not complete' },
  'home.running': '{tool} is running',
  'home.runningPercent': '{tool} is running — {percent} done',
  'home.serversWarn': { one: '{count} line in Servers could not be read', other: '{count} lines in Servers could not be read' },
  'home.dmarcLosing': 'p=reject refuses mail of known senders: {domains}',
  'home.dmarcFixFirst': 'Known senders fail DMARC: {domains}',
  'home.stale': 'last checked {when}',
  'home.asOf': 'as of {date} · Check again',
  'home.more': '+{count} more',
  'home.showAll': 'Show all ({count})',
  'home.showFewer': 'Show fewer',
  'home.recent': 'Recent domains',
  'home.recentTarget': 'Make {domain} the current target',
  'home.targetSet': '{domain} is the current target: the tools you open fill it in.',
  'home.recentMore': 'More for {domain}',
  'home.qa.health': 'Health',
  'home.qa.domain': 'Overview',
  'home.qa.subdomains': 'Subdomains',
  'home.qa.lookup': 'Lookup',
  'home.kept': 'Results in this tab',
  'home.keptErrors': { one: '{count} error', other: '{count} errors' },
  'home.keptWarnings': { one: '{count} warning', other: '{count} warnings' },
  'home.keptClean': 'nothing open',
  'home.jobs': 'Start a job',
  'home.jobsFold': 'Show as a short list',
  'home.workspace': 'This workspace',
  'home.wsCas': { one: '{count} expected CA', other: '{count} expected CAs' },
  'home.wsOrigins': { one: '{count} remembered origin', other: '{count} remembered origins' },
  'home.wsWaivers': { one: '{count} accepted risk', other: '{count} accepted risks' },
  'home.wsEmpty': 'Nothing saved in this workspace yet.',
  'home.manage': 'Manage',
  'home.workspaces': 'Workspaces',
  'home.setup': 'Set up this workspace (optional)',
  'home.setupServers': 'Add your servers — tools then name the machine behind each IP.',
  'home.setupCas': 'Name the CAs you use — other issuers get flagged.',
  'home.setupPortfolio': 'Check your domains once in Domain portfolio — their expiry dates then show here.',
  'home.setupWorkspaces': 'Keep one workspace per customer.',
  'home.setupDone': 'done',
  'home.setupTodo': 'to do',
  'home.setupOpen': 'Open',
  'home.setupNew': 'New',
  'home.setupHide': 'Hide this list',
  'home.privacy': 'Home reads only what this browser keeps; it sends nothing.'
});

registerStrings('tr', {
  'home.titleDefault': 'Varsayılan çalışma alanı',
  'home.factServers': '{count} sunucu',
  'home.factRecent': '{count} son alan adı',
  'home.factActivity': 'son işlem {when}',
  'home.emptyLead': 'Her şey bu tarayıcıda çalışır. Bir aracı çalıştırana kadar hiçbir şey gönderilmez.',
  'home.quickLabel': 'Hızlı başlangıç',
  'home.quick': 'Alan adı, host adı, IP adresi, ağ ya da AS numarası',
  'home.quickPem': '…ya da bir PEM sertifikası yapıştırın',
  'home.quickHint': 'Aracı bu değerle doldurulmuş olarak açar; siz çalıştırana kadar hiçbir şey gönderilmez.',
  'home.attention': 'İlgilenmeniz gerekenler',
  'home.attentionNone': 'İlgilenmeniz gereken bir şey yok.',
  'home.okCt': 'CT {when} kontrol edildi',
  'home.okReg': 'kayıtlar {when} kontrol edildi',
  'home.loading': 'Bu çalışma alanı okunuyor…',
  'home.certs': '{count} sertifikanın süresi {days} gün içinde doluyor',
  'home.certsExpired': '{count} sertifikanın süresi doldu',
  'home.ctFirst': 'CT: bitişleri burada görmek için bir kez kontrol edin',
  'home.reg': 'Kaydın bitmesine {days} gün kaldı',
  'home.regExpired': 'Kaydın süresi {days} gün önce doldu',
  'home.regGone': { one: 'Kayıt kuruluşu bu alan adını tanımıyor', other: 'Kayıt kuruluşu {count} alan adını tanımıyor' },
  'home.regRisk': 'Kayıt durumu: {status}',
  'home.regTransfer': 'Transfer beklemede: {domain}',
  'home.regNoLock': 'Transfer kilidi yok',
  'home.waivers': '{count} kabul edilen riskin süresi {days} gün içinde doluyor',
  'home.waiversEnded': '{count} kabul edilen riskin süresi doldu; yeniden sayılıyor',
  'home.rollout': 'Dağıtım: {total} sunucudan {done} tanesi güncellendi',
  'home.rolloutTicked': '{label} dağıtımı: {verified} doğrulandı, {installed} kuruldu',
  'home.monitorBad': 'İzleme: {count} hedefte son {days} günde kötü bir değişiklik oldu',
  'home.monitorExpiring': 'İzleme: {count} sertifikanın süresi {days} gün içinde doluyor',
  'home.monitorIncomplete': 'İzleme: {count} kontrol tamamlanamadı',
  'home.running': '{tool} çalışıyor',
  'home.runningPercent': '{tool} çalışıyor — {percent} tamamlandı',
  'home.serversWarn': 'Sunucular listesindeki {count} satır okunamadı',
  'home.dmarcLosing': 'p=reject bilinen göndericilerin e-postasını reddediyor: {domains}',
  'home.dmarcFixFirst': 'Bilinen göndericiler DMARC’tan geçemiyor: {domains}',
  'home.stale': 'son kontrol {when}',
  'home.asOf': '{date} itibarıyla · Yeniden kontrol edin',
  'home.more': '+{count} tane daha',
  'home.showAll': 'Tümünü göster ({count})',
  'home.showFewer': 'Daha az göster',
  'home.recent': 'Son alan adları',
  'home.recentTarget': '{domain} alan adını geçerli hedef yap',
  'home.targetSet': '{domain} geçerli hedef: açtığınız araçlar bunu doldurur.',
  'home.recentMore': '{domain} için diğer işlemler',
  'home.qa.health': 'Sağlık',
  'home.qa.domain': 'Özet',
  'home.qa.subdomains': 'Subdomain’ler',
  'home.qa.lookup': 'Sorgulama',
  'home.kept': 'Bu sekmedeki sonuçlar',
  'home.keptErrors': '{count} hata',
  'home.keptWarnings': '{count} uyarı',
  'home.keptClean': 'açık sorun yok',
  'home.jobs': 'Bir işe başlayın',
  'home.jobsFold': 'Kısa liste olarak göster',
  'home.workspace': 'Bu çalışma alanı',
  'home.wsCas': '{count} beklenen CA',
  'home.wsOrigins': '{count} hatırlanan origin',
  'home.wsWaivers': '{count} kabul edilen risk',
  'home.wsEmpty': 'Bu çalışma alanında henüz kayıtlı bir şey yok.',
  'home.manage': 'Yönet',
  'home.workspaces': 'Çalışma alanları',
  'home.setup': 'Bu çalışma alanını hazırlayın (isteğe bağlı)',
  'home.setupServers': 'Sunucularınızı ekleyin — araçlar her IP’nin arkasındaki makineyi adıyla gösterir.',
  'home.setupCas': 'Kullandığınız sertifika otoritelerini yazın — diğerleri işaretlenir.',
  'home.setupPortfolio': 'Alan adlarınızı Alan adı portföyünde bir kez kontrol edin — bitiş tarihleri burada görünür.',
  'home.setupWorkspaces': 'Her müşteri için ayrı bir çalışma alanı kullanın.',
  'home.setupDone': 'tamamlandı',
  'home.setupTodo': 'yapılacak',
  'home.setupOpen': 'Aç',
  'home.setupNew': 'Yeni',
  'home.setupHide': 'Bu listeyi gizle',
  'home.privacy': 'Ana sayfa yalnızca bu tarayıcının sakladıklarını okur; hiçbir şey göndermez.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Does the workspace hold nothing Home builds on? No recent domain, CT baseline, registration
 * snapshot, accepted risk or server: Home shows its empty state.
 * @param {{ recent?: any[], ctSeen?: string, rdapSeen?: string, waivers?: string, servers?: number }} ws
 * @returns {boolean}
 */
export function isEmptyWorkspace({ recent = [], ctSeen = '', rdapSeen = '', waivers = '', servers = 0 } = {}) {
  const has = (text) => typeof text === 'string' && text.trim() !== '';
  return !(Array.isArray(recent) && recent.length) && !has(ctSeen) && !has(rdapSeen) && !has(waivers) && !(servers > 0);
}

/**
 * The facts under the title, as i18n keys with their params: the servers, the recent domains and
 * the last activity (the workspace's last change), each only when there is one.
 * @param {{ servers: number, recent: number, updatedAt?: string|null }} counts
 * @returns {Array<{ key: string, params: object }>}
 */
export function homeFacts({ servers = 0, recent = 0, updatedAt = null } = {}) {
  const out = [];
  if (servers > 0) out.push({ key: 'home.factServers', params: { count: servers } });
  if (recent > 0) out.push({ key: 'home.factRecent', params: { count: recent } });
  if (updatedAt && Number.isFinite(Date.parse(updatedAt))) out.push({ key: 'home.factActivity', params: { at: updatedAt } });
  return out;
}

/**
 * The setup checklist: each item and whether its data exists — a server saved, an expected CA
 * named, a domain checked once in Domain portfolio (a registration snapshot), and a second
 * workspace or this one renamed from Default.
 * @param {{ servers: number, expectedCas: string[], rdapSeen: string, workspaces: number, isDefault: boolean }} ws
 * @returns {Array<{ id: string, done: boolean }>}
 */
export function setupItems({ servers = 0, expectedCas = [], rdapSeen = '', workspaces = 1, isDefault = true } = {}) {
  const done = {
    servers: servers > 0,
    cas: Array.isArray(expectedCas) && expectedCas.length > 0,
    portfolio: typeof rdapSeen === 'string' && /"domains"\s*:\s*\{\s*"/.test(rdapSeen),
    workspaces: workspaces > 1 || !isDefault
  };
  return SETUP_ITEMS.map((item) => ({ id: item, done: done[item] }));
}

/**
 * The recent domains Home lists: the newest {@link RECENT_SHOWN}, each with the quick actions its
 * kind takes (fill-only routes: lib/session.js fillRoute) — an IP address gets DNS Lookup only.
 * @param {Array<{ value: string, at?: string|null }>} recent the workspace part, newest first
 * @returns {Array<{ value: string, at: string|null, actions: Array<{ view: string, params: object }> }>}
 */
export function recentEntries(recent) {
  const out = [];
  for (const r of Array.isArray(recent) ? recent : []) {
    if (!r || typeof r.value !== 'string' || !r.value) continue;
    const target = parseTarget(r.value);
    const actions = RECENT_ACTIONS.map((view) => ({ view, params: target ? fillRoute(view, target) : null })).filter((a) => a.params);
    out.push({ value: r.value, at: typeof r.at === 'string' ? r.at : null, actions });
    if (out.length >= RECENT_SHOWN) break;
  }
  return out;
}

/**
 * The results kept in this tab (lib/session.js: the page session, memory only), newest first, at
 * most {@link KEPT_SHOWN}: the tool, what it was about, when, and its open-risk counts when the
 * tool gave them.
 * @param {{ kept: (view: string) => object|null }} session
 * @param {ReadonlyArray<{ id: string }>} views
 * @returns {Array<{ view: string, subject: string|null, at: Date, status: { error: number, warn: number }|null }>}
 */
export function keptResults(session, views) {
  const out = [];
  for (const v of views || []) {
    const k = session && typeof session.kept === 'function' ? session.kept(v.id) : null;
    if (k && k.at instanceof Date && Number.isFinite(k.at.getTime())) out.push({ view: v.id, subject: k.subject || null, at: k.at, status: k.status || null });
  }
  return out.sort((a, b) => b.at - a.at).slice(0, KEPT_SHOWN);
}

/**
 * How many accepted risks the workspace's `waivers` text holds (the file's list or a bare list;
 * 0 for anything else). A count only: lib/waivers.js reads them when they matter.
 * @param {unknown} text
 * @returns {number}
 */
export function waiverCount(text) {
  try {
    const d = typeof text === 'string' && text.trim() ? JSON.parse(text) : null;
    const list = Array.isArray(d) ? d : d && Array.isArray(d.waivers) ? d.waivers : [];
    return list.length;
  } catch {
    return 0;
  }
}

/** The first line of the notes, cut to {@link NOTE_CHARS} characters (an ellipsis when cut); '' without notes. */
export function firstNoteLine(notes) {
  const line = String(notes || '').split('\n').map((l) => l.trim()).find(Boolean) || '';
  return line.length > NOTE_CHARS ? `${line.slice(0, NOTE_CHARS - 1).trimEnd()}…` : line;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/** A card with its heading (an h2: the page's h1 is the workspace's name). */
function card({ role, title, className = '', actions = null }, ...children) {
  const headingId = uid('home-card');
  const heading = h('h2', { class: 'home-card-title', id: headingId, attrs: { tabindex: -1 } }, title);
  return h('section', { class: ['card', 'home-card', className], dataset: { role }, attrs: { 'aria-labelledby': headingId } },
    h('div', { class: 'home-card-head' }, heading, actions),
    ...children);
}

/** A running job's ring (its progress; turning while that is not known). */
function jobRing(fraction) {
  const pct = typeof fraction === 'number' ? Math.round(fraction * 100) : null;
  const bar = svg('circle', { class: 'home-ring-bar', attrs: { cx: 8, cy: 8, r: 6, pathLength: 100, transform: 'rotate(-90 8 8)' } });
  bar.setAttribute('stroke-dasharray', `${pct === null ? 25 : Math.max(pct, 2)} 100`);
  return h('span', { class: ['home-ring', { 'is-indeterminate': pct === null }], attrs: { 'aria-hidden': 'true' } },
    svg('svg', { attrs: { viewBox: '0 0 16 16', width: 16, height: 16, focusable: 'false' } },
      svg('circle', { class: 'home-ring-track', attrs: { cx: 8, cy: 8, r: 6, pathLength: 100 } }), bar));
}

/**
 * Mount the view.
 * @param {HTMLElement} container
 * @param {object} ctx view context (app.js)
 */
export function mount(container, ctx) {
  const { state } = ctx;
  const now = Date.now();
  const ws = state.workspace;
  const inv = state.inventory;
  const parts = {
    recent: state.workspaceData('recent') || [],
    ctSeen: state.workspaceData('ctSeen') || '',
    rdapSeen: state.workspaceData('rdapSeen') || '',
    waivers: state.workspaceData('waivers') || '',
    rollout: state.workspaceData('rollout') || '',
    digests: state.workspaceData('digests') || '',
    expectedCas: state.workspaceData('expectedCas') || [],
    notes: state.workspaceData('notes') || '',
    origins: state.workspaceData('origins')
  };
  const servers = inv.servers.length;
  const empty = isEmptyWorkspace({ ...parts, servers });

  // The title: the workspace's name (Default's "Default workspace"), its facts under it.
  const title = ws.isDefault ? t('home.titleDefault') : workspaceLabel(ws);
  const facts = homeFacts({ servers, recent: parts.recent.length, updatedAt: ws.updatedAt })
    .map((f) => (f.key === 'home.factActivity' ? t(f.key, { when: formatRelative(f.params.at, now) }) : t(f.key, f.params)));
  ctx.setHeading({ title, purpose: empty ? t('home.emptyLead') : facts.join(' · ') || t('nav.home.purpose') });
  ctx.setActions(Button({ label: t('home.manage'), icon: 'briefcase', size: 'sm', dataset: { action: 'home-manage' }, onClick: () => ctx.openWorkspaces() }));

  const root = h('div', { class: ['home', { 'home-empty': empty }], dataset: { role: 'home' } });
  const cleanups = [];

  /* --- the quick start: the palette's box, loaded on first use ------------------------ */
  function quickStart() {
    const hint = h('p', { class: 'home-quick-hint', id: uid('home-quick-hint') }, t('home.quickHint'));
    const input = h('input', {
      type: 'text',
      class: 'home-quick-input',
      dataset: { role: 'home-quick', shortcut: 'focus' },
      attrs: {
        'aria-label': t('home.quickLabel'),
        'aria-describedby': hint.id,
        placeholder: empty ? `${t('home.quick')} ${t('home.quickPem')}` : t('home.quick'),
        autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', enterkeyhint: 'go'
      }
    });
    const results = h('div', { class: 'home-quick-results' });
    let box = null;
    const attach = () => {
      if (box) return;
      box = ctx.loadPalette().then((mod) => {
        if (ctx.signal.aborted || !mod) return null;
        const palette = mod.PaletteBox({
          views: ctx.views, navigate: ctx.navigate, href: ctx.navHref, state, session: ctx.session, input,
          onQuery: (text) => { hint.hidden = !!text; }
        });
        results.append(palette.el);
        return palette;
      }, () => {
        box = null;
        return null;
      });
    };
    input.addEventListener('focus', attach);
    input.addEventListener('input', attach);
    return h('div', { class: 'home-quick' },
      h('div', { class: 'home-quick-box' }, Icon('search', { size: 18, className: 'home-quick-icon' }), input),
      results,
      hint);
  }

  /* --- Needs attention ---------------------------------------------------------------- */
  const attentionList = h('ul', { class: 'home-rows', dataset: { role: 'home-attention-rows' } });
  const attentionMore = h('div', { class: 'home-rows-more' });
  const loading = h('p', { class: 'muted home-loading', dataset: { role: 'home-loading' } }, t('home.loading'));
  const attentionCard = card({ role: 'home-attention', title: t('home.attention'), className: 'home-attention' }, loading, attentionList, attentionMore);
  let digest = null; // lib/homedigest.js once loaded
  let base = null; // its result without the jobs
  let dmarc = []; // the DMARC rows, read last
  let showAll = false;

  const namesText = (names) => {
    const shown = names.slice(0, 3);
    const more = names.length - shown.length;
    return `${shown.join(', ')}${more > 0 ? ` ${t('home.more', { count: more })}` : ''}`;
  };

  function rowTitle(r) {
    const p = { ...r.params };
    if (p.tool) p.tool = t(`nav.${p.tool}`);
    if (typeof p.percent === 'number') p.percent = formatPercent(p.percent);
    for (const k of ['done', 'total', 'verified', 'installed']) if (typeof p[k] === 'number') p[k] = formatNumber(p[k]);
    if (r.nameParam) p[r.nameParam] = namesText(r.names);
    return t(r.key, p);
  }

  function rowDetail(r) {
    const bits = [];
    if (!r.nameParam && r.names.length) bits.push(h('span', { class: 'home-row-names' }, namesText(r.names)));
    if (r.at && r.stale) bits.push(h('span', { class: 'home-row-stale' }, t('home.asOf', { date: formatDate(r.at) })));
    else if (r.at && r.kind !== 'job') bits.push(h('span', { class: 'home-row-when' }, t('home.stale', { when: formatRelative(r.at, Date.now()) })));
    return bits.flatMap((b, i) => (i ? [h('span', { class: 'home-row-sep', attrs: { 'aria-hidden': 'true' } }, ' · '), b] : [b]));
  }

  function rowEl(r) {
    const mark = r.severity === 'running' ? jobRing(r.job ? r.job.fraction : null) : SeverityIcon(r.severity);
    const content = [
      mark,
      h('span', { class: 'home-row-main' },
        h('span', { class: 'home-row-text' }, rowTitle(r)),
        h('span', { class: 'home-row-detail' }, ...rowDetail(r))),
      Icon('chevron-right', { size: 16, className: 'home-row-go' })
    ];
    const dataset = { kind: r.kind, severity: r.severity, stale: r.stale ? '1' : null };
    if (r.link.workspace) {
      return h('li', null, h('button', {
        type: 'button', class: 'home-row', dataset, on: { click: () => ctx.openWorkspaces(r.link.workspace) }
      }, ...content));
    }
    const href = r.kind === 'job' ? ctx.navHref(r.link.view) : ctx.href(r.link.view, r.link.params || {});
    return h('li', null, h('a', { class: 'home-row', href, dataset }, ...content));
  }

  function okRow(result) {
    const bits = [t('home.attentionNone')];
    if (result.facts.ctAt) bits.push(t('home.okCt', { when: formatRelative(result.facts.ctAt, Date.now()) }));
    if (result.facts.regAt) bits.push(t('home.okReg', { when: formatRelative(result.facts.regAt, Date.now()) }));
    return h('li', null, h('div', { class: 'home-row home-row-ok', dataset: { kind: 'ok', severity: 'ok' } },
      SeverityIcon('ok'), h('span', { class: 'home-row-main' }, h('span', { class: 'home-row-text' }, bits.join(' · ')))));
  }

  /** Draw the rows (the jobs read now); the keyboard focus stays on the row it was on. */
  function renderAttention() {
    if (!digest || !base) return;
    const doc = globalThis.document;
    const focused = doc && attentionCard.contains(doc.activeElement) ? doc.activeElement : null;
    const focusKey = focused && focused.dataset ? `${focused.dataset.kind}/${focused.dataset.severity}/${focused.dataset.action || ''}` : null;
    const rows = digest.sortAttention([...base.rows, ...dmarc, ...digest.jobAttention(jobList())]);
    loading.remove();
    clear(attentionList);
    clear(attentionMore);
    const ok = !rows.length && (base.facts.hasData || dmarc.length);
    attentionCard.hidden = !rows.length && !ok;
    if (ok) attentionList.append(okRow(base));
    const shown = showAll ? rows : rows.slice(0, digest.ATTENTION_SHOWN);
    attentionList.append(...shown.map(rowEl));
    if (rows.length > digest.ATTENTION_SHOWN) {
      attentionMore.append(Button({
        label: showAll ? t('home.showFewer') : t('home.showAll', { count: rows.length }), size: 'sm', variant: 'ghost',
        dataset: { action: 'home-show-all' },
        attrs: { 'aria-expanded': String(showAll) },
        onClick: () => {
          showAll = !showAll;
          renderAttention();
          const btn = attentionMore.querySelector('[data-action="home-show-all"]');
          if (btn) btn.focus({ preventScroll: true });
        }
      }));
    }
    if (focusKey && !attentionCard.contains(doc.activeElement)) {
      const again = [...attentionCard.querySelectorAll('.home-row, [data-action]')]
        .find((el) => `${el.dataset.kind}/${el.dataset.severity}/${el.dataset.action || ''}` === focusKey);
      if (again) again.focus({ preventScroll: true });
    }
  }

  /** Count with lib/homedigest.js (after the first paint), then the DMARC history in an idle moment. */
  function loadAttention() {
    const history = state.workspaceData('reportHistory') || '';
    import('../lib/homedigest.js').then((mod) => {
      if (ctx.signal.aborted) return;
      digest = mod;
      base = mod.attention({ parts, jobs: [], serverWarnings: inv.warnings.length, now: Date.now() });
      renderAttention();
      cleanups.push(onJobs(renderAttention));
      if (!history.trim()) return;
      const idle = globalThis.requestIdleCallback || ((fn) => setTimeout(fn, 200));
      idle(() => {
        if (ctx.signal.aborted) return;
        import('../lib/dmarchistory.js').then(({ readHistory, rollup }) => {
          if (ctx.signal.aborted) return;
          dmarc = mod.dmarcAttention(rollup(readHistory(history), { now: Date.now(), days: mod.DMARC_DAYS }));
          renderAttention();
        }, () => ctx.checkOutdated());
      });
    }, () => {
      loading.textContent = '';
      attentionCard.hidden = true;
      ctx.checkOutdated();
    });
  }

  /* --- Recent domains ------------------------------------------------------------------- */
  function recentCard() {
    const entries = recentEntries(parts.recent);
    if (!entries.length) return null;
    const list = h('ul', { class: 'home-recent-list' }, entries.map((e) => {
      const links = e.actions.map((a) => ({ label: t(`home.qa.${a.view}`), full: t(`nav.${a.view}`), href: ctx.href(a.view, a.params), view: a.view }));
      // On a phone the quick actions sit behind a "⋯" menu (style.css shows one or the other).
      const menu = links.length ? MenuButton({
        label: t('home.recentMore', { domain: e.value }),
        className: 'home-recent-menu',
        dataset: { action: 'home-recent-more' },
        items: links.map((l) => ({ label: l.full, href: l.href, dataset: { view: l.view } }))
      }) : null;
      return h('li', { class: 'home-recent-row', dataset: { value: e.value } },
        h('button', {
          type: 'button',
          class: 'home-recent-name mono',
          title: t('home.recentTarget', { domain: e.value }),
          dataset: { action: 'home-target' },
          on: {
            click: () => {
              if (ctx.session.setTarget(e.value)) announce(t('home.targetSet', { domain: e.value }));
            }
          }
        }, e.value),
        e.at ? h('span', { class: 'home-recent-when muted' }, formatRelative(e.at, now)) : h('span', { class: 'home-recent-when' }),
        h('span', { class: 'home-recent-actions' }, links.map((l) => h('a', {
          class: 'home-recent-action', href: l.href, dataset: { view: l.view }, attrs: { 'aria-label': `${l.full}: ${e.value}` }
        }, l.label))),
        menu ? menu.el : null);
    }));
    return card({ role: 'home-recent', title: t('home.recent'), className: 'home-recent' }, list);
  }

  /* --- Results in this tab ------------------------------------------------------------- */
  function keptCard() {
    const list = keptResults(ctx.session, ctx.views);
    if (!list.length) return null;
    const iconOf = new Map(ctx.views.map((v) => [v.id, v.icon]));
    return card({ role: 'home-kept', title: t('home.kept'), className: 'home-kept' },
      h('ul', { class: 'home-kept-list' }, list.map((k) => {
        const tags = [];
        if (k.status) {
          if (k.status.error) tags.push(Tag(t('home.keptErrors', { count: k.status.error }), { variant: 'error', icon: 'x-circle' }));
          if (k.status.warn) tags.push(Tag(t('home.keptWarnings', { count: k.status.warn }), { variant: 'warn', icon: 'alert' }));
          if (!k.status.error && !k.status.warn) tags.push(Tag(t('home.keptClean'), { variant: 'ok', icon: 'check' }));
        }
        return h('li', null, h('a', { class: 'home-kept-row', href: ctx.navHref(k.view), dataset: { view: k.view } },
          Icon(iconOf.get(k.view) || 'file', { size: 16, className: 'home-kept-icon' }),
          h('span', { class: 'home-kept-tool' }, t(`nav.${k.view}`)),
          k.subject ? h('span', { class: 'home-kept-subject mono' }, k.subject) : null,
          tags.length ? h('span', { class: 'home-kept-tags' }, tags) : null,
          h('span', { class: 'home-kept-when muted' }, formatRelative(k.at, now))));
      })));
  }

  /* --- Start a job ---------------------------------------------------------------------- */
  // The cards while the workspace is new and they were never folded; a compact list after that.
  function jobsCard() {
    const expanded = !!state.settings.startTasks && empty;
    const fold = expanded ? Button({
      label: t('home.jobsFold'), size: 'sm', variant: 'ghost', dataset: { action: 'start-hide' },
      onClick: () => {
        state.updateSettings({ startTasks: false });
        const next = jobsCard();
        el.replaceWith(next);
        const heading = next.querySelector('.home-card-title');
        if (heading) heading.focus({ preventScroll: true });
      }
    }) : null;
    const el = card({ role: 'start-picker', title: t('home.jobs'), className: ['start-picker', 'home-jobs', { 'is-compact': !expanded }], actions: fold },
      expanded ? h('p', { class: 'muted home-card-lead' }, t('start.lead')) : null,
      StartTaskList({ views: ctx.views, href: (view) => ctx.navHref(view), compact: !expanded }));
    return el;
  }

  /* --- This workspace ------------------------------------------------------------------- */
  function workspaceCard() {
    const origins = parts.origins && Array.isArray(parts.origins.entries) ? parts.origins.entries.length : 0;
    const waivers = waiverCount(parts.waivers);
    const counts = [
      servers ? t('home.factServers', { count: servers }) : null,
      parts.expectedCas.length ? t('home.wsCas', { count: parts.expectedCas.length }) : null,
      origins ? t('home.wsOrigins', { count: origins }) : null,
      waivers ? t('home.wsWaivers', { count: waivers }) : null
    ].filter(Boolean);
    const note = firstNoteLine(parts.notes);
    return card({ role: 'home-workspace', title: t('home.workspace'), className: 'home-ws' },
      h('p', { class: 'home-ws-counts' }, counts.length ? counts.join(' · ') : t('home.wsEmpty')),
      note ? h('p', { class: 'home-ws-note muted' }, `“${note}”`) : null,
      h('p', { class: 'home-ws-links' },
        h('a', { href: ctx.navHref('inventory'), dataset: { view: 'inventory' } }, t('nav.inventory')),
        h('span', { class: 'home-row-sep', attrs: { 'aria-hidden': 'true' } }, ' · '),
        h('button', { type: 'button', class: 'home-link-btn home-ws-manage', dataset: { action: 'home-ws-manage' }, on: { click: () => ctx.openWorkspaces() } },
          t('home.manage'))));
  }

  /* --- Set up this workspace ------------------------------------------------------------ */
  function setupCard() {
    if (state.settings.homeSetup === false) return null;
    const items = setupItems({
      servers, expectedCas: parts.expectedCas, rdapSeen: parts.rdapSeen, workspaces: state.workspaces.length, isDefault: ws.isDefault
    });
    if (items.every((i) => i.done)) return null;
    const action = {
      servers: () => h('a', { class: 'home-setup-go', href: ctx.navHref('inventory'), dataset: { view: 'inventory' } }, t('nav.inventory')),
      cas: () => h('button', { type: 'button', class: 'home-link-btn home-setup-go', dataset: { action: 'home-setup-cas' }, on: { click: () => ctx.openWorkspaces('expected') } }, t('home.workspaces')),
      portfolio: () => h('a', { class: 'home-setup-go', href: ctx.navHref('portfolio'), dataset: { view: 'portfolio' } }, t('home.setupOpen')),
      workspaces: () => h('button', { type: 'button', class: 'home-link-btn home-setup-go', dataset: { action: 'home-setup-new' }, on: { click: () => ctx.openWorkspaces('new') } }, t('home.setupNew'))
    };
    const text = { servers: 'home.setupServers', cas: 'home.setupCas', portfolio: 'home.setupPortfolio', workspaces: 'home.setupWorkspaces' };
    const hide = Button({
      label: t('home.setupHide'), size: 'sm', variant: 'ghost', dataset: { action: 'home-setup-hide' },
      onClick: () => {
        state.updateSettings({ homeSetup: false });
        el.remove();
        const title = globalThis.document.getElementById('page-title');
        if (title) title.focus({ preventScroll: true });
      }
    });
    const el = card({ role: 'home-setup', title: t('home.setup'), className: 'home-setup', actions: hide },
      h('ul', { class: 'home-setup-list' }, items.map((item) => h('li', { class: ['home-setup-item', { 'is-done': item.done }], dataset: { item: item.id, done: item.done ? '1' : '0' } },
        item.done ? Icon('check-circle', { size: 18, className: 'home-setup-mark' }) : h('span', { class: 'home-setup-mark home-setup-todo', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'sr-only' }, `${t(item.done ? 'home.setupDone' : 'home.setupTodo')}: `),
        h('span', { class: 'home-setup-text' }, t(text[item.id])),
        action[item.id]()))));
    return el;
  }

  /* --- assemble ------------------------------------------------------------------------- */
  const privacy = h('p', { class: 'home-privacy', dataset: { role: 'home-privacy' } }, Icon('lock', { size: 14 }), h('span', null, t('home.privacy')));
  root.append(quickStart());
  const work = jobList().length > 0 || inv.warnings.length > 0;
  if (empty) {
    if (work) root.append(attentionCard);
    root.append(jobsCard(), setupCard(), privacy);
  } else {
    root.append(attentionCard,
      h('div', { class: 'home-grid' },
        h('div', { class: 'home-col home-col-main' }, recentCard(), keptCard()),
        h('div', { class: 'home-col home-col-side' }, jobsCard(), workspaceCard(), setupCard())),
      privacy);
  }
  container.append(root);
  if (!empty || work) loadAttention();

  // "Delete all local data" (here or in another tab): Home opens again on what is kept now. A
  // workspace switch re-mounts it (app.js); a change another tab makes shows on Home's next visit.
  if (typeof state.subscribe === 'function') {
    const off = state.subscribe(({ key }) => {
      if (key !== 'cleared') return;
      queueMicrotask(() => {
        if (!ctx.signal.aborted) ctx.navigate('home', {}, { force: true });
      });
    });
    if (typeof off === 'function') cleanups.push(off);
  }

  ctx.onCleanup(() => {
    for (const fn of cleanups.splice(0)) fn();
  });
}

export default { id, titleKey, icon, mount };
