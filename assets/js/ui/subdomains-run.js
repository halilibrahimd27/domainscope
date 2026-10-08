/**
 * ui/subdomains-run.js — the progress panel and the results of a Subdomains scan run.
 *
 * Split out of views/subdomains.js so the start route carries only the search page: the view
 * loads this module with its first scan (views/subdomains.js loadRunUi, at the same time as the
 * DoH client), and the shell modulepreloads it once the page is idle (app.js VIEWS[].preload), so
 * a Scan rarely waits for it. A kept run (another view and back, a language switch) is drawn at
 * once from the module already loaded. The strings stay with the view (views/subdomains.js
 * registers every sub.* key), so every label reads the same whichever module draws it.
 *
 * - buildRunUI: the run header (title, time, progress bar, Copy summary, notify), the stage pills
 *   and the result tabs — Overview (stat cards, alerts, technique chips, the SSL Targets
 *   hand-off), Hosts (exports, filters, the table), Origins (the ORIGIN panel with its sweep
 *   command, exclusions and owner lookups) and Sources (per-source chips, status lines, related
 *   domains) — replaying what the run already has and following it live;
 * - the pure helpers only the results use (stat-card filters, the host table filter, per-source
 *   chip states, the origin export, the Copy summary facts), exported for the tests.
 *
 * DOM-free at import time (the tests import it in Node).
 */
import { SCAN_STAGES } from '../lib/scanplan.js';
import { t, formatDuration, formatNumber, formatDateTime, hasString, formatDate } from '../i18n.js';
import { hostSegments, summaryAlerts, initialSubTab, SUB_TABS, subTabParams, nextAutoTab, subTabBadges } from '../lib/subtabs.js';
import { h, clear, scrollBehavior, uid } from './dom.js';
import { sourceHealthSummary, SOURCES } from '../lib/sourceinfo.js';
import {
  ProgressBar, Alert, Icon, StatCard, SegmentedControl, checkbox, DataTable, Badge, ipSortValue, TruncatedList, KindBadge,
  CopyButton, toast, Button, CodeBlock, textInput, ButtonLink, Disclosure, EmptyState, Tabs, announce, ErrorBanner
} from './components.js';
import { SummaryButton } from './summary-button.js';
import { permalinkParams } from '../lib/summarycore.js';
import { NotifyButton } from './jobs.js';
import { scanHostRows, toCsv, toJson } from '../lib/export.js';
import { downloadText, timestampedName } from './download.js';
import { originIndex } from '../lib/originmap.js';
import { state as stateSingleton } from '../state.js';
import { registrableDomain } from '../lib/domain.js';
import { errorKind } from '../lib/util.js';
import {
  CHIP_ERRORS, DNS_ORIGINS, FILTERS, SHELLS, SOURCE_NAMES, WARNING_CODES, countHosts, dayText, isProxiedOriginHost, isResolving,
  languageName, liveHosts, loadOnFirstUse, matchesFilter, namesText, networkOwner, originOverview, originSweepFor,
  realOriginNetworks, reasonText, routeTargets, sourceHealthText, sourceNote, techniqueCounts
} from '../views/subdomains.js';

/** Filters offered in the segmented control. */
export const SEGMENT_FILTERS = Object.freeze(['all', 'resolving', 'cloudflare', 'direct', 'unresolved']);

/** Companion CLI, relative to the site root (published with the Pages site). */
export const CLI_PATH = 'cli/ssl_origin_scan.py';

/** Stages shown as pills ("done" is the panel state). */
export const SHOWN_STAGES = Object.freeze(SCAN_STAGES.filter((s) => s !== 'done'));

/** Origin-hint kinds with a localized label (sub.hint.<kind>). */
export const HINT_KINDS = Object.freeze(['known', 'resolver-leak', 'history', 'sibling-domain', 'direct-sibling', 'spf', 'mx', 'zone']);

/** Stat card → filter. */
const STAT_FILTERS = {
  found: 'all', resolving: 'resolving', cloudflare: 'cloudflare', cdn: 'cdn', direct: 'direct', unresolved: 'unresolved', dangling: 'dangling'
};

/** CSV columns (English headers, like the other exports). */
const CSV_COLUMNS = Object.freeze([
  { key: 'name', header: 'Subdomain' },
  { key: 'status', header: 'DNS status' },
  { key: 'kind', header: 'Classification' },
  { key: 'provider', header: 'Provider' },
  { key: 'hidesOrigin', header: 'Origin hidden' },
  { key: 'dangling', header: 'Dangling CNAME' },
  { key: 'ipv4', header: 'IPv4' },
  { key: 'ipv6', header: 'IPv6' },
  { key: 'cnames', header: 'CNAME chain' },
  { key: 'ttl', header: 'TTL' },
  { key: 'servers', header: 'Servers' },
  { key: 'origins', header: 'Found by' },
  { key: 'wildcardSuspect', header: 'Wildcard suspect' },
  { key: 'resolver', header: 'Resolver' },
  { key: 'error', header: 'Error' }
]);

/**
 * Localized label of an origin id ('input', 'wordlist', 'dns-mine:MX', a source id …).
 * @param {string} origin
 * @returns {string}
 */
export function originLabel(origin) {
  const o = String(origin ?? '');
  if (o.startsWith('dns-mine:')) return t('sub.origin.dnsmine', { record: o.slice('dns-mine:'.length) });
  if (['input', 'cert', 'bruteforce', 'wordlist', 'permutation', 'recursive', 'zone'].includes(o)) return t(`sub.origin.${o}`);
  return SOURCE_NAMES[o] || o;
}

/** Tooltip of an origin chip (null when the label says it all). */
function originTitle(origin) {
  const o = String(origin ?? '');
  if (o.startsWith('dns-mine:')) return t('sub.origin.dnsmineTitle', { record: o.slice('dns-mine:'.length) });
  if (DNS_ORIGINS.has(o)) return t('sub.origin.dnsTitle');
  if (o === 'zone') return t('sub.origin.zoneTitle');
  return null;
}

/**
 * The `origin` block of the JSON export: the networks and the POSIX command the ORIGIN panel shows
 * (no wildcard suspects, no IPv6 /48), with the panel's exclusions applied — whoever runs the
 * exported command never probes an address the user excluded — and what they did (`exclude`).
 * @param {object|null} result ScanResult
 * @param {string[]} [exclude] the tokens typed into the panel's Exclude box
 * @param {object|null} [origins] the origin map read now
 * @returns {{ networks: object[], hints: object[], cliSuggestion: string|null,
 *   exclude: { requested: string[], emitted: string[], excluded: string[], unused: string[], invalid: string[] }|null }}
 */
export function originExport(result, exclude = [], origins = null) {
  const r = result || {};
  const tokens = Array.isArray(exclude) && exclude.length ? exclude.map(String) : null;
  const sweep = originSweepFor(r, { shell: 'posix', exclude: tokens, origins });
  return {
    networks: realOriginNetworks(r.originNetworks, r.hosts).networks,
    hints: r.originHints || [],
    cliSuggestion: sweep.command,
    exclude: tokens
      ? { requested: tokens, emitted: sweep.emitted, excluded: sweep.excluded, unused: sweep.excludeUnused, invalid: sweep.excludeDropped }
      : null
  };
}

/**
 * Which "only through DNS" sentence the technique summary may show (i18n key), or null. The
 * plain claim (no queried source returned the names) needs every selected source to have
 * answered completely; with a source off-quota, down, cut at its page limit or partial the
 * qualified sentence is used, and with no passive source at all nothing is claimed.
 * @param {number} count names found only by DNS discovery
 * @param {string[]} sources source ids selected for the scan
 * @param {object[]} health lib/sources.sourceHealthSummary() of the scan
 * @returns {'sub.tech.dnsOnly'|'sub.tech.dnsOnlyIncomplete'|null}
 */
export function dnsOnlyNoteKey(count, sources, health) {
  if (!(Number(count) > 0) || !Array.isArray(sources) || !sources.length) return null;
  const list = Array.isArray(health) ? health : [];
  const complete = sources.every((sid) => {
    const hl = list.find((x) => x && x.source === sid);
    return !!hl && (hl.state === 'ok' || hl.state === 'empty') && !hl.truncated;
  });
  return complete ? 'sub.tech.dnsOnly' : 'sub.tech.dnsOnlyIncomplete';
}

/**
 * Row predicate of the subdomain table for a filter, or null when nothing is hidden. Whether
 * wildcard suspects are shown is read from `prefs.showWildcard` for every row, so suspects that
 * stream in after the filter was chosen are hidden like the ones already listed.
 * @param {string} filter one of {@link FILTERS}
 * @param {{ showWildcard: boolean }} prefs live preferences (the session)
 * @param {object[]} hosts the hosts listed so far
 * @returns {((host: object) => boolean)|null}
 */
export function hostTableFilter(filter, prefs, hosts) {
  const f = FILTERS.includes(filter) ? filter : 'all';
  if (f === 'all' && (prefs.showWildcard || !(hosts || []).some((x) => x && x.wildcardSuspect))) return null;
  return (x) => (prefs.showWildcard || !x.wildcardSuspect) && matchesFilter(x, f);
}

/**
 * Aggregate the per-domain SourceResults of one source into a chip state.
 * @param {object[]} results
 * @param {string} sourceId
 * @param {number} expected number of domains queried
 * @returns {{ state: 'pending'|'ok'|'partial'|'error', names: number, done: number, expected: number,
 *   errorKind: string|null, error: string|null }}
 */
export function sourceChipState(results, sourceId, expected) {
  const mine = (results || []).filter((r) => r.source === sourceId);
  const names = new Set();
  mine.forEach((r) => (r.names || []).forEach((n) => names.add(n)));
  const failed = mine.filter((r) => !r.ok);
  const partial = mine.some((r) => r.ok && r.partial);
  let state = 'pending';
  if (expected > 0 && mine.length >= expected) {
    if (failed.length === mine.length) state = 'error';
    else if (failed.length || partial) state = 'partial';
    else state = 'ok';
  }
  const err = failed[0] || mine.find((r) => r.partial) || null;
  return { state, names: names.size, done: mine.length, expected, errorKind: err ? err.errorKind : null, error: err ? err.error : null };
}

/** Sort key that groups siblings (reversed labels). */
function hostSortKey(name) {
  return String(name || '').split('.').reverse().join('.');
}

/**
 * A host name as text runs that wrap only after a dot (lib/subtabs.hostSegments): each label is
 * one unbreakable run (`.sub-seg`) with a <wbr> before the next, so a narrow cell never splits
 * `old-shop` at its hyphen. A label too long to keep is plain text, which the name's
 * `overflow-wrap: anywhere` breaks where it must. The text (and a copy of it) is the name, unchanged.
 * @param {string} name
 * @returns {Array<Node|string>}
 */
export function hostNameNodes(name) {
  const out = [];
  for (const seg of hostSegments(name)) {
    if (out.length) out.push(h('wbr'));
    out.push(seg.keep ? h('span', { class: 'sub-seg' }, seg.text) : seg.text);
  }
  return out;
}

/** "Fastly, Vercel" — providers of the CDN / platform hosts (at most 3). */
function providerHint(hosts) {
  const names = [];
  for (const x of hosts || []) {
    const c = x.classification || {};
    if (x.wildcardSuspect || !(c.kind === 'cdn' || c.kind === 'platform') || !c.provider) continue;
    if (!names.includes(c.provider.name)) names.push(c.provider.name);
    if (names.length > 3) break;
  }
  if (!names.length) return null;
  return names.length > 3 ? `${names.slice(0, 3).join(', ')}…` : names.join(', ');
}

/** Schedule `fn` at most once per animation frame. */
function frameThrottle(fn) {
  let queued = false;
  const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
  return () => {
    if (queued) return;
    queued = true;
    raf(() => {
      queued = false;
      fn();
    });
  };
}

/** Call `fn` at most every `ms` milliseconds (the last call always runs). */
function timeThrottle(fn, ms) {
  let timer = null;
  let last = 0;
  return () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      last = Date.now();
      fn();
    }, Math.max(0, ms - (Date.now() - last)));
  };
}

/**
 * The ORIGIN panel's exclusions of each run (`{ raw, tokens }`), kept for the page session so a
 * re-mount (another view and back, a language switch) keeps them; keyed by the run object, so a
 * new scan starts without any and an old run goes with its own.
 */
const originExcludes = new WeakMap();

/**
 * The facts of "Copy summary" (lib/summary subdomainsSummary) for a finished or cancelled run,
 * null while it runs or after an error: the stat cards of the hosts listed, the dangling names,
 * the failed sources and the ORIGIN panel's numbers. A cancelled run has no ORIGIN panel (only a
 * finished result is analysed): its proxied hosts are counted from the hosts found so far, with no
 * candidate or network part, which were never looked for.
 * @param {object} run
 * @returns {object|null}
 */
export function subdomainsSummaryFacts(run) {
  if (!run || (run.status !== 'done' && run.status !== 'cancelled')) return null;
  const hosts = liveHosts(run);
  const o = run.result ? originOverview(run.result) : null;
  return {
    domains: run.config.domains,
    status: run.status,
    counts: countHosts(hosts),
    proxied: o ? o.proxied.length : hosts.filter(isProxiedOriginHost).length,
    withCandidates: o ? o.proxied.filter((p) => p.known.length || p.zone.length || p.leaks.length || p.history.length || p.siblings.length).length : 0,
    networks: o ? o.networks.length : 0,
    dangling: hosts.filter((x) => !x.wildcardSuspect && x.classification && x.classification.dangling).map((x) => x.name),
    failedSources: sourceHealthSummary(run.sourceResults).filter((x) => !x.ok && x.errorKind !== 'abort').length,
    at: run.finishedAt
  };
}

/**
 * Build the progress panel and the results for one run, replay what the run already has
 * and follow it live.
 * @param {object} run a Subdomains run (views/subdomains.js createRun)
 * @param {import('../app.js').ViewContext} ctx the mounted view's context
 * @param {{ session: object, onFinish: () => void, onScanWith: (domains: string[]) => Promise<void> }} opts
 *   session: the view's page session (the chosen tab, filter, wildcard and shell choices live there);
 *   onFinish: the run ended; onScanWith: Sources › Related domains "Scan too"
 * @returns {{ el: HTMLElement, dispose: () => void, showTab: (tabId: string) => void }}
 */
export function buildRunUI(run, ctx, { session, onFinish, onScanWith }) {
  const domainsLabel = run.config.domains.join(', ');
  const inventory = run.config.inventoryServers > 0;
  const subject = run.config.domains[0] || '';
  // Live view of the hosts: full records plus streamed partials (task: rows appear during the
  // wordlist / permutation stages, not only once resolve starts). The final result reconciles.
  const listHosts = () => liveHosts(run);
  /** Proxied host names with a host-specific origin candidate (resolver leak / history / sibling). */
  let originCandidates = new Set();

  /* --- progress panel --------------------------------------------------------- */
  const title = h('h2', { class: 'sub-run-title' });
  const meta = h('div', { class: 'sub-run-meta' });
  const stageList = h('ol', { class: 'sub-stages', attrs: { 'aria-label': t('progress.label') } });
  const stageEls = {};
  for (const s of SHOWN_STAGES) {
    const el = h('li', { class: 'sub-stage', dataset: { stage: s, state: 'pending' } },
      h('span', { class: 'sub-stage-dot', attrs: { 'aria-hidden': 'true' } }),
      h('span', { class: 'sub-stage-label' }, t(`sub.stage.${s}`)),
      h('span', { class: 'sub-stage-note' }));
    stageEls[s] = el;
    stageList.append(el);
  }
  const progress = ProgressBar({ label: t('sub.progress.starting'), indeterminate: true });
  progress.el.classList.add('sub-progress');
  const chips = h('div', { class: 'sub-chips', attrs: { role: 'group', 'aria-label': t('sub.opt.sources') } });
  const chipEls = new Map();
  // "crt.sh still fetching (up to 12 s)" while the DNS sweep already runs — so the wait is not
  // mistaken for another stage (task 3). Both it and the per-source notes are news worth
  // announcing, but they live in the Sources tab, whose panel is hidden while another tab is open
  // (and a hidden live region says nothing): sourceLive, in the run's header, speaks each new line.
  const sourceWaitNote = h('div', { class: 'sub-src-wait', hidden: true });
  const sourceNotes = h('div', { class: 'sub-src-notes' });
  const sourceLive = h('div', { class: 'sr-only sub-src-live', attrs: { 'aria-live': 'polite' } });
  const notice = h('div', { class: 'sub-run-notice' });
  // How this run used an imported zone file (exact: its names only; discover: added as seeds).
  const zoneBanner = run.config.zoneMode === 'exact' || run.config.zoneMode === 'discover'
    ? Alert({ variant: 'info', compact: true, icon: 'file-text', message: t(`sub.zone.${run.config.zoneMode}`) })
    : null;
  if (zoneBanner) {
    zoneBanner.classList.add('sub-zone-banner');
    zoneBanner.dataset.zoneMode = run.config.zoneMode;
  }
  // How this run used names handed over by the Reverse DNS view.
  const handoffMode = run.config.handoff ? run.config.handoff.mode : null;
  const handoffBanner = handoffMode === 'exact' || handoffMode === 'discover'
    ? Alert({ variant: 'info', compact: true, icon: 'swap', message: t(`sub.handoff.${handoffMode}`) })
    : null;
  if (handoffBanner) {
    handoffBanner.classList.add('sub-zone-banner');
    handoffBanner.dataset.handoffMode = handoffMode;
  }
  // "Copy summary": what the stat cards, the summary alerts and the ORIGIN panel show (lib/summary.js).
  // It sits in the run's header, so every tab offers it.
  const summaryFacts = () => subdomainsSummaryFacts(run);
  const summary = SummaryButton({
    kind: 'subdomains',
    facts: summaryFacts,
    disabled: true,
    url: () => ctx.shareUrl(permalinkParams('subdomains', { domain: run.config.domains.join(','), run: '1' }))
  });
  // The run's header stays above the tabs: its title, time, Copy summary and progress bar (whose
  // label names the current stage) are in view whichever tab is open; the stage pills and the
  // per-source chips are in the Sources tab.
  const panel = h('section', { class: 'sub-run card', dataset: { status: run.status }, attrs: { 'aria-label': t('progress.label') } },
    h('div', { class: 'sub-run-head' },
      h('span', { class: 'sub-run-icon', attrs: { 'aria-hidden': 'true' } }, Icon('layers', { size: 18 })),
      h('div', { class: 'sub-run-titles' }, title, meta),
      summary.el,
      NotifyButton(() => run.job || null)),
    progress, zoneBanner, handoffBanner, notice, sourceLive);

  /** Source lines already spoken: a re-render (every source event redraws them) says nothing new. */
  const spoken = new Set();
  function speakSource(text) {
    if (!text || spoken.has(text)) return;
    spoken.add(text);
    sourceLive.append(h('p', null, text));
  }

  /** Grace-window default (lib/scanner DEFAULT_SOURCE_GRACE_MS); only the wording seconds. */
  const SOURCE_GRACE_SECONDS = 12;
  function renderSourceWait() {
    clear(sourceWaitNote);
    // Only while running, and only for sources the scanner said were still fetching that have not
    // settled since (the chip is still pending / spinning).
    const waiting = run.status === 'running' && run.sourceWait && Array.isArray(run.sourceWait.sources)
      ? run.sourceWait.sources.filter((sid) => sourceChipState(run.sourceResults, sid, Math.max(1, run.sourcePlan.domains.length || run.config.domains.length)).state === 'pending')
      : [];
    sourceWaitNote.hidden = !waiting.length;
    if (!waiting.length) return;
    const list = waiting.map((sid) => SOURCE_NAMES[sid] || sid).join(', ');
    const text = t('sub.srcWait', { list, seconds: SOURCE_GRACE_SECONDS, count: waiting.length });
    sourceWaitNote.append(Icon('clock', { size: 14 }), h('span', null, text));
    speakSource(text);
  }

  function renderTitle() {
    title.textContent = run.status === 'running' ? t('sub.run.title', { domains: domainsLabel }) : t('sub.run.titleDone', { domains: domainsLabel });
    panel.dataset.status = run.status;
    root.dataset.status = run.status;
  }

  function renderMeta() {
    const end = run.finishedAt || new Date();
    const elapsed = formatDuration(end - run.startedAt);
    if (run.status === 'running') {
      meta.textContent = t('sub.run.elapsed', { time: elapsed });
    } else if (run.status === 'done') {
      const total = run.result && run.result.stats ? run.result.stats.dnsQueries : null;
      const q = Number.isFinite(total) && Number.isFinite(run.queriesAtStart) ? total - run.queriesAtStart : total;
      meta.textContent = `${Number.isFinite(q) ? t('sub.run.finished', { time: elapsed, queries: formatNumber(q) }) : t('sub.run.finishedShort', { time: elapsed })} · ${formatDateTime(end)}`;
    } else if (run.status === 'cancelled') {
      meta.textContent = t('sub.run.cancelledShort');
    } else {
      meta.textContent = '';
    }
  }

  /** Stage → new names it found (only known once the scan is done). */
  const FOUND_BY_STAGE = { mining: (c) => c.mine, bruteforce: (c) => c.wordlist, permutations: (c) => c.permutation + c.recursive };
  function renderStages() {
    const tech = run.result ? techniqueCounts(run.result.hosts) : null;
    // Mining may run next to the sources: only the first running stage is the "current step".
    const current = SHOWN_STAGES.find((s) => run.stages[s].state === 'active');
    for (const s of SHOWN_STAGES) {
      const st = run.stages[s];
      const el = stageEls[s];
      el.dataset.state = st.state;
      const note = el.querySelector('.sub-stage-note');
      let text = '';
      let noteTitle = '';
      // bruteforce: the stage info carries the total; permutations: learned from its progress.
      const total = Number(st.info && st.info.total) || Number(st.candidates) || 0;
      if (st.state === 'skipped') text = t('sub.stage.skipped');
      else if (st.state === 'active' && (s === 'bruteforce' || s === 'permutations') && total > 0) {
        // Candidate count plus a live "hits" count (names that resolved so far, streamed via
        // onFound) — so the pill shows progress, not just how many names will be tried.
        const hits = listHosts().length;
        text = t('sub.stage.candidates', { count: total }) + (hits > 0 ? ` ${t('sub.stage.liveHits', { count: hits })}` : '');
      } else if (tech && st.state === 'done' && FOUND_BY_STAGE[s]) {
        const n = FOUND_BY_STAGE[s](tech);
        text = t('sub.stage.found', { count: formatNumber(n) });
        noteTitle = t('sub.stage.foundTitle', { count: n });
        el.dataset.found = String(n);
      }
      note.textContent = text;
      el.title = noteTitle;
      if (s === current) el.setAttribute('aria-current', 'step');
      else el.removeAttribute('aria-current');
    }
  }

  const PROGRESS_KEYS = { sources: 1, mining: 1, wildcard: 1, bruteforce: 1, permutations: 1, resolve: 1, hints: 1, done: 1 };
  const renderProgress = frameThrottle(() => {
    if (run.status !== 'running') return;
    const p = run.progress;
    if (!p.stage) {
      progress.setIndeterminate(true);
      return;
    }
    progress.setLabel(PROGRESS_KEYS[p.stage] ? t(`sub.progress.${p.stage}`) : t('sub.progress.starting'));
    if (p.total > 0) progress.set(p.done, p.total);
    else progress.setIndeterminate(true);
  });

  function chipFor(sourceId) {
    let el = chipEls.get(sourceId);
    if (!el) {
      el = h('span', { class: 'sub-chip', dataset: { source: sourceId, state: 'pending' } });
      chipEls.set(sourceId, el);
      chips.append(el);
    }
    return el;
  }

  /** The passive sources this run asks (the scanner's plan once it started, else the config). */
  const sourceIds = () => (run.sourcePlan.sources.length ? run.sourcePlan.sources : run.config.sources);

  function renderChips() {
    const plan = run.sourcePlan;
    const ids = sourceIds();
    const expected = Math.max(1, plan.domains.length || run.config.domains.length);
    chips.hidden = ids.length === 0;
    sourcesNone.hidden = ids.length > 0;
    renderQuotas(ids);
    const health = new Map(sourceHealthSummary(run.sourceResults).map((x) => [x.source, x]));
    for (const sid of ids) {
      const s = sourceChipState(run.sourceResults, sid, expected);
      // A finished (cancelled / failed) run has no pending sources left: nothing will arrive.
      if (run.status !== 'running' && s.state === 'pending') s.state = run.sourceResults.some((r) => r.source === sid) ? 'partial' : 'cancelled';
      const el = chipFor(sid);
      clear(el);
      let value;
      let tip = s.error || '';
      let state = s.state;
      const hl = health.get(sid);
      if (s.state === 'pending') value = s.done ? `${s.done}/${s.expected}` : t('sub.chip.waiting');
      else if (s.state === 'cancelled') value = t('sub.chip.err.abort');
      else if (hl && !(s.state === 'error' && s.errorKind === 'abort')) {
        // Every domain answered: the clear, localized health text (quota, down + fallback …).
        const text = sourceHealthText(hl);
        value = text.short;
        tip = text.detail;
        if (text.tone === 'limited') state = 'limited';
        el.dataset.health = hl.state;
      } else if (s.state === 'error') value = t(`sub.chip.err.${CHIP_ERRORS.includes(s.errorKind) ? s.errorKind : 'unknown'}`);
      else value = `${t('sub.chip.names', { count: s.names })}${s.state === 'partial' ? ` · ${t('sub.chip.partial')}` : ''}`;
      el.dataset.state = state;
      const iconName = { ok: 'check-circle', partial: 'alert', limited: 'clock', error: 'x-circle', cancelled: 'minus-circle' }[state];
      el.append(iconName ? Icon(iconName, { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'sub-chip-name' }, SOURCE_NAMES[sid] || sid),
        h('span', { class: 'sub-chip-value' }, value));
      el.title = tip;
    }
    renderSourceNotes(ids, expected, health);
    renderBadges();
  }

  /** The free limits of the sources this run asks (the same notes as Advanced options). */
  function renderQuotas(ids) {
    clear(quotaList);
    quotaBox.hidden = ids.length === 0;
    for (const sid of ids) {
      const def = SOURCES.find((x) => x.id === sid);
      const note = def ? sourceNote(def) : '';
      if (!note) continue;
      quotaList.append(h('li', { class: 'sub-src-quota', dataset: { source: sid } },
        h('span', { class: 'sub-src-quota-name' }, SOURCE_NAMES[sid] || sid), h('span', { class: 'sub-src-quota-note' }, note)));
    }
  }

  /**
   * One clear line per source that did not simply work (quota used up, temporarily down with
   * the CT fallback, timed out, page limit) — shown once that source has answered for every
   * domain. After the scan, a reassuring line tells how much DNS found on its own.
   */
  function renderSourceNotes(ids, expected, health) {
    clear(sourceNotes);
    const lines = [];
    for (const sid of ids) {
      const hl = health.get(sid);
      if (!hl || sourceChipState(run.sourceResults, sid, expected).state === 'pending') continue;
      if (hl.state === 'empty' || (hl.state === 'ok' && !(hl.truncated && hl.available > hl.names))) continue;
      if (hl.errorKind === 'abort') continue;
      const text = sourceHealthText(hl);
      lines.push(h('li', { class: 'sub-src-note', dataset: { source: sid, tone: text.tone, health: hl.state } },
        Icon({ ok: 'info', warn: 'alert', limited: 'clock', error: 'x-circle' }[text.tone] || 'info', { size: 14 }),
        h('span', null, text.detail)));
      speakSource(text.detail);
    }
    if (!lines.length) return;
    const failed = [...health.values()].some((x) => !x.ok);
    const tail = run.result && failed
      ? h('p', { class: 'sub-src-dns' }, t('sub.srcnote.dnsFound', { count: techniqueCounts(run.result.hosts).dnsOnly }))
      : null;
    sourceNotes.append(h('div', { class: 'sub-src-notes-title' }, t('sub.srcnote.title')), h('ul', { class: 'sub-src-list' }, lines));
    if (tail) {
      sourceNotes.append(tail);
      speakSource(tail.textContent);
    }
  }

  /* --- stats -------------------------------------------------------------------- */
  // A stat card (Overview) filters the host table and opens it; the keyboard focus goes to the
  // Hosts tab, since the card itself is hidden with its panel.
  const stat = {
    found: StatCard({ label: t('sub.stat.found'), icon: 'layers', variant: 'accent', onClick: () => pickFilter('all'), pressed: false }),
    resolving: StatCard({ label: t('sub.stat.resolving'), icon: 'check-circle', variant: 'ok', onClick: () => pickFilter('resolving'), pressed: false }),
    cloudflare: StatCard({ label: t('sub.stat.cloudflare'), icon: 'cloud', variant: 'cloudflare', onClick: () => pickFilter('cloudflare'), pressed: false }),
    cdn: StatCard({ label: t('sub.stat.cdn'), icon: 'zap', variant: 'cdn', onClick: () => pickFilter('cdn'), pressed: false }),
    direct: StatCard({ label: t('sub.stat.direct'), icon: 'server', variant: 'direct', onClick: () => pickFilter('direct'), pressed: false }),
    unresolved: StatCard({ label: t('sub.stat.unresolved'), icon: 'x-circle', variant: 'nxdomain', onClick: () => pickFilter('unresolved'), pressed: false }),
    dangling: StatCard({ label: t('sub.stat.dangling'), icon: 'unlink', variant: 'dangling', onClick: () => pickFilter('dangling'), pressed: false })
  };
  const statsGrid = h('div', { class: 'stat-grid sub-stats' });
  for (const [k, s] of Object.entries(stat)) {
    s.el.dataset.stat = k;
    s.el.title = t('sub.stat.filterHint');
    statsGrid.append(s.el);
  }
  stat.dangling.el.hidden = true;

  /* --- filters + table ------------------------------------------------------------ */
  const seg = SegmentedControl({
    label: t('sub.filter.label'),
    size: 'sm',
    className: 'sub-filter',
    value: session.filter,
    options: SEGMENT_FILTERS.map((f) => ({ value: f, label: t(`sub.filter.${f}`) })),
    onChange: (v) => setFilter(v)
  });
  const wildLabel = h('span');
  const wildBox = checkbox({
    label: wildLabel,
    checked: session.showWildcard,
    className: 'sub-wild-toggle',
    onChange: (on) => {
      session.showWildcard = on;
      applyFilter();
      renderStatsNow();
    }
  });
  wildBox.input.dataset.role = 'sub-show-wildcard';
  wildBox.el.title = t('sub.filter.wildcardHint');
  wildBox.el.hidden = true;

  const ipLink = (ip) => h('a', { class: 'sub-ip', href: ctx.href('ip', { ip }), title: t('sub.ip.intel', { ip }) }, ip);
  const table = DataTable({
    caption: t('sub.caption'),
    search: { placeholder: t('sub.search'), label: t('sub.searchLabel') },
    pageSize: 200,
    sort: { key: 'name', dir: 'asc' },
    empty: t('sub.empty'),
    noMatch: t('sub.noMatch'),
    rowKey: (x) => x.name,
    rowClass: (x) => ({ 'sub-row-wildcard': x.wildcardSuspect, 'sub-row-dangling': x.classification.dangling }),
    className: 'sub-table',
    toolbar: [seg.el, wildBox.el],
    filter: filterFn(),
    columns: [
      {
        key: 'name',
        label: t('sub.col.name'),
        sortable: true,
        sortValue: (x) => hostSortKey(x.name),
        searchValue: (x) => [x.name, ...x.resolution.cnames, x.classification.provider ? x.classification.provider.name : ''].join(' '),
        render: (x) => h('div', { class: 'sub-host' },
          h('a', { class: 'sub-host-name mono', href: ctx.href('lookup', { name: x.name }), title: t('sub.host.lookup', { name: x.name }) }, hostNameNodes(x.name)),
          x.wildcardSuspect ? Badge(t('sub.host.wildcard'), { variant: 'warn', title: t('sub.filter.wildcardHint'), className: 'sub-mini-badge' }) : null)
      },
      {
        key: 'ips',
        label: t('sub.col.ips'),
        sortable: true,
        sortValue: (x) => ipSortValue(x.resolution.ipv4[0] || x.resolution.ipv6[0]),
        searchValue: (x) => [...x.resolution.ipv4, ...x.resolution.ipv6].join(' '),
        render: (x) => {
          const ips = [...x.resolution.ipv4, ...x.resolution.ipv6];
          return ips.length ? h('div', { class: 'sub-ips' }, TruncatedList(ips, { max: 3, inline: true, render: ipLink })) : null;
        }
      },
      {
        key: 'kind',
        label: t('sub.col.kind'),
        sortable: true,
        sortValue: (x) => `${x.classification.dangling ? '0' : '1'}${x.classification.kind}${x.classification.provider ? x.classification.provider.name : ''}`,
        searchValue: (x) => `${t(`kind.${x.classification.dangling ? 'dangling' : x.classification.kind}`)} ${x.classification.provider ? x.classification.provider.name : ''} ${x.resolution.status}`,
        render: (x) => h('div', { class: 'cluster sub-kind' }, KindBadge(x.classification),
          // A streamed partial is "resolving…" only while the run lives (a cancelled run never resolves it).
          x._partial && run.status === 'running' ? Badge(t('sub.host.resolving'), { variant: 'neutral', icon: 'clock', title: t('sub.host.resolvingTitle'), className: 'sub-mini-badge' }) : null,
          x.resolution.status !== 'NOERROR' && x.resolution.status !== 'NXDOMAIN'
            ? Badge(x.resolution.status, { variant: 'error', title: x.resolution.error || null, mono: true }) : null,
          originCandidates.has(x.name) ? h('button', {
            type: 'button',
            class: 'sub-origin-hint',
            title: t('sub.host.originHintTitle'),
            dataset: { action: 'sub-origin-jump' },
            on: { click: () => jumpToOrigin() }
          }, Icon('target', { size: 12 }), t('sub.host.originHint')) : null)
      },
      {
        key: 'cname',
        label: t('sub.col.cname'),
        sortable: true,
        sortValue: (x) => x.resolution.cnames[x.resolution.cnames.length - 1] || '',
        searchValue: (x) => x.resolution.cnames.join(' '),
        render: (x) => (x.resolution.cnames.length
          ? TruncatedList(x.resolution.cnames, {
            max: 2,
            render: (c) => h('span', { class: 'sub-cname', title: x.resolution.cnames.join(' → ') }, h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'), c)
          })
          : null)
      },
      {
        key: 'origins',
        label: t('sub.col.origins'),
        sortable: true,
        sortValue: (x) => x.origins.length,
        defaultDir: 'desc',
        searchValue: (x) => x.origins.map(originLabel).join(' '),
        render: (x) => h('div', { class: 'sub-origins' }, x.origins.map((o) => h('span', {
          class: 'sub-origin',
          dataset: { origin: o, tech: o.startsWith('dns-mine:') ? 'mine' : DNS_ORIGINS.has(o) ? 'dns' : null },
          title: originTitle(o)
        }, originLabel(o))))
      },
      inventory ? {
        key: 'servers',
        label: t('sub.col.servers'),
        sortable: true,
        sortValue: (x) => (x.servers[0] ? x.servers[0].name : ''),
        searchValue: (x) => x.servers.map((s) => `${s.name} ${s.ip}`).join(' '),
        render: (x) => {
          const byName = new Map();
          for (const s of x.servers) byName.set(s.name, [...(byName.get(s.name) || []), s.ip]);
          return byName.size
            ? h('div', { class: 'cluster sub-servers' }, [...byName].map(([name, ips]) => Badge(name, { variant: 'direct', icon: 'server', title: ips.join(', ') })))
            : null;
        }
      } : null
    ].filter(Boolean)
  });
  table.setLoading(run.status === 'running');

  // Without wildcard suspects 'all' needs no filter (keeps the row count simple); the predicate
  // reads showWildcard per row, so suspects streaming in later are hidden under any filter.
  let tableFiltered = false;
  function filterFn() {
    return hostTableFilter(session.filter, session, listHosts());
  }
  function applyFilter() {
    const fn = filterFn();
    tableFiltered = !!fn;
    table.setFilter(fn);
    for (const [k, s] of Object.entries(stat)) s.set({ pressed: STAT_FILTERS[k] === session.filter });
    seg.setValue(session.filter);
  }
  function setFilter(f) {
    session.filter = FILTERS.includes(f) ? f : 'all';
    applyFilter();
  }
  function pickFilter(f) {
    setFilter(f);
    showTab('hosts', { focus: true });
  }

  /* --- actions: copy / download ------------------------------------------------------ */
  const exportList = () => listHosts().filter((x) => (session.showWildcard || !x.wildcardSuspect) && (!session.resolvingOnly || isResolving(x)));
  const countEl = h('span', { class: 'sub-act-count num' });
  const copyBtn = CopyButton(() => namesText(exportList()), { label: t('sub.act.copy'), size: 'sm', variant: 'secondary', className: 'sub-copy' });
  copyBtn.dataset.action = 'sub-copy';
  copyBtn.append(countEl);
  const resolvingBox = checkbox({
    label: t('sub.act.resolvingOnly'),
    checked: session.resolvingOnly,
    className: 'sub-resolving-only',
    onChange: (on) => {
      session.resolvingOnly = on;
      syncActions();
    }
  });
  resolvingBox.input.dataset.role = 'sub-resolving-only';
  const saved = (file) => toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  const exportRows = () => scanHostRows({ hosts: exportList() }).map(({ covered: _c, coveredBy: _b, ...row }) => row);
  const namesBtn = Button({
    label: t('sub.act.names'), icon: 'file-text', size: 'sm', dataset: { export: 'names' },
    onClick: () => saved(downloadText('names.txt', namesText(exportList()), 'text/plain;charset=utf-8'))
  });
  const csvBtn = Button({
    label: t('common.exportCsv'), icon: 'download', size: 'sm', dataset: { export: 'csv' },
    onClick: () => saved(downloadText(timestampedName('subdomains', 'csv', subject), toCsv(exportRows(), CSV_COLUMNS), 'text/csv;charset=utf-8'))
  });
  const jsonBtn = Button({
    label: t('common.exportJson'), icon: 'download', size: 'sm', dataset: { export: 'json' },
    onClick: () => saved(downloadText(timestampedName('subdomains', 'json', subject), `${toJson({
      generator: 'DomainScope',
      version: ctx.version,
      exportedAt: new Date(),
      domains: run.config.domains,
      options: {
        sources: run.config.sources,
        bruteforce: run.config.bruteforce,
        permutationBudget: run.config.permutationBudget,
        originHints: run.config.originHints,
        includeExpired: run.config.includeExpired,
        // The wordlist the scan actually served: level (after any degrade), locale packs and
        // the custom / learned tried-vs-found counts (result.options.wordlist, engine v2).
        wordlist: run.result && run.result.options ? run.result.options.wordlist || null : null
      },
      complete: run.status === 'done',
      discovery: run.result ? techniqueCounts(run.result.hosts) : null,
      sourceHealth: sourceHealthSummary(run.sourceResults).map(({ domains: _d, ...x }) => x),
      // The networks and the POSIX command the ORIGIN panel shows, with its exclusions applied.
      origin: run.result ? originExport(run.result, originExclude.tokens, originIndex(stateSingleton.workspaceData('origins'))) : null,
      subdomains: exportRows()
    })}\n`, 'application/json;charset=utf-8'))
  });
  const actions = h('div', { class: 'sub-actions', attrs: { role: 'group', 'aria-label': t('sub.act.label') } },
    h('div', { class: 'sub-actions-main' }, copyBtn, resolvingBox.el),
    h('div', { class: 'sub-actions-files' }, namesBtn, csvBtn, jsonBtn));

  function syncActions() {
    const n = exportList().length;
    countEl.textContent = formatNumber(n);
    for (const b of [copyBtn, namesBtn, csvBtn, jsonBtn]) b.disabled = n === 0;
  }

  /* --- how the names were found (technique chips) ---------------------------------------- */
  const techHost = h('div', { class: 'sub-tech', attrs: { role: 'group', 'aria-label': t('sub.tech.label') } });
  function renderTechniques() {
    clear(techHost);
    const hosts = listHosts();
    const c = techniqueCounts(hosts);
    techHost.hidden = c.total === 0;
    if (!c.total) return;
    const chip = (key, label, n, what = label) => (n ? h('span', {
      class: 'sub-tech-chip',
      dataset: { tech: key },
      title: t('sub.tech.chipTitle', { count: n, what })
    }, h('span', { class: 'sub-tech-name' }, label), h('span', { class: 'sub-tech-count num' }, formatNumber(n))) : null);
    const dnsChips = [
      chip('zone', t('sub.tech.zone'), c.zone),
      chip('mine', t('sub.tech.mine'), c.mine),
      chip('wordlist', t('sub.tech.wordlist'), c.wordlist),
      chip('permutation', t('sub.tech.permutation'), c.permutation),
      chip('recursive', t('sub.tech.recursive'), c.recursive)
    ].filter(Boolean);
    const srcChips = SOURCES.map((s) => chip(`source:${s.id}`, s.name, c.bySource[s.id] || 0)).filter(Boolean);
    // "Only through DNS" claims nothing about sources that were off, limited or down.
    const onlyKey = run.status !== 'running'
      ? dnsOnlyNoteKey(c.dnsOnly, run.config.sources, sourceHealthSummary(run.result ? run.result.sources || run.sourceResults : run.sourceResults))
      : null;
    // h() skips null children; Node.append would print "null", so it only gets real nodes.
    techHost.append(h('div', { class: 'sub-tech-head' },
      Icon('network', { size: 15 }),
      h('span', { class: 'sub-tech-summary', dataset: { dns: c.dns, sources: c.sources, dnsOnly: c.dnsOnly } },
        t('sub.tech.summary', { dns: formatNumber(c.dns), sources: formatNumber(c.sources) })),
      onlyKey ? h('span', { class: 'sub-tech-only', dataset: { note: onlyKey === 'sub.tech.dnsOnly' ? 'complete' : 'incomplete' } }, t(onlyKey, { count: c.dnsOnly })) : null));
    if (dnsChips.length || srcChips.length) {
      techHost.append(h('div', { class: 'sub-tech-chips' },
        dnsChips.length ? h('div', { class: 'sub-tech-group', dataset: { group: 'dns' } }, dnsChips) : null,
        srcChips.length ? h('div', { class: 'sub-tech-group', dataset: { group: 'sources' } }, srcChips) : null));
    }
    const wl = usage();
    if (wl) techHost.append(wl);
  }

  /**
   * The wordlist-usage line from result.options.wordlist (structured fields, engine v2): the
   * served level (after any degrade), the locale packs applied, and how many custom / learned
   * names were tried vs found. Null when no wordlist ran or the result predates the field.
   */
  function usage() {
    const wl = run.result && run.result.options && run.result.options.wordlist;
    if (!wl || !wl.level || wl.level === 'off') return null;
    const level = hasString(`sub.bf.${wl.level}`, 'en') ? t(`sub.bf.${wl.level}`) : wl.level;
    const parts = [h('span', { class: 'sub-wl-level' }, t('sub.wl.usage', { level }))];
    if (Array.isArray(wl.localePacks) && wl.localePacks.length) {
      parts.push(h('span', null, t('sub.wl.packs', { list: wl.localePacks.map(languageName).join(', ') })));
    }
    if (Array.isArray(wl.localesMissing) && wl.localesMissing.length) {
      parts.push(h('span', { class: 'sub-wl-degraded' }, t('sub.wl.packsMissing', { list: wl.localesMissing.map(languageName).join(', ') })));
    }
    if (wl.customTried) parts.push(h('span', null, t('sub.wl.custom', { found: formatNumber(wl.customFound || 0), tried: formatNumber(wl.customTried) })));
    if (wl.learnedTried) parts.push(h('span', null, t('sub.wl.learned', { found: formatNumber(wl.learnedFound || 0), tried: formatNumber(wl.learnedTried) })));
    if (Array.isArray(wl.degraded) && wl.degraded.length) parts.push(h('span', { class: 'sub-wl-degraded' }, t('sub.wl.degraded', { level })));
    const line = h('div', { class: 'sub-wl-usage', dataset: { level: wl.level } }, Icon('list', { size: 13 }));
    parts.forEach((p, i) => {
      if (i) line.append(h('span', { class: 'sub-wl-sep', attrs: { 'aria-hidden': 'true' } }, '·'));
      line.append(p);
    });
    return line;
  }
  const renderTechniquesSoon = timeThrottle(renderTechniques, 400);

  /* --- ORIGIN panel: where proxied hosts really live ------------------------------------ */
  const originHost = h('div', { class: 'sub-origin-host' });
  function jumpToOrigin() {
    const target = originHost.querySelector('.sub-org');
    if (!target) return;
    showTab('origins');
    target.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    const heading = target.querySelector('.sub-org-title');
    if (heading) heading.focus({ preventScroll: true });
  }
  /** Render the sweep command for the chosen shell into `host` (a CodeBlock, or the "none" hint). */
  // Origin-panel state that survives its own re-renders: the exclude tokens the user pasted (kept
  // per run, so a re-mount keeps them too) and a per-network owner-lookup cache (one RIPEstat
  // request per /24 · /48, on demand).
  let originExclude = originExcludes.get(run);
  if (!originExclude) {
    originExclude = { raw: '', tokens: [] };
    originExcludes.set(run, originExclude);
  }
  const ownerCache = new Map();
  const ownerCtl = new AbortController();

  function renderOrigin() {
    clear(originHost);
    const r = run.result;
    originCandidates = new Set();
    if (!r) return;
    // The origin map, read once per render (2,000 entries at most).
    const origins = originIndex(stateSingleton.workspaceData('origins'));
    const o = originOverview(r, { origins });
    if (!o.proxied.length) return;
    // Hosts with any host-specific candidate (resolver leak / history / sibling-domain) get the
    // "origin?" jump badge in the results table.
    originCandidates = new Set(o.proxied.filter((p) => p.known.length || p.zone.length || p.leaks.length || p.history.length || p.siblings.length).map((p) => p.name));
    const titleId = uid('sub-org');
    const ipLinkOrg = (ip) => h('a', { class: 'sub-ip mono', href: ctx.href('ip', { ip }), title: t('sub.ip.intel', { ip }) }, ip);
    const blocks = [];
    // A zone file's origin may be a private address: plain text, never an IP Intel link (that
    // view asks third-party services about the address as soon as it opens).
    const zoneIpEl = (ip) => h('span', { class: 'sub-ip mono' }, ip);

    // 00. Remembered origins (one row each, a stale one in place, not used).
    const remembered = o.proxied.flatMap((p) => p.remembered.map((x) => ({ name: p.name, x })));
    if (remembered.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'known' } },
        h('h4', { class: 'sub-org-sub' }, Icon('map-pin', { size: 14 }), t('sub.org.known')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.knownHint'), ' ',
          h('a', { class: 'link', href: ctx.href('inventory', { tab: 'origins' }) }, t('sub.org.knownMap'))),
        h('ul', { class: 'sub-org-list' }, remembered.map(({ name, x }) => h('li', {
          class: ['sub-org-leak', { muted: x.stale }], dataset: { host: name, ip: x.ip, kind: x.stale ? 'known-stale' : 'known' }
        }, h('span', { class: 'mono sub-org-name' }, hostNameNodes(name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
        zoneIpEl(x.target), x.stale ? h('span', { class: 'sub-org-via' }, t('sub.org.knownStale', { date: formatDate(x.entry.stale.at) })) : null)))));
    }

    // 0. Exact origins from the imported zone file (Zone File hand-off): authoritative, so first.
    const zoned = o.proxied.filter((p) => p.zone.length);
    if (zoned.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'zone' } },
        h('h4', { class: 'sub-org-sub' }, Icon('file-text', { size: 14 }), t('sub.org.zone')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.zoneHint')),
        h('ul', { class: 'sub-org-list' }, zoned.flatMap((p) => p.zone.map((z) => h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: z.ip, kind: 'zone' } },
          h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
          zoneIpEl(z.ip)))))));
    }

    /** The sweep for a shell with the current exclusions applied (the JSON export reads the same). */
    const currentSweep = (shell) => originSweepFor(r, { shell, exclude: originExclude.tokens.length ? originExclude.tokens : null, origins });

    // 1. Origin networks (/24 · /48 clusters of the DNS-only records). Each card says whether the
    //    command sweeps the whole /24 or only its known addresses (and why), flags shared cloud /
    //    hosting space, and offers an on-demand owner (AS) lookup.
    if (o.networks.length) {
      const netEls = o.networks.map((net) => {
        const sweepWhole = net.sweep === 'cidr';
        // Polite live region: the owner replaces the button when the on-demand lookup answers.
        const ownerEl = h('span', { class: 'sub-org-owner', attrs: { 'aria-live': 'polite' } });
        renderOwner(ownerEl, net);
        // An IPv4 network can be swept for reverse DNS (a /48 cannot): other hosts of the same
        // owner often sit next to the origin. In shared cloud / hosting space the rest of the /24
        // is other customers' (provider-generated names), so only its own addresses are offered.
        // The link only fills the form; the user presses Sweep.
        const focusDomain = registrableDomain(net.hosts[0] || '') || run.config.domains[0] || '';
        const ownV4 = net.ips.filter((ip) => !ip.includes(':'));
        const ptrTarget = net.shared ? ownV4.join(',') : net.cidr;
        const ptrLink = net.cidr.includes(':') || !ptrTarget ? null : h('a', {
          class: 'sub-org-ptr',
          href: ctx.href('ptr', { target: ptrTarget, focus: focusDomain }),
          title: net.shared ? t('sub.org.ptrIpsTitle') : t('sub.org.ptrTitle', { cidr: net.cidr }),
          dataset: { action: 'sub-org-ptr', cidr: net.cidr, target: net.shared ? 'ips' : 'cidr' }
        }, Icon('swap', { size: 13 }), h('span', null, net.shared ? t('sub.org.ptrIps', { count: ownV4.length }) : t('sub.org.ptr')));
        return h('li', { class: 'sub-org-net', dataset: { cidr: net.cidr, sweep: net.sweep, shared: net.shared ? '1' : '0' } },
          h('div', { class: 'sub-org-net-head' },
            h('span', { class: 'sub-org-cidr mono' }, net.cidr),
            CopyButton(net.cidr, { iconOnly: true, size: 'sm' }),
            h('span', { class: 'sub-org-net-meta' },
              t('sub.org.net.hosts', { count: net.hosts.length }), ' · ', t('sub.org.net.ips', { count: net.ips.length })),
            h('span', {
              class: 'sub-org-sweep',
              dataset: { sweep: net.sweep },
              title: sweepWhole ? t('sub.org.sweep.cidrTitle') : t('sub.org.sweep.ipsTitle')
            }, Icon(sweepWhole ? 'network' : 'server', { size: 12 }),
            sweepWhole ? t('sub.org.sweep.cidr') : t('sub.org.sweep.ips', { count: net.ips.length })),
            net.shared ? Badge(t('sub.org.shared'), { variant: 'warn', icon: 'alert', title: t('sub.org.sharedTitle'), className: 'sub-org-shared-badge' }) : null,
            ownerEl,
            ptrLink),
          h('div', { class: 'sub-org-net-body' },
            TruncatedList(net.hosts.map((name) => {
              const host = r.hosts.find((x) => x.name === name);
              const ip = host ? [...host.resolution.ipv4, ...host.resolution.ipv6].find((a) => net.ips.includes(a)) : null;
              return { name, ip };
            }), {
              max: 6,
              inline: true,
              render: (x) => h('span', { class: 'sub-org-member' },
                h('a', { class: 'mono', href: ctx.href('lookup', { name: x.name }) }, hostNameNodes(x.name)),
                x.ip ? h('span', { class: 'sub-org-member-ip mono' }, x.ip) : null)
            })));
      });
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'networks' } },
        h('h4', { class: 'sub-org-sub' }, Icon('network', { size: 14 }), t('sub.org.networks')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.networksHint')),
        o.shared ? Alert({ variant: 'warn', compact: true, icon: 'alert', message: t('sub.org.warnShared') }) : null,
        h('ul', { class: 'sub-org-nets' }, netEls)));
    } else {
      blocks.push(Alert({ variant: 'info', compact: true, icon: 'info', message: t('sub.org.noNetworks') }));
    }

    // 2. Direct answers for proxied names (resolver leak) and pre-proxy history.
    const leaks = o.proxied.filter((p) => p.leaks.length);
    if (leaks.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'leaks' } },
        h('h4', { class: 'sub-org-sub' }, Icon('zap', { size: 14 }), t('sub.org.leaks')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.leaksHint')),
        h('ul', { class: 'sub-org-list' }, leaks.flatMap((p) => p.leaks.map((l) => h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: l.ip } },
          h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
          ipLinkOrg(l.ip), h('span', { class: 'sub-org-via' }, t('sub.org.leakVia', { resolver: l.resolver }))))))));
    }
    const hist = o.proxied.filter((p) => p.history.length);
    if (hist.length) {
      blocks.push(h('div', { class: 'sub-org-block', dataset: { block: 'history' } },
        h('h4', { class: 'sub-org-sub' }, Icon('clock', { size: 14 }), t('sub.org.history')),
        h('p', { class: 'sub-org-hint' }, t('sub.org.historyHint')),
        h('ul', { class: 'sub-org-list' }, hist.flatMap((p) => p.history.map((x) => {
          // Structured fields (no text parsing): the source id and the last-seen date.
          const source = SOURCE_NAMES[x.source] || x.source || '';
          const via = source ? t(x.lastSeen ? 'sub.org.historyViaDate' : 'sub.org.historyVia', { source, date: dayText(x.lastSeen) }) : '';
          return h('li', { class: 'sub-org-leak', dataset: { host: p.name, ip: x.ip } },
            h('span', { class: 'mono sub-org-name' }, hostNameNodes(p.name)), h('span', { class: 'sub-arrow', attrs: { 'aria-hidden': 'true' } }, '→'),
            ipLinkOrg(x.ip), via ? h('span', { class: 'sub-org-via' }, via) : null);
        })))));
    }

    // 3. Confirm with the CLI (TLS + SNI sweep from inside the network). The command is offered
    //    for both shells (POSIX / PowerShell), built by lib/cmdline so every token is quoted, and
    //    an "exclude" box feeds --exclude (a mail server, a shared address, an octet to leave alone).
    const codeHost = h('div', { class: 'sub-org-command-host' });
    const excludeReport = h('div', { class: 'sub-org-exclude-report text-sm', attrs: { 'aria-live': 'polite' } });
    const renderCommand = () => {
      clear(codeHost);
      clear(excludeReport);
      const shell = SHELLS.includes(session.originShell) ? session.originShell : 'posix';
      const sweep = currentSweep(shell);
      if (sweep.command) codeHost.append(CodeBlock(sweep.command, { label: t('sub.org.command'), wrap: true, className: 'sub-org-command' }));
      const nf = sweep.command && sweep.namesFile ? { file: sweep.namesFile, text: sweep.namesText, count: sweep.count } : null;
      if (nf) {
        codeHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: nf.file } },
          h('p', { class: 'sub-org-hint' }, t('sub.org.namesFile', { file: nf.file, count: formatNumber(nf.count) })),
          Button({
            label: t('sub.org.namesFileDownload', { file: nf.file }), icon: 'download', size: 'sm', dataset: { export: 'names-file' },
            onClick: () => saved(downloadText(nf.file, nf.text, 'text/plain;charset=utf-8'))
          })));
      }
      // A target list too long even then: the command reads the targets from a file too.
      if (sweep.command && sweep.targetsFile) {
        codeHost.append(h('div', { class: 'sub-org-namesfile', dataset: { file: sweep.targetsFile } },
          h('p', { class: 'sub-org-hint' }, t('sub.org.targetsFile', { file: sweep.targetsFile, count: formatNumber(sweep.targetCount) })),
          Button({
            label: t('sub.org.namesFileDownload', { file: sweep.targetsFile }), icon: 'download', size: 'sm', dataset: { export: 'targets-file' },
            onClick: () => saved(downloadText(sweep.targetsFile, sweep.targetsText, 'text/plain;charset=utf-8'))
          })));
      }
      // Report what the exclusions did: invalid tokens, ones that touched nothing, networks dropped,
      // and a command they keep too long for a shell.
      const invalid = sweep.excludeDropped || [];
      const unused = sweep.excludeUnused || [];
      const droppedTargets = sweep.droppedTargets || 0;
      const lines = [];
      if (sweep.overLength) lines.push(h('div', { class: 'sub-org-exclude-invalid', dataset: { role: 'over-length' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.overLength', { count: formatNumber(sweep.command.length) }))));
      if (invalid.length) lines.push(h('div', { class: 'sub-org-exclude-invalid', dataset: { role: 'exclude-invalid' } }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.exclude.invalid', { count: invalid.length, list: invalid.slice(0, 5).join(', ') }))));
      if (droppedTargets) lines.push(h('div', { class: 'sub-org-exclude-applied', dataset: { role: 'exclude-applied' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.applied', { count: droppedTargets }))));
      if (unused.length) lines.push(h('div', { class: 'sub-org-exclude-unused', dataset: { role: 'exclude-unused' } }, Icon('info', { size: 13 }), h('span', null, t('sub.org.exclude.unused', { count: unused.length, list: unused.slice(0, 5).join(', ') }))));
      excludeReport.append(...lines);
    };
    const shellSeg = o.command ? SegmentedControl({
      label: t('sub.org.shell'),
      size: 'sm',
      className: 'sub-org-shell',
      value: SHELLS.includes(session.originShell) ? session.originShell : 'posix',
      options: SHELLS.map((sh) => ({ value: sh, label: t(`sub.org.shell.${sh}`), title: t(`sub.org.shellTitle.${sh}`) })),
      onChange: (sh) => {
        session.originShell = SHELLS.includes(sh) ? sh : 'posix';
        renderCommand();
      }
    }) : null;
    const excludeField = o.command ? textInput({
      label: t('sub.org.exclude.label'),
      value: originExclude.raw || '',
      placeholder: t('sub.org.exclude.placeholder'),
      hint: t('sub.org.exclude.hint'),
      mono: true,
      className: 'sub-org-exclude',
      attrs: { 'data-role': 'sub-org-exclude', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off' },
      onInput: (value) => {
        originExclude.raw = value;
        originExclude.tokens = value.split(/[\s,]+/).filter(Boolean);
        renderCommand();
      }
    }) : null;
    renderCommand();
    blocks.push(h('div', { class: 'sub-org-block sub-org-cli', dataset: { block: 'cli' } },
      h('h4', { class: 'sub-org-sub' }, Icon('terminal', { size: 14 }), t('sub.org.cli')),
      h('p', { class: 'sub-org-hint' }, o.command ? t('sub.org.cliHint') : t('sub.org.cliNone')),
      shellSeg ? shellSeg.el : null,
      excludeField ? excludeField.el : null,
      codeHost,
      excludeReport,
      o.droppedCount ? h('p', { class: 'sub-org-dropped text-sm' }, Icon('alert', { size: 13 }), h('span', null, t('sub.org.dropped', { count: o.droppedCount }))) : null,
      h('div', { class: 'cluster' },
        ButtonLink({ href: CLI_PATH, label: t('sub.org.cliDownload'), icon: 'download', size: 'sm', download: 'ssl_origin_scan.py' }))));

    // 4. Every proxied host with its candidates, and the general hints (SPF / MX / siblings).
    const hostTable = DataTable({
      caption: t('sub.org.hosts', { count: o.proxied.length }),
      rows: o.proxied,
      dense: true,
      search: o.proxied.length > 10,
      rowKey: (p) => p.name,
      sort: { key: 'name', dir: 'asc' },
      className: 'sub-org-table',
      columns: [
        { key: 'name', label: t('sub.org.col.host'), sortable: true, mono: true, sortValue: (p) => hostSortKey(p.name), searchValue: (p) => p.name, render: (p) => hostNameNodes(p.name) },
        {
          key: 'candidates', label: t('sub.org.col.candidates'), wrap: true, sortable: true,
          // Rank: exact host-specific evidence (leak / sibling / history) above candidate networks.
          sortValue: (p) => (p.known.length ? -2 : p.zone.length ? -1 : p.leaks.length ? 0 : p.siblings.length ? 1 : p.history.length ? 2 : p.networks.length ? 3 : 4),
          searchValue: (p) => [...p.known.map((k) => k.target), ...p.zone.map((z) => z.ip), ...p.leaks.map((l) => l.ip), ...p.siblings.map((s) => `${s.ip} ${s.sibling}`), ...p.history.map((x) => x.ip), ...p.networks].join(' '),
          render: (p) => {
            const items = [
              ...p.known.map((k) => h('span', { class: 'sub-org-cand', dataset: { kind: 'known' } },
                Badge(t('sub.hint.known'), { variant: 'ok', title: t('sub.hint.known.title') }), zoneIpEl(k.target))),
              ...p.zone.map((z) => h('span', { class: 'sub-org-cand', dataset: { kind: 'zone' } },
                Badge(t('sub.hint.zone'), { variant: 'ok', title: t('sub.hint.zone.title') }), zoneIpEl(z.ip))),
              ...p.leaks.map((l) => h('span', { class: 'sub-org-cand', dataset: { kind: 'resolver-leak' } },
                Badge(t('sub.hint.resolver-leak'), { variant: 'warn', title: t('sub.hint.resolver-leak.title') }), ipLinkOrg(l.ip))),
              ...p.siblings.map((s) => h('span', { class: 'sub-org-cand', dataset: { kind: 'sibling-domain' } },
                Badge(t('sub.org.cand.sibling'), { variant: 'accent', title: t('sub.org.cand.siblingTitle') }), ipLinkOrg(s.ip),
                s.sibling ? h('span', { class: 'sub-org-via' }, t('sub.org.cand.siblingVia', { sibling: s.sibling })) : null)),
              ...p.history.map((x) => h('span', { class: 'sub-org-cand', dataset: { kind: 'history' } },
                Badge(t('sub.hint.history'), { variant: 'info', title: t('sub.hint.history.title') }), ipLinkOrg(x.ip))),
              p.networks.length ? h('span', { class: 'sub-org-cand muted', dataset: { kind: 'network' } },
                Badge(t('sub.org.cand.network'), { variant: 'neutral', title: t('sub.org.cand.networkTitle') }),
                h('span', { class: 'sub-org-cand-nets mono' }, p.networks.join(', '))) : null
            ].filter(Boolean);
            return items.length ? h('div', { class: 'sub-org-cands' }, items) : h('span', { class: 'muted' }, t('sub.org.candNone'));
          }
        },
        {
          key: 'edge', label: t('sub.org.col.edge'),
          searchValue: (p) => [...p.host.resolution.ipv4, ...p.host.resolution.ipv6].join(' '),
          render: (p) => h('div', { class: 'cluster' }, KindBadge(p.host.classification),
            TruncatedList([...p.host.resolution.ipv4, ...p.host.resolution.ipv6], { max: 1, inline: true }))
        }
      ]
    });
    const generalTable = o.general.length ? DataTable({
      caption: t('sub.org.other'),
      rows: o.general,
      dense: true,
      rowKey: (x) => x.ip,
      className: 'sub-org-hints',
      columns: [
        { key: 'ip', label: t('sub.org.col.ip'), sortable: true, sortValue: (x) => ipSortValue(x.ip), render: (x) => ipLinkOrg(x.ip) },
        {
          key: 'reasons', label: t('sub.org.col.evidence'), wrap: true,
          searchValue: (x) => x.reasons.map((y) => `${y.kind} ${reasonText(y)}`).join(' '),
          render: (x) => h('div', { class: 'stack-sm' }, x.reasons.slice(0, 3).map((y) => h('div', { class: 'sub-org-reason' },
            Badge(HINT_KINDS.includes(y.kind) ? t(`sub.hint.${y.kind}`) : y.kind, { variant: 'info', title: HINT_KINDS.includes(y.kind) ? t(`sub.hint.${y.kind}.title`) : null }),
            h('span', { class: 'mono text-xs sub-org-detail' }, reasonText(y)))))
        },
        { key: 'hosts', label: t('sub.org.col.about'), mono: true, render: (x) => ((x.hosts || []).length ? TruncatedList(x.hosts, { max: 2 }) : null) }
      ]
    }) : null;
    blocks.push(Disclosure({
      summary: t('sub.org.hosts', { count: o.proxied.length }),
      className: 'sub-org-more',
      open: o.proxied.length <= 8,
      children: h('div', { class: 'stack' }, hostTable.el,
        generalTable ? h('div', { class: 'stack-sm' }, h('h4', { class: 'sub-org-sub' }, t('sub.org.other')), h('p', { class: 'sub-org-hint' }, t('sub.org.otherHint')), generalTable.el) : null)
    }));

    originHost.append(h('section', { class: 'sub-org card', attrs: { 'aria-labelledby': titleId }, dataset: { proxied: o.proxied.length, networks: o.networks.length } },
      h('div', { class: 'sub-org-head' },
        h('span', { class: 'sub-org-icon', attrs: { 'aria-hidden': 'true' } }, Icon('cloud', { size: 18 })),
        h('div', { class: 'sub-org-titles' },
          h('h3', { class: 'sub-org-title', id: titleId, attrs: { tabindex: '-1' } }, t('sub.org.title')),
          h('p', { class: 'sub-org-lead' }, t('sub.org.lead', { count: o.proxied.length })),
          // Suggest scanning sibling domains together: the same label on a sister brand often sits
          // in the open at the real origin (engine v3 raises it to an exact candidate).
          h('p', { class: 'sub-org-suggest' }, Icon('info', { size: 13 }), h('span', null, t('sub.org.siblingSuggest'))))),
      blocks));
  }

  /** The AS owner of a network: the offline provider at once, else an on-demand RIPEstat lookup. */
  function renderOwner(el, net) {
    clear(el);
    if (net.provider) { el.append(h('span', { class: 'sub-org-owner-prov' }, net.provider.name)); return; }
    const cached = ownerCache.get(net.cidr);
    if (cached) { fillOwner(el, cached); return; }
    el.append(Button({
      label: t('sub.org.owner.lookup'), icon: 'search', size: 'sm', variant: 'ghost',
      // Several networks carry the same button: name the network (and the service it asks).
      ariaLabel: t('sub.org.owner.lookupFor', { cidr: net.cidr }), title: t('sub.org.owner.lookupFor', { cidr: net.cidr }),
      dataset: { action: 'sub-org-owner', cidr: net.cidr },
      onClick: async () => {
        if (!ctx.requireOnline()) return;
        clear(el);
        el.append(h('span', { class: 'sub-org-owner-looking' }, t('sub.org.owner.looking')));
        try {
          const d = await networkOwner(net.cidr, { signal: ownerCtl.signal }, ctx.checkOutdated);
          ownerCache.set(net.cidr, d);
          fillOwner(el, d);
        } catch (err) {
          if (errorKind(err) === 'abort') return;
          clear(el);
          el.append(h('span', { class: 'sub-org-owner-error' }, t('sub.org.owner.error')));
        }
      }
    }));
  }
  function fillOwner(el, d) {
    clear(el);
    if (d && !d.error && d.asn) {
      el.append(h('span', {
        class: ['sub-org-owner-as', { 'is-shared': d.shared }],
        dataset: { asn: String(d.asn), shared: d.shared ? '1' : '0' }
      }, t('sub.org.owner.as', { asn: d.asn, holder: d.holder || d.asName || '' })));
    } else {
      el.append(h('span', { class: 'sub-org-owner-error' }, t('sub.org.owner.error')));
    }
  }

  /* --- summary + CTA ------------------------------------------------------------------ */
  const summaryHost = h('div', { class: 'stack-sm sub-summary' });
  /** The Overview's alerts of the ended run (lib/subtabs.summaryAlerts); its tab badge counts them. */
  let alerts = [];
  function renderSummary() {
    clear(summaryHost);
    const r = run.result;
    alerts = summaryAlerts({
      status: run.status,
      counts: countHosts(listHosts()),
      failedSources: sourceHealthSummary(run.sourceResults).filter((x) => !x.ok && x.errorKind !== 'abort').length,
      wildcards: r ? Object.entries(r.wildcards || {}).filter(([, w]) => w && w.wildcard).map(([d]) => `*.${d}`) : [],
      warnings: r ? r.warnings || [] : []
    });
    const link = (action, label, onClick) => [h('button', { type: 'button', class: 'link-btn', dataset: { action }, on: { click: onClick } }, label)];
    for (const a of alerts) {
      let message;
      let iconName = 'alert';
      let actions = null;
      switch (a.key) {
        case 'none':
          message = t('sub.sum.noneFound');
          iconName = 'search';
          break;
        case 'sources-failed':
          message = t('sub.sum.sourcesFailed', { count: a.count });
          actions = link('sub-sources-link', t('sub.sum.sourcesLink'), () => showTab('sources', { focus: true }));
          break;
        case 'dangling':
          message = t('sub.sum.dangling', { count: a.count });
          iconName = 'unlink';
          break;
        case 'cloudflare':
          message = t('sub.sum.cloudflare', { count: a.count });
          iconName = 'cloud';
          if (originHost.querySelector('.sub-org')) actions = link('sub-origin-link', t('sub.sum.originLink'), () => jumpToOrigin());
          break;
        case 'wildcard':
          message = t('sub.sum.wildcard', { list: a.list.join(', ') });
          iconName = 'layers';
          break;
        default:
          message = WARNING_CODES.includes(a.key) ? t(`sub.warn.${a.key}`, { detail: a.detail }) : `${a.key}: ${a.detail}`;
      }
      const alert = Alert({ variant: a.variant, compact: true, message, icon: iconName, actions });
      alert.dataset.summary = a.key;
      summaryHost.append(alert);
    }
    renderBadges();
  }

  const cta = h('section', { class: 'sub-cta card', dataset: { cta: 'scan' } },
    h('span', { class: 'sub-cta-icon', attrs: { 'aria-hidden': 'true' } }, Icon('target', { size: 20 })),
    h('div', { class: 'sub-cta-text' },
      h('h3', { class: 'sub-cta-title' }, t('sub.cta.title')),
      h('p', { class: 'sub-cta-body' }, t('sub.cta.body'))),
    Button({
      label: t('sub.cta.button'), iconRight: 'arrow-right', variant: 'primary', className: 'sub-cta-btn', dataset: { action: 'sub-cta' },
      onClick: () => ctx.navigate('scan', { domain: run.config.domains.join(',') })
    }));

  /* --- Origins tab: the ORIGIN panel, or why there is none (yet) ---------------------------- */
  const originEmpty = h('div', { class: 'sub-org-empty' });
  let originEmptyText = null;
  function renderOriginEmpty() {
    let text = null;
    if (!originHost.querySelector('.sub-org')) {
      if (run.status === 'running') text = t('sub.org.pending', { count: listHosts().filter(isProxiedOriginHost).length });
      else text = run.result ? t('sub.org.none') : t('sub.org.unfinished');
    }
    if (text === originEmptyText) return;
    originEmptyText = text;
    clear(originEmpty);
    originEmpty.hidden = !text;
    if (text) originEmpty.append(EmptyState({ icon: 'cloud', message: text, compact: true }));
  }

  /* --- Sources tab: the stage pills, the per-source chips and notes, the free limits --------- */
  const stagesId = uid('sub-stages');
  const sourcesId = uid('sub-sources');
  const sourcesNone = h('p', { class: 'sub-src-none', hidden: true }, t('sub.sources.none'));
  const quotaList = h('ul', { class: 'sub-src-list sub-src-quotas' });
  const quotaBox = h('div', { class: 'sub-src-quota-box' }, h('div', { class: 'sub-src-notes-title' }, t('sub.sources.quotas')), quotaList);
  // Related domains in the same certificates (ui/related-domains.js over lib/ctrelated.js): read
  // from the CT results this run already has, loaded only for a run that asks crt.sh or Cert Spotter.
  const relatedHost = h('div', { class: 'sub-rel-host' });
  let related = null;
  const renderRelated = () => {
    if (related) related.update(run, { busy: run.status === 'running' });
  };
  if ((run.config.sources || []).some((s) => s === 'crtsh' || s === 'certspotter')) {
    loadOnFirstUse(() => import('../ui/related-domains.js'), ctx.checkOutdated).then((m) => {
      if (ctx.signal.aborted) return;
      related = m.RelatedDomains({ onScanWith: (domains) => onScanWith && onScanWith(domains) });
      relatedHost.append(related.el);
      renderRelated();
    }, () => {});
  }
  const sourcesPanel = h('div', { class: 'stack sub-tab-sources' },
    h('section', { class: 'sub-src-section card', dataset: { part: 'stages' }, attrs: { 'aria-labelledby': stagesId } },
      h('h3', { class: 'sub-src-heading', id: stagesId }, t('sub.stages.title')),
      stageList),
    h('section', { class: 'sub-src-section card', dataset: { part: 'sources' }, attrs: { 'aria-labelledby': sourcesId } },
      h('h3', { class: 'sub-src-heading', id: sourcesId }, t('sub.opt.sources')),
      h('p', { class: 'sub-src-hint' }, t('sub.opt.sourcesHint')),
      sourcesNone, sourceWaitNote, chips, sourceNotes, quotaBox),
    relatedHost);

  /* --- tabs ----------------------------------------------------------------------------------- */
  // Overview: counts and alerts; Hosts: the table (the automatic tab once there is a host);
  // Origins: the ORIGIN panel with the sweep command; Sources: stages, sources and their limits.
  // Every panel is built up front, so a live run updates them all whichever one is shown.
  const opening = initialSubTab({
    route: ctx.params.tab,
    chosen: session.tab,
    hosts: countHosts(listHosts(), { includeWildcard: session.showWildcard }).found,
    running: run.status === 'running'
  });
  if (opening.chosen) session.tab = opening.tab;
  const tabs = Tabs(SUB_TABS.map((tabId) => ({ id: tabId, label: t(`sub.tab.${tabId}`) })), {
    selected: opening.tab,
    label: t('sub.results'),
    className: 'sub-tabs',
    onChange: (tabId) => remember(tabId)
  });
  const panels = {
    overview: h('div', { class: 'stack sub-tab-overview' }, statsGrid, summaryHost, techHost, cta),
    hosts: h('div', { class: 'stack sub-tab-hosts' }, actions, table.el),
    origins: h('div', { class: 'stack sub-tab-origins' }, originEmpty, originHost),
    sources: sourcesPanel
  };
  for (const tabId of SUB_TABS) tabs.panel(tabId).append(panels[tabId]);

  /**
   * A tab the user picked (a click, the arrow keys, a stat card, a link): kept for this run and in
   * the URL next to `domain` (lib/subtabs.subTabParams; the run's domains after a return through
   * the nav link, whose route names none).
   */
  function remember(tabId) {
    session.tab = tabId;
    const named = routeTargets(ctx.searchParams, ctx.params).length > 0;
    ctx.setParams(subTabParams(tabId, { named, domains: run.config.domains }), { merge: true });
  }
  /** Open a tab for the user (it counts as their choice). */
  function showTab(tabId, { focus = false } = {}) {
    if (!SUB_TABS.includes(tabId)) return;
    tabs.select(tabId, { focus, silent: true });
    remember(tabId);
  }
  // A click on the tab already shown is a choice too (the component reports only a change).
  tabs.el.querySelector('[role="tablist"]').addEventListener('click', (event) => {
    const tab = event.target && event.target.closest ? event.target.closest('[role="tab"]') : null;
    if (tab && session.tab === null) remember(tab.dataset.tab);
  });
  /**
   * An automatic choice follows the run: Sources → Hosts with the first host, Overview when the
   * run ends empty (lib/subtabs.nextAutoTab) — never a tab the user chose, never under the focus.
   */
  function followRun(found) {
    const doc = globalThis.document;
    const next = nextAutoTab(tabs.getSelected(), {
      chosen: session.tab !== null,
      focusInside: !!(doc && doc.activeElement && tabs.el.contains(doc.activeElement)),
      hosts: found,
      running: run.status === 'running'
    });
    if (next) tabs.select(next, { silent: true });
  }
  /** The live counts on the tab labels (lib/subtabs.subTabBadges). */
  let lastCounts = null;
  function renderBadges() {
    const hosts = listHosts();
    const c = lastCounts || countHosts(hosts, { includeWildcard: session.showWildcard });
    const b = subTabBadges({
      found: c.found,
      running: run.status === 'running',
      proxied: hosts.filter(isProxiedOriginHost).length,
      sources: sourceIds().length,
      health: sourceHealthSummary(run.sourceResults),
      alerts
    });
    for (const tabId of SUB_TABS) tabs.setBadge(tabId, b[tabId] ? b[tabId].value : null, b[tabId] ? b[tabId].variant : null);
  }
  // followRun holds a move back while the focus is inside the tabs (a focused tab, a tapped
  // panel); once the focus has left them, the move it held back happens after all. Checked after
  // the focus has landed: a focus that only moves within the tabs, or a window that lost the focus
  // (the element keeps it), still holds.
  tabs.el.addEventListener('focusout', () => {
    setTimeout(() => {
      if (root.isConnected) followRun(lastCounts ? lastCounts.found : 0);
    }, 0);
  });

  const results = h('div', { class: 'sub-results' }, tabs.el);
  const root = h('div', { class: 'stack sub-run-ui', dataset: { run: run.id, status: run.status } }, panel, results);

  /* --- stats rendering ----------------------------------------------------------------- */
  function renderStatsNow() {
    const hosts = listHosts();
    const c = countHosts(hosts, { includeWildcard: session.showWildcard });
    const waiting = run.status === 'running' && hosts.length === 0;
    const v = (n) => (waiting ? '…' : n);
    const hiddenWild = c.wildcard && !session.showWildcard ? t('sub.stat.wildcardHidden', { count: c.wildcard }) : null;
    stat.found.set({ value: v(c.found), hint: hiddenWild || (run.config.domains.length > 1 ? t('sub.stat.foundDomains', { count: run.config.domains.length }) : null) });
    stat.resolving.set({ value: v(c.resolving), hint: t('sub.stat.resolvingHint') });
    stat.cloudflare.set({ value: v(c.cloudflare), hint: t('sub.stat.cloudflareHint') });
    stat.cdn.set({ value: v(c.cdn), hint: providerHint(hosts) || t('sub.stat.cdnHint') });
    stat.direct.set({
      value: v(c.direct),
      hint: inventory ? t('sub.stat.directServers', { count: c.onServers })
        : c.private ? t('sub.stat.directPrivate', { count: c.private }) : t('sub.stat.directHint')
    });
    stat.unresolved.set({ value: v(c.unresolved), hint: t('sub.stat.unresolvedHint') });
    stat.dangling.set({ value: c.dangling, hint: t('sub.stat.danglingHint') });
    stat.dangling.el.hidden = c.dangling === 0 && session.filter !== 'dangling';
    wildLabel.textContent = t('sub.filter.wildcard', { count: c.wildcard });
    wildBox.el.hidden = c.wildcard === 0;
    syncActions();
    lastCounts = c;
    renderBadges();
    renderOriginEmpty();
    followRun(c.found);
  }
  /** Streaming: at most every 150 ms (every host would otherwise walk the whole list). */
  const renderStats = timeThrottle(renderStatsNow, 150);

  /* --- finish ---------------------------------------------------------------------------- */
  function finish() {
    renderTitle();
    renderMeta();
    renderStages();
    renderChips();
    renderSourceWait();
    clear(notice);
    progress.el.hidden = true;
    table.setLoading(false);
    if (run.status === 'done') {
      // The origin panel first: it decides which rows get the "origin?" jump badge.
      renderOrigin();
      table.setRows(run.result.hosts);
      // Rows streamed during resolve were drawn (and cached per object) before renderOrigin filled
      // originCandidates, and setRows keeps that cache: redraw them so their badges appear now.
      table.refresh();
      applyFilter();
      announce(t('sub.doneToast', { count: countHosts(run.result.hosts).found }));
    } else if (run.found && run.found.size) {
      // Cancelled / failed: redraw the streamed partials without their "resolving…" badge
      // (updateRow drops the table's cached row, which setRows with the same objects would keep).
      for (const partial of run.found.values()) table.updateRow(partial);
    }
    if (run.status === 'cancelled') {
      notice.append(Alert({ variant: 'warn', compact: true, message: t('sub.run.cancelled', { time: formatDuration(run.finishedAt - run.startedAt) }) }));
    } else if (run.status === 'error') {
      notice.append(ErrorBanner(run.error, { title: t('sub.run.failed') }));
    }
    renderStatsNow();
    renderTechniques();
    renderSummary();
    renderRelated();
    summary.setDisabled(!summaryFacts());
    stopTicker();
    onFinish();
  }

  /* --- live updates ------------------------------------------------------------------------ */
  let ticker = null;
  function stopTicker() {
    if (ticker) clearInterval(ticker);
    ticker = null;
  }

  // Per-hit updates are batched per frame: a big wordlist streams thousands of hits, and each
  // pill render walks every host. Rows of names shown as a streamed partial are replaced in
  // place; any other full record is appended in a batch (no per-row scan of the table).
  const renderStagesSoon = frameThrottle(renderStages);
  const partialShown = new Set(run.found ? run.found.keys() : []);
  const listener = (type, payload) => {
    switch (type) {
      case 'stage':
        renderStages();
        renderProgress();
        renderSourceWait();
        if (payload.stage === 'sources') renderChips();
        // Announce the stage promptly (not only on the progress bar's 25 % buckets) so a screen
        // reader hears each step change as it happens.
        // A skipped stage (exact zone mode, no wordlist…) is not announced: nothing runs there.
        if (PROGRESS_KEYS[payload.stage] && payload.stage !== 'done'
          && run.stages[payload.stage] && run.stages[payload.stage].state === 'active') announce(t(`sub.progress.${payload.stage}`));
        break;
      case 'progress':
        if (payload && payload.pills) renderStages();
        renderProgress();
        break;
      case 'source':
        renderChips();
        renderSourceWait();
        renderRelated();
        break;
      case 'found':
        // A streamed probe hit (before the resolve stage): show it live, replaced by the full
        // record when 'host' arrives for the same name.
        partialShown.add(payload.name);
        table.upsertRow(payload);
        renderStats();
        renderStagesSoon();
        break;
      case 'host':
        // The full record replaces any partial of the same name (rowKey = name).
        if (partialShown.delete(payload.name)) table.upsertRow(payload);
        else table.addRows([payload]);
        // The first suspect needs a filter where there was none; afterwards the predicate hides them.
        if (payload.wildcardSuspect && !session.showWildcard && !tableFiltered) applyFilter();
        renderStats();
        renderStagesSoon();
        renderTechniquesSoon();
        break;
      case 'done':
      case 'cancelled':
      case 'error':
        finish();
        break;
      default:
        break;
    }
  };

  // Replay what the run already has, then follow it.
  renderTitle();
  renderMeta();
  renderStages();
  renderChips();
  renderSourceWait();
  const replayHosts = listHosts();
  if (replayHosts.length && !run.result) table.setRows(replayHosts);
  applyFilter();
  renderStatsNow();
  renderTechniques();
  if (run.status === 'running') {
    renderProgress();
    ticker = setInterval(renderMeta, 1000);
    run.listeners.add(listener);
  } else {
    finish();
  }

  // The origin map changed (Verify, another tab): the Origins block follows.
  const offOrigins = stateSingleton.subscribe(({ key, value }) => {
    if (run.result && key === 'workspaceData' && (value.parts || []).includes('origins')) {
      renderOrigin();
      table.refresh();
    }
  });

  return {
    el: root,
    /** Open a results tab (the route's `tab=` changed). */
    showTab,
    dispose() {
      offOrigins();
      run.listeners.delete(listener);
      stopTicker();
      // Abandon any in-flight network-owner lookups when the panel is torn down.
      try {
        ownerCtl.abort();
      } catch {
        // already aborted / unsupported
      }
    }
  };
}
