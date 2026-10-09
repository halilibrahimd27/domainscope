/**
 * subtabs.js — the Subdomains results as tabs, as data: which tab a run opens and when an
 * automatic choice moves on, the live counts on the tab labels, the result header's status
 * summary (and the Hosts filter each item opens), the Overview's summary alerts, and where a host
 * name may wrap on a narrow screen.
 *
 * Pure: no DOM, storage, network, clock or i18n. views/subdomains.js feeds it counts and the
 * run's state, and turns the results into tabs, badges, alerts and text runs.
 */

/** The result tabs in page order (the route's `tab=` takes one of these). */
export const SUB_TABS = Object.freeze(['overview', 'hosts', 'origins', 'sources']);

/** Source health states that are a failure of the source, not a limit (lib/sources.sourceHealthSummary). */
const FAILED_STATES = new Set(['unavailable', 'timeout', 'error']);

/** Longest label drawn as one unbreakable run by {@link hostSegments}. */
export const MAX_KEPT_LABEL = 32;

const count = (n) => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

/**
 * A tab id from the route (`#/subdomains?…&tab=origins`), or null for anything else.
 * @param {unknown} value
 * @returns {string|null}
 */
export function parseSubTab(value) {
  return typeof value === 'string' && SUB_TABS.includes(value) ? value : null;
}

/**
 * The tab a run shows while nobody has chosen one: Hosts once there is a host to list; before
 * that Sources while the run is live (its stage pills and source chips are the progress) and
 * Overview once it has ended (it says why nothing was found).
 * @param {{ hosts?: number, running?: boolean }} [state] `hosts`: names listed so far
 * @returns {'overview'|'hosts'|'sources'}
 */
export function autoSubTab({ hosts = 0, running = false } = {}) {
  if (count(hosts)) return 'hosts';
  return running ? 'sources' : 'overview';
}

/**
 * The tab a (re-)mounted run opens with, and whether someone chose it: the route's `tab=` first
 * (a shared or restored URL, a language switch), then the tab chosen earlier in this page
 * session (another view and back), else {@link autoSubTab}.
 * @param {{ route?: unknown, chosen?: unknown, hosts?: number, running?: boolean }} [input]
 * @returns {{ tab: string, chosen: boolean }}
 */
export function initialSubTab({ route = null, chosen = null, hosts = 0, running = false } = {}) {
  const pick = parseSubTab(route) || parseSubTab(chosen);
  return pick ? { tab: pick, chosen: true } : { tab: autoSubTab({ hosts, running }), chosen: false };
}

/**
 * The route params a tab the user picked merges into the URL: `tab=`, plus the run's domains
 * when the route names none (a return through the nav link, `#/subdomains`), so a `tab=` never
 * stands alone and a reload pre-fills the box. Nothing for an unknown tab.
 * @param {unknown} tab
 * @param {{ named?: boolean, domains?: string[] }} [route] `named`: the route already names a domain
 * @returns {{ domain?: string, tab?: string }}
 */
export function subTabParams(tab, { named = false, domains = [] } = {}) {
  const id = parseSubTab(tab);
  if (!id) return {};
  const list = Array.isArray(domains) ? domains.filter((d) => typeof d === 'string' && d !== '') : [];
  return named || !list.length ? { tab: id } : { domain: list.join(','), tab: id };
}

/**
 * Where an automatic choice moves while the run streams (the first host arrives, the run ends
 * without one), or null to stay. A tab the user chose never moves, and neither does one while
 * the keyboard focus is inside the tabs: hiding its panel would drop the focus to the page.
 * @param {string} current the tab shown now
 * @param {{ chosen?: boolean, focusInside?: boolean, hosts?: number, running?: boolean }} [state]
 * @returns {string|null}
 */
export function nextAutoTab(current, { chosen = false, focusInside = false, hosts = 0, running = false } = {}) {
  if (chosen || focusInside) return null;
  const next = autoSubTab({ hosts, running });
  return next === current ? null : next;
}

/**
 * The Overview's summary alerts in display order: nothing found, passive sources that did not
 * answer, dangling CNAMEs, hosts behind Cloudflare, parents with wildcard DNS, then the scanner's
 * warnings. None while the run is live (the numbers still move); a cancelled or failed run only
 * lists what it knows. `key` is the alert's id (a warning's code for a warning).
 * @param {{ status?: string, counts?: { found?: number, dangling?: number, cloudflare?: number },
 *   failedSources?: number, wildcards?: string[], warnings?: Array<{ code: string, detail?: string }> }} [input]
 *   `failedSources`: sources that did not answer (not counting a cancel); `wildcards`: `*.parent` names
 * @returns {Array<{ key: string, variant: 'info'|'warn'|'error', count?: number, list?: string[], detail?: string }>}
 */
export function summaryAlerts({ status = 'running', counts = {}, failedSources = 0, wildcards = [], warnings = [] } = {}) {
  if (status === 'running') return [];
  const c = counts || {};
  const out = [];
  if (status === 'done' && !count(c.found)) out.push({ key: 'none', variant: 'warn' });
  if (count(failedSources)) out.push({ key: 'sources-failed', variant: 'warn', count: count(failedSources) });
  if (count(c.dangling)) out.push({ key: 'dangling', variant: 'error', count: count(c.dangling) });
  if (count(c.cloudflare)) out.push({ key: 'cloudflare', variant: 'info', count: count(c.cloudflare) });
  const wild = Array.isArray(wildcards) ? wildcards.filter((w) => typeof w === 'string' && w) : [];
  if (wild.length) out.push({ key: 'wildcard', variant: 'info', list: wild });
  for (const w of Array.isArray(warnings) ? warnings : []) {
    if (w && typeof w.code === 'string' && w.code) out.push({ key: w.code, variant: 'warn', detail: w.detail === undefined ? '' : String(w.detail) });
  }
  return out;
}

/**
 * The Subdomains run's status summary (docs/DESIGN.md §5.4, §5.6): the hosts found, those that
 * resolve, those behind a CDN (Cloudflare, another CDN or a platform: their origin is hidden),
 * those that do not resolve and the passive sources that failed — items for lib/template.js
 * statusItems. Each item's `filter` is the Hosts table's filter it opens (views/subdomains.js
 * FILTERS), or null for the Sources tab.
 * @param {{ counts?: { found?: number, resolving?: number, cloudflare?: number, cdn?: number, unresolved?: number },
 *   failedSources?: number }} [input] `counts`: views/subdomains.js countHosts
 * @returns {Array<{ key: string, severity: 'error'|'warn'|'info'|'neutral', count: number, filter: string|null, tab: string }>}
 */
export function subStatus({ counts = {}, failedSources = 0 } = {}) {
  const c = counts || {};
  return [
    { key: 'found', severity: 'neutral', count: count(c.found), filter: 'all', tab: 'hosts' },
    { key: 'resolving', severity: 'neutral', count: count(c.resolving), filter: 'resolving', tab: 'hosts' },
    { key: 'behind', severity: 'info', count: count(c.cloudflare) + count(c.cdn), filter: 'behind', tab: 'hosts' },
    { key: 'unresolved', severity: 'warn', count: count(c.unresolved), filter: 'unresolved', tab: 'hosts' },
    { key: 'sources', severity: 'error', count: count(failedSources), filter: null, tab: 'sources' }
  ];
}

/**
 * The live counts on the tab labels; null means no badge.
 * - overview: the warnings and errors among the summary alerts (error when one is an error);
 * - hosts: the names listed (the Found stat: wildcard suspects only while they are shown) — none
 *   while a live run has found nothing yet;
 * - origins: hosts whose origin a proxy hides (warn, like SSL Targets' Behind CDN tab);
 * - sources: `worked/asked` passive sources — error when one failed, warn when one is limited or
 *   incomplete, ok once every one worked; none when the scan asked no source.
 * @param {{ found?: number, running?: boolean, proxied?: number, sources?: number,
 *   health?: Array<{ state: string, ok: boolean, errorKind?: string|null }>,
 *   alerts?: Array<{ variant: string }> }} [input] `sources`: how many sources the scan asks;
 *   `health`: lib/sources.sourceHealthSummary() of the results so far; `alerts`: {@link summaryAlerts}
 * @returns {{ overview: Badge|null, hosts: Badge|null, origins: Badge|null, sources: Badge|null }}
 * @typedef {{ value: number|string, variant: 'ok'|'warn'|'error'|null }} Badge
 */
export function subTabBadges({ found = 0, running = false, proxied = 0, sources = 0, health = [], alerts = [] } = {}) {
  const loud = (Array.isArray(alerts) ? alerts : []).filter((a) => a && (a.variant === 'warn' || a.variant === 'error'));
  const overview = loud.length
    ? { value: loud.length, variant: loud.some((a) => a.variant === 'error') ? 'error' : 'warn' }
    : null;
  const hosts = count(found) || !running ? { value: count(found), variant: null } : null;
  const origins = count(proxied) ? { value: count(proxied), variant: 'warn' } : null;
  return { overview, hosts, origins, sources: sourcesBadge(sources, health) };
}

/** The Sources tab badge ({@link subTabBadges}). */
function sourcesBadge(asked, health) {
  const total = count(asked);
  if (!total) return null;
  // A cancelled request is neither a success nor the source's failure.
  const list = (Array.isArray(health) ? health : []).filter((x) => x && x.errorKind !== 'abort');
  const worked = Math.min(total, list.filter((x) => x.ok).length);
  let variant = null;
  if (list.some((x) => !x.ok && FAILED_STATES.has(x.state))) variant = 'error';
  else if (list.some((x) => !x.ok || x.state === 'partial')) variant = 'warn';
  else if (worked === total) variant = 'ok';
  return { value: `${worked}/${total}`, variant };
}

/**
 * Where a host name may wrap: after a dot, never inside a label (a hyphen is no break, so
 * `old-shop.example.com` never reads as `old-` / `shop…`). Each segment is one label with its
 * dot; the view draws a kept segment as an unbreakable run with a line-break opportunity after
 * it. A label longer than `maxLabel` characters is not kept (`keep: false`): drawn as plain text
 * in a name that may break anywhere (CSS `overflow-wrap: anywhere`), one freak 63-character label
 * wraps inside itself instead of pushing a phone's card sideways.
 * @param {string} name
 * @param {{ maxLabel?: number }} [opts]
 * @returns {Array<{ text: string, keep: boolean }>} the segments, joined, are `name`
 */
export function hostSegments(name, { maxLabel = MAX_KEPT_LABEL } = {}) {
  const s = typeof name === 'string' ? name : String(name ?? '');
  if (!s) return [];
  const max = count(maxLabel) || MAX_KEPT_LABEL;
  const out = [];
  let start = 0;
  for (let i = 0; i <= s.length; i += 1) {
    if (i < s.length && s[i] !== '.') continue;
    const end = i < s.length ? i + 1 : i;
    if (end > start) {
      const text = s.slice(start, end);
      // A leading or doubled dot is not a label of its own: it stays with the next one.
      if (text === '.' && end < s.length) continue;
      out.push({ text, keep: text.replace(/\.$/, '').length <= max });
    }
    start = end;
  }
  return out;
}
