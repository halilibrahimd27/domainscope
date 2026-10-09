/**
 * homedigest.js — Home's "Needs attention" (docs/DESIGN.md §4.2): what the active workspace's own
 * data says needs a look, as rows of counts that link to the tool with the details. Home loads it
 * with a dynamic import() right after its first paint, so neither it nor what it imports is on the
 * start route.
 *
 * It never re-implements an owner's rule: it reads each part through its owner's small DOM-free
 * reader — lib/ctseen.js (the CT watch's baseline and its `due` list), lib/regwatch.js
 * readRdapSeen, lib/regstatus.js statusRisk (the Domain portfolio's own risk rule), lib/waivers.js,
 * lib/rollout.js parseRollout, lib/digests.js — and the bands of lib/expiry.js. It never imports
 * lib/ctwatch.js (it pulls lib/x509.js), lib/policy.js or lib/portfolio.js. The DMARC history (up
 * to 4 MB) is read last by the caller, in an idle callback, through lib/dmarchistory.js (its own
 * dynamic import): its roll-up comes in through {@link dmarcAttention}.
 *
 * The rows:
 * - one row per kind and severity, naming its domains (Home shows {@link NAMES_SHOWN}, then
 *   "+n more"), with a count where the kind has one;
 * - severity error → warn → running → info ({@link SEVERITIES}), then the soonest first;
 * - a row whose data was read longer ago than its kind's limit ({@link STALE_DAYS}: a registration
 *   snapshot 7 days, a CT check 14, a Monitoring import 2) keeps its count and severity and is
 *   `stale`: Home says "as of <date> · Check again", so a domain renewed since is never shown as
 *   expiring without saying how old that is.
 * A row carries an i18n key and its params (`params.tool` is a view id, the caller names it;
 * `nameParam` names the param that takes the domains as text when the key's text holds them).
 *
 * Pure: no DOM, network, storage, clock (`now` is passed in) or i18n.
 */

import { readSeen } from './ctseen.js';
import { readRdapSeen } from './regwatch.js';
import { statusRisk, statusName } from './regstatus.js';
import { readWaivers, waiverState, WAIVER_SOON_DAYS } from './waivers.js';
import { parseRollout } from './rollout.js';
import { readDigests, MONITOR_DIGEST_DAYS } from './digests.js';
import { EXPIRY_BANDS, expirySeverity, daysUntil } from './expiry.js';

/** Severities in the order the rows go. */
export const SEVERITIES = Object.freeze(['error', 'warn', 'running', 'info']);
/** Every kind of row, in the order rows of one severity and day go. */
export const ATTENTION_KINDS = Object.freeze([
  'certExpired', 'regExpired', 'cert', 'reg', 'regGone', 'regRisk', 'regTransfer', 'monitorBad', 'dmarcLosing',
  'regNoLock', 'waivers', 'monitorExpiring', 'monitorIncomplete', 'servers', 'dmarcFixFirst',
  'job', 'ctFirst', 'rollout', 'rolloutTicked', 'waiversEnded'
]);
/** Days after which a kind's data is old: the row says "as of <date>". */
export const STALE_DAYS = Object.freeze({ registration: 7, ct: 14, monitor: 2 });
/** A rollout board changed longer ago than this many days is not listed. */
export const ROLLOUT_DAYS = 30;
/** The DMARC roll-up's period, in days. */
export const DMARC_DAYS = 30;
/** Rows Home shows before "Show all (n)". */
export const ATTENTION_SHOWN = 6;
/** Domains a row names before "+n more". */
export const NAMES_SHOWN = 3;
/** Domains a row's link fills in at most (the Domain portfolio's box takes them). */
export const LINK_DOMAINS = 50;

const DAY_MS = 86400000;
const ms = (v) => (v instanceof Date ? v.getTime() : typeof v === 'number' ? v : Date.parse(v));
const isStale = (at, now, days) => Number.isFinite(ms(at)) && ms(now) - ms(at) > days * DAY_MS;
const oldest = (list) => list.filter(Boolean).sort()[0] || null;
const newest = (list) => list.filter(Boolean).sort().at(-1) || null;

/**
 * @typedef {object} AttentionRow
 * @property {string} kind one of {@link ATTENTION_KINDS}
 * @property {'error'|'warn'|'running'|'info'} severity
 * @property {string} key the i18n key of its text
 * @property {Record<string, any>} params the key's params (`tool`: a view id, named by the caller)
 * @property {string|null} nameParam the param that takes the domains as text, when the key's text names them
 * @property {string[]} names what it is about (domains, a board's name), the soonest first
 * @property {number|null} soonest days to the soonest due (negative: past), null when it has no day
 * @property {string|null} at when its data was read (the oldest of its domains), ISO
 * @property {boolean} stale older than its kind's limit ({@link STALE_DAYS})
 * @property {{ view: string, params?: Record<string, string> }|{ workspace: string }} link where its details are
 * @property {{ id: number, view: string, fraction: number|null }} [job] a running job's progress
 */

/** A row with the fields every kind has. */
function row(kind, severity, key, params, { names = [], soonest = null, at = null, stale = false, link, nameParam = null, job = undefined }) {
  const out = { kind, severity, key, params, nameParam, names, soonest, at, stale, link };
  if (job) out.job = job;
  return out;
}

/** The domains of entries sorted soonest first (then by name), each once. */
function namesOf(entries) {
  const seen = new Set();
  const out = [];
  for (const e of [...entries].sort((a, b) => a.days - b.days || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (!seen.has(e.name)) {
      seen.add(e.name);
      out.push(e.name);
    }
  }
  return out;
}

/** The Domain portfolio filled with these domains (nothing runs), on one of its tabs. */
const portfolioLink = (names, tab = null) => ({
  view: 'portfolio', params: { domains: names.slice(0, LINK_DOMAINS).join(','), ...(tab ? { tab } : {}), run: '0' }
});

/* ------------------------------------------------------------------------ */
/* Certificate expiry (the CT watch's baseline)                             */
/* ------------------------------------------------------------------------ */

/**
 * Certificate expiry from the CT baseline: per domain the `due` days of its last check's current
 * certificates, by the certificate bands (expired, under 7 days: error; under 30: warn). A domain
 * checked before \`due\` existed gives one "check once" row instead (info). Never the baseline's
 * `ids`: they keep a certificate its renewal replaced until it expires.
 * @param {unknown} text the workspace part `ctSeen`
 * @param {number|Date} now
 * @returns {AttentionRow[]}
 */
export function ctAttention(text, now) {
  const seen = readSeen(text);
  const groups = { certExpired: [], cert: [], certWarn: [] };
  const first = [];
  for (const [domain, entry] of Object.entries(seen.domains)) {
    if (!Array.isArray(entry.due)) {
      first.push({ name: domain, days: 0, at: entry.at });
      continue;
    }
    for (const day of entry.due) {
      const days = daysUntil(day, now);
      const sev = expirySeverity('certificate', days);
      if (sev === 'ok' || sev === null) continue;
      const kind = days < 0 ? 'certExpired' : sev === 'error' ? 'cert' : 'certWarn';
      groups[kind].push({ name: domain, days, at: entry.at });
    }
  }
  const out = [];
  const make = (kind, severity, key, list, params) => {
    if (!list.length) return;
    const names = namesOf(list);
    const at = oldest(list.map((e) => e.at));
    out.push(row(kind, severity, key, { count: list.length, ...params }, {
      names, soonest: Math.min(...list.map((e) => e.days)), at, stale: isStale(at, now, STALE_DAYS.ct), link: portfolioLink(names, 'ct')
    }));
  };
  make('certExpired', 'error', 'home.certsExpired', groups.certExpired, {});
  make('cert', 'error', 'home.certs', groups.cert, { days: EXPIRY_BANDS.certificate.error });
  make('cert', 'warn', 'home.certs', groups.certWarn, { days: EXPIRY_BANDS.certificate.warn });
  if (first.length) {
    const names = namesOf(first);
    out.push(row('ctFirst', 'info', 'home.ctFirst', {}, { names, at: oldest(first.map((e) => e.at)), link: portfolioLink(names, 'ct') }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Registrations (the registration watch's snapshot)                         */
/* ------------------------------------------------------------------------ */

/**
 * Registrations from the registration watch's snapshot: the expiry by the registration bands
 * (expired, under 30 days: error; under 60: warn), a registry that does not know the domain
 * (error), and the Domain portfolio's own risk rule (lib/regstatus.js statusRisk): a critical
 * status — a hold, a redemption period, a pending delete — and a pending transfer are errors; no
 * transfer prohibition at all (client, server or plain) is a warning.
 * @param {unknown} text the workspace part `rdapSeen`
 * @param {number|Date} now
 * @returns {AttentionRow[]}
 */
export function regAttention(text, now) {
  const seen = readRdapSeen(text);
  const g = { regExpired: [], regError: [], regWarn: [], regGone: [], regRisk: [], regTransfer: [], regNoLock: [] };
  const critical = new Set();
  for (const [domain, e] of Object.entries(seen.domains)) {
    const base = { name: domain, at: e.at };
    if (e.state === 'not-found') {
      g.regGone.push({ ...base, days: 0 });
      continue;
    }
    const days = e.expires ? daysUntil(e.expires, now) : null;
    const sev = days === null ? null : expirySeverity('registration', days);
    if (sev === 'error') (days < 0 ? g.regExpired : g.regError).push({ ...base, days });
    else if (sev === 'warn') g.regWarn.push({ ...base, days });
    const risk = statusRisk(e.statuses || []);
    const soon = days === null ? 0 : days;
    if (risk.risk === 'critical') {
      g.regRisk.push({ ...base, days: soon });
      for (const c of risk.critical) critical.add(statusName(c));
    } else if (risk.risk === 'pending-transfer') g.regTransfer.push({ ...base, days: soon });
    else if (risk.risk === 'hijack') g.regNoLock.push({ ...base, days: soon });
  }
  const out = [];
  const make = (kind, severity, key, list, params = {}, { nameParam = null, soonest = false } = {}) => {
    if (!list.length) return;
    const names = namesOf(list);
    const at = oldest(list.map((e) => e.at));
    const first = Math.min(...list.map((e) => e.days));
    out.push(row(kind, severity, key, typeof params === 'function' ? params(first) : params, {
      names, nameParam, soonest: soonest ? first : null, at, stale: isStale(at, now, STALE_DAYS.registration), link: portfolioLink(names)
    }));
  };
  // "{days}" is the soonest domain's (its count picks the plural); the others are named after it.
  make('regExpired', 'error', 'home.regExpired', g.regExpired, (first) => ({ count: -first, days: -first }), { soonest: true });
  make('reg', 'error', 'home.reg', g.regError, (first) => ({ count: first, days: first }), { soonest: true });
  make('regGone', 'error', 'home.regGone', g.regGone, { count: g.regGone.length });
  make('regRisk', 'error', 'home.regRisk', g.regRisk, { status: [...critical].sort().join(', ') });
  make('regTransfer', 'error', 'home.regTransfer', g.regTransfer, {}, { nameParam: 'domain' });
  make('reg', 'warn', 'home.reg', g.regWarn, (first) => ({ count: first, days: first }), { soonest: true });
  make('regNoLock', 'warn', 'home.regNoLock', g.regNoLock, { count: g.regNoLock.length });
  return out;
}

/* ------------------------------------------------------------------------ */
/* Accepted risks, rollouts, Monitoring, jobs, the server list              */
/* ------------------------------------------------------------------------ */

/**
 * Accepted risks (lib/waivers.js): ending within WAIVER_SOON_DAYS days (warn), ended — the item
 * counts again — (info). The link opens the Workspaces dialog on them.
 * @param {unknown} text the workspace part `waivers`
 * @param {number|Date} now
 * @returns {AttentionRow[]}
 */
export function waiverAttention(text, now) {
  const soon = [];
  const ended = [];
  for (const w of readWaivers(text, { now })) {
    const st = waiverState(w, { now });
    const entry = { name: w.domain, days: daysUntil(w.expires, now) };
    if (st === 'expiring') soon.push(entry);
    else if (st === 'expired') ended.push(entry);
  }
  const out = [];
  const link = { workspace: 'waivers' };
  if (soon.length) {
    out.push(row('waivers', 'warn', 'home.waivers', { count: soon.length, days: WAIVER_SOON_DAYS }, {
      names: namesOf(soon), soonest: Math.min(...soon.map((e) => e.days)), link
    }));
  }
  if (ended.length) out.push(row('waiversEnded', 'info', 'home.waiversEnded', { count: ended.length }, { names: namesOf(ended), link }));
  return out;
}

/**
 * Rollouts under way (lib/rollout.js), on boards changed in the last {@link ROLLOUT_DAYS} days: a
 * board is open while fewer of its rows are verified than its `total` (the rows the Rollout tab
 * last showed), or — on a board stored before `total` existed — while a ticked row is not
 * verified. One row for them all: "{done} of {total} servers updated" when every open board has
 * its total, else "{verified} verified, {installed} installed" (installed or reloaded, not verified).
 * @param {unknown} text the workspace part `rollout`
 * @param {number|Date} now
 * @returns {AttentionRow[]}
 */
export function rolloutAttention(text, now) {
  const open = [];
  for (const b of parseRollout(text).boards) {
    if (ms(now) - ms(b.updated) > ROLLOUT_DAYS * DAY_MS) continue;
    const verified = b.rows.filter((r) => r.v).length;
    const installed = b.rows.filter((r) => !r.v && (r.i || r.r)).length;
    const hasTotal = Number.isInteger(b.total);
    if (hasTotal ? verified < b.total : installed > 0) open.push({ b, verified, installed, hasTotal });
  }
  if (!open.length) return [];
  const names = open.map((o) => o.b.label || `SHA-256 ${o.b.id.slice(0, 12)}`);
  const at = newest(open.map((o) => o.b.updated));
  const link = { view: 'scan' };
  const verified = open.reduce((n, o) => n + o.verified, 0);
  if (open.every((o) => o.hasTotal)) {
    return [row('rollout', 'info', 'home.rollout', { done: verified, total: open.reduce((n, o) => n + o.b.total, 0) }, { names, at, link })];
  }
  return [row('rolloutTicked', 'info', 'home.rolloutTicked', { verified, installed: open.reduce((n, o) => n + o.installed, 0) }, {
    names, at, link, nameParam: 'label'
  })];
}

/**
 * The Monitoring digest (lib/digests.js), as written by the Monitoring view's last import: the
 * targets with a bad change (error), the certificates near expiry and the checks that did not
 * complete (warn). Stale after {@link STALE_DAYS}.monitor days.
 * @param {unknown} text the workspace part `digests`
 * @param {number|Date} now
 * @returns {AttentionRow[]}
 */
export function monitorAttention(text, now) {
  const d = readDigests(text).monitor;
  if (!d) return [];
  const stale = isStale(d.at, now, STALE_DAYS.monitor);
  const link = { view: 'monitor' };
  const out = [];
  if (d.bad) out.push(row('monitorBad', 'error', 'home.monitorBad', { count: d.bad, days: MONITOR_DIGEST_DAYS.bad }, { at: d.at, stale, link }));
  if (d.expiring) out.push(row('monitorExpiring', 'warn', 'home.monitorExpiring', { count: d.expiring, days: MONITOR_DIGEST_DAYS.expiring }, { at: d.at, stale, link }));
  if (d.incomplete) out.push(row('monitorIncomplete', 'warn', 'home.monitorIncomplete', { count: d.incomplete }, { at: d.at, stale, link }));
  return out;
}

/**
 * The jobs running now (ui/jobs.js jobList): one row each, oldest first.
 * @param {Array<{ id: number, view: string, subject?: string|null, fraction?: number|null }>} jobs
 * @returns {AttentionRow[]}
 */
export function jobAttention(jobs) {
  return (Array.isArray(jobs) ? jobs : []).filter((j) => j && typeof j.view === 'string').map((j) => {
    const fraction = typeof j.fraction === 'number' && Number.isFinite(j.fraction) ? Math.min(1, Math.max(0, j.fraction)) : null;
    return row('job', 'running', fraction === null ? 'home.running' : 'home.runningPercent', { tool: j.view, percent: fraction }, {
      names: j.subject ? [j.subject] : [], link: { view: j.view }, job: { id: j.id, view: j.view, fraction }
    });
  });
}

/**
 * The server list's lines that could not be read (state.inventory.warnings).
 * @param {number} count
 * @returns {AttentionRow[]}
 */
export function serversAttention(count) {
  const n = Number.isInteger(count) && count > 0 ? count : 0;
  return n ? [row('servers', 'warn', 'home.serversWarn', { count: n }, { link: { view: 'inventory' } })] : [];
}

/**
 * DMARC from the report history's roll-up (lib/dmarchistory.js `rollup` over {@link DMARC_DAYS}
 * days): p=reject in force that refuses mail of known senders (error), known senders that fail
 * DMARC (warn, fix them before p=reject).
 * @param {{ rows: Array<{ domain: string, verdict: string, knownFail?: number }> }|null} rolled
 * @returns {AttentionRow[]}
 */
export function dmarcAttention(rolled) {
  const rows = rolled && Array.isArray(rolled.rows) ? rolled.rows : [];
  const out = [];
  const link = { view: 'reports' };
  for (const [verdict, kind, severity, key] of [['enforced-losing', 'dmarcLosing', 'error', 'home.dmarcLosing'], ['fix-first', 'dmarcFixFirst', 'warn', 'home.dmarcFixFirst']]) {
    const list = rows.filter((r) => r && r.verdict === verdict).map((r) => r.domain);
    if (list.length) out.push(row(kind, severity, key, { count: list.length }, { names: list, nameParam: 'domains', link }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Together                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The rows in Home's order: error → warn → running → info, then the soonest first (rows without a
 * day after those with one), then by kind ({@link ATTENTION_KINDS}).
 * @param {AttentionRow[]} rows
 * @returns {AttentionRow[]} a new array
 */
export function sortAttention(rows) {
  const sev = (r) => SEVERITIES.indexOf(r.severity);
  const day = (r) => (typeof r.soonest === 'number' ? r.soonest : Infinity);
  return [...rows].sort((a, b) => sev(a) - sev(b) || day(a) - day(b) || ATTENTION_KINDS.indexOf(a.kind) - ATTENTION_KINDS.indexOf(b.kind));
}

/**
 * What the workspace holds that Home reads, and when it was last read: the CT baseline's and the
 * registration snapshot's domains with their newest check, the accepted risks, the rollout boards,
 * the Monitoring digest. `hasData`: any of them (else Home leaves "Needs attention" out).
 * @param {{ ctSeen?: unknown, rdapSeen?: unknown, waivers?: unknown, rollout?: unknown, digests?: unknown }} parts
 * @param {number|Date} now
 */
export function workspaceFacts(parts, now) {
  const ct = Object.values(readSeen(parts.ctSeen).domains);
  const reg = Object.values(readRdapSeen(parts.rdapSeen).domains);
  const waivers = readWaivers(parts.waivers, { now }).length;
  const boards = parseRollout(parts.rollout).boards.length;
  const monitor = readDigests(parts.digests).monitor || null;
  return {
    ctDomains: ct.length, ctAt: newest(ct.map((e) => e.at)),
    regDomains: reg.length, regAt: newest(reg.map((e) => e.at)),
    waivers, boards, monitorAt: monitor ? monitor.at : null,
    hasData: ct.length > 0 || reg.length > 0 || waivers > 0 || boards > 0 || !!monitor
  };
}

/**
 * Home's "Needs attention" from the workspace's parts, the running jobs and the server list (the
 * DMARC rows are added later: {@link dmarcAttention}).
 * @param {{ parts: { ctSeen?: unknown, rdapSeen?: unknown, waivers?: unknown, rollout?: unknown, digests?: unknown },
 *   jobs?: object[], serverWarnings?: number, now: number|Date }} input
 * @returns {{ rows: AttentionRow[], facts: ReturnType<typeof workspaceFacts>, ok: boolean }}
 *   `ok`: the workspace has data and nothing needs attention (Home's one "Nothing needs attention" row)
 */
export function attention({ parts = {}, jobs = [], serverWarnings = 0, now }) {
  const rows = sortAttention([
    ...ctAttention(parts.ctSeen, now),
    ...regAttention(parts.rdapSeen, now),
    ...waiverAttention(parts.waivers, now),
    ...rolloutAttention(parts.rollout, now),
    ...monitorAttention(parts.digests, now),
    ...jobAttention(jobs),
    ...serversAttention(serverWarnings)
  ]);
  const facts = workspaceFacts(parts, now);
  return { rows, facts, ok: facts.hasData && !rows.length };
}

/**
 * The names a row shows and how many more it has.
 * @param {string[]} names
 * @param {number} [max]
 * @returns {{ shown: string[], more: number }}
 */
export function namesShown(names, max = NAMES_SHOWN) {
  const list = Array.isArray(names) ? names : [];
  return { shown: list.slice(0, max), more: Math.max(0, list.length - max) };
}
