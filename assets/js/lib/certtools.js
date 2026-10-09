/**
 * lib/certtools.js — SSL Targets and Certificate on the page template (docs/DESIGN.md §5.6, §8
 * phase 3), as data: what each result header's status summary counts and what pressing an item
 * does (a Hosts filter, a tab), the key metric, the Certificate's chain and CAA states, and SSL
 * Targets' findings, which replace its stacked alerts.
 *
 * Pure: no DOM, i18n or clock. Texts are keys with their parameters; the views turn them into
 * words. Renewal readiness keeps its status items in lib/renewal.js (renewalStatus), Certificate
 * estate in lib/estate.js (estateStatus), and SSL Targets' folded setup row in lib/scanform.js.
 */

const count = (n) => (Number.isFinite(Number(n)) && Number(n) > 0 ? Math.floor(Number(n)) : 0);

/* ------------------------------------------------------------------------ */
/* SSL Targets                                                              */
/* ------------------------------------------------------------------------ */

/** The SSL Targets status items, in their order (DESIGN §5.6). */
export const SCAN_STATUS = Object.freeze(['servers', 'unresolved', 'behind', 'covered']);

/**
 * The status summary of a scan (DESIGN §5.6): the servers of the list that need the certificate
 * (warn; without a certificate the servers the names point to, neutral) — a press opens the Servers
 * tab —; hosts that do not resolve (warn), hosts behind a CDN (info) and hosts the certificate covers
 * (ok), each a filter of the Hosts table (`filter`: views/scan.js KIND_FILTERS, or 'covered'). The
 * servers count only once the scan has a result and the list has servers.
 * @param {{ counts?: { unresolved?: number, nxdomain?: number, hidden?: number, covered?: number },
 *   stats?: { needsCert?: number, matchedServers?: number }|null, cert?: boolean, inventory?: boolean }} [facts]
 *   `counts`: views/scan.js countHosts (live or final); `stats`: the finished result's
 * @returns {Array<{ key: string, severity: string, count: number, filter: string|null, tab: string }>}
 */
export function scanStatus({ counts = {}, stats = null, cert = false, inventory = false } = {}) {
  const c = counts || {};
  const servers = stats && inventory ? count(cert ? stats.needsCert : stats.matchedServers) : 0;
  return [
    { key: 'servers', severity: cert ? 'warn' : 'neutral', count: servers, filter: null, tab: 'servers' },
    { key: 'unresolved', severity: 'warn', count: count(c.unresolved) + count(c.nxdomain), filter: 'unresolved', tab: 'hosts' },
    { key: 'behind', severity: 'info', count: count(c.hidden), filter: 'hidden', tab: 'hosts' },
    { key: 'covered', severity: 'ok', count: cert ? count(c.covered) : 0, filter: 'covered', tab: 'hosts' }
  ];
}

/**
 * The key metric of a finished scan: the servers to update (with a certificate) or the servers the
 * names point to (without one); null without a result or without a server list.
 * @param {{ stats?: { needsCert?: number, matchedServers?: number }|null, cert?: boolean, inventory?: boolean }} [facts]
 * @returns {{ value: number, kind: 'needs'|'matched', severity: 'warn'|null }|null}
 */
export function scanKeyMetric({ stats = null, cert = false, inventory = false } = {}) {
  if (!stats || !inventory) return null;
  const value = count(cert ? stats.needsCert : stats.matchedServers);
  return { value, kind: cert ? 'needs' : 'matched', severity: cert && value ? 'warn' : null };
}

/**
 * SSL Targets' findings (DESIGN §5.6: "6 alerts → finding list", in the Hosts tab): what the old
 * summary alerts said, each with its key (the view's `data-summary` hook), severity, icon and text
 * (`text`: an i18n key and its parameters; null where the view words it itself: the renewal line).
 * The finding list shows the worst first (lib/template.js findingRows).
 * @param {{ inventory?: boolean, cert?: boolean, stats?: object, suspects?: number, nowhere?: string[], plan?: { need: number,
 *   uncovered: number }|null, verify?: boolean, mx?: boolean, networks?: string[], tech?: { total: number, dns: number, sources: number,
 *   zone?: number }|null, wildcards?: string[], failedSources?: number, warnings?: Array<{ code: string, detail?: string }>,
 *   knownWarnings?: string[] }} facts `stats`: the result's (needsCert, matchedServers, hiddenOrigin, unmatchedIps, dangling);
 *   `suspects`: servers the inventory and DNS disagree on; `nowhere`: names whose TLS terminates nowhere; `plan`: several
 *   certificates (`need`: servers of the list that need a set); `verify`: pairs to check exist; `mx`: in-domain mail servers;
 *   `knownWarnings`: the warning codes the view has words for
 * @returns {Array<{ key: string, severity: 'error'|'warn'|'info'|'ok', icon: string, text: { key: string, params: object }|null,
 *   raw?: string }>}
 */
export function scanFindings({
  inventory = false, cert = false, stats = {}, suspects = 0, nowhere = [], plan = null, verify = false, mx = false, networks = [],
  tech = null, wildcards = [], failedSources = 0, warnings = [], knownWarnings = []
} = {}) {
  const st = stats || {};
  const out = [];
  const add = (key, severity, icon, textKey, params = {}) => out.push({ key, severity, icon, text: textKey ? { key: textKey, params } : null });
  if (inventory) {
    if (cert) {
      // Several certificates: the renewal line says how many servers need one of the sets.
      if (count(st.needsCert)) {
        if (!plan) add('needs', 'warn', 'server', 'scan.sum.needs', { count: count(st.needsCert) });
      } else add('needs-none', 'ok', 'check-circle', 'scan.sum.needsNone');
    } else if (count(st.matchedServers)) add('matched', 'info', 'server', 'scan.sum.matched', { count: count(st.matchedServers) });
    if (count(suspects)) add('topology-suspect', 'warn', 'alert', 'topo.sum.suspect', { count: count(suspects) });
    const none = Array.isArray(nowhere) ? nowhere : [];
    if (none.length) add('topology-nowhere', 'warn', 'alert', 'topo.sum.nowhere', { count: none.length, names: none.slice(0, 3).join(', ') + (none.length > 3 ? '…' : '') });
  } else add('no-inventory', 'info', 'server', 'scan.sum.noInventory');
  if (plan) {
    out.push({ key: 'renewal', severity: inventory && count(plan.need) ? 'warn' : 'info', icon: 'layers', text: null });
    if (count(plan.uncovered)) add('renewal-uncovered', 'info', 'help', 'rw.sum.uncovered', { count: count(plan.uncovered) });
  }
  if (cert && verify) add('verify', 'info', 'check-circle', plan ? 'scan.sum.verifyMany' : 'scan.sum.verify');
  if (cert && mx) add('dane', 'info', 'mail', 'scan.sum.dane');
  if (count(st.hiddenOrigin)) add('hidden', 'info', 'cloud', 'scan.sum.hidden', { count: count(st.hiddenOrigin) });
  const nets = Array.isArray(networks) ? networks : [];
  if (count(st.hiddenOrigin) && nets.length) {
    add('networks', 'info', 'network', 'scan.sum.networks', { count: nets.length, list: nets.slice(0, 3).join(', ') + (nets.length > 3 ? '…' : '') });
  }
  if (tech && count(tech.total)) {
    const params = { dns: count(tech.dns), sources: count(tech.sources), zone: count(tech.zone) };
    add('discovery', 'info', 'search', count(tech.zone) ? 'scan.sum.discoveryZone' : 'scan.sum.discovery', params);
  }
  if (inventory && count(st.unmatchedIps)) add('unmatched', 'info', 'help', 'scan.sum.unmatched', { count: count(st.unmatchedIps) });
  if (count(st.dangling)) add('dangling', 'error', 'unlink', 'scan.sum.dangling', { count: count(st.dangling) });
  const wild = Array.isArray(wildcards) ? wildcards : [];
  if (wild.length) add('wildcard', 'info', 'layers', 'scan.sum.wildcard', { list: wild.join(', ') });
  if (count(failedSources)) add('sources-failed', 'warn', 'alert', 'scan.sum.sourcesFailed', { count: count(failedSources) });
  const known = new Set(Array.isArray(knownWarnings) ? knownWarnings : []);
  for (const w of Array.isArray(warnings) ? warnings : []) {
    if (!w || typeof w.code !== 'string' || !w.code) continue;
    // A code without a sentence (a newer scanner) still reads as `CODE: detail`, never as a raw key.
    const entry = { key: w.code, severity: 'warn', icon: 'alert', text: known.has(w.code) ? { key: `scan.warn.${w.code}`, params: { detail: w.detail } } : null };
    if (!entry.text) entry.raw = `${w.code}: ${w.detail ?? ''}`;
    out.push(entry);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Certificate                                                              */
/* ------------------------------------------------------------------------ */

/** Chain issues that make a file's chain wrong whatever its last issuer (views/cert.js analyzeChain codes). */
const CHAIN_PROBLEMS = Object.freeze(['order', 'unrelated', 'expired', 'self-signed']);

/**
 * The state of a certificate file's chain, for its result header: 'incomplete' (the server
 * certificate alone in a file, or an intermediate the CCADB list has to add), 'issues' (wrong
 * order, a certificate of another chain, an expired intermediate, a self-signed server
 * certificate), 'pending' (the CCADB lookup still runs), 'unknown' (a certificate from Certificate
 * Transparency — a log holds the leaf only —, or a last issuer that is neither a root nor listed),
 * else 'complete'.
 * @param {{ issues?: Array<{ code: string }>, end?: 'root'|'intermediate'|'unknown'|'unchecked'|'pending', fromCt?: boolean }} [facts]
 *   `issues`: analyzeChain's; `end`: views/cert.js chainEndVerdict of the file's lookup
 * @returns {'complete'|'incomplete'|'issues'|'pending'|'unknown'}
 */
export function certChainState({ issues = [], end = 'root', fromCt = false } = {}) {
  const codes = new Set((Array.isArray(issues) ? issues : []).map((i) => i && i.code));
  if (fromCt) return 'unknown';
  if (codes.has('leaf-only')) return 'incomplete';
  if (codes.has('ends-at') && end === 'intermediate') return 'incomplete';
  if (CHAIN_PROBLEMS.some((c) => codes.has(c))) return 'issues';
  if (codes.has('ends-at') && end === 'pending') return 'pending';
  if (codes.has('ends-at') && (end === 'unknown' || end === 'unchecked')) return 'unknown';
  return 'complete';
}

/**
 * The state of a certificate's CAA check (views/cert.js caaCache entry): 'unchecked' (none yet: the
 * CAA tab checks on its first show), 'running', 'error', else what the names' verdicts add up to —
 * 'denied' (one name blocks the CA), 'unknown', 'restricted' or 'allowed'; 'none' when the
 * certificate has no name to check.
 * @param {{ status?: string, rows?: Array<{ verdict: { allowed: boolean|null, verdict: string }|null }> }|null} entry
 * @param {{ names?: number }} [opts] how many names the check covers
 * @returns {'none'|'unchecked'|'running'|'error'|'denied'|'unknown'|'restricted'|'allowed'}
 */
export function caaState(entry, { names = 1 } = {}) {
  if (!count(names)) return 'none';
  if (!entry || entry.status === 'aborted') return 'unchecked';
  if (entry.status === 'running') return 'running';
  if (entry.status === 'error') return 'error';
  const rows = Array.isArray(entry.rows) ? entry.rows : [];
  if (rows.some((r) => r && r.verdict && r.verdict.allowed === false)) return 'denied';
  if (rows.some((r) => !r || !r.verdict || r.verdict.allowed === null)) return 'unknown';
  if (rows.some((r) => r.verdict.verdict === 'restricted')) return 'restricted';
  return 'allowed';
}

const CHAIN_SEVERITY = Object.freeze({ complete: 'neutral', incomplete: 'warn', issues: 'warn', pending: 'neutral', unknown: 'info' });
const CAA_SEVERITY = Object.freeze({
  unchecked: 'neutral', running: 'neutral', error: 'info', denied: 'error', unknown: 'info', restricted: 'warn', allowed: 'ok'
});
const VALIDITY_SEVERITY = Object.freeze({ expired: 'error', expiring: 'warn', notyet: 'warn', ok: 'ok' });

/**
 * The Certificate's status summary (DESIGN §5.6: "✕ expired / ⚠ ≤ 30 d · chain complete/incomplete
 * · CAA"): the validity, the chain of the file and the CAA check, each a button that opens the tab
 * that says more (`tab`) — none is a filter. Every item counts 1: its words are the state
 * (`state`). A certificate without a name to check has no CAA item.
 * @param {{ validity: { state: 'expired'|'expiring'|'notyet'|'ok', days?: number }, chain?: string, caa?: string }} facts
 *   `chain`: {@link certChainState}; `caa`: {@link caaState}
 * @returns {Array<{ key: 'validity'|'chain'|'caa', severity: string, count: 1, state: string, days: number, tab: string }>}
 */
export function certStatus({ validity, chain = 'complete', caa = 'unchecked' } = {}) {
  const v = validity || { state: 'ok', days: 0 };
  const out = [{ key: 'validity', severity: VALIDITY_SEVERITY[v.state] || 'neutral', count: 1, state: v.state, days: count(v.days), tab: 'details' }];
  out.push({ key: 'chain', severity: CHAIN_SEVERITY[chain] || 'neutral', count: 1, state: chain, days: 0, tab: 'chain' });
  if (caa !== 'none') out.push({ key: 'caa', severity: CAA_SEVERITY[caa] || 'neutral', count: 1, state: caa, days: 0, tab: 'caa' });
  return out;
}

/**
 * The Certificate's key metric: the days left (or since it expired, or until it becomes valid), with
 * the validity's severity — the days are the figure, the unit says which.
 * @param {{ state: 'expired'|'expiring'|'notyet'|'ok', days?: number }} validity views/cert.js validityState
 * @returns {{ value: number, unit: 'left'|'ago'|'until', severity: 'error'|'warn'|'ok' }}
 */
export function certKeyMetric(validity) {
  const v = validity || { state: 'ok', days: 0 };
  const value = count(v.days);
  if (v.state === 'expired') return { value, unit: 'ago', severity: 'error' };
  if (v.state === 'notyet') return { value, unit: 'until', severity: 'warn' };
  return { value, unit: 'left', severity: v.state === 'expiring' ? 'warn' : 'ok' };
}
