/**
 * exposure.js — the origin exposure audit of a CDN-proxied host (ROADMAP P0.2). A name sits
 * behind Cloudflare or another CDN and its real origin address is known (the workspace origin map,
 * an imported zone, an inventory server); this module asks how exposed that origin is:
 *
 * - DNS leaks: other records of the same domain that point straight at the origin address — a
 *   non-proxied A / AAAA, an MX host, an SPF ip4 / ip6 / a / mx mechanism, an HTTPS / SVCB address
 *   hint, a TXT record that carries the address as a literal — found over DoH and classified here
 *   ({@link leaksFromCheck}, reusing lib/retire.js checkDomain for the live lookups, and
 *   {@link txtLeaks} for the TXT literals). A record that reveals the origin to anyone reading
 *   public DNS defeats the CDN before a single request is made.
 * - Direct reachability: an HTTPS GET of the origin address with the proxied name as SNI and Host
 *   header (lib/globalping.js httpsGetAtRequest, through the consent gate), compared with the
 *   proxied answer the CDN serves (httpsGetRequest): if the origin serves the site directly, the
 *   WAF is bypassable ({@link exposureProbes}, {@link readExposureSides}, {@link reachabilityFinding},
 *   reusing lib/origincompare.js readSide / compareSides). Private / reserved addresses and names
 *   a probe cannot accept are never sent — they are audited for DNS leaks only.
 * - Advice per finding ({@link FINDING_ADVICE}): allow only the CDN's published ranges at the
 *   firewall, Authenticated Origin Pulls / mTLS, a Cloudflare Tunnel, move the leaked service off
 *   the origin address, rotate the origin address once the leak is closed.
 *
 * DOM-free; runs in browsers and Node 22. Codes are frozen arrays the UI words and the i18n
 * coverage enumerates. Nothing is sent by importing this module: a DNS scan uses the injected DNS
 * client, a reachability probe the caller's Globalping client, and the addresses themselves are
 * only compared here. Spec §5.87.
 */

import { checkDomain, parseRetireTargets } from './retire.js';
import { httpsGetRequest, httpsGetAtRequest, isProbeableIP, isProbeableHost, isProbeablePort } from './globalping.js';
import { readSide, compareSides } from './origincompare.js';
import { knownForScan, originTarget, ORIGIN_DEFAULT_PORT } from './originmap.js';
import { normalizeHostname, registrableDomain } from './domain.js';
import { normalizeIP, isPrivateIP, matchProviderByIP } from './netinfo.js';
import { lookupServers } from './inventory.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies (frozen; the i18n coverage derives keys from them)          */
/* ------------------------------------------------------------------------ */

/** What a finding is (`exp.finding.<kind>`), worst first. */
export const EXPOSURE_FINDINGS = Object.freeze(['reachable', 'dns-a', 'https-hint', 'dns-mx', 'spf', 'txt-ip', 'dns-ns']);
/** A finding's severity (`exp.sev.<s>`), worst first. */
export const EXPOSURE_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
/** What a reachability probe found (`exp.reach.<r>`). Only `exposed` is a finding; the rest are good or inconclusive. */
export const REACH_RESULTS = Object.freeze(['exposed', 'other-content', 'filtered', 'closed', 'unreachable', 'incomplete']);
/** The fixes a finding suggests (`exp.advice.<a>`). */
export const EXPOSURE_ADVICE = Object.freeze(['firewall', 'aop', 'tunnel', 'move', 'rotate']);
/** Why a target is audited for DNS leaks only, never probed (`exp.skip.<r>`). */
export const SKIP_REASONS = Object.freeze(['private', 'reserved', 'wildcard', 'bad-name', 'bad-port']);

/** A finding kind → its severity. `dns-a` of the proxied name itself is lifted to critical ({@link leakSeverity}). */
export const FINDING_SEVERITY = Object.freeze({
  reachable: 'critical', 'dns-a': 'high', 'https-hint': 'high', 'dns-mx': 'medium', spf: 'medium', 'txt-ip': 'medium', 'dns-ns': 'low'
});

/** A finding kind → the advice codes it carries, in display order. */
export const FINDING_ADVICE = Object.freeze({
  reachable: Object.freeze(['firewall', 'aop', 'tunnel', 'rotate']),
  'dns-a': Object.freeze(['rotate', 'firewall', 'tunnel']),
  'https-hint': Object.freeze(['rotate', 'firewall']),
  'dns-mx': Object.freeze(['move', 'rotate', 'firewall']),
  spf: Object.freeze(['move', 'rotate']),
  'txt-ip': Object.freeze(['rotate']),
  'dns-ns': Object.freeze(['move', 'rotate'])
});

/** The CLI / hosts that resolve a proxied name to the CDN (the proxied side of a reachability probe) accept these ports. */
export const EXPOSURE_TIMEOUT_S = 10;
/** Globalping probes one reachability check costs: one for the CDN answer, one for the origin. */
export const EXPOSURE_PROBES = 2;
/** At most this many targets one audit resolves (DoH), to bound a huge origin map. */
export const EXPOSURE_MAX_TARGETS = 500;
/** TXT strings longer than this are not searched for an address literal (a DKIM key, say). */
const TXT_SCAN_MAX = 1024;

const DAY_MS = 86400000;

/* ------------------------------------------------------------------------ */
/* The targets to audit                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ExposureTarget
 * @property {string} name the proxied name whose origin is audited (`*.x` for a wildcard entry)
 * @property {string} ip the origin address
 * @property {number} port the origin port
 * @property {string} target the CLI target (`originTarget`: the address, or `ip:port`)
 * @property {string|null} server the inventory server at the address, if any
 * @property {string} source where the origin is known from ({@link ORIGIN_SOURCES} or `zone`)
 * @property {string|null} domain the registrable domain of the name
 * @property {boolean} wildcard the name is a `*.x` entry
 * @property {boolean} private the origin is a private / reserved / documentation address
 * @property {boolean} probeable the origin and name can be probed from the internet (public address, a host name, a usable port)
 * @property {string|null} skip why it is not probed ({@link SKIP_REASONS}), or null
 */

/**
 * The (proxied name, origin) pairs to audit, from the workspace origin map (its active entries),
 * an imported zone's proxied origins and — for the server label and to mark which address is the
 * customer's own — the inventory. De-duplicated by name, address and port; capped at
 * {@link EXPOSURE_MAX_TARGETS}. Pure.
 * @param {{ map?: object|null, zone?: object|null, index?: Map<string, object[]>|null }} input
 *   `map`: the origins workspace part (or its index); `zone`: `state.session.zone` (its `proxied`
 *   list); `index`: the inventory IP index (`getInventoryIndex`)
 * @returns {{ targets: ExposureTarget[], capped: boolean }}
 */
export function exposureTargets({ map = null, zone = null, index = null } = {}) {
  const seen = new Map();
  const add = (rawName, rawIp, rawPort, source, serverHint) => {
    const name = normalizeHostname(String(rawName ?? ''), { allowWildcard: true });
    const ip = normalizeIP(String(rawIp ?? ''));
    if (!name || !ip) return;
    const port = Number.isInteger(rawPort) && rawPort >= 1 && rawPort <= 65535 ? rawPort : ORIGIN_DEFAULT_PORT;
    const key = `${name}|${ip}|${port}`;
    if (seen.has(key)) return;
    const wildcard = name.startsWith('*.');
    const priv = isPrivateIP(ip);
    const owners = index ? lookupServers([ip], index) : [];
    const server = serverHint || (owners.length ? owners[0].server.name : null);
    // The order matters: a private / reserved address is never probed whatever else is true.
    let skip = null;
    if (priv) skip = 'private';
    else if (!isProbeableIP(ip)) skip = 'reserved';
    else if (wildcard) skip = 'wildcard';
    else if (!isProbeableHost(name)) skip = 'bad-name';
    else if (!isProbeablePort(port)) skip = 'bad-port';
    seen.set(key, {
      name, ip, port, target: originTarget({ ip, port }), server: server || null, source,
      domain: registrableDomain(wildcard ? name.slice(2) : name), wildcard, private: priv,
      probeable: skip === null, skip
    });
  };

  for (const e of knownForScan(map)) add(e.name, e.ip, e.port, e.source || 'manual', e.server);
  const proxied = zone && Array.isArray(zone.proxied) ? zone.proxied : [];
  for (const p of proxied) {
    if (!p || typeof p.name !== 'string') continue;
    for (const ip of Array.isArray(p.ips) ? p.ips : []) add(p.name, ip, ORIGIN_DEFAULT_PORT, 'zone', null);
  }

  const targets = [...seen.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
    || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0) || a.port - b.port);
  return { targets: targets.slice(0, EXPOSURE_MAX_TARGETS), capped: targets.length > EXPOSURE_MAX_TARGETS };
}

/** An audited target's key: `name|ip|port`. */
export const targetKey = (t) => `${t.name}|${t.ip}|${t.port}`;

/* ------------------------------------------------------------------------ */
/* DNS leaks                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ExposureFinding
 * @property {string} kind one of {@link EXPOSURE_FINDINGS}
 * @property {string} severity one of {@link EXPOSURE_SEVERITIES}
 * @property {string} ip the origin address the finding is about
 * @property {number} port the origin port
 * @property {string} target the CLI target of the origin
 * @property {string[]} names the proxied names whose origin this address is (one address can serve several)
 * @property {string} record the DNS owner / term / probe that reveals the address
 * @property {string|null} recordType A, AAAA, MX, NS, HTTPS, SPF, TXT (null for a reachability finding)
 * @property {string|null} detail a short extra ({@link REACH_RESULTS}, an SPF mechanism, a probe location)
 * @property {string|null} server the inventory server at the address
 * @property {string[]} advice the fix codes, in order ({@link FINDING_ADVICE})
 */

/** The severity of a DNS-leak finding: `dns-a` whose leaking owner IS a proxied name itself is critical (the proxy is bypassed in DNS). */
function leakSeverity(kind, record, names) {
  if (kind === 'dns-a' && names.some((n) => n === record)) return 'critical';
  return FINDING_SEVERITY[kind] || 'low';
}

/** Build one finding, filling severity and advice from its kind. */
function finding(kind, { ip, port, target, names, record, recordType = null, detail = null, server = null }) {
  const list = [...new Set(names)].sort();
  const severity = kind === 'reachable' ? FINDING_SEVERITY.reachable : leakSeverity(kind, record, list);
  return { kind, severity, ip, port, target, names: list, record, recordType, detail, server, advice: [...(FINDING_ADVICE[kind] || [])] };
}

/**
 * The DNS leaks in one domain's live evidence (lib/retire.js `checkDomain`, run with the origin
 * addresses as its blocks): the names, MX / NS hosts, SPF mechanisms and HTTPS hints that reach an
 * origin address. Pure — nothing is looked up here.
 * @param {object} check a lib/retire.js DomainCheck
 * @param {Map<string, ExposureTarget[]>} byIp origin address → the targets at it ({@link indexByIp})
 * @returns {ExposureFinding[]}
 */
export function leaksFromCheck(check, byIp) {
  if (!check || typeof check !== 'object') return [];
  const out = [];
  const at = (ip) => byIp.get(normalizeIP(String(ip))) || null;
  const meta = (ip) => {
    const list = at(ip);
    const port = list && list.length ? list[0].port : ORIGIN_DEFAULT_PORT;
    return { ip: normalizeIP(String(ip)), port, target: originTarget({ ip: normalizeIP(String(ip)), port }),
      names: list ? list.map((t) => t.name) : [], server: list && list.length ? list[0].server : null };
  };

  // A / AAAA (hosts, MX hosts, name servers): a resolved name whose address is an origin.
  for (const n of Array.isArray(check.names) ? check.names : []) {
    const roles = Array.isArray(n.roles) ? n.roles : [];
    const kind = roles.includes('mx') && !roles.includes('host') && !roles.includes('apex') ? 'dns-mx'
      : roles.includes('ns') && !roles.includes('host') && !roles.includes('apex') ? 'dns-ns' : 'dns-a';
    for (const [list, type] of [[n.ipv4, 'A'], [n.ipv6, 'AAAA']]) {
      for (const ip of Array.isArray(list) ? list : []) {
        if (!at(ip)) continue;
        out.push(finding(kind, { ...meta(ip), record: n.name, recordType: type }));
      }
    }
  }

  // SPF ip4 / ip6 / a / mx mechanisms that cover an origin (checkDomain already filtered to the blocks).
  for (const m of check.spf && Array.isArray(check.spf.matches) ? check.spf.matches : []) {
    const ip = m.block && m.block.includes('/') ? m.block.split('/')[0] : m.block;
    if (!at(ip)) continue;
    out.push(finding('spf', { ...meta(ip), record: `${m.holder || check.domain}: ${m.term}`, recordType: 'SPF', detail: m.mechanism }));
  }

  // HTTPS / SVCB address hints.
  for (const hint of check.https && Array.isArray(check.https.hints) ? check.https.hints : []) {
    if (!at(hint.address)) continue;
    out.push(finding('https-hint', { ...meta(hint.address), record: hint.owner, recordType: 'HTTPS' }));
  }

  return dedupeFindings(out);
}

/**
 * TXT records that carry an origin address as a bare literal (a verification token, a self-hosted
 * SPF-style note). Pure. SPF (`v=spf1 …`) is covered by {@link leaksFromCheck} and skipped here.
 * @param {Array<{ name?: string, type?: string, data?: unknown }>} answers DoH answer records for the domain / name
 * @param {Map<string, ExposureTarget[]>} byIp origin address → targets
 * @returns {ExposureFinding[]}
 */
export function txtLeaks(answers, byIp) {
  const out = [];
  const ips = [...byIp.keys()];
  for (const rr of Array.isArray(answers) ? answers : []) {
    if (!rr || rr.type !== 'TXT') continue;
    const text = Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '');
    if (!text || text.length > TXT_SCAN_MAX || /^v=spf1(?= |$)/i.test(text)) continue;
    for (const ip of ips) {
      if (!containsAddress(text, ip)) continue;
      const list = byIp.get(ip);
      const port = list.length ? list[0].port : ORIGIN_DEFAULT_PORT;
      out.push(finding('txt-ip', {
        ip, port, target: originTarget({ ip, port }), names: list.map((t) => t.name),
        server: list.length ? list[0].server : null, record: String(rr.name ?? ''), recordType: 'TXT',
        detail: text.length > 60 ? `${text.slice(0, 57)}…` : text
      }));
    }
  }
  return dedupeFindings(out);
}

/** Whether `text` contains the address `ip` as a token (not glued to other hex / digits / dots). */
function containsAddress(text, ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    // An IPv6 address can be written several ways; match the exact normalized form on a boundary.
    const re = new RegExp(`(?<![0-9a-f:])${ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![0-9a-f:])`, 'i');
    return re.test(text);
  }
  const re = new RegExp(`(?<![\\w.])${ip.replace(/\./g, '\\.')}(?![\\w.])`);
  return re.test(text);
}

/** Drop findings with the same kind, record and address (several lookups can surface one). */
function dedupeFindings(list) {
  const seen = new Set();
  const out = [];
  for (const f of list) {
    const k = `${f.kind}|${f.recordType}|${f.record}|${f.ip}|${f.port}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

/** Origin address → the targets at it, for {@link leaksFromCheck} / {@link txtLeaks}. */
export function indexByIp(targets) {
  const byIp = new Map();
  for (const t of Array.isArray(targets) ? targets : []) {
    const ip = normalizeIP(t.ip);
    if (!ip) continue;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(t);
  }
  return byIp;
}

/**
 * Run the DNS-leak half of the audit over the injected DoH client: group the targets by registrable
 * domain, check each domain (its own records, the target names, its MX / NS / SPF / HTTPS) and the
 * TXT of each domain apex, and collect the leaks. Failures are reported, never silent: a domain
 * whose lookups failed is in `failures`. Only an abort rejects.
 * @param {{ targets: ExposureTarget[], dns: object, signal?: AbortSignal, hosts?: Map<string, string[]>|object,
 *   onProgress?: (done: number, total: number) => void }} opts `dns`: a DohClient (query, resolveHost)
 * @returns {Promise<{ findings: ExposureFinding[], domains: string[],
 *   failures: Array<{ domain: string, what: string, error: string }>, aborted: boolean }>}
 */
export async function runLeakScan({ targets, dns, signal, hosts = new Map(), onProgress } = {}) {
  if (!dns || typeof dns.query !== 'function' || typeof dns.resolveHost !== 'function') {
    throw new TypeError('runLeakScan: a DNS client with query() and resolveHost() is required');
  }
  const byDomain = new Map();
  for (const t of Array.isArray(targets) ? targets : []) {
    if (!t.domain) continue;
    if (!byDomain.has(t.domain)) byDomain.set(t.domain, []);
    byDomain.get(t.domain).push(t);
  }
  const findings = [];
  const failures = [];
  const domains = [...byDomain.keys()].sort();
  let done = 0;
  const getHosts = (d) => {
    const raw = hosts instanceof Map ? hosts.get(d) : (hosts && hosts[d]);
    return Array.isArray(raw) ? raw : [];
  };
  let aborted = false;
  for (const domain of domains) {
    const domTargets = byDomain.get(domain);
    const byIp = indexByIp(domTargets);
    const blocks = parseRetireTargets([...byIp.keys()].join('\n')).blocks;
    const names = [...new Set([...domTargets.map((t) => (t.wildcard ? null : t.name)).filter(Boolean), ...getHosts(domain)])];
    try {
      const check = await checkDomain(domain, { dns, blocks, hosts: names, signal });
      for (const f of leaksFromCheck(check, byIp)) findings.push(f);
      const txt = await dns.query(domain, 'TXT', { signal });
      if (txt && txt.ok && Array.isArray(txt.answers)) for (const f of txtLeaks(txt.answers, byIp)) findings.push(f);
      for (const fail of check.failures || []) failures.push({ domain, what: fail.what, error: fail.error });
    } catch (err) {
      if (err && err.name === 'AbortError') {
        aborted = true;
        break;
      }
      failures.push({ domain, what: 'domain', error: String((err && err.message) || err) });
    }
    done += 1;
    if (typeof onProgress === 'function') {
      try {
        onProgress(done, domains.length);
      } catch {
        /* a progress hook never breaks the scan */
      }
    }
  }
  return { findings: sortFindings(dedupeFindings(findings)), domains, failures, aborted };
}

/* ------------------------------------------------------------------------ */
/* Direct reachability (opt-in, through Globalping)                         */
/* ------------------------------------------------------------------------ */

/**
 * The two Globalping request bodies of a reachability check: the proxied answer (a GET of the name,
 * which the CDN serves) and the origin answer (a GET of the origin address with the name as SNI /
 * Host). Pure. Throws for a target a probe cannot accept — guard with `target.probeable` first.
 * @param {{ name: string, ip: string, port?: number }} target
 * @returns {{ proxied: object, origin: object }}
 */
export function exposureProbes({ name, ip, port = ORIGIN_DEFAULT_PORT }) {
  return {
    proxied: httpsGetRequest({ host: name, path: '/', port, timeoutS: EXPOSURE_TIMEOUT_S, probes: 1 }),
    origin: httpsGetAtRequest({ ip, host: name, path: '/', port, timeoutS: EXPOSURE_TIMEOUT_S, probes: 1 })
  };
}

/**
 * Read both finished measurements into {@link readSide} shapes (lib/origincompare.js): the CDN side
 * (the name resolved by the probe) and the origin side (the address with the name as Host). Pure.
 * @param {{ proxiedMeasurement: object, originMeasurement: object, name: string, ip: string, now?: number }} opts
 * @returns {{ proxied: object, origin: object }}
 */
export function readExposureSides({ proxiedMeasurement, originMeasurement, name, ip, now = Date.now() }) {
  return {
    proxied: readSide(proxiedMeasurement, { ip: null, host: name, now }),
    origin: readSide(originMeasurement, { ip, host: name, now })
  };
}

/**
 * The reachability of one origin from its two sides. The origin is `exposed` when it answered over
 * HTTPS with a certificate that covers the name (whatever the status: a 403 over a valid
 * certificate is still a direct hit), and the CDN served a certificate too — the WAF is bypassable.
 * It is `filtered` when the origin gave no TCP answer (a firewall that drops direct traffic — the
 * wanted outcome), `closed` when the connection was refused, `other-content` when it answered but
 * with a certificate that does not cover the name (the address hosts something else), `unreachable`
 * for any other origin failure and `incomplete` when the CDN side itself did not answer (nothing to
 * compare with). Only `exposed` is a finding ({@link EXPOSURE_FINDINGS}). Pure.
 * @param {{ proxied: object, origin: object }} sides {@link readExposureSides}
 * @param {{ name: string, ip: string, port?: number, server?: string|null, now?: number }} ctx
 * @returns {{ result: string, finding: ExposureFinding|null, differs: boolean }}
 */
export function reachabilityFinding(sides, { name, ip, port = ORIGIN_DEFAULT_PORT, server = null, now = Date.now() }) {
  const { proxied, origin } = sides;
  const mk = (result, detail) => ({
    result, differs: false,
    finding: result === 'exposed'
      ? finding('reachable', { ip: normalizeIP(ip), port, target: originTarget({ ip: normalizeIP(ip), port }), names: [name], server, record: name, detail })
      : null
  });
  if (!proxied || !proxied.ok) return mk('incomplete', proxied && proxied.failure ? proxied.failure.kind : null);
  if (origin && origin.ok) {
    const covers = !!(origin.cert && origin.cert.covers);
    if (!covers) return mk('other-content', origin.cert ? 'cert-mismatch' : 'no-cert');
    const cmp = compareSides(proxied, origin, { now });
    const out = mk('exposed', cmp.verdict);
    out.differs = cmp.verdict === 'differs' || cmp.verdict === 'broken';
    return out;
  }
  const kind = origin && origin.failure ? origin.failure.kind : 'unknown';
  if (kind === 'connect-timeout' || kind === 'tls-timeout') return mk('filtered', kind);
  if (kind === 'refused' || kind === 'reset') return mk('closed', kind);
  return mk('unreachable', kind);
}

/* ------------------------------------------------------------------------ */
/* Roll-up, provider hint and exports                                       */
/* ------------------------------------------------------------------------ */

const SEV_RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const KIND_RANK = Object.freeze(Object.fromEntries(EXPOSURE_FINDINGS.map((k, i) => [k, i])));

/** Worst severity first, then by kind, then by the first affected name. */
export function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) =>
    (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)
    || (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9)
    || ((a.names[0] || '') < (b.names[0] || '') ? -1 : (a.names[0] || '') > (b.names[0] || '') ? 1 : 0)
    || (a.record < b.record ? -1 : a.record > b.record ? 1 : 0));
}

/**
 * A roll-up of an audit: the count per severity, the worst severity found and the number of leaked
 * origin addresses. Pure.
 * @param {ExposureFinding[]} findings
 * @returns {{ total: number, worst: string|null, bySeverity: Record<string, number>, leakedIps: number, exposed: number }}
 */
export function exposureSummary(findings) {
  const bySeverity = Object.fromEntries(EXPOSURE_SEVERITIES.map((s) => [s, 0]));
  const ips = new Set();
  let exposed = 0;
  for (const f of Array.isArray(findings) ? findings : []) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    ips.add(`${f.ip}|${f.port}`);
    if (f.kind === 'reachable') exposed += 1;
  }
  const worst = EXPOSURE_SEVERITIES.find((s) => bySeverity[s] > 0) || null;
  return { total: (findings || []).length, worst, bySeverity, leakedIps: ips.size, exposed };
}

/**
 * The CDN a proxied name is served by, guessed from the public addresses the name resolves to (its
 * CDN edge): the matching lib/netinfo.js provider, or null. Used only to word the firewall advice
 * ("allow only <provider>'s ranges"). Pure.
 * @param {string[]} publicIps the name's current public A / AAAA answers
 * @returns {{ id: string, name: string }|null}
 */
export function cdnOf(publicIps) {
  for (const ip of Array.isArray(publicIps) ? publicIps : []) {
    const p = matchProviderByIP(normalizeIP(String(ip)));
    if (p && p.hidesOrigin) return { id: p.id, name: p.name };
  }
  return null;
}

/** CSV columns of the findings export. */
export const EXPOSURE_CSV_COLUMNS = Object.freeze(['severity', 'finding', 'name', 'origin', 'server', 'record', 'record_type', 'detail', 'advice']);

/**
 * The findings as CSV rows (the header first), each value a string. Pure.
 * @param {ExposureFinding[]} findings
 * @returns {string[][]}
 */
export function exposureCsvRows(findings) {
  const rows = [[...EXPOSURE_CSV_COLUMNS]];
  for (const f of sortFindings(findings)) {
    rows.push([
      f.severity, f.kind, f.names.join(' '), f.target, f.server || '', f.record, f.recordType || '',
      f.detail || '', f.advice.join(' ')
    ]);
  }
  return rows;
}

/** How many days ago `date` was, for the "last confirmed" of a target (helper for the panel). */
export function daysAgo(date, now = Date.now()) {
  const t = date instanceof Date ? date.getTime() : Date.parse(String(date));
  return Number.isFinite(t) ? Math.max(0, Math.floor((now - t) / DAY_MS)) : null;
}
