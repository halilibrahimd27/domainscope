/**
 * scanner.js — "SSL target finder": from a certificate and/or domains, find
 * every hostname (CT logs, passive DNS, optional brute force), resolve it,
 * classify it (Cloudflare / CDN / platform / direct / private / NXDOMAIN),
 * check certificate coverage, map it to the user's servers, and collect
 * origin hints for hosts hidden behind a CDN.
 *
 * DOM-free. All DNS goes through the injected DohClient (`config.dns`), all
 * HTTP through `config.fetchImpl`. Cancellation via `config.signal` rejects
 * the scan with an AbortError; results are also streamed through hooks.
 */

import {
  normalizeHostname, stripWildcard, isSubdomainOf, sortHostnames, registrableDomain, isPublicSuffix,
  baseDomainsFromNames, certCovers
} from './domain.js';
import { classifyResolution, matchProviderByIP, normalizeIP, parseCidr, parseIP, ipInCidr, isPrivateIP } from './netinfo.js';
import { buildIpIndex, lookupServers } from './inventory.js';
import { getWordlist } from './wordlist.js';
import { SOURCES, fetchAllSources, mergeCerts } from './sources.js';
import { followCnames } from './doh.js';
import { AbortError, abortReasonToError, splitList } from './util.js';

/* ------------------------------------------------------------------------ */
/* Types                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} HostRecord
 * @property {string} name
 * @property {string[]} origins where the name came from: 'input', 'cert', source ids, 'bruteforce'
 * @property {object} resolution HostResolution (doh.js)
 * @property {object} classification netinfo.classifyResolution() result
 * @property {{ covered: boolean, by: string|null }|null} cert coverage by the scanned certificate (null without cert)
 * @property {Array<{ serverId: string, name: string, ip: string }>} servers inventory servers owning a resolved IP
 * @property {boolean} wildcardSuspect answer identical to the parent's wildcard answer
 * @property {object[]} ipHints IpHint[] from passive sources for this name
 */

/**
 * @typedef {object} OriginHint
 * @property {string} ip
 * @property {Array<{ kind: 'spf'|'mx'|'direct-sibling'|'history', detail: string }>} reasons
 * @property {Array<{ serverId: string, name: string }>} servers inventory servers with this IP
 * @property {object|null} provider netinfo provider of the IP (never a CDN that hides origins)
 * @property {string[]} hosts extension: hostnames the hint is specifically about (history / sibling)
 */

/**
 * @typedef {object} ServerGroup
 * @property {object} server inventory Server
 * @property {Array<{ name: string, ip: string, covered: boolean|null, via: 'dns'|'hint' }>} hosts
 * @property {boolean} needsCert a DNS-matched host is covered by the certificate (without a
 *   certificate: any DNS-matched host)
 * @property {boolean} maybeNeedsCert extension: only origin hints point here
 */

/* ------------------------------------------------------------------------ */
/* Constants / helpers                                                      */
/* ------------------------------------------------------------------------ */

const STAGES = ['sources', 'wildcard', 'bruteforce', 'resolve', 'hints', 'done'];
const ORIGIN_ORDER = ['input', 'cert', ...SOURCES.map((s) => s.id), 'bruteforce'];
const MAX_SPF_DEPTH = 5;
const MAX_SPF_LOOKUPS = 10;
const MAX_MX = 10;
const MAX_BRUTEFORCE = 60000;
const SIBLING_DETAIL_NAMES = 5;

function toAbortError(reason) {
  const err = abortReasonToError(reason);
  return err instanceof AbortError ? err : new AbortError(err.message, { cause: err });
}

function checkAbort(signal) {
  if (signal && signal.aborted) throw toAbortError(signal.reason);
}

function safeCall(fn, ...args) {
  if (typeof fn !== 'function') return;
  try {
    fn(...args);
  } catch {
    /* UI hooks must never break the scan */
  }
}

/** Run `fn` over `items` with at most `limit` in flight; stops early on abort / error. */
async function mapPool(items, limit, fn, signal) {
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < items.length) {
      checkAbort(signal);
      const i = next;
      next += 1;
      try {
        await fn(items[i], i);
      } catch (err) {
        failed = true;
        throw err;
      }
    }
  };
  const n = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: n }, worker));
}

function compareIp(a, b) {
  const x = parseIP(a);
  const y = parseIP(b);
  if (!x || !y) return String(a).localeCompare(String(b));
  if (x.version !== y.version) return x.version - y.version;
  return x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
}

function orderOrigins(set) {
  return [...set].sort((a, b) => {
    const ia = ORIGIN_ORDER.indexOf(a);
    const ib = ORIGIN_ORDER.indexOf(b);
    if (ia !== ib) return (ia === -1 ? Infinity : ia) - (ib === -1 ? Infinity : ib);
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function normalizeSerial(hex) {
  if (typeof hex !== 'string') return null;
  let s = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!s) return null;
  if (s.length % 2) s = `0${s}`;
  while (s.length > 2 && s.startsWith('00')) s = s.slice(2);
  return s;
}

function formatDay(d) {
  return d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : null;
}

/**
 * Is a resolution indistinguishable from the parent's wildcard answer?
 * CNAME wildcards compare the first CNAME target (the synthesized record);
 * address wildcards require every address to be one of the wildcard's.
 */
function isWildcardSuspect(res, wc) {
  if (!wc || !wc.wildcard || !res) return false;
  const hc = res.cnames || [];
  const wcc = wc.cnames || [];
  if (hc.length || wcc.length) return hc.length > 0 && wcc.length > 0 && hc[0] === wcc[0];
  const ips = [...(res.ipv4 || []), ...(res.ipv6 || [])];
  if (!ips.length) return false;
  const wips = new Set([...(wc.ipv4 || []), ...(wc.ipv6 || [])]);
  return ips.every((ip) => wips.has(ip));
}

/* ------------------------------------------------------------------------ */
/* SPF (private, minimal — health.js has the full parser)                   */
/* ------------------------------------------------------------------------ */

function txtStrings(res) {
  if (!res || !res.ok || res.rcode !== 'NOERROR') return [];
  return (res.answers || [])
    .filter((rr) => rr.type === 'TXT')
    .map((rr) => (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '')));
}

function mxExchanges(res) {
  if (!res || !res.ok || res.rcode !== 'NOERROR') return [];
  return (res.answers || [])
    .filter((rr) => rr.type === 'MX' && rr.data && typeof rr.data.exchange === 'string' && rr.data.exchange !== '.')
    .sort((a, b) => a.data.preference - b.data.preference)
    .slice(0, MAX_MX)
    .map((rr) => ({ exchange: rr.data.exchange, preference: rr.data.preference }));
}

/**
 * Walk an SPF policy (include / redirect, ≤ 5 levels, ≤ 10 DNS-querying
 * terms like RFC 7208 §4.6.4) and collect sender addresses:
 * `nets` from ip4:/ip6: and `hosts` from a / mx mechanisms. Only pass ('+')
 * mechanisms are used; macros are skipped. Entries remember whether the SPF
 * record that listed them belongs to one of the scanned domains (`own`).
 */
async function collectSpf(domain, { dns, signal, isOwn }) {
  const state = { lookups: 0, nets: [], hosts: [], errors: [], visited: new Set() };

  const walk = async (name, depth, path, ownChain) => {
    if (depth > MAX_SPF_DEPTH) {
      state.errors.push(`SPF include depth limit reached at ${name}`);
      return;
    }
    if (state.visited.has(name)) return;
    state.visited.add(name);
    const res = await dns.query(name, 'TXT', { signal });
    const record = txtStrings(res).find((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    if (!record) return;
    const own = ownChain && isOwn(name);
    const where = [...path, name].join(' → ');
    const terms = record.trim().split(/\s+/).slice(1);
    let redirect = null;
    const hasAll = terms.some((t) => /^[+?~-]?all$/i.test(t));
    for (const term of terms) {
      if (term.includes('%')) continue; // macro-expanded terms cannot be evaluated here
      const m = /^([+?~-]?)([a-z][a-z0-9_.-]*)(?:([:=])(.*))?$/i.exec(term);
      if (!m) continue;
      const [, qualifier, rawMech, sep, rawValue = ''] = m;
      const mech = rawMech.toLowerCase();
      if (sep === '=') {
        if (mech === 'redirect') redirect = rawValue.toLowerCase().replace(/\.$/, '');
        continue;
      }
      if (qualifier && qualifier !== '+') continue; // -, ~, ? do not describe permitted senders
      if (mech === 'ip4' || mech === 'ip6') {
        const cidr = parseCidr(rawValue);
        if (cidr) state.nets.push({ text: rawValue, cidr, own, detail: `${where}: ${mech}:${rawValue}` });
        continue;
      }
      if (mech === 'a' || mech === 'mx' || mech === 'include' || mech === 'exists' || mech === 'ptr') {
        if (state.lookups >= MAX_SPF_LOOKUPS) {
          state.errors.push(`SPF lookup limit (${MAX_SPF_LOOKUPS}) reached`);
          continue;
        }
        state.lookups += 1;
      }
      const target = (rawValue.split('/')[0] || name).toLowerCase().replace(/\.$/, '');
      if (mech === 'a') {
        state.hosts.push({ host: target, own, detail: `${where}: a${rawValue ? `:${rawValue}` : ''}` });
      } else if (mech === 'mx') {
        const mx = await dns.query(target, 'MX', { signal });
        for (const { exchange } of mxExchanges(mx)) {
          state.hosts.push({ host: exchange, own, detail: `${where}: mx${rawValue ? `:${rawValue}` : ''} → ${exchange}` });
        }
      } else if (mech === 'include' && rawValue) {
        await walk(target, depth + 1, [...path, name], own);
      }
    }
    if (redirect && !hasAll) {
      if (state.lookups < MAX_SPF_LOOKUPS) {
        state.lookups += 1;
        await walk(redirect, depth + 1, [...path, name], own);
      } else {
        state.errors.push(`SPF lookup limit (${MAX_SPF_LOOKUPS}) reached`);
      }
    }
  };

  await walk(domain, 0, [], true);
  return state;
}

/* ------------------------------------------------------------------------ */
/* Scan                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Run a full scan.
 *
 * Pipeline: seeds (domains + certificate names — wildcard bases for '*.x' —
 * + extraNames) → passive sources per registrable domain (parallel, while
 * wildcard detection runs) → wildcard detection per domain / wildcard base →
 * optional brute force (A-only probe; keeps names that exist and do not look
 * like the parent's wildcard) → resolve every name (A + AAAA; streamed via
 * `onHost`) → classify / certificate coverage / inventory match → origin
 * hints (SPF, MX, public IPs of non-proxied siblings, historical source IPs)
 * → server groups and unmatched direct IPs.
 *
 * Stages are reported in execution order: sources, wildcard, bruteforce,
 * resolve, hints, done (skipped stages are still reported, with
 * `{ skipped: true }`).
 *
 * @param {object} config
 * @param {string[]|string} [config.domains] target domains (default: registrable domains of the cert / extra names)
 * @param {object|null} [config.cert] x509 Certificate (uses `hostnames`, `serialHex`)
 * @param {string[]|string} [config.extraNames] additional hostnames ('*.x' allowed)
 * @param {string[]} [config.sources] source ids (default: every defaultEnabled source; [] = none)
 * @param {boolean} [config.includeExpired=false]
 * @param {'off'|'small'|'medium'} [config.bruteforce='off']
 * @param {object[]} [config.inventory] Server[] (or a parseInventory() result)
 * @param {boolean} [config.originHints=true]
 * @param {object} config.dns DohClient
 * @param {typeof fetch} [config.fetchImpl]
 * @param {AbortSignal} [config.signal]
 * @param {string[]} [config.wordlist] extension: custom brute-force labels (used when bruteforce !== 'off')
 * @param {number} [config.maxHosts=20000] extension: cap on resolved names
 * @param {number} [config.concurrency=32] extension: names in flight (the DohClient limiter still applies)
 * @param {object} [hooks] { onStage(stage, info), onSource(result), onHost(record), onProgress({ stage, done, total }) }
 * @returns {Promise<object>} ScanResult
 */
export async function runScan(config = {}, hooks = {}) {
  const {
    domains = [], cert = null, extraNames = [], sources, includeExpired = false, bruteforce = 'off',
    inventory = [], originHints = true, dns, fetchImpl = globalThis.fetch, signal,
    wordlist = null, maxHosts = 20000, concurrency = 32
  } = config || {};
  if (!dns || typeof dns.query !== 'function' || typeof dns.resolveHost !== 'function' || typeof dns.detectWildcard !== 'function') {
    throw new TypeError('runScan: config.dns must be a DohClient');
  }
  checkAbort(signal);
  const h = hooks || {};
  const startedAt = new Date();
  const t0 = Date.now();
  const warnings = [];
  const stage = (name, info = {}) => safeCall(h.onStage, name, info);
  const progress = (name, done, total) => safeCall(h.onProgress, { stage: name, done, total });
  const pool = Math.max(1, Math.floor(Number(concurrency)) || 32);

  /* ---- seeds ----------------------------------------------------------- */
  const origins = new Map();
  const addName = (name, origin) => {
    let set = origins.get(name);
    if (!set) {
      set = new Set();
      origins.set(name, set);
    }
    set.add(origin);
  };
  const wildcardBases = new Set();
  const seed = (raw, origin) => {
    const n = normalizeHostname(String(raw ?? ''), { allowWildcard: true });
    if (!n) return false;
    const { base, wildcard } = stripWildcard(n);
    addName(base, origin);
    if (wildcard) wildcardBases.add(base);
    return true;
  };

  const certHostnames = cert && Array.isArray(cert.hostnames) ? cert.hostnames : [];
  for (const name of certHostnames) seed(name, 'cert');
  const extras = Array.isArray(extraNames) ? extraNames : splitList(extraNames);
  for (const name of extras) {
    if (!seed(name, 'input')) warnings.push({ code: 'INVALID_NAME', detail: String(name) });
  }

  const targetDomains = [];
  const pushTarget = (base) => {
    if (isPublicSuffix(base)) {
      warnings.push({ code: 'PUBLIC_SUFFIX', detail: base });
      return;
    }
    if (!targetDomains.includes(base)) targetDomains.push(base);
  };
  for (const raw of Array.isArray(domains) ? domains : splitList(domains)) {
    const n = normalizeHostname(String(raw ?? ''), { allowWildcard: true });
    if (!n) {
      warnings.push({ code: 'INVALID_DOMAIN', detail: String(raw) });
      continue;
    }
    pushTarget(stripWildcard(n).base);
  }
  if (!targetDomains.length) {
    for (const d of baseDomainsFromNames([...certHostnames, ...extras])) pushTarget(d);
  }
  if (!targetDomains.length && !origins.size) {
    throw new TypeError('runScan: nothing to scan (no valid domain, certificate name or extra name)');
  }
  for (const d of targetDomains) addName(d, 'input');

  const sourceDomains = [...new Set(targetDomains.map((d) => registrableDomain(d) || d))];
  const scopeRoots = [...new Set([...targetDomains, ...wildcardBases])];
  const inScope = (name) => scopeRoots.some((root) => isSubdomainOf(name, root));
  const isOwn = (name) => [...sourceDomains, ...scopeRoots].some((root) => isSubdomainOf(name, root));
  const parents = sortHostnames([...new Set([...targetDomains, ...wildcardBases])]);

  const servers = Array.isArray(inventory) ? inventory : inventory && Array.isArray(inventory.servers) ? inventory.servers : [];
  const ipIndex = buildIpIndex(servers);

  /* ---- wildcard detection (starts now, overlaps the sources stage) ------ */
  const wildcards = {};
  let wildcardDone = 0;
  const wildcardTask = mapPool(parents, 4, async (p) => {
    wildcards[p] = await dns.detectWildcard(p, { signal });
    wildcardDone += 1;
  }, signal);
  wildcardTask.catch(() => {}); // awaited below; avoid an unhandled rejection meanwhile

  /* ---- passive sources -------------------------------------------------- */
  const sourceIds = Array.isArray(sources) ? [...new Set(sources)] : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const sourceTotal = sourceIds.length * sourceDomains.length;
  stage('sources', { domains: sourceDomains, sources: sourceIds, total: sourceTotal, skipped: sourceTotal === 0 });
  const sourceResults = [];
  const hintsByName = new Map();
  let certsAll = [];
  if (sourceTotal > 0) {
    let done = 0;
    const perDomain = await Promise.all(sourceDomains.map((d) => fetchAllSources(d, {
      sources: sourceIds,
      fetchImpl,
      signal,
      includeExpired,
      onResult: (r) => {
        done += 1;
        safeCall(h.onSource, r);
        progress('sources', done, sourceTotal);
      }
    })));
    for (const out of perDomain) {
      for (const r of out.results) {
        sourceResults.push(r);
        for (const n of r.names) if (inScope(n)) addName(n, r.source);
        for (const hint of r.ipHints) {
          if (!inScope(hint.name)) continue;
          if (!hintsByName.has(hint.name)) hintsByName.set(hint.name, []);
          hintsByName.get(hint.name).push(hint);
        }
      }
      certsAll = certsAll.concat(out.certs);
    }
  }
  checkAbort(signal);

  /* ---- wildcard results ------------------------------------------------- */
  stage('wildcard', { parents, total: parents.length });
  await wildcardTask;
  progress('wildcard', wildcardDone, parents.length);
  const nearestWildcard = (name) => {
    let best = null;
    for (const p of parents) {
      const w = wildcards[p];
      if (!w || !w.wildcard || name === p || !isSubdomainOf(name, p)) continue;
      if (!best || p.length > best.parent.length) best = { parent: p, w };
    }
    return best ? best.w : null;
  };

  /* ---- brute force ------------------------------------------------------ */
  const words = bruteforce === 'off' || !bruteforce
    ? []
    : Array.isArray(wordlist) && wordlist.length ? wordlist : getWordlist(bruteforce);
  const candidates = [];
  if (words.length) {
    const seen = new Set();
    outer: for (const p of parents) {
      for (const w of words) {
        const label = String(w ?? '').trim().toLowerCase().replace(/\.+$/, '');
        if (!label) continue;
        const n = normalizeHostname(`${label}.${p}`);
        if (!n || origins.has(n) || seen.has(n)) continue;
        seen.add(n);
        candidates.push(n);
        if (candidates.length >= MAX_BRUTEFORCE) {
          warnings.push({ code: 'BRUTEFORCE_TRUNCATED', detail: String(MAX_BRUTEFORCE) });
          break outer;
        }
      }
    }
  }
  const bf = { tried: candidates.length, found: 0, wildcardDropped: 0, errors: 0 };
  stage('bruteforce', { total: candidates.length, words: words.length, parents, skipped: candidates.length === 0 });
  if (candidates.length) {
    let done = 0;
    await mapPool(candidates, pool, async (name) => {
      const res = await dns.query(name, 'A', { signal });
      done += 1;
      progress('bruteforce', done, candidates.length);
      if (!res.ok) {
        bf.errors += 1;
        return;
      }
      if (res.rcode !== 'NOERROR') return;
      const { cnames } = followCnames(res.answers, name);
      const owners = new Set([name, ...cnames]);
      const ipv4 = [...new Set(res.answers
        .filter((rr) => rr.type === 'A' && owners.has(rr.name))
        .map((rr) => normalizeIP(rr.data))
        .filter(Boolean))];
      if (isWildcardSuspect({ cnames, ipv4, ipv6: [] }, nearestWildcard(name))) {
        bf.wildcardDropped += 1;
        return;
      }
      addName(name, 'bruteforce');
      bf.found += 1;
    }, signal);
  }

  /* ---- resolve ---------------------------------------------------------- */
  let names = sortHostnames([...origins.keys()]);
  let truncated = false;
  if (names.length > maxHosts) {
    // keep explicitly requested names (input / certificate) first
    const isPriority = (n) => origins.get(n).has('input') || origins.get(n).has('cert');
    const priority = names.filter(isPriority);
    const rest = names.filter((n) => !isPriority(n));
    names = sortHostnames([...priority, ...rest].slice(0, maxHosts));
    truncated = true;
    warnings.push({ code: 'TRUNCATED', detail: `${origins.size} > ${maxHosts}` });
  }
  stage('resolve', { total: names.length });
  const records = new Map();
  const matchesByName = new Map();
  let resolvedDone = 0;
  let droppedBruteforce = 0;
  await mapPool(names, pool, async (name) => {
    const resolution = await dns.resolveHost(name, { signal });
    resolvedDone += 1;
    progress('resolve', resolvedDone, names.length);
    const classification = classifyResolution(resolution);
    const wildcardSuspect = isWildcardSuspect(resolution, nearestWildcard(name));
    const nameOrigins = origins.get(name);
    const onlyBruteforce = nameOrigins.size === 1 && nameOrigins.has('bruteforce');
    const hasAnswer = resolution.ipv4.length || resolution.ipv6.length || resolution.cnames.length;
    if (onlyBruteforce && (wildcardSuspect || !hasAnswer)) {
      droppedBruteforce += 1;
      return;
    }
    const matches = lookupServers([...resolution.ipv4, ...resolution.ipv6], ipIndex);
    matchesByName.set(name, matches);
    const record = {
      name,
      origins: orderOrigins(nameOrigins),
      resolution,
      classification,
      cert: cert ? certCovers(certHostnames, name) : null,
      servers: matches.map(({ server, ip }) => ({ serverId: server.id, name: server.name, ip })),
      wildcardSuspect,
      ipHints: hintsByName.get(name) || []
    };
    records.set(name, record);
    safeCall(h.onHost, record);
  }, signal);
  bf.found = Math.max(0, bf.found - droppedBruteforce);
  const hosts = sortHostnames([...records.keys()]).map((n) => records.get(n));
  checkAbort(signal);

  /* ---- origin hints ----------------------------------------------------- */
  const hintMap = new Map();
  const addHint = (rawIp, reason, { own = true, hostNames = [] } = {}) => {
    const ip = normalizeIP(rawIp);
    if (!ip) return;
    const provider = matchProviderByIP(ip);
    if (provider && provider.hidesOrigin) return; // a CDN / WAF edge is never an origin
    const matches = lookupServers([ip], ipIndex);
    if (!own && !matches.length) return; // third-party infrastructure (e.g. a mail provider)
    let hint = hintMap.get(ip);
    if (!hint) {
      hint = { ip, reasons: [], servers: [], provider: provider || null, hosts: new Set(), historyHosts: new Set() };
      hintMap.set(ip, hint);
    }
    if (!hint.reasons.some((r) => r.kind === reason.kind && r.detail === reason.detail)) hint.reasons.push(reason);
    for (const n of hostNames) {
      hint.hosts.add(n);
      if (reason.kind === 'history') hint.historyHosts.add(n);
    }
  };

  const hintsEnabled = originHints !== false;
  stage('hints', { skipped: !hintsEnabled });
  const hintErrors = [];
  if (hintsEnabled) {
    // 1. Historical / passive IPs of each name (not CDN, not the current answer).
    for (const host of hosts) {
      const current = new Set([...host.resolution.ipv4, ...host.resolution.ipv6]);
      for (const hint of host.ipHints) {
        if (current.has(hint.ip)) continue;
        const seen = formatDay(hint.lastSeen);
        addHint(hint.ip, {
          kind: 'history',
          detail: `${hint.source}: ${host.name}${seen ? ` (last seen ${seen})` : ''}`
        }, { hostNames: [host.name] });
      }
    }
    // 2. Public IPs of non-proxied siblings (only useful when something is proxied).
    if (hosts.some((x) => x.classification.hidesOrigin)) {
      const siblings = new Map();
      for (const host of hosts) {
        const kind = host.classification.kind;
        if (kind !== 'direct' && kind !== 'private') continue;
        for (const ip of [...host.resolution.ipv4, ...host.resolution.ipv6]) {
          if (!siblings.has(ip)) siblings.set(ip, []);
          siblings.get(ip).push(host.name);
        }
      }
      for (const [ip, list] of siblings) {
        const more = list.length > SIBLING_DETAIL_NAMES ? ` (+${list.length - SIBLING_DETAIL_NAMES})` : '';
        addHint(ip, { kind: 'direct-sibling', detail: `${list.slice(0, SIBLING_DETAIL_NAMES).join(', ')}${more}` }, { hostNames: list });
      }
    }
    // 3. SPF and MX of each zone apex.
    const zones = [...new Set([...sourceDomains, ...targetDomains])];
    let zonesDone = 0;
    await mapPool(zones, 4, async (zone) => {
      const spf = await collectSpf(zone, { dns, signal, isOwn });
      hintErrors.push(...spf.errors);
      const mx = mxExchanges(await dns.query(zone, 'MX', { signal }));
      const hostJobs = [
        ...spf.hosts.map((x) => ({ ...x, kind: 'spf' })),
        ...mx.map(({ exchange, preference }) => ({
          host: exchange, own: isOwn(exchange), kind: 'mx', detail: `${zone}: MX ${preference} ${exchange}`
        }))
      ];
      await mapPool(hostJobs, 4, async (job) => {
        const r = await dns.resolveHost(job.host, { signal });
        for (const ip of [...r.ipv4, ...r.ipv6]) addHint(ip, { kind: job.kind, detail: job.detail }, { own: job.own });
      }, signal);
      for (const net of spf.nets) {
        const bits = net.cidr.version === 4 ? 32 : 128;
        if (net.cidr.prefix === bits) {
          addHint(net.text.split('/')[0], { kind: 'spf', detail: net.detail }, { own: net.own });
          continue;
        }
        // A range: only interesting where it contains inventory servers.
        if (net.cidr.prefix < (net.cidr.version === 4 ? 8 : 32)) continue;
        for (const ip of ipIndex.keys()) {
          if (ipInCidr(ip, net.cidr)) addHint(ip, { kind: 'spf', detail: net.detail }, { own: true });
        }
      }
      zonesDone += 1;
      progress('hints', zonesDone, zones.length);
    }, signal);
  }
  checkAbort(signal);

  const originHintList = [...hintMap.values()]
    .map((hint) => ({
      ip: hint.ip,
      reasons: hint.reasons,
      servers: lookupServers([hint.ip], ipIndex).map(({ server }) => ({ serverId: server.id, name: server.name })),
      provider: hint.provider,
      hosts: sortHostnames([...hint.hosts]),
      historyHosts: hint.historyHosts
    }))
    .sort((a, b) => b.servers.length - a.servers.length || b.reasons.length - a.reasons.length || compareIp(a.ip, b.ip));

  /* ---- server groups ---------------------------------------------------- */
  const groups = new Map();
  const groupOf = (server) => {
    let g = groups.get(server);
    if (!g) {
      g = { server, hosts: [], needsCert: false, maybeNeedsCert: false };
      groups.set(server, g);
    }
    return g;
  };
  const coveredOf = (host) => (host.cert ? host.cert.covered : null);
  for (const host of hosts) {
    for (const { server, ip } of matchesByName.get(host.name) || []) {
      groupOf(server).hosts.push({ name: host.name, ip, covered: coveredOf(host), via: 'dns' });
    }
  }
  for (const hint of originHintList) {
    if (!hint.servers.length) continue;
    // 'history' hints are about specific names; spf / mx / sibling hints are
    // candidate origins for every host hidden behind a CDN.
    const general = hint.reasons.some((r) => r.kind !== 'history');
    const targets = hosts.filter((x) => hint.historyHosts.has(x.name) || (general && x.classification.hidesOrigin));
    if (!targets.length) continue;
    for (const { server } of lookupServers([hint.ip], ipIndex)) {
      const g = groupOf(server);
      for (const host of targets) {
        if (g.hosts.some((e) => e.name === host.name && e.ip === hint.ip)) continue;
        g.hosts.push({ name: host.name, ip: hint.ip, covered: coveredOf(host), via: 'hint' });
      }
    }
  }
  for (const hint of originHintList) delete hint.historyHosts; // internal only
  const serverGroups = [...groups.values()];
  for (const g of serverGroups) {
    const order = new Map(sortHostnames([...new Set(g.hosts.map((e) => e.name))]).map((n, i) => [n, i]));
    g.hosts.sort((a, b) => (a.via === b.via ? 0 : a.via === 'dns' ? -1 : 1)
      || order.get(a.name) - order.get(b.name) || compareIp(a.ip, b.ip));
    g.needsCert = g.hosts.some((e) => e.via === 'dns' && e.covered !== false);
    g.maybeNeedsCert = !g.needsCert && g.hosts.some((e) => e.via === 'hint' && e.covered !== false);
  }
  serverGroups.sort((a, b) => Number(b.needsCert) - Number(a.needsCert)
    || Number(b.maybeNeedsCert) - Number(a.maybeNeedsCert)
    || String(a.server.name ?? '').localeCompare(String(b.server.name ?? ''), undefined, { numeric: true, sensitivity: 'base' })
    || String(a.server.id ?? '').localeCompare(String(b.server.id ?? '')));

  /* ---- unmatched direct IPs --------------------------------------------- */
  const unmatched = new Map();
  for (const host of hosts) {
    const kind = host.classification.kind;
    if (kind !== 'direct' && kind !== 'private') continue;
    for (const ip of [...host.resolution.ipv4, ...host.resolution.ipv6]) {
      if (lookupServers([ip], ipIndex).length) continue;
      if (!unmatched.has(ip)) unmatched.set(ip, []);
      unmatched.get(ip).push(host.name);
    }
  }
  const unmatchedIps = [...unmatched.entries()]
    .map(([ip, list]) => ({ ip, hosts: sortHostnames(list), provider: matchProviderByIP(ip), private: isPrivateIP(ip) }))
    .sort((a, b) => compareIp(a.ip, b.ip));

  /* ---- CT certificates -------------------------------------------------- */
  const certSerial = cert ? normalizeSerial(cert.serialHex) : null;
  const ctCerts = mergeCerts(certsAll).map((c) => ({
    ...c,
    matchesCert: !!certSerial && normalizeSerial(c.serialHex) === certSerial
  }));

  /* ---- stats ------------------------------------------------------------ */
  const count = (pred) => hosts.filter(pred).length;
  const kindCount = (k) => count((x) => x.classification.kind === k);
  const stats = {
    total: hosts.length,
    resolved: count((x) => x.resolution.ipv4.length > 0 || x.resolution.ipv6.length > 0),
    cloudflare: kindCount('cloudflare'),
    cdn: kindCount('cdn'),
    platform: kindCount('platform'),
    direct: kindCount('direct'),
    private: kindCount('private'),
    nxdomain: kindCount('nxdomain'),
    dangling: count((x) => x.classification.dangling),
    covered: count((x) => !!(x.cert && x.cert.covered)),
    matchedServers: serverGroups.filter((g) => g.hosts.some((e) => e.via === 'dns')).length,
    wildcardSuspects: count((x) => x.wildcardSuspect),
    // extensions
    unresolved: kindCount('unresolved'),
    hiddenOrigin: count((x) => x.classification.hidesOrigin),
    needsCert: serverGroups.filter((g) => g.needsCert).length,
    hintedServers: serverGroups.filter((g) => !g.hosts.some((e) => e.via === 'dns')).length,
    originHints: originHintList.length,
    unmatchedIps: unmatchedIps.length,
    sourcesOk: sourceResults.filter((r) => r.ok).length,
    sourcesFailed: sourceResults.filter((r) => !r.ok).length,
    bruteforceTried: bf.tried,
    bruteforceFound: bf.found,
    bruteforceWildcardDropped: bf.wildcardDropped + droppedBruteforce,
    bruteforceErrors: bf.errors,
    ctCerts: ctCerts.length,
    dnsQueries: typeof dns.stats === 'function' ? dns.stats().queries : null,
    truncated,
    elapsedMs: Date.now() - t0
  };

  const result = {
    startedAt,
    finishedAt: new Date(),
    domains: targetDomains,
    hosts,
    sources: sourceResults,
    wildcards,
    originHints: originHintList,
    servers: serverGroups,
    unmatchedIps,
    ctCerts,
    stats,
    // extensions
    sourceDomains,
    wildcardBases: sortHostnames([...wildcardBases]),
    warnings,
    hintErrors: [...new Set(hintErrors)],
    options: {
      sources: sourceIds, includeExpired: !!includeExpired, bruteforce: words.length ? bruteforce : 'off',
      originHints: hintsEnabled, cert: !!cert, inventoryServers: servers.length
    }
  };
  stage('done', { stats });
  return result;
}

/** Stage names in the order they are reported (extension). */
export const SCAN_STAGES = Object.freeze([...STAGES]);
