#!/usr/bin/env node
/**
 * LIVE (network) benchmark of the discovery engine: runScan() with the v1
 * defaults (config A) vs the v2 DNS-first defaults (config B). Not run by
 * `npm test` / CI.
 *
 *   node tests/live/benchmark-discovery.mjs                       # targets.local.json, else public defaults; A + B
 *   node tests/live/benchmark-discovery.mjs example.com --configs B
 *   node tests/live/benchmark-discovery.mjs --verify 10 --json tests/live/private/bench.json
 *
 * Options:
 *   --configs A,B        which configs to run (default A,B)
 *   --concurrency N      DohClient HTTP concurrency (default 12 = the UI default)
 *   --sources a,b,c      passive sources (default crtsh,certspotter,anubis,thc —
 *                        HackerTarget / OTX anonymous quotas are exhausted)
 *   --no-sources         skip passive sources entirely
 *   --fresh              never replay the source cache (costs live CT quota; final
 *                        answers are still recorded for later runs)
 *   --cache-dir DIR      source replay cache (default <tmp>/domainscope-bench-cache; inside
 *                        the repository only a gitignored folder is accepted)
 *   --verify N           independently re-check up to N names per domain that were
 *                        found ONLY by wordlist / permutation / recursive, through
 *                        https://dns.google/resolve, plus a random sibling label
 *                        under the same parent (wildcard artefact check)
 *   --json FILE          write the per-run metrics as JSON. They name the domains, found
 *                        and missed labels and origin IPs, so inside the repository only
 *                        a gitignored path is accepted (tests/live/private/…, *.local.json);
 *                        anything else stops the run before it starts (targets.mjs reportPath)
 *
 * Politeness: DNS goes only to public DoH resolvers (Cloudflare / Google /
 * DNS.SB balance pool), never to the target's web servers. Passive-source
 * answers (crt.sh, Cert Spotter, Anubis, ip.thc.org) go through
 * ./replay-cache.mjs: a FINAL answer (2xx, not a quota notice) is recorded once
 * and replayed — with the originally measured latency — for every later run,
 * so A and B share one live fetch and re-runs cost no quota. Failures (5xx,
 * 429, crt.sh's flapping 404, network errors) are never recorded: the
 * source's own retries reach the network again and a transient outage cannot
 * freeze into every later run.
 */
import http2 from 'node:http2';
import tls from 'node:tls';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { runScan } from '../../assets/js/lib/scanner.js';
import { isSubdomainOf } from '../../assets/js/lib/domain.js';
import { pickDomains, positionalArgs, readLocalTargets, reportPathOrExit, writeReport, PUBLIC_FALLBACK_DOMAINS } from './targets.mjs';
import { createReplayCache } from './replay-cache.mjs';

/* ---- arguments ---------------------------------------------------------- */
const argv = process.argv.slice(2);
const VALUE_OPTS = new Set(['--configs', '--concurrency', '--sources', '--cache-dir', '--verify', '--json']);
const opt = (name, fb = null) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fb;
};
const flag = (name) => argv.includes(name);
const DOMAINS = pickDomains(positionalArgs(argv, VALUE_OPTS), [...PUBLIC_FALLBACK_DOMAINS]);
const CONFIGS = (opt('--configs', 'A,B')).split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
const CONCURRENCY = Number(opt('--concurrency', '12')) || 12;
const SOURCE_IDS = flag('--no-sources') ? [] : (opt('--sources', 'crtsh,certspotter,anubis,thc')).split(',').filter(Boolean);
const FRESH = flag('--fresh');
const CACHE_DIR = reportPathOrExit(opt('--cache-dir')) ?? join(tmpdir(), 'domainscope-bench-cache');
const VERIFY_N = Number(opt('--verify', '0')) || 0;
const JSON_OUT = reportPathOrExit(opt('--json'));
const ORIGIN = 'https://example.github.io';

/** Ground truth (labels known to exist), only from the gitignored tests/live/targets.local.json. */
const TRUTH = readLocalTargets().groundTruth;

/** A = v1 defaults, B = v2 DNS-first defaults. */
const CONFIG_DEFS = {
  A: { bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false },
  B: { bruteforce: 'smart', mine: true, permutationBudget: 1500, recursive: true }
};

/* ---- HTTP/2 fetchImpl for DoH (like a browser) --------------------------- */
function caBundle() {
  try { return [...tls.getCACertificates('default'), ...tls.getCACertificates('system')]; } catch { return undefined; }
}
const CA = caBundle();
const DOH_ORIGINS = new Set(RESOLVERS.map((r) => new URL(r.url).origin));
const sessions = new Map();
function session(origin) {
  let s = sessions.get(origin);
  if (s && !s.closed && !s.destroyed) return s;
  s = http2.connect(origin, { ca: CA });
  s.on('error', () => {});
  s.unref();
  sessions.set(origin, s);
  return s;
}
function abortError(signal) {
  const reason = signal && signal.reason;
  if (reason instanceof Error) return reason;
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  return err;
}
function h2fetch(url, init = {}) {
  const u = new URL(url);
  const { signal } = init;
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) { reject(abortError(signal)); return; }
    let req;
    try {
      req = session(u.origin).request({
        ':method': 'GET', ':path': u.pathname + u.search, origin: ORIGIN,
        ...Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]))
      });
    } catch (err) { reject(new TypeError(`http2: ${err.message}`)); return; }
    const onAbort = () => { req.close(http2.constants.NGHTTP2_CANCEL); reject(abortError(signal)); };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    const chunks = [];
    let status = 0;
    let headers = {};
    req.on('response', (h) => {
      status = h[':status'];
      headers = Object.fromEntries(Object.entries(h).filter(([k]) => !k.startsWith(':'))
        .map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)]));
    });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (signal) signal.removeEventListener('abort', onAbort);
      if (status < 200 || status > 599) { reject(new TypeError(`http2: no response (status ${status})`)); return; }
      const body = [101, 204, 205, 304].includes(status) ? null : Buffer.concat(chunks);
      resolve(new Response(body, { status, headers }));
    });
    req.on('error', (err) => { if (signal) signal.removeEventListener('abort', onAbort); reject(new TypeError(`http2: ${err.message}`)); });
    req.end();
  });
}

/* ---- passive-source record / replay cache -------------------------------- */
const replay = createReplayCache({
  dir: CACHE_DIR,
  fresh: FRESH,
  onEvent: (e) => {
    const host = (() => { try { return new URL(e.url).host; } catch { return e.url; } })();
    if (e.kind === 'live-failure') console.warn(`   [source cache] ${host}: ${e.error || `HTTP ${e.status}`} (live; not cached, a retry goes live again)`);
    else if (e.kind === 'stale') console.warn(`   [source cache] ${host}: cached entry holds only a failed answer; fetching live`);
  }
});
const sourceLog = replay.stats;
const sourceFetch = replay.fetch;
async function fetchImpl(url, init = {}) {
  const u = new URL(url);
  if (DOH_ORIGINS.has(u.origin)) return h2fetch(url, init);
  return sourceFetch(String(url), init);
}

/* ---- helpers --------------------------------------------------------------- */
const pad = (s, n) => String(s ?? '').slice(0, n).padEnd(n);
const fmtS = (ms) => `${(ms / 1000).toFixed(1)}s`;
const subOf = (name, domain) => (name === domain ? '@' : name.slice(0, -(domain.length + 1)));
const PROBE = new Set(['wordlist', 'permutation', 'recursive']);

function randomLabel(n = 12) {
  const abc = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < n; i += 1) s += abc[Math.floor(Math.random() * abc.length)];
  return s;
}

/** dns.google JSON API: { status, a: string[], cname: string[] }. */
async function googleResolve(name) {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`, {
    headers: { accept: 'application/dns-json' }
  });
  const j = await res.json();
  const answers = Array.isArray(j.Answer) ? j.Answer : [];
  return {
    status: j.Status,
    a: answers.filter((x) => x.type === 1).map((x) => x.data).sort(),
    cname: answers.filter((x) => x.type === 5).map((x) => String(x.data).replace(/\.$/, ''))
  };
}

/** Re-check DNS-only finds independently and against a random sibling label. */
async function verifyProbeFinds(result, domain, n) {
  const onlyProbe = result.hosts.filter((h) => h.origins.length && h.origins.every((o) => PROBE.has(o)));
  const sample = onlyProbe.slice(0, n);
  const rows = [];
  for (const host of sample) {
    const parent = host.name.slice(host.name.indexOf('.') + 1);
    const real = await googleResolve(host.name);
    const sib = await googleResolve(`${randomLabel()}.${parent}`);
    const resolves = real.status === 0 && (real.a.length > 0 || real.cname.length > 0);
    const sameAsWildcard = sib.status === 0 && (sib.a.length || sib.cname.length)
      && ((real.a.length && real.a.join(',') === sib.a.join(','))
        || (real.cname[0] && real.cname[0] === sib.cname[0]));
    rows.push({ name: host.name, via: host.origins.join(','), resolves, wildcardArtefact: !!sameAsWildcard, google: real.a.concat(real.cname).join(' ') });
  }
  return { checked: rows.length, candidates: onlyProbe.length, rows, falsePositives: rows.filter((r) => !r.resolves || r.wildcardArtefact) };
}

/* ---- one run ---------------------------------------------------------------- */
async function runOne(domain, configId) {
  const dns = new DohClient({ fetchImpl, concurrency: CONCURRENCY, timeoutMs: 6000 });
  const t0 = Date.now();
  const stageLog = [];
  const q = () => { const s = dns.stats(); return { queries: s.queries, requests: s.requests, at: Date.now() }; };
  const result = await runScan({
    domains: [domain], sources: SOURCE_IDS, includeExpired: false, originHints: true,
    dns, fetchImpl, ...CONFIG_DEFS[configId]
  }, {
    onStage: (stage, info) => stageLog.push({ stage, skipped: !!info.skipped, total: info.total, ...q() })
  });
  const wall = Date.now() - t0;
  // stage durations: time from a stage event to the next one
  const stageTimes = stageLog.map((s, i) => {
    const next = stageLog[i + 1] || { ...q(), at: t0 + wall };
    return { stage: s.stage, ms: next.at - s.at, queries: next.queries - s.queries, requests: next.requests - s.requests, skipped: s.skipped };
  });
  const ds = dns.stats();
  const hosts = result.hosts;
  const resolving = hosts.filter((h) => h.resolution.ipv4.length || h.resolution.ipv6.length || h.resolution.cnames.length);
  const only = (pred) => hosts.filter((h) => h.origins.length && h.origins.every(pred)).length;
  const byTech = {
    sources: result.stats.fromSources,
    mine: result.stats.mineFound,
    wordlist: result.stats.wordlistFound,
    permutation: result.stats.permutationFound,
    recursive: result.stats.recursiveFound,
    onlyDnsProbe: only((o) => PROBE.has(o)),
    onlyDns: only((o) => PROBE.has(o) || o.startsWith('dns-mine:') || o === 'input')
  };
  const proxied = hosts.filter((h) => h.classification.hidesOrigin);
  const direct = hosts.filter((h) => h.classification.kind === 'direct');
  const leaks = result.originHints.filter((hnt) => hnt.reasons.some((r) => r.kind === 'resolver-leak'));
  const truth = TRUTH[domain];
  let recall = null;
  if (truth) {
    const bySub = new Map(hosts.filter((h) => isSubdomainOf(h.name, domain)).map((h) => [subOf(h.name, domain), h.origins.join(',')]));
    const missed = truth.filter((s) => !bySub.has(s));
    recall = {
      found: truth.length - missed.length, total: truth.length, missed,
      hits: truth.filter((s) => bySub.has(s)).map((s) => `${s}[${bySub.get(s)}]`)
    };
  }
  return {
    domain, config: configId, wallMs: wall, total: hosts.length, resolving: resolving.length,
    recall, byTech, wildcardParents: result.wildcardParents, stageTimes,
    dnsQueries: ds.queries, dnsRequests: ds.requests, cacheHits: ds.cacheHits, dnsFailures: ds.failures,
    qps: Math.round(ds.requests / Math.max(wall / 1000, 0.001)),
    byResolver: Object.fromEntries(Object.entries(ds.byResolver).map(([id, s]) => [id, `${s.ok}/${s.fail}${s.down ? ' DOWN' : ''}`])),
    // an ok result can still carry a partial error (e.g. crt.sh fell back to the identity search)
    sources: result.sources.map((r) => ({
      source: r.source, ok: r.ok, partial: !!r.partial, names: r.names.length, ms: r.elapsedMs, queryForm: r.queryForm || null,
      error: r.error ? `${r.errorKind || (r.ok ? 'partial' : 'error')}: ${String(r.error).slice(0, 80)}` : null
    })),
    proxied: proxied.map((h) => ({ name: h.name, ips: [...h.resolution.ipv4, ...h.resolution.ipv6].slice(0, 3), provider: h.classification.provider ? h.classification.provider.id : null, candidateNetworks: h.candidateNetworks })),
    direct: direct.map((h) => ({ name: h.name, ips: [...h.resolution.ipv4, ...h.resolution.ipv6].slice(0, 3) })),
    originNetworks: result.originNetworks.map((n) => ({ cidr: n.cidr, ips: n.ips.length, hosts: n.hosts.length })),
    resolverLeaks: leaks.map((hnt) => ({ ip: hnt.ip, hosts: hnt.hosts, detail: hnt.reasons.filter((r) => r.kind === 'resolver-leak').map((r) => r.detail) })),
    cliSuggestion: result.cliSuggestion,
    stats: {
      bruteforceTried: result.stats.bruteforceTried, permutationTried: result.stats.permutationTried, recursiveTried: result.stats.recursiveTried,
      bruteforceWildcardDropped: result.stats.bruteforceWildcardDropped, permutationWildcardDropped: result.stats.permutationWildcardDropped,
      recursiveWildcardDropped: result.stats.recursiveWildcardDropped, bruteforceErrors: result.stats.bruteforceErrors
    },
    names: hosts.map((h) => `${h.name} [${h.origins.join(',')}] ${h.classification.kind}`),
    _result: result
  };
}

function printRun(r) {
  console.log(`\n--- ${r.domain} · config ${r.config} · ${fmtS(r.wallMs)} ---`);
  console.log(`names ${r.total} | resolving ${r.resolving} | direct ${r.direct.length} | proxied/CDN ${r.proxied.length}`);
  console.log(`by technique: ${JSON.stringify(r.byTech)}`);
  console.log(`wildcard parents: ${r.wildcardParents.length ? r.wildcardParents.join(', ') : 'none'}`);
  console.log(`stages: ${r.stageTimes.map((s) => `${s.stage}${s.skipped ? '(skip)' : ''} ${fmtS(s.ms)}/${s.requests}rq`).join(' · ')}`);
  console.log(`DNS: ${r.dnsQueries} queries, ${r.dnsRequests} HTTP requests, ${r.cacheHits} cache hits, ${r.dnsFailures} failures, ${r.qps} req/s | per resolver ok/fail ${JSON.stringify(r.byResolver)}`);
  console.log(`probe stats: ${JSON.stringify(r.stats)}`);
  const srcText = (s) => (s.ok
    ? `ok ${s.names}${s.queryForm ? ` via ${s.queryForm}` : ''}${s.error ? ` PARTIAL (${s.error})` : ''}`
    : `FAIL (${s.error})`);
  console.log(`sources: ${r.sources.map((s) => `${s.source} ${srcText(s)} ${fmtS(s.ms)}`).join(' | ') || 'none'}`);
  if (r.recall) {
    console.log(`ground truth recall: ${r.recall.found}/${r.recall.total}${r.recall.missed.length ? ` — missed: ${r.recall.missed.join(', ')}` : ''}`);
    console.log(`   hits: ${r.recall.hits.join(' ')}`);
  }
  console.log(`origin networks: ${r.originNetworks.map((n) => `${n.cidr} (${n.ips} ip, ${n.hosts} hosts)`).join(', ') || 'none'}`);
  for (const p of r.proxied.slice(0, 20)) console.log(`   proxied ${pad(p.name, 36)} ${pad(p.provider, 11)} ${pad(p.ips.join(' '), 34)} → ${p.candidateNetworks.join(' ') || '-'}`);
  if (r.proxied.length > 20) console.log(`   … ${r.proxied.length - 20} more proxied`);
  for (const l of r.resolverLeaks) console.log(`   resolver-leak ${l.ip} for ${l.hosts.join(', ')} (${l.detail.join('; ')})`);
  if (r.cliSuggestion) console.log(`CLI: ${r.cliSuggestion.length > 300 ? `${r.cliSuggestion.slice(0, 300)}…` : r.cliSuggestion}`);
}

/* ---- main -------------------------------------------------------------------- */
async function main() {
  console.log(`Discovery benchmark — ${DOMAINS.join(', ')} · configs ${CONFIGS.join(',')} · DoH concurrency ${CONCURRENCY} · sources ${SOURCE_IDS.join(',') || 'none'}${FRESH ? ' (fresh)' : ` (replay cache ${CACHE_DIR})`}`);
  const runs = [];
  for (const domain of DOMAINS) {
    for (const cfg of CONFIGS) {
      if (!CONFIG_DEFS[cfg]) { console.error(`unknown config ${cfg}`); continue; }
      let r;
      try {
        r = await runOne(domain, cfg);
      } catch (err) {
        console.error(`\n${domain} · ${cfg}: FAILED ${err && err.stack || err}`);
        continue;
      }
      printRun(r);
      if (VERIFY_N > 0 && cfg !== 'A') {
        const v = await verifyProbeFinds(r._result, domain, VERIFY_N);
        r.verify = v;
        console.log(`verify via dns.google: ${v.checked}/${v.candidates} DNS-only finds checked, ${v.falsePositives.length} false positive(s)`);
        for (const row of v.rows) console.log(`   ${row.resolves && !row.wildcardArtefact ? 'OK ' : 'BAD'} ${pad(row.name, 40)} ${pad(row.via, 22)} ${row.google}${row.wildcardArtefact ? ' [same as random sibling]' : ''}`);
      }
      delete r._result;
      runs.push(r);
    }
  }

  console.log('\n=== Summary ===');
  console.log(`${pad('domain', 18)} ${pad('cfg', 3)} ${pad('time', 7)} ${pad('names', 5)} ${pad('resolv', 6)} ${pad('direct', 6)} ${pad('proxied', 7)} ${pad('DNS rq', 7)} ${pad('rq/s', 5)} ${pad('recall', 7)} origin nets`);
  for (const r of runs) {
    console.log(`${pad(r.domain, 18)} ${pad(r.config, 3)} ${pad(fmtS(r.wallMs), 7)} ${pad(r.total, 5)} ${pad(r.resolving, 6)} ${pad(r.direct.length, 6)} ${pad(r.proxied.length, 7)} ${pad(r.dnsRequests, 7)} ${pad(r.qps, 5)} ${pad(r.recall ? `${r.recall.found}/${r.recall.total}` : '-', 7)} ${r.originNetworks.map((n) => n.cidr).join(' ')}`);
  }
  console.log(`passive-source HTTP: ${sourceLog.live} live (${sourceLog.liveFailures} failed, not cached), ${sourceLog.replayed} replayed`
    + `${sourceLog.staleIgnored ? `, ${sourceLog.staleIgnored} stale failure-only cache file(s) ignored` : ''}`);
  if (JSON_OUT) {
    writeReport(JSON_OUT, JSON.stringify(runs, null, 2));
    console.log(`wrote ${JSON_OUT}`);
  }
  for (const s of sessions.values()) { try { s.close(); } catch { /* ignore */ } }
}

main().catch((err) => { console.error('FATAL', err); process.exitCode = 1; });
