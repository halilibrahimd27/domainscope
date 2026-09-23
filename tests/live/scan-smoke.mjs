#!/usr/bin/env node
/**
 * LIVE (network) smoke test of the scan pipeline: sources.js + doh.js +
 * scanner.js + propagation.js + export.js against real services.
 * Not run by `npm test`.
 *
 *   node tests/live/scan-smoke.mjs                      # default domain (webtekno.com, Cloudflare-proxied)
 *   node tests/live/scan-smoke.mjs example.com.tr --bruteforce small --inventory servers.txt --cert new.pem
 *   node tests/live/scan-smoke.mjs example.com --sources crtsh,anubis --no-hints --json out.json --csv hosts.csv
 *
 * Options:
 *   --bruteforce off|small|medium   (default small)
 *   --sources a,b,c                 (default: every defaultEnabled source)
 *   --chain a,b,c                   DoH failover chain (default DEFAULT_CHAIN)
 *   --inventory FILE                server inventory (any format parseInventory accepts)
 *   --cert FILE                     certificate (PEM / DER / p7b)
 *   --no-hints                      skip origin hints
 *   --no-global                     skip the Global DNS (propagation) checks
 *   --geo-name NAME                 name for the ECS geo check (default www.amazon.com)
 *   --json FILE / --csv FILE        write the scan as JSON / the host table as CSV
 *   --browser                       instead: run a small scan INSIDE headless Chrome/Edge (page served on
 *                                   http://127.0.0.1 with the production CSP) to prove the libraries work
 *                                   with real browser CORS / CSP (CHROME env var overrides the browser path)
 *
 * Node's fetch is HTTP/1.1 only, while dns.quad9.net / dns11.quad9.net require
 * HTTP/2. The fetchImpl below therefore sends DoH requests over node:http2
 * (like a browser) and everything else through the global fetch.
 *
 * Exit code 1 when the scan fails, nothing resolves, or a DoH resolver of the
 * chain never answered.
 */
import http2 from 'node:http2';
import http from 'node:http';
import tls from 'node:tls';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DohClient } from '../../assets/js/lib/doh.js';
import { runScan } from '../../assets/js/lib/scanner.js';
import { checkPropagation } from '../../assets/js/lib/propagation.js';
import { toCsv, toJson, scanHostRows, HOST_COLUMNS, namesForCli, targetsForCli, cliCommand } from '../../assets/js/lib/export.js';
import { RESOLVERS, DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';
import { SOURCES } from '../../assets/js/lib/sources.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';

/* ------------------------------------------------------------------------ */
/* Arguments                                                                */
/* ------------------------------------------------------------------------ */

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const option = (name, fallback = null) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};
const optionNames = new Set(['--bruteforce', '--sources', '--chain', '--inventory', '--cert', '--json', '--csv', '--geo-name']);
const positional = argv.filter((a, i) => !a.startsWith('--') && !optionNames.has(argv[i - 1]));
const DOMAIN = positional[0] || 'webtekno.com';
const BRUTEFORCE = option('--bruteforce', 'small');
const SOURCE_IDS = option('--sources') ? option('--sources').split(',') : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
const CHAIN = option('--chain') ? option('--chain').split(',') : [...DEFAULT_CHAIN];
const ORIGIN = 'https://example.github.io'; // what a GitHub Pages deployment sends

/* ------------------------------------------------------------------------ */
/* fetchImpl: HTTP/2 for DoH, global fetch for the rest                     */
/* ------------------------------------------------------------------------ */

function caBundle() {
  try {
    // family.cloudflare-dns.com chains to a root missing from Node's bundle.
    return [...tls.getCACertificates('default'), ...tls.getCACertificates('system')];
  } catch {
    return undefined;
  }
}
const CA = caBundle();
const DOH_ORIGINS = new Set(RESOLVERS.map((r) => new URL(r.url).origin));
const sessions = new Map();
const httpStats = { h2: 0, h1: 0 };

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
    if (signal && signal.aborted) {
      reject(abortError(signal));
      return;
    }
    let req;
    try {
      req = session(u.origin).request({
        ':method': 'GET',
        ':path': u.pathname + u.search,
        origin: ORIGIN,
        ...Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]))
      });
    } catch (err) {
      reject(new TypeError(`http2: ${err.message}`));
      return;
    }
    httpStats.h2 += 1;
    const onAbort = () => {
      req.close(http2.constants.NGHTTP2_CANCEL);
      reject(abortError(signal));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    const chunks = [];
    let status = 0;
    let headers = {};
    req.on('response', (h) => {
      status = h[':status'];
      headers = Object.fromEntries(Object.entries(h).filter(([k]) => !k.startsWith(':')).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)]));
    });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (signal) signal.removeEventListener('abort', onAbort);
      const body = [101, 204, 205, 304].includes(status) ? null : Buffer.concat(chunks);
      resolve(new Response(body, { status, headers }));
    });
    req.on('error', (err) => {
      if (signal) signal.removeEventListener('abort', onAbort);
      reject(new TypeError(`http2: ${err.message}`));
    });
    req.end();
  });
}

async function fetchImpl(url, init = {}) {
  const u = new URL(url);
  if (DOH_ORIGINS.has(u.origin)) return h2fetch(url, init);
  httpStats.h1 += 1;
  const headers = { ...(init.headers || {}) };
  return fetch(url, { ...init, headers });
}

/* ------------------------------------------------------------------------ */
/* Output helpers                                                           */
/* ------------------------------------------------------------------------ */

const t0 = Date.now();
const secs = () => ((Date.now() - t0) / 1000).toFixed(1).padStart(6);
const log = (...a) => console.log(`[${secs()}s]`, ...a);
const pad = (s, n) => String(s ?? '').slice(0, n).padEnd(n);

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  console.log(`Live scan smoke test — domain ${DOMAIN}, sources ${SOURCE_IDS.join(',')}, brute force ${BRUTEFORCE}, chain ${CHAIN.join(' → ')}`);
  const dns = new DohClient({ fetchImpl, chain: CHAIN, concurrency: 16 });
  let failures = 0;

  // 1. Every DoH resolver answers through the fetch shim (explicit resolver, no failover).
  log('DoH reachability (example.com A, explicit resolver, NSID):');
  for (const r of RESOLVERS) {
    const res = await dns.query('example.com', 'A', { resolver: r.id, noCache: true });
    const answers = res.answers.filter((x) => x.type === 'A').map((x) => x.data).join(' ');
    console.log(`   ${pad(r.id, 18)} ${res.ok ? `${pad(res.rcode, 9)} ${pad(`${res.elapsedMs} ms`, 8)} AD=${res.ad ? 1 : 0} nsid=${pad(res.nsid || '-', 16)} ${answers}` : `FAILED ${res.errorKind}: ${res.error}`}`);
    if (!res.ok && CHAIN.includes(r.id)) failures += 1;
  }
  const ecs = await dns.query('www.amazon.com', 'A', { resolver: 'google', ecs: '78.181.32.0/24', noCache: true });
  log(`ECS via google (TR vantage): scope /${ecs.ecs ? ecs.ecs.scopePrefix : '?'} → ${ecs.answers.filter((x) => x.type === 'A').map((x) => x.data).join(' ')}`);

  // 2. Full scan.
  const inventory = option('--inventory') ? parseInventory(readFileSync(option('--inventory'), 'utf8')) : { servers: [] };
  const cert = option('--cert') ? parseCertificates(readFileSync(option('--cert'))).leaf : null;
  const stageAt = {};
  let lastProgress = 0;
  const scan = await runScan({
    domains: [DOMAIN], cert, sources: SOURCE_IDS, includeExpired: false, bruteforce: BRUTEFORCE,
    inventory: inventory.servers, originHints: !flag('--no-hints'), dns, fetchImpl
  }, {
    onStage: (stage, info) => {
      stageAt[stage] = Date.now();
      log(`stage ${stage}${info.skipped ? ' (skipped)' : ''}${info.total !== undefined ? ` total=${info.total}` : ''}`);
    },
    onSource: (r) => log(`   source ${pad(r.source, 12)} ${r.ok ? 'ok ' : 'ERR'} names=${String(r.names.length).padStart(5)} hints=${String(r.ipHints.length).padStart(4)} certs=${String(r.certs.length).padStart(4)} ${String(r.elapsedMs).padStart(6)} ms${r.error ? `  ${r.errorKind}: ${r.error}` : ''}`),
    onProgress: ({ stage, done, total }) => {
      if (stage !== 'resolve' && stage !== 'bruteforce') return;
      if (done === total || Date.now() - lastProgress > 3000) {
        lastProgress = Date.now();
        log(`   ${stage} ${done}/${total}`);
      }
    }
  });

  // 3. Summary.
  const s = scan.stats;
  console.log('\n=== Scan summary ===');
  console.log(`hosts ${s.total} | resolved ${s.resolved} | cloudflare ${s.cloudflare} | cdn ${s.cdn} | platform ${s.platform} | direct ${s.direct} | private ${s.private} | nxdomain ${s.nxdomain} | unresolved ${s.unresolved} | dangling ${s.dangling} | wildcard suspects ${s.wildcardSuspects}`);
  console.log(`covered ${s.covered} | matched servers ${s.matchedServers} | origin hints ${s.originHints} | unmatched IPs ${s.unmatchedIps} | brute force ${s.bruteforceFound}/${s.bruteforceTried} (wildcard-dropped ${s.bruteforceWildcardDropped}) | CT certs ${s.ctCerts} | DNS queries ${s.dnsQueries} | ${(s.elapsedMs / 1000).toFixed(1)} s`);
  console.log(`wildcards: ${Object.entries(scan.wildcards).map(([d, w]) => `${d}=${w.wildcard ? `yes (${[...w.ipv4, ...w.cnames].join(' ')})` : 'no'}`).join(', ')}`);
  console.log('\nSources:');
  for (const r of scan.sources) {
    console.log(`  ${pad(r.source, 12)} ${r.ok ? 'OK   ' : 'FAIL '} names ${String(r.names.length).padStart(5)}  rows ${String(r.rows).padStart(6)}  ${String(r.elapsedMs).padStart(6)} ms  ${r.error ? `${r.errorKind}: ${r.error}` : ''}`);
  }
  const stageTimes = Object.entries(stageAt).sort((a, b) => a[1] - b[1]);
  console.log(`\nStage timings: ${stageTimes.map(([k, v], i) => `${k} ${(((stageTimes[i + 1]?.[1] ?? Date.now()) - v) / 1000).toFixed(1)}s`).join(' | ')}`);

  console.log('\nHosts (first 40):');
  for (const h of scan.hosts.slice(0, 40)) {
    const r = h.resolution;
    const c = h.classification;
    console.log(`  ${pad(h.name, 38)} ${pad(r.status, 8)} ${pad(c.kind + (c.dangling ? '!' : ''), 11)} ${pad(c.provider ? c.provider.id : '', 12)} ${pad([...r.ipv4, ...r.ipv6].slice(0, 2).join(' '), 34)} ${pad(h.origins.join(','), 34)}${h.wildcardSuspect ? ' [wildcard?]' : ''}`);
  }
  if (scan.hosts.length > 40) console.log(`  … ${scan.hosts.length - 40} more`);

  console.log('\nOrigin hints (first 15):');
  for (const hint of scan.originHints.slice(0, 15)) {
    console.log(`  ${pad(hint.ip, 40)} ${hint.reasons.map((r) => `${r.kind}: ${r.detail}`).join(' | ').slice(0, 140)}`);
  }
  if (scan.hintErrors.length) console.log(`  hint notes: ${scan.hintErrors.join('; ')}`);

  const ds = dns.stats();
  console.log(`\nDoH client: queries ${ds.queries}, cache hits ${ds.cacheHits}, shared ${ds.shared}, requests ${ds.requests}, failures ${ds.failures}`);
  for (const [id, r] of Object.entries(ds.byResolver)) {
    console.log(`  ${pad(id, 18)} ok ${String(r.ok).padStart(5)}  fail ${String(r.fail).padStart(4)}  avg ${r.avgMs ?? '-'} ms${r.down ? '  (breaker open)' : ''}${r.lastError ? `  last error: ${r.lastError}` : ''}`);
  }
  console.log(`HTTP requests: ${httpStats.h2} over HTTP/2 (DoH), ${httpStats.h1} over fetch (sources)`);

  // 4. Exports on real data.
  const csv = toCsv(scanHostRows(scan), HOST_COLUMNS);
  const json = toJson(scan);
  JSON.parse(json);
  console.log(`\nExports: CSV ${csv.split('\r\n').length - 2} rows / ${csv.length} chars, JSON ${json.length} chars (re-parsed OK), names.txt ${namesForCli(scan).split('\n').length - 1} names, targets.txt ${targetsForCli([...scan.servers, ...scan.originHints, ...scan.unmatchedIps]).split('\n').length - 1} lines`);
  console.log(`CLI: ${cliCommand({ certFile: cert ? 'new-cert.pem' : null })}`);
  if (option('--json')) writeFileSync(option('--json'), json);
  if (option('--csv')) writeFileSync(option('--csv'), csv);

  // 5. Global DNS for www.<domain>.
  if (!flag('--no-global')) {
    const name = `www.${DOMAIN}`;
    const g = await checkPropagation(name, 'A', { dns });
    console.log(`\nGlobal DNS ${name} A: ${g.resolverResults.length} resolvers + ${g.geoResults.length} geo vantages → ${g.groups.length} answer group(s), consistent=${g.consistent} (resolvers ${g.resolversConsistent}, geo ${g.geoConsistent})`);
    for (const grp of g.groups.slice(0, 6)) {
      console.log(`  ${String(grp.members.length).padStart(3)}× ${grp.values.join(' ').slice(0, 90)}${grp.error ? ' [error]' : ''}${grp.filtered ? ' [filtered]' : ''}  e.g. ${grp.members.slice(0, 4).join(', ')}`);
    }
    const failed = g.resolverResults.filter((x) => !x.response.ok).map((x) => `${x.resolver.id} (${x.response.errorKind})`);
    if (failed.length) console.log(`  failed: ${failed.join(', ')}`);
    console.log(`  IPs seen worldwide (${g.addresses.length}):`);
    for (const a of g.addresses.slice(0, 12)) {
      console.log(`    ${pad(a.ip, 40)} ${pad(a.provider ? a.provider.name : a.private ? 'private' : '-', 22)} ${String(a.members.length).padStart(3)}× e.g. ${a.members.slice(0, 3).join(', ')}`);
    }
    // A geo-aware name shows the ECS view best (CloudFront answers differ per country).
    const geoName = option('--geo-name', 'www.amazon.com');
    const geo = await checkPropagation(geoName, 'A', { dns, resolvers: [] });
    const scoped = geo.geoResults.filter((x) => Number.isFinite(x.scopePrefix) && x.scopePrefix > 0).length;
    console.log(`\nGeo (ECS via google) ${geoName}: ${geo.geoResults.length} vantages → ${geo.groups.length} distinct answers, ${geo.addresses.length} IPs, ${scoped} with non-zero ECS scope`);
    for (const x of geo.geoResults.filter((it) => /^(tr-|us-|de-|jp-)/.test(it.vantage.id))) {
      console.log(`    ${pad(x.vantage.id, 11)} ${pad(x.vantage.isp, 22)} /${x.scopePrefix ?? '-'}  ${x.addresses.join(' ')}`);
    }
  }

  if (!scan.hosts.length || !s.resolved) failures += 1;
  for (const id of CHAIN) if (!ds.byResolver[id] || ds.byResolver[id].ok === 0) failures += 1;
  console.log(`\n${failures ? `FAILED (${failures} problem(s))` : 'LIVE SMOKE OK'} in ${secs().trim()} s`);
  for (const s2 of sessions.values()) s2.close();
  process.exitCode = failures ? 1 : 0;
}

/* ------------------------------------------------------------------------ */
/* Browser mode                                                             */
/* ------------------------------------------------------------------------ */

const REPO = fileURLToPath(new URL('../../', import.meta.url));
// Same policy as index.html (spec §1).
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src https:; base-uri 'none'; form-action 'none'; manifest-src 'self'";

function findBrowser() {
  const candidates = [
    process.env.CHROME,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

function browserScript(domain) {
  return `
import { DohClient } from './assets/js/lib/doh.js';
import { runScan } from './assets/js/lib/scanner.js';
import { checkPropagation } from './assets/js/lib/propagation.js';
import { fetchSource } from './assets/js/lib/sources.js';
import { toCsv, toJson, scanHostRows, HOST_COLUMNS } from './assets/js/lib/export.js';
const out = { csp: [] };
document.addEventListener('securitypolicyviolation', (e) => out.csp.push(e.violatedDirective + ' ' + e.blockedURI));
const t0 = performance.now();
try {
  const dns = new DohClient();
  const q = await dns.query('example.com', 'A', { noCache: true });
  out.query = { ok: q.ok, resolver: q.resolver, rcode: q.rcode, ms: q.elapsedMs, nsid: q.nsid };
  const cs = await fetchSource('certspotter', ${JSON.stringify(domain)});
  out.certspotter = { ok: cs.ok, names: cs.names.length, certs: cs.certs.length, error: cs.error };
  const scan = await runScan({ domains: [${JSON.stringify(domain)}], sources: ['crtsh', 'anubis', 'hackertarget'], bruteforce: 'small', dns });
  out.scan = {
    hosts: scan.stats.total, resolved: scan.stats.resolved, cloudflare: scan.stats.cloudflare, direct: scan.stats.direct,
    nxdomain: scan.stats.nxdomain, hints: scan.stats.originHints, bruteforce: scan.stats.bruteforceFound + '/' + scan.stats.bruteforceTried,
    sources: scan.sources.map((r) => [r.source, r.ok, r.names.length, r.elapsedMs, r.error])
  };
  const g = await checkPropagation('www.' + ${JSON.stringify(domain)}, 'A', { dns });
  out.global = {
    resolvers: g.resolverResults.length, geo: g.geoResults.length, groups: g.groups.length, consistent: g.consistent,
    failed: g.resolverResults.filter((x) => !x.response.ok).map((x) => x.resolver.id + ':' + x.response.errorKind),
    scopes: [...new Set(g.geoResults.map((x) => x.scopePrefix))]
  };
  out.exports = { csv: toCsv(scanHostRows(scan), HOST_COLUMNS).length, json: toJson(scan).length };
  const st = dns.stats();
  out.dns = { queries: st.queries, requests: st.requests, failures: st.failures,
    byResolver: Object.fromEntries(Object.entries(st.byResolver).map(([k, v]) => [k, v.ok + '/' + v.fail + ' ' + v.avgMs + 'ms'])) };
} catch (e) {
  out.error = String((e && e.stack) || e);
}
out.seconds = Math.round((performance.now() - t0) / 100) / 10;
document.getElementById('out').textContent = JSON.stringify(out);
`;
}

async function browserMain() {
  const exe = findBrowser();
  if (!exe) {
    console.log('No Chrome/Edge found (set CHROME=...)');
    process.exitCode = 1;
    return;
  }
  const page = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${CSP}"><title>smoke</title></head><body><pre id="out">pending</pre><script type="module" src="/smoke.js"></script></body></html>`;
  const script = browserScript(DOMAIN);
  const server = http.createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (path === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(page);
    } else if (path === '/smoke.js') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(script);
    } else if (path.startsWith('/assets/js/lib/') && path.endsWith('.js')) {
      const file = normalize(join(REPO, path));
      if (!file.startsWith(normalize(join(REPO, 'assets', 'js', 'lib') + sep)) || !existsSync(file)) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(readFileSync(file));
    } else {
      res.writeHead(404).end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const profile = mkdtempSync(join(tmpdir(), 'scan-smoke-'));
  console.log(`Browser smoke test — ${exe}\n  page ${url} (CSP as index.html), domain ${DOMAIN}`);
  // Real-time run driven over the DevTools protocol (Node 22 global WebSocket).
  // (--dump-dom with --virtual-time-budget is unusable here: virtual time runs
  // ahead while network requests are pending, so timeouts fire early.)
  const chrome = spawn(exe, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank']);
  let ws = null;
  try {
    const portFile = join(profile, 'DevToolsActivePort');
    const started = Date.now();
    while (!existsSync(portFile) && Date.now() - started < 20000) await new Promise((r) => setTimeout(r, 100));
    const port = readFileSync(portFile, 'utf8').split('\n')[0].trim();
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', reject, { once: true });
    });
    let nextId = 0;
    const waiting = new Map();
    const consoleLines = [];
    ws.addEventListener('message', (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && waiting.has(m.id)) {
        waiting.get(m.id)(m);
        waiting.delete(m.id);
      } else if (m.method === 'Log.entryAdded') {
        consoleLines.push(`${m.params.entry.level}: ${m.params.entry.text}`);
      } else if (m.method === 'Runtime.exceptionThrown') {
        consoleLines.push(`exception: ${m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text}`);
      }
    });
    const send = (method, params = {}) => new Promise((resolve) => {
      nextId += 1;
      waiting.set(nextId, resolve);
      ws.send(JSON.stringify({ id: nextId, method, params }));
    });
    await send('Runtime.enable');
    await send('Log.enable');
    await send('Page.navigate', { url });
    let text = 'pending';
    while (Date.now() - started < 400000) {
      await new Promise((r) => setTimeout(r, 1000));
      const res = await send('Runtime.evaluate', {
        expression: "document.getElementById('out') ? document.getElementById('out').textContent : 'pending'",
        returnByValue: true
      });
      text = (res.result && res.result.result && res.result.result.value) || 'pending';
      if (text !== 'pending') break;
    }
    let result = null;
    try {
      result = JSON.parse(text);
    } catch {
      console.log(`  page did not finish: ${text.slice(0, 300)}`);
      console.log(consoleLines.join('\n'));
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(result, null, 2));
    if (consoleLines.length) console.log(`browser console:\n  ${consoleLines.join('\n  ')}`);
    const ok = !result.error && result.query && result.query.ok && result.scan && result.scan.resolved > 0 && !result.csp.length;
    console.log(ok ? 'BROWSER SMOKE OK' : 'BROWSER SMOKE FAILED');
    process.exitCode = ok ? 0 : 1;
  } finally {
    if (ws) ws.close();
    chrome.kill();
    server.close();
    await new Promise((r) => setTimeout(r, 500));
    try { rmSync(profile, { recursive: true, force: true }); } catch { /* profile may still be locked */ }
  }
}

(flag('--browser') ? browserMain() : main()).catch((err) => {
  console.error('Smoke test crashed:', err);
  process.exitCode = 1;
});
