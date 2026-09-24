#!/usr/bin/env node
/**
 * LIVE (network, real browser): which DNS-over-HTTPS endpoints can a web page actually read?
 * Not run by `npm test` / CI.
 *
 *   node tests/live/browser-doh-matrix.mjs                       # Chrome, 3 fresh sessions × 3 reps
 *   node tests/live/browser-doh-matrix.mjs --browser chrome,edge # both browsers
 *   node tests/live/browser-doh-matrix.mjs --only quad9,cloudflare --sessions 1 --reps 2
 *   node tests/live/browser-doh-matrix.mjs --no-candidates --no-vantages --json tests/live/private/doh-matrix.json
 *
 * --json FILE writes the raw samples; like every live report, inside the repository it must go
 * to a gitignored path (tests/live/private/…, *.local.json — see targets.mjs reportPath).
 * For every resolver in assets/js/lib/resolvers.js (plus candidate Quad9 endpoints: IP literals,
 * the dnsN hostnames and the old :5053 port) the page served by tests/e2e/serve.mjs fetches
 * `www.example.com A` in every request form a DoH client can use:
 *   get          GET ?dns=<base64url wire>, accept: application/dns-message (what lib/doh.js does)
 *   post         POST wire, content-type: application/dns-message (needs a CORS preflight)
 *   post-simple  POST wire without a content-type (a "simple" request: no preflight)
 *   json         GET ?name=&type= with accept: application/dns-json (Google: /resolve)
 * and every ECS vantage (GEO_VANTAGES) is queried on DEFAULT_GEO_RESOLVER with its subnet.
 *
 * Each browser session starts from a fresh profile (cold DNS / HTTPS-RR / Alt-Svc caches), then
 * repeats every request (--reps): HTTP/3 usually kicks in after the first response (Alt-Svc) or
 * even on the first request (the HTTPS DNS record advertises alpn=h3). Per request we record:
 *   - outcome in the page (DNS answer decoded / HTTP status / TypeError),
 *   - the CORS failure reason from CDP (Network.loadingFailed corsErrorStatus / blockedReason),
 *   - the protocol actually used and the raw response headers from Chrome's NetLog
 *     (HTTP_TRANSACTION_{QUIC,HTTP2}_SEND_REQUEST_HEADERS) — CDP gives no protocol for a
 *     CORS-blocked response, the NetLog does.
 *
 * Then the circuit breaker / balance pool of lib/doh.js is exercised in the page (--no-breaker
 * skips it): a browser-failing resolver first in the chain, the default bulk balance pool, and a
 * black-hole endpoint that never answers.
 *
 * Exit code 1 when resolvers.js metadata disagrees with what the browser did: a resolver flagged
 * browserReliable:true failed a GET for a browser reason (CORS, HTTP status, bad body), or one
 * flagged false answered every GET (flag is stale). Timeouts / unreachable endpoints are printed
 * as warnings ("~"): they depend on the network the test runs from (e.g. Control D is
 * unreachable from some networks), not on the browser.
 */

import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startServer } from '../e2e/serve.mjs';
import { launchBrowser } from '../e2e/cdp.mjs';
import { RESOLVERS, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, getResolver } from '../../assets/js/lib/resolvers.js';
import { reportPathOrExit, writeReport } from './targets.mjs';

const argv = process.argv.slice(2);
const opt = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] !== undefined ? argv[i + 1] : def;
};
const OPT = {
  browsers: String(opt('--browser', 'chrome')).split(',').map((s) => s.trim()).filter(Boolean),
  sessions: Math.max(1, Number(opt('--sessions', 3)) || 3),
  reps: Math.max(1, Number(opt('--reps', 3)) || 3),
  only: opt('--only', '') ? new Set(String(opt('--only', '')).split(',').map((s) => s.trim())) : null,
  candidates: !argv.includes('--no-candidates'),
  vantages: !argv.includes('--no-vantages'),
  breaker: !argv.includes('--no-breaker'),
  netlog: !argv.includes('--no-netlog'),
  headed: argv.includes('--headed'),
  json: reportPathOrExit(opt('--json', null)),
  timeoutMs: Number(opt('--timeout', 5000)) || 5000
};

const FORMS = ['get', 'post', 'post-simple', 'json'];
const QNAME = 'www.example.com';

/**
 * Candidate endpoints for the resolvers browsers cannot read (Quad9: HTTP/3 without CORS).
 * An IP literal skips the HTTPS DNS record (alpn=h3) but still learns h3 from Alt-Svc;
 * :5053 would be a separate origin (Alt-Svc for :443 does not apply) if Quad9 still served it.
 */
const CANDIDATES = [
  { id: 'quad9@9.9.9.9', of: 'quad9', url: 'https://9.9.9.9/dns-query' },
  { id: 'quad9@149.112.112.112', of: 'quad9', url: 'https://149.112.112.112/dns-query' },
  { id: 'quad9-ecs@9.9.9.11', of: 'quad9-ecs', url: 'https://9.9.9.11/dns-query' },
  { id: 'quad9@dns9', of: 'quad9', url: 'https://dns9.quad9.net/dns-query' },
  { id: 'quad9@dns10', of: 'quad9', url: 'https://dns10.quad9.net/dns-query' },
  { id: 'quad9@dns12', of: 'quad9-ecs', url: 'https://dns12.quad9.net/dns-query' },
  { id: 'quad9@:5053', of: 'quad9', url: 'https://dns.quad9.net:5053/dns-query' },
  { id: 'quad9-ecs@dns11:5053', of: 'quad9-ecs', url: 'https://dns11.quad9.net:5053/dns-query' },
  { id: 'quad9@dns9:5053', of: 'quad9', url: 'https://dns9.quad9.net:5053/dns-query' },
  { id: 'quad9@dns10:5053', of: 'quad9', url: 'https://dns10.quad9.net:5053/dns-query' },
  { id: 'quad9@dns12:5053', of: 'quad9-ecs', url: 'https://dns12.quad9.net:5053/dns-query' }
];

/** JSON API endpoint per resolver (most RFC 8484 endpoints also take ?name=&type= with dns-json). */
const jsonUrlOf = (target) => (target.id === 'google' ? 'https://dns.google/resolve' : target.url);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Random letter case (DNS names are case-insensitive): makes every request URL unique. */
function randomCase(name, used) {
  for (let i = 0; i < 1000; i += 1) {
    const s = [...name].map((c) => (/[a-z]/.test(c) && Math.random() < 0.5 ? c.toUpperCase() : c)).join('');
    if (!used.has(s)) {
      used.add(s);
      return s;
    }
  }
  return name;
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next;
      next += 1;
      out[i] = await fn(items[i], i);
    }
  }));
  return out;
}

/* ------------------------------------------------------------------------ */
/* In-page code (serialised with Function#toString — must be self-contained) */
/* ------------------------------------------------------------------------ */

/** One DoH request from the page; returns what the page could read. */
async function pageFetch(spec) {
  const w = await import('./assets/js/lib/dnswire.js');
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), spec.timeoutMs);
  const init = { credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', signal: ctl.signal };
  let url = spec.url;
  let method = 'GET';
  const wire = spec.form === 'json' ? null : w.encodeQuery(spec.name, 'A', { id: 0, nsid: true, ecs: spec.ecs || null });
  if (spec.form === 'get') {
    url = `${spec.url}${spec.url.includes('?') ? '&' : '?'}dns=${w.base64UrlEncode(wire)}`;
    init.headers = { accept: 'application/dns-message' };
  } else if (spec.form === 'post') {
    method = 'POST';
    init.headers = { accept: 'application/dns-message', 'content-type': 'application/dns-message' };
    init.body = wire;
  } else if (spec.form === 'post-simple') {
    method = 'POST';
    init.headers = { accept: 'application/dns-message' };
    init.body = wire; // a BufferSource body gets no Content-Type → CORS "simple" request, no preflight
  } else {
    url = `${spec.jsonUrl}?name=${encodeURIComponent(spec.name)}&type=A`;
    init.headers = { accept: 'application/dns-json' };
  }
  init.method = method;
  const t0 = performance.now();
  const base = { url, method };
  try {
    const res = await fetch(url, init);
    const buf = new Uint8Array(await res.arrayBuffer());
    const ms = Math.round(performance.now() - t0);
    if (!res.ok) return { ...base, ok: false, status: res.status, ms, error: `HTTP ${res.status}`, kind: 'http' };
    if (spec.form === 'json') {
      try {
        const j = JSON.parse(new TextDecoder().decode(buf));
        if (typeof j.Status !== 'number') throw new Error('no Status');
        return { ...base, ok: true, status: res.status, ms, rcode: j.Status === 0 ? 'NOERROR' : `RCODE${j.Status}`, answers: (j.Answer || []).length };
      } catch (e) {
        return { ...base, ok: false, status: res.status, ms, error: `not DNS JSON: ${e.message}`, kind: 'parse' };
      }
    }
    try {
      const msg = w.decodeMessage(buf);
      const q = msg.questions[0];
      if (!msg.flags.qr || !q || q.name.toLowerCase().replace(/\.$/, '') !== spec.name.toLowerCase()) throw new Error('not the answer to our question');
      return {
        ...base, ok: true, status: res.status, ms, rcode: msg.rcodeName, answers: msg.answers.length,
        scope: msg.edns && msg.edns.ecs ? msg.edns.ecs.scopePrefix : null, nsid: msg.edns && msg.edns.nsid ? msg.edns.nsid : null
      };
    } catch (e) {
      return { ...base, ok: false, status: res.status, ms, error: `bad DNS message: ${e.message}`, kind: 'parse' };
    }
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    return { ...base, ok: false, status: 0, ms, error: ctl.signal.aborted ? `timeout ${spec.timeoutMs} ms` : String(e), kind: ctl.signal.aborted ? 'timeout' : 'network' };
  } finally {
    clearTimeout(timer);
  }
}

/** lib/doh.js circuit breaker + balance pool, exercised in the real browser. */
async function pageBreakerCheck() {
  const { DohClient } = await import('./assets/js/lib/doh.js');
  const rnd = () => Math.random().toString(36).slice(2, 10);
  const pct = (list, p) => {
    const s = list.slice().sort((a, b) => a - b);
    return s.length ? s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] : null;
  };
  const summarize = (res, stats, wallMs, watch) => {
    const hist = (fn) => {
      const m = {};
      for (const r of res) {
        const k = fn(r);
        if (k) m[k] = (m[k] || 0) + 1;
      }
      return m;
    };
    const total = res.map((r) => r.totalMs);
    return {
      queries: res.length,
      ok: res.filter((r) => r.ok).length,
      answeredBy: hist((r) => (r.ok ? r.resolver : null)),
      firstTried: hist((r) => (r.attempts[0] ? r.attempts[0].resolver : null)),
      watchAttempts: res.reduce((n, r) => n + r.attempts.filter((a) => a.resolver === watch).length, 0),
      watchDown: stats.byResolver[watch] ? stats.byResolver[watch].down : null,
      slowOver1s: total.filter((ms) => ms > 1000).length,
      p50: pct(total, 50),
      p95: pct(total, 95),
      max: Math.max(...total),
      wallMs: Math.round(wallMs)
    };
  };
  const out = {};
  // A. A resolver the browser cannot read (Quad9: HTTP/3 without CORS) first in the chain.
  {
    const dns = new DohClient({ chain: ['quad9', 'cloudflare', 'google'], concurrency: 12 });
    const t0 = performance.now();
    const res = await Promise.all(Array.from({ length: 40 }, () => dns.query(`${rnd()}.example.com`, 'A')));
    out.failingFirst = summarize(res, dns.stats(), performance.now() - t0, 'quad9');
  }
  // B. Default client, bulk balance mode (what wordlist / permutation resolving uses).
  {
    const dns = new DohClient({ concurrency: 12 });
    const t0 = performance.now();
    const res = await Promise.all(Array.from({ length: 60 }, () => dns.query(`${rnd()}.example.com`, 'A', { balance: true })));
    out.balance = summarize(res, dns.stats(), performance.now() - t0, 'quad9');
  }
  // C. A black hole (TCP never answers — Quad9's retired :5053) first in the chain, 2 s timeout.
  {
    const dns = new DohClient({ chain: [{ id: 'blackhole', url: 'https://dns.quad9.net:5053/dns-query' }, 'cloudflare'], concurrency: 6, timeoutMs: 2000 });
    const t0 = performance.now();
    const res = await Promise.all(Array.from({ length: 30 }, () => dns.query(`${rnd()}.example.com`, 'A')));
    out.blackhole = summarize(res, dns.stats(), performance.now() - t0, 'blackhole');
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* CDP network recorder                                                     */
/* ------------------------------------------------------------------------ */

function recordNetwork(page) {
  const byId = new Map();
  const order = [];
  const on = (m, fn) => page.conn.on(m, fn, page.sessionId);
  on('Network.requestWillBeSent', (p) => {
    let rec = byId.get(p.requestId);
    if (!rec) {
      rec = { id: p.requestId, url: p.request.url, method: p.request.method, type: p.type, initiator: p.initiator || null, claimed: false, done: false };
      byId.set(p.requestId, rec);
      order.push(rec);
    }
  });
  on('Network.responseReceived', (p) => {
    const rec = byId.get(p.requestId);
    if (rec) {
      rec.protocol = p.response.protocol || null;
      rec.status = p.response.status;
    }
  });
  on('Network.responseReceivedExtraInfo', (p) => {
    const rec = byId.get(p.requestId);
    if (rec) {
      rec.rawStatus = p.statusCode;
      rec.rawHeaders = p.headers;
    } else {
      byId.set(p.requestId, { id: p.requestId, rawStatus: p.statusCode, rawHeaders: p.headers, early: true });
    }
  });
  on('Network.loadingFinished', (p) => {
    const rec = byId.get(p.requestId);
    if (rec) rec.done = true;
  });
  on('Network.loadingFailed', (p) => {
    const rec = byId.get(p.requestId);
    if (rec) {
      rec.done = true;
      rec.failed = { errorText: p.errorText, canceled: !!p.canceled, blockedReason: p.blockedReason || null, cors: p.corsErrorStatus ? p.corsErrorStatus.corsError : null };
    }
  });
  return {
    /** The request a page fetch made (unique URL, or the first unclaimed POST to that URL). */
    async claim(url, method) {
      const deadline = Date.now() + 2500;
      for (;;) {
        const rec = order.find((r) => !r.claimed && r.url === url && r.method === method && r.type !== 'Preflight');
        if (rec && (rec.done || Date.now() > deadline)) {
          rec.claimed = true;
          const pre = order.find((r) => r.type === 'Preflight' && r.initiator && r.initiator.requestId === rec.id);
          return { ...rec, preflight: pre ? { status: pre.rawStatus ?? pre.status ?? null, failed: pre.failed || null } : null };
        }
        if (!rec && Date.now() > deadline) return null;
        await sleep(40);
      }
    }
  };
}

/* ------------------------------------------------------------------------ */
/* NetLog: the protocol really used (also for CORS-blocked responses)        */
/* ------------------------------------------------------------------------ */

async function readNetLog(file) {
  let txt;
  try {
    txt = (await readFile(file, 'utf8')).trim();
  } catch {
    return null;
  }
  // A NetLog cut short by a killed browser lacks the closing brackets.
  if (!txt.endsWith('}')) txt = `${txt.replace(/,\s*$/, '')}]}`;
  let log;
  try {
    log = JSON.parse(txt);
  } catch {
    try {
      log = JSON.parse(`${txt.slice(0, txt.lastIndexOf('},') + 1)}]}`);
    } catch {
      return null;
    }
  }
  const name = Object.fromEntries(Object.entries(log.constants.logEventTypes).map(([k, v]) => [v, k]));
  const bySource = new Map();
  for (const e of log.events || []) {
    const id = e.source && e.source.id;
    if (id === undefined) continue;
    if (!bySource.has(id)) bySource.set(id, []);
    bySource.get(id).push(e);
  }
  const requests = [];
  for (const events of bySource.values()) {
    const start = events.find((e) => name[e.type] === 'URL_REQUEST_START_JOB' && e.params && e.params.url);
    if (!start || !/^https:/.test(start.params.url)) continue;
    let protocol = null;
    let headers = null;
    for (const e of events) {
      const n = name[e.type];
      if (n === 'HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS') protocol = 'h3';
      else if (n === 'HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS') protocol = 'h2';
      else if (n === 'HTTP_TRANSACTION_SEND_REQUEST_HEADERS') protocol = 'http/1.1';
      else if (n === 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' && e.params && Array.isArray(e.params.headers)) headers = e.params.headers;
    }
    requests.push({ url: start.params.url, method: start.params.method, time: Number(start.time), protocol, headers });
  }
  requests.sort((a, b) => a.time - b.time);
  return requests;
}

function attachNetLog(samples, netlog) {
  if (!netlog) return;
  const used = new Set();
  for (const s of samples) {
    const i = netlog.findIndex((r, idx) => !used.has(idx) && r.url === s.url && r.method === s.method);
    if (i === -1) continue;
    used.add(i);
    const r = netlog[i];
    s.netProtocol = r.protocol;
    if (r.headers) {
      s.netStatus = Number((/^\S+\s+(\d{3})/.exec(r.headers[0] || '') || [])[1]) || null;
      s.netAcao = r.headers.some((hd) => /^access-control-allow-origin:/i.test(hd));
      s.netAltSvc = (r.headers.find((hd) => /^alt-svc:/i.test(hd)) || '').replace(/^alt-svc:\s*/i, '') || null;
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Runner                                                                   */
/* ------------------------------------------------------------------------ */

function buildTargets() {
  const list = RESOLVERS.map((r) => ({ id: r.id, url: r.url, of: r.id, resolver: r, candidate: false }));
  if (OPT.candidates) for (const c of CANDIDATES) list.push({ ...c, resolver: getResolver(c.of), candidate: true });
  return OPT.only ? list.filter((t) => OPT.only.has(t.id) || OPT.only.has(t.of)) : list;
}

async function runSession(browserName, session, server, targets) {
  const netlogDir = OPT.netlog ? await mkdtemp(path.join(tmpdir(), 'doh-netlog-')) : null;
  const netlogFile = netlogDir ? path.join(netlogDir, 'netlog.json') : null;
  const browser = await launchBrowser({
    browser: browserName,
    headless: !OPT.headed,
    args: netlogFile ? [`--log-net-log=${netlogFile}`, '--net-log-capture-mode=Default'] : []
  });
  const version = (await browser.version()).product;
  const samples = [];
  let breaker = null;
  try {
    const page = await browser.newPage('about:blank');
    const net = recordNetwork(page);
    await page.send('Network.enable');
    await page.goto(`${server.url}#/about`);
    await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000 });
    const usedNames = new Set();

    const one = async (target, form, rep, extra = {}) => {
      const spec = {
        form, url: target.url, jsonUrl: jsonUrlOf(target), name: randomCase(QNAME, usedNames), timeoutMs: OPT.timeoutMs, ...extra
      };
      const r = await page.evaluate(pageFetch, spec);
      const rec = await net.claim(r.url, r.method);
      const sample = {
        browser: browserName, version, session, rep, target: target.id, of: target.of, candidate: !!target.candidate,
        vantage: extra.vantage || null, form, ...r,
        cdpProtocol: rec ? rec.protocol || null : null,
        rawStatus: rec ? rec.rawStatus ?? null : null,
        cdpAcao: rec && rec.rawHeaders ? Object.keys(rec.rawHeaders).some((k) => k.toLowerCase() === 'access-control-allow-origin') : null,
        errorText: rec && rec.failed ? rec.failed.errorText : null,
        cors: rec && rec.failed ? rec.failed.cors : null,
        blockedReason: rec && rec.failed ? rec.failed.blockedReason : null,
        preflight: rec ? rec.preflight : null
      };
      samples.push(sample);
      return sample;
    };

    for (let rep = 1; rep <= OPT.reps; rep += 1) {
      process.stdout.write(`  ${browserName} session ${session} rep ${rep}: ${targets.length} endpoints × ${FORMS.length} forms`);
      await Promise.all(targets.map(async (t) => {
        for (const form of FORMS) await one(t, form, rep);
      }));
      if (OPT.vantages) {
        const geo = getResolver(DEFAULT_GEO_RESOLVER);
        const gt = { id: `${geo.id}+ecs`, of: geo.id, url: geo.url, candidate: false };
        process.stdout.write(` + ${GEO_VANTAGES.length} ECS vantages`);
        await mapLimit(GEO_VANTAGES, 4, (v) => one(gt, 'get', rep, { ecs: v.subnet, vantage: v.id }));
      }
      process.stdout.write('\n');
    }
    if (OPT.breaker && session === OPT.sessions) {
      process.stdout.write(`  ${browserName} session ${session}: circuit breaker / balance pool check\n`);
      breaker = await page.evaluate(pageBreakerCheck);
    }
  } finally {
    await browser.close();
  }
  if (netlogFile) {
    await sleep(300);
    attachNetLog(samples, await readNetLog(netlogFile));
    await rm(netlogDir, { recursive: true, force: true }).catch(() => {});
  }
  return { samples, breaker, version };
}

/* ------------------------------------------------------------------------ */
/* Report                                                                   */
/* ------------------------------------------------------------------------ */

const protoOf = (s) => s.netProtocol || s.cdpProtocol || '?';
function reasonOf(s) {
  if (s.ok) return 'ok';
  if (s.kind === 'timeout') return 'timeout';
  if (s.cors) return `cors:${s.cors}`;
  if (s.blockedReason) return `blocked:${s.blockedReason}`;
  if (s.kind === 'http') return `http-${s.status}`;
  if (s.kind === 'parse') return 'bad-body';
  return s.errorText ? s.errorText.replace(/^net::/, '') : 'network';
}
function histogram(list, fn) {
  const m = new Map();
  for (const x of list) {
    const k = fn(x);
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}
const fmtHist = (h) => h.map(([k, n]) => `${k}×${n}`).join(' ');

function cellText(list) {
  if (!list.length) return '—';
  const ok = list.filter((s) => s.ok).length;
  const protos = histogram(list, protoOf).map(([k, n]) => (n === list.length ? k : `${k}${n}`)).join('/');
  return `${ok}/${list.length} ${protos}`;
}

function printMatrix(browserName, samples, targets) {
  const w0 = Math.max(24, ...targets.map((t) => t.id.length + 2));
  const wc = 22;
  const pad = (s, n) => String(s).padEnd(n);
  process.stdout.write(`\n${browserName}: resolver × form → ok/n protocol(s)   (fresh = 1st request of a new profile, warm = later reps)\n`);
  process.stdout.write(`${pad('endpoint', w0)}${FORMS.map((f) => pad(f, wc)).join('')}fresh GET  warm GET\n`);
  for (const t of targets) {
    const rows = samples.filter((s) => s.target === t.id && !s.vantage);
    const get = rows.filter((s) => s.form === 'get');
    const fresh = get.filter((s) => s.rep === 1);
    const warm = get.filter((s) => s.rep > 1);
    const frac = (l) => `${l.filter((s) => s.ok).length}/${l.length}`;
    process.stdout.write(`${pad(t.id + (t.candidate ? '*' : ''), w0)}${FORMS.map((f) => pad(cellText(rows.filter((s) => s.form === f)), wc)).join('')}${pad(frac(fresh), 11)}${frac(warm)}\n`);
  }
  const failing = [];
  for (const t of targets) {
    for (const f of FORMS) {
      const rows = samples.filter((s) => s.target === t.id && s.form === f && !s.vantage);
      if (rows.length && rows.some((s) => !s.ok)) failing.push({ t, f, rows });
    }
  }
  if (failing.length) {
    process.stdout.write('\nFailures (reason×count · protocol×count · headers seen in NetLog):\n');
    for (const { t, f, rows } of failing) {
      const bad = rows.filter((s) => !s.ok);
      const acao = histogram(bad.filter((s) => s.netAcao !== undefined), (s) => (s.netAcao ? 'ACAO' : 'no-ACAO'));
      const pre = histogram(bad.filter((s) => s.preflight), (s) => `preflight:${s.preflight.status ?? (s.preflight.failed ? s.preflight.failed.errorText : '?')}`);
      process.stdout.write(`  ${t.id} ${f}: ${fmtHist(histogram(bad, reasonOf))} · ${fmtHist(histogram(bad, protoOf))}${acao.length ? ` · ${fmtHist(acao)}` : ''}${pre.length ? ` · ${fmtHist(pre)}` : ''}\n`);
    }
  }
  const vs = samples.filter((s) => s.vantage);
  if (vs.length) {
    process.stdout.write(`\nECS vantages on ${DEFAULT_GEO_RESOLVER} (GET wire): ${vs.filter((s) => s.ok).length}/${vs.length} ok · ${fmtHist(histogram(vs, protoOf))} · scope ${fmtHist(histogram(vs.filter((s) => s.ok), (s) => (s.scope === null ? 'none' : `/${s.scope}`)))}\n`);
    const badV = GEO_VANTAGES.filter((v) => vs.some((s) => s.vantage === v.id && !s.ok));
    for (const v of badV) {
      const l = vs.filter((s) => s.vantage === v.id);
      process.stdout.write(`  ${v.id} (${v.subnet}): ${cellText(l)} ${fmtHist(histogram(l.filter((s) => !s.ok), reasonOf))}\n`);
    }
    if (!badV.length) process.stdout.write(`  every one of the ${GEO_VANTAGES.length} vantages answered in every rep\n`);
  }
}

function printBreaker(browserName, b) {
  if (!b) return;
  process.stdout.write(`\n${browserName}: circuit breaker / balance pool (lib/doh.js in the page)\n`);
  const line = (label, r, extra) => process.stdout.write(`  ${label}: ${r.ok}/${r.queries} ok · p50 ${r.p50} ms · p95 ${r.p95} ms · max ${r.max} ms · >1 s: ${r.slowOver1s} · wall ${r.wallMs} ms · ${extra}\n`);
  line('A quad9 first in chain (40 q)', b.failingFirst, `quad9 attempts ${b.failingFirst.watchAttempts} · breaker open ${b.failingFirst.watchDown} · answered by ${JSON.stringify(b.failingFirst.answeredBy)}`);
  line('B default balance pool (60 q)', b.balance, `first tried ${JSON.stringify(b.balance.firstTried)} · quad9 attempts ${b.balance.watchAttempts}`);
  line('C black hole first, 2 s timeout (30 q)', b.blackhole, `black-hole attempts ${b.blackhole.watchAttempts} · breaker open ${b.blackhole.watchDown}`);
}

/** Failures that say nothing about the browser: the endpoint was not reachable from here. */
const isNetworkFailure = (s) => !s.ok && !s.cors && !s.blockedReason && (s.kind === 'timeout' || /CONNECTION|NAME_NOT_RESOLVED|ADDRESS_UNREACHABLE|TIMED_OUT/.test(s.errorText || ''));

/**
 * resolvers.js flags vs. what the browser did (GET wire = what lib/doh.js uses). CORS / HTTP
 * failures of a resolver flagged browserReliable:true are errors (exit 1); network failures
 * (timeouts, connection refused / timed out) are warnings — they depend on the test network.
 */
function verdicts(samples) {
  const problems = [];
  const warnings = [];
  const notes = [];
  for (const r of RESOLVERS) {
    const get = samples.filter((s) => s.target === r.id && s.form === 'get' && !s.vantage);
    if (!get.length) continue;
    const ok = get.filter((s) => s.ok).length;
    const bad = get.filter((s) => !s.ok);
    const browserBad = bad.filter((s) => !isNetworkFailure(s));
    const netBad = bad.filter(isNetworkFailure);
    if (r.browserReliable && browserBad.length) problems.push(`${r.id}: browserReliable:true but GET failed in the browser ${browserBad.length}/${get.length} (${fmtHist(histogram(browserBad, reasonOf))})`);
    if (r.browserReliable && netBad.length) {
      const all = netBad.length === get.length;
      warnings.push(`${r.id}: ${all ? 'unreachable from this network' : 'sporadic network failures'} — GET ${ok}/${get.length} (${fmtHist(histogram(netBad, reasonOf))})${all ? '; keep it out of DEFAULT_CHAIN and the balance pool' : ''}`);
    }
    if (!r.browserReliable && ok === get.length) problems.push(`${r.id}: browserReliable:false but GET answered ${ok}/${get.length} — flag may be stale`);
    if (!r.browserReliable && ok < get.length) notes.push(`${r.id}: confirmed unreadable in the browser (${ok}/${get.length} GET ok; ${fmtHist(histogram(bad, reasonOf))}; ${fmtHist(histogram(get, protoOf))})`);
  }
  for (const c of CANDIDATES) {
    const get = samples.filter((s) => s.target === c.id && s.form === 'get');
    if (!get.length) continue;
    const ok = get.filter((s) => s.ok).length;
    notes.push(`candidate ${c.id}: GET ${ok}/${get.length}${ok === get.length ? ' — WORKS (candidate replacement for ' + c.of + ')' : ` (${fmtHist(histogram(get.filter((s) => !s.ok), reasonOf))})`}`);
  }
  return { problems, warnings, notes };
}

async function main() {
  const targets = buildTargets();
  const server = await startServer({ port: 0 });
  process.stdout.write(`Serving ${server.url} — ${targets.length} endpoints, forms ${FORMS.join(', ')}, ${OPT.sessions} session(s) × ${OPT.reps} rep(s)${OPT.vantages ? `, ${GEO_VANTAGES.length} ECS vantages` : ''}\n`);
  const all = [];
  const breakers = {};
  const versions = {};
  try {
    for (const b of OPT.browsers) {
      for (let s = 1; s <= OPT.sessions; s += 1) {
        const { samples, breaker, version } = await runSession(b, s, server, targets);
        all.push(...samples);
        if (breaker) breakers[b] = breaker;
        versions[b] = version;
      }
    }
  } finally {
    await server.close();
  }
  for (const b of OPT.browsers) {
    process.stdout.write(`\n=== ${b} (${versions[b]}) ===`);
    printMatrix(b, all.filter((s) => s.browser === b), targets);
    printBreaker(b, breakers[b]);
  }
  const { problems, warnings, notes } = verdicts(all);
  process.stdout.write('\nVerdict\n');
  for (const n of notes) process.stdout.write(`  - ${n}\n`);
  for (const w of warnings) process.stdout.write(`  ~ ${w}\n`);
  for (const p of problems) process.stdout.write(`  ! ${p}\n`);
  if (!problems.length) process.stdout.write('  resolvers.js browserReliable flags match the browser\n');
  if (OPT.json) {
    writeReport(OPT.json, JSON.stringify({ date: new Date().toISOString(), options: { ...OPT, only: OPT.only ? [...OPT.only] : null }, versions, samples: all, breakers }, null, 1));
    process.stdout.write(`\nRaw samples written to ${OPT.json}\n`);
  }
  if (problems.length) process.exitCode = 1;
}

main().catch((err) => {
  process.stderr.write(`browser-doh-matrix crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});

