#!/usr/bin/env node
/**
 * LIVE (network) verification of assets/js/lib/resolvers.js. Not run by `npm test`.
 *
 *   node tests/live/verify-resolvers.mjs              # resolvers + geo vantages
 *   node tests/live/verify-resolvers.mjs --browser    # + real headless Chrome/Edge CORS check
 *   node tests/live/verify-resolvers.mjs --no-geo     # resolvers only
 *   node tests/live/verify-resolvers.mjs --no-resolvers --json out.json
 *
 * Resolvers (node:http2 — Quad9 requires HTTP/2 and Node's fetch is HTTP/1.1):
 *   - GET ?dns= with `Origin: https://example.github.io` → must be 200 + Access-Control-Allow-Origin
 *     + a decodable DNS message (otherwise the resolver must be DROPPED from RESOLVERS),
 *   - DNSSEC: AD on cloudflare.com, SERVFAIL on dnssec-failed.org,
 *   - filtering: malware.wicar.org / isitblocked.org (blocked by malware/security/family filters),
 *   - NSID support, ECS echo (scope) and whether client ECS changes the answer (www.wikipedia.org JP vs US).
 *   Observed properties are compared with the RESOLVERS metadata; mismatches are reported.
 * Browser (--browser): serves a page on http://127.0.0.1 and lets headless Chrome (or Edge)
 *   fetch every resolver — this is how the HTTP/3-without-CORS problem of Quad9 was found.
 * Geo vantages: RIPEstat maxmind-geo-lite country/city + prefix-overview origin ASN for every
 *   subnet (polite: concurrency 2), then Google DoH queries with each subnet as ECS source:
 *   echoed scope prefix and number of distinct answers for geo-aware names.
 *
 * Exit code 1 when a resolver fails the CORS/200 check, a vantage's country does not match,
 * or Google returns no ECS scope / no geo differences.
 */
import http2 from 'node:http2';
import http from 'node:http';
import tls from 'node:tls';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encodeQuery, decodeMessage, base64UrlEncode } from '../../assets/js/lib/dnswire.js';
import { RESOLVERS, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, getResolver } from '../../assets/js/lib/resolvers.js';

const args = process.argv.slice(2);
const OPT = {
  resolvers: !args.includes('--no-resolvers'),
  geo: !args.includes('--no-geo'),
  browser: args.includes('--browser'),
  json: args.includes('--json') ? args[args.indexOf('--json') + 1] : null
};
const ORIGIN = 'https://example.github.io';
// Test names blocked by malware/security/family filters (isitblocked.org is Quad9's own test name).
// Quad9 nodes do not all carry the same threat feeds, so a resolver counts as filtering when any is blocked.
const MALWARE_TESTS = ['malware.wicar.org', 'isitblocked.org'];
const GEO_NAMES = ['www.amazon.com', 'www.wikipedia.org'];
// Wikimedia maps clients deterministically per region: eqsin (Singapore) for Japan, 208.80.15x.x (US DCs) for the US.
const ECS_PROBE = { name: 'www.wikipedia.org', jp: '221.186.0.0/24', us: '71.178.64.0/24', jpAnswer: '103.102.166.224', usPrefix: '208.80.15' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// HTTP/2 DoH client
// ---------------------------------------------------------------------------
function caBundle() {
  try {
    // family.cloudflare-dns.com chains to Comodo "AAA Certificate Services", absent from Node's bundle.
    return [...tls.getCACertificates('default'), ...tls.getCACertificates('system')];
  } catch {
    return undefined;
  }
}

const sessions = new Map();
function session(origin) {
  let s = sessions.get(origin);
  if (s && !s.closed && !s.destroyed) return s;
  s = http2.connect(origin, { ca: caBundle() });
  s.on('error', () => {});
  sessions.set(origin, s);
  return s;
}

function h2get(url, headers = {}, timeoutMs = 12000) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    let req;
    try {
      req = session(u.origin).request({ ':method': 'GET', ':path': u.pathname + u.search, ...headers });
    } catch (err) {
      reject(err);
      return;
    }
    const chunks = [];
    let resHeaders = {};
    const timer = setTimeout(() => { req.close(); reject(new Error('timeout')); }, timeoutMs);
    req.on('response', (h) => { resHeaders = h; });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { clearTimeout(timer); resolve({ status: resHeaders[':status'], headers: resHeaders, body: Buffer.concat(chunks) }); });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

/** One DoH query; returns { status, acao, ms, msg|null, error|null }. */
async function doh(resolver, name, type, opts = {}) {
  const u = new URL(resolver.url);
  u.searchParams.set('dns', base64UrlEncode(encodeQuery(name, type, opts)));
  const t0 = performance.now();
  try {
    const res = await h2get(u.href, { accept: 'application/dns-message', origin: ORIGIN });
    const ms = Math.round(performance.now() - t0);
    let msg = null;
    let error = null;
    try {
      msg = decodeMessage(res.body);
    } catch (err) {
      error = `decode: ${err.message}`;
    }
    return { status: res.status, acao: res.headers['access-control-allow-origin'] || null, contentType: res.headers['content-type'], ms, msg, error };
  } catch (err) {
    return { status: 0, acao: null, ms: Math.round(performance.now() - t0), msg: null, error: err.message };
  }
}

const aValues = (msg) => (msg?.answers || []).filter((rr) => rr.type === 'A').map((rr) => rr.data).sort();
const blocked = (msg) => !!msg && (msg.rcodeName === 'NXDOMAIN' || msg.rcodeName === 'REFUSED' ||
  aValues(msg).some((ip) => ip === '0.0.0.0' || ip.startsWith('146.112.61.')) || msg.edns?.ede?.some((e) => e.code >= 15 && e.code <= 18));

// ---------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------
async function verifyResolver(r) {
  const out = { id: r.id, url: r.url, ok: false, problems: [], mismatches: [] };
  const basic = await doh(r, 'example.com', 'A', { nsid: true });
  out.status = basic.status;
  out.acao = basic.acao;
  out.latencyMs = basic.ms;
  if (basic.status !== 200) out.problems.push(`HTTP ${basic.status || basic.error}`);
  if (!basic.acao) out.problems.push('no Access-Control-Allow-Origin');
  if (!basic.msg) out.problems.push(basic.error || 'no DNS message');
  if (basic.msg && basic.msg.rcodeName !== 'NOERROR') out.problems.push(`rcode ${basic.msg.rcodeName}`);
  out.ok = out.problems.length === 0;
  if (!out.ok) return out;
  out.nsid = basic.msg.edns?.nsid || null;

  const signed = await doh(r, 'cloudflare.com', 'A'); // AD flag set in query by default
  const bogus = await doh(r, 'dnssec-failed.org', 'A');
  out.ad = !!signed.msg?.flags.ad;
  out.bogusRcode = bogus.msg?.rcodeName || bogus.error;
  out.bogusEde = bogus.msg?.edns?.ede?.map((e) => e.code) || [];
  const validating = out.ad && out.bogusRcode === 'SERVFAIL';

  out.malware = {};
  for (const name of MALWARE_TESTS) {
    const mal = await doh(r, name, 'A');
    out.malware[name] = mal.msg ? `${mal.msg.rcodeName} ${aValues(mal.msg).join(',')}${mal.msg.edns?.ede?.length ? ` EDE${mal.msg.edns.ede.map((e) => e.code).join(',')}` : ''}`.trim() : mal.error;
    if (blocked(mal.msg)) out.blocksMalware = true;
  }
  out.blocksMalware = !!out.blocksMalware;

  const eJp = await doh(r, ECS_PROBE.name, 'A', { ecs: ECS_PROBE.jp });
  const eUs = await doh(r, ECS_PROBE.name, 'A', { ecs: ECS_PROBE.us });
  out.ecsEcho = !!(eJp.msg?.edns?.ecs && eUs.msg?.edns?.ecs);
  out.ecsScope = eJp.msg?.edns?.ecs?.scopePrefix ?? null;
  out.ecsHonoured = aValues(eJp.msg).includes(ECS_PROBE.jpAnswer) && aValues(eUs.msg).some((ip) => ip.startsWith(ECS_PROBE.usPrefix));

  const cmp = (field, observed) => { if (r[field] !== observed) out.mismatches.push(`${field}: metadata ${r[field]} vs observed ${observed}`); };
  cmp('dnssecValidating', validating);
  cmp('ecs', out.ecsHonoured);
  cmp('ecsEcho', out.ecsEcho);
  cmp('nsid', !!out.nsid);
  if ((r.filtering !== null) !== out.blocksMalware) out.mismatches.push(`filtering: metadata ${r.filtering} vs blocks test names: ${JSON.stringify(out.malware)}`);
  return out;
}

// ---------------------------------------------------------------------------
// Real browser check (headless Chrome / Edge)
// ---------------------------------------------------------------------------
function findBrowser() {
  const candidates = [
    process.env.CHROME,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

async function browserCheck() {
  const exe = findBrowser();
  if (!exe) return { skipped: 'no Chrome/Edge found (set CHROME=...)' };
  const query = base64UrlEncode(encodeQuery('example.com', 'A'));
  const list = RESOLVERS.map((r) => ({ id: r.id, url: `${r.url}${r.url.includes('?') ? '&' : '?'}dns=${query}` }));
  const page = `<!doctype html><meta charset="utf-8"><pre id="out">pending</pre><script type="module">
const list = ${JSON.stringify(list)};
const lines = await Promise.all(list.map(async ({ id, url }) => {
  try {
    const r = await fetch(url, { headers: { accept: 'application/dns-message' } });
    const b = new Uint8Array(await r.arrayBuffer());
    return id + ' OK ' + r.status + ' ' + b.length + 'B';
  } catch (e) { return id + ' FAIL ' + e.message; }
}));
document.getElementById('out').textContent = lines.join('\\n');
</script>`;
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const profile = mkdtempSync(join(tmpdir(), 'dohcheck-'));
  try {
    const dom = await new Promise((resolve, reject) => {
      const p = spawn(exe, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        `--user-data-dir=${profile}`, '--virtual-time-budget=25000', '--dump-dom', `http://127.0.0.1:${port}/`]);
      let s = '';
      p.stdout.on('data', (d) => { s += d; });
      p.on('error', reject);
      const t = setTimeout(() => p.kill(), 90000);
      p.on('close', () => { clearTimeout(t); resolve(s); });
    });
    const text = (/<pre id="out">([\s\S]*?)<\/pre>/.exec(dom) || [])[1] || '';
    const results = {};
    for (const line of text.split('\n')) {
      const [id, verdict, ...rest] = line.trim().split(' ');
      if (id && verdict) results[id] = { ok: verdict === 'OK', detail: rest.join(' ') };
    }
    return { browser: exe, results };
  } finally {
    server.close();
    try { rmSync(profile, { recursive: true, force: true }); } catch { /* profile files may still be locked */ }
  }
}

// ---------------------------------------------------------------------------
// Geo vantages
// ---------------------------------------------------------------------------
async function ripe(call, resource) {
  const url = `https://stat.ripe.net/data/${call}/data.json?resource=${encodeURIComponent(resource)}&sourceapp=domainscope`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url);
      if (res.ok) return (await res.json()).data;
    } catch { /* retry */ }
    await sleep(1000 * (attempt + 1));
  }
  throw new Error(`RIPEstat ${call} ${resource} failed`);
}

async function verifyVantage(g) {
  const out = { id: g.id, subnet: g.subnet, problems: [] };
  const geo = await ripe('maxmind-geo-lite', g.subnet);
  const loc = geo.located_resources?.[0]?.locations?.[0] || {};
  out.country = loc.country || null;
  out.city = loc.city || null;
  if (out.country !== g.verifiedCountry) out.problems.push(`country ${out.country} != ${g.verifiedCountry}`);
  if (g.verifiedCity && out.city && out.city !== g.verifiedCity) out.cityNote = `city now ${out.city} (was ${g.verifiedCity})`;
  const po = await ripe('prefix-overview', g.subnet);
  out.asn = po.asns?.[0]?.asn ?? null;
  out.holder = po.asns?.[0]?.holder ?? null;
  if (out.asn !== g.asn) out.problems.push(`origin AS${out.asn} != AS${g.asn}`);
  return out;
}

async function geoDns(vantages) {
  const google = getResolver(DEFAULT_GEO_RESOLVER);
  const results = [];
  for (const g of vantages) {
    const row = { id: g.id, answers: {}, scopes: {} };
    for (const name of GEO_NAMES) {
      const r = await doh(google, name, 'A', { ecs: g.subnet });
      row.answers[name] = aValues(r.msg);
      row.scopes[name] = r.msg?.edns?.ecs?.scopePrefix ?? null;
    }
    results.push(row);
  }
  return results;
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: limit }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

// ---------------------------------------------------------------------------
async function main() {
  const report = { verifiedAt: new Date().toISOString() };
  let failed = false;

  if (OPT.resolvers) {
    console.log(`\n== Resolvers (${RESOLVERS.length}) — HTTP/2 GET ?dns= with Origin: ${ORIGIN}`);
    report.resolvers = await mapLimit(RESOLVERS, 4, verifyResolver);
    for (const r of report.resolvers) {
      const flags = r.ok
        ? `${r.latencyMs}ms ACAO=${r.acao} AD=${r.ad ? 1 : 0} bogus=${r.bogusRcode}${r.bogusEde.length ? `/EDE${r.bogusEde}` : ''} malware=${r.blocksMalware ? 'BLOCKED' : 'resolves'} ecsEcho=${r.ecsEcho ? `scope${r.ecsScope}` : 'no'} ecsHonoured=${r.ecsHonoured ? 'yes' : 'no'} nsid=${r.nsid ?? '-'}`
        : `FAIL: ${r.problems.join('; ')} → DROP from RESOLVERS`;
      console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.id.padEnd(18)} ${flags}`);
      for (const m of r.mismatches) console.log(`     ! metadata mismatch — ${m}`);
      if (!r.ok) failed = true;
    }
  }

  if (OPT.browser) {
    console.log('\n== Real browser fetch from http://127.0.0.1 (headless)');
    report.browser = await browserCheck();
    if (report.browser.skipped) console.log(`skipped: ${report.browser.skipped}`);
    else {
      console.log(`browser: ${report.browser.browser}`);
      for (const r of RESOLVERS) {
        const b = report.browser.results[r.id];
        const expected = r.browserReliable ? 'expected OK' : `known issue: ${r.issue}`;
        console.log(`${b?.ok ? 'OK  ' : 'FAIL'} ${r.id.padEnd(18)} ${b ? b.detail : 'no result'} (${expected})`);
      }
    }
  }

  if (OPT.geo) {
    console.log(`\n== Geo vantages (${GEO_VANTAGES.length}) — RIPEstat maxmind-geo-lite + prefix-overview`);
    report.vantages = await mapLimit(GEO_VANTAGES, 2, verifyVantage);
    for (const v of report.vantages) {
      console.log(`${v.problems.length ? 'FAIL' : 'PASS'} ${v.id.padEnd(11)} ${v.subnet.padEnd(18)} ${v.country}/${v.city || '-'} AS${v.asn} ${v.holder || ''}${v.cityNote ? `  (${v.cityNote})` : ''}${v.problems.length ? `  → ${v.problems.join('; ')}` : ''}`);
      if (v.problems.length) failed = true;
    }
    console.log(`\n== Google DoH (wire format, HTTP/2) with each vantage as ECS source: ${GEO_NAMES.join(', ')}`);
    report.geoDns = await geoDns(GEO_VANTAGES);
    for (const row of report.geoDns) {
      console.log(`${row.id.padEnd(11)} ${GEO_NAMES.map((n) => `${n}: ${(row.answers[n][0] || '-').padEnd(15)} scope ${row.scopes[n] ?? '-'}`).join('   ')}`);
    }
    report.geoSummary = {};
    for (const n of GEO_NAMES) {
      const distinct = new Set(report.geoDns.map((row) => row.answers[n].join(','))).size;
      const withScope = report.geoDns.filter((row) => row.scopes[n] > 0).length;
      report.geoSummary[n] = { distinctAnswers: distinct, vantagesWithScope: withScope };
      console.log(`${n}: ${distinct} distinct answer sets over ${GEO_VANTAGES.length} vantages; non-zero ECS scope for ${withScope}`);
    }
    const anyScope = Object.values(report.geoSummary).some((s) => s.vantagesWithScope > 0);
    const anyGeo = Object.values(report.geoSummary).some((s) => s.distinctAnswers > 1);
    if (!anyScope || !anyGeo) {
      console.log('FAIL: Google did not return an ECS scope / geo-specific answers');
      failed = true;
    }
  }

  for (const s of sessions.values()) s.close();
  if (OPT.json) writeFileSync(OPT.json, JSON.stringify(report, null, 2));
  console.log(`\n${failed ? 'FAILED' : 'ALL CHECKS PASSED'}`);
  process.exitCode = failed ? 1 : 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
