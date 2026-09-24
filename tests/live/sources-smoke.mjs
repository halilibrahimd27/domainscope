#!/usr/bin/env node
/**
 * LIVE (network) smoke test of the passive sources (lib/sources.js): prints
 * per-source results, retries / pages as they happen, and the
 * sourceHealthSummary() table for each domain. Not run by `npm test`.
 *
 *   node tests/live/sources-smoke.mjs                         # targets.local.json, else github.com cloudflare.com
 *   node tests/live/sources-smoke.mjs example.com --sources crtsh,thc
 *   node tests/live/sources-smoke.mjs example.com --node --json tests/live/private/sources.json
 *
 * Options:
 *   --sources a,b,c      (default: every defaultEnabled source)
 *   --include-expired    crt.sh: ask for the full history first
 *   --node               raw Node fetch (default: browser emulation, see below)
 *   --no-probe           skip the raw crt.sh status probe printed first
 *   --json FILE          write every SourceResult + health list as JSON (it lists every name found,
 *                        so inside the repository only a gitignored path is accepted, e.g.
 *                        tests/live/private/…; see targets.mjs reportPath)
 *
 * Browser emulation (default): every request carries
 * `Origin: https://example.github.io`; a response without a matching
 * Access-Control-Allow-Origin becomes `TypeError: Failed to fetch` (exactly
 * what a browser reports for crt.sh's CORS-less 502 pages), and only
 * CORS-safelisted / exposed response headers stay readable (so e.g. Cert
 * Spotter's X-RateLimit-* and Retry-After are hidden, as in a browser).
 *
 * Domains run one after another (polite to the free services). Exit code 1
 * when no source answered for any domain.
 */
import { SOURCES, fetchAllSources } from '../../assets/js/lib/sources.js';
import { pickDomains, reportPathOrExit, writeReport } from './targets.mjs';

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const option = (name, fallback = null) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};
const optionNames = new Set(['--sources', '--json']);
const positional = argv.filter((a, i) => !a.startsWith('--') && !optionNames.has(argv[i - 1]));
const domains = pickDomains(positional, ['github.com', 'cloudflare.com']);
const JSON_OUT = reportPathOrExit(option('--json'));
const sourceIds = option('--sources') ? option('--sources').split(',').map((s) => s.trim()).filter(Boolean) : undefined;
const browserLike = !flag('--node');

/* ------------------------------------------------------------------------ */
/* Browser-like fetch                                                       */
/* ------------------------------------------------------------------------ */

const ORIGIN = 'https://example.github.io';
const SAFELISTED = new Set(['cache-control', 'content-language', 'content-length', 'content-type', 'expires', 'last-modified', 'pragma']);

async function browserFetch(url, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set('origin', ORIGIN);
  const res = await fetch(url, { ...init, headers });
  const acao = res.headers.get('access-control-allow-origin');
  if (acao !== '*' && acao !== ORIGIN) {
    try { await res.body?.cancel(); } catch { /* ignore */ }
    throw new TypeError(`Failed to fetch (HTTP ${res.status} without Access-Control-Allow-Origin)`);
  }
  const exposed = new Set((res.headers.get('access-control-expose-headers') || '')
    .toLowerCase().split(',').map((s) => s.trim()).filter(Boolean));
  const visible = new Headers();
  for (const [k, v] of res.headers) if (SAFELISTED.has(k) || exposed.has(k) || exposed.has('*')) visible.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: visible });
}

const fetchImpl = browserLike ? browserFetch : globalThis.fetch;

/* ------------------------------------------------------------------------ */
/* Output helpers                                                           */
/* ------------------------------------------------------------------------ */

const t0 = Date.now();
const stamp = () => `${String(((Date.now() - t0) / 1000).toFixed(1)).padStart(6)}s`;
const pad = (s, n) => String(s).padEnd(n).slice(0, n);
const secs = (ms) => `${(ms / 1000).toFixed(1)}s`;

/** One raw request per crt.sh query form, to record what crt.sh returns right now. */
async function probeCrtsh(domain) {
  const forms = {
    subdomains: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired&deduplicate=Y`,
    identity: `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired&deduplicate=Y`
  };
  for (const [form, url] of Object.entries(forms)) {
    const started = Date.now();
    try {
      const res = await fetch(url, { headers: { origin: ORIGIN, accept: 'application/json' }, signal: AbortSignal.timeout(90000) });
      const body = await res.text();
      const acao = res.headers.get('access-control-allow-origin');
      let rows = '';
      try { const j = JSON.parse(body); if (Array.isArray(j)) rows = `, ${j.length} rows`; } catch { /* not JSON */ }
      console.log(`  crt.sh ${pad(form, 10)} HTTP ${res.status}  ACAO=${acao ?? '(none)'}  ${secs(Date.now() - started)}${rows}`
        + `${res.ok ? '' : `  body="${body.replace(/\s+/g, ' ').trim().slice(0, 60)}"`}`);
    } catch (err) {
      console.log(`  crt.sh ${pad(form, 10)} ${err.name}: ${err.message}  ${secs(Date.now() - started)}`);
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Run                                                                      */
/* ------------------------------------------------------------------------ */

console.log(`sources smoke — ${browserLike ? `browser emulation (Origin ${ORIGIN})` : 'raw Node fetch'}; `
  + `sources: ${(sourceIds || SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id)).join(', ')}`);
if (!flag('--no-probe') && (!sourceIds || sourceIds.includes('crtsh'))) {
  console.log(`\n[${new Date().toISOString()}] raw crt.sh probe (${domains[0]}):`);
  await probeCrtsh(domains[0]);
}

const report = [];
let anyOk = false;
for (const domain of domains) {
  console.log(`\n=== ${domain} ===`);
  const out = await fetchAllSources(domain, {
    sources: sourceIds,
    fetchImpl,
    includeExpired: flag('--include-expired'),
    onEvent: (e) => {
      if (e.type === 'retry') {
        console.log(`${stamp()}  ${pad(e.source, 12)} retry ${e.attempt}/${e.maxAttempts}${e.form ? ` (${e.form})` : ''} in ${secs(e.delayMs)} after ${e.reason}`);
      } else if (e.type === 'page') {
        console.log(`${stamp()}  ${pad(e.source, 12)} page ${e.page}/${e.maxPages} in ${secs(e.delayMs)}${e.available !== null ? ` (${e.available} records)` : ''}`);
      }
    },
    onResult: (r) => {
      const status = r.ok ? (r.partial ? 'PARTIAL' : 'ok') : `FAIL:${r.errorKind}`;
      console.log(`${stamp()}  ${pad(r.source, 12)} ${pad(status, 18)} names=${pad(r.names.length, 5)} ips=${pad(r.ipHints.length, 4)} `
        + `certs=${pad(r.certs.length, 4)} req=${pad(r.attempts, 3)} ${secs(r.elapsedMs)}`
        + `${r.queryForm ? ` form=${r.queryForm}` : ''}${r.available !== null ? ` available=${r.available}` : ''}${r.truncated ? ' TRUNCATED' : ''}`);
      if (r.error) console.log(`${' '.repeat(22)}error: ${r.error}`);
      if (r.quota) console.log(`${' '.repeat(22)}quota: ${JSON.stringify(r.quota)}`);
    }
  });
  console.log('\n  health summary:');
  for (const s of out.health) {
    console.log(`    ${pad(s.name, 15)} ${pad(s.state, 13)} ${s.message}${s.fallback ? `  [fallback: ${s.fallback}]` : ''}`);
    if (s.ok) anyOk = true;
  }
  const names = [...out.names.keys()];
  console.log(`\n  ${names.length} unique names; wildcard bases: ${out.wildcardBases.join(', ') || '(none)'}`);
  console.log(`  sample: ${names.slice(0, 15).join(' ')}${names.length > 15 ? ' …' : ''}`);
  const seen = Object.entries(out.lastSeen);
  if (seen.length) console.log(`  lastSeen (first 5): ${seen.slice(0, 5).map(([n, d]) => `${n}=${d}`).join(' ')}`);
  report.push({ domain, results: out.results, health: out.health, names, wildcardBases: out.wildcardBases, lastSeen: out.lastSeen });
}

if (JSON_OUT) {
  writeReport(JSON_OUT, JSON.stringify(report, null, 2));
  console.log(`\nwrote ${JSON_OUT}`);
}
console.log(`\ndone in ${secs(Date.now() - t0)}`);
process.exitCode = anyOk ? 0 : 1;
