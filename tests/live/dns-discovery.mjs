#!/usr/bin/env node
/**
 * LIVE (network) smoke test of the DNS-first discovery engine:
 *   dnsmine.js (mineDnsNames) + wordlist.js (loadWordlist 'smart') +
 *   doh.js (balance mode + detectWildcardDeep) + permute.js (permutations).
 * Not run by `npm test`.
 *
 *   node tests/live/dns-discovery.mjs                 # first of targets.local.json, else github.com
 *   node tests/live/dns-discovery.mjs example.com --level smart --no-perms
 *   node tests/live/dns-discovery.mjs --pool cloudflare,google,dnssb
 *
 * Options:
 *   --level small|smart|large   wordlist level (default smart)
 *   --no-perms                  skip the permutation pass
 *   --concurrency N             DoH concurrency (default 24)
 *   --pool a,b,c                balance-mode resolver pool (default the client's
 *                               pool; e.g. cloudflare,google,dnssb to skip
 *                               resolvers that need HTTP/2 quirks Node lacks)
 *
 * Node's global fetch is HTTP/1.1 while dns.quad9.net needs HTTP/2, so DoH
 * requests go over node:http2 (like a browser) and everything else through
 * global fetch. Prints the names found (with evidence), the query rate (qps)
 * achieved by balance mode, and the wall-clock time. Exit code 1 if nothing
 * resolves.
 */
import http2 from 'node:http2';
import tls from 'node:tls';
import { DohClient, detectWildcardDeep, hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { loadWordlist } from '../../assets/js/lib/wordlist.js';
import { mineDnsNames } from '../../assets/js/lib/dnsmine.js';
import { permutations } from '../../assets/js/lib/permute.js';
import { sortHostnames } from '../../assets/js/lib/domain.js';
import { pickDomains, positionalArgs } from './targets.mjs';

const argv = process.argv.slice(2);
const opt = (name, fb) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fb;
};
/** Options that take a value: their value is never the domain. */
const VALUE_OPTS = ['--level', '--concurrency', '--pool'];
const DOMAIN = pickDomains(positionalArgs(argv, VALUE_OPTS), ['github.com'])[0];
const LEVEL = opt('--level', 'smart');
const DO_PERMS = !argv.includes('--no-perms');
const CONCURRENCY = Number(opt('--concurrency', '24')) || 24;
const ORIGIN = 'https://example.github.io';

/* ---- HTTP/2 fetchImpl for DoH ------------------------------------------ */
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
      headers = Object.fromEntries(Object.entries(h).filter(([k]) => !k.startsWith(':')).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)]));
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
async function fetchImpl(url, init = {}) {
  const u = new URL(url);
  if (DOH_ORIGINS.has(u.origin)) return h2fetch(url, init);
  return fetch(url, init);
}

/* ---- run --------------------------------------------------------------- */
const t0 = Date.now();
const secs = () => ((Date.now() - t0) / 1000).toFixed(1);
const log = (...a) => console.log(`[${secs()}s]`, ...a);

async function resolveBatch(dns, names, wildcard) {
  const hits = [];
  const wildV4 = wildcard && wildcard.kind === 'A' ? [...wildcard.ipv4].sort().join(',') : null;
  await Promise.all(names.map(async (name) => {
    // A-only via balance mode (the spec's bulk path): one query per candidate.
    const res = await dns.query(name, 'A', { balance: true });
    const r = hostResolutionFrom(name, res, null);
    if (r.status !== 'NOERROR') return;
    if (!r.ipv4.length && !r.cnames.length) return;
    if (wildV4 && [...r.ipv4].sort().join(',') === wildV4 && !r.cnames.length) return; // wildcard look-alike
    hits.push({ name, ipv4: r.ipv4, ipv6: [], cnames: r.cnames });
  }));
  return hits;
}

async function main() {
  console.log(`\nDNS-first discovery — ${DOMAIN} (level=${LEVEL}, concurrency=${CONCURRENCY})\n${'='.repeat(64)}`);
  const poolOpt = opt('--pool', '');
  const clientOpts = { fetchImpl, concurrency: CONCURRENCY, timeoutMs: 6000 };
  if (poolOpt) clientOpts.balancePool = poolOpt.split(',');
  const dns = new DohClient(clientOpts);

  // 1. wildcard baseline
  const wildcard = await detectWildcardDeep(dns, DOMAIN);
  log('wildcard:', wildcard.wildcard ? `${wildcard.kind} ${JSON.stringify(wildcard.ipv4 || wildcard.cnames)}` : 'none');

  // 2. mine the zone's own records
  const mined = await mineDnsNames(DOMAIN, { dns, resolvePtr: false });
  log(`mineDnsNames: ${mined.names.length} in-domain names, ${mined.externalRefs.length} external refs`);
  const byFrom = {};
  for (const e of mined.evidence) byFrom[e.from] = (byFrom[e.from] || 0) + 1;
  log('  evidence by source:', JSON.stringify(byFrom));

  // 3. smart wordlist, resolved A/AAAA via balance mode
  const words = await loadWordlist(LEVEL, { fetchImpl });
  const candidates = words.map((w) => `${w}.${DOMAIN}`);
  log(`wordlist '${LEVEL}': ${candidates.length} candidates — resolving via balance mode…`);
  const startBulk = Date.now();
  const q0 = dns.stats().queries;
  const wordHits = await resolveBatch(dns, candidates, wildcard);
  const minedHits = await resolveBatch(dns, mined.names, wildcard);
  const bulkQueries = dns.stats().queries - q0;
  const bulkSecs = (Date.now() - startBulk) / 1000;
  const qps = Math.round(bulkQueries / Math.max(bulkSecs, 0.001));

  // 4. permutations from everything found so far
  const foundSoFar = sortHostnames([...new Set([...minedHits, ...wordHits].map((h) => h.name))]);
  let permHits = [];
  if (DO_PERMS && foundSoFar.length) {
    const perms = permutations(foundSoFar, DOMAIN, { budget: 1500 });
    log(`permutations: ${perms.length} candidates from ${foundSoFar.length} found names — resolving…`);
    permHits = await resolveBatch(dns, perms, wildcard);
  }

  // 5. report
  const all = new Map();
  for (const h of [...minedHits, ...wordHits, ...permHits]) if (!all.has(h.name)) all.set(h.name, h);
  const names = sortHostnames([...all.keys()]);
  console.log(`\n${'='.repeat(64)}\nFOUND ${names.length} live hosts under ${DOMAIN}:\n`);
  for (const name of names) {
    const h = all.get(name);
    const target = h.ipv4.concat(h.ipv6).join(', ') || (h.cnames.length ? `CNAME ${h.cnames[h.cnames.length - 1]}` : '');
    console.log(`  ${name.padEnd(40)} ${target}`);
  }
  const st = dns.stats();
  console.log(`\n${'='.repeat(64)}`);
  console.log(`mined:       ${minedHits.length} live / ${mined.names.length} names`);
  console.log(`wordlist:    ${wordHits.length} live / ${candidates.length} candidates`);
  console.log(`permutation: ${permHits.length} live`);
  console.log(`total unique live hosts: ${names.length}`);
  console.log(`balance-mode bulk: ${bulkQueries} queries in ${bulkSecs.toFixed(1)}s → ${qps} qps`);
  console.log(`DoH requests: ${st.requests}, cache hits: ${st.cacheHits}, total time: ${secs()}s`);
  console.log('per-resolver:', Object.fromEntries(Object.entries(st.byResolver).map(([id, s]) => [id, `${s.ok}ok/${s.fail}fail${s.down ? ' DOWN' : ''}`])));

  for (const s of sessions.values()) { try { s.close(); } catch { /* ignore */ } }
  process.exitCode = names.length ? 0 : 1;
}

main().catch((err) => { console.error('FATAL', err); process.exitCode = 1; });
