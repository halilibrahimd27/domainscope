#!/usr/bin/env node
/**
 * LIVE (network) smoke test of assets/js/lib/globalping.js against the real Globalping API.
 * Manual only: not run by `npm test` or CI. It spends real probes from the anonymous hourly quota
 * (250 per egress IP per hour, shared with every tool behind the same address).
 *
 *   node tests/live/globalping-smoke.mjs --dry             # free checks only: /limits + refused POSTs (0 probes)
 *   node tests/live/globalping-smoke.mjs                   # the full smoke: 9 probes (default --budget 10)
 *   node tests/live/globalping-smoke.mjs --only 3,7        # a subset of the checks (0–2 are free)
 *   node tests/live/globalping-smoke.mjs --capture --budget 23   # re-record tests/fixtures/globalping (23 probes)
 *
 * Targets are hard-coded public test targets, never your own (--capture adds two that reach no
 * public address, see below): GitHub, the badssl.com test family (its address is resolved at run time
 * through dns.google and never printed or written as such), Cloudflare and scanme.nmap.org (Nmap's
 * sanctioned scan target). Each badssl.com check is pinned to a probe location that got that
 * host's certificate in a saved run (BADSSL_FROM): that small server resets or drops some probe
 * networks now and then; the other checks use any probe. Every Globalping measurement stays public
 * by id for about six months, so:
 * - the script never imports tests/live/targets.mjs; it reads tests/live/targets.local.json and
 *   .private-denylist only to REFUSE a request that matches them, and never prints what matched;
 * - private / reserved addresses appear only in the free validation checks, which the API refuses
 *   with a 400 before anything is created — except in --capture, which deliberately records two
 *   charged-failure fixtures: m21 (localtest.me, a public name that resolves to 127.0.0.1) and m25
 *   (3fff::1, the IPv6 documentation prefix, which the API accepts and charges);
 * - port 0 is never sent (the API accepts it and charges a probe).
 *
 * Verdicts are computed twice: by a minimal classifier in this file (fingerprint identity, SAN / CN
 * coverage, the tls.error code, the failure text), and — informational only — by
 * assets/js/lib/verify.js when that module exists.
 *
 * Exit code: 0 all green, 1 an expectation failed, 2 refused to run (budget, quota, privacy guard).
 */
import tls from 'node:tls';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  createGlobalping, httpsCheckRequest, isProbeableIP, isProbeableHost, GlobalpingError, GLOBALPING_API
} from '../../assets/js/lib/globalping.js';
import { parseCertificate, computeFingerprints } from '../../assets/js/lib/x509.js';
import { normalizeIP } from '../../assets/js/lib/netinfo.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DENYLIST_FILE = join(ROOT, '.private-denylist');
const LOCAL_TARGETS_FILE = join(ROOT, 'tests', 'live', 'targets.local.json');
const FIXTURE_DIR = join(ROOT, 'tests', 'fixtures', 'globalping');
const MIN_REMAINING = 25;
const CAPTURE_COST = 23;

const GITHUB_IP = '140.82.121.4'; // GitHub (hygiene WELL_KNOWN 140.82.112.0/20)
const CLOUDFLARE_IP = '104.16.124.96'; // www.cloudflare.com anycast
const SCANME_IP = '45.33.32.156'; // scanme.nmap.org
const OTHER_SHA = '0'.repeat(64);
/**
 * Where each badssl.com check runs from. badssl.com is one small server that intermittently resets
 * or drops some probe networks, per host and per day: live 2026-09-24 it reset Tokyo AS3258 and
 * Sydney AS31898 and dropped Lagos AS214354, while it served Hetzner DE, OVH FR, TR, AT and BR probes;
 * on 2026-09-23 a Hetzner DE (Falkenstein AS24940) probe reset expired.badssl.com twice. So no single
 * pin fits every host; each one is a location that got that host's certificate in a saved run:
 * - wrong.host.badssl.com: DE — research m02 (2026-09-24, DE Falkenstein AS24940);
 * - expired.badssl.com: OVH AS16276 — research m03 (2026-09-24, FR Roubaix); not DE (the resets above);
 * - incomplete-chain.badssl.com: DE — research m06 and smoke #6 (2026-09-24, DE AS24940).
 * `{ country: 'DE' }` has landed on AS24940 every time so far. All three pinned checks passed live on
 * 2026-09-24 (#6 alone, then #4 + #5; docs/RESEARCH.md › Globalping facts).
 */
const BADSSL_FROM = Object.freeze({
  'wrong.host.badssl.com': Object.freeze([{ country: 'DE' }]),
  'expired.badssl.com': Object.freeze([{ asn: 16276 }]),
  'incomplete-chain.badssl.com': Object.freeze([{ country: 'DE' }])
});

/* ------------------------------------------------------------------------ */
/* Fixture trim / scrub (shared with --capture; documented in the README)   */
/* ------------------------------------------------------------------------ */

const KEEP_POST_HEADER = /^(?:x-ratelimit-[a-z]+|x-request-cost|retry-after)$/;

/** Probe metadata for a fixture: no coordinates, resolvers or state; `u-<user>` → `u-probe`. */
export function trimProbe(p) {
  if (!p || typeof p !== 'object') return p ?? null;
  const tags = Array.isArray(p.tags) ? p.tags : [];
  const out = tags.filter((t) => t === 'datacenter-network' || t === 'eyeball-network');
  if (tags.some((t) => typeof t === 'string' && t.startsWith('u-'))) out.push('u-probe');
  return {
    continent: p.continent ?? null, region: p.region ?? null, country: p.country ?? null,
    city: p.city ?? null, asn: p.asn ?? null, network: p.network ?? null, tags: out
  };
}

/** A test result for a fixture: no response headers / body; rawOutput only for failures (≤ 300). */
export function trimResult(r, { keepPublicKey = false } = {}) {
  if (!r || typeof r !== 'object') return r ?? null;
  const out = { status: r.status };
  if ('failureSource' in r) out.failureSource = r.failureSource;
  if ('resolvedAddress' in r) out.resolvedAddress = r.resolvedAddress;
  if (r.status === 'failed' && typeof r.rawOutput === 'string') out.rawOutput = r.rawOutput.slice(0, 300);
  for (const k of ['truncated', 'statusCode', 'statusCodeName', 'timings']) if (k in r) out[k] = r[k];
  if ('tls' in r) {
    if (r.tls && typeof r.tls === 'object') {
      const { publicKey, ...rest } = r.tls;
      out.tls = keepPublicKey && publicKey !== undefined ? { ...rest, publicKey } : rest;
    } else {
      out.tls = r.tls ?? null;
    }
  }
  return out;
}

/** A measurement for a fixture: every top-level field, results trimmed. */
export function trimMeasurement(m, opts = {}) {
  if (!m || typeof m !== 'object') return m ?? null;
  const out = {};
  for (const [k, v] of Object.entries(m)) {
    out[k] = k === 'results' && Array.isArray(v)
      ? v.map((t) => ({ probe: trimProbe(t?.probe), result: trimResult(t?.result, opts) }))
      : v;
  }
  return out;
}

/** The committed fixture shape (tests/fixtures/globalping/README.md). */
export function buildFixture({ name, capturedAt, reconstructed, request, post, inProgress, final }, opts = {}) {
  const fx = { name, capturedAt };
  if (reconstructed) fx.reconstructed = reconstructed;
  fx.request = request;
  if (post) {
    const headers = {};
    for (const [k, v] of Object.entries(post.headers || {})) if (KEEP_POST_HEADER.test(k.toLowerCase())) headers[k.toLowerCase()] = v;
    fx.post = { status: post.status, headers, body: post.body ?? null };
  }
  if (inProgress) fx.inProgress = trimMeasurement(inProgress, opts);
  if (final) {
    const f = { status: final.status };
    const ra = final.headers && (final.headers['retry-after'] ?? final.headers['Retry-After']);
    if (ra !== undefined) f.headers = { 'retry-after': ra };
    f.body = trimMeasurement(final.body, opts);
    fx.final = f;
  }
  return fx;
}

/** Replace exact IP literals (not digits of a longer number) in serialized text. */
export function scrubText(text, map) {
  let out = text;
  for (const [from, to] of map) {
    const esc = from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(`(?<![\\d.])${esc}(?![\\d])`, 'g'), to);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Privacy guard                                                            */
/* ------------------------------------------------------------------------ */

/** ERE (grep -E) → JS RegExp, case-insensitive; the same conversion as tests/js/repo-hygiene.test.js. */
function ereToRegExp(pattern) {
  const js = pattern
    .replace(/\[\[:digit:\]\]/g, '[0-9]').replace(/\[\[:alpha:\]\]/g, '[A-Za-z]')
    .replace(/\[\[:alnum:\]\]/g, '[A-Za-z0-9]').replace(/\[\[:space:\]\]/g, '\\s');
  return new RegExp(js, 'i');
}

/** Patterns a request must never match. Read only to refuse; never printed. */
function loadRefusals() {
  const res = [];
  if (existsSync(DENYLIST_FILE)) {
    for (const line of readFileSync(DENYLIST_FILE, 'utf8').split(/\r?\n/)) {
      const p = line.trim();
      if (!p || p.startsWith('#')) continue;
      try {
        res.push(ereToRegExp(p));
      } catch {
        refuse('a .private-denylist pattern is not a valid regular expression');
      }
    }
  }
  if (existsSync(LOCAL_TARGETS_FILE)) {
    let data = {};
    try { data = JSON.parse(readFileSync(LOCAL_TARGETS_FILE, 'utf8')); } catch { refuse('tests/live/targets.local.json is unreadable'); }
    const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const d of Array.isArray(data.domains) ? data.domains : []) {
      if (typeof d === 'string' && d) res.push(new RegExp(`(?<![\\w-])${esc(d)}(?![\\w-])`, 'i'));
    }
    const origins = data.originTruth && typeof data.originTruth === 'object' ? Object.values(data.originTruth) : [];
    for (const ip of origins) {
      const n = normalizeIP(String(ip));
      if (!n) continue;
      const v4 = /^(\d+\.\d+\.\d+)\.\d+$/.exec(n);
      res.push(v4 ? new RegExp(`(?<![\\d.])${esc(v4[1])}\\.\\d{1,3}(?![\\d])`) : new RegExp(esc(n), 'i'));
    }
  }
  return res;
}

let REFUSALS = [];

function refuse(why) {
  console.error(`REFUSED: ${why}. Nothing (more) was sent.`);
  process.exit(2);
}

/** Abort before sending anything that matches a private pattern (details deliberately not printed). */
function guard(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (REFUSALS.some((re) => re.test(text))) refuse('a request matches .private-denylist / targets.local.json (details not printed)');
}

/* ------------------------------------------------------------------------ */
/* Output masking (the badssl.com address is never printed)                 */
/* ------------------------------------------------------------------------ */

const MASKS = [];
const mask = (s) => MASKS.reduce((acc, [ip, label]) => acc.split(ip).join(label), String(s));
const log = (...a) => console.log(mask(a.join(' ')));

/* ------------------------------------------------------------------------ */
/* Ground truth                                                             */
/* ------------------------------------------------------------------------ */

async function resolveA(name) {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(`dns.google HTTP ${res.status} for ${name}`);
  const json = await res.json();
  const ip = (json.Answer || []).filter((a) => a.type === 1).map((a) => a.data)[0];
  if (!ip || !isProbeableIP(ip)) throw new Error(`${name} has no public A record`);
  guard(ip);
  if (!MASKS.some(([m]) => m === ip)) MASKS.push([ip, '<badssl-ip>']);
  return ip;
}

/** The leaf a local TLS client gets for (ip, servername): parsed with x509.js. */
export function localLeaf(ip, servername) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: ip, port: 443, servername, rejectUnauthorized: false, timeout: 10000 }, async () => {
      try {
        const raw = socket.getPeerCertificate(false)?.raw;
        socket.end();
        if (!raw) throw new Error('no peer certificate');
        const der = new Uint8Array(raw);
        const cert = parseCertificate(der);
        const { sha256 } = await computeFingerprints(der);
        resolve({ cert, sha256, spkiHex: Buffer.from(cert.spkiDer).toString('hex') });
      } catch (err) {
        reject(err);
      }
    });
    socket.on('timeout', () => { socket.destroy(); reject(new Error(`local TLS connect to ${servername} timed out`)); });
    socket.on('error', reject);
  });
}

/* ------------------------------------------------------------------------ */
/* Minimal classifier (the CLI's six verdicts; verify.js is the real one)   */
/* ------------------------------------------------------------------------ */

const hexKey = (s) => String(s ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();
const ALT_RE = /(?:^|,\s*)(DNS|IP Address|email|URI|DirName|Registered ID|othername):("(?:[^"\\]|\\.)*"|[^,]*)/g;
const CHAIN_ERRORS = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT']);

function covers(tlsInfo, name) {
  const dns = [];
  for (const m of String(tlsInfo.subject?.alt ?? '').matchAll(ALT_RE)) {
    if (m[1] !== 'DNS') continue;
    let v = m[2];
    if (v.startsWith('"')) { try { v = JSON.parse(v); } catch { /* keep raw */ } }
    dns.push(v.trim().toLowerCase().replace(/\.$/, ''));
  }
  const cn = String(tlsInfo.subject?.CN ?? '').toLowerCase();
  const names = dns.length ? dns : (cn ? [cn] : []);
  return names.some((n) => n === name || (n.startsWith('*.') && name.split('.').slice(1).join('.') === n.slice(2) && name.split('.').length === n.split('.').length));
}

export function localVerdict(test, { name, sha256, now }) {
  const r = test?.result || {};
  const t = r.tls;
  if (t && t.fingerprint256) {
    const warnings = [];
    if (CHAIN_ERRORS.has(t.error)) warnings.push('chain-incomplete');
    if (t.error === 'CERT_HAS_EXPIRED' || Date.parse(t.expiresAt) < now) warnings.push('expired');
    if (!covers(t, name)) return { status: 'NOT_HOSTED', reason: 'not-covered', warnings };
    if (sha256 && hexKey(t.fingerprint256) === sha256) return { status: 'UPDATED', reason: 'new-cert', warnings };
    return { status: 'NEEDS_UPDATE', reason: sha256 ? 'old-cert' : 'no-new-cert', warnings };
  }
  const text = String(r.rawOutput ?? '');
  const alert = /alert number (\d+)/.exec(text);
  if (/ECONNREFUSED/.test(text)) return { status: 'CLOSED', reason: 'refused', warnings: [] };
  if (/EHOSTUNREACH|ENETUNREACH/.test(text)) return { status: 'CLOSED', reason: 'unreachable', warnings: [] };
  if (/timed out while establishing the TCP connection/i.test(text)) return { status: 'TIMEOUT', reason: 'connect-timeout', warnings: [] };
  if (/timed out/i.test(text)) return { status: 'TIMEOUT', reason: 'tls-timeout', warnings: [] };
  if (alert && alert[1] === '112') return { status: 'NOT_HOSTED', reason: 'unrecognized-name', warnings: [] };
  if (alert && alert[1] === '40') return { status: 'TLS_ERROR', reason: 'sni-refused', warnings: [] };
  if (alert) return { status: 'TLS_ERROR', reason: 'tls-alert', warnings: [] };
  if (/wrong version number|packet length too long|unknown protocol/i.test(text)) return { status: 'TLS_ERROR', reason: 'not-tls', warnings: [] };
  if (/ECONNRESET|socket hang up|EPIPE/i.test(text)) return { status: 'TLS_ERROR', reason: 'reset', warnings: [] };
  return { status: 'TLS_ERROR', reason: 'tls-failed', warnings: [] };
}

/** verify.js cross-check (informational): its status for the same test, or null when unavailable. */
let verifyLib;
async function verifyJsStatus(test, { name, cert, now }) {
  if (verifyLib === undefined) {
    const p = join(ROOT, 'assets', 'js', 'lib', 'verify.js');
    verifyLib = null;
    if (existsSync(p)) {
      try { verifyLib = await import(pathToFileURL(p).href); } catch { verifyLib = null; }
    }
  }
  if (!verifyLib || typeof verifyLib.classifyTest !== 'function') return null;
  try {
    const expect = cert && typeof verifyLib.expectationFor === 'function'
      ? await verifyLib.expectationFor(cert)
      : { sha256: [OTHER_SHA], spkiHex: [], hostnames: [], subjectCN: null, notAfter: null };
    return verifyLib.classifyTest(test, { name, expect, now })?.status ?? null;
  } catch (err) {
    return `error: ${err?.message ?? err}`;
  }
}

/* ------------------------------------------------------------------------ */
/* Client with a request log                                                */
/* ------------------------------------------------------------------------ */

const requests = []; // { method, url, status, at, remaining }

async function recordingFetch(url, init = {}) {
  const at = Date.now();
  const method = init.method || 'GET';
  if (method === 'POST') guard(init.body);
  const entry = { method, url: String(url), at, status: null, remaining: null };
  requests.push(entry);
  const res = await fetch(url, init);
  entry.status = res.status;
  entry.remaining = res.headers.get('x-ratelimit-remaining');
  return res;
}

const client = createGlobalping({ fetchImpl: recordingFetch });

/* ------------------------------------------------------------------------ */
/* Checks                                                                   */
/* ------------------------------------------------------------------------ */

const results = []; // { id, title, ok, detail, cost }
let spent = 0;
let budget = 10;

function record(id, title, ok, detail, cost = 0) {
  results.push({ id, title, ok, detail, cost });
  log(`${ok ? 'PASS' : 'FAIL'}  #${id} ${title}${detail ? ` — ${detail}` : ''}${cost ? ` [${cost} probe${cost > 1 ? 's' : ''}]` : ''}`);
}

const rawBody = (target, host, extra = {}) => ({
  type: 'http', target, limit: 1, timeout: 10,
  measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', host, path: '/' } }, ...extra
});

async function expectRefused(body, code) {
  try {
    const c = await client.create(body);
    spent += c.cost;
    return `unexpectedly accepted (id ${c.id}, cost ${c.cost})`;
  } catch (err) {
    if (err instanceof GlobalpingError && err.code === code) return null;
    return `${err?.name} ${err?.code ?? ''} ${err?.message ?? err}`.trim();
  }
}

/** One paid check: measure (ip, name, port), classify every test locally. */
async function probeCheck(id, title, { ip, name, port = 443, timeoutS = 10, locations = null, sha256 = null, cert = null, expect }) {
  const body = httpsCheckRequest({ ip, name, port, timeoutS, locations });
  if (spent + 1 > budget) {
    record(id, title, false, `skipped: the budget (${budget}) is used up`);
    return null;
  }
  guard(body);
  const started = Date.now();
  try {
    const out = await client.measure(body);
    spent += out.cost;
    const secs = ((Date.now() - started) / 1000).toFixed(1);
    const now = Date.parse(out.measurement.createdAt) || Date.now();
    const verdicts = out.measurement.results.map((t) => localVerdict(t, { name, sha256, now }));
    const probes = out.measurement.results.map((t) => `${t.probe?.country ?? '?'} AS${t.probe?.asn ?? '?'}`).join(', ');
    const problems = expect(verdicts, out) || [];
    const vjs = [];
    for (const t of out.measurement.results) {
      const s = await verifyJsStatus(t, { name, cert, now });
      if (s) vjs.push(s);
    }
    const shown = verdicts.map((v) => `${v.status}/${v.reason}${v.warnings.length ? `+${v.warnings.join('+')}` : ''}`).join(' ');
    const extra = vjs.length ? ` · verify.js: ${vjs.join(' ')}` : '';
    // A reset / connect timeout where a certificate was expected: the target did not answer this probe
    // network (seen live 2026-09-24: badssl.com reset Tokyo / Sydney probes while serving everyone else).
    const targetSide = problems.length && verdicts.every((v) => v.reason === 'reset' || v.reason === 'connect-timeout') && !/TIMEOUT|CLOSED/.test(title)
      ? ' · target-side: no TLS answer to this probe network (not a client bug; --only <id> retries from the same location, BADSSL_FROM sets it)' : '';
    record(id, title, problems.length === 0, `${shown} · ${probes} · ${secs} s · id ${out.id}${extra}${problems.length ? ` · ${problems.join('; ')}` : ''}${targetSide}`, out.cost);
    return out;
  } catch (err) {
    if (err?.cost) spent += err.cost;
    record(id, title, false, `${err?.name} ${err?.code ?? ''} ${err?.message ?? err}${err?.measurementId ? ` (id ${err.measurementId})` : ''}`);
    return null;
  }
}

const one = (status, reason, warnings = null) => (verdicts) => {
  const p = [];
  for (const v of verdicts) {
    if (v.status !== status) p.push(`expected ${status}, got ${v.status}`);
    if (reason && v.reason !== reason) p.push(`expected reason ${reason}, got ${v.reason}`);
    for (const w of warnings || []) if (!v.warnings.includes(w)) p.push(`missing warning ${w}`);
  }
  return p;
};

const CHECKS = [
  { id: 0, probes: 0, title: 'GET /limits is free and parses the body-only quota', run: async () => {
    const q = await client.limits();
    record(0, 'GET /limits', Number.isInteger(q.remaining) && q.limit === 250,
      `remaining ${q.remaining}/${q.limit}, type ${q.type}, window ${q.resetAt ? `resets ${q.resetAt.toISOString()}` : 'not open'}`);
  } },
  { id: 1, probes: 0, title: 'private / TEST-NET targets are refused for free (and locally)', run: async () => {
    const problems = [];
    for (const ip of ['10.0.0.1', '192.0.2.1']) {
      if (isProbeableIP(ip)) problems.push(`isProbeableIP(${ip}) is true`);
      const p = await expectRefused(rawBody(ip, 'github.com'), 'private-target');
      if (p) problems.push(`${ip}: ${p}`);
    }
    record(1, 'private targets → private-target ×2', !problems.length, problems.join('; '));
  } },
  { id: 2, probes: 0, title: 'unaccepted host names are refused for free (and locally)', run: async () => {
    const problems = [];
    for (const host of ['_x.github.com', 'github.com.']) {
      if (isProbeableHost(host)) problems.push(`isProbeableHost(${host}) is true`);
      const p = await expectRefused(rawBody(GITHUB_IP, host), 'bad-host');
      if (p) problems.push(`${host}: ${p}`);
    }
    record(2, 'bad hosts → bad-host ×2', !problems.length, problems.join('; '));
  } },
  { id: 3, probes: 1, title: `${GITHUB_IP} / github.com vs a local TLS connect`, run: async () => {
    const local = await localLeaf(GITHUB_IP, 'github.com');
    await probeCheck(3, 'github.com: UPDATED (fingerprint = local leaf)', {
      ip: GITHUB_IP, name: 'github.com', sha256: local.sha256, cert: local.cert,
      expect: (verdicts, out) => {
        const p = one('UPDATED', 'new-cert')(verdicts);
        const t = out.measurement.results[0]?.result?.tls;
        if (t) {
          if (hexKey(t.fingerprint256) !== local.sha256) p.push('fingerprint256 ≠ computeFingerprints(local DER)');
          if (hexKey(t.serialNumber).replace(/^0+(?=.)/, '') !== local.cert.serialHex.replace(/^0+(?=.)/, '')) p.push('serial mismatch');
          if (!t.publicKey || !local.spkiHex.endsWith(hexKey(t.publicKey))) p.push('publicKey is not the tail of the local SPKI');
        }
        const other = out.measurement.results.map((x) => localVerdict(x, { name: 'github.com', sha256: OTHER_SHA, now: Date.now() }).status);
        if (other.some((s) => s !== 'NEEDS_UPDATE')) p.push(`re-classified with another cert: ${other.join(',')} (want NEEDS_UPDATE)`);
        return p;
      }
    });
  } },
  { id: 4, probes: 1, title: 'badssl / wrong.host.badssl.com', run: async () => {
    const ip = await resolveA('wrong.host.badssl.com');
    await probeCheck(4, 'wrong.host.badssl.com: NOT_HOSTED', { ip, name: 'wrong.host.badssl.com', locations: BADSSL_FROM['wrong.host.badssl.com'], expect: one('NOT_HOSTED', 'not-covered') });
  } },
  { id: 5, probes: 1, title: 'badssl / expired.badssl.com', run: async () => {
    const ip = await resolveA('expired.badssl.com');
    await probeCheck(5, 'expired.badssl.com: NEEDS_UPDATE + expired', { ip, name: 'expired.badssl.com', locations: BADSSL_FROM['expired.badssl.com'], expect: one('NEEDS_UPDATE', 'no-new-cert', ['expired']) });
  } },
  { id: 6, probes: 1, title: 'badssl / incomplete-chain.badssl.com vs a local TLS connect', run: async () => {
    const ip = await resolveA('incomplete-chain.badssl.com');
    const local = await localLeaf(ip, 'incomplete-chain.badssl.com');
    await probeCheck(6, 'incomplete-chain.badssl.com: UPDATED + chain-incomplete', {
      ip, name: 'incomplete-chain.badssl.com', locations: BADSSL_FROM['incomplete-chain.badssl.com'], sha256: local.sha256, cert: local.cert, expect: one('UPDATED', 'new-cert', ['chain-incomplete'])
    });
  } },
  { id: 7, probes: 1, title: `${SCANME_IP} / scanme.nmap.org:443`, run: async () => {
    await probeCheck(7, 'scanme.nmap.org:443: CLOSED', { ip: SCANME_IP, name: 'scanme.nmap.org', expect: one('CLOSED', 'refused') });
  } },
  { id: 8, probes: 1, title: `${GITHUB_IP}:8443 / github.com, timeout 5 s`, run: async () => {
    const t0 = Date.now();
    await probeCheck(8, 'github.com:8443: TIMEOUT (connect) in < 16 s', {
      ip: GITHUB_IP, name: 'github.com', port: 8443, timeoutS: 5,
      expect: (verdicts) => [...one('TIMEOUT', 'connect-timeout')(verdicts), ...(Date.now() - t0 < 16000 ? [] : ['took ≥ 16 s'])]
    });
  } },
  { id: 9, probes: 1, title: `${CLOUDFLARE_IP} / github.com (foreign SNI on a Cloudflare IP)`, run: async () => {
    await probeCheck(9, 'Cloudflare IP + github.com: TLS_ERROR / sni-refused', { ip: CLOUDFLARE_IP, name: 'github.com', expect: one('TLS_ERROR', 'sni-refused') });
  } },
  { id: 10, probes: 2, title: 'two measurements in parallel; the quota keeps the minimum', run: async () => {
    const local = await localLeaf(GITHUB_IP, 'github.com');
    const before = requests.length;
    const outs = await Promise.all(['github.com', 'www.github.com'].map((name) => probeCheck(10, `parallel ${name}: UPDATED`, {
      ip: GITHUB_IP, name, sha256: local.sha256, cert: local.cert, expect: one('UPDATED', 'new-cert')
    })));
    const heads = requests.slice(before).filter((r) => r.method === 'POST' && r.remaining !== null).map((r) => Number(r.remaining));
    const q = client.quota;
    const ok = outs.every(Boolean) && heads.length === 2 && q && q.remaining <= Math.min(...heads);
    record(10, 'merged quota ≤ every POST header', !!ok, `headers ${heads.join(', ')} → client.quota.remaining ${q?.remaining}`);
  } }
];

/** Every GET on one measurement id waited ≥ 500 ms after the previous response (request-to-request ≥ 450 ms). */
function pollSpacing() {
  const byId = new Map();
  for (const r of requests) {
    const m = /\/measurements\/([A-Za-z0-9]+)$/.exec(r.url);
    if (r.method === 'GET' && m) (byId.get(m[1]) || byId.set(m[1], []).get(m[1])).push(r.at);
  }
  let min = Infinity;
  for (const list of byId.values()) for (let i = 1; i < list.length; i += 1) min = Math.min(min, list[i] - list[i - 1]);
  return { ids: byId.size, gets: [...byId.values()].reduce((s, l) => s + l.length, 0), min };
}

/* ------------------------------------------------------------------------ */
/* --capture: re-record the fixtures (23 probes; public targets plus the    */
/* deliberate m21 / m25 charged-failure cases: loopback name, 3fff::1)      */
/* ------------------------------------------------------------------------ */

async function capture() {
  const bad = { ip: null };
  bad.ip = await resolveA('badssl.com');
  const scrubMap = [[bad.ip, '54.1.2.3']];
  const specs = [
    ['m01-github-valid', { ...rawBody(GITHUB_IP, 'github.com'), limit: undefined, locations: [{ country: 'DE' }, { country: 'US' }] }, true],
    ['m02-wrong-host', { ...rawBody(bad.ip, 'wrong.host.badssl.com'), limit: undefined, locations: [{ magic: 'AS24940' }] }, true],
    ['m03-expired', { ...rawBody(bad.ip, 'expired.badssl.com'), limit: undefined, locations: [{ asn: 16276 }] }],
    ['m04-self-signed', { ...rawBody(bad.ip, 'self-signed.badssl.com'), limit: undefined, locations: [{ country: 'TR' }] }],
    ['m05-untrusted-root', { ...rawBody(bad.ip, 'untrusted-root.badssl.com'), limit: undefined, locations: [{ tags: ['eyeball-network'] }] }],
    ['m06-incomplete-chain', rawBody(bad.ip, 'incomplete-chain.badssl.com')],
    ['m07-revoked', rawBody(bad.ip, 'revoked.badssl.com')],
    ['m08-no-host-421', { type: 'http', target: bad.ip, limit: 1, timeout: 10, measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', path: '/' } } }],
    ['m09-closed', rawBody(SCANME_IP, 'scanme.nmap.org')],
    ['m10-filtered-default', { ...rawBody(GITHUB_IP, 'github.com'), timeout: undefined, measurementOptions: { protocol: 'HTTPS', port: 8443, request: { method: 'HEAD', host: 'github.com', path: '/' } } }],
    ['m11-filtered-timeout5', { ...rawBody(GITHUB_IP, 'github.com'), timeout: 5, measurementOptions: { protocol: 'HTTPS', port: 8443, request: { method: 'HEAD', host: 'github.com', path: '/' } } }],
    ['m12-sni-refused', rawBody(CLOUDFLARE_IP, 'github.com')],
    ['m13-cf-8443-403', { ...rawBody(CLOUDFLARE_IP, 'www.cloudflare.com'), measurementOptions: { protocol: 'HTTPS', port: 8443, request: { method: 'HEAD', host: 'www.cloudflare.com', path: '/' } } }],
    ['m15-v6-literal', rawBody('2606:4700::6810:7c60', 'www.cloudflare.com')],
    ['m17-unknown-vhost', rawBody(bad.ip, 'no-such-vhost.badssl.com')],
    ['m19-reuse-probe', null], // same probe as m15, filled in below
    ['m20-nxdomain', { type: 'http', target: 'gp-test-nonexistent-7q2z.example.com', limit: 1, timeout: 10, measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', path: '/' } } }],
    ['m21-private-resolve', { type: 'http', target: 'localtest.me', limit: 1, timeout: 10, measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', path: '/' } } }],
    ['m22-http2', { ...rawBody(GITHUB_IP, 'github.com'), measurementOptions: { protocol: 'HTTP2', port: 443, request: { method: 'HEAD', host: 'github.com', path: '/' } } }],
    ['m23-ip-san', rawBody('1.1.1.1', 'one.one.one.one')],
    ['m24-not-tls', { ...rawBody(bad.ip, 'http.badssl.com'), measurementOptions: { protocol: 'HTTPS', port: 80, request: { method: 'HEAD', host: 'http.badssl.com', path: '/' } } }],
    ['m25-v6-doc-enetunreach', rawBody('3fff::1', 'example.com')]
  ];
  const clean = (b) => JSON.parse(JSON.stringify(b)); // drops the undefined keys
  mkdirSync(FIXTURE_DIR, { recursive: true });
  let m15id = null;
  for (const [name, body0, keepPublicKey] of specs) {
    const body = clean(body0 ?? { ...rawBody(CLOUDFLARE_IP, 'www.cloudflare.com'), limit: undefined, locations: m15id });
    if (!body.locations && body.limit === undefined) body.limit = 1;
    const want = Array.isArray(body.locations)
      ? body.locations.reduce((s, l) => s + (l.limit ?? 1), 0)
      : typeof body.locations === 'string' ? 1 : body.limit;
    if (spent + want > budget) refuse(`the capture needs more than --budget ${budget}`);
    guard(body);
    let post = null;
    let inProgress = null;
    const wrapped = async (url, init) => {
      const res = await recordingFetch(url, init);
      if ((init?.method || 'GET') === 'POST') {
        const clone = res.clone();
        post = { status: res.status, headers: Object.fromEntries(res.headers), body: await clone.json().catch(() => null) };
      }
      return res;
    };
    const c = createGlobalping({ fetchImpl: wrapped });
    const out = await c.measure(body, { onUpdate: (m) => { if (!inProgress && m.status === 'in-progress') inProgress = JSON.parse(JSON.stringify(m)); } });
    spent += out.cost;
    if (name === 'm15-v6-literal') m15id = out.id;
    const fixture = buildFixture({
      name, capturedAt: out.measurement.createdAt, request: body, post, inProgress, final: { status: 200, body: out.measurement }
    }, { keepPublicKey: !!keepPublicKey });
    writeFileSync(join(FIXTURE_DIR, `${name}.json`), scrubText(`${JSON.stringify(fixture, null, 2)}\n`, scrubMap));
    log(`wrote tests/fixtures/globalping/${name}.json (id ${out.id}, cost ${out.cost})`);
  }
  const freeOnes = [
    ['v-private-target-400', rawBody('10.0.0.1', 'example.com')],
    ['v-testnet1-400', rawBody('192.0.2.1', 'example.com')],
    ['v-bad-host-400', rawBody(GITHUB_IP, 'github.com:443')],
    ['v-ip-with-ipversion-400', { ...rawBody(GITHUB_IP, 'example.com'), measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', host: 'example.com', path: '/' }, ipVersion: 4 } }],
    ['v-limit-and-location-limit-400', { ...rawBody(GITHUB_IP, 'example.com'), limit: 2, locations: [{ country: 'DE', limit: 1 }] }],
    ['v-no-probes-422', { ...rawBody(GITHUB_IP, 'example.com'), limit: undefined, locations: [{ country: 'AQ' }] }]
  ];
  for (const [name, body0] of freeOnes) {
    const body = clean(body0);
    guard(body);
    const res = await recordingFetch(`${GLOBALPING_API}/measurements`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const post = { status: res.status, headers: Object.fromEntries(res.headers), body: await res.json().catch(() => null) };
    if (res.status === 202) refuse(`${name} was unexpectedly accepted`);
    writeFileSync(join(FIXTURE_DIR, `${name}.json`), scrubText(`${JSON.stringify(buildFixture({ name, capturedAt: new Date().toISOString(), request: body, post }), null, 2)}\n`, scrubMap));
    log(`wrote tests/fixtures/globalping/${name}.json (HTTP ${res.status}, free)`);
  }
  log('validation-cases.json, create-parallel-quota.json and the synthetic fixtures are not recaptured.');
  log('Next: node --test tests/js/repo-hygiene.test.js (scrub check) and the globalping / verify unit suites.');
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

function parseArgs(argv) {
  const o = { dry: false, capture: false, budget: null, only: null, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--dry') o.dry = true;
    else if (a === '--capture') o.capture = true;
    else if (a === '--budget') o.budget = Number(argv[++i]);
    else if (a === '--only') o.only = String(argv[++i] ?? '').split(',').map(Number).filter(Number.isInteger);
    else if (a === '--help' || a === '-h') o.help = true;
    else refuse(`unknown argument ${a}`);
  }
  return o;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    const lines = readFileSync(fileURLToPath(import.meta.url), 'utf8').split(/\r?\n/);
    console.log(lines.slice(2, lines.findIndex((l) => l.trim() === '*/')).join('\n'));
    return 0;
  }
  REFUSALS = loadRefusals();
  guard([GITHUB_IP, CLOUDFLARE_IP, SCANME_IP, 'github.com', 'www.github.com', 'badssl.com', 'www.cloudflare.com', 'scanme.nmap.org', 'one.one.one.one']);
  budget = Number.isInteger(opts.budget) && opts.budget >= 0 ? opts.budget : (opts.capture ? 0 : 10);
  const selected = CHECKS.filter((c) => (opts.only ? opts.only.includes(c.id) : true) && (!opts.dry || c.probes === 0));
  const planned = opts.capture ? CAPTURE_COST : selected.reduce((s, c) => s + c.probes, 0);
  if (planned > budget) refuse(`${planned} probes planned, --budget is ${budget}`);

  const started = Date.now();
  const before = await client.limits();
  log(`Globalping quota before: ${before.remaining}/${before.limit} (${before.type}), ${before.resetAt ? `window resets ${before.resetAt.toISOString()}` : 'no window open'}`);
  if (planned > 0 && before.remaining < Math.max(MIN_REMAINING, planned + MIN_REMAINING)) {
    refuse(`only ${before.remaining} probes left this hour (need ${planned} + ${MIN_REMAINING} spare)`);
  }
  log(`plan: ${opts.capture ? 'capture fixtures' : `checks ${selected.map((c) => c.id).join(',')}`}; up to ${planned} probe(s), budget ${budget}`);

  if (opts.capture) {
    await capture();
  } else {
    for (const c of selected) {
      try {
        await c.run();
      } catch (err) {
        record(c.id, c.title, false, `${err?.name}: ${err?.message ?? err}`);
      }
    }
  }

  const after = await client.limits().catch(() => client.quota);
  const spacing = pollSpacing();
  if (spacing.gets > 1 && spacing.min !== Infinity) {
    record('poll', 'per-id poll spacing', spacing.min >= 450, `${spacing.gets} GETs on ${spacing.ids} ids, closest two on one id ${spacing.min} ms apart`);
  }
  const posts = requests.filter((r) => r.method === 'POST');
  log('');
  log(`Summary: ${results.filter((r) => r.ok).length}/${results.length} checks passed; probes spent ${spent} (budget ${budget}); ` +
    `${posts.length} POSTs (${posts.filter((r) => r.status === 202).length} accepted), ${requests.filter((r) => r.method === 'GET').length} GETs; ` +
    `${((Date.now() - started) / 1000).toFixed(1)} s`);
  log(`Globalping quota after: ${after?.remaining ?? '?'}/${after?.limit ?? '?'} (before ${before.remaining}; other tools behind this IP share the window)`);
  return results.every((r) => r.ok) ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(mask(`smoke crashed: ${err?.stack ?? err}`));
    process.exit(1);
  });
}
