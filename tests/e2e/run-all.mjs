#!/usr/bin/env node
/**
 * run-all.mjs — run every tests/e2e/*.e2e.mjs suite one after another and print a summary.
 *
 *   node tests/e2e/run-all.mjs [--only a,b] [--skip a,b] [--timeout-min 20] [--bail]
 *                              [--browser chrome|edge] [--headed] [--no-shots] [--offline] …
 *
 * - Suites run sequentially (never in parallel): most of them hit live third-party APIs with
 *   small free quotas (HackerTarget ≈ 50/day, Cert Spotter ≈ 10/hour), and each one starts
 *   its own browser and static server.
 * - Order: shell first (offline, fastest), then home (offline: the start page over the workspace's
 *   own data), then investigate (offline: the page template the four tools of "Investigate a
 *   domain" share), then certificates (offline: the same template on the four tools of "Deploy &
 *   renew certificates"), then migrate (offline: the same template on the four tools of "Change &
 *   migrate DNS"), then network (offline: the same template on "Map IPs to servers" and the
 *   workspace pages, Servers and About), then the views in navigation order (domain, the
 *   offline suite of the Domain overview, right after subdomains, then locales, the offline suite
 *   of the adaptive locale packs of Subdomains; verify, the offline suite of SSL
 *   Targets › Verify, right after scan, then renewal, SSL Targets with several certificates at
 *   once, offline too; dane, the offline DANE / TLSA suite of the Certificate view and SSL Targets,
 *   right after cert, then pfx, the offline PKCS#12 suite of the same two views, chainfix, their
 *   offline missing-intermediate suite, renew, the offline Renewal readiness suite, and estate,
 *   the offline Certificate estate suite; explain, the offline suite of DNS Lookup › Explain, right
 *   after lookup; change, the offline DNS change request suite, right after
 *   bulk, then cutover, the offline suite of the cutover follow-ups (Global DNS's expected value and
 *   its name server probe, the TTL planner's calendar); retire, the offline suite of Retire an IP,
 *   right after ptr; takeover, the offline suite of Domain Health › Dependencies (the takeover and
 *   dependency-expiry audit of one domain), right after health; reports, the offline suite of
 *   DMARC & TLS reports, then dmarchistory, the offline suite of its History tab (the report
 *   history a workspace keeps) and the DMARC customer report, then portfolio, the offline suite of the Domain portfolio,
 *   secscore, the offline suite of its domain security: lock depth, registrar class, the score,
 *   regwatch, the offline suite of its registration watch ("Changed since your last check"),
 *   revocation, the offline suite of the renewal radar in the page: revocation from Cert Spotter
 *   in the portfolio's CT tab and the Certificate view, the CLI's --ari / --revocation in Certificate estate,
 *   waivers, the offline suite of the accepted risks: Domain Health's "Accept this risk…" and the end date
 *   passing, the Workspaces dialog's waivers.json, the policy matrix's accepted cells and the CT tab's known certificates,
 *   and monitor, the offline suite of the Monitoring view (the runner's results from a folder and from a fake
 *   GitHub API inside the page),
 *   then carry (offline: the target and kept results carried across views), workspaces
 *   (offline: the customer workspaces in IndexedDB and their hand-over file), origins (offline: the
 *   workspace's origin map filled from a zone and a CLI report, used by the scans) and privacy (offline:
 *   About's ledger of what the page sent, related domains from CT and key continuity), then the
 *   cross-view integration suite, then any other *.e2e.mjs file alphabetically.
 * - --only / --skip take suite names without the `.e2e.mjs` suffix (e.g. `--only shell,cert`).
 * - Every other argument is passed through to each suite (they share --browser, --headed and
 *   --no-shots; unknown flags are ignored by suites that do not use them).
 * - A suite that runs longer than --timeout-min (default 20) minutes is killed and counted
 *   as failed. --bail stops after the first failing suite.
 * - Killing a suite never leaves its browser behind: on POSIX each suite runs in its own process
 *   group, which gets SIGTERM (then SIGKILL after a grace period), so the headless browser dies
 *   with it; cdp.mjs also kills its browsers on SIGTERM / SIGINT. On Windows the browser dies
 *   with the suite's node process (job object). Either way the suite's leftover throw-away
 *   profiles (tests/e2e/.profile-<pid>-<n>) are removed afterwards.
 * - Ctrl+C stops the running suite, skips the rest and prints the summary; a second Ctrl+C
 *   exits at once.
 * - Exit code: 0 when every suite exits 0, otherwise 1 (130 / 143 when interrupted).
 */

import { spawn } from 'node:child_process';
import { readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ORDER = ['shell', 'home', 'investigate', 'certificates', 'migrate', 'network', 'subdomains', 'domain', 'locales', 'zone', 'scan', 'verify', 'renewal', 'cert', 'dane', 'pfx', 'chainfix', 'renew', 'estate', 'global', 'lookup', 'explain', 'bulk', 'change', 'cutover', 'ip', 'ptr', 'retire', 'health', 'takeover', 'reports', 'dmarchistory', 'portfolio', 'secscore', 'regwatch', 'revocation', 'waivers', 'monitor', 'carry', 'workspaces', 'origins', 'privacy', 'integration'];
const POSIX = process.platform !== 'win32';
/** After SIGTERM, how long a timed-out suite gets before SIGKILL. */
const KILL_GRACE_MS = 5000;

/** The suite process currently running (for signal forwarding), and whether we were interrupted. */
let current = null;
let interrupted = null;

/**
 * The throw-away browser profiles a suite process left in tests/e2e (cdp.mjs names them
 * `.profile-<pid>-<n>`).
 * @param {string[]} entries directory entries of tests/e2e
 * @param {number} pid the suite's process id
 * @returns {string[]}
 */
export function profileDirsOf(entries, pid) {
  const prefix = `.profile-${pid}-`;
  return entries.filter((n) => n.startsWith(prefix) && /^\d+$/.test(n.slice(prefix.length)));
}

/** Delete a finished suite's leftover browser profiles; returns how many were found. */
function removeLeftoverProfiles(pid) {
  let entries;
  try {
    entries = readdirSync(HERE);
  } catch {
    return 0;
  }
  const dirs = profileDirsOf(entries, pid);
  for (const d of dirs) {
    try {
      rmSync(path.join(HERE, d), { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    } catch {
      // still locked; .gitignore covers tests/e2e/.profile*/
    }
  }
  return dirs.length;
}

/**
 * Signal a suite and everything it started. POSIX: the whole process group (the suite was spawned
 * detached, so it leads its own group and its browser belongs to it). Windows: the node process;
 * its job object takes the browser down with it.
 */
function signalSuite(child, signal) {
  try {
    if (POSIX) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      // already gone
    }
  }
}

/**
 * Split our own options from the ones passed through to the suites.
 * @param {string[]} argv
 * @returns {{ only: string[]|null, skip: string[], timeoutMin: number, bail: boolean, passThrough: string[] }}
 */
export function parseArgs(argv) {
  const out = { only: null, skip: [], timeoutMin: 20, bail: false, passThrough: [] };
  const list = (v) => String(v || '').split(',').map((s) => s.trim().replace(/\.e2e\.mjs$/, '')).filter(Boolean);
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--only') out.only = list(argv[++i]);
    else if (a === '--skip') out.skip = list(argv[++i]);
    else if (a === '--timeout-min') out.timeoutMin = Math.max(1, Number(argv[++i]) || 20);
    else if (a === '--bail') out.bail = true;
    else out.passThrough.push(a);
  }
  return out;
}

/**
 * The suites to run, in execution order.
 * @param {string[]} files file names in tests/e2e
 * @param {{ only: string[]|null, skip: string[] }} filter
 * @returns {string[]} suite names
 */
export function orderSuites(files, { only = null, skip = [] } = {}) {
  const names = files.filter((f) => f.endsWith('.e2e.mjs')).map((f) => f.replace(/\.e2e\.mjs$/, ''));
  const rank = (n) => (ORDER.includes(n) ? ORDER.indexOf(n) : ORDER.length);
  return names
    .filter((n) => (!only || only.includes(n)) && !skip.includes(n))
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/**
 * Count the runner's PASS / FAIL lines in a suite's output.
 * @param {string} text
 * @returns {{ pass: number, fail: number, failed: string[] }}
 */
export function countResults(text) {
  let pass = 0;
  let fail = 0;
  const failed = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s{0,4}(PASS|FAIL)\s{2}(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === 'PASS') pass += 1;
    else { fail += 1; failed.push(m[2].trim()); }
  }
  return { pass, fail, failed };
}

function runSuite(name, args, timeoutMs) {
  return new Promise((resolve) => {
    const file = path.join(HERE, `${name}.e2e.mjs`);
    const t0 = Date.now();
    let output = '';
    let timedOut = false;
    let killTimer = null;
    // detached on POSIX = own process group, so a timeout / Ctrl+C can reach the browser too
    const child = spawn(process.execPath, [file, ...args], { stdio: ['ignore', 'pipe', 'pipe'], detached: POSIX });
    current = child;
    const onData = (stream) => (chunk) => {
      const s = chunk.toString();
      output += s;
      stream.write(s);
    };
    child.stdout.on('data', onData(process.stdout));
    child.stderr.on('data', onData(process.stderr));
    const timer = setTimeout(() => {
      timedOut = true;
      signalSuite(child, 'SIGTERM');
      killTimer = setTimeout(() => signalSuite(child, 'SIGKILL'), KILL_GRACE_MS);
    }, timeoutMs);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      if (current === child) current = null;
      // a browser that ignored SIGTERM is still in the group: finish it
      if (POSIX && (timedOut || interrupted)) signalSuite(child, 'SIGKILL');
      const removed = removeLeftoverProfiles(child.pid);
      if (removed) process.stdout.write(`(removed ${removed} leftover browser profile(s) of ${name})\n`);
      resolve({ name, code: timedOut ? null : code, signal, timedOut, ms: Date.now() - t0, ...countResults(output) });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      if (current === child) current = null;
      output += String(err);
      resolve({ name, code: null, signal: null, timedOut: false, ms: Date.now() - t0, pass: 0, fail: 1, failed: [String(err)] });
    });
  });
}

function fmtMs(ms) {
  const s = Math.round(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s` : `${s}s`;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const suites = orderSuites(readdirSync(HERE), opts);
  if (!suites.length) {
    process.stdout.write('No E2E suites selected.\n');
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`Running ${suites.length} E2E suite(s) sequentially: ${suites.join(', ')}\n`);
  for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
    process.on(signal, () => {
      if (interrupted) {
        if (current) signalSuite(current, 'SIGKILL');
        process.exit(code);
      }
      interrupted = { signal, code };
      process.stdout.write(`\n${signal}: stopping ${current ? 'the running suite' : 'the run'} (again to exit at once)…\n`);
      if (current) signalSuite(current, 'SIGTERM');
    });
  }
  const results = [];
  for (const name of suites) {
    if (interrupted) break;
    process.stdout.write(`\n${'='.repeat(78)}\n▶ ${name}.e2e.mjs ${opts.passThrough.join(' ')}\n${'='.repeat(78)}\n`);
    const r = await runSuite(name, opts.passThrough, opts.timeoutMin * 60_000);
    results.push(r);
    if (opts.bail && (r.code !== 0 || r.fail)) break;
  }
  if (!results.length) {
    process.exitCode = interrupted ? interrupted.code : 1;
    return;
  }

  process.stdout.write(`\n${'='.repeat(78)}\nE2E summary\n${'='.repeat(78)}\n`);
  const width = Math.max(...results.map((r) => r.name.length));
  let failedSuites = 0;
  for (const r of results) {
    const ok = r.code === 0 && r.fail === 0;
    if (!ok) failedSuites += 1;
    const status = ok ? 'PASS' : r.timedOut ? 'TIMEOUT' : 'FAIL';
    const exit = r.timedOut ? 'killed' : `exit ${r.code ?? r.signal}`;
    process.stdout.write(`  ${status.padEnd(7)} ${r.name.padEnd(width)}  ${String(r.pass).padStart(3)} passed  ${String(r.fail).padStart(2)} failed  ${fmtMs(r.ms).padStart(6)}  (${exit})\n`);
    for (const f of r.failed.slice(0, 10)) process.stdout.write(`            - ${f}\n`);
  }
  const pass = results.reduce((n, r) => n + r.pass, 0);
  const fail = results.reduce((n, r) => n + r.fail, 0);
  const skipped = suites.length - results.length;
  process.stdout.write(`\n${results.length - failedSuites}/${results.length} suites green · ${pass} steps passed · ${fail} failed`
    + `${skipped ? ` · ${skipped} not run (${interrupted ? interrupted.signal : '--bail'})` : ''} · ${fmtMs(results.reduce((n, r) => n + r.ms, 0))}\n`);
  if (interrupted) process.exitCode = interrupted.code;
  else if (failedSuites || skipped) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
