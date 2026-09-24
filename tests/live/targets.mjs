/**
 * Target domains for the live (network) scripts in this folder.
 *
 * Order of precedence:
 *   1. domains given on the command line;
 *   2. tests/live/targets.local.json — gitignored, for your own domains:
 *        { "domains": ["example.com"],
 *          "groundTruth": { "example.com": ["www", "api"] },
 *          "originTruth": { "shop.example.com": "203.0.113.10" } }
 *      groundTruth lists labels known to exist (e.g. copied from your DNS
 *      dashboard) so a benchmark can report recall; originTruth maps proxied
 *      names to their real origin IP;
 *   3. the script's public fallback list.
 *
 * Keep private domains, zone contents and origin IPs in the local file only.
 * Reports the scripts write (--json / --csv / --cache-dir) can contain the
 * same data, so they go through reportPath() below: never into a file that
 * `git add -A` would pick up.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const LOCAL_TARGETS_FILE = fileURLToPath(new URL('./targets.local.json', import.meta.url));

/** The repository root (this file lives in tests/live/). */
export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** Gitignored folder for the reports of the live scripts (e.g. --json tests/live/private/bench.json). */
export const PRIVATE_OUTPUT_DIR = fileURLToPath(new URL('./private/', import.meta.url));

/** Gitignored cache folder of the live scripts. */
const LIVE_CACHE_DIR = fileURLToPath(new URL('./.cache/', import.meta.url));

/** Is `file` the folder `dir` or inside it? (Case-insensitive on Windows, like path.relative.) */
export function isInsideDir(file, dir) {
  const rel = relative(dir, file);
  if (rel === '') return true;
  return !isAbsolute(rel) && rel.split(/[\\/]/)[0] !== '..';
}

/**
 * Does git ignore `file` (an absolute path inside `repoRoot`)? `git check-ignore -q` exits 0
 * when the path is ignored and 1 when it is not — a tracked file counts as not ignored. When
 * git cannot answer (not installed, not a work tree), only the folders .gitignore reserves for
 * private live data (tests/live/private/, tests/live/.cache/) and *.local.json count.
 * @param {string} file
 * @param {string} [repoRoot]
 * @returns {boolean}
 */
export function gitIgnores(file, repoRoot = REPO_ROOT) {
  const r = spawnSync('git', ['check-ignore', '-q', '--', file], { cwd: repoRoot, stdio: 'ignore', windowsHide: true });
  if (r.status === 0) return true;
  if (r.status === 1) return false;
  return isInsideDir(file, PRIVATE_OUTPUT_DIR) || isInsideDir(file, LIVE_CACHE_DIR) || /\.local\.json$/i.test(file);
}

/**
 * Where a live script may write a report or cache. They can hold private domains, zone labels
 * and origin IPs (from targets.local.json), so they must never land where `git add -A` would
 * stage them. The path is resolved against the working directory as usual; a path outside the
 * repository (e.g. in the OS temp folder) is used as given, and a path inside the repository
 * must be ignored by git (tests/live/private/…, *.local.json), otherwise this throws.
 * Call it while parsing the arguments, so a bad path fails before a long run.
 * @param {string} file the --json / --csv / --cache-dir value
 * @param {{ cwd?: string, repoRoot?: string, isIgnored?: (file: string, repoRoot: string) => boolean }} [opts]
 * @returns {string} absolute path
 */
export function reportPath(file, { cwd = process.cwd(), repoRoot = REPO_ROOT, isIgnored = gitIgnores } = {}) {
  if (typeof file !== 'string' || !file.trim()) throw new Error('report path: a file name is required');
  const out = resolve(cwd, file);
  if (isInsideDir(out, repoRoot) && !isIgnored(out, repoRoot)) {
    throw new Error(`refusing to write ${out}: it is inside the repository but not gitignored, and a live report can `
      + 'contain private domains and IPs. Write it under tests/live/private/ (e.g. tests/live/private/report.json), '
      + 'to a *.local.json name, or outside the repository.');
  }
  return out;
}

/**
 * reportPath() for argument parsing: null stays null; an unsafe path prints the reason and
 * exits with code 2 before any work starts.
 * @param {string|null|undefined} file
 * @returns {string|null}
 */
export function reportPathOrExit(file) {
  if (file == null) return null;
  try {
    return reportPath(file);
  } catch (err) {
    console.error(err.message);
    process.exit(2);
  }
}

/**
 * Write a report to a path returned by reportPath(), creating its folder.
 * @param {string} file
 * @param {string} text
 */
export function writeReport(file, text) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
}

/** @returns {{ domains: string[], groundTruth: Record<string, string[]>, originTruth: Record<string, string> }} */
export function readLocalTargets() {
  try {
    const data = JSON.parse(readFileSync(LOCAL_TARGETS_FILE, 'utf8'));
    return {
      domains: Array.isArray(data.domains) ? data.domains.map(String) : [],
      groundTruth: data.groundTruth && typeof data.groundTruth === 'object' ? data.groundTruth : {},
      originTruth: data.originTruth && typeof data.originTruth === 'object' ? data.originTruth : {}
    };
  } catch {
    return { domains: [], groundTruth: {}, originTruth: {} };
  }
}

/**
 * @param {string[]} positional domains from the command line
 * @param {string[]} fallback public domains used when nothing else is configured
 * @returns {string[]}
 */
export function pickDomains(positional, fallback) {
  if (positional.length) return positional;
  const local = readLocalTargets().domains;
  return local.length ? local : fallback;
}

/**
 * Public, globally reachable fallback domains for the live scripts and the
 * E2E suites. cloudflare.com is always Cloudflare-fronted (useful for
 * proxied / origin checks); github.com mixes direct and CDN hosts;
 * wikipedia.org is a large multi-region zone.
 */
export const PUBLIC_FALLBACK_DOMAINS = Object.freeze(['github.com', 'cloudflare.com', 'wikipedia.org']);

/**
 * Positional (non-option) arguments. A value that follows one of
 * `valueOptions` (e.g. `--pool cloudflare,google`) is that option's value,
 * never a domain. Index-based, so a token repeated on the line is judged by
 * its own position.
 * @param {string[]} argv arguments after the script name
 * @param {Iterable<string>} valueOptions options that take a value
 * @returns {string[]}
 */
export function positionalArgs(argv, valueOptions) {
  const takesValue = new Set(valueOptions);
  return argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && takesValue.has(argv[i - 1])));
}
