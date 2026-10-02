#!/usr/bin/env node
/**
 * ds.mjs — DomainScope's headless runner: the app's checks without a browser tab, for cron and
 * scheduled CI jobs (docs/examples/nightly-domainscope.yml). Node 22+, no dependency: the
 * DOM-free libraries of assets/js/lib (and a few pure helpers of the views, DOM-free at import)
 * over Node's own fetch.
 *
 *   node tools/ds.mjs health example.com example.org --json health.json --md health.md
 *   node tools/ds.mjs subdomains example.com --baseline subs.json --json subs.json --fail-on-change
 *   node tools/ds.mjs drift example.com.zone --origin example.com
 *   node tools/ds.mjs ct --list domains.txt --json ct.json
 *   node tools/ds.mjs renew example.com '*.example.com' --ca letsencrypt
 *   node tools/ds.mjs dane fullchain.pem
 *   node tools/ds.mjs audit --policy policy.json domains.txt --json audit.json --md audit.md
 *
 * Commands, options and exit codes: tools/ds/args.mjs (USAGE, `--help`). The checks:
 * tools/ds/commands.mjs; "Changes since the baseline": tools/ds/diff.mjs; the summary and the
 * Markdown file: tools/ds/render.mjs. The `--baseline` semantics follow the Python CLI's
 * (cli/ssl_origin_scan.py): the baseline is read and checked before the run, the same file may
 * be the `--json` report (replaced whole, through a temporary file, after the run), a missing
 * one is a first run only when it is that file, report files that cannot be written are refused
 * before the run.
 *
 * DNS goes through lib/doh.js's DohClient with the app's resolver chain (minus the resolvers
 * Node's fetch cannot read) and the app's concurrency; nothing goes to Globalping.
 */

import { realpathSync } from 'node:fs';
import { readFile, writeFile, rename, unlink, stat, open } from 'node:fs/promises';
import { basename, dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCommandLine, parseListText, samePath, UsageError, USAGE, EXIT, DS_TOOL, DS_VERSION, COMMAND_SPECS } from './ds/args.mjs';
import { setupStrings, renderRunText, renderRunMarkdown, changeText } from './ds/render.mjs';
import { baselineProblem, baselineInfo, baselineNotes, diffReports, notableChanges } from './ds/diff.mjs';
import { DohClient } from '../assets/js/lib/doh.js';
import { parseHostList } from '../assets/js/lib/domain.js';
import { toJson } from '../assets/js/lib/export.js';
import { errorKind } from '../assets/js/lib/util.js';
import { cleanText } from '../assets/js/lib/summary.js';

const PROG = 'ds';
/** After Ctrl-C, how long the program waits for its last output before it exits. */
const INTERRUPT_GRACE_MS = 200;

/**
 * Text of a file: UTF-8 (a BOM is dropped), UTF-16 with a BOM, or UTF-16LE without one (as
 * PowerShell 5.1 may write it; the Python CLI and lib/x509.js read the same).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function decodeText(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8').decode(b.subarray(3));
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.subarray(2));
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.subarray(2));
  if (b.length >= 4 && b.length % 2 === 0) {
    let zeros = 0;
    for (let i = 1; i < b.length; i += 2) if (b[i] === 0) zeros += 1;
    if (zeros >= b.length / 4) return new TextDecoder('utf-16le').decode(b);
  }
  return new TextDecoder('utf-8').decode(b);
}

/** Read a file named on the command line, or a usage error saying why it cannot be read. */
async function readInput(path, option) {
  try {
    return new Uint8Array(await readFile(path));
  } catch (err) {
    const why = err && err.code === 'ENOENT' ? 'no such file' : err && err.code === 'EISDIR' ? 'it is a directory' : (err && err.message) || String(err);
    throw new UsageError(`${option ? `${option}: ` : ''}cannot read ${path}: ${why}`);
  }
}

/** Skipped entries of one file named one by one; the rest are counted. */
export const MAX_SKIPPED_SHOWN = 5;
/** An entry is quoted up to this many characters. */
const MAX_ENTRY_CHARS = 80;

/**
 * The warnings for the entries of a `--list` / `--exact` file that were skipped: the first
 * {@link MAX_SKIPPED_SHOWN} quoted (control and bidi characters out, long ones cut), then how many
 * more — a wrong file named by mistake prints a few lines, not one per line of it.
 * @param {string} label '--list domains.txt'
 * @param {string[]} invalid
 * @param {string} what 'a domain name'
 * @returns {string[]}
 */
export function skippedWarnings(label, invalid, what) {
  const quote = (s) => {
    const clean = cleanText(s);
    return clean.length > MAX_ENTRY_CHARS ? `${clean.slice(0, MAX_ENTRY_CHARS - 1)}…` : clean;
  };
  const out = invalid.slice(0, MAX_SKIPPED_SHOWN).map((bad) => `${label}: skipped "${quote(bad)}": not ${what}`);
  const more = invalid.length - MAX_SKIPPED_SHOWN;
  if (more > 0) out.push(`${label}: ${more} more ${more === 1 ? 'entry' : 'entries'} skipped: not ${what}`);
  return out;
}

/** A temporary file next to `path` (the same directory, so the rename replaces it whole). */
const tempPath = (path) => `${path}.${process.pid}.${Date.now().toString(36)}.tmp`;

/**
 * Refuse a report file that cannot be written before the run, not after it: a missing
 * directory, a directory, a read-only file. Nothing is truncated or left behind; the
 * directory must also take a new file (the report replaces the old one through a temporary
 * file there, which keeps a baseline whole if a write fails).
 * @param {string|null} path
 * @param {string} option
 */
export async function checkOutputPath(path, option) {
  if (!path) return;
  const dir = dirname(resolvePath(path));
  const dirStat = await stat(dir).catch(() => null);
  if (!dirStat || !dirStat.isDirectory()) throw new UsageError(`${option}: directory does not exist: ${dir}`);
  const st = await stat(path).catch(() => null);
  if (st && st.isDirectory()) throw new UsageError(`${option}: ${path} is a directory`);
  try {
    const handle = await open(path, st ? 'r+' : 'wx');
    await handle.close();
    if (!st) await unlink(path);
  } catch (err) {
    throw new UsageError(`${option}: cannot write ${path}: ${err && err.code ? err.code : err}`);
  }
  const temp = tempPath(path);
  try {
    const handle = await open(temp, 'wx');
    await handle.close();
    await unlink(temp);
  } catch (err) {
    throw new UsageError(`${option}: cannot create a file in ${dir} (the report replaces the old one through a temporary file there): ${err && err.code ? err.code : err}`);
  }
}

/** Write `path` whole or not at all: a temporary file next to it, renamed over it. */
async function replaceFile(path, text) {
  const temp = tempPath(path);
  try {
    await writeFile(temp, text, { encoding: 'utf8', flag: 'wx' });
    await rename(temp, path);
  } catch (err) {
    await unlink(temp).catch(() => {});
    throw err;
  }
}

/**
 * Read and check `--baseline FILE`: a previous `--json` report of the same subcommand (UTF-8 or
 * UTF-16 with a BOM). A file that does not exist is the first run when `allowMissing` (it is
 * also the `--json` report): null.
 * @param {string} path
 * @param {string} command
 * @param {{ allowMissing?: boolean }} [opts]
 * @returns {Promise<object|null>}
 */
export async function loadBaseline(path, command, { allowMissing = false } = {}) {
  let bytes;
  try {
    bytes = await readFile(path);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      if (allowMissing) return null;
      throw new UsageError(`--baseline: ${path} does not exist (give a report written with --json)`);
    }
    throw new UsageError(`--baseline: cannot read ${path}: ${(err && err.code) || err}`);
  }
  let doc;
  try {
    doc = JSON.parse(decodeText(new Uint8Array(bytes)));
  } catch (err) {
    throw new UsageError(`--baseline: ${path} is not JSON (${err.message})`);
  }
  const problem = baselineProblem(doc, command);
  if (problem) throw new UsageError(`--baseline: cannot compare with ${path}: ${problem}`);
  return doc;
}

/**
 * The rules of an `audit` run: a built-in preset, or the `--policy` file read (UTF-8 or UTF-16)
 * and checked by lib/policy.js before anything is sent. A rule the file names wrongly (an unknown
 * rule, a value it does not take) is a usage error, not a rule left out: a typo never passes.
 * @param {import('./ds/args.mjs').DsOptions} options
 * @returns {Promise<{ name: string|null, rules: object[], file?: string }>}
 */
export async function loadPolicy(options) {
  const { parsePolicy, presetPolicy, POLICY_RULES } = await import('../assets/js/lib/policy.js');
  if (options.preset) return presetPolicy(options.preset);
  const { policy, errors } = parsePolicy(decodeText(await readInput(options.policy, '--policy')));
  if (errors.length) {
    const known = errors.some((e) => e.code === 'unknown-rule') ? ` (the rules: ${POLICY_RULES.map((r) => r.id).join(', ')})` : '';
    throw new UsageError(`--policy ${options.policy}: ${errors.map(policyErrorText).join('; ')}${known}`);
  }
  return { ...policy, file: basename(options.policy) };
}

/**
 * Why a policy file is refused, in the runner's words (the app's say "it is left out": here the
 * whole file is refused). Values from the file are quoted and cut (lib/summary.js cleanText).
 * @param {{ code: string, rule?: string, value?: string, detail?: string, example?: string }} e lib/policy.js parsePolicy error
 * @returns {string}
 */
export function policyErrorText(e) {
  const q = (s) => `"${cleanText(String(s ?? '')).slice(0, 60)}"`;
  switch (e.code) {
    case 'not-json': return `not JSON (${cleanText(e.detail || '')})`;
    case 'not-object': return 'a policy is a JSON object of rules, such as { "expiryDays": ">= 30" }';
    case 'too-large': return `longer than ${e.value} characters`;
    case 'too-many': return `more than ${e.value} rules`;
    case 'unknown-rule': return `unknown rule ${q(e.rule)}`;
    case 'bad-value': return `${q(e.rule)} does not take ${cleanText(e.value || '')} (for example ${e.example})`;
    case 'empty': return 'no rule in it';
    default: return e.code;
  }
}

/**
 * Run the runner with a command line; resolves with the exit code (never rejects).
 * @param {string[]} argv arguments after the script
 * @param {{ stdout?: { write: Function, isTTY?: boolean }, stderr?: { write: Function },
 *   fetchImpl?: typeof fetch, env?: Record<string, string|undefined>, now?: () => Date,
 *   signal?: AbortSignal }} [io] injected streams, fetch and clock (tests)
 * @returns {Promise<number>}
 */
export async function main(argv, io = {}) {
  const {
    stdout = process.stdout, stderr = process.stderr, fetchImpl = globalThis.fetch,
    env = process.env, now = () => new Date(), signal
  } = io;
  const say = (stream, text) => stream.write(text.endsWith('\n') ? text : `${text}\n`);
  const fail = (err) => {
    say(stderr, `${PROG}: error: ${err && err.message ? err.message : String(err)}`);
    return err instanceof UsageError ? EXIT.USAGE : EXIT.FAILED;
  };

  let cl;
  try {
    cl = parseCommandLine(argv);
  } catch (err) {
    return fail(err);
  }
  if (cl.help) {
    say(stdout, USAGE);
    return EXIT.OK;
  }
  if (cl.version) {
    say(stdout, `${DS_TOOL} ${DS_VERSION}`);
    return EXIT.OK;
  }
  const { command, options } = cl;
  const quiet = options.quiet;
  const warnings = [];
  const warn = (text) => {
    warnings.push(text);
    if (!quiet) say(stderr, `${PROG}: warning: ${text}`);
  };
  const progress = (text) => {
    if (!quiet) say(stderr, `${PROG}: ${text}`);
  };

  // --- inputs, report files and the baseline: all checked before anything is sent ---------
  let targets = cl.targets;
  const inputs = {};
  let baseline = null;
  const jsonIsBaseline = !!(options.baseline && options.json && samePath(options.baseline, options.json));
  try {
    for (const file of options.lists) {
      const { targets: listed, invalid } = parseListText(command, decodeText(await readInput(file, '--list')));
      const what = COMMAND_SPECS[command].targets === 'names' ? 'a name a certificate can carry' : 'a domain name';
      for (const w of skippedWarnings(`--list ${file}`, invalid, what)) warn(w);
      for (const x of listed) if (!targets.includes(x)) targets = [...targets, x];
    }
    if (!targets.length) throw new UsageError(`${command}: no target: ${options.lists.map((f) => `--list ${f}`).join(', ')} names none`);
    if (COMMAND_SPECS[command].targets === 'file') {
      inputs.file = { name: basename(targets[0]), bytes: await readInput(targets[0]) };
    }
    if (command === 'audit') inputs.policy = await loadPolicy(options);
    if (options.exact) {
      const { valid, invalid } = parseHostList(decodeText(await readInput(options.exact, '--exact')));
      for (const w of skippedWarnings(`--exact ${options.exact}`, invalid, 'a host name')) warn(w);
      if (!valid.length) throw new UsageError(`--exact: ${options.exact} lists no host name`);
      inputs.exactNames = valid;
      inputs.exactFile = basename(options.exact);
    }
    await checkOutputPath(options.json, '--json');
    await checkOutputPath(options.md, '--md');
    if (options.baseline) baseline = await loadBaseline(options.baseline, command, { allowMissing: jsonIsBaseline });
  } catch (err) {
    return fail(err);
  }

  // --- the run --------------------------------------------------------------------------
  const t = await setupStrings();
  const dns = new DohClient({ chain: options.chain, concurrency: options.concurrency, fetchImpl });
  const startedAt = now();
  let result;
  const interrupted = () => {
    say(stderr, `${PROG}: interrupted: nothing written`);
    return EXIT.INTERRUPTED;
  };
  try {
    const { runCommand } = await import('./ds/commands.mjs');
    result = await runCommand(command, targets, options, { dns, fetchImpl, signal, now, t, progress, baseline, inputs });
  } catch (err) {
    if (errorKind(err) === 'abort' || (signal && signal.aborted)) return interrupted();
    return fail(err);
  }
  // A check stopped half-way is no report: it would be the next run's baseline.
  if (signal && signal.aborted) return interrupted();
  for (const w of result.warnings) warn(w);
  const report = {
    tool: DS_TOOL,
    version: DS_VERSION,
    command,
    startedAt: startedAt.toISOString(),
    finishedAt: now().toISOString(),
    options: result.options,
    ...(warnings.length ? { warnings: [...warnings] } : {}),
    targets: result.targets
  };

  // --- changes since the baseline ---------------------------------------------------------
  const run = { command, baseline: null, changes: [], notes: [] };
  if (options.baseline) {
    if (baseline) {
      let localParams;
      if (command === 'renew') ({ localParams } = await import('../assets/js/views/renew.js'));
      run.baseline = baselineInfo(baseline, options.baseline);
      run.changes = diffReports(command, baseline, report, { t, ...(localParams ? { localParams } : {}) });
      run.notes = baselineNotes(command, baseline, report);
    } else {
      run.baseline = { file: basename(options.baseline), missing: true };
    }
    report.baseline = run.baseline;
    report.changes = run.changes.map((c) => ({
      tag: c.tag, tone: c.tone, counts: c.counts, target: c.target, item: c.item, kind: c.kind, before: c.before, after: c.after, text: changeText(c)
    }));
  }

  // --- output ------------------------------------------------------------------------------
  if (!quiet) {
    const color = !options.noColor && !env.NO_COLOR && stdout.isTTY === true;
    say(stdout, renderRunText(run, result.docs, { color, showAll: options.showAll }));
  }
  let writeFailed = false;
  const write = async (path, text, label) => {
    if (!path) return;
    try {
      await replaceFile(path, text);
      if (!quiet) say(stderr, `${PROG}: ${label} written to ${path}`);
    } catch (err) {
      writeFailed = true;
      say(stderr, `${PROG}: error: cannot write ${path}: ${(err && err.code) || err}`);
    }
  };
  await write(options.md, renderRunMarkdown(run, result.docs), 'Markdown summary');
  await write(options.json, `${toJson(report)}\n`, 'JSON report');

  if (writeFailed) return EXIT.WRITE;
  // audit: a rule of the policy failed (one that could not be checked is no failure)
  if (result.failed) return EXIT.CHANGED;
  if (options.failOnChange && notableChanges(run.changes).length) return EXIT.CHANGED;
  return EXIT.OK;
}

/** Run as a program: Ctrl-C stops the run (nothing is written), a closed stdout is no error. */
async function cli() {
  const controller = new AbortController();
  const onSignal = () => controller.abort();
  process.once('SIGINT', onSignal);
  // A reader that goes away (`| head`) is not an error: the reports are still written.
  process.stdout.on('error', (err) => {
    if (err && err.code !== 'EPIPE') throw err;
  });
  const code = await main(process.argv.slice(2), { signal: controller.signal });
  process.removeListener('SIGINT', onSignal);
  process.exitCode = code;
  // A stopped run can leave requests nobody waits for (lib/rdap.js' shared bootstrap download is
  // bound by its own timeout and a retry, not by the run's signal): leave once the last line is
  // out rather than half a minute later. The timer keeps nothing alive by itself.
  if (code === EXIT.INTERRUPTED) setTimeout(() => process.exit(code), INTERRUPT_GRACE_MS).unref();
}

/** Is this module the program Node was started with (also through a symlinked path)? */
function isMain() {
  if (!process.argv[1]) return false;
  let invoked;
  try {
    invoked = realpathSync(process.argv[1]);
  } catch {
    invoked = resolvePath(process.argv[1]);
  }
  return samePath(invoked, fileURLToPath(import.meta.url));
}

if (isMain()) await cli();
