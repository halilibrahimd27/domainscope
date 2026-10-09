/**
 * tools/ds/history.mjs — the runner's `--history DIR`: one JSON line per target of a run appended
 * to DIR/YYYY-MM.jsonl (the month of the run's end, UTC), the line the Monitoring view reads
 * (lib/monitor.js historyLines: the score, the soonest certificate expiry, whether the check
 * completed, the changes' tags, tones and items). An item names what moved — a finding or rule id,
 * a host, an RRset key, an issuer, a certificate's CT id or SHA-256, an endpoint's `address|port`,
 * a takeover risk's key —; nothing else of the report is kept: no change's words, no value before
 * or after. The nightly template writes results/history, which its commit step keeps with the
 * reports.
 *
 * - Whole or not at all, like `--json`: the month file is read, the run's lines added after it, and
 *   the result written to a temporary file in DIR that is renamed over it — a run stopped half-way
 *   leaves the file as it was, never a cut line. One writer at a time (the template's checks run one
 *   after the other; two runs at once could lose one run's lines, never damage the file).
 * - Month files older than {@link HISTORY_KEEP_MONTHS} months (this month and the twelve before it
 *   stay) are deleted after the write; nothing else in DIR is touched.
 * - DIR is created when it does not exist (its parent must); a DIR that is a file, or one where no
 *   file can be created, is refused before the run ({@link checkHistoryDir}).
 */

import { mkdir, open, readdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { historyLines, historyFileName, staleHistoryFiles, HISTORY_KEEP_MONTHS } from '../../assets/js/lib/monitor.js';
import { runUrl } from './notify.mjs';
import { UsageError } from './args.mjs';

export { HISTORY_KEEP_MONTHS };

/** A temporary file next to `path` (the same directory, so the rename replaces it whole). */
const tempPath = (path) => `${path}.${process.pid}.${Date.now().toString(36)}.tmp`;

/**
 * Write `path` whole or not at all: a temporary file next to it, renamed over it.
 * @param {string} path
 * @param {string} text
 */
export async function writeWhole(path, text) {
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
 * Refuse a `--history` directory that cannot take the run's lines, before the run: a file, a
 * directory where no file can be created, or a missing one whose parent does not exist.
 * @param {string|null} dir
 */
export async function checkHistoryDir(dir) {
  if (!dir) return;
  const abs = resolvePath(dir);
  const st = await stat(abs).catch(() => null);
  if (st && !st.isDirectory()) throw new UsageError(`--history: ${dir} is not a directory`);
  if (!st) {
    const parent = await stat(dirname(abs)).catch(() => null);
    if (!parent || !parent.isDirectory()) throw new UsageError(`--history: directory does not exist: ${dirname(abs)}`);
    return; // created with the first line
  }
  const probe = tempPath(join(abs, '.ds-history'));
  try {
    const handle = await open(probe, 'wx');
    await handle.close();
    await unlink(probe);
  } catch (err) {
    throw new UsageError(`--history: cannot create a file in ${dir} (each month file is replaced through a temporary file there): ${err && err.code ? err.code : err}`);
  }
}

/**
 * Append a run's lines to its month file and delete the month files past the history's age.
 * @param {string} dir
 * @param {object} report the run's report (tools/ds.mjs; its `changes` with --baseline)
 * @param {{ now?: Date, env?: Record<string, string|undefined> }} [opts] `env`: the GitHub Actions
 *   run's variables, for each line's `run` link
 * @returns {Promise<{ file: string, lines: number, pruned: string[] }>}
 */
export async function appendHistory(dir, report, { now = new Date(), env = {} } = {}) {
  const lines = historyLines(report, { run: runUrl(env) });
  const abs = resolvePath(dir);
  await mkdir(abs, { recursive: true });
  const name = historyFileName(report.finishedAt || now);
  const path = join(abs, name);
  if (lines.length) {
    let before = '';
    try {
      before = await readFile(path, 'utf8');
    } catch (err) {
      if (!err || err.code !== 'ENOENT') throw err;
    }
    // a last line without its newline (a file edited by hand) still ends before the new ones
    const head = before && !before.endsWith('\n') ? `${before}\n` : before;
    await writeWhole(path, `${head}${lines.map((l) => JSON.stringify(l)).join('\n')}\n`);
  }
  const pruned = [];
  for (const old of staleHistoryFiles(await readdir(abs), now)) {
    try {
      await unlink(join(abs, old));
      pruned.push(old);
    } catch {
      // gone already, or not ours to delete: the next run tries again
    }
  }
  return { file: path, lines: lines.length, pruned };
}
