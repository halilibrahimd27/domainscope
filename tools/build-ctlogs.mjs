#!/usr/bin/env node
/**
 * build-ctlogs.mjs — the site's copy of Google's CT log list (assets/data/ctlogs.json): the
 * fallback of assets/js/lib/sct.js `loadCtLogList()` (spec §5.82) when the page cannot
 * fetch the live list (offline, or www.gstatic.com unreachable).
 *
 *   node tools/build-ctlogs.mjs              # download the live list and rewrite the copy
 *   node tools/build-ctlogs.mjs list.json    # build the copy from a v3 list saved earlier
 *   node tools/build-ctlogs.mjs --check      # exit 1 when the copy differs from the live list
 *
 * Maintainers run it; the site never does. No dependencies (Node 22 stdlib plus the app's own
 * lib/sct.js, so the page reads back exactly what the build wrote). The copy is the compact form
 * of `compactLogList()`: per operator its RFC 6962 and static-ct-api logs, each with its ID, name,
 * submission URL, key, state and the date it entered it, and its shard; one log a line, so a
 * refresh reads as a short diff. Nothing is written when the download does not look like the list
 * (fewer than 3 operators or 10 logs).
 */

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { CT_LOG_LIST_URL, compactLogList } from '../assets/js/lib/sct.js';

const OUT = fileURLToPath(new URL('../assets/data/ctlogs.json', import.meta.url));

/**
 * The snapshot of a v3 list (or throws when it does not look like one).
 * @param {any} json
 * @returns {{ format: number, source: string } & import('../assets/js/lib/sct.js').CompactLogList}
 */
export function buildSnapshot(json) {
  const list = compactLogList(json);
  if (!list) throw new Error('not a CT log list');
  const logs = list.operators.reduce((n, o) => n + o.logs.length, 0);
  if (list.operators.length < 3 || logs < 10) throw new Error(`implausible list: ${list.operators.length} operators, ${logs} logs`);
  return { format: 1, source: CT_LOG_LIST_URL, ...list };
}

/**
 * The snapshot as the file holds it: one log a line.
 * @param {ReturnType<typeof buildSnapshot>} s
 * @returns {string}
 */
export function serializeSnapshot(s) {
  const ops = s.operators.map((o) => `    { "name": ${JSON.stringify(o.name)}, "logs": [\n${o.logs.map((l) => `      ${JSON.stringify(l)}`).join(',\n')}\n    ] }`);
  return `{\n  "format": ${s.format},\n  "source": ${JSON.stringify(s.source)},\n  "version": ${JSON.stringify(s.version)},\n`
    + `  "timestamp": ${JSON.stringify(s.timestamp)},\n  "operators": [\n${ops.join(',\n')}\n  ]\n}\n`;
}

async function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const file = args.find((a) => !a.startsWith('--'));
  let json;
  if (file) json = JSON.parse(await readFile(file, 'utf8'));
  else {
    const res = await fetch(CT_LOG_LIST_URL, { signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${CT_LOG_LIST_URL}`);
    json = await res.json();
  }
  const text = serializeSnapshot(buildSnapshot(json));
  if (check) {
    const old = await readFile(OUT, 'utf8').catch(() => '');
    if (old !== text) {
      process.stdout.write('assets/data/ctlogs.json is out of date: run node tools/build-ctlogs.mjs\n');
      process.exitCode = 1;
    } else process.stdout.write('assets/data/ctlogs.json is current\n');
    return;
  }
  await writeFile(OUT, text);
  const s = JSON.parse(text);
  process.stdout.write(`wrote assets/data/ctlogs.json: list ${s.version} of ${s.timestamp}, ${s.operators.length} operators, `
    + `${s.operators.reduce((n, o) => n + o.logs.length, 0)} logs\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    process.stderr.write(`build-ctlogs: ${err.message}\n`);
    process.exitCode = 1;
  });
}
