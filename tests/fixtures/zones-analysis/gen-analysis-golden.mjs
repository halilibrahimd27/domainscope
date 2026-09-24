#!/usr/bin/env node
/**
 * gen-analysis-golden.mjs — goldens of the zone-import analysis libraries
 * (lib/zonelint.js, lib/zoneorigins.js, lib/zonedrift.js planning).
 *
 * Inputs are parsed zones in the lib/zoneparse.js `Zone` shape
 * (`inputs/<name>.zone.json`, built from the design samples with documentation
 * addresses only). For each one this writes, under `expected/`:
 *   <name>.analysis.golden.txt  one line per item (lint, seeds, origins, addresses,
 *                               hand-off, sweep sizes, drift plan), human-diffable
 *   <name>.handoff.json         the CLI hand-off in both scopes (CLI `--zone` conformance)
 *   <name>.names.txt / .targets.txt   handoffFiles() of the proxied sweep, fixed clock and
 *                               inventory (only when the proxied hand-off is not empty)
 * plus `zone-constants.json` (the constants the CLI port must mirror).
 *
 *   node tests/fixtures/zones-analysis/gen-analysis-golden.mjs          # diff against disk, exit 1 on change
 *   node tests/fixtures/zones-analysis/gen-analysis-golden.mjs --write  # rewrite the files
 *
 * The unit tests import {@link goldenFiles} and compare with the files on disk. A change
 * to the parser's output shape reruns this generator in the same change.
 */

import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { lintZone } from '../../../assets/js/lib/zonelint.js';
import {
  deriveSeeds, proxiedOriginMap, addressMap, cliHandoff, zoneSweep, handoffFiles, zoneScanInput,
  privateLookingNames, zoneConstants
} from '../../../assets/js/lib/zoneorigins.js';
import { planDrift } from '../../../assets/js/lib/zonedrift.js';
import { parseInventory, buildIpIndex } from '../../../assets/js/lib/inventory.js';
import { sortHostnames } from '../../../assets/js/lib/domain.js';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const GOLDEN_NOW = new Date(Date.UTC(2026, 0, 1));
export const GOLDEN_INVENTORY = 'web01 192.0.2.10\nweb02 198.51.100.20';

/** Fixture names (sorted) from `inputs/*.zone.json`. */
export function fixtureNames() {
  return readdirSync(join(HERE, 'inputs')).filter((f) => f.endsWith('.zone.json')).map((f) => f.slice(0, -'.zone.json'.length)).sort();
}

/** @returns {object} the parsed Zone of a fixture */
export function loadFixture(name) {
  return JSON.parse(readFileSync(join(HERE, 'inputs', `${name}.zone.json`), 'utf8'));
}

function val(v) {
  if (v === null || v === undefined) return '-';
  if (Array.isArray(v)) return v.length ? v.map(val).join(',') : '-';
  const s = String(v);
  return s === '' || /[\s"]/.test(s) ? JSON.stringify(s) : s;
}

const kv = (obj) => Object.entries(obj).map(([k, v]) => `${k}=${val(v)}`).join(' ');

/**
 * Every golden file of one fixture.
 * @param {string} name
 * @param {object} zone
 * @returns {Map<string, string>} path relative to this directory → content
 */
export function goldenFiles(name, zone) {
  const inventoryIndex = buildIpIndex(parseInventory(GOLDEN_INVENTORY).servers);
  const lines = [`# ${name}.zone.json — analysis golden (gen-analysis-golden.mjs; regenerate with --write)`];
  lines.push(`zone ${kv({ format: zone.format, dialect: zone.dialect, origin: zone.origin, partial: !!zone.partial })}`);

  const lint = lintZone(zone);
  for (const f of lint.findings) lines.push(`lint ${f.severity} ${f.code} ${f.name} ${f.type || '-'} @${f.line} ${kv(f.params)}`.trimEnd());

  const seeds = deriveSeeds(zone, { lint });
  for (const n of seeds.names) lines.push(`seed ${n}`);
  for (const b of seeds.wildcardBases) lines.push(`wildcard ${b}`);
  for (const d of seeds.delegations) lines.push(`delegation ${d}`);
  for (const e of seeds.excluded) lines.push(`exclude ${e.name} ${e.why}`);
  for (const n of sortHostnames([...privateLookingNames(zone)])) lines.push(`private ${n}`);

  const origins = proxiedOriginMap(zone, { inventoryIndex });
  for (const o of origins) {
    const value = o.ips.length ? o.ips.join(',') : o.host || '-';
    lines.push(`origin ${o.name} ${o.kind} ${value} via ${val(o.via)} provider ${val(o.provider)}`
      + ` servers ${val(o.servers.map((s) => s.name))} exposure ${val(o.exposure.map((e) => `${e.by}:${e.name}`))}`
      + `${o.private ? ' private' : ''}${o.ignored.length ? ` ignored ${o.ignored.join(',')}` : ''}`);
  }
  for (const a of addressMap(zone, { inventoryIndex })) {
    const names = a.names.map((n) => `${n.name}${n.proxied ? '*' : ''}${n.exposed ? '!' : ''}${n.via ? '~' : ''}${n.occluded ? '#' : ''}`);
    lines.push(`address ${a.ip} ${names.join(' ')} servers ${val(a.servers.map((s) => s.name))}`
      + `${a.provider ? ` provider ${a.provider}` : ''}${a.private ? ' private' : ''}${a.placeholder ? ' placeholder' : ''}`);
  }

  const handoff = cliHandoff(zone, { origins });
  for (const t of handoff.targets) lines.push(`handoff target ${t}`);
  for (const h of handoff.hostTargets) lines.push(`handoff host ${h}`);
  for (const n of handoff.names) lines.push(`handoff name ${n}`);
  for (const s of handoff.skipped) lines.push(`skip ${s.name} ${s.kind} ${val(s.detail)}`);
  for (const d of [...handoff.dropped.targets, ...handoff.dropped.names]) lines.push(`dropped ${val(d)}`);

  const proxied = zoneSweep(zone, { origins });
  const all = zoneSweep(zone, { origins, scope: 'all' });
  for (const s of [proxied, all]) {
    lines.push(`sweep ${s.scope} ${kv({ targets: s.targets.length, hosts: s.hostTargets.length, names: s.names.length, tokens: s.tokens, chars: s.chars, probes: s.probes, probesAtLeast: s.probesAtLeast, fileForm: s.fileForm })}`);
  }

  const scan = zoneScanInput(zone);
  lines.push(`scan ${kv({ names: scan.names.length, wildcardBases: scan.wildcardBases.length, delegations: scan.delegations.length, proxied: scan.proxied.length, skipped: scan.skipped })}`);

  const plan = planDrift(zone);
  lines.push(`drift ${kv({ rrsets: plan.rrsets, queries: plan.queries, needed: plan.needed, names: plan.names, targetsHidden: plan.targetsHidden, internalShare: plan.internalShare.toFixed(3) })}`);
  lines.push(`drift skipped ${kv(plan.skipped)}`);

  const files = new Map();
  files.set(`expected/${name}.analysis.golden.txt`, `${lines.join('\n')}\n`);
  const scope = (s) => ({ names: s.names, targets: s.targets, hostTargets: s.hostTargets, skipped: s.skipped.map((x) => x.name) });
  files.set(`expected/${name}.handoff.json`, `${JSON.stringify({
    origin: zone.origin, format: zone.format, scopes: { proxied: scope(proxied), all: scope(all) }
  }, null, 2)}\n`);
  if (proxied.names.length && proxied.targets.length + proxied.hostTargets.length) {
    const { namesTxt, targetsTxt } = handoffFiles(proxied, { origin: zone.origin, inventoryIndex, now: GOLDEN_NOW });
    files.set(`expected/${name}.names.txt`, namesTxt);
    files.set(`expected/${name}.targets.txt`, targetsTxt);
  }
  return files;
}

/** The `zone-constants.json` content. */
export function constantsFile() {
  return `${JSON.stringify(zoneConstants(), null, 2)}\n`;
}

/** Every golden file of every fixture, plus the constants. */
export function allGoldenFiles() {
  const files = new Map();
  for (const name of fixtureNames()) for (const [p, c] of goldenFiles(name, loadFixture(name))) files.set(p, c);
  files.set('zone-constants.json', constantsFile());
  return files;
}

/** Minimal line diff (LCS) for the console. */
function diffLines(a, b) {
  const x = a.split('\n');
  const y = b.split('\n');
  const n = x.length;
  const m = y.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && x[i] === y[j]) { i += 1; j += 1; continue; }
    if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) out.push(`+ ${y[j++]}`);
    else out.push(`- ${x[i++]}`);
  }
  return out;
}

function main() {
  const write = process.argv.includes('--write');
  let changed = 0;
  for (const [rel, content] of allGoldenFiles()) {
    const path = join(HERE, rel);
    const old = existsSync(path) ? readFileSync(path, 'utf8') : '';
    if (old === content) continue;
    changed += 1;
    if (write) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      console.log(`wrote ${rel}`);
    } else {
      console.log(`--- ${rel}`);
      for (const line of diffLines(old, content)) console.log(line);
    }
  }
  if (!write && changed) {
    console.log(`${changed} golden file(s) differ; rerun with --write after reviewing`);
    process.exitCode = 1;
  } else if (!changed) {
    console.log('goldens up to date');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
