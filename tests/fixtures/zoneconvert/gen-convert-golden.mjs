#!/usr/bin/env node
/**
 * Goldens of assets/js/lib/zoneconvert.js — each input zone written for every target (BIND, a
 * Route 53 change batch, octoDNS YAML, DNSControl), with the pitfalls it raised and the records it
 * left out or wrote differently.
 *
 *   node tests/fixtures/zoneconvert/gen-convert-golden.mjs            # compare, print the first difference, exit 1 on change
 *   node tests/fixtures/zoneconvert/gen-convert-golden.mjs --write    # rewrite expected/<case>.golden.txt
 *
 * One file per input, sections `## <target>` (the file as written), `## <target> pitfalls`
 * (`severity code ×count: names`) and `## <target> left out` / `## <target> changed` (`line code`).
 * Inputs: pitfalls.zone.txt (every pitfall in one zone) and three of tests/fixtures/zones/ (a
 * Cloudflare export, Route 53 JSON with aliases and routing, octoDNS YAML). Names are example.com /
 * .net / .org, addresses documentation space.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseZone } from '../../../assets/js/lib/zoneparse.js';
import { convertZone, CONVERT_TARGETS } from '../../../assets/js/lib/zoneconvert.js';

export const CONVERT_DIR = dirname(fileURLToPath(import.meta.url));
const ZONES = join(CONVERT_DIR, '..', 'zones');
const EXPECTED = join(CONVERT_DIR, 'expected');

/** The inputs: id → file (read with its own name, so octoDNS takes the zone name from it). */
export const CASES = Object.freeze([
  { id: 'pitfalls', file: join(CONVERT_DIR, 'pitfalls.zone.txt'), name: 'pitfalls.zone.txt', origin: 'example.com' },
  { id: 'cloudflare-export', file: join(ZONES, 'cloudflare-export.txt'), name: 'cloudflare-export.txt' },
  { id: 'route53', file: join(ZONES, 'route53.json'), name: 'route53.json' },
  { id: 'octodns', file: join(ZONES, 'example.com.yaml'), name: 'example.com.yaml' }
]);

/** The parsed zone of a case. */
export function caseZone(c) {
  return parseZone(readFileSync(c.file, 'utf8').replace(/\r\n/g, '\n'), { filename: c.name, origin: c.origin || null });
}

/** The golden text of a case: every target's file, pitfalls, left-out and changed records. */
export function caseGolden(c) {
  const zone = caseZone(c);
  const line = (r) => (r ? `${r.line} ${r.name} ${r.type}` : '?');
  const byId = new Map(zone.records.map((r) => [r.id, r]));
  const out = [`# ${c.id}: ${zone.records.length} records, origin ${zone.origin}`];
  for (const target of CONVERT_TARGETS) {
    const res = convertZone(zone, target);
    out.push(`## ${target} (${res.filename}, ${res.mime}, ${res.written} written)`, res.text.replace(/\n$/, ''));
    out.push(`## ${target} pitfalls`, ...res.pitfalls.map((p) => {
      const extra = Object.entries(p.params).filter(([k]) => k !== 'target').map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : v}`);
      return `${p.severity} ${p.code} ×${p.count}: ${p.names.join(' ')}${extra.length ? ` [${extra.join(' ')}]` : ''}`;
    }));
    if (res.omitted.length) out.push(`## ${target} left out`, ...res.omitted.map((x) => `${line(byId.get(x.id))} ${x.code}`));
    if (res.changed.length) out.push(`## ${target} changed`, ...res.changed.map((x) => `${line(byId.get(x.id))} ${x.code}`));
  }
  return `${out.join('\n')}\n`;
}

export const goldenPath = (id) => join(EXPECTED, `${id}.golden.txt`);

function main() {
  const write = process.argv.includes('--write');
  if (write) mkdirSync(EXPECTED, { recursive: true });
  let changed = 0;
  for (const c of CASES) {
    const text = caseGolden(c);
    const path = goldenPath(c.id);
    const old = existsSync(path) ? readFileSync(path, 'utf8').replace(/\r\n/g, '\n') : null;
    if (old === text) continue;
    changed += 1;
    if (write) {
      writeFileSync(path, text);
      process.stdout.write(`wrote ${c.id}\n`);
    } else {
      const a = (old || '').split('\n');
      const b = text.split('\n');
      const i = b.findIndex((l, n) => l !== a[n]);
      process.stdout.write(`${c.id}: line ${i + 1}\n- ${a[i] ?? '(none)'}\n+ ${b[i] ?? '(none)'}\n`);
    }
  }
  if (!write && changed) process.exitCode = 1;
  process.stdout.write(`${CASES.length} cases, ${changed} ${write ? 'written' : 'different'}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
