/**
 * A DataTable column that sorts by ipSortValue sorts by a BigInt; its CSV / JSON export falls back to
 * the sort value unless the column says better. So every such column must carry an `exportValue`
 * (the address itself). Checked statically over the sources: the column object that contains
 * `ipSortValue(` must also contain `exportValue`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const JS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'assets', 'js');

function sources(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...sources(p));
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

/**
 * The text of the column around `index`: from the `key:` before it to the next column's `key:`
 * (or the end of the file). A column object is told apart by its `key:` property.
 */
function enclosingColumn(src, index) {
  const start = src.lastIndexOf('key:', index);
  const next = src.slice(index).search(/\bkey:/);
  const end = next === -1 ? src.length : index + next;
  return start === -1 ? '' : src.slice(start, end);
}

test('every column sorted by ipSortValue exports the address (exportValue)', () => {
  const bad = [];
  let seen = 0;
  for (const file of sources(JS)) {
    if (file.endsWith('components.js')) continue;
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/sortValue\s*:[^\n]*ipSortValue\(/g)) {
      seen++;
      if (!/\bexportValue\s*:/.test(enclosingColumn(src, m.index))) bad.push(`${file.slice(JS.length + 1)}:${src.slice(0, m.index).split('\n').length}`);
    }
  }
  assert.ok(seen >= 15, `found only ${seen} ipSortValue columns: the scan is broken`);
  assert.deepEqual(bad, [], 'columns with ipSortValue and no exportValue');
});
