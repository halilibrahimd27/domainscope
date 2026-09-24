/**
 * Entry point that makes `node --test tests/js/` work — with the SAME per-file
 * isolation as `node --test "tests/js/*.test.js"` (npm test, CI).
 *
 * Since Node 21 the test runner treats positional arguments as glob patterns and
 * runs a bare directory path as a module, which resolves to this index file.
 * Importing every test file here would run the whole suite in ONE process, where
 * module state (the shared i18n dictionary, caches, registered views) leaks from
 * one file into the next and results depend on file order. Instead, each
 * *.test.js file runs in its own `node --test` child process, exactly like the
 * glob form; this file reports one test per file (with the child's pass / fail
 * counts as diagnostics) and fails a file's test with the child's output when
 * that file has a failing test.
 *
 * `node --test "tests/js/*.test.js"` and a bare `node --test` never pick this
 * file up (it does not match *.test.js).
 */
import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const files = readdirSync(here).filter((f) => f.endsWith('.test.js')).sort();

/** Run one test file in a fresh `node --test` process (TAP output). */
function runFile(file) {
  // NODE_TEST_CONTEXT marks a process as a child of a running test runner; a nested
  // `node --test` that inherits it refuses to run files. Start a clean runner instead.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', join(here, file)], {
      cwd: join(here, '..', '..'), env, stdio: ['ignore', 'pipe', 'pipe']
    });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    child.on('close', (code) => resolve({ code, out }));
    child.on('error', (err) => resolve({ code: -1, out: String(err) }));
  });
}

/** `# pass N` / `# fail N` summary lines of a TAP stream. */
function tapCount(out, key) {
  const m = new RegExp(`^# ${key} (\\d+)`, 'm').exec(out);
  return m ? Number(m[1]) : null;
}

describe('tests/js (one process per file, as in CI)', { concurrency: Math.max(1, Math.min(8, availableParallelism())) }, () => {
  for (const file of files) {
    it(file, async (t) => {
      const { code, out } = await runFile(file);
      const pass = tapCount(out, 'pass');
      const fail = tapCount(out, 'fail');
      t.diagnostic(`${file}: ${pass ?? '?'} passed, ${fail ?? '?'} failed`);
      if (code !== 0 || fail) {
        const failing = out.split(/\r?\n/).filter((l) => /^\s*not ok /.test(l)).slice(0, 20).join('\n');
        throw new Error(`${file}: exit ${code}, ${fail ?? '?'} failing test(s)\n${failing}\n--- output (tail) ---\n${out.slice(-4000)}`);
      }
    });
  }
});
