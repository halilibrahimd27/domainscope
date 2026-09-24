/**
 * Where the live scripts may write their reports (tests/live/targets.mjs reportPath).
 *
 * A live report (--json / --csv / --cache-dir) can name the private domains, zone labels and
 * origin IPs from the gitignored targets.local.json. It must never land in a file that
 * `git add -A` would stage, so a path inside the repository has to be gitignored; everything
 * else is refused before the run starts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  gitIgnores, isInsideDir, reportPath, writeReport, PRIVATE_OUTPUT_DIR, REPO_ROOT
} from '../live/targets.mjs';

const LIVE_DIR = fileURLToPath(new URL('../live/', import.meta.url));
const TARGETS_MODULE = join(LIVE_DIR, 'targets.mjs');

/** Is git usable on this repository (CI checkout or a local clone)? */
const HAS_GIT = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: REPO_ROOT, encoding: 'utf8' }).stdout?.trim() === 'true';

function withTmp(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'ds-report-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('isInsideDir: the folder itself and its children, never a sibling with a common prefix', () => {
  const root = join(tmpdir(), 'ds-root');
  assert.equal(isInsideDir(root, root), true);
  assert.equal(isInsideDir(join(root, 'a', 'b.json'), root), true);
  assert.equal(isInsideDir(join(root, '..foo.json'), root), true, 'a name starting with two dots is still a child');
  assert.equal(isInsideDir(join(`${root}-2`, 'x.json'), root), false);
  assert.equal(isInsideDir(join(root, '..', 'x.json'), root), false);
});

test('reportPath: a path inside the repository that git does not ignore is refused', () => {
  const asked = [];
  const isIgnored = (file) => { asked.push(file); return false; };
  assert.throws(() => reportPath('out.json', { cwd: REPO_ROOT, isIgnored }), /refusing to write .*not gitignored/);
  assert.throws(() => reportPath(join(REPO_ROOT, 'docs', 'bench.json'), { isIgnored }), /refusing/);
  // relative to the working directory, not to the script: `..` from tests/live reaches the repo root
  assert.throws(() => reportPath('../../bench.json', { cwd: LIVE_DIR, isIgnored }), /refusing/);
  assert.deepEqual(asked, [join(REPO_ROOT, 'out.json'), join(REPO_ROOT, 'docs', 'bench.json'), join(REPO_ROOT, 'bench.json')]);
});

test('reportPath: an ignored path inside the repository is accepted, resolved against the working directory', () => {
  const isIgnored = () => true;
  assert.equal(reportPath('tests/live/private/bench.json', { cwd: REPO_ROOT, isIgnored }), join(PRIVATE_OUTPUT_DIR, 'bench.json'));
  assert.equal(reportPath('private/bench.json', { cwd: LIVE_DIR, isIgnored }), join(PRIVATE_OUTPUT_DIR, 'bench.json'));
});

test('reportPath: a path outside the repository is used as given, without asking git', () => {
  withTmp((dir) => {
    const isIgnored = () => { throw new Error('git must not be asked about a path outside the repository'); };
    assert.equal(reportPath(join(dir, 'r.json'), { isIgnored }), join(dir, 'r.json'));
    assert.equal(reportPath('r.json', { cwd: dir, isIgnored }), join(dir, 'r.json'));
  });
});

test('reportPath: an empty name is an error', () => {
  assert.throws(() => reportPath(''), /file name is required/);
  assert.throws(() => reportPath('   '), /file name is required/);
});

test('reportPath with the real .gitignore: tests/live/private/ and *.local.json pass; tracked or plain repo files do not', { skip: !HAS_GIT && 'git is not available' }, () => {
  const opts = { cwd: REPO_ROOT };
  assert.equal(reportPath('tests/live/private/bench.json', opts), join(PRIVATE_OUTPUT_DIR, 'bench.json'));
  assert.equal(reportPath('tests/live/private/deep/er/scan.csv', opts), join(PRIVATE_OUTPUT_DIR, 'deep', 'er', 'scan.csv'));
  assert.equal(reportPath('bench.local.json', opts), join(REPO_ROOT, 'bench.local.json'));
  // an arbitrary new file in the repo root would show up in `git status` / `git add -A`
  assert.throws(() => reportPath('ds-report-guard-check.json', opts), /refusing/);
  // a tracked file counts as not ignored: a report must never overwrite repository content
  assert.throws(() => reportPath('README.md', opts), /refusing/);
  assert.throws(() => reportPath(join(REPO_ROOT, 'tests', 'fixtures', 'report.json')), /refusing/);
});

test('gitIgnores without git: only the private live folders and *.local.json count as ignored', () => {
  const saved = process.env.GIT_DIR;
  withTmp((dir) => {
    // GIT_DIR pointing nowhere makes every git command fail (exit 128), as on a machine without git
    process.env.GIT_DIR = join(dir, 'no-such-git-dir');
    try {
      assert.equal(gitIgnores(join(PRIVATE_OUTPUT_DIR, 'x.json')), true);
      assert.equal(gitIgnores(join(LIVE_DIR, '.cache', 'crtsh', 'x.json')), true);
      assert.equal(gitIgnores(join(REPO_ROOT, 'bench.local.json')), true);
      assert.equal(gitIgnores(join(REPO_ROOT, 'out-report.json')), false);
      assert.equal(gitIgnores(join(LIVE_DIR, 'private-notes.json')), false);
    } finally {
      if (saved === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = saved;
    }
  });
});

test('writeReport creates the missing folders', () => {
  withTmp((dir) => {
    const file = join(dir, 'a', 'b', 'report.json');
    writeReport(file, '{"ok":true}');
    assert.equal(readFileSync(file, 'utf8'), '{"ok":true}');
  });
});

test('reportPathOrExit stops a script with exit code 2 before it writes anything', { skip: !HAS_GIT && 'git is not available' }, () => {
  const name = 'ds-report-guard-check.json';
  const target = join(REPO_ROOT, name);
  const script = `import { reportPathOrExit } from ${JSON.stringify(pathToFileURL(TARGETS_MODULE).href)};\n`
    + 'const out = reportPathOrExit(process.argv[1]);\nconsole.log(`resolved ${out}`);\n';
  try {
    const bad = spawnSync(process.execPath, ['--input-type=module', '-e', script, name], { cwd: REPO_ROOT, encoding: 'utf8' });
    assert.equal(bad.status, 2, bad.stderr);
    assert.match(bad.stderr, /refusing to write/);
    assert.doesNotMatch(bad.stdout, /resolved/);
    assert.equal(existsSync(target), false);

    const good = spawnSync(process.execPath, ['--input-type=module', '-e', script, 'tests/live/private/x.json'], { cwd: REPO_ROOT, encoding: 'utf8' });
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /resolved .*private/);
  } finally {
    rmSync(target, { force: true });
  }
});

test('every live script that takes --json / --csv / --cache-dir routes it through reportPathOrExit', () => {
  const scripts = readdirSync(LIVE_DIR).filter((f) => f.endsWith('.mjs') && f !== 'targets.mjs');
  const writers = [];
  for (const f of scripts) {
    const src = readFileSync(join(LIVE_DIR, f), 'utf8');
    const options = ['--json', '--csv', '--cache-dir'].filter((o) => src.includes(`'${o}'`));
    if (!options.length) continue;
    writers.push(f);
    assert.match(src, /reportPathOrExit\(/, `${f} takes ${options.join(', ')} but never calls reportPathOrExit`);
    // a raw write can bypass the guard; reports go through writeReport()
    assert.doesNotMatch(src, /\bwriteFileSync\s*\(|\bwriteFile\s*\(/, `${f} writes a file directly instead of through writeReport()`);
    // no documented example writes a report to a plain file in the working directory
    for (const m of src.matchAll(/--(?:json|csv) (\S+)/g)) {
      if (m[1] === 'FILE') continue;
      assert.match(m[1], /^tests\/live\/private\/|\.local\.json$/, `${f}: example ${m[0]} is not a gitignored path`);
    }
  }
  assert.ok(writers.length >= 5, `expected the report-writing live scripts, found ${writers.join(', ')}`);
});
