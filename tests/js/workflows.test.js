/**
 * The GitHub Actions workflows (plain-text checks, no YAML dependency):
 * - CI runs on pushes to main, pull requests, by hand and as a reusable workflow, and includes
 *   the offline E2E suites;
 * - Deploy to GitHub Pages runs CI first and deploys only when it passes, never cancels a running
 *   deployment, and publishes the bundle of tools/assemble-site.mjs.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');
const ci = read('.github/workflows/ci.yml');
const pages = read('.github/workflows/pages.yml');
const pkg = JSON.parse(read('package.json'));

/** Lines of a top-level block (`on:`, `jobs:`) up to the next top-level key. */
function block(yaml, key) {
  const lines = yaml.split('\n');
  const start = lines.indexOf(`${key}:`);
  if (start === -1) return [];
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    out.push(line);
  }
  return out;
}

/** Keys at exactly `indent` spaces in a block. */
const keysAt = (lines, indent) => lines
  .filter((l) => new RegExp(`^ {${indent}}[A-Za-z_][\\w-]*:`).test(l))
  .map((l) => l.trim().split(':')[0]);

/** Job id → the text of its body. */
function jobs(yaml) {
  const out = {};
  let current = null;
  for (const line of block(yaml, 'jobs')) {
    const m = /^ {2}([A-Za-z_][\w-]*):\s*$/.exec(line);
    if (m) {
      current = m[1];
      out[current] = '';
    } else if (current) {
      out[current] += `${line}\n`;
    }
  }
  return out;
}

describe('ci.yml', () => {
  test('runs on pushes to main, pull requests, by hand and when called by another workflow', () => {
    assert.match(ci, /^name: CI$/m);
    assert.deepEqual(keysAt(block(ci, 'on'), 2).sort(), ['pull_request', 'push', 'workflow_call', 'workflow_dispatch']);
    assert.match(block(ci, 'on').join('\n'), /push:\n {4}branches: \[main\]/);
  });

  test('has the unit, CLI and offline E2E jobs', () => {
    const j = jobs(ci);
    assert.deepEqual(Object.keys(j).sort(), ['e2e', 'js', 'python']);
    assert.match(j.js, /node --test "tests\/js\/\*\.test\.js"/);
    assert.match(j.python, /python -m unittest discover -s tests\/python/);
    assert.match(j.e2e, /runs-on: ubuntu-latest/);
    assert.match(j.e2e, /run: npm run test:e2e:offline/);
    assert.match(j.e2e, /timeout-minutes: \d+/, 'a hung browser must not hold the deploy');
  });

  test('the offline E2E script runs exactly the suites that need no network', () => {
    const cmd = pkg.scripts['test:e2e:offline'];
    assert.match(cmd, /^node tests\/e2e\/run-all\.mjs --only shell,zone,verify,dane,global,ptr --offline --no-shots$/);
    for (const suite of ['shell', 'zone', 'verify', 'dane', 'global']) assert.ok(existsSync(join(ROOT, 'tests', 'e2e', `${suite}.e2e.mjs`)), suite);
    // global also has live resolver groups: --offline keeps it to its fake-DoH steps.
    assert.match(readFileSync(join(ROOT, 'tests', 'e2e', 'global.e2e.mjs'), 'utf8'), /if \(OFFLINE\)[^\n]*\n\s*else await liveChecks\(/);
  });
});

describe('pages.yml', () => {
  const j = jobs(pages);

  test('deploys pushes to main and manual runs, one at a time, never cancelling a running deployment', () => {
    assert.deepEqual(keysAt(block(pages, 'on'), 2).sort(), ['push', 'workflow_dispatch']);
    assert.match(block(pages, 'on').join('\n'), /push:\n {4}branches: \[main\]/);
    assert.match(pages, /^concurrency:\n {2}group: pages\n {2}cancel-in-progress: false$/m);
    assert.doesNotMatch(pages, /cancel-in-progress: true/);
  });

  test('the deploy job needs the whole CI workflow', () => {
    assert.deepEqual(Object.keys(j).sort(), ['deploy', 'test']);
    assert.match(j.test, /^ {4}uses: \.\/\.github\/workflows\/ci\.yml$/m);
    assert.match(j.deploy, /^ {4}needs: test$/m);
    assert.match(j.deploy, /^ {6}pages: write$/m);
    assert.match(j.deploy, /^ {6}id-token: write$/m);
    assert.doesNotMatch(block(pages, 'permissions').join('\n'), /write/, 'write access only in the deploy job');
  });

  test('publishes the versioned bundle of tools/assemble-site.mjs', () => {
    assert.match(j.deploy, /run: node tools\/assemble-site\.mjs _site "\$\{GITHUB_SHA::12\}"/);
    assert.match(j.deploy, /upload-pages-artifact@v\d+\n {8}with:\n {10}path: _site\n {10}include-hidden-files: true/);
    assert.doesNotMatch(j.deploy, /cp -r assets/, 'assets/ is copied under v/<commit>/ by the tool, not at the root');
    assert.ok(existsSync(join(ROOT, 'tools', 'assemble-site.mjs')));
  });
});
