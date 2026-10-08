/**
 * The GitHub Actions workflows (plain-text checks, no YAML dependency):
 * - CI runs on pushes to main, pull requests, by hand and as a reusable workflow, and includes
 *   the offline E2E suites;
 * - Deploy to GitHub Pages runs CI first and deploys only when it passes, never cancels a running
 *   deployment, and publishes the bundle of tools/assemble-site.mjs;
 * - Intermediates rebuilds the CCADB intermediate list weekly, checks it, and proposes a change
 *   only as a pull request from its own branch.
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

  test('npm run test:py calls python3, which macOS and Linux have (the CLI job gets python from setup-python)', () => {
    assert.equal(pkg.scripts['test:py'], 'python3 -m unittest discover -s tests/python -v');
  });

  test('both READMEs say in Development that the tests need the Node 22 of package.json engines', () => {
    assert.equal(pkg.engines.node, '>=22');
    for (const [file, heading, says] of [['README.md', 'Development', /The tests need Node 22 or later/], ['README.tr.md', 'Geliştirme', /Testler Node 22 veya üstünü ister/]]) {
      const section = read(file).split(/^## /m).find((s) => s.startsWith(`${heading}\n`));
      assert.ok(says.test(section), file);
    }
  });

  test('the offline E2E script runs exactly the suites that need no network', () => {
    const cmd = pkg.scripts['test:e2e:offline'];
    assert.match(cmd, /^node tests\/e2e\/run-all\.mjs --only shell,subdomains,zone,scan,verify,renewal,dane,pfx,chainfix,renew,estate,global,ptr,retire,carry,ip,lookup,health,workspaces,origins,domain,change,privacy,reports,portfolio --offline --no-shots$/);
    for (const suite of ['shell', 'subdomains', 'zone', 'scan', 'verify', 'renewal', 'dane', 'pfx', 'chainfix', 'renew', 'estate', 'global', 'ptr', 'retire', 'carry', 'ip', 'lookup', 'health', 'workspaces', 'origins', 'domain', 'change', 'privacy', 'reports', 'portfolio']) assert.ok(existsSync(join(ROOT, 'tests', 'e2e', `${suite}.e2e.mjs`)), suite);
    // ci.yml's step names the same suites, in the same order.
    const only = cmd.match(/--only (\S+)/)[1].split(',');
    const named = ci.match(/- name: Offline E2E \(([^)]+)\)/);
    assert.ok(named, 'the offline E2E step');
    assert.deepEqual(named[1].split(', '), only);
    // global also has live resolver groups: --offline keeps it to its fake-DoH steps.
    assert.match(readFileSync(join(ROOT, 'tests', 'e2e', 'global.e2e.mjs'), 'utf8'), /if \(OFFLINE\)[^\n]*\n\s*else await liveChecks\(/);
    // subdomains too (live scans): --offline skips them, and only the local server resolves.
    const sub = readFileSync(join(ROOT, 'tests', 'e2e', 'subdomains.e2e.mjs'), 'utf8');
    assert.match(sub, /const liveStep = \(name, fn\) => \{\s*if \(!OFFLINE\) return run\.step\(name, fn\);/);
    assert.match(sub, /args: OFFLINE \? \['--host-resolver-rules=MAP \* ~NOTFOUND , EXCLUDE 127\.0\.0\.1'\] : \[\]/);
    // scan too (its live desktop and phone groups): --offline skips them, only the local server resolves.
    const scan = readFileSync(join(ROOT, 'tests', 'e2e', 'scan.e2e.mjs'), 'utf8');
    assert.match(scan, /const OFFLINE = opts\.has\('--offline'\);/);
    assert.match(scan, /if \(OFFLINE\) \{[^}]*SKIP {2}the live scan \(--offline\)[\s\S]*?\} else \{\s*run\.group\('Desktop 1440×900 \(English\)'\);/);
    assert.match(scan, /args: OFFLINE \? \['--host-resolver-rules=MAP \* ~NOTFOUND , EXCLUDE 127\.0\.0\.1'\] : \[\]/);
    // ip, lookup and health have live API groups: --offline keeps them to their offline group.
    for (const suite of ['ip', 'lookup']) {
      assert.match(readFileSync(join(ROOT, 'tests', 'e2e', `${suite}.e2e.mjs`), 'utf8'), /if \(!OFFLINE\) await liveGroups\(/, suite);
    }
    assert.match(readFileSync(join(ROOT, 'tests', 'e2e', 'health.e2e.mjs'), 'utf8'), /if \(OFFLINE\)[^\n]*\n\s*else await liveGroups\(/);
  });
});

describe('intermediates.yml', () => {
  const yml = read('.github/workflows/intermediates.yml');
  const j = jobs(yml);

  test('runs weekly and by hand, one at a time', () => {
    assert.match(yml, /^name: Intermediates$/m);
    assert.deepEqual(keysAt(block(yml, 'on'), 2).sort(), ['schedule', 'workflow_dispatch']);
    assert.match(block(yml, 'on').join('\n'), /schedule:\n {4}- cron: '\d+ \d+ \* \* \d'/);
    assert.match(yml, /^concurrency:\n {2}group: intermediates\n {2}cancel-in-progress: false$/m);
  });

  test('builds, checks the data before anything is pushed, and only ever proposes it in a pull request', () => {
    assert.deepEqual(Object.keys(j), ['rebuild']);
    assert.doesNotMatch(block(yml, 'permissions').join('\n'), /write/, 'write access only in the job');
    assert.match(j.rebuild, /^ {6}contents: write$/m);
    assert.match(j.rebuild, /^ {6}pull-requests: write$/m);
    const build = j.rebuild.indexOf('run: node tools/build-intermediates.mjs');
    const check = j.rebuild.indexOf('run: node --test tests/js/build-intermediates.test.js');
    const push = j.rebuild.indexOf('git push --force origin "$branch"');
    assert.ok(build > 0 && check > build && push > check, 'build, then check, then push');
    assert.match(j.rebuild, /^ {10}branch=bot\/intermediates$/m);
    assert.match(j.rebuild, /git add -- assets\/data\/intermediates/);
    assert.match(j.rebuild, /gh pr create --head "\$branch" --base main/);
    assert.doesNotMatch(j.rebuild, /push[^\n]*\bmain\b/, 'never pushes to main');
    assert.ok(existsSync(join(ROOT, 'tools', 'build-intermediates.mjs')));
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
    assert.match(j.deploy, /upload-pages-artifact@[0-9a-f]{40} # v\d+\.\d+\.\d+\n {8}with:\n {10}path: _site\n {10}include-hidden-files: true/);
    assert.doesNotMatch(j.deploy, /cp -r assets/, 'assets/ is copied under v/<commit>/ by the tool, not at the root');
    assert.ok(existsSync(join(ROOT, 'tools', 'assemble-site.mjs')));
  });
});

test('every action of the workflows and the nightly template is pinned to a commit SHA, its version in a comment', () => {
  // A tag can be moved; a commit cannot. The deploy job can write to Pages, the bot job to this
  // repository, and the template's copies to their users' repositories.
  for (const file of ['.github/workflows/ci.yml', '.github/workflows/intermediates.yml', '.github/workflows/pages.yml', 'docs/examples/nightly-domainscope.yml']) {
    const uses = [...read(file).matchAll(/^ +(?:- )?uses: (.+)$/gm)].map((m) => m[1]).filter((u) => !u.startsWith('./'));
    assert.ok(uses.length >= 2, file);
    for (const u of uses) assert.match(u, /^actions\/[a-z-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/, `${file}: ${u}`);
  }
});
