/**
 * tools/ds/history.mjs and the runner's `--history DIR`: the option on the command line, the
 * directory checked before the run, one line per target appended to the month's file (a month
 * rollover starts the next file), month files older than 13 months deleted, and the write whole or
 * not at all (a temporary file renamed over the month's). Offline runs of main() over the fake DoH
 * of tests/js/ds-fake-doh.mjs; the lines are read back with lib/monitor.js as the Monitoring view
 * reads them.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCommandLine, UsageError, USAGE, EXIT } from '../../tools/ds/args.mjs';
import { appendHistory, checkHistoryDir, writeWhole, HISTORY_KEEP_MONTHS } from '../../tools/ds/history.mjs';
import { main } from '../../tools/ds.mjs';
import { parseHistory } from '../../assets/js/lib/monitor.js';
import { zoneTable, createFakeFetch } from './ds-fake-doh.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'ds-history-'));
const sink = () => ({ text: '', write(s) { this.text += s; return true; } });
const ACTIONS = { GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'example-org/nightly', GITHUB_RUN_ID: '42' };
const doc = (finishedAt, targets, changes) => ({
  tool: 'domainscope-ds', version: '1.0.0', command: 'health', startedAt: finishedAt, finishedAt, options: {}, targets, ...(changes ? { changes } : {})
});
const health = (target, score) => ({ target, score, grade: score >= 90 ? 'A' : 'B', failedLookups: [], checks: [] });
const read = (path) => parseHistory(readFileSync(path, 'utf8'));

describe('--history on the command line', () => {
  test('a directory every command takes; "-", an empty one and a report\'s own path are refused', () => {
    assert.equal(parseCommandLine(['health', 'example.com']).options.history, null);
    assert.equal(parseCommandLine(['health', 'example.com', '--history', 'results/history']).options.history, 'results/history');
    assert.equal(parseCommandLine(['tls', 'www.example.com', '--history', 'h']).options.history, 'h');
    for (const [argv, message] of [
      [['health', 'example.com', '--history', '-'], /--history takes a directory/],
      [['health', 'example.com', '--history', ' '], /--history takes a directory/],
      [['health', 'example.com', '--history', 'h.json', '--json', 'h.json'], /--history names a directory, not the same path as --json/],
      [['health', 'example.com', '--history', 'h.json', '--baseline', 'h.json'], /--history names a directory, not the same path as --baseline/]
    ]) assert.throws(() => parseCommandLine(argv), (e) => e instanceof UsageError && message.test(e.message), argv.join(' '));
    assert.match(USAGE, /--history DIR {8}also append one JSON line per target to DIR\/YYYY-MM\.jsonl/);
    assert.match(USAGE, /month files older than 13 months are deleted/);
  });

  test('the directory is checked before the run: a file, or a missing one under a missing parent, is refused', async () => {
    const dir = tmp();
    try {
      writeFileSync(join(dir, 'file'), 'x');
      await assert.rejects(checkHistoryDir(join(dir, 'file')), /--history: .* is not a directory/);
      await assert.rejects(checkHistoryDir(join(dir, 'missing', 'history')), /--history: directory does not exist/);
      await checkHistoryDir(join(dir, 'history')); // created with the first line
      assert.ok(!existsSync(join(dir, 'history')), 'nothing created before the run');
      await checkHistoryDir(dir);
      assert.deepEqual(readdirSync(dir), ['file'], 'the probe file is gone');
      await checkHistoryDir(null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('appendHistory', () => {
  test('appends a run\'s lines to its month file; the next month starts the next file', async () => {
    const dir = tmp();
    try {
      const hist = join(dir, 'history');
      const one = await appendHistory(hist, doc('2026-10-31T03:20:00.000Z', [health('example.com', 90), health('example.org', 70)]), { now: new Date('2026-10-31T03:21:00Z'), env: ACTIONS });
      assert.deepEqual([one.lines, one.pruned], [2, []]);
      assert.ok(one.file.endsWith('2026-10.jsonl'));
      const two = await appendHistory(hist, doc('2026-10-31T23:59:00.000Z', [health('example.com', 82)], [
        { tag: 'SCORE', tone: 'info', counts: true, target: 'example.com', item: null, kind: 'changed', text: 'x' }
      ]), { now: new Date('2026-10-31T23:59:30Z') });
      assert.equal(two.lines, 1);
      const three = await appendHistory(hist, doc('2026-11-01T00:00:05.000Z', [health('example.com', 82)]), { now: new Date('2026-11-01T00:00:10Z') });
      assert.ok(three.file.endsWith('2026-11.jsonl'), 'a month rollover starts the next file');
      assert.deepEqual(readdirSync(hist).sort(), ['2026-10.jsonl', '2026-11.jsonl']);
      const oct = read(join(hist, '2026-10.jsonl'));
      assert.deepEqual(oct.skipped, []);
      assert.deepEqual(oct.lines.map((l) => `${l.target} ${l.score} ${l.counts.info}`), ['example.com 90 0', 'example.org 70 0', 'example.com 82 1']);
      assert.equal(oct.lines[0].run, 'https://github.com/example-org/nightly/actions/runs/42', 'the Actions run of the line');
      assert.ok(!('run' in oct.lines[2]), 'no run outside Actions');
      assert.equal(read(join(hist, '2026-11.jsonl')).lines.length, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a file whose last line has no newline (edited by hand) still gets its lines on lines of their own', async () => {
    const dir = tmp();
    try {
      writeFileSync(join(dir, '2026-10.jsonl'), '{"v":1,"note":"by hand"}');
      await appendHistory(dir, doc('2026-10-08T03:20:00.000Z', [health('example.com', 90)]), { now: new Date('2026-10-08T03:21:00Z') });
      const text = readFileSync(join(dir, '2026-10.jsonl'), 'utf8');
      assert.equal(text.split('\n').length, 3);
      assert.deepEqual(parseHistory(text).skipped.map((s) => s.why), ['at'], 'the hand-made line is skipped, the run\'s is read');
      assert.equal(parseHistory(text).lines.length, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('month files older than 13 months are deleted on write; nothing else is touched', async () => {
    const dir = tmp();
    try {
      for (const name of ['2025-08.jsonl', '2025-09.jsonl', '2025-10.jsonl', '2026-09.jsonl', 'notes.md', '2025-01.json']) writeFileSync(join(dir, name), '\n');
      mkdirSync(join(dir, 'keep'));
      const out = await appendHistory(dir, doc('2026-10-08T03:20:00.000Z', [health('example.com', 90)]), { now: new Date('2026-10-08T03:21:00Z') });
      assert.deepEqual(out.pruned, ['2025-08.jsonl', '2025-09.jsonl']);
      assert.deepEqual(readdirSync(dir).sort(), ['2025-01.json', '2025-10.jsonl', '2026-09.jsonl', '2026-10.jsonl', 'keep', 'notes.md']);
      assert.equal(HISTORY_KEEP_MONTHS, 13);
      // a run with no target writes no line, and still prunes
      writeFileSync(join(dir, '2025-07.jsonl'), '\n');
      const empty = await appendHistory(dir, doc('2026-10-09T03:20:00.000Z', []), { now: new Date('2026-10-09T03:21:00Z') });
      assert.deepEqual([empty.lines, empty.pruned], [0, ['2025-07.jsonl']]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('whole or not at all: a write that fails leaves the month file as it was and no temporary file', async () => {
    const dir = tmp();
    try {
      const path = join(dir, '2026-10.jsonl');
      writeFileSync(path, '{"kept":true}\n');
      await writeWhole(path, 'new\n');
      assert.equal(readFileSync(path, 'utf8'), 'new\n');
      // the month's "file" is a directory: the rename fails, nothing is left behind
      mkdirSync(join(dir, 'sub'));
      mkdirSync(join(dir, 'sub', '2026-10.jsonl'));
      await assert.rejects(appendHistory(join(dir, 'sub'), doc('2026-10-08T03:20:00.000Z', [health('example.com', 90)]), { now: new Date('2026-10-08T03:21:00Z') }));
      assert.deepEqual(readdirSync(join(dir, 'sub')), ['2026-10.jsonl']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('main() with --history', () => {
  test('a first run and a run with changes append their lines; a history that cannot be written is exit 3; a file is exit 2 before the run', async () => {
    const dir = tmp();
    try {
      const table = zoneTable();
      const json = join(dir, 'health.json');
      const hist = join(dir, 'results', 'history');
      mkdirSync(join(dir, 'results'));
      const run = async (now, fetchImpl, extra = []) => {
        const stdout = sink();
        const stderr = sink();
        const code = await main(['health', 'example.com', '--json', json, '--baseline', json, '--history', hist, ...extra], { stdout, stderr, fetchImpl, env: ACTIONS, now: () => now });
        return { code, err: stderr.text };
      };
      const first = await run(new Date('2026-10-08T03:20:00Z'), createFakeFetch(table));
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.err, /ds: history: 1 line added to .*2026-10\.jsonl/);
      const second = await run(new Date('2026-10-09T03:20:00Z'), createFakeFetch(table, { rcodes: { 'example.com|TXT': 'SERVFAIL' } }));
      assert.equal(second.code, EXIT.OK, second.err);
      const { lines, skipped } = read(join(hist, '2026-10.jsonl'));
      assert.deepEqual(skipped, []);
      assert.deepEqual(lines.map((l) => [l.at.slice(0, 10), l.ok, l.counts.bad > 0]), [['2026-10-08', true, false], ['2026-10-09', false, true]]);
      assert.ok(lines[1].changes.some((c) => c.tag === 'NEW' && c.item === 'spf.error'), JSON.stringify(lines[1].changes));
      assert.ok(Number.isFinite(lines[0].score) && /^[A-F]$/.test(lines[0].grade));
      // the month's file cannot be replaced (a directory in its place): the reports are written, exit 3
      rmSync(hist, { recursive: true });
      mkdirSync(join(hist, '2026-10.jsonl'), { recursive: true });
      const third = await run(new Date('2026-10-10T03:20:00Z'), createFakeFetch(table));
      assert.equal(third.code, EXIT.WRITE);
      assert.match(third.err, /error: cannot write the history in /);
      assert.match(third.err, /JSON report written to/);
      // a --history that is a file: refused before anything is sent
      writeFileSync(join(dir, 'h.txt'), 'x');
      let asked = 0;
      const stopped = await run(new Date('2026-10-11T03:20:00Z'), async () => { asked += 1; throw new Error('sent'); }, ['--history', join(dir, 'h.txt')]);
      assert.equal(stopped.code, EXIT.USAGE);
      assert.match(stopped.err, /--history: .*h\.txt is not a directory/);
      assert.equal(asked, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
