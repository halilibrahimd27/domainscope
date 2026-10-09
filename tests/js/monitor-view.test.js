// views/monitor.js pure helpers over a made-up results folder (tests/js/monitor-fixture.mjs): the
// folder's files read into the open results (the summaries left alone, a damaged file named), what
// the page draws of them, the badge variants, the repository the links name, and every string key
// the view builds from a library code, in both languages. Pure Node (the view is DOM-free at import
// time).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { hasString, setLang, t } from '../../assets/js/i18n.js';
import {
  MONITOR_FILTERS, MONITOR_TAGS, HISTORY_EXAMPLE, daysVariant, generatedKeys, gradeVariant, importFiles, repoOf, tlsVariant, toneVariant, viewOf
} from '../../assets/js/views/monitor.js';
import { buildSummary, renderSummary } from '../../assets/js/lib/summarycore.js';
import { monitorSummaryFacts } from '../../assets/js/lib/monitor.js';
import { parseCommandLine } from '../../tools/ds/args.mjs';
import { CHANGE_TAGS } from '../../tools/ds/render.mjs';
import { monitorFixture, MONITOR_NOW } from './monitor-fixture.mjs';

describe('a results folder in the view', () => {
  test('the folder\'s files: five reports, three months, the Markdown left alone, a damaged report named', () => {
    const fx = monitorFixture();
    const files = [...fx.files, { name: 'broken.json', text: JSON.stringify({ tool: 'domainscope-ds', version: '1.0.0', command: 'tls', targets: [{ target: 'x', endpoints: [{}] }] }) }];
    const r = importFiles(null, files);
    assert.deepEqual([r.data.reports.length, r.added.history, r.skippedLines], [5, 3, 2]);
    assert.deepEqual(r.problems, [{ name: 'broken.json', error: 'damaged', detail: 'targets[0] endpoints[0] has no "address"' }]);
    // a second drop adds to what is open
    const more = importFiles(r.data, [{ name: 'extra.json', text: JSON.stringify({ ...fx.reports['health.json'], finishedAt: '2026-10-10T03:20:00.000Z' }) }]);
    assert.equal(more.data.reports.length, 6);
  });

  test('what the page draws: the rows, the tiles, the timeline; nothing open draws nothing', () => {
    assert.equal(viewOf(null), null);
    assert.equal(viewOf({ reports: [], lines: [], files: [] }), null);
    const { data } = importFiles(null, monitorFixture().files);
    const view = viewOf(data, MONITOR_NOW);
    assert.equal(view.rows.length, 5);
    assert.deepEqual([view.tiles.bad.length, view.tiles.expiring.length, view.tiles.incomplete.length], [3, 2, 2]);
    assert.equal(view.entries.length, 8, 'the eight changes of the story');
    assert.deepEqual(MONITOR_FILTERS, ['all', 'bad', 'expiring', 'incomplete']);
  });

  test('the Copy summary: the tiles by name, never an address, in both languages', () => {
    const { data } = importFiles(null, monitorFixture().files);
    const view = viewOf(data, MONITOR_NOW);
    const facts = monitorSummaryFacts(view.rows, view.tiles, data);
    try {
      setLang('en');
      const md = renderSummary(buildSummary('monitor', facts, { t, lang: 'en', url: 'https://example.org/#/monitor', now: new Date(MONITOR_NOW) }), 'markdown');
      const lines = md.trim().split('\n');
      assert.equal(lines[0], '**Monitoring · 5 targets**');
      assert.equal(lines[1], '- 5 targets, from 5 reports · history since 2026-08-20');
      assert.match(md, /\*\*Bad changes in the last 7 days, 3 targets:\*\* `example\.com` \(3\), /);
      assert.match(md, /\*\*2 certificates under 21 days:\*\* `mail\.example\.net` expired 4 days ago, `example\.com` 15 days left/);
      assert.match(md, /\*\*2 checks did not complete:\*\* `example\.com` takeover \(not run since 2026-10-07\), `example\.org` health/);
      assert.match(md, /- Health grades: A 1 · B 1 · E 1/);
      assert.match(lines[lines.length - 1], /^DomainScope · checked 2026-10-09 03:40 UTC · https:\/\/example\.org\/#\/monitor$/);
      assert.ok(!/192\.0\.2\.|198\.51\.100\.|2001:db8/.test(md), 'no address');
      setLang('tr');
      const tr = renderSummary(buildSummary('monitor', facts, { t, lang: 'tr', url: null, now: new Date(MONITOR_NOW) }), 'text');
      assert.match(tr, /^İzleme · 5 hedef\n- 5 rapordan 5 hedef · geçmiş 2026-08-20 tarihinden başlıyor\n/);
      assert.match(tr, /21 günden az kalan 2 sertifika: mail\.example\.net 4 gün önce doldu, example\.com 15 gün kaldı/);
      assert.match(tr, /Tamamlanmayan 2 kontrol: example\.com takeover \(2026-10-07 tarihinden beri çalışmadı\), example\.org health/);
    } finally {
      setLang('en');
    }
  });

  test('the Copy summary\'s scope: one report is one, the history alone has none', () => {
    const fx = monitorFixture();
    const text = (files, lang) => {
      const { data } = importFiles(null, files);
      const view = viewOf(data, MONITOR_NOW);
      setLang(lang);
      return renderSummary(buildSummary('monitor', monitorSummaryFacts(view.rows, view.tiles, data), { t, lang, url: null, now: new Date(MONITOR_NOW) }), 'text');
    };
    try {
      const tls = fx.files.filter((f) => f.name === 'tls.json');
      assert.match(text(tls, 'en'), /\n- 2 targets, from 1 report · history since 2026-10-09\n/);
      assert.match(text(tls, 'tr'), /\n- 1 rapordan 2 hedef · geçmiş 2026-10-09 tarihinden başlıyor\n/);
      const history = text(fx.history, 'en');
      assert.match(history, /\n- 5 targets · history since 2026-08-20\n/);
      assert.match(history, /2 certificates under 21 days: mail\.example\.net expired 4 days ago, example\.com 15 days left/, 'the history\'s certificates');
      assert.match(text(fx.history, 'tr'), /\n- 5 hedef · geçmiş 2026-08-20 tarihinden başlıyor\n/);
    } finally {
      setLang('en');
    }
  });

  test('badges: days, grades, tones and tls statuses; the repository of the links', () => {
    assert.deepEqual([-4, 0, 6, 7, 20, 21, 90, null].map(daysVariant), ['error', 'error', 'error', 'warn', 'warn', 'ok', 'ok', 'neutral']);
    assert.deepEqual(['A', 'B', 'C', 'D', 'E', 'F', null].map(gradeVariant), ['ok', 'ok', 'info', 'warn', 'error', 'error', 'neutral']);
    assert.deepEqual(['bad', 'good', 'info', 'quiet'].map(toneVariant), ['error', 'ok', 'info', 'neutral']);
    assert.deepEqual(['OK', 'SKIPPED', 'TIMEOUT', 'EXPIRED', 'NAME_MISMATCH'].map(tlsVariant), ['ok', 'neutral', 'warn', 'error', 'error']);
    const { data } = importFiles(null, monitorFixture().files);
    assert.deepEqual(repoOf(null, data), { owner: 'example-org', repo: 'nightly' }, 'from the history\'s run links');
    assert.deepEqual(repoOf({ owner: 'a', repo: 'b' }, data), { owner: 'a', repo: 'b' }, 'GitHub\'s own wins');
    assert.equal(repoOf(null, { reports: [], lines: [], files: [] }), null);
  });

  test('every key the view builds exists in both languages; every tag the runner writes has its words; the example parses', () => {
    for (const k of generatedKeys()) assert.ok(hasString(k, 'en') && hasString(k, 'tr'), k);
    assert.deepEqual([...MONITOR_TAGS].sort(), [...CHANGE_TAGS].sort());
    const [, ...argv] = HISTORY_EXAMPLE.split(' ');
    assert.equal(parseCommandLine(argv.slice(1)).options.history, 'results/history');
  });
});
