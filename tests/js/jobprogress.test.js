/**
 * lib/jobprogress.js: the progress of a long job outside its view (tab title, navigation ring,
 * favicon badge) and the opt-in desktop notification decision.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  scanFraction, bulkFraction, advance, combineJobs, percentOf, progressTitle, faviconStep, badgedIcon, svgDataUrl,
  offerNotify, shouldNotify, SCAN_STAGE_WEIGHTS, BRAND_ICON_SVG, LONG_JOB_MS
} from '../../assets/js/lib/jobprogress.js';
import { SCAN_STAGES } from '../../assets/js/lib/scanner.js';
import { applyStage, applyProgress, stopStages } from '../../assets/js/views/subdomains.js';

const run0 = () => ({
  stages: Object.fromEntries(SCAN_STAGES.map((s) => [s, { state: 'pending', info: null }])),
  progress: { stage: null, done: 0, total: 0 },
  miningProgress: null,
  rounds: null,
  config: {}
});

describe('scanFraction', () => {
  test('the weights cover exactly the scanner stages', () => {
    assert.deepEqual(Object.keys(SCAN_STAGE_WEIGHTS), [...SCAN_STAGES]);
    assert.equal(Object.values(SCAN_STAGE_WEIGHTS).reduce((a, b) => a + b, 0), 100);
  });

  test('indeterminate before the first stage; the stage progress counts by weight', () => {
    const run = run0();
    assert.equal(scanFraction(run), null);
    assert.equal(scanFraction(null), null);
    applyStage(run, 'sources', { total: 4 });
    assert.equal(scanFraction(run), 0);
    applyProgress(run, { stage: 'sources', done: 2, total: 4 });
    assert.equal(scanFraction(run), 0.05);
    applyStage(run, 'wildcard', { total: 3 });
    applyStage(run, 'bruteforce', { total: 1000 });
    applyProgress(run, { stage: 'bruteforce', done: 500, total: 1000 });
    assert.equal(scanFraction(run), (10 + 5 + 22.5) / 100);
  });

  test('a skipped stage drops out; the end is 1', () => {
    const run = run0();
    applyStage(run, 'sources', {});
    applyStage(run, 'wildcard', {});
    applyStage(run, 'bruteforce', { skipped: true });
    applyStage(run, 'permutations', { total: 10 });
    applyProgress(run, { stage: 'permutations', done: 5, total: 10 });
    assert.equal(scanFraction(run), (10 + 5 + 10) / 55);
    applyStage(run, 'done', {});
    assert.equal(scanFraction(run), 1);
  });

  test('a scripted Smart scan never shows a step backwards (parallel mining, the recursive round restarting from 0)', () => {
    const run = run0();
    const seen = [];
    const raw = [];
    const note = () => {
      raw.push(scanFraction(run));
      seen.push(advance(seen.length ? seen.at(-1) : null, raw.at(-1)));
    };
    applyStage(run, 'sources', { domains: ['example.com'], sources: ['crtsh'] }); note();
    applyStage(run, 'mining', { total: 20 });
    // Mining reports while the sources run: only its own pill moves.
    for (let i = 0; i <= 20; i += 5) { applyProgress(run, { stage: 'mining', done: i, total: 20 }); note(); }
    applyStage(run, 'wildcard', { total: 2 }); note();
    applyStage(run, 'bruteforce', { total: 7000 });
    for (let i = 0; i <= 7000; i += 1000) { applyProgress(run, { stage: 'bruteforce', done: i, total: 7000 }); note(); }
    applyStage(run, 'permutations', { total: 1500 });
    for (let i = 0; i <= 1500; i += 500) { applyProgress(run, { stage: 'permutations', done: i, total: 1500 }); note(); }
    for (let i = 0; i <= 400; i += 100) { applyProgress(run, { stage: 'permutations', done: i, total: 400 }); note(); } // recursive round
    applyStage(run, 'resolve', { total: 30 });
    for (let i = 0; i <= 30; i += 10) { applyProgress(run, { stage: 'resolve', done: i, total: 30 }); note(); }
    applyStage(run, 'hints', { total: 3 }); note();
    applyStage(run, 'done', {}); note();
    for (let i = 1; i < seen.length; i += 1) assert.ok(seen[i] >= seen[i - 1], `step ${i}: ${seen[i - 1]} → ${seen[i]}`);
    assert.equal(seen.at(-1), 1);
    assert.ok(seen.slice(0, -1).every((f) => f < 1));
    // The raw fraction dips only where a stage's total grew (the recursive round), and by little.
    const dips = raw.map((f, i) => (i && f < raw[i - 1] ? raw[i - 1] - f : 0)).filter(Boolean);
    assert.equal(dips.length, 1);
    assert.ok(dips[0] < 0.05, `dip ${dips[0]}`);
  });

  test('advance: never below the last value; an unknown value keeps it', () => {
    assert.equal(advance(null, 0.2), 0.2);
    assert.equal(advance(0.5, 0.4), 0.5);
    assert.equal(advance(0.5, 0.6), 0.6);
    assert.equal(advance(0.5, null), 0.5);
    assert.equal(advance(null, null), null);
    assert.equal(advance(null, 7), 1);
  });

  test('a cancelled scan keeps the progress of the stage that stopped', () => {
    const run = run0();
    applyStage(run, 'sources', {});
    applyStage(run, 'wildcard', {});
    applyStage(run, 'bruteforce', { total: 100 });
    applyProgress(run, { stage: 'bruteforce', done: 40, total: 100 });
    const before = scanFraction(run);
    stopStages(run);
    assert.equal(scanFraction(run), before);
  });
});

describe('bulkFraction / combineJobs / percentOf / progressTitle', () => {
  test('bulk: names resolved; a quarter for the addresses looked up when asked', () => {
    assert.equal(bulkFraction({ names: [] }), null);
    assert.equal(bulkFraction(null), null);
    assert.equal(bulkFraction({ names: ['a', 'b', 'c', 'd'], done: 1, options: {} }), 0.25);
    const job = { names: ['a', 'b', 'c', 'd'], done: 2, ipTotal: 4, ipDone: 2, options: { asn: true } };
    assert.equal(bulkFraction(job), 0.75 * 0.5 + 0.25 * 0.5 * 0.5);
    assert.equal(bulkFraction({ ...job, done: 4, ipDone: 4 }), 1);
    assert.equal(bulkFraction({ ...job, done: 4, ipTotal: 0, ipDone: 0 }), 1, 'no address to look up');
    assert.equal(bulkFraction({ ...job, done: 4, ipDone: 0 }), 0.75);
  });

  test('several jobs show the least advanced one; percent never says 100 while running', () => {
    assert.deepEqual(combineJobs([{ fraction: 0.8 }, { fraction: 0.3 }, { fraction: null }]), { count: 3, fraction: 0.3 });
    assert.deepEqual(combineJobs([{ fraction: null }]), { count: 1, fraction: null });
    assert.deepEqual(combineJobs([]), { count: 0, fraction: null });
    assert.equal(percentOf(0.623), 62);
    assert.equal(percentOf(0.999), 99);
    assert.equal(percentOf(1), 99);
    assert.equal(percentOf(-1), 0);
    assert.equal(percentOf(null), null);
    assert.equal(progressTitle('Subdomains · DomainScope', '62%'), '(62%) Subdomains · DomainScope');
    assert.equal(progressTitle('Alt alan adları · DomainScope', '%62'), '(%62) Alt alan adları · DomainScope');
    assert.equal(progressTitle('DomainScope', null), '(…) DomainScope');
  });
});

describe('favicon badge', () => {
  test('the embedded brand icon is favicon.svg', () => {
    const file = readFileSync(new URL('../../favicon.svg', import.meta.url), 'utf8');
    const norm = (s) => s.replace(/>\s+</g, '><').trim();
    assert.equal(BRAND_ICON_SVG, norm(file));
  });

  test('steps of 5 % (10 % with reduced motion), never full while running', () => {
    assert.equal(faviconStep(0.623), 0.6);
    assert.equal(faviconStep(0.66), 0.65);
    assert.equal(faviconStep(0.66, { reducedMotion: true }), 0.6);
    assert.equal(faviconStep(1), 0.95);
    assert.equal(faviconStep(0.01), 0);
    assert.equal(faviconStep(null), null);
  });

  test('a pie for the progress, a dot when it is not known; a data: URL', () => {
    const svg = badgedIcon(0.6);
    assert.ok(svg.startsWith(BRAND_ICON_SVG.slice(0, -'</svg>'.length)));
    assert.ok(svg.endsWith('</g></svg>'));
    assert.match(svg, /stroke-dasharray="60 100"/);
    assert.doesNotMatch(badgedIcon(0), /stroke-dasharray/, 'no pie at 0 %');
    assert.match(badgedIcon(null), /<circle cx="23" cy="23" r="5" fill="#2563eb"\/>/);
    assert.doesNotMatch(badgedIcon(null), /stroke-dasharray/);
    assert.equal(badgedIcon(0.5, { svg: 'not svg' }), 'not svg');
    const url = svgDataUrl(svg);
    assert.ok(url.startsWith('data:image/svg+xml,%3Csvg'));
    assert.equal(decodeURIComponent(url.slice('data:image/svg+xml,'.length)), svg);
    assert.doesNotMatch(url, /[#"<> ]/, 'safe to put in an href');
  });
});

describe('desktop notification', () => {
  test('"Notify me when done" is offered once a job is long, where the browser allows it', () => {
    assert.equal(offerNotify({ elapsedMs: LONG_JOB_MS - 1, supported: true, permission: 'default' }), false);
    assert.equal(offerNotify({ elapsedMs: LONG_JOB_MS, supported: true, permission: 'default' }), true);
    assert.equal(offerNotify({ elapsedMs: LONG_JOB_MS, supported: true, permission: 'granted' }), true);
    assert.equal(offerNotify({ elapsedMs: 0, supported: true, permission: 'granted', optedIn: true }), true, 'already on for this session');
    assert.equal(offerNotify({ elapsedMs: LONG_JOB_MS, supported: true, permission: 'denied' }), false);
    assert.equal(offerNotify({ elapsedMs: LONG_JOB_MS, supported: false, permission: null }), false);
  });

  test('sent only when opted in, granted, long, finished or failed, and not being watched', () => {
    const base = { optedIn: true, permission: 'granted', status: 'done', durationMs: LONG_JOB_MS, watching: false };
    assert.equal(shouldNotify(base), true);
    assert.equal(shouldNotify({ ...base, status: 'error' }), true);
    assert.equal(shouldNotify({ ...base, status: 'cancelled' }), false);
    assert.equal(shouldNotify({ ...base, optedIn: false }), false);
    assert.equal(shouldNotify({ ...base, permission: 'default' }), false);
    assert.equal(shouldNotify({ ...base, durationMs: LONG_JOB_MS - 1 }), false);
    assert.equal(shouldNotify({ ...base, watching: true }), false);
  });
});
