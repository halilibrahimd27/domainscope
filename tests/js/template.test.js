/**
 * lib/template.js — the page template as data (docs/DESIGN.md §5): the status summary's items and
 * their order, where a result's standard actions go, "Also check", the compact input's summary
 * line, the template states, the phone's floating run bar and a sentence split around its subject;
 * and the four "Investigate a domain" tools' status items (lib/passport.js, lib/healthscore.js,
 * lib/subtabs.js, lib/density.js) as statusItems shows them. Pure Node.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  STATUS_SEVERITIES, STATUS_MAX, TEMPLATE_STATES, RESULT_ACTIONS, RELATED_MAX, PHONE_MAX_WIDTH,
  statusItems, toggleStatus, actionPlan, relatedLinks, optionsSummary, templateState, inputCompact, runBarFloats, splitAtSubject,
  FINDINGS_MAX, findingRows, barStuck
} from '../../assets/js/lib/template.js';
import { PASSPORT_CARDS, passportStatus } from '../../assets/js/lib/passport.js';
import { healthStatus } from '../../assets/js/lib/healthscore.js';
import { subStatus } from '../../assets/js/lib/subtabs.js';
import { lookupStatus } from '../../assets/js/lib/density.js';

const item = (key, severity, count, extra = {}) => ({ key, severity, count, ...extra });
const keys = (list) => list.map((x) => x.key);

describe('the constants', () => {
  test('severities in their order, five items at most, the four states, the five actions, four links, the phone width', () => {
    assert.deepEqual(STATUS_SEVERITIES, ['error', 'warn', 'info', 'ok', 'neutral']);
    assert.equal(STATUS_MAX, 5);
    assert.deepEqual(TEMPLATE_STATES, ['empty', 'ready', 'running', 'done']);
    assert.deepEqual(RESULT_ACTIONS, ['summary', 'plain', 'report', 'export', 'link']);
    assert.equal(RELATED_MAX, 4);
    assert.equal(PHONE_MAX_WIDTH, 719);
    assert.ok(Object.isFrozen(STATUS_SEVERITIES) && Object.isFrozen(TEMPLATE_STATES) && Object.isFrozen(RESULT_ACTIONS));
  });
});

describe('statusItems', () => {
  test('error → warn → info → ok → neutral, the caller\'s order kept within a severity; the same objects', () => {
    const list = [item('hosts', 'neutral', 7), item('ok', 'ok', 12), item('a', 'warn', 1), item('e', 'error', 2), item('b', 'warn', 3), item('n', 'info', 4)];
    const out = statusItems(list);
    assert.deepEqual(keys(out), ['e', 'a', 'b', 'n', 'ok']);
    assert.equal(out[0], list[3], 'the same object, not a copy');
  });

  test('zero counts are left out, except the error count of a verdict tool ("0 errors" is the good news)', () => {
    const list = [item('error', 'error', 0), item('warn', 'warn', 0), item('info', 'info', 2), item('ok', 'ok', 0)];
    assert.deepEqual(keys(statusItems(list)), ['info']);
    assert.deepEqual(keys(statusItems(list, { verdict: true })), ['error', 'info']);
    assert.deepEqual(keys(statusItems([item('sources', 'error', 0)], { verdict: false })), [], 'not a verdict tool: no "0 failed"');
  });

  test('at most five (or `max`); invalid items dropped: no key, an unknown severity, a negative or non-numeric count', () => {
    const many = Array.from({ length: 8 }, (_, i) => item(`k${i}`, 'neutral', i + 1));
    assert.equal(statusItems(many).length, 5);
    assert.deepEqual(keys(statusItems(many, { max: 2 })), ['k0', 'k1']);
    assert.deepEqual(statusItems(many, { max: 0 }), []);
    const bad = [null, item('', 'error', 1), item('x', 'fatal', 1), item('y', 'warn', -1), item('z', 'warn', 'many'), { severity: 'warn', count: 1 }, item('ok', 'warn', '2')];
    assert.deepEqual(keys(statusItems(bad)), ['ok'], 'a numeric string counts');
    assert.deepEqual(statusItems(null), []);
    assert.deepEqual(statusItems('nope'), []);
  });
});

describe('toggleStatus', () => {
  test('a press filters; the pressed item pressed again clears the filter; another item moves it', () => {
    assert.equal(toggleStatus(null, 'warn'), 'warn');
    assert.equal(toggleStatus('warn', 'warn'), null);
    assert.equal(toggleStatus('warn', 'error'), 'error');
  });
});

describe('actionPlan', () => {
  test('the fixed order: Copy summary, ¶, Report, Export, Copy link — what the result offers only', () => {
    assert.deepEqual(actionPlan({ summary: true, report: true, files: 2, print: true, link: true }),
      { row: ['summary', 'plain', 'report', 'export', 'link'], more: [], exportAs: 'menu' });
    assert.deepEqual(actionPlan({ summary: true, link: true }), { row: ['summary', 'plain', 'link'], more: [], exportAs: null });
    assert.deepEqual(actionPlan({}), { row: [], more: [], exportAs: null });
  });

  test('one file is a plain Export button, Print counting as one; more is the Export ▾ menu', () => {
    assert.equal(actionPlan({ files: 1 }).exportAs, 'file');
    assert.equal(actionPlan({ print: true }).exportAs, 'file');
    assert.equal(actionPlan({ files: 1, print: true }).exportAs, 'menu');
    assert.equal(actionPlan({ files: 3 }).exportAs, 'menu');
    assert.equal(actionPlan({ files: -2 }).exportAs, null);
    assert.equal(actionPlan({ files: 'x' }).exportAs, null);
    assert.equal(actionPlan({ files: 1.9 }).exportAs, 'file', 'a whole number of files');
  });

  test('a phone keeps Copy summary in the row and puts the rest behind "⋯", in the same order', () => {
    assert.deepEqual(actionPlan({ summary: true, report: true, files: 1, print: true, link: true, phone: true }),
      { row: ['summary'], more: ['plain', 'report', 'export', 'link'], exportAs: 'menu' });
    assert.deepEqual(actionPlan({ files: 1, link: true, phone: true }), { row: [], more: ['export', 'link'], exportAs: 'file' }, 'no summary: everything behind "⋯"');
  });
});

describe('relatedLinks', () => {
  test('up to four tools, each once, never the tool itself; links without a view dropped; the given order kept', () => {
    const links = [{ view: 'lookup' }, { view: 'health' }, { view: 'lookup', other: true }, null, { view: '' }, { href: '#/x' }, { view: 'global' }, { view: 'scan' }, { view: 'ip' }, { view: 'bulk' }];
    assert.deepEqual(relatedLinks(links, { self: 'health' }).map((x) => x.view), ['lookup', 'global', 'scan', 'ip']);
    assert.equal(relatedLinks(links)[0], links[0], 'the same objects');
    assert.deepEqual(relatedLinks(links, { max: 2 }).map((x) => x.view), ['lookup', 'health']);
    assert.deepEqual(relatedLinks(undefined), []);
  });
});

describe('optionsSummary', () => {
  test('the labels of the choices off their default, in order, joined with " · "; a string always shows', () => {
    assert.equal(optionsSummary([{ label: 'A, AAAA, MX', isDefault: false }, { label: 'Automatic resolver', isDefault: true }, 'DNSSEC (DO)']), 'A, AAAA, MX · DNSSEC (DO)');
    assert.equal(optionsSummary([{ label: 'x', isDefault: true }, null, false, '  ', { label: '' }]), '');
    assert.equal(optionsSummary([{ label: '  small wordlist ' }]), 'small wordlist', 'trimmed; no isDefault means a choice');
    assert.equal(optionsSummary('nope'), '');
  });
});

describe('templateState, inputCompact and runBarFloats', () => {
  test('a run wins, then a result, then a link waiting for a click, else empty', () => {
    assert.equal(templateState({ running: true, result: true, ready: true }), 'running');
    assert.equal(templateState({ result: true, ready: true }), 'done');
    assert.equal(templateState({ ready: true }), 'ready');
    assert.equal(templateState({}), 'empty');
    assert.equal(templateState(), 'empty');
  });

  test('the input is compact from a run on and while a result is on screen', () => {
    assert.deepEqual(TEMPLATE_STATES.map(inputCompact), [false, false, true, true]);
  });

  test('the floating run bar: a phone, the inline Run out of view and a value; Stop while running; never over a result', () => {
    const base = { phone: true, inlineVisible: false, hasValue: true };
    assert.equal(runBarFloats({ ...base, state: 'empty' }), true);
    assert.equal(runBarFloats({ ...base, state: 'ready' }), true);
    assert.equal(runBarFloats({ ...base, hasValue: false, state: 'empty' }), false, 'nothing to run');
    assert.equal(runBarFloats({ ...base, hasValue: false, state: 'running' }), true, 'it carries Stop');
    assert.equal(runBarFloats({ ...base, state: 'done' }), false, 'it would cover the result');
    assert.equal(runBarFloats({ ...base, inlineVisible: true }), false, 'the inline Run is in view');
    assert.equal(runBarFloats({ ...base, phone: false }), false, 'not on a wide screen');
    assert.equal(runBarFloats(), false);
  });

  test('the floating run bar steps aside while another primary button leads (a link\'s Start): one primary at a time; Stop still floats', () => {
    const base = { phone: true, inlineVisible: false, hasValue: true, primary: false };
    assert.equal(runBarFloats({ ...base, state: 'ready' }), false, 'the prompt\'s Start leads');
    assert.equal(runBarFloats({ ...base, state: 'empty' }), false);
    assert.equal(runBarFloats({ ...base, state: 'running' }), true, 'it carries Stop');
    assert.equal(runBarFloats({ ...base, primary: true, state: 'ready' }), true, 'primary by default');
  });
});

describe('splitAtSubject', () => {
  test('the words before and after the subject, wherever the language puts it; null without the marker', () => {
    const M = '\u0001';
    assert.deepEqual(splitAtSubject(`Overview of ${M}`, M), ['Overview of ', '']);
    assert.deepEqual(splitAtSubject(`${M} özeti`, M), ['', ' özeti']);
    assert.deepEqual(splitAtSubject(`Subdomains of ${M} (2 domains)`, M), ['Subdomains of ', ' (2 domains)']);
    assert.equal(splitAtSubject('Overview', M), null);
    assert.equal(splitAtSubject(null, M), null);
    assert.equal(splitAtSubject(`a${M}b`, ''), null);
  });
});

describe('the tools\' status items, as statusItems shows them', () => {
  test('Domain overview: the health card\'s errors and warnings once it is ready, and the cards a failed lookup left n/a, in page order', () => {
    const failed = PASSPORT_CARDS.filter((id) => id !== 'health').slice(-2).reverse();
    const cards = Object.fromEntries(PASSPORT_CARDS.map((id) => [id, { failures: failed.includes(id) ? ['ns'] : [] }]));
    cards.health = { state: 'ready', summary: { error: 2, warn: 1, info: 4, ok: 9 }, failures: [] };
    const items = passportStatus(cards);
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count]), [['error', 'error', 2], ['warn', 'warn', 1], ['na', 'warn', 2]]);
    assert.deepEqual(items[2].cards, PASSPORT_CARDS.filter((id) => failed.includes(id)), 'page order');
    assert.deepEqual(keys(statusItems(items)), ['error', 'warn', 'na']);
    cards.health = { state: 'pending', summary: null, failures: [] };
    assert.deepEqual(keys(passportStatus(cards)), ['na'], 'no health counts before the card is ready');
    assert.deepEqual(passportStatus(null), [{ key: 'na', severity: 'warn', count: 0, cards: [] }]);
    assert.deepEqual(statusItems(passportStatus({})), [], 'nothing to say');
  });

  test('Domain Health: errors, warnings, notes, passed — a verdict tool, so "0 errors" shows', () => {
    const items = healthStatus({ error: 0, warn: 3, info: 1, ok: 20 });
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count]), [['error', 'error', 0], ['warn', 'warn', 3], ['info', 'info', 1], ['ok', 'ok', 20]]);
    assert.deepEqual(keys(statusItems(items, { verdict: true })), ['error', 'warn', 'info', 'ok']);
    assert.deepEqual(keys(statusItems(healthStatus({ ok: 5, warn: -1, info: 2.7 }), { verdict: true })), ['error', 'info', 'ok']);
    assert.equal(healthStatus(null).every((x) => x.count === 0), true);
  });

  test('Subdomains: behind a CDN first (info), then the hosts and those that resolve; failed sources open the Sources tab', () => {
    const items = subStatus({ counts: { found: 7, resolving: 6, cloudflare: 2, cdn: 1, unresolved: 1 }, failedSources: 1 });
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count, x.filter, x.tab]), [
      ['found', 'neutral', 7, 'all', 'hosts'],
      ['resolving', 'neutral', 6, 'resolving', 'hosts'],
      ['behind', 'info', 3, 'behind', 'hosts'],
      ['unresolved', 'warn', 1, 'unresolved', 'hosts'],
      ['sources', 'error', 1, null, 'sources']
    ]);
    assert.deepEqual(keys(statusItems(items)), ['sources', 'unresolved', 'behind', 'found', 'resolving']);
    assert.deepEqual(keys(statusItems(subStatus({ counts: { found: 3, resolving: 3 } }))), ['found', 'resolving'], 'zeros left out');
    assert.deepEqual(statusItems(subStatus()), []);
  });

  test('DNS Lookup: a failed query first, then the types, the records and the types with no records (named)', () => {
    const items = lookupStatus({ types: 8, records: 9, noRecords: ['CAA', 'HTTPS', '', 7], failed: 1 });
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count]), [['failed', 'error', 1], ['types', 'neutral', 8], ['records', 'neutral', 9], ['nodata', 'neutral', 2]]);
    assert.deepEqual(items[3].types, ['CAA', 'HTTPS']);
    assert.deepEqual(keys(statusItems(lookupStatus({ types: 2, records: 0 }))), ['types'], 'no "0 records" item, no "0 failed"');
    assert.deepEqual(statusItems(lookupStatus({ noRecords: 'CAA' })), []);
  });
});

describe('findingRows (phase 3: the finding list)', () => {
  const f = (key, severity) => ({ key, severity });

  test('the worst first, the caller\'s order within a severity; the same objects', () => {
    const list = [f('a', 'info'), f('b', 'warn'), f('c', 'ok'), f('d', 'error'), f('e', 'warn'), f('n', 'neutral')];
    const { shown, more } = findingRows(list, { max: 10 });
    assert.deepEqual(keys(shown), ['d', 'b', 'e', 'a', 'c', 'n']);
    assert.deepEqual(more, []);
    assert.equal(shown[0], list[3], 'not a copy');
  });

  test('at most three rows (FINDINGS_MAX), the rest behind "n more" — but never "1 more" for one row', () => {
    assert.equal(FINDINGS_MAX, 3);
    const five = ['a', 'b', 'c', 'd', 'e'].map((k) => f(k, 'info'));
    assert.deepEqual([keys(findingRows(five).shown), keys(findingRows(five).more)], [['a', 'b', 'c'], ['d', 'e']]);
    const four = five.slice(0, 4);
    assert.deepEqual([keys(findingRows(four).shown), findingRows(four).more], [['a', 'b', 'c', 'd'], []], 'four rows show: "1 more" would hide one row behind a row');
    assert.deepEqual(keys(findingRows(five, { max: 1 }).shown), ['a']);
    assert.deepEqual(findingRows(five, { max: 0 }).shown, []);
  });

  test('a finding without a key, with an unknown severity or a key seen before is dropped', () => {
    const list = [null, f('', 'warn'), f('x', 'fatal'), f('ok', 'ok'), f('ok', 'error'), { severity: 'warn' }];
    assert.deepEqual(keys(findingRows(list).shown), ['ok']);
    assert.deepEqual(findingRows('nope'), { shown: [], more: [] });
  });
});

describe('barStuck (lib/template.js; lib/scanform.js re-exports it)', () => {
  test('the sticky run bar\'s test lives here now; scanform hands out the same function', async () => {
    const scanform = await import('../../assets/js/lib/scanform.js');
    assert.equal(scanform.barStuck, barStuck);
    assert.equal(barStuck({ sticky: true, top: -10, bottom: 900, viewportHeight: 800 }), true);
    assert.equal(barStuck({ sticky: false, top: -10, bottom: 900, viewportHeight: 800 }), false);
  });
});
