/**
 * tests/js/digests.test.js — lib/digests.js: the workspace part `digests` (counts a tool writes for
 * Home): each digest checked on the way in and out, one kind replaced without the others, the
 * size bound, and the Monitoring digest built from the view's own tiles. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  DIGESTS_MAX_CHARS, DIGEST_KINDS, MONITOR_DIGEST_COUNTS, MONITOR_DIGEST_DAYS, monitorDigest, readDigests, digestsText, withDigest
} from '../../assets/js/lib/digests.js';
import { WORKSPACE_LIMITS, sanitizePart } from '../../assets/js/lib/workspace.js';
import { monitorSummaryFacts, MONITOR_RECENT_DAYS, MONITOR_WARN_DAYS } from '../../assets/js/lib/monitor.js';
import { monitorDigestOf, importFiles, viewOf } from '../../assets/js/views/monitor.js';
import { monitorFixture, MONITOR_NOW } from './monitor-fixture.mjs';

const AT = '2026-10-08T03:00:00.000Z';
const IMPORTED = '2026-10-08T09:00:00.000Z';
const MON = { at: AT, imported: IMPORTED, targets: 4, bad: 1, expiring: 0, incomplete: 2 };

describe('the digests part', () => {
  test('its bound is the workspace part\'s; the kinds and counts are named', () => {
    assert.equal(DIGESTS_MAX_CHARS, WORKSPACE_LIMITS.digests);
    assert.deepEqual(DIGEST_KINDS, ['monitor']);
    assert.deepEqual(MONITOR_DIGEST_COUNTS, ['targets', 'bad', 'expiring', 'incomplete']);
    assert.deepEqual(MONITOR_DIGEST_DAYS, { bad: MONITOR_RECENT_DAYS, expiring: MONITOR_WARN_DAYS }, 'the days Home says are the tiles\' own');
  });

  test('a Monitoring digest: two times and four whole counts, nothing else; dates and numbers come back as ISO text', () => {
    assert.deepEqual(monitorDigest(MON), MON);
    assert.deepEqual(monitorDigest({ ...MON, at: new Date(AT), imported: Date.parse(IMPORTED), names: ['example.com'] }), MON, 'no name is kept');
    for (const bad of [{ ...MON, bad: -1 }, { ...MON, targets: 1.5 }, { ...MON, expiring: '3' }, { ...MON, at: 'yesterday' }, { ...MON, imported: null },
      { ...MON, incomplete: 1e8 }, null, 'monitor', []]) {
      assert.equal(monitorDigest(bad), null, JSON.stringify(bad));
    }
  });

  test('read → text round-trips; a kind that does not check or is unknown is left out; junk reads as none', () => {
    const text = digestsText({ monitor: MON, other: { x: 1 } });
    assert.equal(text, JSON.stringify({ monitor: MON }));
    assert.equal(sanitizePart('digests', text), text, 'the workspace keeps it whole');
    assert.deepEqual(readDigests(text), { monitor: MON });
    assert.deepEqual(readDigests(JSON.stringify({ monitor: { ...MON, bad: 'many' } })), {});
    for (const junk of ['', '{', 'null', '[]', '"x"', 42, null, undefined, 'd'.repeat(DIGESTS_MAX_CHARS + 1)]) assert.deepEqual(readDigests(junk), {}, String(junk).slice(0, 20));
    assert.equal(digestsText({}), '', 'nothing to keep: an empty part');
    assert.equal(digestsText(null), '');
  });

  test('withDigest replaces one kind, keeps the others, and removes one with null', () => {
    const one = withDigest('', 'monitor', MON);
    assert.deepEqual(readDigests(one), { monitor: MON });
    const two = withDigest(one, 'monitor', { ...MON, bad: 0 });
    assert.equal(readDigests(two).monitor.bad, 0);
    assert.equal(withDigest(two, 'monitor', null), '');
    assert.equal(withDigest(two, 'monitor', { ...MON, at: 'never' }), '', 'a digest that does not check removes the old one');
    assert.equal(withDigest(one, 'unknown', MON), one, 'an unknown kind changes nothing');
  });
});

describe('the Monitoring view writes its tiles', () => {
  test('monitorDigestOf: the counts of the tiles, the newest check and the import time; never a target', () => {
    const { data } = importFiles(null, monitorFixture().files);
    const view = viewOf(data, MONITOR_NOW);
    const digest = monitorDigestOf(view, data, MONITOR_NOW);
    // the fixture's story: 5 targets, 3 with a bad change this week, 2 certificates under 21 days, 2 checks that did not complete
    assert.deepEqual([digest.targets, digest.bad, digest.expiring, digest.incomplete], [5, 3, 2, 2]);
    assert.equal(digest.at, monitorSummaryFacts(view.rows, view.tiles, data).at.toISOString(), 'when the newest check ran');
    assert.equal(digest.imported, new Date(MONITOR_NOW).toISOString());
    assert.deepEqual(monitorDigest(digest), digest);
    assert.ok(!/example/.test(JSON.stringify(digest)), 'counts only: no target is named');
    assert.equal(monitorDigestOf(null, data, MONITOR_NOW), null, 'nothing open: no digest');
  });
});
