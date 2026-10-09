/**
 * tests/js/home-view.test.js — views/home.js's pure parts: when a workspace is empty, the facts
 * under the title, the setup checklist, the recent domains with their quick actions, the results
 * kept in this tab, and the small readers of This workspace. Documentation names only; no DOM.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  id, titleKey, icon, RECENT_SHOWN, KEPT_SHOWN, RECENT_ACTIONS, SETUP_ITEMS, isEmptyWorkspace, homeFacts, setupItems, recentEntries,
  keptResults, firstNoteLine, waiverCount
} from '../../assets/js/views/home.js';
import { createSessionStore } from '../../assets/js/lib/session.js';
import { VIEWS, DEFAULT_VIEW } from '../../assets/js/app.js';
import { hasString } from '../../assets/js/i18n.js';

describe('Home', () => {
  test('is the start page: #/home, offline, in a group of its own, first', () => {
    assert.deepEqual([id, titleKey, icon], ['home', 'nav.home', 'home']);
    assert.equal(DEFAULT_VIEW, 'home');
    assert.deepEqual([VIEWS[0].id, VIEWS[0].group, VIEWS[0].offline], ['home', 'home', true]);
    assert.deepEqual(VIEWS[0].css, ['views/home.css']);
    for (const key of ['nav.home', 'nav.home.desc', 'nav.home.purpose', 'start.task.portfolio']) {
      assert.ok(hasString(key, 'en') && hasString(key, 'tr'), key);
    }
  });

  test('isEmptyWorkspace: no recent domain, CT baseline, registration snapshot, accepted risk or server', () => {
    assert.equal(isEmptyWorkspace({}), true);
    assert.equal(isEmptyWorkspace({ recent: [], ctSeen: '', rdapSeen: '  ', waivers: '', servers: 0 }), true);
    assert.equal(isEmptyWorkspace({ recent: [{ value: 'example.com' }] }), false);
    assert.equal(isEmptyWorkspace({ ctSeen: '{"v":1,"domains":{}}' }), false);
    assert.equal(isEmptyWorkspace({ rdapSeen: '{"v":1}' }), false);
    assert.equal(isEmptyWorkspace({ waivers: '{"waivers":[]}' }), false);
    assert.equal(isEmptyWorkspace({ servers: 2 }), false);
  });

  test('homeFacts: the servers, the recent domains and the last activity, each only when there is one', () => {
    assert.deepEqual(homeFacts({ servers: 12, recent: 7, updatedAt: '2026-10-09T10:00:00.000Z' }), [
      { key: 'home.factServers', params: { count: 12 } }, { key: 'home.factRecent', params: { count: 7 } },
      { key: 'home.factActivity', params: { at: '2026-10-09T10:00:00.000Z' } }
    ]);
    assert.deepEqual(homeFacts({ servers: 0, recent: 1, updatedAt: null }), [{ key: 'home.factRecent', params: { count: 1 } }]);
    assert.deepEqual(homeFacts({ updatedAt: 'soon' }), []);
  });

  test('setupItems: a ✓ once the data exists; the four in order', () => {
    assert.deepEqual(SETUP_ITEMS, ['servers', 'cas', 'portfolio', 'workspaces']);
    assert.deepEqual(setupItems({}).map((i) => i.done), [false, false, false, false]);
    const done = setupItems({
      servers: 3, expectedCas: ["Let's Encrypt"], rdapSeen: '{"v":1,"domains":{"example.com":{"at":"2026-10-08T00:00:00.000Z"}}}', workspaces: 2, isDefault: true
    });
    assert.deepEqual(done.map((i) => [i.id, i.done]), [['servers', true], ['cas', true], ['portfolio', true], ['workspaces', true]]);
    assert.equal(setupItems({ rdapSeen: '{"v":1,"domains":{}}' })[2].done, false, 'a snapshot without a domain');
    assert.equal(setupItems({ workspaces: 1, isDefault: false })[3].done, true, 'this workspace renamed from Default');
  });

  test('recentEntries: the newest 8 with the quick actions their kind takes, each a fill-only route', () => {
    assert.deepEqual(RECENT_ACTIONS, ['health', 'domain', 'subdomains', 'lookup']);
    const list = Array.from({ length: 12 }, (_, i) => ({ value: `host${i}.example.com`, at: `2026-10-0${(i % 9) + 1}T00:00:00.000Z` }));
    const out = recentEntries(list);
    assert.equal(out.length, RECENT_SHOWN);
    assert.equal(out[0].value, 'host0.example.com', 'the list\'s order: newest first');
    assert.deepEqual(out[0].actions, [
      { view: 'health', params: { domain: 'host0.example.com', run: '0' } },
      { view: 'domain', params: { name: 'host0.example.com', run: '0' } },
      { view: 'subdomains', params: { domain: 'host0.example.com', run: '0' } },
      { view: 'lookup', params: { name: 'host0.example.com', run: '0' } }
    ]);
    const ip = recentEntries([{ value: '192.0.2.10', at: null }])[0];
    assert.deepEqual(ip.actions.map((a) => a.view), ['lookup'], 'an address takes DNS Lookup only');
    assert.deepEqual(recentEntries([null, { value: '' }, { at: 'x' }, 'example.com']), []);
  });

  test('keptResults: the page session\'s results, newest first, at most 6, with their open risks', () => {
    let t = Date.UTC(2026, 9, 9, 8, 0);
    const s = createSessionStore({ now: () => t });
    const views = VIEWS.filter((v) => v.id !== 'home');
    views.slice(0, 8).forEach((v, i) => s.keep(v.id, { subject: `${v.id}.example.com`, at: new Date(t + i * 60000), status: i === 7 ? { error: 1, warn: 2 } : null }));
    const out = keptResults(s, VIEWS);
    assert.equal(out.length, KEPT_SHOWN);
    assert.equal(out[0].view, views[7].id, 'the newest first');
    assert.deepEqual(out[0].status, { error: 1, warn: 2 });
    assert.equal(out[1].status, null);
    assert.ok(out.every((k, i) => i === 0 || out[i - 1].at >= k.at));
    assert.deepEqual(keptResults(createSessionStore(), VIEWS), [], 'a fresh tab: none (the card is left out)');
    t += 1;
  });

  test('This workspace: the first line of the notes, the accepted risks counted', () => {
    assert.equal(firstNoteLine('\n  Renewals every March.  \nCall the NOC first.'), 'Renewals every March.');
    assert.equal(firstNoteLine(''), '');
    assert.equal(firstNoteLine('x'.repeat(200)).length, 120);
    assert.ok(firstNoteLine('x'.repeat(200)).endsWith('…'));
    assert.equal(waiverCount('{"format":"domainscope-waivers","v":1,"waivers":[{"id":"w-1"},{"id":"w-2"}]}'), 2);
    assert.equal(waiverCount('[{"id":"w-1"}]'), 1);
    for (const junk of ['', '{', 'null', '{"waivers":"x"}', 42]) assert.equal(waiverCount(junk), 0);
  });
});
