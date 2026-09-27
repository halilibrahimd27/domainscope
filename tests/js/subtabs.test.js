// Unit tests for the Subdomains results tabs model (assets/js/lib/subtabs.js): the route's tab,
// the automatic choice and when it moves, what a picked tab writes into the URL, the live tab
// badges, the Overview's summary alerts and the wrap points of a host name. Pure: no DOM, no storage.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  SUB_TABS, MAX_KEPT_LABEL, parseSubTab, autoSubTab, initialSubTab, subTabParams, nextAutoTab, summaryAlerts, subTabBadges,
  hostSegments
} from '../../assets/js/lib/subtabs.js';

const health = (source, state, extra = {}) => ({
  source, state, ok: ['ok', 'empty', 'partial'].includes(state), errorKind: null, ...extra
});

describe('parseSubTab — the route\'s tab=', () => {
  test('the four tabs in page order', () => {
    assert.deepEqual(SUB_TABS, ['overview', 'hosts', 'origins', 'sources']);
    assert.ok(Object.isFrozen(SUB_TABS));
    for (const id of SUB_TABS) assert.equal(parseSubTab(id), id);
  });

  test('anything else is no tab', () => {
    for (const v of [undefined, null, '', 'Hosts', 'records', ' hosts', 'hosts ', 1, {}, ['hosts'], '__proto__', 'constructor']) {
      assert.equal(parseSubTab(v), null, JSON.stringify(v));
    }
  });
});

describe('autoSubTab / initialSubTab — which tab a run opens', () => {
  test('Hosts once there is a host; before that Sources while live, Overview once ended', () => {
    assert.equal(autoSubTab({ hosts: 1, running: true }), 'hosts');
    assert.equal(autoSubTab({ hosts: 12, running: false }), 'hosts');
    assert.equal(autoSubTab({ hosts: 0, running: true }), 'sources');
    assert.equal(autoSubTab({ hosts: 0, running: false }), 'overview');
    assert.equal(autoSubTab(), 'overview');
    assert.equal(autoSubTab({ hosts: -3, running: true }), 'sources', 'a bad count is none');
    assert.equal(autoSubTab({ hosts: Number.NaN }), 'overview');
  });

  test('the route wins, then the page session\'s choice, else automatic', () => {
    assert.deepEqual(initialSubTab({ route: 'origins', chosen: 'sources', hosts: 5 }), { tab: 'origins', chosen: true });
    assert.deepEqual(initialSubTab({ route: null, chosen: 'sources', hosts: 5 }), { tab: 'sources', chosen: true });
    assert.deepEqual(initialSubTab({ route: 'nope', chosen: 'overview', hosts: 5 }), { tab: 'overview', chosen: true }, 'an unknown route tab is ignored');
    assert.deepEqual(initialSubTab({ hosts: 5 }), { tab: 'hosts', chosen: false });
    assert.deepEqual(initialSubTab({ hosts: 0, running: true }), { tab: 'sources', chosen: false });
    assert.deepEqual(initialSubTab({ route: 'x', chosen: 'y', hosts: 0 }), { tab: 'overview', chosen: false });
    assert.deepEqual(initialSubTab(), { tab: 'overview', chosen: false });
  });
});

describe('subTabParams — what a picked tab writes into the URL', () => {
  test('only tab= when the route already names a domain (merged, so domain and run=1 stay)', () => {
    assert.deepEqual(subTabParams('origins', { named: true, domains: ['example.com'] }), { tab: 'origins' });
  });

  test('after a return through the nav link: the domains of the run too, domain first', () => {
    const params = subTabParams('hosts', { named: false, domains: ['example.com', 'example.net'] });
    assert.deepEqual(params, { domain: 'example.com,example.net', tab: 'hosts' });
    assert.deepEqual(Object.keys(params), ['domain', 'tab']);
    assert.deepEqual(subTabParams('sources', { domains: ['example.org'] }), { domain: 'example.org', tab: 'sources' }, 'named defaults to false');
  });

  test('no domains to name: tab= alone; empty and non-string entries are skipped', () => {
    assert.deepEqual(subTabParams('hosts'), { tab: 'hosts' });
    assert.deepEqual(subTabParams('hosts', { domains: [] }), { tab: 'hosts' });
    assert.deepEqual(subTabParams('hosts', { domains: 'example.com' }), { tab: 'hosts' }, 'not a list');
    assert.deepEqual(subTabParams('hosts', { domains: ['', null, 'example.com', 7] }), { domain: 'example.com', tab: 'hosts' });
  });

  test('an unknown tab writes nothing', () => {
    for (const v of [undefined, null, '', 'records', 'Hosts', '__proto__']) {
      assert.deepEqual(subTabParams(v, { domains: ['example.com'] }), {}, JSON.stringify(v));
    }
  });
});

describe('nextAutoTab — an automatic choice follows the run', () => {
  test('Sources → Hosts when the first host streams in; Sources → Overview when the run ends empty', () => {
    assert.equal(nextAutoTab('sources', { hosts: 1, running: true }), 'hosts');
    assert.equal(nextAutoTab('sources', { hosts: 0, running: false }), 'overview');
    assert.equal(nextAutoTab('overview', { hosts: 3, running: false }), 'hosts', 'a re-run that found names');
  });

  test('stays when it already shows the automatic tab', () => {
    assert.equal(nextAutoTab('hosts', { hosts: 4, running: true }), null);
    assert.equal(nextAutoTab('hosts', { hosts: 4, running: false }), null);
    assert.equal(nextAutoTab('sources', { hosts: 0, running: true }), null);
  });

  test('never moves a tab the user chose, nor while the keyboard focus is inside the tabs', () => {
    assert.equal(nextAutoTab('origins', { chosen: true, hosts: 4, running: true }), null);
    assert.equal(nextAutoTab('sources', { chosen: true, hosts: 4, running: true }), null);
    assert.equal(nextAutoTab('sources', { focusInside: true, hosts: 4, running: true }), null);
    assert.equal(nextAutoTab('sources', { focusInside: false, hosts: 4, running: true }), 'hosts');
  });
});

describe('summaryAlerts — the Overview\'s alerts', () => {
  test('none while the run is live', () => {
    assert.deepEqual(summaryAlerts({ status: 'running', counts: { found: 0, dangling: 2 }, failedSources: 1 }), []);
    assert.deepEqual(summaryAlerts(), []);
  });

  test('display order and variants', () => {
    const got = summaryAlerts({
      status: 'done',
      counts: { found: 0, dangling: 2, cloudflare: 3 },
      failedSources: 1,
      wildcards: ['*.example.com', '', null],
      warnings: [{ code: 'BRUTEFORCE_TRUNCATED', detail: 20000 }, { code: '' }, null, { code: 'DNS_UNREACHABLE' }]
    });
    assert.deepEqual(got, [
      { key: 'none', variant: 'warn' },
      { key: 'sources-failed', variant: 'warn', count: 1 },
      { key: 'dangling', variant: 'error', count: 2 },
      { key: 'cloudflare', variant: 'info', count: 3 },
      { key: 'wildcard', variant: 'info', list: ['*.example.com'] },
      { key: 'BRUTEFORCE_TRUNCATED', variant: 'warn', detail: '20000' },
      { key: 'DNS_UNREACHABLE', variant: 'warn', detail: '' }
    ]);
  });

  test('"nothing found" only for a finished run; a cancelled one lists what it knows', () => {
    assert.deepEqual(summaryAlerts({ status: 'done', counts: { found: 4 } }), []);
    assert.deepEqual(summaryAlerts({ status: 'cancelled', counts: { found: 0 } }), []);
    assert.deepEqual(summaryAlerts({ status: 'error', counts: { found: 0, dangling: 1 } }).map((a) => a.key), ['dangling']);
  });
});

describe('subTabBadges — live counts on the tab labels', () => {
  test('nothing yet while a run starts', () => {
    assert.deepEqual(subTabBadges({ running: true }), { overview: null, hosts: null, origins: null, sources: null });
  });

  test('hosts: the listed names, 0 once a run ended empty', () => {
    assert.deepEqual(subTabBadges({ found: 42, running: true }).hosts, { value: 42, variant: null });
    assert.deepEqual(subTabBadges({ found: 0, running: false }).hosts, { value: 0, variant: null });
    assert.equal(subTabBadges({ found: 0, running: true }).hosts, null);
  });

  test('origins: hosts whose origin a proxy hides', () => {
    assert.deepEqual(subTabBadges({ proxied: 3 }).origins, { value: 3, variant: 'warn' });
    assert.equal(subTabBadges({ proxied: 0 }).origins, null);
  });

  test('sources: worked / asked, coloured by the worst state', () => {
    assert.equal(subTabBadges({ sources: 0, health: [health('crtsh', 'ok')] }).sources, null, 'no source asked');
    assert.deepEqual(subTabBadges({ sources: 3, health: [] }).sources, { value: '0/3', variant: null }, 'none answered yet');
    assert.deepEqual(subTabBadges({ sources: 3, health: [health('crtsh', 'ok')] }).sources, { value: '1/3', variant: null });
    assert.deepEqual(subTabBadges({ sources: 2, health: [health('crtsh', 'ok'), health('anubis', 'empty')] }).sources, { value: '2/2', variant: 'ok' });
    assert.deepEqual(subTabBadges({ sources: 2, health: [health('crtsh', 'partial'), health('anubis', 'ok')] }).sources, { value: '2/2', variant: 'warn' }, 'incomplete');
    assert.deepEqual(subTabBadges({ sources: 2, health: [health('otx', 'rate-limited'), health('anubis', 'ok')] }).sources, { value: '1/2', variant: 'warn' }, 'limited');
    assert.deepEqual(subTabBadges({ sources: 3, health: [health('otx', 'rate-limited'), health('crtsh', 'unavailable'), health('anubis', 'ok')] }).sources,
      { value: '1/3', variant: 'error' }, 'a failed source is the worst');
    for (const state of ['timeout', 'error']) assert.equal(subTabBadges({ sources: 1, health: [health('crtsh', state)] }).sources.variant, 'error', state);
  });

  test('sources: a cancelled request is neither a success nor a failure', () => {
    const got = subTabBadges({ sources: 2, health: [health('crtsh', 'error', { errorKind: 'abort' }), health('anubis', 'ok')] }).sources;
    assert.deepEqual(got, { value: '1/2', variant: null });
  });

  test('overview: the warnings and errors among the alerts', () => {
    const alerts = summaryAlerts({ status: 'done', counts: { found: 5, cloudflare: 2 }, wildcards: ['*.example.com'] });
    assert.equal(subTabBadges({ alerts }).overview, null, 'info alerts only');
    assert.deepEqual(subTabBadges({ alerts: [...alerts, { key: 'TRUNCATED', variant: 'warn' }] }).overview, { value: 1, variant: 'warn' });
    assert.deepEqual(subTabBadges({ alerts: [{ variant: 'warn' }, { variant: 'error' }, { variant: 'info' }] }).overview, { value: 2, variant: 'error' });
  });
});

describe('hostSegments — a host name wraps only after a dot', () => {
  const texts = (name, opts) => hostSegments(name, opts).map((s) => s.text);

  test('one segment per label, with its dot; joined they are the name', () => {
    assert.deepEqual(hostSegments('api.example.com'), [
      { text: 'api.', keep: true }, { text: 'example.', keep: true }, { text: 'com', keep: true }
    ]);
    for (const name of ['old-shop.example.com', 'a.b.c.d.example.co.uk', '*.api.example.org', 'xn--strae-oqa.example.net', 'example.com.']) {
      assert.equal(texts(name).join(''), name, name);
    }
  });

  test('a hyphen is no wrap point', () => {
    assert.deepEqual(texts('old-shop-v2.example.com'), ['old-shop-v2.', 'example.', 'com']);
  });

  test('a wildcard, a trailing dot, odd dots', () => {
    assert.deepEqual(texts('*.example.com'), ['*.', 'example.', 'com']);
    assert.deepEqual(texts('example.com.'), ['example.', 'com.']);
    assert.deepEqual(texts('.example.com'), ['.example.', 'com'], 'a leading dot stays with its label');
    assert.deepEqual(texts('a..example.com'), ['a.', '.example.', 'com']);
    assert.deepEqual(texts('localhost'), ['localhost']);
    assert.deepEqual(texts('.'), ['.']);
  });

  test('a label longer than maxLabel stays breakable', () => {
    const long = 'x'.repeat(MAX_KEPT_LABEL + 1);
    assert.deepEqual(hostSegments(`${long}.example.com`), [
      { text: `${long}.`, keep: false }, { text: 'example.', keep: true }, { text: 'com', keep: true }
    ]);
    assert.equal(hostSegments(`${'y'.repeat(MAX_KEPT_LABEL)}.example.com`)[0].keep, true, 'exactly maxLabel is kept');
    assert.deepEqual(hostSegments('abcd.example.com', { maxLabel: 3 }).map((s) => s.keep), [false, false, true]);
    assert.deepEqual(hostSegments('abcd.ex', { maxLabel: 0 }).map((s) => s.keep), [true, true], 'a bad maxLabel is the default');
  });

  test('empty and non-string input', () => {
    assert.deepEqual(hostSegments(''), []);
    assert.deepEqual(hostSegments(null), []);
    assert.deepEqual(hostSegments(undefined), []);
    assert.deepEqual(texts(42), ['42']);
  });
});
