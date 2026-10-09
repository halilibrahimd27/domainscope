/**
 * lib/netresults.js — the page template on "Map IPs to servers" and Servers (docs/DESIGN.md §5, §8
 * phase 5): the figures, status items, filters and folded zeros of IP Intel, Bulk Resolve,
 * Reverse DNS and Servers, the facts of Bulk Resolve's and Reverse DNS's Copy summary, the links a
 * result hands over and the columns of a table's Export ▾. The status items as lib/template.js
 * statusItems shows them. Pure Node; documentation addresses and names only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  IP_METRICS, IP_FOLDABLE, IP_FILTERS, ipFigures, ipMetricIds, ipStatus, ipRowMatches,
  BULK_METRICS, BULK_FOLDABLE, HANDOFF_MAX_IPS, BULK_LINK_MAX_NAMES, bulkStatus, bulkLookupFailed, bulkLinkParams, handoffIps, bulkSummaryFacts,
  PTR_METRICS, PTR_FOLDABLE, ptrStatus, ptrStatusOfFilter, ptrSummaryFacts,
  inventoryFigures, inventoryStatus, exportColumns, exportObjects
} from '../../assets/js/lib/netresults.js';
import { statusItems } from '../../assets/js/lib/template.js';
import { toCsv } from '../../assets/js/lib/export.js';
import { SWEEP_FILTERS, sweepSummary } from '../../assets/js/lib/ptrsweep.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { MAX_IPS } from '../../assets/js/views/ip.js';
import { BULK_FILTERS } from '../../assets/js/views/bulk.js';

const keys = (list) => list.map((x) => x.key);
const shown = (items, opts) => statusItems(items, opts).map((x) => `${x.key}:${x.count}`);

/** An IP Intel row as views/ip.js makes it. */
const ipRow = (ip, { kind = 'direct', provider = null, servers = [], info = null, pending = false } = {}) => ({
  ip, hosts: [], info, pending, servers: servers.map((name) => ({ name })),
  classification: { kind, provider: provider ? { name: provider } : null, hidesOrigin: kind === 'cloudflare' || kind === 'cdn' }
});
const answered = (asn, country) => ({ asn, country, ptr: [], errors: [], error: null });

describe('IP Intel', () => {
  const rows = [
    ipRow('203.0.113.7', { info: answered(64500, 'NL'), servers: ['web01'] }),
    ipRow('104.16.1.1', { kind: 'cloudflare', provider: 'Cloudflare', info: answered(13335, 'US') }),
    ipRow('2001:db8::10', { info: answered(64500, 'NL'), servers: ['web01', 'web02'] }),
    ipRow('10.0.0.1', { kind: 'private' }),
    ipRow('198.51.100.20', { pending: true })
  ];

  test('the figures: versions, behind a CDN with its providers, your servers by name, private, networks, countries, pending', () => {
    const f = ipFigures(rows);
    assert.deepEqual(f, {
      ips: 5, v4: 4, v6: 1, cdn: 1, providers: ['Cloudflare'], mine: 2, servers: ['web01', 'web02'], priv: 1, nets: 2,
      countries: ['NL', 'US'], pending: 1
    });
    assert.deepEqual(ipFigures(null), { ips: 0, v4: 0, v6: 0, cdn: 0, providers: [], mine: 0, servers: [], priv: 0, nets: 0, countries: [], pending: 0 });
    assert.equal(ipFigures([null, { ip: 7 }, ipRow('192.0.2.1')]).ips, 1, 'rows without an address are skipped');
  });

  test('the metrics: "Your servers" only with a server list; the zeros that may fold are known at once', () => {
    assert.deepEqual(IP_METRICS, ['ips', 'cdn', 'mine', 'priv', 'nets', 'countries']);
    assert.deepEqual(ipMetricIds({ inventory: true }), [...IP_METRICS]);
    assert.deepEqual(ipMetricIds(), ['ips', 'cdn', 'priv', 'nets', 'countries']);
    assert.deepEqual(IP_FOLDABLE, ['cdn', 'mine', 'priv']);
    assert.ok(IP_FOLDABLE.every((id) => IP_METRICS.includes(id)));
    assert.ok(Object.isFrozen(IP_METRICS) && Object.isFrozen(IP_FOLDABLE) && Object.isFrozen(IP_FILTERS));
  });

  test('the status summary: failed sources first, behind a CDN, then the neutral facts; your servers only with a list', () => {
    const figures = ipFigures(rows);
    const items = ipStatus({ figures, failedSources: 1, inventory: true });
    assert.deepEqual(keys(items), ['sources', 'cdn', 'nets', 'countries', 'mine', 'priv']);
    assert.deepEqual(shown(items), ['sources:1', 'cdn:1', 'nets:2', 'countries:2', 'mine:2'], 'five at most: private gives way to the failure');
    assert.deepEqual(shown(ipStatus({ figures })), ['cdn:1', 'nets:2', 'countries:2', 'priv:1'], 'no list: no "your servers"; no failure: none said');
    assert.deepEqual(items.filter((x) => x.filter).map((x) => x.filter), ['cdn', 'mine', 'private']);
    assert.deepEqual([...IP_FILTERS], ['cdn', 'mine', 'private']);
    assert.deepEqual(shown(ipStatus()), [], 'nothing looked up: no item');
  });

  test('the filters an item presses', () => {
    const pick = (f) => rows.filter((r) => ipRowMatches(r, f)).map((r) => r.ip);
    assert.deepEqual(pick('cdn'), ['104.16.1.1']);
    assert.deepEqual(pick('mine'), ['203.0.113.7', '2001:db8::10']);
    assert.deepEqual(pick('private'), ['10.0.0.1']);
    assert.equal(pick(null).length, rows.length, 'no filter: every row');
    assert.equal(pick('nets').length, rows.length, 'a fact filters nothing');
    assert.equal(ipRowMatches(null, 'cdn'), false);
  });
});

describe('Bulk Resolve', () => {
  const stats = { total: 8, resolved: 7, hidden: 2, cloudflare: 2, direct: 5, onServers: 2, unresolved: 1, errors: 0, ips: 7, v4: 7, v6: 0, servers: 2, mine: 2 };

  test('the status summary: lookup errors, not resolving, behind a CDN, then resolving, direct and your servers; each presses a Show filter', () => {
    const items = bulkStatus(stats, { inventory: true });
    assert.deepEqual(keys(items), ['errors', 'unresolved', 'hidden', 'resolving', 'direct', 'mine']);
    assert.deepEqual(shown(items), ['unresolved:1', 'hidden:2', 'resolving:7', 'direct:5', 'mine:2']);
    assert.deepEqual(shown(bulkStatus({ ...stats, errors: 1 }, { inventory: true })), ['errors:1', 'unresolved:1', 'hidden:2', 'resolving:7', 'direct:5'],
      'five at most: your servers give way to the failed lookups');
    assert.deepEqual(shown(bulkStatus(stats)), ['unresolved:1', 'hidden:2', 'resolving:7', 'direct:5'], 'no server list: no "your servers"');
    for (const x of items) assert.ok(BULK_FILTERS.includes(x.filter), `${x.key} → ${x.filter}`);
    assert.deepEqual(shown(bulkStatus(null)), []);
  });

  test('the metrics and their zeros: "not resolving" and "lookup failed" apart, as the status summary has them', () => {
    assert.deepEqual(BULK_METRICS, ['names', 'hidden', 'direct', 'unresolved', 'failed']);
    assert.ok(BULK_FOLDABLE.every((id) => BULK_METRICS.includes(id)) && !BULK_FOLDABLE.includes('names'));
    assert.ok(BULK_FOLDABLE.includes('failed'), 'no failed lookup: folded once the job ends');
  });

  test('a lookup failed when the resolver gave no answer to tell (SERVFAIL, REFUSED, a timeout): never "not resolving"', () => {
    const failed = (status) => bulkLookupFailed({ resolution: { status } });
    assert.deepEqual(['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'ERROR'].map(failed), [false, false, true, true, true]);
    assert.equal(bulkLookupFailed({ resolution: null }), true, 'no answer at all');
  });

  test('a link carries at most 40 host names (each once), else none', () => {
    assert.deepEqual(bulkLinkParams(['www.example.com', 'api.example.com', 'www.example.com']), { names: 'www.example.com,api.example.com' });
    const many = Array.from({ length: BULK_LINK_MAX_NAMES + 1 }, (_, i) => `h${i}.example.com`);
    assert.equal(bulkLinkParams(many), null);
    assert.equal(bulkLinkParams(many.slice(0, BULK_LINK_MAX_NAMES)).names.split(',').length, BULK_LINK_MAX_NAMES);
    assert.equal(bulkLinkParams([]), null);
    assert.equal(bulkLinkParams(null), null);
  });

  test('"Use in IP Intel" hands over each address once, at most what IP Intel looks up', () => {
    assert.equal(HANDOFF_MAX_IPS, MAX_IPS, 'views/ip.js MAX_IPS');
    assert.deepEqual(handoffIps(['203.0.113.10', '2001:db8::1', '203.0.113.10', '', null]), ['203.0.113.10', '2001:db8::1']);
    const many = Array.from({ length: 300 }, (_, i) => (i < 256 ? `192.0.2.${i}` : `198.51.100.${i - 256}`));
    assert.deepEqual(handoffIps(many), many.slice(0, HANDOFF_MAX_IPS));
    assert.deepEqual(handoffIps(new Set(['192.0.2.1'])), ['192.0.2.1'], 'any iterable (a job\'s Map keys)');
    assert.deepEqual(handoffIps(null), []);
  });

  /** A finished job as views/bulk.js keeps it. */
  function job(overrides = {}) {
    const row = (name, kind, ips, extra = {}) => ({
      name, ips, servers: extra.servers || [],
      resolution: { status: extra.status || (ips.length ? 'NOERROR' : 'NXDOMAIN') },
      classification: { kind, hidesOrigin: extra.hidesOrigin ?? (kind === 'cloudflare' || kind === 'cdn') }
    });
    const rows = [
      row('example.net', 'direct', ['203.0.113.10'], { servers: [{ name: 'web02' }] }),
      row('www.example.net', 'cloudflare', ['104.16.5.5']),
      row('shop.example.net', 'cdn', ['198.51.100.7']),
      // A hosting platform (GitHub Pages, Vercel …) does not hide an origin; a load balancer (AWS ELB) does.
      row('docs.example.net', 'platform', ['192.0.2.80']),
      row('lb.example.net', 'platform', ['198.51.100.8'], { hidesOrigin: true }),
      row('vpn.example.net', 'private', ['10.0.0.6']),
      row('staging.example.net', 'nxdomain', []),
      row('broken.example.net', 'unresolved', [], { status: 'SERVFAIL' })
    ];
    const ips = new Map([
      ['203.0.113.10', { ip: '203.0.113.10', version: 4, servers: [{ name: 'web02' }] }],
      ['104.16.5.5', { ip: '104.16.5.5', version: 4, servers: [] }],
      ['198.51.100.7', { ip: '198.51.100.7', version: 4, servers: [] }],
      ['192.0.2.80', { ip: '192.0.2.80', version: 4, servers: [] }],
      ['198.51.100.8', { ip: '198.51.100.8', version: 4, servers: [] }],
      ['10.0.0.6', { ip: '10.0.0.6', version: 4, servers: [] }],
      ['2001:db8::10', { ip: '2001:db8::10', version: 6, servers: [] }]
    ]);
    const at = new Date('2026-10-09T15:47:00Z');
    return { names: rows.map((r) => r.name), status: 'done', done: rows.length, rows, ips, finishedAt: at, ...overrides };
  }

  test('the facts of Copy summary: counts by class, the names that do not resolve or failed, the addresses, never a server\'s name', () => {
    const f = bulkSummaryFacts(job(), { inventory: true });
    assert.deepEqual(f, {
      names: 8, one: null, status: 'done', done: 8, resolved: 6, cloudflare: 1, cdn: 3, direct: 2, private: 1,
      notFound: ['staging.example.net'], failed: ['broken.example.net'], ips: 7, v4: 6, v6: 1, mine: 1, at: new Date('2026-10-09T15:47:00Z')
    });
    // "Other CDN / platform" is every other provider, whether it hides the origin or not (as Subdomains counts it).
    assert.equal(f.cloudflare + f.cdn + f.direct, f.resolved, 'each name that resolves in one class');
    assert.doesNotMatch(JSON.stringify(f), /web02/, 'no server name');
    assert.equal(bulkSummaryFacts(job()).mine, null, 'no server list: nothing said about one');
    assert.equal(bulkSummaryFacts(job({ names: ['example.net'] })).one, 'example.net');
    assert.equal(bulkSummaryFacts(job({ status: 'cancelled', done: 3 })).done, 3);
    assert.equal(bulkSummaryFacts(job({ status: 'running' })), null, 'a running job: nothing to copy');
    assert.equal(bulkSummaryFacts(null), null);
  });
});

describe('Reverse DNS', () => {
  const summary = { done: 16, withPtr: 12, templated: 9, noReverse: 3, failed: 1, focus: 2, byStatus: { confirmed: 10, mismatch: 2, 'no-ptr': 1, nxdomain: 2, servfail: 1, error: 0 } };

  test('the status summary: failed, not resolving back, confirmed, then with a PTR name and none; each presses a Show filter', () => {
    const items = ptrStatus(summary);
    assert.deepEqual(keys(items), ['failed', 'mismatch', 'confirmed', 'named', 'none']);
    assert.deepEqual(shown(items), ['failed:1', 'mismatch:2', 'confirmed:10', 'named:12', 'none:3']);
    for (const x of items) assert.ok(SWEEP_FILTERS.includes(x.filter), `${x.key} → ${x.filter}`);
    assert.deepEqual(shown(ptrStatus(null)), []);
  });

  test('the item a filter stands for, none for every address or the focus domain', () => {
    assert.deepEqual(SWEEP_FILTERS.map((f) => ptrStatusOfFilter(f)), [null, 'named', null, 'confirmed', 'mismatch', 'none', 'failed']);
  });

  test('the metrics and their zeros', () => {
    assert.deepEqual(PTR_METRICS, ['addresses', 'named', 'confirmed', 'none', 'failed', 'focus', 'servers']);
    assert.ok(PTR_FOLDABLE.every((id) => PTR_METRICS.includes(id)));
  });

  test('the facts of Copy summary from a real sweep summary: the counts, the names that do not resolve back, the focus names', () => {
    const r = (ip, status, names = [], extra = {}) => ({ ip, status, names, template: extra.template || null, version: 4, stage: extra.stage || null, confirmed: [], forward: [] });
    const results = [
      r('192.0.2.1', 'confirmed', ['mail.example.com']),
      r('192.0.2.2', 'mismatch', ['www.example.com']),
      r('192.0.2.3', 'nxdomain'),
      r('192.0.2.5', 'servfail')
    ];
    const s = sweepSummary(results, { focus: 'example.com' });
    const at = new Date('2026-10-09T15:48:00Z');
    const f = ptrSummaryFacts({ label: '192.0.2.0/29', planned: 8, status: 'cancelled', results, finishedAt: at },
      { summary: s, focus: 'example.com', focusNames: ['mail.example.com', 'www.example.com', 'mail.example.com'] });
    assert.deepEqual(f, {
      label: '192.0.2.0/29', planned: 8, status: 'cancelled', done: 4, withPtr: 2, templated: 0, noReverse: 1, failed: 1, confirmed: 1, mismatch: 1,
      mismatches: [{ ip: '192.0.2.2', name: 'www.example.com' }], focus: 'example.com', focusNames: ['mail.example.com', 'www.example.com'], at
    });
    assert.deepEqual(ptrSummaryFacts({ label: 'x', planned: 1, status: 'done', results: [] }, { summary: sweepSummary([]), focusNames: ['a.example.com'] }).focusNames, [], 'no focus domain: no focus names');
    assert.equal(ptrSummaryFacts({ status: 'running', results: [] }, { summary: s }), null);
    assert.equal(ptrSummaryFacts(null, { summary: s }), null);
  });
});

describe('Servers', () => {
  test('the figures and the status summary of a parsed list: warnings first, addresses and groups', () => {
    const parsed = parseInventory('[web]\nweb01 ansible_host=203.0.113.10\nweb02 ansible_host=2001:db8::12\n[db]\ndb01 ansible_host=10.0.0.5\n');
    const f = inventoryFigures(parsed);
    assert.deepEqual({ ...f, lines: f.lines > 0 }, { servers: 3, lines: true, ips: 3, v4: 2, v6: 1, priv: 1, groups: ['web', 'db'], warnings: 0 });
    assert.deepEqual(shown(inventoryStatus(f)), ['ips:3', 'groups:2']);
    const bad = inventoryFigures(parseInventory('web01 203.0.113.10\nweb02 203.0.113.10\n'));
    assert.ok(bad.warnings > 0, 'a duplicate address warns');
    assert.equal(statusItems(inventoryStatus(bad))[0].key, 'warnings');
    assert.deepEqual(inventoryFigures(null), { servers: 0, lines: 0, ips: 0, v4: 0, v6: 0, priv: 0, groups: [], warnings: 0 });
    assert.deepEqual(shown(inventoryStatus(null)), []);
  });
});

describe('a table\'s Export ▾', () => {
  const columns = [
    { key: 'ip', label: 'IP address', exportValue: (r) => r.ip, sortValue: () => 'nope' },
    { key: 'name', label: 'Name', searchValue: (r) => `${r.name} (searched)` },
    { key: 'asn', label: 'ASN', sortValue: (r) => r.asn },
    { key: 'raw', label: 'Raw' },
    { key: 'hosts', label: 'Hosts', exportHeader: 'hosts', exportValue: (r) => [r.name, null, '', 'b.example.com'] },
    { key: 'hidden', label: 'Only in the export', display: false, exportValue: () => 'kept' },
    { key: 'button', label: 'Find domains', export: false },
    null
  ];
  const rows = [{ ip: '192.0.2.1', name: 'a.example.com', asn: 64500, raw: '=1+1' }];

  test('the columns as the table\'s own buttons read them: exportValue, else searchValue, else sortValue, else the field', () => {
    const cols = exportColumns(columns);
    assert.deepEqual(cols.map((c) => [c.key, c.header]), [['ip', 'IP address'], ['name', 'Name'], ['asn', 'ASN'], ['raw', 'Raw'], ['hosts', 'hosts'], ['hidden', 'Only in the export']]);
    assert.deepEqual(exportObjects(rows, cols), [{ ip: '192.0.2.1', name: 'a.example.com (searched)', asn: 64500, raw: '=1+1', hosts: 'a.example.com b.example.com', hidden: 'kept' }]);
    assert.deepEqual(exportColumns(null), []);
    assert.deepEqual(exportObjects(null, cols), []);
  });

  test('CSV through lib/export.js: the headers, the values, a formula never evaluated', () => {
    const csv = toCsv(rows, exportColumns(columns));
    const [head, line] = csv.replace(/^﻿/, '').trim().split(/\r\n/);
    assert.equal(head, 'IP address,Name,ASN,Raw,hosts,Only in the export');
    assert.equal(line, '192.0.2.1,a.example.com (searched),64500,\'=1+1,a.example.com b.example.com,kept');
  });
});
