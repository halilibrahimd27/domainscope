/**
 * lib/certtools.js — SSL Targets and Certificate on the page template (docs/DESIGN.md §5.6, §8
 * phase 3): the status items and what a press does, the key metrics, the Certificate's chain and
 * CAA states, SSL Targets' findings (the old summary alerts); with lib/renewal.js renewalStatus,
 * lib/estate.js estateStatus and lib/scanform.js setupSummary / setupSignature, the other three
 * tools' parts, as lib/template.js statusItems shows them. Pure Node.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  SCAN_STATUS, scanStatus, scanKeyMetric, scanFindings, certChainState, caaState, certStatus, certKeyMetric
} from '../../assets/js/lib/certtools.js';
import { statusItems, findingRows } from '../../assets/js/lib/template.js';
import { RENEWAL_HEAD_SEVERITY, RENEWAL_HEADLINES, renewalStatus, renewalSummary } from '../../assets/js/lib/renewal.js';
import { ESTATE_FILTERS, estateFilterCounts, estateMatches, estateStatus } from '../../assets/js/lib/estate.js';
import { SETUP_DOMAINS_SHOWN, setupSummary, setupSignature } from '../../assets/js/lib/scanform.js';

const keys = (list) => list.map((x) => x.key);

describe('SSL Targets: the status summary and the key metric', () => {
  const counts = { total: 9, unresolved: 1, nxdomain: 1, hidden: 2, covered: 6, cloudflare: 1, cdn: 1 };

  test('servers to update (a press opens Servers), not resolving, behind a CDN, covered (each a Hosts filter)', () => {
    const items = scanStatus({ counts, stats: { needsCert: 2, matchedServers: 3 }, cert: true, inventory: true });
    assert.deepEqual(keys(items), [...SCAN_STATUS]);
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count, x.filter, x.tab]), [
      ['servers', 'warn', 2, null, 'servers'],
      ['unresolved', 'warn', 2, 'unresolved', 'hosts'],
      ['behind', 'info', 2, 'hidden', 'hosts'],
      ['covered', 'ok', 6, 'covered', 'hosts']
    ]);
    assert.deepEqual(keys(statusItems(items)), ['servers', 'unresolved', 'behind', 'covered'], 'warn, warn, info, ok');
  });

  test('without a certificate: the servers the names point to (neutral), nothing covered; without a list or a result: no servers', () => {
    const items = scanStatus({ counts, stats: { needsCert: 2, matchedServers: 3 }, cert: false, inventory: true });
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count]).filter(([, , n]) => n), [['servers', 'neutral', 3], ['unresolved', 'warn', 2], ['behind', 'info', 2]]);
    assert.equal(scanStatus({ counts, stats: { needsCert: 2 }, cert: true, inventory: false })[0].count, 0, 'no server list');
    assert.equal(scanStatus({ counts, stats: null, cert: true, inventory: true })[0].count, 0, 'a running scan: no result yet');
    assert.deepEqual(statusItems(scanStatus()), [], 'nothing to say');
  });

  test('the key metric: the servers to update, or matched; null without a result or a list', () => {
    assert.deepEqual(scanKeyMetric({ stats: { needsCert: 2, matchedServers: 3 }, cert: true, inventory: true }), { value: 2, kind: 'needs', severity: 'warn' });
    assert.deepEqual(scanKeyMetric({ stats: { needsCert: 0 }, cert: true, inventory: true }), { value: 0, kind: 'needs', severity: null });
    assert.deepEqual(scanKeyMetric({ stats: { matchedServers: 3 }, cert: false, inventory: true }), { value: 3, kind: 'matched', severity: null });
    assert.equal(scanKeyMetric({ stats: { needsCert: 2 }, cert: true, inventory: false }), null);
    assert.equal(scanKeyMetric(), null);
  });
});

describe('SSL Targets: the findings (the old summary alerts)', () => {
  const textKeys = (list) => list.map((x) => `${x.key}:${x.severity}:${x.text ? x.text.key : x.raw || 'view'}`);

  test('a certificate scan with a server list: what needs it, what to check, how the names were found', () => {
    const list = scanFindings({
      inventory: true, cert: true, stats: { needsCert: 2, hiddenOrigin: 1, unmatchedIps: 4, dangling: 0 }, verify: true, mx: true,
      networks: ['203.0.113.0/24'], tech: { total: 7, dns: 7, sources: 0 }, failedSources: 0
    });
    assert.deepEqual(textKeys(list), [
      'needs:warn:scan.sum.needs', 'verify:info:scan.sum.verify', 'dane:info:scan.sum.dane', 'hidden:info:scan.sum.hidden',
      'networks:info:scan.sum.networks', 'discovery:info:scan.sum.discovery', 'unmatched:info:scan.sum.unmatched'
    ]);
    assert.deepEqual(list[0].text.params, { count: 2 });
    assert.deepEqual(list[4].text.params, { count: 1, list: '203.0.113.0/24' });
    assert.deepEqual(findingRows(list).shown.map((x) => x.key), ['needs', 'verify', 'dane'], 'the warning first, then the first notes');
  });

  test('no server needs it (ok); no certificate: the matched servers; no list: say how to add one', () => {
    assert.deepEqual(textKeys(scanFindings({ inventory: true, cert: true, stats: { needsCert: 0 } })), ['needs-none:ok:scan.sum.needsNone']);
    assert.deepEqual(textKeys(scanFindings({ inventory: true, cert: false, stats: { matchedServers: 3 } })), ['matched:info:scan.sum.matched']);
    assert.deepEqual(textKeys(scanFindings({ inventory: false, cert: true, stats: { needsCert: 0, unmatchedIps: 2 } })), ['no-inventory:info:scan.sum.noInventory'],
      'unmatched addresses mean nothing without a list');
  });

  test('topology: servers the list and DNS disagree on, names whose TLS ends nowhere (three named)', () => {
    const list = scanFindings({ inventory: true, cert: true, stats: { needsCert: 1 }, suspects: 2, nowhere: ['a.example.net', 'b.example.net', 'c.example.net', 'd.example.net'] });
    assert.deepEqual(keys(list), ['needs', 'topology-suspect', 'topology-nowhere']);
    assert.deepEqual(list[2].text.params, { count: 4, names: 'a.example.net, b.example.net, c.example.net…' });
  });

  test('several certificates: the renewal line (worded by the view) instead of "n servers need it", the names none covers', () => {
    const list = scanFindings({ inventory: true, cert: true, stats: { needsCert: 3 }, plan: { need: 2, uncovered: 1 }, verify: true });
    assert.deepEqual(textKeys(list), ['renewal:warn:view', 'renewal-uncovered:info:rw.sum.uncovered', 'verify:info:scan.sum.verifyMany']);
    assert.equal(scanFindings({ inventory: false, cert: true, plan: { need: 0, uncovered: 0 } }).find((x) => x.key === 'renewal').severity, 'info');
  });

  test('dangling CNAMEs are the error; wildcard DNS, a zone file, failed sources and the scanner\'s own warnings', () => {
    const list = scanFindings({
      inventory: true, cert: false, stats: { dangling: 2 }, tech: { total: 5, dns: 1, sources: 2, zone: 2 }, wildcards: ['*.example.net'],
      failedSources: 1, warnings: [{ code: 'WORDLIST_SHORT', detail: '10' }, { code: 'NEW_CODE', detail: 'x' }, null, { code: '' }],
      knownWarnings: ['WORDLIST_SHORT']
    });
    assert.deepEqual(textKeys(list), [
      'discovery:info:scan.sum.discoveryZone', 'dangling:error:scan.sum.dangling', 'wildcard:info:scan.sum.wildcard',
      'sources-failed:warn:scan.sum.sourcesFailed', 'WORDLIST_SHORT:warn:scan.warn.WORDLIST_SHORT', 'NEW_CODE:warn:NEW_CODE: x'
    ]);
    assert.equal(findingRows(list).shown[0].key, 'dangling', 'the error first');
    assert.deepEqual(scanFindings(), [{ key: 'no-inventory', severity: 'info', icon: 'server', text: { key: 'scan.sum.noInventory', params: {} } }]);
  });
});

describe('Certificate: the chain, CAA, the status summary and the key metric', () => {
  const issue = (...codes) => codes.map((code) => ({ code }));

  test('the chain: complete, incomplete (the leaf alone, a missing intermediate), issues, pending, unknown', () => {
    assert.equal(certChainState({ issues: issue('root-included') }), 'complete');
    assert.equal(certChainState({ issues: [] }), 'complete', 'a lone root CA');
    assert.equal(certChainState({ issues: issue('leaf-only') }), 'incomplete');
    assert.equal(certChainState({ issues: issue('ends-at'), end: 'intermediate' }), 'incomplete');
    assert.equal(certChainState({ issues: issue('ends-at'), end: 'root' }), 'complete', 'ends at a cross-signed root');
    assert.equal(certChainState({ issues: issue('ends-at'), end: 'pending' }), 'pending');
    assert.equal(certChainState({ issues: issue('ends-at'), end: 'unknown' }), 'unknown');
    assert.equal(certChainState({ issues: issue('ends-at'), end: 'unchecked' }), 'unknown');
    for (const code of ['order', 'unrelated', 'expired', 'self-signed']) assert.equal(certChainState({ issues: issue(code, 'root-included') }), 'issues', code);
    assert.equal(certChainState({ issues: issue('leaf-only'), fromCt: true }), 'unknown', 'a log holds the leaf only');
    assert.equal(certChainState(), 'complete');
  });

  test('CAA: unchecked until the tab checks, running, error, and what the names add up to', () => {
    const row = (allowed, verdict) => ({ verdict: { allowed, verdict } });
    assert.equal(caaState(null), 'unchecked');
    assert.equal(caaState({ status: 'aborted' }), 'unchecked');
    assert.equal(caaState({ status: 'running' }), 'running');
    assert.equal(caaState({ status: 'error' }), 'error');
    assert.equal(caaState({ status: 'done', rows: [row(true, 'allowed'), row(false, 'denied')] }), 'denied');
    assert.equal(caaState({ status: 'done', rows: [row(true, 'allowed'), { verdict: null }] }), 'unknown', 'a failed lookup');
    assert.equal(caaState({ status: 'done', rows: [row(true, 'allowed'), row(null, 'unknown')] }), 'unknown');
    assert.equal(caaState({ status: 'done', rows: [row(true, 'restricted'), row(true, 'allowed')] }), 'restricted');
    assert.equal(caaState({ status: 'done', rows: [row(true, 'allowed')] }), 'allowed');
    assert.equal(caaState({ status: 'done', rows: [] }, { names: 0 }), 'none', 'no name to check');
  });

  test('the status summary: validity, chain and CAA, each opening its tab; no CAA item without a name', () => {
    const items = certStatus({ validity: { state: 'expiring', days: 12 }, chain: 'incomplete', caa: 'denied' });
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.state, x.tab, x.count]), [
      ['validity', 'warn', 'expiring', 'details', 1], ['chain', 'warn', 'incomplete', 'chain', 1], ['caa', 'error', 'denied', 'caa', 1]
    ]);
    assert.equal(items[0].days, 12);
    assert.deepEqual(keys(statusItems(items)), ['caa', 'validity', 'chain'], 'the blocked CA first');
    const ok = certStatus({ validity: { state: 'ok', days: 300 }, chain: 'complete', caa: 'unchecked' });
    assert.deepEqual(ok.map((x) => x.severity), ['ok', 'neutral', 'neutral']);
    assert.deepEqual(keys(statusItems(ok)), ['validity', 'chain', 'caa']);
    assert.equal(certStatus({ validity: { state: 'expired', days: 3 }, caa: 'none' }).length, 2);
    assert.deepEqual(certStatus({ validity: { state: 'notyet', days: 2 }, chain: 'unknown', caa: 'allowed' }).map((x) => x.severity), ['warn', 'info', 'ok']);
  });

  test('the key metric: days left, since it expired, or until it is valid', () => {
    assert.deepEqual(certKeyMetric({ state: 'ok', days: 3378 }), { value: 3378, unit: 'left', severity: 'ok' });
    assert.deepEqual(certKeyMetric({ state: 'expiring', days: 12 }), { value: 12, unit: 'left', severity: 'warn' });
    assert.deepEqual(certKeyMetric({ state: 'expired', days: 3 }), { value: 3, unit: 'ago', severity: 'error' });
    assert.deepEqual(certKeyMetric({ state: 'notyet', days: 5 }), { value: 5, unit: 'until', severity: 'warn' });
    assert.deepEqual(certKeyMetric(null), { value: 0, unit: 'left', severity: 'ok' });
  });
});

describe('Renewal readiness: the status summary and the title\'s severity (lib/renewal.js)', () => {
  test('will fail, with warnings, could not be checked, ready — each a filter; a verdict tool keeps "0 will fail"', () => {
    const report = { names: [{ verdict: 'fail' }, { verdict: 'fail' }, { verdict: 'warnings' }, { verdict: 'ready' }] };
    const items = renewalStatus(renewalSummary(report));
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count, x.filter]), [
      ['fail', 'error', 2, 'fail'], ['warnings', 'warn', 1, 'warnings'], ['unknown', 'info', 0, 'unknown'], ['ready', 'ok', 1, 'ready']
    ]);
    assert.deepEqual(keys(statusItems(items, { verdict: true })), ['fail', 'warnings', 'ready']);
    const ready = renewalStatus(renewalSummary({ names: [{ verdict: 'ready' }] }));
    assert.deepEqual(statusItems(ready, { verdict: true }).map((x) => [x.key, x.count]), [['fail', 0], ['ready', 1]]);
    assert.equal(renewalStatus(null).every((x) => x.count === 0), true);
  });

  test('the headline\'s severity: fail is an error, could not be checked information', () => {
    assert.deepEqual(RENEWAL_HEADLINES.map((h) => RENEWAL_HEAD_SEVERITY[h]), ['error', 'info', 'warn', 'ok', null]);
    assert.ok(Object.isFrozen(RENEWAL_HEAD_SEVERITY));
  });
});

describe('Certificate estate: the status summary (lib/estate.js)', () => {
  const cert = (expiry, flags = []) => ({ expiry, flags, kind: 'other' });
  const estate = { certificates: [cert('expired'), cert('7d', ['weak']), cert('30d', ['name-conflict']), cert('90d', ['name-conflict', 'shared-key']), cert('later')] };

  test('expired and soon are the two halves of "expiring", and filters of their own', () => {
    assert.ok(ESTATE_FILTERS.indexOf('expired') > ESTATE_FILTERS.indexOf('expiring') && ESTATE_FILTERS.indexOf('soon') === ESTATE_FILTERS.indexOf('expired') + 1);
    const counts = estateFilterCounts(estate);
    assert.deepEqual([counts.expiring, counts.expired, counts.soon], [3, 1, 2]);
    assert.equal(estateMatches(cert('7d'), 'soon'), true);
    assert.equal(estateMatches(cert('expired'), 'soon'), false);
    assert.equal(estateMatches(cert('90d'), 'expired'), false);
  });

  test('expired (error), expiring within 30 days (warn), name conflicts, shared keys and weak (neutral) — each a filter; zeros out', () => {
    const items = estateStatus(estate);
    assert.deepEqual(items.map((x) => [x.key, x.severity, x.count, x.filter]), [
      ['expired', 'error', 1, 'expired'], ['soon', 'warn', 2, 'soon'], ['name-conflict', 'neutral', 2, 'name-conflict'],
      ['shared-key', 'neutral', 1, 'shared-key'], ['weak', 'neutral', 1, 'weak']
    ]);
    assert.deepEqual(keys(statusItems(estateStatus({ certificates: [cert('later')] }))), [], 'nothing to look at');
    assert.deepEqual(keys(statusItems(estateStatus(null))), []);
  });
});

describe('SSL Targets: the folded setup row and the setup\'s signature (lib/scanform.js)', () => {
  test('the certificate (or how many), the first domains and how many more, the servers, the options changed', () => {
    const row = setupSummary({ cert: { name: '*.example.net', key: 'RSA 2048' }, domains: ['example.net', 'example.org', 'example.com', 'example.net'], servers: 4, changes: [{ id: 'bruteforce' }, null] });
    assert.equal(SETUP_DOMAINS_SHOWN, 2);
    assert.deepEqual(row, {
      cert: { name: '*.example.net', key: 'RSA 2048' }, domains: { shown: ['example.net', 'example.org'], more: 1, fromCert: false }, servers: 4,
      options: [{ id: 'bruteforce' }]
    });
    assert.deepEqual(setupSummary({ cert: { name: 'a.example.net' }, certs: 3 }).cert, { many: 3 });
    assert.deepEqual(setupSummary({ cert: { name: '*.example.net' } }).domains, { shown: [], more: 0, fromCert: true }, 'no domain typed: the certificate\'s names');
    assert.deepEqual(setupSummary(), { cert: null, domains: { shown: [], more: 0, fromCert: false }, servers: 0, options: [] });
  });

  test('the signature: the same setup in another order is the same; a domain, certificate, option or zone mode is another', () => {
    const base = { domains: ['b.example.net', 'a.example.net'], certs: ['01|CN=CA'], extraNames: [], options: { sources: ['crtsh', 'anubis'], bruteforce: 'small', permutations: false, permutationBudget: 2000, includeExpired: false, originHints: true } };
    const sig = setupSignature(base);
    assert.equal(setupSignature({ ...base, domains: ['a.example.net', 'b.example.net'], options: { ...base.options, sources: ['anubis', 'crtsh'] } }), sig);
    assert.equal(setupSignature({ ...base, options: { ...base.options, permutationBudget: 500 } }), sig, 'a budget without permutations');
    for (const other of [
      { ...base, domains: ['a.example.net'] }, { ...base, certs: [] }, { ...base, extraNames: ['x.example.net'] },
      { ...base, options: { ...base.options, bruteforce: 'smart' } }, { ...base, options: { ...base.options, permutations: true } },
      { ...base, zone: 'exact' }
    ]) assert.notEqual(setupSignature(other), sig, JSON.stringify(other));
    assert.equal(typeof setupSignature(), 'string');
  });
});
