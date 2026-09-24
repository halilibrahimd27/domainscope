// Browser-readability metadata of the resolvers (resolvers.js browserReliable / issue) and how
// it is used: kept out of the default failover chain, shown as "not readable in browsers" (not
// as an error) in the Global DNS view, with a terminal command that asks the resolver directly.
// Live evidence: tests/live/browser-doh-matrix.mjs (real Chrome + Edge). No network here.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RESOLVERS, DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import { isBrowserBlocked, terminalCommand, groupAnswers } from '../../assets/js/views/global.js';

const unreliable = RESOLVERS.filter((r) => r.browserReliable === false);
const row = (resolver, values, extra = {}) => ({ kind: 'resolver', key: `resolver:${resolver.id}`, resolver, pending: false, values, ...extra });

describe('browser-unreadable resolvers (HTTP/3 without CORS)', () => {
  test('exactly Quad9 and Quad9 ECS, flagged h3-no-cors, none of them in DEFAULT_CHAIN', () => {
    assert.deepEqual(unreliable.map((r) => r.id).sort(), ['quad9', 'quad9-ecs']);
    for (const r of unreliable) {
      assert.equal(r.issue, 'h3-no-cors');
      assert.ok(!DEFAULT_CHAIN.includes(r.id), `${r.id} not in DEFAULT_CHAIN`);
    }
  });

  test('isBrowserBlocked: only a transport failure of an unreadable resolver', () => {
    const q9 = getResolver('quad9');
    const cf = getResolver('cloudflare');
    assert.equal(isBrowserBlocked(row(q9, ['ERROR'])), true);
    assert.equal(isBrowserBlocked(row(q9, ['93.184.215.14'])), false, 'an answer (HTTP/2, e.g. QUIC blocked) is shown normally');
    assert.equal(isBrowserBlocked(row(q9, ['NXDOMAIN'])), false);
    assert.equal(isBrowserBlocked(row(q9, ['ERROR'], { pending: true })), false);
    assert.equal(isBrowserBlocked(row(cf, ['ERROR'])), false, 'a readable resolver failing is a real failure');
    assert.equal(isBrowserBlocked({ kind: 'geo', resolver: q9, values: ['ERROR'], pending: false }), false);
    assert.equal(isBrowserBlocked(null), false);
  });

  test('every unreadable resolver gets a terminal command (classic DNS on its own address)', () => {
    assert.equal(terminalCommand('quad9', 'www.example.com', 'A'), 'dig @9.9.9.9 www.example.com A');
    assert.equal(terminalCommand('quad9-ecs', 'example.com', 'MX'), 'dig @9.9.9.11 example.com MX');
    for (const r of unreliable) assert.match(terminalCommand(r.id, 'example.com'), /^dig @\d+\.\d+\.\d+\.\d+ example\.com A$/);
    assert.equal(terminalCommand('cloudflare', 'example.com'), null);
    assert.equal(terminalCommand('quad9', ''), null);
  });

  test('unreadable rows are left out of the answer groups, so they never form an error group', () => {
    const rows = [
      row(getResolver('cloudflare'), ['1.2.3.4']),
      row(getResolver('google'), ['1.2.3.4']),
      row(getResolver('quad9'), ['ERROR']),
      row(getResolver('quad9-ecs'), ['ERROR'])
    ];
    const groups = groupAnswers(rows.filter((r) => !isBrowserBlocked(r)));
    assert.deepEqual(groups.map((g) => [g.letter, g.members.length, g.error]), [['A', 2, false]]);
  });
});
