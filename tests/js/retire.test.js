/**
 * lib/retire.js — "what still points at this address?": the address box (blocks, the /24 cap,
 * mapped and nested addresses, issues), range math, SPF coverage of an address (CIDR math, the
 * include path and what an include passes on, macros and failed lookups → "cannot tell"), one
 * domain's live evidence over a fake DoH client, the imported zone's candidates and their live
 * verification, the merged change list (severity, action, verification, groups, passive hits),
 * a whole check with events and an abort, the owners in the server list and the exports.
 * Pure Node, no network; documentation data only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseRetireTargets, parseDomainList, retireTokens, rangeOf, rangeRelation, blockOf, effectiveQualifier, spfCoverage,
  spfMxHosts, checkDomain, zoneCandidates, verifyZoneRefs, knownHostsFor, runRetireCheck, inventoryOwners, buildChanges,
  breakingChanges, passiveNewNames, retireExportRows, retireExportJson, RETIRE_CSV_COLUMNS, SEVERITIES, VERIFIED_STATES,
  CHANGE_ACTIONS, UNKNOWN_REASONS, RETIRE_MAX_ADDRESSES, FAILURE_KINDS, retireGaps
} from '../../assets/js/lib/retire.js';
import { spfLookupCount } from '../../assets/js/lib/health.js';
import { hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

/* ------------------------------------------------------------------------ */
/* A fake DohClient over a table                                            */
/* ------------------------------------------------------------------------ */

/**
 * table: name → { A, AAAA, CNAME (target), MX [{ preference, exchange }], NS [...], TXT [...], HTTPS [...] };
 * a name missing from the table is NXDOMAIN; `rcodes` / `fail` force an rcode or a transport failure
 * ('name|TYPE' or 'name'). A CNAME is followed like a recursive resolver does.
 */
function fakeDns(table, { rcodes = {}, fail = {}, delayMs = 0 } = {}) {
  const calls = [];
  const response = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ecs: null, ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { signal } = {}) {
    throwIfAborted(signal);
    if (delayMs) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, delayMs);
        signal?.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
      });
    }
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push(`${name}|${type}`);
    const f = fail[`${name}|${type}`] ?? fail[name];
    if (f) return response(name, type, { ok: false, rcode: null, error: f, errorKind: 'network' });
    const forced = rcodes[`${name}|${type}`] ?? rcodes[name];
    if (forced) return response(name, type, { rcode: forced });
    const answers = [];
    let cur = name;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = table[cur];
      if (!node) return response(name, type, { rcode: hop ? 'NXDOMAIN' : 'NXDOMAIN', answers });
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', ttl: 300, data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of node[type] || []) answers.push({ name: cur, type, ttl: 300, data });
      return response(name, type, { answers });
    }
    return response(name, type, { rcode: 'SERVFAIL' });
  }
  async function resolveHost(name, { signal } = {}) {
    const [a, aaaa] = await Promise.all([query(name, 'A', { signal }), query(name, 'AAAA', { signal })]);
    return hostResolutionFrom(name, a, aaaa);
  }
  return { query, resolveHost, calls };
}

const blocksOf = (text) => {
  const p = parseRetireTargets(text);
  assert.ok(p.ok, JSON.stringify(p.issues));
  return p.blocks;
};
const codes = (p) => p.issues.map((i) => i.code);

/* ------------------------------------------------------------------------ */

describe('the address box', () => {
  test('single addresses, brackets, a mapped IPv4, comments and separators', () => {
    const p = parseRetireTargets('# web01, retiring Friday\n192.0.2.10, [2001:db8::10]; ::ffff:198.51.100.7 # old mail');
    assert.equal(p.ok, true);
    assert.equal(p.kind, 'addresses');
    assert.deepEqual(p.blocks.map((b) => [b.cidr, b.label, b.version, b.single]), [
      ['192.0.2.10/32', '192.0.2.10', 4, true], ['2001:db8::10/128', '2001:db8::10', 6, true], ['198.51.100.7/32', '198.51.100.7', 4, true]
    ]);
    assert.deepEqual(p.addresses, ['192.0.2.10', '2001:db8::10', '198.51.100.7']);
    assert.equal(p.total, 3);
    assert.equal(p.label, '192.0.2.10, 2001:db8::10, 198.51.100.7');
    assert.deepEqual(p.issues, []);
    assert.deepEqual(retireTokens('a b,c;d\n# x\ne # y'), ['a', 'b', 'c', 'd', 'e']);
  });

  test('networks up to a /24 (IPv6 /120); host bits masked with a note; wider is an error', () => {
    const p = parseRetireTargets('192.0.2.5/28');
    assert.equal(p.ok, true);
    assert.equal(p.blocks[0].cidr, '192.0.2.0/28');
    assert.equal(p.blocks[0].size, 16);
    assert.equal(p.addresses.length, 16);
    assert.equal(p.addresses[15], '192.0.2.15');
    assert.deepEqual(p.issues.map((i) => [i.code, i.severity, i.params.network]), [['host-bits', 'info', '192.0.2.0/28']]);
    assert.equal(parseRetireTargets('192.0.2.0/24').ok, true);
    assert.equal(parseRetireTargets('2001:db8::/120').addresses.length, 256);
    for (const wide of ['192.0.2.0/23', '2001:db8::/64', '0.0.0.0/0']) {
      const w = parseRetireTargets(wide);
      assert.equal(w.ok, false, wide);
      assert.deepEqual(codes(w), ['too-large'], wide);
      assert.deepEqual(w.addresses, []);
    }
    assert.equal(parseRetireTargets('::ffff:192.0.2.0/124').blocks[0].cidr, '192.0.2.0/28', 'a mapped network is its IPv4 network');
  });

  test('a block inside another counts once; the cap counts distinct addresses', () => {
    const p = parseRetireTargets('192.0.2.7 192.0.2.0/28 192.0.2.0/28');
    assert.deepEqual(p.blocks.map((b) => b.cidr), ['192.0.2.0/28']);
    assert.equal(p.total, 16);
    const over = parseRetireTargets('192.0.2.0/24 198.51.100.1');
    assert.equal(over.ok, false);
    assert.deepEqual(codes(over), ['over-cap']);
    assert.equal(over.issues[0].params.count, RETIRE_MAX_ADDRESSES + 1);
  });

  test('junk is a warning, private space a note, nothing usable an error, empty nothing at all', () => {
    const p = parseRetireTargets('192.0.2.300 web01 10.0.0.5 192.0.2.10');
    assert.equal(p.ok, true);
    assert.deepEqual(codes(p), ['invalid', 'private']);
    assert.equal(p.issues[0].params.items, '192.0.2.300, web01');
    assert.equal(p.issues[1].params.items, '10.0.0.5');
    const junk = parseRetireTargets('web01 example.com');
    assert.equal(junk.ok, false);
    assert.deepEqual(codes(junk), ['invalid', 'nothing']);
    const empty = parseRetireTargets('  # nothing yet\n');
    assert.deepEqual([empty.kind, empty.ok, empty.issues.length], ['empty', false, 0]);
  });

  test('the domain box: URLs, wildcards, duplicates, no addresses or single labels, a cap', () => {
    const d = parseDomainList('https://Example.COM/login\n*.example.net example.com 192.0.2.1 intranet www.example.org.');
    assert.deepEqual(d.domains, ['example.com', 'example.net', 'www.example.org']);
    assert.deepEqual(d.invalid, ['192.0.2.1', 'intranet']);
    const many = parseDomainList(Array.from({ length: 30 }, (_, i) => `d${i}.example.com`).join(' '), { max: 25 });
    assert.equal(many.domains.length, 25);
    assert.equal(many.truncated, 5);
  });
});

describe('range math', () => {
  test('equal, contains, within, none — and never across families', () => {
    const block = rangeOf('192.0.2.10');
    assert.equal(rangeRelation(rangeOf('192.0.2.10'), block), 'equal');
    assert.equal(rangeRelation(rangeOf('192.0.2.0', 24), block), 'contains');
    assert.equal(rangeRelation(rangeOf('192.0.2.99', 24), block), 'contains', 'host bits of the range are masked');
    assert.equal(rangeRelation(rangeOf('0.0.0.0', 0), block), 'contains');
    assert.equal(rangeRelation(rangeOf('192.0.2.11'), block), null);
    assert.equal(rangeRelation(rangeOf('192.0.2.0', 25), block), 'contains');
    assert.equal(rangeRelation(rangeOf('192.0.2.128', 25), block), null);
    assert.equal(rangeRelation(rangeOf('192.0.2.10'), rangeOf('192.0.2.0', 28)), 'within');
    assert.equal(rangeRelation(rangeOf('2001:db8::'), block), null);
    assert.equal(rangeRelation(rangeOf('::ffff:192.0.2.10'), block), 'equal', 'a mapped address is its IPv4 address');
    assert.equal(rangeRelation(rangeOf('2001:db8::', 32), rangeOf('2001:db8::10')), 'contains');
    assert.equal(rangeOf('192.0.2.1', 33), null);
    assert.equal(rangeOf('nope'), null);
    const blocks = blocksOf('192.0.2.0/28 2001:db8::10');
    assert.equal(blockOf('192.0.2.15', blocks).cidr, '192.0.2.0/28');
    assert.equal(blockOf('192.0.2.16', blocks), null);
    assert.equal(blockOf('2001:0db8::0010', blocks).cidr, '2001:db8::10/128');
  });
});

/* ------------------------------------------------------------------------ */

describe('SPF coverage of an address', () => {
  test('what an include passes on: only a pass, then the include\'s own qualifier; a redirect passes it through', () => {
    assert.equal(effectiveQualifier([], '+'), '+');
    assert.equal(effectiveQualifier([], '~'), '~');
    assert.equal(effectiveQualifier([{ kind: 'include', qualifier: '+' }], '+'), '+');
    assert.equal(effectiveQualifier([{ kind: 'include', qualifier: '?' }], '+'), '?');
    assert.equal(effectiveQualifier([{ kind: 'include', qualifier: '+' }], '-'), null, 'a fail inside an include is no match');
    assert.equal(effectiveQualifier([{ kind: 'redirect', qualifier: '' }], '~'), '~');
    assert.equal(effectiveQualifier([{ kind: 'include', qualifier: '~' }, { kind: 'redirect', qualifier: '' }], '+'), '~');
    assert.equal(effectiveQualifier([{ kind: 'include', qualifier: '+' }, { kind: 'include', qualifier: '?' }], '+'), null);
  });

  test('ip4 / ip6 CIDR math, a and mx with their CIDR lengths, the include path, macros and ptr → cannot tell', async () => {
    const dns = fakeDns({
      'example.com': {
        TXT: ['v=spf1 ip4:192.0.2.0/24 a:mail.example.com a:web.example.com/24 mx//64 include:_spf.example.net ?include:_spf.example.org -ip4:198.51.100.7 exists:%{i}._ip.example.com ptr ~all'],
        MX: [{ preference: 10, exchange: 'mx1.example.com' }]
      },
      'mail.example.com': { A: ['192.0.2.10'] },
      'web.example.com': { A: ['192.0.2.99'] },
      'mx1.example.com': { AAAA: ['2001:db8::20'] },
      '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.10 ip6:2001:db8::/32 -all'] },
      '_spf.example.org': { TXT: ['v=spf1 ip4:192.0.2.8/29 -all'] }
    });
    const r = await spfLookupCount('example.com', { dns });
    // The tree carries what an address check needs (health.js extension).
    const t = r.tree.terms;
    assert.deepEqual(t.find((x) => x.term === 'a:mail.example.com').addresses, ['192.0.2.10']);
    assert.deepEqual(t.find((x) => x.term === 'mx//64').hosts, ['mx1.example.com']);
    assert.equal(t.find((x) => x.term === 'ip4:192.0.2.0/24').cidr4, 24);
    assert.deepEqual(spfMxHosts(r.tree), ['mx1.example.com']);

    const blocks = blocksOf('192.0.2.10 2001:db8::20');
    const mxAddresses = new Map([['mx1.example.com', { addresses: ['2001:db8::20'], error: null }]]);
    const cov = spfCoverage(r.tree, blocks, { mxAddresses });
    const got = cov.matches.map((m) => [m.term, m.relation, m.effective, m.block, m.path.join(' > '), m.via && m.via.host]);
    assert.deepEqual(got, [
      ['ip4:192.0.2.0/24', 'contains', '+', '192.0.2.10/32', 'example.com', null],
      ['a:mail.example.com', 'equal', '+', '192.0.2.10/32', 'example.com', 'mail.example.com'],
      ['a:web.example.com/24', 'contains', '+', '192.0.2.10/32', 'example.com', 'web.example.com'],
      ['mx//64', 'contains', '+', '2001:db8::20/128', 'example.com', 'mx1.example.com'],
      ['ip4:192.0.2.10', 'equal', '+', '192.0.2.10/32', 'example.com > _spf.example.net', null],
      ['ip6:2001:db8::/32', 'contains', '+', '2001:db8::20/128', 'example.com > _spf.example.net', null],
      ['ip4:192.0.2.8/29', 'contains', '?', '192.0.2.10/32', 'example.com > _spf.example.org', null]
    ]);
    const mx = cov.matches.find((m) => m.term === 'mx//64');
    assert.equal(mx.range, '2001:db8::/64', 'the MX host\'s address widened by the CIDR length');
    assert.deepEqual(cov.unknown.map((u) => [u.term, u.reason]), [['exists:%{i}._ip.example.com', 'macro'], ['ptr', 'ptr']]);
    // -ip4:198.51.100.7 is another address: nothing.
    assert.ok(!cov.matches.some((m) => m.term.includes('198.51.100.7')));
  });

  test('a fail qualifier, a macro include, failed and skipped lookups, an MX host without an answer (hand-built tree)', () => {
    const term = (x) => ({ lookup: false, void: false, macro: false, error: null, child: null, value: null, cidr4: null, cidr6: null, target: null, ...x });
    const tree = {
      domain: 'example.com', record: 'v=spf1 …', terms: [
        term({ term: '-ip4:192.0.2.10', mechanism: 'ip4', qualifier: '-', value: '192.0.2.10', cidr4: 32 }),
        term({ term: 'include:%{l}.example.net', mechanism: 'include', qualifier: '+', macro: true, lookup: true }),
        term({ term: 'a:down.example.com', mechanism: 'a', qualifier: '+', target: 'down.example.com', error: 'dns-error', lookup: true }),
        term({ term: 'a:late.example.com', mechanism: 'a', qualifier: '+', target: 'late.example.com', skipped: true, lookup: true }),
        term({ term: 'mx:example.org', mechanism: 'mx', qualifier: '+', target: 'example.org', hosts: ['mx.example.org'], lookup: true }),
        term({
          term: 'include:gone.example.net', mechanism: 'include', qualifier: '+', target: 'gone.example.net', lookup: true,
          child: { domain: 'gone.example.net', record: null, terms: [], errors: [{ code: 'dns-error', domain: 'gone.example.net' }] }
        }),
        term({
          term: 'include:none.example.net', mechanism: 'include', qualifier: '+', target: 'none.example.net', lookup: true, error: 'no-record',
          child: { domain: 'none.example.net', record: null, terms: [], errors: [{ code: 'no-record', domain: 'none.example.net' }] }
        }),
        term({ term: 'exists:static.example.com', mechanism: 'exists', qualifier: '+', target: 'static.example.com', lookup: true }),
        term({ term: 'redirect=%{d}.example.net', mechanism: 'redirect', qualifier: '', macro: true, target: 'example.com.example.net', skipped: true, lookup: true })
      ]
    };
    const cov = spfCoverage(tree, blocksOf('192.0.2.10'), { mxAddresses: new Map([['mx.example.org', { addresses: [], error: 'SERVFAIL' }]]) });
    assert.deepEqual(cov.matches.map((m) => [m.term, m.qualifier, m.effective]), [['-ip4:192.0.2.10', '-', '-']]);
    assert.deepEqual(cov.unknown.map((u) => [u.term, u.reason, u.target]), [
      ['include:%{l}.example.net', 'macro', null],
      ['a:down.example.com', 'lookup-failed', 'down.example.com'],
      ['a:late.example.com', 'skipped', 'late.example.com'],
      ['mx:example.org', 'lookup-failed', 'mx.example.org'],
      ['include:gone.example.net', 'include-failed', 'gone.example.net'],
      ['redirect=%{d}.example.net', 'skipped', 'example.com.example.net']
    ]);
    assert.deepEqual(UNKNOWN_REASONS.filter((r) => !cov.unknown.some((u) => u.reason === r)), ['ptr', 'multiple']);
    assert.deepEqual(spfCoverage(null, []), { matches: [], unknown: [] });
  });
});

/* ------------------------------------------------------------------------ */

/** One domain with every kind of reference to 192.0.2.10. */
function exampleTable() {
  return {
    'example.com': {
      A: ['192.0.2.10'],
      MX: [{ preference: 10, exchange: 'mail.example.com' }, { preference: 20, exchange: 'mx2.example.net' }],
      NS: ['ns1.example.com', 'ns2.example.net'],
      TXT: ['v=spf1 ip4:192.0.2.10 include:_spf.example.net ~all'],
      HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h2'], ipv4hint: ['192.0.2.10'] } }]
    },
    'www.example.com': { CNAME: 'lb.example.net' },
    'lb.example.net': { A: ['192.0.2.10', '198.51.100.5'] },
    'api.example.com': { A: ['198.51.100.6'] },
    'mail.example.com': { A: ['192.0.2.10'] },
    'mx2.example.net': { A: ['198.51.100.8'] },
    'ns1.example.com': { A: ['192.0.2.10'] },
    'ns2.example.net': { A: ['198.51.100.9'] },
    '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] }
  };
}

describe('one domain over DoH', () => {
  test('its name, the known hosts, MX and NS hosts, SPF and the HTTPS hints; a failed lookup is a failure', async () => {
    const dns = fakeDns(exampleTable(), { rcodes: { 'broken.example.com': 'SERVFAIL' } });
    const blocks = blocksOf('192.0.2.10');
    const progress = [];
    const c = await checkDomain('Example.com.', {
      dns, blocks, signal: undefined,
      hosts: [{ name: 'www.example.com', source: 'scan' }, 'api.example.com', { name: 'broken.example.com', source: 'zone' }, 'bad name'],
      onLookup: (done, total) => progress.push([done, total])
    });
    assert.equal(c.domain, 'example.com');
    const byName = Object.fromEntries(c.names.map((n) => [n.name, n]));
    assert.deepEqual(byName['example.com'].roles, ['apex']);
    assert.deepEqual(byName['www.example.com'].cnames, ['lb.example.net']);
    assert.deepEqual(byName['www.example.com'].sources, ['scan']);
    assert.deepEqual(byName['mail.example.com'].roles, ['mx']);
    assert.deepEqual(byName['ns1.example.com'].roles, ['ns']);
    assert.equal(byName['broken.example.com'].status, 'SERVFAIL');
    assert.deepEqual(c.mx, { status: 'ok', error: null, hosts: [{ host: 'mail.example.com', preference: 10 }, { host: 'mx2.example.net', preference: 20 }] });
    assert.deepEqual(c.ns.hosts, ['ns1.example.com', 'ns2.example.net']);
    assert.deepEqual(c.https.hints, [{ owner: 'example.com', address: '192.0.2.10' }]);
    assert.equal(c.spf.status, 'ok');
    assert.deepEqual(c.spf.matches.map((m) => [m.term, m.effective, m.path.join('>')]), [
      ['ip4:192.0.2.10', '+', 'example.com'], ['ip4:192.0.2.0/24', '+', 'example.com>_spf.example.net']
    ]);
    assert.deepEqual(c.failures.map((f) => [f.what, f.name, f.error]), [['name', 'broken.example.com', 'SERVFAIL']]);
    const [done, total] = progress[progress.length - 1];
    assert.equal(done, total, 'progress ends complete');
  });

  test('no SPF, no MX / NS, a failed MX lookup and multiple SPF records', async () => {
    const dns = fakeDns({
      'example.org': { A: ['198.51.100.1'], TXT: ['v=spf1 -all', 'v=spf1 ip4:192.0.2.10 -all'] },
      'example.net': { A: ['198.51.100.2'] }
    }, { fail: { 'example.org|MX': 'timeout' } });
    const blocks = blocksOf('192.0.2.10');
    const org = await checkDomain('example.org', { dns, blocks });
    assert.equal(org.mx.status, 'failed');
    assert.equal(org.spf.status, 'multiple');
    assert.deepEqual(org.spf.unknown.map((u) => u.reason), ['multiple']);
    assert.deepEqual(org.failures.map((f) => f.what), ['mx']);
    const net = await checkDomain('example.net', { dns, blocks });
    assert.deepEqual([net.mx.status, net.ns.status, net.spf.status, net.https.status], ['none', 'none', 'none', 'none']);
    await assert.rejects(checkDomain('not a domain', { dns, blocks }), TypeError);
    await assert.rejects(checkDomain('example.net', { dns, blocks, signal: AbortSignal.abort() }), { name: 'AbortError' });
  });

  test('an SPF record that could not be read is a "cannot tell" row, never "no SPF"', async () => {
    const dns = fakeDns({ 'example.org': { A: ['198.51.100.1'], TXT: ['v=spf1 ip4:192.0.2.10 -all'] } }, { rcodes: { 'example.org|TXT': 'SERVFAIL' } });
    const blocks = blocksOf('192.0.2.10');
    const c = await checkDomain('example.org', { dns, blocks });
    assert.equal(c.spf.status, 'failed');
    assert.deepEqual(c.spf.unknown.map((u) => [u.holder, u.mechanism, u.reason, u.term]), [['example.org', 'record', 'lookup-failed', '']]);
    assert.deepEqual(c.failures.map((f) => f.what), ['spf']);
    const built = buildChanges({ blocks, checks: [c] });
    assert.deepEqual(built.changes.map((x) => [x.group, x.name, x.type, x.severity, x.action, x.verified, x.reason]), [
      ['example.org', 'example.org', 'TXT', 'unknown', 'check', 'unknown', 'lookup-failed']
    ]);
    assert.equal(built.counts.bySeverity.unknown, 1);
    assert.equal(built.counts.breaking, 0);
  });
});

describe('what a check could not settle', () => {
  const blocks = () => blocksOf('192.0.2.10');

  test('every lookup failing: each kind counted, the SPF row "cannot tell", never settled', async () => {
    const dns = fakeDns({ 'example.org': { A: ['192.0.2.10'] } }, { rcodes: { 'example.org': 'SERVFAIL' } });
    const c = await checkDomain('example.org', { dns, blocks: blocks() });
    assert.deepEqual(c.failures.map((f) => f.what).sort(), ['https', 'mx', 'name', 'ns', 'spf']);
    const built = buildChanges({ blocks: blocks(), checks: [c] });
    assert.equal(built.counts.total, 1, 'only the SPF row, which cannot be told');
    const gaps = retireGaps({ domains: ['example.org'], checks: [c], counts: built.counts });
    assert.deepEqual(gaps, {
      failed: 5, failures: { name: 1, mx: 1, ns: 1, spf: 1, https: 1, domain: 0, zone: 0 }, unknown: 1, notChecked: [], stopped: false, settled: false
    });
    assert.deepEqual(FAILURE_KINDS.filter((k) => !(k in gaps.failures)), []);
  });

  test('a clean check is settled; a stop, an unchecked domain, a failed domain, a failed zone lookup or a "cannot tell" is not', async () => {
    const dns = fakeDns({ 'example.net': { A: ['198.51.100.2'] } });
    const c = await checkDomain('example.net', { dns, blocks: blocks() });
    const built = buildChanges({ blocks: blocks(), checks: [c] });
    assert.equal(built.counts.total, 0);
    assert.equal(retireGaps({ domains: ['example.net'], checks: [c], counts: built.counts }).settled, true);
    const stopped = retireGaps({ domains: ['example.net', 'example.org', 'example.com'], checks: [c], errors: [{ domain: 'example.com', error: 'x' }], aborted: true });
    assert.deepEqual([stopped.notChecked, stopped.stopped, stopped.failures.domain, stopped.failed, stopped.settled], [['example.org'], true, 1, 1, false]);
    const zone = retireGaps({ domains: ['example.net'], checks: [c], zone: [{ live: null }, { live: true }, {}] });
    assert.deepEqual([zone.failures.zone, zone.settled], [1, false]);
    const unknown = retireGaps({ domains: ['example.net'], checks: [c], counts: { bySeverity: { unknown: 2 } } });
    assert.deepEqual([unknown.unknown, unknown.failed, unknown.settled], [2, 0, false]);
    assert.equal(retireGaps().settled, true, 'nothing asked, nothing open');
  });
});

describe('the change list', () => {
  test('severity, action, verification and groups of every live reference', async () => {
    const dns = fakeDns(exampleTable());
    const blocks = blocksOf('192.0.2.10');
    const check = await checkDomain('example.com', { dns, blocks, hosts: ['www.example.com', 'api.example.com'] });
    const { changes, groups, counts } = buildChanges({ blocks, checks: [check] });
    const rows = changes.map((c) => [c.group, c.severity, c.name, c.type, c.value, c.action, c.verified]);
    assert.deepEqual(rows, [
      ['example.com', 'mail', 'example.com', 'MX', '10 mail.example.com', 'repoint', 'live'],
      ['example.com', 'mail', 'example.com', 'TXT', 'ip4:192.0.2.10', 'remove', 'live'],
      ['example.com', 'mail', 'mail.example.com', 'A', '192.0.2.10', 'remove', 'live'],
      ['other', 'mail', '_spf.example.net', 'TXT', 'ip4:192.0.2.0/24', 'provider', 'live'],
      ['example.com', 'ns', 'example.com', 'NS', 'ns1.example.com', 'glue', 'live'],
      ['example.com', 'ns', 'ns1.example.com', 'A', '192.0.2.10', 'remove', 'live'],
      ['example.com', 'live', 'example.com', 'A', '192.0.2.10', 'remove', 'live'],
      ['example.com', 'live', 'example.com', 'HTTPS', '192.0.2.10', 'remove', 'live'],
      ['other', 'live', 'lb.example.net', 'A', '192.0.2.10', 'remove', 'live'],
      ['example.com', 'chain', 'www.example.com', 'CNAME', 'lb.example.net', 'follow', 'live']
    ]);
    assert.deepEqual(changes.find((c) => c.type === 'CNAME').via, ['www.example.com', 'lb.example.net']);
    assert.deepEqual(changes.find((c) => c.name === 'lb.example.net').foundFor, ['example.com']);
    assert.deepEqual(changes.find((c) => c.name === '_spf.example.net').via, ['example.com', '_spf.example.net']);
    assert.deepEqual(groups.map((g) => [g.key, g.kind, g.changes.length]), [['example.com', 'domain', 8], ['other', 'other', 2]]);
    assert.equal(counts.total, 10);
    assert.equal(counts.breaking, 10);
    assert.equal(counts.bySeverity.mail, 4);
    assert.ok(!changes.some((c) => c.name === 'api.example.com'), 'another address: nothing');
    for (const c of changes) {
      assert.ok(SEVERITIES.includes(c.severity) && VERIFIED_STATES.includes(c.verified) && CHANGE_ACTIONS.includes(c.action), c.key);
    }
  });

  test('an SPF term that does not authorize is stale; a range wider than the block is narrowed; cannot tell is its own row', () => {
    const blocks = blocksOf('192.0.2.10');
    const check = {
      domain: 'example.com', names: [], failures: [],
      mx: { status: 'none', hosts: [] }, ns: { status: 'none', hosts: [] }, https: { status: 'none', hints: [] },
      spf: {
        status: 'ok', matches: [
          { path: ['example.com'], holder: 'example.com', record: 'r', term: '-ip4:192.0.2.10', mechanism: 'ip4', qualifier: '-', effective: '-', relation: 'equal', block: '192.0.2.10/32', range: '192.0.2.10/32', via: null },
          { path: ['example.com'], holder: 'example.com', record: 'r', term: 'ip4:192.0.2.0/25', mechanism: 'ip4', qualifier: '+', effective: '+', relation: 'contains', block: '192.0.2.10/32', range: '192.0.2.0/25', via: null },
          { path: ['example.com', 'spf.example.com'], holder: 'spf.example.com', record: 'r2', term: 'ip4:192.0.2.10', mechanism: 'ip4', qualifier: '+', effective: null, relation: 'equal', block: '192.0.2.10/32', range: '192.0.2.10/32', via: null }
        ],
        unknown: [{ path: ['example.com'], holder: 'example.com', record: 'r', term: 'exists:%{i}.x.example.com', mechanism: 'exists', reason: 'macro', target: null }]
      }
    };
    const { changes } = buildChanges({ blocks, checks: [check] });
    assert.deepEqual(changes.map((c) => [c.name, c.value, c.severity, c.action, c.verified, c.reason]), [
      ['example.com', 'ip4:192.0.2.0/25', 'mail', 'narrow', 'live', null],
      ['example.com', '-ip4:192.0.2.10', 'stale', 'remove', 'live', null],
      ['spf.example.com', 'ip4:192.0.2.10', 'stale', 'remove', 'live', null],
      ['example.com', 'exists:%{i}.x.example.com', 'unknown', 'check', 'unknown', 'macro']
    ]);
    assert.deepEqual(breakingChanges(changes).map((c) => c.value), ['ip4:192.0.2.0/25']);
  });
});

/* ------------------------------------------------------------------------ */

/** Reference records as the Zone File view publishes them (zoneorigins.referenceRecords). */
const rec = (name, type, value, extra = {}) => ({
  name, type, value, preference: null, hints: [], proxied: null, internal: false, occluded: false, ttl: 300, line: 1, ...extra
});
function zoneRecords() {
  return [
    rec('example.com', 'A', '192.0.2.10', { line: 3 }),
    rec('www.example.com', 'A', '192.0.2.10', { proxied: true, line: 4 }),
    rec('blog.example.com', 'CNAME', 'www.example.com', { proxied: false, line: 5 }),
    rec('old.example.com', 'A', '192.0.2.10', { line: 6 }),
    rec('example.com', 'MX', 'mail.example.com', { preference: 10, line: 7 }),
    rec('mail.example.com', 'A', '192.0.2.10', { line: 8 }),
    rec('_sip._tcp.example.com', 'SRV', 'mail.example.com', { line: 9 }),
    rec('example.com', 'HTTPS', '.', { hints: ['192.0.2.10'], line: 10 }),
    rec('example.com', 'TXT', 'v=spf1 ip4:192.0.2.0/24 -all', { line: 11 }),
    rec('intranet.example.com', 'A', '192.0.2.10', { internal: true, line: 12 }),
    rec('*.dev.example.com', 'A', '192.0.2.10', { line: 13 }),
    rec('api.example.com', 'A', '198.51.100.6', { line: 14 }),
    rec('loop1.example.com', 'CNAME', 'loop2.example.com', { line: 15 }),
    rec('loop2.example.com', 'CNAME', 'loop1.example.com', { line: 16 })
  ];
}

describe('the imported zone', () => {
  test('every record that reaches an address: A / AAAA, in-zone chains, MX / SRV targets, hints, SPF ranges, proxied origins', () => {
    const refs = zoneCandidates(zoneRecords(), blocksOf('192.0.2.10'));
    assert.deepEqual(refs.map((r) => [r.name, r.type, r.value, r.via.join('>'), r.proxied, !!r.spf, r.hint]), [
      ['example.com', 'A', '192.0.2.10', '', null, false, false],
      ['www.example.com', 'A', '192.0.2.10', '', true, false, false],
      ['blog.example.com', 'CNAME', 'www.example.com', 'www.example.com', true, false, false],
      ['old.example.com', 'A', '192.0.2.10', '', null, false, false],
      ['example.com', 'MX', 'mail.example.com', 'mail.example.com', null, false, false],
      ['mail.example.com', 'A', '192.0.2.10', '', null, false, false],
      ['_sip._tcp.example.com', 'SRV', 'mail.example.com', 'mail.example.com', null, false, false],
      ['example.com', 'HTTPS', '192.0.2.10', '', null, false, true],
      ['example.com', 'TXT', 'v=spf1 ip4:192.0.2.0/24 -all', '', null, true, false],
      ['intranet.example.com', 'A', '192.0.2.10', '', null, false, false],
      ['*.dev.example.com', 'A', '192.0.2.10', '', null, false, false]
    ]);
    const spf = refs.find((r) => r.spf);
    assert.deepEqual(spf.spf, { term: 'ip4:192.0.2.0/24', qualifier: '+', relation: 'contains', range: '192.0.2.0/24' });
    assert.deepEqual(zoneCandidates(null, []), []);
  });

  test('verified live: served, gone from DNS, a failed lookup; proxied, internal and wildcard names are never asked', async () => {
    const dns = fakeDns({
      'example.com': { A: ['192.0.2.10'], MX: [{ preference: 10, exchange: 'mail.example.com' }], TXT: ['v=spf1 ip4:192.0.2.0/24 -all'], HTTPS: [{ priority: 1, target: '.', params: { ipv4hint: ['198.51.100.1'] } }] },
      'mail.example.com': { A: ['192.0.2.10'] },
      'old.example.com': { A: ['198.51.100.44'] },
      '_sip._tcp.example.com': { SRV: [{ priority: 10, weight: 5, port: 5060, target: 'mail.example.com' }] }
    }, { rcodes: { 'www.example.com': 'SERVFAIL' } });
    const refs = zoneCandidates(zoneRecords(), blocksOf('192.0.2.10'));
    const verified = await verifyZoneRefs(refs, { dns });
    assert.deepEqual(verified.map((r) => [r.name, r.type, r.live]), [
      ['example.com', 'A', true],
      ['www.example.com', 'A', undefined],
      ['blog.example.com', 'CNAME', undefined],
      ['old.example.com', 'A', false],
      ['example.com', 'MX', true],
      ['mail.example.com', 'A', true],
      ['_sip._tcp.example.com', 'SRV', true],
      ['example.com', 'HTTPS', false],
      ['example.com', 'TXT', true],
      ['intranet.example.com', 'A', undefined],
      ['*.dev.example.com', 'A', undefined]
    ]);
    assert.ok(!dns.calls.some((c) => c.startsWith('intranet.') || c.startsWith('*.') || c.startsWith('www.') || c.startsWith('blog.')), 'nothing sent for them');
    await assert.rejects(verifyZoneRefs(refs, {}), TypeError);
  });

  test('zone rows join the live rows; the rest are origin / file / internal rows under the zone\'s origin', async () => {
    const table = {
      'example.com': { A: ['192.0.2.10'], MX: [{ preference: 10, exchange: 'mail.example.com' }], TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] },
      'mail.example.com': { A: ['192.0.2.10'] },
      'old.example.com': { A: ['198.51.100.44'] },
      '_sip._tcp.example.com': { SRV: [{ priority: 10, weight: 5, port: 5060, target: 'mail.example.com' }] }
    };
    const dns = fakeDns(table);
    const blocks = blocksOf('192.0.2.10');
    const refs = await verifyZoneRefs(zoneCandidates(zoneRecords(), blocks), { dns });
    // The zone's domain was not in the list: its rows group under the zone's origin.
    const only = buildChanges({ blocks, checks: [], zone: { origin: 'example.com', refs } });
    assert.deepEqual(only.groups.map((g) => [g.key, g.kind]), [['example.com', 'zone']]);
    const rows = Object.fromEntries(only.changes.map((c) => [`${c.name} ${c.type}`, [c.severity, c.verified, c.action]]));
    assert.deepEqual(rows['www.example.com A'], ['origin', 'hidden', 'origin']);
    assert.deepEqual(rows['blog.example.com CNAME'], ['origin', 'hidden', 'origin']);
    assert.deepEqual(rows['old.example.com A'], ['file', 'file', 'remove']);
    assert.deepEqual(rows['intranet.example.com A'], ['live', 'internal', 'remove']);
    assert.deepEqual(rows['*.dev.example.com A'], ['file', 'file', 'remove']);
    assert.deepEqual(rows['example.com MX'], ['mail', 'live', 'repoint']);
    assert.deepEqual(rows['_sip._tcp.example.com SRV'], ['live', 'live', 'repoint']);
    assert.deepEqual(rows['example.com HTTPS'], ['file', 'file', 'remove']);
    assert.deepEqual(rows['example.com TXT'], ['mail', 'live', 'narrow']);
    assert.equal(only.changes.find((c) => c.name === 'old.example.com').line, 6);

    // With the domain checked too, the same records are one row each (sources joined).
    const check = await checkDomain('example.com', { dns, blocks, hosts: ['old.example.com', { name: 'mail.example.com', source: 'zone' }] });
    const both = buildChanges({ blocks, checks: [check], zone: { origin: 'example.com', refs } });
    // A name the zone listed ('zone-name') is not the same as a record the file holds ('zone', with its line).
    const mail = both.changes.find((c) => c.name === 'mail.example.com' && c.type === 'A');
    assert.deepEqual([mail.sources, mail.line], [['dns', 'zone-name', 'zone'], 8]);
    assert.deepEqual(both.groups.map((g) => [g.key, g.kind]), [['example.com', 'domain']]);
    const apex = both.changes.filter((c) => c.name === 'example.com' && c.type === 'A');
    assert.equal(apex.length, 1);
    assert.deepEqual(apex[0].sources, ['dns', 'zone']);
    assert.equal(apex[0].line, 3);
    const spf = both.changes.filter((c) => c.type === 'TXT');
    assert.deepEqual(spf.map((c) => [c.value, c.sources.join(' '), c.verified]), [['ip4:192.0.2.0/24', 'spf zone', 'live']]);
  });
});

/* ------------------------------------------------------------------------ */

describe('a whole check', () => {
  test('domains a few at a time with events; the zone last; a bad domain is its own error', async () => {
    const dns = fakeDns({ ...exampleTable(), 'example.org': { A: ['198.51.100.1'] } });
    const blocks = blocksOf('192.0.2.10');
    const events = [];
    const hosts = new Map([['example.com', knownHostsFor('example.com', { scan: ['www.example.com', 'www.example.org'], zone: ['www.example.com', 'old.example.com'] })]]);
    assert.deepEqual(hosts.get('example.com'), [{ name: 'www.example.com', source: 'scan' }, { name: 'old.example.com', source: 'zone' }]);
    const zoneRefs = zoneCandidates([rec('old.example.com', 'A', '192.0.2.10')], blocks);
    const r = await runRetireCheck({
      blocks, domains: ['example.com', 'example.org', 'bad domain'], hosts, zoneRefs, dns, concurrency: 2,
      onEvent: (e) => events.push(e.type === 'progress' ? 'progress' : `${e.type}:${e.domain || ''}`)
    });
    assert.equal(r.aborted, false);
    assert.deepEqual(r.checks.map((c) => c.domain), ['example.com', 'example.org']);
    assert.deepEqual(r.errors.map((e) => e.domain), ['bad domain']);
    assert.deepEqual(r.zone.map((z) => z.live), [false]);
    assert.ok(events.includes('start:example.com') && events.includes('domain:example.org') && events[events.length - 1] === 'zone:');
    assert.ok(events.includes('progress'));
    const www = r.checks[0].names.find((n) => n.name === 'www.example.com');
    assert.deepEqual(www.sources, ['scan']);
  });

  test('an abort keeps what finished', async () => {
    const dns = fakeDns({ ...exampleTable(), 'example.org': { A: ['198.51.100.1'] } }, { delayMs: 30 });
    const controller = new AbortController();
    const blocks = blocksOf('192.0.2.10');
    const r = await runRetireCheck({
      blocks, domains: ['example.org', 'example.com'], dns, signal: controller.signal, concurrency: 1,
      onEvent: (e) => { if (e.type === 'domain' && e.domain === 'example.org') controller.abort(); }
    });
    assert.equal(r.aborted, true);
    assert.deepEqual(r.checks.map((c) => c.domain), ['example.org']);
  });
});

describe('owners, passive hits and exports', () => {
  test('the servers that own an address, with their other addresses', () => {
    const blocks = blocksOf('192.0.2.0/28');
    const owners = inventoryOwners(blocks, [
      { id: 'web01', name: 'web01', ips: ['192.0.2.5', '198.51.100.5'] },
      { id: 'db01', name: 'db01', ips: ['198.51.100.6'] },
      { id: '192.0.2.9', name: '192.0.2.9', ips: ['192.0.2.9', '192.0.2.9'] }
    ]);
    assert.deepEqual(owners, [
      { name: 'web01', addresses: ['192.0.2.5'], others: ['198.51.100.5'] },
      { name: '192.0.2.9', addresses: ['192.0.2.9'], others: [] }
    ]);
    assert.deepEqual(inventoryOwners(blocks, null), []);
  });

  test('passive names: unverified until checked, then joined to the live row or listed as gone', async () => {
    const dns = fakeDns({
      ...exampleTable(),
      'shop.example.org': { A: ['198.51.100.77'] }
    });
    const blocks = blocksOf('192.0.2.10');
    const passive = [{ address: '192.0.2.10', names: ['mail.example.com', 'shop.example.org', 'forum.example.net', 'cdn.example.com'] }];
    const fresh = passiveNewNames(passive, { checked: ['example.com'], resolved: [] });
    assert.deepEqual(fresh, { names: ['cdn.example.com', 'mail.example.com', 'forum.example.net', 'shop.example.org'], domains: ['example.net', 'example.org'] });

    const before = buildChanges({ blocks, checks: [], passive });
    assert.deepEqual(before.groups.map((g) => g.key), ['passive']);
    assert.ok(before.changes.every((c) => c.verified === 'unverified' && c.severity === 'stale' && c.action === 'check'));

    const com = await checkDomain('example.com', { dns, blocks, hosts: [{ name: 'cdn.example.com', source: 'passive' }] });
    const org = await checkDomain('example.org', { dns, blocks, hosts: [{ name: 'shop.example.org', source: 'passive' }] });
    const after = buildChanges({ blocks, checks: [com, org], passive });
    const mail = after.changes.find((c) => c.name === 'mail.example.com');
    assert.ok(mail.sources.includes('passive') && mail.verified === 'live');
    // shop.example.org points elsewhere now, cdn.example.com is NXDOMAIN: both checked, both gone from the address.
    assert.deepEqual(after.gone, [
      { name: 'cdn.example.com', address: '192.0.2.10', now: [] },
      { name: 'shop.example.org', address: '192.0.2.10', now: ['198.51.100.77'] }
    ]);
    assert.ok(!after.changes.some((c) => c.name === 'cdn.example.com'));
    assert.deepEqual(after.changes.filter((c) => c.group === 'passive').map((c) => c.name), ['forum.example.net']);
    assert.deepEqual(passiveNewNames(passive, { checked: ['example.com', 'example.org'], resolved: com.names.map((n) => n.name).concat(org.names.map((n) => n.name)) }),
      { names: ['forum.example.net'], domains: ['example.net'] });
    assert.equal(after.counts.passive, 1);
  });

  test('a passive name whose lookup failed is never "gone": it stays a passive row that cannot be told', async () => {
    const dns = fakeDns({ ...exampleTable(), 'shop.example.com': { A: ['198.51.100.77'] } }, { rcodes: { 'shop.example.com': 'SERVFAIL' } });
    const blocks = blocksOf('192.0.2.10');
    const passive = [{ address: '192.0.2.10', names: ['shop.example.com'] }];
    const com = await checkDomain('example.com', { dns, blocks, hosts: [{ name: 'shop.example.com', source: 'passive' }] });
    assert.equal(com.names.find((n) => n.name === 'shop.example.com').status, 'SERVFAIL');
    const built = buildChanges({ blocks, checks: [com], passive });
    assert.deepEqual(built.gone, []);
    const row = built.changes.find((c) => c.name === 'shop.example.com');
    assert.deepEqual([row.group, row.groupKind, row.severity, row.action, row.verified, row.reason], ['passive', 'passive', 'stale', 'check', 'unknown', 'lookup-failed']);
    assert.equal(built.counts.passive, 1);
  });

  test('CSV rows (codes, one per record) and the JSON document', async () => {
    const dns = fakeDns(exampleTable());
    const blocks = blocksOf('192.0.2.10');
    const check = await checkDomain('example.com', { dns, blocks, hosts: ['www.example.com'] });
    const built = buildChanges({ blocks, checks: [check] });
    const rows = retireExportRows(built.changes);
    assert.deepEqual(Object.keys(rows[0]), [...RETIRE_CSV_COLUMNS]);
    assert.deepEqual(rows.find((r) => r.type === 'TXT (SPF)' && r.group === 'example.com'), {
      group: 'example.com', severity: 'mail', name: 'example.com', type: 'TXT (SPF)', value: 'ip4:192.0.2.10', address: '192.0.2.10',
      action: 'remove', verified: 'live', via: 'example.com', sources: 'spf', line: ''
    });
    const at = new Date('2026-09-28T10:00:00Z');
    const json = retireExportJson({
      blocks, domains: ['example.com'], changes: built.changes, counts: built.counts, owners: [{ name: 'web01', addresses: ['192.0.2.10'], others: [] }],
      startedAt: at, finishedAt: at, version: '1.0.0'
    });
    assert.equal(json.schema, 'domainscope.ip-retire/1');
    assert.deepEqual(json.addresses, ['192.0.2.10/32']);
    assert.equal(json.startedAt, '2026-09-28T10:00:00.000Z');
    assert.equal(json.changes.length, built.changes.length);
    assert.equal(json.counts.total, built.counts.total);
    assert.doesNotThrow(() => JSON.stringify(json));
  });
});
