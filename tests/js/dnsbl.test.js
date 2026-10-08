/**
 * dnsbl.test.js — lib/dnsbl.js: targets, query names, the per-list code tables, refusal codes,
 * the RFC 5782 test point that decides whether a "not listed" through a public resolver means
 * anything, concurrency, abort and Retry. A fake DNS client only (no network).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  DNSBL_IP_LISTS, DNSBL_DOMAIN_LISTS, DNSBL_LISTS, DNSBL_MEANINGS, DNSBL_STATUSES, DNSBL_REFUSALS, DNSBL_ERRORS,
  createDnsblChecker, decodeCodes, delistUrl, dnsblCounts, dnsblTarget, mergeResults, readAnswer, testPointName, zoneFor
} from '../../assets/js/lib/dnsbl.js';

const byId = (id) => DNSBL_LISTS.find((l) => l.id === id);
const a = (...data) => data.map((d) => ({ name: 'x', type: 'A', ttl: 60, data: d }));
const ok = (answers, extra = {}) => ({ ok: true, rcode: 'NOERROR', answers, authorities: [], resolver: 'cloudflare', ...extra });
const nx = (extra = {}) => ({ ok: true, rcode: 'NXDOMAIN', answers: [], authorities: [], resolver: 'cloudflare', ...extra });

/**
 * A fake DohClient: `table[name]` is a DnsResponse (or a function of the options); any other
 * name under a test point answers listed, everything else NXDOMAIN. Records every query.
 */
function fakeDns(table = {}, { delayMs = 0 } = {}) {
  const calls = [];
  let active = 0;
  let peak = 0;
  return {
    calls,
    get peak() { return peak; },
    async query(name, type, opts = {}) {
      calls.push({ name, type, resolver: opts.resolver || null, noCache: !!opts.noCache });
      active += 1;
      peak = Math.max(peak, active);
      try {
        if (delayMs) {
          await new Promise((resolve, reject) => {
            const timer = setTimeout(resolve, delayMs);
            opts.signal?.addEventListener('abort', () => { clearTimeout(timer); reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); }, { once: true });
          });
        }
        const hit = table[name];
        if (hit) return typeof hit === 'function' ? hit(opts) : hit;
        if (/^2\.0\.0\.127\.|^2\.0\.0\.0\.0\.0\.f\.7\.f\.f\.f\.f\./.test(name) || /^(?:dbltest\.com|test\.surbl\.org|test\.uribl\.com|test)\./.test(name)) return ok(a('127.0.0.2'));
        return nx();
      } finally {
        active -= 1;
      }
    }
  };
}

describe('targets', () => {
  test('an IP address is reversed; IPv6 by nibbles', () => {
    const v4 = dnsblTarget('8.8.4.4');
    assert.deepEqual([v4.ok, v4.kind, v4.value, v4.version], [true, 'ip', '8.8.4.4', 4]);
    assert.equal(v4.label.split('.').reverse().join('.'), '8.8.4.4', 'octets reversed');
    const v6 = dnsblTarget('2606:4700:4700::1111');
    assert.equal(v6.version, 6);
    assert.equal(v6.label, '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2');
  });

  test('private, reserved and documentation addresses are never targets', () => {
    for (const ip of ['10.0.0.1', '192.168.1.1', '127.0.0.2', '100.64.0.1', 'fd00::1', '::1']) assert.deepEqual(dnsblTarget(ip), { ok: false, reason: 'private' }, ip);
    for (const ip of ['192.0.2.10', '198.51.100.7', '203.0.113.99', '2001:db8::1', '224.0.0.1']) assert.deepEqual(dnsblTarget(ip), { ok: false, reason: 'reserved' }, ip);
  });

  test('a host name checks its registrable domain; internal names and junk are refused', () => {
    assert.deepEqual(dnsblTarget('Mail.Example.COM'), { ok: true, kind: 'domain', value: 'example.com', label: 'example.com' });
    assert.equal(dnsblTarget('www.example-test.com.tr').value, 'example-test.com.tr');
    for (const n of ['printer.local', 'db.internal', 'nas.home.arpa', 'intranet', 'x.corp', 'host.lan', 'a.test', 'b.invalid']) assert.deepEqual(dnsblTarget(n), { ok: false, reason: 'internal' }, n);
    assert.deepEqual(dnsblTarget('not a name!'), { ok: false, reason: 'invalid' });
    assert.deepEqual(dnsblTarget(''), { ok: false, reason: 'invalid' });
  });
});

describe('lists', () => {
  test('ids are unique, zones are names, every delist page is https', () => {
    assert.equal(new Set(DNSBL_LISTS.map((l) => l.id)).size, DNSBL_LISTS.length);
    for (const l of DNSBL_LISTS) {
      assert.match(l.zone, /^[a-z0-9-]+(\.[a-z0-9-]+)+$/, l.id);
      assert.match(l.site, /^https:\/\/[a-z0-9.-]+\//, l.id);
      assert.ok(Object.isFrozen(l) && Object.isFrozen(l.codes), l.id);
    }
    assert.ok(DNSBL_IP_LISTS.every((l) => l.kind === 'ip') && DNSBL_DOMAIN_LISTS.every((l) => l.kind === 'domain' && l.test));
    for (const id of ['spamhaus-zen', 'barracuda', 'spamcop', 'psbl', 'mailspike', 'uceprotect-1', 'uceprotect-2', 'uceprotect-3', 's5h']) assert.ok(byId(id), id);
    for (const id of ['spamhaus-dbl', 'surbl', 'uribl']) assert.ok(byId(id), id);
  });

  test('the zone of an IPv6 address: the same, its own, or none (IPv4 only)', () => {
    const v6 = dnsblTarget('2606:4700:4700::1111');
    assert.equal(zoneFor(byId('spamhaus-zen'), v6), 'zen.spamhaus.org');
    assert.equal(zoneFor(byId('sem'), v6), 'bl.ipv6.spameatingmonkey.net');
    assert.equal(zoneFor(byId('psbl'), v6), null);
    assert.equal(zoneFor(byId('psbl'), dnsblTarget('8.8.8.8')), 'psbl.surriel.com');
  });

  test('test points follow RFC 5782 (and the lists’ documented test domains)', () => {
    assert.equal(testPointName(byId('spamcop'), 'bl.spamcop.net'), '2.0.0.127.bl.spamcop.net');
    assert.equal(testPointName(byId('sem'), 'bl.ipv6.spameatingmonkey.net', 6), '2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.bl.ipv6.spameatingmonkey.net');
    assert.equal(testPointName(byId('spamhaus-dbl'), 'dbl.spamhaus.org'), 'dbltest.com.dbl.spamhaus.org');
    assert.equal(testPointName(byId('uribl'), 'multi.uribl.com'), 'test.uribl.com.multi.uribl.com');
  });

  test('delist pages take the address when the list’s page does', () => {
    assert.equal(delistUrl(byId('psbl'), '8.8.8.8'), 'https://psbl.org/listing?ip=8.8.8.8');
    assert.equal(delistUrl(byId('dronebl'), '2606:4700:4700::1111'), 'https://dronebl.org/lookup?ip=2606%3A4700%3A4700%3A%3A1111');
    assert.equal(delistUrl(byId('barracuda'), '8.8.8.8'), 'https://www.barracudacentral.org/rbl/removal-request');
  });

  test('every meaning a decode can give is enumerated', () => {
    const seen = new Set();
    for (const l of DNSBL_LISTS) {
      for (const code of [...Object.keys(l.codes).filter((k) => k.includes('.')), '127.0.0.2', '127.0.0.254', '127.0.2.5', '127.0.0.99', ...l.clean]) {
        for (const d of decodeCodes(l, [code])) seen.add(d.meaning);
      }
    }
    assert.deepEqual([...seen].filter((m) => !DNSBL_MEANINGS.includes(m)), []);
    assert.ok(Object.isFrozen(DNSBL_STATUSES) && Object.isFrozen(DNSBL_REFUSALS) && Object.isFrozen(DNSBL_ERRORS));
  });
});

describe('return codes', () => {
  test('Spamhaus ZEN: each code its list; the refusal codes are never "listed"', () => {
    const zen = byId('spamhaus-zen');
    assert.deepEqual(readAnswer(zen, ok(a('127.0.0.2', '127.0.0.4', '127.0.0.10'))).codes.map((c) => c.meaning), ['sbl', 'xbl', 'pbl']);
    for (const [code, reason] of [['127.255.255.254', 'public-resolver'], ['127.255.255.255', 'rate-limited'], ['127.255.255.252', 'bad-query']]) {
      const r = readAnswer(zen, ok(a(code)));
      assert.equal(r.status, 'refused', code);
      assert.equal(r.reason, reason, code);
    }
    // A refusal next to a listing code is still a refusal (the answer cannot be trusted).
    assert.equal(readAnswer(zen, ok(a('127.0.0.2', '127.255.255.254'))).status, 'refused');
  });

  test('Spamhaus DBL and ZRD: domain codes, "IP queries prohibited", the age of a new domain', () => {
    const dbl = byId('spamhaus-dbl');
    assert.deepEqual(readAnswer(dbl, ok(a('127.0.1.4'))).codes, [{ code: '127.0.1.4', meaning: 'dbl-phish' }]);
    assert.equal(readAnswer(dbl, ok(a('127.0.1.255'))).reason, 'bad-query');
    assert.deepEqual(readAnswer(byId('spamhaus-zrd'), ok(a('127.0.2.5'))).codes, [{ code: '127.0.2.5', meaning: 'young', hours: 5 }]);
  });

  test('SURBL and URIBL: bitmask codes; 127.0.0.1 is their "query refused"', () => {
    assert.deepEqual(readAnswer(byId('surbl'), ok(a('127.0.0.24'))).codes.map((c) => c.meaning), ['phishing', 'malware']);
    assert.deepEqual(readAnswer(byId('uribl'), ok(a('127.0.0.14'))).codes.map((c) => c.meaning), ['uribl-black', 'uribl-grey', 'uribl-red']);
    for (const id of ['surbl', 'uribl']) assert.deepEqual([readAnswer(byId(id), ok(a('127.0.0.1'))).status, readAnswer(byId(id), ok(a('127.0.0.1'))).reason], ['refused', 'query-refused'], id);
    // DroneBL's 127.0.0.1 is a listing class (its test class), not a refusal.
    assert.deepEqual([readAnswer(byId('dronebl'), ok(a('127.0.0.1'))).status, readAnswer(byId('dronebl'), ok(a('127.0.0.9'))).codes[0].meaning], ['listed', 'proxy']);
  });

  test('Mailspike: reputation codes are not a listing; UCEPROTECT levels say what is listed', () => {
    assert.equal(readAnswer(byId('mailspike'), ok(a('127.0.0.18'))).status, 'not-listed');
    assert.deepEqual(readAnswer(byId('mailspike'), ok(a('127.0.0.11'))).codes.map((c) => c.meaning), ['rep-very-bad']);
    assert.equal(readAnswer(byId('uceprotect-3'), ok(a('127.0.0.2'))).codes[0].meaning, 'uce-3');
    assert.equal(readAnswer(byId('psbl'), ok(a('127.0.0.77'))).codes[0].meaning, 'listed', 'an undocumented code still reads listed');
  });

  test('NXDOMAIN and NODATA: not listed; SERVFAIL, REFUSED, odd answers and transport failures are statuses', () => {
    const l = byId('spamcop');
    assert.equal(readAnswer(l, nx()).status, 'not-listed');
    assert.equal(readAnswer(l, ok([])).status, 'not-listed');
    assert.deepEqual([readAnswer(l, { ok: true, rcode: 'SERVFAIL', answers: [] }).status, readAnswer(l, { ok: true, rcode: 'SERVFAIL', answers: [] }).reason], ['error', 'servfail']);
    assert.deepEqual([readAnswer(l, { ok: true, rcode: 'REFUSED', answers: [] }).status, readAnswer(l, { ok: true, rcode: 'REFUSED', answers: [] }).reason], ['refused', 'rcode']);
    assert.equal(readAnswer(l, { ok: true, rcode: 'NOTIMP', answers: [] }).reason, 'rcode');
    // A resolver that rewrites NXDOMAIN to an ad server: never "listed".
    assert.deepEqual([readAnswer(l, ok(a('192.0.2.53'))).status, readAnswer(l, ok(a('192.0.2.53'))).reason], ['error', 'bad-answer']);
    const t = readAnswer(l, { ok: false, rcode: null, answers: [], error: 'timed out after 6000 ms', errorKind: 'timeout' });
    assert.deepEqual([t.status, t.reason, t.error], ['error', 'timeout', 'timed out after 6000 ms']);
  });
});

describe('checks', () => {
  test('a clean address: every list asked through the resolver that answered its test point', async () => {
    const dns = fakeDns({ '2.0.0.127.zen.spamhaus.org': ok(a('127.255.255.254')) });
    const checker = createDnsblChecker({ dns, now: () => 1000 });
    const seen = [];
    const out = await checker.check(dnsblTarget('8.8.4.4'), { onResult: (r) => seen.push(r.list) });
    assert.equal(out.target, '8.8.4.4');
    assert.equal(out.at, 1000);
    assert.deepEqual(out.results.map((r) => r.list), DNSBL_IP_LISTS.map((l) => l.id), 'results in list order');
    assert.equal(seen.length, DNSBL_IP_LISTS.length, 'onResult per list');
    const zen = out.results.find((r) => r.list === 'spamhaus-zen');
    assert.deepEqual([zen.status, zen.reason, zen.testPoint], ['refused', 'public-resolver', true]);
    assert.ok(!dns.calls.some((c) => c.name === '4.4.8.8.zen.spamhaus.org'), 'a list that refused its test point never gets the address');
    const spamcop = out.results.find((r) => r.list === 'spamcop');
    assert.deepEqual([spamcop.status, spamcop.query, spamcop.resolver], ['not-listed', '4.4.8.8.bl.spamcop.net', 'cloudflare']);
    assert.equal(dns.calls.find((c) => c.name === '4.4.8.8.bl.spamcop.net').resolver, 'cloudflare', 'the address asked through the same resolver');
    assert.deepEqual(dnsblCounts(out.results), { total: 15, listed: 0, 'not-listed': 14, refused: 1, error: 0, skipped: 0 });
  });

  test('a test point that comes back NXDOMAIN (Spamhaus through Google): refused, never "not listed"', async () => {
    const dns = fakeDns({ '2.0.0.127.zen.spamhaus.org': nx({ resolver: 'google' }) });
    const out = await createDnsblChecker({ dns }).check(dnsblTarget('8.8.4.4'), { lists: ['spamhaus-zen'] });
    assert.deepEqual(out.results.map((r) => [r.status, r.reason, r.testPoint]), [['refused', 'test-point', true]]);
    assert.equal(dns.calls.length, 1, 'only the test point was asked');
  });

  test('listed: the decoded codes and the delist page', async () => {
    const dns = fakeDns({ '4.4.8.8.bl.spamcop.net': ok(a('127.0.0.2')), '4.4.8.8.dnsbl-2.uceprotect.net': ok(a('127.0.0.2')) });
    const out = await createDnsblChecker({ dns }).check(dnsblTarget('8.8.4.4'), { lists: ['spamcop', 'uceprotect-2', 'psbl'] });
    assert.deepEqual(out.results.map((r) => [r.list, r.status]), [['spamcop', 'listed'], ['psbl', 'not-listed'], ['uceprotect-2', 'listed']]);
    assert.equal(out.results[2].codes[0].meaning, 'uce-2');
    assert.equal(out.results[0].delist, 'https://www.spamcop.net/bl.shtml?8.8.4.4');
  });

  test('IPv6: IPv4-only lists are skipped and asked nothing; its own zone for SpamEatingMonkey', async () => {
    const dns = fakeDns();
    const out = await createDnsblChecker({ dns }).check(dnsblTarget('2606:4700:4700::1111'));
    const psbl = out.results.find((r) => r.list === 'psbl');
    assert.deepEqual([psbl.status, psbl.reason], ['skipped', 'ipv4-only']);
    assert.ok(!dns.calls.some((c) => c.name.endsWith('psbl.surriel.com')));
    assert.ok(dns.calls.some((c) => c.name.endsWith('.bl.ipv6.spameatingmonkey.net') && c.name.startsWith('1.1.1.1.0')));
    assert.ok(dns.calls.some((c) => c.name.startsWith('2.0.0.0.0.0.f.7.f.f.f.f.') && c.name.endsWith('.bl.spamcop.net')), 'the IPv6 test point');
  });

  test('a domain: URIBL refuses (127.0.0.1), SURBL answers, DBL is refused', async () => {
    const dns = fakeDns({
      'test.uribl.com.multi.uribl.com': ok(a('127.0.0.1')),
      'dbltest.com.dbl.spamhaus.org': ok(a('127.255.255.254')),
      'dbltest.com.zrd.spamhaus.org': ok(a('127.255.255.252')),
      'example.com.multi.surbl.org': ok(a('127.0.0.8'))
    });
    const out = await createDnsblChecker({ dns }).check(dnsblTarget('www.example.com'));
    assert.deepEqual(out.results.map((r) => [r.list, r.status, r.reason]), [
      ['spamhaus-dbl', 'refused', 'public-resolver'], ['spamhaus-zrd', 'refused', 'bad-query'], ['surbl', 'listed', null],
      ['uribl', 'refused', 'query-refused'], ['nordspam-dbl', 'not-listed', null]
    ]);
    assert.equal(out.results[2].codes[0].meaning, 'phishing');
    assert.ok(!dns.calls.some((c) => c.name === 'example.com.multi.uribl.com'), 'the domain never went to a list that refused');
  });

  test('a failed test point is an error, not kept: the next check asks it again', async () => {
    let fail = true;
    const dns = fakeDns({ '2.0.0.127.psbl.surriel.com': () => (fail ? { ok: true, rcode: 'SERVFAIL', answers: [], resolver: 'cloudflare' } : ok(a('127.0.0.2'))) });
    const checker = createDnsblChecker({ dns });
    const first = await checker.check(dnsblTarget('8.8.4.4'), { lists: ['psbl'] });
    assert.deepEqual(first.results.map((r) => [r.status, r.reason]), [['error', 'servfail']]);
    fail = false;
    const second = await checker.check(dnsblTarget('8.8.4.4'), { lists: ['psbl'], noCache: true });
    assert.equal(second.results[0].status, 'not-listed');
    assert.deepEqual(mergeResults(first.results, second.results).map((r) => r.status), ['not-listed']);
  });

  test('a good test point is kept for ten minutes (then asked again)', async () => {
    let clock = 0;
    const dns = fakeDns();
    const checker = createDnsblChecker({ dns, now: () => clock });
    await checker.check(dnsblTarget('8.8.4.4'), { lists: ['spamcop'] });
    await checker.check(dnsblTarget('8.8.8.8'), { lists: ['spamcop'] });
    assert.equal(dns.calls.filter((c) => c.name.startsWith('2.0.0.127.')).length, 1);
    clock = 11 * 60 * 1000;
    await checker.check(dnsblTarget('8.8.8.8'), { lists: ['spamcop'] });
    assert.equal(dns.calls.filter((c) => c.name.startsWith('2.0.0.127.')).length, 2);
  });

  test('at most `concurrency` lists at once; an abort rejects and stops the queue', async () => {
    const dns = fakeDns({}, { delayMs: 5 });
    await createDnsblChecker({ dns, concurrency: 3 }).check(dnsblTarget('8.8.4.4'));
    assert.ok(dns.peak <= 3, `peak ${dns.peak}`);
    const slow = fakeDns({}, { delayMs: 50 });
    const ctl = new AbortController();
    const run = createDnsblChecker({ dns: slow, concurrency: 2 }).check(dnsblTarget('8.8.4.4'), { signal: ctl.signal });
    setTimeout(() => ctl.abort(), 10);
    await assert.rejects(run, (err) => err.name === 'AbortError');
    const asked = slow.calls.length;
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(slow.calls.length, asked, 'nothing more was asked after the abort');
    assert.ok(asked <= 2, `asked ${asked}`);
  });

  test('a refused target is never checked', async () => {
    const dns = fakeDns();
    await assert.rejects(createDnsblChecker({ dns }).check(dnsblTarget('10.0.0.1')), TypeError);
    assert.equal(dns.calls.length, 0);
  });
});
