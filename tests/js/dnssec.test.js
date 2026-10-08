/**
 * dnssec.test.js — lib/dnssec.js: canonical forms, DS digests, the signature algorithms, NSEC /
 * NSEC3 proofs and the chain walk, against zones signed with node:crypto
 * (tests/fixtures/dnssec/signed-zones.mjs). No network.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  validateChain, canonicalName, compareNames, canonicalRdata, signedData, dsDigest, nsec3Hash, verifySignature,
  keyBits, namesBelowRoot, worstStatus, DNSSEC_STATUSES, DNSSEC_REASONS, SIG_RESULTS, MAX_NSEC3_ITERATIONS
} from '../../assets/js/lib/dnssec.js';
import { ROOT_ANCHORS } from '../../assets/js/lib/dnssec-anchors.js';
import { decodeMessage, encodeMessage, encodeName, computeKeyTag, base64Decode, hexEncode } from '../../assets/js/lib/dnswire.js';
import { buildZones, fakeDns, makeKey } from '../fixtures/dnssec/signed-zones.mjs';

const NOW = Date.UTC(2026, 9, 8, 12);
const world = buildZones({ now: NOW });
const subtle = globalThis.crypto.subtle;
const run = (name, type, opts = {}) => validateChain(name, type, {
  dns: opts.dns || fakeDns(world, opts), now: opts.now ?? NOW, anchors: world.rootAnchor(), ...opts
});

test('canonical names: lowercase wire form, canonical order (RFC 4034 §6.1)', () => {
  assert.deepEqual([...canonicalName('WwW.Example.')], [3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 0]);
  assert.deepEqual([...canonicalName('.')], [0]);
  // The RFC's own example order.
  const sorted = ['example', 'a.example', 'yljkjljk.a.example', 'Z.a.example', 'zABC.a.EXAMPLE', 'z.example', '\\001.z.example', '*.z.example', '\\200.z.example'];
  const shuffled = [...sorted].reverse();
  shuffled.sort(compareNames);
  assert.deepEqual(shuffled, sorted);
  assert.deepEqual(namesBelowRoot('www.example.com'), ['com', 'example.com', 'www.example.com']);
  assert.deepEqual(namesBelowRoot('.'), []);
});

test('canonical RDATA: names rebuilt in lowercase without compression, other types as sent', () => {
  // A message whose MX exchange is compressed against the owner name.
  const wire = encodeMessage({ answers: [{ name: 'example.com', type: 'MX', ttl: 60, data: { preference: 10, exchange: 'mail.example.com' } }] });
  const mx = decodeMessage(wire).answers[0];
  assert.deepEqual([...canonicalRdata(mx)], [0, 10, ...encodeName('mail.example.com')]);
  const a = { type: 'A', data: '192.0.2.1', rdata: Uint8Array.of(192, 0, 2, 1) };
  assert.deepEqual([...canonicalRdata(a)], [192, 0, 2, 1]);
  const soa = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'SOA', ttl: 60, data: { mname: 'NS1.example.com', rname: 'hostmaster.example.com', serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 } }] })).answers[0];
  // NAPTR: the replacement name lowercased, the character strings left as they are.
  const naptrRaw = Uint8Array.from([0, 1, 0, 2, 1, 0x55, 0, 1, 0x41, 3, 0x57, 0x57, 0x57, 7, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0]);
  assert.deepEqual([...canonicalRdata({ type: 'NAPTR', data: {}, rdata: naptrRaw }).subarray(4, 9)], [1, 0x55, 0, 1, 0x41], 'strings kept');
  assert.deepEqual([...canonicalRdata({ type: 'NAPTR', data: {}, rdata: naptrRaw }).subarray(9)], [...encodeName('www.example')], 'name lowercased');
  const c = canonicalRdata(soa);
  assert.equal(c.length, encodeName('ns1.example.com').length + encodeName('hostmaster.example.com').length + 20);
  assert.equal(c[c.length - 1], 5);
});

test('signedData: RRSIG fields, then the RRs in canonical order, duplicates once, original TTL', () => {
  const sig = { data: { typeCovered: 'A', algorithm: 13, labels: 2, originalTtl: 300, expiration: new Date(NOW + 1e6), inception: new Date(NOW - 1e6), keyTag: 1, signerName: 'example.com', signature: '' } };
  const rr = (ip, ttl) => ({ name: 'example.com', type: 'A', class: 1, ttl, data: ip, rdata: Uint8Array.from(ip.split('.').map(Number)) });
  const data = signedData(sig, [rr('192.0.2.9', 10), rr('192.0.2.1', 20), rr('192.0.2.9', 30)]);
  const owner = encodeName('example.com');
  const head = 18 + encodeName('example.com').length;
  const one = owner.length + 10 + 4;
  assert.equal(data.length, head + 2 * one, 'two RRs (the duplicate once)');
  assert.deepEqual([...data.subarray(head + one - 4, head + one)], [192, 0, 2, 1], 'the lower RDATA first');
  assert.deepEqual([...data.subarray(head + owner.length + 4, head + owner.length + 8)], [0, 0, 1, 44], 'original TTL 300');
  // Fewer labels than the owner: the wildcard owner is signed.
  const wild = signedData({ data: { ...sig.data, labels: 2 } }, [{ ...rr('192.0.2.1', 1), name: 'host.example.com' }]);
  assert.deepEqual([...wild.subarray(head, head + 2)], [1, 42], 'the *. label');
  assert.equal(signedData({ data: { ...sig.data, labels: 3 } }, [rr('192.0.2.1', 1)]), null, 'more labels than the owner');
});

test('DS digests: SHA-1, SHA-256 and SHA-384 over owner and DNSKEY RDATA; other types not checked', async () => {
  const key = makeKey(13, true);
  const rdata = new Uint8Array(key.rdata);
  for (const [type, algo] of [[1, 'sha1'], [2, 'sha256'], [4, 'sha384']]) {
    const want = createHash(algo).update(Buffer.concat([Buffer.from(encodeName('example.com')), key.rdata])).digest('hex');
    assert.equal(await dsDigest('Example.COM', rdata, type, subtle), want, `digest type ${type}`);
  }
  assert.equal(await dsDigest('example.com', rdata, 3, subtle), null, 'GOST');
});

test('the embedded IANA root anchors: each public key has the key tag and SHA-256 digest IANA lists', async () => {
  assert.deepEqual(ROOT_ANCHORS.map((a) => a.keyTag), [20326, 38696]);
  for (const a of ROOT_ANCHORS) {
    const rdata = new Uint8Array([a.flags >> 8, a.flags & 0xff, 3, a.algorithm, ...base64Decode(a.publicKey)]);
    assert.equal(computeKeyTag(rdata), a.keyTag, a.id);
    assert.equal(await dsDigest('.', rdata, a.digestType, subtle), a.digest, a.id);
    assert.equal(keyBits(8, base64Decode(a.publicKey)), 2048, a.id);
  }
});

test('signature algorithms: RSA/SHA-256, ECDSA P-256 and Ed25519 verify; a flipped bit does not', async () => {
  for (const alg of [8, 13, 15]) {
    const key = makeKey(alg, false);
    const data = new TextEncoder().encode(`signed by algorithm ${alg}`);
    const sig = new Uint8Array(key.sign(Buffer.from(data)));
    const pub = base64Decode(key.publicKey);
    assert.equal(await verifySignature(alg, pub, sig, data, subtle), 'valid', `alg ${alg}`);
    sig[5] ^= 1;
    assert.equal(await verifySignature(alg, pub, sig, data, subtle), 'bad-signature', `alg ${alg} tampered`);
  }
  assert.equal(await verifySignature(12, new Uint8Array(64), new Uint8Array(64), new Uint8Array(1), subtle), 'unsupported-algorithm');
  assert.equal(await verifySignature(3, new Uint8Array(64), new Uint8Array(64), new Uint8Array(1), subtle), 'unsupported-algorithm');
});

test('a runtime without Ed25519: "unsupported algorithm", never "bad signature"', async () => {
  const noEd = {
    digest: (...a) => subtle.digest(...a),
    verify: (...a) => subtle.verify(...a),
    importKey: (format, key, algo, ...rest) => {
      if (algo && algo.name === 'Ed25519') return Promise.reject(Object.assign(new Error('Unrecognized name.'), { name: 'NotSupportedError' }));
      return subtle.importKey(format, key, algo, ...rest);
    }
  };
  const r = await run('www.ed.example', 'A', { subtle: noEd });
  assert.equal(r.status, 'insecure');
  assert.equal(r.reason, 'unsupported-algorithm');
  assert.equal(r.breakAt, 'ed.example');
  assert.equal((await run('www.ed.example', 'A')).status, 'secure', 'with Ed25519 the same zone is secure');
});

test('NSEC3 hash (RFC 5155 Appendix A: example, salt aabbccdd, 12 iterations)', async () => {
  assert.equal(await nsec3Hash('example', 'aabbccdd', 12, subtle), '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom');
  assert.equal(await nsec3Hash('a.example', 'aabbccdd', 12, subtle), '35mthgpgcu1qg68fab165klnsnk3dpvl');
});

test('a secure chain: root → example → the zone → the answer, for RSA, ECDSA, Ed25519 and NSEC3 zones', async () => {
  for (const [name, type, zone] of [['www.rsa.example', 'A', 'rsa.example'], ['www.ecdsa.example', 'AAAA', 'ecdsa.example'],
    ['www.ed.example', 'A', 'ed.example'], ['www.n3.example', 'A', 'n3.example'], ['mail.rsa.example', 'MX', 'rsa.example']]) {
    const r = await run(name, type);
    assert.equal(r.status, 'secure', `${name} ${type}: ${r.reason} at ${r.breakAt}`);
    assert.deepEqual(r.zones.map((z) => z.zone), ['.', 'example', zone]);
    assert.ok(r.zones.every((z) => z.status === 'secure'));
    assert.equal(r.answer.zone, zone);
    assert.ok(r.answer.sigs.some((s) => s.result === 'valid'));
    const z = r.zones[2];
    assert.equal(z.ds.length, 1);
    assert.equal(z.ds[0].matches, z.keys.find((k) => k.role === 'ksk').keyTag, 'the DS names the KSK');
    assert.deepEqual(z.keys.map((k) => k.role).sort(), ['ksk', 'zsk']);
    assert.ok(z.keys.find((k) => k.role === 'ksk').signsKeys);
    assert.ok(z.dsSigs.some((s) => s.result === 'valid' && s.signer === 'example'));
  }
  const root = (await run('www.rsa.example', 'A')).zones[0];
  assert.equal(root.dsSource, 'anchor');
  assert.equal(root.keys.find((k) => k.role === 'ksk').bits, 2048);
});

test('the real root anchors do not trust the fixture root: bogus at the root, anchor mismatch', async () => {
  const r = await validateChain('www.rsa.example', 'A', { dns: fakeDns(world), now: NOW });
  assert.equal(r.status, 'bogus');
  assert.equal(r.reason, 'anchor-mismatch');
  assert.equal(r.breakAt, '.');
  assert.equal(r.answer, null, 'nothing below a broken root is asked');
});

test('expired signatures: bogus at the zone, sig-expired; the injected now moves the window', async () => {
  const r = await run('www.expired.example', 'A');
  assert.equal(r.status, 'bogus');
  assert.equal(r.reason, 'sig-expired');
  assert.equal(r.breakAt, 'expired.example');
  assert.ok(r.zones[2].keySigs.every((s) => s.result === 'expired'));
  assert.equal((await run('www.rsa.example', 'A', { now: NOW + 29 * 86400e3 })).status, 'secure', 'valid for 30 days');
  const late = await run('www.rsa.example', 'A', { now: NOW + 31 * 86400e3 });
  assert.equal(late.reason, 'sig-expired');
  assert.equal(late.breakAt, '.');
  // Every signature of the tree is not yet valid two days before the fixture was made.
  const early = await run('www.rsa.example', 'A', { now: NOW - 2 * 86400e3 });
  assert.equal(early.reason, 'sig-not-yet-valid');
  assert.equal(early.breakAt, '.');
});

test('a DS that matches no DNSKEY after a rollover: bogus, ds-no-match, the stale key tag kept for the fix', async () => {
  const r = await run('www.rollover.example', 'A');
  assert.equal(r.status, 'bogus');
  assert.equal(r.reason, 'ds-no-match');
  const z = r.zones.at(-1);
  assert.equal(z.zone, 'rollover.example');
  assert.equal(z.ds[0].matches, null);
  assert.ok(!z.keys.some((k) => k.keyTag === z.ds[0].keyTag) || z.keys.every((k) => !k.matchesDs));
  assert.ok(z.dsSigs.some((s) => s.result === 'valid'), 'the DS itself is properly signed by the parent');
  // Shown, not trusted: the zone's own KSK signs its key set — the key a new DS must name.
  const ksk = z.keys.find((k) => k.role === 'ksk');
  assert.ok(ksk.signsKeys && !ksk.matchesDs);
  assert.ok(z.keySigs.some((s) => s.result === 'valid' && s.keyTag === ksk.keyTag));
  assert.equal(world.zones.get('rollover.example').ksk.keyTag, ksk.keyTag);
});

test('an unsupported algorithm (GOST) is insecure, never bogus', async () => {
  const r = await run('www.gost.example', 'A');
  assert.equal(r.status, 'insecure');
  assert.equal(r.reason, 'unsupported-algorithm');
  assert.equal(r.zones.at(-1).ds[0].supported, false);
  assert.equal(r.answer.status, 'insecure');
});

test('an unsigned delegation: insecure, proven by the parent’s signed NSEC; without the proof it says so', async () => {
  const r = await run('www.unsigned.example', 'A');
  assert.equal(r.status, 'insecure');
  assert.equal(r.reason, 'no-ds');
  const z = r.zones.at(-1);
  assert.equal(z.denial.kind, 'nsec');
  assert.ok(z.denial.signed && z.denial.delegation && !z.denial.hasDs);
  assert.equal(r.answer.records[0].data, '192.0.2.50', 'the answer is still shown');
  // A resolver that strips the NSEC records: the SOA tells the zone apex, the proof is missing.
  const strip = (name, type, res) => ({ ...res, authorities: res.authorities.filter((rr) => rr.type !== 'NSEC' && !(rr.type === 'RRSIG' && rr.data.typeCovered === 'NSEC')) });
  const dns = fakeDns(world, { edit: strip });
  const bare = await run('www.unsigned.example', 'A', { dns });
  assert.equal(bare.status, 'insecure');
  assert.equal(bare.reason, 'no-ds-unproven');
  assert.ok(dns.asked.includes('unsigned.example|SOA'));
});

test('a record changed after signing: bogus at the answer, sig-invalid', async () => {
  const r = await run('bad.rsa.example', 'A');
  assert.equal(r.status, 'bogus');
  assert.equal(r.reason, 'sig-invalid');
  assert.equal(r.breakAt, 'answer');
  assert.ok(r.zones.every((z) => z.status === 'secure'));
});

test('denial of existence: NSEC no data and no name, NSEC3 no data and no name, all secure', async () => {
  for (const [name, type, rcode, kind] of [['www.rsa.example', 'AAAA', 'NOERROR', 'nsec'], ['nope.rsa.example', 'A', 'NXDOMAIN', 'nsec'],
    ['www.n3.example', 'AAAA', 'NOERROR', 'nsec3'], ['nope.n3.example', 'A', 'NXDOMAIN', 'nsec3']]) {
    const r = await run(name, type);
    assert.equal(r.status, 'secure', `${name} ${type}: ${r.reason}`);
    assert.equal(r.answer.rcode, rcode);
    assert.equal(r.answer.denial.kind, kind);
    assert.ok(r.answer.denial.signed);
    assert.ok(rcode === 'NXDOMAIN' ? r.answer.denial.nxdomain : r.answer.denial.nodata);
  }
  // The proof stripped: a signed zone that says "no" without proof is bogus.
  const strip = (name, type, res) => ({ ...res, authorities: res.authorities.filter((rr) => !['NSEC', 'NSEC3'].includes(rr.type)) });
  const r = await run('www.rsa.example', 'AAAA', { dns: fakeDns(world, { edit: strip }) });
  assert.equal(r.status, 'bogus');
  assert.equal(r.reason, 'denial-missing');
  // The proof's signatures stripped.
  const unsigned = (name, type, res) => ({ ...res, authorities: res.authorities.filter((rr) => !(rr.type === 'RRSIG' && rr.data.typeCovered === 'NSEC')) });
  assert.equal((await run('nope.rsa.example', 'A', { dns: fakeDns(world, { edit: unsigned }) })).reason, 'denial-invalid');
});

test('NSEC3 with too many iterations is not computed: insecure (RFC 9276)', async () => {
  const many = (name, type, res) => ({
    ...res,
    authorities: res.authorities.map((rr) => (rr.type === 'NSEC3' ? { ...rr, data: { ...rr.data, iterations: MAX_NSEC3_ITERATIONS + 1 } } : rr))
  });
  const r = await run('www.n3.example', 'AAAA', { dns: fakeDns(world, { edit: many }) });
  assert.equal(r.status, 'insecure');
  assert.equal(r.reason, 'nsec3-iterations');
});

test('a wildcard answer is secure with the NSEC that shows the name itself does not exist', async () => {
  const r = await run('host.wild.rsa.example', 'A');
  assert.equal(r.status, 'secure', r.reason);
  assert.equal(r.answer.wildcard, true);
  assert.ok(r.answer.denial.signed);
  const strip = (name, type, res) => (type === 'A' ? { ...res, authorities: [] } : res);
  const bare = await run('host.wild.rsa.example', 'A', { dns: fakeDns(world, { edit: strip }) });
  assert.equal(bare.status, 'bogus');
  assert.equal(bare.reason, 'denial-missing');
});

test('a CNAME is checked and followed into the target’s own chain', async () => {
  const r = await run('alias.rsa.example', 'A');
  assert.equal(r.status, 'secure');
  assert.equal(r.answer.records[0].type, 'CNAME');
  assert.equal(r.answer.alias.target, 'www.ecdsa.example');
  assert.equal(r.answer.alias.result.status, 'secure');
  assert.deepEqual(r.answer.alias.result.zones.map((z) => z.zone), ['.', 'example', 'ecdsa.example']);
  // The target's answer bogus: the alias is bogus too.
  const tamper = (name, type, res) => (name === 'www.ecdsa.example' && type === 'A'
    ? { ...res, answers: res.answers.map((rr) => (rr.type === 'A' ? { ...rr, data: '203.0.113.9', rdata: Uint8Array.of(203, 0, 113, 9) } : rr)) }
    : res);
  const bad = await run('alias.rsa.example', 'A', { dns: fakeDns(world, { edit: tamper }) });
  assert.equal(bad.status, 'bogus');
  assert.equal(bad.reason, 'chain-broken');
  assert.equal(bad.answer.alias.result.reason, 'sig-invalid');
});

test('a DS question is answered from the parent’s signatures; DNSKEY and SOA at an apex', async () => {
  const ds = await run('rsa.example', 'DS');
  assert.equal(ds.status, 'secure');
  assert.equal(ds.answer.zone, 'example');
  assert.equal(ds.answer.records.length, 1);
  assert.equal((await run('example', 'DNSKEY')).status, 'secure');
  assert.equal((await run('.', 'SOA')).status, 'secure');
});

test('a question that gets no answer: indeterminate, with the failure for a Retry', async () => {
  const fail = (name, type, res) => (name === 'rsa.example' && type === 'DNSKEY' ? null : res);
  const r = await run('www.rsa.example', 'A', { dns: fakeDns(world, { edit: fail }) });
  assert.equal(r.status, 'indeterminate');
  assert.equal(r.reason, 'query-failed');
  assert.equal(r.breakAt, 'rsa.example');
  assert.equal(r.zones.at(-1).failure.errorKind, 'timeout');
  assert.equal(r.zones.at(-1).failure.qtype, 'DNSKEY');
  const servfail = (name, type, res) => (type === 'DS' && name === 'example' ? { ...res, rcode: 'SERVFAIL', answers: [], authorities: [] } : res);
  const s = await run('www.rsa.example', 'A', { dns: fakeDns(world, { edit: servfail }) });
  assert.equal(s.reason, 'rcode');
  assert.equal(s.zones.at(-1).failure.rcode, 'SERVFAIL');
});

test('every question carries DO and CD; each is asked once; an abort rejects', async () => {
  const seen = [];
  const inner = fakeDns(world);
  const dns = { query: (n, t, o) => { seen.push({ n, t, o }); return inner.query(n, t, o); } };
  const r = await run('alias.rsa.example', 'A', { dns, resolver: 'quad9', timeoutMs: 1234 });
  assert.ok(seen.every((q) => q.o.dnssec === true && q.o.cd === true && q.o.resolver === 'quad9' && q.o.timeoutMs === 1234));
  assert.equal(new Set(seen.map((q) => `${q.n}|${q.t}`)).size, seen.length, 'no question twice');
  assert.equal(r.queries, seen.length);
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(run('www.rsa.example', 'A', { signal: ctl.signal }), { name: 'AbortError' });
});

test('codes are frozen lists; worstStatus orders them', () => {
  for (const list of [DNSSEC_STATUSES, DNSSEC_REASONS, SIG_RESULTS]) assert.ok(Object.isFrozen(list));
  assert.equal(worstStatus('secure', 'insecure'), 'insecure');
  assert.equal(worstStatus('bogus', 'indeterminate'), 'bogus');
  assert.equal(hexEncode(Uint8Array.of(1, 255)), '01ff');
});
