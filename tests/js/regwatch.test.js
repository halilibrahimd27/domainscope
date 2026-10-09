/**
 * lib/regwatch.js — the registration watch: the snapshot of a Domain portfolio row, every change
 * code and its tone (a registrar change, a lock removed or added, a hold arriving, other statuses,
 * the registry's name servers, the DS records, the expiry, the registry losing the domain), and the
 * browser's baseline (workspace part `rdapSeen`): read, update, text under its size, the changes
 * since an entry. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  registrationSnapshot, diffRegistration, worstTone, registrarKey, dsKey, emptyRdapSeen, readRdapSeen, updateRdapSeen, rdapSeenText, seenChanges,
  REG_CHANGE_CODES, REG_CHANGE_TONES, TRANSFER_LOCK_STATUSES, HOLD_STATUSES, RDAP_SEEN_VERSION, RDAP_SEEN_MAX_CHARS
} from '../../assets/js/lib/regwatch.js';
import { portfolioFacts } from '../../assets/js/lib/portfolio.js';
import { WORKSPACE_LIMITS } from '../../assets/js/lib/workspace.js';

const NOW = new Date('2026-10-09T03:00:00Z');

/** A snapshot as registrationSnapshot gives it. */
const snap = (extra = {}) => ({
  state: 'ok', registrar: 'Example Registrar, Inc.', ianaId: '9999', statuses: ['client delete prohibited', 'client transfer prohibited'],
  expires: '2027-11-13', nameservers: ['ns1.example.net', 'ns2.example.net'], ds: ['12345 13 2'], ...extra
});
const codes = (list) => list.map((c) => `${c.code}${c.item ? `:${c.item}` : ''}:${c.tone}`);

describe('the snapshot of a portfolio row', () => {
  /** A row's raw lookups, as lib/portfolio.js keeps them. */
  const raw = ({ rdap = {}, ds = [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }] } = {}) => ({
    domain: 'example.com',
    rdap: {
      ok: true, domain: 'example.com', registrar: 'Example Registrar, Inc.', registrarIanaId: '9999', expires: new Date('2027-11-13T10:00:00Z'),
      status: ['clientTransferProhibited', 'client delete prohibited'], nameservers: ['NS2.example.net', 'ns1.example.net'], dnssecSigned: true,
      unsupportedTld: false, notFound: false, error: null, errorKind: null, ...rdap
    },
    ds: { ok: true, rcode: 'NOERROR', answers: ds.map((data) => ({ name: 'example.com', type: 'DS', ttl: 300, data })), flags: {} }
  });

  test('the registrar and its IANA ID, statuses in RDAP spelling, the expiry day, the registry\'s name servers, the DS identities', () => {
    const facts = portfolioFacts(raw(), { now: NOW });
    assert.deepEqual(facts.registration.nameservers, ['ns1.example.net', 'ns2.example.net'], 'the facts carry the RDAP name servers, sorted');
    assert.deepEqual(facts.dnssec.ds, [{ keyTag: 12345, algorithm: 13, digestType: 2 }], 'and the DS identities');
    assert.deepEqual(registrationSnapshot(facts), {
      state: 'ok', registrar: 'Example Registrar, Inc.', ianaId: '9999', statuses: ['client delete prohibited', 'client transfer prohibited'],
      expires: '2027-11-13', nameservers: ['ns1.example.net', 'ns2.example.net'], ds: ['12345 13 2']
    });
  });

  test('what is not known is null: a registry without RDAP, a failed lookup, a DS answer that failed; not registered is a state', () => {
    const unsupported = registrationSnapshot(portfolioFacts(raw({ rdap: { ok: false, unsupportedTld: true, error: 'no RDAP', errorKind: 'unsupported' } }), { now: NOW }));
    assert.equal(unsupported.state, null);
    assert.equal(unsupported.registrar, null);
    assert.deepEqual(unsupported.ds, ['12345 13 2'], 'the DS records come from DNS');
    const notFound = registrationSnapshot(portfolioFacts(raw({ rdap: { ok: false, notFound: true, error: 'Domain not found', errorKind: 'http' } }), { now: NOW }));
    assert.equal(notFound.state, 'not-found');
    const unsigned = registrationSnapshot(portfolioFacts(raw({ ds: [] }), { now: NOW }));
    assert.deepEqual(unsigned.ds, [], 'no DS: an empty list, known');
    const failedDs = portfolioFacts({ ...raw(), ds: { ok: false, rcode: null, answers: [], error: 'timeout', errorKind: 'timeout' } }, { now: NOW });
    assert.equal(registrationSnapshot(failedDs).ds, null, 'a DS lookup that failed: not known');
    assert.equal(dsKey({ keyTag: 1, algorithm: 8, digestType: 2 }), '1 8 2');
  });
});

describe('the changes', () => {
  test('nothing moved: no change', () => {
    assert.deepEqual(diffRegistration(snap(), snap()), []);
    assert.deepEqual(diffRegistration(null, snap()), []);
  });

  test('another registrar: by its IANA ID; a name alone only without one; the same ID under another name is info', () => {
    assert.deepEqual(codes(diffRegistration(snap(), snap({ registrar: 'Other Registrar LLC', ianaId: '1068' }))), ['registrar:bad']);
    assert.deepEqual(codes(diffRegistration(snap(), snap({ registrar: 'EXAMPLE REGISTRAR INC' }))), [], 'case, punctuation and spacing aside');
    assert.deepEqual(codes(diffRegistration(snap(), snap({ registrar: 'Example Holdings Ltd' }))), ['registrar-name:info'], 'the same IANA ID');
    assert.deepEqual(codes(diffRegistration(snap({ ianaId: null }), snap({ ianaId: null, registrar: 'Other Registrar LLC' }))), ['registrar:bad'], 'no ID: the name says it');
    assert.equal(registrarKey('Example, Inc.'), 'example inc');
  });

  test('a transfer lock removed is bad, added good; every transfer prohibition counts', () => {
    assert.deepEqual(codes(diffRegistration(snap(), snap({ statuses: ['client delete prohibited'] }))), ['lock-removed:client transfer prohibited:bad']);
    assert.deepEqual(codes(diffRegistration(snap(), snap({ statuses: ['client delete prohibited', 'client transfer prohibited', 'server transfer prohibited'] }))),
      ['lock-added:server transfer prohibited:good']);
    assert.deepEqual(codes(diffRegistration(snap({ statuses: ['transfer prohibited'] }), snap({ statuses: ['active'] }))),
      ['lock-removed:transfer prohibited:bad', 'status:active:info'], 'RFC 9083\'s plain prohibition: said once, as a lock');
    assert.deepEqual(TRANSFER_LOCK_STATUSES, ['client transfer prohibited', 'server transfer prohibited', 'transfer prohibited']);
  });

  test('a hold, a pending delete, a redemption period or a pending transfer arriving is bad; any other status is info, either way', () => {
    for (const s of HOLD_STATUSES) {
      assert.deepEqual(codes(diffRegistration(snap(), snap({ statuses: [...snap().statuses, s] }))), [`hold:${s}:bad`], s);
    }
    const lifted = diffRegistration(snap({ statuses: [...snap().statuses, 'client hold'] }), snap());
    assert.deepEqual(codes(lifted), ['status:client hold:info'], 'a hold lifted');
    assert.equal(lifted[0].how, 'removed');
    const update = diffRegistration(snap(), snap({ statuses: [...snap().statuses, 'client update prohibited'] }));
    assert.deepEqual(codes(update), ['status:client update prohibited:info']);
    assert.equal(update[0].how, 'added');
  });

  test('the registry\'s name servers changed: bad', () => {
    const c = diffRegistration(snap(), snap({ nameservers: ['ns1.example.org', 'ns2.example.org'] }));
    assert.deepEqual(codes(c), ['ns:bad']);
    assert.deepEqual([c[0].before, c[0].after], [['ns1.example.net', 'ns2.example.net'], ['ns1.example.org', 'ns2.example.org']]);
    assert.deepEqual(diffRegistration(snap({ nameservers: [] }), snap({ nameservers: [] })), [], 'a registry that lists none says nothing');
  });

  test('DS: every one removed or one replaced is bad; one added is info; DS from DNS compare when the registry could not be read', () => {
    assert.deepEqual(codes(diffRegistration(snap(), snap({ ds: [] }))), ['ds-removed:bad']);
    assert.deepEqual(codes(diffRegistration(snap(), snap({ ds: ['23456 13 2'] }))), ['ds-changed:bad']);
    assert.deepEqual(codes(diffRegistration(snap(), snap({ ds: ['12345 13 2', '23456 13 2'] }))), ['ds-added:info'], 'a rollover publishes the new one first');
    assert.deepEqual(codes(diffRegistration(snap({ ds: ['12345 13 2', '23456 13 2'] }), snap({ ds: ['23456 13 2'] }))), ['ds-changed:bad'], 'the old one withdrawn');
    assert.deepEqual(codes(diffRegistration(snap(), { ...snap({ ds: [] }), state: null, registrar: null, ianaId: null, statuses: null, expires: null, nameservers: null })),
      ['ds-removed:bad'], 'RDAP down, DNS read');
    assert.deepEqual(diffRegistration(snap(), snap({ ds: null })), [], 'not known: not compared');
  });

  test('the expiry: later is good (renewed), earlier info', () => {
    const later = diffRegistration(snap(), snap({ expires: '2028-11-13' }));
    assert.deepEqual(codes(later), ['expiry-later:good']);
    assert.deepEqual([later[0].before, later[0].after], ['2027-11-13', '2028-11-13']);
    assert.deepEqual(codes(diffRegistration(snap(), snap({ expires: '2027-01-01' }))), ['expiry-earlier:info']);
  });

  test('the registry no longer holds the domain (bad), or holds it again (info): nothing else of the registration compared then', () => {
    assert.deepEqual(codes(diffRegistration(snap(), { ...snap(), state: 'not-found', registrar: null, ianaId: null, statuses: null, expires: null, nameservers: null })),
      ['unregistered:bad']);
    assert.deepEqual(codes(diffRegistration({ ...snap(), state: 'not-found' }, snap({ registrar: 'Other Registrar LLC', ianaId: '1068' }))), ['registered:info']);
    assert.deepEqual(diffRegistration({ ...snap(), state: null }, snap({ ianaId: '1068' })), [], 'not known before: nothing compared');
  });

  test('several at once come in the code order; the worst tone; every code has its tone', () => {
    const c = diffRegistration(snap(), snap({ registrar: 'Other Registrar LLC', ianaId: '1068', statuses: ['client hold'], expires: '2028-01-01', ds: [] }));
    assert.deepEqual(codes(c), ['registrar:bad', 'lock-removed:client transfer prohibited:bad', 'hold:client hold:bad', 'status:client delete prohibited:info', 'ds-removed:bad', 'expiry-later:good']);
    assert.equal(worstTone(c), 'bad');
    assert.equal(worstTone(diffRegistration(snap(), snap({ expires: '2028-01-01' }))), 'good');
    assert.equal(worstTone([]), null);
    for (const code of REG_CHANGE_CODES) assert.ok(['bad', 'good', 'info'].includes(REG_CHANGE_TONES[code]), code);
  });
});

describe('the baseline (workspace part rdapSeen)', () => {
  test('a check updates the domains its registry answered; one it could not read keeps its entry; DS not read keeps the last ones', () => {
    const first = updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: snap() }, { domain: 'example.org', snapshot: { ...snap(), state: null } }], { now: NOW });
    assert.deepEqual(Object.keys(first.domains), ['example.com'], 'an unreadable registry writes nothing');
    assert.equal(first.domains['example.com'].at, NOW.toISOString());
    const later = new Date(NOW.getTime() + 86400000);
    const second = updateRdapSeen(first, [{ domain: 'example.com', snapshot: snap({ registrar: 'Other Registrar LLC', ds: null }) }, { domain: 'example.net', snapshot: { ...snap(), state: 'not-found' } }],
      { now: later });
    assert.equal(second.domains['example.com'].registrar, 'Other Registrar LLC');
    assert.deepEqual(second.domains['example.com'].ds, ['12345 13 2'], 'the DS of the last check that read them');
    assert.equal(second.domains['example.net'].state, 'not-found');
    assert.equal(second.domains['example.net'].registrar, null);
    assert.equal(first.domains['example.com'].registrar, 'Example Registrar, Inc.', 'a new object: the old one is untouched');
  });

  test('read back from its text; anything else is dropped entry by entry', () => {
    const seen = updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: snap() }], { now: NOW });
    const text = rdapSeenText(seen);
    assert.deepEqual(readRdapSeen(text), seen);
    assert.deepEqual(JSON.parse(text).v, RDAP_SEEN_VERSION);
    for (const junk of [null, '', 'not json', '[]', '{"v":2,"domains":{}}', '{"v":1,"domains":[]}']) assert.deepEqual(readRdapSeen(junk), emptyRdapSeen(), String(junk));
    const hostile = JSON.stringify({
      v: 1,
      domains: {
        'Example.COM': { at: NOW.toISOString(), state: 'ok' },
        'example.org': { at: 'yesterday', state: 'ok' },
        'example.net': { at: NOW.toISOString(), state: 'gone' },
        'ok.example.com': {
          at: NOW.toISOString(), state: 'ok', registrar: 'x'.repeat(500), ianaId: '12a', statuses: ['Client Hold', 'client hold', 7], expires: '13/11/2027',
          nameservers: ['ns1.example.net', 'not a host', 'NS2.example.net'], ds: ['12345 13 2', '1 2', 'abc']
        }
      }
    });
    const read = readRdapSeen(hostile);
    assert.deepEqual(Object.keys(read.domains), ['ok.example.com'], 'a name not canonical, a bad time, an unknown state dropped');
    const e = read.domains['ok.example.com'];
    assert.equal(e.registrar.length, 200, 'a long registrar cut');
    assert.equal(e.ianaId, null, 'an IANA ID is digits');
    assert.deepEqual(e.statuses, ['client hold'], 'statuses in their compared spelling only');
    assert.equal(e.expires, null, 'a day is YYYY-MM-DD');
    assert.deepEqual(e.nameservers, ['ns1.example.net'], 'host names in canonical form only');
    assert.deepEqual(e.ds, ['12345 13 2']);
  });

  test('its text stays under its size (and the workspace\'s): the domains read longest ago go first', () => {
    assert.equal(RDAP_SEEN_MAX_CHARS, WORKSPACE_LIMITS.rdapSeen);
    let seen = emptyRdapSeen();
    for (let i = 0; i < 40; i += 1) seen = updateRdapSeen(seen, [{ domain: `d${i}.example.com`, snapshot: snap() }], { now: NOW.getTime() + i * 1000 });
    const text = rdapSeenText(seen, { maxChars: 2000 });
    assert.ok(text.length <= 2000, String(text.length));
    const kept = Object.keys(readRdapSeen(text).domains);
    assert.ok(kept.length > 0 && kept.length < 40);
    assert.ok(kept.includes('d39.example.com') && !kept.includes('d0.example.com'), 'the newest kept');
    assert.equal(rdapSeenText(emptyRdapSeen()), '', 'an empty baseline is no text (the workspace stores nothing)');
    assert.equal(rdapSeenText(seen, { maxChars: 10 }), '', 'nothing fits: empty');
  });

  test('the changes since an entry, with the time of the check that read it; none for a domain checked for the first time', () => {
    const seen = updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: snap() }], { now: NOW });
    const got = seenChanges(seen.domains['example.com'], snap({ statuses: ['client delete prohibited'], registrar: 'Other Registrar LLC', ianaId: '1068' }));
    assert.equal(got.at, NOW.toISOString());
    assert.deepEqual(codes(got.changes), ['registrar:bad', 'lock-removed:client transfer prohibited:bad']);
    assert.equal(seenChanges(undefined, snap()), null);
    assert.deepEqual(seenChanges(seen.domains['example.com'], snap()).changes, []);
  });
});
