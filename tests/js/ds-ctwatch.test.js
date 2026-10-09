/**
 * The headless runner's CT watch (tools/ds/ctwatch.mjs, ROADMAP P0.7 runner side): `ct` raising
 * what the Domain portfolio's Certificates (CT) tab shows — the expiry radar, new since the last
 * run from a store of the ids seen kept in the report, unexpected CA, wildcard, precertificate
 * only, revoked — and the changes it counts (CA, EXPIRING, REVOKED). No network: crt.sh and Cert
 * Spotter are answered in the test (tests/js/ct-fake.mjs rows, with DER).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCommandLine, radarOption, expectedCaOption, DS_TOOL, DS_VERSION, EXIT, USAGE } from '../../tools/ds/args.mjs';
import { baselineProblem, baselineNotes, diffReports } from '../../tools/ds/diff.mjs';
import { setupStrings, changeText, CHANGE_TAGS } from '../../tools/ds/render.mjs';
import { ctCertId, ctTarget, ctDoc, ctWatchLines, readCertDer } from '../../tools/ds/commands.mjs';
import { seenOf, watchTarget, daysLeftAt, overdueDays, radarCrossing, renewalOverdue, OVERDUE_SHARE } from '../../tools/ds/ctwatch.mjs';
import { carryCt } from '../../tools/ds/carry.mjs';
import { main } from '../../tools/ds.mjs';
import { renderPlainText, renderMarkdown } from '../../assets/js/lib/summary.js';
import { parseCertificate } from '../../assets/js/lib/x509.js';
import { issuerName, dnPart } from '../../assets/js/lib/passport.js';
import { spotterRow, certDer, crtshRow } from './ct-fake.mjs';

const t = await setupStrings();
const DAY = 86400000;
const LE = "C=US, O=Let's Encrypt, CN=R11";
const GTS = 'C=US, O=Google Trust Services, CN=WR1';
const NOW = new Date('2026-10-08T03:00:00Z');

/** A ct certificate as ctTarget writes it (crt.sh unless `sources` says otherwise). */
const cert = (issuer, notBefore, notAfter, names, extra = {}) => {
  const c = {
    ca: issuerName(issuer), intermediate: dnPart(issuer, 'CN'), issuer, notBefore, notAfter, names, sha256: null, serialHex: null,
    sources: ['crtsh'], revoked: null, precert: null, ...extra
  };
  return { id: ctCertId(c), ...c };
};
/** A ct target (both sources read in full). */
const ctT = (certificates, extra = {}) => ({
  target: 'example.com', days: 30, readAt: NOW.toISOString(),
  sources: [{ source: 'crtsh', ok: true, state: 'ok', lastFullAt: NOW.toISOString() }, { source: 'certspotter', ok: true, state: 'ok', lastFullAt: NOW.toISOString() }],
  complete: true, answered: true, recent: 0,
  issuers: [...new Set(certificates.map((c) => c.ca))].map((name) => ({ name, count: certificates.filter((c) => c.ca === name).length, intermediates: [], newest: certificates.find((c) => c.ca === name).notBefore })),
  names: [...new Set(certificates.flatMap((c) => c.names))], certificates, ...extra
});
const report = (targets, extra = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command: 'ct', startedAt: '2026-10-07T03:00:00.000Z', finishedAt: '2026-10-07T03:01:00.000Z',
  options: { sources: ['crtsh', 'certspotter'], days: 30, radar: [30, 14, 7], expectedCas: [] }, targets, ...extra
});
const tags = (changes) => changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.item ?? ''}`.trim());
const watched = (certs, opts = {}, extra = {}) => watchTarget(ctT(certs, extra), { now: NOW, radar: [30, 14, 7], ...opts });

// A 90-day Let's Encrypt certificate: renewed by ACME clients at 30 days left.
const le90 = (notBefore, names = ['example.com', 'www.example.com'], extra = {}) => cert(LE, notBefore, new Date(Date.parse(notBefore) + 90 * DAY - 1000).toISOString(), names, extra);

describe('command line: --radar and --expected-ca', () => {
  test('the radar: the app\'s 30, 14, 7 by default; whole days, largest first, duplicates dropped; ct only', () => {
    assert.deepEqual(parseCommandLine(['ct', 'example.com']).options.radar, [30, 14, 7]);
    assert.deepEqual(parseCommandLine(['ct', 'example.com', '--radar', '7,21,7']).options.radar, [21, 7]);
    assert.deepEqual(radarOption('60 30;1'), [60, 30, 1]);
    for (const bad of ['0', '399', '30,14,7,3,2,1', 'soon', '', '7.5']) {
      assert.throws(() => radarOption(bad), /--radar takes up to 5 whole numbers of days from 1 to 398/, bad);
    }
    assert.throws(() => parseCommandLine(['health', 'example.com', '--radar', '7']), /--radar applies to ct only, not to health/);
  });

  test('expected CAs: repeatable, one CA each, whitespace collapsed, duplicates dropped; empty, too long or too many refused', () => {
    const o = parseCommandLine(['ct', 'example.com', '--expected-ca', 'letsencrypt', '--expected-ca', '  Example   Corp CA ', '--expected-ca', 'LetsEncrypt']).options;
    assert.deepEqual(o.expectedCas, ['letsencrypt', 'Example Corp CA']);
    assert.deepEqual(parseCommandLine(['ct', 'example.com']).options.expectedCas, []);
    assert.throws(() => expectedCaOption(['  ']), /--expected-ca needs a CA/);
    assert.throws(() => expectedCaOption(['x'.repeat(121)]), /at most 120 characters, not 121/);
    assert.throws(() => expectedCaOption(Array.from({ length: 31 }, (_, i) => `ca${i}`)), /at most 30 CAs, not 31/);
    assert.equal(expectedCaOption([...Array.from({ length: 30 }, (_, i) => `ca${i}`), 'CA0']).length, 30, 'a duplicate is not one more');
    assert.throws(() => parseCommandLine(['renew', 'example.com', '--expected-ca', 'x']), /--expected-ca applies to ct only/);
  });

  test('--help says what counts and gives an example that parses', () => {
    assert.match(USAGE, /--radar D,D,\.\.\./);
    assert.match(USAGE, /--expected-ca CA/);
    assert.match(USAGE.replace(/\s+/g, ' '), /less than a quarter of its lifetime left \(ACME clients renew at a third; a crossing before that is listed only\)/);
    const example = /node tools\/ds\.mjs (ct example\.com --expected-ca .+)$/m.exec(USAGE)[1];
    assert.deepEqual(parseCommandLine(example.split(/\s+/)).options.radar, [21, 7]);
    assert.ok(['CA', 'EXPIRING', 'REVOKED'].every((tag) => CHANGE_TAGS.includes(tag)));
  });
});

describe('the store of the certificates seen', () => {
  test('a report\'s own store, its bad entries dropped', () => {
    const prev = { target: 'example.com', seen: { at: '2026-10-07T03:00:00Z', ids: { '0123456789abcdef': '2026-12-01', nothex: '2026-12-01', fedcba9876543210: 'soon' } } };
    assert.deepEqual(seenOf(prev), { at: '2026-10-07T03:00:00.000Z', ids: { '0123456789abcdef': '2026-12-01' } });
  });

  test('a report written before the store: the ids of its certificates, as of its read; none when it never read the domain', () => {
    const a = le90('2026-09-01T00:00:00Z');
    assert.deepEqual(seenOf(ctT([a], { readAt: '2026-10-06T03:00:00.000Z' })), { at: '2026-10-06T03:00:00.000Z', ids: { [a.id]: a.notAfter.slice(0, 10) } });
    assert.deepEqual(seenOf(ctT([a], { readAt: undefined }), '2026-10-05T03:00:00.000Z').at, '2026-10-05T03:00:00.000Z');
    assert.equal(seenOf(ctT([], { answered: false })), null);
    assert.equal(seenOf(null), null);
    assert.equal(seenOf(ctT([a], { readAt: undefined })), null, 'no time: no store');
  });
});

describe('the watch over a report\'s certificates', () => {
  const a = le90('2026-09-15T00:00:00Z');                                       // 68 days left
  const w = cert(LE, '2026-09-20T00:00:00.000Z', '2026-12-19T00:00:00.000Z', ['*.example.com']);
  const gts = cert(GTS, '2026-10-01T00:00:00.000Z', '2026-12-30T00:00:00.000Z', ['shop.example.com'], { sources: ['certspotter'], precert: true, revoked: false });
  const old = le90('2026-07-20T00:00:00Z');                                     // the same names, expires sooner: superseded
  // 11 days left; two labels down, so the wildcard (which expires later) does not supersede it
  const soon = cert(LE, '2026-07-12T00:00:00.000Z', '2026-10-20T00:00:00.000Z', ['api.eu.example.com']);

  test('the app\'s analysis: current, days left, radar, wildcard, precertificate only, superseded, unexpected', () => {
    const x = watched([gts, w, a, old, soon], { expected: ['letsencrypt'] });
    const by = Object.fromEntries(x.certificates.map((c) => [c.id, c]));
    assert.equal(by[a.id].current, true);
    assert.equal(by[a.id].daysLeft, Math.floor((Date.parse(a.notAfter) - NOW.getTime()) / DAY));
    assert.equal(by[a.id].radar, undefined, 'outside the radar');
    assert.deepEqual(by[old.id].flags, ['superseded']);
    assert.equal(by[old.id].current, false);
    assert.deepEqual(by[w.id].flags, ['wildcard']);
    assert.equal(by[w.id].wildcard, true);
    assert.deepEqual(by[gts.id].flags, ['unexpected', 'precert']);
    assert.equal(by[gts.id].unexpected, true);
    assert.equal(by[a.id].unexpected, false);
    assert.equal(by[soon.id].radar, 14, 'the smallest threshold it is within');
    assert.equal(by[soon.id].isNew, null, 'no earlier run: nothing is new');
    assert.deepEqual(x.watch, { radar: [30, 14, 7], expected: ['letsencrypt'], comparedWith: null,
      counts: { current: 4, expiring: 1, new: 0, unexpected: 1, wildcard: 1, precert: 1, revoked: 0 } });
    // without expected CAs no issuer is unexpected (null), as in the app
    assert.equal(watched([gts]).certificates[0].unexpected, null);
  });

  test('new since the last run: an id the store does not hold; the store gains this read\'s ids and drops the expired', () => {
    const gone = { id: 'ffffffffffffffff' };
    const prev = { target: 'example.com', seen: { at: '2026-10-07T03:00:00.000Z', ids: { [a.id]: a.notAfter.slice(0, 10), [gone.id]: '2026-10-01' } } };
    const x = watched([gts, a], { prev });
    const by = Object.fromEntries(x.certificates.map((c) => [c.id, c]));
    assert.equal(by[a.id].isNew, false);
    assert.equal(by[gts.id].isNew, true);
    assert.deepEqual(by[gts.id].flags.includes('new'), true);
    assert.equal(x.watch.comparedWith, '2026-10-07T03:00:00.000Z');
    assert.deepEqual(x.seen, { at: NOW.toISOString(), ids: { [a.id]: a.notAfter.slice(0, 10), [gts.id]: '2026-12-30' } });
    // a source missed `gts` the night after: it stays seen, so it is not new when it comes back
    const after = watched([a], { prev: x });
    assert.ok(after.seen.ids[gts.id]);
    const back = watched([gts, a], { prev: after });
    assert.equal(back.certificates.find((c) => c.id === gts.id).isNew, false);
  });

  test('a night CT could not be read keeps the store as it was; carried certificates are watched again, their old fields replaced', () => {
    const prev = watched([soon, a], {}, { readAt: '2026-10-01T03:00:00.000Z' });
    const unread = { ...ctT([], { answered: false, complete: false, readAt: NOW.toISOString(),
      sources: [{ source: 'crtsh', ok: false, state: 'unavailable' }, { source: 'certspotter', ok: false, state: 'rate-limited' }] }) };
    const carried = carryCt(unread, prev, { now: NOW });
    const x = watchTarget(carried, { prev, now: NOW, radar: [30, 14, 7] });
    assert.deepEqual(x.seen, prev.seen);
    const s = x.certificates.find((c) => c.id === soon.id);
    assert.ok(s.carried);
    assert.equal(s.radar, 14);
    assert.equal(s.isNew, false);
    // a field the watch writes is never left over from the baseline's run
    const stale = watchTarget(ctT([{ ...a, radar: 7, flags: ['new'], isNew: true }]), { now: NOW, radar: [30, 14, 7] });
    assert.equal(stale.certificates[0].radar, undefined);
    assert.deepEqual(stale.certificates[0].flags, []);
  });

  test('a certificate whose dates cannot be read is kept, unwatched', () => {
    const bad = { ...a, id: '00000000000000aa', notAfter: null };
    const x = watched([bad, a]);
    assert.equal(x.certificates.find((c) => c.id === bad.id).current, undefined);
    assert.equal(x.watch.counts.current, 1);
  });
});

describe('the radar crossings and an overdue renewal', () => {
  test('a quarter of the lifetime: a 90-day certificate counts at 14 and 7 days, not at 30; a 200-day one at 30', () => {
    assert.equal(OVERDUE_SHARE, 0.25);
    const c90 = le90('2026-08-01T00:00:00Z');
    assert.ok(Math.abs(overdueDays(c90) - 22.5) < 0.01);
    const c200 = cert(LE, '2026-05-01T00:00:00.000Z', '2026-11-17T00:00:00.000Z', ['example.com']);
    assert.equal(overdueDays(c200), 50);
    assert.equal(overdueDays({ notBefore: null, notAfter: '2026-11-17T00:00:00.000Z' }), Infinity);
    assert.equal(daysLeftAt('2026-10-30T00:00:00.000Z', Date.parse('2026-10-08T03:00:00Z')), 21);
    assert.equal(renewalOverdue({ ...c90, daysLeft: 22 }), true);
    assert.equal(renewalOverdue({ ...c90, daysLeft: 23 }), false);
  });

  test('a crossing: the smallest threshold it is within now, outside it at the last read; never for a new certificate', () => {
    const c = { ...le90('2026-07-20T00:00:00Z'), current: true };                // expires 2026-10-18
    const at = (iso) => Date.parse(iso);
    const now = { ...c, daysLeft: daysLeftAt(c.notAfter, at('2026-10-08T03:00:00Z')) };
    assert.equal(now.daysLeft, 9);
    assert.deepEqual(radarCrossing(now, c, { radar: [30, 14, 7], lastRead: at('2026-10-01T03:00:00Z') }), { daysLeft: 9, threshold: 14, overdue: true });
    assert.equal(radarCrossing(now, c, { radar: [30, 14, 7], lastRead: at('2026-10-07T03:00:00Z') }), null, 'within 14 days already then');
    assert.equal(radarCrossing(now, undefined, { radar: [30, 14, 7], lastRead: at('2026-10-01T03:00:00Z') }), null, 'not known before');
    assert.equal(radarCrossing({ ...now, current: false }, c, { radar: [30, 14, 7], lastRead: at('2026-10-01T03:00:00Z') }), null, 'superseded');
    const at30 = { ...c, daysLeft: 29 };
    assert.deepEqual(radarCrossing(at30, c, { radar: [30, 14, 7], lastRead: at('2026-09-16T03:00:00Z') }), { daysLeft: 29, threshold: 30, overdue: false });
    assert.equal(radarCrossing(at30, c, { radar: [30, 14, 7], lastRead: at('2026-09-17T03:00:00Z') }), null, '30 days left (rounded down) then');
    // a radar changed between two runs moves nothing by itself: the last read is measured with tonight's
    assert.equal(radarCrossing({ ...c, daysLeft: 40 }, c, { radar: [60, 30], lastRead: at('2026-09-26T03:00:00Z') }), null);
  });
});

describe('the changes the watch counts', () => {
  const a = le90('2026-09-15T00:00:00Z');
  const gts = cert(GTS, '2026-10-01T00:00:00.000Z', '2026-12-30T00:00:00.000Z', ['shop.example.com'], { sources: ['certspotter'] });

  test('a new certificate from a CA not named: CA counts; a renewal from a named CA stays CERT, listed only', () => {
    const prior = cert(GTS, '2026-09-01T00:00:00.000Z', '2026-11-30T00:00:00.000Z', ['mail.example.com']);
    const b = report([watched([prior, a], { expected: ['letsencrypt'] }, { readAt: '2026-10-07T03:00:00.000Z' })]);
    const renewal = le90('2026-10-07T12:00:00Z');
    const gtsShop = cert(GTS, '2026-10-07T13:00:00.000Z', '2027-01-05T00:00:00.000Z', ['mail.example.com'], { precert: true });
    const after = report([watchTarget(ctT([gtsShop, renewal, prior, a]), { prev: b.targets[0], now: NOW, radar: [30, 14, 7], expected: ['letsencrypt'] })]);
    const changes = diffReports('ct', b, after, { t });
    assert.deepEqual(tags(changes), [`CA ${gtsShop.id}`, `CERT? ${renewal.id}`]);
    assert.equal(changes[0].tone, 'bad');
    assert.equal(changeText(changes[0]), 'example.com: certificate from Google Trust Services (WR1), not one of the expected CAs, issued 2026-10-07: mail.example.com (precertificate only)');
  });

  test('a new issuer that is not expected counts even when a source may only have missed it before', () => {
    const b = report([watched([a], { expected: ['letsencrypt'] }, {
      complete: false, sources: [{ source: 'crtsh', ok: true, state: 'ok', lastFullAt: '2026-10-07T03:00:00.000Z' }, { source: 'certspotter', ok: false, state: 'rate-limited', lastFullAt: null }],
      readAt: '2026-10-07T03:00:00.000Z' })]);
    const early = cert(GTS, '2026-09-01T00:00:00.000Z', '2026-11-30T00:00:00.000Z', ['shop.example.com'], { sources: ['certspotter'] });
    const changes = diffReports('ct', b, report([watchTarget(ctT([early, a]), { prev: b.targets[0], now: NOW, radar: [30, 14, 7], expected: ['letsencrypt'] })]), { t });
    const issuer = changes.find((c) => c.tag === 'ISSUER');
    assert.equal(issuer.counts, true);
    assert.equal(changeText(issuer), 'example.com: new issuer Google Trust Services: 1 current certificate, newest 2026-09-01, not one of the expected CAs '
      + '(listed only by a source no earlier run read in full: it may not be new)');
    assert.ok(!changes.some((c) => c.tag === 'CA'), 'the ISSUER line says it');
    // expected after all: listed only, as before
    const fine = diffReports('ct', b, report([watchTarget(ctT([early, a]), { prev: b.targets[0], now: NOW, radar: [30, 14, 7], expected: ['letsencrypt', 'pki.goog'] })]), { t });
    assert.equal(fine.find((c) => c.tag === 'ISSUER').counts, false);
  });

  test('new is measured against the store: a certificate a source missed last night is no new CERT', () => {
    const extra = le90('2026-09-20T00:00:00Z', ['api.example.com']);
    const night1 = watched([extra, a], {}, { readAt: '2026-10-06T03:00:00.000Z' });
    const night2 = watchTarget(ctT([a], { readAt: '2026-10-07T03:00:00.000Z', complete: true }), { prev: night1, now: new Date('2026-10-07T03:00:00Z'), radar: [30, 14, 7] });
    const b = report([night2]);
    const changes = diffReports('ct', b, report([watchTarget(ctT([extra, a]), { prev: night2, now: NOW, radar: [30, 14, 7] })]), { t });
    assert.ok(!changes.some((c) => c.tag === 'CERT'), tags(changes).join(' '));
  });

  test('EXPIRING: counted once the renewal is overdue, listed only before; measured from the last read, across a night CT was down', () => {
    const c = le90('2026-07-20T00:00:00Z');                                    // expires 2026-10-17 23:59:59
    const read1 = watched([c], {}, { readAt: '2026-09-30T03:00:00.000Z' });
    const day = (d) => new Date(`2026-10-${d}T03:00:00Z`);
    // night of 2026-10-01: 16 days left, crossed nothing (within 30 days already on 2026-09-30? no: 17 days then)
    const n1 = watchTarget(ctT([c], { readAt: day('01').toISOString() }), { prev: read1, now: day('01'), radar: [30, 14, 7] });
    assert.deepEqual(tags(diffReports('ct', report([read1]), report([n1]), { t })), []);
    // 2026-10-04: within 14 days; the night of 2026-10-04 CT is down, 2026-10-05 it is read again
    const down = carryCt(ctT([], { answered: false, complete: false, readAt: day('04').toISOString(),
      sources: [{ source: 'crtsh', ok: false, state: 'unavailable' }, { source: 'certspotter', ok: false, state: 'rate-limited' }] }), n1, { now: day('04') });
    const n4 = watchTarget(down, { prev: n1, now: day('04'), radar: [30, 14, 7] });
    assert.equal(n4.seen.at, day('01').toISOString(), 'the store keeps the last read');
    const n5 = watchTarget(ctT([c], { readAt: day('05').toISOString() }), { prev: n4, now: day('05'), radar: [30, 14, 7] });
    const changes = diffReports('ct', report([n4], { startedAt: day('04').toISOString() }), report([n5]), { t });
    const expiring = changes.filter((x) => x.tag === 'EXPIRING');
    assert.equal(expiring.length, 1);
    assert.equal(expiring[0].counts, true);
    assert.equal(changeText(expiring[0]), "example.com: example.com, www.example.com: 12 days left (expires 2026-10-17), within the radar's 14 days; Let's Encrypt (R11) — its automatic renewal is overdue");
    // a certificate a source missed the night before (in the store, not in the list) crosses all the same
    const missed = { ...n1, certificates: [] };
    assert.deepEqual(diffReports('ct', report([missed], { startedAt: day('01').toISOString() }), report([n5]), { t }).map((x) => x.tag), ['EXPIRING']);
    // the 30-day crossing of a 90-day certificate is when ACME clients renew it: listed only
    const c2 = le90('2026-08-20T00:00:00Z');                                   // 30 days left on 2026-10-18
    const before30 = watchTarget(ctT([c2], { readAt: '2026-10-17T03:00:00.000Z' }), { now: new Date('2026-10-17T03:00:00Z'), radar: [30, 14, 7] });
    const at30 = watchTarget(ctT([c2], { readAt: '2026-10-18T03:00:00.000Z' }), { prev: before30, now: new Date('2026-10-18T03:00:00Z'), radar: [30, 14, 7] });
    const quiet = diffReports('ct', report([before30]), report([at30]), { t });
    assert.deepEqual(tags(quiet), [`EXPIRING? ${c2.id}`]);
    assert.match(changeText(quiet[0]), /within the radar's 30 days; Let's Encrypt \(R11\) \(an automatic renewal is not overdue yet\)/);
    // renewed in time: the old one is superseded and crosses nothing
    const renewed = le90('2026-10-18T01:00:00Z');
    const n18 = watchTarget(ctT([renewed, c2], { readAt: '2026-10-18T03:00:00.000Z' }), { prev: before30, now: new Date('2026-10-18T03:00:00Z'), radar: [30, 14, 7] });
    assert.ok(!diffReports('ct', report([before30]), report([n18]), { t }).some((x) => x.tag === 'EXPIRING'));
  });

  test('REVOKED: the certificate in use counts; one a newer certificate replaced, or not known before, is listed only', () => {
    const inUse = cert(GTS, '2026-09-01T00:00:00.000Z', '2026-11-30T00:00:00.000Z', ['shop.example.com'], { sources: ['certspotter'], revoked: false });
    const b = report([watched([inUse, a], {}, { readAt: '2026-10-07T03:00:00.000Z' })]);
    const after = report([watchTarget(ctT([{ ...inUse, revoked: true }, a]), { prev: b.targets[0], now: NOW, radar: [30, 14, 7] })]);
    const changes = diffReports('ct', b, after, { t });
    assert.deepEqual(tags(changes), [`REVOKED ${inUse.id}`]);
    assert.equal(changeText(changes[0]), 'example.com: certificate from Google Trust Services (WR1) revoked by its CA: shop.example.com (it was the current certificate of these names)');
    const unknown = report([watched([{ ...inUse, revoked: null }, a], {}, { readAt: '2026-10-07T03:00:00.000Z' })]);
    assert.deepEqual(tags(diffReports('ct', unknown, after, { t })), [`REVOKED? ${inUse.id}`]);
  });

  test('notes: the expected CAs or the radar differ from the baseline\'s (a baseline written before them says nothing)', () => {
    const b = report([]);
    const a2 = report([], { options: { sources: ['crtsh', 'certspotter'], days: 30, radar: [21, 7], expectedCas: ['letsencrypt'] } });
    assert.deepEqual(baselineNotes('ct', b, a2), [
      'The expected CAs differ from the baseline\'s (none → letsencrypt): a certificate seen before is not said again, though the summary marks it.',
      'The expiry radar differs from the baseline\'s (30,14,7 → 21,7 days).'
    ]);
    assert.deepEqual(baselineNotes('ct', report([], { options: { sources: ['crtsh', 'certspotter'], days: 30 } }), a2), []);
  });

  test('a baseline whose store is damaged cannot be compared', () => {
    assert.match(baselineProblem(report([{ ...ctT([]), seen: { at: 5, ids: {} } }]), 'ct'), /has a "seen" that is not a store of certificate ids/);
    assert.equal(baselineProblem(report([watched([a])]), 'ct'), null);
  });
});

describe('the summary\'s watch lines', () => {
  const soon = cert(LE, '2026-07-12T00:00:00.000Z', '2026-10-20T00:00:00.000Z', ['api.example.com']);
  const a = le90('2026-09-15T00:00:00Z');
  const gts = cert(GTS, '2026-10-01T00:00:00.000Z', '2026-12-30T00:00:00.000Z', ['*.shop.example.com'], { sources: ['certspotter'], precert: true });

  test('the radar, new since the last run, the unexpected CAs and the rest, as the app\'s tab counts them', () => {
    const prev = { target: 'example.com', seen: { at: '2026-10-07T03:00:00.000Z', ids: { [a.id]: '2026-12-14', [soon.id]: '2026-10-20' } } };
    const x = watched([gts, a, soon], { prev, expected: ['letsencrypt'] });
    const text = renderPlainText(ctDoc(x, { t, now: NOW, baselined: true }));
    assert.match(text, /- Expiry radar \(30, 14, 7 days\): 1 current certificate within 30 days\n- 11 days left \(2026-10-20\), Let's Encrypt \(R11\): api\.example\.com — its renewal is overdue\n/);
    assert.match(text, /- New since the last run \(2026-10-07\): 1\n- 2026-10-01 Google Trust Services \(WR1\): \*\.shop\.example\.com — not one of the expected CAs — precertificate only\n/);
    assert.match(text, /- Unexpected CA \(expected: letsencrypt\): 1\n- 2026-10-01 Google Trust Services \(WR1\): \*\.shop\.example\.com — precertificate only\n/);
    assert.match(text, /- Wildcard 1 · precertificate only 1\n/);
    const md = renderMarkdown(ctDoc(x, { t, now: NOW, baselined: true }));
    assert.match(md, /`Google Trust Services` \(`WR1`\): `\*\.shop\.example\.com`/, 'values are code spans');
    assert.match(md, /Unexpected CA \(expected: `letsencrypt`\)/);
  });

  test('a first run says nothing is new yet; a run without --baseline says nothing about new; none without expected CAs', () => {
    const x = watched([a]);
    const lines = ctWatchLines(x, { t, baselined: true }).map((parts) => parts.map((p) => (typeof p === 'string' ? p : p.code)).join(''));
    assert.deepEqual(lines, ['Expiry radar (30, 14, 7 days): no current certificate within 30 days',
      'First run for this domain: nothing is marked new; the next run marks what is logged after this one']);
    assert.equal(ctWatchLines(x, { t, baselined: false }).length, 1);
    // CT could not be read: no watch lines, the summary says what is kept
    const unread = watched([], {}, { answered: false });
    assert.doesNotMatch(renderPlainText(ctDoc(unread, { t, now: NOW, baselined: true })), /Expiry radar/);
  });
});

describe('what Cert Spotter\'s DER says', () => {
  test('the serial number and a precertificate; anything unreadable is nothing', () => {
    const b64 = (o) => Buffer.from(certDer({ names: ['shop.example.com'], notBefore: '2026-09-01T00:00:00Z', notAfter: '2026-11-30T00:00:00Z', ...o })).toString('base64');
    const pre = readCertDer(b64({ serial: 9, precert: true }), parseCertificate);
    assert.deepEqual([pre.serialHex, pre.precert], ['09', true]);
    // the public key's SHA-256 (the SubjectPublicKeyInfo's): a known certificate's ref (lib/waivers.js)
    assert.match(pre.spkiSha256, /^[0-9a-f]{64}$/);
    const plain = readCertDer(b64({ serial: 10 }), parseCertificate);
    assert.deepEqual([plain.serialHex, plain.precert, plain.spkiSha256], ['0a', false, pre.spkiSha256], 'the same fake key');
    assert.equal(readCertDer('bm90IGEgY2VydA==', parseCertificate), null);
    assert.equal(readCertDer(undefined, parseCertificate), null);
    assert.equal(readCertDer(b64({}), null), null);
  });

  test('ctTarget keeps them, with the revocation flag, on the certificate crt.sh and Cert Spotter both list', () => {
    const der = Buffer.from(certDer({ names: ['example.com'], notBefore: '2026-09-20T00:00:00Z', notAfter: '2026-12-19T00:00:00Z', serial: 7, precert: true })).toString('base64');
    const fetched = {
      certs: [
        { source: 'crtsh', sources: ['crtsh'], issuer: LE, notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: new Date('2026-12-19T00:00:00Z'), names: ['example.com'], sha256: null, serialHex: null },
        { source: 'certspotter', sources: ['certspotter'], issuer: LE, notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: new Date('2026-12-19T00:00:00Z'), names: ['example.com'], sha256: 'ab'.repeat(32), revoked: true, der }
      ],
      health: [{ source: 'crtsh', state: 'ok', ok: true }, { source: 'certspotter', state: 'ok', ok: true }]
    };
    const x = ctTarget('example.com', fetched, { issuerName, dnPart, days: 30, now: NOW, sources: ['crtsh', 'certspotter'], parseCertificate });
    assert.equal(x.certificates.length, 1);
    const [c] = x.certificates;
    assert.deepEqual([c.serialHex, c.precert, c.revoked, c.sources], ['07', true, true, ['certspotter', 'crtsh']]);
    // without the parser (or the DER) nothing is known
    const y = ctTarget('example.com', { ...fetched, certs: [fetched.certs[0]] }, { issuerName, dnPart, days: 30, now: NOW, sources: ['crtsh'] });
    assert.deepEqual([y.certificates[0].precert, y.certificates[0].revoked], [null, null]);
  });
});

describe('nights of the runner', () => {
  const sink = () => ({ text: '', isTTY: false, write(s) { this.text += s; return true; } });
  const run = async (argv, { fetchImpl, now }) => {
    const stdout = sink();
    const stderr = sink();
    const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now });
    return { code, out: stdout.text, err: stderr.text };
  };

  test('Cert Spotter with DER asked: a precertificate, an unexpected CA the night it is logged, an overdue renewal crossing 14 days', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ds-ctwatch-'));
    try {
      let rows = [
        spotterRow({ names: ['example.com', 'www.example.com'], notBefore: '2026-08-01T00:00:00Z', notAfter: '2026-10-30T00:00:00Z', serial: 1, issuer: LE }),
        spotterRow({ names: ['*.example.com'], notBefore: '2026-09-01T00:00:00Z', notAfter: '2026-11-30T00:00:00Z', serial: 2, issuer: LE }),
        spotterRow({ names: ['shop.example.com'], notBefore: '2026-09-10T00:00:00Z', notAfter: '2026-12-09T00:00:00Z', serial: 3, issuer: GTS, precert: true })
      ];
      const asked = [];
      const fetchImpl = async (url) => {
        const u = String(url);
        asked.push(u);
        if (u.startsWith('https://api.certspotter.com/')) return Response.json(u.includes('after=') ? [] : rows);
        if (u.startsWith('https://crt.sh/')) return Response.json(rows.map((r, i) => crtshRow({ id: i + 1, names: r.dns_names, notBefore: r.not_before.slice(0, 19), notAfter: r.not_after.slice(0, 19), issuer: r.issuer.name, serial: `0${i + 1}` })));
        return new Response('', { status: 404 });
      };
      const json = join(dir, 'ct.json');
      const md = join(dir, 'ct.md');
      const night = (day) => run(['ct', 'example.com', '--baseline', json, '--json', json, '--md', md, '--fail-on-change', '--expected-ca', 'letsencrypt', '--expected-ca', 'Example Corp CA'],
        { fetchImpl, now: new Date(`2026-10-${day}T03:00:00Z`) });

      const first = await night('01');
      assert.equal(first.code, EXIT.OK, first.err);
      assert.ok(asked.filter((u) => u.startsWith('https://api.certspotter.com/')).every((u) => u.includes('&expand=cert_der')), 'the DER is asked for');
      assert.match(first.err, /ds: warning: --expected-ca "Example Corp CA" names no CA DomainScope knows and no issuer read contains it: a typo there makes every issuer unexpected\n/);
      assert.doesNotMatch(first.err, /--expected-ca "letsencrypt"/, 'a CA the app knows is no warning');
      assert.match(first.out, /- 28 days left \(2026-10-30\), Let's Encrypt \(R11\): example\.com, www\.example\.com\n/);
      assert.match(first.out, /- First run for this domain: nothing is marked new/);
      assert.match(first.out, /- 2026-09-10 Google Trust Services \(WR1\): shop\.example\.com — precertificate only\n/);
      let doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.options, { sources: ['crtsh', 'certspotter'], days: 30, radar: [30, 14, 7], expectedCas: ['letsencrypt', 'Example Corp CA'] });
      const shop = doc.targets[0].certificates.find((c) => c.names[0] === 'shop.example.com');
      assert.deepEqual([shop.precert, shop.revoked, shop.unexpected, shop.serialHex, shop.sources], [true, false, true, '03', ['certspotter', 'crtsh']]);
      assert.equal(Object.keys(doc.targets[0].seen.ids).length, 3);

      rows = [...rows, spotterRow({ names: ['api.example.com'], notBefore: '2026-10-01T12:00:00Z', notAfter: '2026-12-30T00:00:00Z', serial: 4, issuer: GTS })];
      const second = await night('02');
      assert.equal(second.code, EXIT.CHANGED, second.err);
      assert.match(second.out, /\n {2}CA {9}example\.com: certificate from Google Trust Services \(WR1\), not one of the expected CAs, issued 2026-10-01: api\.example\.com\n/);
      assert.match(second.out, /- New since the last run \(2026-10-01\): 1\n/);
      assert.match(readFileSync(md, 'utf8'), /- \*\*CA\*\* `example\.com`: certificate from `Google Trust Services` \(`WR1`\), not one of the expected CAs/);

      const quiet = await night('03');
      assert.equal(quiet.code, EXIT.OK, quiet.out);
      assert.match(quiet.out, /Changes since the baseline \(ct\.json, run of 2026-10-02 03:00 UTC\): none/);

      const late = await night('16');
      assert.equal(late.code, EXIT.CHANGED, late.out);
      assert.match(late.out, /EXPIRING {3}example\.com: example\.com, www\.example\.com: 13 days left \(expires 2026-10-30\), within the radar's 14 days; Let's Encrypt \(R11\) — its automatic renewal is overdue\n/);
      doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.changes.filter((c) => c.tag === 'EXPIRING').map((c) => [c.counts, c.tone, c.after]), [[true, 'bad', 14]]);
      assert.equal(doc.targets[0].watch.counts.expiring, 1);

      // a text entry an issuer read contains (an intermediate's name) is no typo
      const text = await run(['ct', 'example.com', '--expected-ca', 'WR1', '--expected-ca', 'letsencrypt'], { fetchImpl, now: new Date('2026-10-16T03:00:00Z') });
      assert.equal(text.code, EXIT.OK, text.err);
      assert.doesNotMatch(text.err, /warning/);
      assert.match(text.out, /- Unexpected CA \(expected: WR1, letsencrypt\): none\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
