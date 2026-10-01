/**
 * lib/ics.js — the expiry calendar (RFC 5545): a golden file, line folding at 75 octets of UTF-8
 * (never inside a character), TEXT escaping, CRLF line endings, a stable UID and the alarms.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildCalendar, foldIcsLine, icsEscape, ICS_FOLD_OCTETS, ICS_ALARM_DAYS, ICS_PRODID } from '../../assets/js/lib/ics.js';

const NOW = new Date('2026-10-02T12:34:56Z');
const octets = (s) => new TextEncoder().encode(s).length;
const unfold = (text) => text.replace(/\r\n /g, '');

const EVENTS = [
  {
    uid: 'expiry-example.com@domainscope',
    date: new Date('2027-01-15T10:00:00Z'),
    summary: 'example.com expires (registrar: Example Registrar, Inc.; renew it)',
    description: 'Registrar: Example Registrar, Inc.\nName servers of: example.org, example-test.com.tr — renew before the date; a lapsed name server domain lets anyone answer for these zones.',
    alarm: 'example.com expires on 2027-01-15'
  },
  { uid: 'expiry-example-test.com.tr@domainscope', date: '2026-11-30', summary: 'example-test.com.tr alan adının süresi doluyor: İstanbul şubesi, ğüşıöç' }
];

/** The golden file, line by line (joined with CRLF, ending with CRLF). */
const GOLDEN = [
  'BEGIN:VCALENDAR',
  'VERSION:2.0',
  'PRODID:-//DomainScope//Domain portfolio//EN',
  'CALSCALE:GREGORIAN',
  'METHOD:PUBLISH',
  'X-WR-CALNAME:DomainScope: example.com\\, example.org',
  'BEGIN:VEVENT',
  'UID:expiry-example.com@domainscope',
  'DTSTAMP:20261002T123456Z',
  'SEQUENCE:9876',
  'DTSTART;VALUE=DATE:20270115',
  'DTEND;VALUE=DATE:20270116',
  'SUMMARY:example.com expires (registrar: Example Registrar\\, Inc.\\; renew it',
  ' )',
  'DESCRIPTION:Registrar: Example Registrar\\, Inc.\\nName servers of: example.o',
  ' rg\\, example-test.com.tr — renew before the date\\; a lapsed name server ',
  ' domain lets anyone answer for these zones.',
  'TRANSP:TRANSPARENT',
  'BEGIN:VALARM',
  'ACTION:DISPLAY',
  'TRIGGER:-P30D',
  'DESCRIPTION:example.com expires on 2027-01-15',
  'END:VALARM',
  'BEGIN:VALARM',
  'ACTION:DISPLAY',
  'TRIGGER:-P7D',
  'DESCRIPTION:example.com expires on 2027-01-15',
  'END:VALARM',
  'END:VEVENT',
  'BEGIN:VEVENT',
  'UID:expiry-example-test.com.tr@domainscope',
  'DTSTAMP:20261002T123456Z',
  'SEQUENCE:9830',
  'DTSTART;VALUE=DATE:20261130',
  'DTEND;VALUE=DATE:20261201',
  'SUMMARY:example-test.com.tr alan adının süresi doluyor: İstanbul şubes',
  ' i\\, ğüşıöç',
  'TRANSP:TRANSPARENT',
  'BEGIN:VALARM',
  'ACTION:DISPLAY',
  'TRIGGER:-P30D',
  'DESCRIPTION:example-test.com.tr alan adının süresi doluyor: İstanbul ş',
  ' ubesi\\, ğüşıöç',
  'END:VALARM',
  'BEGIN:VALARM',
  'ACTION:DISPLAY',
  'TRIGGER:-P7D',
  'DESCRIPTION:example-test.com.tr alan adının süresi doluyor: İstanbul ş',
  ' ubesi\\, ğüşıöç',
  'END:VALARM',
  'END:VEVENT',
  'END:VCALENDAR'
];

describe('buildCalendar', () => {
  const text = buildCalendar(EVENTS, { now: NOW, name: 'DomainScope: example.com, example.org' });

  test('the golden file', () => {
    assert.equal(text, `${GOLDEN.join('\r\n')}\r\n`);
  });

  test('CRLF everywhere, never a bare LF or CR; every physical line within 75 octets', () => {
    assert.ok(text.endsWith('\r\n'));
    assert.doesNotMatch(text.replace(/\r\n/g, ''), /[\r\n]/);
    for (const line of text.split('\r\n').slice(0, -1)) assert.ok(octets(line) <= ICS_FOLD_OCTETS, `${octets(line)}: ${line}`);
  });

  test('unfolded, every property is whole and the text values read back', () => {
    const lines = unfold(text).split('\r\n');
    const summary = lines.find((l) => l.startsWith('SUMMARY:example.com'));
    assert.equal(summary, 'SUMMARY:example.com expires (registrar: Example Registrar\\, Inc.\\; renew it)');
    const unescape = (v) => v.replace(/\\n/g, '\n').replace(/\\([\\;,])/g, '$1');
    assert.equal(unescape(lines.find((l) => l.startsWith('DESCRIPTION:Registrar')).slice('DESCRIPTION:'.length)), EVENTS[0].description);
    assert.equal(unescape(lines.find((l) => l.startsWith('SUMMARY:example-test')).slice('SUMMARY:'.length)), EVENTS[1].summary);
  });

  test('one event per entry, with a VALARM 30 and 7 days before; the UID is the caller\'s', () => {
    assert.deepEqual(ICS_ALARM_DAYS, [30, 7]);
    assert.equal(text.match(/BEGIN:VEVENT/g).length, 2);
    assert.equal(text.match(/TRIGGER:-P30D/g).length, 2);
    assert.equal(text.match(/TRIGGER:-P7D/g).length, 2);
    assert.match(text, /\r\nUID:expiry-example\.com@domainscope\r\n/);
    assert.equal(text.match(/BEGIN:VALARM/g).length, text.match(/END:VALARM/g).length);
  });

  test('stable: the same dates give the same file but for DTSTAMP; a later date a higher SEQUENCE', () => {
    const later = buildCalendar(EVENTS, { now: new Date('2026-10-03T00:00:00Z'), name: 'DomainScope: example.com, example.org' });
    assert.equal(later.replace(/DTSTAMP:\S+/g, ''), text.replace(/DTSTAMP:\S+/g, ''));
    const renewed = buildCalendar([{ ...EVENTS[0], date: '2028-01-15' }], { now: NOW });
    const seq = (s) => Number(/SEQUENCE:(\d+)/.exec(s)[1]);
    assert.ok(seq(renewed) > seq(text));
    assert.match(renewed, /UID:expiry-example\.com@domainscope/);
  });

  test('an entry without a usable date is left out; no name, no X-WR-CALNAME; the PRODID', () => {
    const t = buildCalendar([{ uid: 'x@domainscope', date: 'not a date', summary: 'x' }, { uid: 'bad uid ı', date: '2027-02-01', summary: 's' }], { now: NOW });
    assert.equal(t.match(/BEGIN:VEVENT/g).length, 1);
    assert.match(t, /\r\nUID:bad-uid--@domainscope\r\n|UID:bad-uid-/);
    assert.doesNotMatch(t, /X-WR-CALNAME/);
    assert.match(t, new RegExp(`PRODID:${ICS_PRODID.replace(/[/.]/g, '\\$&')}`));
    assert.equal(buildCalendar([], { now: NOW }), ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:${ICS_PRODID}`, 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH', 'END:VCALENDAR', ''].join('\r\n'));
  });
});

describe('folding and escaping', () => {
  test('folds at 75 octets, a continuation counts its space; never splits a character', () => {
    assert.equal(foldIcsLine('a'.repeat(75)), 'a'.repeat(75));
    assert.equal(foldIcsLine('a'.repeat(76)), `${'a'.repeat(75)}\r\n a`);
    assert.equal(foldIcsLine('a'.repeat(75 + 74 + 1)), `${'a'.repeat(75)}\r\n ${'a'.repeat(74)}\r\n a`);
    // 'ş' is two octets: at 74 octets a third would cross the limit
    const s = `${'a'.repeat(74)}ş`;
    assert.equal(foldIcsLine(s), `${'a'.repeat(74)}\r\n ş`);
    // an emoji (four octets) is kept whole too
    const e = `${'a'.repeat(72)}🔒b`;
    assert.equal(foldIcsLine(e), `${'a'.repeat(72)}\r\n 🔒b`);
    for (const line of foldIcsLine('ğ'.repeat(200)).split('\r\n')) assert.ok(octets(line) <= 75);
    assert.equal(unfold(foldIcsLine('ğ'.repeat(200))), 'ğ'.repeat(200));
  });

  test('TEXT escaping: backslash first, then ; , and line breaks; control characters dropped (a tab is text)', () => {
    assert.equal(icsEscape('a\\b;c,d\ne\r\nf\rg'), 'a\\\\b\\;c\\,d\\ne\\nf\\ng');
    assert.equal(icsEscape('tab\there\u0007bell\u001b'), 'tab\therebell');
    assert.equal(icsEscape(null), '');
  });
});
