/**
 * ics.js — an iCalendar file (RFC 5545) of expiry dates: one all-day event per date with two
 * display alarms before it, for any calendar (Outlook, Google Calendar, Apple Calendar, Thunderbird).
 *
 * - Lines end with CRLF and are folded at 75 octets of UTF-8 (a continuation line starts with one
 *   space; a character is never split), RFC 5545 §3.1.
 * - TEXT values escape backslash, semicolon, comma and line breaks (§3.3.11).
 * - Each event has a stable UID from the caller (one per domain), so importing a newer file
 *   updates the event instead of adding a second one, and a SEQUENCE that grows with the date
 *   (a renewal moves the expiry later: calendars take the later revision).
 * - DTSTAMP is the time the file was made (injected: `now`), the only part that differs between
 *   two files of the same dates.
 *
 * Pure: no DOM, network or clock of its own. Runs in browsers and Node 22.
 */

/** Folding width in octets (RFC 5545 §3.1: lines SHOULD NOT be longer than 75 octets). */
export const ICS_FOLD_OCTETS = 75;
/** Alarms of every event, in days before it. */
export const ICS_ALARM_DAYS = Object.freeze([30, 7]);
/** The PRODID of the files this module writes. */
export const ICS_PRODID = '-//DomainScope//Domain portfolio//EN';

const DAY_MS = 86400000;
const encoder = new TextEncoder();

/**
 * Escape a TEXT value (RFC 5545 §3.3.11): `\` → `\\`, `;` → `\;`, `,` → `\,`, a line break → `\n`;
 * other control characters are dropped.
 * @param {unknown} value
 * @returns {string}
 */
export function icsEscape(value) {
  return String(value ?? '')
    .replace(/\r\n?/g, '\n')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '')
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\n/g, '\\n');
}

/**
 * Fold one content line: at most {@link ICS_FOLD_OCTETS} octets per physical line (the leading
 * space of a continuation counts), never inside a UTF-8 character, joined with CRLF + space.
 * @param {string} line without a line break
 * @returns {string}
 */
export function foldIcsLine(line) {
  const chars = [...String(line)];
  const out = [];
  let cur = '';
  let octets = 0;
  let limit = ICS_FOLD_OCTETS;
  for (const ch of chars) {
    const n = encoder.encode(ch).length;
    if (octets + n > limit) {
      out.push(cur);
      cur = ' ';
      octets = 1;
      limit = ICS_FOLD_OCTETS;
    }
    cur += ch;
    octets += n;
  }
  out.push(cur);
  return out.join('\r\n');
}

/** 'YYYYMMDD' of a date (UTC). */
function icsDate(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

/** 'YYYYMMDDTHHMMSSZ' (UTC). */
function icsDateTime(d) {
  return `${d.toISOString().slice(0, 19).replace(/[-:]/g, '')}Z`;
}

/** The day (UTC) of a date as a Date at 00:00 UTC, or null. */
function dayOf(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}

/** A UID as RFC 5545 takes it: printable ASCII without spaces (anything else becomes '-'). */
function cleanUid(uid) {
  return String(uid ?? '').replace(/[^\x21-\x7e]/g, '-').slice(0, 200) || 'event@domainscope';
}

/**
 * An iCalendar file with one all-day event per entry, each with a display alarm
 * {@link ICS_ALARM_DAYS} days before it (only those still ahead of `now` mean anything, but every
 * event carries both, so a calendar shows the same reminders however late it is imported).
 * @param {Array<{ uid: string, date: Date|string, summary: string, description?: string, alarm?: string }>} events
 *   `uid`: stable per subject (lib/portfolio.js: one per domain); `alarm`: the reminders' text (default `summary`)
 * @param {{ now?: Date, name?: string|null, prodId?: string }} [opts] `name`: X-WR-CALNAME, the calendar's name on import
 * @returns {string} CRLF line endings, folded, ending with CRLF
 */
export function buildCalendar(events, { now = new Date(), name = null, prodId = ICS_PRODID } = {}) {
  const stamp = icsDateTime(now instanceof Date ? now : new Date(now));
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:${prodId}`, 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH'];
  if (name) lines.push(`X-WR-CALNAME:${icsEscape(name)}`);
  for (const e of events || []) {
    const day = dayOf(e && e.date);
    if (!day) continue;
    const next = new Date(day.getTime() + DAY_MS);
    lines.push(
      'BEGIN:VEVENT',
      `UID:${cleanUid(e.uid)}`,
      `DTSTAMP:${stamp}`,
      // a later expiry (a renewal) is a later revision of the same event
      `SEQUENCE:${Math.max(0, Math.floor(day.getTime() / DAY_MS) - 10957)}`,
      `DTSTART;VALUE=DATE:${icsDate(day)}`,
      `DTEND;VALUE=DATE:${icsDate(next)}`,
      `SUMMARY:${icsEscape(e.summary)}`,
      ...(e.description ? [`DESCRIPTION:${icsEscape(e.description)}`] : []),
      'TRANSP:TRANSPARENT'
    );
    for (const days of ICS_ALARM_DAYS) {
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', `TRIGGER:-P${days}D`, `DESCRIPTION:${icsEscape(e.alarm || e.summary)}`, 'END:VALARM');
    }
    lines.push('END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return `${lines.map(foldIcsLine).join('\r\n')}\r\n`;
}
