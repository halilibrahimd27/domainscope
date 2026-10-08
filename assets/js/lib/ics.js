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
 * - The event's day is the expiry's local day, the one the table shows (in the browser: the
 *   user's time zone); no METHOD (a METHOD:PUBLISH object would need an ORGANIZER, RFC 5546).
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

/** 'YYYYMMDD' of a day (its local date parts: see {@link dayOf}). */
function icsDate(d) {
  return `${String(d.getFullYear()).padStart(4, '0')}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
}

/** 'YYYYMMDDTHHMMSSZ' (UTC). */
function icsDateTime(d) {
  return `${d.toISOString().slice(0, 19).replace(/[-:]/g, '')}Z`;
}

/**
 * The calendar day of an event as a local midnight, or null: a Date (an expiry with its time) gives
 * its local day — the day the table shows, in the time zone the file is made in —, a 'YYYY-MM-DD'
 * value is that day as written.
 */
function dayOf(value) {
  const ymd = typeof value === 'string' ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim()) : null;
  if (ymd) return new Date(Number(ymd[1]), Number(ymd[2]) - 1, Number(ymd[3]));
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

/** Days since 2000-01-01 of a local day (whole, whatever daylight saving does to its length). */
function dayNumber(day) {
  return Math.round((Date.UTC(day.getFullYear(), day.getMonth(), day.getDate()) - Date.UTC(2000, 0, 1)) / DAY_MS);
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
 * @param {{ now?: Date, name?: string|null, prodId?: string, alarmDays?: ReadonlyArray<number> }} [opts] `name`:
 *   X-WR-CALNAME, the calendar's name on import; `alarmDays`: the reminders, in whole days before
 *   the event (default {@link ICS_ALARM_DAYS}; the CT watch passes its radar's thresholds)
 * @returns {string} CRLF line endings, folded, ending with CRLF
 */
export function buildCalendar(events, { now = new Date(), name = null, prodId = ICS_PRODID, alarmDays = ICS_ALARM_DAYS } = {}) {
  const alarms = [...new Set((alarmDays || []).filter((d) => Number.isInteger(d) && d >= 0))];
  const stamp = icsDateTime(now instanceof Date ? now : new Date(now));
  // No METHOD: a METHOD:PUBLISH object must carry an ORGANIZER (RFC 5546 §3.2.1); a plain calendar file needs neither.
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:${prodId}`, 'CALSCALE:GREGORIAN'];
  if (name) lines.push(`X-WR-CALNAME:${icsEscape(name)}`);
  for (const e of events || []) {
    const day = dayOf(e && e.date);
    if (!day) continue;
    const next = new Date(day.getFullYear(), day.getMonth(), day.getDate() + 1);
    lines.push(
      'BEGIN:VEVENT',
      `UID:${cleanUid(e.uid)}`,
      `DTSTAMP:${stamp}`,
      // a later expiry (a renewal) is a later revision of the same event
      `SEQUENCE:${Math.max(0, dayNumber(day))}`,
      `DTSTART;VALUE=DATE:${icsDate(day)}`,
      `DTEND;VALUE=DATE:${icsDate(next)}`,
      `SUMMARY:${icsEscape(e.summary)}`,
      ...(e.description ? [`DESCRIPTION:${icsEscape(e.description)}`] : []),
      'TRANSP:TRANSPARENT'
    );
    for (const days of alarms) {
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', `TRIGGER:-P${days}D`, `DESCRIPTION:${icsEscape(e.alarm || e.summary)}`, 'END:VALARM');
    }
    lines.push('END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return `${lines.map(foldIcsLine).join('\r\n')}\r\n`;
}

/** How long a timed event lasts unless it says otherwise, in minutes. */
export const ICS_EVENT_MINUTES = 15;
/** The reminders of a timed event unless the caller picks others, in minutes before it. */
export const ICS_ALARM_MINUTES = Object.freeze([15]);
/** 2000-01-01T00:00Z: the epoch of a timed calendar's SEQUENCE (minutes since then). */
const SEQUENCE_EPOCH = Date.UTC(2000, 0, 1);

/** A Date of a time given as a Date, a number (ms epoch) or a parsable string; null when unusable. */
function timeOf(value) {
  const d = value instanceof Date ? value : (typeof value === 'number' || typeof value === 'string' ? new Date(value) : null);
  return d && Number.isFinite(d.getTime()) ? d : null;
}

/**
 * An iCalendar file of timed events (the steps of a DNS cutover): each starts at its time, in UTC
 * (`DTSTART:…Z`, the same moment in every calendar's time zone), lasts `minutes` (or until its own
 * later `end`) and carries a display alarm `alarmMinutes` before it. SEQUENCE is the minutes from
 * 2000-01-01 to `now`: a file made later is a later revision of the same UIDs, so importing a
 * changed plan moves its events instead of adding new ones. No METHOD (see {@link buildCalendar}).
 * @param {Array<{ uid: string, start: Date|number|string, end?: Date|number|string, summary: string, description?: string, alarm?: string,
 *   alarmMinutes?: number[] }>} events `alarmMinutes`: the event's own reminders instead of the file's ([] for none)
 * @param {{ now?: Date|number, name?: string|null, prodId?: string, minutes?: number, alarmMinutes?: ReadonlyArray<number> }} [opts]
 * @returns {string} CRLF line endings, folded, ending with CRLF
 */
export function buildEventCalendar(events, { now = new Date(), name = null, prodId = ICS_PRODID, minutes = ICS_EVENT_MINUTES, alarmMinutes = ICS_ALARM_MINUTES } = {}) {
  const made = timeOf(now) || new Date();
  const stamp = icsDateTime(made);
  const sequence = Math.max(0, Math.floor((made.getTime() - SEQUENCE_EPOCH) / 60000));
  const length = Number.isFinite(minutes) && minutes > 0 ? Math.round(minutes) : ICS_EVENT_MINUTES;
  const alarms = [...new Set((alarmMinutes || []).filter((m) => Number.isInteger(m) && m >= 0))];
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:${prodId}`, 'CALSCALE:GREGORIAN'];
  if (name) lines.push(`X-WR-CALNAME:${icsEscape(name)}`);
  for (const e of events || []) {
    const start = timeOf(e && e.start);
    if (!start) continue;
    const ownEnd = timeOf(e.end);
    const end = ownEnd && ownEnd > start ? ownEnd : new Date(start.getTime() + length * 60000);
    lines.push(
      'BEGIN:VEVENT',
      `UID:${cleanUid(e.uid)}`,
      `DTSTAMP:${stamp}`,
      `SEQUENCE:${sequence}`,
      `DTSTART:${icsDateTime(start)}`,
      `DTEND:${icsDateTime(end)}`,
      `SUMMARY:${icsEscape(e.summary)}`,
      ...(e.description ? [`DESCRIPTION:${icsEscape(e.description)}`] : []),
      'TRANSP:TRANSPARENT'
    );
    const own = Array.isArray(e.alarmMinutes) ? [...new Set(e.alarmMinutes.filter((m) => Number.isInteger(m) && m >= 0))] : alarms;
    for (const m of own) {
      lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', `TRIGGER:-PT${m}M`, `DESCRIPTION:${icsEscape(e.alarm || e.summary)}`, 'END:VALARM');
    }
    lines.push('END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return `${lines.map(foldIcsLine).join('\r\n')}\r\n`;
}
