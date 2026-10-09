/**
 * tools/ds/ctwatch.mjs — the Domain portfolio's CT watch (Domain portfolio › Certificates (CT),
 * lib/ctwatch.js) in the runner's `ct` reports, so a nightly run raises what the app's tab shows.
 *
 * - Per certificate, the app's own analysis (lib/ctwatch.js analyzeCt) over the certificates a
 *   report holds (this run's read and what it carried): the newest of each name set (`current`),
 *   its days left and the radar threshold it is within, new since the last run, an unexpected CA
 *   (the `--expected-ca` entries, lib/expectedca.js), wildcard, precertificate only (Cert
 *   Spotter's DER says; crt.sh's rows do not), revoked and superseded.
 * - Per domain, the store of the certificates seen (`seen: { at, ids: { id: 'YYYY-MM-DD' } }`,
 *   lib/ctwatch.js updateSeen): the ids every run that read the domain listed, each with its expiry
 *   day, dropped once expired, with the time of the last read. The report keeps it as the app's
 *   workspace keeps its `ctSeen`, so the next run, given the report as `--baseline`, marks what was
 *   logged since — a certificate a source missed one night is not "new" the night after. A run
 *   that could not read the domain keeps the store as it was. A baseline written before the store
 *   stands in with the ids of its certificates.
 * - The radar crossings tools/ds/diff.mjs reports: a current certificate within a threshold it
 *   was outside at the last read, counted once an automatic renewal is overdue — less than a
 *   quarter of the certificate's lifetime left, as ACME clients and Let's Encrypt renew at a
 *   third: before that, a certificate that renews itself is no news.
 * Pure: no I/O.
 */

import { analyzeCt, updateSeen, radarBand, matchesCtFilter, CT_SEEN_VERSION } from '../../assets/js/lib/ctwatch.js';

const DAY_MS = 86400000;
const ID_RE = /^[0-9a-f]{16}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const isStr = (v) => typeof v === 'string';
const time = (v) => (isStr(v) ? Date.parse(v) : NaN);

/** The share of a certificate's lifetime left below which its automatic renewal is overdue. */
export const OVERDUE_SHARE = 0.25;

/** The fields {@link watchTarget} writes on a certificate (a carried one's are written again). */
const WATCH_FIELDS = ['daysLeft', 'current', 'isNew', 'unexpected', 'wildcard', 'flags', 'radar', 'known', 'knownExpired'];

/**
 * The store of certificate ids a baseline's target kept: its `seen` (each id with its expiry day,
 * when the domain was last read), else — a target written before the store — the ids of its
 * certificates, as of its read. Null when the baseline has no target of the domain or never read it.
 * @param {object|null} prev the baseline's target of the domain
 * @param {string|null} [prevAt] the baseline run's start, for a target without `readAt`
 * @returns {{ at: string, ids: Record<string, string> }|null}
 */
export function seenOf(prev, prevAt = null) {
  if (!prev || typeof prev !== 'object') return null;
  const s = prev.seen;
  if (s && typeof s === 'object' && Number.isFinite(time(s.at))) {
    const ids = {};
    for (const [id, day] of Object.entries(s.ids && typeof s.ids === 'object' ? s.ids : {})) {
      if (ID_RE.test(id) && isStr(day) && DAY_RE.test(day)) ids[id] = day;
    }
    return { at: new Date(time(s.at)).toISOString(), ids };
  }
  const certs = Array.isArray(prev.certificates) ? prev.certificates.filter((c) => c && ID_RE.test(String(c.id))) : [];
  const at = Number.isFinite(time(prev.readAt)) ? time(prev.readAt) : time(prevAt);
  if (!Number.isFinite(at) || (prev.answered === false && !certs.length)) return null;
  const ids = {};
  for (const c of certs) ids[c.id] = isStr(c.notAfter) ? c.notAfter.slice(0, 10) : '9999-12-31';
  return { at: new Date(at).toISOString(), ids };
}

/**
 * Whole days left (lib/ctwatch.js counts them so: rounded down) of a certificate expiring at
 * `notAfter`, at `at`.
 * @param {string} notAfter ISO
 * @param {number} at ms
 * @returns {number}
 */
export function daysLeftAt(notAfter, at) {
  return Math.floor((time(notAfter) - at) / DAY_MS);
}

/**
 * A quarter of a certificate's lifetime, in days ({@link OVERDUE_SHARE}): with fewer days left, an
 * automatic renewal — due at a third of the lifetime — is overdue (a 90-day certificate: 22.5, so a
 * radar's 14 and 7 days, not its 30, at which ACME clients renew). Infinity when the dates do not
 * say: every threshold then counts.
 * @param {{ notBefore: string, notAfter: string }} cert
 * @returns {number}
 */
export function overdueDays(cert) {
  const life = (time(cert.notAfter) - time(cert.notBefore)) / DAY_MS;
  return Number.isFinite(life) && life > 0 ? life * OVERDUE_SHARE : Infinity;
}

/**
 * The report's certificates with the CT watch's fields, the watch's counts and the store of the
 * ids seen: `daysLeft`, `current` (the newest valid certificate of its name set, not superseded),
 * `isNew` (not seen at the last run that read the domain; null when no run did), `unexpected` (null
 * without expected CAs), `wildcard`, `flags` (lib/ctwatch.js CT_WATCH_FLAGS) and, for a current one
 * within the radar, `radar` (the smallest threshold it is within); `revoked` and `precert` stay as
 * read (null: not known). A known certificate (`--waivers`, lib/waivers.js kind 'cert': its public
 * key's or its own SHA-256) carries its waiver (`known`) and is neither new nor unexpected; one whose
 * waiver is over carries that (`knownExpired`). A run that could not read the domain keeps the
 * store as it was.
 * @param {object} target a ct target (commands.mjs ctTarget, carried by carry.mjs carryCt)
 * @param {{ prev?: object|null, prevAt?: string|null, now: Date, radar: number[], expected?: string[], known?: object[] }} opts
 *   `prev`: the baseline's target of the domain; `radar`: largest first (lib/ctwatch.js parseRadarDays);
 *   `known`: lib/waivers.js waivers
 * @returns {object}
 */
export function watchTarget(target, { prev = null, prevAt = null, now, radar, expected = [], known = [] }) {
  const domain = target.target;
  const base = seenOf(prev, prevAt);
  const valid = (target.certificates || []).filter((c) => Number.isFinite(time(c.notBefore)) && Number.isFinite(time(c.notAfter)));
  const certs = valid.map((c) => ({
    ...c,
    domain,
    names: [...(c.names || [])],
    notBefore: new Date(time(c.notBefore)),
    notAfter: new Date(time(c.notAfter)),
    revoked: typeof c.revoked === 'boolean' ? c.revoked : null,
    precert: typeof c.precert === 'boolean' ? c.precert : null,
    wildcard: (c.names || []).some((n) => String(n).startsWith('*.'))
  }));
  const seen = { v: CT_SEEN_VERSION, domains: base ? { [domain]: base } : {} };
  const { rows } = analyzeCt([{ domain, state: 'ok', certs }], { now, days: radar, expected, seen, known });
  const byId = new Map(rows.map((r) => [r.id, r]));
  const waiverOf = (w) => ({ id: w.id, reason: w.reason || '', owner: w.owner || '', expires: w.expires });
  const certificates = (target.certificates || []).map((c) => {
    const r = byId.get(c.id);
    const rest = Object.fromEntries(Object.entries(c).filter(([k]) => !WATCH_FIELDS.includes(k)));
    if (!r) return rest;
    return {
      ...rest,
      revoked: r.revoked,
      precert: r.precert,
      wildcard: r.wildcard,
      daysLeft: r.daysLeft,
      current: r.current,
      isNew: r.isNew,
      unexpected: r.unexpected,
      flags: [...r.flags],
      ...(r.band !== null ? { radar: radar[r.band] } : {}),
      ...(r.known ? { known: waiverOf(r.known) } : {}),
      ...(r.knownExpired ? { knownExpired: waiverOf(r.knownExpired) } : {})
    };
  });
  const counts = {
    current: rows.filter((r) => r.current).length,
    expiring: rows.filter((r) => matchesCtFilter(r, 'expiring', { radar: radar[0] })).length,
    new: rows.filter((r) => r.isNew === true).length,
    unexpected: rows.filter((r) => r.unexpected === true).length,
    wildcard: rows.filter((r) => r.wildcard).length,
    precert: rows.filter((r) => r.precert === true).length,
    revoked: rows.filter((r) => r.revoked === true).length,
    ...(rows.some((r) => r.known) ? { known: rows.filter((r) => r.known).length } : {})
  };
  let next = base;
  if (target.answered && Number.isFinite(time(target.readAt))) {
    // The report's store stays { at, ids }: the `due` list the app's baseline gained (for Home) is the app's.
    const read = updateSeen(seen, [{ domain, state: 'ok', at: new Date(time(target.readAt)), certs }], { now }).domains[domain];
    next = read ? { at: read.at, ids: read.ids } : read;
  }
  return {
    ...target,
    certificates,
    watch: { radar: [...radar], expected: [...expected], comparedWith: base ? base.at : null, counts },
    ...(next ? { seen: next } : {})
  };
}

/**
 * A current certificate within a radar threshold it was outside at the last read of the domain
 * (`lastRead`): the smallest such threshold, by this run's radar, so a radar changed between two
 * runs moves nothing by itself. Only a certificate the baseline knew: a new one already within a
 * threshold (a short-lived certificate) has crossed nothing. `overdue`: the threshold is within a
 * quarter of its lifetime ({@link overdueDays}), so an automatic renewal is overdue (the crossing
 * counts).
 * @param {object} cert this run's certificate ({@link watchTarget}: `current`, `daysLeft`)
 * @param {object|undefined} known the baseline's certificate of the same id (anything truthy when
 *   only the baseline's store of the ids seen holds it)
 * @param {{ radar: number[], lastRead: number }} opts `lastRead`: ms
 * @returns {{ daysLeft: number, threshold: number, overdue: boolean }|null}
 */
export function radarCrossing(cert, known, { radar, lastRead }) {
  if (!cert || cert.current !== true || !known || !Array.isArray(radar) || !radar.length || !Number.isFinite(lastRead)) return null;
  const daysLeft = Number.isFinite(cert.daysLeft) ? cert.daysLeft : NaN;
  const band = radarBand(daysLeft, radar);
  if (band === null) return null;
  const before = radarBand(daysLeftAt(cert.notAfter, lastRead), radar);
  if (before !== null && before >= band) return null;
  const threshold = radar[band];
  return { daysLeft, threshold, overdue: threshold <= overdueDays(cert) };
}

/**
 * Has the certificate's automatic renewal fallen overdue ({@link overdueDays})?
 * @param {{ notBefore: string, notAfter: string, daysLeft?: number }} cert
 * @returns {boolean}
 */
export function renewalOverdue(cert) {
  return Number.isFinite(cert.daysLeft) && cert.daysLeft <= overdueDays(cert);
}
