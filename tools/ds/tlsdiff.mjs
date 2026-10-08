/**
 * tools/ds/tlsdiff.mjs — "Changes since the baseline" of the runner's `tls` (tools/ds/tls.mjs), and
 * what a `tls` baseline must hold. Pure: no I/O. tools/ds/diff.mjs dispatches here.
 *
 * Per target (a host and port, or an address), per endpoint (address and port):
 * - NEW / GONE: a target checked now and not then, or the reverse (counted); an address new to a
 *   name or gone from it is listed only (DNS rotates the addresses of a CDN or a pool);
 * - FAILED / RECOVERED / FAILING: a handshake that stopped completing (counted), completes again
 *   (its tone is the new status's), or moved between two failures (listed only); SKIPPED (no IPv6
 *   route) is never a change;
 * - WORSE / BETTER: OK, NAME_MISMATCH, UNTRUSTED, EXPIRED, worst last;
 * - CERT: another certificate served — listed only when it renews the last one (the same CA, key
 *   type and every name kept), counted when it drops a name, changes the key type or the CA;
 * - a host whose DNS lookup failed is listed once (FAILED, not counted: nothing was compared) and
 *   the next run is compared with the endpoints it carried; NXDOMAIN (the name went) is GONE, counted.
 * Per certificate (ARI with --ari, the CRL with --revocation), counted, tone bad:
 * - RENEW-NOW: the CA's ARI window has opened (or ended, the renewal overdue) since the last check
 *   of that certificate, or a certificate first seen in its window;
 * - MOVED-UP: its window starts more than {@link MOVED_UP_MS} earlier than the last answer said — a CA
 *   does that before a mass revocation;
 * - CA-NOTICE: an explanationURL the target's last answers did not carry;
 * - REVOKED: its CRL lists it now, and did not at the last check (or it is new).
 * The research notes named MOVED-UP and CA-NOTICE "WINDOW-MOVED" and "EXPLANATION"; the tags keep to
 * the nine characters of the CLI's change column.
 */

import { code, isoDay } from './render.mjs';
import { windowState } from './ari.mjs';

/** The endpoint statuses of `tls`: a certificate was read (the first four), or none. */
export const TLS_STATUSES = Object.freeze(['OK', 'EXPIRED', 'UNTRUSTED', 'NAME_MISMATCH', 'TLS_ERROR', 'TIMEOUT', 'CLOSED', 'SKIPPED']);
/** Statuses with no certificate read: the handshake did not complete. */
export const TLS_FAILED = Object.freeze(['TLS_ERROR', 'TIMEOUT', 'CLOSED']);
/** A window start this much earlier than the last answer's is MOVED-UP. */
export const MOVED_UP_MS = 24 * 3600000;
/** The statuses of a handshake that read a certificate, best first. */
const CERT_RANK = Object.freeze({ OK: 0, NAME_MISMATCH: 1, UNTRUSTED: 2, EXPIRED: 3 });
const STATE_RANK = Object.freeze({ before: 0, open: 1, past: 2 });

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isStrOrNull = (v) => v === null || v === undefined || typeof v === 'string';

/**
 * Why a `tls` baseline target is not what the comparison reads, or null.
 * @param {object} x
 * @returns {string|null}
 */
export function tlsTargetProblem(x) {
  if (!Array.isArray(x.endpoints)) return 'has no "endpoints" list';
  if (x.carried !== undefined && !(isObj(x.carried) && isStrOrNull(x.carried.from))) return 'has a "carried" without a "from"';
  for (const [i, e] of x.endpoints.entries()) {
    const where = `endpoints[${i}]`;
    if (!isObj(e)) return `${where} is not an object`;
    if (!isStr(e.address)) return `${where} has no "address"`;
    if (!Number.isInteger(e.port)) return `${where} has no "port"`;
    if (!isStr(e.status)) return `${where} has no "status"`;
    for (const [key, v] of [['cert', e.cert], ['lastGood', e.lastGood], ['ari', e.ari], ['revocation', e.revocation]]) {
      if (v !== undefined && v !== null && !isObj(v)) return `${where} has a "${key}" that is not an object`;
    }
    for (const c of [e.cert, e.lastGood && e.lastGood.cert]) {
      if (c && !isStr(c.sha256)) return `${where} has a certificate without "sha256"`;
      if (c && c.names !== undefined && !(Array.isArray(c.names) && c.names.every(isStr))) return `${where} has certificate names that are not a list of text`;
    }
    for (const a of [e.ari, e.lastGood && e.lastGood.ari]) {
      if (a && !(isStrOrNull(a.start) && isStrOrNull(a.end) && isStrOrNull(a.explanationURL) && isStrOrNull(a.checkedAt))) return `${where} has an "ari" whose times are not text`;
    }
    for (const r of [e.revocation, e.lastGood && e.lastGood.revocation]) {
      if (r && !isStr(r.status)) return `${where} has a "revocation" without "status"`;
    }
  }
  return null;
}

function change(tag, target, item, what, { tone = 'info', counts = true, kind = 'changed', before = null, after = null } = {}) {
  return { tag, tone, counts, target, item, kind, before, after, parts: [code(target), ': ', ...what] };
}

const key = (e) => `${e.address}|${e.port}`;
const where = (e) => (e.port === 443 || e.address.includes(':') ? e.address : `${e.address}:${e.port}`);
const shortSha = (sha) => String(sha || '').slice(0, 16);
/** The certificate an endpoint record stands for: this run's, else the last one it carried. */
const certOf = (e) => (e && e.cert) || (e && e.lastGood && e.lastGood.cert) || null;
/** The ARI and revocation records of an endpoint's certificate, read now or carried. */
const extrasOf = (e) => (e && e.cert ? { ari: e.ari || null, revocation: e.revocation || null } : { ari: (e && e.lastGood && e.lastGood.ari) || null, revocation: (e && e.lastGood && e.lastGood.revocation) || null });
const certLabel = (c) => [code(c.subject || shortSha(c.sha256)), ' (', code(c.ca || '?'), `, expires ${isoDay(c.notAfter)})`];

/** What another certificate on the same endpoint changed: [] for a renewal of the same kind. */
function certDifferences(a, b) {
  const out = [];
  const dropped = (b.names || []).filter((n) => !(a.names || []).includes(n));
  if (dropped.length) out.push(`no longer covers ${dropped.slice(0, 3).join(', ')}${dropped.length > 3 ? ` +${dropped.length - 3}` : ''}`);
  if (a.keyType !== b.keyType) out.push(`key type ${b.keyType} → ${a.keyType}`);
  if ((a.caId || a.ca) !== (b.caId || b.ca)) out.push(`CA ${b.ca} → ${a.ca}`);
  return out;
}

/** The time of a target's check (ms), else the report's start. */
const checkedMs = (x, doc) => Date.parse((x && x.checkedAt) || (doc && doc.startedAt) || '') || NaN;

/**
 * @param {object} before the baseline report
 * @param {object} after this run's report
 * @returns {object[]} changes (tools/ds/diff.mjs orders them)
 */
export function diffTls(before, after) {
  const out = [];
  const old = new Map((before.targets || []).map((x) => [x.target, x]));
  const now = new Map((after.targets || []).map((x) => [x.target, x]));
  for (const [target, a] of now) {
    const b = old.get(target);
    if (!b) {
      const ok = (a.endpoints || []).filter((e) => e.cert).length;
      out.push(change('NEW', target, null, [a.carried ? 'now checked (its DNS lookup failed this run)' : `now checked: ${ok} endpoint${ok === 1 ? '' : 's'} served a certificate`], { kind: 'appeared' }));
      continue;
    }
    if (a.carried) {
      // said once: the endpoints of the last check are carried, the next run is compared with them
      if (!b.carried) {
        out.push(change('FAILED', target, null, [`DNS lookup failed this run (${a.dns ? a.dns.status : '?'}): nothing compared; the next run compares with the last check`],
          { tone: 'quiet', counts: false }));
      }
      continue;
    }
    if (b.carried) {
      out.push(change('RECOVERED', target, null, [`DNS answered again; compared with the check of ${isoDay(b.carried.from) || 'an earlier run'}`], { tone: 'quiet', counts: false }));
    }
    const bDns = b.dns && b.dns.status;
    const aDns = a.dns && a.dns.status;
    if (aDns === 'NXDOMAIN' && bDns !== 'NXDOMAIN' && (b.endpoints || []).length) {
      out.push(change('GONE', target, null, ['the name no longer resolves (NXDOMAIN)'], { tone: 'bad', kind: 'disappeared', before: bDns, after: aDns }));
      continue;
    }
    out.push(...diffEndpoints(target, a, b));
    out.push(...diffCertificates(target, a, b, before, after));
  }
  for (const [target] of old) if (!now.has(target)) out.push(change('GONE', target, null, ['no longer checked'], { kind: 'disappeared' }));
  return out;
}

function diffEndpoints(target, a, b) {
  const out = [];
  const prev = new Map((b.endpoints || []).map((e) => [key(e), e]));
  const keys = new Set((a.endpoints || []).map(key));
  for (const e of a.endpoints || []) {
    const p = prev.get(key(e));
    if (e.status === 'SKIPPED') continue;
    if (!p) {
      out.push(change('NEW', target, key(e), ['new address ', code(where(e)), ` — ${e.status}`, ...(e.cert ? [', ', ...certLabel(e.cert)] : [])],
        { tone: 'quiet', counts: false, kind: 'appeared', after: e.status }));
      continue;
    }
    if (p.status === 'SKIPPED') continue;
    const ef = TLS_FAILED.includes(e.status);
    const pf = TLS_FAILED.includes(p.status);
    const at = [code(where(e)), ': '];
    if (ef && pf) {
      if (e.status !== p.status) out.push(change('FAILING', target, key(e), [...at, `${p.status} → ${e.status}${e.error ? ` (${e.error})` : ''}`], { tone: 'quiet', counts: false, before: p.status, after: e.status }));
      continue;
    }
    if (ef) {
      out.push(change('FAILED', target, key(e), [...at, `${p.status} → ${e.status}${e.error ? ` (${e.error})` : ''}`], { tone: 'bad', before: p.status, after: e.status }));
      continue;
    }
    if (pf) {
      const last = p.lastGood && p.lastGood.cert;
      const moved = last && last.sha256 !== e.cert.sha256 ? [', another certificate than before it failed: ', ...certLabel(e.cert)] : [];
      out.push(change('RECOVERED', target, key(e), [...at, `answers again: ${e.status}`, ...moved], { tone: e.status === 'OK' ? 'good' : 'bad', before: p.status, after: e.status }));
    } else if (e.status !== p.status) {
      const worse = (CERT_RANK[e.status] ?? 0) > (CERT_RANK[p.status] ?? 0);
      out.push(change(worse ? 'WORSE' : 'BETTER', target, key(e), [...at, `${p.status} → ${e.status}${e.trustError && worse ? ` (${e.trustError})` : ''}`],
        { tone: worse ? 'bad' : 'good', before: p.status, after: e.status }));
    }
    const pc = certOf(p);
    if (e.cert && pc && pc.sha256 !== e.cert.sha256) {
      const diffs = certDifferences(e.cert, pc);
      out.push(change('CERT', target, key(e), [...at, diffs.length ? 'another certificate: ' : 'renewed: ', ...certLabel(e.cert), ', was ', ...certLabel(pc),
        ...(diffs.length ? [` — ${diffs.join('; ')}`] : [])], { tone: diffs.length ? 'bad' : 'quiet', counts: diffs.length > 0, before: pc.sha256, after: e.cert.sha256 }));
    }
  }
  for (const p of b.endpoints || []) {
    if (keys.has(key(p)) || p.status === 'SKIPPED') continue;
    out.push(change('GONE', target, key(p), ['address ', code(where(p)), ' no longer answered by DNS'], { tone: 'quiet', counts: false, kind: 'disappeared', before: p.status }));
  }
  return out;
}

/** Every certificate a target's report knows, with its ARI and revocation: sha256 → { cert, ari, revocation }. */
function certificatesOf(x) {
  const out = new Map();
  for (const e of (x && x.endpoints) || []) {
    const c = certOf(e);
    if (!c || out.has(c.sha256)) continue;
    out.set(c.sha256, { cert: c, ...extrasOf(e) });
  }
  return out;
}

function diffCertificates(target, a, b, before, after) {
  const out = [];
  const prev = certificatesOf(b);
  const at = checkedMs(a, after);
  const prevExplanations = new Set();
  let prevRead = false;
  for (const { ari } of prev.values()) {
    if (ari && !ari.error) {
      prevRead = true;
      if (ari.explanationURL) prevExplanations.add(ari.explanationURL);
    }
  }
  // this run's certificates only: what the endpoints serve now
  const current = new Map();
  for (const e of a.endpoints || []) if (e.cert && !current.has(e.cert.sha256)) current.set(e.cert.sha256, { cert: e.cert, ari: e.ari || null, revocation: e.revocation || null });
  for (const [sha, x] of current) {
    const p = prev.get(sha) || null;
    const label = certLabel(x.cert);
    const ari = x.ari && !x.ari.error ? x.ari : null;
    const pAri = p && p.ari && !p.ari.error ? p.ari : null;
    if (ari) {
      const state = windowState(ari, at);
      const pState = pAri ? windowState(pAri, Date.parse(pAri.checkedAt) || checkedMs(b, before)) : null;
      if ((state === 'open' || state === 'past') && STATE_RANK[state] > (pState === null ? -1 : STATE_RANK[pState])) {
        out.push(change('RENEW-NOW', target, sha, [...label, state === 'open'
          ? `: the CA's renewal window opened (${isoDay(ari.start)} – ${isoDay(ari.end)}): renew it now`
          : `: the CA's renewal window ended on ${isoDay(ari.end)}: the renewal is overdue`], { tone: 'bad', after: state }));
      }
      if (pAri && Date.parse(ari.start) < Date.parse(pAri.start) - MOVED_UP_MS) {
        const ahead = Math.round((Date.parse(pAri.start) - Date.parse(ari.start)) / 86400000);
        out.push(change('MOVED-UP', target, sha, [...label, `: the CA moved its renewal window ${ahead} day${ahead === 1 ? '' : 's'} earlier (starts ${isoDay(ari.start)}, was ${isoDay(pAri.start)}), as CAs do before a mass revocation`],
          { tone: 'bad', before: pAri.start, after: ari.start }));
      }
      if (ari.explanationURL && prevRead && !prevExplanations.has(ari.explanationURL)) {
        out.push(change('CA-NOTICE', target, sha, [...label, ': the CA explains its renewal window: ', code(ari.explanationURL)], { tone: 'bad', after: ari.explanationURL }));
      }
    }
    const rev = x.revocation;
    if (rev && rev.status === 'revoked' && !(p && p.revocation && p.revocation.status === 'revoked')) {
      out.push(change('REVOKED', target, sha, [...label, `: revoked by its CA on ${isoDay(rev.time) || '?'} (${rev.reason || 'no reason given'}), still served`],
        { tone: 'bad', before: p && p.revocation ? p.revocation.status : null, after: 'revoked' }));
    }
  }
  return out;
}

/**
 * What two `tls` runs did differently.
 * @param {object} o the baseline's options
 * @param {object} n this run's
 * @returns {string[]}
 */
export function tlsNotes(o, n) {
  const notes = [];
  if (o.ari !== undefined && !!o.ari !== !!n.ari) notes.push(`ARI was asked in ${n.ari ? 'this run only' : 'the baseline run only'} (--ari): RENEW-NOW, MOVED-UP and CA-NOTICE compare runs that both asked it.`);
  if (o.revocation !== undefined && !!o.revocation !== !!n.revocation) notes.push(`Revocation was checked in ${n.revocation ? 'this run only' : 'the baseline run only'} (--revocation).`);
  return notes;
}
