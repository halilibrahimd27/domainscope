/**
 * tools/ds/tlsct.mjs — `tls --ct FILE`: the served certificates compared with the same night's
 * `ct` report (tools/ds/commands.mjs ctTarget), with no Certificate Transparency query of its own.
 * Pure: no I/O (tools/ds/tls.mjs reads the file).
 *
 * An address still serves an older certificate than the renewal CT logged for its name — the
 * renewal was issued but not installed there — when the newest current certificate of the report
 * that covers the host (exactly or by a wildcard) and carries every name the served one carries
 * under that domain was issued more than {@link NOT_DEPLOYED_MS} after it (notBefore). Asking for
 * every served name keeps a CDN's edge certificate and the origin's own one apart (they rarely
 * carry the same names), and a certificate for other names is no renewal of this one. The 48 hours
 * leave a deploy hook its time. A certificate CT lists as revoked, not yet valid or expired at the
 * run's time is never "the newer one".
 */

import { DS_TOOL, DS_VERSION } from './args.mjs';
import { certCovers, isSubdomainOf, normalizeHostname } from '../../assets/js/lib/domain.js';

/** A certificate issued this much later than the one served is a renewal not installed yet. */
export const NOT_DEPLOYED_MS = 48 * 3600000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const time = (v) => (isStr(v) ? Date.parse(v) : NaN);
const lower = (n) => String(n).toLowerCase().replace(/\.$/, '');

/**
 * Why `doc` is not a `ct` --json report of this runner that `tls --ct` can read, or null.
 * @param {any} doc parsed JSON
 * @returns {string|null}
 */
export function ctReportProblem(doc) {
  if (!isObj(doc) || doc.tool !== DS_TOOL) return `it is not a --json report of ${DS_TOOL}`;
  if (!isStr(doc.version) || doc.version.split('.')[0] !== DS_VERSION.split('.')[0]) return `it was written by version ${JSON.stringify(doc.version ?? null)}`;
  if (doc.command !== 'ct') return `it is a report of "${doc.command}", not of "ct"`;
  if (!Array.isArray(doc.targets)) return 'it has no "targets" list';
  for (const [i, x] of doc.targets.entries()) {
    if (!isObj(x) || !isStr(x.target)) return `targets[${i}] has no "target"`;
    if (!Array.isArray(x.certificates)) return `targets[${i}] has no "certificates" list`;
  }
  return null;
}

/**
 * What `tls` keeps of a `ct` report: its domains with their certificates (the fields compared),
 * and when it was written.
 * @param {object} doc a report that passed {@link ctReportProblem}
 * @param {string|null} [file] its base name, for the report's options
 * @returns {{ file: string|null, finishedAt: string|null, domains: Array<{ domain: string, certificates: object[] }> }}
 */
export function ctLookup(doc, file = null) {
  const domains = [];
  for (const x of doc.targets) {
    const domain = normalizeHostname(x.target);
    if (!domain) continue;
    const certificates = x.certificates.filter((c) => isObj(c) && Array.isArray(c.names) && Number.isFinite(time(c.notBefore)) && Number.isFinite(time(c.notAfter)))
      .map((c) => ({
        id: isStr(c.id) ? c.id : null,
        ca: isStr(c.ca) ? c.ca : null,
        intermediate: isStr(c.intermediate) ? c.intermediate : null,
        notBefore: c.notBefore,
        notAfter: c.notAfter,
        serialHex: isStr(c.serialHex) ? c.serialHex : null,
        names: c.names.filter(isStr).map(lower),
        revoked: c.revoked === true
      }));
    domains.push({ domain, certificates });
  }
  return { file, finishedAt: isStr(doc.finishedAt) ? doc.finishedAt : null, domains };
}

/** The domains of a lookup a host is in (the host itself, or a parent of it). */
const domainsOf = (lookup, host) => lookup.domains.filter((d) => d.domain === host || isSubdomainOf(host, d.domain));

/** A CT certificate current at `at` (ms): valid, not revoked. */
const current = (c, at) => !c.revoked && time(c.notBefore) <= at && at < time(c.notAfter);

/** A certificate record of the report, as `tls` keeps it (`newer`, `ct.newest`). */
const record = (c) => ({ id: c.id, ca: c.ca, intermediate: c.intermediate, notBefore: c.notBefore, notAfter: c.notAfter, serialHex: c.serialHex });

/**
 * The newest certificate the report lists for `host` that is current at `at`, or null: what CT
 * says the name should be served with (the summary's line).
 * @param {ReturnType<typeof ctLookup>} lookup
 * @param {string} host
 * @param {number} at the run's time (ms)
 * @returns {object|null}
 */
export function newestInCt(lookup, host, at) {
  let best = null;
  for (const d of domainsOf(lookup, lower(host))) {
    for (const c of d.certificates) {
      if (!current(c, at) || !certCovers(c.names, host).covered) continue;
      if (!best || time(c.notBefore) > time(best.notBefore)) best = c;
    }
  }
  return best ? record(best) : null;
}

/**
 * The renewal CT logged that the address does not serve: the newest current certificate of the
 * report that covers `host`, carries every name of the served certificate under its domain and
 * was issued more than {@link NOT_DEPLOYED_MS} after it. Null when there is none (or no host).
 * @param {ReturnType<typeof ctLookup>} lookup
 * @param {string|null} host the SNI asked (null for an address target)
 * @param {{ notBefore: string, names: string[] }} served the endpoint's `cert`
 * @param {number} at the run's time (ms)
 * @returns {object|null}
 */
export function renewalNotDeployed(lookup, host, served, at) {
  if (!host || !served || !Number.isFinite(time(served.notBefore))) return null;
  const servedNames = (Array.isArray(served.names) ? served.names : []).map(lower);
  const after = time(served.notBefore) + NOT_DEPLOYED_MS;
  let best = null;
  for (const d of domainsOf(lookup, lower(host))) {
    const own = servedNames.filter((n) => {
      const bare = n.replace(/^\*\./, '');
      return bare === d.domain || isSubdomainOf(bare, d.domain);
    });
    for (const c of d.certificates) {
      if (!current(c, at) || time(c.notBefore) <= after || !certCovers(c.names, host).covered) continue;
      if (!own.every((n) => c.names.includes(n))) continue;
      if (!best || time(c.notBefore) > time(best.notBefore)) best = c;
    }
  }
  return best ? record(best) : null;
}
