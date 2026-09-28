/**
 * ctrelated.js — other registrable domains that share certificates with the scanned domain's
 * hosts (Subdomains › Sources › Related domains).
 *
 * A certificate names every host it is for; one issued for `shop.example.com` and
 * `shop.example.net` says the two belong together, and a forgotten brand or campaign domain often
 * only shows up that way. The certificates are the ones the scan's Certificate Transparency
 * sources already fetched (lib/sources.js CtCert `names`): nothing is asked again.
 *
 * What the sources give differs, and the result says so:
 * - Cert Spotter's `dns_names` is the certificate's whole name list;
 * - crt.sh's `name_value` lists only the names that matched the search, plus the certificate's
 *   common name (probed 2026-09-28: a 41-name certificate came back with its 3 matching names and
 *   a common name under another domain). A certificate only crt.sh reported therefore adds at
 *   most its common name, and one both sources reported is counted once (same validity, crt.sh's
 *   names a subset of Cert Spotter's).
 * A certificate with names under more than {@link SHARED_CERT_DOMAINS} registrable domains is a
 * shared one — a CDN's or a host's multi-customer certificate — and says nothing about ownership:
 * a domain seen only in such certificates is marked `sharedOnly` and listed after the others.
 *
 * DOM-free, no I/O.
 */

import { registrableDomain, isSubdomainOf, stripWildcard, sortHostnames } from './domain.js';
import { matchProviderByCname } from './netinfo.js';

/** More registrable domains than this in one certificate: a shared (multi-customer) certificate. */
export const SHARED_CERT_DOMAINS = 12;
/** Host names kept per related domain (the rest are counted). */
export const RELATED_NAME_CAP = 12;
/** Certificates kept per related domain, newest first (the rest are counted). */
export const RELATED_CERT_CAP = 10;
/** Related domains returned at most (the rest are counted in `more`). */
export const RELATED_MAX = 200;

/**
 * @typedef {object} RelatedCert a certificate a related domain shares with the scanned domain
 * @property {string} key the source's de-duplication key
 * @property {string[]} sources
 * @property {string} issuer
 * @property {Date|null} notBefore
 * @property {Date|null} notAfter
 * @property {string|null} url crt.sh page (by id, or by SHA-256 for a Cert Spotter issuance)
 * @property {string[]} ownNames names under the scanned domains it carries
 * @property {number} domains registrable domains it names (the scanned ones included)
 * @property {boolean} shared more than {@link SHARED_CERT_DOMAINS} of them
 * @property {boolean} partial only crt.sh reported it: its name list is not complete
 */

/**
 * @typedef {object} RelatedDomain
 * @property {string} domain the registrable domain
 * @property {number} certs certificates it shares with the scanned domain
 * @property {string[]} names its host names in them (wildcards as `*.x`), at most {@link RELATED_NAME_CAP}
 * @property {number} moreNames names left out
 * @property {RelatedCert[]} certificates newest first, at most {@link RELATED_CERT_CAP}
 * @property {Date|null} latest the newest notBefore
 * @property {boolean} current one of the certificates is valid at `now`
 * @property {boolean} sharedOnly every certificate is a shared one
 * @property {string|null} platform a hosting / CDN platform's domain (lib/netinfo.js provider name), not a brand
 */

/** Same moment (or both unknown). */
const sameTime = (a, b) => (a instanceof Date ? a.getTime() : null) === (b instanceof Date ? b.getTime() : null);

/**
 * The certificates of a scan, once each: exact keys folded, and a crt.sh certificate folded into
 * the Cert Spotter issuance with the same validity whose names include all of its own.
 * @param {object[]} certs lib/sources.js CtCert objects (a scan's SourceResult `certs`, merged or not)
 * @returns {Array<object & { complete: boolean }>} complete: its name list is the certificate's whole one
 */
export function uniqueCerts(certs) {
  const byKey = new Map();
  for (const c of Array.isArray(certs) ? certs : []) {
    if (!c || typeof c !== 'object' || !Array.isArray(c.names)) continue;
    const key = typeof c.key === 'string' ? c.key : `${c.source}:${c.id}`;
    const prev = byKey.get(key);
    const sources = Array.isArray(c.sources) ? c.sources : [c.source].filter(Boolean);
    if (prev) {
      for (const s of sources) if (!prev.sources.includes(s)) prev.sources.push(s);
      for (const n of c.names) if (!prev.names.includes(n)) prev.names.push(n);
      prev.complete = prev.complete || sources.includes('certspotter');
      continue;
    }
    byKey.set(key, { ...c, key, names: [...c.names], sources: [...sources], complete: sources.includes('certspotter') });
  }
  const complete = [...byKey.values()].filter((c) => c.complete);
  const out = [];
  for (const c of byKey.values()) {
    if (!c.complete) {
      const twin = complete.find((o) => sameTime(o.notBefore, c.notBefore) && sameTime(o.notAfter, c.notAfter)
        && c.names.every((n) => o.names.includes(n)));
      if (twin) {
        for (const s of c.sources) if (!twin.sources.includes(s)) twin.sources.push(s);
        if (!twin.url && c.url) twin.url = c.url;
        continue;
      }
    }
    out.push(c);
  }
  return out;
}

/** crt.sh link of a certificate: its own page, or a search by SHA-256. */
function certUrl(c) {
  if (typeof c.url === 'string' && c.url) return c.url;
  if (typeof c.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(c.sha256)) return `https://crt.sh/?sha256=${c.sha256.toLowerCase()}`;
  return null;
}

/**
 * Registrable domains that appear in the same certificates as the scanned domains' hosts.
 * @param {object[]} certs lib/sources.js CtCert objects of the scan (both sources, any order)
 * @param {{ domains: string[], now?: Date|number }} opts domains: the scanned domains (a scope such
 *   as `shop.example.com` counts its registrable domain as its own)
 * @returns {{ related: RelatedDomain[], more: number, certs: number, withOthers: number, partial: number,
 *   shared: number }} certs: certificates read; withOthers: those naming another registrable domain;
 *   partial: certificates only crt.sh reported (their other names may be missing); shared: shared ones
 */
export function relatedDomains(certs, { domains = [], now = Date.now() } = {}) {
  const at = now instanceof Date ? now.getTime() : Number(now);
  const own = new Set();
  const scopes = [];
  for (const d of Array.isArray(domains) ? domains : []) {
    const base = stripWildcard(String(d || '').toLowerCase()).base;
    if (!base) continue;
    scopes.push(base);
    const reg = registrableDomain(base);
    if (reg) own.add(reg);
  }
  const inScope = (name) => scopes.some((s) => isSubdomainOf(name, s));
  const list = uniqueCerts(certs);
  const byDomain = new Map();
  let withOthers = 0;
  let partial = 0;
  let shared = 0;
  let read = 0;
  for (const c of list) {
    const bases = c.names.map((n) => stripWildcard(n).base).filter(Boolean);
    const ownNames = c.names.filter((n) => inScope(stripWildcard(n).base));
    if (!ownNames.length) continue; // not a certificate of the scanned hosts
    read += 1;
    if (!c.complete) partial += 1;
    const regs = new Map();
    for (const [i, base] of bases.entries()) {
      const reg = registrableDomain(base);
      if (!reg) continue;
      if (!regs.has(reg)) regs.set(reg, []);
      regs.get(reg).push(c.names[i]);
    }
    const foreign = [...regs.keys()].filter((r) => !own.has(r));
    if (!foreign.length) continue;
    withOthers += 1;
    const isShared = regs.size > SHARED_CERT_DOMAINS;
    if (isShared) shared += 1;
    const entry = {
      key: c.key,
      sources: [...c.sources],
      issuer: String(c.issuerFriendlyName || c.issuer || ''),
      notBefore: c.notBefore instanceof Date ? c.notBefore : null,
      notAfter: c.notAfter instanceof Date ? c.notAfter : null,
      url: certUrl(c),
      ownNames: sortHostnames(ownNames),
      domains: regs.size,
      shared: isShared,
      partial: !c.complete
    };
    for (const reg of foreign) {
      let d = byDomain.get(reg);
      if (!d) {
        d = { domain: reg, names: new Set(), certs: [] };
        byDomain.set(reg, d);
      }
      for (const n of regs.get(reg)) d.names.add(n);
      d.certs.push(entry);
    }
  }
  const time = (d) => (d instanceof Date ? d.getTime() : -Infinity);
  const related = [...byDomain.values()].map((d) => {
    const names = sortHostnames([...d.names]);
    const certsSorted = d.certs.sort((a, b) => time(b.notBefore) - time(a.notBefore) || (a.key < b.key ? -1 : 1));
    const provider = matchProviderByCname(d.domain) || names.map((n) => matchProviderByCname(stripWildcard(n).base)).find(Boolean) || null;
    return {
      domain: d.domain,
      certs: certsSorted.length,
      names: names.slice(0, RELATED_NAME_CAP),
      moreNames: Math.max(0, names.length - RELATED_NAME_CAP),
      certificates: certsSorted.slice(0, RELATED_CERT_CAP),
      latest: certsSorted.length && certsSorted[0].notBefore ? certsSorted[0].notBefore : null,
      current: certsSorted.some((c) => c.notBefore && c.notAfter && c.notBefore.getTime() <= at && c.notAfter.getTime() >= at),
      sharedOnly: certsSorted.every((c) => c.shared),
      platform: provider ? provider.name : null
    };
  }).sort((a, b) => Number(a.sharedOnly) - Number(b.sharedOnly) || Number(!!a.platform) - Number(!!b.platform)
    || b.certs - a.certs || time(b.latest) - time(a.latest) || (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0));
  return {
    related: related.slice(0, RELATED_MAX),
    more: Math.max(0, related.length - RELATED_MAX),
    certs: read,
    withOthers,
    partial,
    shared
  };
}
