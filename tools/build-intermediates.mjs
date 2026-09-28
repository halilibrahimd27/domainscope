#!/usr/bin/env node
/**
 * build-intermediates.mjs — the intermediate certificates and root lifecycle table behind
 * the Certificate view's missing-intermediate repair (assets/js/lib/chainfix.js).
 *
 * Maintainers and the weekly workflow (.github/workflows/intermediates.yml) run it; the site
 * never does. No dependencies (Node 22 stdlib, plus the app's own x509 parser, so the page reads
 * back exactly what the build wrote). It downloads public reports of the Common CA Database
 * (CCADB; none of them is readable from a browser: no CORS), keeps the intermediates a TLS server
 * certificate can chain through, and writes a sharded static dataset:
 *
 *   assets/data/intermediates/manifest.json   format, date, sources, licence, counts, shard layout
 *   assets/data/intermediates/ski/<xx>.json   subject key id → [{ owner, der }] (base64 DER), by its first 2 hex digits
 *   assets/data/intermediates/dn/<x>.json     DN hash (lib/chainfix.js dnHash) → [subject key id], by its first hex digit
 *   assets/data/intermediates/roots.json      the roots (store statuses from CCADB) and the lifecycle table:
 *                                             distrust-after dates (tools/root-lifecycle.json + Mozilla's
 *                                             from CCADB) and the roots that expire from January 1 of last
 *                                             year to December 31 of next year
 *
 * The intermediates come from two places. Mozilla's report lists the ones whose CCADB parent is a
 * root Mozilla includes for websites, with their PEM. It misses the hierarchies browsers reach
 * through a cross-signed root (Let's Encrypt's YE / YR issuers under Root YE / Root YR, Microsoft's
 * TLS G2 CAs) and the ones under a root only other stores keep. So the CCADB certificate records
 * add every intermediate that is TLS capable, trusted by at least one store (Apple, Chrome,
 * Microsoft or Mozilla), not revoked, unexpired and not in Mozilla's report, with its PEM from
 * CCADB's all-certificate PEM reports (one per notBefore year; only the years they need are read).
 *
 * Kept: CA certificates with a subject key id, valid on the build date, whose extended key usage
 * allows TLS server authentication (serverAuth, anyExtendedKeyUsage, or none). Nothing is written
 * when a download looks wrong: too few intermediates or roots, or a well-known current issuer
 * missing ({@link CANARIES}). The manifest's date moves only when the data or the manifest does,
 * so a rebuild with nothing new changes no file; the skipped counts go to the build log only.
 *
 * Usage:
 *   node tools/build-intermediates.mjs             # download (5 min at most each; a report with its columns is cached for 12 h), build, write
 *   node tools/build-intermediates.mjs --offline   # use the cached downloads only
 *   INTERMEDIATES_CACHE=/path node tools/build-intermediates.mjs
 *
 * Data: CCADB, under the Community Data License Agreement – Permissive 2.0 (CDLA-Permissive-2.0),
 * with attribution to the Common CA Database; see assets/data/README.md and THIRD_PARTY_LICENSES.txt.
 */

import { readFile, writeFile, mkdir, readdir, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseCertificates } from '../assets/js/lib/x509.js';
import { dnHash, STORES } from '../assets/js/lib/chainfix.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const OUT = join(REPO, 'assets', 'data', 'intermediates');
const CACHE = process.env.INTERMEDIATES_CACHE || join(tmpdir(), 'domainscope-intermediates');
const CACHE_MS = 12 * 3600 * 1000;
/** One download may take this long: a stalled CCADB answer fails the build, not the job's time limit. */
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

/** The CCADB reports (verified 2026-09-28; no ACAO header, so build time only). */
export const SOURCES = Object.freeze({
  intermediates: {
    name: 'Mozilla: public intermediate certificates with PEM (CCADB)',
    url: 'https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV',
    file: 'PublicAllIntermediateCertsWithPEM.csv'
  },
  included: {
    name: 'Mozilla: included CA certificates with PEM (CCADB)',
    url: 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV',
    file: 'IncludedCACertificateReportPEM.csv'
  },
  records: {
    name: 'CCADB: all certificate records, v4',
    url: 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4',
    file: 'AllCertificateRecordsv4.csv'
  },
  pems: {
    name: 'CCADB: all certificate PEMs, one report per notBefore year',
    url: 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}',
    file: 'AllCertificatePEMs-{year}.csv'
  }
});
/** The PEM report of one notBefore year (SOURCES.pems with the year filled in). */
export const pemSource = (year) => ({ ...SOURCES.pems, url: SOURCES.pems.url.replace('{year}', year), file: SOURCES.pems.file.replace('{year}', year) });
/**
 * Where a Mozilla distrust-after date without an announcement in root-lifecycle.json points: the
 * CCADB report it comes from (its events carry `source: 'ccadb'`, so the page calls the link a
 * source, not an announcement).
 */
export const MOZILLA_REPORT_URL = 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport';
/**
 * Well-known current TLS issuers the list must hold (subject CN and CA owner), each until its own
 * expiry: without one of them the build writes nothing, as a source lost it. YE1, YR1 and
 * Microsoft's TLS G2 CA come from the certificate records only, the others from Mozilla's report.
 * When a CA revokes or retires one early, take it out here.
 */
export const CANARIES = Object.freeze([
  { cn: 'YE1', owner: 'Internet Security Research Group', until: '2028-09-02' },
  { cn: 'YR1', owner: 'Internet Security Research Group', until: '2028-09-02' },
  { cn: 'R12', owner: 'Internet Security Research Group', until: '2027-03-12' },
  { cn: 'Microsoft TLS G2 RSA CA OCSP 02', owner: 'Microsoft Corporation', until: '2029-06-03' },
  { cn: 'WR1', owner: 'Google Trust Services LLC', until: '2029-02-20' },
  { cn: 'Amazon RSA 2048 M02', owner: 'Amazon Trust Services', until: '2030-08-23' },
  { cn: 'Sectigo Public Server Authentication CA DV R36', owner: 'Sectigo', until: '2036-03-21' }
].map((c) => Object.freeze(c)));
/** Hex digits per shard name. */
export const SKI_DIGITS = 2;
export const DN_DIGITS = 1;
/** The dataset format lib/chainfix.js reads. */
export const FORMAT = 1;
/** Below these counts a download is an error page, not the data: nothing is written. */
export const MIN_INTERMEDIATES = 500;
export const MIN_ROOTS = 100;

const REQUIRED = {
  intermediates: ['CA Owner', 'SHA-256 Fingerprint', 'PEM Info'],
  included: ['Owner', 'SHA-256 Fingerprint', 'Trust Bits', 'Distrust for TLS After Date', 'PEM Info'],
  records: ['CA Owner', 'Certificate Name', 'Certificate Record Type', 'Apple Status', 'Chrome Status', 'Microsoft Status', 'Mozilla Status',
    'Revocation Status', 'SHA-256 Fingerprint', 'Valid From (GMT)', 'Valid To (GMT)', 'Subject Key Identifier', 'TLS Capable'],
  pems: ['SHA-256 Fingerprint', 'X.509 Certificate (PEM)']
};
/** The store columns of a CCADB record: 'Trusted' where the store trusts an intermediate. */
const STORE_COLUMNS = ['Apple Status', 'Chrome Status', 'Microsoft Status', 'Mozilla Status'];

/* ------------------------------------------------------------------------ */
/* CSV                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * RFC 4180 CSV: quoted fields with commas, doubled quotes and line breaks (the PEM column).
 * @param {string} text
 * @returns {string[][]}
 */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const s = String(text).replace(/^﻿/, '');
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += c;
    }
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.length > 1 || r[0] !== '');
}

/**
 * CSV rows as objects keyed by the header row.
 * @param {string} text
 * @param {string[]} [required] columns that must exist
 * @returns {Array<Record<string, string>>}
 * @throws when a required column is missing (CCADB renamed a report column)
 */
export function csvObjects(text, required = []) {
  const [head = [], ...rows] = parseCsv(text);
  const missing = required.filter((c) => !head.includes(c));
  if (missing.length) throw new Error(`CSV is missing column(s): ${missing.join(', ')}`);
  return rows.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? ''])));
}

/* ------------------------------------------------------------------------ */
/* Dataset                                                                   */
/* ------------------------------------------------------------------------ */

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
/** 'YYYY-MM-DD' of a Date (UTC). */
const day = (d) => d.toISOString().slice(0, 10);
/** CCADB's '2035.06.04' / '2035-06-04' → '2035-06-04'; '' for anything else. */
const ccadbDay = (s) => {
  const m = /^(\d{4})[.-](\d{2})[.-](\d{2})/.exec(String(s || '').trim());
  return m ? `${m[1]}-${m[2]}-${m[3]}` : '';
};
/** A key id as CCADB writes it (base64) → lowercase hex; '' when absent or not base64. */
const b64Hex = (s) => {
  const v = String(s || '').trim();
  return /^[A-Za-z0-9+/]+={0,2}$/.test(v) ? Buffer.from(v, 'base64').toString('hex') : '';
};
/** The one certificate of a CSV PEM cell (CCADB prefixes it with a quote). */
const pemCert = (cell) => {
  const r = parseCertificates(String(cell || '').replace(/^'/, ''));
  return r.certificates.length === 1 ? r.certificates[0] : null;
};

/** May a TLS server certificate chain through this CA certificate (its EKU)? */
export function tlsCapable(cert) {
  const eku = cert.extKeyUsage || [];
  return !eku.length || eku.includes('serverAuth') || eku.includes('anyExtendedKeyUsage');
}

/**
 * The CCADB records of the intermediates Mozilla's report leaves out that a TLS server certificate
 * can chain through today: 'Intermediate Certificate', TLS capable, 'Trusted' in at least one
 * store, 'Not Revoked' (a revoked parent counts as revoked), not expired on the build date, and
 * not in Mozilla's report (by fingerprint).
 * @param {object[]} records rows of the certificate records report
 * @param {object[]} intermediates rows of Mozilla's intermediate report
 * @param {Date} [now]
 * @returns {object[]} the records, in report order
 */
export function extraIntermediateRecords(records, intermediates, now = new Date()) {
  const inMozilla = new Set(intermediates.map((row) => String(row['SHA-256 Fingerprint'] || '').toLowerCase()));
  const today = day(now);
  return records.filter((row) => row['Certificate Record Type'] === 'Intermediate Certificate'
    && /^true$/i.test(row['TLS Capable'] || '')
    && STORE_COLUMNS.some((c) => row[c] === 'Trusted')
    && row['Revocation Status'] === 'Not Revoked'
    && ccadbDay(row['Valid To (GMT)']) >= today
    && /^[0-9a-f]{64}$/.test(String(row['SHA-256 Fingerprint'] || '').toLowerCase())
    && !inMozilla.has(String(row['SHA-256 Fingerprint']).toLowerCase()));
}

/**
 * The notBefore years of `records` ('Valid From (GMT)'): the PEM reports to read for them.
 * @param {object[]} records
 * @returns {string[]} ascending
 */
export function pemYears(records) {
  const years = new Set();
  for (const row of records) {
    const d = ccadbDay(row['Valid From (GMT)']);
    if (d) years.add(d.slice(0, 4));
  }
  return [...years].sort();
}

/**
 * A root's status in each store, from its CCADB record ('Included', 'Removed', 'Blocked',
 * 'Disabled', 'NotBefore', 'Not Included') and, for Mozilla, its trust bits: 'tls', 'other',
 * 'not-before', 'removed' or 'absent' (lib/chainfix.js STORE_STATUSES). Apple and Microsoft
 * count as 'tls' when CCADB marks the root TLS capable.
 * @param {Record<string, string>} record
 * @param {Record<string, string>|undefined} mozilla the root's row of Mozilla's included report
 * @returns {Record<string, string>}
 */
export function storeStatuses(record, mozilla) {
  const tls = /^true$/i.test(record['TLS Capable'] || '');
  const plain = (v, { included = 'tls' } = {}) => {
    if (v === 'Included') return included;
    if (v === 'NotBefore') return 'not-before';
    if (v === 'Removed' || v === 'Blocked' || v === 'Disabled') return 'removed';
    return 'absent';
  };
  const mozillaStatus = mozilla
    ? (/\bWebsites\b/.test(mozilla['Trust Bits'] || '') ? 'tls' : 'other')
    : plain(record['Mozilla Status'], { included: 'other' });
  return {
    chrome: plain(record['Chrome Status']),
    mozilla: mozillaStatus,
    apple: plain(record['Apple Status'], { included: tls ? 'tls' : 'other' }),
    microsoft: plain(record['Microsoft Status'], { included: tls ? 'tls' : 'other' })
  };
}

/**
 * The manifest's digest: SHA-256 over each data file (its name, a newline, its content, a newline;
 * in name order), then 'manifest.json', a newline, the manifest without `generated` and `digest`
 * as compact JSON (keys in the manifest's order) and a newline.
 * @param {Map<string, string>} files path → content (a manifest.json among them is left out)
 * @param {object} body the manifest without generated and digest
 * @returns {string} lowercase hex
 */
export function datasetDigest(files, body) {
  const digest = createHash('sha256');
  for (const name of [...files.keys()].filter((f) => f !== 'manifest.json').sort()) digest.update(`${name}\n${files.get(name)}\n`);
  digest.update(`manifest.json\n${JSON.stringify(body)}\n`);
  return digest.digest('hex');
}

/** Pretty JSON with one entry per line: small diffs in the weekly pull request. */
function linesJson(obj) {
  const keys = Object.keys(obj).sort();
  if (!keys.length) return '{}\n';
  return `{\n${keys.map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(obj[k])}`).join(',\n')}\n}\n`;
}

/**
 * Build the dataset from the reports (parsed CSV rows) and the hand-kept lifecycle input.
 * Pure: no I/O.
 * @param {{ intermediates: object[], included: object[], records: object[], pems?: object[], lifecycle: { events: object[] },
 *   now?: Date, previous?: object|null, sources?: object, window?: { from: string, to: string }|null,
 *   emptyShards?: boolean, canaries?: Array<{ cn: string, owner: string, until: string }> }} input
 *   pems: rows of the PEM reports the records' extra intermediates need ({@link extraIntermediateRecords},
 *   {@link pemYears}); previous: the manifest on disk; window: the expiry events' span (default:
 *   January 1 of last year to December 31 of next year); emptyShards: also write the shard files
 *   that hold nothing (the site has every one; a test dataset leaves them out); canaries: the
 *   issuers that must be there ({@link CANARIES})
 * @returns {{ files: Map<string, string>, manifest: object,
 *   report: { skipped: object, notes: string[], fromRecords: number, missingCanaries: string[] } }}
 *   files: path relative to assets/data/intermediates → content; report: for the build log
 *   (skipped: counts by reason; fromRecords: intermediates only the certificate records listed)
 */
export function buildDataset({
  intermediates, included, records, pems = [], lifecycle, now = new Date(), previous = null, sources = SOURCES, window = null,
  emptyShards = true, canaries = CANARIES
}) {
  const t = now.getTime();
  const notes = [];
  const skipped = { unreadable: 0, notTls: 0, noKeyId: 0, expired: 0, notYetValid: 0, duplicate: 0, noPem: 0 };

  // The candidates: Mozilla's report, then the intermediates only the certificate records list,
  // with their PEM from the PEM reports (its fingerprint must be the record's).
  const candidates = intermediates.map((row) => ({ pem: row['PEM Info'], owner: row['CA Owner'], expect: null }));
  const pemBy = new Map();
  for (const row of pems) {
    const fp = String(row['SHA-256 Fingerprint'] || '').toLowerCase();
    if (/^[0-9a-f]{64}$/.test(fp)) pemBy.set(fp, row['X.509 Certificate (PEM)']);
  }
  const noPem = [];
  for (const row of extraIntermediateRecords(records, intermediates, now)) {
    const fp = String(row['SHA-256 Fingerprint']).toLowerCase();
    if (!pemBy.has(fp)) {
      skipped.noPem += 1;
      noPem.push(String(row['Certificate Name'] || fp).trim());
      continue;
    }
    candidates.push({ pem: pemBy.get(fp), owner: row['CA Owner'], expect: fp });
  }
  if (noPem.length) {
    notes.push(`no PEM in the reports read for ${noPem.length} record(s): ${noPem.slice(0, 10).join(', ')}${noPem.length > 10 ? ', …' : ''}`);
  }

  // Intermediates: subject key id → entries.
  const bySki = new Map();
  const seen = new Set();
  const kept = [];
  const owners = new Map();
  let fromRecords = 0;
  for (const { pem, owner, expect } of candidates) {
    const cert = pemCert(pem);
    if (!cert || !cert.isCA) { skipped.unreadable += 1; continue; }
    const fp = sha256Hex(cert.der);
    if (expect && fp !== expect) { skipped.unreadable += 1; continue; }
    if (seen.has(fp)) { skipped.duplicate += 1; continue; }
    seen.add(fp);
    if (!tlsCapable(cert)) { skipped.notTls += 1; continue; }
    if (!cert.subjectKeyId) { skipped.noKeyId += 1; continue; }
    if (cert.notAfter.getTime() < t) { skipped.expired += 1; continue; }
    if (cert.notBefore.getTime() > t) { skipped.notYetValid += 1; continue; }
    kept.push(cert);
    if (expect) fromRecords += 1;
    const entry = { owner: String(owner || '').trim(), der: Buffer.from(cert.der).toString('base64') };
    owners.set(cert, entry.owner);
    const list = bySki.get(cert.subjectKeyId) || [];
    list.push({ fp, entry });
    bySki.set(cert.subjectKeyId, list);
  }

  // Well-known current issuers that must be there.
  const missingCanaries = canaries
    .filter((c) => c.until >= day(now))
    .filter((c) => !kept.some((cert) => cert.subjectCN === c.cn && owners.get(cert) === c.owner))
    .map((c) => `${c.cn} (${c.owner})`);

  // The DN index.
  const byDn = new Map();
  for (const cert of kept) {
    const key = dnHash(cert.subjectDN);
    const set = byDn.get(key) || new Set();
    set.add(cert.subjectKeyId);
    byDn.set(key, set);
  }

  // Roots: CCADB records, Mozilla's included report (PEM: DN, exact dates, trust bits).
  const mozillaBy = new Map();
  const mozillaCert = new Map();
  for (const row of included) {
    const fp = String(row['SHA-256 Fingerprint'] || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fp)) continue;
    mozillaBy.set(fp, row);
    const cert = pemCert(row['PEM Info']);
    if (cert) mozillaCert.set(fp, cert);
  }
  const rootRecords = new Map();
  for (const row of records) {
    if (row['Certificate Record Type'] !== 'Root Certificate') continue;
    const fp = String(row['SHA-256 Fingerprint'] || '').toLowerCase();
    if (/^[0-9a-f]{64}$/.test(fp)) rootRecords.set(fp, row);
  }
  const lifecycleEvents = (lifecycle && Array.isArray(lifecycle.events) ? lifecycle.events : []).map((e) => ({
    ...e, roots: (e.roots || []).map((r) => String(r).toLowerCase())
  }));
  const lifecycleRoots = new Set(lifecycleEvents.flatMap((e) => e.roots));
  const parentKeys = new Set(kept.map((c) => c.authorityKeyId).filter(Boolean));
  // The DN of a root the included report does not carry: the issuer DN of its intermediates.
  const issuerDnBySki = new Map();
  for (const c of kept) {
    if (!c.authorityKeyId) continue;
    const dns = issuerDnBySki.get(c.authorityKeyId) || new Set();
    dns.add(c.issuerDN);
    issuerDnBySki.set(c.authorityKeyId, dns);
  }

  const roots = [];
  for (const [fp, row] of rootRecords) {
    const moz = mozillaBy.get(fp);
    const cert = mozillaCert.get(fp) || null;
    const ski = cert && cert.subjectKeyId ? cert.subjectKeyId : b64Hex(row['Subject Key Identifier']);
    const stores = storeStatuses(row, moz);
    const wanted = /^true$/i.test(row['TLS Capable'] || '') || stores.mozilla === 'tls' || (ski && parentKeys.has(ski)) || lifecycleRoots.has(fp);
    if (!wanted) continue;
    const dns = ski ? issuerDnBySki.get(ski) : null;
    const dn = cert ? cert.subjectDN : (dns && dns.size === 1 ? [...dns][0] : null);
    const notAfter = cert ? cert.notAfter.toISOString().replace('.000Z', 'Z') : ccadbDay(row['Valid To (GMT)']);
    roots.push({
      sha256: fp, name: String(row['Certificate Name'] || '').trim(), owner: String(row['CA Owner'] || '').trim(),
      ski: ski || null, dn, notAfter: notAfter || null, stores
    });
  }
  // Several roots named only by a shared CN ('GlobalSign' is R2 … R6) get their DN's first OU.
  const nameCount = new Map();
  for (const r of roots) nameCount.set(r.name, (nameCount.get(r.name) || 0) + 1);
  for (const r of roots) {
    const ou = nameCount.get(r.name) > 1 && r.dn ? /(?:^|,)OU=((?:\\.|[^,\\])+)/.exec(r.dn) : null;
    const unit = ou ? ou[1].replace(/\\(.)/g, '$1') : '';
    if (unit && unit !== r.name) r.name = `${r.name} (${unit})`;
  }
  roots.sort((a, b) => a.name.localeCompare(b.name, 'en') || a.sha256.localeCompare(b.sha256));
  const rootBy = new Map(roots.map((r) => [r.sha256, r]));
  for (const fp of lifecycleRoots) if (!rootBy.has(fp)) notes.push(`root-lifecycle.json names a root CCADB does not list: ${fp}`);

  // The lifecycle table.
  const events = [];
  const covered = new Set();
  for (const e of lifecycleEvents) {
    if (e.type !== 'distrust-after' || !STORES.includes(e.store) || !/^\d{4}-\d{2}-\d{2}$/.test(e.date || '')) {
      notes.push(`root-lifecycle.json: skipped an entry (${e.store} ${e.type} ${e.date})`);
      continue;
    }
    for (const fp of e.roots) {
      if (!rootBy.has(fp)) continue;
      let date = e.date;
      if (e.store === 'mozilla') {
        const listed = ccadbDay(mozillaBy.get(fp) && mozillaBy.get(fp)['Distrust for TLS After Date']);
        if (listed && listed !== date) notes.push(`${rootBy.get(fp).name}: Mozilla's date in CCADB is ${listed} (root-lifecycle.json: ${date}); CCADB's is used`);
        if (listed) date = listed;
      }
      events.push({
        root: fp, type: 'distrust-after', store: e.store, date, basis: e.basis === 'sct' ? 'sct' : 'notBefore', url: e.url || null, source: e.url ? 'announcement' : null
      });
      covered.add(`${fp}|${e.store}`);
    }
  }
  for (const [fp, row] of mozillaBy) {
    const date = ccadbDay(row['Distrust for TLS After Date']);
    if (!date || !rootBy.has(fp) || covered.has(`${fp}|mozilla`)) continue;
    events.push({ root: fp, type: 'distrust-after', store: 'mozilla', date, basis: 'notBefore', url: MOZILLA_REPORT_URL, source: 'ccadb' });
  }
  const year = now.getUTCFullYear();
  const span = window || { from: `${year - 1}-01-01`, to: `${year + 1}-12-31` };
  for (const r of roots) {
    const d = r.notAfter ? r.notAfter.slice(0, 10) : '';
    const trusted = STORES.some((s) => r.stores[s] === 'tls' || r.stores[s] === 'not-before');
    if (d && d >= span.from && d <= span.to && (trusted || lifecycleRoots.has(r.sha256))) {
      events.push({ root: r.sha256, type: 'expiry', store: null, date: r.notAfter, basis: null, url: null, source: null });
    }
  }
  const nameOf = (fp) => rootBy.get(fp).name;
  events.sort((a, b) => nameOf(a.root).localeCompare(nameOf(b.root), 'en') || a.root.localeCompare(b.root)
    || String(a.date).localeCompare(String(b.date)) || String(a.store).localeCompare(String(b.store)));

  // Files.
  const files = new Map();
  const skiShards = {};
  for (let i = 0; i < 16 ** SKI_DIGITS; i += 1) skiShards[i.toString(16).padStart(SKI_DIGITS, '0')] = {};
  for (const [ski, list] of bySki) {
    list.sort((a, b) => a.fp.localeCompare(b.fp));
    skiShards[ski.slice(0, SKI_DIGITS)][ski] = list.map((x) => x.entry);
  }
  const keep = (content) => emptyShards || Object.keys(content).length > 0;
  for (const [name, content] of Object.entries(skiShards)) if (keep(content)) files.set(`ski/${name}.json`, linesJson(content));
  const dnShards = {};
  for (let i = 0; i < 16 ** DN_DIGITS; i += 1) dnShards[i.toString(16).padStart(DN_DIGITS, '0')] = {};
  for (const [key, set] of byDn) dnShards[key.slice(0, DN_DIGITS)][key] = [...set].sort();
  for (const [name, content] of Object.entries(dnShards)) if (keep(content)) files.set(`dn/${name}.json`, linesJson(content));
  const rootsJson = `{\n  "format": ${FORMAT},\n  "roots": [\n${roots.map((r) => `    ${JSON.stringify(r)}`).join(',\n')}\n  ],\n`
    + `  "events": [\n${events.map((e) => `    ${JSON.stringify(e)}`).join(',\n')}\n  ]\n}\n`;
  files.set('roots.json', rootsJson);

  // The manifest without its date and digest is part of the digest: the date moves when the data
  // or anything the manifest says changes, and only then.
  const body = {
    format: FORMAT,
    sources: Object.entries(sources).map(([id, s]) => ({ id, name: s.name, url: s.url })),
    lifecycleInput: 'tools/root-lifecycle.json',
    license: { id: 'CDLA-Permissive-2.0', attribution: 'Common CA Database (CCADB)', text: '../THIRD_PARTY_LICENSES.txt' },
    roots: 'roots.json',
    shards: {
      ski: { dir: 'ski', digits: SKI_DIGITS, files: [...files.keys()].filter((f) => f.startsWith('ski/')).length },
      dn: { dir: 'dn', digits: DN_DIGITS, files: [...files.keys()].filter((f) => f.startsWith('dn/')).length }
    },
    counts: {
      intermediates: kept.length, keys: bySki.size, roots: roots.length,
      events: events.length, distrustEvents: events.filter((e) => e.type === 'distrust-after').length, expiryEvents: events.filter((e) => e.type === 'expiry').length
    },
    lifecycleWindow: span
  };
  const contentDigest = datasetDigest(files, body);
  const same = previous && previous.digest === contentDigest && typeof previous.generated === 'string';
  const { format, ...rest } = body;
  const manifest = { format, generated: same ? previous.generated : day(now), digest: contentDigest, ...rest };
  files.set('manifest.json', `${JSON.stringify(manifest, null, 2)}\n`);
  return { files, manifest, report: { skipped, notes, fromRecords, missingCanaries } };
}

/* ------------------------------------------------------------------------ */
/* I/O                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * The rows of one CCADB report: the cached copy while it is fresh (any age with `offline`), else a
 * download that may take `timeoutMs` at most. Only a download whose columns check out is cached,
 * and a cached copy that fails the check is deleted (and downloaded again unless `offline`), so an
 * error page CCADB answered with 200 is never read twice.
 * @param {{ url: string, file: string }} source SOURCES entry
 * @param {string[]} required the columns the report must have
 * @param {{ offline?: boolean, cache?: string, fetchImpl?: typeof fetch, timeoutMs?: number, log?: (line: string) => void }} [opts]
 * @returns {Promise<Array<Record<string, string>>>}
 */
export async function downloadCsv(source, required, {
  offline = false, cache = CACHE, fetchImpl = globalThis.fetch, timeoutMs = DOWNLOAD_TIMEOUT_MS, log = (line) => process.stdout.write(`${line}\n`)
} = {}) {
  const file = join(cache, source.file);
  let cached = null;
  try {
    const st = await stat(file);
    if (offline || Date.now() - st.mtimeMs < CACHE_MS) cached = await readFile(file, 'utf8');
  } catch {
    if (offline) throw new Error(`--offline: ${file} is not cached`);
  }
  if (cached !== null) {
    try {
      return csvObjects(cached, required);
    } catch (err) {
      await rm(file, { force: true });
      if (offline) throw new Error(`--offline: ${file}: ${err.message} (the cached copy was deleted)`);
      log(`${file}: ${err.message}; the cached copy was deleted`);
    }
  }
  log(`downloading ${source.url}`);
  let text;
  try {
    const res = await fetchImpl(source.url, {
      headers: { 'user-agent': 'domainscope-build-intermediates (+https://github.com/halilibrahimd27/domainscope)' },
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) throw new Error(`${source.url}: HTTP ${res.status}`);
    text = await res.text();
  } catch (err) {
    if (err && err.name === 'TimeoutError') throw new Error(`${source.url}: no complete answer within ${timeoutMs / 1000} s`);
    throw err;
  }
  let rows;
  try {
    rows = csvObjects(text, required);
  } catch (err) {
    throw new Error(`${source.url}: ${err.message} (not cached)`);
  }
  await mkdir(cache, { recursive: true });
  await writeFile(file, text);
  return rows;
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch {
    return null;
  }
}

async function main() {
  const offline = process.argv.includes('--offline');
  const [intermediates, included, records] = await Promise.all([
    downloadCsv(SOURCES.intermediates, REQUIRED.intermediates, { offline }),
    downloadCsv(SOURCES.included, REQUIRED.included, { offline }),
    downloadCsv(SOURCES.records, REQUIRED.records, { offline })
  ]);
  // The PEMs of the intermediates only the records list: one report per notBefore year they need,
  // one after the other (each is 1–2 MB).
  const pems = [];
  for (const year of pemYears(extraIntermediateRecords(records, intermediates))) {
    pems.push(...await downloadCsv(pemSource(year), REQUIRED.pems, { offline }));
  }
  const lifecycle = JSON.parse(await readFile(join(HERE, 'root-lifecycle.json'), 'utf8'));
  const previous = await readJson(join(OUT, 'manifest.json'));
  const { files, manifest, report } = buildDataset({ intermediates, included, records, pems, lifecycle, previous });
  const c = manifest.counts;
  const log = () => {
    process.stdout.write(`${c.intermediates} intermediates (${c.keys} keys; ${report.fromRecords} from the certificate records), ${c.roots} roots, `
      + `${c.distrustEvents} distrust and ${c.expiryEvents} expiry events; skipped ${JSON.stringify(report.skipped)}\n`);
    for (const n of report.notes) process.stdout.write(`note: ${n}\n`);
  };
  if (c.intermediates < MIN_INTERMEDIATES || c.roots < MIN_ROOTS) {
    log();
    throw new Error(`implausible data (${c.intermediates} intermediates, ${c.roots} roots): nothing written`);
  }
  if (report.missingCanaries.length) {
    log();
    throw new Error(`well-known current issuers are missing: ${report.missingCanaries.join(', ')}. Nothing written. `
      + 'Check the CCADB reports; if the CA revoked or retired one, take it out of CANARIES in tools/build-intermediates.mjs.');
  }
  for (const dir of ['ski', 'dn']) {
    await mkdir(join(OUT, dir), { recursive: true });
    for (const name of await readdir(join(OUT, dir))) {
      if (!files.has(`${dir}/${name}`)) await rm(join(OUT, dir, name));
    }
  }
  let changed = 0;
  for (const [name, content] of files) {
    const path = join(OUT, ...name.split('/'));
    let old = null;
    try { old = await readFile(path, 'utf8'); } catch { /* new file */ }
    if (old === content) continue;
    await writeFile(path, content);
    changed += 1;
  }
  log();
  process.stdout.write(`${changed} file(s) changed, dataset of ${manifest.generated}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
