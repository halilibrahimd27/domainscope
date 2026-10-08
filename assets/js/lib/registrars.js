/**
 * registrars.js — the class of a domain's registrar by its IANA Registrar ID (RDAP's "IANA
 * Registrar ID" public id, lib/rdap.js `registrarIanaId`): a corporate (enterprise) registrar,
 * a retail one, or not known.
 *
 * Corporate registrars sell brand protection rather than cheap names: registry locks across the
 * TLDs that offer one, change control by a named account manager, consolidation of a company's
 * domains. CSC's Domain Security Report counts "an enterprise-class registrar" as the first of its
 * eight measures (lib/secscore.js). The list is by IANA ID, never by name: a name in RDAP is the
 * registrar's own text and spelled many ways, the ID is IANA's. Every ID below was checked in
 * IANA's registrar-ids-1.csv (https://www.iana.org/assignments/registrar-ids/) on 2026-10-08, with
 * its name there.
 *
 * A registrar without an IANA ID (a country-code registry's own registrars, as .tr's or .de's)
 * or with one of IANA's reserved IDs (the registry operator acting as registrar, test and SLA
 * IDs) is 'unknown': the ID says nothing about who holds the domain.
 *
 * Pure: no DOM, network or storage. Runs in browsers and Node 22.
 */

const entry = (id, brand, name) => Object.freeze({ id, brand, name });

/**
 * Corporate registrars by IANA Registrar ID: `brand` is how people call it, `name` IANA's name
 * for the ID (registrar-ids-1.csv, 2026-10-08).
 * @type {ReadonlyArray<{ id: number, brand: string, name: string }>}
 */
export const CORPORATE_REGISTRARS = Object.freeze([
  entry(292, 'MarkMonitor', 'MarkMonitor Inc.'),
  entry(299, 'CSC', 'CSC Corporate Domains, Inc.'),
  entry(447, 'Safenames', 'Safenames Ltd'),
  entry(470, 'Com Laude', 'Nom-iq Ltd. dba COM LAUDE'),
  entry(642, 'Corsearch', 'Corsearch Domains LLC'),
  entry(1011, '101domain', '101domain GRS Limited'),
  entry(1251, 'Nameshield', 'Nameshield SAS'),
  entry(1466, 'Lexsynergy', 'Lexsynergy Limited'),
  entry(1639, 'EBRAND', 'EBRAND Holdings S.A.'),
  entry(1750, 'Authentic Web', 'Authentic Web Inc.'),
  entry(3786, 'GoDaddy Corporate Domains', 'GoDaddy Corporate Domains, LLC'),
  entry(3838, 'MarkMonitor', 'MarkMonitor Information Technology (Shanghai) Co., Ltd.')
]);

/**
 * IANA's reserved registrar IDs (status "Reserved" in registrar-ids-1.csv, 2026-10-08): 9998 and
 * 9999 are the registry operator acting as registrar, 9994 the same where ICANN directs it, 9995 –
 * 9997 test and SLA monitoring, 8888888 and 4000001 historic registry use, 1, 3, 8, 119, 365, 376
 * and 10009 IANA's own and test entries. None of them names who holds a domain.
 */
export const RESERVED_REGISTRAR_IDS = Object.freeze([1, 3, 8, 119, 365, 376, 9994, 9995, 9996, 9997, 9998, 9999, 10009, 4000001, 8888888]);

/** The classes {@link registrarClass} returns. */
export const REGISTRAR_CLASSES = Object.freeze(['corporate', 'retail', 'unknown']);

const BY_ID = new Map(CORPORATE_REGISTRARS.map((r) => [r.id, r]));
const RESERVED = new Set(RESERVED_REGISTRAR_IDS);

/**
 * An IANA Registrar ID as a number: '292', 292, ' 292 ' → 292; anything else (none, 'N/A', '0',
 * '12a', a negative or fractional number) → null.
 * @param {unknown} value RDAP's identifier (lib/rdap.js keeps it as written: a string)
 * @returns {number|null}
 */
export function registrarId(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? value : null;
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (!/^\d{1,9}$/.test(s)) return null;
  const n = Number(s);
  return n > 0 ? n : null;
}

/**
 * The corporate registrar an IANA ID is, or null.
 * @param {unknown} ianaId
 * @returns {{ id: number, brand: string, name: string }|null}
 */
export function corporateRegistrar(ianaId) {
  const id = registrarId(ianaId);
  return id === null ? null : BY_ID.get(id) || null;
}

/**
 * The class of a registrar by its IANA ID: 'corporate' (one of {@link CORPORATE_REGISTRARS}),
 * 'retail' (any other accredited ID) or 'unknown' (no ID — a country-code registry's own
 * registrars have none —, an ID that is not a number, or a reserved one).
 * @param {unknown} ianaId
 * @returns {'corporate'|'retail'|'unknown'}
 */
export function registrarClass(ianaId) {
  const id = registrarId(ianaId);
  if (id === null || RESERVED.has(id)) return 'unknown';
  return BY_ID.has(id) ? 'corporate' : 'retail';
}
