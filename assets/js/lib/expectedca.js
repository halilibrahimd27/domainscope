/**
 * lib/expectedca.js — a workspace's expected CAs (lib/workspace.js `expectedCas`) against a
 * certificate's issuer or a CAA issuer domain: the Certificate view, SSL Targets (the loaded
 * certificate and the one each server serves) and the CAA checks mark an issuer "expected CA" or
 * "unexpected CA" with it.
 *
 * An entry is read with lib/health.js's CA table (CAA_ISSUERS): a CA's name ("Let's Encrypt",
 * "DigiCert"), its id ("letsencrypt") or one of its CAA identifiers ("letsencrypt.org") stands
 * for that CA with all its brands and intermediates (a Sectigo entry covers a ZeroSSL issuer);
 * anything else ("Example Corp Internal CA", "ca.example.net") is matched as text, case-insensitive,
 * inside the issuer's name or equal to a CAA identifier — for a private CA.
 *
 * DOM-free and pure.
 *
 * @example
 *   expectedCaStatus({ CN: 'R11', O: "Let's Encrypt", C: 'US' }, ['letsencrypt.org']);   // { expected: true, entry: 'letsencrypt.org', ca: "Let's Encrypt" }
 *   expectedCaStatus('CN=Sectigo RSA DV,O=Sectigo Limited', ["Let's Encrypt"]);          // { expected: false, entry: null, ca: 'Sectigo' }
 *   expectedCaStatus('CN=R11,O=Let\'s Encrypt', []);                                     // null: no expectation, no badge
 */

import { CAA_ISSUERS, caaIssuerInfo } from './health.js';

/**
 * Lowercase, whitespace collapsed, a typographic apostrophe as the ASCII one ("Let’s Encrypt" from
 * iOS Smart Punctuation or a pasted document); a trailing dot of a domain dropped.
 */
const fold = (s) => String(s ?? '').normalize('NFC').replace(/[\u2018\u2019\u201b\u02bc\uff07]/g, "'").replace(/\s+/g, ' ').trim().toLowerCase()
  .replace(/\.$/, '');

/**
 * What an expected-CA entry stands for: a known CA, or a text to find in an issuer (a private CA).
 * @param {string} entry
 * @returns {{ entry: string, ca: { id: string, name: string, domains: ReadonlyArray<string> }|null, needle: string|null }}
 */
export function resolveExpectedCa(entry) {
  const text = fold(entry);
  if (!text) return { entry: String(entry ?? ''), ca: null, needle: null };
  const ca = CAA_ISSUERS.find((c) => c.id === text || fold(c.name) === text || c.domains.includes(text))
    || CAA_ISSUERS.find((c) => c.match.test(text))
    || null;
  return { entry: String(entry), ca: ca ? { id: ca.id, name: ca.name, domains: ca.domains } : null, needle: ca ? null : text };
}

/** The issuer as one text: a DN string, or the values of a parsed name ({ CN, O, … }). */
function issuerText(issuer) {
  if (typeof issuer === 'string') return issuer;
  if (issuer && typeof issuer === 'object') return Object.values(issuer).filter((v) => typeof v === 'string').join(', ');
  return '';
}

/**
 * Is a certificate's issuer one of the expected CAs?
 * @param {string|object} issuer the issuer DN ("CN=R11,O=Let's Encrypt,C=US") or a parsed issuer name
 * @param {ReadonlyArray<string>} expected the workspace's entries
 * @returns {{ expected: boolean, entry: string|null, ca: string|null }|null} null without entries or
 *   without an issuer (no badge); `entry`: the entry that matched; `ca`: the issuer's CA when known
 */
export function expectedCaStatus(issuer, expected) {
  const entries = Array.isArray(expected) ? expected.filter((e) => fold(e)) : [];
  const text = fold(issuerText(issuer));
  if (!entries.length || !text) return null;
  const known = caaIssuerInfo(issuer);
  for (const raw of entries) {
    const r = resolveExpectedCa(raw);
    if (r.ca ? known.some((k) => k.id === r.ca.id) : text.includes(r.needle)) {
      return { expected: true, entry: r.entry, ca: known[0] ? known[0].name : null };
    }
  }
  return { expected: false, entry: null, ca: known[0] ? known[0].name : null };
}

/**
 * Is a CAA issuer domain (an `issue` / `issuewild` value's CA, "letsencrypt.org") one of the
 * expected CAs? A known CA matches by any of its identifiers; a text entry must equal the domain.
 * @param {string} domain
 * @param {ReadonlyArray<string>} expected
 * @returns {{ expected: boolean, entry: string|null }|null} null without entries or domain
 */
export function expectedCaaStatus(domain, expected) {
  const entries = Array.isArray(expected) ? expected.filter((e) => fold(e)) : [];
  const d = fold(domain);
  if (!entries.length || !d) return null;
  const ca = CAA_ISSUERS.find((c) => c.domains.includes(d));
  for (const raw of entries) {
    const r = resolveExpectedCa(raw);
    if (r.ca ? !!ca && ca.id === r.ca.id : r.needle === d) return { expected: true, entry: r.entry };
  }
  return { expected: false, entry: null };
}
