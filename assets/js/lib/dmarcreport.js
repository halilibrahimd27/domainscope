/**
 * dmarcreport.js — DMARC aggregate reports (the `rua` XML of RFC 7489 Appendix C), read and
 * explained in the browser: who sends mail as the domain, whether it passes DMARC, and what stands
 * between the domain and `p=reject`. DOM-free; runs in browsers and Node 22.
 *
 * - {@link readReportFiles}: dropped files (zip, gzip, XML, JSON; lib/zipread.js) → the DMARC
 *   reports, the TLS reports (lib/tlsrpt.js) and a reason for every part that is neither.
 * - {@link parseXml}: a minimal XML reader, and {@link parseAggregateReport} the schema mapping onto
 *   plain objects. Why not DOMParser: the reports are a small, data-only subset of XML, the same
 *   code then runs (and is tested) in Node, where there is no DOMParser, and a reader that refuses
 *   a DTD internal subset cannot expand entities (no billion laughs, no external entities).
 * - {@link aggregateDmarc}: every report of a policy domain together, one {@link SourceRow} per
 *   sending address (volume, SPF / DKIM results and alignment, disposition, reporters); a report
 *   dropped twice counts once.
 * - {@link loadSpfContext}: the domain's current SPF, expanded once (lib/health.js spfLookupCount;
 *   names and types to the DoH resolvers only), so {@link classifySources} can ask for each
 *   address whether the policy authorizes it (health.spfEvaluate, no further query, with the
 *   RFC 7208 limits of 10 DNS lookups and 2 void lookups a receiver applies).
 * - {@link classifySources}: each source is one of {@link SOURCE_CLASSES} — your servers (in the
 *   server list, or authorized by the domain's own SPF terms), an authorized third party (through
 *   an include of another organisation, or signing with the domain's DKIM from its own bounce
 *   domain), a forwarder (DKIM passes, SPF does not) or an unknown sender — with the reason and,
 *   for a known source that fails DMARC or that a broken SPF record now fails, what to fix.
 * - {@link dmarcOverview}: the headline — DMARC compliance, the policy, whether `p=reject` can
 *   come, which sources must be fixed first; {@link dmarcCsvRows} the table as CSV rows.
 *
 * Nothing leaves the browser here except what {@link loadSpfContext} asks the resolvers (the
 * policy domain's SPF and what it includes); the reports themselves are only read.
 */

import { throwIfAborted, errorKind } from './util.js';
import { normalizeHostname, registrableDomain } from './domain.js';
import { normalizeIP, ipVersion, isPrivateIP } from './netinfo.js';
import { spfLookupCount, spfEvaluate, spfMxHosts, parseSpf } from './health.js';
import { lookupServers } from './inventory.js';
import { unpackFile, containerOf, toBytes, ZIP_ERRORS, ZIP_LIMITS } from './zipread.js';
import { parseTlsReport } from './tlsrpt.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies (frozen; the i18n coverage test derives keys from them)      */
/* ------------------------------------------------------------------------ */

/** Classes of a sending address, most trusted first (`rpt.cls.<id>`). */
export const SOURCE_CLASSES = Object.freeze(['yours', 'third-party', 'forwarder', 'unknown']);
/**
 * Why a source is in its class (`rpt.why.<id>`): `inventory` a server in the list; `spf` the
 * domain's own SPF terms authorize it; `spf-listed` its own terms list it, but receivers get a
 * permerror from the record first (a syntax error, too many lookups); `spf-report` the current SPF
 * cannot tell (not checked, a failed lookup, several records), but the reports saw it pass
 * aligned; `spf-include` an include of another organisation authorizes it; `include-listed` such
 * an include lists it, but receivers get a permerror first;
 * `dkim-signed` the current SPF tells nothing about it (it passes every address, or no longer
 * lists it), but it signs with the domain's DKIM and all its mail passed SPF aligned: a direct sender;
 * `dkim-service` it signs with the domain's DKIM and bounces through its own domain; `forwarded`
 * the receiver says it was forwarded (a policy override); `dkim-forwarded` it carries a DKIM
 * signature the domain's own senders make; `dkim-only` DKIM passes, SPF does not; `spf-removed`
 * the reports saw it pass SPF aligned, the current SPF no longer authorizes it; `foreign` it
 * authenticates only as another domain; `none` nothing authenticates it.
 */
export const CLASS_REASONS = Object.freeze([
  'inventory', 'spf', 'spf-listed', 'spf-report', 'spf-include', 'include-listed', 'dkim-signed', 'dkim-service', 'forwarded', 'dkim-forwarded', 'dkim-only',
  'spf-removed', 'foreign', 'none'
]);
/**
 * What a known source needs (`rpt.fix.<id>`). First `spf-permerror` when the current SPF gives
 * the address a permerror (the record, not the sender, breaks SPF: for every sender it lists);
 * then, for one that fails DMARC, the most robust first: `dkim-sign` sign with DKIM for the
 * domain, `dkim-align` DKIM signs only as another domain, `dkim-fix` the domain's DKIM signature
 * does not verify, `spf-add` the domain's SPF does not list the address, `spf-align` SPF passes
 * only for another domain (the return-path).
 */
export const FIX_CODES = Object.freeze(['spf-permerror', 'dkim-sign', 'dkim-align', 'dkim-fix', 'spf-add', 'spf-align']);
/** Headline verdicts of {@link dmarcOverview} (`rpt.verdict.<id>`). */
export const DMARC_VERDICTS = Object.freeze(['no-mail', 'enforced', 'ready', 'fix-first', 'spf-broken']);
/** Notes of {@link dmarcOverview} (`rpt.note.<id>`). */
export const DMARC_NOTES = Object.freeze(['short-range', 'pct', 'testing', 'mixed-policy', 'spf-unknown', 'spf-permerror', 'quarantine', 'rejected-now', 'spf-all']);
/**
 * Dispositions a receiver applied (`policy_evaluated/disposition`): RFC 7489's none, quarantine,
 * reject, and DMARCbis's `pass` (the message passed DMARC, no policy applied).
 */
export const DISPOSITIONS = Object.freeze(['none', 'pass', 'quarantine', 'reject']);
/** Policy overrides of RFC 7489 Appendix C (`PolicyOverrideType`) that mean forwarded mail. */
export const FORWARD_OVERRIDES = Object.freeze(['forwarded', 'mailing_list', 'trusted_forwarder']);
/** Why a file or part of one is no report (`rpt.problem.<code>`): the zip reader's reasons, then these. */
export const REPORT_PROBLEMS = Object.freeze([...ZIP_ERRORS, 'not-report', 'xml', 'not-dmarc', 'incomplete', 'not-json', 'not-tlsrpt', 'empty']);
/** Columns of {@link dmarcCsvRows} (language-neutral; the view writes the same headers). */
export const DMARC_CSV_COLUMNS = Object.freeze([
  'domain', 'source_ip', 'class', 'reason', 'detail', 'servers', 'service', 'service_type', 'service_via', 'service_confidence',
  'messages', 'dmarc_pass', 'dmarc_fail', 'spf_aligned_pass', 'dkim_aligned_pass',
  'disposition_none', 'disposition_pass', 'disposition_quarantine', 'disposition_reject', 'spf_now', 'spf_now_term', 'spf_now_reason', 'fixes',
  'header_from', 'envelope_from',
  'spf_results', 'dkim_results', 'overrides', 'reporters', 'first_seen', 'last_seen'
]);

/** Reports shorter than this (days, every report together) get the `short-range` note. */
export const SHORT_RANGE_DAYS = 7;
/** Most SPF policies one analysis looks up (header-from domains and aligned SPF domains). */
export const SPF_MAX_DOMAINS = 10;
/** Most `mx` hosts of one SPF tree resolved for {@link loadSpfContext}. */
export const SPF_MAX_MX_HOSTS = 10;
/** Most files one {@link readReportFiles} call reads (every file inside the archives together). */
export const MAX_REPORT_FILES = 2000;
/** Work between two turns of the event loop while {@link readReportFiles} reads (ms). */
export const READ_YIELD_MS = 50;
/**
 * Most bytes one {@link readReportFiles} call (a drop) inflates, every dropped file together: each
 * has its own lib/zipread.js `maxTotalBytes` too, so 200 small gzip bombs cost 1 GiB, not 200 × that.
 */
export const MAX_DROP_BYTES = 1024 * 1024 * 1024;

/* ------------------------------------------------------------------------ */
/* A minimal XML reader                                                     */
/* ------------------------------------------------------------------------ */

/** Bounds of {@link parseXml}. */
export const XML_LIMITS = Object.freeze({ maxElements: 2000000, maxDepth: 64 });

/** A document the reader refuses (`code`: 'unterminated', 'mismatch', 'unclosed', 'doctype', 'empty', 'limit'). */
export class XmlError extends Error {
  /**
   * @param {string} code
   * @param {string} [detail]
   */
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'XmlError';
    this.code = code;
  }
}

/**
 * @typedef {object} XmlElement
 * @property {string} name the local name, lowercase (`dmarc:feedback` → `feedback`)
 * @property {Record<string, string>} attrs attributes by their name as written
 * @property {XmlElement[]} children
 * @property {string} text the element's own text (entities and CDATA resolved), untrimmed
 */

const ENTITIES = Object.freeze({ lt: '<', gt: '>', amp: '&', quot: '"', apos: '\'' });

function decodeEntities(s) {
  if (!s.includes('&')) return s;
  return s.replace(/&(?:#(\d{1,7})|#x([0-9a-fA-F]{1,6})|([A-Za-z]+));/g, (m, dec, hex, name) => {
    if (dec || hex) {
      const cp = dec ? Number(dec) : parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff) ? String.fromCodePoint(cp) : '�';
    }
    return Object.prototype.hasOwnProperty.call(ENTITIES, name) ? ENTITIES[name] : m;
  });
}

const localName = (qname) => {
  const i = qname.indexOf(':');
  return (i === -1 ? qname : qname.slice(i + 1)).toLowerCase();
};

const isXmlSpace = (c) => c === 32 || c === 9 || c === 10 || c === 13;

/**
 * The `name="value"` pairs of a start tag's text after its name, in one pass: every step moves
 * forward, so a hostile tag (a megabyte with no '=') costs linear time, never a backtracking
 * regex's quadratic one. A name without a quoted value is passed over, as before.
 * @param {string} s the tag's inner text
 * @param {number} from where the attributes start
 * @returns {Record<string, string>}
 */
function readAttributes(s, from) {
  const attrs = {};
  let i = from;
  const end = s.length;
  while (i < end) {
    while (i < end && isXmlSpace(s.charCodeAt(i))) i += 1;
    const start = i;
    while (i < end && !isXmlSpace(s.charCodeAt(i)) && s.charCodeAt(i) !== 61) i += 1;
    const name = s.slice(start, i);
    while (i < end && isXmlSpace(s.charCodeAt(i))) i += 1;
    if (s.charCodeAt(i) !== 61) continue; // no '=': a bare name (or nothing left)
    i += 1;
    while (i < end && isXmlSpace(s.charCodeAt(i))) i += 1;
    const q = s.charCodeAt(i);
    if (q !== 34 && q !== 39) continue; // an unquoted value: not XML, passed over
    const close = s.indexOf(q === 34 ? '"' : '\'', i + 1);
    if (close === -1) break;
    if (name) attrs[name] = decodeEntities(s.slice(i + 1, close));
    i = close + 1;
  }
  return attrs;
}

/** Where a tag ends: the first '>' outside a quoted attribute value. */
function tagEnd(s, from) {
  let quote = 0;
  for (let i = from; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (quote) {
      if (c === quote) quote = 0;
    } else if (c === 34 || c === 39) quote = c;
    else if (c === 62) return i;
  }
  return -1;
}

/**
 * Read an XML document into a tree of plain objects: elements, attributes, text, CDATA,
 * comments and processing instructions (skipped), the five predefined entities and character
 * references. A DOCTYPE with an internal subset is refused (`doctype`), so no entity is ever
 * expanded; one without it is skipped. Namespace prefixes are dropped from element names.
 * @param {string} text
 * @param {{ maxElements?: number, maxDepth?: number }} [opts]
 * @returns {XmlElement} the document element
 * @throws {XmlError}
 */
export function parseXml(text, { maxElements = XML_LIMITS.maxElements, maxDepth = XML_LIMITS.maxDepth } = {}) {
  const s = String(text ?? '').replace(/^﻿/, '');
  const doc = { name: '#document', attrs: {}, children: [], text: '' };
  const stack = [doc];
  let count = 0;
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    const top = stack[stack.length - 1];
    if (lt === -1) {
      top.text += decodeEntities(s.slice(i));
      break;
    }
    if (lt > i) top.text += decodeEntities(s.slice(i, lt));
    if (s.startsWith('<!--', lt)) {
      const end = s.indexOf('-->', lt + 4);
      if (end === -1) throw new XmlError('unterminated', 'comment');
      i = end + 3;
    } else if (s.startsWith('<![CDATA[', lt)) {
      const end = s.indexOf(']]>', lt + 9);
      if (end === -1) throw new XmlError('unterminated', 'CDATA');
      top.text += s.slice(lt + 9, end);
      i = end + 3;
    } else if (s.startsWith('<?', lt)) {
      const end = s.indexOf('?>', lt + 2);
      if (end === -1) throw new XmlError('unterminated', 'processing instruction');
      i = end + 2;
    } else if (s.startsWith('<!', lt)) {
      const end = tagEnd(s, lt + 2);
      if (end === -1) throw new XmlError('unterminated', 'declaration');
      if (/^<!DOCTYPE/i.test(s.slice(lt, lt + 9)) && s.slice(lt, end).includes('[')) throw new XmlError('doctype');
      i = end + 1;
    } else if (s[lt + 1] === '/') {
      const end = s.indexOf('>', lt + 2);
      if (end === -1) throw new XmlError('unterminated', 'end tag');
      const name = localName(s.slice(lt + 2, end).trim());
      if (stack.length < 2 || top.name !== name) throw new XmlError('mismatch', `</${name}>`);
      stack.pop();
      i = end + 1;
    } else {
      const end = tagEnd(s, lt + 1);
      if (end === -1) throw new XmlError('unterminated', 'start tag');
      let inner = s.slice(lt + 1, end);
      const selfClosing = inner.endsWith('/');
      if (selfClosing) inner = inner.slice(0, -1);
      const m = /^\s*([^\s/>]+)/.exec(inner);
      if (!m) throw new XmlError('mismatch', 'a tag without a name');
      count += 1;
      if (count > maxElements || stack.length > maxDepth) throw new XmlError('limit', count > maxElements ? 'elements' : 'depth');
      const el = { name: localName(m[1]), attrs: readAttributes(inner, m[0].length), children: [], text: '' };
      top.children.push(el);
      if (!selfClosing) stack.push(el);
      i = end + 1;
    }
  }
  if (stack.length > 1) throw new XmlError('unclosed', `<${stack[stack.length - 1].name}>`);
  if (!doc.children.length) throw new XmlError('empty');
  return doc.children[0];
}

/** The first child element with a local name. */
export const xmlChild = (el, name) => (el && el.children ? el.children.find((c) => c.name === name) || null : null);
/** Every child element with a local name. */
export const xmlChildren = (el, name) => (el && el.children ? el.children.filter((c) => c.name === name) : []);
/** The trimmed text of a child element ('' when it is missing). */
export const xmlText = (el, name) => {
  const c = xmlChild(el, name);
  return c ? c.text.trim() : '';
};

/* ------------------------------------------------------------------------ */
/* The aggregate report schema (RFC 7489 Appendix C)                        */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} DmarcRecord
 * @property {string} ip the source address (canonical)
 * @property {number} count messages
 * @property {string} disposition one of {@link DISPOSITIONS} as the receiver applied it (anything else is kept as written)
 * @property {string} dkim DMARC's DKIM result: 'pass' only for an aligned signature that verified
 * @property {string} spf DMARC's SPF result: 'pass' only for an aligned SPF pass
 * @property {Array<{ type: string, comment: string }>} reasons policy overrides
 * @property {string} headerFrom
 * @property {string|null} envelopeFrom
 * @property {string|null} envelopeTo
 * @property {Array<{ domain: string, selector: string|null, result: string, human: string|null }>} dkimAuth every DKIM
 *   signature the receiver checked, aligned or not
 * @property {Array<{ domain: string, scope: string|null, result: string }>} spfAuth the SPF checks
 */

/**
 * @typedef {object} AggregateReport
 * @property {'dmarc'} kind
 * @property {string} key the reporter and report id: one report dropped twice counts once
 * @property {string} file where it came from
 * @property {string} org `org_name`
 * @property {string|null} email
 * @property {string|null} extraContact
 * @property {string} reportId
 * @property {Date} begin
 * @property {Date} end
 * @property {string[]} errors the reporter's own `<error>` notes
 * @property {{ domain: string, p: string, sp: string, np: string|null, pct: number, adkim: 'r'|'s', aspf: 'r'|'s',
 *   fo: string|null, testing: string|null }} policy what the reporter found published
 * @property {DmarcRecord[]} records
 * @property {number} messages
 * @property {number} skipped records that could not be read (no address, a bad count)
 */

const lower = (s) => String(s ?? '').trim().toLowerCase();
const hostOf = (s) => {
  const t = String(s ?? '').trim().replace(/\.$/, '');
  return t ? normalizeHostname(t) || t.toLowerCase() : '';
};
// SPF results as receivers write them; a few write "hardfail".
const SPF_ALIASES = Object.freeze({ hardfail: 'fail' });

/** Epoch seconds (a few reporters send milliseconds) → Date, or null. */
function epoch(s) {
  const n = Number(String(s ?? '').trim());
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n > 1e11 ? n : n * 1000);
}

/**
 * Does a text look like a DMARC aggregate report (a `feedback` document element)? Cheap: only the
 * first few kilobytes are looked at, after the XML declaration, comments and a DOCTYPE without an
 * internal subset ({@link parseXml} skips that one too, and refuses the other).
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeAggregate(text) {
  const head = String(text ?? '').slice(0, 4096).replace(/<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!DOCTYPE(?:[^[>"']|"[^"]*"|'[^']*')*>/gi, '').trimStart();
  return /^<(?:[\w.-]+:)?feedback[\s>/]/i.test(head);
}

/**
 * Read one aggregate report. Records without a readable address or count are skipped and counted
 * (`skipped`); a report without its metadata, policy or date range is refused (`incomplete`, with
 * the missing element in `detail`).
 * @param {string} text the XML
 * @param {{ file?: string }} [opts]
 * @returns {{ ok: true, report: AggregateReport } | { ok: false, code: 'xml'|'not-dmarc'|'incomplete', detail: string }}
 */
export function parseAggregateReport(text, { file = '' } = {}) {
  let root;
  try {
    root = parseXml(text);
  } catch (err) {
    return { ok: false, code: 'xml', detail: err instanceof XmlError ? err.code : String((err && err.message) || err) };
  }
  if (root.name !== 'feedback') return { ok: false, code: 'not-dmarc', detail: root.name };
  const meta = xmlChild(root, 'report_metadata');
  const pol = xmlChild(root, 'policy_published');
  const range = xmlChild(meta, 'date_range');
  const missing = !meta ? 'report_metadata' : !pol ? 'policy_published' : !range ? 'date_range' : null;
  if (missing) return { ok: false, code: 'incomplete', detail: missing };
  const domain = hostOf(xmlText(pol, 'domain'));
  const begin = epoch(xmlText(range, 'begin'));
  const end = epoch(xmlText(range, 'end'));
  const org = xmlText(meta, 'org_name');
  if (!domain || !begin || !end || !org) return { ok: false, code: 'incomplete', detail: !domain ? 'domain' : !org ? 'org_name' : 'date_range' };
  const p = lower(xmlText(pol, 'p')) || 'none';
  const pctText = xmlText(pol, 'pct');
  const pct = /^\d{1,3}$/.test(pctText) ? Math.min(100, Number(pctText)) : 100;
  const align = (v) => (lower(v) === 's' ? 's' : 'r');
  const records = [];
  let skipped = 0;
  for (const rec of xmlChildren(root, 'record')) {
    const row = xmlChild(rec, 'row');
    const ev = xmlChild(row, 'policy_evaluated');
    const ids = xmlChild(rec, 'identifiers');
    const auth = xmlChild(rec, 'auth_results');
    const ip = normalizeIP(xmlText(row, 'source_ip'));
    const countText = xmlText(row, 'count');
    const count = /^\d+$/.test(countText) ? Number(countText) : NaN;
    if (!ip || !Number.isSafeInteger(count)) {
      skipped += 1;
      continue;
    }
    const headerFrom = hostOf(xmlText(ids, 'header_from')) || domain;
    records.push({
      ip,
      count,
      disposition: lower(xmlText(ev, 'disposition')) || 'none',
      dkim: lower(xmlText(ev, 'dkim')) || 'fail',
      spf: lower(xmlText(ev, 'spf')) || 'fail',
      reasons: xmlChildren(ev, 'reason').map((r) => ({ type: lower(xmlText(r, 'type')) || 'other', comment: xmlText(r, 'comment') })),
      headerFrom,
      envelopeFrom: hostOf(xmlText(ids, 'envelope_from')) || null,
      envelopeTo: hostOf(xmlText(ids, 'envelope_to')) || null,
      dkimAuth: xmlChildren(auth, 'dkim').map((d) => ({
        domain: hostOf(xmlText(d, 'domain')),
        selector: xmlText(d, 'selector') || null,
        result: lower(xmlText(d, 'result')) || 'none',
        human: xmlText(d, 'human_result') || null
      })).filter((d) => d.domain),
      spfAuth: xmlChildren(auth, 'spf').map((d) => {
        const result = lower(xmlText(d, 'result')) || 'none';
        return { domain: hostOf(xmlText(d, 'domain')), scope: lower(xmlText(d, 'scope')) || null, result: SPF_ALIASES[result] || result };
      }).filter((d) => d.domain)
    });
  }
  const reportId = xmlText(meta, 'report_id');
  return {
    ok: true,
    report: {
      kind: 'dmarc',
      key: `${org.toLowerCase()}|${reportId || `${domain}|${begin.getTime()}|${end.getTime()}`}`,
      file,
      org,
      email: xmlText(meta, 'email') || null,
      extraContact: xmlText(meta, 'extra_contact_info') || null,
      reportId,
      begin,
      end,
      errors: xmlChildren(meta, 'error').map((e) => e.text.trim()).filter(Boolean),
      policy: {
        domain,
        p,
        sp: lower(xmlText(pol, 'sp')) || p,
        np: lower(xmlText(pol, 'np')) || null,
        pct,
        adkim: align(xmlText(pol, 'adkim')),
        aspf: align(xmlText(pol, 'aspf')),
        fo: xmlText(pol, 'fo') || null,
        testing: lower(xmlText(pol, 'testing')) || null
      },
      records,
      messages: records.reduce((n, r) => n + r.count, 0),
      skipped
    }
  };
}

/* ------------------------------------------------------------------------ */
/* Reading dropped files                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The text of a report file: a UTF-16 or UTF-8 byte order mark wins, else the encoding an XML
 * declaration names (ISO-8859-1, windows-1252 …), else UTF-8.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function decodeReportText(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder('utf-16be').decode(bytes.subarray(2));
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return new TextDecoder('utf-8').decode(bytes.subarray(3));
  const head = String.fromCharCode(...bytes.subarray(0, 200));
  const m = /^<\?xml[^>]*encoding\s*=\s*["']([A-Za-z0-9._-]+)["']/.exec(head);
  if (m && !/^utf-?8$/i.test(m[1])) {
    try {
      return new TextDecoder(m[1]).decode(bytes);
    } catch {
      // an encoding this platform does not know: UTF-8 below
    }
  }
  return new TextDecoder('utf-8').decode(bytes);
}

/**
 * @typedef {object} ReportProblem
 * @property {string} path the file, or the entry inside an archive (`outer.zip › inner.xml`)
 * @property {string} code one of {@link REPORT_PROBLEMS}
 * @property {string} detail
 */

/**
 * Read dropped files into reports: archives are unpacked (lib/zipread.js), then each file is
 * told apart by its content — XML with a `feedback` element is a DMARC aggregate report, JSON with
 * `policies` a TLS report — never by its name. Everything that is neither, or cannot be read, is a
 * {@link ReportProblem}; nothing is dropped silently. At most {@link MAX_REPORT_FILES} plain files
 * are read; the files after that are named, not unpacked. A plain file larger than lib/zipread.js
 * `maxEntryBytes` is not parsed (`too-large`), whether it was dropped as it is or unpacked, so one
 * parse stays short. Archives share one budget across the drop ({@link MAX_DROP_BYTES} inflated, every
 * byte charged as lib/zipread.js charges it): past it a container is `too-large`, not opened, while a
 * plain report is still read. Before each file — a dropped one and every plain file an archive holds — the
 * event loop gets a turn once {@link READ_YIELD_MS} ms of work have passed and a Stop is heard, so
 * a page can draw the progress and stop in the middle of a zipped mailbox folder too. A Stop (the
 * signal's abort) ends the read with what it read before: the reports of the files done, those of
 * the archive it cut included, and `stopped`.
 * @param {Array<{ name: string, bytes: Uint8Array|ArrayBuffer }>} files
 * @param {{ signal?: AbortSignal, limits?: object, onProgress?: (done: number, total: number) => void }} [opts]
 *   `limits`: lib/zipread.js unpackFile bounds and `maxDropBytes` (default {@link MAX_DROP_BYTES}); `onProgress`:
 *   files read of the files known, a dropped file counting one until it is unpacked, then as the plain files inside
 *   it (at least one)
 * @returns {Promise<{ dmarc: AggregateReport[], tls: import('./tlsrpt.js').TlsReport[], problems: ReportProblem[], read: number,
 *   files: number, inflated: number, stopped: boolean }>} `read`: the plain files looked at; `files`: the dropped files
 *   read, all of them unless stopped (then those done and the one it cut once unpacked); `inflated`: the bytes the drop's
 *   archives cost; `stopped`: a Stop ended the read, which then resolves too.
 */
export async function readReportFiles(files, { signal, limits = {}, onProgress = null } = {}) {
  const out = { dmarc: [], tls: [], problems: [], read: 0, files: 0, inflated: 0, stopped: false };
  const list = Array.isArray(files) ? files : [];
  const maxBytes = Number.isFinite(limits.maxEntryBytes) ? limits.maxEntryBytes : ZIP_LIMITS.maxEntryBytes;
  const perFile = Number.isFinite(limits.maxTotalBytes) ? limits.maxTotalBytes : ZIP_LIMITS.maxTotalBytes;
  // What the drop's archives may still inflate, every dropped file together.
  let dropLeft = Number.isFinite(limits.maxDropBytes) ? Math.max(0, limits.maxDropBytes) : MAX_DROP_BYTES;
  let done = 0;
  let total = list.length;
  const step = () => {
    done += 1;
    if (onProgress) onProgress(done, total);
  };
  let turn = Date.now();
  /** A turn for the event loop once READ_YIELD_MS of work have passed; a Stop is heard here. */
  const breathe = async () => {
    if (Date.now() - turn >= READ_YIELD_MS) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      turn = Date.now();
    }
    throwIfAborted(signal);
  };
  try {
    for (const file of list) {
      await breathe();
      if (out.read >= MAX_REPORT_FILES) {
        // Full: the rest is named, not unpacked.
        out.problems.push({ path: String(file && file.name ? file.name : 'file'), code: 'too-many', detail: `${MAX_REPORT_FILES}` });
        out.files += 1;
        step();
        continue;
      }
      const name = String(file && file.name ? file.name : 'file');
      if (!dropLeft && file && containerOf(toBytes(file.bytes))) {
        // The drop's budget is spent: an archive past it is named, not opened.
        out.problems.push({ path: name, code: 'too-large', detail: 'the drop as a whole' });
        out.files += 1;
        step();
        continue;
      }
      const unpacked = await unpackFile(file, { ...limits, maxTotalBytes: Math.min(perFile, dropLeft), signal });
      dropLeft -= Math.min(dropLeft, unpacked.inflated);
      out.inflated += unpacked.inflated;
      out.problems.push(...unpacked.problems);
      out.files += 1;
      // From here the dropped file counts as the plain files inside it.
      total += Math.max(unpacked.files.length, 1) - 1;
      if (!unpacked.files.length) step();
      for (const f of unpacked.files) {
        await breathe();
        readOne(f, out, maxBytes);
        step();
      }
    }
  } catch (err) {
    // A Stop: what was read before it stays (unpackFile and the reader reject with nothing else).
    if (!(err && (err.name === 'AbortError' || err.name === 'TimeoutError'))) throw err;
    out.stopped = true;
  }
  return out;
}

/** One plain file of {@link readReportFiles} into `out`: a report, or a problem that says why not. */
function readOne(f, out, maxBytes) {
  if (out.read >= MAX_REPORT_FILES) {
    out.problems.push({ path: f.path, code: 'too-many', detail: `${MAX_REPORT_FILES}` });
    return;
  }
  out.read += 1;
  if (f.bytes.length > maxBytes) {
    out.problems.push({ path: f.path, code: 'too-large', detail: `over ${maxBytes}` });
    return;
  }
  const text = decodeReportText(f.bytes);
  const lead = text.replace(/^﻿/, '').trimStart();
  if (!lead) {
    out.problems.push({ path: f.path, code: 'empty', detail: '' });
  } else if (lead[0] === '<' && !looksLikeAggregate(lead)) {
    // Another XML document (an RSS feed, a forensic report's HTML part): not worth a full parse.
    out.problems.push({ path: f.path, code: 'not-dmarc', detail: '' });
  } else if (lead[0] === '<') {
    const r = parseAggregateReport(text, { file: f.path });
    if (r.ok) out.dmarc.push(r.report);
    else out.problems.push({ path: f.path, code: r.code, detail: r.detail });
  } else if (lead[0] === '{') {
    const r = parseTlsReport(lead, { file: f.path });
    if (r.ok) out.tls.push(r.report);
    else out.problems.push({ path: f.path, code: r.code, detail: r.detail });
  } else {
    out.problems.push({ path: f.path, code: 'not-report', detail: '' });
  }
}

/* ------------------------------------------------------------------------ */
/* Aggregation                                                              */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SourceRow
 * @property {string} ip
 * @property {4|6} version
 * @property {boolean} private a private or reserved address (an internal relay, a report of a test)
 * @property {number} messages
 * @property {number} pass messages that passed DMARC (an aligned DKIM or SPF pass)
 * @property {number} fail
 * @property {number} dkimAligned messages with an aligned DKIM pass
 * @property {number} spfAligned messages with an aligned SPF pass
 * @property {{ none: number, pass: number, quarantine: number, reject: number }} dispositions messages per {@link DISPOSITIONS}
 * @property {string[]} headerFrom
 * @property {string[]} envelopeFrom
 * @property {Array<{ domain: string, scope: string|null, result: string, messages: number }>} spfAuth
 * @property {Array<{ domain: string, selector: string|null, result: string, messages: number }>} dkimAuth
 * @property {Array<{ type: string, comment: string, messages: number }>} overrides
 * @property {string[]} reporters
 * @property {number} records
 * @property {Date|null} begin
 * @property {Date|null} end
 */

/**
 * @typedef {object} DomainAggregate
 * @property {string} domain the policy domain
 * @property {number} reports
 * @property {number} messages
 * @property {number} pass
 * @property {number} fail
 * @property {Date} begin
 * @property {Date} end
 * @property {number} days whole days the reports span (at least 1)
 * @property {AggregateReport['policy']} policy the policy of the latest report
 * @property {string[]} policies every `p` the reports saw, latest first
 * @property {Array<{ org: string, email: string|null, reports: number, messages: number, pass: number, begin: Date, end: Date }>} reporters
 * @property {SourceRow[]} sources most messages first
 * @property {string[]} errors the reporters' own error notes
 * @property {number} skipped records the reports held that could not be read
 */

const earliest = (a, b) => (!a ? b : !b ? a : a < b ? a : b);
const latest = (a, b) => (!a ? b : !b ? a : a > b ? a : b);
/** What each list addUnique / addAuth fills holds, by value: a report with many distinct values stays linear. */
const listIndex = new WeakMap();
const indexOf = (list) => {
  if (!listIndex.has(list)) listIndex.set(list, new Map());
  return listIndex.get(list);
};
const addUnique = (arr, v) => {
  const index = indexOf(arr);
  if (v && !index.has(v)) {
    index.set(v, v);
    arr.push(v);
  }
};
const bump = (map, key, make) => {
  if (!map.has(key)) map.set(key, make());
  return map.get(key);
};
const DAY_MS = 86400000;

function newSource(ip) {
  return {
    ip, version: ipVersion(ip) || 4, private: isPrivateIP(ip), messages: 0, pass: 0, fail: 0, dkimAligned: 0, spfAligned: 0,
    dispositions: Object.fromEntries(DISPOSITIONS.map((d) => [d, 0])), headerFrom: [], envelopeFrom: [],
    spfAuth: [], dkimAuth: [], overrides: [], reporters: [], records: 0, begin: null, end: null
  };
}

function addAuth(list, entry, count, keys) {
  const index = indexOf(list);
  const key = JSON.stringify(keys.map((k) => entry[k] ?? null));
  const found = index.get(key);
  if (found) found.messages += count;
  else {
    const row = { ...Object.fromEntries(keys.map((k) => [k, entry[k]])), messages: count };
    index.set(key, row);
    list.push(row);
  }
}

/**
 * Every report of each policy domain together, one row per sending address. A report dropped
 * twice (the same reporter and report id) counts once. Domains with the most messages first.
 * @param {AggregateReport[]} reports
 * @returns {{ domains: DomainAggregate[], duplicates: number }}
 */
export function aggregateDmarc(reports) {
  const seen = new Set();
  let duplicates = 0;
  const byDomain = new Map();
  for (const r of reports || []) {
    if (!r || r.kind !== 'dmarc') continue;
    if (seen.has(r.key)) {
      duplicates += 1;
      continue;
    }
    seen.add(r.key);
    const d = bump(byDomain, r.policy.domain, () => ({
      domain: r.policy.domain, reports: 0, messages: 0, pass: 0, fail: 0, begin: null, end: null, latest: null,
      pSeen: [], reporters: new Map(), sources: new Map(), errors: [], skipped: 0
    }));
    d.reports += 1;
    d.begin = earliest(d.begin, r.begin);
    d.end = latest(d.end, r.end);
    if (!d.latest || r.end > d.latest.end) d.latest = r;
    d.pSeen.push({ p: r.policy.p, end: r.end });
    d.skipped += r.skipped;
    for (const e of r.errors) addUnique(d.errors, e);
    const rep = bump(d.reporters, r.org, () => ({ org: r.org, email: r.email, reports: 0, messages: 0, pass: 0, begin: null, end: null }));
    rep.reports += 1;
    rep.begin = earliest(rep.begin, r.begin);
    rep.end = latest(rep.end, r.end);
    for (const rec of r.records) {
      const passed = rec.dkim === 'pass' || rec.spf === 'pass';
      d.messages += rec.count;
      rep.messages += rec.count;
      if (passed) {
        d.pass += rec.count;
        rep.pass += rec.count;
      } else d.fail += rec.count;
      const s = bump(d.sources, rec.ip, () => newSource(rec.ip));
      s.records += 1;
      s.messages += rec.count;
      if (passed) s.pass += rec.count;
      else s.fail += rec.count;
      if (rec.dkim === 'pass') s.dkimAligned += rec.count;
      if (rec.spf === 'pass') s.spfAligned += rec.count;
      if (Object.hasOwn(s.dispositions, rec.disposition)) s.dispositions[rec.disposition] += rec.count;
      addUnique(s.headerFrom, rec.headerFrom);
      addUnique(s.envelopeFrom, rec.envelopeFrom);
      for (const a of rec.spfAuth) addAuth(s.spfAuth, a, rec.count, ['domain', 'scope', 'result']);
      for (const a of rec.dkimAuth) addAuth(s.dkimAuth, a, rec.count, ['domain', 'selector', 'result']);
      for (const o of rec.reasons) addAuth(s.overrides, o, rec.count, ['type', 'comment']);
      addUnique(s.reporters, r.org);
      s.begin = earliest(s.begin, r.begin);
      s.end = latest(s.end, r.end);
    }
  }
  const domains = [...byDomain.values()].map((d) => {
    const pSeen = [...d.pSeen].sort((a, b) => b.end - a.end).map((x) => x.p);
    return {
      domain: d.domain,
      reports: d.reports,
      messages: d.messages,
      pass: d.pass,
      fail: d.fail,
      begin: d.begin,
      end: d.end,
      days: Math.max(1, Math.round((d.end - d.begin) / DAY_MS)),
      policy: { ...d.latest.policy },
      policies: [...new Set(pSeen)],
      reporters: [...d.reporters.values()].sort((a, b) => b.messages - a.messages || a.org.localeCompare(b.org)),
      sources: [...d.sources.values()].sort((a, b) => b.messages - a.messages || a.ip.localeCompare(b.ip)),
      errors: d.errors,
      skipped: d.skipped
    };
  }).sort((a, b) => b.messages - a.messages || a.domain.localeCompare(b.domain));
  return { domains, duplicates };
}

/* ------------------------------------------------------------------------ */
/* The current SPF                                                          */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SpfContext
 * @property {string} domain
 * @property {'ok'|'none'|'failed'|'multiple'} status `none`: no SPF record; `failed`: the lookup got no answer here
 * @property {string|null} record
 * @property {object|null} tree lib/health.js spfLookupCount().tree
 * @property {Map<string, { addresses: string[], error: string|null }>} mxAddresses the addresses of its `mx` hosts
 * @property {string|null} error
 * @property {Date} at
 */

/**
 * The domains whose SPF tells whether an aggregate's sources are authorized: each header-from
 * domain of the policy domain's organisation, and each SPF-checked domain there (a bounce
 * subdomain under relaxed alignment), most messages first, at most {@link SPF_MAX_DOMAINS}. A
 * domain of another organisation a report names is never looked up: a crafted report cannot make
 * the page ask the resolvers about names of its choosing.
 * @param {DomainAggregate} agg
 * @returns {string[]}
 */
export function spfDomainsFor(agg) {
  const weight = new Map();
  const add = (d, n) => {
    if (d) weight.set(d, (weight.get(d) || 0) + n);
  };
  const org = agg ? registrableDomain(agg.domain) || agg.domain : null;
  const inOrg = (d) => (registrableDomain(d) || d) === org;
  for (const s of agg ? agg.sources : []) {
    for (const h of s.headerFrom) if (inOrg(h)) add(h, s.messages);
    for (const a of s.spfAuth) if (inOrg(a.domain)) add(a.domain, a.messages);
  }
  if (agg && !weight.has(agg.domain)) add(agg.domain, 0);
  return [...weight].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([d]) => d).slice(0, SPF_MAX_DOMAINS);
}

/**
 * A domain's current SPF, expanded once: the include / redirect tree (lib/health.js
 * spfLookupCount) and the addresses of every host an `mx` mechanism names. Sends names and types to
 * the resolvers of `dns` only. A lookup that gets no answer is `failed`, never "no SPF".
 * @param {string} domain
 * @param {{ dns: object, signal?: AbortSignal, noCache?: boolean, now?: () => Date }} opts `dns`: a DohClient (query,
 *   resolveHost); `noCache`: every query past the client's cache (a "Check again")
 * @returns {Promise<SpfContext>} rejects only with an AbortError
 */
export async function loadSpfContext(domain, { dns: client, signal, noCache = false, now = () => new Date() } = {}) {
  const name = normalizeHostname(String(domain ?? ''));
  if (!name) throw new TypeError(`Invalid domain: ${String(domain)}`);
  const dns = noCache && client ? {
    query: (n, type, o = {}) => client.query(n, type, { ...o, noCache: true }),
    resolveHost: typeof client.resolveHost === 'function' ? (n, o = {}) => client.resolveHost(n, { ...o, noCache: true }) : undefined
  } : client;
  const base = { domain: name, status: 'failed', record: null, tree: null, mxAddresses: new Map(), error: null, at: now() };
  let r;
  try {
    r = await spfLookupCount(name, { dns, signal });
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    return { ...base, error: String((err && err.message) || err) };
  }
  const own = (code) => r.errors.find((e) => e.domain === name && e.code === code);
  if (r.tree.record === null) {
    if (own('no-record')) return { ...base, status: 'none', tree: r.tree };
    if (own('multiple-records')) return { ...base, status: 'multiple', tree: r.tree };
    return { ...base, error: (own('dns-error') || {}).detail || 'lookup failed' };
  }
  const mxAddresses = new Map();
  for (const host of spfMxHosts(r.tree).slice(0, SPF_MAX_MX_HOSTS)) {
    throwIfAborted(signal);
    try {
      const h = await dns.resolveHost(host, { signal });
      const ok = h && (h.status === 'NOERROR' || h.status === 'NXDOMAIN');
      mxAddresses.set(host, ok ? { addresses: [...(h.ipv4 || []), ...(h.ipv6 || [])], error: null } : { addresses: [], error: (h && (h.error || h.status)) || 'lookup failed' });
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      mxAddresses.set(host, { addresses: [], error: String((err && err.message) || err) });
    }
  }
  return { ...base, status: 'ok', record: r.tree.record, tree: r.tree, mxAddresses };
}

/* ------------------------------------------------------------------------ */
/* Classification                                                           */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ClassifiedSource
 * @property {string} cls one of {@link SOURCE_CLASSES}
 * @property {string} reason one of {@link CLASS_REASONS}
 * @property {string|null} detail what the reason names: a server list's names, the SPF term, the include's
 *   domain, a DKIM selector, the other domain it authenticates as
 * @property {string[]} servers the servers of the list with this address
 * @property {import('./health.js').SpfVerdict|null} spfNow the current SPF's verdict for the address, as a
 *   receiver gets it (for the domain that authorized it, else for the policy domain); null when SPF was not checked
 * @property {string|null} spfDomain the domain `spfNow` is for
 * @property {import('./health.js').SpfVerdict|null} spfListed when `spfNow` is a permerror: what the record means
 *   (health.spfEvaluate `strict: false`: no lookup limits, a syntax error passed over), else null
 * @property {number} atRisk messages that passed DMARC through SPF alone (no aligned DKIM) while the current SPF
 *   gives the address a permerror: in these reports they passed, from now on they fail
 * @property {string[]} fixes for a known source that fails DMARC or has mail at risk: {@link FIX_CODES}
 */

const orgOf = (d) => registrableDomain(d) || d;
/**
 * An SPF pass that says nothing about the address: given by `all` itself (`+all`, `all`), or by a
 * term with a /0 prefix for the address's family (`ip4:0.0.0.0/0`, `ip6:::/0`, `a/0`, `mx//0`), which
 * every address of that family matches.
 */
function passesAll(v, ip) {
  if (!v || v.result !== 'pass') return false;
  if (/^\+?all$/i.test(v.term || '')) return true;
  const t = v.term ? parseSpf(`v=spf1 ${v.term}`).terms[0] : null;
  return !!t && (ipVersion(ip) === 6 ? t.cidr6 : t.cidr4) === 0;
}
/** A verdict that tells nothing about the address: none at all, `unknown`, or a permerror. */
const untold = (v) => !v || v.result === 'unknown' || v.result === 'permerror';
const isKnown = (r) => r.cls === 'yours' || r.cls === 'third-party';

/**
 * The first organisation other than the checked domain's on the way to an SPF match: an include
 * of another organisation, or an `a` / `mx` host there. Null when the domain's own terms matched.
 */
function foreignOnPath(verdict, org) {
  for (const d of verdict.path.slice(1)) if (orgOf(d) !== org) return d;
  if (verdict.via && orgOf(verdict.via.host) !== org) return verdict.via.host;
  return null;
}

/**
 * Put each source of an aggregate into one of {@link SOURCE_CLASSES}. In order: an address of the
 * server list is yours; one the current SPF authorizes is yours (the domain's own terms) or an
 * authorized third party (an include of another organisation); one with an aligned DKIM pass is a
 * forwarder when the receiver says so, yours when all its mail passed SPF aligned too (forwarding
 * breaks SPF), a forwarder when it carries a selector the known senders use, a third party when it
 * bounces through a domain of its own, else a forwarder; the rest are unknown. When
 * the SPF could not be checked (`spf` without the domain, a lookup that failed, a term this page
 * cannot tell), an address the reports saw pass SPF aligned is counted as yours (`spf-report`).
 *
 * A permerror is what receivers get, but it hides whom the record means to authorize: then the
 * same tree is asked again without the RFC 7208 limits and past a syntax error (`spfListed`), only
 * to tell whose the sender is (`spf-listed`, `include-listed`); several SPF records, which leave no
 * tree to ask, fall back to the reports' own evidence like a failed lookup. Such a source gets the
 * `spf-permerror` fix, and `atRisk` counts its mail that passed through SPF alone.
 * @param {DomainAggregate} agg
 * @param {{ spf?: Map<string, SpfContext>, index?: Map<string, object[]> }} [opts] `index`: inventory.buildIpIndex
 * @returns {Array<SourceRow & ClassifiedSource>} in the aggregate's order
 */
export function classifySources(agg, { spf = new Map(), index = new Map() } = {}) {
  const org = orgOf(agg.domain);
  const inOrg = (d) => orgOf(d) === org;
  const rows = agg.sources.map((s) => {
    const servers = lookupServers([s.ip], index).map((x) => x.server.name || x.server.id);
    // The current SPF of every domain that could authorize it: the first pass wins.
    const domains = spfDomainsFor({ domain: agg.domain, sources: [s] });
    let spfNow = null;
    let spfDomain = null;
    for (const d of domains) {
      const c = spf.get(d);
      if (!c) continue;
      const v = c.status === 'ok' ? spfEvaluate(c.tree, s.ip, { mxAddresses: c.mxAddresses })
        : { result: c.status === 'none' ? 'none' : c.status === 'multiple' ? 'permerror' : 'unknown', term: null, holder: d, path: [d], via: null,
          reason: c.status === 'failed' ? 'lookup-failed' : c.status === 'multiple' ? 'multiple-records' : null };
      if (!spfNow || v.result === 'pass') {
        spfNow = v;
        spfDomain = d;
      }
      if (v.result === 'pass') break;
    }
    let spfListed = null;
    if (spfNow && spfNow.result === 'permerror') {
      const c = spf.get(spfDomain);
      if (c && c.status === 'ok') spfListed = spfEvaluate(c.tree, s.ip, { mxAddresses: c.mxAddresses, strict: false });
    }
    const atRisk = spfNow && spfNow.result === 'permerror' ? Math.max(0, s.pass - s.dkimAligned) : 0;
    return { ...s, servers, spfNow, spfDomain, spfListed, atRisk, cls: null, reason: null, detail: null, fixes: [] };
  });

  // Pass 1: the server list and the SPF decide. A pass by `+all` (or a /0 range) authorizes every
  // address, so it tells no sender apart (the overview's `spf-all` note says so).
  for (const r of rows) {
    const auth = r.spfNow && r.spfNow.result === 'pass' ? r.spfNow : null;
    const listed = !auth && r.spfListed && r.spfListed.result === 'pass' ? r.spfListed : null;
    const by = auth || listed;
    if (r.servers.length) {
      Object.assign(r, { cls: 'yours', reason: 'inventory', detail: r.servers.join(', ') });
    } else if (by && !passesAll(by, r.ip)) {
      const foreign = foreignOnPath(by, orgOf(r.spfDomain || agg.domain));
      Object.assign(r, foreign ? { cls: 'third-party', reason: auth ? 'spf-include' : 'include-listed', detail: foreign }
        : { cls: 'yours', reason: auth ? 'spf' : 'spf-listed', detail: by.term });
    } else if (untold(r.spfListed || r.spfNow) && r.spfAligned > 0) {
      Object.assign(r, { cls: 'yours', reason: 'spf-report', detail: null });
    }
  }
  // The DKIM selectors the known senders sign with: a message that carries one was sent by them.
  const knownSelectors = new Set(rows.filter((r) => r.cls).flatMap((r) => r.dkimAuth)
    .filter((a) => a.result === 'pass' && inOrg(a.domain) && a.selector).map((a) => `${a.domain}|${a.selector}`));

  // Pass 2: DKIM, then what is left.
  for (const r of rows) {
    if (r.cls) continue;
    const ownPass = r.dkimAuth.filter((a) => a.result === 'pass' && inOrg(a.domain));
    if (r.dkimAligned > 0 || ownPass.length) {
      const override = r.overrides.find((o) => FORWARD_OVERRIDES.includes(o.type) || (o.type === 'local_policy' && /\barc=pass\b/i.test(o.comment)));
      const carried = ownPass.find((a) => a.selector && knownSelectors.has(`${a.domain}|${a.selector}`));
      const bounce = r.spfAuth.find((a) => a.result === 'pass' && !inOrg(a.domain));
      if (override) Object.assign(r, { cls: 'forwarder', reason: 'forwarded', detail: override.type });
      else if (r.spfAligned > 0 && r.spfAligned >= r.messages) Object.assign(r, { cls: 'yours', reason: 'dkim-signed', detail: ownPass[0] ? ownPass[0].selector : null });
      else if (carried) Object.assign(r, { cls: 'forwarder', reason: 'dkim-forwarded', detail: carried.selector });
      else if (bounce) Object.assign(r, { cls: 'third-party', reason: 'dkim-service', detail: bounce.domain });
      else Object.assign(r, { cls: 'forwarder', reason: 'dkim-only', detail: ownPass[0] ? ownPass[0].selector : null });
      continue;
    }
    const other = [...r.spfAuth, ...r.dkimAuth].find((a) => a.result === 'pass' && !inOrg(a.domain));
    if (r.spfAligned > 0 && r.spfNow && r.spfNow.result !== 'pass') Object.assign(r, { cls: 'unknown', reason: 'spf-removed', detail: r.spfNow.result });
    else if (other) Object.assign(r, { cls: 'unknown', reason: 'foreign', detail: other.domain });
    else Object.assign(r, { cls: 'unknown', reason: 'none', detail: null });
  }

  // What a known source needs: a record that gives it a permerror first (it breaks SPF for every
  // sender the record lists), then, for DMARC failures, the most robust fix first.
  for (const r of rows) {
    const broken = !!r.spfNow && r.spfNow.result === 'permerror';
    if (!isKnown(r) || !(r.fail || r.atRisk)) continue;
    const fixes = broken ? ['spf-permerror'] : [];
    const ownDkim = r.dkimAuth.filter((a) => inOrg(a.domain) && a.result !== 'none');
    const foreignDkim = r.dkimAuth.some((a) => !inOrg(a.domain) && a.result === 'pass');
    // Mail at risk passed through SPF alone: DKIM would carry it past a broken record too.
    if (!ownDkim.length) fixes.push(foreignDkim ? 'dkim-align' : 'dkim-sign');
    else if (!ownDkim.some((a) => a.result === 'pass')) fixes.push('dkim-fix');
    if (r.fail) {
      const ownSpf = r.spfAuth.filter((a) => inOrg(a.domain));
      const foreignSpf = r.spfAuth.some((a) => !inOrg(a.domain) && a.result === 'pass');
      const listed = [r.spfNow, r.spfListed].some((v) => v && v.result === 'pass');
      if (ownSpf.length && !ownSpf.some((a) => a.result === 'pass') && !listed) fixes.push('spf-add');
      else if (!ownSpf.length && foreignSpf) fixes.push('spf-align');
    }
    r.fixes = fixes;
  }
  return rows;
}

/* ------------------------------------------------------------------------ */
/* The headline                                                             */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} DmarcOverview
 * @property {string} domain
 * @property {number} messages
 * @property {number} pass
 * @property {number} fail
 * @property {number|null} compliance pass / messages, null without messages
 * @property {Record<string, { sources: number, messages: number, pass: number }>} byClass per {@link SOURCE_CLASSES}
 * @property {string} verdict one of {@link DMARC_VERDICTS}
 * @property {boolean} enforced `p=reject` at 100 % and not in test mode: receivers refuse what fails now (with
 *   `spf-broken`, the mail that passed through SPF alone; with `enforced`, the blockers' failing mail)
 * @property {Array<SourceRow & ClassifiedSource>} blockers the known sources (yours, third parties) that fail DMARC,
 *   the most failing messages first: what must be fixed before `p=reject`
 * @property {number} blocked messages of theirs that fail
 * @property {Array<SourceRow & ClassifiedSource>} atRisk the known sources that pass in these reports, but through
 *   SPF alone, which now gives them a permerror; the most such messages first
 * @property {number} atRiskMessages those messages
 * @property {{ domain: string, reason: string, sources: number }|null} spfError the permerror receivers get from
 *   the current SPF (for the most mail: its domain and one of health.SPF_PERMERROR_REASONS) and for how many sources
 * @property {Array<SourceRow & ClassifiedSource>} unknown the unknown senders that fail, most messages first
 * @property {number} unknownFail messages of theirs that fail (what `p=reject` would turn away)
 * @property {string[]} notes {@link DMARC_NOTES}
 */

/**
 * The headline of one domain's reports. The verdict: `no-mail` (no message in the reports),
 * `enforced` (`p=reject` at 100 % and not in test mode: any blocker is mail rejected now),
 * `fix-first` (known sources fail), `spf-broken` (none fails in these reports, but some passed
 * through SPF alone and the current SPF gives them a permerror: with `enforced`, that mail is
 * refused now) or `ready` (every known source passes: only unknown senders would be turned away).
 * @param {DomainAggregate} agg
 * @param {Array<SourceRow & ClassifiedSource>} rows from {@link classifySources}
 * @param {{ spfChecked?: boolean }} [opts] `spfChecked`: false adds the `spf-unknown` note
 * @returns {DmarcOverview}
 */
export function dmarcOverview(agg, rows, { spfChecked = true } = {}) {
  const byClass = Object.fromEntries(SOURCE_CLASSES.map((c) => [c, { sources: 0, messages: 0, pass: 0 }]));
  for (const r of rows) {
    const b = byClass[r.cls] || byClass.unknown;
    b.sources += 1;
    b.messages += r.messages;
    b.pass += r.pass;
  }
  const blockers = rows.filter((r) => r.fail > 0 && isKnown(r)).sort((a, b) => b.fail - a.fail || b.messages - a.messages);
  const atRisk = rows.filter((r) => !r.fail && r.atRisk > 0 && isKnown(r)).sort((a, b) => b.atRisk - a.atRisk || a.ip.localeCompare(b.ip));
  const unknown = rows.filter((r) => r.fail > 0 && r.cls === 'unknown').sort((a, b) => b.fail - a.fail || a.ip.localeCompare(b.ip));
  // The permerror of the most mail, and how many sources get one.
  const errors = new Map();
  for (const r of rows) {
    if (!r.spfNow || r.spfNow.result !== 'permerror') continue;
    const e = bump(errors, `${r.spfDomain}|${r.spfNow.reason}`, () => ({ domain: r.spfDomain || agg.domain, reason: r.spfNow.reason || 'syntax', sources: 0, messages: 0 }));
    e.sources += 1;
    e.messages += r.messages;
  }
  const top = [...errors.values()].sort((a, b) => b.messages - a.messages)[0];
  const spfError = top ? { domain: top.domain, reason: top.reason, sources: [...errors.values()].reduce((n, e) => n + e.sources, 0) } : null;
  const p = agg.policy;
  const testing = p.testing === 'y';
  const enforced = p.p === 'reject' && p.pct >= 100 && !testing;
  let verdict;
  if (!agg.messages) verdict = 'no-mail';
  else if (blockers.length) verdict = enforced ? 'enforced' : 'fix-first';
  else if (atRisk.length) verdict = 'spf-broken';
  else verdict = enforced ? 'enforced' : 'ready';
  const notes = [];
  if (agg.days < SHORT_RANGE_DAYS) notes.push('short-range');
  if (p.pct < 100) notes.push('pct');
  if (testing) notes.push('testing');
  if (agg.policies.length > 1) notes.push('mixed-policy');
  if (!spfChecked) notes.push('spf-unknown');
  if (spfError) notes.push('spf-permerror');
  if (p.p === 'quarantine' && p.pct >= 100 && !testing && verdict === 'ready') notes.push('quarantine');
  if (rows.some((r) => r.dispositions.reject > 0 && isKnown(r))) notes.push('rejected-now');
  if (rows.some((r) => passesAll(r.spfNow, r.ip))) notes.push('spf-all');
  return {
    domain: agg.domain,
    messages: agg.messages,
    pass: agg.pass,
    fail: agg.fail,
    compliance: agg.messages ? agg.pass / agg.messages : null,
    byClass,
    verdict,
    enforced,
    blockers,
    blocked: blockers.reduce((n, r) => n + r.fail, 0),
    atRisk,
    atRiskMessages: atRisk.reduce((n, r) => n + r.atRisk, 0),
    spfError,
    unknown,
    unknownFail: unknown.reduce((n, r) => n + r.fail, 0),
    notes
  };
}

/* ------------------------------------------------------------------------ */
/* Export                                                                   */
/* ------------------------------------------------------------------------ */

const iso = (d) => (d instanceof Date && Number.isFinite(d.getTime()) ? d.toISOString() : '');

/**
 * One CSV row per source ({@link DMARC_CSV_COLUMNS}); lists are joined with ' ' (auth results as
 * `domain=result`, DKIM with the selector: `example.com/s1=pass`).
 * @param {DomainAggregate} agg
 * @param {Array<SourceRow & ClassifiedSource>} rows
 * @param {{ serviceOf?: (row: object) => ({ service: string, type: string, via: string, confidence: string }|null) }} [opts]
 *   serviceOf: the service behind a source (lib/senders.js identifySource, as the view has it); the
 *   service columns stay empty without it
 * @returns {object[]}
 */
export function dmarcCsvRows(agg, rows, { serviceOf = null } = {}) {
  return rows.map((r) => {
    const svc = serviceOf ? serviceOf(r) : null;
    return {
      domain: agg.domain,
      source_ip: r.ip,
      class: r.cls,
      reason: r.reason,
      detail: r.detail || '',
      servers: r.servers.join(' '),
      service: svc ? svc.service : '',
      service_type: svc ? svc.type : '',
      service_via: svc ? svc.via : '',
      service_confidence: svc ? svc.confidence : '',
      ...sourceCsvRest(r)
    };
  });
}

/** The columns of a source after its service. */
function sourceCsvRest(r) {
  return {
    messages: r.messages,
    dmarc_pass: r.pass,
    dmarc_fail: r.fail,
    spf_aligned_pass: r.spfAligned,
    dkim_aligned_pass: r.dkimAligned,
    disposition_none: r.dispositions.none,
    disposition_pass: r.dispositions.pass,
    disposition_quarantine: r.dispositions.quarantine,
    disposition_reject: r.dispositions.reject,
    spf_now: r.spfNow ? r.spfNow.result : '',
    spf_now_term: r.spfNow && r.spfNow.term ? r.spfNow.term : '',
    spf_now_reason: r.spfNow && r.spfNow.reason ? r.spfNow.reason : '',
    fixes: r.fixes.join(' '),
    header_from: r.headerFrom.join(' '),
    envelope_from: r.envelopeFrom.join(' '),
    spf_results: r.spfAuth.map((a) => `${a.domain}=${a.result}`).join(' '),
    dkim_results: r.dkimAuth.map((a) => `${a.domain}${a.selector ? `/${a.selector}` : ''}=${a.result}`).join(' '),
    overrides: r.overrides.map((o) => o.type).join(' '),
    reporters: r.reporters.join(' | '),
    first_seen: iso(r.begin),
    last_seen: iso(r.end)
  };
}
