/**
 * domain.js — hostname normalisation, eTLD+1, wildcard matching (RFC 6125)
 * and sorting helpers. DOM-free; runs in browsers and Node 22.
 *
 * All hostnames returned are lowercase ASCII (IDN → punycode), without a
 * trailing dot.
 */

import { splitList } from './util.js';

/* ------------------------------------------------------------------------ */
/* Public-suffix data                                                       */
/* ------------------------------------------------------------------------ */

/**
 * Multi-label public suffixes (a curated subset of the Mozilla Public Suffix
 * List, https://publicsuffix.org/list/). Single-label TLDs need no entry:
 * the fallback for unknown suffixes is "last two labels".
 *
 * Turkey is complete per the PSL `tr` section (TRABIS): note that since 2022
 * direct `.tr` registrations (example.tr) exist and are handled by the fallback.
 */
const MULTI_LABEL_SUFFIXES = [
  // Türkiye (all second-level domains)
  'av.tr', 'bbs.tr', 'bel.tr', 'biz.tr', 'com.tr', 'dr.tr', 'edu.tr', 'gen.tr', 'gov.tr',
  'info.tr', 'k12.tr', 'kep.tr', 'mil.tr', 'name.tr', 'net.tr', 'org.tr', 'pol.tr', 'tel.tr',
  'tsk.tr', 'tv.tr', 'web.tr', 'nc.tr', 'gov.nc.tr',
  // Northern Cyprus / Cyprus / Azerbaijan (common for Turkish users)
  'ac.cy', 'biz.cy', 'com.cy', 'ekloges.cy', 'gov.cy', 'ltd.cy', 'mil.cy', 'net.cy', 'org.cy',
  'press.cy', 'pro.cy', 'tm.cy',
  'biz.az', 'com.az', 'edu.az', 'gov.az', 'info.az', 'int.az', 'mil.az', 'name.az', 'net.az',
  'org.az', 'pp.az', 'pro.az',
  // United Kingdom
  'ac.uk', 'co.uk', 'gov.uk', 'ltd.uk', 'me.uk', 'net.uk', 'nhs.uk', 'org.uk', 'plc.uk',
  'police.uk', 'sch.uk',
  // Australia
  'asn.au', 'com.au', 'edu.au', 'gov.au', 'id.au', 'net.au', 'org.au', 'act.gov.au',
  'nsw.gov.au', 'nt.gov.au', 'qld.gov.au', 'sa.gov.au', 'tas.gov.au', 'vic.gov.au', 'wa.gov.au',
  // Japan
  'ac.jp', 'ad.jp', 'co.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp', 'ne.jp', 'or.jp',
  // Brazil
  'adv.br', 'agr.br', 'app.br', 'arq.br', 'art.br', 'blog.br', 'com.br', 'coop.br', 'dev.br',
  'eco.br', 'edu.br', 'eng.br', 'esp.br', 'etc.br', 'far.br', 'gov.br', 'ind.br', 'inf.br',
  'jor.br', 'leg.br', 'log.br', 'med.br', 'mil.br', 'net.br', 'nom.br', 'odo.br', 'org.br',
  'psi.br', 'rec.br', 'seg.br', 'srv.br', 'tec.br', 'tmp.br', 'tur.br', 'tv.br', 'vet.br',
  'wiki.br',
  // New Zealand / South Africa
  'ac.nz', 'co.nz', 'cri.nz', 'geek.nz', 'gen.nz', 'govt.nz', 'health.nz', 'iwi.nz', 'kiwi.nz',
  'maori.nz', 'mil.nz', 'net.nz', 'org.nz', 'parliament.nz', 'school.nz',
  'ac.za', 'co.za', 'edu.za', 'gov.za', 'law.za', 'mil.za', 'net.za', 'nom.za', 'org.za',
  'school.za', 'web.za',
  // China / Hong Kong / Taiwan
  'ac.cn', 'com.cn', 'edu.cn', 'gov.cn', 'mil.cn', 'net.cn', 'org.cn',
  'com.hk', 'edu.hk', 'gov.hk', 'idv.hk', 'net.hk', 'org.hk',
  'club.tw', 'com.tw', 'ebiz.tw', 'edu.tw', 'game.tw', 'gov.tw', 'idv.tw', 'mil.tw', 'net.tw',
  'org.tw',
  // Mexico / Latin America
  'com.mx', 'edu.mx', 'gob.mx', 'net.mx', 'org.mx',
  'com.ar', 'edu.ar', 'gob.ar', 'gov.ar', 'int.ar', 'mil.ar', 'net.ar', 'org.ar', 'tur.ar',
  'com.co', 'edu.co', 'gov.co', 'mil.co', 'net.co', 'nom.co', 'org.co',
  'gob.cl', 'gov.cl', 'com.pe', 'edu.pe', 'gob.pe', 'net.pe', 'nom.pe', 'org.pe',
  'com.ve', 'gob.ve', 'net.ve', 'org.ve', 'com.ec', 'gob.ec', 'net.ec', 'org.ec',
  'com.uy', 'edu.uy', 'gub.uy', 'net.uy', 'org.uy', 'com.py', 'edu.py', 'gov.py', 'net.py',
  'org.py', 'com.bo', 'gob.bo', 'net.bo', 'org.bo', 'com.gt', 'gob.gt', 'net.gt', 'org.gt',
  'com.do', 'gob.do', 'net.do', 'org.do', 'com.pa', 'gob.pa', 'net.pa', 'org.pa',
  'co.cr', 'fi.cr', 'go.cr', 'or.cr', 'com.sv', 'gob.sv', 'com.hn', 'com.ni', 'com.pr',
  // India / South & South-East Asia
  'ac.in', 'co.in', 'edu.in', 'firm.in', 'gen.in', 'gov.in', 'ind.in', 'mil.in', 'net.in',
  'nic.in', 'org.in', 'res.in',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg', 'per.sg',
  'ac.id', 'biz.id', 'co.id', 'desa.id', 'go.id', 'mil.id', 'my.id', 'net.id', 'or.id',
  'ponpes.id', 'sch.id', 'web.id',
  'biz.my', 'com.my', 'edu.my', 'gov.my', 'mil.my', 'name.my', 'net.my', 'org.my',
  'ac.th', 'co.th', 'go.th', 'in.th', 'mi.th', 'net.th', 'or.th',
  'com.vn', 'edu.vn', 'gov.vn', 'net.vn', 'org.vn',
  'com.ph', 'edu.ph', 'gov.ph', 'net.ph', 'org.ph',
  'com.pk', 'edu.pk', 'gov.pk', 'net.pk', 'org.pk', 'com.bd', 'gov.bd', 'net.bd', 'org.bd',
  'com.lk', 'gov.lk', 'com.np', 'gov.np',
  // Korea / Israel
  'ac.kr', 'co.kr', 'es.kr', 'go.kr', 'hs.kr', 'kg.kr', 'mil.kr', 'ms.kr', 'ne.kr', 'or.kr',
  'pe.kr', 're.kr', 'sc.kr',
  'ac.il', 'co.il', 'gov.il', 'idf.il', 'k12.il', 'muni.il', 'net.il', 'org.il',
  // Ukraine / Russia region / Central Asia / Caucasus
  'com.ua', 'edu.ua', 'gov.ua', 'in.ua', 'kiev.ua', 'kyiv.ua', 'net.ua', 'org.ua',
  'com.by', 'gov.by', 'com.kz', 'edu.kz', 'gov.kz', 'org.kz', 'com.uz', 'co.uz', 'com.kg',
  'com.tj', 'com.ge', 'edu.ge', 'gov.ge', 'org.ge', 'com.am',
  // Middle East / North Africa
  'ac.ae', 'co.ae', 'gov.ae', 'mil.ae', 'net.ae', 'org.ae', 'sch.ae',
  'com.sa', 'edu.sa', 'gov.sa', 'med.sa', 'net.sa', 'org.sa', 'pub.sa', 'sch.sa',
  'com.qa', 'edu.qa', 'gov.qa', 'net.qa', 'org.qa', 'com.kw', 'edu.kw', 'gov.kw', 'net.kw',
  'org.kw', 'com.bh', 'gov.bh', 'com.om', 'gov.om', 'com.jo', 'gov.jo', 'com.lb', 'gov.lb',
  'com.iq', 'gov.iq', 'co.ir', 'gov.ir', 'com.eg', 'edu.eg', 'gov.eg', 'net.eg', 'org.eg',
  'ac.ma', 'co.ma', 'gov.ma', 'net.ma', 'org.ma', 'com.tn', 'gov.tn', 'com.dz', 'gov.dz',
  'com.ly', 'gov.ly',
  // Sub-Saharan Africa
  'ac.ke', 'co.ke', 'go.ke', 'or.ke', 'com.ng', 'edu.ng', 'gov.ng', 'org.ng', 'co.tz', 'go.tz',
  'co.ug', 'go.ug', 'com.gh', 'gov.gh', 'co.zw', 'gov.zw', 'co.bw', 'co.mz', 'com.et',
  // Europe
  'ac.at', 'co.at', 'gv.at', 'or.at', 'com.pl', 'gov.pl', 'net.pl', 'org.pl', 'edu.pl',
  'com.gr', 'edu.gr', 'gov.gr', 'net.gr', 'org.gr', 'com.pt', 'edu.pt', 'gov.pt', 'org.pt',
  'com.es', 'edu.es', 'gob.es', 'nom.es', 'org.es', 'com.ro', 'org.ro', 'co.hu', 'org.hu',
  'co.rs', 'edu.rs', 'gov.rs', 'in.rs', 'org.rs', 'com.hr', 'com.mk', 'com.al', 'com.ba',
  'co.ba', 'co.me', 'edu.me', 'gov.me', 'net.me', 'org.me', 'com.mt', 'gov.mt',
  'asso.fr', 'com.fr', 'gouv.fr', 'nom.fr', 'gov.it', 'edu.it', 'priv.no', 'co.no',
  // North America
  'gc.ca', 'qc.ca', 'on.ca', 'bc.ca', 'ab.ca', 'fed.us', 'nsn.us'
];

/**
 * Popular private suffixes (PSL "PRIVATE DOMAINS" section): each customer
 * gets their own registrable name (user.github.io). Unlike ICANN suffixes,
 * certificates may carry wildcards directly below them (*.github.io), as in
 * Chromium's EXCLUDE_PRIVATE_REGISTRIES rule.
 */
const PRIVATE_SUFFIXES = [
  'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'pages.dev',
  'workers.dev', 'web.app', 'firebaseapp.com', 'appspot.com', 'azurewebsites.net',
  'cloudapp.net', 'azurestaticapps.net', 'blogspot.com', 'onrender.com', 'fly.dev',
  'up.railway.app', 'ondigitalocean.app', 'myshopify.com', 'cloudfront.net', 's3.amazonaws.com',
  'trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'glitch.me', 'surge.sh', 'duckdns.org',
  'ddns.net', 'wixsite.com', 'webflow.io', 'repl.co'
];

const ICANN_SET = new Set(MULTI_LABEL_SUFFIXES);
const SUFFIX_SET = new Set([...MULTI_LABEL_SUFFIXES, ...PRIVATE_SUFFIXES]);
const MAX_SUFFIX_LABELS = [...SUFFIX_SET].reduce((m, x) => Math.max(m, x.split('.').length), 1);

/* ------------------------------------------------------------------------ */
/* Normalisation                                                            */
/* ------------------------------------------------------------------------ */

const ASCII_HOST_RE = /^[a-z0-9._-]+$/;
// A DNS label: 1–63 chars, no leading/trailing hyphen. Underscores are
// permitted anywhere (service labels like `_dmarc`, `_domainkey`).
const LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const WRAPPER_RE = /^["'`<(\u201c\u2018]+|["'`>)\u201d\u2019]+$/g;

/**
 * Normalise a user-supplied host/URL into a lowercase ASCII hostname.
 *
 * Accepts URLs (`https://User@Www.Örnek.com.tr:443/path?q`), host:port,
 * trailing dots, quotes/angle brackets around the value, and IDNs (converted
 * to punycode with the WHATWG URL parser, available in Node and browsers).
 * Labels may contain `_` (e.g. `_dmarc`). IP literals are rejected (the last
 * label may not be numeric).
 *
 * @param {string} input
 * @param {{ allowWildcard?: boolean, allowSingleLabel?: boolean }} [opts]
 *   allowWildcard: permit a single leading `*.`;
 *   allowSingleLabel (extension, default false): accept names like `localhost`.
 * @returns {string|null}
 */
export function normalizeHostname(input, { allowWildcard = false, allowSingleLabel = false } = {}) {
  if (typeof input !== 'string') return null;
  let s = input.trim().replace(WRAPPER_RE, '').trim();
  if (!s) return null;

  // Scheme ("https://", "//").
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^\/\//, '');
  // Path, query, fragment.
  const cut = s.search(/[/?#\\]/);
  if (cut !== -1) s = s.slice(0, cut);
  // Userinfo.
  const at = s.lastIndexOf('@');
  if (at !== -1) s = s.slice(at + 1);
  if (!s || s.startsWith('[')) return null; // IPv6 literal, not a hostname
  // Port.
  const colon = s.indexOf(':');
  if (colon !== -1) {
    if (!/^:\d{0,5}$/.test(s.slice(colon))) return null;
    s = s.slice(0, colon);
  }
  // One trailing dot (absolute name).
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s) return null;

  let wildcard = false;
  if (s.startsWith('*.')) {
    if (!allowWildcard) return null;
    wildcard = true;
    s = s.slice(2);
  }
  if (s.includes('*')) return null;

  s = s.toLowerCase();
  if (!ASCII_HOST_RE.test(s)) {
    s = toAsciiHost(s);
    if (s === null) return null;
  }
  if (!isValidAsciiHostname(s, allowSingleLabel)) return null;
  const out = wildcard ? `*.${s}` : s;
  return out.length <= 253 ? out : null;
}

/** IDN → punycode through the WHATWG URL parser; null on failure. */
function toAsciiHost(host) {
  // Characters that would change how the URL parser splits the string.
  if (/[\s/?#@:[\]\\%]/.test(host)) return null;
  let hostname;
  try {
    hostname = new URL(`http://${host}`).hostname;
  } catch {
    return null;
  }
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  return ASCII_HOST_RE.test(hostname) ? hostname : null;
}

function isValidAsciiHostname(s, allowSingleLabel) {
  if (!s || s.length > 253) return false;
  const labels = s.split('.');
  if (labels.length < 2 && !allowSingleLabel) return false;
  for (const label of labels) {
    if (!LABEL_RE.test(label)) return false;
  }
  // A numeric last label means an IP address (or garbage), never a TLD.
  if (/^\d+$/.test(labels[labels.length - 1])) return false;
  return true;
}

/**
 * Parse free text (newline/space/comma/semicolon separated) into hostnames.
 * `#` comments are ignored. Arrays of strings are accepted too.
 * @param {string|string[]} text
 * @param {{ allowWildcard?: boolean, allowSingleLabel?: boolean }} [opts]
 * @returns {{ valid: string[], invalid: string[] }} both deduplicated, input order.
 */
export function parseHostList(text, opts = {}) {
  const valid = new Set();
  const invalid = new Set();
  for (const token of splitList(text)) {
    const host = normalizeHostname(token, opts);
    if (host) valid.add(host);
    else invalid.add(token);
  }
  return { valid: [...valid], invalid: [...invalid] };
}

/** Lowercase, trim and drop one trailing dot (cheap canonicalisation). */
function canon(name) {
  let s = String(name ?? '').trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

/**
 * Registrable domain (eTLD+1) using the embedded multi-label suffix list,
 * falling back to the last two labels.
 * - `www.example.com.tr` → `example.com.tr`; `a.b.example.co.uk` → `example.co.uk`
 * - A bare public suffix (`com.tr`), single labels, IPs and invalid input → null.
 * - A leading `*.` is ignored.
 * @param {string} host
 * @returns {string|null}
 */
export function registrableDomain(host) {
  let s = canon(host);
  if (s.startsWith('*.')) s = s.slice(2);
  if (!s) return null;
  if (!ASCII_HOST_RE.test(s)) {
    const n = normalizeHostname(s);
    if (!n) return null;
    s = n;
  }
  const labels = s.split('.');
  if (labels.length < 2 || labels.some((l) => !l)) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return null; // IPv4
  // Longest matching suffix first.
  for (let n = Math.min(MAX_SUFFIX_LABELS, labels.length); n >= 2; n -= 1) {
    const suffix = labels.slice(-n).join('.');
    if (SUFFIX_SET.has(suffix)) {
      return labels.length > n ? labels.slice(-(n + 1)).join('.') : null;
    }
  }
  return labels.slice(-2).join('.');
}

/**
 * Whether `name` is itself a (known) public suffix, e.g. `com.tr`, `co.uk`,
 * any single label such as `com`, or (unless `includePrivate` is false) a
 * private suffix such as `github.io`.
 * @param {string} name
 * @param {{ includePrivate?: boolean }} [opts]
 * @returns {boolean}
 */
export function isPublicSuffix(name, { includePrivate = true } = {}) {
  const s = canon(name);
  if (!s) return false;
  if (!s.includes('.')) return true;
  return includePrivate ? SUFFIX_SET.has(s) : ICANN_SET.has(s);
}

/**
 * True when `host` equals `parent` or is below it (label boundary).
 * @param {string} host
 * @param {string} parent
 * @returns {boolean}
 */
export function isSubdomainOf(host, parent) {
  const h = canon(host);
  const p = canon(parent);
  if (!h || !p) return false;
  return h === p || h.endsWith(`.${p}`);
}

/**
 * Split off a leading `*.`.
 * @param {string} name
 * @returns {{ base: string, wildcard: boolean }}
 */
export function stripWildcard(name) {
  const s = canon(name);
  if (s === '*') return { base: '', wildcard: true };
  if (s.startsWith('*.')) return { base: s.slice(2), wildcard: true };
  return { base: s, wildcard: false };
}

/**
 * RFC 6125 §6.4.3 matching of a certificate name against a host.
 * - Non-wildcard patterns match by (case-insensitive) equality.
 * - `*` must be the entire left-most label; it matches exactly one non-empty
 *   label: `*.a.com` matches `x.a.com`, not `a.com` nor `x.y.a.com`.
 * - Partial-label wildcards (`w*.a.com`, `*w.a.com`), wildcards in other
 *   positions and wildcards directly below an ICANN public suffix (`*.com`,
 *   `*.com.tr`) never match. Private suffixes are allowed (`*.github.io`).
 * @param {string} pattern
 * @param {string} host
 * @returns {boolean}
 */
export function wildcardMatches(pattern, host) {
  const p = canon(pattern);
  const h = canon(host);
  if (!p || !h) return false;
  if (!p.includes('*')) return p === h;
  if (!p.startsWith('*.')) return false;
  const base = p.slice(2);
  if (!base || base.includes('*') || isPublicSuffix(base, { includePrivate: false })) return false;
  if (p === h) return true; // a literal "*.a.com" name
  if (!h.endsWith(`.${base}`)) return false;
  const first = h.slice(0, h.length - base.length - 1);
  return first.length > 0 && !first.includes('.');
}

/**
 * Does a certificate (its hostnames/SANs) cover `host`? Exact matches win
 * over wildcard matches.
 * @param {string[]} certHostnames
 * @param {string} host
 * @returns {{ covered: boolean, by: string|null }}
 */
export function certCovers(certHostnames, host) {
  const h = canon(host);
  const names = Array.isArray(certHostnames) ? certHostnames : [];
  if (!h) return { covered: false, by: null };
  for (const name of names) {
    if (typeof name === 'string' && canon(name) === h) return { covered: true, by: name };
  }
  for (const name of names) {
    if (typeof name === 'string' && name.includes('*') && wildcardMatches(name, h)) {
      return { covered: true, by: name };
    }
  }
  return { covered: false, by: null };
}

/* ------------------------------------------------------------------------ */
/* Sorting                                                                  */
/* ------------------------------------------------------------------------ */

/** Natural comparison: digit runs compare numerically (web2 < web10). */
function naturalCompare(a, b) {
  if (a === b) return 0;
  const re = /(\d+)|(\D+)/g;
  const ta = a.match(re) || [];
  const tb = b.match(re) || [];
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i += 1) {
    const x = ta[i];
    const y = tb[i];
    if (x === y) continue;
    const dx = /^\d/.test(x);
    const dy = /^\d/.test(y);
    if (dx && dy) {
      const diff = Number(x) - Number(y);
      if (diff !== 0) return diff < 0 ? -1 : 1;
      if (x.length !== y.length) return x.length < y.length ? -1 : 1; // "01" after "1"
      continue;
    }
    return x < y ? -1 : 1;
  }
  if (ta.length !== tb.length) return ta.length < tb.length ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Sort by reversed labels so siblings group together and each apex comes
 * before its subdomains (`a.com`, `*.a.com`, `api.a.com`, `www.a.com`,
 * `b.com`…). Returns a new array; duplicates are kept.
 * @param {string[]} names
 * @returns {string[]}
 */
export function sortHostnames(names) {
  if (!Array.isArray(names)) return [];
  const keyed = names.map((name, i) => ({ name, i, labels: canon(name).split('.').reverse() }));
  keyed.sort((a, b) => {
    const n = Math.min(a.labels.length, b.labels.length);
    for (let k = 0; k < n; k += 1) {
      const c = naturalCompare(a.labels[k], b.labels[k]);
      if (c !== 0) return c;
    }
    if (a.labels.length !== b.labels.length) return a.labels.length - b.labels.length;
    return a.i - b.i;
  });
  return keyed.map((k) => k.name);
}

/**
 * Unique registrable domains for a list of names (wildcards stripped), in
 * first-seen order. Invalid names are skipped.
 * @param {string[]} names
 * @returns {string[]}
 */
export function baseDomainsFromNames(names) {
  const out = new Set();
  for (const name of Array.isArray(names) ? names : []) {
    if (typeof name !== 'string') continue;
    const { base } = stripWildcard(name);
    const host = normalizeHostname(base);
    if (!host) continue;
    const reg = registrableDomain(host);
    if (reg) out.add(reg);
  }
  return [...out];
}
