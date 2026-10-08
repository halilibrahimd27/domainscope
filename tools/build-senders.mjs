#!/usr/bin/env node
/**
 * build-senders.mjs — the reverse-DNS lists behind DMARC & TLS reports › Identify senders.
 *
 * Maintainers and the weekly workflow (.github/workflows/senders.yml) run it; the site never does.
 * No dependencies (Node 22 stdlib, plus the app's own lib/senders.js and lib/domain.js, so the page
 * reads back exactly what the build wrote). It downloads parsedmarc's reverse-DNS map at a pinned
 * commit ({@link SOURCE}), checks it and writes three small static files that lib/senders.js reads
 * on an Identify senders click:
 *
 *   assets/data/senders/ptr-map.json   the mail-relevant rows: a reverse-DNS base domain → [name,
 *                                      type], the map's types Email Provider, Email Security,
 *                                      Marketing, SaaS, IaaS, PaaS, Web Host, MSP, MSSP and
 *                                      Technology renamed as lib/senders.js PTR_TYPE_MAP says
 *   assets/data/senders/isp.json       the base domains of the map's ISP rows (no names): a sender
 *                                      there is an ISP or home network
 *   assets/data/senders/manifest.json  format, date, the source (URL, commit, SHA-256, rows,
 *                                      types), the licence and its notice, the SHA-256 and size of
 *                                      each data file, and the counts
 *
 * Why this commit. parsedmarc is Apache-2.0, and so was its map until 2026-04-26: from then on the
 * maps README distributes base_reverse_dns_map.csv under CC BY-SA 4.0 (share-alike), because new
 * rows came from IPinfo Lite (itself CC BY-SA 4.0, bundled from 2026-04-23). DomainScope (MIT)
 * bundles no share-alike data, so {@link SOURCE} is the map's last commit before IPinfo Lite came
 * in (6effd80, 2026-04-20). {@link licenceProblems} reads the LICENSE and the maps README at the
 * commit built, so a pin moved to a share-alike version fails instead of shipping.
 *
 * Nothing is written when the download looks wrong: a SHA-256 other than the pinned one, a header
 * other than `base_reverse_dns,name,type`, a quote left open, a row of the wrong width, a type the
 * map does not define, implausibly few or many rows ({@link BOUNDS}), a well-known service missing
 * or renamed ({@link CANARIES}), or a licence that is not Apache-2.0 alone. The manifest's date
 * moves only when the data does, so a rebuild with nothing new changes no file and the weekly
 * workflow opens no pull request.
 *
 * Usage:
 *   node tools/build-senders.mjs             # download (60 s at most each; cached for 12 h), build, write
 *   node tools/build-senders.mjs --offline   # use the cached downloads only
 *   SENDERS_CACHE=/path node tools/build-senders.mjs
 *
 * See assets/data/README.md for the source, its licence and what is kept.
 */

import { readFile, writeFile, mkdir, stat, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PTR_TYPE_MAP, SENDERS_FORMAT } from '../assets/js/lib/senders.js';
import { isPublicSuffix } from '../assets/js/lib/domain.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
/** Where the lists are written. */
export const OUT = join(REPO, 'assets', 'data', 'senders');
const CACHE = process.env.SENDERS_CACHE || join(tmpdir(), 'domainscope-senders');
const CACHE_MS = 12 * 3600 * 1000;
/** One download may take this long, body included. */
const DOWNLOAD_TIMEOUT_MS = 60 * 1000;

/** Format of the lists; lib/senders.js refuses another one. */
export const FORMAT = SENDERS_FORMAT;

/** parsedmarc's repository and the raw files of one of its commits. */
export const REPOSITORY = 'https://github.com/domainaware/parsedmarc';
export const rawUrl = (commit, path) => `https://raw.githubusercontent.com/domainaware/parsedmarc/${commit}/${path}`;

/**
 * The pinned source: parsedmarc's reverse-DNS map at its last Apache-2.0 commit (see the header),
 * with the SHA-256 of the CSV at that commit, and the files whose licence words are read.
 */
export const SOURCE = Object.freeze({
  id: 'parsedmarc',
  name: 'parsedmarc: base_reverse_dns_map.csv',
  repository: REPOSITORY,
  commit: '6effd806045483363428b9002b0542b651f576b6',
  committed: '2026-04-20',
  path: 'parsedmarc/resources/maps/base_reverse_dns_map.csv',
  sha256: '7b2979d682a27a8ae4ebfe8c02bf1f71798d720b04fbe61a2aa41b54b2ad2c87',
  readme: 'parsedmarc/resources/maps/README.md',
  licence: 'LICENSE'
});

/** The files downloaded for one build: the map, then the two whose licence words are checked. */
export const DOWNLOADS = Object.freeze([
  { id: 'csv', path: SOURCE.path, file: `base_reverse_dns_map-${SOURCE.commit.slice(0, 12)}.csv` },
  { id: 'readme', path: SOURCE.readme, file: `maps-README-${SOURCE.commit.slice(0, 12)}.md` },
  { id: 'licence', path: SOURCE.licence, file: `LICENSE-${SOURCE.commit.slice(0, 12)}` }
]);

/** The map's header. */
export const HEADER = Object.freeze(['base_reverse_dns', 'name', 'type']);
/** The map's `type` for an ISP row (its domain goes to isp.json). */
export const ISP_TYPE = 'ISP';
/**
 * Every type the map defines (its README's list on 2026-10-08, plus the older Insurance), compared
 * without case: the pinned commit still writes a few in lower case ('healthcare', 'Real estate').
 * Another type means the map changed its vocabulary, and a mail-relevant row could be lost.
 */
export const KNOWN_TYPES = Object.freeze([
  'Agriculture', 'Automotive', 'Beauty', 'Conglomerate', 'Construction', 'Consulting', 'Defense', 'Education', 'Email Provider', 'Email Security',
  'Entertainment', 'Event Planning', 'Finance', 'Food', 'Government', 'Government Media', 'Healthcare', 'IaaS', 'Industrial', 'Insurance', 'ISP', 'Legal',
  'Logistics', 'Manufacturing', 'Marketing', 'MSP', 'MSSP', 'News', 'Nonprofit', 'PaaS', 'Photography', 'Physical Security', 'Print', 'Publishing',
  'Real Estate', 'Religion', 'Retail', 'SaaS', 'Science', 'Search Engine', 'Social Media', 'Sports', 'Staffing', 'Technology', 'Travel', 'Utilities',
  'Web Host'
]);
/** Plausible counts (the pinned commit: 3,133 rows, 1,349 mail-relevant, 950 ISP). Outside them nothing is written. */
export const BOUNDS = Object.freeze({ rows: [2000, 200000], ptr: [800, 60000], isp: [500, 60000] });
/**
 * Rows that must be there with this type and a name matching the pattern, or the download is not
 * the map it claims to be.
 */
export const CANARIES = Object.freeze([
  ['google.com', /^Google\b/, 'Email Provider'],
  ['outlook.com', /^Outlook\b/, 'Email Provider'],
  ['amazonses.com', /^Amazon SES\b/, 'SaaS'],
  ['sendgrid.net', /SendGrid/, 'Marketing'],
  ['mcsv.net', /Mailchimp/, 'Marketing']
]);
/** The licence the data is used under, and the notice that travels with it. */
export const LICENCE = Object.freeze({
  spdx: 'Apache-2.0',
  name: 'Apache License, Version 2.0',
  copyright: 'parsedmarc: Sean Whalen and contributors',
  notice: `Contains data from parsedmarc (${REPOSITORY}), base_reverse_dns_map.csv at commit ${SOURCE.commit.slice(0, 7)}, `
    + 'Copyright Sean Whalen and contributors, licensed under the Apache License, Version 2.0. Changed by tools/build-senders.mjs: '
    + 'only the mail-relevant rows kept (types renamed), the ISP rows reduced to their base domains, names trimmed.'
});

/** A download or a row that is not what the source should hold. */
export class SenderDataError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SenderDataError';
  }
}

const fail = (msg) => { throw new SenderDataError(msg); };
const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');
const day = (d) => d.toISOString().slice(0, 10);
/** A host name as the lists hold it (lib/senders.js reads back the same shape). */
const NAME_RE = /^(?=.{3,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/;

/**
 * RFC 4180 CSV: fields split by commas, a field in double quotes may hold commas, line breaks and
 * doubled quotes (`""`); CRLF or LF line ends; a BOM is dropped; blank lines are skipped. A quote
 * left open, or text after a closing quote, throws a {@link SenderDataError}. Pure.
 * @param {string} text
 * @returns {string[][]}
 */
export function parseCsv(text) {
  if (typeof text !== 'string') fail('csv: no text');
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let wasQuoted = false;
  let line = 1;
  const endField = () => {
    row.push(field);
    field = '';
    wasQuoted = false;
  };
  const endRow = () => {
    endField();
    if (!(row.length === 1 && row[0] === '')) rows.push(row);
    row = [];
  };
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
          wasQuoted = true;
        }
      } else {
        if (c === '\n') line += 1;
        field += c;
      }
    } else if (c === '"') {
      if (field !== '' || wasQuoted) fail(`csv: line ${line}: a quote inside an unquoted field`);
      quoted = true;
    } else if (c === ',') {
      endField();
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i += 1;
      endRow();
      line += 1;
    } else {
      if (wasQuoted) fail(`csv: line ${line}: text after a closing quote`);
      field += c;
    }
  }
  if (quoted) fail(`csv: line ${line}: a quote is never closed (a cut download?)`);
  if (field !== '' || row.length) endRow();
  return rows;
}

/**
 * What the LICENSE and the maps README at the commit built say about the map's licence: the
 * LICENSE must be the Apache License 2.0, and the README must not put the map under a share-alike
 * licence (CC BY-SA, as parsedmarc's README does from 2026-04-26). Pure.
 * @param {{ licence: string, readme: string }} texts
 * @returns {string[]} problems (empty when the licence is fine)
 */
export function licenceProblems({ licence, readme }) {
  const problems = [];
  if (typeof licence !== 'string' || !/Apache License\s+Version 2\.0/i.test(licence)) problems.push('LICENSE: not the Apache License 2.0');
  if (typeof readme !== 'string' || !readme.trim()) problems.push('maps README: missing');
  else if (/CC[\s-]*BY[\s-]*SA|Attribution[\s-]*ShareAlike|creativecommons\.org\/licenses\/by-sa/i.test(readme)) {
    problems.push('maps README: the map is under a share-alike licence (CC BY-SA) at this commit; DomainScope bundles only an Apache-2.0 version of it');
  }
  return problems;
}

/** The canonical spelling of a known type, or null. */
const knownType = (() => {
  const byLower = new Map(KNOWN_TYPES.map((t) => [t.toLowerCase(), t]));
  return (t) => byLower.get(String(t).trim().toLowerCase()) || null;
})();

/** One entry a line, keys in order: small diffs in the weekly pull request. */
function ptrMapJson(map) {
  const keys = Object.keys(map).sort();
  const body = keys.map((k) => `${JSON.stringify(k)}: ${JSON.stringify(map[k])}`).join(',\n');
  return `{\n"format": ${FORMAT},\n"notice": ${JSON.stringify(LICENCE.notice)},\n"map": {\n${body}\n}\n}\n`;
}

function ispJson(domains) {
  const body = [...domains].sort().map((d) => JSON.stringify(d)).join(',\n');
  return `{\n"format": ${FORMAT},\n"notice": ${JSON.stringify(LICENCE.notice)},\n"domains": [\n${body}\n]\n}\n`;
}

/**
 * The SHA-256 of the lists: each data file's name and content, in name order, then the manifest
 * without `generated` and `digest`, as compact JSON. Equal digests: nothing changed.
 * @param {Map<string, string>} files name → content (manifest.json left out)
 * @param {object} body the manifest without generated and digest
 * @returns {string} lowercase hex
 */
export function datasetDigest(files, body) {
  const digest = createHash('sha256');
  for (const name of [...files.keys()].filter((f) => f !== 'manifest.json').sort()) digest.update(`${name}\n${files.get(name)}\n`);
  digest.update(`manifest.json\n${JSON.stringify(body)}\n`);
  return digest.digest('hex');
}

/**
 * Build the lists from the downloaded files. Pure: no I/O.
 * @param {{ csv: string, csvSha256?: string|null, readme: string, licence: string, previous?: object|null, now?: Date,
 *   source?: object, bounds?: object, canaries?: ReadonlyArray<[string, RegExp, string]> }} input
 *   csv: the map's text; csvSha256: the SHA-256 of its bytes (default: of the text as UTF-8); readme / licence:
 *   the maps README and the LICENSE at the commit; previous: the manifest on disk (its date is kept when nothing
 *   changed); source / bounds / canaries: the checks ({@link SOURCE}, {@link BOUNDS}, {@link CANARIES}; tests pass their own)
 * @returns {{ files: Map<string, string>, manifest: object, report: { problems: string[], counts: object, skipped: object } }}
 *   files: name relative to assets/data/senders → content; problems: why nothing may be written (empty when the data is fine)
 */
export function buildSenders({
  csv, csvSha256 = null, readme, licence, previous = null, now = new Date(), source = SOURCE, bounds = BOUNDS, canaries = CANARIES
}) {
  const problems = [...licenceProblems({ licence, readme })];
  const skipped = { name: 0, key: 0, suffix: 0, duplicate: 0 };
  const sha256 = csvSha256 || (typeof csv === 'string' ? sha256Hex(Buffer.from(csv, 'utf8')) : '');
  if (source.sha256 && sha256 !== source.sha256) problems.push(`csv: SHA-256 ${sha256 || '(none)'}, the pinned commit has ${source.sha256}`);
  let rows = [];
  try {
    rows = parseCsv(csv);
  } catch (err) {
    if (!(err instanceof SenderDataError)) throw err;
    problems.push(err.message);
  }
  const [header, ...data] = rows;
  if (rows.length && (header.length !== HEADER.length || header.some((h, i) => h.trim() !== HEADER[i]))) {
    problems.push(`csv: header ${JSON.stringify(header.join(','))}, expected ${HEADER.join(',')}`);
  }
  const ptr = {};
  const isp = new Set();
  const seen = new Set();
  const unknownTypes = new Map();
  const byType = {};
  let wrongWidth = 0;
  for (const r of rows.length ? data : []) {
    if (r.length !== HEADER.length) {
      wrongWidth += 1;
      continue;
    }
    const key = r[0].trim().toLowerCase().replace(/\.$/, '');
    const name = r[1].replace(/\s+/g, ' ').trim();
    const type = knownType(r[2]);
    if (!type) {
      unknownTypes.set(r[2].trim(), (unknownTypes.get(r[2].trim()) || 0) + 1);
      continue;
    }
    if (!NAME_RE.test(key)) {
      skipped.key += 1;
      continue;
    }
    if (isPublicSuffix(key, { includePrivate: false })) {
      skipped.suffix += 1;
      continue;
    }
    if (seen.has(key)) {
      skipped.duplicate += 1;
      continue;
    }
    seen.add(key);
    byType[type] = (byType[type] || 0) + 1;
    if (type === ISP_TYPE) {
      isp.add(key);
    } else if (Object.hasOwn(PTR_TYPE_MAP, type)) {
      if (!name || name.length > 200 || /[\u0000-\u001f\u007f]/.test(name)) {
        skipped.name += 1;
        continue;
      }
      ptr[key] = [name, PTR_TYPE_MAP[type]];
    }
  }
  if (wrongWidth) problems.push(`csv: ${wrongWidth} rows without exactly ${HEADER.length} fields`);
  for (const [t, n] of unknownTypes) problems.push(`csv: unknown type ${JSON.stringify(t)} (${n} rows)`);
  if (skipped.key > Math.max(10, data.length / 100)) problems.push(`csv: ${skipped.key} rows whose base domain is not a host name`);
  const counts = { rows: data.length, types: Object.keys(byType).length, ptr: Object.keys(ptr).length, isp: isp.size };
  for (const [what, n] of [['rows', counts.rows], ['ptr', counts.ptr], ['isp', counts.isp]]) {
    const b = bounds[what];
    if (b && (n < b[0] || n > b[1])) problems.push(`${what}: ${n}, expected ${b[0]}–${b[1]}`);
  }
  if (!problems.length) {
    for (const [key, re, type] of canaries) {
      const entry = type === ISP_TYPE ? (isp.has(key) ? [key, 'isp'] : null) : ptr[key];
      if (!entry) problems.push(`canary ${key}: missing`);
      else if (type !== ISP_TYPE && (!re.test(entry[0]) || entry[1] !== PTR_TYPE_MAP[type])) {
        problems.push(`canary ${key}: ${JSON.stringify(entry)}, expected a name matching ${re} and type ${PTR_TYPE_MAP[type]}`);
      }
    }
  }
  const files = new Map([['ptr-map.json', ptrMapJson(ptr)], ['isp.json', ispJson(isp)]]);
  const body = {
    format: FORMAT,
    source: {
      id: source.id,
      name: source.name,
      repository: source.repository,
      url: rawUrl(source.commit, source.path),
      commit: source.commit,
      committed: source.committed,
      sha256,
      rows: counts.rows,
      types: counts.types
    },
    licence: { spdx: LICENCE.spdx, name: LICENCE.name, copyright: LICENCE.copyright, url: rawUrl(source.commit, source.licence), notice: LICENCE.notice },
    files: Object.fromEntries([...files].map(([name, text]) => [name, { bytes: Buffer.byteLength(text), sha256: sha256Hex(text) }])),
    counts: { ptr: counts.ptr, isp: counts.isp, byType: Object.fromEntries(Object.entries(byType).sort(([a], [b]) => a.localeCompare(b))) }
  };
  const digest = datasetDigest(files, body);
  const generated = previous && previous.digest === digest && typeof previous.generated === 'string' ? previous.generated : day(now);
  const manifest = { format: FORMAT, generated, digest, ...Object.fromEntries(Object.entries(body).filter(([k]) => k !== 'format')) };
  files.set('manifest.json', `${JSON.stringify(manifest, null, 2)}\n`);
  return { files, manifest, report: { problems, counts, skipped } };
}

/**
 * Download one file of the pinned commit (or read the cached copy, 12 h), as its bytes. The CSV
 * must decode as UTF-8; an HTML error page answered with 200 is neither cached nor read.
 * @param {{ id: string, path: string, file: string }} item a {@link DOWNLOADS} entry
 * @param {{ commit?: string, offline?: boolean, cache?: string, fetchImpl?: typeof fetch, timeoutMs?: number, log?: (line: string) => void }} [opts]
 * @returns {Promise<{ text: string, sha256: string }>}
 */
export async function downloadFile(item, {
  commit = SOURCE.commit, offline = false, cache = CACHE, fetchImpl = globalThis.fetch, timeoutMs = DOWNLOAD_TIMEOUT_MS,
  log = (line) => process.stdout.write(`${line}\n`)
} = {}) {
  const file = join(cache, item.file);
  const check = (bytes) => {
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new SenderDataError(`${item.path}: not UTF-8 text`);
    }
    if (/^\s*<(?:!doctype|html)/i.test(text)) throw new SenderDataError(`${item.path}: an HTML page, not the file`);
    return { text, sha256: sha256Hex(bytes) };
  };
  try {
    const st = await stat(file);
    if (offline || Date.now() - st.mtimeMs < CACHE_MS) {
      const bytes = await readFile(file);
      try {
        return check(bytes);
      } catch (err) {
        await rm(file, { force: true });
        if (offline) throw new Error(`--offline: ${file}: ${err.message} (the cached copy was deleted)`);
        log(`${file}: ${err.message}; the cached copy was deleted`);
      }
    }
  } catch (err) {
    if (offline) throw err.code === 'ENOENT' ? new Error(`--offline: ${file} is not cached`) : err;
  }
  const url = rawUrl(commit, item.path);
  log(`downloading ${url}`);
  let bytes;
  try {
    const res = await fetchImpl(url, {
      headers: { 'user-agent': 'domainscope-build-senders (+https://github.com/halilibrahimd27/domainscope)' },
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    bytes = new Uint8Array(await res.arrayBuffer());
  } catch (err) {
    if (err && err.name === 'TimeoutError') throw new Error(`${url}: no complete answer within ${timeoutMs / 1000} s`);
    throw err;
  }
  let out;
  try {
    out = check(bytes);
  } catch (err) {
    throw new Error(`${url}: ${err.message} (not cached)`);
  }
  await mkdir(cache, { recursive: true });
  await writeFile(file, bytes);
  return out;
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Download, build and write the lists into `out` — or, when a check fails, write nothing and
 * reject with every problem.
 * @param {{ out?: string, offline?: boolean, cache?: string, fetchImpl?: typeof fetch, now?: Date, log?: (line: string) => void,
 *   source?: object, bounds?: object, canaries?: ReadonlyArray<[string, RegExp, string]> }} [opts]
 * @returns {Promise<{ changed: number, manifest: object, report: object }>}
 */
export async function run({
  out = OUT, offline = false, cache = CACHE, fetchImpl = globalThis.fetch, now = new Date(), log = (line) => process.stdout.write(`${line}\n`),
  source = SOURCE, bounds = BOUNDS, canaries = CANARIES
} = {}) {
  const got = {};
  for (const item of DOWNLOADS) {
    const path = item.id === 'csv' ? source.path : item.id === 'readme' ? source.readme : source.licence;
    got[item.id] = await downloadFile({ ...item, path }, { commit: source.commit, offline, cache, fetchImpl, log });
  }
  const previous = await readJson(join(out, 'manifest.json'));
  const { files, manifest, report } = buildSenders({
    csv: got.csv.text, csvSha256: got.csv.sha256, readme: got.readme.text, licence: got.licence.text, previous, now, source, bounds, canaries
  });
  log(`rows ${report.counts.rows}, types ${report.counts.types}: ptr-map ${report.counts.ptr}, isp ${report.counts.isp}`
    + ` (left out: ${Object.entries(report.skipped).map(([k, n]) => `${k} ${n}`).join(', ')})`);
  if (report.problems.length) {
    throw new Error(`the download looks wrong, nothing written:\n  ${report.problems.join('\n  ')}\n`
      + 'If parsedmarc really changed its map, adjust SOURCE, BOUNDS, KNOWN_TYPES or CANARIES in tools/build-senders.mjs.');
  }
  await mkdir(out, { recursive: true });
  let changed = 0;
  for (const [name, content] of files) {
    const path = join(out, name);
    let old = null;
    try { old = await readFile(path, 'utf8'); } catch { /* new file */ }
    if (old === content) continue;
    await writeFile(path, content);
    changed += 1;
  }
  log(`${changed} file(s) changed, lists of ${manifest.generated}`);
  return { changed, manifest, report };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  run({ offline: process.argv.includes('--offline') }).catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
