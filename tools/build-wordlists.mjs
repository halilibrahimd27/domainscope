#!/usr/bin/env node
/**
 * build-wordlists.mjs — reproducible builder for the DomainScope wordlists.
 *
 * No dependencies (Node 22 stdlib only). It downloads a fixed set of permissively
 * licensed subdomain wordlists (pinned to a commit SHA), normalises every label,
 * ranks them by real-world frequency across the sources, and writes the tiered
 * global lists plus the curated per-market locale packs consumed by
 * `assets/js/lib/wordlist.js`:
 *
 *   assets/data/wordlist-base.txt        ~7k  global smart base (plain text)
 *   assets/data/wordlist-large.txt.gz    ~50k base ∪ ranked extension (gzip)
 *   assets/data/wordlist-huge.txt.gz     ~130k full ranked list (gzip)
 *   assets/data/locale/<cc>.txt          curated market packs (plain text)
 *   assets/data/wordlist-manifest.json   counts / bytes / SHA-256 / sources / licences
 *
 * Ranking: reciprocal-rank fusion (RRF) across the ranked sources, with the
 * SecLists top-1M list (Cloudflare-derived real usage) as the primary signal,
 * bitquark second, commonspeak2 a weak presence signal, and the hand-curated
 * core (WORDLIST_SMALL / MEDIUM) and devops permutation vocabularies boosted so
 * the head of every tier is dependable. Tiers are strict prefixes of one master
 * ranking, so base ⊂ large ⊂ huge.
 *
 * Usage:
 *   node tools/build-wordlists.mjs            # build from cache, download if missing
 *   node tools/build-wordlists.mjs --offline  # fail instead of downloading
 *   WORDLIST_CACHE=/path node tools/build-wordlists.mjs
 *
 * The download cache lives outside the repo (default: <os tmp>/domainscope-wordlists)
 * and never ships with the site; tools/ is not part of the Pages bundle.
 */

import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WORDLIST_SMALL, WORDLIST_MEDIUM } from '../assets/js/lib/wordlist.js';
import { LOCALE_PACKS, LOCALE_NOTE } from './locale-data.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const DATA = join(REPO, 'assets', 'data');
const CACHE = process.env.WORDLIST_CACHE || join(tmpdir(), 'domainscope-wordlists');
const OFFLINE = process.argv.includes('--offline');

/* ------------------------------------------------------------------------ */
/* Sources (verified permissive; SHAs pinned 2026-09-23)                     */
/* ------------------------------------------------------------------------ */

const RAW = 'https://raw.githubusercontent.com';
const SECLISTS_SHA = '7ee9b27880ef4a2400c4940956875721f025f76b';
const BITQUARK_SHA = SECLISTS_SHA; // vendored inside SecLists Discovery/DNS
const CS2_SHA = 'a514ff1becb4254a4a11a14e668d9313a3a6f9ed';
const DNSGEN_SHA = '7c98e7ecda2f626d49c47be9c98b234a2e4db5b7';
const ALTDNS_SHA = '6728272cbda8b8ceca4d59f4398e81df921853f2';

/**
 * @typedef {Object} Source
 * @property {string} id
 * @property {string} file       cache filename
 * @property {string} url        pinned raw URL
 * @property {'ranked'|'flat'} kind   ranked = order is a frequency signal
 * @property {number} weight     contribution to the fusion score
 * @property {string} licence
 * @property {string} project    upstream repo URL
 */

/** @type {Source[]} */
const SOURCES = [
  {
    id: 'seclists', file: 'seclists-top1m-110000.txt',
    url: `${RAW}/danielmiessler/SecLists/${SECLISTS_SHA}/Discovery/DNS/subdomains-top1million-110000.txt`,
    kind: 'ranked', weight: 3.0, licence: 'MIT',
    project: 'https://github.com/danielmiessler/SecLists'
  },
  {
    id: 'bitquark', file: 'bitquark-top100000.txt',
    url: `${RAW}/danielmiessler/SecLists/${BITQUARK_SHA}/Discovery/DNS/bitquark-subdomains-top100000.txt`,
    kind: 'ranked', weight: 1.6, licence: 'MIT (bitquark/dnspop, vendored in SecLists)',
    project: 'https://github.com/bitquark/dnspop'
  },
  {
    id: 'commonspeak2', file: 'commonspeak2-subdomains.txt',
    url: `${RAW}/assetnote/commonspeak2-wordlists/${CS2_SHA}/subdomains/subdomains.txt`,
    kind: 'ranked', weight: 0.6, licence: 'Apache-2.0',
    project: 'https://github.com/assetnote/commonspeak2-wordlists'
  },
  {
    id: 'dnsgen', file: 'dnsgen-words.txt',
    url: `${RAW}/AlephNullSK/dnsgen/${DNSGEN_SHA}/dnsgen/words.txt`,
    kind: 'flat', weight: 2.0, licence: 'MIT',
    project: 'https://github.com/AlephNullSK/dnsgen'
  },
  {
    id: 'altdns', file: 'altdns-words.txt',
    url: `${RAW}/infosec-au/altdns/${ALTDNS_SHA}/words.txt`,
    kind: 'flat', weight: 1.6, licence: 'Apache-2.0',
    project: 'https://github.com/infosec-au/altdns'
  },
  {
    id: 'services', file: 'seclists-services-names.txt',
    url: `${RAW}/danielmiessler/SecLists/${SECLISTS_SHA}/Discovery/DNS/services-names.txt`,
    kind: 'flat', weight: 1.2, licence: 'MIT',
    project: 'https://github.com/danielmiessler/SecLists'
  }
];

/* ------------------------------------------------------------------------ */
/* Normalisation                                                             */
/* ------------------------------------------------------------------------ */

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const HEX_HASH_RE = /^[0-9a-f]{16,}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// Ranked (frequency) sources. Flat vocabularies are only a tie-breaker for
// labels these already contain, and a bitquark-only label (its passive-DNS data
// is full of wildcard-spam zones) is dropped for want of corroboration.
const RANKED_SOURCE_IDS = new Set(['seclists', 'bitquark', 'commonspeak2']);
const CORROBORATING_IDS = new Set(['seclists', 'bitquark', 'commonspeak2', 'core']);

/**
 * Content / quality filter — a global public product must not ship these:
 *  - Chinese gambling / SEO spam that fills bitquark's passive-DNS zones;
 *  - keyboard-mash strings from the bitquark head;
 *  - Cloudflare's internal cf-protected* labels;
 *  - adult / profanity / sexual-violence / slur / pharma-spam labels.
 * Generic business labels (casino, bet, sex, xxx, adult) are kept: they are real
 * subdomains on gambling / adult operators' own zones.
 */
export const GAMBLING_SEO_RE = /(bocai|baijia|yulecheng|touzhu|caipiao|shishicai|zhenren|taiyangcheng|liuhecai|zoushitu|bifen|wangzhi|duchang|aomen|pujing|huangguan|qipai|douniu|zuqiu|zhibo|dezhoupuke|lasiwei|zhanshenyule|dafapuke|hunyindiaocha)/;
export const KEYBOARD_MASH = new Set([
  '2tty', 'govyty', 'hgfgdf', '1rer', 'lkjkui', 'hfgfgf', 'yty', 'lkljk', 'zcvbnnn', 'dsasa',
  'tgrrre', 'wxsxc', 'tgtggb', 'oilkjm', 'wqwqw', 'mkuu', 'iuyuy', 'rerew', 'iuyuyt', 'khjghg',
  'qwqee', 'qwrer', 'mjurr', 'qwqwq'
]);
export const CONTENT_DENYLIST = new Set([
  // profanity
  'fuck', 'fucker', 'fuckoff', 'fuckyou', 'cunt', 'bitch', 'pussy',
  // sexual violence / CSAM-adjacent
  'lolita', 'incest', 'rape', 'pedo',
  // explicit sexual
  'porn', 'analsex', 'nudegirls', 'hentai', 'milf', 'shemale', 'bdsm', 'fetish',
  // piracy
  'warez',
  // slurs / hate
  'nazi',
  // pharma spam
  'viagra', 'cialis'
]);

/** True when a label must not appear in any shipped tier. */
export function isBannedLabel(label) {
  if (CONTENT_DENYLIST.has(label) || KEYBOARD_MASH.has(label)) return true;
  if (label.startsWith('cf-protected')) return true;
  if (GAMBLING_SEO_RE.test(label)) return true;
  return false;
}

/**
 * Normalise a raw source line to a single clean DNS label, or `null` to drop it.
 * Rules: lowercase; single label only (no dots / underscores); charset a-z0-9-,
 * 1–63, no leading/trailing '-'; drop obvious junk (hashes, uuids, over-long
 * tokens, numeric-only beyond small numbers, mostly-numeric tokens).
 * @param {string} raw
 * @returns {string|null}
 */
export function normalizeLabel(raw) {
  let s = String(raw ?? '').trim().toLowerCase();
  if (!s || s.startsWith('#')) return null;
  // A few sources carry a trailing dot or "*." wildcard; strip those.
  s = s.replace(/^\*+\./, '').replace(/\.+$/, '');
  if (!s || s.includes('.') || s.includes('_')) return null;
  if (s.length > 30) return null;                 // over-long → almost always junk
  if (!LABEL_RE.test(s)) return null;
  if (UUID_RE.test(s) || HEX_HASH_RE.test(s)) return null;
  const digits = (s.match(/[0-9]/g) || []).length;
  if (/^[0-9]+$/.test(s)) { if (s.length > 3) return null; } // keep 0–999 only
  else if (digits >= 10) return null;             // mostly-numeric noise
  return s;
}

/* ------------------------------------------------------------------------ */
/* Download / cache                                                          */
/* ------------------------------------------------------------------------ */

async function ensureSource(src) {
  const path = join(CACHE, src.file);
  if (existsSync(path)) return path;
  if (OFFLINE) throw new Error(`missing cached source ${src.file} and --offline set`);
  process.stderr.write(`  downloading ${src.id} …\n`);
  const res = await fetch(src.url);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${src.url}`);
  const text = await res.text();
  await mkdir(CACHE, { recursive: true });
  await writeFile(path, text);
  return path;
}

/* ------------------------------------------------------------------------ */
/* Ranking                                                                   */
/* ------------------------------------------------------------------------ */

const RRF_K = 100;

/**
 * Build the master ranking. Every label gets a fusion score; higher = more
 * likely. Core curated labels and devops vocabularies are boosted so the head
 * of the list is dependable regardless of the noisy long tail.
 * @param {Map<string,string[]>} sourceLabels  id → normalised, ordered, deduped labels
 * @returns {{ ranked: string[], score: Map<string,number>, present: Map<string,Set<string>> }}
 */
function rank(sourceLabels) {
  const score = new Map();
  const present = new Map(); // label → set of source ids it appears in
  const bump = (label, add, id) => {
    score.set(label, (score.get(label) || 0) + add);
    if (id) {
      let set = present.get(label);
      if (!set) present.set(label, (set = new Set()));
      set.add(id);
    }
  };
  const hasRankedEvidence = (label) => {
    const set = present.get(label);
    return !!set && [...set].some((id) => RANKED_SOURCE_IDS.has(id));
  };

  // 1. Frequency (ranked) sources first, so the flat / curated boosts below can
  //    condition on real evidence.
  for (const src of SOURCES) {
    if (src.kind !== 'ranked') continue;
    const labels = sourceLabels.get(src.id) || [];
    labels.forEach((label, i) => bump(label, src.weight / (RRF_K + i) * 1000, src.id));
  }

  // 2. Curated core. WORDLIST_SMALL is the guaranteed language-neutral core and
  //    always leads. The MEDIUM extras only get the full curated boost when a
  //    ranked source corroborates them; an evidence-free curated label keeps a
  //    small score (kept, but not guaranteed a top slot ahead of real names).
  const smallSet = new Set();
  WORDLIST_SMALL.forEach((w) => { const l = normalizeLabel(w); if (l) smallSet.add(l); });
  WORDLIST_MEDIUM.forEach((w, i) => {
    const label = normalizeLabel(w);
    if (!label || smallSet.has(label)) return;
    bump(label, hasRankedEvidence(label) ? 40 - Math.min(38, i / 40) : 2, 'core');
  });
  WORDLIST_SMALL.forEach((w, i) => {
    const label = normalizeLabel(w);
    if (label) bump(label, 60 - i / 10, 'core');
  });

  // 3. Flat vocabularies (services-names, dnsgen, altdns) are only a small
  //    tie-breaker, and only for a label a ranked source or the curated core
  //    already holds — never enough to pull an arbitrary English word or a
  //    dnsgen template token (woman, yacht, port-27017) into a tier on its own.
  for (const src of SOURCES) {
    if (src.kind === 'ranked') continue;
    const labels = sourceLabels.get(src.id) || [];
    labels.forEach((label) => { if (score.has(label)) bump(label, 0.05, src.id); });
  }

  // 4. Multi-list agreement bonus, scaled down and counting only independent
  //    ranked sources + the curated core (flat presence does not inflate it).
  for (const [label, set] of present) {
    const n = [...set].filter((id) => CORROBORATING_IDS.has(id)).length;
    if (n >= 2) bump(label, 0.15 * (n - 1));
  }

  // 5. Drop banned content and single-source-bitquark labels (no corroboration:
  //    bitquark's passive-DNS data is full of wildcard-spam zones).
  const keep = (label) => {
    if (isBannedLabel(label)) return false;
    const set = present.get(label);
    if (set && set.size === 1 && set.has('bitquark')) return false;
    return true;
  };

  const ranked = [...score.keys()].filter(keep).sort((a, b) => {
    const d = score.get(b) - score.get(a);
    if (d) return d;
    if (a.length !== b.length) return a.length - b.length;
    return a < b ? -1 : 1;
  });
  return { ranked, score, present };
}

/* ------------------------------------------------------------------------ */
/* Output                                                                    */
/* ------------------------------------------------------------------------ */

const BASE_N = 7000;
const LARGE_N = 50000;
const HUGE_N = 130000;

function toFile(labels) { return labels.join('\n') + '\n'; }

/**
 * Size and SHA-256 (hex) of a written file. The service worker keys its wordlist cache by the
 * hash, so a tier downloaded once is reused across deploys until its content changes.
 * @param {Buffer} buf
 * @returns {{ bytes: number, sha256: string }}
 */
export function fileDigest(buf) {
  return { bytes: buf.length, sha256: createHash('sha256').update(buf).digest('hex') };
}

async function writeText(name, labels) {
  const body = Buffer.from(toFile(labels));
  await writeFile(join(DATA, name), body);
  return fileDigest(body);
}

async function writeGz(name, labels) {
  const gz = gzipSync(Buffer.from(toFile(labels)), { level: 9 });
  // Reproducibility: zlib writes the host OS into gzip header byte 9 (0x0a on
  // Windows, 0x03 on Unix), so the same content produces different bytes on
  // different platforms. Pin it to 0xff ("unknown"); MTIME is already 0.
  if (gz.length > 9) gz[9] = 0xff;
  await writeFile(join(DATA, name), gz);
  return fileDigest(gz);
}

/** Build a locale pack: normalise + dedupe + content filter, preserving order. */
function buildPack(words) {
  const seen = new Set();
  const out = [];
  for (const w of words) {
    const label = normalizeLabel(w);
    if (label && !isBannedLabel(label) && !seen.has(label)) { seen.add(label); out.push(label); }
  }
  return out;
}

/**
 * Optional privacy guard: when the gitignored .private-denylist exists (ERE
 * patterns, one per line), refuse to write any label that matches it. The gz
 * tiers are the only repo data the git hooks / `git grep` cannot see inside, so
 * this is the builder's own defence-in-depth. Only the match count is reported,
 * never the matching labels.
 */
async function loadPrivatePatterns() {
  const path = join(REPO, '.private-denylist');
  if (!existsSync(path)) return null;
  const text = await readFile(path, 'utf8');
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((p) => new RegExp(p, 'i'));
}

function assertNoPrivate(patterns, label) {
  if (!patterns) return;
  for (const re of patterns) if (re.test(label)) throw new Error('private-denylist match in build output (label withheld)');
}

async function main() {
  process.stderr.write(`cache: ${CACHE}\n`);
  await mkdir(join(DATA, 'locale'), { recursive: true });

  // 1. Load + normalise every source (deduped per source, order preserved).
  const sourceLabels = new Map();
  const rawCounts = {};
  for (const src of SOURCES) {
    const path = await ensureSource(src);
    const text = await readFile(path, 'utf8');
    const seen = new Set();
    const labels = [];
    let raw = 0;
    for (const line of text.split(/\r?\n/)) {
      raw += line.trim() ? 1 : 0;
      const label = normalizeLabel(line);
      if (label && !seen.has(label)) { seen.add(label); labels.push(label); }
    }
    sourceLabels.set(src.id, labels);
    rawCounts[src.id] = { raw, kept: labels.length };
  }

  // 2. Rank into one master list.
  const { ranked } = rank(sourceLabels);
  const base = ranked.slice(0, BASE_N);
  const large = ranked.slice(0, Math.min(LARGE_N, ranked.length));
  const huge = ranked.slice(0, Math.min(HUGE_N, ranked.length));

  // 2b. Privacy guard: refuse to write if any output label matches the local
  //     .private-denylist (the gz tiers are the only repo data the git hooks
  //     cannot scan). huge ⊇ large ⊇ base, so checking huge covers the tiers.
  const privatePatterns = await loadPrivatePatterns();
  if (privatePatterns) {
    let matches = 0;
    for (const label of huge) { try { assertNoPrivate(privatePatterns, label); } catch { matches += 1; } }
    for (const words of Object.values(LOCALE_PACKS)) for (const w of words) {
      const l = normalizeLabel(w);
      if (l) { try { assertNoPrivate(privatePatterns, l); } catch { matches += 1; } }
    }
    if (matches > 0) throw new Error(`refusing to write: ${matches} output label(s) match .private-denylist`);
  }

  // 3. Write tiers.
  const baseFile = await writeText('wordlist-base.txt', base);
  const largeFile = await writeGz('wordlist-large.txt.gz', large);
  const hugeFile = await writeGz('wordlist-huge.txt.gz', huge);
  const baseBytes = baseFile.bytes;
  const largeBytes = largeFile.bytes;
  const hugeBytes = hugeFile.bytes;

  // 4. Locale packs.
  const localeInfo = {};
  for (const [cc, words] of Object.entries(LOCALE_PACKS)) {
    const pack = buildPack(words);
    const { bytes, sha256 } = await writeText(join('locale', `${cc}.txt`), pack);
    localeInfo[cc] = { count: pack.length, bytes, sha256 };
  }

  // 5. Manifest.
  const manifest = {
    generatedBy: 'tools/build-wordlists.mjs',
    // Reproducible: take the date from SOURCE_DATE_EPOCH when set, else the clock.
    generatedAt: (process.env.SOURCE_DATE_EPOCH
      ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000)
      : new Date()).toISOString().slice(0, 10),
    note: 'Counts are computed at build time; assets/js/lib/wordlist.js embeds a copy for the UI. ' +
      'A unit test asserts the embedded counts match these files. sha256 keys the wordlist cache of the service worker.',
    licenseFile: 'THIRD_PARTY_LICENSES.txt',
    tiers: {
      small: { id: 'small', approxCount: WORDLIST_SMALL.length, bytes: 0, file: null,
        sources: ['DomainScope curated core'], licence: 'MIT' },
      smart: { id: 'smart', approxCount: base.length, bytes: baseBytes, sha256: baseFile.sha256, file: 'wordlist-base.txt',
        sources: ['DomainScope curated core', 'SecLists', 'bitquark/dnspop', 'commonspeak2', 'dnsgen', 'altdns'],
        licence: 'MIT / Apache-2.0' },
      large: { id: 'large', approxCount: large.length, bytes: largeBytes, sha256: largeFile.sha256, file: 'wordlist-large.txt.gz',
        sources: ['SecLists top-1M', 'bitquark top-100k', 'commonspeak2'], licence: 'MIT / Apache-2.0' },
      huge: { id: 'huge', approxCount: huge.length, bytes: hugeBytes, sha256: hugeFile.sha256, file: 'wordlist-huge.txt.gz',
        sources: ['SecLists top-1M', 'bitquark top-100k', 'commonspeak2'], licence: 'MIT / Apache-2.0' }
    },
    locales: localeInfo,
    localeNote: LOCALE_NOTE,
    sources: SOURCES.map((s) => ({
      id: s.id, project: s.project, licence: s.licence, url: s.url, kind: s.kind,
      raw: rawCounts[s.id].raw, kept: rawCounts[s.id].kept
    }))
  };
  await writeFile(join(DATA, 'wordlist-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  // 6. Report.
  const kb = (n) => (n / 1024).toFixed(1) + ' KiB';
  process.stderr.write('\n== tiers ==\n');
  process.stderr.write(`  small : ${WORDLIST_SMALL.length} labels (built-in)\n`);
  process.stderr.write(`  smart : ${base.length} labels  ${kb(baseBytes)}  wordlist-base.txt\n`);
  process.stderr.write(`  large : ${large.length} labels  ${kb(largeBytes)}  wordlist-large.txt.gz\n`);
  process.stderr.write(`  huge  : ${huge.length} labels  ${kb(hugeBytes)}  wordlist-huge.txt.gz\n`);
  process.stderr.write(`  master unique: ${ranked.length}\n`);
  process.stderr.write('== locale packs ==\n');
  for (const [cc, info] of Object.entries(localeInfo)) {
    process.stderr.write(`  ${cc}: ${info.count} labels  ${kb(info.bytes)}\n`);
  }
  process.stderr.write('== sources ==\n');
  for (const s of SOURCES) {
    process.stderr.write(`  ${s.id.padEnd(13)} ${String(rawCounts[s.id].raw).padStart(7)} raw → ${rawCounts[s.id].kept} kept  [${s.licence}]\n`);
  }
  // Machine-readable summary on stdout.
  process.stdout.write(JSON.stringify({
    small: WORDLIST_SMALL.length, smart: base.length, large: large.length, huge: huge.length,
    master: ranked.length, baseBytes, largeBytes, hugeBytes,
    locales: Object.fromEntries(Object.entries(localeInfo).map(([k, v]) => [k, v.count]))
  }) + '\n');
}

// Only build when run directly (`node tools/build-wordlists.mjs`); importing the
// module for its exports (e.g. from a unit test) must not trigger a build.
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch((err) => { process.stderr.write(`build failed: ${err.stack || err}\n`); process.exit(1); });
}
