#!/usr/bin/env node
/**
 * build-ranges.mjs — the provider IP ranges behind lib/netinfo.js's answer classification.
 *
 * Maintainers and the weekly workflow (.github/workflows/ranges.yml) run it; the site never does.
 * No dependencies (Node 22 stdlib, plus the app's own lib/ip.js, so the page reads back exactly
 * what the build wrote). It downloads the lists the providers publish themselves, checks them and
 * writes a small static dataset that lib/netinfo.js loads on first use:
 *
 *   assets/data/ranges/edges.json      the edge tier: netinfo provider id → merged prefixes. These
 *                                      replace the built-in table of the same provider, so they
 *                                      decide the classification (Cloudflare-proxied, CDN, platform)
 *   assets/data/ranges/networks.json   the network tier: operator id → merged prefixes of its whole
 *                                      published (or announced) space. Display only: an answer there
 *                                      that no edge range holds stays 'direct' and only says whose
 *                                      network it is ("Cloudflare network, not necessarily proxied")
 *   assets/data/ranges/manifest.json   format, date, sources (URL, the publisher's own date, the
 *                                      SHA-256 of what was kept from it, counts), the SHA-256 and
 *                                      size of each data file, and the counts per tier
 *
 * Kept: only what the classification reads. AWS gives CloudFront to the edge tier and its other
 * services, merged, to the network tier; GitHub's meta gives its Pages addresses only (not hooks,
 * actions or git); Google's goog.json (all of Google) and cloud.json (Google Cloud customers), Oracle
 * Cloud and DigitalOcean give the network tier; RIPEstat's announced prefixes of AS13335 and AS209242
 * give the Cloudflare network tier (ROADMAP P2.10: Spectrum, WARP, BYOIP and Cloudflare's own
 * services, outside the 15 + 7 published proxy ranges). Adjacent and overlapping prefixes are merged
 * into the fewest covering prefixes, so per-service and per-region detail is dropped. Imperva (a POST
 * API), Sucuri, Netlify and Vercel (documentation pages) have no list this tool can check: netinfo
 * keeps their built-in ranges. Akamai publishes no list of its edge addresses (its Origin IP ACL
 * list is the addresses that reach origins, not the ones visitors reach), so it stays CNAME-only.
 *
 * Nothing is written when a download looks wrong: an answer of the wrong shape, a prefix that does
 * not parse, a prefix shorter than /8 (IPv4) or /16 (IPv6), a private, reserved or documentation
 * prefix, a source with implausibly few or many prefixes ({@link BOUNDS}), or a well-known address
 * missing from its provider ({@link CANARIES}). The manifest's date moves only when the data does,
 * so a rebuild with nothing new changes no file and the weekly workflow opens no pull request.
 *
 * Usage:
 *   node tools/build-ranges.mjs             # download (60 s at most each; cached for 12 h), build, write
 *   node tools/build-ranges.mjs --offline   # use the cached downloads only
 *   RANGES_CACHE=/path node tools/build-ranges.mjs
 *
 * The lists are the providers' public infrastructure data, published for allow-listing; see
 * assets/data/README.md.
 */

import { readFile, writeFile, mkdir, stat, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseCidr, formatIP, isGloballyRoutable } from '../assets/js/lib/ip.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const OUT = join(REPO, 'assets', 'data', 'ranges');
const CACHE = process.env.RANGES_CACHE || join(tmpdir(), 'domainscope-ranges');
const CACHE_MS = 12 * 3600 * 1000;
/** One download may take this long, body included. */
const DOWNLOAD_TIMEOUT_MS = 60 * 1000;

/** Dataset format; lib/netinfo.js refuses another one. */
export const FORMAT = 1;

/**
 * The published lists (each verified 2026-10-08 with one request: shape and size as parsed below).
 * `parse` names the parser in {@link PARSERS}; `file` is the cache file name.
 */
export const SOURCES = Object.freeze([
  { id: 'cloudflare-v4', name: 'Cloudflare: IPv4 proxy ranges', url: 'https://www.cloudflare.com/ips-v4', parse: 'lines', file: 'cloudflare-ips-v4.txt' },
  { id: 'cloudflare-v6', name: 'Cloudflare: IPv6 proxy ranges', url: 'https://www.cloudflare.com/ips-v6', parse: 'lines', file: 'cloudflare-ips-v6.txt' },
  { id: 'fastly', name: 'Fastly: public IP list', url: 'https://api.fastly.com/public-ip-list', parse: 'fastly', file: 'fastly.json' },
  { id: 'aws', name: 'AWS: ip-ranges.json', url: 'https://ip-ranges.amazonaws.com/ip-ranges.json', parse: 'aws', file: 'aws.json' },
  { id: 'github', name: 'GitHub: meta API (Pages)', url: 'https://api.github.com/meta', parse: 'github', file: 'github-meta.json' },
  { id: 'google', name: 'Google: goog.json (all Google ranges)', url: 'https://www.gstatic.com/ipranges/goog.json', parse: 'google', file: 'goog.json' },
  { id: 'google-cloud', name: 'Google Cloud: cloud.json (customer ranges)', url: 'https://www.gstatic.com/ipranges/cloud.json', parse: 'google', file: 'cloud.json' },
  { id: 'oracle', name: 'Oracle Cloud: public_ip_ranges.json', url: 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', parse: 'oracle', file: 'oracle.json' },
  { id: 'digitalocean', name: 'DigitalOcean: geo feed (RFC 8805)', url: 'https://www.digitalocean.com/geo/google.csv', parse: 'geofeed', file: 'digitalocean.csv' },
  { id: 'as13335', name: 'RIPEstat: prefixes announced by AS13335 (Cloudflare)', url: 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335', parse: 'ripe', file: 'ripe-as13335.json' },
  { id: 'as209242', name: 'RIPEstat: prefixes announced by AS209242 (Cloudflare)', url: 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS209242', parse: 'ripe', file: 'ripe-as209242.json' }
]);

/**
 * Which parsed part of which source feeds each tier entry. Edge ids are lib/netinfo.js PROVIDERS
 * ids; network ids are lib/netinfo.js NETWORKS ids (and lib/ipintel.js INFRA_NETWORKS ids).
 */
export const TIERS = Object.freeze({
  edges: Object.freeze({
    cloudflare: [['cloudflare-v4', 'all'], ['cloudflare-v6', 'all']],
    fastly: [['fastly', 'all']],
    cloudfront: [['aws', 'cloudfront']],
    'github-pages': [['github', 'pages']]
  }),
  networks: Object.freeze({
    cloudflare: [['as13335', 'all'], ['as209242', 'all'], ['cloudflare-v4', 'all'], ['cloudflare-v6', 'all']],
    aws: [['aws', 'all']],
    'google-cloud': [['google-cloud', 'all']],
    google: [['google', 'all']],
    oracle: [['oracle', 'all']],
    digitalocean: [['digitalocean', 'all']]
  })
});

/**
 * Plausible prefix counts per source, before merging (2026-10-08: Cloudflare 15 + 7, Fastly 21,
 * AWS 17,533 of which CloudFront 243, GitHub Pages 10, goog.json 145, cloud.json 1,107, Oracle
 * 1,107 + IPv6, DigitalOcean 1,230, AS13335 5,716, AS209242 302). Outside them nothing is written.
 */
export const BOUNDS = Object.freeze({
  'cloudflare-v4': [8, 100], 'cloudflare-v6': [3, 100], fastly: [8, 500], aws: [5000, 100000], 'aws/cloudfront': [50, 5000],
  github: [2, 200], google: [40, 5000], 'google-cloud': [300, 20000], oracle: [300, 20000], digitalocean: [300, 20000],
  as13335: [1500, 50000], as209242: [20, 20000]
});

/**
 * Addresses that must be in a tier entry, or the download is not what it claims to be (each one is
 * inside the built-in table of lib/netinfo.js, or public infrastructure everyone knows).
 */
export const CANARIES = Object.freeze([
  ['edges', 'cloudflare', '104.16.0.1'],
  ['edges', 'fastly', '151.101.0.1'],
  ['edges', 'cloudfront', '13.32.0.1'],
  ['edges', 'github-pages', '185.199.108.153'],
  ['networks', 'cloudflare', '1.1.1.1'],
  ['networks', 'google', '8.8.8.8'],
  ['networks', 'aws', '205.251.192.1']
]);

/** The shortest prefix length accepted per IP version: anything wider is not one provider's. */
export const MIN_PREFIX = Object.freeze({ 4: 8, 6: 16 });

/** A download or a prefix that is not what the source should publish. */
export class RangeDataError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RangeDataError';
  }
}

const fail = (msg) => { throw new RangeDataError(msg); };
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const asJson = (text, what) => {
  if (typeof text !== 'string') fail(`${what}: no text`);
  try {
    return JSON.parse(text);
  } catch {
    return fail(`${what}: not JSON (an error page?)`);
  }
};
const arrayAt = (obj, key, what) => (Array.isArray(obj[key]) ? obj[key] : fail(`${what}: no "${key}" array`));
const stringsOf = (list, key, what) => list.map((e, i) => {
  const v = key ? (isObj(e) ? e[key] : undefined) : e;
  return typeof v === 'string' ? v : fail(`${what}: entry ${i} has no ${key ? `"${key}" ` : ''}string`);
});

/**
 * Parsers, one per source shape. Each takes the downloaded text and returns named lists of prefix
 * strings (`all`, plus a source-specific part); a wrong shape throws a {@link RangeDataError}.
 * Pure: no I/O.
 * @type {Readonly<Record<string, (text: string, what?: string) => Record<string, string[]>>>}
 */
export const PARSERS = Object.freeze({
  /** Cloudflare's ips-v4 / ips-v6: one prefix a line. */
  lines(text, what = 'list') {
    if (typeof text !== 'string') fail(`${what}: no text`);
    if (/<\s*(?:html|!doctype)/i.test(text)) fail(`${what}: an HTML page, not a list`);
    return { all: text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean) };
  },
  /** Fastly: { addresses: [...], ipv6_addresses: [...] }. */
  fastly(text, what = 'fastly') {
    const j = asJson(text, what);
    if (!isObj(j)) fail(`${what}: not an object`);
    return { all: [...stringsOf(arrayAt(j, 'addresses', what), null, what), ...stringsOf(arrayAt(j, 'ipv6_addresses', what), null, what)] };
  },
  /** AWS: { syncToken, createDate, prefixes: [{ ip_prefix, service }], ipv6_prefixes: [{ ipv6_prefix, service }] }. */
  aws(text, what = 'aws') {
    const j = asJson(text, what);
    if (!isObj(j)) fail(`${what}: not an object`);
    const v4 = arrayAt(j, 'prefixes', what);
    const v6 = arrayAt(j, 'ipv6_prefixes', what);
    const all = [...stringsOf(v4, 'ip_prefix', what), ...stringsOf(v6, 'ipv6_prefix', what)];
    const cloudfront = [
      ...v4.filter((p) => p.service === 'CLOUDFRONT').map((p) => p.ip_prefix),
      ...v6.filter((p) => p.service === 'CLOUDFRONT').map((p) => p.ipv6_prefix)
    ];
    return { all, cloudfront, published: typeof j.createDate === 'string' ? j.createDate : null };
  },
  /** GitHub meta: { pages: [...], hooks, web, … }; only Pages is kept. */
  github(text, what = 'github') {
    const j = asJson(text, what);
    if (!isObj(j)) fail(`${what}: not an object`);
    const pages = stringsOf(arrayAt(j, 'pages', what), null, what);
    return { all: pages, pages };
  },
  /** Google goog.json / cloud.json: { syncToken, creationTime, prefixes: [{ ipv4Prefix } | { ipv6Prefix }] }. */
  google(text, what = 'google') {
    const j = asJson(text, what);
    if (!isObj(j)) fail(`${what}: not an object`);
    const all = arrayAt(j, 'prefixes', what).map((p, i) => {
      const v = isObj(p) ? (p.ipv4Prefix ?? p.ipv6Prefix) : undefined;
      return typeof v === 'string' ? v : fail(`${what}: entry ${i} has no ipv4Prefix / ipv6Prefix`);
    });
    return { all, published: typeof j.creationTime === 'string' ? j.creationTime : null };
  },
  /** Oracle: { last_updated_timestamp, regions: [{ region, cidrs: [{ cidr, tags }], ipv6_cidrs?: [...] }] }. */
  oracle(text, what = 'oracle') {
    const j = asJson(text, what);
    if (!isObj(j)) fail(`${what}: not an object`);
    const all = [];
    for (const [i, r] of arrayAt(j, 'regions', what).entries()) {
      if (!isObj(r)) fail(`${what}: region ${i} is not an object`);
      all.push(...stringsOf(arrayAt(r, 'cidrs', `${what} region ${i}`), 'cidr', what));
      if (r.ipv6_cidrs !== undefined) all.push(...stringsOf(arrayAt(r, 'ipv6_cidrs', `${what} region ${i}`), 'cidr', what));
    }
    return { all, published: typeof j.last_updated_timestamp === 'string' ? j.last_updated_timestamp : null };
  },
  /** An RFC 8805 geofeed (DigitalOcean): prefix,country,region,city,postal — the first column only. */
  geofeed(text, what = 'geofeed') {
    if (typeof text !== 'string') fail(`${what}: no text`);
    if (/<\s*(?:html|!doctype)/i.test(text)) fail(`${what}: an HTML page, not a geofeed`);
    const all = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      all.push(line.split(',')[0].trim());
    }
    return { all };
  },
  /** RIPEstat announced-prefixes: { status: 'ok', data: { prefixes: [{ prefix, timelines }], resource } }. */
  ripe(text, what = 'ripestat') {
    const j = asJson(text, what);
    if (!isObj(j) || !isObj(j.data)) fail(`${what}: no "data" object`);
    if (j.status !== undefined && j.status !== 'ok') fail(`${what}: status ${JSON.stringify(j.status)}`);
    return { all: stringsOf(arrayAt(j.data, 'prefixes', what), 'prefix', what), published: typeof j.data.latest_time === 'string' ? j.data.latest_time : null };
  }
});

/**
 * The canonical text of one published prefix ('104.16.0.0/13', '2400:cb00::/32'); a bare address
 * is a host route. Throws a {@link RangeDataError} for text that is not a prefix, host bits that
 * are set, one that is not globally routable (private, reserved, documentation …), or a prefix
 * wider than {@link MIN_PREFIX} — a list that holds one is not trusted.
 * @param {string} text
 * @param {{ routable?: (ip: string) => boolean, what?: string }} [opts] routable: the check of the
 *   network address (default lib/ip.js isGloballyRoutable; tests pass their own for documentation data)
 * @returns {{ text: string, version: 4|6, start: bigint, end: bigint }}
 */
export function normalizePrefix(text, { routable = isGloballyRoutable, what = 'prefix' } = {}) {
  const c = typeof text === 'string' && /^[0-9a-fA-F:.]+(?:\/\d{1,3})?$/.test(text.trim()) ? parseCidr(text) : null;
  if (!c) fail(`${what}: ${JSON.stringify(String(text).slice(0, 60))} is not a prefix`);
  const bits = c.version === 4 ? 32 : 128;
  const given = parseCidr(text.trim().split('/')[0]);
  if (given.network !== c.network) fail(`${what}: ${text} has host bits set`);
  const network = formatIP(c.network, c.version);
  if (!routable(network)) fail(`${what}: ${text} is not globally routable`);
  if (c.prefix < MIN_PREFIX[c.version]) fail(`${what}: ${text} is wider than /${MIN_PREFIX[c.version]}`);
  const size = 1n << BigInt(bits - c.prefix);
  return { text: `${network}/${c.prefix}`, version: c.version, start: c.network, end: c.network + size - 1n };
}

/** The fewest prefixes covering [start, end] of one version, in order. */
function rangeToPrefixes(start, end, version) {
  const bits = version === 4 ? 32 : 128;
  const out = [];
  let cur = start;
  while (cur <= end) {
    let size = 0; // log2 of the block
    while (size < bits) {
      const next = size + 1;
      const block = 1n << BigInt(next);
      if ((cur & (block - 1n)) !== 0n || cur + block - 1n > end) break;
      size = next;
    }
    out.push(`${formatIP(cur, version)}/${bits - size}`);
    cur += 1n << BigInt(size);
  }
  return out;
}

/**
 * Merge prefixes into the fewest prefixes that cover exactly the same addresses: overlapping and
 * adjacent prefixes join (two halves of a /16 become the /16). IPv4 first, then IPv6, each in
 * address order. Input items are {@link normalizePrefix} results.
 * @param {Array<{ version: 4|6, start: bigint, end: bigint }>} items
 * @returns {string[]}
 */
export function mergePrefixes(items) {
  const out = [];
  for (const version of [4, 6]) {
    const list = items.filter((p) => p.version === version).sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    let cur = null;
    for (const p of list) {
      if (cur && p.start <= cur.end + 1n) {
        if (p.end > cur.end) cur.end = p.end;
      } else {
        if (cur) out.push(...rangeToPrefixes(cur.start, cur.end, version));
        cur = { start: p.start, end: p.end };
      }
    }
    if (cur) out.push(...rangeToPrefixes(cur.start, cur.end, version));
  }
  return out;
}

const sha256Hex = (text) => createHash('sha256').update(text).digest('hex');
const day = (d) => d.toISOString().slice(0, 10);

/** Is `ip` (text) inside one of `prefixes` (text)? */
function covers(prefixes, ip) {
  const a = parseCidr(ip);
  return !!a && prefixes.some((p) => {
    const c = parseCidr(p);
    return c.version === a.version && (a.network & ~((1n << BigInt((c.version === 4 ? 32 : 128) - c.prefix)) - 1n)) === c.network;
  });
}

/**
 * The SHA-256 of the dataset: each data file's name and content, in name order, then the manifest
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

/** One prefix a line, keys in order: small diffs in the weekly pull request. */
function tierJson(tier) {
  const keys = Object.keys(tier).sort();
  const body = keys.map((k) => `${JSON.stringify(k)}: [\n${tier[k].map((p) => JSON.stringify(p)).join(',\n')}\n]`);
  return `{\n${body.join(',\n')}\n}\n`;
}

/**
 * Build the dataset from the downloaded texts. Pure: no I/O.
 * @param {{ texts: Record<string, string>, previous?: object|null, now?: Date,
 *   bounds?: Record<string, [number, number]>, canaries?: ReadonlyArray<[string, string, string]>,
 *   routable?: (ip: string) => boolean, sources?: ReadonlyArray<object> }} input
 *   texts: source id → downloaded text; previous: the manifest on disk (its date and the
 *   publishers' dates are kept when nothing changed); bounds / canaries / routable: the checks
 *   ({@link BOUNDS}, {@link CANARIES}, lib/ip.js isGloballyRoutable; tests pass their own)
 * @returns {{ files: Map<string, string>, manifest: object, report: { problems: string[], counts: object } }}
 *   files: name relative to assets/data/ranges → content; problems: why nothing may be written
 *   (empty when the data is fine)
 */
export function buildRanges({
  texts, previous = null, now = new Date(), bounds = BOUNDS, canaries = CANARIES, routable = isGloballyRoutable, sources = SOURCES
}) {
  const problems = [];
  const parsed = {};
  const kept = {};
  for (const src of sources) {
    try {
      const parts = PARSERS[src.parse](texts[src.id], src.id);
      const norm = {};
      for (const [part, list] of Object.entries(parts)) {
        if (!Array.isArray(list)) continue;
        norm[part] = list.map((p) => normalizePrefix(p, { routable, what: src.id }));
        const b = bounds[part === 'all' ? src.id : `${src.id}/${part}`];
        if (b && (list.length < b[0] || list.length > b[1])) {
          problems.push(`${src.id}${part === 'all' ? '' : `/${part}`}: ${list.length} prefixes, expected ${b[0]}–${b[1]}`);
        }
      }
      parsed[src.id] = { parts: norm, published: typeof parts.published === 'string' ? parts.published : null };
    } catch (err) {
      if (!(err instanceof RangeDataError)) throw err;
      problems.push(err.message);
    }
  }
  const tiers = { edges: {}, networks: {} };
  for (const [tier, entries] of Object.entries(TIERS)) {
    for (const [id, feeds] of Object.entries(entries)) {
      const items = [];
      for (const [srcId, part] of feeds) {
        const p = parsed[srcId] && parsed[srcId].parts[part];
        if (!p) continue;
        items.push(...p);
        (kept[srcId] ||= new Set()).add(part);
      }
      tiers[tier][id] = mergePrefixes(items);
    }
  }
  for (const [tier, id, ip] of canaries) {
    if (!problems.length && !covers(tiers[tier][id] || [], ip)) problems.push(`${tier}/${id}: ${ip} is missing`);
  }
  const files = new Map([['edges.json', tierJson(tiers.edges)], ['networks.json', tierJson(tiers.networks)]]);
  const prevSources = new Map(((previous && previous.sources) || []).map((s) => [s.id, s]));
  const manifestSources = sources.map((src) => {
    const p = parsed[src.id];
    const keptText = p ? [...(kept[src.id] || [])].sort().map((part) => `${part}\n${mergePrefixes(p.parts[part]).join('\n')}`).join('\n') : '';
    const sha256 = sha256Hex(keptText);
    const prev = prevSources.get(src.id);
    const same = prev && prev.sha256 === sha256;
    return {
      id: src.id, name: src.name, url: src.url,
      // the publisher's own stamp of the version kept (it moves only when what is kept does)
      published: same ? prev.published ?? null : (p ? p.published : null),
      prefixes: p ? Object.values(p.parts).reduce((n, l) => Math.max(n, l.length), 0) : 0,
      sha256
    };
  });
  const counts = {};
  for (const [tier, entries] of Object.entries(tiers)) counts[tier] = Object.fromEntries(Object.keys(entries).sort().map((k) => [k, entries[k].length]));
  const body = {
    format: FORMAT,
    sources: manifestSources,
    files: Object.fromEntries([...files].map(([name, text]) => [name, { bytes: Buffer.byteLength(text), sha256: sha256Hex(text) }])),
    counts
  };
  const digest = datasetDigest(files, body);
  const generated = previous && previous.digest === digest && typeof previous.generated === 'string' ? previous.generated : day(now);
  const manifest = { format: FORMAT, generated, digest, sources: body.sources, files: body.files, counts };
  files.set('manifest.json', `${JSON.stringify(manifest, null, 2)}\n`);
  return { files, manifest, report: { problems, counts } };
}

/**
 * Download one source (or read the cached copy, 12 h): the text, checked by its parser so that an
 * error page answered with 200 is neither cached nor read twice.
 * @param {{ id: string, url: string, file: string, parse: string }} source a {@link SOURCES} entry
 * @param {{ offline?: boolean, cache?: string, fetchImpl?: typeof fetch, timeoutMs?: number, log?: (line: string) => void }} [opts]
 * @returns {Promise<string>}
 */
export async function downloadSource(source, {
  offline = false, cache = CACHE, fetchImpl = globalThis.fetch, timeoutMs = DOWNLOAD_TIMEOUT_MS, log = (line) => process.stdout.write(`${line}\n`)
} = {}) {
  const file = join(cache, source.file);
  try {
    const st = await stat(file);
    if (offline || Date.now() - st.mtimeMs < CACHE_MS) {
      const cached = await readFile(file, 'utf8');
      try {
        PARSERS[source.parse](cached, source.id);
        return cached;
      } catch (err) {
        await rm(file, { force: true });
        if (offline) throw new Error(`--offline: ${file}: ${err.message} (the cached copy was deleted)`);
        log(`${file}: ${err.message}; the cached copy was deleted`);
      }
    }
  } catch (err) {
    if (offline) throw err.code === 'ENOENT' ? new Error(`--offline: ${file} is not cached`) : err;
  }
  log(`downloading ${source.url}`);
  let text;
  try {
    const res = await fetchImpl(source.url, {
      headers: { 'user-agent': 'domainscope-build-ranges (+https://github.com/halilibrahimd27/domainscope)' },
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) throw new Error(`${source.url}: HTTP ${res.status}`);
    text = await res.text();
  } catch (err) {
    if (err && err.name === 'TimeoutError') throw new Error(`${source.url}: no complete answer within ${timeoutMs / 1000} s`);
    throw err;
  }
  try {
    PARSERS[source.parse](text, source.id);
  } catch (err) {
    throw new Error(`${source.url}: ${err.message} (not cached)`);
  }
  await mkdir(cache, { recursive: true });
  await writeFile(file, text);
  return text;
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
  const texts = {};
  await Promise.all(SOURCES.map(async (src) => { texts[src.id] = await downloadSource(src, { offline }); }));
  const previous = await readJson(join(OUT, 'manifest.json'));
  const { files, manifest, report } = buildRanges({ texts, previous });
  const line = Object.entries(report.counts).map(([tier, c]) => `${tier}: ${Object.entries(c).map(([k, n]) => `${k} ${n}`).join(', ')}`).join('; ');
  process.stdout.write(`${line}\n`);
  if (report.problems.length) {
    throw new Error(`the downloads look wrong, nothing written:\n  ${report.problems.join('\n  ')}\n`
      + 'If a provider really changed its list, adjust BOUNDS or CANARIES in tools/build-ranges.mjs.');
  }
  await mkdir(OUT, { recursive: true });
  let changed = 0;
  for (const [name, content] of files) {
    const path = join(OUT, name);
    let old = null;
    try { old = await readFile(path, 'utf8'); } catch { /* new file */ }
    if (old === content) continue;
    await writeFile(path, content);
    changed += 1;
  }
  process.stdout.write(`${changed} file(s) changed, dataset of ${manifest.generated}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
