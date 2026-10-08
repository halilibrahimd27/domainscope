/**
 * Repository hygiene — DOM-free, no network. The repo is public and the product
 * is global: test data, fixtures, wordlists, docs and code must not carry real
 * people's or companies' addresses.
 *
 * 1. IPv4 literals (every text file, the .gz wordlist tiers gunzipped). Each
 *    address must be
 *      - special-purpose / documentation space: 192.0.2.0/24, 198.51.100.0/24,
 *        203.0.113.0/24, RFC 1918, loopback, CGNAT, 198.18.0.0/15, multicast …;
 *      - inside a range the product itself ships: provider ranges
 *        (netinfo.matchProviderByIP) or an ECS vantage subnet (GEO_VANTAGES); or
 *      - well-known public infrastructure / a conventional placeholder listed in
 *        WELL_KNOWN below, with its owner.
 *    The provider range dataset (assets/data/ranges, tools/build-ranges.mjs) is
 *    product data too: the prefixes of its two tier files are exempt, one by one,
 *    while each file matches the SHA-256 its manifest records and the manifest
 *    names exactly the builder's official sources (a hand edit fails).
 *    Anything else — an origin IP captured from a live scan, this machine's
 *    egress address, a customer's server — fails with file:line. Use a
 *    documentation range instead (192.0.2.x, 198.51.100.x, 203.0.113.x).
 *    (A server inside a cloud / CDN provider range passes rule 1; rule 2 is
 *    what catches the maintainer's own addresses there.)
 * 2. Only where the gitignored files exist (a maintainer's clone, never CI):
 *    the ERE patterns of `.private-denylist` and the domains / origin IPs of
 *    `tests/live/targets.local.json` must not occur in any file — including the
 *    gunzipped wordlists, which `git grep -I` and the commit hook cannot see.
 *    Documentation-range examples also avoid the last octets of the private
 *    origin IPs (and of its optional `avoidLastOctets` list).
 *    Failures name the file, line and pattern number, never the private text.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { dirname, extname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ipInCidr, matchProviderByIP } from '../../assets/js/lib/netinfo.js';
import { GEO_VANTAGES } from '../../assets/js/lib/resolvers.js';
import { createHash } from 'node:crypto';
import { SOURCES as RANGE_SOURCES } from '../../tools/build-ranges.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/* ---- which files ------------------------------------------------------------ */

/** Directories never scanned (VCS, dependencies, gitignored local output). */
const SKIP_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.claude']);
const SKIP_PATHS = new Set(['tests/e2e/screenshots', 'tests/live/private', 'tests/live/.cache']);
/** Text formats that can carry an address; binary fixtures (DER, .bin, keys) are skipped. */
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.json', '.md', '.py', '.txt', '.yml', '.yaml', '.html', '.css', '.svg', '.csv', '.webmanifest', '.gz', '.xml']);
/** The gitignored private files themselves (read separately, never scanned). */
const isPrivateFile = (rel) => rel === '.private-denylist' || rel.endsWith('.local.json');
/**
 * The intermediate certificate shards (tools/build-intermediates.mjs; the test dataset too) hold
 * each certificate as base64 DER: opaque bytes that can hold no readable address or name, yet in
 * megabytes of them a short case-insensitive denylist pattern would match by chance. Their `der`
 * values are blanked before the scan; the CA owner names and every other file stay scanned.
 */
const DER_SHARD = /^(?:assets\/data|tests\/fixtures)\/intermediates\/ski\/[0-9a-f]+\.json$/;
const blankDer = (rel, text) => (DER_SHARD.test(rel) ? text.replace(/"der":"[A-Za-z0-9+/=]*"/g, '"der":""') : text);
/**
 * The two tier files of the provider range dataset (tools/build-ranges.mjs): the prefixes the
 * providers publish for allow-listing, merged, one JSON string a line. An address there is exempt
 * only as the network of such a prefix string ("3.0.0.0/15"), and only while the file matches its
 * manifest (checked below); any other literal in them, and every other file, is scanned as usual.
 */
const RANGE_TIER = /^assets\/data\/ranges\/(?:edges|networks)\.json$/;
const isRangePrefix = (rel, text, index, ip) => RANGE_TIER.test(rel) && text[index - 1] === '"'
  && /^\/\d{1,3}"/.test(text.slice(index + ip.length, index + ip.length + 5));

const toRel = (p) => relative(ROOT, p).split(sep).join('/');

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const rel = toRel(p);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name) || SKIP_PATHS.has(rel) || name.startsWith('.profile')) continue;
      yield* walk(p);
    } else if (TEXT_EXT.has(extname(name)) && !isPrivateFile(rel)) {
      yield p;
    }
  }
}

let cache = null;
/** @returns {Array<{ rel: string, text: string }>} every scanned file (gz tiers gunzipped) */
function repoFiles() {
  if (cache) return cache;
  cache = [];
  for (const p of walk(ROOT)) {
    const raw = readFileSync(p);
    let text;
    try {
      text = p.endsWith('.gz') ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
    } catch {
      continue; // not gzip after all
    }
    cache.push({ rel: toRel(p), text: blankDer(toRel(p), text) });
  }
  return cache;
}

function lineOf(text, index) {
  let n = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) n += 1;
  return n;
}

/* ---- which addresses are fine -------------------------------------------------- */

const SPECIAL_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
];

/**
 * Public infrastructure every DNS / TLS tool talks about, and conventional placeholders.
 * Add an entry only for an address that is public knowledge — never for a customer's or
 * your own server (those belong in a documentation range).
 */
const WELL_KNOWN = [
  ['1.0.0.0/24', 'Cloudflare public DNS (1.0.0.1)'],
  ['1.1.1.0/24', 'Cloudflare public DNS (1.1.1.1)'],
  ['8.8.4.0/24', 'Google Public DNS'],
  ['8.8.8.0/24', 'Google Public DNS'],
  ['9.9.9.0/24', 'Quad9'],
  ['149.112.112.0/24', 'Quad9'],
  ['76.76.2.0/24', 'Control D'],
  ['76.76.10.0/24', 'Control D'],
  ['192.5.6.30/32', 'a.gtld-servers.net (Verisign)'],
  ['216.239.32.0/24', 'Google authoritative name servers'],
  ['205.251.192.0/21', 'Amazon Route 53 name servers'],
  ['198.51.44.0/23', 'NS1 authoritative name servers'],
  ['193.0.0.0/21', 'RIPE NCC'],
  ['200.160.0.0/20', 'NIC.br / registro.br (LACNIC RDAP fixture)'],
  ['93.184.215.0/24', 'example.com (IANA)'],
  ['93.184.216.0/24', 'example.com (IANA)'],
  ['140.82.112.0/20', 'GitHub'],
  ['17.0.0.0/8', 'Apple (recorded DNS fixture answers)'],
  ['45.33.32.156/32', 'scanme.nmap.org (Nmap\'s sanctioned scan target)'],
  ['103.102.166.0/24', 'Wikimedia'],
  ['208.80.152.0/22', 'Wikimedia'],
  ['184.24.0.0/13', 'Akamai'],
  ['23.32.0.0/11', 'Akamai'],
  ['2.16.0.0/13', 'Akamai'],
  ['96.6.0.0/15', 'Akamai'],
  ['52.96.0.0/14', 'Microsoft 365 / Exchange Online'],
  ['40.96.0.0/13', 'Microsoft 365 / Exchange Online'],
  ['142.250.0.0/15', 'Google'],
  ['172.217.0.0/16', 'Google'],
  // conventional placeholders and range-boundary test values
  ['1.2.3.0/24', 'placeholder (1.2.3.4)'],
  ['4.3.2.1/32', 'placeholder (reverse of 1.2.3.4)'],
  ['5.6.7.0/24', 'placeholder (5.6.7.8)'],
  ['2.2.2.2/32', 'placeholder'],
  ['6.6.6.6/32', 'placeholder'],
  ['54.1.2.3/32', 'placeholder (AWS-style public IP)'],
  ['200.1.2.3/32', 'placeholder (LACNIC space)'],
  ['41.1.1.1/32', 'placeholder (AFRINIC space)'],
  ['11.0.0.1/32', 'boundary: just outside 10.0.0.0/8'],
  ['172.15.0.1/32', 'boundary: just below 172.16.0.0/12'],
  ['172.32.0.1/32', 'boundary: just above 172.16.0.0/12'],
  ['9.255.255.255/32', 'boundary: just below 10.0.0.0/8']
];

/**
 * Pre-existing real addresses that still wait for their file owner to move them to a
 * documentation range. Do not add to this list; remove an entry once its files are fixed.
 */
const LEGACY = [
  // The recorded Google ECS fixture (gg-ecs-v4-amazon): its binary answer echoes this subnet, so
  // the manifest, tests/live/capture-dns-fixtures.mjs and the tests/js/dnswire.test.js assertion
  // change together when the fixture is recaptured with a GEO_VANTAGES subnet.
  ['85.96.0.0/12', 'recorded ECS query in tests/fixtures/dns (gg-ecs-v4-amazon), its capture script and its dnswire assertion']
];

/** 4-arc object identifiers look like addresses (2.5.4.3 = CN, 1.3.101.112 = Ed25519 …). */
const OID_PREFIXES = ['2.5.4.', '2.5.29.', '1.3.101.', '1.3.6.', '1.3.132.', '1.3.36.', '1.2.840.', '2.16.840.', '2.23.140.'];

const inAny = (ip, list) => list.some((entry) => ipInCidr(ip, Array.isArray(entry) ? entry[0] : entry));

/** @returns {string|null} why `ip` is acceptable, or null */
function allowedWhy(ip) {
  if (inAny(ip, SPECIAL_V4)) return 'special-purpose';
  if (/^\d+\.0\.0\.0$/.test(ip)) return '/8 network notation';
  if (/^\d+\.0\.0\.127$/.test(ip)) return 'DNSBL test point (127.0.0.x reversed)';
  if (matchProviderByIP(ip)) return 'provider range (netinfo.js)';
  if (GEO_VANTAGES.some((g) => ipInCidr(ip, g.subnet))) return 'ECS vantage (resolvers.js)';
  const known = WELL_KNOWN.find(([cidr]) => ipInCidr(ip, cidr));
  if (known) return known[1];
  const legacy = LEGACY.find(([cidr]) => ipInCidr(ip, cidr));
  if (legacy) return 'legacy';
  return null;
}

/** An IPv4 literal not glued to other digits / dots / word characters. */
const IPV4_RE = /(?<![\w.§])(\d{1,3}(?:\.\d{1,3}){3})(?![\w]|\.\d)/g;

/** @returns {Array<{ ip: string, index: number, asName: boolean }>} */
function ipv4Literals(text) {
  const out = [];
  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[1];
    const octets = ip.split('.');
    if (octets.some((o) => Number(o) > 255 || (o.length > 1 && o.startsWith('0')))) continue; // not a valid address
    if (OID_PREFIXES.some((p) => ip.startsWith(p))) continue;
    const before = text.slice(Math.max(0, m.index - 12), m.index);
    if (/(?:section|sec\.|rfc \d+)\s*$/i.test(before)) continue; // "RFC 5280 4.2.1.3"
    const after = text.slice(m.index + ip.length, m.index + ip.length + 2);
    out.push({ ip, index: m.index, asName: /^\.[a-z]/i.test(after) });
  }
  return out;
}

function checkIp(ip, asName) {
  if (allowedWhy(ip)) return true;
  // "4.3.2.1.in-addr.arpa", "2.0.0.127.zen.spamhaus.org": the name holds the address reversed
  return asName && !!allowedWhy(ip.split('.').reverse().join('.'));
}

/* ---- tests ---------------------------------------------------------------------- */

test('hygiene: the classifier accepts documentation / infrastructure addresses and rejects real ones', () => {
  for (const ip of ['192.0.2.10', '198.51.100.7', '203.0.113.99', '10.1.2.3', '127.0.0.1', '8.8.8.8', '1.1.1.1', '104.16.1.1']) {
    assert.ok(checkIp(ip, false), `${ip} should be allowed`);
  }
  assert.ok(checkIp(GEO_VANTAGES[0].subnet.replace(/\/\d+$/, ''), false), 'an ECS vantage subnet is product data');
  assert.ok(checkIp('4.3.2.1', true) && checkIp('2.0.0.127', false), 'reversed PTR / DNSBL names');
  // NS1 is next to, but not inside, the documentation range 198.51.100.0/24
  assert.equal(allowedWhy('198.51.44.8'), 'NS1 authoritative name servers');
  // built at run time so that the repo scan below does not see these literals
  const ip4 = (...o) => o.join('.');
  for (const ip of [ip4(198, 51, 99, 1), ip4(203, 0, 114, 1), ip4(192, 0, 3, 1), ip4(46, 101, 1, 1), ip4(31, 13, 1, 1)]) {
    assert.equal(checkIp(ip, false), false, `${ip} must be rejected`);
    assert.equal(checkIp(ip, true), false, `${ip} must be rejected as a name prefix too`);
  }
  const found = ipv4Literals('a 203.0.113.5 b 1.3.6.1.5.5.7.3.1 c 2.5.4.3 d RFC 4034 §3.1.8.1 e 010.0.0.1 f 1.2.3.4.in-addr.arpa g 300.1.1.1');
  assert.deepEqual(found.map((f) => [f.ip, f.asName]), [['203.0.113.5', false], ['1.2.3.4', true]]);
});

test('hygiene: only the base64 DER values of the intermediate shards are left out of the scan', () => {
  const shard = '{\n  "ab": [{"owner":"Example CA 203.0.113.9","der":"MIIB+/0="}]\n}\n';
  assert.equal(blankDer('assets/data/intermediates/ski/ab.json', shard), '{\n  "ab": [{"owner":"Example CA 203.0.113.9","der":""}]\n}\n');
  assert.equal(blankDer('tests/fixtures/intermediates/ski/0b.json', shard).includes('MIIB'), false);
  for (const rel of ['assets/data/intermediates/roots.json', 'assets/data/intermediates/dn/a.json', 'assets/data/other/ski/ab.json']) {
    assert.equal(blankDer(rel, shard), shard, rel);
  }
  assert.ok(repoFiles().some((f) => DER_SHARD.test(f.rel) && f.text.includes('"owner"')), 'the shards are still scanned');
});

test('hygiene: the provider range dataset is the builder\'s own output, so only its prefixes are exempt', () => {
  const dir = join(ROOT, 'assets', 'data', 'ranges');
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.sources.map((s) => s.url), RANGE_SOURCES.map((s) => s.url), 'the sources of tools/build-ranges.mjs');
  const tiers = readdirSync(dir).filter((f) => f !== 'manifest.json');
  assert.deepEqual(tiers.sort(), Object.keys(manifest.files).sort(), 'every file of the dataset is in its manifest');
  for (const name of tiers) {
    const text = readFileSync(join(dir, name), 'utf8');
    assert.equal(createHash('sha256').update(text).digest('hex'), manifest.files[name].sha256,
      `assets/data/ranges/${name} differs from its manifest: rebuild it with tools/build-ranges.mjs, never by hand`);
    assert.ok(RANGE_TIER.test(`assets/data/ranges/${name}`), name);
  }
  // the exemption covers a prefix string of a tier file, nothing else
  assert.ok(isRangePrefix('assets/data/ranges/edges.json', '"192.0.2.0/24",', 1, '192.0.2.0'));
  assert.ok(isRangePrefix('assets/data/ranges/networks.json', '"192.0.2.128/25"\n', 1, '192.0.2.128'));
  assert.equal(isRangePrefix('assets/data/ranges/edges.json', 'see 192.0.2.0/24', 4, '192.0.2.0'), false);
  assert.equal(isRangePrefix('assets/data/ranges/edges.json', '"192.0.2.1",', 1, '192.0.2.1'), false);
  assert.equal(isRangePrefix('assets/data/ranges/manifest.json', '"192.0.2.0/24",', 1, '192.0.2.0'), false);
  assert.equal(isRangePrefix('tests/fixtures/ranges/edges.json', '"192.0.2.0/24",', 1, '192.0.2.0'), false);
});

test('hygiene: every IPv4 literal is documentation space, product data or well-known infrastructure', () => {
  const files = repoFiles();
  assert.ok(files.length > 50, `scanned ${files.length} files`);
  assert.ok(files.some((f) => f.rel.endsWith('.txt.gz')), 'the gzip wordlist tiers are scanned too');
  const bad = [];
  for (const { rel, text } of files) {
    if (!/\d\.\d/.test(text)) continue;
    for (const { ip, index, asName } of ipv4Literals(text)) {
      if (!checkIp(ip, asName) && !isRangePrefix(rel, text, index, ip)) bad.push(`${rel}:${lineOf(text, index)} ${ip}`);
    }
  }
  assert.deepEqual(bad, [], `real-world IPv4 addresses found — use 192.0.2.x / 198.51.100.x / 203.0.113.x instead (or, for public infrastructure, add it to WELL_KNOWN with its owner):\n  ${bad.join('\n  ')}`);
});

test('hygiene: legacy exceptions are still needed (remove fixed ones)', (t) => {
  const stillUsed = new Set();
  for (const { text } of repoFiles()) {
    for (const { ip } of ipv4Literals(text)) {
      const hit = LEGACY.find(([cidr]) => ipInCidr(ip, cidr));
      if (hit) stillUsed.add(hit[0]);
    }
  }
  const stale = LEGACY.filter(([cidr]) => !stillUsed.has(cidr)).map(([cidr]) => cidr);
  // informational only: another change may have just removed the last use
  if (stale.length) t.diagnostic(`LEGACY entries no longer used, delete them: ${stale.join(', ')}`);
  assert.ok(Array.isArray(stale));
});

/** ERE (grep -E) → JS RegExp, case-insensitive like the hook's `git grep -i`. */
function ereToRegExp(pattern) {
  const js = pattern
    .replace(/\[\[:digit:\]\]/g, '[0-9]').replace(/\[\[:alpha:\]\]/g, '[A-Za-z]')
    .replace(/\[\[:alnum:\]\]/g, '[A-Za-z0-9]').replace(/\[\[:space:\]\]/g, '\\s');
  return new RegExp(js, 'i');
}

test('hygiene (local only): no .private-denylist pattern or private target occurs in any file, gz wordlists included', (t) => {
  const denyFile = join(ROOT, '.private-denylist');
  const targetsFile = join(ROOT, 'tests', 'live', 'targets.local.json');
  const patterns = [];
  if (existsSync(denyFile)) {
    readFileSync(denyFile, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
      .forEach((p, i) => {
        let re;
        try { re = ereToRegExp(p); } catch { assert.fail(`.private-denylist pattern #${i + 1} is not a valid regular expression`); }
        patterns.push({ label: `.private-denylist pattern #${i + 1}`, re });
      });
  }
  if (existsSync(targetsFile)) {
    let data = {};
    try { data = JSON.parse(readFileSync(targetsFile, 'utf8')); } catch { /* unreadable: nothing to check */ }
    const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    (Array.isArray(data.domains) ? data.domains : []).forEach((d, i) => {
      patterns.push({ label: `targets.local.json domain #${i + 1}`, re: new RegExp(`(?<![\\w-])${esc(d)}(?![\\w-])`, 'i') });
    });
    // Last octets a documentation-range example must not reuse, so no fixture mirrors a real
    // address: those of the private origin IPs plus the optional `avoidLastOctets` list.
    const octets = new Set((Array.isArray(data.avoidLastOctets) ? data.avoidLastOctets : [])
      .map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 255));
    Object.values(data.originTruth && typeof data.originTruth === 'object' ? data.originTruth : {}).forEach((ip, i) => {
      const v4 = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$/.exec(String(ip));
      if (!v4 || inAny(String(ip), SPECIAL_V4)) return; // documentation / private space is not identifying
      octets.add(Number(v4[2]));
      patterns.push({ label: `targets.local.json origin IP #${i + 1} (its /24)`, re: new RegExp(`(?<![\\d.])${esc(v4[1])}\\.\\d{1,3}(?![\\d])`) });
    });
    if (octets.size) {
      const list = [...octets].sort((a, b) => a - b).join('|');
      patterns.push({
        label: 'a documentation-range address reusing a private last octet',
        re: new RegExp(`(?<![\\d.])(?:192\\.0\\.2|198\\.51\\.100|203\\.0\\.113)\\.(?:${list})(?![\\d])`)
      });
    }
  }
  if (!patterns.length) {
    t.skip('no .private-denylist / targets.local.json in this clone (CI)');
    return;
  }
  const hits = [];
  for (const { rel, text } of repoFiles()) {
    for (const { label, re } of patterns) {
      const g = new RegExp(re.source, `${re.flags}g`);
      for (const m of text.matchAll(g)) {
        hits.push(`${rel}:${lineOf(text, m.index)} matches ${label}`);
        if (hits.length > 50) break;
      }
    }
  }
  assert.deepEqual(hits, [], `private names / addresses found (details deliberately not printed):\n  ${hits.join('\n  ')}`);
});
