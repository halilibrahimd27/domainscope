/**
 * tools/build-ranges.mjs — the parsers of each published list (fixtures shaped like each source,
 * documentation prefixes only), the prefix checks, the merge, the dataset and the download cache.
 * No network: downloads go through a fake fetch, or read the fixtures as the offline cache.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SOURCES, TIERS, BOUNDS, CANARIES, FORMAT, PARSERS, RangeDataError, normalizePrefix, mergePrefixes, buildRanges, downloadSource, datasetDigest
} from '../../tools/build-ranges.mjs';
import { RANGES_FORMAT, getProvider, NETWORKS } from '../../assets/js/lib/netinfo.js';

const FIX = fileURLToPath(new URL('../fixtures/ranges/', import.meta.url));
const anyRoute = () => true; // documentation prefixes are not globally routable: the fixtures need a permissive check
const fixtureTexts = () => Object.fromEntries(SOURCES.map((s) => [s.id, readFileSync(join(FIX, s.file), 'utf8')]));
const build = (over = {}) => buildRanges({ texts: fixtureTexts(), bounds: {}, canaries: [], routable: anyRoute, now: new Date('2026-10-08T12:00:00Z'), ...over });
const quiet = () => {};

test('build-ranges: the sources, tiers and checks line up with lib/netinfo.js', () => {
  assert.equal(FORMAT, RANGES_FORMAT, 'the builder writes the format netinfo reads');
  assert.equal(new Set(SOURCES.map((s) => s.id)).size, SOURCES.length);
  for (const s of SOURCES) {
    assert.match(s.url, /^https:\/\//, s.id);
    assert.equal(typeof PARSERS[s.parse], 'function', s.id);
  }
  const ids = new Set(SOURCES.map((s) => s.id));
  for (const [tier, entries] of Object.entries(TIERS)) {
    for (const [id, feeds] of Object.entries(entries)) {
      if (tier === 'edges') assert.ok(getProvider(id) && getProvider(id).cidrs.length, `edge ${id} replaces a built-in provider table`);
      else assert.ok(NETWORKS.some((n) => n.id === id), `network ${id} is a netinfo NETWORKS entry`);
      for (const [src] of feeds) assert.ok(ids.has(src), `${tier}/${id} ← ${src}`);
    }
  }
  for (const key of Object.keys(BOUNDS)) assert.ok(ids.has(key.split('/')[0]), key);
  for (const [tier, id] of CANARIES) assert.ok(TIERS[tier][id], `${tier}/${id}`);
});

test('build-ranges: each parser reads its source shape', () => {
  const t = fixtureTexts();
  assert.deepEqual(PARSERS.lines(t['cloudflare-v4']), { all: ['192.0.2.0/25', '192.0.2.128/25'] });
  assert.deepEqual(PARSERS.fastly(t.fastly), { all: ['198.51.100.0/27', '2001:db8:f::/48'] });
  const aws = PARSERS.aws(t.aws);
  assert.deepEqual(aws.cloudfront, ['203.0.113.0/26', '2001:db8:a::/48'], 'service CLOUDFRONT only');
  assert.equal(aws.all.length, 7);
  assert.equal(aws.published, '2026-10-08-08-00-00');
  assert.deepEqual(PARSERS.github(t.github).pages, ['198.51.100.153/32', '198.51.100.154/32', '2001:db8:9::153/128'], 'Pages only, not hooks or actions');
  assert.deepEqual(PARSERS.google(t.google).all, ['198.51.100.128/26', '2001:db8:6::/47']);
  assert.deepEqual(PARSERS.google(t['google-cloud']).all, ['198.51.100.160/27', '2001:db8:7::/48']);
  assert.deepEqual(PARSERS.oracle(t.oracle).all, ['203.0.113.128/27', '203.0.113.160/27', '2001:db8:c::/48', '203.0.113.208/28']);
  assert.deepEqual(PARSERS.geofeed(`# comment\n${t.digitalocean}\n`).all, ['203.0.113.224/28', '203.0.113.240/28', '2001:db8:d0::/48']);
  const ripe = PARSERS.ripe(t.as13335);
  assert.deepEqual(ripe.all, ['192.0.2.0/24', '198.51.100.32/27', '2001:db8:cf::/48']);
  assert.equal(ripe.published, '2026-10-08T00:00:00');
});

test('build-ranges: a parser refuses an answer of the wrong shape', () => {
  const bad = [
    ['lines', '<!DOCTYPE html><title>Attention Required!</title>'],
    ['fastly', '{"addresses":["198.51.100.0/27"]}'],
    ['aws', '{"prefixes":[{"ip_prefix":"203.0.113.0/26"}]}'],
    ['aws', '{"prefixes":[{"region":"x"}],"ipv6_prefixes":[]}'],
    ['github', '{"hooks":[]}'],
    ['google', '{"prefixes":[{"service":"Google Cloud"}]}'],
    ['oracle', '{"regions":[{"region":"x"}]}'],
    ['geofeed', '<html><body>Not found</body></html>'],
    ['ripe', '{"status":"error","data":{"prefixes":[]}}'],
    ['ripe', '{"status":"ok"}'],
    ['aws', 'not json'],
    ['fastly', '[]']
  ];
  for (const [parser, text] of bad) assert.throws(() => PARSERS[parser](text), RangeDataError, `${parser}: ${text}`);
});

test('build-ranges: a prefix is canonical, aligned, not too wide and globally routable', () => {
  assert.deepEqual(normalizePrefix('192.0.2.0/24', { routable: anyRoute }), { text: '192.0.2.0/24', version: 4, start: 3221225984n, end: 3221226239n });
  assert.equal(normalizePrefix('2001:DB8:0:0::/32', { routable: anyRoute }).text, '2001:db8::/32');
  assert.equal(normalizePrefix('192.0.2.7', { routable: anyRoute }).text, '192.0.2.7/32', 'a bare address is a host route');
  for (const text of ['192.0.2.1/24', '192.0.2.0/33', '0.0.0.0/0', '192.0.0.0/7', '2001:db8::/15', 'example.com', '', '192.0.2.0/24 x', null]) {
    assert.throws(() => normalizePrefix(text, { routable: anyRoute }), RangeDataError, String(text));
  }
  // by default, private, reserved and documentation space is refused: a list holding it is not trusted
  for (const text of ['192.0.2.0/24', '10.0.0.0/8', '100.64.0.0/10', '2001:db8::/32', 'fc00::/7']) {
    assert.throws(() => normalizePrefix(text), /not globally routable/, text);
  }
  assert.equal(normalizePrefix('104.16.0.0/13').text, '104.16.0.0/13');
});

test('build-ranges: merging keeps exactly the same addresses in the fewest prefixes', () => {
  const m = (...list) => mergePrefixes(list.map((p) => normalizePrefix(p, { routable: anyRoute })));
  assert.deepEqual(m('192.0.2.0/25', '192.0.2.128/25'), ['192.0.2.0/24'], 'two halves');
  assert.deepEqual(m('192.0.2.0/24', '192.0.2.64/26', '192.0.2.10/32'), ['192.0.2.0/24'], 'covered prefixes vanish');
  assert.deepEqual(m('192.0.2.0/26', '192.0.2.64/26', '192.0.2.128/26'), ['192.0.2.0/25', '192.0.2.128/26'], 'an unaligned union');
  assert.deepEqual(m('192.0.2.128/25', '198.51.100.0/24', '192.0.2.0/26'), ['192.0.2.0/26', '192.0.2.128/25', '198.51.100.0/24'], 'gaps stay, address order');
  assert.deepEqual(m('2001:db8:1::/48', '2001:db8::/48', '192.0.2.0/24'), ['192.0.2.0/24', '2001:db8::/47'], 'IPv4 first, then IPv6');
  assert.deepEqual(m('192.0.2.255/32', '198.51.100.0/32'), ['192.0.2.255/32', '198.51.100.0/32'], 'not adjacent');
  assert.deepEqual(mergePrefixes([]), []);
});

test('build-ranges: the dataset from the fixtures', () => {
  const { files, manifest, report } = build();
  assert.deepEqual(report.problems, []);
  assert.deepEqual([...files.keys()].sort(), ['edges.json', 'manifest.json', 'networks.json']);
  const edges = JSON.parse(files.get('edges.json'));
  const networks = JSON.parse(files.get('networks.json'));
  assert.deepEqual(edges, {
    cloudflare: ['192.0.2.0/24', '2001:db8:cf::/48'],
    cloudfront: ['203.0.113.0/26', '2001:db8:a::/48'],
    fastly: ['198.51.100.0/27', '2001:db8:f::/48'],
    'github-pages': ['198.51.100.153/32', '198.51.100.154/32', '2001:db8:9::153/128']
  });
  assert.deepEqual(networks.aws, ['203.0.113.0/25', '2001:db8:a::/47'], 'all of AWS, merged');
  assert.deepEqual(networks.cloudflare, ['192.0.2.0/24', '198.51.100.32/27', '198.51.100.64/27', '2001:db8:cf::/48'], 'both ASes and the proxy ranges');
  assert.deepEqual(networks.oracle, ['203.0.113.128/26', '203.0.113.208/28', '2001:db8:c::/48']);
  assert.deepEqual(networks.digitalocean, ['203.0.113.224/27', '2001:db8:d0::/48']);
  assert.deepEqual(Object.keys(networks), ['aws', 'cloudflare', 'digitalocean', 'google', 'google-cloud', 'oracle'], 'keys in order');
  assert.match(files.get('edges.json'), /^\{\n"cloudflare": \[\n"192\.0\.2\.0\/24",\n"2001:db8:cf::\/48"\n\],\n/, 'one prefix a line');
  // the manifest
  assert.equal(manifest.format, FORMAT);
  assert.equal(manifest.generated, '2026-10-08');
  assert.match(manifest.digest, /^[0-9a-f]{64}$/);
  assert.deepEqual(manifest.sources.map((s) => s.url), SOURCES.map((s) => s.url));
  const aws = manifest.sources.find((s) => s.id === 'aws');
  assert.equal(aws.published, '2026-10-08-08-00-00');
  assert.equal(aws.prefixes, 7);
  assert.match(aws.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(manifest.counts.edges, { cloudflare: 2, cloudfront: 2, fastly: 2, 'github-pages': 3 });
  assert.equal(manifest.counts.networks.aws, 2);
  for (const name of ['edges.json', 'networks.json']) {
    assert.equal(manifest.files[name].bytes, Buffer.byteLength(files.get(name)));
    assert.match(manifest.files[name].sha256, /^[0-9a-f]{64}$/);
  }
  assert.deepEqual(JSON.parse(files.get('manifest.json')), manifest);
  const { generated, digest, ...body } = manifest;
  assert.equal(datasetDigest(files, body), digest, generated);
});

test('build-ranges: a rebuild with nothing new keeps the date and the publishers\' stamps', () => {
  const first = build().manifest;
  const texts = fixtureTexts();
  texts.aws = texts.aws.replace('2026-10-08-08-00-00', '2026-10-15-08-00-00'); // AWS republished the same prefixes
  texts.as13335 = texts.as13335.replaceAll('2026-10-08T00:00:00', '2026-10-15T00:00:00');
  const again = build({ texts, previous: first, now: new Date('2026-10-15T12:00:00Z') });
  assert.equal(again.manifest.generated, '2026-10-08');
  assert.equal(again.manifest.digest, first.digest);
  assert.equal(again.files.get('manifest.json'), build().files.get('manifest.json'), 'byte for byte: the workflow opens nothing');
  // a new prefix: a new date, and AWS's own stamp of that version
  texts.aws = texts.aws.replace('"ipv6_prefixes": [', '"ipv6_prefixes": [\n    { "ipv6_prefix": "2001:db8:e::/48", "region": "x", "service": "EC2", "network_border_group": "x" },');
  const changed = build({ texts, previous: first, now: new Date('2026-10-15T12:00:00Z') });
  assert.equal(changed.manifest.generated, '2026-10-15');
  assert.notEqual(changed.manifest.digest, first.digest);
  assert.equal(changed.manifest.sources.find((s) => s.id === 'aws').published, '2026-10-15-08-00-00');
  assert.equal(changed.manifest.sources.find((s) => s.id === 'as13335').published, '2026-10-08T00:00:00', 'unchanged source: old stamp');
});

test('build-ranges: a download that looks wrong is a problem, so nothing is written', () => {
  const tooFew = build({ bounds: { 'cloudflare-v4': [8, 100], 'aws/cloudfront': [50, 5000] } }).report.problems;
  assert.deepEqual(tooFew, ['cloudflare-v4: 2 prefixes, expected 8–100', 'aws/cloudfront: 2 prefixes, expected 50–5000']);
  const texts = fixtureTexts();
  texts.fastly = '<html>maintenance</html>';
  assert.match(build({ texts }).report.problems.join(), /fastly: not JSON/);
  const texts2 = fixtureTexts();
  texts2.digitalocean = '10.0.0.0/8,NL,,,\n';
  assert.match(build({ texts: texts2, routable: undefined }).report.problems.join(), /digitalocean: 10\.0\.0\.0\/8 is not globally routable/);
  const canary = build({ canaries: [['edges', 'cloudflare', '192.0.2.1'], ['networks', 'google', '203.0.113.1']] }).report.problems;
  assert.deepEqual(canary, ['networks/google: 203.0.113.1 is missing']);
  // the real checks refuse the documentation fixtures outright
  assert.ok(buildRanges({ texts: fixtureTexts() }).report.problems.length > 0);
});

test('build-ranges: downloads are checked before they are cached, and --offline reads the cache only', async () => {
  const cache = await mkdtemp(join(tmpdir(), 'ds-ranges-'));
  try {
    const src = SOURCES.find((s) => s.id === 'fastly');
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), ua: init.headers['user-agent'], signal: init.signal instanceof AbortSignal });
      return new Response(readFileSync(join(FIX, 'fastly.json'), 'utf8'), { status: 200 });
    };
    const text = await downloadSource(src, { cache, fetchImpl, log: quiet });
    assert.deepEqual(JSON.parse(text).addresses, ['198.51.100.0/27']);
    assert.deepEqual(calls, [{ url: 'https://api.fastly.com/public-ip-list', ua: calls[0].ua, signal: true }]);
    assert.match(calls[0].ua, /^domainscope-build-ranges/);
    assert.equal(await downloadSource(src, { cache, fetchImpl, log: quiet }), text);
    assert.equal(calls.length, 1, 'cached for 12 h');
    assert.equal(await readFile(join(cache, src.file), 'utf8'), text);
    // an error page answered with 200 is not cached
    const cf = SOURCES.find((s) => s.id === 'cloudflare-v4');
    const html = async () => new Response('<!doctype html><p>Just a moment…</p>', { status: 200 });
    await assert.rejects(downloadSource(cf, { cache, fetchImpl: html, log: quiet }), /an HTML page.*\(not cached\)/);
    await assert.rejects(downloadSource(cf, { cache, offline: true, log: quiet }), /--offline: .* is not cached/);
    await assert.rejects(downloadSource(cf, { cache, fetchImpl: async () => new Response('', { status: 503 }), log: quiet }), /HTTP 503/);
    // a cached copy that no longer parses is deleted
    await writeFile(join(cache, cf.file), '<html></html>');
    await assert.rejects(downloadSource(cf, { cache, offline: true, log: quiet }), /the cached copy was deleted/);
    await assert.rejects(readFile(join(cache, cf.file)), { code: 'ENOENT' });
    // the fixtures are a complete offline cache
    for (const s of SOURCES) assert.ok((await downloadSource(s, { cache: FIX, offline: true, log: quiet })).length > 0, s.id);
  } finally {
    await rm(cache, { recursive: true, force: true });
  }
});
