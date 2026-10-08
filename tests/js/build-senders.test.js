/**
 * tools/build-senders.mjs — the CSV reader (quoted commas, doubled quotes, line ends, a quote left
 * open), the licence check (Apache-2.0 alone, never a share-alike map), the type filter and
 * renaming, the manifest, the checks that refuse a bad download, and a bad download leaving the
 * files on disk untouched. Fixtures shaped like parsedmarc's map with documentation names only
 * (tests/fixtures/senders); no network: downloads go through a fake fetch.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SOURCE, DOWNLOADS, HEADER, KNOWN_TYPES, BOUNDS, CANARIES, FORMAT, LICENCE, SenderDataError, parseCsv, licenceProblems, buildSenders,
  downloadFile, datasetDigest, run, rawUrl
} from '../../tools/build-senders.mjs';
import { PTR_TYPE_MAP, SENDERS_FORMAT, installSenderMaps } from '../../assets/js/lib/senders.js';

const FIX = fileURLToPath(new URL('../fixtures/senders/', import.meta.url));
const fixture = (name) => readFileSync(join(FIX, name), 'utf8');
const texts = () => ({ csv: fixture('base_reverse_dns_map.csv'), readme: fixture('README.md'), licence: fixture('LICENSE') });
/** The fixture source: no pinned hash, no bounds or canaries of the real map. */
const FIXTURE_SOURCE = { ...SOURCE, sha256: null };
const build = (over = {}) => buildSenders({ ...texts(), source: FIXTURE_SOURCE, bounds: {}, canaries: [], now: new Date('2026-10-08T12:00:00Z'), ...over });
const quiet = () => {};
const sha = (s) => createHash('sha256').update(s).digest('hex');

test('build-senders: the pinned source, its downloads and the checks line up with lib/senders.js', () => {
  assert.equal(FORMAT, SENDERS_FORMAT, 'the builder writes the format lib/senders.js reads');
  assert.match(SOURCE.commit, /^[0-9a-f]{40}$/);
  assert.match(SOURCE.sha256, /^[0-9a-f]{64}$/);
  assert.match(SOURCE.committed, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(DOWNLOADS.map((d) => d.path), [SOURCE.path, SOURCE.readme, SOURCE.licence]);
  for (const d of DOWNLOADS) assert.match(rawUrl(SOURCE.commit, d.path), /^https:\/\/raw\.githubusercontent\.com\/domainaware\/parsedmarc\/[0-9a-f]{40}\//, d.id);
  assert.deepEqual(HEADER, ['base_reverse_dns', 'name', 'type']);
  // every mail-relevant type and the ISP type are types the map defines
  for (const t of [...Object.keys(PTR_TYPE_MAP), 'ISP']) assert.ok(KNOWN_TYPES.includes(t), t);
  for (const [key, re, type] of CANARIES) {
    assert.ok(KNOWN_TYPES.includes(type) && re instanceof RegExp && key.includes('.'), key);
  }
  assert.ok(BOUNDS.rows[0] < BOUNDS.rows[1] && BOUNDS.ptr[0] < BOUNDS.ptr[1] && BOUNDS.isp[0] < BOUNDS.isp[1]);
  assert.equal(LICENCE.spdx, 'Apache-2.0');
  assert.match(LICENCE.notice, /parsedmarc/);
  assert.match(LICENCE.notice, /Apache License, Version 2\.0/);
});

test('parseCsv: quoted commas, doubled quotes, CRLF and LF, a BOM, blank lines', () => {
  assert.deepEqual(parseCsv('a,b,c\nx.example.com,"Example, Inc.",SaaS\n'), [['a', 'b', 'c'], ['x.example.com', 'Example, Inc.', 'SaaS']]);
  assert.deepEqual(parseCsv('﻿a,b\r\n"say ""hi""",2\r\n\r\nlast,row'), [['a', 'b'], ['say "hi"', '2'], ['last', 'row']]);
  assert.deepEqual(parseCsv('"two\nlines",x\n'), [['two\nlines', 'x']], 'a line break inside quotes stays in the field');
  assert.deepEqual(parseCsv('a,,c\n,,\n'), [['a', '', 'c'], ['', '', '']], 'empty fields are kept');
  assert.deepEqual(parseCsv(''), []);
  const rows = parseCsv(fixture('base_reverse_dns_map.csv'));
  assert.deepEqual(rows[0], HEADER);
  assert.deepEqual(rows.find((r) => r[0] === 'filter.example.net'), ['filter.example.net', 'The "Filter" Company', 'Email Security']);
  assert.deepEqual(rows.find((r) => r[0] === 'dsl.example.org'), ['dsl.example.org', 'Example Telecom, Ltd', 'isp']);
  for (const bad of ['a,"b\nc,d\n', 'a,"b"c\n', 'a,b"c"\n']) assert.throws(() => parseCsv(bad), SenderDataError, JSON.stringify(bad));
  assert.throws(() => parseCsv(null), SenderDataError);
});

test('licenceProblems: the Apache License alone; a map put under CC BY-SA is refused', () => {
  assert.deepEqual(licenceProblems({ licence: fixture('LICENSE'), readme: fixture('README.md') }), []);
  const shareAlike = `${fixture('README.md')}\n### License\n\nthis CSV is also distributed under **CC BY-SA 4.0** with attribution to IPinfo.\n`;
  assert.match(licenceProblems({ licence: fixture('LICENSE'), readme: shareAlike }).join(), /share-alike/);
  for (const words of ['Attribution-ShareAlike 4.0', 'https://creativecommons.org/licenses/by-sa/4.0/', 'CC-BY-SA']) {
    assert.equal(licenceProblems({ licence: fixture('LICENSE'), readme: `x ${words} y` }).length, 1, words);
  }
  assert.match(licenceProblems({ licence: 'MIT License\n', readme: fixture('README.md') }).join(), /not the Apache License/);
  assert.match(licenceProblems({ licence: fixture('LICENSE'), readme: '' }).join(), /missing/);
});

test('build-senders: the type filter, the renaming, the ISP list and what is left out', () => {
  const { files, report } = build();
  assert.deepEqual(report.problems, []);
  assert.deepEqual([...files.keys()].sort(), ['isp.json', 'manifest.json', 'ptr-map.json']);
  const ptrMap = JSON.parse(files.get('ptr-map.json'));
  const isp = JSON.parse(files.get('isp.json'));
  assert.equal(ptrMap.format, FORMAT);
  assert.equal(ptrMap.notice, LICENCE.notice, 'the notice travels with the data');
  assert.deepEqual(ptrMap.map, {
    'cloud.example.org': ['Example Cloud', 'cloud'],
    'esp.example.net': ['Example ESP, Inc.', 'marketing'],
    'filter.example.net': ['The "Filter" Company', 'security'],
    'host.example.org': ['Example Hosting', 'hosting'],
    'mailbox.example.net': ['Example Mail', 'mailbox'],
    'msp.example.com': ['Example IT Partners', 'msp'],
    'mssp.example.com': ['Example SOC, managed', 'msp'],
    'paas.example.org': ['Example Apps', 'cloud'],
    'saas.example.com': ['Example Desk', 'saas'],
    'tech.example.com': ['Example Tech', 'technology']
  }, 'the ten mail-relevant types only, renamed; keys lower case; the first of a duplicate; names trimmed');
  assert.deepEqual(isp.domains, ['dsl.example.org', 'isp.example.net'], 'ISP rows, any case of the type, base domains only');
  assert.ok(!files.get('isp.json').includes('Example Broadband'), 'no ISP name');
  assert.deepEqual(report.skipped, { name: 0, key: 1, suffix: 1, duplicate: 1 });
  assert.deepEqual(report.counts, { rows: 17, types: 13, ptr: 10, isp: 2 });
  assert.match(files.get('ptr-map.json'), /\n"cloud\.example\.org": \["Example Cloud","cloud"\],\n"esp\.example\.net"/, 'one entry a line, in key order');
  // what lib/senders.js reads back
  const maps = installSenderMaps({ manifest: JSON.parse(files.get('manifest.json')), ptrMap, isp });
  assert.deepEqual(maps.ptr.get('mailbox.example.net'), ['Example Mail', 'mailbox']);
  assert.ok(maps.isp.has('dsl.example.org'));
});

test('build-senders: the manifest names the source, the commit, the SHA-256, the counts and the licence', () => {
  const { files, manifest } = build();
  assert.equal(manifest.format, FORMAT);
  assert.equal(manifest.generated, '2026-10-08');
  assert.match(manifest.digest, /^[0-9a-f]{64}$/);
  assert.equal(manifest.source.url, rawUrl(SOURCE.commit, SOURCE.path));
  assert.equal(manifest.source.commit, SOURCE.commit);
  assert.equal(manifest.source.sha256, sha(fixture('base_reverse_dns_map.csv')));
  assert.equal(manifest.source.rows, 17);
  assert.deepEqual(manifest.licence, {
    spdx: 'Apache-2.0', name: 'Apache License, Version 2.0', copyright: LICENCE.copyright, url: rawUrl(SOURCE.commit, 'LICENSE'), notice: LICENCE.notice
  });
  for (const name of ['ptr-map.json', 'isp.json']) {
    assert.equal(manifest.files[name].bytes, Buffer.byteLength(files.get(name)));
    assert.equal(manifest.files[name].sha256, sha(files.get(name)));
  }
  assert.deepEqual(manifest.counts.byType.Marketing, 1);
  assert.equal(manifest.counts.byType.ISP, 2, 'the lower-case "isp" counted under its canonical name');
  assert.deepEqual(JSON.parse(files.get('manifest.json')), manifest);
  const { generated, digest, ...body } = manifest;
  assert.equal(datasetDigest(files, body), digest, generated);
  // a rebuild with nothing new keeps the date, byte for byte
  const again = build({ previous: manifest, now: new Date('2026-10-15T12:00:00Z') });
  assert.equal(again.manifest.generated, '2026-10-08');
  assert.equal(again.files.get('manifest.json'), files.get('manifest.json'));
  const changed = build({ previous: manifest, now: new Date('2026-10-15T12:00:00Z'), csv: `${fixture('base_reverse_dns_map.csv')}new.example.net,Example New,SaaS\n` });
  assert.equal(changed.manifest.generated, '2026-10-15');
});

test('build-senders: a download that looks wrong is a problem, so nothing may be written', () => {
  const problems = (over) => build(over).report.problems.join(' | ');
  assert.match(problems({ source: SOURCE }), /SHA-256 [0-9a-f]{64}, the pinned commit has/, 'not the pinned file');
  assert.match(problems({ csv: 'domain,name,type\nx.example.com,X,SaaS\n' }), /header "domain,name,type"/);
  assert.match(problems({ csv: `${fixture('base_reverse_dns_map.csv')}cut.example.com,"Cut short` }), /a quote is never closed/);
  assert.match(problems({ csv: `${fixture('base_reverse_dns_map.csv')}wide.example.com,Wide,SaaS,extra\n` }), /1 rows without exactly 3 fields/);
  assert.match(problems({ csv: `${fixture('base_reverse_dns_map.csv')}new.example.com,New,Mailbox Provider\n` }), /unknown type "Mailbox Provider" \(1 rows\)/);
  assert.match(problems({ bounds: { rows: [2000, 200000] } }), /rows: 17, expected 2000–200000/);
  assert.match(problems({ canaries: [['esp.example.net', /Example ESP/, 'Marketing'], ['gone.example.com', /Gone/, 'SaaS']] }), /canary gone\.example\.com: missing/);
  assert.match(problems({ canaries: [['esp.example.net', /Another/, 'Marketing']] }), /canary esp\.example\.net: .*expected a name matching/);
  assert.match(problems({ readme: `${fixture('README.md')}\nthis CSV is also distributed under CC BY-SA 4.0\n` }), /share-alike/);
  assert.equal(problems({ canaries: [['esp.example.net', /Example ESP/, 'Marketing']] }), '', 'the fixture passes its own canary');
  // the real checks refuse the fixture outright (its hash, its size)
  assert.ok(buildSenders({ ...texts() }).report.problems.length >= 2);
});

test('build-senders: downloads are checked before they are cached, and --offline reads the cache only', async () => {
  const cache = await mkdtemp(join(tmpdir(), 'ds-senders-cache-'));
  try {
    const item = DOWNLOADS[0];
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), ua: init.headers['user-agent'], signal: init.signal instanceof AbortSignal });
      return new Response(fixture('base_reverse_dns_map.csv'), { status: 200 });
    };
    const got = await downloadFile(item, { cache, fetchImpl, log: quiet });
    assert.equal(got.text, fixture('base_reverse_dns_map.csv'));
    assert.equal(got.sha256, sha(fixture('base_reverse_dns_map.csv')));
    assert.deepEqual(calls, [{ url: rawUrl(SOURCE.commit, SOURCE.path), ua: calls[0].ua, signal: true }]);
    assert.match(calls[0].ua, /^domainscope-build-senders/);
    assert.deepEqual(await downloadFile(item, { cache, fetchImpl, log: quiet }), got);
    assert.equal(calls.length, 1, 'cached for 12 h');
    // an error page answered with 200, a non-UTF-8 body and an HTTP error are not cached
    const readme = DOWNLOADS[1];
    await assert.rejects(downloadFile(readme, { cache, fetchImpl: async () => new Response('<!DOCTYPE html><p>Rate limited</p>', { status: 200 }), log: quiet }),
      /an HTML page.*\(not cached\)/);
    await assert.rejects(downloadFile(readme, { cache, fetchImpl: async () => new Response(new Uint8Array([0x61, 0xff, 0xfe]), { status: 200 }), log: quiet }),
      /not UTF-8/);
    await assert.rejects(downloadFile(readme, { cache, fetchImpl: async () => new Response('', { status: 429 }), log: quiet }), /HTTP 429/);
    await assert.rejects(downloadFile(readme, { cache, offline: true, log: quiet }), /--offline: .* is not cached/);
    // a cached copy that no longer reads is deleted
    await writeFile(join(cache, readme.file), '<html></html>');
    await assert.rejects(downloadFile(readme, { cache, offline: true, log: quiet }), /the cached copy was deleted/);
    await assert.rejects(readFile(join(cache, readme.file)), { code: 'ENOENT' });
  } finally {
    await rm(cache, { recursive: true, force: true });
  }
});

test('build-senders: run() writes the lists, then a bad download leaves the files on disk untouched', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ds-senders-run-'));
  const out = join(root, 'senders');
  const cache = join(root, 'cache');
  const byPath = { [SOURCE.path]: 'base_reverse_dns_map.csv', [SOURCE.readme]: 'README.md', [SOURCE.licence]: 'LICENSE' };
  const serve = (over = {}) => async (url) => {
    const path = Object.keys(byPath).find((p) => String(url).endsWith(`/${p}`));
    if (!path) return new Response('', { status: 404 });
    return new Response(over[path] ?? fixture(byPath[path]), { status: 200 });
  };
  const opts = { out, cache, log: quiet, source: FIXTURE_SOURCE, bounds: {}, canaries: [], now: new Date('2026-10-08T12:00:00Z') };
  try {
    const first = await run({ ...opts, fetchImpl: serve() });
    assert.equal(first.changed, 3);
    const before = Object.fromEntries(await Promise.all(['manifest.json', 'ptr-map.json', 'isp.json'].map(async (f) => [f, await readFile(join(out, f), 'utf8')])));
    assert.equal(JSON.parse(before['manifest.json']).counts.ptr, 10);
    // the same download again: nothing changes, not even the date
    await rm(cache, { recursive: true, force: true });
    const again = await run({ ...opts, fetchImpl: serve(), now: new Date('2026-10-15T12:00:00Z') });
    assert.equal(again.changed, 0);
    // a cut download, then a map put under CC BY-SA: rejected, every file as it was
    for (const over of [
      { [SOURCE.path]: `${fixture('base_reverse_dns_map.csv')}cut.example.com,"Cut short` },
      { [SOURCE.readme]: 'This CSV is also distributed under CC BY-SA 4.0.' },
      { [SOURCE.path]: 'base_reverse_dns,name\nx.example.com,X\n' }
    ]) {
      await rm(cache, { recursive: true, force: true });
      await assert.rejects(run({ ...opts, fetchImpl: serve(over) }), /the download looks wrong, nothing written/);
      for (const [f, text] of Object.entries(before)) assert.equal(await readFile(join(out, f), 'utf8'), text, `${f} untouched`);
    }
    // the fixtures are a complete offline cache
    await rm(cache, { recursive: true, force: true });
    await mkdir(cache, { recursive: true });
    for (const d of DOWNLOADS) await copyFile(join(FIX, byPath[d.path]), join(cache, d.file));
    assert.equal((await run({ ...opts, offline: true, fetchImpl: async () => { throw new Error('no network'); } })).changed, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the bundled lists: the pinned map built, its manifest matching each file, and lib/senders.js reads them', async () => {
  const dir = fileURLToPath(new URL('../../assets/data/senders/', import.meta.url));
  const read = (f) => readFileSync(join(dir, f), 'utf8').replace(/\r\n/g, '\n');
  const manifest = JSON.parse(read('manifest.json'));
  assert.equal(manifest.format, FORMAT);
  assert.equal(manifest.source.commit, SOURCE.commit, 'built from the pinned commit');
  assert.equal(manifest.source.sha256, SOURCE.sha256);
  assert.equal(manifest.licence.spdx, 'Apache-2.0');
  for (const name of ['ptr-map.json', 'isp.json']) assert.equal(sha(read(name)), manifest.files[name].sha256, `${name}: as built (a hand edit fails)`);
  const maps = installSenderMaps({ manifest, ptrMap: JSON.parse(read('ptr-map.json')), isp: JSON.parse(read('isp.json')) });
  assert.equal(maps.ptr.size, manifest.counts.ptr);
  assert.equal(maps.isp.size, manifest.counts.isp);
  for (const [key, re, type] of CANARIES) {
    const entry = maps.ptr.get(key);
    assert.ok(entry && re.test(entry[0]) && entry[1] === PTR_TYPE_MAP[type], key);
  }
  for (const key of maps.ptr.keys()) assert.ok(!maps.isp.has(key), `${key} is in one list only`);
});
