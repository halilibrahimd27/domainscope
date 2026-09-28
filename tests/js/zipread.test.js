/**
 * lib/zipread.js — the containers mail reports arrive in: gzip and zip read in the platform's
 * DecompressionStream, the zip central directory (ZIP64, data descriptors, stored and deflated
 * entries, UTF-8 names), CRC-32 and size checks, the caps that stop a zip bomb, and a dropped
 * file unpacked into its plain files with a reason for every part that could not be read.
 * The positive cases read archives Python's zipfile and gzip wrote (tests/fixtures/mailreports,
 * gen_mailreports.py); the broken ones are built here byte by byte. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync, gzipSync } from 'node:zlib';
import {
  ZIP_ERRORS, ZIP_LIMITS, ZipError, crc32, containerOf, toBytes, readZipDirectory, extractZipEntry, inflate, gunzip, unpackFile
} from '../../assets/js/lib/zipread.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'mailreports');
const fixture = (name) => new Uint8Array(readFileSync(join(DIR, name)));
const src = (name) => readFileSync(join(DIR, 'src', name), 'utf8');
const text = (bytes) => new TextDecoder().decode(bytes);

const GOOGLE_XML = 'google.com!example.com!1790380800!1790467199.xml';
const MICROSOFT_XML = 'enterprise.protection.outlook.com!example.com!1790294400!1790380800.xml';
const BIS_XML = 'mail.example.org!example.net!1790294400!1790380799.xml';
const GOOGLE_TLS = 'google.com!example.com!1790380800!1790467199!001.json';
const MICROSOFT_TLS = 'microsoft.com!example.com!1790294400!1790380800.json';

/* ---- a zip writer for the broken cases -------------------------------------------------- */

const enc = new TextEncoder();
const u16 = (n) => [n & 0xff, (n >>> 8) & 0xff];
const u32 = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const u64 = (n) => [...u32(n % 2 ** 32), ...u32(Math.floor(n / 2 ** 32))];

/**
 * entries: [{ name, data, method = 8, flags = 0, crc?, size?, zip64? }]; opts.comment, opts.zip64
 * (a ZIP64 end record with 0xffff / 0xffffffff in the classic one), opts.disk.
 */
function buildZip(entries, { comment = '', zip64 = false, disk = 0 } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = enc.encode(e.name);
    const raw = typeof e.data === 'string' ? enc.encode(e.data) : e.data;
    const method = e.method ?? 8;
    const body = method === 8 ? new Uint8Array(deflateRawSync(raw)) : raw;
    const crc = e.crc ?? crc32(raw);
    const size = e.size ?? raw.length;
    const flags = e.flags ?? 0;
    const local = [...u32(0x04034b50), ...u16(20), ...u16(flags), ...u16(method), ...u16(0), ...u16(0x5b3b),
      ...u32(crc), ...u32(body.length), ...u32(size), ...u16(name.length), ...u16(0), ...name];
    parts.push(Uint8Array.from(local), body);
    const extra = e.zip64 ? [...u16(1), ...u16(24), ...u64(size), ...u64(body.length), ...u64(offset)] : [];
    central.push(Uint8Array.from([...u32(0x02014b50), ...u16(0x031e), ...u16(20), ...u16(flags), ...u16(method), ...u16(0), ...u16(0x5b3b),
      ...u32(crc), ...u32(e.zip64 ? 0xffffffff : body.length), ...u32(e.zip64 ? 0xffffffff : size), ...u16(name.length), ...u16(extra.length),
      ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(e.zip64 ? 0xffffffff : offset), ...name, ...extra]));
    offset += local.length + body.length;
  }
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const tail = [];
  if (zip64) {
    const at = offset + cdSize;
    tail.push(...u32(0x06064b50), ...u64(44), ...u16(45), ...u16(45), ...u32(disk), ...u32(disk), ...u64(entries.length), ...u64(entries.length),
      ...u64(cdSize), ...u64(offset));
    tail.push(...u32(0x07064b50), ...u32(0), ...u64(at), ...u32(1));
  }
  const c = enc.encode(comment);
  tail.push(...u32(0x06054b50), ...u16(zip64 ? 0xffff : disk), ...u16(zip64 ? 0xffff : disk), ...u16(zip64 ? 0xffff : entries.length),
    ...u16(zip64 ? 0xffff : entries.length), ...u32(zip64 ? 0xffffffff : cdSize), ...u32(zip64 ? 0xffffffff : offset), ...u16(c.length), ...c);
  const all = [...parts, ...central, Uint8Array.from(tail)];
  const out = new Uint8Array(all.reduce((n, p) => n + p.length, 0));
  let pos = 0;
  for (const p of all) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

const rejectsCode = (promise, code) => assert.rejects(promise, (err) => err instanceof ZipError && err.code === code);

/* ---- basics ----------------------------------------------------------------------------- */

describe('bytes, CRC-32 and the container sniffer', () => {
  test('crc32 matches the check value and the CRCs zipfile stored', () => {
    assert.equal(crc32(enc.encode('123456789')), 0xcbf43926);
    assert.equal(crc32(new Uint8Array(0)), 0);
    const { entries } = readZipDirectory(fixture('descriptor.zip'));
    assert.equal(crc32(enc.encode(src(GOOGLE_XML))), entries[0].crc);
  });

  test('containerOf reads the first bytes, never the name', () => {
    assert.equal(containerOf(fixture(`${MICROSOFT_XML}.gz`)), 'gzip');
    assert.equal(containerOf(fixture('reports-2026-09.zip')), 'zip');
    assert.equal(containerOf(buildZip([])), 'zip', 'an empty archive starts with its end record');
    assert.equal(containerOf(enc.encode('<?xml version="1.0"?><feedback/>')), null);
    assert.equal(containerOf(enc.encode('{"organization-name":"x"}')), null);
    assert.equal(containerOf(new Uint8Array(0)), null);
    assert.equal(containerOf(Uint8Array.of(0x1f)), null);
  });

  test('toBytes takes a Uint8Array, an ArrayBuffer or another view; anything else is a TypeError', () => {
    const b = Uint8Array.of(1, 2, 3);
    assert.equal(toBytes(b), b);
    assert.deepEqual([...toBytes(b.buffer)], [1, 2, 3]);
    assert.deepEqual([...toBytes(new DataView(b.buffer, 1, 2))], [2, 3]);
    assert.throws(() => toBytes('abc'), TypeError);
  });

  test('vocabularies and limits are frozen', () => {
    assert.ok(Object.isFrozen(ZIP_ERRORS) && Object.isFrozen(ZIP_LIMITS));
    assert.ok(ZIP_ERRORS.includes('crc') && ZIP_ERRORS.includes('too-large'));
    const e = new ZipError('method', 'bzip2');
    assert.equal(e.code, 'method');
    assert.equal(e.detail, 'bzip2');
    assert.equal(e.name, 'ZipError');
  });
});

/* ---- gzip and deflate ---------------------------------------------------------------------- */

describe('gzip and deflate streams', () => {
  test('gunzip: a Microsoft-style .xml.gz and a TLS-RPT .json.gz written by Python', async () => {
    assert.equal(text(await gunzip(fixture(`${MICROSOFT_XML}.gz`))), src(MICROSOFT_XML));
    assert.equal(text(await gunzip(fixture(`${GOOGLE_TLS}.gz`))), src(GOOGLE_TLS));
  });

  test('a gzip bomb stops at the cap, whatever size its trailer announces', async () => {
    const big = new Uint8Array(gzipSync(new Uint8Array(200000)));
    await rejectsCode(gunzip(big, { maxBytes: 1000 }), 'too-large');
    // a trailer that lies (says 10 bytes): the stream itself stops at the cap
    const lying = big.slice();
    lying.set(u32(10), lying.length - 4);
    await rejectsCode(gunzip(lying, { maxBytes: 1000 }), 'too-large');
  });

  test('a truncated or damaged stream is corrupt, bytes that are no gzip too', async () => {
    const gz = fixture(`${MICROSOFT_XML}.gz`);
    await rejectsCode(gunzip(gz.slice(0, gz.length - 40)), 'corrupt');
    await rejectsCode(gunzip(enc.encode('not gzip at all, just text')), 'corrupt');
    await rejectsCode(gunzip(gz.slice(0, 12)), 'truncated');
  });

  test('inflate: raw deflate, the cap, an abort, and a platform without DecompressionStream', async () => {
    const data = enc.encode('a'.repeat(5000));
    assert.equal(text(await inflate(deflateRawSync(data), 'deflate-raw')), 'a'.repeat(5000));
    await rejectsCode(inflate(deflateRawSync(data), 'deflate-raw', { maxBytes: 100 }), 'too-large');
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(inflate(deflateRawSync(data), 'deflate-raw', { signal: ac.signal }), (err) => err.name === 'AbortError');
    await rejectsCode(inflate(deflateRawSync(data), 'deflate-raw', { DecompressionStreamImpl: null }), 'unsupported');
  });
});

/* ---- zip ---------------------------------------------------------------------------------- */

describe('zip archives', () => {
  test('a Google-style zip: one deflated entry, its CRC and size checked', async () => {
    const zip = fixture('google.com!example.com!1790380800!1790467199.zip');
    const { entries, total } = readZipDirectory(zip);
    assert.equal(total, 1);
    assert.equal(entries[0].name, GOOGLE_XML);
    assert.equal(entries[0].method, 8);
    assert.equal(entries[0].encrypted, false);
    assert.equal(text(await extractZipEntry(zip, entries[0])), src(GOOGLE_XML));
  });

  test('data descriptors (bit 3): the central directory has the sizes', async () => {
    const zip = fixture('descriptor.zip');
    const { entries } = readZipDirectory(zip);
    assert.equal(entries[0].flags & 8, 8, 'written to a pipe');
    assert.equal(text(await extractZipEntry(zip, entries[0])), src(GOOGLE_XML));
  });

  test('stored entries, folders, a UTF-8 name and a comment holding the end signature', async () => {
    const zip = buildZip([
      { name: 'raporlar/', data: '', method: 0 },
      { name: 'raporlar/eylül.xml', data: '<feedback/>', method: 0, flags: 0x800 },
      { name: 'b.json', data: '{}' }
    ], { comment: `PK${String.fromCharCode(5, 6)} not the real end record` });
    const { entries } = readZipDirectory(zip);
    assert.deepEqual(entries.map((e) => [e.name, e.directory, e.method]), [['raporlar/', true, 0], ['raporlar/eylül.xml', false, 0], ['b.json', false, 8]]);
    assert.equal(text(await extractZipEntry(zip, entries[1])), '<feedback/>');
    assert.equal(text(await extractZipEntry(zip, entries[2])), '{}');
  });

  test('ZIP64: the end record, the locator and the 64-bit extra field', async () => {
    const zip = buildZip([{ name: 'big.xml', data: '<feedback/>', zip64: true }], { zip64: true });
    const { entries, total } = readZipDirectory(zip);
    assert.equal(total, 1);
    assert.equal(entries[0].size, 11);
    assert.equal(text(await extractZipEntry(zip, entries[0])), '<feedback/>');
  });

  test('what cannot be read is named: encrypted, another method, a bad CRC, a lying size, truncation, several disks', async () => {
    const one = (e, opts) => {
      const zip = buildZip([e], opts);
      return [zip, readZipDirectory(zip).entries[0]];
    };
    await rejectsCode(extractZipEntry(...one({ name: 'a.xml', data: 'x', flags: 1 })), 'encrypted');
    await assert.rejects(extractZipEntry(...one({ name: 'a.xml', data: 'x', method: 12 })), (err) => err.code === 'method' && err.detail === 'bzip2');
    await rejectsCode(extractZipEntry(...one({ name: 'a.xml', data: 'hello', crc: 1234 })), 'crc');
    await rejectsCode(extractZipEntry(...one({ name: 'a.xml', data: 'hello', size: 4 })), 'corrupt');
    await rejectsCode(extractZipEntry(...one({ name: 'a.xml', data: 'hello', size: 50 })), 'corrupt');
    const [zip, entry] = one({ name: 'a.xml', data: 'x'.repeat(2000), method: 0 });
    await rejectsCode(extractZipEntry(zip, entry, { maxBytes: 100 }), 'too-large');
    assert.throws(() => readZipDirectory(buildZip([{ name: 'a', data: 'x' }], { disk: 1 })), (err) => err.code === 'multi-disk');
    const good = fixture('reports-2026-09.zip');
    assert.throws(() => readZipDirectory(good.slice(0, good.length - 30)), (err) => err.code === 'truncated');
    assert.throws(() => readZipDirectory(good.slice(0, 100)), (err) => err.code === 'truncated');
    assert.throws(() => readZipDirectory(enc.encode('x'.repeat(100))), (err) => err.code === 'not-zip');
  });

  test('maxEntries caps the directory; total says how many the archive lists', () => {
    const zip = buildZip(Array.from({ length: 5 }, (_, i) => ({ name: `r${i}.xml`, data: 'x' })));
    const { entries, total } = readZipDirectory(zip, { maxEntries: 2 });
    assert.equal(entries.length, 2);
    assert.equal(total, 5);
  });
});

/* ---- a dropped file --------------------------------------------------------------------- */

describe('unpackFile — a dropped file into its plain files', () => {
  test('a plain file is itself', async () => {
    const r = await unpackFile({ name: BIS_XML, bytes: enc.encode(src(BIS_XML)) });
    assert.deepEqual(r.problems, []);
    assert.equal(r.files.length, 1);
    assert.deepEqual([r.files[0].name, r.files[0].path, r.files[0].via], [BIS_XML, BIS_XML, []]);
  });

  test('a .json.gz loses its .gz, keeps its path', async () => {
    const r = await unpackFile({ name: `${MICROSOFT_TLS}.gz`, bytes: fixture(`${MICROSOFT_TLS}.gz`).buffer });
    assert.deepEqual(r.files.map((f) => [f.name, f.path, f.via]), [[MICROSOFT_TLS, `${MICROSOFT_TLS}.gz`, ['gzip']]]);
    assert.equal(text(r.files[0].bytes), src(MICROSOFT_TLS));
  });

  test('a mailbox export: a zip of zips and gzip files, stored; junk skipped, every report out', async () => {
    const r = await unpackFile({ name: 'reports-2026-09.zip', bytes: fixture('reports-2026-09.zip') });
    assert.deepEqual(r.problems, []);
    assert.deepEqual(r.files.map((f) => [f.name, f.via.join('>')]), [
      [GOOGLE_XML, 'zip>zip'],
      [MICROSOFT_XML, 'zip>gzip'],
      [BIS_XML, 'zip'],
      [GOOGLE_TLS, 'zip>gzip'],
      [MICROSOFT_TLS, 'zip>gzip'],
      ['notes.txt', 'zip']
    ]);
    assert.equal(r.files[0].path, 'reports-2026-09.zip › dmarc/google.com!example.com!1790380800!1790467199.zip › google.com!example.com!1790380800!1790467199.xml');
    assert.equal(text(r.files[1].bytes), src(MICROSOFT_XML));
  });

  test('a third container level is not opened; a broken entry never stops the others', async () => {
    const inner = buildZip([{ name: 'deep.xml.gz', data: new Uint8Array(gzipSync(enc.encode('<feedback/>'))), method: 0 }]);
    const middle = buildZip([{ name: 'inner.zip', data: inner, method: 0 }]);
    const r = await unpackFile({ name: 'outer.gz', bytes: new Uint8Array(gzipSync(middle)) });
    assert.deepEqual(r.files, []);
    assert.deepEqual(r.problems.map((p) => [p.path, p.code]), [['outer.gz › inner.zip', 'nested']]);

    const mixed = buildZip([
      { name: 'good.xml', data: '<feedback/>' },
      { name: 'secret.xml', data: 'x', flags: 1 },
      { name: 'bad.xml', data: 'hello', crc: 7 },
      { name: 'b.json', data: '{}' }
    ]);
    const m = await unpackFile({ name: 'mixed.zip', bytes: mixed });
    assert.deepEqual(m.files.map((f) => f.name), ['good.xml', 'b.json']);
    assert.deepEqual(m.problems.map((p) => [p.path, p.code]), [['mixed.zip › secret.xml', 'encrypted'], ['mixed.zip › bad.xml', 'crc']]);
  });

  test('caps: bytes per entry, bytes per file, entries per archive', async () => {
    const zip = buildZip([{ name: 'a.xml', data: 'a'.repeat(3000) }, { name: 'b.xml', data: 'b'.repeat(3000) }, { name: 'c.xml', data: 'c' }]);
    const perEntry = await unpackFile({ name: 'x.zip', bytes: zip }, { maxEntryBytes: 1000 });
    assert.deepEqual(perEntry.files.map((f) => f.name), ['c.xml']);
    assert.deepEqual(perEntry.problems.map((p) => p.code), ['too-large', 'too-large']);
    const perFile = await unpackFile({ name: 'x.zip', bytes: zip }, { maxTotalBytes: 4000 });
    assert.deepEqual(perFile.files.map((f) => f.name), ['a.xml', 'c.xml']);
    assert.deepEqual(perFile.problems.map((p) => [p.path, p.code]), [['x.zip › b.xml', 'too-large']]);
    const many = await unpackFile({ name: 'x.zip', bytes: zip }, { maxEntries: 2 });
    assert.deepEqual(many.files.map((f) => f.name), ['a.xml', 'b.xml']);
    assert.deepEqual(many.problems.map((p) => [p.code, p.detail]), [['too-many', '3 > 2']]);
  });

  test('a damaged archive is one problem; an abort rejects', async () => {
    const good = fixture('reports-2026-09.zip');
    const r = await unpackFile({ name: 'cut.zip', bytes: good.slice(0, 2000) });
    assert.deepEqual(r.files, []);
    assert.deepEqual(r.problems.map((p) => p.code), ['truncated']);
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(unpackFile({ name: 'r.zip', bytes: good }, { signal: ac.signal }), (err) => err.name === 'AbortError');
  });
});
