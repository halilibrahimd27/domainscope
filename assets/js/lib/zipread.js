/**
 * zipread.js — the containers mail reports arrive in, unpacked in the browser: gzip
 * (`.xml.gz`, `.json.gz`; RFC 1952, through the platform's `DecompressionStream('gzip')`) and
 * ZIP (`.zip`; the central directory is read here, each entry is stored or deflated —
 * `DecompressionStream('deflate-raw')` — and checked against its CRC-32). No dependency and no
 * DOM; runs in browsers and Node 22.
 *
 * - {@link containerOf}: gzip, zip or neither, by the first bytes (never by the file name).
 * - {@link readZipDirectory}: the entries of an archive from its end of central directory record
 *   (ZIP64 included); {@link extractZipEntry} one entry's bytes.
 * - {@link inflate} / {@link gunzip}: a deflate or gzip stream, stopped at `maxBytes`.
 * - {@link unpackFile}: a dropped file → the plain files inside it, a zip holding `.xml.gz`
 *   files included (one level of nesting), with a reason for every part that could not be read.
 *
 * Bounded, so a hostile archive cannot hang or fill the tab: at most {@link ZIP_LIMITS}`.maxEntryBytes`
 * out of one entry or gzip stream (decompression stops as soon as it passes the cap), at most
 * `maxTotalBytes` out of one dropped file and `maxEntries` entries per archive. Not supported,
 * and named, never guessed: encrypted entries, compression other than stored / deflate (deflate64,
 * bzip2, LZMA, zstd …) and archives split over several disks.
 */

import { throwIfAborted } from './util.js';

/** Reasons a part of a file could not be read (`ZipError.code`, the view's `rpt.zip.<code>`). */
export const ZIP_ERRORS = Object.freeze([
  'not-zip', 'truncated', 'multi-disk', 'encrypted', 'method', 'crc', 'too-large', 'too-many', 'corrupt', 'nested', 'unsupported'
]);

/** Default bounds of one {@link unpackFile} call. */
export const ZIP_LIMITS = Object.freeze({
  /** Most bytes out of one zip entry or gzip stream. */
  maxEntryBytes: 32 * 1024 * 1024,
  /** Most bytes out of one dropped file, every entry together. */
  maxTotalBytes: 128 * 1024 * 1024,
  /** Most entries read from one archive. */
  maxEntries: 1000,
  /** Containers inside containers: a zip of `.xml.gz` files is depth 2. */
  maxDepth: 2
});

/** A part of a file that could not be read. `code` is one of {@link ZIP_ERRORS}. */
export class ZipError extends Error {
  /**
   * @param {string} code
   * @param {string} [detail]
   */
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'ZipError';
    this.code = code;
    this.detail = String(detail || '');
  }
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const EOCD_SIZE = 22;
const MAX_COMMENT = 0xffff;

/** Names of the compression methods an entry may name but this reader cannot undo. */
const METHOD_NAMES = Object.freeze({ 1: 'shrink', 6: 'implode', 9: 'deflate64', 12: 'bzip2', 14: 'lzma', 93: 'zstd', 95: 'xz', 98: 'ppmd', 99: 'aes' });

/* ------------------------------------------------------------------------ */
/* Bytes                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The input as a Uint8Array (no copy for a Uint8Array or an ArrayBuffer).
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} input
 * @returns {Uint8Array}
 */
export function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new TypeError('zipread: bytes (Uint8Array or ArrayBuffer) expected');
}

let crcTable = null;

/**
 * CRC-32 (IEEE 802.3, the polynomial of zip and gzip).
 * @param {Uint8Array} bytes
 * @returns {number} unsigned 32-bit
 */
export function crc32(bytes) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * The container a file's bytes start with: gzip (1f 8b), zip (a local file header, or the end
 * record of an empty archive) or null for anything else (plain XML or JSON).
 * @param {Uint8Array|ArrayBuffer} input
 * @returns {'gzip'|'zip'|null}
 */
export function containerOf(input) {
  const b = toBytes(input);
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && ((b[2] === 3 && b[3] === 4) || (b[2] === 5 && b[3] === 6))) return 'zip';
  return null;
}

/** A 64-bit little-endian field as a Number; past 2^53 it is no size this reader handles. */
function u64(view, at) {
  const v = view.getBigUint64(at, true);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZipError('too-large', 'a ZIP64 field past 2^53');
  return Number(v);
}

const utf8 = new TextDecoder('utf-8');
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** An entry name: UTF-8 when flagged (bit 11) or valid, else one character per byte. */
function entryName(bytes, flagged) {
  if (flagged) return utf8.decode(bytes);
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return String.fromCharCode(...bytes);
  }
}

/* ------------------------------------------------------------------------ */
/* ZIP                                                                      */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ZipEntry
 * @property {string} name the path inside the archive ('/' separated)
 * @property {number} method 0 stored, 8 deflate (others are refused by {@link extractZipEntry})
 * @property {number} flags general purpose bits (bit 0: encrypted, bit 3: data descriptor, bit 11: UTF-8)
 * @property {boolean} encrypted
 * @property {boolean} directory
 * @property {number} compressedSize
 * @property {number} size uncompressed
 * @property {number} crc CRC-32 of the uncompressed bytes
 * @property {number} localOffset where its local file header starts
 */

/**
 * Locate the end of central directory record (the last one: a comment may hold the signature).
 * @param {DataView} view
 * @returns {number} its offset
 */
function findEocd(view) {
  const last = view.byteLength - EOCD_SIZE;
  const first = Math.max(0, last - MAX_COMMENT);
  for (let i = last; i >= first; i -= 1) {
    if (view.getUint32(i, true) === SIG_EOCD && i + EOCD_SIZE + view.getUint16(i + 20, true) <= view.byteLength) return i;
  }
  return -1;
}

/**
 * The entries of a zip archive, from its central directory (the local headers are read only when
 * an entry is extracted). A data descriptor (bit 3) needs nothing more: the sizes and the CRC are
 * in the directory. ZIP64 sizes, offsets and entry counts are read.
 * @param {Uint8Array|ArrayBuffer} input
 * @param {{ maxEntries?: number }} [opts]
 * @returns {{ entries: ZipEntry[], total: number }} `total`: the entries the archive lists (more than
 *   `entries` holds when it passes `maxEntries`: the caller says so)
 * @throws {ZipError} not-zip, truncated, multi-disk
 */
export function readZipDirectory(input, { maxEntries = ZIP_LIMITS.maxEntries } = {}) {
  const bytes = toBytes(input);
  if (bytes.length < EOCD_SIZE) throw new ZipError(containerOf(bytes) === 'zip' ? 'truncated' : 'not-zip');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEocd(view);
  if (eocd < 0) throw new ZipError(containerOf(bytes) === 'zip' ? 'truncated' : 'not-zip', 'no end of central directory');
  let disk = view.getUint16(eocd + 4, true);
  let cdDisk = view.getUint16(eocd + 6, true);
  let total = view.getUint16(eocd + 10, true);
  let cdSize = view.getUint32(eocd + 12, true);
  let cdOffset = view.getUint32(eocd + 16, true);
  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && view.getUint32(loc, true) === SIG_ZIP64_LOCATOR) {
      const at = u64(view, loc + 8);
      if (at + 56 > bytes.length || view.getUint32(at, true) !== SIG_ZIP64_EOCD) throw new ZipError('truncated', 'ZIP64 end record');
      disk = view.getUint32(at + 16, true);
      cdDisk = view.getUint32(at + 20, true);
      total = u64(view, at + 32);
      cdSize = u64(view, at + 40);
      cdOffset = u64(view, at + 48);
    }
  }
  if (disk !== 0 || cdDisk !== 0) throw new ZipError('multi-disk');
  if (cdOffset + cdSize > bytes.length) throw new ZipError('truncated', 'central directory');
  const entries = [];
  let pos = cdOffset;
  for (let n = 0; n < total && entries.length < maxEntries; n += 1) {
    if (pos + 46 > bytes.length || view.getUint32(pos, true) !== SIG_CENTRAL) throw new ZipError('truncated', 'central directory entry');
    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const crc = view.getUint32(pos + 16, true);
    let compressedSize = view.getUint32(pos + 20, true);
    let size = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    let localOffset = view.getUint32(pos + 42, true);
    const end = pos + 46 + nameLen + extraLen + commentLen;
    if (end > bytes.length) throw new ZipError('truncated', 'central directory entry');
    const name = entryName(bytes.subarray(pos + 46, pos + 46 + nameLen), (flags & 0x800) !== 0);
    // ZIP64 extra field (0x0001): the 64-bit values of the fields set to 0xffffffff, in this order.
    let x = pos + 46 + nameLen;
    const xEnd = x + extraLen;
    while (x + 4 <= xEnd) {
      const id = view.getUint16(x, true);
      const len = view.getUint16(x + 2, true);
      if (id === 0x0001) {
        let f = x + 4;
        const take = () => {
          if (f + 8 > x + 4 + len) throw new ZipError('truncated', 'ZIP64 extra field');
          const v = u64(view, f);
          f += 8;
          return v;
        };
        if (size === 0xffffffff) size = take();
        if (compressedSize === 0xffffffff) compressedSize = take();
        if (localOffset === 0xffffffff) localOffset = take();
      }
      x += 4 + len;
    }
    entries.push({
      name, method, flags, encrypted: (flags & 1) !== 0, directory: name.endsWith('/'), compressedSize, size, crc, localOffset
    });
    pos = end;
  }
  return { entries, total };
}

/**
 * One entry's uncompressed bytes, checked against its size and CRC-32.
 * @param {Uint8Array|ArrayBuffer} input the whole archive
 * @param {ZipEntry} entry from {@link readZipDirectory}
 * @param {{ maxBytes?: number, signal?: AbortSignal }} [opts]
 * @returns {Promise<Uint8Array>}
 * @throws {ZipError} encrypted, method, too-large, truncated, corrupt, crc
 */
export async function extractZipEntry(input, entry, { maxBytes = ZIP_LIMITS.maxEntryBytes, signal } = {}) {
  const bytes = toBytes(input);
  if (entry.encrypted) throw new ZipError('encrypted');
  if (entry.method !== 0 && entry.method !== 8) throw new ZipError('method', METHOD_NAMES[entry.method] || `method ${entry.method}`);
  if (entry.size > maxBytes) throw new ZipError('too-large', String(entry.size));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const at = entry.localOffset;
  if (at + 30 > bytes.length || view.getUint32(at, true) !== SIG_LOCAL) throw new ZipError('truncated', 'local header');
  const start = at + 30 + view.getUint16(at + 26, true) + view.getUint16(at + 28, true);
  if (start + entry.compressedSize > bytes.length) throw new ZipError('truncated', 'entry data');
  const data = bytes.subarray(start, start + entry.compressedSize);
  const out = entry.method === 0 ? data : await inflate(data, 'deflate-raw', { maxBytes, signal });
  if (out.length !== entry.size) throw new ZipError('corrupt', `size ${out.length} ≠ ${entry.size}`);
  if (crc32(out) !== entry.crc) throw new ZipError('crc');
  return out;
}

/* ------------------------------------------------------------------------ */
/* Deflate and gzip streams                                                 */
/* ------------------------------------------------------------------------ */

/**
 * Decompress a deflate stream in the platform's DecompressionStream, stopping as soon as the
 * output passes `maxBytes` (a zip bomb costs no more than the cap).
 * @param {Uint8Array|ArrayBuffer} input
 * @param {'gzip'|'deflate-raw'|'deflate'} format
 * @param {{ maxBytes?: number, signal?: AbortSignal, DecompressionStreamImpl?: Function }} [opts]
 * @returns {Promise<Uint8Array>}
 * @throws {ZipError} unsupported (no DecompressionStream), too-large, corrupt; an AbortError from `signal`
 */
export async function inflate(input, format, { maxBytes = ZIP_LIMITS.maxEntryBytes, signal, DecompressionStreamImpl = globalThis.DecompressionStream } = {}) {
  const bytes = toBytes(input);
  throwIfAborted(signal);
  if (typeof DecompressionStreamImpl !== 'function') throw new ZipError('unsupported', 'DecompressionStream');
  let stream;
  try {
    stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStreamImpl(format));
  } catch (err) {
    throw new ZipError('unsupported', err && err.message ? err.message : String(format));
  }
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      throwIfAborted(signal);
      let step;
      try {
        step = await reader.read();
      } catch (err) {
        throw new ZipError('corrupt', err && err.message ? err.message : String(err));
      }
      if (step.done) break;
      total += step.value.length;
      if (total > maxBytes) throw new ZipError('too-large', `over ${maxBytes}`);
      chunks.push(step.value);
    }
  } catch (err) {
    reader.cancel().catch(() => {});
    throw err;
  }
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/**
 * A gzip file's content, capped like {@link inflate}. The size a gzip trailer announces (ISIZE) is
 * not trusted: it is modulo 2^32, and a truncated file's last bytes are no trailer at all.
 * @param {Uint8Array|ArrayBuffer} input
 * @param {{ maxBytes?: number, signal?: AbortSignal }} [opts]
 * @returns {Promise<Uint8Array>}
 * @throws {ZipError} corrupt (no gzip, a damaged stream), truncated (shorter than a gzip header and trailer), too-large
 */
export async function gunzip(input, { maxBytes = ZIP_LIMITS.maxEntryBytes, signal } = {}) {
  const bytes = toBytes(input);
  if (containerOf(bytes) !== 'gzip') throw new ZipError('corrupt', 'not gzip');
  if (bytes.length < 18) throw new ZipError('truncated', 'gzip');
  return inflate(bytes, 'gzip', { maxBytes, signal });
}

/* ------------------------------------------------------------------------ */
/* A dropped file                                                           */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} UnpackedFile
 * @property {string} name its own name (a zip entry's last path segment; `.gz` taken off a gunzipped name)
 * @property {string} path where it came from: `outer.zip › inner.xml.gz`
 * @property {Uint8Array} bytes
 * @property {Array<'zip'|'gzip'>} via the containers it came out of, outermost first
 */

/**
 * @typedef {object} UnpackProblem
 * @property {string} path the file or entry (`outer.zip › inner.xml`)
 * @property {string} code one of {@link ZIP_ERRORS}
 * @property {string} detail
 */

const baseName = (p) => String(p).split('/').filter(Boolean).pop() || String(p);
const ungz = (name) => (/\.(?:gz|gzip)$/i.test(name) ? name.replace(/\.(?:gz|gzip)$/i, '') : name);

/**
 * Every plain file inside a dropped file: itself when it is no container, the content of a gzip
 * file, the entries of a zip archive (directories and the `__MACOSX/` resource forks macOS adds
 * are skipped), and one more level inside those (a zip of `.xml.gz` files). What cannot be read
 * is listed with its reason and never stops the rest.
 * @param {{ name: string, bytes: Uint8Array|ArrayBuffer }} file
 * @param {{ maxEntryBytes?: number, maxTotalBytes?: number, maxEntries?: number, maxDepth?: number, signal?: AbortSignal }} [opts]
 * @returns {Promise<{ files: UnpackedFile[], problems: UnpackProblem[] }>} rejects only with an AbortError
 */
export async function unpackFile(file, opts = {}) {
  const limits = { ...ZIP_LIMITS, ...Object.fromEntries(Object.entries(opts).filter(([k, v]) => k in ZIP_LIMITS && Number.isFinite(v))) };
  const { signal } = opts;
  const out = { files: [], problems: [] };
  let budget = limits.maxTotalBytes;
  const fail = (path, err) => {
    if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) throw err;
    const code = err instanceof ZipError ? err.code : 'corrupt';
    out.problems.push({ path, code, detail: err instanceof ZipError ? err.detail : String((err && err.message) || err) });
  };
  const take = (n) => {
    if (n > budget) throw new ZipError('too-large', 'the file as a whole');
    budget -= n;
  };

  async function visit(name, path, bytes, via) {
    throwIfAborted(signal);
    const kind = containerOf(bytes);
    if (!kind) {
      out.files.push({ name, path, bytes, via });
      return;
    }
    if (via.length >= limits.maxDepth) {
      out.problems.push({ path, code: 'nested', detail: kind });
      return;
    }
    if (kind === 'gzip') {
      let inner;
      try {
        inner = await gunzip(bytes, { maxBytes: Math.min(limits.maxEntryBytes, budget), signal });
        take(inner.length);
      } catch (err) {
        fail(path, err);
        return;
      }
      await visit(ungz(name), path, inner, [...via, 'gzip']);
      return;
    }
    let dir;
    try {
      dir = readZipDirectory(bytes, { maxEntries: limits.maxEntries });
    } catch (err) {
      fail(path, err);
      return;
    }
    if (dir.total > dir.entries.length) out.problems.push({ path, code: 'too-many', detail: `${dir.total} > ${limits.maxEntries}` });
    for (const entry of dir.entries) {
      if (entry.directory || /(^|\/)__MACOSX\//.test(entry.name) || /(^|\/)\.DS_Store$/.test(entry.name)) continue;
      const entryPath = `${path} › ${entry.name}`;
      let data;
      try {
        data = await extractZipEntry(bytes, entry, { maxBytes: Math.min(limits.maxEntryBytes, budget), signal });
        take(data.length);
      } catch (err) {
        fail(entryPath, err);
        continue;
      }
      await visit(baseName(entry.name), entryPath, data, [...via, 'zip']);
    }
  }

  await visit(String(file && file.name ? file.name : 'file'), String(file && file.name ? file.name : 'file'), toBytes(file.bytes), []);
  return out;
}
