/**
 * download.js — save generated text/blobs as files, entirely client-side.
 *
 * Uses a Blob + object URL + temporary <a download> (allowed by the CSP: navigation to
 * blob: is not a fetch). The object URL is revoked shortly after the click.
 *
 * @example
 *   import { downloadText, downloadJson, timestampedName } from './ui/download.js';
 *   downloadText('names.txt', names.join('\n') + '\n');
 *   downloadText(timestampedName('hosts', 'csv', 'example.com'), csv, 'text/csv;charset=utf-8');
 *   downloadJson('scan.json', scanResult);   // Dates → ISO, Map → object, Set → array
 */

/**
 * Make a string safe to use as a file name on Windows/macOS/Linux.
 * Keeps letters (incl. Turkish), digits, dot, dash and underscore; collapses the rest to '-'.
 * @param {string} name
 * @param {string} [fallback='download']
 * @returns {string}
 */
export function sanitizeFilename(name, fallback = 'download') {
  let s = String(name ?? '')
    .normalize('NFC')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*]+/g, '-')
    .replace(/\s+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[-.]+|[-.\s]+$/g, '');
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(s)) s = `_${s}`; // reserved on Windows
  if (s.length > 150) {
    const dot = s.lastIndexOf('.');
    const ext = dot > 0 && s.length - dot <= 10 ? s.slice(dot) : '';
    s = s.slice(0, 150 - ext.length) + ext;
  }
  return s || fallback;
}

function pad(n) {
  return String(n).padStart(2, '0');
}

/**
 * Build 'base-subject-YYYYMMDD-HHMM.ext' (local time) — e.g. 'hosts-example.com-20260923-1130.csv'.
 * @param {string} base
 * @param {string} ext without dot
 * @param {string} [subject] e.g. the scanned domain
 * @param {Date} [date=new Date()]
 * @returns {string}
 */
export function timestampedName(base, ext, subject, date = new Date()) {
  const d = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
  const parts = [base, subject, stamp].filter((p) => p !== undefined && p !== null && String(p).trim() !== '');
  const cleanExt = String(ext || '').replace(/^\.+/, '');
  return sanitizeFilename(`${parts.join('-')}${cleanExt ? `.${cleanExt}` : ''}`);
}

/**
 * Trigger a browser download of a Blob.
 * @param {string} filename
 * @param {Blob} blob
 * @returns {string} the sanitized file name used
 */
export function downloadBlob(filename, blob) {
  const name = sanitizeFilename(filename);
  const doc = globalThis.document;
  if (!doc || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
    throw new Error('download.js: downloads need a browser environment');
  }
  const url = URL.createObjectURL(blob);
  const a = doc.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  a.hidden = true;
  doc.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    // Give the browser time to start reading the blob before revoking it.
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  return name;
}

/**
 * Download text as a file.
 * @param {string} filename
 * @param {string} text
 * @param {string} [mime='text/plain;charset=utf-8']
 * @returns {string} the sanitized file name used
 */
export function downloadText(filename, text, mime = 'text/plain;charset=utf-8') {
  return downloadBlob(filename, new Blob([String(text ?? '')], { type: mime }));
}

/**
 * JSON.stringify replacer matching lib/export.toJson: Dates → ISO, Map → object,
 * Set → array, typed arrays/ArrayBuffers dropped, bigint → string.
 * @param {string} _key
 * @param {any} value
 * @returns {any}
 */
export function jsonReplacer(_key, value) {
  if (value instanceof Map) return Object.fromEntries(value);
  if (value instanceof Set) return [...value];
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return undefined;
  if (typeof value === 'bigint') return value.toString();
  return value;
}

/**
 * Download any value as pretty-printed JSON (2 spaces).
 * @param {string} filename
 * @param {any} value
 * @returns {string} the sanitized file name used
 */
export function downloadJson(filename, value) {
  return downloadText(filename, `${JSON.stringify(value, jsonReplacer, 2)}\n`, 'application/json;charset=utf-8');
}
