/**
 * lib/handover.js — the workspace hand-over file: everything of one workspace (lib/workspace.js)
 * in one JSON file, to move it to another browser or to give it to a colleague, optionally sealed
 * with a password (lib/cryptobox.js). Versioned; an import checks the format and every value
 * (lib/workspace.js sanitizeWorkspaceData) before anything is stored.
 *
 * Plain file:
 *   { "format": "domainscope-workspace", "v": 1, "encrypted": false, "workspace": Workspace }
 * Sealed file (the name is inside too: the outside shows only the format and the parameters):
 *   { "format": "domainscope-workspace", "v": 1, "encrypted": true,
 *     "kdf": { "name": "PBKDF2", "hash": "SHA-256", "iterations": 600000, "salt": "<base64, 16 bytes>" },
 *     "cipher": { "name": "AES-GCM", "iv": "<base64, 12 bytes>" }, "data": "<base64: ciphertext + tag>" }
 *   The ciphertext is the JSON of Workspace; "domainscope-workspace/1" and the parameters are
 *   authenticated with it, so no part of the file can change unnoticed.
 * Workspace:
 *   { "name": "Acme", "default": false, "exportedAt": "2026-09-28T09:30:00.000Z", "app": "DomainScope 1.0.0",
 *     "parts": { "inventory": { "text", "updatedAt" }, "learned": { "v": 1, "seq", "labels" }, "wordlist": "…",
 *                "expectedCas": ["…"], "notes": "…", "recent": [{ "value", "at" }],
 *                "origins": { "v": 1, "remember", "entries": [{ "name", "ip", "port", "source", "firstSeen", "lastConfirmed", "server", "stale" }] },
 *                "ctSeen": "<JSON text of lib/ctwatch.js: { v, domains: { <domain>: { at, ids: { <id>: <expiry day> } } } }>" } }
 *   An empty part is left out. `default`: exported from the Default workspace.
 *
 * DOM-free; the password is never stored or kept (lib/cryptobox.js).
 *
 * @example
 *   const text = await exportWorkspaceFile({ name: 'Acme', data }, { password: 'correct horse battery' });
 *   readWorkspaceFile(text).encrypted;                                          // true
 *   const ws = await openWorkspaceFile(text, { password: 'correct horse battery' });   // { name: 'Acme', data, … }
 */

import { sealText, openText, BoxError, DEFAULT_ITERATIONS } from './cryptobox.js';
import { WORKSPACE_PARTS, normalizeWorkspaceName, sanitizeWorkspaceData } from './workspace.js';

/** The `format` of every hand-over file. */
export const HANDOVER_FORMAT = 'domainscope-workspace';
/** The file version this module writes and the newest it reads. */
export const HANDOVER_VERSION = 1;
/** A larger file is refused before it is parsed. */
export const HANDOVER_MAX_BYTES = 40 * 1024 * 1024;

/** What a sealed file's ciphertext is bound to (additional authenticated data). */
const CONTEXT = `${HANDOVER_FORMAT}/${HANDOVER_VERSION}`;

/**
 * Why a hand-over file could not be written or read. `code`: 'too-large', 'not-json',
 * 'not-workspace' (JSON, but not this format), 'newer' (a later version than this app reads),
 * 'damaged' (this format, but broken), and lib/cryptobox.js's 'password-required',
 * 'password-short', 'wrong-password' (a wrong password, or a changed file), 'unsupported',
 * 'crypto-unavailable'.
 */
export class HandoverError extends Error {
  /**
   * @param {string} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message || code);
    this.name = 'HandoverError';
    this.code = code;
  }
}

/** A BoxError as a HandoverError with the same code; anything else is rethrown. */
function fromBox(err) {
  if (err instanceof BoxError) return new HandoverError(err.code, err.message);
  return err;
}

/**
 * The Workspace object of a file: the name, where it came from and its non-empty parts.
 * @param {{ name: string|null, isDefault?: boolean, data: object, app?: string, exportedAt?: Date }} ws
 * @returns {object}
 */
export function workspacePayload({ name, isDefault = false, data, app = 'DomainScope', exportedAt = new Date() }) {
  const clean = sanitizeWorkspaceData(data);
  const parts = {};
  for (const part of WORKSPACE_PARTS) {
    const value = clean[part];
    if (value === null || value === '' || (Array.isArray(value) && !value.length)) continue;
    parts[part] = value;
  }
  return {
    name: normalizeWorkspaceName(name) || null,
    default: !!isDefault,
    exportedAt: exportedAt instanceof Date && !Number.isNaN(exportedAt.getTime()) ? exportedAt.toISOString() : null,
    app: String(app),
    parts
  };
}

/**
 * The file's text: plain JSON (indented, readable), or sealed with `password`.
 * @param {{ name: string|null, isDefault?: boolean, data: object, app?: string, exportedAt?: Date }} ws
 * @param {{ password?: string|null, iterations?: number, crypto?: Crypto }} [opts] no password: a plain file
 * @returns {Promise<string>}
 * @throws {HandoverError} 'password-short', 'crypto-unavailable'
 */
export async function exportWorkspaceFile(ws, { password = null, iterations = DEFAULT_ITERATIONS, crypto = globalThis.crypto } = {}) {
  const workspace = workspacePayload(ws);
  if (password === null || password === undefined || password === '') {
    return `${JSON.stringify({ format: HANDOVER_FORMAT, v: HANDOVER_VERSION, encrypted: false, workspace }, null, 2)}\n`;
  }
  let box;
  try {
    box = await sealText(JSON.stringify(workspace), password, { iterations, context: CONTEXT, crypto });
  } catch (err) {
    throw fromBox(err);
  }
  return `${JSON.stringify({ format: HANDOVER_FORMAT, v: HANDOVER_VERSION, encrypted: true, ...box }, null, 2)}\n`;
}

/**
 * Parse a file and check its outside (nothing is decrypted yet): is it a hand-over file, which
 * version, sealed or not.
 * @param {string} text the file's content
 * @returns {{ encrypted: boolean, file: object }}
 * @throws {HandoverError} 'too-large', 'not-json', 'not-workspace', 'newer', 'damaged'
 */
export function readWorkspaceFile(text) {
  if (typeof text !== 'string') throw new HandoverError('not-json');
  if (text.length > HANDOVER_MAX_BYTES) throw new HandoverError('too-large');
  let file;
  try {
    file = JSON.parse(text.replace(/^\ufeff/, ''));
  } catch {
    throw new HandoverError('not-json');
  }
  if (!file || typeof file !== 'object' || Array.isArray(file) || file.format !== HANDOVER_FORMAT) throw new HandoverError('not-workspace');
  if (!Number.isInteger(file.v) || file.v < 1) throw new HandoverError('damaged', 'no version');
  if (file.v > HANDOVER_VERSION) throw new HandoverError('newer', `format version ${file.v}`);
  if (file.encrypted === true) {
    if (typeof file.data !== 'string' || !file.kdf || !file.cipher) throw new HandoverError('damaged', 'sealed file without its box');
    return { encrypted: true, file };
  }
  if (file.encrypted !== false || !file.workspace || typeof file.workspace !== 'object' || Array.isArray(file.workspace)) {
    throw new HandoverError('damaged', 'no workspace');
  }
  return { encrypted: false, file };
}

/** The Workspace object of a file, checked and sanitized. */
function readPayload(ws) {
  if (!ws || typeof ws !== 'object' || Array.isArray(ws)) throw new HandoverError('damaged', 'no workspace');
  const parts = ws.parts && typeof ws.parts === 'object' && !Array.isArray(ws.parts) ? ws.parts : null;
  if (!parts) throw new HandoverError('damaged', 'no parts');
  const exportedAt = typeof ws.exportedAt === 'string' && !Number.isNaN(new Date(ws.exportedAt).getTime()) ? new Date(ws.exportedAt) : null;
  return {
    name: normalizeWorkspaceName(ws.name) || null,
    isDefault: ws.default === true,
    exportedAt,
    app: typeof ws.app === 'string' ? ws.app.slice(0, 80) : null,
    data: sanitizeWorkspaceData(parts)
  };
}

/**
 * Read a hand-over file: its workspace, every part sanitized.
 * @param {string} text
 * @param {{ password?: string|null, crypto?: Crypto }} [opts] the password of a sealed file
 * @returns {Promise<{ name: string|null, isDefault: boolean, exportedAt: Date|null, app: string|null,
 *   data: ReturnType<typeof sanitizeWorkspaceData>, encrypted: boolean }>}
 * @throws {HandoverError} readWorkspaceFile's codes, 'password-required', 'wrong-password', 'unsupported', 'crypto-unavailable'
 */
export async function openWorkspaceFile(text, { password = null, crypto = globalThis.crypto } = {}) {
  const { encrypted, file } = readWorkspaceFile(text);
  if (!encrypted) return { ...readPayload(file.workspace), encrypted };
  let plain;
  try {
    plain = await openText(file, password ?? '', { context: CONTEXT, crypto });
  } catch (err) {
    throw fromBox(err);
  }
  let ws;
  try {
    ws = JSON.parse(plain);
  } catch {
    throw new HandoverError('damaged', 'the sealed content is not JSON');
  }
  return { ...readPayload(ws), encrypted };
}
