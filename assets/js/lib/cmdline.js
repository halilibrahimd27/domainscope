/**
 * cmdline.js — safe construction of the `cli/ssl_origin_scan.py` origin-sweep
 * command line. DOM-free; runs in browsers and Node 22.
 *
 * The scanner suggests a ready-to-run command that TLS/SNI-sweeps a proxied
 * host's candidate origin blocks with the proxied names. That command string is
 * shown to the user (and may be copy-pasted into a shell), so every token is
 * built here under strict rules — never by ad-hoc template interpolation:
 *
 *  - a TARGET must be a literal IPv4/IPv6 address or a CIDR block (validated by
 *    {@link parseCidr}); it is re-emitted in canonical form;
 *  - a NAME must be a hostname accepted by {@link normalizeHostname} whose
 *    output is limited to letters, digits, hyphen, dot and underscore and never
 *    begins with '-';
 *  - anything else is DROPPED (and reported in `dropped`), never quoted into the
 *    command, so a hostile token (`; rm -rf /`, `$(…)`, backticks, spaces,
 *    quotes, newlines, a leading '-' argument, an over-long or unicode string)
 *    can neither inject a shell command nor be mistaken for a flag;
 *  - the surviving tokens are quoted only when a character outside the safe set
 *    requires it, per the target shell (POSIX single quotes with `'\''`
 *    escaping; PowerShell single quotes with every PowerShell quote character —
 *    ASCII `'` and U+2018–U+201B — doubled). Validated tokens never actually
 *    need quoting — the quoting is defence in depth;
 *  - {@link quoteArg} REFUSES (throws) any non-ASCII or control character, so a
 *    future caller passing free text can never smuggle a Unicode quote that
 *    PowerShell would read as closing the literal, nor a NUL / CR / LF;
 *  - many names do not go inline: above a threshold the command reads them from
 *    a names file (`-n proxied-names.txt`), keeping it far below the Windows
 *    32,767-character command-line limit.
 *
 * The whole design assumes the command may be pasted verbatim into either a
 * POSIX shell or PowerShell, so it must be inert under both.
 */

import { parseCidr, normalizeIP, formatIP } from './netinfo.js';
import { normalizeHostname } from './domain.js';

/* ------------------------------------------------------------------------ */
/* Token validation                                                          */
/* ------------------------------------------------------------------------ */

/**
 * Canonicalise one sweep target: a bare IP address, or `addr/prefix` CIDR.
 * Host bits of a CIDR are masked off and the address is re-emitted in canonical
 * (RFC 5952 for IPv6) form, so the token is always well-formed.
 * @param {unknown} raw
 * @returns {string|null} canonical token, or null when it is not an IP/CIDR
 */
function canonTarget(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  if (s.includes('/')) {
    const c = parseCidr(s);
    if (!c) return null;
    return `${formatIP(c.network, c.version)}/${c.prefix}`;
  }
  return normalizeIP(s); // canonical address text, or null
}

// After normalizeHostname the output is already lowercase ASCII (IDN → puny),
// but assert the exact charset the CLI accepts and reject a leading '-' so a
// name can never be read as an option. Underscore is allowed (service labels).
const NAME_CHARS = /^[a-z0-9_.-]+$/;

/**
 * Canonicalise one sweep name (a hostname).
 * @param {unknown} raw
 * @returns {string|null} normalised hostname, or null when invalid
 */
function canonName(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  const n = normalizeHostname(s);
  if (!n) return null;
  if (n.startsWith('-') || !NAME_CHARS.test(n)) return null;
  return n;
}

/** Validate + dedupe a list with `canon`, keeping first-seen order. */
function validateList(list, canon) {
  const valid = [];
  const dropped = [];
  const seen = new Set();
  for (const raw of Array.isArray(list) ? list : []) {
    const c = canon(raw);
    if (c === null) {
      dropped.push(String(raw ?? ''));
      continue;
    }
    if (seen.has(c)) continue;
    seen.add(c);
    valid.push(c);
  }
  return { valid, dropped };
}

/**
 * Validate sweep targets (IP addresses / CIDR blocks).
 * @param {unknown[]} list
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateTargets(list) {
  return validateList(list, canonTarget);
}

/**
 * Validate sweep names (hostnames).
 * @param {unknown[]} list
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateNames(list) {
  return validateList(list, canonName);
}

/* ------------------------------------------------------------------------ */
/* Shell quoting                                                             */
/* ------------------------------------------------------------------------ */

// Characters that never need quoting. POSIX sh treats none of these as special
// in an argument; PowerShell is given a stricter set (dropping ',', '@', '%',
// '+', '=' which it can treat specially) so the fallback is always safe there.
const POSIX_SAFE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const PWSH_SAFE = /^[A-Za-z0-9_:./-]+$/;

/** POSIX single-quote: wrap and escape embedded quotes as `'\''`. */
function quotePosix(s) {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * PowerShell single-quote (literal): wrap and double every character PowerShell
 * treats as a single quote — ASCII `'` AND the typographic U+2018 ‘ U+2019 ’
 * U+201A ‚ U+201B ‛ (quoteArg already refuses non-ASCII; this is a second layer).
 */
function quotePwsh(s) {
  return `'${s.replace(/['‘’‚‛]/g, (c) => c + c)}'`;
}

// Printable ASCII only: anything else (control characters, NUL / CR / LF,
// Unicode quotes or look-alikes) is refused by quoteArg.
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * Quote one argument for the given shell, only when a character requires it.
 * Throws a TypeError for a value holding a non-ASCII or control character: no
 * quoting is trusted to neutralise those in every shell, so they must never
 * reach a command line (validate / drop such tokens before quoting).
 * @param {unknown} value
 * @param {'posix'|'powershell'} [shell='posix']
 * @returns {string}
 */
export function quoteArg(value, shell = 'posix') {
  const v = String(value ?? '');
  if (!PRINTABLE_ASCII.test(v)) {
    throw new TypeError('quoteArg: refusing a non-ASCII or control character in a shell argument');
  }
  if (shell === 'powershell') return PWSH_SAFE.test(v) ? v : quotePwsh(v);
  return POSIX_SAFE.test(v) ? v : quotePosix(v);
}

/* ------------------------------------------------------------------------ */
/* Command building                                                          */
/* ------------------------------------------------------------------------ */

const DEFAULT_SCRIPT = 'ssl_origin_scan.py';
/** Default names file a long sweep reads its `-n` names from. */
export const DEFAULT_NAMES_FILE = 'proxied-names.txt';
/** More names than this go to the names file instead of inline. */
export const MAX_INLINE_NAMES = 200;
/**
 * An inline command longer than this (characters) goes to the names file: far
 * below the Windows CreateProcess limit (32,767) even after a `python ` prefix.
 */
export const MAX_INLINE_LENGTH = 8000;
// A script / names-file token: a plain relative or absolute path of letters,
// digits, '_', '.', '/', '-' that does not start with '-' (never an option).
const PATH_TOKEN = /^(?!-)[A-Za-z0-9_./-]{1,200}$/;

/**
 * Build the origin-sweep command and report what was kept / dropped.
 *
 * Names go inline (`-n a.example.com b.example.com …`) up to `maxInlineNames`
 * names and `maxLength` characters; beyond either, the command reads them from
 * `namesFile` instead (`-n proxied-names.txt`: the CLI loads a `-n` value that
 * is a file, one name per line), so a large proxied estate never overflows the
 * Windows command-line limit. The caller then offers that file (`names` holds
 * the full validated list for it); `namesInline` says which form was built.
 *
 * @param {object} opts
 * @param {unknown[]} [opts.targets] IP addresses / CIDR blocks for `-t`
 * @param {unknown[]} [opts.names] hostnames for `-n`
 * @param {string} [opts.script='ssl_origin_scan.py'] the script token (a repo
 *   path like `cli/ssl_origin_scan.py`); anything but a plain path falls back
 *   to the default
 * @param {'posix'|'powershell'} [opts.shell='posix']
 * @param {string} [opts.namesFile='proxied-names.txt'] names-file token (plain
 *   path, validated like `script`)
 * @param {number} [opts.maxInlineNames=200] more names than this → names file
 * @param {number} [opts.maxLength=8000] a longer inline command → names file
 * @returns {{ command: string|null, targets: string[], names: string[],
 *   dropped: { targets: string[], names: string[] }, length: number,
 *   namesInline: boolean, namesFile: string|null }}
 *   `command` is null when no valid target or no valid name survives; `length`
 *   is its length (0 when null); `namesFile` is the file the command reads the
 *   names from (null when they are inline).
 */
export function buildSweepCommand({
  targets = [], names = [], script = DEFAULT_SCRIPT, shell = 'posix',
  namesFile = DEFAULT_NAMES_FILE, maxInlineNames = MAX_INLINE_NAMES, maxLength = MAX_INLINE_LENGTH
} = {}) {
  const t = validateTargets(targets);
  const n = validateNames(names);
  const dropped = { targets: t.dropped, names: n.dropped };
  if (!t.valid.length || !n.valid.length) {
    return { command: null, targets: t.valid, names: n.valid, dropped, length: 0, namesInline: true, namesFile: null };
  }
  const q = (v) => quoteArg(v, shell);
  const pathTok = (v, fallback) => (typeof v === 'string' && PATH_TOKEN.test(v) ? v : fallback);
  const head = `${q(pathTok(script, DEFAULT_SCRIPT))} -t ${t.valid.map(q).join(' ')} -n `;
  const inline = `${head}${n.valid.map(q).join(' ')}`;
  const nameCap = Number.isFinite(maxInlineNames) && maxInlineNames >= 0 ? maxInlineNames : Infinity;
  const lenCap = Number.isFinite(maxLength) && maxLength > 0 ? maxLength : Infinity;
  if (n.valid.length <= nameCap && inline.length <= lenCap) {
    return { command: inline, targets: t.valid, names: n.valid, dropped, length: inline.length, namesInline: true, namesFile: null };
  }
  const file = pathTok(namesFile, DEFAULT_NAMES_FILE);
  const command = `${head}${q(file)}`;
  return { command, targets: t.valid, names: n.valid, dropped, length: command.length, namesInline: false, namesFile: file };
}

/**
 * Convenience wrapper returning just the command string (or null).
 * @param {object} opts see {@link buildSweepCommand}
 * @returns {string|null}
 */
export function buildOriginSweepCommand(opts) {
  return buildSweepCommand(opts).command;
}
