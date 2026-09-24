/**
 * cmdline.js — safe construction of the `cli/ssl_origin_scan.py` origin-sweep
 * command line. DOM-free; runs in browsers and Node 22.
 *
 * The scanner suggests a ready-to-run command that TLS/SNI-sweeps a proxied
 * host's candidate origin blocks with the proxied names. That command string is
 * shown to the user (and may be copy-pasted into a shell), so every token is
 * built here under strict rules — never by ad-hoc template interpolation:
 *
 *  - a TARGET (and an `--exclude` entry) must be a literal IPv4/IPv6 address or
 *    a CIDR block (validated by {@link parseCidr}); it is re-emitted in
 *    canonical form;
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
 *    32,767-character command-line limit;
 *  - two opt-ins widen the token rules for the zone-file hand-off, both off by
 *    default so every earlier caller is byte-identical: `allowHostTargets` keeps
 *    a HOST NAME target (a zone's proxied CNAME origin, resolved by the CLI
 *    inside the network) and `allowWildcardNames` keeps a `*.x` name (always
 *    quoted, `*` is in neither safe set). A host target (and, under the opt-in,
 *    a name) that glibc `inet_aton` would read as an IPv4 address (`2026092401`,
 *    `0x7f.0x1`, `0177.1`, `10.1`) is dropped: it must never reach getaddrinfo.
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

// The numeric forms glibc `inet_aton` accepts as an IPv4 address: 1–4 parts, each
// decimal, octal (leading 0) or hex (0x…). `normalizeHostname` already rejects the
// all-decimal forms, but `0x7f.0x1` passes it, so the opt-ins check this too.
const INET_ATON = /^(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+)){0,3}$/i;

/**
 * Would glibc `inet_aton` read `s` as an IPv4 address? Internal: exported for the
 * tests only (the opt-in validators below use it).
 * @param {unknown} s
 * @returns {boolean}
 */
export function isInetAtonNumeric(s) {
  return INET_ATON.test(String(s ?? ''));
}

/**
 * Canonicalise one HOST NAME target (the `allowHostTargets` opt-in): not an
 * IP / CIDR, a `normalizeHostname` result of `[a-z0-9_.-]` with at least one
 * dot, no leading '-', and not an inet_aton numeric form.
 * @param {unknown} raw
 * @returns {string|null}
 */
function canonHostTarget(raw) {
  const s = String(raw ?? '').trim();
  if (!s || s.includes('/') || normalizeIP(s)) return null;
  const n = normalizeHostname(s);
  if (!n || n.startsWith('-') || !NAME_CHARS.test(n) || !n.includes('.') || isInetAtonNumeric(n)) return null;
  return n;
}

// A sweep name under the `allowWildcardNames` opt-in: an optional leading `*.`.
const WILDCARD_NAME_CHARS = /^(\*\.)?[a-z0-9_.-]+$/;

/**
 * Canonicalise one sweep name that may be a `*.x` wildcard (the
 * `allowWildcardNames` opt-in). The CLI probes `*.x` as the base plus a
 * wildcard SNI. inet_aton numeric forms are dropped.
 * @param {unknown} raw
 * @returns {string|null}
 */
function canonWildcardName(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  const n = normalizeHostname(s, { allowWildcard: true });
  if (!n || n.startsWith('-') || !WILDCARD_NAME_CHARS.test(n) || isInetAtonNumeric(n.replace(/^\*\./, ''))) return null;
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
 * Validate sweep targets (IP addresses / CIDR blocks; host names too with
 * `allowHostTargets`).
 * @param {unknown[]} list
 * @param {{ allowHostTargets?: boolean }} [opts]
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateTargets(list, { allowHostTargets = false } = {}) {
  if (allowHostTargets !== true) return validateList(list, canonTarget);
  return validateList(list, (raw) => canonTarget(raw) ?? canonHostTarget(raw));
}

/**
 * Validate sweep names (hostnames; `*.x` too with `allowWildcard`).
 * @param {unknown[]} list
 * @param {{ allowWildcard?: boolean }} [opts]
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateNames(list, { allowWildcard = false } = {}) {
  return validateList(list, allowWildcard === true ? canonWildcardName : canonName);
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
/** The CLI's default `-p` value: a port list of exactly this is omitted. */
const CLI_DEFAULT_PORT = 443;

/**
 * Validate the optional `-p` / `--cert` / `--json` options into command tokens.
 * Every rejected value is reported in `dropped` ('cert', 'json', 'ports:<value>'),
 * never quoted into the command.
 * @param {{ cert?: unknown, json?: unknown, ports?: unknown }} opts
 * @returns {{ tokens: string[], dropped: string[] }} tokens in CLI order: -p, --cert, --json
 */
function validateOptions({ cert = null, json = null, ports = null }) {
  const tokens = [];
  const dropped = [];
  if (ports !== null && ports !== undefined) {
    const list = [];
    for (const p of Array.isArray(ports) ? ports : [ports]) {
      if (Number.isInteger(p) && p >= 1 && p <= 65535) {
        if (!list.includes(p)) list.push(p);
      } else {
        dropped.push(`ports:${String(p)}`);
      }
    }
    if (list.length && !(list.length === 1 && list[0] === CLI_DEFAULT_PORT)) tokens.push('-p', list.join(','));
  }
  const pathOpt = (value, flag, label) => {
    if (value === null || value === undefined) return;
    if (typeof value === 'string' && PATH_TOKEN.test(value)) tokens.push(flag, value);
    else dropped.push(label);
  };
  pathOpt(cert, '--cert', 'cert');
  pathOpt(json, '--json', 'json');
  return { tokens, dropped };
}

/* ------------------------------------------------------------------------ */
/* --exclude                                                                 */
/* ------------------------------------------------------------------------ */

/** A validated target / exclude token as a range: { version, network, prefix } (null when invalid). */
function rangeOf(token) {
  return parseCidr(String(token ?? ''));
}

/** Does range `outer` contain the whole of range `inner`? */
function rangeCovers(outer, inner) {
  if (!outer || !inner || outer.version !== inner.version || outer.prefix > inner.prefix) return false;
  const bits = outer.version === 4 ? 32 : 128;
  const shift = BigInt(bits - outer.prefix);
  return (inner.network >> shift) === (outer.network >> shift);
}

/** Do two ranges share at least one address? */
function rangesOverlap(a, b) {
  return rangeCovers(a, b) || rangeCovers(b, a);
}

/**
 * Split validated targets against validated excludes: a target an exclude covers
 * entirely is removed (sweeping it would probe nothing), an exclude that touches
 * a remaining target is emitted, and one that touches no target at all is
 * `unused` (it would change nothing). An exclude that only removed whole targets
 * did its job without being emitted, so it is neither emitted nor unused.
 * @param {string[]} targets canonical target tokens
 * @param {string[]} excludes canonical exclude tokens
 * @returns {{ targets: string[], excluded: string[], exclude: string[], unused: string[] }}
 */
function applyExcludes(targets, excludes) {
  const ex = excludes.map((tok) => ({ tok, range: rangeOf(tok), applied: false })).filter((x) => x.range);
  const kept = [];
  const excluded = [];
  for (const tok of targets) {
    const range = rangeOf(tok);
    const covering = range ? ex.filter((x) => rangeCovers(x.range, range)) : [];
    if (covering.length) {
      for (const x of covering) x.applied = true;
      excluded.push(tok);
    } else {
      kept.push(tok);
    }
  }
  const keptRanges = kept.map(rangeOf).filter(Boolean);
  // A HOST NAME target (allowHostTargets) has no range until the CLI resolves it
  // inside the network, so any exclude may match one of its addresses: with a
  // host target kept, every exclude is emitted (never silently left out).
  const hostKept = keptRanges.length < kept.length;
  const exclude = [];
  const unused = [];
  for (const x of ex) {
    if (hostKept || keptRanges.some((r) => rangesOverlap(r, x.range))) exclude.push(x.tok);
    else if (!x.applied) unused.push(x.tok);
  }
  return { targets: kept, excluded, exclude, unused };
}

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
 * @param {string|null} [opts.cert=null] `--cert <file>`: the new certificate
 *   the CLI compares against (a plain path token like `script`; anything else
 *   is dropped and reported as `'cert'` in `dropped.options`)
 * @param {string|null} [opts.json=null] `--json <file>`: where the CLI writes
 *   its JSON report (plain path token; otherwise dropped as `'json'`)
 * @param {number[]|null} [opts.ports=null] `-p 443,8443`: integers 1–65535,
 *   deduped in order; omitted when null, empty or exactly `[443]` (the CLI
 *   default); every other value is dropped as `'ports:<value>'`
 * @param {unknown[]|string|null} [opts.exclude=null] `--exclude`: IP addresses /
 *   CIDR blocks the CLI must never probe (validated like `targets`; a string is
 *   split on whitespace / commas). Emitted right after the `-t` targets as
 *   `--exclude a b …` (the CLI flag takes several values and may repeat, like
 *   `-t`). A target an exclude covers entirely is removed from `-t` (reported in
 *   `excluded`); an exclude that overlaps no remaining target is left out of the
 *   command (reported in `excludeUnused`) — unless a host-name target is kept
 *   (its addresses are unknown until the CLI resolves it, so every exclude is
 *   emitted); an invalid one is dropped (reported
 *   in `dropped.exclude`). Only when `exclude` is given (not null / undefined)
 *   does the result carry `exclude`, `excluded`, `excludeUnused` and
 *   `dropped.exclude`, so every earlier call shape is byte-identical.
 * @param {boolean} [opts.allowHostTargets=false] zone hand-off opt-in: keep a
 *   HOST NAME target (see {@link validateTargets}); IP / CIDR targets come first
 *   in the order given, then the host names
 * @param {boolean} [opts.allowWildcardNames=false] zone hand-off opt-in: keep a
 *   `*.x` name (see {@link validateNames}); it is always quoted
 * @param {string|null} [opts.targetsFile=null] zone hand-off opt-in: a targets
 *   file token (plain path, validated like `script`). When given and the
 *   targets exceed `maxInlineTargets`, the names exceed `maxInlineNames` or the
 *   inline command exceeds `maxLength`, BOTH lists go to files
 *   (`-t <targetsFile> … -n <namesFile>`; the CLI reads a `-t` / `-n` value that
 *   is a file) and the result carries `targetsInline` / `targetsFile`. Without
 *   it targets are always inline and neither field is present.
 * @param {number|null} [opts.maxInlineTargets=null] more targets than this →
 *   the file form (only with `targetsFile`)
 * @returns {{ command: string|null, targets: string[], names: string[],
 *   dropped: { targets: string[], names: string[], options: string[], exclude?: string[] }, length: number,
 *   namesInline: boolean, namesFile: string|null, exclude?: string[], excluded?: string[],
 *   excludeUnused?: string[], targetsInline?: boolean, targetsFile?: string|null }}
 *   `command` is null when no valid target or no valid name survives; `length`
 *   is its length (0 when null); `namesFile` is the file the command reads the
 *   names from (null when they are inline). The options follow the names (or
 *   the names file) in the order `-p`, `--cert`, `--json`: argparse's
 *   `nargs='+'` for `-n` stops at the next option. Without the four options
 *   the command is byte-identical to earlier versions and `dropped.options` is [].
 *   With `exclude`, `targets` lists only the targets left in `-t`.
 */
export function buildSweepCommand({
  targets = [], names = [], script = DEFAULT_SCRIPT, shell = 'posix',
  namesFile = DEFAULT_NAMES_FILE, maxInlineNames = MAX_INLINE_NAMES, maxLength = MAX_INLINE_LENGTH,
  cert = null, json = null, ports = null, exclude = null,
  allowHostTargets = false, allowWildcardNames = false, targetsFile = null, maxInlineTargets = null
} = {}) {
  const t = validateTargets(targets, { allowHostTargets: allowHostTargets === true });
  if (allowHostTargets === true) {
    // IP / CIDR targets first, host names after (a stable, readable order).
    t.valid = [...t.valid.filter((x) => canonTarget(x) !== null), ...t.valid.filter((x) => canonTarget(x) === null)];
  }
  const n = validateNames(names, { allowWildcard: allowWildcardNames === true });
  const opts = validateOptions({ cert, json, ports });
  const dropped = { targets: t.dropped, names: n.dropped, options: opts.dropped };
  const withExclude = exclude !== null && exclude !== undefined;
  let targetList = t.valid;
  const extra = {};
  if (withExclude) {
    const raw = typeof exclude === 'string' ? exclude.split(/[\s,]+/).filter(Boolean) : exclude;
    const ex = validateTargets(Array.isArray(raw) ? raw : [raw]);
    const split = applyExcludes(t.valid, ex.valid);
    targetList = split.targets;
    dropped.exclude = ex.dropped;
    extra.exclude = split.exclude;
    extra.excluded = split.excluded;
    extra.excludeUnused = split.unused;
  }
  const withTargetsFile = targetsFile !== null && targetsFile !== undefined;
  const tFile = withTargetsFile && typeof targetsFile === 'string' && PATH_TOKEN.test(targetsFile) ? targetsFile : null;
  if (withTargetsFile && tFile === null) dropped.options.push('targetsFile');
  if (!targetList.length || !n.valid.length) {
    const tf = withTargetsFile ? { targetsInline: true, targetsFile: null } : {};
    return { command: null, targets: targetList, names: n.valid, dropped, length: 0, namesInline: true, namesFile: null, ...tf, ...extra };
  }
  const q = (v) => quoteArg(v, shell);
  const pathTok = (v, fallback) => (typeof v === 'string' && PATH_TOKEN.test(v) ? v : fallback);
  const exTokens = withExclude && extra.exclude.length ? ` --exclude ${extra.exclude.map(q).join(' ')}` : '';
  const head = `${q(pathTok(script, DEFAULT_SCRIPT))} -t ${targetList.map(q).join(' ')}${exTokens} -n `;
  const tail = opts.tokens.length ? ` ${opts.tokens.map(q).join(' ')}` : '';
  const inline = `${head}${n.valid.map(q).join(' ')}${tail}`;
  const nameCap = Number.isFinite(maxInlineNames) && maxInlineNames >= 0 ? maxInlineNames : Infinity;
  const lenCap = Number.isFinite(maxLength) && maxLength > 0 ? maxLength : Infinity;
  const targetCap = Number.isFinite(maxInlineTargets) && maxInlineTargets >= 0 ? maxInlineTargets : Infinity;
  if (n.valid.length <= nameCap && inline.length <= lenCap && !(tFile && targetList.length > targetCap)) {
    const tf = withTargetsFile ? { targetsInline: true, targetsFile: null } : {};
    return { command: inline, targets: targetList, names: n.valid, dropped, length: inline.length, namesInline: true, namesFile: null, ...tf, ...extra };
  }
  const file = pathTok(namesFile, DEFAULT_NAMES_FILE);
  if (tFile) {
    // Both lists to files: the caller offers the two downloads (targets = the
    // validated `targets`, names = the validated `names`, one per line).
    const command = `${q(pathTok(script, DEFAULT_SCRIPT))} -t ${q(tFile)}${exTokens} -n ${q(file)}${tail}`;
    return { command, targets: targetList, names: n.valid, dropped, length: command.length, namesInline: false, namesFile: file, targetsInline: false, targetsFile: tFile, ...extra };
  }
  const command = `${head}${q(file)}${tail}`;
  const tf = withTargetsFile ? { targetsInline: true, targetsFile: null } : {};
  return { command, targets: targetList, names: n.valid, dropped, length: command.length, namesInline: false, namesFile: file, ...tf, ...extra };
}

/**
 * Convenience wrapper returning just the command string (or null).
 * @param {object} opts see {@link buildSweepCommand}
 * @returns {string|null}
 */
export function buildOriginSweepCommand(opts) {
  return buildSweepCommand(opts).command;
}
