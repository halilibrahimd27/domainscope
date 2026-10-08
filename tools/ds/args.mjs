/**
 * tools/ds/args.mjs — the command line of the headless runner (tools/ds.mjs) as data: its
 * subcommands, their options, the checks a value must pass before anything is sent, and the
 * help text. Pure: no file or network I/O (tools/ds.mjs reads the files named here).
 *
 * The runner's DNS goes through lib/doh.js's DohClient over Node's own fetch, which speaks
 * HTTP/1.1 only: the resolvers that answer nothing but HTTP/2 are refused by name
 * ({@link NODE_UNREADABLE}) and left out of the default chain ({@link NODE_CHAIN}), which is
 * otherwise the app's (lib/resolvers.js DEFAULT_CHAIN, state.js DEFAULT_SETTINGS).
 */

import { parseArgs } from 'node:util';
import { isIP } from 'node:net';
import { resolve as resolvePath } from 'node:path';
import { RESOLVERS, DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import { normalizeHostname } from '../../assets/js/lib/domain.js';
import { splitList } from '../../assets/js/lib/util.js';
import { SOURCES } from '../../assets/js/lib/sourceinfo.js';
import { parseRenewalNames, RENEWAL_CAS, RENEWAL_CHALLENGES } from '../../assets/js/lib/renewal.js';
import { DRIFT_DEFAULT_BUDGET, DRIFT_MAX_BUDGET } from '../../assets/js/lib/zonedrift.js';
import { CONCURRENCY_RANGE, DEFAULT_SETTINGS } from '../../assets/js/state.js';
import { POLICY_PRESET_IDS } from '../../assets/js/lib/policy.js';
import { passportDomain } from '../../assets/js/lib/passport.js';
import { PORTFOLIO_DKIM_SELECTORS } from '../../assets/js/lib/portfolio.js';
import { CT_WATCH_DEFAULT_DAYS, CT_WATCH_MAX_DAYS, CT_WATCH_MAX_THRESHOLDS, parseRadarDays } from '../../assets/js/lib/ctwatch.js';
import { WORKSPACE_LIMITS, sanitizeExpectedCas } from '../../assets/js/lib/workspace.js';

/** The runner's name in reports and messages. */
export const DS_TOOL = 'domainscope-ds';
/** Version of the runner and of its `--json` report (a baseline must share the major number). */
export const DS_VERSION = '1.0.0';

/**
 * Exit codes, numbered as the Python CLI's (cli/ssl_origin_scan.py); FAILED: an unexpected error
 * (printed). CHANGED: something changed since --baseline (with --fail-on-change) or, for `audit`,
 * a rule of the policy failed — 4, as the CLI's `--compare --fail-on-change` says "look here".
 */
export const EXIT = Object.freeze({ OK: 0, FAILED: 1, USAGE: 2, WRITE: 3, CHANGED: 4, INTERRUPTED: 130 });

/** The subcommands, in help order. */
export const COMMANDS = Object.freeze(['health', 'subdomains', 'drift', 'ct', 'renew', 'dane', 'audit', 'tls']);

/**
 * What each subcommand takes: `targets` 'domains' (host names, also from --list), 'names'
 * (renewal names, `*.` wildcards too), 'endpoints' (a host or address with an optional port,
 * {@link parseTlsTarget}) or 'file' (exactly one), and its own options.
 */
export const COMMAND_SPECS = Object.freeze({
  health: Object.freeze({ targets: 'domains', options: Object.freeze(['list']) }),
  subdomains: Object.freeze({ targets: 'domains', options: Object.freeze(['list', 'exact', 'level', 'sources']) }),
  drift: Object.freeze({ targets: 'file', options: Object.freeze(['origin', 'include-origins', 'max-queries']) }),
  ct: Object.freeze({ targets: 'domains', options: Object.freeze(['list', 'days', 'sources', 'radar', 'expected-ca']) }),
  renew: Object.freeze({ targets: 'names', options: Object.freeze(['list', 'ca', 'challenge']) }),
  dane: Object.freeze({ targets: 'file', options: Object.freeze([]) }),
  audit: Object.freeze({ targets: 'domains', options: Object.freeze(['list', 'policy', 'preset', 'no-dkim']) }),
  tls: Object.freeze({ targets: 'endpoints', options: Object.freeze(['list', 'ari', 'revocation']) })
});

/** What a target of each kind is, for "not …" messages. */
export const TARGET_WHAT = Object.freeze({
  domains: 'a domain name',
  names: 'a name a certificate can carry',
  endpoints: 'a host name or address, with an optional port (example.com:8443, [2001:db8::1]:443)'
});

/** The port of a `tls` target written without one. */
export const TLS_DEFAULT_PORT = 443;

/**
 * A `tls` target: `host`, `host:port`, `[v6]:port`, an address (no SNI: the server's default
 * certificate), or an https URL's host and port.
 * @param {string} token
 * @returns {{ target: string, host: string|null, address: string|null, port: number }|null} `target`:
 *   the label the report keys it by (the port only when it is not 443); `host` null for an address
 */
export function parseTlsTarget(token) {
  let s = String(token ?? '').trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    let u;
    try {
      u = new URL(s);
    } catch {
      return null;
    }
    if (u.protocol !== 'https:') return null;
    s = u.port ? `${u.hostname}:${u.port}` : u.hostname;
  }
  let host = s;
  let port = TLS_DEFAULT_PORT;
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(s);
  if (bracket) {
    host = bracket[1];
    if (bracket[2]) port = Number(bracket[2]);
    if (isIP(host) !== 6) return null;
  } else if (isIP(s) !== 6) {
    const m = /^([^:]+):(\d{1,5})$/.exec(s);
    if (m) {
      host = m[1];
      port = Number(m[2]);
    } else if (s.includes(':')) {
      return null;
    }
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const suffix = port === TLS_DEFAULT_PORT ? '' : `:${port}`;
  if (isIP(host) === 6) {
    let address;
    try {
      address = new URL(`https://[${host}]/`).hostname.slice(1, -1);
    } catch {
      return null; // a zone index (fe80::1%eth0) or another form the URL parser refuses
    }
    return { target: `[${address}]${suffix}`, host: null, address, port };
  }
  // node:net isIP takes dotted IPv4 only (no leading zeros, no short forms)
  if (isIP(host) === 4) return { target: `${host}${suffix}`, host: null, address: host, port };
  if (/^[\d.]+$/.test(host) || /^0x/i.test(host)) return null; // 010.0.0.1, 127.1, 0x7f.1: never a host name
  const name = normalizeHostname(host);
  if (!name) return null;
  return { target: `${name}${suffix}`, host: name, address: null, port };
}

/**
 * An `audit` target that names a file of domains rather than a domain: a path (a separator in
 * it) or a list's extension (`domains.txt`, `.csv`, `.list`, `.lst` — none is a TLD). A URL (a
 * scheme before `//`) is a target whatever its path: its registrable domain is audited.
 * @param {string} token
 * @returns {boolean}
 */
export function isListArgument(token) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) return false;
  return /[\\/]/.test(token) || /\.(?:txt|csv|list|lst)$/i.test(token);
}

/**
 * Resolvers Node's fetch cannot read (measured 2026-09-28 with Node 22 and 24): they answer
 * HTTP/2 only — Quad9 turns HTTP/1.1 away with 505, CZ.NIC's TLS offers no `http/1.1` ALPN.
 * A browser reads CZ.NIC; here it would only ever fail over.
 */
export const NODE_UNREADABLE = Object.freeze({ quad9: 'HTTP/2 only', 'quad9-ecs': 'HTTP/2 only', cznic: 'HTTP/2 only' });

/** The default failover chain: the app's, without the resolvers Node cannot read. */
export const NODE_CHAIN = Object.freeze(DEFAULT_CHAIN.filter((id) => !NODE_UNREADABLE[id]));

/** Wordlist levels `subdomains --level` takes; `small` is the default of an unattended run. */
export const DS_LEVELS = Object.freeze(['off', 'small', 'smart']);
export const DS_DEFAULT_LEVEL = 'small';
/** The passive sources that list certificates (`ct --sources`). */
export const CT_SOURCES = Object.freeze(['crtsh', 'certspotter']);
/** `ct --days`: the window of "recent" issuances in the summary. */
export const DS_DEFAULT_DAYS = 30;
export const DS_MAX_DAYS = 3650;
/** `ct --radar`: the expiry radar's thresholds in days left, the app's (lib/ctwatch.js), largest first. */
export const DS_DEFAULT_RADAR = CT_WATCH_DEFAULT_DAYS;

/** A command line the runner refuses (exit 2), with the reason as the message. */
export class UsageError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

const OPTION_SPEC = Object.freeze({
  json: { type: 'string' },
  md: { type: 'string' },
  baseline: { type: 'string' },
  'fail-on-change': { type: 'boolean' },
  resolver: { type: 'string' },
  concurrency: { type: 'string' },
  list: { type: 'string', multiple: true },
  quiet: { type: 'boolean', short: 'q' },
  'no-color': { type: 'boolean' },
  'show-all': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
  exact: { type: 'string' },
  level: { type: 'string' },
  sources: { type: 'string' },
  days: { type: 'string' },
  radar: { type: 'string' },
  'expected-ca': { type: 'string', multiple: true },
  origin: { type: 'string' },
  'include-origins': { type: 'boolean' },
  'max-queries': { type: 'string' },
  ca: { type: 'string' },
  challenge: { type: 'string' },
  policy: { type: 'string' },
  preset: { type: 'string' },
  'no-dkim': { type: 'boolean' },
  ari: { type: 'boolean' },
  revocation: { type: 'boolean' }
});

/** Options every subcommand takes. */
const COMMON_OPTIONS = new Set(['json', 'md', 'baseline', 'fail-on-change', 'resolver', 'concurrency', 'quiet', 'no-color', 'show-all', 'help', 'version']);

/**
 * @typedef {object} DsOptions
 * @property {string|null} json report file (`--json`)
 * @property {string|null} md Markdown summary file (`--md`)
 * @property {string|null} baseline the previous `--json` report of the same subcommand
 * @property {boolean} failOnChange exit 4 when a change that counts was found
 * @property {string[]} chain DoH failover chain (resolver ids)
 * @property {boolean} chainGiven `--resolver` was given
 * @property {number} concurrency parallel DoH requests
 * @property {string[]} lists `--list` files of more targets
 * @property {boolean} quiet no summary on stdout
 * @property {boolean} noColor
 * @property {boolean} showAll every change in the summary, not the first 50
 * @property {string|null} exact subdomains: a file of names to resolve (nothing guessed)
 * @property {'off'|'small'|'smart'} level subdomains: wordlist level
 * @property {string[]|null} sources subdomains / ct: passive sources (null = the default)
 * @property {number} days ct: "recent" window
 * @property {number[]} radar ct: the expiry radar's thresholds, days left, largest first (lib/ctwatch.js parseRadarDays)
 * @property {string[]} expectedCas ct: the CAs expected to issue (lib/expectedca.js entries; none: no issuer is unexpected)
 * @property {string|null} origin drift: the zone name
 * @property {boolean} includeOrigins drift: keep origin addresses in the reports
 * @property {number} maxQueries drift: query budget
 * @property {string|null} ca renew: RENEWAL_CAS id
 * @property {string} challenge renew: RENEWAL_CHALLENGES
 * @property {string|null} policy audit: the policy file (lib/policy.js)
 * @property {string|null} preset audit: a lib/policy.js POLICY_PRESET_IDS preset instead of a file
 * @property {boolean} dkim audit: look for DKIM keys at the common selectors (off with --no-dkim)
 * @property {boolean} ari tls: ask each certificate's CA for its ARI renewal window (--ari)
 * @property {boolean} revocation tls: read each certificate's CRL (--revocation)
 */

/**
 * @typedef {object} CommandLine
 * @property {string|null} command null with --help / --version alone
 * @property {string[]} targets the positional targets, as typed (domains normalized)
 * @property {DsOptions} options
 * @property {boolean} help
 * @property {boolean} version
 */

/** The option a parseArgs error names ('--json'; the long form of "'-q, --quiet'"), or null. */
function optionOf(message) {
  const s = String(message || '');
  const long = /'(?:-[A-Za-z], )?(--[A-Za-z][\w-]*)/.exec(s);
  if (long) return long[1];
  const other = /'(-[^'\s,]+)/.exec(s);
  return other ? other[1] : null;
}

/** parseArgs, with its errors as short usage errors. */
function tokenize(argv) {
  try {
    return parseArgs({ args: argv, options: OPTION_SPEC, allowPositionals: true, strict: true });
  } catch (err) {
    const opt = optionOf(err && err.message);
    switch (err && err.code) {
      case 'ERR_PARSE_ARGS_UNKNOWN_OPTION':
        throw new UsageError(opt ? `unknown option ${opt} (see --help)` : 'unknown option (see --help)');
      case 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE':
        throw new UsageError(OPTION_SPEC[(opt || '').replace(/^-+/, '')]?.type === 'boolean'
          ? `${opt} takes no value`
          : `${opt || 'an option'} needs a value`);
      default:
        throw new UsageError(err && err.message ? err.message : String(err));
    }
  }
}

/** A whole number within [min, max], or a usage error naming the option. */
function intOption(value, name, min, max, fallback) {
  if (value === undefined) return fallback;
  const s = String(value).trim();
  const n = /^\d+$/.test(s) ? Number(s) : NaN;
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new UsageError(`--${name} takes a whole number from ${min} to ${max}, not "${value}"`);
  return n;
}

/**
 * The DoH chain of `--resolver` (one id, or several separated by commas: the failover order).
 * @param {string|undefined} value
 * @returns {string[]}
 */
export function resolverChain(value) {
  if (value === undefined) return [...NODE_CHAIN];
  const ids = [...new Set(String(value).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean))];
  if (!ids.length) throw new UsageError('--resolver needs a resolver id');
  for (const id of ids) {
    if (!getResolver(id)) {
      const known = RESOLVERS.filter((r) => !NODE_UNREADABLE[r.id]).map((r) => r.id).join(', ');
      throw new UsageError(`--resolver: unknown resolver "${id}" (one of ${known})`);
    }
    if (NODE_UNREADABLE[id]) {
      throw new UsageError(`--resolver: ${id} answers over HTTP/2 only, which Node's fetch does not speak: pick another resolver`);
    }
  }
  return ids;
}

/**
 * `--radar 30,14,7`: the expiry radar's thresholds (lib/ctwatch.js parseRadarDays: whole days 1 …
 * 398, at most 5, largest first, duplicates dropped); the app's 30, 14, 7 without it.
 * @param {string|undefined} value
 * @returns {number[]}
 */
export function radarOption(value) {
  if (value === undefined) return [...DS_DEFAULT_RADAR];
  const days = parseRadarDays(value);
  if (!days) {
    throw new UsageError(`--radar takes up to ${CT_WATCH_MAX_THRESHOLDS} whole numbers of days from 1 to ${CT_WATCH_MAX_DAYS}, separated by commas (for example 30,14,7), not "${value}"`);
  }
  return days;
}

/**
 * `--expected-ca CA` (repeatable, one CA each: a CA's name, its id or CAA domain, or part of a private
 * CA's name — lib/expectedca.js): trimmed, whitespace collapsed, duplicates dropped, as a workspace
 * keeps its expected CAs (lib/workspace.js sanitizeExpectedCas). An empty one, one longer than a
 * workspace takes or more than a workspace holds is refused: a list cut short would make issuers
 * unexpected.
 * @param {string[]|undefined} values
 * @returns {string[]}
 */
export function expectedCaOption(values) {
  const list = values || [];
  for (const raw of list) {
    const text = String(raw).trim();
    if (!text) throw new UsageError('--expected-ca needs a CA: a name, id or CAA domain (letsencrypt.org), or part of a private CA\'s name');
    if (text.length > WORKSPACE_LIMITS.expectedCa) throw new UsageError(`--expected-ca takes at most ${WORKSPACE_LIMITS.expectedCa} characters, not ${text.length}`);
  }
  const distinct = new Set(list.map((s) => String(s).normalize('NFC').replace(/\s+/g, ' ').trim().toLowerCase()));
  if (distinct.size > WORKSPACE_LIMITS.expectedCas) throw new UsageError(`--expected-ca: at most ${WORKSPACE_LIMITS.expectedCas} CAs, not ${distinct.size}`);
  return sanitizeExpectedCas(list.map(String));
}

/** A comma-separated list of source ids, each in `allowed`. */
function sourceList(value, allowed, name) {
  if (value === undefined) return null;
  const ids = [...new Set(String(value).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean))];
  if (!ids.length) throw new UsageError(`--${name} needs at least one source`);
  for (const id of ids) {
    if (!allowed.includes(id)) throw new UsageError(`--${name}: unknown source "${id}" (one of ${allowed.join(', ')})`);
  }
  return ids;
}

/**
 * The targets of a subcommand from tokens (positional arguments, or the lines of a --list
 * file): domains are normalized host names (a URL gives its host), `audit`'s their registrable
 * domains (lib/passport.js passportDomain, as the app's Domain portfolio reads its list:
 * www.example.com is example.com), renewal names go through lib/renewal.js parseRenewalNames (a
 * `*.` wildcard too). Duplicates are dropped.
 * @param {string} command
 * @param {string[]} tokens
 * @returns {{ targets: string[], invalid: string[] }}
 */
export function parseTargets(command, tokens) {
  const spec = COMMAND_SPECS[command];
  if (!spec) throw new UsageError(`unknown command "${command}"`);
  const list = (tokens || []).map((s) => String(s).trim()).filter(Boolean);
  if (spec.targets === 'file') return { targets: list, invalid: [] };
  if (spec.targets === 'endpoints') {
    const targets = [];
    const invalid = [];
    for (const token of list) {
      const t = parseTlsTarget(token);
      if (!t) invalid.push(token);
      else if (!targets.includes(t.target)) targets.push(t.target);
    }
    return { targets, invalid };
  }
  if (spec.targets === 'names') {
    const parsed = parseRenewalNames(list, { max: Number.MAX_SAFE_INTEGER });
    return { targets: parsed.names.map((n) => n.name), invalid: [...parsed.invalid, ...parsed.suffixWildcards] };
  }
  const targets = [];
  const invalid = [];
  for (const token of list) {
    const host = command === 'audit' ? (passportDomain(token) || {}).domain : normalizeHostname(token);
    if (!host) invalid.push(token);
    else if (!targets.includes(host)) targets.push(host);
  }
  return { targets, invalid };
}

/**
 * The targets of a --list file's text: one or more per line (spaces, commas or semicolons
 * between them), `#` comments. Invalid entries are returned, not thrown: the runner warns
 * about them and goes on, as the Python CLI does with a file.
 * @param {string} command
 * @param {string} text
 * @returns {{ targets: string[], invalid: string[] }}
 */
export function parseListText(command, text) {
  return parseTargets(command, splitList(text));
}

/** Same file? Resolved paths, case-insensitive on Windows. */
export function samePath(a, b, { platform = process.platform } = {}) {
  if (!a || !b) return false;
  const norm = (p) => {
    const abs = resolvePath(p);
    return platform === 'win32' ? abs.toLowerCase() : abs;
  };
  return norm(a) === norm(b);
}

/**
 * Parse and check a command line (without the node / script arguments). Pure: the files it
 * names are not opened here.
 * @param {string[]} argv
 * @returns {CommandLine}
 * @throws {UsageError}
 */
export function parseCommandLine(argv) {
  const { values: v, positionals } = tokenize(Array.isArray(argv) ? argv.map(String) : []);
  const help = v.help === true;
  const version = v.version === true;
  const [command = null, ...rest] = positionals;
  if (!command) {
    if (help || version) return { command: null, targets: [], options: defaults(), help, version };
    throw new UsageError(`a command is needed: ${COMMANDS.join(', ')} (see --help)`);
  }
  if (!COMMAND_SPECS[command]) {
    throw new UsageError(`unknown command "${command}" (one of ${COMMANDS.join(', ')})`);
  }
  const spec = COMMAND_SPECS[command];
  for (const name of Object.keys(v)) {
    if (!COMMON_OPTIONS.has(name) && !spec.options.includes(name)) {
      const owners = COMMANDS.filter((c) => COMMAND_SPECS[c].options.includes(name));
      const list = owners.length > 1 ? `${owners.slice(0, -1).join(', ')} and ${owners.at(-1)}` : owners[0];
      throw new UsageError(`--${name} applies to ${list} only, not to ${command}`);
    }
  }
  if (help || version) return { command, targets: [], options: defaults(), help, version };

  for (const name of ['json', 'md', 'baseline', 'exact', 'policy']) {
    if (v[name] === '-') throw new UsageError(`--${name} takes a file, not "-"`);
    if (v[name] !== undefined && !String(v[name]).trim()) throw new UsageError(`--${name} needs a file name`);
  }
  for (const file of v.list || []) {
    if (file === '-' || !String(file).trim()) throw new UsageError('--list takes a file of targets');
  }

  const options = defaults();
  options.json = v.json ?? null;
  options.md = v.md ?? null;
  options.baseline = v.baseline ?? null;
  options.failOnChange = v['fail-on-change'] === true;
  options.chain = resolverChain(v.resolver);
  options.chainGiven = v.resolver !== undefined;
  options.concurrency = intOption(v.concurrency, 'concurrency', CONCURRENCY_RANGE.min, CONCURRENCY_RANGE.max, DEFAULT_SETTINGS.concurrency);
  options.lists = [...(v.list || [])];
  options.quiet = v.quiet === true;
  options.noColor = v['no-color'] === true;
  options.showAll = v['show-all'] === true;

  if (options.failOnChange && !options.baseline) throw new UsageError('--fail-on-change needs --baseline');
  if (options.json && options.md && samePath(options.json, options.md)) throw new UsageError('--json and --md name the same file');
  if (options.baseline && options.md && samePath(options.baseline, options.md)) {
    throw new UsageError('--baseline and --md name the same file: the Markdown summary would overwrite the baseline and cannot be compared');
  }

  if (command === 'subdomains') {
    options.exact = v.exact ?? null;
    if (v.level !== undefined && !DS_LEVELS.includes(String(v.level).toLowerCase())) {
      throw new UsageError(`--level takes ${DS_LEVELS.join(', ')}, not "${v.level}"`);
    }
    if (options.exact && v.level !== undefined) throw new UsageError('--exact resolves the listed names only: it takes no --level');
    if (options.exact && v.sources !== undefined) throw new UsageError('--exact resolves the listed names only: it asks no passive source');
    options.level = options.exact ? 'off' : (v.level ? String(v.level).toLowerCase() : DS_DEFAULT_LEVEL);
    options.sources = sourceList(v.sources, SOURCES.map((s) => s.id), 'sources');
  }
  if (command === 'ct') {
    options.days = intOption(v.days, 'days', 1, DS_MAX_DAYS, DS_DEFAULT_DAYS);
    options.sources = sourceList(v.sources, [...CT_SOURCES], 'sources');
    options.radar = radarOption(v.radar);
    options.expectedCas = expectedCaOption(v['expected-ca']);
  }
  if (command === 'drift') {
    if (v.origin !== undefined) {
      const origin = normalizeHostname(v.origin, { allowSingleLabel: true });
      if (!origin) throw new UsageError(`--origin: not a zone name: "${v.origin}"`);
      options.origin = origin;
    }
    options.includeOrigins = v['include-origins'] === true;
    options.maxQueries = intOption(v['max-queries'], 'max-queries', 1, DRIFT_MAX_BUDGET, DRIFT_DEFAULT_BUDGET);
  }
  if (command === 'renew') {
    if (v.ca !== undefined) {
      const ca = String(v.ca).trim().toLowerCase();
      if (!RENEWAL_CAS.some((c) => c.id === ca)) throw new UsageError(`--ca: unknown CA "${v.ca}" (one of ${RENEWAL_CAS.map((c) => c.id).join(', ')})`);
      options.ca = ca;
    }
    if (v.challenge !== undefined) {
      const challenge = String(v.challenge).trim().toLowerCase();
      if (!RENEWAL_CHALLENGES.includes(challenge)) throw new UsageError(`--challenge takes ${RENEWAL_CHALLENGES.join(', ')}, not "${v.challenge}"`);
      options.challenge = challenge;
    }
  }

  if (command === 'tls') {
    options.ari = v.ari === true;
    options.revocation = v.revocation === true;
  }

  if (command === 'audit') {
    if ((v.policy === undefined) === (v.preset === undefined)) throw new UsageError('audit needs the rules: --policy FILE or --preset NAME (one of them)');
    if (v.preset !== undefined) {
      const preset = String(v.preset).trim().toLowerCase();
      if (!POLICY_PRESET_IDS.includes(preset)) throw new UsageError(`--preset takes ${POLICY_PRESET_IDS.join(', ')}, not "${v.preset}"`);
      options.preset = preset;
    }
    options.policy = v.policy ?? null;
    options.dkim = v['no-dkim'] !== true;
    // `audit --policy policy.json domains.txt`: a positional file is a list of domains.
    options.lists = [...options.lists, ...rest.filter(isListArgument)];
  }

  let targets = command === 'audit' ? rest.filter((x) => !isListArgument(x)) : rest;
  if (spec.targets === 'file') {
    if (rest.length !== 1) throw new UsageError(`${command} takes one file${rest.length ? `, not ${rest.length}` : ''}`);
  } else {
    const parsed = parseTargets(command, targets);
    if (parsed.invalid.length) {
      throw new UsageError(`not ${TARGET_WHAT[spec.targets]}: ${parsed.invalid.map((s) => `"${s}"`).join(', ')}`);
    }
    if (!parsed.targets.length && !options.lists.length) {
      const one = { names: 'name', endpoints: 'host' }[spec.targets] || 'domain';
      throw new UsageError(`${command} needs at least one ${one} (or --list FILE)`);
    }
    targets = parsed.targets;
  }
  // A report written over a file the run reads would replace the zone export, the certificate
  // or the list with JSON / Markdown.
  const inputs = [
    ...options.lists.map((file) => ['--list', file]),
    ...(options.policy ? [['--policy', options.policy]] : []),
    ...(options.exact ? [['--exact', options.exact]] : []),
    ...(spec.targets === 'file' ? [[command === 'drift' ? 'the zone file' : 'the certificate file', rest[0]]] : [])
  ];
  for (const [option, out] of [['--json', options.json], ['--md', options.md]]) {
    const same = out ? inputs.find(([, file]) => samePath(out, file)) : null;
    if (same) throw new UsageError(`${option} names the same file as ${same[0]} (${same[1]}): the report would overwrite it`);
  }
  return { command, targets, options, help: false, version: false };
}

/** @returns {DsOptions} */
function defaults() {
  return {
    json: null, md: null, baseline: null, failOnChange: false, chain: [...NODE_CHAIN], chainGiven: false,
    concurrency: DEFAULT_SETTINGS.concurrency, lists: [], quiet: false, noColor: false, showAll: false,
    exact: null, level: DS_DEFAULT_LEVEL, sources: null, days: DS_DEFAULT_DAYS, radar: [...DS_DEFAULT_RADAR], expectedCas: [],
    origin: null, includeOrigins: false, maxQueries: DRIFT_DEFAULT_BUDGET, ca: null, challenge: 'unknown',
    policy: null, preset: null, dkim: true, ari: false, revocation: false
  };
}

/** `--help` text. */
export const USAGE = `usage: node tools/ds.mjs COMMAND TARGET... [options]

DomainScope's checks without a browser tab: the app's own libraries (assets/js/lib)
under Node 22+, DNS over HTTPS through the same resolvers and limits, a short summary
on stdout, a JSON report and a Markdown summary, and the changes since the last run.

commands:
  health DOMAIN...               Domain Health: DNS, mail, CAA, DNSSEC and registration checks
  subdomains DOMAIN...           discover the subdomains (passive sources, mining, a wordlist)
      [--level off|small|smart]  wordlist level (default ${DS_DEFAULT_LEVEL}; the app's default is smart)
      [--sources a,b]            passive sources (default: ${SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id).join(', ')})
      [--exact FILE]             resolve the names in FILE only: no source, no guess, no quota
  drift ZONEFILE                 compare a zone export with live DNS (the Zone File view's live check)
      [--origin ZONE]            the zone name, when the file does not say it for sure
      [--max-queries N]          query budget (default ${DRIFT_DEFAULT_BUDGET}, at most ${DRIFT_MAX_BUDGET})
      [--include-origins]        keep the origin addresses behind proxied names in the reports
  ct DOMAIN...                   current certificates from Certificate Transparency, their issuers,
                                 and the Domain portfolio's CT watch: the expiry radar, new since
                                 the last run (--baseline), unexpected CA, wildcard, precertificate
                                 only
      [--days N]                 "recent" issuances: the last N days (default ${DS_DEFAULT_DAYS})
      [--radar D,D,...]          the expiry radar in days left (default ${DS_DEFAULT_RADAR.join(',')}; up to
                                 ${CT_WATCH_MAX_THRESHOLDS}, each 1-${CT_WATCH_MAX_DAYS}): a current certificate crossing one is EXPIRING
      [--expected-ca CA]...      a CA you expect: its name, id or CAA domain (letsencrypt.org), or
                                 part of a private CA's name; repeatable. Any other issuer is an
                                 unexpected CA
      [--sources crtsh,certspotter]
  renew NAME...                  Renewal readiness: will the next ACME renewal validate?
      [--ca ID] [--challenge http-01|dns-01|tls-alpn-01|unknown]
  dane CERT.pem                  the DANE / TLSA renewal guard for a certificate (fullchain.pem)
  audit DOMAIN|FILE...           the Domain portfolio's policy audit: each domain's registration
                                 (RDAP), DNSSEC, the name servers' own domains, CAA and mail posture
                                 against the rules of a policy; a pass / fail matrix, and each
                                 domain's security score (CSC's 8 measures) as a table
      --policy FILE              the policy (JSON, as the app exports it), or
      --preset NAME              a built-in one: ${POLICY_PRESET_IDS.join(', ')}
      [--no-dkim]                skip the DKIM keys (${PORTFOLIO_DKIM_SELECTORS.length} common selectors per domain)
  tls HOST[:PORT]...             the certificate every address of a host serves (SNI = the host; an
                                 address alone: no SNI), its expiry, trust and name, each address on
                                 its own (default port ${TLS_DEFAULT_PORT}; [2001:db8::1]:8443 for IPv6)
      [--ari]                    ask the issuing CA for its ACME renewal window (RFC 9773): Let's
                                 Encrypt, Google Trust Services, ZeroSSL, Sectigo, SSL.com
      [--revocation]             read the CRL each certificate names (no OCSP): REVOKED, with the
                                 reason and the time

targets: DOMAIN / NAME / HOST[:PORT] on the command line, and --list FILE (repeatable) with one or more per
  line (# comments). An invalid entry is an error on the command line and a warning in a file.
  audit takes a file of domains as a target too (a path, or a name ending .txt, .csv, .list,
  .lst), and audits each domain's registrable domain (www.example.com is example.com).

options:
  --json FILE          write the report (JSON); give it to --baseline next time
  --md FILE            write the summary as Markdown (for an issue, a wiki, a chat)
  --baseline FILE      compare with a previous --json report of the same command: the changes
                       open the summary ("Changes since the baseline"); the same file may be
                       given to --json (read before the run, replaced after it). While it does
                       not exist (the first run) there is nothing to compare. What a run could
                       not read (a failed lookup, a source that was down), its report carries
                       from the last run that read it: the next run compares with that read.
  --fail-on-change     exit 4 when anything that counts changed since --baseline
  --resolver ID[,ID]   DoH resolvers in failover order (default ${NODE_CHAIN.join(',')}; ${Object.keys(NODE_UNREADABLE).join(', ')}
                       answer over HTTP/2 only, which Node's fetch does not speak)
  --concurrency N      parallel DoH requests, ${CONCURRENCY_RANGE.min}-${CONCURRENCY_RANGE.max} (default ${DEFAULT_SETTINGS.concurrency}, as in the app)
  --show-all           list every change in the summary (not the first 50)
  -q, --quiet          no summary on stdout (errors still go to stderr)
  --no-color           no colours (also NO_COLOR=1, and whenever stdout is not a terminal)
  -h, --help / --version

what is sent: names and record types to the DoH resolvers (renew also asks Cloudflare,
  Google and DNS.SB by name to compare CAA, as the app does); health asks RDAP; subdomains
  asks the passive sources (quota-limited, shared per IP address) unless --exact; ct asks
  crt.sh and Cert Spotter. Over several domains, Cert Spotter is not asked again after it
  answers "rate limited" until its wait (at most an hour) is over — it takes about 10
  full-domain queries an hour per IP address — and crt.sh is not asked again that run once
  it is down (ct --sources crtsh leaves Cert Spotter out). Nothing goes to Globalping: the
  checks that need a probe (Verify, the MTA-STS policy, the HTTP-01 test) stay in the app,
  behind a click. audit asks the DoH resolvers and RDAP (the registry's server from the IANA
  bootstrap; rdap.org only as the fallback, one request a second), each name server domain once.
  tls connects to every address of each target (a TLS handshake); --ari sends each certificate's
  CertID (the issuer's key identifier and the serial number, both public) to the issuing CA's ARI
  server, --revocation downloads the CRLs the certificates name from their CAs (at most 20 MB each).

tls changes: another certificate on an address (CERT: counted when it drops a name, changes the
  key type or the CA), a handshake that stops completing (FAILED), a worse status (WORSE), and with
  --ari / --revocation: RENEW-NOW (the CA's renewal window has opened, or ended), MOVED-UP (it now
  starts more than a day earlier: CAs do that before a mass revocation), CA-NOTICE (an explanation
  URL the CA did not give before) and REVOKED (the CRL lists a served certificate). A CA is not
  asked again before the Retry-After of its last answer. An IPv6 address this machine cannot reach
  is SKIPPED (GitHub's hosted runners have no IPv6 route), never a change.

ct watch: each domain's report keeps the ids of the certificates seen (the next run's baseline,
  as the app's workspace keeps them), so a run with --baseline marks what was logged since. A
  new certificate from an unexpected CA counts (CA), and so does a current certificate - the
  newest of its names - crossing a radar threshold (EXPIRING) once an automatic renewal is
  overdue: with less than a quarter of its lifetime left (ACME clients renew at a third; a
  crossing before that is listed only), and the certificate in use being revoked (REVOKED).
  Cert Spotter's answers say which certificates are logged only as a precertificate; crt.sh's
  do not.

exit codes: 0 done, 1 the run failed (an unexpected error, printed), 2 usage error (report
  files that cannot be written or that are one of the run's input files, and a baseline that
  cannot be compared, are refused before the run), 3 a report file could not be written
  after the run, 4 a rule of the policy failed (audit), or something changed since --baseline
  (only with --fail-on-change), 130 interrupted (nothing written). When several apply: 3, then 4.
  A rule that could not be checked (a lookup failed, a TLD without RDAP) is no failure, unless it
  failed when last checked (--baseline): it still counts as failed.

examples:
  node tools/ds.mjs health example.com example.org --json health.json --md health.md
  node tools/ds.mjs subdomains example.com --baseline subs.json --json subs.json --fail-on-change
  node tools/ds.mjs ct --list domains.txt --json ct.json --baseline ct.json
  node tools/ds.mjs ct example.com --expected-ca letsencrypt --expected-ca digicert --radar 21,7
  node tools/ds.mjs drift example.com.zone --origin example.com --md drift.md
  node tools/ds.mjs renew example.com '*.example.com' --ca letsencrypt --challenge dns-01
  node tools/ds.mjs dane fullchain.pem
  node tools/ds.mjs audit --policy policy.json domains.txt --json audit.json --md audit.md
  node tools/ds.mjs audit --preset parked example.org --baseline audit.json --json audit.json
  node tools/ds.mjs audit --preset corporate --list domains.txt --md audit.md
  node tools/ds.mjs tls --list tls-hosts.txt --ari --revocation --baseline tls.json --json tls.json
  node tools/ds.mjs tls www.example.com example.com:8443 --ari
`;
