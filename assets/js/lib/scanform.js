/**
 * scanform.js — the SSL Targets setup form as data: which steps are complete, whether the one
 * requirement ("a certificate or at least one domain") is met, which options differ from the
 * defaults (the one-line summary of the collapsed Options step) and whether the run bar is stuck
 * to the bottom of the screen.
 *
 * Pure: no DOM, storage, network, clock or i18n. views/scan.js feeds it counts and the sanitized
 * options, and turns the results into text, check marks and data attributes.
 */

/** The setup steps in page order (the Options step never needs input: it has defaults). */
export const FORM_STEPS = Object.freeze(['cert', 'domains', 'inventory', 'options']);

/**
 * Option ids {@link optionChanges} can report, in the order they are listed.
 * `sources`: the ticked set differs from the default one; `bruteforce`: another wordlist level;
 * `languages`: a manual language / market choice (Subdomains › Advanced) the level uses;
 * `permutations` / `includeExpired` / `originHints`: the switch differs; `permutationBudget`: another
 * budget while permutations are on; `extraNames`, `custom`, `learned`: names this scan adds.
 */
export const OPTION_CHANGE_IDS = Object.freeze([
  'sources', 'bruteforce', 'languages', 'permutations', 'permutationBudget', 'includeExpired', 'originHints',
  'extraNames', 'custom', 'learned'
]);

/** Wordlist levels that add the locale packs (Small is language-neutral, Off tries no names). */
const LEVELS_WITH_PACKS = new Set(['smart', 'large', 'huge']);

const count = (n) => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

/**
 * Where the setup form stands. The requirement matches what Start accepts: typed domains, the
 * certificate's names or extra hostnames (any one of them gives the scan something to search).
 * A step is complete when it has usable input: a server certificate with at least one DNS name
 * (a CA certificate, or one without names, is flagged in `certIssue` instead), typed domains
 * without an invalid entry or a public suffix among them, a saved server.
 * @param {{ cert?: boolean, certCA?: boolean, certNames?: number, domains?: number, invalid?: number,
 *   publicSuffixes?: number, extraNames?: number, servers?: number }} [input] counts from the form
 *   (`cert`: a leaf certificate is loaded; `certCA`: it is a CA certificate; `certNames`: its hostnames)
 * @returns {{ ready: boolean, via: 'domains'|'cert'|'extra'|null,
 *   steps: { cert: boolean, domains: boolean, inventory: boolean, options: boolean },
 *   certIssue: 'ca'|'noNames'|null }}
 *   `via`: what meets the requirement (typed domains first, then the certificate, then extra
 *   names); `certIssue`: why a loaded certificate leaves its step open (a CA certificate first)
 */
export function formProgress({
  cert = false, certCA = false, certNames = 0, domains = 0, invalid = 0, publicSuffixes = 0, extraNames = 0, servers = 0
} = {}) {
  let via = null;
  if (count(domains)) via = 'domains';
  else if (cert && count(certNames)) via = 'cert';
  else if (count(extraNames)) via = 'extra';
  let certIssue = null;
  if (cert && certCA) certIssue = 'ca';
  else if (cert && !count(certNames)) certIssue = 'noNames';
  return {
    ready: via !== null,
    via,
    steps: {
      cert: !!cert && certIssue === null,
      domains: count(domains) > 0 && !count(invalid) && !count(publicSuffixes),
      inventory: count(servers) > 0,
      // Always usable: the defaults are a complete choice (no check mark is drawn for it).
      options: true
    },
    certIssue
  };
}

const sameSet = (a, b) => {
  const x = new Set(a || []);
  const y = new Set(b || []);
  return x.size === y.size && [...x].every((v) => y.has(v));
};

/**
 * The options that differ from the defaults, in {@link OPTION_CHANGE_IDS} order — an empty list
 * means "the recommended defaults". Vocabulary shared with Subdomains (languages, custom and
 * learned names) only counts while a wordlist level uses it.
 * @param {{ sources: string[], bruteforce: string, permutations: boolean, permutationBudget: number,
 *   includeExpired: boolean, originHints: boolean }} options the sanitized scan options
 * @param {typeof options} defaults the sanitized defaults (views/scan.sanitizeOptions(null))
 * @param {{ totalSources?: number, extraNames?: number, locales?: string[]|null, custom?: number, learned?: number }} [more]
 *   `totalSources`: how many sources exist; `extraNames`: valid extra hostnames; `locales`: the manual
 *   language choice (null = automatic, the default); `custom` / `learned`: names the level tries first
 * @returns {Array<{ id: string, value?: boolean|number|string|string[], count?: number, total?: number }>}
 */
export function optionChanges(options, defaults, { totalSources = 0, extraNames = 0, locales = null, custom = 0, learned = 0 } = {}) {
  const o = options || {};
  const d = defaults || {};
  const out = [];
  const sources = Array.isArray(o.sources) ? o.sources : [];
  if (!sameSet(sources, d.sources)) {
    out.push({ id: 'sources', count: sources.length, total: Math.max(count(totalSources), sources.length) });
  }
  const level = o.bruteforce;
  if (level !== d.bruteforce) out.push({ id: 'bruteforce', value: level });
  if (Array.isArray(locales) && LEVELS_WITH_PACKS.has(level)) out.push({ id: 'languages', value: [...new Set(locales)] });
  if (!!o.permutations !== !!d.permutations) out.push({ id: 'permutations', value: !!o.permutations });
  if (o.permutations && o.permutationBudget !== d.permutationBudget) out.push({ id: 'permutationBudget', value: o.permutationBudget });
  if (!!o.includeExpired !== !!d.includeExpired) out.push({ id: 'includeExpired', value: !!o.includeExpired });
  if (!!o.originHints !== !!d.originHints) out.push({ id: 'originHints', value: !!o.originHints });
  if (count(extraNames)) out.push({ id: 'extraNames', count: count(extraNames) });
  const wordlistOn = typeof level === 'string' && level !== 'off';
  if (wordlistOn && count(custom)) out.push({ id: 'custom', count: count(custom) });
  if (wordlistOn && count(learned)) out.push({ id: 'learned', count: count(learned) });
  return out;
}

/** The folded setup row names this many domains, then "+N". */
export const SETUP_DOMAINS_SHOWN = 2;

/**
 * The folded setup (DESIGN §5.5 "Wizard": once a scan starts the steps fold into one row,
 * "Certificate *.example.net · RSA 2048 · Domains example.net · 4 servers · recommended options —
 * Edit"): what each part of that row says. `cert`: the certificate's name and key, or how many
 * certificates (several), or null; `domains`: the first ones and how many more (none typed: the
 * certificate's names are scanned, `fromCert`); `servers`: the server list's size; `options`: the
 * changes from the defaults (lib/scanform optionChanges ids), empty for the recommended ones.
 * @param {{ cert?: { name: string, key?: string|null }|null, certs?: number, domains?: string[], servers?: number,
 *   changes?: Array<{ id: string }> }} [form]
 * @returns {{ cert: { name: string, key: string|null }|{ many: number }|null,
 *   domains: { shown: string[], more: number, fromCert: boolean }, servers: number, options: Array<{ id: string }> }}
 */
export function setupSummary({ cert = null, certs = 0, domains = [], servers = 0, changes = [] } = {}) {
  const list = [...new Set((Array.isArray(domains) ? domains : []).filter((d) => typeof d === 'string' && d))];
  const shown = list.slice(0, SETUP_DOMAINS_SHOWN);
  let certPart = null;
  if (count(certs) > 1) certPart = { many: count(certs) };
  else if (cert && cert.name) certPart = { name: String(cert.name), key: cert.key ? String(cert.key) : null };
  return {
    cert: certPart,
    domains: { shown, more: list.length - shown.length, fromCert: !list.length && !!certPart },
    servers: count(servers),
    options: (Array.isArray(changes) ? changes : []).filter((c) => c && c.id)
  };
}

/**
 * What a scan with this setup would scan, as one string: a finished scan whose setup has the same
 * signature is what the form still asks for, so Run reads "Run again" (DESIGN §5.1, region 3) — any
 * other domain, certificate, extra name, option or zone mode makes it the verb again. The order of
 * the domains, names and sources does not count.
 * @param {{ domains?: string[], certs?: string[], extraNames?: string[], options?: { sources?: string[], bruteforce?: string,
 *   permutations?: boolean, permutationBudget?: number, includeExpired?: boolean, originHints?: boolean }, zone?: string|null }} [setup]
 *   `certs`: a key per certificate (serial and issuer); `zone`: the zone file's mode, or null
 * @returns {string}
 */
export function setupSignature({ domains = [], certs = [], extraNames = [], options = {}, zone = null } = {}) {
  const sorted = (list) => [...new Set((Array.isArray(list) ? list : []).map(String))].sort();
  const o = options || {};
  return JSON.stringify({
    domains: sorted(domains),
    certs: sorted(certs),
    extra: sorted(extraNames),
    sources: sorted(o.sources),
    bruteforce: o.bruteforce || null,
    permutations: o.permutations ? Number(o.permutationBudget) || 0 : 0,
    expired: !!o.includeExpired,
    hints: !!o.originHints,
    zone: zone || null
  });
}

/**
 * Is a bottom-sticky bar stuck (floating over the page)? The run bar is ui/template.js's sticky
 * RunBar now, which asks lib/template.js barStuck; re-exported for the callers of this module.
 */
export { barStuck } from './template.js';
