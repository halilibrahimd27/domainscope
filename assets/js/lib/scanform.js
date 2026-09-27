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
 * A step is complete when it has usable input: a loaded certificate, typed domains without an
 * invalid entry or a public suffix among them, a saved server.
 * @param {{ cert?: boolean, certNames?: number, domains?: number, invalid?: number, publicSuffixes?: number,
 *   extraNames?: number, servers?: number }} [input] counts from the form (`cert`: a leaf certificate is loaded)
 * @returns {{ ready: boolean, via: 'domains'|'cert'|'extra'|null,
 *   steps: { cert: boolean, domains: boolean, inventory: boolean, options: boolean } }}
 *   `via`: what meets the requirement (typed domains first, then the certificate, then extra names)
 */
export function formProgress({ cert = false, certNames = 0, domains = 0, invalid = 0, publicSuffixes = 0, extraNames = 0, servers = 0 } = {}) {
  let via = null;
  if (count(domains)) via = 'domains';
  else if (cert && count(certNames)) via = 'cert';
  else if (count(extraNames)) via = 'extra';
  return {
    ready: via !== null,
    via,
    steps: {
      cert: !!cert,
      domains: count(domains) > 0 && !count(invalid) && !count(publicSuffixes),
      inventory: count(servers) > 0,
      // Always usable: the defaults are a complete choice (no check mark is drawn for it).
      options: true
    }
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

/**
 * Is a bottom-sticky bar stuck (floating over the page) rather than resting in its own place?
 * The bar is the last child of its container, so it rests where the container ends: it floats
 * while that end lies below the viewport and the container is still on screen.
 * @param {{ sticky?: boolean, top?: number, bottom?: number, viewportHeight?: number }} m
 *   `sticky`: the bar is position: sticky at this width; `top` / `bottom`: the container's
 *   bounding rect (viewport coordinates); `viewportHeight`: innerHeight
 * @returns {boolean}
 */
export function barStuck({ sticky = false, top = 0, bottom = 0, viewportHeight = 0 } = {}) {
  const vh = Number(viewportHeight);
  return !!sticky && Number(bottom) > vh + 0.5 && Number(top) < vh;
}
