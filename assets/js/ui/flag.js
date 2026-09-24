/**
 * ui/flag.js — a country flag that looks right on every platform.
 *
 * Flag emoji are pairs of regional-indicator letters. Windows ships no flag glyphs in its emoji
 * font (Segoe UI Emoji), so Chrome and Edge on Windows draw 🇹🇷 as two boxed letters "T R";
 * macOS, iOS, Android, most Linux desktops and Firefox (bundled Twemoji) draw real flags.
 * {@link supportsFlagEmoji} finds out once per page, by drawing a flag on a small canvas and
 * looking for colour (the letter fallback is monochrome). Without support {@link Flag} renders
 * the ISO 3166-1 code as text ("TR") in a chip the calling view styles (`<class>.is-code`).
 *
 * CSP-safe: no inline styles, no web fonts, no HTML strings; the canvas never leaves memory.
 *
 * @example
 *   import { Flag } from '../ui/flag.js';
 *   h('span', null, Flag('JP', { className: 'ipi-flag' }), ' ', formatRegion('JP'));
 *   // → <span class="ipi-flag flag is-emoji" data-cc="JP" aria-hidden="true">🇯🇵</span>
 *   //   or <span class="ipi-flag flag is-code" data-cc="JP" aria-hidden="true">JP</span>
 */

import { h } from './dom.js';
import { flagEmoji } from '../lib/resolvers.js';

/** Globe emoji used for "no country" (anycast): it exists in every emoji font, Windows included. */
export const GLOBE = '\u{1F310}';

/** Switzerland: red and white — easy to tell from monochrome fallback letters. */
const PROBE = '\u{1F1E8}\u{1F1ED}';
const PROBE_SIZE = 32;

let support = null;

/**
 * Does a rendered probe contain colour? True when at least `minPixels` pixels are clearly
 * coloured (the red of the Swiss flag): opaque enough and red well above green and blue.
 * The letter fallback is drawn in solid black and anti-aliased in grey, so it never qualifies.
 * @param {ArrayLike<number>} rgba RGBA bytes (ImageData.data)
 * @param {{ minPixels?: number }} [opts]
 * @returns {boolean}
 */
export function hasColorPixels(rgba, { minPixels = 4 } = {}) {
  if (!rgba || typeof rgba.length !== 'number') return false;
  let hits = 0;
  for (let i = 0; i + 3 < rgba.length; i += 4) {
    const r = rgba[i];
    const g = rgba[i + 1];
    const b = rgba[i + 2];
    const a = rgba[i + 3];
    if (a > 96 && r - g > 64 && r - b > 64) {
      hits += 1;
      if (hits >= minPixels) return true;
    }
  }
  return false;
}

/**
 * Can this browser draw flag emoji? Measured once and cached; false without a DOM/canvas
 * (Node, canvas blocked) so callers fall back to the always-readable country code.
 * @param {{ doc?: Document|null }} [opts] document to probe with (tests)
 * @returns {boolean}
 */
export function supportsFlagEmoji({ doc = typeof document !== 'undefined' ? document : null } = {}) {
  if (support !== null) return support;
  support = false;
  try {
    if (!doc || typeof doc.createElement !== 'function') return support;
    const canvas = doc.createElement('canvas');
    canvas.width = PROBE_SIZE;
    canvas.height = PROBE_SIZE;
    const ctx = canvas.getContext && canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return support;
    ctx.textBaseline = 'top';
    ctx.font = `${PROBE_SIZE - 8}px "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", "Twemoji Mozilla", sans-serif`;
    ctx.fillStyle = '#000';
    ctx.fillText(PROBE, 0, 2);
    support = hasColorPixels(ctx.getImageData(0, 0, PROBE_SIZE, PROBE_SIZE).data);
  } catch {
    support = false;
  }
  return support;
}

/**
 * Override (true/false) or forget (null) the cached support result — for tests and for
 * E2E runs that want to see both renderings.
 * @param {boolean|null} value
 */
export function setFlagEmojiSupport(value) {
  support = value === null ? null : !!value;
}

/**
 * What to show for a country code (pure).
 * @param {string|null|undefined} countryCode ISO 3166-1 alpha-2 (any case); anything else = no country
 * @param {boolean} emoji whether flag emoji render on this platform
 * @returns {{ mode: 'emoji'|'code'|'globe', text: string, cc: string|null }}
 */
export function flagContent(countryCode, emoji) {
  const cc = typeof countryCode === 'string' && /^[A-Za-z]{2}$/.test(countryCode) ? countryCode.toUpperCase() : null;
  if (!cc) return { mode: 'globe', text: GLOBE, cc: null };
  return emoji ? { mode: 'emoji', text: flagEmoji(cc), cc } : { mode: 'code', text: cc, cc };
}

/**
 * Flag element: the flag emoji where the platform draws them, otherwise the country code
 * (class `is-code`); a globe for "no country". Decorative (aria-hidden) unless `title` is
 * given — put the country name next to it or in `title`.
 * @param {string|null|undefined} countryCode
 * @param {{ className?: string, title?: string|null }} [opts] `className` is the view's own
 *   class (e.g. 'ipi-flag'); the element also gets `flag` and `is-emoji|is-code|is-globe`
 * @returns {HTMLSpanElement}
 */
export function Flag(countryCode, { className = '', title = null } = {}) {
  const c = flagContent(countryCode, supportsFlagEmoji());
  return h('span', {
    class: [className, 'flag', `is-${c.mode}`],
    title: title || null,
    dataset: c.cc ? { cc: c.cc } : null,
    attrs: { 'aria-hidden': title ? null : 'true' }
  }, c.text);
}
