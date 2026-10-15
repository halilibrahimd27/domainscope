/**
 * wscolor.js — the optional colour of a workspace (`color` in its meta, lib/workspace.js): one of
 * a small fixed palette, so that work does not land in the wrong customer's workspace. Colour is
 * never the only signal (the name is always shown beside it). Each entry has a light and a dark
 * theme value, both at least 3:1 against the surface they sit on (WCAG 1.4.11; the unit test
 * checks it); assets/css/style.css carries the same values as `--wsc-<id>`. DOM-free.
 */

/** id, value on a light surface (#ffffff), value on a dark surface (#151a21). */
export const WORKSPACE_COLORS = Object.freeze([
  Object.freeze({ id: 'red', light: '#c62828', dark: '#f87171' }),
  Object.freeze({ id: 'orange', light: '#b45309', dark: '#fb923c' }),
  Object.freeze({ id: 'green', light: '#15803d', dark: '#4ade80' }),
  Object.freeze({ id: 'teal', light: '#0f766e', dark: '#2dd4bf' }),
  Object.freeze({ id: 'blue', light: '#1d4ed8', dark: '#60a5fa' }),
  Object.freeze({ id: 'purple', light: '#7e22ce', dark: '#c084fc' }),
  Object.freeze({ id: 'pink', light: '#be185d', dark: '#f472b6' }),
  Object.freeze({ id: 'gray', light: '#4b5563', dark: '#9ca3af' })
]);

export const WORKSPACE_COLOR_IDS = Object.freeze(WORKSPACE_COLORS.map((c) => c.id));

/** The palette id in `value`, or null (anything else, including a CSS colour, is refused). */
export function sanitizeColor(value) {
  return typeof value === 'string' && WORKSPACE_COLOR_IDS.includes(value) ? value : null;
}
