/**
 * The design tokens of assets/css/style.css § 1 (docs/DESIGN.md §6): the set the spec names is
 * there, the two dark blocks define the same tokens, no stylesheet uses a custom property nothing
 * defines (a var() that does not resolve unsets its property silently), and the contrast the spec
 * promises holds in both themes — text, white button labels, and the controls' 3:1 (WCAG 1.4.11).
 * No browser: the stylesheets are read as text.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CSS_DIR = join(ROOT, 'assets', 'css');
const style = readFileSync(join(CSS_DIR, 'style.css'), 'utf8');
const sheets = [
  ...readdirSync(CSS_DIR).filter((f) => f.endsWith('.css')).map((f) => join(CSS_DIR, f)),
  ...readdirSync(join(CSS_DIR, 'views')).filter((f) => f.endsWith('.css')).map((f) => join(CSS_DIR, 'views', f))
];
const stripComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, '');

/** The declarations of the first rule whose selector line matches, as a Map of custom properties. */
function tokenBlock(css, opener) {
  const start = css.indexOf(opener);
  assert.ok(start !== -1, `block ${opener}`);
  const open = css.indexOf('{', start);
  let depth = 0;
  let end = open;
  for (; end < css.length; end++) {
    if (css[end] === '{') depth++;
    else if (css[end] === '}' && --depth === 0) break;
  }
  const body = stripComments(css.slice(open + 1, end));
  return new Map([...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
}

const light = tokenBlock(style, ':root {\n  color-scheme: light;');
const darkAuto = tokenBlock(style, ':root:not([data-theme="light"]) {');
const darkForced = tokenBlock(style, ':root[data-theme="dark"] {');
const compact = tokenBlock(style, ':root[data-density="compact"] {');

describe('design tokens (style.css § 1)', () => {
  test('the set of docs/DESIGN.md §6.1 is defined, under today\'s names', () => {
    const names = [
      '--font-sans', '--font-mono',
      ...['2xs', 'xs', 'sm', 'md', 'lg', 'xl', '2xl'].flatMap((s) => [`--fs-${s}`, `--lh-${s}`]),
      '--fw-regular', '--fw-medium', '--fw-semibold', '--fw-bold',
      ...['0-5', '1', '2', '3', '4', '5', '6', '8', '10', '12'].map((s) => `--space-${s}`),
      '--radius-xs', '--radius-sm', '--radius', '--radius-lg', '--radius-pill',
      '--field-h', '--btn-h', '--btn-h-sm', '--btn-h-lg', '--row-h', '--cell-x', '--card-pad', '--stack-gap', '--section-gap',
      '--header-h', '--sidebar-w', '--drawer-w', '--content-max', '--page-x', '--page-top', '--page-x-phone',
      '--focus-w', '--focus-offset', '--dur', '--ease', '--z-sticky', '--z-header', '--z-popover', '--z-toast',
      '--bg', '--bg-sidebar', '--surface', '--surface-2', '--surface-3', '--surface-hover', '--surface-selected',
      '--border', '--border-strong', '--border-control', '--text', '--text-2', '--text-3', '--text-disabled', '--on-accent',
      '--accent', '--accent-hover', '--accent-solid', '--accent-solid-hover', '--accent-soft', '--accent-soft-border', '--accent-text',
      ...['ok', 'info', 'warn', 'error'].flatMap((s) => [`--${s}`, `--${s}-solid`, `--${s}-bg`, `--${s}-border`]),
      '--neutral', '--neutral-bg', '--neutral-border', '--running',
      '--focus', '--focus-ring', '--selection', '--shadow-xs', '--shadow-sm', '--shadow', '--shadow-lg', '--backdrop', '--header-bg'
    ];
    assert.deepEqual(names.filter((n) => !light.has(n)), [], 'missing in the light :root');
    // The renames of the first draft did not happen: their names are not tokens.
    for (const old of ['--focus-halo', '--shadow-1', '--shadow-2', '--shadow-3']) assert.ok(!light.has(old), old);
    assert.equal(light.get('--radius-lg'), '10px', 'cards and dialogs: 10 px');
    assert.equal(light.get('--btn-h'), '32px');
  });

  test('both dark blocks define the same tokens, and only tokens the light block has', () => {
    assert.deepEqual([...darkAuto.keys()].sort(), [...darkForced.keys()].sort());
    assert.deepEqual([...darkAuto].filter(([k, v]) => darkForced.get(k) !== v), [], 'same values');
    assert.deepEqual([...darkAuto.keys()].filter((k) => !light.has(k)), []);
    // A shadow list may start with --shadow-xs / --shadow-sm: in dark they are transparent shadows, never `none`.
    for (const k of ['--shadow-xs', '--shadow-sm']) assert.notEqual(darkAuto.get(k), 'none', k);
  });

  test('compact density and touch screens change sizes only; touch keeps 40 px targets in compact too', () => {
    assert.deepEqual([...compact.keys()].filter((k) => !/^--(field-h|btn-h|btn-h-sm|row-h|card-pad|stack-gap|section-gap|page-x)$/.test(k)), []);
    assert.match(style, /@media \(pointer: coarse\) \{\s*:root,\s*:root\[data-density="compact"\] \{\s*--field-h: 44px;\s*--btn-h: 40px;\s*--btn-h-sm: 36px;\s*--row-h: 44px;/);
  });

  test('every var() in the stylesheets names a custom property something defines', () => {
    const defined = new Set();
    const used = new Map();
    for (const file of sheets) {
      const css = stripComments(readFileSync(file, 'utf8'));
      for (const m of css.matchAll(/(--[\w-]+)\s*:/g)) defined.add(m[1]);
      for (const m of css.matchAll(/var\(\s*(--[\w-]+)\s*(,)?/g)) {
        if (m[2]) continue; // a fallback is there
        if (!used.has(m[1])) used.set(m[1], file.slice(ROOT.length + 1));
      }
    }
    // Set from the scripts through the CSSOM (SSL Targets' run bar height).
    for (const name of ['--scan-runbar-h']) defined.add(name);
    assert.deepEqual([...used].filter(([name]) => !defined.has(name)), []);
  });
});

/* ------------------------------------------------------------------------ */
/* Contrast (WCAG 2 formula)                                                */
/* ------------------------------------------------------------------------ */

const channel = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);

/** A token's colour as [r, g, b, a] (0–1); rgba() and #rrggbb only. */
function rgba(value) {
  const hex = /^#([0-9a-f]{6})$/i.exec(value);
  if (hex) return [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16) / 255).concat(1);
  const m = /^rgba?\(([^)]+)\)$/.exec(value);
  assert.ok(m, `a colour: ${value}`);
  const [r, g, b, a = '1'] = m[1].split(',').map((s) => s.trim());
  return [Number(r) / 255, Number(g) / 255, Number(b) / 255, Number(a)];
}

/** `fg` (maybe translucent) over the opaque `bg`. */
const over = (fg, bg) => fg.slice(0, 3).map((c, i) => c * fg[3] + bg[i] * (1 - fg[3])).concat(1);
const luminance = ([r, g, b]) => 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
const ratio = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

/** The tokens of a theme: the dark block over the light one. */
const theme = (dark) => (name) => {
  const value = (dark && darkAuto.has(name) ? darkAuto : light).get(name);
  assert.ok(value, `${name} defined`);
  return value;
};

/** Contrast of token `fg` on token `bg` (a translucent bg lies on `base`, the page background). */
function contrast(get, fg, bg, base = '--bg') {
  const ground = rgba(get(bg));
  const opaque = ground[3] < 1 ? over(ground, rgba(get(base))) : ground;
  const text = rgba(get(fg));
  return ratio(text[3] < 1 ? over(text, opaque) : text, opaque);
}

describe('contrast promised by docs/DESIGN.md §6.1', () => {
  for (const [name, dark] of [['light', false], ['dark', true]]) {
    const get = theme(dark);

    test(`${name}: every text role is ≥ 4.5:1 on the surfaces and the page; --text-3 on --surface-3 too`, () => {
      for (const fg of ['--text', '--text-2', '--text-3', '--accent-text', '--neutral']) {
        for (const bg of ['--surface', '--surface-2', '--bg', '--surface-3']) {
          assert.ok(contrast(get, fg, bg) >= 4.5, `${fg} on ${bg}: ${contrast(get, fg, bg).toFixed(2)}`);
        }
      }
      assert.ok(contrast(get, '--text-3', '--surface-selected', '--surface') >= 4.5, 'a selected nav link\'s muted text');
    });

    test(`${name}: a status colour on its own tint is ≥ 4.5:1`, () => {
      for (const s of ['ok', 'info', 'warn', 'error']) {
        assert.ok(contrast(get, `--${s}`, `--${s}-bg`, '--surface') >= 4.5, `${s}: ${contrast(get, `--${s}`, `--${s}-bg`, '--surface').toFixed(2)}`);
      }
    });

    test(`${name}: white button labels sit on fills of ≥ 4.5:1 (primary and danger, at rest and hovered)`, () => {
      for (const bg of ['--accent-solid', '--accent-solid-hover', '--danger-solid', '--danger-solid-hover']) {
        assert.ok(contrast(get, '--on-accent', bg) >= 4.5, `white on ${bg}: ${contrast(get, '--on-accent', bg).toFixed(2)}`);
      }
    });

    test(`${name}: --border-control is ≥ 3:1 on the page, the sidebar and the surfaces a control sits on (WCAG 1.4.11)`, () => {
      for (const bg of ['--bg', '--bg-sidebar', '--surface', '--surface-2']) {
        assert.ok(contrast(get, '--border-control', bg) >= 3, `on ${bg}: ${contrast(get, '--border-control', bg).toFixed(2)}`);
      }
    });
  }

  test('the stylesheets use the hover fill under white labels, not a literal colour', () => {
    assert.match(style, /\.btn-primary:hover:not\(:disabled\) \{\s*background: var\(--accent-solid-hover\);/);
    assert.doesNotMatch(style, /#3b78ea/i, 'the dark hover literal (4.15:1) is gone');
    assert.match(style, /\.btn-danger \{\s*background: var\(--danger-solid\);\s*color: var\(--on-accent\);/);
  });

  test('fields, segmented outlines and the switch\'s track have the control border', () => {
    assert.match(style, /\.input,\s*\.select,\s*\.textarea \{[^}]*border: 1px solid var\(--border-control\);/);
    assert.match(style, /\.segmented \{[^}]*border: 1px solid var\(--border-control\);/);
    assert.match(style, /\.switch-track \{[^}]*border: 1px solid var\(--border-control\);/);
    assert.match(style, /\.switch-thumb \{[^}]*box-shadow: 0 0 0 1px var\(--border-control\)/, 'the off thumb has a ring');
  });
});
