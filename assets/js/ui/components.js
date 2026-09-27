/**
 * components.js — the shared UI component library (vanilla DOM, no framework).
 *
 * Conventions
 * - Stateless components return an Element. Stateful ones return an object with an `el`
 *   Element plus methods; `h()` (ui/dom.js) accepts such objects as children directly.
 * - Every text argument is rendered as text (never HTML). Untrusted data is safe to pass.
 * - Labels come from i18n `t()`; components are rebuilt when a view re-mounts after a
 *   language change, so they do not need to listen for language changes themselves.
 * - Styling lives in assets/css/style.css (classes are listed per component below).
 *
 * Quick reference (see each JSDoc for all options)
 *
 *   import { h } from './dom.js';
 *   import * as C from './components.js';
 *
 *   // Icons & badges
 *   C.Icon('globe', { size: 16 });                         // inline SVG, aria-hidden
 *   C.Badge('NOERROR', { variant: 'ok', icon: 'check' });  // variants: neutral accent ok info warn error
 *                                                           //   + kinds cloudflare cdn platform direct private unresolved nxdomain dangling
 *   C.KindBadge(host.classification);                       // 'Cloudflare' / 'CDN · Fastly' / 'Dangling CNAME' + tooltip reason
 *   C.SeverityIcon('warn', { label: true });  C.SeverityBadge('error');
 *
 *   // Buttons & links
 *   C.Button({ label: t('common.run'), icon: 'play', variant: 'primary', onClick });
 *   C.IconButton({ icon: 'trash', label: t('common.delete'), onClick });
 *   C.CopyButton(() => names.join('\n'), { label: t('common.copy') });
 *   C.ExternalLink('https://crt.sh/?id=123', 'crt.sh');    // http(s) only, rel=noopener noreferrer
 *   C.ButtonLink({ href: 'cli/ssl_origin_scan.py', download: true, label: 'Download', icon: 'download' });
 *
 *   // Keyboard shortcuts: the shell (app.js) owns the keys; a view only marks its controls
 *   C.Button({ label: t('common.run'), dataset: { shortcut: 'submit' }, onClick: run });   // Ctrl/Cmd+Enter in a field near it
 *   C.Button({ label: t('common.stop'), dataset: { shortcut: 'cancel' }, onClick: stop }); // Esc while it is shown
 *   C.textInput({ label: 'Domain', attrs: { 'data-shortcut': 'focus' } });                 // where '/' jumps
 *   pasteBox.dataset.shortcutScope = 'paste';   // a sub-form: the submit inside answers its own fields only, Run the rest
 *   h('div', { class: 'x-results', dataset: { shortcutScope: 'results' } });   // no submit inside: a results filter runs nothing
 *
 *   // Layout
 *   C.Section({ title: 'Results', actions: [btn], children: [...] });
 *   C.Card({ title: 'Certificate', subtitle: 'leaf', children: [...] });
 *   C.StatCard({ label: 'Hosts', value: 42, hint: '3 behind Cloudflare', variant: 'accent' });
 *   C.KeyValueList([['Issuer', cert.issuerDN], { key: 'SHA-256', value: fp, mono: true, copy: true }]);
 *   C.CodeBlock('python3 ssl_origin_scan.py -t targets.txt', { label: 'Command' });
 *   C.CliText(t('about.st.ORIGIN_CERT'));                  // prose whose --options never wrap
 *   C.EmptyState({ icon: 'search', title: 'No results', message: '…', action: C.Button({...}) });
 *   C.Alert({ variant: 'warn', title: 'Heads up', message: '…' });  C.ErrorBanner(err, { onRetry });
 *   C.Spinner({ label: t('common.loading') });  C.TruncatedList(ips, { max: 3 });
 *
 *   // Stateful
 *   const tabs = C.Tabs([{ id: 'hosts', label: 'Hosts', badge: '12', content: () => hostsTable.el }, …]);
 *   const progress = C.ProgressBar({ label: 'Resolving' });  progress.set(10, 120);
 *   const table = C.DataTable({ columns, search: true, export: { filename: 'hosts' } });
 *   table.addRows([row]);  // streaming-friendly (batched per animation frame)
 *   const drop = C.FileDrop({ accept: '.pem,.crt,.cer,.der,.p7b', onFiles: (files) => … });
 *   C.toast(t('common.copied'), { type: 'success' });
 *   const ok = await C.confirmDialog({ title: '…', message: '…', danger: true });
 *   const choice = await C.Modal({ title, content, actions: [{ label, value: 'x', variant: 'primary' }] }).open();
 *
 *   // Form fields → { el, input, value, setError(msg), setHint(msg) }
 *   C.textInput({ label: 'Domain', placeholder: 'example.com', onEnter: run });
 *   C.textarea({ label: 'Hostnames', rows: 8 });
 *   C.select({ label: 'Type', options: ['A', 'AAAA'], value: 'A' });
 *   C.checkbox({ label: 'Include expired', checked: false });
 *   C.radioGroup({ legend: 'Brute force', name: 'bf', options: [{ value: 'off', label: 'Off' }, …], value: 'off' });
 *   C.checkboxGroup({ legend: 'Sources', name: 'src', options: [{ value: 'crtsh', label: 'crt.sh', hint: '…' }], values: ['crtsh'] });
 *   C.SegmentedControl({ label: 'Size', options: [{ value: 's', label: 'S' }, …], value: 's', onChange });
 */

import { h, svg, clear, uid, debounce, isNode } from './dom.js';
import {
  t, formatNumber, formatBytes, formatPercent, getLang, localeTag
} from '../i18n.js';
import { errorKind } from '../lib/util.js';
import { parseIP } from '../lib/netinfo.js';
import { downloadText, timestampedName, jsonReplacer } from './download.js';

/* ------------------------------------------------------------------------ */
/* Icons                                                                    */
/* ------------------------------------------------------------------------ */

// 24×24 stroke icons (drawn for this project). Each entry: list of [tag, attrs].
// `fill: 'currentColor'` marks small solid dots.
const DOT = (cx, cy, r = 1.1) => ['circle', { cx, cy, r, fill: 'currentColor', stroke: 'none' }];
const ICONS = {
  target: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 5 }], DOT(12, 12, 1.6)],
  shield: [['path', { d: 'M12 3l7.5 3v5.5c0 4.6-3.2 8.4-7.5 9.5-4.3-1.1-7.5-4.9-7.5-9.5V6z' }], ['path', { d: 'M8.8 12.2l2.2 2.2 4.3-4.4' }]],
  certificate: [['rect', { x: 3, y: 4, width: 18, height: 13, rx: 2 }], ['path', { d: 'M7 8.5h7M7 12h4' }], ['circle', { cx: 16.5, cy: 14.5, r: 2.5 }], ['path', { d: 'M15 16.6V21l1.5-1 1.5 1v-4.4' }]],
  globe: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M3 12h18' }], ['path', { d: 'M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z' }]],
  search: [['circle', { cx: 11, cy: 11, r: 7 }], ['path', { d: 'M20 20l-4-4' }]],
  list: [['path', { d: 'M9 6h11M9 12h11M9 18h11' }], DOT(4.5, 6, 1.3), DOT(4.5, 12, 1.3), DOT(4.5, 18, 1.3)],
  network: [['rect', { x: 9, y: 3, width: 6, height: 5, rx: 1 }], ['rect', { x: 3, y: 16, width: 6, height: 5, rx: 1 }], ['rect', { x: 15, y: 16, width: 6, height: 5, rx: 1 }], ['path', { d: 'M12 8v4M6 16v-2.5a1.5 1.5 0 0 1 1.5-1.5h9a1.5 1.5 0 0 1 1.5 1.5V16' }]],
  activity: [['path', { d: 'M3 12h4l3-7 4 14 3-7h4' }]],
  server: [['rect', { x: 3, y: 4, width: 18, height: 7, rx: 2 }], ['rect', { x: 3, y: 13, width: 18, height: 7, rx: 2 }], DOT(7, 7.5), DOT(7, 16.5), ['path', { d: 'M11 7.5h6M11 16.5h6' }]],
  info: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 11v5.5' }], DOT(12, 7.8)],
  code: [['path', { d: 'M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5M13.5 4.5l-3 15' }]],
  sun: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4' }]],
  moon: [['path', { d: 'M20 14.5A8 8 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z' }]],
  contrast: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 3a9 9 0 0 1 0 18z', fill: 'currentColor', stroke: 'none' }]],
  sliders: [['path', { d: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1' }], ['circle', { cx: 15, cy: 6, r: 2 }], ['circle', { cx: 9, cy: 12, r: 2 }], ['circle', { cx: 17, cy: 18, r: 2 }]],
  copy: [['rect', { x: 8.5, y: 8.5, width: 12, height: 12, rx: 2 }], ['path', { d: 'M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5' }]],
  check: [['path', { d: 'M5 12.5l4.5 4.5L19 7.5' }]],
  x: [['path', { d: 'M6 6l12 12M18 6L6 18' }]],
  alert: [['path', { d: 'M12 3.8L2.8 19.5h18.4z' }], ['path', { d: 'M12 10v4.5' }], DOT(12, 17)],
  'x-circle': [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M9 9l6 6M15 9l-6 6' }]],
  'check-circle': [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M8 12.5l2.7 2.7L16.2 9.6' }]],
  help: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M9.6 9.4a2.5 2.5 0 1 1 3.6 2.3c-.7.3-1.2 1-1.2 1.8v.5' }], DOT(12, 17)],
  'minus-circle': [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M8 12h8' }]],
  download: [['path', { d: 'M12 4v11M7 10.5l5 5 5-5M5 20h14' }]],
  upload: [['path', { d: 'M12 16V5M7 9.5l5-5 5 5M5 20h14' }]],
  file: [['path', { d: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z' }], ['path', { d: 'M14 3v5h5' }]],
  'file-text': [['path', { d: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z' }], ['path', { d: 'M14 3v5h5M9 13h6M9 17h6' }]],
  trash: [['path', { d: 'M4 7h16M9.5 7V4.5h5V7M6 7l1 13h10l1-13M10 11v5.5M14 11v5.5' }]],
  play: [['path', { d: 'M7.5 4.8v14.4L19 12z' }]],
  stop: [['rect', { x: 6, y: 6, width: 12, height: 12, rx: 1.5 }]],
  refresh: [['path', { d: 'M20 11.5A8 8 0 0 0 5.7 6.6L4 8.5M4 4v4.5h4.5M4 12.5a8 8 0 0 0 14.3 4.9L20 15.5M20 20v-4.5h-4.5' }]],
  link: [['path', { d: 'M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1' }], ['path', { d: 'M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1' }]],
  unlink: [['path', { d: 'M18.8 13.2l1.4-1.4a4.2 4.2 0 0 0-6-6l-1.4 1.4M5.2 10.8l-1.4 1.4a4.2 4.2 0 0 0 6 6l1.4-1.4M8 3.5v2.5M3.5 8H6M16 20.5V18M20.5 16H18' }]],
  external: [['path', { d: 'M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5' }]],
  'chevron-down': [['path', { d: 'M6 9l6 6 6-6' }]],
  'chevron-up': [['path', { d: 'M6 15l6-6 6 6' }]],
  'chevron-right': [['path', { d: 'M9 6l6 6-6 6' }]],
  'chevron-left': [['path', { d: 'M15 6l-6 6 6 6' }]],
  'arrow-up': [['path', { d: 'M12 19V5M6 11l6-6 6 6' }]],
  'arrow-down': [['path', { d: 'M12 5v14M6 13l6 6 6-6' }]],
  'arrow-right': [['path', { d: 'M5 12h14M13 6l6 6-6 6' }]],
  swap: [['path', { d: 'M4 8h14M14.5 4.5L18 8l-3.5 3.5' }], ['path', { d: 'M20 16H6M9.5 12.5L6 16l3.5 3.5' }]],
  sort: [['path', { d: 'M8 9.5l4-4 4 4M8 14.5l4 4 4-4' }]],
  filter: [['path', { d: 'M4 5h16l-6.2 7.6V19l-3.6 1.8v-8.2z' }]],
  cloud: [['path', { d: 'M7 18.5h10.5a4.5 4.5 0 0 0 .6-8.96A6 6 0 0 0 6.4 10.6 4 4 0 0 0 7 18.5z' }]],
  lock: [['rect', { x: 5, y: 11, width: 14, height: 10, rx: 2 }], ['path', { d: 'M8 11V7.5a4 4 0 0 1 8 0V11' }]],
  unlock: [['rect', { x: 5, y: 11, width: 14, height: 10, rx: 2 }], ['path', { d: 'M8 11V7.5a4 4 0 0 1 7.7-1.5' }]],
  key: [['circle', { cx: 8, cy: 15, r: 4 }], ['path', { d: 'M11 12l8.5-8.5M16 7l3 3M13.5 9.5l2 2' }]],
  clock: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3.2 2' }]],
  calendar: [['rect', { x: 3.5, y: 5, width: 17, height: 15.5, rx: 2 }], ['path', { d: 'M16 3v4M8 3v4M3.5 10h17' }]],
  zap: [['path', { d: 'M13 2.5L4.5 13.5H11l-1 8 8.5-11H12z' }]],
  box: [['path', { d: 'M12 3l8 4.5v9L12 21l-8-4.5v-9z' }], ['path', { d: 'M4 7.5l8 4.5 8-4.5M12 12v9' }]],
  terminal: [['rect', { x: 3, y: 4, width: 18, height: 16, rx: 2 }], ['path', { d: 'M7 9l3 3-3 3M12.5 15H17' }]],
  book: [['path', { d: 'M3 5h6a3 3 0 0 1 3 3v12a2.2 2.2 0 0 0-2.2-2H3z' }], ['path', { d: 'M21 5h-6a3 3 0 0 0-3 3v12a2.2 2.2 0 0 1 2.2-2H21z' }]],
  share: [['circle', { cx: 18, cy: 5.5, r: 2.5 }], ['circle', { cx: 6, cy: 12, r: 2.5 }], ['circle', { cx: 18, cy: 18.5, r: 2.5 }], ['path', { d: 'M8.2 10.8l7.6-4.1M8.2 13.2l7.6 4.1' }]],
  plus: [['path', { d: 'M12 5v14M5 12h14' }]],
  minus: [['path', { d: 'M5 12h14' }]],
  eye: [['path', { d: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  hash: [['path', { d: 'M5 9h14M5 15h14M10.5 4l-2 16M15.5 4l-2 16' }]],
  mail: [['rect', { x: 3, y: 5, width: 18, height: 14, rx: 2 }], ['path', { d: 'M3.5 7l8.5 6 8.5-6' }]],
  database: [['ellipse', { cx: 12, cy: 6, rx: 8, ry: 3 }], ['path', { d: 'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3' }]],
  inbox: [['path', { d: 'M3 13l3-8h12l3 8v6H3z' }], ['path', { d: 'M3 13h5l1.5 2.5h5L16 13h5' }]],
  menu: [['path', { d: 'M4 6h16M4 12h16M4 18h16' }]],
  'map-pin': [['path', { d: 'M12 21s-7-6.2-7-11.5a7 7 0 0 1 14 0C19 14.8 12 21 12 21z' }], ['circle', { cx: 12, cy: 9.5, r: 2.5 }]],
  lightbulb: [['path', { d: 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.6 10.8c.7.5 1.1 1.2 1.1 2V16h5v-.2c0-.8.4-1.5 1.1-2A6 6 0 0 0 12 3z' }]],
  layers: [['path', { d: 'M12 3l9 5-9 5-9-5z' }], ['path', { d: 'M3 13l9 5 9-5' }]],
  'git-branch': [['circle', { cx: 6, cy: 5.5, r: 2.5 }], ['circle', { cx: 6, cy: 18.5, r: 2.5 }], ['circle', { cx: 18, cy: 7.5, r: 2.5 }], ['path', { d: 'M6 8v8M18 10c0 4-4 4.5-12 6' }]],
  users: [['circle', { cx: 9, cy: 8, r: 3.5 }], ['path', { d: 'M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18.5 14.2A6.5 6.5 0 0 1 21.5 20' }]]
};

/** Names of every built-in icon (for docs/tests). */
export const ICON_NAMES = Object.freeze(Object.keys(ICONS));

/**
 * Inline SVG icon (currentColor stroke). Decorative (aria-hidden) unless `title` is given.
 * Unknown names render the 'help' glyph.
 * @param {string} name one of {@link ICON_NAMES}
 * @param {{ size?: number, title?: string, className?: string, strokeWidth?: number }} [opts]
 * @returns {SVGSVGElement}
 */
export function Icon(name, { size = 16, title = '', className = '', strokeWidth = 1.9 } = {}) {
  const parts = ICONS[name] || ICONS.help;
  const el = svg('svg', {
    class: ['icon', `icon-${ICONS[name] ? name : 'help'}`, className],
    attrs: {
      viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor',
      'stroke-width': strokeWidth, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', focusable: 'false'
    }
  }, parts.map(([tag, attrs]) => svg(tag, { attrs })));
  if (title) {
    el.setAttribute('role', 'img');
    el.setAttribute('aria-label', title);
    el.prepend(svg('title', null, title));
  } else {
    el.setAttribute('aria-hidden', 'true');
  }
  return el;
}

/* ------------------------------------------------------------------------ */
/* Live region (screen-reader announcements)                                */
/* ------------------------------------------------------------------------ */

let liveRegions = null;

/**
 * Announce a message to screen readers (polite by default).
 * @param {string} message
 * @param {{ assertive?: boolean }} [opts]
 */
export function announce(message, { assertive = false } = {}) {
  const doc = globalThis.document;
  if (!doc || !doc.body) return;
  if (!liveRegions || !liveRegions.polite.isConnected) {
    liveRegions = {
      polite: h('div', { class: 'sr-only', attrs: { 'aria-live': 'polite', 'aria-atomic': 'true' } }),
      assertive: h('div', { class: 'sr-only', attrs: { 'aria-live': 'assertive', 'aria-atomic': 'true' } })
    };
    doc.body.append(liveRegions.polite, liveRegions.assertive);
  }
  const region = assertive ? liveRegions.assertive : liveRegions.polite;
  region.textContent = '';
  // A new text node on the next frame is reliably announced even for repeated messages.
  setTimeout(() => {
    region.textContent = String(message ?? '');
  }, 60);
}

/* ------------------------------------------------------------------------ */
/* Badges & status                                                          */
/* ------------------------------------------------------------------------ */

const BADGE_VARIANTS = new Set(['neutral', 'accent', 'ok', 'info', 'warn', 'error',
  'cloudflare', 'cdn', 'platform', 'direct', 'private', 'unresolved', 'nxdomain', 'dangling']);

/**
 * Small pill label. Classes: .badge .badge-<variant>.
 * @param {string|number} text
 * @param {{ variant?: string, icon?: string, title?: string, className?: string, mono?: boolean }} [opts]
 * @returns {HTMLSpanElement}
 */
export function Badge(text, { variant = 'neutral', icon = null, title = null, className = '', mono = false } = {}) {
  const v = BADGE_VARIANTS.has(variant) ? variant : 'neutral';
  return h('span', { class: ['badge', `badge-${v}`, { mono }, className], title: title || null },
    icon ? Icon(icon, { size: 12, strokeWidth: 2.2 }) : null,
    h('span', { class: 'badge-text' }, text));
}

const KIND_ICONS = {
  cloudflare: 'cloud', cdn: 'zap', platform: 'box', direct: 'server', private: 'lock',
  unresolved: 'help', nxdomain: 'x-circle', dangling: 'unlink'
};

/** Kinds understood by {@link KindBadge} (classification kinds + 'dangling'). */
export const KINDS = Object.freeze(Object.keys(KIND_ICONS));

/**
 * Classification badge for a host (lib/netinfo.classifyResolution result or a kind string).
 * Shows 'Cloudflare', 'CDN · Fastly', 'Platform · Vercel', 'Direct', 'Private IP',
 * 'Unresolved', 'NXDOMAIN' or 'Dangling CNAME' (dangling wins over the kind); the tooltip is
 * the translated reason (`classification.reasonKey`).
 * @param {string|{ kind: string, provider?: { name: string }|null, dangling?: boolean, reasonKey?: string }} input
 * @param {{ provider?: { name: string }|null, showProvider?: boolean, title?: string }} [opts]
 * @returns {HTMLSpanElement}
 */
export function KindBadge(input, { provider = undefined, showProvider = true, title = undefined } = {}) {
  const info = typeof input === 'string' ? { kind: input } : (input || {});
  const kind = info.dangling ? 'dangling' : (KIND_ICONS[info.kind] ? info.kind : 'unresolved');
  const prov = provider !== undefined ? provider : info.provider || null;
  let label = t(`kind.${kind}`);
  if (showProvider && prov && prov.name && kind !== 'cloudflare') label = `${label} · ${prov.name}`;
  const tip = title !== undefined ? title
    : (info.reasonKey ? t(info.reasonKey, { provider: prov && prov.name ? prov.name : t('common.unknown') }) : null);
  const el = Badge(label, { variant: kind, icon: KIND_ICONS[kind], title: tip });
  el.dataset.kind = kind;
  return el;
}

const SEVERITY_ICONS = { ok: 'check-circle', info: 'info', warn: 'alert', error: 'x-circle' };

/**
 * Severity glyph (colored icon + text label, visible or screen-reader-only).
 * Classes: .sev .sev-<severity>.
 * @param {'ok'|'info'|'warn'|'error'} severity
 * @param {{ label?: boolean|string, size?: number }} [opts] label=true shows t('severity.x'); a string overrides it
 * @returns {HTMLSpanElement}
 */
export function SeverityIcon(severity, { label = false, size = 16 } = {}) {
  const sev = SEVERITY_ICONS[severity] ? severity : 'info';
  const text = typeof label === 'string' ? label : t(`severity.${sev}`);
  return h('span', { class: ['sev', `sev-${sev}`], dataset: { severity: sev } },
    Icon(SEVERITY_ICONS[sev], { size }),
    label ? h('span', { class: 'sev-label' }, text) : h('span', { class: 'sr-only' }, text));
}

/**
 * Severity as a badge ('OK', 'Warning', …) with icon.
 * @param {'ok'|'info'|'warn'|'error'} severity
 * @param {string} [text] defaults to t('severity.<severity>')
 * @returns {HTMLSpanElement}
 */
export function SeverityBadge(severity, text) {
  const sev = SEVERITY_ICONS[severity] ? severity : 'info';
  return Badge(text ?? t(`severity.${sev}`), { variant: sev, icon: SEVERITY_ICONS[sev] });
}

/* ------------------------------------------------------------------------ */
/* Buttons & links                                                          */
/* ------------------------------------------------------------------------ */

/**
 * Button. Classes: .btn .btn-<variant> (.btn-sm/.btn-lg).
 * @param {{ label?: string, icon?: string, iconRight?: string, variant?: 'primary'|'secondary'|'ghost'|'danger',
 *   size?: 'sm'|'md'|'lg', onClick?: (e: MouseEvent) => void, type?: string, disabled?: boolean,
 *   title?: string, ariaLabel?: string, className?: string, attrs?: object, dataset?: object }} opts
 * @returns {HTMLButtonElement}
 */
export function Button({
  label = '', icon = null, iconRight = null, variant = 'secondary', size = 'md', onClick = null,
  type = 'button', disabled = false, title = null, ariaLabel = null, className = '', attrs = {}, dataset = {}
} = {}) {
  return h('button', {
    type,
    class: ['btn', `btn-${variant}`, size !== 'md' ? `btn-${size}` : null, { 'btn-icon-only': !label && !!icon }, className],
    disabled,
    title,
    attrs: { 'aria-label': ariaLabel, ...attrs },
    dataset,
    on: onClick ? { click: onClick } : null
  },
  icon ? Icon(icon, { size: size === 'sm' ? 14 : 16 }) : null,
  label ? h('span', { class: 'btn-label' }, label) : null,
  iconRight ? Icon(iconRight, { size: size === 'sm' ? 14 : 16 }) : null);
}

/**
 * Square icon-only button with an accessible label (also used as tooltip).
 * @param {{ icon: string, label: string, onClick?: Function, variant?: string, size?: 'sm'|'md', pressed?: boolean|null,
 *   className?: string, disabled?: boolean }} opts
 * @returns {HTMLButtonElement}
 */
export function IconButton({ icon, label, onClick = null, variant = 'ghost', size = 'md', pressed = null, className = '', disabled = false }) {
  const btn = Button({ icon, variant, size, onClick, title: label, ariaLabel: label, className: ['btn-icon', className].join(' '), disabled });
  if (pressed !== null) btn.setAttribute('aria-pressed', String(!!pressed));
  return btn;
}

/**
 * Put a button into a busy state (spinner, disabled, aria-busy) or restore it.
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 */
export function setButtonBusy(button, busy) {
  if (!button) return;
  button.disabled = !!busy;
  button.classList.toggle('is-busy', !!busy);
  if (busy) {
    button.setAttribute('aria-busy', 'true');
    if (!button.querySelector('.spinner')) button.prepend(h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }));
  } else {
    button.removeAttribute('aria-busy');
    button.querySelectorAll('.spinner').forEach((s) => s.remove());
  }
}

/**
 * Anchor styled as a button (e.g. file downloads). Only safe URLs are accepted (dom.js).
 * @param {{ href: string, label: string, icon?: string, variant?: string, size?: string, download?: boolean|string,
 *   external?: boolean, title?: string }} opts
 * @returns {HTMLAnchorElement}
 */
export function ButtonLink({ href, label, icon = null, variant = 'secondary', size = 'md', download = false, external = false, title = null }) {
  return h('a', {
    href,
    class: ['btn', `btn-${variant}`, size !== 'md' ? `btn-${size}` : null],
    title,
    attrs: {
      download: download === true ? '' : (download || null),
      target: external ? '_blank' : null,
      rel: external ? 'noopener noreferrer' : null
    }
  }, icon ? Icon(icon, { size: size === 'sm' ? 14 : 16 }) : null, h('span', { class: 'btn-label' }, label),
  external ? h('span', { class: 'sr-only' }, ` ${t('common.newTab')}`) : null);
}

/**
 * External link opening in a new tab with rel="noopener noreferrer". Non-http(s) URLs
 * (e.g. from untrusted RDAP data) render as plain text instead of a link.
 * @param {string} href
 * @param {string} [text] defaults to the URL
 * @param {{ icon?: boolean, className?: string, title?: string }} [opts]
 * @returns {HTMLAnchorElement|HTMLSpanElement}
 */
export function ExternalLink(href, text, { icon = true, className = '', title = null } = {}) {
  const label = text ?? href;
  let ok = false;
  try {
    const u = new URL(String(href));
    ok = u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    ok = false;
  }
  if (!ok) return h('span', { class: ['ext-link-invalid', className], title }, label);
  return h('a', {
    href: String(href),
    class: ['ext-link', className],
    title,
    attrs: { target: '_blank', rel: 'noopener noreferrer' }
  }, label, icon ? Icon('external', { size: 12, className: 'ext-link-icon' }) : null,
  h('span', { class: 'sr-only' }, ` ${t('common.newTab')}`));
}

/**
 * Copy text to the clipboard (async Clipboard API, falling back to execCommand).
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyText(text) {
  const value = String(text ?? '');
  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await globalThis.navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // fall through to the legacy path (e.g. permissions policy, insecure context)
  }
  const doc = globalThis.document;
  if (!doc) return false;
  const ta = h('textarea', { class: 'clipboard-proxy', value, attrs: { readonly: true, 'aria-hidden': 'true', tabindex: -1 } });
  doc.body.append(ta);
  const prevFocus = doc.activeElement;
  ta.select();
  let ok = false;
  try {
    ok = doc.execCommand('copy');
  } catch {
    ok = false;
  }
  ta.remove();
  if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus({ preventScroll: true });
  return ok;
}

/**
 * Copy button with "Copied" feedback (icon swap + screen-reader announcement).
 * @param {string|(() => string)} value text or a function producing it at click time
 * @param {{ label?: string, iconOnly?: boolean, size?: 'sm'|'md', variant?: string, title?: string,
 *   toastOnCopy?: boolean|string, onFail?: (text: string) => void, className?: string }} [opts]
 *   `toastOnCopy`: true toasts "Copied", a string toasts that text; `onFail` replaces the
 *   "could not copy" toast (e.g. with the text in a dialog to copy by hand)
 * @returns {HTMLButtonElement}
 */
export function CopyButton(value, {
  label = null, iconOnly = false, size = 'sm', variant = 'ghost', title = null, toastOnCopy = false, onFail = null, className = ''
} = {}) {
  const text = label ?? t('common.copy');
  const btn = Button({
    label: iconOnly ? '' : text,
    icon: 'copy',
    variant,
    size,
    title: title ?? text,
    ariaLabel: iconOnly ? (title ?? text) : null,
    className: ['copy-btn', className].join(' ')
  });
  let timer = null;
  btn.addEventListener('click', async (event) => {
    event.stopPropagation();
    const str = typeof value === 'function' ? value() : value;
    const ok = await copyText(str);
    const icon = btn.querySelector('.icon');
    if (icon) icon.replaceWith(Icon(ok ? 'check' : 'x', { size: size === 'sm' ? 14 : 16 }));
    btn.classList.toggle('is-copied', ok);
    const labelEl = btn.querySelector('.btn-label');
    if (labelEl) labelEl.textContent = ok ? t('common.copied') : text;
    if (ok) announce(t('common.copied'));
    if (!ok && typeof onFail === 'function') onFail(String(str ?? ''));
    else if (!ok) toast(t('common.copyFailed'), { type: 'error' });
    else if (toastOnCopy) toast(typeof toastOnCopy === 'string' ? toastOnCopy : t('common.copied'), { type: 'success', timeout: 2000 });
    clearTimeout(timer);
    timer = setTimeout(() => {
      const cur = btn.querySelector('.icon');
      if (cur) cur.replaceWith(Icon('copy', { size: size === 'sm' ? 14 : 16 }));
      btn.classList.remove('is-copied');
      if (labelEl) labelEl.textContent = text;
    }, 1600);
  });
  return btn;
}

/* ------------------------------------------------------------------------ */
/* Feedback: spinner, progress, alerts, empty states                        */
/* ------------------------------------------------------------------------ */

/**
 * Loading spinner with an accessible label.
 * @param {{ size?: 'sm'|'md'|'lg', label?: string, showLabel?: boolean }} [opts]
 * @returns {HTMLSpanElement}
 */
export function Spinner({ size = 'md', label = null, showLabel = false } = {}) {
  const text = label ?? t('common.loading');
  return h('span', { class: ['spinner-wrap', `spinner-${size}`], attrs: { role: 'status' } },
    h('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } }),
    showLabel ? h('span', { class: 'spinner-label' }, text) : h('span', { class: 'sr-only' }, text));
}

/**
 * Progress bar (determinate or indeterminate) with a label, a "done / total · %" readout
 * and throttled screen-reader announcements.
 * @param {{ label?: string, value?: number, max?: number, indeterminate?: boolean, showCount?: boolean,
 *   format?: (value: number, max: number) => string }} [opts]
 * @returns {{ el: HTMLElement, set(value: number, max?: number): void, setLabel(text: string): void,
 *   setIndeterminate(on: boolean): void, setVariant(v: 'default'|'ok'|'warn'|'error'): void, done(label?: string): void }}
 */
export function ProgressBar({ label = '', value = 0, max = 100, indeterminate = false, showCount = true, format = null } = {}) {
  const labelEl = h('span', { class: 'progress-label' }, label);
  const valueEl = h('span', { class: 'progress-value num' });
  const fill = h('div', { class: 'progress-fill' });
  const track = h('div', {
    class: 'progress-track',
    attrs: { role: 'progressbar', 'aria-valuemin': 0, 'aria-label': label || t('progress.label') }
  }, fill);
  const live = h('div', { class: 'sr-only', attrs: { 'aria-live': 'polite', 'aria-atomic': 'true' } });
  const el = h('div', { class: 'progress' }, h('div', { class: 'progress-head' }, labelEl, valueEl), track, live);
  let cur = { value, max, indeterminate };
  let lastAnnounced = -1;

  function render() {
    el.classList.toggle('is-indeterminate', cur.indeterminate);
    if (cur.indeterminate) {
      track.removeAttribute('aria-valuenow');
      track.removeAttribute('aria-valuemax');
      fill.style.removeProperty('width');
      valueEl.textContent = '';
      return;
    }
    const m = Math.max(0, Number(cur.max) || 0);
    const v = Math.min(m, Math.max(0, Number(cur.value) || 0));
    const ratio = m > 0 ? v / m : 0;
    fill.style.width = `${(ratio * 100).toFixed(2)}%`;
    track.setAttribute('aria-valuemax', String(m));
    track.setAttribute('aria-valuenow', String(v));
    valueEl.textContent = format ? format(v, m)
      : (showCount ? `${t('progress.count', { done: formatNumber(v), total: formatNumber(m) })} · ${formatPercent(ratio)}` : formatPercent(ratio));
    // Announce at most every 25 % so screen readers are not flooded.
    const bucket = Math.floor(ratio * 4);
    if (bucket !== lastAnnounced) {
      lastAnnounced = bucket;
      live.textContent = `${labelEl.textContent} ${formatPercent(ratio)}`;
    }
  }
  render();
  const api = {
    el,
    set(v, m = cur.max) {
      cur = { ...cur, value: v, max: m, indeterminate: false };
      render();
    },
    setLabel(text) {
      labelEl.textContent = text;
      track.setAttribute('aria-label', text || t('progress.label'));
    },
    setIndeterminate(on) {
      cur = { ...cur, indeterminate: !!on };
      render();
    },
    setVariant(v) {
      el.classList.remove('is-ok', 'is-warn', 'is-error');
      if (v && v !== 'default') el.classList.add(`is-${v}`);
    },
    done(text) {
      cur = { ...cur, value: cur.max || 1, max: cur.max || 1, indeterminate: false };
      if (text) api.setLabel(text);
      render();
      live.textContent = text || t('common.done');
    }
  };
  return api;
}

const ALERT_ICONS = { info: 'info', ok: 'check-circle', success: 'check-circle', warn: 'alert', error: 'x-circle' };

/**
 * Inline callout. Classes: .alert .alert-<variant>. Errors/warnings use role=alert.
 * @param {{ variant?: 'info'|'ok'|'warn'|'error', title?: string, message?: string|Node, children?: any,
 *   actions?: Node[], icon?: string|null, dismissible?: boolean, onDismiss?: Function, compact?: boolean }} opts
 * @returns {HTMLDivElement}
 */
export function Alert({ variant = 'info', title = null, message = null, children = null, actions = null, icon = undefined,
  dismissible = false, onDismiss = null, compact = false } = {}) {
  const v = ALERT_ICONS[variant] ? (variant === 'success' ? 'ok' : variant) : 'info';
  const el = h('div', {
    class: ['alert', `alert-${v}`, { 'alert-compact': compact }],
    attrs: { role: v === 'error' || v === 'warn' ? 'alert' : 'status' }
  },
  icon === null ? null : Icon(icon || ALERT_ICONS[v], { size: 18, className: 'alert-icon' }),
  h('div', { class: 'alert-body' },
    title ? h('div', { class: 'alert-title' }, title) : null,
    message !== null && message !== undefined ? h('div', { class: 'alert-message' }, message) : null,
    children,
    actions && actions.length ? h('div', { class: 'alert-actions' }, actions) : null),
  dismissible ? IconButton({
    icon: 'x', label: t('common.close'), size: 'sm',
    onClick: () => {
      el.remove();
      if (onDismiss) onDismiss();
    }
  }) : null);
  return el;
}

/**
 * Friendly description of an error: translated kind message + technical detail.
 * @param {unknown} err
 * @returns {{ kind: string, message: string, detail: string }}
 */
export function describeError(err) {
  if (typeof err === 'string') return { kind: 'unknown', message: err, detail: '' };
  const kind = errorKind(err);
  const message = t(`error.kind.${kind}`);
  const parts = [];
  if (err && typeof err === 'object') {
    if (err.name && err.name !== 'Error') parts.push(err.name);
    if (err.status) parts.push(`HTTP ${err.status}${err.statusText ? ` ${err.statusText}` : ''}`);
    if (err.message && !/^HTTP \d+/.test(err.message)) parts.push(err.message);
    if (err.url) parts.push(err.url);
  } else if (err !== undefined && err !== null) {
    parts.push(String(err));
  }
  return { kind, message, detail: parts.join(' · ') };
}

/**
 * Error callout for a caught error (or message string): translated summary, collapsible
 * technical details and an optional retry button.
 * @param {unknown} error Error object or message
 * @param {{ title?: string, onRetry?: Function, variant?: 'error'|'warn', details?: boolean, compact?: boolean }} [opts]
 * @returns {HTMLDivElement}
 */
export function ErrorBanner(error, { title = null, onRetry = null, variant = 'error', details = true, compact = false } = {}) {
  const info = describeError(error);
  return Alert({
    variant,
    compact,
    title: title ?? t('error.title'),
    message: info.message,
    children: details && info.detail && info.detail !== info.message
      ? h('details', { class: 'alert-details' }, h('summary', null, t('error.details')), h('code', { class: 'mono' }, info.detail))
      : null,
    actions: onRetry ? [Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', onClick: onRetry })] : null
  });
}

/**
 * Empty / zero-data placeholder.
 * @param {{ icon?: string, title?: string, message?: string|Node, action?: Node|Node[], compact?: boolean }} [opts]
 * @returns {HTMLDivElement}
 */
export function EmptyState({ icon = 'inbox', title = null, message = null, action = null, compact = false } = {}) {
  return h('div', { class: ['empty', { 'empty-compact': compact }] },
    icon ? h('div', { class: 'empty-icon' }, Icon(icon, { size: compact ? 20 : 26 })) : null,
    title ? h('div', { class: 'empty-title' }, title) : null,
    message ? h('div', { class: 'empty-message' }, message) : null,
    action ? h('div', { class: 'empty-action' }, action) : null);
}

/* ------------------------------------------------------------------------ */
/* Layout                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Titled page section. Classes: .section, .section-head, .section-body.
 * @param {{ title?: string, description?: string|Node, actions?: Node|Node[], id?: string, level?: 2|3|4,
 *   children?: any, className?: string }} opts
 * @returns {HTMLElement}
 */
export function Section({ title = null, description = null, actions = null, id = null, level = 2, children = null, className = '' } = {}) {
  const headingId = title ? uid('section') : null;
  return h('section', { class: ['section', className], id, attrs: { 'aria-labelledby': headingId } },
    title || actions ? h('div', { class: 'section-head' },
      h('div', { class: 'section-titles' },
        title ? h(`h${level}`, { class: 'section-title', id: headingId }, title) : null,
        description ? h('p', { class: 'section-desc' }, description) : null),
      actions ? h('div', { class: 'section-actions' }, actions) : null) : null,
    h('div', { class: 'section-body' }, children));
}

/**
 * Card container. Classes: .card, .card-head, .card-body, .card-foot.
 * @param {{ title?: string|Node, subtitle?: string|Node, icon?: string, actions?: Node|Node[], children?: any,
 *   footer?: any, padded?: boolean, className?: string, level?: 2|3|4, id?: string }} opts
 * @returns {HTMLDivElement}
 */
export function Card({ title = null, subtitle = null, icon = null, actions = null, children = null, footer = null,
  padded = true, className = '', level = 3, id = null } = {}) {
  return h('div', { class: ['card', className], id },
    title || actions ? h('div', { class: 'card-head' },
      icon ? h('span', { class: 'card-icon' }, Icon(icon, { size: 16 })) : null,
      h('div', { class: 'card-titles' },
        title ? h(`h${level}`, { class: 'card-title' }, title) : null,
        subtitle ? h('div', { class: 'card-subtitle' }, subtitle) : null),
      actions ? h('div', { class: 'card-actions' }, actions) : null) : null,
    h('div', { class: ['card-body', { 'card-body-flush': !padded }] }, children),
    footer ? h('div', { class: 'card-foot' }, footer) : null);
}

/**
 * Metric tile. Pass onClick to make it a button (e.g. click "Cloudflare 12" to filter).
 * @param {{ label: string, value?: string|number, hint?: string|Node, icon?: string, variant?: string,
 *   onClick?: Function, pressed?: boolean }} opts
 * @returns {{ el: HTMLElement, set(patch: { value?, hint?, variant?, label?, pressed? }): void }}
 */
export function StatCard({ label, value = '—', hint = null, icon = null, variant = 'default', onClick = null, pressed = null }) {
  const valueEl = h('div', { class: 'stat-value num' });
  const hintEl = h('div', { class: 'stat-hint' });
  const labelEl = h('div', { class: 'stat-label' }, label);
  const el = h(onClick ? 'button' : 'div', {
    class: ['stat', { 'stat-button': !!onClick }],
    type: onClick ? 'button' : null,
    on: onClick ? { click: onClick } : null
  },
  h('div', { class: 'stat-top' }, icon ? h('span', { class: 'stat-icon' }, Icon(icon, { size: 15 })) : null, labelEl),
  valueEl, hintEl);
  const api = {
    el,
    set({ value: v, hint: hi, variant: va, label: la, pressed: pr } = {}) {
      if (v !== undefined) valueEl.textContent = typeof v === 'number' ? formatNumber(v) : String(v ?? '—');
      if (hi !== undefined) {
        clear(hintEl);
        if (hi !== null) hintEl.append(isNode(hi) ? hi : String(hi));
        hintEl.hidden = hi === null || hi === '';
      }
      if (va !== undefined) {
        [...el.classList].filter((c) => c.startsWith('stat-v-')).forEach((c) => el.classList.remove(c));
        if (va && va !== 'default') el.classList.add(`stat-v-${va}`);
      }
      if (la !== undefined) labelEl.textContent = la;
      if (pr !== undefined && onClick) el.setAttribute('aria-pressed', String(!!pr));
    }
  };
  api.set({ value, hint, variant, pressed: pressed === null ? undefined : pressed });
  return api;
}

function kvItems(items) {
  if (Array.isArray(items)) {
    return items.filter(Boolean).map((it) => (Array.isArray(it) ? { key: it[0], value: it[1] } : it));
  }
  return Object.entries(items || {}).map(([key, value]) => ({ key, value }));
}

/**
 * Definition list of label → value pairs. Values may be Nodes; null/undefined/'' render '—'.
 * Classes: .kv (.kv-cols-2 for two columns on wide screens).
 * @param {Array<[string, any]|{ key: string, value: any, mono?: boolean, copy?: boolean|string, hint?: string }>|object} items
 * @param {{ columns?: 1|2, className?: string }} [opts]
 * @returns {HTMLDListElement}
 */
export function KeyValueList(items, { columns = 1, className = '' } = {}) {
  return h('dl', { class: ['kv', { 'kv-cols-2': columns === 2 }, className] },
    kvItems(items).map(({ key, value, mono = false, copy = false, hint = null }) => {
      const empty = value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length);
      const shown = empty ? h('span', { class: 'muted' }, '—')
        : (Array.isArray(value) ? value.map((v) => h('div', null, v)) : value);
      const copyValue = typeof copy === 'string' ? copy : (typeof value === 'string' || typeof value === 'number' ? String(value) : null);
      return h('div', { class: 'kv-row' },
        h('dt', { class: 'kv-key' }, key, hint ? h('span', { class: 'kv-hint' }, hint) : null),
        h('dd', { class: ['kv-value', { mono }] }, h('span', { class: 'kv-value-text' }, shown),
          copy && !empty && copyValue !== null ? CopyButton(copyValue, { iconOnly: true, size: 'sm' }) : null));
    }));
}

/**
 * Prose that names CLI options (`--strict-public`, `--private-ca`): each option becomes an
 * unbreakable `<code class="nowrap">`, so a narrow screen never splits it at a hyphen.
 * @param {string} text
 * @returns {HTMLSpanElement}
 */
export function CliText(text) {
  const parts = String(text ?? '').split(/(--[a-z][a-z0-9-]*)/);
  return h('span', null, parts.map((part, i) => (i % 2 ? h('code', { class: 'nowrap' }, part) : part)).filter((p) => p !== ''));
}

/**
 * Preformatted text (commands, raw records, PEM) with an optional copy button.
 * Classes: .codeblock (.codeblock-wrap to soft-wrap long lines).
 * @param {string} text
 * @param {{ label?: string, copy?: boolean, wrap?: boolean, maxHeight?: string, className?: string }} [opts]
 * @returns {HTMLDivElement}
 */
export function CodeBlock(text, { label = null, copy = true, wrap = false, maxHeight = null, className = '' } = {}) {
  const pre = h('pre', { class: 'codeblock-pre', attrs: { tabindex: 0 } }, h('code', null, String(text ?? '')));
  if (maxHeight) pre.style.maxHeight = maxHeight;
  return h('div', { class: ['codeblock', { 'codeblock-wrap': wrap }, className] },
    label || copy ? h('div', { class: 'codeblock-head' },
      label ? h('span', { class: 'codeblock-label' }, label) : h('span'),
      copy ? CopyButton(() => String(text ?? ''), { size: 'sm' }) : null) : null,
    pre);
}

/**
 * First `max` items, then a "+N more" toggle to reveal the rest (for IP/SAN lists in cells).
 * @param {any[]} items
 * @param {{ max?: number, render?: (item: any) => Node|string, mono?: boolean, inline?: boolean }} [opts]
 * @returns {HTMLElement}
 */
export function TruncatedList(items, { max = 3, render = (x) => x, mono = true, inline = false } = {}) {
  const list = Array.isArray(items) ? items : [];
  const el = h('div', { class: ['tlist', { mono, 'tlist-inline': inline }] });
  if (!list.length) {
    el.append(h('span', { class: 'muted' }, '—'));
    return el;
  }
  const item = (x) => h('span', { class: 'tlist-item' }, render(x));
  el.append(...list.slice(0, max).map(item));
  if (list.length > max) {
    const rest = list.slice(max);
    const btn = h('button', {
      type: 'button',
      class: 'tlist-more',
      attrs: { 'aria-expanded': 'false' },
      on: {
        click: (e) => {
          e.stopPropagation();
          btn.replaceWith(...rest.map(item));
        }
      }
    }, t('common.moreCount', { count: formatNumber(rest.length) }));
    el.append(btn);
  }
  return el;
}

/**
 * Collapsible <details> block.
 * @param {{ summary: string|Node, children?: any, open?: boolean, className?: string, heading?: number|null }} opts
 *   `heading`: 1–6 holds the summary in an <hN class="disclosure-heading"> in place of the plain
 *   <span>, for a block that is a section of its page (heading navigation finds it; a <summary>
 *   may hold heading content, a <span> may not)
 * @returns {HTMLDetailsElement}
 */
export function Disclosure({ summary, children = null, open = false, className = '', heading = null }) {
  const level = Number.isInteger(heading) && heading >= 1 && heading <= 6 ? heading : 0;
  return h('details', { class: ['disclosure', className], open },
    h('summary', { class: 'disclosure-summary' }, Icon('chevron-right', { size: 14, className: 'disclosure-chevron' }),
      level ? h(`h${level}`, { class: 'disclosure-heading' }, summary) : h('span', null, summary)),
    h('div', { class: 'disclosure-body' }, children));
}

/**
 * Horizontal toolbar row (wraps on small screens).
 * @param {...any} children
 * @returns {HTMLDivElement}
 */
export function Toolbar(...children) {
  return h('div', { class: 'toolbar' }, children);
}

/* ------------------------------------------------------------------------ */
/* Tabs                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Accessible tabs (WAI-ARIA tabs pattern, automatic activation, roving tabindex;
 * ←/→/Home/End). Panel content can be a Node or a function called lazily on first show.
 * @param {Array<{ id: string, label: string, icon?: string, badge?: string|number|null, content?: Node|(() => Node),
 *   disabled?: boolean }>} items
 * @param {{ selected?: string, onChange?: (id: string) => void, label?: string, className?: string }} [opts]
 * @returns {{ el: HTMLElement, select(id: string, opts?: { focus?: boolean }): void, getSelected(): string,
 *   setBadge(id: string, value: string|number|null, variant?: string): void, setLabel(id: string, text: string): void,
 *   panel(id: string): HTMLElement|null }}
 */
export function Tabs(items, { selected = null, onChange = null, label = null, className = '' } = {}) {
  const base = uid('tabs');
  const tablist = h('div', { class: 'tablist', attrs: { role: 'tablist', 'aria-label': label || t('tabs.label') } });
  const panels = h('div', { class: 'tabpanels' });
  const el = h('div', { class: ['tabs', className] }, h('div', { class: 'tablist-scroll' }, tablist), panels);
  const entries = new Map();
  let current = null;

  for (const item of items) {
    const tabId = `${base}-tab-${item.id}`;
    const panelId = `${base}-panel-${item.id}`;
    const badge = h('span', { class: 'tab-badge', hidden: item.badge === null || item.badge === undefined || item.badge === '' },
      item.badge ?? '');
    const labelEl = h('span', { class: 'tab-label' }, item.label);
    const tab = h('button', {
      type: 'button',
      class: 'tab',
      id: tabId,
      disabled: !!item.disabled,
      dataset: { tab: item.id },
      attrs: { role: 'tab', 'aria-selected': 'false', 'aria-controls': panelId, tabindex: -1 },
      on: { click: () => select(item.id) }
    }, item.icon ? Icon(item.icon, { size: 15 }) : null, labelEl, badge);
    const panel = h('div', {
      class: 'tabpanel',
      id: panelId,
      hidden: true,
      dataset: { tab: item.id },
      attrs: { role: 'tabpanel', 'aria-labelledby': tabId, tabindex: 0 }
    });
    tablist.append(tab);
    panels.append(panel);
    entries.set(item.id, { item, tab, panel, badge, labelEl, rendered: false });
  }

  function ensureContent(entry) {
    if (entry.rendered) return;
    entry.rendered = true;
    const c = typeof entry.item.content === 'function' ? entry.item.content() : entry.item.content;
    if (c !== null && c !== undefined) entry.panel.append(isNode(c) || (c && isNode(c.el)) ? (c.el || c) : String(c));
  }

  function select(id, { focus = false, silent = false } = {}) {
    const entry = entries.get(id);
    if (!entry || entry.item.disabled) return;
    const changed = current !== id;
    for (const [key, e] of entries) {
      const on = key === id;
      e.tab.setAttribute('aria-selected', String(on));
      e.tab.tabIndex = on ? 0 : -1;
      e.tab.classList.toggle('is-selected', on);
      e.panel.hidden = !on;
    }
    ensureContent(entry);
    current = id;
    if (focus) entry.tab.focus();
    if (changed && onChange && !silent) onChange(id);
  }

  tablist.addEventListener('keydown', (event) => {
    const enabled = [...entries.values()].filter((e) => !e.item.disabled);
    const idx = enabled.findIndex((e) => e.item.id === current);
    let next = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = enabled[(idx + 1) % enabled.length];
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = enabled[(idx - 1 + enabled.length) % enabled.length];
    else if (event.key === 'Home') next = enabled[0];
    else if (event.key === 'End') next = enabled[enabled.length - 1];
    if (next) {
      event.preventDefault();
      select(next.item.id, { focus: true });
    }
  });

  const first = items.find((i) => !i.disabled);
  const initial = selected && entries.has(selected) ? selected : first && first.id;
  if (initial) select(initial, { silent: true }); // the initial selection does not fire onChange

  return {
    el,
    select: (id, o) => select(id, o),
    getSelected: () => current,
    setBadge(id, value, variant = null) {
      const e = entries.get(id);
      if (!e) return;
      e.badge.textContent = value === null || value === undefined ? '' : (typeof value === 'number' ? formatNumber(value) : String(value));
      e.badge.hidden = value === null || value === undefined || value === '';
      e.badge.className = ['tab-badge', variant ? `tab-badge-${variant}` : ''].join(' ').trim();
    },
    setLabel(id, text) {
      const e = entries.get(id);
      if (e) e.labelEl.textContent = text;
    },
    panel: (id) => entries.get(id)?.panel || null
  };
}

/**
 * Button group where one option is active (aria-pressed toggle buttons).
 * @param {{ options: Array<{ value: string, label?: string, icon?: string, title?: string }>, value?: string,
 *   onChange?: (value: string) => void, label: string, size?: 'sm'|'md', className?: string }} opts
 * @returns {{ el: HTMLElement, value: string, setValue(v: string): void }}
 */
export function SegmentedControl({ options, value = null, onChange = null, label, size = 'md', className = '' }) {
  let current = value ?? options[0]?.value;
  const buttons = options.map((opt) => h('button', {
    type: 'button',
    class: ['seg-btn', { 'seg-icon-only': !opt.label && !!opt.icon }],
    title: opt.title || opt.label || null,
    dataset: { value: opt.value },
    attrs: { 'aria-pressed': String(opt.value === current), 'aria-label': !opt.label ? opt.title : null },
    on: {
      click: () => {
        if (opt.value === current) return;
        api.setValue(opt.value);
        if (onChange) onChange(opt.value);
      }
    }
  }, opt.icon ? Icon(opt.icon, { size: size === 'sm' ? 14 : 16 }) : null, opt.label ? h('span', null, opt.label) : null));
  const el = h('div', { class: ['segmented', `segmented-${size}`, className], attrs: { role: 'group', 'aria-label': label } }, buttons);
  const api = {
    el,
    get value() {
      return current;
    },
    setValue(v) {
      current = v;
      buttons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.value === v)));
    }
  };
  return api;
}

/* ------------------------------------------------------------------------ */
/* Toasts                                                                   */
/* ------------------------------------------------------------------------ */

let toastRegion = null;
const TOAST_ICONS = { info: 'info', success: 'check-circle', ok: 'check-circle', warn: 'alert', error: 'x-circle' };
const MAX_TOASTS = 4;

/**
 * Show a transient notification (bottom-right; bottom on phones).
 * @param {string} message
 * @param {{ type?: 'info'|'success'|'warn'|'error', title?: string, timeout?: number,
 *   action?: { label: string, onClick: Function } }} [opts] timeout 0 = sticky; default 4.5 s (errors 8 s)
 * @returns {{ el: HTMLElement, close(): void }}
 */
export function toast(message, { type = 'info', title = null, timeout = null, action = null } = {}) {
  const doc = globalThis.document;
  const kind = TOAST_ICONS[type] ? (type === 'ok' ? 'success' : type) : 'info';
  if (!doc || !doc.body) return { el: null, close() {} };
  if (!toastRegion || !toastRegion.isConnected) {
    toastRegion = h('div', { class: 'toast-region', attrs: { 'aria-live': 'polite', 'aria-relevant': 'additions' } });
    doc.body.append(toastRegion);
  }
  let timer = null;
  const close = () => {
    clearTimeout(timer);
    if (!el.isConnected) return;
    el.classList.add('is-leaving');
    setTimeout(() => el.remove(), 180);
  };
  const el = h('div', { class: ['toast', `toast-${kind}`], attrs: { role: kind === 'error' ? 'alert' : 'status' } },
    Icon(TOAST_ICONS[kind], { size: 18, className: 'toast-icon' }),
    h('div', { class: 'toast-body' },
      title ? h('div', { class: 'toast-title' }, title) : null,
      h('div', { class: 'toast-message' }, message)),
    action ? Button({
      label: action.label, size: 'sm', variant: 'ghost',
      onClick: () => {
        action.onClick();
        close();
      }
    }) : null,
    IconButton({ icon: 'x', label: t('toast.dismiss'), size: 'sm', onClick: close }));
  toastRegion.append(el);
  while (toastRegion.children.length > MAX_TOASTS) toastRegion.firstElementChild.remove();
  const ms = timeout ?? (kind === 'error' ? 8000 : 4500);
  const arm = () => {
    if (ms > 0) timer = setTimeout(close, ms);
  };
  // Pause while hovered/focused so people can read or click.
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', arm);
  el.addEventListener('focusin', () => clearTimeout(timer));
  arm();
  return { el, close };
}

/** Alias of {@link toast} (component-style name). */
export const Toast = toast;

/* ------------------------------------------------------------------------ */
/* Modal dialog                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Modal dialog built on <dialog> (native focus trap, Esc to close, backdrop click closes
 * when dismissible). `open()` resolves with the clicked action's `value` (or null when
 * dismissed). An action's onClick may return false (or a Promise of false) to keep it open.
 * @param {{ title: string, content?: any, actions?: Array<{ label: string, value?: any, variant?: string, icon?: string,
 *   onClick?: (modal: object) => (boolean|void|Promise<boolean|void>), autofocus?: boolean }>, size?: 'sm'|'md'|'lg',
 *   dismissible?: boolean, onClose?: (value: any) => void, className?: string }} opts
 * @returns {{ el: HTMLDialogElement, body: HTMLElement, open(): Promise<any>, close(value?: any): void, setContent(...nodes: any[]): void }}
 */
export function Modal({ title, content = null, actions = null, size = 'md', dismissible = true, onClose = null, className = '' }) {
  const titleId = uid('modal-title');
  const body = h('div', { class: 'modal-body' }, content);
  let resolveResult = null;
  let resultValue = null;
  const result = new Promise((resolve) => {
    resolveResult = resolve;
  });
  const foot = actions && actions.length ? h('div', { class: 'modal-foot' }) : null;
  const dialog = h('dialog', {
    class: ['modal', `modal-${size}`, className],
    attrs: { 'aria-labelledby': titleId }
  }, h('div', { class: 'modal-box' },
    h('div', { class: 'modal-head' },
      h('h2', { class: 'modal-title', id: titleId }, title),
      dismissible ? IconButton({ icon: 'x', label: t('modal.close'), onClick: () => api.close(null) }) : null),
    body,
    foot));

  const api = {
    el: dialog,
    body,
    open() {
      const doc = globalThis.document;
      doc.body.append(dialog);
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
      const auto = dialog.querySelector('[data-autofocus]') || dialog.querySelector('.modal-body input, .modal-body select, .modal-body textarea');
      if (auto) auto.focus();
      return result;
    },
    close(value = null) {
      resultValue = value;
      if (dialog.open && typeof dialog.close === 'function') dialog.close();
      else finish();
    },
    setContent(...nodes) {
      clear(body);
      body.append(...nodes.flat().filter(Boolean).map((n) => (isNode(n) ? n : (n && isNode(n.el) ? n.el : String(n)))));
    }
  };

  if (foot) {
    for (const action of actions) {
      const btn = Button({
        label: action.label,
        icon: action.icon || null,
        variant: action.variant || 'secondary',
        dataset: action.autofocus ? { autofocus: '1' } : {},
        onClick: async () => {
          if (action.onClick) {
            const keep = await action.onClick(api);
            if (keep === false) return;
          }
          api.close(action.value === undefined ? null : action.value);
        }
      });
      foot.append(btn);
    }
  }

  function finish() {
    dialog.remove();
    if (onClose) onClose(resultValue);
    resolveResult(resultValue);
  }

  dialog.addEventListener('close', finish);
  dialog.addEventListener('cancel', (event) => {
    if (!dismissible) event.preventDefault();
    else resultValue = null;
  });
  dialog.addEventListener('click', (event) => {
    // Clicks on the ::backdrop target the <dialog> itself (the box covers the content).
    if (dismissible && event.target === dialog) api.close(null);
  });
  return api;
}

/**
 * Yes/no confirmation dialog.
 * @param {{ title?: string, message: string|Node, confirmLabel?: string, cancelLabel?: string, danger?: boolean }} opts
 * @returns {Promise<boolean>}
 */
export async function confirmDialog({ title = null, message, confirmLabel = null, cancelLabel = null, danger = false }) {
  const value = await Modal({
    title: title ?? t('common.confirm'),
    size: 'sm',
    content: h('p', { class: 'modal-message' }, message),
    actions: [
      { label: cancelLabel ?? t('common.cancel'), value: false, variant: 'secondary' },
      { label: confirmLabel ?? t('common.ok'), value: true, variant: danger ? 'danger' : 'primary', autofocus: !danger }
    ]
  }).open();
  return value === true;
}

/* ------------------------------------------------------------------------ */
/* File input                                                               */
/* ------------------------------------------------------------------------ */

/**
 * Decode file bytes to text: honours UTF-8/UTF-16 BOMs, otherwise UTF-8 (lenient).
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function decodeText(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer || new ArrayBuffer(0));
  let encoding = 'utf-8';
  let offset = 0;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) offset = 3;
  else if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    encoding = 'utf-16le';
    offset = 2;
  } else if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    encoding = 'utf-16be';
    offset = 2;
  }
  try {
    return new TextDecoder(encoding, { fatal: false }).decode(bytes.subarray(offset));
  } catch {
    return new TextDecoder('utf-8').decode(bytes.subarray(offset));
  }
}

/**
 * @typedef {object} LoadedFile
 * @property {string} name
 * @property {number} size bytes
 * @property {string} type MIME type reported by the browser ('' when unknown)
 * @property {ArrayBuffer} buffer raw bytes (give this to lib/x509.parseCertificates)
 * @property {string} text decoded text (BOM-aware)
 * @property {'drop'|'pick'|'paste'} source
 */

/**
 * Drag & drop + click-to-choose + paste zone. Files are read in the browser only.
 * Pasted text arrives as a LoadedFile named t('file.pasted').
 * @param {{ onFiles: (files: LoadedFile[]) => void, accept?: string, multiple?: boolean, maxBytes?: number,
 *   title?: string, hint?: string, icon?: string, compact?: boolean, paste?: boolean,
 *   onError?: (message: string) => void, className?: string }} opts
 * @returns {{ el: HTMLElement, input: HTMLInputElement, setStatus(text: string|null): void, open(): void }}
 */
export function FileDrop({
  onFiles, accept = '', multiple = false, maxBytes = 10 * 1024 * 1024, title = null, hint = null,
  icon = 'upload', compact = false, paste = true, onError = null, className = ''
}) {
  const hintId = uid('filedrop-hint');
  const input = h('input', {
    type: 'file',
    class: 'filedrop-input',
    tabindex: -1,
    attrs: { accept: accept || null, multiple: multiple || null, 'aria-hidden': 'true' }
  });
  const status = h('div', { class: 'filedrop-status', attrs: { 'aria-live': 'polite' } });
  const titleEl = h('div', { class: 'filedrop-title' }, title ?? t('file.dropTitle'));
  const el = h('div', {
    class: ['filedrop', { 'filedrop-compact': compact }, className],
    attrs: { role: 'button', tabindex: 0, 'aria-describedby': hintId }
  },
  h('div', { class: 'filedrop-icon' }, Icon(icon, { size: compact ? 18 : 22 })),
  h('div', { class: 'filedrop-text' },
    titleEl,
    h('div', { class: 'filedrop-hint', id: hintId }, hint ?? t('file.dropHint'),
      accept ? h('span', { class: 'filedrop-accept' }, ` · ${accept.split(',').map((s) => s.trim()).filter(Boolean).join(' ')}`) : null)),
  status, input);

  const fail = (msg) => {
    status.textContent = msg;
    status.classList.add('is-error');
    if (onError) onError(msg);
    else toast(msg, { type: 'error' });
  };

  async function readFiles(fileList, source) {
    const files = [...(fileList || [])].slice(0, multiple ? 100 : 1);
    if (!files.length) return;
    const out = [];
    for (const file of files) {
      if (file.size > maxBytes) {
        fail(t('file.tooLarge', { name: file.name, size: formatBytes(file.size), max: formatBytes(maxBytes) }));
        continue;
      }
      try {
        const buffer = await file.arrayBuffer();
        out.push({ name: file.name, size: file.size, type: file.type || '', buffer, text: decodeText(buffer), source });
      } catch {
        fail(t('file.readError', { name: file.name }));
      }
    }
    if (!out.length) return;
    status.classList.remove('is-error');
    status.textContent = out.length === 1
      ? t('file.loaded', { name: out[0].name, size: formatBytes(out[0].size) })
      : out.map((f) => f.name).join(', ');
    onFiles(out);
  }

  const openPicker = () => {
    input.value = '';
    input.click();
  };
  el.addEventListener('click', (event) => {
    if (event.target === input) return;
    openPicker();
  });
  el.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      openPicker();
    }
  });
  input.addEventListener('click', (event) => event.stopPropagation());
  input.addEventListener('change', () => readFiles(input.files, 'pick'));

  let depth = 0;
  const setOver = (on) => {
    el.classList.toggle('is-dragover', on);
    titleEl.textContent = on ? t('file.dropActive') : (title ?? t('file.dropTitle'));
  };
  el.addEventListener('dragenter', (event) => {
    event.preventDefault();
    depth += 1;
    setOver(true);
  });
  el.addEventListener('dragover', (event) => {
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
  });
  el.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (!depth) setOver(false);
  });
  el.addEventListener('drop', (event) => {
    event.preventDefault();
    depth = 0;
    setOver(false);
    const dt = event.dataTransfer;
    if (dt && dt.files && dt.files.length) readFiles(dt.files, 'drop');
    else if (dt) {
      const txt = dt.getData('text/plain');
      if (txt) deliverText(txt);
    }
  });

  function deliverText(txt) {
    const buffer = new TextEncoder().encode(txt).buffer;
    const name = t('file.pasted');
    status.classList.remove('is-error');
    status.textContent = t('file.loaded', { name, size: formatBytes(buffer.byteLength) });
    onFiles([{ name, size: buffer.byteLength, type: 'text/plain', buffer, text: txt, source: 'paste' }]);
  }

  if (paste) {
    el.addEventListener('paste', (event) => {
      const cd = event.clipboardData;
      if (!cd) return;
      if (cd.files && cd.files.length) {
        event.preventDefault();
        readFiles(cd.files, 'paste');
        return;
      }
      const txt = cd.getData('text/plain');
      if (txt) {
        event.preventDefault();
        deliverText(txt);
      }
    });
  }

  return {
    el,
    input,
    open: openPicker,
    setStatus(text) {
      status.classList.remove('is-error');
      status.textContent = text ?? '';
    }
  };
}

/* ------------------------------------------------------------------------ */
/* Form fields                                                              */
/* ------------------------------------------------------------------------ */

function fieldShell({ id, label, hint, required, optional, control, className = '', inline = false }) {
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const hintEl = h('div', { class: 'field-hint', id: hintId, hidden: !hint }, hint || '');
  const errorEl = h('div', { class: 'field-error', id: errorId, hidden: true, attrs: { 'aria-live': 'polite' } });
  const describe = () => [hintEl.hidden ? null : hintId, errorEl.hidden ? null : errorId].filter(Boolean).join(' ') || null;
  const labelEl = label ? h('label', { class: 'field-label', for: id }, label,
    required ? h('span', { class: 'field-req', attrs: { 'aria-hidden': 'true' } }, ' *') : null,
    optional ? h('span', { class: 'field-opt' }, ` (${t('common.optional')})`) : null) : null;
  const el = h('div', { class: ['field', { 'field-inline': inline }, className] }, labelEl, control, hintEl, errorEl);
  const sync = () => {
    const d = describe();
    if (d) control.setAttribute('aria-describedby', d);
    else control.removeAttribute('aria-describedby');
  };
  sync();
  return {
    el,
    setError(msg) {
      errorEl.textContent = msg || '';
      errorEl.hidden = !msg;
      control.setAttribute('aria-invalid', msg ? 'true' : 'false');
      el.classList.toggle('has-error', !!msg);
      sync();
    },
    setHint(msg) {
      hintEl.textContent = msg || '';
      hintEl.hidden = !msg;
      sync();
    }
  };
}

/**
 * Labelled text input. Enter triggers `onEnter`.
 * @param {{ label?: string, value?: string, placeholder?: string, hint?: string, type?: string, name?: string,
 *   required?: boolean, optional?: boolean, autocomplete?: string, inputmode?: string, spellcheck?: boolean,
 *   mono?: boolean, onInput?: (value: string, e: Event) => void, onChange?: (value: string, e: Event) => void,
 *   onEnter?: (value: string, e: KeyboardEvent) => void, id?: string, className?: string, attrs?: object }} [opts]
 * @returns {{ el: HTMLElement, input: HTMLInputElement, value: string, setError(msg: string|null): void, setHint(msg: string|null): void, focus(): void }}
 */
export function textInput({
  label = null, value = '', placeholder = '', hint = null, type = 'text', name = null, required = false, optional = false,
  autocomplete = 'off', inputmode = null, spellcheck = false, mono = false, onInput = null, onChange = null, onEnter = null,
  id = null, className = '', attrs = {}
} = {}) {
  const inputId = id || uid('field');
  const input = h('input', {
    id: inputId,
    type,
    name,
    class: ['input', { mono }],
    value,
    placeholder: placeholder || null,
    required,
    attrs: { autocomplete, inputmode, spellcheck: String(!!spellcheck), autocapitalize: 'off', ...attrs },
    on: {
      input: onInput ? (e) => onInput(input.value, e) : null,
      change: onChange ? (e) => onChange(input.value, e) : null,
      keydown: onEnter ? (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
          e.preventDefault();
          onEnter(input.value, e);
        }
      } : null
    }
  });
  const shell = fieldShell({ id: inputId, label, hint, required, optional, control: input, className });
  return {
    ...shell,
    input,
    get value() {
      return input.value;
    },
    set value(v) {
      input.value = v ?? '';
    },
    focus: () => input.focus()
  };
}

/**
 * Labelled textarea (monospace by default — made for lists of hostnames/IPs/PEM).
 * @param {{ label?: string, value?: string, rows?: number, placeholder?: string, hint?: string, mono?: boolean,
 *   wrap?: boolean, required?: boolean, optional?: boolean, onInput?: Function, onChange?: Function, id?: string,
 *   name?: string, className?: string, attrs?: object }} [opts]
 * @returns {{ el: HTMLElement, input: HTMLTextAreaElement, value: string, setError(msg: string|null): void, setHint(msg: string|null): void, focus(): void }}
 */
export function textarea({
  label = null, value = '', rows = 6, placeholder = '', hint = null, mono = true, wrap = false, required = false,
  optional = false, onInput = null, onChange = null, id = null, name = null, className = '', attrs = {}
} = {}) {
  const inputId = id || uid('field');
  const input = h('textarea', {
    id: inputId,
    name,
    class: ['textarea', { mono }],
    rows,
    value,
    placeholder: placeholder || null,
    required,
    attrs: { spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', wrap: wrap ? 'soft' : 'off', ...attrs },
    on: {
      input: onInput ? (e) => onInput(input.value, e) : null,
      change: onChange ? (e) => onChange(input.value, e) : null
    }
  });
  const shell = fieldShell({ id: inputId, label, hint, required, optional, control: input, className });
  return {
    ...shell,
    input,
    get value() {
      return input.value;
    },
    set value(v) {
      input.value = v ?? '';
    },
    focus: () => input.focus()
  };
}

function normalizeOptions(options) {
  return (options || []).map((o) => {
    if (o && typeof o === 'object' && Array.isArray(o.options)) return { group: o.label, options: normalizeOptions(o.options) };
    if (o && typeof o === 'object') return { value: String(o.value), label: o.label ?? String(o.value), disabled: !!o.disabled };
    return { value: String(o), label: String(o), disabled: false };
  });
}

/**
 * Labelled <select>. Options: strings, { value, label, disabled } or optgroups { label, options: [...] }.
 * @param {{ label?: string, options: any[], value?: string, onChange?: (value: string, e: Event) => void, hint?: string,
 *   id?: string, name?: string, className?: string, size?: 'sm'|'md' }} opts
 * @returns {{ el: HTMLElement, input: HTMLSelectElement, value: string, setOptions(options: any[]): void, setError(msg: string|null): void, setHint(msg: string|null): void }}
 */
export function select({ label = null, options = [], value = null, onChange = null, hint = null, id = null, name = null, className = '', size = 'md' }) {
  const inputId = id || uid('field');
  const renderOptions = (opts) => normalizeOptions(opts).map((o) => (o.group !== undefined
    ? h('optgroup', { attrs: { label: o.group } }, o.options.map((x) => h('option', { value: x.value, disabled: x.disabled }, x.label)))
    : h('option', { value: o.value, disabled: o.disabled }, o.label)));
  const input = h('select', {
    id: inputId,
    name,
    class: ['select', { 'select-sm': size === 'sm' }],
    on: { change: onChange ? (e) => onChange(input.value, e) : null }
  }, renderOptions(options));
  if (value !== null && value !== undefined) input.value = String(value);
  const shell = fieldShell({ id: inputId, label, hint, control: input, className });
  return {
    ...shell,
    input,
    get value() {
      return input.value;
    },
    set value(v) {
      input.value = String(v ?? '');
    },
    setOptions(opts) {
      const prev = input.value;
      clear(input);
      input.append(...renderOptions(opts));
      input.value = prev;
      if (input.selectedIndex < 0 && input.options.length) input.selectedIndex = 0;
    }
  };
}

/**
 * Labelled checkbox (or a switch with `switch: true`).
 * @param {{ label: string|Node, checked?: boolean, hint?: string, onChange?: (checked: boolean, e: Event) => void,
 *   name?: string, value?: string, id?: string, disabled?: boolean, switch?: boolean, className?: string }} opts
 * @returns {{ el: HTMLElement, input: HTMLInputElement, checked: boolean }}
 */
export function checkbox({ label, checked = false, hint = null, onChange = null, name = null, value = null, id = null,
  disabled = false, switch: asSwitch = false, className = '' }) {
  const inputId = id || uid('check');
  const input = h('input', {
    type: 'checkbox',
    id: inputId,
    name,
    value: value ?? undefined,
    checked,
    disabled,
    class: asSwitch ? 'switch-input' : 'check-input',
    attrs: { role: asSwitch ? 'switch' : null, 'aria-describedby': hint ? `${inputId}-hint` : null },
    on: { change: onChange ? (e) => onChange(input.checked, e) : null }
  });
  const el = h('div', { class: ['check', { 'check-switch': asSwitch, 'is-disabled': disabled }, className] },
    input,
    h('label', { for: inputId, class: 'check-label' },
      asSwitch ? h('span', { class: 'switch-track', attrs: { 'aria-hidden': 'true' } }, h('span', { class: 'switch-thumb' })) : null,
      h('span', { class: 'check-text' }, label)),
    hint ? h('div', { class: 'check-hint', id: `${inputId}-hint` }, hint) : null);
  return {
    el,
    input,
    get checked() {
      return input.checked;
    },
    set checked(v) {
      input.checked = !!v;
    }
  };
}

function optionList(options) {
  return (options || []).map((o) => (o && typeof o === 'object' ? { hint: null, disabled: false, ...o, value: String(o.value) } : { value: String(o), label: String(o), hint: null, disabled: false }));
}

/**
 * Radio button group in a fieldset.
 * @param {{ legend: string, name?: string, options: Array<{ value: string, label: string|Node, hint?: string, disabled?: boolean }|string>,
 *   value?: string, onChange?: (value: string) => void, inline?: boolean, hint?: string, className?: string }} opts
 * @returns {{ el: HTMLFieldSetElement, inputs: HTMLInputElement[], value: string }}
 */
export function radioGroup({ legend, name = null, options, value = null, onChange = null, inline = false, hint = null, className = '' }) {
  const groupName = name || uid('radio');
  const opts = optionList(options);
  const inputs = [];
  const el = h('fieldset', { class: ['fieldset', 'choice-group', { 'choice-inline': inline }, className] },
    h('legend', { class: 'field-label' }, legend),
    hint ? h('div', { class: 'field-hint' }, hint) : null,
    h('div', { class: 'choice-list' }, opts.map((o) => {
      const cb = checkboxLike('radio', groupName, o, o.value === String(value ?? opts[0]?.value), () => {
        if (onChange) onChange(o.value);
      });
      inputs.push(cb.input);
      return cb.el;
    })));
  return {
    el,
    inputs,
    get value() {
      const on = inputs.find((i) => i.checked);
      return on ? on.value : null;
    },
    set value(v) {
      inputs.forEach((i) => {
        i.checked = i.value === String(v);
      });
    }
  };
}

function checkboxLike(type, name, o, checked, onChange) {
  const inputId = uid(type);
  const input = h('input', {
    type,
    id: inputId,
    name,
    value: o.value,
    checked,
    disabled: o.disabled,
    class: 'check-input',
    attrs: { 'aria-describedby': o.hint ? `${inputId}-hint` : null },
    on: { change: onChange }
  });
  const el = h('div', { class: ['check', { 'is-disabled': o.disabled }] },
    input,
    h('label', { for: inputId, class: 'check-label' }, h('span', { class: 'check-text' }, o.label)),
    o.hint ? h('div', { class: 'check-hint', id: `${inputId}-hint` }, o.hint) : null);
  return { el, input };
}

/**
 * Checkbox group in a fieldset with optional "select all / none" links.
 * @param {{ legend: string, name?: string, options: Array<{ value: string, label: string|Node, hint?: string, disabled?: boolean }|string>,
 *   values?: string[], onChange?: (values: string[]) => void, inline?: boolean, hint?: string, selectAll?: boolean,
 *   className?: string }} opts
 * @returns {{ el: HTMLFieldSetElement, inputs: HTMLInputElement[], values: string[] }}
 */
export function checkboxGroup({ legend, name = null, options, values = [], onChange = null, inline = false, hint = null, selectAll = false, className = '' }) {
  const groupName = name || uid('checks');
  const opts = optionList(options);
  const selected = new Set((values || []).map(String));
  const inputs = [];
  const emit = () => {
    if (onChange) onChange(api.values);
  };
  const setAll = (on) => {
    inputs.forEach((i) => {
      if (!i.disabled) i.checked = on;
    });
    emit();
  };
  const el = h('fieldset', { class: ['fieldset', 'choice-group', { 'choice-inline': inline }, className] },
    h('legend', { class: 'field-label' }, legend),
    selectAll ? h('div', { class: 'choice-bulk' },
      h('button', { type: 'button', class: 'link-btn', on: { click: () => setAll(true) } }, t('common.selectAll')),
      h('span', { class: 'muted', attrs: { 'aria-hidden': 'true' } }, '·'),
      h('button', { type: 'button', class: 'link-btn', on: { click: () => setAll(false) } }, t('common.selectNone'))) : null,
    hint ? h('div', { class: 'field-hint' }, hint) : null,
    h('div', { class: 'choice-list' }, opts.map((o) => {
      const cb = checkboxLike('checkbox', groupName, o, selected.has(o.value), emit);
      inputs.push(cb.input);
      return cb.el;
    })));
  const api = {
    el,
    inputs,
    get values() {
      return inputs.filter((i) => i.checked).map((i) => i.value);
    },
    set values(v) {
      const s = new Set((v || []).map(String));
      inputs.forEach((i) => {
        i.checked = s.has(i.value);
      });
    }
  };
  return api;
}

/* ------------------------------------------------------------------------ */
/* DataTable                                                                */
/* ------------------------------------------------------------------------ */

const EMPTY_VALUE = Symbol('empty');

function isEmptyValue(v) {
  return v === null || v === undefined || v === '' || v === EMPTY_VALUE || (typeof v === 'number' && Number.isNaN(v))
    || (v instanceof Date && Number.isNaN(v.getTime())) || (Array.isArray(v) && v.length === 0);
}

function primitiveOf(v) {
  if (v instanceof Date) return v.getTime();
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (Array.isArray(v)) return primitiveOf(v[0]);
  return v;
}

/**
 * Compare two sort values: numbers/bigints numerically, Dates by time, booleans (false < true),
 * arrays by their first element, strings with a locale-aware natural collator ('web2' < 'web10').
 * Empty values (null, undefined, '', NaN, []) are NOT handled here — the table always sorts
 * them last in both directions.
 * @param {any} a
 * @param {any} b
 * @param {Intl.Collator} [collator]
 * @returns {number}
 */
export function compareValues(a, b, collator) {
  const x = primitiveOf(a);
  const y = primitiveOf(b);
  const tx = typeof x;
  const ty = typeof y;
  if ((tx === 'number' || tx === 'bigint') && (ty === 'number' || ty === 'bigint')) {
    if (tx === ty) return x < y ? -1 : x > y ? 1 : 0;
    const bx = BigInt(Math.trunc(Number(x)));
    const by = BigInt(Math.trunc(Number(y)));
    return bx < by ? -1 : bx > by ? 1 : 0;
  }
  const sx = String(x);
  const sy = String(y);
  return collator ? collator.compare(sx, sy) : (sx < sy ? -1 : sx > sy ? 1 : 0);
}

/**
 * Sort key for IP addresses: IPv4 before IPv6, numeric order within each (as a BigInt).
 * Invalid input → null (sorted last). Use as a column `sortValue`.
 * @param {string} ip
 * @returns {bigint|null}
 */
export function ipSortValue(ip) {
  const parsed = typeof ip === 'string' ? parseIP(ip) : null;
  if (!parsed) return null;
  return (BigInt(parsed.version) << 130n) + parsed.value;
}

/**
 * Case/diacritics-insensitive search normalization ('İSTANBUL' → 'istanbul').
 * @param {unknown} s
 * @returns {string}
 */
export function normalizeSearch(s) {
  return String(s ?? '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
}

function valueToText(v) {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? '' : v.toISOString();
  if (Array.isArray(v)) return v.map(valueToText).join(' ');
  if (typeof v === 'object') return '';
  return String(v);
}

/**
 * Escape one CSV cell (RFC 4180). Text cells starting with = + @ or a tab/CR — and '-' when
 * the text is not a number — get a leading apostrophe so spreadsheet apps do not evaluate
 * them as formulas (untrusted data such as TXT records ends up in exports).
 * @param {any} value
 * @returns {string}
 */
export function csvCell(value) {
  let s = valueToText(value);
  if (typeof value === 'string' && /^[=+@\t\r]/.test(s)) s = `'${s}`;
  else if (typeof value === 'string' && /^-/.test(s) && !/^-\d+(?:[.,]\d+)?$/.test(s)) s = `'${s}`;
  return /[",\r\n;]/.test(s) || /^\s|\s$/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * Rows → CSV text (header row, CRLF line endings, UTF-8 BOM so Excel shows Turkish characters).
 * @param {object[]} rows
 * @param {Array<{ header: string, get: (row: object) => any }>} columns
 * @param {{ bom?: boolean }} [opts]
 * @returns {string}
 */
export function rowsToCsv(rows, columns, { bom = true } = {}) {
  const lines = [columns.map((c) => csvCell(c.header)).join(',')];
  for (const row of rows) lines.push(columns.map((c) => csvCell(c.get(row))).join(','));
  return `${bom ? '﻿' : ''}${lines.join('\r\n')}\r\n`;
}

/**
 * @typedef {object} DataTableColumn
 * @property {string} key unique id; default value source is row[key]
 * @property {string} label header text
 * @property {string} [title] header tooltip
 * @property {(row: any) => (Node|string|number|null|undefined)} [render] cell content (default: row[key] as text)
 * @property {boolean} [sortable=false]
 * @property {(row: any) => any} [sortValue] default row[key] (use ipSortValue for IP columns)
 * @property {'asc'|'desc'} [defaultDir='asc'] direction of the first click
 * @property {(row: any) => string} [searchValue] text matched by the search box (default: sortValue/row[key])
 * @property {boolean} [searchable=true]
 * @property {(row: any) => any} [exportValue] value in CSV/JSON exports (default: searchValue/sortValue/row[key])
 * @property {boolean} [export=true] include in exports
 * @property {string} [exportHeader] CSV header (default: label)
 * @property {string} [className] added to th and td
 * @property {'start'|'end'|'center'} [align]
 * @property {string} [width] CSS width of the column (e.g. '8rem')
 * @property {boolean} [mono] monospace cells
 * @property {boolean} [wrap] let cell text wrap (cells do NOT wrap by default so hostnames/IPs stay whole
 *   and the table scrolls horizontally instead) — use for long text such as TXT data or reasons
 * @property {boolean} [nowrap] kept for compatibility (no-wrap is the default)
 */

/**
 * Sortable, searchable, streaming-friendly table with incremental rendering.
 *
 * - `addRows()` batches appends per animation frame (throttled for big tables), so views can
 *   stream thousands of results without jank.
 * - Only the first `pageSize` rows (after filter + sort) are rendered; "Show N more" adds more.
 * - Rendered <tr>s are cached per row object; call `updateRow(row)` after mutating a row.
 * - Rows are sorted with empty values last; string sorting is natural ('web2' < 'web10').
 * - Export buttons (CSV/JSON) export all rows that pass the current filter/search, in the
 *   current sort order. Provide `export.onExport(format, rows)` to take over (e.g. lib/export.js).
 *
 * @param {{ columns: DataTableColumn[], rows?: any[], rowKey?: (row: any) => string, pageSize?: number,
 *   search?: boolean|{ placeholder?: string, label?: string, value?: string }, sort?: { key: string, dir?: 'asc'|'desc' },
 *   filter?: (row: any) => boolean, empty?: string|Node, noMatch?: string, rowClass?: (row: any) => any,
 *   onRowClick?: (row: any, e: Event) => void, details?: (row: any) => Node|null, toolbar?: Node|Node[],
 *   export?: false|{ filename?: string, subject?: string, formats?: Array<'csv'|'json'>, json?: (rows: any[]) => any,
 *     onExport?: (format: 'csv'|'json', rows: any[]) => void },
 *   caption?: string, maxHeight?: string|null, dense?: boolean, className?: string,
 *   onChange?: (info: { total: number, matched: number, shown: number }) => void }} opts
 */
export function DataTable(opts) {
  const {
    columns: initialColumns,
    rows: initialRows = [],
    rowKey = null,
    pageSize = 200,
    search = false,
    sort = null,
    filter: initialFilter = null,
    empty = null,
    noMatch = null,
    rowClass = null,
    onRowClick = null,
    details = null,
    toolbar = null,
    caption = null,
    maxHeight = undefined,
    dense = false,
    className = '',
    onChange = null
  } = opts || {};
  const exportOpts = opts && (opts.export ?? opts.exportOptions);
  let columns = initialColumns || [];
  let allRows = [];
  let pending = [];
  let filterFn = initialFilter;
  let query = '';
  let sortState = sort && sort.key ? { key: sort.key, dir: sort.dir === 'desc' ? 'desc' : 'asc' } : null;
  let shown = pageSize;
  let view = null; // cached filtered+sorted rows
  let loading = false;
  let emptyContent = empty;
  const trCache = new WeakMap();
  const detailCache = new WeakMap();
  const rowOfTr = new WeakMap(); // rendered <tr> (row or details) → row object
  const searchCache = new WeakMap();
  const expanded = new WeakSet();
  const collator = new Intl.Collator(localeTag(getLang()), { numeric: true, sensitivity: 'base' });

  // --- DOM skeleton ---------------------------------------------------------
  const searchInput = search ? h('input', {
    type: 'search',
    class: 'input input-sm dt-search-input',
    placeholder: (search && search.placeholder) || t('table.searchPlaceholder'),
    value: (search && search.value) || '',
    attrs: { 'aria-label': (search && search.label) || t('table.searchLabel'), autocomplete: 'off', spellcheck: 'false' }
  }) : null;
  if (searchInput) query = searchInput.value;
  const exportFormats = exportOpts ? (exportOpts.formats || ['csv', 'json']) : [];
  const exportGroup = exportFormats.length ? h('div', { class: 'dt-export', attrs: { role: 'group', 'aria-label': t('table.exportLabel') } },
    exportFormats.map((fmt) => Button({
      label: t(fmt === 'csv' ? 'common.exportCsv' : 'common.exportJson'),
      icon: 'download',
      size: 'sm',
      title: t('table.exportLabel'),
      dataset: { export: fmt },
      onClick: () => doExport(fmt)
    }))) : null;
  const toolbarEl = searchInput || toolbar || exportGroup ? h('div', { class: 'dt-toolbar' },
    searchInput ? h('div', { class: 'dt-search' }, Icon('search', { size: 14, className: 'dt-search-icon' }), searchInput) : null,
    toolbar ? h('div', { class: 'dt-tools' }, toolbar) : null,
    exportGroup) : null;

  const thead = h('thead');
  const tbody = h('tbody');
  const table = h('table', { class: ['dt-table', { 'dt-dense': dense }] },
    caption ? h('caption', { class: 'sr-only' }, caption) : null, thead, tbody);
  // tabindex=0 lets keyboard users scroll the table horizontally/vertically.
  const scroll = h('div', {
    class: ['dt-scroll', { 'dt-scroll-free': maxHeight === null }],
    attrs: { tabindex: 0, role: caption ? 'region' : null, 'aria-label': caption || null }
  }, table);
  if (maxHeight) scroll.style.maxHeight = maxHeight;
  const emptyEl = h('div', { class: 'dt-empty', hidden: true });
  const countEl = h('span', { class: 'dt-count', attrs: { 'aria-live': 'polite' } });
  const moreBtn = Button({ label: t('common.showMore'), size: 'sm', variant: 'secondary', icon: 'chevron-down', onClick: () => showMore(pageSize) });
  const allBtn = Button({ label: t('common.showMore'), size: 'sm', variant: 'ghost', onClick: () => showMore(Infinity) });
  const footer = h('div', { class: 'dt-footer' }, countEl, h('div', { class: 'dt-more' }, moreBtn, allBtn));
  // A form of its own for the shell's Ctrl/Cmd+Enter, with no submit: the search box and the row
  // controls never start the view's run (app.js; lib/shellnav.js pickShortcutTarget).
  const el = h('div', { class: ['dt', className], dataset: { shortcutScope: 'table' } }, toolbarEl, scroll, emptyEl, footer);

  // --- header ---------------------------------------------------------------
  function renderHead() {
    const cells = [];
    if (details) cells.push(h('th', { class: 'dt-expander-col', attrs: { scope: 'col' } }, h('span', { class: 'sr-only' }, t('common.details'))));
    for (const col of columns) {
      const sorted = sortState && sortState.key === col.key;
      const th = h('th', {
        class: ['dt-th', col.className, col.align ? `dt-align-${col.align}` : null, { 'dt-sortable': col.sortable, 'is-sorted': sorted }],
        title: col.title || null,
        attrs: { scope: 'col', 'aria-sort': sorted ? (sortState.dir === 'asc' ? 'ascending' : 'descending') : null },
        dataset: { key: col.key }
      });
      if (col.width) th.style.width = col.width;
      if (col.sortable) {
        th.append(h('button', {
          type: 'button',
          class: 'dt-sort',
          attrs: { 'aria-label': `${t('table.sortBy', { column: col.label })}` },
          on: { click: () => toggleSort(col) }
        }, h('span', null, col.label),
        Icon(sorted ? (sortState.dir === 'asc' ? 'arrow-up' : 'arrow-down') : 'sort', { size: 13, className: 'dt-sort-icon' })));
      } else {
        th.append(col.label);
      }
      cells.push(th);
    }
    clear(thead);
    thead.append(h('tr', null, cells));
  }

  function toggleSort(col) {
    if (sortState && sortState.key === col.key) sortState = { key: col.key, dir: sortState.dir === 'asc' ? 'desc' : 'asc' };
    else sortState = { key: col.key, dir: col.defaultDir === 'desc' ? 'desc' : 'asc' };
    view = null;
    renderHead();
    render();
  }

  // --- data helpers -----------------------------------------------------------
  const colValue = (col, row) => (col.sortValue ? col.sortValue(row) : row == null ? undefined : row[col.key]);

  function searchText(row) {
    let s = searchCache.get(row);
    if (s === undefined) {
      s = normalizeSearch(columns.filter((c) => c.searchable !== false)
        .map((c) => valueToText(c.searchValue ? c.searchValue(row) : colValue(c, row)))
        .join('\u0001'));
      if (row && typeof row === 'object') searchCache.set(row, s);
    }
    return s;
  }

  function computeView() {
    if (view) return view;
    const terms = normalizeSearch(query).split(/\s+/).filter(Boolean);
    let rows = allRows;
    if (filterFn || terms.length) {
      rows = rows.filter((row) => {
        if (filterFn && !filterFn(row)) return false;
        if (!terms.length) return true;
        const text = searchText(row);
        return terms.every((term) => text.includes(term));
      });
    } else {
      rows = rows.slice();
    }
    if (sortState) {
      const col = columns.find((c) => c.key === sortState.key);
      if (col) {
        const dir = sortState.dir === 'desc' ? -1 : 1;
        const keyed = rows.map((row, i) => ({ row, i, v: colValue(col, row) }));
        keyed.sort((a, b) => {
          const ea = isEmptyValue(a.v);
          const eb = isEmptyValue(b.v);
          if (ea || eb) return ea && eb ? a.i - b.i : (ea ? 1 : -1);
          return dir * compareValues(a.v, b.v, collator) || a.i - b.i;
        });
        rows = keyed.map((k) => k.row);
      }
    }
    view = rows;
    return view;
  }

  // --- rows -----------------------------------------------------------------
  function renderCell(col, row) {
    const td = h('td', {
      class: [col.className, col.align ? `dt-align-${col.align}` : null, { mono: col.mono, nowrap: col.nowrap, 'dt-wrap': col.wrap }]
    });
    let content;
    try {
      content = col.render ? col.render(row) : (row == null ? null : row[col.key]);
    } catch (err) {
      content = h('span', { class: 'dt-cell-error', title: String(err && err.message) }, '⚠');
    }
    if (content === null || content === undefined || content === '') td.append(h('span', { class: 'dt-null' }, '—'));
    else if (isNode(content)) td.append(content);
    else if (content && typeof content === 'object' && isNode(content.el)) td.append(content.el);
    else if (Array.isArray(content)) td.append(...content.map((c) => (isNode(c) ? c : String(c))));
    else td.append(typeof content === 'number' ? formatNumber(content) : String(content));
    return td;
  }

  function renderRow(row) {
    let tr = trCache.get(row);
    if (tr) return tr;
    const cells = [];
    if (details) {
      const isOpen = expanded.has(row);
      cells.push(h('td', { class: 'dt-expander' }, h('button', {
        type: 'button',
        class: 'dt-expand-btn',
        attrs: { 'aria-expanded': String(isOpen), 'aria-label': t(isOpen ? 'table.collapseRow' : 'table.expandRow') },
        on: {
          click: (e) => {
            e.stopPropagation();
            if (expanded.has(row)) expanded.delete(row);
            else expanded.add(row);
            trCache.delete(row);
            render();
          }
        }
      }, Icon('chevron-right', { size: 14 }))));
    }
    for (const col of columns) cells.push(renderCell(col, row));
    tr = h('tr', {
      class: ['dt-row', rowClass ? rowClass(row) : null, { 'is-clickable': !!onRowClick, 'is-expanded': details && expanded.has(row) }],
      attrs: { tabindex: onRowClick ? 0 : null },
      on: onRowClick ? {
        click: (e) => {
          if (e.target.closest && e.target.closest('a,button,input,select,textarea,label')) return;
          onRowClick(row, e);
        },
        keydown: (e) => {
          if (e.key === 'Enter' && e.target === tr) onRowClick(row, e);
        }
      } : null
    }, cells);
    if (row && typeof row === 'object') {
      trCache.set(row, tr);
      rowOfTr.set(tr, row);
    }
    return tr;
  }

  function renderDetails(row) {
    let tr = detailCache.get(row);
    if (tr) return tr;
    const content = details(row);
    tr = h('tr', { class: 'dt-details' }, h('td', { attrs: { colspan: columns.length + 1 } }, h('div', { class: 'dt-details-body' }, content)));
    if (row && typeof row === 'object') {
      detailCache.set(row, tr);
      rowOfTr.set(tr, row);
    }
    return tr;
  }

  // replaceChildren() detaches every <tr>, even a cached one, and a focused control inside it
  // drops keyboard focus to <body> (streamed rows, refresh, the expand button). Remember where
  // focus was and put it back — on the same control of the rebuilt <tr> when the row was
  // re-rendered (expand toggle, updateRow).
  const ROW_FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]';

  /** Keyboard focus inside the body: its row, which <tr> of the row and which control. */
  function focusInBody() {
    const active = globalThis.document ? globalThis.document.activeElement : null;
    if (!active || active === tbody || !tbody.contains(active)) return null;
    let tr = active;
    while (tr.parentNode !== tbody) tr = tr.parentNode; // this table's <tr>, even from a nested table
    if (!rowOfTr.has(tr)) return null;
    return {
      active,
      row: rowOfTr.get(tr),
      details: tr.classList.contains('dt-details'),
      index: active === tr ? -1 : [...tr.querySelectorAll(ROW_FOCUSABLE)].indexOf(active)
    };
  }

  function restoreFocus(saved) {
    let target = saved.active.isConnected ? saved.active : null;
    if (!target) {
      const tr = (saved.details ? detailCache : trCache).get(saved.row);
      if (tr && tr.isConnected) target = saved.index === -1 ? tr : tr.querySelectorAll(ROW_FOCUSABLE)[saved.index] || null;
    }
    if (target) target.focus({ preventScroll: true });
  }

  let lastRenderAt = 0;
  function render() {
    lastRenderAt = Date.now();
    const rows = computeView();
    const total = allRows.length;
    const matched = rows.length;
    const limit = Math.min(matched, shown);
    const trs = [];
    for (let i = 0; i < limit; i += 1) {
      const row = rows[i];
      trs.push(renderRow(row));
      if (details && expanded.has(row)) trs.push(renderDetails(row));
    }
    const focused = focusInBody();
    tbody.replaceChildren(...trs);
    if (focused) restoreFocus(focused);

    const filtered = !!filterFn || !!normalizeSearch(query).trim();
    // Empty states
    clear(emptyEl);
    if (total === 0) {
      emptyEl.hidden = false;
      emptyEl.append(loading
        ? h('div', { class: 'dt-empty-inner' }, Spinner({ showLabel: true }))
        : (isNode(emptyContent) ? emptyContent : EmptyState({ compact: true, icon: 'inbox', message: emptyContent || t('table.empty') })));
    } else if (matched === 0) {
      emptyEl.hidden = false;
      emptyEl.append(EmptyState({
        compact: true,
        icon: 'filter',
        message: noMatch || t('table.noMatch'),
        action: searchInput && query ? Button({ label: t('common.clearFilters'), size: 'sm', onClick: () => api.setSearch('') }) : null
      }));
    } else {
      emptyEl.hidden = true;
    }
    scroll.hidden = matched === 0;
    table.classList.toggle('is-empty', matched === 0);

    // Footer
    if (total === 0) countEl.textContent = '';
    else if (filtered) countEl.textContent = t('table.countFiltered', { shown: formatNumber(limit), matched: formatNumber(matched), total: formatNumber(total) });
    else if (limit < matched) countEl.textContent = t('table.count', { shown: formatNumber(limit), total: formatNumber(total) });
    else countEl.textContent = t('table.rows', { count: total });
    const remaining = matched - limit;
    moreBtn.hidden = remaining <= 0;
    allBtn.hidden = remaining <= pageSize;
    if (remaining > 0) {
      moreBtn.querySelector('.btn-label').textContent = t('table.showMore', { count: formatNumber(Math.min(pageSize, remaining)) });
      allBtn.querySelector('.btn-label').textContent = t('table.showAll', { count: formatNumber(matched) });
    }
    footer.hidden = total === 0;
    if (exportGroup) exportGroup.querySelectorAll('button').forEach((b) => { b.disabled = matched === 0; });
    if (onChange) onChange({ total, matched, shown: limit });
  }

  function showMore(n) {
    shown = n === Infinity ? Infinity : shown + n;
    render();
  }

  // --- streaming --------------------------------------------------------------
  let scheduled = false;
  function flushPending() {
    if (!pending.length) return;
    allRows.push(...pending);
    pending = [];
    view = null;
  }
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    const raf = globalThis.requestAnimationFrame || ((fn) => setTimeout(fn, 16));
    // Big, fast streams re-render at most ~6×/s; small tables every frame.
    const wait = allRows.length > 1000 ? Math.max(0, 160 - (Date.now() - lastRenderAt)) : 0;
    const run = () => raf(() => {
      scheduled = false;
      flushPending();
      render();
    });
    if (wait) setTimeout(run, wait);
    else run();
  }

  // --- export -----------------------------------------------------------------
  function exportColumns() {
    return columns.filter((c) => c.export !== false).map((c) => ({
      key: c.key,
      header: c.exportHeader || c.label,
      get: (row) => {
        const v = c.exportValue ? c.exportValue(row) : (c.searchValue ? c.searchValue(row) : colValue(c, row));
        return Array.isArray(v) ? v.map(valueToText).join(' ') : v;
      }
    }));
  }

  function doExport(format) {
    flushPending();
    const rows = computeView();
    if (exportOpts.onExport) {
      exportOpts.onExport(format, rows);
      return;
    }
    const cols = exportColumns();
    const base = exportOpts.filename || 'export';
    const name = timestampedName(base, format, exportOpts.subject);
    let file;
    if (format === 'csv') {
      file = downloadText(name, rowsToCsv(rows, cols), 'text/csv;charset=utf-8');
    } else {
      const value = exportOpts.json ? exportOpts.json(rows)
        : rows.map((row) => Object.fromEntries(cols.map((c) => [c.key, c.get(row)])));
      file = downloadText(name, `${JSON.stringify(value, jsonReplacer, 2)}\n`, 'application/json;charset=utf-8');
    }
    toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  }

  // --- wiring -------------------------------------------------------------------
  if (searchInput) {
    const onSearch = debounce(() => {
      query = searchInput.value;
      shown = pageSize;
      view = null;
      render();
    }, 120);
    searchInput.addEventListener('input', onSearch);
  }

  const keyIndex = () => {
    const map = new Map();
    allRows.forEach((r, i) => map.set(rowKey(r), i));
    return map;
  };

  function invalidate(row) {
    trCache.delete(row);
    detailCache.delete(row);
    searchCache.delete(row);
  }

  const api = {
    el,
    /** Replace all rows. */
    setRows(rows) {
      pending = [];
      allRows = Array.isArray(rows) ? rows.slice() : [];
      shown = pageSize;
      view = null;
      render();
    },
    /** Append rows (batched per animation frame; safe to call once per streamed result). */
    addRows(rows) {
      const list = Array.isArray(rows) ? rows : [rows];
      if (!list.length) return;
      pending.push(...list);
      schedule();
    },
    /**
     * Re-render a row after mutating it, or replace a row by `rowKey` with a new object.
     * @returns {boolean} whether the row was found
     */
    updateRow(row) {
      flushPending();
      let idx = allRows.indexOf(row);
      if (idx === -1 && rowKey) idx = allRows.findIndex((r) => rowKey(r) === rowKey(row));
      if (idx === -1) return false;
      const old = allRows[idx];
      invalidate(old);
      if (old !== row && expanded.has(old)) expanded.add(row);
      allRows[idx] = row;
      view = null;
      schedule();
      return true;
    },
    /** updateRow, or addRows when the row (by identity or rowKey) is not present. */
    upsertRow(row) {
      if (!api.updateRow(row)) api.addRows([row]);
    },
    /** Remove a row by identity or by rowKey value. @returns {boolean} */
    removeRow(rowOrKey) {
      flushPending();
      let idx = allRows.indexOf(rowOrKey);
      if (idx === -1 && rowKey) idx = keyIndex().get(typeof rowOrKey === 'object' ? rowKey(rowOrKey) : rowOrKey) ?? -1;
      if (idx === -1) return false;
      invalidate(allRows[idx]);
      allRows.splice(idx, 1);
      view = null;
      schedule();
      return true;
    },
    /** Remove all rows. */
    clear() {
      api.setRows([]);
    },
    /** External predicate (e.g. "covered only" checkboxes); null removes it. */
    setFilter(fn) {
      filterFn = typeof fn === 'function' ? fn : null;
      shown = pageSize;
      view = null;
      render();
    },
    /** Set the search text programmatically (updates the box too). */
    setSearch(text) {
      query = String(text ?? '');
      if (searchInput) searchInput.value = query;
      shown = pageSize;
      view = null;
      render();
    },
    /** The search text the rows are filtered by ('' for none). */
    getSearch() {
      return query;
    },
    /** Sort by a column key ('asc'|'desc'); null clears sorting (insertion order). */
    sortBy(key, dir = 'asc') {
      sortState = key ? { key, dir: dir === 'desc' ? 'desc' : 'asc' } : null;
      view = null;
      renderHead();
      render();
    },
    /** Replace the column definitions (re-renders everything). */
    setColumns(cols) {
      columns = cols || [];
      allRows.forEach(invalidate);
      view = null;
      renderHead();
      render();
    },
    /** Empty-state content when there are no rows at all. */
    setEmpty(content) {
      emptyContent = content;
      render();
    },
    /** Show a spinner in the empty state (e.g. while the first results stream in). */
    setLoading(on) {
      loading = !!on;
      render();
    },
    /** All rows (insertion order). */
    getRows() {
      flushPending();
      return allRows.slice();
    },
    /** Rows passing filter + search, in display order (not limited by pagination). */
    getVisibleRows() {
      flushPending();
      return computeView().slice();
    },
    /** Current sort { key, dir } or null. */
    getSort() {
      return sortState ? { ...sortState } : null;
    },
    /** Force a re-render of every row (e.g. after changing data the renderers read). */
    refresh() {
      flushPending();
      allRows.forEach(invalidate);
      view = null;
      render();
    },
    /** Number of rows (including not-yet-flushed streamed rows). */
    get size() {
      return allRows.length + pending.length;
    }
  };

  renderHead();
  allRows = Array.isArray(initialRows) ? initialRows.slice() : [];
  render();
  return api;
}
