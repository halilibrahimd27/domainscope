/**
 * dom.js — tiny, safe DOM builder and helpers for the UI layer.
 *
 * Security model: untrusted strings (CT log names, TXT records, RDAP data, API
 * responses) only ever become Text nodes or attribute values. There is NO code
 * path here that parses HTML: `innerHTML`/`outerHTML` props are rejected,
 * inline event-handler attributes (`onclick="…"`) are rejected, and URL
 * attributes (`href`, `src`, `action`, …) refuse `javascript:`/`vbscript:`/`data:`
 * schemes. Inline styles are applied through the CSSOM (`el.style.setProperty`),
 * which the page CSP (`style-src 'self'`) allows, never via a `style` attribute.
 *
 * The document is resolved lazily (`globalThis.document` at call time), so the
 * module can be imported in Node and tested with a minimal fake document.
 *
 * @example
 *   import { h, clear } from './ui/dom.js';
 *   const row = h('div', { class: ['row', { active: isActive }], dataset: { id: host.name } },
 *     h('span', { class: 'mono', title: host.name }, host.name),   // untrusted → text node
 *     host.ips.length ? h('span', null, host.ips.join(', ')) : null, // null/false are skipped
 *     [badgeA, badgeB]);                                              // arrays are flattened
 *   clear(container);
 *   container.append(row);
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Attributes whose values are URLs and must not carry script-capable schemes. */
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'poster', 'cite', 'background']);

/** Props that are written as DOM properties (not attributes) when present. */
const PROPERTY_PROPS = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate', 'multiple',
  'readOnly', 'required', 'open', 'defaultValue', 'defaultChecked']);

/** Friendly prop aliases → real attribute names. */
const ATTR_ALIASES = { className: 'class', htmlFor: 'for', tabIndex: 'tabindex', readonly: 'readonly' };

/** Props that would let markup through; always refused. */
const FORBIDDEN_PROPS = new Set(['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'srcdoc']);

function doc() {
  const d = globalThis.document;
  if (!d) throw new Error('dom.js: no document available');
  return d;
}

/**
 * True for a plain object literal (props bag), false for Nodes, arrays, strings, component objects.
 * @param {unknown} v
 * @returns {boolean}
 */
export function isPlainObject(v) {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return (proto === Object.prototype || proto === null) && !('el' in v && isNode(v.el));
}

/**
 * Duck-typed Node check (works with the real DOM and simple fakes).
 * @param {unknown} v
 * @returns {boolean}
 */
export function isNode(v) {
  return !!v && typeof v === 'object' && typeof v.nodeType === 'number';
}

/**
 * Is `url` safe to put in an href/src? Relative URLs, '#…', http(s), mailto, tel and
 * blob: are allowed; javascript:, vbscript:, data: (and anything unknown) are not.
 * Control characters and whitespace that browsers strip before scheme parsing are
 * removed first, so 'java\nscript:' is caught too.
 * @param {unknown} url
 * @returns {boolean}
 */
export function isSafeUrl(url) {
  if (typeof url !== 'string') return false;
  // eslint-disable-next-line no-control-regex
  const cleaned = url.replace(/[\u0000- \u007f-\u009f]/g, '');
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(cleaned);
  if (!m) return true; // relative URL, fragment, or path
  return ['http', 'https', 'mailto', 'tel', 'blob'].includes(m[1].toLowerCase());
}

function setAttr(el, name, value) {
  if (value === null || value === undefined || value === false) {
    el.removeAttribute(name);
    return;
  }
  const lower = name.toLowerCase();
  if (lower.startsWith('on')) throw new Error(`dom.js: inline event handler attribute "${name}" is not allowed; use { on: { … } }`);
  if (lower === 'style') throw new Error('dom.js: style attributes are blocked by the CSP; pass style as an object');
  const str = value === true ? '' : String(value);
  if (URL_ATTRS.has(lower) && !isSafeUrl(str)) {
    // Refuse silently-but-safely: drop the attribute rather than render a script URL.
    el.removeAttribute(name);
    return;
  }
  if (lower === 'xlink:href') el.setAttributeNS('http://www.w3.org/1999/xlink', name, str);
  else el.setAttribute(name, str);
}

/**
 * Normalize a class value: string, array (nested ok) or { name: bool } map.
 * @param {unknown} value
 * @returns {string}
 */
export function classNames(value) {
  const out = [];
  const walk = (v) => {
    if (!v) return;
    if (typeof v === 'string') out.push(...v.split(/\s+/).filter(Boolean));
    else if (Array.isArray(v)) v.forEach(walk);
    else if (typeof v === 'object') for (const [k, on] of Object.entries(v)) if (on) out.push(k);
  };
  walk(value);
  return [...new Set(out)].join(' ');
}

function applyStyle(el, style) {
  if (!style) return;
  if (typeof style !== 'object') throw new Error('dom.js: style must be an object (CSP forbids style attributes)');
  for (const [prop, val] of Object.entries(style)) {
    if (val === null || val === undefined || val === false) continue;
    const name = prop.startsWith('--') ? prop : prop.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
    el.style.setProperty(name, String(val));
  }
}

function applyEvents(el, on) {
  if (!on) return;
  for (const [type, handler] of Object.entries(on)) {
    if (!handler) continue;
    if (Array.isArray(handler)) el.addEventListener(type, handler[0], handler[1]);
    else el.addEventListener(type, handler);
  }
}

/**
 * Apply a props bag to an element (used by {@link h} and {@link svg}).
 * @param {Element} el
 * @param {object|null|undefined} props
 * @returns {Element}
 */
export function applyProps(el, props) {
  if (!props) return el;
  for (const [rawKey, value] of Object.entries(props)) {
    if (FORBIDDEN_PROPS.has(rawKey)) throw new Error(`dom.js: "${rawKey}" is not allowed (untrusted HTML)`);
    switch (rawKey) {
      case 'class':
      case 'className': {
        const cls = classNames(value);
        if (cls) el.setAttribute('class', cls);
        break;
      }
      case 'text':
        if (value !== null && value !== undefined && value !== false) el.textContent = String(value);
        break;
      case 'attrs':
        for (const [k, v] of Object.entries(value || {})) setAttr(el, ATTR_ALIASES[k] || k, v);
        break;
      case 'dataset':
        for (const [k, v] of Object.entries(value || {})) {
          if (v !== null && v !== undefined && v !== false) el.dataset[k] = String(v);
        }
        break;
      case 'on':
        applyEvents(el, value);
        break;
      case 'style':
        applyStyle(el, value);
        break;
      case 'ref':
        break; // handled by the caller after children are appended
      default: {
        if (PROPERTY_PROPS.has(rawKey)) {
          if (value !== undefined) el[rawKey] = rawKey === 'value' || rawKey === 'defaultValue' ? String(value ?? '') : !!value;
          break;
        }
        if (rawKey === 'hidden') {
          el.hidden = !!value;
          break;
        }
        if (/^on[A-Z]/.test(rawKey) && typeof value === 'function') {
          // onClick: fn → addEventListener('click', fn)
          el.addEventListener(rawKey.slice(2).toLowerCase(), value);
          break;
        }
        setAttr(el, ATTR_ALIASES[rawKey] || rawKey, value);
      }
    }
  }
  return el;
}

/**
 * Append children: strings/numbers → Text nodes; Nodes as-is; component objects with an
 * `el` Node → their `el`; arrays/iterables flattened; null/undefined/false/true skipped.
 * @param {Node} parent
 * @param {...unknown} children
 * @returns {Node} parent
 */
export function append(parent, ...children) {
  const d = doc();
  const add = (child) => {
    if (child === null || child === undefined || child === false || child === true) return;
    if (Array.isArray(child)) {
      child.forEach(add);
      return;
    }
    if (isNode(child)) {
      parent.appendChild(child);
      return;
    }
    if (typeof child === 'object' && isNode(child.el)) {
      parent.appendChild(child.el);
      return;
    }
    if (typeof child === 'object' && typeof child[Symbol.iterator] === 'function' && typeof child !== 'string') {
      for (const c of child) add(c);
      return;
    }
    parent.appendChild(d.createTextNode(String(child)));
  };
  children.forEach(add);
  return parent;
}

function build(el, props, children) {
  let p = props;
  let kids = children;
  if (p !== null && p !== undefined && !isPlainObject(p)) {
    // h('div', 'text') / h('div', node) / h('div', [..]) — no props bag given.
    kids = [p, ...children];
    p = null;
  }
  // `value` is applied after the children so <select value="x"> finds its <option>s.
  const deferValue = !!p && Object.prototype.hasOwnProperty.call(p, 'value');
  if (deferValue) {
    const { value, ...rest } = p;
    applyProps(el, rest);
    append(el, ...kids);
    applyProps(el, { value });
  } else {
    applyProps(el, p);
    append(el, ...kids);
  }
  if (p && typeof p.ref === 'function') p.ref(el);
  return el;
}

/**
 * Create an HTML element safely.
 * @param {string} tag e.g. 'div', 'button'
 * @param {object|null} [props] class, text, attrs, dataset, on, style (object), aria-*, role,
 *   id, title, type, href, value, checked, disabled, hidden, ref(el), onClick… (see module doc)
 * @param {...unknown} children strings, numbers, Nodes, component objects ({ el }), arrays; null/false skipped
 * @returns {HTMLElement}
 */
export function h(tag, props, ...children) {
  return build(doc().createElement(tag), props, children);
}

/**
 * Create an SVG element (namespace-aware). Same props/children rules as {@link h}.
 * @param {string} tag e.g. 'svg', 'path', 'circle'
 * @param {object|null} [props]
 * @param {...unknown} children
 * @returns {SVGElement}
 */
export function svg(tag, props, ...children) {
  return build(doc().createElementNS(SVG_NS, tag), props, children);
}

/**
 * Text node helper.
 * @param {unknown} value
 * @returns {Text}
 */
export function text(value) {
  return doc().createTextNode(value === null || value === undefined ? '' : String(value));
}

/**
 * DocumentFragment with the given children.
 * @param {...unknown} children
 * @returns {DocumentFragment}
 */
export function frag(...children) {
  return append(doc().createDocumentFragment(), ...children);
}

/**
 * Remove all children of `el`.
 * @param {Node|null|undefined} el
 * @returns {Node|null|undefined}
 */
export function clear(el) {
  if (!el) return el;
  if (typeof el.replaceChildren === 'function') el.replaceChildren();
  else while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/**
 * Replace all children of `el` with `children` (same rules as {@link append}).
 * @param {Node} el
 * @param {...unknown} children
 * @returns {Node}
 */
export function mount(el, ...children) {
  clear(el);
  return append(el, ...children);
}

/**
 * querySelector shortcut.
 * @param {string} selector
 * @param {ParentNode} [root=document]
 * @returns {Element|null}
 */
export function qs(selector, root) {
  return (root || doc()).querySelector(selector);
}

/**
 * querySelectorAll → real Array.
 * @param {string} selector
 * @param {ParentNode} [root=document]
 * @returns {Element[]}
 */
export function qsa(selector, root) {
  return Array.from((root || doc()).querySelectorAll(selector));
}

/**
 * addEventListener that returns an "off" function.
 * @param {EventTarget} target
 * @param {string} type
 * @param {EventListener} handler
 * @param {AddEventListenerOptions|boolean} [options]
 * @returns {() => void}
 */
export function on(target, type, handler, options) {
  target.addEventListener(type, handler, options);
  return () => target.removeEventListener(type, handler, options);
}

let uidCounter = 0;

/**
 * Unique element id for aria-* wiring (`prefix-N`).
 * @param {string} [prefix='ui']
 * @returns {string}
 */
export function uid(prefix = 'ui') {
  uidCounter += 1;
  return `${prefix}-${uidCounter}`;
}

/**
 * Debounce: call `fn` once calls have stopped for `ms`. The returned function has
 * `.cancel()` and `.flush()`.
 * @template {(...args: any[]) => void} F
 * @param {F} fn
 * @param {number} [ms=150]
 * @returns {F & { cancel: () => void, flush: () => void }}
 */
export function debounce(fn, ms = 150) {
  let timer = null;
  let lastArgs = null;
  const debounced = (...args) => {
    lastArgs = args;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn(...lastArgs);
    }, ms);
  };
  debounced.cancel = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  debounced.flush = () => {
    if (!timer) return;
    clearTimeout(timer);
    timer = null;
    fn(...lastArgs);
  };
  return debounced;
}

/**
 * Visually hidden text for screen readers.
 * @param {string} value
 * @returns {HTMLSpanElement}
 */
export function srOnly(value) {
  return h('span', { class: 'sr-only' }, value);
}
