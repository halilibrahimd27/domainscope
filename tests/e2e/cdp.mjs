/**
 * cdp.mjs — minimal headless Chrome/Edge driver over the Chrome DevTools Protocol.
 * No dependencies: Node 22's global WebSocket + child_process.
 *
 *   import { launchBrowser } from './cdp.mjs';
 *   const browser = await launchBrowser();                     // Chrome, falls back to Edge
 *   const page = await browser.newPage('http://127.0.0.1:8080/', { width: 390, height: 844, mobile: true });
 *   await page.waitFor(() => document.documentElement.dataset.appReady === 'true');
 *   await page.click('[data-control="theme"] [data-value="dark"]');
 *   await page.type('textarea', 'web01 10.0.0.1');
 *   await page.screenshot('tests/e2e/screenshots/x.png', { fullPage: true });
 *   console.log(page.problems());                              // console errors, exceptions, CSP violations
 *   await browser.close();                                     // kills the process, removes the profile
 *
 * Browser selection: `browser: 'chrome'|'edge'|'auto'` or `executablePath`, or the CHROME_PATH /
 * BROWSER_PATH environment variables.
 *
 * Cleanup: every launched browser is registered; when the suite process exits — normally, on an
 * uncaught error, or on SIGINT / SIGTERM / SIGHUP (e.g. run-all's --timeout-min) — the browser is
 * killed and its profile removed, even if the suite never reached `browser.close()`. A launch that
 * fails stops the browser it started before it throws.
 */

import { spawn } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const CANDIDATES = {
  chrome: [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium'
  ],
  edge: [
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/usr/bin/microsoft-edge',
    '/usr/bin/microsoft-edge-stable'
  ]
};

/**
 * Locate a Chromium-based browser.
 * @param {'auto'|'chrome'|'edge'} [preference='auto'] auto = Chrome, then Edge
 * @returns {{ name: string, path: string }|null}
 */
export function findBrowser(preference = 'auto') {
  const env = process.env.CHROME_PATH || process.env.BROWSER_PATH;
  if (env && existsSync(env)) return { name: path.basename(env), path: env };
  const order = preference === 'edge' ? ['edge', 'chrome'] : preference === 'chrome' ? ['chrome', 'edge'] : ['chrome', 'edge'];
  for (const name of order) {
    for (const p of CANDIDATES[name]) if (existsSync(p)) return { name, path: p };
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let profileCounter = 0;

/* ------------------------------------------------------------------------ */
/* Launched-browser registry: no orphaned browsers when a suite is killed   */
/* ------------------------------------------------------------------------ */

/** Browsers launched by this process that are not closed yet: ChildProcess → profile dir. */
const LIVE_BROWSERS = new Map();
let exitHooksInstalled = false;

/**
 * Kill every browser this process launched and still owns, and delete their profiles.
 * Synchronous, so it is safe inside a process 'exit' handler.
 * @returns {number} how many browsers were registered
 */
export function killLaunchedBrowsers() {
  const n = LIVE_BROWSERS.size;
  for (const [proc, profileDir] of LIVE_BROWSERS) killBrowserProcess(proc, profileDir);
  return n;
}

/**
 * Kill one launched browser if it still runs, forget it and delete its profile. Synchronous.
 * @param {import('node:child_process').ChildProcess} proc
 * @param {string} profileDir
 */
function killBrowserProcess(proc, profileDir) {
  try {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
  } catch {
    // already gone
  }
  try {
    rmSync(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    // still locked (Windows); run-all.mjs sweeps leftover .profile-<pid>-* folders
  }
  LIVE_BROWSERS.delete(proc);
}

/**
 * Register a launched browser for cleanup at process exit. Installs the exit / signal hooks once:
 * Node skips 'exit' handlers on an unhandled signal, so each signal handler kills the browsers and
 * then exits with the conventional 128+n code.
 * @param {import('node:child_process').ChildProcess} proc
 * @param {string} profileDir
 */
export function registerBrowserProcess(proc, profileDir) {
  LIVE_BROWSERS.set(proc, profileDir);
  if (exitHooksInstalled) return;
  exitHooksInstalled = true;
  process.once('exit', killLaunchedBrowsers);
  for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
    process.once(signal, () => {
      killLaunchedBrowsers();
      process.exit(code);
    });
  }
}

/** Forget a browser that was closed properly. */
function unregisterBrowserProcess(proc) {
  LIVE_BROWSERS.delete(proc);
}

/* ------------------------------------------------------------------------ */
/* Which resolver failures may an E2E suite tolerate?                        */
/* ------------------------------------------------------------------------ */

/** Chrome net errors that depend on the network the test runs from, not on the app. */
const NETWORK_ERROR_RE = /net::ERR_(?:TIMED_OUT|CONNECTION_[A-Z_]+|QUIC_[A-Z_]+|HTTP2_[A-Z_]+|NETWORK_CHANGED|NAME_NOT_RESOLVED|INTERNET_DISCONNECTED|ADDRESS_UNREACHABLE|EMPTY_RESPONSE|SSL_PROTOCOL_ERROR)\b/;
/** A resolver that answered but refused us: an app bug (URL, method, headers) until proven otherwise. */
const STATUS_OR_CORS_RE = /CORS policy|status of [45]\d\d|net::ERR_FAILED\b/i;

/**
 * Build a classifier for console / log problems that mention a public DoH resolver, shared by the
 * E2E suites so their tolerance stays consistent:
 * - resolvers outside `defaultChain`, or flagged `browserReliable: false`, are fully tolerated
 *   (they are optional, and some are unreadable in browsers by design);
 * - for DEFAULT-CHAIN resolvers only network-level failures are tolerated, at most
 *   `maxNetworkErrorsPerHost` per host; an HTTP status error or a CORS block is always an issue,
 *   because failover would otherwise hide a request the app builds wrongly for one resolver;
 * - `net::ERR_ABORTED` (the client cancelled: timeout, hedged request) is tolerated.
 * @param {{ resolvers: ReadonlyArray<{ id: string, url: string, browserReliable?: boolean }>,
 *   defaultChain: ReadonlyArray<string>, maxNetworkErrorsPerHost?: number }} opts
 * @returns {(text: string) => null | { host: string, tolerated: boolean, reason: string }}
 *   null when the text names none of the resolvers (not this classifier's business)
 */
export function resolverProblemFilter({ resolvers, defaultChain, maxNetworkErrorsPerHost = 2 }) {
  const chain = new Set(defaultChain);
  const hosts = resolvers.map((r) => ({ host: new URL(r.url).hostname, strict: chain.has(r.id) && r.browserReliable !== false }));
  const networkErrors = new Map();
  return (text) => {
    const s = String(text || '');
    const hit = hosts.find(({ host }) => s.includes(`//${host}/`) || s.includes(`//${host}:`) || s.includes(`//${host}?`));
    if (!hit) return null;
    const { host } = hit;
    if (!hit.strict) return { host, tolerated: true, reason: 'optional resolver (not in the default chain, or not browser-readable)' };
    if (STATUS_OR_CORS_RE.test(s)) return { host, tolerated: false, reason: 'default-chain resolver refused the request (HTTP status / CORS)' };
    if (/net::ERR_ABORTED\b/.test(s)) return { host, tolerated: true, reason: 'request cancelled by the client' };
    if (NETWORK_ERROR_RE.test(s)) {
      const n = (networkErrors.get(host) || 0) + 1;
      networkErrors.set(host, n);
      return n <= maxNetworkErrorsPerHost
        ? { host, tolerated: true, reason: `network failure ${n}/${maxNetworkErrorsPerHost}` }
        : { host, tolerated: false, reason: `more than ${maxNetworkErrorsPerHost} network failures from a default-chain resolver` };
    }
    return { host, tolerated: false, reason: 'unexpected failure from a default-chain resolver' };
  };
}

/** JSON-RPC over the browser WebSocket (flat sessions). */
class Connection {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map(); // `${sessionId||''}|${method}` → Set<fn>
    this.closed = false;
    ws.addEventListener('message', (ev) => this.#onMessage(ev));
    ws.addEventListener('close', () => this.#fail(new Error('CDP connection closed')));
    ws.addEventListener('error', () => this.#fail(new Error('CDP connection error')));
  }

  #fail(err) {
    this.closed = true;
    for (const { reject } of this.pending.values()) reject(err);
    this.pending.clear();
  }

  #onMessage(ev) {
    const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
    if (msg.id !== undefined) {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}${msg.error.data ? ` (${msg.error.data})` : ''}`));
      else p.resolve(msg.result);
      return;
    }
    const key = `${msg.sessionId || ''}|${msg.method}`;
    for (const fn of this.listeners.get(key) || []) fn(msg.params || {});
  }

  send(method, params = {}, sessionId = undefined) {
    if (this.closed) return Promise.reject(new Error(`CDP connection closed (${method})`));
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify(payload));
    });
  }

  on(method, fn, sessionId = undefined) {
    const key = `${sessionId || ''}|${method}`;
    if (!this.listeners.has(key)) this.listeners.set(key, new Set());
    this.listeners.get(key).add(fn);
    return () => this.listeners.get(key)?.delete(fn);
  }

  once(method, sessionId, predicate = () => true, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        off();
        reject(new Error(`Timed out waiting for ${method}`));
      }, timeoutMs);
      timer.unref?.(); // never keep the process alive just for this
      const off = this.on(method, (params) => {
        if (!predicate(params)) return;
        clearTimeout(timer);
        off();
        resolve(params);
      }, sessionId);
    });
  }

  close() {
    try {
      this.ws.close();
    } catch {
      // ignore
    }
  }
}

const KEYS = {
  Enter: { code: 'Enter', keyCode: 13, text: '\r' },
  Tab: { code: 'Tab', keyCode: 9 },
  Escape: { code: 'Escape', keyCode: 27 },
  Backspace: { code: 'Backspace', keyCode: 8 },
  Space: { key: ' ', code: 'Space', keyCode: 32, text: ' ' },
  ArrowLeft: { code: 'ArrowLeft', keyCode: 37 },
  ArrowUp: { code: 'ArrowUp', keyCode: 38 },
  ArrowRight: { code: 'ArrowRight', keyCode: 39 },
  ArrowDown: { code: 'ArrowDown', keyCode: 40 },
  Home: { code: 'Home', keyCode: 36 },
  End: { code: 'End', keyCode: 35 }
};

/** A browser tab attached through a flat CDP session. */
export class Page {
  constructor(conn, targetId, sessionId, viewport) {
    this.conn = conn;
    this.targetId = targetId;
    this.sessionId = sessionId;
    this.viewport = viewport;
    /** @type {Array<{ type: string, text: string, url?: string }>} */
    this.consoleMessages = [];
    /** @type {Array<{ text: string, url?: string, line?: number }>} */
    this.exceptions = [];
    /** @type {Array<{ source: string, level: string, text: string, url?: string }>} */
    this.logEntries = [];
    /** @type {Array<object>} CSP violations (Audits issues + securitypolicyviolation events) */
    this.cspViolations = [];
  }

  send(method, params = {}) {
    return this.conn.send(method, params, this.sessionId);
  }

  async _init() {
    const on = (m, fn) => this.conn.on(m, fn, this.sessionId);
    on('Runtime.consoleAPICalled', (p) => {
      const text = (p.args || []).map((a) => (a.value !== undefined ? String(a.value) : a.description || a.type)).join(' ');
      this.consoleMessages.push({ type: p.type, text, url: p.stackTrace?.callFrames?.[0]?.url });
    });
    on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails || {};
      this.exceptions.push({ text: d.exception?.description || d.text || 'exception', url: d.url, line: d.lineNumber });
    });
    on('Log.entryAdded', (p) => {
      const e = p.entry || {};
      this.logEntries.push({ source: e.source, level: e.level, text: e.text, url: e.url });
      if (/Content Security Policy/i.test(e.text || '')) this.cspViolations.push({ via: 'log', text: e.text, url: e.url });
    });
    on('Audits.issueAdded', (p) => {
      const issue = p.issue || {};
      if (issue.code === 'ContentSecurityPolicyIssue') this.cspViolations.push({ via: 'audits', details: issue.details });
    });
    await Promise.all([
      this.send('Page.enable'),
      this.send('Runtime.enable'),
      this.send('Log.enable'),
      this.send('Audits.enable').catch(() => {}),
      this.send('DOM.enable')
    ]);
    // Record CSP violations from inside the page as well (survives across our polling).
    await this.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', (e) => window.__cspViolations.push({
          directive: e.violatedDirective, blocked: e.blockedURI, source: e.sourceFile, line: e.lineNumber, sample: e.sample }));`
    });
    await this.setViewport(this.viewport);
  }

  /**
   * Resize/emulate the viewport.
   * @param {{ width: number, height: number, mobile?: boolean, deviceScaleFactor?: number }} vp
   */
  async setViewport({ width = 1440, height = 900, mobile = false, deviceScaleFactor = mobile ? 2 : 1 } = {}) {
    this.viewport = { width, height, mobile, deviceScaleFactor };
    await this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor, mobile, screenWidth: width, screenHeight: height });
    await this.send('Emulation.setTouchEmulationEnabled', { enabled: mobile, maxTouchPoints: mobile ? 5 : 1 });
  }

  /**
   * Emulate media features, e.g. { 'prefers-color-scheme': 'dark', 'prefers-reduced-motion': 'reduce' }.
   * Pass {} to reset.
   * @param {Record<string, string>} features
   */
  async emulateMedia(features = {}) {
    await this.send('Emulation.setEmulatedMedia', {
      features: Object.entries(features).map(([name, value]) => ({ name, value }))
    });
  }

  /**
   * Navigate and wait for the load event (hash-only changes resolve immediately).
   * @param {string} url
   * @param {{ timeout?: number }} [opts]
   */
  async goto(url, { timeout = 30000 } = {}) {
    const loaded = this.conn.once('Page.loadEventFired', this.sessionId, () => true, timeout);
    const res = await this.send('Page.navigate', { url });
    if (res.errorText) throw new Error(`goto ${url}: ${res.errorText}`);
    if (!res.loaderId) {
      loaded.catch(() => {});
      return; // same-document navigation
    }
    await loaded;
  }

  /**
   * Reload and wait for the load event.
   * @param {{ timeout?: number, ignoreCache?: boolean }} [opts] ignoreCache (default): a hard reload;
   *   false: a normal one, which a service worker answers
   */
  async reload({ timeout = 30000, ignoreCache = true } = {}) {
    const loaded = this.conn.once('Page.loadEventFired', this.sessionId, () => true, timeout);
    await this.send('Page.reload', { ignoreCache });
    await loaded;
  }

  /**
   * Evaluate an expression string, or a function with JSON-serialisable arguments, in the page.
   * Promises are awaited; the result is returned by value.
   * @param {string|Function} exprOrFn
   * @param {...any} args
   * @returns {Promise<any>}
   */
  async evaluate(exprOrFn, ...args) {
    const expression = typeof exprOrFn === 'function'
      ? `(${exprOrFn.toString()})(...${JSON.stringify(args)})`
      : String(exprOrFn);
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (r.exceptionDetails) {
      const d = r.exceptionDetails;
      throw new Error(`evaluate failed: ${d.exception?.description || d.text}`);
    }
    return r.result ? r.result.value : undefined;
  }

  /**
   * Poll until `exprOrFn` is truthy; returns its value.
   * @param {string|Function} exprOrFn
   * @param {{ timeout?: number, interval?: number, args?: any[], message?: string }} [opts]
   */
  async waitFor(exprOrFn, { timeout = 10000, interval = 80, args = [], message = '' } = {}) {
    const deadline = Date.now() + timeout;
    let lastErr = null;
    for (;;) {
      try {
        const v = await this.evaluate(exprOrFn, ...args);
        if (v) return v;
      } catch (err) {
        lastErr = err;
      }
      if (Date.now() > deadline) {
        const what = message || (typeof exprOrFn === 'function' ? exprOrFn.toString().slice(0, 140) : exprOrFn);
        throw new Error(`waitFor timed out after ${timeout} ms: ${what}${lastErr ? ` (last error: ${lastErr.message})` : ''}`);
      }
      await sleep(interval);
    }
  }

  /** Wait for a selector to match a rendered (non-zero size) element. */
  waitForSelector(selector, opts = {}) {
    return this.waitFor((sel) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }, { ...opts, args: [selector], message: `selector ${selector}` });
  }

  /**
   * Real mouse click in the middle of the first element matching `selector` (scrolled into view).
   * @param {string} selector
   */
  async click(selector) {
    const box = await this.evaluate(async (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      // A smooth scroll still in flight (the app's own, e.g. to the results after "Start scan")
      // keeps moving the page after the jump: measure once two frames agree, or the click misses.
      const frame = () => new Promise((r) => {
        requestAnimationFrame(r);
        setTimeout(r, 100); // a background tab may not paint
      });
      const centre = () => {
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height };
      };
      let box = null;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        el.scrollIntoView({ block: 'center', inline: 'center' });
        let last = '';
        for (let i = 0; i < 60; i += 1) {
          await frame();
          box = centre();
          const now = `${Math.round(box.x)},${Math.round(box.y)}`;
          if (now === last) break;
          last = now;
        }
        if (box.x >= 0 && box.y >= 0 && box.x <= innerWidth && box.y <= innerHeight) break;
      }
      return box;
    }, selector);
    if (!box) throw new Error(`click: no element matches ${selector}`);
    if (!box.w || !box.h) throw new Error(`click: element ${selector} is not visible`);
    const base = { x: box.x, y: box.y, button: 'left', clickCount: 1 };
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', ...base });
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...base });
  }

  /**
   * Focus an input/textarea and type text (insertText → real `input` events).
   * @param {string} selector
   * @param {string} text
   * @param {{ replace?: boolean }} [opts] replace (default) clears the field first
   */
  async type(selector, text, { replace = true } = {}) {
    const ok = await this.evaluate((sel, rep) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      el.focus();
      if (rep && 'value' in el) {
        el.select?.();
        if (el.value) document.execCommand('delete');
      }
      return true;
    }, selector, replace);
    if (!ok) throw new Error(`type: no element matches ${selector}`);
    await this.send('Input.insertText', { text });
  }

  /**
   * Press a key (Enter, Tab, Escape, Arrow*, Home, End, Backspace, Space or a single character),
   * optionally with modifiers (e.g. `{ ctrl: true }` for Ctrl+Enter).
   * @param {string} key
   * @param {{ shift?: boolean, ctrl?: boolean, alt?: boolean, meta?: boolean }} [opts]
   */
  async press(key, { shift = false, ctrl = false, alt = false, meta = false } = {}) {
    const def = KEYS[key] || { key, code: key.length === 1 ? `Key${key.toUpperCase()}` : key, keyCode: key.length === 1 ? key.toUpperCase().charCodeAt(0) : 0, text: key.length === 1 ? key : undefined };
    // No nativeVirtualKeyCode (Puppeteer and Playwright send none either): the page gets the same
    // keydown without it, but with it Chrome on macOS also acts on a key the page leaves alone.
    // An Escape, arrow, Home, End or Backspace then opens chrome://settings/help in front of the
    // page, which goes hidden: no more rAF, throttled timers, and every later wait times out.
    const params = {
      key: def.key || key,
      code: def.code,
      windowsVirtualKeyCode: def.keyCode,
      // CDP modifier bits: Alt 1, Ctrl 2, Meta 4, Shift 8.
      modifiers: (alt ? 1 : 0) | (ctrl ? 2 : 0) | (meta ? 4 : 0) | (shift ? 8 : 0)
    };
    await this.send('Input.dispatchKeyEvent', { type: def.text ? 'keyDown' : 'rawKeyDown', ...params, text: def.text });
    await this.send('Input.dispatchKeyEvent', { type: 'keyUp', ...params });
  }

  /**
   * Set files on an <input type=file> (fires input/change like a real pick).
   * @param {string} selector
   * @param {string[]} files absolute or cwd-relative paths
   */
  async setFileInput(selector, files) {
    const { root } = await this.send('DOM.getDocument', { depth: 0 });
    const { nodeId } = await this.send('DOM.querySelector', { nodeId: root.nodeId, selector });
    if (!nodeId) throw new Error(`setFileInput: no element matches ${selector}`);
    await this.send('DOM.setFileInputFiles', { nodeId, files: files.map((f) => path.resolve(f)) });
  }

  /**
   * PNG screenshot. fullPage temporarily grows the viewport to the document height.
   * @param {string} file
   * @param {{ fullPage?: boolean, maxHeight?: number }} [opts]
   */
  async screenshot(file, { fullPage = false, maxHeight = 12000 } = {}) {
    await mkdir(path.dirname(path.resolve(file)), { recursive: true });
    const vp = { ...this.viewport };
    if (fullPage) {
      // Growing the viewport changes vh-based sizes (e.g. max-height: 70vh), which changes the
      // document height again — iterate until it is stable.
      let height = vp.height;
      for (let i = 0; i < 5; i += 1) {
        const next = Math.min(maxHeight, await this.evaluate(() => Math.ceil(Math.max(
          document.documentElement.scrollHeight, document.body.scrollHeight, window.innerHeight))));
        if (next === height && i > 0) break;
        height = next;
        await this.send('Emulation.setDeviceMetricsOverride', {
          width: vp.width, height, deviceScaleFactor: vp.deviceScaleFactor, mobile: vp.mobile,
          screenWidth: vp.width, screenHeight: height
        });
        await sleep(100); // let layout settle (sticky elements, vh units)
      }
    }
    try {
      const { data } = await this.send('Page.captureScreenshot', { format: 'png', fromSurface: true });
      await writeFile(file, Buffer.from(data, 'base64'));
    } finally {
      if (fullPage) await this.setViewport(vp);
    }
  }

  /** Collected problems: console errors/asserts, exceptions, error log entries, CSP violations. */
  async problems() {
    let pageCsp = [];
    try {
      pageCsp = (await this.evaluate('window.__cspViolations || []')) || [];
    } catch {
      pageCsp = [];
    }
    return {
      consoleErrors: this.consoleMessages.filter((m) => m.type === 'error' || m.type === 'assert'),
      exceptions: this.exceptions.slice(),
      logErrors: this.logEntries.filter((e) => e.level === 'error'),
      csp: [...this.cspViolations, ...pageCsp.map((v) => ({ via: 'event', ...v }))]
    };
  }

  /** Forget collected messages (e.g. between test phases). */
  resetProblems() {
    this.consoleMessages.length = 0;
    this.exceptions.length = 0;
    this.logEntries.length = 0;
    this.cspViolations.length = 0;
    return this.evaluate('window.__cspViolations = []').catch(() => {});
  }

  /** Close the tab. */
  async close() {
    await this.conn.send('Target.closeTarget', { targetId: this.targetId }).catch(() => {});
  }
}

/** A launched browser process + its CDP connection. */
export class Browser {
  constructor({ proc, conn, profileDir, name, executablePath }) {
    this.proc = proc;
    this.conn = conn;
    this.profileDir = profileDir;
    this.name = name;
    this.executablePath = executablePath;
    this.pages = [];
  }

  /**
   * Open a new tab.
   * @param {string} [url='about:blank']
   * @param {{ width?: number, height?: number, mobile?: boolean, deviceScaleFactor?: number }} [viewport]
   * @returns {Promise<Page>}
   */
  async newPage(url = 'about:blank', viewport = {}) {
    const { targetId } = await this.conn.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await this.conn.send('Target.attachToTarget', { targetId, flatten: true });
    const page = new Page(this.conn, targetId, sessionId, { width: 1440, height: 900, mobile: false, ...viewport });
    await page._init();
    if (url && url !== 'about:blank') await page.goto(url);
    this.pages.push(page);
    return page;
  }

  /** Version info (product, revision, userAgent). */
  version() {
    return this.conn.send('Browser.getVersion');
  }

  /** Close the browser, kill the process if needed and delete the temporary profile. */
  async close() {
    try {
      await Promise.race([this.conn.send('Browser.close'), sleep(3000)]);
    } catch {
      // already gone
    }
    this.conn.close();
    unregisterBrowserProcess(this.proc);
    const exited = await Promise.race([
      new Promise((r) => {
        if (this.proc.exitCode !== null) r(true);
        else this.proc.once('exit', () => r(true));
      }),
      sleep(5000).then(() => false)
    ]);
    if (!exited) {
      try {
        this.proc.kill('SIGKILL');
      } catch {
        // ignore
      }
      await sleep(300);
    }
    await rm(this.profileDir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 }).catch(() => {});
  }
}

/**
 * Launch headless Chrome (fallback Edge) with a throw-away profile under tests/e2e/.profile-<n>.
 * @param {{ browser?: 'auto'|'chrome'|'edge', executablePath?: string, headless?: boolean, args?: string[],
 *   profileRoot?: string, timeout?: number, lang?: string }} [opts] `lang` is the browser's UI and
 *   page language (navigator.languages, Accept-Language) on every OS, en-US by default
 * @returns {Promise<Browser>}
 */
export async function launchBrowser({
  browser = 'auto', executablePath = null, headless = true, args = [], profileRoot = HERE, timeout = 30000, lang = 'en-US'
} = {}) {
  // Node 20 and 21 have no global WebSocket: say so before starting a browser nothing could reach.
  if (typeof WebSocket !== 'function') throw new Error(`cdp.mjs needs Node 22 or later (for its global WebSocket); this is Node ${process.versions.node}.`);
  const found = executablePath ? { name: path.basename(executablePath), path: executablePath } : findBrowser(browser);
  if (!found) throw new Error('No Chrome or Edge installation found (set CHROME_PATH).');
  profileCounter += 1;
  const profileDir = path.join(profileRoot, `.profile-${process.pid}-${profileCounter}`);
  await rm(profileDir, { recursive: true, force: true }).catch(() => {});
  await mkdir(profileDir, { recursive: true });
  const flags = [
    headless ? '--headless=new' : null,
    '--remote-debugging-port=0',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-sync',
    '--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication',
    '--metrics-recording-only',
    '--mute-audio',
    '--password-store=basic',
    '--hide-scrollbars',
    '--force-color-profile=srgb',
    `--lang=${lang}`,
    // navigator.languages and Accept-Language: Chrome on macOS ignores --lang and takes them from
    // the system languages, so on a Turkish Mac the app would boot in Turkish.
    `--accept-lang=${lang}`,
    '--window-size=1440,900',
    // A mouse on every OS: headless Chrome on Linux sees no input device, so without this a
    // desktop page is `(hover: none) and (pointer: none)` there but `hover` + `fine` on Windows
    // and macOS. Phone pages still get `coarse` from setViewport's touch emulation (on Linux a
    // page turned back from a phone reads `none` again until its next load).
    headless ? '--blink-settings=primaryPointerType=4,availablePointerTypes=4,primaryHoverType=2,availableHoverTypes=2' : null,
    ...args,
    'about:blank'
  ].filter(Boolean);
  const proc = spawn(found.path, flags, { stdio: ['ignore', 'ignore', 'pipe'] });
  registerBrowserProcess(proc, profileDir);
  let stderr = '';
  proc.stderr.on('data', (d) => {
    stderr = (stderr + d.toString()).slice(-4000);
  });
  try {
    const portFile = path.join(profileDir, 'DevToolsActivePort');
    const deadline = Date.now() + timeout;
    let wsUrl = null;
    while (!wsUrl) {
      if (proc.exitCode !== null) throw new Error(`${found.name} exited early (code ${proc.exitCode}): ${stderr}`);
      if (Date.now() > deadline) throw new Error(`${found.name} did not expose DevToolsActivePort within ${timeout} ms`);
      try {
        const [port, wsPath] = (await readFile(portFile, 'utf8')).split(/\r?\n/);
        if (port && wsPath) wsUrl = `ws://127.0.0.1:${port.trim()}${wsPath.trim()}`;
      } catch {
        // not written yet
      }
      if (!wsUrl) await sleep(50);
    }
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', () => reject(new Error(`Could not connect to ${wsUrl}`)), { once: true });
    });
    const conn = new Connection(ws);
    return new Browser({ proc, conn, profileDir, name: found.name, executablePath: found.path });
  } catch (err) {
    // The caller gets no Browser to close, so stop this one now: a running child would keep the
    // suite's process alive after its error.
    killBrowserProcess(proc, profileDir);
    throw err;
  }
}
