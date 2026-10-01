/**
 * What the start route downloads before the user types anything: index.html's scripts,
 * stylesheets and modulepreloads, the static import graph of app.js and of the default view,
 * and that view's stylesheets (VIEWS[].css). The heavy libraries — the discovery engine and the
 * DoH client, zoneparse, x509, health — must stay out of it (they load with the view that needs
 * them or on first use), and the whole stays under a byte budget (gzip, as GitHub Pages serves
 * it). Also checks the per-view stylesheet registry and the idle modulepreload list against the
 * sources, so neither can drift. No network, no browser.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VIEWS, DEFAULT_VIEW, VIEW_CSS_ORDER, ENGINE_MODULES, stylesheetBefore
} from '../../assets/js/app.js';
import * as scanner from '../../assets/js/lib/scanner.js';
import * as scanplan from '../../assets/js/lib/scanplan.js';
import * as sources from '../../assets/js/lib/sources.js';
import * as sourceinfo from '../../assets/js/lib/sourceinfo.js';
import { loadOnFirstUse } from '../../assets/js/views/subdomains.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ASSETS = join(ROOT, 'assets');
const JS = join(ASSETS, 'js');

/**
 * Gzip budget of the start route, in bytes (index.html, boot.js, style.css, app.js's module
 * graph, the default view's graph and stylesheet). Before the per-view stylesheets and the lazy
 * engine it was ≈ 368 KB (376,391 bytes); with them, and the service worker's page side, ≈ 258 KB (264,028 bytes).
 * Wave 2 put the shell's Tools menu and shortcuts, the page session, Copy summary and print, the
 * long-job progress, the Subdomains tabs and the Reverse DNS hand-off on it: ≈ 334 KB (342,043 bytes).
 * Customer workspaces put the workspace store on it (lib/workspace.js with the first-run
 * migration, the IndexedDB backend, the header switcher): every view reads its inventory at
 * mount, so the store opens before the first view — ≈ 355 KB (363,112 bytes). The Workspaces
 * dialog, the hand-over file and its encryption load on first use. A failed workspace write or
 * "Delete all local data" then said why in both languages (a full or blocked storage, another
 * tab holding the database — the browser's own message is English), and a write reads the
 * stored meta in its own transaction: ≈ 358 KB (366,942 bytes). A workspace whose creation could
 * not be written is stored by its next write, and "Delete all local data" also deletes a database
 * the page could not open: ≈ 359 KB (367,785 bytes). Wave 3's new tools — Renewal readiness,
 * Retire an IP and the Domain overview — each put a Copy summary builder with its strings in
 * lib/summary.js and an entry in the shell's navigation, and SSL Targets' several certificates a
 * few shared components: ≈ 368 KB (377,294 bytes). Wave 4's "What this page sent" ledger counts every
 * request from the first one, so its meter (the fetch wrapper and the Resource Timing observer,
 * ui/egress-meter.js) and its log (lib/egresslog.js) load with the shell, and the footer links to
 * it; the deploy's version file joined lib/pwa.js and the senders' notes (what a measurement body
 * carried, a registry's RDAP server) the log. With wave 4's other tools — their navigation
 * entries, FileDrop's `maxFiles`, one-decimal shares, a view's sub-pages (#/change/check) — and
 * every view's Copy summary builder still on it, the start route reached ≈ 379 KB (388,003 bytes).
 * The builders and texts of every view but the start view then moved to lib/summary.js, which
 * loads with the first view that has a Copy summary (ui/view-summaries.js); lib/summarycore.js
 * keeps the rendering, the registry and the Subdomains builder on the start route:
 * ≈ 364 KB (373,095 bytes), under the 370 KB budget it had before wave 4.
 * Raise it only for a reason you can name in the commit.
 */
const START_ROUTE_BUDGET = 370 * 1024;

/** Modules that must never be part of the start route (lib/summary.js: every view's Copy summary but the start view's). */
const HEAVY = ['lib/scanner.js', 'lib/sources.js', 'lib/doh.js', 'lib/dnswire.js', 'lib/zoneparse.js', 'lib/x509.js', 'lib/health.js',
  'lib/propagation.js', 'lib/ipintel.js', 'lib/zonedrift.js', 'lib/summary.js'];

const rel = (file) => relative(ROOT, file).split(sep).join('/');
const code = (file) => readFileSync(file, 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .split('\n').filter((line) => !/^\s*\/\//.test(line)).join('\n');

/**
 * Files reached from `entry` through static imports (`import … from`, `export … from`,
 * `import '…'`); dynamic `import()` is a separate download and is not followed.
 * @param {string} entry absolute path
 * @returns {string[]} absolute paths, entry first
 */
function staticGraph(entry) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    const src = code(file);
    for (const m of src.matchAll(/(?:^|[;\n])\s*(?:import|export)\s[^;'"]*?\bfrom\s*(['"])([^'"]+)\1/g)) queue.push(resolve(dirname(file), m[2]));
    for (const m of src.matchAll(/(?:^|[;\n])\s*import\s*(['"])([^'"]+)\1/g)) queue.push(resolve(dirname(file), m[2]));
  }
  return [...seen];
}

const gz = (file) => gzipSync(readFileSync(file)).length;
const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
const attrUrls = (re) => [...html.matchAll(re)].map((m) => join(ROOT, ...m[1].split('/')));
const defaultView = VIEWS.find((v) => v.id === DEFAULT_VIEW);

/** Every file the start route downloads (absolute paths, unique). */
function startRouteFiles() {
  const files = new Set([join(ROOT, 'index.html')]);
  for (const f of attrUrls(/<script src="([^"]+)"/g)) files.add(f);
  for (const f of attrUrls(/<link rel="(?:stylesheet|modulepreload)" href="([^"]+)"/g)) files.add(f);
  for (const f of staticGraph(join(JS, 'app.js'))) files.add(f);
  for (const f of staticGraph(join(JS, 'views', `${DEFAULT_VIEW}.js`))) files.add(f);
  for (const css of defaultView.css) files.add(join(ASSETS, 'css', ...css.split('/')));
  return [...files];
}

describe('the start route', () => {
  const files = startRouteFiles();

  test(`stays under the ${Math.round(START_ROUTE_BUDGET / 1024)} KB gzip budget`, () => {
    const sizes = files.map((f) => [rel(f), gz(f)]).sort((a, b) => b[1] - a[1]);
    const total = sizes.reduce((sum, [, n]) => sum + n, 0);
    assert.ok(total <= START_ROUTE_BUDGET,
      `${total} bytes > ${START_ROUTE_BUDGET}; largest: ${sizes.slice(0, 8).map(([f, n]) => `${f} ${n}`).join(', ')}`);
  });

  test('leaves the heavy libraries to the views that need them or to their first use', () => {
    const names = files.map(rel);
    assert.deepEqual(HEAVY.filter((m) => names.includes(`assets/js/${m}`)), []);
    assert.ok(names.includes('assets/js/lib/scanplan.js'), 'the plan line comes from lib/scanplan.js');
    assert.ok(names.includes('assets/js/lib/sourceinfo.js'), 'the source list comes from lib/sourceinfo.js');
  });

  test('loads one stylesheet from index.html and the default view\'s own with the view', () => {
    const sheets = files.map(rel).filter((f) => f.endsWith('.css')).sort();
    assert.deepEqual(sheets, ['assets/css/style.css', ...defaultView.css.map((c) => `assets/css/${c}`)].sort());
  });

  test('index.html modulepreloads exactly the static graph of app.js', () => {
    const preloads = attrUrls(/<link rel="modulepreload" href="([^"]+)"/g).map(rel).sort();
    assert.deepEqual(preloads, staticGraph(join(JS, 'app.js')).map(rel).sort());
  });
});

describe('the discovery engine loads on the first scan', () => {
  test('ENGINE_MODULES are what lib/scanner.js adds to the Subdomains view\'s own imports', () => {
    const view = new Set(staticGraph(join(JS, 'views', 'subdomains.js')).map(rel));
    const adds = staticGraph(join(JS, 'lib', 'scanner.js')).map(rel).filter((f) => !view.has(f));
    assert.deepEqual([...ENGINE_MODULES].map((m) => `assets/js/${m}`).sort(), adds.sort());
  });

  test('the views that scan preload the engine; every preload exists', () => {
    for (const v of VIEWS) {
      for (const m of v.preload) assert.ok(existsSync(join(JS, ...m.split('/'))), `${v.id}: ${m}`);
      const scans = /\brunScanner\(/.test(code(join(JS, 'views', `${v.id}.js`)));
      assert.equal(v.preload === ENGINE_MODULES || v.preload.join() === ENGINE_MODULES.join(), scans, `${v.id} preload`);
    }
  });

  test('lib/scanner.js and lib/sources.js re-export the view-side helpers unchanged', () => {
    for (const name of ['SCAN_STAGES', 'HOST_SPECIFIC_HINT_KINDS', 'estimateQueries', 'learnedLabelsFromScan']) {
      assert.equal(scanner[name], scanplan[name], name);
    }
    for (const name of ['SOURCES', 'sourceQuota', 'SOURCE_HEALTH_STATES', 'sourceHealthSummary']) {
      assert.equal(sources[name], sourceinfo[name], name);
    }
    for (const m of ['scanplan.js', 'sourceinfo.js']) {
      const graph = staticGraph(join(JS, 'lib', m)).map(rel);
      assert.deepEqual(HEAVY.filter((h) => graph.includes(`assets/js/${h}`)), [], `${m} stays light`);
    }
  });
});

describe('modules loaded on first use', () => {
  test('a failed load calls onLoadFailed (the shell\'s "older than the site" check) before it rejects', async () => {
    const calls = [];
    const err = new TypeError('Failed to fetch dynamically imported module');
    await assert.rejects(loadOnFirstUse(() => Promise.reject(err), () => calls.push('check')), (e) => e === err);
    assert.deepEqual(calls, ['check']);
    assert.equal(await loadOnFirstUse(() => Promise.resolve('module'), () => calls.push('check')), 'module');
    assert.deepEqual(calls, ['check'], 'not on success');
    await assert.rejects(loadOnFirstUse(() => Promise.reject(err)), (e) => e === err);
  });

  test('every owner lookup (lib/ipintel.js on first use) passes ctx.checkOutdated', () => {
    let calls = 0;
    for (const v of VIEWS) {
      for (const line of code(join(JS, 'views', `${v.id}.js`)).split('\n')) {
        if (!/\bnetworkOwner\(/.test(line) || /function networkOwner\(/.test(line)) continue;
        calls += 1;
        assert.match(line, /networkOwner\([^;]*, ctx\.checkOutdated\)/, `${v.id}: ${line.trim()}`);
      }
    }
    assert.equal(calls, 2, 'Subdomains and SSL Targets');
  });
});

describe('per-view stylesheets (VIEWS[].css)', () => {
  const viewCss = readdirSync(join(ASSETS, 'css', 'views')).filter((f) => f.endsWith('.css')).map((f) => `views/${f}`);

  test('VIEW_CSS_ORDER lists every view stylesheet once; each is used by a view and exists', () => {
    assert.deepEqual([...VIEW_CSS_ORDER].sort(), [...viewCss].sort());
    assert.equal(new Set(VIEW_CSS_ORDER).size, VIEW_CSS_ORDER.length);
    const used = new Set(VIEWS.flatMap((v) => v.css));
    assert.deepEqual(viewCss.filter((f) => !used.has(f)), [], 'a stylesheet no view loads');
    for (const v of VIEWS) {
      assert.ok(v.css.length > 0, `${v.id} has a stylesheet`);
      for (const f of v.css) assert.ok(VIEW_CSS_ORDER.includes(f), `${v.id}: ${f}`);
    }
  });

  test('a view loads every stylesheet whose classes its modules use', () => {
    const global = new Set([...readFileSync(join(ASSETS, 'css', 'style.css'), 'utf8').matchAll(/\.([a-z][\w-]*)/g)].map((m) => m[1]));
    const sheets = viewCss.map((file) => {
      const defined = [...new Set([...readFileSync(join(ASSETS, 'css', ...file.split('/')), 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/\.([a-z][\w-]*)/g)].map((m) => m[1]))].filter((c) => !global.has(c));
      // The sheet's own prefix (sub-, vfy-, glb-…): its most common first segment.
      const counts = new Map();
      for (const c of defined) counts.set(c.split('-')[0], (counts.get(c.split('-')[0]) || 0) + 1);
      const prefix = [...counts].sort((a, b) => b[1] - a[1])[0][0];
      return { file, classes: defined.filter((c) => c.startsWith(`${prefix}-`)) };
    });
    const missing = [];
    for (const v of VIEWS) {
      const tokens = new Set(staticGraph(join(JS, 'views', `${v.id}.js`)).flatMap((f) => code(f).match(/[a-z][\w-]*/g) || []));
      for (const { file, classes } of sheets) {
        const used = classes.filter((c) => tokens.has(c));
        // a stray token (a data attribute value, a comment) is not a use: a view renders several
        if (used.length >= 3 && !v.css.includes(file)) missing.push(`${v.id} → ${file} (${used.slice(0, 3).join(', ')})`);
      }
    }
    assert.deepEqual(missing, []);
  });

  test('stylesheetBefore keeps the injected sheets in VIEW_CSS_ORDER whatever view opened first', () => {
    assert.equal(stylesheetBefore('views/scan.css', []), null);
    assert.equal(stylesheetBefore('views/scan.css', ['views/dane.css', 'views/cert.css']), 'views/dane.css');
    assert.equal(stylesheetBefore('views/subdomains.css', ['views/scan.css']), 'views/scan.css');
    assert.equal(stylesheetBefore('views/about.css', ['views/subdomains.css', 'views/cert.css']), null);
    assert.equal(stylesheetBefore('views/unknown.css', ['views/about.css']), null, 'an unknown sheet goes last');
    // Opening Certificate, then SSL Targets, then Subdomains builds the same order as the reverse.
    const build = (files) => files.reduce((list, f) => {
      if (list.includes(f)) return list;
      const before = stylesheetBefore(f, list);
      const at = before ? list.indexOf(before) : list.length;
      return [...list.slice(0, at), f, ...list.slice(at)];
    }, []);
    const byView = (ids) => ids.flatMap((id) => VIEWS.find((v) => v.id === id).css);
    const a = build(byView(['cert', 'scan', 'subdomains', 'about']));
    const b = build(byView(['about', 'subdomains', 'scan', 'cert']));
    assert.deepEqual(a, b);
    assert.deepEqual(a, VIEW_CSS_ORDER.filter((f) => a.includes(f)));
  });
});
