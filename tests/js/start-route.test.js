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
 * ≈ 365 KB (373,256 bytes), under the 370 KB budget it had before wave 4. Global DNS's mainland
 * China locations (lib/resolvers.js) and the Chinese CDNs recognised by CNAME (lib/netinfo.js), both
 * on the start route, added ≈ 2 KB: ≈ 367 KB (375,666 bytes). The Domain portfolio's navigation
 * entry and the workspace's policy part added ≈ 0.5 KB: ≈ 367 KB (376,219 bytes). Zone File's Compare
 * and Convert load with their tab (≈ 0.1 KB on the route); the inventory's topology keys
 * (lib/inventory.js) added ≈ 4 KB: ≈ 371 KB (380,394 bytes), over the budget. The provider ranges
 * and the answer classification of lib/netinfo.js (12 KB), which only the discovery engine and the
 * views that classify answers use, then left the start route: the IP parsing and CIDR math the
 * shell, the workspace's inventory and the Copy summary need are in lib/ip.js (4 KB), which
 * netinfo.js re-exports: ≈ 364 KB (372,300 bytes). The origin map (lib/originmap.js, which the
 * workspace store and every scan read, and the Subdomains view's rows of remembered origins) added
 * ≈ 5.5 KB: ≈ 369 KB (377,888 bytes), 992 bytes under the budget.
 * Wave 6's correctness fixes in start-route modules (the shell, the workspace store, the Subdomains
 * view, the summary core) together added ≈ 1.6 KB: ≈ 371 KB (379,552 bytes), over the budget, which
 * was 372 KB until the start-route diet. The diet moved a Subdomains scan's progress and results —
 * the run header, the stage pills and the four result tabs (ui/subdomains-run.js), the 199 strings
 * only they use, lib/export.js and lib/subtabs.js — off the start route: they load with the first
 * scan, together with the DoH client, and the shell modulepreloads them once the page is idle; the
 * sidebar's denser groups for 24 tools added a few bytes to style.css: ≈ 332 KB (339,887 bytes).
 * The Takeover risks card's hook (ui/takeover-panel.js, with its engine) sits in ui/subdomains-run.js
 * with the rest of a scan's results, so it adds nothing to the route.
 * The workspace's CT watch baseline part (lib/workspace.js `ctSeen`, the JSON text lib/ctwatch.js
 * reads, which loads with the Domain portfolio's CT tab) added 80 bytes.
 * The command palette keeps only its key (Ctrl/Cmd+K, lib/shellnav.js), the header button, the
 * shortcut list's row, the lazy import and i18n.js's `stringIn` on the route; ui/palette.js,
 * lib/palette.js and palette.css load on its first use: 401 bytes.
 * With every wave 6 feature merged (the workspace's Rollout part and the provider ranges' precache
 * skip in lib/pwa.js included): ≈ 333 KB (340,510 bytes), 38,370 bytes under the budget.
 * With wave 7 merged: ≈ 334 KB (342,523 bytes), 36,357 bytes under the budget. The adaptive locale packs'
 * hooks in lib/wordlist.js, lib/dnsmine.js, lib/scanplan.js and the Subdomains view added 2,013 bytes; their
 * panel (ui/locale-evidence.js) loads with the run header of a scan, and DNS Lookup's Explain and Global DNS's
 * name server probe load on first use too.
 * With wave 7b merged (the domain security score and the DMARC sender names): ≈ 335 KB (342,650 bytes), 36,230 bytes
 * under the budget. The one start-route file that grew is lib/pwa.js (127 bytes): its precache skip list names the two
 * sender lists. The score's panel and libraries load with the portfolio's Domain security tab, and lib/senders.js with
 * the views that use it.
 * With the rest of wave 7b merged (the runner's alerts, the takeover watch with Domain Health's Dependencies card, and the renewal
 * radar): ≈ 335 KB (342,873 bytes), 36,007 bytes under the budget. The one start-route file that grew is assets/css/style.css
 * (223 bytes): the Takeover risks table's styles, which Subdomains' results and the Dependencies card share. The revocation card and
 * its libraries load with the Certificate view and the portfolio's CT tab, and the runner's modules are not in the Pages bundle.
 * With the third batch of wave 7b merged (accepted risks, the served-certificate monitor, the registration and record change watch,
 * the DMARC report history and the Monitoring view): ≈ 335 KB (343,478 bytes), 35,402 bytes under the budget. Six start-route files
 * grew, by 605 bytes together: lib/workspace.js (261: the workspace parts rdapSeen, waivers and reportHistory) and, for the Monitoring
 * view, its navigation entry (app.js, 57), its two strings in both languages (i18n.js, 248), its Copy summary kind
 * (lib/summarycore.js, 20; ui/summary-button.js, 6) and the masking of a GitHub repository's owner and name in request signatures
 * (lib/egresslog.js, 13). The view, its libraries (lib/monitor.js, lib/monitorfetch.js, lib/monitorsummary.js, lib/runreport.js) and
 * its stylesheet load on its first visit; the waiver dialog, the History tab and the registration watch load with the view that uses them.
 * With the content audit and the batched nits pass merged (after wave 7b): ≈ 336 KB (343,878 bytes), 35,002 bytes under the budget. Two start-route
 * files grew, by 400 bytes together: views/subdomains.js (388: `originExport`, the `origin` block of the JSON export that Subdomains and SSL Targets
 * share, with the Exclude box's tokens applied) and app.js (12: the Subdomains view's idle modulepreload names lib/originnow.js). The content audit
 * is a CLI; its card is in views/about.js, which loads on the first visit to About.
 * UI redesign phase 1a (docs/DESIGN.md §8: the tokens and the base components): ≈ 341 KB (348,984 bytes), 29,896 bytes under the budget.
 * style.css grew by 3,320 bytes (the type, spacing, density, layer and colour-role tokens in both themes, the compact and touch blocks,
 * tags, chips and the tabs' faded overflow) and ui/components.js by 1,510 (Tag, Chip, the tabs' "more" chevron, two icons).
 * Phase 1b (the shell and its navigation by job: the header's search, the tablet drawer, the phone bar and its Tools sheet with
 * the palette's box, the page header's purpose line and ⓘ): ≈ 346 KB (354,669 bytes), 24,211 bytes under the budget. app.js
 * grew by 2,623 bytes, i18n.js by 894 (the purpose lines and the six group names in both languages), style.css by 1,148;
 * ui/palette.js stays off the route (the sheet loads it on its first open, as Ctrl/⌘+K does).
 * Phase 1c (Home is the start page, docs/DESIGN.md §4): ≈ 267 KB (273,594 bytes), 105,286 bytes under the budget. The
 * Subdomains view's graph beyond app.js and subdomains.css left the route; Home came on it — views/home.js (11,349 bytes: its
 * strings in both languages), views/home.css (2,896), MenuButton in ui/components.js (2,442), ui/jobs.js's jobList / onJobs (495)
 * and a result's status in lib/session.js (383); ui/start-tasks.js is now Home's, no longer app.js's. Home's counts
 * (lib/homedigest.js with the owners' readers), the DMARC history and the palette load after its first paint or on first use.
 * Phase 1's review fixes: ≈ 269 KB (275,412 bytes), 103,468 bytes under the budget. ui/components.js grew by 811 bytes (RelativeTime, Home's
 * relative times as a <time> with the absolute local time and its UTC offset in the title, and MenuButton's type-ahead), views/home.js by 467,
 * i18n.js by 228 (formatDateTime's `offset`, utcOffsetLabel), app.js by 193 (a purpose line of text and nodes) and style.css by 119 (the
 * sidebar's privacy line wraps).
 * Phase 2 (the page template and Investigate a domain, docs/DESIGN.md §8): ≈ 273 KB (279,382 bytes), 99,498 bytes under the budget.
 * style.css grew by 2,829 bytes (the template's regions: the input card, the run bar and its phone copy, the result header, the status
 * summary, the metric strip, the empty state), ui/session-ui.js by 393 (keptSlotOf, where the kept-result note goes), ui/summary-button.js
 * by 335 (the ¶ button, and copy() for a menu item), app.js by 247 (the kept-result note in the result header's slot) and ui/components.js
 * by 166 (the ¶ icon, CopyButton's icon, MenuButton's visible label). ui/template.js and lib/template.js load with the four tools,
 * never with Home.
 * Phase 3 (Deploy & renew certificates on the template, docs/DESIGN.md §8): ≈ 273 KB (280,031 bytes), 98,849 bytes under the budget.
 * The one start-route file that grew is style.css, by 649 bytes: the template's phase 3 parts — the file input card, the findings list
 * (its "n more" a 24 px target, 40 px on a touch screen), the run bar's grouped and sticky variants, Run in the input's footer.
 * lib/certtools.js loads with SSL Targets and the Certificate view. The four tools' own sheets, off the route, shrank by 764 bytes
 * together (scan.css 67, cert.css 832 — the old overview card's rules —, renew.css 178; estate.css grew by 313 with its figures band),
 * though gzip takes 555 bytes more of them: what left them compressed better than what came.
 * Raise it only for a reason you can name in the commit.
 */
const START_ROUTE_BUDGET = 370 * 1024;

/**
 * Modules that must never be part of the start route (lib/summary.js: every view's Copy summary but the start view's; lib/netinfo.js:
 * the provider tables, the shell needs only lib/ip.js; the palette: Ctrl/⌘+K, the phone Tools sheet and Home's quick start load it on
 * their first use; lib/homedigest.js: Home's counts, with the readers it imports, after Home's first paint; ui/template.js: the result
 * template of the redesign's phase 2, with its views).
 */
const HEAVY = ['lib/scanner.js', 'lib/sources.js', 'lib/doh.js', 'lib/dnswire.js', 'lib/zoneparse.js', 'lib/x509.js', 'lib/health.js',
  'lib/propagation.js', 'lib/ipintel.js', 'lib/zonedrift.js', 'lib/summary.js', 'lib/topology.js', 'lib/netinfo.js', 'ui/palette.js', 'lib/palette.js',
  'lib/homedigest.js', 'lib/ctseen.js', 'lib/regwatch.js', 'lib/waivers.js', 'lib/rollout.js', 'lib/dmarchistory.js', 'lib/ctwatch.js', 'ui/template.js'];

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
    assert.equal(DEFAULT_VIEW, 'home');
    assert.ok(!names.includes('assets/js/views/subdomains.js'), 'Subdomains is no longer the start view');
    // Home loads its counts with a dynamic import() after its first paint, and the DMARC history in an idle moment.
    const home = code(join(JS, 'views', 'home.js'));
    assert.match(home, /import\('\.\.\/lib\/homedigest\.js'\)/);
    assert.match(home, /import\('\.\.\/lib\/dmarchistory\.js'\)/);
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

describe('the Subdomains view graph', () => {
  test('the plan line and the source list come from their light modules, without the heavy libraries', () => {
    const names = staticGraph(join(JS, 'views', 'subdomains.js')).map(rel);
    assert.ok(names.includes('assets/js/lib/scanplan.js'), 'the plan line comes from lib/scanplan.js');
    assert.ok(names.includes('assets/js/lib/sourceinfo.js'), 'the source list comes from lib/sourceinfo.js');
    // The page template is the view's own (HEAVY lists it only to keep it off the start route).
    assert.ok(names.includes('assets/js/ui/template.js'), 'the view draws with the page template');
    assert.deepEqual(HEAVY.filter((m) => m !== 'ui/template.js' && names.includes(`assets/js/${m}`)), []);
  });
});

describe('the discovery engine loads on the first scan', () => {
  test('ENGINE_MODULES are what lib/scanner.js adds to the Subdomains view\'s own imports', () => {
    const view = new Set(staticGraph(join(JS, 'views', 'subdomains.js')).map(rel));
    const adds = staticGraph(join(JS, 'lib', 'scanner.js')).map(rel).filter((f) => !view.has(f));
    assert.deepEqual([...ENGINE_MODULES].map((m) => `assets/js/${m}`).sort(), adds.sort());
  });

  test('the views that scan preload the engine first; every preload exists', () => {
    for (const v of VIEWS) {
      for (const m of v.preload) assert.ok(existsSync(join(JS, ...m.split('/'))), `${v.id}: ${m}`);
      const scans = /\brunScanner\(/.test(code(join(JS, 'views', `${v.id}.js`)));
      // After the engine, a scanning view may preload what its runs draw with (Subdomains: ui/subdomains-run.js).
      assert.equal(v.preload.slice(0, ENGINE_MODULES.length).join() === ENGINE_MODULES.join(), scans, `${v.id} preload`);
    }
  });

  test('a Subdomains scan loads its progress and results (ui/subdomains-run.js) with the DoH client, and the shell preloads them', () => {
    const view = code(join(JS, 'views', 'subdomains.js'));
    assert.match(view, /\[dns, runUi\] = await Promise\.all\(\[ctx\.getDns\(\), loadOnFirstUse\(loadRunUi, ctx\.checkOutdated\)\]\);/);
    assert.match(view, /export const loadRunUi = onceAsync\(\(\) => import\('\.\.\/ui\/subdomains-run\.js'\)\);/);
    // What the Subdomains view has loaded by the time it scans: the start route and its own graph.
    const route = new Set([...startRouteFiles(), ...staticGraph(join(JS, 'views', 'subdomains.js'))].map(rel));
    const runGraph = staticGraph(join(JS, 'ui', 'subdomains-run.js')).map(rel).filter((f) => !route.has(f));
    const preload = VIEWS.find((v) => v.id === 'subdomains').preload.map((m) => `assets/js/${m}`);
    assert.deepEqual(runGraph.filter((f) => !preload.includes(f)), [], 'every module the run UI adds to the route is preloaded');
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
    // The Subdomains view looks owners up from its run's ORIGIN panel (ui/subdomains-run.js).
    for (const file of [...VIEWS.map((v) => `views/${v.id}.js`), 'ui/subdomains-run.js']) {
      for (const line of code(join(JS, ...file.split('/'))).split('\n')) {
        if (!/\bnetworkOwner\(/.test(line) || /function networkOwner\(/.test(line)) continue;
        calls += 1;
        assert.match(line, /networkOwner\([^;]*, ctx\.checkOutdated\)/, `${file}: ${line.trim()}`);
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
