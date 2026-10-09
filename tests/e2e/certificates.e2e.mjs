#!/usr/bin/env node
/**
 * certificates.e2e.mjs — end-to-end test of the page template (ui/template.js, lib/template.js,
 * lib/certtools.js; docs/DESIGN.md §5 and §8 phase 3) on the four tools of "Deploy & renew
 * certificates": SSL Targets, Certificate, Renewal readiness and Certificate estate, in a real
 * headless Chrome/Edge. OFFLINE: the DNS of example.net is answered inside the page
 * (scan.e2e.mjs zoneHandoffScript), every other request that leaves the page fails there, and a
 * network-level guard fails and records any https request that would still go out — the suite
 * asserts none.
 *
 *   node tests/e2e/certificates.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the empty template of each tool: SSL Targets' wizard (the numbered steps, the requirement line
 *     and its sticky run bar — class scan-runbar — last in the form, no folded row); the file tools'
 *     one input card (FileInput: a head with its icon, title and subtitle, the drop zone, the privacy
 *     note in the footer); Renewal readiness' Run in the card's footer, after the privacy note; each
 *     empty state with the chips of what it checks; no result header;
 *   - SSL Targets (ec_wildcard.pem, an inventory of one server): a scan folds the setup into one row
 *     ("Certificate … · Domains … · 1 server · …", Edit with aria-expanded / aria-controls) and the
 *     result header starts on the first screen; Run reads "Run again" (secondary) while the setup
 *     asks for the scan on screen, "Start scan" (primary) once a domain changes; the key metric (the
 *     servers to update), the status summary (servers opens its tab, the host counts filter the
 *     table and a second press shows every host), the actions in order with Export ▾'s five files,
 *     the next steps (Verify, Rollout), the Hosts tab's read-only figures, its findings (worst
 *     first, "n more"), the stages in the Sources tab, tabs without icons;
 *   - Certificate (the sample): the input folds to one row ("Load another file"), the header names
 *     the certificate (CN), its days left, the validity / chain / CAA items open their tabs, Export ▾
 *     ends with Print then Remove (marked as the destructive tail), no Copy link for a file, the next
 *     steps; Remove from the menu empties the page;
 *   - Renewal readiness: a check keeps Run in the footer (the same element), the input compact, the
 *     verdict header with "0 will fail", Export ▾ (CSV, JSON), Copy link, "Run again";
 *   - Certificate estate (report-a.json): the input folds to one row ("1 report loaded", Add files,
 *     Forget all), the header's counts filter the list with the Show select (a second press shows
 *     every row), Export ▾ (CSV, Print), the figures in the Certificates tab;
 *   - phones: at 375×812 (Turkish, dark) Copy summary alone in the row and the rest behind "⋯", and
 *     at 320 px (English, light) no horizontal scroll on the four tools, empty or with a result;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; nothing sent.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import { SOURCES } from '../../assets/js/lib/sources.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, openResultMenu, resultAction, setLangUi, takeDownloads, waitReady, zoneHandoffScript
} from './scan.e2e.mjs';

const APEX = 'example.net';
/**
 * The DNS of example.net, answered in the page (documentation addresses only): web01 serves
 * wild and www.wild (the certificate covers them), shop answers with a Cloudflare address (behind
 * a CDN), api with an address outside the inventory.
 */
const ZONE = {
  'example.net': { A: ['203.0.113.10'] },
  'www.example.net': { A: ['203.0.113.10'] },
  'wild.example.net': { A: ['203.0.113.20'] },
  'www.wild.example.net': { A: ['203.0.113.20'] },
  'api.wild.example.net': { A: ['203.0.113.21'] },
  'shop.wild.example.net': { A: ['104.16.5.5'] }
};
const EXTRA = ['www.wild.example.net', 'api.wild.example.net', 'shop.wild.example.net'];
const INVENTORY = 'web01 203.0.113.20';
/** SSL Targets' stored options: no passive source, no wordlist, no variations, no origin hints. */
const SCAN_OPTIONS = JSON.stringify({ sources: [], knownSources: SOURCES.map((s) => s.id), bruteforce: 'off', permutations: false, originHints: false });

/** Each tool: its route, its result header and its hook for "the result is in". */
const TOOLS = {
  scan: { head: '.scan-run' },
  cert: { head: '.cert-overview' },
  renew: { head: '.rnw-hero' },
  estate: { head: '.estate-overview' }
};
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(r, 30)))));

/** Fail every https request that reaches the network; returns the list it records. */
async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

/** A page with example.net's DNS in it, downloads captured, the network guarded, the scan's options and inventory stored. */
async function openPage(browser, server, viewport) {
  const page = await browser.newPage('about:blank', viewport);
  const hits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  await installDownloadCapture(page);
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await page.evaluate(async ([options, inventory]) => {
    localStorage.setItem('ssds.scan.options', options);
    const { state } = await import('./assets/js/state.js');
    await state.setInventory(inventory).done;
  }, [SCAN_OPTIONS, INVENTORY]);
  return { page, hits };
}

/** The result header's actions row, by kind, in order. */
const actionsRow = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .result-actions > *`)].map((el) => {
  if (el.classList.contains('sum-actions')) return el.querySelector('[data-action="copy-summary-text"]:not([hidden])') ? 'summary+plain' : 'summary';
  if (el.classList.contains('menu-wrap')) return `menu:${el.querySelector('.menu-button').dataset.menu}`;
  return el.dataset.action || el.dataset.export || el.tagName.toLowerCase();
}), head);

/** A menu's items: their hook (data-export or data-action) and whether they are the destructive tail. */
const menuItems = (page, head, which = 'export') => page.evaluate((sel, w) => {
  const btn = document.querySelector(`${sel} .result-actions [data-menu="${w}"]`);
  const menu = btn ? btn.closest('.menu-wrap').querySelector('.menu-popover') : null;
  return menu ? [...menu.querySelectorAll('.menu-item')].map((i) => `${i.dataset.export || i.dataset.action}${i.dataset.tail === '' ? ':tail' : ''}`) : null;
}, head, which);

/** The status summary of a header: key, severity, count, kind (toggle / button / fact) and pressed. */
const statusOf = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .status-summary .status-item`)].map((s) => ({
  key: s.dataset.status,
  severity: s.dataset.severity,
  count: Number(s.dataset.count),
  kind: s.tagName === 'BUTTON' ? (s.hasAttribute('aria-pressed') ? 'toggle' : 'button') : 'fact',
  pressed: s.getAttribute('aria-pressed')
})), head);

/** Whether the tabs of a result draw icons (they do not: DESIGN §7). */
const tabIcons = (page, tabs) => page.evaluate((sel) => document.querySelectorAll(`${sel} [role="tab"] svg`).length, tabs);

/** SSL Targets' run bar: its Run button's label and variant. */
const scanRun = (page) => page.evaluate(() => {
  const btn = document.querySelector('[data-action="scan-run"]');
  return { label: btn.querySelector('.btn-label').textContent, primary: btn.classList.contains('btn-primary'), hidden: btn.hidden };
});

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const shot = async (page, name) => {
    if (!opts.shots) return;
    await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
    await mkdir(opts.shotsDir, { recursive: true });
    await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
  };

  run.group('Node: harness');
  await run.step('run-all orders the certificate tools\' template suite right after investigate, before the tools\' own suites', () => {
    assertEqual(orderSuites(['scan.e2e.mjs', 'certificates.e2e.mjs', 'investigate.e2e.mjs', 'home.e2e.mjs', 'cert.e2e.mjs']),
      ['home', 'investigate', 'certificates', 'scan', 'cert'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: example.net answered in the page\n`);
  const pages = [];
  try {
    const { page, hits } = await openPage(browser, server, { width: 1440, height: 900 });
    pages.push({ page, hits, where: 'desktop' });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(page, 'en');

    run.group('The empty template (desktop 1440×900, English, light)');
    await run.step('SSL Targets: the wizard — the four steps, the requirement line, the sticky run bar last in the form; no folded row, no result header', async () => {
      await gotoRoute(page, 'scan');
      const info = await page.evaluate(() => {
        const form = document.querySelector('.scan-form');
        const bar = document.querySelector('[data-role="scan-runbar"]');
        const run = bar.querySelector('[data-action="scan-run"]');
        return {
          steps: [...document.querySelectorAll('.scan-setup .scan-step')].map((s) => s.dataset.step),
          req: !!form.querySelector('[data-role="scan-requirement"]'),
          bar: [...bar.classList].filter((c) => ['run-bar', 'run-bar-group', 'run-bar-sticky', 'scan-runbar'].includes(c)),
          last: form.lastElementChild === bar,
          info: !!bar.querySelector('.run-bar-info [data-role="scan-wl-plan"]'),
          run: [run.querySelector('.btn-label').textContent, run.classList.contains('btn-primary'), run.dataset.shortcut],
          fold: document.querySelector('.scan-fold').hidden,
          folded: form.classList.contains('is-folded'),
          head: !!document.querySelector('.scan-run')
        };
      });
      assertEqual(info.steps, ['cert', 'domains', 'inventory', 'options'], 'the steps');
      assertEqual([info.req, info.bar, info.last, info.info], [true, ['run-bar', 'run-bar-group', 'run-bar-sticky', 'scan-runbar'], true, true], 'the requirement line and the run bar');
      assertEqual(info.run, ['Start scan', true, 'submit'], 'Start, primary');
      assertEqual([info.fold, info.folded, info.head], [true, false, false], 'nothing folded, no result yet');
      await assertNoHorizontalScroll(page, 'scan empty');
    });

    await run.step('Certificate and Certificate estate: one file input card (a head, the drop zone, the privacy note in the footer); the empty state with its chips', async () => {
      for (const [id, card, empty] of [['cert', '.cert-loader-card', '.cert-empty'], ['estate', '.estate-import', '.estate-empty']]) {
        await gotoRoute(page, id);
        const info = await page.evaluate(([c, e]) => {
          const el = document.querySelector(`#page-body ${c}`);
          return {
            cards: document.querySelectorAll('#page-body .tool-input').length,
            cls: el ? ['tool-input', 'file-input', 'card', 'is-compact'].filter((x) => el.classList.contains(x)) : null,
            head: el ? [!!el.querySelector('.file-input-head .file-input-icon svg'), !!el.querySelector('h2.file-input-title')?.textContent, !!el.querySelector('.file-input-subtitle')] : null,
            drop: !!el?.querySelector('.file-input-body .filedrop'),
            privacy: !!el?.querySelector('.tool-input-foot .privacy-note'),
            empty: !!document.querySelector(`#page-body ${e} .tool-empty`),
            checks: document.querySelectorAll(`#page-body ${e} .tool-empty-check`).length,
            head2: !!document.querySelector('#page-body .result-head')
          };
        }, [card, empty]);
        assertEqual([info.cards, info.cls, info.head, info.drop, info.privacy], [1, ['tool-input', 'file-input', 'card'], [true, true, true], true, true], `${id}: the input card`);
        assert(info.empty && info.checks >= 2 && !info.head2, `${id}: the empty state with its chips, no result header: ${JSON.stringify(info)}`);
        await assertNoHorizontalScroll(page, `${id} empty`);
      }
    });

    await run.step('Renewal readiness: Run in the card\'s footer after the privacy note, not on the field\'s row; the empty state with its chips', async () => {
      await gotoRoute(page, 'renew');
      const info = await page.evaluate(() => {
        const card = document.querySelector('.rnw-form-card');
        const foot = card.querySelector('.tool-input-foot');
        return {
          foot: foot.classList.contains('has-run'),
          order: [...foot.children].map((c) => (c.classList.contains('privacy-note') ? 'privacy' : c.classList.contains('run-bar') ? 'run' : c.className)),
          row: !!card.querySelector('.tool-input-fields > .run-bar'),
          run: !!foot.querySelector('.run-bar [data-action="renew-run"]'),
          checks: document.querySelectorAll('.rnw-empty .tool-empty-check').length
        };
      });
      assertEqual([info.foot, info.order, info.row, info.run], [true, ['privacy', 'run'], false, true], 'Run in the footer');
      assert(info.checks >= 2, `the chips of what it checks (${info.checks})`);
      await assertNoHorizontalScroll(page, 'renew empty');
      await shot(page, 'certificates-renew-empty-desktop-light-en');
    });

    run.group('SSL Targets: a scan folds the setup (example.net answered in the page)');
    await run.step('a scan of ec_wildcard.pem with an inventory of one server: the setup folds into one row, the result header on the first screen, "Run again"', async () => {
      await gotoRoute(page, 'scan');
      await page.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'ec_wildcard.pem')]);
      await page.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate loaded' });
      await page.evaluate((names) => {
        document.querySelector('.scan-options-box').open = true;
        const ta = document.querySelector('[data-role="scan-extra"]');
        ta.value = names.join('\n');
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }, EXTRA);
      await page.evaluate(() => document.querySelector('[data-action="scan-run"]').click());
      await page.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'done', { timeout: 60000, message: 'scan done' });
      await frames(page);
      const fold = await page.evaluate(() => {
        const edit = document.querySelector('[data-action="scan-setup-edit"]');
        const row = document.querySelector('.scan-fold');
        return {
          folded: document.querySelector('.scan-form').classList.contains('is-folded'),
          shown: !row.hidden && row.getBoundingClientRect().height > 0,
          steps: getComputedStyle(document.querySelector('.scan-setup')).display,
          req: getComputedStyle(document.querySelector('[data-role="scan-requirement"]')).display,
          text: row.querySelector('.scan-fold-text').textContent,
          edit: [edit.textContent, edit.getAttribute('aria-expanded'), edit.getAttribute('aria-controls') === document.querySelector('.scan-setup').id],
          headTop: Math.round(document.querySelector('.scan-run').getBoundingClientRect().top + window.scrollY)
        };
      });
      assertEqual([fold.folded, fold.shown, fold.steps, fold.req], [true, true, 'none', 'none'], 'folded into one row');
      assertEqual(fold.text, 'Certificate *.wild.example.net·ECDSA P-256·Domains example.net·1 server·no passive sources · no brute force · no permutations · no origin hints · +3 extra names',
        'the folded row');
      assertEqual(fold.edit, ['Edit', 'false', true], 'Edit controls the steps');
      assert(fold.headTop < 900, `the result header starts on the first screen: ${fold.headTop}`);
      assertEqual(await scanRun(page), { label: 'Run again', primary: false, hidden: false }, 'Run again, secondary');
      await shot(page, 'certificates-scan-result-desktop-light-en');
    });

    await run.step('the result header: the title, the servers to update, the status summary in severity order, the actions, the next steps', async () => {
      const head = await page.evaluate(() => {
        const h = document.querySelector('.scan-run');
        return {
          title: h.querySelector('.result-title').textContent,
          key: h.querySelector('.result-key .scan-key')?.textContent || '',
          keySeverity: h.querySelector('.scan-key')?.dataset.severity,
          meta: h.querySelector('.scan-run-meta').textContent,
          progress: !!h.querySelector('.result-progress .progress'),
          next: [...h.querySelectorAll('.result-next .next-step')].map((b) => b.dataset.action)
        };
      });
      assertEqual([head.title, head.key, head.keySeverity, head.progress], ['Scan of example.net', '1server to update', 'warn', false], 'title and key metric, no progress card');
      assert(/^Finished in /.test(head.meta), `meta: ${head.meta}`);
      assertEqual(head.next, ['scan-next-verify', 'scan-next-rollout'], 'next steps');
      const status = await statusOf(page, '.scan-run');
      assertEqual(status.map((s) => [s.key, s.severity, s.kind]), [['servers', 'warn', 'button'], ['behind', 'info', 'toggle'], ['covered', 'ok', 'toggle']], 'status items');
      assertEqual(status.find((s) => s.key === 'servers').count, 1, 'one server to update');
      assertEqual(await actionsRow(page, '.scan-run'), ['summary+plain', 'menu:export', 'copy-link'], 'actions');
      assertEqual(await menuItems(page, '.scan-run'), ['hosts-csv', 'servers-csv', 'json', 'names', 'targets'], 'Export ▾');
      assertEqual(await tabIcons(page, '.scan-tabs'), 0, 'tabs without icons');
    });

    await run.step('a status press filters the Hosts table (pressed), a second shows every host; "servers to update" opens the Servers tab', async () => {
      const rows = () => page.evaluate(() => [...document.querySelectorAll('.scan-hosts tbody tr.dt-row .scan-host-name')].map((n) => n.textContent).sort());
      const all = await rows();
      assert(all.length >= 4, `hosts: ${all}`);
      await page.click('.scan-run .status-item[data-status="behind"]');
      await page.waitFor(() => document.querySelector('[data-role="scan-filter-kind"]').value === 'hidden', { message: 'Show: behind a CDN' });
      assertEqual(await rows(), ['shop.wild.example.net'], 'the host behind a CDN');
      assertEqual((await statusOf(page, '.scan-run')).find((s) => s.key === 'behind').pressed, 'true', 'pressed');
      await page.click('.scan-run .status-item[data-status="covered"]');
      await page.waitFor(() => document.querySelector('input[data-filter="covered"]').checked, { message: 'Covered only' });
      const covered = await rows();
      assert(covered.length >= 2 && covered.every((n) => n.endsWith('wild.example.net')), `covered hosts: ${covered}`);
      assertEqual((await statusOf(page, '.scan-run')).filter((s) => s.pressed === 'true').map((s) => s.key), ['covered'], 'one item pressed at a time');
      await page.click('.scan-run .status-item[data-status="covered"]');
      await page.waitFor(() => !document.querySelector('input[data-filter="covered"]').checked, { message: 'every host again' });
      assertEqual(await rows(), all, 'every host');
      await page.click('.scan-run .status-item[data-status="servers"]');
      await page.waitFor(() => document.querySelector('.scan-tabs [data-tab="servers"]')?.getAttribute('aria-selected') === 'true'
        && document.activeElement === document.querySelector('.scan-tabs [data-tab="servers"]'), { message: 'Servers tab, focused' });
    });

    await run.step('the Hosts tab: the read-only figures, then the findings (worst first, "n more"), then the table; the stages sit in Sources', async () => {
      await page.click('.scan-tabs [data-tab="hosts"]');
      const info = await page.evaluate(() => {
        const panel = document.querySelector('.scan-tab-hosts');
        return {
          order: [...panel.children].map((c) => (c.classList.contains('metric-strip') ? 'metrics' : c.classList.contains('finding-list') ? 'findings' : c.classList.contains('dt') || c.querySelector('.scan-hosts') ? 'table' : c.className)),
          metrics: [...panel.querySelectorAll('.scan-stats .metric')].map((m) => m.dataset.metric),
          buttons: panel.querySelectorAll('.scan-stats button, .scan-stats a').length,
          findings: [...panel.querySelectorAll('.scan-summary .finding')].map((f) => [f.dataset.summary, f.dataset.severity, f.hidden]),
          more: panel.querySelector('.scan-summary .finding-more')
        };
      });
      assertEqual(info.order.slice(0, 2), ['metrics', 'findings'], 'figures, then findings');
      assert(info.metrics.includes('hosts') && info.metrics.includes('servers') && info.buttons === 0, `read-only figures: ${JSON.stringify(info.metrics)}`);
      assertEqual(info.findings[0].slice(0, 2), ['needs', 'warn'], 'the worst first');
      const hidden = info.findings.filter((f) => f[2]).length;
      assert(info.findings.length > 4 ? hidden === info.findings.length - 3 : hidden === 0, `three rows, then "n more": ${JSON.stringify(info.findings)}`);
      if (hidden) {
        await page.click('.scan-summary .finding-more');
        assertEqual(await page.evaluate(() => [document.querySelectorAll('.scan-summary .finding[hidden]').length, document.querySelector('.scan-summary .finding-more').getAttribute('aria-expanded')]), [0, 'true'], 'every finding');
      }
      await page.click('.scan-tabs [data-tab="sources"]');
      assert(await page.evaluate(() => document.querySelectorAll('.scan-tab-sources .scan-stages .scan-stage').length >= 4), 'the stage pills in Sources');
      await page.click('.scan-tabs [data-tab="hosts"]');
    });

    await run.step('Export ▾ downloads the Servers CSV; the next steps open Verify and Rollout (nothing sent)', async () => {
      await takeDownloads(page);
      await resultAction(page, '[data-export="servers-csv"]', '.scan-run');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'Servers CSV' });
      const [file] = await takeDownloads(page);
      assert(/^servers-.*\.csv$/.test(file.name) && /web01/.test(file.text), `the file: ${file.name}`);
      await page.click('.scan-run [data-action="scan-next-verify"]');
      await page.waitFor(() => document.querySelector('.scan-tabs [data-tab="verify"]')?.getAttribute('aria-selected') === 'true'
        && document.querySelector('.scan-tab-verify [data-vfy="panel"]'), { message: 'Verify' });
      await page.click('.scan-run [data-action="scan-next-rollout"]');
      await page.waitFor(() => document.querySelector('.scan-tabs [data-tab="rollout"]')?.getAttribute('aria-selected') === 'true'
        && document.querySelector('.ro-board'), { message: 'Rollout' });
      await page.click('.scan-tabs [data-tab="hosts"]');
    });

    await run.step('Edit unfolds the steps (aria-expanded); another domain makes Run "Start scan" and primary, the same setup "Run again"; Edit folds them again', async () => {
      await page.click('[data-action="scan-setup-edit"]');
      await page.waitFor(() => !document.querySelector('.scan-form').classList.contains('is-folded'), { message: 'unfolded' });
      assertEqual(await page.evaluate(() => [document.querySelector('[data-action="scan-setup-edit"]').getAttribute('aria-expanded'),
        getComputedStyle(document.querySelector('.scan-setup')).display !== 'none']), ['true', true], 'the steps are back');
      assertEqual(await scanRun(page), { label: 'Run again', primary: false, hidden: false }, 'unchanged setup: Run again');
      await page.type('[data-role="scan-domains"]', `${APEX}\nexample.com`);
      await page.waitFor(() => document.querySelector('[data-action="scan-run"] .btn-label').textContent === 'Start scan', { message: 'the verb again' });
      assertEqual(await scanRun(page), { label: 'Start scan', primary: true, hidden: false }, 'another domain: Start scan, primary');
      await page.type('[data-role="scan-domains"]', APEX);
      await page.waitFor(() => document.querySelector('[data-action="scan-run"] .btn-label').textContent === 'Run again', { message: 'Run again' });
      await page.evaluate(() => document.querySelector('[data-action="scan-setup-edit"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.scan-form').classList.contains('is-folded')
        && document.querySelector('[data-action="scan-setup-edit"]').getAttribute('aria-expanded') === 'false', { message: 'folded by the keyboard' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'scan-setup-edit', 'the focus stays on Edit');
    });

    run.group('Certificate: a file loaded (the sample)');
    await run.step('the input folds to one row, the header names the certificate with its days left; validity, chain and CAA open their tabs', async () => {
      await gotoRoute(page, 'cert');
      // SSL Targets' certificate is the shared current one: Remove it from the menu first.
      if (await page.evaluate(() => !!document.querySelector('.cert-overview'))) {
        await resultAction(page, '[data-action="cert-remove"]', '.cert-overview');
        await page.waitFor(() => !document.querySelector('.cert-overview') && document.querySelector('.cert-loader-card'), { message: 'emptied' });
      }
      await page.click('.cert-loader-card [data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'example.com', { message: 'sample loaded' });
      const info = await page.evaluate(() => {
        const input = document.querySelector('.cert-loader-compact');
        return {
          input: input ? [input.classList.contains('is-compact'), input.querySelector('.file-input-row .cert-reload')?.open, !!input.querySelector('.tool-input-foot .privacy-note')] : null,
          days: document.querySelector('.cert-overview .result-key .cert-days-value')?.textContent || '',
          next: [...document.querySelectorAll('.cert-overview .result-next .next-step')].map((b) => b.dataset.action)
        };
      });
      assertEqual(info.input, [true, false, true], 'one row: "Load another file", folded; the privacy note stays');
      assert(/^\d[\d,]*$/.test(info.days), `days left: ${info.days}`);
      assertEqual(info.next, ['find-targets', 'renew-link'], 'next steps');
      const status = await statusOf(page, '.cert-overview');
      assertEqual([status.map((s) => s.key).sort(), [...new Set(status.map((s) => s.kind))]], [['caa', 'chain', 'validity'], ['button']], 'three buttons, no filter');
      await page.click('.cert-overview .status-item[data-status="chain"]');
      await page.waitFor(() => document.querySelector('.cert-tabs [data-tab="chain"]')?.getAttribute('aria-selected') === 'true', { message: 'the Chain tab' });
      assertEqual(await tabIcons(page, '.cert-tabs'), 0, 'tabs without icons');
      await shot(page, 'certificates-cert-result-desktop-light-en');
    });

    await run.step('the actions: Copy summary, Export ▾ ending with Print then Remove (the destructive tail), no Copy link for a file; Remove empties the page', async () => {
      assertEqual(await actionsRow(page, '.cert-overview'), ['summary+plain', 'menu:export'], 'actions');
      const items = await menuItems(page, '.cert-overview');
      assertEqual(items.slice(-2), ['print', 'cert-remove:tail'], `Print, then Remove: ${items}`);
      assert(items.includes('download-pem') && items.includes('copy-pem'), `the files: ${items}`);
      const opened = await openResultMenu(page, 'export', '.cert-overview');
      assertEqual(opened[opened.length - 1], 'Remove', 'Remove last');
      await page.press('Escape');
      await resultAction(page, '[data-action="cert-remove"]', '.cert-overview');
      await page.waitFor(() => !document.querySelector('.cert-overview') && document.querySelector('.cert-loader-card') && document.querySelector('.cert-empty .tool-empty'),
        { message: 'the empty page again' });
    });

    run.group('Renewal readiness: a check');
    await run.step('Run stays in the footer (the same element) and reads "Run again"; the input compact; the verdict header with "0 will fail", Export ▾, Copy link', async () => {
      await gotoRoute(page, 'renew');
      await page.evaluate(() => { document.querySelector('.rnw-form-card .tool-input-foot .run-bar').dataset.testMark = 'before'; });
      await page.type('[data-role="renew-names"]', `www.${APEX}`);
      await page.click('[data-action="renew-run"]');
      await page.waitFor(() => document.querySelector('.rnw-hero')?.dataset.state === 'done' && !document.querySelector('[data-action="renew-run"]').hidden,
        { timeout: 30000, message: 'check done' });
      const info = await page.evaluate(() => {
        const card = document.querySelector('.rnw-form-card');
        const run = card.querySelector('.tool-input-foot.has-run > .run-bar');
        const btn = run.querySelector('[data-action="renew-run"]');
        return {
          compact: card.classList.contains('is-compact'),
          same: run.dataset.testMark === 'before',
          run: [btn.querySelector('.btn-label').textContent, btn.classList.contains('btn-primary')],
          title: !!document.querySelector('.rnw-hero .result-title .result-sev')
        };
      });
      assertEqual(info, { compact: true, same: true, run: ['Run again', false], title: true }, 'the footer\'s Run, the compact input, a verdict');
      const status = await statusOf(page, '.rnw-hero');
      const fail = status.find((s) => s.key === 'fail');
      assert(fail && fail.severity === 'error' && fail.count === 0, `"0 will fail" stays (a verdict tool): ${JSON.stringify(status)}`);
      assertEqual(await actionsRow(page, '.rnw-hero'), ['summary+plain', 'menu:export', 'copy-link'], 'actions');
      assertEqual(await menuItems(page, '.rnw-hero'), ['renew-csv', 'renew-json'], 'Export ▾');
      await assertNoHorizontalScroll(page, 'renew result');
    });

    run.group('Certificate estate: a report loaded');
    await run.step('the input folds to one row ("1 report loaded", Add files, Forget all); the header counts filter the list with the Show select; Export ▾ (CSV, Print)', async () => {
      await gotoRoute(page, 'estate');
      await page.setFileInput('.estate-page .estate-drop .filedrop-input', [path.join(FIXTURES, 'estate', 'report-a.json')]);
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: '9 rows', timeout: 15000 });
      const input = await page.evaluate(() => {
        const card = document.querySelector('.estate-import');
        return {
          compact: card.classList.contains('is-compact'),
          more: card.querySelector('.estate-import-more .disclosure-summary').textContent.trim(),
          open: card.querySelector('.estate-import-more').open,
          actions: [...card.querySelectorAll('.file-input-actions [data-action]')].map((b) => b.dataset.action)
        };
      });
      assertEqual(input, { compact: true, more: '1 report loaded', open: false, actions: ['estate-add', 'estate-forget'] }, 'one row');
      // (The fixture's certificates expire on fixed dates: how many have expired depends on the day.)
      const status = await statusOf(page, '.estate-overview');
      assertEqual(status.map((s) => [s.key, s.severity, s.kind]), [
        ['expired', 'error', 'toggle'], ['soon', 'warn', 'toggle'], ['name-conflict', 'neutral', 'toggle'], ['shared-key', 'neutral', 'toggle'], ['weak', 'neutral', 'toggle']
      ], 'the counts');
      const expired = status[0].count;
      await page.click('.estate-overview .status-item[data-status="expired"]');
      await page.waitFor((n) => document.querySelector('.estate-filter select').value === 'expired'
        && document.querySelectorAll('.estate-table tbody tr.dt-row').length === n, { args: [expired], message: 'the expired certificates' });
      await page.click('.estate-overview .status-item[data-status="expired"]');
      await page.waitFor(() => document.querySelector('.estate-filter select').value === 'all'
        && document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: 'every certificate' });
      assertEqual(await actionsRow(page, '.estate-overview'), ['summary+plain', 'menu:export'], 'actions: no Copy link (the reports never go into a URL)');
      assertEqual(await menuItems(page, '.estate-overview'), ['csv', 'print'], 'Export ▾');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.estate-metric-row')].map((r) => r.dataset.metrics)), ['expiry', 'kinds'], 'the figures in the Certificates tab');
      assertEqual(await tabIcons(page, '.estate-tabs'), 0, 'tabs without icons');
      await shot(page, 'certificates-estate-result-desktop-light-en');
    });

    run.group('Phones');
    const { page: phone, hits: phoneHits } = await openPage(browser, server, { width: 375, height: 812, mobile: true });
    pages.push({ page: phone, hits: phoneHits, where: 'phone' });
    await run.step('375×812, Turkish, dark: a result of each tool — Copy summary alone in the row, the rest behind "⋯"; no horizontal scroll', async () => {
      await phone.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(phone, 'tr');
      // SSL Targets: the certificate and the extra names, one scan.
      await gotoRoute(phone, 'scan');
      await phone.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'ec_wildcard.pem')]);
      await phone.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate loaded' });
      await phone.evaluate((names) => {
        document.querySelector('.scan-options-box').open = true;
        const ta = document.querySelector('[data-role="scan-extra"]');
        ta.value = names.join('\n');
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }, EXTRA);
      await phone.evaluate(() => document.querySelector('[data-action="scan-run"]').click());
      await phone.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'done', { timeout: 60000, message: 'scan done' });
      await frames(phone);
      assertEqual(await actionsRow(phone, '.scan-run'), ['summary', 'menu:more'], 'SSL Targets: Copy summary, ⋯');
      const fold = await phone.evaluate(() => {
        const row = document.querySelector('.scan-fold').getBoundingClientRect();
        return { inside: row.right <= document.documentElement.clientWidth + 0.5, text: document.querySelector('.scan-fold-text').textContent };
      });
      assert(fold.inside && /^Sertifika \*\.wild\.example\.net/.test(fold.text), `the folded row fits, in Turkish: ${JSON.stringify(fold)}`);
      await assertNoHorizontalScroll(phone, 'scan 375 tr dark');
      await phone.evaluate(() => window.scrollTo(0, 0));
      await shot(phone, 'certificates-scan-result-375-dark-tr');
      // Certificate: SSL Targets' certificate is the shared one.
      await gotoRoute(phone, 'cert');
      await phone.waitFor(() => document.querySelector('.cert-overview'), { message: 'the certificate' });
      assertEqual(await actionsRow(phone, '.cert-overview'), ['summary', 'menu:more'], 'Certificate: Copy summary, ⋯');
      assertEqual((await menuItems(phone, '.cert-overview', 'more')).slice(-1), ['cert-remove:tail'], 'Remove last behind ⋯');
      await assertNoHorizontalScroll(phone, 'cert 375 tr dark');
      // Renewal readiness and Certificate estate.
      await gotoRoute(phone, 'renew');
      await phone.type('[data-role="renew-names"]', `www.${APEX}`);
      await phone.click('[data-action="renew-run"]');
      await phone.waitFor(() => document.querySelector('.rnw-hero')?.dataset.state === 'done' && !document.querySelector('[data-action="renew-run"]').hidden,
        { timeout: 30000, message: 'check done' });
      assertEqual(await actionsRow(phone, '.rnw-hero'), ['summary', 'menu:more'], 'Renewal readiness: Copy summary, ⋯');
      await assertNoHorizontalScroll(phone, 'renew 375 tr dark');
      await gotoRoute(phone, 'estate');
      await phone.setFileInput('.estate-page .estate-drop .filedrop-input', [path.join(FIXTURES, 'estate', 'report-a.json')]);
      await phone.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: '9 rows', timeout: 15000 });
      assertEqual(await actionsRow(phone, '.estate-overview'), ['summary', 'menu:more'], 'Certificate estate: Copy summary, ⋯');
      await assertNoHorizontalScroll(phone, 'estate 375 tr dark');
      await shot(phone, 'certificates-estate-result-375-dark-tr');
    });

    await run.step('320 px (English, light): no horizontal scroll on the four tools, empty or with a result', async () => {
      await setLangUi(phone, 'en');
      await phone.emulateMedia({ 'prefers-color-scheme': 'light' });
      await phone.setViewport({ width: 320, height: 700, mobile: true });
      await phone.waitFor(() => document.documentElement.clientWidth === 320, { message: '320 px' });
      for (const id of Object.keys(TOOLS)) {
        await gotoRoute(phone, id);
        await phone.waitFor((sel) => document.querySelector(sel), { args: [TOOLS[id].head], message: `${id}: its result` });
        await frames(phone);
        await assertNoHorizontalScroll(phone, `${id} 320 result`);
      }
      // Empty: a fresh page of the same browser (the kept results are this page's).
      const empty = await browser.newPage('about:blank', { width: 320, height: 700, mobile: true });
      try {
        await empty.goto(`${server.url}#/about`);
        await waitReady(empty);
        for (const id of Object.keys(TOOLS)) {
          await gotoRoute(empty, id);
          await assertNoHorizontalScroll(empty, `${id} 320 empty`);
        }
      } finally {
        await empty.close();
      }
      await shot(phone, 'certificates-estate-result-320-light-en');
    });

    await run.step('no missing keys; no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertNoMissingKeys(phone);
      for (const p of pages) await assertClean(p.page, p.where, origin);
      assertEqual(pages.map((p) => p.hits), [[], []], 'no request reached the network');
    });
  } finally {
    for (const p of pages) await p.page.close().catch(() => {});
    await browser.close();
    await server.close();
  }
  run.finish();
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stdout.write(`\n${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
export { main };
