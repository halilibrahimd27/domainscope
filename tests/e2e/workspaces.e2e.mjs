#!/usr/bin/env node
/**
 * workspaces.e2e.mjs — customer workspaces in a real headless browser, OFFLINE: the IndexedDB
 * store behind lib/workspace.js (assets/js/workspace-db.js), the header switcher and the
 * Workspaces dialog (ui/workspace-panel.js), the hand-over file (lib/handover.js).
 *
 *   node tests/e2e/workspaces.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Nothing leaves the page (a CDP guard fails every https request). On a 1440 px desktop:
 *   - a first visit creates no database; the data an older version kept in localStorage /
 *     sessionStorage (servers, learned names, the custom wordlist) is in Default after a reload,
 *     and the old keys are gone;
 *   - two workspaces are created in the dialog, each with its own servers: the same address in
 *     both is no DUPLICATE_IP, a switch shows the other inventory and a reload keeps the active
 *     workspace;
 *   - a switch asks first when it would drop unsaved Servers edits (Cancel keeps them) or stop a
 *     running Bulk Resolve job (confirmed: the job stops);
 *   - another tab working in the same workspace follows a save (BroadcastChannel);
 *   - expected CAs: a fixture certificate in the Certificate view is flagged "Unexpected CA", then "Expected CA"
 *     once its CA is listed; the certificate's name joins the recent domains, and switching back
 *     to the workspace makes it the current target again;
 *   - the hand-over file: exported with a password it shows no name, server or address, not even in
 *     its file name (a plain export's file name does carry the name); the import
 *     refuses a wrong password (nothing imported), then opens with the right one as a new workspace
 *     with the same servers, or replaces the workspace of the same name after a confirmation;
 *   - a workspace is deleted after a confirmation;
 *   - the keyboard: Esc in the rename field cancels the rename and leaves the dialog open, the focus
 *     back on Rename (as after saving with Enter); Clear the list keeps the focus in the dialog;
 *   - a workspace whose creation could not be written (every put refused as a full storage) says
 *     why, and is stored by its next save once storage works: it is there after a reload;
 *   - Settings › Delete all local data deletes every workspace and the IndexedDB database, and says so.
 * With storage blocked (every storage accessor throws, as with Safari's "Block all cookies") the page
 * works in memory, and Delete all local data says that nothing had been saved rather than a failure.
 * With a database of a later version (the page cannot open it and works in memory), Delete all local
 * data deletes it all the same and says the database went.
 * Then at 375 px (Turkish, dark) and 320 px: the switcher is in the Tools menu, the dialog fits
 * without horizontal scrolling. Fails on console errors, exceptions, CSP violations and missing
 * i18n keys.
 */

import path from 'node:path';
import os from 'node:os';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  cliOptions, createRunner, assert, assertEqual, waitReady, gotoRoute, setLangUi, assertNoHorizontalScroll,
  shot, assertClean, assertNoMissingKeys, installDownloadCapture, takeDownloads, BASE, SHOTS, ROOT
} from './scan.e2e.mjs';

const opts = cliOptions();
const run = createRunner();

const INVENTORY_A = 'web01 192.0.2.10\nweb02 192.0.2.11';
const INVENTORY_B = 'mail 192.0.2.10\nvpn 198.51.100.7';
const PASSWORD = 'correct horse 2026';
/** The first name of tests/fixtures/rsa_multi_san.pem: the target its load sets. */
const CERT_DOMAIN = 'example-test.com.tr';

/** Fail (and record) every https request that would leave the page. */
async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

/** The workspaces as state.js has them, and what the header shows. */
function wsInfo() {
  return import('./assets/js/state.js').then(({ state }) => {
    const btn = document.querySelector('[data-control="workspace"]');
    return {
      active: state.workspace.isDefault ? 'default' : state.workspace.name,
      list: state.workspaces.map((w) => (w.isDefault ? 'default' : w.name)),
      inventory: state.inventory.text,
      header: btn ? btn.querySelector('.ws-switch-name').textContent : null,
      persistent: state.workspacePersistence
    };
  });
}

/** Is the database there? (indexedDB.databases(): Chrome has it) */
const dbExists = (page) => page.evaluate(async () => (await indexedDB.databases()).some((d) => d.name === 'ssds.workspaces'));

/** Open the Workspaces dialog from the header (desktop) or the Tools menu (phone). */
async function openWorkspaces(page, { phone = false } = {}) {
  if (phone) {
    await page.click('[data-control="nav-menu"]');
    await page.waitFor(() => document.querySelector('dialog.navmenu-modal[open] [data-control="workspace-menu"]'), { message: 'tools menu with the workspace row' });
    await page.click('[data-control="workspace-menu"]');
  } else {
    await page.click('[data-control="workspace"]');
  }
  await page.waitFor(() => document.querySelector('dialog.ws-modal[open] .ws-list li'), { message: 'workspaces dialog', timeout: 15000 });
}

async function closeWorkspaces(page) {
  await page.click('dialog.ws-modal[open] .modal-head .btn');
  await page.waitFor(() => !document.querySelector('dialog.ws-modal'), { message: 'dialog closed' });
}

/** Click the confirming button of the confirmation dialog on top of the Workspaces dialog. */
async function confirmTop(page) {
  await page.waitFor(() => [...document.querySelectorAll('dialog.modal-sm[open]')].length > 0, { message: 'confirmation' });
  await page.evaluate(() => {
    const d = [...document.querySelectorAll('dialog.modal-sm[open]')].pop();
    const btns = d.querySelectorAll('.modal-foot .btn');
    btns[btns.length - 1].click();
  });
  await page.waitFor(() => !document.querySelector('dialog.modal-sm[open]'), { message: 'confirmation closed' });
}

/** The confirmation dialog on top: its message, then Cancel (the first button). */
async function cancelTop(page) {
  await page.waitFor(() => [...document.querySelectorAll('dialog.modal-sm[open]')].length > 0, { message: 'confirmation' });
  const message = await page.evaluate(() => {
    const d = [...document.querySelectorAll('dialog.modal-sm[open]')].pop();
    const text = d.querySelector('.modal-message').textContent;
    d.querySelector('.modal-foot .btn').click();
    return text;
  });
  await page.waitFor(() => !document.querySelector('dialog.modal-sm[open]'), { message: 'confirmation closed' });
  return message;
}

/** The message of the confirmation dialog on top. */
const topMessage = (page) => page.waitFor(() => {
  const d = [...document.querySelectorAll('dialog.modal-sm[open]')].pop();
  return d ? d.querySelector('.modal-message').textContent : false;
}, { message: 'confirmation' });

/** Hold every fetch of the page (nothing is answered offline): a job started now stays running. */
const holdFetches = (page) => page.evaluate(() => {
  window.__realFetch = window.__realFetch || window.fetch;
  window.__heldFetches = 0;
  window.fetch = (input, init = {}) => new Promise((resolve, reject) => {
    window.__heldFetches += 1;
    const signal = init.signal || (input && input.signal);
    if (signal) signal.addEventListener('abort', () => reject(signal.reason || new DOMException('Aborted', 'AbortError')), { once: true });
  });
});

const releaseFetches = (page) => page.evaluate(() => {
  if (window.__realFetch) window.fetch = window.__realFetch;
});

/** The id of a workspace row in the dialog, by its name. */
const rowId = (page, name) => page.evaluate((n) => {
  const li = [...document.querySelectorAll('dialog.ws-modal .ws-list li')].find((x) => x.querySelector('.ws-item-label')?.textContent === n);
  return li ? li.dataset.wsId : null;
}, name);

/** Create a workspace in the open dialog (it becomes the active one). */
async function createWorkspace(page, name) {
  await page.type('[data-role="ws-new-name"]', name);
  await page.click('[data-action="ws-create"]');
  await page.waitFor(wsActiveIs, { args: [name], message: `active ${name}` });
}

function wsActiveIs(name) {
  const btn = document.querySelector('[data-control="workspace"]');
  const row = document.querySelector('dialog.ws-modal .ws-list li.is-active .ws-item-label');
  return (!btn || btn.querySelector('.ws-switch-name').textContent === name) && (!row || row.textContent === name);
}

/** Switch in the open dialog, by name. */
async function switchTo(page, name) {
  const id = await rowId(page, name);
  assert(id, `a row for ${name}`);
  await page.click(`dialog.ws-modal li[data-ws-id="${id}"] [data-action="ws-switch"]`);
  await page.waitFor(wsActiveIs, { args: [name], message: `switched to ${name}` });
}

/** Save an inventory in the Servers view (on screen). */
async function saveInventory(page, text) {
  await page.type('[data-role="inventory-text"]', text);
  await page.click('[data-action="save"]');
  await page.waitFor((t) => document.querySelector('[data-role="inventory-text"]').value === t
    && document.querySelector('[data-action="save"]').disabled, { args: [text], message: 'saved' });
}

const editorText = (page) => page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
const duplicateWarnings = (page) => page.evaluate(() => document.querySelectorAll('.inv-warning[data-code="DUPLICATE_IP"]').length);

async function desktop(browser, server, tmp) {
  run.group('Workspaces (1440 px, offline, real IndexedDB)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await installDownloadCapture(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  let tab2 = null;
  try {
    await run.step('a first visit: Default, and no database until something is saved', async () => {
      await page.goto(`${server.url}#/inventory`);
      await waitReady(page);
      await setLangUi(page, 'en');
      const info = await page.evaluate(wsInfo);
      assertEqual([info.active, info.header, info.list, info.persistent], ['default', 'Default', ['default'], true], 'Default');
      assertEqual(await dbExists(page), false, 'no database yet');
      // Nothing was written to Default: the dialog gives it no made-up "changed …" date.
      await openWorkspaces(page);
      const meta = await page.evaluate(() => !!document.querySelector('dialog.ws-modal .ws-list li[data-ws-id="default"] .ws-item-meta'));
      assertEqual(meta, false, 'no date for an untouched Default');
      await closeWorkspaces(page);
      assertEqual(await dbExists(page), false, 'opening the dialog created no database');
    });

    await run.step('the data of an older version moves into Default on the next load; the old keys go', async () => {
      await page.evaluate(() => {
        localStorage.setItem('ssds.inventory', JSON.stringify({ v: 1, text: 'legacy01 203.0.113.5', updatedAt: '2026-09-01T08:00:00Z' }));
        localStorage.setItem('ssds.learned.labels', JSON.stringify({ v: 1, seq: 2, labels: { billing: [2, 1], intranet: [1, 2] } }));
        sessionStorage.setItem('ssds.wordlist.custom', 'portal\nticket');
      });
      await page.reload();
      await waitReady(page);
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]')?.value === 'legacy01 203.0.113.5', { message: 'migrated inventory' });
      const data = await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        return {
          migrated: state.migrated.sort(),
          learned: Object.keys(state.workspaceData('learned').labels).sort(),
          wordlist: state.workspaceData('wordlist'),
          keys: [localStorage.getItem('ssds.inventory'), localStorage.getItem('ssds.learned.labels'), sessionStorage.getItem('ssds.wordlist.custom')]
        };
      });
      assertEqual(data.migrated, ['inventory', 'learned', 'wordlist'], 'what moved');
      assertEqual([data.learned, data.wordlist], [['billing', 'intranet'], 'portal\nticket'], 'learned names and custom wordlist');
      assertEqual(data.keys, [null, null, null], 'the old keys are gone');
      assertEqual(await dbExists(page), true, 'the database now');
    });

    await run.step('two workspaces, each with its own servers: the same address in both is no DUPLICATE_IP', async () => {
      await openWorkspaces(page);
      await createWorkspace(page, 'Acme');
      await closeWorkspaces(page);
      // The Servers view opened again for Acme: empty.
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]')?.value === '', { message: 'Acme starts empty' });
      await saveInventory(page, INVENTORY_A);
      await openWorkspaces(page);
      await createWorkspace(page, 'Globex');
      await closeWorkspaces(page);
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]')?.value === '', { message: 'Globex starts empty' });
      await saveInventory(page, INVENTORY_B);
      assertEqual(await duplicateWarnings(page), 0, '192.0.2.10 is only Globex\'s mail here');
      const badge = await page.evaluate(() => document.querySelector('.inv-workspace').textContent);
      assertEqual(badge, 'Workspace: Globex', 'the editor names its workspace');
      await openWorkspaces(page);
      await switchTo(page, 'Acme');
      await closeWorkspaces(page);
      await page.waitFor((t) => document.querySelector('[data-role="inventory-text"]')?.value === t, { args: [INVENTORY_A], message: 'Acme\'s inventory back' });
      assertEqual(await duplicateWarnings(page), 0, 'and no warning here either');
      const info = await page.evaluate(wsInfo);
      assertEqual([info.active, info.header, info.list], ['Acme', 'Acme', ['default', 'Acme', 'Globex']], 'list and header');
      await shot(page, opts, 'workspaces-desktop-servers');
    });

    await run.step('a reload opens the workspace used last, with its data', async () => {
      await page.reload();
      await waitReady(page);
      await page.waitFor((t) => document.querySelector('[data-role="inventory-text"]')?.value === t, { args: [INVENTORY_A], message: 'Acme after reload' });
      assertEqual((await page.evaluate(wsInfo)).header, 'Acme', 'header');
    });

    await run.step('a switch asks first when it would drop unsaved server edits or stop a running job', async () => {
      // Unsaved edits in the Servers editor belong to Acme: Cancel keeps them, and Acme.
      await page.type('[data-role="inventory-text"]', `${INVENTORY_A}\nweb09 192.0.2.19`);
      await openWorkspaces(page);
      let id = await rowId(page, 'Globex');
      await page.click(`dialog.ws-modal li[data-ws-id="${id}"] [data-action="ws-switch"]`);
      const unsaved = await cancelTop(page);
      assert(/changes that are not saved/.test(unsaved) && /“Globex”/.test(unsaved), unsaved);
      await closeWorkspaces(page);
      assertEqual([(await page.evaluate(wsInfo)).active, (await editorText(page)).includes('web09')], ['Acme', true], 'still Acme, edits kept');
      await page.type('[data-role="inventory-text"]', INVENTORY_A);
      // A running Bulk Resolve job (its lookups held back) stops with the switch, after a confirmation.
      await gotoRoute(page, '#/bulk');
      await holdFetches(page);
      await page.type('[data-role="bulk-input"]', 'www.example.com');
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => document.getElementById('app-header').classList.contains('is-busy') && window.__heldFetches > 0, { message: 'Bulk Resolve at work' });
      await openWorkspaces(page);
      id = await rowId(page, 'Globex');
      await page.click(`dialog.ws-modal li[data-ws-id="${id}"] [data-action="ws-switch"]`);
      assert(/Still running here: Bulk Resolve/.test(await topMessage(page)), 'names the job');
      await confirmTop(page);
      await page.waitFor(wsActiveIs, { args: ['Globex'], message: 'switched' });
      await closeWorkspaces(page);
      await page.waitFor(() => !document.getElementById('app-header').classList.contains('is-busy') && !document.querySelector('.bulk-results'),
        { message: 'the job stopped, Bulk Resolve opened again empty' });
      await releaseFetches(page);
      await openWorkspaces(page);
      await switchTo(page, 'Acme');
      await closeWorkspaces(page);
      await gotoRoute(page, '#/inventory');
      assertEqual(await editorText(page), INVENTORY_A, 'Acme as saved');
    });

    await run.step('another tab working in the same workspace follows a save', async () => {
      tab2 = await browser.newPage('about:blank', { width: 1200, height: 800 });
      await tab2.goto(`${server.url}#/inventory`);
      await waitReady(tab2);
      await tab2.waitFor((t) => document.querySelector('[data-role="inventory-text"]')?.value === t, { args: [INVENTORY_A], message: 'tab 2 in Acme' });
      // Tab 1 in front again (a background tab's timers are throttled); tab 2 listens in the background.
      await page.send('Page.bringToFront');
      await saveInventory(page, `${INVENTORY_A}\nweb03 192.0.2.12`);
      await tab2.waitFor(() => document.querySelector('[data-role="inventory-text"]').value.includes('web03'), { message: 'tab 2 followed', timeout: 10000 });
      await tab2.close();
      tab2 = null;
    });

    await run.step('expected CAs flag the issuer; the certificate\'s name joins the recent domains', async () => {
      await openWorkspaces(page);
      await page.type('[data-role="ws-expected"]', "Let's Encrypt");
      await page.waitFor(async () => {
        const { state } = await import('./assets/js/state.js');
        return state.workspaceData('expectedCas').join() === "Let's Encrypt";
      }, { message: 'saved expected CAs' });
      const known = await page.evaluate(() => [...document.querySelectorAll('[data-role="ws-expected-list"] .badge')].map((b) => b.textContent));
      assertEqual(known, ["Let's Encrypt"], 'recognised as a known CA');
      await closeWorkspaces(page);
      await gotoRoute(page, '#/cert');
      // The fixtures' test certificate (issued by "Subdomain Scanner Test Root CA" for example-test.com.tr).
      await page.setFileInput('.cert-loader-card .filedrop-input', [path.join(ROOT, 'tests', 'fixtures', 'rsa_multi_san.pem')]);
      await page.waitFor(() => document.querySelector('.cert-overview-issuer [data-expected-ca]'), { message: 'issuer badge' });
      assertEqual(await page.evaluate(() => document.querySelector('.cert-overview-issuer [data-expected-ca]').dataset.expectedCa), 'unexpected', 'not Let\'s Encrypt');
      await openWorkspaces(page);
      await page.type('[data-role="ws-expected"]', "Let's Encrypt\nSubdomain Scanner Test");
      await closeWorkspaces(page);
      await page.waitFor(() => document.querySelector('.cert-overview-issuer [data-expected-ca]')?.dataset.expectedCa === 'expected', { message: 'expected now' });
      await shot(page, opts, 'workspaces-desktop-cert-expected');
      await openWorkspaces(page);
      const recent = await page.evaluate(() => [...document.querySelectorAll('[data-action="ws-recent"]')].map((b) => b.dataset.value));
      assert(recent.includes(CERT_DOMAIN), `recent: ${recent}`);
      await closeWorkspaces(page);
    });

    await run.step('switching workspaces clears the target; switching back fills in its most recent domain', async () => {
      const chip = () => page.evaluate(() => {
        const el = document.querySelector('[data-role="target-chip"]');
        return el && !el.closest('[hidden]') ? el.querySelector('.target-chip-value').textContent : null;
      });
      assertEqual(await chip(), CERT_DOMAIN, 'the certificate made it the target');
      await openWorkspaces(page);
      await switchTo(page, 'Globex');
      await closeWorkspaces(page);
      await page.waitFor(() => !document.querySelector('.cert-overview'), { message: 'the Certificate view opened again, empty' });
      assertEqual(await chip(), null, 'Globex has no recent domain');
      await openWorkspaces(page);
      await switchTo(page, 'Acme');
      await closeWorkspaces(page);
      await page.waitFor((d) => document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent === d, { args: [CERT_DOMAIN], message: 'Acme\'s last domain' });
      const href = await page.evaluate(() => document.querySelector('#app-nav a.nav-link[data-view="health"]').getAttribute('href'));
      assertEqual(href, `#/health?domain=${CERT_DOMAIN}&run=0`, 'every tool gets it filled in');
    });

    let sealed = '';
    await run.step('export with a password: the file shows no name, server or address, not even in its file name', async () => {
      await openWorkspaces(page);
      await page.type('[data-role="ws-export-password"]', PASSWORD);
      await page.type('[data-role="ws-export-repeat"]', `${PASSWORD}x`);
      await page.click('[data-action="ws-export"]');
      await page.waitFor(() => /differ|farklı/.test(document.querySelector('[data-role="ws-export-repeat"]').closest('.field').textContent), { message: 'passwords differ' });
      await page.type('[data-role="ws-export-password"]', PASSWORD);
      await page.type('[data-role="ws-export-repeat"]', PASSWORD);
      await page.click('[data-action="ws-export"]');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'file saved', timeout: 20000 });
      const [file] = await takeDownloads(page);
      assert(/^domainscope-workspace-encrypted-\d{8}-\d{4}\.json$/.test(file.name), file.name);
      const json = JSON.parse(file.text);
      assertEqual([json.format, json.v, json.encrypted, json.kdf.name, json.kdf.hash, json.cipher.name], ['domainscope-workspace', 1, true, 'PBKDF2', 'SHA-256', 'AES-GCM'], 'sealed');
      assert(json.kdf.iterations >= 310000, `iterations ${json.kdf.iterations}`);
      for (const secret of ['Acme', 'web01', '192.0.2.10', CERT_DOMAIN, PASSWORD]) {
        assert(!file.text.includes(secret) && !file.name.includes(secret), `the file shows ${secret}`);
      }
      const fields = await page.evaluate(() => [document.querySelector('[data-role="ws-export-password"]').value, document.querySelector('[data-role="ws-export-repeat"]').value]);
      assertEqual(fields, ['', ''], 'the password is not kept in the form');
      sealed = file.text;
      // A password of spaces only is refused; no password at all is a plain file, named after its workspace.
      await page.type('[data-role="ws-export-password"]', ' '.repeat(10));
      await page.type('[data-role="ws-export-repeat"]', ' '.repeat(10));
      await page.click('[data-action="ws-export"]');
      await page.waitFor(() => /spaces only/.test(document.querySelector('[data-role="ws-export-password"]').closest('.field').textContent),
        { message: 'a blank password refused' });
      await page.type('[data-role="ws-export-password"]', '');
      await page.type('[data-role="ws-export-repeat"]', '');
      await page.click('[data-action="ws-export"]');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'plain file saved' });
      const [plain] = await takeDownloads(page);
      assert(/^domainscope-workspace-Acme-\d{8}-\d{4}\.json$/.test(plain.name), plain.name);
      assertEqual(JSON.parse(plain.text).encrypted, false, 'plain');
    });

    await run.step('import: a wrong password imports nothing; the right one opens it as a new workspace', async () => {
      const file = path.join(tmp, 'acme-sealed.json');
      await writeFile(file, sealed);
      await page.setFileInput('[data-role="ws-import"] input[type="file"]', [file]);
      await page.waitFor(() => document.querySelector('[data-role="ws-import-password"]'), { message: 'asks for the password' });
      await page.type('[data-role="ws-import-password"]', 'not the password');
      await page.click('[data-action="ws-import-open"]');
      await page.waitFor(() => document.querySelector('[data-role="ws-import-error"]')?.dataset.code === 'wrong-password', { message: 'wrong password', timeout: 20000 });
      const words = await page.evaluate(() => document.querySelector('[data-role="ws-import-error"]').textContent);
      assert(/Wrong password, or the file was changed/.test(words), words);
      assertEqual((await page.evaluate(wsInfo)).list, ['default', 'Acme', 'Globex'], 'nothing imported');
      await page.type('[data-role="ws-import-password"]', PASSWORD);
      await page.click('[data-action="ws-import-open"]');
      await page.waitFor(() => document.querySelector('[data-role="ws-import-summary"]'), { message: 'summary', timeout: 20000 });
      const summary = await page.evaluate(() => ({
        text: document.querySelector('[data-role="ws-import-summary"]').textContent,
        replace: !!document.querySelector('[data-action="ws-import-replace"]')
      }));
      assert(/“Acme”/.test(summary.text) && /3 servers/.test(summary.text) && /was encrypted/.test(summary.text), summary.text);
      assertEqual(summary.replace, true, 'a workspace of that name exists: replacing it is offered');
      await shot(page, opts, 'workspaces-desktop-import');
      await page.click('[data-action="ws-import-new"]');
      await page.waitFor(wsActiveIs, { args: ['Acme (2)'], message: 'imported and active' });
      await closeWorkspaces(page);
      const info = await page.evaluate(wsInfo);
      assertEqual(info.list, ['default', 'Acme', 'Acme (2)', 'Globex'], 'a new workspace');
      assert(info.inventory.includes('web03 192.0.2.12'), 'the same servers');
      const expected = await page.evaluate(async () => (await import('./assets/js/state.js')).state.workspaceData('expectedCas'));
      assertEqual(expected, ["Let's Encrypt", 'Subdomain Scanner Test'], 'and the expected CAs');
    });

    await run.step('import over the workspace of the same name, after a confirmation; a JSON that is no workspace file is refused', async () => {
      await openWorkspaces(page);
      await switchTo(page, 'Globex');
      const other = path.join(tmp, 'other.json');
      await writeFile(other, JSON.stringify({ hello: 'world' }));
      await page.setFileInput('[data-role="ws-import"] input[type="file"]', [other]);
      await page.waitFor(() => document.querySelector('[data-role="ws-import-error"]')?.dataset.code === 'not-workspace', { message: 'not a workspace file' });
      await page.setFileInput('[data-role="ws-import"] input[type="file"]', [path.join(tmp, 'acme-sealed.json')]);
      await page.waitFor(() => document.querySelector('[data-role="ws-import-password"]'));
      await page.type('[data-role="ws-import-password"]', PASSWORD);
      await page.click('[data-action="ws-import-open"]');
      await page.waitFor(() => document.querySelector('[data-action="ws-import-replace"]'), { message: 'replace offered', timeout: 20000 });
      await page.click('[data-action="ws-import-replace"]');
      await confirmTop(page);
      await page.waitFor(wsActiveIs, { args: ['Acme'], message: 'Acme, replaced and active' });
      await closeWorkspaces(page);
      assertEqual((await page.evaluate(wsInfo)).list, ['default', 'Acme', 'Acme (2)', 'Globex'], 'no new workspace');
    });

    await run.step('a workspace is deleted after a confirmation', async () => {
      await openWorkspaces(page);
      const id = await rowId(page, 'Acme (2)');
      await page.click(`dialog.ws-modal li[data-ws-id="${id}"] [data-action="ws-delete"]`);
      await confirmTop(page);
      await page.waitFor((i) => !document.querySelector(`dialog.ws-modal li[data-ws-id="${i}"]`), { args: [id], message: 'row gone' });
      await closeWorkspaces(page);
      assertEqual((await page.evaluate(wsInfo)).list, ['default', 'Acme', 'Globex'], 'list');
    });

    await run.step('keyboard: Esc in the rename field cancels the rename, not the dialog; clearing the recent list keeps the focus inside', async () => {
      await openWorkspaces(page);
      const id = await rowId(page, 'Globex');
      const renameFocused = (i) => !!document.activeElement?.matches(`dialog.ws-modal li[data-ws-id="${i}"] [data-action="ws-rename"]`);
      await page.click(`dialog.ws-modal li[data-ws-id="${id}"] [data-action="ws-rename"]`);
      await page.waitFor(() => document.activeElement?.dataset.role === 'ws-rename-input', { message: 'the rename field has the focus' });
      await page.type('[data-role="ws-rename-input"]', 'Globex Corp');
      await page.press('Escape');
      await page.waitFor(renameFocused, { args: [id], message: 'Esc: the focus is back on Rename' });
      assert(await page.evaluate(() => !!document.querySelector('dialog.ws-modal[open]')), 'the dialog stays open');
      assertEqual((await page.evaluate(wsInfo)).list, ['default', 'Acme', 'Globex'], 'not renamed');
      // Enter on Rename opens the field again; Enter in it saves, and the focus is back on Rename.
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.role === 'ws-rename-input', { message: 'the rename field again' });
      await page.type('[data-role="ws-rename-input"]', 'Globex Corp');
      await page.press('Enter');
      await page.waitFor(renameFocused, { args: [id], message: 'saved: the focus is back on Rename' });
      assertEqual((await page.evaluate(wsInfo)).list, ['default', 'Acme', 'Globex Corp'], 'renamed');
      // Acme is active and has recent domains: Clear the list, from the keyboard.
      await page.evaluate(() => document.querySelector('[data-action="ws-recent-clear"]').focus());
      await page.press('Enter');
      await page.waitFor(() => {
        const el = document.activeElement;
        return el?.dataset.role === 'ws-recent-empty' && !!el.closest('dialog.ws-modal[open]');
      }, { message: 'the focus stays in the dialog, on the empty list' });
      await closeWorkspaces(page);
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.workspaceData('recent')), [], 'cleared');
    });

    await run.step('a workspace whose creation could not be written (storage full for a moment) is stored by its next save', async () => {
      await openWorkspaces(page);
      await page.evaluate(() => {
        const put = IDBObjectStore.prototype.put;
        window.__restorePut = () => {
          IDBObjectStore.prototype.put = put;
        };
        IDBObjectStore.prototype.put = function full() {
          throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
        };
      });
      await createWorkspace(page, 'Initech');
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((el) => /Not saved: the browser’s storage for this site is full/.test(el.textContent)),
        { message: 'says why it was not saved' });
      await page.evaluate(() => window.__restorePut());
      await page.type('[data-role="ws-notes"]', 'Initech contacts');
      const status = await page.waitFor(() => {
        const text = document.querySelector('[data-role="ws-notes"]').closest('.ws-block').querySelector('.ws-status').textContent;
        return text && text !== 'Saving…' ? text : false;
      }, { message: 'notes saved' });
      assertEqual(status, 'Saved', 'stored now, never "deleted in another tab"');
      await closeWorkspaces(page);
      await page.reload();
      await waitReady(page);
      const info = await page.evaluate(wsInfo);
      assertEqual([info.active, info.list], ['Initech', ['default', 'Acme', 'Globex Corp', 'Initech']], 'still there after a reload');
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.workspaceData('notes')), 'Initech contacts', 'with its notes');
    });

    await run.step('Settings › Delete all local data deletes every workspace and the database, and says so', async () => {
      await gotoRoute(page, '#/inventory');
      await page.click('[data-control="settings"]');
      await page.waitForSelector('dialog.modal[open] .settings-danger');
      const hint = await page.evaluate(() => document.querySelector('dialog.modal[open] .settings-danger .field-hint').textContent);
      assert(/Deletes every workspace/.test(hint) && /IndexedDB/.test(hint), hint);
      await page.click('dialog.modal[open] .settings-danger .btn-danger');
      await confirmTop(page);
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((el) => /every workspace/.test(el.textContent)), { message: 'the toast says so', timeout: 10000 });
      await page.waitFor(async () => !(await indexedDB.databases()).some((d) => d.name === 'ssds.workspaces'), { message: 'database deleted', timeout: 10000 });
      const info = await page.evaluate(wsInfo);
      assertEqual([info.active, info.header, info.list, info.inventory], ['default', 'Default', ['default'], ''], 'back to an empty Default');
      const keys = await page.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith('ssds.')));
      assertEqual(keys, [], 'no ssds.* key left');
      assertEqual(netHits, [], 'nothing left the page');
    });

    await run.step('desktop: no console errors, CSP violations or missing keys', async () => {
      await assertClean(page, 'workspaces desktop', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    if (tab2) await tab2.close();
    await page.close();
  }
}

/** What a browser that blocks storage for the page (Safari's "Block all cookies") does: every storage accessor throws. */
const BLOCK_STORAGE = `(() => {
  const refuse = () => { throw new DOMException('The operation is insecure.', 'SecurityError'); };
  for (const name of ['localStorage', 'sessionStorage', 'indexedDB']) Object.defineProperty(window, name, { get: refuse, configurable: true });
})();`;

async function blockedStorage(browser, server) {
  run.group('Storage blocked (1024 px, offline)');
  const page = await browser.newPage('about:blank', { width: 1024, height: 800 });
  await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: BLOCK_STORAGE });
  try {
    await run.step('the page works in memory; Delete all local data says nothing had been saved, not that it failed', async () => {
      await page.goto(`${server.url}#/inventory`);
      await waitReady(page);
      await setLangUi(page, 'en');
      const stored = await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => [state.persistence, state.workspacePersistence]));
      assertEqual(stored, [false, false], 'nothing can be stored');
      await saveInventory(page, INVENTORY_A);
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      await page.click('[data-control="settings"]');
      await page.waitForSelector('dialog.modal[open] .settings-danger');
      await page.click('dialog.modal[open] .settings-danger .btn-danger');
      await confirmTop(page);
      const toast = await page.waitFor(() => {
        const el = [...document.querySelectorAll('.toast')].find((x) => /Local data|local data/.test(x.textContent));
        return el ? { text: el.textContent, error: el.classList.contains('toast-error') } : false;
      }, { message: 'the toast', timeout: 10000 });
      assert(/blocks storage for this page, so nothing was saved/.test(toast.text) && !toast.error, toast.text);
      assert(!/IndexedDB|Not all/.test(toast.text), toast.text);
      assertEqual((await page.evaluate(wsInfo)).inventory, '', 'reset in memory');
    });

    await run.step('storage blocked: no console errors, CSP violations or missing keys', async () => {
      await assertClean(page, 'workspaces storage blocked', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    await page.close();
  }
}

async function unreadableDatabase(browser, server) {
  run.group('A database this version cannot open (1024 px, offline)');
  const page = await browser.newPage('about:blank', { width: 1024, height: 800 });
  await networkGuard(page);
  try {
    await run.step('the page works in memory; Delete all local data still deletes the database, and says so', async () => {
      await page.goto(`${server.url}#/inventory`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await saveInventory(page, INVENTORY_A);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.whenSaved());
      // A later version of the app upgraded the database (then a rollback, or an older build still cached).
      await page.evaluate(() => new Promise((resolve, reject) => {
        const request = indexedDB.open('ssds.workspaces', 2);
        request.onupgradeneeded = () => request.result.createObjectStore('later');
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
      }));
      await page.reload();
      await waitReady(page);
      const stored = await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => [state.workspacePersistence, state.workspaceDatabase]));
      assertEqual(stored, [false, true], 'in memory, the database still there');
      assertEqual((await page.evaluate(wsInfo)).inventory, '', 'nothing of it read');
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      await page.click('[data-control="settings"]');
      await page.waitForSelector('dialog.modal[open] .settings-danger');
      await page.click('dialog.modal[open] .settings-danger .btn-danger');
      await confirmTop(page);
      const toast = await page.waitFor(() => {
        const el = [...document.querySelectorAll('.toast')].find((x) => /local data/i.test(x.textContent));
        return el ? { text: el.textContent, error: el.classList.contains('toast-error') } : false;
      }, { message: 'the toast', timeout: 10000 });
      assert(/every workspace \(its IndexedDB database too\)/.test(toast.text) && !toast.error, toast.text);
      assert(!/only in this tab/.test(toast.text), toast.text);
      await page.waitFor(async () => !(await indexedDB.databases()).some((d) => d.name === 'ssds.workspaces'), { message: 'database deleted', timeout: 10000 });
    });

    await run.step('unreadable database: no console errors, CSP violations or missing keys', async () => {
      await assertClean(page, 'workspaces unreadable database', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    await page.close();
  }
}

async function phone(browser, server) {
  run.group('Workspaces on a phone (375 / 320 px, Turkish, dark)');
  const page = await browser.newPage('about:blank', { width: 375, height: 812, mobile: true });
  await networkGuard(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
  try {
    await run.step('375 px: the switcher sits in the Tools menu; the dialog fits', async () => {
      await page.goto(`${server.url}#/inventory`);
      await waitReady(page);
      await setLangUi(page, 'tr');
      const header = await page.evaluate(() => getComputedStyle(document.querySelector('.header-workspace')).display);
      assertEqual(header, 'none', 'no switcher in the header');
      await openWorkspaces(page, { phone: true });
      await createWorkspace(page, 'Müşteri Anonim Şirketi — İstanbul Bölge Müdürlüğü');
      await assertNoHorizontalScroll(page, 'phone dialog');
      const fits = await page.evaluate(() => {
        const body = document.querySelector('dialog.ws-modal .modal-body');
        return body.scrollWidth <= body.clientWidth + 1;
      });
      assert(fits, 'the dialog body does not scroll sideways');
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      if (opts.shots) {
        await mkdir(SHOTS, { recursive: true });
        await page.screenshot(path.join(SHOTS, 'workspaces-phone-tr-dark-dialog.png'));
      }
      await closeWorkspaces(page);
      await page.click('[data-control="nav-menu"]');
      await page.waitFor(() => document.querySelector('dialog.navmenu-modal[open] .navmenu-workspace-name'));
      const row = await page.evaluate(() => document.querySelector('.navmenu-workspace-name').textContent);
      assertEqual(row, 'Müşteri Anonim Şirketi — İstanbul Bölge Müdürlüğü', 'the Tools menu names it');
      // One "Çalışma alanı" in the menu, the workspace row's: Servers and About have a heading of their own.
      const headings = await page.evaluate(() => [...document.querySelectorAll('dialog.navmenu-modal[open] .navmenu-label')].map((el) => el.textContent));
      assertEqual(headings.at(-1), 'Kurulum ve bilgi', 'Servers and About');
      assert(!headings.includes('Çalışma alanı'), headings.join(' | '));
      await assertNoHorizontalScroll(page, 'tools menu');
      await page.evaluate(() => document.querySelector('dialog.navmenu-modal').close());
    });

    await run.step('320 px: the dialog and the Servers card still fit', async () => {
      await page.setViewport({ width: 320, height: 700, mobile: true });
      await page.reload();
      await waitReady(page);
      await assertNoHorizontalScroll(page, '320 servers');
      await openWorkspaces(page, { phone: true });
      await assertNoHorizontalScroll(page, '320 dialog');
      await shot(page, opts, 'workspaces-phone-320');
      await closeWorkspaces(page);
    });

    await run.step('phone: no console errors, CSP violations or missing keys', async () => {
      await assertClean(page, 'workspaces phone', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    await page.close();
  }
}

async function main() {
  if (opts.shots) await mkdir(SHOTS, { recursive: true });
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-workspaces-'));
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`Serving ${server.url} — ${version.product}\n`);
  try {
    await desktop(browser, server, tmp);
    await blockedStorage(browser, server);
    await unreadableDatabase(browser, server);
    await phone(browser, server);
  } finally {
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
