#!/usr/bin/env node
/**
 * pfx.e2e.mjs — end-to-end test of opening a PKCS#12 (.pfx / .p12) file (ui/pfx-import.js over
 * lib/x509.js loadCertificates and lib/pkcs12.js) in the Certificate view and in SSL Targets
 * step 1, in a real headless Chrome/Edge. OFFLINE: the bundles are tests/fixtures/p12_*.p12, and
 * a network-level guard (CDP Fetch) fails and records any https request — the suite asserts none.
 *
 *   node tests/e2e/pfx.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - Certificate view: a .p12 opens the password dialog (focus in the password field, nothing
 *     loaded yet); a wrong password keeps it open with "does not match the integrity check" (and,
 *     for a bundle without a MAC, "no integrity check to tell them apart"); the right one, with
 *     "Check that the private key matches" ticked from the keyboard, loads the leaf and its chain
 *     (file order leaf, root, intermediate), the note says the key matches and takes the focus,
 *     no password field or private key is left in the page, and Download fullchain.pem gives the
 *     leaf and the intermediate in that order without the key (the overview offers no second
 *     chain download). A legacy bundle (RC2-40 + 3DES) marks its encryption weak / legacy and says
 *     the key was not checked; Cancel loads nothing, keeps the certificate shown and says so; the
 *     browser's own WebCrypto opens an AES-192 key (Chromium refuses the key size: the JS
 *     cipher), a PBMAC1 bundle and a Turkish password with an emoji; a bundle whose certificates
 *     use RC4 closes the dialog on the reason (the OpenSSL command with -legacy) and the focus
 *     lands on that warning; a key under RC4 is named "not supported here" in the note, and the
 *     key check says it cannot check it (both crafted here, in a temporary directory);
 *   - SSL Targets step 1: a bundle whose key belongs to its intermediate says the key does not
 *     match the leaf and names the owner, step 2 gets the leaf's domain, fullchain.pem downloads
 *     from the step; the empty password opens a passwordless bundle; a SHA-224 MAC is not
 *     supported and the focus goes to the warning; no scan starts;
 *   - Turkish + dark, a 375 px phone (the dialog and both notes fit without horizontal scroll);
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, gotoRoute, installDownloadCapture, setLangUi, takeDownloads, waitReady
} from './scan.e2e.mjs';

const { passwords: PASSWORDS } = JSON.parse(await readFile(path.join(FIXTURES, 'p12_expected.json'), 'utf8'));
const PASS = PASSWORDS.test;
const fixture = (name) => path.join(FIXTURES, name);
/** The DER of a PEM fixture's first certificate, as base64 (to find it in a download). */
const derB64 = async (file) => Buffer.from(parseCertificates(await readFile(fixture(file))).leaf.der).toString('base64');

// ---------------------------------------------------------------------------
// Crafted bundles (DER by hand: what OpenSSL 3 will no longer write)
// ---------------------------------------------------------------------------
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map((x) => Buffer.from(x)));
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...len]), body]);
};
const seq = (...x) => tlv(0x30, ...x);
const ctx0 = (...x) => tlv(0xa0, ...x);
const octet = (b) => tlv(0x04, b);
const int = (n) => tlv(0x02, Buffer.from(n < 0x80 ? [n] : [n >> 8, n & 0xff]));
const oid = (s) => {
  const [a, b, ...rest] = s.split('.').map(Number);
  const out = [a * 40 + b];
  for (const v of rest) {
    const bytes = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) bytes.unshift((x & 0x7f) | 0x80);
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
};
const DATA = '1.2.840.113549.1.7.1';
const RC4 = seq(oid('1.2.840.113549.1.12.1.1'), seq(octet(Buffer.alloc(8, 7)), int(2048))); // pbeWithSHAAnd128BitRC4
/** PFX around AuthenticatedSafe ContentInfos, with an optional raw MacData. */
const pfxOf = (infos, mac = null) => seq(int(3), seq(oid(DATA), ctx0(octet(seq(...infos)))), ...(mac ? [mac] : []));
const dataInfo = (...bags) => seq(oid(DATA), ctx0(octet(seq(...bags))));
const certBag = (der) => seq(oid('1.2.840.113549.1.12.10.1.3'), ctx0(seq(oid('1.2.840.113549.1.9.22.1'), ctx0(octet(der)))));

/**
 * The crafted files, written to `dir`: certificates under RC4 (EncryptedData), a readable
 * certificate with its key under RC4 (no MAC), and a SHA-224 MAC.
 */
async function craftBundles(dir) {
  const leaf = Buffer.from(parseCertificates(await readFile(fixture('p12_rsa.pem'))).leaf.der);
  const encrypted = seq(oid('1.2.840.113549.1.7.6'), ctx0(seq(int(0), seq(oid(DATA), RC4, tlv(0x80, Buffer.alloc(64, 1))))));
  const shrouded = seq(oid('1.2.840.113549.1.12.10.1.2'), ctx0(seq(RC4, octet(Buffer.alloc(64, 2)))));
  const sha224Mac = seq(seq(seq(oid('2.16.840.1.101.3.4.2.4'), Buffer.from([5, 0])), octet(Buffer.alloc(28, 3))), octet(Buffer.alloc(8, 4)), int(2048));
  const files = {
    'rc4-certs.p12': pfxOf([encrypted]),
    'rc4-key.p12': pfxOf([dataInfo(certBag(leaf), shrouded)]),
    'sha224-mac.p12': pfxOf([dataInfo(certBag(leaf))], sha224Mac)
  };
  for (const [name, bytes] of Object.entries(files)) await writeFile(path.join(dir, name), bytes);
  return (name) => path.join(dir, name);
}

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

/** Element screenshot (beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(opts.shotsDir, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(opts.shotsDir, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Viewport screenshot (the dialog is a modal over the page); no-op with --no-shots. */
async function shotViewport(page, opts, name) {
  if (!opts.shots) return;
  await mkdir(opts.shotsDir, { recursive: true });
  await page.screenshot(path.join(opts.shotsDir, `${name}.png`));
}

/** Elements under `selector` sticking out of the viewport (code blocks scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('pre, .codeblock')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
const focusedRole = (page) => page.evaluate(() => {
  const a = document.activeElement;
  if (!a) return null;
  return a.dataset.role || a.dataset.action || (a.classList.contains('pfx-note') ? 'pfx-note' : a.tagName);
});

/** Choose a bundle (a fixture name or a path) in the loader under `root` and wait for its password dialog. */
async function choose(page, root, file) {
  await page.evaluate((r) => {
    const more = document.querySelector(`${r} details.cert-reload, ${r} details.scan-cert-another`);
    if (more) more.open = true;
  }, root);
  await page.setFileInput(`${root} .filedrop-input`, [path.isAbsolute(file) ? file : fixture(file)]);
  await page.waitFor(() => document.activeElement && document.activeElement.dataset.role === 'pfx-password', { message: `password dialog for ${file}` });
}

/** Type the password, optionally tick the key check from the keyboard, press Enter; wait for the new note. */
async function unlock(page, root, password, { checkKey = false } = {}) {
  // Notes already on screen are marked, so only the one the bundle brings counts.
  await page.evaluate(() => document.querySelectorAll('.pfx-note').forEach((n) => { n.dataset.e2eOld = '1'; }));
  if (password) await page.type('[data-role="pfx-password"]', password);
  if (checkKey) {
    await page.press('Tab'); // → the checkbox
    assertEqual(await focusedRole(page), 'pfx-check-key', 'Tab reaches the key check');
    await page.press('Space');
  }
  await page.press('Enter');
  await page.waitFor((r) => !document.querySelector('.pfx-dialog') && document.querySelector(`${r} .pfx-note:not([data-e2e-old])`),
    { args: [root], message: 'bundle opened', timeout: 20000 });
  await removeToasts(page);
}

/** What the page shows of the note under `root`. */
const noteInfo = (page, root) => page.evaluate((r) => {
  const n = document.querySelector(`${r} .pfx-note`);
  return n ? {
    keyCheck: n.dataset.keyCheck,
    text: n.textContent,
    badges: [...n.querySelectorAll('.pfx-strength')].map((b) => b.textContent),
    facts: [...n.querySelectorAll('.pfx-facts .kv-key')].map((k) => k.textContent)
  } : null;
}, root);

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const LEAF = await derB64('p12_rsa.pem');
  const INTER = await derB64('p12_inter.pem');
  const ROOT_CA = await derB64('p12_root.pem');
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-pfx-e2e-'));
  const crafted = await craftBundles(tmp);

  run.group('Node: harness');
  await run.step('run-all orders the pfx suite right after dane', () => {
    assertEqual(orderSuites(['global.e2e.mjs', 'pfx.e2e.mjs', 'dane.e2e.mjs', 'cert.e2e.mjs']), ['cert', 'dane', 'pfx', 'global'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: PKCS#12 fixtures only\n`);
  let page = null;
  let netHits = [];
  const CERT = '.cert-view';
  const STEP = '.scan-step-cert';
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/cert`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'cert');

    run.group('Certificate view (desktop 1440×900, English, light)');
    await run.step('a .p12 opens the password dialog: focus in the field, nothing loaded yet', async () => {
      await choose(page, CERT, 'p12_rsa_aes.p12');
      const info = await page.evaluate(() => {
        const d = document.querySelector('dialog.pfx-dialog');
        return {
          open: !!(d && d.open),
          title: d && document.getElementById(d.getAttribute('aria-labelledby'))?.textContent,
          intro: d && d.querySelector('.pfx-intro')?.textContent,
          type: document.querySelector('[data-role="pfx-password"]')?.type,
          checked: document.querySelector('[data-role="pfx-check-key"]')?.checked,
          loaded: !!document.querySelector('.cert-overview')
        };
      });
      assert(info.open, 'modal dialog open');
      assertEqual(info.title, 'Open the PKCS#12 file', 'labelled by its title');
      assert(info.intro.startsWith('p12_rsa_aes.p12 is a PKCS#12 file'), `intro: ${info.intro}`);
      assertEqual(info.type, 'password', 'a password field');
      assertEqual(info.checked, false, 'the key check is opt-in');
      assert(!info.loaded, 'no certificate before the password');
      await shotViewport(page, opts, 'pfx-dialog-desktop-light-en');
    });

    await run.step('a wrong password keeps the dialog open with the reason, the field keeps the focus', async () => {
      await page.type('[data-role="pfx-password"]', 'not-the-password');
      await page.press('Enter');
      const err = await page.waitFor(() => {
        const e = document.querySelector('.pfx-dialog .field-error:not([hidden])');
        return e && e.textContent;
      }, { message: 'wrong password error' });
      assert(/^Wrong password: it does not match the file’s integrity check/.test(err), `error: ${err}`);
      assertEqual(await focusedRole(page), 'pfx-password', 'focus stays in the field');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="pfx-password"]').getAttribute('aria-invalid')), 'true', 'aria-invalid');
      assert(!(await page.evaluate(() => !!document.querySelector('.cert-overview'))), 'still nothing loaded');
    });

    await run.step('the right password with the key check: the chain loads, the key matches, the note takes the focus', async () => {
      await unlock(page, CERT, PASS, { checkKey: true });
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.cert-overview-cn')?.textContent,
        options: [...document.querySelectorAll('[data-role="cert-select"] option')].map((o) => o.textContent),
        passwordFields: document.querySelectorAll('input[type="password"]').length,
        dialogs: document.querySelectorAll('dialog').length,
        chainButton: !!document.querySelector('[data-action="download-chain"]')
      }));
      assertEqual(info.cn, 'p12.example.com', 'the leaf');
      assertEqual(info.options.length, 3, 'three certificates');
      assertEqual(info.passwordFields + info.dialogs, 0, 'no dialog or password field left');
      assert(!info.chainButton, 'the overview does not offer a second chain download');
      const note = await noteInfo(page, CERT);
      assertEqual(note.keyCheck, 'match', 'key check');
      assert(note.text.includes('The file holds 3 certificates and 1 private key.'), note.text);
      assert(note.text.includes('The private key matches this certificate'), 'match verdict');
      assert(note.text.includes('AES-256-CBC · PBKDF2-HMAC-SHA256 · 2,048 iterations'), 'encryption');
      assert(note.text.includes('HMAC-SHA256 · 2,048 iterations'), 'integrity check');
      assertEqual(note.facts, ['Friendly name', 'Certificates', 'Private key', 'Integrity check'], 'facts');
      assertEqual(await focusedRole(page), 'pfx-note', 'focus on the note, not <body>');
      assert(!(await page.evaluate(() => /PRIVATE KEY/.test(document.body.textContent))), 'no private key in the page');
      await shotEl(page, opts, 'pfx-cert-desktop-light-en', '.cert-content');
    });

    await run.step('Chain tab: leaf → intermediate → root although the file lists leaf, root, intermediate', async () => {
      await page.click('.cert-tabs .tab[data-tab="chain"]');
      const roles = await page.waitFor(() => {
        const r = [...document.querySelectorAll('.cert-chain > .cert-chain-item')].map((li) => `${li.dataset.role}:${li.querySelector('.cert-chain-cn')?.textContent}`);
        return r.length === 3 ? r : false;
      }, { message: 'chain items' });
      assertEqual(roles, ['leaf:p12.example.com', 'intermediate:Example P12 Test Intermediate', 'root:Example P12 Test Root'], 'chain order');
    });

    await run.step('Download fullchain.pem: the leaf, then the intermediate — no root, no key', async () => {
      await takeDownloads(page);
      await page.click(`${CERT} [data-action="pfx-fullchain"]`);
      const [file] = await takeDownloads(page);
      assertEqual(file && file.name, 'p12.example.com-fullchain.pem', 'file name');
      const blocks = file.text.match(/-----BEGIN ([A-Z ]+)-----\n([\s\S]*?)-----END \1-----/g) || [];
      assertEqual(blocks.length, 2, 'two PEM blocks');
      const bodies = blocks.map((b) => b.replace(/-----[^-]+-----|\s/g, ''));
      assertEqual(bodies, [LEAF, INTER], 'leaf then intermediate');
      assert(!file.text.includes(ROOT_CA) && !/PRIVATE KEY/.test(file.text), 'no root, no key');
    });

    await run.step('a legacy bundle (RC2-40 + 3DES), key check off: weak / legacy marks, "not checked"', async () => {
      await choose(page, CERT, 'p12_rsa_legacy.p12');
      await unlock(page, CERT, PASS);
      const note = await noteInfo(page, CERT);
      assertEqual(note.keyCheck, 'none', 'no key check');
      assert(note.text.includes('RC2-40-CBC · PKCS#12 KDF (SHA-1)'), 'RC2-40');
      assert(note.text.includes('3DES-CBC · PKCS#12 KDF (SHA-1)'), '3DES');
      assert(note.text.includes('HMAC-SHA1'), 'SHA-1 MAC');
      assertEqual(note.badges, ['weak', 'legacy'], 'strength badges');
      // What they mean is written out, not only in a tooltip (keyboard, touch).
      assert(note.text.includes('a private key under it is not protected') && note.text.includes('Export with AES-256 when you can'), 'the badges explained');
      assert(note.text.includes('The key was not checked.'), 'not checked');
    });

    await run.step('no MAC and a wrong password: "no integrity check to tell them apart"', async () => {
      await choose(page, CERT, 'p12_nomac.p12');
      await page.type('[data-role="pfx-password"]', 'nope');
      await page.click('[data-action="pfx-open"]');
      const err = await page.waitFor(() => document.querySelector('.pfx-dialog .field-error:not([hidden])')?.textContent, { message: 'no-mac error' });
      assert(/no integrity check to tell the two apart/.test(err), `error: ${err}`);
      assertEqual(await focusedRole(page), 'pfx-password', 'focus back in the field');
    });

    await run.step('Cancel (Escape) loads nothing, keeps the certificate shown and says so', async () => {
      await page.press('Escape');
      const toast = await page.waitFor(() => !document.querySelector('.pfx-dialog') && document.querySelector('.toast')?.textContent, { message: 'toast' });
      assert(/p12_nomac\.p12 was not opened/.test(toast), `toast: ${toast}`);
      assertEqual(await page.evaluate(() => [document.querySelector('.cert-overview-cn')?.textContent, document.querySelector('.pfx-note')?.dataset.keyCheck]),
        ['p12.example.com', 'none'], 'the legacy bundle is still shown');
      // The drop zone no longer says the file it did not open was loaded.
      const statuses = await page.evaluate(() => [...document.querySelectorAll('.cert-drop .filedrop-status')].map((el) => el.textContent));
      assert(!statuses.some((x) => /p12_nomac/.test(x)), `drop status: ${statuses.join(' | ')}`);
      await removeToasts(page);
    });

    await run.step('certificates under RC4: the dialog closes on the reason, the focus lands on the warning', async () => {
      await choose(page, CERT, crafted('rc4-certs.p12'));
      await page.type('[data-role="pfx-password"]', 'x');
      await page.press('Enter');
      const info = await page.waitFor(() => {
        const w = document.querySelector('.cert-content [data-warning="PKCS12_UNSUPPORTED"]');
        return !document.querySelector('.pfx-dialog') && w ? {
          text: w.textContent,
          focused: document.activeElement === w,
          overview: !!document.querySelector('.cert-overview')
        } : false;
      }, { message: 'unsupported warning' });
      assert(info.text.includes('It uses pbeWithSHAAnd128BitRC4, which this page does not support.'), info.text);
      assert(info.text.includes('openssl pkcs12 -legacy -in rc4-certs.p12 -nokeys -out cert.pem'), 'the -legacy command');
      assert(info.focused, `focus on the warning, not ${await focusedRole(page)}`);
      assert(!info.overview, 'no certificate shown');
      await removeToasts(page);
    });

    await run.step('a key under RC4: "not supported here" in the note, the key check says it cannot check it', async () => {
      await choose(page, CERT, crafted('rc4-key.p12'));
      await unlock(page, CERT, 'x', { checkKey: true });
      const note = await noteInfo(page, CERT);
      assertEqual(note.keyCheck, 'unsupported-encryption', 'key check');
      assert(note.text.includes('pbeWithSHAAnd128BitRC4 · not supported here'), `Private key row: ${note.text}`);
      assert(note.text.includes('The key’s encryption (pbeWithSHAAnd128BitRC4) is not supported here, so the key cannot be checked.'), 'verdict');
      assertEqual(await page.evaluate(() => document.querySelector('.cert-overview-cn')?.textContent), 'p12.example.com', 'the certificate loads');
      assertEqual(await focusedRole(page), 'pfx-note', 'focus on the note');
    });

    await run.step('in the browser WebCrypto: an AES-192 key (Chromium refuses it: the JS cipher), PBMAC1, a password with an emoji', async () => {
      const cases = [
        ['p12_ec_aes128.p12', PASS, 'AES-192-CBC', 'EC P-256'],
        ['p12_p384_pbmac1.p12', PASS, 'PBMAC1 (PBKDF2-HMAC-SHA256, HMAC-SHA256)', 'EC P-384'],
        ['p12_unicode.p12', PASSWORDS.unicode, 'AES-256-CBC', 'EC P-256']
      ];
      for (const [file, password, shown, algorithm] of cases) {
        await choose(page, CERT, file);
        await unlock(page, CERT, password, { checkKey: true });
        const note = await noteInfo(page, CERT);
        assertEqual(note.keyCheck, 'match', `${file}: key check`);
        assert(note.text.includes(shown) && note.text.includes(algorithm), `${file}: ${note.text}`);
      }
    });

    run.group('Languages, themes, phone (Certificate view)');
    await run.step('Turkish + dark: the note is rebuilt in Turkish, no raw keys', async () => {
      await choose(page, CERT, 'p12_rsa_aes.p12');
      await unlock(page, CERT, PASS, { checkKey: true });
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      const note = await page.waitFor(() => {
        const n = document.querySelector('.pfx-note');
        return n && /PKCS#12 dosyasından okundu/.test(n.textContent) ? n.textContent : false;
      }, { message: 'Turkish note' });
      assert(note.includes('Özel anahtar bu sertifikayla eşleşiyor'), 'Turkish verdict');
      assert(note.includes('2.048 yineleme'), 'Turkish number grouping');
      assertEqual(note.match(/\bpfx\.[\w.-]+|\{[a-zA-Z]+\}/g) || [], [], 'raw keys or placeholders');
      await assertNoHorizontalScroll(page, 'desktop dark TR');
      await shotEl(page, opts, 'pfx-cert-desktop-dark-tr', '.cert-content');
    });

    await run.step('phone 375×812: the dialog and the note fit (TR dark, EN light)', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone viewport' });
      await assertNoHorizontalScroll(page, 'phone dark TR');
      assertEqual(await overflowingIn(page, '.pfx-note'), [], 'note inside 375 px (TR dark)');
      await shotEl(page, opts, 'pfx-cert-phone-dark-tr', '.pfx-note');
      await choose(page, CERT, 'p12_ec_aes128.p12');
      assertEqual(await overflowingIn(page, 'dialog.pfx-dialog'), [], 'dialog inside 375 px (TR)');
      await shotViewport(page, opts, 'pfx-dialog-phone-dark-tr');
      await page.click('[data-action="pfx-cancel"]');
      await page.waitFor(() => !document.querySelector('.pfx-dialog'), { message: 'dialog closed' });
      await removeToasts(page);
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => /Read from a PKCS#12 file/.test(document.querySelector('.pfx-note')?.textContent || ''), { message: 'English note' });
      await assertNoHorizontalScroll(page, 'phone light EN');
      assertEqual(await overflowingIn(page, '.pfx-note'), [], 'note inside 375 px (EN light)');
      await shotEl(page, opts, 'pfx-cert-phone-light-en', '.pfx-note');
      await page.setViewport({ width: 1440, height: 900 });
      await page.waitFor(() => document.documentElement.clientWidth === 1440, { message: 'desktop viewport' });
    });

    run.group('SSL Targets step 1');
    await run.step('a key that belongs to the intermediate: "does not match", the owner named, step 2 filled, no scan', async () => {
      await gotoRoute(page, 'scan');
      await choose(page, STEP, 'p12_mismatch.p12');
      await unlock(page, STEP, PASS, { checkKey: true });
      const info = await page.evaluate((s) => ({
        cn: document.querySelector(`${s} .cert-summary-cn`)?.textContent,
        file: document.querySelector(`${s} .cert-summary-file`)?.textContent,
        domains: document.querySelector('[data-role="scan-domains"]')?.value,
        running: !!document.querySelector('.scan-run')
      }), STEP);
      assertEqual(info.cn, 'p12.example.com', 'the leaf');
      assert(/p12_mismatch\.p12 · 2 certificates/.test(info.file), `file: ${info.file}`);
      assertEqual(info.domains, 'example.com', 'step 2 gets the leaf\'s domain');
      assert(!info.running, 'no scan started');
      const note = await noteInfo(page, STEP);
      assertEqual(note.keyCheck, 'mismatch', 'mismatch');
      assert(note.text.includes('The private key does not match this certificate'), 'verdict');
      assert(note.text.includes('The key belongs to Example P12 Test Intermediate.'), 'owner');
      assertEqual(await focusedRole(page), 'pfx-note', 'focus on the note');
      await takeDownloads(page);
      await page.click(`${STEP} [data-action="pfx-fullchain"]`);
      const [file] = await takeDownloads(page);
      const bodies = (file.text.match(/-----BEGIN CERTIFICATE-----\n([\s\S]*?)-----END CERTIFICATE-----/g) || []).map((b) => b.replace(/-----[^-]+-----|\s/g, ''));
      assertEqual(bodies, [LEAF, INTER], 'fullchain from step 1');
      await shotEl(page, opts, 'pfx-scan-desktop-light-en', STEP);
    });

    await run.step('the empty password opens a passwordless bundle (key matches)', async () => {
      await choose(page, STEP, 'p12_empty_password.p12');
      await unlock(page, STEP, '', { checkKey: true });
      const note = await noteInfo(page, STEP);
      assertEqual(note.keyCheck, 'match', 'match');
      assert(note.text.includes('The file holds 1 certificate and 1 private key.'), note.text);
    });

    await run.step('a SHA-224 MAC is not supported: the dialog closes, the focus lands on the warning', async () => {
      await choose(page, STEP, crafted('sha224-mac.p12'));
      await page.press('Enter');
      const info = await page.waitFor((s) => {
        const w = document.querySelector(`${s} [data-warning="PKCS12_UNSUPPORTED"]`);
        return !document.querySelector('.pfx-dialog') && w ? { text: w.textContent, focused: document.activeElement === w } : false;
      }, { args: [STEP], message: 'unsupported warning in step 1' });
      assert(info.text.includes('It uses SHA-224, which this page does not support.'), info.text);
      assert(info.focused, `focus on the warning, not ${await focusedRole(page)}`);
      await removeToasts(page);
    });

    await run.step('phone 375: step 1 with the mismatch note fits (TR dark)', async () => {
      await choose(page, STEP, 'p12_mismatch.p12');
      await unlock(page, STEP, PASS, { checkKey: true });
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375
        && /eşleşmiyor/.test(document.querySelector('.scan-step-cert .pfx-note')?.textContent || ''), { message: 'Turkish phone step 1' });
      await assertNoHorizontalScroll(page, 'SSL Targets phone dark TR');
      assertEqual(await overflowingIn(page, STEP), [], 'step 1 inside 375 px');
      await shotEl(page, opts, 'pfx-scan-phone-dark-tr', STEP);
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'pfx', origin);
      assertEqual(netHits, [], 'https requests that reached the network');
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish();
}

main().catch((err) => {
  process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
