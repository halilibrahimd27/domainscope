#!/usr/bin/env node
/**
 * chainfix.e2e.mjs — end-to-end test of the missing-intermediate repair and the root-store
 * warnings (ui/chain-repair.js over lib/chainfix.js) in the Certificate view and SSL Targets
 * step 1, in a real headless Chrome/Edge. OFFLINE: the page's requests for the bundled CCADB list
 * (assets/data/intermediates/) are answered from the test dataset (tests/fixtures/intermediates/,
 * gen_chainfix_fixtures.mjs), and a network-level guard (CDP Fetch) fails and records any https
 * request — the suite asserts none.
 *
 *   node tests/e2e/chainfix.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - Certificate view: a server certificate alone (chainfix_leaf.pem) gets "Missing intermediate
 *     found" with the added intermediate (issuer, CA owner, expiry) and where it comes from; only
 *     the manifest, the roots table and the shards its key ids point at are read; Download
 *     fullchain.pem gives the leaf and the intermediate issued by the current root — not its
 *     cross-signed copy under the removed old root; the Chain tab lists the added intermediate
 *     under the file's chain, says where the chain ends and which stores trust it, and its own
 *     download adds the intermediate too;
 *   - a chain under a distrusted root: the root-store warnings (Chrome distrusts it after the
 *     cut-off, Mozilla only the renewal, the root expires first) with the announcement link, and
 *     "Source" for Mozilla's date from the CCADB report;
 *   - an issuer the list does not hold: said plainly, no download; a complete chain: no note;
 *   - the list cannot be loaded (the shard request fails): the note says so, Retry reads it (the
 *     Deep CA it adds is one only the certificate records list, as Let's Encrypt's YE issuers);
 *   - a PKCS#12 bundle holding only the server certificate: the bundle's Download fullchain.pem
 *     and the note's both add the intermediate;
 *   - the PEM tab opened while the lookup is still running (the shard request held back): its
 *     fullchain.pem appears once the lookup ends;
 *   - SSL Targets step 1: the same note and download for a lone server certificate, no root-store
 *     warnings there, no scan started;
 *   - Turkish + dark, a 375 px and a 320 px phone (the notes fit without horizontal scroll);
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { orderSuites } from './run-all.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { seq, ctx, oid, octet, int } from '../fixtures/der-builder.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, gotoRoute, installDownloadCapture, setLangUi, takeDownloads, waitReady
} from './scan.e2e.mjs';

const fixture = (name) => path.join(FIXTURES, name);
const DATASET = path.join(FIXTURES, 'intermediates');
/** The instant the expectations were written for (the test PKIs expire from 2035 to 2045, the dataset is of Sep 28, 2026): the page's clock starts here. */
const CHAINFIX_NOW = Date.parse('2026-09-28T12:00:00Z');
/** The DER of a PEM fixture's certificate, as base64 (to find it in a download). */
const derB64 = async (file) => Buffer.from(parseCertificates(await readFile(fixture(file))).certificates[0].der).toString('base64');
const pemBodies = (text) => (text.match(/-----BEGIN CERTIFICATE-----\n([\s\S]*?)-----END CERTIFICATE-----/g) || []).map((b) => b.replace(/-----[^-]+-----|\s/g, ''));

/**
 * Answer the page's requests for the bundled list from the test dataset, and fail (and record)
 * every https request. `served` lists the dataset files read; `offline.shards` fails the shard
 * requests as a lost connection would; `offline.hold` keeps them waiting until
 * `offline.release()` (a slow connection: the lookup is still running meanwhile).
 */
async function interceptDataset(page) {
  const served = [];
  const hits = [];
  const held = [];
  const offline = {
    shards: false,
    hold: false,
    release() {
      offline.hold = false;
      for (const answer of held.splice(0)) answer();
    }
  };
  const fulfill = async (p, rel) => {
    served.push(rel);
    let body = null;
    try {
      body = await readFile(path.join(DATASET, ...rel.split('/')));
    } catch {
      // The test dataset leaves out the shards that hold nothing; the site has every one.
      body = /^(?:ski|dn)\/[0-9a-f]+\.json$/.test(rel) ? Buffer.from('{}') : null;
    }
    const answer = body
      ? { requestId: p.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: body.toString('base64') }
      : { requestId: p.requestId, responseCode: 404, responseHeaders: [{ name: 'Content-Type', value: 'text/plain' }], body: Buffer.from('not found').toString('base64') };
    page.send('Fetch.fulfillRequest', answer).catch(() => {});
  };
  page.conn.on('Fetch.requestPaused', async (p) => {
    const url = p.request.url;
    const m = /\/assets\/data\/intermediates\/(.+)$/.exec(url.split('?')[0]);
    if (!m) {
      hits.push(url);
      page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
      return;
    }
    const rel = m[1];
    const shard = /^(?:ski|dn)\//.test(rel);
    if (offline.shards && shard) {
      page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'InternetDisconnected' }).catch(() => {});
      return;
    }
    if (offline.hold && shard) {
      held.push(() => fulfill(p, rel));
      return;
    }
    await fulfill(p, rel);
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }, { urlPattern: '*/assets/data/intermediates/*' }] });
  return { served, hits, offline, held };
}

/**
 * A PKCS#12 file holding one certificate and nothing else — no key, no MAC, nothing encrypted
 * (what `openssl pkcs12 -export -nokeys` of a lone cert.pem gives, less the MAC).
 * @param {Uint8Array} der
 * @returns {Buffer}
 */
function certOnlyPfx(der) {
  const DATA = '1.2.840.113549.1.7.1';
  const certBag = seq(oid('1.2.840.113549.1.12.10.1.3'), ctx(0, true, seq(oid('1.2.840.113549.1.9.22.1'), ctx(0, true, octet(Buffer.from(der))))));
  const safe = seq(oid(DATA), ctx(0, true, octet(seq(certBag))));
  return seq(int('03'), seq(oid(DATA), ctx(0, true, octet(seq(safe)))));
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

/** Elements under `selector` sticking out of the viewport. */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));

/**
 * Load a file into the loader under `root` and wait until its chain lookup has ended (`until:
 * 'running'`: until it has started). `pfx`: a PKCS#12 file — its password dialog is answered with
 * Enter (no password).
 */
async function loadFile(page, root, file, { until = 'ended', pfx = false } = {}) {
  // The notes on screen are marked, so only the ones the new file brings count.
  await page.evaluate((r) => {
    document.querySelectorAll(`${r} .chainfix`).forEach((el) => { el.dataset.e2eOld = '1'; });
    const more = document.querySelector(`${r} details.cert-reload, ${r} details.scan-cert-another`);
    if (more) more.open = true;
  }, root);
  const name = path.basename(file);
  await page.setFileInput(`${root} .filedrop-input`, [path.isAbsolute(file) ? file : fixture(file)]);
  if (pfx) {
    await page.waitFor(() => document.activeElement && document.activeElement.dataset.role === 'pfx-password', { message: `password dialog for ${name}` });
    await page.press('Enter');
  }
  const states = until === 'running' ? ['running'] : ['done', 'error', 'none'];
  await page.waitFor((r, s) => {
    const box = document.querySelector(`${r} .chainfix:not([data-e2e-old])`);
    return !!box && s.includes(box.dataset.chainfix);
  }, { args: [root, states], message: `chain lookup of ${name} (${until})`, timeout: 15000 });
  await removeToasts(page);
}

/** What the notes under `root` say. */
const notes = (page, root) => page.evaluate((r) => {
  const box = document.querySelector(`${r} .chainfix`);
  const note = box && box.querySelector('[data-chainfix-note]');
  const life = box && box.querySelector('[data-lifecycle]');
  return {
    state: box ? box.dataset.chainfix : null,
    kind: note ? note.dataset.chainfixNote : null,
    title: note ? note.querySelector('.alert-title')?.textContent || null : null,
    text: note ? note.textContent : '',
    added: note ? [...note.querySelectorAll('.chainfix-added li')].map((li) => li.textContent) : [],
    download: !!(box && box.querySelector('[data-action="chainfix-fullchain"]')),
    life: life ? {
      level: life.dataset.lifecycle,
      title: life.querySelector('.alert-title')?.textContent,
      codes: [...life.querySelectorAll('[data-life-code]')].map((li) => li.dataset.lifeCode),
      text: life.textContent,
      links: [...life.querySelectorAll('.chainfix-life a')].map((a) => `${a.textContent.replace('(opens in a new tab)', '').trim()} ${a.href}`)
    } : null
  };
}, root);

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const LEAF = await derB64('chainfix_leaf.pem');
  const INTER = await derB64('chainfix_inter.pem');
  const INTER_CROSS = await derB64('chainfix_inter_cross.pem');
  const NOAKI = await derB64('chainfix_leaf_noaki.pem');
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-chainfix-e2e-'));
  const complete = path.join(tmp, 'complete-chain.pem');
  await writeFile(complete, `${await readFile(fixture('chainfix_inter.pem'), 'utf8')}${await readFile(fixture('chainfix_leaf.pem'), 'utf8')}`);
  // The server certificate and its issuing CA, whose issuer (the Policy CA) is another intermediate;
  // and the server certificate with the intermediate a root issued, in order.
  const deepPartial = path.join(tmp, 'deep-partial.pem');
  await writeFile(deepPartial, `${await readFile(fixture('chainfix_leaf_deep.pem'), 'utf8')}${await readFile(fixture('chainfix_deep_ca.pem'), 'utf8')}`);
  const inOrder = path.join(tmp, 'leaf-inter.pem');
  await writeFile(inOrder, `${await readFile(fixture('chainfix_leaf.pem'), 'utf8')}${await readFile(fixture('chainfix_inter.pem'), 'utf8')}`);
  const leafOnlyPfx = path.join(tmp, 'leaf-only.p12');
  await writeFile(leafOnlyPfx, certOnlyPfx(Buffer.from(LEAF, 'base64')));

  run.group('Node: harness');
  await run.step('run-all orders the chainfix suite right after pfx', () => {
    assertEqual(orderSuites(['global.e2e.mjs', 'chainfix.e2e.mjs', 'pfx.e2e.mjs', 'cert.e2e.mjs']), ['cert', 'pfx', 'chainfix', 'global'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: the test dataset of intermediates\n`);
  let page = null;
  let net = null;
  const CERT = '.cert-view';
  const STEP = '.scan-step-cert';
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(CHAINFIX_NOW) });
    net = await interceptDataset(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/cert`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'cert');

    run.group('Certificate view (desktop 1440×900, English, light)');
    await run.step('a server certificate alone: "Missing intermediate found", what was added and from where', async () => {
      await loadFile(page, CERT, 'chainfix_leaf.pem');
      const n = await notes(page, CERT);
      assertEqual(n.state, 'done', 'lookup ended');
      assertEqual(n.kind, 'repaired', 'repaired');
      assertEqual(n.title, 'Missing intermediate found', 'title');
      assert(n.text.includes('The file holds only the server certificate.'), n.text);
      assertEqual(n.added.length, 1, 'one added');
      assert(n.added[0].startsWith('Added: DomainScope Test Issuing CA'), n.added[0]);
      assert(n.added[0].includes('issued by DomainScope Test Root CA · CA owner: DomainScope Test · valid until Jun 1, 2035'), n.added[0]);
      assert(n.text.includes('From this site’s copy of the CCADB list (Sep 28, 2026). Your certificate was not sent anywhere.'), 'source line');
      assert(n.download, 'Download fullchain.pem');
      assert(!n.life, 'no root-store warning for a current root');
      await shotEl(page, opts, 'chainfix-cert-desktop-light-en', '.cert-content');
    });

    await run.step('only the manifest, the roots table and the shards the key ids point at were read', () => {
      assertEqual(net.served.slice(0, 2), ['manifest.json', 'roots.json'], 'first');
      const shards = net.served.filter((f) => /^(?:ski|dn)\//.test(f));
      assert(shards.length >= 1 && shards.length <= 2 && shards.every((f) => f.startsWith('ski/')), `shards: ${shards.join(', ')}`);
    });

    await run.step('Download fullchain.pem: the leaf, then the intermediate of the current root — not the cross-signed copy', async () => {
      await takeDownloads(page);
      await page.click(`${CERT} [data-action="chainfix-fullchain"]`);
      const [file] = await takeDownloads(page);
      assertEqual(file && file.name, 'www.example.com-fullchain.pem', 'file name');
      assertEqual(pemBodies(file.text), [LEAF, INTER], 'leaf then intermediate');
      assert(!file.text.includes(INTER_CROSS) && !/PRIVATE KEY/.test(file.text), 'no cross-signed copy, no key');
    });

    await run.step('Chain tab: the added intermediate under the file\'s chain, where it ends, and the tab\'s download adds it', async () => {
      await page.click('.cert-tabs .tab[data-tab="chain"]');
      const info = await page.waitFor(() => {
        const part = document.querySelector('.cert-tabs .chainfix-chain');
        return part && part.dataset.chainfix === 'done' ? {
          file: [...document.querySelectorAll('.cert-tabs .cert-chain:not(.chainfix-chain-list) > .cert-chain-item')].map((li) => li.dataset.role || 'missing'),
          added: [...part.querySelectorAll('[data-role="added"] .cert-chain-cn')].map((el) => el.textContent),
          trust: part.querySelector('.chainfix-trust')?.textContent
        } : false;
      }, { message: 'chain tab part' });
      assertEqual(info.file, ['leaf', 'missing'], 'the file: the leaf and the missing issuer');
      assertEqual(info.added, ['DomainScope Test Issuing CA'], 'added');
      assertEqual(info.trust, 'The chain ends at DomainScope Test Root CA (DomainScope Test). Trusted for websites by Chrome, Mozilla (Firefox), Apple, and Microsoft.', 'trust line');
      await takeDownloads(page);
      await page.click('[data-action="download-chain-tab"]');
      const [file] = await takeDownloads(page);
      assertEqual(pemBodies(file.text), [LEAF, INTER], 'the tab\'s fullchain has the intermediate too');
      await shotEl(page, opts, 'chainfix-chain-tab-desktop-light-en', '.cert-tabs-host');
    });

    await run.step('under a distrusted root: the root-store warnings with dates and the announcement', async () => {
      await loadFile(page, CERT, 'chainfix_leaf_lifecycle.pem');
      const n = await notes(page, CERT);
      assertEqual(n.kind, 'repaired', 'the intermediate is added');
      assert(n.added[0].includes('DomainScope Test Distrusted CA') && n.added[0].includes('CA owner: DomainScope Distrust Test'), n.added[0]);
      assertEqual(n.life && n.life.level, 'error', 'an error: Chrome distrusts it');
      assertEqual(n.life.title, 'Root store warnings', 'title');
      assertEqual(n.life.codes, ['distrusted', 'renewal-distrusted', 'root-expires'], 'warnings, worst first');
      assert(n.life.text.includes('Chrome does not trust certificates from DomainScope Test Distrusted Root issued after Jan 31, 2026. This one was issued on Mar 1, 2026.'), n.life.text);
      assert(n.life.text.includes('its renewal has to chain to another root'), 'Mozilla: the renewal');
      assert(n.life.text.includes('expires on Mar 1, 2040, before this certificate does (Jun 1, 2040)'), 'expiry');
      assertEqual(n.life.links, ['Announcement https://example.com/announcements/chrome-distrust', 'Source https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport'],
        'Chrome: the announcement; Mozilla: the CCADB report its date comes from');
      await shotEl(page, opts, 'chainfix-lifecycle-desktop-light-en', '.cert-content');
    });

    await run.step('an issuer the list does not hold: said plainly, nothing to download', async () => {
      await loadFile(page, CERT, 'chainfix_leaf_unknown.pem');
      const n = await notes(page, CERT);
      assertEqual(n.kind, 'not-found', 'not found');
      assert(n.text.includes('(CN=DomainScope Test Unlisted CA,O=DomainScope Unlisted Test,C=XX) is not in the CCADB list of public intermediates (Sep 28, 2026)'), n.text);
      assert(!n.download, 'no download');
    });

    await run.step('a complete chain (in any order): no note, and the overview\'s full chain as the file has it', async () => {
      await loadFile(page, CERT, complete);
      const n = await notes(page, CERT);
      assertEqual([n.state, n.kind, n.life], ['done', null, null], 'nothing to say');
      await takeDownloads(page);
      await page.click(`${CERT} [data-action="download-chain"]`);
      const [file] = await takeDownloads(page);
      assertEqual(pemBodies(file.text), [LEAF, INTER], 'leaf first');
    });

    await run.step('the list cannot be loaded: the note says so, and Retry reads it', async () => {
      await assertClean(page, 'before the lost connection', origin);
      net.offline.shards = true;
      await loadFile(page, CERT, 'chainfix_leaf_deep.pem');
      let n = await notes(page, CERT);
      assertEqual([n.state, n.kind], ['error', 'failed'], 'failed');
      assert(n.text.includes('could not be loaded (you may be offline)'), n.text);
      net.offline.shards = false;
      await page.click(`${CERT} [data-action="chainfix-retry"]`);
      await page.waitFor(() => document.querySelector('.cert-view .chainfix [data-chainfix-note="repaired"]'), { message: 'repaired after Retry' });
      const focused = await page.evaluate(() => {
        const a = document.activeElement;
        return a ? `${a.tagName.toLowerCase()}.${[...a.classList].join('.')}` : 'none';
      });
      assert(/\.chainfix\b/.test(focused), `the keyboard focus moved to the notes, not ${focused}`);
      n = await notes(page, CERT);
      assertEqual(n.added.map((a) => a.split(' — ')[0].replace(/issued by.*$/, '').trim()), ['Added: DomainScope Test Deep CA', 'Added: DomainScope Test Policy CA'], 'two added');
      assertEqual(n.title, '2 missing intermediates found', 'title');
      // The failed requests are the only problems of the step.
      const p = await page.problems();
      const other = p.logErrors.filter((e) => !String(e.url || e.text).includes('/assets/data/intermediates/'));
      assertEqual([other.length, p.exceptions.length, p.consoleErrors.length], [0, 0, 0], 'no other problem');
      await page.resetProblems();
    });

    await run.step('Chain tab: a file that stops at an intermediate issued by another intermediate is not "complete"; leaf + intermediate of a root is', async () => {
      const issues = async (file) => {
        await loadFile(page, CERT, file);
        await page.click('.cert-tabs .tab[data-tab="chain"]');
        return page.waitFor(() => {
          const part = document.querySelector('.cert-tabs .chainfix-chain');
          return part && part.dataset.chainfix === 'done'
            ? [...document.querySelectorAll('.cert-tabs [data-chain-issue]')].map((a) => ({ code: a.dataset.chainIssue, text: a.textContent })) : false;
        }, { message: `Chain tab of ${path.basename(file)}` });
      };
      const partial = await issues(deepPartial);
      assertEqual(partial.map((i) => i.code), ['missing-intermediate'], 'a warning, and no "The chain is complete"');
      assert(partial[0].text.includes('The file stops at DomainScope Test Deep CA. Its issuer is an intermediate, not a root, so servers must send it too'), partial[0].text);
      assertEqual((await issues(inOrder)).map((i) => i.code), ['ends-at', 'ok'], 'the issuing CA\'s issuer is a root: complete');
      await page.click('.cert-tabs .tab[data-tab="names"]');
    });

    await run.step('a PKCS#12 bundle with the server certificate only: both Download fullchain.pem buttons add the intermediate', async () => {
      await loadFile(page, CERT, leafOnlyPfx, { pfx: true });
      const n = await notes(page, CERT);
      assertEqual(n.kind, 'repaired', 'repaired');
      assert(await page.evaluate(() => !!document.querySelector('.cert-view .pfx-note [data-action="pfx-fullchain"]')), 'the bundle\'s note and its download');
      for (const action of ['pfx-fullchain', 'chainfix-fullchain']) {
        await takeDownloads(page);
        await page.click(`${CERT} [data-action="${action}"]`);
        const [file] = await takeDownloads(page);
        assertEqual(file && file.name, 'www.example.com-fullchain.pem', `${action}: file name`);
        assertEqual(pemBodies(file.text), [LEAF, INTER], `${action}: leaf then intermediate`);
      }
    });

    await run.step('the PEM tab opened while the lookup runs: fullchain.pem appears when it ends', async () => {
      net.offline.hold = true;
      await loadFile(page, CERT, 'chainfix_leaf_noaki.pem', { until: 'running' });
      await page.click('.cert-tabs .tab[data-tab="pem"]');
      const before = await page.waitFor(() => {
        const part = document.querySelector('.cert-tabs .cert-pem-fullchain');
        return part ? { tag: part.tagName.toLowerCase(), hidden: part.hidden } : false;
      }, { message: 'PEM tab' });
      assertEqual(before, { tag: 'div', hidden: true }, 'a lone server certificate: no fullchain.pem yet');
      assert(net.held.length > 0, 'the shard request is waiting');
      net.offline.release();
      const after = await page.waitFor(() => {
        const part = document.querySelector('.cert-tabs details.cert-pem-fullchain');
        return part ? part.textContent : false;
      }, { message: 'fullchain.pem in the PEM tab' });
      assertEqual(pemBodies(after), [NOAKI, INTER], 'the leaf, then the intermediate the list added');
      assertEqual((await notes(page, CERT)).kind, 'repaired', 'the note too');
    });

    run.group('Languages, themes, phone (Certificate view)');
    await run.step('Turkish + dark: the notes are rebuilt in Turkish, no raw keys', async () => {
      await loadFile(page, CERT, 'chainfix_leaf_lifecycle.pem');
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      const text = await page.waitFor(() => {
        const box = document.querySelector('.cert-view .chainfix');
        return box && box.dataset.chainfix === 'done' && /Eksik ara sertifika bulundu/.test(box.textContent) ? box.textContent : false;
      }, { message: 'Turkish notes' });
      assert(text.includes('Kök deposu uyarıları'), 'Turkish lifecycle title');
      assert(text.includes('Chrome, DomainScope Test Distrusted Root kökünün 31 Oca 2026 tarihinden sonra verdiği sertifikalara güvenmiyor.'), text);
      assertEqual(text.match(/\bchainfix\.[\w.-]+|\{[a-zA-Z]+\}/g) || [], [], 'raw keys or placeholders');
      await assertNoHorizontalScroll(page, 'desktop dark TR');
      await shotEl(page, opts, 'chainfix-cert-desktop-dark-tr', '.cert-content');
    });

    await run.step('phones 375 and 320: the notes fit (TR dark, EN light)', async () => {
      for (const width of [375, 320]) {
        await page.setViewport({ width, height: 812, mobile: true });
        await page.waitFor((w) => document.documentElement.clientWidth === w, { args: [width], message: `${width} px` });
        await assertNoHorizontalScroll(page, `phone ${width} dark TR`);
        assertEqual(await overflowingIn(page, '.cert-view .chainfix'), [], `notes inside ${width} px (TR dark)`);
        await shotEl(page, opts, `chainfix-cert-phone${width}-dark-tr`, '.cert-view .chainfix');
      }
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => /Root store warnings/.test(document.querySelector('.cert-view .chainfix')?.textContent || ''), { message: 'English notes' });
      await assertNoHorizontalScroll(page, 'phone 320 light EN');
      assertEqual(await overflowingIn(page, '.cert-view .chainfix'), [], 'notes inside 320 px (EN light)');
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: '375 px' });
      await shotEl(page, opts, 'chainfix-cert-phone375-light-en', '.cert-view .chainfix');
      await page.setViewport({ width: 1440, height: 900 });
      await page.waitFor(() => document.documentElement.clientWidth === 1440, { message: 'desktop viewport' });
    });

    run.group('SSL Targets step 1');
    await run.step('a server certificate alone: the note and fullchain.pem, no root-store warnings, no scan', async () => {
      await gotoRoute(page, 'scan');
      await loadFile(page, STEP, 'chainfix_leaf.pem');
      const n = await notes(page, STEP);
      assertEqual(n.kind, 'repaired', 'repaired');
      assert(n.added[0].startsWith('Added: DomainScope Test Issuing CA'), n.added[0]);
      assert(!n.life, 'the root-store warnings stay in the Certificate view');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="scan-domains"]')?.value, !!document.querySelector('.scan-run')]),
        ['example.com', false], 'step 2 filled, no scan');
      await takeDownloads(page);
      await page.click(`${STEP} [data-action="chainfix-fullchain"]`);
      const [file] = await takeDownloads(page);
      assertEqual(pemBodies(file.text), [LEAF, INTER], 'fullchain from step 1');
      await shotEl(page, opts, 'chainfix-scan-desktop-light-en', STEP);
    });

    await run.step('phone 375: step 1 with the note fits (TR dark)', async () => {
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375
        && /Eksik ara sertifika bulundu/.test(document.querySelector('.scan-step-cert .chainfix')?.textContent || ''), { message: 'Turkish phone step 1' });
      await assertNoHorizontalScroll(page, 'SSL Targets phone dark TR');
      assertEqual(await overflowingIn(page, `${STEP} .chainfix`), [], 'the note inside 375 px');
      await shotEl(page, opts, 'chainfix-scan-phone375-dark-tr', STEP);
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'chainfix', origin);
      assertEqual(net.hits, [], 'https requests that reached the network');
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
