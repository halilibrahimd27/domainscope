#!/usr/bin/env node
/**
 * cert.e2e.mjs — end-to-end test of the "Certificate" view in a real headless Chrome/Edge.
 *
 *   node tests/e2e/cert.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--offline]
 *
 * Node side: the pure helpers of views/cert.js against the fixtures (chain analysis,
 * validity, crt.sh row filtering, Punycode, hand-over shapes).
 *
 * Browser side (fixtures from tests/fixtures, uploaded with DOM.setFileInputFiles or pasted):
 *   - chain.pem: overview, Copy summary (Markdown and plain text, a bare #/cert link), SAN table
 *     (IDN shown as Unicode), "does it cover …?" check,
 *     fingerprints and public-key SHA-256 (compared with Node's crypto), chain order,
 *     certificate picker, PEM tab, downloads (captured in the page)
 *   - chain_reversed.pem (wrong order), real_google_chain.pem (ends at a cross-signed root),
 *     with_key.pem (private key ignored and never displayed), test.pfx (the password dialog:
 *     Cancel loads nothing, "test" reads the leaf and its CA; tests/e2e/pfx.e2e.mjs has the rest),
 *     test.csr (CSR), a pasted PEM (ec_wildcard.pem)
 *   - "No file?" (offline: Cert Spotter and crt.sh are answered inside the page): Try a sample
 *     (same-origin file only), a host name refused before any request, nothing logged, a lookup
 *     still running when the sample loads (aborted at once: busy flag, language switch), a
 *     certificate loaded from CT (badge, caveat, leaf-only chain note, Check servers in SSL
 *     Targets; kept over a trip away with "Result from" and Run again, whose lookup leaves the
 *     note while it finds nothing and ends it with the new certificate), SSL Targets step 1 with
 *     the CT note and the sample (fills the domains, starts no
 *     scan), a Cert Spotter 429 → crt.sh download links, the cool-down that skips Cert Spotter
 *     after it, and crt.sh failing during the cool-down (the error says so, with the reset time)
 *   - LIVE (skipped with --offline): real_cloudflare.pem — CAA check over DoH and the
 *     Certificate Transparency lookup of its serial on crt.sh
 *   - "Find servers for this certificate" hands the certificate to SSL Targets; removing it
 *     there clears it here too (shared session)
 *   - language switch, dark mode, 390 px phone layout, screenshots, zero console errors /
 *     exceptions / CSP violations, no missing i18n keys.
 */

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, gotoRoute, installDownloadCapture, setLangUi, shot, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const fixture = (name) => path.join(FIXTURES, name);

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/cert.js');
  const load = async (name) => V.loadCertificateData(await readFile(fixture(name)), { name });
  run.group('Node: views/cert.js helpers');

  await run.step('analyzeChain: complete chain in order (root included)', async () => {
    const { result } = await load('chain.pem');
    const a = V.analyzeChain(result.certificates, result.leaf);
    assertEqual(a.ordered.map((c) => c.subjectCN), ['www.example-test.com.tr', 'Subdomain Scanner Test Root CA'], 'order');
    assert(a.complete && a.inOrder && !a.unrelated.length, 'complete, in order');
    assertEqual(a.issues.map((i) => i.code), ['root-included'], 'issues');
    assertEqual([...a.roles.values()], ['leaf', 'root'], 'roles');
    assertEqual(V.fullchainCerts(a).map((c) => c.subjectCN), ['www.example-test.com.tr'], 'fullchain drops the root');
  });
  await run.step('analyzeChain: reversed file, leaf only, lone CA, cross-signed root', async () => {
    const rev = (await load('chain_reversed.pem')).result;
    const a = V.analyzeChain(rev.certificates, rev.leaf);
    assert(!a.inOrder && a.issues.some((i) => i.code === 'order'), 'order issue');
    assertEqual(a.ordered[0].subjectCN, 'www.example-test.com.tr', 'leaf first after ordering');
    const single = (await load('rsa_multi_san.pem')).result;
    assertEqual(V.analyzeChain(single.certificates, single.leaf).issues.map((i) => i.code), ['leaf-only'], 'leaf only');
    const ca = (await load('ca.pem')).result;
    assertEqual(V.analyzeChain(ca.certificates, ca.leaf).issues, [], 'a lone root CA has no issue');
    const g = (await load('real_google_chain.pem')).result;
    const ga = V.analyzeChain(g.certificates, g.leaf);
    assertEqual(ga.ordered.length, 3, 'three in chain');
    assert(!ga.complete && ga.issues.some((i) => i.code === 'ends-at'), 'ends at a cross-signed root');
    assertEqual(V.fullchainCerts(ga).length, 3, 'a non-self-signed last certificate stays in the fullchain');
    assertEqual(V.pemBundle(V.fullchainCerts(ga)).match(/BEGIN CERTIFICATE/g).length, 3, 'bundle');
  });
  await run.step('validityState / validityText / validityVariant', async () => {
    const cert = { notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2026-12-31T00:00:00Z') };
    const at = (iso) => V.validityState(cert, new Date(iso));
    assertEqual(at('2025-12-30T00:00:00Z').state, 'notyet', 'not yet');
    assertEqual(at('2026-06-01T00:00:00Z').state, 'ok', 'ok');
    assertEqual(at('2026-12-10T00:00:00Z'), { state: 'expiring', days: 21, elapsed: at('2026-12-10T00:00:00Z').elapsed, lifetimeDays: 364 }, 'expiring');
    assertEqual(at('2027-01-03T00:00:00Z').state, 'expired', 'expired');
    assertEqual(V.validityVariant(at('2027-01-03T00:00:00Z')), 'error', 'expired → error');
    assertEqual(V.validityText({ state: 'ok', days: 1 }), '1 day left', 'text');
    assertEqual(V.validityText({ state: 'expired', days: 0 }), 'Expired today', 'expired today');
  });
  await run.step('crtshSerialRows keeps the issuer\'s rows and de-duplicates by id', () => {
    const rows = [
      { id: 1, issuer_name: 'C=US, O=Google Trust Services, CN=WE1', not_before: '2026-09-05T22:29:39', not_after: '2026-12-04T23:29:33' },
      { id: 1, issuer_name: 'C=US, O=Google Trust Services, CN=WE1', not_before: '2026-09-05T22:29:39', not_after: '2026-12-04T23:29:33' },
      { id: 2, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', not_before: '2026-01-01T00:00:00', not_after: '2026-04-01T00:00:00' },
      null
    ];
    const r = V.crtshSerialRows(rows, { issuer: { CN: 'WE1' } });
    assertEqual(r.rows.map((x) => x.id), [1], 'rows');
    assertEqual(r.ignored, 1, 'ignored other issuer');
    assertEqual(r.rows[0].notBefore.toISOString(), '2026-09-05T22:29:39.000Z', 'UTC dates');
    assertEqual(V.crtshSerialRows('not json', {}).rows, [], 'garbage');
  });
  await run.step('punycode, serial formatting, hand-over shapes', async () => {
    assertEqual(V.hostToUnicode('xn--mnchen-3ya.example-test.com.tr'), 'münchen.example-test.com.tr', 'IDN');
    assertEqual(V.hostToUnicode('xn--zz-!!.example.com'), 'xn--zz-!!.example.com', 'invalid label kept');
    assertEqual(V.formatSerial('f1e2d3'), 'F1:E2:D3', 'serial');
    assertEqual(V.formatSerial('abc'), '0A:BC', 'odd length');
    const l = await load('rsa_multi_san.pem');
    assertEqual(V.normalizeCertLoad(l), l, 'CertLoad passes through');
    assertEqual(V.normalizeCertLoad(l.result.leaf).result.leaf, l.result.leaf, 'bare Certificate');
    assertEqual(V.normalizeCertLoad({ cert: l.result.leaf, name: 'x.pem' }).name, 'x.pem', '{ cert }');
    assertEqual(V.normalizeCertLoad(l.result).result.leaf, l.result.leaf, 'parse result');
    assertEqual(V.normalizeCertLoad({ foo: 1 }), null, 'garbage');
  });
}

const tabSel = (id) => `.cert-tabs [data-tab="${id}"]`;

async function uploadFile(page, file) {
  const hasReload = await page.evaluate(() => !!document.querySelector('.cert-reload'));
  if (hasReload) await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
  await page.setFileInput(hasReload ? '.cert-reload .filedrop-input' : '.cert-loader-card .filedrop-input', [fixture(file)]);
}

async function uploadAndWait(page, file) {
  const prev = await page.evaluate(() => document.querySelector('.cert-overview-cn')?.textContent || '');
  await uploadFile(page, file);
  await page.waitFor((p) => {
    const cn = document.querySelector('.cert-overview-cn')?.textContent || '';
    return cn && (cn !== p || document.querySelector('.toast'));
  }, { args: [prev], message: `overview for ${file}` });
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
}

/**
 * Hold requests matching `patterns` for `ms` before they go out (CDP Fetch), so a lookup is
 * surely still in flight when the test acts. Returns a function that stops holding them.
 */
async function delayRequests(page, patterns, ms) {
  const off = page.conn.on('Fetch.requestPaused', (p) => {
    setTimeout(() => page.send('Fetch.continueRequest', { requestId: p.requestId }).catch(() => {}), ms);
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: patterns.map((urlPattern) => ({ urlPattern, requestStage: 'Request' })) });
  return async () => {
    off();
    await page.send('Fetch.disable');
  };
}

/**
 * Cert Spotter and crt.sh identity searches answered inside the page (installed before the app
 * loads), so the "No file?" steps are offline. `window.__ctFake.mode`: 'found' (one issuance
 * with the DER, then the empty page that ends the list), 'none' (nothing current), '429' (Cert
 * Spotter rate limited; crt.sh lists the certificate as precertificate + certificate rows),
 * 'down' (Cert Spotter rate limited, crt.sh answering 404), 'wild-down' (Cert Spotter rate
 * limited, crt.sh answering the name's own search with nothing and its `*.parent` search with a
 * 404), 'hold' (no answer until the request is aborted; `aborted` counts those). Every intercepted request is recorded with its
 * credentials mode; any other fetch goes out.
 */
const ctFakeScript = (row, crtshRows) => `(() => {
  const ROW = ${JSON.stringify(row)};
  const CRTSH = ${JSON.stringify(crtshRows)};
  window.__ctFake = { mode: 'found', calls: [], aborted: 0 };
  const realFetch = window.fetch.bind(window);
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const hold = (init) => new Promise((resolve, reject) => {
    const signal = init && init.signal;
    if (!signal) return;
    signal.addEventListener('abort', () => {
      window.__ctFake.aborted += 1;
      reject(new DOMException('The operation was aborted.', 'AbortError'));
    }, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const mode = window.__ctFake.mode;
    if (url.startsWith('https://api.certspotter.com/v1/issuances')) {
      window.__ctFake.calls.push({ url, credentials: init && init.credentials });
      if (mode === 'hold') return hold(init);
      if (mode === '429' || mode === 'down' || mode === 'wild-down') return json({ code: 'rate_limited', message: 'Rate limit exceeded' }, 429);
      return json(mode === 'none' || /[?&]after=/.test(url) ? [] : [ROW]);
    }
    if (url.startsWith('https://crt.sh/?q=')) {
      window.__ctFake.calls.push({ url, credentials: init && init.credentials });
      if (mode === 'hold') return hold(init);
      const notFound = () => new Response('<html>Not found</html>', { status: 404, headers: { 'content-type': 'text/html' } });
      if (mode === 'down') return notFound();
      if (mode === 'wild-down') return new URL(url).searchParams.get('q').startsWith('*.') ? notFound() : json([]);
      return json(mode === '429' ? CRTSH : []);
    }
    return realFetch(input, init);
  };
})();`;

/** The Cert Spotter row of a fixture certificate, as the API returns it with expand=dns_names,cert_der. */
function certspotterRow(cert, id) {
  const iso = (d) => d.toISOString().replace('.000Z', 'Z');
  return {
    id, tbs_sha256: '00'.repeat(32), cert_sha256: createHash('sha256').update(cert.der).digest('hex'), dns_names: cert.hostnames,
    pubkey_sha256: '00'.repeat(32), not_before: iso(cert.notBefore), not_after: iso(cert.notAfter), revoked: false,
    cert_der: Buffer.from(cert.der).toString('base64')
  };
}

/** Wait until the "No file?" block inside `scope` shows the outcome `status` ([data-ct-result]); returns it. */
const ctResult = (page, scope, status) => page.waitFor((sel, want) => document.querySelector(`${sel} [data-ct-result]`)?.dataset.ctResult === want && want,
  { args: [scope, status], message: `CT lookup outcome ${status} in ${scope}` });

async function main() {
  const opts = cliOptions();
  const OFFLINE = opts.has('--offline');
  const run = createRunner();
  await nodeChecks(run);

  const expected = JSON.parse(await readFile(fixture('expected.json'), 'utf8'))['rsa_multi_san.pem'];
  const x509 = await import('../../assets/js/lib/x509.js');
  const leafNode = x509.parseCertificates(await readFile(fixture('rsa_multi_san.pem'))).leaf;
  const spkiHex = createHash('sha256').update(leafNode.spkiDer).digest('hex');
  const keyPem = await readFile(fixture('with_key.pem'), 'utf8');
  const keyChunk = keyPem.split('-----BEGIN PRIVATE KEY-----')[1].split('\n').filter(Boolean)[2];
  // "No file?": the leaf of the bundled sample (example.com, *.example.com, example.net, www.example.net;
  // issued by an intermediate, as a CT log holds it) is what Cert Spotter "logged" for www.example.net.
  const ctLeaf = x509.parseCertificates(await readFile(path.join(FIXTURES, '..', '..', 'assets', 'data', 'sample-cert.pem'))).leaf;
  const crtshRows = [20000000002, 20000000001].map((id) => ({
    id, issuer_ca_id: 7, issuer_name: 'C=XX, O=Example Trust, CN=Example CA R1', common_name: 'example.com',
    name_value: 'example.com\n*.example.com\nexample.net\nwww.example.net', not_before: '2026-07-01T00:00:00', not_after: '2036-07-01T00:00:00',
    serial_number: '0a1b2c3d4e5f'
  }));

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}${OFFLINE ? ' (offline: live checks skipped)' : ''}\n`);
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await installDownloadCapture(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: ctFakeScript(certspotterRow(ctLeaf, '17000000001'), crtshRows) });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('empty state with the drop zone and the privacy note', async () => {
      await page.goto(`${server.url}#/cert`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await page.waitForSelector('.cert-loader-card .filedrop');
      const info = await page.evaluate(() => ({
        empty: document.querySelector('.cert-content .empty-title')?.textContent,
        privacy: document.querySelector('.cert-privacy')?.textContent || '',
        accept: document.querySelector('.cert-loader-card .filedrop-input').getAttribute('accept')
      }));
      assertEqual(info.empty, 'No certificate loaded', 'empty state');
      assert(/never uploaded/.test(info.privacy), 'privacy note');
      assert(info.accept.includes('.pem') && info.accept.includes('.p7b') && info.accept.includes('.pfx'), `accept: ${info.accept}`);
      await assertNoHorizontalScroll(page, 'empty');
      await shot(page, opts, 'cert-desktop-light-en-empty');
    });

    run.group('No file? A host name\'s certificate from CT, or the sample (offline)');
    await run.step('the block sits in the loader card: host field, Load, Try a sample', async () => {
      const info = await page.evaluate(() => {
        const alt = document.querySelector('.cert-loader-card [data-role="cert-alt"]');
        const input = alt?.querySelector('[data-role="ct-host"]');
        return {
          label: alt?.querySelector('.field-label')?.textContent,
          labelled: !!input && alt.querySelector('.field-label').getAttribute('for') === input.id,
          described: (input?.getAttribute('aria-describedby') || '').split(' ').map((id) => document.getElementById(id)?.textContent || `#${id}?`),
          load: !!alt?.querySelector('[data-action="ct-load"]'),
          sample: alt?.querySelector('[data-action="cert-sample"]')?.textContent
        };
      });
      assertEqual(info.label, 'No file? Load the public certificate of a host name', 'label');
      assert(info.labelled && info.load, 'labelled field and Load button');
      assert(info.described.length === 1 && /^Reads the newest valid certificate/.test(info.described[0]), `hint tied to the field: ${info.described}`);
      assertEqual(info.sample, 'Try a sample', 'sample button');
    });

    await run.step('Try a sample: the bundled example.com / example.net certificate, from this site only', async () => {
      const external = () => performance.getEntriesByType('resource').filter((e) => !e.name.startsWith(location.origin)).length;
      const before = await page.evaluate(external);
      await page.click('[data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'example.com', { message: 'sample loaded' });
      const info = await page.evaluate(() => ({
        badge: document.querySelector('.cert-overview-badges [data-cert-source]')?.dataset.certSource,
        note: document.querySelector('.cert-content .cert-source-note')?.textContent || '',
        names: [...document.querySelectorAll('.cert-tabs .dt-table tbody tr.dt-row')].map((tr) => tr.querySelectorAll('td')[1].textContent.trim()),
        verify: !!document.querySelector('[data-action="ct-verify"]'),
        sample: performance.getEntriesByType('resource').filter((e) => /\/assets\/data\/sample-cert\.pem$/.test(e.name)).length,
        focused: document.activeElement === document.querySelector('.cert-content .cert-source-note')
      }));
      assertEqual(info.badge, 'sample', 'Sample badge');
      assert(info.focused, 'the keyboard focus moves to the new source note, not to <body>');
      assert(/made-up .DomainScope Sample. CA\. No server uses it/.test(info.note), `sample note: ${info.note}`);
      assert(['example.com', '*.example.com', 'example.net', 'www.example.net'].every((n) => info.names.some((c) => c.startsWith(n))), `names ${info.names}`);
      assert(!info.verify, 'no Verify link for the sample');
      assertEqual(info.sample, 1, 'fetched from assets/data');
      assertEqual(await page.evaluate(external), before, 'nothing sent to a third party');
      assertEqual(await page.evaluate(() => window.__ctFake.calls.length), 0, 'no CT request');
      await shot(page, opts, 'cert-desktop-light-en-sample');
    });

    await run.step('a value that is not a host name is refused before any request', async () => {
      await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
      await page.type('.cert-reload [data-role="ct-host"]', '192.0.2.10');
      await page.click('.cert-reload [data-action="ct-load"]');
      const err = await page.waitFor(() => document.querySelector('.cert-reload [data-role="cert-alt"] .field-error')?.textContent, { message: 'field error' });
      assert(/host name such as www\.example\.com/.test(err), `error: ${err}`);
      const described = await page.evaluate(() => (document.querySelector('.cert-reload [data-role="ct-host"]').getAttribute('aria-describedby') || '')
        .split(' ').map((id) => document.getElementById(id)?.className));
      assertEqual(described, ['muted text-sm cert-alt-hint', 'field-error'], 'hint and error both describe the field');
      assertEqual(await page.evaluate(() => window.__ctFake.calls.length), 0, 'no request');
    });

    await run.step('nothing current in the logs: an honest note, and crt.sh (the same logs) is not asked', async () => {
      await page.evaluate(() => { window.__ctFake.mode = 'none'; });
      await page.type('.cert-reload [data-role="ct-host"]', 'WWW.Example.NET');
      await page.press('Enter');
      assertEqual(await ctResult(page, '.cert-reload', 'not-found'), 'not-found', 'outcome');
      const info = await page.evaluate(() => ({
        text: document.querySelector('.cert-reload [data-ct-result]').textContent,
        calls: window.__ctFake.calls,
        cn: document.querySelector('.cert-overview-cn').textContent
      }));
      assert(/No currently valid certificate for www\.example\.net is logged/.test(info.text), `note: ${info.text}`);
      assertEqual(info.calls.length, 1, 'one Cert Spotter request');
      const u = new URL(info.calls[0].url);
      assertEqual(u.searchParams.get('domain'), 'www.example.net', 'normalized name');
      assertEqual(u.searchParams.get('match_wildcards'), 'true', 'wildcard certificates match');
      assertEqual(u.searchParams.getAll('expand'), ['dns_names', 'cert_der'], 'names and DER expanded');
      assertEqual(info.calls[0].credentials, 'omit', 'no credentials');
      assertEqual(info.cn, 'example.com', 'the loaded certificate stays');
    });

    await run.step('a lookup still running when the sample loads is stopped at once: requests, busy flag, language switch', async () => {
      await page.evaluate(() => { window.__ctFake.mode = 'hold'; window.__ctFake.calls = []; window.__ctFake.aborted = 0; });
      await page.click('.cert-reload [data-action="ct-load"]');
      const busy = () => page.evaluate(() => ({
        main: document.getElementById('main').getAttribute('aria-busy'),
        header: document.getElementById('app-header').classList.contains('is-busy')
      }));
      await page.waitFor(() => window.__ctFake.calls.length === 1 && document.getElementById('main').getAttribute('aria-busy') === 'true',
        { message: 'lookup held open, view busy' });
      const btn = await page.evaluate(() => {
        const b = document.querySelector('.cert-reload [data-action="ct-load"]');
        return { state: b.dataset.state, label: b.querySelector('.btn-label').textContent, cancelIcon: !!b.querySelector('.icon-x'), searchIcon: !!b.querySelector('.icon-search') };
      });
      assertEqual(btn, { state: 'running', label: 'Cancel', cancelIcon: true, searchIcon: false }, 'Load turns into Cancel, with its icon');
      assertEqual((await busy()).header, true, 'header activity bar on');
      await page.click('.cert-reload [data-action="cert-sample"]');
      await page.waitFor(() => window.__ctFake.aborted === 1, { message: 'the held request is aborted' });
      await page.waitFor(() => document.getElementById('main').getAttribute('aria-busy') !== 'true', { timeout: 2000, message: 'busy flag released at once' });
      assertEqual(await busy(), { main: 'false', header: false }, 'not busy');
      await setLangUi(page, 'tr');
      const tr = await page.evaluate(() => ({
        note: document.querySelector('.cert-content .cert-source-note')?.textContent || '',
        toasts: [...document.querySelectorAll('.toast')].map((x) => x.textContent).join(' | ')
      }));
      assert(/DomainScope’u denemek için örnek sertifika/.test(tr.note), `view body re-mounted in Turkish: ${tr.note}`);
      assert(!/işlem bitince/.test(tr.toasts), `no deferred language switch: ${tr.toasts}`);
      await setLangUi(page, 'en');
      assertEqual(await page.evaluate(() => window.__ctFake.calls.length), 1, 'nothing asked after the stop');
      await page.evaluate(() => {
        document.querySelectorAll('.toast').forEach((x) => x.remove());
        document.querySelector('.cert-reload').open = true;
      });
    });

    await run.step('found (Enter in the field): the CT badge, the caveat, Check servers in SSL Targets, the focus on the note; the chain note blames no file', async () => {
      await page.evaluate(() => { window.__ctFake.mode = 'found'; window.__ctFake.calls = []; });
      await page.type('.cert-reload [data-role="ct-host"]', 'www.example.net');
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.cert-overview-badges [data-cert-source]')?.dataset.certSource === 'ct', { message: 'CT certificate loaded' });
      const info = await page.evaluate(() => ({
        badge: document.querySelector('.cert-overview-badges [data-cert-source]')?.dataset.certSource,
        title: document.querySelector('.cert-content .cert-source-note[data-cert-source="ct"] .alert-title')?.textContent,
        note: document.querySelector('.cert-content .cert-source-note')?.textContent || '',
        verify: document.querySelector('.cert-source-note [data-action="ct-verify"]')?.textContent,
        crtsh: document.querySelector('.cert-source-note a[href^="https://crt.sh/?q="]')?.getAttribute('href'),
        pages: window.__ctFake.calls.map((c) => new URL(c.url).searchParams.get('after')),
        focused: document.activeElement === document.querySelector('.cert-content .cert-source-note')
          && document.activeElement.getAttribute('tabindex') === '-1'
      }));
      assertEqual(info.badge, 'ct', 'CT badge');
      assert(info.focused, 'Enter left the focus on the new source note');
      assertEqual(info.title, 'Loaded from Certificate Transparency — the server may serve a different one.', 'caveat');
      assert(/newest valid certificate logged for www\.example\.net/.test(info.note), `note: ${info.note}`);
      assertEqual(info.verify, 'Check servers in SSL Targets', 'SSL Targets link');
      assert(/^https:\/\/crt\.sh\/\?q=[0-9a-f]{64}$/.test(info.crtsh || ''), `crt.sh link ${info.crtsh}`);
      assertEqual(info.pages, [null, '17000000001'], 'paged until the empty page');
      await shot(page, opts, 'cert-desktop-light-en-ct');
      await page.click(tabSel('chain'));
      const issues = await page.evaluate(() => [...document.querySelectorAll('[data-chain-issue]')].map((a) => a.dataset.chainIssue));
      assert(issues.includes('ct-leaf-only') && !issues.includes('leaf-only'), `chain issues ${issues}`);
      await page.click(tabSel('names'));
    });

    await run.step('kept over a trip away: "Result from" with Run again; a lookup that finds nothing leaves the note, a new certificate ends it', async () => {
      const note = () => page.evaluate(() => ({
        text: document.querySelector('.page-kept:not([hidden]) .kept-note-text')?.textContent || '',
        rerun: !!document.querySelector('.page-kept:not([hidden]) [data-action="kept-rerun"]'),
        badge: document.querySelector('.cert-overview-badges [data-cert-source]')?.dataset.certSource
      }));
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'cert');
      let n = await note();
      assert(/^Result from /.test(n.text) && n.rerun, `kept note with Run again: ${JSON.stringify(n)}`);
      await page.evaluate(() => { window.__ctFake.mode = 'none'; window.__ctFake.calls = []; });
      await page.click('[data-action="kept-rerun"]');
      await page.waitFor(() => window.__ctFake.calls.length === 1, { message: 'the host looked up again' });
      assertEqual(await ctResult(page, '.cert-reload', 'not-found'), 'not-found', 'outcome');
      n = await note();
      assert(/^Result from /.test(n.text) && n.rerun, `the kept certificate is still dated: ${JSON.stringify(n)}`);
      assertEqual(n.badge, 'ct', 'the same certificate stays');
      await page.evaluate(() => { window.__ctFake.mode = 'found'; window.__ctFake.calls = []; });
      await page.click('[data-action="kept-rerun"]');
      await page.waitFor(() => !document.querySelector('.page-kept:not([hidden])') && window.__ctFake.calls.length > 0, { message: 'the new certificate ends the note' });
      assertEqual((await note()).badge, 'ct', 'loaded from CT again');
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((x) => x.remove()));
    });

    await run.step('Check servers in SSL Targets: step 1 has the certificate and the CT note; nothing is scanned', async () => {
      await page.click('[data-action="ct-verify"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'scan' && !!document.querySelector('.scan-step-cert .cert-summary'));
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.scan-step-cert .cert-summary-cn').textContent,
        badge: document.querySelector('.scan-step-cert .cert-summary [data-cert-source]')?.dataset.certSource,
        file: document.querySelector('.scan-step-cert .cert-summary-file')?.textContent,
        note: document.querySelector('.scan-step-cert .cert-source-note[data-cert-source="ct"]')?.textContent || '',
        domains: document.querySelector('[data-role="scan-domains"]').value,
        results: document.querySelector('.scan-results-host').childElementCount
      }));
      assertEqual(info.cn, 'example.com', 'same certificate');
      assertEqual(info.badge, 'ct', 'CT badge in step 1');
      assertEqual(info.file, 'www.example.net · 1 certificate', 'named after the host, the leaf alone');
      assert(/After the scan, the Verify tab checks which certificate each server really serves/.test(info.note), `note: ${info.note}`);
      assertEqual(info.domains, 'example.com\nexample.net', 'domains from the certificate');
      assertEqual(info.results, 0, 'no scan');
      await assertNoHorizontalScroll(page, 'scan with a CT certificate');
    });

    await run.step('SSL Targets › Try a sample fills example.com and example.net and starts no scan', async () => {
      await page.click('.scan-step-cert [data-action="cert-remove"]');
      await page.waitFor(() => !document.querySelector('.scan-step-cert .cert-summary'));
      const dohBefore = await page.evaluate(() => performance.getEntriesByType('resource').filter((e) => e.name.includes('dns-query')).length);
      await page.click('.scan-step-cert [data-action="cert-sample"]');
      await page.waitFor(() => !!document.querySelector('.scan-step-cert .cert-source-note[data-cert-source="sample"]'), { message: 'sample in step 1' });
      await sleep(600);
      const info = await page.evaluate(() => ({
        domains: document.querySelector('[data-role="scan-domains"]').value,
        note: document.querySelector('.scan-step-cert .cert-source-note').textContent,
        results: document.querySelector('.scan-results-host').childElementCount,
        doh: performance.getEntriesByType('resource').filter((e) => e.name.includes('dns-query')).length,
        focused: document.activeElement === document.querySelector('.scan-step-cert .cert-source-note')
      }));
      assertEqual(info.domains, 'example.com\nexample.net', 'domains filled in');
      assert(info.focused, 'the focus follows the certificate into step 1');
      assert(/a scan runs only when you press Start scan/.test(info.note), `note: ${info.note}`);
      assertEqual(info.results, 0, 'no scan');
      assertEqual(info.doh, dohBefore, 'no DNS query');
      await shot(page, opts, 'scan-desktop-light-en-sample');
    });

    await run.step('Cert Spotter rate limited: crt.sh finds it, with download links; the next lookup skips Cert Spotter', async () => {
      await page.evaluate(() => {
        window.__ctFake.mode = '429';
        window.__ctFake.calls = [];
        document.querySelector('.scan-cert-another').open = true;
      });
      const scope = '.scan-cert-another';
      await page.type(`${scope} [data-role="ct-host"]`, 'www.example.net');
      await page.click(`${scope} [data-action="ct-load"]`);
      assertEqual(await ctResult(page, scope, 'manual'), 'manual', 'outcome');
      const read = () => page.evaluate((sel) => {
        const box = document.querySelector(`${sel} [data-ct-result]`);
        return {
          text: box.textContent,
          links: [...box.querySelectorAll('a.btn')].map((a) => ({ href: a.getAttribute('href'), target: a.getAttribute('target'), rel: a.getAttribute('rel') })),
          spotter: window.__ctFake.calls.filter((c) => c.url.includes('certspotter')).length,
          crtsh: window.__ctFake.calls.filter((c) => c.url.startsWith('https://crt.sh/')).map((c) => new URL(c.url).searchParams.get('q'))
        };
      }, scope);
      let info = await read();
      assert(/Cert Spotter’s hourly limit for your IP address is used up/.test(info.text), `why: ${info.text}`);
      assert(/issued by Example Trust \(Example CA R1\)/.test(info.text), `issuer: ${info.text}`);
      assertEqual(info.links.map((l) => l.href), ['https://crt.sh/?d=20000000001', 'https://crt.sh/?d=20000000002'], 'both crt.sh ids');
      assert(info.links.every((l) => l.target === '_blank' && l.rel === 'noopener noreferrer'), 'new tab, no opener');
      assertEqual(info.spotter, 1, 'one Cert Spotter request');
      assertEqual(info.crtsh.sort(), ['*.example.net', 'www.example.net'], 'the name and its parent wildcard');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-step-cert .cert-summary [data-cert-source]').dataset.certSource), 'sample', 'the sample stays');
      await assertNoHorizontalScroll(page, 'crt.sh links');
      await shot(page, opts, 'scan-desktop-light-en-ct-manual');
      await page.click(`${scope} [data-action="ct-load"]`);
      await page.waitFor(() => window.__ctFake.calls.filter((c) => c.url.startsWith('https://crt.sh/')).length === 4, { message: 'second lookup' });
      assertEqual(await ctResult(page, scope, 'manual'), 'manual', 'second outcome');
      info = await read();
      assertEqual(info.spotter, 1, 'Cert Spotter cooling down: not asked again');
    });

    await run.step('crt.sh failing while Cert Spotter cools down: the error says so, and until when only crt.sh is searched', async () => {
      const scope = '.scan-cert-another';
      await page.evaluate(() => { window.__ctFake.mode = 'down'; window.__ctFake.calls = []; });
      await page.click(`${scope} [data-action="ct-load"]`);
      assertEqual(await ctResult(page, scope, 'error'), 'error', 'outcome');
      const info = await page.evaluate((sel) => {
        const box = document.querySelector(`${sel} [data-ct-result]`);
        return {
          title: box.querySelector('.alert-title')?.textContent,
          text: box.querySelector('.alert-message')?.textContent,
          retry: !!box.querySelector('[data-action="ct-retry"]'),
          detail: box.querySelector('.alert-details code')?.textContent || '',
          spotter: window.__ctFake.calls.filter((c) => c.url.includes('certspotter')).length,
          crtsh: window.__ctFake.calls.filter((c) => c.url.startsWith('https://crt.sh/')).length
        };
      }, scope);
      assertEqual(info.title, 'Certificate Transparency could not be searched', 'title');
      assert(/^Cert Spotter’s hourly limit for your IP address is used up, and crt\.sh could not answer either: The service returned an error\. Until about \d{1,2}:\d{2}\s?([AP]M)?, “Try again” searches crt\.sh only\.$/.test(info.text || ''), `text: ${info.text}`);
      assert(info.retry, 'Try again');
      assert(/HTTP 404/.test(info.detail), `details: ${info.detail}`);
      assertEqual([info.spotter, info.crtsh], [0, 2], 'only crt.sh asked, not retried after a 404');
      await assertNoHorizontalScroll(page, 'crt.sh error');
      await shot(page, opts, 'scan-desktop-light-en-ct-error');
    });

    await run.step('crt.sh answering one search of two: a hedged not-found with Try again, never "not logged"', async () => {
      const scope = '.scan-cert-another';
      await page.evaluate(() => { window.__ctFake.mode = 'wild-down'; window.__ctFake.calls = []; });
      await page.click(`${scope} [data-ct-result] [data-action="ct-retry"]`);
      const cancelFocused = await page.evaluate((sel) => document.activeElement === document.querySelector(`${sel} [data-action="ct-load"]`), scope);
      assert(cancelFocused, 'Try again is cleared: the focus moves to Load (Cancel), not to <body>');
      assertEqual(await ctResult(page, scope, 'not-found'), 'not-found', 'outcome');
      const info = await page.evaluate((sel) => {
        const box = document.querySelector(`${sel} [data-ct-result]`);
        return {
          text: box.querySelector('.alert-message')?.textContent || '',
          retry: !!box.querySelector('[data-action="ct-retry"]'),
          crtsh: window.__ctFake.calls.filter((c) => c.url.startsWith('https://crt.sh/')).map((c) => new URL(c.url).searchParams.get('q')).sort()
        };
      }, scope);
      assert(/No currently valid certificate for www\.example\.net was found in the answers received, but crt\.sh did not answer every search: a valid certificate may still be logged\. Try again later\.$/.test(info.text), `text: ${info.text}`);
      assert(!/Internal names|is logged in Certificate Transparency/.test(info.text), `no flat not-found: ${info.text}`);
      assert(info.retry, 'Try again offered');
      assertEqual(info.crtsh, ['*.example.net', 'www.example.net'], 'both searches sent, the failed 404 not retried');
      await shot(page, opts, 'scan-desktop-light-en-ct-partial');
      // Back to the crt.sh links for the next step.
      await page.evaluate(() => { window.__ctFake.mode = '429'; window.__ctFake.calls = []; });
      await page.click(`${scope} [data-ct-result] [data-action="ct-retry"]`);
      await page.waitFor(() => window.__ctFake.calls.length === 2, { message: 'retry' });
      assertEqual(await ctResult(page, scope, 'manual'), 'manual', 'links again');
    });

    await run.step('back in the Certificate view: the sample is shared, the crt.sh links are kept until a certificate loads', async () => {
      await gotoRoute(page, 'cert');
      await page.waitFor(() => document.querySelector('.cert-overview-badges [data-cert-source]')?.dataset.certSource === 'sample');
      const kept = await page.evaluate(() => document.querySelector('.cert-reload [data-ct-result]')?.dataset.ctResult);
      assertEqual(kept, 'manual', 'crt.sh links kept across views');
      await uploadAndWait(page, 'ec_wildcard.pem');
      await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
      assert(!await page.evaluate(() => document.querySelector('.cert-reload [data-ct-result]')), 'a dropped file settles it');
    });

    await run.step('chain.pem: overview, validity, badges', async () => {
      await uploadAndWait(page, 'chain.pem');
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.cert-overview-cn').textContent,
        issuer: document.querySelector('.cert-overview-issuer').textContent,
        validity: document.querySelector('.cert-overview [data-validity]').dataset.validity,
        badges: [...document.querySelectorAll('.cert-overview-badges .badge')].map((b) => b.textContent),
        picker: [...document.querySelectorAll('[data-role="cert-select"] option')].map((o) => o.textContent),
        fullchainBtn: !!document.querySelector('[data-action="download-chain"]')
      }));
      assertEqual(info.cn, 'www.example-test.com.tr', 'CN');
      assert(info.issuer.includes('Subdomain Scanner Test Root CA'), 'issuer');
      assertEqual(info.validity, 'ok', 'validity');
      assert(info.badges.includes('5 DNS names') && info.badges.includes('Wildcard') && info.badges.includes('RSA 2048'), `badges ${info.badges}`);
      assertEqual(info.picker, ['Server certificate: www.example-test.com.tr', 'Root CA: Subdomain Scanner Test Root CA'], 'picker');
      assert(!info.fullchainBtn, 'no separate fullchain button when the bundle is only the leaf');
      await shot(page, opts, 'cert-desktop-light-en-names');
    });

    await run.step('Copy summary: issuer, names, validity and the file-stays line as Markdown and plain text, a bare #/cert link', async () => {
      await stubClipboard(page);
      const { tip, issuer } = await page.evaluate(() => ({
        tip: document.querySelector('[data-summary="cert"] [data-action="copy-summary"]').title,
        issuer: document.querySelector('.cert-overview-issuer').textContent
      }));
      assert(/nothing from your server list/.test(tip) && /without any file contents/.test(tip), `tooltip: ${tip}`);
      await page.click('[data-summary="cert"] [data-action="copy-summary"]');
      await page.click('[data-summary="cert"] [data-action="copy-summary-text"]');
      await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
      const [md, plain] = await takeClipboard(page);
      const lines = md.trim().split('\n');
      assertEqual(lines[0], '**Certificate · `www.example-test.com.tr`**', 'title');
      assertEqual(lines[1], `- ${issuer.replace(/^Issued by (.+)$/, 'Issued by `$1`')}`, 'the issuer the overview shows, as a code span');
      assert(/^- 5 DNS names: `[^`]+`, `[^`]+`, `[^`]+`, `[^`]+` \+1 more$/.test(lines[2]), `names, as the badge counts them: ${lines[2]}`);
      assert(/^- Valid until \d{4}-\d{2}-\d{2} \(\d[\d,]* days? left\)$/.test(lines[3]), `validity: ${lines[3]}`);
      assertEqual(lines.slice(-3, -1), ['- The certificate file stays in this browser: the link opens the Certificate tool without it', ''], 'file-stays line, then an empty line');
      assert(new RegExp(`^DomainScope · as of \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC · ${origin}/domainscope/#/cert$`).test(lines[lines.length - 1]), `footer: ${lines[lines.length - 1]}`);
      assertEqual(plain, md.replace(/\*\*|`/g, '').replace('\n\nDomainScope · ', '\nDomainScope · '), 'the same lines in plain text');
    });

    await run.step('print from dark mode: the lifetime bar keeps its colours on paper', async () => {
      await page.send('Emulation.setEmulatedMedia', { media: 'print', features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
      try {
        const bar = await page.evaluate(() => {
          const track = document.querySelector('.cert-overview .cert-validity-track');
          const fill = document.querySelector('.cert-overview .cert-validity-fill');
          return {
            adjust: [getComputedStyle(track).printColorAdjust, getComputedStyle(fill).printColorAdjust],
            shown: track.getBoundingClientRect().height > 0 && fill.getBoundingClientRect().width > 0,
            painted: getComputedStyle(fill).backgroundColor !== 'rgba(0, 0, 0, 0)'
          };
        });
        assertEqual(bar, { adjust: ['exact', 'exact'], shown: true, painted: true }, 'the bar is printed with its backgrounds');
      } finally {
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      }
    });

    await run.step('Names tab: 8 SANs, IDN in Unicode, registrable domain links to a scan', async () => {
      const info = await page.evaluate(() => ({
        rows: [...document.querySelectorAll('.cert-tabs .dt-table tbody tr.dt-row')].map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent.trim())),
        domain: document.querySelector('.cert-domain-link')?.getAttribute('href')
      }));
      assertEqual(info.rows.length, 8, 'SAN rows');
      assert(info.rows.some((r) => r[1] === 'xn--mnchen-3ya.example-test.com.tr' && r[2] === 'münchen.example-test.com.tr'), 'IDN column');
      assert(info.rows.some((r) => r[0] === 'IP' && r[1] === '2001:db8::1') && info.rows.some((r) => r[0] === 'E-mail'), 'IP + e-mail SANs');
      assertEqual(info.domain, '#/scan?domain=example-test.com.tr', 'domain link');
    });

    await run.step('"Does it cover …?" follows RFC 6125 wildcard rules', async () => {
      const check = async (host) => {
        await page.type('[data-role="cert-check"]', host);
        await page.press('Enter');
        return page.evaluate(() => ({
          covered: document.querySelector('.cert-check-result [data-covered]')?.dataset.covered ?? null,
          text: document.querySelector('.cert-check-result')?.textContent || '',
          error: document.querySelector('.cert-check .field-error')?.textContent || ''
        }));
      };
      let r = await check('shop.cdn.example-test.com.tr');
      assert(r.covered === 'true' && r.text.includes('*.cdn.example-test.com.tr'), `wildcard: ${JSON.stringify(r)}`);
      r = await check('a.b.cdn.example-test.com.tr');
      assertEqual(r.covered, 'false', 'two labels deep');
      r = await check('https://EXAMPLE-TEST.com.tr/login');
      assertEqual(r.covered, 'true', 'URL + case');
      r = await check('bad..host');
      assert(/valid hostname/.test(r.error), `invalid: ${JSON.stringify(r)}`);
      await page.type('[data-role="cert-check"]', '');
    });

    await run.step('Details tab: fingerprints and public-key SHA-256 match Node / OpenSSL', async () => {
      await page.click(tabSel('details'));
      await page.waitFor(() => !/Computing/.test(document.querySelector('[data-fp="sha256"]')?.textContent || 'Computing')
        && !/Computing/.test(document.querySelector('[data-fp="spki"]')?.textContent || 'Computing'));
      const fp = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('[data-fp]')].map((e) => [e.dataset.fp, e.textContent])));
      assertEqual(fp.sha256.replace(/:/g, '').toLowerCase(), expected.sha256, 'SHA-256');
      assertEqual(fp.sha1.replace(/:/g, '').toLowerCase(), expected.sha1, 'SHA-1');
      assertEqual(fp.spki, spkiHex, 'SPKI SHA-256');
      assertEqual(fp.pin, Buffer.from(spkiHex, 'hex').toString('base64'), 'pin-sha256');
      const text = await page.evaluate(() => document.querySelector('.cert-details').textContent);
      assert(text.includes('F1:E2:D3:C4:B5:A6:97:88') && text.includes('Türkiye') && text.includes('TLS server'), 'serial, country, EKU');
      await shot(page, opts, 'cert-desktop-light-en-details');
    });

    await run.step('Chain tab: roles, issues, correctly ordered fullchain download', async () => {
      await page.click(tabSel('chain'));
      const info = await page.evaluate(() => ({
        roles: [...document.querySelectorAll('.cert-chain-item')].map((li) => li.dataset.role),
        issues: [...document.querySelectorAll('[data-chain-issue]')].map((a) => a.dataset.chainIssue)
      }));
      assertEqual(info.roles, ['leaf', 'root'], 'roles');
      assertEqual(info.issues, ['root-included', 'ok'], 'issues');
      await takeDownloads(page);
      await page.click('[data-action="download-chain-tab"]');
      const [file] = await takeDownloads(page);
      assertEqual(file.name, 'www.example-test.com.tr-fullchain.pem', 'file name');
      assertEqual(file.text.match(/BEGIN CERTIFICATE/g).length, 1, 'leaf only (root dropped)');
      await shot(page, opts, 'cert-desktop-light-en-chain');
    });

    await run.step('picker shows another certificate of the file', async () => {
      await page.evaluate(() => {
        const sel = document.querySelector('[data-role="cert-select"]');
        sel.value = '1';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.click(tabSel('details'));
      await page.waitFor(() => /Certificate authority/.test(document.querySelector('.cert-details')?.textContent || ''));
      await page.evaluate(() => {
        const sel = document.querySelector('[data-role="cert-select"]');
        sel.value = '0';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
    });

    await run.step('PEM tab + downloads: PEM of the certificate, OpenSSL key check', async () => {
      await page.click(tabSel('pem'));
      const info = await page.evaluate(() => ({
        pem: document.querySelector('.cert-tabs .codeblock-pre').textContent,
        spki: document.querySelector('.cert-spki-value').textContent,
        cmd: [...document.querySelectorAll('.cert-tabs code')].map((c) => c.textContent).join('\n')
      }));
      assert(info.pem.startsWith('-----BEGIN CERTIFICATE-----') && info.pem.trim().endsWith('-----END CERTIFICATE-----'), 'PEM');
      assert(info.cmd.includes('openssl pkey -in private.key -pubout -outform DER | openssl dgst -sha256'), 'key match command');
      await page.waitFor(() => !/Computing/.test(document.querySelector('.cert-spki-value').textContent));
      await takeDownloads(page);
      await page.click('[data-action="download-pem"]');
      const [file] = await takeDownloads(page);
      assertEqual(file.name, 'www.example-test.com.tr.pem', 'PEM file name');
      assertEqual(file.text, info.pem, 'download = shown PEM');
    });

    await run.step('CAA / CT tabs for a private CA: CAA evaluated, CT search not automatic', async () => {
      await page.click(tabSel('ct'));
      const ct = await page.evaluate(() => ({
        text: document.querySelector('.cert-ct').textContent,
        running: !!document.querySelector('.cert-ct .spinner')
      }));
      assert(/not a known public CA/.test(ct.text) && !ct.running, 'manual CT search');
      await page.click(tabSel('caa'));
      await page.waitFor(() => !!document.querySelector('.cert-caa [data-caa-summary]') || !!document.querySelector('.cert-caa .alert-error'),
        { timeout: 30000, message: 'CAA result' });
      const caa = await page.evaluate(() => ({
        summary: document.querySelector('.cert-caa [data-caa-summary]')?.dataset.caaSummary,
        unknownIssuer: /not a known public CA/.test(document.querySelector('.cert-caa').textContent)
      }));
      assert(caa.unknownIssuer, 'unknown issuer explained');
      assert(['ok', 'unknown'].includes(caa.summary), `CAA summary ${caa.summary}`);
    });

    await run.step('chain_reversed.pem: order warning, leaf still first in the overview', async () => {
      await uploadAndWait(page, 'chain_reversed.pem');
      assertEqual(await page.evaluate(() => document.querySelector('.cert-overview-cn').textContent), 'www.example-test.com.tr', 'leaf');
      await page.click(tabSel('chain'));
      await page.waitFor(() => [...document.querySelectorAll('[data-chain-issue]')].some((a) => a.dataset.chainIssue === 'order'));
    });

    await run.step('real_google_chain.pem: 3 certificates, ends at a cross-signed root, fullchain download', async () => {
      await uploadAndWait(page, 'real_google_chain.pem');
      await page.click(tabSel('chain'));
      const issues = await page.evaluate(() => [...document.querySelectorAll('[data-chain-issue]')].map((a) => a.dataset.chainIssue));
      assert(issues.includes('ends-at') && issues.includes('ok'), `issues ${issues}`);
      await takeDownloads(page);
      await page.click('[data-action="download-chain"]');
      const [file] = await takeDownloads(page);
      assertEqual(file.text.match(/BEGIN CERTIFICATE/g).length, 3, 'three certificates');
    });

    await run.step('with_key.pem: the private key is ignored and never shown', async () => {
      await uploadAndWait(page, 'with_key.pem');
      const info = await page.evaluate((chunk) => ({
        warning: !!document.querySelector('[data-warning="PRIVATE_KEY_PRESENT"]'),
        inText: document.body.innerText.includes(chunk) || document.body.textContent.includes('PRIVATE KEY-----'),
        inFields: [...document.querySelectorAll('textarea, input')].some((el) => String(el.value).includes(chunk))
      }), keyChunk);
      assert(info.warning, 'warning shown');
      assert(!info.inText && !info.inFields, 'key material not in the page');
      await shot(page, opts, 'cert-desktop-light-en-with-key');
    });

    await run.step('test.pfx: the password dialog (Cancel keeps the certificate shown, "test" opens it); test.csr: CSR explained', async () => {
      const before = await page.evaluate(() => document.querySelector('.cert-overview-cn')?.textContent || '');
      await uploadFile(page, 'test.pfx');
      await page.waitForSelector('[data-role="pfx-password"]');
      await page.click('[data-action="pfx-cancel"]');
      const toast = await page.waitFor(() => !document.querySelector('.pfx-dialog') && document.querySelector('.toast')?.textContent, { message: 'dialog closed, toast' });
      assert(/test\.pfx was not opened/.test(toast), `toast: ${toast}`);
      assertEqual(await page.evaluate(() => [document.querySelector('.cert-overview-cn')?.textContent || '', !!document.querySelector('.pfx-note')]), [before, false], 'the shown certificate stays');
      await uploadFile(page, 'test.pfx');
      await page.waitForSelector('[data-role="pfx-password"]');
      await page.type('[data-role="pfx-password"]', 'test');
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.pfx-note') && document.querySelector('.cert-overview-cn')?.textContent === 'www.example-test.com.tr', { message: 'PKCS#12 opened' });
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
      await uploadFile(page, 'test.csr');
      await page.waitForSelector('[data-warning="CSR_NOT_CERT"]');
    });

    await run.step('pasted PEM is read automatically and the text box is cleared', async () => {
      const pem = await readFile(fixture('ec_wildcard.pem'), 'utf8');
      await page.evaluate(() => {
        document.querySelector('.cert-reload').open = true;
        document.querySelector('.cert-reload .cert-paste').open = true;
      });
      await page.type('.cert-reload [data-role="cert-paste"]', `Hi, here is the cert:\n${pem}\nThanks`);
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === '*.wild.example.net', { message: 'pasted cert shown' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="cert-paste"]')?.value || ''), '', 'cleared');
      const badges = await page.evaluate(() => [...document.querySelectorAll('.cert-overview-badges .badge')].map((b) => b.textContent));
      assert(badges.some((b) => b.includes('EC 256') && b.includes('P-256')), `EC badge ${badges}`);
    });

    if (!OFFLINE) {
      await run.step('LIVE: a CAA lookup cut short by a language switch starts again (not a blank panel)', async () => {
        await uploadAndWait(page, 'real_cloudflare.pem');
        const release = await delayRequests(page, ['*dns-query*'], 1500);
        try {
          await page.click(tabSel('caa'));
          await page.waitForSelector('.cert-caa .spinner');
          await setLangUi(page, 'tr');
          await page.waitFor(() => !!document.querySelector('.cert-caa [data-caa-summary]') || !!document.querySelector('.cert-caa .alert-error'),
            { timeout: 60000, message: 'CAA result after the re-mount' });
        } finally {
          await release();
          await setLangUi(page, 'en');
        }
      });

      await run.step('LIVE real_cloudflare.pem: CAA over DoH allows Google Trust Services', async () => {
        await uploadAndWait(page, 'real_cloudflare.pem');
        await page.click(tabSel('caa'));
        await page.waitFor(() => !!document.querySelector('.cert-caa [data-caa-summary]') || !!document.querySelector('.cert-caa .alert-error'),
          { timeout: 60000, message: 'CAA result' });
        const info = await page.evaluate(() => ({
          summary: document.querySelector('.cert-caa [data-caa-summary]')?.dataset.caaSummary,
          rows: [...document.querySelectorAll('.cert-caa tbody tr.dt-row')].map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent.trim())),
          results: [...document.querySelectorAll('.cert-caa tbody tr.dt-row td.cert-caa-result')].map((td) => td.textContent.trim()),
          heads: [...document.querySelectorAll('.cert-caa thead th')].map((th) => th.textContent.trim()),
          issuer: document.querySelector('.cert-caa').textContent
        }));
        assert(/pki\.goog/.test(info.issuer), 'issuer mapped to pki.goog');
        assertEqual(info.rows.length, 5, 'one row per name / wildcard');
        assertEqual(info.summary, 'ok', `CAA summary (rows: ${JSON.stringify(info.rows)})`);
        assertEqual(info.results.length, 5, 'a Result cell per row');
        assert(info.results.every((r) => r.startsWith('Allowed')), 'every name allowed');
        assert(info.heads.findIndex((x) => /Result/.test(x)) < info.heads.findIndex((x) => /Records/.test(x)), `the verdict before the records: ${info.heads}`);
        await shot(page, opts, 'cert-desktop-light-en-caa');
      });

      await run.step('LIVE: a crt.sh search cut short by a language switch starts again', async () => {
        const release = await delayRequests(page, ['*crt.sh*'], 1500);
        try {
          await page.click(tabSel('ct'));
          await page.waitForSelector('.cert-ct .spinner');
          await setLangUi(page, 'tr');
          await page.waitFor(() => !!document.querySelector('.cert-ct .spinner'), { message: 'crt.sh search running again after the re-mount' });
        } finally {
          await release();
        }
        await setLangUi(page, 'en'); // the search is started again once more, under the English view
      });

      await run.step('LIVE: the serial is looked up on crt.sh automatically (public CA)', async () => {
        await page.click(tabSel('ct'));
        await page.waitFor(() => !!document.querySelector('.cert-ct [data-ct-result]') || !!document.querySelector('.cert-ct .alert-error'),
          { timeout: 170000, interval: 500, message: 'crt.sh result' });
        const info = await page.evaluate(() => ({
          result: document.querySelector('.cert-ct [data-ct-result]')?.dataset.ctResult || 'error',
          rows: [...document.querySelectorAll('.cert-ct tbody tr.dt-row')].map((tr) => tr.textContent)
        }));
        process.stdout.write(`        crt.sh: ${info.result}${info.rows.length ? ` (${info.rows.length} entr${info.rows.length === 1 ? 'y' : 'ies'})` : ''}\n`);
        if (info.result === 'found') assert(info.rows.length >= 1 && info.rows.every((r) => r.includes('WE1')), 'rows of the issuer');
        else if (info.result === 'none') throw new Error('crt.sh answered but did not list a certificate that is known to be logged');
        await shot(page, opts, 'cert-desktop-light-en-ct');
      });
    }

    await run.step('"Find servers for this certificate" opens SSL Targets with the certificate', async () => {
      if (OFFLINE) await uploadAndWait(page, 'rsa_multi_san.pem');
      const cn = await page.evaluate(() => document.querySelector('.cert-overview-cn').textContent);
      await page.click('[data-action="find-targets"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'scan' && !!document.querySelector('.scan-step-cert .cert-summary'));
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.scan-step-cert .cert-summary-cn').textContent,
        taken: /taken over/.test(document.querySelector('.scan-step-cert').textContent),
        domains: document.querySelector('[data-role="scan-domains"]').value
      }));
      assertEqual(info.cn, cn, 'same certificate');
      assert(info.taken, 'hand-over notice');
      assert(info.domains.length > 0, 'domains filled in');
    });

    await run.step('removing it in SSL Targets clears the Certificate view too (shared session)', async () => {
      await page.click('.scan-step-cert [data-action="cert-remove"]');
      await page.waitFor(() => !document.querySelector('.scan-step-cert .cert-summary'));
      await gotoRoute(page, 'cert');
      await page.waitFor(() => !!document.querySelector('.cert-loader-card'));
    });

    await run.step('language switch (Turkish) keeps the loaded certificate', async () => {
      await uploadAndWait(page, 'chain.pem');
      await setLangUi(page, 'tr');
      await page.waitForSelector('.cert-overview');
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.cert-overview-cn').textContent,
        btn: document.querySelector('[data-action="find-targets"]').textContent,
        tab: document.querySelector(`.cert-tabs [data-tab="names"]`).textContent
      }));
      assertEqual(info.cn, 'www.example-test.com.tr', 'kept');
      assert(/sunucularını bul/.test(info.btn) && /Adlar/.test(info.tab), 'Turkish labels');
      await setLangUi(page, 'en');
    });

    await run.step('dark theme', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.click(tabSel('names'));
      await assertNoHorizontalScroll(page, 'dark names');
      await shot(page, opts, 'cert-desktop-dark-en-names');
      await page.click(tabSel('details'));
      await shot(page, opts, 'cert-desktop-dark-en-details');
      await page.click(tabSel('chain'));
      await shot(page, opts, 'cert-desktop-dark-en-chain');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Phone 390×844 (Turkish)');
    await run.step('phone layout fits 390 px (names, details, chain; light and dark)', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await setLangUi(page, 'tr');
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        for (const tab of ['names', 'details', 'chain']) {
          await page.click(tabSel(tab));
          await sleep(100);
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `phone ${scheme} ${tab}`);
          await shot(page, opts, `cert-mobile-${scheme}-tr-${tab}`);
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('phone: the "No file?" block with crt.sh links fits 375 px (Turkish, dark; Cert Spotter still cooling down)', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await page.evaluate(() => {
        window.__ctFake.mode = '429';
        window.__ctFake.calls = [];
        document.querySelector('.cert-reload').open = true;
      });
      await page.type('.cert-reload [data-role="ct-host"]', 'www.example.net');
      await page.click('.cert-reload [data-action="ct-load"]');
      await ctResult(page, '.cert-reload', 'manual');
      const info = await page.evaluate(() => ({
        label: document.querySelector('.cert-reload [data-role="cert-alt"] .field-label')?.textContent,
        text: document.querySelector('.cert-reload [data-ct-result]').textContent,
        sample: document.querySelector('.cert-reload [data-action="cert-sample"]')?.textContent,
        spotter: window.__ctFake.calls.filter((c) => c.url.includes('certspotter')).length
      }));
      assertEqual(info.label, 'Dosyanız yok mu? Bir host adının herkese açık sertifikasını yükleyin', 'Turkish label');
      assert(/saatlik Cert Spotter sınırı doldu/.test(info.text) && /#20000000001 indir/.test(info.text), `Turkish outcome: ${info.text}`);
      assertEqual(info.sample, 'Örnek deneyin', 'Turkish sample button');
      assertEqual(info.spotter, 0, 'still cooling down');
      await assertNoHorizontalScroll(page, 'phone no-file block');
      await shot(page, opts, 'cert-mobile-dark-tr-nofile');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'cert', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
