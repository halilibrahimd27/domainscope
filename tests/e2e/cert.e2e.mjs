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
 *   - chain.pem: overview, SAN table (IDN shown as Unicode), "does it cover …?" check,
 *     fingerprints and public-key SHA-256 (compared with Node's crypto), chain order,
 *     certificate picker, PEM tab, downloads (captured in the page)
 *   - chain_reversed.pem (wrong order), real_google_chain.pem (ends at a cross-signed root),
 *     with_key.pem (private key ignored and never displayed), test.pfx (PKCS#12 instructions),
 *     test.csr (CSR), a pasted PEM (ec_wildcard.pem)
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
  createRunner, gotoRoute, installDownloadCapture, setLangUi, shot, sleep, takeDownloads, waitReady
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

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}${OFFLINE ? ' (offline: live checks skipped)' : ''}\n`);
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await installDownloadCapture(page);
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

    await run.step('test.pfx: PKCS#12 explained with the OpenSSL command; test.csr: CSR explained', async () => {
      await uploadFile(page, 'test.pfx');
      await page.waitForSelector('[data-warning="PKCS12_UNSUPPORTED"]');
      const pfx = await page.evaluate(() => ({
        cmd: document.querySelector('[data-warning="PKCS12_UNSUPPORTED"] code').textContent,
        overview: !!document.querySelector('.cert-overview'),
        noCert: !!document.querySelector('[data-warning="NO_CERTIFICATE"]')
      }));
      assertEqual(pfx.cmd, 'openssl pkcs12 -in test.pfx -nokeys -out cert.pem', 'command with the file name');
      assert(!pfx.overview && !pfx.noCert, 'no overview, no redundant "no certificate" alert');
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
      await run.step('LIVE real_cloudflare.pem: CAA over DoH allows Google Trust Services', async () => {
        await uploadAndWait(page, 'real_cloudflare.pem');
        await page.click(tabSel('caa'));
        await page.waitFor(() => !!document.querySelector('.cert-caa [data-caa-summary]') || !!document.querySelector('.cert-caa .alert-error'),
          { timeout: 60000, message: 'CAA result' });
        const info = await page.evaluate(() => ({
          summary: document.querySelector('.cert-caa [data-caa-summary]')?.dataset.caaSummary,
          rows: [...document.querySelectorAll('.cert-caa tbody tr.dt-row')].map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent.trim())),
          issuer: document.querySelector('.cert-caa').textContent
        }));
        assert(/pki\.goog/.test(info.issuer), 'issuer mapped to pki.goog');
        assertEqual(info.rows.length, 5, 'one row per name / wildcard');
        assertEqual(info.summary, 'ok', `CAA summary (rows: ${JSON.stringify(info.rows)})`);
        assert(info.rows.every((r) => r[3].startsWith('Allowed')), 'every name allowed');
        await shot(page, opts, 'cert-desktop-light-en-caa');
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
