/**
 * About view links that must work on GitHub Pages: "View source" opens the CLI on GitHub (Pages
 * serves .py as application/octet-stream, so a link to the site's copy downloads it), the wordlist
 * licences resolve next to the module (the Pages bundle serves assets/ from v/<version>/assets/),
 * and the self-hosting text names every step a fork needs. No DOM, no network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { CLI_PATH, LICENSES_URL, cliSourceUrl } from '../../assets/js/views/about.js';
import { REPO_URL } from '../../assets/js/app.js';
import { t, setLang } from '../../assets/js/i18n.js';

test('View source points at the CLI on GitHub, Download keeps the site copy', () => {
  assert.equal(cliSourceUrl(REPO_URL), `${REPO_URL}/blob/main/cli/ssl_origin_scan.py`);
  assert.equal(cliSourceUrl(`${REPO_URL}/`), `${REPO_URL}/blob/main/cli/ssl_origin_scan.py`, 'trailing slash');
  assert.equal(CLI_PATH, 'cli/ssl_origin_scan.py');
  assert.ok(existsSync(fileURLToPath(new URL(`../../${CLI_PATH}`, import.meta.url))), 'the file the blob URL names exists');
});

test('the wordlist licences link is resolved from the module, not from the page', () => {
  assert.ok(existsSync(fileURLToPath(LICENSES_URL)), LICENSES_URL);
  assert.match(LICENSES_URL, /\/assets\/data\/THIRD_PARTY_LICENSES\.txt$/);
  const deployed = new URL('../../data/THIRD_PARTY_LICENSES.txt', 'https://example.com/app/v/abc123/assets/js/views/about.js');
  assert.equal(deployed.href, 'https://example.com/app/v/abc123/assets/data/THIRD_PARTY_LICENSES.txt');
});

test('self-hosting names the fork steps in both languages (workflows are off in a new fork)', () => {
  try {
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      for (const re of [/fork/i, /Actions/, /Pages/, /Deploy to GitHub Pages/]) assert.match(t('about.selfhostBody'), re, `${lang}: ${re}`);
    }
  } finally {
    setLang('en');
  }
});
