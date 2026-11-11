/**
 * tools/blocklist-check.mjs — the network-filter matcher that keeps the site's own files from
 * carrying a name a public ad or tracker list blocks (EasyPrivacy's `/netresults.js` once blocked
 * IP Intel, Bulk Resolve, Reverse DNS and Servers for every blocker user). No network: the lists
 * here are a few lines in the lists' own syntax; CI downloads the real ones.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blockedUrls, parseFilter, requestType, siteUrls } from '../../tools/blocklist-check.mjs';

const BASE = 'https://owner.github.io/domainscope/';
const V = `${BASE}v/0123456789ab/assets/`;
const URLS = [BASE, `${BASE}index.html`, `${V}js/lib/netresults.js`, `${V}js/lib/ipresults.js`, `${V}js/views/ip.js`, `${V}data/ranges/manifest.json`, `${V}css/style.css`];
const blocked = (filters) => blockedUrls(URLS, [{ name: 'list', text: filters.join('\n') }]).map((b) => b.url.replace(V, ''));

test('the filter that blocked four views blocks the old name, not the new one', () => {
  assert.deepEqual(blocked(['/netresults.js']), ['js/lib/netresults.js']);
  const [hit] = blockedUrls(URLS, [{ name: 'EasyPrivacy', text: '! comment\n/netresults.js\n' }]);
  assert.deepEqual([hit.type, hit.hits], ['script', [{ list: 'EasyPrivacy', filter: '/netresults.js' }]]);
});

test('anchors, wildcards, separators and regex filters', () => {
  assert.deepEqual(blocked(['||owner.github.io/domainscope/*/netresults.js^']), ['js/lib/netresults.js']);
  assert.deepEqual(blocked(['|https://owner.github.io/domainscope/v/*/lib/ip']), ['js/lib/ipresults.js']);
  assert.deepEqual(blocked(['/views/ip.js|']), ['js/views/ip.js']);
  assert.deepEqual(blocked(['/\\/net[a-z]+\\.js/']), ['js/lib/netresults.js']);
  assert.deepEqual(blocked(['/NETRESULTS.js']), ['js/lib/netresults.js'], 'case-insensitive by default');
  assert.deepEqual(blocked(['/NETRESULTS.js$match-case']), []);
  assert.deepEqual(blocked(['||example.com^', '||ads.example.net/netresults.js']), [], 'another host');
});

test('only a filter that applies to a first-party request of this type on this site', () => {
  assert.deepEqual(blocked(['/netresults.js$third-party', '/netresults.js$3p']), [], 'the site loads its own files');
  assert.deepEqual(blocked(['/netresults.js$domain=other.example']), [], 'only on other sites');
  assert.deepEqual(blocked(['/netresults.js$domain=~github.io']), [], 'except on GitHub Pages');
  assert.deepEqual(blocked(['/netresults.js$domain=github.io']), ['js/lib/netresults.js']);
  assert.deepEqual(blocked(['/netresults.js$domain=github.*']), ['js/lib/netresults.js'], 'any TLD');
  assert.deepEqual(blocked(['/netresults.js$image']), [], 'a module is a script');
  assert.deepEqual(blocked(['/netresults.js$script,xhr']), ['js/lib/netresults.js']);
  assert.deepEqual(blocked(['/manifest.json$xmlhttprequest']), ['data/ranges/manifest.json']);
  assert.deepEqual(blocked(['/netresults.js$~script']), []);
  assert.deepEqual(blocked(['/netresults.js$removeparam=x', '/netresults.js$csp=script-src none', '/netresults.js$badfilter']), [], 'modifies, does not block');
  assert.deepEqual(blocked(['$script,domain=owner.github.io', '*$image']), [], 'a type-only filter names no file');
});

test('@@ exceptions: a matching one unblocks, a cosmetic one does not', () => {
  assert.deepEqual(blocked(['/netresults.js', '@@/netresults.js']), []);
  assert.deepEqual(blocked(['/netresults.js', '@@||owner.github.io^$document']), [], 'the whole site allowed');
  assert.deepEqual(blocked(['/netresults.js', '@@||owner.github.io^$urlblock']), [], 'AdGuard: no network block on the page');
  // EasyList and AdGuard Base carry exactly this line: it turns off generic cosmetic filters on
  // GitHub Pages and lifts no network block (taken for one, it hid the block it should report).
  assert.deepEqual(blocked(['/netresults.js', '@@||github.io^$generichide', '@@||github.io^$elemhide']), ['js/lib/netresults.js']);
  assert.deepEqual(blocked(['/netresults.js', '@@/netresults.js$image']), ['js/lib/netresults.js'], 'an exception of another type');
  assert.deepEqual(blocked(['/netresults.js', '@@/netresults.js$domain=other.example']), ['js/lib/netresults.js']);
});

test('comments, cosmetic, scriptlet and HTML filters are not network filters', () => {
  for (const line of ['! /netresults.js', '[Adblock Plus 2.0]', 'example.com##.ad', '##.netresults', 'github.io#@#.banner',
    'example.com#?#div:has(.ad)', 'example.com##+js(set, x, 1)', 'example.com#%#//scriptlet("x")', 'example.com$$script', '']) {
    assert.equal(parseFilter(line), null, line);
  }
  assert.ok(parseFilter('/netresults.js'));
});

test('request types of the site\'s files', () => {
  assert.deepEqual([BASE, `${V}js/app.js`, `${V}css/a.css`, `${V}icons/x.svg`, `${V}data/x.json`, `${V}data/w.txt.gz`, `${BASE}cli/ip_scan.py`].map(requestType),
    ['document', 'script', 'stylesheet', 'image', 'xmlhttprequest', 'xmlhttprequest', 'other']);
});

test('the deploy\'s URLs: the site root, root files, cli/ and icons/, assets/ under v/<version>/', async () => {
  const urls = await siteUrls(BASE);
  assert.equal(urls[0], BASE);
  for (const want of ['index.html', 'sw.js', 'manifest.tr.webmanifest', 'cli/ip_scan.py', 'cli/dir_scan.py']) assert.ok(urls.includes(BASE + want), want);
  assert.ok(urls.includes(`${V}js/lib/ipresults.js`), 'the module that replaced netresults.js');
  assert.ok(urls.includes(`${V}js/views/bulk.js`));
  assert.ok(!urls.some((u) => /netresults/.test(u)), 'no file is named netresults any more');
  assert.ok(!urls.some((u) => /\.nojekyll|__pycache__|\.DS_Store|\.pyc$/.test(u)), 'no clutter');
  assert.ok(!urls.some((u) => u.startsWith(`${BASE}assets/`)), 'assets/ only under v/<version>/');
});
