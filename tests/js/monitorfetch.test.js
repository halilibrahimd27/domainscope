/**
 * lib/monitorfetch.js — the Monitoring view's GitHub source against a fake GitHub API (no network):
 * the repository typed, the token checked and sent only in the Authorization header of requests to
 * api.github.com (never in a URL, an error or the result), the listing of results/ and of
 * results/history/, the last N months and the 30-file cap, each file raw, the optional open issue,
 * and every failure GitHub answers with (401, 403, a rate limit, 404, a redirect, a timeout).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  GITHUB_API, GITHUB_MAX_FILES, GITHUB_HISTORY_MONTHS, GITHUB_FETCH_ERRORS, GithubFetchError, parseRepo, cleanToken, fetchResults, repoLinks
} from '../../assets/js/lib/monitorfetch.js';
import { readMonitorFiles, emptyMonitor } from '../../assets/js/lib/monitor.js';
import { monitorFixture, MONITOR_NOW } from './monitor-fixture.mjs';

/** A made-up token, built from pieces (no file holds anything token-shaped). */
const TOKEN = ['github', 'pat', 'made', 'up', 'for', 'tests', '0123456789'].join('_');
const REPO = 'example-org/nightly';
const BASE = `${GITHUB_API}/repos/example-org/nightly`;

/**
 * A fake GitHub API over a results folder: `files` by path under results/. Every request is logged
 * with what it carried; `mode` makes it fail.
 */
function fakeGithub(files, { mode = {}, issues = [] } = {}) {
  const calls = [];
  const res = (status, body, headers = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json', 'x-ratelimit-remaining': '4990', 'x-ratelimit-reset': '1791510624', ...headers }
  });
  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    const headers = init.headers || {};
    calls.push({ url, auth: headers.authorization, accept: headers.accept, version: headers['x-github-api-version'], credentials: init.credentials, redirect: init.redirect, referrerPolicy: init.referrerPolicy });
    if (mode.network) throw new TypeError('Failed to fetch');
    if (headers.authorization !== `Bearer ${TOKEN}`) return res(401, { message: 'Bad credentials' });
    if (mode.forbidden) return res(403, { message: 'Resource not accessible by personal access token' });
    if (mode.rate) return res(403, { message: 'API rate limit exceeded' }, { 'x-ratelimit-remaining': '0' });
    if (mode.tooMany) return res(429, { message: 'secondary rate limit' });
    const u = new URL(url);
    if (!u.pathname.startsWith('/repos/example-org/nightly/')) return res(404, { message: 'Not Found' });
    const rest = decodeURIComponent(u.pathname.slice('/repos/example-org/nightly/'.length));
    if (rest === 'issues') {
      if (mode.issuesForbidden) return res(403, { message: 'Resource not accessible by personal access token' });
      return res(200, issues);
    }
    if (!rest.startsWith('contents/results')) return res(404, { message: 'Not Found' });
    const path = rest.slice('contents/results'.length).replace(/^\//, '');
    const inDir = (dir) => Object.keys(files).filter((p) => (dir ? p.startsWith(`${dir}/`) : true)).map((p) => (dir ? p.slice(dir.length + 1) : p));
    if (path === '' || path === 'history') {
      if (path === '' && mode.noResults) return res(404, { message: 'Not Found' });
      const names = inDir(path);
      const entries = new Map();
      for (const n of names) {
        const [first, ...more] = n.split('/');
        entries.set(first, more.length ? { name: first, type: 'dir', size: 0 } : { name: first, type: 'file', size: files[path ? `${path}/${n}` : n].length });
      }
      if (mode.bigFile && path === '') entries.set('huge.json', { name: 'huge.json', type: 'file', size: 200 * 1024 * 1024 });
      return res(200, [...entries.values()]);
    }
    if (!(path in files)) return res(404, { message: 'Not Found' });
    assert.equal(headers.accept, 'application/vnd.github.raw+json', 'a file is asked for raw');
    return res(200, files[path], { 'content-type': 'application/vnd.github.raw+json; charset=utf-8' });
  };
  return { fetchImpl, calls };
}

const fixtureFiles = () => {
  const fx = monitorFixture();
  const files = {};
  for (const f of fx.files) files[/\.jsonl$/.test(f.name) ? `history/${f.name}` : f.name] = f.text;
  return files;
};

describe('the repository and the token', () => {
  test('owner/repo, a github.com URL or a clone address; anything else is none', () => {
    for (const s of ['example-org/nightly', ' https://github.com/example-org/nightly ', 'github.com/example-org/nightly/tree/main/results', 'git@github.com:example-org/nightly.git', 'https://www.github.com/example-org/nightly.git']) {
      assert.deepEqual(parseRepo(s), { owner: 'example-org', repo: 'nightly' }, s);
    }
    for (const s of ['', 'nightly', '-bad/nightly', 'example-org/..', 'example org/nightly', 'https://example.com/a/b', 'a/b c']) assert.equal(parseRepo(s), null, s);
    assert.equal(cleanToken(`  ${TOKEN}\n`), TOKEN);
    for (const s of ['short', `${TOKEN} x`, 'x'.repeat(256), '', null]) assert.equal(cleanToken(s), null, String(s));
    assert.deepEqual(repoLinks({ owner: 'example-org', repo: 'nightly' }), {
      issues: 'https://github.com/example-org/nightly/issues?q=is%3Aissue%20is%3Aopen%20label%3Adomainscope',
      actions: 'https://github.com/example-org/nightly/actions',
      results: 'https://github.com/example-org/nightly/tree/HEAD/results'
    });
    assert.equal(repoLinks({ owner: 'a b', repo: 'c' }), null);
  });
});

describe('fetchResults', () => {
  test('the listing, the last three months of history, every report raw; the token only in the header to api.github.com', async () => {
    const gh = fakeGithub(fixtureFiles());
    const progress = [];
    const out = await fetchResults(REPO, ` ${TOKEN} `, { fetchImpl: gh.fetchImpl, now: MONITOR_NOW, onProgress: (p) => progress.push(p.phase) });
    assert.deepEqual([out.owner, out.repo], ['example-org', 'nightly']);
    assert.deepEqual(out.files.map((f) => f.name), ['2026-10.jsonl', '2026-09.jsonl', '2026-08.jsonl', 'audit.json', 'ct.json', 'health.json', 'takeover.json', 'tls.json']);
    assert.deepEqual(out.history, { months: 3, available: 3 });
    assert.equal(out.requests, 2 + 8, 'two listings and eight files');
    assert.equal(out.issue, null);
    assert.equal(out.issueError, null);
    assert.deepEqual(out.rate, { remaining: 4990, resetAt: 1791510624000 });
    assert.ok(progress.includes('list') && progress.includes('file'));
    for (const c of gh.calls) {
      assert.ok(c.url.startsWith(`${BASE}/contents/results`), c.url);
      assert.ok(!c.url.includes(TOKEN), 'never in a URL');
      assert.deepEqual([c.auth, c.version, c.credentials, c.redirect, c.referrerPolicy], [`Bearer ${TOKEN}`, '2022-11-28', 'omit', 'error', 'no-referrer']);
    }
    assert.ok(!JSON.stringify(out).includes(TOKEN), 'the result holds no token');
    // what came back reads like a dropped folder
    const r = readMonitorFiles(emptyMonitor(), out.files);
    assert.deepEqual([r.data.reports.length, r.added.history, r.skippedLines], [5, 3, 2]);
  });

  test('fewer months when asked; the newest month first; the reports after them within the cap', async () => {
    const files = fixtureFiles();
    const one = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub(files).fetchImpl, now: MONITOR_NOW, months: 1 });
    assert.deepEqual(one.files.slice(0, 2).map((f) => f.name), ['2026-10.jsonl', 'audit.json']);
    assert.deepEqual(one.history, { months: 1, available: 3 });
    // more reports than the cap: the history months first, then the reports by name, the rest named
    for (let i = 0; i < GITHUB_MAX_FILES; i += 1) files[`extra-${String(i).padStart(2, '0')}.json`] = files['health.json'];
    const capped = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub(files).fetchImpl, now: MONITOR_NOW });
    assert.equal(capped.files.length, GITHUB_MAX_FILES);
    // 3 months and 5 + 30 reports: the last 8 reports by name are left out
    assert.deepEqual(capped.skipped.overCap, ['extra-25.json', 'extra-26.json', 'extra-27.json', 'extra-28.json', 'extra-29.json', 'health.json', 'takeover.json', 'tls.json']);
    assert.equal(GITHUB_HISTORY_MONTHS, 3);
    // a file larger than the page reads is never fetched
    const big = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub(fixtureFiles(), { mode: { bigFile: true } }).fetchImpl, now: MONITOR_NOW });
    assert.deepEqual(big.skipped.tooLarge, ['huge.json']);
  });

  test('the open issue, when asked for: its number, title and link; a token that may not read issues says so, the results still come', async () => {
    const issues = [
      { number: 7, title: 'Add a feature', html_url: 'https://github.com/example-org/nightly/pull/7', pull_request: {} },
      { number: 12, title: 'DomainScope: changes since the last nightly run', html_url: 'https://github.com/example-org/nightly/issues/12', updated_at: '2026-10-09T03:45:00Z', comments: 3 }
    ];
    const gh = fakeGithub(fixtureFiles(), { issues });
    const out = await fetchResults(REPO, TOKEN, { fetchImpl: gh.fetchImpl, now: MONITOR_NOW, issue: true });
    assert.deepEqual(out.issue, { number: 12, title: 'DomainScope: changes since the last nightly run', url: 'https://github.com/example-org/nightly/issues/12', updatedAt: '2026-10-09T03:45:00Z', comments: 3 });
    assert.equal(gh.calls.at(-1).url, `${BASE}/issues?labels=domainscope&state=open&per_page=5`);
    const denied = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub(fixtureFiles(), { mode: { issuesForbidden: true } }).fetchImpl, now: MONITOR_NOW, issue: true });
    assert.deepEqual([denied.issue, denied.issueError, denied.files.length], [null, 'forbidden', 8]);
    const odd = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub(fixtureFiles(), { issues: [{ number: 3, title: 'x', html_url: 'javascript:alert(1)' }] }).fetchImpl, now: MONITOR_NOW, issue: true });
    assert.equal(odd.issue.url, null, 'a link that is not the issue\'s own is never kept');
  });

  test('what GitHub refuses, in the view\'s codes; never the token in an error', async () => {
    const attempt = async (opts, repo = REPO, token = TOKEN) => {
      try {
        await fetchResults(repo, token, { fetchImpl: fakeGithub(fixtureFiles(), opts).fetchImpl, now: MONITOR_NOW, timeoutMs: 1000 });
        return 'ok';
      } catch (err) {
        assert.ok(err instanceof GithubFetchError, String(err));
        assert.ok(!JSON.stringify({ m: err.message, p: err.params }).includes(TOKEN));
        return `${err.code}${err.params.status ? ` ${err.params.status}` : ''}${err.params.detail ? `: ${err.params.detail}` : ''}`;
      }
    };
    assert.equal(await attempt({}, 'nope'), 'repo');
    assert.equal(await attempt({}, REPO, 'short'), 'token');
    assert.equal(await attempt({}, REPO, `${TOKEN}x`), 'auth 401: Bad credentials');
    assert.equal(await attempt({ mode: { forbidden: true } }), 'forbidden 403: Resource not accessible by personal access token');
    assert.equal(await attempt({ mode: { rate: true } }), 'rate-limited 403: API rate limit exceeded');
    assert.equal(await attempt({ mode: { tooMany: true } }), 'rate-limited 429: secondary rate limit');
    assert.equal(await attempt({ mode: { noResults: true } }), 'not-found 404: Not Found');
    assert.equal(await attempt({}, 'example-org/other'), 'not-found 404: Not Found');
    assert.equal(await attempt({ mode: { network: true } }), 'network');
    const empty = await fetchResults(REPO, TOKEN, { fetchImpl: fakeGithub({ 'health.md': 'x' }).fetchImpl, now: MONITOR_NOW }).catch((e) => e.code);
    assert.equal(empty, 'empty', 'no report and no history');
    // a redirect (a renamed repository) is refused, never followed with the header
    const redirect = await fetchResults(REPO, TOKEN, { fetchImpl: async (u, init) => { assert.equal(init.redirect, 'error'); throw new TypeError('redirect'); }, now: MONITOR_NOW }).catch((e) => e.code);
    assert.equal(redirect, 'network');
    const slow = await fetchResults(REPO, TOKEN, {
      fetchImpl: (u, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))), now: MONITOR_NOW, timeoutMs: 20
    }).catch((e) => e.code);
    assert.equal(slow, 'timeout');
    const controller = new AbortController();
    const stopped = fetchResults(REPO, TOKEN, { fetchImpl: (u, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))), signal: controller.signal, now: MONITOR_NOW });
    controller.abort();
    await assert.rejects(stopped, (e) => e.name === 'AbortError');
    for (const code of ['repo', 'token', 'auth', 'forbidden', 'not-found', 'rate-limited', 'network', 'timeout', 'empty']) assert.ok(GITHUB_FETCH_ERRORS.includes(code), code);
  });
});
