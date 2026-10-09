/**
 * monitorfetch.js — the Monitoring view's GitHub source: the results a nightly repository keeps
 * (docs/examples/nightly-domainscope.yml), read through GitHub's REST API with the user's own
 * fine-grained token (Contents: read-only on that one repository): the listing of `results/`, the
 * month files of `results/history/` of the last N months, each file raw, and — when asked, with a
 * token that may read issues — the open issue labelled `domainscope`. lib/monitor.js reads what
 * comes back like a dropped folder.
 *
 * CORS (checked 2026-10-08 and 2026-10-09 from a github.io origin): api.github.com answers
 * `Access-Control-Allow-Origin: *`, allows Authorization and X-GitHub-Api-Version in its preflight
 * and exposes the X-RateLimit-* headers; Accept is CORS-safelisted.
 *
 * The token: the caller passes it to {@link fetchResults}, which keeps it in a local variable for
 * the requests of that one read and sends it only to api.github.com, in the Authorization header
 * (never in a URL); it is never stored, logged, returned or put in an error. Requests carry no
 * cookies or referrer and refuse redirects (a redirect would take the header elsewhere). At most
 * {@link GITHUB_MAX_FILES} files a read, one request at a time.
 *
 * DOM-free; I/O through the injectable `fetchImpl`.
 */

import { fetchAndRead, TimeoutError, AbortError, abortReasonToError } from './util.js';
import { recentHistoryFiles, MONITOR_MAX_BYTES } from './monitor.js';

/** GitHub's own site: the repository's pages the view links (never fetched). */
export const GITHUB_WEB = 'https://github.com';
/** The API every request of this module goes to. */
export const GITHUB_API = 'https://api.github.com';
/** The API version asked for (GitHub's header; its preflight allows it). */
export const GITHUB_API_VERSION = '2022-11-28';
/** Where the nightly template writes: results/NAME.json and results/history/YYYY-MM.jsonl. */
export const GITHUB_RESULTS_DIR = 'results';
export const GITHUB_HISTORY_DIR = 'history';
/** Files one read fetches at most (history months first, then the reports). */
export const GITHUB_MAX_FILES = 30;
/** Months of history a read takes by default, and the choices the view offers. */
export const GITHUB_HISTORY_MONTHS = 3;
export const GITHUB_MONTH_CHOICES = Object.freeze([1, 3, 6, 13]);
/** The label of the nightly issue (the template's `label=domainscope`). */
export const GITHUB_ISSUE_LABEL = 'domainscope';
/** Where the user makes a fine-grained token, and how (links the user opens, never fetched). */
export const GITHUB_TOKEN_URL = 'https://github.com/settings/personal-access-tokens/new';
export const GITHUB_TOKEN_DOCS = 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token';
/** Error codes of {@link GithubFetchError} (the view's `mon.gh.err.<code>`). */
export const GITHUB_FETCH_ERRORS = Object.freeze(['repo', 'token', 'auth', 'forbidden', 'not-found', 'rate-limited', 'http', 'network', 'timeout', 'response', 'empty']);

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
/** A file name of results/ fetched by name (no path, nothing that needs escaping beyond these). */
const FILE_RE = /^[A-Za-z0-9._-]{1,120}$/;
const TOKEN_RE = /^[\x21-\x7e]{20,255}$/;

/** A failed read: `code` from {@link GITHUB_FETCH_ERRORS}, `params` for the message. Never holds the token. */
export class GithubFetchError extends Error {
  /**
   * @param {string} code
   * @param {{ status?: number, detail?: string, resetAt?: number|null }} [params]
   */
  constructor(code, params = {}) {
    super(`github read failed: ${code}${params.status ? ` (HTTP ${params.status})` : ''}`);
    this.name = 'GithubFetchError';
    /** @type {string} */
    this.code = code;
    /** @type {object} */
    this.params = params;
  }
}

/**
 * The repository a user typed: `owner/repo`, or a github.com URL or clone address of it; null when
 * it is none.
 * @param {string} text
 * @returns {{ owner: string, repo: string }|null}
 */
export function parseRepo(text) {
  let s = String(text ?? '').trim();
  if (!s) return null;
  s = s.replace(/^git@github\.com:/i, '').replace(/^(?:https?:\/\/)?(?:www\.)?github\.com\//i, '');
  const [owner = '', rawRepo = ''] = s.split(/[/?#]/);
  const repo = rawRepo.replace(/\.git$/i, '');
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo) || repo === '.' || repo === '..') return null;
  return { owner, repo };
}

/**
 * The pages of a repository the view links (opened by the user, never fetched): its open issues
 * labelled `domainscope` (the nightly issue), its Actions runs and its results folder.
 * @param {{ owner: string, repo: string }|null} where
 * @returns {{ issues: string, actions: string, results: string }|null}
 */
export function repoLinks(where) {
  if (!where || !OWNER_RE.test(where.owner) || !REPO_RE.test(where.repo)) return null;
  const at = `${encodeURIComponent(where.owner)}/${encodeURIComponent(where.repo)}`;
  return {
    issues: `${GITHUB_WEB}/${at}/issues?q=${encodeURIComponent(`is:issue is:open label:${GITHUB_ISSUE_LABEL}`)}`,
    actions: `${GITHUB_WEB}/${at}/actions`,
    results: `${GITHUB_WEB}/${at}/tree/HEAD/${GITHUB_RESULTS_DIR}`
  };
}

/**
 * A pasted token as it will be sent: surrounding white space removed, or null when it cannot be one
 * (white space or a control character inside, under 20 or over 255 characters).
 * @param {string} token
 * @returns {string|null}
 */
export function cleanToken(token) {
  const s = typeof token === 'string' ? token.trim() : '';
  return TOKEN_RE.test(s) ? s : null;
}

/** GitHub's text in an error body (`message`), short and plain. */
function bodyDetail(text) {
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    return '';
  }
  const v = body && typeof body === 'object' && !Array.isArray(body) ? body.message : null;
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 200) : '';
}

/** The rate limit an answer reports: what is left and when it resets (ms), each null when not said. */
function rateOf(res) {
  const get = (name) => (res.headers && typeof res.headers.get === 'function' ? res.headers.get(name) : null);
  const remaining = Number.parseInt(get('x-ratelimit-remaining') ?? '', 10);
  const reset = Number.parseInt(get('x-ratelimit-reset') ?? '', 10);
  return { remaining: Number.isFinite(remaining) ? remaining : null, resetAt: Number.isFinite(reset) ? reset * 1000 : null };
}

/** The error of a non-2xx answer. */
function httpFailure(res) {
  const detail = bodyDetail(res.text);
  const params = { status: res.status, ...(detail ? { detail } : {}) };
  if (res.status === 401) return new GithubFetchError('auth', params);
  if (res.status === 429 || (res.status === 403 && res.rate.remaining === 0)) return new GithubFetchError('rate-limited', { ...params, resetAt: res.rate.resetAt });
  if (res.status === 403) return new GithubFetchError('forbidden', params);
  if (res.status === 404) return new GithubFetchError('not-found', params);
  return new GithubFetchError('http', params);
}

/**
 * One GET with the token: `{ status, text, rate }`. Transport failures become GithubFetchError
 * 'network' / 'timeout'; cancellation stays an AbortError.
 */
async function apiGet(url, authorization, accept, { fetchImpl, signal, timeoutMs }) {
  try {
    return await fetchAndRead(url, {
      fetchImpl,
      signal,
      timeoutMs,
      method: 'GET',
      headers: { authorization, accept, 'x-github-api-version': GITHUB_API_VERSION },
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      redirect: 'error'
    }, async (res) => ({ status: res.status, text: await res.text(), rate: rateOf(res) }));
  } catch (err) {
    if (signal && signal.aborted) throw abortReasonToError(signal.reason);
    if (err instanceof AbortError) throw err;
    if (err instanceof TimeoutError) throw new GithubFetchError('timeout');
    throw new GithubFetchError('network');
  }
}

/** A directory listing of the contents API: its entries `{ name, type, size }`, or a 'response' error. */
function listing(res) {
  let body;
  try {
    body = JSON.parse(res.text);
  } catch {
    throw new GithubFetchError('response', { status: res.status });
  }
  if (!Array.isArray(body)) throw new GithubFetchError('response', { status: res.status });
  return body.filter((e) => e && typeof e === 'object' && typeof e.name === 'string' && typeof e.type === 'string')
    .map((e) => ({ name: e.name, type: e.type, size: Number.isFinite(e.size) ? e.size : 0 }));
}

/** The open issue of a listing of issues (pull requests left out), or null. */
function openIssue(text) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return null;
  }
  const issue = (Array.isArray(body) ? body : []).find((i) => i && typeof i === 'object' && !i.pull_request && Number.isInteger(i.number));
  if (!issue) return null;
  const url = typeof issue.html_url === 'string' && /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/issues\/\d+$/.test(issue.html_url) ? issue.html_url : null;
  return {
    number: issue.number,
    title: typeof issue.title === 'string' ? issue.title.replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 200) : '',
    url,
    updatedAt: typeof issue.updated_at === 'string' && !Number.isNaN(Date.parse(issue.updated_at)) ? issue.updated_at : null,
    comments: Number.isInteger(issue.comments) ? issue.comments : null
  };
}

/**
 * Read a repository's results. Resolves with the files as lib/monitor.js readMonitorFiles takes them
 * (`{ name, text, source: 'github' }`), what was left out, the open issue when asked for and the rate
 * limit left; rejects with a {@link GithubFetchError} (or an AbortError when `signal` aborts).
 *
 * @param {string} repoText `owner/repo` or a github.com URL of it
 * @param {string} token a fine-grained token; used for this read only
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {AbortSignal} [opts.signal]
 * @param {number} [opts.months] months of history (this one included)
 * @param {boolean} [opts.issue] also ask for the open issue labelled `domainscope` (needs Issues: read)
 * @param {Date|number} [opts.now] which months are the last ones
 * @param {(p: { phase: 'list'|'file'|'issue', done: number, total: number }) => void} [opts.onProgress]
 * @param {number} [opts.timeoutMs=20000] per request
 * @returns {Promise<{ owner: string, repo: string, files: Array<{ name: string, text: string, source: string }>,
 *   skipped: { tooLarge: string[], overCap: string[] }, history: { months: number, available: number },
 *   issue: object|null, issueError: string|null, rate: { remaining: number|null, resetAt: number|null }, requests: number }>}
 */
export async function fetchResults(repoText, token, {
  fetchImpl = globalThis.fetch, signal, months = GITHUB_HISTORY_MONTHS, issue = false, now = Date.now(), onProgress = null, timeoutMs = 20000
} = {}) {
  const where = parseRepo(repoText);
  if (!where) throw new GithubFetchError('repo');
  const secret = cleanToken(token);
  if (!secret) throw new GithubFetchError('token');
  const authorization = `Bearer ${secret}`;
  const base = `${GITHUB_API}/repos/${encodeURIComponent(where.owner)}/${encodeURIComponent(where.repo)}`;
  const state = { requests: 0, rate: { remaining: null, resetAt: null } };
  const progress = (phase, done, total) => {
    if (typeof onProgress !== 'function') return;
    try {
      onProgress({ phase, done, total });
    } catch {
      /* an observer never breaks the read */
    }
  };
  const get = async (url, accept = 'application/vnd.github+json') => {
    state.requests += 1;
    const res = await apiGet(url, authorization, accept, { fetchImpl, signal, timeoutMs });
    if (res.rate.remaining !== null) state.rate = res.rate;
    return res;
  };

  progress('list', 0, 1);
  const top = await get(`${base}/contents/${GITHUB_RESULTS_DIR}`);
  if (top.status !== 200) throw httpFailure(top);
  const entries = listing(top);
  const reports = entries.filter((e) => e.type === 'file' && /\.json$/i.test(e.name) && FILE_RE.test(e.name)).sort((a, b) => (a.name < b.name ? -1 : 1));
  let monthFiles = [];
  let available = 0;
  if (entries.some((e) => e.type === 'dir' && e.name === GITHUB_HISTORY_DIR)) {
    const hist = await get(`${base}/contents/${GITHUB_RESULTS_DIR}/${GITHUB_HISTORY_DIR}`);
    if (hist.status !== 200) throw httpFailure(hist);
    const files = listing(hist).filter((e) => e.type === 'file' && FILE_RE.test(e.name));
    const recent = recentHistoryFiles(files.map((e) => e.name), now, Math.max(1, Math.floor(months) || GITHUB_HISTORY_MONTHS));
    available = recentHistoryFiles(files.map((e) => e.name), now, 1200).length;
    monthFiles = recent.map((name) => ({ ...files.find((e) => e.name === name), path: `${GITHUB_HISTORY_DIR}/${name}` }));
  }
  if (!reports.length && !monthFiles.length) throw new GithubFetchError('empty');
  const wanted = [...monthFiles, ...reports.map((e) => ({ ...e, path: e.name }))];
  const tooLarge = wanted.filter((e) => e.size > MONITOR_MAX_BYTES).map((e) => e.name);
  const fitting = wanted.filter((e) => e.size <= MONITOR_MAX_BYTES);
  const take = fitting.slice(0, GITHUB_MAX_FILES);
  const overCap = fitting.slice(GITHUB_MAX_FILES).map((e) => e.name);
  const out = [];
  for (const [i, e] of take.entries()) {
    progress('file', i, take.length);
    const path = e.path.split('/').map(encodeURIComponent).join('/');
    const res = await get(`${base}/contents/${GITHUB_RESULTS_DIR}/${path}`, 'application/vnd.github.raw+json');
    if (res.status !== 200) throw httpFailure(res);
    out.push({ name: e.name, text: res.text, source: 'github' });
  }
  progress('file', take.length, take.length);
  let found = null;
  let issueError = null;
  if (issue) {
    progress('issue', 0, 1);
    try {
      const res = await get(`${base}/issues?labels=${GITHUB_ISSUE_LABEL}&state=open&per_page=5`);
      if (res.status === 200) found = openIssue(res.text);
      else issueError = httpFailure(res).code;
    } catch (err) {
      if (err instanceof AbortError || (signal && signal.aborted)) throw err;
      issueError = err && err.code ? err.code : 'network';
    }
  }
  return {
    owner: where.owner,
    repo: where.repo,
    files: out,
    skipped: { tooLarge, overCap },
    history: { months: monthFiles.length, available },
    issue: found,
    issueError,
    rate: state.rate,
    requests: state.requests
  };
}
