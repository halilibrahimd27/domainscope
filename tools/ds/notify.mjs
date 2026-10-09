/**
 * tools/ds/notify.mjs — the headless runner's alert channels: the changes since the baseline
 * posted to the team's chat, pager or own webhook (`--notify`, `--notify-bad`).
 *
 * A port of the Python CLI's --notify (cli/ssl_origin_scan.py detect_notify_format,
 * check_notify_url, notify_host, redact_url, build_notification, send_notification) with the
 * same formats, limits and rules, and three channels the CLI has too:
 * - chat: Slack (also Discord's `…/slack` endpoint), Microsoft Teams and Power Automate (an
 *   Adaptive Card), Discord, Telegram (`chat_id` moved from the query into the body), Google Chat;
 *   at most {@link NOTIFY_MAX_CHANGES} change lines, each message within its service's limit
 *   ({@link NOTIFY_TEXT_LIMITS}), every untrusted value unable to mention, ping or link;
 * - `json` for any other URL: `{ tool, version, command, title, text, startedAt, finishedAt, run,
 *   baseline, counts, changes (≤ 500), changesTotal }`, signed with HMAC-SHA256 when
 *   DOMAINSCOPE_NOTIFY_SECRET is set ({@link signBody});
 * - `pagerduty` (Events API v2): one `trigger` per counted bad change, keyed by
 *   {@link dedupKey}, and a `resolve` once the report shows its problem over
 *   ({@link pagerDutyPlan}, tools/ds/states.mjs); the report keeps the keys still open
 *   (`notify.open`, as delivered: {@link keysOpenAfter}) for the next run;
 * - `ntfy`: plain text (≤ {@link NTFY_MAX_BYTES} bytes) with Title, Priority and Tags headers, and
 *   DOMAINSCOPE_NTFY_TOKEN as a bearer token.
 *
 * A webhook URL is a credential: it is never printed, written or sent anywhere but to itself
 * (errors name its host only, and every answer is redacted: {@link redactUrl}). HTTPS only, but
 * to this machine (localhost, 127.0.0.0/8, [::1]).
 *
 * Pure apart from the injected `fetchImpl` (and the timer of the one retry, injectable too).
 */

import { createHash, createHmac } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';
import { problemStanding, pagedState } from './states.mjs';
import { cleanText, utcStamp } from '../../assets/js/lib/summary.js';

/** `--notify-format`: auto follows each URL ({@link detectNotifyFormat}). */
export const NOTIFY_FORMATS = Object.freeze(['auto', 'slack', 'teams', 'discord', 'telegram', 'googlechat', 'json', 'pagerduty', 'ntfy']);
/**
 * Message text per format, the CLI's _NOTIFY_TEXT_LIMITS: Discord allows 2,000 characters, Telegram
 * 4,096; Slack, Teams and Google Chat take more, but a longer chat message is not read either.
 */
export const NOTIFY_TEXT_LIMITS = Object.freeze({ slack: 3500, teams: 3500, discord: 1800, telegram: 3900, googlechat: 3500, json: 3500 });
/** Change lines in a chat message (the JSON format has them all, up to {@link NOTIFY_MAX_JSON_CHANGES}). */
export const NOTIFY_MAX_CHANGES = 20;
export const NOTIFY_MAX_JSON_CHANGES = 500;
/** Every line of a message is cut at this many characters. */
export const NOTIFY_LINE_LIMIT = 400;
/** Per attempt; one retry after {@link NOTIFY_RETRY_DELAY_MS} (or a 429's Retry-After, at most 10 s). */
export const NOTIFY_TIMEOUT_MS = 10000;
export const NOTIFY_RETRY_DELAY_MS = 2000;
const MAX_RETRY_AFTER_MS = 10000;
/** PagerDuty: events a run sends to one URL (triggers first), the summary's length, the keys kept open. */
export const PAGERDUTY_MAX_EVENTS = 50;
export const PAGERDUTY_SUMMARY_LIMIT = 1024;
export const PAGERDUTY_MAX_OPEN = 500;
/** ntfy: a longer message is turned into an attachment. */
export const NTFY_MAX_BYTES = 4000;
/** The tags whose PagerDuty severity is `critical` (also any change whose `after` says critical); `error` otherwise. */
export const CRITICAL_TAGS = Object.freeze(['REGISTRAR', 'NS', 'DS', 'LOCK', 'EXPIRED', 'UNTRUSTED']);
/**
 * The same problems as today's commands report them, by item: health's registration expired,
 * held or being deleted and DNSSEC broken; drift's name servers; the audit's registrar, transfer
 * lock, registry status, DNSSEC and expiry rules (also a domain added that fails one). And ct's
 * certificate in use revoked (REVOKED), tls's too (a revoked certificate still served) and a
 * served certificate that turned expired or untrusted.
 */
export const CRITICAL_ITEMS = Object.freeze({
  health: Object.freeze(['rdap.expired', 'rdap.hold', 'rdap.pending-delete', 'dnssec.broken']),
  drift: Object.freeze(['NS']),
  audit: Object.freeze(['registrar', 'transferLock', 'status.critical', 'dnssec', 'expiryDays', 'nsExpiryDays'])
});
/** The environment the runner reads (the nightly template sets them from Actions secrets; empty is unset). */
export const NOTIFY_ENV = Object.freeze({
  url: 'DOMAINSCOPE_NOTIFY_URL', bad: 'DOMAINSCOPE_NOTIFY_BAD_URL', secret: 'DOMAINSCOPE_NOTIFY_SECRET', ntfyToken: 'DOMAINSCOPE_NTFY_TOKEN'
});
/** What a target of each command is, for the message's footer. */
const TARGET_NOUNS = Object.freeze({
  health: 'domain', subdomains: 'domain', drift: 'zone', ct: 'domain', renew: 'name', dane: 'certificate', audit: 'domain', tls: 'host', takeover: 'domain'
});

const DISCORD_HOSTS = new Set(['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com']);
const TEAMS_HOSTS = new Set(['outlook.office.com', 'outlook.office365.com']);
// Teams incoming webhooks, Power Automate / Logic Apps workflow triggers
const TEAMS_SUFFIXES = ['.webhook.office.com', '.logic.azure.com', '.api.powerplatform.com'];
const PAGERDUTY_HOSTS = new Set(['events.pagerduty.com', 'events.eu.pagerduty.com']);
const NTFY_HOSTS = new Set(['ntfy.sh']);
const TELEGRAM_PATH = /^\/bot[^/]+\/sendMessage$/;
const DISCORD_PATH = /^\/api\/(?:v\d{1,2}\/)?webhooks\//; // also /api/v10/webhooks/
// Path words of the webhook services: not secrets, kept in error texts.
const PATH_WORDS = new Set(['api', 'automations', 'direct', 'enqueue', 'hook', 'hooks', 'incomingwebhook', 'invoke', 'manual', 'messages', 'paths',
  'powerautomate', 'sendmessage', 'services', 'slack', 'spaces', 'triggers', 'webhook', 'webhookb2', 'webhooks', 'workflows']);
const API_VERSION = /^v\d{1,2}$/; // /api/v10/, /v2/enqueue: not a token either
const DEDUP_KEY = /^[0-9a-f]{32}$/;
const TAG = /^[A-Z][A-Z0-9_-]{0,23}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\s\u0000-\u001f\u007f-\u009f]/;

/* ------------------------------------------------------------------------ */
/* URLs                                                                     */
/* ------------------------------------------------------------------------ */

/** A URL, or null for text that is none. */
function parse(url) {
  try {
    return new URL(String(url));
  } catch {
    return null;
  }
}

/** A URL's host name as compared: lowercase (the URL parser's), without brackets or a final dot. */
const hostOf = (u) => u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');

const decode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

/**
 * The payload a webhook URL expects (the CLI's detect_notify_format): `slack` (hooks.slack.com,
 * and Discord's Slack-compatible `…/slack` endpoint), `discord` (`/api/webhooks/`, also with an
 * API version), `telegram` (api.telegram.org), `teams` (Teams incoming webhooks, Power Automate /
 * Logic Apps workflows), `googlechat` (chat.googleapis.com), `pagerduty` (events.pagerduty.com,
 * events.eu.pagerduty.com), `ntfy` (ntfy.sh; a self-hosted server needs --notify-format ntfy) or
 * `json` for anything else.
 * @param {string} url
 * @returns {string}
 */
export function detectNotifyFormat(url) {
  const u = parse(url);
  if (!u) return 'json';
  const host = hostOf(u);
  if (host === 'hooks.slack.com' || host === 'hooks.slack-gov.com') return 'slack';
  if (DISCORD_HOSTS.has(host) && DISCORD_PATH.test(u.pathname)) return u.pathname.replace(/\/+$/, '').endsWith('/slack') ? 'slack' : 'discord';
  if (host === 'api.telegram.org') return 'telegram';
  if (TEAMS_HOSTS.has(host) || TEAMS_SUFFIXES.some((s) => host.endsWith(s))) return 'teams';
  if (host === 'chat.googleapis.com') return 'googlechat';
  if (PAGERDUTY_HOSTS.has(host)) return 'pagerduty';
  if (NTFY_HOSTS.has(host)) return 'ntfy';
  return 'json';
}

/** A Telegram `chat_id` as the Bot API takes it: a number when it is a safe one, else the text (`@channel`). */
function telegramChatId(u) {
  const value = u.searchParams.get('chat_id');
  if (!value) return null;
  return /^-?\d{1,20}$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : value;
}

/** Is this host this machine: localhost, 127.0.0.0/8 or ::1? */
function loopback(host) {
  return host === 'localhost' || /^127(?:\.\d{1,3}){3}$/.test(host) || host === '::1';
}

/**
 * Why a notification URL is refused, or null — never repeating the URL, which holds the
 * webhook's secret: not a URL, not https:// (http:// only to this machine), a Telegram URL
 * without `/bot…/sendMessage` and `chat_id`, a PagerDuty URL without `routing_key`.
 * @param {string} url
 * @param {string} format the format it will be sent in (not `auto`)
 * @returns {string|null}
 */
export function notifyUrlProblem(url, format) {
  const text = String(url ?? '');
  if (CONTROL.test(text)) return 'the URL contains spaces or control characters';
  const u = parse(text);
  if (!u) return 'not a valid URL';
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || !u.hostname) return 'needs an https:// URL';
  if (u.protocol === 'http:' && !loopback(hostOf(u))) {
    return 'needs an https:// URL: the webhook URL works as a password, and http:// would send it unencrypted (http:// only to this machine: localhost, 127.0.0.1, [::1])';
  }
  if (format === 'telegram' && !(TELEGRAM_PATH.test(u.pathname) && telegramChatId(u) !== null)) {
    return 'a Telegram URL looks like https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat id>';
  }
  if (format === 'pagerduty' && !u.searchParams.get('routing_key')) {
    return 'a PagerDuty URL looks like https://events.pagerduty.com/v2/enqueue?routing_key=<integration key>';
  }
  return null;
}

/**
 * The webhook's host (and port): all of the URL that is ever printed.
 * @param {string} url
 * @returns {string}
 */
export function notifyHost(url) {
  const u = parse(url);
  if (!u) return '?';
  return cleanText(`${u.hostname}${u.port ? `:${u.port}` : ''}`) || '?';
}

/**
 * The URL to send to, without its user info, and the Basic `Authorization` value made of it
 * (fetch refuses a URL with credentials; the CLI's split_credentials).
 * @param {string} url
 * @returns {{ url: string, authorization: string|null }}
 */
export function splitCredentials(url) {
  const u = parse(url);
  if (!u || (!u.username && !u.password)) return { url: u ? u.href : String(url), authorization: null };
  const token = `${decode(u.username)}:${decode(u.password)}`;
  u.username = '';
  u.password = '';
  return { url: u.href, authorization: `Basic ${Buffer.from(token, 'utf8').toString('base64')}` };
}

/** A path segment that may be a token: 8 or more characters or a digit, not a path word or an API version. */
const secretSegment = (segment) => !PATH_WORDS.has(segment.toLowerCase()) && !API_VERSION.test(segment) && (segment.length >= 8 || /\d/.test(segment));

/** How a secret path segment may be written: as in the URL, decoded, encoded; Telegram's `bot<token>` also the token and its part after the `:`. */
function segmentForms(segment) {
  const plain = decode(segment);
  const tokens = [plain];
  if (plain.slice(0, 3).toLowerCase() === 'bot' && plain.includes(':')) tokens.push(plain.slice(3), plain.slice(plain.indexOf(':') + 1));
  return [segment, ...tokens.filter(Boolean).flatMap((tok) => [tok, encodeURIComponent(tok)])];
}

/**
 * The texts {@link redactUrl} takes out of a text for `url` and `extra`, longest first.
 * @param {string} url
 * @param {string[]} [extra]
 * @returns {string[]}
 */
function secretsOf(url, extra = []) {
  const raw = String(url ?? '');
  const secrets = new Set([raw]);
  const always = new Set(extra.filter(Boolean).map(String));
  const u = parse(raw);
  if (u) {
    const { url: target, authorization } = splitCredentials(raw);
    const path = u.pathname;
    const query = u.search.replace(/^\?/, '');
    const hash = u.hash.replace(/^#/, '');
    for (const s of [u.href, target, path, query, hash, decode(path), decode(query), decode(hash)]) secrets.add(s);
    // the path and query as typed too: the parser percent-encodes what the text did not
    const typed = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i.exec(raw);
    if (typed) for (const s of typed.slice(1)) if (s) secrets.add(s);
    for (const segment of path.split('/')) if (secretSegment(decode(segment))) for (const f of segmentForms(segment)) secrets.add(f);
    for (const [, value] of u.searchParams) secrets.add(value);
    for (const pair of query.split('&')) secrets.add(pair.slice(pair.indexOf('=') + 1));
    if (u.username || u.password) {
      secrets.add(u.username);
      secrets.add(decode(u.username));
      // the password however short — or the user name when it is the only credential
      for (const s of u.password ? [u.password, decode(u.password)] : [u.username, decode(u.username)]) always.add(s);
    }
    if (authorization) {
      always.add(authorization);
      always.add(authorization.slice(6));
    }
  }
  return [...new Set([...[...secrets].filter((s) => s.length >= 4), ...[...always].filter(Boolean)])].sort((a, b) => b.length - a.length);
}

/**
 * `text` without `secrets` (longest first). `cut`: the text is the start of a longer one, so it
 * may end inside a secret — whatever it ends with that begins a secret goes too.
 * @param {string} text
 * @param {string[]} secrets {@link secretsOf}
 * @param {boolean} [cut]
 * @returns {string}
 */
function redactWith(text, secrets, cut = false) {
  let out = String(text ?? '');
  for (const secret of secrets) out = out.split(secret).join('***');
  if (!cut) return out;
  out = out.replace(/\uFFFD+$/, ''); // a character cut in two
  let strip = 0;
  for (const secret of secrets) {
    for (let n = Math.min(secret.length - 1, out.length); n > strip; n -= 1) {
      if (out.endsWith(secret.slice(0, n))) {
        strip = n;
        break;
      }
    }
  }
  return out.slice(0, out.length - strip);
}

/**
 * `text` (an error message, an answer's body) without the secret parts of `url` (the CLI's
 * redact_url): the URL as given and as sent, its path, query and fragment, the query values, the
 * path segments that may be tokens, the user name and password and the Basic value made of them,
 * and `extra` (the ntfy token, the signing secret).
 * @param {string} text
 * @param {string} url
 * @param {string[]} [extra]
 * @returns {string}
 */
export function redactUrl(text, url, extra = []) {
  return redactWith(text, secretsOf(url, extra));
}

/**
 * The GitHub Actions run (`$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID`), or
 * null outside one.
 * @param {Record<string, string|undefined>} env
 * @returns {string|null}
 */
export function runUrl(env = {}) {
  const server = String(env.GITHUB_SERVER_URL || '').trim().replace(/\/+$/, '');
  const repo = String(env.GITHUB_REPOSITORY || '').trim();
  const id = String(env.GITHUB_RUN_ID || '').trim();
  if (!/^https:\/\/[\x21-\x7e]+$/.test(server) || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !/^\d+$/.test(id)) return null;
  return `${server}/${repo}/actions/runs/${id}`;
}

/* ------------------------------------------------------------------------ */
/* Routes                                                                   */
/* ------------------------------------------------------------------------ */

/** A notification setting the runner refuses (exit 2); the message never holds a URL. */
export class NotifyConfigError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'NotifyConfigError';
  }
}

const ordinal = (i, n) => (n > 1 ? ` (URL ${i + 1} of ${n})` : '');

/**
 * The URLs of one option, or of its environment variable when the command line gives none, each
 * with its format, checked ({@link notifyUrlProblem}).
 * @param {string[]} given the option's values
 * @param {string} option '--notify'
 * @param {string} envName
 * @param {Record<string, string|undefined>} env
 * @param {string} format NOTIFY_FORMATS
 * @param {boolean} bad
 * @returns {Array<{ url: string, format: string, bad: boolean, source: string }>}
 */
function routesOf(given, option, envName, env, format, bad) {
  const fromLine = (given || []).length > 0;
  const urls = fromLine ? given.map(String) : String(env[envName] || '').split(/\s+/).filter(Boolean);
  const source = fromLine ? option : envName;
  return urls.map((url, i) => {
    if (fromLine && !url.trim()) throw new NotifyConfigError(`${option} needs a URL`);
    const chosen = format === 'auto' ? detectNotifyFormat(url) : format;
    const problem = notifyUrlProblem(url, chosen);
    if (problem) throw new NotifyConfigError(`${source}${ordinal(i, urls.length)}: ${problem}`);
    return { url, format: chosen, bad, source };
  });
}

/**
 * Where this run posts: the `--notify` URLs (else those of DOMAINSCOPE_NOTIFY_URL, separated by
 * whitespace) and the `--notify-bad` ones (else DOMAINSCOPE_NOTIFY_BAD_URL), each in its format.
 * A URL given twice is posted to once (on the --notify route when it is on both). No URL, no
 * route: --notify-format, --notify-always and --fail-on-notify-error then change nothing, so a
 * scheduled job can pass them whether or not its secrets are set.
 * @param {{ notify?: string[], notifyBad?: string[], notifyFormat?: string }} options
 * @param {Record<string, string|undefined>} env
 * @returns {Array<{ url: string, format: string, bad: boolean, source: string }>}
 * @throws {NotifyConfigError}
 */
export function notifyRoutes(options, env = {}) {
  const format = options.notifyFormat || 'auto';
  // the value is never quoted back: it may be a webhook URL given to the wrong option
  if (!NOTIFY_FORMATS.includes(format)) throw new NotifyConfigError(`--notify-format takes ${NOTIFY_FORMATS.join(', ')}`);
  const all = [
    ...routesOf(options.notify, '--notify', NOTIFY_ENV.url, env, format, false),
    ...routesOf(options.notifyBad, '--notify-bad', NOTIFY_ENV.bad, env, format, true)
  ];
  const seen = new Set();
  const routes = all.filter((r) => !seen.has(r.url) && seen.add(r.url));
  const token = String(env[NOTIFY_ENV.ntfyToken] || '').trim();
  if (token && routes.some((r) => r.format === 'ntfy') && !/^[\x21-\x7e]+$/.test(token)) {
    throw new NotifyConfigError(`${NOTIFY_ENV.ntfyToken}: not an access token (printable ASCII, no spaces)`);
  }
  return routes;
}

/* ------------------------------------------------------------------------ */
/* Messages                                                                 */
/* ------------------------------------------------------------------------ */

/** `text` cut at `limit` UTF-16 units, never inside a surrogate pair. */
function cut(text, limit) {
  let n = Math.max(0, limit);
  if (n > 0 && n < text.length && /[\ud800-\udbff]/.test(text[n - 1])) n -= 1;
  return text.slice(0, n);
}

/** A line cut at `limit` characters with '...' (the CLI's _clip). */
export function clip(line, limit = NOTIFY_LINE_LIMIT) {
  const s = String(line);
  return s.length <= limit ? s : `${cut(s, limit - 3)}...`;
}

/** UTF-8 bytes of a text. */
export const byteLength = (s) => Buffer.byteLength(String(s), 'utf8');

/**
 * `items` then `footer`, as many items as fit in `limit` (characters, or what `measure` counts)
 * with the title; the rest counted in a last "... and N more" line. Every line is cut at
 * {@link NOTIFY_LINE_LIMIT} characters, the footer's too (the CLI's _fit_lines).
 * @param {string} title
 * @param {string[]} items
 * @param {string[]} footer
 * @param {number} limit
 * @param {(s: string) => number} [measure]
 * @returns {string[]}
 */
export function fitLines(title, items, footer, limit, measure = (s) => s.length) {
  const foot = footer.map((l) => clip(l));
  let budget = limit - measure(title) - foot.reduce((n, l) => n + measure(l) + 1, 0) - 60;
  const out = [];
  for (const [i, raw] of items.entries()) {
    const line = clip(raw);
    if (measure(line) + 1 > budget) {
      const more = items.length - i;
      out.push(`- ... and ${more} more line${more === 1 ? '' : 's'} - see the --json report`);
      break;
    }
    out.push(line);
    budget -= measure(line) + 1;
  }
  return [...out, ...foot];
}

const when = (iso) => utcStamp(iso) || 'an unknown time';
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * What a route says about a run: the title, one line per change it carries (at most
 * {@link NOTIFY_MAX_CHANGES}, then how many more), the footer (the run, its targets, the run's
 * link); `carried` are the changes it is about (the --notify route: those that count; the
 * --notify-bad route: those that count and are bad), `bad`: whether any of them is bad.
 * @param {object} report the run's report (tools/ds.mjs): `command`, `startedAt`, `targets`, and with
 *   --baseline `baseline` and `changes` (`{ tag, tone, counts, target, item, kind, before, after, text }`)
 * @param {{ bad: boolean }} route
 * @param {{ run?: string|null }} [ctx]
 * @returns {{ title: string, items: string[], footer: string[], carried: object[], bad: boolean }}
 */
export function notificationMessage(report, route, { run = null } = {}) {
  const command = cleanText(report.command);
  const changes = Array.isArray(report.changes) ? report.changes : [];
  const counted = changes.filter((c) => c && c.counts === true);
  const carried = route.bad ? counted.filter((c) => c.tone === 'bad') : counted;
  const info = report.baseline || null;
  const what = route.bad ? 'bad change' : 'change';
  let title;
  if (!info) title = `DomainScope ${command}: finished`;
  else if (info.missing) title = `DomainScope ${command}: first run, no baseline to compare yet`;
  else if (carried.length) title = `DomainScope ${command}: ${plural(carried.length, what)} since ${when(info.finishedAt)}`;
  else title = `DomainScope ${command}: no ${what}s since ${when(info.finishedAt)}`;
  const items = carried.slice(0, NOTIFY_MAX_CHANGES).map((c) => `- ${cleanText(c.tag)} ${cleanText(c.text)}`);
  if (carried.length > NOTIFY_MAX_CHANGES) items.push(`- ... and ${carried.length - NOTIFY_MAX_CHANGES} more changes`);
  const targets = (report.targets || []).map((x) => (x && typeof x.target === 'string' ? cleanText(x.target) : null)).filter(Boolean);
  const named = targets.slice(0, 3).join(', ') + (targets.length > 3 ? ` +${targets.length - 3}` : '');
  const quiet = route.bad ? 0 : changes.length - counted.length;
  const footer = [`Run of ${when(report.startedAt)}: ${plural(targets.length, TARGET_NOUNS[report.command] || 'target')}${named ? ` (${named})` : ''}`
    + `${quiet ? `; ${plural(quiet, 'change')} listed only (not counted)` : ''}.`];
  if (run) footer.push(`Run: ${run}`);
  return { title, items, footer, carried, bad: carried.some((c) => c.tone === 'bad') };
}

// Slack reads <...> as links and mentions (<!channel>): a certificate CN must not ping.
const slackEscape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// The body goes into a ``` code block (no markdown, no mention inside): a backtick must not close it.
const noBackticks = (s) => s.replace(/`/g, 'ˋ');
// Google Chat reads <users/all> as a mention and does not document decoding &lt;: a lookalike instead.
const noAngleBrackets = (s) => s.replace(/</g, '‹');

/** A plain Adaptive Card: TextRuns are never read as markdown, unlike TextBlocks (the CLI's _teams_card). */
function teamsCard(title, lines) {
  const body = [{ type: 'RichTextBlock', inlines: [{ type: 'TextRun', text: title, weight: 'Bolder', size: 'Medium' }] }];
  for (const line of lines) if (line) body.push({ type: 'RichTextBlock', spacing: 'None', inlines: [{ type: 'TextRun', text: line }] });
  return {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      contentUrl: null,
      content: { $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.2', msteams: { width: 'Full' }, body }
    }]
  };
}

/** A change as the JSON format carries it. */
const changeEntry = (c) => ({
  tag: c.tag, tone: c.tone, counts: c.counts, target: c.target, item: c.item ?? null, text: c.text, before: c.before ?? null, after: c.after ?? null
});

/**
 * `sha256=` and the hex HMAC-SHA256 of `timestamp + "." + body` with the secret: the
 * X-DomainScope-Signature of a signed JSON message (X-DomainScope-Timestamp carries `timestamp`).
 * A receiver computes the same over the raw body it got and compares in constant time, and
 * refuses an old timestamp (a replay).
 * @param {string} secret
 * @param {string|number} timestamp unix seconds
 * @param {string|Uint8Array} body the exact bytes sent
 * @returns {string}
 */
export function signBody(secret, timestamp, body) {
  return `sha256=${createHmac('sha256', String(secret)).update(`${timestamp}.`).update(body).digest('hex')}`;
}

/** A header value fetch takes as it is (ASCII), else RFC 2047 encoded (ntfy decodes it). */
function headerText(text) {
  return /^[\x20-\x7e]*$/.test(text) ? text : `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

/**
 * The request of a chat, JSON or ntfy route: `{ url, headers, body }`, the URL without the parts
 * that go into the body (Telegram's `chat_id`) or a header (user info).
 * @param {{ url: string, format: string, bad: boolean }} route
 * @param {object} report
 * @param {{ run?: string|null, env?: object, now?: () => Date, tool: string, version: string }} ctx
 * @returns {{ url: string, headers: Record<string, string>, body: string, secrets: string[] }}
 */
export function buildRequest(route, report, ctx) {
  const { run = null, env = {}, now = () => new Date(), tool, version } = ctx;
  const msg = notificationMessage(report, route, { run });
  const { url, authorization } = splitCredentials(route.url);
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'User-Agent': `${tool}/${version} (+https://github.com/halilibrahimd27/domainscope)` };
  if (authorization) headers.Authorization = authorization;
  const secrets = [];
  if (route.format === 'ntfy') {
    const token = String(env[NOTIFY_ENV.ntfyToken] || '').trim();
    if (token && !authorization) {
      headers.Authorization = `Bearer ${token}`;
      secrets.push(token);
    }
    // the topic is the password of a public ntfy server: whoever knows it reads the messages
    secrets.push(...new URL(url).pathname.split('/').map(decode).filter((s) => s.length >= 4));
    const lines = fitLines('', msg.items, msg.footer, NTFY_MAX_BYTES, byteLength);
    let body = lines.join('\n');
    while (byteLength(body) > NTFY_MAX_BYTES) body = cut(body, body.length - 1); // a footer line of wide characters
    return {
      url,
      headers: {
        ...headers, 'Content-Type': 'text/plain; charset=utf-8', Title: headerText(msg.title), Priority: msg.bad ? '4' : '3', Tags: 'warning',
        ...(run && /^[\x21-\x7e]+$/.test(run) ? { Click: run } : {})
      },
      body,
      secrets
    };
  }
  const lines = fitLines(msg.title, msg.items, msg.footer, NOTIFY_TEXT_LIMITS[route.format] || NOTIFY_TEXT_LIMITS.json);
  const text = lines.join('\n');
  let payload;
  let target = url;
  switch (route.format) {
    case 'slack':
      payload = { text: `*${slackEscape(msg.title)}*\n\`\`\`\n${slackEscape(noBackticks(text))}\n\`\`\`` };
      break;
    case 'discord':
      payload = { content: `**${msg.title}**\n\`\`\`\n${noBackticks(text)}\n\`\`\``, allowed_mentions: { parse: [] } };
      break;
    case 'teams':
      payload = teamsCard(msg.title, lines);
      break;
    case 'googlechat':
      payload = { text: `*${noAngleBrackets(msg.title)}*\n\`\`\`\n${noAngleBrackets(noBackticks(text))}\n\`\`\`` };
      break;
    case 'telegram': {
      const u = new URL(url);
      const chatId = telegramChatId(u);
      u.searchParams.delete('chat_id');
      u.hash = '';
      target = u.href;
      payload = { chat_id: chatId, text: `${msg.title}\n\n${text}`, link_preview_options: { is_disabled: true } };
      break;
    }
    default: {
      const changes = Array.isArray(report.changes) ? report.changes : [];
      const counted = changes.filter((c) => c && c.counts === true);
      const listed = route.bad ? msg.carried : changes;
      const info = report.baseline || null;
      payload = {
        tool, version, command: report.command, title: msg.title, text: `${msg.title}\n${text}`,
        startedAt: report.startedAt ?? null, finishedAt: report.finishedAt ?? null, run,
        baseline: info ? { file: info.file ?? null, missing: !!info.missing, finishedAt: info.finishedAt ?? null } : null,
        counts: { changes: changes.length, counted: counted.length, bad: counted.filter((c) => c.tone === 'bad').length },
        changes: listed.slice(0, NOTIFY_MAX_JSON_CHANGES).map(changeEntry),
        changesTotal: listed.length
      };
    }
  }
  const body = JSON.stringify(payload);
  const secret = String(env[NOTIFY_ENV.secret] || '').trim();
  if (route.format === 'json' && secret) {
    const timestamp = String(Math.floor(now().getTime() / 1000));
    headers['X-DomainScope-Timestamp'] = timestamp;
    headers['X-DomainScope-Signature'] = signBody(secret, timestamp, body);
    secrets.push(secret);
  }
  return { url: target, headers, body, secrets };
}

/* ------------------------------------------------------------------------ */
/* PagerDuty                                                                */
/* ------------------------------------------------------------------------ */

/**
 * A PagerDuty dedup_key: the first 32 hex characters of the SHA-256 of `command|target|item|tag`
 * (no item: an empty one). The same problem keeps its key from run to run.
 * @param {string} command
 * @param {string} target
 * @param {string|null} item
 * @param {string} tag
 * @returns {string}
 */
export function dedupKey(command, target, item, tag) {
  return createHash('sha256').update(`${command}|${target}|${item ?? ''}|${tag}`).digest('hex').slice(0, 32);
}

/**
 * A bad change's PagerDuty severity: `critical` for {@link CRITICAL_TAGS} (registrar, name
 * servers, DS, a lock removed, expired, untrusted), for the items of `command` that are the same
 * problems ({@link CRITICAL_ITEMS}; an audit domain added: one of them among the rules it fails),
 * for ct's and tls's REVOKED, for tls's endpoint that turned EXPIRED or UNTRUSTED and for a change
 * whose `after` says critical (a critical takeover risk), `error` for every other.
 * @param {{ tag: string, item?: string|null, after?: any }} change
 * @param {string|null} [command]
 * @returns {'critical'|'error'}
 */
export function eventSeverity(change, command = null) {
  if (CRITICAL_TAGS.includes(change.tag)) return 'critical';
  const items = Object.prototype.hasOwnProperty.call(CRITICAL_ITEMS, command) ? CRITICAL_ITEMS[command] : [];
  const a = change.after;
  if (typeof change.item === 'string' && items.includes(change.item)) return 'critical';
  if (command === 'audit' && (change.item ?? null) === null && Array.isArray(a) && a.some((id) => items.includes(id))) return 'critical';
  if ((command === 'ct' || command === 'tls') && change.tag === 'REVOKED') return 'critical';
  if (command === 'tls' && (a === 'EXPIRED' || a === 'UNTRUSTED')) return 'critical';
  if (a === 'critical' || (a && typeof a === 'object' && (a.severity === 'critical' || a.risk === 'critical'))) return 'critical';
  return 'error';
}

/** A key's paged state as a report keeps it: a short text or a number. */
const isState = (v) => (typeof v === 'string' && v.length > 0 && v.length <= 64) || Number.isFinite(v);

/**
 * The PagerDuty keys a baseline left open (its `notify.open`), each checked: `{ key, target,
 * item, tag, since, state?, over? }` (`state`: what its item was paged at, tools/ds/states.mjs
 * pagedState). Anything else in the list is dropped (it only ever loses a resolve), a `state`
 * that is not a short text or a number too (the key is then over only once its item is fully
 * good).
 * @param {object|null} doc a report
 * @returns {Array<{ key: string, target: string, item: string|null, tag: string, since: string|null, state?: string|number, over?: true }>}
 */
export function openKeysOf(doc) {
  const list = doc && doc.notify && typeof doc.notify === 'object' && Array.isArray(doc.notify.open) ? doc.notify.open : [];
  const out = [];
  const seen = new Set();
  for (const e of list) {
    if (!e || typeof e !== 'object' || !DEDUP_KEY.test(String(e.key)) || typeof e.target !== 'string' || !TAG.test(String(e.tag))) continue;
    if (!(e.item === null || e.item === undefined || typeof e.item === 'string') || seen.has(e.key)) continue;
    seen.add(e.key);
    out.push({
      key: e.key, target: e.target, item: e.item ?? null, tag: e.tag, since: typeof e.since === 'string' ? e.since : null,
      ...(isState(e.state) ? { state: e.state } : {}), ...(e.over === true ? { over: true } : {})
    });
  }
  return out;
}

/**
 * Is the problem of an open key over, by what this run's report says? Its target is no longer
 * checked, or the report shows its item better than it was paged at, or out of what the run
 * checks (tools/ds/states.mjs problemStanding: a finding's severity, a host's answer, a
 * certificate renewed, a record set's status, a verdict, an endpoint's status, a rule). Never
 * because another change came by: a lookup that failed, a source or a record set not read says
 * nothing, and the key stays open. A command without a rule there: a counted good change of the
 * same target and item, or the item back after it was GONE.
 * @param {{ target: string, item: string|null, tag: string, state?: string|number }} e
 * @param {object} report
 * @returns {boolean}
 */
export function problemOver(e, report) {
  const target = (report.targets || []).find((x) => x && x.target === e.target);
  if (!target) return true;
  const standing = problemStanding(report.command, target, e);
  if (standing !== null) return standing === 'over';
  return (report.changes || []).some((c) => c && c.counts === true && c.target === e.target && (c.item ?? null) === e.item
    && (c.tone === 'good' || (c.tag === 'NEW' && e.tag === 'GONE')));
}

/**
 * What this run sends to PagerDuty and the keys it leaves open: a trigger per counted bad change
 * (one per key, in the changes' order; a new key keeps the state its item is paged at), a resolve
 * per open key whose problem is over ({@link problemOver}) or whose resolve a run could not send
 * yet (`over`). At most `max` events: triggers first; the triggers left out are not sent (`cut`),
 * the resolves left out stay open with `over` and go out with the next run. `kept`, `deferred`
 * and `added` are the parts of `open` ({@link keysOpenAfter}): the baseline's keys still open (a
 * key triggered again keeps its `since` and `state`), those whose resolve waits, the new ones —
 * `open`, as if every event were delivered.
 * @param {object} report this run's report
 * @param {object|null} baseline
 * @param {{ max?: number }} [opts]
 * @returns {{ triggers: Array<{ key: string, change: object }>, resolves: object[], cut: number, open: object[],
 *   kept: object[], deferred: object[], added: object[] }}
 */
export function pagerDutyPlan(report, baseline, { max = PAGERDUTY_MAX_EVENTS } = {}) {
  const triggered = new Map();
  for (const c of report.changes || []) {
    if (!c || c.counts !== true || c.tone !== 'bad') continue;
    const key = dedupKey(report.command, c.target, c.item ?? null, c.tag);
    if (!triggered.has(key)) triggered.set(key, c);
  }
  const open = openKeysOf(baseline);
  const kept = [];
  const ending = [];
  for (const e of open) {
    if (triggered.has(e.key)) {
      const { over, ...still } = e;
      kept.push(still);
    } else if (e.over || problemOver(e, report)) ending.push(e);
    else kept.push(e);
  }
  const triggers = [...triggered].slice(0, Math.max(0, max)).map(([key, change]) => ({ key, change }));
  const resolves = ending.slice(0, Math.max(0, max - triggers.length));
  const deferred = ending.slice(resolves.length).map((e) => ({ ...e, over: true }));
  const known = new Set(open.map((e) => e.key));
  const added = triggers.filter((t) => !known.has(t.key)).map(({ key, change }) => {
    const state = pagedState(report.command, change);
    return { key, target: change.target, item: change.item ?? null, tag: change.tag, since: report.startedAt ?? null, ...(state === null ? {} : { state }) };
  });
  const plan = { triggers, resolves, cut: triggered.size - triggers.length, kept, deferred, added };
  return { ...plan, open: keysOpenAfter(plan) };
}

/**
 * The PagerDuty keys open after a run, by what was delivered: the baseline's keys still open,
 * those whose resolve was not delivered (as they were: the next run decides again), those whose
 * resolve waits for the event budget (`over`), and the new keys whose trigger was delivered — at
 * most {@link PAGERDUTY_MAX_OPEN}, the oldest dropped.
 * @param {{ kept: object[], resolves: object[], deferred: object[], added: object[] }} plan {@link pagerDutyPlan}
 * @param {{ triggered?: Set<string>|null, resolved?: Set<string>|null }} [delivered] the keys of the
 *   triggers and the resolves delivered (null: all of them)
 * @returns {object[]}
 */
export function keysOpenAfter(plan, { triggered = null, resolved = null } = {}) {
  const sent = (set, key) => !set || set.has(key);
  const next = [
    ...plan.kept,
    ...plan.resolves.filter((e) => !sent(resolved, e.key)),
    ...plan.deferred,
    ...plan.added.filter((e) => sent(triggered, e.key))
  ];
  return next.slice(Math.max(0, next.length - PAGERDUTY_MAX_OPEN));
}

/**
 * The Events API v2 requests of a PagerDuty route for a plan: the triggers, then the resolves, to
 * the URL without its `routing_key` (it goes into each event).
 * @param {{ url: string }} route
 * @param {object} report
 * @param {{ triggers: object[], resolves: object[] }} plan
 * @param {{ run?: string|null, tool: string, version: string }} ctx
 * @returns {Array<{ url: string, headers: Record<string, string>, body: string, secrets: string[], action: string, key: string }>}
 */
export function pagerDutyRequests(route, report, plan, { run = null, tool, version }) {
  const { url, authorization } = splitCredentials(route.url);
  const u = new URL(url);
  const routingKey = u.searchParams.get('routing_key');
  u.searchParams.delete('routing_key');
  u.hash = '';
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'User-Agent': `${tool}/${version} (+https://github.com/halilibrahimd27/domainscope)` };
  if (authorization) headers.Authorization = authorization;
  const command = cleanText(report.command);
  const request = (event, action) => ({ url: u.href, headers, body: JSON.stringify(event), secrets: [routingKey], action, key: event.dedup_key });
  return [
    ...plan.triggers.map(({ key, change }) => request({
      routing_key: routingKey,
      event_action: 'trigger',
      dedup_key: key,
      payload: {
        summary: clip(`${cleanText(change.tag)} ${cleanText(change.text)}`, PAGERDUTY_SUMMARY_LIMIT),
        source: `domainscope:${command}`,
        severity: eventSeverity(change, report.command),
        component: change.target,
        group: command,
        custom_details: { tag: change.tag, item: change.item ?? null, before: change.before ?? null, after: change.after ?? null, run }
      },
      client: 'DomainScope',
      ...(run ? { client_url: run } : {})
    }, 'trigger')),
    ...plan.resolves.map((e) => request({ routing_key: routingKey, event_action: 'resolve', dedup_key: e.key }, 'resolve'))
  ];
}

/* ------------------------------------------------------------------------ */
/* Delivery                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The reason in a webhook's error answer: Telegram's `description`, Discord's `message`, Power
 * Automate's `error.message`, else the body — `redact`ed, then on one line and cut at 200
 * characters (a secret echoed across the cut would leave its start, which no redaction finds).
 * @param {string} raw
 * @param {(text: string) => string} [redact]
 * @returns {string}
 */
export function responseDetail(raw, redact = (text) => text) {
  let text = String(raw ?? '');
  try {
    const data = JSON.parse(text);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const error = data.error && typeof data.error === 'object' ? data.error.message : data.error;
      const found = [data.description, data.message, error].find((v) => typeof v === 'string' && v.trim());
      if (found) text = found;
    }
  } catch {
    // not JSON: the body as it is
  }
  // a secret with spaces may only show once they are one
  return redact(redact(text).split(/\s+/).filter(Boolean).join(' ')).slice(0, 200);
}

/** Up to `max` bytes of an answer's body, as text; `cut`: there was more (or may have been). */
async function readSome(res, max) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    try {
      const text = await res.text();
      return { text: text.slice(0, max), cut: text.length > max };
    } catch {
      return { text: '', cut: false };
    }
  }
  const reader = res.body.getReader();
  const chunks = [];
  let n = 0;
  let ended = false;
  try {
    while (n < max) {
      const { value, done } = await reader.read();
      if (done) {
        ended = true;
        break;
      }
      chunks.push(value);
      n += value.length;
    }
  } catch {
    // what came is enough
  } finally {
    reader.cancel().catch(() => {});
  }
  return { text: Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, max).toString('utf8'), cut: n > max || !ended };
}

/** A network failure in a few words, redacted before it is cut: `timed out`, the system's reason (ECONNREFUSED, a TLS error). */
function networkText(err, redact) {
  const cause = err && err.cause;
  const text = (cause && (cause.message || cause.code)) || (err && err.message) || String(err);
  return redact(cleanText(text)).slice(0, 200) || 'failed';
}

/**
 * One POST: `{ ok }`, or `{ problem, retry, retryAfterMs }` (retry: a network error, 5xx or 429), or
 * `{ interrupted }` when the run's signal stopped it. No redirect is followed: a redirected POST
 * would arrive as a GET without the message. What the answer says is `redact`ed before it is cut.
 */
async function postOnce(request, { fetchImpl, signal, timeoutMs, redact }) {
  // A timer of its own rather than AbortSignal.timeout(), whose timer does not keep Node's event
  // loop alive: the timeout must fire whatever the fetch holds open. Cleared once the answer is read.
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(new DOMException('The operation timed out.', 'TimeoutError')), timeoutMs);
  try {
    let res;
    try {
      res = await fetchImpl(request.url, {
        method: 'POST', headers: request.headers, body: request.body, redirect: 'manual',
        signal: signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal
      });
    } catch (err) {
      if (signal && signal.aborted) return { interrupted: true };
      if (timeout.signal.aborted || (err && err.name === 'TimeoutError')) return { problem: 'timed out', retry: true };
      return { problem: networkText(err, redact), retry: true };
    }
    if (res.status >= 200 && res.status < 300) {
      if (res.body && typeof res.body.cancel === 'function') await res.body.cancel().catch(() => {});
      return { ok: true };
    }
    let text = `HTTP ${res.status} ${redact(res.statusText || '')}`.trim();
    if (res.status >= 300 && res.status < 400) text += ' (a redirect; not followed)';
    const body = await readSome(res, 512);
    const detail = responseDetail(body.text, (t) => redact(t, body.cut));
    if (detail) text += `: ${detail}`;
    const after = String((res.headers && res.headers.get('retry-after')) || '').trim();
    return { problem: text, retry: res.status >= 500 || res.status === 429, retryAfterMs: /^\d+$/.test(after) ? Number(after) * 1000 : null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * POST a request: `null` when it was delivered, else what went wrong (redacted: never the URL or
 * a secret), with `interrupted` when the run's signal stopped it. {@link NOTIFY_TIMEOUT_MS} per
 * attempt, one more attempt after {@link NOTIFY_RETRY_DELAY_MS} (a 429's Retry-After, at most
 * 10 s) for network errors, 5xx and 429 — a 4xx is the webhook's answer.
 * @param {{ url: string, headers: object, body: string, secrets?: string[] }} request
 * @param {string} routeUrl the URL as configured (for the redaction)
 * @param {{ fetchImpl: typeof fetch, signal?: AbortSignal, timeoutMs?: number, retryDelayMs?: number,
 *   retries?: number, sleep?: (ms: number, signal?: AbortSignal) => Promise<void> }} opts
 * @returns {Promise<{ problem: string, interrupted?: boolean }|null>}
 */
export async function deliver(request, routeUrl, opts) {
  const { fetchImpl, signal, timeoutMs = NOTIFY_TIMEOUT_MS, retryDelayMs = NOTIFY_RETRY_DELAY_MS, retries = 1, sleep = (ms, sig) => wait(ms, undefined, { signal: sig }) } = opts;
  const secrets = secretsOf(routeUrl, request.secrets || []);
  const redact = (text, cut = false) => redactWith(text, secrets, cut);
  for (let attempt = 0; ; attempt += 1) {
    const r = await postOnce(request, { fetchImpl, signal, timeoutMs, redact });
    if (r.ok) return null;
    if (r.interrupted) return { problem: 'interrupted', interrupted: true };
    if (!r.retry || attempt >= retries) return { problem: cleanText(redact(r.problem)) || 'failed' };
    try {
      await sleep(Math.min(MAX_RETRY_AFTER_MS, Math.max(retryDelayMs, r.retryAfterMs || 0)), signal);
    } catch {
      if (signal && signal.aborted) return { problem: 'interrupted', interrupted: true };
    }
    if (signal && signal.aborted) return { problem: 'interrupted', interrupted: true };
  }
}

/**
 * Post a run's notifications, one route after the other. A route sends when it has something to
 * say: --notify when a change counts (after every run with `always`), --notify-bad when a counted
 * change is bad, PagerDuty when it has events. A route stops at its first request that fails. The
 * PagerDuty keys open after the run are those delivered ({@link keysOpenAfter}): a trigger taken
 * by any PagerDuty URL opens its key, a resolve closes it once every PagerDuty URL took it.
 * @param {object} report this run's report (tools/ds.mjs; `changes` with --baseline)
 * @param {Array<{ url: string, format: string, bad: boolean, source: string }>} routes {@link notifyRoutes}
 * @param {{ baseline?: object|null, always?: boolean, env?: object, now?: () => Date, fetchImpl: typeof fetch,
 *   signal?: AbortSignal, timing?: { timeoutMs?: number, retryDelayMs?: number, sleep?: Function },
 *   tool: string, version: string }} ctx
 * @returns {Promise<{ results: Array<{ route: object, host: string, sent: number, total: number, triggered: number,
 *   resolved: number, carries: boolean, problem: string|null, interrupted: boolean }>, open: object[]|null, cut: number,
 *   interrupted: boolean }>} `open`: the PagerDuty keys open after this run, as delivered (null without a
 *   PagerDuty route); `carries`: the route carried changes that count, or PagerDuty events
 */
export async function sendNotifications(report, routes, ctx) {
  const { baseline = null, always = false, env = {}, now = () => new Date(), fetchImpl, signal, timing = {}, tool, version } = ctx;
  const run = runUrl(env);
  const plan = routes.some((r) => r.format === 'pagerduty') ? pagerDutyPlan(report, baseline) : null;
  const results = [];
  let interrupted = false;
  const triggered = new Set();
  const resolvedBy = new Map(routes.filter((r) => r.format === 'pagerduty').map((r) => [r, new Set()]));
  for (const route of routes) {
    let requests = [];
    let carries = false;
    if (route.format === 'pagerduty') {
      requests = pagerDutyRequests(route, report, plan, { run, tool, version });
      carries = requests.length > 0;
    } else {
      const msg = notificationMessage(report, route, { run });
      carries = msg.carried.length > 0;
      if (carries || (always && !route.bad)) requests = [buildRequest(route, report, { run, env, now, tool, version })];
    }
    const entry = {
      route, host: notifyHost(route.url), sent: 0, total: requests.length,
      triggered: 0, resolved: 0, carries, problem: null, interrupted: false
    };
    results.push(entry);
    for (const request of requests) {
      const failed = await deliver(request, route.url, { fetchImpl, signal, ...timing });
      if (failed) {
        entry.problem = failed.problem;
        entry.interrupted = !!failed.interrupted;
        break;
      }
      entry.sent += 1;
      if (request.action === 'trigger') {
        entry.triggered += 1;
        triggered.add(request.key);
      }
      if (request.action === 'resolve') {
        entry.resolved += 1;
        resolvedBy.get(route).add(request.key);
      }
    }
    if (entry.interrupted) {
      interrupted = true;
      break;
    }
  }
  if (!plan) return { results, open: null, cut: 0, interrupted };
  const resolved = [...resolvedBy.values()].reduce((all, keys) => new Set([...all].filter((k) => keys.has(k))));
  return { results, open: keysOpenAfter(plan, { triggered, resolved }), cut: plan.cut, interrupted };
}
