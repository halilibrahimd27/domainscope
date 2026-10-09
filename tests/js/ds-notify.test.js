/**
 * tools/ds/notify.mjs — the headless runner's alert channels (`--notify`, `--notify-bad`): the
 * format each URL gets (mirroring the Python CLI's NotifyFormatTests), the URL checks that never
 * repeat a URL, the redaction, every format's payload and its cut at the service's limit, the
 * signed JSON (a known-answer HMAC vector the Python tests share), PagerDuty's triggers and
 * resolves over runs — where each problem stands (tools/ds/states.mjs), also over several nights
 * of the diffs as the runner makes them —, ntfy, and runs of `main()` with a fake fetch: the
 * --notify-bad filter, a retry after a 500, a timeout, the exit code order (3, then 5, then 4), a
 * baseline kept when a message did not go out (with what PagerDuty got noted in it), and no URL
 * in stdout, stderr or any file written. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NOTIFY_FORMATS, NOTIFY_TEXT_LIMITS, NOTIFY_MAX_CHANGES, NOTIFY_MAX_JSON_CHANGES, NOTIFY_LINE_LIMIT, NOTIFY_ENV, CRITICAL_TAGS, CRITICAL_ITEMS,
  PAGERDUTY_MAX_EVENTS, PAGERDUTY_SUMMARY_LIMIT, PAGERDUTY_MAX_OPEN, NTFY_MAX_BYTES, NotifyConfigError,
  detectNotifyFormat, notifyUrlProblem, notifyHost, splitCredentials, redactUrl, runUrl, notifyRoutes, notificationMessage,
  fitLines, buildRequest, signBody, dedupKey, eventSeverity, openKeysOf, problemOver, pagerDutyPlan, keysOpenAfter, pagerDutyRequests,
  responseDetail, deliver, sendNotifications, byteLength
} from '../../tools/ds/notify.mjs';
import { parseCommandLine, UsageError, EXIT, USAGE, DS_TOOL, DS_VERSION } from '../../tools/ds/args.mjs';
import { diffReports } from '../../tools/ds/diff.mjs';
import { setupStrings, changeText } from '../../tools/ds/render.mjs';
import { carryHealth, carryHosts } from '../../tools/ds/carry.mjs';
import { TAKEOVER_COUNTED } from '../../tools/ds/states.mjs';
import { COUNTED_SEVERITY } from '../../tools/ds/takeover.mjs';
import { main } from '../../tools/ds.mjs';
import { zoneTable, createFakeFetch, CF_EXPORT } from './ds-fake-doh.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const NOW = new Date('2026-09-28T03:00:00Z');
const FAST = Object.freeze({ timeoutMs: 2000, retryDelayMs: 1 });
const tmp = () => mkdtempSync(join(tmpdir(), 'ds-notify-'));

// Webhook URLs and keys are credentials: built in parts, never written whole (push protection).
const TOKEN = 'SECRETTOKEN' + '0123456789';
const SLACK_URL = 'https://hooks.slack.com/services/' + 'T00000000/B00000000/' + 'X'.repeat(24);
const GCHAT_URL = 'https://chat.googleapis.com/v1/spaces/AAAAexample/messages' + '?key=KEYexample0123456789&token=TOKENexample0123456789';
const TELEGRAM_URL = 'https://api.telegram.org/bot123456:' + 'TEST-token_value/sendMessage' + '?chat_id=-1001234567890';
const ROUTING_KEY = 'R0UT1NGKEY' + 'x'.repeat(22);
const PAGERDUTY_URL = 'https://events.pagerduty.com/v2/enqueue?routing_key=' + ROUTING_KEY;
const NTFY_URL = 'https://ntfy.sh/' + 'domainscope-example-alerts';
const HOOK_URL = 'https://hooks.example.com/hooks/' + TOKEN;

/** A writable stream stand-in that keeps what it is given. */
function sink() {
  return { text: '', isTTY: false, write(s) { this.text += s; return true; } };
}

/** A fake webhook: records each request and answers from a script (a status, a Response or a function), then 200. */
function webhook(script = []) {
  const requests = [];
  const queue = [...script];
  return {
    requests,
    json: () => requests.map((r) => JSON.parse(r.body)),
    fetch: async (url, init = {}) => {
      requests.push({ url, method: init.method, headers: { ...init.headers }, body: init.body, redirect: init.redirect });
      const next = queue.length ? queue.shift() : 200;
      if (typeof next === 'function') return next(url, init);
      if (typeof next === 'number') {
        const body = next === 204 ? null : next < 300 ? 'ok' : `error ${next}`;
        return new Response(body, { status: next, statusText: next < 300 ? 'OK' : 'Bad' });
      }
      return next;
    }
  };
}

/** `main()` with the fake DoH zone, a webhook for every other request and fast notification timing. */
async function runDs(argv, { table = zoneTable(), hook = webhook(), env = {}, now = NOW, timing = FAST, signal } = {}) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetchImpl: createFakeFetch(table, { other: hook.fetch }), env, now: () => now, notifyTiming: timing, signal });
  return { code, out: stdout.text, err: stderr.text, hook };
}

/** The zone of the second night: www's proxy is back on (BETTER, good), mail's address changed (WORSE, bad). */
function movedZone() {
  const table = zoneTable();
  table['www.example.com'].A = ['104.16.1.1'];
  table['mail.example.com'].A = ['198.51.100.26'];
  return table;
}

/** A health report with these changes (the runner's `changes` entries); `extra` replaces any field (`targets`, `command`). */
function reportOf(changes, extra = {}) {
  return {
    tool: DS_TOOL, version: DS_VERSION, command: 'health', startedAt: '2026-09-28T03:00:00.000Z', finishedAt: '2026-09-28T03:02:00.000Z', options: {},
    targets: [{ target: 'example.com' }, { target: 'example.org' }],
    baseline: { file: 'health.json', missing: false, version: DS_VERSION, startedAt: '2026-09-27T03:00:00.000Z', finishedAt: '2026-09-27T03:02:00.000Z' },
    changes, ...extra
  };
}
const change = (tag, tone, target, item, what, extra = {}) => ({
  tag, tone, counts: true, target, item, kind: 'changed', before: null, after: null, text: `${target}: ${what}`, ...extra
});
const CHANGES = [
  change('NEW', 'bad', 'example.com', 'dmarc.missing', 'error dmarc.missing — No DMARC record <!channel> <users/all> `x` & <@here>', { kind: 'appeared', after: 'error' }),
  change('BETTER', 'good', 'example.org', 'spf.softfail', 'spf.softfail: warn → ok — SPF ends in ~all', { before: 'warn', after: 'ok' }),
  change('SCORE', 'quiet', 'example.com', null, 'health score 80 → 70 (a lookup failed this run)', { counts: false, before: 80, after: 70 })
];
const ctx = { run: null, env: {}, now: () => NOW, tool: DS_TOOL, version: DS_VERSION };

/* ------------------------------------------------------------------------ */
/* Formats and URLs                                                         */
/* ------------------------------------------------------------------------ */

describe('formats and URLs', () => {
  test('the format follows the URL (the Python CLI\'s table, plus PagerDuty and ntfy)', () => {
    const table = {
      [SLACK_URL]: 'slack',
      'https://hooks.slack.com/triggers/T000/111/abc': 'slack',
      'https://discord.com/api/webhooks/123/token-value': 'discord',
      'https://discordapp.com/api/webhooks/123/token-value': 'discord',
      'https://discord.com/api/webhooks/123/token-value/slack': 'slack',
      'https://discord.com/api/v10/webhooks/123/token-value': 'discord',
      'https://discord.com/api/v9/webhooks/123/token-value/slack': 'slack',
      'https://discord.com/api/v10/channels/123/messages': 'json',
      'https://discord.com/channels/123': 'json',
      [GCHAT_URL]: 'googlechat',
      [TELEGRAM_URL]: 'telegram',
      'https://example.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/456': 'teams',
      'https://outlook.office.com/webhook/abc/IncomingWebhook/def/ghi': 'teams',
      'https://prod-00.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=abc': 'teams',
      'https://default0000.00.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?sig=abc': 'teams',
      'https://HOOKS.SLACK.COM/services/a/b/c': 'slack',
      'https://example.com/hooks/ssl': 'json',
      'http://127.0.0.1:8080/hook': 'json',
      [PAGERDUTY_URL]: 'pagerduty',
      ['https://events.eu.pagerduty.com/v2/enqueue?routing_key=' + ROUTING_KEY]: 'pagerduty',
      [NTFY_URL]: 'ntfy',
      'https://ntfy.example.com/alerts': 'json'
    };
    for (const [url, want] of Object.entries(table)) {
      assert.equal(detectNotifyFormat(url), want, url);
      assert.deepEqual(notifyRoutes({ notify: [url] }, {}).map((r) => r.format), [want], url);
    }
    assert.deepEqual(NOTIFY_FORMATS, ['auto', 'slack', 'teams', 'discord', 'telegram', 'googlechat', 'json', 'pagerduty', 'ntfy']);
    assert.deepEqual(NOTIFY_TEXT_LIMITS, { slack: 3500, teams: 3500, discord: 1800, telegram: 3900, googlechat: 3500, json: 3500 });
    assert.equal(NOTIFY_MAX_CHANGES, 20);
    // --notify-format names it for every URL: a self-hosted ntfy server, a Slack-compatible chat
    assert.deepEqual(notifyRoutes({ notify: ['https://ntfy.example.com/alerts'], notifyFormat: 'ntfy' }, {}).map((r) => r.format), ['ntfy']);
    assert.throws(() => notifyRoutes({ notify: ['https://example.com/x'], notifyFormat: 'irc' }, {}), NotifyConfigError);
  });

  test('a URL that is refused is never repeated: https:// only (but to this machine), Telegram and PagerDuty need their parts', () => {
    const secret = 'SECRET0token';
    const cases = [
      [`ftp://example.com/${secret}`, 'needs an https:// URL'],
      [`file:///etc/${secret}`, 'needs an https:// URL'],
      [`https://example.com:port/${secret}`, 'not a valid URL'],
      [`https://example.com/${secret} x`, 'spaces or control characters'],
      [`https://example.com/${secret}\n`, 'spaces or control characters'],
      [`https://api.telegram.org/bot1:${secret}/sendMessage`, 'Telegram URL looks like'],
      [`https://api.telegram.org/bot1:${secret}/getMe?chat_id=1`, 'Telegram URL looks like'],
      [`http://hooks.example.com/${secret}`, 'http:// would send it unencrypted'],
      [`http://192.0.2.10/${secret}`, 'http:// only to this machine'],
      [`https://events.pagerduty.com/v2/enqueue?key=${secret}`, 'a PagerDuty URL looks like']
    ];
    for (const [url, needle] of cases) {
      // the environment holds URLs separated by whitespace: a URL with a space is the command line's
      if (!/\s/.test(url)) {
        assert.throws(() => notifyRoutes({}, { [NOTIFY_ENV.url]: url }), (e) => {
          assert.ok(e instanceof NotifyConfigError, url);
          assert.ok(e.message.startsWith(`${NOTIFY_ENV.url}: `) && e.message.includes(needle), e.message);
          assert.ok(!e.message.includes(secret), e.message);
          return true;
        }, url);
      }
      assert.throws(() => parseCommandLine(['health', 'example.com', '--notify', url]), (e) => {
        assert.ok(e instanceof UsageError, url);
        assert.ok(e.message.includes(needle), `${url}: ${e.message}`);
        assert.ok(e.message.startsWith('--notify'), e.message);
        assert.ok(!e.message.includes(secret), e.message);
        return true;
      }, url);
    }
    // which URL of several, by its place
    assert.throws(() => notifyRoutes({}, { [NOTIFY_ENV.bad]: `${SLACK_URL}  http://hooks.example.com/${secret}` }), { message: /^DOMAINSCOPE_NOTIFY_BAD_URL \(URL 2 of 2\): needs an https:\/\/ URL/ });
    assert.throws(() => parseCommandLine(['health', 'example.com', '--notify-bad', SLACK_URL, '--notify-bad', 'nope']), { message: /^--notify-bad \(URL 2 of 2\): not a valid URL$/ });
    assert.throws(() => parseCommandLine(['health', 'example.com', '--notify=']), /--notify needs a URL/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--notify-format', HOOK_URL]), (e) => !e.message.includes(TOKEN) && /--notify-format takes auto, slack/.test(e.message));
    // http:// to this machine is fine: a local relay, a test receiver
    for (const url of ['http://localhost:9/x', 'http://127.0.0.1/x', 'http://127.0.0.2:8080/x', 'http://[::1]:8080/x']) assert.equal(notifyUrlProblem(url, 'json'), null, url);
    assert.equal(notifyUrlProblem(TELEGRAM_URL, 'telegram'), null);
    assert.equal(notifyUrlProblem('http://127.0.0.1/bot1:x/sendMessage?chat_id=5', 'telegram'), null);
  });

  test('routes: the command line, else the environment (URLs separated by whitespace); a URL given twice is posted to once', () => {
    const env = { [NOTIFY_ENV.url]: ` ${SLACK_URL}\n${NTFY_URL}\t`, [NOTIFY_ENV.bad]: `${PAGERDUTY_URL} ${SLACK_URL}` };
    assert.deepEqual(notifyRoutes({}, env).map((r) => [r.format, r.bad, r.source]), [
      ['slack', false, NOTIFY_ENV.url], ['ntfy', false, NOTIFY_ENV.url], ['pagerduty', true, NOTIFY_ENV.bad]
    ]);
    // the command line wins over the environment, route by route
    assert.deepEqual(notifyRoutes({ notify: [HOOK_URL] }, env).map((r) => [r.format, r.bad, r.source]), [
      ['json', false, '--notify'], ['pagerduty', true, NOTIFY_ENV.bad], ['slack', true, NOTIFY_ENV.bad]
    ]);
    assert.deepEqual(notifyRoutes({ notify: [HOOK_URL, HOOK_URL] }, {}).length, 1);
    // nothing set: no route, and the other notify options change nothing
    assert.deepEqual(notifyRoutes({ notifyFormat: 'ntfy' }, { [NOTIFY_ENV.url]: '', [NOTIFY_ENV.bad]: '  ' }), []);
    const cl = parseCommandLine(['health', 'example.com', '--fail-on-notify-error', '--notify-always', '--notify-format', 'ntfy']);
    assert.deepEqual([cl.options.notify, cl.options.notifyBad, cl.options.notifyFormat, cl.options.notifyAlways, cl.options.failOnNotifyError], [[], [], 'ntfy', true, true]);
    // an ntfy token that cannot be a header is refused (only when an ntfy URL uses it)
    assert.throws(() => notifyRoutes({}, { [NOTIFY_ENV.url]: NTFY_URL, [NOTIFY_ENV.ntfyToken]: 'tk_ab cd' }), /DOMAINSCOPE_NTFY_TOKEN: not an access token/);
    assert.doesNotThrow(() => notifyRoutes({}, { [NOTIFY_ENV.url]: SLACK_URL, [NOTIFY_ENV.ntfyToken]: 'tk_ab cd' }));
  });

  test('redaction: the URL and its secret parts out of an answer, the host kept', () => {
    const text = `POST ${SLACK_URL} failed: T00000000/B00000000 no_service ${'X'.repeat(24)}`;
    const redacted = redactUrl(text, SLACK_URL);
    assert.ok(!redacted.includes('X'.repeat(24)) && !redacted.includes('T00000000'), redacted);
    assert.match(redacted, /no_service/);
    const url = 'https://user:pa55word@example.com/hook?sig=s1gnature%2Fvalue&api-version=1';
    const r2 = redactUrl('x user:pa55word s1gnature/value s1gnature%2Fvalue', url);
    assert.ok(!r2.includes('pa55word') && !r2.includes('s1gnature'), r2);
    const basicUrl = 'https://alerts:Hunter2%24ecret@hooks.example.com/hook';
    assert.equal(redactUrl("nonnumeric port: 'Hunter2$ecret@hooks.example.com' Hunter2%24ecret, user alerts", basicUrl),
      "nonnumeric port: '***@hooks.example.com' ***, user ***");
    assert.equal(redactUrl('bad password x', 'https://u:x@example.com/'), 'bad password ***');
    const basic = Buffer.from('alerts:Hunter2$ecret').toString('base64');
    assert.equal(redactUrl(`got Authorization: Basic ${basic}; also ${basic}`, basicUrl), 'got Authorization: ***; also ***');
    assert.equal(redactUrl('bot123456:TEST-token_value 123456:TEST-token_value 123456%3ATEST-token_value (TEST-token_value)', TELEGRAM_URL), '*** *** *** (***)');
    for (const [u, t, want] of [
      ['https://hooks.example.com/hook', 'hooks.example.com: 404 on hook', 'hooks.example.com: 404 on hook'],
      [SLACK_URL, 'services webhooks hooks.slack.com', 'services webhooks hooks.slack.com'],
      ['https://discord.com/api/v10/webhooks/123/tokentokentoken', 'v10 webhooks: tokentokentoken', 'v10 webhooks: ***'],
      [GCHAT_URL, 'spaces/AAAAexample/messages: TOKENexample0123456789', 'spaces/***/messages: ***'],
      [PAGERDUTY_URL, `v2 enqueue: invalid routing key ${ROUTING_KEY}`, 'v2 enqueue: invalid routing key ***'],
      ['https://example.com/hooks/Zq8pLmW', 'unknown Zq8pLmW', 'unknown ***']
    ]) assert.equal(redactUrl(t, u), want, u);
    // what a request carries besides the URL: the ntfy token, the signing secret
    assert.equal(redactUrl('echo tk_secretvalue', NTFY_URL, ['tk_secretvalue']), 'echo ***');
    assert.deepEqual(splitCredentials('https://a%40b:p%3Ass@example.com:8443/x?y=1'),
      { url: 'https://example.com:8443/x?y=1', authorization: `Basic ${Buffer.from('a@b:p:ss').toString('base64')}` });
    assert.deepEqual(splitCredentials(SLACK_URL), { url: SLACK_URL, authorization: null });
    assert.equal(notifyHost(SLACK_URL), 'hooks.slack.com');
    assert.equal(notifyHost('http://[::1]:8080/x'), '[::1]:8080');
    assert.equal(notifyHost(basicUrl), 'hooks.example.com');
    assert.equal(responseDetail('{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}'), 'Bad Request: chat not found');
    assert.equal(responseDetail('{"message": "Unknown Webhook", "code": 10015}'), 'Unknown Webhook');
    assert.equal(responseDetail('{"error":{"code":"X","message":"The input body did not match"}}'), 'The input body did not match');
    assert.equal(responseDetail('  line one\n\n  line two '), 'line one line two');
    assert.equal(runUrl({}), null);
    assert.equal(runUrl({ GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'example/nightly', GITHUB_RUN_ID: '42' }), 'https://github.com/example/nightly/actions/runs/42');
    assert.equal(runUrl({ GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'example/nightly', GITHUB_RUN_ID: '4 2' }), null);
  });
});

/* ------------------------------------------------------------------------ */
/* Messages and payloads                                                    */
/* ------------------------------------------------------------------------ */

describe('messages and payloads', () => {
  const report = reportOf(CHANGES);

  test('the message: the changes that count (the bad ones on the --notify-bad route), the run, the listed-only count', () => {
    const all = notificationMessage(report, { bad: false }, { run: 'https://github.com/example/nightly/actions/runs/42' });
    assert.equal(all.title, 'DomainScope health: 2 changes since 2026-09-27 03:02 UTC');
    assert.deepEqual(all.items.map((l) => l.split(' ').slice(0, 3).join(' ')), ['- NEW example.com:', '- BETTER example.org:']);
    assert.deepEqual(all.footer, ['Run of 2026-09-28 03:00 UTC: 2 domains (example.com, example.org); 1 change listed only (not counted).', 'Run: https://github.com/example/nightly/actions/runs/42']);
    assert.equal(all.bad, true);
    const bad = notificationMessage(report, { bad: true });
    assert.equal(bad.title, 'DomainScope health: 1 bad change since 2026-09-27 03:02 UTC');
    assert.equal(bad.items.length, 1);
    assert.deepEqual(bad.footer, ['Run of 2026-09-28 03:00 UTC: 2 domains (example.com, example.org).']);
    assert.equal(notificationMessage(reportOf([CHANGES[1]]), { bad: true }).title, 'DomainScope health: no bad changes since 2026-09-27 03:02 UTC');
    assert.equal(notificationMessage(reportOf([], { baseline: { file: 'h.json', missing: true } }), { bad: false }).title, 'DomainScope health: first run, no baseline to compare yet');
    assert.equal(notificationMessage({ ...reportOf([]), baseline: undefined, changes: undefined }, { bad: false }).title, 'DomainScope health: finished');
    assert.equal(notificationMessage(reportOf([]), { bad: false }).title, 'DomainScope health: no changes since 2026-09-27 03:02 UTC');
  });

  test('each chat format: no mention, ping or link from a value; Telegram\'s chat_id moved from the query into the body', () => {
    const slack = buildRequest({ url: SLACK_URL, format: 'slack', bad: false }, report, ctx);
    assert.equal(slack.url, SLACK_URL);
    assert.equal(slack.headers['Content-Type'], 'application/json; charset=utf-8');
    assert.match(slack.headers['User-Agent'], /^domainscope-ds\/\d+\.\d+\.\d+ \(\+https:\/\/github\.com\/halilibrahimd27\/domainscope\)$/);
    const s = JSON.parse(slack.body).text;
    assert.ok(s.startsWith('*DomainScope health: 2 changes since 2026-09-27 03:02 UTC*\n```\n- NEW example.com: '), s);
    assert.ok(s.endsWith('\n```'));
    assert.match(s, /&lt;!channel&gt; &lt;users\/all&gt; ˋxˋ &amp; &lt;@here&gt;/);
    assert.ok(!s.includes('<!channel>') && !/`x`/.test(s));

    const discord = JSON.parse(buildRequest({ url: 'https://discord.com/api/webhooks/1/x', format: 'discord', bad: false }, report, ctx).body);
    assert.deepEqual(discord.allowed_mentions, { parse: [] });
    assert.ok(discord.content.startsWith('**DomainScope health: 2 changes'));
    const block = discord.content.slice(discord.content.indexOf('```\n') + 4, discord.content.lastIndexOf('\n```'));
    assert.ok(block.includes('dmarc.missing') && !block.includes('`'), 'no backtick closes the block');

    const teams = JSON.parse(buildRequest({ url: 'https://example.webhook.office.com/x', format: 'teams', bad: false }, report, ctx).body);
    assert.equal(teams.type, 'message');
    const card = teams.attachments[0];
    assert.equal(card.contentType, 'application/vnd.microsoft.card.adaptive');
    assert.equal(card.content.type, 'AdaptiveCard');
    assert.ok(card.content.body.every((b) => b.type === 'RichTextBlock' && b.inlines.every((i) => i.type === 'TextRun')));
    assert.equal(card.content.body[0].inlines[0].weight, 'Bolder');
    assert.equal(card.content.body.length, 1 + 2 + 1, 'title, two changes, the footer');

    const gchat = buildRequest({ url: GCHAT_URL, format: 'googlechat', bad: false }, report, ctx);
    assert.equal(gchat.url, GCHAT_URL);
    const g = JSON.parse(gchat.body).text;
    assert.match(g, /‹!channel> ‹users\/all> ˋxˋ & ‹@here>/);
    assert.ok(!g.includes('&lt;') && !g.includes('<'));

    const tg = buildRequest({ url: TELEGRAM_URL, format: 'telegram', bad: false }, report, ctx);
    assert.equal(tg.url, TELEGRAM_URL.slice(0, TELEGRAM_URL.indexOf('?')));
    const t = JSON.parse(tg.body);
    assert.equal(t.chat_id, -1001234567890);
    assert.ok(t.text.startsWith('DomainScope health: 2 changes since 2026-09-27 03:02 UTC\n\n- NEW '));
    assert.deepEqual(t.link_preview_options, { is_disabled: true });
    const channel = buildRequest({ url: 'https://api.telegram.org/bot1:x/sendMessage?chat_id=%40channel&message_thread_id=7', format: 'telegram', bad: false }, report, ctx);
    assert.equal(channel.url, 'https://api.telegram.org/bot1:x/sendMessage?message_thread_id=7');
    assert.equal(JSON.parse(channel.body).chat_id, '@channel');
    // a chat id beyond a safe number stays text, as the Bot API takes it too
    assert.equal(JSON.parse(buildRequest({ url: 'https://api.telegram.org/bot1:x/sendMessage?chat_id=-100123456789012345678', format: 'telegram', bad: false }, report, ctx).body).chat_id,
      '-100123456789012345678');
    // user:password@ goes as Basic authentication, never in the URL fetch is given
    const withUser = buildRequest({ url: 'https://alerts:Hunter2@hooks.example.com/hook', format: 'slack', bad: false }, report, ctx);
    assert.equal(withUser.url, 'https://hooks.example.com/hook');
    assert.equal(withUser.headers.Authorization, `Basic ${Buffer.from('alerts:Hunter2').toString('base64')}`);
  });

  test('JSON: every change of the run (the bad ones on --notify-bad), the counts and the run\'s link; signed when a secret is set', () => {
    const run = 'https://github.com/example/nightly/actions/runs/42';
    const plain = buildRequest({ url: HOOK_URL, format: 'json', bad: false }, report, { ...ctx, run });
    assert.equal(plain.headers['X-DomainScope-Signature'], undefined);
    const doc = JSON.parse(plain.body);
    assert.deepEqual(Object.keys(doc), ['tool', 'version', 'command', 'title', 'text', 'startedAt', 'finishedAt', 'run', 'baseline', 'counts', 'changes', 'changesTotal']);
    assert.deepEqual([doc.tool, doc.version, doc.command, doc.run], [DS_TOOL, DS_VERSION, 'health', run]);
    assert.deepEqual(doc.counts, { changes: 3, counted: 2, bad: 1 });
    assert.deepEqual(doc.baseline, { file: 'health.json', missing: false, finishedAt: '2026-09-27T03:02:00.000Z' });
    assert.deepEqual(doc.changes.map((c) => `${c.tag}${c.counts ? '' : '?'}`), ['NEW', 'BETTER', 'SCORE?']);
    assert.deepEqual(Object.keys(doc.changes[0]), ['tag', 'tone', 'counts', 'target', 'item', 'text', 'before', 'after']);
    assert.equal(doc.changesTotal, 3);
    assert.ok(doc.text.startsWith(`${doc.title}\n- NEW example.com: `));
    const bad = JSON.parse(buildRequest({ url: HOOK_URL, format: 'json', bad: true }, report, ctx).body);
    assert.deepEqual(bad.changes.map((c) => c.tag), ['NEW']);
    assert.deepEqual(bad.counts, { changes: 3, counted: 2, bad: 1 });

    const secret = 'It\'s a Secret to Everybody';
    const signed = buildRequest({ url: HOOK_URL, format: 'json', bad: false }, report, { ...ctx, env: { [NOTIFY_ENV.secret]: ` ${secret}\n` } });
    assert.equal(signed.headers['X-DomainScope-Timestamp'], String(NOW.getTime() / 1000));
    const want = `sha256=${createHmac('sha256', secret).update(`${NOW.getTime() / 1000}.${signed.body}`).digest('hex')}`;
    assert.equal(signed.headers['X-DomainScope-Signature'], want);
    assert.ok(signed.secrets.includes(secret), 'the secret is redacted from an answer too');
    // only the JSON format is signed
    assert.equal(buildRequest({ url: SLACK_URL, format: 'slack', bad: false }, report, { ...ctx, env: { [NOTIFY_ENV.secret]: secret } }).headers['X-DomainScope-Signature'], undefined);
  });

  test('signBody: a known-answer vector (the same in tests/python), over the exact bytes sent', () => {
    // Python: hmac.new(b"It's a Secret to Everybody", b'1700000000.{"hello":"world"}', hashlib.sha256).hexdigest()
    assert.equal(signBody('It\'s a Secret to Everybody', 1700000000, '{"hello":"world"}'), 'sha256=08c0aaa4721d7e090415dc782eb1818362b0e857612ef36e6dcf8c773571b03b');
    assert.equal(signBody('It\'s a Secret to Everybody', '1700000000', Buffer.from('{"hello":"world"}')), 'sha256=08c0aaa4721d7e090415dc782eb1818362b0e857612ef36e6dcf8c773571b03b');
    // RFC 4231 test case 2, the primitive: HMAC-SHA256("Jefe", "what do ya want for nothing?")
    assert.equal(createHmac('sha256', 'Jefe').update('what do ya want for nothing?').digest('hex'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    assert.equal(signBody('Jefe', 1, 'ü'), `sha256=${createHmac('sha256', 'Jefe').update(Buffer.from('1.ü', 'utf8')).digest('hex')}`, 'UTF-8 bytes');
  });

  test('ntfy: plain text, a title, priority 4 when a change is bad (else 3), a tag, the run\'s link and the token', () => {
    const run = 'https://github.com/example/nightly/actions/runs/42';
    const req = buildRequest({ url: NTFY_URL, format: 'ntfy', bad: false }, report, { ...ctx, run, env: { [NOTIFY_ENV.ntfyToken]: 'tk_' + 'examplevalue' } });
    assert.equal(req.url, NTFY_URL);
    assert.deepEqual({ ...req.headers, 'User-Agent': undefined }, {
      'Content-Type': 'text/plain; charset=utf-8', 'User-Agent': undefined, Title: 'DomainScope health: 2 changes since 2026-09-27 03:02 UTC',
      Priority: '4', Tags: 'warning', Click: run, Authorization: 'Bearer tk_examplevalue'
    });
    assert.ok(req.body.startsWith('- NEW example.com: error dmarc.missing'), req.body);
    assert.ok(req.body.endsWith(`Run: ${run}`));
    assert.ok(req.secrets.includes('tk_examplevalue') && req.secrets.includes('domainscope-example-alerts'), 'the token and the topic are redacted from an answer');
    const quiet = buildRequest({ url: NTFY_URL, format: 'ntfy', bad: false }, reportOf([CHANGES[1]]), ctx);
    assert.equal(quiet.headers.Priority, '3');
    assert.equal(quiet.headers.Authorization, undefined);
    // a URL with user info authenticates itself; a title that is not ASCII goes RFC 2047 encoded
    const own = buildRequest({ url: 'https://u:p@ntfy.example.com/alerts', format: 'ntfy', bad: false }, { ...reportOf([CHANGES[1]]), command: 'sağlık' }, { ...ctx, env: { [NOTIFY_ENV.ntfyToken]: 'tk_x' } });
    assert.equal(own.headers.Authorization, `Basic ${Buffer.from('u:p').toString('base64')}`);
    assert.match(own.headers.Title, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
    assert.equal(Buffer.from(own.headers.Title.slice(10, -2), 'base64').toString('utf8'), 'DomainScope sağlık: 1 change since 2026-09-27 03:02 UTC');
  });

  test('cuts at each limit: every format within its service\'s, ntfy in bytes, every line at 400 characters, PagerDuty\'s summary at 1,024', () => {
    const long = (i) => change('WORSE', 'bad', 'example.com', `host-${i}.example.com`, `${'ğüşİ€😀'.repeat(60)} ${'x'.repeat(i % 7 ? 50 : 900)}`);
    const many = Array.from({ length: 600 }, (_, i) => long(i));
    const big = reportOf(many);
    const caps = { slack: 4000, discord: 2000, telegram: 4096, googlechat: 4096 };
    for (const [format, cap] of Object.entries(caps)) {
      const doc = JSON.parse(buildRequest({ url: format === 'telegram' ? TELEGRAM_URL : HOOK_URL, format, bad: false }, big, ctx).body);
      const text = doc.text || doc.content;
      assert.ok(text.length <= cap, `${format}: ${text.length}`);
      assert.match(text, /- \.\.\. and \d+ more (line|lines|changes)/, format);
      assert.match(text, /Run of 2026-09-28 03:00 UTC/, `${format}: the footer always makes it`);
    }
    const teams = JSON.parse(buildRequest({ url: HOOK_URL, format: 'teams', bad: false }, big, ctx).body);
    const runs = teams.attachments[0].content.body.flatMap((b) => b.inlines.map((i) => i.text));
    assert.ok(runs.join('\n').length <= NOTIFY_TEXT_LIMITS.teams, 'teams');
    assert.ok(runs.every((l) => l.length <= NOTIFY_LINE_LIMIT), 'every line cut at 400 characters');
    const json = JSON.parse(buildRequest({ url: HOOK_URL, format: 'json', bad: false }, big, ctx).body);
    assert.deepEqual([json.changes.length, json.changesTotal], [NOTIFY_MAX_JSON_CHANGES, 600]);
    assert.ok(json.text.length <= NOTIFY_TEXT_LIMITS.json + 100, `${json.text.length}`);
    const ntfy = buildRequest({ url: NTFY_URL, format: 'ntfy', bad: false }, big, ctx);
    assert.ok(byteLength(ntfy.body) <= NTFY_MAX_BYTES, `${byteLength(ntfy.body)} bytes`);
    assert.ok(!/[\ud800-\udfff]/.test(ntfy.body.replace(/[\ud800-\udbff][\udc00-\udfff]/g, '')), 'no lone surrogate');
    // fitLines on its own: the items that fit, then how many more, the footer whole
    assert.deepEqual(fitLines('title', ['- a', '- b'], ['x'.repeat(1000)], 1800), ['- a', '- b', `${'x'.repeat(397)}...`]);
    assert.deepEqual(fitLines('t', ['- one', '- two'], ['end'], 72), ['- one', '- ... and 1 more line - see the --json report', 'end']);
    // PagerDuty: the summary at 1,024 characters, never inside a character
    const plan = pagerDutyPlan(reportOf([change('WORSE', 'bad', 'example.com', 'x', `${'😀'.repeat(600)}`)]), null);
    const [event] = pagerDutyRequests({ url: PAGERDUTY_URL }, reportOf([]), plan, { tool: DS_TOOL, version: DS_VERSION }).map((r) => JSON.parse(r.body));
    assert.ok(event.payload.summary.length <= PAGERDUTY_SUMMARY_LIMIT, `${event.payload.summary.length}`);
    assert.ok(event.payload.summary.endsWith('...'));
    assert.ok(!/[\ud800-\udfff]/.test(event.payload.summary.replace(/[\ud800-\udbff][\udc00-\udfff]/g, '')), 'no lone surrogate');
  });
});

/* ------------------------------------------------------------------------ */
/* PagerDuty                                                                */
/* ------------------------------------------------------------------------ */

describe('PagerDuty', () => {
  test('dedup_key: the first 32 hex characters of sha256(command|target|item|tag), the same in tests/python', () => {
    assert.equal(dedupKey('drift', 'example.com', 'mail.example.com|A', 'WORSE'), '76ba01e87c44289e10e6ce396ed86f09');
    assert.equal(dedupKey('health', 'example.com', null, 'SCORE'), createHash('sha256').update('health|example.com||SCORE').digest('hex').slice(0, 32));
    assert.notEqual(dedupKey('health', 'example.com', 'a', 'NEW'), dedupKey('health', 'example.com', 'a', 'WORSE'));
  });

  test('severity: critical for registrar, name servers, DS, lock, expiry and trust — the tags, and the runner\'s own checks of them; error otherwise', () => {
    assert.deepEqual(CRITICAL_TAGS, ['REGISTRAR', 'NS', 'DS', 'LOCK', 'EXPIRED', 'UNTRUSTED']);
    for (const tag of CRITICAL_TAGS) assert.equal(eventSeverity({ tag }), 'critical', tag);
    assert.equal(eventSeverity({ tag: 'TAKEOVER', after: 'critical' }), 'critical');
    assert.equal(eventSeverity({ tag: 'TAKEOVER', after: { severity: 'critical', kind: 'cname' } }), 'critical');
    assert.equal(eventSeverity({ tag: 'NEW', after: { risk: 'critical' } }), 'critical');
    for (const c of [{ tag: 'WORSE', after: 'error' }, { tag: 'DANGLING' }, { tag: 'TAKEOVER', after: 'high' }, { tag: 'NEW', after: null }]) assert.equal(eventSeverity(c), 'error', c.tag);
    // what today's commands page for those: drift's name servers, the audit's registrar, lock,
    // registry status, DNSSEC and expiry rules (also a domain added that fails one), health's
    // registration expired, held or being deleted and DNSSEC broken, ct's certificate in use revoked,
    // watch's hold, pending delete, redemption or pending transfer arriving and the registry losing the domain
    assert.deepEqual(CRITICAL_ITEMS, {
      health: ['rdap.expired', 'rdap.hold', 'rdap.pending-delete', 'dnssec.broken'],
      drift: ['NS'],
      audit: ['registrar', 'transferLock', 'status.critical', 'dnssec', 'expiryDays', 'nsExpiryDays'],
      watch: ['server hold', 'client hold', 'pending delete', 'redemption period', 'pending transfer', 'registration']
    });
    for (const id of CRITICAL_ITEMS.watch) assert.equal(eventSeverity({ tag: 'STATUS', item: id, after: id }, 'watch'), 'critical', id);
    assert.equal(eventSeverity({ tag: 'STATUS', item: 'client update prohibited', after: 'client update prohibited' }, 'watch'), 'error');
    assert.equal(eventSeverity({ tag: 'WORSE', item: 'NS', after: 'disjoint' }, 'drift'), 'critical');
    assert.equal(eventSeverity({ tag: 'WORSE', item: 'mail.example.com|A', after: 'differs' }, 'drift'), 'error');
    for (const id of CRITICAL_ITEMS.audit) assert.equal(eventSeverity({ tag: 'WORSE', item: id, after: 'fail' }, 'audit'), 'critical', id);
    assert.equal(eventSeverity({ tag: 'NEW', item: 'spf', after: 'fail' }, 'audit'), 'error');
    assert.equal(eventSeverity({ tag: 'NEW', item: null, after: ['spf', 'transferLock'] }, 'audit'), 'critical', 'a domain added that fails a registration rule');
    assert.equal(eventSeverity({ tag: 'NEW', item: null, after: ['spf'] }, 'audit'), 'error');
    for (const id of CRITICAL_ITEMS.health) assert.equal(eventSeverity({ tag: 'NEW', item: id, after: 'error' }, 'health'), 'critical', id);
    assert.equal(eventSeverity({ tag: 'NEW', item: 'dmarc.missing', after: 'error' }, 'health'), 'error');
    assert.equal(eventSeverity({ tag: 'REVOKED', item: 'a'.repeat(16) }, 'ct'), 'critical');
    assert.equal(eventSeverity({ tag: 'EXPIRING', item: 'a'.repeat(16), after: 14 }, 'ct'), 'error');
    assert.equal(eventSeverity({ tag: 'WORSE', item: 'transferLock', after: 'fail' }, 'drift'), 'error', 'an item of another command');
    // the trigger carries it
    const plan = pagerDutyPlan(reportOf([change('WORSE', 'bad', 'example.com', 'NS', 'name servers: same → disjoint', { after: 'disjoint' })], { command: 'drift' }), null);
    const [event] = pagerDutyRequests({ url: PAGERDUTY_URL }, { command: 'drift' }, plan, { tool: DS_TOOL, version: DS_VERSION }).map((r) => JSON.parse(r.body));
    assert.equal(event.payload.severity, 'critical');
  });

  test('a trigger per counted bad change, the key kept open with the state it paged at; a later run resolves it once the item is better than that', () => {
    const worse = change('WORSE', 'bad', 'example.com', 'dmarc.policy', 'dmarc.policy: warn → error — DMARC p=none', { before: 'warn', after: 'error' });
    const run1 = reportOf([worse, CHANGES[1], CHANGES[2], { ...worse, item: 'listed.only', counts: false, tone: 'quiet' }]);
    const plan1 = pagerDutyPlan(run1, null);
    const key = dedupKey('health', 'example.com', 'dmarc.policy', 'WORSE');
    assert.deepEqual(plan1.triggers.map((t) => t.key), [key]);
    assert.deepEqual(plan1.resolves, []);
    assert.deepEqual(plan1.open, [{ key, target: 'example.com', item: 'dmarc.policy', tag: 'WORSE', since: '2026-09-28T03:00:00.000Z', state: 'error' }]);
    const run = 'https://github.com/example/nightly/actions/runs/42';
    const [req] = pagerDutyRequests({ url: PAGERDUTY_URL }, run1, plan1, { run, tool: DS_TOOL, version: DS_VERSION });
    assert.equal(req.url, 'https://events.pagerduty.com/v2/enqueue', 'the routing key moves into the body');
    assert.deepEqual(JSON.parse(req.body), {
      routing_key: ROUTING_KEY,
      event_action: 'trigger',
      dedup_key: key,
      payload: {
        summary: 'WORSE example.com: dmarc.policy: warn → error — DMARC p=none',
        source: 'domainscope:health',
        severity: 'error',
        component: 'example.com',
        group: 'health',
        custom_details: { tag: 'WORSE', item: 'dmarc.policy', before: 'warn', after: 'error', run }
      },
      client: 'DomainScope',
      client_url: run
    });

    const baseline = { ...run1, notify: { open: plan1.open } };
    const night = (severity) => reportOf([], { targets: [{ target: 'example.com', score: 70, checks: [{ id: 'dmarc.policy', severity }] }, { target: 'example.org' }] });
    // nothing moved, the finding still an error: still open, nothing sent
    const quiet = pagerDutyPlan(night('error'), baseline);
    assert.deepEqual([quiet.triggers, quiet.resolves, quiet.open], [[], [], plan1.open]);
    // better than it paged at (back to warn, fixed, no longer reported): resolved
    for (const fixed of [night('warn'), night('ok'), reportOf([])]) {
      const plan = pagerDutyPlan(fixed, baseline);
      assert.deepEqual([plan.triggers, plan.resolves.map((e) => e.key), plan.open], [[], [key], []]);
    }
    const [resolve] = pagerDutyRequests({ url: PAGERDUTY_URL }, reportOf([]), pagerDutyPlan(reportOf([]), baseline), { tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual(JSON.parse(resolve.body), { routing_key: ROUTING_KEY, event_action: 'resolve', dedup_key: key });
    // triggered again (the same problem moved on): stays open with its first time and state
    const again = pagerDutyPlan({ ...reportOf([worse]), startedAt: '2026-09-29T03:00:00.000Z' }, baseline);
    assert.deepEqual([again.triggers.map((t) => t.key), again.resolves, again.open], [[key], [], plan1.open]);
  });

  test('when a problem is over: the item\'s state in this run\'s report says so; a lookup that failed, a source or row not read never does', () => {
    const open = (command, target, item, tag, state) => ({ key: dedupKey(command, target, item, tag), target, item, tag, since: null, ...(state === undefined ? {} : { state }) });
    const run = (command, targets) => ({ ...reportOf([]), command, targets });
    assert.equal(problemOver(open('health', 'example.net', 'x', 'NEW', 'warn'), reportOf([])), true, 'its target no longer checked');
    // health: a finding below the severity it paged at, or no longer reported where its lookup answered
    const h = (checks, extra = {}) => run('health', [{ target: 'example.com', score: 70, checks, ...extra }]);
    const dmarc = open('health', 'example.com', 'dmarc.policy', 'WORSE', 'error');
    assert.equal(problemOver(dmarc, h([{ id: 'dmarc.policy', severity: 'error' }])), false);
    assert.equal(problemOver(dmarc, h([{ id: 'dmarc.policy', severity: 'warn' }])), true);
    assert.equal(problemOver(dmarc, h([])), true, 'no longer reported');
    assert.equal(problemOver(dmarc, h([{ id: 'dmarc.error', severity: 'warn' }])), false, 'its lookup failed: not known gone');
    assert.equal(problemOver(dmarc, h([{ id: 'dmarc.error', severity: 'warn' }], { carried: [{ area: 'dmarc', from: null, checks: [{ id: 'dmarc.policy', severity: 'error' }] }] })), false, 'carried as last read');
    assert.equal(problemOver({ ...dmarc, state: undefined }, h([{ id: 'dmarc.policy', severity: 'info' }])), false, 'without its state: over once fully good');
    const lookup = open('health', 'example.com', 'dmarc.error', 'NEW', 'warn');
    assert.equal(problemOver(lookup, h([{ id: 'dmarc.error', severity: 'warn' }])), false);
    assert.equal(problemOver(lookup, h([])), true, 'the lookup answers again');
    const score = open('health', 'example.com', null, 'SCORE', 70);
    assert.equal(problemOver(score, h([])), false, 'still 70');
    assert.equal(problemOver(score, run('health', [{ target: 'example.com', score: 75, checks: [] }])), true);
    assert.equal(problemOver(score, run('health', [{ target: 'example.com', score: 90, checks: [{ id: 'mx.error', severity: 'warn' }] }])), false, 'a score read while a lookup failed');
    // subdomains: the host's answer — a failed lookup proves nothing, a host an exact run no
    // longer lists is out of its file, one a discovery run did not look up again is not known
    const host = (over = {}) => ({ name: 'www.example.com', status: 'NOERROR', kind: 'cdn', provider: 'Cloudflare', providerId: 'cloudflare', hidesOrigin: true, dangling: false, ipv4: ['104.16.1.1'], ipv6: [], cnames: [], ...over });
    const direct = { kind: 'direct', provider: null, providerId: null, hidesOrigin: false, ipv4: ['192.0.2.10'] };
    const servfail = { status: 'SERVFAIL', kind: null, ipv4: [] };
    const nx = { status: 'NXDOMAIN', kind: null, provider: null, hidesOrigin: false, ipv4: [] };
    const s = (hosts, mode = 'exact') => run('subdomains', [{ target: 'example.com', mode, hosts }]);
    const exposed = open('subdomains', 'example.com', 'www.example.com', 'EXPOSED');
    assert.equal(problemOver(exposed, s([host(direct)])), false);
    assert.equal(problemOver(exposed, s([host()])), true, 'behind its CDN again (a CHANGED)');
    assert.equal(problemOver(exposed, s([host(servfail)])), false, 'a failed lookup');
    assert.equal(problemOver(exposed, s([])), true, 'out of the exact names file');
    assert.equal(problemOver(exposed, s([], 'discover')), false, 'not looked up again');
    const failed = open('subdomains', 'example.com', 'www.example.com', 'FAILED');
    assert.equal(problemOver(failed, s([host(servfail)])), false);
    assert.equal(problemOver(failed, s([host(direct)])), true, 'answers again, whatever it says');
    const dangling = open('subdomains', 'example.com', 'www.example.com', 'DANGLING');
    assert.equal(problemOver(dangling, s([host({ ...nx, status: 'NOERROR', dangling: true, cnames: ['gone.example.net'] })])), false);
    assert.equal(problemOver(dangling, s([host(servfail)])), false);
    assert.equal(problemOver(dangling, s([host(nx)])), true, 'the alias removed');
    const gone = open('subdomains', 'example.com', 'www.example.com', 'GONE');
    assert.equal(problemOver(gone, s([host(nx)])), false);
    assert.equal(problemOver(gone, s([host()])), true);
    // drift: below the status (DRIFT_SEVERITY) or the name servers' match it paged at; a row
    // that could not be checked or was skipped is not known, one out of the file is over
    const d = (rows, preflight = { nsMatch: 'same' }) => run('drift', [{ target: 'example.com', preflight, rows }]);
    const row = open('drift', 'example.com', 'mail.example.com|A', 'WORSE', 'differs');
    assert.equal(problemOver(row, d([{ key: 'mail.example.com|A', status: 'differs' }])), false);
    assert.equal(problemOver(row, d([{ key: 'mail.example.com|A', status: 'match' }])), true);
    for (const status of ['error', 'skipped']) assert.equal(problemOver(row, d([{ key: 'mail.example.com|A', status }])), false, status);
    assert.equal(problemOver(row, d([])), true, 'no longer in the file');
    const occluded = open('drift', 'example.com', 'mail.example.com|A', 'WORSE', 'occluded');
    assert.equal(problemOver(occluded, d([{ key: 'mail.example.com|A', status: 'occluded' }])), false, 'a move to info stays open until it moves back');
    assert.equal(problemOver(occluded, d([{ key: 'mail.example.com|A', status: 'match' }])), true);
    const rowFailed = open('drift', 'example.com', 'mail.example.com|A', 'FAILED', 'error');
    assert.equal(problemOver(rowFailed, d([{ key: 'mail.example.com|A', status: 'error' }])), false);
    assert.equal(problemOver(rowFailed, d([{ key: 'mail.example.com|A', status: 'differs' }])), true, 'checked again (a bad status pages on its own)');
    const ns = open('drift', 'example.com', 'NS', 'WORSE', 'overlap');
    assert.deepEqual(['disjoint', 'overlap', 'unknown', 'same'].map((m) => problemOver(ns, d([], { nsMatch: m }))), [false, false, false, true]);
    // renew: a verdict better than the one it paged at; "could not be checked" is no verdict
    const r = (verdict) => run('renew', [{ target: 'example.com', verdict, findings: [] }]);
    const verdicts = ['ready', 'warnings', 'unknown', 'fail'];
    assert.deepEqual(verdicts.map((v) => problemOver(open('renew', 'example.com', null, 'WORSE', 'warnings'), r(v))), [true, false, false, false]);
    assert.deepEqual(verdicts.map((v) => problemOver(open('renew', 'example.com', null, 'WORSE', 'fail'), r(v))), [true, true, false, false]);
    assert.deepEqual(verdicts.map((v) => problemOver(open('renew', 'example.com', null, 'FAILED', 'unknown'), r(v))), [true, true, false, true]);
    // dane: an endpoint's status (DANE_SEVERITY) better than it paged at
    const e = (endpoints) => run('dane', [{ target: 'example.com', endpoints }]);
    const danger = open('dane', 'example.com', 'smtp|mail.example.com', 'WORSE', 'danger');
    assert.deepEqual(['danger', 'pkix', 'safe', 'error'].map((status) => problemOver(danger, e([{ key: 'smtp|mail.example.com', status }]))), [false, true, true, false]);
    assert.equal(problemOver(danger, e([])), true, 'no longer checked');
    const mxFailed = run('dane', [{ target: 'example.com', endpoints: [], domains: [{ domain: 'example.com', error: 'SERVFAIL', nullMx: false }] }]);
    assert.equal(problemOver(danger, mxFailed), false, 'gone with its MX lookup: not known');
    // audit: a rule that passes (one not checked counts as it was last checked); a domain added
    // that failed a rule, once no rule fails
    const a = (rules) => run('audit', [{ target: 'example.com', rules }]);
    const lock = open('audit', 'example.com', 'transferLock', 'WORSE');
    assert.equal(problemOver(lock, a([{ id: 'transferLock', status: 'fail' }])), false);
    assert.equal(problemOver(lock, a([{ id: 'transferLock', status: 'unknown', last: { status: 'fail', from: null } }])), false);
    assert.equal(problemOver(lock, a([{ id: 'transferLock', status: 'unknown' }])), false, 'never checked: not known');
    assert.equal(problemOver(lock, a([{ id: 'transferLock', status: 'pass' }])), true);
    assert.equal(problemOver(lock, a([])), true, 'no longer a rule');
    const added = open('audit', 'example.com', null, 'NEW');
    assert.equal(problemOver(added, a([{ id: 'transferLock', status: 'pass' }, { id: 'spf', status: 'unknown', last: { status: 'fail', from: null } }])), false);
    assert.equal(problemOver(added, a([{ id: 'transferLock', status: 'pass' }, { id: 'spf', status: 'pass' }])), true);
    // ct: a certificate renewed (superseded by a newer one for its names) ends EXPIRING / CA /
    // REVOKED; an issuer gone from a complete read ends ISSUER
    const ct = (certificates, extra = {}) => run('ct', [{ target: 'example.com', complete: true, issuers: [{ name: 'Example CA' }], certificates, ...extra }]);
    const cert = { key: 'k'.repeat(32), target: 'example.com', item: 'aaaaaaaaaaaaaaaa', tag: 'EXPIRING', since: null };
    assert.equal(problemOver(cert, ct([{ id: 'aaaaaaaaaaaaaaaa', flags: ['superseded'] }])), true);
    assert.equal(problemOver(cert, ct([{ id: 'aaaaaaaaaaaaaaaa', flags: [] }])), false);
    assert.equal(problemOver(cert, ct([])), false, 'a certificate no longer listed is no fix');
    assert.equal(problemOver({ ...cert, tag: 'CA' }, ct([{ id: 'aaaaaaaaaaaaaaaa', flags: ['expiring'] }])), false, 'another bad change of it ends nothing');
    const issuer = { ...cert, item: 'Odd CA', tag: 'ISSUER' };
    assert.equal(problemOver(issuer, ct([])), true);
    assert.equal(problemOver(issuer, ct([], { issuers: [{ name: 'Odd CA' }] })), false);
    assert.equal(problemOver(issuer, ct([], { complete: false })), false, 'a partial read proves nothing');
  });

  test('tls and takeover: a certificate\'s problem lasts while it is served, a risk while it is listed at its severity; a revoked or expired served certificate is critical', () => {
    // severity: a revoked certificate still served (as ct's), an endpoint that turned expired or untrusted
    assert.equal(eventSeverity({ tag: 'REVOKED', after: { state: 'revoked' } }, 'tls'), 'critical');
    for (const after of ['EXPIRED', 'UNTRUSTED']) assert.equal(eventSeverity({ tag: 'WORSE', after }, 'tls'), 'critical', after);
    for (const c of [{ tag: 'WORSE', after: 'NAME_MISMATCH' }, { tag: 'RENEW-NOW', after: { state: 'open' } }, { tag: 'MOVED-UP' }, { tag: 'CA-NOTICE' }, { tag: 'FAILED', after: 'TLS_ERROR' }]) {
      assert.equal(eventSeverity(c, 'tls'), 'error', c.tag);
    }
    assert.equal(eventSeverity({ tag: 'WORSE', after: 'EXPIRED' }, 'drift'), 'error', 'only tls\'s statuses');
    assert.equal(eventSeverity({ tag: 'RISK', after: 'critical' }, 'takeover'), 'critical');
    assert.equal(eventSeverity({ tag: 'RISK', after: 'high' }, 'takeover'), 'error');
    // the footer names what a target is
    const footer = (command, target) => notificationMessage({ ...reportOf([CHANGES[0]]), command, targets: [{ target }] }, { bad: false }).footer[0];
    assert.match(footer('tls', 'www.example.com'), /: 1 host \(www\.example\.com\)\.$/);
    assert.match(footer('takeover', 'example.com'), /: 1 domain \(example\.com\)\.$/);

    const run = (command, targets) => ({ ...reportOf([]), command, targets });
    const open = (command, target, item, tag, state) => ({ key: dedupKey(command, target, item, tag), target, item, tag, since: null, ...(state === undefined ? {} : { state }) });
    // tls: a certificate's problems (the item is its SHA-256) end once no endpoint serves it
    const SHA = 'a'.repeat(64);
    const OTHER = 'b'.repeat(64);
    const ep = (address, status, sha, extra = {}) => ({ address, port: 443, status, ...(sha ? { cert: { sha256: sha } } : {}), ...extra });
    const t = (endpoints, extra = {}) => run('tls', [{ target: 'www.example.com', dns: { status: 'NOERROR' }, endpoints, ...extra }]);
    for (const tag of ['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'REVOKED']) {
      const cert = open('tls', 'www.example.com', SHA, tag);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', SHA)])), false, `${tag}: still served`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', OTHER), ep('192.0.2.11', 'OK', SHA)])), false, `${tag}: still served by one address`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', OTHER), ep('192.0.2.11', 'NAME_MISMATCH', OTHER)])), true, `${tag}: renewed on every address`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', OTHER), ep('192.0.2.11', 'TLS_ERROR', null, { lastGood: { cert: { sha256: SHA } } })])), false, `${tag}: an address that served it could not be read`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', OTHER), ep('2001:db8::1', 'SKIPPED', null, { lastGood: { cert: { sha256: SHA } } })])), true, `${tag}: an IPv6 address this machine cannot reach says nothing`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'CLOSED', null)])), false, `${tag}: nothing read`);
      assert.equal(problemOver(cert, t([ep('192.0.2.10', 'OK', OTHER)], { carried: { from: null } })), false, `${tag}: a DNS lookup failed (last night's endpoints)`);
    }
    assert.equal(problemOver(open('tls', 'www.example.com', SHA, 'REVOKED'), run('tls', [])), true, 'the host is no longer checked');
    // an endpoint's (address|port): FAILED ends when a handshake completes, WORSE and RECOVERED when it is OK; CERT never
    const at = '192.0.2.10|443';
    assert.deepEqual(['TLS_ERROR', 'TIMEOUT', 'CLOSED', 'OK', 'UNTRUSTED', 'SKIPPED'].map((s) => problemOver(open('tls', 'www.example.com', at, 'FAILED'), t([ep('192.0.2.10', s, ['OK', 'UNTRUSTED'].includes(s) ? SHA : null)]))),
      [false, false, false, true, true, false]);
    assert.deepEqual(['OK', 'NAME_MISMATCH', 'EXPIRED', 'TIMEOUT'].map((s) => problemOver(open('tls', 'www.example.com', at, 'WORSE', 'EXPIRED'), t([ep('192.0.2.10', s, s === 'TIMEOUT' ? null : SHA)]))),
      [true, false, false, false]);
    assert.equal(problemOver(open('tls', 'www.example.com', at, 'RECOVERED', 'UNTRUSTED'), t([ep('192.0.2.10', 'OK', SHA)])), true);
    assert.equal(problemOver(open('tls', 'www.example.com', at, 'CERT'), t([ep('192.0.2.10', 'OK', SHA)])), false, 'another certificate: nothing says it is fixed');
    assert.equal(problemOver(open('tls', 'www.example.com', at, 'FAILED'), t([ep('192.0.2.11', 'OK', SHA)])), true, 'the address is no longer asked');
    assert.equal(problemOver(open('tls', 'www.example.com', at, 'FAILED'), t([ep('192.0.2.10', 'OK', SHA)], { carried: { from: null } })), false, 'carried');
    // the name that no longer resolves
    const gone = open('tls', 'www.example.com', null, 'GONE');
    assert.deepEqual([{ status: 'NXDOMAIN' }, { status: 'NOERROR' }, { status: 'SERVFAIL' }, null].map((dns) => problemOver(gone, t([ep('192.0.2.10', 'OK', SHA)], { dns }))), [false, true, false, false]);
    assert.equal(problemOver(gone, t([], { dns: { status: 'NOERROR' } })), false, 'no address to ask');

    // three nights of a revoked certificate: paged once, still open while it is served, resolved when it is replaced
    const revoked = change('REVOKED', 'bad', 'www.example.com', SHA, 'revoked by its CA, still served', { kind: 'changed', after: { state: 'revoked' } });
    const night = (endpoints, changes) => ({ ...t(endpoints), changes });
    const plan1 = pagerDutyPlan(night([ep('192.0.2.10', 'OK', SHA)], [revoked]), null);
    assert.deepEqual([plan1.triggers.length, plan1.resolves.length, plan1.open.map((e) => [e.tag, e.item])], [1, 0, [['REVOKED', SHA]]]);
    const plan2 = pagerDutyPlan(night([ep('192.0.2.10', 'OK', SHA)], []), { notify: { open: plan1.open } });
    assert.deepEqual([plan2.triggers.length, plan2.resolves.length, plan2.open.length], [0, 0, 1], 'still served: the incident stays open');
    const plan3 = pagerDutyPlan(night([ep('192.0.2.10', 'OK', OTHER)], []), { notify: { open: plan2.open } });
    assert.deepEqual([plan3.resolves.map((e) => e.key), plan3.open], [[plan1.triggers[0].key], []], 'replaced: resolved');
    const [request] = pagerDutyRequests({ url: PAGERDUTY_URL }, night([], [revoked]), plan1, { tool: DS_TOOL, version: DS_VERSION });
    assert.equal(JSON.parse(request.body).payload.severity, 'critical');

    // takeover: a risk is over once the report no longer lists it or lists it below the severity it was paged at
    assert.equal(TAKEOVER_COUNTED, COUNTED_SEVERITY, 'the severity a takeover change counts at (states.mjs cannot import takeover.mjs)');
    const tk = (risks) => run('takeover', [{ target: 'example.com', risks }]);
    const KEY = 'ns|example.com|ns.example.net';
    const risk = open('takeover', 'example.com', KEY, 'RISK', 'critical');
    assert.deepEqual(['critical', 'high', 'medium', 'low', 'info'].map((severity) => problemOver(risk, tk([{ key: KEY, severity }]))), [false, true, true, true, true]);
    assert.equal(problemOver(risk, tk([])), true, 'gone');
    assert.equal(problemOver(risk, tk([{ key: KEY, severity: 'info', carried: { from: null } }])), false, 'carried over a lookup that failed: not known gone');
    assert.equal(problemOver({ ...risk, state: undefined }, tk([{ key: KEY, severity: 'low' }])), false, 'without its state: over once gone');
    assert.equal(problemOver(open('takeover', 'example.com', KEY, 'WORSE', 'high'), tk([{ key: KEY, severity: 'high' }])), false);
    const added = open('takeover', 'example.com', null, 'NEW');
    assert.deepEqual([[{ key: 'a', severity: 'medium' }], [{ key: 'a', severity: 'low' }, { key: 'b', severity: 'info' }], [], [{ key: 'a', severity: 'low', carried: { from: null } }]].map((risks) => problemOver(added, tk(risks))),
      [false, true, true, false]);
    // paged at the severity, resolved when the risk is gone
    const found = change('RISK', 'bad', 'example.com', KEY, 'critical NS example.com → ns.example.net', { kind: 'appeared', after: 'critical' });
    const p1 = pagerDutyPlan({ ...tk([{ key: KEY, severity: 'critical' }]), changes: [found] }, null);
    assert.deepEqual(p1.open.map((e) => [e.tag, e.item, e.state]), [['RISK', KEY, 'critical']]);
    const p2 = pagerDutyPlan({ ...tk([]), changes: [change('GONE', 'good', 'example.com', KEY, 'gone', { kind: 'disappeared', before: 'critical' })] }, { notify: { open: p1.open } });
    assert.deepEqual([p2.resolves.length, p2.open], [1, []]);
  });

  test('at most 50 events a run, triggers first; resolves left out stay open (over) and go with the next run; the open keys are capped', () => {
    const open = Array.from({ length: 10 }, (_, i) => ({ key: dedupKey('health', 'example.com', `old-${i}`, 'NEW'), target: 'example.com', item: `old-${i}`, tag: 'NEW', since: null }));
    const fixes = open.map((e) => change('GONE', 'good', 'example.com', e.item, 'gone'));
    const bad = Array.from({ length: 45 }, (_, i) => change('NEW', 'bad', 'example.com', `new-${i}`, 'new', { after: 'error' }));
    // the new findings stand, the old ones are gone
    const checked = (changes) => reportOf(changes, { targets: [{ target: 'example.com', checks: bad.map((c) => ({ id: c.item, severity: 'error' })) }] });
    const plan = pagerDutyPlan(checked([...bad, ...fixes]), { notify: { open } });
    assert.equal(PAGERDUTY_MAX_EVENTS, 50);
    assert.deepEqual([plan.triggers.length, plan.resolves.length, plan.cut], [45, 5, 0]);
    const deferred = plan.open.filter((e) => e.over);
    assert.deepEqual(deferred.map((e) => e.item), ['old-5', 'old-6', 'old-7', 'old-8', 'old-9']);
    assert.equal(plan.open.length, 5 + 45);
    // the next run sends the deferred resolves whatever it finds
    const next = pagerDutyPlan(checked([]), { notify: { open: plan.open } });
    assert.deepEqual(next.resolves.map((e) => e.item), ['old-5', 'old-6', 'old-7', 'old-8', 'old-9']);
    assert.equal(next.open.length, 45);
    // a flood: the triggers past 50 are cut (said on stderr), never opened
    const flood = pagerDutyPlan(reportOf(Array.from({ length: 70 }, (_, i) => change('NEW', 'bad', 'example.com', `f-${i}`, 'new'))), null);
    assert.deepEqual([flood.triggers.length, flood.cut, flood.open.length], [50, 20, 50]);
    // the open keys kept: the newest PAGERDUTY_MAX_OPEN
    const many = Array.from({ length: PAGERDUTY_MAX_OPEN + 20 }, (_, i) => ({ key: dedupKey('health', 'example.com', `k-${i}`, 'NEW'), target: 'example.com', item: `k-${i}`, tag: 'NEW', since: null }));
    const capped = pagerDutyPlan(reportOf([], { targets: [{ target: 'example.com', checks: many.map((e) => ({ id: e.item, severity: 'warn' })) }] }), { notify: { open: many } });
    assert.equal(capped.open.length, PAGERDUTY_MAX_OPEN);
    assert.equal(capped.open[0].item, 'k-20');
  });

  test('the keys open after a run are what was delivered: a trigger not sent opens nothing, a resolve not sent leaves its key as it was', () => {
    const key = (item, extra = {}) => ({ key: dedupKey('health', 'example.com', item, 'NEW'), target: 'example.com', item, tag: 'NEW', since: null, state: 'error', ...extra });
    const baseline = { notify: { open: [key('kept'), key('fixed-1'), key('fixed-2', { over: true })] } };
    const report = reportOf(['new-1', 'new-2'].map((id) => change('NEW', 'bad', 'example.com', id, 'new', { after: 'error' })),
      { targets: [{ target: 'example.com', checks: ['kept', 'new-1', 'new-2'].map((id) => ({ id, severity: 'error' })) }] });
    const plan = pagerDutyPlan(report, baseline);
    assert.deepEqual(plan.resolves.map((e) => e.item), ['fixed-1', 'fixed-2']);
    assert.deepEqual(plan.open, keysOpenAfter(plan), 'the plan\'s own: everything delivered');
    assert.deepEqual(plan.open.map((e) => e.item), ['kept', 'new-1', 'new-2']);
    const open = keysOpenAfter(plan, { triggered: new Set([plan.triggers[0].key]), resolved: new Set([plan.resolves[0].key]) });
    assert.deepEqual(open.map((e) => [e.item, e.over === true, e.state]), [['kept', false, 'error'], ['fixed-2', true, 'error'], ['new-1', false, 'error']]);
    assert.deepEqual(keysOpenAfter(plan, { triggered: new Set(), resolved: new Set() }).map((e) => e.item), ['kept', 'fixed-1', 'fixed-2']);
  });

  test('a baseline\'s open keys are checked: anything else in the list is dropped, a state that is not a short text or a number too', () => {
    const good = { key: 'a'.repeat(32), target: 'example.com', item: null, tag: 'SCORE', since: '2026-09-27T03:00:00.000Z' };
    assert.deepEqual(openKeysOf({ notify: { open: [good, { ...good }, { ...good, key: 'b'.repeat(32), over: true }, { ...good, key: 'xyz' }, { ...good, key: 'c'.repeat(32), tag: 'lower' },
      { ...good, key: 'd'.repeat(32), target: 5 }, { ...good, key: 'e'.repeat(32), item: 7 }, null, 'text'] } }), [good, { ...good, key: 'b'.repeat(32), over: true }]);
    for (const doc of [null, {}, { notify: null }, { notify: { open: 'x' } }, { notify: [] }]) assert.deepEqual(openKeysOf(doc), []);
    assert.deepEqual(openKeysOf({ notify: { open: [{ ...good, state: 70 }, { ...good, key: 'f'.repeat(32), state: 'warn' }, { ...good, key: '1'.repeat(32), state: { x: 1 } },
      { ...good, key: '2'.repeat(32), state: 'x'.repeat(65) }, { ...good, key: '3'.repeat(32), state: Infinity }] } }).map((e) => e.state),
    [70, 'warn', undefined, undefined, undefined]);
  });
});

/* ------------------------------------------------------------------------ */
/* PagerDuty over several nights (the diffs as the runner makes them)       */
/* ------------------------------------------------------------------------ */

describe('PagerDuty over several nights', () => {
  /**
   * Night after night of `command`, each report compared with the one before as the runner does
   * (diffReports, what a night could not read carried: carry.mjs), each with its PagerDuty plan;
   * the keys a night leaves open go into its report, the next night's baseline. Returns per night
   * the changes (TAG/tone), the triggers, the resolves and the keys open (TAG item).
   */
  async function nights(command, perNight) {
    const t = await setupStrings();
    const out = [];
    let prev = null;
    for (const [i, raw] of perNight.entries()) {
      const startedAt = `2026-10-0${i + 1}T03:00:00.000Z`;
      const targets = raw.map((x) => {
        const p = prev && prev.targets.find((y) => y.target === x.target);
        if (command === 'health') {
          const carried = carryHealth(x, p || null, { prevAt: prev ? prev.startedAt : null });
          return carried.length ? { ...x, carried } : x;
        }
        if (command === 'subdomains') return { ...x, hosts: carryHosts(x.hosts, p || null, { prevAt: prev ? prev.startedAt : null }) };
        return x;
      });
      const report = { tool: DS_TOOL, version: DS_VERSION, command, startedAt, finishedAt: startedAt, options: {}, targets };
      const night = { changes: [], triggers: [], resolves: [], open: [] };
      if (prev) {
        report.baseline = { file: `${command}.json`, missing: false, finishedAt: prev.finishedAt };
        report.changes = diffReports(command, prev, report, { t }).map((c) => ({
          tag: c.tag, tone: c.tone, counts: c.counts, target: c.target, item: c.item, kind: c.kind, before: c.before, after: c.after, text: changeText(c)
        }));
        const plan = pagerDutyPlan(report, prev);
        if (plan.open.length) report.notify = { open: plan.open };
        const named = (e) => `${e.tag}${e.item === null ? '' : ` ${e.item}`}`;
        Object.assign(night, {
          changes: report.changes.map((c) => `${c.tag}/${c.counts ? c.tone : 'listed'}`),
          triggers: plan.triggers.map((x) => named(x.change)), resolves: plan.resolves.map(named), open: plan.open.map(named)
        });
      }
      out.push(night);
      prev = report;
    }
    return out;
  }

  const answer = (over = {}) => ({ name: 'www.example.com', status: 'NOERROR', kind: 'cdn', provider: 'Cloudflare', providerId: 'cloudflare', hidesOrigin: true, dangling: false, ipv4: ['104.16.1.1'], ipv6: [], cnames: [], ...over });
  const PROXIED = answer();
  const DIRECT = answer({ kind: 'direct', provider: null, providerId: null, hidesOrigin: false, ipv4: ['192.0.2.10'] });
  const SERVFAIL = { name: 'www.example.com', status: 'SERVFAIL', kind: null, provider: null, hidesOrigin: false, dangling: false, ipv4: [], ipv6: [], cnames: [] };
  const sub = (host) => [{ target: 'example.com', mode: 'exact', hosts: [host] }];

  test('subdomains: an origin exposed, then back behind its CDN (a CHANGED, not a good change) is resolved', async () => {
    const [, exposed, back] = await nights('subdomains', [sub(PROXIED), sub(DIRECT), sub(PROXIED)]);
    assert.deepEqual(exposed, { changes: ['EXPOSED/bad'], triggers: ['EXPOSED www.example.com'], resolves: [], open: ['EXPOSED www.example.com'] });
    assert.deepEqual(back, { changes: ['CHANGED/info'], triggers: [], resolves: ['EXPOSED www.example.com'], open: [] });
  });

  test('subdomains: a lookup that fails one night ends nothing — the origin still exposed after it stays paged until it is behind its CDN', async () => {
    const [, exposed, failed, answers, fixed] = await nights('subdomains', [sub(PROXIED), sub(DIRECT), sub(SERVFAIL), sub(DIRECT), sub(PROXIED)]);
    assert.deepEqual(exposed.open, ['EXPOSED www.example.com']);
    assert.deepEqual(failed, { changes: ['FAILED/bad'], triggers: ['FAILED www.example.com'], resolves: [], open: ['EXPOSED www.example.com', 'FAILED www.example.com'] });
    assert.deepEqual(answers, { changes: ['RECOVERED/good'], triggers: [], resolves: ['FAILED www.example.com'], open: ['EXPOSED www.example.com'] });
    assert.deepEqual(fixed, { changes: ['CHANGED/info'], triggers: [], resolves: ['EXPOSED www.example.com'], open: [] });
  });

  test('subdomains: a dangling alias through a failed lookup, then removed (now resolving: an info change) — both resolved', async () => {
    const DANGLING = answer({ kind: null, provider: null, providerId: null, hidesOrigin: false, dangling: true, ipv4: [], cnames: ['gone.example.net'] });
    const [, dangling, failed, fixed] = await nights('subdomains', [sub(PROXIED), sub(DANGLING), sub(SERVFAIL), sub(PROXIED)]);
    assert.deepEqual(dangling.triggers, ['DANGLING www.example.com']);
    assert.deepEqual([failed.triggers, failed.resolves, failed.open], [['FAILED www.example.com'], [], ['DANGLING www.example.com', 'FAILED www.example.com']]);
    assert.deepEqual(fixed, { changes: ['NEW/info'], triggers: [], resolves: ['DANGLING www.example.com', 'FAILED www.example.com'], open: [] });
  });

  test('audit: a domain added that fails a rule pages once; it is resolved the night every rule passes', async () => {
    const domain = (target, lock) => ({ target, rules: [{ id: 'transferLock', required: 'true', status: lock }, { id: 'expiryDays', required: '>= 30', status: 'pass' }] });
    const [, added, still, fixed] = await nights('audit', [
      [domain('example.com', 'pass')],
      [domain('example.com', 'pass'), domain('example.org', 'fail')],
      [domain('example.com', 'pass'), domain('example.org', 'fail')],
      [domain('example.com', 'pass'), domain('example.org', 'pass')]
    ]);
    assert.deepEqual(added, { changes: ['NEW/bad'], triggers: ['NEW'], resolves: [], open: ['NEW'] });
    assert.deepEqual(still, { changes: [], triggers: [], resolves: [], open: ['NEW'] });
    assert.deepEqual(fixed, { changes: ['BETTER/good'], triggers: [], resolves: ['NEW'], open: [] });
  });

  test('audit: a rule that fails stays paged through a night it could not be checked (its last status carried), then passes', async () => {
    const domain = (lock, last) => [{ target: 'example.com', rules: [{ id: 'transferLock', required: 'true', status: lock, ...(last ? { last } : {}) }] }];
    const [, failing, unchecked, fixed] = await nights('audit', [domain('pass'), domain('fail'), domain('unknown', { status: 'fail', evidence: '', from: '2026-10-02T03:00:00.000Z' }), domain('pass')]);
    assert.deepEqual(failing.triggers, ['WORSE transferLock']);
    assert.deepEqual(unchecked, { changes: ['FAILED/listed'], triggers: [], resolves: [], open: ['WORSE transferLock'] });
    assert.deepEqual(fixed, { changes: ['BETTER/good'], triggers: [], resolves: ['WORSE transferLock'], open: [] });
  });

  test('renew: a name that could not be checked, then checked again at "warnings" (an info change) — its FAILED is resolved', async () => {
    const name = (verdict) => [{ target: 'www.example.com', verdict, findings: [] }];
    const [, failed, again] = await nights('renew', [name('warnings'), name('unknown'), name('warnings')]);
    assert.deepEqual(failed, { changes: ['FAILED/bad'], triggers: ['FAILED'], resolves: [], open: ['FAILED'] });
    assert.deepEqual(again, { changes: ['RECOVERED/info'], triggers: [], resolves: ['FAILED'], open: [] });
  });

  test('renew: a verdict worse stays paged while it stands and through a night it could not be checked, until it is back', async () => {
    const name = (verdict) => [{ target: 'www.example.com', verdict, findings: [] }];
    const [, worse, same, unchecked, back] = await nights('renew', [name('ready'), name('warnings'), name('warnings'), name('unknown'), name('ready')]);
    assert.deepEqual(worse.open, ['WORSE']);
    assert.deepEqual([same.resolves, same.open], [[], ['WORSE']]);
    assert.deepEqual([unchecked.triggers, unchecked.resolves, unchecked.open], [['FAILED'], [], ['WORSE', 'FAILED']]);
    assert.deepEqual([back.changes, back.resolves, back.open], [['RECOVERED/good'], ['WORSE', 'FAILED'], []]);
  });

  test('health: a finding worse stays paged through a night its lookup failed, and is resolved when it is back where it was', async () => {
    const domain = (checks, score = 80) => [{ target: 'example.com', score, checks }];
    const [, worse, failed, back] = await nights('health', [
      domain([{ id: 'dmarc.policy', severity: 'warn' }]),
      domain([{ id: 'dmarc.policy', severity: 'error' }]),
      domain([{ id: 'dmarc.error', severity: 'warn' }]),
      domain([{ id: 'dmarc.policy', severity: 'warn' }])
    ]);
    assert.deepEqual(worse.triggers, ['WORSE dmarc.policy']);
    assert.deepEqual([failed.triggers, failed.resolves, failed.open], [['NEW dmarc.error'], [], ['WORSE dmarc.policy', 'NEW dmarc.error']]);
    assert.deepEqual([back.resolves, back.open], [['WORSE dmarc.policy', 'NEW dmarc.error'], []]);
  });

  test('drift: a record set moved to an info status stays paged on a night with no change, until it matches again', async () => {
    const zone = (status, nsMatch = 'same') => [{ target: 'example.com', preflight: { nsMatch }, rows: [{ key: 'mail.example.com|A', name: 'mail.example.com', type: 'A', status, reasons: [] }] }];
    const [, moved, same, back] = await nights('drift', [zone('match'), zone('occluded'), zone('occluded'), zone('match')]);
    assert.deepEqual(moved.triggers, ['WORSE mail.example.com|A']);
    assert.deepEqual([same.resolves, same.open], [[], ['WORSE mail.example.com|A']]);
    assert.deepEqual(back.resolves, ['WORSE mail.example.com|A']);
    const [, overlap, disjoint, better, fixed] = await nights('drift', [zone('match'), zone('match', 'overlap'), zone('match', 'disjoint'), zone('match', 'overlap'), zone('match')]);
    assert.deepEqual(overlap.triggers, ['WORSE NS']);
    assert.deepEqual([disjoint.triggers, disjoint.open], [['WORSE NS'], ['WORSE NS']]);
    assert.deepEqual([better.changes, better.resolves, better.open], [['BETTER/good'], [], ['WORSE NS']], 'better, but not back where it paged');
    assert.deepEqual(fixed.resolves, ['WORSE NS']);
  });
});

/* ------------------------------------------------------------------------ */
/* Delivery                                                                 */
/* ------------------------------------------------------------------------ */

describe('delivery', () => {
  const request = { url: HOOK_URL, headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: '{}', secrets: [] };

  test('one retry for a 5xx, a 429 and a network error, after Retry-After; a 4xx is the webhook\'s answer; no redirect followed', async () => {
    const slept = [];
    const sleep = async (ms) => { slept.push(ms); };
    let hook = webhook([500, 200]);
    assert.equal(await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep }), null);
    assert.deepEqual([hook.requests.length, slept], [2, [2000]]);
    assert.equal(hook.requests[0].redirect, 'manual');
    assert.equal(hook.requests[0].method, 'POST');
    hook = webhook([new Response('slow down', { status: 429, headers: { 'Retry-After': '7' } }), 204]);
    assert.equal(await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep }), null);
    assert.equal(slept.at(-1), 7000);
    hook = webhook([new Response('slow', { status: 429, headers: { 'Retry-After': '120' } }), 200]);
    await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep });
    assert.equal(slept.at(-1), 10000, 'at most 10 s');
    hook = webhook([503, 503, 200]);
    assert.deepEqual(await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep }), { problem: 'HTTP 503 Bad: error 503' });
    assert.equal(hook.requests.length, 2, 'one retry, not more');
    hook = webhook([new Response(`no_service for /hooks/${TOKEN}`, { status: 404, statusText: 'Not Found' })]);
    assert.deepEqual(await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep }), { problem: 'HTTP 404 Not Found: no_service for ***' });
    assert.equal(hook.requests.length, 1, 'a 4xx is not retried');
    hook = webhook([new Response('', { status: 302, statusText: 'Found', headers: { Location: '/elsewhere' } })]);
    assert.deepEqual(await deliver(request, HOOK_URL, { fetchImpl: hook.fetch, sleep }), { problem: 'HTTP 302 Found (a redirect; not followed)' });
    let calls = 0;
    const refused = async () => {
      calls += 1;
      throw new TypeError('fetch failed', { cause: Object.assign(new Error(`connect ECONNREFUSED ${HOOK_URL}`), { code: 'ECONNREFUSED' }) });
    };
    const failed = await deliver(request, HOOK_URL, { fetchImpl: refused, sleep });
    assert.equal(calls, 2);
    assert.equal(failed.problem, 'connect ECONNREFUSED ***');
  });

  test('a webhook that never answers times out (twice: one retry); the run\'s signal stops it as interrupted', async () => {
    const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
    let calls = 0;
    const counted = (url, init) => {
      calls += 1;
      return hang(url, init);
    };
    assert.deepEqual(await deliver(request, HOOK_URL, { fetchImpl: counted, timeoutMs: 30, retryDelayMs: 1 }), { problem: 'timed out' });
    assert.equal(calls, 2);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    assert.deepEqual(await deliver(request, HOOK_URL, { fetchImpl: hang, signal: controller.signal, timeoutMs: 5000 }), { problem: 'interrupted', interrupted: true });
  });

  test('sendNotifications: --notify when a change counts (or always), --notify-bad when one is bad, PagerDuty when it has events; a route stops at its first failure', async () => {
    const report = reportOf(CHANGES);
    const hook = webhook([200, 200, 500, 500]);
    const routes = [
      { url: SLACK_URL, format: 'slack', bad: false, source: '--notify' },
      { url: HOOK_URL, format: 'json', bad: true, source: '--notify-bad' },
      { url: PAGERDUTY_URL, format: 'pagerduty', bad: true, source: NOTIFY_ENV.bad }
    ];
    const sent = await sendNotifications(report, routes, { fetchImpl: hook.fetch, timing: FAST, tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual(sent.results.map((r) => [r.route.format, r.total, r.sent, r.carries, r.problem]), [
      ['slack', 1, 1, true, null], ['json', 1, 1, true, null], ['pagerduty', 1, 0, true, 'HTTP 500 Bad: error 500']
    ]);
    assert.deepEqual(sent.open, [], 'a trigger that was not delivered opens no key');
    // nothing that counts: only --notify-always posts, on the --notify route
    const none = reportOf([CHANGES[2]]);
    const quiet = webhook();
    const r1 = await sendNotifications(none, routes, { fetchImpl: quiet.fetch, tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual([quiet.requests.length, r1.results.map((r) => r.total)], [0, [0, 0, 0]]);
    const r2 = await sendNotifications(none, routes, { always: true, fetchImpl: quiet.fetch, tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual([quiet.requests.length, r2.results.map((r) => [r.total, r.carries])], [1, [[1, false], [0, false], [0, false]]]);
    assert.match(JSON.parse(quiet.requests[0].body).text, /^\*DomainScope health: no changes since /);
  });

  test('sendNotifications: the PagerDuty keys open as delivered — a trigger taken by any PagerDuty URL opens its key, a resolve closes it once every one took it', async () => {
    const key = (item) => ({ key: dedupKey('health', 'example.com', item, 'NEW'), target: 'example.com', item, tag: 'NEW', since: null, state: 'error' });
    const baseline = { notify: { open: [key('fixed')] } };
    const report = reportOf(['new-1', 'new-2'].map((id) => change('NEW', 'bad', 'example.com', id, 'new', { after: 'error' })),
      { targets: [{ target: 'example.com', checks: ['new-1', 'new-2'].map((id) => ({ id, severity: 'error' })) }] });
    const EU_URL = 'https://events.eu.pagerduty.com/v2/enqueue?routing_key=' + ROUTING_KEY;
    const routes = [PAGERDUTY_URL, EU_URL].map((url) => ({ url, format: 'pagerduty', bad: true, source: NOTIFY_ENV.bad }));
    // the US service takes every event; the EU one the first trigger, then fails
    const hook = webhook([202, 202, 202, 202, 500, 500]);
    const sent = await sendNotifications(report, routes, { baseline, fetchImpl: hook.fetch, timing: FAST, tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual(sent.results.map((r) => [r.sent, r.total, r.triggered, r.resolved]), [[3, 3, 2, 1], [1, 3, 1, 0]]);
    assert.deepEqual(sent.open.map((e) => e.item), ['fixed', 'new-1', 'new-2'], 'the EU service still has "fixed" open');
    // every event delivered everywhere: the plan's keys
    const all = await sendNotifications(report, routes, { baseline, fetchImpl: webhook().fetch, timing: FAST, tool: DS_TOOL, version: DS_VERSION });
    assert.deepEqual(all.open.map((e) => e.item), ['new-1', 'new-2']);
  });

  test('an answer that echoes a secret is redacted before it is cut: no piece of it at the 200-character cut, nor where the 512 bytes read end', async () => {
    const sleep = async () => {};
    for (const [url, secret, extra] of [[PAGERDUTY_URL, ROUTING_KEY, [ROUTING_KEY]], [HOOK_URL, TOKEN, []], [NTFY_URL, 'tk_' + 'examplevalue0123', ['tk_' + 'examplevalue0123']]]) {
      const bodies = [
        ...[150, 180, 190, 195, 199].map((n) => `${'e'.repeat(n)} ${secret} tail`),
        JSON.stringify({ message: `${'m'.repeat(185)} ${secret}` }),
        // the 512 bytes read end inside the secret (at byte 500 + 12): the spaces collapse, what is left is short
        `${' '.repeat(498)}x ${secret}${'z'.repeat(600)}`,
        `${'ü'.repeat(150)}${' '.repeat(198)}x ${secret}${'z'.repeat(600)}`
      ];
      for (const body of bodies) {
        const fetchImpl = async () => new Response(body, { status: 400, statusText: 'Bad Request' });
        const { problem } = await deliver({ url, headers: {}, body: '{}', secrets: extra }, url, { fetchImpl, sleep });
        assert.ok(problem.startsWith('HTTP 400 Bad Request'), problem);
        for (let n = 4; n <= secret.length; n += 1) assert.ok(!problem.includes(secret.slice(0, n)), `${problem.slice(-30)}: ${n} characters of the secret`);
      }
    }
    // the reason in a status line too
    const fetchImpl = async () => new Response('x', { status: 400, statusText: `Bad key ${ROUTING_KEY}` });
    assert.deepEqual(await deliver({ url: PAGERDUTY_URL, headers: {}, body: '{}', secrets: [ROUTING_KEY] }, PAGERDUTY_URL, { fetchImpl, sleep }), { problem: 'HTTP 400 Bad key ***: x' });
    // responseDetail on its own: the redaction given goes before the cut
    assert.equal(responseDetail(`${'e'.repeat(195)} ${TOKEN}`, (s) => s.split(TOKEN).join('***')), `${'e'.repeat(195)} ***`);
  });
});

/* ------------------------------------------------------------------------ */
/* Runs of the runner                                                       */
/* ------------------------------------------------------------------------ */

describe('runs of the runner (main)', () => {
  test('two nights of drift: the chat gets every change, the pager the bad one only; PagerDuty triggers, then resolves', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'drift.json');
      const env = { [NOTIFY_ENV.url]: SLACK_URL, [NOTIFY_ENV.bad]: `${PAGERDUTY_URL} ${HOOK_URL}`, GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'example/nightly', GITHUB_RUN_ID: '42' };
      const argv = ['drift', CF_EXPORT, '--baseline', json, '--json', json, '--fail-on-notify-error'];
      const first = await runDs(argv, { env });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.equal(first.hook.requests.length, 0, 'a first run has nothing to say');

      const second = await runDs([...argv, '--fail-on-change'], { table: movedZone(), env });
      assert.equal(second.code, EXIT.CHANGED, second.err);
      const [chat, pager, hook] = second.hook.requests;
      assert.equal(second.hook.requests.length, 3);
      assert.match(JSON.parse(chat.body).text, /^\*DomainScope drift: 2 changes since 2026-09-28 03:00 UTC\*\n```\n- BETTER example\.com: www\.example\.com A — .*\n- WORSE example\.com: mail\.example\.com A — Matches → Differs\nRun of 2026-09-28 03:00 UTC: 1 zone \(example\.com\)\.\nRun: https:\/\/github\.com\/example\/nightly\/actions\/runs\/42\n```$/);
      const trigger = JSON.parse(pager.body);
      assert.equal(pager.url, 'https://events.pagerduty.com/v2/enqueue');
      assert.deepEqual([trigger.event_action, trigger.dedup_key, trigger.payload.severity, trigger.payload.component, trigger.payload.source, trigger.client_url],
        ['trigger', '76ba01e87c44289e10e6ce396ed86f09', 'error', 'example.com', 'domainscope:drift', 'https://github.com/example/nightly/actions/runs/42']);
      const bad = JSON.parse(hook.body);
      assert.deepEqual(bad.changes.map((c) => `${c.tag} ${c.item}`), ['WORSE mail.example.com|A'], 'the bad route: the bad change only');
      assert.equal(bad.run, 'https://github.com/example/nightly/actions/runs/42');
      assert.match(second.err, /ds: notification sent \(slack, hooks\.slack\.com\)\nds: notification sent \(pagerduty, events\.pagerduty\.com, --notify-bad\): 1 triggered, 0 resolved\nds: notification sent \(json, hooks\.example\.com, --notify-bad\)\nds: JSON report written to /);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.notify, { open: [{ key: '76ba01e87c44289e10e6ce396ed86f09', target: 'example.com', item: 'mail.example.com|A', tag: 'WORSE', since: NOW.toISOString(), state: 'differs' }] });

      // the third night mail is back: the chat says so, PagerDuty resolves the incident
      const third = await runDs(argv, { table: Object.assign(movedZone(), { 'mail.example.com': zoneTable()['mail.example.com'] }), env });
      assert.equal(third.code, EXIT.OK, third.err);
      assert.equal(third.hook.requests.length, 2, 'the slack message and the resolve; the bad route has no bad change');
      assert.deepEqual(JSON.parse(third.hook.requests[1].body), { routing_key: ROUTING_KEY, event_action: 'resolve', dedup_key: '76ba01e87c44289e10e6ce396ed86f09' });
      assert.match(third.err, /notification sent \(pagerduty, events\.pagerduty\.com, --notify-bad\): 0 triggered, 1 resolved/);
      assert.equal(JSON.parse(readFileSync(json, 'utf8')).notify, undefined, 'no key open any more');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('no URL in stdout, stderr, the JSON report or the Markdown, whether the messages go out or fail', async () => {
    const secrets = [TOKEN, ROUTING_KEY, 'domainscope-example-alerts', 'tk_' + 'examplevalue', 'Signing' + 'Secret0', HOOK_URL, PAGERDUTY_URL, NTFY_URL];
    for (const fail of [false, true]) {
      const dir = tmp();
      try {
        const json = join(dir, 'drift.json');
        const md = join(dir, 'drift.md');
        const echo = (url, init) => new Response(`refused ${url} ${JSON.stringify(init.headers)} ${init.body}`, { status: 400, statusText: 'Bad Request' });
        const env = { [NOTIFY_ENV.bad]: PAGERDUTY_URL, [NOTIFY_ENV.url]: NTFY_URL, [NOTIFY_ENV.ntfyToken]: 'tk_' + 'examplevalue', [NOTIFY_ENV.secret]: 'Signing' + 'Secret0' };
        // the command line's --notify URLs (the environment's are then left out), the environment's --notify-bad one
        const argv = ['drift', CF_EXPORT, '--baseline', json, '--json', json, '--md', md, '--notify', HOOK_URL, '--notify', NTFY_URL, '--notify-always'];
        const first = await runDs(argv, { env });
        const second = await runDs([...argv, '--show-all'], { table: movedZone(), env, hook: webhook(fail ? [echo, echo, echo, echo, echo, echo] : []) });
        assert.equal(second.code, EXIT.OK, second.err);
        assert.equal(second.hook.requests.length, 3, 'json, ntfy and the PagerDuty trigger');
        if (fail) assert.equal((second.err.match(/error: notification failed/g) || []).length, 3, second.err);
        const files = readdirSync(dir).map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
        const seen = [first.out, first.err, second.out, second.err, files].join('\n');
        for (const s of secrets) assert.ok(!seen.includes(s), `${fail ? 'failed' : 'sent'}: ${s.slice(0, 12)}… leaked`);
        assert.match(second.err, /\((json|ntfy|pagerduty), (hooks\.example\.com|ntfy\.sh|events\.pagerduty\.com)/, 'the hosts are named');
        // the signed JSON message went out with its signature
        const sent = second.hook.requests.find((r) => r.url === HOOK_URL);
        assert.equal(sent.headers['X-DomainScope-Signature'], signBody('Signing' + 'Secret0', sent.headers['X-DomainScope-Timestamp'], sent.body));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  test('a message with changes that did not go out keeps the previous baseline; the next run sends them again', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'drift.json');
      const argv = ['drift', CF_EXPORT, '--baseline', json, '--json', json, '--notify', HOOK_URL, '--fail-on-notify-error', '--fail-on-change'];
      await runDs(argv);
      const previous = readFileSync(json);
      const down = await runDs(argv, { table: movedZone(), hook: webhook([503, 503]) });
      assert.equal(down.code, EXIT.NOTIFY, down.err);
      assert.equal(down.hook.requests.length, 2, 'one retry');
      assert.match(down.err, /ds: error: notification failed \(json, hooks\.example\.com\): HTTP 503 Bad: error 503\n/);
      assert.match(down.err, /ds: kept the previous baseline in .*drift\.json \(this report is not written there\): the 2 changes will be reported again on the next run/);
      assert.ok(!down.err.includes('JSON report written'));
      assert.deepEqual(readFileSync(json), previous);
      assert.deepEqual(readdirSync(dir), ['drift.json'], 'no temporary file left');
      // the webhook is back: the same changes go out, then the report moves on
      const back = await runDs(argv, { table: movedZone() });
      assert.equal(back.code, EXIT.CHANGED, back.err);
      assert.equal(JSON.parse(back.hook.requests[0].body).changesTotal, 2);
      assert.ok(back.err.indexOf('notification sent') < back.err.indexOf('JSON report written'));
      const after = await runDs(argv, { table: movedZone() });
      assert.deepEqual([after.code, after.hook.requests.length], [EXIT.OK, 0]);
      // a report that is not the baseline is written all the same
      const other = join(dir, 'other.json');
      const failed = await runDs(['drift', CF_EXPORT, '--baseline', json, '--json', other, '--notify', HOOK_URL, '--notify-always'], { hook: webhook([400]) });
      assert.equal(failed.code, EXIT.OK, 'without --fail-on-notify-error');
      assert.ok(existsSync(other));
      assert.doesNotMatch(failed.err, /kept the previous baseline/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a baseline kept because the chat failed still notes what PagerDuty got: the night the problem is fixed resolves it', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'drift.json');
      const argv = ['drift', CF_EXPORT, '--baseline', json, '--json', json, '--notify', HOOK_URL, '--notify-bad', PAGERDUTY_URL, '--fail-on-notify-error'];
      await runDs(argv);
      const first = JSON.parse(readFileSync(json, 'utf8'));
      assert.equal(first.notify, undefined);
      // night 2: mail's address is wrong (WORSE, bad); the chat answers 503 twice, PagerDuty takes the trigger
      const second = await runDs(argv, { table: movedZone(), hook: webhook([503, 503, 202]) });
      assert.equal(second.code, EXIT.NOTIFY, second.err);
      assert.match(second.err, /ds: error: notification failed \(json, hooks\.example\.com\): HTTP 503 Bad: error 503\n/);
      assert.match(second.err, /ds: notification sent \(pagerduty, events\.pagerduty\.com, --notify-bad\): 1 triggered, 0 resolved\n/);
      assert.match(second.err, /ds: kept the previous baseline in .*drift\.json \(this report is not written there; the PagerDuty incidents still open are noted in it\): the 2 changes will be reported again on the next run/);
      const kept = JSON.parse(readFileSync(json, 'utf8'));
      const incident = { key: '76ba01e87c44289e10e6ce396ed86f09', target: 'example.com', item: 'mail.example.com|A', tag: 'WORSE', since: NOW.toISOString(), state: 'differs' };
      assert.deepEqual(kept, { ...first, notify: { open: [incident] } }, 'the previous report, with the incident opened');
      assert.deepEqual(readdirSync(dir), ['drift.json'], 'no temporary file left');
      // night 3: mail is fixed (www's move still to report): the chat gets it, PagerDuty the resolve
      const third = await runDs(argv, { table: Object.assign(movedZone(), { 'mail.example.com': zoneTable()['mail.example.com'] }) });
      assert.equal(third.code, EXIT.OK, third.err);
      assert.deepEqual(third.hook.requests.map((r) => (r.url === HOOK_URL ? 'chat' : JSON.parse(r.body).event_action)), ['chat', 'resolve']);
      assert.equal(JSON.parse(third.hook.requests[1].body).dedup_key, incident.key);
      assert.equal(JSON.parse(readFileSync(json, 'utf8')).notify, undefined, 'nothing open any more');
      // a night PagerDuty itself fails on its one event: nothing opened, the file as it was
      const before = readFileSync(json);
      const down = await runDs(argv, { table: movedZone(), hook: webhook([200, 500, 500]) });
      assert.equal(down.code, EXIT.NOTIFY, down.err);
      assert.match(down.err, /\(this report is not written there\): the 1 change will be reported again on the next run/);
      assert.deepEqual(readFileSync(json), before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('exit codes: 3, then 5, then 4', async () => {
    const dir = tmp();
    try {
      const base = join(dir, 'base.json');
      await runDs(['drift', CF_EXPORT, '--json', base]);
      const argv = (out) => ['drift', CF_EXPORT, '--baseline', base, '--json', out, '--notify', HOOK_URL, '--fail-on-change'];
      const changed = await runDs([...argv(join(dir, 'a.json'))], { table: movedZone(), hook: webhook([400]) });
      assert.equal(changed.code, EXIT.CHANGED, 'a failed notification alone changes nothing');
      const five = await runDs([...argv(join(dir, 'b.json')), '--fail-on-notify-error'], { table: movedZone(), hook: webhook([400]) });
      assert.equal(five.code, EXIT.NOTIFY, '5 before 4');
      // the report's directory goes while the message is posted: the report cannot be written
      const outDir = join(dir, 'out');
      mkdirSync(outDir);
      const gone = webhook([() => {
        rmSync(outDir, { recursive: true, force: true });
        return new Response('no', { status: 400 });
      }]);
      const three = await runDs([...argv(join(outDir, 'c.json')), '--fail-on-notify-error'], { table: movedZone(), hook: gone });
      assert.equal(three.code, EXIT.WRITE, `3 before 5: ${three.err}`);
      assert.equal(EXIT.NOTIFY, 5);
      assert.match(USAGE, /5 a notification was not delivered \(only with\n {2}--fail-on-notify-error\), 130 interrupted \(nothing written\)\. When several apply: 3, then 5,\n {2}then 4\./);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a timeout, a run stopped while it posts, a URL on the command line with nothing to send, the environment\'s URLs', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'drift.json');
      await runDs(['drift', CF_EXPORT, '--json', json]);
      const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
      const slow = await runDs(['drift', CF_EXPORT, '--baseline', json, '--notify', HOOK_URL, '--fail-on-notify-error'],
        { table: movedZone(), hook: webhook([hang, hang]), timing: { timeoutMs: 40, retryDelayMs: 1 } });
      assert.equal(slow.code, EXIT.NOTIFY);
      assert.match(slow.err, /ds: error: notification failed \(json, hooks\.example\.com\): timed out/);
      assert.equal(slow.hook.requests.length, 2);

      // Ctrl-C while the message is posted: exit 130, nothing written (the Markdown neither)
      const out = join(dir, 'stopped.json');
      const md = join(dir, 'stopped.md');
      const controller = new AbortController();
      const stop = webhook([(url, init) => {
        setTimeout(() => controller.abort(), 5);
        return hang(url, init);
      }]);
      const stopped = await runDs(['drift', CF_EXPORT, '--baseline', json, '--json', out, '--md', md, '--notify', HOOK_URL], { table: movedZone(), hook: stop, signal: controller.signal });
      assert.equal(stopped.code, EXIT.INTERRUPTED);
      assert.match(stopped.err, /ds: error: notification \(json, hooks\.example\.com\) interrupted\nds: interrupted: nothing written\n$/);
      assert.ok(!existsSync(out) && !existsSync(md));

      // --notify on the command line without --baseline has nothing to send: a warning
      const lone = await runDs(['drift', CF_EXPORT, '--notify', HOOK_URL, '--json', join(dir, 'lone.json')]);
      assert.match(lone.err, /ds: warning: --notify sends a message only with --baseline \(the changes since the last run\) or --notify-always/);
      assert.equal(lone.hook.requests.length, 0);
      assert.deepEqual(JSON.parse(readFileSync(join(dir, 'lone.json'), 'utf8')).warnings, ['--notify sends a message only with --baseline (the changes since the last run) or --notify-always']);
      // the environment's URLs are set once for every job: no warning
      const quiet = await runDs(['drift', CF_EXPORT], { env: { [NOTIFY_ENV.url]: HOOK_URL } });
      assert.doesNotMatch(quiet.err, /warning/);
      // a URL in the environment is checked before anything is sent
      const refused = await runDs(['drift', CF_EXPORT], { env: { [NOTIFY_ENV.url]: `http://hooks.example.com/${TOKEN}` } });
      assert.equal(refused.code, EXIT.USAGE);
      assert.match(refused.err, /^ds: error: DOMAINSCOPE_NOTIFY_URL: needs an https:\/\/ URL/);
      assert.ok(!refused.err.includes(TOKEN));
      assert.equal(refused.hook.requests.length, 0);
      // -q: the failures still printed, the deliveries not
      const q = await runDs(['drift', CF_EXPORT, '--baseline', json, '-q'], { table: movedZone(), env: { [NOTIFY_ENV.url]: HOOK_URL } });
      assert.equal(q.err, '');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the help and the nightly template name the alert options and secrets', () => {
    for (const s of ['--notify URL', '--notify-bad URL', '--notify-format FMT', '--notify-always', '--fail-on-notify-error', NOTIFY_ENV.url, NOTIFY_ENV.bad, NOTIFY_ENV.secret, NOTIFY_ENV.ntfyToken]) {
      assert.ok(USAGE.includes(s), s);
    }
    const formats = USAGE.slice(USAGE.indexOf('--notify-format FMT'), USAGE.indexOf('--notify-always')).replace(/\s+/g, ' ');
    for (const format of NOTIFY_FORMATS) assert.match(formats, new RegExp(`\\b${format}\\b`), format);
    // the help stays within 100 columns
    for (const line of USAGE.split('\n').filter((l) => l.includes('notif') || l.includes('NOTIFY'))) assert.ok(line.length <= 100, line);
    const yml = readFileSync(join(ROOT, 'docs', 'examples', 'nightly-domainscope.yml'), 'utf8').replace(/\r\n/g, '\n');
    for (const name of Object.values(NOTIFY_ENV)) assert.ok(yml.includes(`${name}: \${{ secrets.${name} }}`), name);
    const readme = readFileSync(join(ROOT, 'docs', 'examples', 'README.md'), 'utf8');
    for (const name of Object.values(NOTIFY_ENV)) assert.ok(readme.includes(name), name);
  });
});
