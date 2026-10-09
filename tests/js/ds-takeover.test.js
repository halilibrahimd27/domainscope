/**
 * The headless runner's `takeover` (tools/ds/takeover.mjs, carry.mjs carryRisks): its command
 * line, the hosts of a subdomains report, the risks a failed lookup carries, the changes since the
 * baseline, the summary, four offline nights of main() over the fake DoH and RDAP of
 * tests/js/ds-fake-doh.mjs (takeoverZone), and a spawned runner over the same (DS_FAKE_DOH=takeover).
 * Documentation names only: example.com and example.net are ours, example.org and
 * example-test.com.tr other people's.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseCommandLine, UsageError, DS_TOOL, DS_VERSION, EXIT, USAGE, COMMAND_SPECS, DS_MAX_DKIM_SELECTORS } from '../../tools/ds/args.mjs';
import { baselineProblem, baselineNotes, diffReports, notableChanges } from '../../tools/ds/diff.mjs';
import { setupStrings, renderChangesMarkdown, renderChangesText, painter, CHANGE_TAGS } from '../../tools/ds/render.mjs';
import { carryRisks } from '../../tools/ds/carry.mjs';
import { subdomainHosts, takeoverInputs, takeoverTarget, takeoverDoc, takeoverWarnings, countsAt } from '../../tools/ds/takeover.mjs';
import { main, skippedWarnings } from '../../tools/ds.mjs';
import { renderMarkdown, renderPlainText } from '../../assets/js/lib/summary.js';
import { fixKey } from '../../assets/js/ui/takeover-panel.js';
import { takeoverZone, createTakeoverFetch } from './ds-fake-doh.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DS = join(ROOT, 'tools', 'ds.mjs');
const NOW = new Date('2026-10-09T03:00:00Z');
const DAY = 86400000;
const t = await setupStrings();

const report = (targets, extra = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command: 'takeover', startedAt: '2026-10-08T03:00:00.000Z', finishedAt: '2026-10-08T03:01:00.000Z',
  options: {}, targets, ...extra
});
const tags = (changes) => changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.target}${c.item ? ` ${c.item}` : ''}`);
const tmp = () => mkdtempSync(join(tmpdir(), 'ds-takeover-'));
function sink() {
  return { text: '', isTTY: false, write(s) { this.text += s; return true; } };
}

/** A risk as the report keeps it. */
const risk = (kind, host, target, severity, code, extra = {}) => ({
  key: `${kind}|${host}|${target}`, kind, host, target, chain: [target], term: null, severity, reason: code,
  reasons: [{ code, severity, ...(extra.domain ? { domain: extra.domain } : {}), ...(code === 'nxdomain' ? { name: target } : {}) }],
  domain: extra.domain || null, expires: null, service: null, evidence: '', fix: '', ...extra
});

describe('takeover: command line', () => {
  test('domains, the hosts to ask (one source), extra DKIM selectors; refused before anything is sent', () => {
    const cl = parseCommandLine(['takeover', 'Example.COM', 'https://example.net/x', '--names', 'hosts.txt', '--dkim-selectors', 'S2048,google,k2._domainkey.example.com']);
    assert.deepEqual(cl.targets, ['example.com', 'example.net']);
    assert.deepEqual([cl.options.names, cl.options.fromSubdomains, cl.options.dkimSelectors], ['hosts.txt', null, ['s2048', 'k2']], 'a common selector dropped, a full name cut to its selector');
    assert.deepEqual(parseCommandLine(['takeover', '--list', 'd.txt', '--from-subdomains', 'results/subdomains.json']).options.fromSubdomains, 'results/subdomains.json');
    assert.deepEqual(COMMAND_SPECS.takeover.options, ['list', 'names', 'from-subdomains', 'dkim-selectors']);
    const refused = [
      [['takeover', 'example.com', '--names', 'a.txt', '--from-subdomains', 's.json'], /--names and --from-subdomains both name the hosts to ask: give one of them/],
      [['takeover', 'example.com', '--names', '-'], /--names takes a file, not "-"/],
      [['takeover', 'example.com', '--from-subdomains', ' '], /--from-subdomains needs a file name/],
      [['takeover', 'example.com', '--dkim-selectors', 'a b,c/d'], /--dkim-selectors: not a DKIM selector: "c\/d"/],
      [['takeover', 'example.com', '--dkim-selectors', ','], /--dkim-selectors needs at least one selector/],
      [['takeover', 'example.com', '--dkim-selectors', Array.from({ length: DS_MAX_DKIM_SELECTORS + 1 }, (_, i) => `x${i}`).join(',')], /at most 20 selectors besides the common ones, not 21/],
      [['takeover', 'example.com', '--names', 'h.txt', '--json', 'h.txt'], /--json names the same file as --names \(h\.txt\)/],
      [['takeover', '--from-subdomains', 's.json'], /takeover needs at least one domain \(or --list FILE\)/],
      [['health', 'example.com', '--from-subdomains', 's.json'], /--from-subdomains applies to tls and takeover only, not to health/],
      [['takeover', 'example.com', '--exact', 'h.txt'], /--exact applies to subdomains only, not to takeover/]
    ];
    for (const [argv, re] of refused) assert.throws(() => parseCommandLine(argv), (err) => err instanceof UsageError && re.test(err.message), argv.join(' '));
    assert.match(USAGE, /\n {2}takeover DOMAIN\.\.\. {13}the takeover and dependency-expiry watch/);
    assert.match(USAGE, /--dkim-selectors a,b\] {5}DKIM selectors besides the 8 common ones/);
    assert.ok(CHANGE_TAGS.includes('RISK'));
  });

  test('the hosts of a subdomains report: those with a CNAME (a dangling one, one a failed lookup carried), never a look-alike', () => {
    const doc = {
      tool: DS_TOOL, version: DS_VERSION, command: 'subdomains', targets: [
        { target: 'example.com', hosts: [
          { name: 'old.example.com', cnames: ['old-app.azurewebsites.net'], dangling: true },
          { name: 'www.example.com', cnames: [], ipv4: ['192.0.2.10'] },
          { name: 'flaky.example.com', status: 'SERVFAIL', cnames: [], lastGood: { at: null, cnames: ['shop.example.net'] } },
          { name: 'any.example.com', cnames: ['x.example.net'], wildcardSuspect: true },
          { name: 'old.example.com', cnames: ['other.example.net'] },
          { cnames: ['nameless.example.net'] }, 'junk'
        ] },
        'junk'
      ]
    };
    const { hosts, invalid, problem } = subdomainHosts(doc);
    assert.equal(problem, null);
    assert.deepEqual(hosts.map((h) => [h.name, h.resolution.cnames]), [['old.example.com', ['old-app.azurewebsites.net']], ['flaky.example.com', ['shop.example.net']]]);
    assert.deepEqual(invalid, []);
    // A crafted report: terminal escapes and a bidi override in host names (never sent, never printed raw).
    const crafted = subdomainHosts({ ...doc, targets: [{ target: 'example.com', hosts: [
      { name: '\u001b]0;x\u0007\u001b[31mred.example.com', cnames: ['x.example.org'] },
      { name: 'a\u202Emoc.example.com', cnames: ['y.example.org'] },
      { name: 'Good.Example.com.', cnames: ['Old-App.azurewebsites.net.', 'bad\u001b[0m.example.org'] }
    ] }] });
    assert.deepEqual(crafted.hosts.map((h) => [h.name, h.resolution.cnames]), [['good.example.com', ['old-app.azurewebsites.net']]]);
    assert.deepEqual(crafted.invalid, ['\u001b]0;x\u0007\u001b[31mred.example.com', 'a\u202Emoc.example.com']);
    assert.match(subdomainHosts({ ...doc, command: 'ct' }).problem, /a report of "ct", not of "subdomains"/);
    assert.match(subdomainHosts({ ...doc, tool: 'other' }).problem, /not a --json report of domainscope-ds/);
    assert.match(subdomainHosts({ ...doc, version: '2.0.0' }).problem, /written by version "2\.0\.0"/);
    assert.match(subdomainHosts({ ...doc, targets: null }).problem, /no "targets" list/);
  });

  test('--names and --from-subdomains are read and checked before anything is sent', async () => {
    const files = {
      'h.txt': 'old.example.com\nnot a host!\n# a comment\nwww.example.com',
      'empty.txt': '# nothing',
      'bad.json': '{ not json',
      'ct.json': JSON.stringify({ tool: DS_TOOL, version: DS_VERSION, command: 'ct', targets: [] }),
      's.json': JSON.stringify({ tool: DS_TOOL, version: DS_VERSION, command: 'subdomains', targets: [{ target: 'example.com', hosts: [
        { name: '\u001b]0;x\u0007\u001b[31mred.example.com', cnames: ['x.example.org'] }, { name: 'old.example.com', cnames: ['old-app.azurewebsites.net'] }
      ] }] })
    };
    const warnings = [];
    const io = { read: async (path) => files[path], warn: (w) => warnings.push(w), skipped: skippedWarnings };
    assert.deepEqual(await takeoverInputs({ names: 'h.txt' }, io), { source: 'names', file: 'h.txt', hosts: ['old.example.com', 'www.example.com'] });
    assert.deepEqual(warnings, ['--names h.txt: skipped "not": not a host name', '--names h.txt: skipped "a": not a host name', '--names h.txt: skipped "host!": not a host name']);
    await assert.rejects(takeoverInputs({ names: 'empty.txt' }, io), /--names: empty\.txt lists no host name/);
    await assert.rejects(takeoverInputs({ fromSubdomains: 'bad.json' }, io), /--from-subdomains: bad\.json is not JSON/);
    await assert.rejects(takeoverInputs({ fromSubdomains: 'ct.json' }, io), /cannot read hosts from ct\.json: it is a report of "ct"/);
    assert.deepEqual(await takeoverInputs({}, io), { source: null, file: null, hosts: [] });
    warnings.length = 0;
    const fromReport = await takeoverInputs({ fromSubdomains: 's.json' }, io);
    assert.deepEqual(fromReport.hosts.map((h) => h.name), ['old.example.com']);
    assert.deepEqual(warnings, ['--from-subdomains s.json: skipped "]0;x [31mred.example.com": not a host name'], 'the name quoted without its control characters');
  });

  test('the warnings never print a name raw: control and bidi characters out', () => {
    const [w] = takeoverWarnings({ target: 'example.com', risks: [], failures: [{ source: 'doh', name: 'mx\u001b[31m.example\u202Eorg' }, { source: 'rdap', name: 'example.net' }] });
    assert.equal(w, 'example.com: no answer for mx [31m.example org, example.net: what they feed could not be checked');
  });
});

describe('takeover: what a failed lookup hides is carried, never fixed', () => {
  const prev = {
    target: 'example.com', checkedAt: '2026-10-08T03:00:00.000Z',
    risks: [
      risk('spf-host', 'example.com', 'relay.example-test.com.tr', 'medium', 'expiring', { domain: 'example-test.com.tr' }),
      risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'high', 'unregistered', { domain: 'example.org' }),
      risk('mx', 'example.com', 'mx.example.org', 'low', 'nxdomain'),
      risk('caa', 'example.com', 'iodef.example.org', 'high', 'pending-delete', { domain: 'example.org', carried: { from: '2026-10-06T03:00:00.000Z' } })
    ]
  };

  test('a risk whose RDAP, record or existence lookup failed stays as last read; others go', () => {
    const x = { risks: [], failures: [{ source: 'rdap', name: 'example-test.com.tr' }, { source: 'doh', name: 'example.com CAA' }, { source: 'doh', name: 'mx.example.org' }] };
    const out = carryRisks(x, prev);
    assert.deepEqual(out.map((r) => [r.key, r.carried && r.carried.from]), [
      ['caa|example.com|iodef.example.org', '2026-10-06T03:00:00.000Z'],
      ['spf-host|example.com|relay.example-test.com.tr', '2026-10-08T03:00:00.000Z'],
      ['mx|example.com|mx.example.org', '2026-10-08T03:00:00.000Z']
    ], 'worst first; a risk the baseline carried keeps its "from"; the DMARC risk, whose lookups answered, is gone');
  });

  test('never better than last read: this run\'s risk of the same key stands only when it is at least as severe', () => {
    const lower = risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'low', 'nxdomain');
    const out = carryRisks({ risks: [lower], failures: [{ source: 'rdap', name: 'example.org' }] }, prev);
    assert.equal(out.find((r) => r.kind === 'dmarc').severity, 'high', 'RDAP failed: not known to be better');
    const worse = risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'critical', 'unregistered', { domain: 'example.org' });
    assert.equal(carryRisks({ risks: [worse], failures: [{ source: 'rdap', name: 'example.org' }] }, prev).find((r) => r.kind === 'dmarc').carried, undefined);
    assert.deepEqual(carryRisks({ risks: [lower], failures: [] }, prev), [lower], 'no failure: nothing carried');
    assert.deepEqual(carryRisks({ risks: [lower], failures: [{ name: 'example.org' }] }, null), [lower], 'no baseline');
  });
});

describe('takeover: changes since the baseline', () => {
  const at = (domain, risks, extra = {}) => ({ target: domain, checkedAt: '2026-10-08T03:00:00.000Z', references: 10, checked: 3, risks, failures: [], domains: [], ...extra });
  const diff = (before, after) => diffReports('takeover', report(before), report(after), { t });

  test('a new risk counts at medium or above; worse, better and gone; a domain new or no longer watched', () => {
    const changes = diff([
      at('example.com', [
        risk('spf-host', 'example.com', 'relay.example-test.com.tr', 'medium', 'expiring', { domain: 'example-test.com.tr' }),
        risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'high', 'unregistered', { domain: 'example.org' }),
        risk('srv', '_sip._tls.example.com', 'sip.example.org', 'low', 'nxdomain'),
        risk('ns', 'example.com', 'ns.example.org', 'high', 'pending-delete', { domain: 'example.org' })
      ]),
      at('example.org', [])
    ], [
      at('example.com', [
        risk('spf-host', 'example.com', 'relay.example-test.com.tr', 'high', 'pending-delete', { domain: 'example-test.com.tr' }),
        risk('acme', '_acme-challenge.example.com', '_acme-challenge.example.org', 'critical', 'unregistered', { domain: 'example.org' }),
        risk('mx', 'example.com', 'mx.example.org', 'low', 'nxdomain'),
        risk('cname', 'files.example.com', 'files.example.com.s3.amazonaws.com', 'info', 'check-http'),
        risk('srv', '_sip._tls.example.com', 'sip.example.org', 'medium', 'expiring', { domain: 'example.org' })
      ]),
      at('example.net', [risk('caa', 'example.net', 'example-test.com.tr', 'medium', 'expiring', { domain: 'example-test.com.tr' })])
    ]);
    assert.deepEqual(tags(changes), [
      'WORSE example.com spf-host|example.com|relay.example-test.com.tr',
      'RISK example.com acme|_acme-challenge.example.com|_acme-challenge.example.org',
      'WORSE example.com srv|_sip._tls.example.com|sip.example.org',
      'GONE example.com dmarc|_dmarc.example.com|reports.example.org',
      'GONE example.com ns|example.com|ns.example.org',
      'NEW example.net',
      'GONE example.org',
      'RISK? example.com mx|example.com|mx.example.org',
      'RISK? example.com cname|files.example.com|files.example.com.s3.amazonaws.com'
    ]);
    const by = Object.fromEntries(changes.map((c) => [`${c.tag} ${c.item}`, c]));
    assert.equal(by['RISK acme|_acme-challenge.example.com|_acme-challenge.example.org'].tone, 'bad');
    assert.equal(by['RISK mx|example.com|mx.example.org'].tone, 'info', 'low: listed only');
    assert.equal(by['RISK cname|files.example.com|files.example.com.s3.amazonaws.com'].tone, 'quiet', 'to check in the app: never counted');
    assert.equal(by['GONE dmarc|_dmarc.example.com|reports.example.org'].tone, 'good');
    const lines = Object.fromEntries(changes.map((c) => [`${c.tag} ${c.item}`, renderChangesMarkdown({ command: 'takeover', baseline: { file: 'takeover.json' }, changes: [c] }).split('\n')[2]]));
    assert.equal(lines['WORSE spf-host|example.com|relay.example-test.com.tr'],
      '- **WORSE** `example.com`: SPF host `example.com` → `relay.example-test.com.tr`: medium → high — `example-test.com.tr` is pending deletion at its registry: once released, anyone can register it.');
    assert.equal(lines['GONE dmarc|_dmarc.example.com|reports.example.org'], '- **GONE** `example.com`: high DMARC `_dmarc.example.com` → `reports.example.org` no longer found');
    assert.equal(lines['NEW null'], '- **NEW** `example.net`: now watched: 1 risk at medium severity or above, 1 in all');
    assert.match(renderChangesMarkdown({ command: 'takeover', baseline: { file: 'takeover.json' }, changes }),
      /- 2 listed only \(risks of low severity and the ones only the page can tell \(to check in the app\), and their moves\): never counted by --fail-on-change/);
    assert.equal(notableChanges(changes).length, 7);
    assert.ok(countsAt('medium') && countsAt('critical') && !countsAt('low') && !countsAt('info'));
  });

  test('a lapsed domain registered again while the record still names it is said, gone or better', () => {
    const before = at('example.com', [
      risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'high', 'unregistered', { domain: 'example.org' }),
      risk('caa', 'example.com', 'iodef.example.net', 'high', 'expired', { domain: 'example.net' })
    ]);
    const after = at('example.com', [risk('dmarc', '_dmarc.example.com', 'reports.example.org', 'low', 'nxdomain')], {
      domains: [{ domain: 'example.org', verdict: 'registered', expires: null }, { domain: 'example.net', verdict: 'expiring', expires: null }]
    });
    const changes = diff([before], [after]);
    const text = changes.map((c) => renderChangesText({ command: 'takeover', baseline: { file: 't.json', finishedAt: null }, changes: [c] }, { paint: painter(false) })[1].trim());
    assert.deepEqual(text, [
      'BETTER     example.com: DMARC _dmarc.example.com → reports.example.org: high → low — example.org is registered now — make sure it is yours; reports.example.org does not exist (NXDOMAIN).',
      'GONE       example.com: high CAA iodef example.com → iodef.example.net: example.net is registered now — make sure it is yours'
    ]);
  });

  test('so is one in a TLD without RDAP, or with an RDAP 404, that is in DNS now', () => {
    // A .com.tr mail host whose domain had lapsed (no RDAP for the TLD, NXDOMAIN): someone registered it.
    const before = at('example.com', [risk('mx', 'example.com', 'mx.mailhost.example-test.com.tr', 'high', 'unregistered-dns', { domain: 'example-test.com.tr' })]);
    for (const verdict of ['no-rdap', 'rdap-404-dns']) {
      const after = at('example.com', [], { domains: [{ domain: 'example-test.com.tr', verdict, expires: null }] });
      const changes = diff([before], [after]);
      assert.deepEqual(changes.map((c) => renderChangesText({ command: 'takeover', baseline: { file: 't.json', finishedAt: null }, changes: [c] }, { paint: painter(false) })[1].trim()), [
        'GONE       example.com: high MX example.com → mx.mailhost.example-test.com.tr: example-test.com.tr is registered now — make sure it is yours'
      ], verdict);
    }
  });

  test('a carried risk compares as last read: a night whose lookup failed is no change', () => {
    const r = risk('spf-host', 'example.com', 'relay.example-test.com.tr', 'high', 'pending-delete', { domain: 'example-test.com.tr' });
    assert.deepEqual(diff([at('example.com', [r])], [at('example.com', [{ ...r, carried: { from: '2026-10-08T03:00:00.000Z' } }])]), []);
  });

  test('a baseline whose risks the comparison cannot walk is refused; the notes say what the runs did differently', () => {
    assert.equal(baselineProblem(report([at('example.com', [risk('mx', 'example.com', 'mx.example.org', 'low', 'nxdomain')])]), 'takeover'), null);
    assert.match(baselineProblem(report([{ target: 'example.com' }]), 'takeover'), /targets\[0\] has no "risks" list/);
    assert.match(baselineProblem(report([at('example.com', [{ key: 'k', kind: 'mx', host: 'example.com', target: 'x' }])]), 'takeover'), /risks\[0\] has no "severity"/);
    assert.match(baselineProblem(report([at('example.com', [{ ...risk('mx', 'example.com', 'x.example.org', 'low', 'nxdomain'), carried: {} }])]), 'takeover'), /risks\[0\] has a "carried" without a "from"/);
    assert.match(baselineProblem(report([at('example.com', [], { domains: [{}] })]), 'takeover'), /has a "domains" list that is not registrations/);
    const o = { dkimSelectors: [], hosts: null, resolvers: ['cloudflare'] };
    assert.deepEqual(baselineNotes('takeover', report([], { options: o }), report([], { options: o })), []);
    const notes = baselineNotes('takeover', report([], { options: o }), report([], { options: { dkimSelectors: ['s2048'], hosts: { source: 'subdomains', file: 'subdomains.json', count: 3 }, resolvers: ['cloudflare'] } }));
    assert.deepEqual(notes, [
      'The extra DKIM selectors differ from the baseline\'s (none → s2048): DKIM CNAME risks can appear or go because of that.',
      'The hosts asked differ from the baseline\'s (none → subdomains subdomains.json): CNAME risks can appear or go because of that.'
    ]);
  });
});

describe('takeover: the report and the summary', () => {
  const finding = (extra = {}) => ({
    id: 'dmarc|_dmarc.example.com|reports.example.org', severity: 'high', kind: 'dmarc', host: '_dmarc.example.com', target: 'reports.example.org',
    chain: ['reports.example.org'], term: 'rua', service: null, fix: 'unregistered',
    reasons: [{ code: 'unregistered', severity: 'high', domain: 'example.org', expires: null }, { code: 'nxdomain', severity: 'low', name: 'reports.example.org' }], ...extra
  });
  const result = (findings, extra = {}) => ({
    references: 9, checked: 2, hosts: 1, spfMacros: 1, findings, failures: [],
    registrations: new Map([['example.org', { verdict: 'unregistered', expires: null }], ['example-test.com.tr', { verdict: 'expiring', expires: new Date(NOW.getTime() + 20 * DAY) }]]), ...extra
  });

  test('a risk keeps its key, reasons, evidence and fix in the app\'s words; the registrations read; the failures', () => {
    const x = takeoverTarget('example.com', result([finding()], {
      failures: [{ source: 'rdap', name: 'example.net', response: { ok: false, error: 'HTTP 503', errorKind: 'http' } }]
    }), { t, fixKey, checkedAt: NOW });
    assert.deepEqual(Object.keys(x), ['target', 'checkedAt', 'references', 'checked', 'hosts', 'spfMacros', 'domains', 'risks', 'failures']);
    const [r] = x.risks;
    assert.equal(r.key, 'dmarc|_dmarc.example.com|reports.example.org');
    assert.deepEqual([r.severity, r.reason, r.domain, r.term], ['high', 'unregistered', 'example.org', 'rua']);
    assert.deepEqual(r.reasons, [{ code: 'unregistered', severity: 'high', domain: 'example.org' }, { code: 'nxdomain', severity: 'low', name: 'reports.example.org' }]);
    assert.match(r.evidence, /^example\.org looks unregistered: .* reports\.example\.org does not exist \(NXDOMAIN\)\.$/);
    assert.equal(r.fix, 'Remove the report address at reports.example.org from the DMARC record (rua), or register example.org yourself.');
    assert.deepEqual(x.domains, [{ domain: 'example-test.com.tr', verdict: 'expiring', expires: '2026-10-29T03:00:00.000Z' }, { domain: 'example.org', verdict: 'unregistered', expires: null }]);
    assert.deepEqual(x.failures, [{ source: 'rdap', name: 'example.net', error: 'HTTP 503', errorKind: 'http' }]);
  });

  test('the summary: what was checked, each risk worst first with its reason, the hosts to check in the app, no answer, the SPF macros', () => {
    const toCheck = finding({ id: 'cname|files.example.com|b.s3.amazonaws.com', kind: 'cname', host: 'files.example.com', target: 'b.s3.amazonaws.com', severity: 'info', term: null,
      service: { id: 'aws-s3', name: 'Amazon S3', status: 'vulnerable', ref: 'https://example.org/' }, fix: 'check-http', reasons: [{ code: 'check-http', severity: 'info' }] });
    const x = takeoverTarget('example.com', result([finding(), toCheck], { failures: [{ source: 'doh', name: 'example.com CAA', response: { ok: false, error: 'timeout' } }] }), { t, fixKey, checkedAt: NOW });
    const md = renderMarkdown(takeoverDoc(x, { t, now: NOW }));
    assert.match(md, /^\*\*Takeover risks · `example\.com`\*\*\n/);
    assert.match(md, /- 1 reference at risk \(9 references checked\)\.\n/);
    assert.match(md, /- \*\*High:\*\* DMARC `_dmarc\.example\.com` → `reports\.example\.org` — `example\.org` looks unregistered/);
    assert.match(md, /- To check in the app \(only the page tells; Subdomains › Takeover risks asks one Globalping probe per host, behind a click\): `files\.example\.com`/);
    assert.match(md, /- No answer: `example\.com CAA`: what they feed could not be checked this run/);
    assert.match(md, /- 1 SPF term builds its domain from a macro/);
    const none = renderPlainText(takeoverDoc(takeoverTarget('example.net', result([]), { t, fixKey, checkedAt: NOW }), { t, now: NOW }));
    assert.match(none, /- Nothing at risk: 9 references checked, 2 registrable domains looked up\./);
  });
});

/* ------------------------------------------------------------------------ */
/* Offline nights                                                           */
/* ------------------------------------------------------------------------ */

async function runMain(argv, { fetchImpl, now = NOW } = {}) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now });
  return { code, out: stdout.text, err: stderr.text };
}

test('takeover over four nights: a lapsed DMARC domain and an expiring one, registered again and pending deletion, a registry outage carried', async () => {
  const dir = tmp();
  try {
    const zone = takeoverZone({ now: NOW.getTime() });
    const log = [];
    const rdapLog = [];
    const rdapStatus = {};
    const fetchImpl = createTakeoverFetch(zone, { log, rdapLog, rdapStatus });
    const json = join(dir, 'takeover.json');
    const md = join(dir, 'takeover.md');
    const subs = join(dir, 'subdomains.json');
    writeFileSync(subs, JSON.stringify({
      tool: DS_TOOL, version: DS_VERSION, command: 'subdomains', targets: [{ target: 'example.com', mode: 'discover', hosts: [
        { name: 'old.example.com', status: 'NXDOMAIN', cnames: ['old-app.azurewebsites.net'], dangling: true, ipv4: [], ipv6: [] },
        { name: 'www.example.com', status: 'NOERROR', cnames: [], ipv4: ['192.0.2.10'], ipv6: [] },
        { name: 'cdn.example.org', status: 'NOERROR', cnames: ['cdn.example.net'], ipv4: [], ipv6: [] }
      ] }]
    }));
    const argv = ['takeover', 'example.com', 'example.net', '--from-subdomains', subs, '--baseline', json, '--json', json, '--md', md, '--fail-on-change', '--no-color'];

    // Night 1: no baseline yet.
    const first = await runMain(argv, { fetchImpl });
    assert.equal(first.code, EXIT.OK, first.err);
    assert.match(first.out, /^Baseline takeover\.json does not exist yet/);
    assert.match(first.out, /\nTakeover risks · example\.com\n- 3 references at risk \(9 references checked\)\.\n- Hosts asked for their CNAME chain: 1\n/);
    assert.match(first.out, /- High: DMARC _dmarc\.example\.com → reports\.example\.org — example\.org looks unregistered/);
    assert.match(first.out, /- High: CNAME old\.example\.com → old-app\.azurewebsites\.net — old-app\.azurewebsites\.net does not exist \(NXDOMAIN\)\./);
    assert.match(first.out, /- Medium: SPF host example\.com → relay\.example-test\.com\.tr — The registration of example-test\.com\.tr ends on 2026-10-29\./);
    assert.match(first.out, /\nTakeover risks · example\.net\n- 1 reference at risk \(5 references checked\)\.\n- Medium: CAA iodef example\.net → example-test\.com\.tr/);
    assert.match(first.err, /ds: warning: 1 host of subdomains\.json under none of the domains left out \(never sent\)/);
    // RDAP: each registrable domain once a run (example-test.com.tr is named by both domains), never our own, never a provider.
    assert.deepEqual([...rdapLog].sort(), ['example-test.com.tr', 'example.org']);
    assert.ok(!log.some((q) => q.name.endsWith('example.org') && q.name !== 'example.org' && q.name !== 'reports.example.org'), 'cdn.example.org was never sent');
    assert.ok(!log.some((q) => q.name === 'example-net.acme.example.com' && q.type === 'A'), 'a delegation into our own domain is not asked for its existence');
    for (const q of ['_dmarc.example.com|TXT', 'example.net|CAA', 'mta-sts.example.com|A', '_acme-challenge.example.net|TXT', '_sip._tls.example.net|SRV', 'selector1._domainkey.example.com|TXT', 'old.example.com|A']) {
      assert.ok(log.some((x) => `${x.name}|${x.type}` === q), q);
    }
    const doc1 = JSON.parse(readFileSync(json, 'utf8'));
    // the hosts with a CNAME the report holds (one of them under neither domain, left out)
    assert.deepEqual(doc1.options, { dkimSelectors: [], hosts: { source: 'subdomains', file: 'subdomains.json', count: 2 }, resolvers: ['cloudflare', 'google', 'dnssb'] });
    assert.equal(doc1.targets[0].spfMacros, 1);

    // Night 2: example.org is registered (the DMARC host itself still does not exist); example-test.com.tr pending deletion.
    zone.registry['example.org'] = zone.rdapJson('example.org', ['active'], 300);
    zone.registry['example-test.com.tr'] = zone.rdapJson('example-test.com.tr', ['pending delete'], -5);
    rdapLog.length = 0;
    const second = await runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + DAY) });
    assert.equal(second.code, EXIT.CHANGED, second.err);
    assert.match(second.out, /^Changes since the baseline \(takeover\.json, run of 2026-10-09 03:00 UTC\): 3\n/);
    assert.match(second.out, /\n {2}WORSE {6}example\.com: SPF host example\.com → relay\.example-test\.com\.tr: medium → high — example-test\.com\.tr is pending deletion/);
    assert.match(second.out, /\n {2}BETTER {5}example\.com: DMARC _dmarc\.example\.com → reports\.example\.org: high → low — example\.org is registered now — make sure it is yours; reports\.example\.org does not exist/);
    assert.match(second.out, /\n {2}WORSE {6}example\.net: CAA iodef example\.net → example-test\.com\.tr: medium → high/);
    assert.match(readFileSync(md, 'utf8'), /- \*\*WORSE\*\* `example\.com`: SPF host `example\.com` → `relay\.example-test\.com\.tr`: medium → high/);

    // Night 3: the registry of example-test.com.tr does not answer: its risks are carried, nothing changed.
    rdapStatus['example-test.com.tr'] = 503;
    const third = await runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + 2 * DAY) });
    assert.equal(third.code, EXIT.OK, third.out + third.err);
    assert.match(third.out, /^Changes since the baseline \(takeover\.json, run of 2026-10-10 03:00 UTC\): none\n/);
    assert.match(third.out, /- High: SPF host example\.com → relay\.example-test\.com\.tr — .* \(carried from 2026-10-10: a lookup it rests on gave no answer this run\)/);
    assert.match(third.err, /ds: warning: example\.net: no answer for example-test\.com\.tr: what they feed could not be checked; 1 risk carried from the last run that read it/);
    const doc3 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(doc3.targets[1].risks.map((r) => [r.key, r.severity, r.carried]), [['caa|example.net|example-test.com.tr', 'high', { from: '2026-10-10T03:00:00.000Z' }]]);

    // Night 4: the registry answers again, still pending deletion: compared with the carried read, no change.
    delete rdapStatus['example-test.com.tr'];
    const fourth = await runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + 3 * DAY) });
    assert.equal(fourth.code, EXIT.OK, fourth.out + fourth.err);
    assert.match(fourth.out, /^Changes since the baseline \(takeover\.json, run of 2026-10-11 03:00 UTC\): none\n/);
    assert.ok(!JSON.parse(readFileSync(json, 'utf8')).targets.some((x) => x.risks.some((r) => r.carried)), 'read again: nothing carried');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('with --notify-bad to PagerDuty: a risk that got worse pages once with its severity, stays open through a registry outage and is resolved when the risk is gone', async () => {
  const dir = tmp();
  try {
    const zone = takeoverZone({ now: NOW.getTime() });
    const rdapStatus = {};
    const base = createTakeoverFetch(zone, { log: [], rdapLog: [], rdapStatus });
    const sent = [];
    // a credential: built in parts, never written whole
    const url = 'https://events.pagerduty.com/v2/enqueue?routing_key=' + 'R0UT1NGKEY' + 'x'.repeat(22);
    const fetchImpl = (target, init) => {
      if (!String(target).startsWith('https://events.pagerduty.com/')) return base(target, init);
      sent.push(JSON.parse(init.body));
      return Promise.resolve(new Response('{"status":"success"}', { status: 202 }));
    };
    const json = join(dir, 'takeover.json');
    const argv = ['takeover', 'example.com', 'example.net', '--baseline', json, '--json', json, '--notify-bad', url, '--fail-on-notify-error', '--no-color'];
    const night = (n) => runMain(argv, { fetchImpl, now: new Date(NOW.getTime() + n * DAY) });
    const kinds = () => sent.splice(0).map((e) => [e.event_action, e.payload ? e.payload.custom_details.tag : null]);

    assert.equal((await night(0)).code, EXIT.OK);
    assert.deepEqual(kinds(), [], 'the first run has nothing to compare with');
    // night 2: example-test.com.tr is pending deletion: two risks get worse (medium to high)
    zone.registry['example-test.com.tr'] = zone.rdapJson('example-test.com.tr', ['pending delete'], -5);
    const second = await night(1);
    assert.equal(second.code, EXIT.OK, second.err);
    assert.deepEqual(kinds(), [['trigger', 'WORSE'], ['trigger', 'WORSE']]);
    const open2 = JSON.parse(readFileSync(json, 'utf8')).notify.open;
    assert.deepEqual(open2.map((e) => [e.tag, e.target, e.state]), [['WORSE', 'example.com', 'high'], ['WORSE', 'example.net', 'high']]);
    // night 3: its registry does not answer: the risks are carried, the incidents stay open
    rdapStatus['example-test.com.tr'] = 503;
    assert.equal((await night(2)).code, EXIT.OK);
    assert.deepEqual(kinds(), []);
    assert.deepEqual(JSON.parse(readFileSync(json, 'utf8')).notify.open.map((e) => e.key), open2.map((e) => e.key));
    // night 4: it answers again, still pending deletion: nothing to resolve
    delete rdapStatus['example-test.com.tr'];
    assert.equal((await night(3)).code, EXIT.OK);
    assert.deepEqual(kinds(), []);
    // night 5: the domain is renewed, no record is at risk any more: both incidents are resolved
    zone.registry['example-test.com.tr'] = zone.rdapJson('example-test.com.tr', ['active'], 300);
    const fifth = await night(4);
    assert.equal(fifth.code, EXIT.OK, fifth.err);
    assert.deepEqual(sent.map((e) => [e.event_action, e.dedup_key]), open2.map((e) => ['resolve', e.key]));
    assert.equal(JSON.parse(readFileSync(json, 'utf8')).notify, undefined, 'nothing left open');
    assert.ok(!(second.out + second.err + fifth.out + fifth.err).includes('R0UT1NGKEY'), 'the routing key is never printed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the program itself: a spawned takeover whose fetch is the fake DoH and RDAP (node --import, DS_FAKE_DOH=takeover)', () => {
  const dir = tmp();
  try {
    const logFile = join(dir, 'requests.json');
    const names = join(dir, 'hosts.txt');
    writeFileSync(names, 'old.example.com\nwww.example.com\n');
    const res = spawnSync(process.execPath, ['--import', pathToFileURL(join(ROOT, 'tests', 'js', 'ds-fake-doh.mjs')).href, DS, 'takeover', 'example.com', 'example.net',
      '--names', names, '--dkim-selectors', 's2048', '--json', join(dir, 't.json'), '--no-color'], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, DS_FAKE_DOH: 'takeover', DS_FAKE_DOH_LOG: logFile, NO_COLOR: '1' }, timeout: 60000
    });
    assert.equal(res.status, EXIT.OK, res.stderr);
    assert.match(res.stdout, /^Takeover risks · example\.com\n- 3 references at risk \(9 references checked\)\.\n- Hosts asked for their CNAME chain: 2\n/);
    assert.match(res.stdout, /- High: CNAME old\.example\.com → old-app\.azurewebsites\.net/);
    const requests = JSON.parse(readFileSync(logFile, 'utf8'));
    assert.deepEqual([...requests.rdap].sort(), ['example-test.com.tr', 'example.org']);
    assert.ok(requests.dns.some((q) => q.name === 's2048._domainkey.example.com' && q.type === 'TXT'), 'the extra selector');
    assert.equal(JSON.parse(readFileSync(join(dir, 't.json'), 'utf8')).command, 'takeover');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
