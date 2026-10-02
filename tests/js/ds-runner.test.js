/**
 * tools/ds.mjs — the headless runner: its command line (tools/ds/args.mjs), "Changes since the
 * baseline" (tools/ds/diff.mjs), the summary and Markdown (tools/ds/render.mjs), and offline
 * runs of the program itself: in-process with an injected fetch, and one spawned process whose
 * fetch is the fake DoH of tests/js/ds-fake-doh.mjs (the Zone File e2e suite's fake live zone).
 * No network: every DoH query is answered by the fake, every other request is a 404.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, mkdirSync, symlinkSync, lstatSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  parseCommandLine, parseListText, parseTargets, resolverChain, samePath, UsageError, COMMANDS, COMMAND_SPECS,
  NODE_CHAIN, NODE_UNREADABLE, DS_TOOL, DS_VERSION, DS_DEFAULT_LEVEL, EXIT, USAGE
} from '../../tools/ds/args.mjs';
import { baselineProblem, baselineInfo, baselineNotes, diffReports, orderChanges, notableChanges } from '../../tools/ds/diff.mjs';
import { setupStrings, renderChangesText, renderChangesMarkdown, renderRunText, painter, changeText, CHANGE_TAGS, MAX_SUMMARY_CHANGES, MAX_MARKDOWN_CHANGES } from '../../tools/ds/render.mjs';
import { ctCertId, ctTarget, ctDoc, hostRow, baselineSeeds, reportHosts, createSourceBreaker, stageProgress, scanWarningParts } from '../../tools/ds/commands.mjs';
import { failedAreas, checkAreas, carryHealth, carryCt, carryHosts, lastFullTimes } from '../../tools/ds/carry.mjs';
import { main, decodeText, skippedWarnings } from '../../tools/ds.mjs';
import { renderParts } from '../../assets/js/lib/summary.js';
import { zoneTable, createFakeFetch, CF_EXPORT, portfolioZone, createPortfolioFetch } from './ds-fake-doh.mjs';
import { DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';
import { issuerName, dnPart } from '../../assets/js/lib/passport.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DS = join(ROOT, 'tools', 'ds.mjs');
const NOW = new Date('2026-09-28T03:00:00Z');
const t = await setupStrings();

/** A report envelope of `command` with these targets. */
const report = (command, targets, extra = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command, startedAt: '2026-09-27T03:00:00.000Z', finishedAt: '2026-09-27T03:02:00.000Z',
  options: {}, targets, ...extra
});
const tags = (changes) => changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.target}${c.item ? ` ${c.item}` : ''}`);
const tmp = () => mkdtempSync(join(tmpdir(), 'ds-runner-'));
/** A writable stream stand-in that keeps what it is given. */
function sink({ isTTY = false } = {}) {
  return { text: '', isTTY, write(s) { this.text += s; return true; } };
}

/* ------------------------------------------------------------------------ */
/* Command line                                                             */
/* ------------------------------------------------------------------------ */

describe('command line', () => {
  test('the default chain is the app\'s, without the resolvers Node\'s fetch cannot read', () => {
    assert.deepEqual([...NODE_CHAIN], DEFAULT_CHAIN.filter((id) => !NODE_UNREADABLE[id]));
    assert.ok(!NODE_CHAIN.includes('cznic') && NODE_CHAIN.includes('cloudflare'));
    assert.deepEqual(COMMANDS, ['health', 'subdomains', 'drift', 'ct', 'renew', 'dane', 'audit']);
    for (const c of COMMANDS) assert.match(USAGE, new RegExp(`\\n  ${c} `), c);
  });

  test('health: domains normalized (a URL gives its host), duplicates dropped, the defaults', () => {
    const cl = parseCommandLine(['health', 'Example.COM', 'https://www.example.org/x', 'example.com.']);
    assert.equal(cl.command, 'health');
    assert.deepEqual(cl.targets, ['example.com', 'www.example.org']);
    assert.deepEqual(cl.options.chain, [...NODE_CHAIN]);
    assert.equal(cl.options.concurrency, 12);
    assert.equal(cl.options.json, null);
    assert.equal(cl.options.failOnChange, false);
  });

  test('help, version and a missing or unknown command', () => {
    assert.equal(parseCommandLine(['--help']).help, true);
    assert.equal(parseCommandLine(['-h']).help, true);
    assert.equal(parseCommandLine(['health', '--help']).help, true);
    assert.equal(parseCommandLine(['--version']).version, true);
    assert.throws(() => parseCommandLine([]), /a command is needed: health, subdomains/);
    assert.throws(() => parseCommandLine(['scan', 'example.com']), /unknown command "scan"/);
    assert.throws(() => parseCommandLine(['health']), /health needs at least one domain \(or --list FILE\)/);
    assert.doesNotThrow(() => parseCommandLine(['health', '--list', 'domains.txt']));
  });

  test('parse errors are short usage errors naming the option', () => {
    assert.throws(() => parseCommandLine(['health', 'example.com', '--nope']), (e) => e instanceof UsageError && /unknown option --nope/.test(e.message));
    assert.throws(() => parseCommandLine(['health', 'example.com', '--json']), /--json needs a value/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--json', '--md', 'x.md']), /--json needs a value/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--quiet=yes']), /--quiet takes no value/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--json', '-']), /--json takes a file, not "-"/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--baseline', '-']), /--baseline takes a file/);
  });

  test('an option of another subcommand is refused, naming where it belongs', () => {
    assert.throws(() => parseCommandLine(['health', 'example.com', '--level', 'small']), /--level applies to subdomains only, not to health/);
    assert.throws(() => parseCommandLine(['renew', 'example.com', '--sources', 'crtsh']), /--sources applies to subdomains and ct only/);
    assert.throws(() => parseCommandLine(['dane', 'cert.pem', '--list', 'x.txt']), /--list applies to health, subdomains, ct, renew and audit only, not to dane/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--no-dkim']), /--no-dkim applies to audit only, not to health/);
    assert.throws(() => parseCommandLine(['ct', 'example.com', '--policy', 'p.json']), /--policy applies to audit only, not to ct/);
  });

  test('--resolver: a known chain in the given order; HTTP/2-only resolvers and unknown ids refused', () => {
    assert.deepEqual(resolverChain('google, Cloudflare,google'), ['google', 'cloudflare']);
    assert.deepEqual(parseCommandLine(['health', 'example.com', '--resolver', 'dnssb']).options.chain, ['dnssb']);
    assert.equal(parseCommandLine(['health', 'example.com', '--resolver', 'dnssb']).options.chainGiven, true);
    for (const id of Object.keys(NODE_UNREADABLE)) assert.throws(() => resolverChain(id), /HTTP\/2 only/, id);
    assert.throws(() => resolverChain('opendns'), /unknown resolver "opendns" \(one of cloudflare/);
    assert.throws(() => resolverChain(' , '), /needs a resolver id/);
  });

  test('--concurrency: the app\'s Settings range', () => {
    assert.equal(parseCommandLine(['health', 'example.com', '--concurrency', '4']).options.concurrency, 4);
    for (const bad of ['0', '33', '1.5', 'x', '-1']) {
      assert.throws(() => parseCommandLine(['health', 'example.com', `--concurrency=${bad}`]), /--concurrency takes a whole number from 1 to 32/, bad);
    }
  });

  test('--fail-on-change needs --baseline; report files must differ where they would overwrite each other', () => {
    assert.throws(() => parseCommandLine(['health', 'example.com', '--fail-on-change']), /--fail-on-change needs --baseline/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--json', 'a.json', '--md', './a.json']), /--json and --md name the same file/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--baseline', 'r.md', '--md', 'r.md']), /--baseline and --md name the same file/);
    const cl = parseCommandLine(['health', 'example.com', '--baseline', 'r.json', '--json', 'r.json', '--fail-on-change']);
    assert.equal(cl.options.failOnChange, true);
    assert.ok(samePath('r.json', './r.json'));
    assert.ok(samePath('C:\\X\\r.json', 'c:\\x\\R.JSON', { platform: 'win32' }));
    assert.ok(!samePath('/x/r.json', '/x/R.json', { platform: 'linux' }));
  });

  test('a report file that is a file the run reads is refused: the zone, the certificate, a list, the names file', () => {
    assert.throws(() => parseCommandLine(['drift', 'example.com.zone', '--json', './example.com.zone']), /--json names the same file as the zone file \(example\.com\.zone\): the report would overwrite it/);
    assert.throws(() => parseCommandLine(['dane', 'fullchain.pem', '--md', 'fullchain.pem']), /--md names the same file as the certificate file \(fullchain\.pem\)/);
    assert.throws(() => parseCommandLine(['ct', '--list', 'a.txt', '--list', 'domains.txt', '--md', 'domains.txt']), /--md names the same file as --list \(domains\.txt\)/);
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--exact', 'hosts.txt', '--json', 'hosts.txt']), /--json names the same file as --exact \(hosts\.txt\)/);
    assert.doesNotThrow(() => parseCommandLine(['ct', '--list', 'domains.txt', '--json', 'ct.json', '--md', 'ct.md']));
  });

  test('skipped entries of a file: the first few quoted and cleaned, then how many more', () => {
    const invalid = ['bad host!', `evil\u202e\u0007name`, 'x'.repeat(200), ...Array.from({ length: 77 }, (_, i) => `"k${i}": 1,`)];
    const lines = skippedWarnings('--exact package.json', invalid, 'a host name');
    assert.equal(lines.length, 6);
    assert.equal(lines[0], '--exact package.json: skipped "bad host!": not a host name');
    assert.equal(lines[1], '--exact package.json: skipped "evil name": not a host name');
    assert.match(lines[2], /skipped "x{79}…": not a host name$/);
    assert.equal(lines[5], '--exact package.json: 75 more entries skipped: not a host name');
    assert.deepEqual(skippedWarnings('--list d.txt', ['a b'], 'a domain name'), ['--list d.txt: skipped "a b": not a domain name']);
  });

  test('subdomains: level, sources, exact', () => {
    const cl = parseCommandLine(['subdomains', 'example.com']);
    assert.equal(cl.options.level, DS_DEFAULT_LEVEL);
    assert.equal(DS_DEFAULT_LEVEL, 'small');
    assert.equal(cl.options.sources, null);
    assert.equal(parseCommandLine(['subdomains', 'example.com', '--level', 'SMART']).options.level, 'smart');
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--level', 'huge']), /--level takes off, small, smart, not "huge"/);
    assert.deepEqual(parseCommandLine(['subdomains', 'example.com', '--sources', 'crtsh,thc']).options.sources, ['crtsh', 'thc']);
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--sources', 'crtsh,urlscan']), /unknown source "urlscan"/);
    const exact = parseCommandLine(['subdomains', 'example.com', '--exact', 'names.txt']);
    assert.equal(exact.options.exact, 'names.txt');
    assert.equal(exact.options.level, 'off');
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--exact', 'n.txt', '--level', 'small']), /takes no --level/);
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--exact', 'n.txt', '--sources', 'crtsh']), /asks no passive source/);
  });

  test('ct: days and the certificate sources', () => {
    assert.equal(parseCommandLine(['ct', 'example.com']).options.days, 30);
    assert.equal(parseCommandLine(['ct', 'example.com', '--days', '7']).options.days, 7);
    assert.throws(() => parseCommandLine(['ct', 'example.com', '--days', '0']), /--days takes a whole number from 1 to 3650/);
    assert.deepEqual(parseCommandLine(['ct', 'example.com', '--sources', 'certspotter']).options.sources, ['certspotter']);
    assert.throws(() => parseCommandLine(['ct', 'example.com', '--sources', 'hackertarget']), /unknown source "hackertarget" \(one of crtsh, certspotter\)/);
  });

  test('drift and dane take exactly one file; drift\'s origin and budget', () => {
    assert.deepEqual(parseCommandLine(['drift', 'zone.txt']).targets, ['zone.txt']);
    assert.throws(() => parseCommandLine(['drift']), /drift takes one file/);
    assert.throws(() => parseCommandLine(['dane', 'a.pem', 'b.pem']), /dane takes one file, not 2/);
    const cl = parseCommandLine(['drift', 'zone.txt', '--origin', 'Example.COM.', '--max-queries', '500', '--include-origins']);
    assert.equal(cl.options.origin, 'example.com');
    assert.equal(cl.options.maxQueries, 500);
    assert.equal(cl.options.includeOrigins, true);
    assert.equal(parseCommandLine(['drift', 'zone.txt']).options.maxQueries, 2000);
    assert.throws(() => parseCommandLine(['drift', 'z.txt', '--max-queries', '10001']), /from 1 to 10000/);
    assert.throws(() => parseCommandLine(['drift', 'z.txt', '--origin', '192.0.2.1']), /--origin: not a zone name/);
  });

  test('renew: wildcards, the CA and the challenge; names a certificate cannot carry refused', () => {
    const cl = parseCommandLine(['renew', 'example.com', '*.example.com', '--ca', 'LetsEncrypt', '--challenge', 'DNS-01']);
    assert.deepEqual(cl.targets, ['example.com', '*.example.com']);
    assert.equal(cl.options.ca, 'letsencrypt');
    assert.equal(cl.options.challenge, 'dns-01');
    assert.equal(parseCommandLine(['renew', 'example.com']).options.challenge, 'unknown');
    assert.throws(() => parseCommandLine(['renew', '192.0.2.1']), /not a name a certificate can carry: "192.0.2.1"/);
    assert.throws(() => parseCommandLine(['renew', '*.com.tr']), /not a name a certificate can carry/);
    assert.throws(() => parseCommandLine(['renew', 'example.com', '--ca', 'acme']), /unknown CA "acme"/);
    assert.throws(() => parseCommandLine(['renew', 'example.com', '--challenge', 'email']), /--challenge takes http-01, dns-01, tls-alpn-01, unknown/);
  });

  test('audit: a policy file or a preset (one of them), a file of domains as a target, registrable domains, --no-dkim', () => {
    const cl = parseCommandLine(['audit', '--preset', 'Baseline', 'https://www.example.com/x', 'example.com', 'mail.example.org']);
    assert.deepEqual(cl.targets, ['example.com', 'example.org'], 'each domain once, as its registrable domain');
    assert.deepEqual([cl.options.preset, cl.options.policy, cl.options.dkim], ['baseline', null, true]);
    const file = parseCommandLine(['audit', '--policy', 'policy.json', 'domains.txt', join('lists', 'more'), 'example.net', '--no-dkim']);
    assert.deepEqual(file.options.lists, ['domains.txt', join('lists', 'more')], 'a list extension or a path is a file of domains');
    assert.deepEqual(file.targets, ['example.net']);
    assert.deepEqual([file.options.policy, file.options.preset, file.options.dkim], ['policy.json', null, false]);
    assert.deepEqual(parseCommandLine(['audit', '--preset', 'parked', '--list', 'd.lst']).options.lists, ['d.lst']);
    assert.throws(() => parseCommandLine(['audit', 'example.com']), /audit needs the rules: --policy FILE or --preset NAME \(one of them\)/);
    assert.throws(() => parseCommandLine(['audit', 'example.com', '--policy', 'p.json', '--preset', 'baseline']), /one of them/);
    assert.throws(() => parseCommandLine(['audit', 'example.com', '--preset', 'strict']), /--preset takes baseline, strict-mail, parked, not "strict"/);
    assert.throws(() => parseCommandLine(['audit', 'example.com', '--policy', '-']), /--policy takes a file, not "-"/);
    assert.throws(() => parseCommandLine(['audit', '--preset', 'baseline']), /audit needs at least one domain \(or --list FILE\)/);
    assert.throws(() => parseCommandLine(['audit', '--preset', 'baseline', '192.0.2.1', 'com.tr']), /not a domain name: "192\.0\.2\.1", "com\.tr"/);
    assert.throws(() => parseCommandLine(['audit', 'example.com', '--policy', 'p.json', '--json', 'p.json']), /--json names the same file as --policy \(p\.json\)/);
    assert.throws(() => parseCommandLine(['audit', '--preset', 'baseline', 'domains.txt', '--md', 'domains.txt']), /--md names the same file as --list \(domains\.txt\)/);
    assert.deepEqual(parseListText('audit', 'www.example.com\nexample.com, mail.example-test.com.tr\n# not this\n203.0.113.9'), {
      targets: ['example.com', 'example-test.com.tr'], invalid: ['203.0.113.9']
    });
  });

  test('--list text: several per line, comments; invalid entries are returned, not thrown', () => {
    const text = '# the watch list\nexample.com, example.org ; www.example.net  # inline\n\nnot_a_host!\n192.0.2.1\nexample.com\n';
    assert.deepEqual(parseListText('health', text), { targets: ['example.com', 'example.org', 'www.example.net'], invalid: ['not_a_host!', '192.0.2.1'] });
    assert.deepEqual(parseListText('renew', '*.example.com\nexample.com\n*.co.uk').targets, ['*.example.com', 'example.com']);
    assert.deepEqual(parseListText('renew', '*.co.uk').invalid, ['*.co.uk']);
    assert.deepEqual(parseTargets('dane', ['cert.pem']), { targets: ['cert.pem'], invalid: [] });
    for (const c of COMMANDS) assert.ok(COMMAND_SPECS[c], c);
  });
});

/* ------------------------------------------------------------------------ */
/* Baseline                                                                 */
/* ------------------------------------------------------------------------ */

describe('baseline', () => {
  test('a report of another tool, version or command, or a damaged list, cannot be a baseline', () => {
    assert.match(baselineProblem([], 'health'), /not a --json report of domainscope-ds/);
    assert.match(baselineProblem({ tool: 'ssl_origin_scan' }, 'health'), /not a --json report/);
    assert.match(baselineProblem({ ...report('health', []), version: '2.0.0' }, 'health'), /written by version "2.0.0", which this version \(1\.0\.0\) cannot compare/);
    assert.match(baselineProblem(report('ct', []), 'health'), /a report of "ct", not of "health"/);
    assert.match(baselineProblem({ ...report('health', []), targets: {} }, 'health'), /no "targets" list/);
    assert.match(baselineProblem(report('health', [{ target: 'example.com', checks: [{ id: 'a' }] }]), 'health'), /targets\[0\] checks\[0\] has no "severity"/);
    assert.match(baselineProblem(report('subdomains', [{ target: 'example.com', mode: 'discover', hosts: [{ name: 'a.example.com', ipv4: '192.0.2.1' }] }]), 'subdomains'), /hosts\[0\] has addresses that are not lists/);
    assert.match(baselineProblem(report('drift', [{ target: 'example.com', rows: [{ key: 'x|A' }] }]), 'drift'), /rows\[0\] has no "status"/);
    assert.match(baselineProblem(report('renew', [{ target: 'example.com' }]), 'renew'), /has no "verdict"/);
    assert.match(baselineProblem(report('dane', [{ target: 'x', endpoints: [{ key: 'k' }] }]), 'dane'), /endpoints\[0\] has no "status"/);
    assert.match(baselineProblem(report('audit', [{ target: 'example.com', rules: [{ id: 'dnssec', status: 'maybe' }] }]), 'audit'), /rules\[0\] has no "status" \(pass, fail or unknown\)/);
    assert.match(baselineProblem(report('audit', [{ target: 'example.com', rules: [{ status: 'pass' }] }]), 'audit'), /rules\[0\] has no "id"/);
    assert.match(baselineProblem(report('ct', [{ target: 'example.com', names: [], issuers: [], certificates: [{ id: 'x', ca: 'y' }] }]), 'ct'), /certificates\[0\] has no "names" list/);
    assert.match(baselineProblem(report('ct', [{ target: 'example.com', names: [], issuers: [], certificates: [{ id: 'x', ca: 'y', names: [], carried: true }] }]), 'ct'), /certificates\[0\] has a "carried" without a "from"/);
    assert.match(baselineProblem(report('ct', [{ target: 'example.com', names: [], issuers: [], sources: [{ source: 'crtsh', lastFullAt: 5 }], certificates: [] }]), 'ct'), /sources\[0\] has a "lastFullAt" that is not text/);
    assert.match(baselineProblem(report('health', [{ target: 'example.com', checks: [], carried: [{ area: 'dmarc', from: null, checks: [{ id: 'x' }] }] }]), 'health'), /carried\[0\] checks\[0\] has no "severity"/);
    assert.match(baselineProblem(report('health', [{ checks: [] }]), 'health'), /targets\[0\] has no "target"/);
    assert.equal(baselineProblem({ ...report('health', [{ target: 'example.com', score: 90, checks: [] }]), version: '1.4.2' }, 'health'), null);
  });

  test('the baseline block names the file by its base name', () => {
    assert.deepEqual(baselineInfo(report('health', []), 'results/nightly/health.json'), {
      file: 'health.json', missing: false, version: DS_VERSION, startedAt: '2026-09-27T03:00:00.000Z', finishedAt: '2026-09-27T03:02:00.000Z'
    });
    assert.equal(baselineInfo(report('health', []), 'C:\\jobs\\health.json').file, 'health.json');
  });

  test('notes say what the two runs did differently', () => {
    const sub = (o) => report('subdomains', [], { options: o });
    assert.match(baselineNotes('subdomains', sub({ mode: 'discover', level: 'small', sources: null }), sub({ mode: 'discover', level: 'smart', sources: null }))[0], /wordlist level or the sources differ .*small \/ default → smart \/ default/);
    assert.match(baselineNotes('subdomains', sub({ mode: 'exact' }), sub({ mode: 'discover' }))[0], /The mode differs/);
    const rn = (o) => report('renew', [], { options: o });
    assert.match(baselineNotes('renew', rn({ ca: 'letsencrypt', challenge: 'http-01' }), rn({ ca: 'letsencrypt', challenge: 'dns-01' }))[0], /The CA or the challenge differs/);
    const dn = (o) => report('dane', [], { options: o });
    assert.match(baselineNotes('dane', dn({ serialHex: '01' }), dn({ serialHex: '02' }))[0], /The certificate differs from the baseline's \(serial 01 → 02\)/);
    const h = (r) => report('health', [], { options: { resolvers: r } });
    assert.match(baselineNotes('health', h(['cloudflare']), h(['google']))[0], /The resolvers differ/);
    assert.deepEqual(baselineNotes('health', h(['cloudflare']), h(['cloudflare'])), []);
    const au = (rules, dkim = true) => report('audit', [], { options: { policy: { name: 'x', version: 1, rules }, dkim } });
    assert.match(baselineNotes('audit', au({ dnssec: '>= signed' }), au({ dnssec: '>= validated' }))[0], /The policy differs from the baseline's/);
    assert.match(baselineNotes('audit', au({ dkim: true }), au({ dkim: true }, false))[0], /DKIM was checked in one run and not in the other \(--no-dkim\)/);
    assert.deepEqual(baselineNotes('audit', au({ dkim: true }), au({ dkim: true })), []);
  });
});

/* ------------------------------------------------------------------------ */
/* Diffs                                                                    */
/* ------------------------------------------------------------------------ */

const check = (id, severity, params = {}) => ({ id, severity, titleKey: `health.${id}.title`, params });

describe('diff: health', () => {
  const before = report('health', [
    { target: 'example.com', score: 88, failedLookups: [], checks: [check('spf.present', 'ok'), check('dmarc.policy-none', 'warn'), check('caa.missing', 'info'), check('mx.unresolvable', 'error', { hosts: 'mx2.example.net' })] },
    { target: 'example.net', score: 100, failedLookups: [], checks: [check('spf.present', 'ok')] }
  ]);

  test('new, worse, better and gone findings, the score, and targets that come and go', () => {
    const after = report('health', [
      { target: 'example.com', score: 74, failedLookups: [], checks: [check('spf.present', 'ok'), check('dmarc.policy-none', 'error'), check('caa.missing', 'warn'), check('dkim.none', 'warn'), check('ns.single-provider', 'info')] },
      { target: 'example.org', score: 100, failedLookups: [], checks: [] }
    ]);
    const changes = diffReports('health', before, after, { t });
    assert.deepEqual(tags(changes), [
      'SCORE example.com', 'WORSE example.com dmarc.policy-none', 'WORSE example.com caa.missing', 'NEW example.com dkim.none',
      'GONE example.com mx.unresolvable', 'NEW example.org', 'GONE example.net'
    ]);
    const score = changes[0];
    assert.equal(score.tone, 'bad');
    assert.equal(changeText(score), 'example.com: health score 88 → 74');
    assert.equal(changes.find((c) => c.item === 'mx.unresolvable').tone, 'good');
    assert.match(changeText(changes.find((c) => c.item === 'dkim.none')), /^example\.com: warn dkim\.none — /);
    assert.ok(changes.every((c) => c.counts));
  });

  test('a finding gone while a lookup failed is listed, not counted', () => {
    const after = report('health', [
      { target: 'example.com', score: 88, failedLookups: ['mx'], checks: [check('spf.present', 'ok'), check('dmarc.policy-none', 'warn'), check('caa.missing', 'info'), check('mx.error', 'warn', { error: 'timeout' })] },
      { target: 'example.net', score: 100, failedLookups: [], checks: [check('spf.present', 'ok')] }
    ]);
    const changes = diffReports('health', before, after, { t });
    assert.deepEqual(tags(changes), ['NEW example.com mx.error', 'GONE? example.com mx.unresolvable']);
    assert.match(changeText(changes[1]), /\(its lookup failed this run: it may still be there\)$/);
    assert.deepEqual(tags(notableChanges(changes)), ['NEW example.com mx.error']);
  });

  test('a broken SPF include is a finding, not a failed lookup; a failed lookup hides its own area only', () => {
    const b = report('health', [{ target: 'example.com', score: 54, checks: [check('spf.include-error', 'error'), check('dmarc.policy-none', 'warn')] }]);
    const a = report('health', [{ target: 'example.com', score: 60, checks: [check('spf.include-error', 'error'), check('rdap.expiry-ok', 'ok')] }]);
    assert.deepEqual(tags(diffReports('health', b, a, { t })), ['SCORE example.com', 'GONE example.com dmarc.policy-none']);
    // RDAP failed: the score it moved is listed only, but DMARC was read and its finding is gone.
    const rdap = report('health', [{ target: 'example.com', score: 60, checks: [check('spf.include-error', 'error'), check('rdap.error', 'info')] }]);
    assert.deepEqual(tags(diffReports('health', b, rdap, { t })), ['GONE example.com dmarc.policy-none', 'SCORE? example.com']);
    const dmarc = report('health', [{ target: 'example.com', score: 60, checks: [check('spf.include-error', 'error'), check('dmarc.error', 'info')] }]);
    assert.deepEqual(tags(diffReports('health', b, dmarc, { t })), ['SCORE? example.com', 'GONE? example.com dmarc.policy-none']);
  });

  test('moves among ok and info are no change; a repeated id counts by its worst severity', () => {
    const b = report('health', [{ target: 'example.com', score: 100, checks: [check('caa.missing', 'info'), check('x.y', 'ok')] }]);
    const a = report('health', [{ target: 'example.com', score: 100, checks: [check('caa.missing', 'ok'), check('x.y', 'info'), check('x.y', 'ok')] }]);
    assert.deepEqual(diffReports('health', b, a, { t }), []);
    const a2 = report('health', [{ target: 'example.com', score: 94, checks: [check('caa.missing', 'info'), check('x.y', 'ok'), check('x.y', 'warn')] }]);
    assert.deepEqual(tags(diffReports('health', b, a2, { t })), ['SCORE example.com', 'WORSE example.com x.y']);
  });

  test('the areas a failed lookup hides: its own, what it feeds, and the checks that need it', () => {
    assert.deepEqual([...failedAreas({ checks: [check('mx.error', 'warn'), check('spf.include-error', 'error')] })].sort(), ['mail-identity', 'mx']);
    assert.deepEqual([...failedAreas({ checks: [check('dmarc.error', 'warn')], failedLookups: ['txt', 'aaaa'] })].sort(), ['apex', 'bimi', 'dmarc', 'ipv6', 'spf']);
    assert.deepEqual([...failedAreas({ checks: [check('mail-identity.fcrdns-error', 'info'), check('rdap.error', 'info')] })].sort(), ['mail-identity', 'rdap']);
    assert.equal(failedAreas({ checks: [check('spf.present', 'ok')], failedLookups: [] }).size, 0);
    assert.deepEqual(checkAreas('ns.rdap-mismatch'), ['ns', 'rdap']);
    assert.deepEqual(checkAreas('dmarc.policy-none'), ['dmarc']);
  });

  /** A health target of one night, carrying what its failed lookups hid from `prev` (commands.mjs healthTarget). */
  const night = (at, score, checks, prev = null, failedLookups = []) => {
    const x = { target: 'example.com', checkedAt: at, score, failedLookups, checks };
    const carried = carryHealth(x, prev);
    return carried.length ? { ...x, carried } : x;
  };

  test('a failed lookup carries its area as last read: the night after compares with that, never with the gap', () => {
    const n1 = night('2026-09-26T03:00:00.000Z', 94, [check('dmarc.policy-none', 'warn'), check('dmarc.present', 'ok'), check('spf.present', 'ok')]);
    const n2 = night('2026-09-27T03:00:00.000Z', 80, [check('dmarc.error', 'warn', { error: 'SERVFAIL' }), check('spf.present', 'ok')], n1);
    assert.deepEqual(n2.carried, [
      { area: 'bimi', from: '2026-09-26T03:00:00.000Z', checks: [] },
      { area: 'dmarc', from: '2026-09-26T03:00:00.000Z', checks: [check('dmarc.policy-none', 'warn'), check('dmarc.present', 'ok')] }
    ]);
    assert.deepEqual(tags(diffReports('health', report('health', [n1]), report('health', [n2]), { t })),
      ['NEW example.com dmarc.error', 'SCORE? example.com', 'GONE? example.com dmarc.policy-none']);
    // DMARC answers again with the warning of months: nothing new; the failed lookup is gone.
    const n3 = night('2026-09-28T03:00:00.000Z', 94, n1.checks, n2);
    const back = diffReports('health', report('health', [n2]), report('health', [n3]), { t });
    assert.deepEqual(tags(back), ['GONE example.com dmarc.error', 'SCORE? example.com']);
    assert.equal(changeText(back[1]), 'example.com: health score 80 → 94 (a lookup failed in the baseline run)');
    // A finding that did appear meanwhile is new, and counts.
    const moved = night('2026-09-28T03:00:00.000Z', 88, [check('dmarc.policy-none', 'warn'), check('dmarc.rua-missing', 'warn'), check('spf.present', 'ok')], n2);
    assert.deepEqual(tags(diffReports('health', report('health', [n2]), report('health', [moved]), { t })),
      ['NEW example.com dmarc.rua-missing', 'GONE example.com dmarc.error', 'SCORE? example.com']);
  });

  test('two nights of failed lookups carry the last read on; an area no run read makes its findings "new" listed only', () => {
    const n1 = night('2026-09-25T03:00:00.000Z', 94, [check('dmarc.policy-none', 'warn')]);
    const n2 = night('2026-09-26T03:00:00.000Z', 80, [check('dmarc.error', 'warn')], n1);
    const n3 = night('2026-09-27T03:00:00.000Z', 80, [check('dmarc.error', 'warn')], n2);
    assert.deepEqual(n3.carried.find((c) => c.area === 'dmarc'), { area: 'dmarc', from: '2026-09-25T03:00:00.000Z', checks: [check('dmarc.policy-none', 'warn')] });
    assert.deepEqual(diffReports('health', report('health', [n2]), report('health', [n3]), { t }), []);
    // The first run of a domain whose DMARC lookup failed: no run read DMARC yet.
    const first = night('2026-09-26T03:00:00.000Z', 80, [check('dmarc.error', 'warn')]);
    assert.deepEqual(first.carried.find((c) => c.area === 'dmarc'), { area: 'dmarc', from: null, checks: [] });
    const read = night('2026-09-27T03:00:00.000Z', 94, [check('dmarc.policy-none', 'warn')], first);
    const changes = diffReports('health', report('health', [first]), report('health', [read]), { t });
    assert.deepEqual(tags(changes), ['GONE example.com dmarc.error', 'SCORE? example.com', 'NEW? example.com dmarc.policy-none']);
    assert.match(changeText(changes[2]), /\(its lookup failed in the baseline run: it may not be new\)$/);
    // An SPF record read while its includes failed keeps what it read; the area goes on carried.
    const spf1 = night('2026-09-26T03:00:00.000Z', 90, [check('spf.all-missing', 'warn'), check('spf.lookups-exceeded', 'error')]);
    const spf2 = night('2026-09-27T03:00:00.000Z', 85, [check('spf.all-missing', 'warn'), check('spf.dns-error', 'warn')], spf1);
    assert.deepEqual(spf2.carried, [{ area: 'spf', from: '2026-09-26T03:00:00.000Z', checks: [check('spf.lookups-exceeded', 'error')] }]);
  });

  test('a string param of a title is a code part (Markdown code span), numbers stay text', () => {
    const b = report('health', [{ target: 'example.com', score: 100, checks: [] }]);
    const a = report('health', [{ target: 'example.com', score: 80, checks: [check('dmarc.inherited', 'warn', { org: '@team example.com' })] }]);
    const [, c] = diffReports('health', b, a, { t });
    assert.ok(c.parts.some((p) => p && p.code === '@team example.com'), JSON.stringify(c.parts));
    assert.match(renderChangesMarkdown({ command: 'health', baseline: baselineInfo(b, 'h.json'), changes: [c] }), /DMARC inherited from `@team example\.com`/);
  });
});

const host = (name, extra = {}) => ({
  name, status: 'NOERROR', kind: 'direct', provider: null, providerId: null, hidesOrigin: false, dangling: false,
  ipv4: [], ipv6: [], cnames: [], origins: ['crtsh'], wildcardSuspect: false, error: null, ...extra
});

describe('diff: subdomains', () => {
  const cf = { kind: 'cloudflare', provider: 'Cloudflare', providerId: 'cloudflare', hidesOrigin: true };
  const before = report('subdomains', [{
    target: 'example.com', mode: 'discover', hosts: [
      host('www.example.com', { ...cf, ipv4: ['104.16.1.1'] }),
      host('api.example.com', { ipv4: ['192.0.2.10'] }),
      host('old.example.com', { ipv4: ['192.0.2.20'] }),
      host('db.example.com', { ipv4: ['192.0.2.30'] }),
      host('flaky.example.com', { status: 'SERVFAIL', error: 'SERVFAIL' }),
      host('shop.example.com', { ...cf, ipv4: ['104.16.1.2'] }),
      host('cdn.example.com', { kind: 'cdn', provider: 'Fastly', providerId: 'fastly', ipv4: ['198.51.100.71'] }),
      host('gone-from-result.example.com', { ipv4: ['192.0.2.40'] }),
      host('ghost.example.com', { ipv4: ['192.0.2.50'], wildcardSuspect: true })
    ]
  }]);

  test('new, dangling, gone, failed, failing, exposed, moved and renumbered hosts', () => {
    const after = report('subdomains', [{
      target: 'example.com', mode: 'discover', hosts: [
        host('www.example.com', { ipv4: ['192.0.2.9'] }),
        host('api.example.com', { ipv4: ['192.0.2.11'] }),
        host('old.example.com', { status: 'NXDOMAIN', kind: 'nxdomain' }),
        host('db.example.com', { status: 'SERVFAIL', error: 'SERVFAIL' }),
        host('flaky.example.com', { status: 'REFUSED', error: 'REFUSED' }),
        host('shop.example.com', { ...cf, ipv4: ['104.16.1.3'] }),
        host('cdn.example.com', { kind: 'cdn', provider: 'Akamai', providerId: 'akamai', ipv4: ['198.51.100.72'] }),
        host('new.example.com', { ipv4: ['192.0.2.60'] }),
        host('blog.example.com', { status: 'NXDOMAIN', kind: 'nxdomain', dangling: true, cnames: ['gone.example.net'] }),
        host('nothing.example.com', { status: 'NXDOMAIN', kind: 'nxdomain' }),
        host('ghost2.example.com', { ipv4: ['192.0.2.51'], wildcardSuspect: true })
      ]
    }]);
    const changes = diffReports('subdomains', before, after, { t });
    assert.deepEqual(tags(changes), [
      'EXPOSED example.com www.example.com', 'CHANGED example.com api.example.com', 'GONE example.com old.example.com',
      'FAILED example.com db.example.com', 'CHANGED example.com cdn.example.com', 'NEW example.com new.example.com',
      'DANGLING example.com blog.example.com', 'FAILING? example.com flaky.example.com', 'GONE? example.com gone-from-result.example.com'
    ]);
    assert.match(changeText(changes[0]), /www\.example\.com — no longer behind Cloudflare: now direct 192\.0\.2\.9/);
    assert.match(changeText(changes[1]), /addresses direct 192\.0\.2\.10 → direct 192\.0\.2\.11/);
    assert.match(changeText(changes.find((c) => c.tag === 'DANGLING')), /dangling CNAME to gone\.example\.net/);
    assert.match(changeText(changes[2]), /old\.example\.com — no longer resolves: NXDOMAIN$/);
    const nodata = diffReports('subdomains', before, report('subdomains', [{ target: 'example.com', mode: 'discover', hosts: [
      ...after.targets[0].hosts.filter((h) => h.name !== 'old.example.com'), host('old.example.com', { kind: 'unresolved' })] }]), { t });
    assert.match(changeText(nodata.find((c) => c.item === 'old.example.com')), /no longer resolves: no address \(NODATA\)$/);
    assert.match(changeText(changes.at(-1)), /not in this run's result/);
  });

  test('exact mode: a name taken out of the file is gone and counts', () => {
    const b = report('subdomains', [{ target: 'example.com', mode: 'exact', hosts: [host('a.example.com', { ipv4: ['192.0.2.1'] }), host('b.example.com', { ipv4: ['192.0.2.2'] })] }]);
    const a = report('subdomains', [{ target: 'example.com', mode: 'exact', hosts: [host('a.example.com', { ipv4: ['192.0.2.1'] })] }]);
    assert.deepEqual(tags(diffReports('subdomains', b, a, { t })), ['GONE example.com b.example.com']);
  });

  test('the previous run\'s resolving hosts and failed lookups seed the next discovery (never wildcard suspects or dead names)', () => {
    assert.deepEqual(baselineSeeds(before, 'example.com'), ['www.example.com', 'api.example.com', 'old.example.com', 'db.example.com',
      'flaky.example.com', 'shop.example.com', 'cdn.example.com', 'gone-from-result.example.com']);
    assert.deepEqual(baselineSeeds(before, 'example.org'), []);
    assert.deepEqual(baselineSeeds(report('subdomains', [{ target: 'example.com', mode: 'exact', hosts: [host('a.example.com', { ipv4: ['192.0.2.1'] })] }]), 'example.com'), []);
    assert.deepEqual(baselineSeeds(null, 'example.com'), []);
    const row = hostRow({ name: 'x.example.com', status: 'NOERROR', kind: 'cdn', provider: 'Fastly', providerId: 'fastly', hidesOrigin: false, dangling: false,
      ipv4: ['151.101.2.1', '151.101.1.1', '151.101.1.1'], ipv6: [], cnames: [], origins: ['input', 'crtsh'], wildcardSuspect: false, error: null, ttl: 30, resolver: 'google' }, new Set(['x.example.com']));
    assert.deepEqual(row.ipv4, ['151.101.1.1', '151.101.2.1']);
    assert.deepEqual(row.origins, ['baseline', 'crtsh']);
    assert.ok(!('ttl' in row) && !('resolver' in row));
  });

  test('a discovery report lists what resolves, dangles, failed or was seeded; an exact one lists every name', () => {
    const rows = [
      host('a.example.com', { ipv4: ['192.0.2.1'] }), host('dead.example.com', { status: 'NXDOMAIN', kind: 'nxdomain' }),
      host('nodata.example.com', { kind: 'unresolved' }), host('blog.example.com', { status: 'NXDOMAIN', dangling: true, cnames: ['x.example.net'] }),
      host('flaky.example.com', { status: 'SERVFAIL' }), host('seeded.example.com', { status: 'NXDOMAIN', kind: 'nxdomain' }),
      host('w1.example.com', { ipv4: ['192.0.2.9'], wildcardSuspect: true })
    ];
    assert.deepEqual(reportHosts(rows, { exact: false, seeded: new Set(['seeded.example.com']) }).map((h) => h.name),
      ['a.example.com', 'blog.example.com', 'flaky.example.com', 'seeded.example.com']);
    assert.equal(reportHosts(rows, { exact: true, seeded: new Set() }).length, rows.length);
  });

  test('a host whose lookup failed keeps its last answer; answering again, it is compared with that', () => {
    const sub = (hosts, finishedAt) => ({ target: 'example.com', mode: 'discover', finishedAt, hosts });
    const n1 = sub([host('shop.example.com', { ...cf, ipv4: ['104.16.1.2'] }), host('api.example.com', { ipv4: ['192.0.2.10'] })], '2026-09-26T03:05:00.000Z');
    const failing = [host('shop.example.com', { status: 'SERVFAIL', kind: 'error', error: 'SERVFAIL' }), host('api.example.com', { status: 'SERVFAIL', kind: 'error', error: 'SERVFAIL' })];
    const n2 = sub(carryHosts(failing, n1), '2026-09-27T03:05:00.000Z');
    assert.deepEqual(n2.hosts[0].lastGood, {
      at: '2026-09-26T03:05:00.000Z', status: 'NOERROR', kind: 'cloudflare', provider: 'Cloudflare', providerId: 'cloudflare', hidesOrigin: true,
      dangling: false, ipv4: ['104.16.1.2'], ipv6: [], cnames: []
    });
    // A second night of SERVFAIL keeps the answer of the first night.
    const n3 = sub(carryHosts(failing, n2), '2026-09-28T03:05:00.000Z');
    assert.equal(n3.hosts[0].lastGood.at, '2026-09-26T03:05:00.000Z');
    assert.equal(baselineSeeds(report('subdomains', [n3]), 'example.com').length, 2, 'failed lookups are looked up again');
    // shop comes back without its proxy, api as it was.
    const n4 = sub([host('shop.example.com', { ipv4: ['192.0.2.44'] }), host('api.example.com', { ipv4: ['192.0.2.10'] })]);
    const changes = diffReports('subdomains', report('subdomains', [n3]), report('subdomains', [n4]), { t });
    assert.deepEqual(tags(changes), ['EXPOSED example.com shop.example.com', 'RECOVERED example.com api.example.com']);
    assert.equal(changeText(changes[0]), 'example.com: shop.example.com — no longer behind Cloudflare: now direct 192.0.2.44 (compared with its answer of 2026-09-26, before the lookup failed)');
    assert.equal(changeText(changes[1]), 'example.com: api.example.com — answers again as before: direct 192.0.2.10');
    assert.equal(changes[1].tone, 'good');
    // Without a last answer (the report of a run that never read it), the move is said as it is.
    const bare = sub([host('api.example.com', { status: 'SERVFAIL', error: 'SERVFAIL' })]);
    const nx = diffReports('subdomains', report('subdomains', [bare]), report('subdomains', [sub([host('api.example.com', { status: 'NXDOMAIN', kind: 'nxdomain' })])]), { t });
    assert.deepEqual(tags(nx), ['RECOVERED example.com api.example.com']);
    assert.equal(changeText(nx[0]), 'example.com: api.example.com — answers again: NXDOMAIN');
    assert.equal(nx[0].tone, 'bad');
    assert.match(baselineProblem(report('subdomains', [sub([host('a.example.com', { status: 'SERVFAIL', lastGood: { at: null, ipv4: '192.0.2.1' } })])]), 'subdomains'),
      /hosts\[0\] lastGood has addresses that are not lists of text/);
  });
});

const cert = (ca, intermediate, notBefore, names, extra = {}) => {
  const c = { ca, intermediate, issuer: `C=US, O=${ca}, CN=${intermediate}`, notBefore, notAfter: '2026-12-01T00:00:00.000Z', names, sha256: null, sources: ['crtsh'], ...extra };
  return { id: ctCertId(c), ...c };
};
const ctT = (certificates, extra = {}) => ({
  target: 'example.com', days: 30, sources: [{ source: 'crtsh', ok: true, state: 'ok' }, { source: 'certspotter', ok: true, state: 'ok' }],
  complete: true, answered: true, recent: 0, issuers: [...new Set(certificates.map((c) => c.ca))].map((name) => ({ name, count: certificates.filter((c) => c.ca === name).length, intermediates: [], newest: certificates.find((c) => c.ca === name).notBefore })),
  names: [...new Set(certificates.flatMap((c) => c.names))], certificates, ...extra
});

describe('diff: ct', () => {
  const le1 = cert("Let's Encrypt", 'R11', '2026-09-01T00:00:00.000Z', ['example.com', 'www.example.com']);
  const before = report('ct', [ctT([le1])]);

  test('a new issuer and a first certificate for a name count; a renewal from a known issuer is listed only', () => {
    const le2 = cert("Let's Encrypt", 'R10', '2026-09-27T00:00:00.000Z', ['example.com', 'www.example.com']);
    const gts = cert('Google Trust Services', 'WR1', '2026-09-26T00:00:00.000Z', ['example.com']);
    const api = cert("Let's Encrypt", 'R11', '2026-09-25T00:00:00.000Z', ['api.example.com']);
    const changes = diffReports('ct', before, report('ct', [ctT([le2, gts, api, le1])]), { t });
    assert.deepEqual(tags(changes), ['ISSUER example.com Google Trust Services', 'NAME example.com api.example.com', `CERT? example.com ${le2.id}`]);
    assert.equal(changes[0].tone, 'bad');
    assert.match(changeText(changes[0]), /new issuer Google Trust Services: 1 current certificate, newest 2026-09-26/);
    assert.match(changeText(changes[1]), /first certificate for api\.example\.com \(Let's Encrypt, 2026-09-25\)/);
    assert.match(changeText(changes[2]), /new certificate from Let's Encrypt \(R10\), 2026-09-27: example\.com, www\.example\.com/);
  });

  test('an issuer or a name only a source the baseline missed lists is listed only; one a source read in full both nights lists counts', () => {
    const b = report('ct', [ctT([le1], { complete: false, sources: [{ source: 'crtsh', ok: false, state: 'timeout' }, { source: 'certspotter', ok: true, state: 'ok' }] })]);
    const gts = cert('Google Trust Services', 'WR1', '2026-09-26T00:00:00.000Z', ['example.com', 'mail.example.com']);
    const changes = diffReports('ct', b, report('ct', [ctT([gts, le1])]), { t });
    assert.deepEqual(tags(changes), ['ISSUER? example.com Google Trust Services', 'NAME? example.com mail.example.com']);
    assert.match(changeText(changes[0]), /listed only by a source no earlier run read in full: it may not be new\)$/);
    // Cert Spotter read the domain in full on both nights and lists it now: it is new.
    const both = cert('Google Trust Services', 'WR1', '2026-09-26T00:00:00.000Z', ['example.com', 'mail.example.com'], { sources: ['certspotter', 'crtsh'] });
    const counted = diffReports('ct', b, report('ct', [ctT([both, le1])]), { t });
    assert.deepEqual(tags(counted), ['ISSUER example.com Google Trust Services', 'NAME example.com mail.example.com']);
    assert.doesNotMatch(changeText(counted[0]), /may not be new/);
  });

  test('a certificate issued after the baseline run is new whichever source lists it, once the baseline read one source in full', () => {
    const crtshOnly = [{ source: 'crtsh', ok: true, state: 'ok' }, { source: 'certspotter', ok: false, state: 'rate-limited' }];
    const b = report('ct', [ctT([le1], { complete: false, sources: crtshOnly })]);
    // Tonight crt.sh is down and Cert Spotter answers, which the baseline did not read.
    const tonight = [{ source: 'crtsh', ok: false, state: 'unavailable' }, { source: 'certspotter', ok: true, state: 'ok' }];
    const late = cert('Google Trust Services', 'WR1', '2026-09-27T12:00:00.000Z', ['example.com'], { sources: ['certspotter'] });
    assert.deepEqual(tags(diffReports('ct', b, report('ct', [ctT([late, le1], { complete: false, sources: tonight })]), { t })), ['ISSUER example.com Google Trust Services']);
    const early = cert('Google Trust Services', 'WR1', '2026-09-26T12:00:00.000Z', ['example.com'], { sources: ['certspotter'] });
    assert.deepEqual(tags(diffReports('ct', b, report('ct', [ctT([early, le1], { complete: false, sources: tonight })]), { t })), ['ISSUER? example.com Google Trust Services']);
    // A baseline that read nothing in full (crt.sh's lighter search, Cert Spotter cut at its page cap) confirms nothing.
    const partial = report('ct', [ctT([le1], { complete: false, sources: [{ source: 'crtsh', ok: true, state: 'partial' }, { source: 'certspotter', ok: true, state: 'ok', truncated: true }] })]);
    assert.deepEqual(tags(diffReports('ct', partial, report('ct', [ctT([late, le1], { complete: false, sources: tonight })]), { t })), ['ISSUER? example.com Google Trust Services']);
  });

  test('a night CT could not be read carries the last read on: the night after, a new CA counts', () => {
    const at = (day) => `2026-09-${day}T03:00:00.000Z`;
    const both = [{ source: 'crtsh', ok: true, state: 'ok' }, { source: 'certspotter', ok: true, state: 'ok' }];
    const n1 = carryCt(ctT([le1], { readAt: at(26), sources: both }), null, { now: new Date(at(26)) });
    assert.deepEqual(n1.sources.map((s) => s.lastFullAt), [at(26), at(26)]);
    const down = [{ source: 'crtsh', ok: false, state: 'unavailable' }, { source: 'certspotter', ok: false, state: 'rate-limited', skipped: true }];
    const n2 = carryCt(ctT([], { readAt: at(27), answered: false, complete: false, sources: down }), n1, { now: new Date(at(27)) });
    assert.deepEqual(n2.certificates, [{ ...le1, carried: { from: at(26) } }]);
    assert.deepEqual(n2.issuers.map((g) => g.name), ["Let's Encrypt"]);
    assert.deepEqual(n2.names, ['example.com', 'www.example.com']);
    assert.deepEqual(n2.sources.map((s) => s.lastFullAt), [at(26), at(26)]);
    assert.deepEqual(tags(diffReports('ct', report('ct', [n1]), report('ct', [n2]), { t })), ['FAILED? example.com']);
    // A second night down: the certificate stays carried from the first read.
    const n2b = carryCt(ctT([], { readAt: at(28), answered: false, complete: false, sources: down }), n2, { now: new Date(at(28)) });
    assert.deepEqual(n2b.certificates[0].carried, { from: at(26) });
    assert.deepEqual(diffReports('ct', report('ct', [n2]), report('ct', [n2b]), { t }), []);
    // crt.sh is back and lists a certificate from a new CA, issued while it was down.
    const gts = cert('Google Trust Services', 'WR1', '2026-09-27T12:00:00.000Z', ['example.com', 'mail.example.com']);
    const crtshOnly = [{ source: 'crtsh', ok: true, state: 'ok' }, { source: 'certspotter', ok: false, state: 'rate-limited' }];
    const n3 = carryCt(ctT([gts, le1], { readAt: at(29), complete: false, sources: crtshOnly }), n2b, { now: new Date(at(29)) });
    const changes = diffReports('ct', report('ct', [n2b]), report('ct', [n3]), { t });
    assert.deepEqual(tags(changes), ['ISSUER example.com Google Trust Services', 'NAME example.com mail.example.com', 'RECOVERED? example.com']);
    assert.equal(changeText(changes[2]), 'example.com: Certificate Transparency read again: 2 current certificates, compared with the last read (2026-09-26)');
    assert.deepEqual(n3.sources.map((s) => `${s.source} ${s.lastFullAt}`), [`crtsh ${at(29)}`, `certspotter ${at(26)}`]);
  });

  test('what a source not read in full listed stays known until every source that listed it read the domain in full without it, or it expires', () => {
    const now = new Date('2026-09-28T03:00:00.000Z');
    const spotter = cert('Sectigo', 'E46', '2026-08-01T00:00:00.000Z', ['shop.example.com'], { sources: ['certspotter'] });
    const shared = cert('DigiCert', 'G2', '2026-07-01T00:00:00.000Z', ['api.example.com'], { sources: ['certspotter', 'crtsh'] });
    const gone = cert('Buypass', 'CA2', '2026-06-01T00:00:00.000Z', ['old.example.com'], { sources: ['crtsh'] });
    const expired = cert('ZeroSSL', 'ECC', '2026-06-01T00:00:00.000Z', ['x.example.com'], { sources: ['certspotter'], notAfter: '2026-09-01T00:00:00.000Z' });
    const prev = ctT([le1, spotter, shared, gone, expired], { readAt: '2026-09-27T03:00:00.000Z' });
    // Tonight crt.sh reads in full, Cert Spotter is cut at its page cap.
    const tonight = ctT([le1], { readAt: now.toISOString(), complete: false, sources: [{ source: 'crtsh', ok: true, state: 'ok' }, { source: 'certspotter', ok: true, state: 'ok', truncated: true }] });
    const x = carryCt(tonight, prev, { now });
    assert.deepEqual(x.certificates.map((c) => `${c.ca}${c.carried ? ` carried from ${c.carried.from}` : ''}`),
      ["Let's Encrypt", 'Sectigo carried from 2026-09-27T03:00:00.000Z', 'DigiCert carried from 2026-09-27T03:00:00.000Z']);
    assert.deepEqual(x.issuers.map((g) => g.name), ['DigiCert', "Let's Encrypt", 'Sectigo']);
    assert.equal(x.recent, tonight.recent, 'recent counts this read');
    assert.deepEqual(diffReports('ct', report('ct', [prev]), report('ct', [x]), { t }), [], 'nothing new, and a read that is not complete says no issuer gone');
    // The summary counts this read, and says what is kept.
    const doc = ctDoc(x, { t, now });
    assert.equal(renderParts(doc.lines[0], 'text'), '1 current certificate · 0 issued in the last 30 days');
    assert.equal(renderParts(doc.lines.at(-1), 'text'), 'The 2 certificates last read on 2026-09-27 are kept for the next comparison (listed by a source not read in full this run)');
    const failed = carryCt(ctT([], { readAt: now.toISOString(), answered: false, complete: false, sources: [{ source: 'crtsh', ok: false, state: 'unavailable' }] }),
      ctT([le1], { readAt: '2026-09-27T03:00:00.000Z', sources: [{ source: 'crtsh', ok: true, state: 'ok' }] }), { now });
    assert.match(renderParts(ctDoc(failed, { t, now }).lines[0], 'text'), /^Certificate Transparency could not be read: crt\.sh \(unavailable\)\. The certificate last read on 2026-09-27 is kept for the next comparison\.$/);
  });

  test('a baseline that read nothing in full compares with the last full read before it', () => {
    // Night 1 read crt.sh in full; night 2 crt.sh answered only in part and Cert Spotter was cut at its cap.
    const n1 = carryCt(ctT([le1], { readAt: '2026-09-26T03:00:00.000Z', sources: [{ source: 'crtsh', ok: true, state: 'ok' }] }), null, { now: NOW });
    const n2 = carryCt(ctT([le1], { readAt: '2026-09-27T03:00:00.000Z', complete: false, sources: [{ source: 'crtsh', ok: true, state: 'partial' }] }), n1, { now: NOW });
    assert.deepEqual([...lastFullTimes(n2)], [['crtsh', '2026-09-26T03:00:00.000Z']]);
    const gts = cert('Google Trust Services', 'WR1', '2026-09-20T00:00:00.000Z', ['example.com']);
    const n3 = carryCt(ctT([gts, le1], { readAt: '2026-09-28T03:00:00.000Z', sources: [{ source: 'crtsh', ok: true, state: 'ok' }] }), n2, { now: NOW });
    assert.deepEqual(tags(diffReports('ct', report('ct', [n2]), report('ct', [n3]), { t })), ['ISSUER example.com Google Trust Services']);
    // Without that earlier full read, the same issuer is listed only.
    const partial = ctT([le1], { complete: false, sources: [{ source: 'crtsh', ok: true, state: 'partial' }] });
    assert.deepEqual(tags(diffReports('ct', report('ct', [partial]), report('ct', [n3]), { t })), ['ISSUER? example.com Google Trust Services']);
  });

  test('a night with Cert Spotter alone names the issuers as a night with both: from the DN, never Cert Spotter\'s operator name', () => {
    const dn = 'C=TR, O=Example Kamu SM, CN=Example Kamu SM SSL';
    const at = { notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: new Date('2026-12-19T00:00:00Z') };
    const crtshCert = { source: 'crtsh', sources: ['crtsh'], issuer: dn, ...at, names: ['example.com'], sha256: null };
    const spotterCert = { source: 'certspotter', sources: ['certspotter'], issuer: dn, issuerFriendlyName: 'Example Operator', ...at, names: ['example.com'], sha256: 'cd'.repeat(32) };
    const opts = { issuerName, dnPart, days: 30, now: NOW, sources: ['crtsh', 'certspotter'] };
    const night1 = ctTarget('example.com', { certs: [crtshCert, spotterCert], health: [{ source: 'crtsh', state: 'ok', ok: true }, { source: 'certspotter', state: 'ok', ok: true }] }, opts);
    const night2 = ctTarget('example.com', { certs: [spotterCert], health: [{ source: 'crtsh', state: 'unavailable', ok: false }, { source: 'certspotter', state: 'ok', ok: true }] }, opts);
    assert.equal(night1.certificates[0].ca, 'Example Kamu SM');
    assert.equal(night2.certificates[0].ca, 'Example Kamu SM');
    assert.equal(night1.certificates[0].id, night2.certificates[0].id);
    assert.deepEqual(diffReports('ct', report('ct', [night1]), report('ct', [night2]), { t }), []);
    assert.deepEqual(diffReports('ct', report('ct', [night2]), report('ct', [night1]), { t }), []);
  });

  test('CT unreadable: FAILED, and read again: RECOVERED, both listed only (the source\'s outage); an issuer gone only after a complete read', () => {
    const down = ctT([], { answered: false, complete: false, sources: [{ source: 'crtsh', ok: false, state: 'timeout' }, { source: 'certspotter', ok: false, state: 'rate-limited', skipped: true }] });
    const failed = diffReports('ct', before, report('ct', [down]), { t });
    assert.deepEqual(tags(failed), ['FAILED? example.com']);
    assert.equal(failed[0].tone, 'quiet');
    assert.equal(changeText(failed[0]), 'example.com: Certificate Transparency could not be read this run (crt.sh timeout, Cert Spotter rate limited (not asked)): '
      + 'nothing compared; the next run compares with the last read');
    assert.deepEqual(diffReports('ct', report('ct', [down]), report('ct', [down]), { t }), []);
    const back = diffReports('ct', report('ct', [down]), before, { t });
    assert.deepEqual(tags(back), ['RECOVERED? example.com']);
    assert.equal(changeText(back[0]), 'example.com: Certificate Transparency read again: 1 current certificate (not compared: no earlier run read it)');
    const added = (a) => changeText(diffReports('ct', report('ct', []), report('ct', [a]), { t })[0]);
    assert.equal(added(down), 'example.com: now watched (Certificate Transparency could not be read this run)');
    assert.equal(added(before.targets[0]), 'example.com: now watched: 1 current certificate');
    const gts = cert('Google Trust Services', 'WR1', '2026-09-26T00:00:00.000Z', ['example.com']);
    assert.deepEqual(tags(diffReports('ct', before, report('ct', [ctT([gts], { names: ['example.com', 'www.example.com'] })]), { t })),
      ['ISSUER example.com Google Trust Services', "GONE? example.com Let's Encrypt"]);
    assert.deepEqual(tags(diffReports('ct', before, report('ct', [ctT([gts], { names: ['example.com', 'www.example.com'], complete: false })]), { t })),
      ['ISSUER example.com Google Trust Services']);
  });

  test('one certificate from crt.sh and Cert Spotter is one id; names of other domains are left out', () => {
    const fetched = {
      certs: [
        { source: 'crtsh', sources: ['crtsh'], issuer: "C=US, O=Let's Encrypt, CN=R11", notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: new Date('2026-12-19T00:00:00Z'), names: ['example.com', 'www.example.com'], sha256: null },
        { source: 'certspotter', sources: ['certspotter'], issuer: "C=US, O=Let's Encrypt, CN=R11", notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: new Date('2026-12-19T00:00:00Z'), names: ['www.example.com', 'example.com', 'example.org'], sha256: 'ab'.repeat(32) }
      ],
      health: [{ source: 'crtsh', state: 'ok', ok: true }, { source: 'certspotter', state: 'ok', ok: true }]
    };
    const x = ctTarget('example.com', fetched, { issuerName, dnPart, days: 30, now: NOW, sources: ['crtsh', 'certspotter'] });
    assert.equal(x.certificates.length, 1);
    assert.deepEqual(x.certificates[0].sources, ['certspotter', 'crtsh']);
    assert.equal(x.certificates[0].sha256, 'ab'.repeat(32));
    assert.deepEqual(x.certificates[0].names, ['example.com', 'www.example.com']);
    assert.equal(x.certificates[0].ca, "Let's Encrypt");
    assert.deepEqual(x.issuers, [{ name: "Let's Encrypt", count: 1, intermediates: ['R11'], newest: '2026-09-20T00:00:00.000Z' }]);
    assert.equal(x.recent, 1);
    assert.equal(x.complete, true);
  });
});

describe('sources a run stops asking', () => {
  const res = (source, extra = {}) => ({ source, ok: true, partial: false, errorKind: null, error: null, quota: null, ...extra });
  const clock = (start) => {
    let now = new Date(start);
    return { now: () => now, set: (d) => { now = new Date(d); } };
  };

  test('Cert Spotter: after a rate limit, not asked until its Retry-After (at most an hour) is over', () => {
    const c = clock(NOW);
    const breaker = createSourceBreaker({ now: c.now, spotterHint: '--sources crtsh leaves it out' });
    assert.deepEqual(breaker.ask(['crtsh', 'certspotter']), ['crtsh', 'certspotter']);
    assert.deepEqual(breaker.note('example.com', [res('crtsh'), res('certspotter')]), []);
    const limited = res('certspotter', { ok: false, errorKind: 'rate-limit', error: 'HTTP 429', quota: { limited: true, retryAfterMs: 7200000 } });
    const [w] = breaker.note('example.net', [res('crtsh'), limited]);
    assert.match(w, /^Cert Spotter answered "rate limited" for example\.net: not asked again until 04:00 UTC \(its anonymous quota is about 10 full-domain queries an hour per IP address, and GitHub's runners share addresses; --sources crtsh leaves it out\)$/);
    assert.deepEqual(breaker.ask(['crtsh', 'certspotter']), ['crtsh']);
    assert.deepEqual(breaker.skipped(['certspotter']), [{ source: 'certspotter', state: 'rate-limited', ok: false, truncated: false, errorKind: 'rate-limit', error: 'not asked: rate limited since example.net', skipped: true }]);
    c.set('2026-09-28T04:00:01Z');
    assert.deepEqual(breaker.ask(['crtsh', 'certspotter']), ['crtsh', 'certspotter'], 'asked again once the hour is over');
    // A readable X-RateLimit-Remaining of 0: the next query would be refused.
    const spent = res('certspotter', { quota: { limited: false, retryAfterMs: null, remaining: 0 } });
    assert.match(breaker.note('example.org', [spent])[0], /^Cert Spotter had no request left this hour for example\.org: not asked again until 05:00 UTC/);
    assert.deepEqual(breaker.ask(['certspotter']), []);
  });

  test('crt.sh: down as a service at once, timeouts only on two domains in a row', () => {
    const breaker = createSourceBreaker({ now: () => NOW });
    const timeout = res('crtsh', { ok: false, errorKind: 'timeout' });
    assert.deepEqual(breaker.note('a.example.com', [timeout]), []);
    assert.deepEqual(breaker.note('b.example.com', [res('crtsh')]), [], 'an answer in between resets the count');
    assert.deepEqual(breaker.note('c.example.com', [timeout]), []);
    assert.deepEqual(breaker.note('d.example.com', [res('crtsh', { ok: false, errorKind: 'http' })]), [], 'an HTTP error of one query is no outage');
    assert.deepEqual(breaker.ask(['crtsh']), ['crtsh']);
    assert.deepEqual(breaker.note('e.example.com', [timeout]), []);
    assert.deepEqual(breaker.note('f.example.com', [timeout]), ['crt.sh timed out on 2 domains in a row (the last: f.example.com): not asked again this run']);
    assert.deepEqual(breaker.ask(['crtsh', 'certspotter']), ['certspotter']);
    const down = createSourceBreaker({ now: () => NOW });
    assert.deepEqual(down.note('example.com', [res('crtsh', { ok: false, errorKind: 'unavailable' })]), ['crt.sh was unavailable for example.com: not asked again this run']);
    assert.equal(down.skipped(['crtsh'])[0].state, 'unavailable');
    assert.deepEqual(down.note('example.org', [res('crtsh')]), [], 'noted once');
  });

  test('a long discovery stage says how far it is in tenths; a short one says nothing more', () => {
    const lines = [];
    const hook = stageProgress('example.com', (s) => lines.push(s));
    for (let done = 1; done <= 20000; done += 1) hook({ stage: 'resolve', done, total: 20000 });
    for (let done = 1; done <= 400; done += 1) hook({ stage: 'hints', done, total: 400 });
    hook({ stage: 'sources', done: 1 });
    assert.equal(lines.length, 10);
    assert.equal(lines[0], 'subdomains example.com: resolve 2,000/20,000 (10%)');
    assert.equal(lines.at(-1), 'subdomains example.com: resolve 20,000/20,000 (100%)');
  });

  test('the scanner\'s warnings in the Subdomains view\'s words, their detail a code part', async () => {
    const { WARNING_CODES } = await import('../../assets/js/views/subdomains.js');
    const cut = scanWarningParts(t, { code: 'TRUNCATED', detail: '22249 > 20000' }, WARNING_CODES);
    assert.equal(renderParts(cut, 'text'), 'Too many names — only the first ones were resolved (22249 > 20000).');
    assert.ok(cut.some((p) => p && p.code === '22249 > 20000'));
    const name = scanWarningParts(t, { code: 'INVALID_NAME', detail: '@team [x](y)' }, WARNING_CODES);
    assert.equal(renderParts(name, 'markdown'), 'Invalid hostname skipped: `@team [x](y)`');
    assert.equal(renderParts(scanWarningParts(t, { code: 'NEW_CODE', detail: 'x' }, WARNING_CODES), 'text'), 'NEW_CODE: x');
  });
});

describe('diff: drift, renew, dane', () => {
  const row = (key, status, extra = {}) => ({ key, name: key.split('|')[0], type: key.split('|')[1], status, reasons: [], ...extra });

  test('drift: status moves by severity, failures, skipped rows, rows new and gone in the file, the name servers', () => {
    const b = report('drift', [{
      target: 'example.com', preflight: { nsMatch: 'same' }, rows: [
        row('www.example.com|A', 'proxied-ok'), row('api.example.com|A', 'origin-exposed'), row('mail.example.com|A', 'match'),
        row('vpn.example.com|A', 'error'), row('ftp.example.com|A', 'differs', { added: ['192.0.2.7'] }), row('old.example.com|A', 'missing-live'),
        row('big.example.com|TXT', 'match'), row('x.example.com|A', 'error')
      ]
    }]);
    const a = report('drift', [{
      target: 'example.com', preflight: { nsMatch: 'disjoint' }, rows: [
        row('www.example.com|A', 'origin-exposed'), row('api.example.com|A', 'proxied-ok'), row('mail.example.com|A', 'error'),
        row('vpn.example.com|A', 'match'), row('ftp.example.com|A', 'differs', { added: ['192.0.2.8'] }), row('big.example.com|TXT', 'skipped', { reasons: ['budget'] }),
        row('x.example.com|A', 'error'), row('new.example.com|A', 'missing-live'), row('ok.example.com|A', 'match')
      ]
    }]);
    const changes = diffReports('drift', b, a, { t });
    assert.deepEqual(tags(changes), [
      'WORSE example.com NS', 'WORSE example.com www.example.com|A', 'BETTER example.com api.example.com|A', 'FAILED example.com mail.example.com|A',
      'RECOVERED example.com vpn.example.com|A', 'CHANGED example.com ftp.example.com|A', 'NEW example.com new.example.com|A',
      'CHANGED? example.com big.example.com|TXT', 'GONE? example.com old.example.com|A'
    ]);
    assert.match(changeText(changes[1]), /www\.example\.com A — Proxied, origin hidden → Origin exposed: proxy is off/);
    assert.match(changeText(changes[5]), /live values changed: now also 192\.0\.2\.8/);
  });

  test('renew: verdicts worse, better, failed, recovered; findings within a verdict; unknown to unknown is listed only', () => {
    const f = (id, severity, extra = {}) => ({ id, severity, params: {}, ...extra });
    const b = report('renew', [
      { target: 'a.example.com', verdict: 'ready', findings: [] },
      { target: 'b.example.com', verdict: 'fail', findings: [f('caa.denied', 'error')] },
      { target: 'c.example.com', verdict: 'warnings', findings: [f('http.ipv6', 'warn')] },
      { target: 'd.example.com', verdict: 'unknown', findings: [f('caa.error', 'warn', { unchecked: true })] },
      { target: 'e.example.com', verdict: 'warnings', findings: [f('resolvers.differ', 'warn')] },
      { target: 'f.example.com', verdict: 'unknown', findings: [f('caa.error', 'warn', { unchecked: true })] },
      { target: 'g.example.com', verdict: 'ready', findings: [] }
    ]);
    const a = report('renew', [
      { target: 'a.example.com', verdict: 'fail', findings: [f('caa.denied', 'error')] },
      { target: 'b.example.com', verdict: 'ready', findings: [] },
      { target: 'c.example.com', verdict: 'unknown', findings: [f('http.error', 'warn', { unchecked: true })] },
      { target: 'd.example.com', verdict: 'ready', findings: [] },
      { target: 'e.example.com', verdict: 'warnings', findings: [f('provider.unknown', 'warn')] },
      { target: 'f.example.com', verdict: 'unknown', findings: [f('acme.error', 'warn'), f('caa.error', 'warn', { unchecked: true })] },
      { target: 'h.example.com', verdict: 'ready', findings: [] }
    ]);
    const changes = diffReports('renew', b, a, { t });
    assert.deepEqual(tags(changes), ['WORSE a.example.com', 'BETTER b.example.com', 'FAILED c.example.com', 'RECOVERED d.example.com',
      'CHANGED e.example.com', 'NEW h.example.com', 'GONE g.example.com', 'FAILING? f.example.com']);
    assert.match(changeText(changes[0]), /^a\.example\.com: Ready → Will fail; new: /);
    assert.match(changeText(changes[4]), /Ready, with warnings; new: .*; gone: /);
  });

  test('dane: endpoints compared by service and host, whatever the certificate\'s name', () => {
    const ep = (key, status) => ({ key, qname: `_${key.startsWith('smtp') ? 25 : 443}._tcp.${key.split('|')[1]}`, status });
    const b = report('dane', [{ target: 'example.com', serialHex: '01', endpoints: [ep('smtp|mail.example.com', 'safe'), ep('https|example.com', 'none'), ep('https|www.example.com', 'error'), ep('smtp|mx2.example.net', 'none')] }]);
    const a = report('dane', [{ target: 'www.example.com', serialHex: '02', endpoints: [ep('smtp|mail.example.com', 'danger'), ep('https|example.com', 'insecure'), ep('https|www.example.com', 'safe'), ep('smtp|mx3.example.net', 'none')] }]);
    const changes = diffReports('dane', b, a, { t });
    assert.deepEqual(tags(changes), ['WORSE www.example.com smtp|mail.example.com', 'WORSE www.example.com https|example.com', 'RECOVERED www.example.com https|www.example.com',
      'NEW www.example.com smtp|mx3.example.net', 'GONE www.example.com smtp|mx2.example.net']);
    assert.match(changeText(changes[0]), /_25\._tcp\.mail\.example\.com — Safe → Will break/);
  });

  test('checked again after a failure: the tone is what the state is now, never good news by itself', () => {
    const f = (id, severity) => ({ id, severity, params: {} });
    const rn = (verdict, findings = []) => report('renew', [{ target: 'example.com', verdict, findings }]);
    const renew = diffReports('renew', rn('unknown', [{ ...f('caa.error', 'warn'), unchecked: true }]), rn('fail', [f('caa.denied', 'error')]), { t });
    assert.deepEqual(tags(renew), ['RECOVERED example.com']);
    assert.equal(renew[0].tone, 'bad');
    assert.match(changeText(renew[0]), /^example\.com: Could not be checked → Will fail/);
    assert.equal(diffReports('renew', rn('unknown'), rn('ready'), { t })[0].tone, 'good');
    const dr = (status) => report('drift', [{ target: 'example.com', rows: [row('www.example.com|A', status)] }]);
    assert.equal(diffReports('drift', dr('error'), dr('origin-exposed'), { t })[0].tone, 'bad');
    assert.equal(diffReports('drift', dr('error'), dr('match'), { t })[0].tone, 'good');
    const dn = (status) => report('dane', [{ target: 'example.com', endpoints: [{ key: 'smtp|mail.example.com', qname: '_25._tcp.mail.example.com', status }] }]);
    assert.equal(diffReports('dane', dn('error'), dn('danger'), { t })[0].tone, 'bad');
    assert.equal(diffReports('dane', dn('error'), dn('safe'), { t })[0].tone, 'good');
  });

  test('changes that count come first; an unknown command or a missing translator is refused', () => {
    const list = [{ counts: false, n: 1 }, { counts: true, n: 2 }, { counts: false, n: 3 }, { counts: true, n: 4 }];
    assert.deepEqual(orderChanges(list).map((c) => c.n), [2, 4, 1, 3]);
    assert.throws(() => diffReports('scan', report('scan', []), report('scan', []), { t }), RangeError);
    assert.throws(() => diffReports('health', report('health', []), report('health', []), {}), TypeError);
  });
});

/* ------------------------------------------------------------------------ */
/* Rendering                                                                */
/* ------------------------------------------------------------------------ */

describe('diff: audit', () => {
  const rule = (id, status, { required = '>= 30', key = 'pol.ev.daysLeft', params = { count: 40, date: '2026-11-06' }, last = null } = {}) => ({
    id, status, required, actual: null, evidence: '', key, params, ...(last ? { last } : {})
  });
  const target = (domain, rules) => ({ target: domain, checkedAt: '2026-09-27T03:00:00.000Z', rules });
  const diff = (before, after) => diffReports('audit', report('audit', before), report('audit', after), { t });

  test('a rule that fails now is WORSE, one that passes now BETTER, with the evidence; the evidence alone moving is no change', () => {
    const changes = diff(
      [target('example.com', [rule('expiryDays', 'pass'), rule('transferLock', 'fail', { required: 'true', key: 'pol.ev.lockOff', params: {} })])],
      [target('example.com', [rule('expiryDays', 'fail', { params: { count: 29, date: '2026-10-26' } }), rule('transferLock', 'pass', { required: 'true', key: 'pol.ev.lockOn', params: {} })])]);
    assert.deepEqual(tags(changes), ['WORSE example.com expiryDays', 'BETTER example.com transferLock']);
    assert.equal(changeText(changes[0]), 'example.com: expiryDays >= 30: pass → fail — 29 days left (2026-10-26)');
    assert.equal(changes[0].tone, 'bad');
    assert.equal(changes[1].tone, 'good');
    assert.deepEqual(diff([target('example.com', [rule('expiryDays', 'pass')])], [target('example.com', [rule('expiryDays', 'pass', { params: { count: 39, date: '2026-11-06' } })])]), []);
  });

  test('a rule not checked this run is listed once, never counted; the night after compares with the status it carried', () => {
    const lastFail = { status: 'fail', evidence: '20 days left', from: '2026-09-26T03:00:00.000Z' };
    const unknown = (extra = {}) => rule('expiryDays', 'unknown', { key: 'pol.ev.failed', params: { what: 'RDAP' }, ...extra });
    const failed = diff([target('example.com', [rule('expiryDays', 'fail')])], [target('example.com', [unknown({ last: lastFail })])]);
    assert.deepEqual(tags(failed), ['FAILED? example.com expiryDays']);
    assert.equal(changeText(failed[0]), 'example.com: expiryDays >= 30: fail → not known — RDAP lookup failed');
    // still not known: nothing; checked again with the status it had: nothing
    assert.deepEqual(diff([target('example.com', [unknown({ last: lastFail })])], [target('example.com', [unknown({ last: lastFail })])]), []);
    assert.deepEqual(diff([target('example.com', [unknown({ last: lastFail })])], [target('example.com', [rule('expiryDays', 'fail')])]), []);
    // checked again with another status: compared with the carried one, and said so
    const better = diff([target('example.com', [unknown({ last: lastFail })])], [target('example.com', [rule('expiryDays', 'pass')])]);
    assert.deepEqual(tags(better), ['BETTER example.com expiryDays']);
    assert.match(changeText(better[0]), /: fail \(last checked 2026-09-26\) → pass — 40 days left/);
    // never checked before: the first check is RECOVERED, counted when it fails
    assert.deepEqual(tags(diff([target('example.com', [unknown()])], [target('example.com', [rule('expiryDays', 'fail')])])), ['RECOVERED example.com expiryDays']);
    assert.deepEqual(tags(diff([target('example.com', [unknown()])], [target('example.com', [rule('expiryDays', 'pass')])])), ['RECOVERED? example.com expiryDays']);
  });

  test('a rule new to the policy or with another requirement says what it is now; rules and domains gone are listed, a new domain counts its failures', () => {
    const changes = diff(
      [target('example.com', [rule('expiryDays', 'pass'), rule('dkim', 'fail', { required: 'true', key: 'pol.ev.dkimNone', params: { count: 8 } })]), target('example.org', [])],
      [target('example.com', [rule('expiryDays', 'fail', { required: '>= 60' }), rule('dnssec', 'pass', { required: '>= signed', key: 'pol.ev.dnssec.signed', params: {} })]),
        target('example.net', [rule('expiryDays', 'fail')])]);
    assert.deepEqual(tags(changes), ['NEW example.com expiryDays', 'NEW example.net', 'GONE example.org', 'NEW? example.com dnssec', 'GONE? example.com dkim']);
    assert.match(changeText(changes[0]), /^example\.com: new rule expiryDays >= 60: fail — 40 days left/);
    assert.equal(changeText(changes[1]), 'example.net: now audited: 1 rule failed');
  });

  test('values from DNS and the registry in the evidence are code parts (Markdown code spans)', () => {
    const changes = diff([target('example.com', [rule('registrar', 'pass', { required: 'Example Registrar', key: 'pol.ev.registrar', params: { name: 'Example Registrar' } })])],
      [target('example.com', [rule('registrar', 'fail', { required: 'Example Registrar', key: 'pol.ev.registrar', params: { name: '@team <!here> *Other*' } })])]);
    assert.match(renderChangesMarkdown({ command: 'audit', baseline: { file: 'audit.json' }, changes }), /- \*\*WORSE\*\* `example\.com`: `registrar Example Registrar`: pass → fail — registrar: `@team <!here> \*Other\*`/);
  });
});

describe('render', () => {
  const b = report('health', [{ target: 'example.com', score: 100, checks: [] }]);
  const a = report('health', [{ target: 'example.com', score: 80, checks: [check('dkim.none', 'warn'), check('dmarc.none', 'warn')] }]);
  const run = { command: 'health', baseline: baselineInfo(b, 'out/health.json'), changes: diffReports('health', b, a, { t }), notes: ['The resolvers differ from the baseline\'s (cloudflare → google).'] };

  test('the summary block in the CLI\'s words, without colours unless asked', () => {
    const lines = renderChangesText(run, { paint: painter(false) });
    assert.equal(lines[0], 'Changes since the baseline (health.json, run of 2026-09-27 03:02 UTC): 3');
    assert.match(lines[1], /^ {2}SCORE {6}example\.com: health score 100 → 80$/);
    assert.ok(lines.includes('  The resolvers differ from the baseline\'s (cloudflare → google).'));
    assert.equal(lines.at(-1), '');
    assert.ok(!lines.join('\n').includes('\u001b['));
    assert.ok(renderChangesText(run, { paint: painter(true) }).join('\n').includes('\u001b[31;1m'), 'red for a bad change');
    assert.ok(CHANGE_TAGS.every((tag) => tag.length <= 9));
  });

  test('a first run says so; nothing changed says none; the cap and the not-counted note', () => {
    assert.match(renderChangesText({ command: 'health', baseline: { file: 'h.json', missing: true }, changes: [] }, { paint: painter(false) })[0],
      /^Baseline h\.json does not exist yet: nothing to compare \(first run\)\. This run's --json report is the next run's baseline\.$/);
    assert.match(renderChangesText({ command: 'health', baseline: run.baseline, changes: [] }, { paint: painter(false) })[0], /: none$/);
    const many = Array.from({ length: MAX_SUMMARY_CHANGES + 3 }, (_, i) => ({ tag: 'NEW', tone: 'info', counts: i % 2 === 0, parts: [`n${i}`] }));
    const lines = renderChangesText({ command: 'ct', baseline: run.baseline, changes: many }, { paint: painter(false) });
    assert.ok(lines.includes('  ... and 3 more - use --show-all or the --json report to list them.'));
    assert.ok(lines.some((l) => /Not counted: 26 /.test(l)));
    assert.equal(renderChangesText({ command: 'ct', baseline: run.baseline, changes: many }, { paint: painter(false), showAll: true }).filter((l) => /^ {2}NEW/.test(l)).length, many.length);
  });

  test('Markdown: the command, bold tags, code spans for values, the not-counted mark', () => {
    const md = renderChangesMarkdown(run);
    assert.match(md, /^\*\*health: changes since the baseline \(run of 2026-09-27 03:02 UTC\): 3\*\*\n\n- \*\*SCORE\*\* `example\.com`: health score 100 → 80\n/);
    assert.match(md, /- \*\*NEW\*\* `example\.com`: warn `dkim\.none` — /);
    assert.match(renderChangesMarkdown({ command: 'health', baseline: { missing: true }, changes: [] }), /^\*\*health: first run\*\*/);
    const quiet = renderChangesMarkdown({ command: 'ct', baseline: run.baseline, changes: [{ tag: 'CERT', counts: false, parts: [{ code: 'example.com' }, ': x'] }] });
    assert.match(quiet, /- \*\*CERT\*\* \(not counted\) `example\.com`: x\n- 1 listed only/);
    const many = Array.from({ length: MAX_MARKDOWN_CHANGES + 5 }, (_, i) => ({ tag: 'NEW', counts: true, parts: [{ code: `h${i}.example.com` }] }));
    const capped = renderChangesMarkdown({ command: 'subdomains', baseline: run.baseline, changes: many });
    assert.equal(capped.split('\n').filter((l) => l.startsWith('- **NEW**')).length, MAX_MARKDOWN_CHANGES);
    assert.match(capped, /- … and 5 more: the JSON report lists them all\n$/);
  });

  test('the stdout summary puts the changes first, then each target\'s summary', () => {
    const doc = { kind: 'ct', title: ['Certificate Transparency · ', { code: 'example.com' }], lines: [['1 current certificate']], inline: false, footer: { when: 'checked 2026-09-28 03:00 UTC', url: null } };
    const text = renderRunText(run, [doc, doc]);
    assert.match(text, /^Changes since the baseline .*\n[\s\S]*\nCertificate Transparency · example\.com\n- 1 current certificate\nDomainScope · checked 2026-09-28 03:00 UTC\n\nCertificate Transparency/);
    assert.equal(renderRunText({ command: 'ct', baseline: null }, [doc]), 'Certificate Transparency · example.com\n- 1 current certificate\nDomainScope · checked 2026-09-28 03:00 UTC\n');
  });

  test('files in UTF-8 (with or without a BOM) and UTF-16 (with a BOM, or PowerShell\'s little-endian without one)', () => {
    const text = 'örnek.example.com\n# yorum\n';
    const utf16 = (s, bom) => {
      const body = Buffer.from(s, 'utf16le');
      return new Uint8Array(bom ? Buffer.concat([Buffer.from([0xff, 0xfe]), body]) : body);
    };
    assert.equal(decodeText(new Uint8Array(Buffer.from(text))), text);
    assert.equal(decodeText(new Uint8Array(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]))), text);
    assert.equal(decodeText(utf16(text, true)), text);
    assert.equal(decodeText(utf16(text, false)), text);
    const be = Buffer.from(text, 'utf16le').swap16();
    assert.equal(decodeText(new Uint8Array(Buffer.concat([Buffer.from([0xfe, 0xff]), be]))), text);
  });
});

/* ------------------------------------------------------------------------ */
/* Offline runs of the program                                              */
/* ------------------------------------------------------------------------ */

/** main() with streams captured, the fake fetch and a fixed clock. */
async function runMain(argv, { fetchImpl, now = NOW } = {}) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now });
  return { code, out: stdout.text, err: stderr.text };
}

const HIDDEN_ORIGINS = ['192.0.2.14', '192.0.2.40', '2001:db8::10', 'origin-lb.example.net'];

describe('offline runs (fake DoH)', () => {
  test('drift: the Zone File e2e zone, origins hidden, nothing internal sent, then a baseline with changes and --fail-on-change', async () => {
    const dir = tmp();
    try {
      const log = [];
      const table = zoneTable();
      const json = join(dir, 'drift.json');
      const md = join(dir, 'drift.md');
      const first = await runMain(['drift', CF_EXPORT, '--baseline', json, '--json', json, '--md', md], { fetchImpl: createFakeFetch(table, { log }) });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.out, /^Baseline drift\.json does not exist yet: nothing to compare \(first run\)/);
      assert.match(first.out, /Zone File · example\.com\n- Live check: \d+ record sets, \d+ DNS queries\n/);
      assert.match(first.out, /Origin exposed: proxy is off: www\.example\.com A/);
      assert.match(first.out, /newer than the file/);
      for (const name of ['origin-lb.example.net', 'intranet.example.com', 'old.dev.example.com']) {
        assert.ok(!log.some((q) => q.name === name), `${name} never queried`);
      }
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.equal(doc.tool, DS_TOOL);
      assert.equal(doc.command, 'drift');
      assert.deepEqual(doc.baseline, { file: 'drift.json', missing: true });
      const [z] = doc.targets;
      const statuses = new Set(z.rows.map((r) => r.status));
      for (const s of ['proxied-ok', 'origin-exposed', 'match']) assert.ok(statuses.has(s), `${s} in ${[...statuses]}`);
      assert.equal(z.preflight.serial, 'newer');
      assert.ok(z.rows.filter((r) => r.status === 'match').every((r) => !('file' in r)), 'matching rows keep no values');
      const saved = readFileSync(json, 'utf8') + readFileSync(md, 'utf8');
      for (const ip of HIDDEN_ORIGINS) assert.ok(!saved.includes(ip), `${ip} redacted`);
      assert.ok(saved.includes('[origin hidden]'));
      assert.match(readFileSync(md, 'utf8'), /^\*\*drift: first run\*\*[\s\S]*\*\*Zone File · `example\.com`\*\*\n- Live check/);

      // www's proxy is back on; mail's address changed: the next run compares with the report above.
      table['www.example.com'].A = ['104.16.1.1'];
      table['mail.example.com'].A = ['198.51.100.26'];
      const second = await runMain(['drift', CF_EXPORT, '--baseline', json, '--json', json, '--fail-on-change', '-q'], { fetchImpl: createFakeFetch(table) });
      assert.equal(second.code, EXIT.CHANGED);
      assert.equal(second.out, '', 'quiet');
      const doc2 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc2.changes.map((c) => `${c.tag} ${c.item}`), ['BETTER www.example.com|A', 'WORSE mail.example.com|A']);
      assert.match(doc2.changes[0].text, /Origin exposed: proxy is off → Proxied, origin hidden/);
      assert.equal(doc2.baseline.missing, false);

      // Nothing moved since: exit 0 even with --fail-on-change.
      const third = await runMain(['drift', CF_EXPORT, '--baseline', json, '--json', json, '--fail-on-change', '--include-origins'], { fetchImpl: createFakeFetch(table) });
      assert.equal(third.code, EXIT.OK, third.err);
      assert.match(third.out, /Changes since the baseline \(drift\.json, run of 2026-09-28 03:00 UTC\): none/);
      assert.match(third.out, /Origin addresses were hidden in one run and kept in the other/);
      assert.ok(readFileSync(json, 'utf8').includes('198.51.100.26'), 'origins kept on opt-in');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('health: a first run, then a lookup that fails and a finding that goes', async () => {
    const dir = tmp();
    try {
      const table = zoneTable();
      const json = join(dir, 'health.json');
      const first = await runMain(['health', 'example.com', '--json', json, '--baseline', json], { fetchImpl: createFakeFetch(table) });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.out, /Domain Health · example\.com\n- .* · score \d+\/100\n/);
      const before = JSON.parse(readFileSync(json, 'utf8')).targets[0];
      assert.ok(before.checks.some((c) => c.id === 'mx.unresolvable' && c.severity === 'error'), before.checks.map((c) => c.id).join(','));
      assert.ok(before.report && before.report.records, 'the report itself is kept');

      // example.com's TXT lookup fails: the SPF error it found goes, the score rises.
      const second = await runMain(['health', 'example.com', '--json', json, '--baseline', json, '--fail-on-change'], {
        fetchImpl: createFakeFetch(table, { rcodes: { 'example.com|TXT': 'SERVFAIL' } })
      });
      assert.equal(second.code, EXIT.CHANGED, second.err);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.item || ''}`),
        ['NEW spf.error', 'SCORE? ', 'GONE? spf.include-error']);
      assert.match(doc.changes[1].text, /health score \d+ → \d+ \(a lookup failed this run\)/);
      assert.match(second.out, /GONE {7}example\.com: error spf\.include-error no longer reported — Broken include\/redirect in SPF \(its lookup failed this run: it may still be there\)/);
      const carried = doc.targets[0].carried.find((c) => c.area === 'spf');
      assert.equal(carried.from, before.checkedAt);
      assert.ok(carried.checks.some((c) => c.id === 'spf.include-error'), 'the SPF area as last read is carried');

      // TXT answers again: compared with the SPF area as the first run read it, so the broken
      // include is no "new" finding; the failed lookup is gone, and the score it moved is listed only.
      const third = await runMain(['health', 'example.com', '--json', json, '--baseline', json, '--fail-on-change'], { fetchImpl: createFakeFetch(table) });
      assert.equal(third.code, EXIT.CHANGED, third.err);
      const doc3 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc3.changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.item || ''}`), ['GONE spf.error', 'SCORE? ']);
      assert.match(doc3.changes[1].text, /\(a lookup failed in the baseline run\)$/);
      assert.equal(doc3.targets[0].carried, undefined, 'nothing to carry');
      const fourth = await runMain(['health', 'example.com', '--json', json, '--baseline', json, '--fail-on-change'], { fetchImpl: createFakeFetch(table) });
      assert.equal(fourth.code, EXIT.OK, fourth.out);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('subdomains --exact: the listed names only, no source asked, and a host behind the proxy that comes out', async () => {
    const dir = tmp();
    try {
      const names = join(dir, 'names.txt');
      writeFileSync(names, '# ours\nwww.example.com\napi.example.com, mail.example.com\nnope.example.com\nwww.example.org\nbad host!\n');
      const table = zoneTable();
      table['www.example.com'].A = ['104.16.1.1'];
      const log = [];
      const other = [];
      const json = join(dir, 'subs.json');
      const first = await runMain(['subdomains', 'example.com', '--exact', names, '--json', json, '--baseline', json], {
        fetchImpl: createFakeFetch(table, { log, other: (url) => { other.push(url); return new Response('', { status: 404 }); } })
      });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.err, /--exact .*names\.txt: skipped "host!": not a host name/);
      assert.deepEqual(other, [], 'no passive source, no RDAP');
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.equal(doc.targets[0].mode, 'exact');
      const hosts = Object.fromEntries(doc.targets[0].hosts.map((h) => [h.name, h]));
      assert.deepEqual(Object.keys(hosts).sort(), ['api.example.com', 'example.com', 'mail.example.com', 'nope.example.com', 'www.example.com']);
      assert.equal(hosts['www.example.com'].kind, 'cloudflare');
      assert.equal(hosts['mail.example.com'].kind, 'direct');
      assert.ok(!log.some((q) => q.name.endsWith('example.org')), 'a name outside the domain is not sent');
      assert.match(first.err, /1 name of names\.txt under none of the domains left out \(never sent\)/);
      assert.deepEqual(doc.warnings.slice(-1), ['1 name of names.txt under none of the domains left out (never sent)']);
      assert.match(first.out, /Subdomains · example\.com\n- \d+ subdomains found/);

      table['www.example.com'].A = ['192.0.2.10'];
      table['www.example.com'].AAAA = ['2001:db8::10'];
      const second = await runMain(['subdomains', 'example.com', '--exact', names, '--json', json, '--baseline', json, '--fail-on-change'], { fetchImpl: createFakeFetch(table) });
      assert.equal(second.code, EXIT.CHANGED, second.err);
      const changes = JSON.parse(readFileSync(json, 'utf8')).changes;
      assert.equal(changes[0].tag, 'EXPOSED');
      assert.match(changes[0].text, /www\.example\.com — no longer behind Cloudflare: now direct 192\.0\.2\.10/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('subdomains discovery: last night\'s hosts are looked up again, so one that went is GONE; a new one from crt.sh is NEW', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'subs.json');
      const base = report('subdomains', [{ target: 'example.com', mode: 'discover', hosts: [
        host('mail.example.com', { ipv4: ['198.51.100.25'] }), host('retired.example.com', { ipv4: ['192.0.2.77'] })
      ] }], { options: { mode: 'discover', level: 'off', sources: ['crtsh'] } });
      delete base.finishedAt;
      writeFileSync(json, JSON.stringify(base));
      const other = [];
      const fetchImpl = createFakeFetch(zoneTable(), {
        other: (url) => {
          other.push(url);
          if (url.startsWith('https://crt.sh/')) {
            return Response.json([{ issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: 'vpn.example.com', name_value: 'vpn.example.com', id: 5, not_before: '2026-09-20T00:00:00', not_after: '2026-12-19T00:00:00', serial_number: '05' }]);
          }
          return new Response('', { status: 404 });
        }
      });
      const res = await runMain(['subdomains', 'example.com', '--level', 'off', '--sources', 'crtsh', '--baseline', json, '--json', json, '--fail-on-change'], { fetchImpl });
      assert.equal(res.code, EXIT.CHANGED, res.err);
      assert.ok(other.every((u) => u.startsWith('https://crt.sh/')), other.join(' '));
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      const t0 = doc.targets[0];
      assert.equal(t0.seeded, 2);
      const byName = Object.fromEntries(t0.hosts.map((h) => [h.name, h]));
      assert.deepEqual(byName['retired.example.com'].origins, ['baseline']);
      assert.equal(byName['retired.example.com'].status, 'NXDOMAIN');
      assert.ok(t0.hosts.every((h) => h.ipv4.length || h.ipv6.length || h.dangling || h.name === 'retired.example.com'), 'only what resolves, and the seeded name');
      const counted = doc.changes.filter((c) => c.counts).map((c) => `${c.tag} ${c.item}`);
      assert.ok(counted.includes('GONE retired.example.com') && counted.includes('NEW vpn.example.com'), counted.join(', '));
      assert.ok(!doc.changes.some((c) => c.item === 'mail.example.com'), 'an unchanged host is no change');
      assert.match(doc.changes.find((c) => c.item === 'retired.example.com').text, /no longer resolves: NXDOMAIN/);
      assert.match(doc.changes.find((c) => c.item === 'vpn.example.com').text, /new host vpn\.example\.com — direct 203\.0\.113\.5/);
      assert.match(res.out, /Changes since the baseline \(subs\.json, run of an unknown time\)/, 'a baseline without a time');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('subdomains discovery: the scanner\'s warnings reach stderr, the report, the summary and the Markdown', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'subs.json');
      const md = join(dir, 'subs.md');
      // A hand-edited baseline: its host is seeded, and the scanner skips the name as the app would.
      writeFileSync(json, JSON.stringify(report('subdomains', [{ target: 'example.com', mode: 'discover', hosts: [host('-bad.example.com', { ipv4: ['192.0.2.99'] })] }])));
      const fetchImpl = createFakeFetch(zoneTable(), { other: (url) => (url.startsWith('https://crt.sh/') ? Response.json([]) : new Response('', { status: 404 })) });
      const res = await runMain(['subdomains', 'example.com', '--level', 'off', '--sources', 'crtsh', '--baseline', json, '--json', json, '--md', md], { fetchImpl });
      assert.equal(res.code, EXIT.OK, res.err);
      assert.match(res.err, /ds: warning: example\.com: Invalid hostname skipped: -bad\.example\.com\n/);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.targets[0].warnings, ['INVALID_NAME']);
      assert.ok(doc.warnings.includes('example.com: Invalid hostname skipped: -bad.example.com'), doc.warnings.join(' | '));
      assert.match(res.out, /\n- Warning: Invalid hostname skipped: -bad\.example\.com\n/);
      assert.match(readFileSync(md, 'utf8'), /\n- \*\*Warning:\*\* Invalid hostname skipped: `-bad\.example\.com`\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('subdomains discovery over two domains: Cert Spotter not asked again after its 429, and the summary says so', async () => {
    const dir = tmp();
    try {
      const spotter = [];
      const fetchImpl = createFakeFetch(zoneTable(), {
        other: (url) => {
          if (url.startsWith('https://crt.sh/')) return Response.json([]);
          if (url.startsWith('https://api.certspotter.com/')) {
            spotter.push(url);
            return new Response('{"code":"rate_limited"}', { status: 429, headers: { 'retry-after': '1800' } });
          }
          return new Response('', { status: 404 });
        }
      });
      const json = join(dir, 'subs.json');
      const res = await runMain(['subdomains', 'example.com', 'example.net', '--level', 'off', '--sources', 'crtsh,certspotter', '--json', json], { fetchImpl });
      assert.equal(res.code, EXIT.OK, res.err);
      assert.equal(spotter.length, 1, spotter.join(' '));
      assert.match(res.err, /ds: subdomains example\.net \(2\/2\), level off, not asking Cert Spotter\n/);
      assert.match(res.err, /ds: warning: Cert Spotter answered "rate limited" for example\.com: not asked again until 03:30 UTC \(its anonymous quota[^\n]*addresses\)\n/);
      const [first, second] = JSON.parse(readFileSync(json, 'utf8')).targets;
      assert.deepEqual(first.sources.map((s) => `${s.source} ${s.state}`), ['crtsh empty', 'certspotter rate-limited']);
      assert.deepEqual(second.sources.map((s) => `${s.source} ${s.state}${s.skipped ? ' skipped' : ''}`), ['crtsh empty', 'certspotter rate-limited skipped']);
      assert.match(res.out, /Subdomains · example\.net\n(?:- .*\n)*- Not asked: Cert Spotter \(rate limited earlier in this run\): the list may be incomplete\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('ct: crt.sh and Cert Spotter answered in the test, a new issuer the next night', async () => {
    const dir = tmp();
    try {
      const crtshRow = (id, issuer, nb, names) => ({ issuer_ca_id: id, issuer_name: issuer, common_name: names[0], name_value: names.join('\n'), id: id * 10, entry_timestamp: nb, not_before: nb, not_after: '2026-12-20T00:00:00', serial_number: `0${id}ab` });
      let rows = [crtshRow(1, "C=US, O=Let's Encrypt, CN=R11", '2026-09-20T00:00:00', ['example.com', 'www.example.com'])];
      const fetchImpl = async (url) => {
        const u = String(url);
        if (u.startsWith('https://crt.sh/')) return Response.json(rows);
        if (u.startsWith('https://api.certspotter.com/')) return new Response('{"code":"rate_limited","message":"rate limit"}', { status: 429, headers: { 'retry-after': '3600' } });
        return new Response('', { status: 404 });
      };
      const json = join(dir, 'ct.json');
      const md = join(dir, 'ct.md');
      const first = await runMain(['ct', 'example.com', '--json', json, '--md', md], { fetchImpl });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.out, /Certificate Transparency · example\.com\n- 1 current certificate · 1 issued in the last 30 days\n- Issuers: Let's Encrypt 1\n/);
      assert.match(first.out, /Not read: Cert Spotter \(rate limited\): the list may be incomplete/);
      assert.match(readFileSync(md, 'utf8'), /- Issuers: `Let's Encrypt` 1/);
      assert.match(first.err, /ds: warning: Cert Spotter answered "rate limited" for example\.com: not asked again until 04:00 UTC/);
      rows = [...rows, crtshRow(2, 'C=US, O=Google Trust Services, CN=WR1', '2026-09-27T00:00:00', ['example.com'])];
      const second = await runMain(['ct', 'example.com', '--baseline', json, '--json', join(dir, 'ct2.json'), '--fail-on-change'], { fetchImpl });
      // The baseline missed Cert Spotter, but crt.sh read the domain in full on both nights and
      // lists the new issuer: it counts.
      assert.equal(second.code, EXIT.CHANGED, second.err);
      assert.match(second.out, /ISSUER {5}example\.com: new issuer Google Trust Services \(WR1\): 1 current certificate, newest 2026-09-27\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('ct over a list: Cert Spotter asked once after its 429, crt.sh not asked again once it is down', async () => {
    const dir = tmp();
    try {
      const list = join(dir, 'domains.txt');
      writeFileSync(list, 'example.com\nexample.net\nexample.org\n');
      const asked = [];
      const fetchImpl = async (url) => {
        const u = String(url);
        asked.push(u);
        if (u.startsWith('https://crt.sh/')) return new Response('busy', { status: 503, headers: { 'retry-after': '0' } });
        if (u.startsWith('https://api.certspotter.com/')) return new Response('{"code":"rate_limited"}', { status: 429, headers: { 'retry-after': '3600' } });
        return new Response('', { status: 404 });
      };
      const json = join(dir, 'ct.json');
      const res = await runMain(['ct', '--list', list, '--json', json], { fetchImpl });
      assert.equal(res.code, EXIT.OK, res.err);
      const spotter = asked.filter((u) => u.startsWith('https://api.certspotter.com/'));
      const crtsh = asked.filter((u) => u.startsWith('https://crt.sh/'));
      assert.equal(spotter.length, 1, spotter.join(' '));
      assert.ok(crtsh.length >= 1 && crtsh.every((u) => u.includes('example.com')), crtsh.join(' '));
      assert.match(res.err, /ds: ct example\.net \(2\/3\), not asking crt\.sh or Cert Spotter\n/);
      assert.match(res.err, /ds: warning: crt\.sh was unavailable for example\.com: not asked again this run\n/);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc.targets[0].sources.map((s) => `${s.source} ${s.state}${s.skipped ? ' skipped' : ''}`), ['crtsh unavailable', 'certspotter rate-limited']);
      for (const x of doc.targets.slice(1)) {
        assert.deepEqual(x.sources.map((s) => `${s.source} ${s.state}${s.skipped ? ' skipped' : ''}`), ['crtsh unavailable skipped', 'certspotter rate-limited skipped'], x.target);
        assert.equal(x.answered, false);
      }
      assert.equal(doc.warnings.length, 2);
      assert.match(res.out, /Certificate Transparency · example\.org\n- Certificate Transparency could not be read: crt\.sh \(unavailable earlier in this run: not asked\), Cert Spotter \(rate limited earlier in this run: not asked\)\./);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('ct over a list, four nights: an outage is listed only, and a new CA issued during it counts the night crt.sh is back', async () => {
    const dir = tmp();
    try {
      const list = join(dir, 'domains.txt');
      writeFileSync(list, 'example.com\nexample.net\nexample.org\n');
      const json = join(dir, 'ct.json');
      const md = join(dir, 'ct.md');
      let crtshDown = false;
      let gts = false;
      const row = (d) => ({ issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: d, name_value: `${d}\nwww.${d}`, id: d.length, not_before: '2026-09-01T00:00:00', not_after: '2026-11-30T00:00:00', serial_number: `0${d.length}` });
      const gtsRow = { issuer_ca_id: 2, issuer_name: 'C=US, O=Google Trust Services, CN=WR1', common_name: 'example.com', name_value: 'example.com\nmail.example.com', id: 99, not_before: '2026-09-28T12:00:00', not_after: '2026-12-27T00:00:00', serial_number: '99' };
      const fetchImpl = async (url) => {
        const u = String(url);
        if (u.startsWith('https://crt.sh/')) {
          if (crtshDown) return new Response('busy', { status: 503, headers: { 'retry-after': '0' } });
          const d = decodeURIComponent(/[?&]q=([^&]+)/.exec(u)[1]).replace(/^%\./, '');
          return Response.json([row(d), ...(gts && d === 'example.com' ? [gtsRow] : [])]);
        }
        if (u.startsWith('https://api.certspotter.com/')) return new Response('{"code":"rate_limited"}', { status: 429, headers: { 'retry-after': '3600' } });
        return new Response('', { status: 404 });
      };
      const nightly = (day) => runMain(['ct', '--list', list, '--baseline', json, '--json', json, '--md', md, '--fail-on-change'], { fetchImpl, now: new Date(`2026-09-${day}T03:00:00Z`) });
      const first = await nightly(27);
      assert.equal(first.code, EXIT.OK, first.err);

      crtshDown = true;
      const outage = await nightly(28);
      assert.equal(outage.code, EXIT.OK, 'the source\'s outage is no change of the domains');
      const doc2 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc2.changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.target}`), ['FAILED? example.com', 'FAILED? example.net', 'FAILED? example.org']);
      assert.deepEqual(doc2.targets[0].issuers.map((g) => g.name), ["Let's Encrypt"], 'the last read is carried');
      assert.deepEqual(doc2.targets[0].certificates[0].carried, { from: '2026-09-27T03:00:00.000Z' });
      assert.match(outage.out, /Certificate Transparency · example\.com\n- Certificate Transparency could not be read: crt\.sh \(unavailable\), Cert Spotter \(rate limited\)\. The certificate last read on 2026-09-27 is kept for the next comparison\.\n/);

      crtshDown = false;
      gts = true;
      const back = await nightly(29);
      assert.equal(back.code, EXIT.CHANGED, back.err);
      const doc3 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(doc3.changes.filter((c) => c.counts).map((c) => `${c.tag} ${c.target} ${c.item}`),
        ['ISSUER example.com Google Trust Services', 'NAME example.com mail.example.com']);
      assert.ok(doc3.changes.filter((c) => !c.counts).every((c) => c.tag === 'RECOVERED'));
      assert.match(back.out, /ISSUER {5}example\.com: new issuer Google Trust Services \(WR1\): 1 current certificate, newest 2026-09-28\n/);
      assert.match(readFileSync(md, 'utf8'), /- \*\*ISSUER\*\* `example\.com`: new issuer `Google Trust Services`/);

      const quiet = await nightly(30);
      assert.equal(quiet.code, EXIT.OK, quiet.out);
      assert.match(quiet.out, /Changes since the baseline \(ct\.json, run of 2026-09-29 03:00 UTC\): none/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('subdomains discovery: a seeded host through a night of SERVFAIL stays watched, and answering at a new address is a change', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'subs.json');
      const table = zoneTable();
      table['legacy.example.com'] = { A: ['203.0.113.77'] };
      let listed = ['legacy.example.com'];
      let rcodes = {};
      const fetchImpl = (...args) => createFakeFetch(table, {
        rcodes,
        other: (url) => (url.startsWith('https://crt.sh/')
          ? Response.json(listed.map((n, i) => ({ issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: n, name_value: n, id: 5 + i, not_before: '2026-09-20T00:00:00', not_after: '2026-12-19T00:00:00', serial_number: `0${5 + i}` })))
          : new Response('', { status: 404 }))
      })(...args);
      const nightly = async (day) => {
        const res = await runMain(['subdomains', 'example.com', '--level', 'off', '--sources', 'crtsh', '--baseline', json, '--json', json, '--fail-on-change', '-q'],
          { fetchImpl, now: new Date(`2026-09-${day}T03:00:00Z`) });
        const doc = JSON.parse(readFileSync(json, 'utf8'));
        return { ...res, doc, legacy: doc.targets[0].hosts.find((h) => h.name === 'legacy.example.com') };
      };
      assert.equal((await nightly(26)).legacy.ipv4[0], '203.0.113.77');
      listed = [];
      const seeded = await nightly(27);
      assert.deepEqual(seeded.legacy.origins, ['baseline'], 'crt.sh no longer lists it: looked up again as last night\'s host');
      rcodes = { 'legacy.example.com|A': 'SERVFAIL', 'legacy.example.com|AAAA': 'SERVFAIL' };
      const failed = await nightly(28);
      assert.equal(failed.code, EXIT.CHANGED);
      assert.equal(failed.legacy.status, 'SERVFAIL');
      assert.deepEqual(failed.legacy.lastGood.ipv4, ['203.0.113.77']);
      assert.deepEqual(failed.doc.changes.map((c) => `${c.tag} ${c.item}`), ['FAILED legacy.example.com']);
      rcodes = {};
      table['legacy.example.com'] = { A: ['198.51.100.200'] };
      const moved = await nightly(29);
      assert.equal(moved.code, EXIT.CHANGED, 'still watched after the failed lookup');
      assert.equal(moved.legacy.ipv4[0], '198.51.100.200');
      assert.deepEqual(moved.doc.changes.map((c) => `${c.tag} ${c.item}`), ['CHANGED legacy.example.com']);
      assert.match(moved.doc.changes[0].text, /legacy\.example\.com — addresses direct 203\.0\.113\.77 → direct 198\.51\.100\.200 \(compared with its answer of \d{4}-\d\d-\d\d, before the lookup failed\)$/);
      assert.equal((await nightly(30)).code, EXIT.OK);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('ct: a night with crt.sh down is no new issuer for a CA Cert Spotter names otherwise', async () => {
    const dir = tmp();
    try {
      const dn = 'C=TR, O=Example Kamu SM, CN=Example Kamu SM SSL';
      let crtshDown = false;
      const fetchImpl = async (url) => {
        const u = String(url);
        if (u.startsWith('https://crt.sh/')) {
          if (crtshDown) return new Response('busy', { status: 503, headers: { 'retry-after': '0' } });
          return Response.json([{ issuer_ca_id: 9, issuer_name: dn, common_name: 'example.com', name_value: 'example.com\nwww.example.com', id: 90, not_before: '2026-09-20T00:00:00', not_after: '2026-12-19T00:00:00', serial_number: '09' }]);
        }
        if (u.startsWith('https://api.certspotter.com/')) {
          if (u.includes('after=')) return Response.json([]);
          return Response.json([{ id: '1', cert_sha256: 'ef'.repeat(32), dns_names: ['example.com', 'www.example.com'], not_before: '2026-09-20T00:00:00Z', not_after: '2026-12-19T00:00:00Z', issuer: { name: dn, friendly_name: 'Example Operator' } }]);
        }
        return new Response('', { status: 404 });
      };
      const json = join(dir, 'ct.json');
      const first = await runMain(['ct', 'example.com', '--baseline', json, '--json', json], { fetchImpl });
      assert.equal(first.code, EXIT.OK, first.err);
      assert.match(first.out, /Issuers: Example Kamu SM 1\n/);
      crtshDown = true;
      const second = await runMain(['ct', 'example.com', '--baseline', json, '--json', json, '--fail-on-change'], { fetchImpl });
      assert.equal(second.code, EXIT.OK, second.out);
      assert.match(second.out, /Changes since the baseline \(ct\.json, run of 2026-09-28 03:00 UTC\): none/);
      assert.match(second.out, /Issuers: Example Kamu SM 1\n/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('audit over four nights: a failed rule is exit 4; RDAP once per domain, from the registry; .tr not known; a night RDAP fails carries the statuses on', async () => {
    const dir = tmp();
    try {
      const zone = portfolioZone({ now: NOW.getTime() });
      const json = join(dir, 'audit.json');
      const md = join(dir, 'audit.md');
      const argv = ['audit', '--preset', 'baseline', 'example.com', 'www.example.org', 'example-test.com.tr', '--json', json, '--baseline', json, '--fail-on-change'];
      const log = [];
      const rdapLog = [];
      const first = await runMain([...argv, '--md', md], { fetchImpl: createPortfolioFetch(zone, { log, rdapLog }) });
      assert.equal(first.code, EXIT.CHANGED, first.err);
      assert.match(first.out, /^Baseline audit\.json does not exist yet/);
      assert.match(first.out, /\nPolicy audit · baseline\n- 3 domains, 7 rules: 3 fail the policy, 0 could not be checked in full, 0 meet every rule\n- Rules: expiryDays >= 30, transferLock true, status\.critical false, nsExpiryDays >= 30, spf valid, spf\.lookups <= 10, dmarc\.policy >= none\n/);
      assert.match(first.out, /\nPolicy audit · example\.org\n- 3 rules failed, 0 could not be checked, 4 passed\n- FAIL expiryDays >= 30: 20 days left \(\d{4}-\d{2}-\d{2}\)\n- FAIL transferLock true: no transfer prohibition \(clientTransferProhibited or serverTransferProhibited\): the domain can be transferred away\n- FAIL nsExpiryDays >= 30: name server domain example\.net: 12 days left\n/);
      assert.match(first.err, /ds: audit: 3 domains, 7 rules, DKIM at 8 selectors\n/);
      assert.match(first.err, /ds: warning: no RDAP for example-test\.com\.tr \(the registry publishes none\): the registration rules could not be checked/);
      assert.deepEqual(rdapLog.map((x) => x.domain).sort(), ['example.com', 'example.net', 'example.org'], 'each once, the name servers\' domain too; none for .tr');
      assert.ok(rdapLog.every((x) => x.host === 'rdap.example.net'), 'the registry the bootstrap names, never rdap.org');
      assert.ok(log.some((q) => q.name === 'google._domainkey.example.com'), 'DKIM at the common selectors');
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.equal(doc.command, 'audit');
      assert.deepEqual(doc.options.policy.rules, { expiryDays: '>= 30', transferLock: true, 'status.critical': false, nsExpiryDays: '>= 30', spf: 'valid', 'spf.lookups': '<= 10', 'dmarc.policy': '>= none' });
      assert.deepEqual([doc.options.preset, doc.options.policyFile, doc.options.dkim], ['baseline', null, true]);
      assert.deepEqual(doc.targets.map((x) => x.target), ['example.com', 'example.org', 'example-test.com.tr'], 'www.example.org is example.org');
      const tr = doc.targets[2];
      assert.deepEqual(tr.rules.filter((r) => r.status === 'unknown').map((r) => r.id), ['expiryDays', 'transferLock', 'status.critical']);
      assert.deepEqual([tr.rules[0].key, tr.rules[0].params, tr.row.registration], ['pol.ev.noRdap', { tld: '.tr' }, 'unsupported']);
      assert.deepEqual(doc.targets[0].rules.find((r) => r.id === 'nsExpiryDays'), {
        id: 'nsExpiryDays', status: 'fail', required: '>= 30', actual: 12, evidence: 'name server domain example.net: 12 days left',
        key: 'pol.ev.nsDays', params: { domain: 'example.net', count: 12 }
      });
      assert.equal(doc.targets[0].row.nsDomains, 'example.net:12');
      const mdText = readFileSync(md, 'utf8');
      assert.match(mdText, /^\*\*audit: first run\*\*/);
      assert.match(mdText, /\*\*Policy audit · `baseline`\*\*\n- 3 domains, 7 rules/);
      assert.match(mdText, /- \*\*NOT KNOWN\*\* `expiryDays >= 30`: the `\.tr` registry publishes no RDAP: see its WHOIS\n/);
      assert.match(mdText, /- \*\*FAIL\*\* `nsExpiryDays >= 30`: name server domain `example\.net`: 12 days left\n/);

      // Night 2: the name servers' domain renewed, example.org locked.
      zone.rdap['example.net'].events[1].eventDate = new Date(NOW.getTime() + 400 * 86400000).toISOString();
      zone.rdap['example.org'].status = ['client transfer prohibited'];
      const second = await runMain(argv, { fetchImpl: createPortfolioFetch(zone) });
      assert.equal(second.code, EXIT.CHANGED, 'example.org still expires in 20 days, the .tr domain has no DMARC');
      const doc2 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(tags(doc2.changes), ['BETTER example.com nsExpiryDays', 'BETTER example.org transferLock', 'BETTER example.org nsExpiryDays', 'BETTER example-test.com.tr nsExpiryDays']);

      // Night 3: example.org's RDAP answers 503 (the registry, then rdap.org as the fallback): its registration
      // rules cannot be checked, listed only; the statuses they had are carried.
      const rdapLog3 = [];
      const third = await runMain(argv, { fetchImpl: createPortfolioFetch(zone, { rdapLog: rdapLog3, rdapStatus: { 'example.org': 503 } }) });
      assert.equal(third.code, EXIT.CHANGED);
      assert.match(third.err, /ds: warning: RDAP could not be read for example\.org: the registration rules could not be checked/);
      assert.ok(rdapLog3.some((x) => x.host === 'rdap.org' && x.domain === 'example.org'), 'rdap.org only when the registry fails');
      const doc3 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(tags(doc3.changes), ['FAILED? example.org expiryDays', 'FAILED? example.org transferLock', 'FAILED? example.org status.critical']);
      const org3 = doc3.targets.find((x) => x.target === 'example.org');
      assert.deepEqual(org3.rules.slice(0, 3).map((r) => [r.status, r.last && r.last.status, r.last && r.last.from]), [
        ['unknown', 'fail', doc2.targets[1].checkedAt], ['unknown', 'pass', doc2.targets[1].checkedAt], ['unknown', 'pass', doc2.targets[1].checkedAt]
      ]);

      // Night 4: RDAP answers again with what it said before: compared with the carried statuses, nothing changed.
      const fourth = await runMain(argv, { fetchImpl: createPortfolioFetch(zone) });
      assert.equal(fourth.code, EXIT.CHANGED, 'rules still fail');
      assert.match(fourth.out, /Changes since the baseline \(audit\.json, run of 2026-09-28 03:00 UTC\): none/);
      assert.deepEqual(JSON.parse(readFileSync(json, 'utf8')).changes, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('audit: a policy file the app exported (every rule met: exit 0), DKIM off, and a file with a typo refused before anything is sent', async () => {
    const dir = tmp();
    try {
      const zone = portfolioZone({ now: NOW.getTime() });
      const policy = join(dir, 'policy.json');
      writeFileSync(policy, '\uFEFF{\n  "name": "mail",\n  "version": 1,\n  "rules": { "spf": "valid", "spf.lookups": "<= 10", "dkim": true }\n}\n');
      const list = join(dir, 'domains.txt');
      writeFileSync(list, '# the portfolio\nexample.com\nmail.example.com\n');
      const log = [];
      const pass = await runMain(['audit', '--policy', policy, list, '--json', join(dir, 'a.json')], { fetchImpl: createPortfolioFetch(zone, { log }) });
      assert.equal(pass.code, EXIT.OK, pass.err + pass.out);
      assert.match(pass.out, /^Policy audit · mail\n- 1 domain, 3 rules: 0 fail the policy, 0 could not be checked in full, 1 meets every rule\n- Rules: spf valid, spf\.lookups <= 10, dkim true\n- Every rule met: example\.com\n/);
      assert.equal(JSON.parse(readFileSync(join(dir, 'a.json'), 'utf8')).options.policyFile, 'policy.json');

      const noDkim = await runMain(['audit', '--policy', policy, 'example.com', '--no-dkim'], { fetchImpl: createPortfolioFetch(zone, { log: (log.length = 0, log) }) });
      assert.equal(noDkim.code, EXIT.OK, 'a rule not checked is no failure');
      assert.match(noDkim.out, /- NOT KNOWN dkim true: not checked \(turned off\)\n/);
      assert.ok(!log.some((q) => q.name.includes('_domainkey')), 'no DKIM question');

      // A registry lock alone (serverTransferProhibited, as nic.io answers) is a transfer lock: no failure.
      writeFileSync(policy, '{ "transferLock": true }');
      zone.rdap['example.com'].status = ['server delete prohibited', 'server transfer prohibited', 'server update prohibited'];
      const registryLock = await runMain(['audit', '--policy', policy, 'example.com', '--no-dkim'], { fetchImpl: createPortfolioFetch(zone) });
      assert.equal(registryLock.code, EXIT.OK, registryLock.out);
      assert.match(registryLock.out, /- Every rule met: example\.com\n/);

      writeFileSync(policy, '{ "expiryDays": ">= 30", "dnsec": "signed", "spf.all": "-none" }');
      const asked = [];
      const fetchImpl = async (url) => {
        asked.push(url);
        return new Response('', { status: 404 });
      };
      const typo = await runMain(['audit', '--policy', policy, 'example.com'], { fetchImpl });
      assert.equal(typo.code, EXIT.USAGE);
      assert.match(typo.err, /^ds: error: --policy .*policy\.json: unknown rule "dnsec"; "spf\.all" does not take "-none" \(for example ">= ~all"\) \(the rules: expiryDays, transferLock, /);
      writeFileSync(policy, '{ "expiryDays": ');
      assert.match((await runMain(['audit', '--policy', policy, 'example.com'], { fetchImpl })).err, /--policy .*: not JSON \(/);
      assert.deepEqual(asked, [], 'nothing sent');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('renew and dane on the fake zone', async () => {
    const table = zoneTable();
    const renew = await runMain(['renew', 'example.com', '*.example.com', '--ca', 'letsencrypt', '--challenge', 'dns-01'], { fetchImpl: createFakeFetch(table) });
    assert.equal(renew.code, EXIT.OK, renew.err);
    assert.match(renew.out, /^Renewal readiness · example\.com, \*\.example\.com\n/);
    assert.match(renew.out, /CA: Let's Encrypt · challenge: DNS-01/);
    const dane = await runMain(['dane', join(ROOT, 'tests', 'fixtures', 'renew_a_rsa.pem')], { fetchImpl: createFakeFetch(table) });
    assert.equal(dane.code, EXIT.OK, dane.err);
    assert.match(dane.out, /^DANE \/ TLSA · example\.com\n- No TLSA records: DANE is not used/);
    const key = await runMain(['dane', join(ROOT, 'tests', 'fixtures', 'with_key.pem')], { fetchImpl: createFakeFetch(table) });
    assert.match(key.err, /with_key\.pem also holds a private key: it was ignored, never read or sent/);
    assert.ok(!/PRIVATE KEY|MII/.test(key.out + key.err), 'no key material printed');
    const pfx = await runMain(['dane', join(ROOT, 'tests', 'fixtures', 'test.pfx')], { fetchImpl: createFakeFetch(table) });
    assert.equal(pfx.code, EXIT.USAGE);
    assert.match(pfx.err, /a PKCS#12 bundle: give the certificates as PEM/);
  });

  test('Ctrl-C (the signal) stops the run: exit 130, nothing written, the baseline kept', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'health.json');
      writeFileSync(json, JSON.stringify(report('health', [{ target: 'example.com', score: 90, checks: [] }])));
      const before = readFileSync(json, 'utf8');
      const controller = new AbortController();
      let asked = 0;
      // Every DoH request waits until the run is stopped; the first one stops it. The rest (the
      // shared RDAP bootstrap, which is not tied to the run's signal) are settled at once.
      const fetchImpl = (url, init = {}) => new Promise((resolve, reject) => {
        if (!/[?&]dns=/.test(String(url))) {
          resolve(new Response('', { status: 404 }));
          return;
        }
        asked += 1;
        const stop = () => reject(init.signal.reason);
        if (init.signal.aborted) stop();
        else init.signal.addEventListener('abort', stop, { once: true });
        setTimeout(() => controller.abort(), 5);
      });
      const stdout = sink();
      const stderr = sink();
      const code = await main(['health', 'example.com', '--baseline', json, '--json', json, '--md', join(dir, 'h.md')], { stdout, stderr, fetchImpl, env: {}, now: () => NOW, signal: controller.signal });
      assert.equal(code, EXIT.INTERRUPTED);
      assert.ok(asked > 0);
      assert.match(stderr.text, /ds: interrupted: nothing written\n$/);
      assert.equal(stdout.text, '');
      assert.equal(readFileSync(json, 'utf8'), before);
      assert.ok(!existsSync(join(dir, 'h.md')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('refused before anything is sent: a report file that cannot be written, a baseline of another command, a missing one', async () => {
    const dir = tmp();
    try {
      const log = [];
      const fetchImpl = createFakeFetch(zoneTable(), { log });
      const noDir = await runMain(['health', 'example.com', '--json', join(dir, 'missing', 'h.json')], { fetchImpl });
      assert.equal(noDir.code, EXIT.USAGE);
      assert.match(noDir.err, /--json: directory does not exist/);
      mkdirSync(join(dir, 'adir'));
      assert.match((await runMain(['health', 'example.com', '--md', join(dir, 'adir')], { fetchImpl })).err, /--md: .* is a directory/);
      const ct = join(dir, 'ct.json');
      writeFileSync(ct, JSON.stringify(report('ct', [])));
      const other = await runMain(['health', 'example.com', '--baseline', ct], { fetchImpl });
      assert.equal(other.code, EXIT.USAGE);
      assert.match(other.err, /--baseline: cannot compare with .*ct\.json: it is a report of "ct", not of "health"/);
      const missing = await runMain(['health', 'example.com', '--baseline', join(dir, 'none.json')], { fetchImpl });
      assert.match(missing.err, /--baseline: .*none\.json does not exist \(give a report written with --json\)/);
      writeFileSync(join(dir, 'bad.json'), '{ not json');
      assert.match((await runMain(['health', 'example.com', '--baseline', join(dir, 'bad.json')], { fetchImpl })).err, /is not JSON/);
      writeFileSync(join(dir, 'empty.txt'), '# nothing yet\n');
      assert.match((await runMain(['health', '--list', join(dir, 'empty.txt')], { fetchImpl })).err, /health: no target: --list .*empty\.txt names none/);
      assert.match((await runMain(['drift', join(dir, 'nope.zone')], { fetchImpl })).err, /cannot read .*nope\.zone: no such file/);
      assert.deepEqual(log, [], 'no DNS query');
      assert.ok(!existsSync(join(dir, 'none.json')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a zone whose name is only a guess needs --origin', async () => {
    const dir = tmp();
    try {
      const file = join(dir, 'db.example.com');
      writeFileSync(file, 'www 300 IN A 192.0.2.1\n');
      const guess = await runMain(['drift', file], { fetchImpl: createFakeFetch(zoneTable()) });
      assert.equal(guess.code, EXIT.USAGE);
      assert.match(guess.err, /the zone name example\.com is a guess .*: confirm it with --origin example\.com/);
      const ok = await runMain(['drift', file, '--origin', 'example.com'], { fetchImpl: createFakeFetch(zoneTable()) });
      assert.equal(ok.code, EXIT.OK, ok.err);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ------------------------------------------------------------------------ */
/* The documented commands                                                  */
/* ------------------------------------------------------------------------ */

describe('the documented commands', () => {
  const unquote = (s) => s.replace(/^'(.*)'$/, '$1');

  test('every ds line of the nightly template, commented ones too, is a command line the runner takes', () => {
    const yml = readFileSync(join(ROOT, 'docs', 'examples', 'nightly-domainscope.yml'), 'utf8').replace(/\r\n/g, '\n');
    const lines = [...yml.matchAll(/^ *#? *ds ([a-z][\w-]*) ([a-z]+)((?: [^\s#]+)*) *$/gm)];
    assert.equal(lines.length, 7, `${lines.length} ds lines`);
    for (const [, name, command, rest] of lines) {
      assert.ok(COMMANDS.includes(command), command);
      const argv = [command, ...rest.trim().split(/\s+/).filter(Boolean).map(unquote), '--baseline', `results/${name}.json`,
        '--json', `results/${name}.json`, '--md', `results/${name}.md`, '--fail-on-change', '--no-color'];
      assert.doesNotThrow(() => parseCommandLine(argv), argv.join(' '));
    }
    assert.match(yml, /timeout -s INT -k 60 "\$limit" node \.domainscope\/tools\/ds\.mjs "\$@" --baseline "results\/\$name\.json" --json "results\/\$name\.json" \\\n\s+--md "results\/\$name\.md" --fail-on-change --no-color/);
    assert.match(yml, /if \[ "\$code" -eq 4 \]; then changed\+=/);
  });

  test('every check has a time limit inside the job\'s, and a night a check failed never closes the issue', () => {
    const yml = readFileSync(join(ROOT, 'docs', 'examples', 'nightly-domainscope.yml'), 'utf8').replace(/\r\n/g, '\n');
    const job = Number(/timeout-minutes: (\d+)/.exec(yml)[1]);
    const check = Number(/CHECK_MINUTES: (\d+)/.exec(yml)[1]);
    const all = Number(/RUN_MINUTES: (\d+)/.exec(yml)[1]);
    assert.ok(check <= all && all + 10 <= job, `${check} / ${all} / ${job}`);
    assert.match(yml, /end=\$\(\( \$\(date \+%s\) \+ RUN_MINUTES \* 60 \)\)/);
    assert.match(yml, /FAILED: \$\{\{ steps\.ds\.outputs\.failed \}\}\n\s+RESULTS:/, 'the issue step knows what failed');
    const issueStep = yml.slice(yml.indexOf('- name: Open, update or close the issue'), yml.indexOf('- name: Fail when a check did not complete'));
    const close = issueStep.indexOf('gh issue close');
    assert.ok(close > issueStep.indexOf('elif [ -n "$FAILED" ]; then'), 'closed only after the failed nights are handled');
    assert.match(issueStep, /elif \[ -n "\$FAILED" \]; then\n(?:.*\n){1,2}\s+if \[ -n "\$issue" \]; then\n\s+gh issue comment "\$issue" --body "Not closed: /);
    assert.match(yml, /--sources crtsh/);
    const readme = readFileSync(join(ROOT, 'docs', 'examples', 'README.md'), 'utf8');
    assert.match(readme, /`--sources crtsh` on the `ct` line/);
    assert.match(readme, /CHECK_MINUTES/);
  });

  test('the template says the three rules, runs nightly with only the token\'s write scopes it needs, and keeps one issue', () => {
    const yml = readFileSync(join(ROOT, 'docs', 'examples', 'nightly-domainscope.yml'), 'utf8').replace(/\r\n/g, '\n');
    assert.match(yml, /Use it in a PRIVATE repository/);
    assert.match(yml, /Never commit inventories or zone files unless you mean to/);
    assert.match(yml, /No secret is needed/);
    assert.match(yml, /^ {4}- cron: '\d+ \d+ \* \* \*'/m);
    assert.match(yml, /^permissions:\n {2}contents: write[^\n]*\n {2}issues: write[^\n]*\n\n/m);
    assert.doesNotMatch(yml, /secrets\./, 'no secret');
    assert.match(yml, /repository: halilibrahimd27\/domainscope\n\s+ref: /);
    for (const cmd of ['gh issue list --label "\\$label" --state open', 'gh issue create', 'gh issue edit', 'gh issue comment', 'gh issue close']) assert.match(yml, new RegExp(cmd), cmd);
    assert.match(yml, /git add results\n/);
    // No token in the checkout while DomainScope's code runs: only the commit and issue steps get it.
    const steps = yml.split(/\n(?= {6}- (?:name|uses): )/);
    const own = steps.find((s) => s.includes("Check out this repository (domains.txt and last night's results)"));
    assert.match(own, /\n {8}with:\n {10}persist-credentials: false/);
    assert.match(steps.find((s) => s.includes('- name: Check out DomainScope')), /persist-credentials: false/);
    const withToken = steps.filter((s) => s.includes('github.token')).map((s) => /- name: ([^\n]+)/.exec(s)[1]);
    assert.deepEqual(withToken, ['Commit the results', 'Open, update or close the issue']);
    assert.ok(!steps.find((s) => s.includes('- name: Run the checks')).includes('TOKEN'));
    const commit = steps.find((s) => s.includes('- name: Commit the results'));
    assert.match(commit, /auth="http\.\$GITHUB_SERVER_URL\/\.extraheader=AUTHORIZATION: basic \$\(printf 'x-access-token:%s' "\$GH_TOKEN" \| base64 -w0\)"\n\s+git -c "\$auth" pull -q --rebase\n\s+git -c "\$auth" push -q/);
    assert.match(yml, /ref: main {3}# pin a commit SHA \(or a release tag once there is one\)/);
    const readme = readFileSync(join(ROOT, 'docs', 'examples', 'README.md'), 'utf8');
    for (const rule of ['Use it in a private repository', 'Never commit inventories or zone files unless you mean to', 'No secret is needed']) assert.ok(readme.includes(rule), rule);
  });

  test('the examples of the README and of --help parse', () => {
    const readme = readFileSync(join(ROOT, 'docs', 'examples', 'README.md'), 'utf8');
    const lines = [...`${readme}\n${USAGE}`.matchAll(/^ *node tools\/ds\.mjs (.+)$/gm)].map((m) => m[1]);
    assert.ok(lines.length >= 12, `${lines.length} examples`);
    for (const line of lines) {
      const argv = line.trim().split(/\s+/).map(unquote);
      if (argv[0] === 'COMMAND') continue;
      assert.doesNotThrow(() => parseCommandLine(argv), line);
    }
  });
});

test('the program itself: a spawned runner whose fetch is the fake DoH (node --import)', () => {
  const dir = tmp();
  try {
    const json = join(dir, 'drift.json');
    const md = join(dir, 'drift.md');
    const logFile = join(dir, 'queries.json');
    const res = spawnSync(process.execPath, ['--import', pathToFileURL(join(ROOT, 'tests', 'js', 'ds-fake-doh.mjs')).href, DS, 'drift', CF_EXPORT, '--json', json, '--md', md, '--no-color'], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, DS_FAKE_DOH: '1', DS_FAKE_DOH_LOG: logFile, NO_COLOR: '1' }, timeout: 60000
    });
    assert.equal(res.status, EXIT.OK, res.stderr);
    assert.match(res.stdout, /^Zone File · example\.com\n- Live check: /);
    assert.match(res.stderr, /ds: JSON report written to /);
    assert.equal(JSON.parse(readFileSync(json, 'utf8')).command, 'drift');
    assert.match(readFileSync(md, 'utf8'), /\*\*Zone File · `example\.com`\*\*/);
    const queries = JSON.parse(readFileSync(logFile, 'utf8'));
    assert.ok(queries.length > 10);
    assert.ok(queries.every((q) => /^https:\/\/(cloudflare-dns\.com|dns\.google|doh\.dns\.sb)\//.test(q.url)), 'the default chain only');
    const usage = spawnSync(process.execPath, [DS, 'health'], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });
    assert.equal(usage.status, EXIT.USAGE);
    assert.equal(usage.stderr, 'ds: error: health needs at least one domain (or --list FILE)\n');
    const help = spawnSync(process.execPath, [DS, '--help'], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });
    assert.equal(help.status, 0);
    assert.equal(help.stdout, `${USAGE}${USAGE.endsWith('\n') ? '' : '\n'}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the program itself: a spawned audit whose fetch is the portfolio fake exits 4 on a failed rule, 0 when every rule is met', () => {
  const dir = tmp();
  try {
    const logFile = join(dir, 'requests.json');
    const spawnAudit = (args) => spawnSync(process.execPath, ['--import', pathToFileURL(join(ROOT, 'tests', 'js', 'ds-fake-doh.mjs')).href, DS, 'audit', ...args, '--no-color'], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, DS_FAKE_DOH: 'portfolio', DS_FAKE_DOH_LOG: logFile, NO_COLOR: '1' }, timeout: 60000
    });
    const parked = spawnAudit(['--preset', 'parked', 'example.org', '--json', join(dir, 'audit.json')]);
    assert.equal(parked.status, EXIT.CHANGED, parked.stderr);
    assert.match(parked.stdout, /^Policy audit · parked domain\n- 1 domain, 6 rules: 1 fails the policy, 0 could not be checked in full, 0 meet every rule\n/);
    assert.match(parked.stdout, /- FAIL transferLock true: no transfer prohibition/);
    assert.match(parked.stdout, /- FAIL caa deny-all: no CAA record: any CA may issue/);
    const requests = JSON.parse(readFileSync(logFile, 'utf8'));
    assert.deepEqual(requests.rdap.map((x) => `${x.host} ${x.domain}`).sort(), ['rdap.example.net example.net', 'rdap.example.net example.org']);
    assert.ok(requests.dns.every((q) => q.name === 'example.org' || q.name.endsWith('.example.org')), 'only the domain\'s own names asked');
    const met = spawnAudit(['--preset', 'strict-mail', 'example.com']);
    assert.equal(met.status, EXIT.OK, met.stdout + met.stderr);
    assert.match(met.stdout, /- Every rule met: example\.com\n/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the program stopped with Ctrl-C (SIGINT) leaves at once, not when the RDAP bootstrap download times out', async (t2) => {
  if (process.platform === 'win32') {
    t2.skip('a signal sent to a child process ends it on Windows without running its handler');
    return;
  }
  const dir = tmp();
  try {
    const child = spawn(process.execPath, ['--import', pathToFileURL(join(ROOT, 'tests', 'js', 'ds-fake-doh.mjs')).href, DS, 'health', 'example.com', '--json', join(dir, 'h.json')], {
      cwd: ROOT, env: { ...process.env, DS_FAKE_DOH: 'hang' }, stdio: ['ignore', 'pipe', 'pipe']
    });
    let err = '';
    let stoppedAt = 0;
    const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal, at: Date.now() })));
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (s) => {
      err += s;
      // Stop it once the bootstrap download (bound by its own 15 s timeout and a retry) hangs.
      if (!stoppedAt && err.includes('fake: GET https://data.iana.org/rdap/dns.json')) {
        stoppedAt = Date.now();
        child.kill('SIGINT');
      }
    });
    const guard = setTimeout(() => child.kill('SIGKILL'), 60000);
    const { code, at } = await exited;
    clearTimeout(guard);
    assert.ok(stoppedAt > 0, err);
    assert.equal(code, EXIT.INTERRUPTED, err);
    assert.match(err, /ds: interrupted: nothing written\n/);
    assert.ok(at - stoppedAt < 5000, `exited ${at - stoppedAt} ms after Ctrl-C`);
    assert.ok(!existsSync(join(dir, 'h.json')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the program runs through a symlinked checkout too', (t2) => {
  const dir = tmp();
  const link = join(dir, 'domainscope');
  try {
    try {
      symlinkSync(ROOT, link, 'junction');
    } catch (err) {
      t2.skip(`no symlink here (${err.code})`);
      return;
    }
    const res = spawnSync(process.execPath, [join(link, 'tools', 'ds.mjs'), '--version'], { cwd: dir, encoding: 'utf8', timeout: 60000 });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, `${DS_TOOL} ${DS_VERSION}\n`);
  } finally {
    // The link first, on its own: never walk into the checkout it points at.
    if (lstatSync(link, { throwIfNoEntry: false })) unlinkSync(link);
    rmSync(dir, { recursive: true, force: true });
  }
});
