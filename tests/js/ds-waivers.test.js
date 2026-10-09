/**
 * The headless runner's accepted risks (`--waivers waivers.json`, tools/ds/waivers.mjs over
 * lib/waivers.js): the option and the file, the changes of an accepted item (WAIVED, listed only;
 * WAIVER-EXPIRED once its end date is over, counted), the summary of what was accepted, the exit
 * codes (--fail-on-change, audit's 4) and where a PagerDuty problem stands. Offline runs of the
 * program on a moved clock, over the fake DoH and RDAP of tests/js/ds-fake-doh.mjs.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCommandLine, UsageError, EXIT, DS_TOOL, DS_VERSION } from '../../tools/ds/args.mjs';
import { diffReports, baselineNotes } from '../../tools/ds/diff.mjs';
import { setupStrings, renderChangesText, renderChangesMarkdown, painter, changeText, TAG_WIDTH } from '../../tools/ds/render.mjs';
import { readWaiversFile, waiversDoc, entryProblem } from '../../tools/ds/waivers.mjs';
import { watchTarget } from '../../tools/ds/ctwatch.mjs';
import { problemStanding } from '../../tools/ds/states.mjs';
import { main } from '../../tools/ds.mjs';
import { zoneTable, createFakeFetch, portfolioZone, createPortfolioFetch } from './ds-fake-doh.mjs';
import { renderPlainText } from '../../assets/js/lib/summary.js';

const t = await setupStrings();
const NIGHT = (day) => new Date(`2026-10-${String(day).padStart(2, '0')}T03:00:00Z`);
const tmp = () => mkdtempSync(join(tmpdir(), 'ds-waivers-'));
const sink = () => ({ text: '', write(s) { this.text += s; return true; } });
const tags = (changes) => changes.map((c) => `${c.tag}${c.counts ? '' : '?'} ${c.target}${c.item ? ` ${c.item}` : ''}`);
const report = (command, targets, options = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command, startedAt: '2026-10-08T03:00:00.000Z', finishedAt: '2026-10-08T03:02:00.000Z', options, targets
});
const file = (waivers) => JSON.stringify({ format: 'domainscope-waivers', v: 1, waivers });
const waiver = (o = {}) => ({ kind: 'finding', domain: 'example.com', ref: 'mx.unresolvable', reason: 'Old MX host goes in November', owner: 'Mail team', expires: '2026-10-20', ...o });

/** main() with captured streams, the given fetch and clock. */
async function runMain(argv, { fetchImpl, now }) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now });
  return { code, out: stdout.text, err: stderr.text };
}

describe('the option and the file', () => {
  test('--waivers is health\'s, audit\'s and ct\'s; a file, never one a report would overwrite', () => {
    for (const argv of [['health', 'example.com'], ['ct', 'example.com'], ['audit', '--preset', 'baseline', 'example.com']]) {
      assert.equal(parseCommandLine([...argv, '--waivers', 'waivers.json']).options.waivers, 'waivers.json', argv[0]);
    }
    assert.equal(parseCommandLine(['health', 'example.com']).options.waivers, null);
    assert.throws(() => parseCommandLine(['subdomains', 'example.com', '--waivers', 'w.json']), /--waivers applies to health, ct and audit only, not to subdomains/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--waivers', '-']), /--waivers takes a file, not "-"/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--waivers', ' ']), /--waivers needs a file name/);
    assert.throws(() => parseCommandLine(['health', 'example.com', '--waivers', 'w.json', '--json', './w.json']), /--json names the same file as --waivers/);
  });

  test('read before the run: a file that is no waivers file is a usage error; an entry that cannot be read is a warning, and its item counts', async () => {
    const read = async (text) => readWaiversFile('waivers.json', { read: async () => text, now: NIGHT(9) });
    await assert.rejects(read('{ nope'), (e) => e instanceof UsageError && /--waivers waivers\.json: not JSON/.test(e.message));
    await assert.rejects(read('{"format":"x"}'), /not a waivers file/);
    await assert.rejects(read(JSON.stringify({ format: 'domainscope-waivers', v: 9, waivers: [] })), /newer version/);
    const r = await read(file([waiver(), waiver({ ref: 'spf.ptr', expires: '2031-01-01' }), waiver({ kind: 'nope' })]));
    assert.deepEqual([r.file, r.list.map((w) => w.ref)], ['waivers.json', ['mx.unresolvable']]);
    assert.deepEqual(r.warnings, [
      '--waivers waivers.json: entry 2 left out: it expires more than 366 days ahead (its item counts)',
      '--waivers waivers.json: entry 3 left out: its kind is not finding, rule or cert (its item counts)'
    ]);
    assert.equal(entryProblem({ code: 'reason' }), 'it has no reason, or one longer than 200 characters');
  });
});

describe('health over four nights', () => {
  test('accepted: left out of the score and counted for nothing; its end date over: WAIVER-EXPIRED counts (exit 4), said once', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'health.json');
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([waiver()]));
      const argv = ['health', 'example.com', '--waivers', w, '--json', json, '--baseline', json, '--fail-on-change'];
      const fetchImpl = createFakeFetch(zoneTable());
      const first = await runMain(argv, { fetchImpl, now: NIGHT(9) });
      assert.equal(first.code, EXIT.OK, first.err);
      const x = JSON.parse(readFileSync(json, 'utf8')).targets[0];
      const mx = x.checks.find((c) => c.id === 'mx.unresolvable');
      assert.deepEqual(mx.waiver, { id: mx.waiver.id, reason: 'Old MX host goes in November', owner: 'Mail team', expires: '2026-10-20' });
      assert.deepEqual([x.waived.count, x.waived.until, x.waived.scoreWith < x.score], [1, '2026-10-20', true]);
      assert.match(first.out, /- 1 accepted risk excluded \(until 2026-10-20\)\n/);
      assert.match(first.out, /\nAccepted risks · waivers\.json\n- 1 of 1 waiver is for health: 1 item accepted \(not counted\), 1 ending within 14 days, 0 expired \(counting again\)\n- Ending within 14 days:\n- example\.com: mx\.unresolvable — MX host does not resolve until 2026-10-20 \(ends in 12 days\) — Mail team: Old MX host goes in November\n/);
      assert.ok(!/Error: MX host does not resolve/.test(first.out), 'the accepted error is not among the problems');

      const second = await runMain(argv, { fetchImpl, now: NIGHT(10) });
      assert.equal(second.code, EXIT.OK, second.out);
      assert.match(second.out, /Changes since the baseline \(health\.json, run of .*\): none/);

      // the night after its last day: it counts again
      const third = await runMain(argv, { fetchImpl, now: NIGHT(21) });
      assert.equal(third.code, EXIT.CHANGED, third.out);
      const doc3 = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(tags(doc3.changes), ['WAIVER-EXPIRED example.com mx.unresolvable', 'SCORE? example.com']);
      assert.equal(doc3.changes[0].text, 'example.com: mx.unresolvable — its accepted risk ended (expired 2026-10-20): it counts again: error — MX host does not resolve');
      assert.equal(doc3.changes[0].tone, 'bad');
      assert.match(doc3.changes[1].text, /\(the accepted risks changed\)$/);
      assert.deepEqual(doc3.targets[0].checks.find((c) => c.id === 'mx.unresolvable').waiverExpired.expires, '2026-10-20');
      assert.match(third.out, /\n {2}WAIVER-EXPIRED {2}example\.com: mx\.unresolvable — its accepted risk ended/, 'the tag column widens for it');
      assert.match(third.out, /\n {2}SCORE {11}example\.com:/);
      assert.match(third.out, /- Expired, counting again:\n- example\.com: mx\.unresolvable — MX host does not resolve — expired 2026-10-20 — Mail team: Old MX host goes in November\n/);

      const fourth = await runMain(argv, { fetchImpl, now: NIGHT(22) });
      assert.equal(fourth.code, EXIT.OK, 'said once');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a risk accepted after a run without waivers: WAIVED and the score listed only (exit 0); a waiver that matches nothing is said', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'health.json');
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([waiver({ expires: '2026-12-31' }), waiver({ ref: 'caa.missing', expires: '2026-12-31' }), waiver({ domain: 'example.org', ref: 'spf.ptr', expires: '2026-12-31' })]));
      const fetchImpl = createFakeFetch(zoneTable());
      const base = ['health', 'example.com', '--json', json, '--baseline', json, '--fail-on-change'];
      assert.equal((await runMain(base, { fetchImpl, now: NIGHT(9) })).code, EXIT.OK);
      const second = await runMain([...base, '--waivers', w], { fetchImpl, now: NIGHT(10) });
      assert.equal(second.code, EXIT.OK, second.out);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(tags(doc.changes), ['SCORE? example.com', 'WAIVED? example.com mx.unresolvable']);
      assert.equal(doc.changes[1].text, 'example.com: mx.unresolvable — error accepted until 2026-12-31: Old MX host goes in November — MX host does not resolve');
      assert.match(second.out, /Not counted: 2 \(.*, accepted risks \(--waivers\)\)/);
      assert.match(second.out, /The waivers file differs from the baseline's \(none → waivers\.json\)/);
      // caa.missing is a note (no waiver needed there); example.org was not checked
      assert.match(second.out, /- Matched nothing this run \(fixed, or no longer reported: the waiver can go\):\n- example\.com: caa\.missing until 2026-12-31\n/);
      assert.ok(!/example\.org: spf\.ptr/.test(second.out), 'a domain not checked this run is not said');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a night its lookup fails: the accepted finding was not checked, so its waiver is kept, never "can go"; read again, accepted again', async () => {
    const dir = tmp();
    try {
      const json = join(dir, 'health.json');
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([waiver()]));
      const argv = ['health', 'example.com', '--waivers', w, '--json', json, '--baseline', json, '--fail-on-change'];
      assert.equal((await runMain(argv, { fetchImpl: createFakeFetch(zoneTable()), now: NIGHT(9) })).code, EXIT.OK);
      const down = await runMain(argv, { fetchImpl: createFakeFetch(zoneTable(), { rcodes: { 'example.com|MX': 'SERVFAIL' } }), now: NIGHT(10) });
      const gone = JSON.parse(readFileSync(json, 'utf8')).changes.find((c) => c.item === 'mx.unresolvable');
      assert.deepEqual([gone.tag, gone.counts, gone.text], ['GONE', false,
        'example.com: error mx.unresolvable no longer reported — MX host does not resolve (its lookup failed this run: it may still be there)']);
      assert.match(down.out, /\nAccepted risks · waivers\.json\n- 1 of 1 waiver is for health: 0 items accepted \(not counted\), 0 ending within 14 days, 0 expired \(counting again\), 1 not checked this run \(kept\)\n- Not checked this run \(kept: its item could not be read\):\n- example\.com: mx\.unresolvable until 2026-10-20\n/);
      assert.ok(!/Matched nothing/.test(down.out), down.out);
      const back = await runMain(argv, { fetchImpl: createFakeFetch(zoneTable()), now: NIGHT(11) });
      assert.match(back.out, /- 1 of 1 waiver is for health: 1 item accepted \(not counted\), 1 ending within 14 days, 0 expired \(counting again\)\n/);
      assert.ok(!/Matched nothing|Not checked this run/.test(back.out), back.out);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('audit: exit 4 and the status "waived"', () => {
  test('a failed rule a waiver accepts fails nothing (exit 0); its end date over: WAIVER-EXPIRED and exit 4', async () => {
    const dir = tmp();
    try {
      const zone = portfolioZone({ now: NIGHT(9).getTime() });
      const policy = join(dir, 'policy.json');
      writeFileSync(policy, '{ "expiryDays": ">= 30" }');
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([waiver({ kind: 'rule', domain: 'example.org', ref: 'expiryDays', reason: 'Renewed by the reseller', owner: 'Ops', expires: '2026-10-15' })]));
      const json = join(dir, 'audit.json');
      const plain = ['audit', '--policy', policy, 'example.org', '--no-dkim'];
      assert.equal((await runMain(plain, { fetchImpl: createPortfolioFetch(zone), now: NIGHT(9) })).code, EXIT.CHANGED, 'example.org expires in 20 days: exit 4');
      const argv = [...plain, '--waivers', w, '--json', json, '--baseline', json, '--fail-on-change'];
      const first = await runMain(argv, { fetchImpl: createPortfolioFetch(zone), now: NIGHT(9) });
      assert.equal(first.code, EXIT.OK, first.out + first.err);
      const rule = JSON.parse(readFileSync(json, 'utf8')).targets[0].rules[0];
      assert.deepEqual([rule.status, rule.was, rule.waiver.expires, rule.waiver.owner], ['waived', 'fail', '2026-10-15', 'Ops']);
      assert.match(first.out, /- 1 domain, 1 rule: 0 fail the policy, 0 could not be checked in full, 1 meets every rule \(1 failed rule accepted by a waiver, not counted\)\n/);
      assert.match(first.out, /- example\.org: expiryDays >= 30 until 2026-10-15 \(ends in 7 days\) — Ops: Renewed by the reseller\n/);

      const second = await runMain(argv, { fetchImpl: createPortfolioFetch(zone), now: NIGHT(16) });
      assert.equal(second.code, EXIT.CHANGED, second.out);
      const doc = JSON.parse(readFileSync(json, 'utf8'));
      assert.deepEqual(tags(doc.changes), ['WAIVER-EXPIRED example.org expiryDays']);
      assert.match(doc.changes[0].text, /^example\.org: expiryDays >= 30: its accepted risk ended \(expired 2026-10-15\): it counts again — \d+ days left/);
      assert.deepEqual(doc.targets[0].rules[0].waiverExpired, { id: doc.targets[0].rules[0].waiverExpired.id, expires: '2026-10-15' });
      assert.match(second.out, /FAIL expiryDays >= 30: .* — its waiver expired on 2026-10-15: it counts again/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('RDAP down: the accepted rules were not checked, so their waivers are kept, never "can go"; the night they end while it is still down, the rules count again (exit 4) and the summary says so', async () => {
    const dir = tmp();
    try {
      const zone = portfolioZone({ now: NIGHT(9).getTime() });
      const policy = join(dir, 'policy.json');
      writeFileSync(policy, '{ "expiryDays": ">= 30", "transferLock": true }');
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([
        waiver({ kind: 'rule', domain: 'example.org', ref: 'expiryDays', reason: 'Renewed by the reseller', owner: 'Ops', expires: '2026-10-15' }),
        waiver({ kind: 'rule', domain: 'example.org', ref: 'transferLock', reason: 'Moving registrars', owner: 'Ops', expires: '2026-10-15' })
      ]));
      const json = join(dir, 'audit.json');
      const argv = ['audit', '--policy', policy, 'example.org', '--no-dkim', '--waivers', w, '--json', json, '--baseline', json, '--fail-on-change'];
      const first = await runMain(argv, { fetchImpl: createPortfolioFetch(zone), now: NIGHT(9) });
      assert.equal(first.code, EXIT.OK, first.out + first.err);
      const rdapDown = () => createPortfolioFetch(zone, { rdapStatus: { 'example.org': 503 } });
      const down = await runMain(argv, { fetchImpl: rdapDown(), now: NIGHT(10) });
      assert.equal(down.code, EXIT.OK, down.out + down.err);
      assert.match(down.out, /- 2 of 2 waivers are for audit: 0 items accepted \(not counted\), 0 ending within 14 days, 0 expired \(counting again\), 2 not checked this run \(kept\)\n- Not checked this run \(kept: its item could not be read\):\n- example\.org: expiryDays until 2026-10-15\n- example\.org: transferLock until 2026-10-15\n/);
      assert.ok(!/Matched nothing/.test(down.out), down.out);
      // their end date passes while RDAP is still down: the rules' last status, a fail, counts again
      const ended = await runMain(argv, { fetchImpl: rdapDown(), now: NIGHT(16) });
      assert.equal(ended.code, EXIT.CHANGED, ended.out);
      assert.match(ended.out, /- 2 of 2 waivers are for audit: 0 items accepted \(not counted\), 0 ending within 14 days, 2 expired \(counting again\)\n- Expired, counting again:\n- example\.org: expiryDays >= 30 — expired 2026-10-15 — Ops: Renewed by the reseller\n- example\.org: transferLock true — expired 2026-10-15 — Ops: Moving registrars\n/);
      const rules = JSON.parse(readFileSync(json, 'utf8')).targets[0].rules;
      assert.deepEqual(rules.map((r) => [r.id, r.status, r.last && r.last.status, r.waiverExpired && r.waiverExpired.expires]),
        [['expiryDays', 'unknown', 'fail', '2026-10-15'], ['transferLock', 'unknown', 'fail', '2026-10-15']]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('diffs: newly accepted is WAIVED (listed only), accepted then passing is BETTER (listed only), accepted then not known is FAILED (listed only)', () => {
    const rule = (status, extra = {}) => ({ id: 'expiryDays', status, required: '>= 30', evidence: '9 days left', key: 'pol.ev.daysLeft', params: { count: 9, date: '2026-10-18' }, ...extra });
    const run = (b, a) => diffReports('audit', report('audit', [{ target: 'example.org', rules: [b] }]), report('audit', [{ target: 'example.org', rules: [a] }]), { t });
    const accepted = rule('waived', { was: 'fail', waiver: { id: 'w-1', reason: 'Renewal pending', owner: 'Ops', expires: '2026-12-31' } });
    const waived = run(rule('fail'), accepted);
    assert.deepEqual(tags(waived), ['WAIVED? example.org expiryDays']);
    assert.match(changeText(waived[0]), /fail → accepted until 2026-12-31: Renewal pending — 9 days left/);
    assert.deepEqual(tags(run(accepted, rule('pass'))), ['BETTER? example.org expiryDays']);
    assert.deepEqual(tags(run(accepted, rule('unknown'))), ['FAILED? example.org expiryDays']);
    assert.deepEqual(tags(run(accepted, accepted)), []);
    const ended = run(accepted, rule('fail'));
    assert.deepEqual(tags(ended), ['WAIVER-EXPIRED example.org expiryDays']);
    assert.match(changeText(ended[0]), /no longer an accepted risk \(not in the waivers file\): it counts again/);
  });
});

describe('ct: a night a source is down', () => {
  test('a known certificate the read did not list: "can go" after a complete read, kept after one with crt.sh down', async () => {
    const dir = tmp();
    try {
      const KEY = 'c3'.repeat(32);
      let crtshDown = false;
      const fetchImpl = async (url) => {
        const u = String(url);
        if (u.startsWith('https://crt.sh/')) return crtshDown ? new Response('busy', { status: 503, headers: { 'retry-after': '0' } }) : Response.json([]);
        if (u.startsWith('https://api.certspotter.com/')) return Response.json([]);
        return new Response('', { status: 404 });
      };
      const w = join(dir, 'waivers.json');
      writeFileSync(w, file([waiver({ kind: 'cert', ref: KEY, reason: 'Our CDN', owner: 'Web', expires: '2026-12-31' })]));
      const argv = ['ct', 'example.com', '--waivers', w];
      const complete = await runMain(argv, { fetchImpl, now: NIGHT(9) });
      assert.equal(complete.code, EXIT.OK, complete.err);
      assert.match(complete.out, new RegExp(`- Matched nothing this run \\(fixed, or no longer reported: the waiver can go\\):\\n- example\\.com: ${KEY} until 2026-12-31\\n`));
      crtshDown = true;
      const partial = await runMain(argv, { fetchImpl, now: NIGHT(10) });
      assert.match(partial.out, new RegExp(`, 1 not checked this run \\(kept\\)\\n- Not checked this run \\(kept: its item could not be read\\):\\n- example\\.com: ${KEY} until 2026-12-31\\n`));
      assert.ok(!/Matched nothing/.test(partial.out), partial.out);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('health and ct diffs', () => {
  const check = (id, severity, extra = {}) => ({ id, severity, titleKey: `health.${id}.title`, params: {}, ...extra });
  const W = { id: 'w-1', reason: 'Q1', owner: '', expires: '2026-12-31' };

  test('an accepted finding\'s moves are listed only; one gone says its waiver can go', () => {
    const b = report('health', [{ target: 'example.com', score: 80, checks: [check('spf.ptr', 'warn', { waiver: W }), check('dkim.none', 'warn', { waiver: W })] }]);
    const a = report('health', [{ target: 'example.com', score: 80, checks: [check('spf.ptr', 'error', { waiver: W }), check('dmarc.missing', 'warn', { waiver: W })] }]);
    const changes = diffReports('health', b, a, { t });
    assert.deepEqual(tags(changes), ['WORSE? example.com spf.ptr', 'NEW? example.com dmarc.missing', 'GONE? example.com dkim.none']);
    assert.match(changeText(changes[0]), /\(accepted until 2026-12-31: not counted\)$/);
    assert.match(changeText(changes[2]), /\(it was an accepted risk: its waiver can go\)$/);
    assert.ok(changes.every((c) => c.accepted));
    // its lookup failed this run: out of sight, not fixed, so its waiver stays
    const hidden = diffReports('health', report('health', [{ target: 'example.com', score: 80, checks: [check('mx.unresolvable', 'error', { waiver: W })] }]),
      report('health', [{ target: 'example.com', score: 80, checks: [check('mx.error', 'warn')] }]), { t }).find((c) => c.item === 'mx.unresolvable');
    assert.match(changeText(hidden), /^example\.com: error mx\.unresolvable no longer reported — .+ \(its lookup failed this run: it may still be there\)$/);
  });

  test('a known certificate in the baseline run that is not any more, from an unexpected CA: WAIVER-EXPIRED; a new issuer whose certificates are all known is listed only', () => {
    const cert = (extra = {}) => ({ id: 'aaaaaaaaaaaaaaaa', ca: 'Other CA', intermediate: 'Other CA 1', names: ['cdn.example.com'], sources: ['certspotter'], notBefore: '2026-09-01T00:00:00.000Z',
      notAfter: '2026-12-01T00:00:00.000Z', current: true, unexpected: false, ...extra });
    const target = (certs, issuers) => ({ target: 'example.com', names: ['cdn.example.com'], issuers, readAt: '2026-10-08T03:00:00.000Z', answered: true, complete: true, sources: [{ source: 'certspotter', ok: true, state: 'ok' }], certificates: certs });
    const b = report('ct', [target([cert({ known: W })], [{ name: 'Other CA', count: 1 }])]);
    const a = report('ct', [target([cert({ unexpected: true, knownExpired: { ...W, expires: '2026-10-01' } })], [{ name: 'Other CA', count: 1 }])]);
    const changes = diffReports('ct', b, a, { t });
    assert.deepEqual(tags(changes), ['WAIVER-EXPIRED example.com aaaaaaaaaaaaaaaa']);
    assert.match(changeText(changes[0]), /no longer a known certificate \(its waiver expired 2026-10-01\): it counts again: cdn\.example\.com$/);
    const fresh = diffReports('ct', report('ct', [target([], [])]), report('ct', [target([cert({ known: W })], [{ name: 'Other CA', count: 1 }])]), { t });
    assert.deepEqual(tags(fresh).filter((x) => x.startsWith('ISSUER')), ['ISSUER? example.com Other CA']);
  });

  test('watchTarget: a known certificate carries its waiver, is neither new nor unexpected; the counts say how many', () => {
    const KEY = '7f'.repeat(32);
    const target = {
      target: 'example.com', readAt: NIGHT(9).toISOString(), answered: true,
      certificates: [{ id: 'bbbbbbbbbbbbbbbb', ca: 'Other CA', issuer: 'C=US, O=Other CA, CN=Other CA 1', intermediate: 'Other CA 1', names: ['cdn.example.com'], spkiSha256: KEY,
        notBefore: '2026-10-01T00:00:00.000Z', notAfter: '2026-12-30T00:00:00.000Z' }]
    };
    const prev = { target: 'example.com', seen: { at: '2026-09-01T00:00:00.000Z', ids: {} }, certificates: [] };
    const known = [{ id: 'w-k', kind: 'cert', domain: 'example.com', ref: KEY, reason: 'Our CDN', owner: 'Web', created: null, expires: '2026-12-31' }];
    const w = watchTarget(target, { prev, now: NIGHT(9), radar: [30, 14, 7], expected: ['letsencrypt.org'], known });
    const c = w.certificates[0];
    assert.deepEqual([c.isNew, c.unexpected, c.flags, c.known], [false, false, ['known'], { id: 'w-k', reason: 'Our CDN', owner: 'Web', expires: '2026-12-31' }]);
    assert.equal(w.watch.counts.known, 1);
    const without = watchTarget(target, { prev, now: NIGHT(9), radar: [30, 14, 7], expected: ['letsencrypt.org'] }).certificates[0];
    assert.deepEqual([without.isNew, without.unexpected, without.known], [true, true, undefined]);
  });

  test('the notes: a waivers file that differs from the baseline\'s', () => {
    assert.deepEqual(baselineNotes('health', { options: {} }, { options: { waivers: 'waivers.json' } }), ['The waivers file differs from the baseline\'s (none → waivers.json): items can be accepted or count again because of that.']);
    assert.deepEqual(baselineNotes('health', { options: { waivers: 'waivers.json' } }, { options: { waivers: 'waivers.json' } }), []);
    assert.deepEqual(baselineNotes('subdomains', { options: {} }, { options: { waivers: 'w.json' } }), []);
  });
});

describe('the summary, the tag column and PagerDuty', () => {
  test('the waivers summary: accepted, ending soon, expired, matched nothing — values as code parts', () => {
    const now = NIGHT(9);
    const doc = waiversDoc('health', { file: 'waivers.json', list: [
      { id: 'w-a', kind: 'finding', domain: 'example.com', ref: 'spf.ptr', reason: 'r <b>', owner: '@team', expires: '2026-12-31' },
      { id: 'w-b', kind: 'finding', domain: 'example.com', ref: 'caa.missing', reason: 'x', owner: '', expires: '2026-12-31' },
      { id: 'w-c', kind: 'rule', domain: 'example.com', ref: 'transferLock', reason: 'x', owner: '', expires: '2026-12-31' }
    ] }, {
      checked: ['example.com'],
      applied: [{ target: 'example.com', what: [{ code: 'spf.ptr' }], waiver: { id: 'w-a', reason: 'r <b>', owner: '@team', expires: '2026-12-31' } }],
      expired: []
    }, { t, now });
    const text = renderPlainText(doc);
    assert.match(text, /^Accepted risks · waivers\.json\n- 2 of 3 waivers are for health: 1 item accepted \(not counted\), 0 ending within 14 days, 0 expired \(counting again\)\n- Accepted:\n- example\.com: spf\.ptr until 2026-12-31 — @team: r <b>\n- Matched nothing this run/);
    assert.ok(!text.includes('transferLock'), 'a rule\'s waiver is not health\'s');
  });

  test('the waivers summary: a waiver whose item could not be read this run is kept, apart from those that matched nothing', () => {
    const doc = waiversDoc('health', { file: 'waivers.json', list: [
      { id: 'w-a', kind: 'finding', domain: 'example.com', ref: 'mx.unresolvable', reason: 'x', owner: '', expires: '2026-12-31' },
      { id: 'w-b', kind: 'finding', domain: 'example.com', ref: 'caa.missing', reason: 'x', owner: '', expires: '2026-12-31' }
    ] }, { checked: ['example.com'], applied: [], expired: [], unread: (w) => w.ref.startsWith('mx.') }, { t, now: NIGHT(9) });
    assert.match(renderPlainText(doc), /, 1 not checked this run \(kept\)\n- Not checked this run \(kept: its item could not be read\):\n- example\.com: mx\.unresolvable until 2026-12-31\n- Matched nothing this run \(fixed, or no longer reported: the waiver can go\):\n- example\.com: caa\.missing until 2026-12-31\n/);
  });

  test('the tag column: 9 wide, wider only in a summary that shows WAIVER-EXPIRED; the note names the accepted risks only when one is listed', () => {
    assert.equal(TAG_WIDTH, 9);
    const base = { command: 'health', baseline: { file: 'h.json' } };
    const plain = renderChangesText({ ...base, changes: [{ tag: 'SCORE', tone: 'bad', counts: true, parts: ['x'] }] }, { paint: painter(false) });
    assert.equal(plain[1], '  SCORE      x');
    const wide = renderChangesText({ ...base, changes: [{ tag: 'SCORE', tone: 'bad', counts: true, parts: ['x'] }, { tag: 'WAIVER-EXPIRED', tone: 'bad', counts: true, parts: ['y'] }] }, { paint: painter(false) });
    assert.deepEqual(wide.slice(1, 3), ['  SCORE           x', '  WAIVER-EXPIRED  y']);
    const quiet = { ...base, changes: [{ tag: 'WAIVED', tone: 'quiet', counts: false, accepted: true, parts: ['z'] }] };
    assert.ok(renderChangesText(quiet, { paint: painter(false) }).some((l) => /Not counted: 1 \(.*, accepted risks \(--waivers\)\)/.test(l)));
    assert.match(renderChangesMarkdown(quiet), /listed only \(.*, accepted risks \(--waivers\)\)/);
    assert.ok(!renderChangesText({ ...base, changes: [{ tag: 'GONE', tone: 'quiet', counts: false, parts: ['z'] }] }, { paint: painter(false) }).join('\n').includes('--waivers'));
  });

  test('PagerDuty: a problem a waiver accepts is over while it does', () => {
    const health = { target: 'example.com', checks: [{ id: 'spf.ptr', severity: 'warn', waiver: { id: 'w', expires: '2026-12-31' } }, { id: 'dkim.none', severity: 'warn' }] };
    assert.equal(problemStanding('health', health, { item: 'spf.ptr', tag: 'NEW', state: 'warn' }), 'over');
    assert.equal(problemStanding('health', health, { item: 'dkim.none', tag: 'NEW', state: 'warn' }), 'bad');
    const audit = { target: 'example.org', rules: [{ id: 'expiryDays', status: 'waived', was: 'fail' }, { id: 'transferLock', status: 'fail' }] };
    assert.equal(problemStanding('audit', audit, { item: 'expiryDays', tag: 'WORSE' }), 'over');
    assert.equal(problemStanding('audit', audit, { item: null, tag: 'NEW' }), 'bad', 'another rule still fails');
    const ct = { target: 'example.com', issuers: [{ name: 'Other CA' }], certificates: [{ id: 'c1', ca: 'Other CA', flags: ['known'], known: { id: 'w', expires: '2026-12-31' } }] };
    assert.equal(problemStanding('ct', ct, { item: 'c1', tag: 'CA' }), 'over');
    assert.equal(problemStanding('ct', ct, { item: 'Other CA', tag: 'ISSUER' }), 'over');
    assert.equal(problemStanding('ct', ct, { item: 'c1', tag: 'REVOKED' }), 'bad', 'a revoked known certificate is still revoked');
  });
});
