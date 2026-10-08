/**
 * Embedded SCTs and the CT policies (lib/sct.js): the SignedCertificateTimestampList inside the
 * certificate (crafted bytes and the fixtures of tests/fixtures/gen_sct_fixtures.mjs, whose test
 * logs signed real SCTs), Google's CT log list v3 in its compact form, its loader (the live list,
 * then the bundled copy), the Chrome and Apple verdicts, and the bundled snapshot as
 * tools/build-ctlogs.mjs writes it. No network: fetch is a fake; `now` is injected.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  CT_LOG_LIST_URL, CT_REASONS, CT_VERDICTS, LOG_STATES, SCT_LIST_STATUSES, SCT_PROBLEMS, SCT_STATUSES, BUNDLED_LOG_LIST_URL,
  certificateScts, compactLogList, decodeSctList, evaluateCtPolicies, findSctExtension, indexLogs, loadCtLogList
} from '../../assets/js/lib/sct.js';
import { buildSnapshot, serializeSnapshot } from '../../tools/build-ctlogs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIX = join(ROOT, 'tests', 'fixtures', 'sct');
const certOf = (file) => parseCertificates(readFileSync(join(FIX, file))).certificates[0];
const V3 = JSON.parse(readFileSync(join(FIX, 'log_list.json'), 'utf8'));
const LIST = compactLogList(V3);
const LOGS = indexLogs(LIST);
const NOW = Date.parse('2026-10-01T00:00:00Z');
const idOf = (name) => [...LOGS.values()].find((l) => l.name.includes(name)).id;

/** A serialized v1 SCT. */
function sctBytes({ version = 0, logId = new Uint8Array(32).fill(7), ms = Date.parse('2026-09-01T00:00:05Z'), ext = [], hash = 4, sig = 3, signature = [0x30, 0x02, 0x01, 0x01] } = {}) {
  const ts = [];
  for (let i = 7, v = ms; i >= 0; i--, v = Math.floor(v / 256)) ts[i] = v % 256;
  return [version, ...logId, ...ts, ext.length >> 8, ext.length & 0xff, ...ext, hash, sig, signature.length >> 8, signature.length & 0xff, ...signature];
}
const listOf = (...scts) => {
  const body = scts.flatMap((s) => [s.length >> 8, s.length & 0xff, ...s]);
  return new Uint8Array([body.length >> 8, body.length & 0xff, ...body]);
};
const b64 = (bytes) => Buffer.from(bytes).toString('base64');

describe('decodeSctList', () => {
  test('reads each field of a v1 SCT', () => {
    const logId = Uint8Array.from({ length: 32 }, (_, i) => i);
    const { scts, error } = decodeSctList(listOf(sctBytes({ logId, ext: [0, 0, 5, 0, 0, 0, 0x12, 0x34] })));
    assert.equal(error, null);
    assert.equal(scts.length, 1);
    const [s] = scts;
    assert.equal(s.version, 0);
    assert.equal(s.logId, b64(logId));
    assert.equal(s.logIdHex, Buffer.from(logId).toString('hex'));
    assert.equal(s.timestamp, Date.parse('2026-09-01T00:00:05Z'));
    assert.equal(s.extensions, '0000050000001234');
    assert.deepEqual([s.hashName, s.signatureName, s.algorithmAllowed], ['SHA-256', 'ECDSA', true]);
    assert.equal(s.signatureLength, 4);
    assert.equal(s.signature, b64([0x30, 0x02, 0x01, 0x01]));
    assert.equal(s.problem, null);
  });

  test('names RSA and unknown algorithms, and flags what RFC 6962 does not allow', () => {
    const { scts } = decodeSctList(listOf(sctBytes({ hash: 4, sig: 1 }), sctBytes({ hash: 2, sig: 3 }), sctBytes({ hash: 9, sig: 42 })));
    assert.deepEqual(scts.map((s) => [s.hashName, s.signatureName, s.algorithmAllowed]), [
      ['SHA-256', 'RSA', true], ['SHA-1', 'ECDSA', false], [null, null, false]
    ]);
    assert.deepEqual(scts.map((s) => [s.hashAlgorithm, s.signatureAlgorithm]), [[4, 1], [2, 3], [9, 42]]);
  });

  test('another version is kept with its version byte only', () => {
    const { scts, error } = decodeSctList(listOf([1, 9, 9, 9], sctBytes()));
    assert.equal(error, null);
    assert.deepEqual([scts[0].version, scts[0].problem, scts[0].logId], [1, 'unknown-version', null]);
    assert.equal(scts[1].problem, null);
  });

  test('a truncated SCT, a truncated list, trailing data and an empty list are codes', () => {
    const good = sctBytes();
    assert.equal(decodeSctList(listOf(good.slice(0, 40))).scts[0].problem, 'truncated');
    assert.equal(decodeSctList(listOf([...good, 0])).scts[0].problem, 'trailing-data');
    const list = listOf(good);
    assert.equal(decodeSctList(list.subarray(0, list.length - 3)).error, 'truncated');
    assert.equal(decodeSctList(new Uint8Array([...list, 0])).error, 'trailing-data');
    assert.deepEqual(decodeSctList(new Uint8Array([0, 0])), { scts: [], error: 'empty' });
    assert.deepEqual(decodeSctList(new Uint8Array([1])), { scts: [], error: 'truncated' });
    assert.deepEqual(decodeSctList(null), { scts: [], error: 'truncated' });
    for (const s of [decodeSctList(list.subarray(0, 9)), decodeSctList(new Uint8Array([0, 5, 0, 9, 1]))]) assert.equal(s.error, 'truncated');
  });

  test('a timestamp beyond what a date can hold is flagged', () => {
    const { scts } = decodeSctList(listOf(sctBytes({ ms: 2 ** 53 })));
    assert.equal(scts[0].problem, 'bad-timestamp');
  });
});

describe('certificateScts (the fixtures)', () => {
  test('finds the list and agrees with the x509 parser on log IDs and times', () => {
    for (const file of ['sct_compliant.pem', 'sct_long_ok.pem', 'sct_unknown.pem']) {
      const cert = certOf(file);
      const got = certificateScts(cert);
      assert.equal(got.status, 'embedded', file);
      assert.equal(got.error, null, file);
      assert.equal(got.critical, false);
      assert.deepEqual(got.scts.map((s) => [s.logId, s.timestamp]), cert.scts.map((s) => [s.logId, s.timestamp.getTime()]), file);
      for (const s of got.scts) {
        assert.deepEqual([s.version, s.hashName, s.signatureName, s.problem], [0, 'SHA-256', 'ECDSA', null]);
        assert.ok(s.signatureLength >= 68 && s.signatureLength <= 72, `DER ECDSA signature: ${s.signatureLength}`);
      }
    }
  });

  test('a static-ct-api log\'s SCT carries its leaf_index extension; an RFC 6962 log\'s none', () => {
    const [alpha, charlie] = certificateScts(certOf('sct_compliant.pem')).scts;
    assert.equal(alpha.logId, idOf('Alpha'));
    assert.equal(alpha.extensions, '');
    assert.equal(charlie.logId, idOf('Charlie'));
    assert.match(charlie.extensions, /^000005[0-9a-f]{10}$/);
  });

  test('a precertificate, a certificate without the extension and bytes that are no certificate', () => {
    assert.deepEqual(certificateScts(certOf('sct_precert.pem')), { status: 'precertificate', scts: [], error: null, critical: false });
    assert.deepEqual(certificateScts(certOf('sct_ca.pem')), { status: 'none', scts: [], error: null, critical: false });
    assert.equal(certificateScts({ der: new Uint8Array([1, 2, 3]) }).status, 'malformed');
    assert.equal(certificateScts(null).status, 'malformed');
    assert.equal(findSctExtension(certOf('sct_ca.pem').der).found, false);
  });

  test('an extension whose value is not an OCTET STRING is malformed', () => {
    const der = Buffer.from(certOf('sct_compliant.pem').der);
    const oid = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);
    const at = der.indexOf(oid) + oid.length;
    // extnValue (04 len) wraps the inner OCTET STRING: turn the inner tag into a BIT STRING.
    const inner = at + 2 + (der[at + 1] & 0x80 ? der[at + 1] & 0x7f : 0);
    assert.equal(der[inner], 0x04);
    der[inner] = 0x03;
    const got = certificateScts({ der: new Uint8Array(der) });
    assert.deepEqual([got.status, got.error], ['malformed', 'not-der']);
  });
});

describe('the log list', () => {
  test('compactLogList keeps per operator the RFC 6962 and the static-ct-api logs', () => {
    assert.equal(LIST.timestamp, '2026-09-30T12:00:00Z');
    assert.deepEqual(LIST.operators.map((o) => [o.name, o.logs.length]), [
      ['Example Log Operator A', 2], ['Example Log Operator B', 2], ['Example Log Operator C', 2]
    ]);
    const charlie = LOGS.get(idOf('Charlie'));
    assert.deepEqual([charlie.api, charlie.url, charlie.state, charlie.operator], ['static', 'https://charlie2026h2.ct.example.net/', 'usable', 'Example Log Operator B']);
    const bravo = LOGS.get(idOf('Bravo'));
    assert.deepEqual([bravo.api, bravo.state, bravo.since, bravo.start, bravo.end], ['rfc6962', 'retired', '2026-09-15T00:00:00Z', '2026-07-01T00:00:00Z', '2028-01-01T00:00:00Z']);
    assert.ok(bravo.key.startsWith('MFkw'));
    assert.equal(LOGS.size, 6);
  });

  test('a compact list passes through unchanged; what is not a list is null', () => {
    assert.deepEqual(compactLogList(JSON.parse(JSON.stringify(LIST))), LIST);
    for (const bad of [null, 'x', {}, { operators: [] }, { operators: [{ name: 'X', logs: [{ log_id: 'not base64!' }] }] }, { operators: [{ name: 'X', logs: [{ log_id: b64([1, 2]) }] }] }]) {
      assert.equal(compactLogList(bad), null, JSON.stringify(bad));
    }
  });

  test('a log without a known state is pending, and a bad date is null', () => {
    const list = compactLogList({ operators: [{ name: 'X', logs: [{ log_id: b64(new Uint8Array(32)), description: 'd', state: { weird: {} }, temporal_interval: { start_inclusive: 'soon' } }] }] });
    assert.deepEqual([list.operators[0].logs[0].state, list.operators[0].logs[0].since, list.operators[0].logs[0].start], ['pending', null, null]);
  });
});

describe('loadCtLogList', () => {
  const BUNDLED = 'https://example.com/data/ctlogs.json';
  const fakeFetch = (routes, calls = []) => async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const r = routes[String(url)];
    if (!r) throw new TypeError('Failed to fetch');
    if (r instanceof Error) throw r;
    return new Response(typeof r.body === 'string' ? r.body : JSON.stringify(r.body), { status: r.status || 200, headers: { 'content-type': 'application/json' } });
  };

  test('the live list first, without credentials; it sends nothing else', async () => {
    const calls = [];
    const got = await loadCtLogList({ fetchImpl: fakeFetch({ [CT_LOG_LIST_URL]: { body: V3 } }, calls), bundledUrl: BUNDLED, now: () => NOW });
    assert.equal(got.source, 'live');
    assert.deepEqual(got.list, LIST);
    assert.equal(got.failure, null);
    assert.deepEqual(calls.map((c) => c.url), [CT_LOG_LIST_URL]);
    assert.equal(calls[0].init.credentials, 'omit');
    assert.ok(calls[0].init.signal, 'a signal covers the timeout');
  });

  test('a failing live list falls back to the bundled copy and says why', async () => {
    const cases = [
      [{ status: 503, body: 'down' }, { errorKind: 'http', status: 503 }],
      [{ body: '<html>' }, { errorKind: 'parse', status: null }],
      [{ body: { hello: 1 } }, { errorKind: 'parse', status: null }],
      [undefined, { errorKind: 'network', status: null }]
    ];
    for (const [live, want] of cases) {
      const routes = { [BUNDLED]: { body: LIST } };
      if (live) routes[CT_LOG_LIST_URL] = live;
      const got = await loadCtLogList({ fetchImpl: fakeFetch(routes), bundledUrl: BUNDLED, now: () => NOW });
      assert.equal(got.source, 'bundled', JSON.stringify(live));
      assert.deepEqual(got.list, LIST);
      assert.deepEqual([got.failure.source, got.failure.errorKind, got.failure.status, got.failure.at], ['ctloglist', want.errorKind, want.status, NOW], JSON.stringify(live));
    }
  });

  test('offline (live: false) reads only the bundled copy; both failing is source none', async () => {
    const calls = [];
    const got = await loadCtLogList({ live: false, fetchImpl: fakeFetch({ [BUNDLED]: { body: LIST } }, calls), bundledUrl: BUNDLED });
    assert.deepEqual([got.source, got.failure, calls.map((c) => c.url)], ['bundled', null, [BUNDLED]]);
    const none = await loadCtLogList({ fetchImpl: fakeFetch({}), bundledUrl: BUNDLED, now: () => NOW });
    assert.deepEqual([none.source, none.list, none.failure.errorKind, none.bundledFailure.source], ['none', null, 'network', 'self']);
    const junk = await loadCtLogList({ live: false, fetchImpl: fakeFetch({ [BUNDLED]: { body: [] } }), bundledUrl: BUNDLED });
    assert.deepEqual([junk.source, junk.bundledFailure.errorKind], ['none', 'parse']);
  });

  test('a timeout is a status; only an abort rejects', async () => {
    const slow = (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
    const got = await loadCtLogList({ fetchImpl: (url, init) => (String(url) === BUNDLED ? fakeFetch({ [BUNDLED]: { body: LIST } })(url, init) : slow(url, init)), bundledUrl: BUNDLED, timeoutMs: 20 });
    assert.deepEqual([got.source, got.failure.errorKind], ['bundled', 'timeout']);
    const ac = new AbortController();
    const pending = loadCtLogList({ fetchImpl: slow, bundledUrl: BUNDLED, signal: ac.signal });
    ac.abort();
    await assert.rejects(pending, (err) => err.name === 'AbortError');
  });

  test('the bundled URL is the site\'s own data file', () => {
    assert.ok(BUNDLED_LOG_LIST_URL.endsWith('/assets/data/ctlogs.json'), BUNDLED_LOG_LIST_URL);
  });
});

describe('evaluateCtPolicies', () => {
  const verdicts = (file, opts = {}) => {
    const cert = certOf(file);
    const r = evaluateCtPolicies(cert, certificateScts(cert), opts.logs === undefined ? LOGS : opts.logs, { now: NOW, ...opts });
    return { r, chrome: [r.policies.chrome.verdict, ...r.policies.chrome.reasons], apple: [r.policies.apple.verdict, ...r.policies.apple.reasons] };
  };

  test('the fixtures under both policies', () => {
    const table = {
      'sct_compliant.pem': [['compliant'], ['compliant']],
      'sct_one_operator.pem': [['not-compliant', 'one-operator'], ['not-compliant', 'one-operator']],
      'sct_long.pem': [['not-compliant', 'too-few-logs'], ['not-compliant', 'too-few-logs']],
      'sct_long_ok.pem': [['compliant'], ['compliant']],
      'sct_unknown.pem': [['not-compliant', 'too-few-logs', 'one-operator'], ['not-compliant', 'too-few-logs', 'one-operator']],
      'sct_static_only.pem': [['compliant'], ['not-compliant', 'no-rfc6962-log']],
      'sct_precert.pem': [['cannot-tell', 'precertificate'], ['cannot-tell', 'precertificate']],
      'sct_ca.pem': [['cannot-tell', 'no-scts'], ['cannot-tell', 'no-scts']]
    };
    for (const [file, [chrome, apple]] of Object.entries(table)) {
      const got = verdicts(file);
      assert.deepEqual(got.chrome, chrome, `${file} chrome`);
      assert.deepEqual(got.apple, apple, `${file} apple`);
    }
  });

  test('counts, lifetimes and how each SCT stands', () => {
    const { r } = verdicts('sct_long_ok.pem');
    assert.equal(r.lifetimeDays, 397);
    assert.deepEqual(r.standings.map((s) => s.status), ['current', 'current', 'current']);
    assert.deepEqual(r.policies.chrome, { verdict: 'compliant', reasons: [], required: 3, logs: 3, counted: 3, operators: 2, current: 3, perOperator: null, rfc6962: 2 });
    assert.deepEqual([r.policies.apple.required, r.policies.apple.perOperator, r.policies.apple.counted], [3, 2, 3]);
    const one = verdicts('sct_one_operator.pem').r;
    assert.deepEqual(one.standings.map((s) => [s.status, s.log.operator]), [['current', 'Example Log Operator A'], ['retired', 'Example Log Operator A']]);
    assert.deepEqual([one.policies.apple.required, one.policies.apple.perOperator, one.policies.apple.counted], [2, 1, 1]);
    const unknown = verdicts('sct_unknown.pem').r;
    assert.deepEqual(unknown.standings.map((s) => s.status), ['current', 'unknown-log', 'not-approved']);
    assert.equal(unknown.unknownLogs, 1);
    assert.equal(unknown.expired, false);
  });

  test('a log missing from the bundled copy makes "cannot tell"; from the live list "not compliant"', () => {
    assert.deepEqual(verdicts('sct_unknown.pem', { listSource: 'bundled' }).chrome, ['cannot-tell', 'unknown-logs-bundled', 'too-few-logs', 'one-operator']);
    assert.deepEqual(verdicts('sct_unknown.pem', { listSource: 'live' }).chrome[0], 'not-compliant');
    // Nothing unknown: the bundled copy's verdict stands.
    assert.deepEqual(verdicts('sct_long.pem', { listSource: 'bundled' }).chrome, ['not-compliant', 'too-few-logs']);
  });

  test('no list at all: cannot tell, and each SCT says so', () => {
    const got = verdicts('sct_compliant.pem', { logs: null });
    assert.deepEqual(got.chrome, ['cannot-tell', 'no-log-list']);
    assert.deepEqual(got.r.standings.map((s) => s.status), ['no-list', 'no-list']);
    assert.equal(got.r.listSource, 'none');
  });

  const synthetic = (days, scts, { now = NOW, error = null } = {}) => {
    const notBefore = new Date('2026-09-01T00:00:00Z');
    const cert = { notBefore, notAfter: new Date(notBefore.getTime() + days * 86400000) };
    const embedded = { status: 'embedded', error, critical: false, scts: scts.map(([log, at], index) => ({ index, version: 0, logId: idOf(log), timestamp: Date.parse(at), problem: null })) };
    return evaluateCtPolicies(cert, embedded, LOGS, { now });
  };
  const at = '2026-09-01T00:00:05Z';

  test('180 days needs two SCTs, a second more needs three (Chrome), and Apple stops at 398 days', () => {
    assert.equal(synthetic(180, [['Alpha', at], ['Charlie', at]]).policies.chrome.verdict, 'compliant');
    const longer = synthetic(180 + 1 / 86400, [['Alpha', at], ['Charlie', at]]);
    assert.deepEqual([longer.policies.chrome.required, longer.policies.chrome.verdict, longer.policies.apple.required], [3, 'not-compliant', 3]);
    const over = synthetic(399, [['Alpha', at], ['Charlie', at], ['Delta', at]]);
    assert.deepEqual([over.policies.chrome.verdict, over.policies.apple.verdict, over.policies.apple.required, ...over.policies.apple.reasons], ['compliant', 'not-compliant', null, 'lifetime-over-398']);
    assert.equal(synthetic(398, [['Alpha', at], ['Charlie', at], ['Delta', at]]).policies.apple.verdict, 'compliant');
  });

  test('a retired log counts only before its retirement; pending logs and future SCTs never', () => {
    const after = synthetic(90, [['Alpha', at], ['Bravo', '2026-09-20T00:00:00Z'], ['Charlie', at]]);
    assert.deepEqual(after.standings.map((s) => s.status), ['current', 'after-retirement', 'current']);
    assert.equal(after.policies.chrome.logs, 2);
    const future = synthetic(90, [['Alpha', at], ['Charlie', '2026-10-02T00:00:00Z']]);
    assert.deepEqual(future.standings.map((s) => s.status), ['current', 'future']);
    assert.deepEqual(future.policies.chrome.reasons, ['too-few-logs', 'one-operator']);
    const pendingOnly = synthetic(90, [['Echo', at], ['Bravo', at]]);
    assert.deepEqual(pendingOnly.policies.chrome.reasons, ['no-current-log', 'too-few-logs', 'one-operator']);
  });

  test('two SCTs of one log count once; a readonly log is currently approved', () => {
    const dup = synthetic(90, [['Alpha', at], ['Alpha', '2026-09-01T00:00:06Z']]);
    assert.deepEqual([dup.policies.chrome.logs, ...dup.policies.chrome.reasons], [1, 'too-few-logs', 'one-operator']);
    const ro = synthetic(90, [['Delta', at], ['Alpha', at]]);
    assert.deepEqual([ro.policies.chrome.verdict, ro.policies.chrome.current], ['compliant', 2]);
  });

  test('a list read only in part, or an unreadable SCT, is not compliant and nothing counts', () => {
    const partial = synthetic(90, [['Alpha', at], ['Charlie', at]], { error: 'truncated' });
    assert.deepEqual([partial.policies.chrome.verdict, ...partial.policies.chrome.reasons], ['not-compliant', 'malformed-list']);
    assert.deepEqual(partial.standings.map((s) => s.status), ['unreadable', 'unreadable']);
    const cert = { notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2026-11-30T00:00:00Z') };
    const embedded = { status: 'embedded', error: null, scts: [{ index: 0, version: 1, logId: null, timestamp: null, problem: 'unknown-version' }, { index: 1, version: 0, logId: idOf('Alpha'), timestamp: Date.parse(at), problem: null }] };
    const r = evaluateCtPolicies(cert, embedded, LOGS, { now: NOW });
    assert.deepEqual(r.standings.map((s) => s.status), ['unreadable', 'current']);
    assert.deepEqual(r.policies.chrome.reasons, ['too-few-logs', 'one-operator']);
    const malformed = evaluateCtPolicies(cert, { status: 'malformed', scts: [], error: 'not-der', critical: false }, LOGS, { now: NOW });
    assert.deepEqual([malformed.policies.apple.verdict, ...malformed.policies.apple.reasons], ['not-compliant', 'malformed-list']);
  });

  test('an expired certificate is flagged', () => {
    assert.equal(synthetic(10, [['Alpha', at], ['Charlie', at]]).expired, true);
  });
});

describe('codes and the bundled snapshot', () => {
  test('the code lists are frozen and cover what the functions return', () => {
    for (const list of [CT_REASONS, CT_VERDICTS, LOG_STATES, SCT_LIST_STATUSES, SCT_PROBLEMS, SCT_STATUSES]) assert.ok(Object.isFrozen(list));
    assert.deepEqual(CT_VERDICTS, ['compliant', 'not-compliant', 'cannot-tell']);
    assert.ok(SCT_PROBLEMS.includes('not-der'));
  });

  test('assets/data/ctlogs.json is what tools/build-ctlogs.mjs writes, and the page can read it', () => {
    const text = readFileSync(join(ROOT, 'assets', 'data', 'ctlogs.json'), 'utf8');
    const json = JSON.parse(text);
    assert.equal(serializeSnapshot(buildSnapshot(json)), text);
    assert.equal(json.source, CT_LOG_LIST_URL);
    const list = compactLogList(json);
    assert.ok(list.operators.length >= 3);
    const ids = list.operators.flatMap((o) => o.logs.map((l) => l.id));
    assert.equal(new Set(ids).size, ids.length, 'log IDs are unique');
    for (const op of list.operators) for (const l of op.logs) {
      assert.equal(Buffer.from(l.id, 'base64').length, 32, l.name);
      assert.ok(LOG_STATES.includes(l.state), l.name);
      assert.ok(/^https:\/\//.test(l.url), l.name);
      assert.ok(['rfc6962', 'static'].includes(l.api), l.name);
    }
    assert.ok(list.operators.some((o) => o.logs.some((l) => l.api === 'static')) && list.operators.some((o) => o.logs.some((l) => l.api === 'rfc6962')));
  });

  test('buildSnapshot refuses what does not look like the list', () => {
    assert.throws(() => buildSnapshot({ hello: 1 }), /not a CT log list/);
    assert.throws(() => buildSnapshot(V3), /implausible list/);
  });
});
