// Unit tests for assets/js/lib/zoneparse.js — offline, no network.
// Fixtures: tests/fixtures/zones/ (example.* names and documentation address ranges only);
// parse goldens: tests/fixtures/zones/expected/*.parse.golden.txt (regenerate with
// `node tests/fixtures/zones/gen-parse-golden.mjs --write`).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ZONE_LIMITS, ZONE_FORMATS, ZONE_DIALECTS, ISSUE_CODES, ORIGIN_SOURCES, NOT_A_ZONE_HINTS, GTLDS,
  AWS_ALIAS_PROVIDERS, awsAliasProvider, detectZoneFormat, parseZone, mergeZones, rdataKey, txtJoinedKey,
  uniqueRecords, zoneNames, toBindText, inferOriginFromFilename, wildcardCovers, tokenizeMaster,
  parseYamlSubset, decodeEscapes, presentLabel, presentCharString, decodeUtf8Lenient
} from '../../assets/js/lib/zoneparse.js';
import { encodeMessage, decodeMessage, encodeName, hexDecode } from '../../assets/js/lib/dnswire.js';
import {
  FIXTURES, ZONES_DIR, parseFixture, fixtureText, formatParseGolden, goldenPath, unifiedDiff
} from '../fixtures/zones/gen-parse-golden.mjs';

const STRICT = process.env.ZONE_PERF_STRICT === '1';
/** Performance budgets: strict under ZONE_PERF_STRICT=1, 3× margin otherwise (shared CI runners). */
const budget = (ms) => (STRICT ? ms : ms * 3);

const readFx = (f) => readFileSync(join(ZONES_DIR, f), 'utf8');
const fx = (id) => FIXTURES.find((f) => f.id === id);
const P = (text, opts) => parseZone(text, opts);
/** A zone body under `$ORIGIN example.com.` / `$TTL 300`. */
const Z = (body, opts) => parseZone(`$ORIGIN example.com.\n$TTL 300\n${body}\n`, opts);
const codes = (z) => z.warnings.map((w) => w.code);
const find = (z, name, type) => z.records.find((r) => r.name === name && (!type || r.type === type));
const findAll = (z, name, type) => z.records.filter((r) => r.name === name && (!type || r.type === type));
const utf8 = (s) => new TextEncoder().encode(s);

/** One RR through the real wire codec (encode → decode), as live DoH answers are. */
function viaWire(type, data, name = 'example.com') {
  const answer = data instanceof Uint8Array ? { name, type, ttl: 60, rdata: data } : { name, type, ttl: 60, data };
  return decodeMessage(encodeMessage({ answers: [answer] })).answers[0];
}

/** Types dnswire.encodeMessage can write from `data` (the others need raw RDATA bytes). */
const WRITABLE = new Set(['A', 'AAAA', 'NS', 'CNAME', 'PTR', 'DNAME', 'MX', 'TXT', 'SPF', 'HINFO', 'SOA', 'SRV', 'NAPTR',
  'CAA', 'DS', 'CDS', 'DNSKEY', 'CDNSKEY', 'TLSA', 'SMIMEA', 'SSHFP', 'SVCB', 'HTTPS', 'URI']);

/* ------------------------------------------------------------------------ */

describe('API surface and closed code sets', () => {
  test('limits, formats, dialects and origin sources', () => {
    assert.ok(Object.isFrozen(ZONE_LIMITS));
    assert.deepEqual(Object.keys(ZONE_LIMITS).sort(), ['maxBytes', 'maxChars', 'maxCnameChain', 'maxCommentChars',
      'maxEntries', 'maxGenerate', 'maxGenerateTotal', 'maxIssues', 'maxJsonDocs', 'maxLineChars', 'maxParenLines',
      'maxRecords', 'maxTokensPerEntry', 'maxYamlDepth']);
    assert.equal(ZONE_LIMITS.maxRecords, 20000);
    assert.equal(ZONE_LIMITS.maxChars, 5000000);
    assert.deepEqual(ZONE_FORMATS, ['bind', 'cloudflare-api', 'route53', 'octodns', 'plesk-info']);
    assert.deepEqual(ZONE_DIALECTS, ['generic', 'cloudflare', 'cli53', 'godaddy', 'cpanel', 'directadmin']);
    assert.deepEqual(ORIGIN_SOURCES, ['user', '$ORIGIN', 'header', 'soa', 'filename', 'records']);
    assert.ok(NOT_A_ZONE_HINTS.includes('pem') && NOT_A_ZONE_HINTS.includes('dns-csv'));
    assert.ok(GTLDS.includes('com') && GTLDS.includes('io') && !GTLDS.includes('local') && !GTLDS.includes('internal'));
  });

  test('ISSUE_CODES: severities follow the spec table (plus the critic additions)', () => {
    const want = {
      error: ['INCLUDE_REJECTED', 'RELATIVE_WITHOUT_ORIGIN', 'UNTERMINATED_QUOTE', 'UNBALANCED_PAREN', 'LINE_TOO_LONG',
        'NO_OWNER', 'BAD_NAME', 'BAD_RDATA', 'BAD_RECORD', 'UNPARSED_LINE', 'PARTIAL_EXPORT', 'OWNER_MISSING_TRAILING_DOT',
        'RECORDS_TRUNCATED', 'GENERATE_TOO_LARGE'],
      warn: ['GENERATE_UNSUPPORTED', 'BAD_TTL', 'TARGET_MISSING_TRAILING_DOT', 'AT_INSIDE_NAME', 'DUPLICATE_KEY',
        'OCTODNS_UNESCAPED_SEMICOLON', 'OUT_OF_ZONE', 'ORIGIN_OVERRIDDEN'],
      info: ['ORIGIN_INFERRED', 'ORIGIN_CORRECTED', 'CF_SOA_OWNER_UNDOTTED', 'NON_IN_CLASS', 'GENERATE_EXPANDED',
        'UNKNOWN_DIRECTIVE', 'FORMAT_UNVERIFIED', 'OCTODNS_IGNORED', 'RDATA_UNPARSED', 'TTL_DEFAULTED', 'NON_ASCII_LABEL',
        'ENCODING_REPLACED', 'JSON_PAGES_MERGED', 'PROXY_FLAG_IGNORED', 'WARNINGS_TRUNCATED', 'INCLUDE_MERGED', 'NO_PROXY_FLAGS']
    };
    const fatal = ['EMPTY', 'TOO_LARGE', 'NOT_TEXT', 'NOT_A_ZONE', 'INVALID_JSON', 'UNSUPPORTED_JSON', 'YAML_UNSUPPORTED',
      'ORIGIN_REQUIRED', 'ORIGIN_MISMATCH', 'API_ERROR'];
    assert.ok(Object.isFrozen(ISSUE_CODES));
    for (const [sev, list] of Object.entries(want)) {
      for (const c of list) assert.deepEqual(ISSUE_CODES[c], { severity: sev, fatal: false }, c);
    }
    for (const c of fatal) assert.deepEqual(ISSUE_CODES[c], { severity: 'error', fatal: true }, c);
    assert.equal(Object.keys(ISSUE_CODES).length, fatal.length + want.error.length + want.warn.length + want.info.length);
  });

  test('parseZone never throws on hostile argument types', () => {
    for (const input of [undefined, null, 42, {}, [], Symbol('x'), new Uint8Array(0), new ArrayBuffer(3), () => 1, true]) {
      const z = parseZone(input);
      assert.ok(z.fatal, `fatal for ${String(typeof input)}`);
      assert.deepEqual(z.records, []);
    }
    assert.equal(parseZone('').fatal.code, 'EMPTY');
    assert.equal(parseZone(undefined).fatal.code, 'EMPTY');
    assert.equal(parseZone(42).fatal.code, 'NOT_TEXT');
    assert.doesNotThrow(() => parseZone('www A 192.0.2.1', null));
    assert.doesNotThrow(() => parseZone('www A 192.0.2.1', { limits: null, origin: 7, format: 9, source: -3 }));
  });

  test('Zone shape', () => {
    const z = parseFixture(fx('cloudflare-export'));
    assert.deepEqual(Object.keys(z), ['format', 'dialect', 'markers', 'origin', 'originSource', 'originConfidence',
      'records', 'warnings', 'fatal', 'partial', 'sources', 'stats', 'defaultTtl']);
    assert.deepEqual(Object.keys(z.stats), ['bytes', 'lines', 'entries', 'records', 'skipped', 'generated', 'proxied', 'dnsOnly', 'byType', 'elapsedMs']);
    assert.deepEqual(z.sources, [{ name: 'cloudflare-export.txt', size: z.stats.bytes, format: 'bind', dialect: 'cloudflare' }]);
    assert.equal(z.stats.bytes, Buffer.byteLength(readFx('cloudflare-export.txt')));
    const r = find(z, 'www.example.com', 'A');
    assert.deepEqual(Object.keys(r), ['id', 'name', 'type', 'ttl', 'ttlAuto', 'data', 'text', 'targets', 'proxied', 'line', 'source']);
    for (const w of z.warnings) {
      assert.deepEqual(Object.keys(w).filter((k) => !['name', 'type'].includes(k)), ['code', 'severity', 'line', 'source', 'params', 'detail']);
      assert.equal(typeof w.detail, 'string');
      assert.equal(typeof w.params, 'object');
    }
    z.records.forEach((rec, i) => assert.equal(rec.id, i));
  });
});

/* ------------------------------------------------------------------------ */

describe('detection', () => {
  const table = [
    ['cloudflare-export.txt', 'bind', 'cloudflare'],
    ['cloudflare-api.json', 'cloudflare-api', null],
    ['route53.json', 'route53', null],
    ['example.com.yaml', 'octodns', null],
    ['bind-edge.zone.txt', 'bind', 'generic'],
    ['cpanel-example.com.db.txt', 'bind', 'cpanel'],
    ['directadmin-example.com.db.txt', 'bind', 'directadmin'],
    ['godaddy.txt', 'bind', 'godaddy'],
    ['cli53.txt', 'bind', 'cli53'],
    ['plesk-info.txt', 'plesk-info', null],
    ['axfr-dig.txt', 'bind', 'generic']
  ];
  for (const [file, format, dialect] of table) {
    test(`${file} → ${format}${dialect ? `/${dialect}` : ''}`, () => {
      const d = detectZoneFormat(readFx(file), { filename: file });
      assert.equal(d.format, format);
      assert.equal(d.dialect, dialect);
      assert.equal(d.notZone, null);
      assert.equal(d.fatal, null);
      assert.equal(d.confidence, 'high');
    });
  }

  test('markers name what was recognised', () => {
    assert.deepEqual(detectZoneFormat(readFx('cloudflare-export.txt')).markers, [';; Domain: header', 'cf_tags', 'ns.cloudflare.com']);
    assert.ok(detectZoneFormat(readFx('axfr-dig.txt')).markers.includes('dig AXFR'));
    assert.deepEqual(detectZoneFormat(readFx('cli53.txt')).markers, ['class AWS', '; AWS routing']);
    assert.ok(detectZoneFormat(readFx('godaddy.txt')).markers.includes('.@ owner'));
  });

  test('not a zone: PEM, HTML, CSV, empty, gzip, binary, AWS text output', () => {
    assert.equal(detectZoneFormat(readFx('bad/cert.pem.txt')).notZone, 'pem');
    assert.equal(detectZoneFormat('<!DOCTYPE html><html><body>x</body></html>').notZone, 'html');
    assert.equal(detectZoneFormat(readFx('bad/inventory.csv')).notZone, 'csv');
    assert.equal(detectZoneFormat('  \n; only a comment\n# and another\n').notZone, 'empty');
    assert.equal(detectZoneFormat(new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0])).notZone, 'gzip');
    assert.equal(detectZoneFormat('www A 192.0.2.1\u0000').notZone, 'binary');
    const aws = 'RESOURCERECORDSETS\texample.com.\t300\tA\nRESOURCERECORDS\t192.0.2.10\n';
    assert.equal(detectZoneFormat(aws).notZone, 'aws-output-json');
    assert.equal(parseZone(aws).fatal.params.hint, 'aws-output-json');
  });

  test('JSON: unknown shapes and syntax errors are fatal', () => {
    assert.equal(detectZoneFormat('{"foo": 1}').fatal.code, 'UNSUPPORTED_JSON');
    assert.equal(parseZone('{"foo": 1}').fatal.code, 'UNSUPPORTED_JSON');
    const bad = parseZone('{"result": [ {"name": "example.com",, } ]}');
    assert.equal(bad.fatal.code, 'INVALID_JSON');
    assert.ok(Number.isInteger(bad.fatal.params.position));
    assert.equal(parseZone('{"result": [').fatal.code, 'INVALID_JSON');
    assert.equal(parseZone('[]').fatal.code, 'EMPTY');
    assert.equal(parseZone('{"result": [], "success": true}').fatal.code, 'EMPTY');
    assert.equal(parseZone('[{"a": 1}]').fatal.code, 'UNSUPPORTED_JSON');
    // a Route 53 page and a Cloudflare page pasted together
    assert.equal(parseZone(`${readFx('route53.json')}\n${readFx('cloudflare-api.json')}`).fatal.code, 'UNSUPPORTED_JSON');
  });

  test('CSV hints: generic CSV vs DNS CSV; inventory and name lists', () => {
    assert.equal(parseZone('Type,Name,Content,TTL\nA,www,192.0.2.10,300\n').fatal.params.hint, 'dns-csv');
    assert.equal(parseZone(readFx('bad/inventory.csv')).fatal.params.hint, 'csv');
    const inv = parseZone('web01 192.0.2.10\ndb01 192.0.2.20\ncache 198.51.100.30\n');
    assert.equal(inv.fatal.code, 'NOT_A_ZONE');
    assert.equal(inv.fatal.params.hint, 'inventory');
    assert.equal(inv.fatal.params.samples.length, 3);
    const names = parseZone('www.example.com\nmail.example.com\napi.example.com\n');
    assert.equal(names.fatal.params.hint, 'names');
  });

  test('a .yaml file name selects octoDNS; format can be forced', () => {
    assert.equal(detectZoneFormat('www:\n  value: x\n', { filename: 'example.com.yml' }).format, 'octodns');
    const forced = parseZone('www 300 IN A 192.0.2.10', { format: 'bind', origin: 'example.com' });
    assert.equal(forced.format, 'bind');
    assert.equal(forced.records.length, 1);
    const asBind = parseZone(readFx('cloudflare-api.json'), { format: 'bind' });
    assert.equal(asBind.fatal.code, 'NOT_A_ZONE');
    const asR53 = parseZone(readFx('route53.json'), { format: 'route53' });
    assert.equal(asR53.format, 'route53');
  });
});

/* ------------------------------------------------------------------------ */

describe('input, encoding and line endings', () => {
  const body = '$ORIGIN example.com.\n$TTL 300\nwww A 192.0.2.10\nmail A 198.51.100.25\n';

  test('BOM, CRLF and lone CR give the same records and line numbers', () => {
    const lf = P(body);
    const lines = (z) => z.records.map((r) => `${r.name}@${r.line}`);
    for (const variant of ['\ufeff' + body, body.replace(/\n/g, '\r\n'), body.replace(/\n/g, '\r')]) {
      const z = P(variant);
      assert.equal(z.fatal, null);
      assert.deepEqual(lines(z), lines(lf));
    }
    assert.deepEqual(lines(lf), ['www.example.com@3', 'mail.example.com@4']);
  });

  test('bytes: UTF-8 BOM, UTF-16LE with BOM (built here), ArrayBuffer', () => {
    const u8 = new Uint8Array([0xef, 0xbb, 0xbf, ...utf8(body)]);
    assert.equal(P(u8).records.length, 2);
    assert.equal(P(u8.buffer).records.length, 2);
    const u16 = new Uint8Array(2 + body.length * 2);
    u16[0] = 0xff;
    u16[1] = 0xfe;
    for (let i = 0; i < body.length; i++) u16[2 + i * 2] = body.charCodeAt(i);
    const z = P(u16);
    assert.equal(z.fatal, null);
    assert.equal(z.records.length, 2);
    assert.equal(z.stats.bytes, u16.length);
  });

  test('UTF-16 without a BOM and NUL characters → NOT_TEXT', () => {
    const u16 = new Uint8Array(body.length * 2);
    for (let i = 0; i < body.length; i++) u16[i * 2] = body.charCodeAt(i);
    const z = P(u16);
    assert.equal(z.fatal.code, 'NOT_TEXT');
    assert.equal(z.fatal.params.hint, 'utf16');
    assert.equal(P('www A 192.0.2.1\n\u0000').fatal.code, 'NOT_TEXT');
    assert.equal(P(new Uint8Array(200).fill(0xff)).fatal.code, 'NOT_TEXT');
  });

  test('an isolated replacement character → ENCODING_REPLACED (info, once)', () => {
    const z = Z('www A 192.0.2.10 ; caf\ufffd\nmail A 198.51.100.25 ; \ufffd');
    assert.equal(z.fatal, null);
    assert.deepEqual(z.warnings.filter((w) => w.code === 'ENCODING_REPLACED').map((w) => w.params.count), [2]);
    const latin1 = new Uint8Array([...utf8('$ORIGIN example.com.\nwww 300 A 192.0.2.10 ; caf'), 0xe9, 0x0a]);
    assert.deepEqual(codes(P(latin1)), ['ENCODING_REPLACED']);
  });

  test('TOO_LARGE is checked before any scanning (string and bytes)', () => {
    const z = P('x'.repeat(101), { limits: { maxChars: 100 } });
    assert.equal(z.fatal.code, 'TOO_LARGE');
    assert.deepEqual(z.fatal.params, { size: 101, max: 100, unit: 'chars' });
    const b = P(new Uint8Array(65), { limits: { maxBytes: 64 } });
    assert.deepEqual(b.fatal.params, { size: 65, max: 64, unit: 'bytes' });
    const t0 = performance.now();
    const huge = P('a'.repeat(ZONE_LIMITS.maxChars + 1));
    assert.equal(huge.fatal.code, 'TOO_LARGE');
    assert.ok(performance.now() - t0 < 1000);
  });

  test('gzip bytes → NOT_A_ZONE hint gzip', () => {
    assert.deepEqual(P(new Uint8Array([0x1f, 0x8b, 8, 0, 1, 2, 3])).fatal.params, { hint: 'gzip', samples: [] });
  });
});

/* ------------------------------------------------------------------------ */

describe('tokenizer', () => {
  test('quotes: a quoted ";" is not a comment, \\" is kept, comments are kept on the entry', () => {
    const e = tokenizeMaster('a TXT "x; y \\"z\\"" ; the comment\nb A 192.0.2.1');
    assert.equal(e.length, 2);
    assert.deepEqual(e[0].tokens, [{ t: 'a', q: false }, { t: 'TXT', q: false }, { t: 'x; y \\"z\\"', q: true }]);
    assert.equal(e[0].comment, 'the comment');
    assert.equal(e[1].line, 2);
  });

  test('parentheses join lines and collect inner comments', () => {
    const e = tokenizeMaster('@ SOA ns. host. (\n 1 ; serial\n 2 3 4 5 ) ; tail\nx A 192.0.2.1');
    assert.equal(e[0].tokens.length, 9);
    assert.equal(e[0].endLine, 3);
    assert.equal(e[0].comment, 'serial tail');
    assert.equal(e[1].line, 4);
  });

  test('glued quote: alpn="h3,h2" is one token; \\# survives raw', () => {
    const e = tokenizeMaster('svc HTTPS 1 . alpn="h3,h2" key7="a b"\ngen TYPE65534 \\# 4 0a000001');
    assert.deepEqual(e[0].tokens.slice(4).map((t) => t.t), ['alpn=h3,h2', 'key7=a b']);
    assert.equal(e[1].tokens[2].t, '\\#');
  });

  test('blank owners (space and tab) inherit the previous owner', () => {
    const z = Z('www A 192.0.2.10\n  AAAA 2001:db8::10\n\tTXT "t"');
    assert.deepEqual(z.records.map((r) => `${r.name} ${r.type}`), ['www.example.com A', 'www.example.com AAAA', 'www.example.com TXT']);
    assert.equal(Z('  A 192.0.2.10\nwww A 192.0.2.19').warnings[0].code, 'NO_OWNER');
  });

  test('a stray ")" is reported and ignored', () => {
    const z = Z('www A 192.0.2.10 )');
    assert.equal(find(z, 'www.example.com').data, '192.0.2.10');
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line, w.params.kind]), [['UNBALANCED_PAREN', 3, 'close']]);
  });

  test('P2 unterminated quote: error at the opening line, later records parsed', () => {
    const z = parseFixture(fx('bad-unterminated-quote'));
    assert.deepEqual(z.records.map((r) => r.name), ['b.example.com', 'c.example.com']);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [['UNTERMINATED_QUOTE', 3]]);
  });

  test('P3 unbalanced parenthesis: error at the opening line, later records parsed', () => {
    const z = parseFixture(fx('bad-unbalanced-paren'));
    assert.deepEqual(z.records.map((r) => r.name), ['b.example.com', 'c.example.com']);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line, w.params.kind]), [['UNBALANCED_PAREN', 3, 'open']]);
  });

  test('an open parenthesis stops at a column-0 $ directive, which still applies', () => {
    const z = P('$ORIGIN example.com.\n$TTL 300\na TXT ( "x"\n$ORIGIN example.net.\nb A 192.0.2.1\n');
    assert.deepEqual(z.records.map((r) => r.name), ['b.example.net']);
    assert.ok(codes(z).includes('UNBALANCED_PAREN'));
  });

  test('a parenthesised entry longer than maxParenLines is dropped; the lines after it are re-read', () => {
    const recs = Array.from({ length: 10 }, (_, i) => `h${i} A 192.0.2.${i + 1}`).join('\n');
    const z = P(`$ORIGIN example.com.\n$TTL 300\n@ SOA ns1 host ( 1 2 3 4 5\n${recs}\n`, { limits: { maxParenLines: 5 } });
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [['UNBALANCED_PAREN', 3]]);
    assert.equal(z.records.length, 10);
  });

  test('a 70,000-character line → LINE_TOO_LONG, the next line is parsed', () => {
    const z = Z(`big TXT "${'x'.repeat(70000)}"\nnext A 192.0.2.1`);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [['LINE_TOO_LONG', 3]]);
    assert.deepEqual(z.records.map((r) => r.name), ['next.example.com']);
  });

  test('too many tokens in one entry → BAD_RDATA', () => {
    const z = Z(`t TXT ${'"a" '.repeat(50)}\nok A 192.0.2.1`, { limits: { maxTokensPerEntry: 20 } });
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.reason]), [['BAD_RDATA', 'too-many-tokens']]);
    assert.ok(find(z, 'ok.example.com'));
  });

  test('maxEntries stops tokenizing with RECORDS_TRUNCATED', () => {
    const body = Array.from({ length: 30 }, (_, i) => `h${i} A 192.0.2.${i + 1}`).join('\n');
    const z = Z(body, { limits: { maxEntries: 10 } });
    assert.ok(z.records.length <= 10);
    assert.ok(codes(z).includes('RECORDS_TRUNCATED'));
    assert.equal(z.partial, true);
  });

  test('type mnemonics and classes are case-insensitive; TTL and class in either order', () => {
    const z = Z('a 60 in a 192.0.2.1\nb in 60 cname a\nc IN 1h30m A 192.0.2.3\nd class1 A 192.0.2.4');
    assert.deepEqual(z.records.map((r) => [r.name, r.ttl, r.type]), [
      ['a.example.com', 60, 'A'], ['b.example.com', 60, 'CNAME'], ['c.example.com', 5400, 'A'], ['d.example.com', 300, 'A']]);
  });

  test('the first token is always the owner, even when it looks like a TTL or type', () => {
    const z = Z('60 A 192.0.2.1\nin A 192.0.2.2\nmx MX 10 mail');
    assert.deepEqual(z.records.map((r) => r.name), ['60.example.com', 'in.example.com', 'mx.example.com']);
  });

  test('UNPARSED_LINE for an unknown type; non-IN classes are skipped (info)', () => {
    const z = Z('a FOO 1\nb CH TXT "v"\nc HS A 192.0.2.1\nd CLASS3 A 192.0.2.1\ne AWS A 192.0.2.1\nok A 192.0.2.9');
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [
      ['UNPARSED_LINE', 3], ['NON_IN_CLASS', 4], ['NON_IN_CLASS', 5], ['NON_IN_CLASS', 6], ['UNPARSED_LINE', 7]]);
    assert.deepEqual(z.records.map((r) => r.name), ['ok.example.com']);
    assert.equal(z.warnings[0].params.snippet, 'a FOO 1');
  });
});

/* ------------------------------------------------------------------------ */

describe('names', () => {
  const edge = () => parseFixture(fx('bind-edge'));

  test('@, $ORIGIN (relative and changing mid-file)', () => {
    const z = edge();
    assert.equal(z.records[0].name, 'example.com');
    assert.ok(find(z, 'sub.example.com', 'A'));
    assert.ok(find(z, 'api.sub.example.com', 'A'));
    const rel = P('$ORIGIN example.com.\n$ORIGIN sub\nx A 192.0.2.1\n');
    assert.equal(rel.records[0].name, 'x.sub.example.com');
  });

  test('decimal escapes in BIND: \\042 → "*", \\052 → "4"; \\. stays inside one label', () => {
    const z = edge();
    assert.ok(find(z, '*.lit.example.com', 'A'));
    assert.ok(find(z, '4.dec.example.com', 'A'));
    assert.ok(find(z, 'dot\\.label.example.com', 'A'));
    assert.deepEqual([...encodeName('dot\\.label.example.com')].slice(0, 10), [9, 100, 111, 116, 46, 108, 97, 98, 101, 108]);
  });

  test('octal escapes in Route 53: \\052 → "*", \\040 → space (presented \\032)', () => {
    const z = parseFixture(fx('route53'));
    assert.ok(find(z, '*.example.com', 'CNAME'));
    assert.ok(find(z, 'name\\032with\\032space.example.com', 'TXT'));
  });

  test('invalid escapes: \\256 (BIND) and \\089 (Route 53) → BAD_NAME', () => {
    const z = Z('a\\256b A 192.0.2.1\nok A 192.0.2.2');
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.reason]), [['BAD_NAME', 'bad-escape']]);
    const r = P(JSON.stringify({ ResourceRecordSets: [
      { Name: 'example.com.', Type: 'SOA', TTL: 900, ResourceRecords: [{ Value: 'ns. host. 1 2 3 4 5' }] },
      { Name: '\\089.example.com.', Type: 'A', TTL: 60, ResourceRecords: [{ Value: '192.0.2.1' }] }] }));
    assert.deepEqual(r.warnings.filter((w) => w.code === 'BAD_NAME').map((w) => w.params.reason), ['bad-escape']);
    assert.equal(r.records.length, 1);
  });

  test('label over 63 octets and name over 255 octets → BAD_NAME', () => {
    const z = Z(`${'a'.repeat(64)} A 192.0.2.1\n${Array(4).fill('b'.repeat(63)).join('.')}. A 192.0.2.2\nok A 192.0.2.3`);
    assert.deepEqual(z.warnings.map((w) => w.params.reason), ['label-too-long', 'too-long']);
    assert.deepEqual(z.records.map((r) => r.name), ['ok.example.com']);
    // exactly 255 octets is fine
    const name = `${Array(3).fill('c'.repeat(63)).join('.')}.${'d'.repeat(61)}.`;
    assert.equal(encodeName(name).length, 255);
    assert.equal(Z(`${name} A 192.0.2.4`).records.length, 1);
  });

  test('names are lowercased; raw non-ASCII labels become punycode (NON_ASCII_LABEL)', () => {
    const z = Z('UPPER A 192.0.2.1\nmüşteri A 192.0.2.2');
    assert.ok(find(z, 'upper.example.com'));
    const idn = z.records[1].name;
    assert.match(idn, /^xn--[a-z0-9-]+\.example\.com$/);
    assert.equal(idn, `${new URL('http://müşteri.x').hostname.slice(0, -2)}.example.com`);
    assert.deepEqual(codes(z), ['NON_ASCII_LABEL']);
  });

  test('GoDaddy "_svc._tcp.@" → below the origin (AT_INSIDE_NAME); other bare "@" → BAD_NAME', () => {
    const z = parseFixture(fx('godaddy'));
    assert.ok(find(z, '_autodiscover._tcp.example.com', 'SRV'));
    assert.ok(find(z, '_imaps._tcp.example.com', 'SRV'));
    assert.equal(codes(z).filter((c) => c === 'AT_INSIDE_NAME').length, 2);
    assert.equal(find(z, 'www.example.com', 'CNAME').data, 'example.com');
    const bad = Z('a@b A 192.0.2.1\nx CNAME a.@\nok A 192.0.2.3');
    assert.deepEqual(bad.warnings.map((w) => [w.code, w.params.reason ?? null]), [['BAD_NAME', 'at-sign'], ['AT_INSIDE_NAME', null]]);
    assert.equal(find(bad, 'x.example.com').data, 'a.example.com');
    // in RDATA the issue names the target as read (one per "x.@" target), anchored on the record
    const srv = Z('_sip._tcp.@ IN SRV 10 5 5060 sip.@');
    assert.deepEqual(srv.warnings.map((w) => [w.code, w.params, w.name]), [
      ['AT_INSIDE_NAME', { name: '_sip._tcp.example.com', raw: '_sip._tcp.@' }, '_sip._tcp.example.com'],
      ['AT_INSIDE_NAME', { name: 'sip.example.com', raw: 'sip.@' }, '_sip._tcp.example.com']]);
  });

  test('RELATIVE_WITHOUT_ORIGIN per record when a later $ORIGIN exists; others kept', () => {
    const z = P('www A 192.0.2.10\n$ORIGIN example.com.\napi A 192.0.2.20\n');
    assert.deepEqual(z.records.map((r) => r.name), ['api.example.com']);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [['RELATIVE_WITHOUT_ORIGIN', 1]]);
    assert.equal(z.origin, 'example.com');
    assert.equal(z.originSource, '$ORIGIN');
    assert.equal(z.originConfidence, 'low');
  });

  test('ORIGIN_REQUIRED when every name is relative and nothing names the zone', () => {
    const z = P('www A 192.0.2.10\nmail A 192.0.2.20\napi A 192.0.2.30\n');
    assert.equal(z.fatal.code, 'ORIGIN_REQUIRED');
    assert.equal(z.fatal.params.relative, 3);
    assert.equal(z.format, 'bind');
    const ok = P('www A 192.0.2.10\nmail A 192.0.2.20\napi A 192.0.2.30\n', { origin: 'Example.COM.' });
    assert.deepEqual(ok.records.map((r) => r.name), ['www.example.com', 'mail.example.com', 'api.example.com']);
    assert.equal(ok.originSource, 'user');
  });

  test('owner without trailing dot that repeats the origin → served name + intendedName (error)', () => {
    const z = parseFixture(fx('cpanel-example.com.db'));
    const r = find(z, 'example.com.example.com', 'TXT');
    assert.equal(r.intendedName, 'example.com');
    const w = z.warnings.find((x) => x.code === 'OWNER_MISSING_TRAILING_DOT');
    assert.deepEqual(w.params, { name: 'example.com.example.com', intended: 'example.com' });
    assert.equal(w.severity, 'error');
  });

  test('TARGET_MISSING_TRAILING_DOT only for TLD-looking names without records under the served name', () => {
    const z = Z('blog CNAME example-blog.github.io\nlb1 CNAME web.lb\nweb.lb.example.com. A 192.0.2.1\nmx MX 10 mail\nsvc CNAME host.internal');
    const blog = find(z, 'blog.example.com');
    assert.deepEqual(blog.targets, ['example-blog.github.io.example.com']);
    assert.deepEqual(blog.intendedTargets, ['example-blog.github.io']);
    assert.equal(find(z, 'lb1.example.com').intendedTargets, undefined);
    assert.equal(find(z, 'svc.example.com').intendedTargets, undefined);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.intended]), [['TARGET_MISSING_TRAILING_DOT', 'example-blog.github.io']]);
    // absolute sources (JSON) never get the heuristic
    assert.equal(parseFixture(fx('cloudflare-api')).records.some((r) => r.intendedTargets), false);
  });

  test('names outside the origin → OUT_OF_ZONE (once per name)', () => {
    const z = Z('www A 192.0.2.1\nother.example.net. A 192.0.2.2\nother.example.net. AAAA 2001:db8::2');
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.name]), [['OUT_OF_ZONE', 'other.example.net']]);
  });
});

/* ------------------------------------------------------------------------ */

describe('TTL', () => {
  test('explicit > $TTL > last explicit > SOA minimum (TTL_DEFAULTED) > null', () => {
    const edge = parseFixture(fx('bind-edge'));
    assert.equal(find(edge, 'slow.example.com').ttl, 604800);
    assert.equal(find(edge, 'upper.example.com').ttl, 3600, '$TTL 1h wins over the last explicit 1w');
    const last = P('$ORIGIN example.com.\n@ 600 A 192.0.2.10\nwww A 192.0.2.20\n');
    assert.equal(find(last, 'www.example.com').ttl, 600);
    const soa = P('$ORIGIN example.com.\n@ SOA ns1 host 1 2 3 4 1234\nwww A 192.0.2.10\n');
    assert.deepEqual(soa.records.map((r) => r.ttl), [1234, 1234]);
    assert.deepEqual(soa.warnings.filter((w) => w.code === 'TTL_DEFAULTED').map((w) => w.params.ttl), [1234]);
    const none = P('$ORIGIN example.com.\nwww A 192.0.2.10\n');
    assert.equal(none.records[0].ttl, null);
  });

  test('units are summed; SOA timers accept units', () => {
    const edge = parseFixture(fx('bind-edge'));
    const soa = edge.records[0].data;
    assert.deepEqual([soa.refresh, soa.retry, soa.expire, soa.minimum], [7200, 1800, 1209600, 300]);
    assert.equal(Z('a 1h30M A 192.0.2.1').records[0].ttl, 5400);
    assert.equal(Z('a 1w2d A 192.0.2.1').records[0].ttl, 777600);
    const trailing = Z('a 1h30 A 192.0.2.1\nb A 192.0.2.2\nc A 192.0.2.3');
    assert.deepEqual(codes(trailing), ['UNPARSED_LINE'], 'digits after a unit are not a TTL');
  });

  test('P5 BAD_TTL: above 2^31-1 → 0 and not remembered as the last explicit TTL', () => {
    const z = P('$ORIGIN example.com.\n@ 300 A 192.0.2.10\nbig 4294967295 A 192.0.2.3\nnext A 192.0.2.4\n');
    assert.deepEqual(z.records.map((r) => r.ttl), [300, 0, 300]);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.ttl]), [['BAD_TTL', 4294967295]]);
    const dir = P('$ORIGIN example.com.\n$TTL 99999999999\n$TTL nope\nwww 60 A 192.0.2.1\n');
    assert.deepEqual(codes(dir), ['BAD_TTL', 'BAD_TTL']);
  });

  test('Cloudflare TTL 1 means Auto (300) only in the Cloudflare dialect', () => {
    const cf = parseFixture(fx('cloudflare-export'));
    const w = find(cf, 'www.example.com', 'A');
    assert.equal(w.ttl, 300);
    assert.equal(w.ttlAuto, true);
    assert.equal(find(cf, 'vpn.example.com').ttlAuto, undefined);
    const generic = Z('www 1 IN A 192.0.2.10');
    assert.equal(generic.records[0].ttl, 1);
    assert.equal(generic.records[0].ttlAuto, undefined);
  });

  test('defaultTtl option seeds $TTL (an $INCLUDE fragment inherits the main file\'s)', () => {
    const z = P('www A 192.0.2.10\n', { origin: 'example.com', defaultTtl: 900 });
    assert.equal(z.records[0].ttl, 900);
    assert.equal(z.defaultTtl, 900);
  });
});

/* ------------------------------------------------------------------------ */

describe('RDATA → dnswire data shapes', () => {
  const one = (line, opts) => {
    const z = Z(line, opts);
    return { z, r: z.records[0] };
  };
  const invalid = (line) => {
    const { z, r } = one(line);
    assert.equal(r.invalid, true, line);
    assert.equal(r.data, null, line);
    const w = z.warnings.find((x) => x.code === 'BAD_RDATA');
    assert.ok(w, line);
    return w.params.reason;
  };

  test('A / AAAA', () => {
    assert.equal(one('a A 192.0.2.10').r.data, '192.0.2.10');
    assert.equal(one('a AAAA 2001:DB8:0:0::1').r.data, '2001:db8::1');
    assert.equal(invalid('a A 999.1.1.1'), 'bad-address');
    assert.equal(invalid('a A 192.0.2.010'), 'bad-address');
    assert.equal(invalid('a A 2001:db8::1'), 'bad-address');
    assert.equal(invalid('a AAAA 192.0.2.1'), 'wrong-family');
    assert.equal(invalid('a A 192.0.2.1 192.0.2.2'), 'extra-field');
    assert.equal(invalid('a AAAA [2001:db8::1]'), 'bad-address');
  });

  test('NS / CNAME / PTR / DNAME', () => {
    const { r } = one('a CNAME Target.Example.NET.');
    assert.equal(r.data, 'target.example.net');
    assert.equal(r.text, 'target.example.net.');
    assert.deepEqual(r.targets, ['target.example.net']);
    assert.equal(one('a DNAME other').r.data, 'other.example.com');
    assert.equal(one('a PTR host.example.net.').r.text, 'host.example.net.');
    assert.equal(invalid('a CNAME'), 'missing-field');
    assert.equal(invalid('a NS a..b.'), 'bad-name');
  });

  test('MX incl. the null MX; P9 a missing preference', () => {
    const { r } = one('@ MX 10 mail');
    assert.deepEqual(r.data, { preference: 10, exchange: 'mail.example.com' });
    const nul = one('@ MX 0 .').r;
    assert.deepEqual(nul.data, { preference: 0, exchange: '.' });
    assert.equal(nul.text, '0 .');
    assert.deepEqual(nul.targets, ['']);
    assert.equal(invalid('@ MX mail.example.com.'), 'missing-field');
    assert.equal(invalid('@ MX 70000 mail'), 'bad-preference');
  });

  test('TXT: several strings, escapes, P4 UTF-8 bytes, >255 bytes kept, bad escape', () => {
    assert.deepEqual(one('t TXT "a" "b c" unq').r.data, ['a', 'b c', 'unq']);
    const kase = one('t TXT "k\\195\\164se"').r;
    assert.deepEqual(kase.data, ['käse']);
    assert.equal(kase.text, '"käse"');
    const latin = one('t TXT "\\228"').r;
    assert.deepEqual(latin.data, ['ä'], 'invalid UTF-8 falls back to Latin-1 like dnswire');
    assert.equal(latin.text, '"\\228"');
    const long = one(`t TXT "${'x'.repeat(300)}"`).r;
    assert.equal(long.data[0].length, 300);
    assert.equal(invalid('t TXT "\\256"'), 'bad-escape');
    assert.equal(invalid('t TXT'), 'missing-field');
    assert.deepEqual(one('t SPF "v=spf1 -all"').r.data, ['v=spf1 -all']);
  });

  test('SOA: units, email, errors', () => {
    const { r } = one('@ SOA ns1 hostmaster 2026092401 1h 15m 2w 5m');
    assert.deepEqual(r.data, { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092401,
      refresh: 3600, retry: 900, expire: 1209600, minimum: 300, email: 'hostmaster@example.com' });
    assert.equal(invalid('@ SOA ns1 host 1 2 3 4'), 'missing-field');
    assert.equal(invalid('@ SOA ns1 host 4294967296 2 3 4 5'), 'bad-serial');
    assert.equal(invalid('@ SOA ns1 host 1h 2 3 4 5'), 'bad-serial');
  });

  test('SRV', () => {
    assert.deepEqual(one('_sip._tcp SRV 10 5 5060 sip').r.data, { priority: 10, weight: 5, port: 5060, target: 'sip.example.com' });
    assert.equal(invalid('_sip._tcp SRV 10 5 70000 sip'), 'bad-port');
  });

  test('CAA: a space inside the value, critical flag, bad tag / flags', () => {
    const { r } = one('@ CAA 0 issue "letsencrypt.org; validationmethods=dns-01"');
    assert.deepEqual(r.data, { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01', critical: false });
    assert.equal(r.text, '0 issue "letsencrypt.org; validationmethods=dns-01"');
    assert.equal(one('@ CAA 128 ISSUE "x"').r.data.critical, true);
    assert.equal(one('@ CAA 128 ISSUE "x"').r.data.tag, 'issue');
    assert.equal(invalid('@ CAA 256 issue "x"'), 'bad-flags');
    assert.equal(invalid('@ CAA 0 is-sue "x"'), 'bad-tag');
  });

  test('DS / CDS: mixed-case hex → lowercase data, uppercase text (as dnswire prints); algorithm mnemonics', () => {
    const { r } = one('dev DS 12345 13 2 0123456789abcdef0123456789ABCDEF 0123456789abcdef0123456789ABCDEF');
    assert.equal(r.data.digest, '0123456789abcdef'.repeat(4));
    assert.equal(r.text, `12345 13 2 ${'0123456789ABCDEF'.repeat(4)}`);
    assert.equal(one('dev DS 12345 ECDSAP256SHA256 2 00ff').r.data.algorithm, 13);
    assert.equal(invalid('dev DS 12345 13 2 abc'), 'bad-digest');
    assert.equal(invalid('dev DS 12345 13 2 zz'), 'bad-digest');
    assert.equal(one('dev CDS 0 0 0 00').r.data.digest, '00');
  });

  test('DNSKEY / CDNSKEY: base64 key, derived fields as dnswire computes them', () => {
    const { r } = one('@ DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d xCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');
    assert.equal(r.data.flags, 257);
    assert.equal(r.data.sep, true);
    assert.equal(r.data.zoneKey, true);
    assert.equal(typeof r.data.keyTag, 'number');
    assert.equal(r.data.publicKey, 'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');
    assert.equal(invalid('@ DNSKEY 257 3 13 not*base64'), 'bad-public-key');
  });

  test('TLSA / SMIMEA / SSHFP', () => {
    assert.deepEqual(one('_443._tcp TLSA 3 1 1 ABCDEF01').r.data, { usage: 3, selector: 1, matchingType: 1, data: 'abcdef01' });
    assert.equal(one('x SMIMEA 3 0 0 00ff').r.data.data, '00ff');
    assert.deepEqual(one('h SSHFP 4 2 AB CD').r.data, { algorithm: 4, fpType: 2, fingerprint: 'abcd' });
    assert.equal(invalid('_443._tcp TLSA 3 1 1 xyz0'), 'bad-association-data');
    assert.equal(invalid('h SSHFP 4 2 abc'), 'bad-fingerprint');
  });

  test('SVCB / HTTPS: P8 glued alpn, mandatory / port / keyNNNNN, ip hints, errors', () => {
    const h = one('svc HTTPS 1 . alpn="h3,h2"').r;
    assert.deepEqual(h.data, { priority: 1, target: '.', params: { alpn: ['h3', 'h2'] } });
    assert.equal(h.text, '1 . alpn="h3,h2"');
    const s = one('_x SVCB 1 svc.example.net. mandatory=alpn,port alpn=h2 port=8443 key65000=abc ipv6hint=2001:DB8::1,2001:db8::2 no-default-alpn').r;
    assert.deepEqual(s.data.params, {
      mandatory: ['alpn', 'port'], alpn: ['h2'], 'no-default-alpn': true, port: 8443,
      ipv6hint: ['2001:db8::1', '2001:db8::2'], key65000: '616263'
    });
    assert.deepEqual(s.targets, ['svc.example.net']);
    assert.equal(one('svc HTTPS 1 . key1=h2').r.data.params.alpn[0], 'h2');
    assert.equal(invalid('svc HTTPS 1 . port=1 port=2'), 'svc-duplicate-key');
    assert.equal(invalid('svc HTTPS 1 . foo=bar'), 'svc-unknown-key');
    assert.equal(invalid('svc HTTPS 1 . ipv4hint=2001:db8::1'), 'svc-ipv4hint');
    assert.equal(invalid('svc HTTPS 1 . port=99999'), 'svc-port');
  });

  test('NAPTR, URI, HINFO, RP, AFSDB, KX, OPENPGPKEY', () => {
    const n = one('@ NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .').r;
    assert.deepEqual(n.data, { order: 100, preference: 10, flags: 'U', services: 'E2U+sip', regexp: '!^.*$!sip:info@example.com!', replacement: '.' });
    assert.deepEqual(one('_http._tcp URI 10 1 "https://www.example.com/"').r.data, { priority: 10, weight: 1, target: 'https://www.example.com/' });
    assert.deepEqual(one('h HINFO "x86" "Linux"').r.data, { cpu: 'x86', os: 'Linux' });
    assert.deepEqual(one('@ RP admin.example.com. txt').r.data, { mbox: 'admin.example.com', txt: 'txt.example.com' });
    assert.deepEqual(one('@ AFSDB 1 afs').r.data, { subtype: 1, hostname: 'afs.example.com' });
    assert.deepEqual(one('@ KX 10 kx').r.data, { preference: 10, exchanger: 'kx.example.com' });
    assert.equal(one('@ OPENPGPKEY AQID').r.data, 'AQID');
    assert.equal(invalid('@ NAPTR 100 10 "U" "E2U+sip" "x"'), 'missing-field');
    assert.equal(invalid('@ URI 10 x "a"'), 'bad-weight');
  });

  test('P15 RFC 3597 generic RDATA; a known type in \\# form is decoded (B2)', () => {
    const g = one('gen TYPE65534 \\# 4 0a000001').r;
    assert.equal(g.type, 'TYPE65534');
    assert.equal(g.data, '0a000001');
    assert.equal(g.text, '\\# 4 0A000001');
    const a = one('hexa A \\# 4 C0000264').r;
    assert.equal(a.data, '192.0.2.100');
    assert.equal(a.text, '192.0.2.100');
    assert.equal(rdataKey('A', a.data), rdataKey('A', viaWire('A', '192.0.2.100').data));
    assert.equal(one('t TYPE1 192.0.2.7').r.type, 'A');
    assert.equal(one('e TYPE65000 \\# 0').r.data, '');
    assert.equal(invalid('gen TYPE65534 \\# 3 0a000001'), 'generic-length');
    assert.equal(invalid('x A \\# 3 0a0000'), 'generic-data');
  });

  test('unparsed types are kept as text with RDATA_UNPARSED (once per type)', () => {
    const z = Z('a LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m\nb LOC 1 N 1 E 0m\nc ALIAS other.example.net.');
    assert.deepEqual(z.records.map((r) => [r.type, r.unsupported, r.data]), [['LOC', true, null], ['LOC', true, null], ['ALIAS', true, null]]);
    assert.equal(z.records[0].text, '52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m');
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.type]), [['RDATA_UNPARSED', 'LOC'], ['RDATA_UNPARSED', 'ALIAS']]);
  });

  test('P6 invalid records are kept (for lint and display) with the raw text', () => {
    const z = parseFixture(fx('bind-edge'));
    const x = find(z, 'x.example.com');
    assert.deepEqual([x.invalid, x.data, x.text], [true, null, '999.1.1.1']);
  });

  test('every parsed record prints and decodes exactly like dnswire (text and rdataKey round trip)', () => {
    let checked = 0;
    for (const f of FIXTURES) {
      const z = parseFixture(f);
      for (const r of z.records) {
        if (r.data === null) continue;
        if ((r.type === 'TXT' || r.type === 'SPF') && r.data.some((s) => utf8(s).length > 255)) continue;
        const live = viaWire(r.type, r.data, r.name);
        assert.equal(live.text, r.text, `${f.id} ${r.name} ${r.type}`);
        assert.equal(rdataKey(r.type, live.data), rdataKey(r.type, r.data), `${f.id} ${r.name} ${r.type}`);
        assert.equal(live.name, r.name);
        checked++;
      }
    }
    assert.ok(checked > 200, `checked ${checked}`);
  });
});

/* ------------------------------------------------------------------------ */

describe('Cloudflare BIND export', () => {
  const cf = () => parseFixture(fx('cloudflare-export'));

  test('pinned counts: 39 records, types, 10 proxied, 26 owners, origin from the header', () => {
    const z = cf();
    assert.equal(z.records.length, 39);
    assert.deepEqual(z.stats.byType, { SOA: 1, NS: 4, A: 14, AAAA: 2, CAA: 2, CNAME: 7, DS: 1, MX: 2, SRV: 2, TXT: 4 });
    assert.equal(z.stats.proxied, 10);
    assert.equal(zoneNames(z).length, 26);
    assert.deepEqual([z.origin, z.originSource, z.originConfidence], ['example.com', 'header', 'high']);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.line]), [['ORIGIN_INFERRED', 0], ['CF_SOA_OWNER_UNDOTTED', 27]]);
    assert.equal(z.records[0].type, 'SOA');
    assert.equal(z.records[0].name, 'example.com');
  });

  test('cf_tags: the last " cf_tags=" wins, JSON-quoted values, comment split off, reserved tags become flags', () => {
    const z = cf();
    const tagged = find(z, 'tagged.example.com');
    assert.equal(tagged.tags.owner, 'ops, eu');
    assert.equal(Object.getPrototypeOf(tagged.tags), null);
    assert.equal(tagged.comment, 'note with cf_tags= as text');
    assert.equal(tagged.proxied, true);
    const api = find(z, 'api.example.com');
    assert.deepEqual({ ...api.tags }, { team: 'backend' });
    assert.equal(api.comment, 'API origin; do not expose');
    const status = find(z, 'status.example.com');
    assert.equal(status.flattenCname, true);
    assert.equal(status.proxied, false);
    assert.equal(status.tags, undefined);
    assert.deepEqual(findAll(z, 'mixed.example.com').map((r) => r.proxied), [true, false]);
    assert.equal(find(z, 'example.com', 'MX').proxied, null);
  });

  test('the DKIM TXT keeps its 255 + N split', () => {
    const d = find(cf(), 'google._domainkey.example.com', 'TXT');
    assert.deepEqual(d.data.map((s) => utf8(s).length), [255, 51]);
  });

  test('cf_tags are honoured in every BIND dialect; a CF export without tags → NO_PROXY_FLAGS', () => {
    const g = P('www.example.com. 300 IN A 127.0.0.1 ; cf_tags=cf-proxied:true\n');
    assert.equal(g.records[0].proxied, true);
    assert.equal(g.dialect, 'generic');
    const old = P(';; Domain:     example.com.\nexample.com\t3600\tIN\tSOA\tada.ns.cloudflare.com. dns.cloudflare.com. 1 2 3 4 5\nwww.example.com.\t1\tIN\tA\t192.0.2.10\n');
    assert.equal(old.dialect, 'cloudflare');
    assert.equal(old.records[1].proxied, null);
    assert.equal(old.records[1].ttlAuto, true);
    assert.ok(codes(old).includes('NO_PROXY_FLAGS'));
    const mx = Z('@ MX 10 mail ; cf_tags=cf-proxied:true\n@ MX 20 mx2 ; cf_tags=cf-proxied:true');
    assert.deepEqual(mx.warnings.map((w) => [w.code, w.params.type]), [['PROXY_FLAG_IGNORED', 'MX']]);
    assert.equal(mx.records[0].proxied, null);
  });

  test('tag grammar corner cases', () => {
    const z = Z('a A 192.0.2.1 ; cf_tags=empty1:,empty2:"",bare,esc:"a\\"b",cf-proxied:false\nb A 192.0.2.2 ;cf_tags=__proto__:x,constructor:y');
    assert.deepEqual({ ...z.records[0].tags }, { empty1: '', empty2: '', bare: '', esc: 'a"b' });
    assert.equal(z.records[0].proxied, false);
    assert.equal(z.records[1].tags.__proto__, 'x');
    assert.equal({}.x, undefined);
  });

  test('placeholders and a Cloudflare address parse as plain proxied records', () => {
    const z = parseFixture(fx('placeholder.cf'));
    assert.equal(find(z, 'worker.example.com').data, '192.0.2.0');
    assert.equal(find(z, 'edge.example.com').data, '100::');
    assert.equal(z.stats.proxied, 4);
  });
});

/* ------------------------------------------------------------------------ */

describe('Cloudflare API JSON', () => {
  test('fixture: origin from the records (low), SRV from data, MX priority, TXT quoted and legacy', () => {
    const z = parseFixture(fx('cloudflare-api'));
    assert.deepEqual([z.origin, z.originSource, z.originConfidence], ['example.com', 'records', 'low']);
    assert.deepEqual(find(z, '_autodiscover._tcp.example.com').data, { priority: 0, weight: 0, port: 443, target: 'mail.example.com' });
    assert.deepEqual(find(z, 'example.com', 'MX').data, { preference: 10, exchange: 'mail.example.com' });
    assert.deepEqual(find(z, 'example.com', 'TXT').data, ['v=spf1 ip4:198.51.100.25 include:_spf.example.net ~all']);
    assert.deepEqual(find(z, '_acme-challenge.example.com').data, ['unquoted-legacy-token-0123456789']);
    assert.equal(find(z, '_acme-challenge.example.com').ttl, 120);
    assert.equal(find(z, 'old.dev.example.com').occludedBy, 'delegation');
    assert.equal(find(z, 'status.example.com').flattenCname, true);
    assert.equal(find(z, 'dev.example.com', 'NS').comment, 'delegated to the dev team');
    assert.deepEqual({ ...find(z, 'api.example.com').tags }, { team: 'backend' });
    assert.equal(z.stats.proxied, 7);
  });

  test('quoted and unquoted TXT content give the same data; long unquoted content is split at 255 bytes', () => {
    const item = (content, id) => ({ id, name: 'example.com', type: 'TXT', content, ttl: 300 });
    const long = 'k'.repeat(300);
    const z = P(JSON.stringify({ result: [item('"abc def"', '1'), item('abc def', '2'), item(long, '3')] }));
    assert.deepEqual(z.records[0].data, z.records[1].data);
    assert.deepEqual(z.records[2].data.map((s) => s.length), [255, 45]);
  });

  test('SRV content fallback ("weight port target" + priority field)', () => {
    const z = P(JSON.stringify([{ name: '_x._tcp.example.com', type: 'SRV', content: '5 443 target.example.com', priority: 10, ttl: 1 }]));
    assert.deepEqual(z.records[0].data, { priority: 10, weight: 5, port: 443, target: 'target.example.com' });
    assert.equal(z.records[0].ttlAuto, true);
  });

  test('proxied is honoured only when proxiable !== false and on A/AAAA/CNAME', () => {
    const z = P(JSON.stringify([
      { name: 'a.example.com', type: 'A', content: '192.0.2.1', proxiable: false, proxied: true, ttl: 1 },
      { name: 'b.example.com', type: 'A', content: '192.0.2.2', proxied: true, ttl: 1 },
      { name: 'c.example.com', type: 'MX', content: 'mail.example.com', priority: 5, proxied: true, ttl: 1 },
      { name: 'd.example.com', type: 'A', content: '192.0.2.3', __proto__: { proxied: true }, ttl: 1 }
    ]));
    assert.deepEqual(z.records.map((r) => r.proxied), [null, true, null, false]);
    assert.equal(z.records[0].proxiable, false);
  });

  test('P13 several pasted pages: merged, de-duplicated by id, JSON_PAGES_MERGED', () => {
    const z = parseFixture(fx('cloudflare-api-pages'));
    assert.equal(z.records.length, 19);
    assert.equal(z.partial, false);
    assert.deepEqual(z.warnings.find((w) => w.code === 'JSON_PAGES_MERGED').params, { pages: 2, duplicates: 1 });
    assert.equal(new Set(z.records.map((r) => `${r.name}|${r.type}|${r.text}`)).size, 19);
  });

  test('PARTIAL_EXPORT when total_count / total_pages exceed what was pasted', () => {
    const z = parseFixture(fx('cloudflare-api-page1'));
    assert.equal(z.partial, true);
    assert.deepEqual(z.warnings.find((w) => w.code === 'PARTIAL_EXPORT').params,
      { have: 10, total: 19, pages: 1, totalPages: 2, provider: 'cloudflare' });
  });

  test('an API error body → fatal API_ERROR; malformed items → BAD_RECORD / BAD_NAME', () => {
    const e = P(JSON.stringify({ success: false, errors: [{ code: 10000, message: 'Authentication error' }], messages: [], result: null }));
    assert.equal(e.fatal.code, 'API_ERROR');
    assert.deepEqual(e.fatal.params, { message: 'Authentication error', code: 10000 });
    assert.equal(e.format, 'cloudflare-api');
    const z = P(JSON.stringify([{ name: 'ok.example.com', type: 'A', content: '192.0.2.1' }, 7, { name: 'x', type: 'BOGUS', content: '' },
      { name: 'a..b.example.com', type: 'A', content: '192.0.2.2' }, { name: 'n.example.com', type: 5, content: 'x' }]));
    assert.deepEqual(z.warnings.filter((w) => w.severity === 'error').map((w) => [w.code, w.line]),
      [['BAD_RECORD', 2], ['BAD_RECORD', 3], ['BAD_NAME', 4], ['BAD_RECORD', 5]]);
    assert.equal(z.records.length, 1);
  });

  test('zone_name, when present, names the zone (high confidence)', () => {
    const z = P(JSON.stringify([{ name: 'www.example.com', type: 'A', content: '192.0.2.1', zone_name: 'example.com' }]));
    assert.deepEqual([z.origin, z.originSource, z.originConfidence], ['example.com', 'header', 'high']);
  });
});

/* ------------------------------------------------------------------------ */

describe('Route 53 JSON and cli53', () => {
  test('aliases (provider table, ttl null), routing sets, truncation', () => {
    const z = parseFixture(fx('route53'));
    assert.deepEqual([z.origin, z.originSource], ['example.com', 'soa']);
    const aliases = z.records.filter((r) => r.alias);
    assert.deepEqual(aliases.map((r) => [r.name, r.alias.provider, r.ttl]), [
      ['example.com', 'cloudfront', null], ['api.example.com', 'elb', null], ['static.example.com', 's3-website', null],
      ['gw.example.com', 'api-gateway', null], ['www.example.com', 'same-zone', null]]);
    assert.equal(aliases[1].alias.evaluateTargetHealth, true);
    assert.equal(aliases[1].data, null);
    const policies = z.records.filter((r) => r.routing).map((r) => r.routing.policy);
    assert.deepEqual([...new Set(policies)], ['weighted', 'geolocation', 'latency', 'failover', 'multivalue']);
    assert.deepEqual(find(z, 'ha.example.com').routing, { policy: 'failover', id: 'primary', failover: 'PRIMARY', healthCheck: '11111111-2222-3333-4444-555555555555' });
    assert.equal(z.partial, true);
    assert.deepEqual(z.warnings.find((w) => w.code === 'PARTIAL_EXPORT').params, { provider: 'route53', next: 'zz.example.com.', have: 22 });
  });

  test('octal TXT escapes decode like dnswire; multi-string values', () => {
    const z = parseFixture(fx('route53'));
    assert.deepEqual(find(z, 'name\\032with\\032space.example.com').data, ['octal \u2014 escapes in TXT']);
    assert.deepEqual(z.records.filter((r) => r.name === 'example.com' && r.type === 'TXT')[1].data, ['part-one-of-a-long-value-', 'part-two']);
    const latin = P(JSON.stringify([{ Name: 'x.example.com.', Type: 'TXT', TTL: 60, ResourceRecords: [{ Value: '"ex\\344mple"' }] }]));
    assert.deepEqual(latin.records[0].data, ['exämple']);
  });

  test('bare arrays, NextToken, malformed sets', () => {
    const z = P(JSON.stringify({ ResourceRecordSets: [{ Name: 'a.example.com.', Type: 'A', TTL: 60, ResourceRecords: [{ Value: '192.0.2.1' }] },
      { Name: 'b.example.com.', Type: 'A' }, 'junk'], NextToken: 'abc' }));
    assert.equal(z.partial, true);
    assert.deepEqual(z.warnings.filter((w) => w.code === 'BAD_RECORD').map((w) => w.params.reason), ['no-values', 'not-an-object']);
    const bare = P(JSON.stringify([{ Name: 'a.example.com', Type: 'AAAA', TTL: 60, ResourceRecords: [{ Value: '2001:db8::1' }] }]));
    assert.equal(bare.format, 'route53');
    assert.equal(bare.records[0].data, '2001:db8::1');
  });

  test('cli53: AWS ALIAS pseudo-records and routing comments', () => {
    const z = parseFixture(fx('cli53'));
    const self = find(z, 'www.example.com');
    assert.deepEqual(self.alias, { target: 'api.example.com', zoneId: null, evaluateTargetHealth: false, provider: 'same-zone' });
    assert.equal(self.ttl, null);
    assert.equal(find(z, 'api.example.com').alias.provider, 'elb');
    assert.deepEqual(find(z, 'geo.example.com').routing, { policy: 'geolocation', id: 'default', geo: { countryCode: '*' } });
    assert.deepEqual(findAll(z, 'app.example.com').map((r) => r.routing.weight), [90, 10]);
  });

  test('awsAliasProvider table', () => {
    assert.equal(AWS_ALIAS_PROVIDERS.length, 7);
    const cases = [
      ['d111.cloudfront.net.', 'cloudfront'], ['dualstack.x.us-east-1.elb.amazonaws.com', 'elb'],
      ['s3-website.eu-west-1.amazonaws.com', 's3-website'], ['abc.execute-api.eu-west-1.amazonaws.com', 'api-gateway'],
      ['env.eu-west-1.elasticbeanstalk.com', 'elastic-beanstalk'], ['a1.awsglobalaccelerator.com', 'global-accelerator'],
      ['vpce-1.vpce-svc-2.us-east-1.vpce.amazonaws.com', 'vpc-endpoint'], ['www.example.com', 'same-zone'], ['other.example.net', 'other']
    ];
    for (const [t, p] of cases) assert.equal(awsAliasProvider(t, { origin: 'example.com' }), p, t);
    assert.equal(awsAliasProvider('x.example.net', { self: true }), 'same-zone');
  });
});

/* ------------------------------------------------------------------------ */

describe('octoDNS YAML', () => {
  test('fixture: apex "? \'\'", same-indent sequences, \\; unescaped, proxied / auto-ttl, dynamic pools, ignored', () => {
    const z = parseFixture(fx('example.com.yaml'));
    assert.deepEqual([z.origin, z.originSource, z.originConfidence], ['example.com', 'filename', 'low']);
    assert.equal(find(z, 'example.com', 'A').proxied, true);
    assert.equal(find(z, 'example.com', 'A').ttl, 300);
    assert.deepEqual(findAll(z, 'example.com', 'MX').map((r) => r.data), [
      { preference: 10, exchange: 'mail.example.com' }, { preference: 20, exchange: 'mx2.example.net' }]);
    assert.deepEqual(find(z, '_dmarc.example.com').data, ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']);
    assert.deepEqual(find(z, 'google._domainkey.example.com').data, ['v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAexample']);
    const api = find(z, 'api.example.com');
    assert.deepEqual([api.ttl, api.ttlAuto, api.proxied], [300, true, true]);
    assert.equal(find(z, 'admin.example.com').ttl, 3600);
    assert.deepEqual(findAll(z, 'geo.example.com').map((r) => [r.data, r.routing.id]), [
      ['198.51.100.30', null], ['198.51.100.31', 'eu'], ['198.51.100.32', 'us'], ['198.51.100.33', 'us']]);
    assert.equal(find(z, 'ignored.example.com'), undefined);
    assert.ok(codes(z).includes('OCTODNS_IGNORED'));
    assert.ok(find(z, '*.example.com', 'CNAME'));
  });

  test('unsorted keys, a bare ";" (warn), P10 quote-aware comments, flow sequences, duplicate keys', () => {
    const y = "www:\n  value: 'abc #def' # real comment\n  type: TXT\nmail:\n  values: [192.0.2.1, '192.0.2.2']\n  type: A\n" +
      'spf:\n  type: TXT\n  value: v=spf1; -all\nwww2:\n  type: A\n  value: 192.0.2.9\nwww2:\n  type: A\n  value: 192.0.2.8\n';
    const z = P(y, { filename: 'example.com.yaml' });
    assert.deepEqual(find(z, 'www.example.com').data, ['abc #def']);
    assert.deepEqual(findAll(z, 'mail.example.com').map((r) => r.data), ['192.0.2.1', '192.0.2.2']);
    assert.deepEqual(find(z, 'www2.example.com').data, '192.0.2.8');
    assert.deepEqual(z.warnings.filter((w) => w.severity !== 'info').map((w) => [w.code, w.line]), [
      ['OCTODNS_UNESCAPED_SEMICOLON', 7], ['DUPLICATE_KEY', 13]]);
  });

  test('YAML_UNSUPPORTED: anchors, aliases, tags, block scalars, flow mappings, second documents, depth', () => {
    const cases = [
      ['a: &x 1\n', 'anchor'], ['a: *x\n', 'alias'], ['a: !include b.yaml\n', 'tag'], ['a: |\n  x\n', 'block-scalar'],
      ['a: >-\n  x\n', 'block-scalar'], ['a: {b: 1}\n', 'flow-mapping'], ['a: 1\n---\nb: 2\n', 'multiple-documents'],
      ['a:\n\tb: 1\n', 'tab-indent'], ['a: [1, [2]]\n', 'nested-flow'], ['a: "open\n  still"\n', 'multi-line-scalar']
    ];
    for (const [text, feature] of cases) {
      const z = P(text, { filename: 'example.com.yaml' });
      assert.equal(z.fatal.code, 'YAML_UNSUPPORTED', text);
      assert.equal(z.fatal.params.feature, feature, text);
    }
    assert.equal(parseFixture(fx('bad-yaml-anchor')).fatal.params.line, 2);
    const deep = `${Array.from({ length: 40 }, (_, i) => `${' '.repeat(i * 2)}k${i}:`).join('\n')}\n`;
    assert.equal(P(deep, { filename: 'example.com.yaml' }).fatal.params.feature, 'depth');
    assert.equal(parseYamlSubset(deep, { limits: { maxYamlDepth: 64 } }).error, null);
  });

  test('parseYamlSubset: null-prototype maps, "? key" at the parent indent, "---" header', () => {
    const r = parseYamlSubset("---\n? ''\n: - a: 1\n    b: [x, 'y z']\n  - 2\n__proto__:\n  polluted: true\n");
    assert.equal(r.error, null);
    assert.equal(Object.getPrototypeOf(r.value), null);
    assert.deepEqual(Object.keys(r.value), ['', '__proto__']);
    assert.equal(r.value[''][0].a, 1);
    assert.deepEqual(r.value[''][0].b, ['x', 'y z']);
    assert.equal(r.value[''][1], 2);
    assert.equal(r.value.__proto__.polluted, true);
    assert.equal({}.polluted, undefined);
    assert.deepEqual(parseYamlSubset('').value, null);
  });

  test('without a zone name from the file name → ORIGIN_REQUIRED; not a mapping → NOT_A_ZONE', () => {
    assert.equal(P(readFx('example.com.yaml'), { filename: 'zone.yaml' }).fatal.code, 'ORIGIN_REQUIRED');
    assert.equal(P(readFx('example.com.yaml'), { filename: 'zone.yaml', origin: 'example.com' }).records.length, 23);
    assert.equal(P('- a\n- b\n', { filename: 'example.com.yaml' }).fatal.code, 'NOT_A_ZONE');
  });
});

/* ------------------------------------------------------------------------ */

describe('panels and dumps', () => {
  test('Plesk dns --info (format unverified)', () => {
    const z = parseFixture(fx('plesk-info'));
    assert.equal(z.records.length, 13);
    assert.ok(codes(z).includes('FORMAT_UNVERIFIED'));
    assert.deepEqual(find(z, '_dmarc.example.com').data, ['v=DMARC1; p=none']);
    assert.ok(z.records.every((r) => r.ttl === null));
  });

  test('DirectAdmin: the file-name origin is corrected by the apex NS owner', () => {
    const z = parseFixture(fx('directadmin-example.com.db'));
    assert.equal(z.origin, 'example.com');
    assert.deepEqual(z.warnings.find((w) => w.code === 'ORIGIN_CORRECTED').params, { from: 'directadmin-example.com', to: 'example.com' });
    assert.ok(find(z, 'ftp.example.com'));
  });

  test('cPanel: origin from "; Zone file for", duplicates kept with duplicateOf', () => {
    const z = parseFixture(fx('cpanel-example.com.db'));
    assert.deepEqual([z.origin, z.originSource], ['example.com', 'header']);
    const cal = findAll(z, 'cpcalendars.example.com');
    assert.equal(cal.length, 2);
    assert.equal(cal[1].duplicateOf, cal[0].id);
    assert.equal(uniqueRecords(z).length, z.records.length - 1);
  });

  test('dig AXFR: the closing SOA is not a second record', () => {
    const z = parseFixture(fx('axfr-dig'));
    assert.equal(z.records.filter((r) => r.type === 'SOA').length, 1);
    assert.ok(z.markers.includes('dig AXFR'));
    assert.equal(z.records.length, 9);
  });

  test('$GENERATE, $INCLUDE (later records parsed), unknown directives', () => {
    const edge = parseFixture(fx('bind-edge'));
    assert.deepEqual(edge.records.filter((r) => r.generated).map((r) => r.name), ['host-1.example.com', 'host-2.example.com', 'host-3.example.com']);
    assert.ok(find(edge, 'kase.example.com'), 'records after $INCLUDE are parsed');
    const inc = edge.warnings.find((w) => w.code === 'INCLUDE_REJECTED');
    assert.equal(inc.params.path, '/etc/bind/other.zone');
    // `at`: the origin the included file is read under (its argument, else the origin in effect)
    const at = (text) => P(text).warnings.filter((w) => w.code === 'INCLUDE_REJECTED').map((w) => [w.params.origin, w.params.at]);
    assert.deepEqual(at('$ORIGIN example.com.\n@ 300 A 192.0.2.1\n$INCLUDE a\n$INCLUDE b lab\n$INCLUDE c lab.example.net.\n$ORIGIN sub.example.com.\n$INCLUDE d\n'),
      [[null, 'example.com'], ['lab', 'lab.example.com'], ['lab.example.net.', 'lab.example.net'], [null, 'sub.example.com']]);
    const z = Z('$GENERATE 1-5000 h$ A 192.0.2.1\n$GENERATE 1-2 h${0,3,d} A 192.0.2.1\n$GENERATE 0-4/2 x$$y$ CNAME t$\n$FOO bar');
    assert.deepEqual(z.warnings.map((w) => w.code), ['GENERATE_TOO_LARGE', 'GENERATE_UNSUPPORTED', 'GENERATE_EXPANDED', 'UNKNOWN_DIRECTIVE']);
    // "$$" is a literal "$", presented escaped ("\$") exactly as dnswire prints a label
    assert.deepEqual(z.records.map((r) => `${r.name}>${r.data}`), ['x\\$y0.example.com>t0.example.com', 'x\\$y2.example.com>t2.example.com', 'x\\$y4.example.com>t4.example.com']);
    const total = Z('$GENERATE 1-8 a$ A 192.0.2.1\n$GENERATE 1-8 b$ A 192.0.2.1', { limits: { maxGenerateTotal: 10 } });
    assert.deepEqual(total.warnings.map((w) => w.code), ['GENERATE_EXPANDED', 'GENERATE_TOO_LARGE']);
  });

  test('internal zone parses (most addresses private)', () => {
    const z = parseFixture(fx('internal'));
    assert.equal(z.records.length, 11);
    assert.equal(z.fatal, null);
  });
});

/* ------------------------------------------------------------------------ */

describe('origin inference (critic A1)', () => {
  test('a delegation NS listed before the apex NS does not "correct" the file-name origin', () => {
    const text = 'dev.example.com. 300 IN NS ns1.example.net.\nexample.com. 300 IN NS ns1.example.net.\nwww.example.com. 300 IN A 192.0.2.10\n';
    const z = P(text, { filename: 'example.com.zone' });
    assert.equal(z.origin, 'example.com');
    assert.equal(z.originSource, 'filename');
    assert.equal(z.originConfidence, 'high');
    assert.ok(!codes(z).includes('ORIGIN_CORRECTED'));
  });

  test('only a delegation NS: never picked as the apex', () => {
    const z = P('dev.example.com. 300 IN NS ns1.example.net.\nwww.example.com. 300 IN A 192.0.2.10\napi.example.com. 300 IN A 192.0.2.20\n');
    assert.equal(z.origin, 'example.com');
    assert.equal(z.originConfidence, 'low');
  });

  test('a sub-zone export whose SOA is dev.example.com keeps dev.example.com', () => {
    const z = P('dev.example.com. 300 IN SOA ns1.example.net. host.example.net. 1 2 3 4 5\ndev.example.com. 300 IN NS ns1.example.net.\nwww.dev.example.com. 300 IN A 192.0.2.10\n', { filename: 'example.com.zone' });
    assert.equal(z.origin, 'dev.example.com');
    assert.equal(z.originSource, 'soa');
    assert.ok(codes(z).includes('ORIGIN_CORRECTED'));
  });

  test('multi-label public suffixes: example-test.com.tr (never the last two labels)', () => {
    const z = P(JSON.stringify([
      { name: 'www.example-test.com.tr', type: 'A', content: '192.0.2.1' }, { name: 'mail.example-test.com.tr', type: 'A', content: '192.0.2.2' }]));
    assert.equal(z.origin, 'example-test.com.tr');
  });

  test('an undotted SOA owner names the zone when nothing else does', () => {
    const z = P('example.com 3600 IN SOA ns1.example.com. host.example.com. 1 2 3 4 5\nwww 300 IN A 192.0.2.10\n');
    assert.deepEqual([z.origin, z.originSource], ['example.com', 'soa']);
    assert.equal(z.records[0].name, 'example.com');
    assert.equal(find(z, 'www.example.com').data, '192.0.2.10');
  });

  test('a $ORIGIN after the first record is a sub-block, not the zone apex', () => {
    const text = '$TTL 3600\n@ IN SOA ns1.example.com. h.example.com. 1 2 3 4 5\n  IN NS ns1.example.com.\n  IN MX 10 mail\nwww A 192.0.2.10\nmail A 192.0.2.25\n$ORIGIN lab.example.com.\napi A 192.0.2.30\n';
    const z = P(text, { filename: 'db.example.com' });
    assert.deepEqual([z.origin, z.originSource], ['example.com', 'filename']);
    assert.deepEqual(z.records.map((r) => `${r.name} ${r.type}`), ['example.com SOA', 'example.com NS', 'example.com MX',
      'www.example.com A', 'mail.example.com A', 'api.lab.example.com A']);
    assert.equal(find(z, 'example.com', 'MX').data.exchange, 'mail.example.com');
    assert.ok(!codes(z).some((c) => c === 'RELATIVE_WITHOUT_ORIGIN' || c === 'NO_OWNER' || c === 'OUT_OF_ZONE'));
    // an absolute SOA owner names the zone; a relative MX before the sub-block resolves under it
    const abs = P('example.com. 300 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5\nexample.com. 300 IN MX 10 mail\nwww.example.com. 300 A 192.0.2.10\n$ORIGIN lab.example.com.\napi 300 A 192.0.2.30\n');
    assert.deepEqual([abs.origin, abs.originSource, abs.originConfidence], ['example.com', 'soa', 'high']);
    assert.equal(find(abs, 'example.com', 'MX').data.exchange, 'mail.example.com');
    assert.ok(!codes(abs).some((c) => c === 'OUT_OF_ZONE' || c === 'BAD_RDATA'));
    // a header names the zone; an SRV block's $ORIGIN does not
    const hdr = P(';; Domain: example.com.\n@ 300 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5\n@ 300 IN NS ns1.example.com.\n$ORIGIN _tcp.example.com.\n_sip 300 SRV 0 5 5060 sip.example.com.\n');
    assert.deepEqual([hdr.origin, hdr.originSource], ['example.com', 'header']);
    assert.ok(find(hdr, '_sip._tcp.example.com', 'SRV'));
    assert.ok(!codes(hdr).includes('OUT_OF_ZONE'));
    // the zone name typed by the user agrees with the file: no ORIGIN_OVERRIDDEN for the sub-block
    const typed = P(text, { origin: 'example.com' });
    assert.equal(typed.records.length, 6);
    assert.ok(!codes(typed).includes('ORIGIN_OVERRIDDEN'));
  });

  test('a $ORIGIN before the first record names the zone (directives may precede it)', () => {
    const lead = P('$TTL 300\n$ORIGIN example.com.\nwww A 192.0.2.10\n$ORIGIN lab.example.com.\napi A 192.0.2.20\n');
    assert.deepEqual([lead.origin, lead.originSource, lead.originConfidence], ['example.com', '$ORIGIN', 'high']);
    assert.deepEqual(lead.records.map((r) => r.name), ['www.example.com', 'api.lab.example.com']);
  });

  test('$ORIGIN . (BIND secondary / named-compilezone / pdnsutil dumps) never makes the root the zone', () => {
    // pdnsutil list-zone: `$ORIGIN .` then absolute owners
    const pdns = P('$ORIGIN .\n$TTL 300\nexample.com. 300 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5\nexample.com. 300 IN NS ns1.example.com.\nwww.example.com. 300 IN CNAME missing.example.com.\ndev.example.com. 300 IN A 10.0.0.5\n');
    assert.deepEqual([pdns.origin, pdns.originSource, pdns.originConfidence], ['example.com', 'soa', 'high']);
    assert.ok(!codes(pdns).includes('OUT_OF_ZONE'));
    // BIND text secondary / `named-compilezone -s relative`: undotted owners under the root
    const dump = '$ORIGIN .\n$TTL 3600\nexample.com IN SOA ns1.example.com. hostmaster.example.com. (\n\t\t\t2024010101 ; serial\n\t\t\t7200 900 1209600 300 )\n\t\t\tNS ns1.example.com.\n\t\t\tA 192.0.2.10\n$ORIGIN _tcp.example.com.\n_sip\t\t\tSRV 0 5 5060 sip.example.com.\n$ORIGIN example.com.\ndev\t\t\tA 10.0.0.5\nns1\t\t\tA 192.0.2.53\nwww\t\t\tCNAME missing\n';
    const z = P(dump);
    assert.deepEqual([z.origin, z.originSource, z.originConfidence], ['example.com', 'soa', 'high']);
    assert.deepEqual(z.records.map((r) => `${r.name} ${r.type}`), ['example.com SOA', 'example.com NS', 'example.com A',
      '_sip._tcp.example.com SRV', 'dev.example.com A', 'ns1.example.com A', 'www.example.com CNAME']);
    assert.deepEqual(codes(z).filter((c) => c !== 'ORIGIN_INFERRED'), []);
    // the typed zone name agrees with the file
    const typed = P(dump, { origin: 'example.com' });
    assert.equal(typed.records.length, 7);
    assert.deepEqual(codes(typed), []);
    // no SOA: the absolute owners name the zone
    const noSoa = P('$ORIGIN .\nexample.com NS ns1.example.com.\nwww.example.com A 192.0.2.10\napi.example.com A 192.0.2.20\n');
    assert.equal(noSoa.origin, 'example.com');
    // the root zone itself stays the root
    const root = P('$ORIGIN .\n$TTL 86400\n@ IN SOA ns.example.net. hostmaster.example.net. 1 2 3 4 5\n@ IN NS ns.example.net.\nexample NS ns.example.net.\n');
    assert.equal(root.origin, '.');
  });

  test('user origin sets the initial origin; $ORIGIN still applies (ORIGIN_OVERRIDDEN)', () => {
    const z = P('www A 192.0.2.1\n$ORIGIN example.net.\nmail A 192.0.2.2\n', { origin: 'https://Example.com/' });
    assert.deepEqual([z.origin, z.originSource], ['example.com', 'user']);
    assert.deepEqual(z.records.map((r) => r.name), ['www.example.com', 'mail.example.net']);
    assert.ok(codes(z).includes('ORIGIN_OVERRIDDEN'));
    assert.ok(codes(z).includes('OUT_OF_ZONE'));
  });

  test('inferOriginFromFilename table', () => {
    const cases = [
      ['directadmin-example.com.db.txt', 'directadmin-example.com'], ['db.example.com', 'example.com'],
      ['example.com.yaml', 'example.com'], ['zone.txt', null], ['/var/named/example.com.db', 'example.com'],
      ['C:\\exports\\Example.COM.zone', 'example.com'], ['cloudflare-export.txt', null], ['inventory.csv', null],
      ['cert.pem.txt', null], ['my zone (1).txt', null], ['example-test.com.tr.json', 'example-test.com.tr'], [null, null], ['', null]
    ];
    for (const [name, want] of cases) assert.equal(inferOriginFromFilename(name), want, String(name));
  });
});

/* ------------------------------------------------------------------------ */

describe('security', () => {
  test('__proto__ / constructor / prototype keys through JSON and YAML leave Object.prototype untouched', () => {
    const j = parseFixture(fx('bad-json-proto'));
    assert.equal(j.fatal, null);
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);
    const t = find(j, 'constructor.example.com');
    assert.equal(Object.getPrototypeOf(t.tags), null);
    assert.deepEqual(Object.keys(t.tags), ['__proto__', 'constructor']);
    assert.equal(t.occludedBy, undefined, 'an inherited-looking meta.__proto__.shadowed_by is ignored');
    const y = parseFixture(fx('bad-yaml-proto'));
    assert.deepEqual(y.records.map((r) => r.name), ['__proto__.example.com', 'constructor.example.com', 'prototype.example.com']);
    assert.equal({}.polluted, undefined);
  });

  test('P14 crafted JSON never reaches Object.assign-style merging', () => {
    const z = P('{"result":[{"name":"example.com","type":"A","content":"192.0.2.1","__proto__":{"isAdmin":true,"proxied":true}}]}');
    assert.equal(z.records[0].proxied, false);
    assert.equal({}.isAdmin, undefined);
  });

  test('comments and tags escape control / bidi characters (\\DDD)', () => {
    const z = Z('www A 192.0.2.1 ; evil \u202e txt cf_tags=k:v\u200b');
    assert.equal(z.records[0].comment, 'evil \\226\\128\\174 txt');
    assert.equal(z.records[0].tags.k, 'v\\226\\128\\139');
  });
});

/* ------------------------------------------------------------------------ */

describe('helpers', () => {
  test('rdataKey round trip against dnswire decoding, every supported type', () => {
    const cases = [
      ['A', '192.0.2.1'], ['AAAA', '2001:db8::1'], ['NS', 'ns1.example.com'], ['CNAME', 'Target.Example.com'],
      ['PTR', 'host.example.com'], ['DNAME', 'other.example.net'], ['MX', { preference: 10, exchange: 'mail.example.com' }],
      ['MX', { preference: 0, exchange: '.' }], ['TXT', ['a', 'b c']], ['SPF', ['v=spf1 -all']],
      ['SOA', { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 7, refresh: 1, retry: 2, expire: 3, minimum: 4 }],
      ['SRV', { priority: 1, weight: 2, port: 443, target: 'x.example.com' }], ['CAA', { flags: 128, tag: 'Issue', value: 'ca.example' }],
      ['DS', { keyTag: 1, algorithm: 13, digestType: 2, digest: 'ABCDEF01' }], ['CDS', { keyTag: 0, algorithm: 0, digestType: 0, digest: '00' }],
      ['DNSKEY', { flags: 256, protocol: 3, algorithm: 13, publicKey: 'AQID' }], ['TLSA', { usage: 3, selector: 1, matchingType: 1, data: 'AABB' }],
      ['SSHFP', { algorithm: 4, fpType: 2, fingerprint: 'ABCD' }],
      ['HTTPS', { priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.2', '192.0.2.1'], port: 443 } }],
      ['NAPTR', { order: 1, preference: 2, flags: 'U', services: 'E2U+sip', regexp: '!x!y!', replacement: '.' }],
      ['URI', { priority: 1, weight: 2, target: 'https://example.com/' }], ['HINFO', { cpu: 'a', os: 'b' }],
      ['OPENPGPKEY', new Uint8Array([1, 2, 3])], ['RP', new Uint8Array([...encodeName('admin.example.com'), ...encodeName('info.example.com')])],
      ['AFSDB', new Uint8Array([0, 1, ...encodeName('afs.example.com')])], ['KX', new Uint8Array([0, 10, ...encodeName('kx.example.com')])]
    ];
    for (const [type, data] of cases) {
      const live = viaWire(type, data);
      const file = Z(`x ${type} ${live.text}`).records[0];
      assert.equal(file.data === null, false, `${type} parses its own presentation`);
      assert.equal(rdataKey(type, file.data), rdataKey(type, live.data), type);
      assert.equal(file.text, live.text, type);
    }
    assert.equal(rdataKey('HTTPS', { priority: 1, target: '.', params: { ipv4hint: ['192.0.2.2', '192.0.2.1'] } }),
      rdataKey('HTTPS', { priority: 1, target: '', params: { ipv4hint: ['192.0.2.1', '192.0.2.2'] } }), 'hints are a set');
  });

  test('rdataKey: root "." equals "", case and trailing dots do not matter, hex is case-insensitive', () => {
    assert.equal(rdataKey('NS', '.'), rdataKey('NS', ''));
    assert.equal(rdataKey('CNAME', 'WWW.Example.com.'), rdataKey('CNAME', 'www.example.com'));
    assert.equal(rdataKey('MX', { preference: 0, exchange: '.' }), rdataKey('MX', { preference: 0, exchange: '' }));
    assert.equal(rdataKey('DS', { keyTag: 1, algorithm: 8, digestType: 2, digest: 'ABCD' }), rdataKey('DS', { keyTag: 1, algorithm: 8, digestType: 2, digest: 'abcd' }));
    assert.equal(rdataKey('A', null), '');
    assert.equal(rdataKey('SOA', { serial: 5 }), '5');
    assert.equal(rdataKey('TYPE65534', '0A000001'), '0a000001');
    assert.notEqual(rdataKey('TXT', ['ab', 'c']), rdataKey('TXT', ['a', 'bc']));
    assert.equal(txtJoinedKey('TXT', ['ab', 'c']), txtJoinedKey('TXT', ['a', 'bc']));
    assert.equal(txtJoinedKey('A', '192.0.2.1'), '');
  });

  test('dnswire pins: presentLabel, presentCharString and decodeUtf8Lenient equal the decoder output', () => {
    const labels = [[0x41, 0x2e, 0x5c, 0x22, 0x28, 0x29, 0x3b, 0x40, 0x24, 0x2a, 0x20, 0x00, 0x7f, 0xc3, 0xa4], [0x5f, 0x74, 0x63, 0x70]];
    const wire = [];
    for (const l of labels) wire.push(l.length, ...l);
    wire.push(0);
    const rr = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'CNAME', rdata: new Uint8Array(wire) }] })).answers[0];
    assert.equal(rr.data, labels.map(presentLabel).join('.'));
    const strings = [utf8('plain'), utf8('quote " back \\ käse'), new Uint8Array([0xe4, 0x00, 0x1b, 0x7f]), utf8('bidi \u202e zw \u200b'), new Uint8Array(0)];
    const txtWire = [];
    for (const s of strings) txtWire.push(s.length, ...s);
    const txt = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'TXT', rdata: new Uint8Array(txtWire) }] })).answers[0];
    assert.equal(txt.text, strings.map(presentCharString).join(' '));
    assert.deepEqual(txt.data, strings.map(decodeUtf8Lenient));
  });

  test('decodeEscapes: decimal vs octal, literal escapes, invalid values', () => {
    assert.deepEqual([...decodeEscapes('\\052').bytes], [52]);
    assert.deepEqual([...decodeEscapes('\\052', { base: 8 }).bytes], [42]);
    assert.equal(decodeEscapes('\\089', { base: 8 }).ok, false);
    assert.equal(decodeEscapes('\\256').ok, false);
    assert.deepEqual([...decodeEscapes('a\\;b\\\\').bytes], [97, 59, 98, 92]);
    assert.deepEqual([...decodeEscapes('ä').bytes], [0xc3, 0xa4]);
    assert.equal(decodeEscapes('x\\').ok, false);
    assert.deepEqual([...decodeEscapes('\\12x').bytes], [49, 50, 120], '\\1 then "2x": fewer than three digits is a literal escape');
  });

  test('toBindText: canonical text parses back to the same records (idempotent after one round)', () => {
    for (const f of FIXTURES) {
      const z = parseFixture(f);
      if (z.fatal) continue;
      const text1 = toBindText(z);
      const z2 = parseZone(text1, { filename: 'roundtrip.zone' });
      assert.equal(z2.fatal, null, f.id);
      // Route 53 routing survives as cli53 comments; octoDNS dynamic / geo pools have no BIND form
      const routingId = (r) => (r.routing && r.routing.policy !== 'dynamic' && r.routing.policy !== 'geo' ? r.routing.id : '');
      const key = (r) => `${r.name}|${r.type}|${r.alias ? `alias:${r.alias.target}:${r.alias.provider}` : rdataKey(r.type, r.data)}|${r.proxied}|${routingId(r)}`;
      const valid = (zz) => zz.records.filter((r) => r.data !== null || r.alias).map(key).sort();
      assert.deepEqual(valid(z2), valid(z), f.id);
      assert.equal(z2.origin, z.origin, f.id);
      const text2 = toBindText(z2);
      const text3 = toBindText(parseZone(text2, { filename: 'roundtrip.zone' }));
      assert.equal(text3, text2, f.id);
    }
    const cf = toBindText(parseFixture(fx('cloudflare-export')));
    assert.match(cf, /^tagged\.example\.com\. 300 IN A 192\.0\.2\.40 ; note with cf_tags= as text cf_tags=owner:"ops, eu",cf-proxied:true$/m);
    assert.match(toBindText(parseFixture(fx('bind-edge'))), /^; not exported \(invalid\): x\.example\.com\. 3600 IN A 999\.1\.1\.1$/m);
    assert.equal(toBindText({ records: [] }, { header: false }), '\n');
  });

  test('uniqueRecords and zoneNames', () => {
    const z = parseFixture(fx('bind-edge'));
    assert.equal(uniqueRecords(z).length, z.records.length - 1);
    const names = zoneNames(z);
    assert.equal(names[0], 'example.com');
    assert.equal(new Set(names).size, names.length);
    assert.deepEqual(uniqueRecords(null), []);
    assert.deepEqual(zoneNames({}), []);
  });

  test('wildcardCovers: closest encloser, empty non-terminals exist (B1)', () => {
    const z = parseFixture(fx('cloudflare-export'));
    assert.equal(wildcardCovers(z, 'x7.apps.example.com'), '*.apps.example.com');
    assert.equal(wildcardCovers(z, 'a.b.apps.example.com'), '*.apps.example.com');
    assert.equal(wildcardCovers(z, 'apps.example.com'), null, 'an empty non-terminal answers NODATA');
    assert.equal(wildcardCovers(z, 'www.example.com'), null);
    assert.equal(wildcardCovers(z, 'nope.example.com'), null);
    const withB = Z('*.apps A 192.0.2.20\nb.apps A 192.0.2.21');
    assert.equal(wildcardCovers(withB, 'a.b.apps.example.com'), null);
    assert.equal(wildcardCovers(withB, 'c.apps.example.com'), '*.apps.example.com');
    const edge = parseFixture(fx('bind-edge'));
    assert.equal(wildcardCovers(edge, 'new.example.com'), '*.example.com');
    assert.equal(wildcardCovers(edge, 'x.old.example.com'), null, 'old.example.com exists: *.old is absent');
    assert.equal(wildcardCovers(null, 'a'), null);
  });

  test('mergeZones: same origin merged, ids renumbered, sources kept, INCLUDE_MERGED', () => {
    const main = parseZone('$ORIGIN example.com.\n$TTL 300\n@ NS ns1\n$INCLUDE part.zone\n', { filename: 'main.zone', source: 0 });
    const part = parseZone('www A 192.0.2.10\nmail A 198.51.100.25\n', { filename: 'part.zone', origin: main.origin, defaultTtl: main.defaultTtl, source: 1 });
    const m = mergeZones([main, part]);
    assert.equal(m.fatal, null);
    assert.deepEqual(m.records.map((r) => [r.id, r.name, r.source, r.ttl]), [
      [0, 'example.com', 0, 300], [1, 'www.example.com', 1, 300], [2, 'mail.example.com', 1, 300]]);
    assert.deepEqual(m.sources.map((s) => s.name), ['main.zone', 'part.zone']);
    assert.deepEqual(m.warnings.map((w) => [w.code, w.severity]), [['INCLUDE_MERGED', 'info']]);
    assert.equal(m.stats.records, 3);
    // `lead`: the part comes first (drop order) but the main file names the merged zone
    const cp = parseZone('; Zone file for example.com\n$ORIGIN example.com.\n$TTL 300\n@ NS ns1\n', { filename: 'main.zone' });
    const own = parseZone('$ORIGIN example.com.\n$TTL 60\nwww A 192.0.2.10\n', { filename: 'part.zone' });
    const pick = (z) => [z.dialect, z.defaultTtl, z.sources.map((s) => s.name).join()];
    assert.deepEqual(pick(mergeZones([own, cp])), ['generic', 60, 'part.zone,main.zone']);
    assert.deepEqual(pick(mergeZones([own, cp], { lead: cp })), ['cpanel', 300, 'part.zone,main.zone']);
    assert.deepEqual(pick(mergeZones([own, cp], { lead: parseZone('') })), ['generic', 60, 'part.zone,main.zone'], 'not one of the zones');
  });

  test('mergeZones: origin mismatch → fatal; duplicates across files; maxRecords', () => {
    const a = parseZone('$ORIGIN example.com.\nwww 300 A 192.0.2.10\n');
    const b = parseZone('$ORIGIN example.net.\nwww 300 A 192.0.2.10\n');
    const bad = mergeZones([a, b]);
    assert.equal(bad.fatal.code, 'ORIGIN_MISMATCH');
    assert.deepEqual(bad.fatal.params.origins, ['example.com', 'example.net']);
    const dup = mergeZones([a, parseZone('$ORIGIN example.com.\nwww 300 A 192.0.2.10\n')]);
    assert.equal(dup.records[1].duplicateOf, 0);
    const cap = mergeZones([a, a, a], { limits: { maxRecords: 2 } });
    assert.equal(cap.records.length, 2);
    assert.equal(cap.partial, true);
    assert.ok(cap.warnings.some((w) => w.code === 'RECORDS_TRUNCATED'));
    assert.equal(mergeZones([]).fatal.code, 'EMPTY');
    const withFatal = mergeZones([a, parseZone('')]);
    assert.equal(withFatal.records.length, 1);
    assert.equal(withFatal.warnings[0].code, 'EMPTY');
  });

  test('mergeZones: an $INCLUDE whose file could not be parsed stays INCLUDE_REJECTED', () => {
    const main = parseZone('$ORIGIN example.com.\n$TTL 300\n@ NS ns1\n$INCLUDE part\n', { filename: 'main.zone' });
    const part = parseZone('www A 192.0.2.10\n', { filename: 'part' });
    assert.equal(part.fatal.code, 'ORIGIN_REQUIRED');
    assert.deepEqual(mergeZones([main, part]).warnings.map((w) => w.code), ['INCLUDE_REJECTED', 'ORIGIN_REQUIRED']);
  });
});

/* ------------------------------------------------------------------------ */

describe('limits', () => {
  test('maxIssues → WARNINGS_TRUNCATED (sticky codes still listed)', () => {
    const body = Array.from({ length: 20 }, (_, i) => `h${i} A 999.0.0.${i}`).join('\n');
    const z = Z(body, { limits: { maxIssues: 5 } });
    assert.equal(z.warnings.length, 6);
    assert.deepEqual(z.warnings.at(-1).params, { max: 5, dropped: 15 });
    assert.equal(z.warnings.at(-1).code, 'WARNINGS_TRUNCATED');
  });

  test('maxRecords → RECORDS_TRUNCATED, partial', () => {
    const body = Array.from({ length: 30 }, (_, i) => `h${i} A 192.0.2.${i + 1}`).join('\n');
    const z = Z(body, { limits: { maxRecords: 10 } });
    assert.equal(z.records.length, 10);
    assert.equal(z.partial, true);
    assert.deepEqual(z.warnings.map((w) => [w.code, w.params.max]), [['RECORDS_TRUNCATED', 10]]);
    const json = P(JSON.stringify(Array.from({ length: 30 }, (_, i) => ({ name: `h${i}.example.com`, type: 'A', content: '192.0.2.1' }))), { limits: { maxRecords: 5 } });
    assert.equal(json.records.length, 5);
    assert.equal(json.partial, true);
  });

  test('maxJsonDocs: extra pasted pages are cut off (RECORDS_TRUNCATED)', () => {
    const page = (i) => JSON.stringify({ result: [{ id: `r${i}`, name: `h${i}.example.com`, type: 'A', content: '192.0.2.1' }] });
    const z = P(Array.from({ length: 5 }, (_, i) => page(i)).join('\n'), { limits: { maxJsonDocs: 3 } });
    assert.equal(z.records.length, 3);
    assert.equal(z.partial, true);
    assert.ok(codes(z).includes('RECORDS_TRUNCATED'));
  });

  test('P1 performance: ~5 MB of BIND parses under 1.5 s with 20,000 records kept', () => {
    const lines = ['$ORIGIN example.com.', '$TTL 300', '@ IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300'];
    let size = 0;
    for (let i = 0; size < ZONE_LIMITS.maxChars - 200; i++) {
      const l = i % 3 === 0 ? `host${i} 300 IN A 192.0.2.${(i % 200) + 1} ; cf_tags=cf-proxied:false`
        : i % 3 === 1 ? `txt${i} IN TXT "v=spf1 ip4:198.51.100.${i % 250} -all"` : `alias${i} CNAME host${i - 2}.example.com.`;
      lines.push(l);
      size += l.length + 1;
    }
    const text = lines.join('\n');
    const t0 = performance.now();
    const z = parseZone(text);
    const ms = performance.now() - t0;
    assert.equal(z.fatal, null);
    assert.equal(z.records.length, ZONE_LIMITS.maxRecords);
    assert.equal(z.partial, true);
    assert.ok(codes(z).includes('RECORDS_TRUNCATED'));
    assert.ok(ms < budget(1500), `${Math.round(ms)} ms`);
  });
});

/* ------------------------------------------------------------------------ */

describe('regressions P1–P15 (prototype defects)', () => {
  test('P7 Route 53 \\089 is BAD_NAME, never \\000', () => {
    const z = P(JSON.stringify([{ Name: '\\089.example.com.', Type: 'A', TTL: 60, ResourceRecords: [{ Value: '192.0.2.1' }] },
      { Name: 'ok.example.com.', Type: 'A', TTL: 60, ResourceRecords: [{ Value: '192.0.2.2' }] }]));
    assert.deepEqual(z.records.map((r) => r.name), ['ok.example.com']);
    assert.ok(!z.records.some((r) => r.name.includes('\\000')));
  });

  test('P12 PEM / CSV → NOT_A_ZONE with a hint (never a silent empty zone)', () => {
    assert.deepEqual(parseFixture(fx('bad-cert.pem')).fatal.params, { hint: 'pem', samples: [] });
    assert.equal(parseFixture(fx('bad-inventory')).fatal.params.hint, 'csv');
    const junk = P('lorem ipsum dolor\nsit amet consectetur\nadipiscing elit sed\n');
    assert.deepEqual([junk.fatal.code, junk.fatal.params.hint], ['NOT_A_ZONE', 'unknown']);
  });

  test('P2 P3 P4 P5 P6 P8 P9 P10 P11 P13 P14 P15 are pinned in the sections above', () => {
    assert.ok(true);
  });
});

/* ------------------------------------------------------------------------ */

describe('parse goldens', () => {
  for (const f of FIXTURES) {
    test(`${f.id} equals expected/${f.id}.parse.golden.txt`, () => {
      const actual = formatParseGolden(parseFixture(f));
      const expected = readFileSync(goldenPath(f), 'utf8');
      if (actual !== expected) {
        assert.fail(`golden differs (run: node tests/fixtures/zones/gen-parse-golden.mjs --write)\n${unifiedDiff(expected, actual, f.id)}`);
      }
    });
  }

  test('the fixture set covers every format and dialect', () => {
    const zones = FIXTURES.map(parseFixture);
    for (const f of ZONE_FORMATS) assert.ok(zones.some((z) => z.format === f), f);
    for (const d of ZONE_DIALECTS) assert.ok(zones.some((z) => z.dialect === d), d);
    assert.ok(fixtureText(fx('cloudflare-api-pages')).includes('"page":2'));
  });
});

/* ------------------------------------------------------------------------ */

describe('fuzz (seeded) and ReDoS', () => {
  /** xorshift32; the seed is printed on failure. */
  function rng(seed) {
    let x = seed >>> 0 || 1;
    return () => {
      x ^= x << 13;
      x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5;
      x >>>= 0;
      return x / 4294967296;
    };
  }
  const INSERTS = ['"', '(', ')', '\\', ';', '$', '\u0000', '\u202e', '\n', ' ', '\t', '@', '.', '*', '{', '[', ':', '- ', "'", '#', '\\#', '$ORIGIN ', '$GENERATE 1-3 a$ A 192.0.2.$', 'cf_tags=', '"\n'];
  const bases = FIXTURES.map((f) => ({ f, text: fixtureText(f) }));

  function mutate(r, text) {
    let t = text;
    const ops = 1 + Math.floor(r() * 4);
    for (let k = 0; k < ops; k++) {
      const pos = Math.floor(r() * (t.length + 1));
      const op = Math.floor(r() * 5);
      if (op === 0) t = t.slice(0, pos) + String.fromCharCode(Math.floor(r() * 128)) + t.slice(pos + 1);
      else if (op === 1) t = t.slice(0, pos);
      else if (op === 2) t = t.slice(0, pos) + INSERTS[Math.floor(r() * INSERTS.length)] + t.slice(pos);
      else if (op === 3 && r() < 0.05) t = t.slice(0, pos) + '('.repeat(10000) + t.slice(pos);
      else t = t.slice(0, pos) + t.slice(pos + Math.floor(r() * 40));
    }
    return t;
  }

  function checkInvariants(z, label) {
    assert.ok(z && typeof z === 'object', label);
    assert.ok(z.records.length <= ZONE_LIMITS.maxRecords, label);
    const all = z.fatal ? [z.fatal, ...z.warnings] : z.warnings;
    for (const w of all) {
      assert.ok(ISSUE_CODES[w.code], `${label}: unknown code ${w.code}`);
      assert.equal(ISSUE_CODES[w.code].fatal, w === z.fatal, `${label}: ${w.code} fatal flag`);
      assert.ok(Number.isInteger(w.line) && w.line >= 0, `${label}: line ${w.line}`);
    }
    if (z.fatal) {
      assert.deepEqual(z.records, [], label);
      assert.ok(!z.fatal.params.internal, `${label}: internal error ${z.fatal.detail}`);
      return;
    }
    const textual = z.format === 'bind' || z.format === 'octodns' || z.format === 'plesk-info';
    const maxLine = textual ? z.stats.lines : Math.max(z.stats.entries, z.stats.lines);
    for (const w of z.warnings) assert.ok(w.line <= maxLine, `${label}: issue line ${w.line} > ${maxLine}`);
    for (const r of z.records) {
      assert.ok(r.line >= 0 && r.line <= maxLine, `${label}: record line ${r.line}`);
      assert.ok(!r.name.endsWith('.') || r.name === '.' || r.name.endsWith('\\.'), `${label}: trailing dot ${r.name}`);
      assert.doesNotThrow(() => encodeName(r.name), `${label}: name ${r.name}`);
      const longTxt = (r.type === 'TXT' || r.type === 'SPF') && r.data !== null && r.data.some((s) => utf8(s).length > 255);
      if (r.data !== null && !longTxt && (WRITABLE.has(r.type) || typeof r.data === 'string')) {
        assert.doesNotThrow(() => encodeMessage({ answers: [{ name: r.name, type: r.type, data: r.data }] }), `${label}: ${r.type} ${r.text}`);
      }
    }
  }

  test('2,000 mutations: never throws, invariants hold, bounded time', () => {
    const seed = Number(process.env.ZONE_FUZZ_SEED) || 0x5eed1234;
    const r = rng(seed);
    const started = performance.now();
    let worst = 0;
    for (let i = 0; i < 2000; i++) {
      const base = bases[Math.floor(r() * bases.length)];
      const text = mutate(r, base.text);
      const label = `seed=${seed} case=${i} base=${base.f.id}`;
      const t0 = performance.now();
      let z;
      try {
        z = parseZone(text, { filename: base.f.files[0].split('/').pop(), ...(base.f.opts || {}) });
      } catch (err) {
        assert.fail(`${label}: threw ${err && err.stack}`);
      }
      const ms = performance.now() - t0;
      if (text.length <= 65536) worst = Math.max(worst, ms);
      checkInvariants(z, label);
      if (!z.fatal && i % 7 === 0) {
        const again = parseZone(toBindText(z), { filename: 'fuzz.zone' });
        checkInvariants(again, `${label} (reprint)`);
      }
    }
    assert.ok(worst < budget(50), `slowest input ${worst.toFixed(1)} ms`);
    assert.ok(performance.now() - started < 20000);
  });

  test('byte-level fuzz of binary inputs', () => {
    const r = rng(0xb17e5);
    for (let i = 0; i < 300; i++) {
      const bytes = new Uint8Array(Math.floor(r() * 400));
      for (let k = 0; k < bytes.length; k++) bytes[k] = Math.floor(r() * 256);
      if (i % 3 === 0 && bytes.length > 2) {
        bytes[0] = 0xff;
        bytes[1] = 0xfe;
      }
      checkInvariants(parseZone(bytes), `bytes case ${i}`);
    }
  });

  test('ReDoS set: each pathological input finishes quickly', () => {
    const cases = {
      yamlColons: ['a:'.repeat(512 * 1024), { filename: 'example.com.yaml' }],
      yamlColonsAsBind: ['a:'.repeat(512 * 1024), {}],
      backslashes: ['\\'.repeat(1024 * 1024), {}],
      quotes: ['"'.repeat(1024 * 1024), {}],
      cfTags: [`$ORIGIN example.com.\nwww 300 A 192.0.2.1 ;${' cf_tags='.repeat(20000)}\n`, {}],
      ttlUnits: [`$ORIGIN example.com.\nwww ${'1h'.repeat(50000)}! A 192.0.2.1\n`, {}],
      parens: [`$ORIGIN example.com.\n${'a TXT ( "x"\n'.repeat(5000)}`, {}],
      deepJson: [`${'['.repeat(100000)}${']'.repeat(100000)}`, {}],
      longLabels: [`$ORIGIN example.com.\n${`${'a'.repeat(60000)} A 192.0.2.1\n`.repeat(10)}`, {}]
    };
    for (const [name, [text, opts]] of Object.entries(cases)) {
      const t0 = performance.now();
      const z = parseZone(text, opts);
      const ms = performance.now() - t0;
      checkInvariants(z, name);
      assert.ok(ms < budget(200), `${name}: ${Math.round(ms)} ms`);
    }
  });
});
