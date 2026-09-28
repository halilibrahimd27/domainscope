/**
 * lib/dmarcreport.js — DMARC aggregate reports: the minimal XML reader (entities, CDATA,
 * namespaces, a refused DTD subset, limits), the RFC 7489 schema mapping on a Google-, a
 * Microsoft- and a DMARCbis-style report, dropped files read by their content (a zip of zips and
 * gzip files, JSON TLS reports, what is neither), every report of a domain together (a report
 * dropped twice counts once), the current SPF over a fake DoH client, the four source classes
 * with their reasons and fixes (an SPF record that gives receivers a permerror included: a syntax
 * error, too many lookups, void lookups, several records), the headline verdicts and notes, and
 * the CSV rows; hostile XML read in linear time.
 * Pure Node, no network; documentation data only (tests/fixtures/mailreports).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import {
  SOURCE_CLASSES, CLASS_REASONS, FIX_CODES, DMARC_VERDICTS, DMARC_NOTES, REPORT_PROBLEMS, DMARC_CSV_COLUMNS, XML_LIMITS, DISPOSITIONS,
  XmlError, parseXml, xmlChild, xmlChildren, xmlText, looksLikeAggregate, parseAggregateReport, decodeReportText, readReportFiles,
  aggregateDmarc, spfDomainsFor, loadSpfContext, classifySources, dmarcOverview, dmarcCsvRows, SPF_MAX_DOMAINS, MAX_REPORT_FILES, READ_YIELD_MS
} from '../../assets/js/lib/dmarcreport.js';
import { crc32 } from '../../assets/js/lib/zipread.js';
import { buildIpIndex, parseInventory } from '../../assets/js/lib/inventory.js';
import { hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'mailreports');
const bytesOf = (name) => new Uint8Array(readFileSync(join(DIR, name)));
const src = (name) => readFileSync(join(DIR, 'src', name), 'utf8');
const enc = new TextEncoder();

const GOOGLE_XML = 'google.com!example.com!1790380800!1790467199.xml';
const MICROSOFT_XML = 'enterprise.protection.outlook.com!example.com!1790294400!1790380800.xml';
const BIS_XML = 'mail.example.org!example.net!1790294400!1790380799.xml';

const report = (name) => {
  const r = parseAggregateReport(src(name), { file: name });
  assert.ok(r.ok, JSON.stringify(r));
  return r.report;
};

/* ---- a fake DohClient over a table (the retire tests' shape) ------------------------------ */

function fakeDns(table, { fail = {} } = {}) {
  const calls = [];
  const response = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ecs: null, ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { signal } = {}) {
    throwIfAborted(signal);
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push(`${name}|${type}`);
    const f = fail[`${name}|${type}`] ?? fail[name];
    if (f) return response(name, type, { ok: false, rcode: null, error: f, errorKind: 'network' });
    const node = table[name];
    if (!node) return response(name, type, { rcode: 'NXDOMAIN' });
    return response(name, type, { answers: (node[type] || []).map((data) => ({ name, type, ttl: 300, data })) });
  }
  async function resolveHost(name, { signal } = {}) {
    const [a, aaaa] = await Promise.all([query(name, 'A', { signal }), query(name, 'AAAA', { signal })]);
    return hostResolutionFrom(name, a, aaaa);
  }
  return { query, resolveHost, calls };
}

/** example.com's current SPF: its own server, its MX, its own include (IPv6) and a mailing service. */
const ZONE = {
  'example.com': {
    TXT: [['v=spf1 ip4:203.0.113.25 mx include:_spf.example.com include:spf.mailer.example.net ~all']],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }]
  },
  'mx1.example.com': { A: ['203.0.113.26'] },
  '_spf.example.com': { TXT: [['v=spf1 ip6:2001:db8:25::/64 -all']] },
  'spf.mailer.example.net': { TXT: [['v=spf1 ip4:198.51.100.0/26 -all']] },
  'example.net': { TXT: [['v=spf1 ip4:192.0.2.10 -all']] }
};
const INVENTORY = 'mail01 203.0.113.25\napp02 203.0.113.99\n';

/** A small aggregate report of example.com: records [ip, count, { dkim, spf, spfResult, disposition }]. */
function smallReport(records, { p = 'none', extraPolicy = '', id = '1' } = {}) {
  const rec = ([ip, count, o = {}]) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated>
    <disposition>${o.disposition || 'none'}</disposition><dkim>${o.dkim || 'fail'}</dkim><spf>${o.spf || 'pass'}</spf></policy_evaluated></row>
    <identifiers><header_from>${o.from || 'example.com'}</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>${o.spfResult || 'pass'}</result></spf></auth_results></record>`;
  return `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>${id}</report_id>
    <date_range><begin>1790294400</begin><end>1790899200</end></date_range></report_metadata>
    <policy_published><domain>example.com</domain><p>${p}</p>${extraPolicy}</policy_published>${records.map(rec).join('')}</feedback>`;
}
const aggOf = (xml) => aggregateDmarc([parseAggregateReport(xml).report]).domains[0];

/** A stored (uncompressed) zip of [name, text] entries: a mailbox folder saved as one archive. */
function storedZip(entries) {
  const le = (v, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(v);
    else b.writeUInt32LE(v);
    return b;
  };
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [name, text] of entries) {
    const n = Buffer.from(name);
    const data = Buffer.from(text);
    const crc = crc32(data);
    const local = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0x800, 2), le(0, 2), le(0, 4), le(crc, 4), le(data.length, 4), le(data.length, 4),
      le(n.length, 2), le(0, 2), n, data]);
    central.push(Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0x800, 2), le(0, 2), le(0, 4), le(crc, 4), le(data.length, 4), le(data.length, 4),
      le(n.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), n]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.concat([le(0x06054b50, 4), le(0, 2), le(0, 2), le(entries.length, 2), le(entries.length, 2), le(cd.length, 4), le(offset, 4), le(0, 2)]);
  return new Uint8Array(Buffer.concat([...locals, cd, end]));
}

/* ---- XML ---------------------------------------------------------------------------------- */

describe('parseXml — a minimal reader for data-only XML', () => {
  test('elements, text, attributes, entities, CDATA, comments, processing instructions, namespaces', () => {
    const root = parseXml(`﻿<?xml version="1.0" encoding="UTF-8"?>
      <!-- a comment <with> a tag inside -->
      <d:feedback xmlns:d="urn:x" note='a "q" > b'>
        <org_name>Mail &amp; Co. &lt;x&gt; &#233;&#x131; &quot;&apos; &unknown;</org_name>
        <id><![CDATA[<raw> & ]]></id>
        <empty/><Empty2 a="1" />
        <?pi skipped?>
        <list><item>1</item><item>2</item></list>
      </d:feedback>`);
    assert.equal(root.name, 'feedback');
    assert.equal(root.attrs.note, 'a "q" > b');
    assert.equal(xmlText(root, 'org_name'), 'Mail & Co. <x> éı "\' &unknown;');
    assert.equal(xmlText(root, 'id'), '<raw> &');
    assert.deepEqual(xmlChildren(xmlChild(root, 'list'), 'item').map((e) => e.text), ['1', '2']);
    assert.equal(xmlChild(root, 'empty2').attrs.a, '1', 'names are lowercased, attributes kept as written');
    assert.equal(xmlText(root, 'missing'), '');
    assert.equal(xmlChild(null, 'x'), null);
  });

  test('a DOCTYPE without an internal subset is skipped; one with it is refused, so no entity is ever expanded', () => {
    assert.equal(parseXml('<!DOCTYPE feedback SYSTEM "feedback.dtd"><feedback/>').name, 'feedback');
    const bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><feedback>&lol2;</feedback>';
    assert.throws(() => parseXml(bomb), (err) => err instanceof XmlError && err.code === 'doctype');
    const xxe = '<!DOCTYPE feedback [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>';
    assert.throws(() => parseXml(xxe), (err) => err.code === 'doctype');
  });

  test('broken documents are named: mismatch, unclosed, unterminated, empty, over the limits', () => {
    const code = (s, opts) => {
      try {
        parseXml(s, opts);
        return null;
      } catch (err) {
        assert.ok(err instanceof XmlError);
        return err.code;
      }
    };
    assert.equal(code('<a><b></a></b>'), 'mismatch');
    assert.equal(code('</a>'), 'mismatch');
    assert.equal(code('<a><b>'), 'unclosed');
    assert.equal(code('<a><!-- never ends'), 'unterminated');
    assert.equal(code('<a><![CDATA[ never ends'), 'unterminated');
    assert.equal(code('<a attr="no end'), 'unterminated');
    assert.equal(code('   '), 'empty');
    assert.equal(code('just text'), 'empty');
    assert.equal(code('<a><b/><b/><b/></a>', { maxElements: 3 }), 'limit');
    assert.equal(code(`${'<a>'.repeat(10)}${'</a>'.repeat(10)}`, { maxDepth: 5 }), 'limit');
    assert.ok(XML_LIMITS.maxElements >= 1000000 && Object.isFrozen(XML_LIMITS));
  });

  test('hostile markup is read in linear time: a megabyte tag with no "=", many bare names, unclosed quotes', () => {
    const cases = {
      noEquals: `<feedback><record x${'a'.repeat(1000000)}></record></feedback>`,
      spaces: `<feedback><record ${' '.repeat(1000000)}a="1"></record></feedback>`,
      bareNames: `<feedback><record ${'a '.repeat(500000)}/></feedback>`,
      equalsOnly: `<feedback><record ${'= '.repeat(500000)}/></feedback>`,
      manyTags: `<feedback>${`<x ${'a'.repeat(2000)}/>`.repeat(500)}</feedback>`,
      entities: `<feedback><x>${'&amp;'.repeat(500000)}${'&'.repeat(500000)}</x></feedback>`
    };
    for (const [name, xml] of Object.entries(cases)) {
      const t0 = performance.now();
      const root = parseXml(xml);
      const ms = performance.now() - t0;
      assert.equal(root.name, 'feedback', name);
      // A backtracking attribute pattern took seconds on 50,000 characters; the margin is for shared CI runners.
      assert.ok(ms < 1500, `${name}: ${Math.round(ms)} ms`);
    }
    assert.deepEqual(parseXml('<a b = "1" c=\'2\' d e=f g="&lt;"/>').attrs, { b: '1', c: '2', g: '<' }, 'a bare name and an unquoted value are passed over');
    const t0 = performance.now();
    assert.throws(() => parseXml(`<feedback><record a="${'x'.repeat(1000000)}`), (err) => err.code === 'unterminated');
    assert.ok(performance.now() - t0 < 1500);
  });

  test('a large report parses quickly (50,000 records)', () => {
    const rec = '<record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>';
    const xml = `<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id><date_range><begin>1790380800</begin><end>1790467199</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published>${rec.repeat(50000)}</feedback>`;
    const t0 = Date.now();
    const r = parseAggregateReport(xml);
    assert.ok(r.ok);
    assert.equal(r.report.messages, 50000);
    assert.ok(Date.now() - t0 < 5000, `${Date.now() - t0} ms`);
  });
});

/* ---- the schema ----------------------------------------------------------------------------- */

describe('parseAggregateReport — RFC 7489 Appendix C', () => {
  test('a Google-style report', () => {
    const r = report(GOOGLE_XML);
    assert.equal(r.kind, 'dmarc');
    assert.equal(r.org, 'google.com');
    assert.equal(r.email, 'noreply-dmarc-support@google.com');
    assert.equal(r.extraContact, 'https://support.google.com/a/answer/2466580');
    assert.equal(r.reportId, '4271836590127734456');
    assert.equal(r.key, 'google.com|4271836590127734456');
    assert.equal(r.begin.toISOString(), '2026-09-26T00:00:00.000Z');
    assert.equal(r.end.toISOString(), '2026-09-26T23:59:59.000Z');
    assert.deepEqual(r.policy, { domain: 'example.com', p: 'none', sp: 'none', np: 'none', pct: 100, adkim: 'r', aspf: 'r', fo: null, testing: null });
    assert.equal(r.records.length, 9);
    assert.equal(r.messages, 4078);
    assert.equal(r.skipped, 0);
    assert.equal(r.file, GOOGLE_XML);
    const fwd = r.records.find((x) => x.ip === '192.0.2.45');
    assert.deepEqual(fwd.reasons, [{ type: 'local_policy', comment: 'arc=pass as.1.example.org=pass' }]);
    assert.deepEqual(fwd.spfAuth, [{ domain: 'lists.example.org', scope: null, result: 'pass' }]);
    assert.deepEqual(fwd.dkimAuth, [{ domain: 'example.com', selector: 'mail2026', result: 'pass', human: null }]);
    assert.equal(fwd.envelopeFrom, null, 'Google leaves the envelope out');
    assert.equal(r.records.find((x) => x.ip === '2001:db8:25::10').count, 96);
  });

  test('a Microsoft-style report: a version, namespaces on the root, envelope fields, the SPF scope', () => {
    const r = report(MICROSOFT_XML);
    assert.equal(r.org, 'Enterprise Outlook');
    assert.equal(r.reportId, '8f3a2c6d1b0e4f7a9c5d2e1f0a3b4c5d');
    assert.equal(r.policy.fo, '0');
    assert.equal(r.policy.np, null);
    const own = r.records.find((x) => x.ip === '203.0.113.99');
    assert.equal(own.envelopeFrom, 'example.com');
    assert.equal(own.envelopeTo, 'example.net');
    assert.deepEqual(own.spfAuth, [{ domain: 'example.com', scope: 'mfrom', result: 'softfail' }]);
    assert.deepEqual(own.dkimAuth, [{ domain: 'example.com', selector: 'default', result: 'none', human: null }]);
    assert.equal(r.messages, 1097);
  });

  test('a DMARCbis-style report: the default namespace, np, strict alignment, no pct (100), an escaped name, CDATA', () => {
    const r = report(BIS_XML);
    assert.equal(r.org, 'Mail & Co. (example.org)');
    assert.equal(r.reportId, 'example.net-20260925');
    assert.deepEqual(r.policy, { domain: 'example.net', p: 'reject', sp: 'quarantine', np: 'reject', pct: 100, adkim: 's', aspf: 's', fo: null, testing: null });
    assert.equal(r.records[1].disposition, 'reject');
  });

  test('refused: no XML, another document, missing parts; unreadable records are skipped and counted', () => {
    assert.deepEqual(parseAggregateReport('<feedback><a></feedback>'), { ok: false, code: 'xml', detail: 'mismatch' });
    assert.deepEqual(parseAggregateReport('<rss version="2.0"/>'), { ok: false, code: 'not-dmarc', detail: 'rss' });
    assert.deepEqual(parseAggregateReport('<feedback><policy_published/></feedback>'), { ok: false, code: 'incomplete', detail: 'report_metadata' });
    const meta = '<report_metadata><org_name>x</org_name><date_range><begin>1790380800</begin><end>1790467199</end></date_range></report_metadata>';
    assert.deepEqual(parseAggregateReport(`<feedback>${meta}</feedback>`), { ok: false, code: 'incomplete', detail: 'policy_published' });
    assert.deepEqual(parseAggregateReport(`<feedback>${meta}<policy_published><p>none</p></policy_published></feedback>`), { ok: false, code: 'incomplete', detail: 'domain' });
    const rec = (ip, count, spf = 'hardfail') => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>${spf}</result></spf></auth_results></record>`;
    const r = parseAggregateReport(`<feedback>${meta.replace('<org_name>', '<report_id>7</report_id><org_name>')}<policy_published><domain>Example.COM.</domain><p>Quarantine</p><pct>30</pct></policy_published>${rec('192.0.2.1', 3)}${rec('not-an-ip', 1)}${rec('192.0.2.2', 'x')}${rec('010.0.0.1', 1)}</feedback>`);
    assert.ok(r.ok);
    assert.equal(r.report.policy.domain, 'example.com');
    assert.equal(r.report.policy.p, 'quarantine');
    assert.equal(r.report.policy.sp, 'quarantine', 'sp defaults to p');
    assert.equal(r.report.policy.pct, 30);
    assert.equal(r.report.records.length, 1);
    assert.equal(r.report.skipped, 3);
    assert.equal(r.report.records[0].spfAuth[0].result, 'fail', '"hardfail" is fail');
    // a date range in milliseconds is read as such
    const ms = parseAggregateReport(`<feedback><report_metadata><org_name>x</org_name><date_range><begin>1790380800000</begin><end>1790467199000</end></date_range></report_metadata><policy_published><domain>example.com</domain></policy_published></feedback>`);
    assert.equal(ms.report.begin.toISOString(), '2026-09-26T00:00:00.000Z');
    assert.equal(ms.report.key, `x|example.com|${Date.parse('2026-09-26T00:00:00Z')}|${Date.parse('2026-09-26T23:59:59Z')}`, 'no report id: the domain and range');
  });

  test('looksLikeAggregate: a feedback document element after the declaration and comments', () => {
    assert.ok(looksLikeAggregate(src(GOOGLE_XML)));
    assert.ok(looksLikeAggregate(src(BIS_XML)));
    assert.ok(looksLikeAggregate('<dmarc:feedback xmlns:dmarc="urn:x">'));
    assert.ok(!looksLikeAggregate('<?xml version="1.0"?><rss/>'));
    assert.ok(!looksLikeAggregate('{"policies":[]}'));
    // a DOCTYPE without an internal subset, which parseXml skips too
    assert.ok(looksLikeAggregate('<?xml version="1.0"?>\n<!DOCTYPE feedback>\n<feedback>'));
    assert.ok(looksLikeAggregate('<!DOCTYPE feedback SYSTEM "urn:a>b"><feedback>'), 'a ">" inside a quoted literal');
    assert.ok(!looksLikeAggregate('<!DOCTYPE rss><rss/>'));
  });

  test('decodeReportText: byte order marks, an XML declaration\'s encoding, UTF-8 otherwise', () => {
    assert.equal(decodeReportText(Uint8Array.of(0xef, 0xbb, 0xbf, 0x3c, 0x61, 0x2f, 0x3e)), '<a/>');
    assert.equal(decodeReportText(Uint8Array.of(0xff, 0xfe, 0x3c, 0, 0x61, 0, 0x2f, 0, 0x3e, 0)), '<a/>');
    assert.equal(decodeReportText(Uint8Array.of(0xfe, 0xff, 0, 0x3c, 0, 0x61, 0, 0x2f, 0, 0x3e)), '<a/>');
    const latin = Uint8Array.from([...enc.encode('<?xml version="1.0" encoding="ISO-8859-1"?><o>'), 0xe9, ...enc.encode('</o>')]);
    assert.equal(xmlText({ children: [parseXml(decodeReportText(latin))] }, 'o'), 'é');
    assert.equal(decodeReportText(enc.encode('<o>ş</o>')), '<o>ş</o>');
  });
});

/* ---- dropped files ----------------------------------------------------------------------- */

describe('readReportFiles — told apart by their content', () => {
  test('a mailbox export: three DMARC reports, two TLS reports, the notes file named', async () => {
    const r = await readReportFiles([{ name: 'reports-2026-09.zip', bytes: bytesOf('reports-2026-09.zip') }]);
    assert.equal(r.read, 6);
    assert.deepEqual(r.dmarc.map((x) => x.org), ['google.com', 'Enterprise Outlook', 'Mail & Co. (example.org)']);
    assert.deepEqual(r.tls.map((x) => x.org), ['Google Inc.', 'Microsoft Corporation']);
    assert.deepEqual(r.problems, [{ path: 'reports-2026-09.zip › notes.txt', code: 'not-report', detail: '' }]);
    assert.equal(r.dmarc[1].file, `reports-2026-09.zip › dmarc/${MICROSOFT_XML}.gz`);
  });

  test('single files as reporters send them: .zip, .xml.gz, .json.gz, plain XML; the progress callback', async () => {
    const seen = [];
    const r = await readReportFiles([
      { name: 'google.com!example.com!1790380800!1790467199.zip', bytes: bytesOf('google.com!example.com!1790380800!1790467199.zip') },
      { name: `${MICROSOFT_XML}.gz`, bytes: bytesOf(`${MICROSOFT_XML}.gz`).buffer },
      { name: 'google.com!example.com!1790380800!1790467199!001.json.gz', bytes: bytesOf('google.com!example.com!1790380800!1790467199!001.json.gz') },
      { name: BIS_XML, bytes: enc.encode(src(BIS_XML)) }
    ], { onProgress: (done, total) => seen.push(`${done}/${total}`) });
    assert.equal(r.dmarc.length, 3);
    assert.equal(r.tls.length, 1);
    assert.deepEqual(r.problems, []);
    assert.deepEqual(seen, ['1/4', '2/4', '3/4', '4/4']);
  });

  test('what is no report says why: another XML, bad JSON, JSON that is no TLS report, text, an empty file, a damaged archive', async () => {
    const r = await readReportFiles([
      { name: 'feed.xml', bytes: enc.encode('<rss/>') },
      { name: 'broken.json', bytes: enc.encode('{"policies": [') },
      { name: 'other.json', bytes: enc.encode('{"hello": 1}') },
      { name: 'readme.txt', bytes: enc.encode('hello') },
      { name: 'empty.xml', bytes: enc.encode('  \n') },
      { name: 'half.xml', bytes: enc.encode('<feedback><report_metadata>') },
      { name: 'cut.zip', bytes: bytesOf('reports-2026-09.zip').slice(0, 1500) },
      { name: 'r.xml.gz', bytes: new Uint8Array(gzipSync(enc.encode(src(GOOGLE_XML)))) }
    ]);
    assert.deepEqual(r.problems.map((p) => [p.path, p.code]), [
      ['feed.xml', 'not-dmarc'], ['broken.json', 'not-json'], ['other.json', 'not-tlsrpt'], ['readme.txt', 'not-report'],
      ['empty.xml', 'empty'], ['half.xml', 'xml'], ['cut.zip', 'truncated']
    ]);
    assert.equal(r.dmarc.length, 1, 'the good one still counts');
    for (const p of r.problems) assert.ok(REPORT_PROBLEMS.includes(p.code), p.code);
  });

  test('an abort rejects', async () => {
    await assert.rejects(readReportFiles([{ name: 'a.xml', bytes: enc.encode('<a/>') }], { signal: AbortSignal.abort() }), (err) => err.name === 'AbortError');
  });

  test('a zipped mailbox folder counts its reports: the bar moves per file inside it, a damaged file counts one', async () => {
    const zip = storedZip(Array.from({ length: 5 }, (_, i) => [`dmarc/r${i}.xml`, smallReport([['192.0.2.1', 1]], { id: `z${i}` })]));
    const seen = [];
    const r = await readReportFiles([
      { name: 'mailbox.zip', bytes: zip },
      { name: 'cut.zip', bytes: zip.slice(0, 40) },
      { name: 'one.xml', bytes: enc.encode(smallReport([['192.0.2.1', 1]], { id: 'one' })) }
    ], { onProgress: (done, total) => seen.push(`${done}/${total}`) });
    assert.deepEqual([r.read, r.dmarc.length, r.problems.map((p) => p.code)], [6, 6, ['truncated']]);
    assert.deepEqual(seen, ['1/7', '2/7', '3/7', '4/7', '5/7', '6/7', '7/7'], 'three dropped files, the first of them five');
  });

  test('a Stop in the middle of a zipped mailbox folder is heard between its reports; the event loop gets its turns', async () => {
    const n = 200;
    const zip = storedZip(Array.from({ length: n }, (_, i) => [`r${i}.xml`, smallReport([['192.0.2.1', 1], ['198.51.100.7', 2]], { id: `s${i}` })]));
    const ctl = new AbortController();
    const seen = [];
    // A clock that moves READ_YIELD_MS per look: every report is a long one, so the reader yields before each.
    const realNow = Date.now;
    let clock = 0;
    Date.now = () => (clock += READ_YIELD_MS);
    try {
      await assert.rejects(readReportFiles([{ name: 'mailbox.zip', bytes: zip }], {
        signal: ctl.signal,
        // The Stop is a task of its own (a click): it runs only when the reader gives the event loop a turn.
        onProgress: (done, total) => {
          seen.push(`${done}/${total}`);
          if (done === 3) setTimeout(() => ctl.abort(), 0);
        }
      }), (err) => err.name === 'AbortError');
    } finally {
      Date.now = realNow;
    }
    assert.deepEqual(seen.slice(0, 3), [`1/${n}`, `2/${n}`, `3/${n}`], 'the total is the reports inside the archive');
    assert.ok(seen.length >= 3 && seen.length < 6, `stopped right after the click, not after ${n} reports: ${seen.length}`);
  });

  test('a plain file past the entry bound is named too large, never parsed in one long task', async () => {
    const xml = smallReport(Array.from({ length: 40 }, (_, i) => [`192.0.2.${i + 1}`, 1]));
    const r = await readReportFiles([
      { name: 'big.xml', bytes: enc.encode(xml) },
      { name: 'big.zip', bytes: storedZip([['inner.xml', xml]]) },
      { name: 'small.xml', bytes: enc.encode(smallReport([['192.0.2.1', 1]], { id: 'small' })) }
    ], { limits: { maxEntryBytes: 1000 } });
    assert.ok(xml.length > 1000);
    assert.deepEqual(r.problems.map((p) => [p.path, p.code]), [['big.xml', 'too-large'], ['big.zip › inner.xml', 'too-large']]);
    assert.equal(r.dmarc.length, 1);
  });

  test('a report that starts with a DOCTYPE line is read', async () => {
    const xml = smallReport([['192.0.2.1', 1]]).replace('<?xml version="1.0"?>', '<?xml version="1.0"?>\n<!DOCTYPE feedback>\n');
    const r = await readReportFiles([{ name: 'd.xml', bytes: enc.encode(xml) }]);
    assert.deepEqual([r.dmarc.length, r.problems], [1, []]);
  });

  test(`past ${MAX_REPORT_FILES} files, the rest is named, never unpacked`, async () => {
    const xml = enc.encode(smallReport([['192.0.2.1', 1]]));
    const files = Array.from({ length: MAX_REPORT_FILES + 3 }, (_, i) => ({ name: `r${i}.xml`, bytes: xml }));
    // the last one is no zip at all: unpacked, it would be a 'not-zip' problem
    files[files.length - 1] = { name: 'last.zip', bytes: enc.encode('PK\u0003\u0004 not really') };
    const r = await readReportFiles(files);
    assert.equal(r.read, MAX_REPORT_FILES);
    assert.equal(r.dmarc.length, MAX_REPORT_FILES);
    assert.deepEqual(r.problems.map((p) => [p.path, p.code]), [[`r${MAX_REPORT_FILES}.xml`, 'too-many'], [`r${MAX_REPORT_FILES + 1}.xml`, 'too-many'], ['last.zip', 'too-many']]);
  });
});

/* ---- aggregation ----------------------------------------------------------------------------- */

describe('aggregateDmarc — a domain\'s reports together', () => {
  test('one row per address across reporters; a report dropped twice counts once; domains by volume', () => {
    const { domains, duplicates } = aggregateDmarc([report(GOOGLE_XML), report(MICROSOFT_XML), report(BIS_XML), report(GOOGLE_XML)]);
    assert.equal(duplicates, 1);
    assert.deepEqual(domains.map((d) => d.domain), ['example.com', 'example.net']);
    const d = domains[0];
    assert.deepEqual([d.reports, d.messages, d.pass, d.fail], [2, 5175, 4913, 262]);
    assert.equal(d.begin.toISOString(), '2026-09-25T00:00:00.000Z');
    assert.equal(d.end.toISOString(), '2026-09-26T23:59:59.000Z');
    assert.equal(d.days, 2);
    assert.deepEqual(d.policies, ['none']);
    assert.deepEqual(d.reporters.map((x) => [x.org, x.reports, x.messages, x.pass]), [['google.com', 1, 4078, 3885], ['Enterprise Outlook', 1, 1097, 1028]]);
    assert.equal(d.sources.length, 10);
    assert.equal(d.sources[0].ip, '198.51.100.10', 'most messages first');
    const mail01 = d.sources.find((s) => s.ip === '203.0.113.25');
    assert.deepEqual([mail01.messages, mail01.pass, mail01.records, mail01.dkimAligned, mail01.spfAligned], [1592, 1592, 2, 1592, 1592]);
    assert.deepEqual(mail01.reporters, ['google.com', 'Enterprise Outlook']);
    assert.deepEqual(mail01.spfAuth, [{ domain: 'example.com', scope: null, result: 'pass', messages: 1204 }, { domain: 'example.com', scope: 'mfrom', result: 'pass', messages: 388 }]);
    assert.deepEqual(mail01.dkimAuth, [{ domain: 'example.com', selector: 'mail2026', result: 'pass', messages: 1592 }]);
    assert.deepEqual(mail01.envelopeFrom, ['example.com']);
    assert.equal(mail01.begin.toISOString(), '2026-09-25T00:00:00.000Z');
    const spoof = d.sources.find((s) => s.ip === '192.0.2.200');
    assert.deepEqual([spoof.messages, spoof.fail, spoof.dispositions], [43, 43, { none: 43, pass: 0, quarantine: 0, reject: 0 }]);
    assert.equal(d.sources.find((s) => s.ip === '2001:db8:25::10').version, 6);
    const net = domains[1];
    assert.deepEqual(net.policy, { domain: 'example.net', p: 'reject', sp: 'quarantine', np: 'reject', pct: 100, adkim: 's', aspf: 's', fo: null, testing: null });
    assert.equal(net.sources[1].dispositions.reject, 4);
  });

  test('DMARCbis: the disposition pass is counted; a disposition that is no key of the tally is not', () => {
    const agg = aggOf(smallReport([['192.0.2.1', 5, { disposition: 'pass', dkim: 'pass' }], ['192.0.2.1', 2, { disposition: 'constructor' }],
      ['192.0.2.1', 3, { disposition: '__proto__' }], ['192.0.2.1', 1, { disposition: 'hasOwnProperty' }]]));
    const s = agg.sources[0];
    assert.deepEqual(s.dispositions, { none: 0, pass: 5, quarantine: 0, reject: 0 });
    assert.equal(s.messages, 11);
    assert.ok(Object.isFrozen(DISPOSITIONS) && DISPOSITIONS.includes('pass'));
    assert.equal(dmarcCsvRows(agg, classifySources(agg))[0].disposition_pass, 5);
  });

  test('the latest report\'s policy, every p the reports saw', () => {
    const later = report(GOOGLE_XML);
    const earlier = report(MICROSOFT_XML);
    earlier.policy.p = 'quarantine';
    const { domains } = aggregateDmarc([later, earlier]);
    assert.equal(domains[0].policy.p, 'none');
    assert.deepEqual(domains[0].policies, ['none', 'quarantine']);
  });

  test('spfDomainsFor: the header-from domains and the aligned SPF domains, by volume, capped', () => {
    const { domains } = aggregateDmarc([report(GOOGLE_XML), report(MICROSOFT_XML)]);
    assert.deepEqual(spfDomainsFor(domains[0]), ['example.com']);
    const agg = {
      domain: 'example.com',
      sources: [{ messages: 5, headerFrom: ['news.example.com'], spfAuth: [{ domain: 'bounce.example.com', messages: 5 }, { domain: 'esp.example.net', messages: 5 }] }]
    };
    assert.deepEqual(spfDomainsFor(agg), ['bounce.example.com', 'news.example.com', 'example.com']);
    const many = { domain: 'example.com', sources: Array.from({ length: 20 }, (_, i) => ({ messages: i, headerFrom: [`h${i}.example.com`], spfAuth: [] })) };
    assert.equal(spfDomainsFor(many).length, SPF_MAX_DOMAINS);
    // A report may name any header_from: only the policy domain's organisation is ever looked up.
    const crafted = {
      domain: 'example.com',
      sources: [{ messages: 99, headerFrom: ['victim.example.net', 'mail.example.com'], spfAuth: [{ domain: 'victim.example.net', messages: 99 }, { domain: 'bounce.example.org', messages: 99 }] }]
    };
    assert.deepEqual(spfDomainsFor(crafted), ['mail.example.com', 'example.com']);
  });
});

/* ---- the current SPF ------------------------------------------------------------------------ */

describe('loadSpfContext — the domain\'s SPF, expanded once', () => {
  test('ok: the tree, the record, the mx hosts\' addresses', async () => {
    const dns = fakeDns(ZONE);
    const c = await loadSpfContext('example.com', { dns, now: () => new Date(0) });
    assert.equal(c.status, 'ok');
    assert.equal(c.record, ZONE['example.com'].TXT[0][0]);
    assert.deepEqual([...c.mxAddresses], [['mx1.example.com', { addresses: ['203.0.113.26'], error: null }]]);
    assert.equal(c.at.getTime(), 0);
    assert.ok(dns.calls.every((q) => /\|(TXT|MX|A|AAAA)$/.test(q)), 'names and types only');
  });

  test('none, several records, a lookup that failed here, a failing mx host', async () => {
    const dns = fakeDns({ ...ZONE, 'dup.example.org': { TXT: [['v=spf1 -all'], ['v=spf1 ~all']] }, 'mx.example.org': { TXT: [['v=spf1 mx -all']], MX: [{ preference: 1, exchange: 'down.example.org' }] } },
      { fail: { 'fail.example.org|TXT': 'timeout', 'down.example.org': 'timeout' } });
    assert.equal((await loadSpfContext('nothing.example.org', { dns })).status, 'none');
    assert.equal((await loadSpfContext('dup.example.org', { dns })).status, 'multiple');
    const f = await loadSpfContext('fail.example.org', { dns });
    assert.deepEqual([f.status, f.error], ['failed', 'timeout']);
    const m = await loadSpfContext('mx.example.org', { dns });
    assert.equal(m.status, 'ok');
    assert.equal(m.mxAddresses.get('down.example.org').addresses.length, 0);
    assert.ok(m.mxAddresses.get('down.example.org').error);
    // "Check again": every query past the client's cache
    const seen = [];
    const spy = { query: (n, type, o) => { seen.push(o.noCache === true); return dns.query(n, type, o); }, resolveHost: (n, o) => { seen.push(o.noCache === true); return dns.resolveHost(n, o); } };
    assert.equal((await loadSpfContext('mx.example.org', { dns: spy, noCache: true })).status, 'ok');
    assert.ok(seen.length >= 3 && seen.every(Boolean), JSON.stringify(seen));
    await assert.rejects(loadSpfContext('bad name', { dns }), TypeError);
    await assert.rejects(loadSpfContext('example.com', { dns, signal: AbortSignal.abort() }), (err) => err.name === 'AbortError');
  });
});

/* ---- classification ------------------------------------------------------------------------- */

async function classified({ withSpf = true, withInventory = true } = {}) {
  const { domains } = aggregateDmarc([report(GOOGLE_XML), report(MICROSOFT_XML)]);
  const agg = domains[0];
  const spf = new Map();
  if (withSpf) {
    const dns = fakeDns(ZONE);
    for (const d of spfDomainsFor(agg)) spf.set(d, await loadSpfContext(d, { dns }));
  }
  const index = withInventory ? buildIpIndex(parseInventory(INVENTORY).servers) : new Map();
  const rows = classifySources(agg, { spf, index });
  return { agg, rows, by: Object.fromEntries(rows.map((r) => [r.ip, r])) };
}
const brief = (r) => [r.cls, r.reason, r.detail];

describe('classifySources — yours, authorized third parties, forwarders, unknown senders', () => {
  test('with the current SPF and the server list', async () => {
    const { by } = await classified();
    assert.deepEqual(brief(by['203.0.113.25']), ['yours', 'inventory', 'mail01']);
    assert.deepEqual(brief(by['203.0.113.99']), ['yours', 'inventory', 'app02'], 'in the list, not in SPF');
    assert.deepEqual(brief(by['203.0.113.26']), ['yours', 'spf', 'mx']);
    assert.deepEqual(by['203.0.113.26'].spfNow.via, { host: 'mx1.example.com', address: '203.0.113.26' });
    assert.deepEqual(brief(by['2001:db8:25::10']), ['yours', 'spf', 'ip6:2001:db8:25::/64'], 'an include of its own organisation');
    assert.deepEqual(brief(by['198.51.100.10']), ['third-party', 'spf-include', 'spf.mailer.example.net']);
    assert.deepEqual(brief(by['198.51.100.20']), ['third-party', 'spf-include', 'spf.mailer.example.net']);
    assert.deepEqual(brief(by['192.0.2.44']), ['forwarder', 'dkim-forwarded', 'mail2026'], 'carries the selector mail01 signs with');
    assert.deepEqual(brief(by['192.0.2.45']), ['forwarder', 'forwarded', 'local_policy'], 'arc=pass override');
    assert.deepEqual(brief(by['198.51.100.200']), ['unknown', 'foreign', 'crm.example.net']);
    assert.deepEqual(brief(by['192.0.2.200']), ['unknown', 'none', null]);
    assert.equal(by['192.0.2.200'].spfNow.result, 'softfail');
    assert.equal(by['192.0.2.200'].spfDomain, 'example.com');
  });

  test('what a known source that fails DMARC needs', async () => {
    const { by, rows } = await classified();
    assert.deepEqual(by['198.51.100.20'].fixes, ['dkim-align', 'spf-align'], 'signs and bounces as the service itself');
    assert.deepEqual(by['203.0.113.99'].fixes, ['dkim-sign', 'spf-add']);
    assert.deepEqual(rows.filter((r) => r.fixes.length).map((r) => r.ip).sort(), ['198.51.100.20', '203.0.113.99']);
    for (const r of rows) for (const f of r.fixes) assert.ok(FIX_CODES.includes(f), f);
  });

  test('without SPF: an aligned SPF pass in the reports counts as yours; without the list, your server is unknown', async () => {
    const { by } = await classified({ withSpf: false, withInventory: false });
    assert.deepEqual(brief(by['203.0.113.26']), ['yours', 'spf-report', null]);
    assert.deepEqual(brief(by['198.51.100.10']), ['yours', 'spf-report', null]);
    assert.equal(by['203.0.113.26'].spfNow, null);
    assert.deepEqual(brief(by['203.0.113.99']), ['unknown', 'none', null]);
    assert.deepEqual(brief(by['192.0.2.44']), ['forwarder', 'dkim-forwarded', 'mail2026']);
  });

  test('a sender SPF passed in the reports that the current SPF no longer authorizes; a DKIM service with its own bounce domain', () => {
    const src0 = {
      ip: '192.0.2.77', version: 4, private: false, messages: 10, pass: 10, fail: 0, dkimAligned: 0, spfAligned: 10,
      dispositions: { none: 10, quarantine: 0, reject: 0 }, headerFrom: ['example.com'], envelopeFrom: [], overrides: [],
      spfAuth: [{ domain: 'example.com', scope: null, result: 'pass', messages: 10 }], dkimAuth: [], reporters: ['x'], records: 1, begin: null, end: null
    };
    const esp = {
      ...src0, ip: '198.51.100.130', dkimAligned: 10, spfAligned: 0,
      spfAuth: [{ domain: 'bounce.esp.example.net', scope: null, result: 'pass', messages: 10 }],
      dkimAuth: [{ domain: 'example.com', selector: 'esp1', result: 'pass', messages: 10 }]
    };
    const ctx = { status: 'ok', tree: { domain: 'example.com', record: 'v=spf1 -all', errors: [], terms: [{ term: '-all', mechanism: 'all', qualifier: '-' }] }, mxAddresses: new Map() };
    const rows = classifySources({ domain: 'example.com', sources: [src0, esp] }, { spf: new Map([['example.com', ctx]]) });
    assert.deepEqual(brief(rows[0]), ['unknown', 'spf-removed', 'fail']);
    assert.deepEqual(brief(rows[1]), ['third-party', 'dkim-service', 'bounce.esp.example.net']);
    // a failed SPF lookup is "cannot tell", so the reports' own evidence stands
    const failed = classifySources({ domain: 'example.com', sources: [src0] }, { spf: new Map([['example.com', { status: 'failed', tree: null, mxAddresses: new Map() }]]) });
    assert.deepEqual(brief(failed[0]), ['yours', 'spf-report', null]);
    assert.equal(failed[0].spfNow.reason, 'lookup-failed');
  });

  test('an SPF record that passes every address (+all) tells no sender apart: DKIM and the reports decide, and the overview says so', async () => {
    const { domains } = aggregateDmarc([report(GOOGLE_XML)]);
    const agg = domains[0];
    const dns = fakeDns({ 'example.com': { TXT: [['v=spf1 +all']] } });
    const spf = new Map([['example.com', await loadSpfContext('example.com', { dns })]]);
    const rows = classifySources(agg, { spf });
    const by = Object.fromEntries(rows.map((r) => [r.ip, r]));
    assert.equal(by['192.0.2.200'].spfNow.term, '+all');
    assert.deepEqual(brief(by['192.0.2.200']), ['unknown', 'none', null], 'a spoofer is no server of yours because +all passes it');
    assert.deepEqual(brief(by['203.0.113.26']), ['unknown', 'none', null], 'nor is a sender with SPF only');
    assert.deepEqual(brief(by['192.0.2.44']), ['forwarder', 'dkim-only', 'mail2026'], 'DKIM still decides');
    // DKIM and SPF both aligned for all its mail: a direct sender (forwarding breaks SPF), never a forwarder
    assert.deepEqual(brief(by['203.0.113.25']), ['yours', 'dkim-signed', 'mail2026']);
    assert.deepEqual(brief(by['2001:db8:25::10']), ['yours', 'dkim-signed', 'mail2026']);
    assert.ok(dmarcOverview(agg, rows).notes.includes('spf-all'));
    assert.ok(!dmarcOverview(agg, classifySources(agg)).notes.includes('spf-all'));
  });

  test('an SPF record that gives receivers a permerror: whom it lists still decides the class; the fix names the record', async () => {
    const classify = async (table, xml) => {
      const agg = aggOf(xml);
      const spf = new Map([['example.com', await loadSpfContext('example.com', { dns: fakeDns(table) })]]);
      const rows = classifySources(agg, { spf });
      return { agg, rows, by: Object.fromEntries(rows.map((r) => [r.ip, r])), o: dmarcOverview({ ...agg, days: 30 }, rows) };
    };
    // (a) eleven includes: a third party listed in the 11th fails SPF with a permerror at receivers
    const eleven = { 'example.com': { TXT: [[`v=spf1 ip4:203.0.113.25 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(' ')} -all`]] } };
    for (let i = 0; i < 11; i += 1) eleven[`s${i}.example.net`] = { TXT: [[`v=spf1 ip4:198.51.100.${i} -all`]] };
    const xml = smallReport([['203.0.113.25', 500, { spf: 'pass' }], ['198.51.100.10', 80, { spf: 'fail', spfResult: 'permerror' }]]);
    const a = await classify(eleven, xml);
    assert.deepEqual(brief(a.by['198.51.100.10']), ['third-party', 'include-listed', 's10.example.net']);
    assert.deepEqual([a.by['198.51.100.10'].spfNow.result, a.by['198.51.100.10'].spfNow.reason, a.by['198.51.100.10'].spfListed.result], ['permerror', 'lookup-limit', 'pass']);
    assert.deepEqual(a.by['198.51.100.10'].fixes, ['spf-permerror', 'dkim-sign'], 'the record first; never spf-add: it is listed');
    assert.deepEqual(brief(a.by['203.0.113.25']), ['yours', 'spf', 'ip4:203.0.113.25'], 'matched before the limit');
    assert.equal(a.o.verdict, 'fix-first');
    assert.deepEqual(a.o.spfError, { domain: 'example.com', reason: 'lookup-limit', sources: 1 });
    assert.ok(a.o.notes.includes('spf-permerror'));

    // (b) three void lookups in front of the domain's own server
    const voids = { 'example.com': { TXT: [['v=spf1 a:v1.example.com a:v2.example.com a:v3.example.com ip4:203.0.113.25 -all']] } };
    const b = await classify(voids, smallReport([['203.0.113.25', 500]]));
    assert.deepEqual(brief(b.by['203.0.113.25']), ['yours', 'spf-listed', 'ip4:203.0.113.25']);
    assert.equal(b.by['203.0.113.25'].spfNow.reason, 'void-limit');

    // (c) a syntax error: every address gets a permerror. The domain's own server passed SPF in the
    // reports, through SPF alone: that mail fails from now on, so the verdict is no "ready".
    const syntax = { 'example.com': { TXT: [['v=spf1 ip4:203.0.113.25 foo:bar -all']] } };
    const c = await classify(syntax, smallReport([['203.0.113.25', 500], ['192.0.2.200', 40, { spf: 'fail', spfResult: 'permerror' }]]));
    assert.deepEqual(brief(c.by['203.0.113.25']), ['yours', 'spf-listed', 'ip4:203.0.113.25'], 'never "unknown sender"');
    assert.deepEqual([c.by['203.0.113.25'].atRisk, c.by['203.0.113.25'].fixes], [500, ['spf-permerror', 'dkim-sign']]);
    assert.deepEqual(brief(c.by['192.0.2.200']), ['unknown', 'none', null], 'the record does not list it either');
    assert.equal(c.o.verdict, 'spf-broken');
    assert.deepEqual([c.o.blockers.length, c.o.atRisk.map((r) => r.ip), c.o.atRiskMessages], [0, ['203.0.113.25'], 500]);
    assert.deepEqual(c.o.spfError, { domain: 'example.com', reason: 'syntax', sources: 2 });
    assert.deepEqual(c.o.notes, ['spf-permerror']);
    assert.equal(c.o.enforced, false, 'p=none: that mail fails from now on, nothing refuses it yet');
    // (d) p=reject in force, and one include too many pushes the domain's own server past the 10th
    // lookup (a common incident): its mail that passed through SPF alone is refused now
    const past = { 'example.com': { TXT: [[`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(' ')} ip4:203.0.113.25 -all`]] } };
    for (let i = 0; i < 11; i += 1) past[`s${i}.example.net`] = eleven[`s${i}.example.net`];
    const d = await classify(past, smallReport([['203.0.113.25', 500]], { p: 'reject' }));
    assert.deepEqual([d.by['203.0.113.25'].spfNow.reason, ...brief(d.by['203.0.113.25'])], ['lookup-limit', 'yours', 'spf-listed', 'ip4:203.0.113.25']);
    assert.deepEqual([d.o.verdict, d.o.enforced, d.o.compliance, d.o.fail, d.o.atRiskMessages], ['spf-broken', true, 1, 0, 500], 'every message passed in the reports');
    const tested = await classify(past, smallReport([['203.0.113.25', 500]], { p: 'reject', extraPolicy: '<testing>y</testing>' }));
    assert.deepEqual([tested.o.verdict, tested.o.enforced], ['spf-broken', false], 'p=reject in test mode is not in force');
    // with DKIM aligned as well, nothing rests on SPF alone: ready, the note still says the record errs
    const signed = await classify(syntax, smallReport([['203.0.113.25', 500, { dkim: 'pass' }]]));
    assert.deepEqual([signed.by['203.0.113.25'].atRisk, signed.o.verdict, signed.o.notes], [0, 'ready', ['spf-permerror']]);

    // several SPF records leave no tree to ask: the reports' own evidence decides, as for a failed lookup
    const two = { 'example.com': { TXT: [['v=spf1 ip4:203.0.113.25 -all'], ['v=spf1 -all']] } };
    const m = await classify(two, smallReport([['203.0.113.25', 500]]));
    assert.deepEqual(brief(m.by['203.0.113.25']), ['yours', 'spf-report', null]);
    assert.deepEqual([m.by['203.0.113.25'].spfNow.reason, m.by['203.0.113.25'].fixes, m.o.verdict], ['multiple-records', ['spf-permerror', 'dkim-sign'], 'spf-broken']);
    const csv = dmarcCsvRows(m.agg, m.rows)[0];
    assert.deepEqual([csv.spf_now, csv.spf_now_reason], ['permerror', 'multiple-records']);
  });

  test('vocabularies are frozen and every class and reason is reachable', () => {
    for (const v of [SOURCE_CLASSES, CLASS_REASONS, FIX_CODES, DMARC_VERDICTS, DMARC_NOTES, REPORT_PROBLEMS, DMARC_CSV_COLUMNS]) assert.ok(Object.isFrozen(v));
    assert.deepEqual(SOURCE_CLASSES, ['yours', 'third-party', 'forwarder', 'unknown']);
  });
});

/* ---- the headline ----------------------------------------------------------------------------- */

describe('dmarcOverview — compliance, what blocks p=reject, what to fix first', () => {
  test('fix-first: the failing known sources, most failing messages first; the unknown senders apart', async () => {
    const { agg, rows } = await classified();
    const o = dmarcOverview(agg, rows);
    assert.equal(o.verdict, 'fix-first');
    assert.equal(o.messages, 5175);
    assert.equal(Math.round(o.compliance * 1000), 949);
    assert.deepEqual(o.blockers.map((r) => [r.ip, r.fail]), [['198.51.100.20', 120], ['203.0.113.99', 57]]);
    assert.equal(o.blocked, 177);
    assert.deepEqual(o.unknown.map((r) => [r.ip, r.fail]), [['192.0.2.200', 43], ['198.51.100.200', 42]]);
    assert.equal(o.unknownFail, 85);
    assert.deepEqual(o.byClass.yours, { sources: 4, messages: 2055, pass: 1998 });
    assert.deepEqual(o.byClass['third-party'], { sources: 2, messages: 3010, pass: 2890 });
    assert.deepEqual(o.byClass.forwarder, { sources: 2, messages: 25, pass: 25 });
    assert.deepEqual(o.byClass.unknown, { sources: 2, messages: 85, pass: 0 });
    assert.deepEqual(o.notes, ['short-range']);
  });

  test('ready, enforced, no mail; the notes', async () => {
    const { agg, rows } = await classified();
    const clean = rows.filter((r) => !['198.51.100.20', '203.0.113.99'].includes(r.ip));
    assert.equal(dmarcOverview(agg, clean).verdict, 'ready');
    const q = { ...agg, policy: { ...agg.policy, p: 'quarantine', pct: 50 }, policies: ['quarantine', 'none'], days: 30 };
    assert.deepEqual(dmarcOverview(q, clean, { spfChecked: false }).notes, ['pct', 'mixed-policy', 'spf-unknown']);
    assert.deepEqual(dmarcOverview({ ...q, policy: { ...q.policy, pct: 100 }, policies: ['quarantine'] }, clean).notes, ['quarantine']);
    const rejected = rows.map((r) => (r.ip === '203.0.113.99' ? { ...r, dispositions: { none: 0, quarantine: 0, reject: r.fail } } : r));
    const enforced = dmarcOverview({ ...agg, policy: { ...agg.policy, p: 'reject' }, days: 30 }, rejected);
    assert.deepEqual([enforced.verdict, enforced.enforced], ['enforced', true]);
    assert.deepEqual(enforced.notes, ['rejected-now']);
    assert.equal(enforced.blockers.length, 2, 'legitimate mail rejected now');
    // DMARCbis test mode: p=reject with t=y is not in force yet
    const testing = dmarcOverview({ ...agg, policy: { ...agg.policy, p: 'reject', testing: 'y' }, days: 30 }, clean);
    assert.deepEqual([testing.verdict, testing.notes, testing.enforced], ['ready', ['testing'], false]);
    assert.equal(dmarcOverview({ ...agg, policy: { ...agg.policy, p: 'reject', pct: 50 }, days: 30 }, clean).enforced, false, 'pct under 100');
    const quarantineTest = dmarcOverview({ ...agg, policy: { ...agg.policy, p: 'quarantine', testing: 'y' }, days: 30 }, clean);
    assert.deepEqual(quarantineTest.notes, ['testing'], 'no "next step is p=reject" while quarantine is only tested');
    const none = dmarcOverview({ ...agg, messages: 0, pass: 0, sources: [] }, []);
    assert.equal(none.verdict, 'no-mail');
    assert.equal(none.compliance, null);
    for (const v of ['fix-first', 'ready', 'enforced', 'no-mail', 'spf-broken']) assert.ok(DMARC_VERDICTS.includes(v));
  });
});

/* ---- CSV -------------------------------------------------------------------------------------- */

test('dmarcCsvRows: one row per source with every column', async () => {
  const { agg, rows } = await classified();
  const out = dmarcCsvRows(agg, rows);
  assert.equal(out.length, 10);
  for (const row of out) assert.deepEqual(Object.keys(row), [...DMARC_CSV_COLUMNS]);
  const r = out.find((x) => x.source_ip === '198.51.100.20');
  assert.deepEqual([r.class, r.reason, r.detail, r.messages, r.dmarc_fail, r.spf_now, r.spf_now_term, r.fixes], [
    'third-party', 'spf-include', 'spf.mailer.example.net', 120, 120, 'pass', 'ip4:198.51.100.0/26', 'dkim-align spf-align'
  ]);
  assert.equal(r.dkim_results, 'mailer.example.net/s1=pass');
  assert.equal(r.spf_results, 'bounces.mailer.example.net=pass');
  assert.equal(out.find((x) => x.source_ip === '203.0.113.25').servers, 'mail01');
  assert.equal(out.find((x) => x.source_ip === '203.0.113.25').reporters, 'google.com | Enterprise Outlook');
  assert.equal(out.find((x) => x.source_ip === '203.0.113.25').first_seen, '2026-09-25T00:00:00.000Z');
});
