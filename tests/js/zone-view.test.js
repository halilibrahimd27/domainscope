/**
 * views/zone.js pure helpers: i18n coverage of every generated key, the samples, the Records
 * filter, the problem list, multi-file parsing, the sweep command (exact tokens, never a /24),
 * the hand-off intent / session shapes and export redaction. Pure Node (the view is DOM-free at
 * import time). Fixtures are documentation data only (example.com, 192.0.2.0/24, 2001:db8::/32).
 */
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const imp = (rel) => import(pathToFileURL(join(ROOT, rel)).href);
const fixture = (name) => readFileSync(join(ROOT, 'tests', 'fixtures', 'zones', name), 'utf8');

let V;
let i18n;
let O;
let L;
let D;
let Zp;

before(async () => {
  i18n = await imp('assets/js/i18n.js');
  V = await imp('assets/js/views/zone.js');
  O = await imp('assets/js/lib/zoneorigins.js');
  L = await imp('assets/js/lib/zonelint.js');
  D = await imp('assets/js/lib/zonedrift.js');
  Zp = await imp('assets/js/lib/zoneparse.js');
});

describe('zone view: strings', () => {
  test('every key built from a library code exists in EN and TR with the same placeholders', () => {
    const en = new Set(i18n.listKeys('en'));
    const tr = new Set(i18n.listKeys('tr'));
    const keys = V.generatedKeys();
    assert.ok(keys.length > 150, `expected many generated keys, got ${keys.length}`);
    assert.deepEqual(keys.filter((k) => !en.has(k)), [], 'missing in EN');
    assert.deepEqual(keys.filter((k) => !tr.has(k)), [], 'missing in TR');
  });

  test('view contract', () => {
    assert.equal(V.id, 'zone');
    assert.equal(V.titleKey, 'nav.zone');
    assert.equal(V.icon, 'file-text');
    assert.equal(typeof V.mount, 'function');
    assert.equal(typeof V.unmount, 'function');
  });
});

describe('zone view: samples and parsing', () => {
  test('the three samples parse without a fatal issue and with a confident origin', () => {
    const got = V.SAMPLES.map((s) => {
      const z = V.parseFiles([{ name: s.file, text: s.text }]);
      return [s.id, z.fatal, z.origin, z.originConfidence, z.format];
    });
    assert.deepEqual(got, [
      ['cloudflare', null, 'example.com', 'high', 'bind'],
      ['route53', null, 'example.com', 'high', 'route53'],
      ['bind', null, 'example.com', 'high', 'bind']
    ]);
  });

  test('the BIND sample shows its mistakes (missing dots, CNAME conflict, two SPF, private IP)', () => {
    const s = V.SAMPLES.find((x) => x.id === 'bind');
    const z = V.parseFiles([{ name: s.file, text: s.text }]);
    const lint = L.lintZone(z);
    const codes = new Set(V.problemList(z, lint).map((p) => p.code));
    for (const c of ['OWNER_MISSING_TRAILING_DOT', 'TARGET_MISSING_TRAILING_DOT', 'CNAME_AND_OTHER_DATA', 'MULTIPLE_SPF', 'PRIVATE_IP']) {
      assert.ok(codes.has(c), `${c} in ${[...codes]}`);
    }
  });

  test('Cloudflare export: counts match the fixture (39 records, 26 names, 10 proxied)', () => {
    const z = V.parseFiles([{ name: 'example.com.txt', text: fixture('cloudflare-export.txt') }]);
    const c = V.zoneCounts(z, V.problemList(z, L.lintZone(z)));
    assert.equal(c.records, 39);
    assert.equal(c.names, 26);
    assert.equal(c.proxied, 10);
    assert.ok(c.errors >= 1, 'origin exposed by ftp');
  });

  test('two Cloudflare API pages dropped together become one zone without duplicates', () => {
    const z = V.parseFiles([
      { name: 'page1.json', text: fixture('cloudflare-api-page1.json') },
      { name: 'page2.json', text: fixture('cloudflare-api-page2.json') }
    ]);
    assert.equal(z.fatal, null);
    assert.equal(z.format, 'cloudflare-api');
    const keys = z.records.map((r) => `${r.name}|${r.type}|${r.text}`);
    assert.equal(new Set(keys).size, keys.length, 'no duplicates');
  });

  test('a BIND secondary dump ($ORIGIN .) is analysed as its SOA zone, not the root', () => {
    const text = '$ORIGIN .\n$TTL 3600\nexample.com IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300\n' +
      '\t\t\tNS ns1.example.com.\n\t\t\tNS ns2.example.net.\n\t\t\tA 192.0.2.10\n$ORIGIN example.com.\n' +
      'dev\t\t\tA 10.0.0.5\nns1\t\t\tA 192.0.2.53\nwww\t\t\tCNAME missing\n';
    const z = V.parseFiles([{ name: 'example.com.bak', text }]);
    assert.deepEqual([z.origin, z.originConfidence], ['example.com', 'high']);
    assert.deepEqual(L.lintZone(z).findings.map((f) => `${f.code}:${f.name}`).sort(),
      ['DANGLING_IN_ZONE_TARGET:www.example.com', 'PRIVATE_IP:dev.example.com']);
    const scan = O.zoneScanInput(z);
    assert.equal(scan.origin, 'example.com');
    assert.deepEqual(scan.delegations, []);
    assert.ok(scan.names.includes('example.com') && scan.names.includes('www.example.com'), scan.names.join());
    assert.equal(D.planDrift(z).skipped.occluded, 0);
  });

  test('an $INCLUDE part merges under the main origin whatever its file name or drop order', () => {
    const main = (name) => ({ name: 'db.example.com', text: `$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\nns1 IN A 192.0.2.53\n$INCLUDE ${name}\n` });
    const part = (name) => ({ name, text: 'mail IN A 192.0.2.80\n@ IN MX 10 mail\n' });
    for (const name of ['mail.inc', 'example.com.include', 'db.example.com.inc', 'mail']) {
      for (const files of [[main(name), part(name)], [part(name), main(name)]]) {
        const z = V.parseFiles(files);
        assert.equal(z.fatal, null, name);
        assert.equal(z.origin, 'example.com', name);
        assert.ok(z.records.some((r) => r.name === 'mail.example.com' && r.type === 'A' && r.ttl === 300), name);
        assert.equal(z.records.find((r) => r.type === 'MX').name, 'example.com', name);
        assert.ok(z.warnings.some((w) => w.code === 'INCLUDE_MERGED'), name);
        assert.ok(!z.warnings.some((w) => w.code === 'INCLUDE_REJECTED' || w.code === 'OUT_OF_ZONE'), name);
      }
    }
    // the $INCLUDE origin argument (absolute or relative) is where the part's names land
    for (const [line, name] of [['$INCLUDE lab lab.example.com.', 'lab'], ['$INCLUDE lab.inc lab', 'lab.inc']]) {
      const z = V.parseFiles([{ name: 'db.example.com', text: `$ORIGIN example.com.\n@ 300 IN SOA ns1 h 1 2 3 4 5\n${line}\n` },
        { name, text: 'api 300 IN A 192.0.2.30\n@ 300 IN TXT "lab"\n' }]);
      assert.equal(z.fatal, null, line);
      assert.equal(z.origin, 'example.com', line);
      assert.deepEqual(z.records.map((r) => r.name), ['example.com', 'api.lab.example.com', 'lab.example.com'], line);
    }
    // a part of absolute names below the zone merges too
    const abs = V.parseFiles([main('part.zone'), { name: 'part.zone', text: 'a.lab.example.com. 300 IN A 192.0.2.1\nb.lab.example.com. 300 IN A 192.0.2.2\n' }]);
    assert.equal(abs.fatal, null);
    assert.equal(abs.origin, 'example.com');
  });

  test('files of different zones → ORIGIN_MISMATCH; a certificate → NOT_A_ZONE pem', () => {
    const a = 'example.com. 300 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5\nexample.com. 300 IN A 192.0.2.10\nwww.example.com. 300 IN A 192.0.2.10\n';
    const b = 'example.org. 300 IN SOA ns1.example.org. h.example.org. 1 2 3 4 5\nexample.org. 300 IN A 192.0.2.10\nwww.example.org. 300 IN A 192.0.2.10\n';
    assert.equal(V.parseFiles([{ name: 'a.txt', text: a }, { name: 'b.txt', text: b }]).fatal.code, 'ORIGIN_MISMATCH');
    const pem = V.parseFiles([{ name: 'cert.pem.txt', text: fixture('bad/cert.pem.txt') }]);
    assert.equal(pem.fatal.code, 'NOT_A_ZONE');
    assert.equal(pem.fatal.params.hint, 'pem');
  });
});

describe('zone view: helpers', () => {
  test('typeGroup / recordMatches / relativeName', () => {
    assert.deepEqual(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'].map(V.typeGroup), ['addr', 'addr', 'CNAME', 'MX', 'TXT', 'NS', 'other', 'other']);
    const r = { type: 'A', proxied: true };
    assert.equal(V.recordMatches(r, { group: 'addr', proxiedOnly: true }), true);
    assert.equal(V.recordMatches({ type: 'A', proxied: false }, { group: 'all', proxiedOnly: true }), false);
    assert.equal(V.recordMatches({ type: 'MX', proxied: null }, { group: 'CNAME' }), false);
    assert.equal(V.relativeName('example.com', 'example.com'), '@');
    assert.equal(V.relativeName('www.example.com', 'example.com'), 'www');
    assert.equal(V.relativeName('*.apps.example.com', 'example.com'), '*.apps');
    assert.equal(V.relativeName('www.example.org', 'example.com'), 'www.example.org');
  });

  test('every problem of every fixture reads without a left-over {placeholder} in EN and TR', () => {
    const files = ['cloudflare-export.txt', 'cloudflare-api.json', 'route53.json', 'example.com.yaml', 'bind-edge.zone.txt', 'cpanel-example.com.db.txt',
      'directadmin-example.com.db.txt', 'godaddy.txt', 'cli53.txt', 'plesk-info.txt', 'internal.zone.txt', 'placeholder.cf.txt', 'axfr-dig.txt',
      'bad/unterminated-quote.txt', 'bad/unbalanced-paren.txt', 'bad/include.txt'];
    const inputs = [...files.map((f) => ({ name: f.split('/').pop(), text: fixture(f) })),
      { name: 'db.example.com', text: '$ORIGIN example.com.\n_sip._tcp.@ 300 IN SRV 10 5 5060 sip.@\nmail 300 IN CNAME www.@\n' }];
    const was = i18n.getLang();
    try {
      for (const lang of ['en', 'tr']) {
        i18n.setLang(lang);
        for (const f of inputs) {
          const z = V.parseFiles([f]);
          for (const p of V.problemList(z, L.lintZone(z))) {
            const text = i18n.t(p.source === 'lint' ? `zone.lint.${p.code}` : V.issueKey(p.code, p.params), p.params);
            assert.doesNotMatch(text, /\{[A-Za-z]+\}/, `${lang} ${f.name} ${p.code}`);
          }
        }
      }
    } finally {
      i18n.setLang(was);
    }
  });

  test('issue texts say what the parser did (served name, ignored $TTL / ")", translated unit)', () => {
    const was = i18n.getLang();
    const say = (lang, text, code, opts = {}) => {
      i18n.setLang(lang);
      const w = Zp.parseZone(text, { filename: 'db.example.com', ...opts }).warnings.find((x) => x.code === code);
      return i18n.t(V.issueKey(w.code, w.params), w.params);
    };
    try {
      const dot = '$ORIGIN example.com.\n$TTL 300\nexample.com IN TXT "x"\n';
      assert.match(say('en', dot, 'OWNER_MISSING_TRAILING_DOT'), /^“example\.com” has no trailing dot .* serves it as example\.com\.example\.com,/);
      assert.match(say('tr', dot, 'OWNER_MISSING_TRAILING_DOT'), /^“example\.com” dosyada/);
      const ttl = '$ORIGIN example.com.\n$TTL 300\n$TTL 1x\nwww A 192.0.2.10\nbig 4294967295 A 192.0.2.11\n';
      i18n.setLang('en');
      const [dir, rec] = V.parseFiles([{ name: 'db.example.com', text: ttl }]).warnings.filter((w) => w.code === 'BAD_TTL');
      assert.equal(i18n.t(V.issueKey(dir.code, dir.params), dir.params), 'Invalid $TTL 1x; the line was ignored.');
      assert.equal(i18n.t(V.issueKey(rec.code, rec.params), rec.params), 'Invalid TTL 4294967295; read as 0.');
      assert.match(say('en', '$ORIGIN example.com.\nns1 300 IN A 192.0.2.53 )\n', 'UNBALANCED_PAREN'), /no matching “\(”; it was ignored/);
      assert.match(say('en', '$ORIGIN example.com.\nns1 300 IN A ( 192.0.2.53\nwww 300 IN A 192.0.2.10\n', 'UNBALANCED_PAREN'), /never closed; this entry was skipped/);
      const many = `$ORIGIN example.com.\n${Array.from({ length: 5 }, (_, i) => `h${i} 300 IN A 192.0.2.${i + 1}`).join('\n')}\n`;
      assert.equal(say('tr', many, 'RECORDS_TRUNCATED', { limits: { maxEntries: 3 } }), 'Yalnızca ilk 3 girdi okundu.');
      assert.equal(V.issueKey('RECORDS_TRUNCATED', { unit: 'records' }), 'zone.issue.RECORDS_TRUNCATED');
      assert.equal(V.issueKey('RECORDS_TRUNCATED', { unit: 'documents' }), 'zone.issue.RECORDS_TRUNCATED.documents');
      assert.equal(V.issueKey('BAD_NAME'), 'zone.issue.BAD_NAME');
    } finally {
      i18n.setLang(was);
    }
  });

  test('problemList merges parse issues and lint findings, errors first', () => {
    const zone = { warnings: [{ code: 'TTL_DEFAULTED', severity: 'info', line: 1, params: {} }, { code: 'BAD_TTL', severity: 'warn', line: 9, params: {} }] };
    const lint = { findings: [{ code: 'MULTIPLE_SPF', severity: 'error', name: 'example.com', type: 'TXT', line: 20, params: {} }] };
    assert.deepEqual(V.problemList(zone, lint).map((p) => [p.source, p.code]), [['lint', 'MULTIPLE_SPF'], ['issue', 'BAD_TTL'], ['issue', 'TTL_DEFAULTED']]);
  });

  test('originConfirmed: high confidence, user origin or an explicit Confirm', () => {
    assert.equal(V.originConfirmed({ fatal: null, origin: 'example.com', originConfidence: 'high' }, false), true);
    assert.equal(V.originConfirmed({ fatal: null, origin: 'example.com', originConfidence: 'low', originSource: 'filename' }, false), false);
    assert.equal(V.originConfirmed({ fatal: null, origin: 'example.com', originConfidence: 'low', originSource: 'filename' }, true), true);
    assert.equal(V.originConfirmed({ fatal: { code: 'EMPTY' }, origin: null }, true), false);
  });

  test('buildIntent / sessionZone shapes (the Subdomains / SSL Targets contract)', () => {
    assert.deepEqual(V.buildIntent({ target: 'subdomains', domain: 'example.com', mode: 'exact', now: 5 }),
      { v: 1, target: 'subdomains', domain: 'example.com', mode: 'exact', autostart: true, at: 5 });
    assert.deepEqual(V.buildIntent({ target: 'scan', domain: 'example.com', mode: 'bogus', autostart: false, now: 7 }),
      { v: 1, target: 'scan', domain: 'example.com', mode: 'exact', autostart: false, at: 7 });
    const z = V.parseFiles([{ name: 'example.com.txt', text: fixture('cloudflare-export.txt') }]);
    const s = V.sessionZone(z, { skipPrivate: true, label: 'x' });
    assert.equal(s.v, 1);
    assert.equal(s.origin, 'example.com');
    assert.equal(s.label, 'x');
    assert.ok(!s.names.includes('intranet.example.com'), 'internal name left out');
    assert.ok(s.names.includes('www.example.com'));
    assert.deepEqual(s.counts, { names: s.names.length + s.wildcardBases.length, origins: s.proxied.length, skipped: s.skipped.length });
    assert.ok(s.proxied.every((p) => p.ips.every((ip) => ip !== '192.0.2.0')), 'no placeholder origin');
    const all = V.sessionZone(z, { skipPrivate: false });
    assert.ok(all.names.includes('intranet.example.com'));
  });
});

describe('zone view: sweep command', () => {
  test('exact origins, host target and wildcard name; never a /24; POSIX and PowerShell', () => {
    const z = V.parseFiles([{ name: 'example.com.txt', text: fixture('cloudflare-export.txt') }]);
    const posix = V.sweepCommand(O.zoneSweep(z, { scope: 'proxied', shell: 'posix' }));
    assert.match(posix.command, /^python3 ssl_origin_scan\.py -t 192\.0\.2\.10 /);
    assert.ok(posix.command.includes(' origin-lb.example.net '), posix.command);
    assert.ok(posix.command.includes(" '*.apps.example.com' "), posix.command);
    assert.ok(!/\/\d{1,2}\b/.test(posix.command), 'no CIDR in the command');
    assert.ok(!posix.command.includes('shop.example.com') && !posix.command.includes('tunnel.example.com'), 'provider / tunnel skipped');
    assert.equal(posix.fileForm, false);
    const pwsh = V.sweepCommand(O.zoneSweep(z, { scope: 'proxied', shell: 'powershell' }));
    assert.match(pwsh.command, /^python ssl_origin_scan\.py -t /);
  });

  test('a large zone switches to the file form (-t zone-targets.txt -n zone-names.txt)', () => {
    const lines = ['$ORIGIN example.com.', '$TTL 300', '@ IN SOA ns1 h 1 2 3 4 5', '@ IN NS ns1', 'ns1 IN A 198.51.100.53'];
    for (let i = 0; i < 80; i += 1) lines.push(`h${i} IN A 198.51.100.${(i % 200) + 1}`);
    const z = V.parseFiles([{ name: 'db.example.com', text: `${lines.join('\n')}\n` }]);
    const sw = O.zoneSweep(z, { scope: 'all', shell: 'posix' });
    assert.equal(sw.fileForm, true);
    const cmd = V.sweepCommand(sw);
    assert.equal(cmd.fileForm, true);
    assert.match(cmd.command, /-t zone-targets\.txt/);
    assert.match(cmd.command, /-n zone-names\.txt/);
  });

  test('no proxied origin → no command', () => {
    const z = V.parseFiles([{ name: 'cpanel.db', text: fixture('cpanel-example.com.db.txt') }]);
    assert.equal(V.sweepCommand(O.zoneSweep(z, { scope: 'proxied' })).command, null);
  });

  test('exports redact origin addresses and hosts unless opted in', () => {
    const z = V.parseFiles([{ name: 'example.com.txt', text: fixture('cloudflare-export.txt') }]);
    const secrets = V.originSecrets(O.proxiedOriginMap(z));
    assert.ok(secrets.has('192.0.2.10') && secrets.has('origin-lb.example.net') && !secrets.has('198.51.100.25'));
    assert.deepEqual(V.redactValues(['192.0.2.10', '104.16.1.1', 'origin-lb.example.net.'], secrets, false), [V.REDACTED, '104.16.1.1', V.REDACTED]);
    assert.deepEqual(V.redactValues(['192.0.2.10'], secrets, true), ['192.0.2.10']);
  });
});

describe('zone view: live check progress', () => {
  test('the progress label follows the count (it was frozen at "0 / N" while the bar moved)', () => {
    const src = readFileSync(join(ROOT, 'assets', 'js', 'views', 'zone.js'), 'utf8');
    const body = /const updateProgress = \(\) => \{([\s\S]*?)\n {4}\};/.exec(src);
    assert.ok(body, 'updateProgress found');
    assert.match(body[1], /progressEl\.setLabel\(t\('zone\.live\.progress', \{ done: formatNumber\(S\.live\.done\), total: formatNumber\(S\.live\.total\) \}\)\)/);
    assert.match(body[1], /progressEl\.set\(S\.live\.done, Math\.max\(1, S\.live\.total\)\)/);
  });
});

describe('zone view: sweep estimate', () => {
  test('SNI names × targets adds up: a *.x name is probed twice (x and *.x)', () => {
    const zone = V.parseFiles([{ name: 'cloudflare-export.txt', text: fixture('cloudflare-export.txt') }]);
    const sw = O.zoneSweep(zone, { origins: O.proxiedOriginMap(zone) });
    const targets = sw.targets.length + sw.hostTargets.length;
    const n = V.sweepProbeNames(sw, targets);
    assert.equal(n * targets, sw.probes, 'names × targets = probes');
    const wild = sw.names.filter((x) => x.startsWith('*.')).length;
    assert.equal(n, sw.names.length + wild, 'each wildcard name adds its base as a second SNI');
    assert.equal(V.sweepProbeNames({ names: ['a.example.com'], probes: 0 }, 0), 1, 'no target: the plain name count');
  });
});
