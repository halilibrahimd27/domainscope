// Unit tests for assets/js/lib/export.js — pure string builders, no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  toCsv, toJson, scanHostRows, scanServerRows, namesForCli, targetsForCli, cliServerName, cliCommand, HOST_COLUMNS, SERVER_COLUMNS
} from '../../assets/js/lib/export.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { classifyResolution, getProvider } from '../../assets/js/lib/netinfo.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';

/** Minimal CSV parser (RFC 4180) used to round-trip the output. */
function parseCsv(text, delim = ',') {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const s = text.replace(/^﻿/, '');
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quoted) {
      if (c === '"' && s[i + 1] === '"') { field += '"'; i += 1; } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === delim) { row.push(field); field = ''; } else if (c === '\r' && s[i + 1] === '\n') { row.push(field); rows.push(row); row = []; field = ''; i += 1; } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

/* ------------------------------------------------------------------------ */

describe('toCsv', () => {
  const cols = [{ key: 'a', header: 'A' }, { key: 'b', header: 'Bee' }, { key: 'c', header: 'Computed', get: (r) => (r.a ?? 0) * 2 }];

  test('BOM, header row, CRLF line endings and trailing newline', () => {
    const csv = toCsv([{ a: 1, b: 'x' }, { a: 2, b: 'y' }], cols);
    assert.equal(csv, '﻿A,Bee,Computed\r\n1,x,2\r\n2,y,4\r\n');
    assert.equal(toCsv([], cols, { bom: false }), 'A,Bee,Computed\r\n');
  });

  test('RFC 4180 quoting of delimiter, quotes, CR/LF and edge whitespace', () => {
    const rows = [{ a: 'x,y', b: 'say "hi"' }, { a: 'line1\nline2', b: ' padded ' }, { a: 'cr\rhere', b: 'plain' }];
    const csv = toCsv(rows, cols.slice(0, 2), { bom: false });
    assert.equal(csv.split('\r\n')[1], '"x,y","say ""hi"""');
    const parsed = parseCsv(csv);
    assert.deepEqual(parsed, [['A', 'Bee'], ['x,y', 'say "hi"'], ['line1\nline2', ' padded '], ['cr\rhere', 'plain']]);
  });

  test('semicolon delimiter (Turkish Excel) and Turkish text', () => {
    const csv = toCsv([{ a: 'İstanbul;Ankara', b: 'Şükrü Öğüt' }], cols.slice(0, 2), { delimiter: ';' });
    assert.ok(csv.startsWith('﻿A;Bee\r\n'));
    assert.deepEqual(parseCsv(csv, ';')[1], ['İstanbul;Ankara', 'Şükrü Öğüt']);
    // invalid delimiters fall back to ','
    assert.ok(toCsv([], cols, { delimiter: '"', bom: false }).startsWith('A,Bee'));
  });

  test('value conversion: null/undefined, dates, arrays, sets, objects, booleans', () => {
    const d = new Date('2026-09-23T10:00:00Z');
    const csv = toCsv([{ a: null, b: undefined, c: d, d: ['1.1.1.1', '2.2.2.2'], e: new Set(['x']), f: { k: 1 }, g: false, h: new Date(NaN) }],
      ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((key) => ({ key })), { bom: false });
    assert.equal(csv.split('\r\n')[1], ',,2026-09-23T10:00:00.000Z,1.1.1.1 2.2.2.2,x,"{""k"":1}",false,');
  });

  test('neutralizes spreadsheet formulas in string cells (CSV injection), not in numbers', () => {
    const csv = toCsv([{ a: '=HYPERLINK("http://evil")', b: -5 }, { a: '+1', b: '@SUM(A1)' }, { a: '-cmd', b: '\tx' }],
      cols.slice(0, 2), { bom: false });
    const parsed = parseCsv(csv);
    assert.deepEqual(parsed[1], ['\'=HYPERLINK("http://evil")', '-5']);
    assert.deepEqual(parsed[2], ["'+1", "'@SUM(A1)"]);
    assert.deepEqual(parsed[3], ["'-cmd", "'\tx"]);
    const raw = toCsv([{ a: '=1+1' }], [{ key: 'a' }], { bom: false, safe: false });
    assert.equal(raw.split('\r\n')[1], '=1+1');
  });

  test('columns default to the union of row keys; a throwing getter yields an empty cell', () => {
    const csv = toCsv([{ x: 1 }, { y: 2 }], undefined, { bom: false });
    assert.equal(csv, 'x,y\r\n1,\r\n,2\r\n');
    const bad = toCsv([{ a: 1 }], [{ key: 'a', get: () => { throw new Error('x'); } }], { bom: false });
    assert.equal(bad, 'a\r\n\r\n');
    assert.equal(toCsv(null, [{ key: 'a' }], { bom: false }), 'a\r\n');
  });
});

describe('toJson', () => {
  test('Dates → ISO, Map → object, Set → array, Uint8Array omitted, pretty 2 spaces', () => {
    const v = {
      when: new Date('2026-01-02T03:04:05Z'),
      bad: new Date(NaN),
      names: new Map([['a.example', new Set(['crtsh', 'otx'])]]),
      der: new Uint8Array([1, 2, 3]),
      buf: new ArrayBuffer(4),
      list: [1, new Uint8Array(1), undefined, () => 1],
      big: 10n,
      re: /^s3\./,
      err: new TypeError('boom'),
      fn: () => 1,
      nan: NaN
    };
    const out = toJson(v);
    assert.equal(out, JSON.stringify({
      when: '2026-01-02T03:04:05.000Z',
      bad: null,
      names: { 'a.example': ['crtsh', 'otx'] },
      list: [1, null, null, null],
      big: '10',
      re: '^s3\\.',
      err: { name: 'TypeError', message: 'boom' },
      nan: null
    }, null, 2));
  });

  test('cycles and shared references', () => {
    const shared = { id: 1 };
    const a = { x: shared, y: shared };
    a.self = a;
    const parsed = JSON.parse(toJson(a));
    assert.deepEqual(parsed, { x: { id: 1 }, y: { id: 1 }, self: '[Circular]' });
    assert.equal(toJson(undefined), 'null');
    assert.equal(toJson('x'), '"x"');
  });

  test('real objects: certificates drop DER bytes, providers use their compact toJSON', () => {
    const cert = parseCertificates(readFileSync(new URL('../fixtures/rsa_multi_san.pem', import.meta.url), 'utf8')).leaf;
    const parsed = JSON.parse(toJson({ cert, cls: classifyResolution({ status: 'NOERROR', ipv4: ['104.16.1.1'] }) }));
    assert.equal(parsed.cert.der, undefined);
    assert.equal(parsed.cert.spkiDer, undefined);
    assert.equal(parsed.cert.serialHex, 'f1e2d3c4b5a69788');
    assert.equal(typeof parsed.cert.notAfter, 'string');
    assert.equal(parsed.cls.provider.id, 'cloudflare');
    assert.equal(parsed.cls.provider.cidrs, undefined);
    assert.equal(typeof parsed.cls.provider.cidrCount, 'number');
  });
});

/* ------------------------------------------------------------------------ */

const D = 'example.com.tr';
const inventory = [
  ...parseInventory('web01 203.0.113.10 10.0.0.10\nweb02 203.0.113.12\n203.0.113.30').servers,
  // server names from CSV / JSON inventories may contain spaces
  { id: 'db 01', name: 'db 01', ips: ['203.0.113.20'], groups: ['db'], line: 4, aliases: [] }
];
const web01 = inventory.find((s) => s.name === 'web01');
const db01 = inventory.find((s) => s.name === 'db 01');
const cf = getProvider('cloudflare');

const host = (name, extra = {}) => ({
  name,
  origins: ['crtsh'],
  resolution: { name, status: 'NOERROR', cnames: [], ipv4: [], ipv6: [], ttl: 300, resolver: 'cloudflare', error: null, ...(extra.resolution || {}) },
  classification: { kind: 'direct', provider: null, hidesOrigin: false, certManagedByProvider: false, dangling: false, reasonKey: 'class.direct', ...(extra.classification || {}) },
  cert: extra.cert === undefined ? { covered: true, by: `*.${D}` } : extra.cert,
  servers: extra.servers || [],
  wildcardSuspect: !!extra.wildcardSuspect,
  ipHints: extra.ipHints || []
});

const SCAN = {
  startedAt: new Date('2026-09-23T10:00:00Z'),
  finishedAt: new Date('2026-09-23T10:01:00Z'),
  domains: [D],
  hosts: [
    host(D, { cert: { covered: false, by: null }, resolution: { ipv4: ['203.0.113.10'] }, servers: [{ serverId: 'web01', name: 'web01', ip: '203.0.113.10' }] }),
    host(`www.${D}`, {
      resolution: { ipv4: ['104.16.1.1'], ipv6: ['2606:4700::1'], cnames: [`${D}.cdn.cloudflare.net`] },
      classification: { kind: 'cloudflare', provider: cf, hidesOrigin: true, certManagedByProvider: true, reasonKey: 'class.cloudflare.cname' },
      ipHints: [{ name: `www.${D}`, ip: '203.0.113.20', source: 'otx' }, { name: `www.${D}`, ip: '203.0.113.20', source: 'hackertarget' }]
    }),
    host(`zz.${D}`, { wildcardSuspect: true }),
    host(`api.${D}`, { resolution: { ipv4: ['198.51.100.7'] } }),
    host(`gone.${D}`, { resolution: { status: 'NXDOMAIN', ttl: null }, classification: { kind: 'nxdomain' }, cert: { covered: false, by: null } })
  ],
  servers: [
    {
      server: web01, needsCert: true, maybeNeedsCert: false,
      hosts: [{ name: D, ip: '203.0.113.10', covered: false, via: 'dns' }, { name: `www.${D}`, ip: '203.0.113.10', covered: true, via: 'hint' }]
    },
    { server: db01, needsCert: false, maybeNeedsCert: true, hosts: [{ name: `www.${D}`, ip: '203.0.113.20', covered: true, via: 'hint' }] }
  ],
  unmatchedIps: [{ ip: '198.51.100.7', hosts: [`api.${D}`], provider: null }],
  originHints: [{ ip: '203.0.113.20', reasons: [{ kind: 'history', detail: 'otx' }], servers: [{ serverId: 'db 01', name: 'db 01' }], provider: null }],
  stats: { total: 5 }
};

describe('scanHostRows / scanServerRows', () => {
  test('flat host rows', () => {
    const rows = scanHostRows(SCAN);
    assert.equal(rows.length, 5);
    const www = rows[1];
    assert.equal(www.name, `www.${D}`);
    assert.equal(www.kind, 'cloudflare');
    assert.equal(www.provider, 'Cloudflare');
    assert.equal(www.providerId, 'cloudflare');
    assert.equal(www.hidesOrigin, true);
    assert.deepEqual(www.ipv4, ['104.16.1.1']);
    assert.deepEqual(www.cnames, [`${D}.cdn.cloudflare.net`]);
    assert.equal(www.covered, true);
    assert.equal(www.coveredBy, `*.${D}`);
    assert.deepEqual(www.historicalIps, ['203.0.113.20']);
    assert.deepEqual(rows[0].servers, ['web01 (203.0.113.10)']);
    assert.equal(rows[0].covered, false);
    assert.equal(rows[4].status, 'NXDOMAIN');
    assert.equal(rows[4].ttl, null);
    assert.deepEqual(scanHostRows(null), []);
    // no certificate → covered null
    assert.equal(scanHostRows({ hosts: [host('x.example', { cert: null })] })[0].covered, null);
  });

  test('host CSV with the default columns', () => {
    const csv = toCsv(scanHostRows(SCAN), HOST_COLUMNS);
    const parsed = parseCsv(csv);
    assert.equal(parsed.length, 6);
    assert.equal(parsed[0][0], 'Hostname');
    const idx = (h) => parsed[0].indexOf(h);
    assert.equal(parsed[2][idx('IPv6')], '2606:4700::1');
    assert.equal(parsed[2][idx('Provider')], 'Cloudflare');
    assert.equal(parsed[2][idx('Covered by certificate')], 'true');
  });

  test('server rows: one per (server, host) + unmatched IPs', () => {
    const rows = scanServerRows(SCAN);
    assert.deepEqual(rows.map((r) => [r.server, r.host, r.ip, r.via, r.needsCert, r.matched]), [
      ['web01', D, '203.0.113.10', 'dns', true, true],
      ['web01', `www.${D}`, '203.0.113.10', 'hint', true, true],
      ['db 01', `www.${D}`, '203.0.113.20', 'hint', false, true],
      ['', `api.${D}`, '198.51.100.7', 'dns', false, false]
    ]);
    assert.deepEqual(rows[0].serverIps, ['203.0.113.10', '10.0.0.10']);
    assert.equal(rows[3].covered, true);
    const csv = toCsv(rows, SERVER_COLUMNS, { bom: false });
    assert.ok(csv.startsWith('Server,Server IPs,Groups,Needs certificate,Hostname,IP,Matched via,Covered by certificate\r\n'));
    assert.deepEqual(scanServerRows({}), []);
  });
});

describe('CLI helpers', () => {
  test('namesForCli: sorted names, wildcard suspects excluded, onlyCovered', () => {
    assert.equal(namesForCli(SCAN), `${D}\napi.${D}\ngone.${D}\nwww.${D}\n`);
    assert.equal(namesForCli(SCAN, { onlyCovered: true }), `api.${D}\nwww.${D}\n`);
    assert.equal(namesForCli({ hosts: [] }), '');
    assert.equal(namesForCli(null), '');
  });

  test('targetsForCli: servers, groups, hints, unmatched IPs and bare IPs; de-duplicated', () => {
    const text = targetsForCli([
      ...SCAN.servers, // groups → server objects
      ...inventory, // duplicates of the above are skipped
      ...SCAN.originHints,
      ...SCAN.unmatchedIps,
      '2001:DB8::1',
      'not-an-ip',
      null
    ]);
    assert.equal(text, [
      'web01 203.0.113.10',
      'web01 10.0.0.10',
      'db_01 203.0.113.20',
      'web02 203.0.113.12',
      '203.0.113.30', // a server named by its IP is written bare
      '198.51.100.7',
      '2001:db8::1',
      ''
    ].join('\n'));
    assert.equal(targetsForCli([]), '');
    assert.equal(targetsForCli(undefined), '');
  });

  test('targetsForCli: an inventory address written with a port keeps it, as the CLI reads the inventory', () => {
    const { servers } = parseInventory('web01 203.0.113.10:8443 203.0.113.11\nweb02 [2001:db8::2]:8443\nweb03 203.0.113.13 203.0.113.13:8443');
    const text = targetsForCli([
      { server: servers[0] }, // a scanner ServerGroup
      ...servers,
      { ip: '203.0.113.10', servers: [{ name: 'hint' }] }, // an origin hint on the same address: the server's line wins
      { ip: '203.0.113.99', hosts: ['www.example.com'] }
    ]);
    assert.equal(text, [
      'web01 203.0.113.10:8443',
      'web01 203.0.113.11',
      'web02 [2001:db8::2]:8443',
      'web03 203.0.113.13 203.0.113.13:8443',
      '203.0.113.99',
      ''
    ].join('\n'));
  });

  test('targetsForCli: a server sharing an address still gets the endpoints no earlier line wrote', () => {
    const { servers } = parseInventory('web01 203.0.113.10:8443\nweb02 203.0.113.10\nweb03 203.0.113.10:8443\nweb04 203.0.113.11\nweb05 203.0.113.11');
    assert.equal(targetsForCli([...servers, { ip: '203.0.113.10', servers: [{ name: 'hint' }] }]), [
      'web01 203.0.113.10:8443',
      'web02 203.0.113.10', // scanned on -p, as the CLI reading the inventory does
      'web04 203.0.113.11', // web03 and web05 add no endpoint: the first name wins
      ''
    ].join('\n'));
  });

  test('targetsForCli: the port on an Ansible host pattern is its SSH port, so the address goes to -p', () => {
    // As Ansible reads its INI: 203.0.113.11:2222 under [web] sets ansible_port, not a TLS port.
    const { servers } = parseInventory('[web]\n203.0.113.11:2222\nweb02 203.0.113.12:8443\n[db]\n[2001:db8::5]:2222 ansible_user=admin\n'
      + 'db02.example.com:2222 ansible_host=203.0.113.14\n');
    assert.equal(targetsForCli(servers), [
      'web02 203.0.113.12:8443', // a later token keeps its TLS port
      'db02.example.com 203.0.113.14',
      '203.0.113.11',
      '2001:db8::5',
      ''
    ].join('\n'));
  });

  test('cliServerName: one token the CLI reads as the whole name (never a comment, variable or IP)', () => {
    const cases = [
      ['web01', 'web01'],
      ['Web Server 1', 'Web_Server_1'],
      ['#bastion', '_bastion'],
      ['Web #2', 'Web_2'],
      ['// legacy', '_legacy'],
      ['db;primary', 'db_primary'],
      ['a, b', 'a_b'],
      ['role=web', 'role_web'],
      ['rack/web01', 'rack_web01'],
      ['rack\u001cweb', 'rack_web'], // Python's splitlines() breaks a line here
      ['a\u0085b', 'a_b'],
      ['a\u2028b', 'a_b'],
      ['  [prod] api  ', '[prod]_api'],
      ['şube-01', 'şube-01'],
      ['203.0.113.9', ''], // an IP as the name would be probed as one
      ['2001:db8::1', ''],
      ['192.0.2.50-60', ''], // so would a range: the CLI expands it
      ['192.0.2.50-192.0.2.60', ''],
      ['db-1', 'db-1'],
      ['face-b00c', 'face-b00c'],
      ['ansible_host: web', 'ansible_host_web'], // never read as the YAML inventory key
      ['db:primary', 'db_primary'],
      ['   ', ''],
      [null, '']
    ];
    for (const [name, want] of cases) assert.equal(cliServerName(name), want, JSON.stringify(name));
    assert.equal(targetsForCli([
      { name: 'Web Server 1', ips: ['192.0.2.11'] },
      { name: '#bastion', ips: ['192.0.2.13'] },
      { name: '203.0.113.8', ips: ['203.0.113.9'] }
    ]), 'Web_Server_1 192.0.2.11\n_bastion 192.0.2.13\n203.0.113.9\n');
  });

  test('cliCommand', () => {
    assert.equal(cliCommand(), 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem');
    assert.equal(cliCommand({ certFile: null }), 'python3 ssl_origin_scan.py -t targets.txt -n names.txt');
    assert.equal(
      cliCommand({ namesFile: 'my names.txt', targetsFile: 'hosts.csv', certFile: "yeni sertifika's.pem", python: 'python', ports: [443, 8443], json: 'out.json' }),
      "python ssl_origin_scan.py -t hosts.csv -n 'my names.txt' --cert 'yeni sertifika'\\''s.pem' --ports 443,8443 --json out.json"
    );
  });
});
