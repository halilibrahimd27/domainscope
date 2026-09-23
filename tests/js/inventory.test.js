import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseInventory, buildIpIndex, lookupServers } from '../../assets/js/lib/inventory.js';

/** Map server id -> sorted ips for order-independent comparison. */
function ipsById(result) {
  const out = {};
  for (const s of result.servers) out[s.id] = [...s.ips].sort();
  return out;
}
function groupsById(result) {
  const out = {};
  for (const s of result.servers) out[s.id] = [...s.groups].sort();
  return out;
}
function codes(result) {
  return result.warnings.map((w) => w.code).sort();
}

/* -------------------------------------------------------------------- */
/* Line formats                                                         */
/* -------------------------------------------------------------------- */

test('name ip [ip...]', () => {
  const r = parseInventory('web01 10.0.0.1 10.0.0.2\nweb02 10.0.0.3');
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1', '10.0.0.2'], web02: ['10.0.0.3'] });
  assert.equal(r.stats.servers, 2);
  assert.equal(r.stats.ips, 3);
});

test('ip name and bare ip', () => {
  const r = parseInventory('10.0.0.1 web01\n10.0.0.2');
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], '10.0.0.2': ['10.0.0.2'] });
});

test('/etc/hosts: aliases, comments, loopback/boilerplate skipped', () => {
  const r = parseInventory([
    '# hosts',
    '127.0.0.1\tlocalhost',
    '::1     localhost ip6-localhost',
    'fe00::0 ip6-localnet',
    '10.0.0.5   web01.example.com web01   # main',
    '10.0.0.6 db01'
  ].join('\n'));
  const ids = r.servers.map((s) => s.id);
  assert.ok(ids.includes('web01.example.com'));
  assert.ok(ids.includes('db01'));
  assert.ok(!ids.includes('localhost'));
  const web = r.servers.find((s) => s.id === 'web01.example.com');
  assert.ok(web.aliases.includes('web01'));
});

test('same name across lines merges IPs (case-insensitive)', () => {
  const r = parseInventory('web01 10.0.0.1\nWEB01 10.0.0.2\nweb01 10.0.0.1');
  assert.equal(r.servers.length, 1);
  assert.deepEqual(r.servers[0].ips, ['10.0.0.1', '10.0.0.2']);
});

test('IPv6, bracket:port and ip:port forms', () => {
  const r = parseInventory('web05 [2001:db8::5]:443\nweb06 10.0.0.60:22\nweb07 2001:db8::7');
  assert.deepEqual(ipsById(r), { web05: ['2001:db8::5'], web06: ['10.0.0.60'], web07: ['2001:db8::7'] });
});

test('invalid IP and no-IP warnings', () => {
  const r = parseInventory('web01 10.0.0.256\ncache01\nweb02 10.0.0.2');
  assert.ok(codes(r).includes('INVALID_IP'));
  assert.ok(codes(r).includes('NO_IP'));
  assert.equal(r.servers.length, 1); // only web02 has a valid IP
});

test('prose lines: IPs stand alone, no bogus server names', () => {
  const r = parseInventory('lutfen sunuculari guncelleyin 10.1.1.1 ve 10.1.1.2 tesekkurler');
  assert.deepEqual(r.servers.map((s) => s.id).sort(), ['10.1.1.1', '10.1.1.2']);
});

test('mixed garbage never throws and is reported', () => {
  const r = parseInventory('!!!\n@@@ ###\n<<<>>>');
  assert.equal(r.servers.length, 0);
  assert.ok(r.warnings.every((w) => w.code === 'PARSE'));
});

test('bullet / numbered list prefixes are stripped', () => {
  const r = parseInventory('- api01 192.168.1.10\n1) api02 192.168.1.11\n* api03 192.168.1.12');
  assert.deepEqual(ipsById(r), { api01: ['192.168.1.10'], api02: ['192.168.1.11'], api03: ['192.168.1.12'] });
});

/* -------------------------------------------------------------------- */
/* Ansible INI                                                          */
/* -------------------------------------------------------------------- */

test('Ansible INI: ansible_host, groups, children, vars', () => {
  const r = parseInventory([
    '[web]',
    'web01 ansible_host=10.0.0.1 ansible_user=ubuntu',
    'web02 ansible_host=10.0.0.2',
    '10.0.0.3',
    '',
    '[db]',
    'db01 ansible_host=10.0.1.1 # primary',
    '',
    '[prod:children]',
    'web',
    'db',
    '',
    '[prod:vars]',
    'ansible_user=root',
    '',
    '[monitoring]',
    'web01'
  ].join('\n'));
  const g = groupsById(r);
  assert.deepEqual(g.web01, ['monitoring', 'prod', 'web']);
  assert.deepEqual(g.web02, ['prod', 'web']);
  assert.deepEqual(g.db01, ['db', 'prod']);
  assert.deepEqual(ipsById(r).web01, ['10.0.0.1']);
  // "10.0.0.3" (unnamed) also inherits the [web] group
  assert.deepEqual(g['10.0.0.3'], ['prod', 'web']);
});

test('Ansible INI: ansible_host as DNS name yields NO_IP but keeps the group', () => {
  const r = parseInventory('[db]\ndb02 ansible_host=db02.internal');
  assert.equal(r.servers.length, 0);
  assert.ok(codes(r).includes('NO_IP'));
});

/* -------------------------------------------------------------------- */
/* YAML                                                                 */
/* -------------------------------------------------------------------- */

test('Ansible YAML: nested groups and children', () => {
  const r = parseInventory([
    'all:',
    '  hosts:',
    '    bastion:',
    '      ansible_host: 203.0.113.10',
    '  children:',
    '    webservers:',
    '      hosts:',
    '        web01:',
    '          ansible_host: 10.0.0.1',
    '        web02:',
    '          ansible_host: 10.0.0.2',
    '    prod:',
    '      children:',
    '        webservers:'
  ].join('\n'));
  assert.deepEqual(ipsById(r), { bastion: ['203.0.113.10'], web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.deepEqual(groupsById(r).web01, ['prod', 'webservers']);
});

test('simple YAML map (name -> ansible_host)', () => {
  const r = parseInventory('web01:\n  ansible_host: 1.2.3.4\nweb02:\n  ansible_host: 1.2.3.5');
  assert.deepEqual(ipsById(r), { web01: ['1.2.3.4'], web02: ['1.2.3.5'] });
});

test('YAML list of records with inline flow and quoted IPs', () => {
  const r = parseInventory([
    'servers:',
    '  - name: web01',
    '    ip: 10.0.0.1',
    '  - name: db01',
    '    ips: [10.0.1.1, 10.0.1.2]',
    '  - hostname: cache01',
    '    addresses:',
    '      - "10.0.2.1"'
  ].join('\n'));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], db01: ['10.0.1.1', '10.0.1.2'], cache01: ['10.0.2.1'] });
});

/* -------------------------------------------------------------------- */
/* CSV / TSV                                                            */
/* -------------------------------------------------------------------- */

test('CSV with header in any column order', () => {
  const r = parseInventory('ip_address,environment,hostname,notes\n10.0.0.1,prod,web01,"multi\nline"\n10.0.0.2,stg,web02,x');
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.deepEqual(groupsById(r).web01, ['prod']);
});

test('semicolon Excel-TR export with sep= line, BOM, Turkish headers, ="..." cells', () => {
  const text = '﻿sep=;\r\nSunucu Adi;Ortam;IP Adresi;Aciklama\r\nWEB01;prod;10.0.0.1;on yuz\r\nDB01;prod;="10.0.1.1";veritabani\r\nyedek;test;;yok\r\n';
  const r = parseInventory(text);
  assert.deepEqual(ipsById(r), { WEB01: ['10.0.0.1'], DB01: ['10.0.1.1'] });
  assert.ok(codes(r).includes('NO_IP')); // 'yedek' row has no IP
});

test('TSV with multiple IP columns', () => {
  const r = parseInventory('Name\tPublic IP\tPrivate IP\nweb01\t203.0.113.1\t10.0.0.1');
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1', '203.0.113.1'] });
});

test('CSV invalid IP is warned once, row without valid IP dropped quietly', () => {
  const r = parseInventory('ip,hostname\n10.0.0.999,web03\n10.0.0.2,web02');
  assert.deepEqual(ipsById(r), { web02: ['10.0.0.2'] });
  assert.deepEqual(codes(r), ['INVALID_IP']);
});

/* -------------------------------------------------------------------- */
/* JSON                                                                 */
/* -------------------------------------------------------------------- */

test('JSON array of objects and bare strings', () => {
  const r = parseInventory(JSON.stringify([
    { name: 'web01', ip: '10.0.0.1' },
    { hostname: 'web02', addresses: ['10.0.0.2', '2001:db8::2'] },
    '10.0.0.3',
    { public_ip: '198.51.100.7', private_ip: '10.0.0.7' }
  ]));
  const by = ipsById(r);
  assert.deepEqual(by.web01, ['10.0.0.1']);
  assert.deepEqual(by.web02, ['10.0.0.2', '2001:db8::2']);
  assert.deepEqual(by['10.0.0.3'], ['10.0.0.3']);
  assert.deepEqual(by['198.51.100.7'], ['10.0.0.7', '198.51.100.7']);
});

test('JSON object keyed by name (terraform-ish)', () => {
  const r = parseInventory(JSON.stringify({
    web_ip: { sensitive: false, type: 'string', value: '203.0.113.5' },
    db_ips: { value: ['10.0.1.1', '10.0.1.2'] },
    lb: { value: { web01: '10.0.0.1', web02: '10.0.0.2' } }
  }));
  const by = ipsById(r);
  assert.deepEqual(by.web_ip, ['203.0.113.5']);
  assert.deepEqual(by.db_ips, ['10.0.1.1', '10.0.1.2']);
  assert.deepEqual(by.web01, ['10.0.0.1']);
  assert.deepEqual(by.web02, ['10.0.0.2']);
});

test('JSON: AWS describe-instances with tags.Name', () => {
  const r = parseInventory(JSON.stringify({
    Reservations: [{ Instances: [{
      InstanceId: 'i-1',
      PrivateIpAddress: '10.0.0.11',
      PublicIpAddress: '54.1.2.3',
      Tags: [{ Key: 'Env', Value: 'prod' }, { Key: 'Name', Value: 'api-1' }]
    }] }]
  }));
  assert.deepEqual(ipsById(r), { 'api-1': ['10.0.0.11', '54.1.2.3'] });
});

test('JSON Lines mixed with plain lines', () => {
  const r = parseInventory('{"name":"a1","ip":"10.9.0.1"}\n{"name":"a2","ip":"10.9.0.2"}\nweb09 10.9.0.9');
  assert.deepEqual(ipsById(r), { a1: ['10.9.0.1'], a2: ['10.9.0.2'], web09: ['10.9.0.9'] });
});

/* -------------------------------------------------------------------- */
/* Duplicates / edge cases                                             */
/* -------------------------------------------------------------------- */

test('duplicate IP across distinct servers is warned', () => {
  const r = parseInventory('web01 10.0.0.1\nweb02 10.0.0.1');
  assert.ok(codes(r).includes('DUPLICATE_IP'));
  const dup = r.warnings.find((w) => w.code === 'DUPLICATE_IP');
  assert.match(dup.detail, /10\.0\.0\.1/);
});

test('empty / whitespace / non-string input', () => {
  for (const input of ['', '   \n\n', null, undefined, 42, {}]) {
    const r = parseInventory(input);
    assert.deepEqual(r.servers, []);
    assert.equal(r.stats.servers, 0);
  }
});

test('result shape is stable', () => {
  const r = parseInventory('web01 10.0.0.1');
  assert.deepEqual(Object.keys(r).sort(), ['servers', 'stats', 'warnings']);
  const s = r.servers[0];
  assert.deepEqual(Object.keys(s).sort(), ['aliases', 'groups', 'id', 'ips', 'line', 'name']);
  assert.equal(s.id, 'web01');
  assert.equal(s.name, 'web01');
  assert.equal(s.line, 1);
  assert.deepEqual(Object.keys(r.stats).sort(), ['ips', 'lines', 'servers']);
});

/* -------------------------------------------------------------------- */
/* buildIpIndex / lookupServers                                        */
/* -------------------------------------------------------------------- */

test('buildIpIndex and lookupServers', () => {
  const { servers } = parseInventory('web01 10.0.0.1 10.0.0.2\ndb01 10.0.1.1\nlb 10.0.0.1');
  const index = buildIpIndex(servers);
  assert.equal(index.get('10.0.0.1').length, 2); // web01 + lb share the VIP
  assert.equal(index.get('10.0.1.1').length, 1);

  const hits = lookupServers(['10.0.0.1', '10.0.1.1', '9.9.9.9'], index);
  const names = hits.map((h) => `${h.server.id}@${h.ip}`).sort();
  assert.deepEqual(names, ['db01@10.0.1.1', 'lb@10.0.0.1', 'web01@10.0.0.1']);
});

test('lookupServers matches IPv4-mapped IPv6 to the plain IPv4', () => {
  const { servers } = parseInventory('web01 10.0.0.1');
  const index = buildIpIndex(servers);
  const hits = lookupServers(['::ffff:10.0.0.1'], index);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].server.id, 'web01');
});

test('lookupServers is robust to bad input', () => {
  assert.deepEqual(lookupServers(['1.2.3.4'], null), []);
  assert.deepEqual(lookupServers('not-an-ip', new Map()), []);
});
