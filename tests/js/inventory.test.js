import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseInventory, buildIpIndex, lookupServers, formatEndpoint, addressTargets, serverTargets, inventoryFormat,
  TOPOLOGY_KEYS, TOPOLOGY_REASONS
} from '../../assets/js/lib/inventory.js';
import { inventoryTopology, terminatesTls, topologyTokens } from '../../assets/js/lib/topology.js';

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

test('/etc/hosts: the stock macOS file (fe80::1%lo0 localhost) adds no server', () => {
  const r = parseInventory([
    '127.0.0.1\tlocalhost',
    '255.255.255.255\tbroadcasthost',
    '::1             localhost',
    'fe80::1%lo0     localhost',
    '10.0.0.5 web01'
  ].join('\n'));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.5'] });
  assert.deepEqual(r.warnings, []);
});

test('same name across lines merges IPs (case-insensitive)', () => {
  const r = parseInventory('web01 10.0.0.1\nWEB01 10.0.0.2\nweb01 10.0.0.1');
  assert.equal(r.servers.length, 1);
  assert.deepEqual(r.servers[0].ips, ['10.0.0.1', '10.0.0.2']);
});

test('IPv6, bracket:port and ip:port forms', () => {
  const r = parseInventory('web05 [2001:db8::5]:443\nweb06 10.0.0.60:22\nweb07 2001:db8::7');
  assert.deepEqual(ipsById(r), { web05: ['2001:db8::5'], web06: ['10.0.0.60'], web07: ['2001:db8::7'] });
  assert.deepEqual(r.servers.map((s) => s.ports ?? null), [{ '2001:db8::5': [443] }, { '10.0.0.60': [22] }, null]);
});

test('invalid IP and no-IP warnings', () => {
  const r = parseInventory('web01 10.0.0.256\ncache01\nweb02 10.0.0.2');
  assert.ok(codes(r).includes('INVALID_IP'));
  assert.ok(codes(r).includes('NO_IP'));
  assert.equal(r.servers.length, 1); // only web02 has a valid IP
});

test('heading lines are skipped, host names that start like a heading are not', () => {
  const hosts = ['ip-10-0-1-23.eu-west-1.compute.example.net', 'ipv6.example.com', 'ip6.example.net', 'addr.example.com'];
  const r = parseInventory(['hostname   ip', 'Sunucu Adı  IP Adresi', 'name | ipv4 | ipv6', ...hosts, 'web01 10.0.0.1'].join('\n'));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'] });
  assert.deepEqual(r.warnings.map((w) => [w.code, w.detail]), hosts.map((h) => ['NO_IP', h]));
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
/* JSON / YAML: network, management and version attributes              */
/* -------------------------------------------------------------------- */

test('ansible-inventory --list: gateway / DNS / NTP hostvars are neither servers nor server IPs', () => {
  const r = parseInventory(JSON.stringify({
    _meta: { hostvars: {
      web01: { ansible_host: '10.0.0.1', ntp_server: '10.0.0.9', dns_servers: ['1.1.1.1', '8.8.8.8'], gateway: '10.0.0.254' },
      web02: { ansible_host: '10.0.0.2', ntp_server: '10.0.0.9', dns_servers: ['1.1.1.1', '8.8.8.8'], gateway: '10.0.0.254' }
    } },
    all: { children: ['ungrouped', 'web'] },
    web: { hosts: ['web01', 'web02'] }
  }));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.deepEqual(groupsById(r), { web01: ['web'], web02: ['web'] });
  assert.deepEqual(r.warnings, []);
  // a host whose only address-looking vars are attributes has no IP of its own
  const bare = parseInventory(JSON.stringify({ _meta: { hostvars: { web01: { ntp_server: '10.0.0.9' } } }, web: { hosts: ['web01'] } }));
  assert.deepEqual(bare.servers, []);
  assert.deepEqual(codes(bare), ['NO_IP']);
});

test('ansible-inventory --list: a shared group var (syslog_server) is never every host\'s own IP', () => {
  // --list flattens [all:vars] into every host's hostvars
  const vars = { syslog_server: '10.0.0.50', backup_server: '10.0.0.60' };
  const r = parseInventory(JSON.stringify({
    _meta: { hostvars: { web01: { ansible_host: '10.0.0.1', ...vars }, web02: { ansible_host: '10.0.0.2', ...vars }, db01: { ansible_host: '10.0.0.3', ...vars } } },
    all: { children: ['ungrouped', 'web', 'db'] }, web: { hosts: ['web01', 'web02'] }, db: { hosts: ['db01'] }
  }));
  assert.deepEqual(ipsById(r), { syslog_server: ['10.0.0.50'], backup_server: ['10.0.0.60'], web01: ['10.0.0.1'], web02: ['10.0.0.2'], db01: ['10.0.0.3'] });
  assert.ok(!codes(r).includes('DUPLICATE_IP'));
  assert.deepEqual(lookupServers(['10.0.0.50'], buildIpIndex(r.servers)).map((x) => x.server.name), ['syslog_server']);
  const yaml = parseInventory(['all:', '  hosts:', '    web01:', '      ansible_host: 10.0.0.1', '      syslog_server: 10.0.0.50',
    '    web02:', '      ansible_host: 10.0.0.2', '      syslog_server: 10.0.0.50'].join('\n'));
  assert.deepEqual(ipsById(yaml), { syslog_server: ['10.0.0.50'], web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.ok(!codes(yaml).includes('DUPLICATE_IP'));
});

test('Ansible YAML hostvars: gateway / DNS / NTP / version vars are ignored', () => {
  const r = parseInventory([
    'all:',
    '  children:',
    '    web:',
    '      hosts:',
    '        web01:',
    '          ansible_host: 10.0.0.1',
    '          ntp_server: 10.0.0.9',
    '          dns_servers: [1.1.1.1, 8.8.8.8]',
    '          gateway: 10.0.0.254',
    '          app_version: 10.2.0.1',
    '        web02:',
    '          ansible_host: 10.0.0.2'
  ].join('\n'));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.deepEqual(r.warnings, []);
  // a plain YAML map of hosts (no groups): the ansible_host field makes each a machine record
  const plain = parseInventory('web01:\n  ansible_host: 10.0.0.1\n  app_version: 10.2.0.1\n  ilo_ip: 10.9.9.1\n');
  assert.deepEqual(ipsById(plain), { web01: ['10.0.0.1'] });
  // group vars, like an INI [all:vars] section
  const vars = parseInventory([
    'all:',
    '  vars:',
    '    ntp_server: 10.0.0.9',
    '    dns_servers: [1.1.1.1, 8.8.8.8]',
    '  children:',
    '    web:',
    '      hosts:',
    '        web01:',
    '          ansible_host: 10.0.0.1'
  ].join('\n'));
  assert.deepEqual(ipsById(vars), { web01: ['10.0.0.1'] });
});

test('named JSON records: gateway, netmask and DNS IPs are not attached to every server', () => {
  const rec = (name, ip) => ({ name, ip, gateway: '10.0.0.254', netmask: '255.255.255.0', dns: ['1.1.1.1', '8.8.8.8'], mac: '00:11:22:33:44:55' });
  const r = parseInventory(JSON.stringify([rec('web01', '10.0.0.1'), rec('web02', '10.0.0.2')]));
  assert.deepEqual(ipsById(r), { web01: ['10.0.0.1'], web02: ['10.0.0.2'] });
  assert.ok(!codes(r).includes('DUPLICATE_IP'));
  assert.deepEqual(lookupServers(['8.8.8.8'], buildIpIndex(r.servers)), []);
});

test('a name / hostname / server key holding an IP identifies an unnamed server, never a server "name"', () => {
  for (const records of [
    [{ name: '10.0.0.1', ip: '10.0.0.1' }, { name: '10.0.0.2', ip: '10.0.0.2' }],
    [{ hostname: '10.0.0.1' }, { hostname: '10.0.0.2' }],
    [{ server: '10.0.0.1', port: 443 }, { server: '10.0.0.2', port: 443 }]
  ]) {
    const r = parseInventory(JSON.stringify(records));
    assert.deepEqual(ipsById(r), { '10.0.0.1': ['10.0.0.1'], '10.0.0.2': ['10.0.0.2'] }, JSON.stringify(records));
  }
});

test('unnamed JSON record: an iLO address is dropped, as in CSV and INI', () => {
  const r = parseInventory(JSON.stringify([{ ip: '10.0.0.1', ilo_ip: '10.9.9.1' }]));
  assert.deepEqual(ipsById(r), { '10.0.0.1': ['10.0.0.1'] });
});

test('regression: name maps and hosts that only look like attributes keep their servers', () => {
  const flat = parseInventory(JSON.stringify({ 'dns-01': '10.0.0.53', 'mail-gw': '10.0.0.25', ntp: '10.0.0.9', web01: '10.0.0.1' }));
  assert.deepEqual(ipsById(flat), { 'dns-01': ['10.0.0.53'], 'mail-gw': ['10.0.0.25'], ntp: ['10.0.0.9'], web01: ['10.0.0.1'] });
  const infra = parseInventory([
    'all:',
    '  children:',
    '    infra:',
    '      hosts:',
    '        ntp:',
    '          ansible_host: 10.0.0.9',
    '        dns:',
    '          ansible_host: 10.0.0.53'
  ].join('\n'));
  assert.deepEqual(ipsById(infra), { ntp: ['10.0.0.9'], dns: ['10.0.0.53'] });
  assert.deepEqual(groupsById(infra), { ntp: ['infra'], dns: ['infra'] });
  // the Servers view's own YAML and JSON examples
  const yaml = parseInventory('all:\n  children:\n    web:\n      hosts:\n        web01:\n          ansible_host: 10.0.1.11\n        web02:\n          ansible_host: 10.0.1.12\n');
  assert.deepEqual(ipsById(yaml), { web01: ['10.0.1.11'], web02: ['10.0.1.12'] });
  assert.deepEqual(groupsById(yaml), { web01: ['web'], web02: ['web'] });
  const json = parseInventory('[\n  { "name": "web01", "ip": "10.0.1.11" },\n  { "name": "web02", "ips": ["10.0.1.12", "2001:db8::12"] }\n]\n');
  assert.deepEqual(ipsById(json), { web01: ['10.0.1.11'], web02: ['10.0.1.12', '2001:db8::12'] });
});

test('regression: a host name holding host / public / internal is no address key of a machine record', () => {
  // A name → IP map stays a map: one such name must not merge the others into one server.
  const lb = parseInventory(JSON.stringify({ web01: '10.0.0.1', web02: '10.0.0.2', 'public-lb': '10.0.0.5' }));
  assert.deepEqual(ipsById(lb), { web01: ['10.0.0.1'], web02: ['10.0.0.2'], '10.0.0.5': ['10.0.0.5'] });
  const api = parseInventory(JSON.stringify({ 'internal-api': '10.0.0.5', 'dns-1': '10.0.0.53', web01: '10.0.0.1' }));
  assert.deepEqual(ipsById(api), { '10.0.0.5': ['10.0.0.5'], 'dns-1': ['10.0.0.53'], web01: ['10.0.0.1'] });
  // Even a real address key (EC2's ip-10-0-0-1 host name) leaves host-shaped names alone.
  const ec2 = parseInventory(JSON.stringify({ 'ip-10-0-0-1': '10.0.0.1', 'dns-1': '10.0.0.53', web01: '10.0.0.2' }));
  assert.deepEqual(ipsById(ec2), { '10.0.0.1': ['10.0.0.1'], 'dns-1': ['10.0.0.53'], web01: ['10.0.0.2'] });
  // Listed Ansible hosts name their entry, whatever their name looks like.
  const yaml = parseInventory([
    'all:',
    '  children:',
    '    infra:',
    '      hosts:',
    '        docker-host-1:',
    '          ansible_host: 10.0.0.10',
    '        dns-1:',
    '          ansible_host: 10.0.0.53',
    '        web01:',
    '          ansible_host: 10.0.0.1'
  ].join('\n'));
  assert.deepEqual(ipsById(yaml), { 'docker-host-1': ['10.0.0.10'], 'dns-1': ['10.0.0.53'], web01: ['10.0.0.1'] });
  assert.deepEqual(groupsById(yaml), { 'docker-host-1': ['infra'], 'dns-1': ['infra'], web01: ['infra'] });
  assert.deepEqual(codes(yaml), []);
  const hostvars = { 'docker-host-1': { ansible_host: '10.0.0.10' }, 'dns-1': { ansible_host: '10.0.0.53' } };
  const list = parseInventory(JSON.stringify({ _meta: { hostvars }, infra: { hosts: ['docker-host-1', 'dns-1'] } }));
  assert.deepEqual(ipsById(list), { 'docker-host-1': ['10.0.0.10'], 'dns-1': ['10.0.0.53'] });
  assert.deepEqual(groupsById(list), { 'docker-host-1': ['infra'], 'dns-1': ['infra'] });
  assert.deepEqual(codes(list), []);
  // --list of ungrouped hosts only: _meta.hostvars alone lists them
  const bare = parseInventory(JSON.stringify({ _meta: { hostvars } }));
  assert.deepEqual(ipsById(bare), { 'docker-host-1': ['10.0.0.10'], 'dns-1': ['10.0.0.53'] });
  const all = parseInventory([
    'all:',
    '  hosts:',
    '    web01:',
    '      ansible_host: 10.0.0.1',
    '    backup-host:',
    '      ansible_host: 10.0.0.8',
    '    mail-gw:',
    '      ansible_host: 10.0.0.25'
  ].join('\n'));
  assert.deepEqual(ipsById(all), { web01: ['10.0.0.1'], 'backup-host': ['10.0.0.8'], 'mail-gw': ['10.0.0.25'] });
  assert.deepEqual(codes(all), []);
});

/* -------------------------------------------------------------------- */
/* Addresses with their own port (the CLI's ip:port targets)            */
/* -------------------------------------------------------------------- */

const targetsById = (r) => Object.fromEntries(r.servers.map((s) => [s.id, serverTargets(s)]));

test('tests/fixtures/inventory-ports.txt: the endpoints and warnings the CLI reads from it too', () => {
  // tests/python/test_inventory_targets.py asserts the same servers, endpoints and warning lines for the CLI.
  const r = parseInventory(readFileSync(new URL('../fixtures/inventory-ports.txt', import.meta.url), 'utf8'));
  assert.deepEqual(targetsById(r), {
    web01: ['203.0.113.10:8443'],
    web02: ['[2001:db8::2]:8443', '203.0.113.12'],
    web03: ['203.0.113.13', '203.0.113.13:8443'],
    web04: ['203.0.113.14'],
    web05: ['203.0.113.15:9443'],
    web06: ['[2001:db8::16]:443'],
    '203.0.113.17': ['203.0.113.17:8443'],
    web11: ['203.0.113.22'],
    web13: ['203.0.113.23'],
    web16: ['203.0.113.10:9443'],
    'web14.example.com': ['203.0.113.24'],
    web15: ['203.0.113.27:8443'],
    '203.0.113.25': ['203.0.113.25'],
    '2001:db8::26': ['2001:db8::26']
  });
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail, w.reason]), [
    [10, 'INVALID_IP', '203.0.113.18:99999', 'port'],
    [11, 'INVALID_IP', '[2001:db8::19]:https', 'port'],
    [12, 'INVALID_IP', '203.0.113.20:0', 'port'],
    [13, 'INVALID_IP', '203.0.113.21:70000', 'port'],
    // the CLI warns about line 14 too, and resolves line 15's host name (servers here are matched by address)
    [14, 'PARSE', 'db.example.net:5432', 'hostPort'],
    [15, 'PARSE', 'web12.example.net:8443', 'hostPort'],
    [15, 'NO_IP', 'web12', undefined],
    // an Ansible host's own port is its SSH port: the host stays on -p (and line 20 is no DUPLICATE_IP)
    [24, 'PARSE', 'web14.example.com:2222', 'sshPort'],
    [26, 'PARSE', '203.0.113.25:2222', 'sshPort'],
    [27, 'PARSE', '[2001:db8::26]:2222', 'sshPort']
  ], 'a port that cannot be used is a warning, never a silently dropped address');
  assert.deepEqual(r.servers.find((s) => s.id === 'web03').ports, { '203.0.113.13': [null, 8443] }, 'null: also on -p');
  assert.equal(r.servers.find((s) => s.id === 'web04').ports, undefined, 'an empty port is none');
});

test('ports in CSV, INI, YAML and JSON; a CIDR with a port is invalid', () => {
  const csv = parseInventory('name,ip\nweb01,203.0.113.10:8443\nweb02,"[2001:db8::2]:8443, 203.0.113.12"\nweb03,203.0.113.13:70000\n');
  assert.deepEqual(targetsById(csv), { web01: ['203.0.113.10:8443'], web02: ['[2001:db8::2]:8443', '203.0.113.12'] });
  assert.deepEqual(codes(csv), ['INVALID_IP']);
  const ini = parseInventory('[web]\nweb01 ansible_host=203.0.113.10:8443\nweb02 ansible_host=203.0.113.12\n');
  assert.deepEqual(targetsById(ini), { web01: ['203.0.113.10:8443'], web02: ['203.0.113.12'] });
  const yaml = parseInventory('all:\n  hosts:\n    web01:\n      ansible_host: 203.0.113.10:8443\n');
  assert.deepEqual(targetsById(yaml), { web01: ['203.0.113.10:8443'] });
  const json = parseInventory(JSON.stringify([{ name: 'web01', ip: '203.0.113.10:8443' }, { name: 'web02', ips: ['[2001:db8::2]:8443', '203.0.113.12'] }]));
  assert.deepEqual(targetsById(json), { web01: ['203.0.113.10:8443'], web02: ['[2001:db8::2]:8443', '203.0.113.12'] });
  const cidr = parseInventory('net01 203.0.113.0/24:443\nweb01 203.0.113.10');
  assert.deepEqual(codes(cidr), ['INVALID_IP']);
  assert.deepEqual(targetsById(cidr), { web01: ['203.0.113.10'] });
});

test('ports merge like the CLI: a bare line of a named address adds the -p ports to its server', () => {
  const r = parseInventory('web01 203.0.113.10:8443\nweb01 203.0.113.10:9443\n203.0.113.10\n203.0.113.11:8443\n203.0.113.11:8443');
  assert.deepEqual(targetsById(r), {
    web01: ['203.0.113.10:8443', '203.0.113.10:9443', '203.0.113.10'],
    '203.0.113.11': ['203.0.113.11:8443']
  });
  assert.ok(!codes(r).includes('DUPLICATE_IP'));
  // Prose: each address stands alone, with its port.
  const prose = parseInventory('please update 203.0.113.10:8443 and [2001:db8::1]:8443 today');
  assert.deepEqual(targetsById(prose), { '203.0.113.10': ['203.0.113.10:8443'], '2001:db8::1': ['[2001:db8::1]:8443'] });
  // An address first given bare: its -p ports stay with the one written with a port.
  const both = parseInventory('web01 203.0.113.10\nweb01 203.0.113.10:8443');
  assert.deepEqual(both.servers[0].ports, { '203.0.113.10': [null, 8443] });
});

test('a host name with a port (the CLI resolves it) is a PARSE warning here, never dropped silently', () => {
  const r = parseInventory('web01 203.0.113.10 web01.example.net:8443\nweb02 web02.example.net:8443\nmeeting at 10:30 with 203.0.113.5');
  assert.deepEqual(targetsById(r), { web01: ['203.0.113.10'], '203.0.113.5': ['203.0.113.5'] });
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail]), [
    [1, 'PARSE', 'web01.example.net:8443'],
    [2, 'PARSE', 'web02.example.net:8443'],
    [2, 'NO_IP', 'web02']
  ]);
});

test('NAME=HOST[:PORT] as the first token: the server has no IP here, and says so (the CLI resolves it)', () => {
  const r = parseInventory(['web01=web01.example.net:8443', 'web02=web02.example.net', 'web03=web03.example.net:8443 203.0.113.13',
    'web04 ansible_host=web04.example.net:8443', 'user=root', 'version=1.2', 'timeout=30', 'web05 203.0.113.15 10:30'].join('\n'));
  assert.deepEqual(targetsById(r), { web03: ['203.0.113.13'], web05: ['203.0.113.15'] });
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail, w.reason]), [
    [1, 'PARSE', 'web01.example.net:8443', 'hostPort'],
    [1, 'NO_IP', 'web01', undefined],
    [2, 'NO_IP', 'web02', undefined],
    [3, 'PARSE', 'web03.example.net:8443', 'hostPort'],
    [4, 'PARSE', 'web04.example.net:8443', 'hostPort'],
    [4, 'NO_IP', 'web04', undefined]
  ], 'variables (user=root) and a time of day stay silent');
  // A bad address is INVALID_IP without a reason; only an address with an unusable port has 'port'.
  const bad = parseInventory('web01 203.0.113.300:8443\nweb02 203.0.113.12:08443x');
  assert.deepEqual(bad.warnings.map((w) => [w.code, w.reason]), [['INVALID_IP', undefined], ['INVALID_IP', 'port']]);
});

test('Ansible INI: a port on the host pattern is its SSH port, the address stays on -p', () => {
  // As Ansible reads its INI: "badwolf.example.com:5309", "192.0.2.50:2222" set ansible_port.
  const r = parseInventory([
    '[web]', '203.0.113.11:2222', 'web02 203.0.113.12:8443', '10:30 203.0.113.13',
    '[db]', '[2001:db8::5]:2222 ansible_user=admin', 'db02.example.com:5309', 'db03:2222 ansible_host=203.0.113.14',
    '[db:vars]', 'ansible_port=2222'
  ].join('\n'));
  assert.deepEqual(targetsById(r), {
    web02: ['203.0.113.12:8443'], // a later token keeps the TLS meaning (not valid Ansible anyway)
    db03: ['203.0.113.14'],
    '203.0.113.11': ['203.0.113.11'],
    '203.0.113.13': ['203.0.113.13'],
    '2001:db8::5': ['2001:db8::5']
  });
  assert.deepEqual(groupsById(r), { web02: ['web'], db03: ['db'], '203.0.113.11': ['web'], '203.0.113.13': ['web'], '2001:db8::5': ['db'] });
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail, w.reason]), [
    [2, 'PARSE', '203.0.113.11:2222', 'sshPort'],
    [6, 'PARSE', '[2001:db8::5]:2222', 'sshPort'],
    [7, 'PARSE', 'db02.example.com:5309', 'sshPort'],
    [7, 'NO_IP', 'db02.example.com', undefined], // the CLI resolves it, on -p
    [8, 'PARSE', 'db03:2222', 'sshPort']
  ]);
  // Outside Ansible (no [group], no ansible_* variable) the same first token is a TLS target.
  assert.deepEqual(targetsById(parseInventory('203.0.113.11:2222\n[2001:db8::5]:8443 web05')), {
    '203.0.113.11': ['203.0.113.11:2222'], web05: ['[2001:db8::5]:8443']
  });
  // ansible_* variables without a group make the context too; a bad port there is INVALID_IP as anywhere.
  const vars = parseInventory('web01.example.com:2222 ansible_host=203.0.113.10\n203.0.113.11:99999 ansible_user=admin');
  assert.deepEqual(targetsById(vars), { 'web01.example.com': ['203.0.113.10'] });
  assert.deepEqual(vars.warnings.map((w) => [w.line, w.code, w.reason]), [[1, 'PARSE', 'sshPort'], [2, 'INVALID_IP', 'port']]);
});

test('JSON: an address with a bad port or a host name with a port is a warning, never dropped silently', () => {
  // tests/python/test_inventory_targets.py reads the same values with the CLI (JSON_CASES).
  const cases = [
    ['[{"name":"web01","ip":"203.0.113.10:99999"}]', [['INVALID_IP', '203.0.113.10:99999', 'port']]],
    ['{"web01":"203.0.113.10:99999"}', [['INVALID_IP', '203.0.113.10:99999', 'port']]],
    ['{"_meta":{"hostvars":{"web01":{"ansible_host":"203.0.113.10:99999"}}}}', [['INVALID_IP', '203.0.113.10:99999', 'port']]],
    ['[{"ip":"[fe80::1%eth0]:8443"}]', [['INVALID_IP', '[fe80::1%eth0]:8443', 'zone']]],
    ['["web01 203.0.113.10:99999"]', [['INVALID_IP', '203.0.113.10:99999', 'port']]],
    // the CLI resolves a host name with a port; here it is a PARSE, and the server has no address
    ['{"web01":"web01.example.net:8443"}', [['PARSE', 'web01.example.net:8443', 'hostPort'], ['NO_IP', 'web01', undefined]]],
    // a name key holding a mistyped address names nothing
    ['[{"name":"203.0.113.10:99999","ip":"203.0.113.11"}]', [['INVALID_IP', '203.0.113.10:99999', 'port']]],
    // neither an address nor a dotted host: silent, as before
    ['[{"name":"cache01","image":"redis:7","ip":"203.0.113.12"}]', []]
  ];
  for (const [text, expected] of cases) {
    const r = parseInventory(text);
    assert.deepEqual(r.warnings.map((w) => [w.code, w.detail, w.reason]), expected, text);
    if (expected.length) assert.deepEqual(r.servers.filter((s) => s.ips.includes('203.0.113.10')), [], text);
  }
  assert.deepEqual(targetsById(parseInventory(cases[6][0])), { '203.0.113.11': ['203.0.113.11'] });
  assert.deepEqual(targetsById(parseInventory(cases[7][0])), { cache01: ['203.0.113.12'] });
  // YAML and JSON Lines go the same way, with the line of the value.
  const yaml = parseInventory('all:\n  hosts:\n    web01:\n      ansible_host: 203.0.113.10:99999\n    web02:\n      ansible_host: 203.0.113.12\n');
  assert.deepEqual(targetsById(yaml), { web02: ['203.0.113.12'] });
  assert.deepEqual(yaml.warnings.map((w) => [w.line, w.code, w.reason]), [[4, 'INVALID_IP', 'port']]);
  const lines = parseInventory('{"name":"web01","ip":"203.0.113.10"}\n{"name":"web02","ip":"203.0.113.12:0"}');
  assert.deepEqual(lines.warnings.map((w) => [w.line, w.code, w.reason]), [[2, 'INVALID_IP', 'port']]);
});

test('a host name with a port warns only where a target is read, never in vars or record attributes', () => {
  // tests/python/test_inventory_targets.py reads the same documents with the CLI (QUIET_HOST_PORTS).
  const list = JSON.stringify({
    _meta: { hostvars: {
      web01: { ansible_host: '203.0.113.10', consul_addr: 'consul.example.com:8500', db_url: 'db.example.com:5432' },
      web02: { ansible_host: '203.0.113.11', consul_addr: 'consul.example.com:8500', db_url: 'db.example.com:5432' }
    } },
    all: { children: ['ungrouped', 'web'] },
    web: { hosts: ['web01', 'web02'] }
  }, null, 2);
  const quiet = [
    [list, { web01: ['203.0.113.10'], web02: ['203.0.113.11'] }],
    ['all:\n  vars:\n    consul_addr: consul.example.com:8500\n  hosts:\n    web01:\n      ansible_host: 203.0.113.10\n      db_url: db.example.com:5432\n',
      { web01: ['203.0.113.10'] }],
    ['[{"name":"web01","ip":"203.0.113.10","health_url":"web01.example.com:8080"}]', { web01: ['203.0.113.10'] }],
    ['{"resources":[{"type":"aws_db_instance","name":"db","instances":[{"attributes":{"id":"db","endpoint":"db.example.com:5432"}}]}]}', {}],
    ['[{"endpoint":"db.example.com:5432"}]', {}]
  ];
  for (const [text, targets] of quiet) {
    const r = parseInventory(text);
    assert.deepEqual(r.warnings, [], text);
    assert.deepEqual(targetsById(r), targets, text);
  }
  // A name map's entry, a Terraform output and ansible_host still say why nothing was taken.
  const warned = [
    ['{"web01":"web01.example.net:8443"}', [['PARSE', 'web01.example.net:8443'], ['NO_IP', 'web01']]],
    ['{"outputs":{"web":{"value":"web01.example.net:8443","type":"string"}}}', [['PARSE', 'web01.example.net:8443'], ['NO_IP', 'web']]],
    ['{"_meta":{"hostvars":{"web01":{"ansible_host":"web01.example.net:2222"}}}}', [['PARSE', 'web01.example.net:2222'], ['NO_IP', 'web01']]]
  ];
  for (const [text, expected] of warned) {
    assert.deepEqual(parseInventory(text).warnings.map((w) => [w.code, w.detail ?? w.name]), expected, text);
  }
});

test('a bracketed address that cannot be read is INVALID_IP, with a zone id named', () => {
  const r = parseInventory('web01 [fe80::1%eth0]:8443\nweb02 [2001:db8::1]8443\nweb03=[fe80::1%eth0]:8443\nweb04 [2001:db8::4]:8443');
  assert.deepEqual(targetsById(r), { web04: ['[2001:db8::4]:8443'] });
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail, w.reason]), [
    [1, 'INVALID_IP', '[fe80::1%eth0]:8443', 'zone'],
    [2, 'INVALID_IP', '[2001:db8::1]8443', undefined],
    [3, 'INVALID_IP', '[fe80::1%eth0]:8443', 'zone']
  ]);
  const csv = parseInventory('name,ip\nweb01,[fe80::1%eth0]:8443\n');
  assert.deepEqual(csv.warnings.map((w) => [w.code, w.reason]), [['INVALID_IP', 'zone']]);
});

test('formatEndpoint, addressTargets and serverTargets', () => {
  assert.equal(formatEndpoint('203.0.113.10', 8443), '203.0.113.10:8443');
  assert.equal(formatEndpoint('2001:DB8::1', 8443), '[2001:db8::1]:8443');
  assert.equal(formatEndpoint('203.0.113.10'), '203.0.113.10');
  for (const bad of [0, 65536, 1.5, '8443', NaN]) assert.equal(formatEndpoint('203.0.113.10', bad), '203.0.113.10');
  assert.equal(formatEndpoint('web01', 443), null);
  const server = { ips: ['203.0.113.10', '203.0.113.11'], ports: { '203.0.113.10': [null, 8443, 8443] } };
  assert.deepEqual(addressTargets(server, '203.0.113.10'), ['203.0.113.10', '203.0.113.10:8443']);
  assert.deepEqual(addressTargets(server, '203.0.113.11'), ['203.0.113.11']);
  assert.deepEqual(addressTargets(null, '203.0.113.12'), ['203.0.113.12']);
  assert.deepEqual(addressTargets(server, 'not-an-ip'), []);
  assert.deepEqual(serverTargets(server), ['203.0.113.10', '203.0.113.10:8443', '203.0.113.11']);
  assert.deepEqual(serverTargets({ ips: ['203.0.113.12'], ports: { '203.0.113.12': [] } }), ['203.0.113.12']);
  assert.deepEqual(serverTargets(null), []);
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

test('duplicates are per endpoint: one address on different ports is no duplicate, as in the CLI', () => {
  const r = parseInventory('web01 203.0.113.10:8443\nweb02 203.0.113.10:9443\nweb03 203.0.113.10:9443\nweb04 203.0.113.10\nweb05 203.0.113.10 203.0.113.10:8443');
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.detail]), [
    [3, 'DUPLICATE_IP', '203.0.113.10:9443 (web02, web03)'],
    [5, 'DUPLICATE_IP', '203.0.113.10 (web04, web05)'] // one warning per server and address
  ]);
  assert.equal(r.stats.ips, 1, 'stats count addresses, not endpoints');
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

test('inventoryFormat: the reader parseInventory picks, with the CSV header and the JSON / YAML data', () => {
  assert.deepEqual(inventoryFormat(''), { format: 'empty' });
  assert.deepEqual(inventoryFormat(null), { format: 'empty' });
  assert.deepEqual(inventoryFormat('web01 192.0.2.1\n192.0.2.2 web02'), { format: 'lines' });
  assert.deepEqual(inventoryFormat('# servers\n[web]\nweb01 ansible_host=192.0.2.1'), { format: 'ini' });
  assert.deepEqual(inventoryFormat('[2001:db8::1]:8443\nweb01 192.0.2.1'), { format: 'lines' }, 'a bracketed address is no INI header');
  assert.deepEqual(inventoryFormat('{"name":"web01","ip":"192.0.2.1"}\n{"name":"web02","ip":"192.0.2.2"}'), { format: 'jsonl' });
  assert.deepEqual(inventoryFormat('[{"name":"web01","ip":"192.0.2.1"}]'), { format: 'json', data: [{ name: 'web01', ip: '192.0.2.1' }] });
  assert.equal(inventoryFormat('{"web01": "192.0.2.1"}').format, 'json');
  assert.deepEqual(inventoryFormat('all:\n  hosts:\n    web01:\n      ansible_host: 192.0.2.1\n'), {
    format: 'yaml', data: { all: { hosts: { web01: { ansible_host: '192.0.2.1' } } } }
  });
  assert.deepEqual(inventoryFormat('\uFEFFrole;IP;Hostname\nweb;192.0.2.1;web01'), {
    format: 'csv', delimiter: ';', nameColumn: 2,
    header: [{ role: 'group', key: 'role' }, { role: 'ip', key: 'ip' }, { role: 'name', key: 'hostname' }]
  });
  assert.equal(inventoryFormat('ip,role\n192.0.2.1,web').nameColumn, -1);
  // parseInventory reads each of them with that reader
  for (const text of ['web01 192.0.2.1', '[web]\nweb01 ansible_host=192.0.2.1', 'hostname,ip\nweb01,192.0.2.1', '[{"name":"web01","ip":"192.0.2.1"}]']) {
    assert.deepEqual(parseInventory(text).servers.map((s) => [s.name, s.ips]), [['web01', ['192.0.2.1']]], text);
  }
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

/* -------------------------------------------------------------------- */
/* Topology keys: where TLS really terminates (parity with the CLI)     */
/* -------------------------------------------------------------------- */

const TOPOLOGY_DIR = new URL('../fixtures/topology/', import.meta.url);
const TOPOLOGY_EXPECTED = JSON.parse(readFileSync(new URL('expected.json', TOPOLOGY_DIR), 'utf8'));

/** The model both parsers are compared on (tests/python/test_inventory_targets.py builds the same). */
function topologyModel(result) {
  return Object.fromEntries(result.servers.map((s) => [s.name, {
    endpoints: serverTargets(s), tlsPorts: s.tlsPorts || [], terminatesTls: s.terminatesTls ?? null,
    vips: s.vips || [], nats: s.nats || [], backends: s.backends || []
  }]));
}
/** [line, code, reason] (line null when `lines` is false), sorted as expected.json lists them. */
function topologyWarnings(result, lines) {
  const key = (w) => [w[0] ?? -1, w[1], w[2] ?? ''];
  return result.warnings.map((w) => [lines ? w.line : null, w.code, w.reason ?? null])
    .sort((a, b) => {
      const [x, y] = [key(a), key(b)];
      return x[0] - y[0] || x[1].localeCompare(y[1]) || x[2].localeCompare(y[2]);
    });
}

for (const [file, want] of Object.entries(TOPOLOGY_EXPECTED.files)) {
  test(`tests/fixtures/topology/${file}: the same servers, endpoints, topology and warnings as the CLI`, () => {
    // tests/python/test_inventory_targets.py reads the same file to the same expected.json.
    const r = parseInventory(readFileSync(new URL(file, TOPOLOGY_DIR), 'utf8'));
    assert.deepEqual(topologyModel(r), { ...(want.core === false ? {} : TOPOLOGY_EXPECTED.servers), ...want.extra });
    assert.deepEqual(topologyWarnings(r, want.lines), want.warnings);
  });
}

test('topology keys: precedence of the ports — an address with its own port keeps it, ports= replaces -p, then -p', () => {
  const r = parseInventory([
    'web01 203.0.113.10 203.0.113.12:9443 ports=443,8443',
    'web02 203.0.113.13 203.0.113.13:8443 ports=4443',
    'web03 203.0.113.14',
    'web04 203.0.113.15 ports=8443',
    'web04 203.0.113.15 ports=443'
  ].join('\n'));
  assert.deepEqual(Object.fromEntries(r.servers.map((s) => [s.name, serverTargets(s)])), {
    web01: ['203.0.113.10:443', '203.0.113.10:8443', '203.0.113.12:9443'],
    web02: ['203.0.113.13:4443', '203.0.113.13:8443'],
    web03: ['203.0.113.14'],
    web04: ['203.0.113.15:8443', '203.0.113.15:443']
  });
  assert.equal(r.servers[2].tlsPorts, undefined, 'no key, no field: the shape of an old inventory');
  assert.deepEqual(r.warnings, []);
  // Two servers on one address but different ports= are different endpoints: no DUPLICATE_IP.
  const nat = parseInventory('web01 203.0.113.10 ports=443\nweb02 203.0.113.10 ports=8443\nweb03 203.0.113.10 ports=8443');
  assert.deepEqual(nat.warnings.map((w) => [w.line, w.code, w.detail]), [[3, 'DUPLICATE_IP', '203.0.113.10:8443 (web02, web03)']]);
});

test('topology keys: an inventory without them parses exactly as before', () => {
  for (const text of ['web01 10.0.0.1\nweb02 10.0.0.2 2001:db8::2', 'hostname,ip\nweb01,10.0.0.1', '[{"name":"web01","ip":"10.0.0.1","natIP":"203.0.113.9"}]']) {
    const r = parseInventory(text);
    for (const s of r.servers) {
      assert.deepEqual(Object.keys(s).sort(), ['aliases', 'groups', 'id', 'ips', 'line', 'name'], text);
    }
    assert.equal(inventoryTopology(r.servers).any, false);
  }
  // GCP's natIP stays one of the server's own addresses, as before (only the key `nat` is topology).
  assert.deepEqual(parseInventory('[{"name":"web01","ip":"10.0.0.1","natIP":"203.0.113.9"}]').servers[0].ips, ['10.0.0.1', '203.0.113.9']);
  // kubectl's container ports are no topology value: read as before (no warning, no server change).
  const k8s = parseInventory(JSON.stringify([{ name: 'web01', ip: '10.0.0.1', ports: [{ containerPort: 80, protocol: 'TCP' }] }]));
  assert.deepEqual([k8s.servers[0].tlsPorts, k8s.warnings], [undefined, []]);
});

test('topology keys: the shared and public addresses of vip= / nat= are no own address (no DUPLICATE_IP, not in stats.ips)', () => {
  const r = parseInventory('lb01 203.0.113.2 vip=203.0.113.50,2001:db8::50\nlb02 203.0.113.3 vip=203.0.113.50\napp01 10.0.0.30 nat=203.0.113.10');
  assert.deepEqual(r.servers.map((s) => [s.name, s.ips, s.vips ?? null, s.nats ?? null]), [
    ['lb01', ['203.0.113.2'], ['203.0.113.50', '2001:db8::50'], null],
    ['lb02', ['203.0.113.3'], ['203.0.113.50'], null],
    ['app01', ['10.0.0.30'], null, ['203.0.113.10']]
  ]);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.stats.ips, 3);
});

test('topology keys: every malformed value is a TOPOLOGY warning naming the key', () => {
  const r = parseInventory([
    'web01 10.0.0.1 ports=443,70000',
    'web02 10.0.0.2 ports=',
    'web03 10.0.0.3 terminates_tls=yes,no',
    'web04 10.0.0.4 vip=[2001:db8::1]:443',
    'web05 10.0.0.5 nat=10.0.0.0/24',
    'web06 10.0.0.6 backends=10.0.0.300',
    'web07 10.0.0.7 backends=',
    'nat=203.0.113.9 # a key without a server'
  ].join('\n'));
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.reason, w.detail]), [
    [1, 'TOPOLOGY', 'ports', 'ports=443,70000'],
    [2, 'TOPOLOGY', 'ports', 'ports='],
    [3, 'TOPOLOGY', 'terminatesTls', 'terminates_tls=yes,no'],
    [4, 'TOPOLOGY', 'vip', 'vip=[2001:db8::1]:443'],
    [5, 'TOPOLOGY', 'nat', 'nat=10.0.0.0/24'],
    [6, 'TOPOLOGY', 'backends', 'backends=10.0.0.300'],
    [7, 'TOPOLOGY', 'backends', 'backends='],
    [8, 'TOPOLOGY', 'noServer', 'nat']
  ]);
  // The servers stay, without the bad value: never a silently dropped server.
  assert.deepEqual(r.servers.map((s) => s.name), ['web01', 'web02', 'web03', 'web04', 'web05', 'web06', 'web07']);
  assert.ok(r.servers.every((s) => !s.tlsPorts && s.terminatesTls === undefined && !s.vips && !s.nats && !s.backends));
  for (const reason of new Set(r.warnings.map((w) => w.reason))) assert.ok(TOPOLOGY_REASONS.includes(reason), reason);
});

test('back-compat: a JSON / YAML `ports` key (Shodan, Ansible host vars) parses as on main, never as TLS ports; tls_ports is the key there', () => {
  // main's exact results for these inputs
  const shodan = JSON.stringify([{ ip_str: '203.0.113.10', ports: [22, 80, 443], hostnames: ['www.example.com'], org: 'Example' }]);
  assert.deepEqual(parseInventory(shodan), {
    servers: [{ id: '203.0.113.10', name: '203.0.113.10', ips: ['203.0.113.10'], groups: [], line: 1, aliases: [] }],
    warnings: [], stats: { lines: 1, servers: 1, ips: 1 }
  });
  assert.deepEqual(parseInventory('all:\n  hosts:\n    web01:\n      ansible_host: 10.0.0.1\n      ports: [22, 80]\n'), {
    servers: [{ id: 'web01', name: 'web01', ips: ['10.0.0.1'], groups: [], line: 4, aliases: [] }],
    warnings: [], stats: { lines: 5, servers: 1, ips: 1 }
  });
  assert.equal(parseInventory(JSON.stringify({ _meta: { hostvars: { web01: { ansible_host: '10.0.0.1', ports: '22,80' } } } })).servers[0].tlsPorts, undefined);
  // tls_ports is read in JSON and YAML
  const json = parseInventory(JSON.stringify([{ name: 'web01', ip: '10.0.0.1', tls_ports: [443, 8443] }]));
  assert.deepEqual([json.servers[0].tlsPorts, serverTargets(json.servers[0]), json.warnings], [[443, 8443], ['10.0.0.1:443', '10.0.0.1:8443'], []]);
  assert.deepEqual(parseInventory('all:\n  hosts:\n    web01:\n      ansible_host: 10.0.0.1\n      tlsPorts: 8443\n').servers[0].tlsPorts, [8443]);
  // on a line and in a CSV column both spellings are read
  assert.deepEqual(parseInventory('web01 10.0.0.1 tls_ports=8443').servers[0].tlsPorts, [8443]);
  assert.deepEqual(parseInventory('name,ip,TLS Ports\nweb01,10.0.0.1,8443').servers[0].tlsPorts, [8443]);
});

test('topology keys on a line with no server: noServer only when nothing else was said about the line', () => {
  const said = (text) => parseInventory(text).warnings.map((w) => [w.line, w.code, w.reason ?? null]);
  assert.deepEqual(said('web01.example.net:8443 ports=443'), [[1, 'PARSE', 'hostPort']], 'a host name with a port: PARSE says it');
  assert.deepEqual(said('[web] ports=443\nweb01 10.0.0.1'), [[1, 'PARSE', null]]);
  assert.deepEqual(said('ports=443'), [[1, 'TOPOLOGY', 'noServer']]);
});

test('topology keys: a key a letter off is never read silently; a CSV header too', () => {
  const r = parseInventory('bad07 10.0.0.56 backend=pool01 port=8443 vips=203.0.113.71 terminate_tls=no terminates.tls=no');
  assert.deepEqual(r.warnings.map((w) => [w.reason, w.detail]), [
    ['nearMiss', 'backend=pool01 (backends=?)'], ['nearMiss', 'port=8443 (ports=?)'], ['nearMiss', 'vips=203.0.113.71 (vip=?)'],
    ['nearMiss', 'terminate_tls=no (terminates_tls=?)']
  ]);
  assert.equal(r.servers[0].terminatesTls, false, 'terminates.tls is the key itself, written with a dot');
  const csv = parseInventory('name,ip,backend\nlb01,203.0.113.2,web01');
  assert.deepEqual(csv.warnings.map((w) => [w.line, w.reason, w.detail]), [[1, 'nearMiss', 'backend (backends?)']]);
  // Ansible variables that only end like a key (ansible_port, http_port) are none
  assert.deepEqual(parseInventory('[web]\nweb01 ansible_host=10.0.0.1 ansible_port=2222 http_port=80').warnings, []);
});

test('topology keys: on a line, ; and | continue a value unless a key= follows', () => {
  const r = parseInventory([
    'web01 10.0.0.1 ports=443;8443', 'web02 10.0.0.2 ports=443|8443', 'lb01;203.0.113.2;ports=443;terminates_tls=no',
    'web03 | 10.0.0.3 | ports=443 | terminates_tls=no', 'web04 10.0.0.4 ports=443;terminates_tls=no'
  ].join('\n'));
  assert.deepEqual(r.servers.map((s) => [s.name, s.tlsPorts, s.terminatesTls ?? null]), [
    ['web01', [443, 8443], null], ['web02', [443, 8443], null], ['lb01', [443], false], ['web03', [443], false], ['web04', [443], false]
  ]);
  assert.deepEqual(r.warnings, []);
});

test('topology keys: JSON / YAML list items and strings and CSV cells split on , and ; only (a name may hold spaces)', () => {
  const json = parseInventory(JSON.stringify([{ name: 'lb01', ip: '203.0.113.2', backends: ['Web Server 1', 'Web Server 2'] },
    { name: 'Web Server 1', ip: '10.0.0.1' }, { name: 'Web Server 2', ip: '10.0.0.2', terminates_tls: 'no' }]));
  assert.deepEqual([json.servers[0].backends, json.warnings], [['Web Server 1', 'Web Server 2'], []]);
  const aws = parseInventory(JSON.stringify({ Reservations: [{ Instances: [
    { PrivateIpAddress: '203.0.113.2', Tags: [{ Key: 'Name', Value: 'edge lb' }], backends: 'prod web 1; prod web 2' },
    { PrivateIpAddress: '10.0.0.1', Tags: [{ Key: 'Name', Value: 'prod web 1' }] },
    { PrivateIpAddress: '10.0.0.2', Tags: [{ Key: 'Name', Value: 'prod web 2' }] }] }] }));
  assert.deepEqual([aws.servers.find((s) => s.name === 'edge lb').backends, aws.warnings], [['prod web 1', 'prod web 2'], []]);
  const csv = parseInventory('name,ip,backends\n"Load Balancer 1",203.0.113.2,"Web Server 1;Web Server 2"\n"Web Server 1",10.0.0.1,\n"Web Server 2",10.0.0.2,');
  assert.deepEqual([csv.servers[0].backends, csv.warnings], [['Web Server 1', 'Web Server 2'], []]);
  // a comma still splits a string, spaces around it go
  const list = parseInventory(JSON.stringify([{ name: 'lb01', ip: '203.0.113.2', backends: 'web01, web02' },
    { name: 'web01', ip: '10.0.0.1' }, { name: 'web02', ip: '10.0.0.2' }]));
  assert.deepEqual(list.servers[0].backends, ['web01', 'web02']);
  // a space-separated list in a structured string is one item: an address list that cannot be one is a warning
  const vip = parseInventory(JSON.stringify([{ name: 'lb01', ip: '203.0.113.2', vip: '203.0.113.50 203.0.113.51' }]));
  assert.deepEqual(vip.warnings.map((w) => [w.code, w.reason]), [['TOPOLOGY', 'vip']]);
});

test('topology keys: TLS ports that usually carry no TLS (22, 80, 3306 …) replace -p only with a warning', () => {
  const r = parseInventory('web01 10.0.0.1 ports=22,80\nweb02 10.0.0.2 ports=443,8443\nweb03 10.0.0.3 tls_ports=3306');
  assert.deepEqual(r.servers.map((s) => [s.name, s.tlsPorts]), [['web01', [22, 80]], ['web02', [443, 8443]], ['web03', [3306]]]);
  assert.deepEqual(r.warnings.map((w) => [w.line, w.code, w.reason, w.detail]), [
    [1, 'TOPOLOGY', 'plainPorts', 'ports=22,80'], [3, 'TOPOLOGY', 'plainPorts', 'tls_ports=3306']
  ]);
  assert.deepEqual(parseInventory('hostname,ip,ports\nweb01,10.0.0.1,"22,80"').warnings.map((w) => [w.line, w.reason]), [[2, 'plainPorts']]);
});

test('topology keys: terminates_tls given both ways keeps yes, the safe value, and warns', () => {
  for (const text of ['web01 10.0.0.1 terminates_tls=no\nweb01 10.0.0.1 terminates_tls=yes', 'web01 10.0.0.1 terminates_tls=yes\nweb01 10.0.0.1 terminates_tls=no',
    'web01 10.0.0.1 terminates_tls=no terminates_tls=yes', 'web01 10.0.0.1 terminates_tls=no\n10.0.0.1 terminates_tls=yes']) {
    const r = parseInventory(text);
    assert.deepEqual(r.servers.map((s) => [s.name, s.terminatesTls]), [['web01', true]], text);
    assert.deepEqual(r.warnings.map((w) => [w.code, w.reason]), [['TOPOLOGY', 'conflict']], text);
  }
  // the same value twice is no conflict
  assert.deepEqual(parseInventory('web01 10.0.0.1 terminates_tls=no\nweb01 10.0.0.1 terminates_tls=off').warnings, []);
});

test('topology keys: names, booleans and spellings; backends by name, by address, across lines', () => {
  const r = parseInventory([
    'LB01 203.0.113.2 Backends=WEB01 terminatesTls=Yes',
    'lb01 203.0.113.2 backends=10.0.0.22',
    'web01 10.0.0.21 terminates-tls=off',
    '10.0.0.22',
    'web03 10.0.0.23 terminates_tls=0'
  ].join('\n'));
  // Named servers first, then the unnamed ones (named by their address), as always.
  assert.deepEqual(r.servers.map((s) => [s.name, s.backends ?? null, s.terminatesTls ?? null]), [
    ['LB01', ['web01', '10.0.0.22'], true],
    ['web01', null, false],
    ['web03', null, false],
    ['10.0.0.22', null, null]
  ]);
  assert.deepEqual(TOPOLOGY_KEYS, ['ports', 'tls_ports', 'terminates_tls', 'vip', 'backends', 'nat']);
  assert.equal(terminatesTls(r.servers[0]), true);
  assert.equal(terminatesTls(r.servers[1]), false);
  assert.equal(terminatesTls({}), true, 'not given: yes');
});

test('lookupServers: DNS answers match through nat= and vip= and say so', () => {
  const { servers } = parseInventory('lb01 203.0.113.2 vip=203.0.113.50\nlb02 203.0.113.3 vip=203.0.113.50\napp01 10.0.0.30 nat=203.0.113.10\nweb01 203.0.113.12');
  const index = buildIpIndex(servers);
  assert.deepEqual(lookupServers(['203.0.113.50', '203.0.113.10', '203.0.113.2', '::ffff:203.0.113.10', '203.0.113.12'], index)
    .map((m) => [m.server.name, m.ip, m.through ?? null]), [
    ['lb01', '203.0.113.50', 'vip'],
    ['lb02', '203.0.113.50', 'vip'],
    ['app01', '203.0.113.10', 'nat'],
    ['lb01', '203.0.113.2', null],
    ['app01', '::ffff:203.0.113.10', 'nat'],
    ['web01', '203.0.113.12', null]
  ]);
  // An own address answered directly has no `through`: the result shape of an old inventory.
  assert.deepEqual(Object.keys(lookupServers(['203.0.113.12'], index)[0]).sort(), ['ip', 'server']);
});

test('inventoryTopology: a passthrough load balancer with TLS terminating nowhere behind it (through every tier)', () => {
  const { servers } = parseInventory(readFileSync(new URL('checks.txt', TOPOLOGY_DIR), 'utf8'));
  assert.deepEqual([...inventoryTopology(servers).nowhere].map((s) => s.name), ['edge01']);
  // the holders of one VIP that disagree: the card lists only those that terminate TLS
  const vip = inventoryTopology(servers).vips.find((v) => v.ip === '203.0.113.70');
  assert.deepEqual([vip.servers.map((s) => s.name), vip.plain.map((s) => s.name)], [['db02', 'db03'], ['db03']]);
});

test('inventoryTopology: load balancers with their backends, VIP holders, NAT pairs, plain servers', () => {
  const { servers } = parseInventory(readFileSync(new URL('inventory.txt', TOPOLOGY_DIR), 'utf8'));
  const topo = inventoryTopology(servers);
  assert.equal(topo.any, true);
  assert.deepEqual(topo.lbs.map((lb) => [lb.server.name, lb.backends.map((b) => b.name)]), [['lb01', ['web01', 'web02']], ['lb02', ['web01', 'web02']]]);
  assert.deepEqual(topo.vips.map((v) => [v.ip, v.servers.map((s) => s.name)]), [['203.0.113.50', ['lb01', 'lb02']]]);
  assert.deepEqual(topo.nats.map((n) => [n.ip, n.server.name]), [['203.0.113.10', 'app01']]);
  assert.deepEqual(topo.plain.map((s) => s.name), ['web01', 'web03']);
  assert.deepEqual([...topo.backendOf].map(([b, lbs]) => [b.name, lbs.map((s) => s.name)]), [['web01', ['lb01', 'lb02']], ['web02', ['lb01', 'lb02']]]);
});

test('topologyTokens: what targets.txt writes for the CLI', () => {
  const { servers } = parseInventory('lb01 203.0.113.2 vip=203.0.113.50 backends=web01,10.0.0.22\nweb01 10.0.0.21 terminates_tls=no ports=8443\n10.0.0.22\napp01 10.0.0.30 nat=203.0.113.10');
  assert.deepEqual(servers.map((s) => [s.name, topologyTokens(s, (n) => (n.includes('.') ? '' : n))]), [
    ['lb01', ['backends=web01,10.0.0.22', 'vip=203.0.113.50']],
    ['web01', ['terminates_tls=no']],
    ['app01', ['nat=203.0.113.10']],
    ['10.0.0.22', []]
  ]);
});
