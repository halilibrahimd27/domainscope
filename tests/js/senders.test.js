/**
 * lib/senders.js — the service behind a DMARC report source: the table (ids, types, guides,
 * suffixes), the matchers (longest suffix, a macro include, case and the final dot), each way a
 * source is named (DKIM, return-path, SPF include, reverse DNS, the ISP list, the network) and
 * their order, the own organisation never named, what is no evidence (a failed signature, a
 * return-path that failed SPF), the ISP label, unknown; the path of the SPF verdict, the guide of
 * a forwarder, what an Identify click looks up, the grouping with its totals, the CSV, and the
 * bundled lists read and refused. With classifySources over a fake DoH: a source authorized by a
 * service's include is named by it. Pure Node, no network; documentation addresses only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  SENDER_SERVICES, SENDER_TYPES, SENDER_VIAS, CONFIDENCES, SERVICE_GUIDES, SENDER_GUIDES, PTR_TYPE_MAP, PASSPORT_KINDS, SENDERS_FILES,
  IDENTIFY_MAX, SERVICE_CSV_COLUMNS, passportKind, suffixesOf, serviceById, serviceBySpf, serviceByDkim, serviceByReturnPath, serviceByPtr,
  lookupMap, spfPathOf, identifySource, senderGuide, identifyCandidates, groupKey, groupSources, serviceCsvRows, installSenderMaps,
  loadSenderMaps, resetSenderMaps
} from '../../assets/js/lib/senders.js';
import { MAIL_PLATFORMS } from '../../assets/js/lib/passport.js';
import { aggregateDmarc, parseAggregateReport, loadSpfContext, classifySources } from '../../assets/js/lib/dmarcreport.js';
import { hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

/** A source row as lib/dmarcreport.js classifySources gives it (only what identifySource reads). */
const row = (over = {}) => ({
  ip: '192.0.2.10', private: false, messages: 10, pass: 10, fail: 0, spfAligned: 0, dkimAligned: 10, cls: 'third-party',
  headerFrom: ['example.com'], dkimAuth: [], spfAuth: [], spfNow: null, spfListed: null, ...over
});
/** Bundled lists of documentation names, as installSenderMaps returns them. */
const MAPS = {
  ptr: new Map([['mailhost.example.net', ['Example Mail Hosting', 'hosting']], ['esp.example.org', ['Example ESP', 'marketing']]]),
  isp: new Set(['broadband.example.net'])
};

describe('the table', () => {
  test('frozen, ids unique, every type and guide known, every suffix a lower-case name', () => {
    assert.ok(Object.isFrozen(SENDER_SERVICES) && SENDER_SERVICES.every(Object.isFrozen));
    assert.ok(SENDER_SERVICES.length >= 60, `about 60 services: ${SENDER_SERVICES.length}`);
    const ids = SENDER_SERVICES.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, 'unique ids');
    const names = SENDER_SERVICES.map((s) => s.name);
    assert.equal(new Set(names).size, names.length, 'unique names');
    for (const s of SENDER_SERVICES) {
      assert.ok(SENDER_TYPES.includes(s.type) && !['isp', 'network'].includes(s.type), `${s.id}: ${s.type}`);
      assert.ok(SENDER_GUIDES.includes(s.guide), `${s.id}: guide ${s.guide}`);
      assert.ok(s.spf.length + s.dkim.length + s.returnPath.length + s.ptr.length > 0, `${s.id}: some evidence`);
      for (const f of ['spf', 'dkim', 'returnPath', 'ptr']) {
        assert.ok(Object.isFrozen(s[f]), `${s.id}.${f} frozen`);
        for (const x of s[f]) assert.match(x, /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/, `${s.id}.${f}: ${x}`);
      }
    }
    // the services with their own guide exist; every type has one too
    for (const g of SERVICE_GUIDES) assert.ok(serviceById(g) && serviceById(g).guide === g, g);
    assert.deepEqual(SENDER_GUIDES, [...SERVICE_GUIDES, ...SENDER_TYPES, 'forwarded']);
    for (const v of [SENDER_TYPES, SENDER_VIAS, CONFIDENCES, SERVICE_GUIDES, SENDER_GUIDES, PASSPORT_KINDS, SENDERS_FILES, SERVICE_CSV_COLUMNS, PTR_TYPE_MAP]) {
      assert.ok(Object.isFrozen(v));
    }
    assert.deepEqual(SENDER_VIAS, ['dkim', 'return-path', 'spf-include', 'ptr', 'isp', 'asn']);
    assert.equal(IDENTIFY_MAX, 200);
    assert.equal(serviceById('nope'), null);
  });

  test('the ids lib/passport.js shares name the same platform; passport kinds', () => {
    for (const p of MAIL_PLATFORMS) {
      const s = serviceById(p.id);
      if (!s) continue;
      assert.equal(s.name, p.name, p.id);
      assert.equal(passportKind(s.type), p.kind, p.id);
    }
    assert.deepEqual(['mailbox', 'security', 'forwarding', 'transactional', 'marketing', 'saas', 'cloud', 'hosting'].map(passportKind),
      ['mailbox', 'gateway', 'forwarding', 'sending', 'sending', 'sending', 'sending', 'sending']);
    for (const t of SENDER_TYPES) assert.ok(PASSPORT_KINDS.includes(passportKind(t)), t);
    // every map type lib/senders.js may read is one of ours
    for (const t of Object.values(PTR_TYPE_MAP)) assert.ok(SENDER_TYPES.includes(t), t);
  });

  test('matchers: the longest suffix on a label boundary, a macro include, case and the final dot', () => {
    assert.equal(serviceBySpf('spf.protection.outlook.com')?.id, 'microsoft365');
    assert.equal(serviceBySpf('SPF.PROTECTION.OUTLOOK.COM.')?.id, 'microsoft365');
    assert.equal(serviceBySpf('_spf.google.com')?.id, 'google');
    assert.equal(serviceBySpf('%{ir}.%{v}.%{d}.spf.has.pphosted.com')?.id, 'proofpoint', 'a macro include by its suffix');
    assert.equal(serviceBySpf('eu._netblocks.mimecast.com')?.id, 'mimecast');
    assert.equal(serviceBySpf('servers.mcsv.net')?.id, 'mailchimp');
    assert.equal(serviceBySpf('spf.mandrillapp.com')?.id, 'mandrill');
    assert.equal(serviceBySpf('one.zoho.com')?.id, 'zoho');
    assert.equal(serviceBySpf('zcsend.net')?.id, 'zohocampaigns');
    assert.equal(serviceBySpf('mx.sendgrid.net.example.com'), null, 'a service domain inside another name');
    assert.equal(serviceBySpf('xsendgrid.net'), null, 'another domain');
    assert.equal(serviceBySpf('google.com'), null, 'only _spf.google.com is Workspace');
    assert.equal(serviceBySpf('spf.example.net'), null);
    assert.equal(serviceBySpf(''), null);
    assert.equal(serviceByDkim('example-com.20230601.gappssmtp.com')?.id, 'google');
    assert.equal(serviceByDkim('contoso.onmicrosoft.com')?.id, 'microsoft365');
    assert.equal(serviceByDkim('example-com.n-v1.dkim.mail.microsoft')?.id, 'microsoft365');
    assert.equal(serviceByDkim('sendgrid.net')?.id, 'sendgrid');
    assert.equal(serviceByReturnPath('bounces.amazonses.com')?.id, 'amazonses');
    assert.equal(serviceByReturnPath('pm.mtasv.net')?.id, 'postmark');
    assert.equal(serviceByReturnPath('_spf.google.com'), null, 'an SPF include is no return-path');
    assert.equal(serviceByPtr('a8-31.smtp-out.amazonses.com')?.id, 'amazonses');
    assert.equal(serviceByPtr('mout.kundenserver.de')?.id, 'ionos');
    assert.equal(serviceByPtr('mail-yw1-f170.google.com'), null, 'Google\'s own reverse names are left to the bundled map');
    assert.deepEqual(suffixesOf('a.b.Example.com.'), ['a.b.example.com', 'b.example.com', 'example.com']);
    assert.deepEqual(suffixesOf('localhost'), []);
    assert.deepEqual(suffixesOf('a..example.com'), []);
    assert.deepEqual(lookupMap(MAPS.ptr, 'host-1.mailhost.example.net'), { key: 'mailhost.example.net', name: 'Example Mail Hosting', type: 'hosting' });
    assert.equal(lookupMap(MAPS.ptr, 'example.net'), null);
    assert.equal(lookupMap(null, 'host-1.mailhost.example.net'), null);
  });
});

describe('identifySource', () => {
  test('dkim: a verified signature of a service, never one of the header From\'s own organisation', () => {
    const r = row({ dkimAuth: [{ domain: 'example.com', selector: 's1', result: 'pass' }, { domain: 'sendgrid.net', selector: 's1', result: 'pass' }] });
    assert.deepEqual(identifySource(r), { id: 'sendgrid', service: 'SendGrid', type: 'transactional', via: 'dkim', confidence: 'high', domain: 'sendgrid.net', guide: 'sendgrid' });
    assert.equal(identifySource(row({ dkimAuth: [{ domain: 'sendgrid.net', result: 'fail' }] })), null, 'a signature that failed names nothing');
    // the policy domain is SendGrid's own: its signature is the domain's, not a service's
    assert.equal(identifySource(row({ headerFrom: ['sendgrid.net'], dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] })), null);
    assert.equal(identifySource(row({ headerFrom: [], dkimAuth: [{ domain: 'mail.sendgrid.net', result: 'pass' }] }), { domain: 'sendgrid.net' }), null);
    // a service the table does not know, but the bundled map does
    const mapped = identifySource(row({ dkimAuth: [{ domain: 'esp.example.org', result: 'pass' }] }), { maps: MAPS });
    assert.deepEqual(mapped, { id: null, service: 'Example ESP', type: 'marketing', via: 'dkim', confidence: 'high', domain: 'esp.example.org', guide: 'marketing' });
  });

  test('return-path: a domain of a service that passed SPF (the HELO too); one that failed is no evidence', () => {
    const r = row({ spfAuth: [{ domain: 'pm.mtasv.net', scope: 'mfrom', result: 'pass' }] });
    assert.equal(identifySource(r).via, 'return-path');
    assert.equal(identifySource(r).id, 'postmark');
    assert.equal(identifySource(row({ spfAuth: [{ domain: 'a8-31.smtp-out.amazonses.com', scope: 'helo', result: 'pass' }] })).id, 'amazonses');
    assert.equal(identifySource(row({ spfAuth: [{ domain: 'amazonses.com', scope: 'mfrom', result: 'fail' }] })), null, 'forwarded or forged');
    assert.equal(identifySource(row({ spfAuth: [{ domain: 'bounce.example.com', result: 'pass' }] })), null, 'its own bounce domain');
  });

  test('spf-include: the include on the path of the verdict that authorizes the address', () => {
    const verdict = { result: 'pass', term: 'ip4:192.0.2.0/24', holder: '_spf.google.com', path: ['example.com', '_spf.google.com'], via: null };
    const r = row({ spfNow: verdict });
    assert.deepEqual(spfPathOf(r), ['example.com', '_spf.google.com']);
    assert.deepEqual(identifySource(r, { spfPath: spfPathOf(r) }),
      { id: 'google', service: 'Google Workspace', type: 'mailbox', via: 'spf-include', confidence: 'high', domain: '_spf.google.com', guide: 'google' });
    // the first foreign domain on the path names it; the domain's own include does not
    const nested = { ...verdict, path: ['example.com', '_spf.example.com', 'spf.protection.outlook.com', 'spf-a.outlook.com'] };
    assert.equal(identifySource(row({ spfNow: nested }), { spfPath: spfPathOf(row({ spfNow: nested })) }).id, 'microsoft365');
    // an a / mx host that matched counts as the last element
    const viaHost = { result: 'pass', term: 'a:mail.zendesk.com', holder: 'example.com', path: ['example.com'], via: { host: 'mail.zendesk.com', address: '192.0.2.10' } };
    assert.deepEqual(spfPathOf(row({ spfNow: viaHost })), ['example.com', 'mail.zendesk.com']);
    assert.equal(identifySource(row(), { spfPath: spfPathOf(row({ spfNow: viaHost })) }).id, 'zendesk');
    // a permerror: what the broken record lists
    const listed = row({ spfNow: { result: 'permerror', path: ['example.com'] }, spfListed: verdict });
    assert.deepEqual(spfPathOf(listed), ['example.com', '_spf.google.com']);
    // not authorized: nothing on the path
    assert.deepEqual(spfPathOf(row({ spfNow: { ...verdict, result: 'softfail' } })), []);
    assert.deepEqual(spfPathOf(row()), []);
    assert.equal(identifySource(row(), { spfPath: ['example.com', 'spf.example.net'] }), null, 'an include of another organisation the table does not know');
  });

  test('ptr: the reverse name in the table or the bundled map, medium when confirmed forward, else low', () => {
    assert.deepEqual(identifySource(row(), { ptrName: 'a8-31.smtp-out.amazonses.com', ptrConfirmed: true }),
      { id: 'amazonses', service: 'Amazon SES', type: 'transactional', via: 'ptr', confidence: 'medium', domain: 'a8-31.smtp-out.amazonses.com', guide: 'amazonses' });
    assert.equal(identifySource(row(), { ptrName: 'a8-31.smtp-out.amazonses.com' }).confidence, 'low');
    const mapped = identifySource(row(), { ptrName: 'web42.mailhost.example.net.', ptrConfirmed: true, maps: MAPS });
    assert.deepEqual(mapped, { id: null, service: 'Example Mail Hosting', type: 'hosting', via: 'ptr', confidence: 'medium', domain: 'web42.mailhost.example.net', guide: 'hosting' });
    assert.equal(identifySource(row(), { ptrName: 'web42.mailhost.example.net' }), null, 'without the lists, only the table');
    assert.equal(identifySource(row(), { ptrName: 'mail.example.com', ptrConfirmed: true, maps: MAPS }), null, 'its own server names no service');
  });

  test('isp: an ISP or home network by its reverse name, labelled with its base domain', () => {
    const id = identifySource(row({ cls: 'unknown' }), { ptrName: 'dsl-203-0-113-7.pool.broadband.example.net', ptrConfirmed: true, maps: MAPS });
    assert.deepEqual(id, { id: null, service: 'broadband.example.net', type: 'isp', via: 'isp', confidence: 'medium', domain: 'dsl-203-0-113-7.pool.broadband.example.net', guide: 'isp' });
    assert.equal(identifySource(row(), { ptrName: 'x.broadband.example.net', maps: MAPS }).confidence, 'low');
    assert.equal(senderGuide(id, row({ cls: 'unknown' })), 'isp');
  });

  test('asn: only the network\'s holder, for what nothing else names', () => {
    assert.deepEqual(identifySource(row(), { holder: { name: ' Example Hosting Ltd ', asn: 64496 } }),
      { id: null, service: 'Example Hosting Ltd', type: 'network', via: 'asn', confidence: 'low', domain: 'AS64496', guide: 'network' });
    assert.equal(identifySource(row(), { holder: { name: 'Example Hosting Ltd' } }).domain, '');
    assert.equal(identifySource(row(), { holder: { name: '  ' } }), null);
  });

  test('the order: DKIM, then the return-path, the include, the reverse name, the ISP list, the network', () => {
    const all = {
      dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }],
      spfAuth: [{ domain: 'pm.mtasv.net', result: 'pass' }],
      spfNow: { result: 'pass', path: ['example.com', '_spf.google.com'] }
    };
    const opts = (r) => ({ spfPath: spfPathOf(r), ptrName: 'a8-31.smtp-out.amazonses.com', ptrConfirmed: true, maps: MAPS, holder: { name: 'Example Hosting Ltd', asn: 64496 } });
    const via = (r, over = {}) => identifySource(r, { ...opts(r), ...over }).via;
    const full = row(all);
    const noDkim = row({ ...all, dkimAuth: [] });
    const noReturnPath = row({ ...all, dkimAuth: [], spfAuth: [] });
    const noInclude = row({ ...all, dkimAuth: [], spfAuth: [], spfNow: null });
    const vias = [via(full), via(noDkim), via(noReturnPath), via(noInclude), via(noInclude, { ptrName: 'x.broadband.example.net' }), via(noInclude, { ptrName: null })];
    assert.deepEqual(vias, [...SENDER_VIAS]);
  });

  test('unknown: nothing names it', () => {
    assert.equal(identifySource(row()), null);
    assert.equal(identifySource(row(), { maps: MAPS, ptrName: 'host.example.org' }), null);
    assert.equal(identifySource(null), null);
  });

  test('senderGuide: a forwarder named by the signature it carries gets "forwarded"', () => {
    const id = identifySource(row({ dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }));
    assert.equal(senderGuide(id, { cls: 'forwarder' }), 'forwarded');
    assert.equal(senderGuide(id, { cls: 'third-party' }), 'sendgrid');
    const byPtr = identifySource(row(), { ptrName: 'a8-31.smtp-out.amazonses.com', ptrConfirmed: true });
    assert.equal(senderGuide(byPtr, { cls: 'forwarder' }), 'amazonses', 'a reverse name is the address\'s own');
    assert.equal(senderGuide(null, { cls: 'forwarder' }), null);
    for (const s of SENDER_SERVICES) assert.ok(SENDER_GUIDES.includes(senderGuide({ ...s, via: 'dkim' }, { cls: 'forwarder' })));
  });
});

describe('Identify senders', () => {
  test('identifyCandidates: public, unnamed or weakly named, not looked up yet; the most mail first, at most max', () => {
    const rows = [
      row({ ip: '192.0.2.1', messages: 5 }),
      row({ ip: '192.0.2.2', messages: 50, dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }),
      row({ ip: '10.0.0.3', private: true, messages: 99 }),
      row({ ip: '192.0.2.4', messages: 20 }),
      row({ ip: '192.0.2.5', messages: 30 }),
      row({ ip: '192.0.2.6', messages: 1 })
    ];
    const weak = new Map([['192.0.2.5', { via: 'ptr', confidence: 'low' }], ['192.0.2.6', { via: 'asn', confidence: 'low' }]]);
    const identOf = (r) => weak.get(r.ip) || identifySource(r);
    const pick = (opts) => identifyCandidates(rows, { identOf, ...opts }).map((r) => r.ip);
    assert.deepEqual(pick(), ['192.0.2.5', '192.0.2.4', '192.0.2.1', '192.0.2.6']);
    assert.deepEqual(pick({ checked: new Set(['192.0.2.4']) }), ['192.0.2.5', '192.0.2.1', '192.0.2.6']);
    assert.deepEqual(pick({ max: 2 }), ['192.0.2.5', '192.0.2.4']);
    weak.set('192.0.2.5', { via: 'ptr', confidence: 'medium' });
    assert.deepEqual(pick(), ['192.0.2.4', '192.0.2.1', '192.0.2.6'], 'a confirmed reverse name needs no second look');
  });

  test('groupSources: one row per service with totals, every ISP together, the unnamed last', () => {
    const rows = [
      row({ ip: '192.0.2.1', messages: 100, pass: 100, dkimAligned: 100, spfAligned: 0, cls: 'third-party', dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }),
      row({ ip: '192.0.2.2', messages: 40, pass: 30, fail: 10, dkimAligned: 30, cls: 'forwarder', dkimAuth: [{ domain: 'o1.sendgrid.net', result: 'pass' }] }),
      row({ ip: '192.0.2.3', messages: 5, pass: 0, fail: 5, dkimAligned: 0, cls: 'unknown' }),
      row({ ip: '198.51.100.4', messages: 7, pass: 0, fail: 7, dkimAligned: 0, cls: 'unknown' }),
      row({ ip: '198.51.100.5', messages: 300, pass: 300, spfAligned: 300, dkimAligned: 0, cls: 'third-party', spfAuth: [{ domain: 'pm.mtasv.net', result: 'pass' }] }),
      row({ ip: '203.0.113.6', messages: 2, pass: 0, fail: 2, dkimAligned: 0, cls: 'unknown' })
    ];
    const ptr = { '192.0.2.3': 'a.broadband.example.net', '198.51.100.4': 'b.broadband.example.net' };
    const identOf = (r) => identifySource(r, { ptrName: ptr[r.ip], ptrConfirmed: r.ip === '192.0.2.3', maps: MAPS });
    const { groups, totals } = groupSources(rows, identOf);
    assert.deepEqual(groups.map((g) => g.key), ['svc:postmark', 'svc:sendgrid', 'isp', 'unnamed']);
    const sg = groups[1];
    assert.deepEqual([sg.service, sg.type, sg.addresses, sg.messages, sg.pass, sg.fail, sg.dkimAligned], ['SendGrid', 'transactional', 2, 140, 130, 10, 130]);
    assert.deepEqual(sg.classes, { 'third-party': 1, forwarder: 1 });
    assert.deepEqual(sg.vias, ['dkim']);
    assert.deepEqual(sg.evidence, ['sendgrid.net', 'o1.sendgrid.net']);
    assert.deepEqual(sg.rows.map((r) => r.ip), ['192.0.2.1', '192.0.2.2'], 'most mail first');
    const isp = groups[2];
    assert.deepEqual([isp.service, isp.type, isp.addresses, isp.confidence, isp.evidence], [null, 'isp', 2, 'medium', ['broadband.example.net']]);
    assert.deepEqual([groups[3].service, groups[3].addresses, groups[3].confidence], [null, 1, null]);
    assert.deepEqual(totals, { services: 3, addresses: 6, messages: 454, unnamedAddresses: 1, unnamedMessages: 2 });
    assert.equal(groupKey(null), 'unnamed');
    assert.equal(groupKey({ id: null, via: 'asn', service: 'Example Hosting Ltd' }), 'net:example hosting ltd');
    assert.equal(groupKey({ id: null, via: 'ptr', service: 'Example Mail Hosting' }), 'name:example mail hosting');
    assert.deepEqual(groupSources([], identOf), { groups: [], totals: { services: 0, addresses: 0, messages: 0, unnamedAddresses: 0, unnamedMessages: 0 } });
  });

  test('serviceCsvRows: one row per group with every column', () => {
    const rows = [row({ ip: '192.0.2.1', dkimAuth: [{ domain: 'sendgrid.net', result: 'pass' }] }), row({ ip: '192.0.2.9', cls: 'unknown' })];
    const out = serviceCsvRows(groupSources(rows, (r) => identifySource(r)).groups);
    for (const r of out) assert.deepEqual(Object.keys(r), [...SERVICE_CSV_COLUMNS]);
    assert.deepEqual(out.map((r) => [r.service, r.type, r.via, r.classes, r.sources]), [
      ['SendGrid', 'transactional', 'dkim', 'third-party=1', '192.0.2.1'],
      ['', '', '', 'unknown=1', '192.0.2.9']
    ]);
  });
});

describe('the bundled lists', () => {
  const manifest = { format: 1, generated: '2026-10-08', source: { commit: 'a'.repeat(40) } };
  const ptrMap = { format: 1, map: { 'mailhost.example.net': ['Example Mail Hosting', 'hosting'] } };
  const isp = { format: 1, domains: ['broadband.example.net'] };

  test('installSenderMaps: reads the shape the builder writes and refuses any other', () => {
    const maps = installSenderMaps({ manifest, ptrMap, isp });
    assert.deepEqual(maps.ptr.get('mailhost.example.net'), ['Example Mail Hosting', 'hosting']);
    assert.ok(maps.isp.has('broadband.example.net'));
    assert.deepEqual(maps.info, { generated: '2026-10-08', commit: 'a'.repeat(40), ptr: 1, isp: 1 });
    const bad = [
      { manifest: { ...manifest, format: 2 } },
      { manifest: { ...manifest, generated: 'yesterday' } },
      { ptrMap: { ...ptrMap, map: [] } },
      { ptrMap: { ...ptrMap, map: { 'Not A Name': ['X', 'hosting'] } } },
      { ptrMap: { ...ptrMap, map: { 'x.example.net': ['X', 'isp'] } } },
      { ptrMap: { ...ptrMap, map: { 'x.example.net': ['', 'hosting'] } } },
      { ptrMap: { ...ptrMap, map: { 'x.example.net': 'X' } } },
      { isp: { ...isp, domains: ['no-dot'] } },
      { isp: { format: 1 } }
    ];
    for (const over of bad) assert.throws(() => installSenderMaps({ manifest, ptrMap, isp, ...over }), TypeError, JSON.stringify(over));
  });

  test('loadSenderMaps: the files next to the module once, a failed read tried again, an abort', async () => {
    resetSenderMaps();
    const files = {
      'manifest.json': manifest, 'ptr-map.json': ptrMap, 'isp.json': isp
    };
    let calls = 0;
    let down = true;
    const fetchImpl = async (url) => {
      calls += 1;
      const name = String(url).split('/').pop();
      if (down) return new Response('', { status: 503 });
      return new Response(JSON.stringify(files[name]), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    await assert.rejects(loadSenderMaps({ fetchImpl }), /503/);
    down = false;
    const before = calls;
    const [a, b] = await Promise.all([loadSenderMaps({ fetchImpl }), loadSenderMaps({ fetchImpl })]);
    assert.equal(a, b, 'one read shared');
    assert.equal(calls - before, 3, 'the three files once');
    assert.ok(a.isp.has('broadband.example.net'));
    assert.equal(await loadSenderMaps({ fetchImpl }), a, 'kept');
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(loadSenderMaps({ signal: ac.signal }), { name: 'AbortError' }, 'a promise that rejects, never a throw');
    // an abort while the read is in flight ends the wait, not the read
    resetSenderMaps();
    const slow = new AbortController();
    let release;
    const gate = new Promise((r) => { release = r; });
    const gated = async (url) => {
      await gate;
      return fetchImpl(url);
    };
    const waiting = loadSenderMaps({ fetchImpl: gated, signal: slow.signal });
    slow.abort();
    await assert.rejects(waiting, { name: 'AbortError' });
    release();
    assert.ok((await loadSenderMaps({ fetchImpl: gated })).isp.has('broadband.example.net'), 'the read went on');
    resetSenderMaps();
    // in Node, without a fetch: the repository's own files from disk
    const real = await loadSenderMaps();
    const onDisk = JSON.parse(readFileSync(new URL('../../assets/data/senders/manifest.json', import.meta.url), 'utf8'));
    assert.equal(real.ptr.size, onDisk.counts.ptr);
    assert.match(real.ptr.get('sendgrid.net')[0], /SendGrid/);
    assert.equal(identifySource(row(), { ptrName: 'o1.email.sendgrid.net', ptrConfirmed: true, maps: real }).id, 'sendgrid', 'the table first');
    resetSenderMaps();
  });
});

/* ---- with lib/dmarcreport.js: a fake DoH client over a table ---------------------------- */

function fakeDns(table) {
  const response = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ecs: null, ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { signal } = {}) {
    throwIfAborted(signal);
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    const node = table[name];
    if (!node) return response(name, type, { rcode: 'NXDOMAIN' });
    return response(name, type, { answers: (node[type] || []).map((data) => ({ name, type, ttl: 300, data })) });
  }
  async function resolveHost(name, { signal } = {}) {
    const [a, aaaa] = await Promise.all([query(name, 'A', { signal }), query(name, 'AAAA', { signal })]);
    return hostResolutionFrom(name, a, aaaa);
  }
  return { query, resolveHost };
}

test('with classifySources: the service whose include authorizes a source names it; DKIM and the return-path name the others', async () => {
  const rec = (ip, count, auth, dkim = 'fail', spf = 'pass') => `<record><row><source_ip>${ip}</source_ip><count>${count}</count>
    <policy_evaluated><disposition>none</disposition><dkim>${dkim}</dkim><spf>${spf}</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers><auth_results>${auth}</auth_results></record>`;
  const xml = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>s-1</report_id>
    <date_range><begin>1790294400</begin><end>1790380799</end></date_range></report_metadata>
    <policy_published><domain>example.com</domain><p>none</p></policy_published>
    ${rec('203.0.113.30', 40, '<spf><domain>example.com</domain><result>pass</result></spf>')}
    ${rec('198.51.100.61', 25, '<dkim><domain>example.com</domain><result>pass</result></dkim><dkim><domain>sendgrid.net</domain><selector>s1</selector><result>pass</result></dkim><spf><domain>sendgrid.net</domain><result>pass</result></spf>', 'pass', 'fail')}
    ${rec('192.0.2.62', 9, '<dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>pm.mtasv.net</domain><result>pass</result></spf>', 'pass', 'fail')}
    ${rec('192.0.2.99', 3, '<spf><domain>example.com</domain><result>fail</result></spf>', 'fail', 'fail')}
    </feedback>`;
  const parsed = parseAggregateReport(xml);
  assert.ok(parsed.ok, JSON.stringify(parsed));
  const agg = aggregateDmarc([parsed.report]).domains[0];
  const dns = fakeDns({
    'example.com': { TXT: [['v=spf1 ip4:203.0.113.25 include:_spf.google.com ~all']] },
    '_spf.google.com': { TXT: [['v=spf1 ip4:203.0.113.0/26 ~all']] }
  });
  const spf = new Map([['example.com', await loadSpfContext('example.com', { dns })]]);
  const rows = classifySources(agg, { spf });
  const named = Object.fromEntries(rows.map((r) => {
    const id = identifySource(r, { domain: agg.domain, spfPath: spfPathOf(r) });
    return [r.ip, id ? `${id.id}/${id.via}` : null];
  }));
  assert.deepEqual(named, {
    '203.0.113.30': 'google/spf-include',
    '198.51.100.61': 'sendgrid/dkim',
    '192.0.2.62': 'postmark/return-path',
    '192.0.2.99': null
  });
  assert.equal(rows.find((r) => r.ip === '203.0.113.30').cls, 'third-party', 'the class still comes from lib/dmarcreport.js');
});
