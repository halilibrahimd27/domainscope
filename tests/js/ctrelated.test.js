/**
 * Related domains from Certificate Transparency (lib/ctrelated.js): the registrable domains that
 * share certificates with the scanned domain's hosts, from the certificates a scan already has —
 * Cert Spotter's complete name lists, crt.sh's partial ones (the matching names and the common
 * name), both folded into one certificate, and shared multi-customer certificates set apart.
 * Reserved names only (example.com / .net / .org, the .example TLD). No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { relatedDomains, uniqueCerts, SHARED_CERT_DOMAINS, RELATED_NAME_CAP, RELATED_CERT_CAP } from '../../assets/js/lib/ctrelated.js';
import { PERF_FACTOR } from './perf.mjs';

const NOW = Date.parse('2026-09-28T12:00:00Z');
const day = (n) => new Date(NOW + n * 86400000);

/** A Cert Spotter issuance as lib/sources.js reports it (every DNS name of the certificate). */
const spotter = (id, names, { from = -30, to = 60, sha = null, issuer = "C=US, O=Let's Encrypt, CN=R11" } = {}) => ({
  key: `sha256:${sha || String(id).padStart(64, '0')}`, source: 'certspotter', sources: ['certspotter'], id: String(id), serialHex: null,
  issuer, issuerFriendlyName: "Let's Encrypt", notBefore: day(from), notAfter: day(to), names, sha256: sha || String(id).padStart(64, '0'), url: null
});
/** A crt.sh certificate (the matching names and the common name only). */
const crtsh = (id, serial, names, { from = -30, to = 60 } = {}) => ({
  key: `crtsh:7:${serial}`, source: 'crtsh', sources: ['crtsh'], id, serialHex: serial, issuer: 'C=US, O=Example CA, CN=Example R1',
  notBefore: day(from), notAfter: day(to), names, sha256: null, url: `https://crt.sh/?id=${id}`
});

describe('uniqueCerts', () => {
  test('folds exact keys and a crt.sh certificate into its Cert Spotter twin (same validity, a subset of its names)', () => {
    const full = spotter(1, ['example.com', 'example.net', 'www.example.com', 'www.example.net']);
    const twin = crtsh(11, 'aa01', ['example.com', 'www.example.com']);
    const other = crtsh(12, 'aa02', ['shop.example.com'], { from: -10 });
    const list = uniqueCerts([twin, full, { ...full, sources: ['certspotter'] }, other]);
    assert.equal(list.length, 2);
    const merged = list.find((c) => c.key === full.key);
    assert.deepEqual(merged.sources, ['certspotter', 'crtsh']);
    assert.equal(merged.complete, true);
    assert.equal(merged.url, 'https://crt.sh/?id=11', 'the crt.sh page of the twin');
    assert.equal(list.find((c) => c.key === other.key).complete, false);
    assert.deepEqual(uniqueCerts(null), []);
    assert.deepEqual(uniqueCerts([null, { key: 'x' }]), [], 'no name list, no certificate');
  });

  test('a crt.sh certificate with another validity, or a name its Cert Spotter look-alike lacks, stays its own', () => {
    const full = spotter(1, ['example.com', 'www.example.com']);
    const list = uniqueCerts([full, crtsh(21, 'bb01', ['example.com'], { from: -29 }), crtsh(22, 'bb02', ['example.com', 'mail.example.com'])]);
    assert.equal(list.length, 3);
  });

  test('a large scan folds each crt.sh certificate into its twin among several with the same validity, in linear time', () => {
    // 20,000 crt.sh rows, 500 Cert Spotter issuances; two issuances share each validity.
    const spotters = [];
    const rows = [];
    for (let i = 0; i < 250; i += 1) {
      spotters.push(spotter(2 * i + 1, [`a${i}.example.com`, `a${i}.example.net`], { from: -i }), spotter(2 * i + 2, [`b${i}.example.com`, `b${i}.example.net`], { from: -i }));
      rows.push(crtsh(10000 + i, `cc${i}`, [`b${i}.example.com`], { from: -i }));
    }
    for (let i = 0; i < 19750; i += 1) rows.push(crtsh(20000 + i, `dd${i}`, [`h${i}.example.com`], { from: -300 - i }));
    const started = performance.now();
    const list = uniqueCerts([...rows, ...spotters]);
    assert.ok(performance.now() - started < 2000 * PERF_FACTOR, 'no pairwise search');
    assert.equal(list.length, 500 + 19750);
    assert.deepEqual(list.find((c) => c.key === spotters[1].key).sources, ['certspotter', 'crtsh'], 'folded into the twin whose names it has');
    assert.deepEqual(list.find((c) => c.key === spotters[0].key).sources, ['certspotter']);
  });
});

describe('relatedDomains', () => {
  test('lists the other registrable domains of the scanned hosts\' certificates, with names, certificates and counts', () => {
    const certs = [
      spotter(1, ['example.com', 'www.example.com', 'example.net', 'shop.example.net'], { from: -20 }),
      spotter(2, ['api.example.com', 'api.example.net'], { from: -100, to: -10 }),
      crtsh(11, 'aa01', ['example.com', 'www.example.com'], { from: -20 }),
      // crt.sh lists the matching name and a common name under another domain
      crtsh(12, 'aa02', ['shop.example.com', '*.example.org'], { from: -5 }),
      // only the scanned domain: nothing related
      spotter(3, ['mail.example.com'])
    ];
    const out = relatedDomains(certs, { domains: ['example.com'], now: NOW });
    assert.deepEqual(out.related.map((d) => [d.domain, d.certs, d.current, d.sharedOnly, d.platform]), [
      ['example.net', 2, true, false, null],
      ['example.org', 1, true, false, null]
    ]);
    const net = out.related[0];
    assert.deepEqual(net.names, ['example.net', 'api.example.net', 'shop.example.net']);
    assert.deepEqual(net.certificates.map((c) => c.key), [certs[0].key, certs[1].key], 'newest first');
    assert.deepEqual(net.certificates[0].ownNames, ['example.com', 'www.example.com']);
    assert.deepEqual(net.certificates[0].sources, ['certspotter', 'crtsh']);
    assert.equal(net.certificates[0].url, 'https://crt.sh/?id=11');
    assert.equal(net.certificates[1].url, `https://crt.sh/?sha256=${certs[1].sha256}`, 'a Cert Spotter issuance: a crt.sh search by SHA-256');
    assert.equal(net.latest.getTime(), day(-20).getTime());
    const org = out.related[1];
    assert.deepEqual(org.names, ['*.example.org']);
    assert.equal(org.certificates[0].partial, true);
    assert.deepEqual({ certs: out.certs, withOthers: out.withOthers, partial: out.partial, shared: out.shared, more: out.more },
      { certs: 4, withOthers: 3, partial: 1, shared: 0, more: 0 });
  });

  test('a domain seen only in expired certificates is not current', () => {
    const out = relatedDomains([spotter(1, ['example.com', 'example.net'], { from: -400, to: -300 })], { domains: ['example.com'], now: NOW });
    assert.equal(out.related[0].current, false);
  });

  test('the scanned domains, their other hosts and a scope below the registrable domain are never related', () => {
    const certs = [
      spotter(1, ['shop.example.com', 'www.example.com', 'example.net']),
      spotter(2, ['example.org', 'example.net']) // no scanned host: not one of the scan's certificates
    ];
    const both = relatedDomains(certs, { domains: ['example.com', 'example.net'], now: NOW });
    assert.deepEqual(both.related.map((d) => d.domain), ['example.org'], 'example.net is scanned too; example.org shares its certificate');
    assert.deepEqual(both.related[0].certificates[0].ownNames, ['example.net']);
    assert.equal(both.certs, 2, 'the second names example.net, which is scanned');
    assert.equal(both.withOthers, 1);
    const scoped = relatedDomains(certs, { domains: ['shop.example.com'], now: NOW });
    assert.deepEqual(scoped.related.map((d) => d.domain), ['example.net'], 'www.example.com is the scope\'s own registrable domain');
    assert.equal(scoped.certs, 1);
    assert.deepEqual(relatedDomains(certs, { domains: [], now: NOW }).related, []);
  });

  test(`a certificate of more than ${SHARED_CERT_DOMAINS} registrable domains under other names is a shared one: its domains come last, flagged`, () => {
    const crowd = Array.from({ length: SHARED_CERT_DOMAINS + 1 }, (_, i) => `customer${i + 1}.example`);
    const certs = [
      spotter(1, ['www.example.com', ...crowd]),
      spotter(2, ['example.com', 'example.net'])
    ];
    const out = relatedDomains(certs, { domains: ['example.com'], now: NOW });
    assert.equal(out.shared, 1);
    assert.equal(out.related[0].domain, 'example.net');
    assert.equal(out.related[0].sharedOnly, false);
    const shared = out.related.filter((d) => d.sharedOnly);
    assert.equal(shared.length, SHARED_CERT_DOMAINS + 1);
    assert.equal(shared[0].certificates[0].shared, true);
    assert.equal(shared[0].certificates[0].domains, SHARED_CERT_DOMAINS + 2);
    // one more brand certificate lifts a domain out of the shared-only group
    const again = relatedDomains([...certs, spotter(3, ['api.example.com', 'customer5.example'])], { domains: ['example.com'], now: NOW });
    const c5 = again.related.find((d) => d.domain === 'customer5.example');
    assert.equal(c5.sharedOnly, false);
    assert.equal(c5.certs, 2);
  });

  test('a company\'s certificate for its brands under other endings is never a shared one, however many they are', () => {
    // example.com and 14 of its country-code twins: the multi-domain certificate the card is for
    const twins = ['de', 'fr', 'it', 'es', 'nl', 'be', 'at', 'ch', 'se', 'dk', 'pl', 'pt', 'co.uk', 'com.tr'].map((tld) => `example.${tld}`);
    assert.ok(twins.length + 1 > SHARED_CERT_DOMAINS, 'more registrable domains than a shared certificate has');
    const brand = spotter(1, ['example.com', 'www.example.com', ...twins.flatMap((d) => [d, `www.${d}`])]);
    const out = relatedDomains([brand], { domains: ['example.com'], now: NOW });
    assert.equal(out.shared, 0);
    assert.equal(out.related.length, twins.length);
    assert.deepEqual(out.related.filter((d) => d.sharedOnly), [], 'every twin is a brand domain the card lists');
    assert.deepEqual(out.related.map((d) => d.domain).sort(), [...twins].sort());
    const c = out.related.find((d) => d.domain === 'example.co.uk');
    assert.deepEqual([c.names, c.certificates[0].shared, c.certificates[0].domains], [['example.co.uk', 'www.example.co.uk'], false, twins.length + 1]);
    // the label of a scope under a multi-label suffix is its registrable domain's
    assert.equal(relatedDomains([brand], { domains: ['shop.example.com.tr'], now: NOW }).shared, 0);
    // half of the other domains under the scanned label is not most: a host's certificate that also names a few twins
    const crowd = Array.from({ length: 7 }, (_, i) => `customer${i + 1}.example`);
    const mixed = relatedDomains([spotter(2, ['example.com', ...twins.slice(0, 7), ...crowd])], { domains: ['example.com'], now: NOW });
    assert.equal(mixed.shared, 1);
    assert.equal(mixed.related.filter((d) => d.sharedOnly).length, 14);
    const most = relatedDomains([spotter(3, ['example.com', ...twins.slice(0, 8), ...crowd.slice(0, 6)])], { domains: ['example.com'], now: NOW });
    assert.equal(most.shared, 0, '8 of 14 under the scanned label');
  });

  test('names and certificates are capped per domain, with the rest counted', () => {
    const names = Array.from({ length: RELATED_NAME_CAP + 3 }, (_, i) => `h${String(i).padStart(2, '0')}.example.net`);
    const certs = Array.from({ length: RELATED_CERT_CAP + 2 }, (_, i) => spotter(i + 1, ['example.com', names[i % names.length]], { from: -i }));
    certs.push(spotter(99, ['example.com', ...names]));
    const [net] = relatedDomains(certs, { domains: ['example.com'], now: NOW }).related;
    assert.equal(net.certs, RELATED_CERT_CAP + 3);
    assert.equal(net.certificates.length, RELATED_CERT_CAP);
    assert.equal(net.names.length, RELATED_NAME_CAP);
    assert.equal(net.moreNames, 3);
  });

  test('a hosting or CDN platform\'s domain is named as one and listed after the brands', () => {
    const out = relatedDomains([
      spotter(1, ['www.example.com', 'shop.example.com.herokudns.com']),
      spotter(2, ['example.com', 'example.org'])
    ], { domains: ['example.com'], now: NOW });
    assert.deepEqual(out.related.map((d) => [d.domain, d.platform]), [['example.org', null], ['herokudns.com', 'Heroku']]);
  });
});
