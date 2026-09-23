import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeHostname, parseHostList, registrableDomain, isPublicSuffix,
  isSubdomainOf, stripWildcard, wildcardMatches, certCovers, sortHostnames,
  baseDomainsFromNames
} from '../../assets/js/lib/domain.js';

/* -------------------------------------------------------------------- */
/* normalizeHostname                                                    */
/* -------------------------------------------------------------------- */

test('normalizeHostname strips scheme, userinfo, port, path, query, trailing dot', () => {
  assert.equal(normalizeHostname('https://User:pw@Www.Example.COM:443/path?q=1#f'), 'www.example.com');
  assert.equal(normalizeHostname('example.com.'), 'example.com');
  assert.equal(normalizeHostname('//example.com/x'), 'example.com');
  assert.equal(normalizeHostname('  example.com  '), 'example.com');
});

test('normalizeHostname converts IDN to punycode', () => {
  assert.equal(normalizeHostname('https://Www.Örnek.com.tr:443/path?q'), 'www.xn--rnek-4qa.com.tr');
  assert.equal(normalizeHostname('münchen.de'), 'xn--mnchen-3ya.de');
  assert.equal(normalizeHostname('İstanbul.com.tr'), 'xn--istanbul-o0e.com.tr');
  assert.equal(normalizeHostname('xn--mnchen-3ya.de'), 'xn--mnchen-3ya.de');
});

test('normalizeHostname allows underscore labels (_dmarc, DKIM)', () => {
  assert.equal(normalizeHostname('_dmarc.example.com'), '_dmarc.example.com');
  assert.equal(normalizeHostname('selector._domainkey.example.com'), 'selector._domainkey.example.com');
});

test('normalizeHostname wildcard handling', () => {
  assert.equal(normalizeHostname('*.example.com'), null);
  assert.equal(normalizeHostname('*.example.com', { allowWildcard: true }), '*.example.com');
  assert.equal(normalizeHostname('*.Örnek.com', { allowWildcard: true }), '*.xn--rnek-4qa.com');
  assert.equal(normalizeHostname('a.*.example.com', { allowWildcard: true }), null); // wildcard not leftmost
  assert.equal(normalizeHostname('w*.example.com', { allowWildcard: true }), null); // partial-label
});

test('normalizeHostname rejects non-hostnames', () => {
  for (const bad of ['', '   ', '1.2.3.4', '[::1]', '::1', 'a..b.com', 'exa mple.com', 'ex!ample.com',
    'localhost', '-bad.com', 'bad-.com', 'a'.repeat(64) + '.com', 'x:99999a', 'http://', 'mailto:x@y']) {
    assert.equal(normalizeHostname(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
  assert.equal(normalizeHostname(42), null);
});

test('normalizeHostname allowSingleLabel extension', () => {
  assert.equal(normalizeHostname('localhost', { allowSingleLabel: true }), 'localhost');
});

test('normalizeHostname enforces total length <= 253', () => {
  const long = (`${'a'.repeat(63)}.`).repeat(4) + 'a'.repeat(10) + '.com'; // > 253
  assert.equal(normalizeHostname(long), null);
});

/* -------------------------------------------------------------------- */
/* parseHostList                                                        */
/* -------------------------------------------------------------------- */

test('parseHostList separates valid from invalid and dedupes', () => {
  const { valid, invalid } = parseHostList('example.com, www.example.com\nEXAMPLE.com\n1.2.3.4 # ip\nbad_ host');
  assert.deepEqual(valid, ['example.com', 'www.example.com']);
  assert.ok(invalid.includes('1.2.3.4'));
});

test('parseHostList accepts an array and wildcard option', () => {
  const { valid } = parseHostList(['*.a.com', 'b.com'], { allowWildcard: true });
  assert.deepEqual(valid, ['*.a.com', 'b.com']);
});

/* -------------------------------------------------------------------- */
/* registrableDomain                                                    */
/* -------------------------------------------------------------------- */

test('registrableDomain: simple and multi-label suffixes', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.c.example.com'), 'example.com');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('registrableDomain: all Turkish SLDs', () => {
  for (const sld of ['com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'k12.tr', 'bel.tr', 'pol.tr',
    'tsk.tr', 'gen.tr', 'web.tr', 'av.tr', 'dr.tr', 'bbs.tr', 'tv.tr', 'kep.tr', 'name.tr', 'info.tr', 'biz.tr']) {
    assert.equal(registrableDomain(`sub.example.${sld}`), `example.${sld}`, sld);
    assert.equal(registrableDomain(`example.${sld}`), `example.${sld}`, sld);
    assert.equal(registrableDomain(sld), null, `bare ${sld}`); // bare suffix
  }
});

test('registrableDomain: direct .tr (post-2022) falls back to last two labels', () => {
  assert.equal(registrableDomain('www.example.tr'), 'example.tr');
});

test('registrableDomain: international suffix families', () => {
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('shop.example.com.au'), 'example.com.au');
  assert.equal(registrableDomain('x.example.co.jp'), 'example.co.jp');
  assert.equal(registrableDomain('x.example.com.br'), 'example.com.br');
  assert.equal(registrableDomain('x.example.co.nz'), 'example.co.nz');
  assert.equal(registrableDomain('x.example.co.za'), 'example.co.za');
  assert.equal(registrableDomain('x.example.com.cn'), 'example.com.cn');
  assert.equal(registrableDomain('x.example.com.mx'), 'example.com.mx');
  assert.equal(registrableDomain('x.example.co.in'), 'example.co.in');
  assert.equal(registrableDomain('x.example.com.sg'), 'example.com.sg');
  assert.equal(registrableDomain('x.example.com.hk'), 'example.com.hk');
  assert.equal(registrableDomain('x.example.co.kr'), 'example.co.kr');
  assert.equal(registrableDomain('x.example.or.kr'), 'example.or.kr');
  assert.equal(registrableDomain('x.example.com.tw'), 'example.com.tw');
  assert.equal(registrableDomain('x.example.co.il'), 'example.co.il');
  assert.equal(registrableDomain('x.example.com.ar'), 'example.com.ar');
  assert.equal(registrableDomain('x.example.com.co'), 'example.com.co');
  assert.equal(registrableDomain('x.example.co.id'), 'example.co.id');
  assert.equal(registrableDomain('x.example.com.my'), 'example.com.my');
  assert.equal(registrableDomain('x.example.com.ua'), 'example.com.ua');
});

test('registrableDomain: private suffixes (github.io etc.)', () => {
  assert.equal(registrableDomain('user.github.io'), 'user.github.io');
  assert.equal(registrableDomain('page.user.github.io'), 'user.github.io');
  assert.equal(registrableDomain('app.herokuapp.com'), 'app.herokuapp.com');
});

test('registrableDomain: invalid input and IDN', () => {
  assert.equal(registrableDomain('localhost'), null);
  assert.equal(registrableDomain('1.2.3.4'), null);
  assert.equal(registrableDomain('*.example.com.tr'), 'example.com.tr');
  assert.equal(registrableDomain('www.Örnek.com.tr'), 'xn--rnek-4qa.com.tr');
  assert.equal(registrableDomain(''), null);
});

test('isPublicSuffix', () => {
  assert.equal(isPublicSuffix('com'), true);
  assert.equal(isPublicSuffix('com.tr'), true);
  assert.equal(isPublicSuffix('co.uk'), true);
  assert.equal(isPublicSuffix('github.io'), true);
  assert.equal(isPublicSuffix('github.io', { includePrivate: false }), false);
  assert.equal(isPublicSuffix('example.com'), false);
});

/* -------------------------------------------------------------------- */
/* isSubdomainOf / stripWildcard                                        */
/* -------------------------------------------------------------------- */

test('isSubdomainOf includes equality and respects label boundary', () => {
  assert.equal(isSubdomainOf('a.example.com', 'example.com'), true);
  assert.equal(isSubdomainOf('example.com', 'example.com'), true);
  assert.equal(isSubdomainOf('notexample.com', 'example.com'), false);
  assert.equal(isSubdomainOf('x.notexample.com', 'example.com'), false);
});

test('stripWildcard', () => {
  assert.deepEqual(stripWildcard('*.example.com'), { base: 'example.com', wildcard: true });
  assert.deepEqual(stripWildcard('example.com'), { base: 'example.com', wildcard: false });
  assert.deepEqual(stripWildcard('*'), { base: '', wildcard: true });
});

/* -------------------------------------------------------------------- */
/* wildcardMatches (RFC 6125 §6.4.3)                                    */
/* -------------------------------------------------------------------- */

test('wildcardMatches: one label only, leftmost only', () => {
  assert.equal(wildcardMatches('*.a.com', 'x.a.com'), true);
  assert.equal(wildcardMatches('*.a.com', 'a.com'), false);
  assert.equal(wildcardMatches('*.a.com', 'x.y.a.com'), false);
  assert.equal(wildcardMatches('*.a.com', 'X.A.COM'), true);
});

test('wildcardMatches: rejects partial-label and misplaced wildcards', () => {
  assert.equal(wildcardMatches('w*.a.com', 'www.a.com'), false);
  assert.equal(wildcardMatches('*w.a.com', 'ww.a.com'), false);
  assert.equal(wildcardMatches('a.*.com', 'a.b.com'), false);
});

test('wildcardMatches: never above an ICANN public suffix, but private is ok', () => {
  assert.equal(wildcardMatches('*.com', 'a.com'), false);
  assert.equal(wildcardMatches('*.com.tr', 'a.com.tr'), false);
  assert.equal(wildcardMatches('*.co.uk', 'a.co.uk'), false);
  assert.equal(wildcardMatches('*.github.io', 'user.github.io'), true);
});

test('wildcardMatches: non-wildcard is exact match', () => {
  assert.equal(wildcardMatches('a.com', 'a.com'), true);
  assert.equal(wildcardMatches('a.com', 'b.com'), false);
});

/* -------------------------------------------------------------------- */
/* certCovers                                                           */
/* -------------------------------------------------------------------- */

test('certCovers prefers exact over wildcard match', () => {
  const names = ['*.example.com', 'www.example.com', 'example.com'];
  assert.deepEqual(certCovers(names, 'www.example.com'), { covered: true, by: 'www.example.com' });
  assert.deepEqual(certCovers(names, 'api.example.com'), { covered: true, by: '*.example.com' });
  assert.deepEqual(certCovers(names, 'a.b.example.com'), { covered: false, by: null });
  assert.deepEqual(certCovers(names, 'example.com'), { covered: true, by: 'example.com' });
  assert.deepEqual(certCovers([], 'x.com'), { covered: false, by: null });
});

/* -------------------------------------------------------------------- */
/* sortHostnames                                                        */
/* -------------------------------------------------------------------- */

test('sortHostnames groups siblings by reversed labels, apex first', () => {
  const input = ['www.b.com', 'b.com', 'api.a.com', 'a.com', '*.a.com', '_dmarc.a.com', 'x.api.a.com'];
  const out = sortHostnames(input);
  assert.ok(out.indexOf('a.com') < out.indexOf('api.a.com'));
  assert.ok(out.indexOf('api.a.com') < out.indexOf('x.api.a.com'));
  assert.ok(out.indexOf('a.com') < out.indexOf('b.com'));
  // all a.com names precede b.com names
  assert.ok(out.slice(0, out.indexOf('b.com')).every((n) => n.endsWith('a.com')));
});

test('sortHostnames orders numeric labels naturally', () => {
  const out = sortHostnames(['web10.a.com', 'web2.a.com', 'web1.a.com']);
  assert.deepEqual(out, ['web1.a.com', 'web2.a.com', 'web10.a.com']);
});

test('sortHostnames returns a new array and tolerates junk', () => {
  const input = ['b.com', 'a.com'];
  const out = sortHostnames(input);
  assert.notEqual(out, input);
  assert.deepEqual(sortHostnames([]), []);
  assert.deepEqual(sortHostnames(null), []);
});

/* -------------------------------------------------------------------- */
/* baseDomainsFromNames                                                 */
/* -------------------------------------------------------------------- */

test('baseDomainsFromNames returns unique registrable domains, wildcards stripped', () => {
  const out = baseDomainsFromNames(['*.cdn.example.com.tr', 'www.example.com.tr', 'other.co.uk', 'bad host', '1.2.3.4']);
  assert.deepEqual(out, ['example.com.tr', 'other.co.uk']);
});
