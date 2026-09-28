/**
 * lib/summary.js — "Copy summary" (Jira / Slack) per view: the facts each view passes, the line
 * budget (5–12 lines; one line for DNS Lookup and IP Intel), the permalink and UTC timestamp
 * footer, Markdown escaping of untrusted values, plain text, permalink params (no inventory, no
 * zone contents) and complete EN + TR texts. Pure Node, no network; documentation data only.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const imp = (rel) => import(pathToFileURL(join(ROOT, rel)).href);

let S;
let i18n;
const NOW = new Date('2026-09-27T14:03:30Z');
const URL_BASE = 'https://example.github.io/domainscope/';
// Characters built from code points: a literal would be invisible in review.
const RLO = String.fromCharCode(0x202e);
const LS = String.fromCharCode(0x2028);
const NUL = String.fromCharCode(0);

before(async () => {
  i18n = await imp('assets/js/i18n.js');
  S = await imp('assets/js/lib/summary.js');
  const { HEALTH_I18N } = await imp('assets/js/lib/health.js');
  // The Verify headline keys a scan summary quotes (registered by the panel, as in the app).
  await imp('assets/js/ui/verify-panel.js');
  for (const lang of ['en', 'tr']) {
    i18n.registerStrings(lang, S.SUMMARY_I18N[lang]);
    i18n.registerStrings(lang, HEALTH_I18N[lang]);
  }
  i18n.setLang('en');
});

after(() => i18n.setLang('en'));

/** Options of one build: the real translator in `lang`, a fixed clock. */
function opts(lang = 'en', url = `${URL_BASE}#/x`) {
  i18n.setLang(lang);
  return { t: i18n.t, lang, url, now: NOW };
}
const md = (doc) => S.renderMarkdown(doc);
const txt = (doc) => S.renderPlainText(doc);
const lines = (text) => text.replace(/\n$/, '').split('\n');

/**
 * Every summary: budget (lines with text), footer (in Markdown its own paragraph, after an empty
 * line; plain text has none), no untranslated key, no unsafe character.
 */
function assertShape(doc, { min = 5, max = 12, inline = false } = {}) {
  for (const [format, out] of [['markdown', md(doc)], ['text', txt(doc)]]) {
    const all = lines(out);
    const ls = all.filter(Boolean);
    if (format === 'markdown') assert.equal(all[all.length - 2], '', `an empty line before the footer:\n${out}`);
    assert.equal(all.length - ls.length, format === 'markdown' ? 1 : 0, `no other empty line:\n${out}`);
    if (inline) assert.equal(ls.length, 2, `one line + footer:\n${out}`);
    else assert.ok(ls.length >= min && ls.length <= max, `${ls.length} lines (${min}–${max}):\n${out}`);
    assert.ok(out.endsWith('\n'), 'trailing newline');
    const foot = ls[ls.length - 1];
    assert.ok(foot.startsWith('DomainScope · '), `footer: ${foot}`);
    assert.ok(/\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/.test(foot), `UTC timestamp: ${foot}`);
    assert.doesNotMatch(out, /\bsum\.[a-z]|\bhealth\.[a-z-]+\.title|\bvfy\.head\./, `untranslated key:\n${out}`);
    assert.doesNotMatch(out, /[\u0000-\u0009\u000b-\u001f\u202a-\u202e\u2066-\u2069\u2028\u2029]/, 'no control / bidi character');
  }
}

/* ------------------------------------------------------------------------ */

describe('text helpers', () => {
  test('cleanText drops control, bidi and separator characters and collapses spaces', () => {
    assert.equal(S.cleanText(`a${NUL}b${RLO}c${LS}d\n\te  f `), 'a b c d e f');
    assert.equal(S.cleanText(null), '');
  });

  test('mdEscape escapes Markdown syntax but keeps intraword underscores', () => {
    assert.equal(S.mdEscape('*bold* [x](y) <!channel> `c` ~s~ a|b \\'), '\\*bold\\* \\[x\\](y) \\<!channel\\> \\`c\\` \\~s\\~ a\\|b \\\\');
    assert.equal(S.mdEscape('No _dmarc record; key_name ok'), 'No \\_dmarc record; key_name ok');
    assert.equal(S.mdEscape('_smtp._tls'), '\\_smtp.\\_tls');
  });

  test('mdCode: one code span, backticks neutralised, long values cut', () => {
    assert.equal(S.mdCode('a`b'), '`a\'b`');
    const long = S.mdCode('x'.repeat(200));
    assert.equal(long.length, S.SUMMARY_MAX_VALUE + 2);
    assert.ok(long.endsWith('…`'));
  });

  test('utcStamp is language-neutral UTC', () => {
    assert.equal(S.utcStamp(NOW), '2026-09-27 14:03 UTC');
    assert.equal(S.utcStamp('2026-01-02T03:04:59+03:00'), '2026-01-02 00:04 UTC');
    assert.equal(S.utcStamp('garbage'), '');
  });
});

describe('permalinkParams', () => {
  test('keeps only the view\'s own shareable keys, never an empty value', () => {
    assert.deepEqual(S.permalinkParams('health', { domain: 'example.com', selectors: '', inventory: 'web01' }), { domain: 'example.com' });
    assert.deepEqual(S.permalinkParams('global', { name: 'www.example.com', type: 'A', geo: null, x: '1' }), { name: 'www.example.com', type: 'A' });
    assert.deepEqual(S.permalinkParams('subdomains', { domain: ['example.com', 'example.net'], run: '1' }), { domain: 'example.com,example.net', run: '1' });
    assert.deepEqual(S.permalinkParams('nope', { a: 'b' }), {});
  });

  test('Zone File and Certificate carry nothing: the file never goes into a URL', () => {
    assert.deepEqual(S.permalinkParams('zone', { tab: 'origins', zone: 'example.com' }), {});
    assert.deepEqual(S.permalinkParams('cert', { name: 'example.com' }), {});
  });

  test('IP Intel drops private and inventory addresses, keeps host names', () => {
    const p = S.permalinkParams('ip', { ips: '192.0.2.10,10.0.0.5,example.com,2001:DB8::1,203.0.113.7' }, { exclude: ['192.0.2.10', '2001:db8::1'] });
    assert.deepEqual(p, { ips: 'example.com,203.0.113.7' });
    assert.deepEqual(S.permalinkParams('ip', { ips: '10.0.0.5' }), {}, 'nothing left: no ips key');
  });

  test('Retire an IP drops private addresses and networks and inventory addresses, keeps the domains', () => {
    const p = S.permalinkParams('retire', { ips: '192.0.2.10,10.0.0.0/28,198.51.100.0/28,203.0.113.7', domains: 'example.com,example.net', run: '0' },
      { exclude: ['192.0.2.10'] });
    assert.deepEqual(p, { ips: '198.51.100.0/28,203.0.113.7', domains: 'example.com,example.net' });
    assert.deepEqual(S.permalinkParams('retire', { ips: '10.0.0.5', domains: 'example.com' }), { domains: 'example.com' });
  });
});

describe('health', () => {
  const report = (checks, summary) => ({ domain: 'example.com', checkedAt: new Date('2026-09-27T09:00:00Z'), summary, checks });
  const check = (id, severity, params = {}) => ({ id, severity, titleKey: `health.${id}.title`, params });

  test('score + verdict, counts, errors before warnings, footer with the permalink', () => {
    const r = report([check('spf.too-many-lookups', 'warn', { count: 12, limit: 10 }), check('dmarc.missing', 'error'), check('ipv6.missing', 'info'), check('ns.ok', 'ok')],
      { ok: 1, info: 1, warn: 1, error: 1 });
    const doc = S.healthSummary({ report: r }, opts('en', `${URL_BASE}#/health?domain=example.com`));
    const out = md(doc);
    assertShape(doc);
    const ls = lines(out);
    assert.equal(ls[0], '**Domain Health · `example.com`**');
    assert.equal(ls[1], '- Problems found · score 74/100');
    assert.equal(ls[2], '- 1 error · 1 warning · 1 note · 1 passed');
    assert.match(ls[3], /^- \*\*Error:\*\* /, 'error first');
    assert.match(ls[4], /^- \*\*Warning:\*\* /);
    assert.deepEqual(ls.slice(5), ['', `DomainScope · checked 2026-09-27 09:00 UTC · ${URL_BASE}#/health?domain=example.com`], 'the footer after an empty line');
    assert.equal(lines(txt(doc))[3].startsWith('- Error: '), true, 'plain text has no **');
    assert.equal(lines(txt(doc))[0], 'Domain Health · example.com', 'plain text has no code spans');
  });

  test('a name a check quotes is a code span, its numbers stay text', () => {
    const r = report([check('dmarc.inherited', 'warn', { org: '_dmarc.example.com' }), check('rdap.expiring-soon', 'error', { days: 12 })],
      { ok: 0, info: 0, warn: 1, error: 1 });
    const out = md(S.healthSummary({ report: r }, opts()));
    assert.ok(out.includes('- **Error:** Domain expires in 12 days'), out);
    assert.ok(out.includes('- **Warning:** DMARC inherited from `_dmarc.example.com`'), out);
    assert.ok(txt(S.healthSummary({ report: r }, opts())).includes('- Warning: DMARC inherited from _dmarc.example.com'));
  });

  test('at most five problems, then "+N more"; a clean report says so', () => {
    const many = Array.from({ length: 8 }, (_, i) => check('dmarc.missing', i < 3 ? 'error' : 'warn'));
    const doc = S.healthSummary({ report: report(many, { ok: 0, info: 0, warn: 5, error: 3 }) }, opts());
    assertShape(doc);
    assert.equal(lines(md(doc)).filter((l) => /^- \*\*(Error|Warning):/.test(l)).length, 5);
    assert.ok(md(doc).includes('- +3 more warnings and errors'));
    const clean = S.healthSummary({ report: report([check('ns.ok', 'ok')], { ok: 12, info: 0, warn: 0, error: 0 }) }, opts());
    assertShape(clean);
    assert.deepEqual(lines(md(clean)).slice(1, 4), ['- Healthy · score 100/100', '- 12 passed', '- No errors or warnings']);
  });

  test('Turkish', () => {
    const doc = S.healthSummary({ report: report([check('dmarc.missing', 'error')], { ok: 3, info: 0, warn: 0, error: 1 }) }, opts('tr'));
    const out = md(doc);
    assertShape(doc);
    assert.match(out, /^\*\*Alan Adı Sağlığı · `example\.com`\*\*/m);
    assert.ok(out.includes('- Sorun bulundu · puan 80/100'));
    assert.ok(out.includes('- 1 hata · 3 başarılı'));
    assert.ok(out.includes('- **Hata:** '));
    assert.ok(out.includes('kontrol edildi: 2026-09-27 09:00 UTC'));
  });

  test('healthScore / trafficLight (shared with the view)', () => {
    assert.equal(S.healthScore({ ok: 10 }), 100);
    assert.equal(S.healthScore({ error: 1, warn: 2 }), 68);
    assert.equal(S.healthScore({ error: 9 }), 0);
    assert.equal(S.healthScore(null), 100);
    assert.deepEqual([S.trafficLight({ error: 1, warn: 3 }), S.trafficLight({ warn: 1 }), S.trafficLight({ ok: 4, info: 2 })], ['error', 'warn', 'ok']);
  });
});

describe('global', () => {
  const base = { name: 'www.example.com', type: 'A', total: 43, answered: 41, failed: 2, addresses: 12 };

  test('by design: operators in the verdict, the answer count, the addresses', () => {
    const verdict = { state: 'by-design', groups: [{ key: 'a' }, { key: 'b' }, { key: 'c' }], operators: [{ name: 'Cloudflare' }, { name: 'Fastly' }], findings: [] };
    const doc = S.globalSummary({ ...base, verdict }, opts('en', `${URL_BASE}#/global?name=www.example.com&type=A`));
    const ls = lines(md(doc));
    assertShape(doc);
    assert.equal(ls[0], '**Global DNS · `www.example.com` A**');
    assert.equal(ls[1], '- Differs by design: CDN / GeoDNS edges (Cloudflare, Fastly)');
    assert.equal(ls[2], '- 3 different answers from 41 of 43 sources · 2 sources failed');
    assert.equal(ls[3], '- 12 addresses seen worldwide');
    assert.equal(lines(md(doc)).pop(), `DomainScope · checked 2026-09-27 14:03 UTC · ${URL_BASE}#/global?name=www.example.com&type=A`, 'no check time: the copy time');
  });

  test('the time the check ended; a name with underscores stays one code span', () => {
    const verdict = { state: 'agree', groups: [{ key: 'a' }], operators: [], findings: [] };
    const doc = S.globalSummary({ ...base, name: '_dmarc.example.com', type: 'TXT', verdict, at: new Date('2026-09-27T11:15:00Z') }, opts());
    const ls = lines(md(doc));
    assert.equal(ls[0], '**Global DNS · `_dmarc.example.com` TXT**');
    assert.ok(ls[ls.length - 1].startsWith('DomainScope · checked 2026-09-27 11:15 UTC · '), ls[ls.length - 1]);
  });

  test('differ: the findings (three at most, then "+N more")', () => {
    const findings = [
      { code: 'nxdomain', members: ['a', 'b'] }, { code: 'rcode', rcode: 'SERVFAIL', members: ['c'] },
      { code: 'cname', members: ['d', 'e', 'f'] }, { code: 'direct', members: ['g'] }
    ];
    const verdict = { state: 'differ', groups: [{ key: 'a' }, { key: 'b', rewritten: true }], operators: [{ name: 'Cloudflare' }], findings };
    const doc = S.globalSummary({ ...base, failed: 0, verdict }, opts());
    const out = md(doc);
    assertShape(doc);
    for (const s of ['- Answers differ', '- 1 answer from 41 of 43 sources', '- Operated by Cloudflare',
      '- NXDOMAIN from 2 sources', '- SERVFAIL from 1 source', '- The CNAME differs (3 sources)', '- +1 more finding']) {
      assert.ok(out.includes(s), `${s}\n${out}`);
    }
  });

  test('nothing answered, stopped early, Turkish', () => {
    const none = S.globalSummary({ ...base, answered: 0, failed: 43, addresses: 0, verdict: null }, opts());
    assertShape(none);
    assert.deepEqual(lines(md(none)).slice(1, 4), ['- No answers', '- 43 sources failed', '- No addresses'], 'no "0 answers from 0 sources" line');
    assert.deepEqual(lines(md(S.globalSummary({ ...base, answered: 0, failed: 43, addresses: 0, verdict: null }, opts('tr')))).slice(1, 4),
      ['- Yanıt alınamadı', '- 43 kaynak başarısız', '- Adres yok']);
    const stoppedNone = S.globalSummary({ ...base, answered: 0, failed: 0, cancelled: true, addresses: 0, verdict: null }, opts());
    assertShape(stoppedNone, { min: 4 });
    assert.deepEqual(lines(md(stoppedNone)).slice(1, 3), ['- Stopped before any source answered', '- No addresses']);
    const stopped = S.globalSummary({ ...base, cancelled: true, verdict: { state: 'agree', groups: [{ key: 'a' }], operators: [], findings: [] } }, opts());
    assert.ok(md(stopped).includes('- All answers agree (stopped early: not every source answered)'));
    const tr = S.globalSummary({ ...base, verdict: { state: 'geo', groups: [{ key: 'a' }, { key: 'b' }], operators: [], findings: [] } }, opts('tr'));
    assertShape(tr);
    assert.ok(md(tr).includes('- 43 kaynağın 41 tanesinden 2 farklı yanıt · 2 kaynak başarısız'));
    assert.ok(md(tr).includes('- Dünya genelinde 12 adres görüldü'));
  });

  test('all answers agree: one answer, in both languages (never "1 different answer")', () => {
    const verdict = { state: 'agree', groups: [{ key: 'a' }], operators: [], findings: [] };
    const en = lines(md(S.globalSummary({ ...base, failed: 0, verdict }, opts())));
    assert.deepEqual(en.slice(1, 3), ['- All answers agree', '- 1 answer from 41 of 43 sources']);
    const tr = lines(md(S.globalSummary({ ...base, failed: 0, verdict }, opts('tr'))));
    assert.deepEqual(tr.slice(1, 3), ['- Tüm yanıtlar aynı', '- 43 kaynağın 41 tanesi aynı yanıtı verdi']);
    assert.doesNotMatch(tr.join(' '), /farklı yanıt/);
  });
});

describe('subdomains', () => {
  const counts = { found: 42, resolving: 38, cloudflare: 12, cdn: 5, direct: 18, private: 2, unresolved: 7, dangling: 2, wildcard: 3 };
  const facts = {
    domains: ['example.com'], status: 'done', counts, proxied: 14, withCandidates: 4, networks: 2,
    dangling: ['old.example.com', 'shop.example.com'], failedSources: 1, at: new Date('2026-09-27T12:00:00Z')
  };

  test('classes, proxied with origin candidates, dangling names as code, wildcard, failed sources', () => {
    const doc = S.subdomainsSummary(facts, opts('en', `${URL_BASE}#/subdomains?domain=example.com&run=1`));
    const ls = lines(md(doc));
    assertShape(doc);
    assert.deepEqual(ls.slice(0, 7), [
      '**Subdomains · `example.com`**',
      '- 42 subdomains found · 38 resolve',
      '- 12 Cloudflare · 5 other CDN / platform · 18 direct IPs (2 of them private) · 7 not resolving',
      '- 14 hosts hide their origin behind a proxy · origin candidates for 4 of them · 2 origin networks to sweep',
      '- 2 dangling CNAMEs (possible takeover): `old.example.com`, `shop.example.com`',
      '- 3 wildcard matches left out',
      '- 1 passive source failed: the list may be incomplete'
    ]);
    assert.equal(ls[8], `DomainScope · scanned 2026-09-27 12:00 UTC · ${URL_BASE}#/subdomains?domain=example.com&run=1`);
  });

  test('nothing proxied, nothing dangling, several domains; nothing found; cancelled', () => {
    const quiet = S.subdomainsSummary({ ...facts, domains: ['example.com', 'example.net', 'example.org', 'example.edu'], proxied: 0, dangling: [], failedSources: 0,
      counts: { ...counts, cloudflare: 0, wildcard: 0, private: 0 } }, opts());
    assertShape(quiet);
    const out = md(quiet);
    assert.ok(out.startsWith('**Subdomains · `example.com`, `example.net`, `example.org` +1 more**'), out);
    assert.equal(lines(txt(quiet))[0], 'Subdomains · example.com, example.net, example.org +1 more');
    assert.ok(out.includes('- No host hides its origin behind a proxy') && out.includes('- No dangling CNAMEs'));
    assert.doesNotMatch(out, /Cloudflare/);
    const none = S.subdomainsSummary({ domains: ['example.com'], status: 'done', counts: { found: 0 } }, opts());
    assertShape(none, { min: 3 });
    assert.ok(md(none).includes('- No subdomains found'));
    const cancelled = S.subdomainsSummary({ ...facts, status: 'cancelled' }, opts());
    assert.ok(md(cancelled).includes('- 42 subdomains found before the scan was cancelled · 38 resolve'));
  });

  test('a cancelled scan never says something is absent: no "no proxied host", no "no dangling CNAME"; Turkish', () => {
    const quiet = { ...facts, status: 'cancelled', proxied: 0, withCandidates: 0, networks: 0, dangling: [], failedSources: 0, counts: { ...counts, wildcard: 0 } };
    for (const lang of ['en', 'tr']) {
      const doc = S.subdomainsSummary(quiet, opts(lang));
      assertShape(doc, { min: 4 });
      assert.doesNotMatch(md(doc), /No host hides|No dangling|gizleyen host yok|Sahipsiz CNAME yok/, md(doc));
    }
    assert.deepEqual(lines(md(S.subdomainsSummary(quiet, opts('tr')))).slice(1, 3), [
      '- Tarama iptal edilmeden önce 42 subdomain bulundu · 38 tanesi çözümleniyor',
      '- 12 Cloudflare · 5 diğer CDN / platform · 18 doğrudan IP (2 tanesi özel IP) · 7 çözümlenmiyor'
    ]);
    // What it did find it still says.
    const found = md(S.subdomainsSummary({ ...quiet, proxied: 3, dangling: ['old.example.com'] }, opts()));
    assert.ok(lines(found).includes('- 3 hosts hide their origin behind a proxy') && found.includes('- 1 dangling CNAME (possible takeover): `old.example.com`'), found);
  });

  test('a cancelled scan (views/subdomains facts): the proxied hosts found so far, never "no host hides its origin", no candidates', async () => {
    const { subdomainsSummaryFacts } = await imp('assets/js/views/subdomains.js');
    const cf = { kind: 'cloudflare', provider: { name: 'Cloudflare' }, hidesOrigin: true, dangling: false };
    const direct = { kind: 'direct', provider: null, hidesOrigin: false, dangling: false };
    const host = (name, ip, classification) => ({ name, wildcardSuspect: false, resolution: { status: 'NOERROR', ipv4: [ip], ipv6: [], cnames: [] }, classification, servers: [] });
    const apex = host('example.net', '203.0.113.10', direct);
    const www = { ...host('www.example.net', '104.16.5.5', cf), _partial: true };
    // Cancelled while resolving: no result (no ORIGIN analysis), one full record and one streamed partial.
    const run = {
      status: 'cancelled', config: { domains: ['example.net'] }, result: null, hosts: [apex], found: new Map([[www.name, www]]),
      sourceResults: [], finishedAt: new Date('2026-09-27T12:00:00Z')
    };
    const facts = subdomainsSummaryFacts(run);
    assert.deepEqual([facts.counts.found, facts.counts.cloudflare, facts.proxied, facts.withCandidates, facts.networks], [2, 1, 1, 0, 0]);
    const out = md(S.subdomainsSummary(facts, opts()));
    assert.deepEqual(lines(out).slice(1, 5), [
      '- 2 subdomains found before the scan was cancelled · 2 resolve',
      '- 1 Cloudflare · 1 direct IP',
      '- 1 host hides its origin behind a proxy',
      ''
    ], out);
    assert.doesNotMatch(out, /No host hides|No dangling|candidate|to sweep/);
    // A finished scan counts them from its ORIGIN analysis; a running one has nothing to copy.
    const done = { ...run, status: 'done', result: { hosts: [apex, { ...www, _partial: false }], originHints: [], originNetworks: [] } };
    assert.deepEqual([subdomainsSummaryFacts(done).proxied, subdomainsSummaryFacts(done).networks], [1, 0]);
    assert.equal(subdomainsSummaryFacts({ ...run, status: 'running' }), null);
    assert.equal(subdomainsSummaryFacts({ ...run, status: 'error' }), null);
  });

  test('a hostile name stays one inert code span (no mention, link, bidi or new line)', () => {
    const evil = `x${RLO}y<!channel>[a](https://example.org)\`@here${LS}- **fake**.example.com`;
    const doc = S.subdomainsSummary({ ...facts, dangling: [evil] }, opts());
    const out = md(doc);
    assertShape(doc);
    const line = lines(out).find((l) => l.includes('dangling'));
    assert.equal(line, "- 1 dangling CNAME (possible takeover): `x y<!channel>[a](https://example.org)'@here - **fake**.example.com`");
  });

  test('Turkish', () => {
    const doc = S.subdomainsSummary(facts, opts('tr'));
    const out = md(doc);
    assertShape(doc);
    assert.ok(out.startsWith('**Subdomain Tarama · `example.com`**'), out);
    for (const s of ['- 42 subdomain bulundu · 38 tanesi çözümleniyor', '12 Cloudflare · 5 diğer CDN / platform · 18 doğrudan IP (2 tanesi özel IP) · 7 çözümlenmiyor',
      '14 host asıl sunucusunu bir proxy arkasında gizliyor · 4 tanesi için asıl sunucu adayı · taranacak 2 asıl sunucu ağı', '2 sahipsiz CNAME (olası ele geçirme)', 'tarandı: 2026-09-27 12:00 UTC']) {
      assert.ok(out.includes(s), `${s}\n${out}`);
    }
  });
});

describe('scan (SSL Targets)', () => {
  const cert = { name: '*.example.com', issuer: 'Example CA (R1)', notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2026-12-01T00:00:00Z') };
  const facts = {
    domains: ['example.com'], cert, hosts: 42, covered: 30, inventory: 300,
    needsCert: ['web01', 'web02', 'web03', 'lb-1', 'lb-2', 'mail01'], hiddenOrigin: 12, networks: 2,
    verify: { key: 'vfy.head.some', params: { live: 3, total: 6, old: 3 } }, dangling: [], at: new Date('2026-09-27T13:00:00Z')
  };

  test('certificate, hosts / covered, the servers that need it by name, CDN, Verify', () => {
    const doc = S.scanSummary(facts, opts('en', `${URL_BASE}#/scan?domain=example.com&run=1`));
    const ls = lines(md(doc));
    assertShape(doc);
    assert.deepEqual(ls.slice(0, 6), [
      '**SSL Targets · `example.com`**',
      '- Certificate `*.example.com` · issued by `Example CA (R1)` · valid until 2026-12-01 (64 days left)',
      '- 42 hosts found · 30 covered by the certificate',
      '- 6 servers in your list need the certificate: `web01`, `web02`, `web03`, `lb-1`, `lb-2` +1 more',
      '- 12 hosts behind a CDN (origin hidden) · 2 origin networks to sweep',
      '- Verify: New certificate live on 3 of 6 servers · still old: 3.'
    ]);
    assert.ok(ls[7].includes('scanned 2026-09-27 13:00 UTC'));
    assert.equal(lines(txt(doc))[3], '- 6 servers in your list need the certificate: web01, web02, web03, lb-1, lb-2 +1 more');
  });

  test('no server list, no Verify run yet, no certificate', () => {
    const noInv = S.scanSummary({ ...facts, inventory: 0, needsCert: [], verify: null, hiddenOrigin: 0 }, opts());
    assertShape(noInv);
    assert.ok(md(noInv).includes('- No server list loaded: which servers need the certificate is not known'));
    assert.ok(md(noInv).includes('- Verify: not checked from the internet yet'));
    const none = S.scanSummary({ ...facts, needsCert: [] }, opts());
    assert.ok(md(none).includes('- No server in your list needs the certificate'));
    const noCert = S.scanSummary({ ...facts, cert: null, matched: 4, domains: ['example.com', 'example.net'], hiddenOrigin: 0, dangling: ['old.example.com'] }, opts());
    assertShape(noCert);
    const out = md(noCert);
    assert.ok(out.startsWith('**SSL Targets · `example.com`, `example.net`**'), out);
    assert.ok(out.includes('- No certificate loaded: names and servers only') && out.includes('- 4 servers in your list serve these names'));
    assert.doesNotMatch(out, /covered|Verify/);
    assert.ok(out.includes('- 1 dangling CNAME (possible takeover): `old.example.com`'));
  });

  test('several certificate sets: line 1 names each set, its key types and the servers that need it', () => {
    const sets = [
      { id: 'A', name: 'example.com', names: 2, keyTypes: ['RSA 2048', 'ECDSA P-256'], servers: 2 },
      { id: 'B', name: 'shop.example.com', names: 1, keyTypes: ['RSA 2048'], servers: 1 }
    ];
    const doc = S.scanSummary({ ...facts, sets }, opts());
    assertShape(doc);
    assert.equal(lines(md(doc))[1],
      '- 2 certificate sets: A: `example.com` +1 (RSA 2048, ECDSA P-256) — 2 servers · B: `shop.example.com` (RSA 2048) — 1 server');
    assert.equal(lines(txt(doc))[1], '- 2 certificate sets: A: example.com +1 (RSA 2048, ECDSA P-256) — 2 servers · B: shop.example.com (RSA 2048) — 1 server');
    const noInv = S.scanSummary({ ...facts, sets, inventory: 0 }, opts());
    assert.equal(lines(md(noInv))[1], '- 2 certificate sets: A: `example.com` +1 (RSA 2048, ECDSA P-256) · B: `shop.example.com` (RSA 2048)');
    assert.equal(lines(md(S.scanSummary({ ...facts, sets }, opts('tr'))))[1],
      '- 2 sertifika seti: A: `example.com` +1 (RSA 2048, ECDSA P-256) — 2 sunucu · B: `shop.example.com` (RSA 2048) — 1 sunucu');
  });

  test('the title names the scanned domains, not the certificate\'s (line 1 names that)', () => {
    const other = S.scanSummary({ ...facts, domains: ['example.net'], cert: { ...cert, name: 'example.com' } }, opts());
    const ls = lines(md(other));
    assert.equal(ls[0], '**SSL Targets · `example.net`**');
    assert.match(ls[1], /^- Certificate `example\.com` · issued by /);
    const many = S.scanSummary({ ...facts, domains: ['example.com', 'example.net', 'example.org', 'example.edu'] }, opts());
    assert.equal(lines(md(many))[0], '**SSL Targets · `example.com`, `example.net`, `example.org` +1 more**');
    // No domain known (never from the view, which names the certificate's base domains): the certificate.
    assert.equal(lines(md(S.scanSummary({ ...facts, domains: [] }, opts())))[0], '**SSL Targets · `*.example.com`**');
  });

  test('passive sources that failed: right under the host count, before "no server needs it"; Turkish', () => {
    const doc = S.scanSummary({ ...facts, failedSources: 1, needsCert: [] }, opts());
    const ls = lines(md(doc));
    assertShape(doc);
    assert.deepEqual(ls.slice(2, 5), [
      '- 42 hosts found · 30 covered by the certificate',
      '- 1 passive source failed: the list may be incomplete',
      '- No server in your list needs the certificate'
    ]);
    assert.equal(lines(md(S.scanSummary({ ...facts, failedSources: 2 }, opts())))[3], '- 2 passive sources failed: the list may be incomplete');
    const tr = lines(md(S.scanSummary({ ...facts, failedSources: 2 }, opts('tr'))));
    assert.deepEqual(tr.slice(2, 4), ['- 42 host bulundu · 30 tanesi sertifikanın kapsamında', '- 2 pasif kaynak başarısız: liste eksik olabilir']);
    const noCert = md(S.scanSummary({ ...facts, cert: null, matched: 4, failedSources: 1 }, opts()));
    assert.ok(noCert.includes('- 42 hosts found\n- 1 passive source failed: the list may be incomplete\n'), noCert);
    assert.doesNotMatch(md(S.scanSummary(facts, opts())), /passive source/, 'every source answered: nothing to say');
  });

  test('an expired certificate, Turkish', () => {
    const doc = S.scanSummary({ ...facts, cert: { ...cert, notAfter: new Date('2026-09-20T00:00:00Z') } }, opts('tr'));
    const out = md(doc);
    assertShape(doc);
    assert.ok(out.includes('2026-09-20 tarihinde sona erdi (7 gün önce)'), out);
    assert.ok(out.includes('- Listenizdeki 6 sunucunun sertifikaya ihtiyacı var: `web01`'));
    assert.ok(out.includes('- Doğrulama: 6 sunucunun 3 tanesinde yeni sertifika yayında · hâlâ eski: 3.'));
  });
});

describe('zone', () => {
  const facts = {
    origin: 'example.com', format: 'Cloudflare export',
    counts: { records: 39, names: 26, proxied: 10, errors: 1, warnings: 2, info: 1 },
    problems: [{ severity: 'warn', title: 'TTL below 60 s' }, { severity: 'info', title: 'Note' }, { severity: 'error', title: 'CNAME next to other data at www' }, { severity: 'warn', title: 'Two SPF records' }]
  };
  // Zone File's own texts, the keys of its problems (views/zone.js registers them as it loads; DOM-free at import).
  before(() => imp('assets/js/views/zone.js'));

  test('counts, problems by severity, the worst three, the privacy note, a bare #/zone link', () => {
    const url = `${URL_BASE}#/zone`;
    const doc = S.zoneSummary(facts, opts('en', url));
    const ls = lines(md(doc));
    assertShape(doc);
    assert.deepEqual(ls, [
      '**Zone File · `example.com`**',
      '- Cloudflare export: 39 records · 26 names · 10 proxied',
      '- Problems: 1 error · 2 warnings · 1 note',
      '- **Error:** CNAME next to other data at www',
      '- **Warning:** TTL below 60 s',
      '- **Warning:** Two SPF records',
      '- The zone file stays in this browser: the link opens Zone File without it',
      '',
      `DomainScope · as of 2026-09-27 14:03 UTC · ${url}`
    ]);
  });

  test('a problem given by its text key: the names and the line it quotes are code spans, in the UI language', () => {
    const problems = [
      { severity: 'warn', key: 'zone.issue.UNPARSED_LINE', params: { snippet: 'www IN A <!channel> `x` [a](https://example.org)' } },
      { severity: 'error', key: 'zone.issue.BAD_NAME', params: { name: '_bad*.example.com' } },
      { severity: 'warn', key: 'zone.lint.MULTIPLE_CNAME', params: { name: 'www.example.com', count: 2 } }
    ];
    const out = md(S.zoneSummary({ ...facts, problems }, opts()));
    assert.deepEqual(lines(out).slice(3, 6), [
      '- **Error:** Invalid name “`_bad*.example.com`”.',
      "- **Warning:** This line could not be understood: `www IN A <!channel> 'x' [a](https://example.org)`",
      '- **Warning:** Several CNAMEs at one name'
    ]);
    assert.ok(txt(S.zoneSummary({ ...facts, problems }, opts())).includes('- Error: Invalid name “_bad*.example.com”.'));
    const tr = md(S.zoneSummary({ ...facts, problems }, opts('tr')));
    assert.ok(tr.includes('- **Hata:** Geçersiz ad “`_bad*.example.com`”.'), tr);
  });

  test('a clean zone; Turkish', () => {
    const clean = S.zoneSummary({ ...facts, counts: { ...facts.counts, errors: 0, warnings: 0, info: 0 }, problems: [] }, opts());
    assertShape(clean);
    assert.ok(md(clean).includes('- No problems found in the zone'));
    const tr = md(S.zoneSummary(facts, opts('tr')));
    for (const s of ['**Zone Dosyası · `example.com`**', '39 kayıt · 26 ad · 10 proxy’li', '- Sorunlar: 1 hata · 2 uyarı · 1 bilgi', '- **Hata:** ',
      '- Zone dosyası bu tarayıcıda kalır: bağlantı Zone Dosyası aracını dosya olmadan açar']) {
      assert.ok(tr.includes(s), `${s}\n${tr}`);
    }
  });
});

describe('cert', () => {
  const facts = {
    name: '*.example.com', issuer: 'Example CA (R1)', dnsNames: ['*.example.com', 'example.com', 'www.example.net', 'api.example.net', 'example.org'],
    notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2026-10-01T00:00:00Z'), warnings: [], source: 'file'
  };

  test('issuer, names (four, then "+N more"), days left, the file-stays note', () => {
    const doc = S.certSummary(facts, opts('en', `${URL_BASE}#/cert`));
    const ls = lines(md(doc));
    assertShape(doc);
    assert.deepEqual(ls.slice(0, 5), [
      '**Certificate · `*.example.com`**',
      '- Issued by `Example CA (R1)`',
      '- 5 DNS names: `*.example.com`, `example.com`, `www.example.net`, `api.example.net` +1 more',
      '- Valid until 2026-10-01 (3 days left)',
      '- The certificate file stays in this browser: the link opens the Certificate tool without it'
    ]);
  });

  test('warnings, CT and sample sources, not yet valid, no names, Turkish', () => {
    const doc = S.certSummary({ ...facts, dnsNames: [], warnings: ['SELF_SIGNED', 'NO_SAN', 'UNKNOWN'], source: 'ct', notBefore: new Date('2026-10-01T00:00:00Z') }, opts());
    const out = md(doc);
    assertShape(doc);
    for (const s of ['- No DNS names', '- Not valid before 2026-10-01', '- **Warning:** self-signed: browsers do not trust it', '- **Warning:** no DNS names: browsers reject it for a host name',
      '- Loaded from Certificate Transparency: a server may serve a different one']) assert.ok(out.includes(s), `${s}\n${out}`);
    assert.doesNotMatch(out, /UNKNOWN/);
    assert.ok(md(S.certSummary({ ...facts, source: 'sample' }, opts())).includes('- This is the built-in sample certificate'));
    const tr = md(S.certSummary(facts, opts('tr')));
    assert.ok(tr.includes('**Sertifika · `*.example.com`**') && tr.includes('- Veren: `Example CA (R1)`') && tr.includes('- 2026-10-01 tarihine kadar geçerli (3 gün kaldı)') && tr.includes('- 5 DNS adı: '), tr);
  });

  test('a hostile issuer is one inert code span, as the subject is (no mention, link or formatting)', () => {
    const issuer = `*Evil* @here <https://example.org|click> https://example.org/x <!channel>${RLO}`;
    const doc = S.certSummary({ ...facts, issuer }, opts());
    assert.equal(lines(md(doc))[1], '- Issued by `*Evil* @here <https://example.org|click> https://example.org/x <!channel>`');
    assert.equal(lines(txt(doc))[1], '- Issued by *Evil* @here <https://example.org|click> https://example.org/x <!channel>');
    const scan = S.scanSummary({ domains: ['example.com'], cert: { name: 'example.com', issuer: '@channel', notAfter: new Date('2026-12-01T00:00:00Z') }, hosts: 1, inventory: 0 }, opts());
    assert.match(lines(md(scan))[1], /^- Certificate `example\.com` · issued by `@channel` · valid until /);
    // A self-signed wildcard names itself as the issuer: a code span, no backslash for Slack to show.
    const wild = S.certSummary({ ...facts, issuer: '*.wild.example.net' }, opts('tr'));
    assert.equal(lines(md(wild))[1], '- Veren: `*.wild.example.net`');
  });
});

describe('renew (Renewal readiness)', () => {
  before(async () => {
    // The finding titles and challenge labels come with lib/renewal.js (the view registers them).
    const { RENEWAL_I18N } = await imp('assets/js/lib/renewal.js');
    for (const lang of ['en', 'tr']) i18n.registerStrings(lang, RENEWAL_I18N[lang]);
  });
  const problem = (severity, id, params) => ({ severity, key: `renew.f.${id}.title`, params });
  const facts = {
    names: [
      { name: 'www.example.com', verdict: 'fail', problems: [problem('error', 'caa.denied', { ca: "Let's Encrypt" }), problem('warn', 'resolvers.servfail', { resolvers: 'DNS.SB' })] },
      { name: '*.example.com', verdict: 'warnings', problems: [problem('warn', 'wildcard.unknown', { base: 'example.com' })] },
      { name: 'example.com', verdict: 'ready', problems: [] }
    ],
    ca: "Let's Encrypt", challenge: 'http-01', tested: 1, at: new Date('2026-09-27T13:59:00Z')
  };

  test('verdict counts, CA and challenge, errors before warnings with the name, the Globalping test, the check time', () => {
    const doc = S.buildSummary('renew', facts, opts('en', `${URL_BASE}#/renew?names=www.example.com`));
    assertShape(doc);
    assert.deepEqual(lines(md(doc)), [
      '**Renewal readiness · `www.example.com`, `*.example.com`, `example.com`**',
      '- 1 will fail · 1 with warnings · 1 ready',
      "- CA: Let's Encrypt · challenge: HTTP-01",
      "- **Error:** `www.example.com` — CAA does not allow `Let's Encrypt`",
      '- **Warning:** `www.example.com` — CAA lookup fails on `DNS.SB`',
      '- **Warning:** `*.example.com` — A wildcard needs DNS-01',
      '- HTTP-01 reachability tested for 1 name from three continents (Globalping)',
      '',
      `DomainScope · checked 2026-09-27 13:59 UTC · ${URL_BASE}#/renew?names=www.example.com`
    ]);
  });

  test('nothing wrong, no CA chosen, the method not known; at most five problems; Turkish', () => {
    const clean = S.renewSummary({ names: [{ name: 'www.example.com', verdict: 'ready', problems: [] }], ca: null, challenge: 'unknown' }, opts());
    assertShape(clean, { min: 4 });
    assert.deepEqual(lines(md(clean)).slice(1, 4), ['- 1 ready', '- CA not chosen · challenge: Not sure', '- No errors or warnings']);
    const many = S.renewSummary({ names: Array.from({ length: 7 }, (_, i) => ({ name: `h${i}.example.com`, verdict: 'fail', problems: [problem('error', 'http.none', { name: `h${i}.example.com` })] })), challenge: 'http-01', ca: "Let's Encrypt" }, opts());
    assertShape(many);
    assert.ok(md(many).includes('- +2 more warnings and errors'), md(many));
    assert.ok(md(many).includes('`h2.example.com` +4 more**'), 'the title lists three names');
    const tr = md(S.renewSummary(facts, opts('tr')));
    for (const s of ['**Yenileme hazırlığı · `www.example.com`', '- 1 tanesi başarısız olacak · 1 tanesi uyarılı · 1 tanesi hazır', "- Otorite: Let's Encrypt · doğrulama: HTTP-01",
      "- **Hata:** `www.example.com` — CAA, `Let's Encrypt` otoritesine izin vermiyor", 'HTTP-01 erişilebilirliği 1 ad için üç kıtadan test edildi (Globalping)']) assert.ok(tr.includes(s), `${s}\n${tr}`);
    assert.deepEqual(S.permalinkParams('renew', { names: 'www.example.com,*.example.com', ca: 'letsencrypt', challenge: 'http-01', run: '0', tab: 'x' }),
      { names: 'www.example.com,*.example.com', ca: 'letsencrypt', challenge: 'http-01' });
  });

  test('a name that could not be checked is counted as such, after the ones that will fail', () => {
    const unknown = { name: 'api.example.com', verdict: 'unknown', problems: [problem('warn', 'caa.error', { name: 'api.example.com', error: 'HTTP 429' })] };
    const facts2 = { names: [{ name: 'www.example.com', verdict: 'ready', problems: [] }, unknown, { ...facts.names[0] }], ca: null, challenge: 'dns-01' };
    assert.deepEqual(lines(md(S.renewSummary(facts2, opts())))[1], '- 1 will fail · 1 could not be checked · 1 ready');
    assert.ok(md(S.renewSummary(facts2, opts())).includes('- **Warning:** `api.example.com` — CAA could not be checked'));
    assert.deepEqual(lines(md(S.renewSummary(facts2, opts('tr'))))[1], '- 1 tanesi başarısız olacak · 1 tanesi kontrol edilemedi · 1 tanesi hazır');
  });
});

describe('lookup (one line)', () => {
  const resp = (type, answers, extra = {}) => ({ ok: true, rcode: 'NOERROR', type, flags: { ad: true }, answers: answers.map((data) => ({ type, data })), ...extra });

  test('values when there are three or fewer, the AD bit when DNSSEC was asked', () => {
    const doc = S.lookupSummary({ name: 'example.com', types: ['A', 'MX'], dnssec: true,
      responses: [resp('A', ['192.0.2.1', '192.0.2.2']), resp('MX', [{ preference: 10, exchange: 'mail.example.com' }])] }, opts('en', `${URL_BASE}#/lookup?name=example.com&type=A,MX`));
    assertShape(doc, { inline: true });
    assert.equal(lines(md(doc))[0], '**DNS Lookup · `example.com`**: A: `192.0.2.1`, `192.0.2.2` · MX: `10 mail.example.com` · DNSSEC validated (AD)');
    assert.equal(lines(txt(doc))[0], 'DNS Lookup · example.com: A: 192.0.2.1, 192.0.2.2 · MX: 10 mail.example.com · DNSSEC validated (AD)');
  });

  test('counts for many records, none, failures and rcodes; NXDOMAIN; PTR subject', () => {
    const doc = S.lookupSummary({ name: 'example.com', types: ['TXT', 'AAAA', 'CAA', 'NS'],
      responses: [resp('TXT', [['a'], ['b'], ['c'], ['d']]), resp('AAAA', []), { ok: false, rcode: null, answers: [] }, resp('NS', [], { rcode: 'SERVFAIL' })] }, opts());
    assert.equal(lines(md(doc))[0], '**DNS Lookup · `example.com`**: TXT: 4 records · AAAA: none · CAA: lookup failed · NS: SERVFAIL');
    const nx = S.lookupSummary({ name: 'nope.example.com', types: ['A', 'AAAA'], responses: [resp('A', [], { rcode: 'NXDOMAIN' }), resp('AAAA', [], { rcode: 'NXDOMAIN' })] }, opts());
    assert.ok(lines(md(nx))[0].endsWith(': the name does not exist (NXDOMAIN)'));
    const ptr = S.lookupSummary({ name: '10.2.0.192.in-addr.arpa', ptrFor: '192.0.2.10', types: ['PTR'], responses: [resp('PTR', ['host.example.com'])] }, opts('tr'));
    assert.equal(lines(md(ptr))[0], '**DNS Sorgulama · `192.0.2.10`**: PTR: `host.example.com`');
  });

  test('the time the last answer arrived, not the time of the copy', () => {
    const facts = { name: 'example.com', types: ['A'], responses: [resp('A', ['192.0.2.1'])] };
    assert.equal(lines(md(S.lookupSummary({ ...facts, at: new Date('2026-09-27T10:00:00Z') }, opts('en', null))))[2], 'DomainScope · checked 2026-09-27 10:00 UTC');
    assert.equal(lines(txt(S.lookupSummary(facts, opts('tr', null))))[1], 'DomainScope · kontrol edildi: 2026-09-27 14:03 UTC');
  });
});

describe('ip (one line)', () => {
  const row = (ip, extra = {}) => ({ ip, info: null, classification: { kind: 'direct', provider: null, hidesOrigin: false }, servers: [], ...extra });

  test('one address: network, place, reverse name, operator; no server name', () => {
    const r = row('203.0.113.7', {
      info: { asn: 64500, asName: 'EXAMPLE-NET', country: 'NL', city: 'Amsterdam', ptr: ['edge.example.net'] },
      classification: { kind: 'cdn', provider: { name: 'Fastly' }, hidesOrigin: true },
      servers: [{ name: 'secret-db-01' }]
    });
    const doc = S.ipSummary({ rows: [r] }, opts('en', `${URL_BASE}#/ip?ips=203.0.113.7`));
    assertShape(doc, { inline: true });
    assert.equal(lines(md(doc))[0], '**IP Intel · `203.0.113.7`**: AS64500 `EXAMPLE-NET` · `Amsterdam, NL` · `edge.example.net` · Fastly · in your server list');
    assert.equal(lines(txt(doc))[0], 'IP Intel · 203.0.113.7: AS64500 EXAMPLE-NET · Amsterdam, NL · edge.example.net · Fastly · in your server list');
    assert.doesNotMatch(md(doc), /secret-db-01/);
  });

  test('a hostile AS name or place is an inert code span', () => {
    const r = row('203.0.113.7', { info: { asn: 64500, holder: '@here https://example.org *x*', country: 'NL', city: '<!channel>' } });
    assert.equal(lines(md(S.ipSummary({ rows: [r] }, opts())))[0], '**IP Intel · `203.0.113.7`**: AS64500 `@here https://example.org *x*` · `<!channel>, NL` · Direct');
  });

  test('a stopped lookup says how many addresses it never looked up; Turkish', () => {
    const rows = [row('203.0.113.7', { info: { asn: 64500, country: 'NL' } }), row('198.51.100.9'), row('198.51.100.10')];
    const doc = S.ipSummary({ rows, stopped: true }, opts());
    assertShape(doc, { inline: true });
    assert.equal(lines(md(doc))[0], '**IP Intel · 3 addresses**: 1 network · 1 country · stopped: 2 addresses not looked up');
    assert.equal(lines(md(S.ipSummary({ rows, stopped: true }, opts('tr'))))[0], '**IP Bilgisi · 3 adres**: 1 ağ · 1 ülke · durduruldu: 2 adres sorgulanmadı');
    assert.equal(lines(md(S.ipSummary({ rows: rows.slice(1, 2), stopped: true }, opts())))[0], '**IP Intel · `198.51.100.9`**: Direct · stopped before it was looked up');
    // Nothing looked up: no "no network data" in front of it (nothing was asked).
    assert.equal(lines(md(S.ipSummary({ rows: rows.slice(1), stopped: true }, opts())))[0], '**IP Intel · 2 addresses**: stopped: 2 addresses not looked up');
    assert.equal(lines(md(S.ipSummary({ rows: rows.slice(1), stopped: true }, opts('tr'))))[0], '**IP Bilgisi · 2 adres**: durduruldu: 2 adres sorgulanmadı');
    const bare = { ip: '198.51.100.9', info: null, servers: [] };
    assert.equal(lines(md(S.ipSummary({ rows: [bare], stopped: true }, opts())))[0], '**IP Intel · `198.51.100.9`**: stopped before it was looked up', 'no operator either');
    assert.doesNotMatch(md(S.ipSummary({ rows: rows.slice(0, 1), stopped: true }, opts())), /stopped/, 'every address looked up: nothing to say');
    assert.doesNotMatch(md(S.ipSummary({ rows }, opts())), /stopped/, 'not stopped');
  });

  test('a failed lookup (every source failed or rate-limited) says so, never a clean result or "no network data"; Turkish', () => {
    const fail = { asn: null, country: null, ptr: [], error: 'ripestat: Network error; ipwhois: Network error', errorKind: 'network' };
    const one = S.ipSummary({ rows: [row('203.0.113.7', { info: fail })] }, opts('en', `${URL_BASE}#/ip?ips=203.0.113.7`));
    assertShape(one, { inline: true });
    assert.equal(lines(md(one))[0], '**IP Intel · `203.0.113.7`**: Direct · lookup failed');
    assert.equal(lines(txt(one))[0], 'IP Intel · 203.0.113.7: Direct · lookup failed');
    assert.equal(lines(md(S.ipSummary({ rows: [row('203.0.113.7', { info: fail })] }, opts('tr'))))[0], '**IP Bilgisi · `203.0.113.7`**: Doğrudan · sorgu başarısız');
    assert.equal(lines(md(S.ipSummary({ rows: [{ ip: '203.0.113.7', info: fail, servers: [] }] }, opts())))[0], '**IP Intel · `203.0.113.7`**: lookup failed');

    // Every address failed: how many, never "no network data".
    const all = [row('203.0.113.7', { info: fail }), row('198.51.100.9', { info: fail }), row('198.51.100.10', { info: fail })];
    const allDoc = S.ipSummary({ rows: all }, opts());
    assertShape(allDoc, { inline: true });
    assert.equal(lines(md(allDoc))[0], '**IP Intel · 3 addresses**: 3 lookups failed');
    assert.equal(lines(md(S.ipSummary({ rows: all }, opts('tr'))))[0], '**IP Bilgisi · 3 adres**: 3 adreste sorgu başarısız');
    assert.doesNotMatch(md(allDoc) + md(S.ipSummary({ rows: all }, opts('tr'))), /no network data|ağ bilgisi yok/);

    // A mix: the failed row is counted, not dropped; with a stopped lookup both are said.
    const mix = [row('203.0.113.7', { info: { asn: 64500, country: 'NL', ptr: [], error: null } }), row('198.51.100.9', { info: fail })];
    assert.equal(lines(md(S.ipSummary({ rows: mix }, opts())))[0], '**IP Intel · 2 addresses**: 1 network · 1 country · 1 lookup failed');
    assert.equal(lines(md(S.ipSummary({ rows: mix }, opts('tr'))))[0], '**IP Bilgisi · 2 adres**: 1 ağ · 1 ülke · 1 adreste sorgu başarısız');
    assert.equal(lines(md(S.ipSummary({ rows: [...mix, row('198.51.100.10')], stopped: true }, opts())))[0],
      '**IP Intel · 3 addresses**: 1 network · 1 country · 1 lookup failed · stopped: 1 address not looked up');
    // An answered address without network data still says so next to a failed one.
    const empty = row('198.51.100.20', { info: { asn: null, country: null, ptr: [], error: null } });
    assert.equal(lines(md(S.ipSummary({ rows: [empty, row('198.51.100.9', { info: fail })] }, opts())))[0], '**IP Intel · 2 addresses**: no network data · 1 lookup failed');
  });

  test('what is not a failed lookup: a partial failure with data, a private address; a row a finished lookup never filled is one', () => {
    const partial = row('203.0.113.7', { info: { asn: 64500, country: null, ptr: [], error: null, errors: [{ source: 'ripestat-geo', error: 'HTTP 429', errorKind: 'rate-limit' }] } });
    assert.equal(lines(md(S.ipSummary({ rows: [partial] }, opts())))[0], '**IP Intel · `203.0.113.7`**: AS64500 · Direct');
    const priv = row('10.0.0.5', { info: { private: true, asn: null, country: null, ptr: [], error: null }, classification: { kind: 'private', provider: null, hidesOrigin: false } });
    assert.doesNotMatch(md(S.ipSummary({ rows: [priv] }, opts())), /failed/);
    assert.equal(lines(md(S.ipSummary({ rows: [partial, priv] }, opts())))[0], '**IP Intel · 2 addresses**: 1 private · 1 network');
    // views/ip fills every row of a lookup that ran to the end; one it did not fill had no result.
    assert.equal(lines(md(S.ipSummary({ rows: [partial, row('198.51.100.9')] }, opts())))[0], '**IP Intel · 2 addresses**: 1 network · 1 lookup failed');
  });

  test('several addresses: CDN / private / inventory counts, networks, countries; Turkish', () => {
    const rows = [
      row('203.0.113.7', { info: { asn: 64500, country: 'NL' }, classification: { kind: 'cloudflare', provider: { name: 'Cloudflare' }, hidesOrigin: true } }),
      row('198.51.100.9', { info: { asn: 64501, country: 'DE' }, servers: [{ name: 'web01' }] }),
      row('10.0.0.5', { info: { private: true, ptr: [], error: null } })
    ];
    const doc = S.ipSummary({ rows }, opts());
    assertShape(doc, { inline: true });
    assert.equal(lines(md(doc))[0], '**IP Intel · 3 addresses**: 1 behind a CDN (Cloudflare) · 1 private · 1 in your server list · 2 networks · 2 countries');
    const tr = md(S.ipSummary({ rows }, opts('tr')));
    assert.ok(tr.startsWith('**IP Bilgisi · 3 adres**: 1 tanesi CDN arkasında (Cloudflare) · 1 tanesi özel (private)'), tr);
    assert.equal(lines(md(S.ipSummary({ rows, at: new Date('2026-09-27T08:30:00Z') }, opts('en', null))))[2], 'DomainScope · checked 2026-09-27 08:30 UTC', 'the time the lookup ended');
  });
});

describe('retire', () => {
  const counts = (bySeverity, extra = {}) => {
    const full = Object.fromEntries(['mail', 'ns', 'live', 'origin', 'chain', 'file', 'stale', 'unknown'].map((s) => [s, bySeverity[s] || 0]));
    const total = Object.values(full).reduce((a, b) => a + b, 0);
    const breaking = ['mail', 'ns', 'live', 'origin', 'chain'].reduce((a, s) => a + full[s], 0);
    return { total, breaking, bySeverity: full, byVerified: {}, ...extra };
  };
  const top = [
    { severity: 'mail', name: 'example.com', type: 'TXT', value: 'ip4:192.0.2.10' },
    { severity: 'mail', name: 'example.com', type: 'MX', value: '10 mail.example.com' },
    { severity: 'ns', name: 'example.com', type: 'NS', value: 'ns1.example.com' },
    { severity: 'live', name: 'www.example.com', type: 'A', value: '192.0.2.10' },
    { severity: 'origin', name: 'shop.example.com', type: 'A', value: '192.0.2.10' },
    { severity: 'chain', name: 'blog.example.com', type: 'CNAME', value: 'www.example.com' },
    { severity: 'stale', name: 'example.com', type: 'TXT', value: '-ip4:192.0.2.10' },
    { severity: 'unknown', name: 'example.com', type: 'TXT', value: 'exists:%{i}.x.example.com' }
  ];

  test('what still points at the address, the worst records, what could not be told; a count of servers, never a name', () => {
    const facts = {
      label: '192.0.2.10', domains: ['example.com', 'example.net'], zone: 'example.com', passive: true,
      counts: counts({ mail: 2, ns: 1, live: 1, origin: 1, chain: 1, stale: 3, unknown: 1 }), top, owners: 1, unverified: 2, failed: 1,
      at: new Date('2026-09-28T09:15:00Z')
    };
    const url = `${URL_BASE}#/retire?ips=192.0.2.10&domains=example.com,example.net`;
    const doc = S.retireSummary(facts, opts('en', url));
    assertShape(doc);
    assert.deepEqual(lines(md(doc)), [
      '**Retire an IP · `192.0.2.10`**',
      '- 7 records still point at it · 6 break something once it is gone',
      '- Checked 2 domains over public DNS: `example.com`, `example.net` · the zone file of `example.com` · passive reverse IP',
      '- Owned by 1 server in your list',
      '- **Mail:** `example.com` TXT `ip4:192.0.2.10`',
      '- **Mail:** `example.com` MX `10 mail.example.com`',
      '- **Name server:** `example.com` NS `ns1.example.com`',
      '- **Address record:** `www.example.com` A `192.0.2.10`',
      '- +2 more records to change',
      '- **Not settled:** 1 SPF term that cannot be told from here · 2 passive hits not checked yet · 1 failed lookup (the list may be incomplete)',
      '- Not covered: internal (split-horizon) DNS and domains that are not in the list',
      '',
      `DomainScope · checked 2026-09-28 09:15 UTC · ${url}`
    ]);
    assert.doesNotMatch(md(doc) + txt(doc), /web01|server name/);
  });

  test('nothing points at it; a stopped check never says nothing; Turkish; no server list', () => {
    const none = S.retireSummary({ label: '192.0.2.10', domains: ['example.com'], counts: counts({}), top: [] }, opts());
    assertShape(none);
    assert.equal(lines(md(none))[1], '- Nothing in the checked domains points at it');
    assert.doesNotMatch(md(none), /server list|your list/, 'no list loaded: nothing said about it');
    const stopped = S.retireSummary({ label: '192.0.2.0/28', domains: ['example.com'], counts: counts({}), top: [], stopped: true, owners: 0 }, opts());
    assert.equal(lines(md(stopped))[1], '- Stopped before anything pointing at it was found');
    assert.match(md(stopped), /- Not in your server list/);
    const tr = S.retireSummary({ label: '192.0.2.10', domains: ['example.com'], counts: counts({ live: 1 }), top: top.slice(3, 4), stopped: true }, opts('tr'));
    assertShape(tr);
    assert.equal(lines(md(tr))[0], '**IP emekliye ayırma · `192.0.2.10`**');
    assert.equal(lines(md(tr))[1], '- 1 kayıt hâlâ bu adresi gösteriyor · adres kalkınca 1 tanesi bir şeyi bozar (erken durduruldu: her alan adı kontrol edilmedi)');
    assert.equal(lines(md(tr))[3], '- **Adres kaydı:** `www.example.com` A `192.0.2.10`');
  });

  test('a failed lookup or a "cannot tell" never reads as nothing; the domains a stop did not reach are named', () => {
    const open = S.retireSummary({ label: '192.0.2.10', domains: ['example.com'], counts: counts({ unknown: 1 }), top: [], failed: 2 }, opts());
    assertShape(open);
    assert.equal(lines(md(open))[1], '- Nothing found pointing at it, but not everything could be checked (below)');
    assert.match(md(open), /- \*\*Not settled:\*\* 1 SPF term that cannot be told from here · 2 failed lookups/);
    const tr = S.retireSummary({ label: '192.0.2.10', domains: ['example.com'], counts: counts({}), top: [], failed: 1 }, opts('tr'));
    assert.equal(lines(md(tr))[1], '- Bu adresi gösteren bir şey bulunmadı, ama her şey kontrol edilemedi (aşağıda)');
    const partial = S.retireSummary({ label: '192.0.2.10', domains: ['example.com'], notChecked: ['example.net', 'example.org'], counts: counts({}), top: [], stopped: true }, opts());
    assert.equal(lines(md(partial))[2], '- Checked 1 domain over public DNS: `example.com` · not checked: `example.net`, `example.org`');
    const none = S.retireSummary({ label: '192.0.2.10', domains: [], notChecked: ['example.com'], counts: counts({}), top: [], stopped: true }, opts());
    assert.deepEqual(lines(md(none)).slice(1, 3), ['- Stopped before anything pointing at it was found', '- No domain checked · not checked: `example.com`']);
    // A domain that does not exist (a typo in the list?) leaves the list open too.
    const typo = S.retireSummary({ label: '192.0.2.10', domains: ['example.com', 'exmaple.example.org'], counts: counts({}), top: [], missing: 1 }, opts());
    assert.equal(lines(md(typo))[1], '- Nothing found pointing at it, but not everything could be checked (below)');
    assert.match(md(typo), /- \*\*Not settled:\*\* 1 domain that does not exist \(a typo\?\)/);
  });

  test('a hostile record value stays an inert code span', () => {
    const doc = S.retireSummary({
      label: '192.0.2.10', domains: ['example.com'], counts: counts({ live: 1 }),
      top: [{ severity: 'live', name: '<!channel>.example.com', type: 'A', value: '@here *x*' }]
    }, opts());
    assert.match(md(doc), /- \*\*Address record:\*\* `<!channel>\.example\.com` A `@here \*x\*`/);
  });
});

describe('reports (DMARC & TLS reports)', () => {
  const blocker = (ip, cls, reason, detail, fail, fixes) => ({ ip, cls, reason, detail, fail, fixes });
  const facts = (over = {}) => ({
    domain: 'example.com',
    dmarc: {
      overview: {
        compliance: 4913 / 5175, messages: 5175, verdict: 'fix-first', blocked: 181,
        blockers: [
          blocker('198.51.100.20', 'third-party', 'spf-include', 'spf.mailer.example.net', 120, ['dkim-align', 'spf-align']),
          blocker('203.0.113.99', 'yours', 'inventory', 'app02', 57, ['dkim-sign', 'spf-add']),
          blocker('203.0.113.26', 'yours', 'spf', 'mx', 3, ['dkim-sign']),
          blocker('198.51.100.130', 'third-party', 'dkim-service', 'bounce.esp.example.net', 1, ['dkim-fix'])
        ],
        unknown: [{ ip: '192.0.2.200' }, { ip: '198.51.100.200' }], unknownFail: 85
      },
      policy: { p: 'none', pct: 100 }, reports: 2, begin: new Date('2026-09-25T00:00:00Z'), end: new Date('2026-09-26T23:59:59Z'), spf: 'checked'
    },
    tls: {
      success: 6138, failure: 63, rate: 6138 / 6201, reports: 2,
      byType: [{ type: 'certificate-expired', sessions: 40 }, { type: 'starttls-not-supported', sessions: 9 }, { type: 'certificate-host-mismatch', sessions: 6 },
        { type: 'validation-failure', sessions: 5 }]
    },
    problems: 1,
    ...over
  });

  test('compliance, the verdict, what to fix first, the unknown senders, TLS-RPT; never a server\'s name', () => {
    const url = `${URL_BASE}#/reports`;
    const doc = S.reportsSummary(facts(), opts('en', url));
    assertShape(doc);
    assert.deepEqual(lines(md(doc)), [
      '**DMARC & TLS reports · `example.com`**',
      '- **DMARC:** 94.9% of 5,175 messages pass · `p=none` · 2 reports, 2026-09-25 → 2026-09-26',
      '- Not ready for p=reject: 4 sources you use fail DMARC (181 messages)',
      '- **Fix first:** `198.51.100.20` (authorized third party `spf.mailer.example.net`): 120 messages fail — it signs DKIM only as another domain: set up DKIM for the domain there',
      '- **Fix first:** `203.0.113.99` (your server): 57 messages fail — sign its mail with DKIM for the domain',
      '- +2 more sources to fix',
      '- Unknown senders: 2 sources, 85 failing messages (spoofing?)',
      '- Sources classified against the domain’s current SPF',
      '- **TLS-RPT:** 99% of 6,201 TLS sessions succeeded · 2 reports',
      '- **Failures:** `certificate-expired` 40, `starttls-not-supported` 9, `certificate-host-mismatch` 6 +1 more',
      '- 1 file or entry was no report or could not be read',
      '',
      `DomainScope · as of 2026-09-27 14:03 UTC · ${url}`
    ]);
    assert.doesNotMatch(md(doc) + txt(doc), /app02/, 'no server name');
  });

  test('ready, enforced (and mail refused now), no mail, a pct under 100, SPF not checked, TLS only; Turkish', () => {
    const f = facts();
    const ready = S.reportsSummary({ ...f, tls: null, problems: 0, dmarc: { ...f.dmarc, spf: 'failed', policy: { p: 'quarantine', pct: 50 }, overview: { ...f.dmarc.overview, verdict: 'ready', blockers: [], blocked: 0, unknown: [], unknownFail: 0 } } }, opts());
    assertShape(ready, { min: 3 });
    assert.deepEqual(lines(md(ready)).slice(1, 4), [
      '- **DMARC:** 94.9% of 5,175 messages pass · `p=quarantine; pct=50` · 2 reports, 2026-09-25 → 2026-09-26',
      '- Ready for p=reject: every source you use passes DMARC',
      '- The current SPF was not checked: classes from the reports alone'
    ]);
    const losing = S.reportsSummary({ ...f, dmarc: { ...f.dmarc, policy: { p: 'reject', pct: 100 }, overview: { ...f.dmarc.overview, verdict: 'enforced', blockers: f.dmarc.overview.blockers.slice(1, 2), blocked: 57 } } }, opts());
    assert.equal(lines(md(losing))[2], '- p=reject is in force, and 1 source you use fails: 57 of its messages are refused');
    const enforced = S.reportsSummary({ ...f, dmarc: { ...f.dmarc, policy: { p: 'reject', pct: 100 }, overview: { ...f.dmarc.overview, verdict: 'enforced', blockers: [], blocked: 0 } } }, opts());
    assert.equal(lines(md(enforced))[2], '- p=reject is in force, and every source you use passes');
    const empty = S.reportsSummary({ ...f, tls: null, dmarc: { ...f.dmarc, overview: { compliance: null, messages: 0, verdict: 'no-mail', blockers: [], blocked: 0, unknown: [], unknownFail: 0 } } }, opts());
    assert.match(lines(md(empty))[1], /^- \*\*DMARC:\*\* no message in the reports · `p=none`/);
    const tlsOnly = S.reportsSummary({ domain: 'example.com', dmarc: null, tls: { ...f.tls, byType: [] }, problems: 0 }, opts());
    assertShape(tlsOnly, { min: 2 });
    assert.equal(lines(md(tlsOnly))[1], '- **TLS-RPT:** 99% of 6,201 TLS sessions succeeded · 2 reports');
    const tr = S.reportsSummary(facts(), opts('tr'));
    assertShape(tr);
    assert.deepEqual(lines(md(tr)).slice(0, 5), [
      '**DMARC ve TLS raporları · `example.com`**',
      '- **DMARC:** 5.175 e-postanın %94,9 kadarı geçiyor · `p=none` · 2 rapor, 2026-09-25 → 2026-09-26',
      '- p=reject için hazır değil: kullandığınız 4 kaynak DMARC’den geçmiyor (181 e-posta)',
      '- **Önce düzeltin:** `198.51.100.20` (yetkili üçüncü taraf `spf.mailer.example.net`): 120 e-posta geçmiyor — DKIM’i yalnızca başka bir alan adı olarak imzalıyor: orada alan adınız için DKIM kurun',
      '- **Önce düzeltin:** `203.0.113.99` (sunucunuz): 57 e-posta geçmiyor — e-postalarını alan adı için DKIM ile imzalayın'
    ]);
    assert.equal(S.buildSummary('reports', facts(), opts()).kind, 'reports');
    assert.deepEqual(S.permalinkParams('reports', { domain: 'example.com', tab: 'tls' }), {}, 'the reports never go into a link');
  });
});

/* ------------------------------------------------------------------------ */
describe('domain (overview)', () => {
  /** passportSummaryFacts() of a healthy domain (lib/passport.js). */
  const facts = (over = {}) => ({
    domain: 'example.com',
    host: null,
    at: new Date('2026-09-27T13:58:00Z'),
    registration: { pending: false, failed: false, outcome: 'ok', registrar: 'Example Registrar, Inc.', expires: new Date('2027-08-13T04:00:00Z'), daysLeft: 319, transferLock: true, tld: 'com', whois: null },
    dns: { pending: false, failed: false, exists: true, providers: ['Cloudflare'], self: false, other: [], dnssec: 'validated', delegationDiffers: false },
    mail: { pending: false, failed: false, mx: 'some', platforms: ['Microsoft 365'], other: [], spf: { state: 'ok', all: '-', redirect: false, count: 1 }, dmarc: { state: 'ok', policy: 'reject', count: 1 } },
    web: {
      pending: false, failed: false, https: true,
      hosts: [{ name: 'example.com', state: 'ok', kind: 'cloudflare', provider: 'Cloudflare' }, { name: 'www.example.com', state: 'ok', kind: 'platform', provider: 'Netlify' }]
    },
    certs: { pending: false, failed: false, caa: 'present', cas: ["Let's Encrypt"], ct: null },
    saas: { pending: false, failed: false, vendors: ['Google', 'Microsoft 365', 'Atlassian', 'Stripe'] },
    health: { pending: false, failed: false, score: 88, light: 'warn' },
    ...over
  });
  const url = `${URL_BASE}#/domain?name=example.com`;

  test('one line per card, names from the app\'s tables as text, the registrar and host names as code', () => {
    const doc = S.buildSummary('domain', facts(), opts('en', url));
    assertShape(doc);
    assert.deepEqual(lines(md(doc)), [
      '**Domain overview · `example.com`**',
      '- **Registration:** `Example Registrar, Inc.` · expires 2027-08-13 (319 days left)',
      '- **DNS:** Cloudflare · DNSSEC validated',
      '- **Mail:** Microsoft 365 · SPF `-all` · DMARC `p=reject`',
      '- **Web:** `example.com` Cloudflare · `www.example.com` Netlify · HTTPS record',
      "- **Certificates:** CAA allows Let's Encrypt",
      '- **Services:** 4 services verified the domain by TXT: Google, Microsoft 365, Atlassian +1 more',
      '- **Health:** Needs attention · score 88/100',
      '',
      `DomainScope · checked 2026-09-27 13:58 UTC · ${url}`
    ]);
    const tr = md(S.buildSummary('domain', facts(), opts('tr', url)));
    assert.match(tr, /^\*\*Alan adı özeti · `example\.com`\*\*$/m);
    assert.match(tr, /- \*\*Kayıt:\*\* `Example Registrar, Inc\.` · 2027-08-13 tarihinde sona eriyor \(319 gün kaldı\)/);
    assert.match(tr, /- \*\*Hizmetler:\*\* 4 hizmet alan adını TXT ile doğrulamış: Google, Microsoft 365, Atlassian \+1 tane daha/);
  });

  test('the CT issuers and what CAA does not allow; no transfer lock; several providers and an unknown name server', () => {
    const doc = S.domainSummary(facts({
      registration: { ...facts().registration, transferLock: false },
      dns: { ...facts().dns, providers: ['Cloudflare', 'Amazon Route 53'], other: ['ns1.example.net'], delegationDiffers: true },
      certs: { ...facts().certs, ct: { issuers: [{ name: "Let's Encrypt", count: 8 }, { name: 'Sectigo', count: 2 }], notAllowed: ['Sectigo'] } }
    }), opts('en', url));
    assertShape(doc);
    const out = md(doc);
    assert.match(out, /- \*\*Registration:\*\* `Example Registrar, Inc\.` · expires 2027-08-13 \(319 days left\) · no transfer lock/);
    assert.match(out, /- \*\*DNS:\*\* Cloudflare, Amazon Route 53 · `ns1\.example\.net` · DNSSEC validated · the registry delegates to other name servers/);
    assert.match(out, /- \*\*Certificates:\*\* CAA allows Let's Encrypt · issuers in CT: `Let's Encrypt` \(8\), `Sectigo` \(2\) · not allowed by CAA: `Sectigo`/);
  });

  test('a stopped build says what was not looked up; failed parts say so; a TLD without RDAP names its registry', () => {
    const doc = S.domainSummary(facts({
      registration: { pending: false, failed: false, outcome: 'unsupported', tld: 'tr', whois: 'TRABİS' },
      dns: { pending: false, failed: true, exists: true, providers: [], self: false, other: [], dnssec: null },
      mail: { pending: false, failed: true, mx: null, platforms: [], other: [], spf: { state: 'none', count: 1 }, dmarc: { state: 'ok', policy: 'none', count: 1 } },
      web: { pending: true, failed: false, hosts: [], https: null },
      certs: { pending: false, failed: false, caa: 'none', cas: [], ct: { issuers: [], notAllowed: [] } },
      saas: { pending: false, failed: true, vendors: [] },
      health: { pending: true, failed: false, score: null, light: null }
    }), opts('en', url));
    assertShape(doc);
    assert.deepEqual(lines(txt(doc)).slice(1, 8), [
      '- Registration: .tr publishes no RDAP: see TRABİS',
      '- DNS: lookup failed',
      '- Mail: MX lookup failed · no SPF · DMARC p=none',
      '- Web: not looked up',
      '- Certificates: no CAA: any CA may issue · no current certificate in CT',
      '- Services: lookup failed',
      '- Health: not looked up'
    ]);
    const other = S.domainSummary(facts({
      registration: { pending: false, failed: true, outcome: 'failed' },
      mail: { pending: false, failed: false, mx: 'null', platforms: [], other: [], spf: { state: 'many', count: 2 }, dmarc: { state: 'none', count: 1 } },
      dns: { pending: false, failed: false, exists: false, providers: [], self: false, other: [], dnssec: 'unsigned' }
    }), opts('en', url));
    assert.match(txt(other), /- Registration: lookup failed\n- DNS: the domain does not exist \(NXDOMAIN\)\n- Mail: accepts no mail \(null MX\) · 2 SPF records \(invalid\) · no DMARC\n/);
    // NS failed, the DNSSEC lookups answered: the line says which part is missing.
    const ns = S.domainSummary(facts({ dns: { pending: false, failed: true, exists: true, providers: [], self: false, other: [], nsFailed: true, dnssec: 'validated' } }), opts('en', url));
    assert.match(txt(ns), /- DNS: NS lookup failed · DNSSEC validated\n/);
    const soa = S.domainSummary(facts({ dns: { ...facts().dns, failed: true } }), opts('en', url));
    assert.match(txt(soa), /- DNS: Cloudflare · DNSSEC validated · some lookups failed\n/);
  });

  test('a line never reads as complete without the lookup that failed: SPF, DMARC, a host\'s HTTPS record, CAA, CT', () => {
    const mail = { ...facts().mail, failed: true, platforms: ['Microsoft 365', 'Proofpoint'] };
    // TXT failed (no SPF known), DMARC answered
    const txtDown = S.domainSummary(facts({ mail: { ...mail, spf: null, spfFailed: true, dmarc: { state: 'ok', policy: 'quarantine', count: 1 } } }), opts('en', url));
    assert.match(txt(txtDown), /- Mail: Microsoft 365, Proofpoint · SPF lookup failed · DMARC p=quarantine\n/);
    // both failed, MX answered
    const both = S.domainSummary(facts({ mail: { ...mail, spf: null, spfFailed: true, dmarc: null, dmarcFailed: true } }), opts('en', url));
    assert.match(txt(both), /- Mail: Microsoft 365, Proofpoint · SPF lookup failed · DMARC lookup failed\n/);
    assert.match(txt(S.domainSummary(facts({ mail: { ...mail, spf: null, spfFailed: true, dmarc: null, dmarcFailed: true } }), opts('tr', url))),
      /- E-posta: Microsoft 365, Proofpoint · SPF sorgusu başarısız · DMARC sorgusu başarısız\n/);
    // www's HTTPS record could not be read, the apex has one
    const web = S.domainSummary(facts({ web: { ...facts().web, failed: true, httpsFailed: ['www.example.com'] } }), opts('en', url));
    assert.match(md(web), /- \*\*Web:\*\* `example\.com` Cloudflare · `www\.example\.com` Netlify · HTTPS record · HTTPS record lookup failed for `www\.example\.com`\n/);
    const noHttps = S.domainSummary(facts({ web: { ...facts().web, failed: true, https: null, httpsFailed: ['example.com', 'www.example.com'] } }), opts('en', url));
    assert.match(txt(noHttps), /- Web: example\.com Cloudflare · www\.example\.com Netlify · HTTPS record lookup failed for example\.com, www\.example\.com\n/);
    // CAA failed: the CT issuers read on the page are kept
    const ct = { issuers: [{ name: "Let's Encrypt", count: 2 }], notAllowed: [] };
    const caaDown = S.domainSummary(facts({ certs: { pending: false, failed: true, caa: null, caaFailed: true, cas: [], ct } }), opts('en', url));
    assert.match(md(caaDown), /- \*\*Certificates:\*\* CAA lookup failed · issuers in CT: `Let's Encrypt` \(2\)\n/);
    const caaOnly = S.domainSummary(facts({ certs: { pending: false, failed: true, caa: null, caaFailed: true, cas: [], ct: null } }), opts('en', url));
    assert.match(txt(caaOnly), /- Certificates: lookup failed\n/);
    const ctDown = S.domainSummary(facts({ certs: { ...facts().certs, ctFailed: true } }), opts('en', url));
    assert.match(txt(ctDown), /- Certificates: CAA allows Let's Encrypt · CT lookup failed\n/);
  });

  test('the SPF qualifier and the DMARC policy are code spans: a tilde pasted into Slack keeps no backslash', () => {
    const doc = S.domainSummary(facts({ mail: { ...facts().mail, spf: { state: 'ok', all: '~', redirect: false, count: 1 }, dmarc: { state: 'ok', policy: 'none', count: 1 } } }), opts('en', url));
    assert.match(md(doc), /- \*\*Mail:\*\* Microsoft 365 · SPF `~all` · DMARC `p=none`\n/);
    assert.doesNotMatch(md(doc), /\\~/);
    assert.match(txt(doc), /- Mail: Microsoft 365 · SPF ~all · DMARC p=none\n/);
    assert.match(md(S.domainSummary(facts({ mail: { ...facts().mail, spf: { state: 'ok', all: '?', redirect: false, count: 1 } } }), opts('tr', url))),
      /- \*\*E-posta:\*\* Microsoft 365 · SPF `\?all` · DMARC `p=reject`\n/);
  });

  test('a name RDAP says no registry holds reads as the card words it', () => {
    const reg = { pending: false, failed: false, outcome: 'invalid', tld: null, whois: null };
    assert.match(txt(S.domainSummary(facts({ registration: reg }), opts('en', url))), /- Registration: not a domain a registry holds\n/);
    assert.match(txt(S.domainSummary(facts({ registration: reg }), opts('tr', url))), /- Kayıt: bir kayıt kuruluşunun tuttuğu bir alan adı değil\n/);
  });

  test('CAA as RFC 8659 reads it: no issue property, issuewild on its own, wildcards only, a critical unknown tag', () => {
    const certs = (over) => ({ certs: { pending: false, failed: false, exists: true, caa: 'present', cas: [], wildcard: false, wildCas: [], criticalTags: [], ct: null, ...over } });
    const line = (over, lang = 'en') => lines(md(S.domainSummary(facts(certs(over)), opts(lang, url)))).find((l) => /^- \*\*(Certificates|Sertifikalar):\*\*/.test(l));
    // iodef only
    assert.equal(line({ caa: 'unrestricted' }), '- **Certificates:** CAA allows any CA (no issue property)');
    // issuewild ";" only, and issuewild naming a CA only
    assert.equal(line({ caa: 'unrestricted', wildcard: true }), '- **Certificates:** CAA allows any CA (no issue property) · no CA for wildcard certificates');
    assert.equal(line({ caa: 'unrestricted', wildcard: true, wildCas: ["Let's Encrypt"] }), "- **Certificates:** CAA allows any CA (no issue property) · wildcard certificates: Let's Encrypt");
    // issue ";" + issuewild letsencrypt.org
    assert.equal(line({ caa: 'present', wildcard: true, wildCas: ["Let's Encrypt"] }), "- **Certificates:** CAA allows wildcard certificates only, from Let's Encrypt");
    // issue CAs with issuewild ";" or another issuewild CA
    assert.equal(line({ caa: 'present', cas: ["Let's Encrypt"], wildcard: true }), "- **Certificates:** CAA allows Let's Encrypt · no CA for wildcard certificates");
    assert.equal(line({ caa: 'present', cas: ["Let's Encrypt"], wildcard: true, wildCas: ['DigiCert'] }), "- **Certificates:** CAA allows Let's Encrypt · wildcard certificates: DigiCert");
    // never "CAA allows " with nothing after it
    assert.equal(line({ caa: 'present' }), '- **Certificates:** CAA allows no CA');
    assert.equal(line({ caa: 'deny-all', wildcard: true }), '- **Certificates:** CAA allows no CA');
    // a critical unknown tag: the tag as a code span, never "Let's Encrypt allowed"
    assert.equal(line({ caa: 'critical', cas: ["Let's Encrypt"], criticalTags: ['tbs'] }), '- **Certificates:** CAA has an unknown tag marked critical (`tbs`): no CA may issue');
    assert.equal(line({ caa: 'critical', criticalTags: ['tbs', 'x`y'] }), "- **Certificates:** CAA has unknown tags marked critical (`tbs`, `x'y`): no CA may issue");
    // Past three tags, "+N more" inside the parentheses: no tag goes unsaid.
    assert.equal(line({ caa: 'critical', criticalTags: ['tbs', 'averyveryverylongtagname', 'zz9', 'q1'] }),
      '- **Certificates:** CAA has unknown tags marked critical (`tbs`, `averyveryverylongtagname`, `zz9` +1 more): no CA may issue');
    // Turkish
    assert.equal(line({ caa: 'unrestricted', wildcard: true }, 'tr'), '- **Sertifikalar:** CAA her CA’ya izin veriyor (issue özelliği yok) · joker sertifikalara hiçbir CA izinli değil');
    assert.equal(line({ caa: 'present', wildcard: true, wildCas: ["Let's Encrypt"] }, 'tr'), "- **Sertifikalar:** CAA yalnızca joker (wildcard) sertifikalara izin veriyor: Let's Encrypt");
    assert.equal(line({ caa: 'critical', criticalTags: ['tbs'] }, 'tr'), '- **Sertifikalar:** CAA’da kritik işaretli bilinmeyen etiket var (`tbs`): hiçbir CA sertifika veremez');
    for (const lang of ['en', 'tr']) {
      for (const over of [{ caa: 'unrestricted' }, { caa: 'present', wildcard: true, wildCas: ['DigiCert'] }, { caa: 'present' }]) {
        assert.doesNotMatch(line(over, lang), /(allows|izinli:) ?(·|$)/, `${lang} ${JSON.stringify(over)}`);
      }
    }
  });

  test('a domain that does not exist: mail, certificates and services say so instead of "no record"', () => {
    const doc = S.domainSummary(facts({
      dns: { pending: false, failed: false, exists: false, providers: [], self: false, other: [], dnssec: 'unsigned' },
      mail: { pending: false, failed: false, exists: false, mx: 'none', platforms: [], other: [], spf: { state: 'none', count: 1 }, dmarc: { state: 'none', count: 1 } },
      web: { pending: false, failed: false, exists: false, https: false, httpsFailed: [], hosts: [{ name: 'example.com', state: 'nxdomain' }, { name: 'www.example.com', state: 'nxdomain' }] },
      certs: { pending: false, failed: false, exists: false, caa: 'none', cas: [], ct: null },
      saas: { pending: false, failed: false, exists: false, vendors: [] }
    }), opts('en', url));
    assert.deepEqual(lines(txt(doc)).slice(2, 7), [
      '- DNS: the domain does not exist (NXDOMAIN)',
      '- Mail: the domain does not exist (NXDOMAIN)',
      '- Web: example.com does not exist · www.example.com does not exist',
      '- Certificates: the domain does not exist (NXDOMAIN)',
      '- Services: the domain does not exist (NXDOMAIN)'
    ]);
  });

  test('an untrusted registrar or host name stays inert; the permalink carries only the name', () => {
    const doc = S.domainSummary(facts({
      registration: { ...facts().registration, registrar: `Evil \`co\` <!channel> @here ${RLO}` },
      web: { ...facts().web, hosts: [{ name: 'example.com', state: 'dangling', kind: 'unresolved', provider: null }, { name: 'www.example.com', state: 'failed' }] }
    }), opts('en', url));
    assertShape(doc);
    const out = md(doc);
    assert.match(out, /- \*\*Registration:\*\* `Evil 'co' <!channel> @here` · expires/);
    assert.match(out, /- \*\*Web:\*\* `example\.com` Dangling CNAME · `www\.example\.com` lookup failed · HTTPS record/);
    assert.deepEqual(S.permalinkParams('domain', { name: 'example.com', run: '0', type: 'A' }), { name: 'example.com' });
  });
});

describe('rendering and dispatch', () => {
  test('buildSummary dispatches by view id and refuses unknown views', () => {
    const doc = S.buildSummary('zone', { origin: 'example.com', counts: { records: 1, names: 1, proxied: 0 } }, opts());
    assert.equal(doc.kind, 'zone');
    assert.throws(() => S.buildSummary('bulk', {}, opts()), RangeError);
    assert.throws(() => S.buildSummary('zone', {}, { lang: 'en' }), TypeError, 'a translator is required');
    assert.deepEqual([...S.SUMMARY_KINDS].sort(), Object.keys(S.PERMALINK_PARAMS).sort());
  });

  test('textParts and renderParts: a title\'s string params as code parts, one line by the renderers\' rule', () => {
    const parts = S.textParts(i18n.t, 'health.dmarc.inherited.title', { org: '@team <b>example.com' });
    assert.deepEqual(parts, ['DMARC inherited from ', { code: '@team <b>example.com' }]);
    assert.deepEqual(S.textParts(i18n.t, 'health.spf.lookups-ok.title', { count: 3, limit: 10 }), ['SPF uses 3 of 10 DNS lookups']);
    const line = [{ strong: 'NEW' }, ' ', { code: 'www.example.com' }, `: *moved* ${RLO}→ [x](y)`];
    assert.equal(S.renderParts(line), '**NEW** `www.example.com`: \\*moved\\* → \\[x\\](y)');
    assert.equal(S.renderParts(line, 'text'), 'NEW www.example.com: *moved* → [x](y)');
    assert.equal(S.renderParts(parts), 'DMARC inherited from `@team <b>example.com`');
    assert.equal(S.renderParts(null), '');
  });

  test('renderSummary picks the format; no URL → no link in the footer', () => {
    const doc = S.zoneSummary({ origin: 'example.com', counts: { records: 1, names: 1, proxied: 0 } }, { ...opts(), url: null });
    assert.equal(S.renderSummary(doc, 'text'), txt(doc));
    assert.equal(S.renderSummary(doc), md(doc));
    assert.equal(lines(md(doc)).pop(), 'DomainScope · as of 2026-09-27 14:03 UTC');
    assert.deepEqual(S.SUMMARY_FORMATS, ['markdown', 'text']);
  });

  test('the Markdown footer is its own paragraph, never a lazy continuation of the last item or the one-line summary', () => {
    const zone = S.zoneSummary({ origin: 'example.com', counts: { records: 1, names: 1, proxied: 0 } }, opts('en', `${URL_BASE}#/zone`));
    const ip = S.ipSummary({ rows: [{ ip: '203.0.113.7', info: { ptr: [], error: null }, classification: { kind: 'direct' }, servers: [] }] }, opts('en', `${URL_BASE}#/ip?ips=203.0.113.7`));
    for (const doc of [zone, ip]) {
      // CommonMark (Jira's Markdown paste, GitHub, GitLab): a line right after a "- " item or a
      // paragraph continues it; only an empty line ends the block.
      const out = md(doc);
      const blocks = out.trimEnd().split('\n\n');
      assert.equal(blocks.length, 2, `the summary, then the footer:\n${out}`);
      assert.match(blocks[1], /^DomainScope · [^\n]+$/, 'the footer alone');
      assert.doesNotMatch(blocks[0], /DomainScope/);
    }
    assert.match(md(zone), /zone file stays in this browser: the link opens Zone File without it\n\nDomainScope · as of /);
    assert.match(md(ip), /^\*\*IP Intel · `203\.0\.113\.7`\*\*: Direct\n\nDomainScope · checked /);
    // Plain text keeps its lines together.
    assert.doesNotMatch(txt(zone), /\n\n/);
    assert.doesNotMatch(txt(ip), /\n\n/);
  });
});

describe('i18n', () => {
  const placeholders = (v) => {
    const forms = typeof v === 'string' ? [v] : Object.values(v);
    return [...new Set(forms.flatMap((f) => [...f.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1])))].sort().join(',');
  };

  test('EN and TR have the same keys and placeholders, never an empty text', () => {
    const en = S.SUMMARY_I18N.en;
    const tr = S.SUMMARY_I18N.tr;
    const other = (v) => (typeof v === 'string' ? v : v.other);
    // A plural form may leave {count} out ("in your server list"); every other placeholder is in both.
    const named = (v) => placeholders(v).split(',').filter((p) => p && p !== 'count').join(',');
    assert.deepEqual(Object.keys(en).sort(), Object.keys(tr).sort());
    for (const k of Object.keys(en)) {
      assert.ok(other(en[k]).trim() && other(tr[k]).trim(), `${k} empty`);
      assert.equal(named(tr[k]), named(en[k]), `${k} placeholders`);
      assert.equal(placeholders(other(tr[k])), placeholders(other(en[k])), `${k} {placeholders} of the 'other' form`);
    }
  });

  test('every sum.* key the builders use exists, and every defined key is used', async () => {
    const src = readFileSync(join(ROOT, 'assets', 'js', 'lib', 'summary.js'), 'utf8');
    const code = src.slice(0, src.indexOf('const STRINGS = ['));
    const used = new Set([...code.matchAll(/'(sum\.[A-Za-z.]+)'/g)].map((m) => m[1]));
    // Keys built from a code: sum.health.light.<light>, sum.global.<state>, sum.global.find.<code>, sum.cert.warn.<code>.
    for (const l of ['ok', 'warn', 'error']) used.add(`sum.health.light.${l}`);
    for (const s of ['agree', 'geo', 'unresolved', 'differ']) used.add(`sum.global.${s}`);
    for (const f of ['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'operators', 'direct', 'records']) used.add(`sum.global.find.${f}`);
    for (const w of S.CERT_SUMMARY_WARNINGS) used.add(`sum.cert.warn.${w}`);
    for (const r of S.RETIRE_BREAKING_SEVERITIES) used.add(`sum.retire.sev.${r}`);
    // Domain overview: sum.domain.dnssec.<state>, sum.domain.spf.<state>, sum.domain.dmarc.<state>.
    for (const d of ['validated', 'signed', 'unsigned', 'failing']) used.add(`sum.domain.dnssec.${d}`);
    for (const st of ['none', 'many', 'invalid']) { used.add(`sum.domain.spf.${st}`); used.add(`sum.domain.dmarc.${st}`); }
    // DMARC & TLS reports: sum.rpt.cls.<class of a source to fix>, sum.rpt.fix.<code>, the hyphenated verdict.
    const { FIX_CODES } = await imp('assets/js/lib/dmarcreport.js');
    for (const c of ['yours', 'third-party']) used.add(`sum.rpt.cls.${c}`);
    for (const f of FIX_CODES) used.add(`sum.rpt.fix.${f}`);
    used.add('sum.rpt.verdict.fix-first');
    const defined = new Set(Object.keys(S.SUMMARY_I18N.en));
    assert.deepEqual([...used].filter((k) => !defined.has(k)), [], 'used but not defined');
    assert.deepEqual([...defined].filter((k) => !used.has(k)), [], 'defined but never used');
  });

  test('every Global DNS finding code of lib/propagation has a text', async () => {
    const { VERDICT_FINDINGS } = await imp('assets/js/lib/propagation.js');
    for (const f of VERDICT_FINDINGS) assert.ok(S.SUMMARY_I18N.en[`sum.global.find.${f}`], f);
  });
});
