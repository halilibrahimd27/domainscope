// The adaptive locale packs in the Subdomains view and SSL Targets: the plan line and the languages
// line before a scan, and a run's explanation of the packs the evidence picked
// (ui/locale-evidence.js, in the run header of both views), in English and Turkish. Pure: no DOM,
// no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as i18n from '../../assets/js/i18n.js';

const S = {
  ...(await import('../../assets/js/views/subdomains.js')),
  ...(await import('../../assets/js/ui/subdomains-run.js')),
  ...(await import('../../assets/js/ui/locale-evidence.js'))
};
const source = (rel) => readFile(new URL(`../../assets/js/${rel}`, import.meta.url), 'utf8');

const inLang = (lang, fn) => {
  const prev = i18n.getLang();
  i18n.setLang(lang);
  try {
    return fn();
  } finally {
    i18n.setLang(prev);
  }
};

/** A lib/localeevidence.js result as lib/scanner.js reports it (one picked pack). */
const EVIDENCE = {
  domain: 'example.com',
  locales: ['tr'],
  signals: [
    {
      locale: 'tr', score: 4.5, picked: true, points: { words: 2.5, letters: 0, ns: 0, mx: 2 },
      words: ['bayi', 'destek', 'kampanya'], wordCount: 3, letters: [], ns: [], mx: ['.com.tr']
    },
    { locale: 'de', score: 1, picked: false, points: { words: 1, letters: 0, ns: 0, mx: 0 }, words: ['kunden'], wordCount: 1, letters: [], ns: [], mx: [] }
  ],
  names: 7, labels: 7, ns: 1, mx: 1
};

describe('before a scan: the plan line and the languages line', () => {
  test('a domain whose TLD has no pack of its own is marked; its packs are not counted in the plan', () => {
    const com = S.wordlistPlan({ level: 'smart', domains: ['example.com'] }).perDomain[0];
    assert.deepEqual([com.evidence, com.packs, com.total], [true, [], S.levelCount('smart')]);
    const tr = S.wordlistPlan({ level: 'smart', domains: ['example.com.tr'] }).perDomain[0];
    assert.equal(tr.evidence, false, 'the TLD decides');
    assert.equal(S.wordlistPlan({ level: 'smart', domains: ['example.com'], locales: [] }).perDomain[0].evidence, false, 'a manual choice');
    assert.equal(S.wordlistPlan({ level: 'small', domains: ['example.com'] }).perDomain[0].evidence, false, 'Small is language-neutral');
    assert.equal(S.wordlistPlan({ level: 'smart', domains: [] }).perDomain[0].evidence, false, 'no domain typed yet');
  });

  test('the plan line says the scan may add market packs from evidence (EN / TR)', () => {
    const plan = S.wordlistPlan({ level: 'smart', domains: ['example.com'], custom: 2 });
    inLang('en', () => {
      assert.match(S.wordlistPlanText(plan), /^≈ [\d,]+ DNS queries for 1 domain \(7,000 smart, plus market packs if the scan finds evidence, \+2 yours\) · /);
      const mixed = S.wordlistPlan({ level: 'large', domains: ['example.com.tr', 'example.net'] });
      assert.match(S.wordlistPlanText(mixed), /\(per domain: 50,000 large, \+283 Turkish, plus market packs if the scan finds evidence\)/);
      assert.doesNotMatch(S.wordlistPlanText(S.wordlistPlan({ level: 'smart', domains: ['example.de'] })), /evidence/);
    });
    inLang('tr', () => {
      assert.match(S.wordlistPlanText(plan), /^1 alan adı için ≈ [\d.]+ DNS sorgusu \(7\.000 akıllı, kanıt bulunursa pazar paketleri de, \+2 sizin\) · /);
    });
  });

  test('the query range counts the packs the evidence may add, in its ceiling only', () => {
    const auto = S.planQueryRange({ level: 'smart', domains: ['example.com'] });
    const none = S.planQueryRange({ level: 'smart', domains: ['example.com'], locales: [] });
    assert.equal(auto.min, none.min);
    assert.ok(auto.max > none.max);
    assert.ok(auto.breakdown.localeEvidence > 0);
  });

  test('the languages line says where the packs of each domain come from', () => {
    inLang('en', () => {
      assert.equal(S.localeSummary(null, ['example.org', 'example.net']),
        'Auto: .org, .net have no market pack of their own, so the scan picks packs from evidence — the words in the names it finds and the countries of the name and mail servers');
      // A country ending without a pack (the UK, Sweden …) names a market: it only has no pack.
      assert.equal(S.localeSummary(null, ['example.co.uk']),
        'Auto: .co.uk has no market pack of its own, so the scan picks packs from evidence — the words in the names it finds and the countries of the name and mail servers');
      assert.equal(S.localeSummary(null, ['example.ch', 'example.com']), 'Auto: German (.ch), French (.ch), Italian (.ch), from evidence for .com');
      assert.equal(i18n.t('sub.lang.auto'), 'Choose from the domain ending or the scan’s evidence');
      assert.equal(S.localeSummary(null, []),
        'Auto: picked from the domain ending (e.g. .de → German, .com.tr → Turkish), or from the scan’s evidence for an ending without a pack');
    });
    inLang('tr', () => {
      assert.equal(S.localeSummary(null, ['example.com']),
        'Otomatik: .com uzantısına özel bir pazar paketi yok; tarama paketleri kanıta göre seçer — bulduğu adlardaki kelimeler ile ad ve posta sunucularının ülkesi');
      assert.equal(S.localeSummary(null, ['example.co.uk', 'example.se']),
        'Otomatik: .co.uk, .se uzantılarına özel bir pazar paketi yok; tarama paketleri kanıta göre seçer — bulduğu adlardaki kelimeler ile ad ve posta sunucularının ülkesi');
      assert.equal(i18n.t('sub.lang.auto'), 'Alan adı uzantısına ya da taramadaki kanıta göre seç');
      assert.equal(S.localeSummary(null, []),
        'Otomatik: alan adı uzantısından seçilir (ör. .de → Almanca, .com.tr → Türkçe); paketi olmayan uzantılarda taramadaki kanıta göre');
    });
  });
});

describe('a run: how each domain got its packs, and why', () => {
  const doneRun = (perDomain) => ({ result: { options: { wordlist: { level: 'smart', perDomain } } }, stages: {} });

  test('localeChoicesOf reads the result, or the wordlist stage while it runs', () => {
    const live = { result: null, stages: { bruteforce: { state: 'active', info: { locales: [{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: EVIDENCE }] } } } };
    assert.deepEqual(S.localeChoicesOf(live), [{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: EVIDENCE }]);
    const done = doneRun([{ domain: 'example.com', locales: ['tr'], localeSource: 'evidence', localeEvidence: EVIDENCE }]);
    assert.deepEqual(S.localeChoicesOf(done), [{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: EVIDENCE }]);
    // A result from before the adaptive packs (no localeSource) and a run before its wordlist stage.
    assert.deepEqual(S.localeChoicesOf(doneRun([{ domain: 'example.com', locales: [] }])), [{ domain: 'example.com', locales: [], source: null, evidence: null }]);
    assert.deepEqual(S.localeChoicesOf({ result: null, stages: { bruteforce: { state: 'pending', info: null } } }), []);
    assert.deepEqual(S.localeChoicesOf(null), []);
  });

  test('one sentence per pack picked from evidence, with its reasons (EN / TR)', () => {
    const choices = [{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: EVIDENCE }];
    inLang('en', () => {
      assert.deepEqual(S.localeEvidenceTexts(choices), [{
        domain: 'example.com', locale: 'tr',
        text: 'Turkish pack added for example.com. Evidence: words in the names found (bayi, destek, kampanya), the mail servers’ domain ending (.com.tr).'
      }]);
    });
    inLang('tr', () => {
      assert.equal(S.localeEvidenceTexts(choices)[0].text,
        'example.com için Türkçe paket eklendi. Kanıt: bulunan adlardaki kelimeler (bayi, destek, kampanya), posta sunucularının alan adı uzantısı (.com.tr).');
    });
  });

  test('long word lists are shortened, IDN letters and name servers named; other sources say nothing', () => {
    const words = ['bayi', 'destek', 'kampanya', 'kargo', 'magaza', 'musteri', 'siparis', 'sube'];
    const ev = {
      ...EVIDENCE,
      signals: [{ locale: 'tr', score: 9, picked: true, points: { words: 6, letters: 1, ns: 2, mx: 0 }, words, wordCount: 11, letters: ['şube'], ns: ['.com.tr', '.net.tr'], mx: [] }]
    };
    inLang('en', () => {
      const [line] = S.localeEvidenceTexts([{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: ev }]);
      assert.equal(line.text, 'Turkish pack added for example.com. Evidence: words in the names found (bayi, destek, kampanya, kargo, magaza and 6 more), '
        + 'the letters of IDN names (şube), the name servers’ domain endings (.com.tr, .net.tr).');
    });
    inLang('tr', () => {
      assert.match(S.localeEvidenceTexts([{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: ev }])[0].text,
        /\(bayi, destek, kampanya, kargo, magaza ve 6 kelime daha\), IDN adlarındaki harfler \(şube\), ad sunucularının alan adı uzantıları \(\.com\.tr, \.net\.tr\)\.$/);
    });
    // One ending each: the singular.
    const single = { ...ev, signals: [{ ...ev.signals[0], ns: ['.com.tr'], mx: ['.com.tr'], points: { ...ev.signals[0].points, mx: 2 } }] };
    const one = [{ domain: 'example.com', locales: ['tr'], source: 'evidence', evidence: single }];
    inLang('en', () => assert.match(S.localeEvidenceTexts(one)[0].text, /the name servers’ domain ending \(\.com\.tr\), the mail servers’ domain ending \(\.com\.tr\)\.$/));
    inLang('tr', () => assert.match(S.localeEvidenceTexts(one)[0].text, /ad sunucularının alan adı uzantısı \(\.com\.tr\), posta sunucularının alan adı uzantısı \(\.com\.tr\)\.$/));
    for (const source of ['tld', 'chosen', 'none', null]) {
      assert.deepEqual(S.localeEvidenceTexts([{ domain: 'example.com', locales: ['tr'], source, evidence: EVIDENCE }]), [], String(source));
    }
    assert.deepEqual(S.localeEvidenceTexts([{ domain: 'example.com', locales: [], source: 'evidence', evidence: EVIDENCE }]), [], 'a pack that did not load is not claimed');
  });

  test('SSL Targets says it too: its run header has the same banner, drawn when the wordlist stage starts and at the end', async () => {
    const scan = await source('views/scan.js');
    assert.match(scan, /import \{ LocaleEvidenceBanner \} from '\.\.\/ui\/locale-evidence\.js';/);
    assert.match(scan, /const localeBanner = LocaleEvidenceBanner\(run\);/);
    assert.match(scan, /zoneBanner, localeBanner\.el, stageList,/, 'under the zone banner, above the stage pills');
    assert.match(scan, /if \(payload\.stage === 'bruteforce'\) localeBanner\.render\(\);/, 'as soon as the wordlist stage starts');
    // At the end, and when a kept run is drawn again (another view and back, a language switch).
    assert.ok((scan.match(/localeBanner\.render\(\);/g) || []).length >= 3, 'stage, finish and replay');
    // Subdomains draws the same banner.
    assert.match(await source('ui/subdomains-run.js'), /const localeBanner = LocaleEvidenceBanner\(run\);/);
  });
});
