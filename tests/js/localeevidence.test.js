// Unit tests for assets/js/lib/localeevidence.js — the adaptive locale packs: which market
// wordlist packs a domain whose TLD has no pack of its own gets, from the words of the names found, the
// letters of IDN labels and the countries of its name and mail servers. No network: the real
// packs are read from disk (lib/wordlist.js loadLocaleVocabulary), and small synthetic packs pin
// the scoring.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  localeEvidence, localeVocabulary, labelWords, unicodeLabel, foldLabel, labelLetters, hostLocales,
  NEUTRAL_WORDS, GLOBAL_HOST_DOMAINS, GENERIC_CCTLDS, SCRIPT_HINTS,
  LOCALE_EVIDENCE_MIN, LOCALE_EVIDENCE_RELATIVE, LOCALE_EVIDENCE_VOLUME, LOCALE_EVIDENCE_MAX_LETTERS, LOCALE_EVIDENCE_EXAMPLES
} from '../../assets/js/lib/localeevidence.js';
import {
  loadLocaleVocabulary, localesForDomain, loadWordlist, LOCALE_PACK_CODES, LOCALE_EVIDENCE_MAX_PACKS, WORDLIST_MEDIUM
} from '../../assets/js/lib/wordlist.js';
import { punycodeEncode } from '../../assets/js/lib/punycode.js';

const PACKS = await loadLocaleVocabulary();
const idn = (label) => `xn--${punycodeEncode(label)}`;
const under = (labels, apex = 'example.com') => labels.map((l) => `${l}.${apex}`);
const signalOf = (ev, cc) => ev.signals.find((s) => s.locale === cc);

describe('the vocabulary', () => {
  test('every pack loads from disk, in pack order', () => {
    assert.deepEqual(Object.keys(PACKS), [...LOCALE_PACK_CODES]);
    for (const cc of LOCALE_PACK_CODES) assert.ok(PACKS[cc].length > 50, cc);
  });

  test('NEUTRAL_WORDS: sorted, unique, every one a pack word that the global lists do not already have', () => {
    const all = new Set(Object.values(PACKS).flat());
    const medium = new Set(WORDLIST_MEDIUM);
    assert.deepEqual([...NEUTRAL_WORDS], [...new Set(NEUTRAL_WORDS)].sort(), 'sorted and unique');
    for (const w of NEUTRAL_WORDS) {
      assert.ok(all.has(w), `${w}: in no pack (dead entry)`);
      assert.ok(!medium.has(w), `${w}: already a global word`);
    }
  });

  test('distinctive words only: no global, neutral or short word; shared words list every pack', () => {
    const vocab = localeVocabulary(PACKS);
    for (const w of ['portal', 'support', 'shop', 'crm', 'intranet', 'hotel', 'campus', 'personal', 'menu', 'agenda', 'transport', 'mypage']) {
      assert.ok(!vocab.has(w), `${w} is no evidence`);
    }
    for (const w of ['ik', 'lk', 'sss', 'iva', 'tva', 'uye']) assert.ok(!vocab.has(w), `${w}: under four letters`);
    assert.deepEqual(vocab.get('destek'), ['tr']);
    assert.deepEqual(vocab.get('kunden'), ['de']);
    assert.deepEqual(vocab.get('cliente'), ['es', 'pt', 'it'], 'a shared word names every pack that has it, in pack order');
    assert.deepEqual(vocab.get('e-fatura'), ['tr'], 'a hyphenated pack word is kept whole');
    assert.equal(localeVocabulary(PACKS), vocab, 'cached per packs object');
    assert.equal(localeVocabulary(null).size, 0);
  });
});

describe('labels', () => {
  const vocab = localeVocabulary(PACKS);

  test('a label matches whole, by its letter runs or as a compound', () => {
    assert.deepEqual(labelWords('e-fatura', vocab), ['e-fatura'], 'whole, before its runs');
    assert.deepEqual(labelWords('musteri-portal2', vocab), ['musteri'], 'a letter run (the global word and the digit say nothing)');
    assert.deepEqual(labelWords('bayisiparis', vocab), ['bayi', 'siparis'], 'two pack words');
    assert.deepEqual(labelWords('destekapi', vocab), ['destek'], 'a pack word of five letters and a global word of three');
    assert.deepEqual(labelWords('apidestek', vocab), ['destek'], 'the other way round');
    assert.deepEqual(labelWords('lohnportal', vocab), ['lohn'], 'four letters next to a global word of four or more');
    assert.deepEqual(labelWords('kundenservice', vocab), ['kundenservice'], 'a pack word as it is');
  });

  test('English and global words, and their look-alike compounds, carry no market', () => {
    for (const label of ['www', 'api', 'terminal', 'motel', 'hotel', 'hotels', 'personal', 'support', 'helpdesk', 'staging-api', 'webmail', 'b2b', 'customer']) {
      assert.deepEqual(labelWords(label, vocab), [], label);
    }
    assert.deepEqual(labelWords('bayiweb', vocab), [], 'four letters next to a global word of three: too weak to split');
    assert.deepEqual(labelWords('destek', new Map()), [], 'no vocabulary, no words');
  });

  test('IDN labels: decoded, folded the way the packs are, and their letters read', () => {
    assert.equal(unicodeLabel(idn('şube')), 'şube');
    assert.equal(unicodeLabel('www'), 'www');
    assert.equal(unicodeLabel('xn--a!b'), null, 'not punycode');
    // Only letters, marks, digits and hyphens: a control or a bidi character is no label at all.
    assert.equal(unicodeLabel('xn--ube-rza8450b'), null, 'U+202E (a right-to-left override) + şube');
    assert.equal(unicodeLabel(idn('ığdır\u0085\u2066x')), null, 'a C1 control (U+0085) and a bidi isolate (U+2066)');
    assert.equal(unicodeLabel(idn('a\u200db')), null, 'a zero-width joiner');
    assert.deepEqual(foldLabel('şube'), ['sube']);
    assert.deepEqual(foldLabel('müşteri'), ['musteri', 'muesteri'], 'Turkish and German spellings of ü');
    assert.deepEqual(foldLabel('prüfung'), ['prufung', 'pruefung']);
    assert.deepEqual(foldLabel('straße'), ['strasse']);
    assert.deepEqual(foldLabel('магазин'), [], 'no ASCII form');
    const cases = [['şube', ['tr']], ['ığdır', ['tr']], ['i\u0307stanbul', ['tr']], ['straße', ['de']], ['bäckerei', ['de']], ['año', ['es']],
      ['ação', ['pt']], ['łódź', ['pl']], ['cœur', ['fr']], ['città', []], ['perché', []], ['così', ['it']], ['магазин', ['ru']],
      ['متجر', ['ar']], ['ショップ', ['ja']], ['日本語のサイト', ['ja']], ['商店', ['zh']], ['café', []], ['müller', []], ['shop', []]];
    for (const [text, want] of cases) assert.deepEqual(labelLetters(text), want, text);
    assert.ok(SCRIPT_HINTS.every(([cc]) => LOCALE_PACK_CODES.includes(cc)), 'every hint names a pack');
  });
});

describe('name and mail servers', () => {
  test('a host\'s ccTLD names its market; global providers and generic ccTLDs say nothing', () => {
    assert.deepEqual(hostLocales('mx.example.com.tr'), ['tr']);
    assert.deepEqual(hostLocales('ns1.example.de'), ['de']);
    assert.deepEqual(hostLocales('ns2.example.ch'), ['de', 'fr', 'it']);
    assert.deepEqual(hostLocales('NS1.EXAMPLE.COM.CO.'), ['es'], 'Colombian under com.co');
    assert.deepEqual(hostLocales('dns.example.co'), [], 'a bare .co is used worldwide');
    assert.deepEqual(hostLocales('ns1.example.com'), []);
    assert.deepEqual(hostLocales('mail.protonmail.ch'), [], 'Proton Mail serves every market from .ch');
    assert.deepEqual(hostLocales('helium.ns.hetzner.de'), []);
    assert.deepEqual(hostLocales('ns1.your-server.de'), [], 'Hetzner\'s webhosting name servers');
    assert.deepEqual(hostLocales('mail.your-server.de'), [], '… and its mail hosts');
    assert.deepEqual(hostLocales('ns1045.ui-dns.de'), []);
    assert.deepEqual(hostLocales(''), []);
    assert.deepEqual(hostLocales('not a host'), []);
    assert.ok(GLOBAL_HOST_DOMAINS.includes('tutanota.de'));
    assert.deepEqual([...GENERIC_CCTLDS], ['co', 'ly']);
  });
});

describe('localeEvidence', () => {
  test('Turkish words in the names found pick the Turkish pack, with the words that did', () => {
    const ev = localeEvidence({ domain: 'example.com', names: under(['www', 'api', 'destek', 'bayi', 'kampanya', 'cdn']), packs: PACKS });
    assert.deepEqual(ev.locales, ['tr']);
    const tr = signalOf(ev, 'tr');
    assert.equal(tr.picked, true);
    assert.deepEqual(tr.words, ['bayi', 'destek', 'kampanya'], 'distinct words, in the order of the sorted names');
    assert.equal(tr.wordCount, 3);
    assert.deepEqual(tr.points, { words: 2.5, letters: 0, ns: 0, mx: 0 }, 'bayi has four letters: ½');
    assert.equal(tr.score, 2.5);
    assert.equal(ev.domain, 'example.com');
    assert.equal(ev.names, 7, 'the domain itself and the six names');
    assert.equal(ev.labels, 7, 'example + six labels');
  });

  test('one word is not enough; each distinct word counts once however many names carry it', () => {
    const one = localeEvidence({ domain: 'example.com', names: under(['destek', 'destek2', 'destek-test', 'www']), packs: PACKS });
    assert.deepEqual(one.locales, [], 'destek once: 1 point');
    assert.equal(signalOf(one, 'tr').score, 1);
    const repeated = localeEvidence({ domain: 'example.com', names: under(Array.from({ length: 30 }, (_, i) => `bayi${i + 1}`)), packs: PACKS });
    assert.equal(signalOf(repeated, 'tr').points.words, 0.5, 'bayi1 … bayi30: one word');
    assert.deepEqual(repeated.locales, []);
  });

  test('an English zone picks nothing', () => {
    const ev = localeEvidence({
      domain: 'example.com',
      names: under(['www', 'mail', 'shop', 'support', 'portal', 'hotel', 'campus', 'planning', 'agenda', 'transport', 'documents', 'terminal', 'personal', 'jobs']),
      ns: ['ns1.example.net', 'ns2.example.net'],
      mx: ['mx.example.org'],
      packs: PACKS
    });
    assert.deepEqual(ev.locales, []);
    assert.deepEqual(ev.signals, []);
  });

  test('shared words are split between their packs, so the language the rest points to wins', () => {
    const ev = localeEvidence({ domain: 'example.com', names: under(['tienda', 'pedidos', 'clientes', 'soporte', 'facturacion']), packs: PACKS });
    assert.deepEqual(ev.locales, ['es']);
    assert.equal(signalOf(ev, 'es').score, 4);
    assert.equal(signalOf(ev, 'pt').score, 1, 'pedidos ½ + clientes ½');
    assert.equal(signalOf(ev, 'pt').picked, false);
  });

  test('mail servers alone: all of them in one market are enough', () => {
    const ev = localeEvidence({ domain: 'example.com', mx: ['mx1.example.com.tr', 'mx2.example.com.tr'], packs: PACKS });
    assert.deepEqual(ev.locales, ['tr']);
    assert.deepEqual(signalOf(ev, 'tr').mx, ['.com.tr']);
    assert.deepEqual(signalOf(ev, 'tr').points, { words: 0, letters: 0, ns: 0, mx: 2 });
    assert.equal(ev.mx, 1, 'one registrable domain');
  });

  test('name servers: half or more in a market give 2, fewer give 1 — which a word can complete', () => {
    const half = localeEvidence({ domain: 'example.com', ns: ['ns1.example.de', 'ns2.example.net'], packs: PACKS });
    assert.deepEqual(half.locales, ['de'], '1 of 2');
    assert.equal(signalOf(half, 'de').points.ns, 2);
    const some = localeEvidence({ domain: 'example.com', ns: ['ns1.example.de', 'ns.example.net', 'ns.example.org'], packs: PACKS });
    assert.deepEqual(some.locales, [], '1 of 3: 1 point');
    assert.equal(signalOf(some, 'de').points.ns, 1);
    const withWord = localeEvidence({ domain: 'example.com', names: under(['kunden']), ns: ['ns1.example.de', 'ns.example.net', 'ns.example.org'], packs: PACKS });
    assert.deepEqual(withWord.locales, ['de'], '1 + kunden');
    assert.deepEqual(signalOf(withWord, 'de').ns, ['.de']);
  });

  test('providers that serve every market say nothing', () => {
    const ev = localeEvidence({
      domain: 'example.com',
      ns: ['hydrogen.ns.hetzner.com', 'oxygen.ns.hetzner.com', 'helium.ns.hetzner.de'],
      mx: ['mail.protonmail.ch', 'mailsec.protonmail.ch'],
      packs: PACKS
    });
    assert.deepEqual(ev.locales, []);
    assert.deepEqual(ev.signals, []);
    // Hetzner's webhosting set: your-server.de's own name servers, second-ns.com / .de, its mail hosts.
    const webhosting = localeEvidence({
      domain: 'example.com',
      ns: ['ns1.your-server.de', 'ns.second-ns.com', 'ns3.second-ns.de'],
      mx: ['mail.your-server.de'],
      packs: PACKS
    });
    assert.deepEqual(webhosting.locales, []);
    assert.deepEqual(webhosting.signals, []);
  });

  test('IDN labels: their letters, else their folded words — one label is one piece of evidence', () => {
    const ev = localeEvidence({ domain: 'example.com', names: under([idn('şube'), idn('müşteri'), 'www']), packs: PACKS });
    assert.deepEqual(ev.locales, ['tr'], 'two Turkish labels pick Turkish');
    const tr = signalOf(ev, 'tr');
    assert.deepEqual(tr.letters, ['müşteri', 'şube'], 'in the order of the sorted names');
    assert.deepEqual(tr.points, { words: 0, letters: 2, ns: 0, mx: 0 }, 'their folded forms (musteri, sube) add nothing more');
    assert.deepEqual(tr.words, []);
    // One name is never enough, however it reads: a pack word in Turkish letters is one point.
    const one = localeEvidence({ domain: 'example.com', names: under([idn('müşteri')]), packs: PACKS });
    assert.deepEqual(one.locales, []);
    assert.deepEqual(signalOf(one, 'tr').points, { words: 0, letters: 1, ns: 0, mx: 0 });
    // Letters several languages share (ü, ö) point nowhere: the folded forms are read as words.
    const de = localeEvidence({ domain: 'example.com', names: under([idn('prüfung'), idn('behörde')]), packs: PACKS });
    assert.deepEqual(de.locales, ['de']);
    assert.deepEqual(signalOf(de, 'de').points, { words: 2, letters: 0, ns: 0, mx: 0 });
    assert.deepEqual(signalOf(de, 'de').words, ['behoerde', 'pruefung']);
    const cyr = localeEvidence({ domain: 'example.net', names: under(['магазин', 'заказ', 'корзина', 'поддержка'].map(idn), 'example.net'), packs: PACKS });
    assert.deepEqual(cyr.locales, ['ru']);
    assert.equal(signalOf(cyr, 'ru').points.letters, LOCALE_EVIDENCE_MAX_LETTERS, 'at most 2 from letters');
  });

  test('an IDN label with a control or bidi character is never evidence, nor named in the explanation', () => {
    // From a passive source: U+202E + şube, and ığdır + U+0085 + U+2066 + x. Each would point to
    // Turkish and, shown as it is, reverse the rest of the run's sentence.
    const planted = ['xn--ube-rza8450b', 'xn--drx-wa18ecdc8205d'];
    const ev = localeEvidence({ domain: 'example.com', names: under([...planted, 'www']), packs: PACKS });
    assert.deepEqual(ev.locales, []);
    assert.deepEqual(ev.signals, []);
    const mixed = localeEvidence({ domain: 'example.com', names: under([...planted, idn('şube')]), packs: PACKS });
    assert.deepEqual(signalOf(mixed, 'tr').letters, ['şube'], 'only the clean label is named');
    assert.equal(signalOf(mixed, 'tr').score, 1);
    assert.deepEqual(mixed.locales, []);
  });

  test('the relative bar: a pack well behind the strongest is left out', () => {
    const ev = localeEvidence({
      domain: 'example.com',
      names: under(['destek', 'kampanya', 'siparis', 'musteri', 'kargo', 'magaza']),
      mx: ['mx.example.de'],
      packs: PACKS
    });
    assert.equal(signalOf(ev, 'tr').score, 6);
    assert.equal(signalOf(ev, 'de').score, 2, 'its mail servers alone');
    assert.ok(signalOf(ev, 'de').score < signalOf(ev, 'tr').score * LOCALE_EVIDENCE_RELATIVE);
    assert.deepEqual(ev.locales, ['tr']);
  });

  test('a bilingual zone gets both packs, strongest first, and never more than three', () => {
    const two = localeEvidence({ domain: 'example.com', names: under(['kundenportal', 'rechnung', 'karriere', 'facture', 'commande', 'livraison', 'panier']), packs: PACKS });
    assert.deepEqual(two.locales, ['fr', 'de']);
    const synthetic = { tr: ['aaaaa', 'bbbbb'], de: ['ccccc', 'ddddd'], fr: ['eeeee', 'fffff'], es: ['ggggg', 'hhhhh'] };
    const many = localeEvidence({ domain: 'example.com', names: under(['aaaaa', 'bbbbb', 'ccccc', 'ddddd', 'eeeee', 'fffff', 'ggggg', 'hhhhh']), packs: synthetic });
    assert.equal(LOCALE_EVIDENCE_MAX_PACKS, 3);
    assert.deepEqual(many.locales, ['tr', 'de', 'fr'], 'equal scores in pack order, cut at three');
    assert.equal(many.signals.length, 4, 'the fourth is still reported');
    assert.equal(signalOf(many, 'es').picked, false);
  });

  test('a large zone: chance matches are scaled down by the number of labels read', () => {
    const noise = Array.from({ length: 1600 }, (_, i) => `host${i}`);
    const ev = localeEvidence({ domain: 'example.com', names: under([...noise, 'destek', 'kampanya', 'siparis']), packs: PACKS });
    assert.ok(ev.labels > LOCALE_EVIDENCE_VOLUME);
    const tr = signalOf(ev, 'tr');
    assert.equal(tr.points.words, Math.round(3 * (LOCALE_EVIDENCE_VOLUME / ev.labels) * 100) / 100);
    assert.deepEqual(ev.locales, []);
    // … while the servers still count in full.
    const withMx = localeEvidence({ domain: 'example.com', names: under([...noise, 'destek']), mx: ['mx.example.com.tr'], packs: PACKS });
    assert.deepEqual(withMx.locales, ['tr']);
  });

  test('names outside the domain are ignored; the domain\'s own labels are read', () => {
    const ev = localeEvidence({ domain: 'destek.example.com', names: ['kampanya.destek.example.com', 'bayi.example.org', 'siparis.example.net'], packs: PACKS });
    assert.deepEqual(signalOf(ev, 'tr').words, ['destek', 'kampanya'], 'destek from the domain, kampanya under it; the others are elsewhere');
    assert.equal(ev.names, 2);
    assert.deepEqual(ev.locales, ['tr']);
  });

  test('examples are capped; the count is not', () => {
    const words = ['destek', 'kampanya', 'siparis', 'musteri', 'kargo', 'magaza', 'kariyer', 'fatura', 'iletisim', 'randevu'];
    const tr = signalOf(localeEvidence({ domain: 'example.com', names: under(words), packs: PACKS }), 'tr');
    assert.equal(tr.words.length, LOCALE_EVIDENCE_EXAMPLES);
    assert.equal(tr.wordCount, words.length);
  });

  test('without packs the words say nothing, the servers and letters still do', () => {
    const ev = localeEvidence({ domain: 'example.com', names: under(['destek', 'kampanya', idn('şube')]), mx: ['mx.example.com.tr'] });
    const tr = signalOf(ev, 'tr');
    assert.deepEqual(tr.points, { words: 0, letters: 1, ns: 0, mx: 2 });
    assert.deepEqual(ev.locales, ['tr']);
  });

  test('robust input: nothing to read gives an empty result', () => {
    for (const input of [undefined, {}, { domain: '' }, { domain: 'example.com', names: 'nope', ns: null, mx: [42, null, ''] }]) {
      const ev = localeEvidence(input);
      assert.deepEqual(ev.locales, []);
      assert.deepEqual(ev.signals, []);
    }
    assert.equal(LOCALE_EVIDENCE_MIN, 2);
  });
});

describe('wired into lib/wordlist.js', () => {
  test('localesForDomain: the TLD wins; a TLD without packs takes the evidence (known codes, at most three)', () => {
    const ev = { locales: ['tr'] };
    assert.deepEqual(localesForDomain('example.com', ev), ['tr']);
    assert.deepEqual(localesForDomain('example.de', ev), ['de'], 'the TLD wins');
    assert.deepEqual(localesForDomain('example.com', { locales: ['xx', 'de', 'de', 'fr', 'it', 'es'] }), ['de', 'fr', 'it'], 'unknown and repeated codes dropped, cut at three');
    assert.deepEqual(localesForDomain('example.com', null), []);
    assert.deepEqual(localesForDomain('example.com', { locales: 'tr' }), [], 'not a list');
    assert.deepEqual(localesForDomain('', ev), ['tr'], 'no domain: the evidence alone');
    const real = localeEvidence({ domain: 'example.com', names: under(['destek', 'kampanya']), packs: PACKS });
    assert.deepEqual(localesForDomain('example.com', real), ['tr']);
  });

  test('loadWordlist adds the packs the evidence picked; explicit locales still win', async () => {
    const plain = await loadWordlist('smart', { domain: 'example.com' });
    assert.ok(!plain.includes('yonetimpanel'), 'precondition: a tr-only label');
    const withTr = await loadWordlist('smart', { domain: 'example.com', evidence: { locales: ['tr'] } });
    assert.ok(withTr.includes('yonetimpanel'));
    const none = await loadWordlist('smart', { domain: 'example.com', evidence: { locales: ['tr'] }, locales: [] });
    assert.ok(!none.includes('yonetimpanel'), 'locales: [] disables');
    const small = await loadWordlist('small', { domain: 'example.com', evidence: { locales: ['tr'] } });
    assert.ok(!small.includes('yonetimpanel'), 'small stays language-neutral');
  });

  test('loadLocaleVocabulary: a pack that cannot load is left out and said; an abort propagates', async () => {
    const seen = [];
    const fetchImpl = async (url) => (String(url).endsWith('/locale/de.txt') ? new Response('', { status: 404 }) : new Response('alpha\nbeta\n'));
    // A fresh `codes` list keeps this off the disk cache of the packs read above: only de and ja, over fetch.
    const { clearWordlistCache } = await import('../../assets/js/lib/wordlist.js');
    clearWordlistCache();
    const out = await loadLocaleVocabulary({ codes: ['ja', 'de', 'xx'], preferFetch: true, fetchImpl, onInfo: (i) => seen.push(i) });
    assert.deepEqual(Object.keys(out), ['ja']);
    assert.deepEqual(out.ja, ['alpha', 'beta']);
    assert.deepEqual(seen, [{ type: 'locale-missing', locale: 'de' }]);
    clearWordlistCache();
    const ctl = new AbortController();
    ctl.abort();
    const abortFetch = async (url, init) => {
      if (init && init.signal && init.signal.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      return new Response('x\n');
    };
    await assert.rejects(loadLocaleVocabulary({ codes: ['tr'], preferFetch: true, fetchImpl: abortFetch, signal: ctl.signal }), { name: 'AbortError' });
    clearWordlistCache();
  });
});
