/**
 * views/scan.js glue for the setup form: the collapsed Options step's summary. The view's own
 * defaults (sanitizeOptions(null)) must read as "recommended defaults" through
 * lib/scanform.optionChanges, and every change it can report must have text in English and
 * Turkish. Pure Node (the view is DOM-free at import time).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeOptions, optionChangeText, BRUTEFORCE_MODES } from '../../assets/js/views/scan.js';
import { optionChanges, OPTION_CHANGE_IDS } from '../../assets/js/lib/scanform.js';
import { SOURCES } from '../../assets/js/lib/sources.js';
import { setLang, getLang, getMissingKeys, clearMissingKeys } from '../../assets/js/i18n.js';

/** Every change optionChanges can produce, one per id (and both values of each switch). */
const SAMPLES = [
  { id: 'sources', count: 2, total: 6 },
  { id: 'sources', count: 0, total: 6 },
  ...BRUTEFORCE_MODES.map((value) => ({ id: 'bruteforce', value })),
  { id: 'languages', value: ['tr', 'de'] },
  { id: 'languages', value: [] },
  { id: 'permutations', value: false },
  { id: 'permutations', value: true },
  { id: 'permutationBudget', value: 5000 },
  { id: 'includeExpired', value: true },
  { id: 'includeExpired', value: false },
  { id: 'originHints', value: false },
  { id: 'originHints', value: true },
  { id: 'extraNames', count: 3 },
  { id: 'custom', count: 12 },
  { id: 'learned', count: 1 }
];

function inLang(lang, fn) {
  const prev = getLang();
  setLang(lang);
  try {
    return fn();
  } finally {
    setLang(prev);
  }
}

describe('SSL Targets › Options summary', () => {
  test('the view defaults are "no change"', () => {
    const d = sanitizeOptions(null);
    assert.deepEqual(optionChanges(d, sanitizeOptions(null), { totalSources: SOURCES.length }), []);
    // A saved selection that equals the defaults stays quiet as well.
    assert.deepEqual(optionChanges(sanitizeOptions({ ...d }), d, { totalSources: SOURCES.length }), []);
  });

  test('a stored change shows up as the matching entries', () => {
    const d = sanitizeOptions(null);
    const saved = sanitizeOptions({ sources: ['crtsh', 'anubis'], knownSources: SOURCES.map((s) => s.id), bruteforce: 'small', permutations: false });
    const changes = optionChanges(saved, d, { totalSources: SOURCES.length });
    assert.deepEqual(changes.map((c) => c.id), ['sources', 'bruteforce', 'permutations']);
    const en = inLang('en', () => changes.map(optionChangeText).join(' · '));
    assert.equal(en, `2 of ${SOURCES.length} sources · small wordlist · no permutations`);
    const tr = inLang('tr', () => changes.map(optionChangeText).join(' · '));
    assert.equal(tr, `2/${SOURCES.length} kaynak · küçük kelime listesi · varyasyon yok`);
  });

  test('every change has text in English and Turkish, with its numbers', () => {
    assert.deepEqual([...new Set(SAMPLES.map((s) => s.id))].sort(), [...OPTION_CHANGE_IDS].sort(), 'every id sampled');
    clearMissingKeys();
    for (const lang of ['en', 'tr']) {
      inLang(lang, () => {
        for (const s of SAMPLES) {
          const text = optionChangeText(s);
          assert.ok(text && !/undefined|null|\{/.test(text), `${lang} ${JSON.stringify(s)}: ${text}`);
          if (s.count) assert.ok(text.includes(String(s.count)), `${lang} ${s.id} shows its count: ${text}`);
        }
        assert.match(optionChangeText({ id: 'permutationBudget', value: 5000 }), /5[.,]000/);
        assert.match(optionChangeText({ id: 'languages', value: ['tr'] }), /^\+/);
      });
    }
    assert.deepEqual(getMissingKeys(), []);
  });

  test('an unknown change reads as nothing', () => {
    assert.equal(optionChangeText({ id: 'nope' }), '');
    assert.equal(optionChangeText(null), '');
  });
});
