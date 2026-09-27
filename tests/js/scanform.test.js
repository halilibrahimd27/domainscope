// Unit tests for the SSL Targets setup form model (assets/js/lib/scanform.js): step progress and
// the one requirement, the non-default options behind the collapsed Options summary, and the
// sticky run bar's "stuck" test. Pure: no DOM, no storage.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { FORM_STEPS, OPTION_CHANGE_IDS, formProgress, optionChanges, barStuck } from '../../assets/js/lib/scanform.js';

/** The sanitized defaults of views/scan.js (sanitizeOptions(null)), written out. */
const DEFAULTS = Object.freeze({
  sources: ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc'],
  knownSources: ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc'],
  includeExpired: false,
  bruteforce: 'smart',
  permutations: true,
  permutationBudget: 1500,
  originHints: true
});
const opts = (over = {}) => ({ ...DEFAULTS, ...over });
const ids = (list) => list.map((c) => c.id);

describe('formProgress — the requirement', () => {
  test('nothing entered: not ready, no step complete (the options always are)', () => {
    const p = formProgress();
    assert.equal(p.ready, false);
    assert.equal(p.via, null);
    assert.deepEqual(p.steps, { cert: false, domains: false, inventory: false, options: true });
  });

  test('typed domains meet it', () => {
    const p = formProgress({ domains: 2 });
    assert.deepEqual([p.ready, p.via, p.steps.domains], [true, 'domains', true]);
  });

  test('a certificate meets it through its names', () => {
    const p = formProgress({ cert: true, certNames: 3 });
    assert.deepEqual([p.ready, p.via, p.steps.cert, p.steps.domains], [true, 'cert', true, false]);
  });

  test('a loaded certificate without a name completes its step but gives the scan nothing', () => {
    const p = formProgress({ cert: true, certNames: 0 });
    assert.deepEqual([p.ready, p.via, p.steps.cert], [false, null, true]);
  });

  test('names without a loaded certificate do not count as one', () => {
    assert.equal(formProgress({ cert: false, certNames: 4 }).ready, false);
  });

  test('extra hostnames alone meet it (Start accepts them), and typed domains come first', () => {
    assert.deepEqual([formProgress({ extraNames: 1 }).ready, formProgress({ extraNames: 1 }).via], [true, 'extra']);
    assert.equal(formProgress({ domains: 1, cert: true, certNames: 2, extraNames: 1 }).via, 'domains');
    assert.equal(formProgress({ cert: true, certNames: 2, extraNames: 1 }).via, 'cert');
  });

  test('an invalid entry or a public suffix keeps the domains step open, not the requirement', () => {
    const typo = formProgress({ domains: 1, invalid: 1 });
    assert.deepEqual([typo.ready, typo.steps.domains], [true, false]);
    const suffix = formProgress({ domains: 1, publicSuffixes: 1 });
    assert.deepEqual([suffix.ready, suffix.steps.domains], [true, false]);
    // Only a public suffix: nothing to scan at all.
    assert.equal(formProgress({ publicSuffixes: 1 }).ready, false);
  });

  test('the inventory step completes with a saved server', () => {
    assert.equal(formProgress({ servers: 1 }).steps.inventory, true);
    assert.equal(formProgress({ servers: 0 }).steps.inventory, false);
  });

  test('odd counts (negative, NaN, strings) read as none', () => {
    const p = formProgress({ domains: -3, certNames: NaN, extraNames: 'x', servers: -1, invalid: NaN });
    assert.deepEqual([p.ready, p.steps.inventory], [false, false]);
    assert.equal(formProgress({ domains: 1, invalid: -2 }).steps.domains, true);
  });

  test('FORM_STEPS lists the steps in page order', () => {
    assert.deepEqual(FORM_STEPS, ['cert', 'domains', 'inventory', 'options']);
    assert.ok(Object.isFrozen(FORM_STEPS));
  });
});

describe('optionChanges — the collapsed Options summary', () => {
  test('the defaults change nothing', () => {
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { totalSources: 6 }), []);
  });

  test('the source set counts, not its order', () => {
    assert.deepEqual(optionChanges(opts({ sources: [...DEFAULTS.sources].reverse() }), DEFAULTS, { totalSources: 6 }), []);
    assert.deepEqual(optionChanges(opts({ sources: ['crtsh', 'anubis'] }), DEFAULTS, { totalSources: 6 }),
      [{ id: 'sources', count: 2, total: 6 }]);
    assert.deepEqual(optionChanges(opts({ sources: [] }), DEFAULTS, { totalSources: 6 }),
      [{ id: 'sources', count: 0, total: 6 }]);
  });

  test('the total never reads below the ticked count', () => {
    assert.deepEqual(optionChanges(opts({ sources: ['crtsh'] }), { ...DEFAULTS, sources: [] }),
      [{ id: 'sources', count: 1, total: 1 }]);
  });

  test('wordlist level, permutations, budget, expired certificates and origin hints', () => {
    const c = optionChanges(opts({ bruteforce: 'large', permutations: false, includeExpired: true, originHints: false }), DEFAULTS);
    assert.deepEqual(c, [
      { id: 'bruteforce', value: 'large' },
      { id: 'permutations', value: false },
      { id: 'includeExpired', value: true },
      { id: 'originHints', value: false }
    ]);
  });

  test('a budget counts only while permutations are on', () => {
    assert.deepEqual(optionChanges(opts({ permutationBudget: 5000 }), DEFAULTS), [{ id: 'permutationBudget', value: 5000 }]);
    assert.deepEqual(ids(optionChanges(opts({ permutations: false, permutationBudget: 5000 }), DEFAULTS)), ['permutations']);
  });

  test('a change back to a default a later release flips is still reported (compared, not hard-coded)', () => {
    const d = { ...DEFAULTS, includeExpired: true, originHints: false, permutations: false };
    assert.deepEqual(optionChanges(opts({ includeExpired: false, originHints: true, permutations: true }), d), [
      { id: 'permutations', value: true },
      { id: 'includeExpired', value: false },
      { id: 'originHints', value: true }
    ]);
  });

  test('extra hostnames are listed with their count', () => {
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { extraNames: 3 }), [{ id: 'extraNames', count: 3 }]);
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { extraNames: 0 }), []);
  });

  test('a manual language choice counts only for levels that add packs (Smart and up)', () => {
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { locales: ['tr', 'de', 'tr'] }), [{ id: 'languages', value: ['tr', 'de'] }]);
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { locales: [] }), [{ id: 'languages', value: [] }]);
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { locales: null }), [], 'automatic is the default');
    assert.deepEqual(ids(optionChanges(opts({ bruteforce: 'small' }), DEFAULTS, { locales: ['tr'] })), ['bruteforce']);
    assert.deepEqual(ids(optionChanges(opts({ bruteforce: 'off' }), DEFAULTS, { locales: ['tr'] })), ['bruteforce']);
  });

  test('custom and learned names count only while a wordlist level tries them', () => {
    assert.deepEqual(optionChanges(opts(), DEFAULTS, { custom: 12, learned: 40 }),
      [{ id: 'custom', count: 12 }, { id: 'learned', count: 40 }]);
    assert.deepEqual(ids(optionChanges(opts({ bruteforce: 'off' }), DEFAULTS, { custom: 12, learned: 40 })), ['bruteforce']);
  });

  test('entries follow OPTION_CHANGE_IDS order', () => {
    const c = optionChanges(
      opts({ sources: ['crtsh'], bruteforce: 'huge', permutationBudget: 500, includeExpired: true, originHints: false }),
      DEFAULTS, { totalSources: 6, extraNames: 2, locales: ['nl'], custom: 1, learned: 5 }
    );
    assert.deepEqual(ids(c), ['sources', 'bruteforce', 'languages', 'permutationBudget', 'includeExpired', 'originHints', 'extraNames', 'custom', 'learned']);
    const order = ids(c).map((id) => OPTION_CHANGE_IDS.indexOf(id));
    assert.deepEqual(order, [...order].sort((a, b) => a - b));
    assert.ok(ids(c).every((id) => OPTION_CHANGE_IDS.includes(id)));
  });

  test('missing inputs do not throw', () => {
    assert.deepEqual(optionChanges(null, null), []);
    assert.deepEqual(ids(optionChanges({ sources: 'crtsh' }, DEFAULTS)), ['sources', 'bruteforce', 'permutations', 'originHints']);
  });
});

describe('barStuck — the sticky run bar', () => {
  const vh = 800;

  test('floats while the form ends below the viewport', () => {
    assert.equal(barStuck({ sticky: true, top: -200, bottom: 1400, viewportHeight: vh }), true);
    assert.equal(barStuck({ sticky: true, top: 120, bottom: 801, viewportHeight: vh }), true);
  });

  test('rests in place once the form ends on screen or above it', () => {
    assert.equal(barStuck({ sticky: true, top: -900, bottom: 800, viewportHeight: vh }), false);
    assert.equal(barStuck({ sticky: true, top: -900, bottom: 800.4, viewportHeight: vh }), false, 'sub-pixel rounding');
    assert.equal(barStuck({ sticky: true, top: -1600, bottom: 300, viewportHeight: vh }), false);
    assert.equal(barStuck({ sticky: true, top: -2600, bottom: -300, viewportHeight: vh }), false);
  });

  test('a form still below the fold is not on screen, so nothing floats', () => {
    assert.equal(barStuck({ sticky: true, top: 900, bottom: 2400, viewportHeight: vh }), false);
  });

  test('never stuck where the bar is not sticky (wide screens)', () => {
    assert.equal(barStuck({ sticky: false, top: -200, bottom: 1400, viewportHeight: vh }), false);
    assert.equal(barStuck(), false);
  });
});
