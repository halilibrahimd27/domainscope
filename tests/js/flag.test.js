/**
 * ui/flag.js — flag emoji support detection (canvas probe, stubbed here) and the
 * emoji / ISO-code / globe choice. No DOM, no network.
 */
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  hasColorPixels, supportsFlagEmoji, setFlagEmojiSupport, flagContent, GLOBE
} from '../../assets/js/ui/flag.js';
import { flagEmoji } from '../../assets/js/lib/resolvers.js';

/** RGBA buffer of `n` pixels, all set to `px`. */
const pixels = (n, px) => {
  const out = new Uint8ClampedArray(n * 4);
  for (let i = 0; i < n; i += 1) out.set(px, i * 4);
  return out;
};

/** A document whose canvas "draws" the given RGBA data, recording what was asked of it. */
function fakeDoc(data, log = []) {
  return {
    createElement(tag) {
      log.push(`create:${tag}`);
      return {
        width: 0,
        height: 0,
        getContext(kind) {
          log.push(`ctx:${kind}`);
          return {
            fillText(text) { log.push(`fill:${text}`); },
            getImageData(x, y, w, h) {
              log.push(`read:${w}x${h}`);
              return { data };
            }
          };
        }
      };
    }
  };
}

describe('hasColorPixels', () => {
  test('clearly red pixels count as colour; black, grey and transparent do not', () => {
    assert.equal(hasColorPixels(pixels(16, [218, 41, 28, 255])), true, 'Swiss red');
    assert.equal(hasColorPixels(pixels(64, [0, 0, 0, 255])), false, 'black letters');
    assert.equal(hasColorPixels(pixels(64, [128, 128, 128, 200])), false, 'grey anti-aliasing');
    assert.equal(hasColorPixels(pixels(64, [255, 0, 0, 0])), false, 'fully transparent');
    assert.equal(hasColorPixels(pixels(64, [0, 0, 255, 255])), false, 'blue is not the probe colour');
  });

  test('a few stray pixels are not enough (minPixels)', () => {
    const data = pixels(64, [0, 0, 0, 255]);
    data.set([230, 30, 30, 255], 0);
    data.set([230, 30, 30, 255], 4);
    assert.equal(hasColorPixels(data), false);
    assert.equal(hasColorPixels(data, { minPixels: 2 }), true);
  });

  test('junk input is false', () => {
    for (const bad of [null, undefined, 42, {}, []]) assert.equal(hasColorPixels(bad), false);
  });
});

describe('supportsFlagEmoji', () => {
  beforeEach(() => setFlagEmojiSupport(null));

  test('colour in the probe → supported; measured once and cached', () => {
    const log = [];
    assert.equal(supportsFlagEmoji({ doc: fakeDoc(pixels(32 * 32, [218, 41, 28, 255]), log) }), true);
    assert.deepEqual(log.slice(0, 2), ['create:canvas', 'ctx:2d']);
    assert.ok(log.includes('fill:\u{1F1E8}\u{1F1ED}'), 'draws the Swiss flag');
    assert.ok(log.includes('read:32x32'));
    const again = [];
    assert.equal(supportsFlagEmoji({ doc: fakeDoc(pixels(4, [0, 0, 0, 255]), again) }), true, 'cached');
    assert.deepEqual(again, [], 'no second probe');
  });

  test('monochrome letters (Windows Chrome/Edge) → not supported', () => {
    assert.equal(supportsFlagEmoji({ doc: fakeDoc(pixels(32 * 32, [0, 0, 0, 255])) }), false);
  });

  test('no DOM, no 2D context or a throwing canvas → not supported', () => {
    assert.equal(supportsFlagEmoji({ doc: null }), false);
    setFlagEmojiSupport(null);
    assert.equal(supportsFlagEmoji({ doc: { createElement: () => ({ getContext: () => null }) } }), false);
    setFlagEmojiSupport(null);
    assert.equal(supportsFlagEmoji({ doc: { createElement: () => { throw new Error('blocked'); } } }), false);
    setFlagEmojiSupport(null);
    assert.equal(supportsFlagEmoji(), false, 'Node has no document');
  });

  test('setFlagEmojiSupport overrides the probe', () => {
    setFlagEmojiSupport(true);
    assert.equal(supportsFlagEmoji({ doc: null }), true);
    setFlagEmojiSupport(false);
    assert.equal(supportsFlagEmoji({ doc: fakeDoc(pixels(32 * 32, [218, 41, 28, 255])) }), false);
  });
});

describe('flagContent', () => {
  test('emoji where supported, the ISO code otherwise (upper-cased)', () => {
    assert.deepEqual(flagContent('jp', true), { mode: 'emoji', text: flagEmoji('JP'), cc: 'JP' });
    assert.deepEqual(flagContent('jp', false), { mode: 'code', text: 'JP', cc: 'JP' });
    assert.deepEqual(flagContent('BR', false), { mode: 'code', text: 'BR', cc: 'BR' });
  });

  test('no country (anycast, junk) → globe in both modes', () => {
    for (const bad of [null, undefined, '', 'X', 'USA', '12', 42]) {
      assert.deepEqual(flagContent(bad, true), { mode: 'globe', text: GLOBE, cc: null }, String(bad));
      assert.deepEqual(flagContent(bad, false), { mode: 'globe', text: GLOBE, cc: null }, String(bad));
    }
    assert.equal(GLOBE, flagEmoji(null));
  });
});
