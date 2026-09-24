/**
 * app.js settings dialog: the honest per-resolver caveats (Quad9 not readable from browsers,
 * Control D unreachable from some networks) exist in both languages and never mark a
 * resolver of the default chain. No DOM, no network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { resolverNoteKey } from '../../assets/js/app.js';
import { hasString, t, setLang } from '../../assets/js/i18n.js';
import { RESOLVERS, DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';

test('Quad9 entries get the HTTP/3-without-CORS note, Control D the reachability note', () => {
  assert.equal(resolverNoteKey(getResolver('quad9')), 'settings.note.h3NoCors');
  assert.equal(resolverNoteKey(getResolver('quad9-ecs')), 'settings.note.h3NoCors');
  assert.equal(resolverNoteKey(getResolver('controld')), 'settings.note.unreachable');
});

test('every resolver flagged unreliable in browsers has a note; the default chain has none', () => {
  for (const r of RESOLVERS) {
    if (r.browserReliable === false) assert.ok(resolverNoteKey(r), r.id);
  }
  for (const id of DEFAULT_CHAIN) assert.equal(resolverNoteKey(getResolver(id)), null, id);
  assert.equal(resolverNoteKey(null), null);
  assert.equal(resolverNoteKey({ id: 'x', browserReliable: false, issue: null }), 'settings.unreliable', 'generic fallback');
});

test('note and badge strings exist in English and Turkish and differ', () => {
  const keys = [...new Set(RESOLVERS.map(resolverNoteKey).filter(Boolean)), 'settings.flagBrowser', 'settings.flagReach'];
  for (const key of keys) {
    assert.ok(hasString(key, 'en') && hasString(key, 'tr'), key);
    setLang('en');
    const en = t(key);
    setLang('tr');
    const tr = t(key);
    assert.notEqual(en, tr, key);
  }
  setLang('en');
  assert.match(t('settings.note.h3NoCors'), /HTTP\/3/);
  assert.match(t('settings.note.h3NoCors'), /CORS/);
  assert.match(t('settings.note.unreachable'), /timed out/);
});
