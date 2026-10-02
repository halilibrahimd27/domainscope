// Unit tests for assets/js/lib/zonetext.js — the text helpers the zone file formats share (a Route 53
// character-string, a YAML scalar octoDNS reads back, octoDNS's TXT form and key order). No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { yamlString } from '../../assets/js/lib/zonetext.js';
import { parseYamlSubset } from '../../assets/js/lib/zoneparse.js';

const ch = (...cps) => String.fromCodePoint(...cps);
const BS = '\\';

describe('yamlString', () => {
  test('anything outside printable ASCII is double-quoted and escaped: PyYAML refuses C1 controls, U+FFFE and U+FFFF raw, folds NEL', () => {
    const cases = [
      [`a${ch(0x85)}b`, `"a${BS}x85b"`], [`a${ch(0x80)}b`, `"a${BS}x80b"`], [`a${ch(0x9f)}b`, `"a${BS}x9fb"`],
      [`a${ch(0xfffe)}b`, `"a${BS}ufffeb"`], [`a${ch(0xffff)}b`, `"a${BS}uffffb"`], [`${ch(0xfeff)}bom`, `"${BS}ufeffbom"`],
      [`a${ch(0x2028)}b`, `"a${BS}u2028b"`], [`a${ch(0x2029)}b`, `"a${BS}u2029b"`], [ch(0xfc), `"${BS}xfc"`],
      [`sur${ch(0x1f600)}rogate`, `"sur${BS}U0001f600rogate"`], [`tab${ch(9)}x`, `"tab${BS}x09x"`], [`del${ch(0x7f)}x`, `"del${BS}x7fx"`],
      [`q"${BS}${ch(0xe9)}`, `"q${BS}"${BS}${BS}${BS}xe9"`]
    ];
    for (const [input, want] of cases) assert.equal(yamlString(input), want, JSON.stringify(input));
  });

  test('what it writes is ASCII only (octoDNS reads a file in the system code page on Windows) and reads back as written', () => {
    const samples = [`a${ch(0x85)}b`, `${ch(0xfffe)}${ch(0xffff)}`, `${ch(0xfeff)}x`, ch(0xfc), `x${ch(0x1f600)}y`, "it's", 'plain', `q"${BS}`, '',
      `${ch(0)}nul`, `crlf${ch(13)}${ch(10)}`, '- item', '#x', `y ${ch(0xe9)} z`];
    for (const s of samples) {
      const y = yamlString(s);
      assert.match(y, /^[\x20-\x7e]*$/, `${JSON.stringify(s)} → ${y}`);
      assert.equal(parseYamlSubset(`k: ${y}\n`).value.k, s === '' ? '' : s, `${JSON.stringify(s)} → ${y}`);
    }
  });

  test('printable ASCII keeps the quoting it had', () => {
    assert.equal(yamlString('mail.example.com.'), 'mail.example.com.');
    assert.equal(yamlString("it's"), "'it''s'");
    assert.equal(yamlString('a"b'), `'a"b'`);
    assert.equal(yamlString(`a${BS}b`), `'a${BS}b'`);
  });
});
