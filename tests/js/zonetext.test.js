// Unit tests for assets/js/lib/zonetext.js — the text helpers the zone file formats share (a Route 53
// character-string, a YAML scalar octoDNS reads back, octoDNS's TXT form and key order). No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { yamlString, route53String, charStringBytes, joinBytes, utf8Text, split255, octodnsTxtValue } from '../../assets/js/lib/zonetext.js';
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

describe('TXT character-strings as bytes', () => {
  const hex = (list) => list.map((b) => Buffer.from(b).toString('hex'));

  test('charStringBytes reads a presentation text: quoted strings, escaped bytes and characters, raw UTF-8, unquoted words', () => {
    assert.deepEqual(hex(charStringBytes(`"a${BS}195" "${BS}188b"`)), ['61c3', 'bc62'], 'a character split across two strings stays two bytes apart');
    assert.deepEqual(hex(charStringBytes(`"${BS}255x"`)), ['ff78'], 'a byte that is not UTF-8');
    assert.deepEqual(hex(charStringBytes(`"${ch(0xfc)}"`)), ['c3bc'], 'raw UTF-8');
    assert.deepEqual(hex(charStringBytes(`"a${BS}"b" "${BS}${BS}"`)), ['612262', '5c']);
    assert.deepEqual(hex(charStringBytes('abc "d e"')), ['616263', '642065']);
    assert.deepEqual(hex(charStringBytes('""')), ['']);
    assert.deepEqual(hex(charStringBytes(`"${ch(0x1f600)}"`)), ['f09f9880']);
  });

  test('joinBytes, utf8Text (null when the bytes are not UTF-8) and split255', () => {
    const joined = joinBytes(charStringBytes(`"a${BS}195" "${BS}188b"`));
    assert.equal(utf8Text(joined), `a${ch(0xfc)}b`, 'joined first, then decoded');
    assert.equal(utf8Text(Uint8Array.from([0xff, 0x78])), null);
    assert.deepEqual(split255(new Uint8Array(600)).map((b) => b.length), [255, 255, 90]);
    assert.deepEqual(split255(new Uint8Array(0)).map((b) => b.length), [0]);
  });

  test('route53String takes bytes too: every byte outside printable ASCII as its octal escape', () => {
    assert.equal(route53String(Uint8Array.from([0x61, 0xc3])), `"a${BS}303"`);
    assert.equal(route53String(Uint8Array.from([0xff, 0x22, 0x5c])), `"${BS}377${BS}"${BS}${BS}"`);
    assert.equal(route53String(`k${ch(0xe4)}se`), `"k${BS}303${BS}244se"`, 'a string as its UTF-8 bytes');
  });

  test('utf8Text keeps a leading byte order mark: it is part of the text', () => {
    assert.equal(utf8Text(Uint8Array.of(0xef, 0xbb, 0xbf, 0x61)), `${ch(0xfeff)}a`);
  });

  test('octodnsTxtValue: in one more pair of quotes when it starts with one (octoDNS strips them), null with " " inside', () => {
    const cases = [['"q"', '""q""'], ['a" "b', null], ['x;y', `x${BS};y`], ['"', '"""'], ['x"', 'x"'], [['"a', 'b"'], '""ab""']];
    for (const [input, want] of cases) assert.equal(octodnsTxtValue(input), want, JSON.stringify(input));
  });
});
