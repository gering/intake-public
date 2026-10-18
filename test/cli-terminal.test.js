import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeTerminal } from '../src/terminal.js';

test('terminal escaping renders every C0, DEL, C1 and specified Unicode control visibly', () => {
  const codes = [
    ...Array.from({ length: 32 }, (_, index) => index),
    ...Array.from({ length: 33 }, (_, index) => 0x7f + index),
    0x2028,
    0x2029,
    0x200e,
    0x200f,
    ...Array.from({ length: 5 }, (_, index) => 0x202a + index),
    ...Array.from({ length: 4 }, (_, index) => 0x2066 + index),
  ];
  for (const code of codes) {
    const hex = code.toString(16);
    assert.equal(
      escapeTerminal(String.fromCodePoint(code)),
      code < 256 ? `\\x${hex.padStart(2, '0')}` : `\\u{${hex}}`,
    );
  }
});

test('terminal escaping distinguishes literal backslashes from escaped terminal sequences', () => {
  assert.equal(escapeTerminal('\\x1b'), String.raw`\\x1b`);
  assert.equal(escapeTerminal('\x1b'), String.raw`\x1b`);
  assert.equal(
    escapeTerminal('\\\x1b[2J\r\n\t\x9b31m\u{202e}'),
    String.raw`\\\x1b[2J\x0d\x0a\x09\x9b31m\u{202e}`,
  );
});

test('terminal escaping converts values to strings and preserves ordinary Unicode', () => {
  for (const value of [0, 31, 1.5, -1, null, undefined, false, 22n])
    assert.equal(escapeTerminal(value), String(value));
  assert.equal(escapeTerminal('café 日本語'), 'café 日本語');
  assert.equal(escapeTerminal(''), '');
});
