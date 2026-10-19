export function escapeTerminal(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/[\p{Cc}\p{Bidi_Control}\u{2028}\u{2029}]/gu, (character) => {
      const code = character.codePointAt(0);
      const hex = code.toString(16);
      return code < 256 ? `\\x${hex.padStart(2, '0')}` : `\\u{${hex}}`;
    });
}
