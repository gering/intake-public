export function escapeTerminal(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(
      /[\p{Cc}\u{2028}\u{2029}\u{200e}\u{200f}\u{202a}-\u{202e}\u{2066}-\u{2069}]/gu,
      (character) => {
        const code = character.codePointAt(0);
        const hex = code.toString(16);
        return code < 256 ? `\\x${hex.padStart(2, '0')}` : `\\u{${hex}}`;
      },
    );
}
