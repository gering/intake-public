import { isAbsolute } from 'node:path';

export function isUnixSocketPath(value) {
  // Stay within the smaller documented Unix pathname limit, including UTF-8.
  return (
    typeof value === 'string' &&
    isAbsolute(value) &&
    !value.includes('\0') &&
    Buffer.byteLength(value, 'utf8') <= 103
  );
}
