import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export function tokenDigest(key, id, secret) {
  return createHmac('sha256', key).update(`${id}.${secret}`).digest();
}

export function createToken(key) {
  const id = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  return { id, token: `${id}.${secret}`, digest: tokenDigest(key, id, secret) };
}

export function parseToken(token) {
  if (typeof token !== 'string' || !/^[\w-]{22}\.[\w-]{43}$/.test(token)) {
    return null;
  }
  const [id, secret] = token.split('.');
  // Reject alternative encodings of the same bytes.
  if (
    Buffer.from(id, 'base64url').toString('base64url') !== id ||
    // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret -- compares the parsed token part with its canonical base64url form; no literal secret.
    Buffer.from(secret, 'base64url').toString('base64url') !== secret
  )
    return null;
  return { id, secret };
}

export function verifyToken(key, token, expected) {
  const parsed = parseToken(token);
  const actual = tokenDigest(key, parsed?.id ?? '', parsed?.secret ?? '');
  const stored =
    Buffer.isBuffer(expected) && expected.length === 32
      ? expected
      : Buffer.alloc(32);
  const matches = timingSafeEqual(actual, stored);
  return Boolean(parsed && expected && matches);
}
