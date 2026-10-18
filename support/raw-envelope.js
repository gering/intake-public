import {
  constants,
  createCipheriv,
  createPublicKey,
  publicEncrypt,
  randomBytes,
} from 'node:crypto';
import { aadBytes } from '../public/crypto.js';

// Authenticate deliberately unprepared plaintext to exercise writer validation.
export function encryptRawValue(ticket, value) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aadBytes(ticket));
    const ciphertext = Buffer.concat([
      cipher.update(value, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const wrappedKey = publicEncrypt(
      {
        key: createPublicKey({ key: ticket.publicKey, format: 'jwk' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      key,
    );
    return {
      version: 1,
      iv: iv.toString('base64url'),
      wrappedKey: wrappedKey.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
    };
  } finally {
    key.fill(0);
  }
}
