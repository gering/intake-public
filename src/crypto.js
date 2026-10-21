import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  privateDecrypt,
  constants,
  randomBytes,
} from 'node:crypto';
import { aadBytes } from '../public/crypto.js';
import { IntakeError } from './errors.js';

export function createTicketKeys(masterKey, id) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 3072,
  });
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(id));
  const der = privateKey.export({ type: 'pkcs8', format: 'der' });
  try {
    const encrypted = Buffer.concat([cipher.update(der), cipher.final()]);
    return {
      publicKey: publicKey.export({ format: 'jwk' }),
      privateKey: JSON.stringify({
        iv: iv.toString('base64url'),
        ciphertext: encrypted.toString('base64url'),
        tag: cipher.getAuthTag().toString('base64url'),
      }),
    };
  } finally {
    der.fill(0);
  }
}

function decode(value, min, max = min) {
  if (typeof value !== 'string' || !/^[\w-]+$/.test(value))
    throw new IntakeError('invalid_envelope');
  const bytes = Buffer.from(value, 'base64url');
  if (
    bytes.length < min ||
    bytes.length > max ||
    bytes.toString('base64url') !== value
  )
    throw new IntakeError('invalid_envelope');
  return bytes;
}

export function validateEnvelope(envelope) {
  if (
    !envelope ||
    envelope.version !== 1 ||
    Object.keys(envelope).sort().join(',') !==
      'ciphertext,iv,version,wrappedKey'
  )
    throw new IntakeError('invalid_envelope');
  return {
    iv: decode(envelope.iv, 12),
    wrappedKey: decode(envelope.wrappedKey, 384),
    ciphertext: decode(envelope.ciphertext, 16, 65536 + 16),
  };
}

export function decryptValue(masterKey, ticket, encryptedPrivateKey, envelope) {
  const encrypted = JSON.parse(encryptedPrivateKey);
  const decipher = createDecipheriv(
    'aes-256-gcm',
    masterKey,
    Buffer.from(encrypted.iv, 'base64url'),
    { authTagLength: 16 },
  );
  decipher.setAAD(Buffer.from(ticket.id));
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64url'));
  const der = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64url')),
    decipher.final(),
  ]);
  let aesKey;
  let plaintext;
  try {
    const { iv, wrappedKey, ciphertext } = validateEnvelope(envelope);
    aesKey = privateDecrypt(
      {
        key: der,
        type: 'pkcs8',
        format: 'der',
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      wrappedKey,
    );
    if (aesKey.length !== 32) throw new IntakeError('invalid_envelope');
    const aes = createDecipheriv('aes-256-gcm', aesKey, iv, {
      authTagLength: 16,
    });
    aes.setAAD(aadBytes(ticket));
    aes.setAuthTag(ciphertext.subarray(-16));
    plaintext = Buffer.concat([
      aes.update(ciphertext.subarray(0, -16)),
      aes.final(),
    ]);
    const value = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(plaintext);
    if (!value.length || ((ticket.trim ?? true) && value !== value.trim()))
      throw new IntakeError('invalid_payload');
    return { value };
  } finally {
    der.fill(0);
    aesKey?.fill(0);
    plaintext?.fill(0);
  }
}
