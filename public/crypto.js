const encoder = new TextEncoder();

export function aadBytes({ id, keyName, purpose, trim = true, metaDigest }) {
  if (typeof metaDigest !== 'string' || !/^[a-f0-9]{64}$/.test(metaDigest))
    throw new Error('invalid_metadata_digest');
  return encoder.encode(
    JSON.stringify([id, keyName, purpose, trim, metaDigest]),
  );
}

export function prepareValue({ trim = true }, value) {
  const prepared = trim ? value.trim() : value;
  if (!prepared.length) throw new Error('empty_value');
  if (encoder.encode(prepared).length > 65536)
    throw new Error('value_too_large');
  return prepared;
}

function encode(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

export async function encryptValue(ticket, value) {
  const prepared = prepareValue(ticket, value);
  const publicKey = await globalThis.crypto.subtle.importKey(
    'jwk',
    ticket.publicKey,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['wrapKey'],
  );
  const key = await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  );
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aadBytes(ticket), tagLength: 128 },
    key,
    encoder.encode(prepared),
  );
  const wrappedKey = await globalThis.crypto.subtle.wrapKey(
    'raw',
    key,
    publicKey,
    { name: 'RSA-OAEP' },
  );
  return {
    version: 1,
    iv: encode(iv),
    wrappedKey: encode(wrappedKey),
    ciphertext: encode(ciphertext),
  };
}
