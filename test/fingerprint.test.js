import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { ticketFingerprint } from '../src/fingerprint.js';

test('fingerprints bind the key, ticket ID and exact value using canonical UTF-8 JSON', () => {
  const key = randomBytes(32);
  const id = 'example-ticket-id';
  const value = ' \tprivate value ☃\r\n';
  const fingerprint = ticketFingerprint(key, id, value);
  assert.match(fingerprint, /^[a-f0-9]{16}$/);
  assert.equal(ticketFingerprint(key, id, value), fingerprint);
  assert.equal(
    fingerprint,
    createHmac('sha256', key)
      .update(JSON.stringify([id, value]), 'utf8')
      .digest('hex')
      .slice(0, 16),
  );
  assert.notEqual(ticketFingerprint(randomBytes(32), id, value), fingerprint);
  assert.notEqual(
    ticketFingerprint(key, 'other-ticket-id', value),
    fingerprint,
  );
  assert.notEqual(ticketFingerprint(key, id, value.trim()), fingerprint);
  assert.notEqual(
    ticketFingerprint(key, 'ab', 'c'),
    ticketFingerprint(key, 'a', 'bc'),
  );
});
