import test from 'node:test';
import assert from 'node:assert/strict';
import { isUnixSocketPath } from '../src/socket-path.js';
import { BwServeAdapter, checkVaultAccess } from '../src/vault.js';

const validPaths = ['/' + 'a'.repeat(102), '/' + 'é'.repeat(51)];
const longPaths = ['/' + 'a'.repeat(103), '/' + 'é'.repeat(51) + 'a'];

test('Unix socket paths use a portable 103-byte UTF-8 limit, not character count', () => {
  for (const path of validPaths) {
    assert.equal(Buffer.byteLength(path, 'utf8'), 103);
    assert(isUnixSocketPath(path));
  }
  for (const path of longPaths) {
    assert.equal(Buffer.byteLength(path, 'utf8'), 104);
    assert(!isUnixSocketPath(path));
  }
  for (const path of [
    '',
    'relative/bw.sock',
    '/private/bw\0.sock',
    null,
    undefined,
    123,
  ])
    assert(!isUnixSocketPath(path));
});

test('vault socket paths cannot be truncated before private-directory validation or connection', () => {
  const configuration = {
    organizationId: 'example-organization',
    collectionId: 'example-collection',
  };
  for (const socketPath of validPaths)
    assert(new BwServeAdapter({ ...configuration, socketPath }));
  for (const socketPath of [...longPaths, '/' + 'a'.repeat(200)]) {
    assert.throws(() => new BwServeAdapter({ ...configuration, socketPath }), {
      code: 'vault_config',
    });
    assert.throws(() => checkVaultAccess({ socketPath }), {
      code: 'invalid_intake_bw_socket',
    });
  }
});
