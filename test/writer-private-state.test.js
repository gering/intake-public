import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { PrivateKeyStore } from '../src/db.js';
import { startWriter } from '../src/writer.js';
import { writerRequest } from '../src/ipc.js';
import { metadataDigest } from '../src/metadata.js';
import { MockVaultAdapter, VaultError } from '../src/vault.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

async function privateFixture(t) {
  let writer;
  // Stop the writer before the fixture closes its databases.
  t.after(async () => writer?.close());
  const f = await fixture(t);
  const vault = new MockVaultAdapter();
  return {
    ...f,
    vault,
    async start(options = {}) {
      writer = await startWriter({
        store: f.store,
        keys: f.keys,
        masterKey: f.config.masterKey,
        fingerprintKey: f.config.fingerprintKey,
        adapter: vault,
        notifyOff: true,
        socketPath: f.config.socketPath,
        pollMs: 60000,
        logger: f.logger,
        ...options,
      });
      await writer.drain();
      return writer;
    },
  };
}

function resetPending(f, id, envelope) {
  f.store.db
    .prepare(
      `UPDATE tickets SET status = 'pending', envelope = ?, next_attempt_at = 0,
      expires_at = ? WHERE id = ?`,
    )
    .run(JSON.stringify(envelope), Date.now() + 86400000, id);
}

function assertRefused(f, id, code) {
  const state = f.store.getState(id);
  assert.equal(state.status, 'failed');
  assert.equal(state.failureCode, code);
  assert.equal(state.envelope, null);
  assert.equal(f.keys.get(id), undefined);
  assert.equal(f.vault.entries.length, 0);
}

test('creation stores the same expiry privately without changing the metadata digest', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create({ ttl: '1m' });
  const snapshot = f.keys.getMetadata(ticket.id);
  assert.equal(snapshot.expiresAt, ticket.createdAt + 60000);
  assert.equal(snapshot.expiresAt, ticket.expiresAt);
  assert.equal(snapshot.revoked, false);
  assert.equal(snapshot.firstSeenAt, null);
  assert.equal(metadataDigest(snapshot), ticket.metaDigest);
});

test('private first-seen timestamps latch once and revocation atomically removes only the key', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  assert.equal(f.keys.markSeen(ticket.id, 1234), 1234);
  assert.equal(f.keys.markSeen(ticket.id, 5678), 1234);
  assert.equal(f.keys.markSeen(ticket.id, 1), 1234);
  assert.equal(f.keys.markSeen('missing', 1234), undefined);
  assert.equal(f.keys.markRevoked(ticket.id), true);
  assert.equal(f.keys.markRevoked(ticket.id), true);
  assert.equal(f.keys.markRevoked('missing'), false);
  assert.equal(f.keys.get(ticket.id), undefined);
  const snapshot = f.keys.getMetadata(ticket.id);
  assert.equal(snapshot.revoked, true);
  assert.equal(snapshot.firstSeenAt, 1234);
  assert.equal(snapshot.expiresAt, ticket.expiresAt);
  assert.deepEqual(snapshot.target, ticket.target);
});

for (const latch of ['socket', 'startup prune', 'periodic prune']) {
  test(`revocation latched by ${latch} cannot be undone by resetting shared state`, async (t) => {
    const f = await privateFixture(t);
    const { ticket } = f.create();
    const envelope = await encryptValue(ticket, 'must-not-be-stored');
    let now = ticket.createdAt;
    let writer;
    if (latch !== 'startup prune') writer = await f.start({ now: () => now });
    f.store.revoke(ticket.id);
    if (latch === 'socket') {
      assert.deepEqual(
        await writerRequest(f.config.socketPath, '/revoke', ticket.id),
        { status: 'revoked' },
      );
    } else if (latch === 'startup prune') {
      writer = await f.start({ now: () => now });
    } else {
      now += 60000;
      await writer.drain();
    }
    assert.equal(f.keys.getMetadata(ticket.id).revoked, true);
    assert.equal(f.keys.get(ticket.id), undefined);
    resetPending(f, ticket.id, envelope);
    await writer.drain();
    assertRefused(f, ticket.id, 'ticket_revoked');
    assert.equal(f.keys.getMetadata(ticket.id).revoked, true);
  });
}

function revokeRequest(socketPath, id) {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        path: '/revoke',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            body: JSON.parse(Buffer.concat(chunks).toString()),
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end(JSON.stringify({ id }));
  });
}

test('revocation socket rejects invalid IDs and tickets not currently revoked', async (t) => {
  const f = await privateFixture(t);
  const { ticket } = f.create();
  const key = f.keys.get(ticket.id);
  await f.start();
  for (const id of [ticket.id, 'a'.repeat(22)]) {
    assert.deepEqual(await revokeRequest(f.config.socketPath, id), {
      status: 409,
      body: { error: 'ticket_not_revoked' },
    });
  }
  assert.deepEqual(await revokeRequest(f.config.socketPath, 'invalid'), {
    status: 400,
    body: { error: 'invalid_ticket_id' },
  });
  assert.equal(f.keys.get(ticket.id), key);
  assert.equal(f.keys.getMetadata(ticket.id).revoked, false);
});

test('private expiry rejects a late submission even if shared expiry is extended', async (t) => {
  const f = await privateFixture(t);
  const { ticket } = f.create({ ttl: '1m' });
  const envelope = await encryptValue(ticket, 'too-late-value');
  resetPending(f, ticket.id, envelope);
  const now = ticket.expiresAt + 900001;
  await f.start({ now: () => now });
  assertRefused(f, ticket.id, 'ticket_expired');
  assert.equal(f.keys.getMetadata(ticket.id).firstSeenAt, now);
});

for (const offset of [0, 1]) {
  test(`private expiry grace ${offset === 0 ? 'includes its exact boundary' : 'rejects the next millisecond'}`, async (t) => {
    const f = await privateFixture(t);
    const { ticket, token } = f.create({ ttl: '1m' });
    f.store.claim(token, await encryptValue(ticket, 'boundary-value'));
    const now = ticket.expiresAt + 1000 + offset;
    await f.start({ now: () => now, expiryGraceMs: 1000 });
    if (offset) assertRefused(f, ticket.id, 'ticket_expired');
    else {
      assert.equal(f.store.getState(ticket.id).status, 'done');
      assert.equal(f.vault.entries.length, 1);
    }
  });
}

for (const failure of ['pre-delivery', 'readiness', 'unknown']) {
  test(`timely first sight preserves ${failure} retries after expiry and pruning`, async (t) => {
    const f = await privateFixture(t);
    const { ticket, token } = f.create({ ttl: '1m' });
    f.store.claim(token, await encryptValue(ticket, 'retry-after-expiry'));
    let now = ticket.createdAt + 1000;
    const firstSeenAt = now;
    let available = false;
    let writes = 0;
    let lookups = 0;
    const writer = await f.start({
      now: () => now,
      adapter: {
        ...(failure === 'readiness' ? { isReady: async () => available } : {}),
        async lookup() {
          lookups += 1;
          return null;
        },
        async write() {
          writes += 1;
          if (!available) {
            const error = new VaultError(
              'vault_network',
              failure !== 'unknown',
            );
            error.ambiguous = failure === 'unknown';
            throw error;
          }
        },
      },
    });
    assert.equal(f.keys.getMetadata(ticket.id).firstSeenAt, firstSeenAt);
    assert.equal(
      f.store.getState(ticket.id).status,
      failure === 'unknown' ? 'unknown' : 'pending',
    );
    assert(f.keys.get(ticket.id));
    now = ticket.expiresAt + 900001;
    f.keys.prune(f.store, now);
    assert(f.keys.get(ticket.id));
    available = true;
    await writer.drain();
    assert.equal(f.store.getState(ticket.id).status, 'done');
    assert.equal(f.keys.getMetadata(ticket.id).firstSeenAt, firstSeenAt);
    assert.equal(f.keys.get(ticket.id), undefined);
    assert.equal(writes, failure === 'readiness' ? 1 : 2);
    assert.equal(lookups, failure === 'unknown' ? 1 : 0);
  });
}

test('periodic pruning removes never-seen expired keys and retains seen in-flight work', async (t) => {
  const f = await privateFixture(t);
  const unused = f.create({ ttl: '1m' });
  let now = unused.ticket.createdAt;
  const writer = await f.start({ now: () => now });
  const seen = [];
  for (const status of ['pending', 'processing', 'unknown']) {
    const { ticket } = f.create({ ttl: '1m' });
    f.keys.markSeen(ticket.id, now);
    f.store.db
      .prepare(
        'UPDATE tickets SET status = ?, next_attempt_at = ? WHERE id = ?',
      )
      .run(status, now + 86400000, ticket.id);
    seen.push({ id: ticket.id, key: f.keys.get(ticket.id) });
  }
  const key = f.keys.get(unused.ticket.id);
  now = unused.ticket.expiresAt + 900000;
  await writer.drain();
  assert.equal(f.keys.get(unused.ticket.id), key);
  // A prune is due only after the configured interval, not on every drain.
  now += 1;
  await writer.drain();
  assert.equal(f.keys.get(unused.ticket.id), key);
  now += 60000;
  await writer.drain();
  assert.equal(f.keys.get(unused.ticket.id), undefined);
  assert(f.keys.getMetadata(unused.ticket.id));
  for (const { id, key } of seen) assert.equal(f.keys.get(id), key);
  assert.equal(f.vault.entries.length, 0);
});

test('private revocation removes a key even when shared state no longer says revoked', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.keys.db
    .prepare('UPDATE ticket_metadata SET revoked = 1 WHERE id = ?')
    .run(ticket.id);
  f.keys.prune(f.store);
  assert.equal(f.keys.get(ticket.id), undefined);
  assert.equal(f.keys.getMetadata(ticket.id).revoked, true);
});

test('legacy private metadata migrates without deriving expiry from shared timestamps', async (t) => {
  const f = await privateFixture(t);
  const { ticket, token } = f.create({ ttl: '1m' });
  f.store.claim(token, await encryptValue(ticket, 'legacy-retry-value'));
  for (const column of ['expires_at', 'revoked', 'first_seen_at'])
    f.keys.db.exec(`ALTER TABLE ticket_metadata DROP COLUMN ${column}`);
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  t.after(() => keys.close());
  const snapshot = keys.getMetadata(ticket.id);
  assert.equal(snapshot.expiresAt, null);
  assert.equal(snapshot.revoked, false);
  assert.equal(snapshot.firstSeenAt, null);
  assert.equal(metadataDigest(snapshot), ticket.metaDigest);
  await f.start({ keys, now: () => ticket.expiresAt + 86400000 });
  assert.equal(f.store.getState(ticket.id).status, 'done');
  assert.equal(f.vault.entries.length, 1);
});

for (const [option, values, code] of [
  [
    'expiryGraceMs',
    [-1, 1.5, NaN, Infinity, 2147483648],
    'invalid_intake_expiry_grace_ms',
  ],
  [
    'shutdownWaitMs',
    [-1, 1.5, NaN, Infinity, 2147483648, 9007199254740992, '100', null],
    'invalid_intake_shutdown_wait_ms',
  ],
  [
    'pruneIntervalMs',
    [0, -1, 1.5, NaN, Infinity, 2147483648],
    'invalid_intake_prune_interval_ms',
  ],
]) {
  test(`writer validates ${option} before startup`, async (t) => {
    const f = await privateFixture(t);
    for (const value of values)
      await assert.rejects(f.start({ [option]: value }), { code });
  });
}
