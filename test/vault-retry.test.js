import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { TicketStore } from '../src/db.js';
import { IntakeError } from '../src/errors.js';
import { listen, closeServer } from '../src/http.js';
import { BwServeAdapter, MockVaultAdapter, VaultError } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { encryptValue } from '../public/crypto.js';
import { fixture, waitFor } from '../support/fixtures.js';
import { encryptRawValue } from '../support/raw-envelope.js';

const execute = promisify(execFile);
const privateValue = 'retry-private-value-7bdf293a';

async function retryFixture(t) {
  const resources = [];
  // Stop writers and servers before the fixture closes its databases.
  t.after(async () => {
    for (const close of resources.reverse()) await close();
  });
  return {
    ...(await fixture(t)),
    cleanup: (close) => resources.push(close),
  };
}

function input(value = privateValue) {
  return {
    target: { item: 'Retry example', field: 'password', notes: '' },
    keyName: 'RETRY_KEY',
    purpose: 'Exercise safe pre-delivery retries',
    value,
    ticketId: 'retry-ticket',
    fingerprint: '0123456789abcdef',
  };
}

function classified(code, preDelivery) {
  return (error) => {
    assert(error instanceof VaultError);
    assert.equal(error.code, code);
    assert.equal(error.preDelivery, preDelivery);
    assert.equal(error.message, 'Vault operation failed.');
    assert.equal(error.cause, undefined);
    assert(!`${error.stack} ${JSON.stringify(error)}`.includes(privateValue));
    return true;
  };
}

function json(response, status, data) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(data));
}

async function serve(f, handler, socketPath) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({ method: request.method, path: request.url });
    handler(request, response);
  });
  await listen(server, socketPath ?? { host: '127.0.0.1', port: 0 });
  f.cleanup(async () => {
    const closed = closeServer(server);
    server.closeAllConnections();
    await closed;
  });
  return {
    requests,
    socketPath,
    baseUrl: socketPath
      ? undefined
      : `http://127.0.0.1:${server.address().port}`,
  };
}

function adapter(server, options = {}) {
  return new BwServeAdapter({
    baseUrl: server.baseUrl,
    socketPath: server.socketPath,
    organizationId: 'retry-organization',
    collectionId: 'retry-collection',
    timeoutMs: 1000,
    ...options,
  });
}

function ambiguousWrite() {
  throw Object.assign(new VaultError('vault_network'), { ambiguous: true });
}

async function queue(f) {
  const { ticket, token } = f.create();
  const envelope = await encryptValue(f.store.open(token), privateValue);
  f.store.claim(token, envelope);
  return { ticket, token, envelope, key: f.keys.get(ticket.id) };
}

function assertPending(f, queued, attempts, nextAttemptAt) {
  const state = f.store.getState(queued.ticket.id);
  assert.equal(state.status, 'pending');
  assert.equal(state.attempts, attempts);
  assert.equal(state.nextAttemptAt, nextAttemptAt);
  assert.deepEqual(state.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
}

async function writer(f, vault, options = {}) {
  const instance = await startWriter({
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
  f.cleanup(() => instance.close());
  await instance.drain();
  return instance;
}

test('private database write contention retries markSeen without losing the key', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const write = t.mock.method(vault, 'write');
  const instance = await writer(f, vault, { now: () => now });
  const queued = await queue(f);
  assert.equal(f.store.db.pragma('busy_timeout', { simple: true }), 5000);
  assert.equal(f.keys.db.pragma('busy_timeout', { simple: true }), 5000);
  f.keys.db.pragma('busy_timeout = 5');
  const blocker = new Database(f.config.privateDbPath);
  f.cleanup(() => blocker.close());
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  blocker.exec('BEGIN IMMEDIATE');

  await instance.drain();
  assertPending(f, queued, 1, now + 5000);
  const pending = f.store.getState(queued.ticket.id);
  assert.equal(pending.failureCode, 'database_busy');
  assert.equal(pending.notifyStatus, null);
  assert.equal(f.keys.getMetadata(queued.ticket.id).firstSeenAt, null);
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 0);
  assert.equal(vault.entries.length, 0);

  blocker.exec('ROLLBACK');
  now += 4999;
  await instance.drain();
  assertPending(f, queued, 1, now + 1);
  assert.equal(vault.entries.length, 0);
  now += 2;
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'done');
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.deepEqual(
    vault.entries.map(({ value }) => value),
    [privateValue],
  );
  await instance.drain();
  assert.equal(write.mock.callCount(), 1);
  assert.equal(vault.entries.length, 1);
});

test('private database contention stops each drain after one markSeen attempt', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const write = t.mock.method(vault, 'write');
  const instance = await writer(f, vault, { now: () => now });
  const queued = [await queue(f), await queue(f), await queue(f)];
  f.keys.db.pragma('busy_timeout = 5');
  const blocker = new Database(f.config.privateDbPath);
  f.cleanup(() => blocker.close());
  const markSeen = t.mock.method(f.keys, 'markSeen');
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  blocker.exec('BEGIN IMMEDIATE');

  for (let drain = 1; drain <= 2; drain += 1) {
    await instance.drain();
    assert.equal(markSeen.mock.callCount(), drain);
    for (const entry of queued) {
      const attempted = markSeen.mock.calls.some(
        ({ arguments: [id] }) => id === entry.ticket.id,
      );
      assertPending(f, entry, attempted ? 1 : 0, attempted ? now + 5000 : 0);
      const state = f.store.getState(entry.ticket.id);
      assert.equal(state.failureCode, attempted ? 'database_busy' : null);
      assert.equal(state.notifyStatus, null);
      assert.equal(f.keys.getMetadata(entry.ticket.id).firstSeenAt, null);
    }
    assert.equal(fail.mock.callCount(), 0);
    assert.equal(removeKey.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 0);
    assert.equal(vault.entries.length, 0);
  }

  blocker.exec('ROLLBACK');
  now += 5000;
  await instance.drain();
  for (const entry of queued) {
    assert.equal(f.store.getState(entry.ticket.id).status, 'done');
    assert.equal(f.keys.get(entry.ticket.id), undefined);
    assert.equal(
      write.mock.calls.filter(
        ({ arguments: [input] }) => input.ticketId === entry.ticket.id,
      ).length,
      1,
    );
  }
  assert.deepEqual(
    vault.entries.map(({ value }) => value),
    queued.map(() => privateValue),
  );
  await instance.drain();
  assert.equal(write.mock.callCount(), queued.length);
  assert.equal(vault.entries.length, queued.length);
});

for (const resolving of [false, true]) {
  for (const [database, method, code] of [
    ['keys', 'getMetadata', 'SQLITE_BUSY'],
    ['keys', 'markSeen', 'SQLITE_LOCKED'],
    ['keys', 'get', 'SQLITE_BUSY_SNAPSHOT'],
    ['store', 'get', 'SQLITE_LOCKED_SHAREDCACHE'],
  ]) {
    test(`${resolving ? 'unknown' : 'pending'} ticket preserves material after ${database}.${method} throws ${code}`, async (t) => {
      const f = await retryFixture(t);
      let now = Date.now();
      const vault = new MockVaultAdapter();
      const lookup = t.mock.method(vault, 'lookup');
      const instance = await writer(f, vault, { now: () => now });
      const queued = await queue(f);
      if (resolving)
        f.store.retry(queued.ticket.id, 'vault_network', {
          now: now - 5000,
          unknown: true,
        });
      const fail = t.mock.method(f.store, 'fail');
      const removeKey = t.mock.method(f.keys, 'delete');
      t.mock.method(
        f[database],
        method,
        () => {
          throw new Database.SqliteError('simulated_lock', code);
        },
        { times: 1 },
      );

      await instance.drain();
      const state = f.store.getState(queued.ticket.id);
      assert.equal(state.status, resolving ? 'unknown' : 'pending');
      assert.equal(state.attempts, resolving ? 2 : 1);
      assert.equal(state.nextAttemptAt, now + (resolving ? 10000 : 5000));
      assert.equal(state.failureCode, 'database_busy');
      assert.equal(state.notifyStatus, null);
      assert.deepEqual(state.envelope, queued.envelope);
      assert.equal(f.keys.get(queued.ticket.id), queued.key);
      assert.equal(fail.mock.callCount(), 0);
      assert.equal(removeKey.mock.callCount(), 0);
      assert.equal(lookup.mock.callCount(), 0);
      assert.equal(vault.entries.length, 0);
      assert(
        f.logs.some((line) => {
          const entry = JSON.parse(line);
          return (
            entry.event ===
              (resolving ? 'ticket_unknown' : 'ticket_requeued') &&
            entry.code === 'database_busy'
          );
        }),
      );

      now = state.nextAttemptAt + 1;
      await instance.drain();
      assert.equal(f.store.getState(queued.ticket.id).status, 'done');
      assert.equal(f.keys.get(queued.ticket.id), undefined);
      assert.equal(lookup.mock.callCount(), resolving ? 1 : 0);
      assert.deepEqual(
        vault.entries.map(({ value }) => value),
        [privateValue],
      );
    });
  }
}

for (const [database, method, code] of [
  ['keys', 'getMetadata', 'SQLITE_IOERR'],
  ['keys', 'markSeen', 'SQLITE_IOERR'],
  ['store', 'get', 'SQLITE_IOERR'],
  ['keys', 'get', 'SQLITE_IOERR'],
  ['keys', 'markSeen', null],
]) {
  test(`unknown ticket preserves material after ${database}.${method} throws ${code ?? 'Error'}`, async (t) => {
    const f = await retryFixture(t);
    let now = Date.now();
    const vault = new MockVaultAdapter();
    const lookup = t.mock.method(vault, 'lookup');
    const write = t.mock.method(vault, 'write');
    write.mock.mockImplementationOnce(ambiguousWrite);
    const instance = await writer(f, vault, {
      now: () => now,
      // Inject into processTicket rather than periodic metadata pruning.
      pruneIntervalMs: 600000,
    });
    const queued = await queue(f);
    await instance.drain();
    const ambiguous = f.store.getState(queued.ticket.id);
    assert.equal(ambiguous.status, 'unknown');
    assert.equal(ambiguous.failureCode, 'vault_network');
    assert.equal(write.mock.callCount(), 1);
    assert.equal(vault.entries.length, 0);
    now = ambiguous.nextAttemptAt;
    const fail = t.mock.method(f.store, 'fail');
    const removeKey = t.mock.method(f.keys, 'delete');
    t.mock.method(
      f[database],
      method,
      () => {
        throw code
          ? new Database.SqliteError('simulated_io_failure', code)
          : new Error('simulated_local_failure');
      },
      { times: 1 },
    );

    await instance.drain();
    const state = f.store.getState(queued.ticket.id);
    assert.equal(state.status, 'unknown');
    assert.equal(state.attempts, 2);
    assert.equal(state.nextAttemptAt, now + 10000);
    assert.equal(state.failureCode, 'writer_state_failed');
    assert.equal(state.notifyStatus, null);
    assert.deepEqual(state.envelope, queued.envelope);
    assert.equal(f.keys.get(queued.ticket.id), queued.key);
    assert.equal(fail.mock.callCount(), 0);
    assert.equal(removeKey.mock.callCount(), 0);
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 1);
    assert.equal(vault.entries.length, 0);

    now = state.nextAttemptAt - 1;
    await instance.drain();
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 1);
    now += 1;
    await instance.drain();
    assert.equal(f.store.getState(queued.ticket.id).status, 'done');
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.equal(lookup.mock.callCount(), 1);
    assert.equal(await lookup.mock.calls[0].result, null);
    assert.equal(write.mock.callCount(), 2);
    assert.deepEqual(
      vault.entries.map(({ value }) => value),
      [privateValue],
    );
    await instance.drain();
    assert.equal(lookup.mock.callCount(), 1);
    assert.equal(write.mock.callCount(), 2);
  });
}

test('unknown SQLite I/O failures stop each drain after one local attempt', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const lookup = t.mock.method(vault, 'lookup');
  const queued = [await queue(f), await queue(f), await queue(f)];
  const write = t.mock.method(vault, 'write');
  for (let attempt = 0; attempt < queued.length; attempt += 1)
    write.mock.mockImplementationOnce(ambiguousWrite, attempt);
  const instance = await writer(f, vault, { now: () => now });
  for (const entry of queued)
    assert.equal(f.store.getState(entry.ticket.id).status, 'unknown');
  now = Math.max(
    ...queued.map((entry) => f.store.getState(entry.ticket.id).nextAttemptAt),
  );
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  const markSeen = t.mock.method(f.keys, 'markSeen', () => {
    throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
  });

  for (let drain = 1; drain <= 2; drain += 1) {
    await instance.drain();
    assert.equal(markSeen.mock.callCount(), drain);
    for (const entry of queued) {
      const attempted = markSeen.mock.calls.some(
        ({ arguments: [id] }) => id === entry.ticket.id,
      );
      const state = f.store.getState(entry.ticket.id);
      assert.equal(state.status, 'unknown');
      assert.equal(state.attempts, attempted ? 2 : 1);
      assert.equal(state.nextAttemptAt, attempted ? now + 10000 : now);
      assert.equal(
        state.failureCode,
        attempted ? 'writer_state_failed' : 'vault_network',
      );
      assert.equal(state.notifyStatus, null);
      assert.deepEqual(state.envelope, entry.envelope);
      assert.equal(f.keys.get(entry.ticket.id), entry.key);
    }
    assert.equal(fail.mock.callCount(), 0);
    assert.equal(removeKey.mock.callCount(), 0);
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), queued.length);
    assert.equal(vault.entries.length, 0);
  }

  markSeen.mock.restore();
  now += 10000;
  await instance.drain();
  for (const entry of queued) {
    assert.equal(f.store.getState(entry.ticket.id).status, 'done');
    assert.equal(f.keys.get(entry.ticket.id), undefined);
    assert.equal(
      vault.entries.filter(({ ticketId }) => ticketId === entry.ticket.id)
        .length,
      1,
    );
  }
  assert.equal(lookup.mock.callCount(), queued.length);
  assert.equal(write.mock.callCount(), queued.length * 2);
});

test('locked retry commit escapes to recovery without failing or deleting the key', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const instance = await writer(f, vault, { now: () => now });
  const queued = await queue(f);
  f.store.db.pragma('busy_timeout = 5');
  const blocker = new Database(f.config.dbPath);
  f.cleanup(() => blocker.close());
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  const retry = t.mock.method(f.store, 'retry');
  t.mock.method(
    f.keys,
    'markSeen',
    () => {
      // begin() has committed processing before the tickets database becomes locked.
      blocker.exec('BEGIN IMMEDIATE');
      throw new Database.SqliteError('simulated_lock', 'SQLITE_BUSY');
    },
    { times: 1 },
  );

  await instance.drain();
  assert.equal(retry.mock.callCount(), 1);
  assert.equal(retry.mock.calls[0].arguments[1], 'database_busy');
  assert.equal(retry.mock.calls[0].error.code, 'SQLITE_BUSY');
  const processing = f.store.getState(queued.ticket.id);
  assert.equal(processing.status, 'processing');
  assert.equal(processing.attempts, 0);
  assert.equal(processing.failureCode, null);
  assert.equal(processing.notifyStatus, null);
  assert.deepEqual(processing.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'processing');
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(vault.entries.length, 0);

  blocker.exec('ROLLBACK');
  await instance.drain();
  const recovered = f.store.getState(queued.ticket.id);
  assert.equal(recovered.status, 'unknown');
  assert.equal(recovered.attempts, 1);
  assert.equal(recovered.failureCode, 'writer_state_failed');
  assert.equal(recovered.nextAttemptAt, now + 120000);
  assert.deepEqual(recovered.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(vault.entries.length, 0);
  now = recovered.nextAttemptAt + 1;
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'done');
  assert.deepEqual(
    vault.entries.map(({ value }) => value),
    [privateValue],
  );
});

for (const phase of ['finish', 'lookup']) {
  test(`database lock during ${phase} keeps the existing unknown path`, async (t) => {
    const f = await retryFixture(t);
    let now = Date.now();
    const vault = new MockVaultAdapter();
    const instance = await writer(f, vault, { now: () => now });
    const queued = await queue(f);
    if (phase === 'lookup')
      f.store.retry(queued.ticket.id, 'vault_network', {
        now: now - 5000,
        unknown: true,
      });
    t.mock.method(
      phase === 'finish' ? f.store : vault,
      phase,
      () => {
        throw new Database.SqliteError('simulated_lock', 'SQLITE_BUSY');
      },
      { times: 1 },
    );

    await instance.drain();
    const state = f.store.getState(queued.ticket.id);
    assert.equal(state.status, 'unknown');
    assert.equal(state.failureCode, 'writer_state_failed');
    assert.equal(
      state.nextAttemptAt,
      now + (phase === 'finish' ? 120000 : 10000),
    );
    assert.deepEqual(state.envelope, queued.envelope);
    assert.equal(f.keys.get(queued.ticket.id), queued.key);
    assert.equal(vault.entries.length, phase === 'finish' ? 1 : 0);
    now = state.nextAttemptAt + 1;
    await instance.drain();
    assert.equal(f.store.getState(queued.ticket.id).status, 'done');
    assert.deepEqual(
      vault.entries.map(({ value }) => value),
      [privateValue],
    );
  });
}

test('unknown retry commit I/O failure escapes to recovery without losing material', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const lookup = t.mock.method(vault, 'lookup');
  const write = t.mock.method(vault, 'write');
  write.mock.mockImplementationOnce(ambiguousWrite);
  const instance = await writer(f, vault, { now: () => now });
  const queued = await queue(f);
  await instance.drain();
  now = f.store.getState(queued.ticket.id).nextAttemptAt;
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  t.mock.method(
    f.keys,
    'markSeen',
    () => {
      throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
    },
    { times: 1 },
  );
  const retry = t.mock.method(
    f.store,
    'retry',
    () => {
      throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
    },
    { times: 1 },
  );

  await instance.drain();
  assert.equal(retry.mock.callCount(), 1);
  assert.equal(retry.mock.calls[0].arguments[1], 'writer_state_failed');
  const processing = f.store.getState(queued.ticket.id);
  assert.equal(processing.status, 'processing');
  assert.equal(processing.notifyStatus, null);
  assert.deepEqual(processing.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 1);

  await instance.drain();
  const recovered = f.store.getState(queued.ticket.id);
  assert.equal(recovered.status, 'unknown');
  assert.equal(recovered.attempts, 2);
  assert.equal(recovered.failureCode, 'writer_state_failed');
  assert.equal(recovered.nextAttemptAt, now + 120000);
  assert.equal(recovered.notifyStatus, null);
  assert.deepEqual(recovered.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 1);
  now = recovered.nextAttemptAt;
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'done');
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.equal(lookup.mock.callCount(), 1);
  assert.equal(write.mock.callCount(), 2);
  assert.deepEqual(
    vault.entries.map(({ value }) => value),
    [privateValue],
  );
});

for (const [database, method] of [
  ['keys', 'getMetadata'],
  ['keys', 'markSeen'],
  ['store', 'get'],
  ['keys', 'get'],
]) {
  test(`pending ticket preserves material after ${database}.${method} throws SQLITE_IOERR`, async (t) => {
    const f = await retryFixture(t);
    let now = Date.now();
    const vault = new MockVaultAdapter();
    const write = t.mock.method(vault, 'write');
    const instance = await writer(f, vault, {
      now: () => now,
      // Inject into processTicket rather than periodic metadata pruning.
      pruneIntervalMs: 600000,
    });
    const queued = await queue(f);
    const fail = t.mock.method(f.store, 'fail');
    const removeKey = t.mock.method(f.keys, 'delete');
    t.mock.method(
      f[database],
      method,
      () => {
        throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
      },
      { times: 1 },
    );

    await instance.drain();
    const state = f.store.getState(queued.ticket.id);
    assert.equal(state.status, 'pending');
    assert.equal(state.attempts, 1);
    assert.equal(state.nextAttemptAt, now + 5000);
    assert.equal(state.failureCode, 'writer_state_failed');
    assert.equal(state.notifyStatus, null);
    assert.deepEqual(state.envelope, queued.envelope);
    assert.equal(f.keys.get(queued.ticket.id), queued.key);
    assert.equal(fail.mock.callCount(), 0);
    assert.equal(removeKey.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 0);
    assert.equal(vault.entries.length, 0);
    assert(
      f.logs.some((line) => {
        const entry = JSON.parse(line);
        return (
          entry.event === 'ticket_requeued' &&
          entry.code === 'writer_state_failed'
        );
      }),
    );

    now = state.nextAttemptAt - 1;
    await instance.drain();
    assert.equal(write.mock.callCount(), 0);
    assert.equal(f.store.getState(queued.ticket.id).status, 'pending');
    now += 1;
    await instance.drain();
    assert.equal(f.store.getState(queued.ticket.id).status, 'done');
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.equal(write.mock.callCount(), 1);
    assert.deepEqual(
      vault.entries.map(({ value }) => value),
      [privateValue],
    );
    await instance.drain();
    assert.equal(write.mock.callCount(), 1);
    assert.equal(vault.entries.length, 1);
  });
}

test('pending non-SQLite local errors retry without stopping the drain', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const write = t.mock.method(vault, 'write');
  const instance = await writer(f, vault, {
    now: () => now,
    pruneIntervalMs: 600000,
  });
  const queued = [await queue(f), await queue(f)];
  const get = t.mock.method(
    f.store,
    'get',
    () => {
      throw new Error('boom');
    },
    { times: 1 },
  );

  await instance.drain();
  assert.equal(get.mock.callCount(), 1);
  const retried = queued.find(
    (entry) => entry.ticket.id === get.mock.calls[0].arguments[0],
  );
  const continued = queued.find((entry) => entry !== retried);
  const state = f.store.getState(retried.ticket.id);
  assert.equal(state.status, 'pending');
  assert.equal(state.attempts, 1);
  assert.equal(state.nextAttemptAt, now + 5000);
  assert.equal(state.failureCode, 'writer_state_failed');
  assert.equal(state.notifyStatus, null);
  assert.deepEqual(state.envelope, retried.envelope);
  assert.equal(f.keys.get(retried.ticket.id), retried.key);
  assert.equal(f.store.getState(continued.ticket.id).status, 'done');
  assert.equal(f.keys.get(continued.ticket.id), undefined);
  assert.equal(write.mock.callCount(), 1);
  assert.equal(write.mock.calls[0].arguments[0].ticketId, continued.ticket.id);
  assert.equal(vault.entries.length, 1);

  now = state.nextAttemptAt;
  await instance.drain();
  assert.equal(f.store.getState(retried.ticket.id).status, 'done');
  assert.equal(f.keys.get(retried.ticket.id), undefined);
  assert.equal(write.mock.callCount(), 2);
  assert.equal(
    write.mock.calls.filter(
      ({ arguments: [input] }) => input.ticketId === retried.ticket.id,
    ).length,
    1,
  );
});

test('pending SQLite I/O failures stop the drain before later tickets', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const write = t.mock.method(vault, 'write');
  const instance = await writer(f, vault, {
    now: () => now,
    pruneIntervalMs: 600000,
  });
  const queued = [await queue(f), await queue(f)];
  const markSeen = t.mock.method(
    f.keys,
    'markSeen',
    () => {
      throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
    },
    { times: 1 },
  );

  await instance.drain();
  assert.equal(markSeen.mock.callCount(), 1);
  const attempted = queued.find(
    (entry) => entry.ticket.id === markSeen.mock.calls[0].arguments[0],
  );
  const untouched = queued.find((entry) => entry !== attempted);
  const attemptedState = f.store.getState(attempted.ticket.id);
  assert.equal(attemptedState.status, 'pending');
  assert.equal(attemptedState.attempts, 1);
  assert.equal(attemptedState.nextAttemptAt, now + 5000);
  assert.equal(attemptedState.failureCode, 'writer_state_failed');
  assert.equal(attemptedState.notifyStatus, null);
  assert.deepEqual(attemptedState.envelope, attempted.envelope);
  assert.equal(f.keys.get(attempted.ticket.id), attempted.key);
  assertPending(f, untouched, 0, 0);
  assert.equal(f.store.getState(untouched.ticket.id).failureCode, null);
  assert.equal(f.store.getState(untouched.ticket.id).notifyStatus, null);
  assert.equal(write.mock.callCount(), 0);
  assert.equal(vault.entries.length, 0);

  await instance.drain();
  assert.equal(f.store.getState(untouched.ticket.id).status, 'done');
  assert.equal(f.keys.get(untouched.ticket.id), undefined);
  assert.equal(f.store.getState(attempted.ticket.id).status, 'pending');
  assert.equal(f.store.getState(attempted.ticket.id).attempts, 1);
  assert.equal(write.mock.callCount(), 1);
  assert.equal(write.mock.calls[0].arguments[0].ticketId, untouched.ticket.id);

  now = attemptedState.nextAttemptAt;
  await instance.drain();
  assert.equal(f.store.getState(attempted.ticket.id).status, 'done');
  assert.equal(f.keys.get(attempted.ticket.id), undefined);
  assert.equal(write.mock.callCount(), 2);
  assert.equal(
    write.mock.calls.filter(
      ({ arguments: [input] }) => input.ticketId === attempted.ticket.id,
    ).length,
    1,
  );
});

test('pending retry commit I/O failure escapes to recovery without losing material', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const lookup = t.mock.method(vault, 'lookup');
  const write = t.mock.method(vault, 'write');
  const instance = await writer(f, vault, {
    now: () => now,
    pruneIntervalMs: 600000,
  });
  const queued = await queue(f);
  const fail = t.mock.method(f.store, 'fail');
  const removeKey = t.mock.method(f.keys, 'delete');
  t.mock.method(
    f.keys,
    'markSeen',
    () => {
      throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
    },
    { times: 1 },
  );
  const retry = t.mock.method(
    f.store,
    'retry',
    () => {
      throw new Database.SqliteError('simulated_io_failure', 'SQLITE_IOERR');
    },
    { times: 1 },
  );

  await instance.drain();
  assert.equal(retry.mock.callCount(), 1);
  assert.equal(retry.mock.calls[0].arguments[1], 'writer_state_failed');
  assert.equal(retry.mock.calls[0].error.code, 'SQLITE_IOERR');
  const processing = f.store.getState(queued.ticket.id);
  assert.equal(processing.status, 'processing');
  assert.equal(processing.attempts, 0);
  assert.equal(processing.failureCode, null);
  assert.equal(processing.notifyStatus, null);
  assert.deepEqual(processing.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 0);
  assert(
    f.logs.some((line) => {
      const entry = JSON.parse(line);
      return (
        entry.event === 'writer_loop_error' && entry.code === 'internal_error'
      );
    }),
  );

  await instance.drain();
  const recovered = f.store.getState(queued.ticket.id);
  // Interrupted processing is ambiguous: recoverInterrupted keeps unknown.
  assert.equal(recovered.status, 'unknown');
  assert.equal(recovered.attempts, 1);
  assert.equal(recovered.failureCode, 'writer_state_failed');
  assert.equal(recovered.nextAttemptAt, now + 120000);
  assert.equal(recovered.notifyStatus, null);
  assert.deepEqual(recovered.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(fail.mock.callCount(), 0);
  assert.equal(removeKey.mock.callCount(), 0);
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 0);

  now = recovered.nextAttemptAt - 1;
  await instance.drain();
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 0);
  now += 1;
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'done');
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.equal(lookup.mock.callCount(), 1);
  assert.equal(write.mock.callCount(), 1);
  assert.deepEqual(
    vault.entries.map(({ value }) => value),
    [privateValue],
  );
  await instance.drain();
  assert.equal(lookup.mock.callCount(), 1);
  assert.equal(write.mock.callCount(), 1);
});

for (const [label, arrange, code] of [
  [
    'missing metadata',
    (f, queued) => {
      f.keys.db
        .prepare('DELETE FROM ticket_metadata WHERE id = ?')
        .run(queued.ticket.id);
    },
    'writer_failed',
  ],
  [
    'revoked metadata',
    (f, queued) => {
      f.keys.db
        .prepare('UPDATE ticket_metadata SET revoked = 1 WHERE id = ?')
        .run(queued.ticket.id);
    },
    'ticket_revoked',
  ],
  [
    'invalid envelope',
    (f, queued) => {
      f.store.db
        .prepare('UPDATE tickets SET envelope = ? WHERE id = ?')
        .run(
          JSON.stringify({ ...queued.envelope, ciphertext: '***' }),
          queued.ticket.id,
        );
    },
    'writer_failed',
  ],
  [
    'tampered envelope',
    (f, queued) => {
      const ciphertext = Buffer.from(queued.envelope.ciphertext, 'base64url');
      ciphertext[ciphertext.length - 1] ^= 1;
      f.store.db.prepare('UPDATE tickets SET envelope = ? WHERE id = ?').run(
        JSON.stringify({
          ...queued.envelope,
          ciphertext: ciphertext.toString('base64url'),
        }),
        queued.ticket.id,
      );
    },
    'writer_failed',
  ],
  [
    'corrupt encrypted private key',
    (f, queued) => {
      f.keys.db
        .prepare('UPDATE private_keys SET encrypted_key = ? WHERE id = ?')
        .run('{', queued.ticket.id);
    },
    'writer_failed',
  ],
  [
    'invalid payload',
    (f, queued) => {
      const envelope = encryptRawValue(f.store.get(queued.ticket.id), '  x');
      f.store.db
        .prepare('UPDATE tickets SET envelope = ? WHERE id = ?')
        .run(JSON.stringify(envelope), queued.ticket.id);
    },
    'invalid_payload',
  ],
]) {
  test(`pending ${label} still fails and deletes the key`, async (t) => {
    const f = await retryFixture(t);
    const vault = new MockVaultAdapter();
    const write = t.mock.method(vault, 'write');
    const instance = await writer(f, vault, { pruneIntervalMs: 600000 });
    const queued = await queue(f);
    arrange(f, queued);
    const retry = t.mock.method(f.store, 'retry');

    await instance.drain();
    const state = f.store.getState(queued.ticket.id);
    assert.equal(state.status, 'failed');
    assert.equal(state.failureCode, code);
    assert.equal(state.envelope, null);
    assert.equal(state.attempts, 0);
    assert.equal(state.nextAttemptAt, 0);
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.equal(retry.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 0);
    assert.equal(vault.entries.length, 0);
  });
}

test('non-VaultError from adapter.write still fails the pending ticket', async (t) => {
  const f = await retryFixture(t);
  const vault = new MockVaultAdapter();
  const write = t.mock.method(vault, 'write', () => {
    throw new Error('boom');
  });
  const instance = await writer(f, vault, { pruneIntervalMs: 600000 });
  const queued = await queue(f);

  await instance.drain();
  const state = f.store.getState(queued.ticket.id);
  assert.equal(state.status, 'failed');
  assert.equal(state.failureCode, 'writer_failed');
  assert.equal(state.envelope, null);
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.equal(write.mock.callCount(), 1);
  assert.equal(vault.entries.length, 0);
});

for (const code of [
  'ticket_revoked',
  'ticket_upgrade_required',
  'invalid_payload',
  'ticket_expired',
  'ticket_metadata_mismatch',
  'invalid_envelope',
]) {
  test(`unknown ticket still fails after deterministic ${code}`, async (t) => {
    const f = await retryFixture(t);
    const now = Date.now();
    const vault = new MockVaultAdapter();
    const lookup = t.mock.method(vault, 'lookup');
    const write = t.mock.method(vault, 'write');
    const instance = await writer(f, vault, { now: () => now });
    const queued = await queue(f);
    f.store.retry(queued.ticket.id, 'vault_network', {
      now: now - 5000,
      unknown: true,
    });
    t.mock.method(
      f.keys,
      'getMetadata',
      () => {
        throw new IntakeError(code);
      },
      { times: 1 },
    );

    await instance.drain();
    const state = f.store.getState(queued.ticket.id);
    assert.equal(state.status, 'failed');
    assert.equal(
      state.failureCode,
      ['ticket_metadata_mismatch', 'invalid_envelope'].includes(code)
        ? 'writer_failed'
        : code,
    );
    assert.equal(state.envelope, null);
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(write.mock.callCount(), 0);
    assert.equal(vault.entries.length, 0);
  });
}

test('unknown ticket with bad AAD fails terminally and sends one failure notification', async (t) => {
  const f = await retryFixture(t);
  let now = Date.now();
  const vault = new MockVaultAdapter();
  const lookup = t.mock.method(vault, 'lookup');
  const write = t.mock.method(vault, 'write');
  write.mock.mockImplementationOnce(ambiguousWrite);
  const notifications = [];
  const instance = await writer(f, vault, {
    now: () => now,
    notifyOff: false,
    notifier: {
      async send(ticket) {
        notifications.push(ticket);
        return {
          status: 'sent',
          attempts: 1,
          error: null,
          notifiedAt: new Date(now).toISOString(),
        };
      },
    },
  });
  const queued = await queue(f);
  await instance.drain();
  const ambiguous = f.store.getState(queued.ticket.id);
  assert.equal(ambiguous.status, 'unknown');
  assert.equal(ambiguous.failureCode, 'vault_network');
  assert.equal(notifications.length, 0);

  const envelope = await encryptValue(
    { ...queued.ticket, purpose: 'Different purpose' },
    privateValue,
  );
  f.store.db
    .prepare('UPDATE tickets SET envelope = ? WHERE id = ?')
    .run(JSON.stringify(envelope), queued.ticket.id);
  now = ambiguous.nextAttemptAt;
  const retry = t.mock.method(f.store, 'retry');
  await instance.drain();
  const failed = f.store.getState(queued.ticket.id);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.failureCode, 'writer_failed');
  assert.equal(failed.envelope, null);
  assert.equal(failed.attempts, ambiguous.attempts);
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  await waitFor(
    () => f.store.getState(queued.ticket.id).notifyStatus === 'sent',
  );
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].status, 'failed');
  assert.equal(notifications[0].failureCode, 'writer_failed');
  assert.equal(notifications[0].envelope, null);
  assert(
    !JSON.stringify({ notifications, logs: f.logs }).includes(privateValue),
  );

  now += 300000;
  await instance.drain();
  assert.equal(f.store.getState(queued.ticket.id).status, 'failed');
  assert.equal(retry.mock.callCount(), 0);
  assert.equal(lookup.mock.callCount(), 0);
  assert.equal(write.mock.callCount(), 1);
  assert.equal(vault.entries.length, 0);
  assert.equal(notifications.length, 1);
});

for (const [corruption, corrupt] of [
  [
    'tampered envelope',
    (f, queued) => {
      const ciphertext = Buffer.from(queued.envelope.ciphertext, 'base64url');
      ciphertext[ciphertext.length - 1] ^= 1;
      f.store.db.prepare('UPDATE tickets SET envelope = ? WHERE id = ?').run(
        JSON.stringify({
          ...queued.envelope,
          ciphertext: ciphertext.toString('base64url'),
        }),
        queued.ticket.id,
      );
    },
  ],
  [
    'corrupt encrypted private key',
    (f, queued) => {
      f.keys.db
        .prepare('UPDATE private_keys SET encrypted_key = ? WHERE id = ?')
        .run('{', queued.ticket.id);
    },
  ],
  [
    'corrupt target_json',
    (f, queued) => {
      f.keys.db
        .prepare('UPDATE ticket_metadata SET target_json = ? WHERE id = ?')
        .run('{', queued.ticket.id);
    },
  ],
]) {
  test(`unknown ticket terminates after ${corruption} without retrying`, async (t) => {
    const f = await retryFixture(t);
    let now = Date.now();
    const vault = new MockVaultAdapter();
    const lookup = t.mock.method(vault, 'lookup');
    const write = t.mock.method(vault, 'write');
    const instance = await writer(f, vault, { now: () => now });
    const queued = await queue(f);
    f.store.retry(queued.ticket.id, 'vault_network', {
      now: now - 5000,
      unknown: true,
    });
    corrupt(f, queued);
    const fail = t.mock.method(f.store, 'fail');
    const retry = t.mock.method(f.store, 'retry');

    for (let drain = 0; drain < 2; drain += 1) {
      await instance.drain();
      const state = f.store.getState(queued.ticket.id);
      assert.equal(state.status, 'failed');
      assert.equal(state.failureCode, 'writer_failed');
      assert.equal(state.envelope, null);
      assert.equal(state.attempts, 1);
      assert.equal(f.keys.get(queued.ticket.id), undefined);
      assert.equal(fail.mock.callCount(), 1);
      assert.equal(retry.mock.callCount(), 0);
      assert.equal(lookup.mock.callCount(), 0);
      assert.equal(write.mock.callCount(), 0);
      assert.equal(vault.entries.length, 0);
      now += 10001;
    }
  });
}

test('unknown ticket fails on a generic write error after an empty recovery lookup', async (t) => {
  const f = await retryFixture(t);
  const now = Date.now();
  const vault = new MockVaultAdapter();
  const lookup = t.mock.method(vault, 'lookup');
  const write = t.mock.method(vault, 'write', () => {
    throw new Error('simulated_write_failure');
  });
  const instance = await writer(f, vault, { now: () => now });
  const queued = await queue(f);
  f.store.retry(queued.ticket.id, 'vault_network', {
    now: now - 5000,
    unknown: true,
  });

  await instance.drain();
  const state = f.store.getState(queued.ticket.id);
  assert.equal(state.status, 'failed');
  assert.equal(state.failureCode, 'writer_failed');
  assert.equal(state.envelope, null);
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.equal(lookup.mock.callCount(), 1);
  assert.equal(await lookup.mock.calls[0].result, null);
  assert.equal(write.mock.callCount(), 1);
  assert.equal(vault.entries.length, 0);
});

for (const unix of [false, true]) {
  const transport = unix ? 'Unix' : 'HTTP';

  for (const sync of [false, true]) {
    for (const [failure, code] of [
      ['HTTP error', 'vault_http_503'],
      ['malformed response', 'vault_response'],
      ['connected reset', 'vault_network'],
      ['timeout', 'vault_timeout'],
    ]) {
      test(`${transport} ${sync ? 'sync' : 'item'} ${failure} has preDelivery=${sync}`, async (t) => {
        const f = await retryFixture(t);
        const server = await serve(
          f,
          (request, response) => {
            request.resume();
            if (failure === 'HTTP error')
              json(response, 503, { success: false, message: privateValue });
            else if (failure === 'malformed response')
              response.end(privateValue);
            else if (failure === 'connected reset') request.socket.destroy();
            // A timeout deliberately leaves the response open.
          },
          unix ? join(f.dir, 'vault.sock') : undefined,
        );
        await assert.rejects(
          adapter(server, {
            sync,
            timeoutMs: failure === 'timeout' ? 100 : 1000,
          }).write(input()),
          classified(code, sync),
        );
        assert.deepEqual(server.requests, [
          { method: 'POST', path: sync ? '/sync' : '/object/item' },
        ]);
      });
    }
  }

  test(`${transport} sync retries preserve queued material, double and cap backoff, then succeed once`, async (t) => {
    const f = await retryFixture(t);
    const queued = await queue(f);
    let now = Date.now();
    let unavailable = true;
    const notifications = [];
    const values = [];
    const server = await serve(
      f,
      (request, response) => {
        if (request.url === '/status') {
          request.resume();
          json(response, 200, {
            success: true,
            data: { template: { status: 'unlocked' } },
          });
        } else if (request.url === '/sync') {
          request.resume();
          json(response, unavailable ? 503 : 200, {
            success: !unavailable,
            data: {},
          });
        } else {
          const chunks = [];
          request.on('data', (chunk) => chunks.push(chunk));
          request.on('end', () => {
            values.push(
              JSON.parse(Buffer.concat(chunks).toString()).login.password,
            );
            json(response, 200, {
              success: true,
              data: { id: 'retried-item' },
            });
          });
        }
      },
      unix ? join(f.dir, 'vault.sock') : undefined,
    );
    const instance = await writer(f, adapter(server, { sync: true }), {
      retryBaseMs: 5000,
      retryMaxMs: 12000,
      now: () => now,
      notifyOff: false,
      notifier: {
        async send(ticket) {
          notifications.push(ticket);
          return {
            status: 'sent',
            attempts: 1,
            error: null,
            notifiedAt: new Date().toISOString(),
          };
        },
      },
    });
    const syncRequests = () =>
      server.requests.filter(({ path }) => path === '/sync').length;
    for (const [index, delay] of [5000, 10000, 12000, 12000].entries()) {
      const due = now + delay;
      assertPending(f, queued, index + 1, due);
      assert.equal(syncRequests(), index + 1);
      assert.equal(values.length, 0);
      assert.equal(notifications.length, 0);
      const requestsBefore = server.requests.length;
      await instance.drain();
      await instance.drain();
      now = due - 1;
      await instance.drain();
      assert.equal(server.requests.length, requestsBefore);
      assertPending(f, queued, index + 1, due);
      now = due;
      if (index === 3) unavailable = false;
      await instance.drain();
    }
    assert.equal(f.store.getState(queued.ticket.id).status, 'done');
    assert.equal(f.store.getState(queued.ticket.id).envelope, null);
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.deepEqual(values, [privateValue]);
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].status, 'done');
    const requestsAfter = server.requests.length;
    await instance.drain();
    assert.equal(server.requests.length, requestsAfter);
    assert(!f.logs.join('').includes(privateValue));
  });

  test(`${transport} reset during a partial item upload is not a pre-delivery failure`, async (t) => {
    const f = await retryFixture(t);
    const value = `${privateValue}${'x'.repeat(8 * 1024 * 1024)}`;
    let received = 0;
    let complete = false;
    const server = await serve(
      f,
      (request) => {
        request.on('error', () => {});
        request.on('end', () => {
          complete = true;
        });
        request.once('data', (chunk) => {
          received += chunk.length;
          request.pause();
          request.socket.destroy();
        });
      },
      unix ? join(f.dir, 'vault.sock') : undefined,
    );
    await assert.rejects(
      adapter(server).write(input(value)),
      classified('vault_network', false),
    );
    assert(received > 0);
    assert(received < Buffer.byteLength(value));
    assert.equal(complete, false);
    assert.deepEqual(server.requests, [
      { method: 'POST', path: '/object/item' },
    ]);
  });
}

async function connectError(socketPath) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    socket.once('error', resolve);
    socket.once('connect', () => {
      socket.destroy();
      reject(new Error('Expected a real Unix connection failure'));
    });
  });
}

for (const [kind, code] of [
  ['missing', 'ENOENT'],
  ['refused', 'ECONNREFUSED'],
  ['denied parent', 'EACCES'],
]) {
  test(`fresh Unix item connection with ${kind} socket is retryable and succeeds later`, async (t) => {
    const f = await retryFixture(t);
    let now = Date.now();
    let parent = f.dir;
    if (kind === 'denied parent') {
      parent = join(f.dir, 'denied');
      await mkdir(parent, { mode: 0o700 });
      f.cleanup(() => chmod(parent, 0o700));
    }
    const socketPath = join(parent, 'vault.sock');
    if (kind === 'refused') {
      await execute(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          "import { createServer } from 'node:net'; createServer().listen(process.argv[1], () => process.exit(0));",
          socketPath,
        ],
        { env: {} },
      );
      assert((await lstat(socketPath)).isSocket());
    } else if (kind === 'denied parent') await chmod(parent, 0o000);
    else await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
    assert.equal((await connectError(socketPath)).code, code);
    const vault = adapter({ socketPath });
    await assert.rejects(
      vault.write(input()),
      classified('vault_network', true),
    );
    const queued = await queue(f);
    // Omit readiness only to exercise the production adapter's item-connect path.
    const instance = await writer(
      f,
      { write: (entry) => vault.write(entry) },
      { now: () => now },
    );
    assertPending(f, queued, 1, now + 5000);
    if (kind === 'denied parent') await chmod(parent, 0o700);
    if (kind === 'refused') await rm(socketPath);
    const server = await serve(
      f,
      (request, response) => {
        request.resume();
        json(response, 200, {
          success: true,
          data: { id: 'recovered-unix-item' },
        });
      },
      socketPath,
    );
    await instance.drain();
    assert.equal(server.requests.length, 0);
    now += 5000;
    await instance.drain();
    assert.equal(f.store.getState(queued.ticket.id).status, 'done');
    assert.equal(f.store.getState(queued.ticket.id).envelope, null);
    assert.equal(f.keys.get(queued.ticket.id), undefined);
    assert.deepEqual(server.requests, [
      { method: 'POST', path: '/object/item' },
    ]);
  });
}

test('retry state persists across reopening and work/begin enforce the exact due time', async (t) => {
  const f = await retryFixture(t);
  const queued = await queue(f);
  const now = Date.now();
  assert.equal(f.store.begin(queued.ticket.id, now), true);
  f.store.retry(queued.ticket.id, 'vault_network', {
    baseMs: 5000,
    maxMs: 12000,
    now,
  });
  assertPending(f, queued, 1, now + 5000);
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  f.cleanup(() => reopened.close());
  assert.deepEqual(
    reopened.getState(queued.ticket.id),
    f.store.getState(queued.ticket.id),
  );
  assert.deepEqual(reopened.work(now + 4999), []);
  assert.equal(reopened.begin(queued.ticket.id, now + 4999), false);
  assertPending(f, queued, 1, now + 5000);
  assert.deepEqual(reopened.work(now + 5000), [queued.ticket.id]);
  assert.equal(reopened.begin(queued.ticket.id, now + 5000), true);
  reopened.retry(queued.ticket.id, 'vault_network', {
    baseMs: 5000,
    maxMs: 12000,
    now: now + 5000,
  });
  assertPending(f, queued, 2, now + 15000);
  assert.deepEqual(reopened.work(now + 14999), []);
  assert.deepEqual(reopened.work(now + 15000), [queued.ticket.id]);
});

test('retry scheduling accepts pending work and saturates attempts without overflowing backoff', async (t) => {
  const f = await retryFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  for (let attempt = 1; attempt <= 35; attempt += 1) {
    f.store.retry(queued.ticket.id, 'vault_network', {
      baseMs: 5000,
      maxMs: 300000,
      now,
    });
    const delay = Math.min(5000 * 2 ** (Math.min(attempt, 31) - 1), 300000);
    assertPending(f, queued, Math.min(attempt, 31), now + delay);
    assert.deepEqual(f.store.work(now + delay - 1), []);
    assert.equal(f.store.begin(queued.ticket.id, now + delay - 1), false);
    now += delay;
  }
});

test('one failed Unix preflight schedules every due pending ticket and does not loop before backoff', async (t) => {
  const f = await retryFixture(t);
  const queued = [await queue(f), await queue(f), await queue(f)];
  const future = await queue(f);
  let now = Date.now();
  const futureDue = now + 20000;
  f.store.retry(future.ticket.id, 'vault_network', {
    baseMs: 20000,
    maxMs: 20000,
    now,
  });
  const server = await serve(
    f,
    (request, response) => {
      request.resume();
      json(response, 200, {
        success: true,
        data: { template: { status: 'locked' } },
      });
    },
    join(f.dir, 'vault.sock'),
  );
  const instance = await writer(f, adapter(server), {
    retryBaseMs: 5000,
    retryMaxMs: 12000,
    now: () => now,
  });
  for (const entry of queued) assertPending(f, entry, 1, now + 5000);
  assertPending(f, future, 1, futureDue);
  assert.deepEqual(server.requests, [{ method: 'GET', path: '/status' }]);
  await instance.drain();
  now += 4999;
  await instance.drain();
  assert.equal(server.requests.length, 1);
  now += 1;
  await instance.drain();
  for (const entry of queued) assertPending(f, entry, 2, now + 10000);
  assertPending(f, future, 1, futureDue);
  assert.deepEqual(server.requests, [
    { method: 'GET', path: '/status' },
    { method: 'GET', path: '/status' },
  ]);
});

test('old shared databases gain due-time columns without changing accepted work or keys', async (t) => {
  const f = await retryFixture(t);
  const queued = await queue(f);
  f.store.db.exec(`
    DROP INDEX ticket_retry;
    ALTER TABLE tickets DROP COLUMN attempts;
    ALTER TABLE tickets DROP COLUMN next_attempt_at;
  `);
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  f.cleanup(() => reopened.close());
  assert.equal(reopened.getState(queued.ticket.id).status, 'pending');
  assert.equal(reopened.getState(queued.ticket.id).attempts, 0);
  assert.equal(reopened.getState(queued.ticket.id).nextAttemptAt, 0);
  assert.deepEqual(
    reopened.getState(queued.ticket.id).envelope,
    queued.envelope,
  );
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.deepEqual(reopened.work(), [queued.ticket.id]);
  assert(
    reopened.db
      .pragma('index_list(tickets)')
      .some(({ name }) => name === 'ticket_retry'),
  );
});
