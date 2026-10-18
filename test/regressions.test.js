import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { TicketStore } from '../src/db.js';
import { decryptValue } from '../src/crypto.js';
import { encryptValue } from '../public/crypto.js';
import { startWriter } from '../src/writer.js';
import { writerRequest } from '../src/ipc.js';
import { MockVaultAdapter } from '../src/vault.js';
import { runCli } from '../src/cli.js';
import { fixture, waitFor } from '../support/fixtures.js';

test('creation and key pruning serialize the keys-first visibility gap across connections', async (t) => {
  const f = await fixture(t);
  const other = new TicketStore(f.config.dbPath, f.config.hmacKey);
  other.db.pragma('busy_timeout = 1');
  t.after(() => other.close());
  const create = f.store.create.bind(f.store);
  t.mock.method(f.store, 'create', (...args) => {
    const id = args[0].id;
    assert(f.keys.get(id));
    assert(f.keys.getMetadata(id));
    assert.throws(() => f.keys.prune(other), { code: 'SQLITE_BUSY' });
    assert(f.keys.get(id));
    assert(f.keys.getMetadata(id));
    return create(...args);
  });
  const { ticket } = f.create();
  f.keys.prune(other);
  assert(f.keys.get(ticket.id));
  assert.equal(f.store.get(ticket.id).status, 'active');
});

test('creation cleans a committed private key when its public transaction fails', async (t) => {
  const f = await fixture(t);
  t.mock.method(f.store, 'create', () => {
    throw new Error('simulated_public_write_failure');
  });
  assert.throws(() => f.create(), /simulated_public_write_failure/);
  assert.equal(f.store.list().length, 0);
  assert.equal(
    f.keys.db.prepare('SELECT COUNT(*) AS count FROM private_keys').get().count,
    0,
  );
  assert.equal(
    f.keys.db.prepare('SELECT COUNT(*) AS count FROM ticket_metadata').get()
      .count,
    0,
  );
});

test('writer decryption preserves a leading UTF-8 byte order mark when whitespace is kept', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create({ keepWhitespace: true });
  const bom = String.fromCodePoint(0xfeff);
  for (const value of [bom, `${bom}private-value`, 'plain ☃ value']) {
    const envelope = await encryptValue(ticket, value);
    const result = decryptValue(
      f.config.masterKey,
      ticket,
      f.keys.get(ticket.id),
      envelope,
    );
    assert.equal(result.value, value);
  }
});

test('an explicitly blank purge retention is rejected without deleting recent tickets', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.store.revoke(ticket.id);
  await new Promise((resolve) => setTimeout(resolve, 2));
  let stderr = '';
  const code = await runCli(['purge', '--older-than-days', ''], {
    env: {
      INTAKE_DB: f.config.dbPath,
      INTAKE_PRIVATE_DB: f.config.privateDbPath,
      INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
      INTAKE_WRITER_KEY: f.config.masterKey.toString('base64'),
    },
    stdout: {
      write() {
        assert.fail('rejected purge must not print success');
      },
    },
    stderr: {
      write(text) {
        stderr += text;
      },
    },
  });
  assert.equal(code, 1);
  assert.equal(stderr, 'intake: invalid_retention_days\n');
  assert.equal(f.store.get(ticket.id).status, 'revoked');
});

test('writer rejects socket work until permissions and startup recovery are complete', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'startup-boundary-value'));
  const vault = new MockVaultAdapter();
  const entered = Promise.withResolvers();
  const gate = Promise.withResolvers();
  const starting = startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault,
    notifyOff: true,
    socketPath: f.config.socketPath,
    logger: f.logger,
    socketPermissions: async (path, mode) => {
      await chmod(path, mode);
      entered.resolve();
      await gate.promise;
    },
  });
  t.after(async () => {
    gate.resolve();
    const writer = await starting;
    await writer.close();
  });
  await entered.promise;
  try {
    await assert.rejects(
      writerRequest(f.config.socketPath, '/process', ticket.id),
      /writer_request_failed/,
    );
    assert.equal(f.store.get(ticket.id).status, 'pending');
    assert.equal(vault.entries.length, 0);
  } finally {
    gate.resolve();
  }
  await starting;
  await waitFor(() => f.store.get(ticket.id).status === 'done');
  assert.equal(vault.entries.length, 1);
});

test('real SQLite contention recovers processing as unknown without immediate replay', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'contention-value'));
  f.store.db.pragma('busy_timeout = 5');
  const worker = new Worker(
    new URL('../support/contention-worker.js', import.meta.url),
    { workerData: { dbPath: f.config.dbPath }, execArgv: [] },
  );
  t.after(() => worker.terminate());
  assert.deepEqual(await once(worker, 'message'), ['ready']);
  let writes = 0;
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    notifyOff: true,
    socketPath: f.config.socketPath,
    pollMs: 60000,
    logger: f.logger,
    adapter: {
      async write() {
        writes++;
        const locked = once(worker, 'message');
        worker.postMessage('lock');
        assert.deepEqual(await locked, ['locked']);
        return { itemId: 'ambiguous-item-id' };
      },
    },
  });
  t.after(() => writer.close());
  await writer.drain();
  assert.equal(f.store.get(ticket.id).status, 'processing');
  await writer.drain();
  assert.equal(f.store.get(ticket.id).status, 'processing');
  const exited = once(worker, 'exit');
  worker.postMessage('release');
  await exited;
  await writer.drain();
  const unknown = f.store.get(ticket.id);
  assert.equal(unknown.status, 'unknown');
  assert.equal(unknown.failureCode, 'writer_state_failed');
  assert.equal(unknown.notifyStatus, null);
  assert.equal(unknown.notifyError, null);
  assert(unknown.envelope);
  assert(f.keys.get(ticket.id));
  assert.equal(writes, 1);
});
