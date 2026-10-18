import test from 'node:test';
import assert from 'node:assert/strict';
import { TicketStore } from '../src/db.js';
import { VaultError } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

const privateValue = 'stuck-private-value-75eb932a';

async function stuckFixture(t) {
  const resources = [];
  t.after(async () => {
    for (const close of resources.reverse()) await close();
  });
  const f = await fixture(t);
  let now = Date.now();
  return {
    ...f,
    async queue() {
      const { ticket, token } = f.create();
      const envelope = await encryptValue(ticket, privateValue);
      f.store.claim(token, envelope);
      return { ticket, token, envelope, key: f.keys.get(ticket.id) };
    },
    advance(ticket) {
      now = f.store.getState(ticket.id).nextAttemptAt;
    },
    reopen() {
      const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
      resources.push(() => store.close());
      return store;
    },
    warnings() {
      return f.logs
        .map((line) => JSON.parse(line))
        .filter((entry) => entry.event === 'ticket_stuck');
    },
    async start(adapter, options = {}) {
      const instance = await startWriter({
        store: f.store,
        keys: f.keys,
        masterKey: f.config.masterKey,
        fingerprintKey: f.config.fingerprintKey,
        adapter,
        notifyOff: true,
        socketPath: f.config.socketPath,
        pollMs: 60000,
        retryBaseMs: 1,
        retryMaxMs: 4,
        unknownSettleMs: 2,
        stuckAttempts: 3,
        logger: f.logger,
        now: () => now,
        ...options,
      });
      let closed = false;
      const close = async () => {
        if (closed) return;
        closed = true;
        await instance.close();
      };
      resources.push(close);
      await instance.drain();
      return { ...instance, close };
    },
  };
}

for (const mode of ['preflight', 'retry', 'unknown', 'lookup']) {
  test(`ticket_stuck is emitted once per ticket across restarts for ${mode} failures`, async (t) => {
    const f = await stuckFixture(t);
    const queued = [await f.queue(), await f.queue()];
    let writes = 0;
    const adapter = {
      async isReady() {
        return mode !== 'preflight';
      },
      async lookup() {
        if (mode === 'lookup') throw new VaultError('vault_http_403');
        return null;
      },
      async write() {
        writes += 1;
        const error = new VaultError('vault_http_400', mode === 'retry');
        error.ambiguous = mode !== 'retry';
        throw error;
      },
    };
    const status = ['unknown', 'lookup'].includes(mode) ? 'unknown' : 'pending';
    const code =
      mode === 'preflight'
        ? 'vault_unavailable'
        : mode === 'lookup'
          ? 'vault_http_403'
          : 'vault_http_400';
    let instance = await f.start(adapter);
    for (let attempts = 1; attempts <= 5; attempts += 1) {
      for (const { ticket, envelope, key } of queued) {
        const state = f.store.getState(ticket.id);
        assert.equal(state.status, status);
        assert.equal(state.attempts, attempts);
        assert.deepEqual(state.envelope, envelope);
        assert.equal(f.keys.get(ticket.id), key);
        assert.equal(state.notifyStatus, null);
        const warnings = f.warnings().filter((entry) => entry.id === ticket.id);
        assert.equal(warnings.length, attempts >= 3 ? 1 : 0);
        if (warnings.length) {
          const { time, ...warning } = warnings[0];
          assert.equal(typeof time, 'string');
          assert.deepEqual(warning, {
            event: 'ticket_stuck',
            id: ticket.id,
            status,
            attempts: 3,
            code,
          });
        }
      }
      await instance.drain();
      assert.equal(f.warnings().length, attempts >= 3 ? 2 : 0);
      if ([2, 3].includes(attempts)) {
        await instance.close();
        instance = await f.start(adapter, { store: f.reopen() });
        assert.equal(f.warnings().length, attempts >= 3 ? 2 : 0);
      }
      if (attempts < 5) {
        f.advance(queued[0].ticket);
        await instance.drain();
      }
    }
    if (mode === 'preflight') assert.equal(writes, 0);
    const logs = f.logs.join('');
    for (const { ticket, token, envelope } of queued)
      for (const sensitive of [
        privateValue,
        ticket.target.item,
        ticket.notifyEmail,
        token,
        envelope.ciphertext,
      ])
        assert.equal(logs.includes(sensitive), false);
  });
}

for (const threshold of [1, 10]) {
  test(`ticket_stuck honors ${threshold === 10 ? 'the default' : 'the minimum'} threshold`, async (t) => {
    const f = await stuckFixture(t);
    const { ticket } = await f.queue();
    const instance = await f.start(
      {
        async isReady() {
          return false;
        },
      },
      { stuckAttempts: threshold === 10 ? undefined : threshold },
    );
    for (let attempts = 1; attempts <= threshold + 1; attempts += 1) {
      assert.equal(f.warnings().length, attempts >= threshold ? 1 : 0);
      f.advance(ticket);
      await instance.drain();
    }
    assert.equal(f.warnings()[0].attempts, threshold);
  });
}

test('ticket_stuck fires at 31 only on the increment, never on saturated retries or restart', async (t) => {
  const f = await stuckFixture(t);
  const { ticket } = await f.queue();
  const adapter = {
    async isReady() {
      return false;
    },
  };
  let instance = await f.start(adapter, { stuckAttempts: 31 });
  for (let attempts = 1; attempts <= 35; attempts += 1) {
    assert.equal(f.store.getState(ticket.id).attempts, Math.min(attempts, 31));
    assert.equal(f.warnings().length, attempts >= 31 ? 1 : 0);
    f.advance(ticket);
    await instance.drain();
  }
  await instance.close();
  instance = await f.start(adapter, { store: f.reopen(), stuckAttempts: 31 });
  f.advance(ticket);
  await instance.drain();
  assert.equal(f.warnings().length, 1);
  assert.equal(f.warnings()[0].attempts, 31);
});

test('interrupted recovery warns only after the threshold transition commits', async (t) => {
  const f = await stuckFixture(t);
  const { ticket } = await f.queue();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    f.store.retry(ticket.id, 'vault_network', { baseMs: 1, maxMs: 4 });
    f.advance(ticket);
  }
  assert.equal(
    f.store.begin(ticket.id, f.store.getState(ticket.id).nextAttemptAt),
    true,
  );
  f.store.db
    .exec(`CREATE TRIGGER block_retry BEFORE UPDATE OF attempts ON tickets
    BEGIN SELECT RAISE(ABORT, 'unavailable'); END;`);
  await assert.rejects(f.start({}));
  assert.equal(f.store.getState(ticket.id).attempts, 2);
  assert.deepEqual(f.warnings(), []);
  f.store.db.exec('DROP TRIGGER block_retry');
  const instance = await f.start({});
  assert.equal(f.store.getState(ticket.id).attempts, 3);
  assert.equal(f.store.getState(ticket.id).status, 'unknown');
  assert.equal(f.warnings().length, 1);
  assert.equal(f.warnings()[0].code, 'writer_interrupted');
  await instance.close();
  await f.start({}, { store: f.reopen() });
  assert.equal(f.warnings().length, 1);
});

test('direct writer startup rejects invalid stuck thresholds', async (t) => {
  const f = await stuckFixture(t);
  for (const stuckAttempts of [
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    32,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    await assert.rejects(f.start({}, { stuckAttempts }), {
      code: 'invalid_intake_stuck_attempts',
    });
});
