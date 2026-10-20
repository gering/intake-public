import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { TicketStore, PrivateKeyStore } from '../src/db.js';
import { startWriter } from '../src/writer.js';
import { writerRequest } from '../src/ipc.js';
import { MailNotifier } from '../src/mail.js';
import { MockVaultAdapter } from '../src/vault.js';
import { listen } from '../src/http.js';
import { encryptValue } from '../public/crypto.js';
import { fixture, waitFor } from '../support/fixtures.js';

const sent = {
  status: 'sent',
  attempts: 1,
  error: null,
  notifiedAt: '2026-01-02T03:04:05.000Z',
};
const failed = {
  status: 'failed',
  attempts: 1,
  error: 'http_422',
  notifiedAt: null,
};

async function notificationFixture(t) {
  let writer;
  const connections = [];
  // Stop background work before closing any database connection.
  t.after(async () => {
    await writer?.close();
    for (const connection of connections) connection.close();
  });
  const f = await fixture(t);
  const vault = new MockVaultAdapter();
  return {
    ...f,
    vault,
    async queue(input) {
      const { ticket, token } = f.create(input);
      f.store.claim(
        token,
        await encryptValue(ticket, 'notification-private-value'),
      );
      return ticket;
    },
    async start(notifier, options = {}) {
      writer = await startWriter({
        store: f.store,
        keys: f.keys,
        masterKey: f.config.masterKey,
        fingerprintKey: f.config.fingerprintKey,
        adapter: vault,
        notifier,
        socketPath: f.config.socketPath,
        pollMs: 60000,
        shutdownWaitMs: 0,
        logger: f.logger,
        ...options,
      });
      return writer;
    },
    async stop() {
      const current = writer;
      writer = undefined;
      await current.close();
    },
    reopen() {
      const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
      const keys = new PrivateKeyStore(f.config.privateDbPath);
      connections.push(keys, store);
      return { store, keys };
    },
  };
}

function assertTerminal(f, id, status = 'done') {
  const state = f.store.getState(id);
  assert.equal(state.status, status);
  assert.equal(state.envelope, null);
  assert.equal(f.keys.get(id), undefined);
  assert(f.keys.getMetadata(id));
  return state;
}

test(
  'a never-resolving notification does not delay later tickets or start duplicate deliveries',
  { timeout: 5000 },
  async (t) => {
    const f = await notificationFixture(t);
    const tickets = [];
    for (let i = 0; i < 3; i += 1) tickets.push(await f.queue({ ttl: '1m' }));
    const now = Math.min(...tickets.map(({ expiresAt }) => expiresAt));
    const deliveries = [];
    const writer = await f.start(
      {
        send(ticket, { signal }) {
          deliveries.push({ ticket, signal });
          return new Promise(() => {});
        },
      },
      { now: () => now, expiryGraceMs: 0 },
    );
    await writer.drain();
    for (const ticket of tickets) {
      const state = assertTerminal(f, ticket.id);
      assert.equal(state.notifyStatus, 'pending');
      assert.equal(state.notifyAttempts, 0);
      assert.equal(f.keys.getMetadata(ticket.id).firstSeenAt, now);
    }
    assert.equal(f.vault.entries.length, 3);
    await writer.drain();
    await writer.drain();
    assert.equal(deliveries.length, 1);
    assert.equal(deliveries[0].ticket.id, tickets[0].id);
    await f.stop();
    assert.equal(deliveries[0].signal.aborted, true);
    for (const ticket of tickets)
      assert.equal(f.store.getState(ticket.id).notifyStatus, 'pending');
  },
);

test('delayed results drain the persisted notification backlog and manual retries only resend mail', async (t) => {
  const f = await notificationFixture(t);
  const tickets = [await f.queue(), await f.queue()];
  const deliveries = [];
  const writer = await f.start({
    send(ticket) {
      const gate = Promise.withResolvers();
      deliveries.push({ ticket, ...gate });
      return gate.promise;
    },
  });
  await writer.drain();
  for (const ticket of tickets) assertTerminal(f, ticket.id);
  assert.equal(deliveries.length, 1);
  deliveries[0].resolve({ ...sent, attempts: 3 });
  await waitFor(() => deliveries.length === 2);
  const first = f.store.getState(tickets[0].id);
  assert.equal(first.notifyStatus, 'sent');
  assert.equal(first.notifyAttempts, 3);
  assert.equal(first.notifyError, null);
  assert.equal(first.notifiedAt, sent.notifiedAt);
  assert.deepEqual(deliveries[1].ticket.target, tickets[1].target);
  assert.equal(deliveries[1].ticket.notifyEmail, tickets[1].notifyEmail);
  deliveries[1].resolve(failed);
  await waitFor(
    () => f.store.getState(tickets[1].id).notifyStatus === 'failed',
  );
  assert.equal(f.store.getState(tickets[1].id).notifyError, failed.error);
  assert.equal(f.store.getState(tickets[1].id).notifiedAt, null);
  await writerRequest(f.config.socketPath, '/notify-retry', tickets[1].id);
  await waitFor(() => deliveries.length === 3);
  deliveries[2].resolve({ ...sent, attempts: 2 });
  await waitFor(() => f.store.getState(tickets[1].id).notifyStatus === 'sent');
  assert.equal(f.store.getState(tickets[1].id).notifyAttempts, 3);
  assert.equal(f.store.getState(tickets[1].id).notifyError, null);
  assert.equal(f.vault.entries.length, 2);
  for (const ticket of tickets) assertTerminal(f, ticket.id);
});

test(
  'pending notifications and manual retries advance while unrelated vault work is stalled',
  { timeout: 5000 },
  async (t) => {
    const vaultGate = Promise.withResolvers();
    const enteredVault = Promise.withResolvers();
    // Release before shutdown waits for the current vault write, including on failure.
    t.after(() => vaultGate.resolve());
    const f = await notificationFixture(t);
    const terminal = [await f.queue(), await f.queue()];
    for (const ticket of terminal) {
      f.store.begin(ticket.id);
      f.store.finish(ticket.id, '0123456789abcdef');
    }
    const pending = await f.queue();
    const deliveries = [];
    const writer = await f.start(
      {
        send(ticket) {
          const gate = Promise.withResolvers();
          deliveries.push({ ticket, ...gate });
          return gate.promise;
        },
      },
      {
        adapter: {
          async write() {
            enteredVault.resolve();
            await vaultGate.promise;
          },
        },
      },
    );
    try {
      await enteredVault.promise;
      assert.equal(deliveries.length, 1);
      deliveries[0].resolve(sent);
      await waitFor(() => deliveries.length === 2);
      assert.equal(deliveries[1].ticket.id, terminal[1].id);
      deliveries[1].resolve(failed);
      await waitFor(
        () => f.store.getState(terminal[1].id).notifyStatus === 'failed',
      );
      assert.equal(f.store.getState(pending.id).status, 'processing');
      await writerRequest(f.config.socketPath, '/notify-retry', terminal[1].id);
      await waitFor(() => deliveries.length === 3);
      deliveries[2].resolve(sent);
      await waitFor(
        () => f.store.getState(terminal[1].id).notifyStatus === 'sent',
      );
      assert.equal(f.store.getState(pending.id).status, 'processing');
      for (const ticket of terminal) assertTerminal(f, ticket.id);
    } finally {
      vaultGate.resolve();
    }
    await writer.drain();
    assertTerminal(f, pending.id);
  },
);

for (const shutdownWaitMs of [undefined, 2000]) {
  test(
    `shutdown records an in-flight notification that finishes within the ${shutdownWaitMs ?? 'default'} wait`,
    { timeout: 5000 },
    async (t) => {
      const f = await notificationFixture(t);
      const ticket = await f.queue();
      const gate = Promise.withResolvers();
      let deliverySignal;
      const writer = await f.start(
        {
          send(_ticket, { signal }) {
            deliverySignal = signal;
            return gate.promise;
          },
        },
        { shutdownWaitMs },
      );
      await writer.drain();
      const completion = setTimeout(() => gate.resolve(sent), 50);
      t.after(() => clearTimeout(completion));
      await f.stop();
      assert.equal(assertTerminal(f, ticket.id).notifyStatus, 'sent');
      assert.equal(deliverySignal.aborted, false);
      const logs = f.logs.map((line) => JSON.parse(line));
      assert.equal(
        logs.filter((line) => line.event === 'notification_result').length,
        1,
      );
      assert(
        !logs.some((line) => line.event === 'shutdown_notification_pending'),
      );
    },
  );
}

for (const shutdownWaitMs of [100, 0]) {
  test(
    shutdownWaitMs === 0
      ? 'zero shutdown wait immediately aborts an in-flight notification and ignores late results'
      : 'shutdown bounds an abort-ignoring notification wait and ignores late results',
    { timeout: 5000 },
    async (t) => {
      const f = await notificationFixture(t);
      const ticket = await f.queue();
      const gate = Promise.withResolvers();
      let deliverySignal;
      const writer = await f.start(
        {
          send(_ticket, { signal }) {
            deliverySignal = signal;
            return gate.promise;
          },
        },
        { shutdownWaitMs },
      );
      await writer.drain();
      const started = performance.now();
      const closing = f.stop();
      if (shutdownWaitMs === 0) assert.equal(deliverySignal.aborted, true);
      else assert.equal(deliverySignal.aborted, false);
      let deadline;
      try {
        // Keep the test alive even though the writer's deadline is unref'ed.
        await Promise.race([
          closing,
          new Promise((_, reject) => {
            deadline = setTimeout(
              () => reject(new Error('shutdown_test_timeout')),
              1000,
            );
          }),
        ]);
      } finally {
        clearTimeout(deadline);
      }
      assert(performance.now() - started < 1000);
      assert.equal(deliverySignal.aborted, true);
      let state = assertTerminal(f, ticket.id);
      assert.equal(state.notifyStatus, 'pending');
      assert.equal(state.notifyAttempts, 0);
      const pending = f.logs
        .map((line) => JSON.parse(line))
        .filter((line) => line.event === 'shutdown_notification_pending');
      assert.equal(pending.length, 1);
      assert.deepEqual(pending[0], {
        time: pending[0].time,
        event: 'shutdown_notification_pending',
        id: ticket.id,
        waitedMs: shutdownWaitMs,
      });
      gate.resolve(sent);
      await new Promise((resolve) => setImmediate(resolve));
      state = f.store.getState(ticket.id);
      assert.equal(state.notifyStatus, 'pending');
      assert.equal(state.notifyAttempts, 0);
      assert(
        !f.logs.some(
          (line) => JSON.parse(line).event === 'notification_result',
        ),
      );
      assert(!f.logs.join('').includes(ticket.notifyEmail));
      assert(!f.logs.join('').includes('notification-private-value'));
    },
  );
}

test(
  'shutdown stops the socket, notification backlog and new vault work while allowing in-flight work to finish',
  { timeout: 5000 },
  async (t) => {
    const vaultGate = Promise.withResolvers();
    const enteredVault = Promise.withResolvers();
    t.after(() => vaultGate.resolve());
    const f = await notificationFixture(t);
    const terminal = [await f.queue(), await f.queue()];
    for (const ticket of terminal) {
      f.store.begin(ticket.id);
      f.store.finish(ticket.id, '0123456789abcdef');
    }
    const pending = [await f.queue(), await f.queue()];
    const mailGate = Promise.withResolvers();
    const deliveries = [];
    const writer = await f.start(
      {
        send(ticket) {
          deliveries.push(ticket.id);
          return mailGate.promise;
        },
      },
      {
        shutdownWaitMs: 2000,
        pollMs: 10,
        adapter: {
          async write(input) {
            enteredVault.resolve();
            await vaultGate.promise;
            await f.vault.write(input);
          },
        },
      },
    );
    try {
      await enteredVault.promise;
      const closing = f.stop();
      let closed = false;
      void closing.then(() => {
        closed = true;
      });
      assert.equal(writer.server.listening, false);
      await assert.rejects(
        writerRequest(f.config.socketPath, '/process', pending[1].id),
      );
      void writer.drain();
      mailGate.resolve(sent);
      await waitFor(
        () => f.store.getState(terminal[0].id).notifyStatus === 'sent',
      );
      assert.equal(closed, false);
      assert.deepEqual(deliveries, [terminal[0].id]);
      assert.equal(f.store.getState(terminal[1].id).notifyStatus, 'pending');
      assert.equal(f.store.getState(pending[0].id).status, 'processing');
      assert.equal(f.store.getState(pending[1].id).status, 'pending');
      vaultGate.resolve();
      await closing;
      await writer.drain();
      assert.equal(f.vault.entries.length, 1);
      assert.equal(f.store.getState(pending[0].id).status, 'done');
      assert.equal(f.store.getState(pending[0].id).notifyStatus, 'pending');
      assert.equal(f.store.getState(pending[1].id).status, 'pending');
      assert.deepEqual(deliveries, [terminal[0].id]);
      assert(
        !f.logs.some(
          (line) => JSON.parse(line).event === 'shutdown_notification_pending',
        ),
      );
    } finally {
      mailGate.resolve(sent);
      vaultGate.resolve();
    }
  },
);

test(
  'restart recovers an abandoned delivery and ignores late results from the stopped writer',
  { timeout: 5000 },
  async (t) => {
    const f = await notificationFixture(t);
    const ticket = await f.queue();
    const gate = Promise.withResolvers();
    let oldSignal;
    const writer = await f.start({
      send(_ticket, { signal }) {
        oldSignal = signal;
        return gate.promise;
      },
    });
    await writer.drain();
    const before = assertTerminal(f, ticket.id);
    assert.equal(before.notifyStatus, 'pending');
    await f.stop();
    assert.equal(oldSignal.aborted, true);
    const reopened = f.reopen();
    assert.equal(reopened.store.getState(ticket.id).notifyStatus, 'pending');
    let recovered = 0;
    const restarted = await f.start(
      {
        async send(input) {
          recovered += 1;
          assert.equal(input.id, ticket.id);
          assert.equal(input.notifyEmail, ticket.notifyEmail);
          return sent;
        },
      },
      reopened,
    );
    await restarted.drain();
    await waitFor(() => f.store.getState(ticket.id).notifyStatus === 'sent');
    gate.resolve(failed);
    await new Promise((resolve) => setImmediate(resolve));
    const after = assertTerminal(f, ticket.id);
    assert.equal(after.notifyStatus, 'sent');
    assert.equal(after.notifyAttempts, 1);
    assert.equal(after.notifyError, null);
    assert.equal(after.completedAt, before.completedAt);
    assert.equal(after.fingerprint, before.fingerprint);
    assert.equal(recovered, 1);
    assert.equal(f.vault.entries.length, 1);
  },
);

for (const failure of ['send', 'record']) {
  test(`notification ${failure} exceptions leave recoverable pending work without blocking tickets`, async (t) => {
    const f = await notificationFixture(t);
    const tickets = [await f.queue(), await f.queue()];
    const record = f.store.recordNotification.bind(f.store);
    let unavailable = true;
    if (failure === 'record') {
      t.mock.method(f.store, 'recordNotification', (...args) => {
        if (unavailable) throw new Error('private-notification-error');
        return record(...args);
      });
    }
    const writer = await f.start({
      async send() {
        if (unavailable && failure === 'send')
          throw new Error('private-notification-error');
        return sent;
      },
    });
    await writer.drain();
    for (const ticket of tickets) {
      const state = assertTerminal(f, ticket.id);
      assert.equal(state.notifyStatus, 'pending');
      assert.equal(state.notifyAttempts, 0);
    }
    unavailable = false;
    await writer.drain();
    await waitFor(() =>
      tickets.every(({ id }) => f.store.getState(id).notifyStatus === 'sent'),
    );
    for (const ticket of tickets)
      assert.equal(f.store.getState(ticket.id).notifyAttempts, 1);
    assert.equal(f.vault.entries.length, 2);
    assert(
      f.logs.some((line) => JSON.parse(line).event === 'writer_loop_error'),
    );
    assert(!f.logs.join('').includes('private-notification-error'));
    assert(!f.logs.join('').includes('notification-private-value'));
  });
}

test(
  'a hanging mail endpoint leaves ticket processing independent and shutdown cancels HTTP delivery',
  { timeout: 5000 },
  async (t) => {
    const f = await notificationFixture(t);
    const received = Promise.withResolvers();
    const disconnected = Promise.withResolvers();
    let requests = 0;
    const server = createServer(async (req, res) => {
      for await (const chunk of req) void chunk;
      requests += 1;
      res.on('close', disconnected.resolve);
      received.resolve();
    });
    await listen(server, { host: '127.0.0.1', port: 0 });
    t.after(
      () =>
        new Promise((resolve) => {
          server.close(resolve);
          server.closeAllConnections();
        }),
    );
    const first = await f.queue();
    const writer = await f.start(
      new MailNotifier({
        url: `http://127.0.0.1:${server.address().port}`,
        token: 'notification-test-token',
        mailbox: 'intake@example.com',
        timeoutMs: 60000,
      }),
      { shutdownWaitMs: 100 },
    );
    await received.promise;
    const second = await f.queue();
    await writer.drain();
    for (const ticket of [first, second]) {
      const state = assertTerminal(f, ticket.id);
      assert.equal(state.notifyStatus, 'pending');
    }
    assert.equal(requests, 1);
    await f.stop();
    await disconnected.promise;
    assert.equal(f.store.getState(first.id).notifyStatus, 'pending');
    assert.equal(f.store.getState(first.id).notifyAttempts, 0);
  },
);
