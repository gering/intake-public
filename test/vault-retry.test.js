import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { TicketStore } from '../src/db.js';
import { listen, closeServer } from '../src/http.js';
import { BwServeAdapter, VaultError } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

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
      await execute(process.execPath, [
        '--input-type=module',
        '-e',
        "import { createServer } from 'node:net'; createServer().listen(process.argv[1], () => process.exit(0));",
        socketPath,
      ]);
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
