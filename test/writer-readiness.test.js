import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { BwServeAdapter } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { listen, closeServer } from '../src/http.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

async function writerFixture(t, f, adapter, notifier, overrides = {}) {
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter,
    notifier,
    notifyOff: !notifier,
    socketPath: f.config.socketPath,
    pollMs: 60000,
    logger: f.logger,
    ...overrides,
  });
  t.after(() => writer.close());
  return writer;
}

async function queue(f) {
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'readiness-private-value'));
  return ticket;
}

function assertQueued(f, ticket) {
  const stored = f.store.get(ticket.id);
  assert.equal(stored.status, 'pending');
  assert(stored.envelope);
  assert(f.keys.get(ticket.id));
}

test('writer leaves reboot-time queued work intact until the Unix vault is unlocked and recovers after downtime', async (t) => {
  const f = await fixture(t);
  const first = await queue(f);
  const socketPath = join(f.dir, 'vault.sock');
  const vault = new BwServeAdapter({
    socketPath,
    organizationId: 'organization',
    collectionId: 'collection',
    timeoutMs: 100,
  });
  let now = Date.now();
  const writer = await writerFixture(t, f, vault, undefined, {
    now: () => now,
  });
  await writer.drain();
  assertQueued(f, first);
  const transitions = () =>
    f.logs
      .map((line) => JSON.parse(line).event)
      .filter((event) =>
        ['vault_unavailable', 'vault_available'].includes(event),
      );
  assert.deepEqual(transitions(), ['vault_unavailable']);

  let status = 'locked';
  let writes = 0;
  const server = createServer((req, res) => {
    assert.equal(req.headers.host, 'localhost:8087');
    assert.equal(req.headers.origin, undefined);
    if (req.url === '/status') {
      assert.equal(req.method, 'GET');
      res.end(
        JSON.stringify({ success: true, data: { template: { status } } }),
      );
    } else {
      assert.equal(req.method, 'POST');
      assert.equal(req.url, '/object/item');
      req.resume();
      writes += 1;
      res.end(
        JSON.stringify({ success: true, data: { id: `item-${writes}` } }),
      );
    }
  });
  await listen(server, socketPath);
  t.after(() => closeServer(server));
  now += 5000;
  await writer.drain();
  assertQueued(f, first);
  assert.equal(writes, 0);
  assert.deepEqual(transitions(), ['vault_unavailable']);
  status = 'unlocked';
  now += 10000;
  await writer.drain();
  assert.equal(f.store.get(first.id).status, 'done');
  assert.equal(writes, 1);
  assert.deepEqual(transitions(), ['vault_unavailable', 'vault_available']);

  const second = await queue(f);
  await closeServer(server);
  await writer.drain();
  assertQueued(f, second);
  await listen(server, socketPath);
  now += 5000;
  await writer.drain();
  assert.equal(f.store.get(second.id).status, 'done');
  assert.equal(writes, 2);
  assert.deepEqual(transitions(), [
    'vault_unavailable',
    'vault_available',
    'vault_unavailable',
    'vault_available',
  ]);
  await queue(f);
  await writer.drain();
  assert.equal(writes, 3);
  assert.equal(transitions().length, 4);
  assert(!f.logs.join('').includes('readiness-private-value'));
});

test('vault readiness failures do not block terminal mail or probe once per queued ticket', async (t) => {
  const f = await fixture(t);
  const pending = await queue(f);
  await queue(f);
  const { ticket: done } = f.create();
  f.store.db
    .prepare(
      "UPDATE tickets SET status = 'done', notify_status = 'pending' WHERE id = ?",
    )
    .run(done.id);
  let probes = 0;
  let mails = 0;
  const writer = await writerFixture(
    t,
    f,
    {
      isReady: async () => {
        probes += 1;
        return false;
      },
      write: async () => assert.fail('Unavailable vault received a write'),
    },
    {
      send: async () => {
        mails += 1;
        return {
          status: 'sent',
          attempts: 1,
          error: null,
          notifiedAt: new Date().toISOString(),
        };
      },
    },
  );
  await writer.drain();
  assertQueued(f, pending);
  assert.equal(f.store.get(done.id).notifyStatus, 'sent');
  assert.equal(mails, 1);
  assert.equal(probes, 1);
});

test('throwing readiness probes emit one outage event and one recovery event across drains', async (t) => {
  const f = await fixture(t);
  const tickets = [await queue(f), await queue(f)];
  let now = Date.now();
  let available = false;
  let writes = 0;
  const writer = await writerFixture(
    t,
    f,
    {
      async isReady() {
        if (!available) throw new Error('private-upstream-readiness-response');
        return true;
      },
      async write() {
        writes += 1;
        return { itemId: `item-${writes}` };
      },
    },
    undefined,
    { now: () => now },
  );
  await writer.drain();
  now += 5000;
  await writer.drain();
  for (const ticket of tickets) assertQueued(f, ticket);
  assert.equal(writes, 0);
  assert.equal(
    f.logs.filter((line) => JSON.parse(line).event === 'vault_unavailable')
      .length,
    1,
  );
  available = true;
  now += 10000;
  await writer.drain();
  assert.equal(writes, 2);
  assert.equal(
    f.logs.filter((line) => JSON.parse(line).event === 'vault_available')
      .length,
    1,
  );
  assert(!f.logs.join('').includes('private-upstream-readiness-response'));
});

test('a failure after successful preflight still consumes the ticket and never replays a write', async (t) => {
  const f = await fixture(t);
  const ticket = await queue(f);
  let writes = 0;
  const writer = await writerFixture(t, f, {
    isReady: async () => true,
    write: async () => {
      writes += 1;
      throw new Error('ambiguous vault failure');
    },
  });
  await writer.drain();
  assert.equal(f.store.get(ticket.id).status, 'failed');
  assert.equal(f.store.get(ticket.id).envelope, null);
  assert.equal(f.keys.get(ticket.id), undefined);
  await writer.drain();
  assert.equal(writes, 1);
});

test('production readiness rejects unsuccessful and malformed status envelopes without exposing responses', async (t) => {
  const f = await fixture(t);
  const socketPath = join(f.dir, 'vault.sock');
  let body = '{"success":true,"data":{"template":{"status":"unlocked"}}}';
  let code = 200;
  const server = createServer((_req, res) => {
    res.writeHead(code);
    res.end(body);
  });
  await listen(server, socketPath);
  t.after(() => closeServer(server));
  const vault = new BwServeAdapter({
    socketPath,
    organizationId: 'organization',
    collectionId: 'collection',
  });
  assert.equal(await vault.isReady(), true);
  for (const invalid of [
    '{"success":false,"data":{"template":{"status":"unlocked"}}}',
    '{"success":true,"data":{"template":{"status":"locked"}}}',
    '{"success":true,"data":{"status":"unlocked"}}',
    'sensitive-upstream-error',
  ]) {
    body = invalid;
    assert.equal(await vault.isReady(), false);
  }
  code = 503;
  assert.equal(await vault.isReady(), false);
});
