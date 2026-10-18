import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { TicketStore, PrivateKeyStore } from '../src/db.js';
import { ticketFingerprint } from '../src/fingerprint.js';
import { listen, closeServer } from '../src/http.js';
import { BwServeAdapter, VaultError } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

const privateValue = 'unknown-private-value-682cbecd';
const organizationId = 'unknown-organization';
const collectionId = 'unknown-collection';
const listPath = `/list/object/items?collectionId=${collectionId}`;
const settleMs = 120000;

async function unknownFixture(t) {
  const resources = [];
  // Hooks run in registration order: stop network activity before closing SQLite.
  t.after(async () => {
    for (const close of resources.reverse()) await close();
  });
  return {
    ...(await fixture(t)),
    cleanup: (close) => resources.push(close),
  };
}

function input(field = 'password') {
  return {
    target: {
      item: 'Unknown outcome example',
      field,
      notes: 'unknown-private-notes-5b9da7',
    },
    keyName: 'UNKNOWN_KEY',
    purpose: 'Resolve an uncertain item write',
    value: privateValue,
    ticketId: 'unknown-ticket',
    fingerprint: '0123456789abcdef',
  };
}

function markerName(field, name) {
  return field === name ? `${name}_reference` : name;
}

function markedItem(entry = input(), overrides = {}) {
  return {
    id: 'existing-item',
    organizationId,
    collectionIds: [collectionId],
    fields: [
      {
        name: markerName(entry.target.field, 'intake_ticket_id'),
        value: entry.ticketId,
        type: 0,
      },
      {
        name: markerName(entry.target.field, 'intake_fingerprint'),
        value: entry.fingerprint,
        type: 0,
      },
    ],
    ...overrides,
  };
}

function json(response, status, data) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(data));
}

async function serve(f, hooks = {}, options = {}) {
  const vault = {
    requests: [],
    posts: [],
    items: [],
    socketPath: join(f.dir, 'vault.sock'),
    ...hooks,
    save(body) {
      const item = { ...body, id: `vault-item-${this.items.length + 1}` };
      this.items.push(item);
      return item;
    },
  };
  const server = createServer((request, response) => {
    vault.requests.push({ method: request.method, path: request.url });
    request.on('error', () => {});
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      if (request.method === 'GET' && request.url === '/status') {
        json(response, 200, {
          success: true,
          data: { template: { status: 'unlocked' } },
        });
      } else if (request.method === 'POST' && request.url === '/sync') {
        if (vault.onSync) vault.onSync(request, response);
        else json(response, 200, { success: true, data: {} });
      } else if (request.method === 'GET' && request.url === listPath) {
        if (vault.onList) vault.onList(request, response);
        else
          json(response, 200, {
            success: true,
            data: { object: 'list', data: vault.items },
          });
      } else if (request.method === 'POST' && request.url === '/object/item') {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        vault.posts.push(body);
        if (vault.onItem) vault.onItem(request, response, body);
        else {
          const item = vault.save(body);
          json(response, 200, { success: true, data: { id: item.id } });
        }
      } else json(response, 404, { success: false });
    });
  });
  await listen(server, vault.socketPath);
  f.cleanup(async () => {
    const closed = closeServer(server);
    server.closeAllConnections();
    await closed;
  });
  vault.adapter = new BwServeAdapter({
    socketPath: vault.socketPath,
    organizationId,
    collectionId,
    timeoutMs: 1000,
    ...options,
  });
  return vault;
}

async function queue(f, options = {}) {
  const { ticket, token } = f.create(options);
  const envelope = await encryptValue(f.store.open(token), privateValue);
  f.store.claim(token, envelope);
  return { ticket, token, envelope, key: f.keys.get(ticket.id) };
}

function queuedInput(f, queued) {
  const metadata = f.keys.getMetadata(queued.ticket.id);
  return {
    target: metadata.target,
    keyName: metadata.keyName,
    purpose: metadata.purpose,
    value: privateValue,
    ticketId: queued.ticket.id,
    fingerprint: ticketFingerprint(
      f.config.fingerprintKey,
      queued.ticket.id,
      privateValue,
    ),
  };
}

async function writer(f, vault, options = {}) {
  const notifications = [];
  const instance = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault.adapter,
    socketPath: f.config.socketPath,
    pollMs: 60000,
    retryBaseMs: 5000,
    retryMaxMs: 12000,
    logger: f.logger,
    notifier: {
      async send(ticket) {
        const persisted = f.store.getState(ticket.id);
        assert.equal(persisted.status, 'done');
        assert.equal(persisted.notifyStatus, 'pending');
        assert.equal(persisted.fingerprint, ticket.fingerprint);
        assert.equal(persisted.envelope, null);
        assert.equal(f.keys.get(ticket.id), undefined);
        assert.equal(JSON.stringify(ticket).includes(privateValue), false);
        notifications.push(ticket);
        return {
          status: 'sent',
          attempts: 1,
          error: null,
          notifiedAt: new Date().toISOString(),
        };
      },
    },
    ...options,
  });
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await instance.close();
  };
  f.cleanup(close);
  await instance.drain();
  return { ...instance, close, notifications };
}

function assertUnknown(f, queued, attempts, due, code) {
  const state = f.store.getState(queued.ticket.id);
  assert.equal(state.status, 'unknown');
  assert.equal(state.attempts, attempts);
  assert.equal(state.nextAttemptAt, due);
  if (code !== undefined) assert.equal(state.failureCode, code);
  assert.deepEqual(state.envelope, queued.envelope);
  assert.equal(f.keys.get(queued.ticket.id), queued.key);
  assert.equal(state.fingerprint, null);
  assert.equal(state.completedAt, null);
  assert.equal(state.notifyStatus, null);
  return state;
}

function assertDone(f, queued, instance) {
  const state = f.store.getState(queued.ticket.id);
  assert.equal(state.status, 'done');
  assert.equal(
    state.fingerprint,
    ticketFingerprint(f.config.fingerprintKey, queued.ticket.id, privateValue),
  );
  assert.equal(state.envelope, null);
  assert.equal(state.failureCode, null);
  assert.equal(state.nextAttemptAt, 0);
  assert.equal(f.keys.get(queued.ticket.id), undefined);
  assert.notEqual(f.keys.getMetadata(queued.ticket.id), null);
  assert.equal(state.notifyStatus, 'sent');
  assert.equal(state.notifyAttempts, 1);
  assert.equal(instance.notifications.length, 1);
  assert.equal(instance.notifications[0].status, 'done');
  assert.equal(instance.notifications[0].fingerprint, state.fingerprint);
  assert.equal(
    instance.notifications[0].notifyEmail,
    f.keys.getMetadata(queued.ticket.id).notifyEmail,
  );
  assertSafeLogs(f);
}

function assertSafeLogs(f) {
  const logs = f.logs.join('');
  for (const value of [
    privateValue,
    input().target.notes,
    input().target.item,
    f.config.defaultNotifyEmail,
  ]) {
    assert.equal(logs.includes(value), false, 'logs exclude private input');
  }
}

async function assertQuietUntil(instance, vault, setNow, due) {
  const before = vault.requests.length;
  await instance.drain();
  setNow(due - 1);
  await instance.drain();
  await instance.drain();
  assert.equal(vault.requests.length, before);
  assert.equal(instance.notifications.length, 0);
}

function classified(code, ambiguous, preDelivery = false) {
  return (error) => {
    assert(error instanceof VaultError);
    assert.equal(error.code, code);
    assert.equal(error.preDelivery, preDelivery);
    assert.equal(error.ambiguous, ambiguous);
    assert.equal(error.message, 'Vault operation failed.');
    assert.equal(error.cause, undefined);
    assert.equal(
      `${error.stack} ${JSON.stringify(error)}`.includes(privateValue),
      false,
      'vault errors exclude private response bodies',
    );
    return true;
  };
}

for (const failure of ['reset', 'timeout']) {
  test(`stored Unix POST with ${failure} settles before lookup and completes without a duplicate`, async (t) => {
    const f = await unknownFixture(t);
    const queued = await queue(f);
    let now = Date.now();
    const vault = await serve(
      f,
      {
        onItem(request, _response, body) {
          vault.save(body);
          if (failure === 'reset') request.socket.destroy();
          // A timeout deliberately leaves the response open after storing the item.
        },
      },
      { timeoutMs: failure === 'timeout' ? 150 : 1000 },
    );
    const instance = await writer(f, vault, { now: () => now });
    const due = now + settleMs;
    assertUnknown(
      f,
      queued,
      1,
      due,
      failure === 'reset' ? 'vault_network' : 'vault_timeout',
    );
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 1);
    assert.deepEqual(vault.requests, [
      { method: 'GET', path: '/status' },
      { method: 'POST', path: '/object/item' },
    ]);
    await assertQuietUntil(instance, vault, (value) => (now = value), due);
    assertUnknown(f, queued, 1, due);
    now = due;
    await instance.drain();
    assertDone(f, queued, instance);
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 1);
    assert.deepEqual(vault.requests.slice(2), [
      { method: 'POST', path: '/sync' },
      { method: 'GET', path: listPath },
    ]);
    const count = vault.requests.length;
    now += settleMs;
    await instance.drain();
    assert.equal(vault.requests.length, count);
    assert.equal(instance.notifications.length, 1);
  });
}

test('a lost Unix POST with no stored item makes exactly one replacement after an empty settled lookup', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  const vault = await serve(f, {
    onItem(request) {
      request.socket.destroy();
    },
  });
  const instance = await writer(f, vault, { now: () => now });
  const due = now + settleMs;
  assertUnknown(f, queued, 1, due, 'vault_network');
  assert.equal(vault.items.length, 0);
  vault.onItem = undefined;
  await assertQuietUntil(instance, vault, (value) => (now = value), due);
  now = due;
  await instance.drain();
  assertDone(f, queued, instance);
  assert.equal(vault.posts.length, 2);
  assert.equal(vault.items.length, 1);
  assert.deepEqual(vault.requests.slice(2), [
    { method: 'POST', path: '/sync' },
    { method: 'GET', path: listPath },
    { method: 'POST', path: '/object/item' },
  ]);
  assert.deepEqual(vault.posts[0], vault.posts[1]);
  await instance.drain();
  assert.equal(vault.posts.length, 2);
});

test('an ambiguous replacement POST starts a fresh settle interval before another lookup', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  const customSettleMs = 23000;
  const vault = await serve(f, {
    onItem(request, _response, body) {
      if (vault.posts.length === 2) vault.save(body);
      request.socket.destroy();
    },
  });
  const instance = await writer(f, vault, {
    now: () => now,
    unknownSettleMs: customSettleMs,
  });
  const firstDue = now + customSettleMs;
  assertUnknown(f, queued, 1, firstDue);
  await assertQuietUntil(instance, vault, (value) => (now = value), firstDue);
  now = firstDue;
  await instance.drain();
  const secondDue = now + customSettleMs;
  assertUnknown(f, queued, 2, secondDue, 'vault_network');
  assert.equal(vault.posts.length, 2);
  assert.equal(vault.items.length, 1);
  await assertQuietUntil(instance, vault, (value) => (now = value), secondDue);
  now = secondDue;
  await instance.drain();
  assertDone(f, queued, instance);
  assert.equal(vault.posts.length, 2);
  assert.equal(vault.items.length, 1);
  assert.deepEqual(vault.requests.slice(2), [
    { method: 'POST', path: '/sync' },
    { method: 'GET', path: listPath },
    { method: 'POST', path: '/object/item' },
    { method: 'POST', path: '/sync' },
    { method: 'GET', path: listPath },
  ]);
});

const responseFailures = [
  [
    'malformed 2xx',
    'vault_response',
    (_request, response) => response.end(privateValue),
  ],
  [
    'unsuccessful 2xx',
    'vault_response',
    (_request, response) =>
      json(response, 200, { success: false, message: privateValue }),
  ],
  [
    'missing item ID',
    'vault_response',
    (_request, response) => json(response, 200, { success: true, data: {} }),
  ],
  [
    'blank item ID',
    'vault_response',
    (_request, response) =>
      json(response, 200, { success: true, data: { id: ' ' } }),
  ],
  [
    'invalid item ID type',
    'vault_response',
    (_request, response) =>
      json(response, 200, { success: true, data: { id: 42 } }),
  ],
  [
    'oversized 2xx',
    'vault_response_too_large',
    (_request, response) =>
      json(response, 200, {
        success: true,
        data: { id: privateValue.repeat(100) },
      }),
  ],
  [
    'HTTP 500',
    'vault_http_500',
    (_request, response) =>
      json(response, 500, { success: false, message: privateValue }),
  ],
  [
    'HTTP 400',
    'vault_http_400',
    (_request, response) =>
      json(response, 400, { success: false, message: privateValue }),
  ],
  [
    'HTTP 503',
    'vault_http_503',
    (_request, response) =>
      json(response, 503, { success: false, message: privateValue }),
  ],
];

for (const [name, code, respond] of responseFailures) {
  test(`item ${name} is an ambiguous VaultError with no private response data`, async (t) => {
    const f = await unknownFixture(t);
    const vault = await serve(
      f,
      { onItem: respond },
      { maxResponseBytes: 1024 },
    );
    await assert.rejects(vault.adapter.write(input()), classified(code, true));
    assert.deepEqual(vault.requests, [
      { method: 'POST', path: '/object/item' },
    ]);
  });

  test(`stored item ${name} remains unknown until a settled lookup confirms it`, async (t) => {
    const f = await unknownFixture(t);
    const queued = await queue(f);
    let now = Date.now();
    const vault = await serve(
      f,
      {
        onItem(request, response, body) {
          vault.save(body);
          respond(request, response);
        },
      },
      { maxResponseBytes: 1024 },
    );
    const instance = await writer(f, vault, { now: () => now });
    const due = now + settleMs;
    assertUnknown(f, queued, 1, due, code);
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 1);
    await assertQuietUntil(instance, vault, (value) => (now = value), due);
    now = due;
    await instance.drain();
    assertDone(f, queued, instance);
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 1);
  });
}

for (const status of [400, 401, 403, 409, 429]) {
  test(`item HTTP ${status} cannot prove the upstream create was rejected`, async (t) => {
    const f = await unknownFixture(t);
    const vault = await serve(f, {
      onItem(_request, response) {
        json(response, status, { success: false, message: privateValue });
      },
    });
    await assert.rejects(
      vault.adapter.write(input()),
      classified(`vault_http_${status}`, true),
    );
  });
}

for (const phase of ['sync', 'list']) {
  test(`unknown lookup ${phase} failures retain material and use doubling capped backoff, not a new settle`, async (t) => {
    const f = await unknownFixture(t);
    const queued = await queue(f);
    let now = Date.now();
    const vault = await serve(f, {
      onItem(request, _response, body) {
        vault.save(body);
        request.socket.destroy();
      },
    });
    const instance = await writer(f, vault, { now: () => now });
    const firstDue = now + settleMs;
    assertUnknown(f, queued, 1, firstDue);
    const hook = phase === 'sync' ? 'onSync' : 'onList';
    vault[hook] = (_request, response) =>
      json(response, 503, { success: false, message: privateValue });
    now = firstDue;
    for (const [index, delay] of [10000, 12000, 12000].entries()) {
      await instance.drain();
      const due = now + delay;
      assertUnknown(f, queued, index + 2, due, 'vault_http_503');
      assert.equal(vault.posts.length, 1);
      assert.equal(vault.items.length, 1);
      assert.equal(instance.notifications.length, 0);
      await assertQuietUntil(instance, vault, (value) => (now = value), due);
      now = due;
    }
    assert.equal(
      vault.requests.filter(({ path }) => path === listPath).length,
      phase === 'sync' ? 0 : 3,
    );
    vault[hook] = undefined;
    await instance.drain();
    assertDone(f, queued, instance);
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 1);
  });
}

const lookupFailures = [
  [
    'malformed response',
    'vault_response',
    (_request, response) => response.end(privateValue),
  ],
  [
    'unsuccessful response',
    'vault_response',
    (_request, response) =>
      json(response, 200, { success: false, message: privateValue }),
  ],
  [
    'invalid list shape',
    'vault_response',
    (_request, response) =>
      json(response, 200, {
        success: true,
        data: { object: 'list', data: {} },
      }),
  ],
  [
    'missing list data',
    'vault_response',
    (_request, response) =>
      json(response, 200, { success: true, data: { object: 'list' } }),
  ],
  ['connected reset', 'vault_network', (request) => request.socket.destroy()],
  ['timeout', 'vault_timeout', () => {}],
  [
    'oversized list',
    'vault_lookup_too_large',
    (_request, response) =>
      json(response, 200, {
        success: true,
        data: { object: 'list', data: [{ notes: privateValue.repeat(100) }] },
      }),
  ],
];

for (const [name, code, respond] of lookupFailures) {
  test(`unknown lookup ${name} is not an empty lookup and never triggers a replacement`, async (t) => {
    const f = await unknownFixture(t);
    const queued = await queue(f);
    let now = Date.now();
    const vault = await serve(
      f,
      {
        onItem(request) {
          request.socket.destroy();
        },
        onList: respond,
      },
      { maxResponseBytes: 1024, timeoutMs: name === 'timeout' ? 150 : 1000 },
    );
    const instance = await writer(f, vault, { now: () => now });
    now += settleMs;
    await instance.drain();
    const due = now + 10000;
    assertUnknown(f, queued, 2, due, code);
    assert.equal(vault.posts.length, 1);
    assert.equal(vault.items.length, 0);
    assert.deepEqual(vault.requests.slice(2), [
      { method: 'POST', path: '/sync' },
      { method: 'GET', path: listPath },
    ]);
    if (code === 'vault_lookup_too_large')
      assert(f.logs.some((line) => line.includes('vault_lookup_too_large')));
    assertSafeLogs(f);
    await assertQuietUntil(instance, vault, (value) => (now = value), due);
    vault.onList = undefined;
    vault.onItem = undefined;
    now = due;
    await instance.drain();
    assertDone(f, queued, instance);
    assert.equal(vault.posts.length, 2);
    assert.equal(vault.items.length, 1);
  });
}

const nearMisses = [
  [
    'different organization',
    (item) => ({ ...item, organizationId: `${organizationId}-other` }),
  ],
  ['missing organization', (item) => ({ ...item, organizationId: undefined })],
  [
    'different collection',
    (item) => ({ ...item, collectionIds: [`${collectionId}-other`] }),
  ],
  [
    'collection substring',
    (item) => ({ ...item, collectionIds: collectionId }),
  ],
  ['missing collection', (item) => ({ ...item, collectionIds: undefined })],
  [
    'ticket prefix',
    (item) => ({
      ...item,
      fields: item.fields.map((field) =>
        field.name === 'intake_ticket_id'
          ? { ...field, value: `prefix-${field.value}` }
          : field,
      ),
    }),
  ],
  [
    'ticket suffix',
    (item) => ({
      ...item,
      fields: item.fields.map((field) =>
        field.name === 'intake_ticket_id'
          ? { ...field, value: `${field.value}-suffix` }
          : field,
      ),
    }),
  ],
  [
    'missing ticket marker',
    (item) => ({ ...item, fields: item.fields.slice(1) }),
  ],
  [
    'reference marker without collision',
    (item) => ({
      ...item,
      fields: item.fields.map((field) =>
        field.name === 'intake_ticket_id'
          ? { ...field, name: 'intake_ticket_id_reference' }
          : field,
      ),
    }),
  ],
  [
    'missing fingerprint',
    (item) => ({ ...item, fields: item.fields.slice(0, 1) }),
  ],
  [
    'fingerprint mismatch',
    (item) => ({
      ...item,
      fields: item.fields.map((field) =>
        field.name === 'intake_fingerprint'
          ? { ...field, value: 'fedcba9876543210' }
          : field,
      ),
    }),
  ],
  [
    'one conflicting fingerprint among duplicates',
    (item) => ({
      ...item,
      fields: [
        ...item.fields,
        { name: 'intake_fingerprint', value: 'fedcba9876543210', type: 0 },
      ],
    }),
  ],
  ['missing fields', (item) => ({ ...item, fields: undefined })],
  ['non-array fields', (item) => ({ ...item, fields: {} })],
];

for (const [name, mutate] of nearMisses) {
  test(`lookup ignores ${name} instead of matching an out-of-scope or inexact marker`, async (t) => {
    const f = await unknownFixture(t);
    const vault = await serve(f);
    vault.items = [mutate(markedItem())];
    assert.equal(await vault.adapter.lookup(input()), null);
    vault.items.push(markedItem(input(), { id: 'exact-match' }));
    assert.deepEqual(await vault.adapter.lookup(input()), {
      itemId: 'exact-match',
    });
    assert.equal(vault.posts.length, 0);
    assert.deepEqual(vault.requests, [
      { method: 'POST', path: '/sync' },
      { method: 'GET', path: listPath },
      { method: 'POST', path: '/sync' },
      { method: 'GET', path: listPath },
    ]);
  });
}

for (const name of ['intake_ticket_id', 'intake_fingerprint']) {
  for (const type of [1, 2, 3, undefined, '0']) {
    test(`lookup ignores ${name} with non-text type ${JSON.stringify(type)}`, async (t) => {
      const f = await unknownFixture(t);
      const vault = await serve(f);
      const item = markedItem();
      item.fields = item.fields.map((field) =>
        field.name === name ? { ...field, type } : field,
      );
      vault.items = [item];
      assert.equal(await vault.adapter.lookup(input()), null);
      assert.equal(vault.posts.length, 0);
    });
  }
}

for (const type of [1, 2, 3]) {
  test(`non-text references of type ${type} do not conflict with matching text fields`, async (t) => {
    const f = await unknownFixture(t);
    const vault = await serve(f);
    const item = markedItem();
    item.fields.push(
      { name: 'intake_ticket_id', value: 'another-ticket', type },
      { name: 'intake_fingerprint', value: 'fedcba9876543210', type },
    );
    vault.items = [item];
    assert.deepEqual(await vault.adapter.lookup(input()), { itemId: item.id });
    assert.equal(vault.posts.length, 0);
  });
}

test('matching duplicate text fingerprints still identify one item', async (t) => {
  const f = await unknownFixture(t);
  const vault = await serve(f);
  const item = markedItem();
  item.fields.push({ ...item.fields[1] });
  vault.items = [item];
  assert.deepEqual(await vault.adapter.lookup(input()), { itemId: item.id });
  assert.equal(vault.posts.length, 0);
});

test('a repeated exact ticket field still identifies one item rather than authorizing a duplicate POST', async (t) => {
  const f = await unknownFixture(t);
  const vault = await serve(f);
  const item = markedItem();
  item.fields.push({ ...item.fields[0] });
  vault.items = [item];
  assert.deepEqual(await vault.adapter.lookup(input()), { itemId: item.id });
  assert.equal(vault.posts.length, 0);
});

test('a marker without a fingerprint does not match and unknown resolution creates exactly one item', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  const entry = queuedInput(f, queued);
  const now = Date.now();
  assert.equal(f.store.begin(queued.ticket.id, now), true);
  assert.ok(
    f.store.retry(queued.ticket.id, 'vault_network', {
      now: now - settleMs,
      unknown: true,
      settleMs,
    }),
  );
  const vault = await serve(f);
  vault.items = [
    null,
    {},
    markedItem(entry, {
      collectionIds: ['another-collection', collectionId],
      fields: [
        null,
        { name: 'password', value: privateValue, type: 1 },
        { name: 'intake_ticket_id', value: entry.ticketId, type: 0 },
        { name: 'intake_fingerprint_reference', value: 'not-the-fingerprint' },
      ],
    }),
  ];
  assert.equal(await vault.adapter.lookup(entry), null);
  assert.equal(vault.posts.length, 0);
  const instance = await writer(f, vault, { now: () => now });
  assertDone(f, queued, instance);
  assert.equal(vault.posts.length, 1);
  await instance.drain();
  assert.equal(vault.posts.length, 1);
});

for (const field of ['intake_ticket_id', 'intake_fingerprint']) {
  test(`lookup and uncertain-write recovery use collision-safe markers for secret field ${field}`, async (t) => {
    const f = await unknownFixture(t);
    const queued = await queue(f, { targetField: field });
    const entry = queuedInput(f, queued);
    let now = Date.now();
    const vault = await serve(f, {
      onItem(request, _response, body) {
        vault.save(body);
        request.socket.destroy();
      },
    });
    const instance = await writer(f, vault, { now: () => now });
    assertUnknown(f, queued, 1, now + settleMs);
    const body = vault.posts[0];
    for (const [name, value] of [
      ['intake_ticket_id', queued.ticket.id],
      ['intake_fingerprint', entry.fingerprint],
    ]) {
      const markers = body.fields.filter(
        (candidate) => candidate.name === markerName(field, name),
      );
      assert.equal(markers.length, 1);
      assert.equal(markers[0].value, value);
      assert.equal(markers[0].type, 0);
    }
    const secret = body.fields.find((candidate) => candidate.name === field);
    assert.equal(secret.type, 1);
    assert.equal(secret.value === privateValue, true);
    // A legacy base marker must not be mistaken for the collision-safe marker.
    const marker = markerName(field, field);
    const decoy = {
      ...vault.items[0],
      id: 'collision-decoy',
      fields: body.fields.map((candidate) =>
        candidate.name === marker ? { ...candidate, name: field } : candidate,
      ),
    };
    if (field === 'intake_ticket_id') vault.items.unshift(decoy);
    else {
      // Wrong reference fingerprints reject a candidate even if the base field matches.
      decoy.fields.push({ name: marker, value: 'fedcba9876543210', type: 0 });
      vault.items.unshift(decoy);
    }
    now += settleMs;
    await instance.drain();
    assertDone(f, queued, instance);
    assert.equal(vault.posts.length, 1);
    assert.equal(
      vault.items.filter(({ id }) => id !== 'collision-decoy').length,
      1,
    );
  });
}

test('multiple exact marker matches stay unknown and never create a third item', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  const vault = await serve(f, {
    onItem(request, _response, body) {
      vault.save(body);
      vault.save(body);
      request.socket.destroy();
    },
  });
  const instance = await writer(f, vault, { now: () => now });
  await assert.rejects(
    vault.adapter.lookup(queuedInput(f, queued)),
    classified('vault_marker_ambiguous', false),
  );
  now += settleMs;
  await instance.drain();
  const due = now + 10000;
  assertUnknown(f, queued, 2, due, 'vault_marker_ambiguous');
  assert.equal(vault.posts.length, 1);
  assert.equal(vault.items.length, 2);
  assert(f.logs.some((line) => line.includes('vault_marker_ambiguous')));
  assertSafeLogs(f);
  await assertQuietUntil(instance, vault, (value) => (now = value), due);
  vault.items.pop();
  now = due;
  await instance.drain();
  assertDone(f, queued, instance);
  assert.equal(vault.posts.length, 1);
});

for (const id of [undefined, null, '', ' ', 42]) {
  test(`a matching marker with invalid item ID ${JSON.stringify(id)} fails closed`, async (t) => {
    const f = await unknownFixture(t);
    const vault = await serve(f);
    vault.items = [markedItem(input(), { id })];
    await assert.rejects(
      vault.adapter.lookup(input()),
      classified('vault_response', false),
    );
    assert.equal(vault.posts.length, 0);
  });
}

test('unknown state persists across database reopen and work/begin respect the exact settled due time', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  const now = Date.now();
  assert.equal(f.store.begin(queued.ticket.id, now), true);
  assert.deepEqual(
    f.store.retry(queued.ticket.id, 'vault_network', {
      now,
      baseMs: 5000,
      maxMs: 12000,
      unknown: true,
      settleMs,
    }),
    {
      id: queued.ticket.id,
      status: 'unknown',
      attempts: 1,
      previousAttempts: 0,
      code: 'vault_network',
    },
  );
  const due = now + settleMs;
  assertUnknown(f, queued, 1, due, 'vault_network');
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  const reopenedKeys = new PrivateKeyStore(f.config.privateDbPath);
  f.cleanup(() => reopened.close());
  f.cleanup(() => reopenedKeys.close());
  assert.deepEqual(
    reopened.getState(queued.ticket.id),
    f.store.getState(queued.ticket.id),
  );
  assert.equal(reopenedKeys.get(queued.ticket.id), queued.key);
  assert.deepEqual(reopened.work(due - 1), []);
  assert.equal(reopened.begin(queued.ticket.id, due - 1), false);
  assertUnknown(f, queued, 1, due);
  assert.deepEqual(reopened.work(due), [queued.ticket.id]);
  assert.equal(reopened.begin(queued.ticket.id, due), true);
  assert.equal(reopened.begin(queued.ticket.id, due), false);
  assert.deepEqual(
    reopened.retry(queued.ticket.id, 'vault_http_503', {
      now: due,
      baseMs: 5000,
      maxMs: 12000,
      unknown: true,
    }),
    {
      id: queued.ticket.id,
      status: 'unknown',
      attempts: 2,
      previousAttempts: 1,
      code: 'vault_http_503',
    },
  );
  assertUnknown(f, queued, 2, due + 10000, 'vault_http_503');
  assert.deepEqual(reopened.work(due + 9999), []);
  assert.deepEqual(reopened.work(due + 10000), [queued.ticket.id]);
});

test('writer restart retains an already-unknown due time and resolves the stored item from reopened databases', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  const vault = await serve(f, {
    onItem(request, _response, body) {
      vault.save(body);
      request.socket.destroy();
    },
  });
  const first = await writer(f, vault, { now: () => now });
  const due = now + settleMs;
  assertUnknown(f, queued, 1, due);
  await first.close();
  now += 7000;
  const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  f.cleanup(() => store.close());
  f.cleanup(() => keys.close());
  const restarted = await writer({ ...f, store, keys }, vault, {
    now: () => now,
  });
  assertUnknown(f, queued, 1, due);
  assert.equal(vault.requests.length, 2);
  await assertQuietUntil(restarted, vault, (value) => (now = value), due);
  now = due;
  await restarted.drain();
  assertDone(f, queued, restarted);
  assert.equal(first.notifications.length, 0);
  assert.equal(vault.posts.length, 1);
  assert.equal(vault.items.length, 1);
});

test('startup recovers interrupted processing as unknown and settles before checking an already-stored item', async (t) => {
  const f = await unknownFixture(t);
  const queued = await queue(f);
  let now = Date.now();
  assert.equal(f.store.begin(queued.ticket.id, now), true);
  const vault = await serve(f);
  vault.items = [markedItem(queuedInput(f, queued))];
  const instance = await writer(f, vault, { now: () => now });
  const due = now + settleMs;
  assertUnknown(f, queued, 1, due, 'writer_interrupted');
  assert.deepEqual(vault.requests, []);
  await assertQuietUntil(instance, vault, (value) => (now = value), due);
  now = due;
  await instance.drain();
  assertDone(f, queued, instance);
  assert.equal(vault.posts.length, 0);
  assert.equal(vault.items.length, 1);
  assert.deepEqual(vault.requests, [
    { method: 'POST', path: '/sync' },
    { method: 'GET', path: listPath },
  ]);
});
