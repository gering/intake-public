import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkVaultAccess } from '../src/vault.js';
import test from 'node:test';
import { BwServeAdapter, MockVaultAdapter } from '../src/vault.js';
import { startWriter } from '../src/writer.js';
import { createToken } from '../src/tokens.js';
import { createTicketKeys } from '../src/crypto.js';
import { metadataDigest } from '../src/metadata.js';
import { encryptValue } from '../public/crypto.js';
import { fixture } from '../support/fixtures.js';

const privateValue = 'sensitive-vault-value-not-for-output';
const privateToken = 'sensitive-link-token-not-for-output';

function input(field = 'password', overrides = {}) {
  return {
    target: { item: 'Example service', field, notes: 'Example notes' },
    keyName: 'SERVICE_KEY',
    purpose: 'Enable the example service',
    value: privateValue,
    ticketId: 'ticket-123',
    fingerprint: '1234567890abcdef',
    ...overrides,
  };
}

async function vaultServer(t, handler, unix = false) {
  const dir = unix ? await mkdtemp(join(tmpdir(), 'intake-vault-')) : null;
  if (dir) t.after(() => rm(dir, { recursive: true, force: true }));
  const socketPath = dir ? join(dir, 'bw.sock') : undefined;
  const requests = [];
  const server = createServer(async (request, response) => {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    requests.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      raw,
      body: raw ? JSON.parse(raw) : null,
    });
    // Mirror the CLI's default Host/Origin guard, including on Unix sockets.
    if (
      unix &&
      (request.headers.host !== 'localhost:8087' ||
        request.headers.origin !== undefined)
    ) {
      json(response, 403, { success: false });
      return;
    }
    handler(request, response, requests.length);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    if (unix) server.listen(socketPath, resolve);
    else server.listen(0, '127.0.0.1', resolve);
  });
  t.after(
    () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  );
  return {
    url: unix ? undefined : `http://127.0.0.1:${server.address().port}`,
    socketPath,
    requests,
  };
}

function adapter(baseUrl, options = {}) {
  return new BwServeAdapter({
    baseUrl,
    organizationId: 'example-organization-id',
    collectionId: 'example-collection-id',
    ...options,
  });
}

for (const sync of [false, true]) {
  test(`Unix vault requests pass the CLI Host guard with sync=${sync}`, async (t) => {
    const server = await vaultServer(
      t,
      (request, response) => {
        json(response, 200, {
          success: true,
          data: request.url === '/sync' ? {} : { id: 'unix-item-id' },
        });
      },
      true,
    );
    const vault = adapter(undefined, { socketPath: server.socketPath, sync });
    assert.deepEqual(await vault.write(input()), { itemId: 'unix-item-id' });
    assert.deepEqual(
      server.requests.map(({ url }) => url),
      sync ? ['/sync', '/object/item'] : ['/object/item'],
    );
    for (const { headers } of server.requests) {
      assert.equal(headers.host, 'localhost:8087');
      assert.equal(headers.origin, undefined);
    }
    if (sync) assert.equal(server.requests[0].raw, '');
    assert.equal(server.requests.at(-1).body.login.password, privateValue);
  });
}

for (const [status, body, code] of [
  [403, { success: false, message: privateValue }, 'vault_http_403'],
  [200, { success: false, message: privateValue }, 'vault_response'],
]) {
  test(`Unix-socket vault sanitizes ${code}`, async (t) => {
    const server = await vaultServer(
      t,
      (_request, response) => {
        json(response, status, body);
      },
      true,
    );
    await assert.rejects(
      adapter(undefined, { socketPath: server.socketPath }).write(input()),
      safeError(code),
    );
    assert.equal(server.requests.length, 1);
  });
}

test('Unix-socket vault sanitizes network failures and timeouts', async (t) => {
  const server = await vaultServer(
    t,
    (request) => request.socket.destroy(),
    true,
  );
  await assert.rejects(
    adapter(undefined, { socketPath: server.socketPath }).write(input()),
    safeError('vault_network'),
  );
  const stalled = await vaultServer(t, () => {}, true);
  await assert.rejects(
    adapter(undefined, {
      socketPath: stalled.socketPath,
      timeoutMs: 100,
    }).write(input()),
    safeError('vault_timeout'),
  );
});

test('vault socket parent must be private and owned by the writer UID', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'intake-vault-permissions-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const config = { socketPath: join(dir, 'bw.sock') };
  checkVaultAccess(config);
  for (const mode of [0o750, 0o755]) {
    await chmod(dir, mode);
    assert.throws(() => checkVaultAccess(config), {
      code: 'unsafe_vault_socket_directory',
    });
  }
  await chmod(dir, 0o700);
  const uid = process.getuid();
  t.mock.method(process, 'getuid', () => uid + 1);
  assert.throws(() => checkVaultAccess(config), {
    code: 'unsafe_vault_socket_directory',
  });
});

test('TCP vault access emits a warning with only a safe code', () => {
  const records = [];
  checkVaultAccess(
    { baseUrl: 'http://127.0.0.1:8087' },
    {
      info: (...args) => records.push(args),
    },
  );
  assert.deepEqual(records, [
    ['vault_tcp_warning', { code: 'vault_tcp_local_users' }],
  ]);
});

function json(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(body));
}

function safeError(code) {
  return (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, 'Vault operation failed.');
    assert.equal(error.cause, undefined);
    const output = `${error.stack} ${JSON.stringify(error)}`;
    assert.ok(!output.includes(privateValue));
    assert.ok(!output.includes(privateToken));
    return true;
  };
}

test('mock vault records independent entries and returns unique item IDs', async () => {
  const mock = new MockVaultAdapter();
  const first = input();
  const original = structuredClone(first);
  const firstResult = await mock.write(first);
  const secondResult = await mock.write(input('api-key'));
  assert.equal(typeof firstResult.itemId, 'string');
  assert.notEqual(firstResult.itemId, secondResult.itemId);
  assert.deepEqual(mock.entries[0], {
    ...original,
    itemId: firstResult.itemId,
  });
  assert.equal(mock.entries.length, 2);
  first.target.notes = 'Changed notes';
  assert.equal(mock.entries[0].target.notes, 'Example notes');
  assert.deepEqual(new MockVaultAdapter().entries, []);
});

for (const field of ['username', 'password']) {
  test(`vault creates an organization-owned login for ${field}`, async (t) => {
    const logs = [];
    for (const method of ['log', 'warn', 'error']) {
      t.mock.method(console, method, (...args) => logs.push(args));
    }
    const server = await vaultServer(t, (_request, response) => {
      json(response, 200, {
        success: true,
        data: {
          object: 'item',
          id: 'created-item-id',
          login: { [field]: privateValue },
        },
      });
    });
    const data = input(field);
    const original = structuredClone(data);
    assert.deepEqual(await adapter(`${server.url}/`).write(data), {
      itemId: 'created-item-id',
    });
    assert.equal(server.requests.length, 1);
    const request = server.requests[0];
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/object/item');
    assert.equal(request.headers['content-type'], 'application/json');
    assert.equal(request.headers.origin, undefined);
    assert.equal(request.headers.host, new URL(server.url).host);
    assert.deepEqual(request.body, {
      organizationId: 'example-organization-id',
      collectionIds: ['example-collection-id'],
      type: 1,
      name: 'Example service',
      notes: 'Example notes',
      fields: [
        { name: 'intake_ticket_id', value: 'ticket-123', type: 0 },
        { name: 'intake_fingerprint', value: '1234567890abcdef', type: 0 },
      ],
      login: {
        uris: [],
        username: field === 'username' ? privateValue : null,
        password: field === 'password' ? privateValue : null,
        totp: null,
      },
    });
    assert.ok(!JSON.stringify(request.headers).includes(privateValue));
    assert.ok(!request.url.includes(privateValue));
    assert.deepEqual(data, original);
    assert.deepEqual(logs, []);
  });
}

test('vault creates a secure note with a hidden custom field for other targets', async (t) => {
  const server = await vaultServer(t, (_request, response) => {
    json(response, 200, { success: true, data: { id: 'secure-note-id' } });
  });
  assert.deepEqual(await adapter(server.url).write(input('api-key')), {
    itemId: 'secure-note-id',
  });
  assert.deepEqual(server.requests[0].body, {
    organizationId: 'example-organization-id',
    collectionIds: ['example-collection-id'],
    type: 2,
    name: 'Example service',
    notes: 'Example notes',
    fields: [
      { name: 'api-key', value: privateValue, type: 1 },
      { name: 'intake_ticket_id', value: 'ticket-123', type: 0 },
      { name: 'intake_fingerprint', value: '1234567890abcdef', type: 0 },
    ],
    secureNote: { type: 0 },
  });
});

for (const field of [
  'intake_ticket_id',
  'intake_fingerprint',
  'intake_ticket_id_reference',
  'intake_fingerprint_reference',
]) {
  test(`vault preserves literal secret target ${field} with unique reference fields`, async (t) => {
    const server = await vaultServer(t, (_request, response) => {
      json(response, 200, { success: true, data: { id: 'collision-item-id' } });
    });
    const mock = new MockVaultAdapter();
    await mock.write(input(field));
    assert.equal(mock.entries[0].target.field, field);
    await adapter(server.url).write(input(field));
    const { fields } = server.requests[0].body;
    assert.deepEqual(fields[0], { name: field, value: privateValue, type: 1 });
    assert.deepEqual(fields.slice(1), [
      {
        name:
          field === 'intake_ticket_id'
            ? 'intake_ticket_id_reference'
            : 'intake_ticket_id',
        value: 'ticket-123',
        type: 0,
      },
      {
        name:
          field === 'intake_fingerprint'
            ? 'intake_fingerprint_reference'
            : 'intake_fingerprint',
        value: '1234567890abcdef',
        type: 0,
      },
    ]);
    assert.equal(new Set(fields.map(({ name }) => name)).size, 3);
  });
}

function existingTicket(f, field) {
  // Persist a digest-bound ticket independently of current CLI target validation.
  const authorization = createToken(f.config.hmacKey);
  const pair = createTicketKeys(f.config.masterKey, authorization.id);
  const metadata = {
    keyName: 'EXISTING_KEY',
    purpose: 'Complete an existing ticket',
    trim: true,
    target: { item: 'Existing item', field, notes: 'Existing notes' },
    notifyEmail: 'ops@example.com',
  };
  metadata.metaDigest = metadataDigest(metadata);
  const ticket = f.store.db
    .transaction(() => {
      f.keys.put(authorization.id, pair.privateKey, metadata);
      return f.store.create({
        ...metadata,
        id: authorization.id,
        digest: authorization.digest,
        publicKey: pair.publicKey,
        ttl: 86400000,
      });
    })
    .immediate();
  return { ticket: { ...ticket, ...metadata }, token: authorization.token };
}

for (const field of ['intake_ticket_id', 'intake_fingerprint']) {
  for (const queued of [false, true]) {
    test(`persisted digest-bound ${queued ? 'queued' : 'active'} ticket targeting ${field} completes without changing its target`, async (t) => {
      const f = await fixture(t);
      const { ticket, token } = existingTicket(f, field);
      const envelope = await encryptValue(f.store.open(token), privateValue);
      if (queued) f.store.claim(token, envelope);
      const server = await vaultServer(
        t,
        (request, response) => {
          json(response, 200, {
            success: true,
            data:
              request.url === '/status'
                ? { template: { status: 'unlocked' } }
                : { id: 'existing-item-id' },
          });
        },
        true,
      );
      const writer = await startWriter({
        store: f.store,
        keys: f.keys,
        masterKey: f.config.masterKey,
        fingerprintKey: f.config.fingerprintKey,
        adapter: adapter(undefined, { socketPath: server.socketPath }),
        notifyOff: true,
        socketPath: f.config.socketPath,
        logger: f.logger,
      });
      try {
        if (!queued) f.store.claim(token, envelope);
        await writer.drain();
        const done = f.store.get(ticket.id);
        assert.equal(done.status, 'done');
        assert.equal(done.failureCode, null);
        assert.equal(done.envelope, null);
        assert.equal(f.keys.get(ticket.id), undefined);
        assert.equal(f.keys.getMetadata(ticket.id).target.field, field);
        assert.deepEqual(
          server.requests.map(({ url }) => url),
          ['/status', '/object/item'],
        );
        const { fields, notes } = server.requests[1].body;
        assert.equal(notes, ticket.target.notes);
        assert.deepEqual(fields[0], {
          name: field,
          value: privateValue,
          type: 1,
        });
        assert.equal(
          fields.find(
            ({ name }) =>
              name ===
              (field === 'intake_ticket_id'
                ? 'intake_ticket_id_reference'
                : 'intake_ticket_id'),
          ).value,
          ticket.id,
        );
        assert.equal(
          fields.find(
            ({ name }) =>
              name ===
              (field === 'intake_fingerprint'
                ? 'intake_fingerprint_reference'
                : 'intake_fingerprint'),
          ).value,
          done.fingerprint,
        );
        assert.equal(new Set(fields.map(({ name }) => name)).size, 3);
      } finally {
        await writer.close();
      }
    });
  }
}

test('vault treats target field names literally and permits omitted notes', async (t) => {
  const server = await vaultServer(t, (_request, response) => {
    json(response, 200, { success: true, data: { id: 'custom-field-id' } });
  });
  await adapter(server.url).write(
    input('Password', { target: { item: 'Example item', field: 'Password' } }),
  );
  assert.equal(server.requests[0].body.type, 2);
  assert.equal(server.requests[0].body.notes, '');
  assert.equal(server.requests[0].body.fields[0].name, 'Password');
});

test('vault awaits optional sync before creating the item and preserves a path prefix', async (t) => {
  const server = await vaultServer(t, (request, response) => {
    json(
      response,
      200,
      request.url === '/api/sync'
        ? {
            success: true,
            data: {
              object: 'message',
              title: 'Syncing complete.',
              message: null,
            },
          }
        : { success: true, data: { object: 'item', id: 'created-item-id' } },
    );
  });
  await adapter(`${server.url}/api/`, { sync: true }).write(input());
  assert.deepEqual(
    server.requests.map(({ method, url }) => ({ method, url })),
    [
      { method: 'POST', url: '/api/sync' },
      { method: 'POST', url: '/api/object/item' },
    ],
  );
  assert.equal(server.requests[0].raw, '');
  assert.equal(server.requests[1].body.login.password, privateValue);
});

for (const [status, body, code] of [
  [400, { success: false, message: privateValue }, 'vault_http_400'],
  [200, { success: false, message: privateValue }, 'vault_response'],
]) {
  test(`vault does not create an item when sync fails with ${code}`, async (t) => {
    const server = await vaultServer(t, (_request, response) => {
      json(response, status, body);
    });
    await assert.rejects(
      adapter(server.url, { sync: true }).write(input()),
      safeError(code),
    );
    assert.equal(server.requests.length, 1);
    assert.equal(server.requests[0].url, '/sync');
    assert.ok(!server.requests[0].raw.includes(privateValue));
  });
}

for (const status of [400, 401, 403, 422, 500, 503]) {
  test(`vault returns a sanitized HTTP ${status} error without retrying writes`, async (t) => {
    const server = await vaultServer(t, (_request, response) => {
      json(response, status, {
        success: false,
        message: `${privateValue} ${privateToken}`,
        data: { value: privateValue },
      });
    });
    await assert.rejects(
      adapter(server.url).write(input()),
      safeError(`vault_http_${status}`),
    );
    assert.equal(server.requests.length, 1);
  });
}

for (const [label, body] of [
  ['an unsuccessful envelope', { success: false, message: privateValue }],
  ['a missing success flag', { data: { id: 'created-item-id' } }],
  ['a top-level id', { success: true, id: 'created-item-id' }],
  [
    'an array instead of an item',
    { success: true, data: [{ id: 'created-item-id' }] },
  ],
  ['a null body', null],
  ['a missing id', { success: true, data: { password: privateValue } }],
  ['a non-string id', { success: true, data: { id: 123 } }],
  ['a blank id', { success: true, data: { id: '  ' } }],
]) {
  test(`vault rejects ${label} as a sanitized response error`, async (t) => {
    const server = await vaultServer(t, (_request, response) =>
      json(response, 200, body),
    );
    await assert.rejects(
      adapter(server.url).write(input()),
      safeError('vault_response'),
    );
    assert.equal(server.requests.length, 1);
  });
}

for (const unix of [false, true]) {
  const transport = unix ? 'Unix-socket' : 'TCP';

  for (const operation of ['readiness', 'write']) {
    test(
      `${transport} vault settles ${operation} on an unexpected protocol upgrade`,
      { timeout: 5000 },
      async (t) => {
        let closed;
        const server = await vaultServer(
          t,
          (_request, response) => {
            closed = once(response.socket, 'close');
            response.writeHead(101, {
              Connection: 'Upgrade',
              Upgrade: privateToken,
            });
            response.end(privateValue);
          },
          unix,
        );
        const vault = adapter(server.url, {
          socketPath: server.socketPath,
          timeoutMs: 50,
        });
        let timer;
        const deadline = new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('vault_request_did_not_settle')),
            500,
          );
        });
        try {
          if (operation === 'readiness') {
            assert.equal(
              await Promise.race([vault.isReady(), deadline]),
              false,
            );
          } else {
            await assert.rejects(
              Promise.race([vault.write(input()), deadline]),
              safeError('vault_network'),
            );
          }
          await closed;
          assert.equal(server.requests.length, 1);
        } finally {
          clearTimeout(timer);
        }
      },
    );
  }

  test(`${transport} vault enforces the default 1 MiB limit and accepts a larger configured cap`, async (t) => {
    const body = JSON.stringify({
      success: true,
      data: {
        id: 'oversized-item-id',
        value: privateValue,
        token: privateToken,
      },
    }).padEnd(1048577, ' ');
    const server = await vaultServer(
      t,
      (_request, response) => response.end(body),
      unix,
    );
    await assert.rejects(
      adapter(server.url, { socketPath: server.socketPath }).write(input()),
      safeError('vault_response_too_large'),
    );
    assert.equal(server.requests.length, 1);
    assert.deepEqual(
      await adapter(server.url, {
        socketPath: server.socketPath,
        maxResponseBytes: Buffer.byteLength(body),
      }).write(input()),
      { itemId: 'oversized-item-id' },
    );
    assert.equal(server.requests.length, 2);
  });

  test(`${transport} vault accepts a body exactly at its configured UTF-8 byte limit`, async (t) => {
    const body = JSON.stringify({
      success: true,
      data: { id: 'bounded-item-id', value: `${privateValue} é` },
    });
    const maxResponseBytes = Buffer.byteLength(body);
    assert.ok(maxResponseBytes > body.length);
    const server = await vaultServer(
      t,
      (_request, response) => response.end(body),
      unix,
    );
    assert.deepEqual(
      await adapter(server.url, {
        socketPath: server.socketPath,
        maxResponseBytes,
      }).write(input()),
      { itemId: 'bounded-item-id' },
    );
    await assert.rejects(
      adapter(server.url, {
        socketPath: server.socketPath,
        maxResponseBytes: maxResponseBytes - 1,
      }).write(input()),
      safeError('vault_response_too_large'),
    );
    assert.equal(server.requests.length, 2);
  });

  for (const contentLength of [false, true]) {
    test(
      `${transport} vault destroys an oversized ${contentLength ? 'Content-Length' : 'chunked'} response before EOF without parsing a valid prefix`,
      { timeout: 5000 },
      async (t) => {
        const logs = [];
        for (const method of ['log', 'warn', 'error']) {
          t.mock.method(console, method, (...args) => logs.push(args));
        }
        const prefix = JSON.stringify({
          success: true,
          data: {
            id: 'partial-item-id',
            value: privateValue,
            token: privateToken,
          },
        });
        let closed;
        const server = await vaultServer(
          t,
          (_request, response) => {
            closed = once(response, 'close');
            response.writeHead(200, {
              'Content-Type': 'application/json',
              ...(contentLength
                ? { 'Content-Length': Buffer.byteLength(prefix) + 2 }
                : {}),
            });
            response.write(prefix);
            // Exceed the cap in a later chunk and deliberately never end the body.
            setImmediate(() => response.write(' '));
          },
          unix,
        );
        await assert.rejects(
          adapter(server.url, {
            socketPath: server.socketPath,
            maxResponseBytes: Buffer.byteLength(prefix),
            timeoutMs: 1000,
          }).write(input()),
          safeError('vault_response_too_large'),
        );
        await closed;
        assert.equal(server.requests.length, 1);
        assert.deepEqual(logs, []);
      },
    );
  }

  test(`${transport} vault fails closed on oversized readiness and sync bodies`, async (t) => {
    const server = await vaultServer(
      t,
      (_request, response) =>
        json(response, 200, {
          success: true,
          data: { template: { status: 'unlocked' }, value: privateValue },
        }),
      unix,
    );
    const vault = adapter(server.url, {
      socketPath: server.socketPath,
      maxResponseBytes: 32,
      sync: true,
    });
    assert.equal(await vault.isReady(), false);
    await assert.rejects(
      vault.write(input()),
      safeError('vault_response_too_large'),
    );
    assert.deepEqual(
      server.requests.map(({ url }) => url),
      ['/status', '/sync'],
    );
  });
}

test('vault sanitizes malformed successful response JSON', async (t) => {
  const server = await vaultServer(t, (_request, response) => {
    response.end(`${privateValue} ${privateToken}`);
  });
  await assert.rejects(
    adapter(server.url).write(input()),
    safeError('vault_response'),
  );
});

test('vault sanitizes network errors and does not retry an ambiguous write', async (t) => {
  const server = await vaultServer(t, (request) => request.socket.destroy());
  await assert.rejects(
    adapter(server.url).write(input()),
    safeError('vault_network'),
  );
  assert.equal(server.requests.length, 1);
});

test('vault times out a write without retrying or exposing the input', async (t) => {
  const server = await vaultServer(t, () => {});
  await assert.rejects(
    adapter(server.url, { timeoutMs: 100 }).write(input()),
    safeError('vault_timeout'),
  );
  assert.equal(server.requests.length, 1);
});

test('vault timeout covers successful response body consumption', async (t) => {
  const server = await vaultServer(t, (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.flushHeaders();
  });
  await assert.rejects(
    adapter(server.url, { timeoutMs: 100 }).write(input()),
    safeError('vault_timeout'),
  );
});

test('vault does not follow redirects that could forward the secret request body', async (t) => {
  const destination = await vaultServer(t, (_request, response) =>
    response.end(),
  );
  const server = await vaultServer(t, (_request, response) => {
    response.writeHead(307, { Location: `${destination.url}/destination` });
    response.end();
  });
  await assert.rejects(
    adapter(server.url).write(input()),
    safeError('vault_network'),
  );
  assert.equal(destination.requests.length, 0);
  assert.equal(server.requests.length, 1);
});

test('vault accepts only unadorned loopback HTTP base URLs', () => {
  for (const baseUrl of [
    'http://127.0.0.1:8087',
    'http://[::1]:8087',
    'http://localhost:8087',
  ]) {
    assert.ok(adapter(baseUrl) instanceof BwServeAdapter);
  }
  assert.ok(
    new BwServeAdapter({
      organizationId: 'organization',
      collectionId: 'collection',
    }),
  );
  for (const baseUrl of [
    'http://example.com',
    'http://127.0.0.1.example.com',
    'http://localhost.example.com',
    'http://[::]:8087',
    'https://127.0.0.1:8087',
    'file:///tmp/vault',
    `http://user:${privateValue}@127.0.0.1:8087`,
    `http://127.0.0.1:8087/?token=${privateToken}`,
    `http://127.0.0.1:8087/#${privateToken}`,
    'http://127.0.0.1:8087/?',
    'http://127.0.0.1:8087/#',
    privateToken,
  ]) {
    assert.throws(() => adapter(baseUrl), safeError('vault_config'));
  }
});

test('vault validates required adapter configuration safely', () => {
  for (const options of [
    { organizationId: '' },
    { organizationId: null },
    { collectionId: '' },
    { collectionId: 123 },
    { timeoutMs: 0 },
    { timeoutMs: -1 },
    { timeoutMs: 1.5 },
    { timeoutMs: 4294967296 },
    { maxResponseBytes: 0 },
    { maxResponseBytes: -1 },
    { maxResponseBytes: 1.5 },
    { maxResponseBytes: Number.MAX_SAFE_INTEGER + 1 },
    { maxResponseBytes: NaN },
    { maxResponseBytes: Infinity },
    { maxResponseBytes: null },
    { maxResponseBytes: '1048576' },
    { sync: 'true' },
    { socketPath: '/private/bw.sock' },
    { baseUrl: undefined, socketPath: '' },
    { baseUrl: undefined, socketPath: 'relative/bw.sock' },
    { baseUrl: undefined, socketPath: '/private/bw\0.sock' },
  ]) {
    assert.throws(
      () => adapter('http://127.0.0.1:8087', options),
      safeError('vault_config'),
    );
  }
});

test('vault rejects timeouts that Node would clamp to one millisecond', () => {
  assert.ok(adapter('http://127.0.0.1:8087', { timeoutMs: 2147483647 }));
  assert.throws(
    () => adapter('http://127.0.0.1:8087', { timeoutMs: 2147483648 }),
    safeError('vault_config'),
  );
});

test('both adapters validate inputs before making a write', async (t) => {
  const server = await vaultServer(t, (_request, response) => response.end());
  const mock = new MockVaultAdapter();
  for (const data of [
    null,
    input('password', { value: { value: privateValue } }),
    input('password', { fingerprint: undefined }),
    input('password', { fingerprint: privateValue }),
    input('password', { target: null }),
    input('password', { target: { item: '', field: 'password' } }),
    input('password', { target: { item: 'Example service', field: '' } }),
    input('password', {
      target: {
        item: 'Example service',
        field: 'password',
        notes: { value: privateValue },
      },
    }),
  ]) {
    await assert.rejects(
      adapter(server.url).write(data),
      safeError('vault_input'),
    );
    await assert.rejects(mock.write(data), safeError('vault_input'));
  }
  assert.equal(server.requests.length, 0);
  assert.equal(mock.entries.length, 0);
});
