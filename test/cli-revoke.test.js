import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import { startWriter } from '../src/writer.js';
import { MockVaultAdapter } from '../src/vault.js';
import { fixture } from '../support/fixtures.js';

const execute = promisify(execFile);
const cliPath = new URL('../src/cli.js', import.meta.url).pathname;
const deferred =
  'Ticket revoked. Writer unreachable; the private key is removed at the next writer prune.\n';

function operatorEnv(f) {
  return {
    INTAKE_DB: f.config.dbPath,
    INTAKE_SOCKET: f.config.socketPath,
    INTAKE_IPC_TIMEOUT_MS: '1000',
    INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
    INTAKE_PRIVATE_DB: '/unreadable/private.sqlite',
    INTAKE_WRITER_KEY_FILE: '/unreadable/writer.key',
    INTAKE_FINGERPRINT_KEY_FILE: '/unreadable/fingerprint.key',
  };
}

async function writer(f) {
  return startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: new MockVaultAdapter(),
    notifyOff: true,
    socketPath: f.config.socketPath,
    pollMs: 60000,
    logger: f.logger,
  });
}

test('CLI revoke asks the running writer to remove the private key without operator private access', async (t) => {
  const f = await fixture(t);
  const service = await writer(f);
  t.after(() => service.close());
  // Create after writer startup so startup pruning cannot satisfy this assertion.
  const { ticket, token } = f.create();
  const other = f.create();
  assert(f.keys.get(ticket.id));
  const result = await execute(
    process.execPath,
    [cliPath, 'revoke', '--', ticket.id],
    { env: operatorEnv(f) },
  );
  assert.equal(result.stdout, 'Ticket revoked. Private key removed.\n');
  assert.equal(result.stderr, '');
  assert.equal(f.store.get(ticket.id).status, 'revoked');
  assert.equal(f.keys.get(ticket.id), undefined);
  assert.throws(() => f.store.open(token));
  assert.equal(f.store.get(other.ticket.id).status, 'active');
  assert(f.keys.get(other.ticket.id));
});

test('CLI revoke succeeds without a writer and the next writer startup prunes the private key', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const result = await execute(
    process.execPath,
    [cliPath, 'revoke', '--', ticket.id],
    {
      env: operatorEnv(f),
    },
  );
  assert.equal(result.stdout, deferred);
  assert.equal(result.stderr, '');
  assert.equal(f.store.get(ticket.id).status, 'revoked');
  assert.throws(() => f.store.open(token));
  assert(f.keys.get(ticket.id));
  const service = await writer(f);
  t.after(() => service.close());
  assert.equal(f.keys.get(ticket.id), undefined);
});

for (const failure of ['status', 'invalid JSON', 'disconnect', 'timeout']) {
  test(`CLI revoke preserves successful revocation when the writer responds with ${failure}`, async (t) => {
    const f = await fixture(t);
    const { ticket } = f.create();
    const requests = [];
    const server = createServer((req, res) => {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        requests.push({
          method: req.method,
          path: req.url,
          body: JSON.parse(body),
          status: f.store.get(ticket.id).status,
        });
        if (failure === 'status') {
          res.writeHead(503);
          res.end('{"error":"writer_unavailable"}');
        } else if (failure === 'invalid JSON') {
          res.end('not JSON');
        } else if (failure === 'disconnect') {
          res.destroy();
        }
      });
    });
    await new Promise((resolve) => server.listen(f.config.socketPath, resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const result = await execute(
      process.execPath,
      [cliPath, 'revoke', '--', ticket.id],
      {
        env: operatorEnv(f),
      },
    );
    assert.equal(result.stdout, deferred);
    assert.equal(result.stderr, '');
    assert.deepEqual(requests, [
      {
        method: 'POST',
        path: '/revoke',
        body: { id: ticket.id },
        status: 'revoked',
      },
    ]);
    assert.equal(f.store.get(ticket.id).status, 'revoked');
    assert(f.keys.get(ticket.id));
  });
}

test('CLI revoke reports when shared state changed before the writer removed the key', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  const server = createServer((req, res) => {
    req.resume();
    res.writeHead(409);
    res.end('{"error":"ticket_not_revoked"}');
  });
  await new Promise((resolve) => server.listen(f.config.socketPath, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(
    execute(process.execPath, [cliPath, 'revoke', '--', ticket.id], {
      env: operatorEnv(f),
    }),
    {
      code: 1,
      stdout:
        'Ticket revoked in shared state, but it is no longer revoked there. The writer did not remove the private key. Inspect it with show.\n',
      stderr: '',
    },
  );
  assert.equal(f.store.get(ticket.id).status, 'revoked');
  assert(f.keys.get(ticket.id));
});

test('CLI revoke does not contact the writer when public revocation fails', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.store.revoke(ticket.id);
  let requests = 0;
  const server = createServer((req, res) => {
    requests += 1;
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(f.config.socketPath, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(
    execute(process.execPath, [cliPath, 'revoke', '--', ticket.id], {
      env: operatorEnv(f),
    }),
    { code: 1, stdout: '', stderr: 'intake: ticket_not_revocable\n' },
  );
  assert.equal(requests, 0);
  assert(f.keys.get(ticket.id));
});
