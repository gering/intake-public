import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { checkHealth } from '../docker/healthcheck.js';
import { startWeb } from '../src/web.js';
import { startWriter } from '../src/writer.js';
import { listen, closeServer } from '../src/http.js';
import { MockVaultAdapter } from '../src/vault.js';
import { fixture } from '../support/fixtures.js';

const execute = promisify(execFile);
const script = new URL('../docker/healthcheck.js', import.meta.url).pathname;

test('container probes reach web and writer without ticket data or mutations', async (t) => {
  const f = await fixture(t);
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: new MockVaultAdapter(),
    notifyOff: true,
    socketPath: f.config.socketPath,
    logger: f.logger,
  });
  t.after(() => writer.close());
  const web = await startWeb({
    store: f.store,
    config: f.config,
    logger: f.logger,
  });
  t.after(() => web.close());
  await checkHealth('web', { PORT: web.server.address().port });
  await checkHealth('writer', { INTAKE_SOCKET: f.config.socketPath });
  const response = await execute(process.execPath, [script, 'writer'], {
    env: { INTAKE_SOCKET: f.config.socketPath },
  });
  assert.equal(response.stdout, '');
  assert.equal(response.stderr, '');
  assert.deepEqual(f.store.list(), []);
});

test('vault health requires an unlocked status envelope and sends the allowed Host without Origin', async (t) => {
  const f = await fixture(t);
  let code = 200;
  let body = JSON.stringify({
    success: true,
    data: { template: { status: 'unlocked' } },
  });
  const server = createServer((req, res) => {
    assert.equal(req.url, '/status');
    assert.equal(req.headers.host, 'localhost:8087');
    assert.equal(req.headers.origin, undefined);
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(body);
  });
  await listen(server, f.config.socketPath);
  t.after(() => closeServer(server));
  const env = { INTAKE_BW_SOCKET: f.config.socketPath };
  await checkHealth('bw', env);
  for (const invalid of [
    { success: true, data: { template: { status: 'locked' } } },
    { success: true, data: { template: { status: 'unauthenticated' } } },
    { success: false, data: { template: { status: 'unlocked' } } },
    { status: 'unlocked' },
    null,
  ]) {
    body = JSON.stringify(invalid);
    await assert.rejects(checkHealth('bw', env));
  }
  body = 'not JSON; sensitive upstream output';
  await assert.rejects(checkHealth('bw', env));
  body = 'x'.repeat(17000);
  await assert.rejects(checkHealth('bw', env));
  code = 403;
  body = JSON.stringify({
    success: true,
    data: { template: { status: 'unlocked' } },
  });
  await assert.rejects(checkHealth('bw', env));
  await assert.rejects(
    execute(process.execPath, [script, 'bw'], {
      env,
    }),
    { code: 1, stdout: '', stderr: '' },
  );
});

test('container health fails closed for unavailable services and startup responses', async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    checkHealth('writer', { INTAKE_SOCKET: f.config.socketPath }),
  );
  await assert.rejects(
    checkHealth('bw', { INTAKE_BW_SOCKET: f.config.socketPath }),
  );
  await assert.rejects(checkHealth('unknown', {}));
  const server = createServer((_req, res) => {
    res.writeHead(503);
    res.end();
  });
  await listen(server, f.config.socketPath);
  t.after(() => closeServer(server));
  await assert.rejects(
    checkHealth('writer', { INTAKE_SOCKET: f.config.socketPath }),
  );
});
