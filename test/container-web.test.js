import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { startWeb } from '../src/web.js';
import { fixture } from '../support/fixtures.js';

const env = { INTAKE_HMAC_KEY: Buffer.alloc(32, 1).toString('base64') };

test('web keeps loopback by default and permits an explicit container bind', async (t) => {
  assert.equal(loadConfig(env).host, '127.0.0.1');
  for (const host of ['127.0.0.1', '0.0.0.0']) {
    assert.equal(loadConfig({ ...env, INTAKE_HOST: host }).host, host);
    const f = await fixture(t);
    const web = await startWeb({
      store: f.store,
      config: { ...f.config, host },
      logger: f.logger,
    });
    try {
      assert.equal(web.server.address().address, host);
      const response = await fetch(
        `http://127.0.0.1:${web.server.address().port}/healthz`,
      );
      assert.equal(response.status, 204);
      assert.equal(await response.text(), '');
    } finally {
      await web.close();
    }
  }
  for (const host of ['', 'localhost', '::', 'example.com', '0.0.0.0\n'])
    assert.throws(() => loadConfig({ ...env, INTAKE_HOST: host }), {
      code: 'invalid_intake_host',
    });
});

test('healthz exposes no data, retains security headers and does not touch tickets', async (t) => {
  const f = await fixture(t);
  const web = await startWeb({
    store: f.store,
    config: f.config,
    logger: f.logger,
  });
  t.after(() => web.close());
  for (const method of ['open', 'claim'])
    t.mock.method(f.store, method, () =>
      assert.fail('health accessed tickets'),
    );
  const base = `http://127.0.0.1:${web.server.address().port}`;
  for (const method of ['GET', 'HEAD']) {
    const response = await fetch(base + '/healthz', { method });
    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal(
      response.headers.get('Strict-Transport-Security'),
      'max-age=31536000; includeSubDomains',
    );
    assert(response.headers.get('Content-Security-Policy'));
    assert.equal(response.headers.get('Set-Cookie'), null);
  }
  for (const [path, method] of [
    ['/healthz', 'POST'],
    ['/healthz?details=true', 'GET'],
  ]) {
    const response = await fetch(base + path, { method });
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), { error: 'not_found' });
  }
});
