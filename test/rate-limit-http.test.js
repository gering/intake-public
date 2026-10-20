import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createToken } from '../src/tokens.js';
import { startWeb } from '../src/web.js';
import { encryptValue } from '../public/crypto.js';
import { fixture, post } from '../support/fixtures.js';

async function webFixture(t, overrides = {}) {
  const f = await fixture(t, { clientIpHeader: 'client-ip', ...overrides });
  const web = await startWeb({
    store: f.store,
    config: f.config,
    logger: f.logger,
  });
  t.after(() => web.close());
  return { ...f, web, base: `http://127.0.0.1:${web.server.address().port}` };
}

test('successful opens never consume the ticket failure allowance', async (t) => {
  const f = await webFixture(t, { ticketLimit: 2, ipLimit: 100 });
  const { ticket, token } = f.create();
  for (let i = 0; i < 6; i++) {
    const response = await post(
      f.base,
      '/api/open',
      { token },
      { 'client-ip': '192.0.2.1' },
    );
    assert.equal(response.status, 200);
    await response.text();
  }
  const wrongToken = `${ticket.id}.${createToken(f.config.hmacKey).token.split('.')[1]}`;
  for (let i = 0; i <= f.config.ticketLimit; i++) {
    const response = await post(
      f.base,
      '/api/open',
      { token: wrongToken },
      { 'client-ip': '192.0.2.1' },
    );
    const status = i < f.config.ticketLimit ? 400 : 429;
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), {
      error: status === 429 ? 'rate_limited' : 'ticket_unavailable',
    });
  }
});

test('ticket failure exhaustion blocks wrong tokens but not valid open and submit', async (t) => {
  const f = await webFixture(t, { ticketLimit: 2, ipLimit: 100 });
  const { ticket, token } = f.create();
  const wrongToken = `${ticket.id}.${createToken(f.config.hmacKey).token.split('.')[1]}`;
  const envelope = await encryptValue(ticket, 'submitted value');
  for (const [path, status, ip] of [
    ['/api/open', 400, '192.0.2.1'],
    ['/api/submit', 400, '192.0.2.2'],
    ['/api/open', 429, '192.0.2.1'],
    ['/api/submit', 429, '192.0.2.2'],
  ]) {
    const response = await post(
      f.base,
      path,
      { token: wrongToken, envelope },
      { 'client-ip': ip },
    );
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), {
      error: status === 429 ? 'rate_limited' : 'ticket_unavailable',
    });
    const stored = f.store.getState(ticket.id);
    assert.equal(stored.status, 'active');
    assert.equal(stored.openedAt, null);
    assert.equal(stored.usedAt, null);
    assert.equal(stored.envelope, null);
  }
  const opened = await post(
    f.base,
    '/api/open',
    { token },
    { 'client-ip': '192.0.2.3' },
  );
  assert.equal(opened.status, 200);
  assert.equal((await opened.json()).id, ticket.id);
  const stillBlocked = await post(
    f.base,
    '/api/open',
    { token: wrongToken },
    { 'client-ip': '192.0.2.1' },
  );
  assert.equal(stillBlocked.status, 429);
  assert.deepEqual(await stillBlocked.json(), { error: 'rate_limited' });
  const invalidEnvelope = await post(
    f.base,
    '/api/submit',
    { token, envelope: {} },
    { 'client-ip': '192.0.2.3' },
  );
  assert.equal(invalidEnvelope.status, 400);
  assert.deepEqual(await invalidEnvelope.json(), { error: 'invalid_envelope' });
  const submitted = await post(
    f.base,
    '/api/submit',
    { token, envelope },
    { 'client-ip': '192.0.2.3' },
  );
  assert.equal(submitted.status, 202);
  assert.deepEqual(await submitted.json(), { status: 'pending' });
  assert.equal(f.store.getState(ticket.id).status, 'pending');
  assert.deepEqual(f.store.getState(ticket.id).envelope, envelope);
});

for (const path of ['/api/open', '/api/submit']) {
  test(`${path} still applies client limits to a valid token with an exhausted ticket bucket`, async (t) => {
    const f = await webFixture(t, { ticketLimit: 1, ipLimit: 1 });
    const { ticket, token } = f.create();
    const wrongToken = `${ticket.id}.${createToken(f.config.hmacKey).token.split('.')[1]}`;
    const rejected = await post(
      f.base,
      '/api/open',
      { token: wrongToken },
      { 'client-ip': '192.0.2.1' },
    );
    assert.equal(rejected.status, 400);
    assert.deepEqual(await rejected.json(), { error: 'ticket_unavailable' });
    const opened = await post(
      f.base,
      '/api/open',
      { token },
      { 'client-ip': '192.0.2.2' },
    );
    assert.equal(opened.status, 200);
    await opened.json();
    const limited = await post(
      f.base,
      path,
      { token, envelope: await encryptValue(ticket, 'submitted value') },
      { 'client-ip': '192.0.2.2' },
    );
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), { error: 'rate_limited' });
    assert.equal(f.store.getState(ticket.id).status, 'active');
    assert.equal(f.store.getState(ticket.id).usedAt, null);
  });
}

for (const state of [
  'unknown',
  'expired',
  'revoked',
  'pending',
  'processing',
  'done',
  'failed',
]) {
  test(`${state} tickets consume the ticket failure allowance`, async (t) => {
    const f = await webFixture(t, { ticketLimit: 2 });
    const { ticket, token } = f.create();
    if (state === 'expired')
      f.store.db
        .prepare('UPDATE tickets SET expires_at = 0 WHERE id = ?')
        .run(ticket.id);
    else if (state !== 'unknown')
      f.store.db
        .prepare('UPDATE tickets SET status = ? WHERE id = ?')
        .run(state, ticket.id);
    const attempt =
      state === 'unknown' ? createToken(f.config.hmacKey).token : token;
    for (const [path, status] of [
      ['/api/open', 400],
      ['/api/submit', 400],
      ['/api/open', 429],
      ['/api/submit', 429],
    ]) {
      const response = await post(
        f.base,
        path,
        { token: attempt, envelope: {} },
        { 'client-ip': '192.0.2.1' },
      );
      assert.equal(response.status, status);
      assert.deepEqual(await response.json(), {
        error: status === 429 ? 'rate_limited' : 'ticket_unavailable',
      });
    }
  });
}

for (const [failure, path, status, error] of [
  ['envelope errors', '/api/submit', 400, 'invalid_envelope'],
  ['internal failures', '/api/open', 500, 'internal_error'],
]) {
  test(`valid token ${failure} do not consume ticket allowances`, async (t) => {
    const f = await webFixture(t, { ticketLimit: 1 });
    const { ticket, token } = f.create();
    const open =
      error === 'internal_error'
        ? t.mock.method(f.store, 'open', () => {
            throw new Error('private failure');
          })
        : null;
    try {
      for (let i = 0; i < 3; i++) {
        const response = await post(
          f.base,
          path,
          { token, envelope: {} },
          { 'client-ip': '192.0.2.1' },
        );
        assert.equal(response.status, status);
        assert.deepEqual(await response.json(), { error });
      }
    } finally {
      open?.mock.restore();
    }
    const wrongToken = `${ticket.id}.${createToken(f.config.hmacKey).token.split('.')[1]}`;
    const response = await post(
      f.base,
      '/api/open',
      { token: wrongToken },
      { 'client-ip': '192.0.2.1' },
    );
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'ticket_unavailable' });
  });
}

for (const [body, status] of [
  ['{bad', 400],
  [JSON.stringify({ token: 'x'.repeat(200) }), 413],
]) {
  test(`a ${status} body failure consumes the client allowance before reading another body`, async (t) => {
    const f = await webFixture(t, { bodyLimit: 100, ipLimit: 1 });
    const response = await fetch(`${f.base}/api/open`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'client-ip': '192.0.2.1' },
      body,
    });
    assert.equal(response.status, status);
    await response.text();
    const limited = await new Promise((resolve, reject) => {
      const req = request(
        `${f.base}/api/open`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': '1000000',
            'client-ip': '192.0.2.1',
            Connection: 'close',
          },
          signal: AbortSignal.timeout(3000),
        },
        (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve({ status: res.statusCode, body });
            req.destroy();
          });
          res.on('error', reject);
        },
      );
      t.after(() => req.destroy());
      req.on('error', reject);
      req.flushHeaders();
    });
    assert.equal(limited.status, 429);
    assert.deepEqual(JSON.parse(limited.body), { error: 'rate_limited' });
  });
}

test('HTTP requests share the configured IPv6 /48 allowance across /64 clients', async (t) => {
  const f = await webFixture(t, { ipLimit: 10, ipv6Limit48: 2 });
  for (const [ip, status] of [
    ['2001:db8:abcd:1::1', 400],
    ['2001:0DB8:ABCD:0002::2', 400],
    ['2001:db8:abcd:3::1', 429],
    ['2001:db8:abce:1::1', 400],
  ]) {
    const response = await post(f.base, '/api/open', {}, { 'client-ip': ip });
    assert.equal(response.status, status, ip);
    assert.deepEqual(await response.json(), {
      error: status === 429 ? 'rate_limited' : 'ticket_unavailable',
    });
  }
});
