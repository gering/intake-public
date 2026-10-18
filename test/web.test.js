import test from 'node:test';
import assert from 'node:assert/strict';
import { startWeb } from '../src/web.js';
import { encryptValue } from '../public/crypto.js';
import { securityHeaders } from '../src/http.js';
import { fixture, post } from '../support/fixtures.js';
import { createToken } from '../src/tokens.js';
import { connect } from 'node:net';
import { readFile } from 'node:fs/promises';

test('web and browser have no fingerprint computation or fingerprint key path', async () => {
  for (const path of [
    '../src/web.js',
    '../src/crypto.js',
    '../public/app.js',
    '../public/crypto.js',
  ]) {
    const source = await readFile(new URL(path, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /fingerprint|createHash|createHmac/i, path);
  }
  const source = await readFile(
    new URL('../src/db.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /envelopeFingerprint|createHash|createHmac/);
});

async function webFixture(t, overrides) {
  const f = await fixture(t, overrides);
  const web = await startWeb({
    store: f.store,
    config: f.config,
    logger: f.logger,
  });
  t.after(() => web.close());
  return { ...f, web, base: `http://127.0.0.1:${web.server.address().port}` };
}

function checkHeaders(response) {
  for (const [key, value] of Object.entries(securityHeaders))
    assert.equal(response.headers.get(key), value, key);
}

test('page/assets do not open or consume; JSON open returns AAD metadata but no private keys', async (t) => {
  const f = await webFixture(t);
  const { ticket, token } = f.create({
    targetItem: 'Private vault item sentinel',
    targetField: 'PRIVATE_TARGET_FIELD_SENTINEL',
    targetNotes: 'Private target notes sentinel',
    notifyEmail: 'private-recipient@example.com',
  });
  for (const path of ['/', '/app.js', '/crypto.js', '/styles.css']) {
    const response = await fetch(f.base + path);
    assert.equal(response.status, 200);
    checkHeaders(response);
    const body = await response.text();
    assert(!body.includes(token));
    assert(!body.includes(ticket.id));
  }
  assert.equal(f.store.get(ticket.id).openedAt, null);
  assert.equal(f.store.get(ticket.id).status, 'active');
  for (let index = 0; index < 2; index++) {
    const response = await post(f.base, '/api/open', { token });
    assert.equal(response.status, 200);
    checkHeaders(response);
    const body = await response.text();
    for (const privateMetadata of [
      ticket.target.item,
      ticket.target.field,
      ticket.target.notes,
      ticket.notifyEmail,
    ])
      assert(!body.includes(privateMetadata));
    const opened = JSON.parse(body);
    assert.deepEqual(Object.keys(opened).sort(), [
      'expiresAt',
      'id',
      'keyName',
      'metaDigest',
      'publicKey',
      'purpose',
      'trim',
    ]);
    assert.equal(opened.trim, true);
    assert.equal(opened.keyName, ticket.keyName);
    assert.equal(opened.metaDigest, ticket.metaDigest);
    assert.equal(opened.publicKey.kty, 'RSA');
  }
  assert.equal(f.store.get(ticket.id).status, 'active');
  assert(f.store.get(ticket.id).openedAt);
  assert.equal((await post(f.base, '/api/create', {})).status, 404);
});

test('legacy tickets fail closed with an upgrade status on both HTTP endpoints', async (t) => {
  const f = await webFixture(t);
  const { ticket, token } = f.create();
  f.store.db
    .prepare('UPDATE tickets SET meta_digest = NULL WHERE id = ?')
    .run(ticket.id);
  for (const path of ['/api/open', '/api/submit']) {
    const response = await post(f.base, path, { token });
    assert.equal(response.status, 409);
    checkHeaders(response);
    assert.deepEqual(await response.json(), {
      error: 'ticket_upgrade_required',
    });
  }
  assert.equal(f.store.getState(ticket.id).status, 'active');
  assert.equal(f.store.getState(ticket.id).openedAt, null);
});

test('parallel HTTP submits have exactly one winner and never return the value', async (t) => {
  const f = await webFixture(t);
  const { ticket, token } = f.create();
  const value = 'private-parallel-value-123456';
  const envelope = await encryptValue(ticket, value);
  const responses = await Promise.all(
    Array.from({ length: 16 }, () =>
      post(f.base, '/api/submit', { token, envelope }),
    ),
  );
  assert.equal(
    responses.filter((response) => response.status === 202).length,
    1,
  );
  assert.equal(
    responses.filter((response) => response.status === 400).length,
    15,
  );
  for (const response of responses) {
    checkHeaders(response);
    const body = await response.text();
    assert(!body.includes(value));
    assert(!body.includes(token));
    assert(!body.includes(envelope.ciphertext));
    const json = JSON.parse(body);
    if (response.status === 202) {
      assert.deepEqual(json, { status: 'pending' });
      assert.equal(f.store.get(ticket.id).fingerprint, null);
    } else assert.equal(json.error, 'ticket_unavailable');
  }
  assert.equal(f.store.get(ticket.id).status, 'pending');
  assert.equal((await post(f.base, '/api/open', { token })).status, 400);
  assert(!f.logs.join('').includes(value));
  assert(!f.logs.join('').includes(token));
  assert(!f.logs.join('').includes(envelope.ciphertext));
});

test('expired, revoked, nonexistent and malformed tokens return the same generic error', async (t) => {
  const f = await webFixture(t);
  const expired = f.create();
  f.store.db
    .prepare('UPDATE tickets SET expires_at = 0 WHERE id = ?')
    .run(expired.ticket.id);
  const revoked = f.create();
  f.store.revoke(revoked.ticket.id);
  const used = f.create();
  f.store.claim(
    used.token,
    await encryptValue(used.ticket, 'already submitted'),
  );
  const nonexistent = createToken(f.config.hmacKey).token;
  for (const token of [
    expired.token,
    revoked.token,
    used.token,
    nonexistent,
    'not-a-token',
  ]) {
    for (const path of ['/api/open', '/api/submit']) {
      const response = await post(f.base, path, { token, envelope: {} });
      assert.equal(response.status, 400);
      checkHeaders(response);
      assert.deepEqual(await response.json(), { error: 'ticket_unavailable' });
    }
  }
});

test('per-ticket and per-IP HTTP rate limits return 429 with security headers', async (t) => {
  const f = await webFixture(t, { ticketLimit: 1, ipLimit: 100 });
  const { token } = f.create();
  const [id, secret] = token.split('.');
  const wrongToken = `${id}.${secret[0] === 'A' ? 'B' : 'A'}${secret.slice(1)}`;
  const rejected = await post(f.base, '/api/open', { token: wrongToken });
  assert.equal(rejected.status, 400);
  assert.deepEqual(await rejected.json(), { error: 'ticket_unavailable' });
  const limited = await post(f.base, '/api/submit', { token, envelope: {} });
  assert.equal(limited.status, 429);
  checkHeaders(limited);
  assert.deepEqual(await limited.json(), { error: 'rate_limited' });
  const g = await webFixture(t, { ipLimit: 1, ticketLimit: 100 });
  assert.equal(
    (await post(g.base, '/api/open', { token: 'invalid' })).status,
    400,
  );
  assert.equal(
    (await post(g.base, '/api/open', { token: 'different' })).status,
    429,
  );
});

test('forwarded IP is ignored unless proxy trust is explicitly configured', async (t) => {
  for (const trustProxy of [false, true]) {
    const f = await webFixture(t, { trustProxy, ipLimit: 1 });
    const first = await post(
      f.base,
      '/api/open',
      {},
      { 'X-Forwarded-For': '127.0.0.2' },
    );
    assert.equal(first.status, 400);
    const second = await post(
      f.base,
      '/api/open',
      {},
      { 'X-Forwarded-For': '127.0.0.3' },
    );
    assert.equal(second.status, trustProxy ? 400 : 429);
  }
});

test('API rejects cross-origin, non-JSON, oversized bodies and unknown paths safely', async (t) => {
  const f = await webFixture(t, { bodyLimit: 100 });
  const requests = [
    [
      () => post(f.base, '/api/open', {}, { Origin: 'https://example.com' }),
      403,
    ],
    [
      () => post(f.base, '/api/open', {}, { 'Sec-Fetch-Site': 'cross-site' }),
      403,
    ],
    [() => fetch(f.base + '/api/open', { method: 'POST', body: '{}' }), 415],
    [() => post(f.base, '/api/open', { token: 'x'.repeat(200) }), 413],
    [
      () =>
        fetch(f.base + '/api/open', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{bad',
        }),
      400,
    ],
    [() => fetch(f.base + '/api/open?token=ignored'), 404],
    [() => fetch(f.base + '/missing'), 404],
  ];
  for (const [send, expected] of requests) {
    const response = await send();
    assert.equal(response.status, expected);
    checkHeaders(response);
    await response.text();
  }
});

test('exact security headers cover static, HEAD, API success, errors, 404 and internal failure', async (t) => {
  const f = await webFixture(t);
  const { token } = f.create({ keepWhitespace: true });
  const csp =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
  const requests = [
    () => fetch(f.base + '/'),
    () => fetch(f.base + '/styles.css'),
    () => fetch(f.base + '/app.js', { method: 'HEAD' }),
    () => post(f.base, '/api/open', { token }),
    () => post(f.base, '/api/open', { token: 'invalid' }),
    () => fetch(f.base + '/missing'),
  ];
  for (const send of requests) {
    const response = await send();
    assert.equal(response.headers.get('Content-Security-Policy'), csp);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(
      response.headers.get('Cross-Origin-Resource-Policy'),
      'same-origin',
    );
    checkHeaders(response);
    await response.text();
  }
  const opened = await (await post(f.base, '/api/open', { token })).json();
  assert.equal(opened.trim, false);
  t.mock.method(f.store, 'open', () => {
    throw new Error('private failure');
  });
  const failed = await post(f.base, '/api/open', { token });
  assert.equal(failed.status, 500);
  assert.equal(failed.headers.get('Content-Security-Policy'), csp);
  checkHeaders(failed);
  assert.deepEqual(await failed.json(), { error: 'internal_error' });
});

test('HTTP parser and expectation errors also carry the strict response headers', async (t) => {
  const f = await webFixture(t);
  for (const [request, status] of [
    ['INVALID HTTP REQUEST\r\n\r\n', '400 Bad Request'],
    [
      'GET / HTTP/1.1\r\nHost: intake.example.com\r\nExpect: unsupported\r\nConnection: close\r\n\r\n',
      '417 Expectation Failed',
    ],
  ]) {
    const raw = await new Promise((resolve, reject) => {
      const socket = connect(f.web.server.address().port, '127.0.0.1');
      let data = '';
      socket.setEncoding('utf8');
      socket.on('error', reject);
      socket.on('data', (chunk) => {
        data += chunk;
      });
      socket.on('end', () => resolve(data));
      socket.on('connect', () => socket.write(request));
    });
    assert(raw.startsWith(`HTTP/1.1 ${status}\r\n`));
    assert.deepEqual(
      [...raw.matchAll(/^Cross-Origin-Resource-Policy:\s*([^\r\n]*)/gim)].map(
        (match) => match[1],
      ),
      ['same-origin'],
    );
    for (const [key, value] of Object.entries(securityHeaders))
      assert(raw.toLowerCase().includes(`${key}: ${value}\r\n`.toLowerCase()));
  }
});
