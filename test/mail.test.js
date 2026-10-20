import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { MailNotifier } from '../src/mail.js';

const privateValue = 'private-value-not-for-mail';
const privateToken = 'private-link-token-not-for-mail';
const apiToken = 'mail-api-token-not-for-output';

function ticket(overrides = {}) {
  return {
    id: 'ticket-123',
    keyName: 'SERVICE_KEY',
    purpose: 'Enable the example service',
    target: {
      item: 'Example service',
      field: 'api-key',
      notes: 'private-notes-not-for-mail',
    },
    notifyEmail: 'ops@example.com',
    status: 'done',
    completedAt: '2026-01-02T03:04:05.000Z',
    fingerprint: '0123456789abcdef',
    value: privateValue,
    token: privateToken,
    envelope: { ciphertext: 'private-ciphertext-not-for-mail' },
    ...overrides,
  };
}

async function mailServer(t, handler) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let text = '';
    for await (const chunk of request) text += chunk;
    requests.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: JSON.parse(text),
    });
    handler(request, response, requests.length);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(
    () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  );
  return { url: `http://127.0.0.1:${server.address().port}`, requests };
}

function notifier(url, options = {}) {
  return new MailNotifier({
    url,
    token: apiToken,
    mailbox: 'intake+notifications@example.com',
    backoffMs: [0, 0],
    ...options,
  });
}

function json(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(body));
}

function assertNoSecrets(value) {
  const text = JSON.stringify(value);
  for (const forbidden of [
    privateValue,
    privateToken,
    apiToken,
    'private-notes-not-for-mail',
    'private-ciphertext-not-for-mail',
  ]) {
    assert.ok(!text.includes(forbidden));
  }
}

test('mail posts the encoded mailbox route, bearer header, and allowlisted metadata', async (t) => {
  const server = await mailServer(t, (_request, response) => {
    json(response, 200, {
      messageId: 'message-123',
      accepted: ['ops@example.com'],
      rejected: [],
    });
  });
  const logs = [];
  for (const method of ['log', 'warn', 'error']) {
    t.mock.method(console, method, (...args) => logs.push(args));
  }
  const input = ticket();
  const original = structuredClone(input);
  const sender = notifier(`${server.url}/`);
  const before = Date.now();
  const result = await sender.send(input);
  assert.equal(result.status, 'sent');
  assert.equal(result.attempts, 1);
  assert.equal(result.error, null);
  assert.equal(new Date(result.notifiedAt).toISOString(), result.notifiedAt);
  assert.ok(Date.parse(result.notifiedAt) >= before);
  assert.ok(Date.parse(result.notifiedAt) <= Date.now());
  assert.equal(server.requests.length, 1);
  const request = server.requests[0];
  assert.equal(request.method, 'POST');
  assert.equal(
    request.url,
    '/v1/mailboxes/intake%2Bnotifications%40example.com/send',
  );
  assert.equal(request.headers.authorization, `Bearer ${apiToken}`);
  assert.equal(request.headers['content-type'], 'application/json');
  assert.deepEqual(Object.keys(request.body).sort(), ['subject', 'text', 'to']);
  assert.deepEqual(request.body.to, ['ops@example.com']);
  assert.equal(request.body.subject, 'Intake ticket completed');
  for (const metadata of [
    input.id,
    input.keyName,
    input.purpose,
    input.completedAt,
    input.fingerprint,
    input.target.item,
    input.target.field,
  ]) {
    assert.ok(request.body.text.includes(metadata));
  }
  assertNoSecrets(request.body);
  assertNoSecrets(result);
  assertNoSecrets(sender);
  assert.deepEqual(input, original);
  assert.deepEqual(logs, []);
});

test('mail preserves an API path prefix', async (t) => {
  const server = await mailServer(t, (_request, response) => response.end());
  assert.equal(
    (await notifier(`${server.url}/api/`).send(ticket())).status,
    'sent',
  );
  assert.equal(
    server.requests[0].url,
    '/api/v1/mailboxes/intake%2Bnotifications%40example.com/send',
  );
});

test('mail retries a 503 and then succeeds', async (t) => {
  const server = await mailServer(t, (_request, response, attempt) => {
    json(response, attempt === 1 ? 503 : 200, { rejected: [] });
  });
  const result = await notifier(server.url).send(ticket());
  assert.equal(result.status, 'sent');
  assert.equal(result.attempts, 2);
  assert.equal(result.error, null);
  assert.equal(server.requests.length, 2);
  assert.deepEqual(server.requests[0].body, server.requests[1].body);
});

for (const status of [429, 500, 503]) {
  test(`mail limits HTTP ${status} retries to two, even with more delays`, async (t) => {
    const server = await mailServer(t, (_request, response) => {
      json(response, status, {
        error: 'recipient_not_allowed',
        detail: `${privateValue} ${privateToken} ${apiToken}`,
      });
    });
    const result = await notifier(server.url, { backoffMs: [0, 0, 0, 0] }).send(
      ticket(),
    );
    assert.deepEqual(result, {
      status: 'failed',
      attempts: 3,
      error: `http_${status}`,
      notifiedAt: null,
    });
    assert.equal(server.requests.length, 3);
    assertNoSecrets(result);
  });
}

for (const status of [400, 401, 403, 404, 422]) {
  test(`mail does not retry permanent HTTP ${status} failures`, async (t) => {
    const server = await mailServer(t, (_request, response) => {
      json(response, status, {
        error: 'secret_detected',
        detail: privateValue,
      });
    });
    const input = ticket();
    const result = await notifier(server.url).send(input);
    assert.deepEqual(result, {
      status: 'failed',
      attempts: 1,
      error: `http_${status}`,
      notifiedAt: null,
    });
    assert.equal(server.requests.length, 1);
    assert.equal(input.status, 'done');
    assertNoSecrets(result);
  });
}

for (const code of ['recipient_not_allowed', 'send_not_allowed']) {
  test(`mail records only ${code} for HTTP 403 without retrying or logging`, async (t) => {
    const server = await mailServer(t, (_request, response) => {
      json(response, 403, {
        error: code,
        message: `${privateValue} ${privateToken} ${apiToken}`,
        detail: { token: privateToken, value: privateValue },
      });
    });
    const logs = [];
    for (const method of ['log', 'info', 'debug', 'warn', 'error']) {
      t.mock.method(console, method, (...args) => logs.push(args));
    }
    const input = ticket();
    const original = structuredClone(input);
    const sender = notifier(server.url);
    const result = await sender.send(input);
    assert.deepEqual(result, {
      status: 'failed',
      attempts: 1,
      error: code,
      notifiedAt: null,
    });
    assert.equal(server.requests.length, 1);
    assert.deepEqual(input, original);
    assertNoSecrets(result);
    assertNoSecrets(sender);
    assert.deepEqual(logs, []);
  });
}

for (const [name, body] of [
  ['empty', ''],
  [
    'malformed JSON',
    `{"error":"recipient_not_allowed","message":"${privateValue}`,
  ],
  ['null', 'null'],
  [
    'UTF-8 BOM',
    String.fromCharCode(0xfeff) + '{"error":"recipient_not_allowed"}',
  ],
  ['array', JSON.stringify([{ error: 'recipient_not_allowed' }])],
  ['unknown code', JSON.stringify({ error: `arbitrary_${privateValue}` })],
  [
    'code suffix',
    JSON.stringify({ error: `send_not_allowed_${privateToken}` }),
  ],
  ['wrong case', JSON.stringify({ error: 'RECIPIENT_NOT_ALLOWED' })],
  ['object code', JSON.stringify({ error: { code: 'send_not_allowed' } })],
  ['nested code', JSON.stringify({ detail: { error: 'send_not_allowed' } })],
  ['other field', JSON.stringify({ code: 'recipient_not_allowed' })],
  [
    'body over 4 KiB',
    JSON.stringify({ error: 'send_not_allowed', message: 'x'.repeat(4096) }),
  ],
]) {
  test(`mail keeps HTTP 403 with ${name} body generic, private, and nonretryable`, async (t) => {
    const server = await mailServer(t, (_request, response) => {
      response.writeHead(403, { 'Content-Type': 'application/json' });
      response.end(body);
    });
    const logs = [];
    for (const method of ['log', 'info', 'debug', 'warn', 'error']) {
      t.mock.method(console, method, (...args) => logs.push(args));
    }
    const sender = notifier(server.url);
    const result = await sender.send(ticket());
    assert.deepEqual(result, {
      status: 'failed',
      attempts: 1,
      error: 'http_403',
      notifiedAt: null,
    });
    assert.equal(server.requests.length, 1);
    assertNoSecrets(result);
    assertNoSecrets(sender);
    assert.deepEqual(logs, []);
  });
}

test('mail cancels an oversized streaming 403 body without reading it to completion', async (t) => {
  let reads = 0;
  let cancelled = false;
  const body = new ReadableStream(
    {
      pull(controller) {
        reads += 1;
        controller.enqueue(
          Buffer.from(
            (reads === 1
              ? '{"error":"recipient_not_allowed","message":"'
              : ''
            ).padEnd(2048, 'x'),
          ),
        );
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const fetch = t.mock.method(
    globalThis,
    'fetch',
    async () => new Response(body, { status: 403 }),
  );
  assert.deepEqual(await notifier('https://mail.example.com').send(ticket()), {
    status: 'failed',
    attempts: 1,
    error: 'http_403',
    notifiedAt: null,
  });
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(reads, 3);
  assert.equal(cancelled, true);
});

test('mail keeps a stalled HTTP 403 body nonretryable after the read timeout', async (t) => {
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(403, { 'Content-Type': 'application/json' });
    response.flushHeaders();
  });
  assert.deepEqual(
    await notifier(server.url, { timeoutMs: 100 }).send(ticket()),
    {
      status: 'failed',
      attempts: 1,
      error: 'http_403',
      notifiedAt: null,
    },
  );
  assert.equal(server.requests.length, 1);
});

test('mail keeps an interrupted HTTP 403 body nonretryable without exposing the error', async (t) => {
  const fetch = t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error(privateValue));
          },
        }),
        { status: 403 },
      ),
  );
  const logs = [];
  for (const method of ['log', 'info', 'debug', 'warn', 'error']) {
    t.mock.method(console, method, (...args) => logs.push(args));
  }
  const result = await notifier('https://mail.example.com').send(ticket());
  assert.deepEqual(result, {
    status: 'failed',
    attempts: 1,
    error: 'http_403',
    notifiedAt: null,
  });
  assert.equal(fetch.mock.callCount(), 1);
  assertNoSecrets(result);
  assert.deepEqual(logs, []);
});

test('mail retries a network disconnect', async (t) => {
  const server = await mailServer(t, (request, response, attempt) => {
    if (attempt === 1) request.socket.destroy();
    else json(response, 200, { rejected: [] });
  });
  const result = await notifier(server.url).send(ticket());
  assert.equal(result.status, 'sent');
  assert.equal(result.attempts, 2);
  assert.equal(server.requests.length, 2);
});

test('mail returns a bounded network error after repeated disconnects', async (t) => {
  const server = await mailServer(t, (request) => request.socket.destroy());
  assert.deepEqual(await notifier(server.url).send(ticket()), {
    status: 'failed',
    attempts: 3,
    error: 'network',
    notifiedAt: null,
  });
  assert.equal(server.requests.length, 3);
});

test('mail times out every attempt without leaking ticket data', async (t) => {
  const server = await mailServer(t, () => {});
  const result = await notifier(server.url, { timeoutMs: 100 }).send(ticket());
  assert.deepEqual(result, {
    status: 'failed',
    attempts: 3,
    error: 'timeout',
    notifiedAt: null,
  });
  assert.equal(server.requests.length, 3);
  assertNoSecrets(result);
});

test('mail cancellation interrupts a retry backoff without another attempt', async (t) => {
  const attempted = Promise.withResolvers();
  const fetch = t.mock.method(globalThis, 'fetch', async () => {
    attempted.resolve();
    return new Response('', { status: 503 });
  });
  const controller = new AbortController();
  const delivering = notifier('https://mail.example.com', {
    backoffMs: [60000, 60000],
  }).send(ticket(), { signal: controller.signal });
  const rejected = assert.rejects(delivering, { name: 'AbortError' });
  await attempted.promise;
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await rejected;
  assert.equal(fetch.mock.callCount(), 1);
});

test('mail cancellation before sending does not make an HTTP request', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', () => {
    assert.fail('Cancelled delivery must not start');
  });
  await assert.rejects(
    notifier('https://mail.example.com').send(ticket(), {
      signal: AbortSignal.abort(),
    }),
    { name: 'AbortError' },
  );
  assert.equal(fetch.mock.callCount(), 0);
});

test('mail timeout also covers reading the successful response body', async (t) => {
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.flushHeaders();
  });
  const result = await notifier(server.url, {
    timeoutMs: 100,
    backoffMs: [],
  }).send(ticket());
  assert.equal(result.error, 'timeout');
  assert.equal(result.attempts, 1);
});

test('mail treats a nonempty rejected list as a permanent failure', async (t) => {
  const server = await mailServer(t, (_request, response) => {
    json(response, 200, { rejected: [privateValue] });
  });
  assert.deepEqual(await notifier(server.url).send(ticket()), {
    status: 'failed',
    attempts: 1,
    error: 'rejected',
    notifiedAt: null,
  });
  assert.equal(server.requests.length, 1);
});

test('mail treats a rejected list after a UTF-8 BOM split across chunks as a permanent failure', async (t) => {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(Uint8Array.of(0xef));
      controller.enqueue(Uint8Array.of(0xbb));
      controller.enqueue(Uint8Array.of(0xbf));
      controller.enqueue(Buffer.from('{"rejected":["ops@example.com"]}'));
      controller.close();
    },
  });
  const fetch = t.mock.method(
    globalThis,
    'fetch',
    async () => new Response(body, { status: 200 }),
  );
  assert.deepEqual(await notifier('https://mail.example.com').send(ticket()), {
    status: 'failed',
    attempts: 1,
    error: 'rejected',
    notifiedAt: null,
  });
  assert.equal(fetch.mock.callCount(), 1);
});

for (const status of [201, 202, 204]) {
  test(`mail accepts HTTP ${status} without a JSON response body`, async (t) => {
    const server = await mailServer(t, (_request, response) => {
      response.writeHead(status);
      response.end('accepted');
    });
    assert.equal((await notifier(server.url).send(ticket())).status, 'sent');
  });
}

test('mail does not follow redirects or forward its authorization token', async (t) => {
  const destination = await mailServer(t, (_request, response) =>
    response.end(),
  );
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(307, { Location: `${destination.url}/destination` });
    response.end();
  });
  const result = await notifier(server.url, { backoffMs: [] }).send(ticket());
  assert.equal(result.status, 'failed');
  assert.equal(destination.requests.length, 0);
  assertNoSecrets(result);
});

test('mail supports failed-ticket notifications without a fingerprint', async (t) => {
  const server = await mailServer(t, (_request, response) =>
    json(response, 200, {}),
  );
  const result = await notifier(server.url).send(
    ticket({ status: 'failed', fingerprint: null }),
  );
  assert.equal(result.status, 'sent');
  assert.equal(server.requests[0].body.subject, 'Intake ticket failed');
  assert.ok(
    server.requests[0].body.text.includes('Fingerprint: Not available'),
  );
  assertNoSecrets(server.requests[0].body);
});

test('mail rejects invalid notification metadata without making requests', async (t) => {
  const server = await mailServer(t, (_request, response) => response.end());
  for (const input of [
    null,
    ticket({ status: 'pending' }),
    ticket({ notifyEmail: 'ops@example.com,other@example.com' }),
    ticket({ notifyEmail: 'ops@example.com\r\nBcc: other@example.com' }),
    ticket({ target: null }),
    ticket({ fingerprint: { value: privateValue } }),
  ]) {
    assert.deepEqual(await notifier(server.url).send(input), {
      status: 'failed',
      attempts: 0,
      error: 'invalid_ticket',
      notifiedAt: null,
    });
  }
  assert.equal(server.requests.length, 0);
});

test('mail rejects timeouts that Node would clamp to one millisecond', () => {
  assert.ok(notifier('https://mail.example.com', { timeoutMs: 2147483647 }));
  assert.throws(
    () => notifier('https://mail.example.com', { timeoutMs: 2147483648 }),
    { code: 'mail_config' },
  );
});

test('mail rejects unencodable bearer tokens before attempting a request', async (t) => {
  const server = await mailServer(t, (_request, response) => response.end());
  for (const character of [
    String.fromCharCode(256),
    String.fromCodePoint(65536),
  ]) {
    assert.throws(
      () => notifier(server.url, { token: `${apiToken}${character}` }),
      (error) => {
        assert.equal(error.code, 'mail_config');
        assertNoSecrets({
          message: error.message,
          stack: error.stack,
          ...error,
        });
        return true;
      },
    );
  }
  assert.equal(server.requests.length, 0);
});

test('mail validates configuration without exposing invalid URLs or tokens', () => {
  for (const options of [
    { url: `https://user:${privateValue}@mail.example.com` },
    { url: `https://mail.example.com?token=${privateToken}` },
    { url: `https://mail.example.com#${privateToken}` },
    { url: 'https://mail.example.com?' },
    { url: 'https://mail.example.com#' },
    { url: 'http://mail.example.com' },
    { url: 'file:///tmp/mail' },
    { url: privateToken },
    { token: '' },
    { token: `${apiToken}\n` },
    { mailbox: 'Name <intake@example.com>' },
    { timeoutMs: 0 },
    { backoffMs: [-1] },
  ]) {
    assert.throws(
      () => notifier('https://mail.example.com', options),
      (error) => {
        assert.equal(error.code, 'mail_config');
        assertNoSecrets({
          message: error.message,
          stack: error.stack,
          ...error,
        });
        return true;
      },
    );
  }
});

test('mail fails closed on a successful response over 16 KiB without leaking or logging data', async (t) => {
  const input = ticket();
  const original = structuredClone(input);
  const body = JSON.stringify({ rejected: [], detail: input, token: apiToken });
  const text = body.padEnd(16 * 1024 + 1, ' ');
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(text),
    });
    response.end(text);
  });
  const logs = [];
  for (const method of ['log', 'info', 'debug', 'warn', 'error']) {
    t.mock.method(console, method, (...args) => logs.push(args));
  }
  const result = await notifier(server.url).send(input);
  assert.deepEqual(result, {
    status: 'failed',
    attempts: 1,
    error: 'response_too_large',
    notifiedAt: null,
  });
  assert.equal(server.requests.length, 1);
  assert.deepEqual(input, original);
  assertNoSecrets(result);
  assert.deepEqual(logs, []);
});

test('mail cancels an oversized successful stream without a content length', async (t) => {
  let reads = 0;
  let cancelled = false;
  const body = new ReadableStream(
    {
      pull(controller) {
        reads += 1;
        controller.enqueue(
          Buffer.from(
            (reads === 1 ? JSON.stringify(ticket()) : '').padEnd(4096, ' '),
          ),
        );
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const response = new Response(body);
  assert.equal(response.headers.has('content-length'), false);
  const fetch = t.mock.method(globalThis, 'fetch', async () => response);
  const result = await notifier('https://mail.example.com').send(ticket());
  assert.deepEqual(result, {
    status: 'failed',
    attempts: 1,
    error: 'response_too_large',
    notifiedAt: null,
  });
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(reads, 5);
  assert.equal(cancelled, true);
  assertNoSecrets(result);
});

test('mail accepts a successful response at the 16 KiB byte limit', async (t) => {
  const body = JSON.stringify({ rejected: [], message: 'é' });
  const text = body + ' '.repeat(16 * 1024 - Buffer.byteLength(body));
  assert.equal(Buffer.byteLength(text), 16 * 1024);
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(text);
  });
  const result = await notifier(server.url).send(ticket());
  assert.equal(result.status, 'sent');
  assert.equal(result.attempts, 1);
  assert.equal(result.error, null);
  assert.equal(server.requests.length, 1);
});

test('mail timeout covers a successful response stalled at the 16 KiB byte limit', async (t) => {
  const server = await mailServer(t, (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.flushHeaders();
    response.write(' '.repeat(16 * 1024));
  });
  const result = await notifier(server.url, {
    timeoutMs: 100,
    backoffMs: [],
  }).send(ticket());
  assert.deepEqual(result, {
    status: 'failed',
    attempts: 1,
    error: 'timeout',
    notifiedAt: null,
  });
  assert.equal(server.requests.length, 1);
  assertNoSecrets(result);
});
