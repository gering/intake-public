import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { PassThrough } from 'node:stream';
import { readJson, securityHeaders } from '../src/http.js';
import { startWeb } from '../src/web.js';
import { fixture } from '../support/fixtures.js';

test('JSON body limits pause the request instead of draining later chunks', async () => {
  const req = new PassThrough();
  req.headers = { 'content-type': 'application/json' };
  try {
    const body = readJson(req, 32);
    req.write(Buffer.alloc(33, 'x'));
    await assert.rejects(body, { code: 'body_too_large', status: 413 });
    assert(req.isPaused());
    req.write(Buffer.alloc(1024, 'x'));
    assert.equal(req.readableLength, 1024);
  } finally {
    req.destroy();
  }
});

test(
  'an oversized upload receives the complete 413 response before its connection closes',
  { timeout: 5000 },
  async (t) => {
    const f = await fixture(t, { bodyLimit: 1024 });
    const web = await startWeb({
      store: f.store,
      config: f.config,
      logger: f.logger,
    });
    t.after(() => web.close());
    const totalBytes = 4 * 1024 * 1024;
    let bytesRead = 0;
    let received;
    const requestClosed = new Promise((resolve) => {
      web.server.prependOnceListener('request', (req) => {
        received = req;
        req.on('data', (chunk) => {
          bytesRead += chunk.length;
        });
        req.once('close', resolve);
      });
    });
    const raw = await new Promise((resolve, reject) => {
      const socket = connect(web.server.address().port, '127.0.0.1');
      t.after(() => socket.destroy());
      let data = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk) => {
        data += chunk;
      });
      socket.on('error', (error) => {
        if (error.code !== 'ECONNRESET') reject(error);
      });
      socket.on('close', () => resolve(data));
      socket.on('connect', () => {
        socket.write(
          `POST /api/open HTTP/1.1\r\nHost: intake.example.com\r\nContent-Type: application/json\r\nContent-Length: ${totalBytes}\r\nConnection: keep-alive\r\n\r\n`,
        );
        socket.write(Buffer.alloc(totalBytes, 'x'));
      });
    });
    await requestClosed;
    assert.match(raw, /^HTTP\/1\.1 413 Payload Too Large\r\n/);
    assert.match(raw, /\r\nConnection: close\r\n/i);
    const body = raw.match(
      /\r\n\r\n(?:[0-9a-f]+\r\n)?(\{"error":"body_too_large"\})(?:\r\n0\r\n\r\n)?$/i,
    );
    assert(body, 'The response contains the complete JSON error body');
    assert.deepEqual(JSON.parse(body[1]), { error: 'body_too_large' });
    for (const [key, value] of Object.entries(securityHeaders))
      assert(raw.toLowerCase().includes(`${key}: ${value}\r\n`.toLowerCase()));
    assert(received.destroyed);
    assert(bytesRead > f.config.bodyLimit);
    assert(
      bytesRead < totalBytes,
      `${bytesRead} of ${totalBytes} body bytes were read`,
    );
  },
);
