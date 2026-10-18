import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHmac, randomBytes } from 'node:crypto';
import { encryptRawValue } from '../support/raw-envelope.js';
import { stat } from 'node:fs/promises';
import { TicketStore } from '../src/db.js';
import { startWeb } from '../src/web.js';
import { startWriter } from '../src/writer.js';
import { writerRequest } from '../src/ipc.js';
import { MockVaultAdapter } from '../src/vault.js';
import { MailNotifier } from '../src/mail.js';
import { encryptValue } from '../public/crypto.js';
import { closeServer, listen } from '../src/http.js';
import { fixture, post, waitFor } from '../support/fixtures.js';

async function startFixture(
  t,
  {
    mailStatuses = [200],
    mailErrors = [],
    adapter,
    notifyOff = false,
    pollMs = 20,
  } = {},
) {
  let web;
  let writer;
  let webStore;
  let mailServer;
  // Hooks run in registration order: stop work before fixture closes SQLite.
  t.after(async () => {
    await web?.close();
    await writer?.close();
    webStore?.close();
    if (mailServer) await closeServer(mailServer);
  });
  const f = await fixture(t);
  const mails = [];
  mailServer = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    mails.push({
      path: req.url,
      authorization: req.headers.authorization,
      body,
      state: f.store.get(body.text.match(/[\w-]{22}/)?.[0])?.status,
    });
    res.writeHead(
      mailStatuses[Math.min(mails.length - 1, mailStatuses.length - 1)],
      { 'Content-Type': 'application/json' },
    );
    res.end(
      JSON.stringify(
        mailErrors[mails.length - 1]
          ? {
              error: mailErrors[mails.length - 1],
            }
          : {
              messageId: 'message-id',
              accepted: body.to,
              rejected: [],
            },
      ),
    );
  });
  await listen(mailServer, { host: '127.0.0.1', port: 0 });
  const vault = adapter ?? new MockVaultAdapter();
  const notifier = new MailNotifier({
    url: `http://127.0.0.1:${mailServer.address().port}`,
    token: 'mail-authorization-fixture',
    mailbox: 'intake@example.com',
    timeoutMs: 1000,
    backoffMs: [1, 1],
  });
  writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault,
    notifier,
    notifyOff,
    socketPath: f.config.socketPath,
    pollMs,
    logger: f.logger,
  });
  webStore = new TicketStore(f.config.dbPath, f.config.hmacKey);
  web = await startWeb({
    store: webStore,
    config: f.config,
    logger: f.logger,
  });
  return {
    ...f,
    vault,
    writer,
    web,
    mails,
    base: `http://127.0.0.1:${web.server.address().port}`,
  };
}

test('writer fingerprints bind each ticket ID and the configured key', async (t) => {
  const f = await fixture(t);
  const value = 'low-entropy-value';
  const fingerprints = [];
  for (const fingerprintKey of [
    f.config.fingerprintKey,
    f.config.fingerprintKey,
    randomBytes(32),
  ]) {
    const { ticket, token } = f.create();
    f.store.claim(token, await encryptValue(ticket, value));
    const writer = await startWriter({
      store: f.store,
      keys: f.keys,
      masterKey: f.config.masterKey,
      fingerprintKey,
      adapter: new MockVaultAdapter(),
      notifyOff: true,
      socketPath: f.config.socketPath,
      logger: f.logger,
    });
    try {
      await writer.drain();
      const done = f.store.get(ticket.id);
      assert.equal(done.status, 'done');
      assert.equal(
        done.fingerprint,
        createHmac('sha256', fingerprintKey)
          .update(JSON.stringify([ticket.id, value]), 'utf8')
          .digest('hex')
          .slice(0, 16),
      );
      fingerprints.push(done.fingerprint);
    } finally {
      await writer.close();
    }
  }
  assert.notEqual(fingerprints[0], fingerprints[1]);
  assert.notEqual(fingerprints[0], fingerprints[2]);
});

test('end-to-end: browser encrypts, Unix writer decrypts, vault writes, then ping mail sends', async (t) => {
  const f = await startFixture(t);
  const { ticket, token } = f.create({
    targetNotes: 'Move into the application collection after review',
  });
  const value = 'e2e-private-input-4ebcb5';
  const pasted = ` \t\r\n${String.fromCodePoint(0xfeff)}${value}\n\r `;
  assert.equal((await fetch(f.base + '/')).status, 200);
  assert.equal(f.store.get(ticket.id).status, 'active');
  const open = await post(f.base, '/api/open', { token });
  const browserTicket = await open.json();
  assert.equal(browserTicket.trim, true);
  const envelope = await encryptValue(browserTicket, pasted);
  const submission = await post(f.base, '/api/submit', { token, envelope });
  assert.equal(submission.status, 202);
  const result = await submission.json();
  assert(!JSON.stringify(result).includes(value));
  await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
  const done = f.store.get(ticket.id);
  assert.equal(done.status, 'done');
  assert.equal(done.envelope, null);
  assert.equal(done.notifyAttempts, 1);
  assert.equal(done.notifyError, null);
  assert.equal(
    done.fingerprint,
    createHmac('sha256', f.config.fingerprintKey)
      .update(JSON.stringify([ticket.id, value]), 'utf8')
      .digest('hex')
      .slice(0, 16),
  );
  assert(done.notifiedAt);
  assert.equal(f.keys.get(ticket.id), undefined);
  assert.equal(f.vault.entries.length, 1);
  assert.equal(f.vault.entries[0].value, value);
  assert.equal(f.vault.entries[0].ticketId, ticket.id);
  assert.equal(f.vault.entries[0].fingerprint, done.fingerprint);
  assert.deepEqual(f.vault.entries[0].target, ticket.target);
  assert.equal((await stat(f.config.socketPath)).mode & 0o777, 0o660);
  assert.equal(f.mails.length, 1);
  const mail = f.mails[0];
  assert.equal(mail.state, 'done');
  assert.deepEqual(mail.body.to, ['ops@example.com']);
  for (const metadata of [
    ticket.id,
    ticket.keyName,
    ticket.purpose,
    ticket.target.item,
    ticket.target.field,
    done.fingerprint,
    done.completedAt,
  ])
    assert(mail.body.text.includes(metadata));
  const exposed = JSON.stringify({
    logs: f.logs,
    mails: f.mails,
    response: result,
  });
  for (const sensitive of [
    value,
    token,
    token.split('.')[1],
    envelope.ciphertext,
  ])
    assert(!exposed.includes(sensitive));
  assert.equal(
    (await post(f.base, '/api/submit', { token, envelope })).status,
    400,
  );
});

test('notification 503 retries succeed without repeating a vault write', async (t) => {
  const f = await startFixture(t, { mailStatuses: [503, 200] });
  const { ticket, token } = f.create();
  await post(f.base, '/api/submit', {
    token,
    envelope: await encryptValue(ticket, 'retry-notification-value'),
  });
  await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
  assert.equal(f.store.get(ticket.id).notifyAttempts, 2);
  assert.equal(f.vault.entries.length, 1);
  assert.equal(f.mails.length, 2);
});

test('permanent notification failure leaves ticket done and vault intact; CLI IPC retry resends only mail', async (t) => {
  const f = await startFixture(t, { mailStatuses: [422, 200] });
  const { ticket, token } = f.create();
  await post(f.base, '/api/submit', {
    token,
    envelope: await encryptValue(ticket, 'stored-despite-mail-failure'),
  });
  await waitFor(() => f.store.get(ticket.id).notifyStatus === 'failed');
  const failedMail = f.store.get(ticket.id);
  assert.equal(failedMail.status, 'done');
  assert.equal(failedMail.notifyAttempts, 1);
  assert.equal(failedMail.notifyError, 'http_422');
  assert.equal(f.vault.entries.length, 1);
  assert.equal(f.keys.get(ticket.id), undefined);
  assert.equal(f.keys.getMetadata(ticket.id).notifyEmail, ticket.notifyEmail);
  f.store.db
    .prepare(
      `UPDATE tickets SET key_name = ?, purpose = ?, trim = ?, meta_digest = ? WHERE id = ?`,
    )
    .run('ALTERED_KEY', 'Altered purpose', 0, '0'.repeat(64), ticket.id);
  await writerRequest(f.config.socketPath, '/notify-retry', ticket.id);
  await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
  assert.equal(f.store.get(ticket.id).notifyAttempts, 2);
  assert.equal(f.vault.entries.length, 1);
  assert.deepEqual(f.mails.at(-1).body.to, ['ops@example.com']);
  assert(f.mails.at(-1).body.text.includes(ticket.keyName));
  assert(f.mails.at(-1).body.text.includes(ticket.purpose));
  assert(f.mails.at(-1).body.text.includes(ticket.target.item));
  assert(!JSON.stringify(f.mails).includes('ALTERED_KEY'));
  assert(!JSON.stringify(f.mails).includes('Altered'));
  await assert.rejects(
    writerRequest(f.config.socketPath, '/notify-retry', ticket.id),
  );
});

test('writer failure is terminal, cannot reuse token, and sends a value-free failure ping', async (t) => {
  const value = 'vault-failure-private-value';
  const f = await startFixture(t, {
    adapter: {
      async write() {
        throw new Error(value);
      },
    },
  });
  const { ticket, token } = f.create();
  const envelope = await encryptValue(ticket, value);
  await post(f.base, '/api/submit', { token, envelope });
  await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
  const failed = f.store.get(ticket.id);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.failureCode, 'writer_failed');
  assert.equal(failed.envelope, null);
  assert.equal((await post(f.base, '/api/open', { token })).status, 400);
  assert(!JSON.stringify({ logs: f.logs, mails: f.mails }).includes(value));
  assert(f.mails[0].body.text.toLowerCase().includes('failed'));
});

test('bad AAD fails closed before calling vault and still consumes the ticket', async (t) => {
  const f = await startFixture(t);
  const { ticket, token } = f.create();
  const envelope = await encryptValue(
    { ...ticket, purpose: 'Different purpose' },
    'aad-bound-value',
  );
  await post(f.base, '/api/submit', { token, envelope });
  await waitFor(() => f.store.get(ticket.id).status === 'failed');
  assert.equal(f.vault.entries.length, 0);
  assert.throws(() => f.store.open(token), /ticket_unavailable/);
});

test('committed queue survives missed socket wakeup and is processed at writer startup', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'durable-queued-value'));
  const vault = new MockVaultAdapter();
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault,
    notifyOff: true,
    socketPath: f.config.socketPath,
    logger: f.logger,
  });
  t.after(() => writer.close());
  await waitFor(() => f.store.get(ticket.id).status === 'done');
  assert.equal(vault.entries.length, 1);
  assert.equal(f.store.get(ticket.id).notifyStatus, 'failed');
  assert.equal(f.store.get(ticket.id).notifyError, 'disabled');
});

test('interrupted external writes become unknown on startup and wait for settled lookup', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'ambiguous-crash-value'));
  f.store.begin(ticket.id);
  const vault = new MockVaultAdapter();
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault,
    notifyOff: true,
    socketPath: f.config.socketPath,
    logger: f.logger,
  });
  t.after(() => writer.close());
  await writer.drain();
  const unknown = f.store.get(ticket.id);
  assert.equal(unknown.status, 'unknown');
  assert.equal(unknown.failureCode, 'writer_interrupted');
  assert(unknown.envelope);
  assert(f.keys.get(ticket.id));
  assert.equal(unknown.notifyStatus, null);
  assert.equal(vault.entries.length, 0);
});

test('writer refuses missing mail configuration and a second writer cannot steal its socket', async (t) => {
  const f = await fixture(t);
  const options = {
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: new MockVaultAdapter(),
    socketPath: f.config.socketPath,
    logger: f.logger,
  };
  await assert.rejects(startWriter(options), /mail_configuration_required/);
  const writer = await startWriter({ ...options, notifyOff: true });
  t.after(() => writer.close());
  await assert.rejects(startWriter({ ...options, notifyOff: true }), {
    code: 'EADDRINUSE',
  });
  assert.equal(
    (await writerRequest(f.config.socketPath, '/process', 'a'.repeat(22)))
      .status,
    'queued',
  );
});

test('mail allowlist and sender-permission failures persist safe nonretryable codes without undoing storage', async (t) => {
  for (const code of ['recipient_not_allowed', 'send_not_allowed']) {
    const f = await startFixture(t, {
      mailStatuses: [403],
      mailErrors: [code],
    });
    const { ticket, token } = f.create();
    const value = 'stored-before-forbidden-notification';
    await post(f.base, '/api/submit', {
      token,
      envelope: await encryptValue(ticket, value),
    });
    await waitFor(() => f.store.get(ticket.id).notifyStatus === 'failed');
    const done = f.store.get(ticket.id);
    assert.equal(done.status, 'done');
    assert.equal(done.notifyError, code);
    assert.equal(done.notifyAttempts, 1);
    assert.equal(done.notifiedAt, null);
    assert.equal(f.mails.length, 1);
    assert.equal(f.vault.entries.length, 1);
    assert.equal(f.vault.entries[0].value, value);
    const exposed = JSON.stringify({ logs: f.logs, mails: f.mails });
    assert(!exposed.includes(value));
    assert(!exposed.includes(token));
  }
});

test('writer rejects authenticated untrimmed or empty plaintext as invalid_payload without a vault write', async (t) => {
  const f = await startFixture(t);
  for (const [keepWhitespace, value] of [
    [false, '  malicious-untrimmed-value\r\n'],
    [false, '\t \n﻿'],
    [false, ''],
    [true, ''],
  ]) {
    const { ticket, token } = f.create({ keepWhitespace });
    const envelope = encryptRawValue(ticket, value);
    const response = await post(f.base, '/api/submit', { token, envelope });
    assert.equal(response.status, 202);
    await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
    const failed = f.store.get(ticket.id);
    assert.equal(failed.status, 'failed');
    assert.equal(failed.failureCode, 'invalid_payload');
    assert.equal(failed.envelope, null);
    assert.equal(f.keys.get(ticket.id), undefined);
    assert.equal(f.vault.entries.length, 0);
    assert.throws(() => f.store.open(token), /ticket_unavailable/);
    if (value.trim())
      assert(
        !JSON.stringify({ logs: f.logs, mails: f.mails }).includes(
          value.trim(),
        ),
      );
  }
});

test('keep-whitespace stores exact plaintext including whitespace-only values and matching fingerprints', async (t) => {
  const f = await startFixture(t);
  for (const value of [' \t\r\n﻿keep-exactly  \n', ' \t\r\n﻿']) {
    const { ticket, token } = f.create({ keepWhitespace: true });
    const opened = await (await post(f.base, '/api/open', { token })).json();
    assert.equal(opened.trim, false);
    await post(f.base, '/api/submit', {
      token,
      envelope: await encryptValue(opened, value),
    });
    await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
    const done = f.store.get(ticket.id);
    assert.equal(done.status, 'done');
    assert.equal(f.vault.entries.at(-1).value, value);
    assert.equal(
      done.fingerprint,
      createHmac('sha256', f.config.fingerprintKey)
        .update(JSON.stringify([ticket.id, value]), 'utf8')
        .digest('hex')
        .slice(0, 16),
    );
  }
});

test('flipping the trim metadata in transit fails AAD authentication before vault storage', async (t) => {
  const f = await startFixture(t);
  for (const keepWhitespace of [false, true]) {
    const { ticket, token } = f.create({ keepWhitespace });
    const envelope = await encryptValue(
      { ...ticket, trim: !ticket.trim },
      'already-trimmed-value',
    );
    await post(f.base, '/api/submit', { token, envelope });
    await waitFor(() => f.store.get(ticket.id).notifyStatus === 'sent');
    assert.equal(f.store.get(ticket.id).status, 'failed');
    assert.equal(f.vault.entries.length, 0);
    assert.throws(() => f.store.open(token), /ticket_unavailable/);
  }
});
