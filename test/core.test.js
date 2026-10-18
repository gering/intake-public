import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { stat, readFile, writeFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import {
  createToken,
  tokenDigest,
  verifyToken,
  parseToken,
} from '../src/tokens.js';
import { parseDuration, ticketTtl, emailAddress } from '../src/validation.js';
import {
  createTicketKeys,
  decryptValue,
  validateEnvelope,
} from '../src/crypto.js';
import { encryptValue, aadBytes } from '../public/crypto.js';
import { metadataDigest } from '../src/metadata.js';
import { loadConfig, readSecret } from '../src/config.js';
import { RateLimiter } from '../src/rate-limit.js';
import { createLogger } from '../src/logger.js';
import { fixture } from '../support/fixtures.js';
import { encryptRawValue } from '../support/raw-envelope.js';
import { TicketStore, PrivateKeyStore } from '../src/db.js';

const DAY = 86400000;
const TRIM_WHITESPACE = String.fromCodePoint(
  0x0009,
  0x000a,
  0x000b,
  0x000c,
  0x000d,
  0x0020,
  0x00a0,
  0x1680,
  0x2000,
  0x2001,
  0x2002,
  0x2003,
  0x2004,
  0x2005,
  0x2006,
  0x2007,
  0x2008,
  0x2009,
  0x200a,
  0x2028,
  0x2029,
  0x202f,
  0x205f,
  0x3000,
  0xfeff,
);

test('existing shared database modes are preserved and unsafe database permissions are refused', async (t) => {
  const f = await fixture(t);
  try {
    await chmod(f.config.dbPath, 0o640);
    const second = new TicketStore(f.config.dbPath, f.config.hmacKey);
    second.close();
    assert.equal((await stat(f.config.dbPath)).mode & 0o777, 0o640);
    await chmod(f.config.dbPath, 0o644);
    assert.throws(
      () => new TicketStore(f.config.dbPath, f.config.hmacKey),
      /unsafe_database_permissions/,
    );
    await chmod(f.config.privateDbPath, 0o640);
    assert.throws(
      () => new PrivateKeyStore(f.config.privateDbPath),
      /unsafe_database_permissions/,
    );
  } finally {
    await chmod(f.config.dbPath, 0o660);
    await chmod(f.config.privateDbPath, 0o600);
  }
});

test('tokens use independent 128-bit ids, 256-bit secrets and bound HMACs', () => {
  const key = randomBytes(32);
  const first = createToken(key);
  const second = createToken(key);
  assert.equal(first.id.length, 22);
  assert.equal(parseToken(first.token).secret.length, 43);
  assert.notEqual(first.id, second.id);
  assert.notEqual(first.token, second.token);
  assert.equal(first.digest.length, 32);
  assert(verifyToken(key, first.token, first.digest));
  assert(!verifyToken(key, second.token, first.digest));
  assert(
    !verifyToken(
      key,
      `${first.id}.${parseToken(second.token).secret}`,
      first.digest,
    ),
  );
  assert(!verifyToken(randomBytes(32), first.token, first.digest));
  assert(
    !verifyToken(
      key,
      `${second.id}.${parseToken(first.token).secret}`,
      first.digest,
    ),
  );
  for (const invalid of [null, undefined, '', 'not-a-token', first.token + 'x'])
    assert(!verifyToken(key, invalid, first.digest));
  assert(!verifyToken(key, first.token, Buffer.alloc(31)));
  assert(!verifyToken(key, first.token, undefined));
  assert.deepEqual(
    tokenDigest(key, first.id, parseToken(first.token).secret),
    first.digest,
  );
});

test('TTL defaults to 24h, caps at 7d, and accepts a configured maximum', () => {
  assert.equal(ticketTtl(), DAY);
  assert.equal(ticketTtl('30m'), 1800000);
  assert.equal(ticketTtl('24h'), DAY);
  assert.equal(ticketTtl('7d'), DAY * 7);
  assert.equal(ticketTtl('9d', DAY * 10), DAY * 9);
  assert.equal(parseDuration('12h'), DAY / 2);
  for (const value of [
    '8d',
    '0m',
    '0h',
    '-1h',
    '1',
    '1.5h',
    '1w',
    'Infinityh',
    '99999999999999999999d',
  ])
    assert.throws(() => ticketTtl(value));
  assert.throws(() => ticketTtl('25h', DAY));
});

test('notification addresses are one plain address, never header input or lists', () => {
  assert.equal(
    emailAddress('ops+intake@example.com'),
    'ops+intake@example.com',
  );
  for (const value of [
    undefined,
    '',
    'ops@example.com\r\nBcc: intake@example.com',
    'ops@example.com,intake@example.com',
    'Operator <ops@example.com>',
    ' ops@example.com',
    'ops@example.com ',
    '.ops@example.com',
    'ops..team@example.com',
    'ops@-example.com',
  ])
    assert.throws(() => emailAddress(value));
});

test('browser WebCrypto envelopes decrypt in writer and bind all AAD fields', async () => {
  const masterKey = randomBytes(32);
  const id = createToken(randomBytes(32)).id;
  const keys = createTicketKeys(masterKey, id);
  const ticket = {
    id,
    keyName: 'DATABASE_KEY',
    purpose: 'Connect café 🔒',
    trim: true,
    target: {
      item: 'Database ☃',
      field: 'password',
      notes: 'Review before moving 🔒',
    },
    notifyEmail: 'ops@example.com',
    publicKey: keys.publicKey,
  };
  ticket.metaDigest = metadataDigest(ticket);
  assert.equal(
    ticket.metaDigest,
    'b690a8eb0cf1b9cb037619717830c43a062dca508f52a4478129f55d215d2f13',
  );
  for (const trim of [undefined, true, false]) {
    // Property insertion order must not affect the fixed-order AAD array.
    const reordered = {
      notifyEmail: ticket.notifyEmail,
      target: {
        notes: ticket.target.notes,
        field: ticket.target.field,
        item: ticket.target.item,
      },
      metaDigest: ticket.metaDigest,
      trim,
      purpose: ticket.purpose,
      keyName: ticket.keyName,
      id,
    };
    assert.equal(metadataDigest(reordered), ticket.metaDigest);
    assert.deepEqual(
      aadBytes(reordered),
      new TextEncoder().encode(
        JSON.stringify([
          id,
          ticket.keyName,
          ticket.purpose,
          trim ?? true,
          ticket.metaDigest,
        ]),
      ),
    );
  }
  const envelope = await encryptValue(
    ticket,
    'value with unicode ☃ and\nnewlines',
  );
  assert.equal(validateEnvelope(envelope).iv.length, 12);
  assert.equal(validateEnvelope(envelope).wrappedKey.length, 384);
  const result = decryptValue(masterKey, ticket, keys.privateKey, envelope);
  assert.equal(result.value, 'value with unicode ☃ and\nnewlines');
  assert.deepEqual(Object.keys(result), ['value']);
  for (const changed of [
    { ...ticket, id: `${id}-changed` },
    { ...ticket, keyName: 'CHANGED_KEY' },
    { ...ticket, purpose: 'Changed purpose' },
    { ...ticket, trim: false },
    { ...ticket, metaDigest: '0'.repeat(64) },
    {
      ...ticket,
      metaDigest: metadataDigest({
        ...ticket,
        notifyEmail: 'other@example.com',
      }),
    },
    ...['item', 'field', 'notes'].map((field) => ({
      ...ticket,
      metaDigest: metadataDigest({
        ...ticket,
        target: {
          ...ticket.target,
          [field]: `${ticket.target[field]}-changed`,
        },
      }),
    })),
  ]) {
    assert.throws(
      () => decryptValue(masterKey, changed, keys.privateKey, envelope),
      { message: /unable to authenticate data/ },
    );
    // Already-prepared plaintext is valid in either mode: flipping trim must
    // fail authentication, not merely the writer's whitespace validation.
    const wrongEnvelope = await encryptValue(changed, result.value);
    assert.throws(
      () => decryptValue(masterKey, ticket, keys.privateKey, wrongEnvelope),
      { message: /unable to authenticate data/ },
    );
  }
  assert.throws(() =>
    decryptValue(randomBytes(32), ticket, keys.privateKey, envelope),
  );
  assert.throws(() => validateEnvelope({ ...envelope, iv: 'x' }));
  assert.throws(() => validateEnvelope({ ...envelope, extra: true }));
  assert.notDeepEqual(await encryptValue(ticket, result.value), envelope);
});

test('browser default trims String.prototype.trim boundaries before encryption', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  assert.equal(ticket.trim, true);
  const defaultTicket = { ...ticket };
  delete defaultTicket.trim;
  const internal = `value${TRIM_WHITESPACE}with internal whitespace ☃`;
  const nonTrimWhitespace = String.fromCodePoint(
    0x0085,
    0x180e,
    0x200b,
    0x2060,
  );
  const cases = [
    ['already prepared', internal, internal],
    ['spaces and tabs', ` \t${internal}\t `, internal],
    ['newlines', `\r\n${internal}\n\r`, internal],
    [
      'all ECMAScript whitespace',
      `${TRIM_WHITESPACE}${internal}${TRIM_WHITESPACE}`,
      internal,
    ],
    [
      'BOM',
      `${String.fromCodePoint(0xfeff)}${internal}${String.fromCodePoint(0xfeff)}`,
      internal,
    ],
    [
      'non-trim code points',
      `${TRIM_WHITESPACE}${nonTrimWhitespace}${internal}${nonTrimWhitespace}${TRIM_WHITESPACE}`,
      `${nonTrimWhitespace}${internal}${nonTrimWhitespace}`,
    ],
  ];
  for (const browserTicket of [defaultTicket, ticket]) {
    for (const [label, input, expected] of cases) {
      assert.equal(input.trim(), expected, label);
      const envelope = await encryptValue(browserTicket, input);
      const result = decryptValue(
        f.config.masterKey,
        browserTicket,
        f.keys.get(ticket.id),
        envelope,
      );
      assert.equal(result.value, expected, label);
    }
  }
});

test('keepWhitespace tickets preserve boundary and internal whitespace, whitespace-only values and BOM', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create({ keepWhitespace: true });
  assert.equal(ticket.trim, false);
  for (const value of [
    ` \tvalue${TRIM_WHITESPACE}with internal whitespace ☃\r\n `,
    TRIM_WHITESPACE,
    ' \t\r\n',
    String.fromCodePoint(0xfeff),
    `${String.fromCodePoint(0xfeff)}value${String.fromCodePoint(0xfeff)}`,
  ]) {
    const envelope = await encryptValue(ticket, value);
    const result = decryptValue(
      f.config.masterKey,
      ticket,
      f.keys.get(ticket.id),
      envelope,
    );
    assert.equal(result.value, value);
  }
});

test('browser rejects zero-length values in every mode and whitespace-only values when trimming', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  for (const trim of [undefined, true, false]) {
    const browserTicket = { ...ticket, trim };
    await assert.rejects(encryptValue(browserTicket, ''), {
      message: 'empty_value',
    });
    if (trim !== false) {
      for (const value of [
        ' \t\r\n',
        TRIM_WHITESPACE,
        String.fromCodePoint(0xfeff),
      ])
        await assert.rejects(encryptValue(browserTicket, value), {
          message: 'empty_value',
        });
    }
  }
});

test('writer rejects authenticated raw empty or untrimmed payloads instead of silently preparing them', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  const privateKey = f.keys.get(ticket.id);
  for (const trim of [undefined, true, false]) {
    const rawTicket = { ...ticket, trim };
    assert.throws(
      () =>
        decryptValue(
          f.config.masterKey,
          rawTicket,
          privateKey,
          encryptRawValue(rawTicket, ''),
        ),
      { code: 'invalid_payload', message: 'invalid_payload' },
    );
    if (trim !== false) {
      for (const value of [
        ' leading',
        'trailing ',
        '\r\nvalue\n',
        `${TRIM_WHITESPACE}value${TRIM_WHITESPACE}`,
        TRIM_WHITESPACE,
        String.fromCodePoint(0xfeff),
      ])
        assert.throws(
          () =>
            decryptValue(
              f.config.masterKey,
              rawTicket,
              privateKey,
              encryptRawValue(rawTicket, value),
            ),
          { code: 'invalid_payload', message: 'invalid_payload' },
        );
    }
  }
  const keepTicket = { ...ticket, trim: false };
  for (const value of [
    ' \t\r\n',
    TRIM_WHITESPACE,
    String.fromCodePoint(0xfeff),
    `${String.fromCodePoint(0xfeff)} raw value \n`,
  ]) {
    const result = decryptValue(
      f.config.masterKey,
      keepTicket,
      privateKey,
      encryptRawValue(keepTicket, value),
    );
    assert.equal(result.value, value);
  }
});

test('public store has no private keys, raw tokens or values; key store is private', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  assert.equal(ticket.notifyEmail, 'ops@example.com');
  const row = f.store.db
    .prepare('SELECT * FROM tickets WHERE id = ?')
    .get(ticket.id);
  assert.deepEqual(
    row.token_hmac,
    tokenDigest(f.config.hmacKey, ticket.id, parseToken(token).secret),
  );
  assert(!JSON.stringify(row).includes(token));
  assert(!Object.keys(row).some((key) => key.includes('private')));
  assert.equal((await stat(f.config.privateDbPath)).mode & 0o777, 0o600);
  const privateKey = f.keys.get(ticket.id);
  assert(!privateKey.includes('PRIVATE KEY'));
  assert(!privateKey.includes('"d":'));
  assert.equal(
    (await readFile(f.config.dbPath)).includes(Buffer.from(token)),
    false,
  );
});

test('ticket creation requires email, validates before persisting, and honors defaults', async (t) => {
  const f = await fixture(t);
  f.config.defaultNotifyEmail = undefined;
  assert.throws(() => f.create(), /single_notify_email_required/);
  assert.equal(f.store.list().length, 0);
  const { ticket } = f.create({
    notifyEmail: 'intake@example.com',
    ttl: '48h',
  });
  assert.equal(ticket.notifyEmail, 'intake@example.com');
  assert.equal(ticket.expiresAt - ticket.createdAt, 2 * DAY);
  assert.throws(() =>
    f.create({ notifyEmail: 'ops@example.com', keyName: 'bad\nname' }),
  );
});

test('ticket creation preserves targets colliding with vault reference names', async (t) => {
  const f = await fixture(t);
  for (const targetField of ['intake_fingerprint', 'intake_ticket_id']) {
    const { ticket, token } = f.create({ targetField });
    assert.equal(ticket.target.field, targetField);
    assert.equal(f.store.open(token).metaDigest, metadataDigest(ticket));
    assert.equal(f.keys.getMetadata(ticket.id).target.field, targetField);
    assert(f.keys.get(ticket.id));
  }
  assert.equal(f.store.list().length, 2);
});

test('keepWhitespace only accepts booleans and rejects invalid input before persisting', async (t) => {
  const f = await fixture(t);
  for (const keepWhitespace of [
    null,
    '',
    'true',
    'false',
    0,
    1,
    NaN,
    [],
    {},
    Object(false),
  ]) {
    assert.throws(() => f.create({ keepWhitespace }), {
      code: 'invalid_keep_whitespace',
      message: 'invalid_keep_whitespace',
    });
  }
  assert.equal(f.store.list().length, 0);
  assert.equal(
    f.keys.db.prepare('SELECT count(*) AS count FROM private_keys').get().count,
    0,
  );
});

test('trim defaults to true and roundtrips as a boolean through storage, reopen and open', async (t) => {
  const f = await fixture(t);
  const defaults = f.create();
  const explicitTrim = f.create({ keepWhitespace: false });
  const keepWhitespace = f.create({ keepWhitespace: true });
  const token = createToken(f.config.hmacKey);
  const directTicket = f.store.create({
    id: token.id,
    digest: token.digest,
    keyName: defaults.ticket.keyName,
    purpose: defaults.ticket.purpose,
    target: defaults.ticket.target,
    notifyEmail: defaults.ticket.notifyEmail,
    metaDigest: defaults.ticket.metaDigest,
    publicKey: defaults.ticket.publicKey,
    ttl: DAY,
  });
  const cases = [
    [defaults, true],
    [explicitTrim, true],
    [keepWhitespace, false],
    [{ ticket: directTicket, token: token.token }, true],
  ];
  for (const [{ ticket }, expected] of cases) {
    assert.equal(ticket.trim, expected);
    assert.equal(f.store.get(ticket.id).trim, expected);
    assert.equal(
      f.store.db.prepare('SELECT trim FROM tickets WHERE id = ?').get(ticket.id)
        .trim,
      expected ? 1 : 0,
    );
  }
  f.store.close();
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  try {
    for (const [{ ticket, token }, expected] of cases) {
      assert.equal(reopened.get(ticket.id).trim, expected);
      assert.equal(reopened.open(token).trim, expected);
    }
  } finally {
    reopened.close();
  }
});

test('opening an old database migrates existing tickets to trim=true', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  // Dropping only the new column reproduces the previous schema and data.
  f.store.db.exec('ALTER TABLE tickets DROP COLUMN trim');
  assert(
    !f.store.db
      .pragma('table_info(tickets)')
      .some(({ name }) => name === 'trim'),
  );
  f.store.close();
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  try {
    const column = reopened.db
      .pragma('table_info(tickets)')
      .find(({ name }) => name === 'trim');
    assert.equal(column.notnull, 1);
    assert.equal(column.dflt_value, '1');
    assert.equal(reopened.get(ticket.id).trim, true);
    assert.equal(reopened.open(token).trim, true);
    assert.equal(
      reopened.db
        .prepare('SELECT trim FROM tickets WHERE id = ?')
        .get(ticket.id).trim,
      1,
    );
  } finally {
    reopened.close();
  }
});

test('open is non-consuming; expired, revoked, used and wrong tokens share one error', async (t) => {
  const f = await fixture(t);
  const first = f.create();
  f.store.open(first.token);
  f.store.open(first.token);
  assert.equal(f.store.get(first.ticket.id).status, 'active');
  assert(f.store.get(first.ticket.id).openedAt);
  const generic = (operation) =>
    assert.throws(operation, { message: 'ticket_unavailable' });
  generic(() => f.store.open(first.token, first.ticket.expiresAt));
  generic(() => f.store.open(createToken(f.config.hmacKey).token));
  f.store.revoke(first.ticket.id);
  generic(() => f.store.open(first.token));
  const second = f.create();
  const envelope = await encryptValue(second.ticket, 'one-value');
  f.store.claim(second.token, envelope);
  generic(() => f.store.open(second.token));
  generic(() => f.store.claim(second.token, envelope));
  assert.throws(() => f.store.revoke(second.ticket.id));
});

test('invalid envelope does not consume a ticket', async (t) => {
  const f = await fixture(t);
  const { token, ticket } = f.create();
  assert.throws(() => f.store.claim(token, {}), /invalid_envelope/);
  assert.equal(f.store.get(ticket.id).status, 'active');
});

test('purge respects retention, active expiry, notifications and work in flight', async (t) => {
  const f = await fixture(t);
  const expired = f.create();
  const revoked = f.create();
  const pending = f.create();
  const done = f.create();
  f.store.revoke(revoked.ticket.id);
  f.store.claim(
    pending.token,
    await encryptValue(pending.ticket, 'queued-value'),
  );
  f.store.claim(done.token, await encryptValue(done.ticket, 'completed-value'));
  f.store.begin(done.ticket.id);
  f.store.finish(done.ticket.id, '1234567890abcdef');
  const future = Date.now() + 40 * DAY;
  const removed = f.store.purge(30, future);
  assert.deepEqual(
    new Set(removed),
    new Set([expired.ticket.id, revoked.ticket.id]),
  );
  assert(f.store.get(pending.ticket.id));
  assert(f.store.get(done.ticket.id));
  f.store.recordNotification(done.ticket.id, {
    status: 'sent',
    attempts: 1,
    error: null,
    notifiedAt: new Date().toISOString(),
  });
  assert.deepEqual(f.store.purge(30, future), [done.ticket.id]);
  f.keys.prune(f.store);
  assert.equal(f.keys.get(expired.ticket.id), undefined);
  assert(f.keys.get(pending.ticket.id));
  assert.throws(() => f.store.purge(-1));
});

test('structured logs redact sensitive fields and untrusted error messages', () => {
  const logs = [];
  const logger = createLogger({ write: (line) => logs.push(line) });
  const sensitive = 'unpredictable-sensitive-text.123';
  logger.info('request_failed', {
    id: sensitive,
    token: sensitive,
    value: sensitive,
    secret: sensitive,
    envelope: { ciphertext: sensitive },
    error: new Error(sensitive),
    authorization: sensitive,
    code: 'writer_failed',
    attempts: 1,
  });
  assert(!logs.join('').includes(sensitive));
  const record = JSON.parse(logs[0]);
  assert.equal(record.code, 'writer_failed');
  assert.equal(record.token, '[REDACTED]');
  assert.equal(record.attempts, 1);
});

test('fixed-window limits enforce IP, ticket and bounded memory independently', () => {
  const limiter = new RateLimiter({
    ipLimit: 2,
    ticketLimit: 1,
    windowMs: 100,
    maxEntries: 4,
  });
  assert(limiter.allowClient('192.0.2.1', 0));
  assert(limiter.allowTicketFailure('ticket', 0));
  assert(limiter.allowClient('192.0.2.2', 1));
  assert(!limiter.allowTicketFailure('ticket', 1));
  assert(limiter.allowClient('192.0.2.1', 2));
  assert(!limiter.allowClient('192.0.2.1', 3));
  assert(limiter.allowClient('192.0.2.3', 4));
  assert(limiter.allowClient('192.0.2.4', 5));
  assert(limiter.allowClient('192.0.2.5', 6));
  assert.equal(limiter.clientBuckets.size, 4);
  assert(!limiter.clientBuckets.has('ip:192.0.2.2'));
  assert(limiter.ticketBlocked('ticket', 6));
  assert(limiter.allowClient('192.0.2.4', 101));
});

test('writer-only key files must be owned by the running uid and mode 0600', async (t) => {
  const f = await fixture(t);
  for (const name of ['INTAKE_WRITER_KEY', 'INTAKE_FINGERPRINT_KEY']) {
    const env = { [`${name}_FILE`]: f.config.fingerprintKeyFile };
    const options = { writerOnly: true, key: true };
    assert.deepEqual(readSecret(env, name, options), f.config.fingerprintKey);
    for (const mode of [0o640, 0o644, 0o700]) {
      await chmod(f.config.fingerprintKeyFile, mode);
      assert.throws(() => readSecret(env, name, options), {
        code: `unsafe_${name.toLowerCase()}_file`,
      });
    }
    await chmod(f.config.fingerprintKeyFile, 0o600);
  }
  const uid = process.getuid();
  t.mock.method(process, 'getuid', () => uid + 1);
  assert.throws(
    () =>
      readSecret(
        { INTAKE_FINGERPRINT_KEY_FILE: f.config.fingerprintKeyFile },
        'INTAKE_FINGERPRINT_KEY',
        { writerOnly: true, key: true },
      ),
    /unsafe_intake_fingerprint_key_file/,
  );
});

test('configuration pins bounds and web does not load writer credentials', async (t) => {
  const f = await fixture(t);
  const env = {
    INTAKE_HMAC_KEY: randomBytes(32).toString('base64'),
    INTAKE_MAX_TTL: '10d',
    INTAKE_WRITER_KEY_FILE: '/unreadable/private.key',
    INTAKE_FINGERPRINT_KEY_FILE: '/unreadable/fingerprint.key',
    MAIL_API_TOKEN_FILE: '/unreadable/mail.key',
  };
  const web = loadConfig(env);
  assert.equal(web.maxTtl, 10 * DAY);
  assert.equal(web.masterKey, undefined);
  assert.equal(web.fingerprintKey, undefined);
  assert.equal(web.mail, undefined);
  assert.throws(() => loadConfig({ ...env, PORT: '0' }));
  for (const name of [
    'INTAKE_IPC_TIMEOUT_MS',
    'INTAKE_POLL_MS',
    'INTAKE_RATE_WINDOW_MS',
  ]) {
    assert.throws(() => loadConfig({ ...env, [name]: '2147483648' }));
  }
  assert.throws(() => loadConfig({ ...env, TRUST_PROXY: 'maybe' }));
  assert.throws(() =>
    loadConfig({
      ...env,
      INTAKE_PUBLIC_URL: 'https://intake.example.com/path',
    }),
  );
  assert.throws(() => loadConfig({ ...env, INTAKE_MAX_TTL: '0d' }));
  const path = join(f.dir, 'master.key');
  const key = randomBytes(32).toString('base64');
  await writeFile(path, key, { mode: 0o600 });
  assert.deepEqual(
    readSecret({ INTAKE_WRITER_KEY_FILE: path }, 'INTAKE_WRITER_KEY', {
      key: true,
      writerOnly: true,
    }),
    Buffer.from(key, 'base64'),
  );
  const insecure = join(f.dir, 'insecure.key');
  await writeFile(insecure, key, { mode: 0o644 });
  assert.throws(() =>
    readSecret({ INTAKE_WRITER_KEY_FILE: insecure }, 'INTAKE_WRITER_KEY', {
      key: true,
      writerOnly: true,
    }),
  );
  const writerEnv = {
    INTAKE_HMAC_KEY: env.INTAKE_HMAC_KEY,
    INTAKE_WRITER_KEY: key,
    INTAKE_FINGERPRINT_KEY_FILE: f.config.fingerprintKeyFile,
    BW_ORGANIZATION_ID: 'organization-id',
    BW_COLLECTION_ID: 'collection-id',
  };
  assert.throws(() => loadConfig(writerEnv, 'writer'), /missing_mail_api_url/);
  const vaultEnv = { ...writerEnv, INTAKE_NOTIFY: 'off' };
  const writer = loadConfig(vaultEnv, 'writer');
  assert.equal(writer.notifyOff, true);
  assert.equal(writer.vault.socketPath, '/run/intake-bw/bw.sock');
  assert.equal(writer.vault.baseUrl, undefined);
  assert.equal(writer.vault.maxResponseBytes, 1048576);
  for (const value of ['1', '4096', '2097152', `${Number.MAX_SAFE_INTEGER}`]) {
    assert.equal(
      loadConfig({ ...vaultEnv, BW_MAX_RESPONSE_BYTES: value }, 'writer').vault
        .maxResponseBytes,
      Number(value),
    );
  }
  for (const value of [
    '',
    '0',
    '-1',
    '1.5',
    'NaN',
    'Infinity',
    'not-a-number',
    `${Number.MAX_SAFE_INTEGER + 1}`,
  ]) {
    assert.throws(
      () => loadConfig({ ...vaultEnv, BW_MAX_RESPONSE_BYTES: value }, 'writer'),
      { code: 'invalid_bw_max_response_bytes' },
    );
  }
  assert.equal(
    loadConfig({ ...env, BW_MAX_RESPONSE_BYTES: 'invalid' }).vault,
    undefined,
  );
  assert.equal(
    loadConfig({ ...vaultEnv, INTAKE_BW_SOCKET: '/private/bw.sock' }, 'writer')
      .vault.socketPath,
    '/private/bw.sock',
  );
  const tcp = loadConfig(
    { ...vaultEnv, INTAKE_BW_URL: 'http://127.0.0.1:8087' },
    'writer',
  ).vault;
  assert.equal(tcp.socketPath, undefined);
  assert.equal(tcp.baseUrl, 'http://127.0.0.1:8087');
  assert.throws(
    () =>
      loadConfig(
        {
          ...vaultEnv,
          INTAKE_BW_SOCKET: '/private/bw.sock',
          INTAKE_BW_URL: 'http://127.0.0.1:8087',
        },
        'writer',
      ),
    { code: 'conflicting_vault_configuration' },
  );
  for (const socketPath of ['/' + 'a'.repeat(102), '/' + 'é'.repeat(51)])
    assert.equal(
      loadConfig({ ...vaultEnv, INTAKE_BW_SOCKET: socketPath }, 'writer').vault
        .socketPath,
      socketPath,
    );
  for (const socketPath of [
    '',
    'relative/bw.sock',
    '/private/bw\0.sock',
    '/' + 'a'.repeat(103),
    '/' + 'é'.repeat(51) + 'a',
  ])
    assert.throws(
      () => loadConfig({ ...vaultEnv, INTAKE_BW_SOCKET: socketPath }, 'writer'),
      { code: 'invalid_intake_bw_socket' },
    );
  assert.throws(
    () =>
      loadConfig(
        {
          ...writerEnv,
          MAIL_API_URL: 'http://mail.example.com',
          MAIL_API_TOKEN: 'placeholder-token',
          MAIL_API_MAILBOX: 'intake@example.com',
        },
        'writer',
      ),
    /mail_api_requires_https/,
  );
});
