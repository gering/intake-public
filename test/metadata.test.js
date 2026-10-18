import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createPrivateKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { TicketStore, PrivateKeyStore } from '../src/db.js';
import { startWriter } from '../src/writer.js';
import { MockVaultAdapter } from '../src/vault.js';
import { encryptValue, aadBytes } from '../public/crypto.js';
import { metadataDigest } from '../src/metadata.js';
import { fixture } from '../support/fixtures.js';

function assertSharedSchema(store) {
  const columns = store.db
    .pragma('table_info(tickets)')
    .map(({ name }) => name);
  assert(!columns.includes('target_json'));
  assert(!columns.includes('notify_email'));
  assert.deepEqual(
    store.db
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all()
      .map(({ name }) => name),
    ['tickets'],
  );
}

const sent = () => ({
  status: 'sent',
  attempts: 1,
  error: null,
  notifiedAt: new Date().toISOString(),
});

async function processQueue(t, f, overrides = {}) {
  const vault = new MockVaultAdapter();
  const notifications = [];
  const writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: vault,
    notifier: {
      async send(ticket) {
        notifications.push(ticket);
        return sent();
      },
    },
    socketPath: f.config.socketPath,
    pollMs: 60000,
    logger: f.logger,
    ...overrides,
  });
  t.after(() => writer.close());
  await writer.drain();
  return { writer, vault, notifications };
}

const mutations = [
  {
    name: 'metadata digest',
    column: 'meta_digest',
    value: () => '0'.repeat(64),
  },
  { name: 'key name', column: 'key_name', value: () => 'MANIPULATED_KEY' },
  { name: 'purpose', column: 'purpose', value: () => 'Manipulated purpose' },
  { name: 'trim', column: 'trim', value: (ticket) => (ticket.trim ? 0 : 1) },
];

for (const mutation of mutations) {
  for (const when of ['before open', 'after enqueue']) {
    test(`public DB mutation of ${mutation.name} ${when} cannot change writer operations`, async (t) => {
      const f = await fixture(t);
      const { ticket, token } = f.create({ targetNotes: 'Original notes' });
      const webStore = new TicketStore(f.config.dbPath, f.config.hmacKey);
      t.after(() => webStore.close());
      const mutate = () =>
        webStore.db
          .prepare(`UPDATE tickets SET ${mutation.column} = ? WHERE id = ?`)
          .run(mutation.value(ticket), ticket.id);
      if (when === 'before open') mutate();
      const opened = webStore.open(token);
      webStore.claim(
        token,
        await encryptValue(opened, 'already-trimmed-value'),
      );
      if (when === 'after enqueue') mutate();
      const { vault, notifications } = await processQueue(t, f);
      const failed = f.store.getState(ticket.id);
      assert.equal(failed.status, 'failed');
      assert.equal(failed.envelope, null);
      assert.equal(failed.fingerprint, null);
      assert.equal(vault.entries.length, 0);
      assert.equal(f.keys.get(ticket.id), undefined);
      assert.equal(notifications.length, 1);
      assert.deepEqual(notifications[0].target, ticket.target);
      assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
      assert.equal(notifications[0].keyName, ticket.keyName);
      assert.equal(notifications[0].purpose, ticket.purpose);
      assert.equal(notifications[0].trim, ticket.trim);
      assert(!JSON.stringify(notifications).includes('attacker@example.com'));
      assert.throws(() => webStore.open(token), /ticket_unavailable/);
    });
  }
}

test('browser AAD rejects missing and noncanonical metadata digests', () => {
  for (const metaDigest of [
    undefined,
    null,
    '',
    '0',
    'A'.repeat(64),
    '0'.repeat(65),
  ]) {
    assert.throws(() => aadBytes({ metaDigest }), /invalid_metadata_digest/);
  }
});

test('metadata digest roundtrips through both databases without exposing canonical input', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const expected = metadataDigest(ticket);
  assert.match(expected, /^[a-f0-9]{64}$/);
  assert.equal(ticket.target.notes, '');
  assert.equal(ticket.metaDigest, expected);
  const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  t.after(() => store.close());
  t.after(() => keys.close());
  assert.equal(store.get(ticket.id).metaDigest, expected);
  assert.equal(keys.getMetadata(ticket.id).metaDigest, expected);
  assert.equal(store.open(token).metaDigest, expected);
  assert.equal(
    new TextDecoder().decode(aadBytes(store.open(token))),
    JSON.stringify([
      ticket.id,
      ticket.keyName,
      ticket.purpose,
      ticket.trim,
      expected,
    ]),
  );
});

test('shared schema, rows, database and WAL exclude private material after create, submit and process', async (t) => {
  const f = await fixture(t);
  f.store.db.pragma('wal_autocheckpoint = 0');
  const { ticket, token } = f.create({
    targetItem: 'private-target-item-7fbdf85c',
    targetField: 'private-target-field-82d129f4',
    targetNotes: 'private-target-notes-848f0af7',
    notifyEmail: 'private-recipient-0a49f38b@example.com',
  });
  const value = 'private-submitted-value-08f3d783';
  const encryptedPrivateKey = f.keys.get(ticket.id);
  const encrypted = JSON.parse(encryptedPrivateKey);
  const decipher = createDecipheriv(
    'aes-256-gcm',
    f.config.masterKey,
    Buffer.from(encrypted.iv, 'base64url'),
  );
  decipher.setAAD(Buffer.from(ticket.id));
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64url'));
  const privateDer = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64url')),
    decipher.final(),
  ]);
  const privateKey = createPrivateKey({
    key: privateDer,
    format: 'der',
    type: 'pkcs8',
  });
  const secrets = [
    ...Object.entries(ticket.target).map(([field, text]) => [
      `target.${field}`,
      Buffer.from(text),
    ]),
    ['notify email', Buffer.from(ticket.notifyEmail)],
    ['plaintext value', Buffer.from(value)],
    ['encrypted private key blob', Buffer.from(encryptedPrivateKey)],
    ['encrypted private key ciphertext', Buffer.from(encrypted.ciphertext)],
    [
      'encrypted private key bytes',
      Buffer.from(encrypted.ciphertext, 'base64url'),
    ],
    ['private key DER', privateDer],
    ['private key PEM marker', Buffer.from('PRIVATE KEY')],
    ['private key JWK d', Buffer.from(privateKey.export({ format: 'jwk' }).d)],
  ];
  for (const [name, key] of [
    ['private key', privateDer],
    ['master key', f.config.masterKey],
    ['fingerprint key', f.config.fingerprintKey],
    ['HMAC key', f.config.hmacKey],
  ]) {
    secrets.push([`${name} bytes`, key]);
    for (const encoding of ['base64', 'base64url', 'hex'])
      secrets.push([
        `${name} ${encoding}`,
        Buffer.from(key.toString(encoding)),
      ]);
  }
  async function inspect(stage) {
    assertSharedSchema(f.store);
    assert.deepEqual(f.store.get(ticket.id), {
      id: ticket.id,
      keyName: ticket.keyName,
      purpose: ticket.purpose,
      trim: ticket.trim,
      metaDigest: ticket.metaDigest,
      ...f.store.getState(ticket.id),
      publicKey: ticket.publicKey,
    });
    const row = f.store.db
      .prepare('SELECT * FROM tickets WHERE id = ?')
      .get(ticket.id);
    assert.equal(Object.hasOwn(row, 'target_json'), false);
    assert.equal(Object.hasOwn(row, 'notify_email'), false);
    // Keep the WAL while copying its committed pages into the main file, so both are inspected.
    assert.equal(f.store.db.pragma('wal_checkpoint(PASSIVE)')[0].busy, 0);
    const dumps = [
      ['row', Buffer.from(JSON.stringify(row))],
      ['database', await readFile(f.config.dbPath)],
      ['WAL', await readFile(`${f.config.dbPath}-wal`)],
    ];
    for (const [name, bytes] of dumps) {
      assert(bytes.length > 0, `${stage}: shared ${name} must be inspected`);
      for (const [secret, needle] of secrets)
        assert.equal(
          bytes.includes(needle),
          false,
          `${stage}: shared ${name} contains ${secret}`,
        );
    }
  }
  await inspect('create');
  f.store.claim(token, await encryptValue(f.store.open(token), value));
  assert.equal(f.store.getState(ticket.id).status, 'pending');
  assert(f.store.getState(ticket.id).envelope);
  await inspect('submit');
  const { vault, notifications } = await processQueue(t, f);
  assert.equal(f.store.getState(ticket.id).status, 'done');
  assert.equal(f.keys.get(ticket.id), undefined);
  assert.equal(vault.entries[0].value, value);
  assert.deepEqual(vault.entries[0].target, ticket.target);
  assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
  assert.deepEqual(f.keys.getMetadata(ticket.id).target, ticket.target);
  await inspect('process');
});

for (const field of ['item', 'field', 'notes', 'notifyEmail']) {
  test(`a forged shared digest for ${field} cannot replace the private AAD snapshot`, async (t) => {
    const f = await fixture(t);
    const { ticket, token } = f.create({ targetNotes: 'Original notes' });
    const forged =
      field === 'notifyEmail'
        ? { ...ticket, notifyEmail: 'attacker@example.com' }
        : {
            ...ticket,
            target: { ...ticket.target, [field]: 'Manipulated target' },
          };
    f.store.db
      .prepare('UPDATE tickets SET meta_digest = ? WHERE id = ?')
      .run(metadataDigest(forged), ticket.id);
    f.store.claim(
      token,
      await encryptValue(f.store.open(token), 'no-vault-write'),
    );
    const { vault, notifications } = await processQueue(t, f);
    assert.equal(f.store.getState(ticket.id).status, 'failed');
    assert.equal(vault.entries.length, 0);
    assert.equal(notifications.length, 1);
    assert.deepEqual(notifications[0].target, ticket.target);
    assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
    assert(!JSON.stringify(notifications).includes('attacker@example.com'));
  });
}

test('writer recomputes its private snapshot digest rather than trusting a stored digest', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const forgedDigest = '0'.repeat(64);
  f.store.db
    .prepare('UPDATE tickets SET meta_digest = ? WHERE id = ?')
    .run(forgedDigest, ticket.id);
  f.keys.db
    .prepare('UPDATE ticket_metadata SET meta_digest = ? WHERE id = ?')
    .run(forgedDigest, ticket.id);
  f.store.claim(
    token,
    await encryptValue(f.store.open(token), 'no-vault-write'),
  );
  const { vault } = await processQueue(t, f);
  assert.equal(f.store.getState(ticket.id).status, 'failed');
  assert.equal(vault.entries.length, 0);
});

for (const hasDigest of [true, false]) {
  test(`legacy shared target/notify columns are dropped ${hasDigest ? 'while preserving the digest' : 'without digest backfill'} and trusted private metadata is kept`, async (t) => {
    const f = await fixture(t);
    const { ticket, token } = f.create({ targetNotes: 'Trusted legacy notes' });
    const trusted = f.keys.getMetadata(ticket.id);
    const encryptedPrivateKey = f.keys.get(ticket.id);
    f.store.db.exec(`
      ALTER TABLE tickets ADD COLUMN target_json TEXT NOT NULL DEFAULT '{}';
      ALTER TABLE tickets ADD COLUMN notify_email TEXT NOT NULL DEFAULT '';
    `);
    f.store.db
      .prepare(
        'UPDATE tickets SET target_json = ?, notify_email = ? WHERE id = ?',
      )
      .run('not JSON', 'attacker@example.com', ticket.id);
    if (!hasDigest)
      f.store.db.exec('ALTER TABLE tickets DROP COLUMN meta_digest');
    const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
    t.after(() => store.close());
    assertSharedSchema(store);
    assert.equal(
      store.get(ticket.id).metaDigest,
      hasDigest ? ticket.metaDigest : null,
    );
    assert.equal(Object.hasOwn(store.get(ticket.id), 'target'), false);
    assert.equal(Object.hasOwn(store.get(ticket.id), 'notifyEmail'), false);
    assert.deepEqual(f.keys.getMetadata(ticket.id), trusted);
    assert.equal(f.keys.get(ticket.id), encryptedPrivateKey);
    if (hasDigest) {
      store.claim(
        token,
        await encryptValue(store.open(token), 'migrated-private-target-value'),
      );
      const { vault, notifications } = await processQueue(t, f, { store });
      assert.equal(store.getState(ticket.id).status, 'done');
      assert.equal(vault.entries.length, 1);
      assert.deepEqual(vault.entries[0].target, ticket.target);
      assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
      const processed = f.keys.getMetadata(ticket.id);
      assert(Number.isSafeInteger(processed.firstSeenAt));
      assert.deepEqual({ ...processed, firstSeenAt: null }, trusted);
    } else {
      for (const operation of [
        () => store.open(token),
        () => store.claim(token, {}),
      ])
        assert.throws(operation, {
          code: 'ticket_upgrade_required',
          status: 409,
        });
      assert.equal(store.getState(ticket.id).status, 'active');
      assert.equal(store.getState(ticket.id).openedAt, null);
      assert.equal(store.getState(ticket.id).envelope, null);
    }
  });
}

test('legacy schemas gain nullable digest columns without backfilling untrusted metadata', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.db.exec('ALTER TABLE tickets DROP COLUMN meta_digest');
  f.keys.db.exec('ALTER TABLE ticket_metadata DROP COLUMN meta_digest');
  const store = new TicketStore(f.config.dbPath, f.config.hmacKey);
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  t.after(() => store.close());
  t.after(() => keys.close());
  assert.equal(store.get(ticket.id).metaDigest, null);
  assert.equal(keys.getMetadata(ticket.id).metaDigest, null);
  for (const operation of [
    () => store.open(token),
    () => store.claim(token, {}),
  ])
    assert.throws(operation, { code: 'ticket_upgrade_required', status: 409 });
  assert.equal(store.getState(ticket.id).status, 'active');
  assert.equal(store.getState(ticket.id).openedAt, null);
  assert.equal(store.getState(ticket.id).envelope, null);
  assert.throws(() => store.open(`${ticket.id}.${'A'.repeat(43)}`), {
    code: 'ticket_unavailable',
  });
  // New creation still publishes a digest in both migrated schemas.
  const created = f.create();
  assert.equal(
    store.get(created.ticket.id).metaDigest,
    metadataDigest(created.ticket),
  );
  assert.equal(
    keys.getMetadata(created.ticket.id).metaDigest,
    metadataDigest(created.ticket),
  );
});

for (const legacy of ['shared', 'private', 'both']) {
  test(`queued ticket with missing ${legacy} digest fails closed without a vault write`, async (t) => {
    const f = await fixture(t);
    const { ticket, token } = f.create();
    f.store.claim(
      token,
      await encryptValue(f.store.open(token), 'legacy-value'),
    );
    if (legacy !== 'private')
      f.store.db
        .prepare('UPDATE tickets SET meta_digest = NULL WHERE id = ?')
        .run(ticket.id);
    if (legacy !== 'shared')
      f.keys.db
        .prepare('UPDATE ticket_metadata SET meta_digest = NULL WHERE id = ?')
        .run(ticket.id);
    const { vault, notifications } = await processQueue(t, f);
    const state = f.store.getState(ticket.id);
    assert.equal(state.status, 'failed');
    assert.equal(state.failureCode, 'ticket_upgrade_required');
    assert.equal(state.envelope, null);
    assert.equal(vault.entries.length, 0);
    assert.equal(f.keys.get(ticket.id), undefined);
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
  });
}

for (const targetJson of [
  JSON.stringify({
    item: 'Attacker item',
    field: 'attacker-field',
    notes: 'Attacker notes',
  }),
  'not JSON',
]) {
  for (const when of ['before open', 'after enqueue']) {
    test(`attacker-added shared metadata columns with ${targetJson === 'not JSON' ? 'malformed' : 'forged'} target ${when} are ignored`, async (t) => {
      const f = await fixture(t);
      const { ticket, token } = f.create({ targetNotes: 'Original notes' });
      const webStore = new TicketStore(f.config.dbPath, f.config.hmacKey);
      t.after(() => webStore.close());
      const inject = () => {
        webStore.db.exec(`
          ALTER TABLE tickets ADD COLUMN target_json TEXT;
          ALTER TABLE tickets ADD COLUMN notify_email TEXT;
        `);
        webStore.db
          .prepare(
            'UPDATE tickets SET target_json = ?, notify_email = ? WHERE id = ?',
          )
          .run(targetJson, 'attacker@example.com', ticket.id);
      };
      if (when === 'before open') inject();
      const opened = webStore.open(token);
      assert.equal(Object.hasOwn(opened, 'target'), false);
      assert.equal(Object.hasOwn(opened, 'notifyEmail'), false);
      assert.equal(opened.metaDigest, ticket.metaDigest);
      webStore.claim(
        token,
        await encryptValue(opened, 'trusted-private-target-value'),
      );
      if (when === 'after enqueue') inject();
      const shared = webStore.get(ticket.id);
      assert.equal(Object.hasOwn(shared, 'target'), false);
      assert.equal(Object.hasOwn(shared, 'notifyEmail'), false);
      const { vault, notifications } = await processQueue(t, f);
      assert.equal(f.store.getState(ticket.id).status, 'done');
      assert.equal(f.store.getState(ticket.id).envelope, null);
      assert.equal(f.keys.get(ticket.id), undefined);
      assert.equal(vault.entries.length, 1);
      assert.equal(vault.entries[0].value, 'trusted-private-target-value');
      assert.deepEqual(vault.entries[0].target, ticket.target);
      assert.equal(notifications.length, 1);
      assert.deepEqual(notifications[0].target, ticket.target);
      assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
      assert(
        !JSON.stringify({ entries: vault.entries, notifications }).includes(
          'attacker@example.com',
        ),
      );
      // Keep the injected columns present: these reads must ignore them, not migrate them away.
      assert.deepEqual(
        webStore.db
          .prepare('SELECT target_json, notify_email FROM tickets WHERE id = ?')
          .get(ticket.id),
        { target_json: targetJson, notify_email: 'attacker@example.com' },
      );
    });
  }
}

test('an old private database is not backfilled from untrusted public metadata', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  f.store.claim(token, await encryptValue(ticket, 'old-ticket-value'));
  f.keys.db.exec('DROP TABLE ticket_metadata');
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  t.after(() => keys.close());
  assert.equal(keys.getMetadata(ticket.id), null);
  assert(keys.get(ticket.id));
  const { vault, notifications } = await processQueue(t, f, { keys });
  assert.equal(f.store.getState(ticket.id).status, 'failed');
  assert.equal(
    f.store.getState(ticket.id).notifyError,
    'private_metadata_missing',
  );
  assert.equal(vault.entries.length, 0);
  assert.equal(notifications.length, 0);
  assert.equal(keys.get(ticket.id), undefined);
});

test('trusted metadata survives key destruction, restart and notification recovery', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create({ targetNotes: 'Original notes' });
  f.store.claim(token, await encryptValue(ticket, 'stored-before-restart'));
  let writer = await startWriter({
    store: f.store,
    keys: f.keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: new MockVaultAdapter(),
    notifyOff: true,
    socketPath: f.config.socketPath,
    logger: f.logger,
  });
  await writer.drain();
  await writer.close();
  assert.equal(f.keys.get(ticket.id), undefined);
  assert(f.keys.getMetadata(ticket.id));
  f.store.db
    .prepare(
      `UPDATE tickets SET key_name = ?, purpose = ?, trim = ?, meta_digest = ?,
    notify_status = 'pending' WHERE id = ?`,
    )
    .run(
      'MANIPULATED_KEY',
      'Manipulated purpose',
      0,
      '0'.repeat(64),
      ticket.id,
    );
  const keys = new PrivateKeyStore(f.config.privateDbPath);
  t.after(() => keys.close());
  const notifications = [];
  writer = await startWriter({
    store: f.store,
    keys,
    masterKey: f.config.masterKey,
    fingerprintKey: f.config.fingerprintKey,
    adapter: {
      async write() {
        assert.fail('notification recovery must not replay vault writes');
      },
    },
    notifier: {
      async send(ticket) {
        notifications.push(ticket);
        return sent();
      },
    },
    socketPath: f.config.socketPath,
    logger: f.logger,
  });
  t.after(() => writer.close());
  await writer.drain();
  assert.equal(f.store.getState(ticket.id).notifyStatus, 'sent');
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].notifyEmail, ticket.notifyEmail);
  assert.deepEqual(notifications[0].target, ticket.target);
  assert.equal(notifications[0].keyName, ticket.keyName);
  assert.equal(notifications[0].purpose, ticket.purpose);
  assert.equal(notifications[0].trim, ticket.trim);
});

test('pruning retains terminal metadata until public purge and removes orphan snapshots', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.store.revoke(ticket.id);
  f.keys.prune(f.store);
  assert.equal(f.keys.get(ticket.id), undefined);
  assert(f.keys.getMetadata(ticket.id));
  assert.deepEqual(f.store.purge(0, Date.now() + 1000), [ticket.id]);
  f.keys.prune(f.store);
  assert.equal(f.keys.getMetadata(ticket.id), null);
  const orphan = f.create();
  f.store.db.prepare('DELETE FROM tickets WHERE id = ?').run(orphan.ticket.id);
  f.keys.prune(f.store);
  assert.equal(f.keys.get(orphan.ticket.id), undefined);
  assert.equal(f.keys.getMetadata(orphan.ticket.id), null);
});
