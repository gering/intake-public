import test from 'node:test';
import assert from 'node:assert/strict';
import { TicketStore } from '../src/db.js';
import { startWeb } from '../src/web.js';
import { encryptValue } from '../public/crypto.js';
import { fixture, post } from '../support/fixtures.js';

test('old status CHECK migrates atomically without changing tickets, retries, or indexes', async (t) => {
  const f = await fixture(t);
  const statuses = [
    'active',
    'pending',
    'processing',
    'done',
    'failed',
    'revoked',
  ];
  const ids = [];
  for (const status of statuses) {
    const { ticket, token } = f.create();
    if (status !== 'active') {
      f.store.claim(token, await encryptValue(ticket, `value-${status}`));
      f.store.db
        .prepare(
          'UPDATE tickets SET status = ?, attempts = 3, next_attempt_at = 123456 WHERE id = ?',
        )
        .run(status, ticket.id);
    }
    ids.push(ticket.id);
  }
  const rows = () =>
    f.store.db.prepare('SELECT * FROM tickets ORDER BY id').all();
  const before = rows();
  const schema = f.store.db
    .prepare("SELECT sql FROM sqlite_master WHERE name = 'tickets'")
    .get().sql;
  assert(schema.includes("'unknown'"));
  // Reproduce the old CHECK, including its original column order and accepted data.
  f.store.db
    .transaction(() => {
      f.store.db.exec(
        schema
          .replace('CREATE TABLE tickets', 'CREATE TABLE tickets_legacy')
          .replace(",'unknown'", ''),
      );
      f.store.db.exec(`INSERT INTO tickets_legacy SELECT * FROM tickets;
      DROP TABLE tickets;
      ALTER TABLE tickets_legacy RENAME TO tickets;
      CREATE INDEX ticket_work ON tickets(status, notify_status);
      CREATE INDEX ticket_retry ON tickets(status, next_attempt_at);`);
    })
    .immediate();
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  try {
    assert.deepEqual(rows(), before);
    assert.deepEqual(
      reopened.db.prepare('SELECT * FROM tickets ORDER BY id').all(),
      before,
    );
    assert.deepEqual(
      new Set(
        reopened.db.pragma('index_list(tickets)').map(({ name }) => name),
      ),
      new Set(['sqlite_autoindex_tickets_1', 'ticket_work', 'ticket_retry']),
    );
    const id = ids[2];
    reopened.recoverInterrupted('writer_interrupted', {
      now: 1000000,
      settleMs: 120000,
    });
    const state = reopened.getState(id);
    assert.equal(state.status, 'unknown');
    assert.equal(state.attempts, 4);
    assert.equal(state.nextAttemptAt, 1120000);
    assert(state.envelope);
    assert(f.keys.get(id));
    assert.throws(() =>
      reopened.db
        .prepare('UPDATE tickets SET status = ? WHERE id = ?')
        .run('invalid', id),
    );
  } finally {
    reopened.close();
  }
});

test('unknown state and due time survive reopen, cannot be purged, and preserve private keys', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const envelope = await encryptValue(ticket, 'retained-unknown-value');
  f.store.claim(token, envelope);
  f.store.begin(ticket.id);
  const now = Date.now();
  f.store.retry(ticket.id, 'vault_timeout', {
    unknown: true,
    now,
    settleMs: 120000,
  });
  const reopened = new TicketStore(f.config.dbPath, f.config.hmacKey);
  try {
    const state = reopened.getState(ticket.id);
    assert.equal(state.status, 'unknown');
    assert.equal(state.nextAttemptAt, now + 120000);
    assert.deepEqual(state.envelope, envelope);
    assert.equal(reopened.begin(ticket.id, now + 119999), false);
    assert.deepEqual(reopened.work(now + 119999), []);
    assert.deepEqual(reopened.work(now + 120000), [ticket.id]);
    assert.deepEqual(reopened.purge(0, now + 864000000), []);
    const key = f.keys.get(ticket.id);
    f.keys.prune(reopened);
    assert.equal(f.keys.get(ticket.id), key);
    // Startup must not reset or shorten an already scheduled unknown retry.
    assert.deepEqual(reopened.recoverInterrupted(), []);
    assert.deepEqual(reopened.getState(ticket.id), state);
    assert.equal(reopened.begin(ticket.id, now + 120000), true);
  } finally {
    reopened.close();
  }
});

test('unknown tickets remain consumed for both web open and resubmission', async (t) => {
  let web;
  t.after(async () => web?.close());
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const envelope = await encryptValue(ticket, 'non-resubmittable-value');
  f.store.claim(token, envelope);
  f.store.begin(ticket.id);
  f.store.retry(ticket.id, 'vault_timeout', {
    unknown: true,
    settleMs: 120000,
  });
  web = await startWeb({ store: f.store, config: f.config, logger: f.logger });
  const base = `http://127.0.0.1:${web.server.address().port}`;
  for (const path of ['/api/open', '/api/submit']) {
    const response = await post(base, path, { token, envelope });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'ticket_unavailable' });
  }
  assert.equal(f.store.getState(ticket.id).status, 'unknown');
  assert.deepEqual(f.store.getState(ticket.id).envelope, envelope);
});
