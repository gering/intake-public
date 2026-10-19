import {
  databaseFailure,
  openDatabase,
  validateDatabaseSchema,
} from './db-open.js';
import { parseToken, verifyToken } from './tokens.js';
import { unavailable, IntakeError } from './errors.js';
import { validateEnvelope } from './crypto.js';

function connection(path, mode, tables, migrate) {
  const db = openDatabase(path, mode, tables);
  try {
    migrate(db);
    validateDatabaseSchema(db, tables);
    return db;
  } catch (error) {
    try {
      if (db.open) db.close();
    } catch {
      // Preserve the classified error even if closing also fails.
    }
    throw databaseFailure(error);
  }
}

function metadata(row) {
  if (!row) return null;
  return {
    id: row.id,
    keyName: row.key_name,
    purpose: row.purpose,
    trim: Boolean(row.trim),
    target: JSON.parse(row.target_json),
    notifyEmail: row.notify_email,
    metaDigest: row.meta_digest,
    expiresAt: row.expires_at,
    revoked: Boolean(row.revoked),
    firstSeenAt: row.first_seen_at,
  };
}

function state(row) {
  if (!row) return null;
  return {
    id: row.id,
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    openedAt: row.opened_at,
    usedAt: row.used_at,
    completedAt: row.completed_at,
    envelope: row.envelope ? JSON.parse(row.envelope) : null,
    fingerprint: row.fingerprint,
    failureCode: row.failure_code,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    notifyStatus: row.notify_status,
    notifyAttempts: row.notify_attempts,
    notifyError: row.notify_error,
    notifiedAt: row.notified_at,
  };
}

function ticket(row) {
  if (!row) return null;
  return {
    id: row.id,
    keyName: row.key_name,
    purpose: row.purpose,
    trim: Boolean(row.trim),
    metaDigest: row.meta_digest,
    ...state(row),
    publicKey: JSON.parse(row.public_key),
  };
}

function summary(row, now) {
  if (!row) return null;
  return {
    id: row.id,
    keyName: row.key_name,
    status:
      row.status === 'active' && row.expires_at <= now ? 'expired' : row.status,
    expiresAt: new Date(row.expires_at).toISOString(),
    notifyStatus: row.notify_status,
    fingerprint: row.fingerprint,
    attempts: row.attempts,
    failureCode: row.failure_code,
  };
}

const summaryColumns =
  'id, key_name, status, expires_at, notify_status, fingerprint, attempts, failure_code';

const ticketSchema = `(
      id TEXT PRIMARY KEY, token_hmac BLOB NOT NULL, key_name TEXT NOT NULL,
      purpose TEXT NOT NULL, trim INTEGER NOT NULL DEFAULT 1 CHECK(trim IN (0,1)),
      meta_digest TEXT,
      public_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','pending','processing','unknown','done','failed','revoked')),
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      opened_at INTEGER, used_at INTEGER, completed_at TEXT, envelope TEXT,
      fingerprint TEXT, failure_code TEXT,
      attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 31),
      next_attempt_at INTEGER NOT NULL DEFAULT 0,
      notify_status TEXT CHECK(notify_status IN ('pending','sent','failed')),
      notify_attempts INTEGER NOT NULL DEFAULT 0, notify_error TEXT, notified_at TEXT
    )`;

export class TicketStore {
  constructor(path, hmacKey) {
    this.hmacKey = hmacKey;
    this.db = connection(path, 0o660, ['tickets'], (db) => {
      db.exec(`CREATE TABLE IF NOT EXISTS tickets ${ticketSchema}`);
      db.transaction(() => {
        if (
          !db
            .pragma('table_info(tickets)')
            .some((column) => column.name === 'trim')
        )
          db.exec(
            'ALTER TABLE tickets ADD COLUMN trim INTEGER NOT NULL DEFAULT 1 CHECK(trim IN (0,1))',
          );
        if (
          !db
            .pragma('table_info(tickets)')
            .some((column) => column.name === 'meta_digest')
        )
          db.exec('ALTER TABLE tickets ADD COLUMN meta_digest TEXT');
        for (const [name, definition] of [
          [
            'attempts',
            'INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 31)',
          ],
          ['next_attempt_at', 'INTEGER NOT NULL DEFAULT 0'],
        ]) {
          if (
            !db
              .pragma('table_info(tickets)')
              .some((column) => column.name === name)
          )
            db.exec(`ALTER TABLE tickets ADD COLUMN ${name} ${definition}`);
        }
        // Never backfill trusted metadata from the web-writable database.
        for (const name of ['target_json', 'notify_email']) {
          if (
            db
              .pragma('table_info(tickets)')
              .some((column) => column.name === name)
          )
            db.exec(`ALTER TABLE tickets DROP COLUMN ${name}`);
        }
        const schema = db
          .prepare(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'tickets'",
          )
          .get().sql;
        if (!schema.includes("'unknown'")) {
          // SQLite cannot alter a CHECK constraint; rebuild atomically, by column name.
          db.exec(`CREATE TABLE tickets_upgrade ${ticketSchema}`);
          const columns = db
            .pragma('table_info(tickets_upgrade)')
            .map(({ name }) => name)
            .join(',');
          db.exec(`INSERT INTO tickets_upgrade (${columns}) SELECT ${columns} FROM tickets;
            DROP TABLE tickets;
            ALTER TABLE tickets_upgrade RENAME TO tickets;`);
        }
        db.exec(`
          CREATE INDEX IF NOT EXISTS ticket_work ON tickets(status, notify_status);
          CREATE INDEX IF NOT EXISTS ticket_retry ON tickets(status, next_attempt_at);
        `);
      }).immediate();
    });
  }

  create(
    { id, digest, keyName, purpose, trim = true, metaDigest, publicKey, ttl },
    now = Date.now(),
  ) {
    this.db
      .prepare(
        `INSERT INTO tickets
      (id,token_hmac,key_name,purpose,trim,meta_digest,public_key,created_at,expires_at)
      VALUES (?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        id,
        digest,
        keyName,
        purpose,
        trim ? 1 : 0,
        metaDigest,
        JSON.stringify(publicKey),
        now,
        now + ttl,
      );
    return this.get(id);
  }

  get(id) {
    return ticket(
      this.db.prepare('SELECT * FROM tickets WHERE id = ?').get(id),
    );
  }

  getState(id) {
    return state(
      this.db
        .prepare(
          `SELECT id, status, created_at, expires_at,
      opened_at, used_at, completed_at, envelope, fingerprint, failure_code,
      attempts, next_attempt_at, notify_status, notify_attempts, notify_error, notified_at FROM tickets WHERE id = ?`,
        )
        .get(id),
    );
  }

  authorize(token, now) {
    const parsed = parseToken(token);
    const row = parsed
      ? this.db.prepare('SELECT * FROM tickets WHERE id = ?').get(parsed.id)
      : undefined;
    const valid = verifyToken(this.hmacKey, token, row?.token_hmac);
    if (!valid || !row || row.status !== 'active' || row.expires_at <= now)
      throw unavailable();
    if (row.meta_digest === null)
      throw new IntakeError('ticket_upgrade_required', 409);
    if (!/^[a-f0-9]{64}$/.test(row.meta_digest)) throw unavailable();
    return row;
  }

  open(token, now = Date.now()) {
    return this.db
      .transaction(() => {
        const row = this.authorize(token, now);
        this.db
          .prepare(
            'UPDATE tickets SET opened_at = COALESCE(opened_at, ?) WHERE id = ?',
          )
          .run(now, row.id);
        return {
          id: row.id,
          keyName: row.key_name,
          purpose: row.purpose,
          trim: Boolean(row.trim),
          metaDigest: row.meta_digest,
          publicKey: JSON.parse(row.public_key),
          expiresAt: new Date(row.expires_at).toISOString(),
        };
      })
      .immediate();
  }

  claim(token, envelope, now = Date.now()) {
    return this.db
      .transaction(() => {
        const row = this.authorize(token, now);
        validateEnvelope(envelope);
        this.db
          .prepare(
            "UPDATE tickets SET status = 'pending', used_at = ?, envelope = ? WHERE id = ?",
          )
          .run(now, JSON.stringify(envelope), row.id);
        return { id: row.id, status: 'pending' };
      })
      .immediate();
  }

  isPending(id) {
    return Boolean(
      this.db
        .prepare("SELECT 1 FROM tickets WHERE id = ? AND status = 'pending'")
        .get(id),
    );
  }

  isUnknown(id) {
    return Boolean(
      this.db
        .prepare("SELECT 1 FROM tickets WHERE id = ? AND status = 'unknown'")
        .get(id),
    );
  }

  begin(id, now = Date.now()) {
    return (
      this.db
        .prepare(
          "UPDATE tickets SET status = 'processing' WHERE id = ? AND status IN ('pending','unknown') AND next_attempt_at <= ?",
        )
        .run(id, now).changes === 1
    );
  }

  retry(
    id,
    code,
    {
      baseMs = 5000,
      maxMs = 300000,
      now = Date.now(),
      unknown = false,
      settleMs = 0,
    } = {},
  ) {
    if (
      !Number.isSafeInteger(baseMs) ||
      baseMs <= 0 ||
      !Number.isSafeInteger(maxMs) ||
      maxMs < baseMs ||
      maxMs > 2147483647 ||
      !Number.isSafeInteger(settleMs) ||
      settleMs < 0 ||
      settleMs > 2147483647
    )
      throw new IntakeError('invalid_vault_retry');
    return this.db
      .transaction(() => {
        const row = this.db
          .prepare(
            "SELECT attempts FROM tickets WHERE id = ? AND status IN ('pending','processing','unknown')",
          )
          .get(id);
        if (!row) return false;
        // Saturation bounds both the persisted counter and exponent indefinitely.
        const attempts = Math.min(row.attempts + 1, 31);
        const delay = Math.max(
          settleMs,
          Math.min(maxMs, baseMs * 2 ** row.attempts),
        );
        this.db
          .prepare(
            `UPDATE tickets SET status = ?, attempts = ?,
        next_attempt_at = ?, failure_code = ? WHERE id = ?`,
          )
          .run(
            unknown ? 'unknown' : 'pending',
            attempts,
            now + delay,
            code,
            id,
          );
        return {
          id,
          status: unknown ? 'unknown' : 'pending',
          attempts,
          previousAttempts: row.attempts,
          code,
        };
      })
      .immediate();
  }

  finish(id, fingerprint) {
    return (
      this.db
        .prepare(
          `UPDATE tickets SET status = 'done', fingerprint = ?, envelope = NULL,
      failure_code = NULL, next_attempt_at = 0,
      completed_at = ?, notify_status = 'pending' WHERE id = ? AND status = 'processing'`,
        )
        .run(fingerprint, new Date().toISOString(), id).changes === 1
    );
  }

  fail(id, code) {
    return (
      this.db
        .prepare(
          `UPDATE tickets SET status = 'failed', failure_code = ?, envelope = NULL,
      completed_at = ?, notify_status = 'pending' WHERE id = ? AND status = 'processing'`,
        )
        .run(code, new Date().toISOString(), id).changes === 1
    );
  }

  recoverInterrupted(code = 'writer_interrupted', options = {}) {
    // A crash can hide a delivered write; retain material for settled marker lookup.
    return this.db
      .transaction(() => {
        const rows = this.db
          .prepare("SELECT id FROM tickets WHERE status = 'processing'")
          .all();
        return rows.map(({ id }) =>
          this.retry(id, code, {
            ...options,
            unknown: true,
            settleMs: options.settleMs ?? 120000,
          }),
        );
      })
      .immediate();
  }

  work(now = Date.now()) {
    return this.db
      .prepare(
        "SELECT id FROM tickets WHERE (status IN ('pending','unknown') AND next_attempt_at <= ?) OR (status IN ('done','failed') AND notify_status = 'pending') ORDER BY created_at",
      )
      .all(now)
      .map(({ id }) => id);
  }

  recordNotification(id, result) {
    this.db
      .prepare(
        `UPDATE tickets SET notify_status = ?, notify_attempts = notify_attempts + ?,
      notify_error = ?, notified_at = ? WHERE id = ? AND status IN ('done','failed')`,
      )
      .run(result.status, result.attempts, result.error, result.notifiedAt, id);
  }

  retryNotification(id) {
    const changed = this.db
      .prepare(
        "UPDATE tickets SET notify_status = 'pending', notify_error = NULL WHERE id = ? AND status IN ('done','failed') AND notify_status = 'failed'",
      )
      .run(id).changes;
    if (!changed) throw new IntakeError('notification_not_retryable', 409);
  }

  revoke(id) {
    const changed = this.db
      .prepare(
        "UPDATE tickets SET status = 'revoked', completed_at = ? WHERE id = ? AND status = 'active'",
      )
      .run(new Date().toISOString(), id).changes;
    if (!changed) throw new IntakeError('ticket_not_revocable', 409);
  }

  list(now = Date.now()) {
    return this.db
      .prepare(`SELECT ${summaryColumns} FROM tickets ORDER BY created_at DESC`)
      .all()
      .map((row) => summary(row, now));
  }

  show(id, now = Date.now()) {
    return summary(
      this.db
        .prepare(`SELECT ${summaryColumns} FROM tickets WHERE id = ?`)
        .get(id),
      now,
    );
  }

  purge(days = 30, now = Date.now()) {
    if (!Number.isSafeInteger(days) || days < 0)
      throw new IntakeError('invalid_retention_days');
    const cutoff = now - days * 86400000;
    return this.db
      .transaction(() => {
        const ids = this.db
          .prepare(
            `SELECT id FROM tickets WHERE
        (status = 'active' AND expires_at < ?) OR
        (status IN ('done','failed','revoked') AND completed_at < ? AND COALESCE(notify_status,'sent') != 'pending')`,
          )
          .all(cutoff, new Date(cutoff).toISOString())
          .map(({ id }) => id);
        const remove = this.db.prepare('DELETE FROM tickets WHERE id = ?');
        for (const id of ids) remove.run(id);
        return ids;
      })
      .immediate();
  }

  close() {
    this.db.close();
  }
}

export class PrivateKeyStore {
  constructor(path) {
    this.db = connection(
      path,
      0o600,
      ['private_keys', 'ticket_metadata'],
      (db) => {
        db.exec(`
          CREATE TABLE IF NOT EXISTS private_keys (id TEXT PRIMARY KEY, encrypted_key TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS ticket_metadata (
            id TEXT PRIMARY KEY, key_name TEXT NOT NULL, purpose TEXT NOT NULL,
            trim INTEGER NOT NULL CHECK(trim IN (0,1)), target_json TEXT NOT NULL,
            notify_email TEXT NOT NULL, meta_digest TEXT,
            expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
            first_seen_at INTEGER
          );
        `);
        db.transaction(() => {
          for (const [name, definition] of [
            ['meta_digest', 'TEXT'],
            ['expires_at', 'INTEGER'],
            ['revoked', 'INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))'],
            ['first_seen_at', 'INTEGER'],
          ]) {
            if (
              !db
                .pragma('table_info(ticket_metadata)')
                .some((column) => column.name === name)
            )
              db.exec(
                `ALTER TABLE ticket_metadata ADD COLUMN ${name} ${definition}`,
              );
          }
        }).immediate();
      },
    );
  }
  put(
    id,
    key,
    {
      keyName,
      purpose,
      trim,
      target,
      notifyEmail,
      metaDigest,
      expiresAt = null,
    },
  ) {
    this.db
      .transaction(() => {
        this.db.prepare('INSERT INTO private_keys VALUES (?,?)').run(id, key);
        this.db
          .prepare(
            `INSERT INTO ticket_metadata
          (id,key_name,purpose,trim,target_json,notify_email,meta_digest,expires_at)
          VALUES (?,?,?,?,?,?,?,?)`,
          )
          .run(
            id,
            keyName,
            purpose,
            trim ? 1 : 0,
            JSON.stringify({
              item: target.item,
              field: target.field,
              notes: target.notes,
            }),
            notifyEmail,
            metaDigest,
            expiresAt,
          );
      })
      .immediate();
  }
  get(id) {
    return this.db
      .prepare('SELECT encrypted_key FROM private_keys WHERE id = ?')
      .get(id)?.encrypted_key;
  }
  getMetadata(id) {
    return metadata(
      this.db.prepare('SELECT * FROM ticket_metadata WHERE id = ?').get(id),
    );
  }
  markRevoked(id) {
    return this.db
      .transaction(() => {
        const changed = this.db
          .prepare('UPDATE ticket_metadata SET revoked = 1 WHERE id = ?')
          .run(id).changes;
        this.delete(id);
        return changed === 1;
      })
      .immediate();
  }
  markSeen(id, now) {
    return this.db
      .prepare(
        `UPDATE ticket_metadata SET first_seen_at = COALESCE(first_seen_at, ?)
        WHERE id = ? RETURNING first_seen_at`,
      )
      .get(now, id)?.first_seen_at;
  }
  delete(id) {
    // Key destruction must not remove trusted metadata needed by notification retries.
    this.db.prepare('DELETE FROM private_keys WHERE id = ?').run(id);
  }
  remove(id) {
    this.db
      .transaction(() => {
        this.delete(id);
        this.db.prepare('DELETE FROM ticket_metadata WHERE id = ?').run(id);
      })
      .immediate();
  }
  prune(tickets, now = Date.now(), graceMs = 900000) {
    return tickets.db
      .transaction(() => {
        const state = tickets.db.prepare(
          'SELECT status FROM tickets WHERE id = ?',
        );
        for (const { id } of this.db
          .prepare(
            'SELECT id FROM private_keys UNION SELECT id FROM ticket_metadata',
          )
          .all()) {
          const ticket = state.get(id);
          const snapshot = this.getMetadata(id);
          if (!ticket) this.remove(id);
          else if (ticket.status === 'revoked') this.markRevoked(id);
          else if (
            snapshot?.revoked ||
            ['done', 'failed'].includes(ticket.status) ||
            (snapshot?.expiresAt != null &&
              snapshot.firstSeenAt === null &&
              now > snapshot.expiresAt + graceMs)
          )
            this.delete(id);
        }
      })
      .immediate();
  }
  close() {
    this.db.close();
  }
}
