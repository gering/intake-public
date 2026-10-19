import test from 'node:test';
import assert from 'node:assert/strict';
import fs, {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import Database from 'better-sqlite3';
import { PrivateKeyStore, TicketStore } from '../src/db.js';
import { openDatabase, validateDatabaseSchema } from '../src/db-open.js';
import { IntakeError } from '../src/errors.js';
import { fixture as ticketFixture } from '../support/fixtures.js';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'intake-db-open-'));
  chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { dir, path: join(dir, 'tickets.db') };
}

function unsafe(action, code = 'unsafe_database') {
  assert.throws(action, (error) => {
    assert.ok(error instanceof IntakeError);
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    return true;
  });
}

function withPragmaMock(t, intercept) {
  const original = Database.prototype.pragma;
  return t.mock.method(
    Database.prototype,
    'pragma',
    function (source, ...args) {
      return intercept.call(this, source, () =>
        original.call(this, source, ...args),
      );
    },
  );
}

test('new databases use the requested modes and retain SQLite hardening', (t) => {
  for (const mode of [0o600, 0o660]) {
    const { path } = fixture(t);
    const db = openDatabase(path, mode, ['tickets']);
    t.after(() => db.close());
    assert.equal(lstatSync(path).mode & 0o777, mode);
    assert.equal(db.pragma('trusted_schema', { simple: true }), 0);
    assert.equal(db.pragma('cell_size_check', { simple: true }), 1);
    assert.equal(db.pragma('journal_mode', { simple: true }), 'wal');
    assert.equal(db.pragma('synchronous', { simple: true }), 2);
    assert.equal(db.pragma('busy_timeout', { simple: true }), 5000);
    assert.equal(db.pragma('secure_delete', { simple: true }), 1);
    assert.equal(db.pragma('quick_check', { simple: true }), 'ok');
    // better-sqlite3 enables defensive mode without an unsafeMode() call.
    db.pragma('writable_schema = ON');
    assert.equal(db.pragma('writable_schema', { simple: true }), 0);
    assert.throws(
      () => db.exec("DELETE FROM sqlite_schema WHERE name = 'tickets'"),
      /may not be modified/,
    );
  }
});

test('a database created by a concurrent first open is reused', (t) => {
  const { path } = fixture(t);
  const originalOpen = fs.openSync;
  let raced = false;
  const mock = t.mock.method(fs, 'openSync', (target, flags, mode) => {
    if (!raced && target === path && flags & fs.constants.O_EXCL) {
      raced = true;
      const fd = originalOpen(target, flags, mode);
      try {
        fs.fchmodSync(fd, mode);
      } finally {
        fs.closeSync(fd);
      }
      const error = new Error('file exists');
      error.code = 'EEXIST';
      throw error;
    }
    return originalOpen(target, flags, mode);
  });
  syncBuiltinESMExports();
  try {
    const db = openDatabase(path, 0o660, ['tickets']);
    t.after(() => db.close());
    assert.equal(raced, true);
    assert.equal(lstatSync(path).mode & 0o777, 0o660);
    assert.equal(db.pragma('quick_check', { simple: true }), 'ok');
    assert.equal(db.pragma('database_list')[0].file, path);
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
});

test('an exclusive-create collision still fails when no valid file exists', (t) => {
  const { path } = fixture(t);
  const originalOpen = fs.openSync;
  const mock = t.mock.method(fs, 'openSync', (target, flags, mode) => {
    if (target === path) {
      const error = new Error('file exists');
      error.code = 'EEXIST';
      throw error;
    }
    return originalOpen(target, flags, mode);
  });
  syncBuiltinESMExports();
  try {
    unsafe(() => openDatabase(path, 0o660, ['tickets']));
    assert.equal(existsSync(path), false);
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
});

test('in-memory stores retain schema validation and SQLite hardening', () => {
  for (const Store of [TicketStore, PrivateKeyStore]) {
    const store = new Store(':memory:');
    try {
      assert.equal(store.db.pragma('trusted_schema', { simple: true }), 0);
      assert.equal(store.db.pragma('cell_size_check', { simple: true }), 1);
      validateDatabaseSchema(
        store.db,
        Store === TicketStore
          ? ['tickets']
          : ['private_keys', 'ticket_metadata'],
      );
    } finally {
      store.close();
    }
  }
});

test('existing safe file permissions retain the original shared and private masks', (t) => {
  for (const [Store, modes] of [
    [TicketStore, [0o640, 0o760, 0o670, 0o1660, 0o2660, 0o4660]],
    [PrivateKeyStore, [0o700, 0o1600, 0o2600, 0o4600]],
  ]) {
    for (const mode of modes) {
      const { path } = fixture(t);
      const first = new Store(path);
      first.close();
      chmodSync(path, mode);
      const second = new Store(path);
      t.after(() => second.close());
      assert.equal(lstatSync(path).mode & 0o7777, mode);
    }
  }
});

test('a shared database symlink cannot open or alter private keys', (t) => {
  const { dir, path } = fixture(t);
  const privateDir = join(dir, 'private');
  mkdirSync(privateDir, { mode: 0o700 });
  const privatePath = join(privateDir, 'keys.db');
  const keys = new PrivateKeyStore(privatePath);
  keys.db
    .prepare('INSERT INTO private_keys (id, encrypted_key) VALUES (?, ?)')
    .run('fixture', 'encrypted-key-fixture');
  keys.close();
  const before = readFileSync(privatePath);
  symlinkSync(privatePath, path);
  unsafe(() => new TicketStore(path));
  assert.deepEqual(readFileSync(privatePath), before);
  assert.equal(lstatSync(privatePath).mode & 0o777, 0o600);
  const reopened = new PrivateKeyStore(privatePath);
  t.after(() => reopened.close());
  assert.equal(reopened.get('fixture'), 'encrypted-key-fixture');
  assert.equal(
    reopened.db
      .prepare(
        "SELECT count(*) AS count FROM sqlite_schema WHERE name = 'tickets'",
      )
      .get().count,
    0,
  );
});

test('a private-key database symlink never reaches pruning or destroys a ticket key', async (t) => {
  const { dir, config, keys, create } = await ticketFixture(t, {
    publicUrl: 'https://example.com',
  });
  const { ticket } = create();
  const encryptedKey = keys.get(ticket.id);
  assert.equal(typeof encryptedKey, 'string');
  assert.ok(encryptedKey.length > 0);
  const sharedPath = join(dir, 'shared-link.sqlite');
  symlinkSync(config.privateDbPath, sharedPath);
  const prune = t.mock.method(keys, 'prune');
  unsafe(() => {
    const untrusted = new TicketStore(sharedPath, config.hmacKey);
    try {
      keys.prune(untrusted);
    } finally {
      untrusted.close();
    }
  });
  assert.equal(prune.mock.callCount(), 0);
  assert.equal(keys.get(ticket.id), encryptedKey);
});

test('dangling database symlinks and directories are rejected before opening', (t) => {
  const { dir, path } = fixture(t);
  const missing = join(dir, 'missing.db');
  symlinkSync(missing, path);
  unsafe(() => new TicketStore(path));
  assert.equal(existsSync(missing), false);
  rmSync(path);
  mkdirSync(path);
  unsafe(() => new TicketStore(path));
});

for (const suffix of ['-wal', '-shm', '-journal']) {
  test(`${suffix} symlinks cannot write to a private target`, (t) => {
    const { dir, path } = fixture(t);
    const target = join(dir, 'private-material');
    const secret = Buffer.from('private-fixture-material');
    writeFileSync(target, secret, { mode: 0o600 });
    symlinkSync(target, `${path}${suffix}`);
    unsafe(() => new TicketStore(path));
    assert.equal(existsSync(path), false);
    assert.deepEqual(readFileSync(target), secret);
    assert.equal(lstatSync(target).mode & 0o777, 0o600);
  });

  test(`${suffix} hard links and directories are rejected`, (t) => {
    const { dir, path } = fixture(t);
    const target = join(dir, 'sidecar-target');
    writeFileSync(target, 'sidecar-fixture', { mode: 0o600 });
    linkSync(target, `${path}${suffix}`);
    unsafe(() => new TicketStore(path));
    assert.equal(readFileSync(target, 'utf8'), 'sidecar-fixture');
    rmSync(`${path}${suffix}`);
    mkdirSync(`${path}${suffix}`);
    unsafe(() => new TicketStore(path));
    assert.equal(existsSync(path), false);
  });
}

test('database hard links are rejected without changing their target', (t) => {
  const { dir, path } = fixture(t);
  const original = join(dir, 'original.db');
  const store = new TicketStore(original);
  store.close();
  const before = readFileSync(original);
  linkSync(original, path);
  unsafe(() => new TicketStore(path));
  assert.deepEqual(readFileSync(original), before);
});

test('a symlinked immediate parent is rejected before creating a database', (t) => {
  const { dir } = fixture(t);
  const parent = join(dir, 'actual');
  const alias = join(dir, 'alias');
  mkdirSync(parent, { mode: 0o700 });
  symlinkSync(parent, alias, 'dir');
  for (const Store of [TicketStore, PrivateKeyStore])
    unsafe(() => new Store(join(alias, 'tickets.db')));
  assert.equal(existsSync(join(parent, 'tickets.db')), false);
});

test('symlinked ancestors and relative paths resolve to the validated database', (t) => {
  const { dir } = fixture(t);
  const actual = join(dir, 'actual');
  const alias = join(dir, 'alias');
  mkdirSync(join(actual, 'parent'), { recursive: true, mode: 0o700 });
  symlinkSync(actual, alias, 'dir');
  const path = join(alias, 'parent', 'tickets.db');
  const store = new TicketStore(relative(process.cwd(), path));
  t.after(() => store.close());
  assert.equal(
    store.db.pragma('database_list')[0].file,
    join(actual, 'parent', 'tickets.db'),
  );
});

test('world-writable real parents are rejected for both stores', (t) => {
  for (const Store of [TicketStore, PrivateKeyStore]) {
    for (const mode of [0o702, 0o707, 0o777]) {
      const { dir, path } = fixture(t);
      chmodSync(dir, mode);
      unsafe(() => new Store(path), 'unsafe_database_permissions');
      assert.equal(existsSync(path), false);
    }
  }
});

test('private directories reject every group and other permission bit', (t) => {
  for (const mode of [
    0o710, 0o720, 0o740, 0o750, 0o770, 0o701, 0o702, 0o704, 0o705, 0o707,
  ]) {
    const { dir, path } = fixture(t);
    chmodSync(dir, mode);
    unsafe(() => new PrivateKeyStore(path), 'unsafe_database_permissions');
    assert.equal(existsSync(path), false);
  }
});

test('shared parents allow group access and other read/traverse without other write', (t) => {
  for (const mode of [0o2770, 0o770, 0o755, 0o704, 0o701, 0o705]) {
    const { dir, path } = fixture(t);
    chmodSync(dir, mode);
    const store = new TicketStore(path);
    t.after(() => store.close());
    assert.equal(lstatSync(dir).mode & 0o7777, mode);
  }
});

test('unsafe database permission bits retain their specific error code', (t) => {
  for (const [Store, mode] of [
    [TicketStore, 0o664],
    [TicketStore, 0o662],
    [TicketStore, 0o661],
    [PrivateKeyStore, 0o640],
    [PrivateKeyStore, 0o620],
    [PrivateKeyStore, 0o610],
    [PrivateKeyStore, 0o604],
    [PrivateKeyStore, 0o602],
    [PrivateKeyStore, 0o601],
  ]) {
    const { path } = fixture(t);
    writeFileSync(path, '', { mode: 0o600 });
    chmodSync(path, mode);
    unsafe(() => new Store(path), 'unsafe_database_permissions');
    assert.equal(lstatSync(path).mode & 0o777, mode);
  }
});

test('private parents must belong to the current real UID, not only its group', (t) => {
  const { path } = fixture(t);
  const uid = process.getuid();
  t.mock.method(process, 'getuid', () => uid + 1);
  unsafe(() => new PrivateKeyStore(path));
  assert.equal(existsSync(path), false);
  const shared = new TicketStore(path);
  t.after(() => shared.close());
});

test('private database files must belong to the current real UID', (t) => {
  const { path } = fixture(t);
  const store = new PrivateKeyStore(path);
  store.close();
  const original = fs.lstatSync;
  const mock = t.mock.method(fs, 'lstatSync', (target, ...args) => {
    const stat = original(target, ...args);
    if (target === path) stat.uid += 1;
    return stat;
  });
  syncBuiltinESMExports();
  try {
    unsafe(() => new PrivateKeyStore(path));
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
});

for (const [description, sql] of [
  [
    'triggers',
    'CREATE TRIGGER unexpected AFTER INSERT ON tickets BEGIN SELECT 1; END',
  ],
  ['views', 'CREATE VIEW unexpected AS SELECT id FROM tickets'],
  ['extra tables', 'CREATE TABLE unexpected (id TEXT)'],
  [
    'internal-looking extra tables',
    'CREATE TABLE sqlitex_unexpected (id TEXT)',
  ],
]) {
  test(`shared schemas reject ${description} before migrations`, (t) => {
    const { path } = fixture(t);
    const store = new TicketStore(path);
    store.db.exec(sql);
    store.close();
    const before = readFileSync(path);
    unsafe(() => new TicketStore(path));
    assert.deepEqual(readFileSync(path), before);
  });
}

test('private schemas reject unexpected tables and views', (t) => {
  for (const sql of [
    'CREATE TABLE tickets (id TEXT)',
    'CREATE VIEW unexpected AS SELECT id FROM private_keys',
    'CREATE TRIGGER unexpected AFTER DELETE ON private_keys BEGIN SELECT 1; END',
  ]) {
    const { path } = fixture(t);
    const keys = new PrivateKeyStore(path);
    keys.db.exec(sql);
    keys.close();
    unsafe(() => new PrivateKeyStore(path));
  }
});

test('SQLite internal tables and indexes on expected tables remain supported', (t) => {
  const { path } = fixture(t);
  const initial = openDatabase(path, 0o660, ['tickets']);
  initial.exec(`
    CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);
    CREATE INDEX ticket_value ON tickets(value);
    INSERT INTO tickets(value) VALUES ('fixture');
    ANALYZE;
  `);
  validateDatabaseSchema(initial, ['tickets']);
  assert.ok(
    initial
      .prepare("SELECT name FROM sqlite_schema WHERE type = 'table'")
      .all()
      .some(({ name }) => name === 'sqlite_sequence'),
  );
  initial.close();
  const reopened = openDatabase(path, 0o660, ['tickets']);
  t.after(() => reopened.close());
  validateDatabaseSchema(reopened, ['tickets']);
});

test('ordinary private sidecars may have broader modes inside the private parent', (t) => {
  const { path } = fixture(t);
  const first = new PrivateKeyStore(path);
  t.after(() => first.close());
  for (const suffix of ['-wal', '-shm']) {
    assert.equal(existsSync(`${path}${suffix}`), true);
    chmodSync(`${path}${suffix}`, 0o666);
  }
  const second = new PrivateKeyStore(path);
  t.after(() => second.close());
  assert.equal(second.db.pragma('quick_check', { simple: true }), 'ok');
});

test('a missing parent directory is database_unavailable', (t) => {
  const { dir } = fixture(t);
  const path = join(dir, 'absent', 'tickets.db');
  unsafe(() => openDatabase(path, 0o660, ['tickets']), 'database_unavailable');
  unsafe(() => new TicketStore(path), 'database_unavailable');
  unsafe(
    () => new PrivateKeyStore(join(dir, 'absent', 'keys.db')),
    'database_unavailable',
  );
  assert.equal(existsSync(path), false);
});

test('an unreadable database parent is database_unavailable', (t) => {
  const { dir, path } = fixture(t);
  chmodSync(dir, 0o000);
  try {
    unsafe(
      () => openDatabase(path, 0o660, ['tickets']),
      'database_unavailable',
    );
    assert.equal(existsSync(path), false);
  } finally {
    chmodSync(dir, 0o700);
  }
});

test('busy and locked migration errors are database_unavailable and close the handle', (t) => {
  const { SqliteError } = Database;
  for (const code of ['SQLITE_BUSY', 'SQLITE_BUSY_SNAPSHOT', 'SQLITE_LOCKED']) {
    const { path } = fixture(t);
    let opened;
    const exec = t.mock.method(Database.prototype, 'exec', function () {
      opened = this;
      throw new SqliteError('database is locked', code);
    });
    try {
      unsafe(() => new TicketStore(path), 'database_unavailable');
      assert.equal(opened.open, false);
    } finally {
      exec.mock.restore();
    }
  }
});

test('a busy error while opening is database_unavailable and closes SQLite', (t) => {
  const { path } = fixture(t);
  const { SqliteError } = Database;
  let opened;
  withPragmaMock(t, function (source, run) {
    if (String(source).startsWith('busy_timeout')) {
      opened = this;
      throw new SqliteError('database is locked', 'SQLITE_BUSY');
    }
    return run();
  });
  unsafe(() => openDatabase(path, 0o660, ['tickets']), 'database_unavailable');
  assert.equal(opened.open, false);
});

test('non-lock SQLite failures stay unsafe_database', (t) => {
  const { path } = fixture(t);
  let opened;
  const exec = t.mock.method(Database.prototype, 'exec', function () {
    opened = this;
    throw new Database.SqliteError(
      'database disk image is malformed',
      'SQLITE_CORRUPT',
    );
  });
  try {
    unsafe(() => new TicketStore(path));
    assert.equal(opened.open, false);
  } finally {
    exec.mock.restore();
  }
});

test('migration errors close the connection and hide SQLite details', (t) => {
  const { path } = fixture(t);
  const initial = openDatabase(path, 0o660, ['tickets']);
  initial.exec('CREATE TABLE tickets (id TEXT PRIMARY KEY)');
  initial.close();
  let opened;
  withPragmaMock(t, function (source, run) {
    opened = this;
    return run();
  });
  unsafe(() => new TicketStore(path));
  assert.equal(opened.open, false);
});

test('missing expected tables fail post-migration validation and close the handle', () => {
  const db = openDatabase(':memory:', 0o600, [
    'private_keys',
    'ticket_metadata',
  ]);
  db.exec('CREATE TABLE private_keys (id TEXT PRIMARY KEY)');
  unsafe(() => validateDatabaseSchema(db, ['private_keys', 'ticket_metadata']));
  assert.equal(db.open, false);
});

test('post-migration validation rejects executable schema and closes the handle', () => {
  const db = openDatabase(':memory:', 0o660, ['tickets']);
  db.exec(
    'CREATE TABLE tickets (id TEXT); CREATE VIEW unexpected AS SELECT * FROM tickets',
  );
  unsafe(() => validateDatabaseSchema(db, ['tickets']));
  assert.equal(db.open, false);
});

test('garbage databases produce a generic error and preserve their bytes', (t) => {
  for (const Store of [TicketStore, PrivateKeyStore]) {
    const { path } = fixture(t);
    const garbage = Buffer.alloc(512, 0xff);
    writeFileSync(path, garbage, { mode: 0o600 });
    unsafe(() => new Store(path));
    assert.deepEqual(readFileSync(path), garbage);
  }
});

test('failed quick_check closes the opened connection without exposing SQLite details', (t) => {
  const { path } = fixture(t);
  let opened;
  withPragmaMock(t, function (source, run) {
    if (source === 'quick_check') {
      opened = this;
      return [{ quick_check: 'fixture corruption details' }];
    }
    return run();
  });
  unsafe(() => openDatabase(path, 0o660, ['tickets']));
  assert.equal(opened.open, false);
});

for (const [description, result] of [
  ['no rows', []],
  ['a different result key', [{ other: 'ok' }]],
  ['extra result keys', [{ quick_check: 'ok', other: 'ok' }]],
  ['multiple rows', [{ quick_check: 'ok' }, { quick_check: 'ok' }]],
]) {
  test(`quick_check rejects ${description} and closes the connection`, (t) => {
    const { path } = fixture(t);
    let opened;
    withPragmaMock(t, function (source, run) {
      if (source === 'quick_check') {
        opened = this;
        return result;
      }
      return run();
    });
    unsafe(() => openDatabase(path, 0o660, ['tickets']));
    assert.equal(opened.open, false);
  });
}

test('database_list must resolve to the validated path', (t) => {
  const { path } = fixture(t);
  const { path: other } = fixture(t);
  const second = openDatabase(other, 0o660, ['tickets']);
  second.close();
  let opened;
  withPragmaMock(t, function (source, run) {
    if (source === 'database_list') {
      opened = this;
      return [{ seq: 0, name: 'main', file: other }];
    }
    return run();
  });
  unsafe(() => openDatabase(path, 0o660, ['tickets']));
  assert.equal(opened.open, false);
});

for (const code of ['SQLITE_BUSY', 'SQLITE_BUSY_SNAPSHOT', 'SQLITE_LOCKED']) {
  test(`identity validation maps ${code} to database_unavailable and closes SQLite`, (t) => {
    const { path } = fixture(t);
    let opened;
    withPragmaMock(t, function (source, run) {
      if (source === 'database_list') {
        opened = this;
        throw new Database.SqliteError('fixture lock details', code);
      }
      return run();
    });
    unsafe(
      () => openDatabase(path, 0o660, ['tickets']),
      'database_unavailable',
    );
    assert.equal(opened.open, false);
  });
}

test('permission-bit failures found after open keep their code', (t) => {
  const { dir, path } = fixture(t);
  withPragmaMock(t, function (source, run) {
    if (source === 'trusted_schema = OFF') chmodSync(dir, 0o707);
    return run();
  });
  unsafe(
    () => openDatabase(path, 0o660, ['tickets']),
    'unsafe_database_permissions',
  );
});

for (const identity of ['dev', 'ino']) {
  test(`database ${identity} replacement during opening is rejected and closes SQLite`, (t) => {
    const { path } = fixture(t);
    const original = fs.lstatSync;
    let checks = 0;
    let opened;
    const mock = t.mock.method(fs, 'lstatSync', (target, ...args) => {
      const stat = original(target, ...args);
      if (target === path && ++checks > 1) stat[identity] += 1;
      return stat;
    });
    syncBuiltinESMExports();
    withPragmaMock(t, function (source, run) {
      opened = this;
      return run();
    });
    try {
      writeFileSync(path, '', { mode: 0o660 });
      unsafe(() => openDatabase(path, 0o660, ['tickets']));
      assert.equal(opened.open, false);
    } finally {
      mock.mock.restore();
      syncBuiltinESMExports();
    }
  });
}

test('a database file removed after open is unsafe_database', (t) => {
  const { path } = fixture(t);
  let opened;
  withPragmaMock(t, function (source, run) {
    if (String(source).startsWith('trusted_schema')) {
      opened = this;
      renameSync(path, `${path}.moved`);
    }
    return run();
  });
  unsafe(() => openDatabase(path, 0o660, ['tickets']));
  assert.equal(existsSync(path), false);
  assert.equal(opened.open, false);
});

test('an unreadable database after open is unsafe_database', (t) => {
  if (process.getuid?.() === 0) {
    t.skip('root ignores directory mode bits');
    return;
  }
  const { dir, path } = fixture(t);
  let opened;
  withPragmaMock(t, function (source, run) {
    if (String(source).startsWith('trusted_schema')) {
      opened = this;
      chmodSync(dir, 0o000);
    }
    return run();
  });
  try {
    unsafe(() => openDatabase(path, 0o660, ['tickets']));
    assert.equal(opened.open, false);
  } finally {
    chmodSync(dir, 0o700);
  }
});
