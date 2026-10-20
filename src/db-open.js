import Database from 'better-sqlite3';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { IntakeError } from './errors.js';

const operationalFsCodes = new Set(['ENOENT', 'EACCES', 'EPERM']);
const databaseIoCodes = new Set([
  'ENOSPC',
  'EMFILE',
  'ENFILE',
  'EROFS',
  'EIO',
  'SQLITE_FULL',
  'SQLITE_IOERR',
  'SQLITE_CANTOPEN',
  'SQLITE_NOMEM',
  'SQLITE_READONLY',
]);

function isDatabaseIoError(error) {
  if (
    !(error instanceof Error) ||
    error instanceof IntakeError ||
    error.code === 'SQLITE_READONLY_DBMOVED' ||
    error.code === 'SQLITE_CANTOPEN_SYMLINK' ||
    error.code === 'SQLITE_CANTOPEN_DIRTYWAL'
  )
    return false;
  return (
    databaseIoCodes.has(error.code) ||
    (typeof error.code === 'string' &&
      (error.code.startsWith('SQLITE_IOERR_') ||
        error.code.startsWith('SQLITE_CANTOPEN_') ||
        error.code.startsWith('SQLITE_READONLY_')))
  );
}

export function isDatabaseLockError(error) {
  return (
    typeof error?.code === 'string' &&
    (error.code.startsWith('SQLITE_BUSY') ||
      error.code.startsWith('SQLITE_LOCKED'))
  );
}

function isOperationalDatabaseError(error) {
  if (!(error instanceof Error) || error instanceof IntakeError) return false;
  if (operationalFsCodes.has(error.code)) return true;
  return isDatabaseLockError(error);
}

export function databaseFailure(error) {
  if (
    error instanceof IntakeError &&
    (error.code === 'unsafe_database' ||
      error.code === 'unsafe_database_permissions' ||
      error.code === 'database_unavailable' ||
      error.code === 'database_io_error')
  )
    return error;
  if (isDatabaseIoError(error)) return new IntakeError('database_io_error');
  if (isOperationalDatabaseError(error))
    return new IntakeError('database_unavailable');
  return new IntakeError('unsafe_database');
}

function rejectDatabase(db, error) {
  try {
    if (db?.open) db.close();
  } catch {
    // Preserve the generic opening error even if closing also fails.
  }
  throw databaseFailure(error);
}

function optionalStat(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function validateOwner(stat, mode) {
  if (mode === 0o600 && stat.uid !== process.getuid())
    throw new IntakeError('unsafe_database');
}

function validateParent(path, mode) {
  const stat = lstatSync(dirname(path));
  if (!stat.isDirectory()) throw new IntakeError('unsafe_database');
  validateOwner(stat, mode);
  if (stat.mode & (mode === 0o600 ? 0o077 : 0o002))
    throw new IntakeError('unsafe_database_permissions');
}

function validateFile(path, mode) {
  const stat = optionalStat(path);
  if (!stat) return null;
  if (!stat.isFile() || stat.nlink !== 1)
    throw new IntakeError('unsafe_database');
  validateOwner(stat, mode);
  if (stat.mode & (mode === 0o600 ? 0o077 : 0o007))
    throw new IntakeError('unsafe_database_permissions');
  return stat;
}

function validateFiles(path, mode) {
  const stat = validateFile(path, mode);
  for (const suffix of ['-wal', '-shm', '-journal']) {
    const sidecar = optionalStat(`${path}${suffix}`);
    if (sidecar && (!sidecar.isFile() || sidecar.nlink !== 1))
      throw new IntakeError('unsafe_database');
  }
  return stat;
}

function sameFile(left, right) {
  return left && right && left.dev === right.dev && left.ino === right.ino;
}

function validateIdentity(db, path, mode, original) {
  // Once the handle is open, a missing or unreadable file is tampering.
  // Resource, I/O and lock errors stay operational so the caller can map them.
  try {
    validateParent(path, mode);
    const current = validateFiles(path, mode);
    const databases = db.pragma('database_list');
    const main = databases.find(({ name }) => name === 'main');
    if (
      !main ||
      databases.some(({ name }) => name !== 'main' && name !== 'temp') ||
      resolve(main.file) !== path ||
      realpathSync(main.file) !== path ||
      !sameFile(original, current) ||
      !sameFile(original, lstatSync(main.file))
    )
      throw new IntakeError('unsafe_database');
  } catch (error) {
    if (
      error instanceof IntakeError ||
      isDatabaseLockError(error) ||
      isDatabaseIoError(error)
    )
      throw error;
    throw new IntakeError('unsafe_database');
  }
}

export function validateDatabaseSchema(
  db,
  expectedTables,
  { allowMissing = false } = {},
) {
  try {
    const expected = new Set(expectedTables);
    const found = new Set();
    for (const { type, name, tbl_name: table, sql } of db
      .prepare('SELECT type, name, tbl_name, sql FROM main.sqlite_schema')
      .all()) {
      if (type === 'table') {
        if (!expected.has(name) && !name.startsWith('sqlite_'))
          throw new IntakeError('unsafe_database');
        if (!/^CREATE\s+TABLE\b/i.test(sql ?? ''))
          throw new IntakeError('unsafe_database');
        found.add(name);
      } else if (type === 'index') {
        if (!expected.has(table) && !table.startsWith('sqlite_'))
          throw new IntakeError('unsafe_database');
      } else {
        // Triggers and views are executable schema, even with internal-looking names.
        throw new IntakeError('unsafe_database');
      }
    }
    if (!allowMissing && [...expected].some((name) => !found.has(name)))
      throw new IntakeError('unsafe_database');
  } catch (error) {
    rejectDatabase(db, error);
  }
}

export function openDatabase(path, mode, expectedTables) {
  let db;
  try {
    if (typeof path !== 'string' || !path || (mode !== 0o600 && mode !== 0o660))
      throw new IntakeError('unsafe_database');
    const memory = path === ':memory:';
    const absolute = memory ? path : resolve(path);
    let resolved = absolute;
    let original;
    if (!memory) {
      validateParent(absolute, mode);
      resolved = join(realpathSync(dirname(absolute)), basename(absolute));
      original = validateFiles(resolved, mode);
      if (!original) {
        let fd;
        try {
          fd = openSync(
            resolved,
            constants.O_CREAT |
              constants.O_EXCL |
              constants.O_RDWR |
              constants.O_NOFOLLOW,
            mode,
          );
        } catch (error) {
          // Another process created the file after the empty check.
          if (error.code !== 'EEXIST') throw error;
          original = validateFiles(resolved, mode);
          if (!original) throw new IntakeError('unsafe_database');
        }
        if (fd !== undefined) {
          try {
            fchmodSync(fd, mode);
            original = fstatSync(fd);
          } finally {
            closeSync(fd);
          }
        }
      }
    }
    // better-sqlite3 enables SQLITE_DBCONFIG_DEFENSIVE by default; do not use unsafeMode().
    db = new Database(resolved, { fileMustExist: !memory });
    db.pragma('trusted_schema = OFF');
    db.pragma('cell_size_check = ON');
    db.pragma('busy_timeout = 5000');
    if (!memory) validateIdentity(db, resolved, mode, original);
    validateDatabaseSchema(db, expectedTables, { allowMissing: true });
    const check = db.pragma('quick_check');
    if (
      check.length !== 1 ||
      Object.keys(check[0]).length !== 1 ||
      !Object.hasOwn(check[0], 'quick_check') ||
      check[0].quick_check !== 'ok'
    )
      throw new IntakeError('unsafe_database');
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = FULL');
    db.pragma('secure_delete = ON');
    if (!memory) validateIdentity(db, resolved, mode, original);
    return db;
  } catch (error) {
    rejectDatabase(db, error);
  }
}
