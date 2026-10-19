import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { readFile, stat, symlink, chmod, writeFile } from 'node:fs/promises';
import { runCli } from '../src/cli.js';
import { assertNonRoot } from '../src/errors.js';
import { startWeb } from '../src/web.js';
import { startWriter } from '../src/writer.js';
import { createLogger } from '../src/logger.js';
import { fixture } from '../support/fixtures.js';
import { encryptValue } from '../public/crypto.js';
import { decryptValue } from '../src/crypto.js';
import { MockVaultAdapter } from '../src/vault.js';

const execute = promisify(execFile);
const cliPath = new URL('../src/cli.js', import.meta.url).pathname;
const createArgs = [
  'create',
  '--key-name',
  'DB_PASSWORD',
  '--purpose',
  'Connect the application',
  '--target-item',
  'Application database',
  '--target-field',
  'password',
];

function cliEnv(f) {
  return {
    ...process.env,
    INTAKE_DB: f.config.dbPath,
    INTAKE_PRIVATE_DB: f.config.privateDbPath,
    INTAKE_SOCKET: f.config.socketPath,
    INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
    INTAKE_WRITER_KEY: f.config.masterKey.toString('base64'),
    INTAKE_FINGERPRINT_KEY_FILE: f.config.fingerprintKeyFile,
    INTAKE_PUBLIC_URL: 'https://intake.example.com',
    INTAKE_DEFAULT_NOTIFY_EMAIL: 'ops@example.com',
    INTAKE_HMAC_KEY_FILE: '',
    INTAKE_WRITER_KEY_FILE: '',
  };
}

async function invoke(args, env) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    env,
    stdout: {
      write: (text) => {
        stdout += text;
      },
    },
    stderr: {
      write: (text) => {
        stderr += text;
      },
    },
  });
  return { code, stdout, stderr };
}

test('actual CLI prints one creation link, lists without tokens, revokes and purges', async (t) => {
  const f = await fixture(t);
  const env = cliEnv(f);
  const created = await execute(
    process.execPath,
    [
      cliPath,
      ...createArgs,
      '--ttl',
      '48h',
      '--target-notes',
      'Review before moving',
    ],
    { env },
  );
  assert.equal(created.stderr, '');
  assert.match(
    created.stdout,
    /^https:\/\/intake\.example\.com\/#req=[\w-]{22}\.[\w-]{43}\n$/,
  );
  const token = created.stdout.trim().split('#req=')[1];
  const id = token.split('.')[0];
  const ticket = f.store.get(id);
  assert.equal(ticket.expiresAt - ticket.createdAt, 48 * 3600000);
  assert.equal(Object.hasOwn(ticket, 'target'), false);
  assert.equal(Object.hasOwn(ticket, 'notifyEmail'), false);
  assert.equal(ticket.trim, true);
  assert.deepEqual(f.keys.getMetadata(id), {
    id,
    keyName: ticket.keyName,
    purpose: ticket.purpose,
    trim: ticket.trim,
    expiresAt: ticket.expiresAt,
    revoked: false,
    firstSeenAt: null,
    target: {
      item: 'Application database',
      field: 'password',
      notes: 'Review before moving',
    },
    notifyEmail: 'ops@example.com',
    metaDigest: ticket.metaDigest,
  });
  assert.match(ticket.metaDigest, /^[a-f0-9]{64}$/);
  const listed = await execute(process.execPath, [cliPath, 'list'], { env });
  assert(listed.stdout.includes(id));
  assert(listed.stdout.includes('DB_PASSWORD\tactive'));
  assert(listed.stdout.includes('NOTIFY STATUS'));
  assert(!listed.stdout.includes(token));
  assert(!listed.stdout.includes(token.split('.')[1]));
  assert(!listed.stdout.includes('Review before moving'));
  await execute(process.execPath, [cliPath, 'revoke', '--', id], { env });
  assert.equal(f.store.get(id).status, 'revoked');
  await new Promise((resolve) => setTimeout(resolve, 2));
  const purged = await execute(
    process.execPath,
    [cliPath, 'purge', '--older-than-days', '0'],
    { env },
  );
  assert.equal(purged.stdout, 'Purged 1 tickets.\n');
  assert.equal(f.store.get(id), null);
  assert.equal(f.keys.get(id), undefined);
  assert.equal(f.keys.getMetadata(id), null);
  const packageJson = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  assert.equal(packageJson.bin.intake, 'src/cli.js');
  assert((await stat(cliPath)).mode & 0o111);
});

test('CLI list shows the writer fingerprint without loading the fingerprint key', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const value = 'private-operator-reference-value';
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
  try {
    f.store.claim(token, await encryptValue(ticket, value));
    await writer.drain();
    const done = f.store.get(ticket.id);
    assert.equal(done.status, 'done');
    assert.equal(vault.entries[0].fingerprint, done.fingerprint);
    const result = await execute(process.execPath, [cliPath, 'list'], {
      env: {
        ...cliEnv(f),
        INTAKE_FINGERPRINT_KEY_FILE: '/unreadable/fingerprint.key',
      },
    });
    assert.equal(result.stderr, '');
    assert(result.stdout.includes('FINGERPRINT'));
    assert(result.stdout.includes(`${ticket.id}\t`));
    assert(result.stdout.includes(`\t${done.fingerprint}\t0\t-\n`));
    assert(!result.stdout.includes(value));
    assert(!result.stdout.includes(token));
  } finally {
    await writer.close();
  }
});

test('installed intake bin executes through a symlink', async (t) => {
  const f = await fixture(t);
  const bin = join(f.dir, 'intake');
  await symlink(cliPath, bin);
  const result = await execute(bin, ['--help'], { env: cliEnv(f) });
  assert(result.stdout.includes('Usage:'));
  assert.equal(result.stderr, '');
});

test('CLI default/explicit email behavior, TTL bound errors and sanitized parser failures', async (t) => {
  const f = await fixture(t);
  const env = cliEnv(f);
  const missingEmail = await invoke(createArgs, {
    ...env,
    INTAKE_DEFAULT_NOTIFY_EMAIL: '',
  });
  assert.equal(missingEmail.code, 1);
  assert.equal(missingEmail.stderr, 'intake: single_notify_email_required\n');
  assert.equal(f.store.list().length, 0);
  const explicit = await invoke(
    [...createArgs, '--notify-email', 'intake@example.com'],
    env,
  );
  assert.equal(explicit.code, 0);
  const id = explicit.stdout.split('#req=')[1].split('.')[0];
  assert.equal(f.keys.getMetadata(id).notifyEmail, 'intake@example.com');
  assert.equal(Object.hasOwn(f.store.get(id), 'notifyEmail'), false);
  for (const ttl of ['0h', '-1d', '8d']) {
    const result = await invoke([...createArgs, `--ttl=${ttl}`], env);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.match(
      result.stderr,
      /^intake: (invalid_ttl|ttl_exceeds_maximum)\n$/,
    );
  }
  const extended = await invoke([...createArgs, '--ttl', '8d'], {
    ...env,
    INTAKE_MAX_TTL: '10d',
  });
  assert.equal(extended.code, 0);
  const sensitive = 'sensitive-untrusted-argument';
  for (const args of [
    ['list', `--${sensitive}`],
    ['revoke', sensitive],
    [sensitive],
    ['purge', '--older-than-days', '-1'],
  ]) {
    const result = await invoke(args, env);
    assert.equal(result.code, 1);
    assert(!result.stderr.includes(sensitive));
    assert.equal(result.stdout, '');
  }
});

test('help needs no credentials and error output never echoes raw filesystem errors', async (t) => {
  const f = await fixture(t);
  const help = await invoke(['--help'], {});
  assert.equal(help.code, 0);
  assert(help.stdout.includes('notify-retry'));
  const env = {
    ...cliEnv(f),
    INTAKE_DB: join(f.dir, 'missing-private-directory/tickets.sqlite'),
  };
  const result = await invoke(['list'], env);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, 'intake: database_unavailable\n');
  assert(!result.stderr.includes(f.dir));
});

test('web and writer entrypoints refuse uid 0 before accessing configuration or resources', async (t) => {
  const logs = [];
  const logger = createLogger({ write: (line) => logs.push(line) });
  t.mock.method(process, 'getuid', () => 0);
  assert.throws(assertNonRoot, /non_root_user_required/);
  await assert.rejects(startWeb({ logger }), /non_root_user_required/);
  await assert.rejects(startWriter({ logger }), /non_root_user_required/);
  const cli = await invoke(['--help'], {});
  assert.equal(cli.code, 1);
  assert.equal(cli.stderr, 'intake: non_root_user_required\n');
  assert.equal(logs.length, 0);
});

test('real writer startup fails closed without mail configuration and does not leak keys', async (t) => {
  const f = await fixture(t);
  const env = {
    ...cliEnv(f),
    INTAKE_NOTIFY: 'on',
    MAIL_API_URL: '',
    BW_ORGANIZATION_ID: 'organization-id',
    BW_COLLECTION_ID: 'collection-id',
  };
  const result = await execute(
    process.execPath,
    [new URL('../src/writer-main.js', import.meta.url).pathname],
    { env },
  ).then(
    () => assert.fail('writer must refuse startup'),
    (error) => error,
  );
  assert.equal(result.code, 1);
  assert.equal(result.stderr, '');
  const record = JSON.parse(result.stdout);
  assert.equal(record.event, 'writer_start_failed');
  assert(!result.stdout.includes(env.INTAKE_WRITER_KEY));
  assert(!result.stdout.includes(env.INTAKE_HMAC_KEY));
});

for (const mode of [0o750, 0o755]) {
  test(`real writer startup refuses vault socket parent mode ${mode.toString(8)}`, async (t) => {
    const f = await fixture(t);
    const parent = join(f.dir, 'private');
    await chmod(parent, mode);
    const env = {
      ...cliEnv(f),
      INTAKE_NOTIFY: 'off',
      INTAKE_BW_SOCKET: join(parent, 'bw.sock'),
      BW_ORGANIZATION_ID: 'organization-id',
      BW_COLLECTION_ID: 'collection-id',
    };
    const result = await execute(
      process.execPath,
      [new URL('../src/writer-main.js', import.meta.url).pathname],
      { env },
    ).then(
      () => assert.fail('writer must refuse startup'),
      (error) => error,
    );
    assert.equal(result.code, 1);
    assert.equal(result.stderr, '');
    assert.equal(
      JSON.parse(result.stdout).code,
      'unsafe_vault_socket_directory',
    );
    assert(!result.stdout.includes(parent));
    await assert.rejects(stat(f.config.socketPath), { code: 'ENOENT' });
  });
}

for (const tail of ['a'.repeat(120), 'é'.repeat(60)]) {
  test(`real writer startup rejects an overlong ${tail[0] === 'a' ? 'ASCII' : 'UTF-8'} vault socket before listening`, async (t) => {
    const f = await fixture(t);
    const socketPath = join(f.dir, 'private', tail);
    const env = {
      ...cliEnv(f),
      INTAKE_NOTIFY: 'off',
      INTAKE_BW_SOCKET: socketPath,
      BW_ORGANIZATION_ID: 'example-organization',
      BW_COLLECTION_ID: 'example-collection',
    };
    const result = await execute(
      process.execPath,
      [new URL('../src/writer-main.js', import.meta.url).pathname],
      { env },
    ).then(
      () => assert.fail('writer must refuse startup'),
      (error) => error,
    );
    assert.equal(result.code, 1);
    assert.equal(result.stderr, '');
    assert.equal(JSON.parse(result.stdout).code, 'invalid_intake_bw_socket');
    assert(!result.stdout.includes(socketPath));
    await assert.rejects(stat(f.config.socketPath), { code: 'ENOENT' });
  });
}

for (const kind of ['unset', 'missing', '0640', '0644', 'invalid', 'short']) {
  test(`real writer startup rejects ${kind} fingerprint key file before opening its socket`, async (t) => {
    const f = await fixture(t);
    const env = {
      ...cliEnv(f),
      INTAKE_NOTIFY: 'off',
      BW_ORGANIZATION_ID: 'organization-id',
      BW_COLLECTION_ID: 'collection-id',
    };
    if (kind === 'unset') {
      env.INTAKE_FINGERPRINT_KEY_FILE = '';
      // A direct environment value must not bypass the dedicated file requirement.
      env.INTAKE_FINGERPRINT_KEY = f.config.fingerprintKey.toString('base64');
    } else if (kind === 'missing') {
      env.INTAKE_FINGERPRINT_KEY_FILE = join(f.dir, 'missing.key');
    } else if (kind === '0640' || kind === '0644') {
      await chmod(f.config.fingerprintKeyFile, Number.parseInt(kind, 8));
    } else {
      await writeFile(
        f.config.fingerprintKeyFile,
        kind === 'short' ? Buffer.alloc(16).toString('base64') : 'not-a-key',
      );
    }
    const result = await execute(
      process.execPath,
      [new URL('../src/writer-main.js', import.meta.url).pathname],
      { env },
    ).then(
      () => assert.fail('writer must refuse startup'),
      (error) => error,
    );
    assert.equal(result.code, 1);
    assert.equal(result.stderr, '');
    assert.equal(JSON.parse(result.stdout).event, 'writer_start_failed');
    for (const secret of [
      env.INTAKE_WRITER_KEY,
      env.INTAKE_HMAC_KEY,
      f.config.fingerprintKey.toString('base64'),
      f.dir,
    ])
      assert(!result.stdout.includes(secret));
    await assert.rejects(stat(f.config.socketPath), { code: 'ENOENT' });
  });
}

test('CLI --keep-whitespace is a per-ticket boolean and preserves the encrypted value exactly', async (t) => {
  const f = await fixture(t);
  const env = cliEnv(f);
  for (const keep of [false, true]) {
    const result = await invoke(
      [...createArgs, ...(keep ? ['--keep-whitespace'] : [])],
      env,
    );
    assert.equal(result.code, 0);
    assert.equal(result.stderr, '');
    const token = result.stdout.trim().split('#req=')[1];
    const ticket = f.store.get(token.split('.')[0]);
    assert.equal(ticket.trim, !keep);
    const opened = f.store.open(token);
    assert.equal(opened.trim, !keep);
    const value = ' \t\n  value with internal  spaces\n ';
    const envelope = await encryptValue(opened, value);
    const decrypted = decryptValue(
      f.config.masterKey,
      ticket,
      f.keys.get(ticket.id),
      envelope,
    );
    assert.equal(decrypted.value, keep ? value : value.trim());
  }
  for (const args of [
    [...createArgs, '--keep-whitespace=false'],
    ['list', '--keep-whitespace'],
  ]) {
    const result = await invoke(args, env);
    assert.equal(result.code, 1);
    assert.equal(result.stderr, 'intake: invalid_arguments\n');
  }
  const help = await invoke(['--help'], {});
  assert(help.stdout.includes('--keep-whitespace'));
});
