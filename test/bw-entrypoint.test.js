import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const execute = promisify(execFile);
const entrypoint = new URL('../docker/bw-entrypoint.sh', import.meta.url)
  .pathname;

async function setup(t, overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'intake-bw-entrypoint-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'client-id'), 'test-client-id\n', { mode: 0o600 });
  await writeFile(join(dir, 'client-secret'), 'test-client-secret\n', {
    mode: 0o600,
  });
  await writeFile(join(dir, 'password'), 'test-master-password\n', {
    mode: 0o600,
  });
  await writeFile(
    join(dir, 'bw'),
    `#!/bin/sh
set -eu
printf '%s|%s|%s|%s|%s\\n' "$*" "\${BW_CLIENTID-unset}" "\${BW_CLIENTSECRET-unset}" "\${BW_SESSION-unset}" "$(umask)" >> "$CALLS"
case "$*" in
  'config server' ) printf '%s\\n' "\${CONFIGURED_SERVER-https://vault.example.com}" ;;
  'config server '* )
    printf '%s\\n' 'sensitive-config-output' >&2
    [ "\${FAIL-config}" != config ] ;;
  'login --check' ) [ "\${LOGGED_IN-no}" = yes ] ;;
  'login --apikey' )
    [ "$BW_CLIENTID" = test-client-id ]
    [ "$BW_CLIENTSECRET" = test-client-secret ]
    printf '%s\\n' 'sensitive-login-output'
    [ "\${FAIL-no}" != login ] ;;
  'unlock --passwordfile '* )
    [ "$3" = "$BW_PASSWORD_FILE" ]
    [ "$4" = --raw ]
    printf '%s\\n' 'sensitive-unlock-output' >&2
    [ "\${FAIL-no}" != unlock ] || exit 1
    [ "\${FAIL-no}" != empty ] || exit 0
    printf '%s\\n' 'test-session-key' ;;
  'serve --hostname unix:///run/intake-bw/bw.sock' )
    [ "$BW_SESSION" = test-session-key ] ;;
  *) exit 9 ;;
esac
`,
    { mode: 0o700 },
  );
  await writeFile(
    join(dir, 'node'),
    `#!/bin/sh
set -eu
[ "$1" = /opt/intake/docker/prepare-bw-socket.js ]
printf '%s|%s|%s|%s|%s\\n' "node $*" "\${BW_CLIENTID-unset}" "\${BW_CLIENTSECRET-unset}" "\${BW_SESSION-unset}" "$(umask)" >> "$CALLS"
[ "\${FAIL-no}" != socket ]
`,
    { mode: 0o700 },
  );
  const env = {
    ...process.env,
    PATH: `${dir}:${process.env.PATH}`,
    CALLS: join(dir, 'calls'),
    BW_SERVER: 'https://vault.example.com',
    BW_CLIENTID_FILE: join(dir, 'client-id'),
    BW_CLIENTSECRET_FILE: join(dir, 'client-secret'),
    BW_PASSWORD_FILE: join(dir, 'password'),
    BW_CLIENTID: 'inherited-client-id',
    BW_CLIENTSECRET: 'inherited-client-secret',
    BW_SESSION: 'inherited-session',
    FAIL: 'no',
    ...overrides,
  };
  return {
    dir,
    env,
    calls: async () => (await readFile(env.CALLS, 'utf8')).trim().split('\n'),
  };
}

async function assertUnsafeSecret(f) {
  await assert.rejects(execute('/bin/sh', [entrypoint], { env: f.env }), {
    code: 1,
    stdout: '',
    stderr: 'Vault secret files are unreadable or unsafe.\n',
  });
  // Validation precedes even the logged-in-profile probe or any secret read.
  await assert.rejects(readFile(f.env.CALLS), { code: 'ENOENT' });
}

for (const name of [
  'BW_CLIENTID_FILE',
  'BW_CLIENTSECRET_FILE',
  'BW_PASSWORD_FILE',
]) {
  test(`bw bootstrap rejects unreadable or group/other-accessible ${name} before CLI calls`, async (t) => {
    for (const loggedIn of ['no', 'yes']) {
      for (const mode of [0o000, 0o640, 0o604, 0o620, 0o601]) {
        const f = await setup(t, { LOGGED_IN: loggedIn });
        await chmod(f.env[name], mode);
        await assertUnsafeSecret(f);
      }
    }
  });

  test(`bw bootstrap rejects missing or non-regular ${name} without exposing its path`, async (t) => {
    for (const kind of ['missing', 'directory', 'symlink']) {
      const f = await setup(t);
      await rm(f.env[name]);
      if (kind === 'directory') await mkdir(f.env[name]);
      if (kind === 'symlink') {
        const target = join(f.dir, 'private-target');
        await writeFile(target, 'private-secret-target', { mode: 0o600 });
        await symlink(target, f.env[name]);
      }
      await assertUnsafeSecret(f);
    }
  });

  test(`bw bootstrap accepts owner-readable private modes for ${name}`, async (t) => {
    for (const mode of [0o400, 0o600]) {
      const f = await setup(t);
      await chmod(f.env[name], mode);
      const result = await execute('/bin/sh', [entrypoint], { env: f.env });
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, '');
      assert((await f.calls()).at(-1).startsWith('serve --hostname '));
    }
  });
}

test('bw bootstrap rejects failed or malformed permission inspection with the same generic error', async (t) => {
  for (const [mode, exit] of [
    ['600', 1],
    ['', 0],
    ['invalid-private-output', 0],
    ['888', 0],
    ['600\n644', 0],
  ]) {
    const f = await setup(t, { STAT_MODE: mode, STAT_EXIT: String(exit) });
    await writeFile(
      join(f.dir, 'stat'),
      `#!/bin/sh
printf '%s\\n' 'private-stat-error-message' >&2
printf '%s' "$STAT_MODE"
exit "$STAT_EXIT"
`,
      { mode: 0o700 },
    );
    await assertUnsafeSecret(f);
  }
});

test('bw bootstrap confines API credentials to login and exports only the unlocked session', async (t) => {
  const f = await setup(t);
  const result = await execute('/bin/sh', [entrypoint], { env: f.env });
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  const calls = await f.calls();
  assert(
    calls.some((line) =>
      line.startsWith('config server https://vault.example.com|'),
    ),
  );
  assert(
    calls.some((line) =>
      line.startsWith(
        'login --apikey|test-client-id|test-client-secret|unset|',
      ),
    ),
  );
  for (const line of calls.filter(
    (line) => !line.startsWith('login --apikey|'),
  )) {
    const [, id, secret] = line.split('|');
    assert.equal(id, 'unset');
    assert.equal(secret, 'unset');
  }
  assert(
    calls
      .at(-1)
      .startsWith(
        'serve --hostname unix:///run/intake-bw/bw.sock|unset|unset|test-session-key|',
      ),
  );
  assert(calls.every((line) => /\|0*77$/.test(line)));
});

test('bw bootstrap reuses a logged-in profile but obtains a fresh session', async (t) => {
  const f = await setup(t, { LOGGED_IN: 'yes' });
  await execute('/bin/sh', [entrypoint], { env: f.env });
  const calls = await f.calls();
  assert(!calls.some((line) => line.startsWith('login --apikey|')));
  assert(calls.some((line) => line.startsWith('unlock --passwordfile ')));
  assert(calls.at(-1).startsWith('serve --hostname '));
});

test('bw bootstrap refuses a logged-in profile for a different server', async (t) => {
  const f = await setup(t, {
    LOGGED_IN: 'yes',
    CONFIGURED_SERVER: 'https://other.example.com',
  });
  await assert.rejects(execute('/bin/sh', [entrypoint], { env: f.env }), {
    code: 1,
    stdout: '',
    stderr: 'Vault server does not match the existing CLI profile.\n',
  });
  const calls = await f.calls();
  assert(!calls.some((line) => line.startsWith('config server https:')));
  assert(!calls.some((line) => line.startsWith('unlock ')));
  assert(!calls.some((line) => line.startsWith('serve ')));
});

for (const failure of ['config', 'login', 'unlock', 'empty', 'socket']) {
  test(`bw bootstrap fails closed without leaking CLI output on ${failure} failure`, async (t) => {
    const f = await setup(t, { FAIL: failure });
    await assert.rejects(
      execute('/bin/sh', [entrypoint], { env: f.env }),
      (error) => {
        assert.equal(error.code, 1);
        assert.equal(error.stdout, '');
        assert(
          !/sensitive-|test-session|test-client|test-master/.test(error.stderr),
        );
        return true;
      },
    );
    assert(!(await f.calls()).some((line) => line.startsWith('serve ')));
  });
}
