import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:net';
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepareBwSocket } from '../docker/prepare-bw-socket.js';

const execute = promisify(execFile);
const helper = new URL('../docker/prepare-bw-socket.js', import.meta.url)
  .pathname;

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'intake-bw-socket-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, path: join(dir, 'bw.sock') };
}

test('socket helper logs internal and system error codes without paths or messages', async (t) => {
  const f = await fixture(t);
  await writeFile(f.path, 'preserve this file', { mode: 0o600 });
  for (const [path, code] of [
    [f.path, 'vault_socket_not_socket'],
    [join(f.dir, 'sensitive-missing-parent', 'bw.sock'), 'ENOENT'],
  ]) {
    await assert.rejects(execute(process.execPath, [helper, path]), {
      code: 1,
      stdout: '',
      stderr: `Socket preparation failed (${code}).\n`,
    });
  }
});

test('socket helper redacts unsafe or absent error codes rather than logging an exception', async (t) => {
  const f = await fixture(t);
  for (const code of ['unsafe\ncode', 'unsafe-code', '', null, 123]) {
    const preload = `import fs from 'node:fs/promises';
      import { syncBuiltinESMExports } from 'node:module';
      fs.lstat = async () => { throw Object.assign(new Error('sensitive-exception-message'), { code: ${JSON.stringify(code)} }); };
      syncBuiltinESMExports();`;
    await assert.rejects(
      execute(process.execPath, [
        '--import',
        `data:text/javascript,${encodeURIComponent(preload)}`,
        helper,
        f.path,
      ]),
      {
        code: 1,
        stdout: '',
        stderr: 'Socket preparation failed (socket_preparation_failed).\n',
      },
    );
  }
});

test('vault socket preparation accepts a fresh private volume', async (t) => {
  const f = await fixture(t);
  await prepareBwSocket(f.path);
  await assert.rejects(lstat(f.path), { code: 'ENOENT' });
});

test('vault socket preparation removes only a confirmed stale Unix socket', async (t) => {
  const f = await fixture(t);
  await execute(process.execPath, [
    '--input-type=module',
    '-e',
    "import { createServer } from 'node:net'; createServer().listen(process.argv[1], () => process.exit(0));",
    f.path,
  ]);
  assert((await lstat(f.path)).isSocket());
  await prepareBwSocket(f.path);
  await assert.rejects(lstat(f.path), { code: 'ENOENT' });
});

test('vault socket preparation refuses a live listener without removing it', async (t) => {
  const f = await fixture(t);
  const server = createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen(f.path, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(prepareBwSocket(f.path), {
    message: 'vault_socket_live',
  });
  assert((await lstat(f.path)).isSocket());
});

test('vault socket preparation refuses regular files and symlinks', async (t) => {
  const f = await fixture(t);
  const file = join(f.dir, 'data');
  await writeFile(file, 'preserve this file', { mode: 0o600 });
  await assert.rejects(prepareBwSocket(file), {
    message: 'vault_socket_not_socket',
  });
  await symlink(file, f.path);
  await assert.rejects(prepareBwSocket(f.path), {
    message: 'vault_socket_not_socket',
  });
  assert.equal(await readFile(file, 'utf8'), 'preserve this file');
  assert((await lstat(f.path)).isSymbolicLink());
});

for (const mode of [0o750, 0o755]) {
  test(`vault socket preparation refuses a non-private ${mode.toString(8)} parent`, async (t) => {
    const f = await fixture(t);
    await chmod(f.dir, mode);
    await assert.rejects(prepareBwSocket(f.path), {
      message: 'vault_socket_directory_unsafe',
    });
  });
}
