import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:net';
import { chmod, lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  prepareBwSocket,
  prepareWriterSocket,
} from '../docker/prepare-bw-socket.js';

const execute = promisify(execFile);

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'intake-writer-socket-'));
  await chmod(dir, 0o770);
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, path: join(dir, 'writer.sock') };
}

test('writer socket preparation accepts only its owned shared directory without relaxing the vault check', async (t) => {
  const f = await fixture(t);
  await prepareWriterSocket(f.path);
  await assert.rejects(prepareBwSocket(f.path), {
    message: 'vault_socket_directory_unsafe',
  });
  for (const name of ['getuid', 'getgid']) {
    const current = process[name]();
    const mock = t.mock.method(process, name, () => current + 1);
    await assert.rejects(prepareWriterSocket(f.path), {
      message: 'writer_socket_directory_unsafe',
    });
    mock.mock.restore();
  }
});

test('writer socket preparation recovers an uncleanly stopped listener before rebinding', async (t) => {
  const f = await fixture(t);
  await execute(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import { createServer } from 'node:net'; createServer().listen(process.argv[1], () => process.exit(0));",
      f.path,
    ],
    { env: {} },
  );
  assert((await lstat(f.path)).isSocket());
  await prepareWriterSocket(f.path);
  const server = createServer();
  await new Promise((resolve) => server.listen(f.path, resolve));
  await new Promise((resolve) => server.close(resolve));
});

test('writer socket preparation preserves a live listener and regular files', async (t) => {
  const f = await fixture(t);
  const server = createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen(f.path, resolve));
  try {
    await assert.rejects(prepareWriterSocket(f.path), {
      message: 'vault_socket_live',
    });
    assert((await lstat(f.path)).isSocket());
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  await writeFile(f.path, 'not a socket');
  await assert.rejects(prepareWriterSocket(f.path), {
    message: 'vault_socket_not_socket',
  });
  assert((await lstat(f.path)).isFile());
});

for (const mode of [0o700, 0o755, 0o777]) {
  test(`writer socket preparation refuses unexpected ${mode.toString(8)} directory permissions`, async (t) => {
    const f = await fixture(t);
    await chmod(f.dir, mode);
    await assert.rejects(prepareWriterSocket(f.path), {
      message: 'writer_socket_directory_unsafe',
    });
  });
}

test('non-root writer entrypoint launches its command only after socket preparation succeeds', async (t) => {
  const f = await fixture(t);
  await writeFile(
    join(f.dir, 'node'),
    `#!/bin/sh
set -eu
[ "$1" = /opt/intake/docker/prepare-bw-socket.js ]
exec "$REAL_NODE" "$SOCKET_HELPER" "$2" "$3"
`,
    { mode: 0o700 },
  );
  const env = {
    PATH: `${f.dir}:${process.env.PATH}`,
    REAL_NODE: process.execPath,
    SOCKET_HELPER: new URL('../docker/prepare-bw-socket.js', import.meta.url)
      .pathname,
    INTAKE_SOCKET: f.path,
  };
  const args = [
    new URL('../docker/writer-entrypoint.sh', import.meta.url).pathname,
    '/bin/sh',
    '-c',
    'printf "%s\\n" launched',
  ];
  assert.equal((await execute('/bin/sh', args, { env })).stdout, 'launched\n');
  await writeFile(f.path, 'not a socket');
  await assert.rejects(execute('/bin/sh', args, { env }), {
    code: 1,
    stdout: '',
    stderr: 'Socket preparation failed (vault_socket_not_socket).\n',
  });
});
