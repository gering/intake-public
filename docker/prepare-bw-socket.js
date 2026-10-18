import { lstat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createConnection } from 'node:net';

function socketError(code) {
  return Object.assign(new Error(code), { code });
}

export async function prepareBwSocket(path) {
  const directory = await lstat(dirname(path));
  if (
    !directory.isDirectory() ||
    directory.uid !== process.getuid() ||
    directory.mode & 0o077
  )
    throw socketError('vault_socket_directory_unsafe');
  await removeStaleSocket(path);
}

export async function prepareWriterSocket(path) {
  const directory = await lstat(dirname(path));
  if (
    !directory.isDirectory() ||
    directory.uid !== process.getuid() ||
    directory.gid !== process.getgid() ||
    (directory.mode & 0o7777) !== 0o770
  )
    throw socketError('writer_socket_directory_unsafe');
  await removeStaleSocket(path);
}

async function removeStaleSocket(path) {
  let previous;
  try {
    previous = await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  if (!previous.isSocket()) throw socketError('vault_socket_not_socket');
  await new Promise((resolve, reject) => {
    const socket = createConnection(path);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(socketError('vault_socket_probe_timeout'));
    }, 1000);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      reject(socketError('vault_socket_live'));
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      socket.destroy();
      if (error.code === 'ECONNREFUSED') resolve();
      else reject(error);
    });
  });
  const current = await lstat(path);
  if (current.dev !== previous.dev || current.ino !== previous.ino)
    throw socketError('vault_socket_changed');
  // Only a confirmed stale socket in a checked, single-writer volume.
  await unlink(path);
}

if (import.meta.main) {
  try {
    const role = process.argv[3] ?? 'bw';
    if (role === 'writer') await prepareWriterSocket(process.argv[2]);
    else if (role === 'bw')
      await prepareBwSocket(process.argv[2] ?? '/run/intake-bw/bw.sock');
    else throw socketError('invalid_socket_role');
  } catch (error) {
    const code =
      typeof error?.code === 'string' && /^[A-Za-z0-9_]+$/.test(error.code)
        ? error.code
        : 'socket_preparation_failed';
    process.stderr.write(`Socket preparation failed (${code}).\n`);
    process.exitCode = 1;
  }
}
