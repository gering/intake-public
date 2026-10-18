import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { TicketStore, PrivateKeyStore } from '../src/db.js';
import { createTicket } from '../src/tickets.js';
import { createLogger } from '../src/logger.js';

export async function fixture(t, overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'intake-'));
  await mkdir(join(dir, 'private'), { mode: 0o700 });
  const config = {
    dbPath: join(dir, 'tickets.sqlite'),
    privateDbPath: join(dir, 'private/keys.sqlite'),
    socketPath: join(dir, 'writer.sock'),
    hmacKey: randomBytes(32),
    masterKey: randomBytes(32),
    fingerprintKey: randomBytes(32),
    fingerprintKeyFile: join(dir, 'private/fingerprint.key'),
    publicUrl: 'https://intake.example.com',
    defaultNotifyEmail: 'ops@example.com',
    maxTtl: 7 * 86400000,
    port: 0,
    bodyLimit: 100000,
    ipLimit: 1000,
    ticketLimit: 1000,
    rateWindowMs: 60000,
    rateMaxEntries: 10000,
    ipcTimeoutMs: 1000,
    ...overrides,
  };
  await writeFile(
    config.fingerprintKeyFile,
    config.fingerprintKey.toString('base64'),
    {
      mode: 0o600,
    },
  );
  const store = new TicketStore(config.dbPath, config.hmacKey);
  const keys = new PrivateKeyStore(config.privateDbPath);
  const logs = [];
  const logger = createLogger({ write: (line) => logs.push(line) });
  t.after(async () => {
    keys.close();
    store.close();
    await rm(dir, { recursive: true, force: true });
  });
  function create(input = {}) {
    const result = createTicket({
      store,
      keys,
      config,
      input: {
        keyName: 'DB_PASSWORD',
        purpose: 'Connect the application to its database',
        targetItem: 'Application database',
        targetField: 'password',
        ...input,
      },
    });
    return { ...result, token: new URL(result.link).hash.slice(5) };
  }
  return { dir, config, store, keys, logs, logger, create };
}

export async function waitFor(fn, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = fn();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('condition_timeout');
}

export function post(baseUrl, path, body, headers = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}
