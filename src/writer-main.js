import { assertNonRoot, IntakeError } from './errors.js';
import { loadConfig } from './config.js';
import { TicketStore, PrivateKeyStore } from './db.js';
import { startWriter } from './writer.js';
import { BwServeAdapter, checkVaultAccess } from './vault.js';
import { MailNotifier } from './mail.js';
import { createLogger } from './logger.js';

const logger = createLogger();
let store;
let keys;
try {
  assertNonRoot();
  process.umask(0o007);
  const config = loadConfig(process.env, 'writer');
  const adapter = new BwServeAdapter(config.vault);
  checkVaultAccess(config.vault, logger);
  store = new TicketStore(config.dbPath, config.hmacKey);
  keys = new PrivateKeyStore(config.privateDbPath);
  const writer = await startWriter({
    store,
    keys,
    masterKey: config.masterKey,
    fingerprintKey: config.fingerprintKey,
    adapter,
    notifier: config.notifyOff ? undefined : new MailNotifier(config.mail),
    notifyOff: config.notifyOff,
    socketPath: config.socketPath,
    pollMs: config.pollMs,
    shutdownWaitMs: config.shutdownWaitMs,
    retryBaseMs: config.vaultRetryBaseMs,
    retryMaxMs: config.vaultRetryMaxMs,
    unknownSettleMs: config.unknownSettleMs,
    stuckAttempts: config.stuckAttempts,
    logger,
  });
  let stopping = false;
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, async () => {
      if (stopping) return;
      stopping = true;
      await writer.close();
      keys.close();
      store.close();
    });
} catch (error) {
  keys?.close();
  store?.close();
  logger.info('writer_start_failed', {
    code: error instanceof IntakeError ? error.code : 'startup_failed',
  });
  process.exitCode = 1;
}
