import { assertNonRoot, IntakeError } from './errors.js';
import { loadConfig } from './config.js';
import { TicketStore } from './db.js';
import { startWeb } from './web.js';
import { createLogger } from './logger.js';

const logger = createLogger();
let store;
try {
  assertNonRoot();
  process.umask(0o007);
  const config = loadConfig();
  store = new TicketStore(config.dbPath, config.hmacKey);
  const web = await startWeb({ store, config, logger });
  let stopping = false;
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, async () => {
      if (stopping) return;
      stopping = true;
      await web.close();
      store.close();
    });
} catch (error) {
  store?.close();
  logger.info('web_start_failed', {
    code: error instanceof IntakeError ? error.code : 'startup_failed',
  });
  process.exitCode = 1;
}
