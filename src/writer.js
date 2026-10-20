import { createServer } from 'node:http';
import { ticketFingerprint } from './fingerprint.js';
import { chmod } from 'node:fs/promises';
import { assertNonRoot, IntakeError } from './errors.js';
import { decryptValue } from './crypto.js';
import { aadBytes } from '../public/crypto.js';
import { metadataDigest } from './metadata.js';
import { isDatabaseLockError } from './db-open.js';
import { VaultError } from './vault.js';
import { createLogger } from './logger.js';
import { json, readJson, listen, closeServer } from './http.js';

function isSqliteError(error) {
  return (
    error?.name === 'SqliteError' ||
    (typeof error?.code === 'string' && error.code.startsWith('SQLITE_'))
  );
}

export async function startWriter({
  store,
  keys,
  masterKey,
  fingerprintKey,
  adapter,
  notifier,
  notifyOff = false,
  socketPath,
  pollMs = 1000,
  shutdownWaitMs = 5000,
  expiryGraceMs = 900000,
  pruneIntervalMs = 60000,
  retryBaseMs = 5000,
  retryMaxMs = 300000,
  unknownSettleMs = 120000,
  stuckAttempts = 10,
  now = Date.now,
  logger = createLogger(),
  socketPermissions = chmod,
}) {
  assertNonRoot();
  if (!Buffer.isBuffer(fingerprintKey) || fingerprintKey.length !== 32)
    throw new IntakeError('invalid_intake_fingerprint_key');
  if (!notifyOff && !notifier)
    throw new IntakeError('mail_configuration_required');
  if (
    !Number.isSafeInteger(retryBaseMs) ||
    retryBaseMs <= 0 ||
    !Number.isSafeInteger(retryMaxMs) ||
    retryMaxMs < retryBaseMs ||
    retryMaxMs > 2147483647
  )
    throw new IntakeError('invalid_vault_retry');
  if (
    !Number.isSafeInteger(unknownSettleMs) ||
    unknownSettleMs <= 0 ||
    unknownSettleMs > 2147483647
  )
    throw new IntakeError('invalid_intake_unknown_settle_ms');
  if (
    !Number.isSafeInteger(stuckAttempts) ||
    stuckAttempts <= 0 ||
    stuckAttempts > 31
  )
    throw new IntakeError('invalid_intake_stuck_attempts');
  for (const [value, code, minimum] of [
    [expiryGraceMs, 'invalid_intake_expiry_grace_ms', 0],
    [shutdownWaitMs, 'invalid_intake_shutdown_wait_ms', 0],
    [pruneIntervalMs, 'invalid_intake_prune_interval_ms', 1],
  ]) {
    if (!Number.isSafeInteger(value) || value < minimum || value > 2147483647)
      throw new IntakeError(code);
  }
  let lastPrune;
  let running = false;
  let current = Promise.resolve();
  let stopped = false;
  let ready = false;
  let recoveryNeeded = false;
  let vaultNotReady = false;
  let notification;
  let notificationAbandoned = false;
  const notificationAbort = new AbortController();

  function warnStuck(transition) {
    if (
      transition &&
      transition.previousAttempts < stuckAttempts &&
      transition.attempts === stuckAttempts
    ) {
      const { id, status, attempts, code } = transition;
      logger.info('ticket_stuck', { id, status, attempts, code });
    }
  }

  function retry(id, code) {
    warnStuck(
      store.retry(id, code, {
        baseMs: retryBaseMs,
        maxMs: retryMaxMs,
        now: now(),
      }),
    );
    logger.info('ticket_requeued', { id, code });
  }

  function unknown(id, code, settle = false) {
    warnStuck(
      store.retry(id, code, {
        baseMs: retryBaseMs,
        maxMs: retryMaxMs,
        now: now(),
        unknown: true,
        settleMs: settle ? unknownSettleMs : 0,
      }),
    );
    logger.info(
      ['vault_marker_ambiguous', 'vault_lookup_too_large'].includes(code)
        ? code
        : 'ticket_unknown',
      { id, code, status: 'unknown' },
    );
  }

  function recover(code) {
    const transitions = store.recoverInterrupted(code, {
      baseMs: retryBaseMs,
      maxMs: retryMaxMs,
      settleMs: unknownSettleMs,
      now: now(),
    });
    for (const transition of transitions) warnStuck(transition);
  }

  async function processTicket(id, vaultReady) {
    const resolving = store.isUnknown(id);
    if (store.begin(id, now())) {
      let vaultAccepted = false;
      let lookupInProgress = false;
      let lookupCompleted = false;
      let writeStarted = false;
      let decrypting = false;
      try {
        const snapshot = keys.getMetadata(id);
        if (!snapshot) throw new IntakeError('ticket_metadata_mismatch');
        if (snapshot.revoked) throw new IntakeError('ticket_revoked');
        // Latch before vault readiness checks so retries survive expiry during an outage.
        const seen = keys.markSeen(id, now());
        if (
          snapshot.expiresAt !== null &&
          seen > snapshot.expiresAt + expiryGraceMs
        )
          throw new IntakeError('ticket_expired');
        if (!resolving && adapter.isReady && !(await vaultReady())) {
          retry(id, 'vault_unavailable');
          return;
        }
        const submitted = store.get(id);
        if (snapshot.metaDigest === null || submitted.metaDigest === null)
          throw new IntakeError('ticket_upgrade_required');
        // Only the writer-private snapshot determines decryption AAD.
        const ticket = { ...snapshot, metaDigest: metadataDigest(snapshot) };
        if (
          snapshot.metaDigest !== ticket.metaDigest ||
          submitted.metaDigest !== ticket.metaDigest ||
          !Buffer.from(aadBytes(ticket)).equals(aadBytes(submitted))
        )
          throw new IntakeError('ticket_metadata_mismatch');
        const encryptedPrivateKey = keys.get(id);
        // Node crypto reports bad keys/envelopes as generic Error; these are definite.
        decrypting = true;
        const decrypted = decryptValue(
          masterKey,
          ticket,
          encryptedPrivateKey,
          submitted.envelope,
        );
        decrypting = false;
        const fingerprint = ticketFingerprint(
          fingerprintKey,
          ticket.id,
          decrypted.value,
        );
        const input = {
          target: ticket.target,
          keyName: ticket.keyName,
          purpose: ticket.purpose,
          value: decrypted.value,
          ticketId: ticket.id,
          fingerprint,
        };
        let found = null;
        if (resolving) {
          lookupInProgress = true;
          found = await adapter.lookup(input);
          lookupInProgress = false;
          lookupCompleted = true;
        }
        if (!found) {
          writeStarted = true;
          await adapter.write(input);
        }
        vaultAccepted = true;
        if (!store.finish(id, fingerprint))
          throw new IntakeError('completion_commit_failed');
        logger.info('ticket_done', { id, status: 'done' });
      } catch (error) {
        if (
          vaultAccepted ||
          lookupInProgress ||
          (error instanceof VaultError && error.ambiguous)
        ) {
          unknown(
            id,
            error instanceof VaultError ? error.code : 'writer_state_failed',
            vaultAccepted || !lookupInProgress,
          );
        } else if (
          (error instanceof VaultError && error.preDelivery) ||
          isDatabaseLockError(error)
        ) {
          const code = isDatabaseLockError(error)
            ? 'database_busy'
            : error.code;
          if (resolving) unknown(id, code);
          else retry(id, code);
          if (code === 'database_busy') return true;
        } else if (
          !(error instanceof IntakeError) &&
          !decrypting &&
          (resolving ? !lookupCompleted : !writeStarted)
        ) {
          // Keep material when local state fails before lookup or vault delivery.
          if (resolving) unknown(id, 'writer_state_failed');
          else retry(id, 'writer_state_failed');
          if (isSqliteError(error)) return true;
        } else {
          const code =
            error instanceof IntakeError &&
            [
              'invalid_payload',
              'ticket_upgrade_required',
              'ticket_revoked',
              'ticket_expired',
            ].includes(error.code)
              ? error.code
              : 'writer_failed';
          store.fail(id, code);
          logger.info('ticket_failed', { id, code });
        }
      }
    }
    const ticket = store.getState(id);
    if (ticket && ['done', 'failed'].includes(ticket.status)) keys.delete(id);
    if (
      ticket &&
      ['done', 'failed'].includes(ticket.status) &&
      ticket.notifyStatus === 'pending'
    )
      sendNotification(ticket);
  }

  function sendNotification(ticket) {
    if (notification || stopped) return;
    // SQLite holds the backlog; only one delivery is in flight, separate from vault work.
    const delivery = { id: ticket.id };
    notification = delivery;
    delivery.promise = (async () => {
      let recorded = false;
      const { id } = ticket;
      try {
        const metadata = keys.getMetadata(id);
        const result = !metadata
          ? {
              status: 'failed',
              attempts: 0,
              error: 'private_metadata_missing',
              notifiedAt: null,
            }
          : notifyOff
            ? {
                status: 'failed',
                attempts: 0,
                error: 'disabled',
                notifiedAt: null,
              }
            : await notifier.send(
                { ...ticket, ...metadata },
                { signal: notificationAbort.signal },
              );
        // Only the shutdown deadline abandons a result, even if cancellation is ignored.
        if (notificationAbandoned) return;
        store.recordNotification(id, result);
        recorded = true;
        logger.info('notification_result', {
          id,
          notifyStatus: result.status,
          attempts: result.attempts,
          code: result.error ?? 'ok',
        });
      } catch {
        // Keep pending after a send/commit error for recovery on a later poll or restart.
        if (!notificationAbandoned)
          logger.info('writer_loop_error', { code: 'internal_error' });
      } finally {
        notification = undefined;
        if (recorded && !stopped) queueMicrotask(drainNotifications);
      }
    })();
  }

  function drainNotifications() {
    if (notification || stopped) return;
    try {
      const id = store.nextNotification();
      if (!id) return;
      const ticket = store.getState(id);
      if (
        ticket &&
        ['done', 'failed'].includes(ticket.status) &&
        ticket.notifyStatus === 'pending'
      ) {
        keys.delete(id);
        sendNotification(ticket);
      }
    } catch {
      logger.info('writer_loop_error', { code: 'internal_error' });
    }
  }

  function drain() {
    drainNotifications();
    if (running || stopped) return current;
    running = true;
    current = (async () => {
      try {
        if (recoveryNeeded) {
          recover('writer_state_failed');
          recoveryNeeded = false;
        }
        const time = now();
        if (time - lastPrune >= pruneIntervalMs) {
          keys.prune(store, time, expiryGraceMs);
          lastPrune = time;
        }
        let vaultUnavailable = false;
        async function vaultReady() {
          if (!vaultUnavailable) {
            try {
              vaultUnavailable = !(await adapter.isReady());
            } catch {
              vaultUnavailable = true;
            }
            if (vaultUnavailable !== vaultNotReady) {
              vaultNotReady = vaultUnavailable;
              logger.info(
                vaultUnavailable ? 'vault_unavailable' : 'vault_available',
              );
            }
          }
          return !vaultUnavailable;
        }
        for (const id of store.work(now())) {
          if (stopped) break;
          // Do not repeat a local SQLite failure for every due ticket.
          if (await processTicket(id, vaultReady)) break;
        }
      } catch {
        recoveryNeeded = true;
        logger.info('writer_loop_error', { code: 'internal_error' });
      } finally {
        running = false;
      }
    })();
    return current;
  }

  const server = createServer(
    { requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 4096 },
    async (req, res) => {
      try {
        if (!ready || stopped) throw new IntakeError('writer_starting', 503);
        if (req.method === 'GET' && req.url === '/healthz') {
          res.writeHead(204);
          res.end();
          return;
        }
        if (
          req.method !== 'POST' ||
          !['/process', '/notify-retry', '/revoke'].includes(req.url)
        )
          throw new IntakeError('not_found', 404);
        const { id } = await readJson(req, 1024);
        if (typeof id !== 'string' || !/^[\w-]{22}$/.test(id))
          throw new IntakeError('invalid_ticket_id');
        if (req.url === '/revoke') {
          store.db
            .transaction(() => {
              if (store.getState(id)?.status !== 'revoked')
                throw new IntakeError('ticket_not_revoked', 409);
              keys.markRevoked(id);
            })
            .immediate();
          json(res, 202, { status: 'revoked' });
          return;
        }
        if (req.url === '/notify-retry') store.retryNotification(id);
        void drain();
        json(res, 202, { status: 'queued' });
      } catch (error) {
        const known = error instanceof IntakeError;
        json(res, known ? error.status : 500, {
          error: known ? error.code : 'internal_error',
        });
      }
    },
  );
  // Do not unlink an existing socket: it may belong to a live writer.
  await listen(server, socketPath);
  try {
    await socketPermissions(socketPath, 0o660);
    recover();
    lastPrune = now();
    keys.prune(store, lastPrune, expiryGraceMs);
    ready = true;
  } catch (error) {
    await closeServer(server);
    throw error;
  }
  const timer = setInterval(() => void drain(), pollMs);
  timer.unref();
  void drain();
  logger.info('writer_started');
  return {
    server,
    drain,
    async close() {
      stopped = true;
      clearInterval(timer);
      const serverClosed = closeServer(server);
      const delivery = notification;
      if (delivery) {
        let timeout;
        try {
          if (shutdownWaitMs > 0)
            await Promise.race([
              delivery.promise,
              new Promise((resolve) => {
                timeout = setTimeout(resolve, shutdownWaitMs);
              }),
            ]);
          if (notification === delivery) {
            notificationAbandoned = true;
            notificationAbort.abort();
            logger.info('shutdown_notification_pending', {
              id: delivery.id,
              waitedMs: shutdownWaitMs,
            });
          }
        } finally {
          clearTimeout(timeout);
        }
      }
      await serverClosed;
      await current;
    },
  };
}
