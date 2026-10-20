import { readFileSync, statSync } from 'node:fs';
import { validateHeaderName } from 'node:http';
import { isUnixSocketPath } from './socket-path.js';
import { IntakeError } from './errors.js';
import { parseDuration, emailAddress } from './validation.js';

function positive(env, name, fallback) {
  const value = env[name] === undefined ? fallback : Number(env[name]);
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    (name.endsWith('_MS') && value > 2147483647)
  )
    throw new IntakeError(`invalid_${name.toLowerCase()}`);
  return value;
}

function hstsMaxAge(env) {
  const value = env.INTAKE_HSTS_MAX_AGE ?? '31536000';
  if (value === 'off') return 0;
  const seconds = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(seconds))
    throw new IntakeError('invalid_intake_hsts_max_age');
  return seconds;
}

function boolean(env, name, fallback = false) {
  if (env[name] === undefined) return fallback;
  if (!['true', 'false', '1', '0'].includes(env[name]))
    throw new IntakeError(`invalid_${name.toLowerCase()}`);
  return ['true', '1'].includes(env[name]);
}

function clientIpHeader(env) {
  const name = env.INTAKE_CLIENT_IP_HEADER;
  if (name === undefined || name.trim().toLowerCase() === 'off')
    return undefined;
  try {
    validateHeaderName(name);
  } catch {
    throw new IntakeError('invalid_intake_client_ip_header');
  }
  return name.toLowerCase();
}

export function readSecret(
  env,
  name,
  { writerOnly = false, key = false, fileOnly = false } = {},
) {
  if (fileOnly && !env[`${name}_FILE`])
    throw new IntakeError(`missing_${name.toLowerCase()}_file`);
  let value;
  if (env[`${name}_FILE`]) {
    const path = env[`${name}_FILE`];
    const stat = statSync(path);
    if (
      !stat.isFile() ||
      (writerOnly
        ? stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600
        : stat.mode & 0o007)
    )
      throw new IntakeError(`unsafe_${name.toLowerCase()}_file`);
    value = readFileSync(path, 'utf8').trim();
  } else value = env[name];
  if (!value || /[\r\n]/.test(value))
    throw new IntakeError(`missing_${name.toLowerCase()}`);
  if (!key) return value;
  if (
    !/^[A-Za-z0-9+/]{43}=$/.test(value) ||
    Buffer.from(value, 'base64').length !== 32
  )
    throw new IntakeError(`invalid_${name.toLowerCase()}`);
  return Buffer.from(value, 'base64');
}

export function loadConfig(env = process.env, role = 'web') {
  const ipLimit = positive(env, 'INTAKE_RATE_IP_LIMIT', 30);
  const config = {
    dbPath: env.INTAKE_DB ?? '/var/lib/intake/public/tickets.sqlite',
    socketPath: env.INTAKE_SOCKET ?? '/run/intake/writer.sock',
    hmacKey: readSecret(env, 'INTAKE_HMAC_KEY', { key: true }),
    host: env.INTAKE_HOST ?? '127.0.0.1',
    port: positive(env, 'PORT', 3000),
    maxTtl: parseDuration(env.INTAKE_MAX_TTL ?? '7d'),
    defaultNotifyEmail: env.INTAKE_DEFAULT_NOTIFY_EMAIL
      ? emailAddress(env.INTAKE_DEFAULT_NOTIFY_EMAIL)
      : undefined,
    publicUrl: env.INTAKE_PUBLIC_URL ?? 'https://intake.example.com',
    trustProxy: boolean(env, 'TRUST_PROXY'),
    clientIpHeader: clientIpHeader(env),
    hstsMaxAge: hstsMaxAge(env),
    hstsIncludeSubDomains: boolean(env, 'INTAKE_HSTS_INCLUDE_SUBDOMAINS', true),
    bodyLimit: positive(env, 'INTAKE_BODY_LIMIT', 100000),
    rateWindowMs: positive(env, 'INTAKE_RATE_WINDOW_MS', 60000),
    ipLimit,
    ipv6Limit48: positive(env, 'INTAKE_RATE_IPV6_48_LIMIT', ipLimit * 4),
    ticketLimit: positive(env, 'INTAKE_RATE_TICKET_LIMIT', 10),
    rateMaxEntries: positive(env, 'INTAKE_RATE_MAX_ENTRIES', 10000),
    pollMs: positive(env, 'INTAKE_POLL_MS', 1000),
    ipcTimeoutMs: positive(env, 'INTAKE_IPC_TIMEOUT_MS', 45000),
  };
  if (!['127.0.0.1', '0.0.0.0'].includes(config.host))
    throw new IntakeError('invalid_intake_host');
  if (config.port > 65535) throw new IntakeError('invalid_port');
  if (config.rateMaxEntries < 2)
    throw new IntakeError('invalid_intake_rate_max_entries');
  const url = new URL(config.publicUrl);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  )
    throw new IntakeError('invalid_public_url');
  config.publicUrl = url.origin;
  if (role !== 'web') {
    config.privateDbPath =
      env.INTAKE_PRIVATE_DB ?? '/var/lib/intake/private/keys.sqlite';
    config.masterKey = readSecret(env, 'INTAKE_WRITER_KEY', {
      writerOnly: true,
      key: true,
    });
  }
  if (role === 'writer') {
    config.shutdownWaitMs =
      env.INTAKE_SHUTDOWN_WAIT_MS === undefined
        ? 5000
        : Number(env.INTAKE_SHUTDOWN_WAIT_MS);
    if (
      !Number.isSafeInteger(config.shutdownWaitMs) ||
      config.shutdownWaitMs < 0 ||
      config.shutdownWaitMs > 2147483647
    )
      throw new IntakeError('invalid_intake_shutdown_wait_ms');
    config.unknownSettleMs = positive(env, 'INTAKE_UNKNOWN_SETTLE_MS', 120000);
    config.vaultRetryBaseMs = positive(env, 'INTAKE_VAULT_RETRY_BASE_MS', 5000);
    config.vaultRetryMaxMs = positive(env, 'INTAKE_VAULT_RETRY_MAX_MS', 300000);
    config.stuckAttempts = positive(env, 'INTAKE_STUCK_ATTEMPTS', 10);
    if (config.stuckAttempts > 31)
      throw new IntakeError('invalid_intake_stuck_attempts');
    if (config.vaultRetryMaxMs < config.vaultRetryBaseMs)
      throw new IntakeError('invalid_vault_retry');
    config.fingerprintKey = readSecret(env, 'INTAKE_FINGERPRINT_KEY', {
      writerOnly: true,
      key: true,
      fileOnly: true,
    });
    if (
      env.INTAKE_NOTIFY !== undefined &&
      !['on', 'off'].includes(env.INTAKE_NOTIFY)
    )
      throw new IntakeError('invalid_intake_notify');
    config.notifyOff = env.INTAKE_NOTIFY === 'off';
    if (!config.notifyOff) {
      if (!env.MAIL_API_URL) throw new IntakeError('missing_mail_api_url');
      const mailUrl = new URL(env.MAIL_API_URL);
      if (
        !['https:', 'http:'].includes(mailUrl.protocol) ||
        mailUrl.username ||
        mailUrl.password ||
        mailUrl.search ||
        mailUrl.hash
      )
        throw new IntakeError('invalid_mail_api_url');
      if (
        mailUrl.protocol === 'http:' &&
        !['127.0.0.1', '[::1]', 'localhost'].includes(mailUrl.hostname)
      )
        throw new IntakeError('mail_api_requires_https');
      config.mail = {
        url: mailUrl.href.replace(/\/$/, ''),
        token: readSecret(env, 'MAIL_API_TOKEN', { writerOnly: true }),
        mailbox: emailAddress(env.MAIL_API_MAILBOX),
        timeoutMs: positive(env, 'MAIL_API_TIMEOUT_MS', 10000),
        backoffMs: [
          positive(env, 'MAIL_API_RETRY_DELAY_1_MS', 1000),
          positive(env, 'MAIL_API_RETRY_DELAY_2_MS', 3000),
        ],
      };
    }
    if (!env.BW_ORGANIZATION_ID || !env.BW_COLLECTION_ID)
      throw new IntakeError('missing_vault_configuration');
    if (env.INTAKE_BW_SOCKET !== undefined && env.INTAKE_BW_URL !== undefined)
      throw new IntakeError('conflicting_vault_configuration');
    const socketPath =
      env.INTAKE_BW_URL === undefined
        ? (env.INTAKE_BW_SOCKET ?? '/run/intake-bw/bw.sock')
        : undefined;
    if (socketPath !== undefined && !isUnixSocketPath(socketPath))
      throw new IntakeError('invalid_intake_bw_socket');
    config.vault = {
      socketPath,
      baseUrl: env.INTAKE_BW_URL,
      organizationId: env.BW_ORGANIZATION_ID,
      collectionId: env.BW_COLLECTION_ID,
      sync: boolean(env, 'BW_SYNC_BEFORE_WRITE', true),
      timeoutMs: positive(env, 'BW_TIMEOUT_MS', 10000),
      maxResponseBytes: positive(env, 'BW_MAX_RESPONSE_BYTES', 1048576),
    };
  }
  return config;
}
