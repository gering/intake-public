import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseDocument } from 'yaml';
import { loadConfig } from '../src/config.js';
import { fixture } from '../support/fixtures.js';

async function writerEnv(t) {
  const f = await fixture(t);
  return {
    INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
    INTAKE_WRITER_KEY: f.config.masterKey.toString('base64'),
    INTAKE_FINGERPRINT_KEY_FILE: f.config.fingerprintKeyFile,
    INTAKE_NOTIFY: 'off',
    BW_ORGANIZATION_ID: 'organization',
    BW_COLLECTION_ID: 'collection',
  };
}

test('writer retry configuration defaults to 5 seconds through 5 minutes and accepts bounded overrides', async (t) => {
  const env = await writerEnv(t);
  const defaults = loadConfig(env, 'writer');
  assert.equal(defaults.vaultRetryBaseMs, 5000);
  assert.equal(defaults.vaultRetryMaxMs, 300000);
  assert.equal(defaults.unknownSettleMs, 120000);
  const custom = loadConfig(
    {
      ...env,
      INTAKE_VAULT_RETRY_BASE_MS: '20',
      INTAKE_VAULT_RETRY_MAX_MS: '80',
      INTAKE_UNKNOWN_SETTLE_MS: '150000',
    },
    'writer',
  );
  assert.equal(custom.vaultRetryBaseMs, 20);
  assert.equal(custom.vaultRetryMaxMs, 80);
  assert.equal(custom.unknownSettleMs, 150000);
});

test('writer retry configuration rejects invalid timers and inverted bounds', async (t) => {
  const env = await writerEnv(t);
  for (const name of [
    'INTAKE_VAULT_RETRY_BASE_MS',
    'INTAKE_VAULT_RETRY_MAX_MS',
    'INTAKE_UNKNOWN_SETTLE_MS',
  ]) {
    for (const value of ['0', '-1', '1.5', 'NaN', '2147483648']) {
      assert.throws(() => loadConfig({ ...env, [name]: value }, 'writer'), {
        code: `invalid_${name.toLowerCase()}`,
      });
    }
  }
  assert.throws(
    () =>
      loadConfig(
        {
          ...env,
          INTAKE_VAULT_RETRY_BASE_MS: '100',
          INTAKE_VAULT_RETRY_MAX_MS: '99',
        },
        'writer',
      ),
    { code: 'invalid_vault_retry' },
  );
});

test('shutdown wait configuration is writer-only and defaults to 5000 with bounded overrides including zero', async (t) => {
  const env = await writerEnv(t);
  assert.equal(loadConfig(env, 'writer').shutdownWaitMs, 5000);
  for (const value of ['0', '100', '2147483647'])
    assert.equal(
      loadConfig({ ...env, INTAKE_SHUTDOWN_WAIT_MS: value }, 'writer')
        .shutdownWaitMs,
      Number(value),
    );
  for (const value of [
    '-1',
    '1.5',
    'invalid',
    'NaN',
    'Infinity',
    '2147483648',
    '9007199254740992',
  ])
    assert.throws(
      () => loadConfig({ ...env, INTAKE_SHUTDOWN_WAIT_MS: value }, 'writer'),
      { code: 'invalid_intake_shutdown_wait_ms' },
    );
  for (const role of ['web', 'cli'])
    assert.equal(
      loadConfig({ ...env, INTAKE_SHUTDOWN_WAIT_MS: 'invalid' }, role)
        .shutdownWaitMs,
      undefined,
    );
});

test('stuck-attempt configuration is writer-only and defaults to 10 within 1 through 31', async (t) => {
  const env = await writerEnv(t);
  assert.equal(loadConfig(env, 'writer').stuckAttempts, 10);
  for (const value of ['1', '10', '31'])
    assert.equal(
      loadConfig({ ...env, INTAKE_STUCK_ATTEMPTS: value }, 'writer')
        .stuckAttempts,
      Number(value),
    );
  for (const value of [
    '',
    '0',
    '-1',
    '1.5',
    'NaN',
    'Infinity',
    '32',
    '9007199254740992',
  ])
    assert.throws(
      () => loadConfig({ ...env, INTAKE_STUCK_ATTEMPTS: value }, 'writer'),
      { code: 'invalid_intake_stuck_attempts' },
    );
  for (const role of ['web', 'cli'])
    assert.equal(
      loadConfig({ ...env, INTAKE_STUCK_ATTEMPTS: 'invalid' }, role)
        .stuckAttempts,
      undefined,
    );
});

test('Compose exposes retry timers and the stuck threshold only to writer without build inputs', async () => {
  const source = await readFile(
    new URL('../docker-compose.yml', import.meta.url),
    'utf8',
  );
  const stack = parseDocument(source).toJS();
  for (const [name, fallback] of [
    ['INTAKE_VAULT_RETRY_BASE_MS', 5000],
    ['INTAKE_VAULT_RETRY_MAX_MS', 300000],
    ['INTAKE_STUCK_ATTEMPTS', 10],
    ['INTAKE_UNKNOWN_SETTLE_MS', 120000],
  ]) {
    assert.equal(
      stack.services.writer.environment[name],
      `\${${name}:-${fallback}}`,
    );
    assert.equal(stack.services.web.environment[name], undefined);
    assert.equal(stack.services.bw.environment[name], undefined);
  }
});
