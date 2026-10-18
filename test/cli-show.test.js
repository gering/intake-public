import test from 'node:test';
import assert from 'node:assert/strict';
import { runCli } from '../src/cli.js';
import { fixture } from '../support/fixtures.js';
import { encryptValue } from '../public/crypto.js';
import { TicketStore } from '../src/db.js';

const header =
  'ID\tKEY NAME\tSTATUS\tEXPIRY\tNOTIFY STATUS\tFINGERPRINT\tATTEMPTS\tFAILURE CODE\n';
const malicious =
  '\x1b[2J\x1b]52;c;c2VjcmV0\x07\r\n\t\x9b31m\u{2028}\u{2029}\u{200e}\u{200f}\u{202e}\u{2066}\u{2069}\\x1b';
const escaped = String.raw`\x1b[2J\x1b]52;c;c2VjcmV0\x07\x0d\x0a\x09\x9b31m\u{2028}\u{2029}\u{200e}\u{200f}\u{202e}\u{2066}\u{2069}\\x1b`;

async function show(f, args) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    env: {
      INTAKE_DB: f.config.dbPath,
      INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
      INTAKE_WRITER_KEY_FILE: '/unreadable/writer-key',
      INTAKE_FINGERPRINT_KEY_FILE: '/unreadable/fingerprint-key',
    },
    stdout: {
      write: (text) => {
        stdout += text;
      },
    },
    stderr: {
      write: (text) => {
        stderr += text;
      },
    },
  });
  return { code, stdout, stderr };
}

test('CLI show prints only one ticket summary without tokens, keys or queued ciphertext', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const other = f.create();
  f.store.claim(token, await encryptValue(ticket, 'secret-show-test-value'));
  const result = await show(f, ['show', '--', ticket.id]);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.split('\n').length, 3);
  assert(result.stdout.includes(`${ticket.id}\t${ticket.keyName}\tpending\t`));
  for (const forbidden of [
    token,
    token.split('.')[1],
    other.ticket.id,
    'secret-show-test-value',
    'wrappedKey',
    'ciphertext',
    'token_hmac',
  ])
    assert(!result.stdout.includes(forbidden));
});

test('CLI show uses the same expiry and fingerprint summary as list without parsing envelopes', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.store.db
    .prepare(
      'UPDATE tickets SET expires_at = ?, fingerprint = ?, envelope = ?, meta_digest = ?, public_key = ? WHERE id = ?',
    )
    .run(
      1,
      '0123456789abcdef',
      'malformed',
      'malformed',
      'malformed',
      ticket.id,
    );
  const result = await show(f, ['show', '--', ticket.id]);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, (await show(f, ['list'])).stdout);
  assert(result.stdout.includes('\texpired\t1970-01-01T00:00:00.001Z\t'));
  assert(result.stdout.includes('\t0123456789abcdef\t0\t-\n'));
});

test('CLI list and show display unknown without exposing retained ciphertext', async (t) => {
  const f = await fixture(t);
  const { ticket, token } = f.create();
  const envelope = await encryptValue(ticket, 'retained-cli-unknown-value');
  f.store.claim(token, envelope);
  f.store.begin(ticket.id);
  f.store.retry(ticket.id, 'vault_timeout', {
    unknown: true,
    settleMs: 120000,
  });
  const result = await show(f, ['show', '--', ticket.id]);
  assert.equal(result.code, 0);
  assert.equal(result.stdout, (await show(f, ['list'])).stdout);
  assert(result.stdout.includes(`${ticket.id}\t${ticket.keyName}\tunknown\t`));
  assert(
    result.stdout.startsWith(
      'ID\tKEY NAME\tSTATUS\tEXPIRY\tNOTIFY STATUS\tFINGERPRINT\tATTEMPTS\tFAILURE CODE\n',
    ),
  );
  assert(result.stdout.endsWith('\t-\t1\tvault_timeout\n'));
  for (const sensitive of [
    token,
    envelope.ciphertext,
    'retained-cli-unknown-value',
  ])
    assert(!result.stdout.includes(sensitive));
});

test('CLI list and show escape malicious stored fields without adding rows or columns', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  const other = f.create();
  f.store.db
    .prepare('UPDATE tickets SET created_at = 1 WHERE id = ?')
    .run(other.ticket.id);
  f.store.db
    .prepare(
      `UPDATE tickets SET key_name = ?, status = 'failed', expires_at = 1,
       notify_status = 'failed', fingerprint = ?, attempts = 31, failure_code = ?,
       created_at = 2 WHERE id = ?`,
    )
    .run(
      `key:${malicious}`,
      `fingerprint:${malicious}`,
      `failure:${malicious}`,
      ticket.id,
    );
  const expectedRow = [
    ticket.id,
    `key:${escaped}`,
    'failed',
    '1970-01-01T00:00:00.001Z',
    'failed',
    `fingerprint:${escaped}`,
    '31',
    `failure:${escaped}`,
  ].join('\t');
  for (const args of [['list'], ['show', '--', ticket.id]]) {
    const result = await show(f, args);
    assert.equal(result.code, 0);
    assert.equal(result.stderr, '');
    assert(result.stdout.startsWith(`${header}${expectedRow}\n`));
    const rows = result.stdout.trimEnd().split('\n');
    assert.equal(rows.length, args[0] === 'list' ? 3 : 2);
    for (const row of rows) assert.equal(row.split('\t').length, 8);
    if (args[0] === 'list') assert(rows[2].startsWith(`${other.ticket.id}\t`));
  }
});

test('CLI list escapes malicious stored ticket IDs', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  f.store.db
    .prepare('UPDATE tickets SET id = ? WHERE id = ?')
    .run(malicious, ticket.id);
  const result = await show(f, ['list']);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert(result.stdout.startsWith(`${header}${escaped}\t`));
  assert.equal(result.stdout.split('\n').length, 3);
  assert.equal(result.stdout.split('\n')[1].split('\t').length, 8);
});

test('CLI list and show escape every summary field, including ID and expiry, at the output boundary', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  const summary = Object.fromEntries(
    [
      'id',
      'keyName',
      'status',
      'expiresAt',
      'notifyStatus',
      'fingerprint',
      'attempts',
      'failureCode',
    ].map((name) => [name, malicious]),
  );
  t.mock.method(TicketStore.prototype, 'list', () => [summary]);
  t.mock.method(TicketStore.prototype, 'show', () => summary);
  const expected = `${header}${Array(8).fill(escaped).join('\t')}\n`;
  for (const args of [['list'], ['show', '--', ticket.id]])
    assert.deepEqual(await show(f, args), {
      code: 0,
      stdout: expected,
      stderr: '',
    });
});

test('CLI show rejects missing, extra and invalid IDs and reports unavailable tickets safely', async (t) => {
  const f = await fixture(t);
  const { ticket } = f.create();
  for (const args of [
    ['show'],
    ['show', '--', ticket.id, ticket.id],
    ['show', 'invalid'],
  ]) {
    const result = await show(f, args);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^intake: invalid_(arguments|ticket_id)\n$/);
  }
  assert.deepEqual(await show(f, ['show', 'A'.repeat(22)]), {
    code: 1,
    stdout: '',
    stderr: 'intake: ticket_unavailable\n',
  });
});
