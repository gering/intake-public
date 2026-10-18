#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { loadConfig } from './config.js';
import { TicketStore, PrivateKeyStore } from './db.js';
import { createTicket } from './tickets.js';
import { writerRequest } from './ipc.js';
import { IntakeError, assertNonRoot } from './errors.js';
import { escapeTerminal } from './terminal.js';

const help = `Usage:
  intake create --key-name NAME --purpose TEXT --target-item NAME --target-field NAME
    [--target-notes TEXT] [--ttl 24h] [--notify-email ops@example.com] [--keep-whitespace]
  intake list
  intake show <id>
  intake revoke <id>
  intake purge [--older-than-days 30]
  intake notify-retry <id>

Creation prints a one-time link exactly once. Preserve it privately; it cannot be recovered.
Every ticket requires a notification address (or INTAKE_DEFAULT_NOTIFY_EMAIL).
Values are trimmed in the browser by default; --keep-whitespace preserves them exactly.
`;

export async function runCli(
  args,
  { env = process.env, stdout = process.stdout, stderr = process.stderr } = {},
) {
  let store;
  let keys;
  try {
    assertNonRoot();
    if (args.length === 0 || args[0] === '--help' || args[0] === 'help') {
      stdout.write(help);
      return 0;
    }
    const [command, ...rest] = args;
    const options = {
      create: [
        'key-name',
        'purpose',
        'target-item',
        'target-field',
        'target-notes',
        'ttl',
        'notify-email',
        'keep-whitespace',
      ],
      list: [],
      show: [],
      revoke: [],
      purge: ['older-than-days'],
      'notify-retry': [],
    }[command];
    if (!options) throw new IntakeError('unknown_command');
    const { values, positionals } = parseArgs({
      args: rest,
      options: Object.fromEntries(
        options.map((name) => [
          name,
          { type: name === 'keep-whitespace' ? 'boolean' : 'string' },
        ]),
      ),
      allowPositionals: true,
      strict: true,
    });
    if (
      positionals.length !==
      (['show', 'revoke', 'notify-retry'].includes(command) ? 1 : 0)
    )
      throw new IntakeError('invalid_arguments');
    if (positionals[0] && !/^[\w-]{22}$/.test(positionals[0]))
      throw new IntakeError('invalid_ticket_id');
    const config = loadConfig(
      env,
      ['create', 'purge'].includes(command) ? 'cli' : 'web',
    );
    if (command === 'notify-retry') {
      await writerRequest(
        config.socketPath,
        '/notify-retry',
        positionals[0],
        config.ipcTimeoutMs,
      );
      stdout.write(
        'Notification retry queued. Check intake list for the result.\n',
      );
      return 0;
    }
    store = new TicketStore(config.dbPath, config.hmacKey);
    if (command === 'create') {
      keys = new PrivateKeyStore(config.privateDbPath);
      const input = Object.fromEntries(
        Object.entries(values).map(([key, value]) => [
          key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()),
          value,
        ]),
      );
      const { link } = createTicket({ store, keys, config, input });
      stdout.write(`${link}\n`);
    } else if (command === 'list' || command === 'show') {
      const tickets =
        command === 'show' ? [store.show(positionals[0])] : store.list();
      if (tickets.includes(null)) throw new IntakeError('ticket_unavailable');
      stdout.write(
        'ID\tKEY NAME\tSTATUS\tEXPIRY\tNOTIFY STATUS\tFINGERPRINT\tATTEMPTS\tFAILURE CODE\n',
      );
      for (const ticket of tickets)
        stdout.write(
          [
            ticket.id,
            ticket.keyName,
            ticket.status,
            ticket.expiresAt,
            ticket.notifyStatus ?? '-',
            ticket.fingerprint ?? '-',
            ticket.attempts,
            ticket.failureCode ?? '-',
          ]
            .map(escapeTerminal)
            .join('\t') + '\n',
        );
    } else if (command === 'revoke') {
      store.revoke(positionals[0]);
      try {
        await writerRequest(
          config.socketPath,
          '/revoke',
          positionals[0],
          config.ipcTimeoutMs,
        );
      } catch {
        stdout.write(
          'Ticket revoked. Writer unreachable; the private key is removed at the next writer prune.\n',
        );
        return 0;
      }
      stdout.write('Ticket revoked. Private key removed.\n');
    } else {
      const retention = values['older-than-days'] ?? '30';
      if (!/^\d+$/.test(retention))
        throw new IntakeError('invalid_retention_days');
      const days = Number(retention);
      keys = new PrivateKeyStore(config.privateDbPath);
      const ids = store.purge(days);
      for (const id of ids) keys.remove(id);
      keys.prune(store);
      stdout.write(`Purged ${ids.length} tickets.\n`);
    }
    return 0;
  } catch (error) {
    // Parser, filesystem and dependency messages may echo arguments or user data.
    const code =
      error instanceof IntakeError
        ? error.code
        : error.code?.startsWith('ERR_PARSE_ARGS_')
          ? 'invalid_arguments'
          : 'command_failed';
    stderr.write(`intake: ${code}\n`);
    return 1;
  } finally {
    keys?.close();
    store?.close();
  }
}

if (import.meta.main) {
  process.umask(0o007);
  process.exitCode = await runCli(process.argv.slice(2));
}
