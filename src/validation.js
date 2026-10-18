import { IntakeError } from './errors.js';

export function parseDuration(input) {
  const match = typeof input === 'string' && /^(\d+)(m|h|d)$/.exec(input);
  if (!match) throw new IntakeError('invalid_ttl');
  const milliseconds =
    Number(match[1]) * { m: 60000, h: 3600000, d: 86400000 }[match[2]];
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0)
    throw new IntakeError('invalid_ttl');
  return milliseconds;
}

export function ticketTtl(input = '24h', max = parseDuration('7d')) {
  const ttl = parseDuration(input);
  if (ttl > max) throw new IntakeError('ttl_exceeds_maximum');
  return ttl;
}

export function emailAddress(value) {
  if (
    typeof value !== 'string' ||
    value.length > 254 ||
    !/^[A-Za-z0-9.!#$%&'*+\-/=?^_`{|}~]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$/.test(
      value,
    )
  ) {
    throw new IntakeError('single_notify_email_required');
  }
  const [local, domain] = value.split('@');
  if (
    local.length > 64 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    domain.includes('..') ||
    domain
      .split('.')
      .some(
        (label) =>
          label.length > 63 || label.startsWith('-') || label.endsWith('-'),
      )
  )
    throw new IntakeError('single_notify_email_required');
  return value;
}

export function text(value, name, max = 1000) {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > max ||
    /\p{Cc}/u.test(value)
  )
    throw new IntakeError(`invalid_${name}`);
  return value;
}

export function ticketInput(input, defaultNotifyEmail, maxTtl) {
  if (
    input.keepWhitespace !== undefined &&
    typeof input.keepWhitespace !== 'boolean'
  )
    throw new IntakeError('invalid_keep_whitespace');
  return {
    trim: !input.keepWhitespace,
    keyName: text(input.keyName, 'key_name', 128),
    purpose: text(input.purpose, 'purpose'),
    target: {
      item: text(input.targetItem, 'target_item', 256),
      field: text(input.targetField, 'target_field', 128),
      notes:
        input.targetNotes === undefined
          ? ''
          : text(input.targetNotes, 'target_notes', 4000),
    },
    notifyEmail: emailAddress(input.notifyEmail ?? defaultNotifyEmail),
    ttl: ticketTtl(input.ttl, maxTtl),
  };
}
