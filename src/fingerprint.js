import { createHmac } from 'node:crypto';

export function ticketFingerprint(key, ticketId, value) {
  return createHmac('sha256', key)
    .update(JSON.stringify([ticketId, value]), 'utf8')
    .digest('hex')
    .slice(0, 16);
}
