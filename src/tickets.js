import { createToken } from './tokens.js';
import { createTicketKeys } from './crypto.js';
import { ticketInput } from './validation.js';
import { metadataDigest } from './metadata.js';

export function createTicket({ store, keys, config, input }) {
  const validated = ticketInput(
    input,
    config.defaultNotifyEmail,
    config.maxTtl,
  );
  const metadata = { ...validated, metaDigest: metadataDigest(validated) };
  const token = createToken(config.hmacKey);
  const pair = createTicketKeys(config.masterKey, token.id);
  const now = Date.now();
  let inserted = false;
  try {
    // Creation and pruning share the public write lock, always before private writes.
    const ticket = store.db
      .transaction(() => {
        keys.put(token.id, pair.privateKey, {
          ...metadata,
          expiresAt: now + validated.ttl,
        });
        inserted = true;
        return store.create(
          {
            ...metadata,
            id: token.id,
            digest: token.digest,
            publicKey: pair.publicKey,
          },
          now,
        );
      })
      .immediate();
    return {
      ticket: { ...ticket, ...metadata },
      link: `${config.publicUrl}/#req=${token.token}`,
    };
  } catch (error) {
    if (inserted) keys.remove(token.id);
    throw error;
  }
}
