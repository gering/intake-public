import { createHash } from 'node:crypto';

export function metadataDigest({ target, notifyEmail }) {
  return createHash('sha256')
    .update(
      JSON.stringify([
        { item: target.item, field: target.field, notes: target.notes },
        notifyEmail,
      ]),
      'utf8',
    )
    .digest('hex');
}
