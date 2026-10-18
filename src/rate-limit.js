import { isIP } from 'node:net';
import { IntakeError } from './errors.js';

function clientBuckets(ip) {
  if (isIP(ip) !== 6) return [ip];
  let address = ip.split('%')[0];
  // Expand an embedded IPv4 tail into two words before expanding IPv6 zeros.
  if (address.includes('.')) {
    const split = address.lastIndexOf(':');
    const bytes = address
      .slice(split + 1)
      .split('.')
      .map(Number);
    address = `${address.slice(0, split + 1)}${((bytes[0] << 8) | bytes[1]).toString(16)}:${((bytes[2] << 8) | bytes[3]).toString(16)}`;
  }
  const [head, tail] = address.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const words = (
    tail === undefined
      ? left
      : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
  ).map((word) => Number.parseInt(word, 16));
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff)
    return [
      `${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`,
    ];
  return [64, 48].map(
    (prefix) =>
      `${words
        .slice(0, prefix / 16)
        .map((word) => word.toString(16).padStart(4, '0'))
        .join(':')}/${prefix}`,
  );
}

function expire(buckets, now) {
  for (const [key, bucket] of buckets) {
    if (bucket.expires <= now) buckets.delete(key);
  }
}

export class RateLimiter {
  constructor({
    windowMs = 60000,
    ipLimit = 30,
    ipv6Limit48 = ipLimit * 4,
    ticketLimit = 10,
    maxEntries = 10000,
  } = {}) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 2)
      throw new IntakeError('invalid_intake_rate_max_entries');
    if (!Number.isSafeInteger(ipv6Limit48) || ipv6Limit48 <= 0)
      throw new IntakeError('invalid_intake_rate_ipv6_48_limit');
    this.windowMs = windowMs;
    this.ipLimit = ipLimit;
    this.ipv6Limit48 = ipv6Limit48;
    this.ticketLimit = ticketLimit;
    this.maxEntries = maxEntries;
    this.clientBuckets = new Map();
    this.ticketBuckets = new Map();
  }

  charge(buckets, key, limit, now) {
    let bucket = buckets.get(key);
    if (!bucket) {
      if (buckets.size >= this.maxEntries)
        buckets.delete(buckets.keys().next().value);
      bucket = { count: 0, expires: now + this.windowMs };
    }
    // Map insertion order tracks use, including requests over the limit.
    buckets.delete(key);
    buckets.set(key, bucket);
    bucket.count++;
    return bucket.count <= limit;
  }

  allowClient(ip, now = Date.now()) {
    expire(this.clientBuckets, now);
    let allowed = true;
    for (const [index, key] of clientBuckets(ip).entries()) {
      const limit = index === 0 ? this.ipLimit : this.ipv6Limit48;
      if (!this.charge(this.clientBuckets, `ip:${key}`, limit, now))
        allowed = false;
    }
    return allowed;
  }

  allowTicketFailure(id, now = Date.now()) {
    expire(this.ticketBuckets, now);
    return this.charge(this.ticketBuckets, id, this.ticketLimit, now);
  }

  ticketBlocked(id, now = Date.now()) {
    expire(this.ticketBuckets, now);
    const bucket = this.ticketBuckets.get(id);
    if (!bucket) return false;
    this.ticketBuckets.delete(id);
    this.ticketBuckets.set(id, bucket);
    return bucket.count >= this.ticketLimit;
  }
}
