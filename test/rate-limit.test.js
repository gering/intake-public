import test from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../src/rate-limit.js';
import { loadConfig } from '../src/config.js';

const env = { INTAKE_HMAC_KEY: Buffer.alloc(32, 1).toString('base64') };

for (const maxEntries of [0, 1, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
  test(`rate-limit capacity ${maxEntries} is rejected by config and direct construction`, () => {
    assert.throws(() => new RateLimiter({ maxEntries }), {
      code: 'invalid_intake_rate_max_entries',
    });
    assert.throws(
      () => loadConfig({ ...env, INTAKE_RATE_MAX_ENTRIES: String(maxEntries) }),
      { code: 'invalid_intake_rate_max_entries' },
    );
  });
}

test('IPv6 /48 allowance defaults to four times the client allowance', () => {
  assert.equal(loadConfig(env).ipv6Limit48, 120);
  assert.equal(
    loadConfig({ ...env, INTAKE_RATE_IP_LIMIT: '7' }).ipv6Limit48,
    28,
  );
  assert.equal(
    loadConfig({
      ...env,
      INTAKE_RATE_IP_LIMIT: '7',
      INTAKE_RATE_IPV6_48_LIMIT: '12',
    }).ipv6Limit48,
    12,
  );
  assert.equal(new RateLimiter({ ipLimit: 7 }).ipv6Limit48, 28);
  assert.throws(
    () =>
      loadConfig({
        ...env,
        INTAKE_RATE_IP_LIMIT: String(Number.MAX_SAFE_INTEGER),
      }),
    { code: 'invalid_intake_rate_ipv6_48_limit' },
  );
});

for (const value of [
  '',
  '0',
  '-1',
  '1.5',
  'no',
  String(Number.MAX_SAFE_INTEGER + 1),
]) {
  test(`IPv6 /48 allowance ${JSON.stringify(value)} must be a positive safe integer`, () => {
    assert.throws(
      () => loadConfig({ ...env, INTAKE_RATE_IPV6_48_LIMIT: value }),
      { code: 'invalid_intake_rate_ipv6_48_limit' },
    );
    assert.throws(() => new RateLimiter({ ipv6Limit48: Number(value) }), {
      code: 'invalid_intake_rate_ipv6_48_limit',
    });
  });
}

test('two-entry capacity keeps client and ticket counts in separate maps', () => {
  const limiter = new RateLimiter({
    maxEntries: 2,
    ipLimit: 2,
    ticketLimit: 1,
  });
  assert(limiter.allowClient('192.0.2.1', 0));
  assert(limiter.allowTicketFailure('same-ticket', 0));
  assert(limiter.allowClient('192.0.2.1', 0));
  assert(!limiter.allowTicketFailure('same-ticket', 0));
  assert(!limiter.allowClient('192.0.2.1', 0));
  assert.equal(limiter.clientBuckets.get('ip:192.0.2.1').count, 3);
  assert.equal(limiter.ticketBuckets.get('same-ticket').count, 2);
});

for (const kind of ['client', 'ticket']) {
  function setup(options = {}) {
    const limiter = new RateLimiter({
      maxEntries: 2,
      ipLimit: 1,
      ticketLimit: 1,
      windowMs: 100,
      ...options,
    });
    return {
      limiter,
      allow: (id, now) =>
        kind === 'client'
          ? limiter.allowClient(`192.0.2.${id}`, now)
          : limiter.allowTicketFailure(`ticket-${id}`, now),
      buckets:
        kind === 'client' ? limiter.clientBuckets : limiter.ticketBuckets,
      key: (id) => (kind === 'client' ? `ip:192.0.2.${id}` : `ticket-${id}`),
    };
  }

  test(`a full ${kind} map evicts the least recently used bucket`, () => {
    const { allow, buckets, key } = setup({ ipLimit: 10, ticketLimit: 10 });
    assert(allow(1, 0));
    assert(allow(2, 1));
    assert(allow(1, 2));
    assert(allow(3, 3));
    assert.deepEqual([...buckets.keys()], [key(1), key(3)]);
    assert.equal(buckets.size, 2);
  });

  test(`expired ${kind} entries are evicted before an unexpired LRU bucket`, () => {
    const { allow, buckets, key } = setup({ ipLimit: 10, ticketLimit: 10 });
    assert(allow(1, 0));
    assert(allow(2, 40));
    assert(allow(1, 50));
    assert(allow(3, 100));
    assert.deepEqual([...buckets.keys()], [key(2), key(3)]);
    assert.equal(buckets.get(key(2)).count, 1);
  });

  test(`denied ${kind} requests touch LRU order without extending the window`, () => {
    const { allow, buckets, key } = setup();
    assert(allow(1, 0));
    assert(allow(2, 1));
    assert(!allow(1, 2));
    assert(allow(3, 3));
    assert(buckets.has(key(1)));
    assert(!buckets.has(key(2)));
    assert.equal(buckets.get(key(1)).expires, 100);
    assert(allow(1, 100));
  });
}

test('IPv6 clients share normalized /64 and /48 buckets', () => {
  const limiter = new RateLimiter({ ipLimit: 1 });
  assert(limiter.allowClient('2001:db8:abcd:12::1', 0));
  assert(!limiter.allowClient('2001:0DB8:ABCD:0012:ffff:0000:0000:0002', 1));
  assert(limiter.allowClient('2001:db8:abcd:13::1', 2));
  assert.equal(limiter.clientBuckets.size, 3);
  assert(limiter.clientBuckets.has('ip:2001:0db8:abcd:0012/64'));
  assert(limiter.clientBuckets.has('ip:2001:0db8:abcd:0013/64'));
  assert.equal(limiter.clientBuckets.get('ip:2001:0db8:abcd/48').count, 3);
});

test('IPv6 /48 limits apply across different /64 clients and expire on time', () => {
  const limiter = new RateLimiter({
    ipLimit: 10,
    ipv6Limit48: 2,
    windowMs: 100,
  });
  assert(limiter.allowClient('2001:db8:abcd:1::1', 0));
  assert(limiter.allowClient('2001:db8:abcd:2::1', 1));
  assert(!limiter.allowClient('2001:db8:abcd:3::1', 2));
  assert(limiter.allowClient('2001:db8:abce:1::1', 3));
  assert.equal(limiter.clientBuckets.get('ip:2001:0db8:abcd:0003/64').count, 1);
  assert.equal(limiter.clientBuckets.get('ip:2001:0db8:abcd/48').count, 3);
  assert(limiter.allowClient('2001:db8:abcd:4::1', 100));
});

test('requests rejected by /64 still consume the IPv6 /48 allowance', () => {
  const limiter = new RateLimiter({ ipLimit: 1, ipv6Limit48: 2 });
  assert(limiter.allowClient('2001:db8:abcd:1::1', 0));
  assert(!limiter.allowClient('2001:db8:abcd:1::2', 1));
  assert(!limiter.allowClient('2001:db8:abcd:2::1', 2));
  assert.equal(limiter.clientBuckets.get('ip:2001:0db8:abcd/48').count, 3);
});

test('IPv4-mapped IPv6 shares the IPv4 bucket in dotted and hex forms without a /48 bucket', () => {
  for (const mapped of [
    '::ffff:192.0.2.10',
    '::FFFF:c000:020a',
    '0000:0000:0000:0000:0000:ffff:c000:20a',
  ]) {
    const limiter = new RateLimiter({ ipLimit: 1, ipv6Limit48: 1 });
    assert(limiter.allowClient(mapped, 0));
    assert(!limiter.allowClient('192.0.2.10', 1));
    assert(limiter.allowClient('192.0.2.11', 2));
    assert.deepEqual(
      [...limiter.clientBuckets.keys()],
      ['ip:192.0.2.10', 'ip:192.0.2.11'],
    );
  }
});

test('IPv6 compression, embedded IPv4 and scope identifiers do not split buckets', () => {
  for (const addresses of [
    ['2001:db8::1', '2001:0db8:0:0:0:0:0:2'],
    ['2001:db8::1%eth0', '2001:DB8:0:0::2%eth1'],
    ['2001:db8::192.0.2.1', '2001:db8:0:0:ffff::1'],
  ]) {
    const limiter = new RateLimiter({ ipLimit: 1 });
    assert(limiter.allowClient(addresses[0], 0));
    assert(!limiter.allowClient(addresses[1], 1));
    assert.equal(limiter.clientBuckets.size, 2);
  }
});

test('client churn cannot evict an exhausted ticket bucket', () => {
  const limiter = new RateLimiter({ ticketLimit: 2, maxEntries: 100 });
  assert(limiter.allowTicketFailure('ticket', 0));
  assert(limiter.allowTicketFailure('ticket', 1));
  assert(limiter.ticketBlocked('ticket', 2));
  for (let i = 0; i < 150; i++) {
    limiter.allowClient(`2001:db8:abcd:${i.toString(16)}::1`, 3 + i);
  }
  assert.equal(limiter.clientBuckets.size, 100);
  assert.equal(limiter.ticketBuckets.size, 1);
  assert(limiter.ticketBlocked('ticket', 200));
  assert(!limiter.allowTicketFailure('ticket', 201));
});

test('ticket checks do not charge or create buckets and keep the fixed expiry', () => {
  const limiter = new RateLimiter({
    ticketLimit: 2,
    windowMs: 100,
    maxEntries: 2,
  });
  assert(!limiter.ticketBlocked('missing', 0));
  assert.equal(limiter.ticketBuckets.size, 0);
  assert(limiter.allowTicketFailure('ticket-1', 0));
  assert(limiter.allowTicketFailure('ticket-2', 1));
  assert(!limiter.ticketBlocked('ticket-1', 2));
  assert.equal(limiter.ticketBuckets.get('ticket-1').count, 1);
  assert.equal(limiter.ticketBuckets.get('ticket-1').expires, 100);
  assert(limiter.allowTicketFailure('ticket-3', 3));
  assert(!limiter.ticketBuckets.has('ticket-2'));
  assert(limiter.allowTicketFailure('ticket-1', 4));
  assert(limiter.ticketBlocked('ticket-1', 99));
  assert(!limiter.ticketBlocked('ticket-1', 100));
  assert(limiter.allowTicketFailure('ticket-1', 100));
});
