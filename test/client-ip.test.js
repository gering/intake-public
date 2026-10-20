import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { loadConfig } from '../src/config.js';
import { startWeb } from '../src/web.js';
import { fixture, post } from '../support/fixtures.js';

const hmacKey = Buffer.alloc(32, 1).toString('base64');
const header = 'cf-connecting-ip';

async function webFixture(t, env = {}) {
  const f = await fixture(t);
  const config = {
    ...loadConfig({
      INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
      INTAKE_RATE_IP_LIMIT: '1',
      ...env,
    }),
    port: 0,
    socketPath: f.config.socketPath,
  };
  const web = await startWeb({ store: f.store, config, logger: f.logger });
  t.after(() => web.close());
  return { ...f, base: `http://127.0.0.1:${web.server.address().port}` };
}

function warnings(f) {
  return f.logs
    .map((line) => JSON.parse(line))
    .filter((record) => record.event === 'client_ip_header_warning');
}

test('client IP header configuration is optional, case-insensitive and validated safely', () => {
  assert.equal(
    loadConfig({ INTAKE_HMAC_KEY: hmacKey }).clientIpHeader,
    undefined,
  );
  for (const off of ['off', 'OFF', 'Off', ' off '])
    assert.equal(
      loadConfig({ INTAKE_HMAC_KEY: hmacKey, INTAKE_CLIENT_IP_HEADER: off })
        .clientIpHeader,
      undefined,
    );
  assert.equal(
    loadConfig({
      INTAKE_HMAC_KEY: hmacKey,
      INTAKE_CLIENT_IP_HEADER: 'CF-Connecting-IP',
    }).clientIpHeader,
    header,
  );
  for (const name of [
    '',
    ' ',
    '\t',
    ' \t ',
    'invalid header',
    'header:secret',
    'header\r\nsecret',
    ' header',
    'header ',
  ]) {
    assert.throws(
      () =>
        loadConfig({ INTAKE_HMAC_KEY: hmacKey, INTAKE_CLIENT_IP_HEADER: name }),
      {
        code: 'invalid_intake_client_ip_header',
        message: 'invalid_intake_client_ip_header',
      },
    );
  }
});

for (const trustProxy of ['false', 'true']) {
  test(`configured header supplies validated IPv4/IPv6 and wins over TRUST_PROXY=${trustProxy}`, async (t) => {
    const f = await webFixture(t, {
      INTAKE_CLIENT_IP_HEADER: 'CF-Connecting-IP',
      TRUST_PROXY: trustProxy,
    });
    for (const [ip, status] of [
      ['192.0.2.10', 400],
      ['2001:db8::10', 400],
      ['192.0.2.10', 429],
    ]) {
      const response = await post(
        f.base,
        '/api/open',
        {},
        {
          'CF-Connecting-IP': ip,
          'X-Forwarded-For': '198.51.100.1',
        },
      );
      assert.equal(response.status, status);
      await response.text();
    }
    assert.deepEqual(warnings(f), []);
  });
}

for (const setting of [undefined, 'off', 'OFF', 'Off']) {
  test(`spoofed proxy headers cannot bypass socket limits when switch is ${setting ?? 'unset'}`, async (t) => {
    const f = await webFixture(
      t,
      setting === undefined ? {} : { INTAKE_CLIENT_IP_HEADER: setting },
    );
    for (const [ip, status] of [
      ['192.0.2.10', 400],
      ['192.0.2.11', 429],
    ]) {
      const response = await post(
        f.base,
        '/api/open',
        {},
        {
          [header]: ip,
          'X-Forwarded-For': ip,
        },
      );
      assert.equal(response.status, status);
      await response.text();
    }
    assert.deepEqual(warnings(f), []);
  });
}

for (const value of [
  undefined,
  '',
  'sensitive-invalid-ip',
  '192.0.2.1, 192.0.2.2',
  '192.0.2.1:443',
  '999.0.0.1',
  '[2001:db8::1]',
]) {
  test(`configured ${value === undefined ? 'missing' : JSON.stringify(value)} header fails closed, never using socket or forwarded IP`, async (t) => {
    const f = await webFixture(t, {
      INTAKE_CLIENT_IP_HEADER: header,
      TRUST_PROXY: 'true',
    });
    const { ticket, token } = f.create();
    for (const path of ['/api/open', '/api/submit']) {
      const response = await post(
        f.base,
        path,
        { token },
        {
          ...(value === undefined ? {} : { [header]: value }),
          'X-Forwarded-For': '198.51.100.10',
        },
      );
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: 'request_rejected' });
      assert.equal(f.store.get(ticket.id).status, 'active');
      assert.equal(f.store.get(ticket.id).openedAt, null);
    }
    // Rejected requests never charge either a socket or ticket allowance.
    const valid = await post(
      f.base,
      '/api/open',
      { token },
      { [header]: '192.0.2.1' },
    );
    assert.equal(valid.status, 200);
    await valid.text();
    const records = warnings(f);
    assert.equal(records.length, 1);
    for (const record of records) {
      assert.equal(
        record.code,
        value === undefined
          ? 'missing_client_ip_header'
          : 'invalid_client_ip_header',
      );
      assert.deepEqual(Object.keys(record).sort(), ['code', 'event', 'time']);
    }
    assert(!f.logs.join('').includes('sensitive-invalid-ip'));
    assert(!f.logs.join('').includes('198.51.100.'));
    assert(!f.logs.join('').includes('192.0.2.'));
    assert(!f.logs.join('').includes('2001:db8'));
  });
}

test('repeated configured header fields are rejected even when both contain the same valid IP', async (t) => {
  const f = await webFixture(t, {
    INTAKE_CLIENT_IP_HEADER: header,
    TRUST_PROXY: 'true',
  });
  for (const path of ['/api/open', '/api/submit']) {
    const ip = '192.0.2.10';
    const response = await new Promise((resolve, reject) => {
      const req = request(
        `${f.base}${path}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            [header]: [ip, ip],
            'X-Forwarded-For': ip,
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res));
        },
      );
      req.on('error', reject);
      req.end('{}');
    });
    assert.equal(response.statusCode, 400);
  }
  assert.deepEqual(
    warnings(f).map(({ code }) => code),
    ['invalid_client_ip_header'],
  );
});

test('header warnings are throttled independently per safe code for one minute', async (t) => {
  const f = await webFixture(t, { INTAKE_CLIENT_IP_HEADER: header });
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  for (const time of [0, 1, 59999, 60000, 60001]) {
    now = time;
    for (const headers of [{}, { [header]: 'sensitive-invalid-ip' }]) {
      const response = await post(f.base, '/api/open', {}, headers);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: 'request_rejected' });
    }
  }
  assert.deepEqual(
    warnings(f).map(({ code }) => code),
    [
      'missing_client_ip_header',
      'invalid_client_ip_header',
      'missing_client_ip_header',
      'invalid_client_ip_header',
    ],
  );
  assert(!f.logs.join('').includes('sensitive-invalid-ip'));
});

test('health checks and static assets do not require the configured client IP header', async (t) => {
  const f = await webFixture(t, { INTAKE_CLIENT_IP_HEADER: header });
  for (const method of ['GET', 'HEAD']) {
    for (const [path, status] of [
      ['/healthz', 204],
      ['/', 200],
      ['/crypto.js', 200],
    ]) {
      const response = await fetch(`${f.base}${path}`, { method });
      assert.equal(response.status, status);
      await response.text();
    }
  }
  assert.deepEqual(warnings(f), []);
});

for (const setting of [undefined, 'off', 'OFF', 'Off']) {
  test(`with the client header ${setting ?? 'unset'} TRUST_PROXY selects only the last valid forwarded element`, async (t) => {
    const f = await webFixture(t, {
      TRUST_PROXY: 'true',
      ...(setting === undefined ? {} : { INTAKE_CLIENT_IP_HEADER: setting }),
    });
    for (const [forwarded, status] of [
      ['192.0.2.10, 198.51.100.10', 400],
      ['192.0.2.11, 198.51.100.10', 429],
      ['192.0.2.12, invalid-last', 400],
      ['192.0.2.13, invalid-last', 429],
    ]) {
      const response = await post(
        f.base,
        '/api/open',
        {},
        {
          'X-Forwarded-For': forwarded,
          [header]: '203.0.113.10',
        },
      );
      assert.equal(response.status, status);
      await response.text();
    }
    assert.deepEqual(warnings(f), []);
  });
}

for (const source of ['header', 'forwarded']) {
  test(`${source} client IP limits normalize IPv6 /64 and IPv4-mapped addresses`, async (t) => {
    const f = await webFixture(
      t,
      source === 'header'
        ? { INTAKE_CLIENT_IP_HEADER: header }
        : { TRUST_PROXY: 'true' },
    );
    for (const [ip, status] of [
      ['2001:db8:abcd:1::1', 400],
      ['2001:0DB8:ABCD:0001:ffff::2', 429],
      ['2001:db8:abcd:2::1', 400],
      ['::ffff:192.0.2.10', 400],
      ['192.0.2.10', 429],
      ['::ffff:c000:20a', 429],
      ['192.0.2.11', 400],
    ]) {
      const response = await post(
        f.base,
        '/api/open',
        {},
        {
          [source === 'header' ? header : 'X-Forwarded-For']: ip,
        },
      );
      assert.equal(response.status, status, ip);
      await response.text();
    }
  });
}

test('HTTP rate-limit capacity admits new clients instead of rejecting every new bucket', async (t) => {
  const f = await webFixture(t, {
    INTAKE_CLIENT_IP_HEADER: header,
    INTAKE_RATE_MAX_ENTRIES: '2',
  });
  for (const [ip, status] of [
    ['192.0.2.1', 400],
    ['192.0.2.2', 400],
    ['192.0.2.1', 429],
    ['192.0.2.3', 400],
    ['192.0.2.1', 429],
    ['192.0.2.2', 400],
  ]) {
    const response = await post(f.base, '/api/open', {}, { [header]: ip });
    assert.equal(response.status, status, ip);
    await response.text();
  }
});

test('minimum capacity retains limits for repeated opens by the same client and ticket', async (t) => {
  const f = await webFixture(t, {
    INTAKE_RATE_MAX_ENTRIES: '2',
    INTAKE_RATE_IP_LIMIT: '1',
    INTAKE_RATE_TICKET_LIMIT: '1',
  });
  const { token } = f.create();
  for (const status of [200, 429, 429, 429, 429]) {
    const response = await post(f.base, '/api/open', { token });
    assert.equal(response.status, status);
    await response.text();
  }
});

test('changing the configured IP does not bypass the ticket limit for wrong tokens', async (t) => {
  const f = await webFixture(t, {
    INTAKE_CLIENT_IP_HEADER: header,
    INTAKE_RATE_IP_LIMIT: '100',
    INTAKE_RATE_TICKET_LIMIT: '1',
  });
  const { token } = f.create();
  const [id, secret] = token.split('.');
  const wrongToken = `${id}.${secret[0] === 'A' ? 'B' : 'A'}${secret.slice(1)}`;
  const first = await post(
    f.base,
    '/api/open',
    { token: wrongToken },
    { [header]: '192.0.2.10' },
  );
  assert.equal(first.status, 400);
  await first.text();
  const second = await post(
    f.base,
    '/api/open',
    { token: wrongToken },
    { [header]: '192.0.2.11' },
  );
  assert.equal(second.status, 429);
  assert.deepEqual(await second.json(), { error: 'rate_limited' });
});
