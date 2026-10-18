import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { loadConfig } from '../src/config.js';
import { startWeb } from '../src/web.js';
import { encryptValue } from '../public/crypto.js';
import { fixture, post } from '../support/fixtures.js';

const hmacKey = Buffer.alloc(32, 1).toString('base64');

test('HSTS configuration defaults to one year and validates nonnegative whole seconds or off', () => {
  const config = (value) =>
    loadConfig({
      INTAKE_HMAC_KEY: hmacKey,
      ...(value === undefined ? {} : { INTAKE_HSTS_MAX_AGE: value }),
    });
  assert.equal(config().hstsMaxAge, 31536000);
  assert.equal(config('86400').hstsMaxAge, 86400);
  assert.equal(config('0').hstsMaxAge, 0);
  assert.equal(config('off').hstsMaxAge, 0);
  assert.equal(config('9007199254740991').hstsMaxAge, Number.MAX_SAFE_INTEGER);
  for (const value of [
    '',
    '-1',
    '1.5',
    '1e3',
    'Infinity',
    'NaN',
    '9007199254740992',
    'OFF',
    'true',
    ' 60 ',
    '60\r\n',
  ])
    assert.throws(() => config(value), { code: 'invalid_intake_hsts_max_age' });
});

test('HSTS subdomain coverage defaults on and accepts only boolean values', () => {
  assert.equal(
    loadConfig({ INTAKE_HMAC_KEY: hmacKey }).hstsIncludeSubDomains,
    true,
  );
  for (const [value, expected] of [
    ['true', true],
    ['1', true],
    ['false', false],
    ['0', false],
  ]) {
    assert.equal(
      loadConfig({
        INTAKE_HMAC_KEY: hmacKey,
        INTAKE_HSTS_INCLUDE_SUBDOMAINS: value,
      }).hstsIncludeSubDomains,
      expected,
    );
  }
  for (const value of ['', 'off', 'TRUE', 'yes', ' true ', '2']) {
    assert.throws(
      () =>
        loadConfig({
          INTAKE_HMAC_KEY: hmacKey,
          INTAKE_HSTS_INCLUDE_SUBDOMAINS: value,
        }),
      { code: 'invalid_intake_hsts_include_subdomains' },
    );
  }
});

async function webFixture(t, setting, includeSubDomains) {
  const f = await fixture(t, { ticketLimit: 1 });
  const loaded = loadConfig({
    INTAKE_HMAC_KEY: f.config.hmacKey.toString('base64'),
    ...(setting === undefined ? {} : { INTAKE_HSTS_MAX_AGE: setting }),
    ...(includeSubDomains === undefined
      ? {}
      : { INTAKE_HSTS_INCLUDE_SUBDOMAINS: includeSubDomains }),
  });
  const web = await startWeb({
    store: f.store,
    config: {
      ...f.config,
      hstsMaxAge: loaded.hstsMaxAge,
      hstsIncludeSubDomains: loaded.hstsIncludeSubDomains,
    },
    logger: f.logger,
  });
  t.after(() => web.close());
  return { ...f, web, base: `http://127.0.0.1:${web.server.address().port}` };
}

async function rawResponse(f, request) {
  return new Promise((resolve, reject) => {
    const socket = connect(f.web.server.address().port, '127.0.0.1');
    let data = '';
    socket.setEncoding('utf8');
    socket.on('error', reject);
    socket.on('data', (chunk) => {
      data += chunk;
    });
    socket.on('end', () => resolve(data));
    socket.on('connect', () => socket.write(request));
  });
}

for (const [setting, includeSubDomains, expected] of [
  [undefined, undefined, 'max-age=31536000; includeSubDomains'],
  ['86400', undefined, 'max-age=86400; includeSubDomains'],
  ['60', 'true', 'max-age=60; includeSubDomains'],
  ['60', '1', 'max-age=60; includeSubDomains'],
  ['86400', 'false', 'max-age=86400'],
  [undefined, '0', 'max-age=31536000'],
  ['0', 'true', null],
  ['off', 'false', null],
]) {
  test(`HSTS ${setting ?? 'default'} with subdomains ${includeSubDomains ?? 'default'} applies to static, API, errors and parser responses`, async (t) => {
    const f = await webFixture(t, setting, includeSubDomains);
    const first = f.create();
    const [id, secret] = first.token.split('.');
    const wrongToken = `${id}.${secret[0] === 'A' ? 'B' : 'A'}${secret.slice(1)}`;
    const second = f.create();
    const envelope = await encryptValue(
      second.ticket,
      'hsts-private-test-value',
    );
    const requests = [
      [() => fetch(f.base + '/'), 200],
      [() => fetch(f.base + '/styles.css'), 200],
      [() => fetch(f.base + '/app.js', { method: 'HEAD' }), 200],
      [() => post(f.base, '/api/open', { token: first.token }), 200],
      [() => post(f.base, '/api/open', { token: wrongToken }), 400],
      [() => post(f.base, '/api/open', { token: first.token }), 429],
      [
        () => post(f.base, '/api/submit', { token: second.token, envelope }),
        202,
      ],
      [() => post(f.base, '/api/open', { token: 'invalid' }), 400],
      [
        () => post(f.base, '/api/open', {}, { Origin: 'https://example.com' }),
        403,
      ],
      [() => fetch(f.base + '/api/open', { method: 'POST', body: '{}' }), 415],
      [() => fetch(f.base + '/missing'), 404],
    ];
    for (const [send, status] of requests) {
      const response = await send();
      assert.equal(response.status, status);
      assert.equal(response.headers.get('Strict-Transport-Security'), expected);
      assert.equal(response.headers.get('Cache-Control'), 'no-store');
      await response.text();
    }
    t.mock.method(f.store, 'open', () => {
      throw new Error('private-error');
    });
    const failed = await post(f.base, '/api/open', {});
    assert.equal(failed.status, 500);
    assert.equal(failed.headers.get('Strict-Transport-Security'), expected);
    await failed.text();
    for (const [request, status] of [
      ['INVALID HTTP REQUEST\r\n\r\n', '400 Bad Request'],
      [
        'GET / HTTP/1.1\r\nHost: intake.example.com\r\nExpect: unsupported\r\nConnection: close\r\n\r\n',
        '417 Expectation Failed',
      ],
    ]) {
      const raw = await rawResponse(f, request);
      assert(raw.startsWith(`HTTP/1.1 ${status}\r\n`));
      const values = [
        ...raw.matchAll(/^Strict-Transport-Security:\s*([^\r\n]*)/gim),
      ].map((match) => match[1]);
      assert.deepEqual(values, expected === null ? [] : [expected]);
    }
  });
}

test('HSTS overrides do not mutate defaults for another web instance', async (t) => {
  const disabled = await webFixture(t, 'off');
  const normal = await webFixture(t);
  const custom = await webFixture(t, '60');
  const hostOnly = await webFixture(t, undefined, 'false');
  for (const [f, expected] of [
    [disabled, null],
    [normal, 'max-age=31536000; includeSubDomains'],
    [custom, 'max-age=60; includeSubDomains'],
    [hostOnly, 'max-age=31536000'],
  ]) {
    const response = await fetch(f.base + '/');
    assert.equal(response.headers.get('Strict-Transport-Security'), expected);
    await response.text();
  }
});
