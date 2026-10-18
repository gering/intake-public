import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseDocument } from 'yaml';

const source = await readFile(
  new URL('../docker-compose.yml', import.meta.url),
  'utf8',
);
const document = parseDocument(source);
assert.deepEqual(document.errors, []);
assert.deepEqual(document.warnings, []);
const stack = document.toJS();
const secretNames = [
  'token_hmac_key',
  'writer_master_key',
  'fingerprint_key',
  'mail_api_token',
  'bw_client_id',
  'bw_client_secret',
  'bw_master_password',
];
const roleSecrets = {
  web: ['token_hmac_key'],
  writer: [
    'token_hmac_key',
    'writer_master_key',
    'fingerprint_key',
    'mail_api_token',
  ],
  bw: ['bw_client_id', 'bw_client_secret', 'bw_master_password'],
};

function assertNoPorts(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert.notEqual(key, 'ports', 'No published ports anywhere in the stack');
    assertNoPorts(child);
  }
}

test('Compose parses and hardens all three non-root services without published ports', () => {
  assert.deepEqual(Object.keys(stack.services).sort(), ['bw', 'web', 'writer']);
  assertNoPorts(stack);
  for (const [role, service] of Object.entries(stack.services)) {
    assert.equal(service.read_only, true);
    assert.deepEqual(service.tmpfs, ['/tmp']);
    assert.deepEqual(service.cap_drop, ['ALL']);
    assert.deepEqual(service.security_opt, ['no-new-privileges:true']);
    assert.match(service.user, /^[1-9]\d*:[1-9]\d*$/);
    assert.equal(service.restart, 'unless-stopped');
    assert.equal(service.init, true);
    assert.equal(service.build.context, '.');
    assert.equal(service.build.target, role);
    assert.deepEqual(service.healthcheck.test, [
      'CMD',
      'node',
      'docker/healthcheck.js',
      role,
    ]);
    for (const key of [
      'privileged',
      'cap_add',
      'network_mode',
      'pid',
      'env_file',
      'devices',
    ])
      assert.equal(service[key], undefined);
  }
  assert.equal(stack.services.web.user, '10001:10001');
  assert.deepEqual(stack.services.web.group_add, ['10010']);
  assert.equal(stack.services.writer.user, '10002:10010');
  assert.equal(stack.services.bw.user, stack.services.writer.user);
});

test('Compose bounds each service process count and memory by role', () => {
  for (const [role, pids, memory] of [
    ['web', 64, '256m'],
    ['writer', 128, '512m'],
    ['bw', 256, '1g'],
  ]) {
    assert.equal(stack.services[role].pids_limit, pids);
    assert.equal(stack.services[role].mem_limit, memory);
  }
});

test('Compose isolates web networking and waits for unlocked vault and ready writer', () => {
  assert.deepEqual(stack.services.web.networks, ['tunnel']);
  for (const role of ['writer', 'bw'])
    assert.deepEqual(stack.services[role].networks, ['egress']);
  assert.equal(stack.networks.tunnel.external, true);
  assert.equal(
    stack.networks.tunnel.name,
    '${INTAKE_TUNNEL_NETWORK:-intake-tunnel}',
  );
  assert.deepEqual(stack.networks.egress, { driver: 'bridge' });
  assert.deepEqual(stack.services.web.expose, ['3000']);
  assert.equal(stack.services.web.environment.INTAKE_HOST, '0.0.0.0');
  assert.equal(
    stack.services.web.environment.INTAKE_CLIENT_IP_HEADER,
    '${INTAKE_CLIENT_IP_HEADER-cf-connecting-ip}',
  );
  assert.equal(stack.services.web.environment.TRUST_PROXY, 'false');
  assert.equal(
    stack.services.web.environment.INTAKE_HSTS_MAX_AGE,
    '${INTAKE_HSTS_MAX_AGE:-31536000}',
  );
  assert.equal(
    stack.services.web.environment.INTAKE_HSTS_INCLUDE_SUBDOMAINS,
    '${INTAKE_HSTS_INCLUDE_SUBDOMAINS:-true}',
  );
  assert.equal(
    stack.services.web.depends_on.writer.condition,
    'service_healthy',
  );
  assert.equal(
    stack.services.writer.depends_on.bw.condition,
    'service_healthy',
  );
});

test('Compose mounts only the intended databases and sockets into each role', () => {
  assert.deepEqual(Object.keys(stack.volumes).sort(), [
    'bw-data',
    'bw-sock',
    'intake-shared',
    'intake-sock',
    'intake-writer',
  ]);
  assert.deepEqual(stack.services.web.volumes, [
    'intake-sock:/run/intake:ro',
    'intake-shared:/var/lib/intake/public',
  ]);
  assert.deepEqual(stack.services.writer.volumes, [
    'intake-sock:/run/intake',
    'intake-shared:/var/lib/intake/public',
    'intake-writer:/var/lib/intake/private',
    'bw-sock:/run/intake-bw:ro',
  ]);
  assert.deepEqual(stack.services.bw.volumes, [
    'bw-sock:/run/intake-bw',
    'bw-data:/var/lib/intake/bw',
  ]);
});

test('Compose provisions all credentials from scoped file secrets, never raw environment values', () => {
  assert.deepEqual(Object.keys(stack.secrets).sort(), [...secretNames].sort());
  for (const secret of Object.values(stack.secrets)) {
    assert.deepEqual(Object.keys(secret), ['file']);
    assert.match(secret.file, /^\$\{[A-Z_]+:-\.\/secrets\/[a-z_]+\}$/);
  }
  for (const [role, service] of Object.entries(stack.services)) {
    assert.deepEqual(service.secrets, roleSecrets[role]);
    const files = Object.entries(service.environment).filter(([key]) =>
      key.endsWith('_FILE'),
    );
    assert.equal(files.length, service.secrets.length);
    for (const [, path] of files)
      assert(service.secrets.includes(path.replace('/run/secrets/', '')));
    for (const name of [
      'INTAKE_HMAC_KEY',
      'INTAKE_WRITER_KEY',
      'INTAKE_FINGERPRINT_KEY',
      'MAIL_API_TOKEN',
      'BW_CLIENTID',
      'BW_CLIENTSECRET',
      'BW_SESSION',
    ])
      assert.equal(service.environment[name], undefined);
  }
  assert.equal(stack.services.web.environment.INTAKE_PRIVATE_DB, undefined);
  assert.equal(stack.services.web.environment.INTAKE_BW_SOCKET, undefined);
  assert.equal(stack.services.web.environment.BW_MAX_RESPONSE_BYTES, undefined);
  assert.equal(
    stack.services.writer.environment.BW_MAX_RESPONSE_BYTES,
    '${BW_MAX_RESPONSE_BYTES:-1048576}',
  );
  assert.equal(stack.services.bw.environment.BW_MAX_RESPONSE_BYTES, undefined);
  assert.equal(stack.services.bw.environment.HOME, '/var/lib/intake/bw');
  assert.equal(
    stack.services.bw.environment.BITWARDENCLI_APPDATA_DIR,
    '/var/lib/intake/bw',
  );
});

test('Docker targets pin runtime versions and initialize non-root volume metadata', async () => {
  const dockerfile = await readFile(
    new URL('../Dockerfile', import.meta.url),
    'utf8',
  );
  assert(
    dockerfile.includes(
      'FROM node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS base',
    ),
  );
  assert(dockerfile.includes('RUN npm ci --omit=dev'));
  assert(
    dockerfile.includes(
      'COPY docker/bw/package.json docker/bw/package-lock.json ./',
    ),
  );
  const bwDeps = dockerfile
    .split('FROM build-tools AS bw-deps\n')[1]
    ?.split('\nFROM ')[0];
  assert(bwDeps.includes('RUN npm ci --omit=dev --ignore-scripts'));
  assert(!dockerfile.includes('npm i -g'));
  assert(
    dockerfile.includes(
      'COPY --from=bw-deps /build/bw/node_modules /opt/bitwarden/node_modules',
    ),
  );
  assert(
    dockerfile.includes(
      'ln -s /opt/bitwarden/node_modules/@bitwarden/cli/build/bw.js /usr/local/bin/bw',
    ),
  );
  for (const [target, user] of [
    ['web', '10001:10001'],
    ['writer', '10002:10010'],
    ['bw', '10002:10010'],
  ]) {
    const block = dockerfile
      .split(new RegExp(`FROM [^\\n]+ AS ${target}\\n`))[1]
      ?.split(/\nFROM /)[0];
    assert(block, `Missing ${target} target`);
    assert(block.includes(`USER ${user}\n`));
  }
  for (const directory of [
    'install -d -o 10002 -g 10010 -m 0770 /run/intake',
    'install -d -o 10002 -g 10010 -m 2770 /var/lib/intake/public',
    'install -d -o 10002 -g 10010 -m 0700 /var/lib/intake/private /run/intake-bw',
    'install -d -o 10002 -g 10010 -m 0700 /var/lib/intake/bw /run/intake-bw',
  ])
    assert(dockerfile.includes(directory));
  const ignored = await readFile(
    new URL('../.dockerignore', import.meta.url),
    'utf8',
  );
  for (const pattern of [
    '.git',
    '.env*',
    'data',
    'test',
    'tests',
    'node_modules',
    'notes',
    'secrets',
  ])
    assert(ignored.split('\n').includes(pattern));
});
