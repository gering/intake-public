import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import { join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = (name) => readFile(join(root, name), 'utf8');
// An existing ignored/untracked local file must not satisfy a clean-checkout COPY.
const files = execFileSync('git', ['ls-files', '--cached', '-z'], {
  cwd: root,
  env: { PATH: process.env.PATH },
  encoding: 'utf8',
})
  .split('\0')
  .filter(Boolean);
const dockerfile = await read('Dockerfile');
const document = parseDocument(await read('docker-compose.yml'));
assert.deepEqual(document.errors, []);
assert.deepEqual(document.warnings, []);
const services = Object.entries(document.toJS().services);
const ignoreFile = files.includes('Dockerfile.dockerignore')
  ? 'Dockerfile.dockerignore'
  : '.dockerignore';
const ignored = ignoreMatcher(await read(ignoreFile));

// Support the syntax used here, failing closed on unsupported build constructs.
function stagesFrom(source) {
  const stages = [];
  const lines = source.replace(/\\\r?\n\s*/g, ' ').split(/\r?\n/);
  for (const line of lines.map((line) => line.trim())) {
    if (!line || line.startsWith('#')) continue;
    const instruction = line.match(/^([a-z]+)\s+(.+)$/i);
    assert(
      instruction && !line.includes('<<'),
      `Unsupported instruction: ${line}`,
    );
    const [, operation, args] = instruction;
    const op = operation.toUpperCase();
    if (op === 'FROM') {
      const from = args.match(/^(\S+)\s+AS\s+([a-z][\w.-]*)$/i);
      assert(from, `FROM needs an explicit stage alias: ${args}`);
      const [, image, alias] = from;
      const name = alias.toLowerCase();
      assert(
        !stages.some((stage) => stage.name === name),
        `Duplicate stage: ${name}`,
      );
      const parent = stages.find((stage) => stage.name === image.toLowerCase());
      if (!parent)
        assert.match(
          image,
          /^[^$\s@]+@sha256:[a-f0-9]{64}$/,
          `Unpinned FROM: ${image}`,
        );
      stages.push({ name, parent, instructions: [] });
    } else {
      assert(
        stages.length,
        'Instructions before FROM need explicit validation',
      );
      stages.at(-1).instructions.push({ op, args });
    }
  }
  assert(stages.length, 'No Dockerfile stages');
  return stages;
}

function glob(pattern) {
  assert(!/[[\]\\]/.test(pattern), `Unsupported glob: ${pattern}`);
  let expression = '^';
  for (let i = 0; i < pattern.length; i += 1) {
    if (pattern.slice(i, i + 3) === '**/') {
      expression += '(?:.*/)?';
      i += 2;
    } else if (pattern.slice(i, i + 2) === '**') {
      expression += '.*';
      i += 1;
    } else if (pattern[i] === '*') expression += '[^/]*';
    else if (pattern[i] === '?') expression += '[^/]';
    else expression += pattern[i].replace(/[.*+?^${}()|\\]/g, '\\$&');
  }
  return new RegExp(`${expression}$`);
}

function ignoreMatcher(source) {
  const rules = source.split(/\r?\n/).flatMap((line) => {
    if (!line.trim() || line.startsWith('#')) return [];
    const text = line.trim();
    const negate = text.startsWith('!');
    const pattern = posix.normalize(
      (negate ? text.slice(1) : text).replace(/^\/+|\/+$/g, ''),
    );
    return pattern === '.' ? [] : [{ negate, pattern: glob(pattern) }];
  });
  return (file) => {
    const parts = file.split('/');
    const ancestors = parts.map((_, i) => parts.slice(0, i + 1).join('/'));
    let excluded = false;
    for (const rule of rules)
      if (ancestors.some((path) => rule.pattern.test(path)))
        excluded = !rule.negate;
    return excluded;
  };
}

function copyFrom(args) {
  let from;
  while (args.startsWith('--')) {
    const flag = args.match(/^--(from|chmod|chown)=(\S+)\s+/);
    assert(flag, `Unsupported COPY option: ${args}`);
    if (flag[1] === 'from') from = flag[2];
    args = args.slice(flag[0].length);
  }
  assert(!/['"`\\$]/.test(args), `Unsupported COPY quoting/expansion: ${args}`);
  const paths = args.split(/\s+/);
  assert(paths.length >= 2, `Missing COPY source/destination: ${args}`);
  return { from, sources: paths.slice(0, -1), destination: paths.at(-1) };
}

const privatePath = /(?:^|\/)(?:\.env[^/]*|secrets)(?:\/|$)/i;

function copyInputs(source, tracked, excludes) {
  assert(
    !source.includes('**') && !/[$\\]/.test(source),
    `Unsupported COPY glob: ${source}`,
  );
  assert(!source.split('/').includes('..'), 'COPY outside context');
  const entries = new Set(['.', ...tracked]);
  for (const file of tracked)
    for (let dir = posix.dirname(file); dir !== '.'; dir = posix.dirname(dir))
      entries.add(dir);
  const pattern = glob(posix.normalize(source.replace(/^\/+/, '')));
  const matches = [...entries].filter((file) => pattern.test(file));
  assert(matches.length, `COPY absent from clean checkout: ${source}`);
  const inputs = new Set();
  for (const match of matches) {
    assert(!excludes(match), `COPY excluded by .dockerignore: ${match}`);
    const children = tracked.filter(
      (file) =>
        (file === match || match === '.' || file.startsWith(`${match}/`)) &&
        !excludes(file),
    );
    assert(children.length, `COPY has no retained tracked files: ${match}`);
    for (const file of children) {
      assert(
        !privatePath.test(file),
        `COPY includes local secrets/.env: ${file}`,
      );
      inputs.add(file);
    }
  }
  return { matches, files: [...inputs] };
}

const stages = stagesFrom(dockerfile);

test('Compose builds use existing tracked context, Dockerfile and targets, not local secrets/.env', async () => {
  assert(files.includes('Dockerfile') && files.includes(ignoreFile));
  for (const [role, service] of services) {
    const build = service.build;
    assert(build && typeof build === 'object', `${role}: missing local build`);
    for (const key of Object.keys(build))
      assert(
        ['context', 'dockerfile', 'target'].includes(key),
        `Unchecked build input: ${key}`,
      );
    // These are the context/Dockerfile whose COPY and ignore rules we check.
    assert.equal(resolve(root, build.context), resolve(root));
    const path = resolve(root, build.dockerfile ?? 'Dockerfile');
    assert.equal(path, join(root, 'Dockerfile'));
    assert((await lstat(resolve(root, build.context))).isDirectory());
    assert((await lstat(path)).isFile());
    assert(
      stages.some((stage) => stage.name === build.target),
      `Missing target: ${build.target}`,
    );
    assert.equal(service.env_file, undefined, 'No local env_file prerequisite');
  }
  // Runtime Compose interpolation/secrets are deployment inputs, not build inputs.
  for (const stage of stages)
    for (const { op, args } of stage.instructions) {
      assert(
        !['ARG', 'ADD', 'ONBUILD'].includes(op),
        `Unchecked build input: ${op}`,
      );
      assert(
        !/--mount\b|--ssh\b/.test(args),
        'No unchecked build mounts/secrets',
      );
      assert(
        !privatePath.test(args.replaceAll(/[\s"']/g, '/')),
        'No build-time secrets/.env',
      );
      if (op === 'ENV')
        assert(
          !/(?:^|\s)\w*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|_KEY)(?:=|\s)/i.test(
            args,
          ),
          'No build credentials',
        );
    }
});

test('Every external FROM is sha256 pinned and aliases inherit a pinned base', () => {
  assert(stages.length);
  assert.throws(() => stagesFrom('FROM node:22 AS base'), /Unpinned FROM/);
  assert.throws(() => stagesFrom('FROM missing AS web'), /Unpinned FROM/);
  const pinned = `node:22@sha256:${'a'.repeat(64)}`;
  const [base, alias] = stagesFrom(`FROM ${pinned} AS base\nFROM base AS app`);
  assert.equal(alias.parent, base);
});

test('Every local COPY exists in a clean checkout and is retained by .dockerignore', async () => {
  for (const [index, stage] of stages.entries()) {
    for (const { op, args } of stage.instructions) {
      if (op !== 'COPY') continue;
      const copy = copyFrom(args);
      if (copy.from !== undefined) {
        const prior = stages.slice(0, index);
        const from = /^\d+$/.test(copy.from)
          ? prior[Number(copy.from)]
          : prior.find((stage) => stage.name === copy.from.toLowerCase());
        assert(
          from,
          `COPY --from must name an earlier pinned stage: ${copy.from}`,
        );
        continue;
      }
      let count = 0;
      for (const source of copy.sources) {
        const inputs = copyInputs(source, files, ignored);
        count += inputs.matches.length;
        for (const file of inputs.files)
          assert(
            (await lstat(join(root, file))).isFile(),
            `Missing regular COPY input: ${file}`,
          );
      }
      if (count > 1)
        assert(
          copy.destination.endsWith('/'),
          'Multi-source COPY needs directory destination',
        );
    }
  }
});

test('bw installs integrity-locked CLI dependencies without lifecycle scripts', async () => {
  const manifest = JSON.parse(await read('docker/bw/package.json'));
  const lock = JSON.parse(await read('docker/bw/package-lock.json'));
  const cliVersion = manifest.dependencies['@bitwarden/cli'];
  const multerVersion = manifest.overrides['@bitwarden/cli'].multer;
  const tmpVersion = manifest.overrides['external-editor'].tmp;
  for (const version of [cliVersion, multerVersion, tmpVersion])
    assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(manifest.private, true);
  assert.deepEqual(manifest.dependencies, { '@bitwarden/cli': cliVersion });
  assert.deepEqual(manifest.overrides, {
    '@bitwarden/cli': { multer: multerVersion },
    'external-editor': { tmp: tmpVersion },
  });
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.equal(
    lock.packages['node_modules/@bitwarden/cli'].version,
    cliVersion,
  );
  assert.equal(lock.packages['node_modules/multer'].version, multerVersion);
  assert.equal(lock.packages['node_modules/tmp'].version, tmpVersion);
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue;
    assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//);
    assert.match(entry.integrity, /^sha(256|384|512)-[A-Za-z0-9+/]+=*$/);
  }
  for (const path of [
    'docker/bw/package.json',
    'docker/bw/package-lock.json',
  ]) {
    assert(files.includes(path), `Untracked bw manifest: ${path}`);
    assert(!ignored(path), `Ignored bw manifest: ${path}`);
  }
  assert(ignored('docker/bw/node_modules/@bitwarden/cli/build/bw.js'));
  const dependencies = stages.find(({ name }) => name === 'bw-deps');
  assert(
    dependencies.instructions.some(
      ({ op, args }) => op === 'WORKDIR' && args === '/build/bw',
    ),
  );
  assert(
    dependencies.instructions.some(
      ({ op, args }) =>
        op === 'RUN' && args === 'npm ci --omit=dev --ignore-scripts',
    ),
  );
});

test('app installs the reviewed bundled SQLite prebuilds and smoke-tests loading them', async () => {
  const lock = JSON.parse(await read('package-lock.json'));
  const sqlite = lock.packages['node_modules/better-sqlite3'];
  assert.equal(
    sqlite.version,
    '13.0.3',
    'Recheck bundled prebuilds and Node-API/glibc compatibility on upgrades',
  );
  assert.deepEqual(sqlite.dependencies, { 'node-addon-api': '^8.0.0' });
  const dependencies = stages.find(({ name }) => name === 'app-deps');
  assert(
    dependencies.instructions.some(
      ({ op, args }) =>
        op === 'RUN' &&
        args.replace(/\s+/g, ' ') ===
          `npm ci --omit=dev --ignore-scripts && node -e "require('better-sqlite3')(':memory:').close()"`,
    ),
  );
});

test('every dependency-stage npm ci disables explicit and implicit lifecycle scripts', () => {
  // binding.gyp can trigger npm's default node-gyp rebuild even when the lock
  // omits hasInstallScript. Require script suppression for every install in
  // these toolchain-free stages, independently of that incomplete metadata.
  for (const stage of stages.filter(({ name }) => name.endsWith('-deps'))) {
    const installs = stage.instructions.flatMap(({ op, args }) =>
      op === 'RUN' ? [...args.matchAll(/\bnpm\s+ci\b([^;&|]*)/g)] : [],
    );
    assert(installs.length, `Missing dependency install: ${stage.name}`);
    for (const [, flags] of installs)
      assert.match(
        flags,
        /(?:^|\s)--ignore-scripts(?:\s|$)/,
        `${stage.name}: npm ci must suppress explicit scripts and binding.gyp rebuilds`,
      );
  }
});

test('dependency and runtime stages do not install or inherit native toolchains', () => {
  for (const name of ['app-deps', 'bw-deps'])
    assert.equal(
      stages.find((stage) => stage.name === name).parent.name,
      'base',
    );
  const tools = /(?:^|[^\w.-])(?:python3|make|g\+\+)(?=$|[^\w+.-])/;
  for (const stage of stages)
    for (const { op, args } of stage.instructions)
      if (op === 'RUN' || op === 'COPY')
        assert(
          !tools.test(args),
          `Stage installs native toolchain: ${stage.name}`,
        );
});

test('COPY validation catches missing/ignored inputs and supports package manifest globs', () => {
  const manifests = ['docker/bw/package.json', 'docker/bw/package-lock.json'];
  assert.deepEqual(
    copyInputs('docker/bw/package*.json', manifests, ignored).files,
    manifests,
  );
  assert.throws(
    () => copyInputs('local-only.json', files, ignored),
    /absent from clean checkout/,
  );
  assert.throws(
    () => copyInputs('src', files, ignoreMatcher('src')),
    /excluded by .dockerignore/,
  );
  assert.throws(
    () => copyInputs('.env', ['.env'], ignored),
    /excluded by .dockerignore/,
  );
  assert.throws(
    () => copyInputs('secrets/key', ['secrets/key'], () => false),
    /local secrets/,
  );
  assert.throws(
    () => copyInputs('../package.json', files, ignored),
    /outside context/,
  );
});

test('Ignore matching covers ancestors, **, negation and last-match precedence', () => {
  const excludes = ignoreMatcher(
    '# comment\n.env*\n/notes/\n**/notes\n*.log\n!keep.log\nkeep.log',
  );
  for (const file of [
    '.env.local',
    'notes/a.txt',
    'docker/notes/a.txt',
    'keep.log',
  ])
    assert(excludes(file), `Expected excluded: ${file}`);
  for (const file of [
    'docker/bw/package.json',
    'docker/.env',
    'docker/debug.log',
  ])
    assert(!excludes(file), `Expected retained: ${file}`);
  const exception = ignoreMatcher('**/*.json\n!docker/bw/package*.json');
  assert(exception('package.json'));
  assert(!exception('docker/bw/package-lock.json'));
});

test('Dockerfile builds with BuildKit and the classic builder without unpinned frontends', () => {
  // A syntax directive pulls an unpinned frontend image at build time.
  assert.doesNotMatch(dockerfile, /^#\s*syntax\s*=/im);
  // BuildKit-only flags would break hosts that build with the classic builder.
  assert.doesNotMatch(
    dockerfile,
    /^(?:COPY|ADD)\s+[^\n]*--(?:chmod|link|parents)\b/im,
  );
  assert.doesNotMatch(dockerfile, /^RUN\s+--(?:mount|network|security)\b/im);
  assert.doesNotMatch(dockerfile, /<<\s*-?\s*['"]?[A-Z]+/);
});
