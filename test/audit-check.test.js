import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  auditTarget,
  evaluateAdvisories,
  extractAdvisories,
  extractHighAdvisories,
  parseAllowlist,
  parseAuditOutput,
  runAuditChecks,
  validateAllowlist,
} from '../scripts/audit-check.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const today = '2026-10-18';
const entry = {
  target: 'root',
  id: 'GHSA-2345-6789-cfgh',
  package: 'example-package',
  reason: 'The affected feature is disabled while the upstream fix is pending.',
  expires: '2026-10-25',
};

function report(severity = 'high') {
  return {
    auditReportVersion: 2,
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        [severity]: 1,
        total: 1,
      },
    },
    vulnerabilities: {
      'example-package': {
        name: 'example-package',
        severity,
        via: [
          {
            source: 1234567,
            name: 'example-package',
            dependency: 'example-package',
            title: 'Synthetic advisory for audit checker tests',
            url: 'https://github.com/advisories/GHSA-2345-6789-cfgh',
            severity,
          },
        ],
      },
    },
  };
}

const cleanReport = {
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
};

async function fixture(t, entries = []) {
  const directory = await mkdtemp(join(tmpdir(), 'intake-audit-check-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({ type: 'module' }),
  );
  await writeFile(
    join(directory, '.audit-allowlist.json'),
    JSON.stringify({ entries }),
  );
  await mkdir(join(directory, 'docker/bw'), { recursive: true });
  await writeFile(
    join(directory, 'docker/bw/package.json'),
    JSON.stringify({ name: 'example-bw' }),
  );
  return directory;
}

test('audit: parses a valid allowlist and accepts an empty one', () => {
  assert.deepEqual(
    parseAllowlist(JSON.stringify({ entries: [entry] }), { today }),
    [entry],
  );
  assert.deepEqual(validateAllowlist({ entries: [] }, { today }), []);
});

test('audit: rejects expired entries, including stale entries', () => {
  assert.throws(
    () =>
      validateAllowlist(
        { entries: [{ ...entry, expires: '2026-10-17' }] },
        { today },
      ),
    /expired/,
  );
});

test('audit: expiry is inclusive and uses the injected UTC day', () => {
  const sameDay = { ...entry, expires: today };
  assert.deepEqual(
    validateAllowlist(
      { entries: [sameDay] },
      { today: new Date('2026-10-18T23:59:59Z') },
    ),
    [sameDay],
  );
  assert.throws(
    () =>
      validateAllowlist(
        { entries: [sameDay] },
        { today: new Date('2026-10-19T00:00:00Z') },
      ),
    /expired/,
  );
});

test('audit: rejects missing, empty, short and placeholder reasons', () => {
  for (const reason of [
    undefined,
    null,
    '',
    '   ',
    'too short',
    'TODO: investigate later',
    'placeholder text',
    'TBD TBD TBD',
    'temporary exception',
  ]) {
    assert.throws(
      () => validateAllowlist({ entries: [{ ...entry, reason }] }, { today }),
      /non-placeholder reason/,
    );
  }
});

test('audit: rejects invalid dates and accepts real leap days', () => {
  for (const expires of [
    undefined,
    '2026-02-29',
    '2026-11-31',
    '2026-13-01',
    '2026-10-25T00:00:00Z',
    '2026-1-01',
  ]) {
    assert.throws(
      () => validateAllowlist({ entries: [{ ...entry, expires }] }, { today }),
      /real YYYY-MM-DD/,
    );
  }
  assert.equal(
    validateAllowlist(
      { entries: [{ ...entry, expires: '2028-02-29' }] },
      { today },
    ).length,
    1,
  );
});

test('audit: rejects unknown entry and top-level fields', () => {
  assert.throws(
    () =>
      validateAllowlist({ entries: [{ ...entry, extra: true }] }, { today }),
    /unknown fields/,
  );
  assert.throws(
    () => validateAllowlist({ entries: [], extra: true }, { today }),
    /only an entries array/,
  );
});

test('audit: rejects duplicate target/advisory/package identities', () => {
  assert.throws(
    () =>
      validateAllowlist(
        {
          entries: [
            entry,
            {
              ...entry,
              reason: 'A different justification still duplicates the entry.',
            },
          ],
        },
        { today },
      ),
    /duplicates/,
  );
});

test('audit: rejects malformed or missing GHSA ids and package names', () => {
  for (const id of [
    undefined,
    '1234567',
    'GHSA-xxxx-xxxx',
    'https://example.com/advisory',
    'GHSA-!!!!-xxxx-xxxx',
  ]) {
    assert.throws(
      () => validateAllowlist({ entries: [{ ...entry, id }] }, { today }),
      /GHSA id/,
    );
  }
  for (const name of [undefined, '', 'example package', '*', '@scope/']) {
    assert.throws(
      () =>
        validateAllowlist(
          { entries: [{ ...entry, package: name }] },
          { today },
        ),
      /exact npm package/,
    );
  }
  assert.equal(
    validateAllowlist(
      { entries: [{ ...entry, package: '@example/package' }] },
      { today },
    ).length,
    1,
  );
});

test('audit: rejects malformed allowlist JSON and shapes', () => {
  assert.throws(() => parseAllowlist('{broken', { today }), /not valid JSON/);
  for (const value of [null, [], {}, { entries: null }, { entries: [null] }]) {
    assert.throws(() => validateAllowlist(value, { today }), /Audit allowlist/);
  }
});

test('audit: blocks an unallowlisted high advisory', () => {
  const result = evaluateAdvisories(extractHighAdvisories(report()), []);
  assert.deepEqual(result.blocked, [
    { target: 'root', id: entry.id, package: entry.package, severity: 'high' },
  ]);
  assert.deepEqual(result.allowed, []);
});

test('audit: allows an advisory only for the exact target, id and package', () => {
  const advisories = extractHighAdvisories(report());
  assert.equal(evaluateAdvisories(advisories, [entry]).allowed.length, 1);
  assert.equal(evaluateAdvisories(advisories, [entry]).blocked.length, 0);
  assert.equal(
    evaluateAdvisories(advisories, [{ ...entry, id: 'GHSA-cfgh-jmpq-rvwx' }])
      .blocked.length,
    1,
  );
});

test('audit: ignores moderate advisories for blocking but includes them in summaries', () => {
  assert.deepEqual(extractHighAdvisories(report('moderate')), []);
  const advisories = extractAdvisories(report('moderate'));
  assert.equal(advisories.length, 1);
  assert.equal(evaluateAdvisories(advisories, []).blocked.length, 0);
});

test('audit: blocks critical advisories', () => {
  const result = evaluateAdvisories(
    extractHighAdvisories(report('critical')),
    [],
  );
  assert.equal(result.blocked[0].severity, 'critical');
});

test('audit: an exception for a different package cannot allow an advisory', () => {
  const result = evaluateAdvisories(extractHighAdvisories(report()), [
    { ...entry, package: 'other-package' },
  ]);
  assert.equal(result.blocked.length, 1);
  assert.equal(result.stale.length, 1);
});

test('audit: reports unmatched exceptions as stale', () => {
  assert.deepEqual(evaluateAdvisories([], [entry]).stale, [entry]);
  assert.deepEqual(
    evaluateAdvisories(extractAdvisories(report()), [entry]).stale,
    [],
  );
});

test('audit: deduplicates advisory objects and resolves transitive references', () => {
  const value = report();
  value.vulnerabilities.parent = { severity: 'high', via: ['example-package'] };
  value.vulnerabilities['example-package'].via.push({
    ...value.vulnerabilities['example-package'].via[0],
  });
  Object.assign(value.metadata.vulnerabilities, { high: 2, total: 2 });
  assert.equal(extractHighAdvisories(value).length, 1);
});

test('audit: rejects per-severity metadata mismatches even when totals match', () => {
  for (const severity of ['info', 'low', 'moderate', 'high', 'critical']) {
    const value = report(severity);
    const other = severity === 'info' ? 'low' : 'info';
    Object.assign(value.metadata.vulnerabilities, {
      [severity]: 0,
      [other]: 1,
    });
    assert.throws(
      () => parseAuditOutput(JSON.stringify(value)),
      /metadata counts do not match the reported vulnerabilities/,
    );
    assert.throws(
      () => extractAdvisories(value),
      /metadata counts do not match the reported vulnerabilities/,
    );
  }
});

test('audit: rejects total metadata mismatches', () => {
  for (const total of [0, 2]) {
    const value = report();
    value.metadata.vulnerabilities.total = total;
    assert.throws(
      () => parseAuditOutput(JSON.stringify(value)),
      /metadata counts do not match the reported vulnerabilities/,
    );
    assert.throws(
      () => extractAdvisories(value),
      /metadata counts do not match the reported vulnerabilities/,
    );
  }
});

test('audit: handles nonzero npm exit status with a vulnerability JSON report', () => {
  assert.equal(
    extractHighAdvisories(parseAuditOutput(JSON.stringify(report()), 1)).length,
    1,
  );
  assert.deepEqual(parseAuditOutput(JSON.stringify(cleanReport)), cleanReport);
});

test('audit: fails closed on unparsable npm output without echoing it', () => {
  const output = '<html>private registry response</html>';
  assert.throws(
    () => parseAuditOutput(output, 1),
    (error) =>
      /unparsable JSON/.test(error.message) && !error.message.includes(output),
  );
});

test('audit: fails closed on npm errors and unsupported report shapes', () => {
  for (const value of [
    { error: { code: 'ECONNREFUSED' } },
    { ...cleanReport, error: {} },
    null,
    {},
    { auditReportVersion: 2, vulnerabilities: [] },
  ]) {
    assert.throws(
      () => parseAuditOutput(JSON.stringify(value), 1),
      /npm audit/,
    );
  }
  assert.throws(
    () => parseAuditOutput(JSON.stringify(cleanReport), 2),
    /npm audit failed/,
  );
  assert.throws(
    () => parseAuditOutput(JSON.stringify(cleanReport), null),
    /npm audit failed/,
  );
});

test('audit: fails closed on malformed vulnerability and advisory details', () => {
  for (const vulnerability of [
    null,
    {},
    { severity: 'high', via: ['missing-package'] },
    { severity: 'high', via: [] },
  ]) {
    assert.throws(
      () =>
        extractAdvisories({
          ...report(),
          vulnerabilities: { broken: vulnerability },
        }),
      /npm audit/,
    );
  }
  for (const change of [
    { url: undefined },
    { severity: 'unknown' },
    { name: undefined },
    { url: 'https://example.org/advisories/GHSA-2345-6789-cfgh' },
  ]) {
    const value = report();
    Object.assign(value.vulnerabilities['example-package'].via[0], change);
    assert.throws(() => extractAdvisories(value), /npm audit/);
  }
});

test('audit: runs exactly root and docker/bw with per-target severity summaries', async (t) => {
  const directory = await fixture(t);
  const targets = [];
  const lines = [];
  const code = await runAuditChecks({
    root: directory,
    today,
    log: (line) => lines.push(line),
    audit: (_root, target) => {
      targets.push(target);
      return target === 'root' ? cleanReport : report('moderate');
    },
  });
  assert.equal(code, 0);
  assert.deepEqual(targets, ['root', 'docker/bw']);
  assert.match(
    lines.join('\n'),
    /docker\/bw: advisories info=0 low=0 moderate=1 high=0 critical=0; allowed=0 blocked=0/,
  );
});

test('audit: returns failure for blocked advisories in any target and keeps checking', async (t) => {
  const directory = await fixture(t);
  const lines = [];
  const code = await runAuditChecks({
    root: directory,
    today,
    log: (line) => lines.push(line),
    audit: (_root, target) =>
      target === 'root' ? report('critical') : cleanReport,
  });
  assert.equal(code, 1);
  assert.ok(lines.some((line) => line.includes('BLOCKED critical')));
  assert.ok(lines.some((line) => line.startsWith('docker/bw:')));
});

test('audit: rejects each incomplete high/critical vulnerability even alongside valid advisories', () => {
  for (const via of [[], ['hidden'], ['example-package']]) {
    const value = report();
    value.vulnerabilities.hidden = { severity: 'critical', via };
    Object.assign(value.metadata.vulnerabilities, { critical: 1, total: 2 });
    assert.throws(
      () => extractAdvisories(value),
      /without matching advisory details/,
    );
  }
});

test('audit: rejects nonzero exit status without advisory details explaining the failure', () => {
  assert.throws(
    () => parseAuditOutput(JSON.stringify(cleanReport), 1),
    /nonzero without/,
  );
  assert.throws(
    () => parseAuditOutput(JSON.stringify(report('moderate')), 1),
    /nonzero without/,
  );
});

test('audit: an allowed high advisory cannot mask an incomplete critical report', async (t) => {
  const directory = await fixture(t, [entry]);
  const value = report();
  value.vulnerabilities.hidden = { severity: 'critical', via: [] };
  Object.assign(value.metadata.vulnerabilities, { critical: 1, total: 2 });
  const lines = [];
  const code = await runAuditChecks({
    root: directory,
    today,
    log: (line) => lines.push(line),
    audit: () => value,
  });
  assert.equal(code, 1);
  assert.ok(lines.some((line) => line.includes('ERROR npm audit')));
});

test('audit: an allowed node-forge advisory cannot mask a partial docker/bw report', async (t) => {
  const exception = {
    ...entry,
    target: 'docker/bw',
    id: 'GHSA-86w9-cpqp-85rv',
    package: 'node-forge',
  };
  const directory = await fixture(t, [exception]);
  const value = report();
  const vulnerability = value.vulnerabilities['example-package'];
  value.vulnerabilities = {
    'node-forge': {
      ...vulnerability,
      name: 'node-forge',
      via: [
        {
          ...vulnerability.via[0],
          name: 'node-forge',
          dependency: 'node-forge',
          url: `https://github.com/advisories/${exception.id}`,
        },
      ],
    },
  };
  Object.assign(value.metadata.vulnerabilities, {
    high: 5,
    critical: 3,
    total: 8,
  });
  const lines = [];
  const code = await runAuditChecks({
    root: directory,
    today,
    log: (line) => lines.push(line),
    audit: (_root, target) => (target === 'root' ? cleanReport : value),
  });
  assert.equal(code, 1);
  assert.ok(lines.some((line) => line.startsWith('root: advisories')));
  assert.ok(
    lines.includes(
      'docker/bw: ERROR npm audit metadata counts do not match the reported vulnerabilities',
    ),
  );
  assert.ok(!lines.some((line) => /ALLOWED|WARNING stale/.test(line)));
  assert.equal(lines.at(-1), 'Dependency audit FAILED');
});

test('audit: rejects offline/incomplete reports even when npm exits successfully', async (t) => {
  const directory = await fixture(t);
  const offlineReport = { auditReportVersion: 2, vulnerabilities: {} };
  for (const value of [
    offlineReport,
    { ...offlineReport, metadata: {} },
    { ...offlineReport, metadata: { vulnerabilities: null } },
    { ...offlineReport, metadata: { vulnerabilities: {} } },
    { ...cleanReport, error: { code: 'ENOTCACHED' } },
    {
      ...cleanReport,
      metadata: {
        vulnerabilities: { ...cleanReport.metadata.vulnerabilities, high: -1 },
      },
    },
  ]) {
    const run = () => ({ status: 0, stdout: JSON.stringify(value) });
    assert.throws(() => auditTarget(directory, 'root', { run }), /npm audit/);
    assert.throws(() => extractAdvisories(value), /npm audit/);
    const lines = [];
    assert.equal(
      await runAuditChecks({
        root: directory,
        today,
        log: (line) => lines.push(line),
        audit: (_root, target) =>
          target === 'root'
            ? auditTarget(directory, target, { run })
            : cleanReport,
      }),
      1,
    );
    assert.ok(lines.some((line) => line.startsWith('root: ERROR')));
    assert.ok(lines.some((line) => line.startsWith('docker/bw: advisories')));
  }
});

test('audit: rejects high/critical metadata without reported vulnerabilities', () => {
  const value = { ...cleanReport, metadata: report().metadata };
  assert.throws(
    () => extractAdvisories(value),
    /metadata counts do not match the reported vulnerabilities/,
  );
});

test('audit: resolves a reconverging graph with bounded traversal', () => {
  const value = report();
  let reads = 0;
  for (let index = 0; index < 40; index++) {
    const via =
      index === 39
        ? ['example-package']
        : [`left-${index + 1}`, `right-${index + 1}`];
    for (const side of ['left', 'right']) {
      value.vulnerabilities[`${side}-${index}`] = {
        severity: 'high',
        get via() {
          assert.ok(
            ++reads < 1000,
            'shared descendants must not be traversed exponentially',
          );
          return via;
        },
      };
      value.metadata.vulnerabilities.high++;
      value.metadata.vulnerabilities.total++;
    }
  }
  assert.equal(extractHighAdvisories(value).length, 1);
});

test('audit: resolves shared cycles regardless of entry order and rejects cycles without advisories', () => {
  for (const references of [
    ['first', 'second'],
    ['second', 'first'],
  ]) {
    const value = report('critical');
    for (const name of references) {
      value.vulnerabilities[name] = {
        severity: 'critical',
        via: name === 'first' ? ['second', 'example-package'] : ['first'],
      };
    }
    Object.assign(value.metadata.vulnerabilities, { critical: 3, total: 3 });
    assert.equal(extractHighAdvisories(value).length, 1);
    value.vulnerabilities.first.via = ['second'];
    assert.throws(
      () => extractAdvisories(value),
      /without matching advisory details/,
    );
  }
});

test('audit: fails on registry errors while still checking remaining targets', async (t) => {
  const directory = await fixture(t);
  const lines = [];
  const code = await runAuditChecks({
    root: directory,
    today,
    log: (line) => lines.push(line),
    audit: (_root, target) => {
      if (target === 'root')
        return parseAuditOutput('{"error":{"code":"ECONNREFUSED"}}', 1);
      return cleanReport;
    },
  });
  assert.equal(code, 1);
  assert.ok(lines.some((line) => /root: ERROR npm audit failed/.test(line)));
  assert.ok(lines.some((line) => line.startsWith('docker/bw:')));
});

test('audit: requires an exact fixed allowlist target without normalization', () => {
  for (const target of [
    undefined,
    null,
    '',
    'ROOT',
    ' root',
    'root ',
    '.',
    './docker/bw',
    'docker/bw/',
    'docker/../bw',
    '../docker/bw',
    'docker\\bw',
    '*',
    'packages/example',
    [],
    {},
    0,
  ]) {
    assert.throws(
      () => validateAllowlist({ entries: [{ ...entry, target }] }, { today }),
      /target of root or docker\/bw/,
    );
  }
  const missing = { ...entry };
  delete missing.target;
  assert.throws(
    () => validateAllowlist({ entries: [missing] }, { today }),
    /target of root or docker\/bw/,
  );
  for (const target of ['root', 'docker/bw']) {
    assert.deepEqual(
      validateAllowlist({ entries: [{ ...entry, target }] }, { today }),
      [{ ...entry, target }],
    );
  }
});

test('audit: permits the same advisory/package in distinct targets but not duplicates within either', () => {
  const entries = [entry, { ...entry, target: 'docker/bw' }];
  assert.deepEqual(validateAllowlist({ entries }, { today }), entries);
  for (const target of ['root', 'docker/bw']) {
    assert.throws(
      () =>
        validateAllowlist(
          {
            entries: [
              { ...entry, target },
              { ...entry, target },
            ],
          },
          { today },
        ),
      /duplicates a target\/advisory\/package identity/,
    );
  }
});

test('audit: trims valid justifications and rejects invalid injected dates', () => {
  assert.deepEqual(
    validateAllowlist(
      { entries: [{ ...entry, reason: `  ${entry.reason}  ` }] },
      { today },
    ),
    [entry],
  );
  for (const day of ['2026-02-29', '2026-1-01', null]) {
    assert.throws(
      () => validateAllowlist({ entries: [] }, { today: day }),
      /valid UTC date/,
    );
  }
});

test('audit: exceptions cannot cross targets in either direction', () => {
  for (const target of ['root', 'docker/bw']) {
    const other = target === 'root' ? 'docker/bw' : 'root';
    const exception = { ...entry, target: other };
    const advisories = extractHighAdvisories(report(), target);
    const result = evaluateAdvisories(advisories, [exception]);
    assert.deepEqual(result.allowed, []);
    assert.deepEqual(result.blocked, advisories);
    assert.deepEqual(result.stale, [exception]);
  }
});

test('audit: keeps duplicate advisory identities in different targets independently allowed or blocked', () => {
  const rootAdvisories = extractHighAdvisories(report(), 'root');
  const dockerAdvisories = extractHighAdvisories(report(), 'docker/bw');
  const advisories = [...rootAdvisories, ...dockerAdvisories];
  const dockerEntry = { ...entry, target: 'docker/bw' };
  assert.deepEqual(evaluateAdvisories(advisories, [dockerEntry]), {
    allowed: dockerAdvisories,
    blocked: rootAdvisories,
    stale: [],
  });
  assert.deepEqual(evaluateAdvisories(advisories, [entry, dockerEntry]), {
    allowed: advisories,
    blocked: [],
    stale: [],
  });
});

test('audit: resolves transitive Bitwarden references to the real node-forge advisory identity', () => {
  const value = report();
  const forge = value.vulnerabilities['example-package'];
  delete value.vulnerabilities['example-package'];
  forge.name = 'node-forge';
  Object.assign(forge.via[0], {
    name: 'node-forge',
    dependency: 'node-forge',
    url: 'https://github.com/advisories/GHSA-86w9-cpqp-85rv',
  });
  // Put the parent first so resolution cannot depend on report ordering.
  value.vulnerabilities['@bitwarden/cli'] = {
    severity: 'high',
    via: ['node-forge'],
  };
  value.vulnerabilities['node-forge'] = forge;
  Object.assign(value.metadata.vulnerabilities, { high: 2, total: 2 });
  const advisories = extractHighAdvisories(value, 'docker/bw');
  const exception = {
    ...entry,
    target: 'docker/bw',
    id: 'GHSA-86w9-cpqp-85rv',
    package: 'node-forge',
  };
  assert.deepEqual(advisories, [
    {
      target: 'docker/bw',
      id: exception.id,
      package: 'node-forge',
      severity: 'high',
    },
  ]);
  assert.deepEqual(evaluateAdvisories(advisories, [exception]).blocked, []);
  assert.deepEqual(
    evaluateAdvisories(advisories, [
      { ...exception, package: '@bitwarden/cli' },
    ]).blocked,
    advisories,
  );
  assert.deepEqual(
    evaluateAdvisories(extractHighAdvisories(value, 'root'), [exception])
      .allowed,
    [],
  );
});

test('audit: deduplication retains the highest severity regardless of advisory order', () => {
  for (const order of [
    ['high', 'critical'],
    ['critical', 'high'],
  ]) {
    const value = report('critical');
    const advisory = value.vulnerabilities['example-package'].via[0];
    value.vulnerabilities['example-package'].via = order.map((severity) => ({
      ...advisory,
      severity,
    }));
    assert.deepEqual(extractHighAdvisories(value, 'docker/bw'), [
      {
        target: 'docker/bw',
        id: entry.id,
        package: entry.package,
        severity: 'critical',
      },
    ]);
  }
});

test('audit: validates all metadata counts as nonnegative safe integers', () => {
  for (const field of [
    'info',
    'low',
    'moderate',
    'high',
    'critical',
    'total',
  ]) {
    for (const count of [
      undefined,
      null,
      -1,
      0.5,
      '0',
      Number.MAX_SAFE_INTEGER + 1,
    ]) {
      const value = {
        ...cleanReport,
        metadata: {
          vulnerabilities: {
            ...cleanReport.metadata.vulnerabilities,
            [field]: count,
          },
        },
      };
      assert.throws(
        () => parseAuditOutput(JSON.stringify(value)),
        /unsupported or incomplete report/,
      );
      assert.throws(
        () => extractAdvisories(value),
        /unsupported or incomplete report/,
      );
    }
  }
});

test('audit: only accepts canonical GHSA advisory URLs', () => {
  for (const url of [
    'http://github.com/advisories/GHSA-2345-6789-cfgh',
    'https://github.com/advisories/GHSA-2345-6789-cfgh/',
    'https://github.com/advisories/GHSA-2345-6789-cfgh?extra=true',
    'https://github.com/advisories/not-a-ghsa',
    'https://github.com.evil.example/advisories/GHSA-2345-6789-cfgh',
  ]) {
    const value = report();
    value.vulnerabilities['example-package'].via[0].url = url;
    assert.throws(() => extractAdvisories(value), /no supported GHSA URL/);
  }
});

test('audit: fixed targets are independent of manifest workspace configuration', async (t) => {
  const directory = await fixture(t);
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({ workspaces: ['ignored/*', '../outside'] }),
  );
  const calls = [];
  assert.equal(
    await runAuditChecks({
      root: directory,
      today,
      log: () => {},
      audit: (auditRoot, target) => {
        calls.push({ root: auditRoot, target });
        return cleanReport;
      },
    }),
    0,
  );
  assert.deepEqual(calls, [
    { root: directory, target: 'root' },
    { root: directory, target: 'docker/bw' },
  ]);
});

test('audit: launches the exact lockfile-only command in each fixed directory without a shell', () => {
  const calls = [];
  const npmCli = join(root, 'example-npm-cli.js');
  const run = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: JSON.stringify(cleanReport) };
  };
  for (const target of ['root', 'docker/bw']) {
    assert.deepEqual(auditTarget(root, target, { run, npmCli }), cleanReport);
  }
  for (const [index, cwd] of [root, join(root, 'docker/bw')].entries()) {
    assert.equal(calls[index].command, process.execPath);
    assert.deepEqual(calls[index].args, [
      npmCli,
      'audit',
      '--json',
      '--audit-level=high',
      '--package-lock-only',
      '--offline=false',
    ]);
    assert.deepEqual(calls[index].options, {
      cwd,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    });
  }
});

test('audit: supports npm fallback when no npm JS entrypoint is supplied', () => {
  const calls = [];
  auditTarget(root, 'docker/bw', {
    npmCli: '',
    run: (command, args, options) => {
      calls.push({ command, args, options });
      return { status: 0, stdout: JSON.stringify(cleanReport) };
    },
  });
  const { command, args, options } = calls[0];
  assert.equal(
    command,
    process.platform === 'win32' ? process.execPath : 'npm',
  );
  assert.deepEqual(args.slice(process.platform === 'win32' ? 1 : 0), [
    'audit',
    '--json',
    '--audit-level=high',
    '--package-lock-only',
    '--offline=false',
  ]);
  assert.equal(options.cwd, join(root, 'docker/bw'));
  assert.ok(!options.shell);
});

test('audit: rejects nonfixed targets before spawning npm or extracting advisories', () => {
  for (const target of [
    undefined,
    null,
    '.',
    '../outside',
    'docker/bw/',
    '*',
    'packages/example',
  ]) {
    assert.throws(
      () =>
        auditTarget(root, target, {
          run: () => assert.fail('must not spawn for an invalid target'),
        }),
      /target must be root or docker\/bw/,
    );
    if (target !== undefined)
      assert.throws(
        () => extractAdvisories(cleanReport, target),
        /target must be root or docker\/bw/,
      );
  }
});

test('audit: fails closed on subprocess errors, signals and invalid statuses without leaking output', () => {
  const output = 'private registry response';
  for (const result of [
    { error: new Error(output) },
    { signal: 'SIGTERM' },
    { signal: 'SIGKILL', status: null },
    { status: 2, stdout: JSON.stringify(cleanReport) },
    { status: null, stdout: JSON.stringify(cleanReport) },
    { status: 0, stdout: output, stderr: output },
  ]) {
    assert.throws(
      () => auditTarget(root, 'root', { npmCli: '', run: () => result }),
      (error) =>
        /npm audit/.test(error.message) && !error.message.includes(output),
    );
  }
  assert.deepEqual(
    auditTarget(root, 'docker/bw', {
      run: () => ({ status: 1, stdout: JSON.stringify(report()) }),
    }),
    report(),
  );
});

test('audit: a docker/bw exception cannot allow the identical root advisory in a full run', async (t) => {
  const directory = await fixture(t, [{ ...entry, target: 'docker/bw' }]);
  const lines = [];
  assert.equal(
    await runAuditChecks({
      root: directory,
      today,
      log: (line) => lines.push(line),
      audit: () => report(),
    }),
    1,
  );
  assert.ok(
    lines.includes(
      'root: advisories info=0 low=0 moderate=0 high=1 critical=0; allowed=0 blocked=1',
    ),
  );
  assert.ok(
    lines.includes(
      'docker/bw: advisories info=0 low=0 moderate=0 high=1 critical=0; allowed=1 blocked=0',
    ),
  );
  assert.ok(lines.includes(`  BLOCKED high ${entry.id} ${entry.package}`));
  assert.ok(lines.includes(`  ALLOWED high ${entry.id} ${entry.package}`));
  assert.equal(lines.at(-1), 'Dependency audit FAILED');
});

test('audit: matching exceptions in both targets allow duplicate advisory identities', async (t) => {
  const directory = await fixture(t, [
    entry,
    { ...entry, target: 'docker/bw' },
  ]);
  const lines = [];
  assert.equal(
    await runAuditChecks({
      root: directory,
      today,
      log: (line) => lines.push(line),
      audit: () => report(),
    }),
    0,
  );
  assert.equal(lines.filter((line) => line.includes('ALLOWED high')).length, 2);
  assert.ok(!lines.some((line) => /BLOCKED|WARNING stale/.test(line)));
  assert.equal(lines.at(-1), 'Dependency audit passed');
});

test('audit: stale warnings identify target, id and package after a clean full run', async (t) => {
  const entries = [entry, { ...entry, target: 'docker/bw' }];
  const directory = await fixture(t, entries);
  const lines = [];
  assert.equal(
    await runAuditChecks({
      root: directory,
      today,
      log: (line) => lines.push(line),
      audit: () => cleanReport,
    }),
    0,
  );
  const warnings = lines.filter((line) => line.startsWith('WARNING stale'));
  assert.deepEqual(
    warnings,
    entries.map(
      (item) =>
        `WARNING stale audit exception: ${item.target} ${item.id} ${item.package}; remove it if no longer needed`,
    ),
  );
});

test('audit: matching an advisory in one target does not hide a stale exception in the other', async (t) => {
  const directory = await fixture(t, [
    entry,
    { ...entry, target: 'docker/bw' },
  ]);
  for (const active of ['root', 'docker/bw']) {
    const lines = [];
    assert.equal(
      await runAuditChecks({
        root: directory,
        today,
        log: (line) => lines.push(line),
        audit: (_root, target) => (target === active ? report() : cleanReport),
      }),
      0,
    );
    const staleTarget = active === 'root' ? 'docker/bw' : 'root';
    const warnings = lines.filter((line) => line.startsWith('WARNING stale'));
    assert.equal(warnings.length, 1);
    assert.ok(
      warnings[0].includes(`: ${staleTarget} ${entry.id} ${entry.package};`),
    );
  }
});

test('audit: an advisory downgraded below high is not a stale exception in its target', async (t) => {
  const directory = await fixture(t, [{ ...entry, target: 'docker/bw' }]);
  const lines = [];
  assert.equal(
    await runAuditChecks({
      root: directory,
      today,
      log: (line) => lines.push(line),
      audit: (_root, target) =>
        target === 'root' ? cleanReport : report('moderate'),
    }),
    0,
  );
  assert.ok(lines.some((line) => line.includes('moderate=1')));
  assert.ok(!lines.some((line) => /ALLOWED|BLOCKED|WARNING stale/.test(line)));
});

test('audit: suppresses stale warnings on any failed or blocked target and continues auditing', async (t) => {
  const directory = await fixture(t, [{ ...entry, id: 'GHSA-cfgh-jmpq-rvwx' }]);
  for (const failingTarget of ['root', 'docker/bw']) {
    for (const failure of ['error', 'blocked']) {
      const lines = [];
      const calls = [];
      const code = await runAuditChecks({
        root: directory,
        today,
        log: (line) => lines.push(line),
        audit: (_root, target) => {
          calls.push(target);
          if (target !== failingTarget) return cleanReport;
          if (failure === 'error')
            throw new Error('npm audit could not complete');
          return report();
        },
      });
      assert.equal(code, 1);
      assert.deepEqual(calls, ['root', 'docker/bw']);
      assert.ok(!lines.some((line) => line.startsWith('WARNING stale')));
      assert.equal(lines.at(-1), 'Dependency audit FAILED');
    }
  }
});

test('audit: rejects invalid and expired stale allowlists before auditing any target', async (t) => {
  const directory = await fixture(t);
  for (const entries of [
    [{ ...entry, target: undefined }],
    [{ ...entry, target: 'packages/example' }],
    [{ ...entry, expires: '2026-10-17' }],
    [entry, entry],
  ]) {
    await writeFile(
      join(directory, '.audit-allowlist.json'),
      JSON.stringify({ entries }),
    );
    await assert.rejects(
      runAuditChecks({
        root: directory,
        today,
        log: () => {},
        audit: () =>
          assert.fail('invalid allowlists must fail before auditing'),
      }),
      /Audit allowlist entry/,
    );
  }
});

test('audit: fails closed when the allowlist is missing or unparsable', async (t) => {
  const directory = await fixture(t);
  const options = {
    root: directory,
    today,
    audit: () => assert.fail('must not run npm'),
    log: () => {},
  };
  await writeFile(join(directory, '.audit-allowlist.json'), '{broken');
  await assert.rejects(runAuditChecks(options), /not valid JSON/);
  await rm(join(directory, '.audit-allowlist.json'));
  await assert.rejects(runAuditChecks(options), { code: 'ENOENT' });
});

test('audit: executes through a symlink without node_modules or network access and fails closed on incomplete output', async (t) => {
  const directory = await fixture(t);
  await mkdir(join(directory, 'scripts'));
  await copyFile(
    join(root, 'scripts/audit-check.js'),
    join(directory, 'scripts/audit-check.js'),
  );
  const link = join(directory, 'audit-link.js');
  const npmCli = join(directory, 'fake-npm.cjs');
  const callLog = join(directory, 'npm-calls.jsonl');
  await symlink(join(directory, 'scripts/audit-check.js'), link);
  const execute = () =>
    spawnSync(process.execPath, [link], {
      cwd: directory,
      env: { ...process.env, npm_execpath: npmCli },
      encoding: 'utf8',
      timeout: 10_000,
    });
  await writeFile(
    npmCli,
    `
    const { appendFileSync, existsSync } = require('node:fs');
    appendFileSync(${JSON.stringify(callLog)}, JSON.stringify({
      cwd: process.cwd(), args: process.argv.slice(2), installed: existsSync('node_modules')
    }) + '\\n');
    console.log(${JSON.stringify(JSON.stringify(cleanReport))});
  `,
  );
  const passed = execute();
  assert.ifError(passed.error);
  assert.equal(passed.status, 0, passed.stderr);
  assert.match(passed.stdout, /Dependency audit passed/);
  const calls = (await readFile(callLog, 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    calls,
    [directory, join(directory, 'docker/bw')].map((cwd) => ({
      cwd,
      args: [
        'audit',
        '--json',
        '--audit-level=high',
        '--package-lock-only',
        '--offline=false',
      ],
      installed: false,
    })),
  );
  await writeFile(
    npmCli,
    'console.log(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} }));\n',
  );
  const failed = execute();
  assert.ifError(failed.error);
  assert.equal(failed.status, 1, failed.stderr);
  assert.match(failed.stdout, /root: ERROR npm audit/);
  assert.match(failed.stdout, /docker\/bw: ERROR npm audit/);
  assert.match(failed.stdout, /Dependency audit FAILED/);
});
