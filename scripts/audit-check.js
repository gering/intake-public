import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const targets = ['root', 'docker/bw'];
const severities = ['info', 'low', 'moderate', 'high', 'critical'];
const advisoryId = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const key = (entry) => `${entry.target}:${entry.id}:${entry.package}`;
const isObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function validateTarget(target) {
  if (!targets.includes(target))
    throw new Error('Audit target must be root or docker/bw');
}

function validDay(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    return false;
  const date = new Date(value);
  return (
    Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value
  );
}

export function validateAllowlist(value, { today = new Date() } = {}) {
  const day = today instanceof Date ? today.toISOString().slice(0, 10) : today;
  if (!validDay(day)) throw new Error('today must be a valid UTC date');
  if (
    !isObject(value) ||
    Object.keys(value).some((field) => field !== 'entries') ||
    !Array.isArray(value.entries)
  ) {
    throw new Error('Audit allowlist must contain only an entries array');
  }
  const seen = new Set();
  return value.entries.map((entry, index) => {
    const label = `Audit allowlist entry ${index + 1}`;
    if (
      !isObject(entry) ||
      Object.keys(entry).some(
        (field) =>
          !['target', 'id', 'package', 'reason', 'expires'].includes(field),
      )
    ) {
      throw new Error(`${label} has unknown fields or is not an object`);
    }
    if (!targets.includes(entry.target))
      throw new Error(`${label} needs a target of root or docker/bw`);
    if (typeof entry.id !== 'string' || !advisoryId.test(entry.id)) {
      throw new Error(`${label} needs a GHSA id (GHSA-xxxx-xxxx-xxxx)`);
    }
    if (typeof entry.package !== 'string' || !packageName.test(entry.package)) {
      throw new Error(`${label} needs an exact npm package name`);
    }
    if (
      typeof entry.reason !== 'string' ||
      entry.reason.trim().length < 10 ||
      /\b(?:todo|tbd|fixme|placeholder)\b/i.test(entry.reason) ||
      /^(?:temporary exception|no reason provided|not applicable|testing only)[.!\s]*$/i.test(
        entry.reason.trim(),
      )
    ) {
      throw new Error(
        `${label} needs a non-placeholder reason of at least 10 characters`,
      );
    }
    if (!validDay(entry.expires))
      throw new Error(`${label} needs a real YYYY-MM-DD expiry date`);
    if (entry.expires < day) throw new Error(`${label} has expired`);
    if (seen.has(key(entry)))
      throw new Error(`${label} duplicates a target/advisory/package identity`);
    seen.add(key(entry));
    return { ...entry, reason: entry.reason.trim() };
  });
}

export function parseAllowlist(text, options) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Audit allowlist is not valid JSON');
  }
  return validateAllowlist(value, options);
}

function validateAuditReport(report) {
  if (
    !isObject(report) ||
    Object.hasOwn(report, 'error') ||
    report.auditReportVersion !== 2 ||
    !isObject(report.vulnerabilities) ||
    !isObject(report.metadata) ||
    !isObject(report.metadata.vulnerabilities) ||
    [...severities, 'total'].some(
      (severity) =>
        !Number.isSafeInteger(report.metadata.vulnerabilities[severity]) ||
        report.metadata.vulnerabilities[severity] < 0,
    )
  ) {
    throw new Error(
      'npm audit returned an unsupported or incomplete report; check registry connectivity',
    );
  }
  const vulnerabilities = Object.values(report.vulnerabilities);
  const counts = Object.fromEntries(
    severities.map((severity) => [severity, 0]),
  );
  for (const vulnerability of vulnerabilities) {
    if (
      !isObject(vulnerability) ||
      !severities.includes(vulnerability.severity) ||
      !Array.isArray(vulnerability.via)
    ) {
      throw new Error('npm audit returned a malformed vulnerability');
    }
    // npm audit v2 counts each vulnerable package once, by its package severity.
    counts[vulnerability.severity]++;
  }
  const metadata = report.metadata.vulnerabilities;
  if (
    severities.some((severity) => metadata[severity] !== counts[severity]) ||
    metadata.total !==
      severities.reduce((total, severity) => total + metadata[severity], 0) ||
    metadata.total !== vulnerabilities.length
  ) {
    throw new Error(
      'npm audit metadata counts do not match the reported vulnerabilities',
    );
  }
}

export function parseAuditOutput(text, status = 0) {
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    throw new Error(
      'npm audit returned unparsable JSON; check npm and registry connectivity',
    );
  }
  if (
    !isObject(report) ||
    Object.hasOwn(report, 'error') ||
    ![0, 1].includes(status)
  ) {
    throw new Error(
      'npm audit failed; check npm, registry connectivity, and registry credentials',
    );
  }
  validateAuditReport(report);
  if (
    status === 1 &&
    report.metadata.vulnerabilities.high +
      report.metadata.vulnerabilities.critical ===
      0
  ) {
    throw new Error(
      'npm audit exited nonzero without high/critical advisory details',
    );
  }
  return report;
}

export function extractAdvisories(report, target = 'root') {
  validateTarget(target);
  validateAuditReport(report);
  const advisories = new Map();
  for (const vulnerability of Object.values(report.vulnerabilities)) {
    for (const via of vulnerability.via) {
      // Strings are transitive references; their advisory objects live in the referenced package.
      if (typeof via === 'string' && Object.hasOwn(report.vulnerabilities, via))
        continue;
      if (
        !isObject(via) ||
        !severities.includes(via.severity) ||
        typeof via.name !== 'string' ||
        !packageName.test(via.name)
      ) {
        throw new Error('npm audit returned a malformed advisory');
      }
      const match =
        typeof via.url === 'string' &&
        /^https:\/\/github\.com\/advisories\/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/.exec(
          via.url,
        );
      if (!match)
        throw new Error(
          'npm audit advisory has no supported GHSA URL; review the report manually',
        );
      const advisory = {
        target,
        id: match[1],
        package: via.name,
        severity: via.severity,
      };
      const previous = advisories.get(key(advisory));
      if (
        !previous ||
        severities.indexOf(advisory.severity) >
          severities.indexOf(previous.severity)
      ) {
        advisories.set(key(advisory), advisory);
      }
    }
  }
  const resolved = new Map();
  const dependents = new Map();
  const pending = [];
  for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
    let severity = -1;
    for (const via of vulnerability.via) {
      if (typeof via === 'string') {
        if (!dependents.has(via)) dependents.set(via, []);
        dependents.get(via).push(name);
      } else {
        severity = Math.max(severity, severities.indexOf(via.severity));
      }
    }
    resolved.set(name, severity);
    if (severity >= 0) pending.push(name);
  }
  // Cache and propagate only severity increases, bounding work even with shared descendants or cycles.
  for (let index = 0; index < pending.length; index++) {
    const name = pending[index];
    for (const dependent of dependents.get(name) ?? []) {
      if (resolved.get(dependent) >= resolved.get(name)) continue;
      resolved.set(dependent, resolved.get(name));
      pending.push(dependent);
    }
  }
  for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
    if (
      ['high', 'critical'].includes(vulnerability.severity) &&
      resolved.get(name) < severities.indexOf(vulnerability.severity)
    ) {
      throw new Error(
        'npm audit reports high/critical vulnerabilities without matching advisory details',
      );
    }
  }
  const result = [...advisories.values()];
  if (
    report.metadata.vulnerabilities.high +
      report.metadata.vulnerabilities.critical >
      0 &&
    !result.some((advisory) => ['high', 'critical'].includes(advisory.severity))
  ) {
    throw new Error(
      'npm audit reports high/critical vulnerabilities without matching advisory details',
    );
  }
  return result;
}

export function extractHighAdvisories(report, target = 'root') {
  return extractAdvisories(report, target).filter((advisory) =>
    ['high', 'critical'].includes(advisory.severity),
  );
}

export function evaluateAdvisories(advisories, entries) {
  const relevant = advisories.filter((advisory) =>
    ['high', 'critical'].includes(advisory.severity),
  );
  const allowedKeys = new Set(entries.map(key));
  const currentKeys = new Set(advisories.map(key));
  return {
    allowed: relevant.filter((advisory) => allowedKeys.has(key(advisory))),
    blocked: relevant.filter((advisory) => !allowedKeys.has(key(advisory))),
    stale: entries.filter((entry) => !currentKeys.has(key(entry))),
  };
}

export function auditTarget(
  root,
  target,
  { run = spawnSync, npmCli = process.env.npm_execpath } = {},
) {
  validateTarget(target);
  const args = [
    'audit',
    '--json',
    '--audit-level=high',
    '--package-lock-only',
    '--offline=false',
  ];
  // npm run exposes the JS entrypoint, avoiding Windows command-shim/shell handling.
  const cli =
    npmCli ||
    (process.platform === 'win32'
      ? resolve(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')
      : null);
  const result = run(
    cli ? process.execPath : 'npm',
    cli ? [cli, ...args] : args,
    {
      cwd: target === 'root' ? root : resolve(root, target),
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (result.error || result.signal)
    throw new Error(
      'npm audit could not complete; check npm and registry connectivity',
    );
  return parseAuditOutput(result.stdout, result.status);
}

export async function runAuditChecks({
  root = resolve(dirname(fileURLToPath(import.meta.url)), '..'),
  today = new Date(),
  audit = auditTarget,
  log = console.log,
} = {}) {
  const entries = parseAllowlist(
    await readFile(resolve(root, '.audit-allowlist.json'), 'utf8'),
    { today },
  );
  const current = [];
  let failed = false;
  for (const target of targets) {
    try {
      const advisories = extractAdvisories(await audit(root, target), target);
      current.push(...advisories);
      const counts = severities.map(
        (severity) =>
          `${severity}=${advisories.filter((a) => a.severity === severity).length}`,
      );
      const result = evaluateAdvisories(advisories, entries);
      log(
        `${target}: advisories ${counts.join(' ')}; allowed=${result.allowed.length} blocked=${result.blocked.length}`,
      );
      for (const advisory of result.allowed)
        log(
          `  ALLOWED ${advisory.severity} ${advisory.id} ${advisory.package}`,
        );
      for (const advisory of result.blocked)
        log(
          `  BLOCKED ${advisory.severity} ${advisory.id} ${advisory.package}`,
        );
      failed ||= result.blocked.length > 0;
    } catch (error) {
      log(`${target}: ERROR ${error.message}`);
      failed = true;
    }
  }
  // Only declare entries stale after every target was successfully audited and passed.
  if (!failed) {
    for (const entry of evaluateAdvisories(current, entries).stale) {
      log(
        `WARNING stale audit exception: ${entry.target} ${entry.id} ${entry.package}; remove it if no longer needed`,
      );
    }
  }
  log(`Dependency audit ${failed ? 'FAILED' : 'passed'}`);
  return failed ? 1 : 0;
}

function isEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    return (
      realpathSync(process.argv[1]) ===
      realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  try {
    process.exitCode = await runAuditChecks();
  } catch (error) {
    console.error(`Dependency audit FAILED: ${error.message}`);
    process.exitCode = 1;
  }
}
