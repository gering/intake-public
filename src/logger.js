const safeKeys = new Set([
  'id',
  'status',
  'code',
  'attempts',
  'notifyStatus',
  'waitedMs',
]);

export function redact(fields = {}) {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => {
      if (!safeKeys.has(key)) return [key, '[REDACTED]'];
      if (key === 'attempts' || key === 'waitedMs')
        return [key, Number.isSafeInteger(value) ? value : '[REDACTED]'];
      const pattern = key === 'id' ? /^[\w-]{22}$/ : /^[a-z][a-z0-9_]{0,63}$/;
      return [
        key,
        typeof value === 'string' && pattern.test(value) ? value : '[REDACTED]',
      ];
    }),
  );
}

export function createLogger(sink = process.stdout) {
  return {
    info(event, fields) {
      const name = /^[a-z][a-z_]{0,63}$/.test(event) ? event : 'redacted_event';
      sink.write(
        `${JSON.stringify({ time: new Date().toISOString(), event: name, ...redact(fields) })}\n`,
      );
    },
  };
}
