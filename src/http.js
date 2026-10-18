import { IntakeError } from './errors.js';

export const securityHeaders = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

export function json(res, status, body, headers = securityHeaders) {
  res.writeHead(status, {
    ...headers,
    'Content-Type': 'application/json; charset=utf-8',
  });
  res.end(JSON.stringify(body));
}

export function readJson(req, maxBytes) {
  if (
    !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
      req.headers['content-type'] ?? '',
    )
  ) {
    req.resume();
    return Promise.reject(new IntakeError('json_required', 415));
  }
  return new Promise((resolve, reject) => {
    let bytes = 0;
    let failed = false;
    const chunks = [];
    req.on('data', (chunk) => {
      if (failed) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        failed = true;
        chunks.length = 0;
        req.pause();
        reject(new IntakeError('body_too_large', 413));
      } else chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || typeof body !== 'object' || Array.isArray(body))
          throw new Error();
        resolve(body);
      } catch {
        reject(new IntakeError('invalid_json'));
      }
    });
    req.on('error', () => reject(new IntakeError('request_aborted')));
    req.on('aborted', () => reject(new IntakeError('request_aborted')));
  });
}

export async function listen(server, address) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(address, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

export async function closeServer(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
    server.closeIdleConnections();
  });
}
