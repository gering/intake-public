import { request } from 'node:http';
import { IntakeError } from './errors.js';

export function writerRequest(socketPath, path, id, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        path,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(timeoutMs),
      },
      (res) => {
        let bytes = 0;
        const chunks = [];
        res.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 4096) res.destroy();
          else chunks.push(chunk);
        });
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode >= 300) {
            if (res.statusCode === 409) {
              try {
                const parsed = JSON.parse(body);
                if (parsed?.error === 'ticket_not_revoked')
                  return reject(new IntakeError('ticket_not_revoked', 409));
              } catch {
                // A non-JSON conflict keeps the generic non-2xx failure.
              }
            }
            return reject(new IntakeError('writer_request_failed', 503));
          }
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new IntakeError('writer_invalid_response', 503));
          }
        });
        res.on('error', () =>
          reject(new IntakeError('writer_unavailable', 503)),
        );
      },
    );
    req.on('error', () => reject(new IntakeError('writer_unavailable', 503)));
    req.end(JSON.stringify({ id }));
  });
}
