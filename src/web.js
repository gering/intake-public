import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { assertNonRoot, IntakeError } from './errors.js';
import {
  securityHeaders,
  json,
  readJson,
  listen,
  closeServer,
} from './http.js';
import { RateLimiter } from './rate-limit.js';
import { parseToken } from './tokens.js';
import { writerRequest } from './ipc.js';
import { createLogger } from './logger.js';

const assets = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/crypto.js': ['crypto.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
};

export async function startWeb({ store, config, logger = createLogger() }) {
  assertNonRoot();
  const headers = { ...securityHeaders };
  if (config.hstsMaxAge === 0) delete headers['Strict-Transport-Security'];
  else
    headers['Strict-Transport-Security'] =
      `max-age=${config.hstsMaxAge ?? 31536000}${config.hstsIncludeSubDomains === false ? '' : '; includeSubDomains'}`;
  const files = new Map(
    await Promise.all(
      Object.entries(assets).map(async ([path, [file, type]]) => [
        path,
        {
          type,
          body: await readFile(new URL(`../public/${file}`, import.meta.url)),
        },
      ]),
    ),
  );
  const limiter = new RateLimiter({
    windowMs: config.rateWindowMs,
    ipLimit: config.ipLimit,
    ipv6Limit48: config.ipv6Limit48,
    ticketLimit: config.ticketLimit,
    maxEntries: config.rateMaxEntries,
  });
  const ipHeaderWarnings = new Map();
  const server = createServer(
    { requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 8192 },
    async (req, res) => {
      let id;
      try {
        const path = req.url;
        if (
          (req.method === 'GET' || req.method === 'HEAD') &&
          path === '/healthz'
        ) {
          res.writeHead(204, headers);
          res.end();
          return;
        }
        if (
          (req.method === 'GET' || req.method === 'HEAD') &&
          files.has(path)
        ) {
          const file = files.get(path);
          res.writeHead(200, { ...headers, 'Content-Type': file.type });
          res.end(req.method === 'HEAD' ? undefined : file.body);
          return;
        }
        if (
          req.method !== 'POST' ||
          !['/api/open', '/api/submit'].includes(path)
        )
          throw new IntakeError('not_found', 404);
        if (
          req.headers['sec-fetch-site'] === 'cross-site' ||
          (req.headers.origin && req.headers.origin !== config.publicUrl)
        )
          throw new IntakeError('origin_rejected', 403);
        let ip = req.socket.remoteAddress ?? 'unknown';
        if (config.clientIpHeader) {
          const values = req.headersDistinct[config.clientIpHeader];
          const forwarded = values?.length === 1 ? values[0].trim() : undefined;
          if (forwarded && isIP(forwarded)) ip = forwarded;
          else {
            const code = values
              ? 'invalid_client_ip_header'
              : 'missing_client_ip_header';
            const now = performance.now();
            if (
              !ipHeaderWarnings.has(code) ||
              now >= ipHeaderWarnings.get(code)
            ) {
              logger.info('client_ip_header_warning', { code });
              ipHeaderWarnings.set(code, now + 60000);
            }
            throw new IntakeError('request_rejected', 400);
          }
        } else if (config.trustProxy && req.headers['x-forwarded-for']) {
          const forwarded = req.headers['x-forwarded-for']
            .split(',')
            .at(-1)
            .trim();
          if (isIP(forwarded)) ip = forwarded;
        }
        // Charge malformed/oversized bodies against the IP bucket too.
        if (!limiter.allowClient(ip))
          throw new IntakeError('rate_limited', 429);
        const body = await readJson(req, config.bodyLimit ?? 100000);
        id = parseToken(body.token)?.id;
        if (id && limiter.ticketBlocked(id))
          throw new IntakeError('rate_limited', 429);
        if (path === '/api/open') {
          const ticket = store.open(body.token);
          json(res, 200, ticket, headers);
        } else {
          const result = store.claim(body.token, body.envelope);
          logger.info('ticket_claimed', {
            id: result.id,
            status: result.status,
          });
          // The committed queue is authoritative; a missed wake-up is recovered by polling.
          void writerRequest(
            config.socketPath,
            '/process',
            result.id,
            config.ipcTimeoutMs,
          ).catch(() =>
            logger.info('writer_wakeup_failed', {
              id: result.id,
              code: 'writer_unavailable',
            }),
          );
          json(res, 202, { status: result.status }, headers);
        }
      } catch (error) {
        const known = error instanceof IntakeError;
        if (known && error.code === 'ticket_unavailable' && id)
          limiter.allowTicketFailure(id);
        if (!known) logger.info('web_error', { code: 'internal_error' });
        if (known && error.code === 'body_too_large') {
          res.setHeader('Connection', 'close');
          res.once('finish', () => req.destroy());
        }
        json(
          res,
          known ? error.status : 500,
          {
            error: known ? error.code : 'internal_error',
          },
          headers,
        );
      }
    },
  );
  server.on('checkExpectation', (req, res) => {
    req.resume();
    json(res, 417, { error: 'expectation_failed' }, headers);
  });
  server.on('clientError', (_error, socket) => {
    socket.end(
      `HTTP/1.1 400 Bad Request\r\n${Object.entries(headers)
        .map(([key, value]) => `${key}: ${value}\r\n`)
        .join('')}Content-Length: 0\r\nConnection: close\r\n\r\n`,
    );
  });
  await listen(server, {
    host: config.host ?? '127.0.0.1',
    port: config.port ?? 3000,
  });
  logger.info('web_started');
  return { server, close: () => closeServer(server) };
}
