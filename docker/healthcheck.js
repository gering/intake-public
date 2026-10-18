import { get } from 'node:http';

export async function checkHealth(role, env = process.env) {
  let options;
  if (role === 'web') {
    options = {
      hostname: '127.0.0.1',
      port: env.PORT ?? 3000,
      path: '/healthz',
    };
  } else if (role === 'writer') {
    options = {
      socketPath: env.INTAKE_SOCKET ?? '/run/intake/writer.sock',
      path: '/healthz',
    };
  } else if (role === 'bw') {
    options = {
      socketPath: env.INTAKE_BW_SOCKET ?? '/run/intake-bw/bw.sock',
      path: '/status',
      headers: { Host: 'localhost:8087' },
    };
  } else throw new Error('invalid_healthcheck_role');
  await new Promise((resolve, reject) => {
    const request = get({ ...options, agent: false }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 16384)
          request.destroy(new Error('healthcheck_response_large'));
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          if (response.statusCode !== (role === 'bw' ? 200 : 204))
            throw new Error('healthcheck_failed');
          if (role === 'bw') {
            const data = JSON.parse(body);
            if (
              data.success !== true ||
              data.data?.template?.status !== 'unlocked'
            )
              throw new Error('vault_not_unlocked');
          }
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(2000, () =>
      request.destroy(new Error('healthcheck_timeout')),
    );
    request.on('error', reject);
  });
}

if (import.meta.main) {
  try {
    await checkHealth(process.argv[2]);
  } catch {
    process.exitCode = 1;
  }
}
