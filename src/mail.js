import { setTimeout as sleep } from 'node:timers/promises';

function configurationError() {
  return Object.assign(new Error('Invalid mail configuration.'), {
    code: 'mail_config',
  });
}

function isAddress(value) {
  return typeof value === 'string' && /^[^\s@<>,;]+@[^\s@<>,;]+$/.test(value);
}

function mailUrl(value) {
  try {
    const url = new URL(value);
    const local = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
    if (
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      String(value).includes('?') ||
      String(value).includes('#')
    ) {
      throw configurationError();
    }
    return url.href.replace(/\/+$/, '');
  } catch {
    throw configurationError();
  }
}

function messageFor(ticket) {
  if (
    !ticket ||
    !['done', 'failed'].includes(ticket.status) ||
    !isAddress(ticket.notifyEmail) ||
    !ticket.target ||
    ![
      ticket.id,
      ticket.keyName,
      ticket.purpose,
      ticket.target.item,
      ticket.target.field,
    ].every((value) => typeof value === 'string') ||
    ![ticket.completedAt, ticket.fingerprint].every(
      (value) => value == null || typeof value === 'string',
    )
  ) {
    throw new Error('Invalid notification metadata.');
  }

  const outcome = ticket.status === 'done' ? 'completed' : 'failed';
  return {
    to: [ticket.notifyEmail],
    subject: `Intake ticket ${outcome}`,
    text: [
      `Intake ticket ${outcome}.`,
      `Ticket ID: ${ticket.id}`,
      `Key name: ${ticket.keyName}`,
      `Purpose: ${ticket.purpose}`,
      `Completed at: ${ticket.completedAt ?? 'Not available'}`,
      `Fingerprint: ${ticket.fingerprint ?? 'Not available'}`,
      `Target item: ${ticket.target.item}`,
      `Target field: ${ticket.target.field}`,
    ].join('\n'),
  };
}

async function forbiddenError(response) {
  try {
    if (!response.body) return 'http_403';
    const chunks = [];
    let bytes = 0;
    // Only inspect a small 403 body, and expose exact allowlisted codes, never text.
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > 4096) return 'http_403';
      chunks.push(chunk);
    }
    const code = JSON.parse(
      Buffer.concat(chunks, bytes).toString('utf8'),
    )?.error;
    if (code === 'recipient_not_allowed') return 'recipient_not_allowed';
    if (code === 'send_not_allowed') return 'send_not_allowed';
  } catch {
    // A missing, malformed, or interrupted body cannot make a 403 retryable.
  }
  return 'http_403';
}

export class MailNotifier {
  #url;
  #token;
  #timeoutMs;
  #backoffMs;

  constructor({
    url,
    token,
    mailbox,
    timeoutMs = 10000,
    backoffMs = [1000, 3000],
  } = {}) {
    if (
      typeof token !== 'string' ||
      !token ||
      [...token].some((character) => {
        const code = character.charCodeAt(0);
        return code <= 32 || code === 127 || code > 255;
      }) ||
      !isAddress(mailbox) ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs <= 0 ||
      timeoutMs > 2147483647 ||
      !Array.isArray(backoffMs) ||
      !backoffMs.every(
        (delay) => Number.isInteger(delay) && delay >= 0 && delay <= 2147483647,
      )
    ) {
      throw configurationError();
    }
    this.#url = `${mailUrl(url)}/v1/mailboxes/${encodeURIComponent(mailbox)}/send`;
    this.#token = token;
    this.#timeoutMs = timeoutMs;
    this.#backoffMs = backoffMs.slice(0, 2);
  }

  async send(ticket) {
    let body;
    try {
      // Deliberately do not serialize the ticket, target notes, or envelope.
      body = JSON.stringify(messageFor(ticket));
    } catch {
      return {
        status: 'failed',
        attempts: 0,
        error: 'invalid_ticket',
        notifiedAt: null,
      };
    }

    for (let attempt = 0; ; attempt += 1) {
      const signal = AbortSignal.timeout(this.#timeoutMs);
      let error;
      let retryable = false;
      try {
        const response = await fetch(this.#url, {
          method: 'POST',
          redirect: 'error',
          signal,
          headers: {
            Authorization: `Bearer ${this.#token}`,
            'Content-Type': 'application/json',
          },
          body,
        });
        if (response.ok) {
          const text = await response.text();
          let result;
          try {
            result = JSON.parse(text);
          } catch {
            // A successful API response need not contain JSON (including 204).
          }
          if (Array.isArray(result?.rejected) && result.rejected.length > 0) {
            error = 'rejected';
          } else {
            return {
              status: 'sent',
              attempts: attempt + 1,
              error: null,
              notifiedAt: new Date().toISOString(),
            };
          }
        } else {
          error = `http_${response.status}`;
          retryable =
            response.status === 429 ||
            (response.status >= 500 && response.status < 600);
          if (response.status === 403) {
            error = await forbiddenError(response);
          } else {
            // Other error bodies may echo secrets; do not inspect them.
            await response.body?.cancel().catch(() => {});
          }
        }
      } catch {
        error = signal.aborted ? 'timeout' : 'network';
        retryable = true;
      }

      if (!retryable || attempt >= this.#backoffMs.length) {
        return {
          status: 'failed',
          attempts: attempt + 1,
          error,
          notifiedAt: null,
        };
      }
      await sleep(this.#backoffMs[attempt]);
    }
  }
}
