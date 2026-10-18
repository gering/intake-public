import { randomUUID } from 'node:crypto';
import { statSync } from 'node:fs';
import { request } from 'node:http';
import { dirname } from 'node:path';
import { IntakeError } from './errors.js';
import { isUnixSocketPath } from './socket-path.js';

export function checkVaultAccess(config, logger) {
  if (config.socketPath === undefined) {
    logger.info('vault_tcp_warning', { code: 'vault_tcp_local_users' });
    return;
  }
  if (!isUnixSocketPath(config.socketPath))
    throw new IntakeError('invalid_intake_bw_socket');
  let parent;
  try {
    parent = statSync(dirname(config.socketPath));
  } catch {
    throw new IntakeError('unsafe_vault_socket_directory');
  }
  if (
    !parent.isDirectory() ||
    parent.uid !== process.getuid() ||
    (parent.mode & 0o077) !== 0
  )
    throw new IntakeError('unsafe_vault_socket_directory');
}

export class VaultError extends Error {
  constructor(code, preDelivery = false) {
    super('Vault operation failed.');
    this.code = code;
    this.preDelivery = preDelivery;
    this.ambiguous = false;
  }
}

function vaultError(code, preDelivery = false) {
  return new VaultError(code, preDelivery);
}

function localUrl(value) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'http:' ||
      !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      String(value).includes('?') ||
      String(value).includes('#')
    ) {
      throw vaultError('vault_config');
    }
    return url.href.replace(/\/+$/, '');
  } catch {
    throw vaultError('vault_config');
  }
}

function markerName(field, name) {
  return field === name ? `${name}_reference` : name;
}

function writeInput(input) {
  const { target, keyName, purpose, value, ticketId, fingerprint } =
    input ?? {};
  if (
    !target ||
    typeof target.item !== 'string' ||
    !target.item.trim() ||
    typeof target.field !== 'string' ||
    !target.field.trim() ||
    typeof fingerprint !== 'string' ||
    !/^[a-f0-9]{16}$/.test(fingerprint) ||
    (target.notes != null && typeof target.notes !== 'string') ||
    ![keyName, purpose, value, ticketId].every(
      (entry) => typeof entry === 'string',
    )
  ) {
    throw vaultError('vault_input');
  }
  return {
    target: {
      item: target.item,
      field: target.field,
      notes: target.notes ?? '',
    },
    keyName,
    purpose,
    value,
    ticketId,
    fingerprint,
  };
}

export class MockVaultAdapter {
  entries = [];

  async lookup(input) {
    const { ticketId, fingerprint } = writeInput(input);
    const matches = this.entries.filter(
      (entry) =>
        entry.ticketId === ticketId && entry.fingerprint === fingerprint,
    );
    if (matches.length > 1) throw vaultError('vault_marker_ambiguous');
    return matches.length === 0 ? null : { itemId: matches[0].itemId };
  }

  async write(input) {
    const entry = writeInput(input);
    const itemId = randomUUID();
    this.entries.push({ ...entry, itemId });
    return { itemId };
  }
}

export class BwServeAdapter {
  #baseUrl;
  #socketPath;
  #organizationId;
  #collectionId;
  #sync;
  #timeoutMs;
  #maxResponseBytes;

  constructor({
    baseUrl,
    socketPath = baseUrl === undefined ? '/run/intake-bw/bw.sock' : undefined,
    organizationId,
    collectionId,
    sync = false,
    timeoutMs = 10000,
    maxResponseBytes = 1048576,
  } = {}) {
    if (
      typeof organizationId !== 'string' ||
      !organizationId.trim() ||
      typeof collectionId !== 'string' ||
      !collectionId.trim() ||
      typeof sync !== 'boolean' ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs <= 0 ||
      timeoutMs > 2147483647 ||
      !Number.isSafeInteger(maxResponseBytes) ||
      maxResponseBytes <= 0
    ) {
      throw vaultError('vault_config');
    }
    if (socketPath !== undefined) {
      if (baseUrl !== undefined || !isUnixSocketPath(socketPath))
        throw vaultError('vault_config');
      this.#socketPath = socketPath;
    } else this.#baseUrl = localUrl(baseUrl);
    this.#organizationId = organizationId;
    this.#collectionId = collectionId;
    this.#sync = sync;
    this.#timeoutMs = timeoutMs;
    this.#maxResponseBytes = maxResponseBytes;
  }

  async #request(path, method, body) {
    const signal = AbortSignal.timeout(this.#timeoutMs);
    let response;
    let connecting = false;
    let connected = false;
    try {
      response = await new Promise((resolve, reject) => {
        const options = {
          method,
          signal,
          // A fresh connection lets a failed connect prove zero delivery.
          agent: false,
          headers: { 'Content-Type': 'application/json' },
        };
        const req = this.#socketPath
          ? request(
              {
                ...options,
                socketPath: this.#socketPath,
                path,
                // bw serve validates HTTP Host even over its Unix socket.
                headers: { ...options.headers, Host: 'localhost:8087' },
              },
              resolve,
            )
          : request(`${this.#baseUrl}${path}`, options, resolve);
        req.on('socket', (socket) => {
          connecting = socket.connecting === true && !req.reusedSocket;
          connected = !connecting;
          socket.once('connect', () => {
            connected = true;
          });
        });
        req.on('error', reject);
        // HTTP 101 bypasses the response callback and transfers socket ownership.
        req.on('upgrade', (_response, socket) => {
          socket.destroy();
          reject(vaultError('vault_network'));
        });
        req.end(body === undefined ? undefined : JSON.stringify(body));
      });
    } catch (error) {
      // !finish and bytesWritten are not delivery proof: writes can be buffered
      // or partially delivered. Only a socket that never connected qualifies.
      const preDelivery =
        connecting &&
        !connected &&
        ['ECONNREFUSED', 'ENOENT', 'EACCES', 'ECONNRESET'].includes(error.code);
      throw vaultError(
        signal.aborted ? 'vault_timeout' : 'vault_network',
        preDelivery,
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      // The API may echo sensitive input in errors. Do not read its error body.
      response.destroy();
      throw vaultError(
        response.statusCode >= 300 && response.statusCode < 400
          ? 'vault_network'
          : `vault_http_${response.statusCode}`,
      );
    }
    let result;
    let responseBytes = 0;
    try {
      const chunks = [];
      for await (const chunk of response) {
        responseBytes += chunk.length;
        if (responseBytes > this.#maxResponseBytes) {
          // Destroying the response also closes the underlying request socket.
          response.destroy();
          throw vaultError('vault_response_too_large');
        }
        chunks.push(chunk);
      }
      result = JSON.parse(
        Buffer.concat(chunks, responseBytes).toString('utf8'),
      );
    } catch {
      throw vaultError(
        responseBytes > this.#maxResponseBytes
          ? 'vault_response_too_large'
          : signal.aborted
            ? 'vault_timeout'
            : 'vault_response',
      );
    }
    if (result?.success !== true) {
      throw vaultError('vault_response');
    }
    return result.data;
  }

  async lookup(input) {
    const { target, ticketId, fingerprint } = writeInput(input);
    await this.#request('/sync', 'POST');
    let listing;
    try {
      const query = new URLSearchParams({ collectionId: this.#collectionId });
      listing = await this.#request(`/list/object/items?${query}`, 'GET');
    } catch (error) {
      if (
        error instanceof VaultError &&
        error.code === 'vault_response_too_large'
      )
        throw vaultError('vault_lookup_too_large');
      throw error;
    }
    // The list contains collection secrets. Retain only a single matching ID.
    try {
      if (!Array.isArray(listing?.data)) throw vaultError('vault_response');
      const ticketField = markerName(target.field, 'intake_ticket_id');
      const fingerprintField = markerName(target.field, 'intake_fingerprint');
      let itemId = null;
      for (const item of listing.data) {
        if (
          item?.organizationId !== this.#organizationId ||
          !Array.isArray(item.collectionIds) ||
          !item.collectionIds.includes(this.#collectionId) ||
          !Array.isArray(item.fields)
        )
          continue;
        const markers = item.fields.filter(
          (field) => field?.name === ticketField && field.type === 0,
        );
        const fingerprints = item.fields.filter(
          (field) => field?.name === fingerprintField && field.type === 0,
        );
        if (
          !markers.some((field) => field.value === ticketId) ||
          fingerprints.length === 0 ||
          fingerprints.some((field) => field.value !== fingerprint)
        )
          continue;
        if (typeof item.id !== 'string' || !item.id.trim())
          throw vaultError('vault_response');
        if (itemId !== null) throw vaultError('vault_marker_ambiguous');
        itemId = item.id;
      }
      return itemId === null ? null : { itemId };
    } finally {
      if (Array.isArray(listing?.data)) listing.data.length = 0;
    }
  }

  async isReady() {
    try {
      const data = await this.#request('/status', 'GET');
      return data?.template?.status === 'unlocked';
    } catch {
      return false;
    }
  }

  async write(input) {
    const { target, value, ticketId, fingerprint } = writeInput(input);
    const login = ['username', 'password'].includes(target.field);
    const item = {
      organizationId: this.#organizationId,
      collectionIds: [this.#collectionId],
      type: login ? 1 : 2,
      name: target.item,
      notes: target.notes,
      fields: [
        ...(login ? [] : [{ name: target.field, value, type: 1 }]),
        {
          name: markerName(target.field, 'intake_ticket_id'),
          value: ticketId,
          type: 0,
        },
        {
          name: markerName(target.field, 'intake_fingerprint'),
          value: fingerprint,
          type: 0,
        },
      ],
      ...(login
        ? {
            login: {
              uris: [],
              username: target.field === 'username' ? value : null,
              password: target.field === 'password' ? value : null,
              totp: null,
            },
          }
        : { secureNote: { type: 0 } }),
    };

    if (this.#sync) {
      try {
        await this.#request('/sync', 'POST');
      } catch (error) {
        // No item request has started, regardless of how sync failed.
        if (error instanceof VaultError) error.preDelivery = true;
        throw error;
      }
    }
    // No inline retry: a disconnected response may already have created an item.
    try {
      const created = await this.#request('/object/item', 'POST', item);
      if (typeof created?.id !== 'string' || !created.id.trim()) {
        throw vaultError('vault_response');
      }
      return { itemId: created.id };
    } catch (error) {
      // bw serve also maps upstream save errors to 400, not only rejections.
      if (error instanceof VaultError && !error.preDelivery)
        error.ambiguous = true;
      throw error;
    }
  }
}
