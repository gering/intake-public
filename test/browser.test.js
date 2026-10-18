import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  readAndClearFragment,
  failureState,
  mountApp,
  valueEntry,
} from '../public/app.js';

const html = await readFile(
  new URL('../public/index.html', import.meta.url),
  'utf8',
);
const token = 'a'.repeat(22) + '.' + 'b'.repeat(43);
const ticket = {
  id: 'a'.repeat(22),
  keyName: 'DB_PASSWORD',
  purpose: 'Connect the application',
  expiresAt: '2026-10-19T12:00:00.000Z',
  trim: true,
};

class Element {
  constructor(document, id, attributes) {
    this.document = document;
    this.id = id;
    this.attributes = new Map(
      [...attributes.matchAll(/([\w-]+)="([^"]*)"/g)].map((match) => [
        match[1],
        match[2],
      ]),
    );
    this.hidden = /\bhidden\b/.test(attributes);
    this.type = this.attributes.get('type');
    this.value = '';
    this.textContent = '';
    this.disabled = false;
    this.listeners = new Map();
    this.children = [];
  }
  setAttribute(name, value) {
    this.attributes.set(name, value);
  }
  getAttribute(name) {
    return this.attributes.get(name);
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }
  addEventListener(name, listener) {
    this.listeners.set(name, listener);
  }
  async emit(name, fields = {}) {
    await this.listeners.get(name)?.({ preventDefault() {}, ...fields });
  }
  focus() {
    this.document.activeElement = this;
  }
  querySelector(selector) {
    assert.equal(selector, 'h1');
    return this.document.getElementById(this.id.replace('state-', 'h-'));
  }
  remove() {
    for (const id of [this.id, ...this.children])
      this.document.elements.delete(id);
  }
}

function documentFixture() {
  const document = {
    elements: new Map(),
    getElementById(id) {
      return this.elements.get(id) ?? null;
    },
  };
  for (const match of html.matchAll(/<[\w-]+\b([^>]*\bid="([^"]+)"[^>]*)>/g))
    document.elements.set(match[2], new Element(document, match[2], match[1]));
  for (const match of html.matchAll(
    /<section\b[^>]*id="([^"]+)"[^>]*>([\s\S]*?)<\/section>/g,
  ))
    document.elements.get(match[1]).children = [
      ...match[2].matchAll(/\bid="([^"]+)"/g),
    ].map((child) => child[1]);
  return document;
}

function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function clientFixture({
  openedTicket = ticket,
  openResponse,
  submitResponse,
  network = false,
  linkToken = token,
} = {}) {
  const document = documentFixture();
  const calls = [];
  const encrypted = [];
  mountApp({
    document,
    token: linkToken,
    fetch: async (path, options) => {
      calls.push({ path, ...options, body: JSON.parse(options.body) });
      if (path === '/api/open')
        return openResponse ?? response(200, openedTicket);
      if (network) throw new TypeError('network error');
      return submitResponse ?? response(202, { status: 'pending' });
    },
    encrypt: async (metadata, value) => {
      encrypted.push({ metadata, value });
      return { encrypted: true };
    },
  });
  return {
    document,
    calls,
    encrypted,
    el: (id) => document.getElementById(id),
  };
}

test('fragment is read once and immediately removed before parsing, initialization or requests', async () => {
  let reads = 0;
  const events = [];
  const location = {
    get hash() {
      reads++;
      events.push('read');
      return '#req=' + token;
    },
    pathname: '/',
    search: '?state=success&demo=shown',
  };
  const history = {
    replaceState(...args) {
      events.push('clear');
      assert.deepEqual(args, [null, '', '/?state=success&demo=shown']);
    },
  };
  const captured = readAndClearFragment(location, history);
  assert.equal(reads, 1);
  assert.deepEqual(events, ['read', 'clear']);
  assert.equal(captured, token);
  const f = clientFixture({ linkToken: captured });
  assert.equal(f.calls.length, 0);
  assert.equal(f.el('state-landing').hidden, false);
  assert.equal(f.el('state-success').hidden, true);
  assert.equal(f.el('secret').value, '');
  await f.el('open-form').emit('click');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].path, '/api/open');
  assert.equal(f.calls[0].body.token, token);
});

test('malformed or missing fragments are cleared and produce only the invalid page without a request', () => {
  for (const hash of [
    '',
    '#req=bad',
    '#state=form',
    '#req=' + token + '&state=form',
  ]) {
    let cleaned = false;
    const captured = readAndClearFragment(
      { hash, pathname: '/', search: '' },
      {
        replaceState() {
          cleaned = true;
        },
      },
    );
    assert(cleaned);
    assert.equal(captured, null);
    const f = clientFixture({ linkToken: captured });
    assert.equal(f.el('state-invalid').hidden, false);
    assert.equal(f.el('secret'), null);
    assert.equal(f.el('open-form'), null);
    assert.equal(f.calls.length, 0);
  }
});

test('real form metadata comes from open, the hint is static and trim-neutral; the eye toggle preserves the value', async () => {
  for (const trim of [true, false]) {
    const f = clientFixture({ openedTicket: { ...ticket, trim } });
    await f.el('open-form').emit('click');
    assert.equal(f.el('state-form').hidden, false);
    assert.equal(f.el('state-landing').hidden, true);
    assert.equal(f.el('f-key').textContent, ticket.keyName);
    assert.equal(f.el('f-purpose').textContent, ticket.purpose);
    assert.equal(f.el('f-expires').dateTime, ticket.expiresAt);
    // The hint is static markup; open must not rewrite it per trim mode.
    assert.equal(f.el('secret-hint').textContent, '');
    const input = f.el('secret');
    const toggle = f.el('toggle');
    input.value = '  value\nwith line breaks  ';
    assert.equal(input.getAttribute('data-visible'), 'false');
    await toggle.emit('click');
    assert.equal(input.getAttribute('data-visible'), 'true');
    assert.equal(toggle.getAttribute('aria-label'), 'Hide secret');
    assert.equal(toggle.getAttribute('aria-pressed'), 'true');
    assert.equal(input.value, '  value\nwith line breaks  ');
    await toggle.emit('click');
    assert.equal(input.getAttribute('data-visible'), 'false');
    assert.equal(toggle.getAttribute('aria-label'), 'Show secret');
    assert.equal(toggle.getAttribute('aria-pressed'), 'false');
    assert.equal(input.value, '  value\nwith line breaks  ');
  }
});

async function pasteInto(input, text, start = 0, end = input.value.length) {
  input.selectionStart = start;
  input.selectionEnd = end;
  const old = input.value;
  await input.emit('paste', {
    clipboardData: {
      getData(format) {
        assert.equal(format, 'text/plain');
        return text;
      },
    },
  });
  input.value = (old.slice(0, start) + text + old.slice(end)).replace(
    /\r\n?/g,
    '\n',
  );
  await input.emit('input');
}

test('value entry preserves raw clipboard line endings through normalized display, edits and clearing', async () => {
  const input = documentFixture().getElementById('secret');
  const entry = valueEntry(input);
  const raw = 'A\r\nB\rC\nD';
  await pasteInto(input, raw);
  assert.equal(input.value, 'A\nB\nC\nD');
  assert.equal(entry.read(), raw);
  await pasteInto(input, 'X\r\nY', 2, 3);
  assert.equal(entry.read(), 'A\r\nX\r\nY\rC\nD');
  input.value = input.value.replace('C', 'changed');
  await input.emit('input');
  assert.equal(entry.read(), 'A\r\nX\r\nY\rchanged\nD');
  input.value = input.value.slice(0, 1) + input.value.slice(2);
  await input.emit('input');
  assert.equal(entry.read(), 'AX\r\nY\rchanged\nD');
  input.value += '\nend';
  await input.emit('input');
  assert.equal(entry.read(), 'AX\r\nY\rchanged\nD\nend');
  entry.clear();
  assert.equal(input.value, '');
  assert.equal(entry.read(), '');
});

test('pasted raw newlines reach encryption unchanged in both modes, including a newline-only kept value', async () => {
  for (const [trim, raw] of [
    [true, '\r\nalpha\r\nbeta\r\n'],
    [false, '\r\nalpha\r\nbeta\r\n'],
    [false, '\r\n'],
  ]) {
    const f = clientFixture({ openedTicket: { ...ticket, trim } });
    await f.el('open-form').emit('click');
    await pasteInto(f.el('secret'), raw);
    await f.el('toggle').emit('click');
    await f.el('toggle').emit('click');
    await f.el('secret-form').emit('submit');
    assert.equal(f.encrypted[0].value, raw);
    assert.equal(f.el('secret'), null);
  }
  const f = clientFixture();
  await f.el('open-form').emit('click');
  await pasteInto(f.el('secret'), '\r\n');
  await f.el('secret-form').emit('submit');
  assert.equal(f.encrypted.length, 0);
  assert.equal(f.el('secret-err').hidden, false);
});

test('browser rejects empty normalized values without encryption or submission', async () => {
  for (const [trim, value] of [
    [true, ' \t\n﻿'],
    [false, ''],
  ]) {
    const f = clientFixture({ openedTicket: { ...ticket, trim } });
    await f.el('open-form').emit('click');
    f.el('secret').value = value;
    await f.el('secret-form').emit('submit');
    assert.equal(f.encrypted.length, 0);
    assert.equal(f.calls.length, 1);
    assert.equal(f.el('secret-err').hidden, false);
    assert.equal(f.el('secret').getAttribute('aria-invalid'), 'true');
    assert.equal(f.el('state-form').hidden, false);
  }
});

test('successful real submit clears and removes form, shows queued confirmation without a fingerprint', async () => {
  const f = clientFixture({ openedTicket: { ...ticket, trim: false } });
  await f.el('open-form').emit('click');
  const input = f.el('secret');
  input.value = '  keep exact  ';
  await f.el('secret-form').emit('submit');
  assert.equal(f.calls.length, 2);
  assert.deepEqual(f.encrypted, [
    { metadata: { ...ticket, trim: false }, value: '  keep exact  ' },
  ]);
  assert.equal(f.calls[1].path, '/api/submit');
  assert.equal(f.calls[1].credentials, 'omit');
  assert.equal(f.calls[1].cache, 'no-store');
  assert.equal(f.calls[1].redirect, 'error');
  assert.deepEqual(f.calls[1].body, { token, envelope: { encrypted: true } });
  assert.equal(input.value, '');
  assert.equal(f.el('secret'), null);
  assert.equal(f.el('open-form'), null);
  assert.equal(f.el('state-success').hidden, false);
  assert.equal(f.el('s-key').textContent, ticket.keyName);
  assert.equal(f.el('s-fp'), null);
  assert.doesNotMatch(
    html.match(/id="state-success"[\s\S]*?<\/section>/)[0],
    /fingerprint/i,
  );
  assert(f.el('s-time').dateTime);
});

test('final API errors remove the form and every retry control even on a concurrent submit failure', async () => {
  for (const phase of ['open', 'submit']) {
    const unavailable = response(400, { error: 'ticket_unavailable' });
    const f = clientFixture(
      phase === 'open'
        ? { openResponse: unavailable }
        : { submitResponse: unavailable },
    );
    const input = f.el('secret');
    await f.el('open-form').emit('click');
    if (phase === 'submit') {
      input.value = 'not stored';
      await f.el('secret-form').emit('submit');
    }
    assert.equal(f.el('state-expired').hidden, false);
    assert.equal(f.el('secret'), null);
    assert.equal(f.el('secret-form'), null);
    assert.equal(f.el('open-form'), null);
    assert.equal(f.el('submit'), null);
    assert.equal(input.value, '');
    assert.equal(f.el('status').textContent, '');
  }
});

test('transient submit errors keep the form for deliberate retry without automatically resubmitting', async () => {
  for (const options of [
    { network: true },
    { submitResponse: response(429, { error: 'rate_limited' }) },
    { submitResponse: response(503, { error: 'internal_error' }) },
  ]) {
    const f = clientFixture(options);
    await f.el('open-form').emit('click');
    f.el('secret').value = 'retry deliberately';
    await f.el('secret-form').emit('submit');
    assert.equal(f.calls.length, 2);
    assert.equal(f.el('state-form').hidden, false);
    assert.equal(f.el('state-expired').hidden, true);
    assert.equal(f.el('secret').value, '');
    assert.equal(f.el('submit').disabled, false);
    assert(f.el('status').textContent);
  }
});

test('client state function separates terminal generic errors from transient failures', () => {
  for (const state of ['landing', 'form']) {
    assert.equal(failureState(400, 'ticket_unavailable', state), 'expired');
    assert.equal(failureState(400, 'invalid_envelope', state), 'invalid');
    for (const status of [undefined, 429, 500, 502, 503])
      assert.equal(failureState(status, 'internal_error', state), state);
  }
});

test('production markup uses eye icons with only CSP-compatible local assets and no state navigation', async () => {
  assert.match(html, /class="icon-eye"/);
  assert.match(html, /class="icon-eye-off"/);
  assert.match(html, /id="toggle"/);
  const hint = html.match(/<p id="secret-hint"[^>]*>([\s\S]*?)<\/p>/);
  assert.equal(hint?.[1].trim(), 'Paste the value as issued.');
  assert.doesNotMatch(html, /spaces|line breaks are removed|whitespace/i);
  assert.doesNotMatch(
    html,
    /<nav\b|class="demo"|data-state=|\bstyle=|\bon\w+=|<style\b/i,
  );
  for (const script of html.matchAll(
    /<script\b([^>]*)>([\s\S]*?)<\/script>/g,
  )) {
    assert.match(script[1], /src="\/app\.js"/);
    assert.equal(script[2], '');
  }
  for (const asset of html.matchAll(/\b(?:src|href)="([^"]+)"/g))
    assert(asset[1].startsWith('/'));
  const app = await readFile(
    new URL('../public/app.js', import.meta.url),
    'utf8',
  );
  const css = await readFile(
    new URL('../public/styles.css', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(app, /^import\s/m);
  assert.doesNotMatch(app, /URLSearchParams|setTimeout|setInterval|\.style\b/);
  assert.doesNotMatch(css, /@import|url\(|\.demo\b/);
});
