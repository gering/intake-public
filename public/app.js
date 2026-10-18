export function readAndClearFragment(location, history) {
  const hash = location.hash;
  history.replaceState(null, '', location.pathname + location.search);
  return /^#req=([\w-]{22}\.[\w-]{43})$/.exec(hash)?.[1] ?? null;
}

export function failureState(status, code, currentState) {
  if (code === 'ticket_unavailable') return 'expired';
  if (!status || status === 429 || status >= 500) return currentState;
  return 'invalid';
}

export function valueEntry(input) {
  // Textareas normalize line endings for display. Keep pasted CR/LF intact,
  // mapping subsequent edits back to the raw value without changing untouched text.
  let raw = '';
  let paste;
  const normalized = (value) => value.replace(/\r\n?/g, '\n');
  function rawOffset(index) {
    let offset = 0;
    for (let i = 0; i < index && offset < raw.length; i++, offset++)
      if (raw[offset] === '\r' && raw[offset + 1] === '\n') offset++;
    return offset;
  }
  function read() {
    const current = input.value;
    const previous = normalized(raw);
    if (paste) {
      const candidate =
        raw.slice(0, rawOffset(paste.start)) +
        paste.value +
        raw.slice(rawOffset(paste.end));
      paste = null;
      if (normalized(candidate) === current) {
        raw = candidate;
        return raw;
      }
    }
    if (current !== previous) {
      let start = 0;
      let suffix = 0;
      while (
        start < previous.length &&
        start < current.length &&
        previous[start] === current[start]
      )
        start++;
      while (
        suffix < previous.length - start &&
        suffix < current.length - start &&
        previous.at(-suffix - 1) === current.at(-suffix - 1)
      )
        suffix++;
      raw =
        raw.slice(0, rawOffset(start)) +
        current.slice(start, current.length - suffix) +
        raw.slice(rawOffset(previous.length - suffix));
    }
    return raw;
  }
  input.addEventListener('paste', (event) => {
    read();
    if (event.clipboardData)
      paste = {
        start: input.selectionStart,
        end: input.selectionEnd,
        value: event.clipboardData.getData('text/plain'),
      };
  });
  input.addEventListener('input', read);
  return {
    read,
    clear() {
      raw = '';
      paste = null;
      input.value = '';
    },
  };
}

export function mountApp({
  document,
  token,
  fetch = globalThis.fetch,
  encrypt = async (ticket, value) =>
    (await import('./crypto.js')).encryptValue(ticket, value),
}) {
  const states = ['landing', 'form', 'success', 'expired', 'invalid'];
  const el = (id) => document.getElementById(id);
  const input = el('secret');
  const entry = valueEntry(input);
  const toggle = el('toggle');
  const openButton = el('open-form');
  const submitButton = el('submit');
  const submitLabel = el('submit-label');
  const status = el('status');
  let state;
  let ticket;
  let busy = false;
  const fmt = new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });

  function show(name, focus = true) {
    state = name;
    for (const candidate of states)
      el('state-' + candidate).hidden = candidate !== name;
    if (['success', 'expired', 'invalid'].includes(name)) {
      token = null;
      ticket = null;
      entry.clear();
      el('state-form').remove();
      el('state-landing').remove();
    }
    if (focus) {
      const heading = el('state-' + name).querySelector('h1');
      heading.setAttribute('tabindex', '-1');
      heading.focus();
    }
  }

  function displayTime(id, value) {
    const date = new Date(value);
    el(id).dateTime = date.toISOString();
    el(id).textContent = fmt.format(date);
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw Object.assign(new Error('request_failed'), {
        status: response.status,
        code: result.error,
      });
    }
    return response.json();
  }

  function failed(error) {
    const next = failureState(error.status, error.code, state);
    if (next !== state) {
      status.textContent = '';
      show(next);
    } else {
      status.textContent =
        error.status === 429
          ? 'Too many requests. Wait a minute and try again.'
          : 'Delivery could not be confirmed. Check your connection or contact the requester before trying again. No automatic retry has been made.';
    }
  }

  function toggleSecret() {
    const visible = toggle.getAttribute('aria-pressed') === 'true';
    input.setAttribute('data-visible', String(!visible));
    toggle.setAttribute('aria-label', visible ? 'Show secret' : 'Hide secret');
    toggle.setAttribute('aria-pressed', String(!visible));
  }
  toggle.addEventListener('click', toggleSecret);

  openButton.addEventListener('click', async () => {
    if (busy || state !== 'landing' || !token) return;
    busy = true;
    openButton.disabled = true;
    status.textContent = 'Opening form…';
    try {
      ticket = await post('/api/open', { token });
      el('f-key').textContent = ticket.keyName;
      el('f-purpose').textContent = ticket.purpose;
      displayTime('f-expires', ticket.expiresAt);
      status.textContent = '';
      show('form');
      input.focus();
    } catch (error) {
      failed(error);
    } finally {
      busy = false;
      openButton.disabled = false;
    }
  });

  el('secret-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || state !== 'form' || !ticket || !token) return;
    const raw = entry.read();
    const value = ticket.trim === false ? raw : raw.trim();
    const empty = !value.length;
    const oversized = new TextEncoder().encode(value).length > 65536;
    const err = el('secret-err');
    err.hidden = !empty && !oversized;
    if (empty || oversized) {
      err.textContent = empty
        ? 'Please enter a value.'
        : 'The value must be at most 64 KiB of UTF-8 text.';
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }
    input.removeAttribute('aria-invalid');
    busy = true;
    submitButton.disabled = true;
    submitLabel.textContent = 'Encrypting…';
    status.textContent = '';
    try {
      const envelope = await encrypt(ticket, raw);
      entry.clear();
      submitLabel.textContent = 'Sending…';
      await post('/api/submit', { token, envelope });
      el('s-key').textContent = ticket.keyName;
      displayTime('s-time', Date.now());
      show('success');
    } catch (error) {
      entry.clear();
      failed(error);
    } finally {
      busy = false;
      submitButton.disabled = false;
      submitLabel.textContent = 'Send securely';
    }
  });

  show(token ? 'landing' : 'invalid', false);
}

if (typeof window !== 'undefined') {
  // No imports or application requests may precede fragment removal.
  const token = readAndClearFragment(window.location, window.history);
  const supported = Boolean(
    globalThis.crypto?.subtle &&
    globalThis.CSS?.supports('-webkit-text-security', 'disc'),
  );
  mountApp({ document: window.document, token: supported ? token : null });
  if (!supported) {
    document.getElementById('status').textContent =
      'This browser needs WebCrypto, a secure HTTPS connection, and masked text-field support.';
  }
}
