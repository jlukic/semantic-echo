/* Shared WebTransport machinery for every page on this host.
   No framework, no imports: a diagnostic tool has to run when the network is
   the thing under test. */

/*******************************
          Endpoints
*******************************/

/* Described by what each one advertises on the wire, because that is what a
   client reacts to. The server build is a footnote — most people reading this
   do not run Go. The SETTINGS values are what these builds put on the wire;
   `/settings` serves the same table so the two cannot drift. */
const ENDPOINTS = [
  {
    id: 'stock',
    port: 443,
    name: 'Library defaults',
    advertises: 'WT_MAX_SESSIONS, no flow-control settings',
    stack: 'webtransport-go v0.12.0 · quic-go v0.61.0',
  },
  {
    id: 'trio',
    port: 4440,
    name: 'Defaults plus flow control',
    advertises: 'WT_MAX_SESSIONS and all three WT_INITIAL_MAX_* settings',
    stack: 'webtransport-go v0.12.0 · quic-go v0.61.0',
  },
  {
    id: 'validated',
    port: 4436,
    name: 'Older server build',
    advertises: 'byte-identical SETTINGS to the row above',
    stack: 'webtransport-go v0.11.0 · quic-go v0.60.0',
  },
  {
    id: 'rust',
    port: 4438,
    name: 'Independent implementation',
    advertises: 'WT_MAX_SESSIONS = 1 at the legacy codepoint, draft-06',
    stack: 'wtransport 0.7.1 over quinn',
  },
];

/* Certificate-path endpoints. Same echo, same handler; they differ in how the
   client is asked to trust the leaf. */
const CERT_ENDPOINTS = [
  { id: 'pki', port: 4436, name: 'WebPKI', detail: 'Real Let’s Encrypt chain, ordinary validation' },
  { id: 'pinned', port: 4437, hashPort: 4437, name: 'serverCertificateHashes', detail: 'Self-signed P-256 leaf, ten-day validity, pinned by SHA-256' },
  { id: 'certsign', port: 4439, hashPort: 4439, name: 'Pinned leaf carrying CertSign', detail: 'KeyUsage 0x21, still not a CA' },
  { id: 'altport', port: 6443, hashPort: 6443, name: 'Pinned leaf on another port', detail: 'Byte-identical certificate to the row above' },
];

const endpointURL = port => port === 443
  ? `https://${location.hostname}/echo`
  : `https://${location.hostname}:${port}/echo`;

/*******************************
         Error shapes
*******************************/

/* Safari's WebTransportError message is always empty, whatever went wrong, so
   name the shape rather than trusting the text. */
const describe = error => {
  const name = error?.name || 'Error';
  const parts = [error?.message ? `${name}: "${error.message}"` : `${name}, empty message`];
  if (error?.source) parts.push(`source=${error.source}`);
  if (error?.streamErrorCode !== undefined && error?.streamErrorCode !== null) {
    parts.push(`code=${error.streamErrorCode}`);
  }
  return parts.join(' ');
};

/* Safari exposes the datagram streams as createWritable()/createReadable()
   factories rather than the accessors the specification settled on. */
const datagramStreams = session => {
  const datagrams = session.datagrams || {};
  const factory = name => typeof datagrams[name] === 'function' ? datagrams[name]() : null;
  return {
    writable: datagrams.writable || factory('createWritable'),
    readable: datagrams.readable || factory('createReadable'),
    shape: datagrams.writable ? 'accessors' : (typeof datagrams.createWritable === 'function' ? 'factories' : 'absent'),
  };
};

const fetchHash = async port => {
  // origin-absolute: a relative fetch inherits credentials from a
  // https://user:pass@host/ URL and browsers reject that, which would read
  // here as a WebTransport failure
  const response = await fetch(`${location.origin}/hash${port}`);
  return (await response.text()).trim();
};

const buildOptions = async opts => {
  const options = {};
  if (opts.requireUnreliable !== false) options.requireUnreliable = true;
  if (opts.allowPooling) options.allowPooling = true;
  if (opts.protocols?.length) options.protocols = opts.protocols;

  const hash = opts.hash ? opts.hash.trim() : (opts.hashPort ? await fetchHash(opts.hashPort) : '');
  if (hash) {
    options.serverCertificateHashes = [{
      algorithm: 'sha-256',
      value: Uint8Array.from(atob(hash), c => c.charCodeAt(0)),
    }];
  }
  return { options, hash };
};

/*******************************
        The attempt
*******************************/

const TIMEOUT_MS = 8000;

/* One attempt, one codepath. Every surface on this host goes through here so
   two pages cannot report different things about the same endpoint. */
async function attempt(target, opts = {}) {
  const log = opts.onLine || (() => {});
  const t0 = performance.now();
  const since = () => Math.round(performance.now() - t0);

  if (typeof WebTransport !== 'function') {
    log('WebTransport is not implemented in this runtime', 'bad');
    return { outcome: 'error', ms: 0, detail: 'WebTransport is not implemented here' };
  }

  let wt = null;
  try {
    const { options, hash } = await buildOptions(opts);
    log(hash ? `pinning ${hash.slice(0, 12)}…` : 'no pinning, ordinary certificate validation', 'dim');
    log(`connecting ${target}`);

    wt = new WebTransport(target, options);
    if (opts.maxAge) {
      try {
        wt.datagrams.incomingMaxAge = opts.maxAge;
        wt.datagrams.outgoingMaxAge = opts.maxAge;
      } catch (error) { log(`maxAge setters threw ${describe(error)}`, 'bad'); }
    }

    wt.closed.then(
      info => log(`closed: ${JSON.stringify(info)}`, 'dim'),
      error => log(`closed: ${describe(error)}`, 'bad'));

    let timer;
    await Promise.race([
      wt.ready,
      new Promise((_, reject) => {
        // a server that omits WT_MAX_SESSIONS entirely makes Safari hang here
        // rather than reject, so the timeout is load-bearing
        timer = setTimeout(() => reject(new Error(`no answer within ${TIMEOUT_MS / 1000}s`)), TIMEOUT_MS);
      }),
    ]);
    clearTimeout(timer);

    const ms = since();
    log(`ready in ${ms}ms  reliability=${wt.reliability}  congestionControl=${wt.congestionControl}`, 'ok');
    const detail = opts.echo === false ? 'session established' : await echoOnce(wt, log);
    return { outcome: 'ready', ms, detail, session: opts.keepOpen ? wt : null };
  }
  catch (error) {
    log(`failed after ${since()}ms — ${describe(error)}`, 'bad');
    return {
      outcome: error?.name === 'WebTransportError' ? 'refused' : 'error',
      ms: since(),
      detail: describe(error),
    };
  }
  finally {
    if (wt && !opts.keepOpen) { try { wt.close(); } catch (error) { /* already gone */ } }
  }
}

const echoOnce = async (session, log) => {
  const { writable, readable, shape } = datagramStreams(session);
  if (!writable || !readable) {
    log('no datagram API in this runtime; session is established regardless');
    return 'established, no datagram API';
  }
  if (shape === 'factories') log('datagram streams via createWritable()/createReadable()', 'dim');

  const started = performance.now();
  const writer = writable.getWriter();
  await writer.write(new TextEncoder().encode('ping'));
  const reader = readable.getReader();
  const echo = await Promise.race([
    reader.read(),
    new Promise(resolve => setTimeout(() => resolve({ timeout: true }), 2500)),
  ]);
  if (echo.timeout) { log('datagram echo timed out after 2.5s', 'bad'); return 'established, echo timed out'; }
  const ms = Math.round(performance.now() - started);
  log(`datagram echo "${new TextDecoder().decode(echo.value)}" in ${ms}ms`, 'ok');
  return `datagram round trip ${ms}ms`;
};

/*******************************
     What the server saw
*******************************/

/* The browser gives a web developer nothing on a failed handshake: one
   WebTransportError with an empty message. The server saw considerably more,
   so ask it. */
const observed = async () => {
  try {
    const response = await fetch(`${location.origin}/observed`, { cache: 'no-store' });
    if (!response.ok) return null;
    return await response.json();
  }
  catch (error) { return null; }
};

const VERDICTS = {
  established: { tone: 'good', text: 'Session established.' },
  'no-udp': {
    tone: 'bad',
    text: 'No QUIC packet from your address reached this port. UDP is being blocked or filtered somewhere between you and here — the WebTransport implementation never got a chance to run.',
  },
  'gave-up': {
    tone: 'bad',
    text: 'Your client completed QUIC and TLS, read the server’s SETTINGS, and then closed without sending the extended CONNECT request. It rejected the handshake on the settings it was offered.',
  },
  'upgrade-failed': {
    tone: 'bad',
    text: 'Your client sent the extended CONNECT request, but the server could not complete the upgrade.',
  },
  declined: {
    tone: 'bad',
    text: 'The server declined the session against its abuse budget rather than for any protocol reason.',
  },
  unknown: { tone: '', text: 'No server-side record for your address in the last few seconds.' },
};

const verdictFor = events => {
  if (!events?.length) return 'no-udp';
  const kinds = new Set(events.map(e => e.kind));
  if (kinds.has('session')) return 'established';
  if (kinds.has('declined')) return 'declined';
  if (kinds.has('refused') || kinds.has('connect')) return 'upgrade-failed';
  if (kinds.has('quic')) return 'gave-up';
  return 'unknown';
};

const EVENT_LABELS = {
  quic: 'QUIC and TLS completed, HTTP/3 connection accepted',
  connect: 'Extended CONNECT request received',
  session: 'WebTransport session established',
  refused: 'Session upgrade failed',
  declined: 'Session declined by an abuse budget',
  closed: 'Connection closed',
};

const renderObservation = (host, data, port) => {
  host.textContent = '';
  const events = (data?.events || []).filter(e => !port || e.port === port);
  const verdict = VERDICTS[verdictFor(events)];

  if (events.length) {
    const list = document.createElement('ul');
    list.className = 'timeline';
    for (const event of events) {
      const item = document.createElement('li');
      if (event.kind === 'session') item.className = 'good';
      if (event.kind === 'refused' || event.kind === 'declined') item.className = 'bad';

      const at = document.createElement('span');
      at.className = 'at';
      at.textContent = new Date(event.t).toTimeString().slice(0, 8);

      const what = document.createElement('span');
      what.className = 'what';
      what.textContent = `:${event.port}  ${EVENT_LABELS[event.kind] || event.kind}`;
      if (event.detail) {
        const detail = document.createElement('span');
        detail.className = 'detail';
        detail.textContent = event.detail;
        what.append(detail);
      }
      item.append(at, what);
      list.append(item);
    }
    host.append(list);
  }

  const box = document.createElement('div');
  box.className = `verdict ${verdict.tone}`;
  box.textContent = verdict.text;
  host.append(box);
};

/*******************************
        Page furniture
*******************************/

const setTheme = next => {
  document.documentElement.classList.remove('dark', 'light');
  document.documentElement.classList.add(next);
  try { localStorage.setItem('theme', next); } catch (error) { /* private mode */ }
};

const initChrome = () => {
  const toggle = document.querySelector('#theme-toggle');
  if (toggle) {
    toggle.onclick = () => setTheme(document.documentElement.classList.contains('dark') ? 'light' : 'dark');
  }

  for (const block of document.querySelectorAll('.code-block')) {
    const button = document.createElement('button');
    button.className = 'copy';
    button.title = 'Copy';
    button.onclick = async () => {
      await navigator.clipboard.writeText(block.querySelector('pre').textContent);
      button.classList.add('done');
      setTimeout(() => button.classList.remove('done'), 1500);
    };
    block.append(button);
  }
};

const chipFor = result => {
  const chip = document.createElement('span');
  chip.className = `chip ${result.outcome}`;
  chip.textContent = result.outcome === 'ready' ? `ready ${result.ms}ms` : `${result.outcome} ${result.ms}ms`;
  chip.title = result.detail;
  return chip;
};

const lineWriter = host => (message, tone) => {
  const line = document.createElement('div');
  if (tone) line.className = tone;
  line.textContent = `${new Date().toTimeString().slice(0, 8)}  ${message}`;
  host.append(line);
  host.scrollTop = host.scrollHeight;
};

document.addEventListener('DOMContentLoaded', initChrome);
