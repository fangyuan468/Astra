import { AstraWebSocket } from '../websocket';

class ControlledSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: ControlledSocket[] = [];
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  sent: string[] = [];
  constructor() { ControlledSocket.instances.push(this); }
  send(value: string) { this.sent.push(value); }
  close() {
    this.readyState = ControlledSocket.CLOSED;
    // Browser close events are asynchronous, unlike the older test mock.
    queueMicrotask(() => this.onclose?.());
  }
  authenticate() {
    this.readyState = ControlledSocket.OPEN;
    this.onopen?.();
    this.onmessage?.({ data: JSON.stringify({ type: 'auth_ok', interaction_api_major: '3' }) });
  }
}

beforeEach(() => {
  ControlledSocket.instances = [];
  vi.stubGlobal('WebSocket', ControlledSocket);
});
afterEach(() => vi.unstubAllGlobals());

function client() {
  return new AstraWebSocket({ url: 'ws://localhost/ws', token: 'test-token', reconnect: false });
}

test('close settles connect before authentication and stale events cannot affect a new attempt', async () => {
  const ws = client();
  const outcomes: string[] = [];
  const pending = ws.connect().then(() => outcomes.push('resolved'), () => outcomes.push('rejected'));
  const oldSocket = ControlledSocket.instances[0];
  ws.close();
  await Promise.resolve();
  await Promise.resolve();
  expect(outcomes).toEqual(['rejected']);
  await pending;
  const next = ws.connect();
  oldSocket.authenticate();
  expect(ws.connectionState).toBe('connecting');
  ControlledSocket.instances[1].authenticate();
  await next;
  expect(ws.isConnected).toBe(true);
  ws.close();
});

test('concurrent connect calls share one authenticated connection', async () => {
  const ws = client();
  const callers = Array.from({ length: 100 }, () => ws.connect());
  expect(ControlledSocket.instances).toHaveLength(1);
  ControlledSocket.instances[0].authenticate();
  await Promise.all(callers);
  expect(ws.isConnected).toBe(true);
  ws.close();
});


test('a connecting listener can cancel and replace the attempt without opening a stale socket', async () => {
  const ws = client();
  let replacement: Promise<void> | undefined;
  let replaced = false;
  ws.on('stateChange', (state) => {
    if (state === 'connecting' && !replaced) {
      replaced = true;
      ws.close();
      replacement = ws.connect();
    }
  });
  const first = ws.connect();
  await expect(first).rejects.toThrow('WebSocket closed');
  expect(ControlledSocket.instances).toHaveLength(1);
  ControlledSocket.instances[0].authenticate();
  await replacement;
  expect(ws.isConnected).toBe(true);
  ws.close();
});

test.each([
  [{ type: 'auth_error', message: 'denied' }, 'denied'],
  [{ type: 'auth_ok', interaction_api_major: 'unsupported' }, 'contract mismatch'],
] as const)('authentication failure %j settles all callers and permits a fresh connection', async (frame, reason) => {
  const ws = client();
  const first = ws.connect();
  const second = ws.connect();
  ControlledSocket.instances[0].onmessage?.({ data: JSON.stringify(frame) });
  await expect(first).rejects.toThrow(reason);
  await expect(second).rejects.toThrow(reason);
  const next = ws.connect();
  ControlledSocket.instances[1].authenticate();
  await next;
  ws.close();
});

test('close settles an authenticated reconnect waiting for run attachment', async () => {
  const ws = client();
  ws.runId = 'existing-run';
  const pending = ws.connect();
  ControlledSocket.instances[0].authenticate();
  expect(ControlledSocket.instances[0].sent.map((frame) => JSON.parse(frame).type)).toEqual(['auth', 'attach_run']);
  ws.close();
  await expect(pending).rejects.toThrow('WebSocket closed');
  expect(ws.runId).toBe('existing-run');
});

test('a constructor failure clears the pending attempt so a later connect can succeed', async () => {
  const ws = client();
  vi.stubGlobal('WebSocket', class { constructor() { throw new Error('invalid URL'); } });
  await expect(ws.connect()).rejects.toThrow('invalid URL');
  expect(ws.connectionState).toBe('error');
  vi.stubGlobal('WebSocket', ControlledSocket);
  const next = ws.connect();
  ControlledSocket.instances[0].authenticate();
  await next;
  ws.close();
});

// Both notification APIs run synchronously and may call back into connect().
for (const notification of ['emitter', 'option'] as const) {
  function recoveryClient(onStateChange: (state: string) => void) {
    const ws = new AstraWebSocket({
      url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
      ...(notification === 'option' ? { onStateChange } : {}),
    });
    if (notification === 'emitter') ws.on('stateChange', onStateChange);
    return ws;
  }

  test(`${notification}: error notification can synchronously start a fresh attempt`, async () => {
    let recovery: Promise<void> | undefined;
    const ws = recoveryClient((state) => {
      if (state === 'error') recovery = ws.connect();
    });
    const first = ws.connect();
    const failed = expect(first).rejects.toThrow('WebSocket connection failed');
    const old = ControlledSocket.instances[0];
    old.onerror?.();
    const recovered = recovery!.catch((error) => error);
    try {
      expect(ControlledSocket.instances).toHaveLength(2);
      expect(old.readyState).toBe(ControlledSocket.CLOSED);
      old.authenticate();
      old.onclose?.();
      expect(ws.connectionState).toBe('connecting');
      ControlledSocket.instances[1].authenticate();
      expect(await recovered).toBeUndefined();
      await failed;
      expect(ws.isConnected).toBe(true);
    } finally { ws.close(); await recovered; await failed; }
  });

  test(`${notification}: denied reattachment exposes the usable connection to synchronous connect`, async () => {
    let recovery: Promise<void> | undefined;
    let recovering = false;
    const ws = recoveryClient((state) => {
      if (recovering && state === 'connected') recovery = ws.connect();
    });
    const initial = ws.connect();
    const old = ControlledSocket.instances[0];
    old.authenticate();
    await initial;
    old.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
    old.close();
    await Promise.resolve();
    recovering = true;
    const reconnect = ws.connect();
    const denied = expect(reconnect).rejects.toThrow('Not found');
    const socket = ControlledSocket.instances[1];
    socket.authenticate();
    expect(JSON.parse(socket.sent[1])).toMatchObject({ type: 'attach_run', run_id: 'owned-run' });
    socket.onmessage?.({ data: JSON.stringify({ type: 'error', message: 'Not found', retryable: false }) });
    const recovered = recovery!.catch((error) => error);
    try {
      await denied;
      expect(await recovered).toBeUndefined();
      expect(ControlledSocket.instances).toHaveLength(2);
      expect(ws.isConnected).toBe(true);
      expect(ws.runId).toBeNull();
    } finally { recovering = false; ws.close(); }
  });
}

test('a reattach acknowledgement listener can replace the connection without stale completion', async () => {
  const ws = client();
  const initial = ws.connect();
  const first = ControlledSocket.instances[0];
  first.authenticate();
  await initial;
  first.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
  first.close();
  await Promise.resolve();
  const reconnect = ws.connect();
  const accepted = expect(reconnect).resolves.toBeUndefined();
  const attaching = ControlledSocket.instances[1];
  attaching.authenticate();
  let replacement: Promise<void> | undefined;
  const replace = () => {
    ws.off('session_info', replace);
    ws.close();
    replacement = ws.connect();
  };
  ws.on('session_info', replace);
  const acknowledgements: unknown[] = [];
  ws.on('session_info', (event) => acknowledgements.push(event));
  attaching.onmessage?.({ data: JSON.stringify({ type: 'session_info', session_id: 'session', run_id: 'owned-run' }) });
  const replaced = replacement!.catch((error) => error);
  try {
    expect(ws.connectionState).toBe('connecting');
    expect(acknowledgements).toHaveLength(1);
    await accepted;
    const current = ControlledSocket.instances[2];
    current.authenticate();
    current.onmessage?.({ data: JSON.stringify({ type: 'session_info', session_id: 'session', run_id: 'owned-run' }) });
    expect(await replaced).toBeUndefined();
    expect(ws.isConnected).toBe(true);
  } finally { ws.close(); await replaced; await accepted; }
});

test('throwing state callbacks cannot interrupt connection settlement or cleanup', async () => {
  const states: string[] = [];
  const ws = new AstraWebSocket({
    url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
    onStateChange: () => { throw new Error('consumer callback failed'); },
  });
  ws.on('stateChange', (state) => states.push(state));
  try {
    const connecting = ws.connect();
    expect(ControlledSocket.instances).toHaveLength(1);
    ControlledSocket.instances[0].authenticate();
    await connecting;
    expect(ws.isConnected).toBe(true);
    ws.close();
    expect(states).toEqual(['connecting', 'connected', 'disconnected']);
    expect(ws.readyState).toBe(ControlledSocket.CLOSED);
  } finally { ws.close(); }
});

test('throwing event callbacks cannot orphan an accepted attachment or suppress later consumers', async () => {
  const ws = new AstraWebSocket({
    url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
    onEvent: () => { throw new Error('consumer callback failed'); },
  });
  const received: unknown[] = [];
  ws.on('session_info', (event) => received.push(event));
  try {
    const connecting = ws.connect();
    const socket = ControlledSocket.instances[0];
    socket.authenticate();
    await connecting;
    const attached = ws.attachRun('owned-run');
    const acknowledgement = { type: 'session_info', session_id: 'session', run_id: 'owned-run' };
    socket.onmessage?.({ data: JSON.stringify(acknowledgement) });
    await attached;
    expect(received).toEqual([acknowledgement]);
    expect(ws.runId).toBe('owned-run');
    expect(ws.isConnected).toBe(true);
  } finally { ws.close(); }
});

test('close and explicit reconnect cancel the old automatic retry deadline', async () => {
  vi.useFakeTimers();
  const ws = new AstraWebSocket({
    url: 'ws://localhost/ws', token: 'test-token', reconnectDelayMs: 100,
  });
  try {
    const first = ws.connect();
    ControlledSocket.instances[0].authenticate();
    await first;
    ControlledSocket.instances[0].close();
    await Promise.resolve();
    ws.close();
    const reopened = ws.connect();
    ControlledSocket.instances[1].authenticate();
    await reopened;
    await vi.advanceTimersByTimeAsync(50);
    ControlledSocket.instances[1].close();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(50);
    expect(ControlledSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(50);
    expect(ControlledSocket.instances).toHaveLength(3);
    expect(ControlledSocket.instances.flatMap((socket) => socket.sent).map((frame) => JSON.parse(frame).type))
      .not.toContain('cancel_run');
  } finally { ws.close(); vi.useRealTimers(); }
});

for (const stage of ['authentication', 'reattachment', 'attachment'] as const) {
  test(`a ${stage} send failure settles its obligation and permits recovery`, async () => {
    let failSend = false;
    class FailingSocket extends ControlledSocket {
      send(value: string) {
        if (failSend) throw new Error('send failed');
        super.send(value);
      }
    }
    vi.stubGlobal('WebSocket', FailingSocket);
    const ws = client();
    try {
      let attempt = ws.connect();
      let socket = ControlledSocket.instances[0];
      if (stage !== 'authentication') {
        socket.authenticate();
        await attempt;
        if (stage === 'reattachment') {
          socket.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
          socket.close();
          await Promise.resolve();
          attempt = ws.connect();
          socket = ControlledSocket.instances[1];
        }
      }
      failSend = true;
      const failed = stage === 'attachment' ? ws.attachRun('owned-run') : attempt;
      const rejected = expect(failed).rejects.toThrow('send failed');
      if (stage !== 'attachment') socket.authenticate();
      await rejected;
      failSend = false;
      if (stage === 'attachment') {
        attempt = ws.attachRun('owned-run');
      } else {
        attempt = ws.connect();
        socket = ControlledSocket.instances.at(-1)!;
        socket.authenticate();
      }
      if (stage !== 'authentication') {
        expect(JSON.parse(socket.sent.at(-1)!)).toMatchObject({ type: 'attach_run', run_id: 'owned-run' });
        socket.onmessage?.({ data: JSON.stringify({ type: 'session_info', session_id: 'session', run_id: 'owned-run' }) });
      }
      await attempt;
      expect(ws.isConnected).toBe(true);
    } finally { ws.close(); }
  });
}

for (const cleanupApi of ['option', 'generic', 'typed'] as const) {
  test(`${cleanupApi}: terminal cleanup does not interrupt the accepted frame's other subscribers`, async () => {
    const terminal = { type: 'run_finished', run_id: 'owned-run', index: 1, owner_generation: 1, status: 'completed' };
    let ws: AstraWebSocket;
    const cleanup = (event: { type: string }) => { if (event.type === 'run_finished') ws.close(); };
    ws = new AstraWebSocket({
      url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
      ...(cleanupApi === 'option' ? { onEvent: cleanup } : {}),
    });
    if (cleanupApi === 'generic') ws.on('event', cleanup);
    if (cleanupApi === 'typed') ws.on('run_finished', cleanup);
    const generic: unknown[] = [];
    const typed: unknown[] = [];
    ws.on('event', (event) => { if (event.type === 'run_finished') generic.push(event); });
    ws.on('run_finished', () => { throw new Error('subscriber failed'); });
    ws.on('run_finished', (event) => typed.push(event));
    try {
      const connected = ws.connect();
      const socket = ControlledSocket.instances[0];
      socket.authenticate();
      await connected;
      socket.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
      socket.onmessage?.({ data: JSON.stringify(terminal) });
      expect(generic).toEqual([terminal]);
      expect(typed).toEqual([terminal]);
      expect(ws.connectionState).toBe('disconnected');
      expect(ws.runId).toBeNull();
    } finally { ws.close(); }
  });
}

test('accepted frame reaches every consumer once even when a subscriber reconnects before inclusive replay', async () => {
  const ws = client();
  const received: string[] = [];
  let replacement: Promise<void | Error> | undefined;
  ws.on('event', (event) => {
    if (event.type === 'text_delta' && !replacement) {
      ws.close();
      replacement = ws.connect().catch((error: Error) => error);
    }
  });
  ws.on('text_delta', (event) => { if (event.type === 'text_delta') received.push(event.content); });
  try {
    const connected = ws.connect();
    const old = ControlledSocket.instances[0];
    old.authenticate();
    await connected;
    old.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
    const frame = { type: 'text_delta', run_id: 'owned-run', index: 3, content: 'hello' };
    old.onmessage?.({ data: JSON.stringify(frame) });
    expect(received).toEqual(['hello']);
    expect(ws.connectionState).toBe('connecting');
    old.onmessage?.({ data: JSON.stringify({ ...frame, index: 4, content: 'stale' }) });
    expect(received).toEqual(['hello']);
    const current = ControlledSocket.instances[1];
    current.authenticate();
    expect(JSON.parse(current.sent[1])).toEqual({ type: 'attach_run', run_id: 'owned-run', last_index: 3 });
    current.onmessage?.({ data: JSON.stringify({ type: 'session_info', session_id: 'session', run_id: 'owned-run' }) });
    expect(await replacement).toBeUndefined();
    current.onmessage?.({ data: JSON.stringify(frame) });
    current.onmessage?.({ data: JSON.stringify({ ...frame, index: 4, content: 'next' }) });
    expect(received).toEqual(['hello', 'next']);
    expect(ws.isConnected).toBe(true);
  } finally { ws.close(); await replacement; }
});

test('state notifications still stop when their callback closes the committed connection', async () => {
  const states: string[] = [];
  const ws = new AstraWebSocket({
    url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
    onStateChange: (state) => { if (state === 'connected') ws.close(); },
  });
  ws.on('stateChange', (state) => states.push(state));
  try {
    const connected = ws.connect();
    ControlledSocket.instances[0].authenticate();
    await connected;
    expect(states).toEqual(['connecting', 'disconnected']);
    expect(ws.isConnected).toBe(false);
  } finally { ws.close(); }
});

test.each([
  { reply: { type: 'session_info', session_id: 'session', run_id: 'owned-run' }, error: undefined, runId: 'owned-run' },
  { reply: { type: 'error', message: 'Not found', retryable: false }, error: 'Not found', runId: null },
])('reattach $reply.type reaches event subscribers even when its connected notification closes the transport', async ({ reply, error, runId }) => {
  let closeOnConnected = false;
  const ws = new AstraWebSocket({
    url: 'ws://localhost/ws', token: 'test-token', reconnect: false,
    onStateChange: (state) => { if (closeOnConnected && state === 'connected') ws.close(); },
  });
  const replies: unknown[] = [];
  ws.on('session_info', (event) => replies.push(event));
  ws.on('error', (event) => replies.push(event));
  try {
    const initial = ws.connect();
    const first = ControlledSocket.instances[0];
    first.authenticate();
    await initial;
    first.onmessage?.({ data: JSON.stringify({ type: 'run_started', run_id: 'owned-run' }) });
    first.close();
    await Promise.resolve();
    const reconnect = ws.connect().then(() => undefined, (failure: Error) => failure.message);
    const socket = ControlledSocket.instances[1];
    socket.authenticate();
    closeOnConnected = true;
    socket.onmessage?.({ data: JSON.stringify(reply) });
    expect(await reconnect).toBe(error);
    expect(replies).toEqual([reply]);
    expect(ws.isConnected).toBe(false);
    expect(ws.runId).toBe(runId);
  } finally { ws.close(); }
});

test('accepted-frame delivery preserves listener removal and addition during dispatch', async () => {
  const ws = client();
  const received: string[] = [];
  const removed = () => { received.push('removed'); };
  const added = () => { received.push('added'); };
  ws.on('text_delta', () => {
    ws.off('text_delta', removed);
    ws.on('text_delta', added);
  });
  ws.on('text_delta', removed);
  try {
    const connecting = ws.connect();
    const socket = ControlledSocket.instances[0];
    socket.authenticate();
    await connecting;
    socket.onmessage?.({ data: JSON.stringify({ type: 'text_delta', content: 'hello' }) });
    expect(received).toEqual(['added']);
  } finally { ws.close(); }
});
