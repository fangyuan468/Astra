import { AstraClient } from '../client';

afterEach(() => vi.unstubAllGlobals());

test('raw transport leaves error bodies and FormData untouched; typed fetch keeps JSON defaults', async () => {
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('upstream detail', { status: 403 }));
  vi.stubGlobal('fetch', fetchMock);
  const client = new AstraClient({ baseUrl: 'https://example.test/base', pathPrefix: '/api' });
  const body = new FormData();
  body.set('file', new Blob(['contents']), 'test.txt');
  const signal = new AbortController().signal;
  const response = await client.fetchResponse('/upload', { method: 'POST', body, signal });
  expect(response.status).toBe(403);
  expect(response.bodyUsed).toBe(false);
  expect(await response.text()).toBe('upstream detail');
  expect(fetchMock.mock.calls[0]).toEqual(['https://example.test/base/api/upload', expect.objectContaining({ body, signal })]);
  expect(new Headers(fetchMock.mock.calls[0][1]?.headers).has('Content-Type')).toBe(false);
  await expect(client.fetch('/typed', { method: 'POST', body: '{}' })).rejects.toMatchObject({ status: 403 });
  expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('Content-Type')).toBe('application/json');
});

test('anonymous raw requests suppress configured auth and refresh but allow explicit headers', async () => {
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('unauthorized', { status: 401 }));
  vi.stubGlobal('fetch', fetchMock);
  const client = new AstraClient({ baseUrl: 'https://example.test', accessToken: 'access', refreshToken: 'refresh', headers: { authorization: 'Bearer configured' } });
  await client.fetchResponse('/public', {}, { auth: 'none' });
  await client.fetchResponse('/public', { headers: { Authorization: 'Bearer explicit' } }, { auth: 'none' });
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(new Headers(fetchMock.mock.calls[0][1]?.headers).has('Authorization')).toBe(false);
  expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('Authorization')).toBe('Bearer explicit');
});

test.each([null, {}, { access_token: 'new', refresh_token: 1 }])('malformed refresh does not publish credentials or notify: %j', async payload => {
  const notify = vi.fn();
  const fetchMock = vi.fn(async (url: string) => url.endsWith('/auth/refresh')
    ? Response.json(payload) : new Response('expired', { status: 401 }));
  vi.stubGlobal('fetch', fetchMock);
  const client = new AstraClient({ baseUrl: 'https://example.test', accessToken: 'old', refreshToken: 'refresh', onTokenRefresh: notify });
  const snapshot = client.getTokens();
  await expect(client.getMe()).rejects.toMatchObject({ status: 401 });
  expect(client.getTokens()).toEqual(snapshot);
  expect(notify).not.toHaveBeenCalled();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});
