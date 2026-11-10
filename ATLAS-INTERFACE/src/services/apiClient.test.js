import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../config/env.js', () => ({ env: { apiBaseUrl: 'http://api.test/api/v1', useMock: false } }));

const json = (status, body, headers = {}) => new Response(body === null ? null : JSON.stringify(body), { status, headers });
let api, calls, handlers;

function route(fn) { handlers.push(fn); }

beforeEach(async () => {
  vi.resetModules();
  calls = []; handlers = [];
  vi.stubGlobal('fetch', vi.fn(async (url, init) => {
    const call = { url: String(url).replace('http://api.test/api/v1', ''), method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined };
    calls.push(call);
    for (const h of handlers) { const r = await h(call); if (r) return r; }
    return json(404, { error: { code: 'not_found', message: 'nope', details: null } });
  }));
  api = await import('./apiClient.js');
});
afterEach(() => { vi.unstubAllGlobals(); });

describe('requests', () => {
  it('sends the bearer token and JSON body', async () => {
    api.setSession({ accessToken: 'AT', refreshToken: 'RT' });
    route((c) => c.url === '/x' && json(200, { data: 1 }));
    await api.request('/x', { method: 'POST', body: { a: 1 } });
    expect(calls[0].headers.Authorization).toBe('Bearer AT');
    expect(calls[0].headers['Content-Type']).toBe('application/json');
    expect(calls[0].body).toEqual({ a: 1 });
  });

  it('never sends a token when auth is false (login)', async () => {
    api.setSession({ accessToken: 'AT', refreshToken: 'RT' });
    route(() => json(200, { data: 1 }));
    await api.request('/auth/login', { method: 'POST', body: {}, auth: false });
    expect(calls[0].headers.Authorization).toBeUndefined();
  });

  it('parses the backend error envelope into an ApiError', async () => {
    route(() => json(429, { error: { code: 'account_locked', message: 'locked', details: { retry_after_seconds: 120 } } }, { 'Retry-After': '120' }));
    const err = await api.request('/auth/login', { method: 'POST', body: {}, auth: false }).catch((e) => e);
    expect(err).toBeInstanceOf(api.ApiError);
    expect(err).toMatchObject({ status: 429, code: 'account_locked', message: 'locked', details: { retry_after_seconds: 120 }, retryAfter: '120' });
  });

  it('copes with non-JSON error bodies and 204', async () => {
    route((c) => c.url === '/html' && new Response('<h1>bad gateway</h1>', { status: 502 }));
    route((c) => c.url === '/empty' && new Response(null, { status: 204 }));
    expect(await api.request('/html').catch((e) => e)).toMatchObject({ status: 502, code: 'http_error' });
    expect(await api.request('/empty')).toBeNull();
  });

  it('maps network failures and aborts', async () => {
    fetch.mockRejectedValueOnce(new TypeError('failed'));
    expect(await api.request('/x').catch((e) => e)).toMatchObject({ code: 'network' });
    fetch.mockRejectedValueOnce(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    expect(await api.request('/x').catch((e) => e)).toMatchObject({ code: 'timeout' });
  });

  it('keeps tokens out of web storage', async () => {
    api.setSession({ accessToken: 'SECRET-AT', refreshToken: 'SECRET-RT' });
    route(() => json(200, { data: 1 }));
    await api.request('/x');
    expect(JSON.stringify({ ...localStorage })).not.toContain('SECRET');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('SECRET');
  });
});

describe('token refresh', () => {
  const expired = () => json(401, { error: { code: 'unauthorized', message: 'expired', details: null } });

  it('refreshes once on 401 and retries with the NEW token', async () => {
    api.setSession({ accessToken: 'OLD', refreshToken: 'RT1' });
    route((c) => c.url === '/auth/refresh' && json(200, { data: { access_token: 'NEW', refresh_token: 'RT2', user: {} } }));
    route((c) => c.url === '/things' && (c.headers.Authorization === 'Bearer NEW' ? json(200, { data: ['ok'] }) : expired()));
    expect(await api.request('/things')).toEqual({ data: ['ok'] });
    expect(calls.map((c) => c.url)).toEqual(['/things', '/auth/refresh', '/things']);
    expect(calls[1].body).toEqual({ refresh_token: 'RT1' });
    expect(calls[1].headers.Authorization).toBeUndefined();            // the refresh call itself is not authenticated
    api.setSession(null);
  });

  it('shares ONE refresh between concurrent 401s (tokens rotate, a second refresh would revoke the session)', async () => {
    api.setSession({ accessToken: 'OLD', refreshToken: 'RT1' });
    let refreshes = 0;
    route(async (c) => { if (c.url !== '/auth/refresh') return null; refreshes += 1; await new Promise((r) => setTimeout(r, 30)); return json(200, { data: { access_token: 'NEW', refresh_token: 'RT2' } }); });
    route((c) => (c.headers.Authorization === 'Bearer NEW' ? json(200, { data: c.url }) : expired()));
    const out = await Promise.all([api.request('/a'), api.request('/b'), api.request('/c')]);
    expect(out.map((o) => o.data)).toEqual(['/a', '/b', '/c']);
    expect(refreshes).toBe(1);
  });

  it('ends the session when the refresh token is rejected', async () => {
    const lost = vi.fn();
    api.onAuthLost(lost);
    api.setSession({ accessToken: 'OLD', refreshToken: 'DEAD' });
    route((c) => c.url === '/auth/refresh' && json(401, { error: { code: 'invalid_refresh_token', message: 'bad', details: null } }));
    route(() => expired());
    const err = await api.request('/things').catch((e) => e);
    expect(err).toMatchObject({ code: 'session_expired', status: 401 });
    expect(lost).toHaveBeenCalledTimes(1);
    expect(api.hasSession()).toBe(false);
  });

  it('keeps the session if the refresh fails for a non-auth reason (network down)', async () => {
    const lost = vi.fn();
    api.onAuthLost(lost);
    api.setSession({ accessToken: 'OLD', refreshToken: 'RT' });
    route((c) => c.url === '/auth/refresh' && json(503, { error: { code: 'rate_limiter_unavailable', message: 'down', details: null } }));
    route(() => expired());
    const err = await api.request('/things').catch((e) => e);
    expect(err.status).toBe(503);
    expect(lost).not.toHaveBeenCalled();
    expect(api.hasSession()).toBe(true);
  });

  it('retries exactly once: a second 401 is surfaced, no loop', async () => {
    api.setSession({ accessToken: 'OLD', refreshToken: 'RT' });
    route((c) => c.url === '/auth/refresh' && json(200, { data: { access_token: 'NEW', refresh_token: 'RT2' } }));
    route(() => expired());
    const err = await api.request('/things').catch((e) => e);
    expect(err.status).toBe(401);
    expect(calls.filter((c) => c.url === '/things')).toHaveLength(2);
    expect(calls.filter((c) => c.url === '/auth/refresh')).toHaveLength(1);
  });

  it.each([['invalid_credentials'], ['forbidden'], ['scope_violation']])('does not refresh for %s', async (code) => {
    api.setSession({ accessToken: 'AT', refreshToken: 'RT' });
    route(() => json(code === 'invalid_credentials' ? 401 : 403, { error: { code, message: 'x', details: null } }));
    await api.request('/things').catch(() => {});
    expect(calls.map((c) => c.url)).toEqual(['/things']);
  });

  it('does not try to refresh when auth is false or there is no refresh token', async () => {
    route(() => expired());
    await api.request('/auth/login', { auth: false }).catch(() => {});
    api.setSession({ accessToken: 'AT', refreshToken: null });
    await api.request('/things').catch(() => {});
    expect(calls.some((c) => c.url === '/auth/refresh')).toBe(false);
  });
});
