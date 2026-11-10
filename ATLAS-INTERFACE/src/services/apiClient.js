import { env } from '../config/env.js';
import { mockRequest } from './mock/handler.js';
import { endpoints } from './contract.js';

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'unknown', details = null, retryAfter = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;          // the backend's machine-readable error code, e.g. "scope_violation"
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

// Tokens live in memory only: never in web storage, never logged. A page reload signs the user out by design.
let session = null;
let authLostHandler = null;
let refreshing = null;

export const setSession = (s) => { session = s ? { accessToken: s.accessToken, refreshToken: s.refreshToken } : null; };
export const clearSession = () => { session = null; };
export const hasSession = () => Boolean(session?.accessToken);
export const onAuthLost = (fn) => { authLostHandler = fn; };

const TIMEOUT_MS = 15000;

async function parse(res) {
  if (res.status === 204) return null;
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }
  if (!res.ok) {
    const e = json?.error;
    throw new ApiError(e?.message || `The server returned ${res.status}.`, {
      status: res.status, code: e?.code || 'http_error', details: e?.details ?? null, retryAfter: res.headers.get('retry-after'),
    });
  }
  return json;
}

async function attempt(path, { method = 'GET', body, signal } = {}, token) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  signal?.addEventListener('abort', () => controller.abort());
  try {
    const res = await fetch(`${env.apiBaseUrl}${path}`, {
      method,
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    return await parse(res);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err?.name === 'AbortError') throw new ApiError('The request timed out or was cancelled.', { code: 'timeout' });
    throw new ApiError(`Could not reach the API at ${env.apiBaseUrl}.`, { code: 'network' });
  } finally {
    clearTimeout(timer);
  }
}

// One refresh at a time: concurrent 401s share it (refresh tokens rotate, so a second refresh would revoke the session).
function refreshSession() {
  if (!refreshing) {
    const refreshToken = session.refreshToken;
    refreshing = (async () => {
      try {
        const res = await attempt(endpoints.refresh, { method: 'POST', body: { refresh_token: refreshToken } }, null);
        setSession({ accessToken: res.data.access_token, refreshToken: res.data.refresh_token });
        return res.data.access_token;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {          // refresh token rejected: the session is really over
          clearSession();
          authLostHandler?.();
          throw new ApiError('Your session has expired. Please sign in again.', { status: 401, code: 'session_expired' });
        }
        throw e;                                                   // network/server trouble: keep the session, let the caller retry
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

/** auth:false for endpoints that must not carry a token (login). */
export async function request(path, opts = {}) {
  if (env.useMock) return mockRequest(path, opts);
  const { auth = true } = opts;
  try {
    return await attempt(path, opts, auth ? session?.accessToken : null);
  } catch (err) {
    const expired = err instanceof ApiError && err.status === 401 && err.code === 'unauthorized';
    if (!auth || !expired || !session?.refreshToken) throw err;
    const fresh = await refreshSession();
    return attempt(path, opts, fresh);                             // exactly one retry
  }
}
