import { env } from '../config/env.js';
import { mockRequest } from './mock/handler.js';

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'unknown' } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

// The token lives in memory only: never in storage, never logged.
let authToken = null;
export function setAuthToken(token) { authToken = token || null; }

const TIMEOUT_MS = 15000;

export async function request(path, { method = 'GET', body, signal } = {}) {
  if (env.useMock) return mockRequest(path, { method, body });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  signal?.addEventListener('abort', () => controller.abort());
  try {
    const res = await fetch(`${env.apiBaseUrl}${path}`, {
      method,
      headers: {
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new ApiError(`The server returned ${res.status}.`, { status: res.status, code: 'http_error' });
    }
    return res.status === 204 ? null : await res.json();
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err.name === 'AbortError') throw new ApiError('The request timed out or was cancelled.', { code: 'timeout' });
    throw new ApiError(`Could not reach the API at ${env.apiBaseUrl}.`, { code: 'network' });
  } finally {
    clearTimeout(timer);
  }
}
