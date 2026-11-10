import { request, setSession, clearSession } from './apiClient.js';
import { endpoints } from './contract.js';

export async function login({ username, password, totpCode }) {
  const res = await request(endpoints.login, {
    method: 'POST', auth: false,
    body: { username, password, ...(totpCode ? { totp_code: totpCode } : {}) },
  });
  setSession({ accessToken: res.data.access_token, refreshToken: res.data.refresh_token });
  return res.data.user;
}

export async function logout() {
  try { await request(endpoints.logout, { method: 'POST' }); }
  catch { /* the server may already consider the session gone */ }
  finally { clearSession(); }
}

export const fetchMe = async () => (await request(endpoints.me)).data;
