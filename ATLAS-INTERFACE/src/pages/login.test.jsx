import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../config/env.js', () => ({ env: { apiBaseUrl: 'http://api.test/api/v1', useMock: false } }));
const authService = { login: vi.fn(), logout: vi.fn(async () => {}) };
vi.mock('../services/authService.js', () => authService);
vi.mock('../pages/DashboardPage.jsx', () => ({ default: () => <h1>Dashboard shown</h1> }));

const { AuthProvider } = await import('../auth/AuthContext.jsx');
const { default: App } = await import('../App.jsx');
const apiClient = await import('../services/apiClient.js');

const mount = () => render(<MemoryRouter><AuthProvider><App /></AuthProvider></MemoryRouter>);
const err = (code, extra = {}) => Object.assign(new apiClient.ApiError(extra.message || code, { status: 401, code, details: extra.details }), {});

beforeEach(() => { authService.login.mockReset(); });

describe('sign-in gate', () => {
  it('shows ONLY the sign-in form when there is no session (no app page renders)', () => {
    mount();
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeTruthy();
    expect(screen.queryByText('Dashboard shown')).toBeNull();
  });

  it('disables submit until both fields are filled, then signs in and shows the app', async () => {
    authService.login.mockResolvedValue({ username: 'alice', role: 'analyst' });
    const u = userEvent.setup();
    mount();
    const btn = screen.getByRole('button', { name: 'Sign in' });
    expect(btn.disabled).toBe(true);
    await u.type(screen.getByLabelText('Username'), '  alice ');
    await u.type(screen.getByLabelText('Password'), 'pw-pw-pw-pw-1');
    expect(btn.disabled).toBe(false);
    await u.click(btn);
    expect(await screen.findByText('Dashboard shown')).toBeTruthy();
    expect(authService.login).toHaveBeenCalledWith({ username: 'alice', password: 'pw-pw-pw-pw-1', totpCode: undefined });
  });

  it('shows a clear message, keeps the username and clears the rejected password', async () => {
    authService.login.mockRejectedValue(err('invalid_credentials'));
    const u = userEvent.setup();
    mount();
    await u.type(screen.getByLabelText('Username'), 'alice');
    await u.type(screen.getByLabelText('Password'), 'wrong-wrong-1');
    await u.click(screen.getByRole('button', { name: 'Sign in' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Incorrect username or password/);
    expect(screen.getByLabelText('Username').value).toBe('alice');
    expect(screen.getByLabelText('Password').value).toBe('');
  });

  it('asks for the one-time code when the account has MFA, then sends it', async () => {
    authService.login.mockRejectedValueOnce(err('mfa_required')).mockResolvedValueOnce({ username: 'alice', role: 'analyst' });
    const u = userEvent.setup();
    mount();
    await u.type(screen.getByLabelText('Username'), 'alice');
    await u.type(screen.getByLabelText('Password'), 'pw-pw-pw-pw-1');
    await u.click(screen.getByRole('button', { name: 'Sign in' }));
    const code = await screen.findByLabelText('One-time code');
    expect((await screen.findByRole('alert')).textContent).toMatch(/6-digit code/);
    await u.type(screen.getByLabelText('Password'), 'pw-pw-pw-pw-1');          // password was cleared? only on non-MFA errors
    expect(screen.getByRole('button', { name: 'Sign in' }).disabled).toBe(true);   // needs 6 digits
    await u.type(code, '123456');
    await u.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByText('Dashboard shown');
    expect(authService.login).toHaveBeenLastCalledWith(expect.objectContaining({ totpCode: '123456' }));
  });

  it('explains a locked account', async () => {
    authService.login.mockRejectedValue(err('account_locked', { details: { retry_after_seconds: 600 } }));
    const u = userEvent.setup();
    mount();
    await u.type(screen.getByLabelText('Username'), 'alice');
    await u.type(screen.getByLabelText('Password'), 'pw-pw-pw-pw-1');
    await u.click(screen.getByRole('button', { name: 'Sign in' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/locked.*10 minutes/);
  });

  it('returns to sign-in with an explanation when the API client reports the session is over', async () => {
    authService.login.mockResolvedValue({ username: 'alice', role: 'analyst' });
    const u = userEvent.setup();
    mount();
    await u.type(screen.getByLabelText('Username'), 'alice');
    await u.type(screen.getByLabelText('Password'), 'pw-pw-pw-pw-1');
    await u.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByText('Dashboard shown');
    // simulate the client's refresh being rejected: it invokes the registered handler
    apiClient.setSession({ accessToken: 'a', refreshToken: 'dead' });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'x', details: null } }), { status: 401 })));
    await act(async () => { await apiClient.request('/anything').catch(() => {}); });
    await waitFor(() => expect(screen.queryByText('Dashboard shown')).toBeNull());
    expect(screen.getByRole('status').textContent).toMatch(/session expired/i);
    vi.unstubAllGlobals();
  });
});
