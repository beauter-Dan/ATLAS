// END-TO-END against a REAL ATLAS CORE (no mocks). Opt-in: run with
//   VITE_USE_MOCK=false VITE_API_BASE_URL=http://127.0.0.1:8792/api/v1 npm run test:e2e
// Expects a backend seeded with `python -m scripts.seed_synthetic` (users admin1/analyst1/viewer1, password SyntheticPass123!).
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { env } from '../config/env.js';
import * as api from '../services/apiClient.js';
import * as auth from '../services/authService.js';
import { endpoints } from '../services/contract.js';
import { createTarget, getTarget, listTargets, updateTarget } from '../services/targetService.js';
import * as asm from '../services/assessmentService.js';
import { getDashboardSummary } from '../services/dashboardService.js';

const PW = 'SyntheticPass123!';
const live = env.useMock === false;
const raw = (path, init = {}) => fetch(`${env.apiBaseUrl}${path}`, { headers: { 'Content-Type': 'application/json', ...(init.token ? { Authorization: `Bearer ${init.token}` } : {}) }, ...init });
const rawLogin = async (username) => (await (await raw(endpoints.login, { method: 'POST', body: JSON.stringify({ username, password: PW }) })).json()).data;
const form = (over = {}) => ({ name: `E2E ${Date.now()}`, organization: 'E2E Org', baseDomain: 'e2e.test', description: '', authorization: { reference: 'E2E-1', authorizedBy: 'E2E CISO', validFrom: '2026-01-01', validUntil: '2099-01-01' }, ...over });

describe.skipIf(!live)('UI services <-> real ATLAS CORE', () => {
  beforeAll(() => { api.clearSession(); });
  afterAll(() => { api.clearSession(); });

  it('rejects wrong credentials with the backend error code and does not create a session', async () => {
    const err = await auth.login({ username: 'analyst1', password: 'definitely-wrong-1' }).catch((e) => e);
    expect(err).toMatchObject({ status: 401, code: 'invalid_credentials' });
    expect(api.hasSession()).toBe(false);
    expect(await api.request(endpoints.me).catch((e) => e)).toMatchObject({ status: 401, code: 'unauthorized' });
  });

  it('analyst: login, list, detail with per-assessment scope, and dashboard', async () => {
    const user = await auth.login({ username: 'analyst1', password: PW });
    expect(user).toMatchObject({ username: 'analyst1', role: 'analyst' });

    const targets = await listTargets();
    const seeded = targets.find((t) => t.name === 'Synthetic Shop Ltd');
    expect(seeded).toMatchObject({ baseDomain: 'example.test', organization: '', authorization: { status: 'authorized', reference: 'SYNTH-AUTH-001' } });
    expect(seeded.assessments).toHaveLength(1);

    const detail = await getTarget(seeded.id);
    const scope = Object.values(detail.scope)[0];
    expect(scope.permitted.sort()).toEqual(['*.example.test', 'example.test']);
    expect(scope.excluded).toEqual(['admin.example.test']);

    const d = await getDashboardSummary();
    expect(d).toMatchObject({ targets: expect.any(Number), activeAssessments: 1 });
    expect(d.assessmentProgress[0]).toMatchObject({ name: 'Synthetic baseline assessment', status: 'active' });
    expect(d.assessmentProgress[0].percent).toBeGreaterThan(50);
    expect(d.recentActivity.length).toBeGreaterThan(0);
    expect(Object.keys(d.recentActivity[0]).sort()).toEqual(['id', 'message', 'timestamp']);
  });

  it('analyst: create + edit; the server (not just the UI) refuses authorization edits and duplicates', async () => {
    await auth.login({ username: 'analyst1', password: PW });
    const f = form();
    const created = await createTarget(f);
    expect(created).toMatchObject({ name: f.name, organization: 'E2E Org', baseDomain: 'e2e.test', authorization: { status: 'authorized', validFrom: '2026-01-01', validUntil: '2099-01-01' } });

    expect((await listTargets()).some((t) => t.id === created.id)).toBe(true);
    expect(await createTarget(f).catch((e) => e)).toMatchObject({ status: 409, code: 'conflict' });

    const edited = await updateTarget(created.id, await getTarget(created.id), { ...f, description: 'changed' });
    expect(edited.description).toBe('changed');

    // bypass the disabled form fields: the API still says no
    const forged = await updateTarget(created.id, edited, { ...f, description: 'changed', authorization: { ...f.authorization, validUntil: '2100-01-01' } }).catch((e) => e);
    expect(forged).toMatchObject({ status: 403, code: 'authorization_edit_forbidden' });
  });

  it('viewer: can read, cannot write', async () => {
    await auth.login({ username: 'viewer1', password: PW });
    expect((await listTargets()).length).toBeGreaterThan(0);
    expect(await createTarget(form({ name: 'Viewer attempt' })).catch((e) => e)).toMatchObject({ status: 403, code: 'forbidden' });
  });

  it('another user cannot see or open a target they have no access to (404, not 403)', async () => {
    await auth.login({ username: 'admin1', password: PW });
    const stranger = `stranger${Date.now()}`;
    const res = await raw(endpoints.refresh.replace('/refresh', '/users'), { method: 'POST', token: (await rawLogin('admin1')).access_token, body: JSON.stringify({ username: stranger, password: 'Stranger-Passw0rd-9', role: 'analyst' }) });
    expect(res.status).toBe(201);
    const seededId = (await listTargets()).find((t) => t.name === 'Synthetic Shop Ltd').id;
    await auth.login({ username: stranger, password: 'Stranger-Passw0rd-9' });
    expect(await listTargets()).toEqual([]);
    expect(await getTarget(seededId).catch((e) => e)).toMatchObject({ status: 404, code: 'not_found' });
    expect((await getDashboardSummary())).toMatchObject({ targets: 0, activeAssessments: 0, assessmentProgress: [], recentActivity: [] });
  });

  it('refreshes an expired access token transparently, using the rotated tokens', async () => {
    const t = await rawLogin('analyst1');
    api.setSession({ accessToken: 'expired-or-bogus', refreshToken: t.refresh_token });
    expect((await api.request(endpoints.me)).data.username).toBe('analyst1');          // 401 -> refresh -> retry
    // the original refresh token was rotated out: replaying it is a theft signal and revokes the session
    const replay = await raw(endpoints.refresh, { method: 'POST', body: JSON.stringify({ refresh_token: t.refresh_token }) });
    expect(replay.status).toBe(401);
  });

  it('when the session is revoked server-side the client signs the user out', async () => {
    const lost = vi.fn();
    api.onAuthLost(lost);
    await auth.login({ username: 'analyst1', password: PW });
    await raw('/auth/logout-all', { method: 'POST', token: (await rawLogin('analyst1')).access_token });   // revokes every session of the user
    const err = await api.request(endpoints.me).catch((e) => e);
    expect(err).toMatchObject({ code: 'session_expired' });
    expect(lost).toHaveBeenCalledTimes(1);
    expect(api.hasSession()).toBe(false);
    api.onAuthLost(null);
  });

  it('logout revokes the token on the server', async () => {
    const t = await rawLogin('viewer1');
    api.setSession({ accessToken: t.access_token, refreshToken: t.refresh_token });
    await auth.logout();
    expect((await raw(endpoints.me, { token: t.access_token })).status).toBe(401);
    expect(api.hasSession()).toBe(false);
  });

  it('CORS: the backend answers a browser preflight for the UI origin', async () => {
    const r = await fetch(`${env.apiBaseUrl}/targets`, { method: 'OPTIONS', headers: { Origin: 'http://localhost:5173', 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' } });
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
  });

  describe('assessments: lifecycle, scope and members', () => {
    const name = `E2E assessment ${Date.now()}`;
    let aid; let targetId;

    it('analyst creates an assessment and is its owner (listed first among members)', async () => {
      await auth.login({ username: 'analyst1', password: PW });
      targetId = (await listTargets()).find((t) => t.name === 'Synthetic Shop Ltd').id;
      aid = (await asm.createAssessment({ targetId, name, environment: 'staging', description: 'e2e' })).id;
      expect((await asm.listAssessments()).find((a) => a.id === aid)).toMatchObject({ name, targetName: 'Synthetic Shop Ltd', status: 'draft' });
      const d = await asm.getAssessment(aid);
      expect(d).toMatchObject({ status: 'draft', environment: 'staging', rules: [], target: { name: 'Synthetic Shop Ltd', authorizationStatus: 'authorized' } });
      expect(d.members).toEqual([expect.objectContaining({ username: 'analyst1', isOwner: true, permission: 'analyst' })]);
      expect(Object.keys(d.counts).sort()).toEqual(['assets', 'experiments', 'findings', 'hypotheses', 'observations']);
    });

    it('the seeded assessment reports real collected counts', async () => {
      const seeded = (await asm.listAssessments()).find((a) => a.name === 'Synthetic baseline assessment');
      const d = await asm.getAssessment(seeded.id);
      expect(d.counts.assets).toBeGreaterThan(0);
      expect(d.counts.observations).toBeGreaterThan(0);
      expect(d.rules.map((r) => `${r.type}:${r.value}`).sort()).toEqual(['exclude:admin.example.test', 'include:*.example.test', 'include:example.test']);
    });

    it('an analyst cannot change scope or status (server refuses even though the UI would hide the controls)', async () => {
      expect(await asm.addRule(aid, { type: 'include', match: 'domain', value: 'x.example.test', note: '' }).catch((e) => e)).toMatchObject({ status: 403, code: 'forbidden' });
      expect(await asm.setStatus(aid, 'active').catch((e) => e)).toMatchObject({ status: 403, code: 'forbidden' });
    });

    it('an approver who is not a member cannot even see it (404)', async () => {
      await auth.login({ username: 'approver1', password: PW });
      expect((await asm.listAssessments()).some((a) => a.id === aid)).toBe(false);
      expect(await asm.getAssessment(aid).catch((e) => e)).toMatchObject({ status: 404, code: 'not_found' });
    });

    it('admin adds the approver as a member; scope rule errors carry the server code', async () => {
      await auth.login({ username: 'admin1', password: PW });
      await asm.addMember(aid, 'approver1', 'approver');
      expect((await asm.getAssessment(aid)).members.map((m) => `${m.username}:${m.permission}`).sort()).toEqual(['analyst1:analyst', 'approver1:approver']);
      expect(await asm.addMember(aid, 'no-such-user', 'viewer').catch((e) => e)).toMatchObject({ status: 404, code: 'not_found' });
      expect(await asm.addMember(aid, 'analyst1', 'viewer').catch((e) => e)).toMatchObject({ status: 409, code: 'owner_immutable' });
      expect(await asm.addRule(aid, { type: 'include', match: 'wildcard', value: 'example.test', note: '' }).catch((e) => e)).toMatchObject({ status: 422, code: 'invalid_scope_rule' });
    });

    it('approver: activation is refused without scope, then allowed once a permitted rule exists; invalid transitions are refused', async () => {
      await auth.login({ username: 'approver1', password: PW });
      expect(await asm.setStatus(aid, 'active').catch((e) => e)).toMatchObject({ status: 422, code: 'scope_required' });
      await asm.addRule(aid, { type: 'include', match: 'domain', value: 'EXAMPLE.test', note: 'primary' });            // approver adds scope
      expect(await asm.addRule(aid, { type: 'include', match: 'domain', value: 'example.test', note: '' }).catch((e) => e)).toMatchObject({ status: 409, code: 'conflict' });
      await asm.setStatus(aid, 'active');
      expect((await asm.getAssessment(aid)).status).toBe('active');
      expect(await asm.setStatus(aid, 'draft').catch((e) => e)).toMatchObject({ status: 409, code: 'invalid_transition' });
      await asm.setStatus(aid, 'paused');
      expect((await asm.getAssessment(aid)).status).toBe('paused');
    });

    it('approver removes a rule; analyst member removal works for non-owners only', async () => {
      const rule = (await asm.getAssessment(aid)).rules[0];
      await asm.removeRule(rule.id);
      expect((await asm.getAssessment(aid)).rules).toEqual([]);
      await auth.login({ username: 'admin1', password: PW });
      const approverId = (await asm.getAssessment(aid)).members.find((m) => m.username === 'approver1').userId;
      await asm.removeMember(aid, approverId);
      expect((await asm.getAssessment(aid)).members.map((m) => m.username)).toEqual(['analyst1']);
    });

    it('the dashboard reflects the new draft/paused assessment for its owner', async () => {
      await auth.login({ username: 'analyst1', password: PW });
      const d = await getDashboardSummary();
      expect(d.assessmentProgress.map((p) => p.id)).toContain(aid);
    });
  });
});
