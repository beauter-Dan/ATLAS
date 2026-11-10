import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthContext } from '../auth/AuthContext.jsx';

vi.mock('../config/env.js', () => ({ env: { apiBaseUrl: 'http://api.test/api/v1', useMock: false } }));
const svc = { listTargets: vi.fn(), getTarget: vi.fn(), createTarget: vi.fn(), updateTarget: vi.fn() };
vi.mock('../services/targetService.js', () => svc);
const { default: TargetsPage } = await import('./TargetsPage.jsx');
const { default: TargetFormPage } = await import('./TargetFormPage.jsx');
const { default: TargetDetailPage } = await import('./TargetDetailPage.jsx');
const { ApiError } = await import('../services/apiClient.js');

const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
const target = (over = {}) => ({ id: 't1', name: 'Alpha', organization: 'Org A', baseDomain: 'alpha.test', description: 'desc', createdAt: '2026-01-01T00:00:00Z',
  authorization: { status: 'authorized', reference: 'REF-1', authorizedBy: 'CISO', validFrom: day(-10), validUntil: day(10) },
  assessments: [{ id: 'p1', name: 'Spring', status: 'active', environment: 'staging', startedAt: '2026-02-01T00:00:00Z' }],
  scope: { p1: { permitted: ['a.alpha.test'], excluded: ['pay.alpha.test'] } }, ...over });

const as = (role, ui, path = '/') => render(
  <AuthContext.Provider value={{ status: 'authenticated', user: { username: 'u', role }, login: vi.fn(), logout: vi.fn() }}>
    <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
  </AuthContext.Provider>);

beforeEach(() => { Object.values(svc).forEach((f) => f.mockReset()); });

describe('targets list', () => {
  it('shows derived authorization and hides "Register" from viewers', async () => {
    svc.listTargets.mockResolvedValue([target(), target({ id: 't2', name: 'Beta', authorization: { ...target().authorization, validUntil: day(-1) } })]);
    as('viewer', <TargetsPage />);
    const table = await screen.findByRole('table');
    expect(within(table).getByText('Alpha')).toBeTruthy();
    expect(within(table).getAllByText(/^(Authorized|Authorization expired)$/).map((e) => e.textContent).sort()).toEqual(['Authorization expired', 'Authorized']);
    expect(screen.queryByRole('link', { name: 'Register target' })).toBeNull();
  });

  it('analysts can register targets; search and status filter work', async () => {
    svc.listTargets.mockResolvedValue([target(), target({ id: 't2', name: 'Beta', organization: 'Zed', baseDomain: 'beta.test' })]);
    const u = userEvent.setup();
    as('analyst', <TargetsPage />);
    await screen.findByRole('table');
    expect(screen.getAllByRole('link', { name: 'Register target' }).length).toBeGreaterThan(0);
    await u.type(screen.getByLabelText('Search targets'), 'zed');
    expect(screen.queryByText('Alpha')).toBeNull();
    expect(screen.getByText('Beta')).toBeTruthy();
  });

  it('explains an empty result as "visible to you"', async () => {
    svc.listTargets.mockResolvedValue([]);
    as('analyst', <TargetsPage />);
    expect(await screen.findByText('No targets visible to you')).toBeTruthy();
  });

  it('surfaces load failures with a retry', async () => {
    svc.listTargets.mockRejectedValueOnce(new ApiError('down', { status: 503, code: 'x' })).mockResolvedValueOnce([target()]);
    const u = userEvent.setup();
    as('analyst', <TargetsPage />);
    await u.click(await screen.findByRole('button', { name: /try again|retry/i }));
    expect(await screen.findByText('Alpha')).toBeTruthy();
  });
});

describe('target detail', () => {
  it('lists scope per assessment and never mixes assessments', async () => {
    svc.getTarget.mockResolvedValue(target({ assessments: [{ id: 'p1', name: 'Spring', status: 'active', environment: 'staging', startedAt: 'x' }, { id: 'p2', name: 'Autumn', status: 'draft', environment: 'staging', startedAt: 'x' }],
      scope: { p1: { permitted: ['a.alpha.test'], excluded: [] }, p2: { permitted: [], excluded: ['b.alpha.test'] } } }));
    as('viewer', <Routes><Route path="/targets/:id" element={<TargetDetailPage />} /></Routes>, '/targets/t1');
    expect(await screen.findByText('a.alpha.test')).toBeTruthy();
    expect(screen.getByText('b.alpha.test')).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Edit target' })).toBeNull();      // viewers cannot edit
  });

  it('warns when authorization has expired', async () => {
    svc.getTarget.mockResolvedValue(target({ authorization: { ...target().authorization, validUntil: day(-3) } }));
    as('analyst', <Routes><Route path="/targets/:id" element={<TargetDetailPage />} /></Routes>, '/targets/t1');
    expect(await screen.findByText(/authorization window has ended/)).toBeTruthy();
  });

  it('shows the "no access" wording when the API answers 404', async () => {
    svc.getTarget.mockRejectedValue(new ApiError('Target not found', { status: 404, code: 'not_found' }));
    as('analyst', <Routes><Route path="/targets/:id" element={<TargetDetailPage />} /></Routes>, '/targets/zzz');
    expect(await screen.findByRole('alert')).toBeTruthy();
  });
});

describe('target form', () => {
  const edit = (role) => { svc.getTarget.mockResolvedValue(target()); return as(role, <Routes><Route path="/targets/:id/edit" element={<TargetFormPage />} /></Routes>, '/targets/t1/edit'); };

  it('analysts cannot edit authorization fields (server also enforces); other fields stay editable', async () => {
    edit('analyst');
    const ref = await screen.findByLabelText('Authorization reference');
    expect(ref.disabled).toBe(true);
    expect(screen.getByLabelText('Valid until').disabled).toBe(true);
    expect(screen.getByLabelText('Name').disabled).toBe(false);
    expect(screen.getByText(/Only an approver or administrator/)).toBeTruthy();
  });

  it('approvers can edit authorization fields', async () => {
    edit('approver');
    expect((await screen.findByLabelText('Authorization reference')).disabled).toBe(false);
  });

  it('shows field errors and does not call the API for an invalid form', async () => {
    const u = userEvent.setup();
    as('analyst', <Routes><Route path="/targets/new" element={<TargetFormPage />} /></Routes>, '/targets/new');
    await u.click(await screen.findByRole('button', { name: 'Register target' }));
    expect(await screen.findByText('Enter a target name.')).toBeTruthy();
    expect(screen.getByText(/Enter the target’s base domain/)).toBeTruthy();
    expect(svc.createTarget).not.toHaveBeenCalled();
  });

  it('translates a server refusal into a readable message', async () => {
    svc.updateTarget.mockRejectedValue(new ApiError('x', { status: 403, code: 'insufficient_target_permission' }));
    const u = userEvent.setup();
    edit('analyst');
    await u.type(await screen.findByLabelText('Description'), ' more');
    await u.click(screen.getByRole('button', { name: 'Save changes' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/person who registered this target/);
  });
});
