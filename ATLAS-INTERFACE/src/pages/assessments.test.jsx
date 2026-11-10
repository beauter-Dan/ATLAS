import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthContext } from '../auth/AuthContext.jsx';

vi.mock('../config/env.js', () => ({ env: { apiBaseUrl: 'http://api.test/api/v1', useMock: false } }));
const svc = { listAssessments: vi.fn(), getAssessment: vi.fn(), createAssessment: vi.fn(), setStatus: vi.fn(), addRule: vi.fn(), removeRule: vi.fn(), addMember: vi.fn(), removeMember: vi.fn() };
vi.mock('../services/assessmentService.js', () => svc);
vi.mock('../services/targetService.js', () => ({ listTargets: vi.fn(async () => [{ id: 't1', name: 'Alpha', baseDomain: 'alpha.test' }]) }));
const { default: AssessmentsPage } = await import('./AssessmentsPage.jsx');
const { default: AssessmentDetailPage } = await import('./AssessmentDetailPage.jsx');
const { default: AssessmentFormPage } = await import('./AssessmentFormPage.jsx');
const { ApiError } = await import('../services/apiClient.js');

const asm = (over = {}) => ({ id: 'a1', name: 'Spring', description: '', status: 'draft', environment: 'staging', createdAt: '2026-01-01T00:00:00Z',
  target: { id: 't1', name: 'Alpha', authorizationStatus: 'authorized' },
  rules: [{ id: 'r1', type: 'include', match: 'domain', value: 'a.alpha.test', note: '' }, { id: 'r2', type: 'exclude', match: 'domain', value: 'pay.alpha.test', note: '' }],
  members: [{ userId: 'u1', username: 'owner1', permission: 'approver', isOwner: true }, { userId: 'u2', username: 'viewer1', permission: 'viewer', isOwner: false }],
  counts: { assets: 4, observations: 0, hypotheses: 0, experiments: 0, findings: 0 }, ...over });

const as = (role, ui, path = '/') => render(
  <AuthContext.Provider value={{ status: 'authenticated', user: { username: 'u', role }, login: vi.fn(), logout: vi.fn() }}>
    <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
  </AuthContext.Provider>);
const detail = (role) => as(role, <Routes><Route path="/assessments/:id" element={<AssessmentDetailPage />} /></Routes>, '/assessments/a1');

beforeEach(() => { Object.values(svc).forEach((f) => f.mockReset()); svc.getAssessment.mockResolvedValue(asm()); });

describe('assessments list', () => {
  it('lists, filters by status, and hides "New assessment" from viewers', async () => {
    svc.listAssessments.mockResolvedValue([
      { id: 'a1', name: 'Spring', targetId: 't1', targetName: 'Alpha', status: 'active', environment: 'staging', createdAt: 'x' },
      { id: 'a2', name: 'Autumn', targetId: 't1', targetName: 'Alpha', status: 'draft', environment: 'test', createdAt: 'x' }]);
    const u = userEvent.setup();
    as('viewer', <AssessmentsPage />);
    await screen.findByRole('table');
    expect(screen.queryByRole('link', { name: 'New assessment' })).toBeNull();
    await u.selectOptions(screen.getByLabelText('Filter by status'), 'draft');
    expect(screen.queryByText('Spring')).toBeNull();
    expect(screen.getByText('Autumn')).toBeTruthy();
  });
  it('analysts see "New assessment"', async () => {
    svc.listAssessments.mockResolvedValue([]);
    as('analyst', <AssessmentsPage />);
    expect(await screen.findByText('No assessments visible to you')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'New assessment' }).length).toBeGreaterThan(0);
  });
});

describe('assessment detail — what each role sees', () => {
  it('viewer: read-only (no status buttons, no rule/member forms, no remove buttons)', async () => {
    detail('viewer');
    await screen.findByText('a.alpha.test');
    expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Add rule' })).toBeNull();
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull();
    expect(screen.getByText('Only approvers can change scope.')).toBeTruthy();
  });
  it('analyst: can manage members but not scope or status', async () => {
    detail('analyst');
    await screen.findByText('a.alpha.test');
    expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Add rule' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Remove viewer1' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Remove owner1' })).toBeNull();              // the owner can never be removed
  });
  it('approver: sees only the status changes valid from the current status', async () => {
    detail('approver');
    await screen.findByText('a.alpha.test');
    expect(screen.getByRole('button', { name: 'Activate' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Archive' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Pause' })).toBeNull();
    expect(screen.getByText(/This assessment is a draft/)).toBeTruthy();
  });
  it('paused assessments offer Resume, not Activate', async () => {
    svc.getAssessment.mockResolvedValue(asm({ status: 'paused' }));
    detail('approver');
    expect(await screen.findByRole('button', { name: 'Resume' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
    expect(screen.getByText(/paused/i, { selector: '.notice' })).toBeTruthy();
  });
  it('warns when the target authorization is not valid', async () => {
    svc.getAssessment.mockResolvedValue(asm({ target: { id: 't1', name: 'Alpha', authorizationStatus: 'expired' } }));
    detail('approver');
    expect(await screen.findByText(/authorization is expired/)).toBeTruthy();
  });
});

describe('assessment detail — actions', () => {
  it('changes status, then reloads', async () => {
    svc.setStatus.mockResolvedValue({});
    const u = userEvent.setup();
    detail('approver');
    await u.click(await screen.findByRole('button', { name: 'Activate' }));
    expect(svc.setStatus).toHaveBeenCalledWith('a1', 'active');
    await waitFor(() => expect(svc.getAssessment).toHaveBeenCalledTimes(2));
  });
  it('explains a refused activation in plain language', async () => {
    svc.setStatus.mockRejectedValue(new ApiError('x', { status: 422, code: 'scope_required' }));
    const u = userEvent.setup();
    detail('approver');
    await u.click(await screen.findByRole('button', { name: 'Activate' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/at least one permitted scope rule/);
  });
  it('validates a rule locally and does not call the API for a bad value', async () => {
    const u = userEvent.setup();
    detail('approver');
    await screen.findByText('a.alpha.test');
    await u.selectOptions(screen.getByLabelText('Match'), 'wildcard');
    await u.type(screen.getByLabelText('Value'), 'alpha.test');
    await u.click(screen.getByRole('button', { name: 'Add rule' }));
    expect(await screen.findByText('Use the form *.example.test.')).toBeTruthy();
    expect(svc.addRule).not.toHaveBeenCalled();
  });
  it('adds a valid rule, clears the field and reloads', async () => {
    svc.addRule.mockResolvedValue({});
    const u = userEvent.setup();
    detail('approver');
    await screen.findByText('a.alpha.test');
    await u.type(screen.getByLabelText('Value'), 'new.alpha.test');
    await u.click(screen.getByRole('button', { name: 'Add rule' }));
    expect(svc.addRule).toHaveBeenCalledWith('a1', { type: 'include', match: 'domain', value: 'new.alpha.test', note: '' });
    await waitFor(() => expect(screen.getByLabelText('Value').value).toBe(''));
  });
  it('removes a rule', async () => {
    svc.removeRule.mockResolvedValue(null);
    const u = userEvent.setup();
    detail('approver');
    await u.click(await screen.findByRole('button', { name: 'Remove rule pay.alpha.test' }));
    expect(svc.removeRule).toHaveBeenCalledWith('r2');
  });
  it('shows the server message when a rule is rejected', async () => {
    svc.addRule.mockRejectedValue(new ApiError("Invalid value for domain: 'x'", { status: 422, code: 'invalid_scope_rule' }));
    const u = userEvent.setup();
    detail('approver');
    await screen.findByText('a.alpha.test');
    await u.type(screen.getByLabelText('Value'), 'ok.alpha.test');
    await u.click(screen.getByRole('button', { name: 'Add rule' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Invalid value for domain/);
  });
  it('adds and removes members; refusal is explained', async () => {
    svc.addMember.mockResolvedValueOnce({}).mockRejectedValueOnce(new ApiError('x', { status: 403, code: 'insufficient_assessment_permission' }));
    svc.removeMember.mockResolvedValue(null);
    const u = userEvent.setup();
    detail('analyst');
    await u.type(await screen.findByLabelText('Username'), 'bob');
    await u.selectOptions(screen.getByLabelText('Permission'), 'analyst');
    await u.click(screen.getByRole('button', { name: 'Add or update' }));
    expect(svc.addMember).toHaveBeenCalledWith('a1', 'bob', 'analyst');
    await u.type(await screen.findByLabelText('Username'), 'eve');
    await u.click(screen.getByRole('button', { name: 'Add or update' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/permission on this assessment does not allow/);
    await u.click(screen.getByRole('button', { name: 'Remove viewer1' }));
    expect(svc.removeMember).toHaveBeenCalledWith('a1', 'u2');
  });
  it('a stranger (404) gets the neutral "no access" wording', async () => {
    svc.getAssessment.mockRejectedValue(new ApiError('Assessment not found', { status: 404, code: 'not_found' }));
    detail('analyst');
    expect(await screen.findByRole('alert')).toBeTruthy();
  });
});

describe('new assessment form', () => {
  it('requires a target and name, then creates and navigates to the new assessment', async () => {
    svc.createAssessment.mockResolvedValue({ id: 'new1' });
    const u = userEvent.setup();
    as('analyst', <Routes><Route path="/assessments/new" element={<AssessmentFormPage />} /><Route path="/assessments/:id" element={<h1>Detail page</h1>} /></Routes>, '/assessments/new');
    await u.click(await screen.findByRole('button', { name: 'Create assessment' }));
    expect(await screen.findByText('Choose a target.')).toBeTruthy();
    expect(screen.getByText('Enter a name.')).toBeTruthy();
    expect(svc.createAssessment).not.toHaveBeenCalled();
    await u.selectOptions(screen.getByLabelText('Target'), 't1');
    await u.type(screen.getByLabelText('Name'), 'My assessment');
    await u.click(screen.getByRole('button', { name: 'Create assessment' }));
    expect(svc.createAssessment).toHaveBeenCalledWith(expect.objectContaining({ targetId: 't1', name: 'My assessment', environment: 'staging' }));
    expect(await screen.findByText('Detail page')).toBeTruthy();
  });
  it('preselects the target from ?target=', async () => {
    as('analyst', <Routes><Route path="/assessments/new" element={<AssessmentFormPage />} /></Routes>, '/assessments/new?target=t1');
    expect((await screen.findByLabelText('Target')).value).toBe('t1');
  });
});
