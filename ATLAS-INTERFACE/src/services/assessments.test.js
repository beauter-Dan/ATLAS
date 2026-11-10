import { beforeEach, describe, expect, it, vi } from 'vitest';
import { validateRuleValue } from '../utils/scope.js';
import { STATUS_TRANSITIONS, toAssessmentPayload, toRulePayload, toUiAssessmentDetail } from './mappers.js';

const request = vi.fn();
vi.mock('./apiClient.js', () => ({ request: (...a) => request(...a) }));
const svc = await import('./assessmentService.js');
beforeEach(() => { request.mockReset(); });

describe('validateRuleValue (mirrors server rules, server stays authoritative)', () => {
  it.each([
    ['domain', 'example.test', ''], ['domain', 'EXAMPLE.test', ''], ['domain', '*.example.test', 'x'], ['domain', 'https://example.test', 'x'], ['domain', 'exa mple.test', 'x'],
    ['wildcard', '*.example.test', ''], ['wildcard', 'example.test', 'x'], ['wildcard', '*.*.example.test', 'x'], ['wildcard', '*.', 'x'],
    ['ip', '203.0.113.7', ''], ['ip', '2001:db8::1', ''], ['ip', '999.1.1.1', 'x'], ['ip', 'host.test', 'x'],
    ['cidr', '203.0.113.0/24', ''], ['cidr', '203.0.113.0', 'x'], ['cidr', 'foo/24', 'x'],
    ['url_prefix', 'https://example.test/admin', ''], ['url_prefix', 'example.test/admin', 'x'], ['url_prefix', 'ftp://example.test', 'x'],
    ['domain', '', 'x'], ['domain', '   ', 'x'],
  ])('%s %j', (match, value, bad) => {
    expect(Boolean(validateRuleValue(match, value))).toBe(Boolean(bad));
  });
  it('limits length', () => expect(validateRuleValue('url_prefix', `https://a.test/${'x'.repeat(600)}`)).toMatch(/500/));
});

it('status transitions mirror the backend state machine', () => {
  expect(STATUS_TRANSITIONS).toEqual({ draft: ['active', 'archived'], active: ['paused', 'completed'], paused: ['active', 'completed', 'archived'], completed: ['archived'], archived: [] });
});

it('maps payloads', () => {
  expect(toAssessmentPayload({ targetId: 't', name: ' N ', environment: 'test', description: ' ' })).toEqual({ target_id: 't', name: 'N', environment: 'test', description: null });
  expect(toRulePayload('a1', { type: 'exclude', match: 'domain', value: ' X.test ', note: '' })).toEqual({ assessment_id: 'a1', rule_type: 'exclude', match_type: 'domain', value: 'X.test', note: null });
});

it('maps assessment detail incl. derived target authorization', () => {
  const d = toUiAssessmentDetail({ id: 'a', target_id: 't', name: 'A', status: 'draft', environment: 'staging', owner_id: 'u', created_at: 'c', description: null },
    { target: { id: 't', name: 'T', base_domain: 't.test', authorization_reference: null }, rules: [{ id: 'r', rule_type: 'include', match_type: 'domain', value: 'x.test', note: null }],
      members: [{ user_id: 'u', username: 'alice', permission: 'approver', is_owner: true }], counts: { assets: 3 } });
  expect(d).toMatchObject({ id: 'a', description: '', ownerId: 'u', target: { name: 'T', authorizationStatus: 'pending' },
    rules: [{ id: 'r', type: 'include', match: 'domain', value: 'x.test', note: '' }], members: [{ userId: 'u', username: 'alice', isOwner: true }], counts: { assets: 3 } });
});

describe('assessmentService', () => {
  it('getAssessment loads detail, rules, members and the five counts using page_size=1', async () => {
    request.mockImplementation(async (p) => {
      if (p === '/assessments/a1') return { data: { id: 'a1', target_id: 't1', name: 'A', status: 'active', environment: 'staging', created_at: 'c' } };
      if (p === '/targets/t1') return { data: { id: 't1', name: 'T', base_domain: 't.test' } };
      if (p.startsWith('/scope-rules')) return { data: [], meta: { total: 0 } };
      if (p === '/assessments/a1/members') return { data: [] };
      const m = p.match(/^\/(assets|observations|hypotheses|experiments|findings)\?(.*)$/);
      if (m) { expect(new URLSearchParams(m[2]).get('page_size')).toBe('1'); return { data: [], meta: { total: { assets: 5, observations: 6, hypotheses: 7, experiments: 8, findings: 9 }[m[1]] } }; }
      throw new Error(`unexpected ${p}`);
    });
    const a = await svc.getAssessment('a1');
    expect(a.counts).toEqual({ assets: 5, observations: 6, hypotheses: 7, experiments: 8, findings: 9 });
  });

  it('addMember resolves the username to an id first, then PUTs', async () => {
    request.mockResolvedValueOnce({ data: { id: 'u9', username: 'bob', role: 'analyst' } }).mockResolvedValueOnce({ data: {} });
    await svc.addMember('a1', ' bob ', 'analyst');
    expect(request.mock.calls[0][0]).toBe('/auth/users/lookup?username=bob');
    expect(request.mock.calls[1]).toEqual(['/assessments/a1/members/u9', { method: 'PUT', body: { permission: 'analyst' } }]);
  });

  it('removeRule and setStatus hit the contract paths', async () => {
    request.mockResolvedValue(null);
    await svc.removeRule('r1'); await svc.setStatus('a1', 'paused');
    expect(request.mock.calls).toEqual([['/scope-rules/r1', { method: 'DELETE' }], ['/assessments/a1/status', { method: 'POST', body: { status: 'paused' } }]]);
  });
});
