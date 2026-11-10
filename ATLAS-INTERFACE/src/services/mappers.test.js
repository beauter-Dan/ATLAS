import { describe, expect, it } from 'vitest';
import { authorizationStatus, groupRules, toCreatePayload, toPatchPayload, toUiDashboard, toUiTarget } from './mappers.js';

const raw = (over = {}) => ({
  id: 't1', name: 'N', base_domain: 'n.test', organization: 'Org', description: 'd', authorization_reference: 'REF', authorized_by: 'CISO',
  authorization_valid_from: '2026-01-01T00:00:00Z', authorization_valid_until: '2026-12-31T23:59:59Z', created_at: '2026-01-02T10:00:00Z', ...over,
});
const NOW = new Date('2026-06-15T12:00:00Z');

describe('authorizationStatus (mirrors the backend rule)', () => {
  it('authorized only inside a complete window', () => expect(authorizationStatus(raw(), NOW)).toBe('authorized'));
  it('pending before the window', () => expect(authorizationStatus(raw({ authorization_valid_from: '2026-07-01T00:00:00Z' }), NOW)).toBe('pending'));
  it('expired after the window', () => expect(authorizationStatus(raw({ authorization_valid_until: '2026-06-15T11:59:59Z' }), NOW)).toBe('expired'));
  it.each(['authorization_reference', 'authorized_by', 'authorization_valid_from', 'authorization_valid_until'])('pending when %s is missing', (k) => {
    expect(authorizationStatus(raw({ [k]: null }), NOW)).toBe('pending');
  });
  it('treats naive timestamps as UTC', () => {
    expect(authorizationStatus(raw({ authorization_valid_from: '2026-06-15T11:00:00', authorization_valid_until: '2026-06-15T13:00:00' }), NOW)).toBe('authorized');
  });
});

describe('toUiTarget', () => {
  it('maps fields, dates and defaults', () => {
    const t = toUiTarget(raw({ organization: null, description: null }), { assessments: [{ id: 'a1', target_id: 't1', name: 'A', status: 'active', environment: 'staging', created_at: 'x' }] });
    expect(t).toMatchObject({ id: 't1', name: 'N', organization: '', baseDomain: 'n.test', description: '', createdAt: '2026-01-02T10:00:00Z' });
    expect(t.authorization).toMatchObject({ reference: 'REF', authorizedBy: 'CISO', validFrom: '2026-01-01', validUntil: '2026-12-31' });
    expect(t.assessments).toEqual([{ id: 'a1', targetId: 't1', name: 'A', status: 'active', environment: 'staging', startedAt: 'x' }]);
  });
});

describe('payloads', () => {
  const form = { name: ' N ', organization: ' Org ', baseDomain: ' N.Test ', description: '  ', authorization: { reference: ' R ', authorizedBy: ' B ', validFrom: '2026-01-01', validUntil: '2026-12-31' } };
  it('create payload is trimmed, lower-cased and uses full-day timestamps', () => {
    expect(toCreatePayload(form)).toEqual({ name: 'N', base_domain: 'n.test', organization: 'Org', description: null, authorization_reference: 'R', authorized_by: 'B',
      authorization_valid_from: '2026-01-01T00:00:00Z', authorization_valid_until: '2026-12-31T23:59:59Z' });
  });
  it('patch payload contains ONLY changed fields', () => {
    const original = toUiTarget(raw());
    const same = { name: 'N', organization: 'Org', baseDomain: 'n.test', description: 'd', authorization: { ...original.authorization } };
    expect(toPatchPayload(original, same)).toEqual({});
    expect(toPatchPayload(original, { ...same, description: 'new' })).toEqual({ description: 'new' });
    expect(toPatchPayload(original, { ...same, authorization: { ...same.authorization, reference: 'R2' } })).toEqual({ authorization_reference: 'R2' });
  });
  it('a non-approver editing only the description never sends authorization fields', () => {
    const original = toUiTarget(raw());
    const patch = toPatchPayload(original, { name: 'N', organization: 'Org', baseDomain: 'n.test', description: 'x', authorization: { ...original.authorization } });
    expect(Object.keys(patch).some((k) => k.startsWith('authorization'))).toBe(false);
  });
});

it('groups scope rules per assessment', () => {
  expect(groupRules([
    { assessment_id: 'a', rule_type: 'include', value: 'x.test' }, { assessment_id: 'a', rule_type: 'exclude', value: 'y.test' }, { assessment_id: 'b', rule_type: 'include', value: 'z.test' },
  ])).toEqual({ a: { permitted: ['x.test'], excluded: ['y.test'] }, b: { permitted: ['z.test'], excluded: [] } });
});

it('maps the dashboard summary', () => {
  expect(toUiDashboard({ targets: 1, active_assessments: 2, assets: 3, technologies: 4, pending_hypotheses: 5, confirmed_findings: 6, recent_activity: [], assessment_progress: [] }))
    .toEqual({ targets: 1, activeAssessments: 2, assets: 3, technologies: 4, pendingHypotheses: 5, confirmedFindings: 6, recentActivity: [], assessmentProgress: [] });
});
