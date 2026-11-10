const ago = (min) => new Date(Date.now() - min * 60000).toISOString();
const day = (offset, end = false) => `${new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10)}T${end ? '23:59:59' : '00:00:00'}Z`;

// SYNTHETIC DEMO DATA ONLY (reserved .example names). Shapes are the REAL backend contract (ATLAS-SHARED/contracts/openapi.json),
// so the same mappers run in demo mode and against the live API.
export const mockUser = { id: 'u-demo', username: 'demo.approver', role: 'approver', is_active: true, mfa_enabled: false };

export const targets = [
  { id: 't1', name: 'Demo Retail', organization: 'Example Retail Ltd', base_domain: 'retail.example', description: 'Public storefront and checkout services.',
    authorization_reference: 'ENG-2026-014', authorized_by: 'Example Retail security office', authorization_valid_from: day(-30), authorization_valid_until: day(60, true), created_by: 'u-demo', created_at: ago(60 * 24 * 40) },
  { id: 't2', name: 'Demo Bank Portal', organization: 'Example Bank plc', base_domain: 'bank.example', description: 'Customer web portal and mobile API.',
    authorization_reference: 'ENG-2026-021', authorized_by: 'Example Bank CISO', authorization_valid_from: day(-10), authorization_valid_until: day(80, true), created_by: 'u-demo', created_at: ago(60 * 24 * 20) },
  { id: 't3', name: 'Demo Logistics', organization: 'Example Freight Co', base_domain: 'freight.example', description: 'Tracking site; engagement paperwork still in progress.',
    authorization_reference: 'ENG-2026-030', authorized_by: 'Example Freight legal', authorization_valid_from: day(5), authorization_valid_until: day(95, true), created_by: 'u-demo', created_at: ago(60 * 24 * 3) },
  { id: 't4', name: 'Demo Media (2025)', organization: 'Example Media Group', base_domain: 'media.example', description: 'Previous engagement that has ended.',
    authorization_reference: 'ENG-2025-088', authorized_by: 'Example Media IT', authorization_valid_from: day(-200), authorization_valid_until: day(-20, true), created_by: 'u-demo', created_at: ago(60 * 24 * 210) },
];

export const assessments = [
  { id: 'p1', target_id: 't1', name: 'Spring review', status: 'active', environment: 'staging', created_at: ago(130) },
  { id: 'p2', target_id: 't2', name: 'Partner portal baseline', status: 'draft', environment: 'staging', created_at: ago(20) },
  { id: 'p0', target_id: 't4', name: 'Autumn baseline', status: 'completed', environment: 'staging', created_at: ago(60 * 24 * 120) },
];

export const scopeRules = [
  { id: 'r1', assessment_id: 'p1', rule_type: 'include', match_type: 'domain', value: 'shop.retail.example' },
  { id: 'r2', assessment_id: 'p1', rule_type: 'include', match_type: 'wildcard', value: '*.api.retail.example' },
  { id: 'r3', assessment_id: 'p1', rule_type: 'exclude', match_type: 'domain', value: 'payments.retail.example' },
  { id: 'r4', assessment_id: 'p2', rule_type: 'include', match_type: 'domain', value: 'portal.bank.example' },
  { id: 'r5', assessment_id: 'p2', rule_type: 'exclude', match_type: 'domain', value: 'core.bank.example' },
  { id: 'r6', assessment_id: 'p0', rule_type: 'include', match_type: 'domain', value: 'www.media.example' },
];

export const dashboard = {
  targets: 4, active_assessments: 1, assets: 187, technologies: 23, pending_hypotheses: 9, confirmed_findings: 5,
  recent_activity: [
    { id: 'a1', timestamp: ago(6), message: 'Data collection ran · Spring review' },
    { id: 'a2', timestamp: ago(41), message: 'Hypotheses generated · Spring review' },
    { id: 'a3', timestamp: ago(130), message: 'Assessment created · Spring review' },
  ],
  assessment_progress: [
    { id: 'p1', name: 'Spring review', percent: 57, status: 'active' },
    { id: 'p2', name: 'Partner portal baseline', percent: 14, status: 'draft' },
  ],
};

export const members = {
  p1: [{ user_id: 'u-demo', username: 'demo.approver', permission: 'approver', is_owner: true }, { user_id: 'u-v', username: 'demo.viewer', permission: 'viewer', is_owner: false }],
  p2: [{ user_id: 'u-demo', username: 'demo.approver', permission: 'approver', is_owner: true }],
  p0: [{ user_id: 'u-demo', username: 'demo.approver', permission: 'approver', is_owner: true }],
};
export const knownUsers = [mockUser, { id: 'u-v', username: 'demo.viewer', role: 'viewer' }, { id: 'u-a', username: 'demo.analyst', role: 'analyst' }];
export const counts = {
  '/assets': { p1: 187, p2: 0, p0: 64 }, '/observations': { p1: 412, p2: 0, p0: 150 }, '/hypotheses': { p1: 9, p2: 0, p0: 12 },
  '/experiments': { p1: 2, p2: 0, p0: 3 }, '/findings': { p1: 5, p2: 0, p0: 7 },
};
