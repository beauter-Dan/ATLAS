// Endpoint map. Every path below exists in ATLAS-SHARED/contracts/openapi.json (v1.1.0).
// Components never build URLs themselves. Do not add a path that is not in the contract.
export const endpoints = {
  login: '/auth/login',
  refresh: '/auth/refresh',
  logout: '/auth/logout',
  me: '/auth/me',
  dashboardSummary: '/dashboard/summary',
  targets: '/targets',
  target: (id) => `/targets/${encodeURIComponent(id)}`,
  assessments: '/assessments',
  assessment: (id) => `/assessments/${encodeURIComponent(id)}`,
  assessmentStatus: (id) => `/assessments/${encodeURIComponent(id)}/status`,
  members: (id) => `/assessments/${encodeURIComponent(id)}/members`,
  member: (id, uid) => `/assessments/${encodeURIComponent(id)}/members/${encodeURIComponent(uid)}`,
  userLookup: '/auth/users/lookup',
  scopeRules: '/scope-rules',
  scopeRule: (id) => `/scope-rules/${encodeURIComponent(id)}`,
  counts: { assets: '/assets', observations: '/observations', hypotheses: '/hypotheses', experiments: '/experiments', findings: '/findings' },
};
