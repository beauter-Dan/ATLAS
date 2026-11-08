// Drives both the sidebar and the router. `milestone` refers to the build plan.
export const NAV_GROUPS = [
  { label: 'Overview', items: [
    { path: '/', title: 'Dashboard', description: 'Targets, assessments, assets and findings at a glance.', milestone: 4 },
  ]},
  { label: 'Scope', items: [
    { path: '/targets', title: 'Targets', description: 'Register targets, define permitted and excluded assets, review authorization.', milestone: 5 },
    { path: '/assessments', title: 'Assessments', description: 'Configure, start and monitor assessments.', milestone: 6 },
  ]},
  { label: 'Collection', items: [
    { path: '/reconnaissance', title: 'Reconnaissance', description: 'Domains, DNS, certificates, HTTP and TLS metadata, fingerprints.', milestone: 7 },
    { path: '/assets', title: 'Asset inventory', description: 'Searchable inventory with clear scope status.', milestone: 8 },
    { path: '/architecture', title: 'Architecture', description: 'Interactive graph of domains, services, APIs, data stores and third parties.', milestone: 9 },
  ]},
  { label: 'Intelligence', items: [
    { path: '/applications', title: 'Applications', description: 'Routes, controllers, middleware, authentication and authorization.', milestone: 10 },
    { path: '/databases', title: 'Databases', description: 'Schemas, tables, relationships and data classifications from authorized evidence.', milestone: 11 },
    { path: '/apis', title: 'APIs', description: 'Endpoints, methods, authentication and structures.', milestone: 12 },
  ]},
  { label: 'Analysis', items: [
    { path: '/analysis', title: 'AI analysis', description: 'Observations, hypotheses, reasoning, evidence and confidence.', milestone: 13 },
    { path: '/experiments', title: 'Experiments', description: 'Proposed experiments, approvals, execution and audit history.', milestone: 14 },
    { path: '/findings', title: 'Findings', description: 'Validated findings with severity, evidence and remediation.', milestone: 15 },
    { path: '/reports', title: 'Reports', description: 'Browse and export assessment reports.', milestone: 15 },
  ]},
  { label: 'System', items: [
    { path: '/settings', title: 'Settings', description: 'Profile, API connection, AI provider, preferences and security.', milestone: 15 },
  ]},
];

export const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);
