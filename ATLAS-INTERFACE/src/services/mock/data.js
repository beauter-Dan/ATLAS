const ago = (min) => new Date(Date.now() - min * 60000).toISOString();
const day = (offset) => new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10);

// SYNTHETIC DEMO DATA ONLY. Uses reserved .example names.
export const dashboardSummary = {
  targets: 4,
  activeAssessments: 2,
  assets: 187,
  technologies: 23,
  pendingHypotheses: 9,
  confirmedFindings: 5,
  recentActivity: [
    { id: 'a1', timestamp: ago(6), message: 'Certificate data collected for Demo Retail' },
    { id: 'a2', timestamp: ago(41), message: 'Hypothesis queued for review on Demo Bank Portal' },
    { id: 'a3', timestamp: ago(130), message: 'Assessment "Spring review" started' },
  ],
  assessmentProgress: [
    { id: 'p1', name: 'Spring review', percent: 62, status: 'collecting' },
    { id: 'p2', name: 'Partner portal baseline', percent: 18, status: 'queued' },
  ],
};

export const targets = [
  {
    id: 't1', name: 'Demo Retail', organization: 'Example Retail Ltd',
    description: 'Public storefront and checkout services.',
    authorization: { status: 'authorized', reference: 'ENG-2026-014', authorizedBy: 'Example Retail security office', validFrom: day(-30), validUntil: day(60) },
    permittedAssets: ['shop.retail.example', '*.api.retail.example', 'cdn.retail.example'],
    excludedAssets: ['payments.retail.example', 'hr.retail.example'],
    assessments: [{ id: 'p1', name: 'Spring review', status: 'collecting', startedAt: ago(130) }],
    createdAt: ago(60 * 24 * 40), updatedAt: ago(60 * 24 * 2),
  },
  {
    id: 't2', name: 'Demo Bank Portal', organization: 'Example Bank plc',
    description: 'Customer web portal and mobile API.',
    authorization: { status: 'authorized', reference: 'ENG-2026-021', authorizedBy: 'Example Bank CISO', validFrom: day(-10), validUntil: day(80) },
    permittedAssets: ['portal.bank.example', 'api.bank.example'],
    excludedAssets: ['core.bank.example'],
    assessments: [{ id: 'p2', name: 'Partner portal baseline', status: 'queued', startedAt: ago(20) }],
    createdAt: ago(60 * 24 * 20), updatedAt: ago(60 * 24),
  },
  {
    id: 't3', name: 'Demo Logistics', organization: 'Example Freight Co',
    description: 'Tracking site; engagement paperwork still in progress.',
    authorization: { status: 'pending', reference: 'ENG-2026-030', authorizedBy: 'Example Freight legal', validFrom: day(5), validUntil: day(95) },
    permittedAssets: ['track.freight.example'],
    excludedAssets: [],
    assessments: [],
    createdAt: ago(60 * 24 * 3), updatedAt: ago(60 * 24 * 3),
  },
  {
    id: 't4', name: 'Demo Media (2025)', organization: 'Example Media Group',
    description: 'Previous engagement that has ended.',
    authorization: { status: 'authorized', reference: 'ENG-2025-088', authorizedBy: 'Example Media IT', validFrom: day(-200), validUntil: day(-20) },
    permittedAssets: ['www.media.example'],
    excludedAssets: ['admin.media.example'],
    assessments: [{ id: 'p0', name: 'Autumn baseline', status: 'complete', startedAt: ago(60 * 24 * 120) }],
    createdAt: ago(60 * 24 * 210), updatedAt: ago(60 * 24 * 25),
  },
];
