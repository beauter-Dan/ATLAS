// PROVISIONAL endpoint map. Do not add endpoints that are not in
// ATLAS-SHARED/contracts/openapi.json. Check every path here against it once available.
// Components never build URLs themselves.
export const endpoints = {
  dashboardSummary: '/dashboard/summary',
  targets: '/targets',
  target: (id) => `/targets/${encodeURIComponent(id)}`,
};
