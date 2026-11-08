import { dashboardSummary, targets } from './data.js';

// In-memory store: resets on page reload. Mirrors the provisional shapes in src/types/models.js.
const store = { targets: structuredClone(targets) };
const wait = () => new Promise((r) => setTimeout(r, 300));

async function fail(message, status, code) {
  const { ApiError } = await import('../apiClient.js');
  throw new ApiError(message, { status, code });
}

const AUTH_KEYS = ['reference', 'authorizedBy', 'validFrom', 'validUntil'];

export async function mockRequest(path, { method = 'GET', body } = {}) {
  await wait();

  if (method === 'GET' && path === '/dashboard/summary') {
    return structuredClone({ ...dashboardSummary, targets: store.targets.length });
  }

  if (path === '/targets') {
    if (method === 'GET') return structuredClone(store.targets);
    if (method === 'POST') {
      const now = new Date().toISOString();
      const created = {
        ...body,
        id: `t${Date.now()}`,
        authorization: { ...body.authorization, status: 'pending' }, // only the backend authorizes
        assessments: [], createdAt: now, updatedAt: now,
      };
      store.targets.unshift(created);
      return structuredClone(created);
    }
  }

  const m = path.match(/^\/targets\/([^/]+)$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    const idx = store.targets.findIndex((t) => t.id === id);
    if (idx === -1) return fail('That target does not exist.', 404, 'not_found');
    if (method === 'GET') return structuredClone(store.targets[idx]);
    if (method === 'PUT') {
      const prev = store.targets[idx];
      const authChanged = AUTH_KEYS.some((k) => prev.authorization[k] !== body.authorization[k]);
      store.targets[idx] = {
        ...prev, ...body, id,
        authorization: { ...body.authorization, status: authChanged ? 'pending' : prev.authorization.status },
        assessments: prev.assessments, createdAt: prev.createdAt, updatedAt: new Date().toISOString(),
      };
      return structuredClone(store.targets[idx]);
    }
  }

  return fail(`No mock available for ${method} ${path}.`, 404, 'mock_missing');
}
