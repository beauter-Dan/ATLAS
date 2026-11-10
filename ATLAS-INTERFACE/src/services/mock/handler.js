import { assessments, counts, dashboard, knownUsers, members, mockUser, scopeRules, targets } from './data.js';

// In-memory store: resets on page reload. Responses use the real backend envelope: {data, meta}.
const store = { targets: structuredClone(targets), assessments: structuredClone(assessments), rules: structuredClone(scopeRules), members: structuredClone(members) };
const TRANSITIONS = { draft: ['active', 'archived'], active: ['paused', 'completed'], paused: ['active', 'completed', 'archived'], completed: ['archived'], archived: [] };
const HOSTRE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const authValid = (t) => t.authorization_reference && t.authorized_by && t.authorization_valid_from && t.authorization_valid_until
  && new Date(t.authorization_valid_from) <= new Date() && new Date() <= new Date(t.authorization_valid_until);
const wait = () => new Promise((r) => setTimeout(r, 200));

async function fail(message, status, code, details = null) {
  const { ApiError } = await import('../apiClient.js');
  throw new ApiError(message, { status, code, details });
}

const page = (rows, q) => {
  const size = Number(q.get('page_size') || 50), n = Number(q.get('page') || 1);
  return { data: structuredClone(rows.slice((n - 1) * size, n * size)), meta: { page: n, page_size: size, total: rows.length } };
};
const filterBy = (rows, q, keys) => rows.filter((r) => keys.every((k) => !q.has(k) || r[k] === q.get(k)));
const AUTH_FIELDS = ['authorization_reference', 'authorized_by', 'authorization_valid_from', 'authorization_valid_until'];

export async function mockRequest(rawPath, { method = 'GET', body } = {}) {
  await wait();
  const [path, query = ''] = rawPath.split('?');
  const q = new URLSearchParams(query);

  if (path === '/auth/me') return { data: mockUser };
  if (path === '/auth/login' && method === 'POST') return { data: { access_token: 'demo', refresh_token: 'demo', token_type: 'bearer', expires_in: 900, user: mockUser } };
  if (path === '/auth/logout') return null;
  if (path === '/dashboard/summary') return { data: { ...structuredClone(dashboard), targets: store.targets.length } };
  if (path === '/assessments' && method === 'GET') return page(filterBy(store.assessments, q, ['target_id']), q);
  if (path === '/assessments' && method === 'POST') {
    if (!store.targets.some((t) => t.id === body?.target_id)) return fail('Target not found', 404, 'not_found');
    if (!body.name) return fail('Invalid request', 422, 'validation_error', [{ loc: ['body', 'name'], msg: 'Field required' }]);
    const a = { id: `p${Date.now()}`, target_id: body.target_id, name: body.name, description: body.description ?? null, status: 'draft', environment: body.environment || 'staging', owner_id: mockUser.id, created_at: new Date().toISOString() };
    store.assessments.unshift(a); store.members[a.id] = [{ user_id: mockUser.id, username: mockUser.username, permission: 'approver', is_owner: true }];
    return { data: structuredClone(a) };
  }
  let m2 = path.match(/^\/assessments\/([^/]+)$/);
  if (m2) { const a = store.assessments.find((x) => x.id === m2[1]); return a ? { data: structuredClone(a) } : fail('Assessment not found', 404, 'not_found'); }
  m2 = path.match(/^\/assessments\/([^/]+)\/status$/);
  if (m2 && method === 'POST') {
    const a = store.assessments.find((x) => x.id === m2[1]);
    if (!a) return fail('Assessment not found', 404, 'not_found');
    if (!TRANSITIONS[a.status].includes(body.status)) return fail(`${a.status} -> ${body.status} not allowed`, 409, 'invalid_transition');
    if (body.status === 'active') {
      if (!authValid(store.targets.find((t) => t.id === a.target_id))) return fail('Authorization expired or missing', 422, 'authorization_required');
      if (!store.rules.some((r) => r.assessment_id === a.id && r.rule_type === 'include')) return fail('At least one include scope rule is required', 422, 'scope_required');
    }
    a.status = body.status;
    return { data: { id: a.id, status: a.status } };
  }
  m2 = path.match(/^\/assessments\/([^/]+)\/members(?:\/([^/]+))?$/);
  if (m2) {
    const list = (store.members[m2[1]] ||= []);
    if (method === 'GET') return { data: structuredClone(list) };
    const owner = list.find((x) => x.is_owner);
    if (m2[2] === owner?.user_id) return fail('The owner\'s access cannot be changed', 409, 'owner_immutable');
    if (method === 'PUT') {
      const u = knownUsers.find((x) => x.id === m2[2]);
      if (!u) return fail('User not found', 404, 'not_found');
      const cur = list.find((x) => x.user_id === u.id);
      if (cur) cur.permission = body.permission; else list.push({ user_id: u.id, username: u.username, permission: body.permission, is_owner: false });
      return { data: structuredClone(list.find((x) => x.user_id === u.id)) };
    }
    if (method === 'DELETE') { store.members[m2[1]] = list.filter((x) => x.user_id !== m2[2]); return null; }
  }
  if (path === '/auth/users/lookup') { const u = knownUsers.find((x) => x.username === q.get('username')); return u ? { data: { id: u.id, username: u.username, role: u.role } } : fail('User not found', 404, 'not_found'); }
  if (counts[path]) return { data: [], meta: { page: 1, page_size: 1, total: counts[path][q.get('assessment_id')] ?? 0 } };
  if (path === '/scope-rules' && method === 'GET') return page(filterBy(store.rules, q, ['assessment_id']), q);
  if (path === '/scope-rules' && method === 'POST') {
    const v = String(body.value || '').toLowerCase();
    const ok = { domain: HOSTRE.test(v), wildcard: v.startsWith('*.') && HOSTRE.test(v.slice(2)), ip: /^[0-9a-f:.]+$/.test(v), cidr: /^[0-9a-f:.]+\/\d+$/.test(v), url_prefix: /^https?:\/\//.test(v) }[body.match_type];
    if (!ok) return fail(`Invalid value for ${body.match_type}: '${body.value}'`, 422, 'invalid_scope_rule');
    if (store.rules.some((r) => r.assessment_id === body.assessment_id && r.rule_type === body.rule_type && r.match_type === body.match_type && r.value === v)) return fail('Constraint violation', 409, 'conflict');
    const rule = { id: `r${Date.now()}`, assessment_id: body.assessment_id, rule_type: body.rule_type, match_type: body.match_type, value: v, note: body.note ?? null };
    store.rules.push(rule);
    return { data: structuredClone(rule) };
  }
  m2 = path.match(/^\/scope-rules\/([^/]+)$/);
  if (m2 && method === 'DELETE') { store.rules = store.rules.filter((r) => r.id !== m2[1]); return null; }

  if (path === '/targets') {
    if (method === 'GET') return page(store.targets, q);
    if (method === 'POST') {
      const missing = ['name', 'base_domain'].filter((k) => !body?.[k]);
      if (missing.length) return fail('Invalid request', 422, 'validation_error', missing.map((m) => ({ loc: ['body', m], msg: 'Field required' })));
      if (store.targets.some((t) => t.name === body.name)) return fail('Constraint violation', 409, 'conflict');
      const created = { organization: null, description: null, authorization_reference: null, authorized_by: null,
        authorization_valid_from: null, authorization_valid_until: null, ...body, id: `t${Date.now()}`, created_by: mockUser.id, created_at: new Date().toISOString() };
      store.targets.unshift(created);
      return { data: structuredClone(created) };
    }
  }

  const m = path.match(/^\/targets\/([^/]+)$/);
  if (m) {
    const t = store.targets.find((x) => x.id === decodeURIComponent(m[1]));
    if (!t) return fail('Target not found', 404, 'not_found');
    if (method === 'GET') return { data: structuredClone(t) };
    if (method === 'PATCH') {
      if (mockUser.role === 'analyst' && AUTH_FIELDS.some((k) => k in body)) return fail('Only an approver or admin may change a target\'s authorization record', 403, 'authorization_edit_forbidden');
      Object.assign(t, body);
      return { data: structuredClone(t) };
    }
  }
  return fail(`No mock available for ${method} ${path}.`, 404, 'mock_missing');
}
