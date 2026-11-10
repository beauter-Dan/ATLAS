import { beforeEach, describe, expect, it, vi } from 'vitest';

const request = vi.fn();
vi.mock('./apiClient.js', () => ({ request: (...a) => request(...a) }));
const { listTargets, getTarget, createTarget, updateTarget } = await import('./targetService.js');
const { fetchAll } = await import('./pagination.js');

const T = (id) => ({ id, name: id, base_domain: `${id}.test`, organization: 'O', authorization_reference: 'R', authorized_by: 'B',
  authorization_valid_from: '2020-01-01T00:00:00Z', authorization_valid_until: '2099-01-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z' });
const page = (data, total = data.length, p = 1) => ({ data, meta: { page: p, page_size: 200, total } });

beforeEach(() => { request.mockReset(); });

describe('fetchAll', () => {
  it('walks every page and stops at total', async () => {
    request.mockResolvedValueOnce(page(Array(200).fill({ i: 1 }), 250, 1)).mockResolvedValueOnce(page(Array(50).fill({ i: 2 }), 250, 2));
    expect(await fetchAll('/x', { a: 'b' })).toHaveLength(250);
    expect(request.mock.calls[0][0]).toBe('/x?a=b&page=1&page_size=200');
    expect(request.mock.calls[1][0]).toBe('/x?a=b&page=2&page_size=200');
  });
  it('does not loop forever on an empty page', async () => {
    request.mockResolvedValue(page([], 5));
    expect(await fetchAll('/x')).toEqual([]);
    expect(request).toHaveBeenCalledTimes(1);
  });
});

it('listTargets issues two list calls (no N+1) and groups assessments', async () => {
  const asm = { id: 'x', target_id: 'a', name: 'X', status: 'active', environment: 'staging', created_at: 'c' };
  request.mockImplementation(async (...args) => {
    return String(args[0]).startsWith('/targets') ? page([T('a'), T('b')]) : page([asm]);
  });
  const out = await listTargets();
  expect(request).toHaveBeenCalledTimes(2);
  expect(out.map((t) => [t.id, t.assessments.length, t.authorization.status])).toEqual([['a', 1, 'authorized'], ['b', 0, 'authorized']]);
});

it('getTarget loads the target, its assessments and each assessment\'s scope rules', async () => {
  request.mockImplementation(async (p) => {
    if (p === '/targets/a') return { data: T('a') };
    if (p.startsWith('/assessments?target_id=a')) return page([{ id: 'p1', target_id: 'a', name: 'P1', status: 'draft', environment: 'staging', created_at: 'c' }]);
    if (p.startsWith('/scope-rules?assessment_id=p1')) return page([{ assessment_id: 'p1', rule_type: 'include', value: 'a.test' }, { assessment_id: 'p1', rule_type: 'exclude', value: 'x.a.test' }]);
    throw new Error(`unexpected ${p}`);
  });
  const t = await getTarget('a');
  expect(t.scope).toEqual({ p1: { permitted: ['a.test'], excluded: ['x.a.test'] } });
});

it('createTarget POSTs the backend payload', async () => {
  request.mockResolvedValue({ data: T('new') });
  const form = { name: 'N', organization: 'O', baseDomain: 'N.test', description: '', authorization: { reference: 'R', authorizedBy: 'B', validFrom: '2026-01-01', validUntil: '2026-02-01' } };
  const t = await createTarget(form);
  expect(request).toHaveBeenCalledWith('/targets', { method: 'POST', body: expect.objectContaining({ base_domain: 'n.test', authorization_valid_until: '2026-02-01T23:59:59Z' }) });
  expect(t.id).toBe('new');
});

describe('updateTarget', () => {
  const original = { ...{ id: 'a', name: 'a', organization: 'O', baseDomain: 'a.test', description: '', authorization: { reference: 'R', authorizedBy: 'B', validFrom: '2020-01-01', validUntil: '2099-01-01' } }, assessments: ['keep'], scope: { k: 1 } };
  it('sends nothing when nothing changed', async () => {
    const same = { name: 'a', organization: 'O', baseDomain: 'a.test', description: '', authorization: { ...original.authorization } };
    expect(await updateTarget('a', original, same)).toBe(original);
    expect(request).not.toHaveBeenCalled();
  });
  it('PATCHes only the diff and keeps assessments/scope', async () => {
    request.mockResolvedValue({ data: { ...T('a'), description: 'new' } });
    const form = { name: 'a', organization: 'O', baseDomain: 'a.test', description: 'new', authorization: { ...original.authorization } };
    const out = await updateTarget('a', original, form);
    expect(request).toHaveBeenCalledWith('/targets/a', { method: 'PATCH', body: { description: 'new' } });
    expect(out.assessments).toEqual(['keep']);
    expect(out.scope).toEqual({ k: 1 });
  });
});
