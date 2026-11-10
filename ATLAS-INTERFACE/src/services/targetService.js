import { request } from './apiClient.js';
import { endpoints } from './contract.js';
import { fetchAll } from './pagination.js';
import { groupRules, toCreatePayload, toPatchPayload, toUiTarget } from './mappers.js';

/** Targets with their assessments (two list calls, not N+1). Scope is per assessment, see getTarget. */
export async function listTargets() {
  const [targets, assessments] = await Promise.all([fetchAll(endpoints.targets), fetchAll(endpoints.assessments)]);
  return targets.map((t) => toUiTarget(t, { assessments: assessments.filter((a) => a.target_id === t.id) }));
}

export async function getTarget(id) {
  const [{ data: target }, assessments] = await Promise.all([request(endpoints.target(id)), fetchAll(endpoints.assessments, { target_id: id })]);
  const rules = (await Promise.all(assessments.map((a) => fetchAll(endpoints.scopeRules, { assessment_id: a.id })))).flat();
  return toUiTarget(target, { assessments, scope: groupRules(rules) });
}

export async function createTarget(form) {
  const { data } = await request(endpoints.targets, { method: 'POST', body: toCreatePayload(form) });
  return toUiTarget(data);
}

export async function updateTarget(id, original, form) {
  const patch = toPatchPayload(original, form);
  if (Object.keys(patch).length === 0) return original;
  const { data } = await request(endpoints.target(id), { method: 'PATCH', body: patch });
  return { ...toUiTarget(data), assessments: original.assessments, scope: original.scope };
}
