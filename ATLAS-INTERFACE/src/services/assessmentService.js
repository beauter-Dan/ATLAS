import { request } from './apiClient.js';
import { endpoints } from './contract.js';
import { fetchAll } from './pagination.js';
import { toAssessmentPayload, toRulePayload, toUiAssessmentDetail, toUiAssessment } from './mappers.js';

export async function listAssessments() {
  const [assessments, targets] = await Promise.all([fetchAll(endpoints.assessments), fetchAll(endpoints.targets)]);
  const names = Object.fromEntries(targets.map((t) => [t.id, t.name]));
  return assessments.map((a) => ({ ...toUiAssessment(a), targetName: names[a.target_id] || 'Unknown target', createdAt: a.created_at }));
}

const total = async (path, assessmentId) =>
  (await request(`${path}?${new URLSearchParams({ assessment_id: assessmentId, page: '1', page_size: '1' })}`)).meta.total;

export async function getAssessment(id) {
  const { data: a } = await request(endpoints.assessment(id));
  const [{ data: target }, rules, members, ...counts] = await Promise.all([
    request(endpoints.target(a.target_id)),
    fetchAll(endpoints.scopeRules, { assessment_id: id }),
    request(endpoints.members(id)).then((r) => r.data),
    ...Object.values(endpoints.counts).map((p) => total(p, id)),
  ]);
  return toUiAssessmentDetail(a, { target, rules, members, counts: Object.fromEntries(Object.keys(endpoints.counts).map((k, i) => [k, counts[i]])) });
}

export async function createAssessment(form) {
  const { data } = await request(endpoints.assessments, { method: 'POST', body: toAssessmentPayload(form) });
  return data;
}

export const setStatus = (id, status) => request(endpoints.assessmentStatus(id), { method: 'POST', body: { status } });
export const addRule = (id, form) => request(endpoints.scopeRules, { method: 'POST', body: toRulePayload(id, form) });
export const removeRule = (ruleId) => request(endpoints.scopeRule(ruleId), { method: 'DELETE' });

export async function addMember(id, username, permission) {
  const { data: user } = await request(`${endpoints.userLookup}?${new URLSearchParams({ username: username.trim() })}`);
  return request(endpoints.member(id, user.id), { method: 'PUT', body: { permission } });
}
export const removeMember = (id, userId) => request(endpoints.member(id, userId), { method: 'DELETE' });
