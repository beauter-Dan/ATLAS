// Backend (snake_case, ISO datetimes) <-> UI models (camelCase, YYYY-MM-DD). The ONLY place the two shapes meet.

const day = (iso) => (iso ? String(iso).slice(0, 10) : '');

/**
 * Mirrors the backend rule (services/scope.authorization_ok): a record needs a reference, an authorizer and a validity
 * window that contains "now". The backend has no "revoked" state. The server still decides; this is for display only.
 */
export function authorizationStatus(raw, now = new Date()) {
  if (!raw.authorization_reference || !raw.authorized_by || !raw.authorization_valid_from || !raw.authorization_valid_until) return 'pending';
  const toDate = (s) => new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);   // naive timestamps are UTC
  if (now < toDate(raw.authorization_valid_from)) return 'pending';
  if (now > toDate(raw.authorization_valid_until)) return 'expired';
  return 'authorized';
}

export function toUiAssessment(a) {
  return { id: a.id, targetId: a.target_id, name: a.name, status: a.status, environment: a.environment, startedAt: a.created_at };
}

export function toUiTarget(raw, { assessments = [], scope = {} } = {}) {
  return {
    id: raw.id,
    name: raw.name,
    organization: raw.organization || '',
    baseDomain: raw.base_domain,
    description: raw.description || '',
    authorization: {
      status: authorizationStatus(raw),
      reference: raw.authorization_reference || '',
      authorizedBy: raw.authorized_by || '',
      validFrom: day(raw.authorization_valid_from),
      validUntil: day(raw.authorization_valid_until),
    },
    assessments: assessments.map(toUiAssessment),
    // Scope belongs to an assessment (set by an approver). Keyed by assessment id: { permitted: [], excluded: [] }
    scope,
    createdAt: raw.created_at,
  };
}

export function groupRules(rules) {
  const out = {};
  for (const r of rules) {
    const s = (out[r.assessment_id] ||= { permitted: [], excluded: [] });
    (r.rule_type === 'include' ? s.permitted : s.excluded).push(r.value);
  }
  return out;
}

const startOfDay = (d) => `${d}T00:00:00Z`;
const endOfDay = (d) => `${d}T23:59:59Z`;

export function toCreatePayload(form) {
  return {
    name: form.name.trim(),
    base_domain: form.baseDomain.trim().toLowerCase(),
    organization: form.organization.trim(),
    description: form.description.trim() || null,
    authorization_reference: form.authorization.reference.trim(),
    authorized_by: form.authorization.authorizedBy.trim(),
    authorization_valid_from: startOfDay(form.authorization.validFrom),
    authorization_valid_until: endOfDay(form.authorization.validUntil),
  };
}

/** Only changed fields are sent, so a user who may not edit authorization can still edit the rest. */
export function toPatchPayload(original, form) {
  const next = toCreatePayload(form);
  const prev = {
    name: original.name, base_domain: original.baseDomain, organization: original.organization,
    description: original.description || null,
    authorization_reference: original.authorization.reference, authorized_by: original.authorization.authorizedBy,
    authorization_valid_from: startOfDay(original.authorization.validFrom), authorization_valid_until: endOfDay(original.authorization.validUntil),
  };
  return Object.fromEntries(Object.entries(next).filter(([k, v]) => v !== prev[k]));
}

export function toUiDashboard(d) {
  return {
    targets: d.targets,
    activeAssessments: d.active_assessments,
    assets: d.assets,
    technologies: d.technologies,
    pendingHypotheses: d.pending_hypotheses,
    confirmedFindings: d.confirmed_findings,
    recentActivity: d.recent_activity,
    assessmentProgress: d.assessment_progress,
  };
}

// ---- assessments
export const STATUS_TRANSITIONS = {      // mirrors the backend; the server stays authoritative
  draft: ['active', 'archived'], active: ['paused', 'completed'], paused: ['active', 'completed', 'archived'], completed: ['archived'], archived: [],
};

export const toUiRule = (r) => ({ id: r.id, type: r.rule_type, match: r.match_type, value: r.value, note: r.note || '' });
export const toUiMember = (m) => ({ userId: m.user_id, username: m.username, permission: m.permission, isOwner: m.is_owner });

export function toUiAssessmentDetail(a, { target, rules = [], members = [], counts = {} } = {}) {
  return {
    id: a.id, targetId: a.target_id, name: a.name, description: a.description || '', status: a.status, environment: a.environment,
    ownerId: a.owner_id, createdAt: a.created_at,
    target: target ? { id: target.id, name: target.name, baseDomain: target.base_domain, authorizationStatus: authorizationStatus(target) } : null,
    rules: rules.map(toUiRule), members: members.map(toUiMember), counts,
  };
}

export const toAssessmentPayload = (f) => ({ target_id: f.targetId, name: f.name.trim(), environment: f.environment, description: f.description.trim() || null });
export const toRulePayload = (assessmentId, f) => ({ assessment_id: assessmentId, rule_type: f.type, match_type: f.match, value: f.value.trim(), note: f.note.trim() || null });
