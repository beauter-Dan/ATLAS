const norm = (v) => v.trim().toLowerCase();

export const normalizeAsset = norm;

/**
 * Effective authorization. A target is only "authorized" when the backend says so AND
 * today is inside the validity window. Anything else is shown as not authorized.
 */
export function effectiveAuthorization(target, now = new Date()) {
  const a = target?.authorization;
  if (!a) return 'pending';
  if (a.status === 'revoked') return 'revoked';
  if (a.status === 'pending') return 'pending';
  const today = now.toISOString().slice(0, 10);
  if (a.validUntil && a.validUntil < today) return 'expired';
  if (a.validFrom && a.validFrom > today) return 'pending';
  return a.status === 'authorized' ? 'authorized' : 'pending';
}

/** Assets listed as both permitted and excluded. Excluded always wins. */
export function assetConflicts(permitted = [], excluded = []) {
  const ex = new Set(excluded.map(norm));
  return permitted.filter((p) => ex.has(norm(p)));
}

export function validateTarget(t) {
  const e = {};
  if (!t.name.trim()) e.name = 'Enter a target name.';
  if (!t.organization.trim()) e.organization = 'Enter the organization that owns the target.';
  if (!t.authorization.reference.trim()) e.reference = 'Enter the authorization reference.';
  if (!t.authorization.authorizedBy.trim()) e.authorizedBy = 'Enter who granted authorization.';
  if (!t.authorization.validFrom) e.validFrom = 'Choose a start date.';
  if (!t.authorization.validUntil) e.validUntil = 'Choose an end date.';
  if (t.authorization.validFrom && t.authorization.validUntil && t.authorization.validUntil < t.authorization.validFrom) {
    e.validUntil = 'The end date must be on or after the start date.';
  }
  if (t.permittedAssets.length === 0) e.permittedAssets = 'Add at least one permitted asset.';
  const conflicts = assetConflicts(t.permittedAssets, t.excludedAssets);
  if (conflicts.length) e.excludedAssets = `Listed as both permitted and excluded: ${conflicts.join(', ')}. Remove it from one list.`;
  return e;
}
