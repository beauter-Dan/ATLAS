/**
 * Effective authorization. A target is only "authorized" when the derived status says so AND today is inside the
 * validity window. Anything else is shown as not authorized. (The server remains the authority.)
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

const HOST = /^(?=.{1,255}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export function validateTarget(t) {
  const e = {};
  if (!t.name.trim()) e.name = 'Enter a target name.';
  else if (t.name.trim().length > 200) e.name = 'Use 200 characters or fewer.';
  if (!t.organization.trim()) e.organization = 'Enter the organization that owns the target.';
  else if (t.organization.trim().length > 200) e.organization = 'Use 200 characters or fewer.';
  if (!t.baseDomain.trim()) e.baseDomain = 'Enter the target’s base domain, for example example.test.';
  else if (!HOST.test(t.baseDomain.trim())) e.baseDomain = 'Enter a valid domain name without a scheme or path.';
  if (!t.authorization.reference.trim()) e.reference = 'Enter the authorization reference.';
  if (!t.authorization.authorizedBy.trim()) e.authorizedBy = 'Enter who granted authorization.';
  if (!t.authorization.validFrom) e.validFrom = 'Choose a start date.';
  if (!t.authorization.validUntil) e.validUntil = 'Choose an end date.';
  if (t.authorization.validFrom && t.authorization.validUntil && t.authorization.validUntil < t.authorization.validFrom) {
    e.validUntil = 'The end date must be on or after the start date.';
  }
  return e;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
export const MATCH_TYPES = [
  ['domain', 'Domain (exact)', 'example.test — only this host, not its subdomains'],
  ['wildcard', 'Wildcard', '*.example.test — subdomains, not the apex'],
  ['ip', 'IP address', '203.0.113.7'],
  ['cidr', 'IP range (CIDR)', '203.0.113.0/24'],
  ['url_prefix', 'URL prefix', 'https://example.test/admin — matches that path and below'],
];

/** Light client-side check; the server validates authoritatively. Returns an error message or ''. */
export function validateRuleValue(match, raw) {
  const v = raw.trim().toLowerCase();
  if (!v) return 'Enter a value.';
  if (v.length > 500) return 'Use 500 characters or fewer.';
  if (match === 'domain' && !(HOST.test(v))) return 'Enter a host name such as example.test (no scheme, path or wildcard).';
  if (match === 'wildcard' && !(v.startsWith('*.') && HOST.test(v.slice(2)))) return 'Use the form *.example.test.';
  if (match === 'ip' && !IPV4.test(v) && !v.includes(':')) return 'Enter an IP address.';
  if (match === 'cidr' && !/^[0-9a-f:.]+\/\d{1,3}$/.test(v)) return 'Enter a range such as 203.0.113.0/24.';
  if (match === 'url_prefix' && !/^https?:\/\/\S+$/.test(v)) return 'Start with http:// or https://.';
  return '';
}
