import { describe, expect, it } from 'vitest';
import { effectiveAuthorization, validateTarget } from './scope.js';
import { describeActionError, describeAuthError } from './errors.js';
import { hasRole } from './roles.js';

const good = { name: 'N', organization: 'O', baseDomain: 'example.test', description: '', authorization: { reference: 'R', authorizedBy: 'B', validFrom: '2026-01-01', validUntil: '2026-12-31' } };

describe('validateTarget', () => {
  it('accepts a complete form', () => expect(validateTarget(good)).toEqual({}));
  it.each([['https://example.test'], ['example'], ['exa mple.test'], ['example.test/path'], ['-bad.test'], ['a'.repeat(300) + '.test']])('rejects base domain %s', (d) => {
    expect(validateTarget({ ...good, baseDomain: d }).baseDomain).toBeTruthy();
  });
  it('requires the end date to follow the start date', () => {
    expect(validateTarget({ ...good, authorization: { ...good.authorization, validUntil: '2025-01-01' } }).validUntil).toMatch(/on or after/);
  });
  it('mirrors server length limits', () => expect(validateTarget({ ...good, name: 'n'.repeat(201) }).name).toBeTruthy());
});

describe('effectiveAuthorization', () => {
  const now = new Date('2026-06-15T00:00:00Z');
  const t = (status, validFrom = '2026-01-01', validUntil = '2026-12-31') => ({ authorization: { status, validFrom, validUntil } });
  it('only shows authorized when status AND dates agree', () => {
    expect(effectiveAuthorization(t('authorized'), now)).toBe('authorized');
    expect(effectiveAuthorization(t('authorized', '2026-01-01', '2026-03-01'), now)).toBe('expired');
    expect(effectiveAuthorization(t('authorized', '2026-09-01', '2026-12-01'), now)).toBe('pending');
    expect(effectiveAuthorization(t('pending'), now)).toBe('pending');
    expect(effectiveAuthorization(null, now)).toBe('pending');
  });
});

describe('error messages', () => {
  it('describes authentication failures', () => {
    expect(describeAuthError({ code: 'invalid_credentials' })).toMatch(/Incorrect/);
    expect(describeAuthError({ code: 'account_locked', details: { retry_after_seconds: 600 } })).toMatch(/10 minutes/);
    expect(describeAuthError({ code: 'account_locked', details: { retry_after_seconds: 30 } })).toMatch(/1 minute\b/);
    expect(describeAuthError({ code: 'rate_limited', details: { retry_after_seconds: 7 } })).toMatch(/7 seconds/);
    expect(describeAuthError({ code: 'weird', message: 'from server' })).toBe('from server');
  });
  it('describes action failures', () => {
    expect(describeActionError({ code: 'authorization_edit_forbidden' })).toMatch(/approver/);
    expect(describeActionError({ code: 'not_found' })).toMatch(/do not have access/);
  });
});

it('hasRole ranks roles and fails closed', () => {
  expect(hasRole({ role: 'approver' }, 'analyst')).toBe(true);
  expect(hasRole({ role: 'viewer' }, 'analyst')).toBe(false);
  expect(hasRole(null, 'viewer')).toBe(false);
  expect(hasRole({ role: 'unknown' }, 'viewer')).toBe(false);
});
