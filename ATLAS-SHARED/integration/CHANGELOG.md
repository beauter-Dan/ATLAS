# ATLAS API Changelog

## 1.1.0 — Phase 13 (verification & hardening)  ⚠ contains client-visible changes
**Breaking / behavioural**
- **Tokens:** `POST /auth/login` now returns `{access_token, refresh_token, token_type, expires_in, user}`. Access tokens are opaque, expire after **15 min** (was 1 h signed token); use `POST /auth/refresh`. Old tokens issued before the upgrade are invalid.
- **Per-assessment access control:** users only see assessments they own or are members of. Everything else → **404**. Lists of assessments, targets and every child resource are filtered. Previously any analyst saw everything.
- Creating an assessment makes the caller its **owner**. `scope-rules` writes, assessment status changes need **approver** (global and assessment-level). Editing a target's `authorization_*` fields needs a global approver.
- Password policy enforced on user creation (≥12 chars, not common, no username). `POST /auth/users` may now return `weak_password` 422.
- Login may return **429 `account_locked`**; auth endpoints have their own per-IP rate limit.
- Scope: redirects are authorized per hop; URLs with userinfo/backslashes/odd ports/schemes are rejected (`scope_violation` 403); hosts resolving to non-public addresses are refused unless an `ip`/`cidr` include rule exists.
**Added**
- Auth: `/auth/refresh`, `/auth/logout`, `/auth/logout-all`, `/auth/sessions`, `/auth/change-password`, `/auth/mfa/{enroll,activate,disable}`, `/auth/password-reset/{request,confirm}`, `GET /auth/users`, `PATCH /auth/users/{id}`, `POST /auth/users/{id}/password-reset`, `DELETE /auth/users/{id}/mfa`, `GET /auth/users/lookup`; audit-log filters `action`, `outcome`.
- Membership: `GET /assessments/{id}/members`, `PUT|DELETE /assessments/{id}/members/{user_id}`.
- Jobs: `POST /assessments/{id}/collect/jobs`, `GET /assessments/{id}/collect/jobs/{job_id}`.
- `assets` filter `value`. Error codes listed in API-CONTRACT.md. CORS allow-list, security headers, upload size limits.
**Fixed**: duplicate route extraction; query strings (tokens) no longer stored in evidence/audit; assessment audit rows now carry `assessment_id`.
**Database:** migration `0002` (sessions, members, reset tokens, MFA columns, `assessments.owner_id`, PostgreSQL audit-log immutability trigger).

## 1.0.0
Initial contract (Milestones 1–12). **0.1.0**: `GET /api/v1/health`.
