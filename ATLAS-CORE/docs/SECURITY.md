# ATLAS CORE — Security documentation (v1.1.0)

## Trust model
* Every assessment has an **owner** and **members** with a permission (`viewer < analyst < approver`). Effective permission =
  `min(global role, membership permission)`; `admin` bypasses. Roles are global: `viewer < analyst < approver < admin`.
* A user who is not a member cannot see that an assessment exists (**404**). A member with too little permission gets
  **403 `insufficient_assessment_permission`**. A global-role failure is **403 `forbidden`**. Denials are audited (`access_denied`).
* Sensitive actions need the *assessment-level* permission **and** the global role: changing scope rules, activating/pausing,
  approving/rejecting experiments, confirming a vulnerability (all `approver`), editing a target's authorization record (global approver).
* Separation of duties: the requester of an experiment can never approve it.

## Authentication
| Topic | Implementation |
|---|---|
| Passwords | PBKDF2-HMAC-SHA256, 600 000 iterations (configurable), per-password salt, versioned format `pbkdf2_sha256$iters$salt$hash`; legacy hashes verify and are upgraded transparently at next login |
| Policy | ≥12 and ≤128 chars, not common/repetitive, must not contain the username |
| Tokens | Opaque random 256-bit access token (15 min) + refresh token (7 d). **Only SHA-256 hashes are stored.** Server-side sessions: revocable, listed at `GET /auth/sessions` |
| Refresh | Rotating. Re-use of a rotated-out refresh token revokes the whole session (theft signal) |
| Revocation | `POST /auth/logout`, `/auth/logout-all`; automatic on password change/reset, role change, deactivation, MFA reset |
| Brute force | Per-account lockout (default 5 failures → 15 min, HTTP 429 `account_locked`); per-IP Redis bucket on login/refresh/reset (default 10/min); unknown users cost the same hashing time and return the identical error |
| Reset | `request` always returns 202 (no account enumeration); tokens are random, hashed at rest, single-use, 1 h; delivery is the pluggable `ResetDelivery` (default delivers nowhere). Admin can issue a one-time token |
| MFA | RFC 6238 TOTP (verified against the RFC test vectors), seed encrypted at rest, ±1 step window, replay of a used step rejected; enroll → activate → login requires `totp_code` |
| Credential hygiene | Never in responses (`password_hash`, `credentials_encrypted` are not serializable), audit details (keys matching password/secret/token/… are redacted), logs (redacting log-record factory), AI prompts (redaction layer), or 422 validation errors (inputs are not echoed) |

## Scope enforcement (default deny)
1. **Authorization record**: target needs reference, authorizer and a currently valid window; assessment must be `active`.
2. **Rules**: excludes beat includes; kinds `domain` (exact), `wildcard` (`*.x`, not the apex), `ip`, `cidr`, `url_prefix` (path-boundary safe).
3. **Discovered ≠ authorized**: anything found by collectors is stored `discovered`; only a human-written rule can authorize it. Clients cannot set `scope_state`.
4. **Before every request** (`services/netguard.py`): strict URL parsing with the same parser the HTTP client uses (rejects backslashes,
   userinfo, non-http(s) schemes, control characters, non-allowed ports, >2048 chars); IDNA-normalized hosts; scope + authorization
   check on the full URL; hosts resolving to non-public addresses (loopback, RFC1918, link-local, metadata endpoint…) are refused unless an
   explicit `ip`/`cidr` include rule covers the address.
5. **Redirects** are followed only by collectors, at most `ATLAS_MAX_REDIRECTS` (3), and **each hop is authorized independently before it
   is requested**. A blocked hop stops the chain and is recorded. Experiments never follow redirects.
6. **Every decision is logged** (`scope_decision`, outcome `allowed`/`denied`, hop, URL **without query string/userinfo**).
7. **Re-verification at execution**: experiments re-check scope/authorization when they run; background jobs re-check actor validity,
   membership (≥analyst), assessment state, authorization window and every host when the worker executes them.
8. Experiments are limited to two read-only types (`http_status_check`, `header_review`), GET/HEAD, a header allow-list, no credentials
   as parameters, validated synthetic data, request/rate caps, mandatory rollback plan, human approval. Nothing destructive exists to enable.

## Rate limiting
Redis sliding window (single atomic Lua script, Redis clock) shared by every worker/process. General budget per principal (token hash or IP);
separate brute-force bucket for auth endpoints per client IP. `X-Forwarded-For` is ignored unless `ATLAS_TRUST_PROXY_HEADERS=true`
(set it only behind a proxy you control, otherwise clients can pick their own bucket). If Redis is down: `memory` (degrade to per-process,
default), `closed` (503) or `open`.

## Audit log
Append-only: no API write path, and on PostgreSQL a trigger rejects any `UPDATE`/`DELETE`. No foreign keys, so history survives deletion of
the audited objects. Readable only by admins at `GET /auth/audit-logs` (filters: `assessment_id`, `action`, `outcome`).
Events: logins (incl. denied/locked/unknown), refresh and reuse, logout, password/MFA changes, user/role changes, membership changes,
access, role and scope denials and scope decisions, every CRUD mutation, collection, internal analysis, AI runs, experiment lifecycle, evidence
verification, finding classification, report generation, job queued/rejected/completed.
*Limit:* a database superuser can still disable the trigger; ship audit rows to an external write-once store for stronger guarantees.

## Deployment checklist
- [ ] `ATLAS_ENV=production`, strong `ATLAS_SECRET_KEY` (rotating it invalidates encrypted target credentials and MFA seeds — re-enter them)
- [ ] TLS terminated in front of the API; `ATLAS_TRUST_PROXY_HEADERS=true` only if that proxy sets `X-Forwarded-For`
- [ ] PostgreSQL role with least privilege; backups; Redis not exposed publicly (and ideally password/ACL protected via the URL)
- [ ] Egress firewall for API/worker hosts (blocks cloud metadata & internal ranges — defense in depth against DNS rebinding)
- [ ] `ATLAS_CORS_ORIGINS` set to the real UI origin(s) only
- [ ] Delete the synthetic users; create real admins with `scripts.create_admin`
- [ ] Review `docs/SECURITY-REVIEW.md` residual risks
