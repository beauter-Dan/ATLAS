# ATLAS CORE — Phase 13 Verification Report

## 0. Environment (everything below was actually executed here)
Python 3.12.3 · **PostgreSQL 16.15** (Ubuntu package, local) · **Redis 7.0.15** · SQLAlchemy 2.1.8 · Alembic 1.20.1 · FastAPI 0.162.0 ·
Starlette 1.10.0 · psycopg 3.3.8 · redis-py 8.1.0 · Celery 5.6.3 · pytest 9.2.0. One host, one PostgreSQL instance, one Redis instance.

## 1. Baseline (before any change)
| Check | Result |
|---|---|
| Existing suite on SQLite | **24 passed**, 1 warning (third-party Starlette `TestClient`/httpx deprecation), 0 failures |
| Existing suite re-pointed at PostgreSQL | **23 passed** (the SQLite-only migration test excluded). Caveat: that harness shared **one** DB session across all requests, so it could not reveal per-request transaction, locking or concurrency problems |
| `alembic upgrade head` (0001) on PostgreSQL | applied cleanly; `alembic check`: no model/migration drift |
| Code inspection of the previous summary's claims | Mostly accurate, but see §1.1 — several claims were weaker than stated |

### 1.1 Corrections to the earlier (Milestone 1–12) summary
* "Append-only audit log" — was only true by API convention; no database enforcement existed. Now enforced by a PostgreSQL trigger.
* "Strict scope enforcement" — collectors checked the bare **host**, so `url_prefix` rules were never applied to what collectors actually requested; redirect targets were not classified; no private-address guard.
* "Rate limiting" — in-process only, keyed on the raw `Authorization` header.
* "Background jobs" — the task relied on `run_collection`'s per-host checks; it did not verify that the *queuing user* was still active or still a member.
* "Authentication and authorization" — global roles only (any analyst could read/modify any assessment); tokens were stateless and unrevocable.
* The 24-test count was accurate, but none of the tests covered access control, token lifecycle, redirects, concurrency or PostgreSQL behaviour.

## 2. Final results
| Run | Result |
|---|---|
| **PostgreSQL 16.15 + Redis 7.0.15** (`ATLAS_TEST_DATABASE_URL` set) | **157 passed, 0 failed, 0 skipped**, 1 warning (same third-party deprecation), ≈44 s |
| **SQLite + Redis** | **138 passed, 0 failed, 19 skipped** (the 19 `@pytest.mark.pg` tests, which require PostgreSQL), 1 warning |
| `alembic upgrade head` / `downgrade 0001` / `upgrade head` on PostgreSQL | all succeeded; `alembic check`: **no drift**; current = `0002 (head)` |

Per file (PostgreSQL run): access_control 11 · ai 3 · api_flow 9 · audit_logging 4 · auth 18 · contract 3 · health 2 · intel 4 · postgres 19 · ratelimit 9 · regression 10 · scope 4 · scope_audit 61. Total **157**.

**One unexplained transient failure:** in a single full PostgreSQL run, one test's *fixture* (`scratch_url`, which creates a throw-away
database) errored. It did not recur in the next **five** consecutive runs (four full, one module), and I could not capture the message.
The most likely cause is a transient `CREATE DATABASE` failure; a retry was added to the fixture. Root cause is **not** established.

## 3. Requirement-by-requirement
### Part 2 — PostgreSQL
| Requirement | Evidence |
|---|---|
| Models against PostgreSQL | whole suite runs against PG through `alembic upgrade head`; `test_foreign_keys_checks_and_uniques` |
| Migrations / fresh install | `test_fresh_install_creates_every_table_and_matches_models` (empty DB → all tables, version 0002, trigger present) |
| Migration upgrade with data | `test_upgrade_path_preserves_and_backfills_existing_data` (0001 → 0002 with legacy rows; owner backfill; defaults; downgrade removes objects; re-upgrade) |
| Foreign keys / cascades / SET NULL | `test_foreign_keys_…`, `test_cascades_set_null_and_audit_survival` |
| Constraints (CHECK/UNIQUE) | same tests: invalid status/env/kind/confidence/permission/role, experiment bounds, non-whitelisted experiment type, duplicates |
| Transactions & rollback | `test_transaction_rollback_and_savepoints`, `test_failed_collector_leaves_no_partial_rows…` |
| Pagination / filtering / sorting | `test_pagination_filtering_sorting_are_consistent` (120 rows: no gaps/overlap, asc/desc, combined filters, invalid params, injection string), `test_boolean_filter_on_postgres` |
| Value-length errors (PG enforces varchar limits) | `test_overlong_values_are_422_not_500`, `test_data_error_handler_maps_to_422` |
| Concurrency (real parallel connections) | 16 racing inserts → exactly 1 row; 6 racing experiment runs → **1 execution, 1 outbound request**; racing approvals; racing hypothesis generation (no dupes/errors); 4 racing collections; racing membership upserts; racing refresh with one token → exactly 1 success; 10 racing bad logins → lockout |
| Audit immutability | `test_audit_log_is_append_only_in_the_database` |

### Part 3 — Access control — `test_access_control.py` (11 tests)
Stranger sees nothing in 12 list endpoints and gets 404 on 23 write/trigger endpoints; stranger who is a *global approver* still blocked;
read-only member; permission capped by global role; analyst member limited by assessment permission; approval and confirmation need
assessment-level approver; membership management rules, immutable owner, removal revokes access immediately; admin bypass; target visibility
and authorization-record edit restriction; denials audited.

### Part 4 — Authentication — `test_auth.py` (18 tests)
Hash format/legacy upgrade, password policy, token expiry/revocation/hash-only storage, logout-all/deactivation, refresh rotation + reuse
detection + expiry, lockout and expiry of lockout, indistinguishable unknown user, audited failures without passwords, change-password
session revocation, admin-issued and self-service reset (single-use, expiry, hashed, no enumeration, delivery interface), TOTP RFC 6238
vectors, MFA enroll/activate/login/replay/admin reset, no credentials in responses/logs/audit/422/AI prompts.

### Part 5 — Scope audit — `test_scope_audit.py` (61 tests)
Nothing requested when assessment inactive/authorization expired/host out of scope/excluded (spies on HTTP, DNS, TLS, RDAP, CT);
discovered assets stay unauthorized; 10 classification tricks (userinfo, suffix, query, trailing dot, case, port…); 12 malformed/dangerous
URLs rejected before any request; `url_prefix` boundaries; IDNA; redirects (out-of-scope, excluded, in-scope+relative, 3rd hop, loop bound,
6 dangerous targets, in-scope name resolving to private address, loopback initial host); per-path checks for API-doc probes; decisions logged
for allow and deny with query strings removed; experiments re-check at run time and never follow redirects; background jobs rejected after
pause / deactivation / membership revoked / read-only / authorization expiry / no actor, and skip hosts excluded after queueing; endpoint
fail-fast; **real Celery worker + Redis broker round trip** with result isolation between assessments.

### Part 6 — Distributed rate limiting — `test_ratelimit.py` (9 tests)
Two Redis clients share one budget and are atomic under 100 concurrent hits (exactly 20 winners); sliding window expires; middleware keys
are hashed; fail modes (memory / closed 503 / open); **two separate uvicorn server processes sharing only Redis enforce one budget
(20 OK + 10×429 of 30 alternating requests)** and a control run with the in-memory backend allows all 30 — showing the Redis result is
due to shared state; auth brute-force bucket not evadable by rotating usernames or spoofing `X-Forwarded-For`.

### Parts 7–8 — Regression & docs
`test_regression.py` (envelope for 401/403/404/405/409/422, no input echo, CORS, security headers, size limits, production-secret guard,
forged `confirmed` rejected, no partial data after collector failure), `test_audit_logging.py` (lifecycle + security events, admin-only,
no write path, scrubbing). Documentation updated: README, SECURITY, this report, SECURITY-REVIEW, and `ATLAS-SHARED/integration/*`.

## 4. Defects found while verifying (all fixed; each has a regression test)
Detailed in `SECURITY-REVIEW.md`. Those **reproduced by a failing test during this phase**: duplicate route extraction (Python decorators
matched by two regexes), `Location`-header and denial-reason query strings (tokens) persisted in evidence/audit, assessment audit rows not
linked to the assessment, enqueue-before-commit in the job endpoint, `value` filter missing on assets. Those found **by code inspection** (not
reproduced on the old code, guarded by new tests): the F-01…F-09 class listed in the security review.

## 5. NOT verified — be explicit
* Real network transports (`_http`, `_tls`, `_dns`, `_ct`, `_rdap`) were **never run** (phase rule: no collectors against external infrastructure). Their parsing/guards are covered through fakes only.
* Other PostgreSQL versions (≤15, 17), managed PostgreSQL, PgBouncer, replicas; Redis Sentinel/Cluster; multi-host deployment.
* Behaviour under load; performance of per-request token lookups; many-worker uvicorn/gunicorn (two server processes were tested).
* DNS-rebinding between the address guard and the connection (documented residual risk).
* The AI providers (`anthropic`, `openai_compatible`) were not called; only the offline provider and a fake were used.
* The web interface (`ATLAS-INTERFACE`) was not run or modified; see `INTERFACE-GAP-ANALYSIS.md`.

---
## 6. Addendum — v1.2.0 (interface integration), verified after Phase 13
Changes: `GET /dashboard/summary`; `organization` on targets (migration `0003`); `role_denied` audit events; the **interface was wired to the real contract**
(sign-in, token refresh, error envelope, mappers, Targets pages) and given a test suite.

| Run (all executed) | Result |
|---|---|
| Backend on **PostgreSQL 16.15 + Redis 7.0.15** | **163 passed**, 0 failed, 0 skipped (was 157; +6 `test_dashboard`, role-denial, organization) |
| Backend on SQLite + Redis | **144 passed**, 0 failed, 19 skipped (PostgreSQL-only tests) |
| `alembic upgrade head` / `check` on PostgreSQL | `0003 (head)`; "No new upgrade operations detected" |
| Interface unit + component tests (vitest + jsdom) | **69 passed** (API client incl. refresh single-flight and rotation, mappers, services, validation, sign-in/MFA/lockout/session-loss flow, role-gated forms, list/detail pages, whole app in demo mode) |
| Interface **end-to-end** against a live backend on PostgreSQL (real services, no mocks) | **9 passed**: wrong-credential error codes; analyst list/detail/per-assessment scope/dashboard; create/edit with server-side refusal of a *forged* authorization edit and of duplicates; viewer read-only; second user sees nothing and gets 404; transparent refresh with rotation + replay detection; server-side revocation signs the client out; logout revokes; CORS preflight |
| Interface production build | succeeds |

Defects found by these tests (all fixed): an unused/incorrect `distinct()` usage raising a SQLAlchemy warning in the new dashboard query (caught by the warning
check, fixed with `select(col).distinct()`). Test-harness bugs fixed along the way (e.g. a `beforeEach` that returned a mock, which vitest then invoked as a cleanup hook) were not application defects.

**Still not verified:** the interface in a real browser (including real CORS enforcement); the other eight screens (not built); load behaviour; everything
listed in §5 above.

---
## 7. Addendum — v1.2.1 (Assessments screen)
Built the interface's **Assessments** section (list, create, detail with status transitions, scope rules, members) against the real contract.
Verified (all executed): backend **PostgreSQL 164 passed**, SQLite 145 passed + 19 skipped; interface **116 unit/component tests passed**, production build OK;
interface **end-to-end 17 passed** against a live backend on PostgreSQL (the 8 new tests cover assessment lifecycle across analyst / approver-non-member /
admin / approver-member: 403 for an analyst changing scope or status, 404 for a non-member, owner immutability, `scope_required` before activation, activation after a
permitted rule exists, `invalid_transition`, duplicate-rule `conflict`, invalid-rule `invalid_scope_rule`, rule/member removal, dashboard reflecting the new assessment).

**Defect found by wiring the screen to the live backend (fixed, regression-tested):** `GET /assessments/{id}/members` omitted the **owner**, because ownership is
stored on the assessment rather than as a membership row. `test_member_list_includes_the_owner_once_and_first` guards it (including no duplicate when a legacy
membership row also exists). The interface's own mock backend had hidden this: it listed the owner, the real server did not — a reminder that the E2E suite, not the mock, is the proof.

**Still not verified:** a real browser; the remaining interface screens (Assets, Observations, Architecture, Hypotheses, Experiments, Findings, Reports) are not built;
no UI yet to trigger collection/experiments/AI/reports; load; everything in §5.
