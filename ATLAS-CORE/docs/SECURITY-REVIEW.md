# ATLAS CORE — Security Review (Phase 13)

Scope: authentication, authorization, scope enforcement, collectors/experiments/jobs, rate limiting, data protection, audit.
Method: reading the actual code, then writing tests that try to break each property. "Reproduced" = a test failed against the code before the fix
in this phase. "Inspection" = found by reading code; the fix is guarded by a new test but the old behaviour was not executed.

## Findings (all remediated)
| ID | Sev. | Finding | Found by | Fix | Guard test |
|---|---|---|---|---|---|
| F-01 | **High** | No assessment-level access control: any analyst could list/read/modify/run anything in any assessment | inspection | owners + members, effective permission = min(global, membership), 404 for strangers, checks on every endpoint and list | `test_access_control.py` |
| F-02 | **High** | Stateless HMAC tokens: not revocable, 1 h life; logout/deactivation/password change could not end a session | inspection | opaque hashed server-side sessions, 15 min access + rotating refresh with reuse detection, revocation on every credential event | `test_auth.py` |
| F-03 | **High** | No account lockout; brute force limited only by the global limiter | inspection | per-account lockout, per-IP auth bucket, uniform errors/timing for unknown users | `test_lockout…`, `test_login_bruteforce…` |
| F-04 | **High** | Collectors authorized the **host**, not the URL → `url_prefix` exclusions were never applied to what they requested | inspection | every request authorized on the full URL (`netguard`), each probed path included | `test_each_probed_api_doc_path…`, `test_url_prefix…` |
| F-05 | **High** | Redirect destinations unclassified; no protection against in-scope names pointing at internal addresses (SSRF-style) | inspection | per-hop authorization before each request, hop limit, private/loopback/link-local refusal unless explicit ip/cidr rule | `test_redirect_*`, `test_in_scope_name_resolving_to_private…` |
| F-06 | **High** | `url_prefix` match had no path boundary: rule `https://example.test` also matched `https://example.test.evil.test` | inspection | boundary-aware matching; strict URL parsing with the client's own parser (no differentials) | `test_url_prefix_rules_respect_path_boundaries`, `test_strict_url_parsing…` |
| F-07 | Med | Queued jobs did not re-verify the queuing user (still active? still a member with analyst rights?) | inspection | `jobs.authorize_job` at execution + endpoint fail-fast + audit | `test_job_*` incl. real worker |
| F-08 | Med | Rate limiter in-process (bypassable by running more workers), keyed on the raw bearer token | inspection | Redis sliding window shared by all processes; keys hash the principal; fail modes | `test_ratelimit.py` |
| F-09 | Med | "Append-only" audit log only by convention | inspection | PostgreSQL trigger blocks UPDATE/DELETE; no write API; secrets scrubbed from details | `test_audit_log_is_append_only…` |
| F-10 | Med | `Location` header query strings (possible tokens) stored in evidence; scope-denial messages embedded the full URL incl. query | **reproduced** | stored/logged without query/userinfo (`redact_url`) | `test_redirect_to_out_of_scope_host…`, `test_audit_scrubs_urls…` |
| F-11 | Med | Collector failure mid-host could leave partial rows / poison the DB transaction | inspection | SAVEPOINT per host, get-or-create assets under SAVEPOINT | `test_failed_collector_leaves_no_partial_rows…` |
| F-12 | Med | No row locking: concurrent `run` of one approved experiment could contact the target several times | inspection | `SELECT … FOR UPDATE` on lifecycle actions | `test_concurrent_experiment_run_executes_exactly_once` |
| F-13 | Low | PostgreSQL enforces varchar limits; oversize input would be HTTP 500 | inspection | schema `max_length` mirrors columns + `DataError` → 422; request size caps on uploads | `test_overlong_values_are_422_not_500` |
| F-14 | Low | Browser UI on another origin could not call the API (no CORS) | found while joining the interface | explicit origin allow-list, no credentials mode | `test_cors_allows_only_configured_origins` |
| F-15 | Low | Python routes extracted twice (one decorator matched two framework regexes) | **reproduced** | patterns limited to file types + de-dup | `test_routes_are_not_duplicated…` |
| F-16 | Low | Audit rows for creating/updating/deleting an assessment were not linked to it | **reproduced** | `assessment_id_of()` | `test_lifecycle_events_are_audited…` |
| F-17 | Low | Job endpoint enqueued inside an open transaction (worker could outrun the audit row) | **reproduced** | commit, then enqueue with a pre-generated task id | `test_enqueue_endpoint_prechecks_and_queues` |

## Residual risks (open — please read)
1. **DNS rebinding / TOCTOU** *(Medium)*: the address guard resolves a name, the HTTP client resolves again to connect. Mitigate with an egress firewall on API/worker hosts; connection-time IP pinning is not implemented.
2. **Scope is host-based** *(Low)*: `ATLAS_ALLOWED_PORTS` is global, rules cannot differ per port.
3. ~~Role-level 403s were not audited~~ — **closed in v1.2.0**: refusals by global role are now audited as `role_denied` (actor, needed role, method, path; never the query string) — `test_role_denials_are_audited`.
4. **Audit trigger is not tamper-proof against a DB superuser** *(Low)*; no external log shipping provided.
5. **MFA** *(Low)*: no recovery codes; not enforced for privileged roles; TOTP secret shown once at enrollment.
6. **Password-reset delivery** *(Info)*: interface only; the default drops tokens. Self-service reset is therefore inert until a delivery backend is plugged in.
7. **Strict refresh handling** *(Info)*: two tabs refreshing with the same token at once → session revoked (by design).
8. **Owner can delegate** *(Info)*: an owner may grant `approver` membership to any global approver; separation of duties (requester ≠ approver) still holds.
9. **Evidence/experiments data** *(Info)*: collected response metadata is stored as received (minus query strings in `Location`); bodies are not stored, but headers/titles may contain target-supplied text. Treat evidence as untrusted input (the UI must escape it; reports HTML-escape it).
10. **Untested externally** — see `VERIFICATION-REPORT.md §5` (real network transports, AI providers, scale, other PG/Redis versions).

## Secure-by-default checks performed
No endpoint returns credential material; `credentials` is write-only and Fernet-encrypted; 422 responses don't echo input; passwords and
tokens never appear in logs/audit/AI prompts (tests assert each); CORS has no wildcard and no credentials mode; security headers on all
responses; startup refuses default secrets outside development; request/upload size caps; all list filters are parameterized and sort keys
allow-listed; there is no code path to exploit, brute-force, or write to a target.
