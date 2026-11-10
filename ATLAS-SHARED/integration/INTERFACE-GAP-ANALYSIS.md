# ATLAS-INTERFACE ↔ ATLAS-CORE gap analysis — status after integration (CORE v1.2.0)

Verified by: interface unit/component tests (116), the full app in demo mode, and an **end-to-end suite of 17 tests that drives the interface's real
service layer against a live ATLAS CORE on PostgreSQL** (`npm run test:e2e`). Not verified: behaviour in a real browser.

| # | Gap found earlier | Resolution | Evidence |
|---|---|---|---|
| 1 | UI called `GET /dashboard/summary`, absent from the contract | **Added to CORE** (access-filtered, progress computed from real workflow stages, coarse activity feed). UI maps snake_case → camelCase | `test_dashboard.py` (6), e2e "analyst: login, list, detail … dashboard", mapper test |
| 2 | UI `Target` model differed from backend (camelCase, `organization`, authorization `status`, target-level permitted/excluded assets) | Added optional `organization` to CORE (migration 0003). UI maps fields in one module; `status` is **derived** from the authorization window (mirrors the server rule); scope is shown **per assessment** because that is where the backend defines it | `mappers.test.js`, `targetService.test.js`, e2e detail test |
| 3 | UI error handling used HTTP status only | `ApiError` carries the backend `code`/`details`; messages translated for people | `apiClient.test.js`, `utils.test.js` |
| 4 | No sign-in; single static token | Sign-in screen (incl. TOTP step), in-memory tokens, one-shot shared refresh, session-lost handling, sign-out | `login.test.jsx`, `apiClient.test.js`, e2e refresh/revoke tests |
| 5 | UI assumed plain arrays | Services unwrap `{data, meta}`; lists fetch **all pages** (page size 200) | `targetService.test.js` (fetchAll) |
| 6 | UI assumed unscoped targets | Access-filtered lists; 404 shown as "not found or no access" | e2e "another user cannot see…", `targets.test.jsx` |
| 7 | CORS | Backend allow-list; preflight verified at HTTP level | `test_regression.py`, e2e CORS test |
| 8 | Routes/placeholders | Dashboard, Targets and **Assessments** (list/create/detail, status, scope rules, members) are real; other sections remain placeholders | `assessments.test.jsx`, `assessments.test.js`, e2e "assessments" suite (8 tests) |

## Still open
* The remaining screens (Assets, Observations, Architecture, Hypotheses, Experiments, Findings, Reports) are not built.
  Their endpoints and mapping patterns are in place for them to follow (`contract.js`, `mappers.js`, `pagination.js`).
* No UI yet to *run* collection, experiments, AI analysis or reports for an assessment (the Assessments page manages scope, members and status only).
* No real-browser run; no accessibility or visual regression testing.
* Reload signs the user out (tokens are memory-only by design).
