# ATLAS-INTERFACE ↔ ATLAS-CORE gap analysis

`ATLAS-INTERFACE` (React/Vite scaffold) was **joined into this package unmodified**. It runs in mock mode by default
(`VITE_USE_MOCK=true`) and its own files state its types and endpoint map are **provisional** until the shared contract is applied.
I did not run the interface and did not change its code (outside this phase's scope); this is what must change before `VITE_USE_MOCK=false` works.

| # | Interface today | Backend reality (v1.1.0) | Needed |
|---|---|---|---|
| 1 | Calls `GET /dashboard/summary` | **Endpoint does not exist** in the contract | decide: add a read-only summary endpoint to CORE (new feature, not done in this phase) *or* compose the dashboard from `/assessments`, `/assets`, `/technologies`, `/hypotheses`, `/findings` (`meta.total` gives counts) |
| 2 | `Target` = `{organization, authorization:{status,reference,authorizedBy,validFrom,validUntil}, permittedAssets[], excludedAssets[], assessments[]}` camelCase | `Target` = `{name, base_domain, authorization_reference, authorized_by, authorization_valid_from/until, …}` snake_case; scope lives in **assessment** `scope-rules`; no `organization`, no authorization `status` | map/rename in the service layer; derive `status` (pending/authorized/expired) client-side from the validity window; `permitted/excluded` come from `GET /scope-rules?assessment_id=` |
| 3 | `apiClient` throws `ApiError` from the HTTP status only, `code:'http_error'` | errors are `{error:{code,message,details}}` | read `error.code`/`message` (e.g. show `scope_violation`, `account_locked`, `mfa_required`) |
| 4 | Sends a single bearer token held in memory; no login screen | needs login → tokens (15 min) → refresh on 401 | add login (+ optional TOTP step) and a refresh-once-then-relogin interceptor; keep tokens in memory as it already does |
| 5 | Treats lists as plain arrays | lists are `{data, meta:{page,page_size,total}}` | unwrap `data`, use `meta` for paging |
| 6 | Assumes an unscoped `/targets` | results are filtered per user; strangers get **404** | show "not found or no access" without leaking existence |
| 7 | Base URL `http://localhost:8000/api/v1` | matches; CORS now allows `http://localhost:5173` | set `ATLAS_CORS_ORIGINS` if the UI runs elsewhere |
| 8 | `/targets/new`, `/findings`, `/assets`, `/assessments`, `/reports`, `/experiments`, `/architecture` routes | all exist in the contract (`/architecture?assessment_id=` requires the query param) | follow `openapi.json` exactly when replacing the mock handler |

Recommendation: replace `src/types/models.js` and `src/services/contract.js` with types generated from `contracts/openapi.json` (e.g. `openapi-typescript`) and delete the mock handler's divergent shapes.
