# ATLAS Integration Guide (v1.2.1)

1. **Develop against the contract:** `contracts/openapi.json` (+ `evidence-schema.json`, `architecture-schema.json`, `data-models.md`). No backend access needed.
2. **Run the backend locally:** `ATLAS-CORE/README.md`. Synthetic demo: `python -m scripts.seed_synthetic` (users `admin1/approver1/approver2/analyst1/viewer1`, password `SyntheticPass123!` — demo only).
3. **Auth flow for a client:** login → keep both tokens **in memory** → send the access token as a Bearer header → on 401 `unauthorized` call `/auth/refresh` once (replace BOTH tokens with the response) → if that fails, send the user to login. On `mfa_required` ask for the 6-digit code and repeat login with `totp_code`. On 429 honour `Retry-After`.
4. **CORS:** set `ATLAS_CORS_ORIGINS` to the UI origin (default `http://localhost:5173`, Vite's default).
5. **Typical flow:** create target (+ authorization record) → create assessment (you become owner) → approver/admin adds scope rules and members → approver activates → collect → analyze source/schema → build architecture → generate hypotheses → create/submit experiment → another approver approves → run → create finding → verify evidence → approver confirms → report.
6. **UI rules:** show confidence and verification badges; link every item to its `evidence_id`; never present hypotheses/AI inferences as findings; 404 on an assessment means "not yours or doesn't exist" — don't offer to request access via error text; escape all evidence strings.
7. **Versioning:** breaking changes → `/api/v2`. Any change to shared contracts must be logged in `CHANGELOG.md` and regenerated with `python -m scripts.export_contracts`.
8. **The web interface** (`ATLAS-INTERFACE`) now talks to this contract (see its README and `INTERFACE-GAP-ANALYSIS.md`). Demo mode (`VITE_USE_MOCK=true`) uses the same contract shapes.
