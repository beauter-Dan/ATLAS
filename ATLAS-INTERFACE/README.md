# ATLAS Interface

React + Vite web client for **ATLAS CORE** (v1.2.0 contract). Built pages: Sign-in, Dashboard, Targets (list, detail, register/edit) and **Assessments** (list, create, detail with status control,
scope rules and members). The other sections in the navigation (Assets, Observations, Architecture, Hypotheses, Experiments, Findings,
Reports, …) are **placeholders** — their backend endpoints exist, their screens have not been built.

## Run
```bash
npm install
cp .env.example .env.local
npm run dev            # http://localhost:5173
```
* **Demo mode** (`VITE_USE_MOCK=true`, default): synthetic in-memory data, no sign-in. The demo data uses the *real backend response shapes*,
  so the same mapping code runs in both modes.
* **Live mode** (`VITE_USE_MOCK=false`): needs a running ATLAS CORE whose `ATLAS_CORS_ORIGINS` includes this app's origin
  (default `http://localhost:5173`). You will see a sign-in screen; the header shows your name/role and a **Sign out** button.
  With the backend's synthetic seed (`python -m scripts.seed_synthetic`): users `admin1`, `approver1`, `analyst1`, `viewer1`,
  password `SyntheticPass123!` (demo only).

## Behaviour worth knowing
* **Assessments:** status buttons shown depend on the current status (mirroring the server's state machine). Activation is refused by the server
  without a valid target authorization **and** at least one permitted rule — the UI explains which. Scope changes and status changes are
  approver-only; members can be managed by the owner, an assessment approver or an admin (the server decides; the UI shows the server's reason).
* **Tokens live in memory only** (never `localStorage`). A page reload signs you out — a deliberate security trade-off.
* The API client refreshes an expired access token **once**, shares one refresh between concurrent requests (refresh tokens rotate), and
  returns you to sign-in with an explanation if the session is over.
* **Scope is per assessment** in the backend, so the target page shows permitted/excluded assets grouped by assessment. Authorization is
  shown as Authorized / Pending / Expired, derived from the target's authorization record (the server remains the authority).
* The UI hides actions your role cannot perform (e.g. *Register target* for viewers, authorization fields for non-approvers) — a convenience only;
  **the server enforces every rule** (the end-to-end test proves it by sending forged requests).
* A target you cannot access answers "not found or no access" — the backend deliberately does not reveal whether it exists.

## Project layout
`src/services/` — `contract.js` (endpoint map), `apiClient.js` (auth, refresh, error envelope), `mappers.js` (backend ↔ UI shapes),
`*Service.js`, `mock/` · `src/auth/` — session state · `src/pages/`, `src/components/`, `src/layouts/`, `src/utils/`.

## Tests
```bash
npm test               # 116 tests: API client, mappers, services, validation, sign-in flow, role-gated pages and forms, whole app in demo mode
npm run build          # production build

# END-TO-END against a REAL backend (opt-in; never runs by default)
#   1) backend:  python -m scripts.seed_synthetic --database-url <url> ; start uvicorn with that database (see ATLAS-CORE/README.md)
#   2)           VITE_API_BASE_URL=http://127.0.0.1:8792/api/v1 npm run test:e2e
```
The end-to-end suite (17 tests) uses the real service layer — no mocks — to check sign-in errors, role enforcement, cross-user isolation,
token refresh/rotation/revocation, the CORS preflight, and the full assessment lifecycle (create, scope rules, members, activation refusals,
status transitions) across four different users. It does **not** run a browser (see limitations).

## Limitations
* Never run in a real browser in this verification (no browser was available). CORS is verified at the HTTP level (preflight response), not by a browser.
* No accessibility audit beyond semantic markup and labelled controls; no visual regression tests.
* Authorization shown for a target has no "revoked" state because the backend has none.
* `updated at` is not shown: the backend does not store it.
