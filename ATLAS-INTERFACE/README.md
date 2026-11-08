# ATLAS Interface

Frontend for ATLAS (Automated Target Intelligence and Analysis System). Runs on its own, no backend needed.

## Install and run
```bash
npm install
cp .env.example .env.local
npm run dev        # http://localhost:5173
npm run build      # production build to dist/
```
Place this folder at `~/Documents/ATLAS/ATLAS-INTERFACE/`.

## Configuration
| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000/api/v1` | ATLAS CORE API |
| `VITE_USE_MOCK` | `true` | `true` serves labelled synthetic demo data; `false` calls the API |

`VITE_*` values are bundled into the browser. Never put secrets in them.

## Structure
- `src/config` env and navigation (drives sidebar and routes)
- `src/layouts` app shell
- `src/pages` one file per section (unbuilt sections use `PlaceholderPage`)
- `src/components` Panel, StatCard, Badge, ScopeBadge, PageHeader, States (Loading / ErrorState / EmptyState)
- `src/hooks/useApi.js` loading, error and reload handling
- `src/services` `apiClient.js` (only place that calls `fetch`), `contract.js` (endpoint map), per-domain services, `mock/`
- `src/types` model definitions, `src/utils`, `src/styles` (tokens, base, components)

## Contract status (important)
`ATLAS-SHARED/contracts/*` was not available when this scaffold was written. `src/services/contract.js`,
`src/types/models.js` and `src/services/mock/` are provisional. Replace them with the documented
endpoints and models before turning mock mode off. Do not add endpoints that are not in `openapi.json`.

## Built so far
- Dashboard: stat cards link to their sections, refresh keeps current data on screen while reloading.
- Targets: searchable and filterable list, registration and edit form, detail page with authorization, permitted and excluded assets, and assessment history.
- Scope rules (`src/utils/scope.js`): a target shows as authorized only if the backend status is `authorized` and today is inside the validity window; excluded assets always win over permitted ones; a form cannot be saved with an asset in both lists; authorization status is never set from the UI.
- Mock mode keeps targets in memory, so created and edited targets reset on reload.

## Adding a section
1. Add the model to `src/types`, the endpoint to `contract.js`, and a mock to `services/mock`.
2. Add a service function, then a page that uses `useApi`.
3. Swap its `PlaceholderPage` route in `App.jsx`.

## Testing
No test runner is set up yet (milestone 17). For now: `npm run build` must pass, and in the browser check each nav link,
the mobile menu below 900px, and the loading, error (set `VITE_USE_MOCK=false` with no backend) and populated states.
