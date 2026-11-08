# ATLAS CORE
**Automated Target Intelligence and Analysis System — Core Engine** (v1.1.0, Phase 13: verified & hardened)

Evidence-driven backend for **authorized** security assessments. It never invents technical facts, never auto-authorizes
discovered assets, never lets AI confirm a finding, and contains no exploitation or destructive-testing capability.

| Document | What it is |
|---|---|
| `docs/VERIFICATION-REPORT.md` | Baseline, what was tested, exact results, what was **not** tested |
| `docs/SECURITY-REVIEW.md` | Findings (found → fixed), residual risks |
| `docs/SECURITY.md` | How the security model works and how to deploy it safely |
| `../ATLAS-SHARED/integration/` | API contract, integration guide, changelog, interface gap analysis |

## 1. Install
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "import secrets;print(secrets.token_urlsafe(48))"      # put the output in ATLAS_SECRET_KEY
```
Any `ATLAS_ENV` other than `development` **refuses to start** while `ATLAS_SECRET_KEY` is the default.

## 2. PostgreSQL (primary database) and Redis
```bash
docker compose up -d          # postgres:16 + redis:7, with healthchecks
```
or use your own servers and set in `.env`:
```
ATLAS_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME
ATLAS_REDIS_URL=redis://HOST:6379/0
```
The database user needs `CREATE` on its schema (migrations create tables, one function and one trigger).
SQLite (`ATLAS_DATABASE_URL=sqlite:///atlas.db`) still works for lightweight local use, but it lacks row locking and the audit-log
trigger, and is **not** the supported production database. Set `ATLAS_RATE_LIMIT_BACKEND=memory` if you run without Redis
(per-process limits only).

## 3. Migrations
```bash
alembic upgrade head          # fresh install: 0001 -> 0002
alembic current               # expect: 0002 (head)
alembic check                 # expect: "No new upgrade operations detected" (no model/migration drift)
alembic downgrade 0001        # reversible (drops sessions/members/MFA columns and the audit trigger)
# after changing models:  alembic revision --autogenerate -m "msg"  then REVIEW the file before applying
```
Upgrading an existing 0001 database is supported: assessments get `owner_id` backfilled from `created_by`
(where that user still exists); existing users keep working (their old password hash is upgraded at next login).

## 4. Run
```bash
python -m scripts.create_admin admin            # first admin; prompts for a policy-compliant password
uvicorn app.main:app --workers 4                # API + OpenAPI docs at /docs
celery -A app.worker.celery_app worker -l info  # optional background collection
```
Rate limiting is shared by all workers through Redis (see `docs/SECURITY.md`).

## 5. Try it with synthetic data (offline; contacts nothing)
```bash
python -m scripts.seed_synthetic --database-url sqlite:///atlas_demo.db      # or a PostgreSQL URL
ATLAS_DATABASE_URL=sqlite:///atlas_demo.db ATLAS_RATE_LIMIT_BACKEND=memory uvicorn app.main:app
```
Users `admin1 / approver1 / approver2 / analyst1 / viewer1`, password `SyntheticPass123!` (**demo only — never reuse**).
`analyst1` owns the assessment; the approvers and `viewer1` are members. Output: `sample_data/synthetic_report.json`.

## 6. Tests
```bash
pytest -q                                   # SQLite + Redis-backed tests (Redis tests skip if Redis is unreachable)

# full run against REAL PostgreSQL (creates database `atlas_test`; role needs CREATEDB)
export ATLAS_TEST_DATABASE_URL=postgresql+psycopg://atlas:atlas@localhost:5432/atlas_test
export ATLAS_TEST_REDIS_URL=redis://localhost:6379/15      # default; db 15 is flushed by tests
pytest -q
```
The schema is always built with `alembic upgrade head`, so every test run also exercises the migrations. Tests use only synthetic
data and fake network transports; nothing contacts external infrastructure. Markers: `pg`, `redis` (auto-skipped when unavailable).
Verified result of the last run: **157 tests — PostgreSQL 157 passed; SQLite 138 passed + 19 PostgreSQL-only skipped.**

## 7. API
`/api/v1`, OpenAPI at `/docs`, contract at `contracts/openapi.json` (72 paths / 93 operations; regenerate with
`python -m scripts.export_contracts`, which also updates `../ATLAS-SHARED/contracts/`; a test fails if it is stale).
Envelope: `{data, meta?}` / `{error:{code,message,details}}`. See `../ATLAS-SHARED/integration/API-CONTRACT.md`.

## 8. Known limitations (read before relying on it)
* **Not exercised in this phase:** the real network transports (HTTP/TLS/DNS/RDAP/crt.sh) — per the phase rules they were never run
  against external infrastructure; tests use fakes. First real use should be against a host you own.
* **DNS rebinding window:** the private-address guard resolves a host, then the HTTP client resolves it again to connect. A hostile
  authoritative DNS server could answer differently the second time. Mitigate at the network layer (egress firewall for the worker).
* **Scope rules are host-based** — ports are limited by `ATLAS_ALLOWED_PORTS`, not per-rule.
* Tested on PostgreSQL 16.15 and Redis 7.0.15 only, single instance each (no replicas, Sentinel/Cluster, PgBouncer, managed services).
* No load/performance testing. Opaque tokens cost one indexed DB lookup per request.
* Password-reset **delivery** is a pluggable interface; the shipped default delivers nowhere (admins can issue one-time tokens). MFA has
  no recovery codes and is not enforced by role. No SSO/OIDC.
* Concurrent refresh with the same token is treated as token theft and revokes the session (strict by design; two browser tabs
  racing a refresh will be logged out).
* Evidence rows are de-duplicated in code, not by a database constraint, so concurrent identical collections may store duplicates.
* PDF reporting and new intelligence features are intentionally **not** started (phase rule).
