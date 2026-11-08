import json, pathlib, subprocess, sys, os
from app.main import app

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_openapi_contract_is_current():
    spec = json.loads((ROOT / "contracts" / "openapi.json").read_text())
    assert spec == json.loads(json.dumps(app.openapi())), "Run: python -m scripts.export_contracts"


def test_required_endpoints_present():
    paths = app.openapi()["paths"]
    for p in ("targets", "assessments", "assets", "technologies", "observations", "hypotheses", "experiments", "findings", "reports", "apis", "databases"):
        assert f"/api/v1/{p}" in paths
    assert "/api/v1/architecture" in paths


def test_migrations_apply_on_sqlite(tmp_path):
    env = {**os.environ, "ATLAS_DATABASE_URL": f"sqlite:///{tmp_path}/m.db"}
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    import sqlite3
    names = {x[0] for x in sqlite3.connect(tmp_path / "m.db").execute("select name from sqlite_master where type='table'")}
    assert {"users", "targets", "assessments", "scope_rules", "assets", "technologies", "observations", "relationships", "application_routes",
            "api_endpoints", "database_schemas", "database_tables", "hypotheses", "experiments", "findings", "evidence", "reports", "audit_logs"} <= names
