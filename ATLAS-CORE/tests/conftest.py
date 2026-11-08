"""Isolated test infrastructure.

ATLAS_TEST_DATABASE_URL=postgresql+psycopg://...  -> run against REAL PostgreSQL (schema built by `alembic upgrade head`)
unset                                             -> SQLite file in a temp dir (same migrations)
ATLAS_TEST_REDIS_URL (default redis://localhost:6379/15) is used by Redis-backed tests; they skip if unreachable.
"""
import os, pathlib, tempfile, uuid
from datetime import datetime, timedelta, timezone

PG_URL = os.environ.get("ATLAS_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("ATLAS_TEST_REDIS_URL", "redis://localhost:6379/15")
_tmp = tempfile.mkdtemp(prefix="atlas-test-")
DB_URL = PG_URL or f"sqlite:///{_tmp}/test.db"
IS_PG = DB_URL.startswith("postgresql")
os.environ.update(ATLAS_ENV="test", ATLAS_SECRET_KEY="test-secret-key-0123456789", ATLAS_DATABASE_URL=DB_URL,
                  ATLAS_REDIS_URL=REDIS_URL, ATLAS_PASSWORD_HASH_ITERATIONS="1000", ATLAS_RATE_LIMIT_PER_MINUTE="100000",
                  ATLAS_AUTH_RATE_LIMIT_PER_MINUTE="100000", ATLAS_RATE_LIMIT_BACKEND="memory",
                  ATLAS_COLLECTOR_MIN_INTERVAL_SECONDS="0", ATLAS_AI_PROVIDER="none")

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = pathlib.Path(__file__).resolve().parents[1]


def alembic_cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    return cfg


def ensure_pg_database(url: str) -> None:
    """CREATE DATABASE can fail transiently ("template1 is being accessed by other users"); retry briefly."""
    import time
    u = make_url(url)
    admin = create_engine(u.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        for attempt in range(5):
            try:
                with admin.connect() as c:
                    if not c.scalar(text("select 1 from pg_database where datname=:n"), {"n": u.database}):
                        c.execute(text(f'CREATE DATABASE "{u.database}"'))
                return
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(0.5)
    finally:
        admin.dispose()


from app.core.config import get_settings  # noqa: E402
from app.db.session import Base, get_engine, get_sessionmaker  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AssessmentMember, User  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.services import auth as auth_svc, collectors  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "pg: needs a real PostgreSQL (ATLAS_TEST_DATABASE_URL)")
    config.addinivalue_line("markers", "redis: needs a reachable Redis (ATLAS_TEST_REDIS_URL)")


def pytest_collection_modifyitems(config, items):
    redis_ok = False
    try:
        import redis
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1).ping()
        redis_ok = True
    except Exception:
        pass
    for it in items:
        if "pg" in it.keywords and not IS_PG:
            it.add_marker(pytest.mark.skip(reason="requires ATLAS_TEST_DATABASE_URL (real PostgreSQL)"))
        if "redis" in it.keywords and not redis_ok:
            it.add_marker(pytest.mark.skip(reason=f"Redis not reachable at {REDIS_URL}"))


@pytest.fixture(scope="session", autouse=True)
def _schema():
    """Build the schema ONCE through the real migrations (so every test also exercises them)."""
    if IS_PG:
        ensure_pg_database(DB_URL)
        eng = get_engine()
        with eng.begin() as c:
            c.execute(text("DROP SCHEMA public CASCADE")); c.execute(text("CREATE SCHEMA public"))
    command.upgrade(alembic_cfg(DB_URL), "head")
    yield
    get_engine().dispose()


@pytest.fixture(autouse=True)
def _clean():
    from app.core import ratelimit
    ratelimit._memory.hits.clear(); ratelimit._redis.clear()
    eng = get_engine()
    names = [t.name for t in Base.metadata.sorted_tables]
    with eng.begin() as c:
        if IS_PG:
            c.execute(text("TRUNCATE " + ", ".join(f'"{n}"' for n in names) + " RESTART IDENTITY CASCADE"))
        else:
            for n in reversed(names):
                c.execute(text(f'DELETE FROM "{n}"'))
    s = get_settings()
    saved = s.model_dump()
    yield
    for k, v in saved.items():  # settings mutated by a test never leak into the next one
        setattr(s, k, v)


@pytest.fixture()
def db_session():
    s = get_sessionmaker()()
    yield s
    s.rollback()
    s.close()


@pytest.fixture()
def client():
    return TestClient(app)


def make_user(db, username, role="viewer", password="CorrectHorse-Battery9"):
    u = User(username=username, password_hash=hash_password(password), role=role)
    db.add(u); db.flush()
    tok = auth_svc.issue_session(db, u)
    db.commit()
    return {"user": u, "id": u.id, "h": {"Authorization": f"Bearer {tok['access_token']}"}, "tokens": tok, "password": password}


@pytest.fixture()
def new_user(db_session):
    return lambda username, role="viewer": make_user(db_session, username, role)


@pytest.fixture()
def users(db_session):
    out = {r: make_user(db_session, f"{r}1", r) for r in ("viewer", "analyst", "approver", "admin")}
    out["approver2"] = make_user(db_session, "approver2", "approver")
    return out


class FakeTransports(collectors.Transports):
    """Offline transports. `routes` lets a test script per-URL responses (for redirect tests)."""

    def __init__(self):
        self.calls, self.routes, self.resolved = [], {}, {}
        self.dns = lambda h: {"A": ["203.0.113.10"], "CNAME": ["cdn.example.test."]}
        self.rdap = lambda d: {"ldhName": d, "status": ["active"], "events": [{"eventAction": "expiration", "eventDate": "2030-01-01"}]}
        self.ct = lambda d: [d, f"api.{d}", f"admin.{d}", "other-corp.test"][:4]
        self.tls = lambda h, port=443: {"protocol": "TLSv1.3", "cipher": "AES", "issuer": "CN=Synthetic CA", "subject": "CN=" + h,
                                        "not_after": "2030-01-01T00:00:00+00:00", "not_before": "2025-01-01T00:00:00+00:00",
                                        "san": [h], "verified": True, "verify_error": None}
        self.resolve = lambda h: self.resolved.get(h, ["93.184.216.34"])  # public address by default
        self.http = self._http

    def _http(self, url):
        self.calls.append(url)
        if url in self.routes:
            r = self.routes[url]
            return r(url) if callable(r) else r
        if url.endswith("/openapi.json"):
            import json
            return {"url": url, "status": 200, "headers": {}, "body": json.dumps({"paths": {
                "/api/orders/{id}": {"get": {"summary": "x", "security": [{"k": []}]}, "delete": {"summary": "y"}}}})}
        if url.endswith(".json") or url.endswith("api-docs"):
            return {"url": url, "status": 404, "headers": {}, "body": ""}
        return {"url": url, "status": 200, "headers": {"server": "nginx/1.18.0", "via": "1.1 proxy", "x-powered-by": "Express", "x-frame-options": "DENY"},
                "body": "<html><head><title>Synthetic</title><meta name='generator' content='SynthCMS 2.1'><script src='https://cdn.thirdparty.test/lib.js'></script>"
                        "<script src='/static/jquery-3.4.1.min.js'></script></head></html>"}


@pytest.fixture()
def fake(monkeypatch):
    f = FakeTransports()
    monkeypatch.setattr(collectors, "_transports", f)
    return f


def redirect(to, status=302):
    return {"status": status, "headers": {"location": to}, "body": ""}


@pytest.fixture()
def world(client, users, db_session):
    """analyst1 owns an ACTIVE assessment on example.test (include apex + *.example.test, exclude admin.example.test).
    admin sets scope + membership; approver1/approver2 are 'approver' members, viewer1 a 'viewer' member."""
    A, ADM = users["analyst"]["h"], users["admin"]["h"]
    now = datetime.now(timezone.utc)
    t = client.post("/api/v1/targets", headers=A, json={
        "name": "Synthetic Corp", "base_domain": "example.test", "authorization_reference": "AUTH-1", "authorized_by": "CISO",
        "authorization_valid_from": (now - timedelta(days=1)).isoformat(), "authorization_valid_until": (now + timedelta(days=30)).isoformat(),
        "credentials": "s3cret-credential-value"})
    assert t.status_code == 201, t.text
    t = t.json()["data"]
    a = client.post("/api/v1/assessments", headers=A, json={"target_id": t["id"], "name": "Q1", "environment": "staging"}).json()["data"]
    for rt, mt, v in (("include", "domain", "example.test"), ("include", "wildcard", "*.example.test"), ("exclude", "domain", "admin.example.test")):
        r = client.post("/api/v1/scope-rules", headers=ADM, json={"assessment_id": a["id"], "rule_type": rt, "match_type": mt, "value": v})
        assert r.status_code == 201, r.text
    for who, perm in (("approver", "approver"), ("approver2", "approver"), ("viewer", "viewer")):
        assert client.put(f"/api/v1/assessments/{a['id']}/members/{users[who]['id']}", headers=ADM, json={"permission": perm}).status_code == 200
    r = client.post(f"/api/v1/assessments/{a['id']}/status", headers=users["approver"]["h"], json={"status": "active"})
    assert r.status_code == 200, r.text
    return {"target": t, "assessment": a, "aid": a["id"]}
