"""Real-PostgreSQL verification (skipped unless ATLAS_TEST_DATABASE_URL points at PostgreSQL)."""
import json, os, subprocess, sys, uuid
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from app.db.session import Base, get_engine, get_sessionmaker
from app.main import app
from app.models import (Assessment, AssessmentMember, AuditLog, Evidence, Experiment, Observation, ScopeRule, Target, User)
from tests.conftest import DB_URL, ROOT, ensure_pg_database

pytestmark = pytest.mark.pg
URL = "/api/v1"


# =========================================================== migrations on empty & populated databases
def alembic(url, *args):
    env = {**os.environ, "ATLAS_DATABASE_URL": url}
    r = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-800:]
    return r.stdout + r.stderr


@pytest.fixture()
def scratch_url():
    u = make_url(DB_URL)
    name = f"atlas_scratch_{uuid.uuid4().hex[:8]}"
    ensure_pg_database(str(u.set(database=name).render_as_string(hide_password=False)))
    url = u.set(database=name).render_as_string(hide_password=False)
    yield url
    admin = create_engine(u.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


def test_fresh_install_creates_every_table_and_matches_models(scratch_url):
    alembic(scratch_url, "upgrade", "head")
    eng = create_engine(scratch_url)
    names = set(inspect(eng).get_table_names())
    assert {t.name for t in Base.metadata.sorted_tables} | {"alembic_version"} == names
    with eng.connect() as c:
        assert c.scalar(text("select version_num from alembic_version")) == "0003"
        assert c.scalar(text("select count(*) from pg_trigger where tgname='audit_logs_no_update_delete'")) == 1
    assert "No new upgrade operations" in alembic(scratch_url, "check") or True     # `alembic check` exits 0 only when no drift
    eng.dispose()


def test_upgrade_path_preserves_and_backfills_existing_data(scratch_url):
    alembic(scratch_url, "upgrade", "0001")
    eng = create_engine(scratch_url)
    with eng.begin() as c:
        c.execute(text("insert into users (id,username,password_hash,role,is_active,created_at) values ('u1','legacy','salt$hash','analyst',true,now())"))
        c.execute(text("insert into targets (id,name,base_domain,created_at) values ('t1','T','example.test',now())"))
        c.execute(text("insert into assessments (id,target_id,name,status,environment,status_history,created_by,created_at) "
                       "values ('a1','t1','A','draft','staging','[]','u1',now()), ('a2','t1','B','draft','staging','[]','ghost-user',now())"))
    alembic(scratch_url, "upgrade", "head")
    with eng.connect() as c:
        rows = dict(c.execute(text("select id, owner_id from assessments")).all())
        assert rows == {"a1": "u1", "a2": None}                                      # backfilled where the creator still exists
        u = c.execute(text("select failed_login_count, mfa_enabled, locked_until from users where id='u1'")).one()
        assert (u[0], u[1], u[2]) == (0, False, None)
    # downgrade removes the new objects cleanly, and re-upgrade works
    alembic(scratch_url, "downgrade", "0001")
    insp = inspect(eng)
    assert "auth_sessions" not in insp.get_table_names() and "owner_id" not in {c["name"] for c in insp.get_columns("assessments")}
    with eng.connect() as c:
        assert c.scalar(text("select count(*) from pg_trigger where tgname='audit_logs_no_update_delete'")) == 0
    alembic(scratch_url, "upgrade", "head")
    eng.dispose()


# =========================================================== constraints
def mk_assessment(db):
    t = Target(name=f"t-{uuid.uuid4().hex[:6]}", base_domain="example.test"); db.add(t); db.flush()
    a = Assessment(target_id=t.id, name="a"); db.add(a); db.flush()
    return a


def expect_integrity(db, obj):
    with pytest.raises(IntegrityError):
        db.add(obj); db.flush()
    db.rollback()


def test_foreign_keys_checks_and_uniques(db_session):
    db = db_session
    a = mk_assessment(db); db.commit()
    expect_integrity(db, Observation(assessment_id="no-such", evidence_id=None, category="c", kind="unknown", description="d", collection_source="s"))
    expect_integrity(db, AssessmentMember(assessment_id=a.id, user_id="no-such", permission="viewer"))
    expect_integrity(db, Assessment(target_id=a.target_id, name="x", status="bogus"))                       # CHECK
    expect_integrity(db, Assessment(target_id=a.target_id, name="x", environment="prod"))                   # CHECK
    expect_integrity(db, Observation(assessment_id=a.id, category="c", kind="direct_observation", description="d", collection_source="s"))   # needs evidence
    expect_integrity(db, Observation(assessment_id=a.id, category="c", kind="made_up", description="d", collection_source="s"))
    expect_integrity(db, Evidence(assessment_id=a.id, category="c", description="d", collection_source="s", reference="r", content_hash="h", confidence="very"))
    expect_integrity(db, Experiment(assessment_id=a.id, experiment_type="http_status_check", rollback_plan="r", rate_limit_per_minute=31))
    expect_integrity(db, Experiment(assessment_id=a.id, experiment_type="http_status_check", rollback_plan="r", max_requests=0))
    expect_integrity(db, Experiment(assessment_id=a.id, experiment_type="sql_injection", rollback_plan="r"))  # only whitelisted types exist
    u = User(username="dup", password_hash="x", role="viewer"); db.add(u); db.commit()
    expect_integrity(db, User(username="dup", password_hash="x", role="viewer"))
    expect_integrity(db, User(username="badrole", password_hash="x", role="root"))
    db.add(ScopeRule(assessment_id=a.id, rule_type="include", match_type="domain", value="example.test")); db.commit()
    expect_integrity(db, ScopeRule(assessment_id=a.id, rule_type="include", match_type="domain", value="example.test"))
    expect_integrity(db, ScopeRule(assessment_id=a.id, rule_type="allow", match_type="domain", value="x.test"))


def test_cascades_set_null_and_audit_survival(db_session):
    db = db_session
    owner = User(username="own", password_hash="x", role="analyst"); db.add(owner); db.flush()
    a = mk_assessment(db); a.owner_id = owner.id; db.flush()
    ev = Evidence(assessment_id=a.id, category="c", description="d", collection_source="s", reference="r", content_hash="h"); db.add(ev); db.flush()
    db.add(Observation(assessment_id=a.id, evidence_id=ev.id, category="c", description="d", collection_source="s"))
    db.add(AssessmentMember(assessment_id=a.id, user_id=owner.id, permission="viewer"))
    db.add(AuditLog(action="keep.me", resource_type="assessment", assessment_id=a.id)); db.commit()
    aid = a.id
    db.execute(text("delete from users where id=:i"), {"i": owner.id}); db.commit()          # SET NULL on owner, CASCADE on membership
    assert db.scalar(text("select owner_id from assessments where id=:i"), {"i": aid}) is None
    assert db.scalar(text("select count(*) from assessment_members where assessment_id=:i"), {"i": aid}) == 0
    db.execute(text("delete from assessments where id=:i"), {"i": aid}); db.commit()          # CASCADE everything underneath
    for tbl in ("evidence", "observations"):
        assert db.scalar(text(f"select count(*) from {tbl} where assessment_id=:i"), {"i": aid}) == 0
    assert db.scalar(text("select count(*) from audit_logs where action='keep.me'")) == 1      # audit history outlives its subject


def test_audit_log_is_append_only_in_the_database(db_session):
    db = db_session
    db.add(AuditLog(action="a", resource_type="t")); db.commit()
    for stmt in ("update audit_logs set action='tampered'", "delete from audit_logs"):
        with pytest.raises(DBAPIError) as e:
            db.execute(text(stmt)); db.commit()
        db.rollback()
        assert "append-only" in str(e.value)
    assert db.scalar(text("select count(*) from audit_logs where action='a'")) == 1


# =========================================================== transactions / rollback
def test_transaction_rollback_and_savepoints(db_session):
    db = db_session
    t = Target(name="rb", base_domain="example.test"); db.add(t); db.flush()
    db.rollback()
    assert db.scalar(text("select count(*) from targets where name='rb'")) == 0
    t = Target(name="keep", base_domain="example.test"); db.add(t); db.flush()
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(Target(name="keep", base_domain="dup.test")); db.flush()                 # unique violation inside SAVEPOINT
    db.commit()
    assert db.scalar(text("select count(*) from targets where name='keep'")) == 1           # outer work survived the savepoint rollback


def test_failed_collector_leaves_no_partial_rows_and_session_stays_usable(client, users, world, fake, db_session):
    def boom(h, port=443):
        raise TimeoutError("tls probe timed out")
    fake.tls = boom
    r = client.post(f"{URL}/assessments/{world['aid']}/collect", headers=users["analyst"]["h"],
                    json={"hosts": ["example.test", "www.example.test"], "collectors": ["rdap", "dns", "tls"]}).json()["data"]
    assert len(r["errors"]) == 2 and r["collected"] == []
    assert db_session.scalar(text("select count(*) from evidence where assessment_id=:a"), {"a": world["aid"]}) == 0     # rdap/dns rows rolled back
    assert db_session.scalar(text("select count(*) from audit_logs where action='collect' and assessment_id=:a"), {"a": world["aid"]}) == 2


# =========================================================== pagination / filtering / sorting
def test_pagination_filtering_sorting_are_consistent(client, users, world):
    aid, A = world["aid"], users["analyst"]["h"]
    s = get_sessionmaker()()
    for i in range(120):
        s.execute(text("insert into assets (id,assessment_id,asset_type,value,scope_state,discovery_source,details,created_at) "
                       "values (:id,:a,:t,:v,:s,'seed','{}',now() + (:i || ' seconds')::interval)"),
                  {"id": f"seed-{i:03d}", "a": aid, "t": "subdomain" if i % 3 else "domain", "v": f"h{i:03d}.example.test", "s": "authorized" if i % 2 else "discovered", "i": i})
    s.commit(); s.close()
    seen, pages = [], 0
    for page in (1, 2, 3, 4):
        r = client.get(f"{URL}/assets?assessment_id={aid}&page={page}&page_size=50&sort=value", headers=A).json()
        pages += bool(r["data"]); seen += [x["value"] for x in r["data"]]
        assert r["meta"] == {"page": page, "page_size": 50, "total": 120}
    assert pages == 3 and seen == sorted(seen) and len(set(seen)) == 120 and len(seen) == 120          # no gaps, no overlap
    desc = client.get(f"{URL}/assets?assessment_id={aid}&sort=-value&page_size=5", headers=A).json()["data"]
    assert [x["value"] for x in desc] == ["h119.example.test", "h118.example.test", "h117.example.test", "h116.example.test", "h115.example.test"]
    assert client.get(f"{URL}/assets?assessment_id={aid}&scope_state=authorized", headers=A).json()["meta"]["total"] == 60
    assert client.get(f"{URL}/assets?assessment_id={aid}&scope_state=authorized&asset_type=domain&page_size=200", headers=A).json()["meta"]["total"] == 20
    assert client.get(f"{URL}/assets?assessment_id={aid}&value=h007.example.test", headers=A).json()["meta"]["total"] == 1
    assert client.get(f"{URL}/assets?assessment_id={aid}&page=99", headers=A).json()["data"] == []
    for bad in ("sort=nope", "page=0", "page_size=201", "page_size=0"):
        assert client.get(f"{URL}/assets?{bad}", headers=A).status_code in (422,), bad
    assert client.get(f"{URL}/assets?assessment_id={aid}&value=%27%20OR%201%3D1--", headers=A).json()["meta"]["total"] == 0   # filters are parameterized


def test_boolean_filter_on_postgres(client, users, world, fake):
    A, aid = users["analyst"]["h"], world["aid"]
    src = {"a.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/x")\ndef f(): ...\n@app.get("/y")\ndef g(user=Depends(get_current_user)): ...\n'}
    client.post(f"{URL}/assessments/{aid}/internal/source", headers=A, json={"label": "app", "files": src})
    assert client.get(f"{URL}/application-routes?assessment_id={aid}&auth_required=true", headers=A).json()["meta"]["total"] == 1


# =========================================================== value-length / data errors (PostgreSQL enforces varchar limits)
def test_overlong_values_are_422_not_500(client, users, world):
    A = users["analyst"]["h"]
    r = client.post(f"{URL}/targets", headers=A, json={"name": "n" * 201, "base_domain": "x.test"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    r = client.post(f"{URL}/findings", headers=A, json={"assessment_id": world["aid"], "title": "t" * 301, "classification": "insufficient_evidence", "rationale": "r"})
    assert r.status_code == 422
    r = client.post(f"{URL}/assets", headers=A, json={"assessment_id": world["aid"], "asset_type": "domain", "value": "a" * 501})
    assert r.status_code == 422


def test_data_error_handler_maps_to_422():
    from sqlalchemy.exc import DataError
    async def boom():
        raise DataError("stmt", {}, Exception("value too long for type character varying(10)"))
    app.add_api_route("/__dataerror", boom, methods=["GET"])
    r = TestClient(app).get("/__dataerror")
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_data"


# =========================================================== concurrency (real parallel connections)
def par(n, fn):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(lambda i: fn(i), range(n)))


def call(method, url, **kw):
    c = TestClient(app)
    r = getattr(c, method)(url, **kw)
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else None)


def test_concurrent_duplicate_inserts_yield_exactly_one_row(client, users, world):
    A, aid = users["analyst"]["h"], world["aid"]
    res = par(16, lambda i: call("post", f"{URL}/assets", headers=A, json={"assessment_id": aid, "asset_type": "domain", "value": "race.example.test"}))
    codes = sorted(c for c, _ in res)
    assert codes.count(201) == 1 and codes.count(409) == 15, codes
    assert client.get(f"{URL}/assets?assessment_id={aid}&value=race.example.test", headers=A).json()["meta"]["total"] == 1


def test_concurrent_experiment_run_executes_exactly_once(client, users, world, fake):
    A, P, aid = users["analyst"]["h"], users["approver"]["h"], world["aid"]
    e = client.post(f"{URL}/experiments", headers=A, json={"assessment_id": aid, "experiment_type": "header_review",
                    "parameters": {"url": "https://example.test/", "headers_of_interest": ["x-frame-options"]}, "rollback_plan": "n/a", "max_requests": 1}).json()["data"]
    client.post(f"{URL}/experiments/{e['id']}/submit", headers=A)
    client.post(f"{URL}/experiments/{e['id']}/approve", headers=P)
    res = par(6, lambda i: call("post", f"{URL}/experiments/{e['id']}/run", headers=A))
    codes = sorted(c for c, _ in res)
    assert codes.count(200) == 1 and codes.count(409) == 5, codes                    # row lock serialises; losers see a non-approved state
    assert fake.calls.count("https://example.test/") == 1                             # the target was contacted ONCE, not 6 times
    assert client.get(f"{URL}/experiments/{e['id']}", headers=A).json()["data"]["status"] == "completed"


def test_concurrent_double_approval(client, users, world):
    A, aid = users["analyst"]["h"], world["aid"]
    e = client.post(f"{URL}/experiments", headers=A, json={"assessment_id": aid, "experiment_type": "http_status_check",
                    "parameters": {"url": "https://example.test/"}, "rollback_plan": "n/a"}).json()["data"]
    client.post(f"{URL}/experiments/{e['id']}/submit", headers=A)
    res = par(2, lambda i: call("post", f"{URL}/experiments/{e['id']}/approve", headers=users["approver" if i else "approver2"]["h"]))
    assert sorted(c for c, _ in res) == [200, 409]


def test_concurrent_hypothesis_generation_has_no_duplicates_or_errors(client, users, world, fake):
    A, aid = users["analyst"]["h"], world["aid"]
    client.post(f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"]})
    client.post(f"{URL}/assessments/{aid}/internal/source", headers=A, json={"label": "app", "files": {"m.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.post("/orders/{id}/cancel")\ndef c(id): ...\n'}})
    res = par(5, lambda i: call("post", f"{URL}/assessments/{aid}/hypotheses/generate", headers=A))
    assert all(c == 200 for c, _ in res), res
    created = sum(b["data"]["created"] for _, b in res)
    total = client.get(f"{URL}/hypotheses?assessment_id={aid}&page_size=200", headers=A).json()
    assert created == total["meta"]["total"] > 0 and len({h["title"] for h in total["data"]}) == total["meta"]["total"]


def test_concurrent_collections_do_not_error_on_shared_assets(client, users, world, fake):
    A, aid = users["analyst"]["h"], world["aid"]
    res = par(4, lambda i: call("post", f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"], "collectors": ["dns", "ct", "http"]}))
    assert all(c == 200 and not b["data"]["errors"] for c, b in res), [b["data"]["errors"] for _, b in res if b]
    vals = [a["value"] for a in client.get(f"{URL}/assets?assessment_id={aid}&page_size=200", headers=A).json()["data"]]
    assert len(vals) == len(set(vals))


def test_concurrent_membership_upserts(client, users, new_user, world):
    dan = new_user("dan", "analyst")
    res = par(8, lambda i: call("put", f"{URL}/assessments/{world['aid']}/members/{dan['id']}", headers=users["admin"]["h"], json={"permission": ["viewer", "analyst"][i % 2]}))
    assert all(c in (200, 409) for c, _ in res) and any(c == 200 for c, _ in res)
    assert sum(1 for m in client.get(f"{URL}/assessments/{world['aid']}/members", headers=users["admin"]["h"]).json()["data"] if m["user_id"] == dan["id"]) == 1


def test_concurrent_refresh_with_same_token_allows_only_one(client, users):
    t = client.post(f"{URL}/auth/login", json={"username": "analyst1", "password": users["analyst"]["password"]}).json()["data"]
    res = par(4, lambda i: call("post", f"{URL}/auth/refresh", json={"refresh_token": t["refresh_token"]}))
    codes = sorted(c for c, _ in res)
    assert codes.count(200) == 1 and codes.count(401) == 3 and 500 not in codes, codes


def test_concurrent_failed_logins_lock_the_account(client, users):
    from app.core.config import get_settings
    get_settings().max_failed_logins = 5
    res = par(10, lambda i: call("post", f"{URL}/auth/login", json={"username": "viewer1", "password": "definitely-wrong-1"}))
    assert all(c in (401, 429) for c, _ in res), res
    ok = client.post(f"{URL}/auth/login", json={"username": "viewer1", "password": users["viewer"]["password"]})
    assert ok.status_code == 429 and ok.json()["error"]["code"] == "account_locked"
    s = get_sessionmaker()()
    assert 5 <= s.scalar(text("select failed_login_count from users where username='viewer1'")) <= 10
    s.close()
