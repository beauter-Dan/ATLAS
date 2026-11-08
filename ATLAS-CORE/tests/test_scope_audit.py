"""Phase 13 scope-enforcement audit. `fake` records every outbound call; assertions are on what was (not) requested."""
import json
from datetime import timedelta
import pytest
from sqlalchemy import select
from app.core.errors import ApiError
from app.db.session import get_sessionmaker
from app.models import Assessment, AuditLog, ScopeRule, Target, User
from app.services import jobs, netguard, scope
from tests.conftest import redirect

URL = "/api/v1"


def spy(fake):
    """Record dns/tls/rdap/ct calls too (http is already in fake.calls)."""
    rec = {"dns": [], "tls": [], "rdap": [], "ct": []}
    for k in rec:
        orig = getattr(fake, k)
        setattr(fake, k, (lambda k, orig: lambda *a, **kw: (rec[k].append(a[0]), orig(*a, **kw))[1])(k, orig))
    return rec


def total(fake, rec):
    return len(fake.calls) + sum(len(v) for v in rec.values())


def collect(client, users, aid, hosts, names=None, who="analyst"):
    body = {"hosts": hosts, **({"collectors": names} if names else {})}
    return client.post(f"{URL}/assessments/{aid}/collect", headers=users[who]["h"], json=body)


def audit_rows(client, users, aid, **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    return client.get(f"{URL}/auth/audit-logs?assessment_id={aid}&page_size=500&{qs}", headers=users["admin"]["h"]).json()["data"]


# ---------------------------------------------------------------- before any request
def test_nothing_is_requested_when_assessment_not_active(client, users, world, fake):
    rec = spy(fake)
    client.post(f"{URL}/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
    r = collect(client, users, world["aid"], ["example.test"]).json()["data"]
    assert r["collected"] == [] and "not active" in r["skipped"][0]["reason"]
    assert total(fake, rec) == 0


def test_expired_authorization_blocks_everything(client, users, world, fake, db_session):
    rec = spy(fake)
    t = db_session.get(Target, world["target"]["id"])
    t.authorization_valid_until = scope.authorization_ok.__globals__["datetime"].now(scope.timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    r = collect(client, users, world["aid"], ["example.test"]).json()["data"]
    assert r["collected"] == [] and "expired" in r["skipped"][0]["reason"] and total(fake, rec) == 0


def test_out_of_scope_and_excluded_hosts_are_never_contacted(client, users, world, fake):
    rec = spy(fake)
    r = collect(client, users, world["aid"], ["admin.example.test", "other-corp.test", "evil.test"]).json()["data"]
    assert r["collected"] == [] and len(r["skipped"]) == 3
    assert "excluded" in r["skipped"][0]["reason"] and "not in the authorized scope" in r["skipped"][1]["reason"]
    assert total(fake, rec) == 0


def test_discovered_assets_stay_unauthorized(client, users, world, fake):
    aid, A = world["aid"], users["analyst"]["h"]
    collect(client, users, aid, ["example.test"])
    assets = {a["value"]: a for a in client.get(f"{URL}/assets?assessment_id={aid}&page_size=200", headers=A).json()["data"]}
    assert assets["other-corp.test"]["scope_state"] == "discovered"          # seen in CT logs
    assert assets["203.0.113.10"]["scope_state"] == "discovered"             # resolved IP
    assert assets["cdn.thirdparty.test"]["scope_state"] == "discovered"      # third-party reference
    assert assets["admin.example.test"]["scope_state"] == "excluded"
    assert assets["api.example.test"]["scope_state"] == "authorized"         # only because a HUMAN-written wildcard rule covers it
    rec, before = spy(fake), len(fake.calls)
    r = collect(client, users, aid, ["other-corp.test", "203.0.113.10", "cdn.thirdparty.test"]).json()["data"]
    assert r["collected"] == [] and len(fake.calls) == before and sum(len(v) for v in rec.values()) == 0
    sc = client.post(f"{URL}/assessments/{aid}/scope-check", headers=A, json={"value": "other-corp.test"}).json()["data"]
    assert sc["scope_state"] == "discovered" and sc["access_allowed"] is False
    # creating an asset manually does not authorize it either
    a = client.post(f"{URL}/assets", headers=A, json={"assessment_id": aid, "asset_type": "domain", "value": "new-found.test"}).json()["data"]
    assert a["scope_state"] == "discovered"
    # client-supplied scope_state is ignored/rejected
    client.post(f"{URL}/assets", headers=A, json={"assessment_id": aid, "asset_type": "domain", "value": "sneaky.test", "scope_state": "authorized"})
    got = client.get(f"{URL}/assets?assessment_id={aid}&value=sneaky.test", headers=A).json()
    assert got["meta"]["total"] == 1 and got["data"][0]["scope_state"] == "discovered"


# ---------------------------------------------------------------- parser differentials / URL tricks
@pytest.mark.parametrize("value,expected", [
    ("https://example.test@evil.test/", "discovered"),        # userinfo trick: real host is evil.test
    ("https://example.test.evil.test/", "discovered"),        # suffix trick
    ("https://evil.test/?h=example.test", "discovered"),      # query mentions the in-scope name
    ("https://evil.test/example.test", "discovered"),
    ("https://EXAMPLE.TEST./x", "authorized"),                # case + trailing dot
    ("https://www.example.test:8443/x", "authorized"),
    ("example.test", "authorized"),
    ("evil-example.test", "discovered"),
    ("admin.example.test", "excluded"),
    ("https://ADMIN.example.test/x", "excluded"),
])
def test_classification_tricks(client, users, world, value, expected):
    r = client.post(f"{URL}/assessments/{world['aid']}/scope-check", headers=users["viewer"]["h"], json={"value": value})
    assert r.json()["data"]["scope_state"] == expected


@pytest.mark.parametrize("bad", [
    "https://example.test\\@evil.test/",     # backslash parser differential
    "https://user:pw@example.test/",         # credentials in URL
    "ftp://example.test/", "file:///etc/passwd", "javascript:alert(1)", "gopher://example.test/",
    "https://example.test:22/", "https://example.test:6379/",   # non-web ports
    "https://example.test/\x00", "https://exa mple.test/", "//example.test/", "https://example.test/" + "a" * 3000,
])
def test_strict_url_parsing_rejects_before_any_request(client, users, world, fake, db_session, bad):
    ctx = netguard.ScopeContext(None, "test", fake)
    ok, why, _ = netguard.authorize_url(db_session, world["aid"], bad, ctx)
    assert ok is False and why
    r = netguard.safe_fetch(db_session, world["aid"], bad, ctx)
    assert r["blocked"] is True and fake.calls == []


def test_url_prefix_rules_respect_path_boundaries(client, users, world, db_session):
    aid = world["aid"]
    for rt, v in (("exclude", "https://example.test/billing"),):
        assert client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": aid, "rule_type": rt, "match_type": "url_prefix", "value": v}).status_code == 201
    c = lambda v: scope.classify(db_session, aid, v)[0]
    assert c("https://example.test/billing") == "excluded" and c("https://example.test/billing/x?y=1") == "excluded"
    assert c("https://example.test/billingfoo") == "authorized" and c("https://example.test/home") == "authorized"
    # include-by-prefix must not leak to look-alike hosts
    r = ScopeRule(assessment_id=aid, rule_type="include", match_type="url_prefix", value="https://shop.other.test")
    assert not scope.rule_matches(r, "https://shop.other.test.evil.test/") and scope.rule_matches(r, "https://shop.other.test/x")


def test_idna_hosts_are_normalized(client, users, world, db_session):
    aid = world["aid"]
    assert client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": aid, "rule_type": "include", "match_type": "wildcard", "value": "*.bücher.test"}).status_code == 201
    assert scope.classify(db_session, aid, "https://shop.bücher.test/")[0] == "authorized"
    assert scope.classify(db_session, aid, "shop.xn--bcher-kva.test")[0] == "authorized"
    assert scope.classify(db_session, aid, "shop.bucher.test")[0] == "discovered"


# ---------------------------------------------------------------- redirects are checked independently
def http_decisions(client, users, aid):
    return [(r["details"]["hop"], r["details"]["url"], r["outcome"]) for r in audit_rows(client, users, aid, action="scope_decision")
            if r["details"].get("operation") == "collect" and r["details"]["url"].startswith("http")]


def test_redirect_to_out_of_scope_host_is_not_followed(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://evil.test/landing?token=SECRET123")
    r = collect(client, users, world["aid"], ["example.test"], ["http"]).json()["data"]
    assert r["collected"] and fake.calls == ["https://example.test/"]                     # evil.test never requested
    ev = client.get(f"{URL}/evidence?assessment_id={world['aid']}&category=http_response_metadata", headers=users["analyst"]["h"]).json()["data"][0]
    assert ev["payload"]["redirect_blocked"]["to"] == "https://evil.test/landing"          # logged WITHOUT the query string
    dec = http_decisions(client, users, world["aid"])
    assert (0, "https://example.test/", "allowed") in dec and (1, "https://evil.test/landing", "denied") in dec
    assert "SECRET123" not in json.dumps(audit_rows(client, users, world["aid"]))
    assert "SECRET123" not in json.dumps(ev), json.dumps(ev)[:600]


def test_redirect_to_excluded_host_blocked(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://admin.example.test/panel")
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert fake.calls == ["https://example.test/"]


def test_redirect_to_in_scope_host_is_followed_and_each_hop_checked(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://www.example.test/")
    fake.routes["https://www.example.test/"] = redirect("/welcome")                       # relative redirect
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert fake.calls == ["https://example.test/", "https://www.example.test/", "https://www.example.test/welcome"]
    ev = client.get(f"{URL}/evidence?assessment_id={world['aid']}&category=http_response_metadata", headers=users["analyst"]["h"]).json()["data"][0]
    assert [c["status"] for c in ev["payload"]["redirect_chain"]] == [302, 302, 200]
    assert len([d for d in http_decisions(client, users, world["aid"]) if d[2] == "allowed"]) >= 3


def test_third_hop_out_of_scope_stops_the_chain(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://www.example.test/")
    fake.routes["https://www.example.test/"] = redirect("https://api.example.test/")
    fake.routes["https://api.example.test/"] = redirect("https://evil.test/")
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert fake.calls == ["https://example.test/", "https://www.example.test/", "https://api.example.test/"]


def test_redirect_loop_is_bounded(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://www.example.test/")
    fake.routes["https://www.example.test/"] = redirect("https://example.test/")
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert len(fake.calls) == 4                                                           # max_redirects(3)+1, no hang


@pytest.mark.parametrize("target", ["http://169.254.169.254/latest/meta-data/", "ftp://example.test/x", "https://example.test:22/",
                                    "https://user:pw@example.test/", "http://127.0.0.1/admin", "gopher://example.test/"])
def test_dangerous_redirect_targets_are_blocked(client, users, world, fake, target):
    fake.routes["https://example.test/"] = redirect(target)
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert fake.calls == ["https://example.test/"]


def test_in_scope_name_resolving_to_private_address_is_blocked(client, users, world, fake):
    fake.resolved["www.example.test"] = ["10.0.0.5"]                                        # DNS points an in-scope name at the internal network
    fake.routes["https://example.test/"] = redirect("https://www.example.test/")
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert fake.calls == ["https://example.test/"]
    rows = [r for r in audit_rows(client, users, world["aid"], outcome="denied") if "non-public" in json.dumps(r["details"])]
    assert rows
    # explicit, human-written ip/cidr include rule is required to allow it
    client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": world["aid"], "rule_type": "include", "match_type": "cidr", "value": "10.0.0.0/8"})
    fake.calls.clear()
    collect(client, users, world["aid"], ["example.test"], ["http"])
    assert "https://www.example.test/" in fake.calls


def test_initial_host_resolving_to_loopback_is_not_probed(client, users, world, fake):
    rec = spy(fake)
    fake.resolved["example.test"] = ["127.0.0.1"]
    collect(client, users, world["aid"], ["example.test"], ["http", "tls", "api_docs"])
    assert fake.calls == [] and rec["tls"] == []


def test_each_probed_api_doc_path_is_scope_checked(client, users, world, fake):
    client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": world["aid"], "rule_type": "exclude", "match_type": "url_prefix", "value": "https://example.test/openapi.json"})
    collect(client, users, world["aid"], ["example.test"], ["api_docs"])
    assert "https://example.test/openapi.json" not in fake.calls and "https://example.test/swagger.json" in fake.calls


# ---------------------------------------------------------------- logging of decisions
def test_scope_decisions_are_logged_for_allow_and_deny(client, users, world, fake):
    collect(client, users, world["aid"], ["example.test", "admin.example.test"], ["http"])
    rows = audit_rows(client, users, world["aid"], action="scope_decision")
    outcomes = {(r["details"]["url"], r["outcome"]) for r in rows}
    assert ("admin.example.test", "denied") in outcomes and ("example.test", "allowed") in outcomes
    assert all(r["actor_id"] == users["analyst"]["id"] and "query" not in json.dumps(r["details"]) for r in rows)


# ---------------------------------------------------------------- experiments
def exp_body(aid, url="https://example.test/"):
    return {"assessment_id": aid, "experiment_type": "http_status_check", "parameters": {"url": url}, "rollback_plan": "n/a"}


def approved_experiment(client, users, aid, url="https://example.test/"):
    e = client.post(f"{URL}/experiments", headers=users["analyst"]["h"], json=exp_body(aid, url)).json()["data"]
    client.post(f"{URL}/experiments/{e['id']}/submit", headers=users["analyst"]["h"])
    client.post(f"{URL}/experiments/{e['id']}/approve", headers=users["approver"]["h"])
    return e["id"]


@pytest.mark.parametrize("url", ["https://admin.example.test/", "https://evil.test/", "https://example.test@evil.test/", "ftp://example.test/", "https://example.test:22/"])
def test_experiment_creation_rejects_unauthorized_urls(client, users, world, fake, url):
    r = client.post(f"{URL}/experiments", headers=users["analyst"]["h"], json=exp_body(world["aid"], url))
    # ftp:// is refused by parameter validation (422) before scope; everything else by scope (403). Never any network call.
    assert r.status_code in (403, 422) and (r.status_code == 422 or r.json()["error"]["code"] == "scope_violation") and fake.calls == []


def test_experiment_rechecks_authorization_at_run_time(client, users, world, fake, db_session):
    eid = approved_experiment(client, users, world["aid"])
    t = db_session.get(Target, world["target"]["id"])
    t.authorization_valid_until = scope.datetime.now(scope.timezone.utc) - timedelta(seconds=1); db_session.commit()
    r = client.post(f"{URL}/experiments/{eid}/run", headers=users["analyst"]["h"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "scope_violation" and fake.calls == []
    assert client.get(f"{URL}/experiments/{eid}", headers=users["analyst"]["h"]).json()["data"]["status"] == "approved"   # never started
    assert any(x["outcome"] == "denied" for x in audit_rows(client, users, world["aid"], action="scope_decision"))


def test_experiment_blocked_if_host_excluded_after_approval(client, users, world, fake):
    eid = approved_experiment(client, users, world["aid"], "https://www.example.test/")
    client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": world["aid"], "rule_type": "exclude", "match_type": "domain", "value": "www.example.test"})
    assert client.post(f"{URL}/experiments/{eid}/run", headers=users["analyst"]["h"]).json()["error"]["code"] == "scope_violation"
    assert fake.calls == []


def test_experiments_never_follow_redirects(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://evil.test/x?k=v")
    eid = approved_experiment(client, users, world["aid"])
    r = client.post(f"{URL}/experiments/{eid}/run", headers=users["analyst"]["h"]).json()["data"]
    assert r["status"] == "completed" and set(fake.calls) == {"https://example.test/"}      # repeats of the SAME url only
    assert r["result"]["redirect"] == {"to": "https://evil.test/x", "followed": False, "scope_state": "discovered"}


def test_experiment_unapproved_or_paused_does_not_run(client, users, world, fake):
    e = client.post(f"{URL}/experiments", headers=users["analyst"]["h"], json=exp_body(world["aid"])).json()["data"]
    assert client.post(f"{URL}/experiments/{e['id']}/run", headers=users["analyst"]["h"]).json()["error"]["code"] == "approval_required"
    eid = approved_experiment(client, users, world["aid"])
    client.post(f"{URL}/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
    assert client.post(f"{URL}/experiments/{eid}/run", headers=users["analyst"]["h"]).status_code == 403 and fake.calls == []


# ---------------------------------------------------------------- background jobs re-check at execution
def run_task(aid, hosts, actor_id, names=("http",)):
    from app.worker import collect_task
    return collect_task.apply(args=[aid, hosts, list(names), actor_id]).get()


def test_job_runs_when_everything_still_valid(client, users, world, fake):
    r = run_task(world["aid"], ["example.test"], users["analyst"]["id"])
    assert r["status"] == "completed" and r["result"]["collected"] and fake.calls


def test_job_rejected_if_assessment_paused_after_queueing(client, users, world, fake):
    client.post(f"{URL}/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
    r = run_task(world["aid"], ["example.test"], users["analyst"]["id"])
    assert r["status"] == "rejected" and r["code"] == "job_scope_invalid" and fake.calls == []
    assert any(x["action"] == "job.rejected" for x in audit_rows(client, users, world["aid"], outcome="denied"))


def test_job_rejected_if_actor_deactivated(client, users, world, fake):
    client.patch(f"{URL}/auth/users/{users['analyst']['id']}", headers=users["admin"]["h"], json={"is_active": False})
    r = run_task(world["aid"], ["example.test"], users["analyst"]["id"])
    assert r["code"] == "job_actor_invalid" and fake.calls == []


def test_job_rejected_if_membership_revoked(client, users, new_user, world, fake):
    dan = new_user("dan", "analyst")
    client.put(f"{URL}/assessments/{world['aid']}/members/{dan['id']}", headers=users["admin"]["h"], json={"permission": "analyst"})
    assert run_task(world["aid"], ["example.test"], dan["id"])["status"] == "completed"
    client.delete(f"{URL}/assessments/{world['aid']}/members/{dan['id']}", headers=users["admin"]["h"])
    fake.calls.clear()
    assert run_task(world["aid"], ["example.test"], dan["id"])["code"] == "job_access_revoked" and fake.calls == []
    client.put(f"{URL}/assessments/{world['aid']}/members/{dan['id']}", headers=users["admin"]["h"], json={"permission": "viewer"})
    assert run_task(world["aid"], ["example.test"], dan["id"])["code"] == "job_access_revoked"       # read-only is not enough to run


def test_job_rejected_if_authorization_expired(client, users, world, fake, db_session):
    t = db_session.get(Target, world["target"]["id"])
    t.authorization_valid_until = scope.datetime.now(scope.timezone.utc) - timedelta(seconds=1); db_session.commit()
    r = run_task(world["aid"], ["example.test"], users["analyst"]["id"])
    assert r["code"] == "job_scope_invalid" and "expired" in r["message"] and fake.calls == []


def test_job_skips_hosts_excluded_after_queueing(client, users, world, fake):
    client.post(f"{URL}/scope-rules", headers=users["admin"]["h"], json={"assessment_id": world["aid"], "rule_type": "exclude", "match_type": "domain", "value": "www.example.test"})
    r = run_task(world["aid"], ["www.example.test", "example.test"], users["analyst"]["id"])["result"]
    assert [c["host"] for c in r["collected"]] == ["example.test"] and r["skipped"][0]["host"] == "www.example.test"
    assert all("www.example.test" not in c for c in fake.calls)


def test_job_without_actor_is_rejected(client, users, world, fake):
    assert run_task(world["aid"], ["example.test"], None)["code"] == "job_actor_invalid" and fake.calls == []


def test_enqueue_endpoint_prechecks_and_queues(client, users, world, fake):
    from app.worker import celery_app
    celery_app.conf.task_always_eager, celery_app.conf.task_eager_propagates = True, False
    try:
        r = client.post(f"{URL}/assessments/{world['aid']}/collect/jobs", headers=users["analyst"]["h"], json={"hosts": ["example.test"], "collectors": ["http"]})
        assert r.status_code == 202 and r.json()["data"]["job_id"] and fake.calls
        client.post(f"{URL}/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
        r = client.post(f"{URL}/assessments/{world['aid']}/collect/jobs", headers=users["analyst"]["h"], json={"hosts": ["example.test"]})
        assert r.status_code == 403 and r.json()["error"]["code"] == "job_scope_invalid"       # fail fast, nothing queued
        assert client.post(f"{URL}/assessments/{world['aid']}/collect/jobs", headers=users["viewer"]["h"], json={"hosts": ["example.test"]}).status_code == 403
    finally:
        celery_app.conf.task_always_eager = False


# ---------------------------------------------------------------- real broker -> worker round trip (no network is touched)
@pytest.mark.redis
def test_real_celery_worker_roundtrip_and_result_isolation(client, users, world, fake):
    import os, subprocess, sys, time
    from tests.conftest import DB_URL, REDIS_URL, ROOT
    import redis
    redis.Redis.from_url(REDIS_URL).flushdb()
    # pause the assessment: the job must be REJECTED by the worker's own re-check, and no network may be used
    cid = client.post(f"{URL}/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
    assert cid.status_code == 200
    from app.worker import collect_task
    env = {**os.environ, "ATLAS_DATABASE_URL": DB_URL, "ATLAS_REDIS_URL": REDIS_URL}
    worker = subprocess.Popen([sys.executable, "-m", "celery", "-A", "app.worker.celery_app", "worker", "--pool=solo", "-l", "warning"],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(4)
        # the API pre-check would refuse a paused assessment, so queue directly (a job queued earlier and executed later)
        job = collect_task.apply_async(args=[world["aid"], ["example.test"], ["http"], users["analyst"]["id"]])
        for _ in range(40):
            r = client.get(f"{URL}/assessments/{world['aid']}/collect/jobs/{job.id}", headers=users["analyst"]["h"]).json()["data"]
            if r["state"] == "SUCCESS":
                break
            time.sleep(0.5)
        assert r["state"] == "SUCCESS" and r["result"]["status"] == "rejected" and r["result"]["code"] == "job_scope_invalid"
        # another assessment's members cannot read this job's result through their own assessment id
        other = client.post(f"{URL}/assessments", headers=users["analyst"]["h"], json={"target_id": world["target"]["id"], "name": "other"}).json()["data"]
        leak = client.get(f"{URL}/assessments/{other['id']}/collect/jobs/{job.id}", headers=users["analyst"]["h"]).json()["data"]
        assert "result" not in leak
    finally:
        worker.terminate(); worker.wait(10); worker.stderr.close()
