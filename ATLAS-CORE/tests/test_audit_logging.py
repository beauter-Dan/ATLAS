import json
import pytest
from tests.conftest import redirect

URL = "/api/v1"


def rows(client, users, **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    return client.get(f"{URL}/auth/audit-logs?page_size=500&{qs}", headers=users["admin"]["h"]).json()["data"]


def actions(client, users, **q):
    return {r["action"] for r in rows(client, users, **q)}


def test_lifecycle_events_are_audited_with_actor_and_assessment(client, users, world, fake):
    A, P, ADM, aid = users["analyst"]["h"], users["approver"]["h"], users["admin"]["h"], world["aid"]
    client.post(f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"]})
    client.post(f"{URL}/assessments/{aid}/internal/source", headers=A, json={"label": "app", "files": {"a.py": '@app.get("/x")\ndef f(): ...\n'}})
    client.post(f"{URL}/assessments/{aid}/internal/schema", headers=A, json={"name": "s", "sql": "CREATE TABLE t (id INT);"})
    client.post(f"{URL}/assessments/{aid}/architecture/build", headers=A)
    client.post(f"{URL}/assessments/{aid}/hypotheses/generate", headers=A)
    client.post(f"{URL}/assessments/{aid}/ai/reconnaissance", headers=A)
    e = client.post(f"{URL}/experiments", headers=A, json={"assessment_id": aid, "experiment_type": "http_status_check", "parameters": {"url": "https://example.test/"}, "rollback_plan": "n/a"}).json()["data"]
    for step, h in (("submit", A), ("approve", P), ("run", A), ("rollback", A)):
        client.post(f"{URL}/experiments/{e['id']}/{step}", headers=h)
    ev = client.get(f"{URL}/evidence?assessment_id={aid}", headers=A).json()["data"][0]["id"]
    client.post(f"{URL}/evidence/{ev}/verify", headers=A, json={})
    f = client.post(f"{URL}/findings", headers=A, json={"assessment_id": aid, "title": "t", "classification": "informational_observation", "evidence_ids": [ev]}).json()["data"]
    client.post(f"{URL}/findings/{f['id']}/classify", headers=A, json={"classification": "false_positive", "rationale": "r"})
    client.post(f"{URL}/assessments/{aid}/reports", headers=A)
    client.post(f"{URL}/assessments/{aid}/status", headers=P, json={"status": "paused"})
    got = actions(client, users, assessment_id=aid)
    expected = {"assessment.create", "scoperule.create", "member.set", "assessment.status", "collect",
                "scope_decision", "internal.source", "internal.schema", "architecture.build", "hypotheses.generate", "ai.reconnaissance",
                "experiment.create", "experiment.submit", "experiment.approve", "experiment.run", "experiment.finish", "experiment.rollback",
                "evidence.verify", "finding.create", "finding.classify", "report.generate"}
    assert expected - got == set(), expected - got
    for r in rows(client, users, assessment_id=aid):
        assert r["timestamp"] and r["outcome"] in ("success", "denied", "allowed") and r["resource_type"]
        assert r["actor_id"] or r["action"] == "x", r
    st = [r for r in rows(client, users, assessment_id=aid, action="assessment.status")][0]
    assert st["actor_id"] == users["approver"]["id"] and st["details"]["to"] == "paused"


def test_security_events_are_audited(client, users, new_user, world):
    from app.core.config import get_settings
    get_settings().max_failed_logins = 2
    bob = new_user("bob", "analyst")
    for _ in range(2):
        client.post(f"{URL}/auth/login", json={"username": "bob", "password": "wrong-password-9"})
    client.post(f"{URL}/auth/login", json={"username": "bob", "password": bob["password"]})            # locked
    client.post(f"{URL}/auth/login", json={"username": "ghost", "password": "wrong-password-9"})
    client.get(f"{URL}/assessments/{world['aid']}", headers=bob["h"])                                  # stranger
    t = client.post(f"{URL}/auth/login", json={"username": "viewer1", "password": users["viewer"]["password"]}).json()["data"]
    client.post(f"{URL}/auth/refresh", json={"refresh_token": t["refresh_token"]})
    client.post(f"{URL}/auth/refresh", json={"refresh_token": t["refresh_token"]})                      # reuse
    client.post(f"{URL}/auth/logout-all", headers=users["analyst"]["h"])
    client.patch(f"{URL}/auth/users/{bob['id']}", headers=users["admin"]["h"], json={"role": "viewer"})
    client.post(f"{URL}/auth/users", headers=users["admin"]["h"], json={"username": "newbie", "password": "Str0ng-Passphrase-1", "role": "analyst"})
    client.delete(f"{URL}/assessments/{world['aid']}/members/{users['viewer']['id']}", headers=users["admin"]["h"])
    got = actions(client, users)
    assert {"auth.login", "auth.refresh", "auth.refresh_reuse", "auth.logout_all", "access_denied", "user.update", "user.create", "member.remove"} <= got
    denied = rows(client, users, action="auth.login", outcome="denied")
    reasons = {r["details"].get("reason") for r in denied}
    assert {"bad_password_or_inactive", "account_locked", "unknown_user"} <= reasons
    assert "wrong-password-9" not in json.dumps(denied)


def test_audit_log_is_admin_only_filterable_and_immutable_via_api(client, users, world):
    for who in ("viewer", "analyst", "approver"):
        assert client.get(f"{URL}/auth/audit-logs", headers=users[who]["h"]).status_code == 403
    assert client.get(f"{URL}/auth/audit-logs").status_code == 401
    assert all(r["outcome"] == "success" for r in rows(client, users, outcome="success"))
    for method in ("post", "put", "patch", "delete"):
        r = getattr(client, method)(f"{URL}/auth/audit-logs", headers=users["admin"]["h"])
        assert r.status_code in (405, 422), method                   # there is no write path for audit rows
    oa = client.get("/openapi.json").json()["paths"]
    assert set(oa[f"{URL}/auth/audit-logs"]) == {"get"} and not any("audit" in p and p != f"{URL}/auth/audit-logs" for p in oa)


def test_audit_scrubs_urls_and_secret_keys(client, users, world, fake):
    fake.routes["https://example.test/"] = redirect("https://evil.test/cb?access_token=TOPSECRET99&x=1")
    client.post(f"{URL}/assessments/{world['aid']}/collect", headers=users["analyst"]["h"], json={"hosts": ["example.test"], "collectors": ["http"]})
    blob = json.dumps(rows(client, users))
    assert "TOPSECRET99" not in blob and "s3cret-credential-value" not in blob
