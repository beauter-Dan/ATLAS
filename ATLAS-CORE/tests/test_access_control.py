"""Per-assessment access control with several synthetic users. Stranger => 404 (existence hidden);
member with too little permission => 403 insufficient_assessment_permission."""
import pytest

SRC = {"app/main.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.post("/orders/{id}/cancel")\ndef c(id): ...\n'}
SQL = "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT);"


@pytest.fixture()
def populated(client, users, world, fake):
    """alice (analyst1) owns the assessment, which already holds assets, evidence, hypotheses, experiment, finding, report, schema."""
    A, P, aid = users["analyst"]["h"], users["approver"]["h"], world["aid"]
    client.post(f"/api/v1/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"]})
    client.post(f"/api/v1/assessments/{aid}/internal/source", headers=A, json={"label": "app", "files": SRC})
    s = client.post(f"/api/v1/assessments/{aid}/internal/schema", headers=A, json={"name": "shop", "sql": SQL}).json()["data"]
    client.post(f"/api/v1/assessments/{aid}/architecture/build", headers=A)
    client.post(f"/api/v1/assessments/{aid}/hypotheses/generate", headers=A)
    e = client.post("/api/v1/experiments", headers=A, json={"assessment_id": aid, "experiment_type": "http_status_check",
                    "parameters": {"url": "https://example.test/"}, "rollback_plan": "n/a"}).json()["data"]
    ev = client.get(f"/api/v1/evidence?assessment_id={aid}", headers=A).json()["data"][0]["id"]
    f = client.post("/api/v1/findings", headers=A, json={"assessment_id": aid, "title": "t", "classification": "informational_observation", "evidence_ids": [ev]}).json()["data"]
    rep = client.post(f"/api/v1/assessments/{aid}/reports", headers=A).json()["data"]
    hyp = client.get(f"/api/v1/hypotheses?assessment_id={aid}", headers=A).json()["data"][0]
    return {"schema": s["schema_id"], "exp": e["id"], "evidence": ev, "finding": f["id"], "report": rep["id"], "hyp": hyp["id"], "aid": aid}


LISTS = ["assets", "technologies", "observations", "evidence", "application-routes", "apis", "databases", "hypotheses",
         "experiments", "findings", "reports", "scope-rules"]


def test_stranger_sees_nothing(client, users, new_user, populated):
    bob = new_user("bob", "analyst")["h"]
    aid = populated["aid"]
    assert client.get("/api/v1/assessments", headers=bob).json()["meta"]["total"] == 0
    assert client.get("/api/v1/targets", headers=bob).json()["meta"]["total"] == 0
    for res in LISTS:
        r = client.get(f"/api/v1/{res}", headers=bob).json()
        assert r["meta"]["total"] == 0, res
        assert client.get(f"/api/v1/{res}?assessment_id={aid}", headers=bob).json()["meta"]["total"] == 0, res
    # direct object access: 404 (never 403) so existence is not leaked
    assert client.get(f"/api/v1/assessments/{aid}", headers=bob).status_code == 404
    assert client.get(f"/api/v1/findings/{populated['finding']}", headers=bob).status_code == 404
    assert client.get(f"/api/v1/evidence/{populated['evidence']}", headers=bob).status_code == 404
    assert client.get(f"/api/v1/targets/{client.get('/api/v1/targets', headers=users['analyst']['h']).json()['data'][0]['id']}", headers=bob).status_code == 404
    assert client.get(f"/api/v1/databases/{populated['schema']}/tables", headers=bob).status_code == 404
    assert client.get(f"/api/v1/reports/{populated['report']}/html", headers=bob).status_code == 404
    assert client.get(f"/api/v1/architecture?assessment_id={aid}", headers=bob).status_code == 404
    assert client.get(f"/api/v1/assessments/{aid}/members", headers=bob).status_code == 404


def test_stranger_cannot_write_or_trigger_anything(client, users, new_user, populated):
    bob = new_user("bob", "analyst")["h"]
    aid, gen = populated["aid"], populated
    calls = [
        ("patch", f"/api/v1/assessments/{aid}", {"name": "hijack"}),
        ("post", "/api/v1/assets", {"assessment_id": aid, "asset_type": "domain", "value": "x.example.test"}),
        ("post", "/api/v1/observations", {"assessment_id": aid, "category": "c", "description": "d", "evidence_reference": "r"}),
        ("post", "/api/v1/hypotheses", {"assessment_id": aid, "category": "c", "title": "t", "reasoning": "r", "supporting_evidence_ids": [gen["evidence"]], "safe_validation_approach": "s"}),
        ("post", "/api/v1/experiments", {"assessment_id": aid, "experiment_type": "http_status_check", "parameters": {"url": "https://example.test/"}, "rollback_plan": "n"}),
        ("post", "/api/v1/findings", {"assessment_id": aid, "title": "t", "classification": "informational_observation", "evidence_ids": [gen["evidence"]]}),
        ("post", f"/api/v1/assessments/{aid}/scope-check", {"value": "example.test"}),
        ("post", f"/api/v1/assessments/{aid}/collect", {"hosts": ["example.test"]}),
        ("post", f"/api/v1/assessments/{aid}/collect/jobs", {"hosts": ["example.test"]}),
        ("post", f"/api/v1/assessments/{aid}/internal/source", {"label": "l", "files": SRC}),
        ("post", f"/api/v1/assessments/{aid}/internal/schema", {"name": "n", "sql": SQL}),
        ("post", f"/api/v1/assessments/{aid}/architecture/build", None),
        ("post", f"/api/v1/assessments/{aid}/ai/reconnaissance", None),
        ("post", f"/api/v1/assessments/{aid}/hypotheses/generate", None),
        ("post", f"/api/v1/assessments/{aid}/reports", None),
        ("post", f"/api/v1/experiments/{gen['exp']}/submit", None),
        ("post", f"/api/v1/experiments/{gen['exp']}/run", None),
        ("post", f"/api/v1/findings/{gen['finding']}/classify", {"classification": "false_positive", "rationale": "x"}),
        ("post", f"/api/v1/evidence/{gen['evidence']}/verify", {}),
        ("put", f"/api/v1/assessments/{aid}/members/{users['viewer']['id']}", {"permission": "viewer"}),
    ]
    for method, url, body in calls:
        r = getattr(client, method)(url, headers=bob, **({"json": body} if body is not None else {}))
        assert r.status_code == 404 and r.json()["error"]["code"] == "not_found", (method, url, r.status_code, r.text[:120])
    # approver-gated endpoints: the stranger must be a global approver for the assessment-level gate to be what stops them
    apr = new_user("approver9", "approver")["h"]
    for method, url, body in (("post", "/api/v1/scope-rules", {"assessment_id": aid, "rule_type": "include", "match_type": "domain", "value": "evil.test"}),
                              ("post", f"/api/v1/assessments/{aid}/status", {"status": "paused"})):
        r = getattr(client, method)(url, headers=apr, json=body)
        assert r.status_code == 404 and r.json()["error"]["code"] == "not_found", (url, r.status_code)
    assert client.post("/api/v1/scope-rules", headers=bob, json={"assessment_id": aid, "rule_type": "include", "match_type": "domain", "value": "evil.test"}).status_code == 403
    # DELETE is admin-only: a non-admin is refused by role before any object lookup
    assert client.delete(f"/api/v1/hypotheses/{gen['hyp']}", headers=bob).status_code == 403
    # and nothing changed
    assert client.get(f"/api/v1/assessments/{aid}", headers=users["analyst"]["h"]).json()["data"]["name"] == "Q1"


def test_stranger_approver_still_blocked(client, users, new_user, populated):
    """Global role is not enough: a global approver who is not a member of the assessment sees nothing."""
    other = new_user("approver3", "approver")["h"]
    assert client.get(f"/api/v1/assessments/{populated['aid']}", headers=other).status_code == 404
    assert client.post(f"/api/v1/experiments/{populated['exp']}/approve", headers=other).status_code == 404


def test_viewer_member_is_read_only(client, users, populated):
    V, aid = users["viewer"]["h"], populated["aid"]
    for res in LISTS:
        assert client.get(f"/api/v1/{res}?assessment_id={aid}", headers=V).status_code == 200
    assert client.get(f"/api/v1/architecture?assessment_id={aid}", headers=V).status_code == 200
    assert client.get(f"/api/v1/reports/{populated['report']}/html", headers=V).status_code == 200
    assert client.post(f"/api/v1/assessments/{aid}/scope-check", headers=V, json={"value": "example.test"}).status_code == 200
    # write attempts: global viewer role blocks first (403 forbidden) -- either way never succeeds
    for r in (client.post("/api/v1/assets", headers=V, json={"assessment_id": aid, "asset_type": "domain", "value": "z.example.test"}),
              client.post(f"/api/v1/assessments/{aid}/collect", headers=V, json={"hosts": ["example.test"]})):
        assert r.status_code == 403


def test_assessment_permission_is_capped_by_global_role(client, users, new_user, populated):
    """Global viewer granted 'approver' on the assessment is still only a viewer."""
    gv = new_user("globalviewer", "viewer")
    aid = populated["aid"]
    assert client.put(f"/api/v1/assessments/{aid}/members/{gv['id']}", headers=users["admin"]["h"], json={"permission": "approver"}).status_code == 200
    assert client.get(f"/api/v1/assessments/{aid}", headers=gv["h"]).status_code == 200
    assert client.post(f"/api/v1/assessments/{aid}/hypotheses/generate", headers=gv["h"]).status_code == 403


def test_analyst_member_limited_by_assessment_permission(client, users, new_user, populated):
    """Global analyst with only 'viewer' on THIS assessment can read but not write (403 insufficient_assessment_permission)."""
    carol = new_user("carol", "analyst")
    aid = populated["aid"]
    client.put(f"/api/v1/assessments/{aid}/members/{carol['id']}", headers=users["admin"]["h"], json={"permission": "viewer"})
    assert client.get(f"/api/v1/hypotheses?assessment_id={aid}", headers=carol["h"]).json()["meta"]["total"] > 0
    r = client.post(f"/api/v1/assessments/{aid}/hypotheses/generate", headers=carol["h"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "insufficient_assessment_permission"
    r = client.post("/api/v1/assets", headers=carol["h"], json={"assessment_id": aid, "asset_type": "domain", "value": "q.example.test"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "insufficient_assessment_permission"
    client.put(f"/api/v1/assessments/{aid}/members/{carol['id']}", headers=users["admin"]["h"], json={"permission": "analyst"})
    assert client.post("/api/v1/assets", headers=carol["h"], json={"assessment_id": aid, "asset_type": "domain", "value": "q.example.test"}).status_code == 201
    # analyst-level members still cannot change scope or approve
    assert client.post("/api/v1/scope-rules", headers=carol["h"], json={"assessment_id": aid, "rule_type": "include", "match_type": "domain", "value": "evil.test"}).status_code == 403


def test_approval_needs_assessment_level_approver(client, users, new_user, populated):
    """A global approver who is only an 'analyst' member cannot approve/reject/confirm on this assessment."""
    ap = new_user("approver4", "approver")
    aid, eid = populated["aid"], populated["exp"]
    client.put(f"/api/v1/assessments/{aid}/members/{ap['id']}", headers=users["admin"]["h"], json={"permission": "analyst"})
    client.post(f"/api/v1/experiments/{eid}/submit", headers=users["analyst"]["h"])
    r = client.post(f"/api/v1/experiments/{eid}/approve", headers=ap["h"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "insufficient_assessment_permission"
    assert client.post(f"/api/v1/findings/{populated['finding']}/classify", headers=ap["h"],
                       json={"classification": "confirmed_vulnerability", "rationale": "r"}).status_code == 403
    assert client.post(f"/api/v1/experiments/{eid}/approve", headers=users["approver"]["h"]).status_code == 200


def test_membership_management_rules(client, users, new_user, populated):
    aid, owner, adm = populated["aid"], users["analyst"], users["admin"]
    dan = new_user("dan", "analyst")
    # a mere analyst-member cannot manage members; owner can; admin can
    client.put(f"/api/v1/assessments/{aid}/members/{dan['id']}", headers=owner["h"], json={"permission": "analyst"})
    erin = new_user("erin", "analyst")
    assert client.put(f"/api/v1/assessments/{aid}/members/{erin['id']}", headers=dan["h"], json={"permission": "viewer"}).status_code == 403
    assert client.put(f"/api/v1/assessments/{aid}/members/{erin['id']}", headers=users["approver"]["h"], json={"permission": "viewer"}).status_code == 200   # assessment approver may
    assert client.put(f"/api/v1/assessments/{aid}/members/{erin['id']}", headers=adm["h"], json={"permission": "bogus"}).status_code == 422
    # owner is immutable
    assert client.put(f"/api/v1/assessments/{aid}/members/{owner['id']}", headers=adm["h"], json={"permission": "viewer"}).json()["error"]["code"] == "owner_immutable"
    assert client.delete(f"/api/v1/assessments/{aid}/members/{owner['id']}", headers=adm["h"]).status_code == 409
    listing = client.get(f"/api/v1/assessments/{aid}/members", headers=owner["h"]).json()["data"]
    assert {m["username"] for m in listing} >= {"dan", "erin", "approver1", "viewer1"}
    # removal revokes access immediately
    assert client.get(f"/api/v1/assessments/{aid}", headers=erin["h"]).status_code == 200
    assert client.delete(f"/api/v1/assessments/{aid}/members/{erin['id']}", headers=adm["h"]).status_code == 204
    assert client.get(f"/api/v1/assessments/{aid}", headers=erin["h"]).status_code == 404
    assert client.get(f"/api/v1/auth/users/lookup?username=dan", headers=owner["h"]).json()["data"]["id"] == dan["id"]


def test_admin_bypasses_and_owner_has_access(client, users, populated):
    aid = populated["aid"]
    assert client.get(f"/api/v1/assessments/{aid}", headers=users["admin"]["h"]).status_code == 200
    assert client.get("/api/v1/assessments", headers=users["admin"]["h"]).json()["meta"]["total"] == 1
    assert client.patch(f"/api/v1/assessments/{aid}", headers=users["analyst"]["h"], json={"name": "renamed"}).json()["data"]["name"] == "renamed"
    assert client.post(f"/api/v1/assessments/{aid}/status", headers=users["analyst"]["h"], json={"status": "paused"}).status_code == 403   # global role


def test_target_access(client, users, new_user, world):
    tid = world["target"]["id"]
    bob = new_user("bob", "analyst")
    assert client.get(f"/api/v1/targets/{tid}", headers=bob["h"]).status_code == 404
    assert client.patch(f"/api/v1/targets/{tid}", headers=bob["h"], json={"description": "x"}).status_code == 404
    assert client.post("/api/v1/assessments", headers=bob["h"], json={"target_id": tid, "name": "sneaky"}).status_code == 404
    # assessment members can SEE the target but only its creator/admin may modify it
    assert client.get(f"/api/v1/targets/{tid}", headers=users["viewer"]["h"]).status_code == 200
    assert client.patch(f"/api/v1/targets/{tid}", headers=users["approver"]["h"], json={"description": "x"}).status_code == 403
    assert client.patch(f"/api/v1/targets/{tid}", headers=users["admin"]["h"], json={"description": "ok"}).status_code == 200
    # editing the authorization record needs approver+ even for the creator
    r = client.patch(f"/api/v1/targets/{tid}", headers=users["analyst"]["h"], json={"authorization_valid_until": "2099-01-01T00:00:00Z"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "authorization_edit_forbidden"
    assert client.patch(f"/api/v1/targets/{tid}", headers=users["analyst"]["h"], json={"description": "mine"}).status_code == 200


def test_denials_are_audited(client, users, new_user, populated):
    bob = new_user("bob", "analyst")
    client.get(f"/api/v1/assessments/{populated['aid']}", headers=bob["h"])
    client.post(f"/api/v1/assessments/{populated['aid']}/hypotheses/generate", headers=bob["h"])
    rows = client.get("/api/v1/auth/audit-logs?action=access_denied&outcome=denied", headers=users["admin"]["h"]).json()["data"]
    assert len(rows) >= 2 and all(r["actor_id"] == bob["id"] for r in rows)
    assert client.get("/api/v1/auth/audit-logs", headers=bob["h"]).status_code == 403
