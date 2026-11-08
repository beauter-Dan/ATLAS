from app.services.reporting import render_html

SRC = {"app/main.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.post("/orders/{id}/cancel")\ndef c(id): ...\n'}
SQL = "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT);\nCREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id));"


def test_auth_rbac_errors_pagination(client, users, world):
    assert client.get("/api/v1/targets").status_code == 401
    assert client.get("/api/v1/targets", headers=users["viewer"]["h"]).status_code == 200
    r = client.post("/api/v1/targets", headers=users["viewer"]["h"], json={"name": "x", "base_domain": "x.test"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    r = client.post("/api/v1/targets", headers=users["analyst"]["h"], json={"base_domain": "x"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    assert client.get("/api/v1/targets/none", headers=users["viewer"]["h"]).json()["error"]["code"] == "not_found"
    t = client.get("/api/v1/targets", headers=users["viewer"]["h"]).json()
    assert t["meta"]["total"] == 1 and "credentials_encrypted" not in t["data"][0]       # secrets never returned
    assert client.get("/api/v1/targets?name=nomatch", headers=users["viewer"]["h"]).json()["meta"]["total"] == 0
    assert client.get("/api/v1/targets?sort=bogus", headers=users["viewer"]["h"]).status_code == 422
    assert client.post("/api/v1/auth/users", headers=users["analyst"]["h"], json={"username": "n", "password": "p" * 12}).status_code == 403


def test_login(client, users):
    r = client.post("/api/v1/auth/login", json={"username": "admin1", "password": users["admin"]["password"]})
    assert r.status_code == 200
    tok = r.json()["data"]["access_token"]
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).json()["data"]["role"] == "admin"
    assert client.post("/api/v1/auth/login", json={"username": "admin1", "password": "bad"}).status_code == 401


def test_activation_requires_authorization(client, users):
    H = users["analyst"]["h"]
    t = client.post("/api/v1/targets", headers=H, json={"name": "noauth", "base_domain": "n.test"}).json()["data"]
    a = client.post("/api/v1/assessments", headers=H, json={"target_id": t["id"], "name": "x"}).json()["data"]
    r = client.post(f"/api/v1/assessments/{a['id']}/status", headers=users["admin"]["h"], json={"status": "active"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "authorization_required"


def test_collection_respects_scope(client, users, world, fake):
    H, aid = users["analyst"]["h"], world["aid"]
    r = client.post(f"/api/v1/assessments/{aid}/collect", headers=H,
                    json={"hosts": ["example.test", "admin.example.test", "other-corp.test"]}).json()["data"]
    assert [c["host"] for c in r["collected"]] == ["example.test"] and not r["errors"]
    assert {s["host"] for s in r["skipped"]} == {"admin.example.test", "other-corp.test"}
    assert not any("admin.example.test" in c or "other-corp" in c for c in fake.calls)       # never touched
    assets = {a["value"]: a for a in client.get(f"/api/v1/assets?assessment_id={aid}&page_size=200", headers=H).json()["data"]}
    assert assets["admin.example.test"]["scope_state"] == "excluded"                          # discovered via CT, excluded by rule
    assert assets["203.0.113.10"]["scope_state"] == "discovered"                             # never auto-authorized
    assert assets["cdn.thirdparty.test"]["scope_state"] == "discovered"
    obs = client.get(f"/api/v1/observations?assessment_id={aid}&page_size=200", headers=H).json()["data"]
    assert obs and all(o["evidence_id"] for o in obs)
    techs = {t["name"].lower() for t in client.get(f"/api/v1/technologies?assessment_id={aid}", headers=H).json()["data"]}
    assert {"nginx", "express", "jquery"} <= techs
    assert client.get(f"/api/v1/apis?assessment_id={aid}", headers=H).json()["meta"]["total"] == 2


def test_collection_blocked_when_paused(client, users, world, fake):
    aid = world["aid"]
    client.post(f"/api/v1/assessments/{aid}/status", headers=users["approver"]["h"], json={"status": "paused"})
    r = client.post(f"/api/v1/assessments/{aid}/collect", headers=users["analyst"]["h"], json={"hosts": ["example.test"]}).json()["data"]
    assert r["collected"] == [] and not fake.calls
    r = client.post(f"/api/v1/assessments/{aid}/internal/source", headers=users["analyst"]["h"], json={"label": "app", "files": SRC})
    assert r.status_code == 403 and r.json()["error"]["code"] == "scope_violation"


def test_full_pipeline(client, users, world, fake):
    A, P, aid = users["analyst"]["h"], users["approver"]["h"], world["aid"]
    client.post(f"/api/v1/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"]})
    assert client.post(f"/api/v1/assessments/{aid}/internal/source", headers=A, json={"label": "shop-app", "files": SRC}).status_code == 200
    s = client.post(f"/api/v1/assessments/{aid}/internal/schema", headers=A, json={"name": "shop", "sql": SQL}).json()["data"]
    assert s["technology"] == "postgresql"
    tables = client.get(f"/api/v1/databases/{s['schema_id']}/tables", headers=A).json()["data"]
    assert {t["name"] for t in tables} == {"users", "orders"}
    arch = client.post(f"/api/v1/assessments/{aid}/architecture/build", headers=A).json()["data"]
    assert arch["new_relationships"] > 0 and all(e["evidence_id"] and e["confidence"] for e in arch["edges"])
    assert arch["trust_boundaries"] and client.get(f"/api/v1/architecture?assessment_id={aid}", headers=A).status_code == 200
    gr = client.post(f"/api/v1/assessments/{aid}/hypotheses/generate", headers=A); assert gr.status_code == 200, gr.text; g = gr.json()["data"]
    assert g["created"] >= 3
    again = client.post(f"/api/v1/assessments/{aid}/hypotheses/generate", headers=A).json()["data"]
    assert again["created"] == 0
    hyps = client.get(f"/api/v1/hypotheses?assessment_id={aid}&page_size=200", headers=A).json()["data"]
    assert all(h["supporting_evidence_ids"] and h["safe_validation_approach"] and h["missing_evidence"] is not None for h in hyps)
    hyp = hyps[0]

    # --- experiments
    body = {"assessment_id": aid, "hypothesis_id": hyp["id"], "experiment_type": "header_review",
            "parameters": {"url": "https://example.test/", "headers_of_interest": ["X-Frame-Options", "Content-Security-Policy"]},
            "synthetic_data": {"email": "user@example.test"}, "rollback_plan": "Read-only; discard results", "max_requests": 1}
    bad = {**body, "parameters": {"url": "https://admin.example.test/", "headers_of_interest": ["x"]}}
    assert client.post("/api/v1/experiments", headers=A, json=bad).json()["error"]["code"] == "scope_violation"
    assert client.post("/api/v1/experiments", headers=A, json={**body, "rollback_plan": " "}).json()["error"]["code"] == "rollback_required"
    assert client.post("/api/v1/experiments", headers=A, json={**body, "synthetic_data": {"email": "real@gmail.com"}}).json()["error"]["code"] == "unsafe_synthetic_data"
    assert client.post("/api/v1/experiments", headers=A, json={**body, "parameters": {**body["parameters"], "method": "POST"}}).status_code == 422
    assert client.post("/api/v1/experiments", headers=A, json={**body, "parameters": {**body["parameters"], "authorization": "x"}}).status_code == 422
    e = client.post("/api/v1/experiments", headers=A, json=body).json()["data"]
    eid = e["id"]
    assert client.post(f"/api/v1/experiments/{eid}/run", headers=A).json()["error"]["code"] == "approval_required"
    client.post(f"/api/v1/experiments/{eid}/submit", headers=A)
    assert client.post(f"/api/v1/experiments/{eid}/approve", headers=A).status_code == 403            # analyst cannot approve
    assert client.post(f"/api/v1/experiments/{eid}/run", headers=A).json()["error"]["code"] == "approval_required"
    assert client.post(f"/api/v1/experiments/{eid}/approve", headers=P).status_code == 200
    r = client.post(f"/api/v1/experiments/{eid}/run", headers=A).json()["data"]
    assert r["status"] == "completed" and "x-frame-options" in r["result"]["present"] and "content-security-policy" in r["result"]["absent"]
    assert client.post(f"/api/v1/experiments/{eid}/run", headers=A).status_code == 409

    # --- findings
    ev_id = r["result"]["evidence_id"]
    f = client.post("/api/v1/findings", headers=A, json={"assessment_id": aid, "hypothesis_id": hyp["id"], "title": "Missing CSP",
                                                          "classification": "potential_vulnerability", "evidence_ids": [ev_id], "severity": "low"})
    assert f.status_code == 201, f.text
    fid = f.json()["data"]["id"]
    assert client.post("/api/v1/findings", headers=A, json={"assessment_id": aid, "title": "t", "classification": "confirmed_vulnerability",
                                                             "evidence_ids": [ev_id]}).status_code == 422
    assert client.post(f"/api/v1/findings/{fid}/classify", headers=A, json={"classification": "confirmed_vulnerability", "rationale": "r"}).status_code == 403
    assert client.post(f"/api/v1/findings/{fid}/classify", headers=P, json={"classification": "confirmed_vulnerability", "rationale": "r"}).json()["error"]["code"] == "verified_evidence_required"
    assert client.post(f"/api/v1/evidence/{ev_id}/verify", headers=A, json={}).status_code == 200
    ok = client.post(f"/api/v1/findings/{fid}/classify", headers=P, json={"classification": "confirmed_vulnerability", "rationale": "Header absent per verified evidence", "severity": "low"})
    assert ok.status_code == 200, ok.text
    assert client.post(f"/api/v1/findings/{fid}/classify", headers=P, json={"classification": "false_positive"}).status_code == 422
    kinds = {o["kind"] for o in client.get(f"/api/v1/observations?assessment_id={aid}&page_size=200", headers=A).json()["data"]}
    assert "confirmed" in kinds

    # --- rollback + report + audit
    assert client.post(f"/api/v1/experiments/{eid}/rollback", headers=A).json()["data"]["status"] == "rolled_back"
    rep = client.post(f"/api/v1/assessments/{aid}/reports", headers=A).json()["data"]
    c = rep["content"]
    assert len(c["findings"]["confirmed_vulnerability"]) == 1 and "credentials" not in str(c["target"]).lower()
    assert client.get(f"/api/v1/reports/{rep['id']}/html", headers=A).status_code == 200
    acts = {x["action"] for x in client.get(f"/api/v1/auth/audit-logs?assessment_id={aid}&page_size=500", headers=users["admin"]["h"]).json()["data"]}
    assert {"experiment.approve", "experiment.run", "finding.classify", "collect", "report.generate"} <= acts
    denied = [x for x in client.get(f"/api/v1/auth/audit-logs?assessment_id={aid}&outcome=denied&page_size=500", headers=users["admin"]["h"]).json()["data"]]
    assert any(x["action"] == "scope_decision" for x in denied)


def test_separation_of_duties(client, users, world, fake):
    body = {"assessment_id": world["aid"], "experiment_type": "http_status_check", "parameters": {"url": "https://example.test/"},
            "rollback_plan": "n/a"}
    e = client.post("/api/v1/experiments", headers=users["approver"]["h"], json=body).json()["data"]
    client.post(f"/api/v1/experiments/{e['id']}/submit", headers=users["approver"]["h"])
    r = client.post(f"/api/v1/experiments/{e['id']}/approve", headers=users["approver"]["h"])
    assert r.json()["error"]["code"] == "separation_of_duties"
    assert client.post(f"/api/v1/experiments/{e['id']}/approve", headers=users["approver2"]["h"]).status_code == 200


def test_experiment_scope_rechecked_at_run(client, users, world, fake):
    A = users["analyst"]["h"]
    body = {"assessment_id": world["aid"], "experiment_type": "http_status_check", "parameters": {"url": "https://example.test/"}, "rollback_plan": "n/a"}
    e = client.post("/api/v1/experiments", headers=A, json=body).json()["data"]
    client.post(f"/api/v1/experiments/{e['id']}/submit", headers=A)
    client.post(f"/api/v1/experiments/{e['id']}/approve", headers=users["approver"]["h"])
    client.post(f"/api/v1/assessments/{world['aid']}/status", headers=users["approver"]["h"], json={"status": "paused"})
    assert client.post(f"/api/v1/experiments/{e['id']}/run", headers=A).json()["error"]["code"] == "scope_violation"
    assert not fake.calls


def test_rate_limit_and_evidence_rules(client, users, world, monkeypatch):
    from app.core.config import get_settings
    A = users["analyst"]["h"]
    assert client.post("/api/v1/hypotheses", headers=A, json={"assessment_id": world["aid"], "category": "c", "title": "t", "reasoning": "r",
                                                               "supporting_evidence_ids": [], "safe_validation_approach": "s"}).status_code == 422
    assert client.post("/api/v1/hypotheses", headers=A, json={"assessment_id": world["aid"], "category": "c", "title": "t", "reasoning": "r",
                                                               "supporting_evidence_ids": ["nope"], "safe_validation_approach": "s"}).json()["error"]["code"] == "unknown_evidence"
    o = client.post("/api/v1/observations", headers=A, json={"assessment_id": world["aid"], "category": "manual_note", "description": "Seen in docs",
                                                              "evidence_reference": "doc://runbook#3"}).json()["data"]
    assert o["evidence_id"] and o["verification_status"] == "unverified"
    assert client.post("/api/v1/observations", headers=A, json={"assessment_id": world["aid"], "category": "x", "description": "d",
                                                                 "kind": "confirmed", "evidence_reference": "r"}).status_code == 422
    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 3)
    codes = [client.get("/api/v1/health", headers={"Authorization": "Bearer rl-test"}).status_code for _ in range(5)]
    assert codes[-1] == 429
