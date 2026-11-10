import json
URL = "/api/v1"


def summary(client, h):
    r = client.get(f"{URL}/dashboard/summary", headers=h)
    assert r.status_code == 200, r.text
    return r.json()["data"]


def prog(d, aid):
    return next(p for p in d["assessment_progress"] if p["id"] == aid)


def test_requires_authentication(client):
    assert client.get(f"{URL}/dashboard/summary").status_code == 401


def test_shape_and_access_filtering(client, users, new_user, world):
    d = summary(client, users["viewer"]["h"])
    assert set(d) == {"targets", "active_assessments", "assets", "technologies", "pending_hypotheses", "confirmed_findings",
                      "assessment_progress", "recent_activity"}
    assert d["targets"] == 1 and d["active_assessments"] == 1
    stranger = summary(client, new_user("bob", "analyst")["h"])
    assert stranger["targets"] == 0 and stranger["active_assessments"] == 0 and stranger["assessment_progress"] == [] and stranger["recent_activity"] == []
    adm = summary(client, users["admin"]["h"])
    assert adm["targets"] == 1 and len(adm["assessment_progress"]) == 1


def test_progress_reflects_real_workflow_stages(client, users, world, fake):
    A, P, aid = users["analyst"]["h"], users["approver"]["h"], world["aid"]
    assert prog(summary(client, A), aid)["percent"] == round(100 * 2 / 7)               # scope defined + activated
    client.post(f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"]})
    assert prog(summary(client, A), aid)["percent"] == round(100 * 3 / 7)
    client.post(f"{URL}/assessments/{aid}/internal/source", headers=A, json={"label": "a", "files": {"m.py": '@app.post("/o/{id}")\ndef f(id): ...\n'}})
    client.post(f"{URL}/assessments/{aid}/hypotheses/generate", headers=A)
    d = summary(client, A)
    assert prog(d, aid)["percent"] == round(100 * 4 / 7) and d["pending_hypotheses"] > 0
    e = client.post(f"{URL}/experiments", headers=A, json={"assessment_id": aid, "experiment_type": "http_status_check", "parameters": {"url": "https://example.test/"}, "rollback_plan": "n/a"}).json()["data"]
    client.post(f"{URL}/experiments/{e['id']}/submit", headers=A); client.post(f"{URL}/experiments/{e['id']}/approve", headers=P)
    client.post(f"{URL}/experiments/{e['id']}/run", headers=A)
    assert prog(summary(client, A), aid)["percent"] == round(100 * 5 / 7)
    ev = client.get(f"{URL}/evidence?assessment_id={aid}", headers=A).json()["data"][0]["id"]
    client.post(f"{URL}/findings", headers=A, json={"assessment_id": aid, "title": "t", "classification": "informational_observation", "evidence_ids": [ev]})
    client.post(f"{URL}/assessments/{aid}/reports", headers=A)
    assert prog(summary(client, A), aid)["percent"] == 100
    d = summary(client, A)
    assert d["confirmed_findings"] == 0 and d["assets"] > 0 and d["technologies"] > 0


def test_activity_feed_is_coarse_and_access_filtered(client, users, new_user, world, fake):
    A = users["analyst"]["h"]
    client.post(f"{URL}/assessments/{world['aid']}/collect", headers=A, json={"hosts": ["example.test", "admin.example.test"]})
    feed = summary(client, users["viewer"]["h"])["recent_activity"]
    assert feed and any(f["message"].startswith("Data collection ran") and "Q1" in f["message"] for f in feed)
    blob = json.dumps(feed)
    assert users["analyst"]["id"] not in blob and "admin.example.test" not in blob and "scope" not in blob.lower()
    assert all(set(f) == {"id", "timestamp", "message"} for f in feed)
    assert summary(client, new_user("bob", "analyst")["h"])["recent_activity"] == []


def test_role_denials_are_audited(client, users):
    r = client.post(f"{URL}/targets", headers=users["viewer"]["h"], json={"name": "x", "base_domain": "x.test"})
    assert r.status_code == 403
    rows = client.get(f"{URL}/auth/audit-logs?action=role_denied", headers=users["admin"]["h"]).json()["data"]
    assert rows and rows[0]["actor_id"] == users["viewer"]["id"] and rows[0]["outcome"] == "denied"
    assert rows[0]["details"] == {"needed_role": "analyst", "role": "viewer", "method": "POST", "path": "/api/v1/targets"}


def test_target_organization_round_trip(client, users):
    A = users["analyst"]["h"]
    t = client.post(f"{URL}/targets", headers=A, json={"name": "Org Co", "base_domain": "org.test", "organization": "Example Org Ltd"}).json()["data"]
    assert t["organization"] == "Example Org Ltd"
    assert client.patch(f"{URL}/targets/{t['id']}", headers=A, json={"organization": "Renamed Ltd"}).json()["data"]["organization"] == "Renamed Ltd"
    assert client.post(f"{URL}/targets", headers=A, json={"name": "Long", "base_domain": "l.test", "organization": "o" * 201}).status_code == 422
