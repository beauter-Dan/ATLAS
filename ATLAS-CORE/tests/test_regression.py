"""API regression: envelope, CORS, headers, limits, startup safety, rollback behaviour."""
import json
import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import app

URL = "/api/v1"


def test_uniform_error_envelope_for_every_status(client, users, world):
    A = users["analyst"]["h"]
    cases = {401: client.get(f"{URL}/targets"), 403: client.get(f"{URL}/auth/audit-logs", headers=A),
             404: client.get(f"{URL}/targets/nope", headers=A), 405: client.put(f"{URL}/health"),
             422: client.post(f"{URL}/targets", headers=A, json={}), 409: client.post(f"{URL}/targets", headers=A, json={"name": "Synthetic Corp", "base_domain": "x.test"})}
    for status, r in cases.items():
        assert r.status_code == status, (status, r.status_code)
        e = r.json()["error"]
        assert set(e) == {"code", "message", "details"} and isinstance(e["code"], str) and e["code"], status


def test_422_does_not_echo_submitted_values(client, users):
    r = client.post(f"{URL}/auth/login", json={"username": 5, "password": "TopSecretPassw0rd!"})
    assert r.status_code == 422 and "TopSecretPassw0rd" not in r.text


def test_cors_allows_only_configured_origins(client):
    ok = client.options(f"{URL}/targets", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
    assert ok.status_code == 200 and ok.headers["access-control-allow-origin"] == "http://localhost:5173" and "authorization" in ok.headers["access-control-allow-headers"].lower()
    bad = client.options(f"{URL}/targets", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers
    assert "access-control-allow-credentials" not in ok.headers          # tokens travel in headers, never cookies


def test_security_headers_present(client):
    r = client.get(f"{URL}/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"


def test_request_size_limits(client, users, world):
    A = users["analyst"]["h"]
    big = {"label": "x", "files": {"a.py": "a" * 5_000_001}}
    assert client.post(f"{URL}/assessments/{world['aid']}/internal/source", headers=A, json=big).status_code == 422
    many = {"label": "x", "files": {f"f{i}.py": "x" for i in range(2001)}}
    assert client.post(f"{URL}/assessments/{world['aid']}/internal/source", headers=A, json=many).status_code == 422
    assert client.post(f"{URL}/assessments/{world['aid']}/collect", headers=A, json={"hosts": ["a.example.test"] * 101}).status_code == 422
    assert client.post(f"{URL}/assessments/{world['aid']}/collect", headers=A, json={"hosts": ["example.test"], "collectors": ["nmap"]}).status_code == 422


def test_production_refuses_default_secret():
    with pytest.raises(RuntimeError):
        Settings(env="production", secret_key="change-me").validate_for_runtime()
    Settings(env="production", secret_key="x" * 40).validate_for_runtime()


def test_malformed_json_and_wrong_types(client, users):
    A = {**users["analyst"]["h"], "Content-Type": "application/json"}
    assert client.post(f"{URL}/targets", headers=A, content=b"{not json").status_code == 422
    assert client.get(f"{URL}/targets?page=abc", headers=users["analyst"]["h"]).status_code == 422


def test_confirmed_kind_cannot_be_forged_through_api(client, users, world):
    A, aid = users["analyst"]["h"], world["aid"]
    r = client.post(f"{URL}/observations", headers=A, json={"assessment_id": aid, "category": "c", "description": "d", "kind": "confirmed", "evidence_reference": "r"})
    assert r.status_code == 422
    r = client.post(f"{URL}/findings", headers=A, json={"assessment_id": aid, "title": "t", "classification": "confirmed_vulnerability", "evidence_ids": []})
    assert r.status_code == 422


def test_failed_collector_does_not_leave_partial_data(client, users, world, fake):
    def boom(h, port=443):
        raise TimeoutError("tls timed out")
    fake.tls = boom
    A, aid = users["analyst"]["h"], world["aid"]
    r = client.post(f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"], "collectors": ["rdap", "dns", "tls"]}).json()["data"]
    assert r["collected"] == [] and "TimeoutError" in r["errors"][0]["error"]
    assert client.get(f"{URL}/evidence?assessment_id={aid}", headers=A).json()["meta"]["total"] == 0
    fake.tls = lambda h, port=443: {"protocol": "TLSv1.3", "cipher": "c", "issuer": "i", "subject": "s", "not_after": "x", "not_before": "x", "san": [], "verified": True, "verify_error": None}
    r = client.post(f"{URL}/assessments/{aid}/collect", headers=A, json={"hosts": ["example.test"], "collectors": ["rdap", "dns", "tls"]}).json()["data"]
    assert r["collected"] and not r["errors"]


def test_openapi_documents_new_security_surface():
    paths = app.openapi()["paths"]
    for p in ("auth/login", "auth/refresh", "auth/logout", "auth/logout-all", "auth/sessions", "auth/change-password", "auth/mfa/enroll", "auth/mfa/activate",
              "auth/mfa/disable", "auth/password-reset/request", "auth/password-reset/confirm", "auth/users", "assessments/{aid}/members",
              "assessments/{aid}/members/{uid}", "assessments/{aid}/collect/jobs", "assessments/{aid}/collect/jobs/{job_id}"):
        assert f"{URL}/{p}" in paths, p
