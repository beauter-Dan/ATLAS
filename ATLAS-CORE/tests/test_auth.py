import logging
from datetime import timedelta
import pytest
from sqlalchemy import select
from app.core.config import get_settings
from app.core.security import (hash_password, needs_rehash, totp_code, totp_verify, verify_password, hash_token, decrypt_secret)
from app.models import AuditLog, AuthSession, User
from app.services import auth as svc
from app.services.reset_delivery import ResetDelivery, set_delivery, NullDelivery

PW = "CorrectHorse-Battery9"


def login(client, u, pw=PW, **kw):
    return client.post("/api/v1/auth/login", json={"username": u, "password": pw, **kw})


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


# ---------------- hashing
def test_hash_format_and_legacy_rehash(client, db_session, users):
    h = hash_password("abc", iterations=1000)
    assert h.startswith("pbkdf2_sha256$1000$") and verify_password("abc", h) and not verify_password("abd", h)
    assert hash_password("abc", 1000) != h                      # unique salt
    # legacy milestone-1 format "salt$hash" (200k iterations) still verifies and is upgraded at next login
    import base64, hashlib, os
    salt = os.urandom(16)
    legacy = base64.b64encode(salt).decode() + "$" + base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"oldpw-oldpw-1", salt, 200_000)).decode()
    assert verify_password("oldpw-oldpw-1", legacy) and needs_rehash(legacy)
    u = db_session.get(User, users["viewer"]["id"]); u.password_hash = legacy; db_session.commit()
    assert login(client, "viewer1", "oldpw-oldpw-1").status_code == 200
    db_session.expire_all()
    assert db_session.get(User, users["viewer"]["id"]).password_hash.startswith("pbkdf2_sha256$")


def test_password_policy(client, users):
    A = users["admin"]["h"]
    for bad in ("short", "aaaaaaaaaaaaaaaa", "password1234", "newuser-newuser1"):
        r = client.post("/api/v1/auth/users", headers=A, json={"username": "newuser", "password": bad})
        assert r.status_code == 422 and r.json()["error"]["code"] == "weak_password", bad
    assert client.post("/api/v1/auth/users", headers=A, json={"username": "newuser", "password": "Tr0ub4dor&3-horse"}).status_code == 201


# ---------------- tokens
def test_login_response_never_contains_secrets(client, users):
    body = login(client, "admin1").text
    assert "password_hash" not in body and "pbkdf2" not in body
    assert '"refresh_token"' in body and '"access_token"' in body


def test_token_expiry_and_revocation(client, db_session, users):
    t = login(client, "analyst1").json()["data"]
    assert client.get("/api/v1/auth/me", headers=H(t["access_token"])).status_code == 200
    sess = db_session.scalar(select(AuthSession).where(AuthSession.access_hash == hash_token(t["access_token"])))
    sess.access_expires_at = svc.utcnow() - timedelta(seconds=1); db_session.commit()
    assert client.get("/api/v1/auth/me", headers=H(t["access_token"])).json()["error"]["code"] == "unauthorized"
    t2 = login(client, "analyst1").json()["data"]
    assert client.post("/api/v1/auth/logout", headers=H(t2["access_token"])).status_code == 204
    assert client.get("/api/v1/auth/me", headers=H(t2["access_token"])).status_code == 401           # revoked
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t2["refresh_token"]}).status_code == 401


def test_only_hashes_are_stored(client, db_session, users):
    t = login(client, "analyst1").json()["data"]
    row = db_session.scalar(select(AuthSession).where(AuthSession.user_id == users["analyst"]["id"], AuthSession.access_hash == hash_token(t["access_token"])))
    assert row and t["access_token"] not in (row.access_hash, row.refresh_hash)


def test_logout_all_and_deactivation(client, db_session, users):
    a, b = login(client, "analyst1").json()["data"], login(client, "analyst1").json()["data"]
    assert client.post("/api/v1/auth/logout-all", headers=H(a["access_token"])).json()["data"]["revoked"] >= 2
    assert client.get("/api/v1/auth/me", headers=H(b["access_token"])).status_code == 401
    c = login(client, "viewer1").json()["data"]
    r = client.patch(f"/api/v1/auth/users/{users['viewer']['id']}", headers=users["admin"]["h"], json={"is_active": False})
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers=H(c["access_token"])).status_code == 401
    assert login(client, "viewer1").status_code == 401


def test_refresh_rotation_and_reuse_detection(client, users):
    t = login(client, "analyst1").json()["data"]
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r1.status_code == 200
    n = r1.json()["data"]
    assert n["access_token"] != t["access_token"] and n["refresh_token"] != t["refresh_token"]
    assert client.get("/api/v1/auth/me", headers=H(t["access_token"])).status_code == 401          # old access dead
    assert client.get("/api/v1/auth/me", headers=H(n["access_token"])).status_code == 200
    # replaying the ROTATED-OUT refresh token = theft signal: whole session revoked
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401
    assert client.get("/api/v1/auth/me", headers=H(n["access_token"])).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": n["refresh_token"]}).status_code == 401


def test_refresh_expiry(client, db_session, users):
    t = login(client, "analyst1").json()["data"]
    s = db_session.scalar(select(AuthSession).where(AuthSession.refresh_hash == hash_token(t["refresh_token"])))
    s.refresh_expires_at = svc.utcnow() - timedelta(seconds=1); db_session.commit()
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401


# ---------------- login protection
def test_lockout_after_repeated_failures(client, db_session, users):
    get_settings().max_failed_logins = 3
    for _ in range(3):
        assert login(client, "analyst1", "wrong-password-1").json()["error"]["code"] == "invalid_credentials"
    r = login(client, "analyst1")                                          # correct password, but locked
    assert r.status_code == 429 and r.json()["error"]["code"] == "account_locked"
    u = db_session.get(User, users["analyst"]["id"]); u.locked_until = svc.utcnow() - timedelta(seconds=1); db_session.commit()
    assert login(client, "analyst1").status_code == 200                    # lock expired
    db_session.expire_all()
    assert db_session.get(User, users["analyst"]["id"]).failed_login_count == 0


def test_unknown_user_is_indistinguishable(client, users):
    a, b = login(client, "nobody-here", "x" * 14), login(client, "analyst1", "x" * 14)
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_failures_are_audited_without_passwords(client, db_session, users):
    login(client, "analyst1", "SuperSecretWrong-123")
    rows = db_session.scalars(select(AuditLog).where(AuditLog.action == "auth.login", AuditLog.outcome == "denied")).all()
    assert rows and "SuperSecretWrong-123" not in str([r.details for r in rows])


# ---------------- change / reset
def test_change_password_revokes_other_sessions(client, users):
    a, b = login(client, "analyst1").json()["data"], login(client, "analyst1").json()["data"]
    r = client.post("/api/v1/auth/change-password", headers=H(a["access_token"]), json={"current_password": "nope-nope-nope1", "new_password": "An0ther-Strong-pw!"})
    assert r.status_code == 401
    r = client.post("/api/v1/auth/change-password", headers=H(a["access_token"]), json={"current_password": PW, "new_password": "weak"})
    assert r.status_code == 422
    r = client.post("/api/v1/auth/change-password", headers=H(a["access_token"]), json={"current_password": PW, "new_password": "An0ther-Strong-pw!"})
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers=H(a["access_token"])).status_code == 200      # current session kept
    assert client.get("/api/v1/auth/me", headers=H(b["access_token"])).status_code == 401      # others revoked
    assert login(client, "analyst1").status_code == 401 and login(client, "analyst1", "An0ther-Strong-pw!").status_code == 200


def test_admin_issued_reset_is_single_use_and_expires(client, db_session, users):
    r = client.post(f"/api/v1/auth/users/{users['viewer']['id']}/password-reset", headers=users["admin"]["h"])
    tok = r.json()["data"]["reset_token"]
    assert client.post(f"/api/v1/auth/users/{users['viewer']['id']}/password-reset", headers=users["analyst"]["h"]).status_code == 403
    old = login(client, "viewer1").json()["data"]
    bad = client.post("/api/v1/auth/password-reset/confirm", json={"token": tok, "new_password": "weak"})
    assert bad.status_code == 422
    ok = client.post("/api/v1/auth/password-reset/confirm", json={"token": tok, "new_password": "Brand-New-Passw0rd"})
    assert ok.status_code == 200
    assert client.get("/api/v1/auth/me", headers=H(old["access_token"])).status_code == 401   # sessions revoked
    assert client.post("/api/v1/auth/password-reset/confirm", json={"token": tok, "new_password": "Brand-New-Passw0rd2"}).status_code == 400
    assert login(client, "viewer1", "Brand-New-Passw0rd").status_code == 200
    tok2 = client.post(f"/api/v1/auth/users/{users['viewer']['id']}/password-reset", headers=users["admin"]["h"]).json()["data"]["reset_token"]
    from app.models import PasswordResetToken
    row = db_session.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(tok2)))
    assert tok2 not in (row.token_hash,)                                                         # stored hashed
    row.expires_at = svc.utcnow() - timedelta(seconds=1); db_session.commit()
    assert client.post("/api/v1/auth/password-reset/confirm", json={"token": tok2, "new_password": "Brand-New-Passw0rd3"}).status_code == 400


def test_self_service_reset_does_not_leak_existence_and_uses_delivery(client, users):
    got = {}

    class Capture(ResetDelivery):
        def deliver(self, username, token):
            got[username] = token
    set_delivery(Capture())
    try:
        a = client.post("/api/v1/auth/password-reset/request", json={"username": "viewer1"})
        b = client.post("/api/v1/auth/password-reset/request", json={"username": "ghost-user"})
        assert a.status_code == b.status_code == 202 and a.json() == b.json()
        assert "viewer1" in got and "ghost-user" not in got and got["viewer1"] not in a.text
        assert client.post("/api/v1/auth/password-reset/confirm", json={"token": got["viewer1"], "new_password": "Reset-Via-Delivery9"}).status_code == 200
    finally:
        set_delivery(NullDelivery())


# ---------------- MFA
def test_totp_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # ASCII "12345678901234567890"
    assert totp_code(secret, 59) == "287082" and totp_code(secret, 1111111109) == "081804"
    assert totp_verify(secret, "287082", t=59) is not None and totp_verify(secret, "000000", t=59) is None
    step = totp_verify(secret, "287082", t=59)
    assert totp_verify(secret, "287082", last_step=step, t=59) is None            # replay blocked


def test_mfa_enrollment_login_and_replay(client, db_session, users):
    t = login(client, "analyst1").json()["data"]
    enr = client.post("/api/v1/auth/mfa/enroll", headers=H(t["access_token"])).json()["data"]
    assert enr["otpauth_uri"].startswith("otpauth://totp/") and enr["secret"] in enr["otpauth_uri"]
    db_session.expire_all()
    u = db_session.get(User, users["analyst"]["id"])
    assert enr["secret"] not in (u.mfa_secret_encrypted or "") and decrypt_secret(u.mfa_secret_encrypted) == enr["secret"]   # encrypted at rest
    db_session.rollback()      # end the read txn (SQLite would otherwise keep the file locked for the API)
    assert client.post("/api/v1/auth/mfa/activate", headers=H(t["access_token"]), json={"code": "000000"}).status_code == 401
    import time
    from app.core.security import totp_step, _hotp
    code = _hotp(enr["secret"], totp_step())
    assert client.post("/api/v1/auth/mfa/activate", headers=H(t["access_token"]), json={"code": code}).status_code == 200
    assert login(client, "analyst1").json()["error"]["code"] == "mfa_required"
    assert login(client, "analyst1", totp_code="123456").status_code == 401
    nxt = _hotp(enr["secret"], totp_step() + 1)                                    # next step (within window), unused
    ok = login(client, "analyst1", totp_code=nxt)
    assert ok.status_code == 200 and ok.json()["data"]["user"]["mfa_enabled"] is True
    assert login(client, "analyst1", totp_code=nxt).status_code == 401              # replay of the same code rejected
    r = client.post(f"/api/v1/auth/users/{users['analyst']['id']}/password-reset", headers=users["admin"]["h"])
    assert client.delete(f"/api/v1/auth/users/{users['analyst']['id']}/mfa", headers=users["admin"]["h"]).status_code == 204
    assert login(client, "analyst1").status_code == 200


# ---------------- secrets never leak
def test_credentials_never_in_responses_logs_audit_or_errors(client, db_session, users, world, caplog):
    secret = "s3cret-credential-value"
    A, ADM = users["analyst"]["h"], users["admin"]["h"]
    tid = world["target"]["id"]
    bodies = [client.get("/api/v1/targets", headers=A).text, client.get(f"/api/v1/targets/{tid}", headers=A).text,
              client.patch(f"/api/v1/targets/{tid}", headers=A, json={"credentials": "another-secret-123"}).text,
              client.post("/api/v1/targets", headers=A, json={"name": 5, "credentials": secret}).text,      # 422 must not echo input
              client.get("/api/v1/auth/audit-logs?page_size=500", headers=ADM).text]
    assert all(secret not in b and "credentials_encrypted" not in b and "another-secret-123" not in b for b in bodies)
    with caplog.at_level(logging.INFO):
        logging.getLogger("atlas.test").warning("connecting with password=hunter2hunter2 token=abcdef1234567890 to host")
    assert "hunter2hunter2" not in caplog.text and "abcdef1234567890" not in caplog.text
    from app.services.audit import audit
    audit(db_session, actor_id=None, action="x", resource_type="t", details={"password": "p1", "nested": {"api_key": "k1", "ok": 1}}, commit=True)
    row = db_session.scalar(select(AuditLog).where(AuditLog.action == "x"))
    assert row.details == {"password": "[REDACTED]", "nested": {"api_key": "[REDACTED]", "ok": 1}}


def test_ai_prompt_never_contains_credentials(client, db_session, users, world, fake):
    from app.ai import agents
    from app.ai.providers import AIProvider

    class Spy(AIProvider):
        name = "spy"
        def complete(self, system, prompt, ctx):
            self.prompt = system + prompt
            return '{"statements": []}'
    A = users["analyst"]["h"]
    client.post("/api/v1/observations", headers=A, json={"assessment_id": world["aid"], "category": "dns_records",
                "description": "config leak password=Sup3rSecretPw and key AKIAABCDEFGHIJKLMNOP for ops@corp.com", "evidence_reference": "doc://x"})
    spy = Spy()
    agents.run_agent(db_session, world["aid"], "reconnaissance", None, provider=spy)
    for needle in ("Sup3rSecretPw", "AKIAABCDEFGHIJKLMNOP", "ops@corp.com", "s3cret-credential-value"):
        assert needle not in spy.prompt
