"""Authentication: opaque revocable sessions, refresh rotation with reuse detection, lockout,
password policy, password reset, TOTP MFA. Credentials never reach logs, audit details or responses."""
import re
from datetime import datetime, timedelta, timezone
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.security import (decrypt_secret, dummy_hash, encrypt_secret, hash_password, hash_token, needs_rehash, new_token,
                               totp_new_secret, totp_uri, totp_verify, verify_password)
from app.models import AuthSession, PasswordResetToken, User
from app.services.audit import audit

COMMON = {"password1234", "passw0rd1234", "123456789012", "qwertyuiop12", "administrator", "letmein123456",
          "changeme1234", "welcome12345", "password12345", "iloveyou12345"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def validate_password(pw: str, username: str = "") -> None:
    problems = []
    if len(pw) < 12:
        problems.append("at least 12 characters")
    if len(pw) > 128:
        problems.append("at most 128 characters")
    if pw.lower() in COMMON or len(set(pw)) < 5:
        problems.append("not a common or repetitive password")
    if username and username.lower() in pw.lower():
        problems.append("must not contain the username")
    if problems:
        raise ApiError(422, "weak_password", "Password policy: " + "; ".join(problems))


def issue_session(db: Session, user: User, ip: str | None = None, ua: str | None = None) -> dict:
    s, now = get_settings(), utcnow()
    at, rt = new_token(), new_token()
    row = AuthSession(user_id=user.id, access_hash=hash_token(at), access_expires_at=now + timedelta(seconds=s.access_token_ttl_seconds),
                      refresh_hash=hash_token(rt), refresh_expires_at=now + timedelta(seconds=s.refresh_token_ttl_seconds),
                      ip=ip, user_agent=(ua or "")[:200])
    db.add(row)
    db.flush()
    return {"access_token": at, "refresh_token": rt, "token_type": "bearer", "expires_in": s.access_token_ttl_seconds, "session_id": row.id}


def authenticate(db: Session, token: str) -> tuple[User, AuthSession] | None:
    row = db.scalar(select(AuthSession).where(AuthSession.access_hash == hash_token(token)))
    if not row or row.revoked_at or aware(row.access_expires_at) <= utcnow():
        return None
    user = db.get(User, row.user_id)
    return (user, row) if user and user.is_active else None


def revoke_session(db: Session, session: AuthSession, reason: str) -> None:
    if not session.revoked_at:
        session.revoked_at, session.revoked_reason = utcnow(), reason


def revoke_all(db: Session, user_id: str, reason: str, except_session_id: str | None = None) -> int:
    q = update(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    if except_session_id:
        q = q.where(AuthSession.id != except_session_id)
    return db.execute(q.values(revoked_at=utcnow(), revoked_reason=reason)).rowcount


def _fail(db: Session, user: User, why: str, ip) -> None:
    s = get_settings()
    user.failed_login_count = (user.failed_login_count or 0) + 1
    locked = user.failed_login_count >= s.max_failed_logins
    if locked:
        user.locked_until = utcnow() + timedelta(seconds=s.lockout_seconds)
    audit(db, actor_id=user.id, action="auth.login", resource_type="user", resource_id=user.id, outcome="denied",
          details={"reason": why, "locked": locked, "ip": ip})
    db.commit()
    raise ApiError(401, "invalid_credentials", "Invalid credentials")


def login(db: Session, username: str, password: str, totp_code: str | None, ip: str | None, ua: str | None) -> dict:
    now = utcnow()
    user = db.scalar(select(User).where(User.username == username).with_for_update())
    if not user:
        verify_password(password, dummy_hash())  # equalize timing
        audit(db, actor_id=None, action="auth.login", resource_type="user", outcome="denied",
              details={"reason": "unknown_user", "ip": ip}, commit=True)
        raise ApiError(401, "invalid_credentials", "Invalid credentials")
    if user.locked_until and aware(user.locked_until) > now:
        wait = int((aware(user.locked_until) - now).total_seconds()) + 1
        audit(db, actor_id=user.id, action="auth.login", resource_type="user", resource_id=user.id, outcome="denied",
              details={"reason": "account_locked", "ip": ip}, commit=True)
        raise ApiError(429, "account_locked", "Too many failed attempts; try again later", {"retry_after_seconds": wait})
    if not (user.is_active and verify_password(password, user.password_hash)):
        _fail(db, user, "bad_password_or_inactive", ip)
    if user.mfa_enabled:
        if not totp_code:
            raise ApiError(401, "mfa_required", "A one-time code is required")
        step = totp_verify(decrypt_secret(user.mfa_secret_encrypted), totp_code, user.mfa_last_step)
        if step is None:
            _fail(db, user, "invalid_mfa", ip)
        user.mfa_last_step = step
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count, user.locked_until, user.last_login_at = 0, None, now
    tokens = issue_session(db, user, ip, ua)
    audit(db, actor_id=user.id, action="auth.login", resource_type="user", resource_id=user.id, details={"ip": ip, "session": tokens["session_id"]})
    db.commit()
    return {**tokens, "user": user}


def refresh(db: Session, refresh_token: str, ip: str | None, ua: str | None) -> dict:
    h, now = hash_token(refresh_token), utcnow()
    row = db.scalar(select(AuthSession).where(or_(AuthSession.refresh_hash == h, AuthSession.prev_refresh_hash == h)).with_for_update())
    if not row or row.revoked_at:
        raise ApiError(401, "invalid_refresh_token", "Invalid or expired refresh token")
    if row.refresh_hash != h:  # a rotated-out token was replayed: assume theft, kill the session
        revoke_session(db, row, "refresh_token_reuse")
        audit(db, actor_id=row.user_id, action="auth.refresh_reuse", resource_type="session", resource_id=row.id, outcome="denied", commit=True)
        raise ApiError(401, "invalid_refresh_token", "Invalid or expired refresh token")
    user = db.get(User, row.user_id)
    if aware(row.refresh_expires_at) <= now or not user or not user.is_active:
        raise ApiError(401, "invalid_refresh_token", "Invalid or expired refresh token")
    s, at, rt = get_settings(), new_token(), new_token()
    row.prev_refresh_hash, row.refresh_hash, row.access_hash = row.refresh_hash, hash_token(rt), hash_token(at)
    row.access_expires_at = now + timedelta(seconds=s.access_token_ttl_seconds)
    row.refresh_expires_at = now + timedelta(seconds=s.refresh_token_ttl_seconds)
    audit(db, actor_id=user.id, action="auth.refresh", resource_type="session", resource_id=row.id)
    db.commit()
    return {"access_token": at, "refresh_token": rt, "token_type": "bearer", "expires_in": s.access_token_ttl_seconds, "user": user}


def change_password(db: Session, user: User, current: str, new: str, keep_session_id: str | None) -> None:
    if not verify_password(current, user.password_hash):
        audit(db, actor_id=user.id, action="auth.change_password", resource_type="user", resource_id=user.id, outcome="denied", commit=True)
        raise ApiError(401, "invalid_credentials", "Current password is incorrect")
    validate_password(new, user.username)
    user.password_hash, user.password_changed_at = hash_password(new), utcnow()
    n = revoke_all(db, user.id, "password_changed", except_session_id=keep_session_id)
    audit(db, actor_id=user.id, action="auth.change_password", resource_type="user", resource_id=user.id, details={"sessions_revoked": n})


# ---- password reset (delivery is pluggable; see reset_delivery.py)
def create_reset_token(db: Session, user: User, created_by: str | None) -> tuple[str, datetime]:
    now = utcnow()
    db.execute(update(PasswordResetToken).where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)).values(used_at=now))
    token, exp = new_token(), now + timedelta(seconds=get_settings().reset_token_ttl_seconds)
    db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(token), expires_at=exp, created_by=created_by))
    db.flush()
    return token, exp


def confirm_reset(db: Session, token: str, new_password: str) -> None:
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token)).with_for_update())
    if not row or row.used_at or aware(row.expires_at) <= utcnow():
        raise ApiError(400, "invalid_reset_token", "Invalid or expired reset token")
    user = db.get(User, row.user_id)
    validate_password(new_password, user.username)
    user.password_hash, user.password_changed_at = hash_password(new_password), utcnow()
    user.failed_login_count, user.locked_until = 0, None
    row.used_at = utcnow()
    n = revoke_all(db, user.id, "password_reset")
    audit(db, actor_id=user.id, action="auth.password_reset", resource_type="user", resource_id=user.id, details={"sessions_revoked": n})


# ---- MFA (TOTP)
def mfa_enroll(db: Session, user: User) -> dict:
    if user.mfa_enabled:
        raise ApiError(409, "mfa_already_enabled", "MFA is already enabled")
    secret = totp_new_secret()
    user.mfa_secret_encrypted, user.mfa_last_step = encrypt_secret(secret), None
    audit(db, actor_id=user.id, action="auth.mfa_enroll", resource_type="user", resource_id=user.id)
    return {"secret": secret, "otpauth_uri": totp_uri(secret, user.username)}


def mfa_activate(db: Session, user: User, code: str) -> None:
    if user.mfa_enabled or not user.mfa_secret_encrypted:
        raise ApiError(409, "mfa_state", "No pending MFA enrollment")
    step = totp_verify(decrypt_secret(user.mfa_secret_encrypted), code)
    if step is None:
        raise ApiError(401, "invalid_mfa", "Invalid one-time code")
    user.mfa_enabled, user.mfa_last_step = True, step
    audit(db, actor_id=user.id, action="auth.mfa_enable", resource_type="user", resource_id=user.id)


def mfa_disable(db: Session, user: User, password: str, code: str) -> None:
    if not user.mfa_enabled:
        raise ApiError(409, "mfa_state", "MFA is not enabled")
    if not verify_password(password, user.password_hash) or totp_verify(decrypt_secret(user.mfa_secret_encrypted), code, user.mfa_last_step) is None:
        raise ApiError(401, "invalid_credentials", "Invalid password or code")
    user.mfa_enabled, user.mfa_secret_encrypted, user.mfa_last_step = False, None, None
    audit(db, actor_id=user.id, action="auth.mfa_disable", resource_type="user", resource_id=user.id)
