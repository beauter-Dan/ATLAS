from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core import enums as E
from app.core.deps import client_ip, current_session, current_user, require_role
from app.core.errors import ApiError
from app.core.security import hash_password
from app.db.session import get_db
from app.models import AuditLog, AuthSession, User
from app.services import auth as svc
from app.services.audit import audit
from app.services.reset_delivery import get_delivery

router = APIRouter(prefix="/auth", tags=["auth"])


class Login(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class Refresh(BaseModel):
    refresh_token: str = Field(max_length=200)


class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(max_length=128)
    role: str = "viewer"


class PatchUser(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class ChangePw(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=128)


class ResetRequest(BaseModel):
    username: str = Field(max_length=100)


class ResetConfirm(BaseModel):
    token: str = Field(max_length=200)
    new_password: str = Field(max_length=128)


class Code(BaseModel):
    code: str = Field(max_length=10)


class MfaDisable(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(max_length=10)


def _u(u: User):
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active, "mfa_enabled": u.mfa_enabled}


def _tokens(res: dict) -> dict:
    return {"data": {"access_token": res["access_token"], "refresh_token": res["refresh_token"], "token_type": "bearer",
                     "expires_in": res["expires_in"], "user": _u(res["user"])}}


@router.post("/login", operation_id="login")
def login(body: Login, request: Request, db: Session = Depends(get_db)):
    return _tokens(svc.login(db, body.username, body.password, body.totp_code, client_ip(request), request.headers.get("user-agent")))


@router.post("/refresh", operation_id="refresh_token")
def refresh(body: Refresh, request: Request, db: Session = Depends(get_db)):
    return _tokens(svc.refresh(db, body.refresh_token, client_ip(request), request.headers.get("user-agent")))


@router.post("/logout", status_code=204, operation_id="logout")
def logout(res=Depends(current_session), db: Session = Depends(get_db)):
    user, sess = res
    svc.revoke_session(db, sess, "logout")
    audit(db, actor_id=user.id, action="auth.logout", resource_type="session", resource_id=sess.id)
    db.commit()


@router.post("/logout-all", operation_id="logout_all")
def logout_all(user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = svc.revoke_all(db, user.id, "logout_all")
    audit(db, actor_id=user.id, action="auth.logout_all", resource_type="user", resource_id=user.id, details={"sessions": n})
    db.commit()
    return {"data": {"revoked": n}}


@router.get("/sessions", operation_id="list_sessions")
def sessions(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).order_by(AuthSession.created_at.desc())).all()
    return {"data": [{"id": r.id, "created_at": r.created_at, "ip": r.ip, "user_agent": r.user_agent} for r in rows]}


@router.get("/me", operation_id="whoami")
def me(user: User = Depends(current_user)):
    return {"data": _u(user)}


@router.post("/change-password", operation_id="change_password")
def change_password(body: ChangePw, res=Depends(current_session), db: Session = Depends(get_db)):
    user, sess = res
    svc.change_password(db, user, body.current_password, body.new_password, sess.id)
    db.commit()
    return {"data": {"changed": True}}


@router.post("/password-reset/request", status_code=202, operation_id="password_reset_request")
def reset_request(body: ResetRequest, db: Session = Depends(get_db)):
    """Always 202 so account existence is not revealed. The token goes to the configured delivery backend only."""
    user = db.scalar(select(User).where(User.username == body.username, User.is_active.is_(True)))
    if user:
        token, _ = svc.create_reset_token(db, user, None)
        get_delivery().deliver(user.username, token)
        audit(db, actor_id=user.id, action="auth.reset_requested", resource_type="user", resource_id=user.id)
        db.commit()
    return {"data": {"accepted": True}}


@router.post("/password-reset/confirm", operation_id="password_reset_confirm")
def reset_confirm(body: ResetConfirm, db: Session = Depends(get_db)):
    svc.confirm_reset(db, body.token, body.new_password)
    db.commit()
    return {"data": {"reset": True}}


@router.post("/mfa/enroll", operation_id="mfa_enroll")
def mfa_enroll(user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = svc.mfa_enroll(db, user)
    db.commit()
    return {"data": out}


@router.post("/mfa/activate", operation_id="mfa_activate")
def mfa_activate(body: Code, user: User = Depends(current_user), db: Session = Depends(get_db)):
    svc.mfa_activate(db, user, body.code)
    db.commit()
    return {"data": {"mfa_enabled": True}}


@router.post("/mfa/disable", operation_id="mfa_disable")
def mfa_disable(body: MfaDisable, user: User = Depends(current_user), db: Session = Depends(get_db)):
    svc.mfa_disable(db, user, body.password, body.code)
    db.commit()
    return {"data": {"mfa_enabled": False}}


# ---- administration
@router.post("/users", status_code=201, operation_id="create_user")
def create_user(body: NewUser, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    if body.role not in E.ROLES:
        raise ApiError(422, "invalid_value", f"role must be one of {E.ROLES}")
    svc.validate_password(body.password, body.username)
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(u); db.flush()
    audit(db, actor_id=admin.id, action="user.create", resource_type="user", resource_id=u.id, details={"role": u.role})
    db.commit()
    return {"data": _u(u)}


@router.get("/users", operation_id="list_users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    return {"data": [_u(u) for u in db.scalars(select(User).order_by(User.username)).all()]}


@router.get("/users/lookup", operation_id="lookup_user")
def lookup_user(username: str, db: Session = Depends(get_db), _: User = Depends(require_role("analyst"))):
    u = db.scalar(select(User).where(User.username == username, User.is_active.is_(True)))
    if not u:
        raise ApiError(404, "not_found", "User not found")
    return {"data": {"id": u.id, "username": u.username, "role": u.role}}


@router.patch("/users/{uid}", operation_id="update_user")
def patch_user(uid: str, body: PatchUser, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    u = db.get(User, uid)
    if not u:
        raise ApiError(404, "not_found", "User not found")
    if body.role is not None:
        if body.role not in E.ROLES:
            raise ApiError(422, "invalid_value", f"role must be one of {E.ROLES}")
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.is_active is False or body.role is not None:
        svc.revoke_all(db, u.id, "account_changed")
    audit(db, actor_id=admin.id, action="user.update", resource_type="user", resource_id=u.id, details={"role": body.role, "is_active": body.is_active})
    db.commit()
    return {"data": _u(u)}


@router.post("/users/{uid}/password-reset", operation_id="admin_issue_reset")
def admin_reset(uid: str, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    u = db.get(User, uid)
    if not u:
        raise ApiError(404, "not_found", "User not found")
    token, exp = svc.create_reset_token(db, u, admin.id)
    audit(db, actor_id=admin.id, action="auth.reset_issued", resource_type="user", resource_id=u.id)
    db.commit()
    return {"data": {"reset_token": token, "expires_at": exp, "note": "Shown once. Deliver out-of-band."}}


@router.delete("/users/{uid}/mfa", status_code=204, operation_id="admin_reset_mfa")
def admin_reset_mfa(uid: str, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    u = db.get(User, uid)
    if not u:
        raise ApiError(404, "not_found", "User not found")
    u.mfa_enabled, u.mfa_secret_encrypted, u.mfa_last_step = False, None, None
    svc.revoke_all(db, u.id, "mfa_reset")
    audit(db, actor_id=admin.id, action="auth.mfa_reset", resource_type="user", resource_id=u.id)
    db.commit()


@router.get("/audit-logs", operation_id="list_audit_logs")
def audit_logs(assessment_id: str | None = None, action: str | None = None, outcome: str | None = None,
               page: int = 1, page_size: int = 100, db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    q = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if assessment_id:
        q = q.where(AuditLog.assessment_id == assessment_id)
    if action:
        q = q.where(AuditLog.action == action)
    if outcome:
        q = q.where(AuditLog.outcome == outcome)
    rows = db.scalars(q.offset((max(page, 1) - 1) * page_size).limit(min(page_size, 500))).all()
    return {"data": [{"id": r.id, "timestamp": r.timestamp, "actor_id": r.actor_id, "action": r.action, "resource_type": r.resource_type,
                      "resource_id": r.resource_id, "assessment_id": r.assessment_id, "outcome": r.outcome, "details": r.details} for r in rows]}
