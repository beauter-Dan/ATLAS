from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core import enums as E
from app.core.deps import require_role
from app.core.errors import ApiError
from app.db.session import get_db
from app.models import Assessment, AssessmentMember, User
from app.services import access
from app.services.audit import audit

router = APIRouter(tags=["members"])


class Perm(BaseModel):
    permission: str


def _can_manage(db, user, aid) -> Assessment:
    a = access.require(db, user, aid, "viewer")
    if not (user.role == "admin" or a.owner_id == user.id or access.effective_level(db, user, aid) >= E.MEMBER_LEVEL["approver"]):
        raise ApiError(403, "insufficient_assessment_permission", "Only the owner, an assessment approver or an admin can manage members")
    return a


def _row(m: AssessmentMember, u: User | None, owner_id):
    return {"user_id": m.user_id, "username": u.username if u else None, "permission": m.permission, "is_owner": m.user_id == owner_id}


@router.get("/assessments/{aid}/members", operation_id="list_members")
def list_members(aid: str, db: Session = Depends(get_db), user: User = Depends(require_role("viewer"))):
    a = access.require(db, user, aid, "viewer")
    rows = db.scalars(select(AssessmentMember).where(AssessmentMember.assessment_id == aid)).all()
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_([m.user_id for m in rows] or ["-"]))).all()}
    return {"data": [_row(m, users.get(m.user_id), a.owner_id) for m in rows]}


@router.put("/assessments/{aid}/members/{uid}", operation_id="set_member")
def set_member(aid: str, uid: str, body: Perm, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    a = _can_manage(db, user, aid)
    if body.permission not in E.MEMBER_PERMISSIONS:
        raise ApiError(422, "invalid_value", f"permission must be one of {E.MEMBER_PERMISSIONS}")
    target = db.get(User, uid)
    if not target or not target.is_active:
        raise ApiError(404, "not_found", "User not found")
    if uid == a.owner_id:
        raise ApiError(409, "owner_immutable", "The owner's access cannot be changed")
    m = db.scalar(select(AssessmentMember).where(AssessmentMember.assessment_id == aid, AssessmentMember.user_id == uid).with_for_update())
    try:
        if m:
            m.permission = body.permission
        else:
            m = AssessmentMember(assessment_id=aid, user_id=uid, permission=body.permission, added_by=user.id)
            db.add(m)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "conflict", "Concurrent membership change; retry")
    audit(db, actor_id=user.id, action="member.set", resource_type="assessment_member", resource_id=m.id, assessment_id=aid,
          details={"user_id": uid, "permission": body.permission})
    db.commit()
    return {"data": _row(m, target, a.owner_id)}


@router.delete("/assessments/{aid}/members/{uid}", status_code=204, operation_id="remove_member")
def remove_member(aid: str, uid: str, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    a = _can_manage(db, user, aid)
    if uid == a.owner_id:
        raise ApiError(409, "owner_immutable", "The owner's access cannot be removed")
    m = db.scalar(select(AssessmentMember).where(AssessmentMember.assessment_id == aid, AssessmentMember.user_id == uid))
    if not m:
        raise ApiError(404, "not_found", "Membership not found")
    db.delete(m)
    audit(db, actor_id=user.id, action="member.remove", resource_type="assessment_member", resource_id=m.id, assessment_id=aid, details={"user_id": uid})
    db.commit()
