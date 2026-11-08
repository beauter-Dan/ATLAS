"""Per-assessment access control.

Effective level on an assessment = min(global role, membership permission); admins bypass.
Owners get their global role (capped at approver). Not a member => the assessment is invisible (404, no
existence leak). A member with too little permission gets 403 `insufficient_assessment_permission`."""
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from app.core.enums import MEMBER_LEVEL, ROLE_LEVEL
from app.core.errors import ApiError
from app.models import Assessment, AssessmentMember, DatabaseSchema, DatabaseTable, Target, User
from app.services.audit import audit

ADMIN_LEVEL = 99


def _cap(user: User) -> int:
    return min(ROLE_LEVEL[user.role], MEMBER_LEVEL["approver"])


def effective_level(db: Session, user: User, assessment_id: str) -> int | None:
    if user.role == "admin":
        return ADMIN_LEVEL if db.get(Assessment, assessment_id) else None
    a = db.get(Assessment, assessment_id)
    if not a:
        return None
    if a.owner_id == user.id:
        return _cap(user)
    m = db.scalar(select(AssessmentMember).where(AssessmentMember.assessment_id == assessment_id, AssessmentMember.user_id == user.id))
    return min(MEMBER_LEVEL[m.permission], _cap(user)) if m else None


def _deny(db, user, aid, code, status, msg, needed):
    audit(db, actor_id=user.id, action="access_denied", resource_type="assessment", resource_id=aid, assessment_id=aid,
          outcome="denied", details={"needed": needed, "reason": code}, commit=True)
    raise ApiError(status, code, msg)


def require(db: Session, user: User, assessment_id: str, minimum: str = "viewer") -> Assessment:
    lvl = effective_level(db, user, assessment_id)
    if lvl is None:
        _deny(db, user, assessment_id, "not_found", 404, "Assessment not found", minimum)
    if lvl < MEMBER_LEVEL[minimum]:
        _deny(db, user, assessment_id, "insufficient_assessment_permission", 403,
              f"Requires '{minimum}' permission on this assessment", minimum)
    return db.get(Assessment, assessment_id)


def accessible_ids(user: User):
    if user.role == "admin":
        return select(Assessment.id)
    return select(Assessment.id).where(or_(Assessment.owner_id == user.id,
                                           Assessment.id.in_(select(AssessmentMember.assessment_id).where(AssessmentMember.user_id == user.id))))


def target_filter(user: User):
    if user.role == "admin":
        return None
    return or_(Target.created_by == user.id, Target.id.in_(select(Assessment.target_id).where(Assessment.id.in_(accessible_ids(user)))))


def list_filter(model, user: User):
    """SQL predicate restricting a list query to what the user may see (None = unrestricted)."""
    if user.role == "admin":
        return None
    if model is Target:
        return target_filter(user)
    if model is Assessment:
        return Assessment.id.in_(accessible_ids(user))
    if model is DatabaseTable:
        return model.schema_id.in_(select(DatabaseSchema.id).where(DatabaseSchema.assessment_id.in_(accessible_ids(user))))
    if hasattr(model, "assessment_id"):
        return model.assessment_id.in_(accessible_ids(user))
    return None


def assessment_id_of(db: Session, obj) -> str | None:
    if isinstance(obj, Assessment):
        return obj.id
    if isinstance(obj, DatabaseTable):
        s = db.get(DatabaseSchema, obj.schema_id)
        return s.assessment_id if s else None
    return getattr(obj, "assessment_id", None)


def check_object(db: Session, user: User, obj, minimum: str = "viewer"):
    """Authorize access to an existing object (any resource)."""
    if isinstance(obj, Target):
        if user.role == "admin":
            return
        visible = obj.created_by == user.id or db.scalar(select(Assessment.id).where(
            Assessment.target_id == obj.id, Assessment.id.in_(accessible_ids(user))).limit(1))
        if not visible:
            raise ApiError(404, "not_found", "Target not found")
        if minimum != "viewer" and obj.created_by != user.id:
            raise ApiError(403, "insufficient_target_permission", "Only the target's creator or an admin may modify it")
        return
    aid = assessment_id_of(db, obj)
    if aid:
        require(db, user, aid, minimum)


def check_create(db: Session, user: User, model, data: dict, level: str = "analyst"):
    if model is Assessment:
        t = db.get(Target, data["target_id"])
        if not t:
            raise ApiError(404, "not_found", "Target not found")
        check_object(db, user, t, "viewer")
    elif data.get("assessment_id"):
        require(db, user, data["assessment_id"], level)
