"""Background execution. A queued job is NOT trusted: everything is re-verified when it actually runs."""
from sqlalchemy.orm import Session
from app.core.enums import MEMBER_LEVEL
from app.core.errors import ApiError
from app.models import User
from app.services import access, collectors, scope
from app.services.audit import audit


def authorize_job(db: Session, assessment_id: str, actor_id: str | None) -> User:
    """Raises ApiError (and audits) unless actor, membership, assessment state and authorization are all still valid."""
    def reject(code, msg):
        audit(db, actor_id=actor_id, action="job.rejected", resource_type="assessment", resource_id=assessment_id,
              assessment_id=assessment_id, outcome="denied", details={"reason": code}, commit=True)
        raise ApiError(403, code, msg)
    actor = db.get(User, actor_id) if actor_id else None
    if not actor or not actor.is_active:
        reject("job_actor_invalid", "The user who queued this job is no longer active")
    lvl = access.effective_level(db, actor, assessment_id)
    if lvl is None or lvl < MEMBER_LEVEL["analyst"]:
        reject("job_access_revoked", "The user no longer has analyst access to this assessment")
    ok, why = scope.check_internal_access(db, assessment_id)
    if not ok:
        reject("job_scope_invalid", why)
    return actor


def execute_collection_job(db: Session, assessment_id: str, hosts: list[str], names: list[str], actor_id: str | None) -> dict:
    actor = authorize_job(db, assessment_id, actor_id)
    res = collectors.run_collection(db, assessment_id, hosts, names, actor.id)  # per-host scope re-checked here too
    audit(db, actor_id=actor.id, action="job.completed", resource_type="assessment", resource_id=assessment_id, assessment_id=assessment_id,
          details={"collected": len(res["collected"]), "skipped": len(res["skipped"])})
    return res
