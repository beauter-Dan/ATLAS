"""Read-only dashboard aggregates. Everything is filtered through the same access rules as the list endpoints."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models import (Assessment, Asset, AuditLog, Evidence, Experiment, Finding, Hypothesis, Report, ScopeRule, Target,
                        Technology, User)
from app.services import access

# Only coarse, non-sensitive labels are exposed in the feed (no actor ids, no audit details).
LABELS = {
    "assessment.create": "Assessment created", "assessment.status": "Assessment status changed", "collect": "Data collection ran",
    "job.completed": "Background collection finished", "internal.source": "Source code analyzed", "internal.schema": "Database schema analyzed",
    "architecture.build": "Architecture map built", "hypotheses.generate": "Hypotheses generated", "experiment.approve": "Experiment approved",
    "experiment.finish": "Experiment finished", "finding.classify": "Finding classified", "report.generate": "Report generated",
}
STAGES = 7  # scope defined, activated, data collected, analyzed, experiment completed, finding recorded, report generated


def _count(db: Session, user: User, model, *conds) -> int:
    q = select(func.count()).select_from(model)
    flt = access.list_filter(model, user)
    if flt is not None:
        q = q.where(flt)
    for c in conds:
        q = q.where(c)
    return db.scalar(q) or 0


def _ids(db: Session, col, ids: list[str], *conds) -> set[str]:
    return set(db.scalars(select(col).where(col.in_(ids), *conds).distinct()).all()) if ids else set()


def progress(db: Session, user: User) -> list[dict]:
    q = select(Assessment).where(Assessment.status.in_(["draft", "active", "paused"])).order_by(Assessment.created_at.desc()).limit(10)
    flt = access.list_filter(Assessment, user)
    if flt is not None:
        q = q.where(flt)
    rows = db.scalars(q).all()
    ids = [a.id for a in rows]
    done = [
        _ids(db, ScopeRule.assessment_id, ids, ScopeRule.rule_type == "include"),
        {a.id for a in rows if a.status != "draft"},
        _ids(db, Evidence.assessment_id, ids),
        _ids(db, Hypothesis.assessment_id, ids),
        _ids(db, Experiment.assessment_id, ids, Experiment.status == "completed"),
        _ids(db, Finding.assessment_id, ids),
        _ids(db, Report.assessment_id, ids),
    ]
    return [{"id": a.id, "name": a.name, "status": a.status,
             "percent": round(100 * sum(a.id in s for s in done) / STAGES)} for a in rows]


def activity(db: Session, user: User) -> list[dict]:
    q = select(AuditLog).where(AuditLog.outcome == "success", AuditLog.action.in_(list(LABELS)), AuditLog.assessment_id.is_not(None))
    if user.role != "admin":
        q = q.where(AuditLog.assessment_id.in_(access.accessible_ids(user)))
    rows = db.scalars(q.order_by(AuditLog.timestamp.desc()).limit(10)).all()
    names = {a.id: a.name for a in db.scalars(select(Assessment).where(Assessment.id.in_([r.assessment_id for r in rows] or ["-"]))).all()}
    return [{"id": r.id, "timestamp": r.timestamp,
             "message": f"{LABELS[r.action]} · {names[r.assessment_id]}" if r.assessment_id in names else LABELS[r.action]} for r in rows]


def summary(db: Session, user: User) -> dict:
    return {
        "targets": _count(db, user, Target),
        "active_assessments": _count(db, user, Assessment, Assessment.status == "active"),
        "assets": _count(db, user, Asset),
        "technologies": _count(db, user, Technology),
        "pending_hypotheses": _count(db, user, Hypothesis, Hypothesis.status == "open"),
        "confirmed_findings": _count(db, user, Finding, Finding.classification == "confirmed_vulnerability"),
        "assessment_progress": progress(db, user),
        "recent_activity": activity(db, user),
    }
