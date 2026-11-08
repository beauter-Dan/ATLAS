"""Validation of findings. Confirmation requires human-verified evidence; AI can never confirm."""
from sqlalchemy.orm import Session
from app.core.enums import ROLE_LEVEL
from app.core.errors import ApiError
from app.models import Experiment, Finding, Hypothesis, Observation, User
from app.services import normalize
from app.services.audit import audit
from sqlalchemy import select


def validate_classification(db: Session, f: Finding, classification: str, rationale: str, user: User, severity=None):
    evs = normalize.require_evidence(db, f.assessment_id, f.evidence_ids) if f.evidence_ids else []
    if classification in ("potential_vulnerability", "informational_observation") and not evs:
        raise ApiError(422, "evidence_required", f"{classification} requires at least one evidence reference")
    if classification in ("false_positive", "insufficient_evidence") and not (rationale or "").strip():
        raise ApiError(422, "rationale_required", f"{classification} requires a rationale")
    if classification == "confirmed_vulnerability":
        if ROLE_LEVEL[user.role] < ROLE_LEVEL["approver"]:
            raise ApiError(403, "forbidden", "Only an approver/admin can confirm a vulnerability")
        if not any(e.verification_status == "verified" for e in evs):
            raise ApiError(422, "verified_evidence_required", "Confirmation requires at least one human-verified evidence item")
        if not (rationale or "").strip():
            raise ApiError(422, "rationale_required", "Confirmation requires a rationale")
        if f.hypothesis_id:
            done = db.scalars(select(Experiment).where(Experiment.hypothesis_id == f.hypothesis_id,
                                                       Experiment.status == "completed")).first()
            if not done and not any(e.collection_source in ("manual", "source_code", "schema_export") for e in evs):
                raise ApiError(422, "validation_missing", "Hypothesis-linked confirmation needs a completed experiment or manual verification evidence")
    f.classification, f.rationale, f.classified_by = classification, rationale or f.rationale, user.id
    if severity:
        f.severity = severity
    if classification == "confirmed_vulnerability":
        normalize.record(db, assessment_id=f.assessment_id, asset_id=None, category="confirmed_finding",
                         source=f"finding:{f.id}", reference=f"finding:{f.id}", kind="confirmed", confidence="high",
                         description=f"Finding confirmed by human reviewer: {f.title}",
                         payload={"finding_id": f.id, "evidence_ids": f.evidence_ids, "by": user.id})
    if f.hypothesis_id:
        h = db.get(Hypothesis, f.hypothesis_id)
        if h:
            h.status = {"confirmed_vulnerability": "validated", "false_positive": "refuted"}.get(classification, h.status)
    audit(db, actor_id=user.id, action="finding.classify", resource_type="finding", resource_id=f.id,
          assessment_id=f.assessment_id, details={"classification": classification})


def verify_evidence(db: Session, ev, user: User, status: str):
    ev.verification_status, ev.verified_by = status, user.id
    for ob in db.scalars(select(Observation).where(Observation.evidence_id == ev.id)).all():
        ob.verification_status = status
    audit(db, actor_id=user.id, action="evidence.verify", resource_type="evidence", resource_id=ev.id,
          assessment_id=ev.assessment_id, details={"status": status})
