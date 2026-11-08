"""Evidence normalization: every observation is backed by an Evidence row."""
import hashlib, json
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.errors import ApiError
from app.models import Asset, Evidence, Observation, Technology
from app.services.scope import classify


def ensure_asset(db: Session, assessment_id: str, asset_type: str, value: str, source: str) -> Asset:
    value = value.strip().lower() if asset_type != "url" else value.strip()
    a = db.scalar(select(Asset).where(Asset.assessment_id == assessment_id, Asset.asset_type == asset_type,
                                      Asset.value == value))
    if a:
        return a
    state, _ = classify(db, assessment_id, value)
    a = Asset(assessment_id=assessment_id, asset_type=asset_type, value=value, scope_state=state,
              discovery_source=source, details={})
    try:
        with db.begin_nested():  # concurrent collectors: loser of the unique-constraint race re-reads
            db.add(a)
            db.flush()
    except IntegrityError:
        return db.scalar(select(Asset).where(Asset.assessment_id == assessment_id, Asset.asset_type == asset_type, Asset.value == value))
    return a


def record(db: Session, *, assessment_id, asset_id, category, description, source, reference,
           payload=None, confidence="medium", kind="direct_observation") -> Observation:
    payload = payload or {}
    h = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    ev = db.scalar(select(Evidence).where(Evidence.assessment_id == assessment_id,
                                          Evidence.asset_id == asset_id, Evidence.collection_source == source,
                                          Evidence.category == category, Evidence.content_hash == h))
    if not ev:
        ev = Evidence(assessment_id=assessment_id, asset_id=asset_id, category=category,
                      description=description, collection_source=source, reference=reference,
                      content_hash=h, payload=payload, confidence=confidence)
        db.add(ev)
        db.flush()
    ob = db.scalar(select(Observation).where(Observation.evidence_id == ev.id, Observation.kind == kind))
    if not ob:
        ob = Observation(assessment_id=assessment_id, asset_id=asset_id, evidence_id=ev.id, category=category,
                         kind=kind, description=description, collection_source=source,
                         evidence_reference=reference, confidence=confidence)
        db.add(ob)
        db.flush()
    return ob


def add_technology(db, *, assessment_id, asset_id, evidence_id, name, version, category, confidence):
    t = db.scalar(select(Technology).where(Technology.assessment_id == assessment_id,
                                           Technology.asset_id == asset_id, Technology.name == name,
                                           Technology.version == version))
    if not t:
        t = Technology(assessment_id=assessment_id, asset_id=asset_id, evidence_id=evidence_id, name=name,
                       version=version, category=category, confidence=confidence)
        db.add(t)
        db.flush()
    return t


def require_evidence(db: Session, assessment_id: str, ids: list[str]) -> list[Evidence]:
    """Every cited evidence id must exist inside the same assessment."""
    found = db.scalars(select(Evidence).where(Evidence.id.in_(ids or []),
                                              Evidence.assessment_id == assessment_id)).all()
    missing = set(ids or []) - {e.id for e in found}
    if missing:
        raise ApiError(422, "unknown_evidence", "Evidence not found in this assessment", sorted(missing))
    return list(found)
