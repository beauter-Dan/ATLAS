import html
from collections import Counter
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import (ApiEndpoint, ApplicationRoute, Asset, Assessment, DatabaseSchema, DatabaseTable, Evidence,
                        Experiment, Finding, Hypothesis, Observation, Report, ScopeRule, Technology)
from app.services import architecture

DISCLAIMER = ("Findings are evidence-based. 'confirmed' status requires human-verified evidence; AI output is "
              "limited to inferences and hypotheses that cite evidence.")


def _rows(db, model, aid, cols):
    return [{c: getattr(r, c) for c in cols} for r in db.scalars(select(model).where(model.assessment_id == aid)).all()]


def build(db: Session, aid: str, user_id: str | None) -> Report:
    a = db.get(Assessment, aid)
    t = a.target
    findings = _rows(db, Finding, aid, ["id", "title", "classification", "severity", "evidence_ids", "rationale", "hypothesis_id"])
    obs = db.scalars(select(Observation).where(Observation.assessment_id == aid)).all()
    schemas = db.scalars(select(DatabaseSchema).where(DatabaseSchema.assessment_id == aid)).all()
    content = {
        "schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(), "disclaimer": DISCLAIMER,
        "assessment": {"id": a.id, "name": a.name, "status": a.status, "environment": a.environment},
        "target": {"id": t.id, "name": t.name, "base_domain": t.base_domain, "authorization_reference": t.authorization_reference,
                   "authorized_by": t.authorized_by},
        "scope_rules": _rows(db, ScopeRule, aid, ["rule_type", "match_type", "value"]),
        "assets": _rows(db, Asset, aid, ["id", "asset_type", "value", "scope_state"]),
        "technologies": _rows(db, Technology, aid, ["name", "version", "category", "confidence", "evidence_id"]),
        "observation_summary": {"by_kind": dict(Counter(o.kind for o in obs)), "by_category": dict(Counter(o.category for o in obs)),
                                "unverified": sum(o.verification_status == "unverified" for o in obs)},
        "architecture": architecture.graph(db, aid),
        "application_routes": _rows(db, ApplicationRoute, aid, ["method", "path", "auth_required", "evidence_id"]),
        "api_endpoints": _rows(db, ApiEndpoint, aid, ["method", "path", "documented", "evidence_id"]),
        "databases": [{"name": s.name, "technology": s.technology, "technology_confidence": s.technology_confidence,
                       "tables": [{"name": x.name, "sensitivity": x.sensitivity} for x in
                                  db.scalars(select(DatabaseTable).where(DatabaseTable.schema_id == s.id)).all()]} for s in schemas],
        "hypotheses": _rows(db, Hypothesis, aid, ["id", "category", "title", "confidence", "status", "supporting_evidence_ids", "missing_evidence"]),
        "experiments": _rows(db, Experiment, aid, ["id", "experiment_type", "status", "approved_by", "result"]),
        "findings": {c: [f for f in findings if f["classification"] == c] for c in
                     ["confirmed_vulnerability", "potential_vulnerability", "informational_observation", "false_positive", "insufficient_evidence"]},
        "unknowns": [o.description for o in obs if o.kind == "unknown"],
        "evidence_count": len(db.scalars(select(Evidence.id).where(Evidence.assessment_id == aid)).all()),
    }
    r = Report(assessment_id=aid, format="json", content=content, generated_by=user_id)
    db.add(r); db.flush()
    return r


def render_html(report: Report) -> str:
    c, e = report.content, html.escape
    rows = "".join(f"<tr><td>{e(f['classification'])}</td><td>{e(f['title'])}</td><td>{e(str(f['severity']))}</td>"
                   f"<td>{e(', '.join(f['evidence_ids']))}</td></tr>" for group in c["findings"].values() for f in group)
    hyp = "".join(f"<li>[{e(h['confidence'])}] {e(h['title'])} <em>({e(h['status'])})</em></li>" for h in c["hypotheses"])
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>ATLAS report {e(c['assessment']['name'])}</title></head><body>"
            f"<h1>{e(c['assessment']['name'])}</h1><p>{e(c['disclaimer'])}</p><h2>Findings</h2>"
            f"<table border=1><tr><th>Classification</th><th>Title</th><th>Severity</th><th>Evidence</th></tr>{rows}</table>"
            f"<h2>Hypotheses (unconfirmed)</h2><ul>{hyp}</ul></body></html>")
