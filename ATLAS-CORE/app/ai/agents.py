import json, re
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.ai import providers
from app.ai.redact import redact
from app.core.errors import ApiError
from app.models import Evidence, Hypothesis, Observation
from app.services.audit import audit

RULES = ("You assist an AUTHORIZED security assessment. Use ONLY the evidence provided. Never invent technical facts. "
         "Reply with JSON: {\"statements\":[{\"text\",\"classification\",\"evidence_ids\",\"confidence\"}]}. "
         "classification is one of direct_observation, inference, hypothesis, unknown. You may NOT declare anything "
         "confirmed. Every statement except 'unknown' must cite evidence_ids from the input. "
         "Do not provide exploit code or attack steps; propose only safe validation ideas.")
AGENTS = {
    "reconnaissance": ("Reconnaissance Analyst", ["domain_registration", "dns_records", "certificate_transparency", "http_response_metadata",
                                                  "tls_configuration", "technology_fingerprint", "browser_resources", "api_documentation"]),
    "architecture": ("Architecture Analyst", None),
    "application": ("Application Analyst", ["application_source_analysis", "api_documentation", "database_schema_analysis"]),
    "security_research": ("Security Research Analyst", None),
    "evidence_validation": ("Evidence Validation Analyst", None),
    "reporting": ("Reporting Analyst", None),
}
ALLOWED = {"direct_observation", "inference", "hypothesis", "unknown"}


def parse_statements(raw: str) -> list[dict]:
    raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    try:
        return list(json.loads(raw).get("statements", []))
    except (ValueError, AttributeError, TypeError):
        raise ApiError(502, "ai_invalid_output", "AI provider returned unparseable output")


def run_agent(db: Session, assessment_id: str, agent: str, actor_id: str | None, provider=None) -> dict:
    if agent not in AGENTS:
        raise ApiError(404, "unknown_agent", f"Unknown agent '{agent}'", sorted(AGENTS))
    title, cats = AGENTS[agent]
    q = select(Observation).where(Observation.assessment_id == assessment_id, Observation.evidence_id.is_not(None),
                                  Observation.collection_source.not_like("ai:%"))
    if cats:
        q = q.where(Observation.category.in_(cats))
    obs = db.scalars(q.limit(200)).all()
    ctx = {"observations": [{"evidence_id": o.evidence_id, "category": o.category, "description": redact(o.description),
                             "confidence": o.confidence} for o in obs]}
    if agent in ("evidence_validation", "security_research", "reporting"):
        ctx["hypotheses"] = [{"id": h.id, "title": redact(h.title), "evidence_ids": h.supporting_evidence_ids}
                             for h in db.scalars(select(Hypothesis).where(Hypothesis.assessment_id == assessment_id)).all()]
    prompt = f"Role: {title}\nEvidence (JSON):\n{redact(json.dumps(ctx))}"
    provider = provider or providers.get_provider()
    raw = provider.complete(f"You are the {title}. {RULES}", prompt, ctx)
    valid_ev = {e for e in db.scalars(select(Evidence.id).where(Evidence.assessment_id == assessment_id)).all()}
    accepted, rejected = [], []
    for s in parse_statements(raw):
        cls, ids = s.get("classification"), [i for i in s.get("evidence_ids", []) if i in valid_ev]
        note = None
        if cls == "confirmed" or cls not in ALLOWED:
            cls, note = "hypothesis", "AI cannot confirm findings; downgraded to hypothesis"
        if cls != "unknown" and not ids:
            rejected.append({"text": s.get("text"), "reason": "no valid supporting evidence"})
            continue
        conf = s.get("confidence") if s.get("confidence") in ("low", "medium", "high") else "low"
        if cls in ("hypothesis", "inference") and conf == "high":
            conf = "medium"
        item = {"text": str(s.get("text", ""))[:2000], "classification": cls, "evidence_ids": ids, "confidence": conf, "note": note}
        accepted.append(item)
        if cls != "direct_observation" and ids:  # AI reasoning is stored as an observation citing REAL evidence; AI text is never evidence itself
            if not db.scalar(select(Observation).where(Observation.evidence_id == ids[0], Observation.kind == cls,
                                                       Observation.description == item["text"])):
                db.add(Observation(assessment_id=assessment_id, evidence_id=ids[0], category=f"ai_{agent}", kind=cls,
                                   description=item["text"], collection_source=f"ai:{agent}",
                                   evidence_reference=",".join(ids), confidence=conf))
        if cls == "unknown" and not ids:
            db.add(Observation(assessment_id=assessment_id, evidence_id=None, category=f"ai_{agent}", kind="unknown",
                               description=item["text"], collection_source=f"ai:{agent}", evidence_reference="", confidence="low"))
        if cls == "hypothesis" and agent == "security_research" and ids:
            title_h = item["text"][:300]
            if not db.scalar(select(Hypothesis).where(Hypothesis.assessment_id == assessment_id, Hypothesis.title == title_h)):
                db.add(Hypothesis(assessment_id=assessment_id, category="ai_research", title=title_h, reasoning=item["text"],
                                  supporting_evidence_ids=ids, assumptions=["AI-generated; requires analyst review"],
                                  missing_evidence=["Independent validation"], confidence="low",
                                  safe_validation_approach="Analyst review, then non-destructive approved experiment if warranted.",
                                  origin=f"ai:{agent}"))
    audit(db, actor_id=actor_id, action=f"ai.{agent}", resource_type="assessment", resource_id=assessment_id,
          assessment_id=assessment_id, details={"provider": provider.name, "accepted": len(accepted), "rejected": len(rejected)})
    return {"agent": title, "provider": provider.name, "statements": accepted, "rejected": rejected}
