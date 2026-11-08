"""Rule-based hypothesis generation. Hypotheses are NOT findings; each lists assumptions and missing evidence."""
import re
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import (ApiEndpoint, ApplicationRoute, DatabaseTable, DatabaseSchema, Evidence, Hypothesis, Technology)

STATE_WORDS = re.compile(r"checkout|approve|cancel|refund|status|transition|reset|verify|confirm|payment|order", re.I)
PARAM = re.compile(r"\{\w+\}|:\w+|<[\w:]+>")
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _h(cat, title, reasoning, ev, assumptions, missing, conf, validation):
    return dict(category=cat, title=title[:300], reasoning=reasoning, supporting_evidence_ids=sorted(set(ev)),
                assumptions=assumptions, missing_evidence=missing, confidence=conf, safe_validation_approach=validation)


def generate_candidates(db: Session, aid: str) -> list[dict]:
    out = []
    routes = db.scalars(select(ApplicationRoute).where(ApplicationRoute.assessment_id == aid)).all()
    for r in routes:
        if r.method in MUTATING and r.auth_required is None:
            out.append(_h("authentication_authorization_boundary", f"State-changing route {r.method} {r.path} may lack an authentication check",
                          f"Static analysis of {r.source_file}:{r.line} found no authentication marker near this {r.method} route. Global middleware may still enforce it.",
                          [r.evidence_id], ["Authentication is not enforced by global middleware not seen in the analyzed files"],
                          ["Middleware/gateway configuration", "Runtime behaviour in an authorized test environment"], "low",
                          "Review middleware and gateway configuration; then, in staging, run an approved single-request status check with no credentials against this route."))
        if PARAM.search(r.path):
            out.append(_h("data_ownership", f"Object access on {r.method} {r.path} may not verify record ownership",
                          "The route addresses a record by identifier; whether the handler checks the caller owns it is not visible from route declarations alone.",
                          [r.evidence_id], ["Identifiers map to user-owned records"], ["Handler source", "Authorization policy"], "low",
                          "Code-review the handler's ownership check; if absent from review, validate in staging with two synthetic accounts under an approved experiment."))
        if STATE_WORDS.search(r.path):
            out.append(_h("application_state_transitions", f"Workflow route {r.path} may allow out-of-order state transitions",
                          "Route name suggests a step in a multi-step workflow. Servers sometimes rely on clients to follow the expected order.",
                          [r.evidence_id], ["The route belongs to a stateful workflow"], ["State machine definition", "Server-side transition checks"], "low",
                          "Document the intended state machine, then review server-side guards; test only with synthetic records in staging."))
    tables = db.scalars(select(DatabaseTable).join(DatabaseSchema, DatabaseTable.schema_id == DatabaseSchema.id)
                        .where(DatabaseSchema.assessment_id == aid)).all()
    schemas = {s.id: s for s in db.scalars(select(DatabaseSchema).where(DatabaseSchema.assessment_id == aid)).all()}
    for t in tables:
        if t.ownership_columns:
            out.append(_h("data_ownership", f"Table {t.name} is owner-scoped via {', '.join(t.ownership_columns)}; queries may not always filter by owner",
                          f"The schema links rows to an owner through {t.ownership_columns}. Sensitivity={t.sensitivity}. Enforcement lives in application code, not the schema.",
                          [schemas[t.schema_id].evidence_id], ["Row isolation relies on application-level filtering"],
                          ["Data-access layer code", "Row-level security policies"], "medium" if t.sensitivity in ("confidential", "restricted") else "low",
                          "Review data-access code paths for owner filters; validate with synthetic tenants in a non-production database."))
    for tech in db.scalars(select(Technology).where(Technology.assessment_id == aid)).all():
        if tech.version:
            out.append(_h("third_party_dependencies", f"{tech.name} {tech.version} exposed in responses may have published advisories",
                          "A component version is disclosed to clients. Disclosed versions can differ from actual patch levels (backports, proxies).",
                          [tech.evidence_id], ["Disclosed version is accurate"], ["Actual installed version", "Vendor advisory mapping"], "low",
                          "Check vendor advisories for this version and confirm the real version with the system owner."))
    for ev in db.scalars(select(Evidence).where(Evidence.assessment_id == aid, Evidence.category == "browser_resources")).all():
        no_sri = [x for x in ev.payload.get("third_party", []) if x["type"] == "script" and not x["sri"]]
        if no_sri:
            hosts = sorted({x["host"] for x in no_sri})
            out.append(_h("third_party_dependencies", f"Third-party scripts without integrity checks: {', '.join(hosts)}",
                          "Scripts loaded from external hosts without Subresource Integrity run with the page's privileges if the third party is compromised.",
                          [ev.id], ["Scripts execute in a context handling sensitive data"], ["Which pages load these scripts", "Data exposed to those pages"], "medium",
                          "Review where scripts load; consider SRI or self-hosting. No active testing required."))
        # protocol interpretation: layered proxies
    for ev in db.scalars(select(Evidence).where(Evidence.assessment_id == aid, Evidence.category == "http_response_metadata")).all():
        h = ev.payload.get("headers", {})
        if h.get("via") and h.get("x-powered-by"):
            out.append(_h("protocol_interpretation_differences", "Proxy layer and origin both visible; they may parse requests differently",
                          "Response headers reveal both an intermediary (Via) and an origin framework (X-Powered-By). Different components can interpret edge cases differently.",
                          [ev.id], ["Proxy and origin are different software"], ["Proxy and origin configuration", "Request normalisation settings"], "low",
                          "Compare proxy/origin configuration documents with the owner; no traffic testing needed for the review step."))
    apis = db.scalars(select(ApiEndpoint).where(ApiEndpoint.assessment_id == aid)).all()
    documented = {(a.method, a.path) for a in apis}
    if apis and routes:
        undocumented = sorted({r.path for r in routes if r.path not in {p for _, p in documented}})[:20]
        if undocumented:
            out.append(_h("architectural_inconsistencies", f"{len(undocumented)} source routes do not appear in the public API description",
                          "Routes exist in source that the published API description omits; undocumented routes are often less reviewed.",
                          [r.evidence_id for r in routes[:5]] + [a.evidence_id for a in apis[:3]],
                          ["Public API description is meant to be complete"], ["Whether routes are internal-only", "Gateway exposure rules"], "low",
                          "Ask the owner whether these routes are internal-only and confirm gateway exposure by configuration review."))
    for a in apis:
        if a.documented and a.auth_scheme is None and a.method in MUTATING:
            out.append(_h("api_trust_assumptions", f"Documented {a.method} {a.path} declares no security requirement",
                          "The public API description lists no security scheme for a state-changing operation; the description may simply be incomplete.",
                          [a.evidence_id], ["Missing declaration reflects missing enforcement"], ["Gateway/app enforcement"], "low",
                          "Compare against implementation; validate with an approved single unauthenticated status check in staging."))
    return out


def generate(db: Session, aid: str) -> list[Hypothesis]:
    created, seen = [], set()
    for c in generate_candidates(db, aid):
        if not c["supporting_evidence_ids"]:
            continue  # no evidence, no hypothesis
        if c["title"] in seen or db.scalar(select(Hypothesis).where(Hypothesis.assessment_id == aid, Hypothesis.title == c["title"])):
            continue
        seen.add(c["title"])
        h = Hypothesis(assessment_id=aid, origin="rule_engine", **c)
        try:
            with db.begin_nested():  # a concurrent generate() may have inserted the same title
                db.add(h)
                db.flush()
            created.append(h)
        except IntegrityError:
            pass
    return created
