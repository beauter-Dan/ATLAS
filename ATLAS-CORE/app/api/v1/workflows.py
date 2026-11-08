from typing import Any, Optional
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.ai import agents
from app.core import enums as E
from app.core.deps import require_role
from app.core.errors import ApiError
from app.db.session import get_db
from app.models import Assessment, DatabaseSchema, DatabaseTable, Evidence, Experiment, Finding, Report, ScopeRule, User
from app.services import (access, app_intel, architecture, collectors, db_intel, experiments as exp_svc, findings as find_svc,
                          hypotheses as hyp_svc, jobs, reporting, scope)
from app.services.audit import audit

router = APIRouter(tags=["workflows"])
Viewer, Analyst, Approver = require_role("viewer"), require_role("analyst"), require_role("approver")


class Data(BaseModel):
    data: Any


def _x(db, eid, user, level) -> Experiment:
    """Lock the experiment row (SELECT ... FOR UPDATE) so concurrent lifecycle calls serialize."""
    e = db.get(Experiment, eid, with_for_update=True)
    if not e:
        raise ApiError(404, "not_found", "Experiment not found")
    access.require(db, user, e.assessment_id, level)
    return e


class StatusBody(BaseModel):
    status: str


@router.post("/assessments/{aid}/status", response_model=Data, operation_id="set_assessment_status")
def set_status(aid: str, body: StatusBody, db: Session = Depends(get_db), user: User = Depends(Approver)):
    access.require(db, user, aid, "approver")
    a = db.get(Assessment, aid, with_for_update=True)
    if body.status not in E.STATUS_TRANSITIONS.get(a.status, set()):
        raise ApiError(409, "invalid_transition", f"{a.status} -> {body.status} not allowed")
    if body.status == "active":
        ok, why = scope.authorization_ok(a.target)
        if not ok:
            raise ApiError(422, "authorization_required", why)
        if not db.scalar(select(ScopeRule.id).where(ScopeRule.assessment_id == aid, ScopeRule.rule_type == "include").limit(1)):
            raise ApiError(422, "scope_required", "At least one include scope rule is required")
    a.status_history = [*a.status_history, {"from": a.status, "to": body.status, "by": user.id}]
    a.status = body.status
    audit(db, actor_id=user.id, action="assessment.status", resource_type="assessment", resource_id=aid, assessment_id=aid,
          details={"to": body.status})
    db.commit()
    return {"data": {"id": a.id, "status": a.status}}


class ScopeCheck(BaseModel):
    value: str = Field(max_length=2048)


@router.post("/assessments/{aid}/scope-check", response_model=Data, operation_id="scope_check")
def scope_check(aid: str, body: ScopeCheck, db: Session = Depends(get_db), user: User = Depends(Viewer)):
    access.require(db, user, aid, "viewer")
    state, rule_id = scope.classify(db, aid, body.value)
    ok, why = scope.check_access(db, aid, body.value)
    return {"data": {"value": body.value, "scope_state": state, "matched_rule_id": rule_id, "access_allowed": ok, "reason": why}}


class CollectBody(BaseModel):
    hosts: list[str] = Field(max_length=100)
    collectors: list[str] = collectors.ALL_COLLECTORS


def _check_collectors(names):
    bad = set(names) - set(collectors.ALL_COLLECTORS)
    if bad:
        raise ApiError(422, "invalid_collectors", f"Unknown collectors: {sorted(bad)}")


@router.post("/assessments/{aid}/collect", response_model=Data, operation_id="run_collection")
def collect(aid: str, body: CollectBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    _check_collectors(body.collectors)
    res = collectors.run_collection(db, aid, body.hosts, body.collectors, user.id)
    db.commit()
    return {"data": res}


@router.post("/assessments/{aid}/collect/jobs", response_model=Data, status_code=202, operation_id="enqueue_collection")
def enqueue(aid: str, body: CollectBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    """Queues a background collection. Authorization is verified now (fail fast) AND again when the job executes."""
    access.require(db, user, aid, "analyst")
    _check_collectors(body.collectors)
    jobs.authorize_job(db, aid, user.id)
    import uuid
    from app.worker import collect_task
    job_id = str(uuid.uuid4())
    audit(db, actor_id=user.id, action="job.queued", resource_type="assessment", resource_id=aid, assessment_id=aid,
          details={"job_id": job_id, "hosts": len(body.hosts)})
    db.commit()  # commit BEFORE enqueueing so a worker never starts ahead of the audit trail / open transaction
    collect_task.apply_async(args=[aid, body.hosts, body.collectors, user.id], task_id=job_id)
    return {"data": {"job_id": job_id, "state": "queued"}}


@router.get("/assessments/{aid}/collect/jobs/{job_id}", response_model=Data, operation_id="get_collection_job")
def job_status(aid: str, job_id: str, db: Session = Depends(get_db), user: User = Depends(Viewer)):
    access.require(db, user, aid, "viewer")
    from celery.result import AsyncResult
    from app.worker import celery_app
    r = AsyncResult(job_id, app=celery_app)
    out = {"job_id": job_id, "state": r.state}
    if r.ready() and isinstance(r.result, dict) and r.result.get("assessment_id") == aid:  # never expose another assessment's result
        out["result"] = r.result
    return {"data": out}


class SourceBody(BaseModel):
    label: str = Field(max_length=200)
    files: dict[str, str]

    @model_validator(mode="after")
    def _limits(self):
        if len(self.files) > 2000 or sum(len(v) for v in self.files.values()) > 5_000_000 or any(len(k) > 500 for k in self.files):
            raise ValueError("source upload too large (max 2000 files, 5,000,000 characters)")
        return self


@router.post("/assessments/{aid}/internal/source", response_model=Data, operation_id="analyze_source")
def analyze_source(aid: str, body: SourceBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    scope.enforce_internal(db, aid, action="source_analysis", actor_id=user.id)
    res = app_intel.persist(db, aid, body.files, body.label)
    audit(db, actor_id=user.id, action="internal.source", resource_type="assessment", resource_id=aid, assessment_id=aid,
          details={"files": len(body.files)})
    db.commit()
    return {"data": {**{k: v for k, v in res.items() if k != "routes"}, "route_count": len(res["routes"])}}


class SchemaBody(BaseModel):
    name: str = Field(max_length=200)
    sql: str = Field(max_length=2_000_000)
    technology: Optional[str] = Field(default=None, max_length=50)


@router.post("/assessments/{aid}/internal/schema", response_model=Data, operation_id="analyze_schema")
def analyze_schema(aid: str, body: SchemaBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    scope.enforce_internal(db, aid, action="schema_analysis", actor_id=user.id)
    schema, res = db_intel.persist(db, aid, body.name, body.sql, body.technology)
    audit(db, actor_id=user.id, action="internal.schema", resource_type="database_schema", resource_id=schema.id, assessment_id=aid)
    db.commit()
    return {"data": {"schema_id": schema.id, "technology": res["technology"], "technology_confidence": res["technology_confidence"],
                     "tables": [t["name"] for t in res["tables"]]}}


@router.get("/databases/{schema_id}/tables", response_model=Data, operation_id="list_schema_tables")
def schema_tables(schema_id: str, db: Session = Depends(get_db), user: User = Depends(Viewer)):
    s = db.get(DatabaseSchema, schema_id)
    if not s:
        raise ApiError(404, "not_found", "DatabaseSchema not found")
    access.require(db, user, s.assessment_id, "viewer")
    rows = db.scalars(select(DatabaseTable).where(DatabaseTable.schema_id == schema_id)).all()
    return {"data": [{"id": t.id, "name": t.name, "columns": t.columns, "primary_key": t.primary_key, "foreign_keys": t.foreign_keys,
                      "ownership_columns": t.ownership_columns, "sensitivity": t.sensitivity} for t in rows]}


@router.post("/assessments/{aid}/architecture/build", response_model=Data, operation_id="build_architecture")
def build_arch(aid: str, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    n = architecture.build_relationships(db, aid)
    audit(db, actor_id=user.id, action="architecture.build", resource_type="assessment", resource_id=aid, assessment_id=aid, details={"new": n})
    db.commit()
    return {"data": {"new_relationships": n, **architecture.graph(db, aid)}}


@router.get("/architecture", response_model=Data, operation_id="get_architecture")
def get_arch(assessment_id: str, db: Session = Depends(get_db), user: User = Depends(Viewer)):
    access.require(db, user, assessment_id, "viewer")
    return {"data": architecture.graph(db, assessment_id)}


@router.post("/assessments/{aid}/ai/{agent}", response_model=Data, operation_id="run_ai_agent")
def run_agent(aid: str, agent: str, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    res = agents.run_agent(db, aid, agent, user.id)
    db.commit()
    return {"data": res}


@router.post("/assessments/{aid}/hypotheses/generate", response_model=Data, operation_id="generate_hypotheses")
def gen_hyp(aid: str, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    created = hyp_svc.generate(db, aid)
    audit(db, actor_id=user.id, action="hypotheses.generate", resource_type="assessment", resource_id=aid, assessment_id=aid,
          details={"created": len(created)})
    db.commit()
    return {"data": {"created": len(created), "ids": [h.id for h in created]}}


def _exp_action(fn_name: str, level: str, role_dep):
    def endpoint(eid: str, db: Session = Depends(get_db), user: User = Depends(role_dep)):
        e = _x(db, eid, user, level)
        getattr(exp_svc, fn_name)(db, e, user)
        db.commit()
        return {"data": {"id": e.id, "status": e.status, "result": e.result}}
    return endpoint


for _name, _lvl, _dep in (("submit", "analyst", Analyst), ("approve", "approver", Approver), ("reject", "approver", Approver),
                          ("run", "analyst", Analyst), ("rollback", "analyst", Analyst)):
    router.add_api_route(f"/experiments/{{eid}}/{_name}", _exp_action(_name, _lvl, _dep), methods=["POST"], response_model=Data,
                         operation_id=f"experiment_{_name}")


class ClassifyBody(BaseModel):
    classification: str
    rationale: str = Field(default="", max_length=10000)
    severity: Optional[str] = None


@router.post("/findings/{fid}/classify", response_model=Data, operation_id="classify_finding")
def classify(fid: str, body: ClassifyBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    f = db.get(Finding, fid, with_for_update=True)
    if not f:
        raise ApiError(404, "not_found", "Finding not found")
    access.require(db, user, f.assessment_id, "approver" if body.classification == "confirmed_vulnerability" else "analyst")
    if body.classification not in E.CLASSIFICATIONS:
        raise ApiError(422, "invalid_value", f"classification must be one of {E.CLASSIFICATIONS}")
    if body.severity and body.severity not in E.SEVERITIES:
        raise ApiError(422, "invalid_value", f"severity must be one of {E.SEVERITIES}")
    find_svc.validate_classification(db, f, body.classification, body.rationale, user, body.severity)
    db.commit()
    return {"data": {"id": f.id, "classification": f.classification, "severity": f.severity}}


class VerifyBody(BaseModel):
    status: str = "verified"


@router.post("/evidence/{eid}/verify", response_model=Data, operation_id="verify_evidence")
def verify(eid: str, body: VerifyBody, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    ev = db.get(Evidence, eid)
    if not ev:
        raise ApiError(404, "not_found", "Evidence not found")
    access.require(db, user, ev.assessment_id, "analyst")
    if body.status not in ("verified", "disputed", "unverified"):
        raise ApiError(422, "invalid_value", "status must be verified|disputed|unverified")
    find_svc.verify_evidence(db, ev, user, body.status)
    db.commit()
    return {"data": {"id": ev.id, "verification_status": ev.verification_status}}


@router.post("/assessments/{aid}/reports", response_model=Data, status_code=201, operation_id="generate_report")
def gen_report(aid: str, db: Session = Depends(get_db), user: User = Depends(Analyst)):
    access.require(db, user, aid, "analyst")
    r = reporting.build(db, aid, user.id)
    audit(db, actor_id=user.id, action="report.generate", resource_type="report", resource_id=r.id, assessment_id=aid)
    db.commit()
    return {"data": {"id": r.id, "content": r.content}}


@router.get("/reports/{rid}/html", response_class=HTMLResponse, operation_id="report_html")
def report_html(rid: str, db: Session = Depends(get_db), user: User = Depends(Viewer)):
    r = db.get(Report, rid)
    if not r:
        raise ApiError(404, "not_found", "Report not found")
    access.require(db, user, r.assessment_id, "viewer")
    return HTMLResponse(reporting.render_html(r))
