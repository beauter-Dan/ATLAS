"""Controlled, non-destructive experiments. Only whitelisted read-only types exist."""
import re, time
from datetime import datetime, timezone
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.enums import ROLE_LEVEL
from app.core.errors import ApiError
from app.models import Assessment, Experiment, Hypothesis, User
from app.services import collectors, netguard, normalize, scope
from app.services.audit import audit

ALLOWED_HEADERS = {"accept", "user-agent", "x-request-id", "accept-language"}
FORBIDDEN_PARAM_KEYS = re.compile(r"password|secret|token|cookie|authorization|api[_-]?key|session", re.I)
SYNTH_EMAIL = re.compile(r"^[^@\s]+@([a-z0-9\-]+\.)*(test|example|invalid|localhost|example\.(com|org|net))$", re.I)
EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.I)
LONG_DIGITS = re.compile(r"\b\d{9,19}\b")


def validate_synthetic(data) -> None:
    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if FORBIDDEN_PARAM_KEYS.search(str(k)):
                    raise ApiError(422, "unsafe_synthetic_data", f"Key '{k}' not allowed in synthetic data")
                walk(x)
        elif isinstance(v, list):
            [walk(x) for x in v]
        elif isinstance(v, str):
            for m in re.finditer(r"[^@\s]+@[^@\s]+", v):
                if not SYNTH_EMAIL.match(m.group(0)):
                    raise ApiError(422, "unsafe_synthetic_data", "Emails must use reserved domains (.test, example.*)")
            if LONG_DIGITS.search(v):
                raise ApiError(422, "unsafe_synthetic_data", "Long digit sequences (card/ID-like) are not allowed")
    walk(data or {})


def validate_params(db: Session, a: Assessment, etype: str, params: dict) -> None:
    if FORBIDDEN_PARAM_KEYS.search(" ".join(params.keys())):
        raise ApiError(422, "unsafe_parameters", "Credentials/session material cannot be experiment parameters")
    url = params.get("url")
    if not url or not url.startswith(("http://", "https://")):
        raise ApiError(422, "invalid_parameters", "parameters.url (absolute http/https URL) is required")
    if params.get("method", "GET").upper() not in ("GET", "HEAD"):
        raise ApiError(422, "invalid_parameters", "Only GET/HEAD are permitted (non-destructive)")
    bad = [h for h in params.get("headers", {}) if h.lower() not in ALLOWED_HEADERS]
    if bad:
        raise ApiError(422, "invalid_parameters", f"Headers not allowed: {bad}")
    if etype == "header_review" and not params.get("headers_of_interest"):
        raise ApiError(422, "invalid_parameters", "headers_of_interest is required for header_review")


def create(db: Session, data: dict, user: User) -> Experiment:
    a = db.get(Assessment, data["assessment_id"])
    if not a:
        raise ApiError(404, "not_found", "Assessment not found")
    if not (data.get("rollback_plan") or "").strip():
        raise ApiError(422, "rollback_required", "A rollback plan is required")
    validate_params(db, a, data["experiment_type"], data.get("parameters") or {})
    validate_synthetic(data.get("synthetic_data"))
    if data.get("hypothesis_id"):
        h = db.get(Hypothesis, data["hypothesis_id"])
        if not h or h.assessment_id != a.id:
            raise ApiError(422, "invalid_hypothesis", "Hypothesis not in this assessment")
    if a.environment == "production":
        data["max_requests"] = min(data.get("max_requests", 3), 3)
        data["rate_limit_per_minute"] = min(data.get("rate_limit_per_minute", 6), 6)
    ctx = netguard.ScopeContext(user.id, "experiment_create", collectors.get_transports())
    data["parameters"] = {**data["parameters"], "url": netguard.require_url(db, a.id, data["parameters"]["url"], ctx)}
    ctx.flush(db, a.id)
    e = Experiment(**data, requested_by=user.id, status="draft")
    db.add(e); db.flush()
    audit(db, actor_id=user.id, action="experiment.create", resource_type="experiment", resource_id=e.id, assessment_id=a.id)
    return e


def _transition(db, e: Experiment, user, frm: set, to: str, action: str):
    if e.status not in frm:
        raise ApiError(409, "invalid_state", f"Cannot {action} an experiment in state '{e.status}'")
    prev, e.status = e.status, to
    audit(db, actor_id=user.id, action=f"experiment.{action}", resource_type="experiment", resource_id=e.id,
          assessment_id=e.assessment_id, details={"from": prev, "to": to})


def submit(db, e, user):
    _transition(db, e, user, {"draft"}, "pending_approval", "submit")


def approve(db, e, user):
    if ROLE_LEVEL[user.role] < ROLE_LEVEL["approver"]:
        raise ApiError(403, "forbidden", "Approver role required")
    if e.requested_by == user.id:
        raise ApiError(403, "separation_of_duties", "Requester cannot approve their own experiment")
    _transition(db, e, user, {"pending_approval"}, "approved", "approve")
    e.approved_by, e.approved_at = user.id, datetime.now(timezone.utc)


def reject(db, e, user):
    if ROLE_LEVEL[user.role] < ROLE_LEVEL["approver"]:
        raise ApiError(403, "forbidden", "Approver role required")
    _transition(db, e, user, {"pending_approval"}, "rejected", "reject")


def run(db: Session, e: Experiment, user: User):
    if e.status != "approved" or not e.approved_by:
        raise ApiError(409, "approval_required", "Experiment must be approved by a human before it can run")
    a = db.get(Assessment, e.assessment_id)
    url = e.parameters["url"]
    ctx = netguard.ScopeContext(user.id, "experiment_run", collectors.get_transports())
    netguard.require_url(db, a.id, url, ctx)  # scope/authorization re-checked NOW; raises (and audits) if denied
    _transition(db, e, user, {"approved"}, "running", "run")
    e.started_at = datetime.now(timezone.utc)
    gap = 60.0 / e.rate_limit_per_minute if get_settings().env != "test" else 0
    results = []
    try:
        for i in range(1 if e.experiment_type == "header_review" else e.max_requests):
            if i:
                time.sleep(gap)
            r = netguard.safe_fetch(db, a.id, url, ctx, max_redirects=0)  # never follows redirects in experiments
            if r.get("blocked"):
                raise RuntimeError(f"blocked mid-run: {r['reason']}")
            results.append({"status": r["status"], "headers": r["headers"], "redirect": r.get("redirect")})
        if e.experiment_type == "header_review":
            want = [h.lower() for h in e.parameters["headers_of_interest"]]
            e.result = {"requests": 1, "present": {h: results[0]["headers"].get(h) for h in want if h in results[0]["headers"]},
                        "absent": [h for h in want if h not in results[0]["headers"]]}
        else:
            e.result = {"requests": len(results), "statuses": [r["status"] for r in results]}
        if results[0]["redirect"]:
            e.result["redirect"] = results[0]["redirect"]
        e.status = "completed"
        ob = normalize.record(db, assessment_id=a.id, asset_id=None, category="experiment_result",
                              source=f"experiment:{e.id}", reference=f"{e.parameters.get('method', 'GET')} {netguard.safe_url(url)}",
                              confidence="high", description=f"Experiment {e.id} ({e.experiment_type}) result: {e.result}",
                              payload=e.result)
        e.result = {**e.result, "evidence_id": ob.evidence_id}
    except Exception as ex:
        e.status, e.result = "failed", {"error": f"{type(ex).__name__}: {ex}"}
    ctx.flush(db, a.id)
    e.finished_at = datetime.now(timezone.utc)
    audit(db, actor_id=user.id, action="experiment.finish", resource_type="experiment", resource_id=e.id,
          assessment_id=a.id, details={"status": e.status})
    if e.hypothesis_id and e.status == "completed":
        h = db.get(Hypothesis, e.hypothesis_id)
        if h and h.status == "open":
            h.status = "experiment_planned"


def rollback(db, e, user):
    _transition(db, e, user, {"approved", "running", "completed", "failed"}, "rolled_back", "rollback")
    e.result = {**(e.result or {}), "rollback": "Executed rollback plan: " + e.rollback_plan[:500],
                "note": "Experiments are read-only; rollback records closure and discards synthetic data."}
    e.synthetic_data = {}
