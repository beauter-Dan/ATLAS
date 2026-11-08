"""Scope enforcement. Default deny; excludes beat includes; discovery never authorizes."""
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.errors import ApiError, ScopeViolation
from app.models import Asset, Assessment, ScopeRule
from app.services.audit import audit


def redact_url(url: str) -> str:
    """For messages/logs: no query, fragment or userinfo (they may carry tokens)."""
    import re
    u = str(url).split("#")[0].split("?")[0]
    return re.sub(r"//[^/@]*@", "//", u)[:300]


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def normalize_host(value: str) -> str:
    """Host as the HTTP client will see it (lowercase, no port/userinfo/trailing dot, IDNA/punycode)."""
    v = value.strip().lower()
    host = ""
    if "://" in v:
        try:
            import httpx
            host = httpx.URL(v).host
        except Exception:
            host = urlparse(v).hostname or ""
    else:
        host = urlparse("//" + v).hostname or ""
    return _idna(host.rstrip("."))


def validate_rule_value(match_type: str, value: str) -> str:
    v = value.strip().lower()
    if match_type in ("domain", "wildcard"):
        v = _idna(v)
    try:
        if match_type == "domain":
            assert v and "/" not in v and "*" not in v
        elif match_type == "wildcard":
            assert v.startswith("*.") and "*" not in v[2:] and "/" not in v
        elif match_type == "ip":
            ipaddress.ip_address(v)
        elif match_type == "cidr":
            ipaddress.ip_network(v, strict=False)
        elif match_type == "url_prefix":
            assert v.startswith(("http://", "https://"))
    except (AssertionError, ValueError):
        raise ApiError(422, "invalid_scope_rule", f"Invalid value for {match_type}: {value!r}")
    return v.rstrip(".") if match_type in ("domain", "wildcard") else v


def rule_matches(rule: ScopeRule, value: str) -> bool:
    host, rv = normalize_host(value), rule.value.lower()
    if not host:
        return False
    if rule.match_type == "domain":
        return host == rv
    if rule.match_type == "wildcard":
        apex = rv[2:]
        return host.endswith("." + apex) and host != apex
    if rule.match_type == "ip":
        return host == rv
    if rule.match_type == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(rv, strict=False)
        except ValueError:
            return False
    if rule.match_type == "url_prefix":
        v = value.strip().lower()
        if "://" not in v or not v.startswith(rv):
            return False
        # must end on a boundary so https://example.test does not match https://example.test.evil.test
        return len(v) == len(rv) or rv.endswith("/") or v[len(rv)] in "/?#:"
    return False


def classify(db: Session, assessment_id: str, value: str) -> tuple[str, str | None]:
    rules = db.scalars(select(ScopeRule).where(ScopeRule.assessment_id == assessment_id)).all()
    for r in rules:
        if r.rule_type == "exclude" and rule_matches(r, value):
            return "excluded", r.id
    for r in rules:
        if r.rule_type == "include" and rule_matches(r, value):
            return "authorized", r.id
    return "discovered", None


def authorization_ok(target) -> tuple[bool, str]:
    if not target.authorization_reference or not target.authorized_by:
        return False, "Target has no authorization record"
    t = datetime.now(timezone.utc)

    def aware(d):
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    if not target.authorization_valid_from or not target.authorization_valid_until:
        return False, "Authorization validity window missing"
    if t < aware(target.authorization_valid_from):
        return False, "Authorization not yet valid"
    if t > aware(target.authorization_valid_until):
        return False, "Authorization expired"
    return True, "ok"


def check_internal_access(db: Session, assessment_id: str) -> tuple[bool, str]:
    a = db.get(Assessment, assessment_id)
    if not a:
        raise ApiError(404, "not_found", "Assessment not found")
    if a.status != "active":
        return False, f"Assessment is '{a.status}', not active"
    return authorization_ok(a.target)


def check_access(db: Session, assessment_id: str, value: str) -> tuple[bool, str]:
    ok, why = check_internal_access(db, assessment_id)
    if not ok:
        return False, why
    state, _ = classify(db, assessment_id, value)
    if state == "excluded":
        return False, f"{redact_url(value)} is explicitly excluded"
    if state != "authorized":
        return False, f"{redact_url(value)} is not in the authorized scope"
    return True, "ok"


def enforce(db: Session, assessment_id: str, value: str, *, action: str, actor_id=None) -> None:
    ok, why = check_access(db, assessment_id, value)
    if not ok:
        audit(db, actor_id=actor_id, action=f"scope_denied:{action}", resource_type="scope",
              assessment_id=assessment_id, details={"value": redact_url(value), "reason": why},
              outcome="denied", commit=True)
        raise ScopeViolation(why, {"value": redact_url(value), "action": action})


def enforce_internal(db: Session, assessment_id: str, *, action: str, actor_id=None) -> None:
    ok, why = check_internal_access(db, assessment_id)
    if not ok:
        audit(db, actor_id=actor_id, action=f"scope_denied:{action}", resource_type="scope",
              assessment_id=assessment_id, details={"reason": why}, outcome="denied", commit=True)
        raise ScopeViolation(why, {"action": action})


def reclassify_assets(db: Session, assessment_id: str) -> int:
    n = 0
    for a in db.scalars(select(Asset).where(Asset.assessment_id == assessment_id)).all():
        state, _ = classify(db, assessment_id, a.value)
        if state != a.scope_state:
            a.scope_state, n = state, n + 1
    return n
