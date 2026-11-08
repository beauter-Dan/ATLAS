from datetime import datetime, timedelta, timezone
from app.models import Assessment, ScopeRule, Target
from app.services import scope


def mk(db, **tkw):
    now = datetime.now(timezone.utc)
    t = Target(name="t", base_domain="example.test", authorization_reference="A", authorized_by="B",
               authorization_valid_from=now - timedelta(days=1), authorization_valid_until=now + timedelta(days=1), **tkw)
    db.add(t); db.flush()
    a = Assessment(target_id=t.id, name="a", status="active"); db.add(a); db.flush()
    return t, a


def rules(db, a, *rs):
    for rt, mt, v in rs:
        db.add(ScopeRule(assessment_id=a.id, rule_type=rt, match_type=mt, value=v))
    db.flush()


def test_default_deny_and_precedence(db_session):
    t, a = mk(db_session)
    rules(db_session, a, ("include", "wildcard", "*.example.test"), ("exclude", "domain", "admin.example.test"),
          ("include", "cidr", "203.0.113.0/24"))
    c = lambda v: scope.classify(db_session, a.id, v)[0]  # noqa: E731
    assert c("www.example.test") == "authorized"
    assert c("https://www.example.test:8443/x") == "authorized"
    assert c("example.test") == "discovered"          # wildcard excludes apex
    assert c("admin.example.test") == "excluded"
    assert c("evil-example.test") == "discovered"
    assert c("203.0.113.9") == "authorized" and c("198.51.100.1") == "discovered"


def test_url_prefix_exclusion(db_session):
    t, a = mk(db_session)
    rules(db_session, a, ("include", "domain", "example.test"), ("exclude", "url_prefix", "https://example.test/billing"))
    assert scope.classify(db_session, a.id, "https://example.test/home")[0] == "authorized"
    assert scope.classify(db_session, a.id, "https://example.test/billing/x")[0] == "excluded"


def test_authorization_expiry_and_inactive(db_session):
    t, a = mk(db_session)
    rules(db_session, a, ("include", "domain", "example.test"))
    assert scope.check_access(db_session, a.id, "example.test")[0]
    t.authorization_valid_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert "expired" in scope.check_access(db_session, a.id, "example.test")[1]
    t.authorization_valid_until = datetime.now(timezone.utc) + timedelta(days=1)
    a.status = "paused"
    assert not scope.check_access(db_session, a.id, "example.test")[0]


def test_rule_validation():
    import pytest
    from app.core.errors import ApiError
    with pytest.raises(ApiError):
        scope.validate_rule_value("wildcard", "example.test")
    with pytest.raises(ApiError):
        scope.validate_rule_value("cidr", "nope")
