"""Create a fully SYNTHETIC assessment (example.test, reserved TLD) using offline fake transports.
Usage: python -m scripts.seed_synthetic [--database-url sqlite:///atlas_demo.db]"""
import argparse, json, os, pathlib, sys

ap = argparse.ArgumentParser()
ap.add_argument("--database-url", default=None)
args = ap.parse_args()
if args.database_url:
    os.environ["ATLAS_DATABASE_URL"] = args.database_url
os.environ.setdefault("ATLAS_COLLECTOR_MIN_INTERVAL_SECONDS", "0")

from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.core.security import hash_password
from app.db.session import Base, get_engine, get_sessionmaker
from alembic import command
from alembic.config import Config
from app.models import AssessmentMember, Finding, ScopeRule, Target, Assessment, User, Hypothesis
from app.services import collectors, experiments, findings, hypotheses, architecture, reporting, app_intel, db_intel

ROOT = pathlib.Path(__file__).resolve().parents[1]
PASSWORD = "SyntheticPass123!"
cfg = Config(str(pathlib.Path(__file__).resolve().parents[1] / "alembic.ini"))
cfg.set_main_option("script_location", str(pathlib.Path(__file__).resolve().parents[1] / "alembic"))
command.upgrade(cfg, "head")          # same migrations as production
db = get_sessionmaker()()


class Synthetic(collectors.Transports):
    def __init__(self):
        self.dns = lambda h: {"A": ["203.0.113.10"], "CNAME": ["cdn.example.test."]}
        self.rdap = lambda d: {"ldhName": d, "status": ["active"], "events": [{"eventAction": "expiration", "eventDate": "2030-01-01"}]}
        self.ct = lambda d: [d, f"api.{d}", f"admin.{d}"]
        self.tls = lambda h, port=443: {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "issuer": "CN=Synthetic CA", "subject": f"CN={h}",
                                        "not_before": "2025-01-01T00:00:00+00:00", "not_after": "2030-01-01T00:00:00+00:00", "san": [h], "verified": True, "verify_error": None}
        self.resolve = lambda h: ["93.184.216.34"]   # synthetic public address (documentation ranges are not "global")
        self.http = self._http

    def _http(self, url):
        if url.endswith("/openapi.json"):
            return {"url": url, "status": 200, "headers": {}, "body": json.dumps({"paths": {
                "/orders/{order_id}": {"get": {"summary": "Get order", "security": [{"bearer": []}]}},
                "/checkout": {"post": {"summary": "Checkout"}}}})}
        if url.endswith(("swagger.json", "api-docs")):
            return {"url": url, "status": 404, "headers": {}, "body": ""}
        return {"url": url, "status": 200, "headers": {"server": "nginx/1.18.0", "via": "1.1 synthetic-proxy", "x-powered-by": "Express", "x-frame-options": "DENY"},
                "body": "<html><head><title>Synthetic Shop</title><script src='https://cdn.thirdparty.test/widget.js'></script></head></html>"}


collectors._transports = Synthetic()
for name, role in (("admin1", "admin"), ("approver1", "approver"), ("approver2", "approver"), ("analyst1", "analyst"), ("viewer1", "viewer")):
    if not db.scalar(select(User).where(User.username == name)):
        db.add(User(username=name, password_hash=hash_password(PASSWORD), role=role))
db.commit()
U = {u.username: u for u in db.scalars(select(User)).all()}

now = datetime.now(timezone.utc)
t = Target(name="Synthetic Shop Ltd", base_domain="example.test", authorization_reference="SYNTH-AUTH-001", authorized_by="Synthetic CISO",
           authorization_valid_from=now - timedelta(days=1), authorization_valid_until=now + timedelta(days=90),
           description="Entirely fictional target for demos/tests", created_by=U["admin1"].id)
db.add(t); db.flush()
a = Assessment(target_id=t.id, name="Synthetic baseline assessment", environment="staging", status="active",
               created_by=U["analyst1"].id, owner_id=U["analyst1"].id)
db.add(a); db.flush()
for name, perm in (("approver1", "approver"), ("approver2", "approver"), ("viewer1", "viewer")):
    db.add(AssessmentMember(assessment_id=a.id, user_id=U[name].id, permission=perm, added_by=U["admin1"].id))
for rt, mt, v in (("include", "domain", "example.test"), ("include", "wildcard", "*.example.test"), ("exclude", "domain", "admin.example.test")):
    db.add(ScopeRule(assessment_id=a.id, rule_type=rt, match_type=mt, value=v))
db.commit()

print("collect:", collectors.run_collection(db, a.id, ["example.test", "admin.example.test"], collectors.ALL_COLLECTORS, U["analyst1"].id))
files = {str(p.relative_to(ROOT / "sample_data/synthetic_app")): p.read_text() for p in (ROOT / "sample_data/synthetic_app/app").rglob("*.py")}
app_intel.persist(db, a.id, files, "synthetic-shop-app")
db_intel.persist(db, a.id, "shop", (ROOT / "sample_data/synthetic_app/schema.sql").read_text(), "postgresql")
architecture.build_relationships(db, a.id)
print("hypotheses:", len(hypotheses.generate(db, a.id)))
db.commit()

hyp = db.scalars(select(Hypothesis).where(Hypothesis.assessment_id == a.id)).first()
e = experiments.create(db, {"assessment_id": a.id, "hypothesis_id": hyp.id, "experiment_type": "header_review",
                            "parameters": {"url": "https://example.test/", "headers_of_interest": ["content-security-policy", "x-frame-options"]},
                            "synthetic_data": {"email": "synthetic.user@example.test"}, "rollback_plan": "Read-only request; no state to restore.",
                            "rate_limit_per_minute": 6, "max_requests": 1}, U["analyst1"])
experiments.submit(db, e, U["analyst1"]); experiments.approve(db, e, U["approver1"]); experiments.run(db, e, U["analyst1"])
f = Finding(assessment_id=a.id, hypothesis_id=hyp.id, title="CSP header not observed", description="Experiment shows no Content-Security-Policy header.",
            evidence_ids=[e.result["evidence_id"]], severity="low")
findings.validate_classification(db, f, "potential_vulnerability", "", U["analyst1"], "low")
db.add(f); db.commit()
rep = reporting.build(db, a.id, U["analyst1"].id); db.commit()
out = ROOT / "sample_data" / "synthetic_report.json"
out.write_text(json.dumps(rep.content, indent=2, default=str))
print(f"assessment={a.id}\nreport -> {out}\nusers: admin1/approver1/approver2/analyst1/viewer1  password: {PASSWORD}")
