import json
from app.ai import agents
from app.ai.redact import redact
from app.ai.providers import AIProvider
from app.models import Observation


class Fake(AIProvider):
    name = "fake"

    def __init__(self, stmts):
        self.stmts = stmts

    def complete(self, system, prompt, ctx):
        self.prompt = prompt
        return "```json\n" + json.dumps({"statements": self.stmts}) + "\n```"


def test_redaction():
    t = redact("password=hunter2 key AKIAABCDEFGHIJKLMNOP mail bob@corp.com Bearer abcdefghijklmnop1234 card 4111 1111 1111 1111")
    for s in ("hunter2", "AKIA", "bob@corp.com", "abcdefghijklmnop1234", "4111"):
        assert s not in t


def test_ai_guardrails(client, users, world, fake, db_session):
    H = users["analyst"]["h"]
    client.post(f"/api/v1/assessments/{world['aid']}/collect", headers=H, json={"hosts": ["example.test"], "collectors": ["dns"]})
    ev = db_session.query(Observation).filter_by(assessment_id=world["aid"]).first().evidence_id
    p = Fake([
        {"text": "Host resolves to a single address", "classification": "inference", "evidence_ids": [ev], "confidence": "high"},
        {"text": "Definitely vulnerable to X", "classification": "confirmed", "evidence_ids": [ev], "confidence": "high"},
        {"text": "Invented fact", "classification": "direct_observation", "evidence_ids": ["bogus"], "confidence": "high"},
        {"text": "We lack WAF info", "classification": "unknown", "evidence_ids": [], "confidence": "low"}])
    r = agents.run_agent(db_session, world["aid"], "security_research", None, provider=p)
    cls = {s["text"]: s for s in r["statements"]}
    assert cls["Definitely vulnerable to X"]["classification"] == "hypothesis"   # AI cannot confirm
    assert cls["Host resolves to a single address"]["confidence"] == "medium"    # capped
    assert [x["text"] for x in r["rejected"]] == ["Invented fact"]               # uncited dropped
    assert "unknown" in {s["classification"] for s in r["statements"]}


def test_null_provider_endpoint(client, users, world, fake):
    H = users["analyst"]["h"]
    client.post(f"/api/v1/assessments/{world['aid']}/collect", headers=H, json={"hosts": ["example.test"], "collectors": ["dns", "rdap"]})
    r = client.post(f"/api/v1/assessments/{world['aid']}/ai/reconnaissance", headers=H)
    assert r.status_code == 200 and r.json()["data"]["statements"]
    assert client.post(f"/api/v1/assessments/{world['aid']}/ai/nope", headers=H).status_code == 404
