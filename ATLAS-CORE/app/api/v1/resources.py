from datetime import datetime
from typing import Annotated, Any, Optional
from pydantic import Field
from fastapi import APIRouter
from sqlalchemy import select
from app.api.v1.crud import crud_router
from app.core import enums as E
from app.core.enums import ROLE_LEVEL
from app.core.errors import ApiError
from app.core.security import encrypt_secret
from app.models import (ApiEndpoint, ApplicationRoute, Assessment, Asset, DatabaseSchema, DatabaseTable, Evidence,
                        Experiment, Finding, Hypothesis, Observation, Report, ScopeRule, Target, Technology)
from app.services import experiments as exp_svc, findings as find_svc, normalize, scope

O = Optional


def _assessment(db, aid):
    a = db.get(Assessment, aid)
    if not a:
        raise ApiError(404, "not_found", "Assessment not found")
    return a


def _choice(v, allowed, name):
    if v not in allowed:
        raise ApiError(422, "invalid_value", f"{name} must be one of {allowed}")


# ---- targets
def target_before_create(db, d, user):
    d["created_by"] = user.id
    c = d.pop("credentials", None)
    d["credentials_encrypted"] = encrypt_secret(c) if c else None


def target_before_update(db, obj, d, user):
    if any(k.startswith("authorization") for k in d) and ROLE_LEVEL[user.role] < ROLE_LEVEL["approver"]:
        raise ApiError(403, "authorization_edit_forbidden", "Only an approver or admin may change a target's authorization record")
    if "credentials" in d:
        c = d.pop("credentials")
        obj.credentials_encrypted = encrypt_secret(c) if c else None


TARGET_FIELDS = {"name": (str, ...), "base_domain": (str, ...), "organization": (O[str], None), "description": (O[str], None),
                 "authorization_reference": (O[str], None), "authorized_by": (O[str], None),
                 "authorization_document": (O[str], None), "authorization_valid_from": (O[datetime], None),
                 "authorization_valid_until": (O[datetime], None), "credentials": (O[Annotated[str, Field(max_length=4096)]], None)}
targets = crud_router("targets", Target, "Target", TARGET_FIELDS, list(TARGET_FIELDS), ["name", "base_domain"],
                      hidden=("credentials_encrypted",), before_create=target_before_create, before_update=target_before_update)


# ---- assessments
def assessment_before_create(db, d, user):
    if not db.get(Target, d["target_id"]):
        raise ApiError(404, "not_found", "Target not found")
    _choice(d["environment"], E.ENVIRONMENTS, "environment")
    d.update(created_by=user.id, owner_id=user.id, status="draft", status_history=[])


assessments = crud_router("assessments", Assessment, "Assessment",
                          {"target_id": (str, ...), "name": (str, ...), "description": (O[str], None), "environment": (str, "staging")},
                          ["name", "description"], ["target_id", "status", "environment"], before_create=assessment_before_create)


# ---- scope rules
def rule_before_create(db, d, user):
    _assessment(db, d["assessment_id"])
    _choice(d["rule_type"], E.RULE_TYPES, "rule_type"); _choice(d["match_type"], E.MATCH_TYPES, "match_type")
    d["value"] = scope.validate_rule_value(d["match_type"], d["value"])


def reclass(db, obj):
    scope.reclassify_assets(db, obj.assessment_id)


scope_rules = crud_router("scope-rules", ScopeRule, "ScopeRule",
                          {"assessment_id": (str, ...), "rule_type": (str, ...), "match_type": (str, ...), "value": (str, ...), "note": (O[str], None)},
                          None, ["assessment_id", "rule_type", "match_type"], before_create=rule_before_create, after_change=reclass,
                          write_role="approver", delete_role="approver", assessment_level="approver")


# ---- assets (scope_state is computed, never client supplied)
def asset_before_create(db, d, user):
    _assessment(db, d["assessment_id"]); _choice(d["asset_type"], E.ASSET_TYPES, "asset_type")
    d["value"] = d["value"].strip().lower()
    d["scope_state"], _ = scope.classify(db, d["assessment_id"], d["value"])


assets = crud_router("assets", Asset, "Asset",
                     {"assessment_id": (str, ...), "asset_type": (str, ...), "value": (str, ...),
                      "discovery_source": (str, "manual"), "details": (dict, {})},
                     None, ["assessment_id", "asset_type", "scope_state", "value"], before_create=asset_before_create)


# ---- technologies (evidence mandatory)
def tech_before_create(db, d, user):
    _assessment(db, d["assessment_id"]); normalize.require_evidence(db, d["assessment_id"], [d["evidence_id"]])
    _choice(d["confidence"], E.CONFIDENCE, "confidence")


technologies = crud_router("technologies", Technology, "Technology",
                           {"assessment_id": (str, ...), "asset_id": (O[str], None), "evidence_id": (str, ...), "name": (str, ...),
                            "version": (O[str], None), "category": (str, "unknown"), "confidence": (str, "medium")},
                           None, ["assessment_id", "asset_id", "name", "category"], before_create=tech_before_create)


# ---- observations (creates backing evidence automatically)
def obs_create(db, d, user):
    _assessment(db, d["assessment_id"])
    _choice(d["kind"], ["direct_observation", "inference", "hypothesis", "unknown"], "kind")
    _choice(d["confidence"], E.CONFIDENCE, "confidence")
    if d["kind"] != "unknown" and not d["evidence_reference"].strip():
        raise ApiError(422, "evidence_required", "evidence_reference is required")
    if d["kind"] == "unknown":
        o = Observation(assessment_id=d["assessment_id"], asset_id=d.get("asset_id"), category=d["category"], kind="unknown",
                        description=d["description"], collection_source=d["collection_source"], evidence_reference="", confidence="low")
        db.add(o); db.flush(); return o
    return normalize.record(db, assessment_id=d["assessment_id"], asset_id=d.get("asset_id"), category=d["category"],
                            description=d["description"], source=d["collection_source"], reference=d["evidence_reference"],
                            payload=d.get("evidence_payload") or {}, confidence=d["confidence"], kind=d["kind"])


observations = crud_router("observations", Observation, "Observation",
                           {"assessment_id": (str, ...), "asset_id": (O[str], None), "category": (str, ...), "description": (str, ...),
                            "collection_source": (str, "manual"), "evidence_reference": (str, ""), "evidence_payload": (O[dict], None),
                            "confidence": (str, "medium"), "kind": (str, "direct_observation")},
                           None, ["assessment_id", "asset_id", "category", "kind", "confidence", "verification_status"],
                           custom_create=obs_create, allow_delete=False)

evidence = crud_router("evidence", Evidence, "Evidence", None, None,
                       ["assessment_id", "asset_id", "category", "collection_source", "verification_status"], allow_delete=False)
# evidence is immutable & created only through collectors/observations

# ---- read-only intelligence tables
routes = crud_router("application-routes", ApplicationRoute, "ApplicationRoute", None, None,
                     ["assessment_id", "method", "framework", "auth_required"], allow_delete=False)
apis = crud_router("apis", ApiEndpoint, "ApiEndpoint", None, None, ["assessment_id", "asset_id", "method", "documented"], allow_delete=False)
databases = crud_router("databases", DatabaseSchema, "DatabaseSchema", None, None, ["assessment_id", "technology"], allow_delete=False)
db_tables = crud_router("database-tables", DatabaseTable, "DatabaseTable", None, None, ["schema_id", "sensitivity"], allow_delete=False)


# ---- hypotheses
def hyp_before_create(db, d, user):
    _assessment(db, d["assessment_id"]); _choice(d["confidence"], E.CONFIDENCE, "confidence")
    if not d["supporting_evidence_ids"]:
        raise ApiError(422, "evidence_required", "A hypothesis must cite supporting evidence")
    normalize.require_evidence(db, d["assessment_id"], d["supporting_evidence_ids"])
    d.update(origin="manual", status="open")


def hyp_before_update(db, obj, d, user):
    if "status" in d:
        _choice(d["status"], E.HYP_STATUS, "status")


HYP = {"assessment_id": (str, ...), "category": (str, ...), "title": (str, ...), "reasoning": (str, ...),
       "supporting_evidence_ids": (list[str], ...), "assumptions": (list[str], []), "missing_evidence": (list[str], []),
       "confidence": (str, "low"), "safe_validation_approach": (str, ...)}
hypotheses = crud_router("hypotheses", Hypothesis, "Hypothesis", HYP, ["reasoning", "assumptions", "missing_evidence", "confidence", "status"],
                         ["assessment_id", "category", "status", "confidence", "origin"], before_create=hyp_before_create,
                         before_update=hyp_before_update)


# ---- experiments (no PATCH; lifecycle endpoints only)
experiments = crud_router("experiments", Experiment, "Experiment",
                          {"assessment_id": (str, ...), "hypothesis_id": (O[str], None), "experiment_type": (str, ...),
                           "parameters": (dict, ...), "synthetic_data": (dict, {}), "rate_limit_per_minute": (int, 6),
                           "max_requests": (int, 3), "rollback_plan": (str, ...)},
                          None, ["assessment_id", "hypothesis_id", "status", "experiment_type"],
                          custom_create=lambda db, d, u: exp_svc.create(db, d, u), allow_delete=False)


# ---- findings
def finding_create(db, d, user):
    _assessment(db, d["assessment_id"])
    if d["classification"] == "confirmed_vulnerability":
        raise ApiError(422, "use_classify", "Create as potential_vulnerability, then POST /findings/{id}/classify to confirm")
    if d.get("severity"):
        _choice(d["severity"], E.SEVERITIES, "severity")
    _choice(d["classification"], E.CLASSIFICATIONS, "classification")
    f = Finding(**d)
    find_svc.validate_classification(db, f, d["classification"], d.get("rationale", ""), user, d.get("severity"))
    db.add(f); db.flush()
    return f


findings = crud_router("findings", Finding, "Finding",
                       {"assessment_id": (str, ...), "hypothesis_id": (O[str], None), "title": (str, ...), "description": (str, ""),
                        "classification": (str, "insufficient_evidence"), "severity": (O[str], None),
                        "evidence_ids": (list[str], []), "rationale": (str, "")},
                       None, ["assessment_id", "classification", "severity", "hypothesis_id"], custom_create=finding_create)

reports = crud_router("reports", Report, "Report", None, None, ["assessment_id", "format"], allow_delete=False)

resource_routers = [targets, assessments, scope_rules, assets, technologies, observations, evidence, routes, apis,
                    databases, db_tables, hypotheses, experiments, findings, reports]
