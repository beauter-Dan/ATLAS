import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core import enums as E
from app.db.session import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


def _id():
    return mapped_column(String(36), primary_key=True, default=uid)


def _ts():
    return mapped_column(DateTime(timezone=True), default=now)


def _fk(table, nullable=False):
    return mapped_column(String(36), ForeignKey(f"{table}.id", ondelete="CASCADE"),
                         nullable=nullable, index=True)


def _in(table, col, values):
    vals = ", ".join(repr(v) for v in values)
    return CheckConstraint(f"{col} IN ({vals})", name=f"ck_{table}_{col}")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _id()
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mfa_last_step: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (_in("users", "role", E.ROLES),)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = _id()
    name: Mapped[str] = mapped_column(String(200), unique=True)
    base_domain: Mapped[str] = mapped_column(String(255))
    organization: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authorization_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorization_document: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authorization_valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    credentials_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = _ts()


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = _id()
    target_id: Mapped[str] = _fk("targets")
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    environment: Mapped[str] = mapped_column(String(20), default="staging")
    status_history: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    owner_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = _ts()
    target = relationship("Target")
    __table_args__ = (_in("assessments", "status", E.ASSESSMENT_STATUS),
                      _in("assessments", "environment", E.ENVIRONMENTS))


class ScopeRule(Base):
    __tablename__ = "scope_rules"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    rule_type: Mapped[str] = mapped_column(String(20))
    match_type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(500))
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("assessment_id", "rule_type", "match_type", "value"),
                      _in("scope_rules", "rule_type", E.RULE_TYPES),
                      _in("scope_rules", "match_type", E.MATCH_TYPES))


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    asset_type: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(500))
    scope_state: Mapped[str] = mapped_column(String(20), default="discovered")
    discovery_source: Mapped[str] = mapped_column(String(100), default="manual")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("assessment_id", "asset_type", "value"),
                      _in("assets", "asset_type", E.ASSET_TYPES),
                      _in("assets", "scope_state", E.SCOPE_STATES))


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    asset_id: Mapped[Optional[str]] = _fk("assets", nullable=True)
    category: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    collection_source: Mapped[str] = mapped_column(String(100))
    reference: Mapped[str] = mapped_column(String(1000))
    content_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    verification_status: Mapped[str] = mapped_column(String(15), default="unverified")
    verified_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    timestamp: Mapped[datetime] = _ts()
    __table_args__ = (_in("evidence", "confidence", E.CONFIDENCE),
                      _in("evidence", "verification_status", E.VERIFICATION))


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    asset_id: Mapped[Optional[str]] = _fk("assets", nullable=True)
    evidence_id: Mapped[Optional[str]] = _fk("evidence", nullable=True)
    category: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(25), default="direct_observation")
    description: Mapped[str] = mapped_column(Text)
    collection_source: Mapped[str] = mapped_column(String(100))
    evidence_reference: Mapped[str] = mapped_column(String(1000), default="")
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    verification_status: Mapped[str] = mapped_column(String(15), default="unverified")
    timestamp: Mapped[datetime] = _ts()
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (_in("observations", "kind", E.OBS_KINDS),
                      _in("observations", "confidence", E.CONFIDENCE),
                      _in("observations", "verification_status", E.VERIFICATION),
                      CheckConstraint("kind = 'unknown' OR evidence_id IS NOT NULL",
                                      name="ck_observations_evidence_required"))


class Technology(Base):
    __tablename__ = "technologies"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    asset_id: Mapped[Optional[str]] = _fk("assets", nullable=True)
    evidence_id: Mapped[str] = _fk("evidence")
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    category: Mapped[str] = mapped_column(String(50), default="unknown")
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (_in("technologies", "confidence", E.CONFIDENCE),)


class Relationship(Base):
    __tablename__ = "relationships"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    source_asset_id: Mapped[str] = _fk("assets")
    target_asset_id: Mapped[str] = _fk("assets")
    relation_type: Mapped[str] = mapped_column(String(50))
    evidence_id: Mapped[str] = _fk("evidence")
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    crosses_trust_boundary: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("assessment_id", "source_asset_id", "target_asset_id", "relation_type"),
                      _in("relationships", "confidence", E.CONFIDENCE))


class ApplicationRoute(Base):
    __tablename__ = "application_routes"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    evidence_id: Mapped[str] = _fk("evidence")
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    framework: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    source_file: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)  # None = unknown
    created_at: Mapped[datetime] = _ts()


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    asset_id: Mapped[Optional[str]] = _fk("assets", nullable=True)
    evidence_id: Mapped[str] = _fk("evidence")
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    documented: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_scheme: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _ts()


class DatabaseSchema(Base):
    __tablename__ = "database_schemas"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    evidence_id: Mapped[str] = _fk("evidence")
    name: Mapped[str] = mapped_column(String(200))
    technology: Mapped[str] = mapped_column(String(50), default="unknown")
    technology_confidence: Mapped[str] = mapped_column(String(10), default="low")
    source: Mapped[str] = mapped_column(String(50), default="schema_export")
    created_at: Mapped[datetime] = _ts()


class DatabaseTable(Base):
    __tablename__ = "database_tables"
    id: Mapped[str] = _id()
    schema_id: Mapped[str] = _fk("database_schemas")
    name: Mapped[str] = mapped_column(String(200))
    columns: Mapped[list] = mapped_column(JSON, default=list)
    primary_key: Mapped[list] = mapped_column(JSON, default=list)
    foreign_keys: Mapped[list] = mapped_column(JSON, default=list)
    ownership_columns: Mapped[list] = mapped_column(JSON, default=list)
    sensitivity: Mapped[str] = mapped_column(String(20), default="internal")
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("schema_id", "name"),)


class Hypothesis(Base):
    __tablename__ = "hypotheses"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    category: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(300))
    reasoning: Mapped[str] = mapped_column(Text)
    supporting_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    assumptions: Mapped[list] = mapped_column(JSON, default=list)
    missing_evidence: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[str] = mapped_column(String(10), default="low")
    safe_validation_approach: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(25), default="open")
    origin: Mapped[str] = mapped_column(String(30), default="manual")
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("assessment_id", "title"),
                      _in("hypotheses", "confidence", E.CONFIDENCE),
                      _in("hypotheses", "status", E.HYP_STATUS))


class Experiment(Base):
    __tablename__ = "experiments"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    hypothesis_id: Mapped[Optional[str]] = _fk("hypotheses", nullable=True)
    experiment_type: Mapped[str] = mapped_column(String(40))
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    synthetic_data: Mapped[dict] = mapped_column(JSON, default=dict)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=6)
    max_requests: Mapped[int] = mapped_column(Integer, default=3)
    rollback_plan: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    requested_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (_in("experiments", "status", E.EXP_STATUS),
                      _in("experiments", "experiment_type", E.EXP_TYPES),
                      CheckConstraint("rate_limit_per_minute BETWEEN 1 AND 30", name="ck_experiments_rate"),
                      CheckConstraint("max_requests BETWEEN 1 AND 5", name="ck_experiments_max"))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    hypothesis_id: Mapped[Optional[str]] = _fk("hypotheses", nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    classification: Mapped[str] = mapped_column(String(30), default="insufficient_evidence")
    severity: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    classified_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (_in("findings", "classification", E.CLASSIFICATIONS),)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    format: Mapped[str] = mapped_column(String(10), default="json")
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()


class AuditLog(Base):
    """Append-only. No FKs so history survives deletions."""
    __tablename__ = "audit_logs"
    id: Mapped[str] = _id()
    timestamp: Mapped[datetime] = _ts()
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(60))
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    assessment_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class AssessmentMember(Base):
    __tablename__ = "assessment_members"
    id: Mapped[str] = _id()
    assessment_id: Mapped[str] = _fk("assessments")
    user_id: Mapped[str] = _fk("users")
    permission: Mapped[str] = mapped_column(String(15), default="viewer")
    added_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("assessment_id", "user_id"), _in("assessment_members", "permission", E.MEMBER_PERMISSIONS))


class AuthSession(Base):
    """Opaque, revocable tokens. Only SHA-256 hashes are stored."""
    __tablename__ = "auth_sessions"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = _fk("users")
    access_hash: Mapped[str] = mapped_column(String(64), unique=True)
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prev_refresh_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    refresh_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = _ts()


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = _fk("users")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
