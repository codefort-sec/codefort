"""SQLAlchemy ORM models conforming to CodeFort Database Design (database.md)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict


# 1. Users
class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    github_user_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    login: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    memberships: Mapped[List["Membership"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    extension_credentials: Mapped[List["ExtensionCredential"]] = relationship(back_populates="user")


# 2. Organizations
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    github_org_id: Mapped[Optional[int]] = mapped_column(BigInteger, unique=True, nullable=True)
    login: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    memberships: Mapped[List["Membership"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    repositories: Mapped[List["Repository"]] = relationship(back_populates="organization")


# 3. Memberships
class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(30), nullable=False, default="MEMBER")  # OWNER, ADMIN, MEMBER, VIEWER

    user: Mapped["User"] = relationship(back_populates="memberships")
    organization: Mapped["Organization"] = relationship(back_populates="memberships")


# 4. Repositories
class Repository(Base, TimestampMixin):
    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    github_repo_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    owner_login: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    installation_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    is_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    organization: Mapped[Optional["Organization"]] = relationship(back_populates="repositories")
    pull_requests: Mapped[List["PullRequest"]] = relationship(back_populates="repository", cascade="all, delete-orphan")
    scans: Mapped[List["Scan"]] = relationship(back_populates="repository", cascade="all, delete-orphan")
    incidents: Mapped[List["Incident"]] = relationship(back_populates="repository")


# 5. Pull Requests
class PullRequest(Base, TimestampMixin):
    __tablename__ = "pull_requests"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)
    github_pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    author_login: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    head_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    base_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="open")
    html_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    repository: Mapped["Repository"] = relationship(back_populates="pull_requests")
    scans: Mapped[List["Scan"]] = relationship(back_populates="pull_request", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_pull_requests_repo_pr", "repository_id", "github_pr_number", unique=True),
    )


# 6. Scans
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)
    pull_request_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=True)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default=ScanStatus.QUEUED.value)
    verdict: Mapped[str] = mapped_column(String(30), default=Verdict.SCAN_PENDING.value)
    risk_score: Mapped[Optional[int]] = mapped_column(SmallInteger, nullable=True)
    scoring_version: Mapped[Optional[str]] = mapped_column(String(40), default="1.0.0")
    coverage_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    summary_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    repository: Mapped["Repository"] = relationship(back_populates="scans")
    pull_request: Mapped[Optional["PullRequest"]] = relationship(back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    evidence_items: Mapped[List["Evidence"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    telemetry_events: Mapped[List["TelemetryEvent"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    patches: Mapped[List["Patch"]] = relationship(back_populates="scan")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="chk_risk_score_range"),
        Index("ix_scans_repo_created", "repository_id", created_at.desc()),
        Index("ix_scans_pr_created", "pull_request_id", created_at.desc()),
    )


# 7. Findings
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Numeric(4, 3), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    line_start: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    evidence: Mapped[Optional["Evidence"]] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )


# 8. Evidence
class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # STATIC, DEPENDENCY, WORKFLOW, SANDBOX, MODEL
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details_redacted: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    artifact_uri: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan: Mapped["Scan"] = relationship(back_populates="evidence_items")
    findings: Mapped[List["Finding"]] = relationship(back_populates="evidence")


# 9. Telemetry Events
class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)  # PROCESS, NETWORK, FILE, SYSCALL
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_host: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_path_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details_redacted: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="telemetry_events")

    __table_args__ = (
        Index("ix_telemetry_scan_occurred", "scan_id", occurred_at),
    )


# 10. Patches
class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT")  # DRAFT, VALIDATING, READY, REJECTED, APPLIED
    diff_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    validation_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan: Mapped["Scan"] = relationship(back_populates="patches")


# 11. Incidents
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    repository: Mapped["Repository"] = relationship(back_populates="incidents")


# 12. Audit Events
class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    metadata_redacted: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# 13. Webhook Deliveries
class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    github_delivery_id: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    event_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="PROCESSED")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


# 14. Extension Credentials
class ExtensionCredential(Base):
    __tablename__ = "extension_credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    scopes: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user: Mapped["User"] = relationship(back_populates="extension_credentials")
