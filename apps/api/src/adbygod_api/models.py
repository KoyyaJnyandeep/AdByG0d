from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import CHAR, JSON, TypeDecorator

from adbygod_api.database import Base
from adbygod_api.core.security.at_rest import (
    protect_json_for_db,
    protect_text_for_db,
    reveal_json_from_db,
    reveal_text_from_db,
)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class GUID(TypeDecorator):
    """Platform-independent UUID column."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value if dialect.name == "postgresql" else str(value)
        parsed = uuid.UUID(str(value))
        return parsed if dialect.name == "postgresql" else str(parsed)

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class EncryptedJSON(TypeDecorator):
    """JSON column that stores encrypted wrapper JSON and returns plaintext objects."""

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return protect_json_for_db(value)

    def process_result_value(self, value, dialect):
        return reveal_json_from_db(value)


class EncryptedText(TypeDecorator):
    """Text column encrypted at rest while preserving the Python ``str`` API."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return protect_text_for_db(value)

    def process_result_value(self, value, dialect):
        return reveal_text_from_db(value)


class AssessmentStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CollectionMode(str, enum.Enum):
    LINUX_REMOTE = "LINUX_REMOTE"
    WINDOWS_LOCAL = "WINDOWS_LOCAL"
    WINDOWS_REMOTE = "WINDOWS_REMOTE"
    IMPORT = "IMPORT"
    MANUAL = "MANUAL"


class DataOrigin(str, enum.Enum):
    COLLECTED = "COLLECTED"
    IMPORTED = "IMPORTED"
    INFERRED = "INFERRED"
    SIMULATED = "SIMULATED"


class EntityType(str, enum.Enum):
    USER = "USER"
    GROUP = "GROUP"
    COMPUTER = "COMPUTER"
    DOMAIN = "DOMAIN"
    FOREST = "FOREST"
    OU = "OU"
    GPO = "GPO"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    GMSA = "GMSA"
    DMSA = "DMSA"
    CA = "CA"
    CERT_TEMPLATE = "CERT_TEMPLATE"
    TRUST = "TRUST"
    SITE = "SITE"
    DC = "DC"
    UNKNOWN = "UNKNOWN"


class EdgeType(str, enum.Enum):
    MEMBER_OF = "MEMBER_OF"
    HAS_CONTROL = "HAS_CONTROL"
    GENERIC_ALL = "GENERIC_ALL"
    WRITE_DACL = "WRITE_DACL"
    WRITE_OWNER = "WRITE_OWNER"
    FORCE_CHANGE_PASSWORD = "FORCE_CHANGE_PASSWORD"
    ADD_MEMBER = "ADD_MEMBER"
    ALLOWED_TO_DELEGATE = "ALLOWED_TO_DELEGATE"
    ALLOWED_TO_ACT = "ALLOWED_TO_ACT"
    HAS_SPN = "HAS_SPN"
    CAN_ENROLL = "CAN_ENROLL"
    OWNS = "OWNS"
    CONTAINS = "CONTAINS"
    APPLIES_GPO = "APPLIES_GPO"
    TRUSTS = "TRUSTS"
    LOCAL_ADMIN = "LOCAL_ADMIN"
    CAN_RDP = "CAN_RDP"
    CAN_WINRM = "CAN_WINRM"
    DCSYNC = "DCSYNC"
    ADMIN_TO = "ADMIN_TO"
    READ_LAPS_PASSWORD = "READ_LAPS_PASSWORD"
    READ_GMSA_PASSWORD = "READ_GMSA_PASSWORD"
    WRITE_SPN = "WRITE_SPN"
    ADD_KEY_CREDENTIAL_LINK = "ADD_KEY_CREDENTIAL_LINK"
    WRITE_GP_LINK = "WRITE_GP_LINK"
    WRITE_ACCOUNT_RESTRICTIONS = "WRITE_ACCOUNT_RESTRICTIONS"
    SQL_ADMIN = "SQL_ADMIN"
    HAS_SESSION = "HAS_SESSION"
    MANAGE_CA = "MANAGE_CA"
    MANAGE_CERTIFICATES = "MANAGE_CERTIFICATES"
    CA_PRIVATE_KEY_CONTROL = "CA_PRIVATE_KEY_CONTROL"
    GOLDEN_CERT = "GOLDEN_CERT"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    REMEDIATED = "REMEDIATED"
    ACCEPTED = "ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REGRESSED = "REGRESSED"


def enum_column(enum_cls: type[enum.Enum], length: int | None = None):
    return SAEnum(
        enum_cls,
        values_callable=lambda cls: [item.value for item in cls],
        native_enum=False,
        validate_strings=True,
        length=length,
    )


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    last_login: Mapped[datetime | None] = mapped_column(DateTime)
    tokens_invalidated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    preferences: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, onupdate=_utcnow_naive)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class WorkspaceUser(Base):
    __tablename__ = "workspace_users"
    __table_args__ = (UniqueConstraint("workspace_id", "user_id", name="uq_workspace_users_workspace_user"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("platform_users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class ConnectivityMode(str, enum.Enum):
    DIRECT = "DIRECT"
    SOCKS5 = "SOCKS5"
    CHISEL = "CHISEL"
    LIGOLO = "LIGOLO"
    RELAY_AGENT = "RELAY_AGENT"
    MANAGED_SSH_SOCKS = "MANAGED_SSH_SOCKS"


class ConnectivityProfileStatus(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"


class ConnectivityProfile(Base):
    __tablename__ = "connectivity_profiles"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[ConnectivityMode] = mapped_column(enum_column(ConnectivityMode, 50), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(), default=dict)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[ConnectivityProfileStatus] = mapped_column(
        enum_column(ConnectivityProfileStatus, 20),
        default=ConnectivityProfileStatus.UNKNOWN,
    )
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    created_by: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id"))


class TunnelSessionStatus(str, enum.Enum):
    STARTING = "starting"
    ACTIVE = "active"
    FAILED = "failed"
    STOPPED = "stopped"


class TunnelSession(Base):
    __tablename__ = "tunnel_sessions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("connectivity_profiles.id"), nullable=False)
    mode: Mapped[ConnectivityMode] = mapped_column(enum_column(ConnectivityMode, 50), nullable=False)
    jumpbox_host: Mapped[str] = mapped_column(String(255), nullable=False)
    jumpbox_port: Mapped[int] = mapped_column(Integer, nullable=False)
    jumpbox_username: Mapped[str] = mapped_column(String(255), nullable=False)
    local_host: Mapped[str] = mapped_column(String(50), nullable=False, default="127.0.0.1")
    local_port: Mapped[int] = mapped_column(Integer, nullable=False)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[TunnelSessionStatus] = mapped_column(enum_column(TunnelSessionStatus, 20), nullable=False, default=TunnelSessionStatus.STARTING)
    started_by: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("platform_users.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_healthcheck_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    sanitized_command_preview: Mapped[str] = mapped_column(Text, nullable=False, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("workspaces.id"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    dc_ip: Mapped[str | None] = mapped_column(String(50))
    connectivity_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("connectivity_profiles.id"), nullable=True
    )
    status: Mapped[AssessmentStatus] = mapped_column(enum_column(AssessmentStatus, 50), default=AssessmentStatus.PENDING)
    collection_mode: Mapped[CollectionMode | None] = mapped_column(enum_column(CollectionMode, 50))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    created_by: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id"))
    modules_run: Mapped[list[Any]] = mapped_column(JSON, default=list)
    collection_config: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(), default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    last_message: Mapped[str | None] = mapped_column(String(500))
    previous_assessment_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("assessments.id"))


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    entity_type: Mapped[EntityType] = mapped_column(enum_column(EntityType, 50), nullable=False)
    distinguished_name: Mapped[str | None] = mapped_column(Text)
    object_sid: Mapped[str | None] = mapped_column(String(100))
    sam_account_name: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    dns_hostname: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin_count: Mapped[bool] = mapped_column(Boolean, default=False)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_protected_user: Mapped[bool] = mapped_column(Boolean, default=False)
    tier: Mapped[int | None] = mapped_column(Integer)
    is_crown_jewel: Mapped[bool] = mapped_column(Boolean, default=False)
    business_tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    owner_team: Mapped[str | None] = mapped_column(String(255))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    object_created: Mapped[datetime | None] = mapped_column(DateTime)
    object_modified: Mapped[datetime | None] = mapped_column(DateTime)
    last_logon: Mapped[datetime | None] = mapped_column(DateTime)
    password_last_set: Mapped[datetime | None] = mapped_column(DateTime)


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(50))
    source_host: Mapped[str | None] = mapped_column(String(255))
    source_port: Mapped[int | None] = mapped_column(Integer)
    collection_method: Mapped[str | None] = mapped_column(String(100))
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    is_corroborated: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    origin: Mapped[DataOrigin] = mapped_column(enum_column(DataOrigin, 50), default=DataOrigin.COLLECTED)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("entities.id"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("entities.id"), nullable=False)
    edge_type: Mapped[EdgeType] = mapped_column(enum_column(EdgeType, 100), nullable=False)
    provenance: Mapped[str | None] = mapped_column(Text)
    inheritance_root: Mapped[str | None] = mapped_column(Text)
    risk_weight: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("evidence_records.id"))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    edge_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    edge_provenance_type: Mapped[str] = mapped_column(String(20), default="collected")
    edge_key: Mapped[str | None] = mapped_column(String(64))
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    module: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[SeverityLevel] = mapped_column(enum_column(SeverityLevel, 20), nullable=False)
    technical_severity: Mapped[float | None] = mapped_column(Float)
    reachability_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    asset_criticality: Mapped[float | None] = mapped_column(Float)
    breadth_score: Mapped[float | None] = mapped_column(Float)
    remediation_complexity: Mapped[float | None] = mapped_column(Float)
    composite_score: Mapped[float | None] = mapped_column(Float)
    affected_count: Mapped[int] = mapped_column(Integer, default=0)
    affected_objects: Mapped[list[Any]] = mapped_column(JSON, default=list)
    root_cause: Mapped[str | None] = mapped_column(Text)
    causal_chain: Mapped[list[Any]] = mapped_column(JSON, default=list)
    attack_path: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[FindingStatus] = mapped_column(enum_column(FindingStatus, 50), default=FindingStatus.OPEN)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id"))
    remediation: Mapped[str | None] = mapped_column(Text)
    remediation_steps: Mapped[list[Any]] = mapped_column(JSON, default=list)
    fix_complexity: Mapped[str | None] = mapped_column(String(50))
    estimated_effort: Mapped[str | None] = mapped_column(String(100))
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)
    cve_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    mitre_attack_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    drift_status: Mapped[str | None] = mapped_column(String(50))
    previous_finding_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("findings.id"))
    waiver_reason: Mapped[str | None] = mapped_column(Text)
    waiver_expiry: Mapped[datetime | None] = mapped_column(DateTime)
    waiver_owner: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, onupdate=_utcnow_naive)
    origin: Mapped[DataOrigin] = mapped_column(enum_column(DataOrigin, 50), default=DataOrigin.INFERRED)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (UniqueConstraint("finding_id", "evidence_id", name="uq_finding_evidence_pair"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("findings.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("evidence_records.id"), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(50), default="supports")
    evidence_strength: Mapped[str] = mapped_column(String(50), default="payload_level_fallback")
    relevance: Mapped[str | None] = mapped_column(Text)
    source_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence: Mapped[EvidenceRecord] = relationship()


class ExposurePath(Base):
    __tablename__ = "exposure_paths"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    source_entity_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("entities.id"))
    target_entity_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("entities.id"))
    path_steps: Mapped[list[Any] | None] = mapped_column(JSON)
    hop_count: Mapped[int | None] = mapped_column(Integer)
    path_score: Mapped[float | None] = mapped_column(Float)
    target_tier: Mapped[int | None] = mapped_column(Integer)
    path_type: Mapped[str | None] = mapped_column(String(100))
    explanation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class GraphCentrality(Base):
    __tablename__ = "graph_centrality"
    __table_args__ = (UniqueConstraint("assessment_id", "entity_id", name="uq_graph_centrality"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    betweenness: Mapped[float] = mapped_column(Float, default=0.0)
    degree_centrality: Mapped[float] = mapped_column(Float, default=0.0)
    eigenvector: Mapped[float] = mapped_column(Float, default=0.0)
    pagerank: Mapped[float] = mapped_column(Float, default=0.0)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class GraphLayout(Base):
    __tablename__ = "graph_layout"
    __table_args__ = (UniqueConstraint("assessment_id", "user_id", "layout_name", name="uq_graph_layout"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id", ondelete="SET NULL"))
    layout_name: Mapped[str] = mapped_column(String(128), nullable=False)
    node_positions: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class GraphSnapshot(Base):
    __tablename__ = "graph_snapshot"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id", ondelete="SET NULL"))
    label: Mapped[str | None] = mapped_column(String(256))
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    snapshot_data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class GraphMarkings(Base):
    __tablename__ = "graph_markings"

    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("platform_users.id", ondelete="CASCADE"), primary_key=True)
    owned_ids: Mapped[list] = mapped_column(JSON, default=list)
    high_value_ids: Mapped[list] = mapped_column(JSON, default=list)
    pinned_ids: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, onupdate=_utcnow_naive)


class GraphView(Base):
    __tablename__ = "graph_view"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class AssessmentDiff(Base):
    __tablename__ = "assessment_diffs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    baseline_assessment_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("assessments.id"))
    current_assessment_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("assessments.id"))
    new_findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    resolved_findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    regressed_findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    new_entities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    removed_entities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    score_delta: Mapped[float | None] = mapped_column(Float)
    severity_deltas: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class CertTemplate(Base):
    __tablename__ = "cert_templates"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    distinguished_name: Mapped[str | None] = mapped_column(Text)
    ca_name: Mapped[str | None] = mapped_column(String(255))
    enrollee_supplies_subject: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_manager_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_signatures_required: Mapped[int] = mapped_column(Integer, default=0)
    validity_period: Mapped[str | None] = mapped_column(String(50))
    renewal_period: Mapped[str | None] = mapped_column(String(50))
    ekus: Mapped[list[Any]] = mapped_column(JSON, default=list)
    enrollment_rights: Mapped[list[Any]] = mapped_column(JSON, default=list)
    write_rights: Mapped[list[Any]] = mapped_column(JSON, default=list)
    esc1_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    esc2_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    esc3_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    esc4_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id"))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(50))
    user_agent: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class ChainStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"   # paused — needs cracked creds or user input
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class StartingPosition(str, enum.Enum):
    ANON = "ANON"               # no credentials at all
    DOMAIN_USER = "DOMAIN_USER" # plaintext domain user creds
    HASH_ONLY = "HASH_ONLY"     # NT hash, no plaintext
    LOCAL_ADMIN = "LOCAL_ADMIN" # local admin on a domain-joined box
    SVC_ACCT = "SVC_ACCT"       # service account / constrained delegation


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("assessments.id"))
    owner_user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("platform_users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="Path to DA")
    status: Mapped[str] = mapped_column(String(20), default=ChainStatus.PENDING)
    target_label: Mapped[str | None] = mapped_column(String(255))
    path_nodes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    steps: Mapped[list[Any]] = mapped_column(EncryptedJSON(), default=list)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    loot: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(), default=dict)
    job_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    target: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255))
    params: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(), default=dict)
    starting_position: Mapped[str | None] = mapped_column(String(30))
    all_paths: Mapped[list[Any]] = mapped_column(JSON, default=list)   # all generated paths for this chain
    selected_path: Mapped[int] = mapped_column(Integer, default=0)
    failed_steps: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)


class OpsecProfile(str, enum.Enum):
    LOUD = "LOUD"
    BALANCED = "BALANCED"
    GHOST = "GHOST"


class OffensiveJobStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"


class OffensiveJob(Base):
    __tablename__ = "offensive_jobs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("assessments.id"))
    technique_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    params: Mapped[dict] = mapped_column(EncryptedJSON(), default=dict)
    executor: Mapped[str] = mapped_column(String(50), nullable=False, default="impacket")
    opsec_profile: Mapped[OpsecProfile] = mapped_column(
        enum_column(OpsecProfile, 20), default=OpsecProfile.BALANCED
    )
    status: Mapped[OffensiveJobStatus] = mapped_column(
        enum_column(OffensiveJobStatus, 20), default=OffensiveJobStatus.PENDING
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("platform_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    exit_code: Mapped[int | None] = mapped_column(Integer)


class JobOutput(Base):
    __tablename__ = "job_outputs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("offensive_jobs.id"), nullable=False)
    stream: Mapped[str] = mapped_column(String(10), nullable=False, default="stdout")
    line: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assessments.id"), nullable=False)
    module_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_mode: Mapped[str] = mapped_column(String(50), nullable=False)
    execution_mode: Mapped[str] = mapped_column(String(50), nullable=False, default="SIMULATION_CONSENSUS")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="RUNNING")
    final_verdict: Mapped[str | None] = mapped_column(String(100))
    risk_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[int | None] = mapped_column(Integer)
    consensus_score: Mapped[int | None] = mapped_column(Integer)
    evidence_quality_score: Mapped[int | None] = mapped_column(Integer)
    severity_projection: Mapped[str | None] = mapped_column(String(50))
    summary: Mapped[str | None] = mapped_column(Text)
    reasoning_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    telemetry_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(GUID(), ForeignKey("platform_users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    origin: Mapped[str] = mapped_column(String(50), default="SIMULATED")


class ValidationExpertDecision(Base):
    __tablename__ = "validation_expert_decisions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    validation_run_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("validation_runs.id"), nullable=False)
    expert_id: Mapped[str] = mapped_column(String(100), nullable=False)
    expert_name: Mapped[str] = mapped_column(String(255), nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    score_delta: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity_hint: Mapped[str | None] = mapped_column(String(50))
    summary: Mapped[str | None] = mapped_column(Text)
    reasoning_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    supporting_signals_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    contradicting_signals_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    missing_signals_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_refs_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    related_finding_ids_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    related_entity_ids_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    related_edge_ids_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    telemetry_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class ReconScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ReconScan(Base):
    __tablename__ = "recon_scans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[ReconScanStatus] = mapped_column(
        enum_column(ReconScanStatus, 20), default=ReconScanStatus.QUEUED
    )
    target_dc_ip: Mapped[str | None] = mapped_column(String(50))
    domain: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)


class KillChainPhaseStatus(str, enum.Enum):
    NOT_STARTED = "not_started"
    PARTIAL = "partial"
    COMPLETE = "complete"


class KillChainProgress(Base):
    __tablename__ = "kill_chain_progress"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    phase_id: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[KillChainPhaseStatus] = mapped_column(
        enum_column(KillChainPhaseStatus, 20), default=KillChainPhaseStatus.NOT_STARTED
    )
    techniques_run: Mapped[list[Any]] = mapped_column(JSON, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, onupdate=_utcnow_naive)


class AuthLevel(str, enum.Enum):
    ANON = "anon"
    AUTHENTICATED = "authenticated"
    LOCAL_ADMIN = "local_admin"
    DOMAIN_ADMIN = "domain_admin"
    DA_FOREST = "da_forest"
    SYSTEM = "system"


class OperatorSession(Base):
    __tablename__ = "operator_sessions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )
    target_ip: Mapped[str | None] = mapped_column(String(100), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_level: Mapped[AuthLevel] = mapped_column(
        enum_column(AuthLevel, 50), nullable=False, default=AuthLevel.ANON
    )
    commands_run: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    machines_owned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    users_owned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow_naive, onupdate=_utcnow_naive)


class ToolCheckResult(Base):
    __tablename__ = "tool_check_results"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    install_cmd: Mapped[str | None] = mapped_column(Text, nullable=True)
    phases: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow_naive)
    checked_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True
    )


# Used by core/ai_operator/worker_pool.py for in-memory pool state tracking
class AIOperatorStatus(str, enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"


class GraphProjectionState(Base):
    __tablename__ = "graph_projection_state"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assessments.id"), primary_key=True
    )
    last_projected_at: Mapped[datetime | None] = mapped_column(DateTime)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|projecting|ready|error


class AIOperatorAction(Base):
    __tablename__ = "ai_operator_actions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("operator_sessions.id", ondelete="CASCADE"), nullable=True
    )
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    technique_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    command_executed: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    phase_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    worker_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow_naive)
