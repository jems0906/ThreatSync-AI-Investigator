import enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from db.database import Base


# ── Enumerations ──────────────────────────────────────────────────────────────

class AlertStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    INVESTIGATED = "investigated"
    CLOSED = "closed"


class InvestigationStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


# ── ORM Models ────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_uuid = Column(String(36), unique=True, nullable=False, index=True)
    alert_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(256), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True)
    hostname = Column(String(256), nullable=True)
    severity_hint = Column(String(16), nullable=True)   # low / medium / high / critical
    raw_data = Column(JSON, nullable=False)
    status = Column(String(32), default=AlertStatus.NEW, nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    investigations = relationship(
        "Investigation", back_populates="alert", cascade="all, delete-orphan"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)

    # LLM-generated fields
    threat_type = Column(String(64), nullable=True)
    severity_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    key_findings = Column(JSON, nullable=True)
    investigation_steps = Column(JSON, nullable=True)
    iocs = Column(JSON, nullable=True)
    mitre_tactics = Column(JSON, nullable=True)
    recommendation = Column(String(32), nullable=True)   # escalate / monitor / ignore
    estimated_risk = Column(String(16), nullable=True)   # critical / high / medium / low
    raw_analysis = Column(Text, nullable=True)

    status = Column(String(32), default=InvestigationStatus.PENDING, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    alert = relationship("Alert", back_populates="investigations")
    approval = relationship(
        "ApprovalRequest",
        back_populates="investigation",
        uselist=False,
        cascade="all, delete-orphan",
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (UniqueConstraint("investigation_id"),)

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(
        Integer, ForeignKey("investigations.id"), nullable=False, index=True
    )
    status = Column(String(32), default=ApprovalStatus.PENDING, nullable=False)
    analyst_id = Column(String(256), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    investigation = relationship("Investigation", back_populates="approval")


class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(256), nullable=False, index=True)
    action = Column(String(128), nullable=False)
    resource = Column(String(512), nullable=True)
    source_ip = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    extra_metadata = Column(JSON, nullable=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(256), nullable=False, index=True)
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(128), nullable=True, index=True)
    status = Column(String(32), nullable=False, index=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
