"""
SQLAlchemy models. Matches the schema designed in LLD §6, with two known
deviations from the written doc:

1. IP address columns are String, not Postgres's native INET type. INET's
   real advantage is native subnet-containment operators (<<, >>=), which
   nothing in the MVP or Version 2 roadmap currently needs — and comparing
   INET against a plain Python string parameter fails at the driver level
   (`operator does not exist: inet = character varying`) unless every query
   explicitly casts the bind parameter. String avoids that friction.
2. security_events has no `category` column — category lives on
   detection_rules and is reachable via rule_id, so storing it again here
   would just be duplicated, driftable data.
"""
import uuid

from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(String, nullable=False, unique=True)
    hostname = Column(String, nullable=True)
    open_ports = Column(ARRAY(Integer), nullable=False, default=list)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RawEventRow(Base):
    __tablename__ = "raw_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    dest_ip = Column(String, nullable=True)
    dest_port = Column(Integer, nullable=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    raw_payload = Column(JSONB, nullable=False)

    __table_args__ = (
        Index("ix_raw_events_type_source_time", "event_type", "source_ip", "occurred_at"),
    )


class DetectionRuleRow(Base):
    __tablename__ = "detection_rules"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    category = Column(String, nullable=False)
    default_severity = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)


class SecurityEventRow(Base):
    __tablename__ = "security_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String, ForeignKey("detection_rules.id"), nullable=False)
    severity_score = Column(Integer, nullable=False)
    severity_label = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    target_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=True)
    description = Column(String, nullable=False)
    event_count = Column(Integer, nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    evidence_ids = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    acknowledged = Column(Boolean, nullable=False, default=False)