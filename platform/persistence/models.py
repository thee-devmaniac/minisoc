"""
SQLAlchemy models. Matches the schema designed in LLD §6, with one deviation:
ip_address is String, not Postgres's native INET type. INET's real advantage
is native subnet-containment operators (<<, >>=), which nothing in the MVP
or Version 2 roadmap currently needs — and comparing INET against a plain
Python string parameter fails at the driver level (`operator does not exist:
inet = character varying`) unless every query explicitly casts the bind
parameter. String avoids that friction entirely. Revisit if a genuine need
for subnet-range queries shows up later.

Only devices is needed for Milestone 1 — raw_events, detection_rules, and
security_events are added when their respective milestones arrive, to avoid
carrying unused tables (same principle as deferring Redis in §3.5).
"""
import uuid

from sqlalchemy import ARRAY, Column, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
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