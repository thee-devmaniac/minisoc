"""
Query interface for all tables. api/, discovery/, and detection/ call into
this — none of them should build SQLAlchemy queries themselves (LLD §7).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


def upsert_device(
    session: Session, ip_address: str, hostname: str | None, open_ports: list[int]
) -> models.Device:
    """Insert a newly-discovered device, or refresh an existing one's
    last_seen/open_ports/hostname. first_seen is never overwritten."""
    stmt = select(models.Device).where(models.Device.ip_address == ip_address)
    device = session.execute(stmt).scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if device:
        device.hostname = hostname or device.hostname
        device.open_ports = sorted(set(open_ports))
        device.last_seen = now
    else:
        device = models.Device(
            ip_address=ip_address,
            hostname=hostname,
            open_ports=sorted(set(open_ports)),
            first_seen=now,
            last_seen=now,
        )
        session.add(device)

    session.commit()
    session.refresh(device)
    return device


def list_devices(session: Session) -> list[models.Device]:
    stmt = select(models.Device).order_by(models.Device.last_seen.desc())
    return list(session.execute(stmt).scalars())


def ensure_rule(
    session: Session,
    id: str,
    name: str,
    description: str,
    category: str,
    default_severity: int,
) -> models.DetectionRuleRow:
    """Registers rule metadata if not already present. Called once at
    startup per active rule — logic itself lives in code, this table is
    metadata only (LLD §6)."""
    existing = session.get(models.DetectionRuleRow, id)
    if existing:
        return existing

    row = models.DetectionRuleRow(
        id=id,
        name=name,
        description=description,
        category=category,
        default_severity=default_severity,
        enabled=True,
    )
    session.add(row)
    session.commit()
    return row


def insert_raw_event(session: Session, event) -> uuid.UUID:
    """`event` is a normalization.normalizer.RawEvent. Kept as a positional
    duck-typed argument rather than importing RawEvent here to avoid
    persistence/ depending on normalization/ (LLD §7 dependency direction:
    detection depends on normalization's shape, persistence should not)."""
    row = models.RawEventRow(
        event_type=event.event_type,
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        dest_port=event.dest_port,
        occurred_at=event.occurred_at,
        raw_payload=event.raw_payload,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.id


def insert_security_event(
    session: Session,
    *,
    rule_id: str,
    severity_score: int,
    severity_label: str,
    source_ip: str,
    description: str,
    event_count: int,
    window_start: datetime,
    window_end: datetime,
    evidence_ids: list[uuid.UUID],
) -> models.SecurityEventRow:
    row = models.SecurityEventRow(
        rule_id=rule_id,
        severity_score=severity_score,
        severity_label=severity_label,
        source_ip=source_ip,
        description=description,
        event_count=event_count,
        window_start=window_start,
        window_end=window_end,
        evidence_ids=evidence_ids,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def list_security_events(session: Session, limit: int = 100) -> list[models.SecurityEventRow]:
    stmt = (
        select(models.SecurityEventRow)
        .order_by(models.SecurityEventRow.created_at.desc())
        .limit(limit)
    )
    return list(session.execute(stmt).scalars())


def get_offset(session: Session, collector_id: str) -> int:
    """Returns 0 for a collector that's never been seen before — the
    correct behavior for first-ever startup, distinct from a restart."""
    row = session.get(models.CollectorStateRow, collector_id)
    return row.offset if row else 0


def set_offset(session: Session, collector_id: str, offset: int) -> None:
    row = session.get(models.CollectorStateRow, collector_id)
    if row:
        row.offset = offset
    else:
        row = models.CollectorStateRow(
            collector_id=collector_id, offset=offset)
        session.add(row)
    session.commit()


def find_correlatable_event(
    session: Session,
    rule_id: str,
    source_ip: str,
    gap_seconds: int,
    before_time: datetime,
):
    """Finds the most recent security_event for this rule+source whose
    window_end is within gap_seconds of before_time. Returns None if no
    such row exists, or if the gap exceeds the rule's own window — i.e.
    the incident is considered closed and a new one should be opened
    (Version 2 Phase 1 correlation, anchored to the rule's own window
    rather than a separately invented constant)."""
    stmt = (
        select(models.SecurityEventRow)
        .where(models.SecurityEventRow.rule_id == rule_id)
        .where(models.SecurityEventRow.source_ip == source_ip)
        .order_by(models.SecurityEventRow.window_end.desc())
        .limit(1)
    )
    candidate = session.execute(stmt).scalar_one_or_none()
    if candidate is None:
        return None

    gap = (before_time - candidate.window_end).total_seconds()
    if gap <= gap_seconds:
        return candidate
    return None


def update_security_event(
    session: Session,
    event_row: models.SecurityEventRow,
    *,
    event_count: int,
    window_end: datetime,
    description: str,
    new_evidence_id,
) -> models.SecurityEventRow:
    """Updates an existing incident row in place rather than inserting a
    new one. window_start and created_at are deliberately left untouched —
    they mark when the incident was first detected, not last reconfirmed
    (last_seen_at, via the column's onupdate, covers that)."""
    event_row.event_count = event_count
    event_row.window_end = window_end
    event_row.description = description
    event_row.evidence_ids = list(event_row.evidence_ids) + [new_evidence_id]
    session.commit()
    session.refresh(event_row)
    return event_row
