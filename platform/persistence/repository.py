"""
Query interface for devices. api/ and discovery/ call into this — neither
should build SQLAlchemy queries themselves (LLD §7 dependency rule).
"""
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