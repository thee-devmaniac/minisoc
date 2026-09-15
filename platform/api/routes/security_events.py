from fastapi import APIRouter

from persistence import repository
from persistence.db import get_session

router = APIRouter(prefix="/security-events", tags=["security-events"])


def _serialize(e) -> dict:
    return {
        "id": str(e.id),
        "rule_id": e.rule_id,
        "severity_score": e.severity_score,
        "severity_label": e.severity_label,
        "source_ip": e.source_ip,
        "description": e.description,
        "event_count": e.event_count,
        "window_start": e.window_start.isoformat() if e.window_start else None,
        "window_end": e.window_end.isoformat() if e.window_end else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "acknowledged": e.acknowledged,
    }


@router.get("")
def list_security_events():
    with get_session() as session:
        events = repository.list_security_events(session)
        return [_serialize(e) for e in events]