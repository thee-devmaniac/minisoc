"""
Converts source-specific raw dicts into the common RawEvent shape used by
detection (LLD §5, step 3). This is the single place that owns input
validation before anything reaches the detection engine or the database —
malformed input is dropped here, never raised past this boundary, so one
bad line never takes down the polling loop (LLD §3.2 observability NFR:
log what happened, don't crash).
"""
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class RawEvent:
    event_type: str
    source_ip: str
    dest_ip: str | None
    dest_port: int | None
    occurred_at: datetime
    raw_payload: dict


def normalize_capture_event(raw: dict) -> RawEvent | None:
    """Normalizes a dict from capture's JSON-lines output (see
    capture/sniffer.py) into a RawEvent. Returns None for anything
    malformed rather than raising."""
    try:
        return RawEvent(
            event_type=raw["type"],
            source_ip=raw["source_ip"],
            dest_ip=raw.get("dest_ip"),
            dest_port=raw.get("dest_port"),
            occurred_at=datetime.fromtimestamp(raw["ts"], tz=timezone.utc),
            raw_payload=raw,
        )
    except (KeyError, TypeError, ValueError):
        return None


def normalize_log_event(raw: dict) -> RawEvent | None:
    """Normalizes a dict from log_tailer.py's auth-log parsing into a
    RawEvent. dest_ip/dest_port are left None — the log line only tells us
    who connected and from where, not which local service/port (we know
    it's always target's sshd, but the schema doesn't need that duplicated
    here)."""
    try:
        occurred_at = datetime.strptime(raw["ts_str"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        return RawEvent(
            event_type=raw["type"],
            source_ip=raw["source_ip"],
            dest_ip=None,
            dest_port=None,
            occurred_at=occurred_at,
            raw_payload=raw,
        )
    except (KeyError, TypeError, ValueError):
        return None