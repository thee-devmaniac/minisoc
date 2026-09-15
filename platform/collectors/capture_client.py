"""
Reads new lines appended to capture's shared JSON-lines output since the
last poll, and returns them as plain dicts for normalization.

Offset tracking is in-process (module-level state), not persisted — a
platform restart re-reads the file from the start, re-ingesting already-seen
SYN events. Accepted as an MVP limitation: the file stays small in a lab,
and Version 2's correlation work will need to handle duplicate-ish detections
anyway, so this doesn't introduce a new problem class, just an early
instance of one already on the roadmap.
"""
import json
from pathlib import Path

CAPTURE_FILE = Path("/var/minisoc/capture/events.jsonl")

_last_offset = 0


def poll_new_events() -> list[dict]:
    global _last_offset

    if not CAPTURE_FILE.exists():
        return []

    events = []
    with CAPTURE_FILE.open("r") as f:
        f.seek(_last_offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed lines rather than crash the poll loop
            if raw.get("type") == "heartbeat":
                continue  # leftover from the Phase 5 scaffold stub
            events.append(raw)
        _last_offset = f.tell()

    return events