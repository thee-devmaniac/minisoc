"""
Reads new lines appended to capture's shared JSON-lines output since the
given offset, and returns (events, new_offset).

Pure function — no module-level state. Offset ownership lives in the poll
loop (main.py), which persists it via persistence/repository.py's
collector_state table. This fixes the Milestone 2/3 gap where a platform
restart always re-read the file from byte 0, re-detecting already-seen
events on every restart (visible directly in the duplicate-timestamped
security_events rows from real testing).
"""
import json
from pathlib import Path

CAPTURE_FILE = Path("/var/minisoc/capture/events.jsonl")


def poll_new_events(start_offset: int) -> tuple[list[dict], int]:
    if not CAPTURE_FILE.exists():
        return [], start_offset

    events = []
    with CAPTURE_FILE.open("r") as f:
        f.seek(start_offset)
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
        new_offset = f.tell()

    return events, new_offset