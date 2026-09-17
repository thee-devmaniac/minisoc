"""
Tails target's SSH auth log via the shared volume (Milestone 5 handoff
design — see target/Dockerfile and docker-compose.yml). Same pure-function
offset pattern as capture_client.py, applied to plain text lines instead
of JSON.

Each line looks like:
  2026-09-15T04:58:07Z sshd[123]: Failed password for root from 172.28.0.5 port 54321 ssh2
  2026-09-15T04:58:09Z sshd[123]: Failed password for invalid user admin from 172.28.0.5 port 54322 ssh2
  2026-09-15T04:58:11Z sshd[123]: Accepted password for labuser from 172.28.0.5 port 54323 ssh2

The leading timestamp is one we add ourselves (target/Dockerfile), not
sshd's own — sshd -e emits no timestamp, since that's normally syslog's job.
"""
import re
from pathlib import Path

AUTH_LOG_FILE = Path("/var/log/minisoc/auth.log")

_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)


def _parse_line(line: str) -> dict | None:
    parts = line.split(" ", 1)
    if len(parts) != 2:
        return None
    ts_str, rest = parts

    failed = _FAILED_RE.search(rest)
    if failed:
        return {
            "type": "ssh_auth_failure",
            "source_ip": failed.group("ip"),
            "username": failed.group("user"),
            "ts_str": ts_str,
        }

    accepted = _ACCEPTED_RE.search(rest)
    if accepted:
        return {
            "type": "ssh_auth_success",
            "source_ip": accepted.group("ip"),
            "username": accepted.group("user"),
            "ts_str": ts_str,
        }

    return None


def poll_new_events(start_offset: int) -> tuple[list[dict], int]:
    if not AUTH_LOG_FILE.exists():
        return [], start_offset

    events = []
    with AUTH_LOG_FILE.open("r") as f:
        f.seek(start_offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = _parse_line(line)
            if parsed:
                events.append(parsed)
        new_offset = f.tell()

    return events, new_offset