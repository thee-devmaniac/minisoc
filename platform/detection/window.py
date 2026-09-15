"""
Per-source_ip sliding time window tracking distinct destination ports.
In-process, not shared across workers or persisted across restarts —
sufficient for MVP (single-process FastAPI, one polling loop). Revisit if
Version 2 correlation needs this shared across processes (that's exactly
the scenario Redis was deferred for in LLD §3.5).
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta


class PortWindowTracker:
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self._events: dict[str, deque] = defaultdict(deque)

    def record(
        self, source_ip: str, dest_port: int, occurred_at: datetime
    ) -> tuple[set[int], datetime]:
        """Records a (dest_port, timestamp) for this source, prunes anything
        older than the window, and returns (distinct ports still in window,
        earliest timestamp still in window)."""
        dq = self._events[source_ip]
        dq.append((occurred_at, dest_port))

        cutoff = occurred_at - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        ports = {port for _, port in dq}
        earliest = dq[0][0] if dq else occurred_at
        return ports, earliest