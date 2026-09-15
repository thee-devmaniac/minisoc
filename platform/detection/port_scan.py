"""
port_scan_v1: fires when one source IP attempts connections to enough
distinct destination ports within a rolling time window (LLD §5 detection
scenarios table — port scanning, ranked highest learning value / lowest
false-positive risk of the candidate rules).

Note: this fires again on every new port beyond the threshold within the
same window (e.g. 6 ports, 7 ports, 8 ports all produce separate alerts).
That's expected for MVP — deduplication into a single alert-per-incident is
explicitly Version 2 correlation work (LLD §9), not a bug to fix here.
"""
from detection.base import SecurityEventDraft
from detection.window import PortWindowTracker
from normalization.normalizer import RawEvent

RULE_ID = "port_scan_v1"
WINDOW_SECONDS = 60
DISTINCT_PORT_THRESHOLD = 5
BASE_SEVERITY = 60


class PortScanRule:
    id = RULE_ID
    subscribes_to = ["tcp_syn"]

    def __init__(self):
        self._tracker = PortWindowTracker(window_seconds=WINDOW_SECONDS)

    def evaluate(self, event: RawEvent) -> SecurityEventDraft | None:
        if event.dest_port is None:
            return None

        ports, earliest = self._tracker.record(
            event.source_ip, event.dest_port, event.occurred_at
        )

        if len(ports) < DISTINCT_PORT_THRESHOLD:
            return None

        return SecurityEventDraft(
            rule_id=self.id,
            severity_score=BASE_SEVERITY,
            source_ip=event.source_ip,
            description=(
                f"{event.source_ip} attempted connections to {len(ports)} "
                f"distinct ports within {WINDOW_SECONDS}s"
            ),
            event_count=len(ports),
            window_start=earliest,
            window_end=event.occurred_at,
        )