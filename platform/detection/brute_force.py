"""
brute_force_v1: fires when one source IP accumulates enough failed SSH
login attempts within a rolling time window (LLD §5 detection scenarios —
second-highest learning value / lowest false-positive risk candidate,
after port scanning).

Severity is set higher than port_scan_v1 (70 vs 60) — a credential attack
is a more direct threat than reconnaissance. This is a calibration choice,
not a fixed rule; revisit once more rule types exist to compare against.

Same repeated-firing behavior as port_scan_v1: every attempt past the
threshold produces a new alert. Deduplication is Version 2 correlation
work (LLD §9), not handled here.
"""
from detection.base import SecurityEventDraft
from detection.window import CountWindowTracker
from normalization.normalizer import RawEvent

RULE_ID = "brute_force_v1"
WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 5
BASE_SEVERITY = 70


class BruteForceRule:
    id = RULE_ID
    subscribes_to = ["ssh_auth_failure"]
    window_seconds = WINDOW_SECONDS

    def __init__(self):
        self._tracker = CountWindowTracker(window_seconds=WINDOW_SECONDS)

    def evaluate(self, event: RawEvent) -> SecurityEventDraft | None:
        count, earliest = self._tracker.record(
            event.source_ip, event.occurred_at)

        if count < FAILURE_THRESHOLD:
            return None

        return SecurityEventDraft(
            rule_id=self.id,
            severity_score=BASE_SEVERITY,
            source_ip=event.source_ip,
            description=(
                f"{event.source_ip} had {count} failed SSH login attempts "
                f"within {WINDOW_SECONDS}s"
            ),
            event_count=count,
            window_start=earliest,
            window_end=event.occurred_at,
        )
