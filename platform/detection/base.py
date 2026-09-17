"""
Base abstraction for detection rules (LLD §7, FR9). A rule declares which
RawEvent types it cares about and returns a SecurityEventDraft when its
threshold trips.

Deliberate deviation from the original design sketch: each rule owns its
own windowed state internally (see detection/window.py) rather than the
engine owning a shared window store keyed by rule. Simpler with a single
rule; if a second rule needs the same windowing shape, extract it into
engine-owned shared state at that point rather than now.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from normalization.normalizer import RawEvent


@dataclass
class SecurityEventDraft:
    """What a rule hands back when it detects something. The engine fills
    in evidence and persists it — rules never touch persistence directly."""
    rule_id: str
    severity_score: int
    source_ip: str
    description: str
    event_count: int
    window_start: datetime
    window_end: datetime


class DetectionRule(Protocol):
    id: str
    subscribes_to: list[str]
    # used by the engine for correlation (Version 2 Phase 1) —
    window_seconds: int
    # an incident is "still open" if the gap since its last
    # contributing event is within this rule's own window

    def evaluate(self, event: RawEvent) -> SecurityEventDraft | None:
        ...
