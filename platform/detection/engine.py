"""
Dispatches normalized RawEvents to subscribed detection rules, and persists
both the raw event (audit trail, LLD §6) and any resulting security event.
"""
from detection.base import DetectionRule
from detection.severity import severity_label_for
from normalization.normalizer import RawEvent
from persistence import repository
from persistence.db import get_session


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule]):
        self._rules_by_event_type: dict[str, list[DetectionRule]] = {}
        for rule in rules:
            for event_type in rule.subscribes_to:
                self._rules_by_event_type.setdefault(event_type, []).append(rule)

    def process(self, event: RawEvent) -> None:
        with get_session() as session:
            raw_event_id = repository.insert_raw_event(session, event)

            for rule in self._rules_by_event_type.get(event.event_type, []):
                draft = rule.evaluate(event)
                if draft is None:
                    continue

                repository.insert_security_event(
                    session,
                    rule_id=draft.rule_id,
                    severity_score=draft.severity_score,
                    severity_label=severity_label_for(draft.severity_score),
                    source_ip=draft.source_ip,
                    description=draft.description,
                    event_count=draft.event_count,
                    window_start=draft.window_start,
                    window_end=draft.window_end,
                    evidence_ids=[raw_event_id],
                )