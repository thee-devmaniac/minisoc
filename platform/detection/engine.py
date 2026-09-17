"""
Dispatches normalized RawEvents to subscribed detection rules, and persists
both the raw event (audit trail, LLD §6) and any resulting security event.

Version 2 Phase 1: adds correlation. Previously every threshold-crossing
detection inserted a new security_events row — a single 20-port scan
produced 16 rows. Now, a detection that's part of the same ongoing incident
(same rule_id + source_ip, gap since the last one within the rule's own
window) updates that incident's row in place instead of creating a new one.

Deliberately NOT doing cross-rule correlation (e.g. treating simultaneous
port_scan_v1 + brute_force_v1 from one source as one campaign) — that's a
genuinely harder, higher-value feature closer to real SIEM correlation, and
conflating it with this same-rule dedup would make this change much larger
than it needs to be. Named as a future step, not solved here.
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
                self._rules_by_event_type.setdefault(
                    event_type, []).append(rule)

    def process(self, event: RawEvent) -> None:
        with get_session() as session:
            raw_event_id = repository.insert_raw_event(session, event)

            for rule in self._rules_by_event_type.get(event.event_type, []):
                draft = rule.evaluate(event)
                if draft is None:
                    continue

                existing = repository.find_correlatable_event(
                    session,
                    rule_id=draft.rule_id,
                    source_ip=draft.source_ip,
                    gap_seconds=rule.window_seconds,
                    before_time=draft.window_end,
                )

                if existing is not None:
                    repository.update_security_event(
                        session,
                        existing,
                        event_count=draft.event_count,
                        window_end=draft.window_end,
                        description=draft.description,
                        new_evidence_id=raw_event_id,
                    )
                else:
                    repository.insert_security_event(
                        session,
                        rule_id=draft.rule_id,
                        severity_score=draft.severity_score,
                        severity_label=severity_label_for(
                            draft.severity_score),
                        source_ip=draft.source_ip,
                        description=draft.description,
                        event_count=draft.event_count,
                        window_start=draft.window_start,
                        window_end=draft.window_end,
                        evidence_ids=[raw_event_id],
                    )
