"""
Integration test for Version 2 Phase 1 correlation. Requires a live
Postgres via DATABASE_URL — this is deliberately not a unit test, since
correlation's correctness depends on real query behavior (ordering,
upsert-in-place), not just pure logic.

Run with a real DATABASE_URL, e.g. against the dev stack:
  docker compose exec platform pytest tests/integration -v
"""
import os
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="requires a live Postgres via DATABASE_URL"
)


@pytest.fixture
def engine_and_session():
    from persistence.db import engine as db_engine, get_session
    from persistence.models import Base
    from persistence import repository

    Base.metadata.create_all(bind=db_engine)
    with get_session() as session:
        import sqlalchemy

        session.execute(sqlalchemy.text(
            "TRUNCATE security_events, raw_events;"))
        session.commit()

        # security_events.rule_id has a FK to detection_rules — main.py's
        # startup event registers this in the real app; the test fixture
        # must do the same.
        repository.ensure_rule(
            session, id="port_scan_v1", name="Port Scan", description="test",
            category="reconnaissance", default_severity=60,
        )
        repository.ensure_rule(
            session, id="brute_force_v1", name="SSH Brute Force", description="test",
            category="credential_access", default_severity=70,
        )

    yield get_session


def test_rapid_successive_detections_correlate_into_one_row(engine_and_session):
    from detection.engine import DetectionEngine
    from detection.port_scan import PortScanRule, DISTINCT_PORT_THRESHOLD
    from normalization.normalizer import RawEvent
    from persistence import repository

    get_session = engine_and_session
    engine = DetectionEngine(rules=[PortScanRule()])
    now = datetime.now(timezone.utc)

    # first burst: 7 distinct ports, all within a few seconds — should
    # produce exactly ONE incident row, updated in place as it grows
    for i in range(DISTINCT_PORT_THRESHOLD + 2):
        event = RawEvent(
            event_type="tcp_syn", source_ip="10.0.0.9", dest_ip="10.0.0.3",
            dest_port=2000 + i, occurred_at=now + timedelta(seconds=i), raw_payload={},
        )
        engine.process(event)

    with get_session() as session:
        rows = repository.list_security_events(session)
        matching = [r for r in rows if r.source_ip == "10.0.0.9"]

    assert len(
        matching) == 1, "rapid successive detections must correlate into one row"
    assert matching[0].event_count == DISTINCT_PORT_THRESHOLD + 2
    assert matching[0].created_at is not None
    # first-seen (created_at) must predate the final update (last_seen_at)
    assert matching[0].created_at <= matching[0].last_seen_at


def test_detection_after_window_gap_creates_new_incident(engine_and_session):
    from detection.engine import DetectionEngine
    from detection.port_scan import PortScanRule, DISTINCT_PORT_THRESHOLD, WINDOW_SECONDS
    from normalization.normalizer import RawEvent
    from persistence import repository

    get_session = engine_and_session
    engine = DetectionEngine(rules=[PortScanRule()])
    now = datetime.now(timezone.utc)

    # first incident
    for i in range(DISTINCT_PORT_THRESHOLD):
        event = RawEvent(
            event_type="tcp_syn", source_ip="10.0.0.10", dest_ip="10.0.0.3",
            dest_port=3000 + i, occurred_at=now + timedelta(seconds=i), raw_payload={},
        )
        engine.process(event)

    # second incident: same source, but well past the rule's own window —
    # a fresh PortScanRule instance's tracker has also aged out the old
    # ports by now, so it re-accumulates from scratch
    gap_start = now + timedelta(seconds=WINDOW_SECONDS + 30)
    for i in range(DISTINCT_PORT_THRESHOLD):
        event = RawEvent(
            event_type="tcp_syn", source_ip="10.0.0.10", dest_ip="10.0.0.3",
            dest_port=4000 + i, occurred_at=gap_start + timedelta(seconds=i), raw_payload={},
        )
        engine.process(event)

    with get_session() as session:
        rows = repository.list_security_events(session)
        matching = [r for r in rows if r.source_ip == "10.0.0.10"]

    assert len(
        matching) == 2, "a detection after the rule's window has elapsed must open a new incident"


def test_different_source_ips_never_correlate_together(engine_and_session):
    from detection.engine import DetectionEngine
    from detection.brute_force import BruteForceRule, FAILURE_THRESHOLD
    from normalization.normalizer import RawEvent
    from persistence import repository

    get_session = engine_and_session
    engine = DetectionEngine(rules=[BruteForceRule()])
    now = datetime.now(timezone.utc)

    for source_ip in ["10.0.0.20", "10.0.0.21"]:
        for i in range(FAILURE_THRESHOLD):
            event = RawEvent(
                event_type="ssh_auth_failure", source_ip=source_ip, dest_ip=None,
                dest_port=None, occurred_at=now + timedelta(seconds=i), raw_payload={},
            )
            engine.process(event)

    with get_session() as session:
        rows = repository.list_security_events(session)
        matching = [r for r in rows if r.source_ip in (
            "10.0.0.20", "10.0.0.21")]

    assert len(
        matching) == 2, "different source IPs must never be merged into the same incident"
