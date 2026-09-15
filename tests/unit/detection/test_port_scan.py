from datetime import datetime, timedelta, timezone

from detection.port_scan import DISTINCT_PORT_THRESHOLD, WINDOW_SECONDS, PortScanRule
from detection.severity import severity_label_for
from detection.window import PortWindowTracker
from normalization.normalizer import RawEvent, normalize_capture_event


def _event(source_ip="10.0.0.5", dest_port=22, occurred_at=None) -> RawEvent:
    return RawEvent(
        event_type="tcp_syn",
        source_ip=source_ip,
        dest_ip="10.0.0.3",
        dest_port=dest_port,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        raw_payload={},
    )


class TestPortWindowTracker:
    def test_distinct_ports_accumulate_within_window(self):
        tracker = PortWindowTracker(window_seconds=60)
        now = datetime.now(timezone.utc)

        tracker.record("1.2.3.4", 22, now)
        ports, _ = tracker.record("1.2.3.4", 80, now + timedelta(seconds=5))

        assert ports == {22, 80}

    def test_ports_outside_window_are_pruned(self):
        tracker = PortWindowTracker(window_seconds=10)
        now = datetime.now(timezone.utc)

        tracker.record("1.2.3.4", 22, now)
        ports, _ = tracker.record("1.2.3.4", 80, now + timedelta(seconds=15))

        assert ports == {80}  # port 22 aged out

    def test_different_sources_tracked_independently(self):
        tracker = PortWindowTracker(window_seconds=60)
        now = datetime.now(timezone.utc)

        tracker.record("1.2.3.4", 22, now)
        ports_other, _ = tracker.record("5.6.7.8", 443, now)

        assert ports_other == {443}


class TestPortScanRule:
    def test_does_not_fire_below_threshold(self):
        rule = PortScanRule()
        now = datetime.now(timezone.utc)

        for i in range(DISTINCT_PORT_THRESHOLD - 1):
            result = rule.evaluate(_event(dest_port=1000 + i, occurred_at=now))

        assert result is None

    def test_fires_at_threshold(self):
        rule = PortScanRule()
        now = datetime.now(timezone.utc)
        result = None

        for i in range(DISTINCT_PORT_THRESHOLD):
            result = rule.evaluate(_event(dest_port=1000 + i, occurred_at=now))

        assert result is not None
        assert result.rule_id == "port_scan_v1"
        assert result.event_count == DISTINCT_PORT_THRESHOLD
        assert result.source_ip == "10.0.0.5"

    def test_does_not_fire_when_window_expires_between_attempts(self):
        rule = PortScanRule()
        now = datetime.now(timezone.utc)
        result = None

        for i in range(DISTINCT_PORT_THRESHOLD):
            occurred_at = now + timedelta(seconds=i * (WINDOW_SECONDS + 1))
            result = rule.evaluate(_event(dest_port=1000 + i, occurred_at=occurred_at))

        assert result is None  # each attempt aged the previous ones out


class TestSeverityLabel:
    def test_boundaries(self):
        assert severity_label_for(0) == "low"
        assert severity_label_for(30) == "low"
        assert severity_label_for(31) == "medium"
        assert severity_label_for(60) == "medium"
        assert severity_label_for(61) == "high"
        assert severity_label_for(85) == "high"
        assert severity_label_for(86) == "critical"
        assert severity_label_for(100) == "critical"


class TestNormalizer:
    def test_normalizes_valid_capture_event(self):
        raw = {"type": "tcp_syn", "source_ip": "1.2.3.4", "dest_ip": "1.2.3.5", "dest_port": 22, "ts": 1700000000.0}
        event = normalize_capture_event(raw)

        assert event is not None
        assert event.event_type == "tcp_syn"
        assert event.source_ip == "1.2.3.4"
        assert event.dest_port == 22

    def test_returns_none_for_missing_required_field(self):
        raw = {"type": "tcp_syn", "dest_ip": "1.2.3.5"}  # missing source_ip, ts
        assert normalize_capture_event(raw) is None

    def test_returns_none_for_malformed_timestamp(self):
        raw = {"type": "tcp_syn", "source_ip": "1.2.3.4", "ts": "not-a-number"}
        assert normalize_capture_event(raw) is None