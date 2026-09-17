from datetime import datetime, timedelta, timezone

from collectors.log_tailer import _parse_line
from detection.brute_force import BruteForceRule, FAILURE_THRESHOLD, WINDOW_SECONDS
from detection.window import CountWindowTracker
from normalization.normalizer import RawEvent, normalize_log_event


class TestParseLine:
    def test_parses_failed_password_valid_user(self):
        line = "2026-09-15T04:58:07Z sshd[123]: Failed password for root from 172.28.0.5 port 54321 ssh2"
        result = _parse_line(line)

        assert result == {
            "type": "ssh_auth_failure",
            "source_ip": "172.28.0.5",
            "username": "root",
            "ts_str": "2026-09-15T04:58:07Z",
        }

    def test_parses_failed_password_invalid_user(self):
        line = "2026-09-15T04:58:07Z sshd[123]: Failed password for invalid user admin from 172.28.0.5 port 54321 ssh2"
        result = _parse_line(line)

        assert result["username"] == "admin"  # "invalid" must not be captured as the username
        assert result["type"] == "ssh_auth_failure"

    def test_parses_accepted_password(self):
        line = "2026-09-15T04:58:07Z sshd[123]: Accepted password for labuser from 172.28.0.5 port 54321 ssh2"
        result = _parse_line(line)

        assert result["type"] == "ssh_auth_success"
        assert result["username"] == "labuser"

    def test_returns_none_for_unrelated_line(self):
        line = "2026-09-15T04:58:07Z sshd[123]: Server listening on 0.0.0.0 port 22."
        assert _parse_line(line) is None

    def test_returns_none_for_malformed_line(self):
        assert _parse_line("garbage-with-no-space-separated-timestamp") is None


class TestNormalizeLogEvent:
    def test_normalizes_valid_event(self):
        raw = {
            "type": "ssh_auth_failure",
            "source_ip": "172.28.0.5",
            "username": "root",
            "ts_str": "2026-09-15T04:58:07Z",
        }
        event = normalize_log_event(raw)

        assert event is not None
        assert event.event_type == "ssh_auth_failure"
        assert event.source_ip == "172.28.0.5"
        assert event.occurred_at == datetime(2026, 9, 15, 4, 58, 7, tzinfo=timezone.utc)

    def test_returns_none_for_bad_timestamp(self):
        raw = {"type": "ssh_auth_failure", "source_ip": "1.2.3.4", "ts_str": "not-a-timestamp"}
        assert normalize_log_event(raw) is None


class TestCountWindowTracker:
    def test_counts_accumulate_within_window(self):
        tracker = CountWindowTracker(window_seconds=60)
        now = datetime.now(timezone.utc)

        tracker.record("1.2.3.4", now)
        count, _ = tracker.record("1.2.3.4", now + timedelta(seconds=5))

        assert count == 2

    def test_old_events_pruned(self):
        tracker = CountWindowTracker(window_seconds=10)
        now = datetime.now(timezone.utc)

        tracker.record("1.2.3.4", now)
        count, _ = tracker.record("1.2.3.4", now + timedelta(seconds=15))

        assert count == 1  # first event aged out


class TestBruteForceRule:
    def _event(self, source_ip="1.2.3.4", occurred_at=None) -> RawEvent:
        return RawEvent(
            event_type="ssh_auth_failure",
            source_ip=source_ip,
            dest_ip=None,
            dest_port=None,
            occurred_at=occurred_at or datetime.now(timezone.utc),
            raw_payload={},
        )

    def test_does_not_fire_below_threshold(self):
        rule = BruteForceRule()
        now = datetime.now(timezone.utc)
        result = None

        for i in range(FAILURE_THRESHOLD - 1):
            result = rule.evaluate(self._event(occurred_at=now + timedelta(seconds=i)))

        assert result is None

    def test_fires_at_threshold(self):
        rule = BruteForceRule()
        now = datetime.now(timezone.utc)
        result = None

        for i in range(FAILURE_THRESHOLD):
            result = rule.evaluate(self._event(occurred_at=now + timedelta(seconds=i)))

        assert result is not None
        assert result.rule_id == "brute_force_v1"
        assert result.event_count == FAILURE_THRESHOLD

    def test_different_sources_do_not_interfere(self):
        rule = BruteForceRule()
        now = datetime.now(timezone.utc)

        for i in range(FAILURE_THRESHOLD - 1):
            rule.evaluate(self._event(source_ip="1.1.1.1", occurred_at=now + timedelta(seconds=i)))

        result = rule.evaluate(self._event(source_ip="2.2.2.2", occurred_at=now))
        assert result is None  # 2.2.2.2 only has 1 attempt, unaffected by 1.1.1.1's count