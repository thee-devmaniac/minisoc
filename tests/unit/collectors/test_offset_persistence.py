import json

from collectors.capture_client import poll_new_events as poll_capture
from collectors.log_tailer import poll_new_events as poll_log


class TestCaptureClientOffsets:
    def test_first_poll_from_zero_returns_all_events(self, tmp_path, monkeypatch):
        f = tmp_path / "events.jsonl"
        f.write_text(
            json.dumps({"type": "tcp_syn", "source_ip": "1.2.3.4", "dest_port": 22, "ts": 1.0}) + "\n"
        )
        import collectors.capture_client as cc
        monkeypatch.setattr(cc, "CAPTURE_FILE", f)

        events, new_offset = poll_capture(0)

        assert len(events) == 1
        assert new_offset > 0

    def test_simulated_restart_does_not_reread_old_events(self, tmp_path, monkeypatch):
        """This is the exact bug being fixed: a restart must resume from the
        persisted offset, not from 0, or already-seen events get re-detected."""
        f = tmp_path / "events.jsonl"
        f.write_text(
            json.dumps({"type": "tcp_syn", "source_ip": "1.2.3.4", "dest_port": 22, "ts": 1.0}) + "\n"
        )
        import collectors.capture_client as cc
        monkeypatch.setattr(cc, "CAPTURE_FILE", f)

        # first "process lifetime": poll once, persist the returned offset
        events1, offset_after_first_run = poll_capture(0)
        assert len(events1) == 1

        # simulate a platform restart: a fresh call, but starting from the
        # offset that would have been loaded from collector_state
        events2, offset_after_restart = poll_capture(offset_after_first_run)
        assert events2 == []  # nothing new — must NOT re-return the old event
        assert offset_after_restart == offset_after_first_run

    def test_new_lines_after_restart_are_picked_up(self, tmp_path, monkeypatch):
        f = tmp_path / "events.jsonl"
        f.write_text(
            json.dumps({"type": "tcp_syn", "source_ip": "1.2.3.4", "dest_port": 22, "ts": 1.0}) + "\n"
        )
        import collectors.capture_client as cc
        monkeypatch.setattr(cc, "CAPTURE_FILE", f)

        _, offset = poll_capture(0)

        with f.open("a") as fh:
            fh.write(json.dumps({"type": "tcp_syn", "source_ip": "1.2.3.4", "dest_port": 80, "ts": 2.0}) + "\n")

        events, _ = poll_capture(offset)
        assert len(events) == 1
        assert events[0]["dest_port"] == 80

    def test_heartbeat_lines_still_filtered(self, tmp_path, monkeypatch):
        f = tmp_path / "events.jsonl"
        f.write_text(json.dumps({"type": "heartbeat", "ts": 1.0}) + "\n")
        import collectors.capture_client as cc
        monkeypatch.setattr(cc, "CAPTURE_FILE", f)

        events, _ = poll_capture(0)
        assert events == []

    def test_missing_file_returns_empty_and_unchanged_offset(self, tmp_path, monkeypatch):
        import collectors.capture_client as cc
        monkeypatch.setattr(cc, "CAPTURE_FILE", tmp_path / "does_not_exist.jsonl")

        events, offset = poll_capture(42)
        assert events == []
        assert offset == 42


class TestLogTailerOffsets:
    def test_simulated_restart_does_not_reread_old_events(self, tmp_path, monkeypatch):
        f = tmp_path / "auth.log"
        f.write_text(
            "2026-09-15T04:58:07Z sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        )
        import collectors.log_tailer as lt
        monkeypatch.setattr(lt, "AUTH_LOG_FILE", f)

        events1, offset_after_first_run = poll_log(0)
        assert len(events1) == 1

        events2, offset_after_restart = poll_log(offset_after_first_run)
        assert events2 == []
        assert offset_after_restart == offset_after_first_run

    def test_new_lines_after_restart_are_picked_up(self, tmp_path, monkeypatch):
        f = tmp_path / "auth.log"
        f.write_text(
            "2026-09-15T04:58:07Z sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        )
        import collectors.log_tailer as lt
        monkeypatch.setattr(lt, "AUTH_LOG_FILE", f)

        _, offset = poll_log(0)

        with f.open("a") as fh:
            fh.write("2026-09-15T04:58:09Z sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2\n")

        events, _ = poll_log(offset)
        assert len(events) == 1