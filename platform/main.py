"""
Version 2, Phase 0: fixes the offset-persistence gap discovered while
running Milestone 5 for real — a platform restart previously re-read both
shared files from byte 0, re-detecting already-seen events. Offsets are now
persisted in Postgres (collector_state table) and loaded on startup.

Table creation uses Base.metadata.create_all() on startup rather than Alembic
migrations — a deliberate MVP shortcut (same category as deferring Redis,
LLD §3.5). Fine while there's one developer and the schema is still moving;
revisit once it needs to evolve without dropping data.
"""
import asyncio
import os

from fastapi import FastAPI
from sqlalchemy import create_engine as _create_engine, text

from api.routes import devices, security_events
from collectors.capture_client import poll_new_events as poll_new_capture_events
from collectors.log_tailer import poll_new_events as poll_new_log_events
from detection.brute_force import BruteForceRule
from detection.engine import DetectionEngine
from detection.port_scan import PortScanRule
from normalization.normalizer import normalize_capture_event, normalize_log_event
from persistence import repository
from persistence.db import engine as db_engine, get_session
from persistence.models import Base

POLL_INTERVAL_SECONDS = 5

CAPTURE_COLLECTOR_ID = "capture_events"
LOG_COLLECTOR_ID = "auth_log"

app = FastAPI(title="minisoc-platform", version="0.4.0-offset-persistence")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

Base.metadata.create_all(bind=db_engine)

app.include_router(devices.router)
app.include_router(security_events.router)

detection_engine = DetectionEngine(rules=[PortScanRule(), BruteForceRule()])

# Loaded from persistence at startup, updated in-process, written back to
# persistence only when they actually advance.
_capture_offset = 0
_log_offset = 0


async def _poll_loop():
    global _capture_offset, _log_offset

    while True:
        try:
            capture_raw, new_capture_offset = poll_new_capture_events(_capture_offset)
            for raw in capture_raw:
                event = normalize_capture_event(raw)
                if event is not None:
                    detection_engine.process(event)
            if new_capture_offset != _capture_offset:
                _capture_offset = new_capture_offset
                with get_session() as session:
                    repository.set_offset(session, CAPTURE_COLLECTOR_ID, _capture_offset)

            log_raw, new_log_offset = poll_new_log_events(_log_offset)
            for raw in log_raw:
                event = normalize_log_event(raw)
                if event is not None:
                    detection_engine.process(event)
            if new_log_offset != _log_offset:
                _log_offset = new_log_offset
                with get_session() as session:
                    repository.set_offset(session, LOG_COLLECTOR_ID, _log_offset)

        except Exception as exc:  # noqa: BLE001 - poll loop must never die silently or crash the app
            print(f"[poll_loop] error processing batch: {exc}")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
async def on_startup():
    global _capture_offset, _log_offset

    with get_session() as session:
        repository.ensure_rule(
            session,
            id="port_scan_v1",
            name="Port Scan",
            description="Source IP attempted connections to 5+ distinct ports within 60s",
            category="reconnaissance",
            default_severity=60,
        )
        repository.ensure_rule(
            session,
            id="brute_force_v1",
            name="SSH Brute Force",
            description="Source IP had 5+ failed SSH login attempts within 60s",
            category="credential_access",
            default_severity=70,
        )
        _capture_offset = repository.get_offset(session, CAPTURE_COLLECTOR_ID)
        _log_offset = repository.get_offset(session, LOG_COLLECTOR_ID)

    print(f"[startup] resuming from offsets: capture={_capture_offset}, auth_log={_log_offset}")
    asyncio.create_task(_poll_loop())


@app.get("/health")
def health():
    """Liveness check — does not touch the DB."""
    return {"status": "ok"}


@app.get("/health/db")
def health_db():
    """Readiness check — confirms the platform can actually reach Postgres."""
    if not DATABASE_URL:
        return {"status": "error", "detail": "DATABASE_URL not set"}
    try:
        engine = _create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "reachable"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}