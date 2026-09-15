"""
Milestone 2/3: adds real detection on top of Milestone 1's discovery routes.

Table creation uses Base.metadata.create_all() on startup rather than Alembic
migrations — a deliberate MVP shortcut (same category as deferring Redis,
LLD §3.5). Fine while there's one developer and the schema is still moving;
revisit once it needs to evolve without dropping data.

The detection pipeline runs as a background asyncio polling loop, started
on FastAPI startup: poll capture's shared volume -> normalize -> dispatch to
DetectionEngine -> persist raw + security events. Polling (not push) was the
deliberate choice discussed for this milestone — closer to a real monitoring
system's behavior than an on-demand trigger.
"""
import asyncio
import os

from fastapi import FastAPI
from sqlalchemy import create_engine as _create_engine, text

from api.routes import devices, security_events
from collectors.capture_client import poll_new_events
from detection.engine import DetectionEngine
from detection.port_scan import PortScanRule
from normalization.normalizer import normalize_capture_event
from persistence import repository
from persistence.db import engine as db_engine, get_session
from persistence.models import Base

POLL_INTERVAL_SECONDS = 5

app = FastAPI(title="minisoc-platform", version="0.2.0-milestone2-3")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

Base.metadata.create_all(bind=db_engine)

app.include_router(devices.router)
app.include_router(security_events.router)

detection_engine = DetectionEngine(rules=[PortScanRule()])


async def _poll_loop():
    while True:
        try:
            raw_events = poll_new_events()
            for raw in raw_events:
                event = normalize_capture_event(raw)
                if event is None:
                    continue
                detection_engine.process(event)
        except Exception as exc:  # noqa: BLE001 - poll loop must never die silently or crash the app
            print(f"[poll_loop] error processing batch: {exc}")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
async def on_startup():
    with get_session() as session:
        repository.ensure_rule(
            session,
            id="port_scan_v1",
            name="Port Scan",
            description="Source IP attempted connections to 5+ distinct ports within 60s",
            category="reconnaissance",
            default_severity=60,
        )
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