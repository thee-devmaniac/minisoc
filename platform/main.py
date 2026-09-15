"""
Milestone 1: adds real device-discovery routes on top of the Phase 5 scaffold.

Table creation uses Base.metadata.create_all() on startup rather than Alembic
migrations — a deliberate MVP shortcut (same category as deferring Redis,
LLD §3.5). Fine while there's one table and one developer; revisit once the
schema needs to evolve without dropping data.
"""
import os

from fastapi import FastAPI
from sqlalchemy import create_engine, text

from api.routes import devices
from persistence.db import engine
from persistence.models import Base

app = FastAPI(title="minisoc-platform", version="0.1.0-milestone1")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

Base.metadata.create_all(bind=engine)

app.include_router(devices.router)


@app.get("/health")
def health():
    """Liveness check — does not touch the DB."""
    return {"status": "ok"}


@app.get("/health/db")
def health_db():
    """Readiness check — confirms the platform can actually reach Postgres.
    This is the check to run first when verifying Phase 5 is complete."""
    if not DATABASE_URL:
        return {"status": "error", "detail": "DATABASE_URL not set"}
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "reachable"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}