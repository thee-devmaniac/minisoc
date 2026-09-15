# minisoc

A small, honest network intrusion detection & security monitoring learning platform.

This is **not** a production IDS and is not intended to be one. It's a deliberately
scoped project to build real understanding of network telemetry, detection
engineering, and security event correlation — validated against a controlled
lab, never against systems outside it.

Full design context lives in [`docs/LLD.md`](docs/LLD.md) — read that first.

## Current status: Phase 5 — environment scaffold

No detection logic exists yet. This stage only proves the five-container lab
topology (`db`, `platform`, `target`, `attacker`, `capture`) comes up cleanly
and can reach each other as designed.

## Quickstart

```bash
cp .env.example .env    # edit if you want different local credentials
docker compose up -d db target capture platform
```

Then verify:

```bash
curl http://localhost:8000/health       # platform is serving
curl http://localhost:8000/health/db    # platform can reach postgres
docker compose logs capture             # heartbeat lines appearing every 30s
```

The `attacker` container is never started automatically:

```bash
docker compose run attacker ./run_portscan.sh
```

## Project layout

See `docs/LLD.md` §11 for the full rationale. Short version:

- `platform/` — the backend monolith (collectors, normalization, detection, persistence, API)
- `capture/` — privileged packet-sniffing container, isolated from platform's own code
- `attacker/`, `target/` — the lab itself
- `docs/` — LLD, architecture, threat model, detection rule log

## Safety boundary

All offensive tooling in `attacker/` only ever targets `target/`, inside the
isolated `lab_net` Docker network. Nothing in this repo is intended to scan,
attack, or monitor any system you do not own or have explicit authorization
to test.
