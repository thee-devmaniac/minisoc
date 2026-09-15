# Low-Level Design — Network Intrusion Detection & Security Monitoring Platform (MVP)

Status: Baseline agreed. Implementation not yet started.
Scope: This document covers the MVP only. Version 2 and Advanced features are named but not designed here.

---

## 1. Problem Definition

Build a small, honest security monitoring platform — not a Suricata/Zeek competitor — that:
- Collects network and host telemetry from a lab environment you own
- Turns raw telemetry into structured security events via explicit, testable detection rules
- Surfaces those events through an API and a minimal view

The deliverable claim is: *"I built a detection engine and validated it against a controlled adversarial lab,"* not *"I built an IDS."*

### Limitations (explicit, not hidden)
- No encrypted-traffic inspection
- No malware/file analysis
- No wireless attack detection
- No live external threat intelligence feeds
- Not designed to resist a deliberately evasive adversary — detects common, unsophisticated attack patterns only

---

## 2. Threat Model

**Assets:** lab hosts/services under monitoring, the platform's own event data, credentials used by collectors.

**Attacker model:** an attacker with network access to the lab segment, or attempting SSH access against a lab host. Not a nation-state adversary evading detection deliberately.

**In scope to detect:**
- Reconnaissance (port/service scanning)
- Credential brute-forcing
- Anomalous connection volume/bursts
- Unexpected exposed services (later milestone)

**Out of scope:**
- Encrypted payload inspection
- Malware/file-based threats
- Wireless-specific attacks
- Detection evasion resistance

**Trust boundary:** everything runs inside an isolated Docker network with no route to the real LAN or internet beyond build-time package installs. The platform itself is an asset once it holds real event data (API/DB access matters even though auth is deferred past MVP).

---

## 3. Requirements

### 3.1 Functional (MVP)

| ID | Requirement |
|----|-------------|
| FR1 | Docker Compose lab network with isolated target, attacker, capture, platform, db containers |
| FR2 | On-demand host/port discovery via Nmap |
| FR3 | Persist discovered hosts as device inventory |
| FR4 | Capture raw TCP connection attempts via Scapy (src/dst IP, dst port, timestamp, flags) |
| FR5 | Tail SSH auth logs on target, parse failed/successful attempts |
| FR6 | Normalize both telemetry types into a common RawEvent schema |
| FR7 | Detect port-scan behavior (distinct ports/source/window) |
| FR8 | Detect SSH brute-force behavior (failures/source/window) |
| FR9 | Each detection rule independently defined — new rules added without modifying existing ones |
| FR10 | Persist security events (severity, category, source/dest, timestamp, evidence reference) |
| FR11 | Read-only API: list/filter events by severity, time, source |
| FR12 | Minimal event view (bare JSON/HTML list — no dashboard styling yet) |

### 3.2 Non-Functional

- **Reproducibility:** entire stack comes up via `docker compose up` on a clean machine with only Docker installed
- **Portability:** no host-OS-specific dependencies beyond Docker
- **Observability:** every collector and the detection engine logs its own activity, not just alerts
- **Testability:** detection rules unit-testable against synthetic RawEvent data, no live capture required
- **Extensibility:** new rule or telemetry source requires no modification to existing ones
- **Performance:** explicitly deferred — correctness and clarity prioritized for MVP

### 3.3 Security

- Isolated lab network, no route to real LAN/internet beyond build-time
- Least privilege: only the `capture` container gets `NET_RAW`/`NET_ADMIN`
- Secrets via `.env`, never committed, from Milestone 1
- No-auth-on-localhost API is an accepted, documented shortcut for MVP only — closed before Version 2
- Raw evidence behind every detection event must remain retrievable (audit trail)
- All parsed input passes through the normalization layer before reaching DB or API — no raw interpolation into SQL/shell

### 3.4 Explicitly Deferred

API auth/authz, TLS between components, alert correlation/dedup, dashboard styling, external threat intel, ML/anomaly detection.

### 3.5 Confirmed MVP Technology Stack

Each choice evaluated against alternatives before confirming — see project history for full rationale. Summary:

| Component | Choice | MVP verdict | Notes |
|---|---|---|---|
| Backend | Python + FastAPI | Confirmed | Async support, Pydantic validation at API boundary |
| Frontend | Next.js + TypeScript + Tailwind | Confirmed, **deferred** | Not touched until Milestone 6+; MVP view is bare JSON/HTML per FR12 |
| Database | PostgreSQL | Confirmed | Relational fit for devices/rules/events; `jsonb` for variable raw payloads |
| Cache/messaging | Redis | **Cut from MVP** | Windowed rule state kept in-process for MVP; reintroduce at correlation (Version 2, Phase 8) when shared state across processes is actually needed |
| Packet analysis | Scapy | Confirmed | Python-native, transparent parsing — central to the project's learning goal |
| Network discovery | Nmap | Confirmed | Also used by the attacker container (dual use) |
| Containerization | Docker + Docker Compose | Confirmed | Kubernetes explicitly rejected — no learning payoff for a 5-container lab |
| Attack tooling (attacker container) | Nmap (recon) + Hydra (SSH brute-force) | Confirmed | Generates real, realistic telemetry rather than synthetic test data |

**Principle applied:** no dependency is introduced before it's earned. Redis is the clearest example — it has an obvious future home (Phase 8 correlation) but no justified MVP use yet.

---

## 4. Lab Topology

```
docker-compose network (isolated, build-time-only egress)
├── target      — SSH server + one other exposed service; generates auth.log
├── attacker    — nmap, hydra; scripted, on-demand, no autonomous runs
├── capture     — Scapy sniffer; NET_RAW/NET_ADMIN; passive
├── platform    — FastAPI backend: normalizer + detection engine + API
└── db          — Postgres
```

**Attacker container guardrails:**
- Reaches only `target` inside the Compose network — no internet, no real LAN
- Driven by deliberate scripts (`docker compose run attacker <script>`), never autonomous
- Every run logged (what/when) — this is the ground truth used to validate detection output

**Open implementation question for Milestone 1:** Docker's default bridge network does not let one container passively sniff another's traffic for free. `capture` will likely need `network_mode: service:target` or a macvlan setup — to be resolved concretely during environment setup, not assumed.

---

## 5. Data Flow

```
1. RAW TELEMETRY
   capture: TCP SYN observed (src=attacker, dst=target, dport=22)
   target:  sshd logs "Failed password for root from <ip>"

2. COLLECTION
   Scapy sniffer -> local buffer/file
   Log tailer -> local buffer/file

3. NORMALIZATION
   -> RawEvent { source_ip, dest_ip, dest_port, event_type, timestamp, raw_payload }
   event_type: "tcp_syn" | "ssh_auth_failure"
   (input validation owned here — nothing unparsed touches DB)

4. DETECTION
   Rules subscribe to relevant event_types, keep windowed state per source_ip
   PortScanRule:   distinct dest_ports / source_ip / window
   BruteForceRule: failure count / source_ip / window
   Threshold trip -> SecurityEvent

5. SECURITY EVENT
   { rule_id, category, severity_score, source_ip, target_host,
     description, evidence_ref, first_seen, last_seen, event_count }

6. STORAGE — Postgres

7. API — read-only, filterable by severity/time/source

8. VIEW — bare JSON/HTML list (MVP only)
```

Note: `SecurityEvent` and `Alert` are the same row for MVP. The split arrives with correlation (Version 2, Phase 8) — see Section 9.

---

## 6. Database Schema (MVP)

### `devices`
```
id            uuid PK
ip_address    inet
hostname      text, nullable
open_ports    int[]
first_seen    timestamptz
last_seen     timestamptz
```

### `raw_events`  (audit trail — indexed on (event_type, source_ip, occurred_at))
```
id            uuid PK
event_type    text        -- 'tcp_syn' | 'ssh_auth_failure'
source_ip     inet
dest_ip       inet, nullable
dest_port     int, nullable
occurred_at   timestamptz
raw_payload   jsonb
```

### `detection_rules`  (metadata only — logic lives in code)
```
id                text PK   -- e.g. 'port_scan_v1'
name              text
description       text
category          text      -- 'reconnaissance' | 'credential_access' | ...
default_severity  int
enabled           boolean
```

### `security_events`  (event + alert collapsed for MVP)
```
id                uuid PK
rule_id           text FK -> detection_rules
severity_score    int          -- 0-100, source of truth
severity_label    text         -- derived from score, stored for query convenience
source_ip         inet
target_device_id  uuid FK -> devices, nullable
description       text
event_count       int
window_start      timestamptz
window_end        timestamptz
created_at        timestamptz
evidence_ids      uuid[]       -- -> raw_events
acknowledged      boolean default false
```

**Severity model:** numeric score (0–100) is the source of truth; `severity_label` is a derived enum (e.g., 0–30 low, 31–60 medium, 61–85 high, 86–100 critical) computed via one shared mapping function — never allowed to drift independently from the score. Confidence is folded into the single score for MVP; splitting severity vs. confidence into separate fields is a named Version 2 refinement.

**Known seam:** `raw_events` grows fast even in a small lab. No retention policy for MVP — flagged as a decision point before this goes anywhere near production-like volume.

**Deliberately not modeled yet:** `alerts` (separate from events), `users`/auth, `threat_intel_indicators`.

---

## 7. Component Boundaries

```
platform/
├── collectors/
│   ├── log_tailer.py       -- tails target auth.log -> RawEvents
│   └── capture_client.py   -- reads capture container's output -> RawEvents
├── normalization/
│   └── normalizer.py       -- source-specific formats -> common RawEvent schema
├── detection/
│   ├── base.py             -- DetectionRule interface
│   ├── port_scan.py
│   ├── brute_force.py
│   └── engine.py           -- dispatches events, manages windowed state
├── persistence/
│   ├── models.py           -- SQLAlchemy models
│   └── repository.py       -- sole owner of SQL access
├── api/
│   └── routes/ (events.py, devices.py)
└── main.py
```

**Dependency rule:** one direction only. `api` → `persistence`, `detection`; `detection` → `normalization`'s output shape only; `collectors` know nothing about detection or API. A rule file importing from `api/`, or `detection/` reaching into `collectors/`, is a boundary leak — treat as a bug.

### `DetectionRule` interface (MVP, deliberately minimal)
```python
class DetectionRule:
    id: str
    subscribes_to: list[str]   # event_types this rule cares about
    def evaluate(self, event: RawEvent, window_state) -> SecurityEvent | None
```
`engine.py` owns windowing/state (e.g., "last N minutes per source_ip"). Rules are stateless from their own perspective — this is what makes FR9 and the unit-testability NFR actually hold.

---

## 8. Privileged Boundary: `capture` ↔ platform

- `capture` has `NET_RAW`/`NET_ADMIN`, runs Scapy, does the **minimum processing possible** — capture, not judgment
- `capture` has **no DB access**. A compromised, network-sniffing, privileged container should not also hold DB credentials — packet parsers are a real attack surface
- **Interface:** `capture` writes JSON-lines to a shared Docker volume file; `collectors/capture_client.py` in the platform container tails it — same pattern as `log_tailer.py`, one consistent transport mechanism for both collectors
- **Trade-off accepted for MVP:** file-based handoff has a small partial-write race window on crash. Acceptable for a lab MVP; not acceptable in anything real. Named future improvement: named pipe or unix socket.

---

## 9. What Changes in Version 2 (named, not designed)

- `security_events` splits into `events` (raw detections) + `alerts` (correlated/deduped groupings)
- Correlation logic: e.g., repeated brute-force detections from one IP within a window → one alert with a count, not N rows
- Severity/confidence split into separate fields
- API authentication
- Dashboard replaces bare list view
- Additional rules: connection bursts, unexpected exposed services

---

## 10. Milestone Roadmap (MVP)

1. Lab environment: Compose network, target + attacker containers, resolve capture's traffic-visibility approach
2. Nmap discovery → device inventory in Postgres
3. Scapy capture → raw connection-attempt logging (no detection yet)
4. First detection rule: port scan, built against the `DetectionRule` interface
5. SSH auth log ingestion → brute-force detection
6. Minimal read-only API + bare alert list

Each milestone: objective → security concept learned → architecture impact → implementation → tests → manual verification → security review → docs. No milestone starts until the previous one works and is understood, not just running.

---

## 11. Repository Structure

Repo name: **`minisoc`**

```
minisoc/
│
├── platform/                    # the monolith backend
│   ├── collectors/
│   │   ├── log_tailer.py
│   │   └── capture_client.py
│   ├── normalization/
│   │   └── normalizer.py
│   ├── detection/
│   │   ├── base.py
│   │   ├── port_scan.py
│   │   ├── brute_force.py
│   │   └── engine.py
│   ├── persistence/
│   │   ├── models.py
│   │   └── repository.py
│   ├── api/
│   │   └── routes/
│   │       ├── events.py
│   │       └── devices.py
│   ├── main.py
│   └── requirements.txt / pyproject.toml
│
├── capture/                      # separate, privileged container's own code
│   ├── sniffer.py                 # Scapy logic — isolated from platform/
│   └── Dockerfile
│
├── attacker/                      # scripted attack tooling
│   ├── scripts/
│   │   ├── run_portscan.sh
│   │   └── run_bruteforce.sh
│   └── Dockerfile
│
├── target/
│   └── Dockerfile                 # SSH server + exposed service, log config
│
├── frontend/                      # exists but untouched until Milestone 6+
│   └── (Next.js app, created when we get there)
│
├── tests/
│   ├── unit/
│   │   └── detection/              # rules tested against synthetic RawEvents
│   └── integration/
│
├── docs/
│   ├── LLD.md
│   ├── ARCHITECTURE.md             # thin — points back to LLD for now
│   ├── THREAT_MODEL.md             # extracted from LLD §2 once stable
│   └── DETECTION_RULES.md          # grows as rules are added, one entry per rule
│
├── scripts/                        # dev convenience scripts only — attack scripts live in attacker/
│
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└── Makefile
```

**Deliberate choices:**
- `capture/`, `attacker/`, `target/` are separate top-level directories, not subfolders of `platform/` — they are genuinely separate deployable units with separate Dockerfiles and privilege levels. The "modular monolith" applies to `platform/` internally, not to the lab topology around it.
- No `infrastructure/` folder — no IaC in this project; don't create empty aspirational folders.
- `docs/DETECTION_RULES.md` starts skeletal and grows one entry per shipped rule — doubles as an evidence log of what was built and why.

**What never lives where:**
- No SQL/Postgres-specific logic outside `persistence/repository.py`
- No detection logic inside `api/routes/` — routes call into `detection`/`persistence`, never contain rule logic
- No raw packet-parsing code in `platform/` — stays in `capture/`, crossing only via the file-based handoff designed in §8
