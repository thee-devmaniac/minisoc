"""
Phase 5 scope only: prove this container runs with NET_RAW/NET_ADMIN and can
write to the shared handoff volume (/var/minisoc/capture) that platform's
capture_client.py will read from (LLD §8).

Real packet sniffing + JSON-lines event emission arrives in Milestone 3.
"""
import json
import time
from pathlib import Path

OUTPUT_DIR = Path("/var/minisoc/capture")
OUTPUT_FILE = OUTPUT_DIR / "events.jsonl"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("[capture] scaffold running — no real sniffing yet (see Milestone 3)")
    while True:
        heartbeat = {"type": "heartbeat", "ts": time.time()}
        with OUTPUT_FILE.open("a") as f:
            f.write(json.dumps(heartbeat) + "\n")
        time.sleep(30)


if __name__ == "__main__":
    main()
