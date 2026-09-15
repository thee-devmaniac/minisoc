"""
Milestone 2/3: real packet capture, replacing the Phase 5 heartbeat stub.

Captures TCP SYN packets only (SYN set, ACK not set) — i.e. connection
attempts, not full traffic. This deliberately matches the project's stated
scope (LLD §1: no payload inspection) and is sufficient for port-scan
detection: both -sT (full connect) and -sS (SYN-only) scans send a SYN for
every port they probe, so this single signal covers both scan types.

Because `capture` runs with network_mode: service:target (LLD §4), sniffing
the default interface here observes target's actual traffic.
"""
import json
import time
from pathlib import Path

from scapy.all import IP, TCP, sniff

OUTPUT_DIR = Path("/var/minisoc/capture")
OUTPUT_FILE = OUTPUT_DIR / "events.jsonl"

SYN_FLAG = 0x02
ACK_FLAG = 0x10


def _append_event(event: dict) -> None:
    with OUTPUT_FILE.open("a") as f:
        f.write(json.dumps(event) + "\n")


def _handle_packet(pkt) -> None:
    if IP not in pkt or TCP not in pkt:
        return

    tcp = pkt[TCP]
    is_syn_only = bool(tcp.flags & SYN_FLAG) and not bool(tcp.flags & ACK_FLAG)
    if not is_syn_only:
        return

    event = {
        "type": "tcp_syn",
        "source_ip": pkt[IP].src,
        "dest_ip": pkt[IP].dst,
        "dest_port": int(tcp.dport),
        "ts": time.time(),
    }
    _append_event(event)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("[capture] sniffing TCP SYN packets (connection attempts) on this interface")
    sniff(filter="tcp", prn=_handle_packet, store=False)


if __name__ == "__main__":
    main()