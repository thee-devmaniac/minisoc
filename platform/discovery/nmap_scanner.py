"""
Runs Nmap discovery scans and parses the results into plain dicts.

Deliberately subprocess + stdlib XML parsing rather than a wrapper library
(python-nmap etc.) — same reasoning as choosing Scapy over a higher-level
capture library in the LLD: seeing exactly what's happening end to end is
the point of this project.

Uses -sT (TCP connect scan), not -sS (SYN scan): -sT needs no raw-socket
capability, keeping `platform` unprivileged per LLD §3.3/§8. -sS stays a
tool for the `attacker` container's future recon scripts.
"""
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

SCAN_TIMEOUT_SECONDS = 120


class NmapScanError(RuntimeError):
    pass


def scan_subnet(cidr: str) -> list[dict]:
    """Scan a CIDR range and return a list of {ip_address, hostname, open_ports}
    for every host that responded as up.

    Uses --top-ports 100 and -T4 timing rather than Nmap's default (top 1000
    ports, normal timing) — a full default scan across a /24 can comfortably
    exceed a two-minute timeout even in a small lab, since Nmap probes every
    possible address regardless of how many are actually in use. Revisit this
    scope trade-off in Version 2 if full port coverage becomes necessary."""
    _validate_cidr(cidr)

    try:
        result = subprocess.run(
            ["nmap", "-sT", "-T4", "--top-ports", "100", "-oX", "-", cidr],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapScanError(
            f"nmap scan of {cidr} exceeded {SCAN_TIMEOUT_SECONDS}s timeout"
        ) from exc

    if result.returncode != 0:
        raise NmapScanError(result.stderr.strip() or "nmap exited non-zero")

    return _parse_nmap_xml(result.stdout)


def _validate_cidr(cidr: str) -> None:
    """Reject anything that isn't a well-formed CIDR before it ever reaches
    subprocess — this is the input-validation boundary (LLD §3.3)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise NmapScanError(f"invalid CIDR: {cidr!r}") from exc


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        address_el = host_el.find("address")
        ip = address_el.get("addr") if address_el is not None else None
        if not ip:
            continue

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        open_ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    open_ports.append(int(port_el.get("portid")))

        hosts.append(
            {"ip_address": ip, "hostname": hostname, "open_ports": open_ports}
        )

    return hosts