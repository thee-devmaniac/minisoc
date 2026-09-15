import ipaddress

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from discovery.nmap_scanner import NmapScanError, scan_subnet
from persistence import repository
from persistence.db import get_session

router = APIRouter(prefix="/devices", tags=["devices"])


class DiscoverRequest(BaseModel):
    subnet: str

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError("subnet must be a valid CIDR, e.g. 172.28.0.0/24") from exc
        return v


def _serialize(device) -> dict:
    return {
        "id": str(device.id),
        "ip_address": str(device.ip_address),
        "hostname": device.hostname,
        "open_ports": device.open_ports,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }


@router.post("/discover")
def discover(req: DiscoverRequest):
    """Runs an on-demand Nmap TCP connect scan against the given subnet and
    upserts results into the device inventory (LLD §6, FR2/FR3)."""
    try:
        hosts = scan_subnet(req.subnet)
    except NmapScanError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    with get_session() as session:
        devices = [
            repository.upsert_device(session, h["ip_address"], h["hostname"], h["open_ports"])
            for h in hosts
        ]
        return {
            "discovered": len(devices),
            "devices": [_serialize(d) for d in devices],
        }


@router.get("")
def list_devices():
    with get_session() as session:
        devices = repository.list_devices(session)
        return [_serialize(d) for d in devices]