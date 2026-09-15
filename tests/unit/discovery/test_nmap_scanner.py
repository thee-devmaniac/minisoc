import pytest

from discovery.nmap_scanner import (
    NmapScanError,
    _parse_nmap_xml,
    _validate_cidr,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="172.28.0.2" addrtype="ipv4"/>
    <hostnames><hostname name="target.lab_net" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="172.28.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parses_up_host_with_open_port_only():
    hosts = _parse_nmap_xml(SAMPLE_XML)

    assert len(hosts) == 1  # the "down" host must be excluded
    host = hosts[0]
    assert host["ip_address"] == "172.28.0.2"
    assert host["hostname"] == "target.lab_net"
    assert host["open_ports"] == [22]  # closed port 80 must be excluded


def test_validate_cidr_accepts_valid_range():
    _validate_cidr("172.28.0.0/24")  # should not raise


def test_validate_cidr_rejects_garbage():
    with pytest.raises(NmapScanError):
        _validate_cidr("not-a-subnet")


def test_validate_cidr_rejects_single_ip_masquerading_as_cidr_is_allowed():
    # strict=False means a host address like this is accepted as a /32 —
    # documenting the behavior explicitly rather than leaving it implicit.
    _validate_cidr("172.28.0.2")