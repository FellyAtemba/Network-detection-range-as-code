import base64
import json
import pytest
from tests.conftest import run_container_cmd, check_connection

def test_management_ssh_access_allowed(octet2):
    """Management (VLAN 10 / eth6) can initiate SSH to internal targets."""
    assert check_connection("management", f"10.{octet2}.50.10", 22) is True
    assert check_connection("management", f"10.{octet2}.20.10", 22) is True

def test_non_management_ssh_access_denied(octet2):
    """Non-management zones (e.g. Users, Guest) CANNOT initiate SSH to management/internal targets."""
    assert check_connection("users", f"10.{octet2}.10.10", 22) is False
    assert check_connection("guest", f"10.{octet2}.10.10", 22) is False
    assert check_connection("dmz", f"10.{octet2}.10.10", 22) is False

_SPOOF_UDP_SCRIPT = '''
import socket, struct, sys

def cksum(d):
    if len(d) % 2:
        d += b"\\x00"
    s = sum(struct.unpack("!%dH" % (len(d) // 2), d))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

src_ip, dst_ip = sys.argv[1], sys.argv[2]
src = socket.inet_aton(src_ip)
dst = socket.inet_aton(dst_ip)
payload = b"spoof"
ihl = (4 << 4) | 5
total_len = 20 + 8 + len(payload)
ip_hdr = struct.pack("!BBHHHBBH4s4s", ihl, 0, total_len, 54321, 0, 64, 17, 0, src, dst)
ip_hdr = ip_hdr[:10] + struct.pack("!H", cksum(ip_hdr)) + ip_hdr[12:]
udp_hdr = struct.pack("!HHHH", 40000, 53, 8 + len(payload), 0)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(ip_hdr + udp_hdr + payload, (dst_ip, 0))
'''

def _send_spoofed_udp(container, spoofed_src_ip, dst_ip):
    """Craft and send a UDP datagram from `container` with its IP source
    forged to `spoofed_src_ip`. Needs CAP_NET_RAW (a Docker default capability)."""
    encoded = base64.b64encode(_SPOOF_UDP_SCRIPT.encode()).decode()
    cmd = f"sh -c \"echo {encoded} | base64 -d | python3 - {spoofed_src_ip} {dst_ip}\""
    return run_container_cmd(container, cmd)

def _spoof_deny_packet_count(nft_json_stdout):
    """Sum packet counters across every rule logging with the NF_SPOOF_DENY prefix."""
    total = 0
    data = json.loads(nft_json_stdout)
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        exprs = rule.get("expr", [])
        if any(e.get("log", {}).get("prefix", "").strip() == "NF_SPOOF_DENY" for e in exprs):
            total += sum(e["counter"]["packets"] for e in exprs if "counter" in e)
    return total

def test_spoofed_source_ip_denied(octet2):
    """A packet arriving via Guest's interface but claiming a Management-range
    source IP is dropped by the anti-spoof rule. Confirmed by the nftables
    packet counter increasing, not just by the rule's text being present."""
    gateway = "clab-netforge-a3-gateway"
    spoofed_src = f"10.{octet2}.10.99"      # inside Management's range, not Guest's
    dst_ip = f"10.{octet2}.50.10"

    before = _spoof_deny_packet_count(run_container_cmd(gateway, "nft -j list ruleset").stdout)
    _send_spoofed_udp("clab-netforge-a3-guest", spoofed_src, dst_ip)
    after = _spoof_deny_packet_count(run_container_cmd(gateway, "nft -j list ruleset").stdout)

    assert after > before, f"NF_SPOOF_DENY packet counter did not increase ({before} -> {after})"

def test_stateful_established_return(octet2):
    """Return traffic for established sessions is permitted without opening new sessions."""
    # Finance initiates TCP connection to Servers:5432
    assert check_connection("finance", f"10.{octet2}.50.10", 5432) is True
    # Server initiating NEW session back to Users should be DENIED
    assert check_connection("servers", f"10.{octet2}.40.10", 443) is False

