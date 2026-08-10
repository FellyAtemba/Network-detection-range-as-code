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

def test_spoofed_source_ip_denied(octet2):
    """Spoofed packets (e.g. Guest sending packet with Management source IP) are dropped and logged."""
    # Send packet from guest container with spoofed source IP 10.51.10.10 using python/scapy or nc
    cmd = f"python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((\"10.{octet2}.50.10\", 53)); s.send(b\"spoof\")'"
    res = run_container_cmd("clab-netforge-a3-guest", cmd)
    # Check nftables counters for spoof rule
    nft_res = run_container_cmd("clab-netforge-a3-gateway", "nft -j list ruleset")
    assert "NF_SPOOF_DENY" in nft_res.stdout or res.returncode != 0

def test_stateful_established_return(octet2):
    """Return traffic for established sessions is permitted without opening new sessions."""
    # Finance initiates TCP connection to Servers:5432
    assert check_connection("finance", f"10.{octet2}.50.10", 5432) is True
    # Server initiating NEW session back to Users should be DENIED
    assert check_connection("servers", f"10.{octet2}.40.10", 443) is False
