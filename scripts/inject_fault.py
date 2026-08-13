#!/usr/bin/env python3
import json
import os
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"Command failed: {cmd}\nStderr: {res.stderr}")
    return res

def get_octet():
    var_path = os.path.join(ROOT_DIR, "configs", "variant.json")
    if os.path.exists(var_path):
        with open(var_path, "r") as f:
            return json.load(f).get("second_octet", 51)
    return 51

def inject_fault1():
    """Fault 1: Remove established-return handling for finance path."""
    octet2 = get_octet()
    nft_fault1 = f"""flush ruleset
table inet segmentation {{
  chain forward {{
    type filter hook forward priority 0; policy drop;

    # Anti-spoofing
    iifname "eth2" ip saddr != 10.{octet2}.40.0/24 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth3" ip saddr != 10.{octet2}.20.0/26 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth4" ip saddr != 10.{octet2}.30.0/25 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth5" ip saddr != 10.{octet2}.50.0/27 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth6" ip saddr != 10.{octet2}.10.0/27 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth7" ip saddr != 10.{octet2}.70.0/24 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth8" ip saddr != 10.{octet2}.60.0/28 counter log prefix "NF_SPOOF_DENY " drop

    # FAULT 1: Established return handling EXCLUDES finance path (eth3 / 10.{octet2}.20.0/26)
    iifname != "eth3" oifname != "eth3" ct state established,related accept comment "established-return-non-finance"

    # Management Ingress
    iifname "eth6" oifname {{ "eth2", "eth3", "eth4", "eth5", "eth7", "eth8" }} tcp dport 22 accept comment "management-admin"

    # Business paths
    iifname "eth3" oifname "eth5" tcp dport {{ 443, 445, 5432 }} accept comment "finance-to-payroll"
    iifname "eth4" oifname "eth5" tcp dport {{ 22, 443, 8443 }} accept comment "engineering-to-code"
    iifname "eth2" oifname "eth5" tcp dport 443 accept comment "users-to-servers"

    # Centralized DNS and NTP
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8" }} oifname "eth5" udp dport {{ 53, 123 }} accept comment "central-dns-ntp"
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8" }} oifname "eth5" tcp dport 53 accept comment "central-dns-tcp"

    # Guest -> DMZ
    iifname "eth7" oifname "eth8" tcp dport {{ 80, 443 }} accept comment "guest-to-dmz-web"

    # DMZ -> Servers
    iifname "eth8" oifname "eth5" tcp dport {{ 443, 5432 }} accept comment "dmz-to-approved-server"

    # Default deny
    counter log prefix "NF_SEGMENT_DENY " drop
  }}
}}
"""
    nft_path = os.path.join(ROOT_DIR, "configs", "gateway", "nftables.conf")
    with open(nft_path, "w") as f:
        f.write(nft_fault1)
    run_cmd("docker exec clab-netforge-a3-gateway nft -f /etc/nftables.conf")
    print("Fault 1 injected: Established return handling removed for finance path.")

def inject_fault2():
    """Fault 2: Broaden management ingress beyond declared source."""
    octet2 = get_octet()
    nft_fault2 = f"""flush ruleset
table inet segmentation {{
  chain forward {{
    type filter hook forward priority 0; policy drop;

    ct state established,related accept comment "established-return"

    # FAULT 2: Broadened management ingress to allow eth2 (Users) as well as eth6
    iifname {{ "eth2", "eth6" }} oifname {{ "eth2", "eth3", "eth4", "eth5", "eth7", "eth8" }} tcp dport 22 accept comment "broadened-management-admin"

    # Business paths
    iifname "eth3" oifname "eth5" tcp dport {{ 443, 445, 5432 }} accept comment "finance-to-payroll"
    iifname "eth4" oifname "eth5" tcp dport {{ 22, 443, 8443 }} accept comment "engineering-to-code"
    iifname "eth2" oifname "eth5" tcp dport 443 accept comment "users-to-servers"

    # Default deny
    counter log prefix "NF_SEGMENT_DENY " drop
  }}
}}
"""
    nft_path = os.path.join(ROOT_DIR, "configs", "gateway", "nftables.conf")
    with open(nft_path, "w") as f:
        f.write(nft_fault2)
    run_cmd("docker exec clab-netforge-a3-gateway nft -f /etc/nftables.conf")
    print("Fault 2 injected: Management ingress broadened to allow Users zone (eth2).")

def inject_fault3():
    """Fault 3: Remove DMZ-to-server traffic from sensor mirror."""
    run_cmd("docker exec clab-netforge-a3-gateway tc filter del dev eth8 ingress")
    print("Fault 3 injected: DMZ interface (eth8) mirror rule deleted on gateway.")

def inject_fault4():
    """Fault 4 (D1): Make finance-zone return path asymmetric through core."""
    octet2 = get_octet()
    # Replace gateway's connected route to finance with a route through core.
    # This creates asymmetric return: return traffic for finance goes
    # gateway→core→gateway (via eth1 transit) instead of direct delivery via eth3,
    # causing TTL exhaustion / routing loop that breaks the TCP handshake.
    run_cmd(f"docker exec clab-netforge-a3-gateway ip route replace 10.{octet2}.20.0/26 via 10.{octet2}.254.1 dev eth1")
    print(f"Fault 4 (D1) injected: Finance return path (10.{octet2}.20.0/26) set asymmetric through core.")

def restore():
    """Restore clean baseline state."""
    # Regenerate configs from variant.json
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'build_configs.py')}")
    # Reload nftables rules
    run_cmd("docker exec clab-netforge-a3-gateway nft -f /etc/nftables.conf")
    octet2 = get_octet()
    # Restore tc mirror rules on gateway (without running full bootstrap.sh which blocks on tail)
    for iface in ["eth1", "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8"]:
        run_cmd(f"docker exec clab-netforge-a3-gateway tc qdisc add dev {iface} clsact", check=False)
        run_cmd(f"docker exec clab-netforge-a3-gateway tc filter add dev {iface} ingress matchall action mirred egress mirror dev eth9", check=False)
    # Restore all connected routes on gateway (fault4 destroys the finance connected route)
    route_map = {
        "eth2": ("40.0/24", "40.1"),   # users
        "eth3": ("20.0/26", "20.1"),   # finance
        "eth4": ("30.0/25", "30.1"),   # engineering
        "eth5": ("50.0/27", "50.1"),   # servers
        "eth6": ("10.0/27", "10.1"),   # management
        "eth7": ("70.0/24", "70.1"),   # guest
        "eth8": ("60.0/28", "60.1"),   # dmz
    }
    for iface, (subnet, gw_host) in route_map.items():
        run_cmd(f"docker exec clab-netforge-a3-gateway ip route replace 10.{octet2}.{subnet} dev {iface} scope link src 10.{octet2}.{gw_host}", check=False)
    # Restore routes on servers and core
    run_cmd(f"docker exec clab-netforge-a3-servers ip route replace default via 10.{octet2}.50.1")
    run_cmd(f"docker exec clab-netforge-a3-core ip route replace 10.{octet2}.0.0/16 via 10.{octet2}.254.2", check=False)
    print("Baseline restored cleanly.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: inject_fault.py <fault1|fault2|fault3|fault4|restore>")
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    if cmd == "fault1":
        inject_fault1()
    elif cmd == "fault2":
        inject_fault2()
    elif cmd == "fault3":
        inject_fault3()
    elif cmd == "fault4":
        inject_fault4()
    elif cmd == "restore":
        restore()
    else:
        print(f"Unknown fault command: {cmd}")
        sys.exit(1)
