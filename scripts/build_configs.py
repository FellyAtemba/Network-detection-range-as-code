#!/usr/bin/env python3
import json
import os
import sys

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    variant_file = os.path.join(root_dir, "configs", "variant.json")
    
    if not os.path.exists(variant_file):
        print(f"Error: {variant_file} not found")
        sys.exit(1)
        
    with open(variant_file, "r") as f:
        var = json.load(f)
        
    octet2 = var.get("second_octet", 51)
    
    # Create required directories
    os.makedirs(os.path.join(root_dir, "evidence", "suricata-logs"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "configs", "core"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "configs", "gateway"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "telemetry"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "pcaps"), exist_ok=True)

    # 1. Generate topology.clab.yml
    topo_content = f"""name: netforge-a3
topology:
  nodes:
    core:
      kind: linux
      image: quay.io/frrouting/frr:10.2.1
      binds:
        - {root_dir}/configs/core/frr.conf:/etc/frr/frr.conf:ro
    gateway:
      kind: linux
      image: soc-gateway:latest
      binds:
        - {root_dir}/configs/gateway/bootstrap.sh:/bootstrap.sh:ro
        - {root_dir}/configs/gateway/nftables.conf:/etc/nftables.conf:ro
    sensor:
      kind: linux
      image: jasonish/suricata:7.0.8
      cmd: /wait-and-run.sh
      binds:
        - {root_dir}/scripts/wait-and-run.sh:/wait-and-run.sh:ro
        - {root_dir}/telemetry/suricata.yaml:/etc/suricata/suricata.yaml:ro
        - {root_dir}/detections/local.rules:/var/lib/suricata/rules/suricata.rules:ro
        - {root_dir}/evidence/suricata-logs:/var/log/suricata
    users:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.40.10/24 dev eth1", "ip route replace default via 10.{octet2}.40.1"]
    finance:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.20.10/26 dev eth1", "ip route replace default via 10.{octet2}.20.1"]
    engineering:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.30.10/25 dev eth1", "ip route replace default via 10.{octet2}.30.1"]
    servers:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.50.10/27 dev eth1", "ip route replace default via 10.{octet2}.50.1"]
    management:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.10.10/27 dev eth1", "ip route replace default via 10.{octet2}.10.1"]
    guest:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.70.10/24 dev eth1", "ip route replace default via 10.{octet2}.70.1"]
    dmz:
      kind: linux
      image: soc-host:latest
      exec: ["ip address add 10.{octet2}.60.10/28 dev eth1", "ip route replace default via 10.{octet2}.60.1"]
  links:
    - endpoints: ["core:eth1", "gateway:eth1"]
    - endpoints: ["gateway:eth2", "users:eth1"]
    - endpoints: ["gateway:eth3", "finance:eth1"]
    - endpoints: ["gateway:eth4", "engineering:eth1"]
    - endpoints: ["gateway:eth5", "servers:eth1"]
    - endpoints: ["gateway:eth6", "management:eth1"]
    - endpoints: ["gateway:eth7", "guest:eth1"]
    - endpoints: ["gateway:eth8", "dmz:eth1"]
    - endpoints: ["gateway:eth9", "sensor:eth1"]
"""
    with open(os.path.join(root_dir, "topology.clab.yml"), "w") as f:
        f.write(topo_content)
        
    # 2. Generate configs/core/frr.conf
    frr_content = f"""frr defaults traditional
hostname nf-core
service integrated-vtysh-config
!
interface eth1
 ip address 10.{octet2}.254.1/30
!
ip route 10.{octet2}.0.0/16 10.{octet2}.254.2
line vty
"""
    with open(os.path.join(root_dir, "configs", "core", "frr.conf"), "w") as f:
        f.write(frr_content)
        
    # 3. Generate configs/gateway/bootstrap.sh
    bootstrap_content = f"""#!/bin/sh
set -eu
# Wait for containerlab to create ALL interfaces (eth9 is the last link)
echo "Waiting for interfaces..."
while ! ip link show eth9 >/dev/null 2>&1; do sleep 0.5; done
sleep 1
echo "Interfaces ready, configuring..."
ip address add 10.{octet2}.254.2/30 dev eth1 || true
ip address add 10.{octet2}.40.1/24 dev eth2 || true
ip address add 10.{octet2}.20.1/26 dev eth3 || true
ip address add 10.{octet2}.30.1/25 dev eth4 || true
ip address add 10.{octet2}.50.1/27 dev eth5 || true
ip address add 10.{octet2}.10.1/27 dev eth6 || true
ip address add 10.{octet2}.70.1/24 dev eth7 || true
ip address add 10.{octet2}.60.1/28 dev eth8 || true
ip link set eth9 promisc on || true
for interface in eth1 eth2 eth3 eth4 eth5 eth6 eth7 eth8; do
  tc qdisc add dev "$interface" clsact || true
  tc filter add dev "$interface" ingress matchall action mirred egress mirror dev eth9 || true
done
sysctl -w net.ipv4.ip_forward=1
nft -f /etc/nftables.conf
tail -f /dev/null
"""
    with open(os.path.join(root_dir, "configs", "gateway", "bootstrap.sh"), "w") as f:
        f.write(bootstrap_content)
    os.chmod(os.path.join(root_dir, "configs", "gateway", "bootstrap.sh"), 0o755)

    # 4. Generate configs/gateway/nftables.conf
    nft_content = f"""flush ruleset
table ip nat {{
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    oifname "eth1" masquerade
  }}
}}
table inet segmentation {{
  chain forward {{
    type filter hook forward priority 0; policy drop;

    # Anti-spoofing checks
    iifname "eth2" ip saddr != 10.{octet2}.40.0/24 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth3" ip saddr != 10.{octet2}.20.0/26 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth4" ip saddr != 10.{octet2}.30.0/25 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth5" ip saddr != 10.{octet2}.50.0/27 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth6" ip saddr != 10.{octet2}.10.0/27 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth7" ip saddr != 10.{octet2}.70.0/24 counter log prefix "NF_SPOOF_DENY " drop
    iifname "eth8" ip saddr != 10.{octet2}.60.0/28 counter log prefix "NF_SPOOF_DENY " drop

    # Stateful connection tracking
    ct state established,related accept comment "established-return"

    # Management admin SSH+HTTPS+DNS to internal zones (P-NET-06/14/22/30)
    iifname "eth6" oifname {{ "eth2", "eth3", "eth4", "eth5", "eth7", "eth8" }} tcp dport {{ 22, 443 }} accept comment "management-admin"
    iifname "eth6" oifname {{ "eth2", "eth3", "eth4", "eth5", "eth7", "eth8" }} udp dport 53 accept comment "management-dns"

    # Business paths to Servers (eth5)
    iifname "eth3" oifname "eth5" tcp dport {{ 443, 445, 5432 }} accept comment "finance-to-payroll"
    iifname "eth4" oifname "eth5" tcp dport {{ 22, 443, 8443 }} accept comment "engineering-to-code"
    iifname "eth2" oifname "eth5" tcp dport 443 accept comment "users-to-servers"

    # Finance to Guest zone (P-NET-03/11/19/27)
    iifname "eth3" oifname "eth7" tcp dport {{ 22, 443 }} accept comment "finance-to-guest"
    iifname "eth3" oifname "eth7" udp dport 53 accept comment "finance-to-guest-dns"

    # Servers to DMZ (P-NET-05/13/21/29)
    iifname "eth5" oifname "eth8" tcp dport {{ 22, 443 }} accept comment "servers-to-dmz"
    iifname "eth5" oifname "eth8" udp dport 53 accept comment "servers-to-dmz-dns"

    # Engineering self-zone forwarding (P-NET-04/12/20/28)
    iifname "eth4" oifname "eth4" tcp dport {{ 22, 443 }} accept comment "engineering-self"
    iifname "eth4" oifname "eth4" udp dport 53 accept comment "engineering-self-dns"

    # Centralized DNS (53) and NTP (123) on Servers
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8" }} oifname "eth5" udp dport {{ 53, 123 }} accept comment "central-dns-ntp"
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8" }} oifname "eth5" tcp dport 53 accept comment "central-dns-tcp"

    # Guest (eth7) -> DMZ (eth8) Public Web
    iifname "eth7" oifname "eth8" tcp dport {{ 80, 443 }} accept comment "guest-to-dmz-web"

    # Internet (eth1) -> DMZ (eth8) Public Web HTTPS only
    iifname "eth1" oifname "eth8" tcp dport 443 accept comment "internet-to-dmz-https"

    # DMZ (eth8) -> Servers (eth5) App-to-DB plus admin (P-NET-07/15/23)
    iifname "eth8" oifname "eth5" tcp dport {{ 22, 443, 5432 }} accept comment "dmz-to-approved-server"
    iifname "eth8" oifname "eth5" udp dport 53 accept comment "dmz-to-server-dns"

    # Edge Outbound HTTPS only (no HTTP per NET-14)
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth7" }} oifname "eth1" tcp dport 443 accept comment "outbound-https"
    iifname {{ "eth2", "eth3", "eth4", "eth5", "eth7" }} oifname "eth1" udp dport 53 accept comment "outbound-dns"

    # Default deny & log
    counter log prefix "NF_SEGMENT_DENY " drop
  }}
}}
"""
    with open(os.path.join(root_dir, "configs", "gateway", "nftables.conf"), "w") as f:
        f.write(nft_content)

    print(f"Successfully generated topology and configs for variant octet {octet2}")

if __name__ == "__main__":
    main()
