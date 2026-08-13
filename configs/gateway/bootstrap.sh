#!/bin/sh
set -eu
# Wait for containerlab to create ALL interfaces (eth9 is the last link)
echo "Waiting for interfaces..."
while ! ip link show eth9 >/dev/null 2>&1; do sleep 0.5; done
sleep 1
echo "Interfaces ready, configuring..."
ip address add 10.51.254.2/30 dev eth1 || true
ip address add 10.51.40.1/24 dev eth2 || true
ip address add 10.51.20.1/26 dev eth3 || true
ip address add 10.51.30.1/25 dev eth4 || true
ip address add 10.51.50.1/27 dev eth5 || true
ip address add 10.51.10.1/27 dev eth6 || true
ip address add 10.51.70.1/24 dev eth7 || true
ip address add 10.51.60.1/28 dev eth8 || true
ip link set eth9 promisc on || true
for interface in eth1 eth2 eth3 eth4 eth5 eth6 eth7 eth8; do
  tc qdisc add dev "$interface" clsact || true
  tc filter add dev "$interface" ingress matchall action mirred egress mirror dev eth9 || true
done
sysctl -w net.ipv4.ip_forward=1
nft -f /etc/nftables.conf
tail -f /dev/null
