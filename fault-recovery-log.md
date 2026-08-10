# Fault Recovery Log

Evidence marker: `UBI-A7-6C1390578232`
Variant: V1 | Second octet: 51

## Methodology

Each fault is injected on a clean baseline, detected via a failing automated test,
diagnosed from packet captures / firewall counters / routing tables, corrected with
the smallest possible change, and verified by a passing retest. The git history
preserves each stage.

---

## Fault 1 — Established Return Handling Removed for Finance Path

| Field | Value |
|---|---|
| **Fault ID** | F-001 |
| **Injected change** | `ct state established,related accept` rule modified to exclude traffic involving eth3 (finance interface). Return SYN-ACK from servers back to finance is dropped. |
| **Failing test** | `test_fault1_established_return_failure` — Finance TCP/443 to Servers times out |
| **Diagnosis** | PCAP `fault1_established_failure.pcap` shows SYN from finance (10.51.20.10) to servers (10.51.50.10:443), server responds with SYN-ACK, but SYN-ACK is dropped at gateway because `ct state established,related` no longer covers eth3 traffic. nftables counter shows `NF_SEGMENT_DENY` increments on the return path. |
| **Root cause** | Fault replaced `ct state established,related accept` with `iifname != "eth3" oifname != "eth3" ct state established,related accept`, preventing any stateful return traffic for the finance zone. |
| **Fix** | Restore original `ct state established,related accept comment "established-return"` rule (no interface filter). |
| **Green retest** | `test_fault1_established_return_failure` passes — finance TCP/443 to servers succeeds, return traffic flows through `ct state established`. |
| **Commit** | See git log for fault1-inject and fault1-fix commits |

---

## Fault 2 — Management Ingress Broadened to Users Zone

| Field | Value |
|---|---|
| **Fault ID** | F-002 |
| **Injected change** | Management admin SSH rule changed from `iifname "eth6"` to `iifname { "eth2", "eth6" }`, allowing Users zone (eth2) to SSH into all internal zones. |
| **Failing test** | `test_fault2_broadened_management_ingress` — Users SSH to Servers unexpectedly succeeds |
| **Diagnosis** | Users container (10.51.40.10) successfully connects to Servers (10.51.50.10:22) under fault. nftables ruleset dump shows `broadened-management-admin` comment confirming the widened ingress policy. No `NF_SEGMENT_DENY` counter increment for this path. |
| **Root cause** | Adding `eth2` to the management admin rule grants Users zone administrative SSH access across all internal zones, violating least-privilege segmentation. |
| **Fix** | Restore management SSH rule to `iifname "eth6"` only — management zone is the sole authorized admin ingress point. |
| **Green retest** | `test_fault2_broadened_management_ingress` passes — Users SSH to Servers is correctly denied. |
| **Commit** | See git log for fault2-inject and fault2-fix commits |

---

## Fault 3 — DMZ Sensor Mirror Missing

| Field | Value |
|---|---|
| **Fault ID** | F-003 |
| **Injected change** | `tc filter del dev eth8 ingress` removes the traffic mirroring rule on the DMZ-facing interface, preventing the sensor from seeing DMZ traffic. |
| **Failing test** | `test_fault3_dmz_sensor_mirror_missing` — `tc filter show dev eth8 ingress` output no longer contains `mirred` |
| **Diagnosis** | Running `tc filter show dev eth8 ingress` on gateway returns empty output. Suricata on the sensor node stops seeing any DMZ-originated flows. Traffic between DMZ and Servers still passes (forwarding rules unaffected), but observability is lost for that interface. |
| **Root cause** | The `tc filter` ingress mirroring rule for eth8 was deleted. The bootstrap.sh sets these mirrors at boot, but they are runtime state — deleting them leaves a gap until the next container restart or re-execution of bootstrap.sh. |
| **Fix** | Re-execute gateway bootstrap.sh which re-applies `tc filter add dev eth8 ingress matchall action mirred egress mirror dev eth9`. |
| **Green retest** | `test_fault3_dmz_sensor_mirror_missing` passes — `tc filter show dev eth8 ingress` shows `mirred` rule active. |
| **Commit** | See git log for fault3-inject and fault3-fix commits |

---

## Fault 4 (D-Set) — Asymmetric Return Path for Finance Zone

| Field | Value |
|---|---|
| **Fault ID** | F-004 / D1 |
| **Injected change** | Added static route on servers and core containers to send finance return traffic (10.51.20.0/26) via core (10.51.254.1) instead of directly via gateway. Also added a matching route on gateway to forward finance-destined traffic to core, creating an asymmetric path. |
| **Failing test** | `test_fault4_asymmetric_return_failure` — Finance TCP/443 to Servers times out |
| **Diagnosis** | PCAP `fault4_asymmetric_return.pcap` shows outbound SYN from finance traverses gateway eth3→eth5 (normal path), but return SYN-ACK from servers goes via core (10.51.254.1) → gateway eth1 → finance. Because the return path enters gateway on eth1 instead of eth5, the conntrack state is not matched (different interface tuple), and the stateful `ct state established,related` rule fails to match the return packet. The packet is then evaluated against forwarding rules and hits the default deny. |
| **Root cause** | Asymmetric routing causes the TCP return path to differ from the forward path. The gateway's stateful firewall cannot correlate the return packet with the original connection because it arrives on a different interface than expected. |
| **Fix** | Remove the injected static routes: restore servers default route (`default via 10.51.50.1`), delete the spurious finance route on servers and core, and restore core's aggregate route (`10.51.0.0/16 via 10.51.254.2`). |
| **Green retest** | `test_fault4_asymmetric_return_failure` passes — Finance TCP/443 to Servers succeeds with symmetric path through gateway. |
| **Commit** | See git log for fault4-inject and fault4-fix commits |

---

## Summary

| Fault | Category | Detection Method | MTTR |
|---|---|---|---|
| F-001 | Stateful tracking bypass | Automated test + PCAP analysis | Immediate (config restore) |
| F-002 | Over-permissive ACL | Automated test + nftables dump | Immediate (config restore) |
| F-003 | Observability gap | Automated test + tc filter check | Immediate (bootstrap re-run) |
| F-004 | Asymmetric routing | Automated test + PCAP + route analysis | Immediate (route correction) |

All faults were detected by automated assertions, diagnosed from infrastructure evidence,
and resolved through version-controlled configuration changes.
