# SOC-A3 Detection Strategy

**Evidence Marker:** `UBI-A7-6C1390578232`

## Sensor Placement

The Suricata sensor operates as a **passive observer** connected to the
gateway's `eth9` interface. All gateway interfaces (`eth1`–`eth8`) mirror
ingress traffic to `eth9` via Linux `tc` (traffic control) ingress filters
with `mirred egress mirror` actions. This placement provides:

- **Full east–west visibility**: Every inter-zone packet traversing the
  gateway is copied to the sensor.
- **No inline risk**: Sensor failure does not affect forwarding or policy
  enforcement.
- **No routable address**: The sensor interface receives mirrored copies
  only and cannot initiate traffic into protected zones.

## Rule Categories

The detection rules in `local.rules` are organized into six categories:

### 1. Segmentation Violation Rules (SID 1000001–1000005)
Detect traffic crossing zone boundaries that the nftables policy should
deny. Any alert here indicates either a misconfigured firewall rule or
an active bypass attempt. Covers Guest→Finance, Guest→Management,
Users→Management, DMZ→Management, and Servers→Users paths.

### 2. SSH Brute-Force Detection (SID 1000010)
Threshold-based rule detecting 5+ SSH SYN packets within 60 seconds
from a single source. Indicates credential-stuffing or automated
brute-force attacks against any SSH listener.

### 3. Unauthorized SSH Access (SID 1000011)
Only the Management zone (10.51.10.0/27) is authorized to initiate SSH.
Any SSH connection from another zone triggers a policy violation alert,
even if the nftables rule permits the traffic for engineering-specific paths.

### 4. DNS Exfiltration Indicators (SID 1000020)
Flags DNS queries with query names exceeding 50 bytes — a classic
indicator of DNS-tunnel-based data exfiltration tools (iodine, dnscat2).

### 5. Outbound Plaintext HTTP Enforcement (SID 1000030)
Enterprise policy mandates HTTPS-only for outbound web traffic. Any
internal host attempting TCP/80 to an external destination violates
this policy and triggers an alert.

### 6. Source IP Spoofing Detection (SID 1000040)
Detects traffic from the guest zone with source IPs outside the
expected 10.51.70.0/24 subnet, indicating either a misconfigured host
or an active spoofing attack.

## Relationship to nftables

The Suricata rules complement nftables policy enforcement:

| Layer | Tool | Function |
|---|---|---|
| Prevention | nftables | Drops and logs denied traffic with `NF_SEGMENT_DENY` prefix |
| Detection | Suricata | Alerts on traffic patterns indicating policy violations or attacks |
| Evidence | Both | nftables counters + Suricata EVE JSON provide independent evidence |

Suricata observes mirrored copies of traffic before nftables acts on it,
so it can alert on packets that will be denied. This provides defense-in-depth:
even if a firewall rule is misconfigured, Suricata generates an alert.
