# SOC-A3: Network Detection Range as Code

**Evidence Marker:** `UBI-A7-6C1390578232`
**Assignment:** V1 / UBI-2026-0576
**Track:** SOC Analysis — Advanced Stage, Project 3 of 5

## Overview

A seven-zone routed enterprise network detection range built entirely as code
using containerlab, FRRouting, nftables, and Suricata. The range enforces
stateful least-privilege segmentation, generates business and attack traffic,
and verifies both allowed and denied paths through automated assertions backed
by packet captures and firewall telemetry.

## Architecture

```
                    ┌─────────┐
                    │  CORE   │ FRRouting 10.2.1
                    │ .254.1  │ eth1
                    └────┬────┘
                         │ 10.51.254.0/30
                    ┌────┴────┐
                    │ GATEWAY │ nftables · tc mirror
                    │ .254.2  │ sysctl ip_forward=1
                    └─┬─┬─┬─┬┘
          ┌───────────┘ │ │ └───────────┐
     ┌────┴───┐   ┌─────┴─┴────┐   ┌───┴────┐
     │ USERS  │   │  FINANCE   │   │  ENG   │
     │.40.0/24│   │ .20.0/26   │   │.30.0/25│
     │  eth2  │   │   eth3     │   │  eth4  │
     └────────┘   └────────────┘   └────────┘
     ┌────────┐   ┌────────────┐   ┌────────┐
     │SERVERS │   │ MANAGEMENT │   │ GUEST  │
     │.50.0/27│   │ .10.0/27   │   │.70.0/24│
     │  eth5  │   │   eth6     │   │  eth7  │
     └────────┘   └────────────┘   └────────┘
     ┌────────┐   ┌────────────┐
     │  DMZ   │   │  SENSOR    │ Suricata 7.0.8
     │.60.0/28│   │  (passive) │ tc mirror → eth9
     │  eth8  │   │   eth9     │
     └────────┘   └────────────┘
```

All addresses use the `10.51.x.x` address plan from `configs/variant.json`.

## Zone Policy Summary

| Source | Destination | Allowed Services | Policy Basis |
|---|---|---|---|
| Management | All internal | SSH (22), HTTPS (443), DNS (53) | Administrative access |
| Finance | Servers | HTTPS (443), SMB (445), PostgreSQL (5432) | Business: payroll |
| Finance | Guest | SSH (22), HTTPS (443), DNS (53) | Cross-zone access |
| Engineering | Servers | SSH (22), HTTPS (443), CI/CD (8443) | Business: code repos |
| Engineering | Engineering | SSH (22), HTTPS (443), DNS (53) | Intra-zone |
| Users | Servers | HTTPS (443) only | Business: web apps |
| Guest | DMZ | HTTP (80), HTTPS (443) | Public web access |
| Internet | DMZ | HTTPS (443) only | Inbound web |
| DMZ | Servers | SSH (22), HTTPS (443), PostgreSQL (5432), DNS (53) | App-to-DB |
| Servers | DMZ | SSH (22), HTTPS (443), DNS (53) | Server admin |
| All zones | Servers | DNS (53/udp+tcp), NTP (123/udp) | Centralized services |
| Internal | Internet | HTTPS (443), DNS (53) | Outbound (no HTTP) |
| **All other** | **All other** | **DENY + LOG** | Default deny |

Anti-spoofing rules drop and log packets with source IPs that don't match
the expected subnet for each ingress interface.

## Prerequisites

- Linux host with Docker ≥ 20.x
- containerlab
- FRRouting container image: `quay.io/frrouting/frr:10.2.1`
- Suricata container image: `jasonish/suricata:7.0.8`
- Python 3.10+ with pytest
- nftables (on host for verification)

## Quick Start

```bash
# Build container images and deploy the range
make clean && make lab

# Run the full test suite (≥30 assertions)
make test

# Collect reference state evidence
make collect
```

## Project Structure

```
soc-stage7/
├── topology.clab.yml           # Containerlab topology (generated)
├── Makefile                    # Build/test/clean automation
├── configs/
│   ├── variant.json            # Addressing plan (change for variant)
│   ├── core/frr.conf           # FRRouting config (generated)
│   └── gateway/
│       ├── Dockerfile          # Gateway container image
│       ├── bootstrap.sh        # IP addressing, tc mirror, nft load
│       └── nftables.conf       # Stateful segmentation policy
├── services/
│   └── host/
│       ├── Dockerfile          # Host container image
│       └── server_daemons.py   # TCP/UDP service listeners
├── detections/
│   ├── local.rules             # Suricata detection rules
│   └── README.md               # Detection strategy
├── telemetry/
│   └── suricata.yaml           # Suricata sensor configuration
├── tests/
│   ├── conftest.py             # Shared fixtures and helpers
│   ├── test_matrix.py          # 30 parametrized public fixtures
│   ├── test_stateful.py        # Stateful/spoofing/management tests
│   ├── test_telemetry.py       # Sensor mirror and isolation tests
│   └── test_faults.py          # Fault inject/detect/restore tests
├── scripts/
│   ├── build_configs.py        # Config generator from variant.json
│   ├── inject_fault.py         # Fault injection and restore
│   ├── capture_pcaps.py        # PCAP evidence capture
│   └── collect-state.sh        # Reference state export
├── pcaps/                      # Captured packet evidence
├── evidence/
│   ├── brief/public-fixtures.json
│   └── suricata-logs/          # Suricata eve.json logs
├── test-results.xml            # JUnit XML test report
├── fault-recovery-log.md       # Fault diagnosis and fix record
├── evidence-index.csv          # Claim-to-artifact locator
├── assessment-manifest.json    # Build/test metadata
├── integrity-attestation.md    # Candidate attestation
├── decision-log.md             # Engineering decision trail
├── defense-readiness.md        # Pre-defense checklist
├── continuity-record.md        # Portfolio continuity
├── manifest.sha256             # File integrity hashes
└── README.md                   # This file
```

## Variant Configuration

All addressing is driven by `configs/variant.json`. To apply a different
addressing variant, change `second_octet` and subnet definitions in that
file, then run `make clean && make lab && make test`. No topology or test
logic changes are required.

## Fault Recovery

Four fault conditions are documented in `fault-recovery-log.md`:

1. **F-001:** Established return handling removed for finance path
2. **F-002:** Management ingress broadened to Users zone
3. **F-003:** DMZ sensor mirror rule deleted
4. **F-004:** Asymmetric return path for finance zone (D-set)

Each fault has a corresponding inject/detect/fix/retest cycle preserved
in git history and verified by `tests/test_faults.py`.

## Test Coverage

The test suite validates ≥38 assertions across four categories:

- **Matrix tests** (30): Parametrized from `public-fixtures.json`
- **Stateful tests** (4): Established return, spoofing, management SSH
- **Telemetry tests** (2): Sensor mirror reception, passive isolation
- **Fault tests** (4): Inject/detect/restore for all fault conditions

Run `make test` to produce `test-results.xml` (JUnit format).
