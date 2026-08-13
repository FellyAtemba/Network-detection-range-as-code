# Continuity Record — Stage 7 (Network Detection Range as Code)

## 1. Previous-stage commit and component reused

Previous stage: Stage 6, "Deception Sensor and Analysis Pipeline"
(`github.com/FellyAtemba/Ubuntu-Bridge-Initiative-SOC_STAGE-6`).

**Commit:** `fc6c0a983eaaf52ecff3837d90a299a958dfbf08`
**Component reused:** The nftables rule-writing pattern from Stage 6's
network boundary enforcement (Stage 6 built "an nftables-defined network
boundary and an isolation-test harness" around the honeypot).

## 2. Interface consumed and backward-compatible extension

What's consumed from that commit is a pattern, not a schema or a running
service: Stage 6's approach to writing network-boundary rules in nftables
carries into this stage's `configs/gateway/nftables.conf` — the same
rule-writing approach applied to a larger, multi-zone topology rather than
Stage 6's single honeypot boundary.

Separately, `evidence-index.csv`'s claim-to-raw-locator contract (raw
filename, exact locator, what it proves, what it doesn't, confidence, one
alternative considered) is a required deliverable in all three stages —
not something reused from Stage 6 specifically, but a constant format this
stage extends with network-specific locator types (pcap frame numbers,
nftables counter names, `eve.json` offsets) alongside the log-line/session
locators used before.

## 3. Evidence that prior raw-to-result provenance remains intact

This is pattern reuse (a rule-writing approach carried into new code), not
artifact reuse — no Stage 6 file is imported or copied into this repo, so
there's no shared raw-evidence chain between the two stages' outputs to
preserve. This stage's own provenance chain (trigger → pcap/counter/log →
assertion → `evidence-index.csv` row) stands on its own and follows the
same standard Stage 5/6 used.

## 4. Migration record for incompatible changes

Stage 6's nftables pattern enforced one boundary (honeypot vs. everything
else). Scaling that pattern to this stage's 7-zone segmentation matrix
required work a single-boundary model didn't need: per-zone anti-spoof
rules, inter-zone business-path rules, and centralized DNS/NTP exceptions.

A related gap surfaced and was corrected during this stage's own build:
two tests (`test_spoofed_source_ip_denied`, `test_sensor_mirror_receives_traffic`)
initially asserted only connection success/failure rather than
firewall-counter or sensor-log evidence. Both were rewritten to check
nftables packet-counter deltas and new `eve.json` events before submission
— see `integrity-attestation.md` for the full change.

## 5. Handoff to Stage 8 (Detection Engineering Under Adversary Pressure)

Forward to the next stage:
- The `evidence-index.csv` convention with its network-locator extension.
- The variant-driven address plan (`configs/variant.json` →
  `scripts/build_configs.py`, currently `second_octet=51`) and its
  regeneration approach.
- The verified 30-path allow/deny matrix.
- The four fault signatures — F-001 (finance established-return removed),
  F-002 (management ingress broadened to Users), F-003 (DMZ sensor mirror
  rule deleted), F-004 (finance asymmetric return, the private D-set
  condition) — as known-bad patterns for Stage 8's detection content to
  target.
