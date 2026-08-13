# Advanced Project 3 Integrity Attestation

Intern code: `UBI-2026-0576`
Variant: `V1/UBI-2026-0576`
Evidence marker: `UBI-A7-6C1390578232`

I attest that I performed the submitted work on the assigned authorized
artifacts or lab. I have declared material assistance below and can reproduce
the work during artifact check. I did not alter raw evidence, fabricate tool
output, rewrite commit history, share restricted artifacts, or cross scope.

Assistance and tools used:
AI assistant (Claude, Anthropic) used during the build/debug phase for:
(1) reviewing `configs/gateway/nftables.conf` against the output of
`scripts/build_configs.py` and identifying that the committed file reflected
a previously fault-injected state plus several missing zone-pair rules,
corrected by rerunning the generator; (2) reviewing and rewriting two test
assertions — `tests/test_stateful.py::test_spoofed_source_ip_denied` and
`tests/test_telemetry.py::test_sensor_mirror_receives_traffic` — that passed
regardless of the underlying security behavior, replaced with checks against
nftables packet-counter deltas and new Suricata `eve.json` events tied to the
triggered connection; (3) diagnosing a sensor-container crash loop from
`docker logs`/`docker ps` output (missing capabilities); an initial proposed
fix (`cap-add` field) was incompatible with the installed containerlab
version and was not used in the final build. All resulting changes were
verified by rerunning `make clean && make lab && make test` to a clean pass
before acceptance. Assistance is not authorship; I can explain and reproduce
each of the above at defense.

Signed name: `Annet Felly Atemba`
UTC date/time: `13-08-2026 23:50 UTC`
