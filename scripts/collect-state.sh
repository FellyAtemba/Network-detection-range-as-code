#!/usr/bin/env bash
set -euo pipefail

out="${1:-evidence/reference-state}"
mkdir -p "$out"
date -u +%FT%TZ > "$out/captured-at.txt"

# Use Docker wrapper for containerlab since it requires privileged access
CLAB_CMD="docker run --rm --privileged --net=host --pid=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /home/at3mba/soc-stage7:/home/at3mba/soc-stage7 \
  -v /home/at3mba/.local/bin/containerlab:/usr/local/bin/containerlab \
  -w /home/at3mba/soc-stage7 \
  alpine:3.20 /usr/local/bin/containerlab"

$CLAB_CMD inspect --name netforge-a3 --format json > "$out/containerlab-inspect.json" 2>/dev/null || echo '{"error": "inspect not available"}' > "$out/containerlab-inspect.json"
docker exec clab-netforge-a3-core vtysh -c 'show ip route json' > "$out/routes.json"
docker exec clab-netforge-a3-gateway nft -j list ruleset > "$out/nftables.json"
docker exec clab-netforge-a3-gateway ip -j address > "$out/gateway-addresses.json"
docker logs clab-netforge-a3-sensor > "$out/sensor-container.log" 2>&1
find "$out" -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > "$out/manifest.sha256"
