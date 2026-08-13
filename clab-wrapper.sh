#!/usr/bin/env bash
set -euo pipefail
WORK_DIR="/home/at3mba/soc-stage7"
docker run --rm --privileged --net=host --pid=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$WORK_DIR":"$WORK_DIR" \
  -v /home/at3mba/.local/bin/containerlab:/usr/local/bin/containerlab \
  -w "$WORK_DIR" \
  alpine:3.20 containerlab "$@"
