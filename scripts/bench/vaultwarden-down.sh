#!/usr/bin/env bash
# Stop the benchmark Vaultwarden (its storage is volatile and goes with it).
set -euo pipefail

if [ -n "$(docker ps -q --filter "name=^ow-bench-vw$")" ]; then
  docker stop ow-bench-vw >/dev/null
  docker wait ow-bench-vw >/dev/null 2>&1 || true
  echo "stopped ow-bench-vw"
else
  echo "ow-bench-vw is not running"
fi
