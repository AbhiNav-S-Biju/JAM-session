#!/usr/bin/env bash
# Start the CageWatch sandbox container with hardening flags.
# Usage: engine/sandbox/run_agent.sh [benign|attack|benign_unusual]
# Run inside WSL2 Ubuntu. The container is started detached and kept (no --rm)
# so the monitor can pause it and preserve evidence. Remove with: docker rm -f cagewatch-agent
set -euo pipefail

MODE="${1:-benign}"
case "$MODE" in benign|attack|benign_unusual) ;; *) echo "mode must be benign|attack|benign_unusual" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$(cd "$HERE/.." && pwd)"
IMAGE="cagewatch-sandbox:latest"
NET="cagewatch-net"
NAME="cagewatch-agent"

# Dedicated bridge network (monitor watches this bridge; disconnect target for containment).
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

# Build image if missing.
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" "$HERE"

# Remove any previous run.
docker rm -f "$NAME" >/dev/null 2>&1 || true

# Hardening: non-root, no capabilities, read-only rootfs, no privilege escalation,
# resource limits, writable tmpfs only at /work (noexec), NO docker socket, NOT privileged.
docker run -d \
  --name "$NAME" \
  --network "$NET" \
  --user 1000:1000 \
  --cap-drop=ALL \
  --read-only \
  --security-opt no-new-privileges \
  --pids-limit 100 \
  --memory 256m \
  --cpus 0.5 \
  --tmpfs /work:rw,noexec,nosuid,nodev,size=16m,uid=1000,gid=1000 \
  --mount type=bind,src="$HERE/data/authorized",dst=/data/authorized,readonly \
  --mount type=bind,src="$HERE/data/untrusted",dst=/data/untrusted,readonly \
  --mount type=bind,src="$HERE/data/secrets",dst=/secrets,readonly \
  --mount type=bind,src="$ENGINE/agent",dst=/agent,readonly \
  --label cagewatch=1 \
  --label cagewatch.mode="$MODE" \
  "$IMAGE" --mode "$MODE"

echo "started $NAME (mode=$MODE) on network $NET"
