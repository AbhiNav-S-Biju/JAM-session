#!/usr/bin/env bash
# Run each agent mode in the sandbox and print its steps. Usage: engine/agent/test_modes.sh [mode ...]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODES=("$@"); [ ${#MODES[@]} -eq 0 ] && MODES=(benign benign_unusual attack)

for m in "${MODES[@]}"; do
  echo "=== $m ==="
  "$ROOT/engine/sandbox/run_agent.sh" "$m" >/dev/null
  timeout 60 docker wait cagewatch-agent >/dev/null
  docker logs cagewatch-agent 2>&1 | python3 -c '
import sys, json
for line in sys.stdin:
    try: d = json.loads(line)
    except ValueError: print("  (non-json)", line.strip()); continue
    if d["event"] == "step":
        print("  %-8s %-18s %-28s tainted=%s" % (d["step_id"], d["action"], d["target"], d["tainted"]))
    elif d["event"] == "result" and not d["ok"]:
        print("      -> blocked/failed:", d["error"])
'
  echo "  exit code: $(docker inspect -f '{{.State.ExitCode}}' cagewatch-agent)"
done
docker rm -f cagewatch-agent >/dev/null 2>&1 || true
