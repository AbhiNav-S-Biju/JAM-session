#!/usr/bin/env bash
# Start the collector, run one agent mode, wait for it to finish, and summarise events.jsonl.
# Usage: engine/collector/test_collector.sh [benign|attack|benign_unusual]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-attack}"
RUN="run-$MODE-$(date +%H%M%S)"
cd "$ROOT"

python3 engine/collector/collector.py --run-id "$RUN" --until-exit &
CPID=$!
sleep 4   # let inotify and the network monitor come up
engine/sandbox/run_agent.sh "$MODE" >/dev/null
wait "$CPID"

python3 - "$ROOT/shared/runtime/events.jsonl" <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    d = e["detail"]
    what = d.get("action") or d.get("path") or (f'{d.get("dst_ip")}:{d.get("dst_port")}' if "dst_ip" in d else "") or ""
    if e["type"] == "step":
        what += f'  {d.get("target")}  tainted={d.get("tainted")}'
    if e["type"] == "step_result" and not d["ok"]:
        what = "FAILED " + d["error"]
    if e["type"] == "step_result" and d["ok"]:
        continue
    print(f'{e["id"]} {e["ts"][11:23]} {e["source"]:<10} {e["type"]:<12} {str(e["step_id"]):<8} {what}')
EOF
ls -la "$ROOT/shared/runtime/capture.pcap" 2>/dev/null
docker rm -f cagewatch-agent >/dev/null 2>&1 || true
