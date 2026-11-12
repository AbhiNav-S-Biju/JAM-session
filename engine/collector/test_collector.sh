#!/usr/bin/env bash
# Start the collector, run one agent mode, wait for it to finish, and summarise events.jsonl.
# Usage: engine/collector/test_collector.sh [benign|attack|benign_unusual]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-attack}"
RUN="run-$MODE-$(date +%H%M%S)"
cd "$ROOT"

LOG="$(mktemp)"
python3 engine/collector/collector.py --run-id "$RUN" --until-exit >"$LOG" 2>&1 &
CPID=$!
for _ in $(seq 1 300); do grep -q "collector: ready" "$LOG" && break; sleep 0.2; done   # up to 60 s (first run builds an image)
grep -q "collector: ready" "$LOG" || { echo "collector did not become ready"; cat "$LOG"; kill $CPID; exit 1; }
engine/sandbox/run_agent.sh "$MODE" >/dev/null
timeout 90 tail --pid="$CPID" -f /dev/null || { echo "collector did not stop, killing"; kill $CPID; }
cat "$LOG"

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
