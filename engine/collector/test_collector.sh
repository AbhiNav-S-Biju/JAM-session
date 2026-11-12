#!/usr/bin/env bash
# Start the collector, run one agent mode, wait for it to finish, and summarise events.jsonl.
# Usage: engine/collector/test_collector.sh [benign|attack|benign_unusual]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-attack}"
RUN="run-$MODE-$(date +%H%M%S)"
cd "$ROOT"

LOG="$(mktemp)"
python3 engine/collector/collector.py --run-id "$RUN" --until-exit --rules engine.detect.rules:evaluate ${NO_RESPOND:+} $([ -z "${NO_RESPOND:-}" ] && echo --respond) >"$LOG" 2>&1 &
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
    print(f'{e["verdict"][:4]:<4} {e["id"]} {e["ts"][11:23]} {e["source"]:<10} {e["type"]:<12} {str(e["step_id"]):<8} {what}')
EOF
ls -la "$ROOT/shared/runtime/capture.pcap" 2>/dev/null
python3 - "$ROOT/shared/runtime/incidents.json" "$RUN" <<'EOF'
import json, sys
try: items = [i for i in json.load(open(sys.argv[1])) if i["run_id"] == sys.argv[2]]
except (OSError, ValueError): items = []
if not items: print("INCIDENT: none for", sys.argv[2])
for i in items:
    print(f'INCIDENT {i["incident_id"]} severity={i["severity"]} risk={i["risk_score"]} factors={i["score_factors"]}')
    print("  chain:", " -> ".join(i["chain"]), f'| time_to_detect_ms={i["time_to_detect_ms"]}')
    for r in i["rules_triggered"]: print(f'  {r["rule_id"]} {r["name"]}: events={r["event_ids"]} steps={r["step_ids"]}')
    print(f'  status={i["status"]} time_to_contain_ms={i["time_to_contain_ms"]} evidence={i["evidence"]}')
    for act in i["actions_taken"]: print(f'  ACTION {act["action"]:<20} ok={act["ok"]} took={act["took_ms"]}ms {act["error"] or ""}')
EOF
echo "CONTAINER: $(docker inspect -f '{{.State.Status}} paused={{.State.Paused}} networks=[{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}]' cagewatch-agent 2>&1)"
ls "$ROOT/shared/runtime/evidence/" 2>/dev/null | tail -1 | sed 's/^/EVIDENCE DIR: /'
grep -h '"type": "\(pause\|disconnect\)"' "$ROOT/shared/runtime/events.jsonl" | cut -c1-140
INC="$(ls -t "$ROOT/shared/runtime/evidence/" 2>/dev/null | head -1)"
if [ -n "$INC" ] && [ "$MODE" = attack ]; then
  echo "VAULT verify:"; python3 engine/evidence/vault.py verify "$INC"
  echo "VAULT tamper-test:"; python3 engine/evidence/vault.py tamper-test "$INC"
  tail -2 "$ROOT/shared/runtime/anchors.log"
fi
docker rm -f cagewatch-agent >/dev/null 2>&1 || true
