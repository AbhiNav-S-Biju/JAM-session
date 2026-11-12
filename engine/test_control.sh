#!/usr/bin/env bash
# End-to-end test of the dashboard control path (control.json -> engine -> engine_status.json).
# Usage: bash engine/test_control.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
S=shared/runtime/engine_status.json

send() { echo "{\"cmd\":\"$1\",\"ts\":\"$(date +%s%N)\"}" > shared/runtime/control.json; }
st()   { python3 -c "import json;s=json.load(open('$S'));print('   STATUS:',s['state'],'|',s.get('run_id'),'|',s.get('incident_id'),'|',s['message'])"; }
wait_state() { # wait until state is one of the given values (max 60 s)
  for _ in $(seq 1 300); do
    s=$(python3 -c "import json;print(json.load(open('$S'))['state'])" 2>/dev/null)
    for want in "$@"; do [ "$s" = "$want" ] && return 0; done
    sleep 0.2
  done; echo "   TIMEOUT waiting for $*"; }

python3 engine/run.py reset >/dev/null
python3 engine/run.py serve-control > /tmp/cagewatch-ctl.log 2>&1 &
SERVER=$!
sleep 1.5

echo "> run_attack (expect auto containment)"
T0=$(date +%s.%N); send run_attack; wait_state running; wait_state contained finished error; st
echo "   took $(python3 -c "print(round($(date +%s.%N)-$T0,1))") s"

echo "> reset, run_benign_unusual, emergency_halt mid-run (expect manual containment)"
send reset; sleep 1; send run_benign_unusual; wait_state running
for _ in $(seq 1 100); do docker ps -q -f name=cagewatch-agent | grep -q . && break; sleep 0.2; done; sleep 2
send emergency_halt; wait_state contained error; sleep 4; st
docker inspect -f '   container: {{.State.Status}} networks=[{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}]' cagewatch-agent
ID=$(python3 -c "import json;print(json.load(open('shared/runtime/incidents.json'))[-1]['incident_id'])")
python3 -c "import json;i=json.load(open('shared/runtime/incidents.json'))[-1];print('   incident:',i['incident_id'],i['status'],'reason='+i.get('containment_reason',''),i['chain'],'ttc',i['time_to_contain_ms'],'len',i['evidence'].get('chain_length'))"
python3 engine/evidence/vault.py verify "$ID" | cut -c1-50

echo "> unknown command (expect rejected)"
echo '{"cmd":"rm -rf /","ts":"bogus-1"}' > shared/runtime/control.json; sleep 1; st

echo "> reset (expect idle, no containers)"
send reset; sleep 1.5; st
docker ps -a --format '   {{.Names}}' | grep cagewatch || echo "   no cagewatch containers"

kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null
echo "--- engine log"; cat /tmp/cagewatch-ctl.log
