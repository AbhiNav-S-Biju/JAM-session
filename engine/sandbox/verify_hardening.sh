#!/usr/bin/env bash
# Verify the running cagewatch-agent container has the required hardening. Exit 1 on any failure.
set -uo pipefail
NAME="${1:-cagewatch-agent}"
fail=0
check() { # description, jq-free docker inspect format, expected substring
  local desc="$1" fmt="$2" want="$3" got
  got="$(docker inspect -f "$fmt" "$NAME" 2>/dev/null || echo ERR)"
  if [[ "$got" == *"$want"* ]]; then echo "PASS  $desc ($got)"; else echo "FAIL  $desc (got: $got, want: $want)"; fail=1; fi
}
docker inspect "$NAME" >/dev/null 2>&1 || { echo "container $NAME not found"; exit 1; }

check "non-root user"        '{{.Config.User}}'                      '1000'
check "cap-drop ALL"         '{{.HostConfig.CapDrop}}'               'ALL'
check "read-only rootfs"     '{{.HostConfig.ReadonlyRootfs}}'        'true'
check "no-new-privileges"    '{{.HostConfig.SecurityOpt}}'           'no-new-privileges'
check "not privileged"       '{{.HostConfig.Privileged}}'            'false'
check "pids limit"           '{{.HostConfig.PidsLimit}}'             '100'
check "memory limit 256m"    '{{.HostConfig.Memory}}'                '268435456'
check "dedicated network"    '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 'cagewatch-net'

if docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$NAME" | grep -q docker.sock; then
  echo "FAIL  docker socket is mounted"; fail=1
else echo "PASS  no docker socket mounted"; fi

# Bind mounts must all be read-only.
rw="$(docker inspect -f '{{range .Mounts}}{{if .RW}}{{.Destination}} {{end}}{{end}}' "$NAME")"
if [[ -z "${rw// }" ]]; then echo "PASS  all bind mounts read-only"; else echo "FAIL  writable mounts: $rw"; fail=1; fi

exit $fail
