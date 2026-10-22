#!/bin/bash
# Container entrypoint (root). Process tree:
#   entrypoint.sh (root)
#   ├─ watchdog supervisor (root) -> amazon-efs-mount-watchdog: keeps the TLS
#   │                                tunnel alive, re-signs it with the rotated
#   │                                credentials from the user-mount profile
#   ├─ efs-utils log forwarder     -> stdout (CloudWatch only sees stdout)
#   ├─ agent_app.py                -> drops to uid $AGENT_UID before importing
#   └─ gateway.py (root, :8080)    -> mint creds, mount, rotate, proxy
set -u
export HOME=/root
AGENT_UID="${AGENT_UID:-1000}"

supervise_watchdog() {
  local backoff=1
  while true; do
    /usr/bin/amazon-efs-mount-watchdog
    echo "{\"component\":\"entrypoint\",\"event\":\"watchdog_exited\",\"code\":$?}"
    sleep "$backoff"; backoff=$(( backoff < 30 ? backoff * 2 : 30 ))
  done
}
supervise_watchdog &

mkdir -p /var/log/amazon/efs
touch /var/log/amazon/efs/mount.log /var/log/amazon/efs/mount-watchdog.log
tail -q -n0 -F /var/log/amazon/efs/mount.log /var/log/amazon/efs/mount-watchdog.log \
  | sed -u 's/^/[efs-utils] /' &

python3.11 /app/agent_app.py &

exec python3.11 /app/gateway.py
