#!/usr/bin/env bash
# Restarts the enclave if the server stops answering. Run every 30 s by the
# trustgate-watchdog.timer. It only counts failures, so one slow response does
# not cause a restart, and it leaves a grace period after a restart so the
# enclave has time to boot.
#
# Overridable for testing: TG_HEALTH_URL, TG_STATE_DIR, TG_RESTART_CMD, TG_FAILS,
# TG_GRACE_SECONDS.
set -u
URL=${TG_HEALTH_URL:-http://127.0.0.1:8444/healthz}
STATE=${TG_STATE_DIR:-/run/trustgate-watchdog}
RESTART=${TG_RESTART_CMD:-systemctl restart trustgate-enclave.service trustgate-forwarder.service}
FAILS_NEEDED=${TG_FAILS:-3}
GRACE=${TG_GRACE_SECONDS:-120}

mkdir -p "$STATE"
now=$(date +%s)

if [ -f "$STATE/grace-until" ] && [ "$now" -lt "$(cat "$STATE/grace-until")" ]; then
  exit 0
fi

if curl -sf -m 5 "$URL" >/dev/null; then
  rm -f "$STATE/fails"
  exit 0
fi

fails=$(( $(cat "$STATE/fails" 2>/dev/null || echo 0) + 1 ))
echo "$fails" > "$STATE/fails"
echo "trustgate-watchdog: health check failed ($fails/$FAILS_NEEDED)"

if [ "$fails" -ge "$FAILS_NEEDED" ]; then
  echo "trustgate-watchdog: restarting the enclave"
  rm -f "$STATE/fails"
  echo $(( now + GRACE )) > "$STATE/grace-until"
  $RESTART
fi
