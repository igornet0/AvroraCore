#!/usr/bin/env bash
# Build and start the AvroraCore ↔ BackupSAS stand, run e2e.py, tear down.
#   KEEP=1     keep the stand running afterwards
#   NO_TEST=1  only build + start
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/compose.yml")

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build

echo "waiting for avrora…"
for _ in $(seq 1 180); do
  if "${COMPOSE[@]}" logs avrora 2>/dev/null | grep -q "Avrora listening"; then break; fi
  sleep 1
done

status=0
if [ "${NO_TEST:-0}" != "1" ]; then
  python3 "$HERE/e2e.py" || status=$?
  if [ "$status" != "0" ]; then
    echo "── logs (tail) ──"
    "${COMPOSE[@]}" logs --tail=40 || true
  fi
fi

if [ "${KEEP:-0}" = "1" ]; then
  echo "stand kept: API http://127.0.0.1:${E2E_HTTP_PORT:-28787}/api"
  echo "stop with:  ${COMPOSE[*]} down -v"
else
  "${COMPOSE[@]}" down -v >/dev/null
fi
exit "$status"
