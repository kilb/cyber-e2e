#!/bin/bash
# Robustly (re)start the isolated cybergym-e2e uvicorn on 127.0.0.1:8900 in its
# own session. Mirrors the sibling project's start_server.sh discipline:
# ALWAYS restart after editing server.py or adding a case directory, because the
# running process discovers its case list at import time and will otherwise keep
# serving a stale set (causing confusing `unknown case_id` 404s).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2

PORT="${E2E_PORT:-8900}"
export E2E_API_KEY="${E2E_API_KEY:-localtest}"
export E2E_CASES_ROOT="${E2E_CASES_ROOT:-$HERE/../cases}"

pkill -f "uvicorn server:app .*${PORT}" 2>/dev/null
sleep 2

PY="${E2E_PY:-$HERE/venv/bin/python}"
[ -x "$PY" ] || PY=python3

setsid "$PY" -m uvicorn server:app --host 127.0.0.1 --port "$PORT" \
  > "$HERE/server-${PORT}.log" 2>&1 < /dev/null &
disown
sleep 3
if pgrep -f "uvicorn server:app .*${PORT}" >/dev/null; then
  echo "OK: cybergym-e2e uvicorn running on 127.0.0.1:${PORT} (pid $(pgrep -f "uvicorn server:app .*${PORT}" | head -1))"
  curl -s "http://127.0.0.1:${PORT}/health" && echo
else
  echo "FAIL: uvicorn not running; log tail:"; tail -15 "$HERE/server-${PORT}.log"
  exit 1
fi
