#!/usr/bin/env bash
# SentinelSOC - start the backend and the dashboard together.
#
#   ./start.sh              backend :8000, dashboard :3000
#   PORT=3100 ./start.sh    dashboard on another port when 3000 is taken
set -euo pipefail
cd "$(dirname "$0")"

API_PORT="${API_PORT:-8000}"
PORT="${PORT:-3000}"

if [ ! -d .venv ]; then
  echo "No .venv. Run:  uv venv --python 3.12 .venv && uv pip install -r requirements.txt"
  exit 1
fi
if [ ! -d frontend/node_modules ]; then
  echo "Frontend deps missing. Run:  cd frontend && npm install"
  exit 1
fi
if [ ! -f data/samples/auth.log ]; then
  echo "Generating sample logs…"
  .venv/bin/python scripts/generate_logs.py
fi

free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

# Kill whatever is already listening on a given port so re-running this script
# never fails with "address already in use". Only ever touches the two ports
# this script itself is about to bind (API_PORT, PORT) - never a blanket kill.
kill_port() {
  local port="$1" pids
  pids="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)"
  [ -z "$pids" ] && return 0

  echo "Port $port is busy (pid(s): $pids) - stopping so we can bind it."
  kill $pids 2>/dev/null || true

  for _ in $(seq 1 10); do
    free "$port" && return 0
    sleep 0.3
  done

  echo "  still busy, forcing…"
  kill -9 $pids 2>/dev/null || true
  sleep 0.3
  free "$port" || { echo "Could not free port $port."; exit 1; }
}

kill_port "$API_PORT"
kill_port "$PORT"

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "backend    http://localhost:$API_PORT/api/docs"
.venv/bin/python -m uvicorn main:app --app-dir backend --port "$API_PORT" --log-level warning &

echo "dashboard  http://localhost:$PORT"
( cd frontend && NEXT_PUBLIC_API_URL="http://127.0.0.1:$API_PORT" npm run dev -- --port "$PORT" ) &

wait
