#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
threat_count="${1:-10}"
threat_scenario="${2:-mixed}"
threat_seed="${3:-}"
agent_pid=""
ui_pid=""

cleanup() {
  trap - INT TERM EXIT
  if [[ -n "${agent_pid}" ]]; then
    kill "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  if [[ -n "${ui_pid}" ]]; then
    kill "${ui_pid}" 2>/dev/null || true
    wait "${ui_pid}" 2>/dev/null || true
  fi
  echo "Argus local demo stopped."
}

stop_cleanly() {
  cleanup
  exit 0
}

trap stop_cleanly INT TERM
trap cleanup EXIT

if [[ ! -x "${repo_root}/.venv/bin/python" ]]; then
  echo "Python environment missing; creating it now ..."
  python3 -m venv "${repo_root}/.venv"
  "${repo_root}/.venv/bin/pip" install -r "${repo_root}/agent/requirements.txt"
fi

if [[ ! -d "${repo_root}/ui/node_modules" ]]; then
  echo "UI dependencies missing; installing them now ..."
  npm --prefix "${repo_root}/ui" ci
fi

if curl --fail --silent http://127.0.0.1:8000/health >/dev/null 2>&1; then
  echo "Port 8000 already has an Argus backend running. Stop it before using make demo-local."
  exit 1
fi

if curl --fail --silent http://127.0.0.1:5173 >/dev/null 2>&1; then
  echo "Port 5173 is already in use. Stop that service before using make demo-local."
  exit 1
fi

echo "Starting Argus backend at http://127.0.0.1:8000 ..."
(
  cd "${repo_root}/agent/src"
  exec env ARGUS_LOCAL_DEMO=true IN_CLUSTER=false \
    ../../.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000
) &
agent_pid=$!

echo "Starting Argus console at http://127.0.0.1:5173 ..."
npm --prefix "${repo_root}/ui" run dev -- --host 127.0.0.1 &
ui_pid=$!

backend_ready=false
for _attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:8000/health >/dev/null 2>&1; then
    backend_ready=true
    break
  fi
  if ! kill -0 "${agent_pid}" 2>/dev/null; then
    echo "Argus backend exited before becoming ready."
    exit 1
  fi
  if ! kill -0 "${ui_pid}" 2>/dev/null; then
    echo "Argus console exited before the backend became ready."
    exit 1
  fi
  sleep 1
done

if [[ "${backend_ready}" != "true" ]]; then
  echo "Argus backend did not become ready within 30 seconds."
  exit 1
fi

seed_field=""
if [[ -n "${threat_seed}" ]]; then
  seed_field=", \"seed\": ${threat_seed}"
fi

echo "Generating ${threat_count} '${threat_scenario}' incidents ..."
simulation_response="$(curl --fail --silent --show-error \
  -X POST http://127.0.0.1:8000/simulate-threats \
  -H "Content-Type: application/json" \
  -d "{\"count\": ${threat_count}, \"scenario\": \"${threat_scenario}\"${seed_field}}")"

echo "${simulation_response}"
echo ""
echo "Argus is ready:"
echo "  Console: http://127.0.0.1:5173"
echo "  API docs: http://127.0.0.1:8000/docs"
echo "  Health:   http://127.0.0.1:8000/health"
echo ""
echo "No Kubernetes cluster is being used. Incidents are stored in memory."
echo "Press Ctrl-C to stop the backend and console."

wait "${agent_pid}"
