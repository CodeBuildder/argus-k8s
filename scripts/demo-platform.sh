#!/usr/bin/env bash
set -Eeuo pipefail

argus_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
phoenix_root="${PHOENIX_ROOT:-$(cd "${argus_root}/../sentinel-stack/phoenix" 2>/dev/null && pwd)}"
sentinel_root="${SENTINEL_ROOT:-$(cd "${argus_root}/../sentinel-stack/sentinel" 2>/dev/null && pwd)}"
dry_run="${DEMO_PLATFORM_DRY_RUN:-false}"
exit_after_ready="${DEMO_PLATFORM_EXIT_AFTER_READY:-false}"
demo_context="${DEMO_PLATFORM_CONTEXT:-$(kubectl config current-context 2>/dev/null || true)}"
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-demo.XXXXXX")"
owned_pids=()

cleanup() {
  trap - INT TERM EXIT
  if ((${#owned_pids[@]})); then
    echo ""
    echo "Stopping command-owned demo processes ..."
    for owned_pid in "${owned_pids[@]}"; do
      kill "${owned_pid}" 2>/dev/null || true
    done
    for owned_pid in "${owned_pids[@]}"; do
      wait "${owned_pid}" 2>/dev/null || true
    done
  fi
  echo "Demo stopped. Logs: ${log_dir}"
}
trap cleanup EXIT INT TERM

fail() { echo "ERROR: $*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }
http_ok() { curl --fail --silent --max-time 2 "$1" >/dev/null 2>&1; }
port_in_use() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

wait_for_url() {
  local label="$1" url="$2" pid="${3:-}" attempt
  for attempt in $(seq 1 40); do
    if http_ok "${url}"; then return 0; fi
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
      fail "${label} exited before becoming ready. See ${log_dir}."
    fi
    sleep 1
  done
  fail "${label} did not become ready at ${url}. See ${log_dir}."
}

start_forward() {
  local label="$1" namespace="$2" service="$3" local_port="$4" remote_port="$5" health_url="$6"
  if http_ok "${health_url}"; then
    echo "  reuse: ${label} (${health_url})"
    return
  fi
  port_in_use "${local_port}" && fail "Port ${local_port} is occupied but does not serve ${label}."
  echo "  start: ${label} on 127.0.0.1:${local_port}"
  kubectl --context "${demo_context}" -n "${namespace}" port-forward "svc/${service}" "${local_port}:${remote_port}" \
    >"${log_dir}/${label// /-}.log" 2>&1 &
  local forward_pid=$!
  owned_pids+=("${forward_pid}")
  wait_for_url "${label}" "${health_url}" "${forward_pid}"
}

start_service() {
  local label="$1" port="$2" health_url="$3" workdir="$4"
  shift 4
  if http_ok "${health_url}"; then
    echo "  reuse: ${label} (${health_url})"
    return
  fi
  port_in_use "${port}" && fail "Port ${port} is occupied but ${label} is not healthy."
  echo "  start: ${label} on 127.0.0.1:${port}"
  (cd "${workdir}" && exec "$@") >"${log_dir}/${label// /-}.log" 2>&1 &
  local service_pid=$!
  owned_pids+=("${service_pid}")
  wait_for_url "${label}" "${health_url}" "${service_pid}"
}

echo "Sentinel platform deterministic demo"
echo "  Context:  ${demo_context:-<none>}"
echo "  Argus:    ${argus_root}"
echo "  Phoenix:  ${phoenix_root}"
echo "  Sentinel: ${sentinel_root}"
echo "  Mode:     replayed Argus evidence + Phoenix simulator (no live Chaos Mesh)"

for required in curl jq kubectl lsof npm python3; do require_command "${required}"; done
[[ -n "${demo_context}" ]] || fail "No Kubernetes context is selected."
[[ -d "${phoenix_root}/dashboard" ]] || fail "Phoenix checkout not found. Set PHOENIX_ROOT."
[[ -d "${sentinel_root}/dashboard" ]] || fail "Sentinel checkout not found. Set SENTINEL_ROOT."
[[ -x "${argus_root}/.venv/bin/python" ]] || fail "Argus environment missing. Run: make setup-local"
[[ -d "${argus_root}/ui/node_modules" ]] || fail "Argus UI dependencies missing. Run: make setup-local"
[[ -x "${sentinel_root}/.venv/bin/python" ]] || fail "Sentinel environment missing. Run: make -C ${sentinel_root} setup-local"
[[ -d "${sentinel_root}/dashboard/node_modules" ]] || fail "Sentinel dashboard dependencies are missing."
[[ -d "${phoenix_root}/dashboard/node_modules" ]] || fail "Phoenix dashboard dependencies are missing."

kubectl --context "${demo_context}" get --raw=/readyz >/dev/null
kubectl --context "${demo_context}" -n sentinel-platform get svc sentinel-world-model >/dev/null
for phoenix_service in phoenix-graph phoenix-chaos phoenix-faultlib phoenix-sim phoenix-agent; do
  kubectl --context "${demo_context}" -n phoenix-system get svc "${phoenix_service}" >/dev/null
done

if [[ "${dry_run}" == "true" ]]; then
  echo "Preflight passed. No processes, port-forwards, findings, or cluster resources were created."
  exit 0
fi

if [[ -f "${argus_root}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${argus_root}/.env"
  set +a
fi

echo "==> Connecting shared services"
start_forward "sog" sentinel-platform sentinel-world-model 8010 8000 http://127.0.0.1:8010/health
start_forward "phoenix-graph" phoenix-system phoenix-graph 8080 80 http://127.0.0.1:8080/health
start_forward "phoenix-faultlib" phoenix-system phoenix-faultlib 8081 80 http://127.0.0.1:8081/health
start_forward "phoenix-chaos" phoenix-system phoenix-chaos 8082 80 http://127.0.0.1:8082/health
start_forward "phoenix-sim" phoenix-system phoenix-sim 8083 80 http://127.0.0.1:8083/health
start_forward "phoenix-agent" phoenix-system phoenix-agent 8084 80 http://127.0.0.1:8084/health

echo "==> Starting or reusing consoles"
start_service "argus-api" 8000 http://127.0.0.1:8000/health "${argus_root}/agent/src" \
  env ARGUS_LOCAL_DEMO=true IN_CLUSTER=false WORLD_MODEL_URL=http://127.0.0.1:8010 \
  "${argus_root}/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8000
start_service "argus-ui" 5173 http://127.0.0.1:5173 "${argus_root}" \
  npm --prefix ui run dev -- --host 127.0.0.1 --port 5173
start_service "phoenix-ui" 5174 http://127.0.0.1:5174 "${phoenix_root}" \
  env VITE_ARGUS_URL=http://127.0.0.1:5173 VITE_SENTINEL_URL=http://127.0.0.1:5175 \
  npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5174
start_service "sentinel-api" 8090 http://127.0.0.1:8090/health "${sentinel_root}" \
  env WORLD_MODEL_URL=http://127.0.0.1:8010 OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  "${sentinel_root}/.venv/bin/python" -m uvicorn main:app --app-dir backend/src --host 127.0.0.1 --port 8090
start_service "sentinel-ui" 5175 http://127.0.0.1:5175 "${sentinel_root}" \
  env VITE_ARGUS_URL=http://127.0.0.1:5173 VITE_PHOENIX_URL=http://127.0.0.1:5174 \
  npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5175

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
correlation_id="judge-demo-${run_id}"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
entity_id="service/phoenix-system/phoenix-sim"

echo "==> Publishing deterministic correlated evidence"
curl --fail --silent --show-error -X POST http://127.0.0.1:8010/findings \
  -H "Content-Type: application/json" \
  -d "{\"event_id\":\"argus-${run_id}\",\"type\":\"finding\",\"source\":\"argus\",\"timestamp\":\"${timestamp}\",\"entity_id\":\"${entity_id}\",\"severity\":\"critical\",\"correlation_id\":\"${correlation_id}\",\"replayed\":true,\"payload\":{\"finding_type\":\"falco_alert\",\"rule\":\"Deterministic C2 Callback Proof\",\"description\":\"Replayed Argus evidence for the judge demo\",\"provenance\":\"replayed\",\"seed\":42}}" >/dev/null
curl --fail --silent --show-error -X POST http://127.0.0.1:8010/findings \
  -H "Content-Type: application/json" \
  -d "{\"event_id\":\"phoenix-${run_id}\",\"type\":\"finding\",\"source\":\"phoenix\",\"timestamp\":\"${timestamp}\",\"entity_id\":\"${entity_id}\",\"severity\":\"high\",\"correlation_id\":\"${correlation_id}\",\"payload\":{\"finding_type\":\"healing_action\",\"scenario_id\":\"sim-${run_id}\",\"outcome\":\"verified_recovery\",\"description\":\"Phoenix simulator verified service recovery\",\"provenance\":\"simulator\",\"domain\":\"simulator\",\"seed\":42}}" >/dev/null

echo "==> Verifying the Sentinel incident"
verified=false
for _attempt in $(seq 1 45); do
  if curl --fail --silent --max-time 25 http://127.0.0.1:8090/overview | jq -e --arg correlation_id "${correlation_id}" '.incidents[] | select(.correlation_id == $correlation_id and .sources == ["argus","phoenix"] and .provenance == ["replayed","simulator"])' >/dev/null; then
    verified=true
    break
  fi
  sleep 1
done
[[ "${verified}" == "true" ]] || fail "Sentinel did not expose correlation ${correlation_id}."

echo ""
echo "✅ Full platform demo is ready"
echo "  Argus:    http://127.0.0.1:5173"
echo "  Phoenix:  http://127.0.0.1:5174"
echo "  Sentinel: http://127.0.0.1:5175"
echo "  SOG API:  http://127.0.0.1:8010/health"
echo "  Evidence: ${correlation_id} (replayed + simulator, seed 42)"
echo ""
echo "Open Sentinel → Open Incidents → select the correlated lifecycle."
echo "Press Ctrl-C to stop only processes started by this command."

if [[ "${exit_after_ready}" == "true" ]]; then
  exit 0
fi

while true; do sleep 60; done
