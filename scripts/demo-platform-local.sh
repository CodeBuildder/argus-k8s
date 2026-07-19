#!/usr/bin/env bash
set -Eeuo pipefail

argus_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
phoenix_root="${PHOENIX_ROOT:-${argus_root}/../sentinel-stack/phoenix}"
sentinel_root="${SENTINEL_ROOT:-${argus_root}/../sentinel-stack/sentinel}"
platform_root="${SENTINEL_PLATFORM_ROOT:-${argus_root}/../sentinel-stack/sentinel-platform}"
dry_run="${DEMO_PLATFORM_DRY_RUN:-false}"
exit_after_ready="${DEMO_PLATFORM_EXIT_AFTER_READY:-false}"
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-local-demo.XXXXXX")"
artifact_dir="${DEMO_PLATFORM_ARTIFACT_DIR:-${argus_root}/artifacts/demo-platform}"
redis_port="${DEMO_REDIS_PORT:-6389}"
redis_name="sentinel-local-demo-$$"
owned_pids=()
redis_owned=false

cleanup() {
  trap - INT TERM EXIT
  if ((${#owned_pids[@]})); then
    echo ""
    echo "Stopping command-owned local demo processes ..."
    for owned_pid in "${owned_pids[@]}"; do kill "${owned_pid}" 2>/dev/null || true; done
    for owned_pid in "${owned_pids[@]}"; do wait "${owned_pid}" 2>/dev/null || true; done
  fi
  if [[ "${redis_owned}" == "true" ]]; then
    docker stop --time 2 "${redis_name}" >/dev/null 2>&1 || true
  fi
  echo "Local platform demo stopped. Logs: ${log_dir}"
}
trap cleanup EXIT INT TERM

fail() { echo "ERROR: $*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }
http_ok() { curl --fail --silent --max-time 3 "$1" >/dev/null 2>&1; }
port_in_use() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
now_ms() { python3 -c 'import time; print(time.time_ns() // 1_000_000)'; }

wait_for_url() {
  local label="$1" url="$2" pid="${3:-}" attempt
  for attempt in $(seq 1 60); do
    if http_ok "${url}"; then return 0; fi
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
      fail "${label} exited before becoming ready. See ${log_dir}."
    fi
    sleep 1
  done
  fail "${label} did not become ready at ${url}. See ${log_dir}."
}

stop_known_listener() {
  local port="$1" expected_cwd="$2" expected_command="$3" listener_pid listener_cwd listener_command
  port_in_use "${port}" || return 0
  listener_pid="$(lsof -nP -tiTCP:"${port}" -sTCP:LISTEN | head -1)"
  listener_cwd="$(lsof -a -p "${listener_pid}" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
  listener_command="$(ps -p "${listener_pid}" -o command= 2>/dev/null || true)"
  [[ "${listener_cwd}" == "${expected_cwd}" && "${listener_command}" == *"${expected_command}"* ]] ||
    fail "Port ${port} belongs to PID ${listener_pid}, not the expected ${expected_command} process in ${expected_cwd}."
  echo "  replace: ${expected_command} listener on 127.0.0.1:${port}"
  kill "${listener_pid}"
  for _attempt in $(seq 1 20); do port_in_use "${port}" || return 0; sleep 0.25; done
  fail "PID ${listener_pid} did not release port ${port}."
}

stop_cluster_forward() {
  local port="$1" listener_pid listener_command
  port_in_use "${port}" || return 0
  listener_pid="$(lsof -nP -tiTCP:"${port}" -sTCP:LISTEN | head -1)"
  listener_command="$(ps -p "${listener_pid}" -o command= 2>/dev/null || true)"
  [[ "${listener_command}" == *"kubectl"*"port-forward"* ]] ||
    fail "Port ${port} is occupied by PID ${listener_pid}; local mode will not terminate an unrelated listener."
  echo "  replace: Kubernetes port-forward on 127.0.0.1:${port}"
  kill "${listener_pid}"
  for _attempt in $(seq 1 20); do port_in_use "${port}" || return 0; sleep 0.25; done
  fail "Port-forward PID ${listener_pid} did not release port ${port}."
}

ensure_venv() {
  local service_root="$1" requirements="$2"
  if [[ ! -x "${service_root}/.venv/bin/python" ]]; then
    echo "  install: Python dependencies in ${service_root}"
    python3 -m venv "${service_root}/.venv"
    "${service_root}/.venv/bin/pip" install -r "${requirements}"
  elif ! "${service_root}/.venv/bin/python" -c 'import fastapi, uvicorn' >/dev/null 2>&1; then
    echo "  repair: incomplete Python dependencies in ${service_root}"
    "${service_root}/.venv/bin/pip" install -r "${requirements}"
  fi
}

ensure_node_modules() {
  local package_root="$1"
  if [[ ! -d "${package_root}/node_modules" ]]; then
    echo "  install: npm dependencies in ${package_root}"
    npm --prefix "${package_root}" install
  fi
}

start_service() {
  local label="$1" port="$2" health_url="$3" workdir="$4"
  shift 4
  port_in_use "${port}" && fail "Port ${port} is still occupied before starting ${label}."
  echo "  start: ${label} on 127.0.0.1:${port}"
  (cd "${workdir}" && exec "$@") >"${log_dir}/${label}.log" 2>&1 &
  local service_pid=$!
  owned_pids+=("${service_pid}")
  wait_for_url "${label}" "${health_url}" "${service_pid}"
}

echo "Sentinel platform local judge demo"
echo "  Mode:       cluster-free synthetic topology + deterministic evidence"
echo "  Kubernetes: not used"
echo "  Argus:      ${argus_root}"
echo "  Phoenix:    ${phoenix_root}"
echo "  Sentinel:   ${sentinel_root}"
echo "  SOG:        ${platform_root}"

for required in curl jq lsof npm python3 docker ps; do require_command "${required}"; done
[[ -d "${phoenix_root}/dashboard" ]] || fail "Phoenix checkout not found. Set PHOENIX_ROOT."
[[ -d "${sentinel_root}/dashboard" ]] || fail "Sentinel checkout not found. Set SENTINEL_ROOT."
[[ -d "${platform_root}/world_model" ]] || fail "Sentinel Platform checkout not found. Set SENTINEL_PLATFORM_ROOT."
docker info >/dev/null 2>&1 || fail "Docker is not running. Start Docker or OrbStack, then retry."

if [[ "${dry_run}" == "true" ]]; then
  echo "Preflight passed. No cluster, containers, processes, or evidence were changed."
  exit 0
fi

if [[ -f "${argus_root}/.env" ]]; then set -a; source "${argus_root}/.env"; set +a; fi

echo "==> Installing missing local dependencies"
ensure_venv "${argus_root}" "${argus_root}/agent/requirements.txt"
ensure_venv "${platform_root}" "${platform_root}/world_model/requirements.txt"
ensure_venv "${sentinel_root}" "${sentinel_root}/backend/requirements.txt"
for phoenix_service in graph sim chaos faultlib agent; do
  ensure_venv "${phoenix_root}/${phoenix_service}" "${phoenix_root}/${phoenix_service}/requirements.txt"
done
ensure_node_modules "${argus_root}/ui"
ensure_node_modules "${phoenix_root}/dashboard"
ensure_node_modules "${sentinel_root}/dashboard"

echo "==> Replacing only known platform listeners"
stop_cluster_forward 8010
for service_port in 8080 8081 8082 8083 8084; do stop_cluster_forward "${service_port}"; done
stop_known_listener 8000 "${argus_root}/agent/src" "uvicorn"
stop_known_listener 5173 "${argus_root}/ui" "vite"
stop_known_listener 5174 "${phoenix_root}/dashboard" "vite"
stop_known_listener 8090 "${sentinel_root}" "uvicorn"
stop_known_listener 5175 "${sentinel_root}/dashboard" "vite"
port_in_use "${redis_port}" && fail "Redis demo port ${redis_port} is already occupied."

echo "==> Starting disposable local SOG"
docker run --rm --name "${redis_name}" -p "127.0.0.1:${redis_port}:6379" redis:7-alpine \
  >"${log_dir}/redis.log" 2>&1 &
redis_pid=$!
owned_pids+=("${redis_pid}")
redis_owned=true
for _attempt in $(seq 1 40); do
  docker exec "${redis_name}" redis-cli ping 2>/dev/null | grep -q PONG && break
  kill -0 "${redis_pid}" 2>/dev/null || fail "Disposable Redis exited. See ${log_dir}/redis.log."
  sleep 0.5
done
docker exec "${redis_name}" redis-cli ping 2>/dev/null | grep -q PONG || fail "Disposable Redis did not become ready."

start_service sog 8010 http://127.0.0.1:8010/health "${platform_root}/world_model/src" \
  env WM_REDIS_URL="redis://127.0.0.1:${redis_port}" "${platform_root}/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8010

echo "==> Starting local Phoenix services"
start_service phoenix-graph 8080 http://127.0.0.1:8080/health "${phoenix_root}/graph/src" \
  env PHOENIX_LOCAL_DEMO=true "${phoenix_root}/graph/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8080
start_service phoenix-sim 8083 http://127.0.0.1:8083/health "${phoenix_root}/sim/src" \
  "${phoenix_root}/sim/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8083
start_service phoenix-chaos 8082 http://127.0.0.1:8082/health "${phoenix_root}/chaos/src" \
  env SIMULATOR_URL=http://127.0.0.1:8083 "${phoenix_root}/chaos/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8082
start_service phoenix-faultlib 8081 http://127.0.0.1:8081/health "${phoenix_root}/faultlib/src" \
  env CHAOS_URL=http://127.0.0.1:8082 "${phoenix_root}/faultlib/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8081
start_service phoenix-agent 8084 http://127.0.0.1:8084/health "${phoenix_root}" \
  env CHAOS_URL=http://127.0.0.1:8082 GRAPH_URL=http://127.0.0.1:8080 FAULTLIB_URL=http://127.0.0.1:8081 \
  WORLD_MODEL_URL=http://127.0.0.1:8010 DB_PATH="${log_dir}/phoenix-memory.db" OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  "${phoenix_root}/agent/.venv/bin/python" -m uvicorn main:app --app-dir agent/src --host 127.0.0.1 --port 8084

echo "==> Starting specialist and command-center consoles"
start_service argus-api 8000 http://127.0.0.1:8000/health "${argus_root}/agent/src" \
  env ARGUS_LOCAL_DEMO=true IN_CLUSTER=false WORLD_MODEL_URL=http://127.0.0.1:8010 \
  "${argus_root}/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8000
start_service argus-ui 5173 http://127.0.0.1:5173/api/health "${argus_root}" \
  npm --prefix ui run dev -- --host 127.0.0.1 --port 5173
start_service phoenix-ui 5174 http://127.0.0.1:5174/api/graph/health "${phoenix_root}" \
  env VITE_ARGUS_URL=http://127.0.0.1:5173 VITE_SENTINEL_URL=http://127.0.0.1:5175 \
  npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5174
start_service sentinel-api 8090 http://127.0.0.1:8090/health "${sentinel_root}" \
  env WORLD_MODEL_URL=http://127.0.0.1:8010 OPENAI_API_KEY="${OPENAI_API_KEY:-}" SENTINEL_DEMO_MODE=portable \
  "${sentinel_root}/.venv/bin/python" -m uvicorn main:app --app-dir backend/src --host 127.0.0.1 --port 8090
start_service sentinel-ui 5175 http://127.0.0.1:5175/api/health "${sentinel_root}" \
  env VITE_ARGUS_URL=http://127.0.0.1:5173 VITE_PHOENIX_URL=http://127.0.0.1:5174 \
  npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5175
curl --fail --silent --max-time 20 http://127.0.0.1:5175/api/readiness |
  jq -e '.ready_to_present == true and .mode == "portable"' >/dev/null ||
  fail "Sentinel presentation preflight is not ready. Open http://127.0.0.1:5175 for component remediation."

echo "==> Seeding the synthetic cluster and cross-agent lifecycles"
demo_started_ms="$(now_ms)"
run_id="$(DEMO_SEED=42 bash "${argus_root}/scripts/seed-platform-local.sh")"
seeded_ms="$(now_ms)"
correlation_id="local-${run_id}-checkout-egress"
verified=false
incident_file="${log_dir}/verified-incident.json"
for _attempt in $(seq 1 60); do
  if curl --fail --silent --max-time 25 http://127.0.0.1:5175/api/overview |
    jq -e --arg correlation_id "${correlation_id}" '.incidents[] | select(.correlation_id == $correlation_id and .sources == ["argus","phoenix"] and .provenance == ["replayed","simulator"] and (.proof.lifecycle | length) == 7 and .proof.metrics.availability_percent == "not measured")' >"${incident_file}"; then
    verified=true
    break
  fi
  sleep 1
done
[[ "${verified}" == "true" ]] || fail "Sentinel UI did not expose local correlation ${correlation_id}."
verified_ms="$(now_ms)"

mkdir -p "${artifact_dir}"
run_json="${artifact_dir}/${correlation_id}.json"
run_markdown="${artifact_dir}/${correlation_id}.md"
openai_configured="$(curl --fail --silent http://127.0.0.1:8090/health | jq -r '.openai_configured == true')"
jq -n --arg run_id "${run_id}" --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg correlation_id "${correlation_id}" --argjson openai_configured "${openai_configured}" \
  --argjson seed_ms "$((seeded_ms - demo_started_ms))" --argjson correlation_ms "$((verified_ms - seeded_ms))" \
  --argjson lifecycle_ms "$((verified_ms - demo_started_ms))" --slurpfile incident "${incident_file}" \
  '{schema_version:"1.0",verdict:"PASS",run_id:$run_id,generated_at:$generated_at,
    correlation:{id:$correlation_id,verified:true,sources:["argus","phoenix"],incident:$incident[0]},
    entity:{id:"service/storefront/checkout"},
    timings:{argus_evidence_publish_ms:$seed_ms,phoenix_recovery_publish_ms:0,sentinel_correlation_ms:$correlation_ms,total_lifecycle_ms:$lifecycle_ms},
    recovery:{result:"verified_recovery",availability:"recovery verified; availability percentage not measured"},
    governance:{approval_required:false,reason:"bounded simulator action"},openai:{configured:$openai_configured,briefing_generated:false},
    evidence:{provenance:["replayed","simulator"],seed:42,live_chaos:false},
    interpretation:"A real local SOG and all three product services processed an explicitly synthetic cluster topology, replayed Argus evidence, and Phoenix simulator outcomes. No Kubernetes API or live fault was used."}' >"${run_json}"
bash "${argus_root}/scripts/render-demo-report.sh" "${run_json}" "${run_markdown}"
cp "${run_json}" "${artifact_dir}/latest-demo.json"
cp "${run_markdown}" "${artifact_dir}/latest-demo.md"

DEMO_SEED=42 bash "${argus_root}/scripts/platform-local-feed.sh" >"${log_dir}/feed.log" 2>&1 &
feed_pid=$!
owned_pids+=("${feed_pid}")

overview="$(curl --fail --silent --max-time 25 http://127.0.0.1:5175/api/overview)"
echo ""
echo "PLATFORM LOCAL PROOF: PASS"
echo "  Kubernetes API calls:       0"
printf '  Synthetic topology:         %s entities · %s relationships · %s namespaces\n' \
  "$(jq -r '.counts.entities' <<<"${overview}")" "$(jq -r '.counts.edges' <<<"${overview}")" "$(jq -r '.counts.namespaces' <<<"${overview}")"
printf '  Seeded evidence:            %s findings · %s incidents\n' \
  "$(jq -r '.counts.findings' <<<"${overview}")" "$(jq -r '.counts.incidents' <<<"${overview}")"
echo "  Recovery:                   verified in simulator"
echo "  Provenance:                 replayed + simulator (seed 42)"
echo "  Dynamic feed:               every ${DEMO_FEED_INTERVAL_SECONDS:-20}s"
echo "  Evidence:                   ${artifact_dir}/latest-demo.md"
echo ""
echo "Open Argus    → http://127.0.0.1:5173"
echo "Open Phoenix  → http://127.0.0.1:5174"
echo "Open Sentinel → http://127.0.0.1:5175"
echo "Synthetic data is labeled in every topology node and evidence payload."
echo "Press Ctrl-C to stop the entire disposable local platform."

if [[ "${exit_after_ready}" == "true" ]]; then exit 0; fi
while true; do sleep 60; done
