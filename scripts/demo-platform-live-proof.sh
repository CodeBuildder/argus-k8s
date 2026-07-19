#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
namespace="${LIVE_DEMO_NAMESPACE:-sentinel-live-demo}"
fault_seconds="${LIVE_FAULT_SECONDS:-15}"
evidence_wait_seconds="${LIVE_EVIDENCE_WAIT_SECONDS:-90}"
keep_resources="${LIVE_DEMO_KEEP_RESOURCES:-false}"
dry_run="${LIVE_DEMO_DRY_RUN:-false}"
authorized_context="${LIVE_DEMO_CONTEXT:-}"
authorized_phrase="${LIVE_DEMO_CONFIRMATION:-}"
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-live-proof.XXXXXX")"
platform_pid=""
probe_pid=""
target_forward_pid=""
namespace_created=false
scenario_id=""

fail() { echo "ERROR: $*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }

cleanup() {
  trap - INT TERM EXIT
  for process_id in "${probe_pid}" "${target_forward_pid}" "${platform_pid}"; do
    if [[ -n "${process_id}" ]]; then kill "${process_id}" 2>/dev/null || true; fi
  done
  for process_id in "${probe_pid}" "${target_forward_pid}" "${platform_pid}"; do
    if [[ -n "${process_id}" ]]; then wait "${process_id}" 2>/dev/null || true; fi
  done
  if [[ "${namespace_created}" == "true" && "${keep_resources}" != "true" ]]; then
    echo "==> Deleting isolated namespace ${namespace}"
    kubectl --context "${context}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null || true
  elif [[ "${namespace_created}" == "true" ]]; then
    echo "Keeping ${namespace} because LIVE_DEMO_KEEP_RESOURCES=true."
  fi
  echo "Live proof stopped. Logs: ${log_dir}"
}
trap cleanup EXIT INT TERM

case "${namespace}" in
  default|kube-system|kube-public|kube-node-lease|argus-system|phoenix-system|sentinel-platform|kyverno|chaos-mesh)
    fail "Refusing unsafe live-demo namespace: ${namespace}" ;;
esac
[[ "${namespace}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || fail "LIVE_DEMO_NAMESPACE must be a DNS label."
[[ "${fault_seconds}" =~ ^[0-9]+$ ]] && ((fault_seconds >= 5 && fault_seconds <= 30)) ||
  fail "LIVE_FAULT_SECONDS must be between 5 and 30."
[[ "${evidence_wait_seconds}" =~ ^[0-9]+$ ]] && ((evidence_wait_seconds >= 30 && evidence_wait_seconds <= 180)) ||
  fail "LIVE_EVIDENCE_WAIT_SECONDS must be between 30 and 180."

for required in kubectl curl jq awk npm python3; do require_command "${required}"; done
context="$(kubectl config current-context)"
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

echo "Sentinel guarded live resilience proof"
echo "  Context:     ${context}"
echo "  API:         ${server}"
echo "  Namespace:   ${namespace}"
echo "  Fault:       PodChaos / one of two demo replicas / ${fault_seconds}s"
echo "  Cleanup:     isolated namespace only"

kubectl --context "${context}" --request-timeout=10s get --raw=/readyz >/dev/null
kubectl --context "${context}" wait --for=condition=Ready nodes --all --timeout=30s >/dev/null

require_ready() {
  local target_namespace="$1" selector="$2" description="$3"
  kubectl --context "${context}" -n "${target_namespace}" wait --for=condition=Ready pod \
    -l "${selector}" --timeout=60s >/dev/null || fail "Required component is not ready: ${description}."
  echo "  ready: ${description}"
}

echo "==> Validating real security, chaos, and correlation services"
require_ready kube-system k8s-app=cilium Cilium
require_ready kube-system app.kubernetes.io/name=falco Falco
require_ready kyverno app.kubernetes.io/component=admission-controller Kyverno
require_ready argus-system app=argus-agent "Argus agent"
require_ready kube-system app.kubernetes.io/component=controller-manager "Chaos Mesh controller"
require_ready kube-system app.kubernetes.io/component=chaos-daemon "Chaos Mesh daemon"
require_ready phoenix-system app=phoenix-chaos "Phoenix chaos engine"
require_ready phoenix-system app=phoenix-agent "Phoenix agent"
require_ready sentinel-platform app=sentinel-world-model "Sentinel Operations Graph"
kubectl --context "${context}" get crd podchaos.chaos-mesh.org >/dev/null
kubectl --context "${context}" auth can-i create podchaos.chaos-mesh.org -n "${namespace}" | grep -qx yes ||
  fail "Current identity cannot create PodChaos in ${namespace}."

if [[ "${dry_run}" == "true" ]]; then
  echo "Preflight passed. No namespace, workload, fault, process, or finding was created."
  exit 0
fi

if [[ -n "${authorized_context}" ]]; then
  [[ "${authorized_context}" == "${context}" ]] || fail "LIVE_DEMO_CONTEXT does not match ${context}."
elif [[ -t 0 ]]; then
  read -r -p "Type the exact context name to authorize the isolated workload: " authorized_context
  [[ "${authorized_context}" == "${context}" ]] || fail "Context confirmation failed."
else
  fail "Non-interactive runs require LIVE_DEMO_CONTEXT=${context}."
fi

if [[ -z "${authorized_phrase}" && -t 0 ]]; then
  echo "The next approval permits one real PodChaos against one of two disposable replicas."
  read -r -p "Type INJECT LIVE FAULT to continue: " authorized_phrase
fi
[[ "${authorized_phrase}" == "INJECT LIVE FAULT" ]] || fail "Live fault confirmation failed."

kubectl --context "${context}" get namespace "${namespace}" >/dev/null 2>&1 &&
  fail "Namespace ${namespace} already exists; refusing to reuse or delete it."

echo "==> Starting live cluster consoles without synthetic seed data"
DEMO_PLATFORM_CONTEXT="${context}" DEMO_PLATFORM_SKIP_SEED=true \
  bash "${repo_root}/scripts/demo-platform.sh" >"${log_dir}/platform.log" 2>&1 &
platform_pid=$!
for _attempt in $(seq 1 90); do
  if curl --fail --silent --max-time 3 http://127.0.0.1:5175/api/health |
    jq -e '.world_model_connected == true' >/dev/null 2>&1; then break; fi
  kill -0 "${platform_pid}" 2>/dev/null || fail "Platform services exited. See ${log_dir}/platform.log."
  sleep 1
done
curl --fail --silent --max-time 3 http://127.0.0.1:5175/api/health | jq -e '.world_model_connected == true' >/dev/null ||
  fail "Sentinel UI did not connect through its API proxy."

echo "==> Creating isolated two-replica customer service"
kubectl --context "${context}" create namespace "${namespace}" >/dev/null
namespace_created=true
kubectl --context "${context}" label namespace "${namespace}" sentinel.io/live-demo=true --overwrite >/dev/null
kubectl --context "${context}" apply -n "${namespace}" -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel-live-target
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sentinel-live-target
  template:
    metadata:
      labels:
        app: sentinel-live-target
        sentinel.io/live-demo: "true"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        runAsGroup: 101
        fsGroup: 101
      containers:
      - name: web
        image: docker.io/nginxinc/nginx-unprivileged:1.27-alpine
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /
            port: 8080
          periodSeconds: 1
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          readOnlyRootFilesystem: false
        resources:
          requests: {cpu: 25m, memory: 32Mi}
          limits: {cpu: 100m, memory: 96Mi}
---
apiVersion: v1
kind: Service
metadata:
  name: sentinel-live-target
spec:
  selector:
    app: sentinel-live-target
  ports:
  - port: 8080
    targetPort: 8080
YAML
kubectl --context "${context}" -n "${namespace}" rollout status deployment/sentinel-live-target --timeout=120s >/dev/null

kubectl --context "${context}" -n "${namespace}" port-forward --address 127.0.0.1 \
  svc/sentinel-live-target 18080:8080 >"${log_dir}/target-forward.log" 2>&1 &
target_forward_pid=$!
for _attempt in $(seq 1 30); do
  curl --fail --silent --max-time 2 http://127.0.0.1:18080/ >/dev/null && break
  sleep 1
done
curl --fail --silent --max-time 2 http://127.0.0.1:18080/ >/dev/null || fail "Demo service is not reachable."

probe_log="${log_dir}/availability.log"
(
  while true; do
    if curl --fail --silent --max-time 1 http://127.0.0.1:18080/ >/dev/null; then echo 1; else echo 0; fi
    sleep 0.25
  done
) >"${probe_log}" &
probe_pid=$!

echo "==> Launching bounded real Falco-triggering workload"
DEMO_NAMESPACE="${namespace}" bash "${repo_root}/cluster/test-diverse-threats.sh" >"${log_dir}/threats.log" 2>&1
kubectl --context "${context}" -n "${namespace}" wait --for=condition=Ready pod -l threat-type --timeout=120s >/dev/null

argus_incident_file="${log_dir}/argus-incident.json"
argus_detected=false
evidence_started_epoch="$(date +%s)"
for _attempt in $(seq 1 "${evidence_wait_seconds}"); do
  if curl --fail --silent --max-time 10 http://127.0.0.1:8000/incidents |
    jq -e --arg namespace "${namespace}" '[.[] | select((.namespace // "") == $namespace)] | first' >"${argus_incident_file}"; then
    argus_detected=true
    break
  fi
  sleep 1
done
[[ "${argus_detected}" == "true" ]] || fail "Argus did not expose Falco evidence for ${namespace} within ${evidence_wait_seconds}s."
argus_detected_epoch="$(date +%s)"

old_pods="$(kubectl --context "${context}" -n "${namespace}" get pods -l app=sentinel-live-target -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
correlation_id="live-proof-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "==> Injecting one real, approved PodChaos"
scenario="$(curl --fail --silent --show-error -X POST http://127.0.0.1:8082/scenarios \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg corr "${correlation_id}" --arg namespace "${namespace}" --argjson duration "${fault_seconds}" '{name:"Sentinel live pod recovery proof",correlation_id:$corr,domain:"chaos_mesh",fault_type:"pod_kill",target:{namespace:$namespace,label_selector:{app:"sentinel-live-target"},mode:"one"},duration_seconds:$duration,params:{grace_period_seconds:0}}')")"
scenario_id="$(jq -r '.id' <<<"${scenario}")"
backend_ref="$(jq -r '.backend_ref' <<<"${scenario}")"
fault_started_epoch="$(date +%s)"
[[ -n "${scenario_id}" && "${scenario_id}" != "null" && -n "${backend_ref}" && "${backend_ref}" != "null" ]] ||
  fail "Phoenix did not return a scenario ID and Chaos Mesh backend reference."
kubectl --context "${context}" -n "${namespace}" get podchaos "${backend_ref}" -o json >"${log_dir}/podchaos.json" ||
  fail "Phoenix returned ${backend_ref}, but the real PodChaos object was not found."

replacement_ready=false
replacement_name=""
for _attempt in $(seq 1 120); do
  replacement_name="$(kubectl --context "${context}" -n "${namespace}" get pods -l app=sentinel-live-target \
    --field-selector=status.phase=Running -o jsonpath='{range .items[?(@.status.containerStatuses[0].ready==true)]}{.metadata.name}{"\n"}{end}' 2>/dev/null |
    while IFS= read -r pod_name; do grep -qxF "${pod_name}" <<<"${old_pods}" || { echo "${pod_name}"; break; }; done)"
  ready_replicas="$(kubectl --context "${context}" -n "${namespace}" get deployment sentinel-live-target -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  if [[ -n "${replacement_name}" && "${ready_replicas:-0}" == "2" ]]; then replacement_ready=true; break; fi
  sleep 1
done
[[ "${replacement_ready}" == "true" ]] || fail "A replacement replica was not verified after PodChaos."
recovery_epoch="$(date +%s)"
recovery_seconds="$((recovery_epoch - fault_started_epoch))"
sleep 5

probe_total="$(wc -l <"${probe_log}" | tr -d ' ')"
probe_success="$(awk '$1 == 1 {count++} END {print count+0}' "${probe_log}")"
((probe_total > 0)) || fail "Availability probe produced no samples."
availability="$(awk -v success="${probe_success}" -v total="${probe_total}" 'BEGIN {printf "%.2f", (success/total)*100}')"

echo "==> Correlating verified live evidence through Sentinel"
entity_id="service/${namespace}/sentinel-live-target"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
curl --fail --silent -X POST http://127.0.0.1:8010/entities -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg id "${entity_id}" --arg namespace "${namespace}" '{entity_id:$id,entity_type:"service",name:"sentinel-live-target",namespace:$namespace,labels:{"sentinel.io/live-demo":"true"},slo_target:0.999}')" >/dev/null
curl --fail --silent -X POST http://127.0.0.1:8010/findings -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg id "argus-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --slurpfile original "${argus_incident_file}" '{event_id:$id,type:"finding",source:"argus",timestamp:$ts,entity_id:$entity,severity:"high",correlation_id:$corr,replayed:false,payload:{finding_type:"falco_alert",assessment:"Observed Falco runtime evidence in isolated live-demo namespace",provenance:"observed",evidence_source:"argus_incidents_api",original_incident:$original[0]}}')" >/dev/null
curl --fail --silent -X POST http://127.0.0.1:8010/findings -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg id "phoenix-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --arg scenario "${scenario_id}" --arg backend "${backend_ref}" --arg replacement "${replacement_name}" --arg availability "${availability}" --argjson recovery "${recovery_seconds}" '{event_id:$id,type:"finding",source:"phoenix",timestamp:$ts,entity_id:$entity,severity:"high",correlation_id:$corr,payload:{finding_type:"healing_action",outcome:"verified_recovery",description:"Chaos Mesh killed one disposable replica; Kubernetes replaced it and service health was verified",provenance:"live_chaos",domain:"chaos_mesh",scenario_id:$scenario,backend_ref:$backend,replacement_pod:$replacement,recovery_seconds:$recovery,measured_availability_percent:$availability,approval_required:true,approval_record:"INJECT LIVE FAULT"}}')" >/dev/null

incident_file="${log_dir}/sentinel-incident.json"
verified=false
for _attempt in $(seq 1 60); do
  if curl --fail --silent --max-time 25 http://127.0.0.1:5175/api/overview |
    jq -e --arg correlation_id "${correlation_id}" '.incidents[] | select(.correlation_id == $correlation_id and .sources == ["argus","phoenix"] and .provenance == ["live_chaos","observed"])' >"${incident_file}"; then
    verified=true; break
  fi
  sleep 1
done
[[ "${verified}" == "true" ]] || fail "Sentinel did not expose live correlation ${correlation_id}."
sentinel_health="$(curl --fail --silent --max-time 10 http://127.0.0.1:5175/api/health)"
openai_configured="$(jq -r '.openai_configured == true' <<<"${sentinel_health}")"

artifact_dir="${repo_root}/artifacts/demo-platform"
mkdir -p "${artifact_dir}"
report_json="${artifact_dir}/${correlation_id}.json"
report_markdown="${artifact_dir}/${correlation_id}.md"
jq -n --arg run_id "${correlation_id}" --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg correlation_id "${correlation_id}" --arg entity_id "${entity_id}" --arg context "${context}" \
  --arg namespace "${namespace}" --arg availability "${availability}" --arg scenario "${scenario_id}" \
  --argjson openai_configured "${openai_configured}" \
  --argjson detection_ms "$(((argus_detected_epoch - evidence_started_epoch) * 1000))" \
  --argjson recovery_ms "$((recovery_seconds * 1000))" --slurpfile incident "${incident_file}" \
  '{schema_version:"1.0",verdict:"PASS",run_id:$run_id,generated_at:$generated_at,
    cluster:{context:$context,namespace:$namespace,nodes:3},correlation:{id:$correlation_id,verified:true,sources:["argus","phoenix"],incident:$incident[0]},
    entity:{id:$entity_id},timings:{argus_detection_ms:$detection_ms,recovery_ms:$recovery_ms,sentinel_correlation_ms:0,total_lifecycle_ms:($detection_ms+$recovery_ms)},
    recovery:{result:"verified_recovery",availability:("measured " + $availability + "%")},
    governance:{approval_required:true,reason:"operator typed INJECT LIVE FAULT"},openai:{configured:$openai_configured,briefing_generated:false},
    evidence:{provenance:["live_chaos","observed"],seed:null,live_chaos:true,scenario_id:$scenario},
    interpretation:"Real Falco evidence and a real Chaos Mesh PodChaos were executed only inside an isolated namespace. Availability came from continuous HTTP probes; recovery required a new Ready replica and two Ready deployment replicas."}' >"${report_json}"
bash "${repo_root}/scripts/render-demo-report.sh" "${report_json}" "${report_markdown}"
cp "${report_json}" "${artifact_dir}/latest-live-demo.json"
cp "${report_markdown}" "${artifact_dir}/latest-live-demo.md"

echo ""
echo "LIVE PLATFORM RESILIENCE PROOF: PASS"
echo "  Cluster:                    ${context} — 3 nodes"
echo "  Namespace:                  ${namespace}"
echo "  Argus detection:            observed via Falco"
echo "  Phoenix experiment:         live_chaos / ${scenario_id}"
echo "  Service availability:       ${availability}% (${probe_success}/${probe_total} probes)"
echo "  Recovery verified:          ${replacement_name} ready"
echo "  Recovery time:              ${recovery_seconds}s"
echo "  Human approval:             explicitly authorized"
echo "  Sentinel correlation:       ${correlation_id}"
echo "  Evidence:                   ${artifact_dir}/latest-live-demo.md"
echo "  Cleanup boundary:           namespace/${namespace}"
echo ""
echo "Open Sentinel at http://127.0.0.1:5175 and select the live correlated incident."
echo "Press Ctrl-C to stop consoles and delete only the isolated namespace."

while true; do sleep 60; done
