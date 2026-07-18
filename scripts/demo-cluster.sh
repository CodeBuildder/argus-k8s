#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
namespace="${DEMO_NAMESPACE:-argus-demo}"
wait_seconds="${DEMO_WAIT_SECONDS:-30}"
keep_resources="${DEMO_KEEP_RESOURCES:-false}"
confirmed_context="${DEMO_CLUSTER_CONTEXT:-}"
dry_run=false
port_forward_pid=""
ui_pid=""
port_forward_log=""
ui_log=""
cleanup_started=false
namespace_created=false

usage() {
  cat <<'EOF'
Usage: scripts/demo-cluster.sh [--dry-run] [--keep]

Environment:
  DEMO_CLUSTER_CONTEXT  Exact kubectl context; skips the interactive prompt
  DEMO_NAMESPACE        Isolated namespace (default: argus-demo)
  DEMO_WAIT_SECONDS     Evidence collection window (default: 30)
  DEMO_KEEP_RESOURCES   true to retain the demo namespace
EOF
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    --keep) keep_resources=true ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

case "$namespace" in
  default|kube-system|kube-public|kube-node-lease|argus-system|kyverno)
    echo "Refusing unsafe demo namespace: $namespace" >&2; exit 2 ;;
esac
[[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "DEMO_NAMESPACE must be a valid DNS label" >&2; exit 2;
}
[[ "$wait_seconds" =~ ^[0-9]+$ ]] && (( wait_seconds >= 5 && wait_seconds <= 300 )) || {
  echo "DEMO_WAIT_SECONDS must be between 5 and 300" >&2; exit 2;
}

for command in kubectl; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

if [[ "$dry_run" != true ]]; then
  for command in curl npm; do
    command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
  done
fi

context="$(kubectl config current-context)"
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

echo "Argus guarded cluster demo"
echo "  Context:   $context"
echo "  API:       $server"
echo "  Namespace: $namespace"

if [[ "$dry_run" == true ]]; then
  echo "DRY RUN: preflight only; no cluster resources will be changed."
elif [[ -n "$confirmed_context" ]]; then
  [[ "$confirmed_context" == "$context" ]] || {
    echo "DEMO_CLUSTER_CONTEXT does not match the active context '$context'" >&2; exit 2;
  }
elif [[ -t 0 ]]; then
  read -r -p "Type the exact context name to authorize bounded demo resources: " confirmed_context
  [[ "$confirmed_context" == "$context" ]] || { echo "Context confirmation failed." >&2; exit 2; }
else
  echo "Non-interactive runs require DEMO_CLUSTER_CONTEXT='$context'" >&2; exit 2
fi

echo "==> Checking Kubernetes API and node readiness"
kubectl --request-timeout=10s get --raw=/readyz >/dev/null
kubectl wait --for=condition=Ready nodes --all --timeout=30s >/dev/null

require_ready_workload() {
  local label="$1" target_namespace="$2" description="$3" count
  count="$(kubectl get pods -n "$target_namespace" -l "$label" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)"
  [[ "$count" != "0" ]] || {
    echo "Required component is not running: $description ($target_namespace, $label)" >&2; exit 1;
  }
  kubectl wait -n "$target_namespace" --for=condition=Ready pods -l "$label" --timeout=60s >/dev/null
  echo "  ready: $description ($count pod(s))"
}

echo "==> Validating the installed security stack"
require_ready_workload "k8s-app=cilium" "kube-system" "Cilium"
require_ready_workload "app.kubernetes.io/name=falco" "kube-system" "Falco"
require_ready_workload "app.kubernetes.io/component=admission-controller" "kyverno" "Kyverno"
require_ready_workload "app=argus-agent" "argus-system" "Argus agent"

if [[ "$dry_run" == true ]]; then
  echo "Preflight passed. Re-run without --dry-run to execute the demo."
  exit 0
fi

cleanup() {
  [[ "$cleanup_started" == false ]] || return
  cleanup_started=true

  if [[ -n "$ui_pid" ]]; then
    kill "$ui_pid" 2>/dev/null || true
    wait "$ui_pid" 2>/dev/null || true
  fi
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  if [[ "$namespace_created" != true ]]; then
    :
  elif [[ "$keep_resources" == true ]]; then
    echo "Keeping namespace $namespace (DEMO_KEEP_RESOURCES=true)."
  else
    echo "==> Cleaning up isolated demo namespace"
    kubectl delete namespace "$namespace" --wait=false --ignore-not-found >/dev/null
  fi
  if [[ -n "$port_forward_log" ]]; then rm -f "$port_forward_log"; fi
  if [[ -n "$ui_log" ]]; then rm -f "$ui_log"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if kubectl get namespace "$namespace" >/dev/null 2>&1; then
  echo "Namespace $namespace already exists; refusing to reuse or delete it." >&2
  echo "Choose another DEMO_NAMESPACE or inspect and remove the existing namespace yourself." >&2
  exit 1
fi

if curl --fail --silent --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1; then
  echo "Port 8000 already has an HTTP service. Stop it before running make demo-cluster." >&2
  exit 1
fi
if curl --fail --silent --max-time 2 http://127.0.0.1:5173 >/dev/null 2>&1; then
  echo "Port 5173 already has an HTTP service. Stop it before running make demo-cluster." >&2
  exit 1
fi

if [[ ! -d "$repo_root/ui/node_modules" ]]; then
  echo "==> Installing missing UI dependencies"
  npm --prefix "$repo_root/ui" ci
fi

wait_for_url() {
  local url="$1" process_id="$2" description="$3" log_file="$4"
  for _attempt in $(seq 1 30); do
    if curl --fail --silent --max-time 2 "$url" >/dev/null 2>&1; then
      echo "  ready: $description"
      return 0
    fi
    if ! kill -0 "$process_id" 2>/dev/null; then
      echo "$description exited before becoming ready:" >&2
      tail -30 "$log_file" >&2 || true
      return 1
    fi
    sleep 1
  done
  echo "$description did not become ready within 30 seconds:" >&2
  tail -30 "$log_file" >&2 || true
  return 1
}

port_forward_log="$(mktemp -t argus-port-forward.XXXXXX)"
ui_log="$(mktemp -t argus-ui.XXXXXX)"

echo "==> Connecting the local console to the in-cluster Argus agent"
kubectl port-forward --address 127.0.0.1 -n argus-system svc/argus-agent 8000:80 >"$port_forward_log" 2>&1 &
port_forward_pid=$!
wait_for_url "http://127.0.0.1:8000/health" "$port_forward_pid" "Argus service port-forward" "$port_forward_log"

echo "==> Starting the Argus console"
npm --prefix "$repo_root/ui" run dev -- --host 127.0.0.1 >"$ui_log" 2>&1 &
ui_pid=$!
wait_for_url "http://127.0.0.1:5173/api/health" "$ui_pid" "Argus console and API proxy" "$ui_log"

echo ""
echo "Argus cluster console: http://127.0.0.1:5173"
echo ""

echo "==> Creating isolated namespace"
kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
namespace_created=true
kubectl label namespace "$namespace" argus.io/demo=true --overwrite >/dev/null

echo "==> Launching bounded threat workloads"
DEMO_NAMESPACE="$namespace" bash cluster/test-diverse-threats.sh

echo "==> Waiting for workloads and telemetry"
kubectl wait -n "$namespace" --for=condition=Ready pods -l threat-type --timeout=90s >/dev/null
sleep "$wait_seconds"

echo ""; echo "==> Workload evidence"
kubectl get pods -n "$namespace" -l threat-type -o wide
echo ""; echo "==> Recent Falco evidence"
kubectl logs -n kube-system -l app.kubernetes.io/name=falco --since=5m --tail=80 --prefix=true || true
echo ""; echo "==> Recent Argus evidence"
kubectl logs -n argus-system -l app=argus-agent --since=5m --tail=80 --prefix=true || true
echo ""; echo "==> Kyverno policy evidence"
kubectl get policyreport -n "$namespace" 2>/dev/null || echo "No namespaced PolicyReport resource is available."
echo ""; echo "==> Cilium flow command"
echo "hubble observe --namespace $namespace --since 5m"
echo ""; echo "Demo evidence collected. The real-cluster console remains available at:"
echo "  http://127.0.0.1:5173"
echo "Press Ctrl-C to stop the console, port-forward, and demo workloads."

while kill -0 "$ui_pid" 2>/dev/null && kill -0 "$port_forward_pid" 2>/dev/null; do
  sleep 2
done

echo "A supervised demo process exited unexpectedly." >&2
if ! kill -0 "$ui_pid" 2>/dev/null; then tail -30 "$ui_log" >&2 || true; fi
if ! kill -0 "$port_forward_pid" 2>/dev/null; then tail -30 "$port_forward_log" >&2 || true; fi
exit 1
