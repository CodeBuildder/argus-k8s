#!/usr/bin/env bash
set -Eeuo pipefail

namespace="${DEMO_NAMESPACE:-argus-demo}"
wait_seconds="${DEMO_WAIT_SECONDS:-30}"
keep_resources="${DEMO_KEEP_RESOURCES:-false}"
confirmed_context="${DEMO_CLUSTER_CONTEXT:-}"
dry_run=false

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
  if [[ "$keep_resources" == true ]]; then
    echo "Keeping namespace $namespace (DEMO_KEEP_RESOURCES=true)."
  else
    echo "==> Cleaning up isolated demo namespace"
    kubectl delete namespace "$namespace" --wait=false --ignore-not-found >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> Creating isolated namespace"
kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
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
echo ""; echo "Demo completed. Review the evidence above and the Argus console."
