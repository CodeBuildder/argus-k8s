#!/bin/bash
# Provision Argus custom dashboards into Grafana via ConfigMap
# Run after kube-prometheus-stack is deployed
# Issue #12: https://github.com/CodeBuildder/argus-k8s/issues/12

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="${SCRIPT_DIR}/dashboards"

echo "==> Provisioning Argus Grafana dashboards..."

kubectl create configmap argus-dashboards \
  --namespace monitoring \
  --from-file="${DASHBOARD_DIR}/argus-security-overview.json" \
  --from-file="${DASHBOARD_DIR}/argus-cluster-health.json" \
  --from-file="${DASHBOARD_DIR}/argus-policy-violations.json" \
  --from-file="${DASHBOARD_DIR}/argus-network-flows.json" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl label configmap argus-dashboards \
  --namespace monitoring \
  grafana_dashboard=1 \
  --overwrite

echo "==> Restarting Grafana to pick up dashboards..."
kubectl rollout restart deployment/kube-prometheus-stack-grafana -n monitoring

echo "==> Done. Dashboards will appear in Grafana under 'Argus' folder."
