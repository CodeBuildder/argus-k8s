#!/bin/bash
# Argus Agent — build and deploy to cluster
# Issue #17: https://github.com/CodeBuildder/argus-k8s/issues/17
#
# Usage: ANTHROPIC_API_KEY=sk-ant-... ./deploy.sh

set -euo pipefail

NAMESPACE="argus-system"
IMAGE_NAME="argus-agent"
IMAGE_TAG="latest"

echo "==> Building agent Docker image..."
cd "$(dirname "$0")"
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .

echo "==> Loading image into k3s nodes..."
# Export image and import into each k3s node
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | \
  ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@192.168.139.42 \
  "sudo k3s ctr images import -"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | \
  ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@192.168.139.77 \
  "sudo k3s ctr images import -"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | \
  ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@192.168.139.45 \
  "sudo k3s ctr images import -"

echo "==> Applying RBAC..."
kubectl apply -f k8s/rbac.yaml

echo "==> Creating secret..."
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ERROR: ANTHROPIC_API_KEY env var is required"
  exit 1
fi
kubectl create secret generic argus-secrets \
  --namespace "${NAMESPACE}" \
  --from-literal=anthropic-api-key="${ANTHROPIC_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying agent..."
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/network-policy.yaml

echo "==> Waiting for rollout..."
kubectl rollout status deployment/argus-agent -n "${NAMESPACE}" --timeout=120s

echo "==> Agent deployed successfully."
echo "    Health: kubectl port-forward -n argus-system svc/argus-agent 8080:80"
echo "    Logs:   kubectl logs -n argus-system -l app=argus-agent -f"
