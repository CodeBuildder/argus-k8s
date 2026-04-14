#!/bin/bash
# Argus - Join worker nodes to k3s cluster
# Issue #3: https://github.com/CodeBuildder/argus-k8s/issues/3
#
# Prerequisites:
#   - k3s master running (run 02-install-master.sh first)
#   - k3sup installed (brew install k3sup)
#
# Usage: ./03-join-workers.sh

set -euo pipefail

MASTER_IP="192.168.139.42"
WORKER1_IP="192.168.139.77"
WORKER2_IP="192.168.139.45"
USER="kaushikkumaran"
SSH_KEY="$HOME/.orbstack/ssh/id_ed25519"

echo "==> Joining worker1 (${WORKER1_IP}) to cluster..."
k3sup join \
  --host "${WORKER1_IP}" \
  --server-host "${MASTER_IP}" \
  --user "${USER}" \
  --ssh-key "${SSH_KEY}"

echo "==> Joining worker2 (${WORKER2_IP}) to cluster..."
k3sup join \
  --host "${WORKER2_IP}" \
  --server-host "${MASTER_IP}" \
  --user "${USER}" \
  --ssh-key "${SSH_KEY}"

echo "==> All nodes status:"
kubectl get nodes -o wide

echo ""
echo "==> Done. Next: install Cilium CNI (issue #4)"
