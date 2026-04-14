#!/bin/bash
# Argus - Install k3s on master node
# Issue #2: https://github.com/CodeBuildder/argus-k8s/issues/2
#
# Prerequisites:
#   - OrbStack VMs running (run 01-provision-vms.sh first)
#   - k3sup installed (brew install k3sup)
#
# Usage: ./02-install-master.sh

set -euo pipefail

MASTER_IP="192.168.139.42"
USER="kaushikkumaran"
SSH_KEY="$HOME/.orbstack/ssh/id_ed25519"

echo "==> Installing k3s on master node ${MASTER_IP}..."

k3sup install \
  --host "${MASTER_IP}" \
  --user "${USER}" \
  --ssh-key "${SSH_KEY}" \
  --k3s-extra-args "--disable traefik --disable servicelb --flannel-backend=none --disable-network-policy --cluster-cidr=10.244.0.0/16" \
  --local-path ~/.kube/config \
  --context argus

echo "==> Switching to argus context..."
kubectl config use-context argus

echo "==> Master node status (NotReady is expected until Cilium is installed):"
kubectl get nodes

echo ""
echo "==> Done. Next: run 03-join-workers.sh"
