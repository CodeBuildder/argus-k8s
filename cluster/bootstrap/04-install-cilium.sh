#!/bin/bash
# Argus - Install Cilium CNI with kube-proxy replacement and Hubble
# Issue #4: https://github.com/CodeBuildder/argus-k8s/issues/4
#
# Prerequisites:
#   - k3s cluster running with all nodes (run 02 and 03 first)
#   - cilium-cli installed (brew install cilium-cli)
#   - hubble installed (brew install hubble)
#
# Usage: ./04-install-cilium.sh

set -euo pipefail

MASTER_IP="192.168.139.42"

echo "==> Installing Cilium v1.15.0 with kube-proxy replacement..."
cilium install \
  --version 1.15.0 \
  --set ipam.mode=kubernetes \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="${MASTER_IP}" \
  --set k8sServicePort=6443

echo "==> Waiting for Cilium to be ready..."
cilium status --wait

echo "==> Enabling Hubble relay and UI..."
cilium hubble enable --ui

echo "==> Final status:"
cilium status

echo ""
echo "==> Cilium and Hubble installed successfully."
echo "    Run 'cilium hubble ui' to open the network flow graph."
echo "    Run 'hubble observe' to stream live flows."
echo ""
echo "    Next: create namespaces (issue #5)"
