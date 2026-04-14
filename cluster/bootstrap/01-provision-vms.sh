#!/bin/bash
# Argus - Provision OrbStack VMs for k3s cluster
# Issue #1: https://github.com/CodeBuildder/argus-k8s/issues/1
#
# Prerequisites:
#   - OrbStack installed and running (brew install orbstack)
#   - ~/.orbstack/ssh/id_ed25519 exists
#
# Usage: ./01-provision-vms.sh

set -euo pipefail

echo "==> Provisioning OrbStack VMs..."
orb create ubuntu:22.04 k3s-master
orb create ubuntu:22.04 k3s-worker1
orb create ubuntu:22.04 k3s-worker2

echo "==> Installing SSH daemon on all nodes..."
for vm in k3s-master k3s-worker1 k3s-worker2; do
  echo "  -> $vm"
  ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@${vm}.orb.local \
    "sudo apt-get install -y openssh-server && sudo systemctl enable ssh && sudo systemctl start ssh"
  ssh-copy-id -i ~/.orbstack/ssh/id_ed25519.pub kaushikkumaran@${vm}.orb.local
done

echo "==> Verifying SSH access via IP..."
MASTER_IP="192.168.139.42"
WORKER1_IP="192.168.139.77"
WORKER2_IP="192.168.139.45"

ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@${MASTER_IP} "echo ok: master"
ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@${WORKER1_IP} "echo ok: worker1"
ssh -i ~/.orbstack/ssh/id_ed25519 kaushikkumaran@${WORKER2_IP} "echo ok: worker2"

echo ""
echo "==> All VMs provisioned and SSH verified."
echo "    Master:  ${MASTER_IP}"
echo "    Worker1: ${WORKER1_IP}"
echo "    Worker2: ${WORKER2_IP}"
echo ""
echo "    Next: run 02-install-master.sh"
