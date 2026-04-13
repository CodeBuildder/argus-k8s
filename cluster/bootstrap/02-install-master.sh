#!/usr/bin/env bash
# Usage: ./02-install-master.sh
#
# Installs k3s on k3s-master with:
#   --flannel-backend=none        (Cilium will handle CNI)
#   --disable-network-policy      (Cilium will handle NetworkPolicy)
#   --disable=traefik             (not needed for this project)
#
# Prerequisites:
#   - 01-provision-vms.sh has been run successfully
#   - k3sup installed locally (brew install k3sup)
#
# TODO: implement in Module 1

echo "TODO: implement master node k3s install in Module 1"
