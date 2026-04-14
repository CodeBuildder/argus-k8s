# Argus — Architecture

## Cluster Topology

| Node | Role | IP | OS |
|---|---|---|---|
| k3s-master | Control plane | 192.168.139.42 | Ubuntu 22.04 ARM64 |
| k3s-worker1 | Worker | 192.168.139.77 | Ubuntu 22.04 ARM64 |
| k3s-worker2 | Worker | 192.168.139.45 | Ubuntu 22.04 ARM64 |

## Network

All nodes communicate over OrbStack's internal virtual bridge.
Node IPs are stable across Mac network changes (WiFi, ethernet, etc).
SSH access requires ~/.orbstack/ssh/id_ed25519.

## Architecture diagram

[Will be added after Module 1 is complete]
