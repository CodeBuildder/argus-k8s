# ADR 001: OrbStack over Multipass for VM provisioning

## Status
Accepted

## Context
Need lightweight Linux VMs on Apple M3 (ARM64) to host a 3-node k3s cluster.
VMs need real Linux kernels for eBPF (Cilium) and kernel module access (Falco).
Docker containers (kind, Docker Desktop K8s) are insufficient because eBPF requires
kernel-level access that container-in-container isolation cannot provide.

## Decision
Use OrbStack to provision Ubuntu 22.04 ARM64 VMs.

## Rationale
- Uses macOS native Virtualization.framework — fastest VM startup on M3
- ARM64-native, no emulation overhead
- Automatic SSH key injection — no manual setup for k3sup
- Internal virtual bridge (orb0) is WiFi-independent — cluster survives network changes
- VM IPs are stable across restarts

## Rejected Alternatives
- Multipass: Works but slower startup, less Mac-native integration on M3
- kind: Runs nodes as Docker containers — eBPF/Cilium and Falco kernel access breaks
- minikube: Single node only, cannot demonstrate real multi-node topology
- Docker Desktop K8s: Black box networking, cannot swap CNI

## Consequences
OrbStack is not open source (free tier sufficient for this project).
VMs consume ~8GB RAM total (2+3+3) — acceptable on 32GB M3.
