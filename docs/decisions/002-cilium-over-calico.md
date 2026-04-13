# ADR 002: Cilium over Calico as CNI

## Status
Accepted

## Context
Need a CNI that supports NetworkPolicy enforcement, provides network-level observability,
and runs on ARM64. CNI choice also determines whether kube-proxy can be replaced.

## Decision
Use Cilium with eBPF mode, kube-proxy replacement enabled, and Hubble for observability.

## Rationale
- eBPF programs run in kernel — faster than iptables-based routing, fully observable
- kube-proxy replacement via eBPF eliminates iptables entirely from the data path
- Hubble provides L3/L4/L7 network flow visibility out of the box with no extra tooling
- CiliumNetworkPolicy extends standard K8s NetworkPolicy with L7 rules (HTTP path, DNS)
- ARM64 support stable since Cilium 1.14
- eBPF is a transferable skill — used in Datadog agent, cloud provider networking, security tooling

## Rejected Alternatives
- Calico: iptables-based by default, requires separate configuration for eBPF mode,
  less integrated observability than Hubble
- Flannel: No NetworkPolicy support, no observability, only L3 routing
- Weave: Effectively unmaintained

## Consequences
Must pass --flannel-backend=none and --disable-network-policy to k3s at install time.
Cilium CLI must be installed separately from kubectl.
kube-proxy replacement requires --k8sServiceHost and --k8sServicePort flags at Cilium install.
