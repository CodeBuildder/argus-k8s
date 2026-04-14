# Argus

> Autonomous Kubernetes security platform combining eBPF-native threat detection,
> policy enforcement, and an AI reasoning agent for real-time threat response and remediation.

## Cluster status

| Node | Role | IP | Status |
|---|---|---|---|
| k3s-master | Control plane | 192.168.139.42 | ✅ Ready |
| k3s-worker1 | Worker | 192.168.139.77 | ✅ Ready |
| k3s-worker2 | Worker | 192.168.139.45 | ✅ Ready |

**Cilium:** v1.15.0 — eBPF mode, kube-proxy replacement enabled
**Hubble:** Relay + UI enabled — live network flow observability active

### Hubble UI — 3/3 nodes, 20.6 flows/s

![Hubble UI](docs/screenshots/hubble-ui.png)

## Stack

| Layer | Tool | Why |
|---|---|---|
| Local cluster | k3s on OrbStack VMs | Lightweight, ARM-native, production-like topology |
| CNI | Cilium + Hubble | eBPF-native, replaces kube-proxy, L7 network observability |
| Runtime security | Falco | CNCF-graduated, syscall-level threat detection, structured JSON events |
| Admission control | Kyverno | K8s-native policy-as-code, rejects non-compliant workloads pre-deployment |
| mTLS | Linkerd | Automatic zero-trust service encryption, lightweight vs Istio |
| Metrics | Prometheus | Industry standard scraping and alerting |
| Logs | Loki + Promtail | Lightweight log aggregation, native Grafana integration |
| Dashboards | Grafana | Unified observability — metrics, logs, security events |
| AI Agent | Python + Claude API | Enriches Falco alerts with cluster context, reasons about threat severity, routes remediation actions |
| UI | React + Tailwind | Real-time incident feed, human approval queue, agent chat |

## Modules

| Module | Description | Status |
|---|---|---|
| 1 — Cluster Foundation | OrbStack VMs, k3s, Cilium, Hubble | ✅ Complete |
| 2 — Security Layers | Falco, Kyverno, CiliumNetworkPolicy | ⏳ Pending |
| 3 — Observability Stack | Prometheus, Grafana, Loki | ⏳ Pending |
| 4 — AI Agent Engine | Falco webhook → context enrichment → Claude → action router | ⏳ Pending |
| 5 — Command & Control UI | React dashboard, approval queue, agent chat | ⏳ Pending |

## How it works

[fill in after agent is built]

## Local setup

[fill in after Module 1 is complete]

## Architecture decisions

See [docs/decisions/](docs/decisions/) for rationale behind every tool choice.
