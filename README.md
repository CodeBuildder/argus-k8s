<!--
Argus — Autonomous Kubernetes Security Platform
Copyright (c) 2026 Kaushikkumaran
Original work — see NOTICE for details
Commit history: https://github.com/CodeBuildder/argus-k8s/commits/main
-->

# Argus

> Autonomous Kubernetes security platform combining eBPF-native threat detection,
> policy enforcement, and an AI reasoning agent for real-time threat response and remediation.

## Cluster status

### Network flow observability
![Hubble UI — live eBPF network flows](docs/screenshots/hubble-ui-flows.png)
*Live TCP flows between Cilium components captured at the kernel level via eBPF*

| Node | Role | IP | Status |
|---|---|---|---|
| k3s-master | Control plane | 192.168.139.42 | ✅ Ready |
| k3s-worker1 | Worker | 192.168.139.77 | ✅ Ready |
| k3s-worker2 | Worker | 192.168.139.45 | ✅ Ready |

**Cilium:** v1.15.0 — eBPF mode, kube-proxy replacement enabled
**Hubble:** Relay + UI enabled — live network flow observability active

### Hubble UI — 3/3 nodes, 20.6 flows/s

![Hubble UI](docs/screenshots/hubble-ui.png)

## Security status

### Falco — Runtime threat detection
- **Driver:** modern_ebpf (CO-RE, no kernel headers required)
- **Status:** ✅ Running on all 3 nodes (DaemonSet)
- **Output:** JSON via HTTP webhook → Argus agent
- **Test:** `cat /etc/shadow` in container → detected in <1ms, tagged MITRE T1555
- **Custom rules:** shell in prod, outbound connections, /etc writes, curl/wget, privilege escalation

**Why Falco for Argus:** Argus needs a low-level event stream it can reason over with an AI agent. Falco sits at the syscall layer — below the application, below the container runtime — so it catches things that application-level logging misses entirely: unexpected shell spawns, file reads on sensitive paths, outbound connections from workloads that should be silent. The structured JSON output feeds directly into the agent webhook, giving it a machine-readable event with MITRE ATT&CK tags already attached. No log scraping, no parsing — just a clean signal the agent can act on.

### Kyverno — Admission control
- **Status:** ✅ Running (v1.17.1)
- **Namespace:** kyverno
- **Mode:** Enforce (blocks non-compliant workloads at admission)
- **Policies:**
  - `disallow-root-containers` — rejects pods without runAsNonRoot=true
  - `require-resource-limits` — rejects pods missing CPU/memory limits
  - `approved-registries-only` — rejects images outside approved registries

### Cilium Network Policies — Zero-trust network segmentation
- **Status:** ✅ Applied
- **Model:** Default deny ingress, explicit allow
- **Rules:**
  - `prod` and `staging` namespaces: deny all ingress by default
  - `monitoring` namespace: allowed to scrape metrics from prod/staging
  - `argus-system` namespace: allowed to reach prod/staging for agent remediation
  - Cross-namespace traffic: blocked and visible as dropped flows in Hubble UI

## Agent status

### Module 4 — AI Agent Engine
**Issue #13: Falco webhook receiver** ✅
- FastAPI endpoint `POST /falco/webhook` receiving Falco JSON alerts
- Pydantic validation — invalid payloads return 422
- Priority normalization (Critical/Warning/Error/Notice)
- Deduplication engine — same rule+pod+namespace suppressed for 5 minutes
- Background task processing — 202 returned immediately, Falco never blocks
- 18 unit tests covering validation, dedup, field mapping

**Issue #14: Context enricher** ✅
- Parallel queries to Kubernetes API, Loki, Hubble, and Kyverno with asyncio.gather
- 5-second timeout with graceful degradation — partial results returned on failure
- Pod metadata, recent logs, network flows, and policy violations collected per alert

**Issue #15: Claude reasoning layer** ✅
- Structured JSON decisions: severity, confidence, recommended action, blast radius
- Model routing — claude-opus-4-6 for Critical/Error, claude-sonnet-4-6 for others
- Prompt caching on system prompt reduces token cost by ~90% on repeat calls
- Retry with exponential backoff on rate limit and connection errors

**Issue #16: Action router** ✅
- LOG, NOTIFY, ISOLATE, KILL, and HUMAN_REQUIRED actions
- ISOLATE creates a CiliumNetworkPolicy deny-all for the offending pod
- KILL requires confidence >= 0.85, falls back to ISOLATE below threshold
- HUMAN_REQUIRED queues actions for manual approval via REST API
- All decisions shipped to Loki as structured audit log entries

**Issue #17: Containerize and deploy** ✅
- Multi-stage Docker build, non-root user, minimal runtime image
- Kubernetes manifests: Deployment, Service, RBAC, Secret template
- deploy.sh builds image locally, loads into all 3 k3s nodes via SSH, applies manifests
- Liveness and readiness probes on /health
- `make deploy-agent` target wired up

## Observability status

### Prometheus — Metrics collection
- **Status:** ✅ Running (kube-prometheus-stack)
- **Retention:** 7 days
- **Targets:** alertmanager, apiserver, coredns, node-exporter (3 nodes), kube-state-metrics, kubelet

### Grafana — Dashboards
- **Status:** ✅ Running
- **URL:** kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80
- **Login:** admin / argus-admin
- **Dashboards:** 25 default Kubernetes dashboards loaded

### Loki — Log aggregation
- **Status:** ✅ Running (loki-stack)
- **Retention:** 72 hours (disk-constrained on 20GiB VMs)
- **Promtail:** DaemonSet collecting logs from all pods on all 3 nodes
- **Falco pipeline:** JSON events parsed and labeled by rule, priority, hostname
- **Query:** `{app="falco"}` returns structured Falco alerts in Grafana Explore
- **Datasource:** http://loki.monitoring.svc.cluster.local:3100

### Custom dashboards — Argus security views
- **Argus / Security Overview** — live Falco event stream, critical alert count
- **Argus / Cluster Health** — node CPU/memory, pod restarts
- **Argus / Policy Violations** — Kyverno admission denials
- **Argus / Network Flows** — Cilium eBPF dropped flows, flow rate by verdict
- **Provisioning:** ConfigMap with grafana_dashboard=1 label — survives pod restarts

### Screenshots
![Argus Grafana dashboards](docs/screenshots/grafana-argus-dashboards.png)
![Security Overview — live Falco event stream](docs/screenshots/grafana-security-overview.png)
![Cluster Health dashboard](docs/screenshots/grafana-cluster-health.png)
![Prometheus targets — all scrape targets UP](docs/screenshots/prometheus-targets.png)
![Grafana dashboard library — 25 default K8s dashboards](docs/screenshots/grafana-dashboards.png)
![Grafana cluster overview — CPU and memory across all nodes](docs/screenshots/grafana-cluster-overview.png)
![Loki — Falco security events streaming in real time](docs/screenshots/loki-falco-logs.png)
*Critical Falco detections (T1620 fileless execution) ingested and queryable via LogQL*

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

## Author

Built by [Kaushikkumaran](https://github.com/CodeBuildder) — April 2026

Original architecture, AI agent design, and UI concept.
All design decisions documented in [docs/decisions/](docs/decisions/).

## Modules

| Module | Description | Status |
|---|---|---|
| 1 — Cluster Foundation | OrbStack VMs, k3s, Cilium, Hubble | ✅ Complete |
| 2 — Security Layers | Falco, Kyverno, CiliumNetworkPolicy | ✅ Complete |
| 3 — Observability Stack | Prometheus, Grafana, Loki | ✅ Complete |
| 4 — AI Agent Engine | Falco webhook → context enrichment → Claude → action router | ✅ Complete |
| 5 — Command & Control UI | React dashboard, approval queue, agent chat | ⏳ Pending |

## How it works

[fill in after agent is built]

## Local setup

### Prerequisites
- macOS (Apple Silicon M-series)
- OrbStack installed (`brew install orbstack`)
- CLI tools: `brew install kubectl helm k3sup cilium-cli hubble k9s`

### Spin up the cluster
```bash
make cluster-up
```

This provisions 3 OrbStack VMs, installs k3s, deploys Cilium with eBPF
kube-proxy replacement, enables Hubble, and creates all namespaces.

### Verify
```bash
make cluster-status
cilium hubble ui
```

## Architecture decisions

See [docs/decisions/](docs/decisions/) for rationale behind every tool choice.
