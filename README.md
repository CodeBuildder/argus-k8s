<!--
Argus — Kubernetes Security Platform
Copyright (c) 2026 Kaushikkumaran
Original work — see NOTICE for details
Commit history: https://github.com/CodeBuildder/argus-k8s/commits/main
-->

# Argus

> A Kubernetes security platform combining eBPF-native threat detection,
> policy enforcement, and an automated reasoning agent for real-time threat response.

## Cluster status

### Network flow observability
![Hubble UI — live eBPF network flows](docs/screenshots/hubble-ui-flows.png)
*Live TCP flows between Cilium components captured at the kernel level via eBPF*

| Node | Role | IP | Status |
|---|---|---|---|
| k3s-master | Control plane | 192.168.139.42 | Active |
| k3s-worker1 | Worker | 192.168.139.77 | Active |
| k3s-worker2 | Worker | 192.168.139.45 | Active |

**Cilium:** v1.15.0 — eBPF mode, kube-proxy replacement enabled
**Hubble:** Relay + UI enabled — live network flow observability active

### Hubble UI — 3/3 nodes, 20.6 flows/s

![Hubble UI](docs/screenshots/hubble-ui.png)

## Security status

### Falco — Runtime threat detection
- **Driver:** modern_ebpf (CO-RE, no kernel headers required)
- **Status:** Running on all 3 nodes (DaemonSet)
- **Output:** JSON via HTTP webhook → Argus agent
- **Test:** `cat /etc/shadow` in container → detected in <1ms, tagged MITRE T1555
- **Custom rules:** shell in prod, outbound connections, /etc writes, curl/wget, privilege escalation

Falco sits at the syscall layer — below the application, below the container runtime — so it catches things that application-level logging misses: unexpected shell spawns, file reads on sensitive paths, and outbound connections from workloads that should be silent. The structured JSON output feeds directly into the agent webhook, giving it a machine-readable event with MITRE ATT&CK tags already attached. No log scraping, no parsing — a clean, structured signal the agent can act on immediately.

### Kyverno — Admission control
- **Status:** Running (v1.17.1)
- **Namespace:** kyverno
- **Mode:** Enforce — blocks non-compliant workloads at admission time, before they run
- **Policies:**
  - `disallow-root-containers` — rejects pods without `runAsNonRoot: true`
  - `require-resource-limits` — rejects pods missing CPU/memory limits
  - `approved-registries-only` — rejects images from outside approved registries

### Cilium Network Policies — Zero-trust network segmentation
- **Status:** Applied
- **Model:** Default deny ingress, explicit allow per namespace
- **Rules:**
  - `prod` and `staging` namespaces: deny all ingress by default
  - `monitoring` namespace: allowed to scrape metrics from prod/staging
  - `argus-system` namespace: allowed to reach prod/staging for agent remediation
  - Cross-namespace traffic: blocked and visible as dropped flows in Hubble

## Agent status

### Module 4 — Detection Agent

**Issue #13: Falco webhook receiver**
- FastAPI endpoint `POST /falco/webhook` receiving Falco JSON alerts
- Pydantic validation — invalid payloads return 422
- Priority normalization (Critical/Warning/Error/Notice)
- Deduplication engine — same rule+pod+namespace suppressed for 5 minutes
- Background task processing — 202 returned immediately, Falco never blocks
- 18 unit tests covering validation, dedup, field mapping

**Issue #14: Context enricher**
- Parallel queries to Kubernetes API, Loki, Hubble, and Kyverno with asyncio.gather
- 5-second timeout with graceful degradation — partial results returned on failure
- Pod metadata, recent logs, network flows, and policy violations collected per alert

**Issue #15: Reasoning layer**
- Structured JSON decisions: severity, confidence, recommended action, blast radius
- Model routing based on alert severity
- Prompt caching on system prompt reduces token cost on repeat calls
- Retry with exponential backoff on rate limit and connection errors

**Issue #16: Action router**
- LOG, NOTIFY, ISOLATE, KILL, and HUMAN_REQUIRED actions
- ISOLATE creates a CiliumNetworkPolicy deny-all for the offending pod
- KILL requires confidence >= 0.85, falls back to ISOLATE below threshold
- HUMAN_REQUIRED queues actions for manual approval via REST API
- All decisions shipped to Loki as structured audit log entries

**Issue #17: Containerize and deploy**
- Multi-stage Docker build, non-root user, minimal runtime image
- Kubernetes manifests: Deployment, Service, RBAC, Secret template
- deploy.sh builds image locally, loads into all 3 k3s nodes via SSH, applies manifests
- Liveness and readiness probes on /health
- `make deploy-agent` target wired up

**Network policies configured**
- argus-agent allowed egress to external reasoning API
- argus-agent allowed egress to monitoring/kube-system/prod/staging namespaces
- Loki, Hubble, K8s API all reachable from agent pod

## Observability status

### Prometheus — Metrics collection
- **Status:** Running (kube-prometheus-stack)
- **Retention:** 7 days
- **Targets:** alertmanager, apiserver, coredns, node-exporter (3 nodes), kube-state-metrics, kubelet

### Grafana — Dashboards
- **Status:** Running
- **URL:** `kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80`
- **Login:** admin / argus-admin
- **Dashboards:** 25 default Kubernetes dashboards loaded

### Loki — Log aggregation
- **Status:** Running (loki-stack)
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

## How it works

Every container running on the cluster is monitored at the syscall level by Falco. When Falco detects suspicious behavior — a shell spawning inside a container, a read of `/etc/shadow`, an unexpected outbound connection — it sends a structured JSON alert to the Argus agent via webhook.

The agent receives the alert and immediately queries the cluster for surrounding context: what is this pod, what namespace is it in, what does its recent log output look like, are there active network flows to unusual destinations, has Kyverno flagged this workload before? These queries run in parallel and complete in under 5 seconds.

With that context assembled, the agent scores the incident — assigning a severity level, a confidence score, and a recommended action. Actions fall into five categories:

- **LOG** — record the event, no intervention
- **NOTIFY** — send an alert to Slack or PagerDuty
- **ISOLATE** — cut the pod's network access via a CiliumNetworkPolicy deny-all rule, keeping the workload running for forensics
- **KILL** — delete the pod immediately (only at confidence >= 0.85)
- **HUMAN_REQUIRED** — queue the proposed action in the approval UI for a human to review

Everything is written to Loki as a structured audit trail and appears in real time in the Argus console: a threat feed, a detection pipeline visualization, a cluster map showing node and pod status, and a human approval queue for anything the agent is not confident enough to handle autonomously.

Kyverno catches a separate category of threat — workloads that violate security policy at deploy time. A pod attempting to run as root, use a hostPath mount, or pull from an unapproved registry is rejected before it ever runs. These admission events are surfaced in the console alongside runtime threats, clearly marked as blocked at admission.

## Stack

| Layer | Tool | Purpose |
|---|---|---|
| Local cluster | k3s on OrbStack VMs | Lightweight, ARM-native, production-like 3-node topology |
| CNI | Cilium + Hubble | eBPF-native networking, kube-proxy replacement, L7 flow observability |
| Runtime security | Falco | Syscall-level threat detection, structured JSON alerts, MITRE tagging |
| Admission control | Kyverno | Policy-as-code, rejects non-compliant workloads before they run |
| mTLS | Linkerd | Automatic zero-trust service encryption, lightweight vs Istio |
| Metrics | Prometheus | Standard scraping, alerting, retention |
| Logs | Loki + Promtail | Lightweight log aggregation, native Grafana integration |
| Dashboards | Grafana | Unified view — metrics, logs, security events |
| Detection agent | Python + FastAPI | Enriches alerts with cluster context, scores severity, routes remediation |
| Console | React + Tailwind | Real-time incident feed, approval queue, cluster map, agent chat |

## Modules

| Module | Description | Status |
|---|---|---|
| 1 — Cluster Foundation | OrbStack VMs, k3s, Cilium, Hubble | Complete |
| 2 — Security Layers | Falco, Kyverno, CiliumNetworkPolicy | Complete |
| 3 — Observability Stack | Prometheus, Grafana, Loki | Complete |
| 4 — Detection Agent | Falco webhook, context enrichment, reasoning layer, action router | Complete |
| 5 — Command & Control UI | React console, threat feed, approval queue, cluster map | In Progress |

## Local setup

### Prerequisites
- macOS (Apple Silicon M-series)
- OrbStack installed (`brew install orbstack`)
- CLI tools: `brew install kubectl helm k3sup cilium-cli hubble k9s`

### Spin up the cluster
```bash
make cluster-up
```

This provisions 3 OrbStack VMs, installs k3s, deploys Cilium with eBPF kube-proxy replacement, enables Hubble, and creates all namespaces.

### Verify the cluster
```bash
make cluster-status
cilium hubble ui
```

### Run locally (development)

**Backend agent:**
```bash
cd agent/src
source ../.env
uvicorn main:app --reload --port 8000
```

**Console UI:**
```bash
cd ui
npm install
npm run dev
```

The UI runs at `http://localhost:5173` and proxies `/api/*` to the agent at port 8000.

To populate the console with sample incidents:
```bash
curl -X POST http://localhost:8000/simulate-threats \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'
```

## Architecture decisions

See [docs/decisions/](docs/decisions/) for the reasoning behind every tool choice.

## Author

Built by [Kaushikkumaran](https://github.com/CodeBuildder) — April 2026

Original architecture, agent design, and console concept.
All design decisions documented in [docs/decisions/](docs/decisions/).
