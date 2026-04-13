# Argus — Repo Bootstrap Instructions

You are setting up the **Argus** project: an autonomous Kubernetes security platform combining
eBPF-native threat detection, policy enforcement, and an AI reasoning agent for real-time
threat response and remediation.

Your job is to scaffold the entire repo structure with all directories, placeholder files,
a proper README, ADRs, and a Makefile. Do not install anything. Do not run any cluster
commands. This is repo structure and documentation only.

---

## 1. Create the full directory structure

```
argus/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── .gitignore
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── policy-test.yml
├── docs/
│   ├── architecture.md
│   └── decisions/
│       ├── 001-orbstack-over-multipass.md
│       ├── 002-cilium-over-calico.md
│       ├── 003-falco-for-runtime-security.md
│       ├── 004-kyverno-for-admission-control.md
│       └── 005-loki-over-elk.md
├── cluster/
│   ├── bootstrap/
│   │   ├── 01-provision-vms.sh          # placeholder, with usage comment
│   │   ├── 02-install-master.sh         # placeholder
│   │   └── 03-join-workers.sh           # placeholder
│   └── namespaces/
│       └── namespaces.yaml              # prod, staging, monitoring namespaces + labels
├── security/
│   ├── falco/
│   │   ├── values.yaml                  # placeholder helm values
│   │   └── custom-rules.yaml            # placeholder custom rules file
│   ├── kyverno/
│   │   ├── no-root-containers.yaml      # placeholder policy
│   │   ├── require-resource-limits.yaml # placeholder policy
│   │   └── approved-registries.yaml     # placeholder policy
│   └── cilium/
│       ├── deny-cross-namespace.yaml    # placeholder CiliumNetworkPolicy
│       └── default-deny-ingress.yaml    # placeholder
├── observability/
│   ├── prometheus/
│   │   └── values.yaml                  # placeholder
│   ├── grafana/
│   │   └── dashboards/
│   │       └── README.md                # note: dashboard JSONs go here
│   └── loki/
│       └── values.yaml                  # placeholder
├── agent/
│   ├── src/
│   │   ├── main.py                      # placeholder FastAPI entrypoint
│   │   ├── webhook.py                   # placeholder Falco webhook receiver
│   │   ├── enricher.py                  # placeholder context enricher
│   │   ├── reasoning.py                 # placeholder Claude API agent
│   │   ├── actions.py                   # placeholder action router
│   │   └── audit.py                     # placeholder audit logger
│   ├── tests/
│   │   └── .gitkeep
│   ├── Dockerfile                       # placeholder
│   └── requirements.txt                 # placeholder with expected deps listed as comments
└── ui/
    ├── src/
    │   └── .gitkeep
    ├── public/
    │   └── .gitkeep
    └── Dockerfile                       # placeholder
```

---

## 2. File contents to generate

### `README.md`

Write a professional README with these exact sections:

```
# Argus

> Autonomous Kubernetes security platform combining eBPF-native threat detection,
> policy enforcement, and an AI reasoning agent for real-time threat response and remediation.

## Architecture diagram placeholder
[diagram will be added after Module 1 is complete]

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
| 1 — Cluster Foundation | OrbStack VMs, k3s, Cilium, Hubble | 🔨 In Progress |
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
```

---

### `docs/decisions/001-orbstack-over-multipass.md`

```markdown
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
```

---

### `docs/decisions/002-cilium-over-calico.md`

```markdown
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
```

---

### `docs/decisions/003-falco-for-runtime-security.md`

```markdown
# ADR 003: Falco for runtime threat detection

## Status
Accepted

## Context
Need a runtime security tool that detects suspicious behavior inside running containers
at the syscall level — not just static image scanning. Output must be machine-readable
for the AI agent to consume.

## Decision
Use Falco deployed via Helm in eBPF mode with JSON webhook output.

## Rationale
- CNCF graduated project — industry standard for K8s runtime security
- Detects at syscall level: shell spawns, sensitive file reads, privilege escalation,
  network connections from unexpected processes
- Ships with a large default ruleset covering MITRE ATT&CK techniques
- Emits structured JSON events — directly consumable by the agent webhook receiver
- eBPF driver mode works on ARM64 without kernel module compilation
- Active ecosystem: rules contributed by the community, Falco plugins for cloud audit logs

## Rejected Alternatives
- Tetragon: Newer, eBPF-native, can enforce (kill processes) not just detect.
  Smaller rule ecosystem, less documentation. Considered as a stretch goal add-on.
- Tracee (Aqua): Good tool, smaller community, fewer resources when debugging
- KubeArmor: LSM-based enforcement, interesting but niche — limited docs for ARM64

## Consequences
Falco emits high volume of events — agent must implement alert deduplication and
suppression logic to avoid Claude API cost explosion.
Custom rules should be maintained in security/falco/custom-rules.yaml, not modified
in the default ruleset.
```

---

### `docs/decisions/004-kyverno-for-admission-control.md`

```markdown
# ADR 004: Kyverno for admission control

## Status
Accepted

## Context
Need policy-as-code admission control to reject non-compliant workloads before
they run. Policies must be testable in CI before cluster apply.

## Decision
Use Kyverno for admission control policies.

## Rationale
- K8s-native YAML syntax — policies look like K8s resources, no new language to learn
- Supports validate, mutate, and generate policy types
- kyverno CLI enables policy unit testing in GitHub Actions without a live cluster
- CNCF incubating project, active development
- Faster to write correct policies than OPA/Rego for this use case

## Rejected Alternatives
- OPA/Gatekeeper: Rego is a purpose-built policy language, more widely referenced
  on job descriptions, but significantly higher learning curve. Considered for future
  addition as a stretch goal to demonstrate Rego knowledge.
- Pod Security Admission (built-in): Too coarse-grained, only three levels
  (privileged/baseline/restricted), no custom rules

## Consequences
Policies stored in security/kyverno/ and tested via kyverno CLI in CI pipeline.
Kyverno webhook must be running before any workload deployments or all deployments
will be blocked.
```

---

### `docs/decisions/005-loki-over-elk.md`

```markdown
# ADR 005: Loki over ELK stack for log aggregation

## Status
Accepted

## Context
Need log aggregation for pod logs and Falco alert stream. Must run alongside
Prometheus, Grafana, Cilium, Falco, and the AI agent on a 3-node laptop cluster
without exhausting available RAM.

## Decision
Use Grafana Loki with Promtail for log collection.

## Rationale
- Loki indexes log metadata (labels) not log content — dramatically lower memory
  footprint than Elasticsearch which indexes full text
- Native Grafana integration — single pane for metrics (Prometheus) and logs (Loki)
- Promtail DaemonSet automatically collects all pod logs with K8s metadata labels
- Falco JSON events can be shipped directly to Loki via Promtail pipeline
- LGTM stack (Loki, Grafana, Tempo, Mimir) is a coherent, modern observability story

## Rejected Alternatives
- ELK (Elasticsearch + Logstash + Kibana): Elasticsearch alone requires 2-4GB RAM
  minimum. Running ELK alongside the rest of this stack on a laptop cluster would
  cause memory pressure and pod evictions. Operationally complex.
- Fluentd + Elasticsearch: Same memory problem, adds Fluentd complexity

## Consequences
Loki is not a full-text search engine — complex log queries require LogQL knowledge.
Log retention is configured by chunk size, not time — must tune carefully for disk usage
on 20GiB VM disks.
```

---

### `cluster/namespaces/namespaces.yaml`

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  labels:
    environment: prod
    app.kubernetes.io/managed-by: argus
---
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    environment: staging
    app.kubernetes.io/managed-by: argus
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    environment: monitoring
    app.kubernetes.io/managed-by: argus
---
apiVersion: v1
kind: Namespace
metadata:
  name: argus-system
  labels:
    environment: system
    app.kubernetes.io/managed-by: argus
```

---

### `Makefile`

```makefile
.PHONY: help cluster-up cluster-down deploy-cilium deploy-falco deploy-kyverno \
        deploy-observability deploy-agent deploy-ui status clean

help:
	@echo "Argus — available commands:"
	@echo ""
	@echo "  Cluster"
	@echo "    make cluster-up          Provision OrbStack VMs and bootstrap k3s"
	@echo "    make cluster-down        Stop all OrbStack VMs"
	@echo "    make cluster-status      Show node and pod status"
	@echo ""
	@echo "  Security"
	@echo "    make deploy-cilium       Install Cilium CNI + enable Hubble"
	@echo "    make deploy-falco        Install Falco via Helm"
	@echo "    make deploy-kyverno      Install Kyverno + apply policies"
	@echo ""
	@echo "  Observability"
	@echo "    make deploy-observability  Install Prometheus + Grafana + Loki"
	@echo ""
	@echo "  Application"
	@echo "    make deploy-agent        Build and deploy AI agent"
	@echo "    make deploy-ui           Build and deploy React UI"
	@echo ""
	@echo "  Utilities"
	@echo "    make hubble-ui           Open Hubble network flow UI"
	@echo "    make grafana-ui          Port-forward Grafana to localhost:3000"
	@echo "    make k9s                 Open k9s cluster terminal UI"
	@echo "    make clean               Destroy VMs and reset kubeconfig"

cluster-up:
	@echo "TODO: implement in cluster/bootstrap/"

cluster-down:
	orb stop k3s-master k3s-worker1 k3s-worker2

cluster-status:
	kubectl get nodes -o wide
	kubectl get pods -A

deploy-cilium:
	@echo "TODO: implement after cluster-up is working"

deploy-falco:
	@echo "TODO: implement after Cilium is running"

deploy-kyverno:
	@echo "TODO: implement after Falco is running"

deploy-observability:
	@echo "TODO: implement after security layer is deployed"

deploy-agent:
	@echo "TODO: implement after observability is running"

deploy-ui:
	@echo "TODO: implement after agent is running"

hubble-ui:
	cilium hubble ui

grafana-ui:
	kubectl port-forward -n monitoring svc/grafana 3000:80

k9s:
	k9s

clean:
	orb delete k3s-master k3s-worker1 k3s-worker2 || true
	rm -f ~/.kube/config
```

---

### `.gitignore`

```
# Secrets — never commit these
*.env
.env*
secrets/
kubeconfig
*.kubeconfig
**/secret.yaml
**/secrets.yaml

# Python
__pycache__/
*.py[cod]
.venv/
venv/
*.egg-info/
dist/
.pytest_cache/

# Node
node_modules/
.next/
build/
dist/

# OS
.DS_Store
*.swp

# Terraform (if added later)
*.tfstate
*.tfstate.backup
.terraform/

# IDE
.vscode/
.idea/
```

---

### `agent/requirements.txt`

```
# Web framework
fastapi
uvicorn[standard]

# Anthropic SDK — AI agent reasoning
anthropic

# Kubernetes client — context enrichment (kubectl wrapper)
kubernetes

# HTTP client — Loki and Hubble API queries
httpx

# Data validation
pydantic

# Async support
asyncio

# Logging
structlog
```

---

### `agent/src/main.py`

```python
"""
Argus AI Agent — entrypoint

Receives Falco webhook alerts, enriches with cluster context,
reasons via Claude API, and routes remediation actions.
"""

# TODO: implement in Module 4
# Expected flow:
#   POST /falco/webhook  → webhook.py → enricher.py → reasoning.py → actions.py → audit.py

from fastapi import FastAPI

app = FastAPI(title="Argus Agent", version="0.1.0")


@app.get("/health")
async def health():
    return {"status": "ok", "module": "agent", "version": "0.1.0"}


@app.post("/falco/webhook")
async def falco_webhook(payload: dict):
    # TODO: implement in Module 4
    return {"status": "received", "note": "agent not yet implemented"}
```

---

### `agent/src/enricher.py`

```python
"""
Context enricher — given a Falco alert, queries the cluster for surrounding context.

Queries performed:
  - kubectl: pod info, deployment, namespace, image, recent restarts
  - Loki: pod logs from last N minutes
  - Hubble: network flows from pod in last N minutes
  - Kyverno: active policy violations for this pod

Output is a structured dict passed to the reasoning layer.
"""

# TODO: implement in Module 4
```

---

### `agent/src/reasoning.py`

```python
"""
AI reasoning layer — sends enriched context to Claude API and returns a structured decision.

Decision schema:
  {
    "severity": "LOW | MED | HIGH | CRITICAL",
    "confidence": 0.0 - 1.0,
    "assessment": "string — agent's reasoning",
    "likely_false_positive": bool,
    "recommended_action": "LOG | NOTIFY | ISOLATE | KILL | HUMAN_REQUIRED",
    "blast_radius": "string — what could be affected",
    "suppress_minutes": int | null
  }
"""

# TODO: implement in Module 4
```

---

### `agent/src/actions.py`

```python
"""
Action router — executes remediation based on agent decision.

Actions available:
  LOG       → write to audit log, update Grafana dashboard
  NOTIFY    → send to Slack/Discord webhook
  ISOLATE   → apply CiliumNetworkPolicy to cut pod network access
  KILL      → kubectl delete pod (requires HIGH confidence)
  HUMAN_REQUIRED → push to UI approval queue, block until approved/rejected
"""

# TODO: implement in Module 4
```

---

### `agent/src/audit.py`

```python
"""
Audit logger — every agent decision is logged to Loki with full context.

Log entry schema:
  {
    "timestamp": "ISO8601",
    "alert": <original Falco event>,
    "context": <enriched cluster context>,
    "decision": <agent decision>,
    "action_taken": "string",
    "action_approved_by": "human | agent | suppressed",
    "duration_ms": int
  }
"""

# TODO: implement in Module 4
```

---

### `CONTRIBUTING.md`

```markdown
# Contributing to Argus

## Branch naming
- `feat/module-1-cluster` — new features by module
- `fix/falco-arm64-ebpf` — bug fixes
- `docs/adr-cilium` — documentation

## Commit style
Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `chore:` tooling, deps
- `test:` tests only

## Before pushing
- All Kyverno policies must pass `kyverno test` locally
- Python agent: `ruff check` and `pytest` must pass
- No secrets, kubeconfigs, or .env files committed

## Module order
Build in module order. Do not start Module N+1 until Module N is working end-to-end.
```

---

## 3. After creating all files

Run these commands:

```bash
cd argus
git init
git add .
git commit -m "chore: scaffold project structure and ADRs"
```

Then create the GitHub repo named `argus` and push:

```bash
gh repo create argus --public --description "Autonomous Kubernetes security platform combining eBPF-native threat detection, policy enforcement, and an AI reasoning agent for real-time threat response and remediation." --push --source=.
```

If `gh` CLI is not installed: `brew install gh` then `gh auth login` first.

Add these topics on GitHub after push:
`kubernetes`, `security`, `ebpf`, `falco`, `cilium`, `ai-agents`, `observability`, `devsecops`, `k8s`, `homelab`

---

## 4. What you are NOT doing yet

- No VM provisioning
- No k3s installation
- No Helm installs
- No kubectl commands against a cluster

This task is repo scaffolding only. Everything else comes in subsequent modules.
```