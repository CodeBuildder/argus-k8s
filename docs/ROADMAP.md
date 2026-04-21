# Argus — Roadmap

## Module 1 — Cluster Foundation
Complete

OrbStack VMs, k3s, Cilium eBPF networking, Hubble flow observability, namespace setup.

---

## Module 2 — Security Layers
Complete

Falco runtime detection via eBPF, Kyverno admission control with three enforced policies, CiliumNetworkPolicies for zero-trust namespace segmentation.

---

## Module 3 — Observability Stack
Complete

Prometheus metrics collection, Grafana dashboards (25 default K8s dashboards + 4 custom Argus security views), Loki log aggregation with Promtail DaemonSet, Falco JSON pipeline into Loki.

---

## Module 4 — Detection Agent
Complete

Falco webhook receiver, context enricher (kubectl + Loki + Hubble + Kyverno), reasoning layer with structured decision output, action router (LOG / NOTIFY / ISOLATE / KILL / HUMAN_REQUIRED), audit logger, containerized deployment with RBAC.

---

## Module 5 — Command & Control UI
In Progress

### Pages
- Command center — live KPIs, detection pipeline flow, cluster node health
- Threat feed — real-time incident cards with detail panel, recommended actions, inline chat
- Attack chains — correlated multi-stage attack paths
- Cluster map — visual node/pod topology with threat status overlay
- Security posture — incident summary, secret scanning, CVE exposure, compliance signals
- Approval queue — human review workflow for low-confidence automated actions
- Agent chat — conversational queries about current cluster security state
- Infrastructure observability — node metrics and resource usage

### Tech stack
- React + TypeScript + Tailwind
- Recharts for metrics visualization
- FastAPI backend shared with the detection agent

---

## Module 6 — Runtime eBPF and Kernel Enforcement
Planned

- Deeper kernel-level instrumentation for syscall patterns
- Process lineage tracking across container restarts
- Memory-based threat detection (fileless execution patterns)

---

## Module 7 — Correlation and Learning
Planned

- Attack chain detection — correlate sequences of events from the same pod or namespace
- Suppression learning — recognize recurring false positives and reduce noise automatically
- Image reputation scoring — Trivy CVE scan integrated into threat confidence score
- Composite severity scoring — combines namespace risk, blast radius, recurrence, and image age

---

## Module 8 — Supply Chain and Identity
Planned

- SPIFFE/SPIRE workload identity
- Image signing verification at admission
- SBOM generation and dependency tracking

---

## Module 9 — Advanced Visualizations
Planned

- Behavioral baseline dashboards — deviation from normal traffic patterns
- Attack chain timeline view — visual sequence of correlated events
- Expanded cluster topology map with real-time flow overlays
