# Argus — Roadmap

## Module 1 — Cluster Foundation ✅
OrbStack VMs, k3s, Cilium eBPF, Hubble, namespaces

## Module 2 — Security Layers ✅
Falco runtime detection, Kyverno admission control, CiliumNetworkPolicies

## Module 3 — Observability Stack 🔨
Prometheus, Grafana, Loki, custom security dashboards

## Module 4 — AI Agent Engine ⏳
### Core (existing issues)
- Falco webhook receiver
- Context enricher (kubectl + Loki + Hubble)
- Claude API reasoning layer
- Action router (isolate/kill/notify/human-approval)
- Audit logger

### Extended features (new)
- Attack chain detection — correlate sequences of events from same pod
- False positive learning — suppress recurring known-safe patterns
- Image reputation scoring — Trivy CVE scan integrated into threat score
- Composite severity scoring — namespace + blast radius + repeat + image age
- Runbook automation — auto-generate GitHub incident issues

## Module 5 — Command & Control UI ⏳
### Views
- Command center — live KPIs, threat summary, cluster health at a glance
- Threat feed — real-time AI-reasoned incident cards with action buttons
- Cluster map — visual node/pod topology with threat status overlay
- Security posture — MITRE ATT&CK coverage, CIS K8s Benchmark, SOC2 mapping
- Incident history — full audit trail, exportable as PDF
- Agent chat — natural language queries against cluster security state

### Tech stack
- React + TypeScript + Tailwind + shadcn/ui
- Recharts for metrics
- WebSocket for real-time feed
- FastAPI backend (shared with agent)

## Module 6 — Chaos Testing ⏳
- Chaos Mesh deployment
- Attack simulation scenarios
- End-to-end detection → response demo recording

## LinkedIn post ⏳
- Demo GIF: threat → agent reasoning → pod isolation → incident card
- Architecture diagram
- One-post strategy targeting VPs and hiring managers
