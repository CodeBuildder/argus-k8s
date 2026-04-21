# Argus — Architecture

## Cluster topology

| Node | Role | IP | OS |
|---|---|---|---|
| k3s-master | Control plane | 192.168.139.42 | Ubuntu 22.04 ARM64 |
| k3s-worker1 | Worker | 192.168.139.77 | Ubuntu 22.04 ARM64 |
| k3s-worker2 | Worker | 192.168.139.45 | Ubuntu 22.04 ARM64 |

All nodes communicate over OrbStack's internal virtual bridge (`orb0`). Node IPs are stable across Mac network changes — the cluster survives WiFi switches and sleeps. SSH access uses `~/.orbstack/ssh/id_ed25519`.

---

## Detection pipeline

Threats flow through five layers, each catching a different category of activity:

```
Syscall event (kernel)
        |
        v
  [ Falco — Layer 1 ]        ← Runtime detection. Watches every syscall on every
        |                       container. Fires on shell spawns, sensitive file reads,
        |                       unexpected outbound connections, privilege escalation.
        |
  [ eBPF — Layer 2 ]         ← Kernel instrumentation. Raw syscall patterns before
        |                       userspace processes them. Catches fileless execution,
        |                       memory-based attacks, kernel module loads.
        |
  [ Kyverno — Layer 3 ]      ← Admission control. Intercepts workloads before they
        |                       run. Blocks root containers, missing resource limits,
        |                       images from unapproved registries. Pod never starts.
        |
  [ Cilium — Layer 4 ]       ← Network layer. Monitors L3/L4/L7 flows via eBPF.
        |                       Detects C2 callbacks, lateral movement, DNS tunneling,
        |                       cross-namespace policy violations.
        |
  [ Argus Agent — Layer 5 ]  ← Receives alerts from Falco webhook, enriches with
                                cluster context, scores severity and confidence,
                                routes to the appropriate response action.
```

---

## Agent processing flow

When a Falco alert arrives at the agent:

1. **Webhook receiver** (`webhook.py`) — validates the JSON payload, normalizes priority levels, checks deduplication cache (same rule+pod+namespace suppressed for 5 minutes), returns 202 immediately so Falco never blocks
2. **Context enricher** (`enricher.py`) — queries in parallel: pod metadata from kubectl, recent logs from Loki, network flows from Hubble, active policy violations from Kyverno. 5-second hard timeout with graceful degradation
3. **Reasoning layer** (`reasoning.py`) — takes the alert + enriched context, produces a structured decision: severity, confidence score (0–1), recommended action, blast radius assessment, false positive likelihood
4. **Action router** (`actions.py`) — executes based on the decision:
   - `LOG` — write to audit trail
   - `NOTIFY` — Slack or PagerDuty webhook
   - `ISOLATE` — apply CiliumNetworkPolicy deny-all to the offending pod (pod stays running, network cut)
   - `KILL` — delete the pod (requires confidence >= 0.85)
   - `HUMAN_REQUIRED` — push to the approval queue in the console, wait for a human decision
5. **Audit logger** (`audit.py`) — every decision written to Loki with full context: original alert, enrichment data, decision, action taken, duration

---

## Network segmentation

```
Namespace: production
  - Deny all ingress by default (CiliumNetworkPolicy)
  - Allow: monitoring namespace → scrape metrics
  - Allow: argus-system → agent remediation traffic

Namespace: staging
  - Deny all ingress by default
  - Allow: monitoring namespace → scrape metrics

Namespace: monitoring
  - Allow egress to production and staging for metric scraping

Namespace: argus-system
  - Allow egress to production, staging, monitoring, kube-system
  - Allow egress to external reasoning API
```

Cross-namespace traffic that does not match an explicit allow rule is dropped and visible as a denied flow in Hubble.

---

## Console layout

The web console runs as a React app that talks to the agent's REST API:

```
/               → Command Center    — live KPIs, detection pipeline, node health
/threats        → Threat Feed       — real-time incident list with detail panel
/approvals      → Approval Queue    — pending human review items
/chains         → Attack Chains     — correlated multi-stage attack sequences
/cluster        → Cluster Map       — node/pod topology with threat overlay
/posture        → Security Posture  — incident summary, CVE exposure, compliance
/hunt           → Threat Hunting    — ad-hoc queries and investigation tools
/infra          → Infrastructure    — node metrics and resource utilization
/chat           → Agent Chat        — conversational interface to cluster state
```

All pages pull from the agent's REST endpoints and auto-refresh on a polling interval. The console does not require a WebSocket connection — all real-time behavior is achieved via periodic fetches.
