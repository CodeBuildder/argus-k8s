# Argus Architecture

## Overview

[Architecture diagram will be added after Module 1 is complete]

## Component interaction

```
Falco (runtime events)
    │
    ▼ JSON webhook
agent/src/webhook.py
    │
    ▼ raw alert
agent/src/enricher.py  ──── kubectl (pod/deployment/namespace info)
    │                  ──── Loki API (recent pod logs)
    │                  ──── Hubble API (network flows)
    │                  ──── Kyverno (active policy violations)
    ▼ enriched context
agent/src/reasoning.py ──── Claude API
    │
    ▼ structured decision
agent/src/actions.py
    │
    ├── LOG       → audit.py → Loki
    ├── NOTIFY    → Slack/Discord webhook
    ├── ISOLATE   → CiliumNetworkPolicy apply
    ├── KILL      → kubectl delete pod
    └── HUMAN_REQUIRED → UI approval queue
```

## Network topology

```
OrbStack host (macOS M3)
├── k3s-master  (192.168.64.x)  — control plane
├── k3s-worker1 (192.168.64.x)  — workloads
└── k3s-worker2 (192.168.64.x)  — workloads
```

[IP addresses will be filled in after Module 1]
