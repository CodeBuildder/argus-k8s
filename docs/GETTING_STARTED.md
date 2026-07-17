# Getting Started

This guide provides one path from a fresh checkout to a populated Argus console. Start
with local synthetic mode. Use full-cluster mode only when you specifically need real
Falco, Cilium, or Kyverno evidence.

## Choose a mode

| Mode | What it proves | Requires Kubernetes? |
|---|---|---:|
| Local synthetic | API, console, approvals, attack chains, and incident workflows | No |
| Full cluster | Real syscall, network, and admission-control detections | Yes |

## Local synthetic mode

### Prerequisites

- Python 3.11 or newer
- Node.js 18 or newer
- npm
- curl

No API key, OrbStack VM, Kubernetes cluster, Falco, Cilium, or Kyverno installation is
required.

### 1. Install dependencies

From the repository root:

```bash
make setup-local
```

This creates `.venv`, installs the agent requirements, and installs the locked UI
dependencies with `npm ci`.

### 2. Launch the populated demo

```bash
make demo-local
```

The command performs the complete startup sequence:

1. Verify local dependencies.
2. Confirm ports 8000 and 5173 are available.
3. Start the FastAPI agent.
4. Start the Vite console.
5. Wait for `/health` to succeed.
6. Generate ten mixed incidents.
7. Print the console and API URLs.

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Press `Ctrl-C` in the terminal to
stop both services.

### 3. Generate another batch

While `make demo-local` is running, use a second terminal:

```bash
make simulate-threats THREAT_COUNT=10 THREAT_SCENARIO=mixed
```

Supported scenarios:

| Scenario | Result |
|---|---|
| `mixed` | Random Falco, Kyverno, Cilium, and kernel-style incidents |
| `human_approval` | Incidents routed into the approval queue |
| `attack_chain` | Ordered incidents designed to form a correlated chain |

Replay a known incident selection:

```bash
make simulate-threats \
  THREAT_COUNT=10 \
  THREAT_SCENARIO=attack_chain \
  THREAT_SEED=20260717
```

The API returns the effective seed for every unseeded run. Preserve it when you need an
identical selection later.

### Run services separately

Use this only when developing one service:

```bash
make dev-agent
```

In another terminal:

```bash
make dev-ui
```

The UI proxies `/api/*` to the agent at `http://127.0.0.1:8000`.

### Local-mode limitations

- Incidents are stored in memory and disappear when the backend stops.
- Kubernetes telemetry is unavailable, so cluster-derived panels may be empty or degraded.
- Generated incidents exercise application workflows; they are not real Falco detections.
- Automated Kubernetes remediation is not executed without a cluster.

## Full-cluster mode

Full-cluster mode provisions three k3s nodes on OrbStack and deploys Cilium, Falco,
Kyverno, Prometheus, Grafana, Loki, and Argus. Follow [setup.md](../setup.md) for the
complete prerequisites and deployment sequence.

After the stack is healthy, create real policy-compliant workloads that trigger runtime
rules:

```bash
bash cluster/test-diverse-threats.sh
```

This script requires a working `kubectl` context. It creates real pods and runs continuously
until those pods are deleted.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect to localhost port 8000` | Agent is not running | Run `make dev-agent` or `make demo-local` |
| `Missing local environment` | Python dependencies are not installed | Run `make setup-local` |
| Port 8000 or 5173 is already in use | Another local service is running | Stop it, then rerun `make demo-local` |
| Console opens but has no incidents | The backend was restarted or never seeded | Run `make simulate-threats` |
| Cluster panels show no live data | Local synthetic mode has no Kubernetes telemetry | Use full-cluster mode for real telemetry |
| `kubectl` connection failure | Full-cluster mode is not configured | Complete [setup.md](../setup.md) |

## Verify the repository

```bash
make test
```

This runs the complete backend test suite and a production UI build.
