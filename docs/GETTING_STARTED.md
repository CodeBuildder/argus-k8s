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
required for the synthetic incident workflow. To use live AI reasoning, summaries,
threat hunting, forecasting, or chat, add this to the repository `.env`:

```bash
OPENAI_API_KEY=your_key_here
```

The key requires available OpenAI API quota. Never commit `.env`.

### 1. Launch the populated demo

From the repository root:

```bash
make demo-local
```

The command performs the complete startup sequence:

1. Install missing Python and UI dependencies.
2. Confirm ports 8000 and 5173 are available.
3. Start the FastAPI agent.
4. Start the Vite console.
5. Wait for `/health` to succeed.
6. Generate ten mixed incidents.
7. Print the console and API URLs.

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Press `Ctrl-C` in the terminal to
stop both services.

`make setup-local` remains available if you prefer to install dependencies separately.

### 2. Generate another batch

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

The guarded demo works with an existing Kubernetes cluster where Cilium, Falco,
Kyverno, and Argus are already installed. The repository also includes an OrbStack/k3s
development-cluster bootstrap; follow [setup.md](../setup.md) when you need that stack.
The Argus deployment consumes `OPENAI_API_KEY` from the `argus-secrets` Kubernetes
Secret and uses the OpenAI Responses API for its live reasoning workflows.

OrbStack's built-in `orbstack` Kubernetes context is separate from the three-node k3s
cluster. Select the Argus context before preflight:

```bash
kubectl config get-contexts
kubectl config use-context argus
kubectl get nodes -o wide
```

The expected nodes are `k3s-master`, `k3s-worker1`, and `k3s-worker2`. If the output
contains one node named `orbstack`, the wrong cluster is selected.

After the stack is healthy, run the guarded cluster demo:

```bash
make demo-cluster
```

The command prints the active Kubernetes context and API server, then requires the exact
context name before it creates resources. It validates node, Cilium, Falco, Kyverno, and
Argus readiness; launches bounded workloads in an isolated `argus-demo` namespace;
starts the React console against the in-cluster agent; collects evidence; and remains
available until `Ctrl-C` removes the namespace and stops the supervised local processes.

Run the read-only preflight first when using a new cluster:

```bash
make demo-cluster-dry-run
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect to localhost port 8000` | Agent is not running | Run `make dev-agent` or `make demo-local` |
| `Missing local environment` | Python dependencies are not installed | Run `make setup-local` |
| Port 8000 or 5173 is already in use | Another local service is running | Stop it, then rerun `make demo-local` |
| Console opens but has no incidents | The backend was restarted or never seeded | Run `make simulate-threats` |
| AI panels report `OPENAI_API_KEY not configured` | The agent started without an OpenAI credential | Add `OPENAI_API_KEY` to `.env` locally or redeploy the cluster agent with `OPENAI_API_KEY=... make deploy-agent` |
| OpenAI returns `429 insufficient_quota` | The API project has no available credit or billing quota | Enable API billing or add credits in the OpenAI Platform, then retry |
| Cluster panels show no live data | Local synthetic mode has no Kubernetes telemetry | Use full-cluster mode for real telemetry |
| `kubectl` connection failure | Full-cluster mode is not configured | Complete [setup.md](../setup.md) |
| Cilium missing while the three OrbStack VMs are running | The `orbstack` context is selected instead of the k3s cluster | Run `kubectl config use-context argus`, then repeat the dry run |
| `make cluster-up` reports that machines already exist | The k3s VMs are already provisioned | Do not recreate them; select `argus` and run `make demo-cluster-dry-run` |
| Cluster console URL does not respond | Port 8000 or 5173 is occupied, or the service port-forward exited | Stop the conflicting local process and rerun `make demo-cluster`; startup prints the failed child-process log |

## Verify the repository

```bash
make test
```

This runs the complete backend test suite and a production UI build.
