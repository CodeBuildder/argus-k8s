# Argus — Local Setup

This guide covers everything needed to run Argus locally: spinning up the cluster, deploying the security stack, and running the console.

---

## Prerequisites

**Hardware:** macOS on Apple Silicon (M1/M2/M3). The cluster runs three ARM64 Linux VMs.

**Tools to install:**
```bash
brew install orbstack kubectl helm k3sup cilium-cli hubble k9s
```

**Credentials:** You need an API key from Anthropic to run the reasoning agent. Set it in `agent/.env`:
```
ANTHROPIC_API_KEY=your_key_here
```

---

## 1. Choose fresh setup or existing cluster

OrbStack has a built-in Kubernetes cluster whose context is normally `orbstack`.
Argus does not use it. Argus uses a separate, real three-node k3s cluster running
inside the `k3s-master`, `k3s-worker1`, and `k3s-worker2` OrbStack machines.

Inspect what already exists before provisioning anything:

```bash
orb list
kubectl config get-contexts
```

If the three `k3s-*` machines and the `argus` context already exist, reuse them:

```bash
kubectl config use-context argus
kubectl get nodes -o wide
make demo-cluster-dry-run
```

Do not run `make cluster-up` against an existing installation. The bootstrap scripts
create fixed machine names and are not an idempotent upgrade workflow.

## 2. Fresh cluster setup

### Provision the VMs and install k3s
```bash
make cluster-up
```

The bootstrap is designed for this repository owner's current OrbStack layout. Before
using it on another workstation, review the username, SSH key, and IP variables in
`cluster/bootstrap/*.sh`; they are currently environment-specific.

This runs four steps in sequence:
1. Provisions three OrbStack VMs (`k3s-master`, `k3s-worker1`, `k3s-worker2`) running Ubuntu 22.04 ARM64
2. Installs k3s on the master node with `--flannel-backend=none` (Cilium takes over networking)
3. Joins both worker nodes to the cluster
4. Installs Cilium in eBPF mode with kube-proxy replacement and Hubble enabled

### Verify the cluster is healthy
```bash
kubectl config use-context argus
make cluster-status
```

Expected output: 3 nodes in Ready state, Cilium status shows all agents operational.

If you see one node named `orbstack`, you selected OrbStack's built-in Kubernetes
context. Switch back with `kubectl config use-context argus`.

### Open the Hubble network flow UI
```bash
cilium hubble ui
```

---

## 3. Security stack

### Deploy Falco (runtime threat detection)
```bash
make deploy-falco
```

Installs Falco via Helm into `kube-system`. Uses the `modern_ebpf` driver — no kernel headers required. Falco starts monitoring syscalls immediately on all three nodes.

### Deploy Kyverno (admission control)
```bash
make deploy-kyverno
```

Installs Kyverno and applies three policies:
- `disallow-root-containers` — blocks pods without `runAsNonRoot: true`
- `require-resource-limits` — blocks pods missing CPU/memory limits
- `approved-registries-only` — blocks images from unapproved registries

---

## 4. Observability

The repository's `make deploy-observability` target is currently a placeholder. Do not
rely on it for a fresh installation. On the maintained Argus cluster, verify the
existing Prometheus, Grafana, Loki, and Promtail workloads with:

```bash
kubectl get pods -n monitoring
```

### Access Grafana
```bash
make grafana-ui
# Opens at http://localhost:3000 — login: admin / argus-admin
```

---

## 5. Detection agent

### Deploy to cluster
```bash
ANTHROPIC_API_KEY=your_key make deploy-agent
```

### Run locally for development
```bash
cd agent/src
source ../.env
uvicorn main:app --reload --port 8000
```

The agent exposes these endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check |
| `/incidents` | GET | List detected incidents |
| `/incidents/stats` | GET | Incident counts and metrics |
| `/approvals` | GET | Pending human approval queue |
| `/approvals/{id}/approve` | POST | Approve a queued action |
| `/approvals/{id}/reject` | POST | Reject a queued action |
| `/simulate-threats` | POST | Inject sample incidents for testing |
| `/chat` | POST | Conversational queries about cluster security state |

---

## 6. Run the guarded real-cluster demo

First perform the read-only preflight:

```bash
kubectl config use-context argus
make demo-cluster-dry-run
```

It must report ready Cilium, Falco, Kyverno, and Argus components. Then run:

```bash
make demo-cluster
```

Type `argus` when asked to confirm the active context. The command creates only the
`argus-demo` namespace, launches bounded workloads, waits for telemetry, prints real
Falco/Argus/Kyverno evidence, forwards the in-cluster agent, and starts the React
console at [http://127.0.0.1:5173](http://127.0.0.1:5173). It remains active until
`Ctrl-C`, which stops the console and port-forward and deletes the demo namespace.

## 7. Console UI

### Install dependencies and start
```bash
cd ui
npm install
npm run dev
```

The console runs at `http://localhost:5173`. All `/api/*` requests are proxied to the agent at `http://localhost:8000`.

`make demo-cluster` handles the cluster service port-forward and console automatically.
When developing the UI separately, the equivalent manual port-forward is:

```bash
kubectl port-forward -n argus-system svc/argus-agent 8000:80
```

### Optional: populate the local synthetic API

This endpoint creates synthetic UI data. It is not evidence from Falco, Cilium, or
Kyverno and is not part of the full-cluster demo.

```bash
curl -X POST http://localhost:8000/simulate-threats \
  -H "Content-Type: application/json" \
  -d '{"count": 15}'
```

This injects incidents across all detection layers (Falco runtime, eBPF kernel, Kyverno admission, Cilium network) so every page of the console has data to display.

---

## Useful commands

| Command | What it does |
|---|---|
| `make cluster-status` | Node and pod status across the cluster |
| `make cluster-down` | Stop all OrbStack VMs |
| `make clean` | Destroy VMs and reset kubeconfig |
| `cilium hubble ui` | Live network flow visualization |
| `k9s` | Terminal-based cluster browser |
| `kubectl get policyreport -A` | View Kyverno policy violations |
| `kubectl get ciliumnetworkpolicies -A` | List active network isolation policies |

---

## Troubleshooting

**Agent fails to start with `ModuleNotFoundError: No module named 'webhook'`**

Run uvicorn from inside `agent/src/`, not from `agent/`:
```bash
cd agent/src && uvicorn main:app --reload --port 8000
```

**Console shows no data / API calls fail**

Check that the vite proxy target in `ui/vite.config.ts` points to port 8000, not 8080.

**Kyverno blocks all new pods after install**

The Kyverno admission webhook must be ready before any workload deployments. Wait 30 seconds after `make deploy-kyverno` before deploying other workloads.

**Cilium not ready after cluster-up**

Cilium takes 60–90 seconds to initialize on first install. Run `cilium status --wait` to block until all agents are healthy.

**`demo-cluster-dry-run` says Cilium is missing, but the k3s VMs are running**

Check the selected context:

```bash
kubectl config current-context
kubectl config get-contexts
```

If it prints `orbstack`, that is the separate built-in cluster. Run:

```bash
kubectl config use-context argus
make demo-cluster-dry-run
```

**Threat pods remain after an interrupted manual test**

The guarded runner deletes its namespace automatically. For manual recovery, delete
only the labelled demo namespace:

```bash
kubectl delete namespace argus-demo --ignore-not-found
```
