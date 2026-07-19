# Sentinel Platform — Judge Setup and Argus Cluster Guide

This guide has one entry point. Choose exactly one path, run its read-only doctor, then
run the command it prints. The portable path is recommended for judges; the live path is
the measured k3s proof used for the technical demo.

## Start here — choose one path

The repositories must share this layout:

```text
Projects/
├── argus-k8s/                 # run every command below here
└── sentinel-stack/
    ├── phoenix/
    ├── sentinel/
    └── sentinel-platform/
```

### Path A — portable full-platform demo (recommended)

This path needs Docker or OrbStack but does not need Kubernetes. It runs the real local
Argus, Phoenix, Sentinel, and SOG services against clearly labeled synthetic topology,
replayed Argus evidence, and Phoenix simulator outcomes.

```bash
make doctor
make demo-platform
```

Open the three consoles:

- Argus: <http://127.0.0.1:5173>
- Phoenix: <http://127.0.0.1:5174>
- Sentinel: <http://127.0.0.1:5175>

Successful runs write `artifacts/demo-platform/latest-demo.{json,md}`. `Ctrl-C` stops
only command-owned processes and removes the disposable Redis container.

### Path B — guarded live k3s proof

This path needs the existing three-node `argus` k3s cluster and deployed security,
chaos, agent, and SOG stack. The doctor is read-only:

```bash
kubectl config use-context argus
make doctor-live
make demo-platform-live
```

The live command separately asks for the exact context and `INJECT LIVE FAULT`. It
creates only `sentinel-live-demo`, targets one of two disposable replicas, waits for
observed Argus evidence, verifies the real Phoenix/Chaos Mesh object and Kubernetes
replacement, measures HTTP availability and recovery time, and requires Sentinel
correlation. Successful runs write
`artifacts/demo-platform/latest-live-demo.{json,md}`. `Ctrl-C` deletes only the isolated
namespace.

### What the modes claim

| Mode | Evidence provenance | Kubernetes mutation | Availability claim |
|---|---|---:|---|
| Portable | `replayed` + `simulator` | None | Explicitly not measured |
| Live k3s | `observed` + `live_chaos` | Isolated, approved namespace only | Measured by continuous HTTP probes |

The remainder of this document explains how the maintained Argus k3s environment is
constructed and troubleshot. Judges using Path A can stop here.

---

## Cluster prerequisites

**Hardware:** macOS on Apple Silicon (M1/M2/M3). The cluster runs three ARM64 Linux VMs.

**Tools to install:**
```bash
brew install orbstack kubectl helm k3sup cilium-cli hubble k9s
```

**Credentials:** You need an OpenAI API key to run the reasoning agent. Set it in the repository `.env`:
```
OPENAI_API_KEY=your_key_here
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
OPENAI_API_KEY=your_key make deploy-agent
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
