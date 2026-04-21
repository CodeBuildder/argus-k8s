# Argus — Grafana Dashboards

Dashboard JSON files go in this directory. Grafana picks them up automatically via the sidecar ConfigMap mechanism — any file here with a `.json` extension is loaded on Grafana startup without manual import.

---

## Default dashboards (from kube-prometheus-stack)

These are provisioned automatically when Grafana is installed:

- **Kubernetes / Compute Resources / Cluster** — cluster-wide CPU and memory usage
- **Kubernetes / Compute Resources / Namespace** — per-namespace resource breakdown
- **Kubernetes / Networking / Cluster** — network traffic across the cluster
- **Node Exporter / Nodes** — OS-level metrics per node (CPU, memory, disk, network)
- **Prometheus / Overview** — Prometheus health and scrape target status

---

## Custom dashboards (Argus security views)

These are built specifically for Argus and stored as JSON in this directory:

- **Argus / Security Events** — Falco alert rate over time, severity breakdown, top triggered rules
- **Argus / Network Policy** — Cilium dropped flows by namespace, cross-namespace violation attempts
- **Argus / Agent Decisions** — agent decision log, actions taken per hour, approval queue depth
- **Argus / Cluster Health** — combined node health, pod restarts, and security posture in one view

---

## Adding a new dashboard

1. Build the dashboard in the Grafana UI
2. Go to Dashboard settings → JSON Model → copy the JSON
3. Save the file here as `argus-<name>.json`
4. Restart Grafana (or wait for the sidecar to pick it up): `kubectl rollout restart deployment -n monitoring kube-prometheus-stack-grafana`

---

## Accessing Grafana

```bash
make grafana-ui
# Available at http://localhost:3000
# Login: admin / argus-admin
```
