# Argus Grafana Dashboards

## Default dashboards (from kube-prometheus-stack)
- Kubernetes / Compute Resources / Cluster — cluster-wide CPU/memory
- Kubernetes / Compute Resources / Namespace — per-namespace usage
- Kubernetes / Networking / Cluster — network traffic
- Node Exporter / Nodes — OS-level node metrics
- Prometheus / Overview — Prometheus health

## Custom dashboards (to be built in Module 3/4)
- Argus / Security Events — Falco alert rate, severity, top rules
- Argus / Network Policy — Cilium dropped flows, cross-namespace attempts
- Argus / Agent Decisions — AI agent reasoning log, actions taken, approval queue
- Argus / Cluster Health — combined cluster + security posture overview

Dashboard JSON files go in this directory.
They are auto-loaded by Grafana via the sidecar configmap mechanism.
