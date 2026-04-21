# ADR 005: Loki over ELK stack for log aggregation

## Status
Accepted

## Context
Need log aggregation for pod logs and Falco alert stream. Must run alongside
Prometheus, Grafana, Cilium, Falco, and the detection agent on a 3-node laptop cluster
without exhausting available RAM.

## Decision
Use Grafana Loki with Promtail for log collection.

## Rationale
- Loki indexes log metadata (labels) not log content — dramatically lower memory
  footprint than Elasticsearch which indexes full text
- Native Grafana integration — single pane for metrics (Prometheus) and logs (Loki)
- Promtail DaemonSet automatically collects all pod logs with K8s metadata labels
- Falco JSON events can be shipped directly to Loki via Promtail pipeline
- LGTM stack (Loki, Grafana, Tempo, Mimir) is a coherent, modern observability story

## Rejected Alternatives
- ELK (Elasticsearch + Logstash + Kibana): Elasticsearch alone requires 2-4GB RAM
  minimum. Running ELK alongside the rest of this stack on a laptop cluster would
  cause memory pressure and pod evictions. Operationally complex.
- Fluentd + Elasticsearch: Same memory problem, adds Fluentd complexity

## Consequences
Loki is not a full-text search engine — complex log queries require LogQL knowledge.
Log retention is configured by chunk size, not time — must tune carefully for disk usage
on 20GiB VM disks.
