"""
Context enricher — given a Falco alert, queries the cluster for surrounding context.

Queries performed:
  - kubectl: pod info, deployment, namespace, image, recent restarts
  - Loki: pod logs from last N minutes
  - Hubble: network flows from pod in last N minutes
  - Kyverno: active policy violations for this pod

Output is a structured dict passed to the reasoning layer.
"""

# TODO: implement in Module 4
