"""
Falco webhook receiver — validates and parses incoming Falco JSON alert payloads.

Falco alert schema (simplified):
  {
    "output": "string — human-readable event description",
    "priority": "Emergency | Alert | Critical | Error | Warning | Notice | Informational | Debug",
    "rule": "string — matched rule name",
    "time": "ISO8601 timestamp",
    "output_fields": {
      "container.id": "...",
      "k8s.pod.name": "...",
      "k8s.ns.name": "...",
      "proc.name": "...",
      "evt.type": "...",
      ...
    }
  }
"""

# TODO: implement in Module 4
