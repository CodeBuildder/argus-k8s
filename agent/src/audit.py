"""
Audit logger — every agent decision is logged to Loki with full context.

Log entry schema:
  {
    "timestamp": "ISO8601",
    "alert": <original Falco event>,
    "context": <enriched cluster context>,
    "decision": <agent decision>,
    "action_taken": "string",
    "action_approved_by": "human | agent | suppressed",
    "duration_ms": int
  }
"""

# TODO: implement in Module 4
