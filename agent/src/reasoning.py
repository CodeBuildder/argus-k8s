"""
AI reasoning layer — sends enriched context to Claude API and returns a structured decision.

Decision schema:
  {
    "severity": "LOW | MED | HIGH | CRITICAL",
    "confidence": 0.0 - 1.0,
    "assessment": "string — agent's reasoning",
    "likely_false_positive": bool,
    "recommended_action": "LOG | NOTIFY | ISOLATE | KILL | HUMAN_REQUIRED",
    "blast_radius": "string — what could be affected",
    "suppress_minutes": int | null
  }
"""

# TODO: implement in Module 4
