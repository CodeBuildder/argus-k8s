"""
Action router — executes remediation based on agent decision.

Actions available:
  LOG       → write to audit log, update Grafana dashboard
  NOTIFY    → send to Slack/Discord webhook
  ISOLATE   → apply CiliumNetworkPolicy to cut pod network access
  KILL      → kubectl delete pod (requires HIGH confidence)
  HUMAN_REQUIRED → push to UI approval queue, block until approved/rejected
"""

# TODO: implement in Module 4
