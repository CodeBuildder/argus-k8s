"""
Argus Agent — audit logger
Copyright (c) 2026 Kaushikkumaran

Every agent decision is logged to Loki with full context.
The audit log is the source of truth for:
  - What threats were detected
  - What the agent reasoned
  - What actions were taken
  - Who approved human-required actions
  - How long enrichment and reasoning took

Audit entries are queryable in Grafana via:
  {app="argus-agent"} | json | action_taken != ""
"""

import json
import time
from datetime import datetime, timezone
import httpx
import structlog

log = structlog.get_logger()

LOKI_URL = "http://loki.monitoring.svc.cluster.local:3100"


def _build_audit_entry(
    alert: dict,
    context: dict,
    decision: any,
    action_result: dict,
) -> dict:
    """Build a structured audit log entry."""
    fields = alert.get("fields", {})

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "argus_decision",
        "rule": alert.get("rule", "unknown"),
        "priority": alert.get("priority", "unknown"),
        "pod": fields.get("k8s_pod_name", "unknown"),
        "namespace": fields.get("k8s_ns_name", "unknown"),
        "hostname": alert.get("hostname", "unknown"),
        "severity": decision.severity.value,
        "confidence": decision.confidence,
        "assessment": decision.assessment,
        "likely_false_positive": decision.likely_false_positive,
        "recommended_action": decision.recommended_action.value,
        "blast_radius": decision.blast_radius,
        "action_taken": action_result.get("action", "unknown"),
        "action_status": action_result.get("status", "unknown"),
        "action_detail": action_result.get("message", ""),
        "enrichment_sources": context.get("enrichment_sources", []),
        "enrichment_duration_ms": context.get("enrichment_duration_ms", 0),
        "mitre_tags": alert.get("tags", []),
        "suppress_minutes": decision.suppress_minutes,
    }


async def _ship_to_loki(entry: dict) -> None:
    """
    Ship audit entry to Loki via HTTP push API.
    Non-blocking — failures are logged but don't affect the main pipeline.
    """
    try:
        now_ns = str(int(time.time() * 1e9))
        payload = {
            "streams": [
                {
                    "stream": {
                        "app": "argus-agent",
                        "namespace": "argus-system",
                        "event_type": "audit",
                        "severity": entry.get("severity", "unknown"),
                        "action": entry.get("action_taken", "unknown"),
                    },
                    "values": [[now_ns, json.dumps(entry)]]
                }
            ]
        }

        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.post(
                f"{LOKI_URL}/loki/api/v1/push",
                json=payload,
            )
            if response.status_code not in (200, 204):
                log.warning("audit_loki_push_failed", status=response.status_code)

    except Exception as e:
        log.warning("audit_loki_unavailable", error=str(e))


async def audit_log(
    alert: dict,
    context: dict,
    decision: any,
    action_result: dict,
) -> None:
    """
    Main audit log entry point.

    Logs to:
    1. structlog (stdout — always works, picked up by Promtail -> Loki)
    2. Loki HTTP push API (direct push for guaranteed delivery)
    """
    entry = _build_audit_entry(alert, context, decision, action_result)

    from main import incident_store
    incident_store.append({
        **entry,
        "ts": time.time(),
        "id": f"{int(time.time()*1000)}-{entry.get('pod', 'unknown')}",
    })
    if len(incident_store) > 500:
        incident_store.pop(0)

    log.info(
        "argus_audit",
        **{k: v for k, v in entry.items() if k not in ("assessment", "blast_radius")}
    )

    await _ship_to_loki(entry)
