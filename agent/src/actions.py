"""
Argus Agent — action router
Copyright (c) 2026 Kaushikkumaran

Executes remediation actions based on Claude's decision.
Every action is logged to the audit trail before and after execution.

Safety rules:
  - KILL requires confidence >= 0.85 — falls back to ISOLATE if below threshold
  - HUMAN_REQUIRED adds to in-memory approval queue — never auto-executes
  - All actions are idempotent where possible (re-applying ISOLATE is safe)
  - Actions never raise — errors are logged and surfaced in audit trail
"""

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
import httpx
import structlog

log = structlog.get_logger()

KILL_CONFIDENCE_THRESHOLD = 0.85

# In-memory approval queue for HUMAN_REQUIRED actions
# In production this would be persisted to a database
approval_queue: list[dict] = []

# Suppression registry: "namespace/pod/rule" -> expiry unix timestamp
# Populated when a human rejects an approval; prevents re-queuing the same event
suppression_list: dict[str, float] = {}


async def action_log(alert: dict, decision: Any) -> dict:
    """
    LOG action — record to audit trail only. No cluster changes.
    Used for low-severity alerts and false positives.
    """
    log.info(
        "action_log",
        rule=alert.get("rule"),
        severity=decision.severity.value,
        assessment=decision.assessment[:100],
    )
    return {"action": "LOG", "status": "completed", "message": "Logged to audit trail"}


async def action_notify(alert: dict, decision: Any, webhook_url: str | None = None) -> dict:
    """
    NOTIFY action — send alert to Slack/Discord webhook.
    If no webhook URL configured, logs a warning and records as skipped.
    """
    fields = alert.get("fields", {})
    pod = fields.get("k8s_pod_name", "unknown")
    namespace = fields.get("k8s_ns_name", "unknown")

    message = {
        "text": f"*Argus Security Alert*",
        "attachments": [
            {
                "color": "#ff4757" if decision.severity.value in ("CRITICAL", "HIGH") else "#ffa502",
                "fields": [
                    {"title": "Rule", "value": alert.get("rule", "unknown"), "short": True},
                    {"title": "Severity", "value": decision.severity.value, "short": True},
                    {"title": "Pod", "value": f"{namespace}/{pod}", "short": True},
                    {"title": "Confidence", "value": f"{round(decision.confidence * 100)}%", "short": True},
                    {"title": "Assessment", "value": decision.assessment, "short": False},
                    {"title": "Recommended action", "value": decision.recommended_action.value, "short": True},
                ]
            }
        ]
    }

    if not webhook_url:
        log.warning("notify_no_webhook_configured", rule=alert.get("rule"))
        return {"action": "NOTIFY", "status": "skipped", "message": "No webhook URL configured"}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()
        log.info("notify_sent", rule=alert.get("rule"), pod=pod)
        return {"action": "NOTIFY", "status": "completed", "message": "Notification sent"}
    except Exception as e:
        log.error("notify_failed", rule=alert.get("rule"), error=str(e))
        return {"action": "NOTIFY", "status": "failed", "error": str(e)}


async def action_isolate(alert: dict, decision: Any) -> dict:
    """
    ISOLATE action — apply CiliumNetworkPolicy to cut pod network access.

    Creates a deny-all ingress+egress policy targeting the specific pod.
    The pod keeps running but cannot communicate with anything.
    This is reversible — delete the policy to restore network access.
    """
    fields = alert.get("fields", {})
    pod_name = fields.get("k8s_pod_name", "unknown")
    namespace = fields.get("k8s_ns_name", "unknown")

    if pod_name == "unknown" or namespace == "unknown":
        log.error("isolate_missing_pod_info", alert_rule=alert.get("rule"))
        return {"action": "ISOLATE", "status": "failed", "error": "Missing pod name or namespace"}

    policy_name = f"argus-isolate-{pod_name}"

    isolation_policy = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
            "labels": {
                "managed-by": "argus",
                "argus-action": "isolation",
                "argus-rule": re.sub(r'[^A-Za-z0-9._-]', '-', alert.get("rule", "unknown"))[:63].strip('-'),
            }
        },
        "spec": {
            "description": f"Argus isolation: {alert.get('rule', 'unknown')}",
            "endpointSelector": {
                "matchLabels": {
                    "k8s:io.kubernetes.pod.name": pod_name,
                }
            },
        }
    }

    try:
        def _apply_policy():
            from kubernetes import client, config as k8s_config
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()

            custom_api = client.CustomObjectsApi()
            try:
                custom_api.create_namespaced_custom_object(
                    group="cilium.io",
                    version="v2",
                    namespace=namespace,
                    plural="ciliumnetworkpolicies",
                    body=isolation_policy,
                )
            except Exception as create_err:
                if "already exists" in str(create_err).lower():
                    log.info("isolate_policy_already_exists", pod=pod_name, namespace=namespace)
                else:
                    raise

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _apply_policy)

        log.info("isolate_applied", pod=pod_name, namespace=namespace, policy=policy_name)
        return {
            "action": "ISOLATE",
            "status": "completed",
            "pod": pod_name,
            "namespace": namespace,
            "policy_name": policy_name,
            "message": f"Network isolation applied to {namespace}/{pod_name}",
        }

    except Exception as e:
        log.error("isolate_failed", pod=pod_name, namespace=namespace, error=str(e))
        return {"action": "ISOLATE", "status": "failed", "pod": pod_name, "error": str(e)}


async def action_kill(alert: dict, decision: Any) -> dict:
    """
    KILL action — delete the compromised pod.

    Safety gate: requires confidence >= KILL_CONFIDENCE_THRESHOLD (0.85).
    Below threshold, falls back to ISOLATE automatically.

    The pod's controller (Deployment/DaemonSet) will restart it — this is
    intentional. A clean restart eliminates the compromised process while
    preserving service availability.
    """
    fields = alert.get("fields", {})
    pod_name = fields.get("k8s_pod_name", "unknown")
    namespace = fields.get("k8s_ns_name", "unknown")

    if decision.confidence < KILL_CONFIDENCE_THRESHOLD:
        log.warning(
            "kill_confidence_too_low",
            pod=pod_name,
            confidence=decision.confidence,
            threshold=KILL_CONFIDENCE_THRESHOLD,
            fallback="ISOLATE",
        )
        isolate_result = await action_isolate(alert, decision)
        isolate_result["kill_downgraded"] = True
        isolate_result["kill_downgrade_reason"] = f"Confidence {decision.confidence:.2f} < threshold {KILL_CONFIDENCE_THRESHOLD}"
        return isolate_result

    if pod_name == "unknown" or namespace == "unknown":
        return {"action": "KILL", "status": "failed", "error": "Missing pod name or namespace"}

    try:
        def _delete_pod():
            from kubernetes import client, config as k8s_config
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()

            v1 = client.CoreV1Api()
            v1.delete_namespaced_pod(name=pod_name, namespace=namespace)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _delete_pod)

        log.info("kill_executed", pod=pod_name, namespace=namespace, confidence=decision.confidence)
        return {
            "action": "KILL",
            "status": "completed",
            "pod": pod_name,
            "namespace": namespace,
            "message": f"Pod {namespace}/{pod_name} deleted. Controller will restart it.",
        }

    except Exception as e:
        log.error("kill_failed", pod=pod_name, namespace=namespace, error=str(e))
        return {"action": "KILL", "status": "failed", "pod": pod_name, "error": str(e)}


async def action_human_required(alert: dict, decision: Any) -> dict:
    """
    HUMAN_REQUIRED action — add to approval queue, wait for human decision.

    The approval queue is exposed via the API so the UI can display
    pending approvals. The agent does NOT auto-remediate until approved.
    Respects suppression windows set by previous human rejections.
    """
    fields = alert.get("fields", {})
    pod_name = fields.get("k8s_pod_name", "unknown")
    namespace = fields.get("k8s_ns_name", "unknown")

    # Check suppression — don't re-queue if a human recently rejected this combo
    suppression_key = f"{namespace}/{pod_name}/{alert.get('rule', '')}"
    expiry = suppression_list.get(suppression_key, 0)
    if expiry > time.time():
        expires_in = int(expiry - time.time())
        log.info("human_required_suppressed", key=suppression_key, expires_in_seconds=expires_in)
        return {
            "action": "HUMAN_REQUIRED",
            "status": "suppressed",
            "suppressed_key": suppression_key,
            "expires_in_seconds": expires_in,
            "message": f"Suppressed by previous human rejection. Auto-resumes in {expires_in}s.",
        }

    queue_entry = {
        "id": f"{int(datetime.now(timezone.utc).timestamp())}-{pod_name}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
        "decision": {
            "severity": decision.severity.value,
            "confidence": decision.confidence,
            "assessment": decision.assessment,
            "blast_radius": decision.blast_radius,
            "recommended_action": decision.recommended_action.value,
        },
        "status": "pending",
        "pod": pod_name,
        "namespace": namespace,
    }

    approval_queue.append(queue_entry)

    log.info(
        "human_required_queued",
        queue_id=queue_entry["id"],
        pod=pod_name,
        namespace=namespace,
        queue_size=len(approval_queue),
    )

    return {
        "action": "HUMAN_REQUIRED",
        "status": "queued",
        "queue_id": queue_entry["id"],
        "pod": pod_name,
        "namespace": namespace,
        "message": "Added to human approval queue. Awaiting decision.",
    }


async def route_action(
    alert: dict,
    decision: Any,
    notify_webhook: str | None = None,
) -> dict:
    """
    Route the agent decision to the appropriate action handler.

    Args:
        alert: Normalized alert payload from webhook.py
        decision: AgentDecision from reasoning.py
        notify_webhook: Optional Slack/Discord webhook URL

    Returns:
        Action result dict with status and details.
    """
    from reasoning import RecommendedAction

    action = decision.recommended_action

    log.info(
        "routing_action",
        rule=alert.get("rule"),
        action=action.value,
        severity=decision.severity.value,
        confidence=decision.confidence,
        false_positive=decision.likely_false_positive,
    )

    if action == RecommendedAction.LOG:
        return await action_log(alert, decision)
    elif action == RecommendedAction.NOTIFY:
        return await action_notify(alert, decision, notify_webhook)
    elif action == RecommendedAction.ISOLATE:
        return await action_isolate(alert, decision)
    elif action == RecommendedAction.KILL:
        return await action_kill(alert, decision)
    elif action == RecommendedAction.HUMAN_REQUIRED:
        return await action_human_required(alert, decision)
    else:
        log.error("unknown_action", action=str(action))
        return await action_human_required(alert, decision)
