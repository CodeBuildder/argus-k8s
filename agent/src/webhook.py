"""
Argus Agent — Falco webhook receiver
Copyright (c) 2026 Kaushikkumaran

Receives Falco JSON alert payloads, validates, deduplicates,
and passes to the enrichment + reasoning pipeline.

Falco alert schema reference:
https://falco.org/docs/alerts/formatting/
"""

import time
import hashlib
from enum import Enum
from typing import Any
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, field_validator
import structlog

from config import config as app_config

log = structlog.get_logger()

router = APIRouter()

# Deduplication cache: key -> timestamp of last seen
# Prevents alert storms from overwhelming the reasoning API
dedup_cache: dict[str, float] = {}

# Default suppression window in seconds
DEDUP_WINDOW_SECONDS = app_config.DEDUP_WINDOW_SECONDS


class Priority(str, Enum):
    CRITICAL = "Critical"
    ERROR = "Error"
    WARNING = "Warning"
    NOTICE = "Notice"
    INFORMATIONAL = "Informational"
    DEBUG = "Debug"


class FalcoOutputFields(BaseModel):
    """Key fields extracted from Falco alert output_fields."""
    container_id: str | None = None
    container_name: str | None = None
    container_image_repository: str | None = None
    container_image_tag: str | None = None
    k8s_pod_name: str | None = None
    k8s_ns_name: str | None = None
    proc_name: str | None = None
    proc_cmdline: str | None = None
    proc_pname: str | None = None
    fd_name: str | None = None
    user_name: str | None = None
    user_uid: int | None = None

    model_config = {"populate_by_name": True, "extra": "allow"}

    @classmethod
    def from_falco(cls, fields: dict) -> "FalcoOutputFields":
        """Map Falco dot-notation field names to Python-safe names."""
        mapping = {
            "container.id": "container_id",
            "container.name": "container_name",
            "container.image.repository": "container_image_repository",
            "container.image.tag": "container_image_tag",
            "k8s.pod.name": "k8s_pod_name",
            "k8s.ns.name": "k8s_ns_name",
            "proc.name": "proc_name",
            "proc.cmdline": "proc_cmdline",
            "proc.pname": "proc_pname",
            "fd.name": "fd_name",
            "user.name": "user_name",
            "user.uid": "user_uid",
        }
        normalized = {}
        for falco_key, python_key in mapping.items():
            if falco_key in fields:
                normalized[python_key] = fields[falco_key]
        return cls(**normalized)


class FalcoAlert(BaseModel):
    """
    Pydantic model for a Falco JSON alert payload.

    Falco emits alerts in this format when http_output is enabled.
    Reference: https://falco.org/docs/alerts/
    """
    rule: str
    priority: Priority
    time: str
    output: str
    hostname: str | None = None
    source: str | None = None
    tags: list[str] = []
    output_fields: dict[str, Any] = {}

    @field_validator("rule")
    @classmethod
    def rule_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("rule cannot be empty")
        return v.strip()

    @field_validator("priority", mode="before")
    @classmethod
    def normalize_priority(cls, v: str) -> str:
        """Normalize priority — Falco sometimes sends lowercase."""
        if isinstance(v, str):
            return v.capitalize()
        return v

    def dedup_key(self) -> str:
        """
        Generate a deduplication key for this alert.

        Key is based on: rule + pod name + namespace + process name.
        Same rule firing on same pod within DEDUP_WINDOW = suppressed.
        """
        fields = self.output_fields
        pod = fields.get("k8s.pod.name") or fields.get("container.name") or "unknown"
        ns = fields.get("k8s.ns.name") or "unknown"
        proc = fields.get("proc.name") or "unknown"
        raw = f"{self.rule}|{pod}|{ns}|{proc}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_enricher_payload(self) -> dict:
        """Serialize alert for the enricher layer."""
        return {
            "rule": self.rule,
            "priority": self.priority.value,
            "time": self.time,
            "output": self.output,
            "hostname": self.hostname,
            "tags": self.tags,
            "fields": FalcoOutputFields.from_falco(self.output_fields).model_dump(),
            "raw_fields": self.output_fields,
        }


def is_duplicate(alert: FalcoAlert, window_seconds: int = DEDUP_WINDOW_SECONDS) -> bool:
    """
    Check if this alert is a duplicate within the suppression window.

    Returns True if the alert should be suppressed.
    Updates the cache timestamp if not suppressed.
    """
    key = alert.dedup_key()
    now = time.time()

    if key in dedup_cache:
        last_seen = dedup_cache[key]
        if now - last_seen < window_seconds:
            log.info(
                "alert_deduplicated",
                rule=alert.rule,
                key=key,
                suppressed_for_seconds=round(window_seconds - (now - last_seen)),
            )
            return True

    dedup_cache[key] = now

    # Evict stale entries to prevent unbounded growth
    stale_keys = [k for k, ts in dedup_cache.items() if now - ts > window_seconds * 2]
    for k in stale_keys:
        del dedup_cache[k]

    return False


async def process_alert(payload: dict) -> None:
    """
    Background task: full agent pipeline.
    Delegates to main.py process_alert which has full pipeline wired.
    """
    import os
    from enricher import enrich_context
    from reasoning import reason_about_threat
    from actions import route_action
    from audit import audit_log
    import structlog as _log
    _l = _log.get_logger()
    rule = payload.get("rule", "unknown")
    _l.info("pipeline_started", rule=rule)
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    notify_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    context = await enrich_context(payload)
    decision = await reason_about_threat(context, api_key)
    action_result = await route_action(payload, decision, notify_webhook or None)
    await audit_log(payload, context, decision, action_result)
    _l.info("pipeline_complete", rule=rule, severity=decision.severity.value, action=action_result.get("action"), status=action_result.get("status"))


@router.post("/falco/webhook", status_code=202)
async def receive_falco_alert(
    alert: FalcoAlert,
    background_tasks: BackgroundTasks,
):
    """
    Receive a Falco alert via HTTP webhook.

    Falco configuration required in values.yaml:
        falco.http_output.enabled: true
        falco.http_output.url: http://argus-agent.argus-system.svc/falco/webhook

    Returns 202 Accepted immediately so Falco doesn't block on our processing.
    Alert is processed asynchronously in a background task.
    """
    log.info(
        "falco_alert_received",
        rule=alert.rule,
        priority=alert.priority.value,
        hostname=alert.hostname,
        pod=alert.output_fields.get("k8s.pod.name"),
        namespace=alert.output_fields.get("k8s.ns.name"),
    )

    if is_duplicate(alert):
        return {"status": "deduplicated", "rule": alert.rule}

    payload = alert.to_enricher_payload()
    background_tasks.add_task(process_alert, payload)

    return {
        "status": "accepted",
        "rule": alert.rule,
        "priority": alert.priority.value,
        "dedup_key": alert.dedup_key(),
    }


@router.get("/falco/webhook/health")
async def webhook_health():
    return {
        "status": "ok",
        "dedup_cache_size": len(dedup_cache),
        "dedup_window_seconds": DEDUP_WINDOW_SECONDS,
    }
