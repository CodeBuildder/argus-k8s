"""Best-effort Argus client for the Sentinel Operations Graph (SOG)."""

import asyncio
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx
import structlog

from config import config as app_config

log = structlog.get_logger()

_PRIORITY_MAP = {
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "debug": "info",
}

_DECISION_POSTURE_MAP = {
    "critical": "critical",
    "high": "high-risk",
    "med": "medium-risk",
    "medium": "medium-risk",
}

_NA = frozenset({"", "None", "<NA>", "N/A", "null", "none"})
_MAX_ATTEMPTS = 2


def _clean(value: Any) -> str | None:
    return None if value is None or str(value) in _NA else str(value)


def entity_id(raw_fields: dict, hostname: str | None = None) -> str | None:
    """Resolve a SOG entity ID from normalized Falco fields."""
    namespace = _clean(raw_fields.get("k8s.ns.name")) or "default"
    pod = _clean(raw_fields.get("k8s.pod.name")) or _clean(raw_fields.get("container.name"))
    if pod:
        return f"pod/{namespace}/{pod}"

    host = _clean(hostname) or _clean(raw_fields.get("hostname"))
    if host:
        return f"node/cluster/{host}"
    return None


def event_id(dedup_key: str, alert_time: str) -> str:
    """Return a stable schema-compatible UUID for one accepted Falco alert."""
    identity = f"argus|{dedup_key}|{alert_time}"
    return str(uuid5(NAMESPACE_URL, identity))


def security_posture_for_decision(severity: str, likely_false_positive: bool) -> str | None:
    if likely_false_positive:
        return None
    return _DECISION_POSTURE_MAP.get(severity.strip().lower())


def _result(status: str, **details: Any) -> dict[str, Any]:
    return {"status": status, **details}


async def _request(method: str, path: str, body: dict, timeout: float) -> dict[str, Any]:
    base_url = app_config.WORLD_MODEL_URL.rstrip("/")
    if not base_url:
        return _result("disabled")

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(method, f"{base_url}{path}", json=body)
        except httpx.RequestError as exc:
            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(0.1 * attempt)
                continue
            return _result("failed", reason="transport_error", error=str(exc), attempts=attempt)
        except Exception as exc:  # defensive: integration must never break local response
            return _result("failed", reason="client_error", error=str(exc), attempts=attempt)

        if response.status_code < 400:
            try:
                response_body = response.json()
            except ValueError:
                response_body = {}
            return _result(
                response_body.get("status", "accepted"),
                status_code=response.status_code,
                attempts=attempt,
            )

        if response.status_code >= 500 and attempt < _MAX_ATTEMPTS:
            await asyncio.sleep(0.1 * attempt)
            continue

        return _result(
            "failed",
            reason="http_error",
            status_code=response.status_code,
            response=response.text[:200],
            attempts=attempt,
        )

    return _result("failed", reason="retry_exhausted")


async def post_finding(
    *,
    dedup_key: str,
    raw_fields: dict,
    rule: str,
    priority: str,
    alert_time: str,
    output: str,
    tags: list,
    hostname: str | None = None,
    assessment: dict | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    finding_event_id = event_id(dedup_key, alert_time)
    affected_entity_id = entity_id(raw_fields, hostname)
    severity = _PRIORITY_MAP.get(priority.lower(), "info")

    payload: dict[str, Any] = {
        "finding_type": "falco_alert",
        "description": output or rule,
        "rule": rule,
        "priority": priority,
        "tags": tags,
        "raw_fields": raw_fields,
        "provenance": "observed",
    }
    if assessment:
        payload["assessment"] = assessment

    body: dict[str, Any] = {
        "event_id": finding_event_id,
        "type": "finding",
        "source": "argus",
        "timestamp": alert_time,
        "severity": severity,
        "payload": payload,
    }
    if affected_entity_id:
        body["entity_id"] = affected_entity_id
    if correlation_id:
        body["correlation_id"] = correlation_id

    result = await _request("POST", "/findings", body, timeout=8.0)
    log_method = log.warning if result["status"] == "failed" else log.debug
    log_method(
        "world_model_finding",
        rule=rule,
        event_id=finding_event_id,
        entity_id=affected_entity_id,
        **result,
    )
    return {**result, "event_id": finding_event_id, "entity_id": affected_entity_id}


async def patch_entity_posture(entity_id_value: str, security_posture: str) -> dict[str, Any]:
    """Update an existing entity's posture without gating Argus processing."""
    if not entity_id_value:
        return _result("skipped", reason="missing_entity")

    result = await _request(
        "PATCH",
        f"/entities/{entity_id_value}",
        {"security_posture": security_posture},
        timeout=5.0,
    )
    log_method = log.warning if result["status"] == "failed" else log.debug
    log_method(
        "world_model_posture",
        entity_id=entity_id_value,
        security_posture=security_posture,
        **result,
    )
    return {**result, "entity_id": entity_id_value, "security_posture": security_posture}
