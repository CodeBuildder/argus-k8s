"""
Argus Agent — context enricher
Copyright (c) 2026 Kaushikkumaran

Given a Falco alert, queries multiple data sources in parallel to build
a rich context object for the Claude reasoning layer.

Data sources:
  - Kubernetes API: pod spec, owner, image, restarts, node, namespace labels
  - Loki: pod logs from last 10 minutes
  - Hubble: network flows from/to pod in last 10 minutes
  - Kyverno: active policy violations for the pod namespace

Design principles:
  - All queries run concurrently via asyncio.gather
  - Partial failures return None for that field — never crash
  - Total enrichment time target: < 5 seconds
  - Context is structured for direct consumption by the Claude prompt builder
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any
import httpx
import structlog

log = structlog.get_logger()

LOKI_URL = "http://loki.monitoring.svc.cluster.local:3100"
HUBBLE_URL = "http://hubble-relay.kube-system.svc.cluster.local:4245"
ENRICHMENT_TIMEOUT = 5.0


def _get_k8s_client():
    """Get Kubernetes client — in-cluster or local kubeconfig."""
    try:
        from kubernetes import client, config as k8s_config
        try:
            k8s_config.load_incluster_config()
        except Exception:
            k8s_config.load_kube_config()
        return client
    except Exception as e:
        log.warning("k8s_client_unavailable", error=str(e))
        return None


async def fetch_pod_context(namespace: str, pod_name: str) -> dict | None:
    """
    Fetch pod context from the Kubernetes API.

    Returns:
        - pod_name, namespace, node
        - image name and tag
        - restart count (last 1h indicator of instability)
        - owner (Deployment/DaemonSet/StatefulSet name)
        - pod age in hours
        - namespace labels (environment=prod etc.)
        - resource limits (missing limits = higher risk)
        - service account name
    """
    if not namespace or not pod_name:
        return None

    try:
        k8s = _get_k8s_client()
        if not k8s:
            return None

        v1 = k8s.CoreV1Api()

        # Run pod and namespace fetch concurrently
        loop = asyncio.get_event_loop()

        pod = await loop.run_in_executor(
            None,
            lambda: v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        )
        ns = await loop.run_in_executor(
            None,
            lambda: v1.read_namespace(name=namespace)
        )

        # Extract container info (first container)
        container = pod.spec.containers[0] if pod.spec.containers else None
        container_status = (
            pod.status.container_statuses[0]
            if pod.status and pod.status.container_statuses
            else None
        )

        # Calculate pod age
        creation_time = pod.metadata.creation_timestamp
        age_hours = None
        if creation_time:
            age_hours = round(
                (datetime.now(timezone.utc) - creation_time).total_seconds() / 3600,
                1
            )

        # Extract owner reference
        owner_name = None
        owner_kind = None
        if pod.metadata.owner_references:
            owner = pod.metadata.owner_references[0]
            owner_kind = owner.kind
            owner_name = owner.name

        # Resource limits
        has_limits = False
        limits = None
        if container and container.resources and container.resources.limits:
            has_limits = True
            limits = {
                "cpu": container.resources.limits.get("cpu"),
                "memory": container.resources.limits.get("memory"),
            }

        return {
            "pod_name": pod_name,
            "namespace": namespace,
            "node": pod.spec.node_name,
            "image": container.image if container else None,
            "restart_count": container_status.restart_count if container_status else 0,
            "owner_kind": owner_kind,
            "owner_name": owner_name,
            "pod_age_hours": age_hours,
            "namespace_labels": dict(ns.metadata.labels or {}),
            "has_resource_limits": has_limits,
            "resource_limits": limits,
            "service_account": pod.spec.service_account_name,
            "pod_phase": pod.status.phase if pod.status else None,
        }

    except Exception as e:
        log.warning("pod_context_fetch_failed", pod=pod_name, namespace=namespace, error=str(e))
        return None


async def fetch_recent_logs(namespace: str, pod_name: str, minutes: int = 10) -> list[str] | None:
    """
    Fetch recent pod logs from Loki via LogQL.

    Query: {namespace="<ns>", pod="<pod>"} last <minutes> minutes
    Returns: list of log lines (max 50), newest first
    """
    if not namespace or not pod_name:
        return None

    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)

        params = {
            "query": f'{{namespace="{namespace}", pod="{pod_name}"}}',
            "start": str(int(start.timestamp() * 1e9)),
            "end": str(int(end.timestamp() * 1e9)),
            "limit": "50",
            "direction": "backward",
        }

        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params=params,
            )
            response.raise_for_status()
            data = response.json()

        lines = []
        for stream in data.get("data", {}).get("result", []):
            for _, line in stream.get("values", []):
                lines.append(line)

        return lines[:50] if lines else []

    except Exception as e:
        log.warning("loki_fetch_failed", pod=pod_name, namespace=namespace, error=str(e))
        return None


async def fetch_network_flows(namespace: str, pod_name: str, minutes: int = 10) -> list[dict] | None:
    """
    Fetch recent network flows for the pod from Hubble REST API.

    Returns flows showing what the pod was talking to — critical for
    detecting C2 communication, lateral movement, data exfiltration.
    """
    if not namespace or not pod_name:
        return None

    try:
        params = {
            "blacklist": "false",
            "follow": "false",
            "since": f"{minutes}m",
            "pod_name": pod_name,
            "namespace": namespace,
        }

        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(
                f"{HUBBLE_URL}/api/v1/flows",
                params=params,
            )
            response.raise_for_status()
            data = response.json()

        flows = []
        for flow in data.get("flows", [])[:20]:
            flows.append({
                "source": flow.get("source", {}).get("identity"),
                "destination": flow.get("destination", {}).get("identity"),
                "verdict": flow.get("verdict"),
                "protocol": flow.get("l4", {}).get("TCP") and "TCP" or flow.get("l4", {}).get("UDP") and "UDP",
                "dst_port": (
                    flow.get("l4", {}).get("TCP", {}).get("destination_port") or
                    flow.get("l4", {}).get("UDP", {}).get("destination_port")
                ),
            })

        return flows

    except Exception as e:
        log.warning("hubble_fetch_failed", pod=pod_name, namespace=namespace, error=str(e))
        return None


async def fetch_policy_violations(namespace: str) -> list[dict] | None:
    """
    Fetch active Kyverno policy violations for the namespace.

    Uses the Kubernetes API to read PolicyReport resources.
    A pod with existing policy violations is higher risk.
    """
    if not namespace:
        return None

    try:
        k8s = _get_k8s_client()
        if not k8s:
            return None

        custom_api = k8s.CustomObjectsApi()
        loop = asyncio.get_event_loop()

        reports = await loop.run_in_executor(
            None,
            lambda: custom_api.list_namespaced_custom_object(
                group="wgpolicyk8s.io",
                version="v1alpha2",
                namespace=namespace,
                plural="policyreports",
            )
        )

        violations = []
        for report in reports.get("items", []):
            for result in report.get("results", []):
                if result.get("result") == "fail":
                    violations.append({
                        "policy": result.get("policy"),
                        "rule": result.get("rule"),
                        "message": result.get("message"),
                        "resource": result.get("resources", [{}])[0].get("name"),
                    })

        return violations[:10]

    except Exception as e:
        log.warning("kyverno_fetch_failed", namespace=namespace, error=str(e))
        return None


async def fetch_vulnerability_report(namespace: str, pod_name: str) -> dict | None:
    """
    Fetch Trivy vulnerability report for the pod's container image.
    Reads VulnerabilityReport CRDs from the Kubernetes API.
    """
    if not namespace or not pod_name:
        return None
    try:
        k8s = _get_k8s_client()
        if not k8s:
            return None
        custom_api = k8s.CustomObjectsApi()
        loop = asyncio.get_event_loop()
        reports = await loop.run_in_executor(
            None,
            lambda: custom_api.list_namespaced_custom_object(
                group="aquasecurity.github.io",
                version="v1alpha1",
                namespace=namespace,
                plural="vulnerabilityreports",
            )
        )
        total_critical = 0
        total_high = 0
        top_cves = []
        for report in reports.get("items", []):
            if pod_name in report.get("metadata", {}).get("name", ""):
                summary = report.get("report", {}).get("summary", {})
                total_critical += summary.get("criticalCount", 0)
                total_high += summary.get("highCount", 0)
                vulns = report.get("report", {}).get("vulnerabilities", [])
                for v in vulns[:3]:
                    if v.get("severity") in ("CRITICAL", "HIGH"):
                        top_cves.append({
                            "id": v.get("vulnerabilityID"),
                            "severity": v.get("severity"),
                            "package": v.get("resource"),
                            "fixed_version": v.get("fixedVersion"),
                        })
        return {
            "critical_count": total_critical,
            "high_count": total_high,
            "top_cves": top_cves[:5],
            "risk_score": min(100, total_critical * 20 + total_high * 5),
        }
    except Exception as e:
        log.warning("trivy_fetch_failed", pod=pod_name, namespace=namespace, error=str(e))
        return None


async def enrich_context(alert_payload: dict) -> dict:
    """
    Main enrichment entry point. Runs all data source queries concurrently.

    Args:
        alert_payload: Normalized alert dict from webhook.py

    Returns:
        Enriched context dict with all available data.
        Missing data sources return None — never raises exceptions.

    Context schema:
    {
        "alert": <original alert>,
        "pod": <K8s pod context or None>,
        "logs": <list of log lines or None>,
        "flows": <list of network flows or None>,
        "violations": <list of policy violations or None>,
        "enrichment_duration_ms": <int>,
        "enrichment_sources": <list of successful sources>,
    }
    """
    start = asyncio.get_event_loop().time()

    fields = alert_payload.get("fields", {})
    namespace = fields.get("k8s_ns_name") or alert_payload.get("raw_fields", {}).get("k8s.ns.name")
    pod_name = fields.get("k8s_pod_name") or alert_payload.get("raw_fields", {}).get("k8s.pod.name")

    log.info(
        "enrichment_started",
        rule=alert_payload.get("rule"),
        namespace=namespace,
        pod=pod_name,
    )

    # Run all queries concurrently with timeout
    try:
        pod_ctx, logs, flows, violations, vuln_report = await asyncio.wait_for(
            asyncio.gather(
                fetch_pod_context(namespace, pod_name),
                fetch_recent_logs(namespace, pod_name),
                fetch_network_flows(namespace, pod_name),
                fetch_policy_violations(namespace),
                fetch_vulnerability_report(namespace, pod_name),
                return_exceptions=True,
            ),
            timeout=ENRICHMENT_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log.warning("enrichment_timeout", timeout=ENRICHMENT_TIMEOUT)
        pod_ctx = logs = flows = violations = vuln_report = None

    # Handle exceptions from individual queries (return_exceptions=True)
    if isinstance(pod_ctx, Exception):
        pod_ctx = None
    if isinstance(logs, Exception):
        logs = None
    if isinstance(flows, Exception):
        flows = None
    if isinstance(violations, Exception):
        violations = None
    if isinstance(vuln_report, Exception):
        vuln_report = None

    duration_ms = round((asyncio.get_event_loop().time() - start) * 1000)

    successful_sources = [
        src for src, val in [
            ("kubernetes", pod_ctx),
            ("loki", logs),
            ("hubble", flows),
            ("kyverno", violations),
            ("trivy", vuln_report),
        ]
        if val is not None
    ]

    log.info(
        "enrichment_complete",
        rule=alert_payload.get("rule"),
        sources=successful_sources,
        duration_ms=duration_ms,
    )

    return {
        "alert": alert_payload,
        "pod": pod_ctx,
        "logs": logs,
        "flows": flows,
        "violations": violations,
        "vulnerabilities": vuln_report,
        "enrichment_duration_ms": duration_ms,
        "enrichment_sources": successful_sources,
    }
