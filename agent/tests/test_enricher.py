"""
Tests for the context enricher.
Copyright (c) 2026 Kaushikkumaran

Uses mocks for all external dependencies (K8s API, Loki, Hubble).
Tests verify the enricher handles partial failures gracefully.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from enricher import (
    enrich_context,
    fetch_pod_context,
    fetch_recent_logs,
    fetch_network_flows,
    fetch_policy_violations,
)

SAMPLE_ALERT = {
    "rule": "Read sensitive file untrusted",
    "priority": "Warning",
    "time": "2026-04-15T06:00:00Z",
    "output": "Warning: Sensitive file opened",
    "fields": {
        "k8s_pod_name": "test-pod",
        "k8s_ns_name": "prod",
        "proc_name": "cat",
        "fd_name": "/etc/shadow",
    },
    "raw_fields": {
        "k8s.pod.name": "test-pod",
        "k8s.ns.name": "prod",
    }
}


class TestEnrichContext:
    async def test_returns_all_keys(self):
        with patch("enricher.fetch_pod_context", return_value={"pod_name": "test-pod"}), \
             patch("enricher.fetch_recent_logs", return_value=["log line 1"]), \
             patch("enricher.fetch_network_flows", return_value=[]), \
             patch("enricher.fetch_policy_violations", return_value=[]):
            result = await enrich_context(SAMPLE_ALERT)

        assert "alert" in result
        assert "pod" in result
        assert "logs" in result
        assert "flows" in result
        assert "violations" in result
        assert "enrichment_duration_ms" in result
        assert "enrichment_sources" in result

    async def test_partial_failure_doesnt_crash(self):
        """If Loki and Hubble fail, enricher still returns pod context."""
        with patch("enricher.fetch_pod_context", return_value={"pod_name": "test-pod"}), \
             patch("enricher.fetch_recent_logs", side_effect=Exception("Loki down")), \
             patch("enricher.fetch_network_flows", side_effect=Exception("Hubble down")), \
             patch("enricher.fetch_policy_violations", return_value=None):
            result = await enrich_context(SAMPLE_ALERT)

        assert result["pod"] is not None
        assert result["logs"] is None
        assert result["flows"] is None
        assert "kubernetes" in result["enrichment_sources"]
        assert "loki" not in result["enrichment_sources"]

    async def test_all_sources_fail_returns_empty_context(self):
        """If everything fails, enricher returns context with all None fields."""
        with patch("enricher.fetch_pod_context", return_value=None), \
             patch("enricher.fetch_recent_logs", return_value=None), \
             patch("enricher.fetch_network_flows", return_value=None), \
             patch("enricher.fetch_policy_violations", return_value=None):
            result = await enrich_context(SAMPLE_ALERT)

        assert result["pod"] is None
        assert result["logs"] is None
        assert result["flows"] is None
        assert result["enrichment_sources"] == []
        assert result["alert"] == SAMPLE_ALERT

    async def test_enrichment_sources_tracked(self):
        with patch("enricher.fetch_pod_context", return_value={"pod_name": "test-pod"}), \
             patch("enricher.fetch_recent_logs", return_value=["line"]), \
             patch("enricher.fetch_network_flows", return_value=None), \
             patch("enricher.fetch_policy_violations", return_value=[]):
            result = await enrich_context(SAMPLE_ALERT)

        assert "kubernetes" in result["enrichment_sources"]
        assert "loki" in result["enrichment_sources"]
        assert "hubble" not in result["enrichment_sources"]

    async def test_missing_pod_name_in_alert(self):
        """Alert with no pod name should still return without crashing."""
        alert_no_pod = {**SAMPLE_ALERT, "fields": {}, "raw_fields": {}}
        with patch("enricher.fetch_pod_context", return_value=None), \
             patch("enricher.fetch_recent_logs", return_value=None), \
             patch("enricher.fetch_network_flows", return_value=None), \
             patch("enricher.fetch_policy_violations", return_value=None):
            result = await enrich_context(alert_no_pod)
        assert result is not None


class TestFetchRecentLogs:
    async def test_returns_log_lines(self):
        mock_response = {
            "data": {
                "result": [
                    {"values": [["1234567890", "log line 1"], ["1234567891", "log line 2"]]}
                ]
            }
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(
                return_value=MagicMock(
                    status_code=200,
                    json=lambda: mock_response,
                    raise_for_status=lambda: None,
                )
            )
            result = await fetch_recent_logs("prod", "test-pod")

        assert result is not None
        assert "log line 1" in result

    async def test_loki_failure_returns_none(self):
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(side_effect=Exception("connection refused"))
            result = await fetch_recent_logs("prod", "test-pod")

        assert result is None

    async def test_missing_namespace_returns_none(self):
        result = await fetch_recent_logs(None, "test-pod")
        assert result is None

    async def test_missing_pod_returns_none(self):
        result = await fetch_recent_logs("prod", None)
        assert result is None


class TestFetchPodContext:
    async def test_k8s_unavailable_returns_none(self):
        with patch("enricher._get_k8s_client", return_value=None):
            result = await fetch_pod_context("prod", "test-pod")
        assert result is None

    async def test_missing_namespace_returns_none(self):
        result = await fetch_pod_context(None, "test-pod")
        assert result is None

    async def test_missing_pod_returns_none(self):
        result = await fetch_pod_context("prod", None)
        assert result is None

    async def test_k8s_error_returns_none(self):
        mock_k8s = MagicMock()
        mock_k8s.CoreV1Api.return_value.read_namespaced_pod.side_effect = Exception("not found")
        with patch("enricher._get_k8s_client", return_value=mock_k8s):
            result = await fetch_pod_context("prod", "nonexistent-pod")
        assert result is None


class TestFetchPolicyViolations:
    async def test_k8s_unavailable_returns_none(self):
        with patch("enricher._get_k8s_client", return_value=None):
            result = await fetch_policy_violations("prod")
        assert result is None

    async def test_missing_namespace_returns_none(self):
        result = await fetch_policy_violations(None)
        assert result is None

    async def test_no_violations_returns_empty_list(self):
        mock_k8s = MagicMock()
        mock_k8s.CustomObjectsApi.return_value.list_namespaced_custom_object.return_value = {
            "items": []
        }
        with patch("enricher._get_k8s_client", return_value=mock_k8s):
            result = await fetch_policy_violations("prod")
        assert result == []
