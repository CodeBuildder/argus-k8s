"""
Tests for the AI reasoning layer.
Copyright (c) 2026 Kaushikkumaran

Uses mocked Anthropic API responses — no real API calls in tests.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from reasoning import (
    reason_about_threat,
    AgentDecision,
    SeverityLevel,
    RecommendedAction,
    _default_decision,
    _build_user_prompt,
    _select_model,
    SONNET_MODEL,
    OPUS_MODEL,
)

SAMPLE_CONTEXT = {
    "alert": {
        "rule": "Read sensitive file untrusted",
        "priority": "Warning",
        "time": "2026-04-15T06:00:00Z",
        "output": "Warning: Sensitive file opened",
        "hostname": "k3s-worker1",
        "tags": ["T1555", "filesystem"],
        "fields": {
            "k8s_pod_name": "payment-service-7f9b",
            "k8s_ns_name": "prod",
            "proc_name": "cat",
            "proc_cmdline": "cat /etc/shadow",
            "proc_pname": "bash",
            "fd_name": "/etc/shadow",
            "user_name": "root",
            "user_uid": 0,
            "container_image_repository": "docker.io/library/nginx",
            "container_image_tag": "alpine",
        },
        "raw_fields": {}
    },
    "pod": {
        "pod_name": "payment-service-7f9b",
        "namespace": "prod",
        "node": "k3s-worker1",
        "image": "docker.io/library/nginx:alpine",
        "restart_count": 0,
        "owner_kind": "Deployment",
        "owner_name": "payment-service",
        "pod_age_hours": 336.0,
        "namespace_labels": {"environment": "prod"},
        "has_resource_limits": True,
        "service_account": "default",
        "pod_phase": "Running",
    },
    "logs": ["GET /api/v1/health 200", "GET /api/v1/payments 200"],
    "flows": [
        {"source": "payment-service", "destination": "postgres", "verdict": "FORWARDED", "protocol": "TCP", "dst_port": 5432}
    ],
    "violations": [],
    "enrichment_sources": ["kubernetes", "loki", "hubble", "kyverno"],
    "enrichment_duration_ms": 245,
}

VALID_MODEL_RESPONSE = json.dumps({
    "severity": "HIGH",
    "confidence": 0.85,
    "assessment": "Shell process cat read /etc/shadow in a prod nginx container. This is highly unusual for a web server. The pod has been stable for 14 days with no restarts, suggesting external compromise rather than misconfiguration.",
    "likely_false_positive": False,
    "recommended_action": "ISOLATE",
    "blast_radius": "Payment service is in prod namespace with access to postgres. Compromise could expose customer payment data.",
    "suppress_minutes": None,
})


def make_mock_response(content_text: str):
    mock_usage = MagicMock()
    mock_usage.input_tokens = 500
    mock_usage.output_tokens = 150
    mock_usage.cache_read_input_tokens = 400
    mock_usage.cache_creation_input_tokens = 100

    mock_content = MagicMock()
    mock_content.text = content_text

    mock_response = MagicMock()
    mock_response.content = [mock_content]
    mock_response.usage = mock_usage
    return mock_response


class TestReasonAboutThreat:
    async def test_valid_response_returns_decision(self):
        mock_response = make_mock_response(VALID_MODEL_RESPONSE)

        with patch("anthropic.AsyncAnthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            decision = await reason_about_threat(SAMPLE_CONTEXT, "test-key")

        assert isinstance(decision, AgentDecision)
        assert decision.severity == SeverityLevel.HIGH
        assert decision.confidence == 0.85
        assert decision.recommended_action == RecommendedAction.ISOLATE
        assert decision.likely_false_positive is False

    async def test_invalid_json_returns_default_decision(self):
        mock_response = make_mock_response("this is not json at all")

        with patch("anthropic.AsyncAnthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            decision = await reason_about_threat(SAMPLE_CONTEXT, "test-key")

        assert decision.recommended_action == RecommendedAction.HUMAN_REQUIRED
        assert decision.confidence == 0.0

    async def test_markdown_fenced_json_is_parsed(self):
        fenced = "```json\n" + VALID_MODEL_RESPONSE + "\n```"
        mock_response = make_mock_response(fenced)

        with patch("anthropic.AsyncAnthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            decision = await reason_about_threat(SAMPLE_CONTEXT, "test-key")

        assert decision.severity == SeverityLevel.HIGH

    async def test_api_error_returns_default_decision(self):
        import anthropic as anthropic_module

        with patch("anthropic.AsyncAnthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create = AsyncMock(
                side_effect=Exception("API unavailable")
            )

            decision = await reason_about_threat(SAMPLE_CONTEXT, "test-key")

        assert decision.recommended_action == RecommendedAction.HUMAN_REQUIRED

    async def test_confidence_clamped_to_range(self):
        response_data = json.loads(VALID_MODEL_RESPONSE)
        response_data["confidence"] = 1.5
        mock_response = make_mock_response(json.dumps(response_data))

        with patch("anthropic.AsyncAnthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            decision = await reason_about_threat(SAMPLE_CONTEXT, "test-key")

        assert decision.confidence <= 1.0


class TestModelSelection:
    def test_critical_uses_opus(self):
        alert = {"priority": "Critical"}
        assert _select_model(alert) == OPUS_MODEL

    def test_error_uses_opus(self):
        alert = {"priority": "Error"}
        assert _select_model(alert) == OPUS_MODEL

    def test_warning_uses_sonnet(self):
        alert = {"priority": "Warning"}
        assert _select_model(alert) == SONNET_MODEL

    def test_notice_uses_sonnet(self):
        alert = {"priority": "Notice"}
        assert _select_model(alert) == SONNET_MODEL

    def test_unknown_uses_sonnet(self):
        alert = {"priority": "unknown"}
        assert _select_model(alert) == SONNET_MODEL


class TestDefaultDecision:
    def test_default_is_human_required(self):
        decision = _default_decision("test reason")
        assert decision.recommended_action == RecommendedAction.HUMAN_REQUIRED
        assert decision.confidence == 0.0
        assert decision.severity == SeverityLevel.HIGH
        assert decision.likely_false_positive is False

    def test_default_contains_reason(self):
        decision = _default_decision("Loki is down")
        assert "Loki is down" in decision.assessment


class TestBuildUserPrompt:
    def test_prompt_contains_rule(self):
        prompt = _build_user_prompt(SAMPLE_CONTEXT)
        assert "Read sensitive file untrusted" in prompt

    def test_prompt_contains_pod_name(self):
        prompt = _build_user_prompt(SAMPLE_CONTEXT)
        assert "payment-service-7f9b" in prompt

    def test_prompt_contains_namespace(self):
        prompt = _build_user_prompt(SAMPLE_CONTEXT)
        assert "prod" in prompt

    def test_prompt_contains_command(self):
        prompt = _build_user_prompt(SAMPLE_CONTEXT)
        assert "cat /etc/shadow" in prompt

    def test_prompt_handles_missing_pod_context(self):
        context = {**SAMPLE_CONTEXT, "pod": None}
        prompt = _build_user_prompt(context)
        assert "Unavailable" in prompt

    def test_prompt_handles_missing_logs(self):
        context = {**SAMPLE_CONTEXT, "logs": None}
        prompt = _build_user_prompt(context)
        assert "Unavailable" in prompt

    def test_prompt_handles_empty_violations(self):
        context = {**SAMPLE_CONTEXT, "violations": []}
        prompt = _build_user_prompt(context)
        assert "None" in prompt


class TestAgentDecision:
    def test_valid_decision(self):
        d = AgentDecision(
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            assessment="Test assessment.",
            likely_false_positive=False,
            recommended_action=RecommendedAction.ISOLATE,
            blast_radius="Payment namespace.",
        )
        assert d.severity == SeverityLevel.HIGH

    def test_confidence_clamped_above(self):
        d = AgentDecision(
            severity=SeverityLevel.LOW,
            confidence=2.0,
            assessment="Test.",
            likely_false_positive=True,
            recommended_action=RecommendedAction.LOG,
            blast_radius="Minimal.",
        )
        assert d.confidence == 1.0

    def test_confidence_clamped_below(self):
        d = AgentDecision(
            severity=SeverityLevel.LOW,
            confidence=-0.5,
            assessment="Test.",
            likely_false_positive=True,
            recommended_action=RecommendedAction.LOG,
            blast_radius="Minimal.",
        )
        assert d.confidence == 0.0
