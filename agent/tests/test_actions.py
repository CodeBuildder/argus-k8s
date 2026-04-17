"""
Tests for the action router.
Copyright (c) 2026 Kaushikkumaran
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from actions import (
    action_log,
    action_notify,
    action_isolate,
    action_kill,
    action_human_required,
    route_action,
    approval_queue,
    KILL_CONFIDENCE_THRESHOLD,
)
from reasoning import AgentDecision, SeverityLevel, RecommendedAction


def make_decision(
    severity=SeverityLevel.HIGH,
    confidence=0.9,
    action=RecommendedAction.ISOLATE,
    false_positive=False,
):
    return AgentDecision(
        severity=severity,
        confidence=confidence,
        assessment="Test assessment.",
        likely_false_positive=false_positive,
        recommended_action=action,
        blast_radius="Test blast radius.",
    )


SAMPLE_ALERT = {
    "rule": "Shell spawned in container",
    "priority": "Warning",
    "time": "2026-04-15T06:00:00Z",
    "output": "Warning: shell spawned",
    "hostname": "k3s-worker1",
    "tags": ["T1059"],
    "fields": {
        "k8s_pod_name": "payment-service-7f9b",
        "k8s_ns_name": "prod",
        "proc_name": "bash",
        "proc_cmdline": "bash",
    },
    "raw_fields": {}
}


class TestActionLog:
    async def test_log_returns_completed(self):
        decision = make_decision(action=RecommendedAction.LOG)
        result = await action_log(SAMPLE_ALERT, decision)
        assert result["action"] == "LOG"
        assert result["status"] == "completed"


class TestActionNotify:
    async def test_notify_without_webhook_skips(self):
        decision = make_decision(action=RecommendedAction.NOTIFY)
        result = await action_notify(SAMPLE_ALERT, decision, webhook_url=None)
        assert result["action"] == "NOTIFY"
        assert result["status"] == "skipped"

    async def test_notify_with_webhook_sends(self):
        decision = make_decision(action=RecommendedAction.NOTIFY)
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.post = AsyncMock(
                return_value=MagicMock(status_code=200, raise_for_status=lambda: None)
            )
            result = await action_notify(SAMPLE_ALERT, decision, webhook_url="http://hooks.slack.com/test")
        assert result["status"] == "completed"

    async def test_notify_failure_returns_failed(self):
        decision = make_decision(action=RecommendedAction.NOTIFY)
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.post = AsyncMock(side_effect=Exception("connection refused"))
            result = await action_notify(SAMPLE_ALERT, decision, webhook_url="http://hooks.slack.com/test")
        assert result["status"] == "failed"


class TestActionIsolate:
    async def test_isolate_missing_pod_returns_failed(self):
        alert = {**SAMPLE_ALERT, "fields": {}}
        decision = make_decision()
        result = await action_isolate(alert, decision)
        assert result["status"] == "failed"

    async def test_isolate_applies_policy(self):
        decision = make_decision()
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=None)
            result = await action_isolate(SAMPLE_ALERT, decision)
        assert result["action"] == "ISOLATE"

    async def test_isolate_k8s_error_returns_failed(self):
        decision = make_decision()
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=Exception("k8s unavailable"))
            result = await action_isolate(SAMPLE_ALERT, decision)
        assert result["status"] == "failed"
        assert result["action"] == "ISOLATE"


class TestActionKill:
    async def test_kill_low_confidence_downgrades_to_isolate(self):
        decision = make_decision(
            action=RecommendedAction.KILL,
            confidence=0.5,
        )
        with patch("actions.action_isolate", return_value={"action": "ISOLATE", "status": "completed"}):
            result = await action_kill(SAMPLE_ALERT, decision)
        assert result.get("kill_downgraded") is True
        assert "kill_downgrade_reason" in result

    async def test_kill_high_confidence_executes(self):
        decision = make_decision(
            action=RecommendedAction.KILL,
            confidence=0.95,
        )
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=None)
            result = await action_kill(SAMPLE_ALERT, decision)
        assert result["action"] == "KILL"

    async def test_kill_threshold_boundary(self):
        decision_below = make_decision(confidence=KILL_CONFIDENCE_THRESHOLD - 0.01)
        decision_above = make_decision(confidence=KILL_CONFIDENCE_THRESHOLD)

        with patch("actions.action_isolate", return_value={"action": "ISOLATE", "status": "completed", "kill_downgraded": True}):
            result_below = await action_kill(SAMPLE_ALERT, decision_below)
        assert result_below.get("kill_downgraded") is True

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=None)
            result_above = await action_kill(SAMPLE_ALERT, decision_above)
        assert result_above["action"] == "KILL"


class TestActionHumanRequired:
    async def test_adds_to_approval_queue(self):
        approval_queue.clear()
        decision = make_decision(action=RecommendedAction.HUMAN_REQUIRED)
        result = await action_human_required(SAMPLE_ALERT, decision)
        assert result["status"] == "queued"
        assert len(approval_queue) == 1
        assert approval_queue[0]["status"] == "pending"

    async def test_queue_entry_has_required_fields(self):
        approval_queue.clear()
        decision = make_decision(action=RecommendedAction.HUMAN_REQUIRED)
        result = await action_human_required(SAMPLE_ALERT, decision)
        entry = approval_queue[0]
        assert "id" in entry
        assert "timestamp" in entry
        assert "alert" in entry
        assert "decision" in entry
        assert entry["pod"] == "payment-service-7f9b"
        assert entry["namespace"] == "prod"


class TestRouteAction:
    async def test_routes_log(self):
        decision = make_decision(action=RecommendedAction.LOG)
        result = await route_action(SAMPLE_ALERT, decision)
        assert result["action"] == "LOG"

    async def test_routes_human_required(self):
        approval_queue.clear()
        decision = make_decision(action=RecommendedAction.HUMAN_REQUIRED)
        result = await route_action(SAMPLE_ALERT, decision)
        assert result["action"] == "HUMAN_REQUIRED"
        assert result["status"] == "queued"

    async def test_routes_notify_without_webhook(self):
        decision = make_decision(action=RecommendedAction.NOTIFY)
        result = await route_action(SAMPLE_ALERT, decision, notify_webhook=None)
        assert result["action"] == "NOTIFY"
