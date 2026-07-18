"""Contract and failure-isolation tests for SOG publishing."""

import os
import sys
from uuid import UUID

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import world_model


class FakeClient:
    responses: list[httpx.Response | Exception] = []
    requests: list[tuple[str, str, dict]] = []

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def request(self, method: str, url: str, json: dict):
        self.requests.append((method, url, json))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(status_code: int, body: dict | None = None) -> httpx.Response:
    request = httpx.Request("POST", "http://world-model.test")
    if body is None:
        return httpx.Response(status_code, text="failure", request=request)
    return httpx.Response(status_code, json=body, request=request)


@pytest.fixture(autouse=True)
def world_model_client(monkeypatch):
    FakeClient.responses = []
    FakeClient.requests = []
    monkeypatch.setattr(world_model.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(world_model.app_config, "WORLD_MODEL_URL", "http://world-model.test")


def finding_args(**overrides):
    values = {
        "dedup_key": "0123456789abcdef",
        "raw_fields": {
            "k8s.ns.name": "production",
            "k8s.pod.name": "api-gateway-abc",
            "proc.name": "bash",
        },
        "rule": "Shell Spawned in Container",
        "priority": "Critical",
        "alert_time": "2026-07-17T12:00:00Z",
        "output": "Unexpected shell spawned",
        "tags": ["T1059.004"],
        "hostname": "k3s-worker1",
        "assessment": {"confidence": 0.94},
    }
    return {**values, **overrides}


def test_event_id_is_stable_uuid_and_changes_with_alert_identity():
    first = world_model.event_id("dedup-a", "2026-07-17T12:00:00Z")
    replay = world_model.event_id("dedup-a", "2026-07-17T12:00:00Z")
    another_alert = world_model.event_id("dedup-a", "2026-07-17T12:01:00Z")
    another_workload = world_model.event_id("dedup-b", "2026-07-17T12:00:00Z")

    assert UUID(first).version == 5
    assert first == replay
    assert first != another_alert
    assert first != another_workload


def test_entity_id_prefers_pod_and_falls_back_to_node():
    assert world_model.entity_id(finding_args()["raw_fields"]) == "pod/production/api-gateway-abc"
    assert world_model.entity_id({}, "k3s-worker2") == "node/cluster/k3s-worker2"
    assert world_model.entity_id({}) is None


@pytest.mark.asyncio
async def test_post_finding_uses_world_model_contract():
    FakeClient.responses = [response(200, {"status": "accepted"})]

    result = await world_model.post_finding(**finding_args())

    assert result["status"] == "accepted"
    assert result["entity_id"] == "pod/production/api-gateway-abc"
    method, url, body = FakeClient.requests[0]
    assert method == "POST"
    assert url == "http://world-model.test/findings"
    assert UUID(body["event_id"]).version == 5
    assert body["type"] == "finding"
    assert body["source"] == "argus"
    assert body["severity"] == "critical"
    assert body["payload"]["finding_type"] == "falco_alert"
    assert body["payload"]["description"] == "Unexpected shell spawned"
    assert body["payload"]["provenance"] == "observed"


@pytest.mark.asyncio
async def test_post_finding_preserves_explicit_correlation_id():
    FakeClient.responses = [response(200, {"status": "accepted"})]
    await world_model.post_finding(**finding_args(correlation_id="case-argus-phoenix-1"))
    body = FakeClient.requests[0][2]
    assert body["correlation_id"] == "case-argus-phoenix-1"


@pytest.mark.asyncio
async def test_duplicate_is_successful_idempotent_outcome():
    FakeClient.responses = [response(200, {"status": "duplicate"})]

    result = await world_model.post_finding(**finding_args())

    assert result["status"] == "duplicate"
    assert result["attempts"] == 1


@pytest.mark.asyncio
async def test_disabled_world_model_is_non_fatal(monkeypatch):
    monkeypatch.setattr(world_model.app_config, "WORLD_MODEL_URL", "")

    result = await world_model.post_finding(**finding_args())

    assert result["status"] == "disabled"
    assert FakeClient.requests == []


@pytest.mark.asyncio
async def test_server_error_retries_then_reports_failure(monkeypatch):
    FakeClient.responses = [response(503), response(503)]

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(world_model.asyncio, "sleep", no_sleep)
    result = await world_model.post_finding(**finding_args())

    assert result["status"] == "failed"
    assert result["reason"] == "http_error"
    assert result["attempts"] == 2
    assert len(FakeClient.requests) == 2


@pytest.mark.asyncio
async def test_transport_error_retries_without_escaping(monkeypatch):
    error = httpx.ConnectError("connection refused", request=httpx.Request("POST", "http://world-model.test"))
    FakeClient.responses = [error, error]

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(world_model.asyncio, "sleep", no_sleep)
    result = await world_model.post_finding(**finding_args())

    assert result["status"] == "failed"
    assert result["reason"] == "transport_error"
    assert result["attempts"] == 2


@pytest.mark.asyncio
async def test_patch_posture_reports_missing_entity_and_http_failure():
    assert await world_model.patch_entity_posture("", "critical") == {
        "status": "skipped",
        "reason": "missing_entity",
    }

    FakeClient.responses = [response(404)]
    result = await world_model.patch_entity_posture("pod/default/missing", "high-risk")

    assert result["status"] == "failed"
    assert result["status_code"] == 404


def test_posture_mapping_skips_false_positives():
    assert world_model.security_posture_for_decision("CRITICAL", False) == "critical"
    assert world_model.security_posture_for_decision("HIGH", False) == "high-risk"
    assert world_model.security_posture_for_decision("MED", False) == "medium-risk"
    assert world_model.security_posture_for_decision("CRITICAL", True) is None
