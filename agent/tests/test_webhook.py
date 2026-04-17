"""
Tests for the Falco webhook receiver.
Copyright (c) 2026 Kaushikkumaran
"""

import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import app
from webhook import dedup_cache, FalcoAlert, FalcoOutputFields, is_duplicate

client = TestClient(app)

VALID_ALERT = {
    "rule": "Read sensitive file untrusted",
    "priority": "Warning",
    "time": "2026-04-15T06:00:00.000000000Z",
    "output": "Warning: Sensitive file opened for reading by non-trusted program",
    "hostname": "k3s-worker1",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem"],
    "output_fields": {
        "k8s.pod.name": "test-pod",
        "k8s.ns.name": "prod",
        "proc.name": "cat",
        "proc.cmdline": "cat /etc/shadow",
        "container.image.repository": "docker.io/library/ubuntu",
        "container.image.tag": "latest",
        "fd.name": "/etc/shadow",
        "user.name": "root",
        "user.uid": 0,
    }
}


class TestWebhookEndpoint:
    def test_health_endpoint(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_valid_alert_accepted(self):
        dedup_cache.clear()
        response = client.post("/falco/webhook", json=VALID_ALERT)
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert data["rule"] == "Read sensitive file untrusted"
        assert data["priority"] == "Warning"

    def test_invalid_alert_missing_rule(self):
        bad_alert = {**VALID_ALERT}
        del bad_alert["rule"]
        response = client.post("/falco/webhook", json=bad_alert)
        assert response.status_code == 422

    def test_invalid_alert_missing_priority(self):
        bad_alert = {**VALID_ALERT}
        del bad_alert["priority"]
        response = client.post("/falco/webhook", json=bad_alert)
        assert response.status_code == 422

    def test_invalid_alert_missing_time(self):
        bad_alert = {**VALID_ALERT}
        del bad_alert["time"]
        response = client.post("/falco/webhook", json=bad_alert)
        assert response.status_code == 422

    def test_invalid_alert_empty_rule(self):
        bad_alert = {**VALID_ALERT, "rule": "   "}
        response = client.post("/falco/webhook", json=bad_alert)
        assert response.status_code == 422

    def test_priority_normalization_lowercase(self):
        alert = {**VALID_ALERT, "priority": "warning"}
        dedup_cache.clear()
        response = client.post("/falco/webhook", json=alert)
        assert response.status_code == 202

    def test_priority_normalization_critical(self):
        alert = {**VALID_ALERT, "priority": "critical"}
        dedup_cache.clear()
        response = client.post("/falco/webhook", json=alert)
        assert response.status_code == 202
        assert response.json()["priority"] == "Critical"

    def test_duplicate_alert_suppressed(self):
        dedup_cache.clear()
        response1 = client.post("/falco/webhook", json=VALID_ALERT)
        assert response1.status_code == 202
        assert response1.json()["status"] == "accepted"

        response2 = client.post("/falco/webhook", json=VALID_ALERT)
        assert response2.status_code == 202
        assert response2.json()["status"] == "deduplicated"

    def test_different_pods_not_deduplicated(self):
        dedup_cache.clear()
        alert1 = {**VALID_ALERT}
        alert1["output_fields"] = {**VALID_ALERT["output_fields"], "k8s.pod.name": "pod-aaa"}

        alert2 = {**VALID_ALERT}
        alert2["output_fields"] = {**VALID_ALERT["output_fields"], "k8s.pod.name": "pod-bbb"}

        r1 = client.post("/falco/webhook", json=alert1)
        r2 = client.post("/falco/webhook", json=alert2)

        assert r1.json()["status"] == "accepted"
        assert r2.json()["status"] == "accepted"


class TestFalcoAlertModel:
    def test_dedup_key_consistent(self):
        alert = FalcoAlert(**VALID_ALERT)
        key1 = alert.dedup_key()
        key2 = alert.dedup_key()
        assert key1 == key2

    def test_dedup_key_differs_by_pod(self):
        a1 = FalcoAlert(**{**VALID_ALERT, "output_fields": {**VALID_ALERT["output_fields"], "k8s.pod.name": "pod-a"}})
        a2 = FalcoAlert(**{**VALID_ALERT, "output_fields": {**VALID_ALERT["output_fields"], "k8s.pod.name": "pod-b"}})
        assert a1.dedup_key() != a2.dedup_key()

    def test_output_fields_mapped_correctly(self):
        alert = FalcoAlert(**VALID_ALERT)
        payload = alert.to_enricher_payload()
        assert payload["fields"]["k8s_pod_name"] == "test-pod"
        assert payload["fields"]["k8s_ns_name"] == "prod"
        assert payload["fields"]["proc_name"] == "cat"
        assert payload["fields"]["fd_name"] == "/etc/shadow"


class TestOutputFieldsMapping:
    def test_from_falco_maps_dot_notation(self):
        fields = FalcoOutputFields.from_falco(VALID_ALERT["output_fields"])
        assert fields.k8s_pod_name == "test-pod"
        assert fields.k8s_ns_name == "prod"
        assert fields.proc_name == "cat"
        assert fields.fd_name == "/etc/shadow"
        assert fields.user_name == "root"
        assert fields.user_uid == 0

    def test_missing_fields_are_none(self):
        fields = FalcoOutputFields.from_falco({})
        assert fields.k8s_pod_name is None
        assert fields.container_id is None


class TestDeduplication:
    def test_first_alert_not_duplicate(self):
        dedup_cache.clear()
        alert = FalcoAlert(**VALID_ALERT)
        assert is_duplicate(alert, window_seconds=300) is False

    def test_second_alert_is_duplicate(self):
        dedup_cache.clear()
        alert = FalcoAlert(**VALID_ALERT)
        is_duplicate(alert, window_seconds=300)
        assert is_duplicate(alert, window_seconds=300) is True

    def test_alert_not_duplicate_after_window(self):
        dedup_cache.clear()
        alert = FalcoAlert(**VALID_ALERT)
        key = alert.dedup_key()
        dedup_cache[key] = time.time() - 400
        assert is_duplicate(alert, window_seconds=300) is False
