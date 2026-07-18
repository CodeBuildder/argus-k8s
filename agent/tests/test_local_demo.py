"""Regression coverage for the explicitly cluster-free local demo mode."""

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from main import app


client = TestClient(app)


def test_health_reports_local_demo_mode(monkeypatch):
    monkeypatch.setenv("ARGUS_LOCAL_DEMO", "true")

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["mode"] == "local_demo"


def test_cluster_overview_uses_fallback_without_kubernetes(monkeypatch):
    monkeypatch.setenv("ARGUS_LOCAL_DEMO", "true")

    response = client.get("/cluster-overview")

    assert response.status_code == 200
    assert response.json()["cluster_source"] == "node_telemetry_fallback"


def test_infra_observability_uses_fallback_without_kubernetes(monkeypatch):
    monkeypatch.setenv("ARGUS_LOCAL_DEMO", "true")

    response = client.get("/infra-observability")

    assert response.status_code == 200
    assert response.json()["source"] == "incident_fallback"
