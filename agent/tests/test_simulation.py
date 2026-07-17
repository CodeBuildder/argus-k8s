"""Tests for the deterministic threat and incident generator."""

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from main import app, incident_store


client = TestClient(app)


def _simulate(**overrides):
    payload = {"count": 5, "scenario": "mixed", "seed": 20260717, **overrides}
    return client.post("/simulate-threats", json=payload)


def test_seed_makes_generated_incident_selection_reproducible():
    incident_store.clear()
    first = _simulate().json()
    first_rules = [incident["rule"] for incident in incident_store]

    incident_store.clear()
    second = _simulate().json()
    second_rules = [incident["rule"] for incident in incident_store]

    assert first["seed"] == second["seed"] == 20260717
    assert first_rules == second_rules
    assert first["severity_distribution"] == second["severity_distribution"]
    assert first["action_distribution"] == second["action_distribution"]


def test_generated_timestamp_matches_incident_time():
    incident_store.clear()
    response = _simulate(count=1)

    assert response.status_code == 200
    incident = incident_store[-1]
    assert abs(incident["ts"] - __import__("datetime").datetime.fromisoformat(incident["timestamp"]).timestamp()) < 0.001


def test_human_approval_scenario_only_generates_review_actions():
    incident_store.clear()
    response = _simulate(count=4, scenario="human_approval")

    assert response.status_code == 200
    assert response.json()["action_distribution"] == {"HUMAN_REQUIRED": 4}


def test_rejects_invalid_count_and_scenario():
    assert _simulate(count=0).status_code == 422
    assert _simulate(count=101).status_code == 422
    assert _simulate(count="many").status_code == 422
    assert _simulate(scenario="unknown").status_code == 422


def test_server_generates_seed_when_omitted():
    incident_store.clear()
    response = client.post("/simulate-threats", json={"count": 1})

    assert response.status_code == 200
    assert isinstance(response.json()["seed"], int)
