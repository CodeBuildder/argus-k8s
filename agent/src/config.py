"""
Argus Agent — configuration
Copyright (c) 2026 Kaushikkumaran

All configuration loaded from environment variables.
Never hardcode secrets or cluster-specific values.
"""

import os
from pathlib import Path


def _load_local_env() -> None:
    """
    Best-effort .env loader for local development.
    Kubernetes deployments still use pod environment variables / secrets.
    Existing environment variables always win.
    """
    root_env = Path(__file__).resolve().parents[2] / ".env"
    if not root_env.exists():
        return

    for raw_line in root_env.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


class Config:
    # Anthropic API
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    AI_MODEL: str = os.getenv("AI_MODEL", "cl" + "aude-opus-4-5")

    # Deduplication
    DEDUP_WINDOW_SECONDS: int = int(os.getenv("DEDUP_WINDOW_SECONDS", "300"))

    # Kubernetes
    KUBECONFIG_PATH: str = os.getenv("KUBECONFIG", "")
    IN_CLUSTER: bool = os.getenv("IN_CLUSTER", "true").lower() == "true"

    # Loki
    LOKI_URL: str = os.getenv("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100")

    # Hubble
    HUBBLE_URL: str = os.getenv("HUBBLE_URL", "http://hubble-relay.kube-system.svc.cluster.local:4245")

    # Agent behavior
    AUTO_ISOLATE_CRITICAL: bool = os.getenv("AUTO_ISOLATE_CRITICAL", "false").lower() == "true"
    HUMAN_APPROVAL_TIMEOUT_SECONDS: int = int(os.getenv("HUMAN_APPROVAL_TIMEOUT_SECONDS", "300"))

    # Audit
    AUDIT_LOG_PATH: str = os.getenv("AUDIT_LOG_PATH", "/var/log/argus/audit.jsonl")

    @classmethod
    def validate(cls) -> None:
        if not cls.ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")


config = Config()
