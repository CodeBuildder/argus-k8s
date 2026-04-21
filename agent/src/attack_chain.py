"""
Argus Agent — attack chain correlation engine
Copyright (c) 2026 Kaushikkumaran

Correlates individual Falco alerts into multi-stage attack chains.
Uses a 30-minute sliding window to group related alerts by namespace/node.

MITRE ATT&CK kill chain stages mapped to Falco rules:
  Reconnaissance    → port scans, service enumeration
  Initial Access    → shell spawn, unexpected process
  Execution         → curl/wget, script execution, memfd
  Persistence       → cron modification, startup file write
  Privilege Escalation → capability grant, sudo, SUID
  Lateral Movement  → cross-namespace traffic, SSH
  Exfiltration      → large outbound transfer, DNS tunneling
  Defense Evasion   → log clearing, binary deletion
"""

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
import structlog

log = structlog.get_logger()

CHAIN_WINDOW_SECONDS = 1800  # 30 minutes
MAX_CHAINS = 50

# MITRE kill chain stage mapping
RULE_TO_STAGE = {
    "fileless execution via memfd_create": "Execution",
    "shell spawned in container": "Initial Access",
    "reverse shell": "Initial Access",
    "curl or wget executed in container": "Execution",
    "crypto miner process": "Execution",
    "process hollowing": "Execution",
    "syscall injection": "Execution",
    "read sensitive file untrusted": "Reconnaissance",
    "sensitive file read": "Reconnaissance",
    "port scan": "Reconnaissance",
    "write below etc": "Persistence",
    "write below binary": "Persistence",
    "binary modified": "Persistence",
    "clear log activities": "Defense Evasion",
    "log tampering": "Defense Evasion",
    "contact k8s api server from container": "Reconnaissance",
    "api server credentials stolen": "Privilege Escalation",
    "network tool launched in container": "Reconnaissance",
    "modify binary dirs": "Persistence",
    "sudo potential privilege escalation": "Privilege Escalation",
    "privilege escalation": "Privilege Escalation",
    "kernel memory access": "Privilege Escalation",
    "launch privileged container": "Privilege Escalation",
    "outbound connection to c2 server": "Exfiltration",
    "outbound c2": "Exfiltration",
    "c2 callback": "Exfiltration",
    "dns tunneling": "Exfiltration",
    "ssrf to cloud metadata": "Exfiltration",
    "exfiltration over alternative protocol": "Exfiltration",
    "lateral movement": "Lateral Movement",
    "container escape attempt": "Privilege Escalation",
    "ptrace attached to process": "Execution",
}

STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Persistence",
    "Defense Evasion",
    "Lateral Movement",
    "Exfiltration",
]

STAGE_MITRE = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Privilege Escalation": "TA0004",
    "Persistence": "TA0003",
    "Defense Evasion": "TA0005",
    "Lateral Movement": "TA0008",
    "Exfiltration": "TA0010",
}

# In-memory chain store
attack_chains: list[dict] = []

# Active correlation windows: key → list of alerts
_windows: dict[str, list[dict]] = defaultdict(list)


def _correlation_key(audit_entry: dict) -> str:
    """Group alerts by namespace+node — same attacker likely in same area."""
    ns = audit_entry.get("namespace") or "host"
    node = audit_entry.get("hostname") or "unknown"
    return f"{ns}:{node}"


def _get_stage(rule: str) -> str:
    """Map Falco rule name to MITRE kill chain stage."""
    rule_lower = rule.lower()
    for pattern, stage in RULE_TO_STAGE.items():
        if pattern in rule_lower:
            return stage
    return "Execution"  # Default assumption


def _chain_confidence(stages: list[str]) -> float:
    """
    More stages = higher confidence this is a real attack.
    Single stage: low confidence.
    3+ distinct stages: high confidence.
    """
    distinct = len(set(stages))
    if distinct == 1:
        return 0.35
    elif distinct == 2:
        return 0.60
    elif distinct == 3:
        return 0.80
    else:
        return min(0.95, 0.80 + (distinct - 3) * 0.05)


def _build_chain(key: str, alerts: list[dict]) -> dict:
    """Build a chain object from correlated alerts."""
    stages = [a["stage"] for a in alerts]
    stage_order_indices = {s: i for i, s in enumerate(STAGE_ORDER)}
    sorted_stages = sorted(set(stages), key=lambda s: stage_order_indices.get(s, 99))

    first_ts = min(a["ts"] for a in alerts)
    last_ts = max(a["ts"] for a in alerts)
    duration_seconds = int(last_ts - first_ts)

    ns = alerts[0].get("namespace") or "host"
    node = alerts[0].get("hostname") or "unknown"
    pod = alerts[0].get("pod") or "unknown"

    chain_id = hashlib.md5(f"{key}{first_ts}".encode()).hexdigest()[:12]

    return {
        "id": chain_id,
        "created_at": datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat(),
        "last_seen": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat(),
        "duration_seconds": duration_seconds,
        "namespace": ns,
        "hostname": node,
        "pod": pod,
        "alert_count": len(alerts),
        "stages_detected": sorted_stages,
        "stage_count": len(sorted_stages),
        "confidence": _chain_confidence(stages),
        "severity": "CRITICAL" if len(sorted_stages) >= 3 else "HIGH" if len(sorted_stages) == 2 else "MED",
        "alerts": [
            {
                "rule": a["rule"],
                "stage": a["stage"],
                "mitre_tactic": STAGE_MITRE.get(a["stage"], ""),
                "ts": a["ts"],
                "severity": a.get("severity", "MED"),
            }
            for a in sorted(alerts, key=lambda x: x["ts"])
        ],
        "mitre_tactics": [STAGE_MITRE.get(s, "") for s in sorted_stages],
    }


def correlate_alert(audit_entry: dict) -> dict | None:
    """
    Add alert to correlation window.
    Returns a chain object if a new chain is detected, None otherwise.
    """
    now = time.time()
    key = _correlation_key(audit_entry)

    alert_entry = {
        "rule": audit_entry.get("rule", "unknown"),
        "stage": _get_stage(audit_entry.get("rule", "")),
        "ts": now,
        "severity": audit_entry.get("severity", "MED"),
        "namespace": audit_entry.get("namespace"),
        "hostname": audit_entry.get("hostname"),
        "pod": audit_entry.get("pod"),
    }

    # Evict expired alerts from window
    _windows[key] = [
        a for a in _windows[key]
        if now - a["ts"] < CHAIN_WINDOW_SECONDS
    ]

    _windows[key].append(alert_entry)

    # Need at least 2 alerts to form a chain
    if len(_windows[key]) < 2:
        return None

    stages = [a["stage"] for a in _windows[key]]
    distinct_stages = set(stages)

    # Only create chain if we see 2+ distinct kill chain stages
    if len(distinct_stages) < 2:
        return None

    chain = _build_chain(key, _windows[key])

    # Update or add chain
    existing = next((c for c in attack_chains if c["id"] == chain["id"]), None)
    if existing:
        existing.update(chain)
    else:
        attack_chains.append(chain)
        if len(attack_chains) > MAX_CHAINS:
            attack_chains.pop(0)
        log.info(
            "attack_chain_detected",
            chain_id=chain["id"],
            stages=chain["stages_detected"],
            confidence=chain["confidence"],
            namespace=chain["namespace"],
            alert_count=chain["alert_count"],
        )

    return chain
