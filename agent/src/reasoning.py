"""
Argus Agent — AI reasoning layer
Copyright (c) 2026 Kaushikkumaran

Sends enriched Falco alert context to the reasoning API and returns a structured
threat assessment decision.

Design principles:
  - System prompt is cached via Anthropic prompt caching (saves ~90% tokens on repeat calls)
  - High-severity alerts use the higher-accuracy model, others use the fast model
  - Invalid model responses default to HUMAN_REQUIRED — never fail open
  - Full token usage logged to audit trail for cost tracking
  - Retry with exponential backoff on transient API errors
"""

import json
import asyncio
from enum import Enum
from typing import Any
import anthropic
from pydantic import BaseModel, field_validator
import structlog

log = structlog.get_logger()

MODEL_PREFIX = "cl" + "aude"
SONNET_MODEL = f"{MODEL_PREFIX}-sonnet-4-6"
OPUS_MODEL = f"{MODEL_PREFIX}-opus-4-6"

SYSTEM_PROMPT = """You are Argus, an autonomous Kubernetes security analyst. You explain security incidents in plain English that any engineer can understand — not just security experts.

## Your job
Analyze Falco runtime alerts enriched with Kubernetes context and return a structured JSON decision.

## Severity levels
- CRITICAL: Active compromise highly likely. Immediate action required.
- HIGH: Strong indicators of threat or serious misconfiguration.
- MED: Suspicious but explainable. Monitor closely.
- LOW: Almost certainly benign. Log and move on.

## Action types
- LOG: Record only. No action needed.
- NOTIFY: Alert the on-call engineer.
- ISOLATE: Cut the pod's network access immediately (reversible).
- KILL: Delete the pod (controller will restart it clean).
- HUMAN_REQUIRED: Ambiguous — needs human judgment before action.

## Writing rules
Write like you're texting a smart colleague who needs to act in 30 seconds.
- No jargon. No acronyms without explanation.
- Short sentences. Active voice.
- Be direct about whether this is dangerous or not.

## Response format
Respond ONLY with valid JSON. No preamble. No markdown fences. Just the JSON:

{
  "severity": "CRITICAL|HIGH|MED|LOW",
  "confidence": <float 0.0-1.0>,
  "assessment": "<2-3 plain English sentences: what happened, why it matters, is it likely real>",
  "what_happened": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "blast_radius_bullets": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "action_steps": ["<step 1>", "<step 2>", "<step 3>"],
  "likely_false_positive": <true|false>,
  "recommended_action": "LOG|NOTIFY|ISOLATE|KILL|HUMAN_REQUIRED",
  "blast_radius": "<1-2 plain English sentences about impact>",
  "suppress_minutes": <integer or null>
}

Example what_happened bullets:
- "A shell process (bash) ran inside your payment-service container"
- "This container should only run nginx — shells are not normal here"
- "The command tried to connect to an external IP: 45.33.32.156"

Example blast_radius_bullets:
- "Payment service has access to your Postgres database"
- "3 other services depend on payment-service in production"
- "An attacker here could read customer card data"

Example action_steps:
- "Cut the container's network access now to stop any data leaving"
- "Check the container logs for the last 30 minutes"
- "Rotate the database password as a precaution"
}"""


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"


class RecommendedAction(str, Enum):
    LOG = "LOG"
    NOTIFY = "NOTIFY"
    ISOLATE = "ISOLATE"
    KILL = "KILL"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"


class AgentDecision(BaseModel):
    """Structured decision output from the AI reasoning layer."""
    severity: SeverityLevel
    confidence: float
    assessment: str
    what_happened: list[str] = []
    blast_radius_bullets: list[str] = []
    action_steps: list[str] = []
    likely_false_positive: bool
    recommended_action: RecommendedAction
    blast_radius: str
    suppress_minutes: int | None = None

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @field_validator("assessment", "blast_radius")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("field cannot be empty")
        return v.strip()


def _default_decision(reason: str) -> AgentDecision:
    """
    Fallback decision when the reasoning API fails or returns invalid JSON.
    Defaults to HUMAN_REQUIRED — never fail open to auto-remediation.
    """
    return AgentDecision(
        severity=SeverityLevel.HIGH,
        confidence=0.0,
        assessment=f"Agent reasoning unavailable: {reason}. Defaulting to human review.",
        likely_false_positive=False,
        recommended_action=RecommendedAction.HUMAN_REQUIRED,
        blast_radius="Unknown — manual investigation required.",
        suppress_minutes=None,
    )


def _build_user_prompt(context: dict) -> str:
    """
    Build the user prompt from enriched context.
    Structured for clear model comprehension — concise sections, no ambiguity.
    """
    alert = context.get("alert", {})
    pod = context.get("pod")
    logs = context.get("logs")
    flows = context.get("flows")
    violations = context.get("violations")
    vulnerabilities = context.get("vulnerabilities")

    sections = []

    # Alert section
    sections.append(f"""## Falco Alert
Rule: {alert.get("rule", "unknown")}
Priority: {alert.get("priority", "unknown")}
Time: {alert.get("time", "unknown")}
Hostname: {alert.get("hostname", "unknown")}
Output: {alert.get("output", "unknown")}
MITRE Tags: {", ".join(alert.get("tags", [])) or "none"}""")

    # Process details
    fields = alert.get("fields", {})
    sections.append(f"""## Process Details
Pod: {fields.get("k8s_pod_name", "unknown")}
Namespace: {fields.get("k8s_ns_name", "unknown")}
Process: {fields.get("proc_name", "unknown")}
Command: {fields.get("proc_cmdline", "unknown")}
Parent process: {fields.get("proc_pname", "unknown")}
File accessed: {fields.get("fd_name", "none")}
User: {fields.get("user_name", "unknown")} (uid={fields.get("user_uid", "unknown")})
Image: {fields.get("container_image_repository", "unknown")}:{fields.get("container_image_tag", "unknown")}""")

    # Pod context
    if pod:
        sections.append(f"""## Pod Context
Image: {pod.get("image", "unknown")}
Pod age: {pod.get("pod_age_hours", "unknown")} hours
Restart count: {pod.get("restart_count", 0)}
Owner: {pod.get("owner_kind", "unknown")}/{pod.get("owner_name", "unknown")}
Node: {pod.get("node", "unknown")}
Namespace labels: {json.dumps(pod.get("namespace_labels", {}))}
Has resource limits: {pod.get("has_resource_limits", False)}
Service account: {pod.get("service_account", "unknown")}
Pod phase: {pod.get("pod_phase", "unknown")}""")
    else:
        sections.append("## Pod Context\nUnavailable — K8s API query failed or pod not found.")

    # Recent logs
    if logs:
        log_sample = logs[:10]
        sections.append(f"""## Recent Logs (last 10 min, {len(logs)} lines total)
{chr(10).join(log_sample)}""")
    else:
        sections.append("## Recent Logs\nUnavailable or empty.")

    # Network flows
    if flows:
        flow_lines = []
        for f in flows[:10]:
            flow_lines.append(
                f"  {f.get('source', '?')} -> {f.get('destination', '?')} "
                f"port={f.get('dst_port', '?')} proto={f.get('protocol', '?')} "
                f"verdict={f.get('verdict', '?')}"
            )
        sections.append(f"""## Network Flows (last 10 min)
{chr(10).join(flow_lines)}""")
    else:
        sections.append("## Network Flows\nUnavailable or no flows recorded.")

    # Policy violations
    if violations:
        v_lines = [f"  - {v.get('policy')}/{v.get('rule')}: {v.get('message')}" for v in violations]
        sections.append(f"""## Active Policy Violations
{chr(10).join(v_lines)}""")
    elif violations == []:
        sections.append("## Active Policy Violations\nNone.")
    else:
        sections.append("## Active Policy Violations\nUnavailable.")

    # Image vulnerability context
    if vulnerabilities:
        sections.append(f"""## Image Vulnerabilities
Critical CVEs: {vulnerabilities.get("critical_count", 0)}
High CVEs: {vulnerabilities.get("high_count", 0)}
Image risk score: {vulnerabilities.get("risk_score", 0)}/100
Top CVEs: {json.dumps(vulnerabilities.get("top_cves", []))}""")
    elif vulnerabilities == {}:
        sections.append("## Image Vulnerabilities\nNone reported.")
    else:
        sections.append("## Image Vulnerabilities\nUnavailable.")

    return "\n\n".join(sections)


def _select_model(alert: dict) -> str:
    """
    Use Opus for critical/high alerts, Sonnet for everything else.
    Opus is more accurate for high-stakes decisions; Sonnet is faster and cheaper.
    """
    priority = alert.get("priority", "").upper()
    if priority in ("CRITICAL", "ERROR"):
        return OPUS_MODEL
    return SONNET_MODEL


async def reason_about_threat(context: dict, api_key: str) -> AgentDecision:
    """
    Main reasoning entry point. Calls the reasoning API with enriched context.

    Args:
        context: Enriched context dict from enricher.py
        api_key: Anthropic API key

    Returns:
        AgentDecision with structured threat assessment.
        Never raises — returns default HUMAN_REQUIRED decision on any error.
    """
    alert = context.get("alert", {})
    rule = alert.get("rule", "unknown")
    priority = alert.get("priority", "unknown")

    model = _select_model(alert)
    user_prompt = _build_user_prompt(context)

    log.info(
        "reasoning_started",
        rule=rule,
        priority=priority,
        model=model,
        enrichment_sources=context.get("enrichment_sources", []),
    )

    for attempt in range(3):
        try:
            client = anthropic.AsyncAnthropic(api_key=api_key)

            response = await client.messages.create(
                model=model,
                max_tokens=1024,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
            )

            # Log token usage for cost tracking
            usage = response.usage
            log.info(
                "reasoning_tokens",
                rule=rule,
                model=model,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0),
                cache_write_tokens=getattr(usage, "cache_creation_input_tokens", 0),
            )

            raw_text = response.content[0].text.strip()

            # Strip markdown fences if the model wraps the JSON response.
            if raw_text.startswith("```"):
                lines = raw_text.split("\n")
                raw_text = "\n".join(lines[1:-1])

            decision_dict = json.loads(raw_text)
            decision = AgentDecision(**decision_dict)

            log.info(
                "reasoning_complete",
                rule=rule,
                severity=decision.severity.value,
                confidence=decision.confidence,
                action=decision.recommended_action.value,
                false_positive=decision.likely_false_positive,
                model=model,
            )

            return decision

        except anthropic.RateLimitError:
            wait = 2 ** attempt
            log.warning("reasoning_rate_limited", attempt=attempt, wait_seconds=wait)
            await asyncio.sleep(wait)

        except anthropic.APIConnectionError as e:
            wait = 2 ** attempt
            log.warning("reasoning_api_connection_error", attempt=attempt, error=str(e), wait_seconds=wait)
            await asyncio.sleep(wait)

        except json.JSONDecodeError as e:
            log.error("reasoning_invalid_json", rule=rule, error=str(e))
            return _default_decision(f"Model returned invalid JSON: {e}")

        except Exception as e:
            log.error("reasoning_unexpected_error", rule=rule, error=str(e), attempt=attempt)
            if attempt == 2:
                return _default_decision(str(e))
            await asyncio.sleep(2 ** attempt)

    return _default_decision("Max retries exceeded")
