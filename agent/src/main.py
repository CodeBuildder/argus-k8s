"""
Argus Agent — FastAPI entrypoint
Copyright (c) 2026 Kaushikkumaran

Entry point for the Argus AI agent. Receives Falco webhook alerts,
enriches with cluster context, reasons via Claude API, routes actions.
"""

import json
import logging
import os
import structlog
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from webhook import router as webhook_router

logging.basicConfig(level=logging.INFO)
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("argus_agent_starting", version="0.1.0")
    yield
    log.info("argus_agent_stopping")


app = FastAPI(
    title="Argus Agent",
    description="Autonomous Kubernetes security agent — threat detection, reasoning, remediation",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(webhook_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus-agent", "version": "0.1.0"}


@app.get("/metrics")
async def metrics():
    from webhook import dedup_cache
    return {
        "dedup_cache_size": len(dedup_cache),
        "status": "ok",
    }


@app.get("/approvals")
async def get_approval_queue():
    from actions import approval_queue
    return {
        "pending": [a for a in approval_queue if a["status"] == "pending"],
        "resolved": [a for a in approval_queue if a["status"] != "pending"][-50:],
        "total": len(approval_queue),
    }


@app.get("/approvals/suppressed")
async def get_suppressed():
    from actions import suppression_list
    now = time.time()
    active = {k: v for k, v in suppression_list.items() if v > now}
    return {
        "suppressed": [
            {
                "key": k,
                "expires_in_seconds": int(v - now),
                "expires_at": datetime.fromtimestamp(v, tz=timezone.utc).isoformat(),
            }
            for k, v in active.items()
        ]
    }


async def _execute_approved_action(entry: dict) -> None:
    """Execute the queued action after a human clicks Approve."""
    from types import SimpleNamespace
    from actions import action_kill, action_isolate, action_notify, action_log

    decision_data = entry["decision"]
    alert = entry["alert"]
    action = decision_data["recommended_action"]

    # confidence = 1.0 so KILL threshold is always satisfied on human override
    decision = SimpleNamespace(
        severity=SimpleNamespace(value=decision_data["severity"]),
        confidence=1.0,
        assessment=decision_data["assessment"],
        recommended_action=SimpleNamespace(value=action),
        likely_false_positive=False,
    )

    try:
        if action == "KILL":
            result = await action_kill(alert, decision)
        elif action == "ISOLATE":
            result = await action_isolate(alert, decision)
        elif action == "NOTIFY":
            result = await action_notify(alert, decision, os.getenv("SLACK_WEBHOOK_URL") or None)
        else:
            result = await action_log(alert, decision)

        entry["execution_result"] = result
        log.info("approved_action_executed", queue_id=entry["id"], action=action, status=result.get("status"))
    except Exception as e:
        log.error("approved_action_failed", queue_id=entry["id"], error=str(e))
        entry["execution_result"] = {"status": "failed", "error": str(e)}


@app.post("/approvals/{queue_id}/approve")
async def approve_action(queue_id: str, background_tasks: BackgroundTasks):
    from actions import approval_queue
    for entry in approval_queue:
        if entry["id"] == queue_id and entry["status"] == "pending":
            entry["status"] = "approved"
            entry["resolved_at"] = datetime.now(timezone.utc).isoformat()
            log.info("human_approved", queue_id=queue_id)
            background_tasks.add_task(_execute_approved_action, entry)
            return {"status": "approved", "queue_id": queue_id}
    raise HTTPException(status_code=404, detail="Queue entry not found")


@app.post("/approvals/{queue_id}/reject")
async def reject_action(queue_id: str, request: Request):
    from actions import approval_queue, suppression_list

    try:
        body = await request.json()
        reason = body.get("reason", "")
        suppress_minutes = int(body.get("suppress_minutes", 30))
    except Exception:
        reason = ""
        suppress_minutes = 30

    for entry in approval_queue:
        if entry["id"] == queue_id and entry["status"] == "pending":
            entry["status"] = "rejected"
            entry["rejected_reason"] = reason
            entry["resolved_at"] = datetime.now(timezone.utc).isoformat()

            suppress_key = f"{entry['namespace']}/{entry['pod']}/{entry['alert'].get('rule', '')}"
            suppression_list[suppress_key] = time.time() + (suppress_minutes * 60)

            log.info("human_rejected", queue_id=queue_id, reason=reason,
                     suppressed_key=suppress_key, suppress_minutes=suppress_minutes)
            return {
                "status": "rejected",
                "queue_id": queue_id,
                "suppressed_key": suppress_key,
                "suppressed_minutes": suppress_minutes,
            }
    raise HTTPException(status_code=404, detail="Queue entry not found")


from actions import approval_queue
import time

# In-memory incident store (populated by audit logger)
incident_store: list[dict] = []

@app.get("/incidents")
async def get_incidents(limit: int = 50, severity: str | None = None, namespace: str | None = None):
    incidents = list(reversed(incident_store[-200:]))
    if severity:
        incidents = [i for i in incidents if i.get("severity", "").upper() == severity.upper()]
    if namespace:
        incidents = [i for i in incidents if i.get("namespace") == namespace]
    return {"incidents": incidents[:limit], "total": len(incident_store)}

@app.get("/incidents/stats")
async def get_incident_stats():
    now = time.time()
    hour_ago = now - 3600
    recent = [i for i in incident_store if i.get("ts", 0) > hour_ago]
    return {
        "total_1h": len(recent),
        "critical_1h": len([i for i in recent if i.get("severity") == "CRITICAL"]),
        "high_1h": len([i for i in recent if i.get("severity") == "HIGH"]),
        "auto_remediated_1h": len([i for i in recent if i.get("action_taken") in ("ISOLATE", "KILL")]),
        "false_positives_1h": len([i for i in recent if i.get("likely_false_positive")]),
        "total_all_time": len(incident_store),
    }

@app.get("/attack-chains")
async def get_attack_chains():
    from attack_chain import attack_chains
    return {
        "chains": list(reversed(attack_chains[-20:])),
        "total": len(attack_chains),
    }

@app.get("/attack-chains/{chain_id}")
async def get_attack_chain(chain_id: str):
    from attack_chain import attack_chains
    chain = next((c for c in attack_chains if c["id"] == chain_id), None)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    return chain

@app.post("/incidents/summarize")
async def summarize_incidents(request: Request):
    """
    Generate an AI-powered summary of recent incidents using Claude.
    Analyzes patterns, trends, and provides actionable insights.
    """
    import os
    from anthropic import Anthropic
    
    body = await request.json()
    time_window = body.get("time_window", 3600)  # Default 1 hour
    
    now = time.time()
    cutoff = now - time_window
    recent = [i for i in incident_store if i.get("ts", 0) > cutoff]
    
    if not recent:
        return {"summary": "No incidents in the specified time window.", "insights": []}
    
    # Prepare incident data for Claude
    incident_summary = []
    for inc in recent[-20:]:  # Last 20 incidents
        incident_summary.append({
            "rule": inc.get("rule"),
            "severity": inc.get("severity"),
            "namespace": inc.get("namespace"),
            "pod": inc.get("pod"),
            "action_taken": inc.get("action_taken"),
            "assessment": inc.get("assessment", "")[:200],  # Truncate
            "likely_false_positive": inc.get("likely_false_positive", False)
        })
    
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not configured"}
    
    try:
        client = Anthropic(api_key=api_key)
        
        prompt = f"""Analyze these {len(recent)} security incidents from the last {time_window//60} minutes and provide:

1. Executive Summary (2-3 sentences)
2. Key Patterns & Trends
3. Top 3 Actionable Recommendations
4. Risk Assessment

Recent Incidents:
{json.dumps(incident_summary, indent=2)}

Statistics:
- Total incidents: {len(recent)}
- Critical: {len([i for i in recent if i.get('severity') == 'CRITICAL'])}
- High: {len([i for i in recent if i.get('severity') == 'HIGH'])}
- Auto-remediated: {len([i for i in recent if i.get('action_taken') in ('ISOLATE', 'KILL')])}
- Likely false positives: {len([i for i in recent if i.get('likely_false_positive')])}

Provide a concise, actionable summary for security operators."""

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        summary_text = response.content[0].text
        
        return {
            "summary": summary_text,
            "incident_count": len(recent),
            "time_window_minutes": time_window // 60,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        

    except Exception as e:
        log.error("incident_summary_failed", error=str(e))
        return {"error": f"Failed to generate summary: {str(e)}"}

@app.post("/chat")
async def chat_with_agent(request: Request):
    """
    Conversational AI interface grounded in real cluster state.
    Streams Claude responses token-by-token via SSE.
    """
    from anthropic import AsyncAnthropic
    from actions import approval_queue

    body = await request.json()
    message = body.get("message", "")
    history = body.get("history", [])  # [{role, content}]

    if not message:
        return JSONResponse({"error": "message is required"}, status_code=400)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    # Build cluster context snapshot
    from actions import approval_queue as aq
    pending = [a for a in aq if a["status"] == "pending"]
    recent = list(reversed(incident_store[-20:]))
    chains_data: list = []
    try:
        from attack_chain import attack_chains
        chains_data = attack_chains[-5:]
    except Exception:
        pass

    incident_rows = [
        {k: v for k, v in inc.items() if k in ("rule", "severity", "namespace", "pod", "action_taken", "assessment", "ts")}
        for inc in recent
    ]

    system_prompt = f"""You are Argus, an AI-powered Kubernetes security assistant. \
Answer questions about the cluster's security posture using the live data below.

## Live Cluster State ({datetime.now(timezone.utc).strftime('%H:%M UTC')})

**Recent incidents (last {len(recent)}):**
{json.dumps(incident_rows, indent=2)}

**Pending human approvals:** {len(pending)}
{json.dumps([{{k: v for k, v in a.items() if k in ("id", "pod", "namespace", "decision")}} for a in pending], indent=2)}

**Active attack chains:** {len(chains_data)}

## Instructions
- Be concise and precise — operators are under time pressure
- Cite specific pod names, namespaces, and incident rules when relevant
- If asked about something not in the data, say so clearly
- Suggest concrete next steps when appropriate
- Format lists with bullet points for readability"""

    messages = [{"role": m["role"], "content": m["content"]} for m in history[-20:]]
    messages.append({"role": "user", "content": message})

    if not api_key:
        # Demo mode — stream a canned response
        async def demo_stream():
            demo = (
                "I'm running in **demo mode** — no `ANTHROPIC_API_KEY` configured. "
                "In production I analyse your real cluster telemetry: Falco alerts, "
                "Hubble network flows, Kyverno violations, CVE hits, and pending approvals, "
                "then answer your questions grounded in that live data."
            )
            for word in demo.split():
                yield f"data: {json.dumps({'type': 'text', 'text': word + ' '})}\n\n"
                await asyncio.sleep(0.04)
            yield f"data: {json.dumps({'type': 'done', 'usage': {'input': 0, 'output': 0}})}\n\n"
        return StreamingResponse(demo_stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    client = AsyncAnthropic(api_key=api_key)

    async def stream_response():
        try:
            async with client.messages.stream(
                model="claude-sonnet-4-6",
                max_tokens=1200,
                system=system_prompt,
                messages=messages,
            ) as stream:
                async for text in stream.text_stream:
                    yield f"data: {json.dumps({'type': 'text', 'text': text})}\n\n"
                final = await stream.get_final_message()
                yield f"data: {json.dumps({'type': 'done', 'usage': {'input': final.usage.input_tokens, 'output': final.usage.output_tokens}})}\n\n"
        except Exception as e:
            log.error("chat_stream_failed", error=str(e))
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/threat-hunt")
async def threat_hunt(request: Request):
    """
    Natural language threat hunting powered by Claude.
    Translates NL queries to Hubble/Loki/K8s API queries.
    """
    import os
    from anthropic import Anthropic
    
    body = await request.json()
    nl_query = body.get("query", "")
    
    if not nl_query:
        return {"error": "Query is required"}
    
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not configured"}
    
    try:
        client = Anthropic(api_key=api_key)
        
        prompt = f"""You are a Kubernetes security analyst. Translate this natural language query into the appropriate system query.

Available data sources:
1. Hubble (Cilium network flows): Use for network connections, traffic patterns, L3-L7 visibility
2. Loki (logs): Use for Falco alerts, application logs, audit logs
3. Kubernetes API: Use for pod info, resource limits, RBAC, secrets

Natural language query: "{nl_query}"

Respond with:
1. Which data source to use (hubble/loki/k8s)
2. The translated query in the appropriate format
3. Brief explanation of what you're looking for

Format your response as JSON:
{{
  "source": "hubble|loki|k8s",
  "query": "the actual query string",
  "explanation": "what this query does"
}}"""

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Parse Claude's response
        response_text = response.content[0].text
        
        # Try to extract JSON from response
        import re
        json_match = re.search(r'\{[^}]+\}', response_text, re.DOTALL)
        if json_match:
            query_info = json.loads(json_match.group())
        else:
            query_info = {
                "source": "loki",
                "query": nl_query,
                "explanation": "Query translation in progress"
            }
        
        return {
            "query": query_info.get("query", nl_query),
            "source": query_info.get("source", "loki"),
            "explanation": query_info.get("explanation", ""),
            "results": [],  # Would be populated by actual query execution
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        log.error("threat_hunt_failed", error=str(e))
        return {"error": f"Failed to process query: {str(e)}"}

@app.post("/drift-detection/baseline")
async def create_drift_baseline():
    """
    Create a baseline snapshot of current cluster state for drift detection.
    Captures: deployments, configmaps, secrets, network policies, RBAC.
    """
    from kubernetes import client, config
    
    try:
        if os.getenv("IN_CLUSTER", "true").lower() == "true":
            config.load_incluster_config()
        else:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        
        baseline = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "deployments": [],
            "configmaps": [],
            "secrets": [],
            "namespaces": []
        }
        
        # Capture deployments
        deployments = apps_v1.list_deployment_for_all_namespaces()
        for dep in deployments.items:
            baseline["deployments"].append({
                "name": dep.metadata.name,
                "namespace": dep.metadata.namespace,
                "replicas": dep.spec.replicas,
                "image": dep.spec.template.spec.containers[0].image if dep.spec.template.spec.containers else None,
                "labels": dep.metadata.labels
            })
        
        # Capture configmaps
        configmaps = v1.list_config_map_for_all_namespaces()
        baseline["configmaps"] = [{"name": cm.metadata.name, "namespace": cm.metadata.namespace} for cm in configmaps.items]
        
        # Capture secrets
        secrets = v1.list_secret_for_all_namespaces()
        baseline["secrets"] = [{"name": s.metadata.name, "namespace": s.metadata.namespace, "type": s.type} for s in secrets.items]
        
        # Capture namespaces
        namespaces = v1.list_namespace()
        baseline["namespaces"] = [ns.metadata.name for ns in namespaces.items]
        
        # Store baseline (in production, this would go to a database)
        global drift_baseline
        drift_baseline = baseline
        
        return {
            "status": "baseline_created",
            "timestamp": baseline["timestamp"],
            "resources_captured": {
                "deployments": len(baseline["deployments"]),
                "configmaps": len(baseline["configmaps"]),
                "secrets": len(baseline["secrets"]),
                "namespaces": len(baseline["namespaces"])
            }
        }
        
    except Exception as e:
        log.error("drift_baseline_failed", error=str(e))
        return {"error": f"Failed to create baseline: {str(e)}"}

drift_baseline = None

@app.get("/drift-detection/check")
async def check_drift():
    """
    Compare current cluster state against baseline to detect drift.
    """
    global drift_baseline
    
    if not drift_baseline:
        return {"error": "No baseline exists. Create one first with POST /drift-detection/baseline"}
    
    from kubernetes import client, config
    
    try:
        if os.getenv("IN_CLUSTER", "true").lower() == "true":
            config.load_incluster_config()
        else:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        
        drifts = []
        
        # Check deployments
        current_deployments = apps_v1.list_deployment_for_all_namespaces()
        baseline_dep_names = {f"{d['namespace']}/{d['name']}" for d in drift_baseline["deployments"]}
        current_dep_names = {f"{d.metadata.namespace}/{d.metadata.name}" for d in current_deployments.items}
        
        # New deployments
        for new_dep in current_dep_names - baseline_dep_names:
            drifts.append({
                "type": "deployment_added",
                "resource": new_dep,
                "severity": "medium"
            })
        
        # Deleted deployments
        for deleted_dep in baseline_dep_names - current_dep_names:
            drifts.append({
                "type": "deployment_deleted",
                "resource": deleted_dep,
                "severity": "high"
            })
        
        # Check configmaps
        current_cms = v1.list_config_map_for_all_namespaces()
        baseline_cm_names = {f"{cm['namespace']}/{cm['name']}" for cm in drift_baseline["configmaps"]}
        current_cm_names = {f"{cm.metadata.namespace}/{cm.metadata.name}" for cm in current_cms.items}
        
        for new_cm in current_cm_names - baseline_cm_names:
            drifts.append({
                "type": "configmap_added",
                "resource": new_cm,
                "severity": "low"
            })
        
        return {
            "baseline_timestamp": drift_baseline["timestamp"],
            "check_timestamp": datetime.now(timezone.utc).isoformat(),
            "drift_detected": len(drifts) > 0,
            "drift_count": len(drifts),
            "drifts": drifts[:20]  # Return top 20
        }
        
    except Exception as e:
        log.error("drift_check_failed", error=str(e))
        return {"error": f"Failed to check drift: {str(e)}"}

@app.post("/risk-forecast")
async def forecast_risk(request: Request):
    """
    AI-powered risk forecasting based on current security posture.
    Uses Claude to analyze trends and predict potential issues.
    """
    import os
    from anthropic import Anthropic
    
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not configured"}
    
    try:
        # Gather current security metrics
        now = time.time()
        hour_ago = now - 3600
        recent_incidents = [i for i in incident_store if i.get("ts", 0) > hour_ago]
        
        metrics = {
            "incidents_1h": len(recent_incidents),
            "critical_incidents": len([i for i in recent_incidents if i.get("severity") == "CRITICAL"]),
            "high_incidents": len([i for i in recent_incidents if i.get("severity") == "HIGH"]),
            "auto_remediated": len([i for i in recent_incidents if i.get("action_taken") in ("ISOLATE", "KILL")]),
            "false_positives": len([i for i in recent_incidents if i.get("likely_false_positive")]),
            "attack_chains": 0
        }
        
        try:
            from attack_chain import attack_chains
            metrics["attack_chains"] = len(attack_chains)
        except:
            pass
        
        client = Anthropic(api_key=api_key)
        
        prompt = f"""As a security analyst, forecast potential risks for the next 24-48 hours based on current metrics:

Current Security Metrics:
- Incidents (last hour): {metrics['incidents_1h']}
- Critical: {metrics['critical_incidents']}
- High: {metrics['high_incidents']}
- Auto-remediated: {metrics['auto_remediated']}
- False positives: {metrics['false_positives']}
- Active attack chains: {metrics['attack_chains']}

Provide:
1. Risk Level (Low/Medium/High/Critical)
2. Top 3 Predicted Threats (next 24-48h)
3. Recommended Preventive Actions
4. Confidence Score (0-100%)

Be concise and actionable."""

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        
        forecast_text = response.content[0].text
        
        return {
            "forecast": forecast_text,
            "metrics": metrics,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "forecast_window": "24-48 hours"
        }
        
    except Exception as e:
        log.error("risk_forecast_failed", error=str(e))
        return {"error": f"Failed to generate forecast: {str(e)}"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"error": "internal server error"})


async def process_alert(payload: dict) -> None:
    """
    Full agent pipeline: enrich -> reason -> act -> audit.
    Called as a background task after webhook returns 202.
    """
    import os
    from enricher import enrich_context
    from reasoning import reason_about_threat
    from actions import route_action
    from audit import audit_log

    rule = payload.get("rule", "unknown")
    log.info("pipeline_started", rule=rule)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    notify_webhook = os.getenv("SLACK_WEBHOOK_URL", "")

    context = await enrich_context(payload)
    decision = await reason_about_threat(context, api_key)
    action_result = await route_action(payload, decision, notify_webhook or None)
    await audit_log(payload, context, decision, action_result)

    log.info(
        "pipeline_complete",
        rule=rule,
        severity=decision.severity.value,
        action=action_result.get("action"),
        status=action_result.get("status"),
    )
