"""
Argus Agent — FastAPI entrypoint
Copyright (c) 2026 Kaushikkumaran

Entry point for the Argus AI agent. Receives Falco webhook alerts,
enriches with cluster context, reasons via Claude API, routes actions.
"""

import logging
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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
        "total": len(approval_queue),
    }


@app.post("/approvals/{queue_id}/approve")
async def approve_action(queue_id: str):
    from actions import approval_queue
    for entry in approval_queue:
        if entry["id"] == queue_id:
            entry["status"] = "approved"
            log.info("human_approved", queue_id=queue_id)
            return {"status": "approved", "queue_id": queue_id}
    raise HTTPException(status_code=404, detail="Queue entry not found")


@app.post("/approvals/{queue_id}/reject")
async def reject_action(queue_id: str):
    from actions import approval_queue
    for entry in approval_queue:
        if entry["id"] == queue_id:
            entry["status"] = "rejected"
            log.info("human_rejected", queue_id=queue_id)
            return {"status": "rejected", "queue_id": queue_id}
    raise HTTPException(status_code=404, detail="Queue entry not found")


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
