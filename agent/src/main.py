"""
Argus Agent — FastAPI entrypoint
Copyright (c) 2026 Kaushikkumaran

Entry point for the Argus AI agent. Receives Falco webhook alerts,
enriches with cluster context, reasons via Claude API, routes actions.
"""

import logging
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"error": "internal server error"})
