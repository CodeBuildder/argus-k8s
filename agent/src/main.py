"""
Argus AI Agent — entrypoint

Receives Falco webhook alerts, enriches with cluster context,
reasons via Claude API, and routes remediation actions.
"""

# TODO: implement in Module 4
# Expected flow:
#   POST /falco/webhook  → webhook.py → enricher.py → reasoning.py → actions.py → audit.py

from fastapi import FastAPI

app = FastAPI(title="Argus Agent", version="0.1.0")


@app.get("/health")
async def health():
    return {"status": "ok", "module": "agent", "version": "0.1.0"}


@app.post("/falco/webhook")
async def falco_webhook(payload: dict):
    # TODO: implement in Module 4
    return {"status": "received", "note": "agent not yet implemented"}
