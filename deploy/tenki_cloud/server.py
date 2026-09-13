"""Phase 6: Tenki Cloud SIEM & Fuzzer Coordinator API.

Lightweight FastAPI hub hosted on Tenki Cloud compute instances, providing:
  - POST /api/telemetry/ingest    — Receives structured forensic incidents from field agents.
  - GET  /api/incidents           — Returns paginated incident log for the dashboard.
  - GET  /api/incidents/summary   — Aggregated statistics for live visualization.
  - POST /api/fuzzer/jobs         — Accepts fuzzing job submissions from the engine.
  - GET  /api/fuzzer/results/{id} — Returns completed fuzzing job results.
  - GET  /health                  — Liveness probe for Tenki Cloud health checks.
"""

import json
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel as FastAPIBaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# ---------------------------------------------------------------------------
# In-memory stores (replace with DB in production)
# ---------------------------------------------------------------------------

_incidents: Deque[Dict[str, Any]] = deque(maxlen=10_000)
_fuzzer_jobs: Dict[str, Dict[str, Any]] = {}
_boot_time = time.time()

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> "FastAPI":  # type: ignore[name-defined]
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the Tenki Cloud server. "
            "Install it with: uv pip install fastapi uvicorn"
        )

    app = FastAPI(
        title="AegisAgent — Tenki Cloud SIEM & Fuzzer Coordinator",
        description=(
            "Centralized security telemetry hub and distributed fuzzing coordinator "
            "for AegisAgent, hosted on Tenki Cloud compute infrastructure."
        ),
        version="0.1.0",
        docs_url="/docs",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Health & Metadata
    # ------------------------------------------------------------------

    @app.get("/health")
    async def health():
        """Liveness probe — used by Tenki Cloud orchestrator health checks."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - _boot_time, 1),
            "incidents_stored": len(_incidents),
            "fuzzer_jobs": len(_fuzzer_jobs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Telemetry Ingestion
    # ------------------------------------------------------------------

    @app.post("/api/telemetry/ingest", status_code=202)
    async def ingest_telemetry(payload: Dict[str, Any]):
        """
        Receive a structured forensic incident from a field AegisAgent instance.
        Accepts JSON payloads matching the ForensicIncident schema.
        """
        payload["received_at"] = datetime.now(timezone.utc).isoformat()
        payload.setdefault("incident_id", f"INC-{uuid.uuid4().hex[:8].upper()}")
        _incidents.appendleft(payload)

        # Persist to JSONL audit log on disk
        log_path = Path("tenki_incidents.jsonl")
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except OSError:
            pass

        return {
            "accepted": True,
            "incident_id": payload["incident_id"],
            "queue_depth": len(_incidents),
        }

    @app.get("/api/incidents")
    async def list_incidents(
        limit: int = Query(default=50, le=500),
        severity: Optional[str] = Query(default=None),
        canary_only: bool = Query(default=False),
    ):
        """Return paginated incident list, optionally filtered."""
        filtered = list(_incidents)
        if severity:
            filtered = [i for i in filtered if i.get("severity") == severity.upper()]
        if canary_only:
            filtered = [i for i in filtered if i.get("canary_tripped")]
        return {"total": len(filtered), "incidents": filtered[:limit]}

    @app.get("/api/incidents/summary")
    async def incident_summary():
        """Aggregated summary statistics for the live dashboard."""
        all_inc = list(_incidents)
        total = len(all_inc)
        by_severity: Dict[str, int] = {}
        canary_trips = 0
        for inc in all_inc:
            sev = inc.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if inc.get("canary_tripped"):
                canary_trips += 1

        return {
            "total_incidents": total,
            "canary_trips": canary_trips,
            "by_severity": by_severity,
            "most_recent": all_inc[0] if all_inc else None,
        }

    # ------------------------------------------------------------------
    # Fuzzer Job Coordination
    # ------------------------------------------------------------------

    @app.post("/api/fuzzer/jobs", status_code=202)
    async def submit_fuzzer_job(payload: Dict[str, Any]):
        """
        Accept a fuzzing job from the AegisAgent engine (--tenki-distributed).
        Spawns local worker (or delegates to Tenki Cloud runner fleet in production).
        """
        job_id = f"JOB-{uuid.uuid4().hex[:10].upper()}"
        mutations = payload.get("mutations", [])

        _fuzzer_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "mutation_count": len(mutations),
            "findings": [],
        }

        # In production this would dispatch to Tenki Cloud compute runners.
        # Here we run synchronously for demo correctness (small jobs only).
        try:
            from aegis.fuzzer.mutations import Mutation
            from aegis.fuzzer.engine import probe_mutation
            from concurrent.futures import ThreadPoolExecutor

            mut_objects = [Mutation(**m) for m in mutations]
            _fuzzer_jobs[job_id]["status"] = "running"
            findings = []
            with ThreadPoolExecutor(max_workers=4) as ex:
                for result in ex.map(probe_mutation, mut_objects):
                    findings.append(result.model_dump())
            _fuzzer_jobs[job_id]["findings"] = findings
            _fuzzer_jobs[job_id]["status"] = "complete"
            _fuzzer_jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            _fuzzer_jobs[job_id]["status"] = "error"
            _fuzzer_jobs[job_id]["error"] = str(e)

        return {"job_id": job_id, "status": _fuzzer_jobs[job_id]["status"]}

    @app.get("/api/fuzzer/results/{job_id}")
    async def get_fuzzer_results(job_id: str):
        """Retrieve completed fuzzing job results."""
        if job_id not in _fuzzer_jobs:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
        return _fuzzer_jobs[job_id]

    @app.get("/api/fuzzer/jobs")
    async def list_jobs():
        """List all fuzzer jobs."""
        return {
            "total": len(_fuzzer_jobs),
            "jobs": [
                {k: v for k, v in job.items() if k != "findings"}
                for job in _fuzzer_jobs.values()
            ],
        }

    return app


# ---------------------------------------------------------------------------
# Entry point for: uvicorn deploy.tenki_cloud.server:app --reload
# ---------------------------------------------------------------------------
if FASTAPI_AVAILABLE:
    app = create_app()


if __name__ == "__main__":
    try:
        import uvicorn
        uvicorn.run("deploy.tenki_cloud.server:app", host="0.0.0.0", port=8080, reload=True)
    except ImportError:
        print("Install uvicorn: uv pip install fastapi uvicorn")
