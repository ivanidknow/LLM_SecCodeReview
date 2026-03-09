"""
Analysis API Router.

- POST /api/analysis/chat      — Stream LLM response using .cursorrules
- POST /api/analysis/optimize   — Post-Discovery adaptive optimization
- GET  /api/analysis/status     — Check Ollama availability
- GET  /api/analysis/models     — List locally available Ollama models
"""

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.services.llm_client import ollama
from app.services.optimizer import analyze_discovery_results

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


# ─── Models ───────────────────────────────────────────────────


class ChatRequest(BaseModel):
    project_path: str
    user_query: str
    model: str = "llama3"

    @field_validator("project_path")
    @classmethod
    def path_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("project_path is required")
        return v.strip()

    @field_validator("user_query")
    @classmethod
    def query_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("user_query is required")
        return v.strip()


class OptimizeRequest(BaseModel):
    discovery_log: str
    current_selected_ids: list[str]
    model: str = "llama3"
    is_full_scan: bool = False

    @field_validator("discovery_log")
    @classmethod
    def log_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("discovery_log is required")
        return v.strip()


# ─── Helpers ──────────────────────────────────────────────────


def _read_cursorrules(project_path: str) -> str | None:
    expanded = os.path.expanduser(project_path)
    rules_path = os.path.join(expanded, ".cursorrules")
    if not os.path.isfile(rules_path):
        return None
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/chat")
async def analysis_chat(req: ChatRequest):
    """Stream an LLM response using the project's .cursorrules as system context."""
    if not await ollama.health_check():
        raise HTTPException(status_code=503, detail="OLLAMA_OFFLINE: Start Ollama with: ollama serve")

    expanded_path = os.path.expanduser(req.project_path)
    if not os.path.isdir(expanded_path):
        raise HTTPException(status_code=400, detail=f"Project directory does not exist: {expanded_path}")

    system_prompt = _read_cursorrules(expanded_path)
    if not system_prompt:
        raise HTTPException(status_code=400, detail="No .cursorrules found. Run 'Sync Cursor' first.")

    async def stream_generator():
        async for chunk in ollama.generate_response(
            prompt=req.user_query, system=system_prompt, model=req.model,
        ):
            yield chunk

    return StreamingResponse(
        stream_generator(), media_type="text/plain",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/optimize")
async def optimize_scan(req: OptimizeRequest):
    """
    Post-Discovery adaptive optimization.

    Analyzes discovery output and recommends module additions/removals
    based on detected technologies and architecture patterns.
    """
    result = await analyze_discovery_results(
        discovery_output=req.discovery_log,
        current_selected_ids=req.current_selected_ids,
        model=req.model,
    )

    if result.error:
        raise HTTPException(status_code=503, detail=result.error)

    response = result.to_dict()
    response["is_full_scan"] = req.is_full_scan

    # Special warning for Full Scan with redundant modules
    if req.is_full_scan and result.redundant_ids:
        response["full_scan_warning"] = (
            f"Full Scan includes {len(result.redundant_ids)} unnecessary module(s) "
            f"for this architecture ({result.architecture_type}). "
            f"Optimize to save time?"
        )

    return response


@router.get("/status")
async def ollama_status():
    is_online = await ollama.health_check()
    return {"ollama": "online" if is_online else "offline", "base_url": ollama.base_url}


@router.get("/models")
async def list_models():
    models = await ollama.get_local_models()
    return {"models": models}


# ─── Report Push/Pull ─────────────────────────────────────────

_report_buffer: list[str] = []


class ReportPush(BaseModel):
    lines: list[str]


@router.post("/report")
async def push_report(req: ReportPush):
    """Accept formatted report lines from generate_test_report.py."""
    global _report_buffer
    _report_buffer = req.lines
    return {"status": "ok", "lines": len(req.lines)}


@router.get("/report")
async def get_report():
    """Return buffered report lines for the frontend terminal."""
    return {"lines": _report_buffer}

