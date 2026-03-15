from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import re

from app.services.database import (
    upsert_project, 
    get_all_projects, 
    create_audit, 
    get_audits_for_project,
    get_project_by_path,
    get_session_logs,
    clear_session_logs,
    update_project_stage
)

router = APIRouter(prefix="/api/history", tags=["history"])


class ProjectSaveRequest(BaseModel):
    name: str
    absolute_path: str


class AuditSaveRequest(BaseModel):
    project_path: str
    status: str
    findings_stats: dict  # {"total": 10, "critical": 2, "high": 3, "medium": 4, "low": 1}
    metrics: dict         # {"architecture": 2, "iam": 1, "data_flow": 3, "business_logic": 1, "iac": 2, "compliance": 1}


@router.post("/projects")
async def save_project(req: ProjectSaveRequest):
    """Upsert a project based on its absolute path."""
    if not req.absolute_path or not req.name:
        raise HTTPException(400, "Missing name or path")
    
    pid = await upsert_project(req.name, req.absolute_path)
    return {"message": "Project saved", "project_id": pid}


@router.get("/projects")
async def list_projects():
    """List all scanned projects."""
    projects = await get_all_projects()
    return {"projects": projects}


@router.post("/save")
async def save_audit(req: AuditSaveRequest):
    """Save an audit result. Called automatically after the Final Report is generated."""
    # First ensure the project exists (should have been created when selected on frontend)
    project_name = os.path.basename(req.project_path)
    pid = await upsert_project(project_name, req.project_path)
    
    # Calculate the exact report path the backend uses
    _BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    computed_report_path = os.path.join(_BACKEND_DIR, "data", "reports", f"report_{pid}.md")
    
    # Save the audit and metrics
    aid = await create_audit(
        project_id=pid,
        report_path=computed_report_path,
        status=req.status,
        findings_stats=req.findings_stats,
        metrics=req.metrics
    )
    return {"message": "Audit saved", "audit_id": aid}


@router.get("/projects/{project_id}/audits")
async def list_audits(project_id: str):
    """Get all audits for a specific project."""
    audits = await get_audits_for_project(project_id)
    return {"audits": audits}


@router.get("/audits/{audit_id}/report")
async def download_report(audit_id: str, report_path: str):
    """Download the markdown report for an audit."""
    if not os.path.exists(report_path) or os.path.getsize(report_path) < 100:
        # Fallback logic if the LLM timed out completely or the file is virtually empty
        # We try to find the raw JSON file for this project and render it natively
        try:
            # We don't have project_id directly in the request query params, but we can query it
            import sqlite3
            import aiosqlite
            from app.services.database import DB_PATH
            
            project_id = None
            async with aiosqlite.connect(DB_PATH) as db:
                async with db.execute("SELECT project_id FROM audits WHERE id = ?", (audit_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        project_id = row[0]
            
            if project_id:
                from app.services.database import get_findings_for_project
                aggregated_findings = await get_findings_for_project(project_id)
                
                if aggregated_findings:
                    # Deterministic python assembly (Fallback Mode)
                    _BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    
                    report_out = f"# [FALLBACK] Security Assessment Report\n\n"
                    report_out += f"> This report was generated natively from raw database findings because the main file was missing.\n\n"
                    report_out += f"## 1. Детальный реестр уязвимостей\n\n"
                    
                    for i, f in enumerate(aggregated_findings, 1):
                        report_out += f"### [SEC-{i:02d}] {f.get('protocol_id', 'Vulnerability')}\n"
                        report_out += f"* *Критичность:* *{f.get('severity', 'HIGH')}*\n" 
                        report_out += f"* *CWE:* [CWE-000: Auto-Assigned by Engine]\n"
                        report_out += f"* *Локация:* `{f.get('file_path', 'N/A')}:{f.get('line_number', 'N/A')}`\n"
                        report_out += f"* *Root Cause:* Проблема безопасности обнаружена анализатором на этапе {f.get('phase', 'N/A')}.\n"
                        report_out += f"* *Сценарий атаки:* Злоумышленник может использовать данную уязвимость ({f.get('protocol_id', 'N/A')}).\n"
                        report_out += f"* *Рекомендация:* Изучите детали и исправьте логику:\n\n"
                        report_out += f"{f.get('description', '')}\n\n"
                        if f.get('code_snippet') and f.get('code_snippet') != 'N/A':
                            report_out += f"```\n{f.get('code_snippet')}\n```\n\n"
                        report_out += "---\n\n"
                    
                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(report_out)
        except Exception as e:
            print(f"Fallback generation error: {e}")

    if not os.path.exists(report_path):
        raise HTTPException(404, "Report file not found and no fallback data available")
        
    filename = os.path.basename(report_path)
    return FileResponse(
        path=report_path, 
        media_type="text/markdown", 
        filename=filename
    )


@router.get("/projects/by-path")
async def get_project_by_path_endpoint(path: str):
    """Get project ID and details by absolute path."""
    project = await get_project_by_path(path)
    if not project:
        raise HTTPException(404, "Project not found")
        
    # State Persistence Fix checking
    artifact_path = os.path.join(path, ".security_review", "artifacts", "discovery_report.json")
    if os.path.exists(artifact_path) and project.get("current_stage") == "discovery":
        await update_project_stage(project["id"], "deep_scan")
        project = await get_project_by_path(path)
        
    return {"project": project}


@router.get("/projects/{project_id}/last-session")
async def get_project_last_session(project_id: str):
    """Retrieve the last active session logs for a project."""
    logs = await get_session_logs(project_id)
    return {"logs": logs}


@router.delete("/projects/{project_id}/logs")
async def reset_project_session(project_id: str):
    """Clear the streaming logs for a project."""
    await clear_session_logs(project_id)
    return {"message": "Session reset"}
