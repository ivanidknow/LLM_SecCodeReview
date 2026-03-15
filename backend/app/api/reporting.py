import logging
import os
import datetime
import asyncio
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from app.services.llm_client import ollama
from app.services.database import get_findings_for_project, upsert_project, append_audit_log, update_project_stage
from app.api.analysis import _resolve_path

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reporting"])

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class FinalReportRequest(BaseModel):
    project_id: str
    project_name: str
    model: str = os.getenv("DEFAULT_MODEL", "mistral-small:22b")

_REPORT_SYSTEM = """\
You are the SecCodeReview Engine v3.5 writing a GOLD STANDARD Security Assessment Report.
Output ONLY strict GitHub-formatted Markdown. Do NOT output any [LOG] tags.
Use Russian language for descriptions, Root Cause, Сценарий атаки, and Рекомендация sections.
Use English for technical terms, CWE IDs, and code references.

Follow this EXACT structure from the reference report:

# Security Assessment Report: SecCodeReview

## 0. Executive Summary
[Generate the executive summary outlining the overall posture and top systemic issues based on the provided findings context]

## 6. Глобальные рекомендации
1. [Numbered global recommendations based on the most critical systemic patterns found]
"""

@router.post("/final_report")
async def generate_final_report(req: FinalReportRequest):
    if not await ollama.health_check():
        raise HTTPException(503, detail="OLLAMA_OFFLINE: Start Ollama with: ollama serve")

    pid = req.project_id
    project_name = req.project_name
    await update_project_stage(pid, "report")

    # Fetch DB Findings
    aggregated_findings = await get_findings_for_project(pid)
    
    if not aggregated_findings:
        async def empty_stream():
            yield "[REPORT] ═══ Generating Gold Standard Report ═══\n"
            yield f"[REPORT] No findings found in database for project {project_name}.\n"
            yield "[REPORT] ═══ Report COMPLETE ═══\n"
        return StreamingResponse(
            empty_stream(),
            media_type="text/plain",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    _DATA_DIR = os.path.join(_BACKEND_DIR, "data", "reports")
    if not os.path.exists(_DATA_DIR):
        os.makedirs(_DATA_DIR)
    
    report_file_path = os.path.join(_DATA_DIR, f"report_{pid}.md")
    if not os.path.exists(report_file_path):
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(f"# Initializing Security Report for {project_name}...\n")

    async def stream_report():
        try:
            yield "[REPORT] ═══ Generating Gold Standard Report ═══\n"
            yield f"[REPORT] Fetched {len(aggregated_findings)} findings from database. Building native document...\n"
            asyncio.create_task(append_audit_log(pid, "INFO", f"[REPORT] Fetched {len(aggregated_findings)} findings from database."))
            
            summary_prompt = "Generate ONLY '## 0. Executive Summary' (Top systemic issues and overall posture) and '## 6. Глобальные рекомендации' for this project based on the findings below.\n"
            summary_prompt += f"\nRAW FINDINGS DATA:\n{str(aggregated_findings[:20])}\n(Truncated for brevity)"
            
            yield "[REPORT] Calling LLM for Executive Summary (timeout=300s)...\n"
            
            llm_summary = ""
            try:
                # LLM execution ONLY for the executive summary segment
                llm_summary = await ollama.generate_response_full(
                    prompt=summary_prompt, 
                    system=_REPORT_SYSTEM, 
                    model=req.model
                )
            except Exception as e:
                yield f"[WARN] LLM context failed: {str(e)}\n"
                llm_summary = "Timeout or Error generating summary."
                
            yield f"[REPORT] Building {len(aggregated_findings)} finding entries natively (Deterministic Template Mode)...\n"
        
            # Deterministic python assembly
            report_out = f"# Security Assessment Report: SecCodeReview\n\n"
            report_out += llm_summary + "\n\n"
            report_out += f"## 1. Детальный реестр уязвимостей\n\n"
            
            # 2. Bucket Findings (Evidence First)
            hard_findings = []
            logic_findings = []
            
            hard_keywords = ["select", "system(", "exec(", "subprocess", "pickle", "eval("]
            
            for f in aggregated_findings:
                code_lower = f.get('code_snippet', '').lower()
                desc_lower = f.get('description', '').lower()
                proto_lower = f.get('protocol_id', '').lower()
                
                is_hard = False
                for term in hard_keywords:
                    # Also checking exact literal markers passed in evidence
                    if term in code_lower or term in desc_lower or term in proto_lower:
                        is_hard = True
                        break
                        
                if f.get('severity', '').upper() == "CRITICAL":
                    is_hard = True

                if is_hard:
                    hard_findings.append(f)
                else:
                    logic_findings.append(f)

            def render_finding(f_item, idx, category_prefix="SEC"):
                out = f"### [{category_prefix}-{idx:02d}] {f_item.get('protocol_id', 'Vulnerability')}\n"
                out += f"* *Критичность:* *{f_item.get('severity', 'HIGH')}*\n" 
                out += f"* *CWE:* [CWE-000: Auto-Assigned by Engine]\n"
                out += f"* *Локация:* `{f_item.get('file_path', 'N/A')}:{f_item.get('line_number', 'N/A')}`\n"
                out += f"* *Root Cause:* {f_item.get('description', 'Техническое описание отсутствует.')}\n"
                out += f"* *Сценарий атаки:* {f_item.get('attack_scenario') or 'Сценарий атаки не указан.'}\n"
                out += f"* *Рекомендация:* Рекомендуется провести ревью кода и исправить уязвимость согласно лучшим практикам.\n\n"
                if f_item.get('code_snippet') and f_item.get('code_snippet') != 'N/A':
                    out += f"```\n{f_item.get('code_snippet')}\n```\n\n"
                out += "---\n\n"
                return out

            global_idx = 1
            if hard_findings:
                report_out += "### 🔴 Критичные уязвимости (Hard Findings)\n\n"
                for i, f in enumerate(hard_findings, 1):
                    report_out += render_finding(f, global_idx, "SEC")
                    global_idx += 1

            if logic_findings:
                report_out += "### 🟠 Ошибки бизнес-логики и прочие риски\n\n"
                for i, f in enumerate(logic_findings, 1):
                    # Filtering requirement: only include if they have a non-trivial Attack Scenario
                    atk_sc = f.get('attack_scenario', '')
                    if not atk_sc or len(atk_sc) < 10:
                        # Append naive marker
                        f['attack_scenario'] = "Уязвимость требует дополнительного ручного ревью для формирования вектора атаки."
                    report_out += render_finding(f, global_idx, "SEC")
                    global_idx += 1

            # 4. Immediate Persistence
            with open(report_file_path, "w", encoding="utf-8") as f_out:
                f_out.write(report_out)
            yield f"[REPORT] Saved to disk at data/reports/report_{pid}.md\n"

            # Yield chunks back to UI
            # We break the large string into smaller chunks to stream it nicely to the UI
            chunk_size = 1024
            for i in range(0, len(report_out), chunk_size):
                chunk = report_out[i:i+chunk_size]
                yield chunk
                await asyncio.sleep(0.01)
                asyncio.create_task(append_audit_log(pid, "INFO", chunk))

            yield "\n---\n"
            yield "[REPORT] ═══ Report COMPLETE ═══\n"
            asyncio.create_task(append_audit_log(pid, "INFO", "[REPORT] ═══ Report COMPLETE ═══\n"))
            
        except Exception as e:
            yield f"\n\n[ERROR] Report generation interrupted: {str(e)}\n"

    return StreamingResponse(
        stream_report(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
