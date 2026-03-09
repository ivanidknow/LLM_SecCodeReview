"""
CursorOrchestrator — Smart Rule Generation Service.

Builds a structured .cursorrules System Prompt with:
- Security Sentinel role
- Injected project context (type, stack, risk level)
- Protocols grouped by category
- Local LLM tuning
"""

import os
from datetime import datetime
from typing import Any


class CursorOrchestrator:

    @staticmethod
    def generate_rules(
        project_path: str,
        protocols: list[dict[str, Any]],
        project_context: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Build a structured .cursorrules and write to {project_path}/.cursorrules.

        Args:
            project_path: Absolute project directory.
            protocols: Sorted list of protocol dicts.
            project_context: Optional dict with PROJECT_TYPE, TECH_STACK, RISK_LEVEL.
        """
        target_file = os.path.join(project_path, ".cursorrules")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        doc = _brain(timestamp, len(protocols), project_context or {})
        doc += _protocols(protocols)
        doc += _output_format()
        doc += _llm_tuning()

        try:
            os.makedirs(project_path, exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(doc)
            return {"success": True, "target": target_file}
        except PermissionError:
            return {"success": False, "error": f"Permission denied: {target_file}"}
        except OSError as e:
            return {"success": False, "error": f"OS error: {e}"}


def _brain(timestamp: str, count: int, ctx: dict[str, str]) -> str:
    context_block = ""
    if ctx:
        lines = []
        if ctx.get("PROJECT_TYPE"):
            lines.append(f"- **Project Type**: {ctx['PROJECT_TYPE']}")
        if ctx.get("TECH_STACK"):
            lines.append(f"- **Tech Stack**: {ctx['TECH_STACK']}")
        if ctx.get("RISK_LEVEL"):
            level = ctx["RISK_LEVEL"].upper()
            lines.append(f"- **Risk Level**: {level}")
            if level == "HIGH":
                lines.append("- ⚠ HIGH RISK: Apply maximum scrutiny. Flag even LOW-severity issues.")
            elif level == "LOW":
                lines.append("- LOW RISK: Focus on CRITICAL and HIGH severity only.")
        if lines:
            context_block = "\n## PROJECT CONTEXT\n\n" + "\n".join(lines) + "\n"

    return f"""\
# ═══════════════════════════════════════════════════════════════
# HEXSTRIKE SECURITY AUDIT — .cursorrules
# Generated: {timestamp} | Protocols: {count}
# ═══════════════════════════════════════════════════════════════

## ROLE

You are the **Hexstrike Security Sentinel**. Your mission is to audit
code against the following MANDATORY protocols. Cite Protocol IDs
(e.g., DEEP_SCAN/AUTH) for every violation found.

## BEHAVIOR

Strictly enforce every protocol below. Flag violations:

```
🚨 SECURITY_ALERT: [PROTOCOL_ID]
   Severity : CRITICAL | HIGH | MEDIUM | LOW
   Location : file/path.ext:line
   Finding  : Description
   Evidence : Code snippet (max 5 lines)
   Fix      : Remediation
```
{context_block}
## RULES

1. Scan ALL files: source, config, IaC, tests, scripts.
2. Follow `<EXECUTION_PIPELINE>` steps in order.
3. `<ASSERTIONS>` are hard invariants — every failure is a finding.
4. Cite exact `@ID` in every finding.
5. Severity: CRITICAL (RCE, auth bypass) → HIGH (injection, priv-esc) → MEDIUM (info leak, weak crypto) → LOW (best practice).

---

"""


def _protocols(protocols: list[dict]) -> str:
    grouped: dict[str, list[dict]] = {}
    for p in protocols:
        grouped.setdefault(p.get("category", "uncategorized"), []).append(p)
    parts: list[str] = []
    for cat, protos in grouped.items():
        parts.append(f"\n## {cat.replace('_', ' ').upper()}\n\n")
        for p in protos:
            pid = p.get("id", "UNKNOWN")
            goal = p.get("goal", "")
            content = p.get("content", "").strip()
            parts.append(f"### `{pid}`\n\n")
            if goal and goal != "No goal defined":
                parts.append(f"> **Goal:** {goal}\n\n")
            parts.append(f"```\n{content}\n```\n\n")
    return "".join(parts)


def _output_format() -> str:
    return """\
---

## AUDIT OUTPUT

### Findings (CRITICAL → LOW)

| # | Protocol ID | Severity | File:Line | Finding | Fix |
|---|-------------|----------|-----------|---------|-----|

### Executive Summary
- Findings by severity
- Top 3 critical issues
- Posture: `CRITICAL` / `AT RISK` / `ACCEPTABLE` / `STRONG`

### Remediation Roadmap
Quick Win → Medium → Major Refactor.

"""


def _llm_tuning() -> str:
    return """\
---
# Local LLM: CRITICAL > HIGH > MEDIUM > LOW. Max 3 lines per finding.
# Reference @ID only. Use ## headers as anchors. Keep SECURITY_ALERT format.
"""