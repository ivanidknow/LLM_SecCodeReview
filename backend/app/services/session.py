"""
Session Service — Persists project analysis state across workflow steps.

Stores discovery findings, detected stack, architecture type, and workflow
progress in a JSON file at .security_review/session.json so the AI has
immediate context without re-scanning.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class ProjectSession:
    """Read/write session data for a project to .security_review/session.json."""

    def __init__(self, project_path: str):
        self.project_path = project_path
        self._dir = os.path.join(project_path, ".security_review")
        self._path = os.path.join(self._dir, "session.json")

    def _ensure_dir(self) -> None:
        os.makedirs(self._dir, exist_ok=True)

    def load(self) -> dict[str, Any]:
        """Load session data. Returns empty dict if no session exists."""
        if not os.path.isfile(self._path):
            return {}
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read session: %s", e)
            return {}

    def save(self, data: dict[str, Any]) -> None:
        """Save session data. Merges with existing data."""
        self._ensure_dir()
        existing = self.load()
        existing.update(data)
        existing["last_updated"] = datetime.now(timezone.utc).isoformat()
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
            logger.info("Session saved: %s", self._path)
        except OSError as e:
            logger.error("Failed to save session: %s", e)

    def save_discovery(
        self,
        tech_stack: str = "",
        project_type: str = "",
        architecture: str = "",
        technologies: list[str] | None = None,
        entry_points: list[str] | None = None,
        warnings: list[str] | None = None,
        secrets: list[str] | None = None,
        raw_log: str = "",
    ) -> None:
        """Save discovery-specific findings."""
        self.save({
            "discovery": {
                "completed": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tech_stack": tech_stack,
                "project_type": project_type,
                "architecture": architecture,
                "technologies": technologies or [],
                "entry_points": entry_points or [],
                "warnings": warnings or [],
                "secrets": secrets or [],
                "raw_log_length": len(raw_log),
            },
            "workflow_step": "modeling",
        })

    def save_workflow_step(self, step: str) -> None:
        """Update current workflow step."""
        self.save({"workflow_step": step})

    def get_ai_context(self) -> str:
        """Build a context string for the AI from session data."""
        data = self.load()
        if not data:
            return ""

        parts = ["## PROJECT SESSION CONTEXT"]
        disc = data.get("discovery", {})
        if disc:
            parts.append(f"- Tech Stack: {disc.get('tech_stack', 'unknown')}")
            parts.append(f"- Project Type: {disc.get('project_type', 'unknown')}")
            parts.append(f"- Architecture: {disc.get('architecture', 'unknown')}")
            techs = disc.get("technologies", [])
            if techs:
                parts.append(f"- Technologies: {', '.join(techs)}")
            eps = disc.get("entry_points", [])
            if eps:
                parts.append(f"- Entry Points: {', '.join(eps[:10])}")
            warns = disc.get("warnings", [])
            if warns:
                parts.append(f"- Warnings ({len(warns)}): {'; '.join(warns[:5])}")

        step = data.get("workflow_step", "discovery")
        parts.append(f"- Current Step: {step}")

        return "\n".join(parts)
