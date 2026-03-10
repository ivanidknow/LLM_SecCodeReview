"""
Projects API Router.

Handles Cursor sync operations with Smart Selection:
- Accepts individual Protocol IDs and Category IDs
- Accepts project context (type, stack, risk_level) for .cursorrules injection
- Category IDs auto-expand to all child protocols via strict mapping
- Generates structured .cursorrules via CursorOrchestrator
"""

import logging
import os
import subprocess

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.core.parser import ProtocolParser
from app.services.cursor_sync import CursorOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/projects", tags=["projects"])

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PROTOCOL_PATH = os.path.join(_BACKEND_DIR, "..", ".security_review", "guidelines")
_parser = ProtocolParser(_PROTOCOL_PATH)

_KNOWN_CATEGORIES: dict[str, str] = {
    "discovery":                 "discovery",
    "modeling":                  "modeling",
    "deep_scan":                 "deep_scan",
    "validation_and_reporting":  "validation_and_reporting",
    "validating_and_reporting":  "validation_and_reporting",
}


# ─── Models ───────────────────────────────────────────────────


class ProjectContext(BaseModel):
    project_type: str = ""      # web, api, cli, mobile
    tech_stack: str = ""        # react, python, go, etc.
    risk_level: str = "medium"  # low, medium, high


class SyncRequest(BaseModel):
    project_path: str
    selected_ids: list[str]
    project_context: ProjectContext | None = None

    @field_validator("project_path")
    @classmethod
    def path_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("project_path must not be empty")
        return v.strip()

    @field_validator("selected_ids")
    @classmethod
    def ids_must_not_be_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("selected_ids must contain at least one ID")
        return v


class SyncResponse(BaseModel):
    message: str
    synced_count: int
    synced_ids: list[str]
    target: str
    categories_expanded: list[str]
    warnings: list[str]


# ─── Helpers ──────────────────────────────────────────────────


def _expand_categories(selected_ids: list[str], tree: dict) -> tuple[list[str], list[str]]:
    expanded_proto_ids: list[str] = []
    expanded_categories: list[str] = []
    individual_ids: list[str] = []

    for sid in selected_ids:
        sid_n = sid.lower().strip()
        if sid_n in _KNOWN_CATEGORIES:
            target = _KNOWN_CATEGORIES[sid_n]
            expanded_categories.append(sid)
            # Match any tree_key that STARTS WITH the target directory
            for tree_key, protocols in tree.items():
                normalized_key = tree_key.replace("\\", "/").lower()
                # Check if this node is exactly the target or a child of the target
                if normalized_key == target or normalized_key.startswith(f"{target}/"):
                    for proto in protocols:
                        pid = proto.get("id", "")
                        if pid and pid not in expanded_proto_ids:
                            expanded_proto_ids.append(pid)
        else:
            individual_ids.append(sid)

    final = list(expanded_proto_ids)
    for rid in individual_ids:
        if rid not in final:
            final.append(rid)
    return final, expanded_categories


def _resolve_protocols(ids: list[str], tree: dict) -> list[dict]:
    resolved, seen = [], set()
    for protos in tree.values():
        for p in protos:
            pid = p.get("id", "")
            if pid in ids and pid not in seen:
                resolved.append(p)
                seen.add(pid)
    return resolved


def _check_git_tracked(path: str) -> str | None:
    if not os.path.isdir(os.path.join(path, ".git")):
        return None
    if not os.path.isfile(os.path.join(path, ".cursorrules")):
        return None
    try:
        r = subprocess.run(["git", "ls-files", "--error-unmatch", ".cursorrules"],
                           cwd=path, capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return "WARNING: .cursorrules is tracked by git. Consider adding to .gitignore."
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


# ─── Path Resolution ──────────────────────────────────────────

# Project root = one level above the backend/ directory
_PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))


def _resolve_project_path(raw_path: str) -> str | None:
    """
    Aggressively resolve the project path with multiple fallback strategies.

    Order:
      1. Absolute / expanded path as-is
      2. Relative to the project root (security review/)
      3. Relative to Desktop
      4. Relative to CWD
    """
    candidates: list[tuple[str, str]] = []

    # 1. Direct (absolute or expanduser)
    direct = os.path.abspath(os.path.expanduser(raw_path))
    candidates.append(("direct", direct))

    # 2. Relative to project root (e.g., "testbed" → "C:\...\security review\testbed")
    from_root = os.path.abspath(os.path.join(_PROJECT_ROOT, raw_path))
    candidates.append(("project_root", from_root))

    # 3. Relative to Desktop (common user location on Windows)
    desktop = os.path.join(os.path.expanduser("~"), "Desktop", raw_path)
    candidates.append(("desktop", os.path.abspath(desktop)))

    # 4. Relative to CWD
    from_cwd = os.path.abspath(raw_path)
    candidates.append(("cwd", from_cwd))

    seen = set()
    for label, path in candidates:
        if path in seen:
            continue
        seen.add(path)
        logger.info(f"  [{label}] Trying: {path}")
        if os.path.isdir(path):
            logger.info(f"  ✓ Resolved via [{label}]: {path}")
            return path

    return None


# ─── Endpoint ─────────────────────────────────────────────────


@router.post("/sync-cursor", response_model=SyncResponse)
async def sync_cursor(req: SyncRequest):
    """Sync selected protocols + project context → .cursorrules"""
    warnings: list[str] = []

    logger.info(f"sync-cursor: raw project_path = '{req.project_path}'")
    expanded_path = _resolve_project_path(req.project_path)

    if expanded_path is None:
        # Build a useful error showing every path we tried
        direct = os.path.abspath(os.path.expanduser(req.project_path))
        from_root = os.path.abspath(os.path.join(_PROJECT_ROOT, req.project_path))
        raise HTTPException(
            400,
            detail=(
                f"Directory not found. Tried:\n"
                f"  1. {direct}\n"
                f"  2. {from_root}\n"
                f"Tip: Use the full absolute path (e.g., C:\\Users\\user\\Desktop\\project)"
            ),
        )

    logger.info(f"sync-cursor: resolved_path = '{expanded_path}'")

    git_warn = _check_git_tracked(expanded_path)
    if git_warn:
        logger.warning(git_warn)
        warnings.append(git_warn)

    tree = _parser.get_methodology_tree()
    if not tree:
        raise HTTPException(500, detail="Methodology tree empty")

    final_ids, expanded_cats = _expand_categories(req.selected_ids, tree)
    selected_protocols = _resolve_protocols(final_ids, tree)

    if not selected_protocols:
        raise HTTPException(400, detail=f"No matching protocols. IDs: {req.selected_ids}")

    selected_protocols.sort(key=lambda p: p.get("id", ""))

    # Build context dict for injection
    ctx = {}
    if req.project_context:
        if req.project_context.project_type:
            ctx["PROJECT_TYPE"] = req.project_context.project_type
        if req.project_context.tech_stack:
            ctx["TECH_STACK"] = req.project_context.tech_stack
        if req.project_context.risk_level:
            ctx["RISK_LEVEL"] = req.project_context.risk_level

    result = CursorOrchestrator.generate_rules(expanded_path, selected_protocols, ctx)

    if not result["success"]:
        raise HTTPException(500, detail=result.get("error", "Write failed"))

    return SyncResponse(
        message="Protocols synced successfully",
        synced_count=len(selected_protocols),
        synced_ids=[p.get("id", "") for p in selected_protocols],
        target=result["target"],
        categories_expanded=expanded_cats,
        warnings=warnings,
    )

