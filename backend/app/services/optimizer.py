"""
Optimizer Service — Post-Discovery Adaptive Planning.

Uses OllamaClient to analyze Discovery output and recommend
module additions/removals based on detected technologies.
"""

import json
import logging
import re
from dataclasses import dataclass, field

from app.services.llm_client import ollama

logger = logging.getLogger(__name__)

OPTIMIZE_SYSTEM = """\
You are a Security Audit Optimizer. Your job is to analyze Discovery phase output
and recommend the most efficient set of security scan modules.

You know these available module categories and IDs:

DISCOVERY:
  - architecture (Architecture analysis) [MANDATORY]
  - business_processes (Business process review)
  - license_compliance (License/compliance check)

MODELING:
  - dfd (Data Flow Diagrams)
  - threat_modeling (Threat modeling — STRIDE/DREAD)

DEEP_SCAN:
  - static_analysis (Discovery-Driven SAST)
  - taint_analysis (Taint analysis & data flow tracking)
  - manual_logic_review (Manual logic review for business flaws)
  - iac_audit (Infrastructure-as-Code audit — Docker, K8s, Terraform, CI/CD)

VALIDATION:
  - validating_and_reporting [MANDATORY]
"""

OPTIMIZE_PROMPT = """\
Analyze the following Discovery log output. Identify:
1. Technologies detected (e.g., Docker, JWT, PostgreSQL, React, gRPC, etc.)
2. Architecture patterns (monolith, microservices, serverless, etc.)
3. Risk indicators (public APIs, auth mechanisms, file uploads, etc.)

Then compare with the currently selected module IDs: {current_ids}

Return ONLY a valid JSON object (no markdown, no explanation):
{{
  "detected_technologies": ["tech1", "tech2"],
  "architecture_type": "monolith|microservices|serverless|hybrid",
  "recommended_ids": ["id1", "id2"],
  "redundant_ids": ["id3"],
  "reasoning": {{
    "id1": "why this module is needed",
    "id3": "why this module is redundant"
  }},
  "is_optimized": true|false
}}

Rules:
- "architecture" and "validating_and_reporting" are ALWAYS required, never put them in redundant.
- If Docker/K8s/Terraform/CI-CD files are found → recommend "iac_audit".
- If no IaC files found → mark "iac_audit" as redundant.
- If complex auth (JWT/OAuth/SAML) found → recommend "threat_modeling" and "taint_analysis".
- If simple static site with no backend → many modules are redundant.
- "is_optimized" is false if recommended_ids has items NOT in current selection, or redundant_ids has items IN current selection.

Discovery log:
{discovery_log}
"""


@dataclass
class OptimizationResult:
    detected_technologies: list[str] = field(default_factory=list)
    architecture_type: str = "unknown"
    recommended_ids: list[str] = field(default_factory=list)
    redundant_ids: list[str] = field(default_factory=list)
    reasoning: dict[str, str] = field(default_factory=dict)
    is_optimized: bool = True
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "detected_technologies": self.detected_technologies,
            "architecture_type": self.architecture_type,
            "recommended_ids": self.recommended_ids,
            "redundant_ids": self.redundant_ids,
            "reasoning": self.reasoning,
            "is_optimized": self.is_optimized,
            "error": self.error,
        }


async def analyze_discovery_results(
    discovery_output: str,
    current_selected_ids: list[str],
    model: str = "llama3",
) -> OptimizationResult:
    """
    Use Ollama to analyze Discovery output and recommend module changes.

    Args:
        discovery_output: Full terminal log from the Discovery phase.
        current_selected_ids: Currently selected module IDs.
        model: Ollama model to use for analysis.

    Returns:
        OptimizationResult with recommendations.
    """
    if not await ollama.health_check():
        return OptimizationResult(error="OLLAMA_OFFLINE")

    prompt = OPTIMIZE_PROMPT.format(
        current_ids=json.dumps(current_selected_ids),
        discovery_log=discovery_output[:8000],  # Trim to avoid context overflow
    )

    # Collect full response (not streaming for this use case)
    full_response = ""
    async for chunk in ollama.generate_response(
        prompt=prompt,
        system=OPTIMIZE_SYSTEM,
        model=model,
    ):
        full_response += chunk

    # Parse JSON from response
    return _parse_optimization(full_response, current_selected_ids)


def _parse_optimization(
    raw: str,
    current_ids: list[str],
) -> OptimizationResult:
    """Extract JSON from LLM response, with fallback heuristics."""
    # Try to find JSON in the response
    json_match = re.search(r'\{[\s\S]*\}', raw)
    if not json_match:
        logger.warning("No JSON found in optimizer response: %s", raw[:200])
        return OptimizationResult(error="Failed to parse AI response")

    try:
        data = json.loads(json_match.group())
    except json.JSONDecodeError as e:
        logger.warning("Invalid JSON from optimizer: %s", e)
        return OptimizationResult(error=f"Invalid JSON from AI: {e}")

    result = OptimizationResult(
        detected_technologies=data.get("detected_technologies", []),
        architecture_type=data.get("architecture_type", "unknown"),
        recommended_ids=data.get("recommended_ids", []),
        redundant_ids=data.get("redundant_ids", []),
        reasoning=data.get("reasoning", {}),
        is_optimized=data.get("is_optimized", True),
    )

    # Double-check: never mark mandatory modules as redundant
    mandatory = {"architecture", "validating_and_reporting"}
    result.redundant_ids = [r for r in result.redundant_ids if r not in mandatory]

    # Recompute is_optimized
    missing = [r for r in result.recommended_ids if r not in current_ids]
    unnecessary = [r for r in result.redundant_ids if r in current_ids]
    if missing or unnecessary:
        result.is_optimized = False

    return result
