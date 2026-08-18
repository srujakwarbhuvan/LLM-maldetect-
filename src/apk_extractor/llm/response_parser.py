"""
Response parser for the LLM Reasoning Layer.

Extracts structured fields from the XML-tagged sections in the LLM response,
with robust fallback handling when sections are missing or malformed.
"""

from __future__ import annotations

import re
from typing import Optional

from loguru import logger

from apk_extractor.llm.schemas import LLMExplanation, MalwareFamily, RiskLevel


# ---------------------------------------------------------------------------
# Section extraction helpers
# ---------------------------------------------------------------------------

def _extract_tag(text: str, tag: str) -> Optional[str]:
    """Extract content between <TAG>...</TAG>, case-insensitive, stripped."""
    pattern = rf"<{tag}>(.*?)</{tag}>"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_bullets(text: str, tag: str) -> list[str]:
    """Extract bullet-point list from a tagged section."""
    section = _extract_tag(text, tag)
    if not section:
        return []
    bullets = []
    for line in section.splitlines():
        line = line.strip().lstrip("-•*·").strip()
        if line:
            bullets.append(line)
    return bullets


def _parse_family(text: str) -> MalwareFamily:
    """Parse the FAMILY section into a MalwareFamily enum."""
    section = _extract_tag(text, "FAMILY")
    if not section:
        return MalwareFamily.UNKNOWN

    section_lower = section.lower()
    mapping = {
        "banker": MalwareFamily.BANKER,
        "banking": MalwareFamily.BANKER,
        "spyware": MalwareFamily.SPYWARE,
        "ransomware": MalwareFamily.RANSOMWARE,
        "adware": MalwareFamily.ADWARE,
        "dropper": MalwareFamily.DROPPER,
        "backdoor": MalwareFamily.BACKDOOR,
        "sms stealer": MalwareFamily.SMS_STEALER,
        "sms_stealer": MalwareFamily.SMS_STEALER,
        "rootkit": MalwareFamily.ROOTKIT,
        "clicker": MalwareFamily.CLICKER,
        "cryptominer": MalwareFamily.CRYPTOMINER,
        "crypto miner": MalwareFamily.CRYPTOMINER,
        "remote access trojan": MalwareFamily.RAT,
        "rat": MalwareFamily.RAT,
        "benign": MalwareFamily.BENIGN,
        "unknown": MalwareFamily.UNKNOWN,
    }
    for key, family in mapping.items():
        if key in section_lower:
            return family

    logger.warning(f"Unrecognised malware family: '{section}' — defaulting to UNKNOWN")
    return MalwareFamily.UNKNOWN


def _parse_risk_level(text: str) -> Optional[RiskLevel]:
    """Parse the RISK_ASSESSMENT section into a RiskLevel enum."""
    section = _extract_tag(text, "RISK_ASSESSMENT")
    if not section:
        return None

    section_upper = section.upper()
    for level in RiskLevel:
        if level.value in section_upper:
            return level

    logger.warning(f"Unrecognised risk level: '{section}' — skipping")
    return None


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_llm_response(
    raw_text: str,
    model_used: str = "claude-sonnet-4-20250514",
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    reasoning_tokens: Optional[int] = None,
) -> LLMExplanation:
    """
    Parse the raw LLM text response into a structured LLMExplanation.

    Attempts to extract each tagged section; falls back gracefully
    to the full raw text if parsing fails.

    Parameters
    ----------
    raw_text:
        The complete text returned by the LLM.
    model_used:
        Model identifier string for provenance tracking.
    input_tokens / output_tokens / reasoning_tokens:
        Token usage stats from the API response.

    Returns
    -------
    LLMExplanation
        Fully populated (or best-effort) structured explanation.
    """
    # Extract the main explanation paragraph
    explanation = _extract_tag(raw_text, "EXPLANATION")
    if not explanation:
        # If tagging is absent, use the whole response as explanation
        explanation = raw_text.strip()
        logger.warning("No <EXPLANATION> tag found — using full response as explanation")

    likely_behaviors = _extract_bullets(raw_text, "BEHAVIORS")
    recommendations = _extract_bullets(raw_text, "RECOMMENDATIONS")
    technical_indicators = _extract_bullets(raw_text, "TECHNICAL_INDICATORS")
    family = _parse_family(raw_text)
    risk = _parse_risk_level(raw_text)

    return LLMExplanation(
        raw_explanation=explanation,
        suspected_malware_family=family,
        likely_behaviors=likely_behaviors,
        user_recommendations=recommendations,
        technical_indicators=technical_indicators,
        llm_risk_assessment=risk,
        model_used=model_used,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        reasoning_tokens=reasoning_tokens,
    )
