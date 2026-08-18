"""
Pydantic schemas for the LLM Reasoning Layer.

Defines the contract between:
  - predict.py output  →  PredictionResult (input to LLM)
  - LLM response       →  LLMExplanation  (structured output)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Standardised risk level labels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MalwareFamily(str, Enum):
    """Common Android malware families the LLM may identify."""

    BANKER = "Banker"
    SPYWARE = "Spyware"
    RANSOMWARE = "Ransomware"
    ADWARE = "Adware"
    DROPPER = "Dropper"
    BACKDOOR = "Backdoor"
    SMS_STEALER = "SMS Stealer"
    ROOTKIT = "Rootkit"
    CLICKER = "Clicker"
    CRYPTOMINER = "Cryptominer"
    RAT = "Remote Access Trojan"
    UNKNOWN = "Unknown"
    BENIGN = "Benign"


# ---------------------------------------------------------------------------
# Input schema  (mirrors predict.py JSON output)
# ---------------------------------------------------------------------------


class ModelScore(BaseModel):
    """Individual classifier score."""

    model_config = ConfigDict(protected_namespaces=())

    model_name: str = Field(..., description="e.g. 'random_forest', 'svm', 'xgboost'")
    probability: float = Field(..., ge=0.0, le=1.0, description="P(malware)")
    verdict: str = Field(..., description="'malware' | 'benign'")


class SuspiciousFeature(BaseModel):
    """A single suspicious feature flag from the ML pipeline."""

    feature_name: str
    value: Any
    importance: Optional[float] = Field(
        None, description="Feature importance score from the ensemble"
    )
    description: Optional[str] = None


class PredictionResult(BaseModel):
    """
    Full output from predict.py — the primary input to explain_with_llm().

    All fields are optional so the LLM layer degrades gracefully when
    the ML pipeline is partially unavailable.
    """

    model_config = ConfigDict(protected_namespaces=())

    # --- Identity ---
    apk_hash: Optional[str] = None
    apk_filename: Optional[str] = None

    # --- Ensemble verdict ---
    verdict: str = Field(..., description="'malware' | 'benign'")
    risk_level: RiskLevel
    malware_score: float = Field(
        ..., ge=0.0, le=100.0, description="Ensemble malware probability ×100"
    )
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Ensemble confidence"
    )

    # --- Per-model breakdown ---
    model_scores: List[ModelScore] = Field(default_factory=list)

    # --- Feature flags ---
    suspicious_features: List[SuspiciousFeature] = Field(default_factory=list)
    top_features: List[str] = Field(
        default_factory=list,
        description="Names of top-N most important features",
    )

    # --- Raw extracted features (subset sent to LLM for context) ---
    feature_summary: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Compact dict of feature values for key categories "
            "(permissions, api_calls, manifest_stats, certificate)"
        ),
    )

    @field_validator("malware_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        return round(v, 2)


# ---------------------------------------------------------------------------
# Output schema  (structured LLM explanation)
# ---------------------------------------------------------------------------


class LLMExplanation(BaseModel):
    """
    Structured explanation produced by explain_with_llm().

    The raw LLM text is always preserved in `raw_explanation`.
    All other fields are best-effort structured extractions.
    """

    model_config = ConfigDict(protected_namespaces=())

    # --- Core free-text output ---
    raw_explanation: str = Field(
        ..., description="Full LLM-generated explanation paragraph(s)"
    )

    # --- Structured extractions ---
    suspected_malware_family: MalwareFamily = Field(
        default=MalwareFamily.UNKNOWN,
        description="Best-guess malware family classification",
    )
    likely_behaviors: List[str] = Field(
        default_factory=list,
        description="Bullet-point list of likely malicious behaviours",
    )
    user_recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable steps the user should take",
    )
    technical_indicators: List[str] = Field(
        default_factory=list,
        description="Key technical evidence supporting the verdict",
    )

    # --- Meta ---
    model_used: str = Field(default="claude-sonnet-4-20250514")
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    reasoning_tokens: Optional[int] = None
    llm_risk_assessment: Optional[RiskLevel] = Field(
        None, description="Risk level inferred by the LLM independently"
    )

    def to_report_dict(self) -> Dict[str, Any]:
        """Return a clean dict suitable for JSON serialisation in API responses."""
        return {
            "explanation": self.raw_explanation,
            "suspected_family": self.suspected_malware_family.value,
            "likely_behaviors": self.likely_behaviors,
            "user_recommendations": self.user_recommendations,
            "technical_indicators": self.technical_indicators,
            "llm_risk_assessment": (
                self.llm_risk_assessment.value if self.llm_risk_assessment else None
            ),
            "model_used": self.model_used,
            "token_usage": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "reasoning": self.reasoning_tokens,
            },
        }
