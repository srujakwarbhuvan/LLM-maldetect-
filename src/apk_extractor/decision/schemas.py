"""
Pydantic schemas for the Decision Engine.

Defines the contract between:
  - DecisionInput  — combined ML + LLM signals
  - FinalVerdict   — the authoritative output of the Decision Engine
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from apk_extractor.llm.schemas import LLMExplanation, MalwareFamily, PredictionResult, RiskLevel


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class VerdictLabel(str, Enum):
    """Final binary verdict labels."""
    MALWARE = "malware"
    BENIGN = "benign"
    UNCERTAIN = "uncertain"   # Reserved for unresolvable disagreements


class DisagreementCase(str, Enum):
    """Categorises how/why ML and LLM signals disagreed."""
    NONE = "none"                          # Full agreement
    ML_HIGH_LLM_LOW = "ml_high_llm_low"   # ML says malware, LLM says low risk
    ML_LOW_LLM_HIGH = "ml_low_llm_high"   # ML says benign, LLM says high risk
    BORDERLINE_SCORE = "borderline_score"  # Malware score in ambiguous zone (40–65)
    LLM_UNAVAILABLE = "llm_unavailable"   # LLM did not return a risk assessment
    FAMILY_MISMATCH = "family_mismatch"   # LLM identified benign, ML flagged malware


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------


class DecisionInput(BaseModel):
    """
    Combined signals passed to the Decision Engine.

    Either construct this directly, or use DecisionEngine.from_results()
    to build it from a (PredictionResult, LLMExplanation) pair.
    """

    model_config = ConfigDict(protected_namespaces=())

    # --- ML signals ---
    ml_verdict: VerdictLabel = Field(..., description="Raw ML ensemble verdict")
    ml_malware_score: float = Field(..., ge=0.0, le=100.0,
                                    description="Ensemble malware probability ×100")
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0,
                                           description="Ensemble prediction confidence")
    ml_risk_level: RiskLevel = Field(..., description="Risk level from the ML pipeline")
    model_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Per-model malware probabilities, keyed by model name"
    )

    # --- LLM signals ---
    llm_risk_level: Optional[RiskLevel] = Field(
        None, description="Risk level the LLM assessed independently"
    )
    llm_malware_family: MalwareFamily = Field(
        default=MalwareFamily.UNKNOWN,
        description="Malware family identified by the LLM"
    )
    llm_explanation: str = Field(
        default="", description="Raw LLM explanation text (for inclusion in reasoning)"
    )
    llm_available: bool = Field(
        True, description="False when the LLM call failed or timed out"
    )

    # --- Metadata ---
    apk_hash: Optional[str] = None
    apk_filename: Optional[str] = None


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class FinalVerdict(BaseModel):
    """
    The authoritative output of the Decision Engine.

    Combines ML ensemble scores and LLM risk assessment into a single,
    calibrated verdict with full audit trail.
    """

    model_config = ConfigDict(protected_namespaces=())

    # --- Core verdict ---
    verdict: VerdictLabel = Field(..., description="Final binary classification")
    final_risk_level: RiskLevel = Field(..., description="Calibrated final risk level")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Decision confidence (0–1). Reduced when signals disagree."
    )

    # --- Score details ---
    malware_score: float = Field(
        ..., ge=0.0, le=100.0, description="Final calibrated malware score (0–100)"
    )
    ml_score_contribution: float = Field(
        ..., ge=0.0, le=1.0,
        description="Weight assigned to the ML score in the final decision"
    )
    llm_score_contribution: float = Field(
        ..., ge=0.0, le=1.0,
        description="Weight assigned to the LLM risk signal in the final decision"
    )

    # --- Disagreement handling ---
    disagreement_case: DisagreementCase = Field(
        default=DisagreementCase.NONE,
        description="Categorises any ML↔LLM disagreement"
    )
    disagreement_resolved: bool = Field(
        True,
        description="True if the engine resolved the disagreement; False = UNCERTAIN"
    )

    # --- Audit trail ---
    reasoning: List[str] = Field(
        default_factory=list,
        description="Step-by-step reasoning trace for the decision"
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Non-fatal issues encountered during decision making"
    )

    # --- Provenance ---
    malware_family: MalwareFamily = Field(
        default=MalwareFamily.UNKNOWN,
        description="Best-guess malware family (from LLM, or UNKNOWN)"
    )
    apk_hash: Optional[str] = None
    apk_filename: Optional[str] = None

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(v, 4)

    @field_validator("malware_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        return round(v, 2)

    def to_report_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict for API responses."""
        return {
            "verdict": self.verdict.value,
            "final_risk_level": self.final_risk_level.value,
            "confidence": self.confidence,
            "malware_score": self.malware_score,
            "malware_family": self.malware_family.value,
            "disagreement": {
                "case": self.disagreement_case.value,
                "resolved": self.disagreement_resolved,
            },
            "weights": {
                "ml": self.ml_score_contribution,
                "llm": self.llm_score_contribution,
            },
            "reasoning": self.reasoning,
            "warnings": self.warnings,
            "apk_hash": self.apk_hash,
            "apk_filename": self.apk_filename,
        }
