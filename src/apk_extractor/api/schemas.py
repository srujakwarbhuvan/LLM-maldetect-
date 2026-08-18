"""
API response schemas — all Pydantic models for request/response contracts.

These are distinct from the internal ML/LLM schemas so the API surface
stays stable even as internal models evolve.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ModelScoreResponse(BaseModel):
    """Per-classifier score breakdown."""
    model_config = ConfigDict(protected_namespaces=())
    model_name: str
    probability: float = Field(..., ge=0.0, le=1.0)
    verdict: str


class SuspiciousFeatureResponse(BaseModel):
    """A flagged suspicious feature."""
    feature_name: str
    value: Any
    importance: Optional[float] = None
    description: Optional[str] = None


class DisagreementResponse(BaseModel):
    """ML ↔ LLM disagreement metadata."""
    case: str
    resolved: bool


class WeightsResponse(BaseModel):
    """Score contribution weights."""
    ml: float
    llm: float


class TokenUsageResponse(BaseModel):
    """LLM token usage stats."""
    input: Optional[int] = None
    output: Optional[int] = None
    reasoning: Optional[int] = None


class LLMExplanationResponse(BaseModel):
    """LLM Reasoning Layer output."""
    explanation: str
    suspected_family: str
    likely_behaviors: List[str] = Field(default_factory=list)
    user_recommendations: List[str] = Field(default_factory=list)
    technical_indicators: List[str] = Field(default_factory=list)
    llm_risk_assessment: Optional[str] = None
    model_used: str
    token_usage: TokenUsageResponse


class DecisionResponse(BaseModel):
    """Decision Engine output."""
    verdict: str
    final_risk_level: str
    confidence: float
    malware_score: float
    malware_family: str
    disagreement: DisagreementResponse
    weights: WeightsResponse
    reasoning: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """
    Full /analyze endpoint response — the complete analysis result.

    Contains outputs from all three pipeline stages:
      1. Feature extraction
      2. ML ensemble prediction
      3. LLM explanation
      4. Decision Engine final verdict
    """

    # --- Identity ---
    apk_hash: str
    apk_filename: str
    analysis_id: str = Field(..., description="UUID for this analysis run")

    # --- Stage 1: Feature extraction summary ---
    extraction_success: bool
    extraction_warnings: List[str] = Field(default_factory=list)
    feature_summary: Dict[str, Any] = Field(default_factory=dict)

    # --- Stage 2: ML ensemble ---
    ml_verdict: str
    ml_risk_level: str
    ml_malware_score: float
    ml_confidence: Optional[float] = None
    model_scores: List[ModelScoreResponse] = Field(default_factory=list)
    suspicious_features: List[SuspiciousFeatureResponse] = Field(default_factory=list)

    # --- Stage 3: LLM explanation ---
    llm_explanation: Optional[LLMExplanationResponse] = None
    llm_available: bool = True

    # --- Stage 4: Final decision ---
    decision: DecisionResponse

    # --- Timing ---
    processing_time_seconds: float


class ErrorResponse(BaseModel):
    """Standard error response body."""
    error: str
    detail: Optional[str] = None
    stage: Optional[str] = Field(None, description="Pipeline stage that failed")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str
    ml_models_loaded: bool
    llm_available: bool
