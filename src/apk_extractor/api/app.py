"""
FastAPI application factory and route definitions.

Endpoints
---------
GET  /health          — liveness + model status
POST /analyze         — full pipeline: extract → predict → explain → decide
GET  /analyze/{id}    — retrieve a cached analysis by ID (in-memory cache)
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from apk_extractor.api.predictor import MLPredictor
from apk_extractor.api.schemas import (
    AnalysisResponse,
    DecisionResponse,
    DisagreementResponse,
    ErrorResponse,
    HealthResponse,
    LLMExplanationResponse,
    ModelScoreResponse,
    SuspiciousFeatureResponse,
    TokenUsageResponse,
    WeightsResponse,
)
from apk_extractor.decision import make_final_decision
from apk_extractor.llm import explain_with_llm
from apk_extractor.llm.schemas import LLMExplanation
from apk_extractor.pipeline.apk_pipeline import APKFeatureExtractor

# ---------------------------------------------------------------------------
# Config (read from env vars with sensible defaults)
# ---------------------------------------------------------------------------

API_VERSION     = "1.0.0"
MAX_APK_SIZE_MB = int(os.environ.get("MAX_APK_SIZE_MB", "100"))
MODELS_DIR      = Path(os.environ.get("MODELS_DIR", "models"))
GEMINI_KEY   = os.environ.get("GEMINI_API_KEY", "")

# In-memory analysis cache (replace with Redis in production)
_ANALYSIS_CACHE: dict[str, AnalysisResponse] = {}
_MAX_CACHE      = 200   # evict oldest entries


# ---------------------------------------------------------------------------
# Lazy singletons — created once on first request
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_extractor() -> APKFeatureExtractor:
    return APKFeatureExtractor(log_level="WARNING")


@lru_cache(maxsize=1)
def _get_predictor() -> MLPredictor:
    return MLPredictor(models_dir=MODELS_DIR if MODELS_DIR.exists() else None)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    title: str = "Android Malware Detection API",
    version: str = API_VERSION,
    models_dir: Optional[Path] = None,
) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Parameters
    ----------
    title : str
        OpenAPI title.
    version : str
        API version string shown in docs.
    models_dir : Path, optional
        Override the default MODELS_DIR env-var path for .pkl files.

    Returns
    -------
    FastAPI
    """
    global MODELS_DIR
    if models_dir:
        MODELS_DIR = models_dir

    app = FastAPI(
        title=title,
        version=version,
        description=(
            "Static analysis pipeline for Android APK malware detection. "
            "Combines ML ensemble scoring, LLM contextual explanation, "
            "and a calibrated Decision Engine into a single /analyze endpoint."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS — open during development; tighten in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Exception handlers
    # ------------------------------------------------------------------

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request, exc):
        logger.exception(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="Internal server error",
                detail=str(exc),
            ).model_dump(),
        )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get(
        "/health",
        response_model=HealthResponse,
        summary="Health check",
        tags=["Meta"],
    )
    async def health() -> HealthResponse:
        """Returns API liveness status and component availability."""
        predictor = _get_predictor()
        return HealthResponse(
            status="ok",
            version=API_VERSION,
            ml_models_loaded=not predictor.is_heuristic_mode,
            llm_available=bool(GEMINI_KEY),
        )

    @app.post(
        "/analyze",
        response_model=AnalysisResponse,
        status_code=status.HTTP_200_OK,
        summary="Analyze an APK file for malware",
        tags=["Analysis"],
        responses={
            400: {"model": ErrorResponse, "description": "Invalid APK or file too large"},
            422: {"model": ErrorResponse, "description": "Extraction failed"},
            500: {"model": ErrorResponse, "description": "Internal pipeline error"},
        },
    )
    async def analyze(
        file: UploadFile = File(..., description="APK file to analyze"),
        enable_llm: bool = Form(True, description="Run LLM explanation (requires GEMINI_API_KEY)"),
        enable_thinking: bool = Form(True, description="Enable extended thinking in LLM"),
    ) -> AnalysisResponse:
        """
        Full analysis pipeline for an Android APK.

        **Stages:**
        1. **Feature Extraction** — 239 static features (permissions, API calls, manifest, code, cert)
        2. **ML Prediction** — Random Forest + SVM + XGBoost ensemble
        3. **LLM Explanation** — Claude generates contextual explanation (optional)
        4. **Decision Engine** — Calibrated final verdict with disagreement handling

        **Returns** a complete JSON report with malware score, risk level,
        per-model breakdown, suspicious features, LLM narrative, and reasoning trace.
        """
        start_time = time.monotonic()
        analysis_id = str(uuid.uuid4())

        # ── Validate upload ────────────────────────────────────────────
        if not file.filename or not file.filename.lower().endswith(".apk"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an .apk file.",
            )

        # ── Save to temp file ──────────────────────────────────────────
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            size_bytes = 0
            max_bytes  = MAX_APK_SIZE_MB * 1024 * 1024
            async with aiofiles.open(tmp_path, "wb") as f:
                while chunk := await file.read(1024 * 1024):   # 1 MB chunks
                    size_bytes += len(chunk)
                    if size_bytes > max_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"APK exceeds maximum allowed size of {MAX_APK_SIZE_MB} MB.",
                        )
                    await f.write(chunk)

            logger.info(
                f"[{analysis_id}] Received {file.filename!r} "
                f"({size_bytes / 1024:.1f} KB)"
            )

            # ── Stage 1: Feature extraction ────────────────────────────
            extractor = _get_extractor()
            logger.info(f"[{analysis_id}] Stage 1: Feature extraction")
            apk_features = extractor.extract(tmp_path)

            if apk_features is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Feature extraction failed. File may be corrupt or not a valid APK.",
                )

            # Override filename with the original upload name
            apk_features.apk_filename = file.filename

            # ── Stage 2: ML prediction ─────────────────────────────────
            predictor = _get_predictor()
            logger.info(f"[{analysis_id}] Stage 2: ML prediction")
            prediction = predictor.predict(apk_features)

            # ── Stage 3: LLM explanation ───────────────────────────────
            llm_explanation: Optional[LLMExplanation] = None
            llm_available = False

            if enable_llm and GEMINI_KEY:
                logger.info(f"[{analysis_id}] Stage 3: LLM Explanation starting...")
                try:
                    llm_explanation = explain_with_llm(
                        prediction,
                        api_key=GEMINI_KEY,
                        enable_thinking=enable_thinking,
                    )
                    llm_available = True
                except Exception as e:
                    logger.warning(f"[{analysis_id}] LLM explanation failed: {e}")
            elif not GEMINI_KEY:
                logger.info(f"[{analysis_id}] Stage 3: Skipped (no GEMINI_API_KEY)")
            else:
                logger.info(f"[{analysis_id}] Stage 3: Skipped (enable_llm=False)")

            # ── Stage 4: Decision Engine ───────────────────────────────
            logger.info(f"[{analysis_id}] Stage 4: Decision Engine")
            final_verdict = make_final_decision(prediction, llm_explanation)

            # ── Assemble response ──────────────────────────────────────
            elapsed = round(time.monotonic() - start_time, 3)

            llm_resp: Optional[LLMExplanationResponse] = None
            if llm_explanation:
                usage = TokenUsageResponse(
                    input=llm_explanation.input_tokens,
                    output=llm_explanation.output_tokens,
                    reasoning=llm_explanation.reasoning_tokens,
                )
                llm_resp = LLMExplanationResponse(
                    explanation=llm_explanation.raw_explanation,
                    suspected_family=llm_explanation.suspected_malware_family.value,
                    likely_behaviors=llm_explanation.likely_behaviors,
                    user_recommendations=llm_explanation.user_recommendations,
                    technical_indicators=llm_explanation.technical_indicators,
                    llm_risk_assessment=(
                        llm_explanation.llm_risk_assessment.value
                        if llm_explanation.llm_risk_assessment else None
                    ),
                    model_used=llm_explanation.model_used,
                    token_usage=usage,
                )

            decision_resp = DecisionResponse(
                verdict=final_verdict.verdict.value,
                final_risk_level=final_verdict.final_risk_level.value,
                confidence=final_verdict.confidence,
                malware_score=final_verdict.malware_score,
                malware_family=final_verdict.malware_family.value,
                disagreement=DisagreementResponse(
                    case=final_verdict.disagreement_case.value,
                    resolved=final_verdict.disagreement_resolved,
                ),
                weights=WeightsResponse(
                    ml=final_verdict.ml_score_contribution,
                    llm=final_verdict.llm_score_contribution,
                ),
                reasoning=final_verdict.reasoning,
                warnings=final_verdict.warnings,
            )

            response = AnalysisResponse(
                apk_hash=apk_features.apk_hash,
                apk_filename=apk_features.apk_filename,
                analysis_id=analysis_id,
                extraction_success=apk_features.extraction_success,
                extraction_warnings=apk_features.extraction_warnings,
                feature_summary=predictor._build_feature_summary(apk_features),
                ml_verdict=prediction.verdict,
                ml_risk_level=prediction.risk_level.value,
                ml_malware_score=prediction.malware_score,
                ml_confidence=prediction.confidence,
                model_scores=[
                    ModelScoreResponse(
                        model_name=ms.model_name,
                        probability=ms.probability,
                        verdict=ms.verdict,
                    )
                    for ms in prediction.model_scores
                ],
                suspicious_features=[
                    SuspiciousFeatureResponse(
                        feature_name=sf.feature_name,
                        value=sf.value,
                        importance=sf.importance,
                        description=sf.description,
                    )
                    for sf in prediction.suspicious_features
                ],
                llm_explanation=llm_resp,
                llm_available=llm_available,
                decision=decision_resp,
                processing_time_seconds=elapsed,
            )

            # Cache result
            if len(_ANALYSIS_CACHE) >= _MAX_CACHE:
                oldest_key = next(iter(_ANALYSIS_CACHE))
                del _ANALYSIS_CACHE[oldest_key]
            _ANALYSIS_CACHE[analysis_id] = response

            logger.info(
                f"[{analysis_id}] Analysis complete in {elapsed}s | "
                f"verdict={final_verdict.verdict.value} | "
                f"score={final_verdict.malware_score}"
            )
            return response

        finally:
            # Always clean up temp file
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    @app.get(
        "/analyze/{analysis_id}",
        response_model=AnalysisResponse,
        summary="Retrieve a cached analysis by ID",
        tags=["Analysis"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_analysis(analysis_id: str) -> AnalysisResponse:
        """Retrieve a previously computed analysis result by its UUID."""
        result = _ANALYSIS_CACHE.get(analysis_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found. Results are held in memory and may have been evicted.",
            )
        return result

    return app
