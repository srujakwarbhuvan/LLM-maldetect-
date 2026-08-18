"""
Decision Engine — core logic for combining ML + LLM signals into a final verdict.

Decision Rules (in priority order):
  1. CRITICAL score (≥85)         → MALWARE, no LLM override needed
  2. Very low score (≤15)         → BENIGN, no LLM override needed
  3. LLM unavailable              → fall back to ML-only with confidence penalty
  4. ML/LLM agree                 → combine with high confidence
  5. ML high / LLM low risk       → trust ML, flag disagreement, reduce confidence
  6. ML low / LLM high risk       → escalate to LLM, flag disagreement, reduce confidence
  7. Borderline score (40–65)     → weight LLM more heavily; UNCERTAIN if still unclear
"""

from __future__ import annotations

from typing import Optional, Union
import math

from loguru import logger

from apk_extractor.llm.schemas import LLMExplanation, MalwareFamily, PredictionResult, RiskLevel
from apk_extractor.decision.schemas import (
    DecisionInput,
    DisagreementCase,
    FinalVerdict,
    VerdictLabel,
)


# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------

SCORE_CRITICAL     = 85.0   # Above → always MALWARE
SCORE_HIGH         = 65.0   # Above → lean MALWARE
SCORE_BORDERLINE_HI = 65.0  # ]40, 65] → ambiguous zone upper
SCORE_BORDERLINE_LO = 40.0  # ]15, 40] → ambiguous zone lower
SCORE_LOW          = 15.0   # Below → always BENIGN

# Confidence penalties
PENALTY_DISAGREEMENT  = 0.15   # ML↔LLM disagree
PENALTY_BORDERLINE    = 0.10   # Score in ambiguous zone
PENALTY_LLM_MISSING   = 0.12   # LLM unavailable

# LLM weight when it is available vs. ML-only
WEIGHT_LLM_NORMAL     = 0.25   # LLM gets 25% of the combined score
WEIGHT_LLM_BORDERLINE = 0.40   # LLM gets 40% in ambiguous zone (more context needed)
WEIGHT_ML_NORMAL      = 1.0 - WEIGHT_LLM_NORMAL
WEIGHT_ML_BORDERLINE  = 1.0 - WEIGHT_LLM_BORDERLINE

# Numeric score assigned to each RiskLevel (for blending)
_RISK_TO_SCORE: dict[RiskLevel, float] = {
    RiskLevel.LOW:      12.0,
    RiskLevel.MEDIUM:   40.0,
    RiskLevel.HIGH:     72.0,
    RiskLevel.CRITICAL: 92.0,
}

_SCORE_TO_RISK: list[tuple[float, RiskLevel]] = [
    (85.0, RiskLevel.CRITICAL),
    (65.0, RiskLevel.HIGH),
    (40.0, RiskLevel.MEDIUM),
    (0.0,  RiskLevel.LOW),
]


def _score_to_risk(score: float) -> RiskLevel:
    for threshold, level in _SCORE_TO_RISK:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def _risk_to_score(risk: Optional[RiskLevel]) -> Optional[float]:
    return _RISK_TO_SCORE.get(risk) if risk else None


def _verdict_from_score(score: float) -> VerdictLabel:
    if score >= SCORE_BORDERLINE_LO:
        return VerdictLabel.MALWARE
    if score <= SCORE_LOW:
        return VerdictLabel.BENIGN
    return VerdictLabel.UNCERTAIN


# ---------------------------------------------------------------------------
# DecisionEngine
# ---------------------------------------------------------------------------


class DecisionEngine:
    """
    Combines ML ensemble scores and LLM risk assessment into a calibrated
    final verdict, with explicit handling of all ML↔LLM disagreement cases.

    Usage
    -----
    >>> engine = DecisionEngine()
    >>> verdict = engine.decide(decision_input)

    Or use the class-method shortcut:
    >>> verdict = DecisionEngine.from_results(prediction, explanation)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decide(self, inp: DecisionInput) -> FinalVerdict:
        """
        Run the decision pipeline and return a FinalVerdict.

        Parameters
        ----------
        inp : DecisionInput
            Aggregated ML + LLM signals.

        Returns
        -------
        FinalVerdict
        """
        reasoning: list[str] = []
        warnings:  list[str] = []

        ml_score   = inp.ml_malware_score
        ml_conf    = inp.ml_confidence or 0.80   # default if not provided
        llm_risk   = inp.llm_risk_level
        llm_score  = _risk_to_score(llm_risk)
        available  = inp.llm_available

        reasoning.append(
            f"ML ensemble score: {ml_score:.1f}/100  "
            f"(risk={inp.ml_risk_level.value}, confidence={ml_conf:.0%})"
        )
        if available and llm_risk:
            reasoning.append(
                f"LLM risk assessment: {llm_risk.value}  "
                f"(≈{llm_score:.0f}/100), family={inp.llm_malware_family.value}"
            )
        else:
            reasoning.append("LLM risk assessment: unavailable")

        # ── Rule 1: Hard MALWARE (very high ML score) ─────────────────
        if ml_score >= SCORE_CRITICAL:
            return self._build_verdict(
                score=ml_score,
                verdict=VerdictLabel.MALWARE,
                confidence=min(ml_conf, 0.97),
                ml_weight=1.0, llm_weight=0.0,
                disagreement=DisagreementCase.NONE,
                reasoning=reasoning + [
                    f"Score ≥ {SCORE_CRITICAL} → hard MALWARE verdict, no LLM override."
                ],
                warnings=warnings,
                inp=inp,
            )

        # ── Rule 2: Hard BENIGN (very low ML score) ────────────────────
        if ml_score <= SCORE_LOW:
            return self._build_verdict(
                score=ml_score,
                verdict=VerdictLabel.BENIGN,
                confidence=min(ml_conf, 0.95),
                ml_weight=1.0, llm_weight=0.0,
                disagreement=DisagreementCase.NONE,
                reasoning=reasoning + [
                    f"Score ≤ {SCORE_LOW} → hard BENIGN verdict, no LLM override."
                ],
                warnings=warnings,
                inp=inp,
            )

        # ── Rule 3: LLM unavailable — ML-only with penalty ─────────────
        if not available or llm_score is None:
            warnings.append("LLM explanation was unavailable; relying on ML score only.")
            penalised_conf = max(ml_conf - PENALTY_LLM_MISSING, 0.30)
            verdict = _verdict_from_score(ml_score)
            return self._build_verdict(
                score=ml_score,
                verdict=verdict,
                confidence=penalised_conf,
                ml_weight=1.0, llm_weight=0.0,
                disagreement=DisagreementCase.LLM_UNAVAILABLE,
                reasoning=reasoning + ["LLM unavailable → falling back to ML-only decision."],
                warnings=warnings,
                inp=inp,
            )

        # ── Detect disagreement case ────────────────────────────────────
        disagreement = self._detect_disagreement(ml_score, llm_risk, inp)
        if disagreement != DisagreementCase.NONE:
            reasoning.append(f"Disagreement detected: {disagreement.value}")

        # ── Rule 4: Borderline zone — weight LLM more ──────────────────
        if SCORE_BORDERLINE_LO < ml_score < SCORE_BORDERLINE_HI:
            return self._handle_borderline(ml_score, llm_score, ml_conf, disagreement,
                                           reasoning, warnings, inp)

        # ── Rule 5: ML says MALWARE, LLM says LOW ──────────────────────
        if ml_score >= SCORE_HIGH and llm_risk == RiskLevel.LOW:
            warnings.append(
                "ML scores HIGH/CRITICAL malware probability but LLM assessed LOW risk. "
                "Trusting ML — static features are strong evidence."
            )
            blended = self._blend(ml_score, llm_score,
                                  WEIGHT_ML_NORMAL, WEIGHT_LLM_NORMAL)
            conf = max(ml_conf - PENALTY_DISAGREEMENT, 0.50)
            return self._build_verdict(
                score=blended,
                verdict=VerdictLabel.MALWARE,
                confidence=conf,
                ml_weight=WEIGHT_ML_NORMAL, llm_weight=WEIGHT_LLM_NORMAL,
                disagreement=DisagreementCase.ML_HIGH_LLM_LOW,
                reasoning=reasoning + [
                    f"ML score ({ml_score:.1f}) dominates; blended score = {blended:.1f}.",
                    "Decision: MALWARE (ML override of LLM low-risk assessment).",
                ],
                warnings=warnings,
                inp=inp,
            )

        # ── Rule 6: ML says BENIGN, LLM says HIGH/CRITICAL ─────────────
        if ml_score < SCORE_BORDERLINE_LO and llm_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            warnings.append(
                "ML scored below borderline but LLM flagged HIGH/CRITICAL risk. "
                "Escalating to LLM assessment — possible evasion or novel malware."
            )
            blended = self._blend(ml_score, llm_score,
                                  WEIGHT_ML_BORDERLINE, WEIGHT_LLM_BORDERLINE)
            conf = max(ml_conf - PENALTY_DISAGREEMENT, 0.45)
            verdict = _verdict_from_score(blended)
            return self._build_verdict(
                score=blended,
                verdict=verdict,
                confidence=conf,
                ml_weight=WEIGHT_ML_BORDERLINE, llm_weight=WEIGHT_LLM_BORDERLINE,
                disagreement=DisagreementCase.ML_LOW_LLM_HIGH,
                reasoning=reasoning + [
                    f"LLM risk escalation applied; blended score = {blended:.1f}.",
                    f"Decision: {verdict.value.upper()} (LLM-influenced).",
                ],
                warnings=warnings,
                inp=inp,
            )

        # ── Rule 7: Agreement — standard blend ─────────────────────────
        blended = self._blend(ml_score, llm_score, WEIGHT_ML_NORMAL, WEIGHT_LLM_NORMAL)
        conf = ml_conf  # no penalty — signals agree

        # Anchor the verdict to ML when there is no disagreement.
        # The numeric LLM proxy can drag a benign score (e.g. 20) into
        # the 15–40 uncertain band even when both sides agree it's benign.
        score_derived = _verdict_from_score(blended)
        if disagreement == DisagreementCase.NONE:
            verdict = inp.ml_verdict  # trust the ML pipeline's own classification
        else:
            verdict = score_derived

        reasoning.append(
            f"ML and LLM agree. Blended score = {blended:.1f} → {verdict.value.upper()}."
        )
        return self._build_verdict(
            score=blended,
            verdict=verdict,
            confidence=min(conf, 0.97),
            ml_weight=WEIGHT_ML_NORMAL, llm_weight=WEIGHT_LLM_NORMAL,
            disagreement=disagreement,
            reasoning=reasoning,
            warnings=warnings,
            inp=inp,
        )

    # ------------------------------------------------------------------
    # Class-method shortcut
    # ------------------------------------------------------------------

    @classmethod
    def from_results(
        cls,
        prediction: PredictionResult,
        explanation: Optional[LLMExplanation] = None,
    ) -> FinalVerdict:
        """
        Build a DecisionInput from a (PredictionResult, LLMExplanation) pair
        and immediately run the decision pipeline.

        Parameters
        ----------
        prediction : PredictionResult
            Output from the ML predict pipeline (Component 1 input).
        explanation : LLMExplanation, optional
            Output from explain_with_llm(). Pass None if LLM call failed.

        Returns
        -------
        FinalVerdict
        """
        model_scores = {
            ms.model_name: ms.probability
            for ms in prediction.model_scores
        }

        try:
            ml_verdict = VerdictLabel(prediction.verdict.lower())
        except ValueError:
            ml_verdict = VerdictLabel.UNCERTAIN

        inp = DecisionInput(
            ml_verdict=ml_verdict,
            ml_malware_score=prediction.malware_score,
            ml_confidence=prediction.confidence,
            ml_risk_level=prediction.risk_level,
            model_scores=model_scores,
            llm_risk_level=explanation.llm_risk_assessment if explanation else None,
            llm_malware_family=(
                explanation.suspected_malware_family if explanation
                else MalwareFamily.UNKNOWN
            ),
            llm_explanation=explanation.raw_explanation if explanation else "",
            llm_available=explanation is not None,
            apk_hash=prediction.apk_hash,
            apk_filename=prediction.apk_filename,
        )

        return cls().decide(inp)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _blend(ml_score: float, llm_score: float,
               w_ml: float, w_llm: float) -> float:
        """Weighted average of ML score and LLM-derived score."""
        blended = w_ml * ml_score + w_llm * llm_score
        return round(min(max(blended, 0.0), 100.0), 2)

    @staticmethod
    def _detect_disagreement(
        ml_score: float,
        llm_risk: Optional[RiskLevel],
        inp: DecisionInput,
    ) -> DisagreementCase:
        """Classify the disagreement pattern between ML and LLM signals."""
        if llm_risk is None:
            return DisagreementCase.LLM_UNAVAILABLE

        # LLM identified app as benign family but ML says malware
        if (inp.llm_malware_family == MalwareFamily.BENIGN
                and ml_score >= SCORE_BORDERLINE_LO):
            return DisagreementCase.FAMILY_MISMATCH

        # Borderline ML score
        if SCORE_BORDERLINE_LO < ml_score < SCORE_BORDERLINE_HI:
            return DisagreementCase.BORDERLINE_SCORE

        # ML very high, LLM very low
        if ml_score >= SCORE_HIGH and llm_risk == RiskLevel.LOW:
            return DisagreementCase.ML_HIGH_LLM_LOW

        # ML low, LLM high
        if ml_score < SCORE_BORDERLINE_LO and llm_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return DisagreementCase.ML_LOW_LLM_HIGH

        return DisagreementCase.NONE

    def _handle_borderline(
        self,
        ml_score: float,
        llm_score: float,
        ml_conf: float,
        disagreement: DisagreementCase,
        reasoning: list[str],
        warnings: list[str],
        inp: DecisionInput,
    ) -> FinalVerdict:
        """Handle the 40–65 ambiguous zone by weighting LLM more heavily."""
        blended = self._blend(ml_score, llm_score,
                              WEIGHT_ML_BORDERLINE, WEIGHT_LLM_BORDERLINE)
        reasoning.append(
            f"Borderline zone ({SCORE_BORDERLINE_LO}–{SCORE_BORDERLINE_HI}): "
            f"LLM weight increased to {WEIGHT_LLM_BORDERLINE:.0%}. "
            f"Blended score = {blended:.1f}."
        )

        verdict = _verdict_from_score(blended)
        conf = max(ml_conf - PENALTY_BORDERLINE, 0.40)

        if verdict == VerdictLabel.UNCERTAIN:
            warnings.append(
                "Score remains in ambiguous zone after blending. "
                "Verdict set to UNCERTAIN — manual review recommended."
            )
            conf = max(conf - 0.10, 0.30)

        reasoning.append(f"Decision: {verdict.value.upper()}.")
        return self._build_verdict(
            score=blended,
            verdict=verdict,
            confidence=conf,
            ml_weight=WEIGHT_ML_BORDERLINE, llm_weight=WEIGHT_LLM_BORDERLINE,
            disagreement=disagreement,
            reasoning=reasoning,
            warnings=warnings,
            inp=inp,
        )

    @staticmethod
    def _build_verdict(
        score: float,
        verdict: VerdictLabel,
        confidence: float,
        ml_weight: float,
        llm_weight: float,
        disagreement: DisagreementCase,
        reasoning: list[str],
        warnings: list[str],
        inp: DecisionInput,
    ) -> FinalVerdict:
        return FinalVerdict(
            verdict=verdict,
            final_risk_level=_score_to_risk(score),
            confidence=round(confidence, 4),
            malware_score=score,
            ml_score_contribution=round(ml_weight, 4),
            llm_score_contribution=round(llm_weight, 4),
            disagreement_case=disagreement,
            disagreement_resolved=(verdict != VerdictLabel.UNCERTAIN),
            reasoning=reasoning,
            warnings=warnings,
            malware_family=inp.llm_malware_family,
            apk_hash=inp.apk_hash,
            apk_filename=inp.apk_filename,
        )


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def make_final_decision(
    prediction: Union[PredictionResult, dict],
    explanation: Optional[LLMExplanation] = None,
) -> FinalVerdict:
    """
    Combine a PredictionResult and optional LLMExplanation into a FinalVerdict.

    This is the primary entry point for the Decision Engine. It accepts the
    outputs of the ML pipeline and the LLM Reasoning Layer and produces a
    single authoritative verdict with full reasoning trace.

    Parameters
    ----------
    prediction : PredictionResult | dict
        ML pipeline output. If a dict, it will be parsed into PredictionResult.
    explanation : LLMExplanation, optional
        LLM Reasoning Layer output. Pass None if the LLM call failed.

    Returns
    -------
    FinalVerdict
        {verdict, confidence, final_risk_level, malware_score,
         reasoning, warnings, disagreement_case, ...}

    Examples
    --------
    >>> from apk_extractor.decision import make_final_decision
    >>> verdict = make_final_decision(prediction_result, llm_explanation)
    >>> print(verdict.verdict)          # VerdictLabel.MALWARE
    >>> print(verdict.confidence)       # 0.87
    >>> print(verdict.reasoning)        # ['ML score: 87.3/100 ...', ...]
    >>> print(verdict.to_report_dict()) # JSON-ready dict
    """
    if isinstance(prediction, dict):
        prediction = PredictionResult(**prediction)

    logger.info(
        f"Decision Engine | apk={prediction.apk_filename or prediction.apk_hash} | "
        f"ml_score={prediction.malware_score:.1f} | "
        f"llm={'available' if explanation else 'unavailable'}"
    )

    verdict = DecisionEngine.from_results(prediction, explanation)

    logger.info(
        f"Final verdict: {verdict.verdict.value.upper()} | "
        f"risk={verdict.final_risk_level.value} | "
        f"confidence={verdict.confidence:.0%} | "
        f"disagreement={verdict.disagreement_case.value}"
    )

    return verdict
