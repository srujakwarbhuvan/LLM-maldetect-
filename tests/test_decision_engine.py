"""
Tests for the Decision Engine — covers all 7 decision rules and edge cases.

Run with:  venv\Scripts\python -m pytest tests/test_decision_engine.py -v
"""

from __future__ import annotations

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apk_extractor.decision.engine import DecisionEngine, make_final_decision, SCORE_CRITICAL, SCORE_LOW
from apk_extractor.decision.schemas import DecisionInput, DisagreementCase, VerdictLabel
from apk_extractor.llm.schemas import (
    LLMExplanation, MalwareFamily, ModelScore, PredictionResult, RiskLevel, SuspiciousFeature
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_prediction(score: float, risk: RiskLevel = RiskLevel.HIGH,
                     verdict: str = "malware") -> PredictionResult:
    return PredictionResult(
        apk_hash="abc123",
        apk_filename="test.apk",
        verdict=verdict,
        risk_level=risk,
        malware_score=score,
        confidence=0.90,
        model_scores=[
            ModelScore(model_name="random_forest", probability=score / 100, verdict=verdict),
            ModelScore(model_name="xgboost",       probability=score / 100, verdict=verdict),
        ],
    )


def _make_explanation(risk: RiskLevel,
                      family: MalwareFamily = MalwareFamily.SMS_STEALER) -> LLMExplanation:
    return LLMExplanation(
        raw_explanation="Test explanation.",
        suspected_malware_family=family,
        llm_risk_assessment=risk,
    )


# ---------------------------------------------------------------------------
# Rule 1: Hard MALWARE — score ≥ 85
# ---------------------------------------------------------------------------

class TestRule1HardMalware:
    def test_critical_score_always_malware(self):
        pred = _make_prediction(92.0, RiskLevel.CRITICAL)
        expl = _make_explanation(RiskLevel.LOW)          # LLM says LOW — should be ignored
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.MALWARE
        assert verdict.final_risk_level == RiskLevel.CRITICAL
        assert verdict.ml_score_contribution == 1.0
        assert verdict.llm_score_contribution == 0.0

    def test_boundary_85_is_hard_malware(self):
        pred = _make_prediction(SCORE_CRITICAL)
        verdict = make_final_decision(pred, None)
        assert verdict.verdict == VerdictLabel.MALWARE


# ---------------------------------------------------------------------------
# Rule 2: Hard BENIGN — score ≤ 15
# ---------------------------------------------------------------------------

class TestRule2HardBenign:
    def test_very_low_score_always_benign(self):
        pred = _make_prediction(5.0, RiskLevel.LOW, "benign")
        expl = _make_explanation(RiskLevel.CRITICAL)    # LLM says CRITICAL — should be ignored
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.BENIGN
        assert verdict.final_risk_level == RiskLevel.LOW
        assert verdict.ml_score_contribution == 1.0

    def test_boundary_15_is_hard_benign(self):
        pred = _make_prediction(SCORE_LOW, RiskLevel.LOW, "benign")
        verdict = make_final_decision(pred, None)
        assert verdict.verdict == VerdictLabel.BENIGN


# ---------------------------------------------------------------------------
# Rule 3: LLM unavailable
# ---------------------------------------------------------------------------

class TestRule3LLMUnavailable:
    def test_no_explanation_uses_ml_only(self):
        pred = _make_prediction(75.0)
        verdict = make_final_decision(pred, explanation=None)
        assert verdict.disagreement_case == DisagreementCase.LLM_UNAVAILABLE
        assert verdict.ml_score_contribution == 1.0
        assert len(verdict.warnings) >= 1

    def test_confidence_is_penalised_when_llm_missing(self):
        pred = _make_prediction(75.0)
        pred.confidence = 0.90
        verdict = make_final_decision(pred, explanation=None)
        # Confidence must be < 0.90 (penalty applied)
        assert verdict.confidence < 0.90


# ---------------------------------------------------------------------------
# Rule 4: Borderline zone (40–65)
# ---------------------------------------------------------------------------

class TestRule4BorderlineZone:
    def test_borderline_gives_higher_llm_weight(self):
        pred = _make_prediction(52.0, RiskLevel.MEDIUM)
        expl = _make_explanation(RiskLevel.HIGH)
        verdict = make_final_decision(pred, expl)
        assert verdict.llm_score_contribution == pytest.approx(0.40)

    def test_borderline_malware_when_llm_high(self):
        pred = _make_prediction(55.0, RiskLevel.MEDIUM)
        expl = _make_explanation(RiskLevel.HIGH)
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.MALWARE

    def test_borderline_uncertain_when_blended_stays_ambiguous(self):
        # ML=52, LLM≈LOW(12): blended≈0.6*52+0.4*12 = 36 → UNCERTAIN (15 < 36 < 40)
        pred = _make_prediction(52.0, RiskLevel.MEDIUM)
        expl = _make_explanation(RiskLevel.LOW, MalwareFamily.BENIGN)
        verdict = make_final_decision(pred, expl)
        # Blended = 0.6*52 + 0.4*12 = 36 → falls in 15–40 UNCERTAIN band
        assert verdict.verdict in (VerdictLabel.UNCERTAIN, VerdictLabel.BENIGN)


# ---------------------------------------------------------------------------
# Rule 5: ML high, LLM low → trust ML
# ---------------------------------------------------------------------------

class TestRule5MLHighLLMLow:
    def test_ml_high_llm_low_trusts_ml(self):
        pred = _make_prediction(78.0, RiskLevel.HIGH)
        expl = _make_explanation(RiskLevel.LOW)
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.MALWARE
        assert verdict.disagreement_case == DisagreementCase.ML_HIGH_LLM_LOW
        assert len(verdict.warnings) >= 1

    def test_confidence_reduced_on_ml_high_llm_low(self):
        pred = _make_prediction(78.0, RiskLevel.HIGH)
        expl = _make_explanation(RiskLevel.LOW)
        verdict = make_final_decision(pred, expl)
        assert verdict.confidence < 0.90  # penalty applied


# ---------------------------------------------------------------------------
# Rule 6: ML low, LLM high → escalate to LLM
# ---------------------------------------------------------------------------

class TestRule6MLLowLLMHigh:
    def test_llm_escalation_applied(self):
        pred = _make_prediction(30.0, RiskLevel.LOW, "benign")
        expl = _make_explanation(RiskLevel.HIGH)
        verdict = make_final_decision(pred, expl)
        assert verdict.disagreement_case == DisagreementCase.ML_LOW_LLM_HIGH
        assert verdict.llm_score_contribution == pytest.approx(0.40)

    def test_llm_critical_escalates_verdict(self):
        pred = _make_prediction(25.0, RiskLevel.LOW, "benign")
        expl = _make_explanation(RiskLevel.CRITICAL)
        verdict = make_final_decision(pred, expl)
        # blended = 0.6*25 + 0.4*92 = 51.8 → MALWARE
        assert verdict.verdict == VerdictLabel.MALWARE


# ---------------------------------------------------------------------------
# Rule 7: Agreement — standard blend
# ---------------------------------------------------------------------------

class TestRule7Agreement:
    def test_agreement_high_confidence(self):
        pred = _make_prediction(80.0, RiskLevel.HIGH)
        expl = _make_explanation(RiskLevel.HIGH)
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.MALWARE
        assert verdict.disagreement_case == DisagreementCase.NONE
        assert verdict.confidence >= 0.85

    def test_benign_agreement(self):
        pred = _make_prediction(20.0, RiskLevel.LOW, "benign")
        expl = _make_explanation(RiskLevel.LOW, MalwareFamily.BENIGN)
        verdict = make_final_decision(pred, expl)
        assert verdict.verdict == VerdictLabel.BENIGN
        assert verdict.disagreement_case == DisagreementCase.NONE


# ---------------------------------------------------------------------------
# DecisionEngine.from_results() integration
# ---------------------------------------------------------------------------

class TestFromResults:
    def test_from_results_with_explanation(self):
        pred = _make_prediction(87.3, RiskLevel.HIGH)
        expl = _make_explanation(RiskLevel.HIGH, MalwareFamily.SMS_STEALER)
        verdict = DecisionEngine.from_results(pred, expl)
        assert verdict.verdict == VerdictLabel.MALWARE
        assert verdict.malware_family == MalwareFamily.SMS_STEALER

    def test_from_results_without_explanation(self):
        pred = _make_prediction(72.0, RiskLevel.HIGH)
        verdict = DecisionEngine.from_results(pred, explanation=None)
        assert verdict.disagreement_case == DisagreementCase.LLM_UNAVAILABLE

    def test_to_report_dict_has_required_keys(self):
        pred = _make_prediction(87.3, RiskLevel.HIGH)
        verdict = DecisionEngine.from_results(pred, None)
        d = verdict.to_report_dict()
        required = {"verdict", "final_risk_level", "confidence", "malware_score",
                    "malware_family", "disagreement", "weights", "reasoning", "warnings"}
        assert required.issubset(d.keys())

    def test_make_final_decision_accepts_dict(self):
        pred_dict = {
            "verdict": "malware",
            "risk_level": "HIGH",
            "malware_score": 87.3,
        }
        verdict = make_final_decision(pred_dict, explanation=None)
        assert isinstance(verdict.verdict, VerdictLabel)
