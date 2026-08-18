"""
ML Predictor — wraps the trained .pkl ensemble models.

Provides a clean predict() interface that returns a PredictionResult
compatible with the LLM Reasoning Layer and Decision Engine.

If no .pkl files are found, falls back to a rule-based heuristic predictor
so the API can still function during development without trained models.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

from apk_extractor.llm.schemas import (
    ModelScore,
    PredictionResult,
    RiskLevel,
    SuspiciousFeature,
)
from apk_extractor.models.features import APKFeatures


# ---------------------------------------------------------------------------
# Feature importance heuristics (used when .pkl models unavailable)
# ---------------------------------------------------------------------------

# Features weighted by known malware signal strength
_HEURISTIC_WEIGHTS: Dict[str, float] = {
    "perm_SEND_SMS": 0.14,
    "perm_RECEIVE_SMS": 0.11,
    "perm_READ_SMS": 0.10,
    "api_sendTextMessage": 0.09,
    "api_sendMultipartTextMessage": 0.08,
    "perm_BIND_DEVICE_ADMIN": 0.10,
    "perm_SYSTEM_ALERT_WINDOW": 0.09,
    "perm_BIND_ACCESSIBILITY_SERVICE": 0.10,
    "perm_REQUEST_INSTALL_PACKAGES": 0.08,
    "api_DexClassLoader": 0.09,
    "api_Runtime_exec": 0.08,
    "api_ProcessBuilder_start": 0.07,
    "perm_BIND_VPN_SERVICE": 0.07,
    "api_TelephonyManager": 0.04,
    "perm_READ_PHONE_STATE": 0.04,
    "api_getDeviceId": 0.04,
    "api_getSubscriberId": 0.04,
    "api_Method_invoke": 0.03,
    "api_Class_forName": 0.03,
    "perm_WRITE_EXTERNAL_STORAGE": 0.02,
    "perm_RECORD_AUDIO": 0.05,
    "perm_CAMERA": 0.03,
    "perm_ACCESS_FINE_LOCATION": 0.03,
}

_CERT_PENALTY = 0.08   # unsigned APK adds to score
_DEBUG_PENALTY = 0.05  # debuggable APK adds to score


def _score_to_risk(score: float) -> RiskLevel:
    if score >= 85:   return RiskLevel.CRITICAL
    if score >= 65:   return RiskLevel.HIGH
    if score >= 40:   return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _apk_features_to_flat(features: APKFeatures) -> Dict[str, Any]:
    """Flatten APKFeatures into a single key→value dict for model input."""
    flat: Dict[str, Any] = {}
    flat.update(features.permissions.permissions)
    flat.update(features.api_calls.api_calls)
    for k, v in features.manifest.model_dump().items():
        flat[k] = v
    for k, v in features.code_structure.model_dump().items():
        flat[k] = v
    for k, v in features.certificate.model_dump().items():
        flat[k] = v
    for k, v in features.structural.model_dump().items():
        flat[k] = v
    return flat


# ---------------------------------------------------------------------------
# MLPredictor
# ---------------------------------------------------------------------------


class MLPredictor:
    """
    Wraps trained scikit-learn / XGBoost .pkl model files.

    Falls back to a heuristic score if no models are loaded —
    this keeps the API functional during development.

    Parameters
    ----------
    models_dir : Path, optional
        Directory containing ``random_forest.pkl``, ``svm.pkl``,
        ``xgboost.pkl``, and (optionally) ``scaler.pkl`` / ``selector.pkl``.
    """

    # Expected model file names
    _MODEL_FILES = {
        "random_forest": "random_forest.pkl",
        "svm":           "svm.pkl",
        "xgboost":       "xgboost.pkl",
    }
    _SCALER_FILE   = "scaler.pkl"
    _SELECTOR_FILE = "selector.pkl"
    _FEATURES_FILE = "feature_names.pkl"   # ordered list of feature names

    def __init__(self, models_dir: Optional[Path] = None) -> None:
        self.models_dir = Path(models_dir) if models_dir else None
        self._models: Dict[str, Any] = {}
        self._scaler: Optional[Any] = None
        self._selector: Optional[Any] = None
        self._feature_names: Optional[List[str]] = None
        self._heuristic_mode = True

        if self.models_dir and self.models_dir.exists():
            self._load_models()
        else:
            logger.warning(
                "No models directory provided or directory not found. "
                "Running in HEURISTIC mode — predictions are rule-based estimates."
            )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_models(self) -> None:
        """Try to load all .pkl files from models_dir."""
        loaded = []
        for name, filename in self._MODEL_FILES.items():
            path = self.models_dir / filename
            if path.exists():
                try:
                    with open(path, "rb") as f:
                        self._models[name] = pickle.load(f)
                    loaded.append(name)
                    logger.info(f"Loaded model: {name} from {path}")
                except Exception as e:
                    logger.warning(f"Failed to load {name}: {e}")

        # Optional preprocessing artifacts
        for attr, filename in [("_scaler", self._SCALER_FILE),
                                ("_selector", self._SELECTOR_FILE),
                                ("_feature_names", self._FEATURES_FILE)]:
            path = self.models_dir / filename
            if path.exists():
                try:
                    with open(path, "rb") as f:
                        setattr(self, attr, pickle.load(f))
                    logger.info(f"Loaded {filename}")
                except Exception as e:
                    logger.warning(f"Could not load {filename}: {e}")

        if loaded:
            self._heuristic_mode = False
            logger.info(f"MLPredictor ready with models: {loaded}")
        else:
            logger.warning("No models loaded — falling back to heuristic mode.")

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features: APKFeatures) -> PredictionResult:
        """
        Run ML prediction on extracted APK features.

        Parameters
        ----------
        features : APKFeatures
            Output of APKFeatureExtractor.extract().

        Returns
        -------
        PredictionResult
            Compatible with explain_with_llm() and make_final_decision().
        """
        if self._heuristic_mode:
            return self._heuristic_predict(features)
        return self._model_predict(features)

    # ------------------------------------------------------------------
    # Model-based prediction
    # ------------------------------------------------------------------

    def _model_predict(self, features: APKFeatures) -> PredictionResult:
        """Run the trained ensemble and return a PredictionResult."""
        flat = _apk_features_to_flat(features)

        # Build feature vector in the correct column order
        if self._feature_names:
            X = np.array([[flat.get(f, 0) for f in self._feature_names]], dtype=float)
        else:
            # Fall back: sorted keys
            keys = sorted(flat.keys())
            X = np.array([[flat.get(k, 0) for k in keys]], dtype=float)

        # Preprocessing
        if self._scaler:
            X = self._scaler.transform(X)
        if self._selector:
            X = self._selector.transform(X)

        # Per-model predictions
        model_scores: List[ModelScore] = []
        proba_values: List[float] = []

        for name, model in self._models.items():
            try:
                if hasattr(model, "predict_proba"):
                    proba = float(model.predict_proba(X)[0][1])
                else:
                    # SVM without probability=True
                    raw = float(model.decision_function(X)[0])
                    # Sigmoid normalisation
                    proba = 1.0 / (1.0 + np.exp(-raw))

                verdict_str = "malware" if proba >= 0.5 else "benign"
                model_scores.append(ModelScore(
                    model_name=name, probability=proba, verdict=verdict_str
                ))
                proba_values.append(proba)
            except Exception as e:
                logger.warning(f"Model {name} prediction failed: {e}")

        if not proba_values:
            logger.error("All models failed — falling back to heuristic.")
            return self._heuristic_predict(features)

        # Ensemble: simple average
        ensemble_proba = float(np.mean(proba_values))
        malware_score  = round(ensemble_proba * 100, 2)
        verdict_str    = "malware" if ensemble_proba >= 0.5 else "benign"
        risk_level     = _score_to_risk(malware_score)

        # Confidence: 1 - normalised std (higher agreement → higher confidence)
        std = float(np.std(proba_values)) if len(proba_values) > 1 else 0.0
        confidence = round(max(0.0, 1.0 - 2 * std), 4)

        # Build suspicious features from the flat dict + real model importances if available
        real_importances = None
        if "random_forest" in self._models and hasattr(self._models["random_forest"], "feature_importances_") and self._feature_names:
            importances = self._models["random_forest"].feature_importances_
            real_importances = dict(zip(self._feature_names, importances))
        elif "xgboost" in self._models and hasattr(self._models["xgboost"], "feature_importances_") and self._feature_names:
            importances = self._models["xgboost"].feature_importances_
            real_importances = dict(zip(self._feature_names, importances))

        suspicious = self._build_suspicious_features(flat, real_importances)
        top_names  = [sf.feature_name for sf in suspicious[:10]]

        return PredictionResult(
            apk_hash=features.apk_hash,
            apk_filename=features.apk_filename,
            verdict=verdict_str,
            risk_level=risk_level,
            malware_score=malware_score,
            confidence=confidence,
            model_scores=model_scores,
            suspicious_features=suspicious,
            top_features=top_names,
            feature_summary=self._build_feature_summary(features),
        )

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    def _heuristic_predict(self, features: APKFeatures) -> PredictionResult:
        """
        Rule-based heuristic when no trained models are available.

        Computes a weighted sum over known high-signal features,
        then applies certificate and debug penalties.
        """
        flat = _apk_features_to_flat(features)
        raw_score = 0.0

        for feat, weight in _HEURISTIC_WEIGHTS.items():
            val = flat.get(feat, 0)
            if isinstance(val, (int, float)) and val > 0:
                raw_score += weight

        # Certificate penalties
        if not features.certificate.is_signed:
            raw_score += _CERT_PENALTY
        if features.manifest.debuggable:
            raw_score += _DEBUG_PENALTY

        # Normalise to 0–100
        malware_score = round(min(raw_score * 100, 100.0), 2)
        verdict_str   = "malware" if malware_score >= 40 else "benign"
        risk_level    = _score_to_risk(malware_score)

        # Synthetic per-model scores (heuristic, not real models)
        synthetic_models = [
            ModelScore(model_name="heuristic_rf",  probability=min(raw_score * 1.05, 1.0), verdict=verdict_str),
            ModelScore(model_name="heuristic_xgb", probability=min(raw_score * 0.98, 1.0), verdict=verdict_str),
            ModelScore(model_name="heuristic_svm", probability=min(raw_score * 1.02, 1.0), verdict=verdict_str),
        ]

        suspicious = self._build_suspicious_features(flat)
        top_names  = [sf.feature_name for sf in suspicious[:10]]

        logger.info(
            f"Heuristic prediction: score={malware_score}, verdict={verdict_str}"
        )

        return PredictionResult(
            apk_hash=features.apk_hash,
            apk_filename=features.apk_filename,
            verdict=verdict_str,
            risk_level=risk_level,
            malware_score=malware_score,
            confidence=0.70,   # fixed lower confidence for heuristic
            model_scores=synthetic_models,
            suspicious_features=suspicious,
            top_features=top_names,
            feature_summary=self._build_feature_summary(features),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_suspicious_features(flat: Dict[str, Any], real_importances: Optional[Dict[str, float]] = None) -> List[SuspiciousFeature]:
        """Return suspicious features sorted by importance, highest first."""
        results = []
        
        if real_importances:
            active_feats = []
            for feat, weight in real_importances.items():
                val = flat.get(feat)
                if val is not None and val not in (0, False) and weight > 0:
                    active_feats.append((feat, weight, val))
            
            active_feats.sort(key=lambda x: x[1], reverse=True)
            
            # Limit to top 20 to avoid overloading the LLM
            for feat, weight, val in active_feats[:20]:
                results.append(SuspiciousFeature(
                    feature_name=feat,
                    value=val,
                    importance=float(weight),
                ))
        else:
            for feat, weight in sorted(_HEURISTIC_WEIGHTS.items(),
                                       key=lambda x: x[1], reverse=True):
                val = flat.get(feat)
                if val is not None and val not in (0, False):
                    results.append(SuspiciousFeature(
                        feature_name=feat,
                        value=val,
                        importance=weight,
                    ))
        return results

    @staticmethod
    def _build_feature_summary(features: APKFeatures) -> Dict[str, Any]:
        """Build the compact feature_summary dict sent to the LLM."""
        return {
            "permissions": features.permissions.permissions,
            "api_calls":   features.api_calls.api_calls,
            "manifest":    features.manifest.model_dump(),
            "code_structure": features.code_structure.model_dump(),
            "certificate": features.certificate.model_dump(),
        }

    @property
    def is_heuristic_mode(self) -> bool:
        """True when running without trained .pkl models."""
        return self._heuristic_mode
