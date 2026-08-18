"""
Model Training Script for apk_feature_extractor.

Trains a RandomForestClassifier on features extracted from APK dataset,
standardizes feature vectors, saves .pkl model artifacts to models/,
and generates models/training_report.json with performance metrics.
"""

import json
import pickle
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEATURES_CSV = PROJECT_ROOT / "features.csv"
MODELS_DIR = PROJECT_ROOT / "models"


def train_and_save_model() -> Dict[str, Any]:
    if not FEATURES_CSV.exists():
        raise FileNotFoundError(f"Feature dataset not found at {FEATURES_CSV}")

    df = pd.read_csv(FEATURES_CSV)
    print(f"Loaded dataset from {FEATURES_CSV} with {len(df)} rows and {len(df.columns)} columns.")

    # Target label: 1 if APK... (Malware), 0 if Benign...
    df["label"] = df["apk_filename"].apply(
        lambda name: 1 if str(name).startswith("APK") else 0
    )

    # Exclude non-numeric/metadata columns
    drop_cols = [
        "label",
        "apk_hash",
        "apk_filename",
        "extraction_timestamp",
        "manifest_package_name",
        "manifest_version_name",
        "cert_issuer_hash",
        "cert_subject_hash",
        "cert_signature_algorithm",
    ]

    feature_cols = [col for col in df.columns if col not in drop_cols]
    
    # Convert all feature columns to numeric, replacing any non-convertibles or NaN with 0
    X_df = df[feature_cols].copy()
    for col in X_df.columns:
        X_df[col] = pd.to_numeric(X_df[col], errors="coerce").fillna(0)

    X = X_df.values.astype(float)
    y = df["label"].values.astype(int)

    feature_names = list(X_df.columns)

    malware_count = int(np.sum(y == 1))
    benign_count = int(np.sum(y == 0))
    total_count = int(len(y))

    print(f"Dataset stats: Total={total_count}, Malware={malware_count}, Benign={benign_count}")

    # Train/Test Split (stratified)
    test_size = 0.25 if total_count >= 10 else 0.5
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_scaled, y_train)

    # Metrics on test set
    y_pred = clf.predict(X_test_scaled)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Re-fit scaler and clf on full dataset before saving artifacts for production use
    scaler_full = StandardScaler()
    X_full_scaled = scaler_full.fit_transform(X)
    clf_full = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_full.fit(X_full_scaled, y)

    # Save artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    with open(MODELS_DIR / "random_forest.pkl", "wb") as f:
        pickle.dump(clf_full, f)

    with open(MODELS_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler_full, f)

    with open(MODELS_DIR / "feature_names.pkl", "wb") as f:
        pickle.dump(feature_names, f)

    report = {
        "dataset_sample_count": total_count,
        "malware_count": malware_count,
        "benign_count": benign_count,
        "feature_count": len(feature_names),
        "test_set_size": len(y_test),
        "defensible_model_assessment": total_count >= 500,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": cm,
        },
    }

    with open(MODELS_DIR / "training_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Artifacts successfully saved to {MODELS_DIR}")
    print(f"Report: {json.dumps(report, indent=2)}")

    return report


if __name__ == "__main__":
    train_and_save_model()
