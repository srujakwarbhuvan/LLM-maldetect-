"""
Demo / smoke-test for the LLM Reasoning Layer.

Usage
-----
    # Set your API key first
    $env:ANTHROPIC_API_KEY = "sk-ant-..."

    # Run with the real output.json from this repo
    python -m apk_extractor.llm.demo

    # Or from the project root:
    python src/apk_extractor/llm/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ── Resolve import path ──────────────────────────────────────────────────────
# Allow running directly: python src/apk_extractor/llm/demo.py
_repo_root = Path(__file__).resolve().parents[4]  # d:\feature
_src = _repo_root / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from apk_extractor.llm import explain_with_llm
from apk_extractor.llm.schemas import PredictionResult, SuspiciousFeature, ModelScore, RiskLevel

console = Console()


# ---------------------------------------------------------------------------
# Sample prediction result (mirrors predict.py JSON output format)
# ---------------------------------------------------------------------------

SAMPLE_PREDICTION: dict = {
    "apk_hash": "000e7149ab7550ef605c2b22cb1beaffbee9219699661d89158d490a3ffa393a",
    "apk_filename": "APK000E7149.apk",
    "verdict": "malware",
    "risk_level": "HIGH",
    "malware_score": 87.3,
    "confidence": 0.92,
    "model_scores": [
        {"model_name": "random_forest", "probability": 0.91, "verdict": "malware"},
        {"model_name": "xgboost",       "probability": 0.88, "verdict": "malware"},
        {"model_name": "svm",           "probability": 0.82, "verdict": "malware"},
    ],
    "suspicious_features": [
        {"feature_name": "perm_SEND_SMS",        "value": 1, "importance": 0.1423},
        {"feature_name": "perm_RECEIVE_SMS",     "value": 1, "importance": 0.1187},
        {"feature_name": "perm_READ_SMS",        "value": 1, "importance": 0.0981},
        {"feature_name": "api_sendTextMessage",  "value": 1, "importance": 0.0876},
        {"feature_name": "api_TelephonyManager", "value": 1, "importance": 0.0754},
        {"feature_name": "perm_READ_PHONE_STATE","value": 1, "importance": 0.0698},
        {"feature_name": "api_getNetworkOperator","value": 1,"importance": 0.0612},
        {"feature_name": "perm_WAKE_LOCK",       "value": 1, "importance": 0.0534},
    ],
    "top_features": [
        "perm_SEND_SMS", "perm_RECEIVE_SMS", "perm_READ_SMS",
        "api_sendTextMessage", "api_TelephonyManager",
    ],
    "feature_summary": {
        "permissions": {
            "perm_INTERNET": 1,
            "perm_READ_PHONE_STATE": 1,
            "perm_READ_SMS": 1,
            "perm_RECEIVE_SMS": 1,
            "perm_SEND_SMS": 1,
            "perm_WAKE_LOCK": 1,
            "perm_WRITE_EXTERNAL_STORAGE": 1,
        },
        "api_calls": {
            "api_DefaultHttpClient": 1,
            "api_HttpClient": 1,
            "api_NotificationManager": 1,
            "api_TelephonyManager": 1,
            "api_getDefault": 1,
            "api_getNetworkOperator": 1,
            "api_listen": 1,
            "api_notify": 1,
            "api_open": 1,
            "api_sendTextMessage": 1,
        },
        "manifest": {
            "num_dangerous_permissions": 5,
            "num_services": 1,
            "num_receivers": 4,
            "num_exported_receivers": 0,
            "debuggable": False,
            "uses_native_code": False,
            "min_sdk_version": 5,
            "target_sdk_version": 5,
        },
        "code_structure": {
            "num_classes": 39,
            "num_methods": 168,
            "class_name_entropy": 4.46,
            "method_name_entropy": 4.58,
            "uses_reflection": False,
            "reflection_count": 0,
        },
        "certificate": {
            "is_signed": False,
            "is_self_signed": False,
            "is_expired": False,
            "validity_days": None,
            "signature_algorithm": None,
        },
    },
}


def _render_explanation(explanation) -> None:
    """Pretty-print the LLMExplanation using Rich."""
    console.print()
    console.print(Panel(
        f"[bold cyan]{explanation.raw_explanation}[/bold cyan]",
        title="[bold yellow]🔍 LLM Analysis[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
    ))

    # Suspected family + risk
    console.print(Panel(
        f"[bold red]Family:[/bold red]  {explanation.suspected_malware_family.value}\n"
        f"[bold red]LLM Risk:[/bold red] {explanation.llm_risk_assessment.value if explanation.llm_risk_assessment else 'N/A'}",
        title="[bold red]Verdict[/bold red]",
        border_style="red",
    ))

    # Likely behaviours
    if explanation.likely_behaviors:
        t = Table("Likely Behaviors", box=box.ROUNDED, style="dim", header_style="bold magenta")
        t.add_column("", style="white")
        for b in explanation.likely_behaviors:
            t.add_row(b)
        console.print(t)

    # Recommendations
    if explanation.user_recommendations:
        t = Table("User Recommendations", box=box.ROUNDED, style="dim", header_style="bold green")
        t.add_column("", style="white")
        for r in explanation.user_recommendations:
            t.add_row(r)
        console.print(t)

    # Technical indicators
    if explanation.technical_indicators:
        t = Table("Technical Indicators", box=box.ROUNDED, style="dim", header_style="bold blue")
        t.add_column("", style="white")
        for i in explanation.technical_indicators:
            t.add_row(i)
        console.print(t)

    # Token usage
    console.print(
        f"\n[dim]Token usage — input: {explanation.input_tokens} | "
        f"output: {explanation.output_tokens} | model: {explanation.model_used}[/dim]"
    )


def main() -> None:
    console.rule("[bold blue]Android Malware LLM Reasoning Layer — Demo[/bold blue]")
    console.print(f"\n[bold]APK:[/bold] {SAMPLE_PREDICTION['apk_filename']}")
    console.print(f"[bold]Score:[/bold] {SAMPLE_PREDICTION['malware_score']}/100  |  "
                  f"[bold]Risk:[/bold] {SAMPLE_PREDICTION['risk_level']}  |  "
                  f"[bold]Verdict:[/bold] {SAMPLE_PREDICTION['verdict'].upper()}\n")

    console.print("[dim]Calling Anthropic claude-sonnet-4-20250514 with extended thinking...[/dim]")

    try:
        explanation = explain_with_llm(SAMPLE_PREDICTION, enable_thinking=True)
        _render_explanation(explanation)

        # Also dump as JSON for downstream use
        output_path = _repo_root / "data" / "output" / "llm_explanation.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(explanation.to_report_dict(), f, indent=2)
        console.print(f"\n[green]✓ Explanation saved to:[/green] {output_path}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        logger.exception("Demo failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
