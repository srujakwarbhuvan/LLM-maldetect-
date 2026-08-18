"""
Prompt builder for the LLM Reasoning Layer.

Responsible for constructing well-structured, information-dense prompts
from a PredictionResult, keeping token usage predictable and focused.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_extractor.llm.schemas import PredictionResult


# ---------------------------------------------------------------------------
# Feature descriptions — map raw feature names → human-readable context
# ---------------------------------------------------------------------------

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    # Permissions
    "perm_SEND_SMS": "Sends SMS messages (often used by premium SMS malware)",
    "perm_RECEIVE_SMS": "Intercepts incoming SMS messages",
    "perm_READ_SMS": "Reads SMS inbox (credential/OTP theft)",
    "perm_READ_CALL_LOG": "Accesses call history",
    "perm_READ_CONTACTS": "Reads device contacts (data exfiltration)",
    "perm_READ_PHONE_STATE": "Reads IMEI, phone number, SIM info",
    "perm_RECORD_AUDIO": "Can record microphone audio (spyware)",
    "perm_CAMERA": "Can silently take photos/video",
    "perm_ACCESS_FINE_LOCATION": "Tracks precise GPS location",
    "perm_ACCESS_COARSE_LOCATION": "Tracks approximate location",
    "perm_SYSTEM_ALERT_WINDOW": "Draws overlays over other apps (phishing/banking overlay attacks)",
    "perm_BIND_ACCESSIBILITY_SERVICE": "Abuses Accessibility API for UI interactions (banking malware)",
    "perm_BIND_DEVICE_ADMIN": "Device Administrator privileges (ransomware/persistence)",
    "perm_REQUEST_INSTALL_PACKAGES": "Can silently install additional APKs (dropper)",
    "perm_WRITE_EXTERNAL_STORAGE": "Writes to SD card (data collection/ransomware)",
    "perm_INTERNET": "Network access",
    "perm_WAKE_LOCK": "Prevents device from sleeping (background operations)",
    "perm_RECEIVE_BOOT_COMPLETED": "Auto-starts on device boot (persistence)",
    "perm_BIND_VPN_SERVICE": "Can intercept all network traffic (MitM / spyware)",
    "perm_FOREGROUND_SERVICE": "Runs persistent foreground service",
    # API calls
    "api_sendTextMessage": "Programmatically sends SMS messages",
    "api_sendMultipartTextMessage": "Sends multi-part SMS (premium SMS fraud)",
    "api_TelephonyManager": "Accesses telephony state and device IDs",
    "api_getDeviceId": "Harvests hardware device identifier (IMEI)",
    "api_getSubscriberId": "Harvests SIM/IMSI identifier",
    "api_getLine1Number": "Retrieves device phone number",
    "api_Runtime_exec": "Executes shell commands (root exploits)",
    "api_ProcessBuilder_start": "Starts OS processes (command execution)",
    "api_DexClassLoader": "Dynamically loads code at runtime (dropper/evasion)",
    "api_PathClassLoader": "Loads classes from file system (code injection)",
    "api_Cipher_getInstance": "Uses cryptographic cipher (ransomware/C2 comms)",
    "api_HttpClient": "Makes HTTP network connections",
    "api_HttpURLConnection": "Makes HTTPS network connections",
    "api_ServerSocket": "Opens a local server socket (backdoor)",
    "api_Socket": "Opens raw TCP/UDP socket",
    "api_ContentResolver_query": "Queries content providers (contacts, SMS, etc.)",
    "api_AudioRecord": "Records audio from microphone",
    "api_Camera_open": "Opens camera for capture",
    "api_ClipboardManager": "Reads/writes clipboard (credential theft)",
    "api_getPrimaryClip": "Reads clipboard content",
    "api_getAllMessagesFromIcc": "Reads SIM card SMS messages",
    "api_getLastKnownLocation": "Retrieves cached GPS location",
    "api_requestLocationUpdates": "Subscribes to real-time GPS updates",
    "api_Method_invoke": "Reflective method invocation (obfuscation/evasion)",
    "api_Class_forName": "Dynamic class loading via reflection",
    "api_System_load": "Loads native (.so) library",
    # Manifest / code structure
    "num_dangerous_permissions": "Count of dangerous Android permissions requested",
    "num_services": "Number of background services declared",
    "num_receivers": "Number of broadcast receivers (event hooks)",
    "debuggable": "App marked as debuggable (unusual in production)",
    "uses_native_code": "App uses native (.so) libraries",
    "class_name_entropy": "Entropy of class names (high = likely obfuscated)",
    "method_name_entropy": "Entropy of method names (high = likely obfuscated)",
    # Certificate
    "is_signed": "Whether the APK is signed",
    "is_self_signed": "Whether the certificate is self-signed",
    "is_expired": "Whether the signing certificate has expired",
    "validity_days": "Signing certificate validity period in days",
}


def describe_feature(feature_name: str) -> str:
    """Return a human-readable description for a feature name, or a fallback."""
    return _FEATURE_DESCRIPTIONS.get(
        feature_name,
        feature_name.replace("_", " ").replace("perm ", "permission: ").replace("api ", "API: "),
    )


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert Android malware analyst and security researcher with deep knowledge of:
- Android malware families (banking trojans, spyware, ransomware, SMS stealers, droppers, etc.)
- Android security internals, permissions model, and dangerous API patterns
- Reverse engineering indicators and behavioural analysis techniques

You will receive a structured JSON report from an automated ML-based malware detection pipeline.
Your task is to produce a professional, human-readable security analysis report.

You MUST structure your response with these exact XML-like section tags:
<EXPLANATION>
  A 2-4 paragraph narrative analysis. Explain what the app likely does, what malware family it
  resembles (if applicable), and the key evidence. Write for a technical security team audience.
</EXPLANATION>

<FAMILY>
  One of: Banker, Spyware, Ransomware, Adware, Dropper, Backdoor, SMS Stealer, Rootkit,
  Clicker, Cryptominer, Remote Access Trojan, Unknown, Benign
</FAMILY>

<BEHAVIORS>
  - Bullet point 1
  - Bullet point 2
  (List 3-6 specific likely behaviours based on the evidence)
</BEHAVIORS>

<RECOMMENDATIONS>
  - Recommendation 1
  - Recommendation 2
  (List 3-5 actionable steps for the user/security team)
</RECOMMENDATIONS>

<TECHNICAL_INDICATORS>
  - Indicator 1
  - Indicator 2
  (List 3-6 key technical indicators that support the verdict)
</TECHNICAL_INDICATORS>

<RISK_ASSESSMENT>
  One of: LOW, MEDIUM, HIGH, CRITICAL
  (Your independent risk assessment based on the evidence)
</RISK_ASSESSMENT>

Be precise, evidence-based, and avoid speculation beyond what the features support.
If the app appears benign, say so clearly and explain why the score may be elevated.
"""

_USER_PROMPT_TEMPLATE = """\
## ML Pipeline Detection Report

### Verdict Summary
- **File**: {filename}
- **Verdict**: {verdict}
- **Risk Level**: {risk_level}
- **Ensemble Malware Score**: {malware_score:.1f}/100
- **Confidence**: {confidence}

### Per-Model Scores
{model_scores_section}

### Top Suspicious Features (Most Influential)
{suspicious_features_section}

### Feature Context
{feature_context_section}

---
Please provide your expert analysis of this APK based on the above detection data.
"""


def _format_model_scores(prediction: "PredictionResult") -> str:
    if not prediction.model_scores:
        return "*(model scores not available)*"
    lines = []
    for ms in prediction.model_scores:
        bar_filled = round(ms.probability * 20)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        lines.append(
            f"- **{ms.model_name}**: {ms.probability:.1%} malware probability "
            f"[{bar}] → **{ms.verdict.upper()}**"
        )
    return "\n".join(lines)


def _format_suspicious_features(prediction: "PredictionResult") -> str:
    if not prediction.suspicious_features:
        if prediction.top_features:
            lines = [
                f"- `{f}` — {describe_feature(f)}"
                for f in prediction.top_features[:15]
            ]
            return "\n".join(lines)
        return "*(no suspicious features flagged)*"

    lines = []
    for sf in prediction.suspicious_features[:15]:
        desc = sf.description or describe_feature(sf.feature_name)
        importance_str = f" (importance: {sf.importance:.4f})" if sf.importance else ""
        lines.append(
            f"- `{sf.feature_name}` = **{sf.value}**{importance_str}  \n"
            f"  → {desc}"
        )
    return "\n".join(lines)


def _format_feature_context(prediction: "PredictionResult") -> str:
    if not prediction.feature_summary:
        return "*(full feature context not provided)*"

    sections = []
    fs = prediction.feature_summary

    # Permissions
    perms = fs.get("permissions", {})
    if perms:
        active_perms = [k for k, v in perms.items() if v == 1 or v is True]
        if active_perms:
            perm_lines = [f"  - `{p}` — {describe_feature(p)}" for p in active_perms[:20]]
            sections.append("**Declared Permissions (active):**\n" + "\n".join(perm_lines))

    # API calls
    apis = fs.get("api_calls", {})
    if apis:
        active_apis = [k for k, v in apis.items() if isinstance(v, (int, float)) and v > 0]
        if active_apis:
            api_lines = [f"  - `{a}` — {describe_feature(a)}" for a in active_apis[:20]]
            sections.append("**Sensitive API Calls (detected):**\n" + "\n".join(api_lines))

    # Manifest stats
    manifest = fs.get("manifest", {})
    if manifest:
        important_keys = [
            "num_dangerous_permissions", "num_services", "num_receivers",
            "num_exported_services", "num_exported_receivers",
            "debuggable", "uses_native_code", "min_sdk_version", "target_sdk_version",
        ]
        mlines = [
            f"  - `{k}` = `{manifest[k]}`"
            for k in important_keys
            if k in manifest
        ]
        if mlines:
            sections.append("**Manifest Statistics:**\n" + "\n".join(mlines))

    # Code structure
    code = fs.get("code_structure", {})
    if code:
        code_keys = [
            "num_classes", "num_methods", "class_name_entropy",
            "method_name_entropy", "uses_reflection", "reflection_count",
        ]
        clines = [
            f"  - `{k}` = `{code[k]}`"
            for k in code_keys
            if k in code
        ]
        if clines:
            sections.append("**Code Structure:**\n" + "\n".join(clines))

    # Certificate
    cert = fs.get("certificate", {})
    if cert:
        cert_keys = ["is_signed", "is_self_signed", "is_expired", "validity_days", "signature_algorithm"]
        certlines = [
            f"  - `{k}` = `{cert[k]}`"
            for k in cert_keys
            if k in cert
        ]
        if certlines:
            sections.append("**Certificate Info:**\n" + "\n".join(certlines))

    return "\n\n".join(sections) if sections else "*(no feature context available)*"


def build_analysis_prompt(prediction: "PredictionResult") -> tuple[str, str]:
    """
    Build the (system_prompt, user_prompt) tuple for the Anthropic Messages API.

    Returns
    -------
    tuple[str, str]
        (system_prompt, user_message_content)
    """
    filename = prediction.apk_filename or prediction.apk_hash or "Unknown APK"
    confidence_str = (
        f"{prediction.confidence:.1%}" if prediction.confidence is not None else "N/A"
    )

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        filename=filename,
        verdict=prediction.verdict.upper(),
        risk_level=prediction.risk_level.value,
        malware_score=prediction.malware_score,
        confidence=confidence_str,
        model_scores_section=_format_model_scores(prediction),
        suspicious_features_section=_format_suspicious_features(prediction),
        feature_context_section=_format_feature_context(prediction),
    )

    return _SYSTEM_PROMPT, user_prompt
