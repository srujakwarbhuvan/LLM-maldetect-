"""
LLM Explainer — core module of the LLM Reasoning Layer.

Public API
----------
    explain_with_llm(prediction_result: dict | PredictionResult) -> LLMExplanation

    LLMExplainer   — class-based interface for production use (supports
                     connection pooling, retry logic, and config injection)
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional, Union

import anthropic
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from apk_extractor.llm.prompt_builder import build_analysis_prompt
from apk_extractor.llm.response_parser import parse_llm_response
from apk_extractor.llm.schemas import LLMExplanation, PredictionResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_TEMPERATURE = 1.0          # Required for extended thinking
DEFAULT_THINKING_BUDGET = 8000     # Thinking tokens budget (0 = disabled)
MAX_RETRIES = 3
RETRY_MIN_WAIT = 2                 # seconds
RETRY_MAX_WAIT = 30                # seconds


# ---------------------------------------------------------------------------
# LLMExplainer class
# ---------------------------------------------------------------------------


class LLMExplainer:
    """
    Production-grade LLM explainer for Android malware predictions.

    Wraps the Anthropic client with:
      - Configurable extended thinking support
      - Automatic retry with exponential back-off
      - Structured response parsing
      - Token usage tracking
      - Graceful error handling

    Usage
    -----
    >>> explainer = LLMExplainer(api_key="sk-ant-...")
    >>> explanation = explainer.explain(prediction_result)
    >>> print(explanation.raw_explanation)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        thinking_budget_tokens: int = DEFAULT_THINKING_BUDGET,
        enable_thinking: bool = True,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout: float = 120.0,
    ) -> None:
        """
        Initialise the LLM explainer.

        Parameters
        ----------
        api_key:
            Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        model:
            Anthropic model identifier.
        max_tokens:
            Maximum tokens for the response (includes thinking tokens).
        thinking_budget_tokens:
            Token budget for extended thinking (0 to disable).
        enable_thinking:
            Whether to enable extended thinking mode.
        temperature:
            Sampling temperature. Must be 1.0 when thinking is enabled.
        timeout:
            HTTP request timeout in seconds.
        """
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError(
                "Anthropic API key is required. Set ANTHROPIC_API_KEY environment "
                "variable or pass api_key= to LLMExplainer()."
            )

        self.client = anthropic.Anthropic(api_key=resolved_key, timeout=timeout)
        self.model = model
        self.max_tokens = max_tokens
        self.thinking_budget_tokens = thinking_budget_tokens
        self.enable_thinking = enable_thinking
        self.temperature = temperature

        logger.info(
            f"LLMExplainer initialised | model={self.model} | "
            f"thinking={'enabled' if enable_thinking else 'disabled'} | "
            f"max_tokens={max_tokens}"
        )

    @retry(
        retry=retry_if_exception_type((anthropic.RateLimitError, anthropic.APIConnectionError)),
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(min=RETRY_MIN_WAIT, max=RETRY_MAX_WAIT),
        reraise=True,
    )
    def _call_api(self, system_prompt: str, user_prompt: str) -> anthropic.types.Message:
        """Make the Anthropic API call with retry logic."""
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        if self.enable_thinking and self.thinking_budget_tokens > 0:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": self.thinking_budget_tokens,
            }
            kwargs["temperature"] = 1.0  # Required for thinking
        else:
            kwargs["temperature"] = self.temperature

        logger.debug(f"Calling Anthropic API | model={self.model}")
        start = time.monotonic()
        response = self.client.messages.create(**kwargs)
        elapsed = time.monotonic() - start
        logger.debug(f"API call completed in {elapsed:.2f}s")
        return response

    def _extract_text_from_response(self, response: anthropic.types.Message) -> str:
        """Extract the text content block(s) from an Anthropic response."""
        text_parts = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            # thinking blocks are silently skipped (internal reasoning)
        return "\n\n".join(text_parts)

    def explain(self, prediction: Union[PredictionResult, Dict[str, Any]]) -> LLMExplanation:
        """
        Generate an LLM-powered explanation for a malware prediction.

        Parameters
        ----------
        prediction:
            Either a PredictionResult instance or a raw dict from predict.py.

        Returns
        -------
        LLMExplanation
            Structured explanation with family classification, behaviours,
            recommendations, and technical indicators.

        Raises
        ------
        anthropic.APIError
            If the API call fails after all retries.
        pydantic.ValidationError
            If the input dict cannot be parsed as a PredictionResult.
        """
        # Normalise input
        if isinstance(prediction, dict):
            prediction = PredictionResult(**prediction)

        logger.info(
            f"Generating LLM explanation | apk={prediction.apk_filename or prediction.apk_hash} "
            f"| score={prediction.malware_score:.1f} | verdict={prediction.verdict}"
        )

        # Build prompts
        system_prompt, user_prompt = build_analysis_prompt(prediction)
        logger.debug(f"Prompt length: {len(user_prompt)} chars")

        # Call API
        try:
            response = self._call_api(system_prompt, user_prompt)
        except anthropic.RateLimitError as e:
            logger.error(f"Rate limit exceeded after {MAX_RETRIES} retries: {e}")
            raise
        except anthropic.APIConnectionError as e:
            logger.error(f"API connection error after {MAX_RETRIES} retries: {e}")
            raise
        except anthropic.APIStatusError as e:
            logger.error(f"API status error {e.status_code}: {e.message}")
            raise

        # Extract raw text
        raw_text = self._extract_text_from_response(response)
        if not raw_text.strip():
            logger.warning("LLM returned empty response — returning minimal explanation")
            raw_text = (
                f"Analysis unavailable. ML pipeline verdict: {prediction.verdict.upper()} "
                f"with a malware score of {prediction.malware_score:.1f}/100."
            )

        # Parse token usage
        usage = response.usage
        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)
        # cache_read / thinking tokens may appear in future SDK versions
        reasoning_tokens = getattr(usage, "cache_read_input_tokens", None)

        logger.info(
            f"LLM explanation generated | "
            f"input_tokens={input_tokens} output_tokens={output_tokens}"
        )

        # Parse and return structured output
        return parse_llm_response(
            raw_text=raw_text,
            model_used=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
        )


# ---------------------------------------------------------------------------
# Module-level convenience function  (the primary public API)
# ---------------------------------------------------------------------------


def explain_with_llm(
    prediction_result: Union[Dict[str, Any], PredictionResult],
    *,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    enable_thinking: bool = True,
    thinking_budget_tokens: int = DEFAULT_THINKING_BUDGET,
    return_raw: bool = False,
) -> Union[LLMExplanation, str]:
    """
    Generate a contextual LLM explanation for a malware prediction result.

    This is the primary entry point for the LLM Reasoning Layer. It accepts
    the JSON output from predict.py and returns a structured explanation
    containing the suspected malware family, likely behaviours, technical
    indicators, and actionable user recommendations.

    Parameters
    ----------
    prediction_result:
        The JSON output from predict.py as a dict, or a PredictionResult
        instance. Required fields: ``verdict``, ``risk_level``,
        ``malware_score``.

    api_key:
        Anthropic API key. Falls back to the ``ANTHROPIC_API_KEY``
        environment variable if not provided.

    model:
        Anthropic model to use. Defaults to ``claude-sonnet-4-20250514``.

    max_tokens:
        Maximum number of tokens in the model response.

    enable_thinking:
        Enable extended thinking mode (recommended for better analysis).
        When enabled, temperature is forced to 1.0 per API requirements.

    thinking_budget_tokens:
        Token budget allocated to extended thinking (default 8 000).
        Set to 0 to disable thinking even when ``enable_thinking=True``.

    return_raw:
        If True, return the raw explanation string instead of the full
        LLMExplanation object. Useful for quick integrations.

    Returns
    -------
    LLMExplanation
        Structured explanation object (default).
    str
        Raw explanation text when ``return_raw=True``.

    Examples
    --------
    >>> from apk_extractor.llm import explain_with_llm
    >>>
    >>> result = {
    ...     "verdict": "malware",
    ...     "risk_level": "HIGH",
    ...     "malware_score": 87.3,
    ...     "apk_filename": "suspicious.apk",
    ...     "suspicious_features": [
    ...         {"feature_name": "perm_SEND_SMS", "value": 1},
    ...         {"feature_name": "api_sendTextMessage", "value": 1},
    ...     ],
    ... }
    >>>
    >>> explanation = explain_with_llm(result)
    >>> print(explanation.suspected_malware_family)
    MalwareFamily.SMS_STEALER
    >>> print(explanation.raw_explanation)
    'This application exhibits strong indicators of SMS-based malware...'
    """
    explainer = LLMExplainer(
        api_key=api_key,
        model=model,
        max_tokens=max_tokens,
        enable_thinking=enable_thinking,
        thinking_budget_tokens=thinking_budget_tokens,
    )
    result = explainer.explain(prediction_result)

    if return_raw:
        return result.raw_explanation
    return result
