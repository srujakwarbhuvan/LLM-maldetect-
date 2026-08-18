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

from google import genai
from google.genai import types
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
from google.genai.errors import APIError, ServerError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "gemini-flash-latest"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_TEMPERATURE = 0.7          
DEFAULT_THINKING_BUDGET = 8000     
MAX_RETRIES = 3
RETRY_MIN_WAIT = 2                 # seconds
RETRY_MAX_WAIT = 30                # seconds


# ---------------------------------------------------------------------------
# LLMExplainer class
# ---------------------------------------------------------------------------


class LLMExplainer:
    """
    Production-grade LLM explainer for Android malware predictions.

    Wraps the Gemini API client with:
      - Automatic retry with exponential back-off
      - Structured response parsing
      - Token usage tracking
      - Graceful error handling

    Usage
    -----
    >>> explainer = LLMExplainer(api_key="AIza...")
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
            Gemini API key. Falls back to GEMINI_API_KEY env var.
        model:
            Gemini model identifier.
        max_tokens:
            Maximum tokens for the response.
        """
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "Gemini API key is required. Set GEMINI_API_KEY environment "
                "variable or pass api_key= to LLMExplainer()."
            )

        self.client = genai.Client(api_key=resolved_key)
        
        self.model_name = model
        self.max_tokens = max_tokens
        self.temperature = temperature

        logger.info(
            f"LLMExplainer initialised | model={self.model_name} | "
            f"max_tokens={max_tokens}"
        )

    @retry(
        retry=retry_if_exception_type((APIError, ServerError)),
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(min=RETRY_MIN_WAIT, max=RETRY_MAX_WAIT),
        reraise=True,
    )
    def _call_api(self, system_prompt: str, user_prompt: str) -> Any:
        """Make the Gemini API call with retry logic."""
        
        logger.debug(f"Calling Gemini API | model={self.model_name}")
        start = time.monotonic()
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
            )
        )
        elapsed = time.monotonic() - start
        logger.debug(f"API call completed in {elapsed:.2f}s")
        return response

    def _extract_text_from_response(self, response: Any) -> str:
        """Extract the text content block(s) from a Gemini response."""
        try:
            return response.text
        except ValueError:
            logger.warning(f"Response blocked or empty")
            return ""

    def explain(self, prediction: Union[PredictionResult, Dict[str, Any]]) -> LLMExplanation:
        """
        Generate an LLM-powered explanation for a malware prediction.
        """
        if isinstance(prediction, dict):
            prediction = PredictionResult(**prediction)

        logger.info(
            f"Generating LLM explanation | apk={prediction.apk_filename or prediction.apk_hash} "
            f"| score={prediction.malware_score:.1f} | verdict={prediction.verdict}"
        )

        system_prompt, user_prompt = build_analysis_prompt(prediction)
        logger.debug(f"Prompt length: {len(user_prompt)} chars")

        try:
            response = self._call_api(system_prompt, user_prompt)
        except APIError as e:
            logger.error(f"Google API Error after {MAX_RETRIES} retries: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling Gemini API: {e}")
            raise

        raw_text = self._extract_text_from_response(response)
        if not raw_text.strip():
            logger.warning("LLM returned empty response — returning minimal explanation")
            raw_text = (
                f"Analysis unavailable. ML pipeline verdict: {prediction.verdict.upper()} "
                f"with a malware score of {prediction.malware_score:.1f}/100."
            )

        input_tokens = None
        output_tokens = None
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            input_tokens = getattr(response.usage_metadata, "prompt_token_count", None)
            output_tokens = getattr(response.usage_metadata, "candidates_token_count", None)

        logger.info(
            f"LLM explanation generated | "
            f"input_tokens={input_tokens} output_tokens={output_tokens}"
        )

        return parse_llm_response(
            raw_text=raw_text,
            model_used=self.model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=None,
        )


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
