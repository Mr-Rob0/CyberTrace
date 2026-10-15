"""
LLM Provider Abstraction Module
================================
Provides a provider-agnostic interface for executing structured prompts against
large language model APIs, with strict security and reliability invariants.

Key Principles:
    - Provider Agnostic: Interfaces through a common abstract base class.
    - Zero Credential Exposure: API keys are read from environment variables and
      NEVER hardcoded, printed, logged, or exposed in exceptions.
    - Resilient Error Handling: Distinguishes between authentication errors,
      rate limits, network timeouts, and malformed outputs.
    - Zero Test-Time Network Calls: Provides a deterministic mock provider for testing.
"""

from abc import ABC, abstractmethod
import os
import json
import logging
from typing import Optional, Dict, Any, Union

import requests
from utils.config import get_config
from utils.logger import get_logger

logger = get_logger("ai.provider")


class ProviderError(Exception):
    """Base exception for LLM provider errors."""
    pass


class ProviderAuthError(ProviderError):
    """Raised when authentication fails (HTTP 401/403) or API key is invalid."""
    pass


class ProviderRateLimitError(ProviderError):
    """Raised when API rate limit or quota is exceeded (HTTP 429)."""
    pass


class ProviderTimeoutError(ProviderError):
    """Raised when request times out."""
    pass


class ProviderNetworkError(ProviderError):
    """Raised when network connection fails."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when provider endpoint is down or unreachable (HTTP 5xx)."""
    pass


class LLMProvider(ABC):
    """
    Abstract interface for LLM providers.
    """

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str) -> str:
        """
        Generate text output from the provider given a prompt and system instruction.

        Args:
            prompt: User-level input text containing sanitized incident context.
            system_prompt: System-level instruction defining output format and constraints.

        Returns:
            Raw response text from the model.

        Raises:
            ProviderError: On any failure.
        """
        raise NotImplementedError


class OpenAICompatibleProvider(LLMProvider):
    """
    Provider for OpenAI-compatible HTTP endpoints (OpenAI, Azure, Ollama, Groq, vLLM).
    Uses standard requests with timeout, retries, and credential masking.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: int = 30,
    ):
        self._api_key = api_key or get_config("OPENAI_API_KEY", "")
        self.base_url = (base_url or get_config("OPENAI_API_BASE", "https://api.openai.com/v1")).rstrip("/")
        self.model = model or get_config("OPENAI_MODEL", "gpt-4o-mini")
        self.timeout_seconds = timeout_seconds

        if not self._api_key:
            raise ProviderAuthError("OpenAI API key is missing or empty.")

    def __repr__(self) -> str:
        return f"OpenAICompatibleProvider(model='{self.model}', base_url='{self.base_url}')"

    def generate(self, prompt: str, system_prompt: str) -> str:
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=self.timeout_seconds,
            )
        except requests.exceptions.Timeout as exc:
            logger.warning(f"LLM request timed out after {self.timeout_seconds}s.")
            raise ProviderTimeoutError(f"Request timed out after {self.timeout_seconds}s.") from exc
        except requests.exceptions.ConnectionError as exc:
            logger.warning("LLM provider connection failed.")
            raise ProviderNetworkError("Failed to connect to LLM provider endpoint.") from exc
        except requests.exceptions.RequestException as exc:
            logger.warning("LLM request failed with network error.")
            raise ProviderNetworkError("Unexpected network error while contacting provider.") from exc

        if response.status_code in (401, 403):
            logger.error("LLM Provider authentication rejected (HTTP %d).", response.status_code)
            raise ProviderAuthError("Authentication rejected by LLM provider. Please check credentials.")

        if response.status_code == 429:
            logger.warning("LLM Provider rate limit exceeded (HTTP 429).")
            raise ProviderRateLimitError("LLM Provider rate limit exceeded. Please retry later.")

        if response.status_code >= 500:
            logger.error("LLM Provider service error (HTTP %d).", response.status_code)
            raise ProviderUnavailableError(f"LLM Provider service unavailable (HTTP {response.status_code}).")

        if not response.ok:
            logger.error("LLM Provider returned error HTTP %d.", response.status_code)
            raise ProviderError(f"LLM Provider returned HTTP {response.status_code}.")

        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return content
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            logger.error("Malformed JSON payload received from LLM provider.")
            raise ProviderError("Malformed JSON structure in LLM response.") from exc


class MockLLMProvider(LLMProvider):
    """
    Configurable mock provider for automated testing.
    Never initiates external network calls.
    """

    def __init__(
        self,
        canned_response: Optional[str] = None,
        simulate_error: Optional[Exception] = None,
        record_prompts: bool = True,
    ):
        self.canned_response = canned_response or ""
        self.simulate_error = simulate_error
        self.recorded_calls = []
        self.record_prompts = record_prompts

    def generate(self, prompt: str, system_prompt: str) -> str:
        if self.record_prompts:
            self.recorded_calls.append({"prompt": prompt, "system_prompt": system_prompt})

        if self.simulate_error:
            raise self.simulate_error

        return self.canned_response


def get_configured_provider() -> Optional[LLMProvider]:
    """
    Factory function to instantiate the active LLM provider from environment variables.

    Returns:
        LLMProvider instance if valid credentials exist, or None if unconfigured.
    """
    api_key = get_config("OPENAI_API_KEY", "").strip()

    # Reject empty or standard template placeholder keys
    if not api_key or api_key.startswith("your_") or "placeholder" in api_key.lower():
        return None

    try:
        return OpenAICompatibleProvider(api_key=api_key)
    except Exception as exc:
        logger.warning("Could not initialize configured LLM provider: %s", str(exc))
        return None
