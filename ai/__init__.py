"""
AI Module
=========
Contains LLM-based functionality and deterministic report generators,
ISOLATED from the core analysis pipeline.

Key Design Principle:
    The deterministic pipeline produces structured findings first.
    The AI report generator strictly grounds its reporting in those verified findings.
    It must NEVER invent evidence, events, IPs, timestamps, techniques, or conclusions.

Public Exports:
    - generate_report: Generates natural-language investigation reports
    - IncidentReport: Strongly-typed structured report data model
    - IncidentReportContext: Grounded incident context
    - LLMProvider: Abstract provider interface
    - OpenAICompatibleProvider: HTTP provider for OpenAI-compatible APIs
    - MockLLMProvider: Safe test provider with zero network calls
    - get_configured_provider: Factory to discover active credentials
"""

from ai.schema import IncidentReport
from ai.context_builder import IncidentReportContext, IncidentContextBuilder
from ai.provider import (
    LLMProvider,
    OpenAICompatibleProvider,
    MockLLMProvider,
    get_configured_provider,
    ProviderError,
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderNetworkError,
)
from ai.fallback_generator import generate_deterministic_fallback
from ai.report_generator import generate_report

__all__ = [
    "generate_report",
    "IncidentReport",
    "IncidentReportContext",
    "IncidentContextBuilder",
    "LLMProvider",
    "OpenAICompatibleProvider",
    "MockLLMProvider",
    "get_configured_provider",
    "generate_deterministic_fallback",
    "ProviderError",
    "ProviderAuthError",
    "ProviderRateLimitError",
    "ProviderTimeoutError",
    "ProviderNetworkError",
]
