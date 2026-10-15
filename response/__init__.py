"""
Response Module
===============
Provides risk scoring, prevention recommendations, and what-if analysis.

Sub-modules:
    - risk_scoring: Calculates understandable risk/confidence scores
    - prevention: Recommends defensive actions
    - what_if: Simulates where an attack could have been stopped
"""
"""Response-prioritisation, recommendations, and defensive simulations."""

from response.risk_scoring import calculate_risk_score
from response.prevention import recommend_actions
from response.what_if import run_what_if_analysis

__all__ = ["calculate_risk_score", "recommend_actions", "run_what_if_analysis"]
