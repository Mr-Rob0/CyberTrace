"""Explainable, deterministic incident risk scoring.

The score is for response prioritisation, never a probability that an incident
is malicious. Each contribution is returned so an analyst can audit it.
"""

from typing import Any, Iterable

_SEVERITY_POINTS = {"LOW": 12, "MEDIUM": 28, "HIGH": 48, "CRITICAL": 65}
_HIGH_IMPACT_STAGES = {"PRIVILEGE_ESCALATION", "COLLECTION", "EXFILTRATION", "LATERAL_MOVEMENT"}


def _value(source: Any, name: str, default: Any = None) -> Any:
    return source.get(name, default) if isinstance(source, dict) else getattr(source, name, default)


def _stages(incident: Any) -> list[str]:
    chain = _value(incident, "attack_chain", _value(incident, "chain", {})) or {}
    raw_steps: Iterable[Any] = _value(chain, "steps", []) if not isinstance(chain, list) else chain
    return [str(_value(step, "stage", "")).upper() for step in raw_steps if _value(step, "stage")]


def calculate_risk_score(incident: dict) -> dict:
    """Return a 0–100 response-priority score and evidence confidence score.

    Accepts dictionaries or Incident-like objects. Missing data reduces the
    confidence rather than causing a misleading failure.
    """
    if not incident:
        raise ValueError("incident is required")
    severity = str(_value(incident, "severity", "LOW")).upper()
    severity_points = _SEVERITY_POINTS.get(severity, _SEVERITY_POINTS["LOW"])
    detection_count = max(0, int(_value(incident, "detection_count", 0) or 0))
    event_ids = _value(incident, "event_ids", []) or []
    stages = _stages(incident)
    entities = set()
    for field in ("source_ips", "destination_ips", "usernames", "hostnames"):
        entities.update(str(item) for item in (_value(incident, field, []) or []) if item)
    detection_points = min(12, detection_count * 2)
    progression_points = min(14, len(set(stages)) * 3)
    impact_points = 9 if any(stage in _HIGH_IMPACT_STAGES for stage in stages) else 0
    scope_points = min(8, max(0, len(entities) - 1) * 2)
    overall_score = min(100, severity_points + detection_points + progression_points + impact_points + scope_points)
    stated_confidence = float(_value(incident, "confidence", 0.0) or 0.0)
    evidence_bonus = min(0.12, len(event_ids) * 0.01) + min(0.08, len(set(stages)) * 0.02)
    confidence = max(0.0, min(0.95, stated_confidence * 0.8 + evidence_bonus))
    return {
        "overall_score": int(overall_score),
        "risk_level": "CRITICAL" if overall_score >= 80 else "HIGH" if overall_score >= 55 else "MEDIUM" if overall_score >= 30 else "LOW",
        "confidence": round(confidence, 2),
        "factors": {
            "severity": {"points": severity_points, "value": severity},
            "detection_volume": {"points": detection_points, "count": detection_count},
            "attack_progression": {"points": progression_points, "stages": stages},
            "potential_impact": {"points": impact_points, "high_impact_stage_present": bool(impact_points)},
            "entity_scope": {"points": scope_points, "unique_entities": len(entities)},
        },
        "disclaimer": "Risk score prioritizes investigation and response; it is not a probability of compromise.",
    }
