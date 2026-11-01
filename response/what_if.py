"""Deterministic defensive counterfactual analysis for reconstructed chains."""

from typing import Any

_DEFENSE_COVERAGE = {
    "MFA": {"CREDENTIAL_ACCESS", "INITIAL_ACCESS"},
    "RATE_LIMITING": {"CREDENTIAL_ACCESS", "DISCOVERY"},
    "NETWORK_SEGMENTATION": {"LATERAL_MOVEMENT", "EXFILTRATION", "DISCOVERY"},
    "EGRESS_FILTERING": {"EXFILTRATION"},
    "PRIVILEGED_ACCESS_MANAGEMENT": {"PRIVILEGE_ESCALATION"},
    "ENDPOINT_DETECTION": {"EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION", "COLLECTION"},
    "DATA_LOSS_PREVENTION": {"COLLECTION", "EXFILTRATION"},
    "FIREWALL_FILTERING": {"DISCOVERY", "INITIAL_ACCESS", "EXFILTRATION"},
}


def _value(source: Any, name: str, default: Any = None) -> Any:
    return source.get(name, default) if isinstance(source, dict) else getattr(source, name, default)


def run_what_if_analysis(attack_chain: dict, defenses: list) -> dict:
    """Estimate the earliest observed step selected controls could disrupt."""
    if attack_chain is None:
        raise ValueError("attack_chain is required")
    steps = _value(attack_chain, "steps", []) if not isinstance(attack_chain, list) else attack_chain
    normalized = {str(_value(item, "id", item)).upper().replace(" ", "_") for item in (defenses or [])}
    covered = set().union(*(_DEFENSE_COVERAGE.get(item, set()) for item in normalized)) if normalized else set()
    indexed = [(index, step, str(_value(step, "stage", "")).upper()) for index, step in enumerate(steps)]
    match = next(((index, step, stage) for index, step, stage in indexed if stage in covered), None)
    if not match:
        unmitigated_all = [_value(item, "step_id", f"STEP-{pos + 1:04d}") for pos, item, _ in indexed]
        return {
            "blocked_at": None,
            "prevented_steps": [],
            "unmitigated_steps": unmitigated_all,
            "effectiveness": 0,
            "selected_defenses": sorted(normalized),
            "explanation": "No selected defense maps to an observed attack stage in this chain.",
        }
    index, step, stage = match
    prevented = [_value(item, "step_id", f"STEP-{position + 1:04d}") for position, item, _ in indexed[index:]]
    unmitigated = [_value(item, "step_id", f"STEP-{position + 1:04d}") for position, item, _ in indexed[:index]]
    return {
        "blocked_at": {"step_id": _value(step, "step_id", f"STEP-{index + 1:04d}"), "stage": stage, "title": _value(step, "title", stage)},
        "prevented_steps": prevented,
        "unmitigated_steps": unmitigated,
        "effectiveness": round((len(prevented) / max(1, len(steps))) * 100),
        "selected_defenses": sorted(normalized),
        "explanation": "Selected controls align with the earliest matching observed stage; later stages are modeled as potentially avoided.",
    }
