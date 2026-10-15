"""Evidence-led incident containment and prevention recommendations."""

from typing import Any, Dict, List


def _value(source: Any, name: str, default: Any = None) -> Any:
    return source.get(name, default) if isinstance(source, dict) else getattr(source, name, default)


def _stages(incident: Any) -> set[str]:
    chain = _value(incident, "attack_chain", _value(incident, "chain", {})) or {}
    steps = _value(chain, "steps", []) if not isinstance(chain, list) else chain
    return {str(_value(step, "stage", "")).upper() for step in steps}


def recommend_actions(incident: dict) -> list:
    """Produce concise, deduplicated response actions from observed findings."""
    if not incident:
        raise ValueError("incident is required")
    stages = _stages(incident)
    root_cause = _value(incident, "root_cause", {}) or {}
    cause_type = str(_value(root_cause, "candidate_type", _value(incident, "root_cause_type", ""))).upper()
    actions: List[Dict[str, str]] = []

    def add(action: str, priority: str, rationale: str, category: str) -> None:
        if not any(item["action"] == action for item in actions):
            actions.append({"action": action, "priority": priority, "rationale": rationale, "category": category})

    add("Preserve relevant logs and isolate affected hosts from untrusted networks.", "CRITICAL", "Preserves evidence while limiting additional activity during the investigation.", "containment")
    if "CREDENTIAL_ACCESS" in stages or cause_type == "CREDENTIAL_COMPROMISE":
        add("Reset affected credentials, revoke active sessions, and require MFA for privileged access.", "CRITICAL", "Authentication abuse or a credential-compromise hypothesis is present in the evidence.", "identity")
        add("Review authentication-rate limits and alerting for repeated failures.", "HIGH", "Helps detect and slow repeated password-guessing attempts.", "identity")
    if "INITIAL_ACCESS" in stages or cause_type == "SUSPICIOUS_REMOTE_ACCESS":
        add("Restrict remote administration to approved networks and review ingress allow-lists.", "HIGH", "The chain includes or suggests untrusted remote access.", "network")
    if "PRIVILEGE_ESCALATION" in stages or cause_type == "PRIVILEGE_ABUSE":
        add("Audit privileged-group membership, sudo rules, and recent administrative changes.", "CRITICAL", "Elevated execution can expand incident impact rapidly.", "privilege")
    if "COLLECTION" in stages or "EXFILTRATION" in stages:
        add("Block suspicious egress paths and review outbound transfer destinations and volumes.", "CRITICAL", "Collection or outbound-transfer activity may indicate data exposure.", "data protection")
        add("Rotate secrets accessible to affected accounts and hosts.", "HIGH", "Sensitive data or credentials may have been accessible after compromise.", "data protection")
    if "LATERAL_MOVEMENT" in stages:
        add("Segment affected systems and inspect peer authentication for lateral movement.", "HIGH", "Cross-host progression requires scoped containment and validation.", "network")
    add("Document the response decision and validate remediation with a follow-up log review.", "MEDIUM", "Maintains an auditable response trail and checks for recurrence.", "verification")
    return actions
