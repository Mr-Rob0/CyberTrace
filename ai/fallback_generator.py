"""
Deterministic Fallback Report Generator Module
==============================================
Generates a structured, evidence-grounded incident report purely through
deterministic aggregation when an LLM provider is unavailable or unconfigured.

Key Principles:
    - 100% Reliable: Zero external dependencies, network calls, or API keys required.
    - Explicit Provenance: Clearly marked as a deterministic, non-LLM generated report.
    - Deterministic & Evidence-Derived: Directly structures verified pipeline outputs without generative AI; acknowledges potential implementation errors or telemetry gaps.
"""

from datetime import datetime
from typing import Dict, Any, List

from ai.schema import IncidentReport
from ai.context_builder import IncidentReportContext


def generate_defensive_recommendations(context: IncidentReportContext) -> List[Dict[str, Any]]:
    """
    Derive deterministic, evidence-grounded mitigation recommendations from detections and mappings.
    """
    recommendations: List[Dict[str, Any]] = []
    seen_actions = set()

    # Analyze triggered rules
    rule_ids = {d.get("rule_id") for d in context.detections}
    technique_ids = {m.get("technique_id") for m in context.mitre_mappings}

    # 1. Credential Compromise / Brute Force
    if "R001" in rule_ids or "T1110.001" in technique_ids:
        action = "Enforce Multi-Factor Authentication (MFA) and account lockout policies on authentication endpoints."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "HIGH",
                "rationale": "Mitigates repeated password guessing and credential compromise attempts observed in telemetry.",
            })

    # 2. Port Reconnaissance
    if "R002" in rule_ids or "T1046" in technique_ids:
        action = "Implement network-layer ingress filtering and drop unauthenticated multi-port sweeps at perimeter firewalls."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "MEDIUM",
                "rationale": "Prevents reconnaissance scans from mapping internal services and active ports.",
            })

    # 3. Suspicious Remote Subnet / Ingress
    if "R003" in rule_ids or "T1078" in technique_ids or "T1078.003" in technique_ids:
        action = "Restrict remote administrative ingress (SSH, RDP) to trusted corporate VPN and bastion hosts."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "HIGH",
                "rationale": "Closes direct perimeter exposure to untrusted external subnets and anomalous IP origins.",
            })

    # 4. Privilege Escalation
    if "R004" in rule_ids or "T1548.003" in technique_ids or "T1548.001" in technique_ids:
        action = "Audit sudoers configuration, revoke unneeded NOPASSWD directives, and review SUID binaries."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "CRITICAL",
                "rationale": "Prevents unauthorized administrative privilege escalation via elevation abuse.",
            })

    # 5. Sensitive File Access
    if "R005" in rule_ids or "T1003.008" in technique_ids or "T1552.004" in technique_ids:
        action = "Harden file system permissions on credentials stores (/etc/shadow, SSH keys) and deploy File Integrity Monitoring (FIM)."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "CRITICAL",
                "rationale": "Prevents credential dumping and unauthorized harvesting of cryptographic identities.",
            })

    # 6. Large Outbound Transfer / Exfiltration
    if "R006" in rule_ids or "T1048" in technique_ids or "T1048.002" in technique_ids:
        action = "Deploy egress filtering, configure network DLP, and block unapproved outbound transfers to external endpoints."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.append({
                "action": action,
                "priority": "HIGH",
                "rationale": "Prevents unauthorized outbound transmission of collected sensitive files.",
            })

    # General baseline recommendation
    if context.incident_overview.get("usernames"):
        users_str = ", ".join(context.incident_overview.get("usernames", []))
        action = f"Immediately revoke active sessions and rotate credentials for affected accounts: {users_str}."
        if action not in seen_actions:
            seen_actions.add(action)
            recommendations.insert(0, {
                "action": action,
                "priority": "CRITICAL",
                "rationale": "Essential containment step to disrupt ongoing session access.",
            })

    if not recommendations:
        recommendations.append({
            "action": "Maintain monitoring of affected hosts and preserve raw logs for retrospective review.",
            "priority": "LOW",
            "rationale": "Baseline defensive readiness in the absence of specific multi-stage attack indicators.",
        })

    return recommendations


def generate_deterministic_fallback(context: IncidentReportContext) -> IncidentReport:
    """
    Produce a complete, schema-compliant, grounded report from context without calling an LLM.
    """
    ov = context.incident_overview
    inc_id = context.incident_id
    severity = ov.get("severity", "UNKNOWN")
    confidence = ov.get("confidence", 0.0)

    # 1. Executive Summary
    det_count = len(context.detections)
    rules_str = ", ".join(dict.fromkeys(d.get("rule_name", "") for d in context.detections if d.get("rule_name")))
    primary_rc = context.root_cause_candidates[0] if context.root_cause_candidates else {}
    rc_title = primary_rc.get("title", "Unknown")
    anom_count = sum(1 for a in context.ml_anomalies if a.get("is_anomaly"))

    exec_summary = (
        f"[DETERMINISTIC FALLBACK REPORT — NON-LLM GENERATED]\n\n"
        f"Incident {inc_id} has been evaluated as {severity} severity with an aggregate pipeline "
        f"confidence of {confidence:.2f}. The incident correlates {det_count} deterministic rule "
        f"detection(s) [{rules_str or 'None'}] spanning {context.raw_event_count} evidence telemetry events. "
        f"Preliminary root-cause analysis identifies '{rc_title}' as the primary probable entry point "
        f"with {primary_rc.get('confidence', 0.0):.2f} confidence. "
        f"Machine learning anomaly detection flagged {anom_count} statistical outlier events. "
        f"This report is compiled strictly from verified deterministic pipeline outputs without LLM interpretation."
    )

    # 2. Impact Assessment
    users = ov.get("usernames", [])
    hosts = ov.get("hostnames", [])
    src_ips = ov.get("source_ips", [])
    dst_ips = ov.get("destination_ips", [])

    impacted_entities = list(dict.fromkeys(users + hosts + dst_ips))
    scope_str = (
        f"Multi-system compromise involving {len(hosts)} host(s) and {len(users)} account(s)"
        if len(hosts) > 1 or len(users) > 1
        else f"Localized activity involving {len(hosts)} host(s) and {len(users)} account(s)"
    )

    impact_assessment = {
        "scope": scope_str,
        "impacted_systems": impacted_entities,
        "narrative": (
            f"Observed activity originated from source IP(s) {', '.join(src_ips) or 'N/A'} "
            f"targeting system(s) {', '.join(hosts) or 'N/A'} and account(s) {', '.join(users) or 'N/A'}. "
            f"Reconstruction indicates {len(context.attack_stages)} progressive attack stage(s)."
        ),
        "uncertainty_statement": (
            "Impact assessment is strictly bounded by provided log telemetry. Unmonitored network segments, "
            "ephemeral memory-only malware, or unlogged outbound connections cannot be completely ruled out."
        ),
    }

    # 3. Defensive Recommendations
    recommendations = generate_defensive_recommendations(context)

    # 4. Limitations and Gaps
    limitations = [
        "Report is synthesized deterministically without generative language model reasoning.",
        "Analysis is bounded strictly by provided synthetic log telemetry files.",
        "Deterministic reporting directly reflects pipeline outputs, eliminating generative LLM hallucinations while remaining subject to potential code implementation errors or telemetry gaps.",
        "Anomaly detection outputs reflect unsupervised statistical divergence, not verified malicious intent.",
        "Root cause candidate is an evidence-backed probabilistic hypothesis rather than absolute ground truth.",
        "Alternative benign hypotheses include authorized administrative troubleshooting, automated maintenance scripts, or sanctioned red-team assessments.",
    ]

    # 5. Evidence References Mapping
    ev_refs = {
        "verified_event_ids": sorted(list(context.valid_event_ids)),
        "unverified_event_ids": [],
        "verified_detection_ids": sorted(list(context.valid_detection_ids)),
        "unverified_detection_ids": [],
        "verified_technique_ids": sorted(list(context.valid_technique_ids)),
    }

    return IncidentReport(
        incident_id=inc_id,
        generation_method="deterministic_fallback",
        generated_at=datetime.now().isoformat(),
        provider_info="Deterministic Fallback (Rule & Evidence Aggregation Engine)",
        executive_summary=exec_summary,
        incident_overview=ov,
        timeline_summary=context.timeline,
        attack_stages=context.attack_stages,
        rule_detections=context.detections,
        mitre_mappings=context.mitre_mappings,
        ml_anomaly_observations=context.ml_anomalies,
        probable_root_cause=primary_rc,
        impact_assessment=impact_assessment,
        defensive_recommendations=recommendations,
        limitations_and_gaps=limitations,
        evidence_references=ev_refs,
        validation_warnings=[],
        is_valid=True,
    )
