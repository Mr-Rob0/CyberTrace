"""
Report Validator Module
=======================
Validates generated incident reports against structured schemas and enforces
strict evidence-grounding constraints before reports can be displayed.

Key Principles:
    - Schema Validation: Ensures all required incident report sections exist.
    - Grounded ID Verification: Verifies that every referenced event_id, detection_id,
      and technique_id exists in the supplied incident context.
    - Hallucination Flagging: Flags unsupported claims and unknown IDs rather than
      silently presenting them as verified facts.
    - Semantic Safety: Verifies that ML anomaly scores are not equated to attack probabilities,
      and that root cause is properly framed as probable.
    - Read-Only Pipeline: Guarantees that reports cannot modify pipeline data or state.
"""

import re
import json
from typing import List, Dict, Any, Tuple, Optional, Set
from utils.logger import get_logger
from ai.context_builder import IncidentReportContext

logger = get_logger("ai.validator")

REQUIRED_SECTIONS = [
    "executive_summary",
    "incident_overview",
    "timeline_summary",
    "attack_stages",
    "rule_detections",
    "mitre_mappings",
    "ml_anomaly_observations",
    "probable_root_cause",
    "impact_assessment",
    "defensive_recommendations",
    "limitations_and_gaps",
]


def extract_json_from_llm_response(text: str) -> Optional[Dict[str, Any]]:
    """
    Safely extract a JSON object from raw LLM response text, handling markdown code fences.
    """
    if not text or not isinstance(text, str):
        return None

    cleaned = text.strip()

    # Case 1: Direct JSON
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

    # Case 2: Code-fenced JSON (```json ... ``` or ``` ...)
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Case 3: Embedded outermost curly braces
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(cleaned[first_brace : last_brace + 1])
        except json.JSONDecodeError:
            pass

    return None


class ReportValidator:
    """
    Validates structured report dictionaries against schema and incident context allowlists.
    """

    @staticmethod
    def validate(
        report_data: Dict[str, Any],
        context: IncidentReportContext,
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate report data against context grounding rules and schema invariants.

        Args:
            report_data: Structured report dictionary (parsed from LLM or fallback).
            context: Verified IncidentReportContext from the CyberTrace pipeline.

        Returns:
            Tuple of:
                - is_valid (bool): True if schema and structural rules pass.
                - warnings (List[str]): List of warning strings or flagged hallucinations.
                - validated_data (Dict[str, Any]): Cleaned report dictionary.
        """
        warnings: List[str] = []
        validated: Dict[str, Any] = report_data.copy()

        # 1. Mandatory Schema Section Check
        for sec in REQUIRED_SECTIONS:
            if sec not in validated or validated[sec] is None:
                warnings.append(f"Missing mandatory section: '{sec}'.")
                # Provide a neutral empty placeholder to avoid UI crash
                if sec in ("timeline_summary", "attack_stages", "rule_detections", "mitre_mappings", "ml_anomaly_observations", "defensive_recommendations", "limitations_and_gaps"):
                    validated[sec] = []
                elif sec in ("incident_overview", "probable_root_cause", "impact_assessment"):
                    validated[sec] = {}
                else:
                    validated[sec] = "Not provided."

        # 2. Executive Summary Grounding Check
        exec_sum = str(validated.get("executive_summary", ""))
        if len(exec_sum.strip()) < 10:
            warnings.append("Executive summary is insufficiently detailed or empty.")

        # 3. Grounded Event ID Verification
        cited_event_ids: Set[str] = set()

        def extract_event_ids(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if "event_id" in k.lower():
                        if isinstance(v, str):
                            cited_event_ids.add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, str):
                                    cited_event_ids.add(item)
                    else:
                        extract_event_ids(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract_event_ids(item)

        extract_event_ids(validated)

        # Check cited event IDs against context
        for eid in cited_event_ids:
            if eid and eid not in context.valid_event_ids:
                warnings.append(f"Flagged unsupported event ID reference: '{eid}' was not observed in incident evidence.")

        # 4. Grounded Detection ID Verification
        cited_detection_ids: Set[str] = set()

        def extract_detection_ids(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if "detection_id" in k.lower():
                        if isinstance(v, str):
                            cited_detection_ids.add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, str):
                                    cited_detection_ids.add(item)
                    else:
                        extract_detection_ids(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract_detection_ids(item)

        extract_detection_ids(validated)

        for did in cited_detection_ids:
            if did and did not in context.valid_detection_ids:
                warnings.append(f"Flagged unsupported detection ID reference: '{did}' was not generated by rule engine.")

        # 5. MITRE ATT&CK Technique Grounding Verification
        mitre_entries = validated.get("mitre_mappings", [])
        if isinstance(mitre_entries, list):
            for m in mitre_entries:
                if isinstance(m, dict):
                    tid = str(m.get("technique_id", ""))
                    if tid and tid not in context.valid_technique_ids:
                        warnings.append(f"Flagged unsupported MITRE technique: '{tid}' was not mapped by the deterministic pipeline.")

        # 6. ML Anomaly Framing Verification
        ml_entries = validated.get("ml_anomaly_observations", [])
        ml_text = json.dumps(ml_entries).lower()
        if "probability of attack" in ml_text or "confirmed attack" in ml_text:
            warnings.append("ML anomaly observations incorrectly framed anomaly scores as attack probabilities.")

        # 7. Probable Root Cause Grounding & Framing Verification
        pipeline_primary_rc = context.root_cause_candidates[0] if context.root_cause_candidates else None
        rc = validated.get("probable_root_cause", {})
        if isinstance(rc, dict):
            rc_title = str(rc.get("title", "")).lower()
            rc_reason = str(rc.get("reasoning", "")).lower()
            if "confirmed root cause" in rc_title or "absolute truth" in rc_reason:
                warnings.append("Root cause was asserted with absolute certainty rather than as a probable hypothesis.")

            # Ensure the LLM cannot alter the pipeline's primary root cause candidate
            if pipeline_primary_rc:
                expected_type = pipeline_primary_rc.get("candidate_type")
                model_type = rc.get("candidate_type")
                if model_type and model_type != expected_type:
                    warnings.append(
                        f"LLM attempted to alter probable root-cause candidate type from '{expected_type}' to '{model_type}'. Overriding with pipeline-established candidate."
                    )
                    validated["probable_root_cause"] = pipeline_primary_rc.copy()
        elif pipeline_primary_rc:
            validated["probable_root_cause"] = pipeline_primary_rc.copy()

        # 8. Deterministic Pipeline Invariant Enforcement (Severity & Confidence Immutability)
        expected_sev = context.incident_overview.get("severity")
        if expected_sev:
            model_sev = validated.get("incident_overview", {}).get("severity")
            if model_sev and str(model_sev).upper() != str(expected_sev).upper():
                warnings.append(
                    f"LLM attempted to alter deterministic pipeline severity from '{expected_sev}' to '{model_sev}'. Overriding with verified pipeline ground truth."
                )
            validated.setdefault("incident_overview", {})["severity"] = expected_sev

        expected_conf = context.incident_overview.get("confidence")
        if expected_conf is not None:
            model_conf = validated.get("incident_overview", {}).get("confidence")
            try:
                if model_conf is not None and abs(float(model_conf) - float(expected_conf)) > 1e-3:
                    warnings.append(
                        f"LLM attempted to alter deterministic pipeline confidence from '{expected_conf}' to '{model_conf}'. Overriding with verified pipeline ground truth."
                    )
            except (ValueError, TypeError):
                pass
            validated.setdefault("incident_overview", {})["confidence"] = expected_conf

        validated.setdefault("incident_overview", {})["incident_id"] = context.incident_id
        validated.setdefault("incident_overview", {})["status"] = context.incident_overview.get("status", "OPEN")
        validated.setdefault("incident_overview", {})["start_time"] = context.incident_overview.get("start_time")
        validated.setdefault("incident_overview", {})["end_time"] = context.incident_overview.get("end_time")

        # 9. Unsupported Factual Claims Verification (IPs, Users, Hosts)
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        cited_ips = set()
        for ip in ip_pattern.findall(json.dumps(validated)):
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.0", "255.255.255.255"):
                cited_ips.add(ip)
        for ip in cited_ips:
            if context.valid_ips and ip not in context.valid_ips:
                warnings.append(f"Flagged unsupported factual IP address claim: '{ip}' was not observed in incident evidence.")

        cited_users = set()
        ov_users = validated.get("incident_overview", {}).get("usernames", [])
        if isinstance(ov_users, list):
            cited_users.update(str(u) for u in ov_users if u)
        for u in cited_users:
            if context.valid_usernames and u not in context.valid_usernames:
                warnings.append(f"Flagged unsupported username claim: '{u}' was not observed in incident evidence.")

        cited_hosts = set()
        ov_hosts = validated.get("incident_overview", {}).get("hostnames", [])
        if isinstance(ov_hosts, list):
            cited_hosts.update(str(h) for h in ov_hosts if h)
        for h in cited_hosts:
            if context.valid_hostnames and h not in context.valid_hostnames:
                warnings.append(f"Flagged unsupported hostname claim: '{h}' was not observed in incident evidence.")

        # 10. Missing Evidence Safeguards
        if not context.attack_stages and validated.get("attack_stages"):
            warnings.append("LLM invented attack stages when telemetry was insufficient to reconstruct an attack chain. Resetting attack stages to unestablished.")
            validated["attack_stages"] = []

        if not context.mitre_mappings and validated.get("mitre_mappings"):
            warnings.append("LLM invented MITRE technique mappings when none were verified by the deterministic pipeline. Resetting mappings.")
            validated["mitre_mappings"] = []

        # 11. Evidence References Aggregation
        validated["evidence_references"] = {
            "verified_event_ids": sorted(list(cited_event_ids.intersection(context.valid_event_ids))),
            "unverified_event_ids": sorted(list(cited_event_ids - context.valid_event_ids)),
            "verified_detection_ids": sorted(list(cited_detection_ids.intersection(context.valid_detection_ids))),
            "unverified_detection_ids": sorted(list(cited_detection_ids - context.valid_detection_ids)),
        }

        # Structure is valid as long as essential dict structure exists
        is_valid = isinstance(validated, dict) and bool(validated.get("executive_summary"))
        return is_valid, warnings, validated
