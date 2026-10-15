"""
Verification Script for Phase 10: End-to-End Workflow Audit
============================================================
Runs the complete CyberTrace workflow on:
  1. combined_attack.csv (Multi-stage attack demonstration)
  2. normal_activity.csv (Benign baseline comparison)

Validates all 11 workflow steps and core safety invariants, including the
response-prioritisation and defensive-counterfactual layer.
"""

import os
import sys
import json
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.root_cause import RootCauseAnalyzer
from mitre.technique_mapper import map_to_mitre
from detection.anomaly_detector import detect_anomalies
from ai.report_generator import generate_report
from ai.schema import IncidentReport
from response import calculate_risk_score, recommend_actions, run_what_if_analysis

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))


def run_full_workflow(dataset_name: str):
    filepath = os.path.join(DATA_DIR, dataset_name)
    print(f"\n=======================================================")
    print(f"RUNNING COMPLETE WORKFLOW ON: {dataset_name}")
    print(f"=======================================================")

    # Step 1 & 2: Parse and Normalize
    parse_result = parse_log_file(filepath)
    events = parse_result.events
    print(f"[Step 1 & 2] Parsed & Normalized Events: {len(events)} (Failed rows: {parse_result.failed_rows})")

    # Step 3: Deterministic Rule Detection R001-R006
    rule_engine = RuleEngine()
    detections = rule_engine.detect(events)
    rule_counts = {}
    for d in detections:
        rule_counts[d.rule_id] = rule_counts.get(d.rule_id, 0) + 1
    print(f"[Step 3] Deterministic Detections: {len(detections)} {rule_counts}")

    # Step 4: Correlation & Incident Detection
    correlator = EventCorrelator()
    groups = correlator.correlate(detections)
    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)
    print(f"[Step 4] Correlated Groups: {len(groups)} | Formal Incidents: {len(incidents)}")

    # Main Incident Selection
    if incidents:
        main_inc = max(incidents, key=lambda i: i.detection_count)
        print(f"         Selected Main Incident: {main_inc.incident_id} (Severity: {main_inc.severity}, Confidence: {main_inc.confidence:.2f}, Events: {len(main_inc.event_ids)})")
    else:
        main_inc = {
            "incident_id": "INC-NONE",
            "severity": "LOW",
            "confidence": 0.0,
            "status": "CLOSED",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "event_ids": [],
            "detection_ids": [],
            "source_ips": [],
            "destination_ips": [],
            "usernames": [],
            "hostnames": [],
        }
        print(f"         Zero incidents detected. (Synthetic baseline normal activity verified clean).")

    # Step 5: Attack Chain Reconstruction & Probable Root Cause
    reconstructor = AttackChainReconstructor()
    if incidents:
        chain = reconstructor.reconstruct(main_inc, events=events, detections=detections)
        stages = [f"{s.step_id}:{s.stage}" for s in chain.steps]
    else:
        chain = reconstructor.reconstruct(None)
        stages = []
    print(f"[Step 5] Reconstructed Attack Stages ({len(stages)}): {stages}")

    rc_analyzer = RootCauseAnalyzer()
    root_causes = rc_analyzer.analyze(chain)
    primary_rc = root_causes[0]
    print(f"         Primary Probable Root Cause: {primary_rc.title} (Type: {primary_rc.candidate_type}, Confidence: {primary_rc.confidence:.2f})")

    # Step 6: MITRE ATT&CK Mapping
    mappings = map_to_mitre(chain, events=events, detections=detections)
    technique_list = [f"{m.technique_id} ({m.technique_name})" for m in mappings]
    print(f"[Step 6] MITRE ATT&CK Mappings ({len(mappings)}): {technique_list}")

    # Step 7: ML Anomaly Detection (Isolation Forest)
    anomalies = detect_anomalies(events)
    flagged_anoms = [a for a in anomalies if a.is_anomaly]
    print(f"[Step 7] ML Anomalies Flagged: {len(flagged_anoms)} of {len(anomalies)} events ({len(flagged_anoms)/len(anomalies):.1%})")

    # Step 8: Response planning (risk priority, safeguards, and counterfactual)
    response_context = main_inc.to_dict() if incidents else main_inc.copy()
    response_context.update({
        "attack_chain": chain,
        "root_cause": primary_rc.to_dict(),
    })
    risk = calculate_risk_score(response_context)
    recommendations = recommend_actions(response_context)
    simulation = run_what_if_analysis(chain, ["MFA", "Privileged Access Management", "Egress Filtering"])
    print(f"[Step 8] Response Priority: {risk['overall_score']}/100 ({risk['risk_level']}); Recommended Actions: {len(recommendations)}")
    if incidents:
        assert risk["overall_score"] > 0, "Detected incidents must receive a response-priority score"
        assert recommendations, "Detected incidents must receive defensive recommendations"
    assert "effectiveness" in simulation, "Counterfactual analysis must return effectiveness"

    # Step 9: Evidence-Grounded Report Generation (Deterministic Fallback Mode)
    report = generate_report(
        incident_or_findings=main_inc,
        events=events,
        detections=detections,
        attack_chain=chain,
        root_causes=root_causes,
        mitre_mappings=mappings,
        anomaly_results=anomalies,
        force_fallback=True,
    )
    print(f"[Step 9] Report Generated: Method='{report.generation_method}', Valid={report.is_valid}")
    print(f"         Executive Summary Snippet: {report.executive_summary[:120]}...")

    # Step 10: Evidence References & Grounding Traceability
    ev_refs = report.evidence_references
    print(f"[Step 10] Evidence Traceability: Verified Event IDs={len(ev_refs.get('verified_event_ids', []))}, Unverified Event IDs={len(ev_refs.get('unverified_event_ids', []))}")
    assert len(ev_refs.get("unverified_event_ids", [])) == 0, "Unverified event IDs detected in report!"

    # Step 11: Export Validation (Markdown & JSON)
    md_content = report.to_markdown()
    json_content = report.to_json()
    assert "# Incident Investigation Report" in md_content
    assert "## 1. Executive Summary" in md_content
    assert "## 10. Recommended Defensive Actions" in md_content
    parsed_json = json.loads(json_content)
    assert parsed_json["incident_id"] == report.incident_id
    assert "executive_summary" in parsed_json
    print(f"[Step 11] Export Validation: Markdown length={len(md_content)} chars, JSON length={len(json_content)} chars. BOTH VALID.")

    return {
        "dataset": dataset_name,
        "events_count": len(events),
        "detections_count": len(detections),
        "incidents_count": len(incidents),
        "stages_count": len(stages),
        "primary_root_cause": primary_rc.candidate_type,
        "mitre_count": len(mappings),
        "anomalies_count": len(flagged_anoms),
        "generation_method": report.generation_method,
        "md_length": len(md_content),
        "json_length": len(json_content),
        "report": report,
    }


if __name__ == "__main__":
    res_combined = run_full_workflow("combined_attack.csv")
    res_normal = run_full_workflow("normal_activity.csv")

    print("\n=======================================================")
    print("COMPARATIVE INVARIANT VERIFICATION SUMMARY")
    print("=======================================================")
    print(f"1. combined_attack.csv: Detections={res_combined['detections_count']}, Incidents={res_combined['incidents_count']}, RootCause={res_combined['primary_root_cause']}, MITRE={res_combined['mitre_count']}")
    print(f"2. normal_activity.csv: Detections={res_normal['detections_count']}, Incidents={res_normal['incidents_count']}, RootCause={res_normal['primary_root_cause']}, MITRE={res_normal['mitre_count']}")
    
    # Invariant assertions
    assert res_normal["detections_count"] == 0, "Normal activity should have 0 deterministic detections"
    assert res_normal["incidents_count"] == 0, "Normal activity should have 0 incidents"
    assert res_normal["primary_root_cause"] == "UNKNOWN", "Normal activity root cause should be UNKNOWN"
    assert res_normal["mitre_count"] == 0, "Normal activity should have 0 MITRE mappings"
    
    assert res_combined["detections_count"] >= 5, "Combined attack must trigger deterministic detections"
    assert res_combined["incidents_count"] >= 1, "Combined attack must create formal incidents"
    assert res_combined["primary_root_cause"] == "CREDENTIAL_COMPROMISE", "Combined attack primary root cause must be CREDENTIAL_COMPROMISE"
    assert res_combined["mitre_count"] >= 5, "Combined attack must map MITRE techniques"

    print("\nALL INVARIANTS AND WORKFLOW STEPS VERIFIED SUCCESSFULLY!")
