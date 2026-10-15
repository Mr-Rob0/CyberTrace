"""
CyberTrace Attack Reconstruction and Root-Cause Analysis Demo (Phase 6)
========================================================================
Demonstrates the full deterministic reconstruction pipeline:
    Logs -> Parser -> Normalizer -> RuleEngine -> EventCorrelator -> IncidentDetector -> TimelineBuilder -> AttackChainReconstructor -> AttackGraph -> RootCauseAnalyzer

Evaluates:
    1. data/sample_attacks/combined_attack.csv (Multi-stage attack)
    2. data/sample_attacks/normal_activity.csv (Benign baseline)

Usage:
    python scripts/test_reconstruction.py
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "sample_attacks")

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from correlation.timeline_builder import TimelineBuilder
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.attack_graph import build_attack_graph
from reconstruction.root_cause import RootCauseAnalyzer, identify_root_cause


def run_reconstruction_pipeline(filepath: str, label: str):
    filename = os.path.basename(filepath)
    print("\n" + "=" * 50)
    print("CYBERTRACE ATTACK RECONSTRUCTION")
    print("=" * 50)
    print(f"Dataset: {label} ({filename})")

    # 1. Parse & Normalize
    parse_result = parse_log_file(filepath)
    events = parse_result.events

    # 2. Rule Detection
    engine = RuleEngine()
    detections = engine.detect(events)

    # 3. Correlation
    correlator = EventCorrelator()
    groups = correlator.correlate(detections)

    # 4. Incident Formulation
    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)

    if not incidents:
        print("\nIncidents Formulated: 0")
        print("Reconstructed Chains: 0")
        print("\n>> Clean Baseline Activity: Zero incidents and zero reconstructed attack chains.")
        print("=" * 50)
        return

    # Process each formulated incident
    events_map = {e.event_id: e for e in events}
    reconstructor = AttackChainReconstructor()
    analyzer = RootCauseAnalyzer()

    for inc in incidents:
        # 5. Timeline Construction
        timeline = TimelineBuilder.build_for_incident(inc, events_map, detections=detections)

        # 6. Attack Chain Reconstruction
        chain = reconstructor.reconstruct(inc, events=events, detections=detections)

        # 7. Attack Graph Construction
        graph = build_attack_graph(chain)

        # 8. Root Cause Candidates
        candidates = analyzer.analyze(chain)

        print(f"\nIncident:\n{inc.incident_id}")
        print(f"\nOverall Confidence:\n{chain.overall_confidence:.2f}")

        print("\nProbable Attack Sequence:\n")
        for idx, step in enumerate(chain.steps, start=1):
            t_start = step.timestamp_start.strftime("%Y-%m-%d %H:%M:%S")
            t_end = step.timestamp_end.strftime("%Y-%m-%d %H:%M:%S")
            time_str = t_start if t_start == t_end else f"{t_start} -> {t_end}"
            print(f"{idx}. {step.stage}")
            print(f"   Confidence: {step.confidence:.2f}")
            print(f"   Time:       {time_str}")
            print(f"   Observed:   {step.observed_evidence}")
            print(f"   Inference:  {step.inference_reason}")
            ev_sample = ", ".join(step.event_ids[:4]) + (f" (+{len(step.event_ids)-4} more)" if len(step.event_ids) > 4 else "")
            print(f"   Evidence:   {ev_sample} [Total events: {len(step.event_ids)}]")
            print()

        print("ATTACK GRAPH\n")
        if chain.steps:
            for idx, step in enumerate(chain.steps):
                print(f"{step.stage}")
                if idx < len(chain.steps) - 1:
                    next_step = chain.steps[idx + 1]
                    matching_edges = [e for e in graph.edges if e.source == step.step_id and e.target == next_step.step_id]
                    rel = matching_edges[0].relationship if matching_edges else "precedes"
                    print(f"        ↓  ({rel})")
            print()
        else:
            print("[Empty Graph - No stages inferred]\n")

        print("PROBABLE ROOT-CAUSE CANDIDATES\n")
        for cand in candidates:
            prim_tag = " (PRIMARY)" if cand.is_primary else ""
            print(f"{cand.rank}. Candidate:  {cand.title}{prim_tag}")
            print(f"   Type:       {cand.candidate_type}")
            print(f"   Confidence: {cand.confidence:.2f}")
            ev_str = ", ".join(cand.evidence_event_ids[:6]) + (f" (+{len(cand.evidence_event_ids)-6} more)" if len(cand.evidence_event_ids) > 6 else "")
            print(f"   Evidence:   {ev_str or 'None'}")
            print(f"   Reasoning:  {cand.reasoning}\n")

        print("LIMITATIONS\n")
        print(
            "Attack reconstruction and preliminary root-cause identification are based solely "
            "on available synthetic log telemetry and represent evidence-backed probable inference "
            "rather than confirmed ground truth. Telemetry gaps or unmonitored services may omit "
            "intermediate attacker actions. Final root-cause determination and prevention "
            "recommendations will be integrated in subsequent phases."
        )
        print("=" * 50)


def main():
    combined_attack_path = os.path.join(DATA_DIR, "combined_attack.csv")
    normal_activity_path = os.path.join(DATA_DIR, "normal_activity.csv")

    run_reconstruction_pipeline(combined_attack_path, "Combined Multi-Stage Attack")
    run_reconstruction_pipeline(normal_activity_path, "Normal Baseline Activity")


if __name__ == "__main__":
    main()
