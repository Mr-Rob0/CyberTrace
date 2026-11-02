"""
Audit and Regression Tests for CyberTrace Attack Reconstruction & Graph Visualization
=====================================================================================
Validates Attack Reconstruction audit requirements on the UWF-ZeekData22 dataset:
    1. Validates reconstructed stages against actual underlying telemetry.
    2. Distinguishes observed network behaviour from confirmed malicious activity.
    3. Does not treat unlabelled events as confirmed malicious or confirmed benign.
    4. Enforces clear distinction between:
       - Observed behaviour
       - Inferred attack technique
       - Dataset ground-truth label
    5. Recalibrates confidence to reflect evidence support, not assumed compromise.
    6. Ensures zero hallucination: no downstream attack stages without supporting evidence.
    7. Ensures Attack Progression Graph renders non-blank, informative visualizations
       for isolated single stages, multi-stage progressions, and empty graphs.
    8. Preserves evidence traceability: AttackStep -> Detection IDs -> Event IDs.
"""

import os
import pytest
from datetime import datetime
import plotly.graph_objects as go

from preprocessing.log_parser import CSVLogParser
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor, AttackStage, AttackStep
from reconstruction.attack_graph import build_attack_graph, AttackGraph, AttackGraphNode, AttackGraphEdge
from visualization.graph import render_attack_graph


UWF_DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "uploads", "upload_a7c005001b2242fde365.csv")
)
COMBINED_DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks", "combined_attack.csv")
)


@pytest.fixture(scope="module")
def uwf_pipeline_results():
    """Execute pipeline once on the uploaded UWF-ZeekData22 dataset."""
    if not os.path.exists(UWF_DATASET_PATH):
        pytest.skip(f"UWF-ZeekData22 dataset not found at {UWF_DATASET_PATH}")

    parser = CSVLogParser()
    parse_result = parser.parse_file(UWF_DATASET_PATH)

    rule_engine = RuleEngine()
    detections = rule_engine.detect(parse_result.events)

    correlator = EventCorrelator()
    groups = correlator.correlate(detections)

    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)

    return parse_result, detections, incidents


class TestUWFZeekAttackReconstructionAudit:
    """Audit tests using the uploaded UWF-ZeekData22 dataset."""

    def test_uwf_dataset_ingestion_and_target_ip_presence(self, uwf_pipeline_results):
        """Validate that the dataset contains source IP 143.88.11.10 telemetry."""
        parse_result, _, incidents = uwf_pipeline_results
        assert parse_result.total_rows > 20000

        target_events = [e for e in parse_result.events if getattr(e, "source_ip", "") == "143.88.11.10"]
        assert len(target_events) > 4000, "Expected >4000 events for IP 143.88.11.10"

        # Verify ground truth column is unlabelled ('none') for 143.88.11.10
        raw_msgs = [e.raw_message for e in target_events[:20]]
        assert any("mitre_attack_tactics=none" in msg for msg in raw_msgs)

    def test_uwf_incident_contains_observed_89_evidence_events(self, uwf_pipeline_results):
        """Requirement 1: Verify INC-0001 contains exactly 89 evidence events for 143.88.11.10."""
        _, _, incidents = uwf_pipeline_results
        target_inc = next((i for i in incidents if "143.88.11.10" in i.source_ips and len(i.event_ids) == 89), None)
        assert target_inc is not None, "Expected an incident with 89 evidence events from 143.88.11.10"
        assert len(target_inc.event_ids) == 89
        assert "143.88.11.10" in target_inc.source_ips

    def test_reconstruction_produces_only_supported_discovery_stage(self, uwf_pipeline_results):
        """Requirement 6: Zero hallucination — only 1 stage (DISCOVERY) is generated."""
        parse_result, detections, incidents = uwf_pipeline_results
        target_inc = next(i for i in incidents if "143.88.11.10" in i.source_ips and len(i.event_ids) == 89)

        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(target_inc, events=parse_result.events, detections=detections)

        assert len(chain.steps) == 1, "Must produce exactly 1 stage; no downstream stages without evidence"
        step = chain.steps[0]
        assert step.stage == AttackStage.DISCOVERY.value
        assert len(step.event_ids) == 89

        # Confirm all 89 event IDs exist in the incident
        for eid in step.event_ids:
            assert eid in target_inc.event_ids

    def test_triad_distinction_observed_inferred_ground_truth(self, uwf_pipeline_results):
        """Requirements 2, 3, 4: Clear distinction between observed behaviour, inferred technique, and dataset label."""
        parse_result, detections, incidents = uwf_pipeline_results
        target_inc = next(i for i in incidents if "143.88.11.10" in i.source_ips and len(i.event_ids) == 89)

        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(target_inc, events=parse_result.events, detections=detections)
        step = chain.steps[0]

        # 1. Observed Behaviour: factual telemetry recording
        assert hasattr(step, "observed_behavior")
        assert "143.88.11.10" in step.observed_behavior
        assert "89" in step.observed_behavior
        assert "port" in step.observed_behavior.lower()

        # 2. Inferred Technique: analytical MITRE mapping
        assert hasattr(step, "inferred_technique")
        assert "T1046" in step.inferred_technique or "Discovery" in step.inferred_technique
        assert "Network Service Discovery" in step.inferred_technique or "Reconnaissance" in step.inferred_technique

        # 3. Dataset Ground-Truth Label: explicitly recognizes unlabelled status
        assert hasattr(step, "dataset_label")
        assert "none" in step.dataset_label.lower() or "unlabelled" in step.dataset_label.lower()

        # Serialization check
        step_dict = step.to_dict()
        assert "observed_behavior" in step_dict
        assert "inferred_technique" in step_dict
        assert "dataset_label" in step_dict

    def test_confidence_recalibration_evidence_support_not_compromise(self, uwf_pipeline_results):
        """Requirement 5: Recalibrate confidence to represent evidence support, not assumed compromise."""
        parse_result, detections, incidents = uwf_pipeline_results
        target_inc = next(i for i in incidents if "143.88.11.10" in i.source_ips and len(i.event_ids) == 89)

        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(target_inc, events=parse_result.events, detections=detections)
        step = chain.steps[0]

        # Step confidence must be calibrated: not inflated to 0.90+ for unlabelled uncorroborated probe
        assert step.confidence <= 0.75, f"Step confidence {step.confidence} is overconfident; expected <= 0.75"
        assert step.confidence >= 0.60, f"Step confidence {step.confidence} should reflect positive evidence support"

        # Overall chain confidence must reflect single-stage uncorroborated status
        assert chain.overall_confidence < 0.75, f"Overall confidence {chain.overall_confidence} must be < 0.75"
        assert chain.overall_confidence >= 0.50, f"Overall confidence {chain.overall_confidence} should be >= 0.50"

    def test_attack_progression_graph_not_blank_for_single_stage(self, uwf_pipeline_results):
        """Requirement 7: Attack Progression Graph must NOT be blank for single-stage incidents."""
        parse_result, detections, incidents = uwf_pipeline_results
        target_inc = next(i for i in incidents if "143.88.11.10" in i.source_ips and len(i.event_ids) == 89)

        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(target_inc, events=parse_result.events, detections=detections)

        graph = build_attack_graph(chain)
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 0

        fig = render_attack_graph(graph)
        assert isinstance(fig, go.Figure)

        # Graph must contain non-empty data traces
        assert len(fig.data) >= 1
        trace = fig.data[0]
        assert len(trace.x) == 1
        assert trace.x[0] == 0.0
        assert trace.y[0] == 0.0

        # Graph must contain visible annotations explaining the isolated stage
        assert len(fig.layout.annotations) >= 3
        annotation_texts = [a.text for a in fig.layout.annotations]
        assert any("DISCOVERY" in t for t in annotation_texts)
        assert any("Isolated Stage" in t for t in annotation_texts)

        # Graph layout must be centered
        assert tuple(fig.layout.xaxis.range) == (-1.0, 1.0)

    def test_empty_attack_graph_rendering_not_blank(self):
        """Requirement 7: Empty attack graph must render clear status display instead of blank square."""
        empty_graph = AttackGraph("INC-EMPTY")
        fig = render_attack_graph(empty_graph)

        assert isinstance(fig, go.Figure)
        assert len(fig.layout.annotations) >= 1
        assert any("No Attack Stages Reconstructed" in a.text for a in fig.layout.annotations)

    def test_multi_stage_combined_attack_chain_preserved(self):
        """Requirement 8: Multi-stage attacks retain multi-stage progression and high confidence."""
        if not os.path.exists(COMBINED_DATASET_PATH):
            pytest.skip(f"combined_attack.csv not found at {COMBINED_DATASET_PATH}")

        parser = CSVLogParser()
        parse_result = parser.parse_file(COMBINED_DATASET_PATH)
        rule_engine = RuleEngine()
        detections = rule_engine.detect(parse_result.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)

        main_inc = max(incidents, key=lambda i: len(i.event_ids))
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(main_inc, events=parse_result.events, detections=detections)

        assert len(chain.steps) >= 4
        assert chain.overall_confidence > 0.85

        graph = build_attack_graph(chain)
        assert len(graph.nodes) >= 4
        assert len(graph.edges) >= 3

        fig = render_attack_graph(graph)
        assert len(fig.data) >= 2
        assert len(fig.layout.annotations) >= len(graph.nodes)
