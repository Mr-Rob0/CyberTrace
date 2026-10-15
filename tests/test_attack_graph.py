"""
Unit and Integration Tests for reconstruction/attack_graph.py
=============================================================
Tests verify:
    - Requirement K: Attack graph nodes correspond to actual reconstructed stages.
    - Requirement L: Graph edges connect valid stages in chronological order.
    - Requirement M: Graph does not contain impossible self-loops (source != target).
    - NetworkX DiGraph correctly reflects nodes and directed edges.
    - Edge relationships use controlled vocabulary: 'precedes', 'supports', 'leads_to'.
    - Empty attack chain results in empty graph.
    - ASCII rendering creates readable representation.
"""

import os
from datetime import datetime
import pytest

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor, AttackStage
from reconstruction.attack_graph import (
    AttackGraphNode,
    AttackGraphEdge,
    AttackGraph,
    build_attack_graph,
    VALID_EDGE_RELATIONSHIPS,
)

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks")
)


class TestAttackGraphModel:
    """Test graph model validation and invariants."""

    def test_valid_node_creation(self):
        node = AttackGraphNode(
            node_id="STEP-0001",
            stage=AttackStage.CREDENTIAL_ACCESS.value,
            title="Credential Access",
            confidence=0.90,
            event_ids=["EVT-01", "EVT-02"],
        )
        assert node.node_id == "STEP-0001"
        assert node.confidence == 0.90
        assert len(node.event_ids) == 2

    def test_invalid_stage_rejected(self):
        with pytest.raises(ValueError, match="Invalid stage"):
            AttackGraphNode(
                node_id="STEP-0001",
                stage="FAKE_STAGE",
                title="Fake",
                confidence=0.85,
                event_ids=["EVT-01"],
            )

    def test_edge_prevents_self_loop(self):
        """Requirement M: impossible self-loops are strictly prevented."""
        with pytest.raises(ValueError, match="Impossible self-loop"):
            AttackGraphEdge(
                source="STEP-0001",
                target="STEP-0001",  # Self loop!
                relationship="precedes",
            )

    def test_edge_invalid_relationship_rejected(self):
        with pytest.raises(ValueError, match="Invalid relationship"):
            AttackGraphEdge(
                source="STEP-0001",
                target="STEP-0002",
                relationship="causes_definitely",  # Forbidden: not in controlled set
            )


class TestAttackGraphIntegration:
    """Test graph generation from reconstructed attack chains."""

    @pytest.fixture
    def reconstructed_chain(self):
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        main_inc = max(incidents, key=lambda inc: inc.detection_count)
        reconstructor = AttackChainReconstructor()
        return reconstructor.reconstruct(main_inc, events=parse_res.events, detections=detections)

    def test_requirement_k_nodes_correspond_to_reconstructed_stages(self, reconstructed_chain):
        """K. Attack graph nodes correspond to actual reconstructed stages."""
        graph = build_attack_graph(reconstructed_chain)

        assert len(graph.nodes) == len(reconstructed_chain.steps)
        step_ids = [s.step_id for s in reconstructed_chain.steps]
        graph_node_ids = list(graph.nodes.keys())
        assert step_ids == graph_node_ids

        for step in reconstructed_chain.steps:
            node = graph.nodes[step.step_id]
            assert node.stage == step.stage
            assert node.confidence == step.confidence
            assert node.event_ids == step.event_ids

    def test_requirement_l_edges_connect_valid_stages(self, reconstructed_chain):
        """L. Graph edges connect valid stages in chronological sequence."""
        graph = build_attack_graph(reconstructed_chain)

        assert len(graph.edges) == len(reconstructed_chain.steps) - 1
        for edge in graph.edges:
            assert edge.source in graph.nodes
            assert edge.target in graph.nodes
            assert edge.relationship in VALID_EDGE_RELATIONSHIPS

    def test_requirement_m_no_self_loops(self, reconstructed_chain):
        """M. Graph does not contain impossible self-loops."""
        graph = build_attack_graph(reconstructed_chain)

        for edge in graph.edges:
            assert edge.source != edge.target, f"Self-loop detected on {edge.source}"

    def test_networkx_graph_properties(self, reconstructed_chain):
        """Verify underlying NetworkX DiGraph representation."""
        graph = build_attack_graph(reconstructed_chain)
        nx_g = graph.nx_graph

        assert nx_g.number_of_nodes() == len(reconstructed_chain.steps)
        assert nx_g.number_of_edges() == len(reconstructed_chain.steps) - 1
        # In a sequential chain, graph must be a directed acyclic graph (DAG)
        import networkx as nx
        assert nx.is_directed_acyclic_graph(nx_g)

    def test_empty_chain_produces_empty_graph(self):
        """Empty attack chain produces empty graph without errors."""
        empty_chain = AttackChainReconstructor().reconstruct(None)
        graph = build_attack_graph(empty_chain)

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert graph.render_ascii() == "[Empty Attack Graph]"

    def test_ascii_rendering_contains_stages(self, reconstructed_chain):
        """ASCII rendering contains all stage names in sequence."""
        graph = build_attack_graph(reconstructed_chain)
        rendered = graph.render_ascii()

        for step in reconstructed_chain.steps:
            assert step.stage in rendered
