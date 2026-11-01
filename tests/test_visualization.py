"""
Unit Tests for visualization/timeline.py and visualization/graph.py
===================================================================
Tests verify:
    1. render_timeline handles empty, None, and valid AttackChain data.
    2. render_timeline produces a valid Plotly go.Figure.
    3. render_attack_graph handles empty, None, AttackGraph, DiGraph, and dicts.
    4. render_attack_graph produces valid nodes, directed edges, and Plotly annotations.
"""

import os
import pytest
import networkx as nx
import plotly.graph_objects as go

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.attack_graph import build_attack_graph, AttackGraph
from visualization.timeline import render_timeline
from visualization.graph import render_attack_graph

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))


@pytest.fixture
def sample_attack_chain_and_graph():
    filepath = os.path.join(DATA_DIR, "combined_attack.csv")
    parsed = parse_log_file(filepath)
    engine = RuleEngine()
    dets = engine.detect(parsed.events)
    correlator = EventCorrelator()
    groups = correlator.correlate(dets)
    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)
    chain = AttackChainReconstructor().reconstruct(incidents[0], events=parsed.events, detections=dets)
    graph = build_attack_graph(chain)
    return chain, graph


class TestTimelineVisualization:
    """Tests for visualization/timeline.py."""

    def test_render_timeline_empty_returns_figure(self):
        fig = render_timeline([])
        assert isinstance(fig, go.Figure)

    def test_render_timeline_none_returns_figure(self):
        fig = render_timeline(None)
        assert isinstance(fig, go.Figure)

    def test_render_timeline_with_attack_chain(self, sample_attack_chain_and_graph):
        chain, _ = sample_attack_chain_and_graph
        fig = render_timeline(chain)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) >= 1
        # Should have annotations for stages
        assert len(fig.layout.annotations) == len(chain.steps)

    def test_render_timeline_with_dict(self):
        dict_data = [
            {"step_id": "STEP-01", "stage": "CREDENTIAL_ACCESS", "title": "Brute force", "confidence": 0.9, "timestamp": "2026-10-15T10:00:00"},
            {"step_id": "STEP-02", "stage": "PRIVILEGE_ESCALATION", "title": "Sudo", "confidence": 0.88, "timestamp": "2026-10-15T10:05:00"},
        ]
        fig = render_timeline(dict_data)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) >= 1
        assert len(fig.layout.annotations) == 2


class TestAttackGraphVisualization:
    """Tests for visualization/graph.py."""

    def test_render_attack_graph_empty_returns_figure(self):
        fig = render_attack_graph(None)
        assert isinstance(fig, go.Figure)

    def test_render_attack_graph_empty_attack_graph_returns_figure(self):
        empty_graph = AttackGraph("INC-EMPTY")
        fig = render_attack_graph(empty_graph)
        assert isinstance(fig, go.Figure)

    def test_render_attack_graph_with_attack_graph_instance(self, sample_attack_chain_and_graph):
        _, graph = sample_attack_chain_and_graph
        fig = render_attack_graph(graph)
        assert isinstance(fig, go.Figure)
        # Should have node scatter and edge traces
        assert len(fig.data) >= 2
        # Should have node and arrow annotations
        assert len(fig.layout.annotations) >= len(graph.nodes)

    def test_render_attack_graph_with_nx_digraph(self, sample_attack_chain_and_graph):
        _, graph = sample_attack_chain_and_graph
        fig = render_attack_graph(graph.nx_graph)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) >= 2

    def test_render_attack_graph_with_dict(self):
        graph_dict = {
            "nodes": [
                {"node_id": "STEP-01", "stage": "INITIAL_ACCESS", "title": "Login", "confidence": 0.85, "event_ids": ["E1"]},
                {"node_id": "STEP-02", "stage": "EXFILTRATION", "title": "Data stream", "confidence": 0.90, "event_ids": ["E2"]},
            ],
            "edges": [
                {"source": "STEP-01", "target": "STEP-02", "relationship": "leads_to"}
            ]
        }
        fig = render_attack_graph(graph_dict)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) >= 2

    def test_render_timeline_out_of_order_events_sorted(self):
        """Events provided out of order must be sorted chronologically."""
        unordered_events = [
            {"step_id": "STEP-03", "stage": "EXFILTRATION", "timestamp": "2026-10-15 11:00:00"},
            {"step_id": "STEP-01", "stage": "INITIAL_ACCESS", "timestamp": "2026-10-15 09:00:00"},
            {"step_id": "STEP-02", "stage": "PRIVILEGE_ESCALATION", "timestamp": "2026-10-15 10:00:00"},
        ]
        fig = render_timeline(unordered_events)
        assert isinstance(fig, go.Figure)
        x_coords = list(fig.data[0].x)
        assert x_coords == sorted(x_coords), "Timeline points were not sorted chronologically!"

    def test_render_attack_graph_with_none_confidence_does_not_crash(self):
        """Node with confidence None should not raise a format string TypeError."""
        graph_dict = {
            "nodes": [
                {"node_id": "STEP-01", "stage": "DISCOVERY", "title": "Scan", "confidence": None, "event_ids": ["E1"]},
            ],
            "edges": []
        }
        fig = render_attack_graph(graph_dict)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) >= 1

    def test_render_attack_graph_single_node(self):
        """Single node graph renders correctly without edge errors."""
        graph_dict = {
            "nodes": [
                {"node_id": "STEP-01", "stage": "INITIAL_ACCESS", "title": "Ingress", "confidence": 0.85, "event_ids": ["E1"]},
            ],
            "edges": []
        }
        fig = render_attack_graph(graph_dict)
        assert isinstance(fig, go.Figure)
        assert len(fig.data) == 1

    def test_render_attack_graph_missing_edge_endpoints_safe(self):
        """Edges with endpoints not in nodes_dict should be skipped safely."""
        graph_dict = {
            "nodes": [
                {"node_id": "STEP-01", "stage": "INITIAL_ACCESS", "title": "Ingress", "confidence": 0.85, "event_ids": ["E1"]},
            ],
            "edges": [
                {"source": "STEP-01", "target": "NON_EXISTENT_STEP", "relationship": "leads_to"}
            ]
        }
        fig = render_attack_graph(graph_dict)
        assert isinstance(fig, go.Figure)

