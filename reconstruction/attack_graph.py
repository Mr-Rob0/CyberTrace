"""
Attack Graph Module
===================
Constructs a directed graph representing the reconstructed progression of an attack.

Each node represents an inferred AttackStage backed by log evidence.
Each edge represents a chronological progression or evidentiary transition
between stages (e.g., 'precedes', 'supports', 'leads_to').

Edge Semantic Constraints:
    - "leads_to": Represents a probable chronological transition between sequential
      stages within the inferred attack chain based on evidence timestamps.
      It does NOT prove physical causality, mechanistic determinism, or attacker intent.
    - "supports": Represents evidentiary corroboration where activity in one stage
      provides foundational access or enablement for a subsequent stage.
    - "precedes": Denotes strict temporal precedence where one stage occurred earlier
      in the incident timeline without strong domain-specific correlation.

Deterministic Constraints:
    - Only creates edges based on chronological evidence.
    - Does not claim causal certainty.
    - Prevents impossible self-loops.
    - Uses NetworkX for topological representation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import networkx as nx

from reconstruction.attack_chain import AttackChain, AttackStep, VALID_ATTACK_STAGES


VALID_EDGE_RELATIONSHIPS = {"precedes", "supports", "leads_to"}



@dataclass
class AttackGraphNode:
    """
    A single node in the attack graph corresponding to an inferred attack stage.
    """
    node_id: str
    stage: str
    title: str
    confidence: float
    event_ids: List[str]
    timestamp_start: Optional[datetime] = None
    timestamp_end: Optional[datetime] = None

    def __post_init__(self):
        if not self.node_id:
            raise ValueError("node_id cannot be empty")
        if self.stage not in VALID_ATTACK_STAGES:
            raise ValueError(f"Invalid stage '{self.stage}'. Allowed: {VALID_ATTACK_STAGES}")
        if not (0.0 < self.confidence < 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0 (exclusive).")
        if not self.event_ids:
            raise ValueError("AttackGraphNode must have at least one supporting event_id.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph node to serializable dictionary."""
        return {
            "node_id": self.node_id,
            "stage": self.stage,
            "title": self.title,
            "confidence": round(self.confidence, 4),
            "event_ids": self.event_ids,
            "timestamp_start": self.timestamp_start.isoformat() if self.timestamp_start else None,
            "timestamp_end": self.timestamp_end.isoformat() if self.timestamp_end else None,
        }


@dataclass
class AttackGraphEdge:
    """
    A directed edge representing transition or evidentiary progression between stages.

    Note on Relationship Semantics:
        - 'leads_to': Inferred chronological transition between sequential stages.
          Represents temporal succession in the reconstruction model; does NOT prove
          physical causality or adversary intention.
        - 'supports': Evidentiary enablement between stages (e.g., privilege escalation
          enables sensitive data collection).
        - 'precedes': Simple temporal precedence in the reconstructed incident timeline.
    """
    source: str
    target: str
    relationship: str
    description: str = ""


    def __post_init__(self):
        if not self.source or not self.target:
            raise ValueError("Edge source and target must not be empty.")
        if self.source == self.target:
            raise ValueError(f"Impossible self-loop: edge cannot connect node '{self.source}' to itself.")
        if self.relationship not in VALID_EDGE_RELATIONSHIPS:
            raise ValueError(f"Invalid relationship '{self.relationship}'. Allowed: {VALID_EDGE_RELATIONSHIPS}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph edge to serializable dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "description": self.description,
        }


class AttackGraph:
    """
    Directed graph structure holding stages (nodes) and transitions (edges).
    """

    def __init__(self, incident_id: str = "INC-UNKNOWN"):
        self.incident_id: str = incident_id
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.edges: List[AttackGraphEdge] = []
        self._nx_graph: nx.DiGraph = nx.DiGraph()

    def add_node(self, node: AttackGraphNode) -> None:
        """Add a stage node to the graph."""
        self.nodes[node.node_id] = node
        self._nx_graph.add_node(
            node.node_id,
            stage=node.stage,
            title=node.title,
            confidence=node.confidence,
            event_ids=node.event_ids,
        )

    def add_edge(self, edge: AttackGraphEdge) -> None:
        """Add a transition edge between stage nodes."""
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError(f"Edge endpoints '{edge.source}' or '{edge.target}' do not exist in graph.")
        self.edges.append(edge)
        self._nx_graph.add_edge(
            edge.source,
            edge.target,
            relationship=edge.relationship,
            description=edge.description,
        )

    @property
    def nx_graph(self) -> nx.DiGraph:
        """Return underlying NetworkX DiGraph instance."""
        return self._nx_graph

    def render_ascii(self) -> str:
        """Render a clean text-based visualization of the attack graph."""
        if not self.nodes:
            return "[Empty Attack Graph]"

        lines: List[str] = []
        node_order = list(self.nodes.values())

        for idx, node in enumerate(node_order):
            lines.append(f"  [{node.node_id}] {node.stage} (conf={node.confidence:.2f}, {len(node.event_ids)} events)")
            if idx < len(node_order) - 1:
                # Find edge to next
                matching_edges = [
                    e for e in self.edges if e.source == node.node_id and e.target == node_order[idx + 1].node_id
                ]
                rel = matching_edges[0].relationship if matching_edges else "precedes"
                lines.append(f"         |")
                lines.append(f"         v  --({rel})-->")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert attack graph to serializable dictionary."""
        return {
            "incident_id": self.incident_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


def build_attack_graph(attack_chain: Union[AttackChain, Dict[str, Any]]) -> AttackGraph:
    """
    Build an AttackGraph from an AttackChain instance or dictionary.

    Args:
        attack_chain: AttackChain instance or serialized dict.

    Returns:
        AttackGraph instance populated with nodes and chronological edges.
    """
    if isinstance(attack_chain, dict):
        incident_id = attack_chain.get("incident_id", "INC-UNKNOWN")
        steps_raw = attack_chain.get("steps", [])
        graph = AttackGraph(incident_id=incident_id)

        node_ids: List[str] = []
        for s in steps_raw:
            node = AttackGraphNode(
                node_id=s["step_id"],
                stage=s["stage"],
                title=s["title"],
                confidence=s["confidence"],
                event_ids=s["event_ids"],
            )
            graph.add_node(node)
            node_ids.append(node.node_id)

        # Connect consecutive nodes chronologically
        for i in range(len(node_ids) - 1):
            src_id = node_ids[i]
            tgt_id = node_ids[i + 1]
            src_stage = graph.nodes[src_id].stage
            tgt_stage = graph.nodes[tgt_id].stage
            rel = _determine_relationship(src_stage, tgt_stage)
            graph.add_edge(
                AttackGraphEdge(
                    source=src_id,
                    target=tgt_id,
                    relationship=rel,
                    description=f"{src_stage} {rel} {tgt_stage}",
                )
            )

        return graph

    if isinstance(attack_chain, AttackChain):
        graph = AttackGraph(incident_id=attack_chain.incident_id)
        if not attack_chain.steps:
            return graph

        # Add nodes
        for step in attack_chain.steps:
            node = AttackGraphNode(
                node_id=step.step_id,
                stage=step.stage,
                title=step.title,
                confidence=step.confidence,
                event_ids=step.event_ids,
                timestamp_start=step.timestamp_start,
                timestamp_end=step.timestamp_end,
            )
            graph.add_node(node)

        # Add chronological edges between consecutive steps
        steps = attack_chain.steps
        for i in range(len(steps) - 1):
            s_curr = steps[i]
            s_next = steps[i + 1]
            rel = _determine_relationship(s_curr.stage, s_next.stage)
            edge = AttackGraphEdge(
                source=s_curr.step_id,
                target=s_next.step_id,
                relationship=rel,
                description=f"{s_curr.stage} chronologically {rel} {s_next.stage}",
            )
            graph.add_edge(edge)

        return graph

    raise TypeError(f"Unsupported attack_chain type: {type(attack_chain)}")


def _determine_relationship(stage_from: str, stage_to: str) -> str:
    """
    Determine deterministic edge relationship based on chronological transition.

    Relationship Semantics:
        - 'leads_to': Probable chronological progression between attack stages based on
          temporal telemetry. Does NOT prove physical causality or attacker intent.
        - 'supports': Evidentiary enablement (e.g. elevated privileges enabling data staging).
        - 'precedes': Temporal precedence where no specialized semantic linkage applies.
    """
    if stage_from == "CREDENTIAL_ACCESS" and stage_to == "INITIAL_ACCESS":

        return "leads_to"
    if stage_from == "INITIAL_ACCESS" and stage_to == "PRIVILEGE_ESCALATION":
        return "leads_to"
    if stage_from == "PRIVILEGE_ESCALATION" and stage_to == "COLLECTION":
        return "supports"
    if stage_from == "COLLECTION" and stage_to == "EXFILTRATION":
        return "leads_to"
    if stage_from == "DISCOVERY":
        return "supports"
    return "precedes"
