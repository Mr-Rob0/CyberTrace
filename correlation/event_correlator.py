"""
Event Correlator Module
=======================
Deterministically links and clusters security detections based on multiple
correlating signals:
    - Same Source IP (+0.30)
    - Same Destination IP (+0.20)
    - Same Username (+0.20)
    - Same Hostname (+0.15)
    - Temporal Proximity within configurable window (+0.15)
    - Shared Evidence / Event IDs (+0.40)

Score is strictly capped at 1.0. This is a deterministic similarity metric,
NOT an ML probability.

Uses graph-based connected-components grouping (NetworkX) to bundle related
detections into unified incident groups without duplicate alert spam.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
import networkx as nx

from detection.rule_engine import Detection


@dataclass
class CorrelationConfig:
    """Configurable weights and thresholds for event correlation."""
    correlation_window_seconds: int = 1800  # 30 minutes
    correlation_threshold: float = 0.40

    # Weight contributions
    weight_same_source_ip: float = 0.30
    weight_same_destination_ip: float = 0.20
    weight_host_pivot: float = 0.20  # Compromised destination host acts as outbound source
    weight_same_username: float = 0.20
    weight_same_hostname: float = 0.15
    weight_temporal_proximity: float = 0.15
    weight_shared_evidence: float = 0.40


class EventCorrelator:
    """
    Correlates individual rule detections into cohesive incident clusters.
    """

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()

    def calculate_pair_score(self, d1: Detection, d2: Detection) -> float:
        """
        Calculate a deterministic correlation score between two detections.

        Returns:
            Float between 0.0 and 1.0.
        """
        score = 0.0

        # 1. Source IP match
        if d1.source_ip and d2.source_ip and d1.source_ip == d2.source_ip:
            score += self.config.weight_same_source_ip

        # 2. Destination IP match
        if d1.destination_ip and d2.destination_ip and d1.destination_ip == d2.destination_ip:
            score += self.config.weight_same_destination_ip

        # 2b. Host Pivot / Egress (Target of attack acts as source of subsequent action)
        if (d1.destination_ip and d2.source_ip and d1.destination_ip == d2.source_ip) or (
            d1.source_ip and d2.destination_ip and d1.source_ip == d2.destination_ip
        ):
            score += self.config.weight_host_pivot

        # 3. Username match
        if d1.username and d2.username and d1.username.lower() == d2.username.lower():
            score += self.config.weight_same_username

        # 4. Hostname match
        if d1.hostname and d2.hostname and d1.hostname.lower() == d2.hostname.lower():
            score += self.config.weight_same_hostname

        # 5. Temporal Proximity
        time_diff = abs((d1.timestamp - d2.timestamp).total_seconds())
        if time_diff <= self.config.correlation_window_seconds:
            score += self.config.weight_temporal_proximity

        # 6. Shared Evidence (common event IDs)
        shared_events = set(d1.event_ids) & set(d2.event_ids)
        if shared_events:
            score += self.config.weight_shared_evidence

        # Strictly cap score at 1.0
        return min(round(score, 4), 1.0)

    def correlate(self, detections: List[Detection]) -> List[List[Detection]]:
        """
        Group detections into correlated incident clusters using graph connected components.

        Args:
            detections: List of Detection objects.

        Returns:
            List of detection groups, where each group is a list of correlated Detections.
        """
        if not detections:
            return []

        if len(detections) == 1:
            return [[detections[0]]]

        # Map detection_id to Detection object
        det_map = {d.detection_id: d for d in detections}

        # Build correlation graph
        graph = nx.Graph()
        for det_id in det_map:
            graph.add_node(det_id)

        n = len(detections)
        for i in range(n):
            for j in range(i + 1, n):
                d1 = detections[i]
                d2 = detections[j]
                score = self.calculate_pair_score(d1, d2)

                if score >= self.config.correlation_threshold:
                    graph.add_edge(d1.detection_id, d2.detection_id, weight=score)

        # Find connected components (incident clusters)
        groups: List[List[Detection]] = []
        for component in nx.connected_components(graph):
            group = [det_map[det_id] for det_id in component]
            # Sort each group chronologically
            group.sort(key=lambda d: d.timestamp)
            groups.append(group)

        # Sort all groups by earliest detection timestamp
        groups.sort(key=lambda g: g[0].timestamp)
        return groups


def correlate_events(detected_events: List[Detection]) -> List[List[Detection]]:
    """
    Functional interface to correlate a list of detections.

    Args:
        detected_events: List of Detection instances.

    Returns:
        List of correlated detection groups.
    """
    correlator = EventCorrelator()
    return correlator.correlate(detected_events)
