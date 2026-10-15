"""
Unit Tests for correlation/event_correlator.py
=============================================
Tests verify:
    - Same source IP + close timestamps correlates.
    - Same destination IP + close timestamps correlates.
    - Same username contributes to correlation.
    - Same hostname contributes to correlation.
    - Detections far outside correlation window do not correlate solely on time.
    - Unrelated detections remain in separate groups.
    - Shared evidence strongly correlates.
    - Correlation scores remain strictly bounded in [0.0, 1.0].
    - Graph connected components grouping handles multiple chained detections.
"""

from datetime import datetime, timedelta
import pytest

from detection.rule_engine import Detection
from correlation.event_correlator import EventCorrelator, CorrelationConfig, correlate_events


def make_test_detection(
    detection_id: str = "DET-01",
    rule_id: str = "R001",
    rule_name: str = "Brute Force",
    timestamp: datetime = datetime(2026, 10, 16, 9, 0, 0),
    severity: str = "HIGH",
    source_ip: str = "192.168.1.188",
    destination_ip: str = "192.168.1.12",
    username: str = "svc_admin",
    hostname: str = "srv-app-prod",
    event_ids: list = None,
    confidence: float = 0.85,
) -> Detection:
    return Detection(
        detection_id=detection_id,
        rule_id=rule_id,
        rule_name=rule_name,
        timestamp=timestamp,
        severity=severity,
        title=f"Test {rule_name}",
        description=f"Test detection {detection_id}",
        event_ids=event_ids or ["EVT-01"],
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        confidence=confidence,
    )


class TestPairwiseCorrelationScores:
    """Test calculate_pair_score across various signal combinations."""

    def test_same_source_ip_and_close_time_correlates(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip="192.168.1.188",
            destination_ip=None, username=None, hostname=None, event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(minutes=5), source_ip="192.168.1.188",
            destination_ip=None, username=None, hostname=None, event_ids=["E2"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        # source_ip (+0.30) + temporal (+0.15) = 0.45 >= threshold (0.40)
        assert score >= 0.40
        assert score == 0.45

    def test_same_destination_and_close_time_correlates(self):
        correlator = EventCorrelator(CorrelationConfig(correlation_threshold=0.35))
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip="192.168.1.10",
            destination_ip="192.168.1.50", username=None, hostname=None, event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(minutes=5), source_ip="192.168.1.20",
            destination_ip="192.168.1.50", username=None, hostname=None, event_ids=["E2"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        # destination_ip (+0.20) + temporal (+0.15) = 0.35
        assert score == 0.35

    def test_same_username_increases_correlation(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(detection_id="D1", timestamp=t0, username="alice", event_ids=["E1"])
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(minutes=5), username="alice",
            source_ip=d1.source_ip, event_ids=["E2"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        # source_ip (+0.30) + username (+0.20) + dest_ip (+0.20) + hostname (+0.15) + temporal (+0.15) = 1.0 (capped)
        assert score == 1.0

    def test_same_hostname_increases_correlation(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip=None, destination_ip=None,
            username=None, hostname="srv-db-01", event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(minutes=2), source_ip=None,
            destination_ip=None, username=None, hostname="srv-db-01", event_ids=["E2"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        # hostname (+0.15) + temporal (+0.15) = 0.30
        assert score == 0.30

    def test_outside_time_window_does_not_get_temporal_boost(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip=None, destination_ip=None,
            username=None, hostname=None, event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(hours=5), source_ip=None,
            destination_ip=None, username=None, hostname=None, event_ids=["E2"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        assert score == 0.0

    def test_shared_evidence_strongly_correlates(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip=None, destination_ip=None,
            username=None, hostname=None, event_ids=["EVT-SHARED-1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(hours=2), source_ip=None,
            destination_ip=None, username=None, hostname=None, event_ids=["EVT-SHARED-1"]
        )

        score = correlator.calculate_pair_score(d1, d2)
        # shared evidence (+0.40)
        assert score >= 0.40

    def test_score_remains_strictly_bounded_at_one(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(detection_id="D1", timestamp=t0, event_ids=["E1"])
        d2 = make_test_detection(detection_id="D2", timestamp=t0, event_ids=["E1"])

        score = correlator.calculate_pair_score(d1, d2)
        assert 0.0 <= score <= 1.0


class TestDetectionClustering:
    """Test group construction and connected components in EventCorrelator."""

    def test_empty_input_returns_empty_groups(self):
        correlator = EventCorrelator()
        assert correlator.correlate([]) == []

    def test_unrelated_detections_remain_separate(self):
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip="192.168.1.10",
            destination_ip="192.168.1.20", username="userA", hostname="hostA", event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(hours=4), source_ip="10.0.0.99",
            destination_ip="10.0.0.100", username="userB", hostname="hostB", event_ids=["E2"]
        )

        groups = correlator.correlate([d1, d2])
        assert len(groups) == 2
        assert len(groups[0]) == 1
        assert len(groups[1]) == 1

    def test_chained_correlations_cluster_into_single_group(self):
        """A links to B, B links to C -> {A, B, C} forms one group."""
        correlator = EventCorrelator()
        t0 = datetime(2026, 10, 16, 9, 0, 0)

        # d1 and d2 share source_ip
        d1 = make_test_detection(
            detection_id="D1", timestamp=t0, source_ip="192.168.1.188",
            destination_ip="192.168.1.12", username="user1", event_ids=["E1"]
        )
        d2 = make_test_detection(
            detection_id="D2", timestamp=t0 + timedelta(minutes=5), source_ip="192.168.1.188",
            destination_ip="192.168.1.12", username="root", event_ids=["E2"]
        )
        # d2 and d3 share destination_ip and username
        d3 = make_test_detection(
            detection_id="D3", timestamp=t0 + timedelta(minutes=10), source_ip=None,
            destination_ip="192.168.1.12", username="root", event_ids=["E3"]
        )

        groups = correlator.correlate([d1, d2, d3])
        assert len(groups) == 1
        assert len(groups[0]) == 3
        assert {d.detection_id for d in groups[0]} == {"D1", "D2", "D3"}
