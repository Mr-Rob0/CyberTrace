"""
Unit Tests for correlation/incident_detector.py
===============================================
Tests verify:
    - Creation of Incident instances from correlated detection clusters.
    - Deterministic severity derivation rules.
    - Confidence calculation bounds and behavior.
    - Accurate start_time and end_time computation.
    - Unique incident IDs across multiple incidents.
    - Complete aggregation of evidence event IDs and entity sets.
    - Empty inputs produce empty incident lists.
"""

from datetime import datetime, timedelta
import pytest

from detection.rule_engine import Detection
from correlation.incident_detector import Incident, IncidentDetector, detect_incidents


def make_test_detection(
    detection_id: str,
    severity: str = "HIGH",
    timestamp: datetime = datetime(2026, 10, 16, 9, 0, 0),
    event_ids: list = None,
    source_ip: str = "192.168.1.188",
    destination_ip: str = "192.168.1.12",
    username: str = "svc_admin",
    hostname: str = "srv-app-prod",
) -> Detection:
    return Detection(
        detection_id=detection_id,
        rule_id="R001",
        rule_name="Test Rule",
        timestamp=timestamp,
        severity=severity,
        title=f"Test alert {detection_id}",
        description="Test alert description",
        event_ids=event_ids or [f"EVT-{detection_id}"],
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        confidence=0.85,
    )


class TestIncidentDetectorLogic:
    """Test incident generation and attribute synthesis."""

    def test_empty_groups_produces_empty_incidents(self):
        detector = IncidentDetector()
        assert detector.detect_incidents([]) == []

    def test_single_detection_cluster_creates_incident(self):
        detector = IncidentDetector()
        t0 = datetime(2026, 10, 16, 9, 15, 0)
        d1 = make_test_detection("DET-01", severity="HIGH", timestamp=t0, event_ids=["E1", "E2"])

        incidents = detector.detect_incidents([[d1]])
        assert len(incidents) == 1
        inc = incidents[0]

        assert inc.incident_id.startswith("INC-")
        assert inc.severity == "HIGH"
        assert inc.status == "OPEN"
        assert inc.start_time == t0
        assert inc.end_time == t0
        assert inc.detection_ids == ["DET-01"]
        assert inc.event_ids == ["E1", "E2"]
        assert inc.source_ips == ["192.168.1.188"]
        assert inc.usernames == ["svc_admin"]
        assert 0.0 <= inc.confidence <= 1.0

    def test_multiple_detections_cluster_aggregates_entities_and_events(self):
        detector = IncidentDetector()
        t1 = datetime(2026, 10, 16, 9, 10, 0)
        t2 = datetime(2026, 10, 16, 9, 25, 0)

        d1 = make_test_detection(
            "DET-01", severity="HIGH", timestamp=t1, event_ids=["E1", "E2"],
            source_ip="192.168.1.188", username="svc_admin"
        )
        d2 = make_test_detection(
            "DET-02", severity="CRITICAL", timestamp=t2, event_ids=["E2", "E3"],
            source_ip="192.168.1.188", username="root"
        )

        incidents = detector.detect_incidents([[d1, d2]])
        assert len(incidents) == 1
        inc = incidents[0]

        # Invariant checks
        assert inc.start_time == t1
        assert inc.end_time == t2
        assert inc.severity == "CRITICAL"  # Promoted by CRITICAL detection
        assert inc.detection_count == 2
        assert set(inc.detection_ids) == {"DET-01", "DET-02"}
        # Event IDs must be deduplicated
        assert inc.event_ids == ["E1", "E2", "E3"]
        assert set(inc.usernames) == {"svc_admin", "root"}

    def test_severity_derivation_rules(self):
        detector = IncidentDetector()

        # 1. Any CRITICAL -> CRITICAL
        d_crit = make_test_detection("D1", severity="CRITICAL")
        d_low = make_test_detection("D2", severity="LOW")
        assert detector.derive_severity([d_crit, d_low]) == "CRITICAL"

        # 2. HIGH -> HIGH
        d_high = make_test_detection("D3", severity="HIGH")
        d_med = make_test_detection("D4", severity="MEDIUM")
        assert detector.derive_severity([d_high, d_med]) == "HIGH"

        # 3. MEDIUM -> MEDIUM
        assert detector.derive_severity([d_med, d_low]) == "MEDIUM"

        # 4. Only LOW -> LOW
        assert detector.derive_severity([d_low]) == "LOW"

    def test_incident_ids_are_unique(self):
        detector = IncidentDetector()
        d1 = make_test_detection("D1")
        d2 = make_test_detection("D2")

        incidents = detector.detect_incidents([[d1], [d2]])
        assert len(incidents) == 2
        assert incidents[0].incident_id != incidents[1].incident_id

    def test_incident_serialization_to_dict(self):
        detector = IncidentDetector()
        d1 = make_test_detection("D1")
        inc = detector.create_incident([d1])
        d_dict = inc.to_dict()

        assert d_dict["incident_id"] == inc.incident_id
        assert d_dict["severity"] == inc.severity
        assert d_dict["status"] == "OPEN"
        assert "start_time" in d_dict
        assert "end_time" in d_dict
        assert d_dict["event_ids"] == inc.event_ids
