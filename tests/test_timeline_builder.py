"""
Unit and Integration Tests for correlation/timeline_builder.py
==============================================================
Tests verify:
    - Chronological sorting of timeline items.
    - Exact preservation of original event IDs and raw messages.
    - Association of related detection IDs with timeline items.
    - End-to-end integration with combined_attack.csv:
        * Produces at least one meaningful correlated incident with timeline.
    - End-to-end integration with normal_activity.csv:
        * Produces zero incidents and empty timeline.
"""

from datetime import datetime, timedelta
import os
import pytest

from preprocessing.event_schema import NormalizedEvent
from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine, Detection
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector, Incident
from correlation.timeline_builder import TimelineBuilder, TimelineItem, build_timeline

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))


def make_test_event(event_id: str, timestamp: datetime, **kwargs) -> NormalizedEvent:
    base = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": "auth.log",
        "event_type": "login_failed",
        "source_ip": "192.168.1.188",
        "destination_ip": "192.168.1.12",
        "username": "svc_admin",
        "raw_message": f"Raw message for {event_id}",
    }
    base.update(kwargs)
    return NormalizedEvent(**base)


class TestTimelineBuilderUnit:
    """Unit tests for TimelineBuilder mechanics."""

    def test_timeline_is_strictly_chronological(self):
        t1 = datetime(2026, 10, 16, 9, 0, 0)
        t2 = datetime(2026, 10, 16, 9, 10, 0)
        t3 = datetime(2026, 10, 16, 9, 20, 0)

        # Unordered events
        e3 = make_test_event("E3", t3)
        e1 = make_test_event("E1", t1)
        e2 = make_test_event("E2", t2)

        incident = Incident(
            incident_id="INC-01",
            created_at=datetime.now(),
            start_time=t1,
            end_time=t3,
            severity="HIGH",
            status="OPEN",
            confidence=0.88,
            detection_ids=["DET-01"],
            event_ids=["E3", "E1", "E2"],  # Shuffled order
            source_ips=["192.168.1.188"],
            destination_ips=["192.168.1.12"],
            usernames=["svc_admin"],
            hostnames=[],
            detection_count=1,
            summary="Test incident",
            correlation_score=0.8,
        )

        timeline = TimelineBuilder.build_for_incident(incident, [e1, e2, e3])

        assert len(timeline) == 3
        # Must be sorted strictly chronologically
        assert timeline[0].event_id == "E1"
        assert timeline[1].event_id == "E2"
        assert timeline[2].event_id == "E3"
        assert timeline[0].timestamp <= timeline[1].timestamp <= timeline[2].timestamp

    def test_timeline_preserves_original_event_ids_and_messages(self):
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        e1 = make_test_event("EXACT-FORENSIC-ID-99", t0, raw_message="Unmodified Audit Trail")

        incident = Incident(
            incident_id="INC-01",
            created_at=datetime.now(),
            start_time=t0,
            end_time=t0,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-01"],
            event_ids=["EXACT-FORENSIC-ID-99"],
            source_ips=[],
            destination_ips=[],
            usernames=[],
            hostnames=[],
            detection_count=1,
            summary="Test",
            correlation_score=0.8,
        )

        timeline = TimelineBuilder.build_for_incident(incident, [e1])
        assert len(timeline) == 1
        assert timeline[0].event_id == "EXACT-FORENSIC-ID-99"
        assert timeline[0].raw_message == "Unmodified Audit Trail"

    def test_timeline_maps_related_detection_ids(self):
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        e1 = make_test_event("E1", t0)

        det = Detection(
            detection_id="DET-R001-01",
            rule_id="R001",
            rule_name="Brute Force",
            timestamp=t0,
            severity="HIGH",
            title="Test",
            description="Test",
            event_ids=["E1"],
            confidence=0.85,
        )

        incident = Incident(
            incident_id="INC-01",
            created_at=datetime.now(),
            start_time=t0,
            end_time=t0,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-R001-01"],
            event_ids=["E1"],
            source_ips=[],
            destination_ips=[],
            usernames=[],
            hostnames=[],
            detection_count=1,
            summary="Test",
            correlation_score=0.8,
        )

        timeline = TimelineBuilder.build_for_incident(incident, [e1], detections=[det])
        assert len(timeline) == 1
        assert timeline[0].related_detection_ids == ["DET-R001-01"]


class TestEndToEndCorrelationPipeline:
    """Integration tests executing the complete pipeline on actual synthetic datasets."""

    def test_combined_attack_produces_coherent_incident_and_timeline(self):
        """Verify full pipeline: combined_attack.csv -> parsed -> detected -> correlated -> incident."""
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        parse_res = parse_log_file(filepath)
        assert parse_res.failed_rows == 0

        # Step 1: Detect
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        assert len(detections) > 0

        # Step 2: Correlate
        correlator = EventCorrelator()
        detection_groups = correlator.correlate(detections)
        assert len(detection_groups) >= 1

        # Step 3: Detect Incidents
        detector = IncidentDetector()
        incidents = detector.detect_incidents(detection_groups)
        assert len(incidents) >= 1

        # Main incident inspection
        main_incident = max(incidents, key=lambda inc: inc.detection_count)
        assert main_incident.severity in ["HIGH", "CRITICAL"]
        assert main_incident.status == "OPEN"
        assert main_incident.detection_count >= 3
        assert len(main_incident.event_ids) >= 30

        # Step 4: Build Timeline
        timeline = TimelineBuilder.build_for_incident(
            main_incident, parse_res.events, detections=detections
        )
        assert len(timeline) == len(main_incident.event_ids)

        # Invariant checks on the timeline
        for i in range(len(timeline) - 1):
            assert timeline[i].timestamp <= timeline[i + 1].timestamp

        all_input_eids = {e.event_id for e in parse_res.events}
        for item in timeline:
            assert item.event_id in all_input_eids
            assert item.raw_message != ""

    def test_normal_activity_produces_zero_incidents(self):
        """normal_activity.csv should produce zero incidents and empty timeline."""
        filepath = os.path.join(DATA_DIR, "normal_activity.csv")
        parse_res = parse_log_file(filepath)
        assert parse_res.failed_rows == 0

        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        assert len(detections) == 0

        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        assert len(groups) == 0

        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        assert len(incidents) == 0
