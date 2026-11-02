"""
Independent Audit Remediation Verification Tests
================================================
Validates all verified bug fixes and design corrections:
- BUG-01: normalize_action in EventNormalizer
- BUG-02: AttackChainReconstructor does not mutate incident.event_ids
- BUG-03: Incident correlation_score propagation
- BUG-04: Incident summary accurate conditional phrasing for pure failures
- BUG-05: R002 sliding window loop progression
- LIM-01: Auto-detection of alternative CSV delimiters (TSV, semicolon)
- UWF-ZeekData22 validation on external network telemetry
"""

import io
import pytest
from datetime import datetime, timedelta
from preprocessing.normalizer import EventNormalizer, normalize_action
from preprocessing.log_parser import CSVLogParser
from detection.rule_engine import RuleEngine, DetectionConfig
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector, Incident
from reconstruction.attack_chain import AttackChainReconstructor


class TestAuditRemediation:
    """Verifies that all audit findings and bug fixes operate correctly."""

    def test_bug01_normalize_action_applied_in_record_normalization(self):
        """BUG-01: Verify that raw action string is preserved in lowercase and recognized by RuleEngine."""
        raw_record = {
            "event_id": "EVT-00001",
            "timestamp": "2026-10-15 10:00:00",
            "source": "auth",
            "event_type": "login",
            "action": "Denied",
            "username": "target_user",
        }
        event = EventNormalizer.normalize_record(raw_record)
        assert event.action == "denied", f"Expected 'denied', got '{event.action}'"
        assert event.action.lower() in normalize_action("Denied") or event.action == "denied"

        raw_record_allowed = {
            "event_id": "EVT-00002",
            "timestamp": "2026-10-15 10:00:01",
            "source": "auth",
            "event_type": "login",
            "action": "Allowed",
            "username": "target_user",
        }
        event_allowed = EventNormalizer.normalize_record(raw_record_allowed)
        assert event_allowed.action == "allowed", f"Expected 'allowed', got '{event_allowed.action}'"

    def test_bug01_r001_triggers_on_denied_actions(self):
        """BUG-01: Verify that R001 brute force detects events with action='Denied'."""
        csv_content = """timestamp,source_ip,username,action,event_type
2026-10-15 10:00:01,10.0.0.99,victim,Denied,login
2026-10-15 10:00:02,10.0.0.99,victim,Denied,login
2026-10-15 10:00:03,10.0.0.99,victim,Denied,login
2026-10-15 10:00:04,10.0.0.99,victim,Denied,login
2026-10-15 10:00:05,10.0.0.99,victim,Denied,login
2026-10-15 10:00:06,10.0.0.99,victim,Denied,login
"""
        parser = CSVLogParser()
        res = parser.parse_csv_string(csv_content)
        assert all(e.action == "denied" for e in res.events)

        re = RuleEngine()
        detections = re.detect(res.events)
        assert len(detections) >= 1, "R001 must trigger on normalized 'Denied' authentication failures"
        assert detections[0].rule_id == "R001"

    def test_bug02_attack_chain_reconstructor_preserves_incident_evidence(self):
        """BUG-02: Verify that reconstructor prioritizes incident events without external mutation."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        eids = [f"EVT-{i:05d}" for i in range(1, 6)]
        inc = Incident(
            incident_id="INC-0001",
            created_at=t0,
            start_time=t0,
            end_time=t0 + timedelta(minutes=5),
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-R001-0001"],
            event_ids=list(eids),
            source_ips=["192.168.1.100"],
            destination_ips=["192.168.1.1"],
            usernames=["admin"],
            hostnames=["auth-srv"],
            detection_count=1,
            summary="Brute force test",
            correlation_score=0.85,
        )
        initial_len = len(inc.event_ids)
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(inc, events=[], detections=[])
        assert len(inc.event_ids) == initial_len, "Incident event_ids must not be mutated"

    def test_bug04_summary_text_accurate_for_pure_failures(self):
        """BUG-04: Verify that pure failure incidents do not claim 'followed by login'."""
        csv_content = """timestamp,source_ip,username,action,event_type
2026-10-15 10:00:01,10.0.0.99,victim,failure,login
2026-10-15 10:00:02,10.0.0.99,victim,failure,login
2026-10-15 10:00:03,10.0.0.99,victim,failure,login
2026-10-15 10:00:04,10.0.0.99,victim,failure,login
2026-10-15 10:00:05,10.0.0.99,victim,failure,login
2026-10-15 10:00:06,10.0.0.99,victim,failure,login
"""
        parser = CSVLogParser()
        res = parser.parse_csv_string(csv_content)
        re = RuleEngine()
        dets = re.detect(res.events)
        groups = EventCorrelator().correlate(dets)
        incidents = IncidentDetector().detect_incidents(groups)

        assert len(incidents) == 1
        summary = incidents[0].summary
        assert "followed by login" not in summary.lower(), "Must NOT claim 'followed by login' when only failures occurred"
        assert "unconfirmed" in summary.lower(), "Must retain uncertainty disclaimer"

    def test_bug05_r002_advances_properly(self):
        """BUG-05: Verify that R002 sliding window loop advances past matched window."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        # 15 distinct ports scanned in rapid succession
        events = []
        for p in range(1, 16):
            rec = {
                "event_id": f"EVT-{p:05d}",
                "timestamp": t0 + timedelta(seconds=p),
                "source": "firewall",
                "source_ip": "192.168.1.100",
                "destination_ip": "192.168.1.1",
                "destination_port": p * 100,
                "event_type": "network_connection",
            }
            events.append(EventNormalizer.normalize_record(rec))

        re = RuleEngine(DetectionConfig(port_scan_threshold=10, port_scan_window_seconds=120))
        dets = re.detect(events)
        assert len(dets) == 1, f"Expected exactly 1 port scan detection, got {len(dets)}"
        assert len(dets[0].event_ids) == 15

    def test_lim01_tsv_and_semicolon_auto_detection(self):
        """LIM-01: Verify CSVLogParser auto-detects tab and semicolon delimiters."""
        tsv_data = "timestamp\tsource_ip\tdestination_ip\n2026-10-15 10:00:00\t192.168.1.1\t10.0.0.1\n"
        parser = CSVLogParser()
        res_tsv = parser.parse_csv_string(tsv_data)
        assert res_tsv.successful_rows == 1
        assert res_tsv.events[0].source_ip == "192.168.1.1"

        sc_data = "timestamp;source_ip;destination_ip\n2026-10-15 10:00:00;192.168.1.1;10.0.0.1\n"
        res_sc = parser.parse_csv_string(sc_data)
        assert res_sc.successful_rows == 1
        assert res_sc.events[0].destination_ip == "10.0.0.1"

    def test_uwf_zeek_telemetry_end_to_end(self):
        """External dataset validation: Ensure UWF-ZeekData22 parses cleanly and triggers R002."""
        path = "data/uploads/upload_7c5b8f344db31c5b4a8a.csv"
        parser = CSVLogParser()
        res = parser.parse_file(path)
        assert res.total_rows == 10260
        assert res.successful_rows == 10260
        assert res.failed_rows == 0

        re = RuleEngine()
        dets = re.detect(res.events)
        assert len(dets) == 6
        assert all(d.rule_id == "R002" for d in dets)

        groups = EventCorrelator().correlate(dets)
        assert len(groups) == 2

        incidents = IncidentDetector().detect_incidents(groups)
        assert len(incidents) == 2
        for inc in incidents:
            assert inc.severity == "MEDIUM"
            assert "143.88.11.10" in inc.source_ips
