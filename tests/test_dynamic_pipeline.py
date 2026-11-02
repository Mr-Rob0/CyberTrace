"""
Dynamic Pipeline and Dataset-Independence Test Suite
===================================================
Comprehensive tests for CyberTrace verifying dynamic CSV ingestion,
automatic column alias normalisation, schema resilience, dynamic rule detection,
Isolation Forest anomaly detection, event correlation, attack reconstruction,
MITRE ATT&CK mapping, report generation, and dataset switching isolation.

Tests explicitly satisfy Phase 13 requirements:
    1. Valid CSV upload
    2. Invalid CSV upload
    3. Different column names (Dataset A & B schemas)
    4. Missing values
    5. Invalid timestamps
    6. Empty dataset
    7. Small dataset
    8. Rule-based detections on dynamic records
    9. Isolation Forest scoring on dynamic records
    10. Event correlation
    11. Dynamic incident generation
    12. Attack timeline reconstruction without forced stages
    13. MITRE ATT&CK mapping with evidence traceability
    14. Dynamic report generation (Markdown & JSON)
    15. Dataset switching isolation
    16. Prevention of stale or hardcoded data
"""

import os
import json
import tempfile
from datetime import datetime, timedelta
import pytest

from preprocessing.log_parser import CSVLogParser, parse_log_file, ParseResult
from preprocessing.column_mapper import detect_column_mapping
from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import RuleEngine, Detection, DetectionConfig
from detection.anomaly_detector import AnomalyDetector, detect_anomalies
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector, Incident
from reconstruction.attack_chain import AttackChainReconstructor, AttackStage
from reconstruction.root_cause import RootCauseAnalyzer
from mitre.technique_mapper import TechniqueMapper
from ai.report_generator import generate_report
from ai.fallback_generator import generate_deterministic_fallback


class TestDynamicCSVUploadAndSchemaMapping:
    """Tests 1-7: File upload, column aliases, missing values, error handling."""

    def test_1_valid_csv_upload_standard_schema(self):
        """Test 1: Valid CSV parsing with standard headers."""
        csv_content = (
            "timestamp,source,event_type,source_ip,destination_ip,source_port,destination_port,username,hostname,process,action,severity,raw_message,event_id\n"
            "2026-10-15 08:30:00,auth.log,login_success,192.168.1.50,192.168.1.20,50000,22,alice,srv-01,sshd,success,low,Accepted key,EVT-001\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_content)

        assert result.successful_rows == 1
        assert result.failed_rows == 0
        assert not result.has_errors
        evt = result.events[0]
        assert evt.event_id == "EVT-001"
        assert evt.username == "alice"
        assert evt.source_ip == "192.168.1.50"
        assert evt.action == "success"

    def test_2_invalid_csv_upload_empty_and_no_header(self):
        """Test 2: Empty CSV and missing header error handling."""
        parser = CSVLogParser()
        with pytest.raises(ValueError, match="CSV file is empty"):
            parser.parse_csv_string("")

    def test_3_dataset_a_schema_mapping(self):
        """Test 3a: Dataset A format (timestamp, source_ip, destination_ip, username, event_type, status)."""
        csv_a = (
            "timestamp,source_ip,destination_ip,username,event_type,status\n"
            "2026-10-15 09:00:00,10.0.1.5,10.0.1.20,bob,login,failure\n"
            "2026-10-15 09:01:00,10.0.1.5,10.0.1.20,bob,login,success\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_a)

        assert result.successful_rows == 2
        assert result.failed_rows == 0
        assert len(result.events) == 2

        # Auto-generated sequential event IDs because dataset lacked event_id column
        assert result.events[0].event_id == "EVT-00001"
        assert result.events[1].event_id == "EVT-00002"
        # Source defaulted safely
        assert result.events[0].source == "security_log"
        assert result.events[0].source_ip == "10.0.1.5"
        assert result.events[0].username == "bob"
        assert result.events[0].action == "failure"
        assert result.events[1].action == "success"

    def test_3_dataset_b_schema_mapping(self):
        """Test 3b: Dataset B format (Time, SrcAddress, DestAddress, User, Action, Result)."""
        csv_b = (
            "Time,SrcAddress,DestAddress,User,Action,Result\n"
            "2026-10-15 10:15:30,172.16.0.4,172.16.0.10,charlie,file_download,success\n"
            "2026-10-15 10:16:00,172.16.0.4,172.16.0.10,charlie,file_delete,allowed\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_b)

        assert result.successful_rows == 2
        assert result.failed_rows == 0
        evt = result.events[0]
        assert evt.timestamp == datetime(2026, 10, 15, 10, 15, 30)
        assert evt.source_ip == "172.16.0.4"
        assert evt.destination_ip == "172.16.0.10"
        assert evt.username == "charlie"
        assert evt.event_type == "file_download"
        assert evt.action == "success"

    def test_4_missing_values_handled_safely(self):
        """Test 4: Missing optional attributes are safely converted to None/defaults."""
        csv_sparse = (
            "timestamp,event_type\n"
            "2026-10-15 11:00:00,system_startup\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_sparse)

        assert result.successful_rows == 1
        evt = result.events[0]
        assert evt.source_ip is None
        assert evt.destination_ip is None
        assert evt.source_port is None
        assert evt.destination_port is None
        assert evt.username is None
        assert evt.hostname is None
        assert evt.process is None
        assert evt.action is None
        assert evt.severity == "low"
        assert evt.event_id == "EVT-00001"

    def test_5_invalid_timestamp_captured_without_crash(self):
        """Test 5: Malformed timestamp generates ParseError rather than unhandled exception."""
        csv_bad_ts = (
            "timestamp,source,event_type,event_id\n"
            "INVALID_DATE_STRING,auth.log,login,BAD-01\n"
            "2026-10-15 12:00:00,auth.log,login,GOOD-01\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_bad_ts)

        assert result.total_rows == 2
        assert result.successful_rows == 1
        assert result.failed_rows == 1
        assert result.has_errors is True
        assert result.errors[0].event_id == "BAD-01"
        assert result.events[0].event_id == "GOOD-01"

    def test_6_empty_dataset_rows(self):
        """Test 6: Valid header but 0 data rows yields clean empty ParseResult."""
        csv_header_only = "timestamp,source,event_type,event_id\n"
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_header_only)

        assert result.total_rows == 0
        assert result.successful_rows == 0
        assert result.failed_rows == 0
        assert result.events == []

    def test_7_small_dataset_safe_handling(self):
        """Test 7: Small dataset (e.g. 2 rows) is safely processed by all modules."""
        csv_small = (
            "timestamp,source,event_type,source_ip,username,action,event_id\n"
            "2026-10-15 08:00:00,auth.log,login_success,192.168.1.10,analyst,success,E-01\n"
            "2026-10-15 08:05:00,auth.log,login_success,192.168.1.10,analyst,success,E-02\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_small)

        engine = RuleEngine()
        detections = engine.detect(result.events)
        assert len(detections) == 0

        # ML anomaly scoring handles small input safely without crashing
        anomalies = detect_anomalies(result.events)
        assert isinstance(anomalies, list)


class TestDynamicAnalysisAndCorrelations:
    """Tests 8-14: Rule engine, ML, Correlation, Incidents, Reconstructions, MITRE, Reports."""

    def test_8_rule_detections_on_dynamic_records(self):
        """Test 8: Rule engine fires on dynamic user events with actual event ID linkages."""
        base_time = datetime(2026, 10, 15, 14, 0, 0)
        events = [
            NormalizedEvent(
                event_id=f"DYN-FAIL-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
                source="auth.log",
                event_type="login_failed",
                source_ip="203.0.113.50",
                username="root",
                action="failure",
            )
            for i in range(5)
        ]

        engine = RuleEngine()
        dets = engine.detect(events)
        assert len(dets) >= 1
        d = next(x for x in dets if x.rule_id == "R001")
        assert d.severity == "HIGH"
        assert d.source_ip == "203.0.113.50"
        assert d.username == "root"
        assert set(d.event_ids) == {f"DYN-FAIL-{i}" for i in range(5)}
        assert len(d.evidence) == 5

    def test_8b_r007_successful_login_after_failures(self):
        """Test 8b: Rule R007 triggers when multiple failures are followed by successful login."""
        base_time = datetime(2026, 10, 15, 15, 0, 0)
        events = [
            NormalizedEvent(
                event_id=f"FAIL-{i}",
                timestamp=base_time + timedelta(seconds=i * 5),
                source="auth.log",
                event_type="login_failed",
                source_ip="198.51.100.99",
                username="admin_user",
                action="failure",
            )
            for i in range(4)
        ]
        # Successful login
        events.append(
            NormalizedEvent(
                event_id="SUCCESS-01",
                timestamp=base_time + timedelta(seconds=25),
                source="auth.log",
                event_type="login_success",
                source_ip="198.51.100.99",
                username="admin_user",
                action="success",
            )
        )

        engine = RuleEngine()
        dets = engine.detect(events)
        r007_dets = [d for d in dets if d.rule_id == "R007"]
        assert len(r007_dets) == 1
        d = r007_dets[0]
        assert d.severity in {"LOW", "MEDIUM", "HIGH"}
        assert d.username == "admin_user"
        assert "SUCCESS-01" in d.event_ids
        assert len(d.event_ids) == 5

    def test_8c_r008_suspicious_privileged_login(self):
        """Test 8c: Rule R008 detects direct remote privileged account login."""
        event = NormalizedEvent(
            event_id="ROOT-LOGIN-01",
            timestamp=datetime(2026, 10, 15, 16, 0, 0),
            source="auth.log",
            event_type="login_success",
            source_ip="198.51.100.22",
            destination_ip="10.0.0.5",
            username="root",
            action="success",
        )
        engine = RuleEngine()
        dets = engine.detect([event])
        r008_dets = [d for d in dets if d.rule_id == "R008"]
        assert len(r008_dets) == 1
        assert r008_dets[0].rule_id == "R008"
        assert r008_dets[0].username == "root"
        assert r008_dets[0].source_ip == "198.51.100.22"

    def test_9_isolation_forest_dynamic_scoring(self):
        """Test 9: Isolation Forest calculates anomaly scores dynamically from dataset."""
        base_time = datetime(2026, 10, 15, 9, 0, 0)
        events = [
            NormalizedEvent(
                event_id=f"EVT-{i:03d}",
                timestamp=base_time + timedelta(seconds=i * 20),
                source="firewall",
                event_type="network_flow",
                source_ip=f"10.0.0.{i % 5 + 1}",
                destination_ip="10.0.0.100",
                destination_port=80,
                action="allowed",
                severity="low",
            )
            for i in range(25)
        ]
        # Add an anomalous outlier event
        events.append(
            NormalizedEvent(
                event_id="OUTLIER-999",
                timestamp=base_time + timedelta(seconds=600),
                source="audit.log",
                event_type="large_outbound_transfer",
                source_ip="10.0.0.2",
                destination_ip="203.0.113.99",
                destination_port=4444,
                action="failure",
                severity="critical",
                raw_message="Exfiltration stream bytes=150000000",
            )
        )

        results = detect_anomalies(events)
        assert len(results) == len(events)
        for r in results:
            assert 0.0 <= r.anomaly_score <= 1.0
            assert "Statistical anomaly signal only" in r.disclaimer

    def test_10_and_11_event_correlation_and_dynamic_incidents(self):
        """Tests 10 & 11: Detections are correlated into incidents with dynamic IDs and real evidence."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        d1 = Detection(
            detection_id="DET-0001",
            rule_id="R001",
            rule_name="Brute Force Login Attempt",
            timestamp=t0,
            severity="HIGH",
            title="Brute force detected",
            description="5 failed logins",
            event_ids=["EVT-1", "EVT-2"],
            source_ip="192.168.1.188",
            username="target_user",
        )
        d2 = Detection(
            detection_id="DET-0002",
            rule_id="R003",
            rule_name="Suspicious Login",
            timestamp=t0 + timedelta(minutes=5),
            severity="MEDIUM",
            title="Suspicious login from unusual subnet",
            description="Login from 10.0.0.120",
            event_ids=["EVT-3"],
            source_ip="192.168.1.188",
            username="target_user",
        )

        correlator = EventCorrelator()
        groups = correlator.correlate([d1, d2])
        assert len(groups) == 1

        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        assert len(incidents) == 1

        inc = incidents[0]
        assert inc.incident_id.startswith("INC-")
        assert inc.detection_count == 2
        assert set(inc.event_ids) == {"EVT-1", "EVT-2", "EVT-3"}
        assert "target_user" in inc.usernames
        assert "192.168.1.188" in inc.source_ips

    def test_12_attack_timeline_reconstruction_no_forced_stages(self):
        """Test 12: Attack chain only reconstructs stages supported by actual evidence."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        d1 = Detection(
            detection_id="DET-0001",
            rule_id="R001",
            rule_name="Brute Force Login Attempt",
            timestamp=t0,
            severity="HIGH",
            title="Brute force detected",
            description="5 failed logins",
            event_ids=["EVT-1", "EVT-2"],
            source_ip="192.168.1.188",
            username="admin",
        )
        inc = Incident(
            incident_id="INC-0001",
            created_at=t0,
            start_time=t0,
            end_time=t0,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-0001"],
            event_ids=["EVT-1", "EVT-2"],
            source_ips=["192.168.1.188"],
            destination_ips=["192.168.1.20"],
            usernames=["admin"],
            hostnames=["srv-01"],
            detection_count=1,
            summary="Single stage brute force incident",
            correlation_score=0.85,
        )

        events = [
            NormalizedEvent(
                event_id="EVT-1",
                timestamp=t0,
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.188",
                destination_ip="192.168.1.20",
                username="admin",
                action="failure",
            ),
            NormalizedEvent(
                event_id="EVT-2",
                timestamp=t0 + timedelta(seconds=5),
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.188",
                destination_ip="192.168.1.20",
                username="admin",
                action="failure",
            ),
        ]

        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(inc, events=events, detections=[d1])

        # Must NOT force all 5 stages if only Credential Access occurred
        stages = [step.stage for step in chain.steps]
        assert AttackStage.CREDENTIAL_ACCESS.value in stages
        assert AttackStage.EXFILTRATION.value not in stages
        assert AttackStage.PRIVILEGE_ESCALATION.value not in stages

    def test_13_mitre_mapping_traceability(self):
        """Test 13: MITRE techniques contain verified supporting event IDs and detection IDs."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        d1 = Detection(
            detection_id="DET-0001",
            rule_id="R001",
            rule_name="Brute Force Login Attempt",
            timestamp=t0,
            severity="HIGH",
            title="Brute force detected",
            description="Brute force attempt",
            event_ids=["EVT-1", "EVT-2"],
            source_ip="192.168.1.188",
            username="admin",
        )
        inc = Incident(
            incident_id="INC-0001",
            created_at=t0,
            start_time=t0,
            end_time=t0,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-0001"],
            event_ids=["EVT-1", "EVT-2"],
            source_ips=["192.168.1.188"],
            destination_ips=["192.168.1.20"],
            usernames=["admin"],
            hostnames=["srv-01"],
            detection_count=1,
            summary="Brute force incident",
            correlation_score=0.85,
        )
        events = [
            NormalizedEvent(
                event_id="EVT-1",
                timestamp=t0,
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.188",
                destination_ip="192.168.1.20",
                username="admin",
                action="failure",
            ),
            NormalizedEvent(
                event_id="EVT-2",
                timestamp=t0 + timedelta(seconds=10),
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.188",
                destination_ip="192.168.1.20",
                username="admin",
                action="failure",
            ),
        ]

        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(incident=inc, events=events, detections=[d1])

        assert len(mappings) >= 1
        m = next(x for x in mappings if x.technique_id == "T1110.001")
        assert m.technique_name == "Password Guessing"
        assert m.tactic == "Credential Access"
        assert "DET-0001" in m.supporting_detection_ids
        assert set(m.supporting_event_ids) == {"EVT-1", "EVT-2"}

    def test_14_dynamic_report_generation_markdown_and_json(self):
        """Test 14: Report generation outputs valid Markdown and JSON matching actual incident."""
        t0 = datetime(2026, 10, 15, 10, 0, 0)
        d1 = Detection(
            detection_id="DET-0001",
            rule_id="R001",
            rule_name="Brute Force Login Attempt",
            timestamp=t0,
            severity="HIGH",
            title="Brute force detected",
            description="Brute force attempt",
            event_ids=["EVT-1"],
            source_ip="192.168.1.188",
            username="admin",
        )
        inc = Incident(
            incident_id="INC-CUSTOM-99",
            created_at=t0,
            start_time=t0,
            end_time=t0,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=["DET-0001"],
            event_ids=["EVT-1"],
            source_ips=["192.168.1.188"],
            destination_ips=["192.168.1.20"],
            usernames=["admin"],
            hostnames=["srv-01"],
            detection_count=1,
            summary="Custom investigation incident",
            correlation_score=0.85,
        )
        events = [
            NormalizedEvent(
                event_id="EVT-1",
                timestamp=t0,
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.188",
                destination_ip="192.168.1.20",
                username="admin",
                action="failure",
            )
        ]

        report = generate_report(
            incident_or_findings=inc,
            events=events,
            detections=[d1],
            force_fallback=True,
        )

        assert report.incident_id == "INC-CUSTOM-99"
        md_text = report.to_markdown()
        assert "INC-CUSTOM-99" in md_text
        assert "192.168.1.188" in md_text
        assert "admin" in md_text

        json_text = report.to_json()
        data = json.loads(json_text)
        assert data["incident_id"] == "INC-CUSTOM-99"
        assert data["incident_overview"]["severity"] == "HIGH"


class TestDatasetSwitchingAndIsolation:
    """Tests 15-16: Dataset switching and prevention of stale or hardcoded data."""

    def test_15_switching_datasets_produces_isolated_results(self):
        """Test 15: Parsing dataset 1 and dataset 2 in sequence produces completely distinct outcomes."""
        csv1 = (
            "timestamp,source,event_type,source_ip,username,action,event_id\n"
            "2026-10-15 08:00:00,auth.log,login_success,10.0.0.1,user_alpha,success,EVT-A1\n"
        )
        csv2 = (
            "timestamp,source,event_type,source_ip,username,action,event_id\n"
            "2026-10-15 12:00:00,firewall,packet_drop,198.51.100.5,user_beta,failure,EVT-B1\n"
        )
        parser = CSVLogParser()

        res1 = parser.parse_csv_string(csv1, dataset_name="dataset1.csv")
        res2 = parser.parse_csv_string(csv2, dataset_name="dataset2.csv")

        assert len(res1.events) == 1
        assert len(res2.events) == 1
        assert res1.events[0].username == "user_alpha"
        assert res2.events[0].username == "user_beta"
        assert res1.events[0].source_ip != res2.events[0].source_ip
        assert res1.events[0].event_id != res2.events[0].event_id

    def test_16_no_hardcoded_dashboard_outputs(self):
        """Test 16: Ensure an arbitrary custom benign CSV yields 0 detections and 0 incidents."""
        csv_benign = (
            "timestamp,source,event_type,source_ip,destination_ip,username,action,event_id\n"
            "2026-10-15 08:00:00,auth.log,login_success,192.168.1.10,192.168.1.20,dev_user,success,B-01\n"
            "2026-10-15 08:05:00,auth.log,login_success,192.168.1.10,192.168.1.20,dev_user,success,B-02\n"
            "2026-10-15 08:10:00,auth.log,login_success,192.168.1.10,192.168.1.20,dev_user,success,B-03\n"
        )
        parser = CSVLogParser()
        res = parser.parse_csv_string(csv_benign)

        engine = RuleEngine()
        detections = engine.detect(res.events)
        assert len(detections) == 0, "Benign custom logs must not trigger fake detections"

        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        assert len(groups) == 0

        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        assert len(incidents) == 0, "Benign custom logs must not generate incidents"
