"""
Unit and Integration Tests for detection/rule_engine.py
======================================================
Tests verify:
    1. Brute-force pattern triggers R001.
    2. Fewer than 5 failures does NOT trigger R001.
    3. Failures outside the configured time window do NOT trigger R001.
    4. Port scan pattern triggers R002.
    5. Fewer than 10 distinct ports does NOT trigger R002.
    6. Port contacts spread beyond the time window do NOT trigger R002.
    7. Suspicious 10.0.0.x login triggers R003.
    8. Normal 192.168.1.x login does not trigger R003.
    9. Privilege escalation indicator triggers R004.
    10. Sensitive shadow/passwd/credential access triggers R005.
    11. Case-insensitive sensitive-file matching works.
    12. R006 does not fabricate detections when transfer size is unavailable.
    13. Every detection contains valid event_ids.
    14. Detection event_ids correspond to actual input events.
    15. Detection IDs are unique.
    16. Rule IDs are correct.
    17. Severity values are valid (LOW, MEDIUM, HIGH, CRITICAL).
    18. Confidence values are between 0 and 1.
    19. Empty event list returns no detections.
    20. Normal activity dataset produces no unexpected high-confidence detections.
"""

from datetime import datetime, timedelta
import os
import pytest

from preprocessing.event_schema import NormalizedEvent
from preprocessing.log_parser import parse_log_file
from detection.rule_engine import (
    RuleEngine,
    Detection,
    DetectionConfig,
    SEVERITY_LEVELS,
    apply_rules,
)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))


def make_test_event(
    event_id: str = "EVT-01",
    timestamp: datetime = datetime(2026, 10, 15, 10, 0, 0),
    source: str = "auth.log",
    event_type: str = "login_failed",
    source_ip: str = "192.168.1.100",
    destination_ip: str = "192.168.1.20",
    source_port: int = 50000,
    destination_port: int = 22,
    username: str = "admin",
    hostname: str = "srv-01",
    process: str = "sshd",
    action: str = "failure",
    severity: str = "low",
    raw_message: str = "Failed login attempt",
) -> NormalizedEvent:
    """Helper to generate a NormalizedEvent with defaults."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        username=username,
        hostname=hostname,
        process=process,
        action=action,
        severity=severity,
        raw_message=raw_message,
    )


class TestRuleEngineRules:
    """Unit tests for individual detection rules."""

    def test_empty_event_list_returns_no_detections(self):
        engine = RuleEngine()
        assert engine.detect([]) == []

    # -------------------------------------------------------------------------
    # R001: Brute Force Tests
    # -------------------------------------------------------------------------

    def test_brute_force_pattern_triggers_r001(self):
        """5 failed logins within 5 minutes triggers R001."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 10, 0, 0)
        events = [
            make_test_event(
                event_id=f"BF-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.105",
                action="failure",
            )
            for i in range(5)
        ]

        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]

        assert len(r001_dets) == 1
        det = r001_dets[0]
        assert det.severity == "HIGH"
        assert det.source_ip == "192.168.1.105"
        assert det.confidence >= 0.80
        assert len(det.event_ids) == 5
        assert set(det.event_ids) == {f"BF-{i}" for i in range(5)}

    def test_fewer_than_threshold_failures_does_not_trigger_r001(self):
        """4 failed logins (threshold=5) must NOT trigger R001."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 10, 0, 0)
        events = [
            make_test_event(
                event_id=f"BF-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.105",
                action="failure",
            )
            for i in range(4)
        ]

        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]
        assert len(r001_dets) == 0

    def test_failures_outside_window_do_not_trigger_r001(self):
        """5 failed logins spaced 10 minutes apart (exceeding 300s window) do NOT trigger R001."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 10, 0, 0)
        events = [
            make_test_event(
                event_id=f"BF-{i}",
                timestamp=base_time + timedelta(seconds=i * 600),  # 10 min intervals
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.105",
                action="failure",
            )
            for i in range(5)
        ]

        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]
        assert len(r001_dets) == 0

    # -------------------------------------------------------------------------
    # R002: Port Scan Tests
    # -------------------------------------------------------------------------

    def test_port_scan_pattern_triggers_r002(self):
        """10 distinct destination ports probed within 120s triggers R002."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 11, 0, 0)
        events = [
            make_test_event(
                event_id=f"PS-{i}",
                timestamp=base_time + timedelta(seconds=i * 5),
                source="firewall",
                event_type="port_scan_probe",
                source_ip="192.168.1.50",
                destination_ip="192.168.1.10",
                destination_port=1000 + i,
                action="blocked",
            )
            for i in range(10)
        ]

        detections = engine.detect(events)
        r002_dets = [d for d in detections if d.rule_id == "R002"]

        assert len(r002_dets) == 1
        det = r002_dets[0]
        assert det.severity == "MEDIUM"
        assert det.source_ip == "192.168.1.50"
        assert det.destination_ip == "192.168.1.10"
        assert det.confidence >= 0.80
        assert len(det.event_ids) == 10

    def test_fewer_than_threshold_ports_does_not_trigger_r002(self):
        """9 distinct destination ports (threshold=10) must NOT trigger R002."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 11, 0, 0)
        events = [
            make_test_event(
                event_id=f"PS-{i}",
                timestamp=base_time + timedelta(seconds=i * 5),
                source="firewall",
                event_type="port_scan_probe",
                source_ip="192.168.1.50",
                destination_ip="192.168.1.10",
                destination_port=1000 + i,
                action="blocked",
            )
            for i in range(9)
        ]

        detections = engine.detect(events)
        r002_dets = [d for d in detections if d.rule_id == "R002"]
        assert len(r002_dets) == 0

    def test_port_contacts_spread_beyond_window_do_not_trigger_r002(self):
        """10 distinct destination ports spread over 30 minutes (exceeding 120s) must NOT trigger R002."""
        engine = RuleEngine()
        base_time = datetime(2026, 10, 15, 11, 0, 0)
        events = [
            make_test_event(
                event_id=f"PS-{i}",
                timestamp=base_time + timedelta(seconds=i * 200),  # 200s intervals
                source="firewall",
                event_type="network_flow",
                source_ip="192.168.1.50",
                destination_ip="192.168.1.10",
                destination_port=1000 + i,
                action="allowed",
            )
            for i in range(10)
        ]

        detections = engine.detect(events)
        r002_dets = [d for d in detections if d.rule_id == "R002"]
        assert len(r002_dets) == 0

    # -------------------------------------------------------------------------
    # R003: Suspicious Login Tests
    # -------------------------------------------------------------------------

    def test_suspicious_10_0_0_x_login_triggers_r003(self):
        """Successful login from 10.0.0.x triggers R003."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="CL-01",
            source="auth.log",
            event_type="login_success",
            source_ip="10.0.0.120",
            username="mrodriguez",
            action="success",
        )
        detections = engine.detect([event])
        r003_dets = [d for d in detections if d.rule_id == "R003"]

        assert len(r003_dets) == 1
        det = r003_dets[0]
        assert det.severity == "MEDIUM"
        assert det.source_ip == "10.0.0.120"
        assert det.username == "mrodriguez"
        assert det.event_ids == ["CL-01"]

    def test_normal_192_168_1_x_login_does_not_trigger_r003(self):
        """Successful login from normal 192.168.1.x subnet does NOT trigger R003."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="NORM-01",
            source="auth.log",
            event_type="login_success",
            source_ip="192.168.1.45",
            username="mrodriguez",
            action="success",
        )
        detections = engine.detect([event])
        r003_dets = [d for d in detections if d.rule_id == "R003"]
        assert len(r003_dets) == 0

    # -------------------------------------------------------------------------
    # R004: Privilege Escalation Tests
    # -------------------------------------------------------------------------

    def test_privilege_escalation_indicator_triggers_r004(self):
        """Privilege escalation transition triggers R004."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="PE-01",
            source="audit.log",
            event_type="privilege_change",
            username="root",
            process="sh",
            action="elevated",
            raw_message="Privilege change: uid changed to 0(root)",
        )
        detections = engine.detect([event])
        r004_dets = [d for d in detections if d.rule_id == "R004"]

        assert len(r004_dets) == 1
        det = r004_dets[0]
        assert det.severity == "HIGH"
        assert "Privilege Escalation" in det.title
        assert det.event_ids == ["PE-01"]

    # -------------------------------------------------------------------------
    # R005: Sensitive File Access Tests
    # -------------------------------------------------------------------------

    def test_sensitive_shadow_passwd_credential_access_triggers_r005(self):
        """Accessing shadow or confidential file triggers R005."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="FA-01",
            source="audit.log",
            event_type="file_read",
            username="root",
            raw_message="cat /etc/shadow read by root",
        )
        detections = engine.detect([event])
        r005_dets = [d for d in detections if d.rule_id == "R005"]

        assert len(r005_dets) == 1
        assert r005_dets[0].severity == "HIGH"
        assert r005_dets[0].event_ids == ["FA-01"]

    def test_case_insensitive_sensitive_file_matching(self):
        """Case variations like 'CONFIDENTIAL' or 'Passwd' trigger R005."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="FA-02",
            source="file_audit",
            event_type="file_access",
            raw_message="Access granted to restricted share /CONFIDENTIAL/financial.xlsx",
        )
        detections = engine.detect([event])
        r005_dets = [d for d in detections if d.rule_id == "R005"]
        assert len(r005_dets) == 1

    # -------------------------------------------------------------------------
    # R006: Large Outbound Transfer Tests
    # -------------------------------------------------------------------------

    def test_r006_large_outbound_transfer_with_bytes(self):
        """High volume transfer (>100MB) triggers R006."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="DX-01",
            source="firewall",
            event_type="network_flow",
            source_ip="192.168.1.70",
            destination_ip="10.0.0.95",
            raw_message="FIREWALL PASS: High volume outbound stream proto=TCP bytes=150000000 dst=10.0.0.95:8443",
        )
        detections = engine.detect([event])
        r006_dets = [d for d in detections if d.rule_id == "R006"]

        assert len(r006_dets) == 1
        assert r006_dets[0].severity == "HIGH"
        assert r006_dets[0].event_ids == ["DX-01"]

    def test_r006_does_not_fabricate_detections_when_bytes_unavailable_or_small(self):
        """Normal byte counts (<100MB) do NOT trigger R006."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="DX-02",
            source="firewall",
            event_type="network_flow",
            raw_message="FIREWALL PASS: proto=TCP bytes=1240 dst=192.168.1.10:443",
        )
        detections = engine.detect([event])
        r006_dets = [d for d in detections if d.rule_id == "R006"]
        assert len(r006_dets) == 0


class TestDetectionInvariantsAndQuality:
    """Verify detection invariants: IDs, severities, confidence, event mapping."""

    def test_detection_invariants(self):
        """Check all fields of a produced Detection object."""
        engine = RuleEngine()
        event = make_test_event(
            event_id="TEST-EVID-99",
            source="auth.log",
            event_type="login_success",
            source_ip="10.0.0.5",
            action="success",
        )
        detections = engine.detect([event])
        assert len(detections) > 0

        det = detections[0]
        # Invariant checks
        assert det.detection_id.startswith("DET-")
        assert det.rule_id in ["R001", "R002", "R003", "R004", "R005", "R006"]
        assert det.severity in SEVERITY_LEVELS
        assert 0.0 <= det.confidence <= 1.0
        assert det.confidence < 1.0  # Never claims 1.0 certainty
        assert "TEST-EVID-99" in det.event_ids
        assert len(det.evidence) == 1
        assert det.evidence[0]["event_id"] == "TEST-EVID-99"

        # Serialization check
        d_dict = det.to_dict()
        assert d_dict["detection_id"] == det.detection_id
        assert d_dict["confidence"] == det.confidence

    def test_detection_ids_are_unique(self):
        """Every generated detection ID must be strictly unique."""
        engine = RuleEngine()
        events = [
            make_test_event(event_id=f"ID-{i}", source_ip=f"10.0.0.{i}", action="success")
            for i in range(1, 10)
        ]
        detections = engine.detect(events)
        ids = [d.detection_id for d in detections]
        assert len(ids) == len(set(ids)), "Duplicate detection IDs found"


class TestSyntheticDatasetDetections:
    """Integration test: evaluate rule engine across sample datasets."""

    def test_normal_activity_produces_no_detections(self):
        """normal_activity.csv is benign baseline: must produce 0 detections."""
        filepath = os.path.join(DATA_DIR, "normal_activity.csv")
        parse_res = parse_log_file(filepath)
        assert parse_res.failed_rows == 0

        engine = RuleEngine()
        detections = engine.detect(parse_res.events)

        # False positive test: zero detections expected on benign baseline
        assert len(detections) == 0, (
            f"Unexpected detections on normal_activity.csv: {[d.title for d in detections]}"
        )

    def test_combined_attack_produces_multi_stage_detections(self):
        """combined_attack.csv must trigger multiple rules across its attack stages."""
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        parse_res = parse_log_file(filepath)
        assert parse_res.failed_rows == 0

        engine = RuleEngine()
        detections = engine.detect(parse_res.events)

        assert len(detections) > 0

        rule_ids = {d.rule_id for d in detections}
        # Combined attack has brute force (R001), privilege escalation (R004),
        # sensitive file access (R005), and large outbound transfer (R006)
        assert "R001" in rule_ids, "Expected R001 Brute Force detection"
        assert "R004" in rule_ids, "Expected R004 Privilege Escalation detection"
        assert "R005" in rule_ids, "Expected R005 Sensitive File Access detection"
        assert "R006" in rule_ids, "Expected R006 Large Outbound Transfer detection"

        # Verify all evidence event IDs map to actual input events
        all_input_eids = {e.event_id for e in parse_res.events}
        for det in detections:
            for eid in det.event_ids:
                assert eid in all_input_eids, f"Evidence event_id {eid} not in input events"
