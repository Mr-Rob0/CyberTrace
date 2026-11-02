"""
Unit and Integration Tests for Improved Authentication Brute-Force & Spray Detection
=====================================================================================
Tests verify:
    1. Legitimate sporadic failed logins (1-2 attempts, low rate) produce NO alerts.
    2. Rapid repeated failures trigger R001 with burst evidence and accurate severity.
    3. Distributed / time-spread failures with large idle gaps do not cause false positives.
    4. Multiple accounts targeted from a single IP trigger Password Spray detection (R001 / T1110.003).
    5. Successful login after failures (R007) is treated as an elevated risk indicator,
       NOT conclusive proof of account compromise.
    6. Application settings (DetectionConfig) dynamically configure thresholds.
    7. No hallucination of device, host, or geographic data when fields are absent.
    8. Complete preservation of event IDs and evidence records across all detections.
"""

from datetime import datetime, timedelta
import pytest

from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import (
    RuleEngine,
    Detection,
    DetectionConfig,
    SEVERITY_LEVELS,
    apply_rules,
)
from mitre.technique_mapper import TechniqueMapper
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector


def make_auth_event(
    event_id: str,
    timestamp: datetime,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "192.168.1.20",
    username: str = "alice",
    hostname: str = "srv-app-01",
    action: str = "failure",
    event_type: str = "login_failed",
    raw_message: str = "Authentication failure for user",
) -> NormalizedEvent:
    """Helper to generate an authentication NormalizedEvent."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="auth.log",
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=49152,
        destination_port=22,
        username=username,
        hostname=hostname,
        process="sshd",
        action=action,
        severity="low" if action == "success" else "medium",
        raw_message=raw_message,
    )


class TestLegitimateAndLowRateLogins:
    """Verify benign authentication failure patterns do not trigger false alerts."""

    def test_single_or_double_failed_login_produces_no_alert(self):
        """User mistyping password 1-2 times must produce zero detections."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        events = [
            make_auth_event("TYPO-01", base_time, username="charlie"),
            make_auth_event("TYPO-02", base_time + timedelta(seconds=45), username="charlie"),
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        assert len(detections) == 0

    def test_three_isolated_failures_below_threshold_produce_no_alert(self):
        """3 failed logins (threshold=5) for a single user must NOT trigger R001."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        events = [
            make_auth_event(f"FAIL-{i}", base_time + timedelta(seconds=i * 60), username="david")
            for i in range(3)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        assert len(detections) == 0

    def test_spread_out_failures_with_large_idle_gaps_do_not_cluster(self):
        """Failures separated by gaps larger than max_gap_seconds (default 180s) must not form a burst."""
        base_time = datetime(2026, 10, 20, 8, 0, 0)
        # 5 failures each separated by 200 seconds (total span > 800s, each gap > 180s)
        events = [
            make_auth_event(f"GAP-FAIL-{i}", base_time + timedelta(seconds=i * 200), username="user1")
            for i in range(5)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]
        assert len(r001_dets) == 0

    def test_burst_rate_filter_suppresses_low_velocity_failures(self):
        """When configured with min burst rate, slow attempts are filtered out."""
        # Config requires at least 2.0 attempts/min
        config = DetectionConfig(brute_force_threshold=5, brute_force_burst_min_rate_per_minute=2.0)
        engine = RuleEngine(config=config)
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        # 5 attempts over 240 seconds -> rate = 5 / 4 min = 1.25 attempts/min (< 2.0)
        events = [
            make_auth_event(f"SLOW-{i}", base_time + timedelta(seconds=i * 60), username="admin")
            for i in range(5)
        ]
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]
        assert len(r001_dets) == 0


class TestRapidRepeatedFailures:
    """Verify concentrated, high-velocity authentication bursts are reliably detected."""

    def test_rapid_burst_triggers_r001_with_evidence_and_burst_metrics(self):
        """6 failed logins in 15 seconds must trigger R001 with high burst rate in metadata."""
        base_time = datetime(2026, 10, 20, 10, 15, 0)
        events = [
            make_auth_event(
                f"BURST-{i}",
                base_time + timedelta(seconds=i * 3),
                source_ip="198.51.100.80",
                destination_ip="10.0.0.5",
                username="root",
                hostname="srv-auth-master",
            )
            for i in range(6)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]

        assert len(r001_dets) == 1
        det = r001_dets[0]
        assert det.severity == "HIGH"
        assert det.source_ip == "198.51.100.80"
        assert det.destination_ip == "10.0.0.5"
        assert det.username == "root"
        assert det.hostname == "srv-auth-master"
        assert len(det.event_ids) == 6
        assert set(det.event_ids) == {f"BURST-{i}" for i in range(6)}

        # Metadata verification
        assert det.metadata["failure_count"] == 6
        assert det.metadata["burst_rate_per_minute"] >= 20.0
        assert det.metadata["distinct_user_count"] == 1
        assert det.metadata["attack_pattern"] == "targeted_brute_force"
        assert "velocity" in det.description.lower() or "burst" in det.description.lower()

    def test_massive_high_volume_burst_triggers_critical_severity(self):
        """22 rapid failures trigger CRITICAL severity."""
        base_time = datetime(2026, 10, 20, 11, 0, 0)
        events = [
            make_auth_event(
                f"MASSIVE-{i}",
                base_time + timedelta(seconds=i * 2),
                source_ip="203.0.113.19",
                username="admin",
            )
            for i in range(22)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]

        assert len(r001_dets) == 1
        assert r001_dets[0].severity == "CRITICAL"
        assert r001_dets[0].metadata["failure_count"] == 22


class TestMultipleTargetedAccountsAndPasswordSpray:
    """Verify multi-account targeting (password spraying) is accurately detected."""

    def test_single_ip_targeting_multiple_users_triggers_spray_alert(self):
        """Source IP targeting 4 distinct accounts with 1 failure each must trigger Password Spray."""
        base_time = datetime(2026, 10, 20, 12, 0, 0)
        target_accounts = ["alice", "bob", "charlie", "david"]
        events = [
            make_auth_event(
                f"SPRAY-{i}",
                base_time + timedelta(seconds=i * 5),
                source_ip="198.51.100.50",
                username=target_accounts[i],
            )
            for i in range(4)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]

        assert len(r001_dets) == 1
        det = r001_dets[0]
        assert "Password Spray" in det.title
        assert det.metadata["attack_pattern"] == "password_spray"
        assert det.metadata["distinct_user_count"] == 4
        assert set(det.metadata["target_users"]) == set(target_accounts)
        assert len(det.event_ids) == 4
        assert set(det.event_ids) == {f"SPRAY-{i}" for i in range(4)}

    def test_distributed_failures_across_distinct_source_ips_no_false_positive(self):
        """Failures originating from different benign sources (1 per IP) must NOT trigger spray."""
        base_time = datetime(2026, 10, 20, 12, 30, 0)
        events = [
            make_auth_event(f"DIST-{i}", base_time + timedelta(seconds=i * 10), source_ip=f"10.0.1.{i}", username="alice")
            for i in range(4)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        assert len(detections) == 0


class TestSuccessfulLoginFollowingFailures:
    """Verify R007 treats successful login after failures as a risk indicator, not definitive compromise."""

    def test_successful_login_after_failures_marked_as_risk_indicator_not_proof(self):
        """4 failures followed by success creates R007 alert with is_conclusive_proof=False."""
        base_time = datetime(2026, 10, 20, 14, 0, 0)
        events = [
            make_auth_event(
                f"PRE-FAIL-{i}",
                base_time + timedelta(seconds=i * 5),
                source_ip="192.168.1.99",
                username="sysadmin",
                action="failure",
            )
            for i in range(4)
        ]
        # Success event
        events.append(
            make_auth_event(
                "POST-SUCC-01",
                base_time + timedelta(seconds=25),
                source_ip="192.168.1.99",
                username="sysadmin",
                action="success",
                event_type="login_success",
            )
        )

        engine = RuleEngine()
        detections = engine.detect(events)
        r007_dets = [d for d in detections if d.rule_id == "R007"]

        assert len(r007_dets) == 1
        det = r007_dets[0]
        assert det.rule_id == "R007"
        assert "Risk Indicator" in det.title
        assert det.metadata["is_conclusive_proof"] is False
        assert det.metadata["requires_analyst_verification"] is True
        assert det.metadata["prior_failure_count"] == 4
        assert det.metadata["success_event_id"] == "POST-SUCC-01"
        assert "POST-SUCC-01" in det.event_ids
        assert len(det.event_ids) == 5
        assert "conclusive proof" in det.description.lower() or "risk indicator" in det.description.lower()


class TestConfigurableSettingsAndIntegrity:
    """Verify thresholds are customizable and no fields are fabricated."""

    def test_configurable_brute_force_thresholds(self):
        """Adjusting brute_force_threshold changes trigger condition."""
        custom_config = DetectionConfig(brute_force_threshold=7)
        engine = RuleEngine(config=custom_config)
        base_time = datetime(2026, 10, 20, 15, 0, 0)

        # 6 failures: should not trigger with threshold 7
        events_6 = [
            make_auth_event(f"CFG-FAIL-{i}", base_time + timedelta(seconds=i * 4), username="user_x")
            for i in range(6)
        ]
        assert len([d for d in engine.detect(events_6) if d.rule_id == "R001"]) == 0

        # 7 failures: should trigger with threshold 7
        events_7 = events_6 + [make_auth_event("CFG-FAIL-6", base_time + timedelta(seconds=28), username="user_x")]
        r001_dets = [d for d in engine.detect(events_7) if d.rule_id == "R001"]
        assert len(r001_dets) == 1

    def test_no_hallucination_when_host_or_destination_is_missing(self):
        """When hostname and destination_ip are None, rule engine does NOT fabricate them."""
        base_time = datetime(2026, 10, 20, 16, 0, 0)
        events = [
            NormalizedEvent(
                event_id=f"NO-HOST-{i}",
                timestamp=base_time + timedelta(seconds=i * 5),
                source="auth.log",
                event_type="login_failed",
                source_ip="192.168.1.150",
                destination_ip=None,
                source_port=None,
                destination_port=None,
                username="testuser",
                hostname=None,
                process="sshd",
                action="failure",
                severity="low",
                raw_message="Failed password for testuser",
            )
            for i in range(5)
        ]
        engine = RuleEngine()
        detections = engine.detect(events)
        r001_dets = [d for d in detections if d.rule_id == "R001"]

        assert len(r001_dets) == 1
        det = r001_dets[0]
        assert det.hostname is None
        assert det.destination_ip is None
        assert det.metadata["target_dest_ips"] == []
        assert det.metadata["target_hostnames"] == []
        # Ensure description does not fabricate a fictitious host
        assert "host None" not in det.description
        assert "destination None" not in det.description

    def test_mitre_mapping_for_password_spray(self):
        """Technique mapper assigns T1110.003 when attack pattern is password spray."""
        base_time = datetime(2026, 10, 20, 17, 0, 0)
        accounts = ["admin", "root", "oracle", "postgres"]
        events = [
            make_auth_event(
                f"SPRAY-MAP-{i}",
                base_time + timedelta(seconds=i * 5),
                source_ip="198.51.100.33",
                username=accounts[i],
            )
            for i in range(4)
        ]
        engine = RuleEngine()
        dets = engine.detect(events)
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(attack_chain=None, incident=None, events=events, detections=dets)

        tids = [m.technique_id for m in mappings]
        assert "T1110.003" in tids
        spray_map = next(m for m in mappings if m.technique_id == "T1110.003")
        assert spray_map.technique_name == "Password Spraying"
        assert spray_map.tactic == "Credential Access"


class TestEvidenceBasedSeverityProgression:
    """
    Regression tests verifying severity scales strictly with evidence strength:
        A. Three failed logins followed by success from the same IP (LOW severity, unconfirmed).
        B. Five failed logins followed by success from the same IP (MEDIUM severity, unconfirmed).
        C. Large rapid burst of failed logins (CRITICAL severity).
        D. Multiple usernames targeted from one IP (HIGH severity password spray).
        E. Successful login after failures with additional suspicious post-access evidence (promoted to CRITICAL).
        F. Legitimate authentication mistakes (0 detections).
    """

    def test_case_a_three_failed_logins_followed_by_success(self):
        """Case A: 3 failures + 1 success for standard user produces LOW severity R007 and MEDIUM incident."""
        base_time = datetime(2026, 10, 25, 8, 0, 0)
        events = [
            make_auth_event(f"CASEA-F-{i}", base_time + timedelta(seconds=i * 5), username="analyst_bob")
            for i in range(3)
        ]
        events.append(
            make_auth_event("CASEA-S-1", base_time + timedelta(seconds=20), username="analyst_bob", action="success", event_type="login_success")
        )
        engine = RuleEngine()
        dets = engine.detect(events)

        # R001 does not trigger (3 < 5)
        assert len([d for d in dets if d.rule_id == "R001"]) == 0

        # R007 triggers as LOW severity (small failure count, potential corrected typo)
        r007_dets = [d for d in dets if d.rule_id == "R007"]
        assert len(r007_dets) == 1
        assert r007_dets[0].severity == "LOW"
        assert r007_dets[0].metadata["is_conclusive_proof"] is False

        # Incident is LOW or MEDIUM and status is REVIEW
        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 1
        assert incidents[0].severity in {"LOW", "MEDIUM"}
        assert incidents[0].status == "REVIEW"
        assert "unconfirmed" in incidents[0].summary.lower()

    def test_case_b_five_failed_logins_followed_by_success(self):
        """Case B (Exact cybertrace_custom_test.csv model): 5 failures + 1 success produces MEDIUM alerts and MEDIUM incident."""
        base_time = datetime(2026, 10, 25, 9, 0, 0)
        events = [
            make_auth_event(f"CASEB-F-{i}", base_time + timedelta(seconds=i * 4), username="custom_attacker")
            for i in range(5)
        ]
        events.append(
            make_auth_event("CASEB-S-1", base_time + timedelta(seconds=25), username="custom_attacker", action="success", event_type="login_success")
        )
        engine = RuleEngine()
        dets = engine.detect(events)

        # R001 triggers with MEDIUM severity (standard user, small failure volume)
        r001_dets = [d for d in dets if d.rule_id == "R001"]
        assert len(r001_dets) == 1
        assert r001_dets[0].severity == "MEDIUM"

        # R007 triggers with MEDIUM severity (NOT CRITICAL)
        r007_dets = [d for d in dets if d.rule_id == "R007"]
        assert len(r007_dets) == 1
        assert r007_dets[0].severity == "MEDIUM"
        assert r007_dets[0].metadata["is_conclusive_proof"] is False

        # Incident severity is MEDIUM, status is REVIEW
        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.severity == "MEDIUM"
        assert inc.status == "REVIEW"
        assert "unconfirmed" in inc.summary.lower()

    def test_case_c_large_rapid_burst_of_failed_logins(self):
        """Case C: 25 rapid failures trigger CRITICAL severity R001 and CRITICAL incident."""
        base_time = datetime(2026, 10, 25, 10, 0, 0)
        events = [
            make_auth_event(f"CASEC-F-{i}", base_time + timedelta(seconds=i * 1), username="target_user")
            for i in range(25)
        ]
        engine = RuleEngine()
        dets = engine.detect(events)

        r001_dets = [d for d in dets if d.rule_id == "R001"]
        assert len(r001_dets) == 1
        assert r001_dets[0].severity == "CRITICAL"

        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 1
        assert incidents[0].severity == "CRITICAL"

    def test_case_d_multiple_usernames_targeted_from_one_ip(self):
        """Case D: Password spray across 4 usernames triggers HIGH severity R001 with T1110.003 mapping."""
        base_time = datetime(2026, 10, 25, 11, 0, 0)
        users = ["user_alpha", "user_beta", "user_gamma", "user_delta"]
        events = [
            make_auth_event(f"CASED-F-{i}", base_time + timedelta(seconds=i * 4), username=users[i])
            for i in range(4)
        ]
        engine = RuleEngine()
        dets = engine.detect(events)

        r001_dets = [d for d in dets if d.rule_id == "R001"]
        assert len(r001_dets) == 1
        assert r001_dets[0].severity == "HIGH"
        assert r001_dets[0].metadata["attack_pattern"] == "password_spray"

        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 1
        assert incidents[0].severity == "HIGH"

    def test_case_e_successful_login_after_failures_with_additional_suspicious_evidence(self):
        """Case E: Failures + success followed by privilege escalation promotes incident to CRITICAL."""
        base_time = datetime(2026, 10, 25, 12, 0, 0)
        events = [
            make_auth_event(f"CASEE-F-{i}", base_time + timedelta(seconds=i * 4), username="attacker")
            for i in range(5)
        ]
        events.append(
            make_auth_event("CASEE-S-1", base_time + timedelta(seconds=25), username="attacker", action="success", event_type="login_success")
        )
        # Add confirmed post-access privilege escalation event (R004)
        events.append(
            NormalizedEvent(
                event_id="CASEE-PE-1",
                timestamp=base_time + timedelta(seconds=35),
                source="audit.log",
                event_type="privilege_change",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.20",
                username="root",
                hostname="srv-app-01",
                process="sh",
                action="elevated",
                severity="high",
                raw_message="Privilege change: uid changed to 0(root)",
            )
        )
        engine = RuleEngine()
        dets = engine.detect(events)

        # Has R001, R007, and R004
        rule_ids = {d.rule_id for d in dets}
        assert "R001" in rule_ids
        assert "R007" in rule_ids
        assert "R004" in rule_ids

        # Correlated incident includes post-access privilege escalation
        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 1
        inc = incidents[0]
        # Promoted to HIGH or CRITICAL because of verified privilege escalation
        assert inc.severity in {"HIGH", "CRITICAL"}
        assert inc.status == "OPEN"

    def test_case_f_legitimate_authentication_mistakes(self):
        """Case F: 1-2 failed logins (ordinary human errors) produce ZERO detections and ZERO incidents."""
        base_time = datetime(2026, 10, 25, 13, 0, 0)
        events = [
            make_auth_event("CASEF-1", base_time, username="employee"),
            make_auth_event("CASEF-2", base_time + timedelta(seconds=30), username="employee"),
        ]
        engine = RuleEngine()
        dets = engine.detect(events)
        assert len(dets) == 0
        incidents = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets))
        assert len(incidents) == 0


