"""
Unit and Integration Tests for MITRE ATT&CK Technique Mapper
============================================================
Phase 7 Verification Suite for CyberTrace.

Test Matrix:
    - TestGroupModel: Validation of TechniqueMapping dataclass invariants
    - TestGroupRegistry: Validation of official MITRE ATT&CK Enterprise taxonomy
    - TestGroupCombinedAttack (Req A): Full pipeline test on combined_attack.csv
    - TestGroupNormalActivity (Req B): Verification of 0 techniques on normal_activity.csv
    - TestGroupIndividualScenarios (Req C): Independent tests for all 5 synthetic attack datasets
    - TestGroupUnseenEntities (Req D): Robustness against altered IPs, users, hosts, event IDs
    - TestGroupDatasetInvariance (Req E): Explicit test that filename/path does not affect mapping
    - TestGroupTraceability: Full forensic traceability from technique to raw_message
"""

import os
import shutil
import tempfile
import pytest
from datetime import datetime, timedelta

from preprocessing.log_parser import parse_log_file
from preprocessing.normalizer import normalize_events
from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import apply_rules, Detection
from correlation.event_correlator import correlate_events
from correlation.incident_detector import detect_incidents, Incident
from reconstruction.attack_chain import build_attack_chain, AttackChain, AttackStep, AttackStage
from mitre.technique_mapper import (
    TechniqueMapping,
    TechniqueMapper,
    map_to_mitre,
    ATTACK_REGISTRY,
)


# =============================================================================
# 1. MODEL INVARIANT TESTS
# =============================================================================

class TestGroupModel:
    """Tests validating TechniqueMapping data model boundaries and invariants."""

    def test_valid_technique_mapping_creation(self):
        """TechniqueMapping instantiates cleanly with valid parameters."""
        mapping = TechniqueMapping(
            technique_id="T1110.001",
            technique_name="Password Guessing",
            tactic="Credential Access",
            tactics=["Credential Access"],
            confidence=0.88,
            rationale="Repeated authentication failures detected.",
            supporting_detection_ids=["DET-0001"],
            supporting_event_ids=["EVT-0001", "EVT-0002"],
            evidence_count=2,
            sub_technique_of="T1110",
        )
        assert mapping.technique_id == "T1110.001"
        assert mapping.confidence == 0.88
        assert mapping.evidence_count == 2
        assert len(mapping.supporting_event_ids) == 2

    def test_technique_id_must_start_with_t(self):
        """Technique ID must be an official ATT&CK ID starting with 'T'."""
        with pytest.raises(ValueError, match="Invalid MITRE technique ID"):
            TechniqueMapping(
                technique_id="INVALID_ID",
                technique_name="Fake Technique",
                tactic="Discovery",
                tactics=["Discovery"],
                confidence=0.80,
                rationale="Test",
                supporting_detection_ids=["DET-0001"],
                supporting_event_ids=["EVT-0001"],
                evidence_count=1,
            )

    def test_confidence_boundary_never_one_point_zero(self):
        """Confidence cannot be 1.0 (100% certainty is forbidden)."""
        with pytest.raises(ValueError, match="never 1.0"):
            TechniqueMapping(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                tactics=["Discovery"],
                confidence=1.0,
                rationale="Test",
                supporting_detection_ids=["DET-0001"],
                supporting_event_ids=["EVT-0001"],
                evidence_count=1,
            )

    def test_confidence_boundary_strictly_positive(self):
        """Confidence cannot be 0.0 or negative."""
        with pytest.raises(ValueError, match="must be in \\(0.0, 1.0\\)"):
            TechniqueMapping(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                tactics=["Discovery"],
                confidence=0.0,
                rationale="Test",
                supporting_detection_ids=["DET-0001"],
                supporting_event_ids=["EVT-0001"],
                evidence_count=1,
            )

    def test_supporting_event_ids_cannot_be_empty(self):
        """Every technique mapping must be substantiated by at least one event ID."""
        with pytest.raises(ValueError, match="at least one supporting event ID"):
            TechniqueMapping(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                tactics=["Discovery"],
                confidence=0.85,
                rationale="Test",
                supporting_detection_ids=["DET-0001"],
                supporting_event_ids=[],
                evidence_count=0,
            )

    def test_evidence_count_automatically_aligned(self):
        """evidence_count aligns with length of supporting_event_ids."""
        mapping = TechniqueMapping(
            technique_id="T1046",
            technique_name="Network Service Discovery",
            tactic="Discovery",
            tactics=["Discovery"],
            confidence=0.85,
            rationale="Test",
            supporting_detection_ids=["DET-0001"],
            supporting_event_ids=["EVT-1", "EVT-2", "EVT-3"],
            evidence_count=999,  # Mismatched initial value
        )
        assert mapping.evidence_count == 3

    def test_to_dict_serialization(self):
        """to_dict produces fully serializable dictionary representation."""
        mapping = TechniqueMapping(
            technique_id="T1078.003",
            technique_name="Local Accounts",
            tactic="Initial Access",
            tactics=["Initial Access", "Defense Evasion"],
            confidence=0.86543,
            rationale="Account compromise observed.",
            supporting_detection_ids=["DET-0001"],
            supporting_event_ids=["EVT-0001"],
            evidence_count=1,
            sub_technique_of="T1078",
            metadata={"source_ip": "10.0.0.1"},
        )
        d = mapping.to_dict()
        assert d["technique_id"] == "T1078.003"
        assert d["confidence"] == 0.8654
        assert d["tactic"] == "Initial Access"
        assert d["supporting_event_ids"] == ["EVT-0001"]
        assert d["metadata"] == {"source_ip": "10.0.0.1"}


# =============================================================================
# 2. TAXONOMY AND REGISTRY TESTS
# =============================================================================

class TestGroupRegistry:
    """Tests verifying the ATTACK_REGISTRY meets enterprise taxonomy standards."""

    def test_registry_has_expected_supported_techniques(self):
        """Verify core enterprise techniques are present in the registry."""
        expected = {
            "T1110.001",
            "T1078",
            "T1078.003",
            "T1046",
            "T1083",
            "T1548.003",
            "T1548.001",
            "T1003.008",
            "T1552.004",
            "T1560.001",
            "T1048",
            "T1048.002",
        }
        for tid in expected:
            assert tid in ATTACK_REGISTRY, f"Missing registered technique {tid}"

    def test_registry_fields_structure(self):
        """Every entry in ATTACK_REGISTRY must have all standard fields."""
        for tid, entry in ATTACK_REGISTRY.items():
            assert entry["technique_id"] == tid
            assert len(entry["technique_name"]) > 0
            assert len(entry["primary_tactic"]) > 0
            assert isinstance(entry["tactics"], list)
            assert len(entry["tactics"]) > 0
            assert entry["url"].startswith("https://attack.mitre.org/techniques/")


# =============================================================================
# 3. REQUIREMENT A — COMBINED ATTACK TEST
# =============================================================================

class TestGroupCombinedAttack:
    """
    Requirement A:
    Verify technique mapping against combined_attack.csv.
    """

    @pytest.fixture
    def combined_pipeline_output(self):
        """Execute Phase 1-6 pipeline on combined_attack.csv."""
        res = parse_log_file("data/sample_attacks/combined_attack.csv")
        events = res.events
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))
        incident = incidents[0]
        chain = build_attack_chain(incident, events, dets)
        return {
            "events": events,
            "detections": dets,
            "incident": incident,
            "chain": chain,
        }

    def test_combined_attack_generates_mitre_techniques(self, combined_pipeline_output):
        """Techniques are produced for combined attack."""
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(
            attack_chain=combined_pipeline_output["chain"],
            incident=combined_pipeline_output["incident"],
            events=combined_pipeline_output["events"],
            detections=combined_pipeline_output["detections"],
        )
        assert len(mappings) >= 5, f"Expected at least 5 techniques, got {len(mappings)}"

    def test_combined_attack_techniques_structure(self, combined_pipeline_output):
        """Each mapped technique has valid structure, official ID, and valid confidence."""
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(
            attack_chain=combined_pipeline_output["chain"],
            incident=combined_pipeline_output["incident"],
            events=combined_pipeline_output["events"],
            detections=combined_pipeline_output["detections"],
        )
        for m in mappings:
            assert m.technique_id.startswith("T")
            assert 0.70 <= m.confidence <= 0.95
            assert len(m.tactic) > 0
            assert len(m.supporting_event_ids) > 0
            assert m.evidence_count == len(m.supporting_event_ids)
            assert len(m.rationale) > 0

    def test_combined_attack_no_fabricated_event_ids(self, combined_pipeline_output):
        """Every single supporting event ID exists in the original normalized event pool."""
        mapper = TechniqueMapper()
        events = combined_pipeline_output["events"]
        valid_eids = {e.event_id for e in events}

        mappings = mapper.map_techniques(
            attack_chain=combined_pipeline_output["chain"],
            incident=combined_pipeline_output["incident"],
            events=events,
            detections=combined_pipeline_output["detections"],
        )

        for m in mappings:
            for eid in m.supporting_event_ids:
                assert eid in valid_eids, f"Fabricated event_id '{eid}' in {m.technique_id} mapping!"

    def test_combined_attack_expected_core_techniques(self, combined_pipeline_output):
        """Verify the expected core techniques for the 5 reconstructed attack stages."""
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(
            attack_chain=combined_pipeline_output["chain"],
            incident=combined_pipeline_output["incident"],
            events=combined_pipeline_output["events"],
            detections=combined_pipeline_output["detections"],
        )
        mapped_tids = {m.technique_id for m in mappings}

        # Check core expected techniques:
        # 1. Password Guessing
        assert "T1110.001" in mapped_tids
        # 2. Valid Accounts (prefers T1078 when account locality is unknown)
        assert "T1078" in mapped_tids
        # 3. Sudo Elevation
        assert "T1548.003" in mapped_tids
        # 4. Shadow Dumping / Credential File Access
        assert "T1003.008" in mapped_tids
        # 5. Exfiltration Over Alternative Protocol (parent T1048)
        assert "T1048" in mapped_tids


# =============================================================================
# 4. REQUIREMENT B — NORMAL ACTIVITY TEST
# =============================================================================

class TestGroupNormalActivity:
    """
    Requirement B:
    Verify that benign activity generates 0 MITRE mappings.
    """

    def test_normal_activity_produces_zero_mappings(self):
        """normal_activity.csv produces 0 detections, 0 incidents, and 0 MITRE mappings."""
        res = parse_log_file("data/sample_attacks/normal_activity.csv")
        events = res.events
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))
        assert len(dets) == 0
        assert len(incidents) == 0

        chain = None
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(
            attack_chain=chain,
            incident=None,
            events=events,
            detections=dets,
        )
        assert len(mappings) == 0, f"Expected 0 mappings for normal activity, got {len(mappings)}"


# =============================================================================
# 5. REQUIREMENT C — INDIVIDUAL SCENARIOS TEST
# =============================================================================

class TestGroupIndividualScenarios:
    """
    Requirement C:
    Test each scenario dataset independently to verify appropriate mapping based on actual evidence.
    """

    def _run_pipeline(self, filepath: str):
        res = parse_log_file(filepath)
        events = res.events
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], events, dets) if incidents else None
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(
            attack_chain=chain,
            incident=incidents[0] if incidents else None,
            events=events,
            detections=dets,
        )
        return events, dets, incidents, mappings

    def test_brute_force_scenario(self):
        """brute_force.csv maps to T1110.001 (Password Guessing) and T1078 (Valid Accounts)."""
        _, _, _, mappings = self._run_pipeline("data/sample_attacks/brute_force.csv")
        tids = [m.technique_id for m in mappings]
        assert "T1110.001" in tids
        assert "T1078" in tids
        bf_map = next(m for m in mappings if m.technique_id == "T1110.001")
        assert bf_map.tactic == "Credential Access"
        assert bf_map.evidence_count >= 10
        assert 0.80 <= bf_map.confidence <= 0.95

    def test_port_scan_scenario(self):
        """port_scan.csv maps to T1046 (Network Service Discovery)."""
        _, _, _, mappings = self._run_pipeline("data/sample_attacks/port_scan.csv")
        tids = [m.technique_id for m in mappings]
        assert "T1046" in tids
        ps_map = next(m for m in mappings if m.technique_id == "T1046")
        assert ps_map.tactic == "Discovery"
        assert ps_map.evidence_count >= 10
        assert 0.80 <= ps_map.confidence <= 0.95

    def test_compromised_login_scenario(self):
        """compromised_login.csv maps to T1078, T1083, and credential techniques."""
        _, _, _, mappings = self._run_pipeline("data/sample_attacks/compromised_login.csv")
        tids = [m.technique_id for m in mappings]
        assert "T1078" in tids
        assert "T1003.008" in tids
        # SUID search in compromised login maps to T1083 (File and Directory Discovery)
        assert "T1083" in tids
        # SUID discovery alone must NOT map to T1548.001 (Setuid and Setgid)
        assert "T1548.001" not in tids

    def test_privilege_escalation_scenario(self):
        """privilege_escalation.csv maps to T1548.003 (Sudo and Sudo Caching)."""
        _, _, _, mappings = self._run_pipeline("data/sample_attacks/privilege_escalation.csv")
        tids = [m.technique_id for m in mappings]
        assert "T1548.003" in tids
        pe_map = next(m for m in mappings if m.technique_id == "T1548.003")
        assert pe_map.tactic == "Privilege Escalation"
        assert pe_map.evidence_count >= 3
        assert pe_map.confidence >= 0.90
        # Fix 4: authorized_keys does NOT map to Private Keys
        assert "T1552.004" not in tids

    def test_data_exfiltration_scenario(self):
        """data_exfiltration.csv maps to T1048 and T1560.001."""
        _, _, _, mappings = self._run_pipeline("data/sample_attacks/data_exfiltration.csv")
        tids = [m.technique_id for m in mappings]
        assert "T1048" in tids
        assert "T1560.001" in tids
        exfil_map = next(m for m in mappings if m.technique_id == "T1048")
        assert exfil_map.tactic == "Exfiltration"
        assert exfil_map.evidence_count >= 5


# =============================================================================
# 6. REQUIREMENT D — UNSEEN ENTITIES TEST
# =============================================================================

class TestGroupUnseenEntities:
    """
    Requirement D:
    Verify that changing source IP, username, hostname, and event IDs produces identical techniques.
    The mapping must be strictly behavioral and entity-agnostic.
    """

    def test_unseen_entities_mapping(self):
        """
        Synthesize events with entirely novel IP (203.0.113.88), user ('unknown_operator'),
        hostname ('dc-omega-01'), and custom event IDs ('CUSTOM-9999').
        Behavioral pattern: 12 failed logins -> R001 -> T1110.001.
        """
        now = datetime(2026, 5, 1, 10, 0, 0)
        events = []
        for i in range(12):
            events.append(
                NormalizedEvent(
                    timestamp=now,
                    source="auth.log",
                    event_type="login_failed",
                    source_ip="203.0.113.88",
                    destination_ip="198.51.100.2",
                    source_port=44000 + i,
                    destination_port=22,
                    username="unknown_operator",
                    hostname="dc-omega-01",
                    process="sshd",
                    action="failure",
                    severity="medium",
                    raw_message=f"Failed password for unknown_operator from 203.0.113.88 port {44000 + i} ssh2",
                    event_id=f"CUSTOM-{1000 + i}",
                )
            )

        dets = apply_rules(events)
        assert len(dets) > 0

        incidents = detect_incidents(correlate_events(dets))
        assert len(incidents) > 0

        chain = build_attack_chain(incidents[0], events, dets)
        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(chain, incidents[0], events, dets)

        assert len(mappings) == 1
        m = mappings[0]
        assert m.technique_id == "T1110.001"
        assert m.technique_name == "Password Guessing"
        assert m.tactic == "Credential Access"
        assert m.evidence_count == 12
        assert all(eid.startswith("CUSTOM-") for eid in m.supporting_event_ids)
        assert "unknown_operator" in m.rationale


# =============================================================================
# 7. REQUIREMENT E — NO HARDCODED DATASET DEPENDENCE
# =============================================================================

class TestGroupDatasetInvariance:
    """
    Requirement E:
    Explicitly test that renaming or moving the dataset file produces identical mapping results.
    """

    def test_filename_and_path_invariance(self):
        """Copying combined_attack.csv to a random temp file produces identical mappings."""
        src_path = "data/sample_attacks/combined_attack.csv"

        # Baseline run
        res1 = parse_log_file(src_path)
        dets1 = apply_rules(res1.events)
        inc1 = detect_incidents(correlate_events(dets1))[0]
        chain1 = build_attack_chain(inc1, res1.events, dets1)
        mapper = TechniqueMapper()
        mappings_base = mapper.map_techniques(chain1, inc1, res1.events, dets1)

        # Temporary renamed copy in isolated folder
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_csv = os.path.join(temp_dir, "completely_random_audit_log_987654.csv")
            shutil.copyfile(src_path, temp_csv)

            res2 = parse_log_file(temp_csv)
            dets2 = apply_rules(res2.events)
            inc2 = detect_incidents(correlate_events(dets2))[0]
            chain2 = build_attack_chain(inc2, res2.events, dets2)
            mappings_renamed = mapper.map_techniques(chain2, inc2, res2.events, dets2)

            assert len(mappings_base) == len(mappings_renamed)
            for m1, m2 in zip(mappings_base, mappings_renamed):
                assert m1.technique_id == m2.technique_id
                assert m1.technique_name == m2.technique_name
                assert m1.tactic == m2.tactic
                assert m1.confidence == m2.confidence
                assert m1.evidence_count == m2.evidence_count
                assert m1.supporting_event_ids == m2.supporting_event_ids


# =============================================================================
# 8. EVIDENCE TRACEABILITY TESTS
# =============================================================================

class TestGroupTraceability:
    """
    Requirement 8:
    Verify end-to-end traceability from technique -> detection -> event -> raw_message.
    """

    def test_full_traceability_to_raw_message(self):
        """Technique mappings preserve 100% path back to raw log messages."""
        res = parse_log_file("data/sample_attacks/combined_attack.csv")
        events = res.events
        events_by_id = {e.event_id: e for e in events}
        dets = apply_rules(events)
        dets_by_id = {d.detection_id: d for d in dets}
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], events, dets)

        mapper = TechniqueMapper()
        mappings = mapper.map_techniques(chain, incidents[0], events, dets)

        for mapping in mappings:
            # 1. Trace supporting detections
            for did in mapping.supporting_detection_ids:
                assert did in dets_by_id
                det = dets_by_id[did]
                assert det.detection_id == did

            # 2. Trace supporting events
            for eid in mapping.supporting_event_ids:
                assert eid in events_by_id
                event = events_by_id[eid]
                assert event.event_id == eid
                # 3. Trace raw message
                assert len(event.raw_message) > 0
                assert isinstance(event.raw_message, str)


# =============================================================================
# 9. CONVENIENCE API & EDGE CASES
# =============================================================================

class TestGroupApiAndEdgeCases:
    """Tests verifying map_to_mitre convenience API and edge case handling."""

    def test_map_to_mitre_with_none_or_empty(self):
        """Calling map_to_mitre with None or empty structures returns empty list."""
        assert map_to_mitre(None) == []
        assert map_to_mitre([]) == []
        assert map_to_mitre({}) == []

    def test_map_to_mitre_with_attack_chain(self):
        """Convenience API accepts AttackChain instance."""
        res = parse_log_file("data/sample_attacks/brute_force.csv")
        events = res.events
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], events, dets)

        mappings = map_to_mitre(chain, events=events, detections=dets)
        assert len(mappings) > 0
        assert any(m.technique_id == "T1110.001" for m in mappings)

    def test_map_to_mitre_with_incident(self):
        """Convenience API accepts Incident instance."""
        res = parse_log_file("data/sample_attacks/port_scan.csv")
        events = res.events
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))

        mappings = map_to_mitre(incidents[0], events=events, detections=dets)
        assert len(mappings) > 0
        assert any(m.technique_id == "T1046" for m in mappings)


# =============================================================================
# 10. PHASE 7.1 AUDIT CORRECTIONS REGRESSION SUITE
# =============================================================================

class TestGroupPhase71AuditCorrections:
    """
    Mandatory regression tests for Phase 7.1 audit corrections:
    1. Successful login without local account evidence prefers T1078.
    2. Large transfer maps to parent T1048 without asymmetric encryption assumption.
    3. Large transfer over port 873 does not imply HTTPS/TCP 443.
    4. SUID discovery ('find / -perm -4000') maps to T1083, not T1548.001.
    5. authorized_keys does not trigger Private Keys (T1552.004).
    6. Genuine private-key access still triggers T1552.004.
    7. Ordinary sudo ls without elevation evidence produces 0 mappings.
    8. Valid sudo elevation evidence still maps to T1548.003.
    9. Benign tar backup does not automatically trigger T1560.001.
    10. Genuine suspicious archive staging maps to T1560.001.
    11. Every mapping has valid event and detection references.
    12. Normal activity produces zero unsupported mappings.
    13. Mapping behavior remains entity- and filename-independent.
    """

    def test_login_without_local_proof_prefers_t1078(self):
        """1. Successful login without evidence of local account architecture prefers T1078 over T1078.003."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id=f"FAIL-{i}", timestamp=now, source="auth.log", event_type="login_failed",
                source_ip="192.168.1.100", destination_ip="192.168.1.10", username="user1",
                process="sshd", action="failure", severity="medium", raw_message=f"Failed password for user1"
            ) for i in range(6)
        ]
        events.append(
            NormalizedEvent(
                event_id="SUCC-01", timestamp=now, source="auth.log", event_type="login_success",
                source_ip="192.168.1.100", destination_ip="192.168.1.10", username="user1",
                process="sshd", action="success", severity="high", raw_message="Accepted password for user1"
            )
        )
        dets = apply_rules(events)
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], events, dets) if incidents else None
        mappings = TechniqueMapper().map_techniques(chain, incidents[0] if incidents else None, events, dets)

        tids = [m.technique_id for m in mappings]
        assert "T1078" in tids, "Expected T1078 (Valid Accounts)"
        assert "T1078.003" not in tids, "Over-specific T1078.003 should not be forced without local account proof"
        m_1078 = next(m for m in mappings if m.technique_id == "T1078")
        assert "local vs. domain/central" in m_1078.rationale.lower()

    def test_large_transfer_maps_to_parent_t1048_without_asymmetric_assumption(self):
        """2. Large transfer maps to parent T1048 and does not assert asymmetric encryption."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="XFER-01", timestamp=now, source="firewall", event_type="large_outbound_transfer",
                source_ip="192.168.1.10", destination_ip="10.0.0.95", source_port=50000, destination_port=8443,
                username="user1", process="curl", action="allowed", severity="high",
                raw_message="FIREWALL PASS: High volume outbound stream proto=TCP bytes=150000000 dst=10.0.0.95:8443"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1048" in tids
        assert "T1048.002" not in tids
        m_1048 = next(m for m in mappings if m.technique_id == "T1048")
        assert "asymmetric" not in m_1048.technique_name.lower()
        assert "8443" in m_1048.metadata["destination_ports"]

    def test_large_transfer_over_port_873_no_https_assumption(self):
        """3. Large transfer over non-web port (873) records actual port without hardcoding HTTPS/TCP 443."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="XFER-RSYNC", timestamp=now, source="firewall", event_type="large_outbound_transfer",
                source_ip="192.168.1.10", destination_ip="10.0.0.95", source_port=50000, destination_port=873,
                username="backup_agent", process="rsync", action="allowed", severity="high",
                raw_message="FIREWALL PASS: High volume outbound stream proto=TCP bytes=150000000 dst=10.0.0.95:873"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        m_1048 = next(m for m in mappings if m.technique_id == "T1048")
        assert "873" in m_1048.rationale
        assert "HTTPS/TCP 443" not in m_1048.rationale

    def test_large_transfer_without_alternative_protocol_does_not_force_t1048(self):
        """3b. Large transfer without alternative protocol telemetry reports R006 detection but does not force T1048."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="XFER-RAW", timestamp=now, source="firewall", event_type="large_outbound_transfer",
                source_ip="192.168.1.10", destination_ip="10.0.0.95", source_port=50000, destination_port=443,
                username="system", process="firewall", action="allowed", severity="high",
                raw_message="FIREWALL PASS: High volume outbound stream proto=TCP bytes=150000000 dst=10.0.0.95:443"
            )
        ]
        dets = apply_rules(events)
        # R006 detects the high volume egress
        assert any(d.rule_id == "R006" for d in dets)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1048" not in tids, "Large transfer without alternative protocol telemetry must not force T1048"
        assert "T1048.002" not in tids

    def test_suid_discovery_maps_to_t1083_not_t1548_001(self):
        """4. 'find / -perm -4000' discovery command maps to T1083, not T1548.001."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="SUID-FIND", timestamp=now, source="audit.log", event_type="privilege_recon",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="user1",
                process="bash", action="executed", severity="medium",
                raw_message="EXECVE: cmd='find / -perm -4000 2>/dev/null' uid=1001(user1)"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1083" in tids, "Expected T1083 (File and Directory Discovery)"
        assert "T1548.001" not in tids, "Read-only SUID search should not map to T1548.001"

    def test_authorized_keys_does_not_trigger_private_keys(self):
        """5. Accessing/modifying authorized_keys (PE-4027) does NOT trigger T1552.004 (Private Keys)."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="PE-4027", timestamp=now, source="audit.log", event_type="file_modify",
                source_ip="192.168.1.48", destination_ip="192.168.1.15", username="root",
                process="bash", action="executed", severity="high",
                raw_message="Root command executed: root authorized_keys modified"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1552.004" not in tids, "authorized_keys is a public key file; must not map to Private Keys"

    def test_genuine_private_key_still_maps_to_t1552_004(self):
        """6. Genuine private key events (jwt_private_key.pem, id_rsa) still trigger T1552.004."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="KEY-01", timestamp=now, source="audit.log", event_type="sensitive_file_read",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="root",
                process="cat", action="read", severity="high",
                raw_message="AUDIT_READ: root accessed sensitive file /opt/app/keys/jwt_private_key.pem"
            ),
            NormalizedEvent(
                event_id="KEY-02", timestamp=now, source="audit.log", event_type="credential_access",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="user1",
                process="bash", action="executed", severity="medium",
                raw_message="EXECVE: cmd='cat ~/.ssh/id_rsa' uid=1001(user1)"
            ),
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1552.004" in tids
        m_key = next(m for m in mappings if m.technique_id == "T1552.004")
        assert "KEY-01" in m_key.supporting_event_ids
        assert "KEY-02" in m_key.supporting_event_ids

    def test_ordinary_sudo_ls_does_not_trigger_t1548_003(self):
        """7. Ordinary sudo ls without elevation evidence produces 0 mappings."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="SUDO-BENIGN", timestamp=now, source="audit.log", event_type="command_exec",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="bob",
                process="sudo", action="executed", severity="low",
                raw_message="sudo: bob : TTY=pts/0 ; COMMAND=/bin/ls"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1548.003" not in tids, "Ordinary sudo ls without elevation must not map to T1548.003"

    def test_valid_sudo_elevation_still_maps_to_t1548_003(self):
        """8. Valid sudo elevation with UID transition to root maps to T1548.003."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="SUDO-ELEV", timestamp=now, source="audit.log", event_type="privilege_change",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="root",
                process="bash", action="elevated", severity="critical",
                raw_message="Privilege transition: uid changed from 1005(user1) to 0(root)"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1548.003" in tids

    def test_benign_tar_backup_does_not_trigger_t1560_001(self):
        """9. Benign scheduled tar backup by backup_agent does not trigger T1560.001."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="TAR-BENIGN", timestamp=now, source="audit.log", event_type="file_archive",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="backup_agent",
                process="tar", action="created", severity="low",
                raw_message="tar -czvf /backup/daily_backup.tar.gz /var/log"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1560.001" not in tids, "Routine daily backup must not trigger malicious archive staging"

    def test_suspicious_archive_staging_maps_to_t1560_001(self):
        """10. Genuine suspicious archive staging with confidential paths maps to T1560.001."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        events = [
            NormalizedEvent(
                event_id="TAR-SUSP", timestamp=now, source="audit.log", event_type="file_archive",
                source_ip="192.168.1.10", destination_ip="192.168.1.10", username="user1",
                process="tar", action="created", severity="medium",
                raw_message="tar -czvf /tmp/staging_archive.tar.gz /mnt/shares/confidential/*"
            )
        ]
        dets = apply_rules(events)
        mappings = TechniqueMapper().map_techniques(events=events, detections=dets)
        tids = [m.technique_id for m in mappings]
        assert "T1560.001" in tids

    def test_every_mapping_has_valid_event_and_detection_references(self):
        """11. Every mapping has valid event count and non-empty supporting event references."""
        res = parse_log_file("data/sample_attacks/combined_attack.csv")
        dets = apply_rules(res.events)
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], res.events, dets)
        mappings = TechniqueMapper().map_techniques(chain, incidents[0], res.events, dets)

        valid_eids = {e.event_id for e in res.events}
        valid_dids = {d.detection_id for d in dets}

        for m in mappings:
            assert m.evidence_count == len(m.supporting_event_ids)
            assert len(m.supporting_event_ids) > 0
            assert all(eid in valid_eids for eid in m.supporting_event_ids)
            assert all(did in valid_dids for did in m.supporting_detection_ids)

    def test_normal_activity_zero_unsupported_mappings_maintained(self):
        """12. Normal activity produces zero mappings."""
        res = parse_log_file("data/sample_attacks/normal_activity.csv")
        dets = apply_rules(res.events)
        mappings = TechniqueMapper().map_techniques(events=res.events, detections=dets)
        assert len(mappings) == 0

    def test_entity_and_filename_independence_preserved(self):
        """13. Mapping behavior remains independent of filenames and entity identifiers."""
        res = parse_log_file("data/sample_attacks/combined_attack.csv")
        dets = apply_rules(res.events)
        incidents = detect_incidents(correlate_events(dets))
        chain = build_attack_chain(incidents[0], res.events, dets)
        base_tids = [m.technique_id for m in TechniqueMapper().map_techniques(chain, incidents[0], res.events, dets)]

        # Mutate entities
        mutated_events = []
        for e in res.events:
            mut_e = NormalizedEvent(
                event_id=e.event_id.replace("CA-", "MUT-"),
                timestamp=e.timestamp + timedelta(days=50),
                source=e.source,
                event_type=e.event_type,
                source_ip="172.16.100.2" if e.source_ip == "192.168.1.12" else ("172.16.100.1" if e.source_ip == "192.168.1.188" else e.source_ip),
                destination_ip="172.16.100.2" if e.destination_ip == "192.168.1.12" else e.destination_ip,
                source_port=e.source_port,
                destination_port=e.destination_port,
                username="mutated_user" if e.username == "svc_admin" else e.username,
                hostname="mutated_host" if e.hostname == "srv-app-prod" else e.hostname,
                process=e.process,
                action=e.action,
                severity=e.severity,
                raw_message=e.raw_message.replace("svc_admin", "mutated_user").replace("192.168.1.188", "172.16.100.1"),
            )
            mutated_events.append(mut_e)

        dets_mut = apply_rules(mutated_events)
        inc_mut = detect_incidents(correlate_events(dets_mut))[0]
        chain_mut = build_attack_chain(inc_mut, mutated_events, dets_mut)
        mut_tids = [m.technique_id for m in TechniqueMapper().map_techniques(chain_mut, inc_mut, mutated_events, dets_mut)]

        assert base_tids == mut_tids

