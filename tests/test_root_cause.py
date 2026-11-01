"""
Unit and Integration Tests for reconstruction/root_cause.py
===========================================================
Tests verify:
    - Requirement N: Root-cause candidates contain supporting evidence.
    - Requirement O: Root-cause candidate confidence is strictly between 0.0 and 1.0.
    - Requirement P: Unknown root cause is returned when evidence is insufficient.
    - Candidates are ranked deterministically by confidence descending.
    - Primary candidate has rank 1 and is_primary True.
    - Uses approved terminology: "probable root cause", "root-cause candidate" (NEVER "confirmed").
    - Confidence cannot be 1.0 (never claims certainty).
    - Candidate types match controlled vocabulary: CREDENTIAL_COMPROMISE, PRIVILEGE_ABUSE, etc.
"""

import os
import pytest

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.root_cause import (
    RootCauseType,
    RootCauseCandidate,
    RootCauseAnalyzer,
    identify_root_cause,
    VALID_ROOT_CAUSE_TYPES,
)

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks")
)


class TestRootCauseModel:
    """Test validation and invariants of RootCauseCandidate model."""

    def test_valid_candidate_creation(self):
        cand = RootCauseCandidate(
            candidate_type=RootCauseType.CREDENTIAL_COMPROMISE.value,
            title="Compromised Admin Credentials",
            confidence=0.92,
            evidence_event_ids=["EVT-01", "EVT-02"],
            reasoning="Repeated failed logins followed by sudo transition.",
            rank=1,
            is_primary=True,
        )
        assert cand.candidate_type == "CREDENTIAL_COMPROMISE"
        assert cand.rank == 1
        assert cand.is_primary is True
        assert cand.confidence == 0.92

    def test_confidence_boundary_1_0_rejected(self):
        """Confidence 1.0 is rejected (never claim absolute certainty)."""
        with pytest.raises(ValueError, match="never 1.0"):
            RootCauseCandidate(
                candidate_type=RootCauseType.CREDENTIAL_COMPROMISE.value,
                title="Test",
                confidence=1.0,  # Invalid
                evidence_event_ids=["EVT-01"],
                reasoning="test",
            )

    def test_invalid_candidate_type_rejected(self):
        with pytest.raises(ValueError, match="Invalid root cause type"):
            RootCauseCandidate(
                candidate_type="IMPOSSIBLE_TYPE",
                title="Test",
                confidence=0.85,
                evidence_event_ids=["EVT-01"],
                reasoning="test",
            )

    def test_supported_candidate_without_evidence_rejected(self):
        """Non-UNKNOWN candidate must reference supporting evidence event IDs."""
        with pytest.raises(ValueError, match="supporting evidence_event_ids"):
            RootCauseCandidate(
                candidate_type=RootCauseType.PRIVILEGE_ABUSE.value,
                title="Test",
                confidence=0.85,
                evidence_event_ids=[],  # Empty evidence for supported candidate
                reasoning="test",
            )


class TestRootCauseAnalysisIntegration:
    """Test preliminary root cause analysis on realistic and empty attack chains."""

    @pytest.fixture
    def reconstructed_chain(self):
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        main_inc = max(incidents, key=lambda inc: inc.detection_count)
        reconstructor = AttackChainReconstructor()
        return reconstructor.reconstruct(main_inc, events=parse_res.events, detections=detections)

    def test_requirement_n_candidates_contain_supporting_evidence(self, reconstructed_chain):
        """N. Root-cause candidates contain supporting evidence."""
        analyzer = RootCauseAnalyzer()
        candidates = analyzer.analyze(reconstructed_chain)

        assert len(candidates) >= 1
        for cand in candidates:
            if cand.candidate_type != RootCauseType.UNKNOWN.value:
                assert len(cand.evidence_event_ids) > 0, (
                    f"Candidate {cand.title} has empty evidence_event_ids"
                )

    def test_requirement_o_candidate_confidence_between_0_and_1(self, reconstructed_chain):
        """O. Root-cause candidate confidence is between 0 and 1."""
        analyzer = RootCauseAnalyzer()
        candidates = analyzer.analyze(reconstructed_chain)

        for cand in candidates:
            assert 0.0 <= cand.confidence < 1.0, f"Confidence {cand.confidence} out of range"
            assert cand.confidence < 1.0, "Confidence must never be 1.0"

    def test_requirement_p_unknown_root_cause_for_insufficient_evidence(self):
        """P. Unknown root cause is returned when evidence is insufficient."""
        empty_chain = AttackChainReconstructor().reconstruct(None)
        analyzer = RootCauseAnalyzer()
        candidates = analyzer.analyze(empty_chain)

        assert len(candidates) == 1
        top = candidates[0]
        assert top.candidate_type == RootCauseType.UNKNOWN.value
        assert top.is_primary is True
        assert top.confidence < 0.30
        assert "insufficient" in top.reasoning.lower() or "empty" in top.reasoning.lower()

    def test_combined_attack_identifies_credential_compromise_as_primary(self, reconstructed_chain):
        """Combined attack should rank CREDENTIAL_COMPROMISE as primary root cause candidate."""
        analyzer = RootCauseAnalyzer()
        candidates = analyzer.analyze(reconstructed_chain)

        primary = candidates[0]
        assert primary.is_primary is True
        assert primary.rank == 1
        assert primary.candidate_type == RootCauseType.CREDENTIAL_COMPROMISE.value
        assert primary.confidence >= 0.88
        assert len(primary.evidence_event_ids) >= 10
        assert "brute force" in primary.reasoning.lower() or "failed" in primary.reasoning.lower()

    def test_candidates_ranked_descending_by_confidence(self, reconstructed_chain):
        """Candidates must be sorted strictly by confidence descending."""
        candidates = identify_root_cause(reconstructed_chain)

        for i in range(len(candidates) - 1):
            assert candidates[i].confidence >= candidates[i + 1].confidence
            assert candidates[i].rank == i + 1

    def test_standalone_brute_force_identifies_credential_compromise(self):
        """Standalone brute force dataset should identify CREDENTIAL_COMPROMISE with evidence."""
        filepath = os.path.join(DATA_DIR, "brute_force.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        chain = AttackChainReconstructor().reconstruct(incidents[0], events=parse_res.events, detections=detections)
        candidates = RootCauseAnalyzer().analyze(chain)

        assert len(candidates) >= 1
        primary = candidates[0]
        assert primary.is_primary is True
        assert primary.candidate_type == RootCauseType.CREDENTIAL_COMPROMISE.value
        assert primary.confidence >= 0.80
        assert len(primary.evidence_event_ids) > 0

    def test_data_exfiltration_identifies_insider_data_access(self):
        """Data exfiltration without initial access telemetry maps to INSIDER_DATA_ACCESS."""
        filepath = os.path.join(DATA_DIR, "data_exfiltration.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        chain = AttackChainReconstructor().reconstruct(incidents[0], events=parse_res.events, detections=detections)
        candidates = RootCauseAnalyzer().analyze(chain)

        assert len(candidates) >= 1
        primary = candidates[0]
        assert primary.is_primary is True
        assert primary.candidate_type == RootCauseType.INSIDER_DATA_ACCESS.value
        assert primary.confidence >= 0.80
        assert len(primary.evidence_event_ids) > 0

    def test_port_scan_reconnaissance_root_cause(self):
        """Port scan scenario produces informative reconnaissance analysis."""
        filepath = os.path.join(DATA_DIR, "port_scan.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        chain = AttackChainReconstructor().reconstruct(incidents[0], events=parse_res.events, detections=detections)
        candidates = RootCauseAnalyzer().analyze(chain)

        assert len(candidates) >= 1
        primary = candidates[0]
        assert primary.is_primary is True
        assert "reconnaissance" in primary.title.lower() or "reconnaissance" in primary.reasoning.lower()
        assert len(primary.evidence_event_ids) > 0

    def test_normal_activity_distinguished_from_unknown_root_cause(self):
        """Normal baseline produces zero incidents; pipeline does not generate fake root cause candidate."""
        filepath = os.path.join(DATA_DIR, "normal_activity.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)

        # Baseline produces 0 detections and 0 incidents
        assert len(detections) == 0
        assert len(incidents) == 0

        # Contrast with port_scan.csv which HAS an incident and generates an UNKNOWN reconnaissance candidate
        ps_filepath = os.path.join(DATA_DIR, "port_scan.csv")
        ps_parse = parse_log_file(ps_filepath)
        ps_dets = engine.detect(ps_parse.events)
        ps_groups = correlator.correlate(ps_dets)
        ps_incidents = detector.detect_incidents(ps_groups)

        assert len(ps_incidents) == 1
        ps_chain = AttackChainReconstructor().reconstruct(ps_incidents[0], events=ps_parse.events, detections=ps_dets)
        ps_rc = RootCauseAnalyzer().analyze(ps_chain)

        assert len(ps_rc) == 1
        assert ps_rc[0].candidate_type == RootCauseType.UNKNOWN.value
        assert "reconnaissance" in ps_rc[0].title.lower()


