"""
Unit and Integration Tests for reconstruction/attack_chain.py
=============================================================
Tests verify:
    - Requirement A: Combined attack produces multiple meaningful stages.
    - Requirement B: Stages are ordered strictly chronologically.
    - Requirement C: Every stage contains valid, non-empty event IDs.
    - Requirement D: Every event ID exists in the original incident evidence / log dataset.
    - Requirement E: Stage confidence is strictly between 0.0 and 1.0.
    - Requirement F: Overall chain confidence is strictly between 0.0 and 1.0.
    - Requirement G: No stage has confidence 1.0 (never claims certainty).
    - Requirement H: Unsupported stages are not created.
    - Requirement I: Normal activity produces no attack chain.
    - Requirement J: Empty incident creates no stages.
    - Requirement Q: Observed evidence and inference reasoning are kept separate.
    - Requirement R: No ground-truth attack labels are read from the dataset.
    - Traceability: AttackStep -> detection_ids -> event_ids -> NormalizedEvent -> raw_message.
"""

import os
from datetime import datetime, timedelta
import pytest

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine, Detection
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector, Incident
from correlation.timeline_builder import TimelineBuilder
from reconstruction.attack_chain import (
    AttackStage,
    AttackStep,
    AttackChain,
    AttackChainReconstructor,
    build_attack_chain,
    VALID_ATTACK_STAGES,
)

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks")
)


class TestAttackStepModel:
    """Test validation and invariants of AttackStep model."""

    def test_valid_step_creation(self):
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        t1 = datetime(2026, 10, 16, 9, 5, 0)
        step = AttackStep(
            step_id="STEP-0001",
            stage=AttackStage.CREDENTIAL_ACCESS.value,
            title="Credential Access",
            description="Brute force login failures",
            timestamp_start=t0,
            timestamp_end=t1,
            detection_ids=["DET-01"],
            event_ids=["EVT-01", "EVT-02"],
            source_ips=["192.168.1.188"],
            destination_ips=["192.168.1.12"],
            usernames=["svc_admin"],
            hostnames=["srv-app-prod"],
            confidence=0.92,
            evidence_summary="Observed 2 failed logins",
            observed_evidence="2 failed login events from 192.168.1.188",
            inference_reason="Pattern matches password guessing",
        )
        assert step.step_id == "STEP-0001"
        assert step.confidence == 0.92
        d = step.to_dict()
        assert d["step_id"] == "STEP-0001"
        assert d["stage"] == "CREDENTIAL_ACCESS"

    def test_confidence_boundary_1_0_rejected(self):
        """Confidence 1.0 must be rejected (Requirement G: never claim certainty)."""
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        with pytest.raises(ValueError, match="(?i)never 1.0"):
            AttackStep(
                step_id="STEP-0001",
                stage=AttackStage.CREDENTIAL_ACCESS.value,
                title="Credential Access",
                description="desc",
                timestamp_start=t0,
                timestamp_end=t0,
                detection_ids=[],
                event_ids=["EVT-01"],
                source_ips=[],
                destination_ips=[],
                usernames=[],
                hostnames=[],
                confidence=1.0,  # Invalid: cannot claim 1.0
                evidence_summary="summary",
                observed_evidence="obs",
                inference_reason="inf",
            )

    def test_invalid_stage_rejected(self):
        """Invalid stage values outside controlled vocabulary are rejected."""
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        with pytest.raises(ValueError, match="Invalid attack stage"):
            AttackStep(
                step_id="STEP-0001",
                stage="NON_EXISTENT_STAGE",
                title="test",
                description="test",
                timestamp_start=t0,
                timestamp_end=t0,
                detection_ids=[],
                event_ids=["EVT-01"],
                source_ips=[],
                destination_ips=[],
                usernames=[],
                hostnames=[],
                confidence=0.85,
                evidence_summary="summary",
                observed_evidence="obs",
                inference_reason="inf",
            )

    def test_empty_event_ids_rejected(self):
        """AttackStep cannot be created without supporting event IDs."""
        t0 = datetime(2026, 10, 16, 9, 0, 0)
        with pytest.raises(ValueError, match="at least one event_id"):
            AttackStep(
                step_id="STEP-0001",
                stage=AttackStage.DISCOVERY.value,
                title="test",
                description="test",
                timestamp_start=t0,
                timestamp_end=t0,
                detection_ids=[],
                event_ids=[],  # Empty: rejected
                source_ips=[],
                destination_ips=[],
                usernames=[],
                hostnames=[],
                confidence=0.85,
                evidence_summary="summary",
                observed_evidence="obs",
                inference_reason="inf",
            )

    def test_inverted_timestamps_rejected(self):
        """timestamp_start cannot be after timestamp_end."""
        t0 = datetime(2026, 10, 16, 9, 10, 0)
        t1 = datetime(2026, 10, 16, 9, 0, 0)
        with pytest.raises(ValueError, match="timestamp_start cannot be after timestamp_end"):
            AttackStep(
                step_id="STEP-0001",
                stage=AttackStage.DISCOVERY.value,
                title="test",
                description="test",
                timestamp_start=t0,
                timestamp_end=t1,
                detection_ids=[],
                event_ids=["EVT-01"],
                source_ips=[],
                destination_ips=[],
                usernames=[],
                hostnames=[],
                confidence=0.85,
                evidence_summary="summary",
                observed_evidence="obs",
                inference_reason="inf",
            )


class TestAttackChainReconstructionPipeline:
    """Test full reconstruction from incidents and evidence."""

    @pytest.fixture
    def combined_attack_setup(self):
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)
        incident = max(incidents, key=lambda inc: inc.detection_count)
        return parse_res.events, detections, incident

    def test_requirement_a_combined_attack_produces_multiple_meaningful_stages(self, combined_attack_setup):
        """A. Combined attack produces multiple meaningful stages."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        assert len(chain.steps) >= 4, f"Expected at least 4 stages, got {len(chain.steps)}"
        stages = [s.stage for s in chain.steps]
        assert AttackStage.CREDENTIAL_ACCESS.value in stages
        assert AttackStage.PRIVILEGE_ESCALATION.value in stages
        assert AttackStage.COLLECTION.value in stages
        assert AttackStage.EXFILTRATION.value in stages

    def test_requirement_b_stages_are_ordered_chronologically(self, combined_attack_setup):
        """B. Stages are ordered chronologically based on evidence timestamps."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        for i in range(len(chain.steps) - 1):
            s_curr = chain.steps[i]
            s_next = chain.steps[i + 1]
            assert s_curr.timestamp_start <= s_next.timestamp_start, (
                f"Step {s_curr.step_id} ({s_curr.timestamp_start}) occurs after "
                f"Step {s_next.step_id} ({s_next.timestamp_start})"
            )

    def test_requirement_c_every_stage_contains_valid_event_ids(self, combined_attack_setup):
        """C. Every stage contains valid, non-empty event IDs."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        for step in chain.steps:
            assert len(step.event_ids) > 0, f"Step {step.step_id} has empty event_ids"
            assert all(isinstance(eid, str) and len(eid) > 0 for eid in step.event_ids)

    def test_requirement_d_every_event_id_exists_in_incident_evidence(self, combined_attack_setup):
        """D. Every event ID exists in the original incident evidence / log dataset."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        all_known_eids = {e.event_id for e in events}
        for step in chain.steps:
            for eid in step.event_ids:
                assert eid in all_known_eids, f"Event ID {eid} not found in original log evidence"

    def test_requirement_e_stage_confidence_is_between_0_and_1(self, combined_attack_setup):
        """E. Stage confidence is between 0 and 1."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        for step in chain.steps:
            assert 0.0 < step.confidence < 1.0, f"Step confidence {step.confidence} out of bounds"

    def test_requirement_f_overall_chain_confidence_is_between_0_and_1(self, combined_attack_setup):
        """F. Overall chain confidence is between 0 and 1."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        assert 0.0 < chain.overall_confidence < 1.0

    def test_requirement_g_no_stage_has_confidence_1_0(self, combined_attack_setup):
        """G. No stage has confidence 1.0 (never claims certainty)."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        for step in chain.steps:
            assert step.confidence < 1.0, f"Step {step.step_id} has forbidden confidence 1.0"
        assert chain.overall_confidence < 1.0

    def test_requirement_h_unsupported_stages_are_not_created(self, combined_attack_setup):
        """H. Unsupported stages (e.g. LATERAL_MOVEMENT, PERSISTENCE) are not created."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        stages = {s.stage for s in chain.steps}
        assert AttackStage.LATERAL_MOVEMENT.value not in stages
        assert AttackStage.PERSISTENCE.value not in stages
        assert AttackStage.EXECUTION.value not in stages

    def test_requirement_i_normal_activity_creates_no_attack_chain(self):
        """I. Normal activity creates no attack chain."""
        filepath = os.path.join(DATA_DIR, "normal_activity.csv")
        parse_res = parse_log_file(filepath)
        engine = RuleEngine()
        detections = engine.detect(parse_res.events)
        correlator = EventCorrelator()
        groups = correlator.correlate(detections)
        detector = IncidentDetector()
        incidents = detector.detect_incidents(groups)

        assert len(incidents) == 0
        # If build_attack_chain is called with empty incident or timeline:
        chain = build_attack_chain([])
        assert len(chain.steps) == 0
        assert chain.overall_confidence == 0.0

    def test_requirement_j_empty_incident_creates_no_stages(self):
        """J. Empty incident creates no stages."""
        empty_inc = Incident(
            incident_id="INC-EMPTY",
            created_at=datetime.now(),
            start_time=datetime.now(),
            end_time=datetime.now(),
            severity="LOW",
            status="OPEN",
            confidence=0.5,
            detection_ids=["DET-DUMMY"],
            event_ids=["E-DUMMY"],
            source_ips=[],
            destination_ips=[],
            usernames=[],
            hostnames=[],
            detection_count=1,
            summary="Empty test",
            correlation_score=0.5,
        )
        # Incident with no matching events in pool
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(empty_inc, events=[], detections=[])

        assert len(chain.steps) == 0
        assert chain.overall_confidence == 0.0

    def test_requirement_q_observed_evidence_and_inference_reason_are_separate(self, combined_attack_setup):
        """Q. Observed evidence and inference reasoning are kept strictly separate."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        for step in chain.steps:
            assert step.observed_evidence != step.inference_reason
            assert len(step.observed_evidence) > 10
            assert len(step.inference_reason) > 10
            # Observed evidence focuses on facts (event counts, IPs, users)
            # Inference explains reasoning
            assert any(term in step.inference_reason.lower() for term in ["consistent", "indicat", "behavior", "signif", "vector", "compromise"])

    def test_requirement_r_no_ground_truth_attack_labels_used(self, combined_attack_setup):
        """R. No ground-truth attack labels are read from the dataset."""
        events, detections, incident = combined_attack_setup
        for e in events:
            assert not hasattr(e, "label")
            assert not hasattr(e, "attack_label")
            assert not hasattr(e, "ground_truth")

    def test_traceability_from_step_to_raw_message(self, combined_attack_setup):
        """Verify full traceability: AttackStep -> detection_ids -> event_ids -> NormalizedEvent -> raw_message."""
        events, detections, incident = combined_attack_setup
        reconstructor = AttackChainReconstructor()
        chain = reconstructor.reconstruct(incident, events=events, detections=detections)

        event_lookup = {e.event_id: e for e in events}

        for step in chain.steps:
            for eid in step.event_ids:
                event = event_lookup.get(eid)
                assert event is not None, f"Event {eid} must exist in normalized events"
                assert event.raw_message is not None and len(event.raw_message) > 0
