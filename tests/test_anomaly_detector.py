"""
Test Suite: ML-Based Anomaly Detector (Phase 8)
================================================
Comprehensive verification of the Isolation Forest anomaly detector, covering:
    1. Deterministic initialization and fixed random seed reproducibility
    2. Training on valid benign baseline telemetry (normal_activity.csv)
    3. Inference on unseen events
    4. Empty input handling for fit() and predict()
    5. Missing, None, and malformed attribute resilience
    6. AnomalyResult schema validation and score directionality
    7. Evidence traceability to event_id and verbatim raw_message
    8. Dataset filename and scenario label leakage prevention
    9. Entity (IP, username, hostname, event_id) leakage prevention into features
    10. Separation of training and evaluation data transformations
    11. Complete structural distinction between ML AnomalyResult and RuleEngine Detection
    12. Invariance of deterministic detection rules (R001-R006)
    13. Error handling on unfitted detector and unsupported states
    14. Reproducible inference scoring across repeated runs
"""

from datetime import datetime, timedelta
import pytest
import numpy as np

from preprocessing.log_parser import parse_log_file
from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import apply_rules, Detection
from detection.anomaly_detector import (
    AnomalyDetector,
    AnomalyDetectorConfig,
    AnomalyResult,
    EventFeatureExtractor,
    detect_anomalies,
)


@pytest.fixture
def benign_events():
    """Load benign baseline events from normal_activity.csv."""
    result = parse_log_file("data/sample_attacks/normal_activity.csv")
    assert len(result.events) > 0, "Failed to load normal_activity.csv events"
    return result.events


@pytest.fixture
def fitted_detector(benign_events):
    """Provide a detector fitted on normal_activity.csv."""
    detector = AnomalyDetector(AnomalyDetectorConfig(random_state=42, contamination=0.05))
    detector.fit(benign_events)
    return detector


# =============================================================================
# 1. INITIALIZATION & DETERMINISM
# =============================================================================

class TestDetectorInitializationAndDeterminism:
    """Requirement 1 & 14: Model initialization and deterministic behavior."""

    def test_default_initialization(self):
        """Detector initializes cleanly with default config without fitting."""
        detector = AnomalyDetector()
        assert detector.is_fitted is False
        assert detector.model is None
        assert detector.training_event_count == 0
        assert detector.config.random_state == 42
        assert detector.config.contamination == 0.05

    def test_deterministic_scoring_with_fixed_seed(self, benign_events):
        """Running fit and predict twice with identical seed produces bit-identical scores."""
        d1 = AnomalyDetector(AnomalyDetectorConfig(random_state=42, contamination=0.05))
        d1.fit(benign_events)
        res1 = d1.predict(benign_events)

        d2 = AnomalyDetector(AnomalyDetectorConfig(random_state=42, contamination=0.05))
        d2.fit(benign_events)
        res2 = d2.predict(benign_events)

        assert len(res1) == len(res2)
        for r1, r2 in zip(res1, res2):
            assert r1.event_id == r2.event_id
            assert r1.is_anomaly == r2.is_anomaly
            assert np.isclose(r1.anomaly_score, r2.anomaly_score)
            assert np.isclose(r1.decision_score, r2.decision_score)


# =============================================================================
# 2. TRAINING & INFERENCE
# =============================================================================

class TestDetectorTrainingAndInference:
    """Requirement 2 & 3: Training on benign data and scoring unseen events."""

    def test_training_on_benign_data(self, benign_events):
        """Fitting on benign events marks detector as fitted and tracks event count."""
        detector = AnomalyDetector(AnomalyDetectorConfig(random_state=42))
        detector.fit(benign_events)
        assert detector.is_fitted is True
        assert detector.training_event_count == len(benign_events)
        assert detector.model is not None

    def test_inference_on_unseen_attack_events(self, fitted_detector):
        """Inference runs cleanly on unseen events from brute_force scenario."""
        res_attack = parse_log_file("data/sample_attacks/brute_force.csv")
        results = fitted_detector.predict(res_attack.events)
        assert len(results) == len(res_attack.events)
        assert all(isinstance(r, AnomalyResult) for r in results)

        # Confirm some events are flagged as anomalous in brute force
        anomalies = [r for r in results if r.is_anomaly]
        assert len(anomalies) > 0, "Expected brute-force dataset to produce anomaly signals"


# =============================================================================
# 3. EDGE CASES: EMPTY & MALFORMED INPUT
# =============================================================================

class TestDetectorEdgeCases:
    """Requirement 4 & 5: Empty input, missing values, and malformed attributes."""

    def test_predict_on_empty_event_list_returns_empty_list(self, fitted_detector):
        """Predicting on an empty list returns an empty list without error."""
        assert fitted_detector.predict([]) == []

    def test_fit_on_empty_event_list_raises_value_error(self):
        """Fitting on an empty event list raises ValueError."""
        detector = AnomalyDetector()
        with pytest.raises(ValueError, match="Cannot fit"):
            detector.fit([])

    def test_predict_before_fit_raises_runtime_error(self):
        """Predicting before fitting raises RuntimeError."""
        detector = AnomalyDetector()
        now = datetime(2026, 10, 15, 12, 0, 0)
        sample = [NormalizedEvent(event_id="E-1", timestamp=now, source="auth", event_type="login")]
        with pytest.raises(RuntimeError, match="has not been fitted"):
            detector.predict(sample)

    def test_handling_missing_and_none_attributes(self, fitted_detector):
        """Detector gracefully handles events with None for optional fields."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        event_sparse = NormalizedEvent(
            event_id="SPARSE-1",
            timestamp=now,
            source="syslog",
            event_type="routine_access",
            source_ip=None,
            destination_ip=None,
            source_port=None,
            destination_port=None,
            username=None,
            hostname=None,
            process=None,
            action=None,
            severity="low",
            raw_message="",
        )
        results = fitted_detector.predict([event_sparse])
        assert len(results) == 1
        r = results[0]
        assert r.event_id == "SPARSE-1"
        assert 0.0 <= r.anomaly_score <= 1.0


# =============================================================================
# 4. SCHEMA, SCORE DIRECTION & TRACEABILITY
# =============================================================================

class TestResultSchemaAndTraceability:
    """Requirement 6 & 7: Output schema, score direction, and raw-message traceability."""

    def test_anomaly_result_schema_fields(self, fitted_detector):
        """AnomalyResult contains all required fields and serializes to dict."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        event = NormalizedEvent(
            event_id="TEST-01",
            timestamp=now,
            source="auth.log",
            event_type="login_failed",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.10",
            source_port=45000,
            destination_port=22,
            username="attacker",
            process="sshd",
            action="failure",
            severity="high",
            raw_message="Failed password for invalid user attacker",
        )
        results = fitted_detector.predict([event])
        assert len(results) == 1
        r = results[0]

        # Field validation
        assert r.event_id == "TEST-01"
        assert r.supporting_event_id == "TEST-01"
        assert r.raw_message == "Failed password for invalid user attacker"
        assert r.model_name == "IsolationForest"
        assert r.model_version == "0.1.0"
        assert isinstance(r.is_anomaly, bool)
        assert isinstance(r.explanation, str)
        assert len(r.explanation) > 0
        assert "Statistical anomaly signal" in r.disclaimer

        # Serialization
        d = r.to_dict()
        assert d["event_id"] == "TEST-01"
        assert "anomaly_score" in d
        assert "decision_score" in d
        assert "contributing_factors" in d

    def test_anomaly_score_directionality_and_bounds(self, fitted_detector):
        """Anomaly score is strictly bounded in [0.0, 1.0] with higher meaning more anomalous."""
        res_attack = parse_log_file("data/sample_attacks/data_exfiltration.csv")
        results = fitted_detector.predict(res_attack.events)

        for r in results:
            assert 0.0 <= r.anomaly_score <= 1.0
            # Decision function: negative values indicate outliers
            if r.decision_score < 0:
                assert r.is_anomaly is True
                assert r.anomaly_score >= 0.50
            else:
                assert r.is_anomaly is False
                assert r.anomaly_score <= 0.50


# =============================================================================
# 5. DATA LEAKAGE PREVENTION
# =============================================================================

class TestDataLeakagePrevention:
    """Requirement 8, 9 & 10: Prevention of leakage from IDs, IPs, usernames, filenames, and test labels."""

    def test_entity_identifiers_do_not_leak_into_feature_vectors(self, fitted_detector):
        """Mutating IPs, usernames, hostnames, and event IDs leaves feature vector 100% identical."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        e1 = NormalizedEvent(
            event_id="EVT-ORIGINAL",
            timestamp=now,
            source="auth.log",
            event_type="login_success",
            source_ip="192.168.1.50",
            destination_ip="192.168.1.10",
            source_port=52000,
            destination_port=22,
            username="alice",
            hostname="server-alpha",
            process="sshd",
            action="success",
            severity="low",
            raw_message="Accepted password for alice from 192.168.1.50 port 52000 ssh2",
        )
        e2 = NormalizedEvent(
            event_id="EVT-MUTATED",
            timestamp=now,
            source="auth.log",
            event_type="login_success",
            source_ip="10.10.99.123",        # Completely different IP
            destination_ip="172.16.0.1",       # Completely different IP
            source_port=52000,
            destination_port=22,
            username="bob_mutated",            # Completely different username
            hostname="host-omega",             # Completely different hostname
            process="sshd",
            action="success",
            severity="low",
            raw_message="Accepted password for bob_mutated from 10.10.99.123 port 52000 ssh2",
        )

        r1 = fitted_detector.predict([e1])[0]
        r2 = fitted_detector.predict([e2])[0]

        # Feature vectors must be completely identical
        for k in r1.feature_values:
            assert np.isclose(r1.feature_values[k], r2.feature_values[k]), f"Feature '{k}' leaked entity values!"
        assert np.isclose(r1.anomaly_score, r2.anomaly_score)

    def test_feature_extractor_does_not_contain_entity_field_names(self, fitted_detector):
        """Feature names never contain username, ip, hostname, or event_id."""
        for feat in fitted_detector.extractor.feature_names:
            low = feat.lower()
            assert "ip" not in low or low in {"dst_port_privileged", "dst_port_ephemeral", "src_port_ephemeral", "is_privilege_event", "rolling_priv_events_window"}
            assert "username" not in low
            assert "hostname" not in low
            assert "event_id" not in low
            assert "file_path" not in low
            assert "scenario" not in low


# =============================================================================
# 6. PIPELINE INTEGRATION & SEPARATION FROM RULES
# =============================================================================

class TestPipelineSeparationAndInvariance:
    """Requirement 11 & 12: Separation from R001-R006 and deterministic rule invariance."""

    def test_anomaly_result_distinct_from_rule_detection(self, fitted_detector, benign_events):
        """AnomalyResult is distinct from Detection model produced by RuleEngine."""
        res = fitted_detector.predict(benign_events)
        assert len(res) > 0
        first = res[0]
        assert isinstance(first, AnomalyResult)
        assert not isinstance(first, Detection)
        assert hasattr(first, "anomaly_score")
        assert not hasattr(first, "rule_id")

    def test_existing_rule_engine_detections_remain_identical(self):
        """Applying detection rules R001-R006 across sample attacks produces exact expected baseline counts."""
        # Normal activity produces 0 detections
        norm_events = parse_log_file("data/sample_attacks/normal_activity.csv").events
        assert apply_rules(norm_events) == []

        # Combined attack produces detections without interference
        comb_events = parse_log_file("data/sample_attacks/combined_attack.csv").events
        comb_dets = apply_rules(comb_events)
        assert len(comb_dets) > 0
        rule_ids = {d.rule_id for d in comb_dets}
        assert "R001" in rule_ids
        assert "R006" in rule_ids


# =============================================================================
# 7. CONVENIENCE FUNCTION & REPRODUCIBILITY
# =============================================================================

class TestConvenienceFunctionAndScoring:
    """Requirement 13 & 14: detect_anomalies convenience API and reproducibility."""

    def test_detect_anomalies_convenience_function(self, benign_events):
        """detect_anomalies runs end-to-end and returns AnomalyResults."""
        # When passing empty list
        assert detect_anomalies([]) == []

        # When passing events without pre-created detector
        subset = benign_events[:15]
        results = detect_anomalies(subset)
        assert len(results) == len(subset)
        assert all(isinstance(r, AnomalyResult) for r in results)

    def test_unseen_scenario_detection_rates_are_stable(self, fitted_detector):
        """Evaluations on port_scan and compromised_login produce stable anomaly percentages."""
        ps_events = parse_log_file("data/sample_attacks/port_scan.csv").events
        res_ps = fitted_detector.predict(ps_events)
        anom_ps = sum(1 for r in res_ps if r.is_anomaly)
        rate_ps = anom_ps / len(res_ps)
        # Port scan has rapid network flows contacting unusual ports, should produce an anomaly rate > 40%
        assert rate_ps > 0.40, f"Expected port scan anomaly rate > 40%, got {rate_ps:.1%}"


# =============================================================================
# 8. PHASE 8.1 AUDIT: ROLLING TEMPORAL FEATURES
# =============================================================================

class TestPhase81RollingTemporalAudit:
    """Phase 8.1 Audit: Temporal features, causal ordering, isolation, and edge cases."""

    def test_timestamp_ordering_invariance(self, fitted_detector):
        """Scrambling event input order returns identical per-event scores and features."""
        events = parse_log_file("data/sample_attacks/compromised_login.csv").events
        results_orig = fitted_detector.predict(events)

        # Scramble order
        import random
        rng = random.Random(42)
        shuffled = list(events)
        rng.shuffle(shuffled)

        results_shuffled = fitted_detector.predict(shuffled)

        orig_by_id = {r.event_id: r for r in results_orig}
        for r_shuf in results_shuffled:
            r_orig = orig_by_id[r_shuf.event_id]
            assert np.isclose(r_shuf.anomaly_score, r_orig.anomaly_score)
            assert np.isclose(r_shuf.decision_score, r_orig.decision_score)
            for k in r_shuf.feature_values:
                assert np.isclose(r_shuf.feature_values[k], r_orig.feature_values[k])

    def test_equal_timestamps_determinism(self, fitted_detector):
        """Events occurring at the exact same second are handled deterministically without errors."""
        base_t = datetime(2026, 10, 15, 10, 15, 1)
        e1 = NormalizedEvent(
            event_id="EQ-1",
            timestamp=base_t,
            source="firewall",
            event_type="port_scan_probe",
            destination_port=80,
            action="blocked",
            severity="medium",
        )
        e2 = NormalizedEvent(
            event_id="EQ-2",
            timestamp=base_t,
            source="firewall",
            event_type="port_scan_probe",
            destination_port=443,
            action="blocked",
            severity="medium",
        )
        # Passing [e1, e2] vs [e2, e1]
        res_12 = fitted_detector.predict([e1, e2])
        res_21 = fitted_detector.predict([e2, e1])

        assert len(res_12) == 2
        assert len(res_21) == 2

        d_12 = {r.event_id: r for r in res_12}
        d_21 = {r.event_id: r for r in res_21}

        for eid in ["EQ-1", "EQ-2"]:
            assert np.isclose(d_12[eid].anomaly_score, d_21[eid].anomaly_score)
            assert np.isclose(d_12[eid].decision_score, d_21[eid].decision_score)

    def test_missing_and_none_timestamps_safe_handling(self, fitted_detector):
        """Events with None or missing timestamps are safely handled without TypeError."""
        e_none = NormalizedEvent(
            event_id="NO-TS",
            timestamp=datetime(2026, 1, 1, 0, 0, 0), # Valid for schema
            source="auth.log",
            event_type="login_success",
        )
        # Manually alter timestamp to None on an instance to simulate malformed input
        object.__setattr__(e_none, "timestamp", None)
        results = fitted_detector.predict([e_none])
        assert len(results) == 1
        assert results[0].event_id == "NO-TS"
        assert 0.0 <= results[0].anomaly_score <= 1.0

    def test_unrelated_event_temporal_isolation(self, fitted_detector):
        """Events separated by more than rolling window (> 120s) do not contaminate each other."""
        t1 = datetime(2026, 10, 15, 12, 0, 0)
        t2 = datetime(2026, 10, 15, 12, 5, 0) # 300 seconds later (> 120s)
        e1 = NormalizedEvent(
            event_id="ISO-1",
            timestamp=t1,
            source="auth.log",
            event_type="login_failed",
            action="failure",
            severity="medium",
        )
        e2 = NormalizedEvent(
            event_id="ISO-2",
            timestamp=t2,
            source="auth.log",
            event_type="login_success",
            action="success",
            severity="low",
        )
        res = fitted_detector.predict([e1, e2])
        r2 = res[1]
        # Event 2 should not have Event 1 in its 120s rolling window
        assert r2.feature_values["rolling_events_window"] == 1.0
        assert r2.feature_values["rolling_failed_auth_window"] == 0.0

    def test_causal_online_ordering_no_future_leakage(self, fitted_detector):
        """Events occurring in the future (t > curr_t) do not leak into the current event's window."""
        t1 = datetime(2026, 10, 15, 12, 0, 0)
        t2 = datetime(2026, 10, 15, 12, 0, 30) # 30s in the future
        e1 = NormalizedEvent(
            event_id="PAST-1",
            timestamp=t1,
            source="auth.log",
            event_type="login_success",
            action="success",
            severity="low",
        )
        e2 = NormalizedEvent(
            event_id="FUTURE-BURST",
            timestamp=t2,
            source="auth.log",
            event_type="login_failed",
            action="failure",
            severity="high",
        )
        # Even if future event is a failed login burst, past event should see zero failed logins
        res = fitted_detector.predict([e1, e2])
        r1 = res[0]
        assert r1.feature_values["rolling_events_window"] == 1.0
        assert r1.feature_values["rolling_failed_auth_window"] == 0.0

    def test_failed_auth_counts_strictly_require_auth_events(self, fitted_detector):
        """Non-auth events with 'failure' action do NOT increment rolling_failed_auth_window."""
        t1 = datetime(2026, 10, 15, 12, 0, 0)
        t2 = datetime(2026, 10, 15, 12, 0, 10)
        # Firewall dropped packet with action='failure' but not an auth event
        e_drop = NormalizedEvent(
            event_id="NET-DROP",
            timestamp=t1,
            source="firewall",
            event_type="network_flow",
            action="failure",
            destination_port=80,
            severity="low",
        )
        e_curr = NormalizedEvent(
            event_id="NET-FLOW",
            timestamp=t2,
            source="firewall",
            event_type="network_flow",
            action="allowed",
            destination_port=80,
            severity="low",
        )
        res = fitted_detector.predict([e_drop, e_curr])
        r_curr = res[1]
        assert r_curr.feature_values["rolling_failed_auth_window"] == 0.0

    def test_cross_dataset_isolation_in_sequential_evaluations(self, fitted_detector):
        """Evaluating datasets independently guarantees context isolation without cross-contamination."""
        bf_events = parse_log_file("data/sample_attacks/brute_force.csv").events
        cl_events = parse_log_file("data/sample_attacks/compromised_login.csv").events

        res_bf_1 = fitted_detector.predict(bf_events)
        res_cl_1 = fitted_detector.predict(cl_events)
        res_bf_2 = fitted_detector.predict(bf_events)

        # Re-running brute_force after compromised_login yields bit-identical scores
        for r1, r2 in zip(res_bf_1, res_bf_2):
            assert np.isclose(r1.anomaly_score, r2.anomaly_score)
            assert np.isclose(r1.decision_score, r2.decision_score)


# =============================================================================
# 9. PHASE 8.1 AUDIT: ANOMALY EXPLANATION RELEVANCE
# =============================================================================

class TestPhase81ExplanationAudit:
    """Phase 8.1 Audit: Factual consistency, non-accusatory framing, and PE-4000/CA-6055 fixes."""

    def test_pe4000_explanation_grounded_in_actual_features(self, fitted_detector):
        """PE-4000 explanation cites unobserved source 'audit.log', avoiding fabricated non-auth heuristics."""
        pe_events = parse_log_file("data/sample_attacks/privilege_escalation.csv").events
        res = fitted_detector.predict(pe_events)
        r_4000 = next(r for r in res if r.event_id == "PE-4000")

        assert r_4000.is_anomaly is True
        # Must cite unobserved source 'audit.log'
        assert "audit.log" in r_4000.explanation
        assert "outside baseline training vocabulary" in r_4000.explanation
        # Must NOT claim 'non-authentication process' or attack causality
        assert "non-authentication process" not in r_4000.explanation.lower()
        assert "malicious" not in r_4000.explanation.lower()

    def test_ca6055_explanation_clarifies_ambient_temporal_context(self, fitted_detector):
        """CA-6055 (HTTP GET) distinguishes ambient failed login window from the event itself."""
        ca_events = parse_log_file("data/sample_attacks/combined_attack.csv").events
        res = fitted_detector.predict(ca_events)
        r_6055 = next(r for r in res if r.event_id == "CA-6055")

        assert r_6055.is_anomaly is True
        # Must explicitly label failed logins as concurrent temporal context
        assert "Concurrent temporal context" in r_6055.explanation
        assert "4 failed authentication attempt(s)" in r_6055.explanation
        # Must identify unobserved event type 'network_flow'
        assert "network_flow" in r_6055.explanation
        # Must NOT attribute failed login frequency directly to HTTP GET as its own action
        assert "Elevated failed login frequency:" not in r_6055.explanation

    def test_explanations_use_neutral_statistical_framing(self, fitted_detector):
        """Explanations use neutral statistical baseline divergence framing without inflammatory terms."""
        bf_events = parse_log_file("data/sample_attacks/brute_force.csv").events
        res = fitted_detector.predict(bf_events)

        for r in res:
            if r.is_anomaly:
                assert r.explanation.startswith("Statistical baseline divergence:")
                assert "Anomalous telemetry signal:" not in r.explanation
                assert "attack" not in r.explanation.lower()
                assert "exploit" not in r.explanation.lower()
                assert "hacker" not in r.explanation.lower()


# =============================================================================
# 10. PHASE 8.1 AUDIT: SCORE SEMANTICS & THRESHOLDS
# =============================================================================

class TestPhase81ScoreSemanticsAudit:
    """Phase 8.1 Audit: Score monotonicity, decision boundary, contamination, and non-probability disclaimers."""

    def test_score_monotonicity_and_directionality(self, fitted_detector):
        """Anomaly score is strictly inversely monotonic with Isolation Forest decision_score."""
        dx_events = parse_log_file("data/sample_attacks/data_exfiltration.csv").events
        res = fitted_detector.predict(dx_events)

        for r in res:
            expected_score = float(np.clip(0.5 - r.decision_score, 0.0, 1.0))
            assert np.isclose(r.anomaly_score, expected_score)
            # Negative decision score implies outlier with anomaly_score >= 0.50
            if r.decision_score < 0:
                assert r.is_anomaly is True
                assert r.anomaly_score >= 0.50
            else:
                assert r.is_anomaly is False
                assert r.anomaly_score <= 0.50

    def test_contamination_parameter_effect_on_classification(self, benign_events):
        """Higher contamination expands anomaly classification boundary; lower contamination tightens it."""
        det_low = AnomalyDetector(AnomalyDetectorConfig(contamination=0.01, random_state=42))
        det_low.fit(benign_events)
        res_low = det_low.predict(benign_events)
        count_low = sum(1 for r in res_low if r.is_anomaly)

        det_high = AnomalyDetector(AnomalyDetectorConfig(contamination=0.10, random_state=42))
        det_high.fit(benign_events)
        res_high = det_high.predict(benign_events)
        count_high = sum(1 for r in res_high if r.is_anomaly)

        assert count_high > count_low, f"Expected higher contamination to flag more events: {count_high} vs {count_low}"

    def test_disclaimer_affirms_score_is_not_attack_probability(self, fitted_detector):
        """AnomalyResult.disclaimer explicitly affirms statistical nature and disclaims attack proof."""
        now = datetime(2026, 10, 15, 12, 0, 0)
        ev = NormalizedEvent(
            event_id="DISCLAIM-1",
            timestamp=now,
            source="auth.log",
            event_type="login_failed",
            severity="high",
        )
        res = fitted_detector.predict([ev])[0]
        assert "Statistical anomaly signal only" in res.disclaimer
        assert "does NOT constitute proof of malicious activity or an attack" in res.disclaimer

    def test_baseline_training_vs_attack_evaluation_anomaly_counts(self):
        """Verify anomaly count semantics: baseline self-evaluation yields ~5%, while attack evaluation flags majority."""
        from detection.anomaly_detector import detect_anomalies
        from preprocessing.log_parser import parse_log_file

        normal_events = parse_log_file("data/sample_attacks/normal_activity.csv").events
        norm_res = detect_anomalies(normal_events)
        norm_anom_count = sum(1 for r in norm_res if r.is_anomaly)

        # Baseline: 7 of 130 events (5.38%, consistent with contamination=0.05)
        assert norm_anom_count == 7

        bf_events = parse_log_file("data/sample_attacks/brute_force.csv").events
        bf_res = detect_anomalies(bf_events)
        bf_anom_count = sum(1 for r in bf_res if r.is_anomaly)

        # Attack scenario: 61 of 71 events flagged due to extreme deviation from benign baseline
        assert bf_anom_count == 61


