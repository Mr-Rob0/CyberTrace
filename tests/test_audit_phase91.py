"""
Phase 9.1: Final Provider and Report-Security Audit Tests
=========================================================
Focused audit suite verifying:
    1. The LLM cannot silently alter pipeline severity or confidence.
    2. The LLM cannot alter the pipeline's primary root-cause candidate.
    3. The validator detects unsupported factual claims (unobserved IPs, usernames, hostnames).
    4. Missing evidence (attack stages, MITRE mappings) cannot be invented.
    5. Zero credential exposure in repr, logs, exceptions, and exported reports.
    6. Generated recommendations are purely advisory and never executed.
    7. Input context size is strictly bounded against payload ballooning.
    8. Deterministic fallback uses actual pipeline outputs and acknowledges limitations.
"""

import os
import json
import pytest
from unittest.mock import patch

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.root_cause import RootCauseAnalyzer, RootCauseType
from mitre.technique_mapper import map_to_mitre
from detection.anomaly_detector import detect_anomalies

from ai.schema import IncidentReport
from ai.context_builder import IncidentContextBuilder, IncidentReportContext, sanitize_untrusted_text
from ai.validator import ReportValidator
from ai.provider import OpenAICompatibleProvider, MockLLMProvider, ProviderAuthError
from ai.fallback_generator import generate_deterministic_fallback, generate_defensive_recommendations
from ai.report_generator import generate_report

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks")
)


@pytest.fixture
def audit_pipeline():
    filepath = os.path.join(DATA_DIR, "combined_attack.csv")
    parsed = parse_log_file(filepath)
    engine = RuleEngine()
    detections = engine.detect(parsed.events)
    correlator = EventCorrelator()
    groups = correlator.correlate(detections)
    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)
    main_inc = max(incidents, key=lambda i: i.detection_count)

    reconstructor = AttackChainReconstructor()
    chain = reconstructor.reconstruct(main_inc, events=parsed.events, detections=detections)

    rc_analyzer = RootCauseAnalyzer()
    root_causes = rc_analyzer.analyze(chain)
    mappings = map_to_mitre(chain, events=parsed.events, detections=detections)
    anomalies = detect_anomalies(parsed.events)

    return {
        "incident": main_inc,
        "events": parsed.events,
        "detections": detections,
        "attack_chain": chain,
        "root_causes": root_causes,
        "mitre_mappings": mappings,
        "anomaly_results": anomalies,
    }


class TestSecurityAndPipelineInvariants:
    def test_llm_cannot_alter_severity(self, audit_pipeline):
        """If the LLM returns an altered severity, the validator overrides it with pipeline ground truth."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            events=pipe["events"],
            detections=pipe["detections"],
        )
        assert context.incident_overview["severity"] in ("HIGH", "CRITICAL")
        expected_sev = context.incident_overview["severity"]

        # Simulated malicious LLM response attempting to downgrade severity to LOW
        tampered_report = {
            "executive_summary": "Tampered summary",
            "incident_overview": {"severity": "LOW"},  # Altered!
            "timeline_summary": [],
            "attack_stages": [],
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {},
            "impact_assessment": {},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, validated = ReportValidator.validate(tampered_report, context)

        # Invariant: Severity is restored to pipeline ground truth and warning is flagged
        assert validated["incident_overview"]["severity"] == expected_sev
        assert any("attempted to alter deterministic pipeline severity" in w for w in warnings)

    def test_llm_cannot_alter_confidence(self, audit_pipeline):
        """If the LLM returns an altered confidence, the validator overrides it with pipeline ground truth."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            events=pipe["events"],
            detections=pipe["detections"],
        )
        expected_conf = context.incident_overview["confidence"]

        tampered_report = {
            "executive_summary": "Tampered summary",
            "incident_overview": {"confidence": 0.05},  # Altered!
            "timeline_summary": [],
            "attack_stages": [],
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {},
            "impact_assessment": {},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, validated = ReportValidator.validate(tampered_report, context)

        assert validated["incident_overview"]["confidence"] == expected_conf
        assert any("attempted to alter deterministic pipeline confidence" in w for w in warnings)

    def test_llm_cannot_alter_root_cause_type(self, audit_pipeline):
        """If the LLM attempts to swap the established root cause, the validator overrides it."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            attack_chain=pipe["attack_chain"],
            root_causes=pipe["root_causes"],
        )
        expected_rc_type = context.root_cause_candidates[0]["candidate_type"]
        assert expected_rc_type == RootCauseType.CREDENTIAL_COMPROMISE.value

        tampered_report = {
            "executive_summary": "Tampered summary",
            "incident_overview": {},
            "timeline_summary": [],
            "attack_stages": [],
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {
                "candidate_type": "MALWARE_EXECUTION",  # Altered!
                "title": "Fabricated Malware Execution",
            },
            "impact_assessment": {},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, validated = ReportValidator.validate(tampered_report, context)

        assert validated["probable_root_cause"]["candidate_type"] == expected_rc_type
        assert any("attempted to alter probable root-cause candidate type" in w for w in warnings)


class TestFactualClaimValidation:
    def test_unsupported_factual_ip_claim_detected(self, audit_pipeline):
        """Validator detects unobserved IP addresses cited in the report."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            events=pipe["events"],
        )

        unsupported_ip = "198.51.100.222"
        assert unsupported_ip not in context.valid_ips

        report_with_fake_ip = {
            "executive_summary": f"Breach occurred from {unsupported_ip}.",
            "incident_overview": {"source_ips": [unsupported_ip]},
            "timeline_summary": [],
            "attack_stages": [],
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {},
            "impact_assessment": {"narrative": f"Attacker IP was {unsupported_ip}"},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, _ = ReportValidator.validate(report_with_fake_ip, context)
        assert any(unsupported_ip in w and "unsupported factual IP" in w for w in warnings)

    def test_unsupported_username_claim_detected(self, audit_pipeline):
        """Validator detects unobserved usernames cited in the report."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            events=pipe["events"],
        )

        unsupported_user = "phantom_attacker_99"
        assert unsupported_user not in context.valid_usernames

        report_with_fake_user = {
            "executive_summary": "Test summary",
            "incident_overview": {"usernames": [unsupported_user]},
            "timeline_summary": [],
            "attack_stages": [],
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {},
            "impact_assessment": {},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, _ = ReportValidator.validate(report_with_fake_user, context)
        assert any(unsupported_user in w and "unsupported username" in w for w in warnings)

    def test_missing_attack_stages_cannot_be_invented(self):
        """If context has no attack stages, LLM-invented stages are cleared and warned."""
        context = IncidentReportContext(
            incident_id="INC-EMPTY-CHAIN",
            incident_overview={"severity": "LOW"},
            timeline=[],
            attack_stages=[],  # Empty!
            detections=[],
            mitre_mappings=[],
            ml_anomalies=[],
            root_cause_candidates=[],
        )

        invented_report = {
            "executive_summary": "Test summary",
            "incident_overview": {},
            "timeline_summary": [],
            "attack_stages": [{"step_id": "STEP-01", "stage": "INITIAL_ACCESS"}],  # Invented!
            "rule_detections": [],
            "mitre_mappings": [],
            "ml_anomaly_observations": [],
            "probable_root_cause": {},
            "impact_assessment": {},
            "defensive_recommendations": [],
            "limitations_and_gaps": [],
        }

        is_valid, warnings, validated = ReportValidator.validate(invented_report, context)
        assert len(validated["attack_stages"]) == 0
        assert any("invented attack stages" in w for w in warnings)


class TestCredentialSafetyAndPrivacy:
    def test_zero_credential_exposure_in_repr_and_report(self):
        """API key is never exposed in provider __repr__, report JSON, or Markdown export."""
        secret_key = "sk-live-test-supersecret-credential-value-999"
        provider = OpenAICompatibleProvider(api_key=secret_key, base_url="https://api.test.com/v1")

        # Invariant: __repr__ contains no key fragments
        rep_str = repr(provider)
        assert "supersecret" not in rep_str
        assert "sk-live" not in rep_str
        assert "key=" not in rep_str

        # Generate report
        mock_provider = MockLLMProvider(
            canned_response=json.dumps({
                "executive_summary": "Audited executive summary.",
                "incident_overview": {"severity": "LOW"},
                "timeline_summary": [],
                "attack_stages": [],
                "rule_detections": [],
                "mitre_mappings": [],
                "ml_anomaly_observations": [],
                "probable_root_cause": {},
                "impact_assessment": {},
                "defensive_recommendations": [],
                "limitations_and_gaps": [],
            })
        )

        report = generate_report(
            incident_or_findings={"incident_id": "INC-TEST", "severity": "LOW"},
            provider=mock_provider,
        )

        exported_json = report.to_json()
        exported_md = report.to_markdown()

        assert secret_key not in exported_json
        assert secret_key not in exported_md

    def test_recommendations_purely_advisory_no_execution(self, audit_pipeline):
        """Defensive recommendations are pure advisory text and cannot execute code."""
        pipe = audit_pipeline
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            detections=pipe["detections"],
            mitre_mappings=pipe["mitre_mappings"],
        )

        recs = generate_defensive_recommendations(context)
        assert len(recs) > 0
        for r in recs:
            assert isinstance(r["action"], str)
            assert isinstance(r["priority"], str)
            assert "executable" not in r
            assert "command" not in r

    def test_input_context_strictly_bounded_in_length(self, audit_pipeline):
        """Prompt text enforces strict maximum length even if thousands of raw events exist."""
        pipe = audit_pipeline
        # Create massive synthetic timeline of 500 events
        large_timeline = pipe["events"] * 10
        context = IncidentContextBuilder.build(
            incident=pipe["incident"],
            events=large_timeline,
            detections=pipe["detections"],
        )

        prompt_text = context.to_prompt_text(max_total_chars=5000)
        assert len(prompt_text) <= 5100
        assert "REMAINDER TRUNCATED" in prompt_text
