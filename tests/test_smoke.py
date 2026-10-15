"""
Smoke Tests for CyberTrace
===========================
These tests verify that:
    1. All project modules can be imported without errors.
    2. The event schema works correctly.
    3. The config module loads properly.
    4. The logger works correctly.

Run with: pytest tests/test_smoke.py -v
"""

import pytest


class TestModuleImports:
    """Test that all project modules can be imported successfully."""

    def test_import_preprocessing(self):
        """Verify preprocessing package imports."""
        import preprocessing
        import preprocessing.log_parser
        import preprocessing.normalizer
        import preprocessing.event_schema

    def test_import_detection(self):
        """Verify detection package imports."""
        import detection
        import detection.rule_engine
        import detection.anomaly_detector
        import detection.classifier

    def test_import_correlation(self):
        """Verify correlation package imports."""
        import correlation
        import correlation.event_correlator
        import correlation.timeline_builder
        import correlation.incident_detector

    def test_import_reconstruction(self):
        """Verify reconstruction package imports."""
        import reconstruction
        import reconstruction.attack_chain
        import reconstruction.attack_graph
        import reconstruction.root_cause

    def test_import_mitre(self):
        """Verify MITRE package imports."""
        import mitre
        import mitre.technique_mapper

    def test_import_response(self):
        """Verify response package imports."""
        import response
        import response.risk_scoring
        import response.prevention
        import response.what_if

    def test_import_ai(self):
        """Verify AI package imports."""
        import ai
        import ai.report_generator

    def test_import_visualization(self):
        """Verify visualization package imports."""
        import visualization
        import visualization.timeline
        import visualization.graph

    def test_import_utils(self):
        """Verify utils package imports."""
        import utils
        import utils.config
        import utils.logger


class TestEventSchema:
    """Test the event schema module."""

    def test_common_event_fields_exist(self):
        """Verify that COMMON_EVENT_FIELDS is defined and non-empty."""
        from preprocessing.event_schema import COMMON_EVENT_FIELDS

        assert isinstance(COMMON_EVENT_FIELDS, list)
        assert len(COMMON_EVENT_FIELDS) > 0

    def test_common_event_fields_contain_key_fields(self):
        """Verify that essential fields are present in the schema."""
        from preprocessing.event_schema import COMMON_EVENT_FIELDS

        essential_fields = ["timestamp", "source", "event_type", "source_ip", "severity"]
        for field in essential_fields:
            assert field in COMMON_EVENT_FIELDS, f"Missing essential field: {field}"

    def test_create_empty_event(self):
        """Verify that create_empty_event returns a proper dict with all fields as None."""
        from preprocessing.event_schema import create_empty_event, COMMON_EVENT_FIELDS

        event = create_empty_event()

        assert isinstance(event, dict)
        assert len(event) == len(COMMON_EVENT_FIELDS)

        # Every field should exist and be None
        for field in COMMON_EVENT_FIELDS:
            assert field in event, f"Missing field in empty event: {field}"
            assert event[field] is None, f"Field {field} should be None, got {event[field]}"


class TestConfig:
    """Test the configuration module."""

    def test_project_name(self):
        """Verify the project name is set correctly."""
        from utils.config import PROJECT_NAME

        assert PROJECT_NAME == "CyberTrace"

    def test_project_version(self):
        """Verify the project version is set."""
        from utils.config import PROJECT_VERSION

        assert PROJECT_VERSION is not None
        assert len(PROJECT_VERSION) > 0

    def test_get_config_with_default(self):
        """Verify get_config returns default when env var is not set."""
        from utils.config import get_config

        result = get_config("THIS_VARIABLE_DOES_NOT_EXIST_12345", "my_default")
        assert result == "my_default"


class TestLogger:
    """Test the logger module."""

    def test_get_logger(self):
        """Verify that get_logger returns a proper Logger instance."""
        from utils.logger import get_logger
        import logging

        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"

    def test_logger_can_log(self):
        """Verify that the logger can log messages without errors."""
        from utils.logger import get_logger

        logger = get_logger("test_logging")
        # These should not raise any exceptions
        logger.info("Smoke test: info message")
        logger.warning("Smoke test: warning message")
        logger.debug("Smoke test: debug message")


class TestPlaceholderFunctions:
    """Verify that placeholder functions raise NotImplementedError as expected."""

    def test_parse_log_file_implemented(self):
        """Log parser is implemented and callable."""
        from preprocessing.log_parser import parse_log_file
        assert callable(parse_log_file)

    def test_normalize_events_implemented(self):
        """Normalizer is implemented and callable."""
        from preprocessing.normalizer import normalize_events
        assert normalize_events([]) == []

    def test_apply_rules_implemented(self):
        """Rule engine is implemented and callable."""
        from detection.rule_engine import apply_rules
        assert apply_rules([]) == []

    def test_detect_anomalies_implemented(self):
        """Anomaly detector is implemented and callable."""
        from detection.anomaly_detector import detect_anomalies
        assert callable(detect_anomalies)
        assert detect_anomalies([]) == []

    def test_correlate_events_implemented(self):
        """Event correlator is implemented and callable."""
        from correlation.event_correlator import correlate_events
        assert correlate_events([]) == []

    def test_build_attack_chain_implemented(self):
        """Attack chain builder is implemented and callable."""
        from reconstruction.attack_chain import build_attack_chain
        assert callable(build_attack_chain)

    def test_build_attack_graph_implemented(self):
        """Attack graph builder is implemented and callable."""
        from reconstruction.attack_graph import build_attack_graph
        assert callable(build_attack_graph)

    def test_identify_root_cause_implemented(self):
        """Root cause analyzer is implemented and callable."""
        from reconstruction.root_cause import identify_root_cause
        assert callable(identify_root_cause)

    def test_map_to_mitre_implemented(self):
        """MITRE technique mapper is implemented and callable."""
        from mitre.technique_mapper import map_to_mitre
        assert callable(map_to_mitre)
        assert map_to_mitre([]) == []

    def test_generate_report_implemented(self):
        """Report generator is implemented and callable."""
        from ai.report_generator import generate_report

        assert callable(generate_report)
        report = generate_report({})
        assert report is not None
        assert report.incident_id is not None

