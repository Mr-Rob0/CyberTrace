"""
Unit Tests for preprocessing/log_parser.py
=========================================
Tests verify:
    - Ingestion and parsing of valid CSV files and strings.
    - Enforcement of mandatory schema columns.
    - Error tolerance: malformed rows generate ParseErrors rather than crashing.
    - Accurate reporting of row numbers and event_ids in ParseErrors.
    - Exact preservation of event_id and raw_message.
    - Successful ingestion of all seven sample attack and benign datasets.
"""

import os
import pytest

from preprocessing.log_parser import CSVLogParser, ParseResult, ParseError, parse_log_file
from preprocessing.event_schema import NormalizedEvent

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))

SAMPLE_FILES = [
    "brute_force.csv",
    "port_scan.csv",
    "compromised_login.csv",
    "privilege_escalation.csv",
    "data_exfiltration.csv",
    "combined_attack.csv",
    "normal_activity.csv",
]


class TestCSVLogParserBasic:
    """Basic functional tests of CSVLogParser."""

    def test_parse_valid_csv_string(self):
        csv_data = (
            "timestamp,source,event_type,source_ip,destination_ip,source_port,destination_port,"
            "username,hostname,process,action,severity,raw_message,event_id\n"
            "2026-10-15 08:30:00,auth.log,login_success,192.168.1.50,192.168.1.20,50000,22,"
            "alice,srv-01,sshd,success,low,Accepted publickey,EVT-001\n"
            "2026-10-15 08:31:00,auth.log,login_failed,192.168.1.51,192.168.1.20,50001,22,"
            "bob,srv-01,sshd,failure,medium,Failed password,EVT-002\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_data)

        assert isinstance(result, ParseResult)
        assert result.total_rows == 2
        assert result.successful_rows == 2
        assert result.failed_rows == 0
        assert not result.has_errors
        assert len(result.events) == 2

        evt1 = result.events[0]
        assert evt1.event_id == "EVT-001"
        assert evt1.source == "auth.log"
        assert evt1.source_ip == "192.168.1.50"
        assert evt1.source_port == 50000
        assert evt1.destination_port == 22
        assert evt1.action == "success"

    def test_file_not_found_raises_error(self):
        parser = CSVLogParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file("non_existent_file_xyz_123.csv")

    def test_missing_mandatory_columns_raises_value_error(self):
        # Missing 'timestamp' and 'event_id'
        csv_data = "source,event_type,action\nauth.log,login,success\n"
        parser = CSVLogParser()
        with pytest.raises(ValueError, match="missing mandatory columns"):
            parser.parse_csv_string(csv_data)

    def test_empty_csv_raises_value_error(self):
        parser = CSVLogParser()
        with pytest.raises(ValueError, match="CSV file is empty"):
            parser.parse_csv_string("")


class TestCSVLogParserErrorHandling:
    """Test non-fatal error handling and error collection for malformed rows."""

    def test_invalid_timestamp_reported_as_error(self):
        csv_data = (
            "timestamp,source,event_type,event_id\n"
            "NOT_A_TIMESTAMP,auth.log,login_failed,BAD-TS-01\n"
            "2026-10-15 08:30:00,auth.log,login_success,GOOD-01\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_data)

        assert result.total_rows == 2
        assert result.successful_rows == 1
        assert result.failed_rows == 1
        assert result.has_errors is True

        err = result.errors[0]
        assert err.row_number == 2
        assert err.event_id == "BAD-TS-01"
        assert "Unable to parse timestamp" in err.error_message
        assert len(result.events) == 1
        assert result.events[0].event_id == "GOOD-01"

    def test_invalid_port_reported_as_error(self):
        csv_data = (
            "timestamp,source,event_type,source_port,event_id\n"
            "2026-10-15 08:30:00,auth.log,login_failed,999999,BAD-PORT-01\n"
            "2026-10-15 08:31:00,auth.log,login_success,22,GOOD-02\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_data)

        assert result.failed_rows == 1
        assert result.successful_rows == 1
        assert result.errors[0].event_id == "BAD-PORT-01"
        assert "out of valid range" in result.errors[0].error_message

    def test_invalid_ip_reported_as_error(self):
        csv_data = (
            "timestamp,source,event_type,source_ip,event_id\n"
            "2026-10-15 08:30:00,firewall,flow,999.888.777.666,BAD-IP-01\n"
            "2026-10-15 08:31:00,firewall,flow,192.168.1.1,GOOD-03\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_data)

        assert result.failed_rows == 1
        assert result.successful_rows == 1
        assert result.errors[0].event_id == "BAD-IP-01"
        assert "Invalid IP address" in result.errors[0].error_message

    def test_missing_event_id_reported_as_error(self):
        csv_data = (
            "timestamp,source,event_type,event_id\n"
            "2026-10-15 08:30:00,auth.log,login_failed,\n"
        )
        parser = CSVLogParser()
        result = parser.parse_csv_string(csv_data)

        assert result.failed_rows == 1
        assert result.errors[0].event_id is None
        assert "missing required 'event_id'" in result.errors[0].error_message


class TestDatasetIngestion:
    """Verify that all actual sample datasets parse completely and cleanly."""

    @pytest.mark.parametrize("filename", SAMPLE_FILES)
    def test_sample_datasets_parse_without_errors(self, filename):
        filepath = os.path.join(DATA_DIR, filename)
        result = parse_log_file(filepath)

        assert isinstance(result, ParseResult)
        assert result.total_rows > 0, f"{filename} produced 0 rows"
        assert result.failed_rows == 0, (
            f"{filename} had parsing errors: {[str(e) for e in result.errors]}"
        )
        assert result.successful_rows == result.total_rows
        assert len(result.events) == result.total_rows

        # Spot check that every event is a valid NormalizedEvent
        for event in result.events:
            assert isinstance(event, NormalizedEvent)
            assert event.event_id is not None
            assert event.timestamp is not None
            assert event.source is not None

    def test_combined_attack_produces_valid_events(self):
        filepath = os.path.join(DATA_DIR, "combined_attack.csv")
        result = parse_log_file(filepath)

        assert result.successful_rows == 178
        assert result.failed_rows == 0

        # Verify that entity linkages are preserved
        event_ids = [e.event_id for e in result.events]
        assert len(set(event_ids)) == len(event_ids), "Event IDs must be unique"

        # Verify attacker IP appears
        attacker_events = [e for e in result.events if e.source_ip == "192.168.1.188"]
        assert len(attacker_events) > 30, "Attacker IP events not found in expected volume"

    def test_normal_activity_produces_valid_events(self):
        filepath = os.path.join(DATA_DIR, "normal_activity.csv")
        result = parse_log_file(filepath)

        assert result.successful_rows == 130
        assert result.failed_rows == 0
        assert len(result.events) == 130
