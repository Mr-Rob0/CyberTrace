"""
Unit Tests for preprocessing/normalizer.py
=========================================
Tests verify:
    - Timestamp parsing across supported string formats.
    - Port conversion to integer and boundary validation.
    - IP address validation and canonicalization.
    - Severity normalization.
    - Empty string and NaN conversion to None.
    - Case normalization of categorical fields.
    - Preservation of event_id and raw_message.
    - Absence of attack labels.
    - Batch normalization via normalize_events.
"""

from datetime import datetime
import pytest

from preprocessing.normalizer import (
    parse_timestamp,
    normalize_port,
    normalize_ip,
    normalize_severity,
    EventNormalizer,
    normalize_events,
)
from preprocessing.event_schema import NormalizedEvent


class TestFieldNormalizers:
    """Test individual field normalization utility functions."""

    def test_parse_timestamp_standard_format(self):
        dt = parse_timestamp("2026-10-15 08:30:45")
        assert dt == datetime(2026, 10, 15, 8, 30, 45)

    def test_parse_timestamp_iso_format(self):
        dt = parse_timestamp("2026-10-15T08:30:45")
        assert dt == datetime(2026, 10, 15, 8, 30, 45)

    def test_parse_timestamp_datetime_passthrough(self):
        original = datetime(2026, 10, 15, 8, 30, 45)
        dt = parse_timestamp(original)
        assert dt == original

    def test_parse_timestamp_empty_raises_value_error(self):
        with pytest.raises(ValueError, match="empty or missing"):
            parse_timestamp("")
        with pytest.raises(ValueError, match="empty or missing"):
            parse_timestamp(None)

    def test_parse_timestamp_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="Unable to parse timestamp"):
            parse_timestamp("not-a-timestamp-123")

    def test_normalize_port_valid_strings(self):
        assert normalize_port("80") == 80
        assert normalize_port("443") == 443
        assert normalize_port(22) == 22
        assert normalize_port("8080.0") == 8080

    def test_normalize_port_empty_becomes_none(self):
        assert normalize_port("") is None
        assert normalize_port("   ") is None
        assert normalize_port(None) is None
        assert normalize_port("nan") is None

    def test_normalize_port_invalid_string_raises_value_error(self):
        with pytest.raises(ValueError, match="cannot be converted to integer"):
            normalize_port("http")

    def test_normalize_port_out_of_range_raises_value_error(self):
        with pytest.raises(ValueError, match="out of valid range"):
            normalize_port("70000")
        with pytest.raises(ValueError, match="out of valid range"):
            normalize_port("-5")

    def test_normalize_ip_valid(self):
        assert normalize_ip("192.168.1.1") == "192.168.1.1"
        assert normalize_ip("10.0.0.120") == "10.0.0.120"
        assert normalize_ip("127.0.0.1") == "127.0.0.1"
        assert normalize_ip("::1") == "::1"

    def test_normalize_ip_empty_becomes_none(self):
        assert normalize_ip("") is None
        assert normalize_ip("   ") is None
        assert normalize_ip(None) is None
        assert normalize_ip("nan") is None

    def test_normalize_ip_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid IP address"):
            normalize_ip("999.999.999.999")
        with pytest.raises(ValueError, match="Invalid IP address"):
            normalize_ip("192.168.1.300")
        with pytest.raises(ValueError, match="Invalid IP address"):
            normalize_ip("not_an_ip")

    def test_normalize_severity_standard_levels(self):
        assert normalize_severity("LOW") == "low"
        assert normalize_severity("Medium") == "medium"
        assert normalize_severity("HIGH") == "high"
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("info") == "info"

    def test_normalize_severity_synonyms(self):
        assert normalize_severity("warn") == "medium"
        assert normalize_severity("warning") == "medium"
        assert normalize_severity("error") == "high"
        assert normalize_severity("crit") == "critical"

    def test_normalize_severity_empty_defaults_to_low(self):
        assert normalize_severity("") == "low"
        assert normalize_severity(None) == "low"

    def test_normalize_severity_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="Unrecognized severity"):
            normalize_severity("extreme_danger")


class TestRecordNormalization:
    """Test full dictionary record normalization through EventNormalizer."""

    def test_normalize_valid_record(self):
        raw = {
            "timestamp": "2026-10-15 09:15:02",
            "source": "AUTH.LOG",
            "event_type": "LOGIN_SUCCESS",
            "source_ip": "192.168.1.105",
            "destination_ip": "192.168.1.20",
            "source_port": "40041",
            "destination_port": "22",
            "username": "admin",
            "hostname": "srv-auth-01",
            "process": "sshd",
            "action": "SUCCESS",
            "severity": "HIGH",
            "raw_message": "Accepted password for admin from 192.168.1.105 port 40041 ssh2",
            "event_id": "BF-1041",
        }

        normalizer = EventNormalizer()
        event = normalizer.normalize_record(raw)

        assert isinstance(event, NormalizedEvent)
        assert event.event_id == "BF-1041"
        assert event.timestamp == datetime(2026, 10, 15, 9, 15, 2)
        assert event.source == "auth.log"           # Lowercase normalized
        assert event.event_type == "login_success"   # Lowercase normalized
        assert event.source_ip == "192.168.1.105"
        assert event.destination_ip == "192.168.1.20"
        assert event.source_port == 40041           # Converted to int
        assert event.destination_port == 22         # Converted to int
        assert event.username == "admin"
        assert event.hostname == "srv-auth-01"
        assert event.process == "sshd"
        assert event.action == "success"            # Lowercase normalized
        assert event.severity == "high"             # Lowercase normalized
        assert event.raw_message == "Accepted password for admin from 192.168.1.105 port 40041 ssh2"

    def test_empty_fields_become_none(self):
        raw = {
            "timestamp": "2026-10-15 10:00:33",
            "source": "firewall",
            "event_type": "network_flow",
            "source_ip": "192.168.1.25",
            "destination_ip": "192.168.1.10",
            "source_port": "",
            "destination_port": "443",
            "username": "",
            "hostname": "fw-core-01",
            "process": "",
            "action": "allowed",
            "severity": "low",
            "raw_message": "PASS",
            "event_id": "PS-2000",
        }

        normalizer = EventNormalizer()
        event = normalizer.normalize_record(raw)

        assert event.source_port is None
        assert event.destination_port == 443
        assert event.username is None
        assert event.process is None

    def test_missing_event_id_raises_value_error(self):
        raw = {
            "timestamp": "2026-10-15 10:00:00",
            "source": "firewall",
            "event_type": "flow",
            "event_id": "",
        }
        normalizer = EventNormalizer()
        with pytest.raises(ValueError, match="missing required 'event_id'"):
            normalizer.normalize_record(raw)

    def test_missing_mandatory_source_raises_value_error(self):
        raw = {
            "timestamp": "2026-10-15 10:00:00",
            "source": "",
            "event_type": "flow",
            "event_id": "TEST-01",
        }
        normalizer = EventNormalizer()
        with pytest.raises(ValueError, match="missing required 'source'"):
            normalizer.normalize_record(raw)

    def test_no_attack_labels_introduced_during_normalization(self):
        raw = {
            "timestamp": "2026-10-15 10:00:00",
            "source": "firewall",
            "event_type": "port_scan_probe",
            "event_id": "TEST-01",
            "raw_message": "SYN flood probe detected",
        }
        normalizer = EventNormalizer()
        event = normalizer.normalize_record(raw)
        data = event.to_dict()

        for forbidden in ["attack_stage", "attack_label", "is_attack", "malicious"]:
            assert forbidden not in data, f"Forbidden label '{forbidden}' introduced in normalization"


class TestNormalizeEventsBatch:
    """Test batch normalization using normalize_events function."""

    def test_normalize_empty_list(self):
        assert normalize_events([]) == []

    def test_normalize_list_of_dicts(self):
        records = [
            {
                "timestamp": "2026-10-15 08:30:00",
                "source": "auth.log",
                "event_type": "login_success",
                "event_id": "EVT-1",
            },
            {
                "timestamp": "2026-10-15 08:31:00",
                "source": "auth.log",
                "event_type": "login_failed",
                "event_id": "EVT-2",
            },
        ]
        result = normalize_events(records)
        assert len(result) == 2
        assert all(isinstance(e, NormalizedEvent) for e in result)
        assert result[0].event_id == "EVT-1"
        assert result[1].event_id == "EVT-2"

    def test_normalize_already_normalized_passthrough(self):
        event = NormalizedEvent(
            event_id="EVT-ALREADY",
            timestamp=datetime(2026, 10, 15, 8, 30, 0),
            source="syslog",
            event_type="test",
        )
        result = normalize_events([event])
        assert result[0] is event
