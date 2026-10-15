"""
Unit Tests for preprocessing/event_schema.py
============================================
Tests verify:
    - Creation of NormalizedEvent instances.
    - Type validations (timestamp, ports, IP, severity).
    - Preservation of event_id and raw_message.
    - Absence of attack labels / ground-truth leaks.
    - Deterministic derived boolean properties (is_auth_event, is_network_event, etc.).
    - Serialization to dict via to_dict().
"""

from datetime import datetime
import pytest

from preprocessing.event_schema import (
    NormalizedEvent,
    COMMON_EVENT_FIELDS,
    VALID_SEVERITIES,
    create_empty_event,
)


def make_valid_event(**kwargs):
    """Helper to create a valid baseline NormalizedEvent with overrides."""
    base = {
        "event_id": "EVT-101",
        "timestamp": datetime(2026, 10, 15, 9, 30, 0),
        "source": "auth.log",
        "event_type": "login_failed",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "source_port": 49152,
        "destination_port": 22,
        "username": "admin",
        "hostname": "srv-auth",
        "process": "sshd",
        "action": "failure",
        "severity": "medium",
        "raw_message": "Failed password for admin",
    }
    base.update(kwargs)
    return NormalizedEvent(**base)


class TestEventSchemaModel:
    """Test the core NormalizedEvent dataclass."""

    def test_create_valid_event(self):
        """A properly formatted event instantiates without issues."""
        event = make_valid_event()
        assert event.event_id == "EVT-101"
        assert event.timestamp == datetime(2026, 10, 15, 9, 30, 0)
        assert event.source == "auth.log"
        assert event.event_type == "login_failed"
        assert event.source_ip == "192.168.1.50"
        assert event.destination_ip == "192.168.1.10"
        assert event.source_port == 49152
        assert event.destination_port == 22
        assert event.username == "admin"
        assert event.hostname == "srv-auth"
        assert event.process == "sshd"
        assert event.action == "failure"
        assert event.severity == "medium"
        assert event.raw_message == "Failed password for admin"

    def test_evidence_preservation(self):
        """Event ID and raw message must remain exact and unmodified."""
        raw_msg = "Original Unmodified Syslog String: proto=TCP len=512 ID=998822"
        event = make_valid_event(event_id="CRITICAL-EVIDENCE-42", raw_message=raw_msg)
        assert event.event_id == "CRITICAL-EVIDENCE-42"
        assert event.raw_message == raw_msg

    def test_no_attack_labels_present(self):
        """NormalizedEvent model must never expose an attack label or stage."""
        event = make_valid_event()
        assert not hasattr(event, "attack_label")
        assert not hasattr(event, "attack_stage")
        assert not hasattr(event, "is_attack")
        assert "attack_label" not in event.to_dict()
        assert "attack_stage" not in event.to_dict()

    def test_empty_event_id_raises_value_error(self):
        """An event without an event_id must fail validation."""
        with pytest.raises(ValueError, match="event_id must not be empty"):
            make_valid_event(event_id="")

    def test_invalid_timestamp_type_raises_type_error(self):
        """Non-datetime timestamp must raise TypeError."""
        with pytest.raises(TypeError, match="timestamp must be a datetime"):
            make_valid_event(timestamp="2026-10-15 09:30:00")

    def test_invalid_severity_raises_value_error(self):
        """Severity not in allowed list raises ValueError."""
        with pytest.raises(ValueError, match="Invalid severity"):
            make_valid_event(severity="catastrophic")

    def test_invalid_port_range_raises_value_error(self):
        """Ports outside 0-65535 must raise ValueError."""
        with pytest.raises(ValueError, match="source_port must be between"):
            make_valid_event(source_port=70000)

        with pytest.raises(ValueError, match="destination_port must be between"):
            make_valid_event(destination_port=-1)

    def test_invalid_port_type_raises_type_error(self):
        """Non-integer port must raise TypeError."""
        with pytest.raises(TypeError, match="must be an integer"):
            make_valid_event(source_port="80")

    def test_invalid_ip_raises_value_error(self):
        """Malformed IP strings must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid source_ip"):
            make_valid_event(source_ip="999.999.999.999")

        with pytest.raises(ValueError, match="Invalid destination_ip"):
            make_valid_event(destination_ip="not_an_ip")

    def test_optional_fields_can_be_none(self):
        """All non-mandatory fields must be safely allowed to be None."""
        event = NormalizedEvent(
            event_id="MINIMAL-01",
            timestamp=datetime(2026, 10, 15, 12, 0, 0),
            source="syslog",
            event_type="heartbeat",
        )
        assert event.source_ip is None
        assert event.destination_ip is None
        assert event.source_port is None
        assert event.destination_port is None
        assert event.username is None
        assert event.hostname is None
        assert event.process is None
        assert event.action is None
        assert event.severity == "low"
        assert event.raw_message == ""


class TestDerivedBooleanProperties:
    """Verify that derived fields are purely deterministic functions of raw fields."""

    def test_is_auth_event(self):
        auth_evt = make_valid_event(source="auth.log", event_type="login_failed")
        assert auth_evt.is_auth_event is True

        pam_evt = make_valid_event(source="syslog", event_type="session_opened")
        assert pam_evt.is_auth_event is True

        dns_evt = make_valid_event(source="firewall", event_type="dns_query")
        assert dns_evt.is_auth_event is False

    def test_is_network_event(self):
        fw_evt = make_valid_event(source="firewall", event_type="network_flow")
        assert fw_evt.is_network_event is True

        probe_evt = make_valid_event(source="syslog", event_type="port_scan_probe")
        assert probe_evt.is_network_event is True

        cron_evt = make_valid_event(
            source="syslog", event_type="cron",
            source_port=None, destination_port=None
        )
        assert cron_evt.is_network_event is False

    def test_is_file_event(self):
        file_evt = make_valid_event(source="file_audit", event_type="file_access")
        assert file_evt.is_file_event is True

        read_evt = make_valid_event(source="audit.log", event_type="sensitive_file_read")
        assert read_evt.is_file_event is True

        net_evt = make_valid_event(source="firewall", event_type="network_flow")
        assert net_evt.is_file_event is False

    def test_is_process_event(self):
        proc_evt = make_valid_event(process="bash")
        assert proc_evt.is_process_event is True

        cmd_evt = make_valid_event(process=None, event_type="command_exec")
        assert cmd_evt.is_process_event is True

        noop_evt = make_valid_event(process=None, event_type="heartbeat")
        assert noop_evt.is_process_event is False

    def test_is_privilege_event(self):
        priv_evt = make_valid_event(event_type="privilege_change")
        assert priv_evt.is_privilege_event is True

        sudo_evt = make_valid_event(process="sudo", event_type="command")
        assert sudo_evt.is_privilege_event is True

        elev_evt = make_valid_event(action="elevated", event_type="token_mod")
        assert elev_evt.is_privilege_event is True

        norm_evt = make_valid_event(process="curl", action="success", event_type="network_flow")
        assert norm_evt.is_privilege_event is False

    def test_to_dict_includes_derived_fields(self):
        """to_dict includes all event fields and derived properties."""
        event = make_valid_event()
        d = event.to_dict()
        assert d["event_id"] == "EVT-101"
        assert "is_auth_event" in d
        assert "is_network_event" in d
        assert "is_file_event" in d
        assert "is_process_event" in d
        assert "is_privilege_event" in d
        assert d["is_auth_event"] is True
