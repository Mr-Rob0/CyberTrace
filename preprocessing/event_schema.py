"""
Event Schema Module
===================
Defines the normalized event data structure and common schema for CyberTrace.

All security events parsed from disparate log sources are normalized into the
`NormalizedEvent` dataclass.

Key Principles:
    - Evidence Preservation: `event_id` and `raw_message` are strictly preserved.
    - No Ground-Truth Leaks: Never includes attack labels or attack stages.
    - Type Safety: Strongly typed timestamps, ports, and severity levels.
    - Deterministic Classification: Helper properties (e.g., `is_auth_event`)
      are purely derived from intrinsic event fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import ipaddress


# Canonical schema fields expected in all CyberTrace event representations
COMMON_EVENT_FIELDS: List[str] = [
    "timestamp",
    "source",
    "event_type",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "username",
    "hostname",
    "process",
    "action",
    "severity",
    "raw_message",
    "event_id",
]

# Standard allowed severity levels
VALID_SEVERITIES = {"low", "medium", "high", "critical", "info"}


@dataclass(frozen=True)
class NormalizedEvent:
    """
    Normalized security event model for CyberTrace.

    Immutable dataclass representing a single security event after parsing
    and normalization.
    """
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    action: Optional[str] = None
    severity: str = "low"
    raw_message: str = ""

    def __post_init__(self):
        """Validate critical invariants upon initialization."""
        if not self.event_id:
            raise ValueError("event_id must not be empty")

        if not isinstance(self.timestamp, datetime):
            raise TypeError(f"timestamp must be a datetime instance, got {type(self.timestamp)}")

        # Validate severity
        if self.severity.lower() not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of: {VALID_SEVERITIES}"
            )

        # Validate ports if provided
        for port_val, port_name in [
            (self.source_port, "source_port"),
            (self.destination_port, "destination_port"),
        ]:
            if port_val is not None:
                if not isinstance(port_val, int):
                    raise TypeError(f"{port_name} must be an integer, got {type(port_val)}")
                if not (0 <= port_val <= 65535):
                    raise ValueError(f"{port_name} must be between 0 and 65535, got {port_val}")

        # Validate IP addresses if provided
        for ip_val, ip_name in [
            (self.source_ip, "source_ip"),
            (self.destination_ip, "destination_ip"),
        ]:
            if ip_val is not None and ip_val != "":
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError as err:
                    raise ValueError(f"Invalid {ip_name} address '{ip_val}': {err}") from err

    # =========================================================================
    # Deterministic Derived Properties
    # =========================================================================

    @property
    def is_auth_event(self) -> bool:
        """Determines if the event relates to authentication or identity sessions."""
        auth_sources = {"auth.log", "auth", "audit.log", "security", "pam"}
        auth_keywords = {"login", "auth", "password", "session", "credential", "logout"}

        if self.source.lower() in auth_sources:
            return True
        return any(kw in self.event_type.lower() for kw in auth_keywords)

    @property
    def is_network_event(self) -> bool:
        """Determines if the event describes network transport or flow activity."""
        net_sources = {"firewall", "netflow", "suricata", "zeek", "pcap", "network"}
        net_keywords = {
            "network", "flow", "port_scan", "probe", "connection", "traffic",
            "web", "dns", "outbound", "ingress", "egress",
        }

        if self.source.lower() in net_sources:
            return True
        if any(kw in self.event_type.lower() for kw in net_keywords):
            return True
        # Explicit non-zero port activity on firewall/network logs
        return (self.source_port is not None and self.source_port > 0) and (
            self.destination_port is not None and self.destination_port > 0
        )

    @property
    def is_file_event(self) -> bool:
        """Determines if the event relates to filesystem access, reads, or modifications."""
        file_sources = {"file_audit", "file", "smb", "nfs"}
        file_keywords = {"file", "read", "write", "archive", "modify", "share"}

        if self.source.lower() in file_sources:
            return True
        return any(kw in self.event_type.lower() for kw in file_keywords)

    @property
    def is_process_event(self) -> bool:
        """Determines if the event relates to process invocation, execution, or commands."""
        proc_keywords = {"exec", "command", "process", "cmd", "fork", "cron"}
        if self.process is not None and self.process != "":
            return True
        return any(kw in self.event_type.lower() for kw in proc_keywords)

    @property
    def is_privilege_event(self) -> bool:
        """Determines if the event involves privilege escalation, sudo, or permission changes."""
        priv_keywords = {"privilege", "sudo", "elevat", "setuid", "capability"}
        if any(kw in self.event_type.lower() for kw in priv_keywords):
            return True
        if self.action is not None and "elevat" in self.action.lower():
            return True
        if self.process is not None and self.process.lower() in {"sudo", "su", "pkexec", "doas"}:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert the normalized event to a standard dictionary representation."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "hostname": self.hostname,
            "process": self.process,
            "action": self.action,
            "severity": self.severity,
            "raw_message": self.raw_message,
            "is_auth_event": self.is_auth_event,
            "is_network_event": self.is_network_event,
            "is_file_event": self.is_file_event,
            "is_process_event": self.is_process_event,
            "is_privilege_event": self.is_privilege_event,
        }


def create_empty_event() -> Dict[str, None]:
    """
    Create a blank event dictionary with all common fields set to None.
    Maintained for backward compatibility.
    """
    return {field_name: None for field_name in COMMON_EVENT_FIELDS}
