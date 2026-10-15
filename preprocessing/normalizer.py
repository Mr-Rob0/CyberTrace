"""
Event Normalizer Module
=======================
Transforms parsed raw log dictionaries into standardized `NormalizedEvent` objects.

Applies deterministic transformations:
    - Timestamps: Parsed into timezone-naive datetime objects
    - Empty / NaN strings: Converted to None
    - Ports: Converted to valid integers (0-65535) or None
    - Severity: Canonical lowercase ('low', 'medium', 'high', 'critical', 'info')
    - Text fields (event_type, action, source): Canonical lowercase representation
    - IP addresses: Canonical RFC-compliant IP strings or None
    - Evidence Preservation: `event_id` and `raw_message` are preserved intact.

IMPORTANT:
    This module performs NO attack detection or threat scoring.
    It purely standardizes log representation across sources.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import ipaddress
import math

from preprocessing.event_schema import NormalizedEvent, VALID_SEVERITIES


def _clean_str(val: Any) -> Optional[str]:
    """Clean string values, converting empty/NaN/None representations to None."""
    if val is None:
        return None
    if isinstance(val, float) and math.isnan(val):
        return None
    s = str(val).strip()
    if s == "" or s.lower() in {"nan", "none", "null"}:
        return None
    return s


def parse_timestamp(ts_val: Any) -> datetime:
    """
    Parse a timestamp value into a timezone-naive datetime object.

    Supports:
        - datetime objects (converted to naive if needed)
        - Strings: ISO 8601 ('2026-10-15T09:15:00'), 'YYYY-MM-DD HH:MM:SS', etc.
    """
    if isinstance(ts_val, datetime):
        return ts_val.replace(tzinfo=None)

    clean_str = _clean_str(ts_val)
    if not clean_str:
        raise ValueError("Timestamp value is empty or missing")

    # Common datetime string formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(clean_str, fmt)
        except ValueError:
            continue

    # Try fromisoformat as a fallback
    try:
        dt = datetime.fromisoformat(clean_str)
        return dt.replace(tzinfo=None)
    except Exception as err:
        raise ValueError(f"Unable to parse timestamp '{ts_val}': unrecognized format") from err


def normalize_ip(ip_val: Any) -> Optional[str]:
    """
    Validate and return canonical representation of an IP address.

    Returns:
        Canonical IP string if valid, None if empty.
    Raises:
        ValueError: If an IP string is provided but invalid.
    """
    clean_ip = _clean_str(ip_val)
    if clean_ip is None:
        return None

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return str(ip_obj)
    except ValueError as err:
        raise ValueError(f"Invalid IP address '{ip_val}': {err}") from err


def normalize_port(port_val: Any) -> Optional[int]:
    """
    Validate and convert port value to an integer within 0-65535.

    Returns:
        Integer port or None if empty.
    Raises:
        ValueError: If port cannot be converted or is out of range.
    """
    clean_port = _clean_str(port_val)
    if clean_port is None:
        return None

    try:
        # Handle cases like "80.0" from float serialization
        if "." in clean_port:
            port_int = int(float(clean_port))
        else:
            port_int = int(clean_port)
    except (ValueError, TypeError) as err:
        raise ValueError(f"Port '{port_val}' cannot be converted to integer") from err

    if not (0 <= port_int <= 65535):
        raise ValueError(f"Port {port_int} out of valid range (0-65535)")

    return port_int


def normalize_severity(sev_val: Any) -> str:
    """Normalize severity string to lowercase valid value (defaults to 'low')."""
    clean_sev = _clean_str(sev_val)
    if not clean_sev:
        return "low"

    sev_lower = clean_sev.lower()
    if sev_lower in VALID_SEVERITIES:
        return sev_lower

    # Common mappings
    mapping = {
        "warn": "medium",
        "warning": "medium",
        "err": "high",
        "error": "high",
        "crit": "critical",
        "alert": "critical",
        "emergency": "critical",
        "notice": "info",
        "debug": "info",
    }
    if sev_lower in mapping:
        return mapping[sev_lower]

    raise ValueError(f"Unrecognized severity '{sev_val}'. Allowed: {VALID_SEVERITIES}")


class EventNormalizer:
    """Normalizes raw dictionary records into `NormalizedEvent` instances."""

    @staticmethod
    def normalize_record(raw_record: Dict[str, Any]) -> NormalizedEvent:
        """
        Normalize a single raw record dictionary into a `NormalizedEvent`.

        Args:
            raw_record: Raw dictionary representing a log row.

        Returns:
            NormalizedEvent instance.

        Raises:
            ValueError: If mandatory fields are missing or values are malformed.
        """
        # Event ID (Mandatory)
        event_id = _clean_str(raw_record.get("event_id"))
        if not event_id:
            raise ValueError("Record is missing required 'event_id'")

        # Timestamp (Mandatory)
        raw_ts = raw_record.get("timestamp")
        timestamp = parse_timestamp(raw_ts)

        # Source & Event Type (Mandatory strings)
        raw_source = _clean_str(raw_record.get("source"))
        if not raw_source:
            raise ValueError(f"Event '{event_id}' is missing required 'source'")
        source = raw_source.lower()

        raw_event_type = _clean_str(raw_record.get("event_type"))
        if not raw_event_type:
            raise ValueError(f"Event '{event_id}' is missing required 'event_type'")
        event_type = raw_event_type.lower()

        # IP Addresses
        source_ip = normalize_ip(raw_record.get("source_ip"))
        destination_ip = normalize_ip(raw_record.get("destination_ip"))

        # Ports
        source_port = normalize_port(raw_record.get("source_port"))
        destination_port = normalize_port(raw_record.get("destination_port"))

        # String Fields
        username = _clean_str(raw_record.get("username"))
        hostname = _clean_str(raw_record.get("hostname"))
        process = _clean_str(raw_record.get("process"))
        
        raw_action = _clean_str(raw_record.get("action"))
        action = raw_action.lower() if raw_action else None

        # Severity
        severity = normalize_severity(raw_record.get("severity"))

        # Raw Message (Preserve exact content if given, or empty string)
        raw_msg_val = raw_record.get("raw_message")
        if raw_msg_val is None:
            raw_message = ""
        elif isinstance(raw_msg_val, float) and math.isnan(raw_msg_val):
            raw_message = ""
        else:
            raw_message = str(raw_msg_val).strip()

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            username=username,
            hostname=hostname,
            process=process,
            action=action,
            severity=severity,
            raw_message=raw_message,
        )


def normalize_events(events: List[Any]) -> List[NormalizedEvent]:
    """
    Standardize a list of raw event dictionaries or existing NormalizedEvents.

    Args:
        events: List of raw event dictionaries or `NormalizedEvent` instances.

    Returns:
        List of standardized `NormalizedEvent` instances.
    """
    normalized_list = []
    normalizer = EventNormalizer()

    for item in events:
        if isinstance(item, NormalizedEvent):
            normalized_list.append(item)
        elif isinstance(item, dict):
            normalized_list.append(normalizer.normalize_record(item))
        else:
            raise TypeError(f"Cannot normalize item of type {type(item)}")

    return normalized_list
