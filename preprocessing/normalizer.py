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
    - Action/Status: Canonical 'success', 'failure', or clean string
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
import re

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
        - Unix epoch numbers (int, float, numeric string)
        - Strings: ISO 8601 ('2026-10-15T09:15:00', '2026-10-15T09:15:00Z', with timezone offsets)
        - Standard formats: 'YYYY-MM-DD HH:MM:SS', 'YYYY/MM/DD HH:MM:SS', 'MM/DD/YYYY HH:MM:SS', etc.
        - Syslog formats: 'Oct 15 08:30:00', 'Oct 15 2026 08:30:00'
    """
    if isinstance(ts_val, datetime):
        return ts_val.replace(tzinfo=None)

    # Check for integer/float epoch timestamp directly
    if isinstance(ts_val, (int, float)):
        if math.isnan(ts_val):
            raise ValueError("Timestamp value is empty or missing")
        try:
            # Handle milliseconds vs seconds epoch
            epoch_sec = ts_val / 1000.0 if ts_val > 1e11 else float(ts_val)
            return datetime.fromtimestamp(epoch_sec)
        except Exception as err:
            raise ValueError(f"Unable to parse timestamp '{ts_val}': {err}") from err

    clean_str = _clean_str(ts_val)
    if not clean_str:
        raise ValueError("Timestamp value is empty or missing")

    # Check if string is a numeric epoch timestamp
    if re.fullmatch(r"^\d{9,13}(\.\d+)?$", clean_str):
        try:
            epoch_num = float(clean_str)
            epoch_sec = epoch_num / 1000.0 if epoch_num > 1e11 else epoch_num
            return datetime.fromtimestamp(epoch_sec)
        except Exception:
            pass

    # Normalize ISO 'Z' to '+00:00' if needed
    iso_candidate = clean_str
    if iso_candidate.endswith("Z") or iso_candidate.endswith("z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(iso_candidate)
        return dt.replace(tzinfo=None)
    except Exception:
        pass

    # Common datetime string formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d-%m-%Y %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%b %d %Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(clean_str, fmt)
        except ValueError:
            continue

    # Try syslog without year by prepending current year
    try:
        cur_year = datetime.now().year
        return datetime.strptime(f"{cur_year} {clean_str}", f"%Y %b %d %H:%M:%S")
    except ValueError:
        pass

    raise ValueError(f"Unable to parse timestamp '{ts_val}': unrecognized format")


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
        "fatal": "critical",
        "notice": "info",
        "debug": "info",
        "informational": "info",
    }
    if sev_lower in mapping:
        return mapping[sev_lower]

    raise ValueError(f"Unrecognized severity '{sev_val}'. Allowed: {VALID_SEVERITIES}")


def normalize_action(action_val: Any, status_val: Any = None) -> Optional[str]:
    """
    Normalize action or authentication status strings to canonical lowercase
    ('success', 'failure', or clean lowercase string).
    """
    raw = _clean_str(action_val) if action_val is not None else _clean_str(status_val)
    if not raw:
        return None

    act_lower = raw.lower()
    success_synonyms = {
        "success", "successful", "succeeded", "allow", "allowed", "accept",
        "accepted", "permit", "permitted", "pass", "passed", "ok", "true", "yes"
    }
    failure_synonyms = {
        "failure", "fail", "failed", "deny", "denied", "drop", "dropped",
        "block", "blocked", "reject", "rejected", "false", "no", "error"
    }

    if act_lower in success_synonyms:
        return "success"
    if act_lower in failure_synonyms:
        return "failure"
    return act_lower


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
            # Fallback to action or generic type if available
            raw_act_fallback = _clean_str(raw_record.get("action")) or _clean_str(raw_record.get("status"))
            if raw_act_fallback:
                raw_event_type = f"{raw_act_fallback}_event"
            else:
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

        # Action / Status normalization
        raw_action = _clean_str(raw_record.get("action"))
        if not raw_action and "status" in raw_record:
            raw_action = _clean_str(raw_record.get("status"))
        if not raw_action and "result" in raw_record:
            raw_action = _clean_str(raw_record.get("result"))
        action = raw_action.lower() if raw_action else None

        # Severity
        severity = normalize_severity(raw_record.get("severity"))

        # Raw Message (Preserve exact content if given, or generate descriptive synthesis)
        raw_msg_val = raw_record.get("raw_message")
        if raw_msg_val is not None and not (isinstance(raw_msg_val, float) and math.isnan(raw_msg_val)):
            raw_message = str(raw_msg_val).strip()
            # If dataset has label/tactics fields in unmapped columns not yet in raw_message, preserve them
            for extra_key in ["mitre_attack_tactics", "tactics", "attack_tactic", "label", "ground_truth", "attack_cat"]:
                if extra_key in raw_record:
                    raw_val = raw_record.get(extra_key)
                    if raw_val is not None:
                        s_val = str(raw_val).strip()
                        if s_val and s_val.lower() not in {"nan", "null"} and f"{extra_key}=" not in raw_message:
                            raw_message += f" {extra_key}={s_val}"
        else:
            # Construct a clear factual synthesis from available telemetry fields
            parts = [f"[{source}]", event_type]
            if username:
                parts.append(f"user={username}")
            if source_ip:
                parts.append(f"src={source_ip}")
            if destination_ip:
                dst_str = f"dst={destination_ip}"
                if destination_port:
                    dst_str += f":{destination_port}"
                parts.append(dst_str)
            if action:
                parts.append(f"action={action}")
            if process:
                parts.append(f"proc={process}")
            for extra_key in ["mitre_attack_tactics", "tactics", "attack_tactic", "label", "ground_truth", "attack_cat"]:
                if extra_key in raw_record:
                    raw_val = raw_record.get(extra_key)
                    if raw_val is not None:
                        s_val = str(raw_val).strip()
                        if s_val and s_val.lower() not in {"nan", "null"}:
                            parts.append(f"{extra_key}={s_val}")
            raw_message = " ".join(parts)

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
