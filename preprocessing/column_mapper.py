"""
Column Mapper Module
====================
Provides automatic column identification, alias resolution, and capability
assessment for security log datasets with arbitrary schema conventions.

Supports:
    - Auto-detection of known column aliases (Time, SrcAddress, User, Action, etc.)
    - Manual mapping overrides
    - Graceful handling of missing optional fields
    - Detailed capability warnings when security detections lack required fields
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

# Controlled aliases for canonical fields in NormalizedEvent
CANONICAL_ALIASES: Dict[str, List[str]] = {
    "timestamp": [
        "timestamp", "time", "datetime", "date_time", "date", "event_time",
        "eventtime", "event_timestamp", "log_time", "@timestamp", "ts",
        "time_stamp", "record_time", "created_at", "utc_time", "system_time"
    ],
    "source": [
        "source", "log_source", "logsource", "source_type", "sourcetype",
        "service", "app", "application", "component", "facility", "system",
        "channel", "logger"
    ],
    "event_type": [
        "event_type", "eventtype", "event_name", "eventname", "type",
        "activity", "action_type", "message_type", "operation", "category",
        "sub_type", "event", "event_id_name", "signature", "audit_type",
        "event_description", "event_class"
    ],
    "event_id": [
        "event_id", "eventid", "id", "record_id", "recordid", "guid",
        "uuid", "log_id", "logid", "entry_id", "sequence_number"
    ],
    "source_ip": [
        "source_ip", "sourceip", "src_ip", "srcip", "src", "srcaddress",
        "src_address", "src_addr", "source_address", "sourceaddress",
        "client_ip", "clientip", "remote_ip", "origin_ip", "src_host_ip",
        "ip_src", "caller_ip", "src_host"
    ],
    "destination_ip": [
        "destination_ip", "destinationip", "dest_ip", "destip", "dst_ip",
        "dstip", "destaddress", "dest_address", "dest_addr", "destination_address",
        "destinationaddress", "target_ip", "server_ip", "dst", "dst_host_ip",
        "ip_dst", "target_host_ip"
    ],
    "source_port": [
        "source_port", "sourceport", "src_port", "srcport", "src_pt",
        "sport", "client_port", "src_p", "origin_port"
    ],
    "destination_port": [
        "destination_port", "destinationport", "dest_port", "destport",
        "dst_port", "dstport", "dst_pt", "dport", "target_port", "server_port",
        "dst_p"
    ],
    "username": [
        "username", "user_name", "user", "account", "account_name",
        "user_id", "userid", "login", "identity", "actor", "target_user",
        "usr", "principal", "subject", "auth_user"
    ],
    "hostname": [
        "hostname", "host", "host_name", "computer_name", "computername",
        "server", "system_name", "device_name", "dest_host", "device",
        "endpoint", "workstation", "node"
    ],
    "process": [
        "process", "process_name", "processname", "command", "cmd",
        "proc", "image", "executable", "app_name", "program", "binary",
        "command_line", "cmdline"
    ],
    "action": [
        "action", "result", "status", "outcome", "disposition", "reason",
        "decision", "auth_status", "response"
    ],
    "severity": [
        "severity", "level", "priority", "log_level", "loglevel",
        "alert_severity", "sev", "impact"
    ],
    "raw_message": [
        "raw_message", "rawmessage", "message", "msg", "description",
        "details", "log_message", "payload", "info", "raw", "log"
    ],
}


def clean_header_name(header: str) -> str:
    """Normalize header string for fuzzy comparison: lowercase, no punctuation."""
    if not header:
        return ""
    h = str(header).strip().lower()
    h = re.sub(r'[\s\.\-]+', '_', h)
    return h


@dataclass
class ColumnMappingResult:
    """Detailed summary of column identification and capability assessment."""
    mapping: Dict[str, str] = field(default_factory=dict)         # canonical -> actual csv header
    csv_to_canonical: Dict[str, str] = field(default_factory=dict)# actual csv header -> canonical
    unmapped_columns: List[str] = field(default_factory=list)
    missing_canonical_fields: List[str] = field(default_factory=list)
    capability_notes: List[str] = field(default_factory=list)
    is_valid: bool = True
    validation_error: Optional[str] = None
    has_event_id: bool = False
    has_source: bool = False


def detect_column_mapping(
    csv_columns: List[str],
    manual_mapping: Optional[Dict[str, str]] = None,
) -> ColumnMappingResult:
    """
    Automatically identify canonical security log fields from raw CSV column names.

    Args:
        csv_columns: List of header strings from the CSV.
        manual_mapping: Optional user-supplied mapping {canonical_field: csv_header}.

    Returns:
        ColumnMappingResult with mapping details, capability notes, and validation status.
    """
    cleaned_col_map: Dict[str, str] = {clean_header_name(c): c for c in csv_columns if c and c.strip()}
    raw_col_set = set(csv_columns)

    mapping: Dict[str, str] = {}
    csv_to_canonical: Dict[str, str] = {}

    # 1. Apply manual mapping overrides first if provided
    if manual_mapping:
        for canonical, actual in manual_mapping.items():
            if actual in raw_col_set:
                mapping[canonical] = actual
                csv_to_canonical[actual] = canonical

    # 1b. Schema disambiguation: When both Action and Result/Status exist:
    # "Action" describes the operation (event_type), while "Result"/"Status" describes outcome (action)
    has_act = "action" in cleaned_col_map
    has_outcome = "result" in cleaned_col_map or "status" in cleaned_col_map
    if has_act and has_outcome and "event_type" not in mapping:
        mapping["event_type"] = cleaned_col_map["action"]
        csv_to_canonical[cleaned_col_map["action"]] = "event_type"
        outcome_col = cleaned_col_map.get("result") or cleaned_col_map.get("status")
        if "action" not in mapping:
            mapping["action"] = outcome_col
            csv_to_canonical[outcome_col] = "action"

    # 2. Match canonical fields against aliases
    for canonical, aliases in CANONICAL_ALIASES.items():
        if canonical in mapping:
            continue

        # Check exact canonical name match first
        canonical_clean = clean_header_name(canonical)
        if canonical_clean in cleaned_col_map:
            actual = cleaned_col_map[canonical_clean]
            if actual not in csv_to_canonical:
                mapping[canonical] = actual
                csv_to_canonical[actual] = canonical
                continue

        # Check aliases
        for alias in aliases:
            alias_clean = clean_header_name(alias)
            if alias_clean in cleaned_col_map:
                actual = cleaned_col_map[alias_clean]
                if actual not in csv_to_canonical:
                    mapping[canonical] = actual
                    csv_to_canonical[actual] = canonical
                    break

    unmapped_columns = [c for c in csv_columns if c not in csv_to_canonical]
    missing_canonical = [c for c in CANONICAL_ALIASES if c not in mapping]

    # Validate essential requirements
    is_valid = True
    validation_error = None
    has_event_id = "event_id" in mapping
    has_source = "source" in mapping

    # Timestamp is mandatory for chronological security event analysis
    if "timestamp" not in mapping:
        is_valid = False
        validation_error = (
            f"CSV log is missing mandatory columns: ['timestamp']. "
            f"Found columns: {list(csv_columns)}. "
            "Please ensure a timestamp/time column is present or specify manual mapping."
        )

    # Capability Notes for missing fields
    capability_notes = []
    if "destination_port" not in mapping:
        capability_notes.append("Destination port column absent: Network port scan detection (R002) is disabled.")
    if "source_ip" not in mapping:
        capability_notes.append("Source IP column absent: Network IP correlation and IP brute-force tracking will be limited.")
    if "username" not in mapping:
        capability_notes.append("Username column absent: Identity-based correlation will rely strictly on IP addresses and hostnames.")
    if "process" not in mapping:
        capability_notes.append("Process/Command column absent: Execution and privilege escalation command inspection will be limited.")
    if not has_event_id:
        capability_notes.append("Event ID column absent: Sequential event IDs (EVT-00001...) will be automatically generated.")
    if not has_source:
        capability_notes.append("Log source column absent: Defaulting log source to 'security_log'.")

    return ColumnMappingResult(
        mapping=mapping,
        csv_to_canonical=csv_to_canonical,
        unmapped_columns=unmapped_columns,
        missing_canonical_fields=missing_canonical,
        capability_notes=capability_notes,
        is_valid=is_valid,
        validation_error=validation_error,
        has_event_id=has_event_id,
        has_source=has_source,
    )
