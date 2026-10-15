"""
Detection Engine Module
=======================
Deterministic rule-based threat detection engine for CyberTrace.

Evaluates normalized events against a set of predefined detection rules:
    - R001: Brute Force Login Attempt
    - R002: Port Scan (Reconnaissance)
    - R003: Suspicious Login from Unusual Subnet
    - R004: Privilege Escalation Indicator
    - R005: Sensitive File Access Indicator
    - R006: Large Outbound Data Transfer Indicator

Key Principles:
    - 100% Deterministic: Operates strictly on normalized event attributes.
    - Evidence Preservation: Every detection maintains links to the exact
      original event_ids and machine-readable evidence records.
    - No False Certainty: Confidence represents condition strength, never 1.0 certainty.
    - Zero Hallucination: Never invents security facts or unrecorded data.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re
import uuid

from preprocessing.event_schema import NormalizedEvent

# Controlled severity values
SEVERITY_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass
class Detection:
    """
    Structured security detection produced by the rule engine.
    """
    detection_id: str
    rule_id: str
    rule_name: str
    timestamp: datetime
    severity: str
    title: str
    description: str
    event_ids: List[str]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    confidence: float = 0.80
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.detection_id:
            raise ValueError("detection_id must not be empty")
        if not self.rule_id:
            raise ValueError("rule_id must not be empty")
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity '{self.severity}'. Allowed: {SEVERITY_LEVELS}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0")
        if not self.event_ids:
            raise ValueError("event_ids must contain at least one evidence event ID")

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection to a standard serializable dictionary."""
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "event_ids": self.event_ids,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "hostname": self.hostname,
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class DetectionConfig:
    """Configurable thresholds for detection rules."""
    # R001 Brute Force
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300

    # R002 Port Scan
    port_scan_threshold: int = 10
    port_scan_window_seconds: int = 120

    # R003 Suspicious Subnet
    suspicious_subnet_prefix: str = "10.0.0."

    # R005 Sensitive File Keywords
    sensitive_file_keywords: List[str] = field(default_factory=lambda: [
        "shadow", "passwd", "credential", "secrets", "confidential",
        "authorized_keys", "private_key", ".pem", ".key", "pii"
    ])

    # R006 Large Outbound Transfer (bytes)
    large_transfer_min_bytes: int = 100_000_000  # 100 MB


def _extract_evidence(event: NormalizedEvent) -> Dict[str, Any]:
    """Helper to serialize a single event into a machine-readable evidence dictionary."""
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "username": event.username,
        "hostname": event.hostname,
        "process": event.process,
        "action": event.action,
        "raw_message": event.raw_message,
    }


class RuleEngine:
    """
    Deterministic detection rule evaluator for CyberTrace.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self._counter = 0

    def _next_detection_id(self, rule_id: str) -> str:
        """Generate a deterministic, unique detection ID."""
        self._counter += 1
        return f"DET-{rule_id}-{self._counter:04d}"

    def detect(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Evaluate all rules across the given normalized events.

        Args:
            events: List of NormalizedEvent instances.

        Returns:
            List of Detection objects.
        """
        if not events:
            return []

        # Ensure events are ordered chronologically for windowed calculations
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        detections: List[Detection] = []
        detections.extend(self._evaluate_r001_brute_force(sorted_events))
        detections.extend(self._evaluate_r002_port_scan(sorted_events))
        detections.extend(self._evaluate_r003_suspicious_login(sorted_events))
        detections.extend(self._evaluate_r004_privilege_escalation(sorted_events))
        detections.extend(self._evaluate_r005_sensitive_file_access(sorted_events))
        detections.extend(self._evaluate_r006_large_outbound_transfer(sorted_events))

        # Sort detections chronologically
        detections.sort(key=lambda d: d.timestamp)
        return detections

    # =========================================================================
    # RULE R001: Brute Force
    # =========================================================================

    def _evaluate_r001_brute_force(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect repeated failed login attempts from the same source IP.
        """
        detections = []
        # Filter for failed authentication events
        failed_logins = [
            e for e in events
            if e.is_auth_event and (
                e.action == "failure" or
                "failed" in e.event_type.lower() or
                "fail" in e.event_type.lower()
            )
        ]

        if not failed_logins:
            return detections

        # Group by source_ip
        by_source_ip: Dict[str, List[NormalizedEvent]] = {}
        for evt in failed_logins:
            if evt.source_ip:
                by_source_ip.setdefault(evt.source_ip, []).append(evt)

        window_duration = timedelta(seconds=self.config.brute_force_window_seconds)

        for src_ip, ip_events in by_source_ip.items():
            if len(ip_events) < self.config.brute_force_threshold:
                continue

            # Cluster failures into sliding / contiguous time windows to avoid duplicate spam
            clusters: List[List[NormalizedEvent]] = []
            current_cluster: List[NormalizedEvent] = []

            for evt in ip_events:
                if not current_cluster:
                    current_cluster.append(evt)
                else:
                    # If this event falls within window of the start of the current cluster
                    if evt.timestamp - current_cluster[0].timestamp <= window_duration:
                        current_cluster.append(evt)
                    else:
                        if len(current_cluster) >= self.config.brute_force_threshold:
                            clusters.append(current_cluster)
                        current_cluster = [evt]

            if current_cluster and len(current_cluster) >= self.config.brute_force_threshold:
                clusters.append(current_cluster)

            for cluster in clusters:
                fail_count = len(cluster)
                # Calculate confidence: 0.80 base + incremental confidence up to 0.95
                confidence = min(0.80 + 0.01 * (fail_count - self.config.brute_force_threshold), 0.95)

                target_usernames = list({e.username for e in cluster if e.username})
                user_label = target_usernames[0] if len(target_usernames) == 1 else (
                    f"{len(target_usernames)} users" if target_usernames else "unknown"
                )

                dest_ips = list({e.destination_ip for e in cluster if e.destination_ip})
                dest_ip = dest_ips[0] if dest_ips else None
                hostnames = list({e.hostname for e in cluster if e.hostname})
                hostname = hostnames[0] if hostnames else None

                first_ts = cluster[0].timestamp
                last_ts = cluster[-1].timestamp
                duration_sec = (last_ts - first_ts).total_seconds()

                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R001"),
                        rule_id="R001",
                        rule_name="Brute Force Login Attempt",
                        timestamp=last_ts,
                        severity="HIGH",
                        title=f"Brute Force Login Burst Detected ({fail_count} failures)",
                        description=(
                            f"Detected {fail_count} failed authentication attempts from {src_ip} "
                            f"targeting user '{user_label}' within {int(duration_sec)} seconds."
                        ),
                        event_ids=[e.event_id for e in cluster],
                        source_ip=src_ip,
                        destination_ip=dest_ip,
                        username=target_usernames[0] if target_usernames else None,
                        hostname=hostname,
                        confidence=confidence,
                        evidence=[_extract_evidence(e) for e in cluster],
                        metadata={
                            "failure_count": fail_count,
                            "window_seconds": self.config.brute_force_window_seconds,
                            "actual_duration_seconds": duration_sec,
                            "target_users": target_usernames,
                        },
                    )
                )

        return detections

    # =========================================================================
    # RULE R002: Port Scan
    # =========================================================================

    def _evaluate_r002_port_scan(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect a source IP contacting many distinct destination ports on a single host.
        """
        detections = []
        # Filter network / firewall events with non-empty ports
        net_events = [
            e for e in events
            if e.source_ip and e.destination_ip and e.destination_port is not None and e.destination_port > 0
        ]

        if not net_events:
            return detections

        # Group by (source_ip, destination_ip)
        by_pair: Dict[tuple, List[NormalizedEvent]] = {}
        for evt in net_events:
            by_pair.setdefault((evt.source_ip, evt.destination_ip), []).append(evt)

        window_duration = timedelta(seconds=self.config.port_scan_window_seconds)

        for (src_ip, dst_ip), pair_events in by_pair.items():
            # Distinct ports overall
            unique_ports = {e.destination_port for e in pair_events}
            if len(unique_ports) < self.config.port_scan_threshold:
                continue

            # Sliding window check
            i = 0
            while i < len(pair_events):
                window_events = []
                window_start = pair_events[i].timestamp

                for j in range(i, len(pair_events)):
                    if pair_events[j].timestamp - window_start <= window_duration:
                        window_events.append(pair_events[j])
                    else:
                        break

                distinct_ports_in_window = {e.destination_port for e in window_events}
                if len(distinct_ports_in_window) >= self.config.port_scan_threshold:
                    port_count = len(distinct_ports_in_window)
                    confidence = min(0.80 + 0.005 * (port_count - self.config.port_scan_threshold), 0.95)

                    hostnames = list({e.hostname for e in window_events if e.hostname})
                    hostname = hostnames[0] if hostnames else None

                    detections.append(
                        Detection(
                            detection_id=self._next_detection_id("R002"),
                            rule_id="R002",
                            rule_name="Port Scan (Network Reconnaissance)",
                            timestamp=window_events[-1].timestamp,
                            severity="MEDIUM",
                            title=f"Port Scan Detected ({port_count} distinct ports targeted)",
                            description=(
                                f"Source IP {src_ip} attempted connections to {port_count} distinct ports "
                                f"on target {dst_ip} within {self.config.port_scan_window_seconds} seconds."
                            ),
                            event_ids=[e.event_id for e in window_events],
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            hostname=hostname,
                            confidence=confidence,
                            evidence=[_extract_evidence(e) for e in window_events],
                            metadata={
                                "distinct_port_count": port_count,
                                "sampled_ports": sorted(list(distinct_ports_in_window))[:15],
                                "total_probe_packets": len(window_events),
                            },
                        )
                    )
                    # Advance past this scan cluster to prevent spamming multiple detections
                    i = j
                else:
                    i += 1

        return detections

    # =========================================================================
    # RULE R003: Suspicious Login
    # =========================================================================

    def _evaluate_r003_suspicious_login(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect successful authentication originating from an unusual subnet (10.0.0.x).
        """
        detections = []
        prefix = self.config.suspicious_subnet_prefix

        for evt in events:
            if not evt.is_auth_event:
                continue

            # Must be a successful login
            is_success = (
                evt.action == "success" or
                "success" in evt.event_type.lower()
            )
            if not is_success:
                continue

            if evt.source_ip and evt.source_ip.startswith(prefix):
                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R003"),
                        rule_id="R003",
                        rule_name="Suspicious Login from Unusual Subnet",
                        timestamp=evt.timestamp,
                        severity="MEDIUM",
                        title=f"Suspicious Login from Unusual Network ({evt.source_ip})",
                        description=(
                            f"User '{evt.username or 'unknown'}' successfully logged in from "
                            f"unusual network address {evt.source_ip} to host {evt.hostname or evt.destination_ip}."
                        ),
                        event_ids=[evt.event_id],
                        source_ip=evt.source_ip,
                        destination_ip=evt.destination_ip,
                        username=evt.username,
                        hostname=evt.hostname,
                        confidence=0.85,
                        evidence=[_extract_evidence(evt)],
                        metadata={
                            "detected_subnet_prefix": prefix,
                            "original_action": evt.action,
                        },
                    )
                )

        return detections

    # =========================================================================
    # RULE R004: Privilege Escalation Indicator
    # =========================================================================

    def _evaluate_r004_privilege_escalation(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect indicators of privilege changes, sudo alterations, or root transitions.
        """
        detections = []

        for evt in events:
            is_priv_evt = evt.is_privilege_event
            action_elevated = evt.action is not None and "elevat" in evt.action.lower()
            type_priv = any(k in evt.event_type.lower() for k in ["privilege_change", "privilege_escalat", "sudo_enum"])

            if is_priv_evt or action_elevated or type_priv:
                confidence = 0.88 if (action_elevated or "privilege_change" in evt.event_type.lower()) else 0.80

                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R004"),
                        rule_id="R004",
                        rule_name="Privilege Escalation Indicator",
                        timestamp=evt.timestamp,
                        severity="HIGH",
                        title="Privilege Escalation Indicator Detected",
                        description=(
                            f"Observed potential privilege transition or elevated execution "
                            f"by user '{evt.username or 'unknown'}' on host {evt.hostname or evt.destination_ip} "
                            f"via process '{evt.process or 'unknown'}'."
                        ),
                        event_ids=[evt.event_id],
                        source_ip=evt.source_ip,
                        destination_ip=evt.destination_ip,
                        username=evt.username,
                        hostname=evt.hostname,
                        confidence=confidence,
                        evidence=[_extract_evidence(evt)],
                        metadata={
                            "action": evt.action,
                            "process": evt.process,
                            "raw_message": evt.raw_message,
                        },
                    )
                )

        return detections

    # =========================================================================
    # RULE R005: Sensitive File Access Indicator
    # =========================================================================

    def _evaluate_r005_sensitive_file_access(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect suspicious access to sensitive system/credential files.
        """
        detections = []
        keywords = [kw.lower() for kw in self.config.sensitive_file_keywords]

        for evt in events:
            msg_lower = evt.raw_message.lower() if evt.raw_message else ""
            type_lower = evt.event_type.lower() if evt.event_type else ""

            matched_keyword = None
            for kw in keywords:
                if kw in msg_lower or kw in type_lower:
                    matched_keyword = kw
                    break

            if matched_keyword:
                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R005"),
                        rule_id="R005",
                        rule_name="Sensitive File Access Indicator",
                        timestamp=evt.timestamp,
                        severity="HIGH",
                        title=f"Sensitive Resource Access Detected ('{matched_keyword}')",
                        description=(
                            f"Access or read operation involving sensitive resource keyword '{matched_keyword}' "
                            f"detected for user '{evt.username or 'unknown'}' on host {evt.hostname or evt.destination_ip}."
                        ),
                        event_ids=[evt.event_id],
                        source_ip=evt.source_ip,
                        destination_ip=evt.destination_ip,
                        username=evt.username,
                        hostname=evt.hostname,
                        confidence=0.85,
                        evidence=[_extract_evidence(evt)],
                        metadata={
                            "matched_keyword": matched_keyword,
                            "raw_message": evt.raw_message,
                        },
                    )
                )

        return detections

    # =========================================================================
    # RULE R006: Large Outbound Data Transfer
    # =========================================================================

    def _evaluate_r006_large_outbound_transfer(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect unusually large outbound network transfers from explicit telemetry.
        Never fabricates byte counts or triggers without direct evidence.
        """
        detections = []

        for evt in events:
            bytes_found = None

            # Safely extract bytes if recorded in raw_message (e.g. 'bytes=120000000')
            if evt.raw_message:
                match = re.search(r'bytes=(\d+)', evt.raw_message, re.IGNORECASE)
                if match:
                    try:
                        bytes_found = int(match.group(1))
                    except ValueError:
                        bytes_found = None

            is_explicit_type = "large_outbound" in evt.event_type.lower() or "exfil" in evt.event_type.lower()

            if (bytes_found is not None and bytes_found >= self.config.large_transfer_min_bytes) or is_explicit_type:
                bytes_mb = round(bytes_found / (1024 * 1024), 2) if bytes_found else "High volume"
                confidence = 0.88 if bytes_found and bytes_found >= self.config.large_transfer_min_bytes else 0.80

                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R006"),
                        rule_id="R006",
                        rule_name="Large Outbound Data Transfer",
                        timestamp=evt.timestamp,
                        severity="HIGH",
                        title="Large Outbound Network Transfer Detected",
                        description=(
                            f"Potential data exfiltration stream observed from {evt.source_ip} "
                            f"to {evt.destination_ip}:{evt.destination_port or ''} ({bytes_mb} MB)."
                        ),
                        event_ids=[evt.event_id],
                        source_ip=evt.source_ip,
                        destination_ip=evt.destination_ip,
                        username=evt.username,
                        hostname=evt.hostname,
                        confidence=confidence,
                        evidence=[_extract_evidence(evt)],
                        metadata={
                            "bytes_transferred": bytes_found,
                            "raw_message": evt.raw_message,
                        },
                    )
                )

        return detections


def apply_rules(normalized_events: List[NormalizedEvent]) -> List[Detection]:
    """
    Convenience function for evaluating rules on a list of normalized events.

    Args:
        normalized_events: List of NormalizedEvent instances.

    Returns:
        List of Detection objects.
    """
    engine = RuleEngine()
    return engine.detect(normalized_events)
