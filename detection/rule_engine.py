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
    - R007: Successful Login Following Repeated Failures
    - R008: Suspicious Privileged Account Activity

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
    # R001 Brute Force / Authentication Threat Detection
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    brute_force_burst_min_rate_per_minute: float = 0.5  # Min attempts/min for burst classification
    brute_force_max_gap_seconds: int = 180  # Max gap between failures in same burst cluster
    user_spray_threshold: int = 3  # Distinct accounts from same source to flag spray
    user_spray_min_failures: int = 3  # Min total failures across accounts to trigger spray alert
    user_spray_window_seconds: int = 300  # Time window for multi-account spray

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

    # R007 Successful Login Following Repeated Failures (Risk Indicator)
    enable_r007_login_after_failures: bool = True
    login_after_failures_threshold: int = 3
    login_after_failures_window_seconds: int = 300

    # R008 Suspicious Privileged Account Activity
    enable_r008_privileged_account_activity: bool = True
    privileged_usernames: List[str] = field(default_factory=lambda: [
        "root", "admin", "administrator", "system"
    ])

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionConfig":
        """Build DetectionConfig from a dictionary, safely casting types."""
        valid_fields = cls.__dataclass_fields__
        kwargs = {}
        for k, v in data.items():
            if k in valid_fields:
                field_type = valid_fields[k].type
                try:
                    if field_type == int:
                        kwargs[k] = int(v)
                    elif field_type == float:
                        kwargs[k] = float(v)
                    elif field_type == bool:
                        kwargs[k] = bool(v)
                    else:
                        kwargs[k] = v
                except (ValueError, TypeError):
                    kwargs[k] = v
        return cls(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {k: getattr(self, k) for k in self.__dataclass_fields__.keys()}


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


# Canonical cybersecurity authentication outcome synonyms
AUTH_FAILURE_ACTIONS = {"failure", "fail", "failed", "deny", "denied", "block", "blocked", "reject", "rejected", "false", "error"}
AUTH_SUCCESS_ACTIONS = {"success", "successful", "succeeded", "accept", "accepted", "allow", "allowed", "permit", "permitted", "pass", "passed", "ok", "true"}


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
        detections.extend(self._evaluate_r007_login_after_failures(sorted_events))
        detections.extend(self._evaluate_r008_privileged_account_activity(sorted_events))

        # Sort detections chronologically
        detections.sort(key=lambda d: d.timestamp)
        return detections

    # =========================================================================
    # RULE R001: Brute Force
    # =========================================================================

    def _evaluate_r001_brute_force(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect authentication threats: targeted brute force and multi-account password spraying.
        Evaluates temporal burst density, target diversity, and entity correlation rather than a static count.
        """
        detections = []
        # Filter for failed authentication events
        failed_logins = [
            e for e in events
            if e.is_auth_event and (
                (e.action and e.action.lower() in AUTH_FAILURE_ACTIONS) or
                "failed" in e.event_type.lower() or
                "fail" in e.event_type.lower()
            )
        ]

        if not failed_logins:
            return detections

        # Group by source_ip (or host if source_ip absent)
        by_source: Dict[str, List[NormalizedEvent]] = {}
        for evt in failed_logins:
            key = evt.source_ip or (f"host:{evt.hostname}" if evt.hostname else None)
            if key:
                by_source.setdefault(key, []).append(evt)

        window_duration = timedelta(seconds=self.config.brute_force_window_seconds)
        max_gap = getattr(self.config, "brute_force_max_gap_seconds", 180)
        min_cluster_len = min(
            self.config.brute_force_threshold,
            getattr(self.config, "user_spray_min_failures", 3)
        )

        for src_key, ip_events in by_source.items():
            if len(ip_events) < min_cluster_len:
                continue

            # Cluster failures into sliding / contiguous time windows
            clusters: List[List[NormalizedEvent]] = []
            current_cluster: List[NormalizedEvent] = []

            for evt in ip_events:
                if not current_cluster:
                    current_cluster.append(evt)
                else:
                    within_window = (evt.timestamp - current_cluster[0].timestamp <= window_duration)
                    within_gap = (max_gap is None or (evt.timestamp - current_cluster[-1].timestamp).total_seconds() <= max_gap)
                    if within_window and within_gap:
                        current_cluster.append(evt)
                    else:
                        if len(current_cluster) >= min_cluster_len:
                            clusters.append(current_cluster)
                        current_cluster = [evt]

            if current_cluster and len(current_cluster) >= min_cluster_len:
                clusters.append(current_cluster)

            for cluster in clusters:
                fail_count = len(cluster)
                first_ts = cluster[0].timestamp
                last_ts = cluster[-1].timestamp
                duration_sec = max((last_ts - first_ts).total_seconds(), 1.0)
                burst_rate_per_min = (fail_count / duration_sec) * 60.0

                # Analyze target usernames and host correlation
                target_usernames = sorted(list({e.username for e in cluster if e.username}))
                distinct_user_count = len(target_usernames)

                # Destination host correlation without hallucination
                dest_ips = sorted(list({e.destination_ip for e in cluster if e.destination_ip}))
                hostnames = sorted(list({e.hostname for e in cluster if e.hostname}))
                primary_dest_ip = dest_ips[0] if dest_ips else None
                primary_hostname = hostnames[0] if hostnames else None

                # Determine if this meets the multi-user spray pattern
                spray_threshold = getattr(self.config, "user_spray_threshold", 3)
                spray_min_fails = getattr(self.config, "user_spray_min_failures", 3)
                is_spray = (distinct_user_count >= spray_threshold and fail_count >= spray_min_fails)

                # Determine if this meets the targeted burst threshold
                is_targeted_burst = (fail_count >= self.config.brute_force_threshold)

                # Filter out sporadic ordinary failures
                min_rate = getattr(self.config, "brute_force_burst_min_rate_per_minute", 0.5)
                if not is_spray and not is_targeted_burst:
                    continue
                if not is_spray and burst_rate_per_min < min_rate:
                    continue

                # Evidence-based severity calibration:
                # Privileged accounts or high volume / spray attacks are HIGH/CRITICAL.
                # Small bursts on standard accounts are MEDIUM (unconfirmed suspicion).
                is_privileged = any(
                    u.lower() in getattr(self.config, "privileged_usernames", ["root", "admin", "administrator", "system"])
                    for u in target_usernames
                )

                if fail_count >= 20 or (fail_count >= 15 and burst_rate_per_min >= 20.0) or distinct_user_count >= 10:
                    severity = "CRITICAL"
                    severity_reason = f"Massive failure burst ({fail_count} attempts, {burst_rate_per_min:.1f} attempts/min) indicating intense automated campaign"
                elif is_spray:
                    severity = "HIGH"
                    severity_reason = f"Horizontal credential spray targeting {distinct_user_count} distinct accounts ({burst_rate_per_min:.1f} attempts/min)"
                elif fail_count >= 10:
                    severity = "HIGH"
                    severity_reason = f"Substantial failure volume ({fail_count} attempts) targeting account"
                elif is_privileged and fail_count >= self.config.brute_force_threshold:
                    severity = "HIGH"
                    severity_reason = f"Targeted failure burst ({fail_count} attempts) against privileged administrative account"
                elif fail_count >= self.config.brute_force_threshold:
                    severity = "MEDIUM"
                    severity_reason = f"Failed authentication burst ({fail_count} attempts) against standard user; unconfirmed threat pattern"
                else:
                    severity = "LOW"
                    severity_reason = f"Low failure volume ({fail_count} attempts) within threshold window"

                # Confidence calculation based on evidence strength (never 1.0)
                base_conf = 0.82
                conf_vol = min(0.01 * max(0, fail_count - self.config.brute_force_threshold), 0.08)
                conf_burst = 0.04 if burst_rate_per_min >= 5.0 else 0.0
                conf_spray = 0.03 if is_spray else 0.0
                confidence = min(round(base_conf + conf_vol + conf_burst + conf_spray, 2), 0.95)

                # Source representation
                src_ip_val = cluster[0].source_ip or (src_key if not src_key.startswith("host:") else None)

                # Target host phrasing (only if fields present)
                target_dest_desc = ""
                if primary_hostname and primary_dest_ip:
                    target_dest_desc = f"targeting {primary_hostname} ({primary_dest_ip})"
                elif primary_hostname:
                    target_dest_desc = f"targeting host {primary_hostname}"
                elif primary_dest_ip:
                    target_dest_desc = f"targeting destination {primary_dest_ip}"

                if is_spray and distinct_user_count >= spray_threshold:
                    user_preview = ", ".join(f"'{u}'" for u in target_usernames[:4])
                    if distinct_user_count > 4:
                        user_preview += f" (+{distinct_user_count - 4} more)"
                    title = f"Password Spray Attack Detected ({distinct_user_count} accounts targeted, {fail_count} failures)"
                    desc = (
                        f"Detected horizontal password spray of {fail_count} failed login attempts targeting {distinct_user_count} "
                        f"distinct accounts ({user_preview}) from source {src_ip_val or 'unknown'} "
                        f"{target_dest_desc + ' ' if target_dest_desc else ''}within {int(duration_sec)}s "
                        f"(velocity: {burst_rate_per_min:.1f} attempts/min). "
                        f"Multi-account targeting pattern indicates credential spray or automated enumeration activity."
                    )
                    user_val = target_usernames[0] if len(target_usernames) == 1 else None
                else:
                    user_label = target_usernames[0] if len(target_usernames) == 1 else (
                        f"{distinct_user_count} users" if target_usernames else "unknown"
                    )
                    title = f"Brute Force Login Burst Detected ({fail_count} failures)"
                    desc = (
                        f"Detected {fail_count} failed authentication attempts targeting user '{user_label}' "
                        f"from {src_ip_val or 'unknown'} {target_dest_desc + ' ' if target_dest_desc else ''}within {int(duration_sec)}s "
                        f"(velocity: {burst_rate_per_min:.1f} attempts/min). "
                        f"Failure burst density indicates automated password guessing or brute force activity."
                    )
                    user_val = target_usernames[0] if target_usernames else None

                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R001"),
                        rule_id="R001",
                        rule_name="Brute Force Login Attempt",
                        timestamp=last_ts,
                        severity=severity,
                        title=title,
                        description=desc,
                        event_ids=[e.event_id for e in cluster],
                        source_ip=src_ip_val,
                        destination_ip=primary_dest_ip,
                        username=user_val,
                        hostname=primary_hostname,
                        confidence=confidence,
                        evidence=[_extract_evidence(e) for e in cluster],
                        metadata={
                            "failure_count": fail_count,
                            "window_seconds": self.config.brute_force_window_seconds,
                            "actual_duration_seconds": round(duration_sec, 2),
                            "burst_rate_per_minute": round(burst_rate_per_min, 2),
                            "target_users": target_usernames,
                            "distinct_user_count": distinct_user_count,
                            "attack_pattern": "password_spray" if is_spray else "targeted_brute_force",
                            "severity_reason": severity_reason,
                            "target_dest_ips": dest_ips,
                            "target_hostnames": hostnames,
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
                    i += len(window_events)
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
                (evt.action and evt.action.lower() in AUTH_SUCCESS_ACTIONS) or
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

    # =========================================================================
    # RULE R007: Successful Login Following Repeated Failures
    # =========================================================================

    def _evaluate_r007_login_after_failures(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect successful authentication following multiple failed attempts.
        Treated as an elevated risk indicator of potential credential compromise,
        not definitive proof (analyst confirmation of session activity required).
        """
        if not getattr(self.config, "enable_r007_login_after_failures", True):
            return []

        detections = []
        auth_events = [e for e in events if e.is_auth_event]
        if not auth_events:
            return detections

        window_duration = timedelta(seconds=self.config.login_after_failures_window_seconds)

        # Group auth events by entity (source_ip or username)
        by_entity: Dict[str, List[NormalizedEvent]] = {}
        for evt in auth_events:
            key = evt.source_ip or evt.username
            if key:
                by_entity.setdefault(key, []).append(evt)

        for key, entity_events in by_entity.items():
            for i, evt in enumerate(entity_events):
                is_success = (
                    (evt.action and evt.action.lower() in AUTH_SUCCESS_ACTIONS) or
                    "success" in evt.event_type.lower()
                )
                if not is_success:
                    continue

                # Collect failures immediately preceding this success within window
                failures_before = [
                    prev_evt for prev_evt in entity_events[:i]
                    if ((prev_evt.action and prev_evt.action.lower() in AUTH_FAILURE_ACTIONS) or "fail" in prev_evt.event_type.lower())
                    and (evt.timestamp - prev_evt.timestamp <= window_duration)
                    and (evt.timestamp >= prev_evt.timestamp)
                ]

                if len(failures_before) >= self.config.login_after_failures_threshold:
                    fail_count = len(failures_before)
                    all_evts = failures_before + [evt]
                    target_user = evt.username or (failures_before[0].username if failures_before else "unknown")

                    # Attribute correlation checks
                    same_user_failures = [f for f in failures_before if f.username == target_user]
                    same_ip_failures = [f for f in failures_before if f.source_ip and f.source_ip == evt.source_ip]
                    is_correlated = bool(same_user_failures or same_ip_failures)

                    is_privileged = target_user.lower() in getattr(
                        self.config, "privileged_usernames", ["root", "admin", "administrator", "system"]
                    )

                    # Evidence-based severity calibration:
                    # - CRITICAL: Requires massive prior failures (>= 20) on administrative accounts.
                    # - HIGH: Substantial prior failures (>= 10) or privileged account with repeated failures (>= 6).
                    # - MEDIUM: Moderate failure burst (5-9 failures) followed by success (unconfirmed compromise).
                    # - LOW: Small failure count (3-4 failures), highly likely a corrected user typo.
                    if fail_count >= 20 and is_privileged:
                        severity = "CRITICAL"
                        severity_reason = f"Successful administrative login for '{target_user}' following massive failure burst ({fail_count} failures)"
                    elif fail_count >= 10:
                        severity = "HIGH"
                        severity_reason = f"Successful login following substantial failure burst ({fail_count} failures)"
                    elif is_privileged and fail_count >= 6:
                        severity = "HIGH"
                        severity_reason = f"Successful login for privileged account '{target_user}' following repeated failures ({fail_count} failures)"
                    elif fail_count >= 5:
                        severity = "MEDIUM"
                        severity_reason = f"Successful login following {fail_count} failed attempts; unconfirmed compromise indicator requiring verification"
                    else:
                        severity = "LOW"
                        severity_reason = f"Successful login following {fail_count} failed attempts; potential benign typo pattern"

                    confidence = min(0.85 + 0.02 * (fail_count - self.config.login_after_failures_threshold), 0.95)

                    dest_info = ""
                    if evt.hostname and evt.destination_ip:
                        dest_info = f"on {evt.hostname} ({evt.destination_ip})"
                    elif evt.hostname:
                        dest_info = f"on host {evt.hostname}"
                    elif evt.destination_ip:
                        dest_info = f"on destination {evt.destination_ip}"

                    # Note in title and description that this is an elevated risk indicator, not proven compromise
                    title = f"Brute-Force Compromise Risk Indicator ({target_user})"
                    description = (
                        f"Account '{target_user}' successfully authenticated from {evt.source_ip or 'unknown'} "
                        f"{dest_info + ' ' if dest_info else ''}following {fail_count} failed login attempts "
                        f"within {self.config.login_after_failures_window_seconds}s. "
                        f"This represents an elevated risk indicator of potential credential guessing success or unauthorized access, "
                        f"rather than conclusive proof of account compromise. Analyst verification of user session activity is recommended."
                    )

                    detections.append(
                        Detection(
                            detection_id=self._next_detection_id("R007"),
                            rule_id="R007",
                            rule_name="Successful Login Following Repeated Failures",
                            timestamp=evt.timestamp,
                            severity=severity,
                            title=title,
                            description=description,
                            event_ids=[e.event_id for e in all_evts],
                            source_ip=evt.source_ip,
                            destination_ip=evt.destination_ip,
                            username=target_user,
                            hostname=evt.hostname,
                            confidence=confidence,
                            evidence=[_extract_evidence(e) for e in all_evts],
                            metadata={
                                "prior_failure_count": fail_count,
                                "success_event_id": evt.event_id,
                                "window_seconds": self.config.login_after_failures_window_seconds,
                                "risk_indicator_type": "post_failure_success",
                                "is_conclusive_proof": False,
                                "requires_analyst_verification": True,
                                "same_user_failure_count": len(same_user_failures),
                                "same_ip_failure_count": len(same_ip_failures),
                                "severity_reason": severity_reason,
                            },
                        )
                    )

        return detections

    # =========================================================================
    # RULE R008: Suspicious Privileged Account Activity
    # =========================================================================

    def _evaluate_r008_privileged_account_activity(self, events: List[NormalizedEvent]) -> List[Detection]:
        """
        Detect suspicious or unusual direct privileged account operations
        (such as direct remote login as root/admin, or interactive administrative logon).
        """
        if not getattr(self.config, "enable_r008_privileged_account_activity", True):
            return []

        detections = []
        privileged_users = {
            u.lower() for u in getattr(
                self.config, "privileged_usernames", ["root", "admin", "administrator", "system"]
            )
        }

        for evt in events:
            if not evt.is_auth_event:
                continue

            is_priv = evt.username and evt.username.lower() in privileged_users
            if not is_priv:
                continue

            is_success = (
                (evt.action and evt.action.lower() in AUTH_SUCCESS_ACTIONS) or
                "success" in evt.event_type.lower()
            )
            is_login_type = any(kw in evt.event_type.lower() for kw in ["login", "auth", "session", "logon"])
            if not (is_success and is_login_type):
                continue

            # Must originate from a remote/network source IP (not local loopback or local host)
            if evt.source_ip and evt.source_ip not in {"127.0.0.1", "::1", "localhost"} and evt.source_ip != evt.destination_ip:
                detections.append(
                    Detection(
                        detection_id=self._next_detection_id("R008"),
                        rule_id="R008",
                        rule_name="Suspicious Privileged Account Activity",
                        timestamp=evt.timestamp,
                        severity="HIGH",
                        title=f"Direct Remote Privileged Login Detected ('{evt.username}')",
                        description=(
                            f"Direct administrative session opened for privileged account '{evt.username}' "
                            f"from remote IP {evt.source_ip} to target {evt.hostname or evt.destination_ip}."
                        ),
                        event_ids=[evt.event_id],
                        source_ip=evt.source_ip,
                        destination_ip=evt.destination_ip,
                        username=evt.username,
                        hostname=evt.hostname,
                        confidence=0.88,
                        evidence=[_extract_evidence(evt)],
                        metadata={
                            "privileged_user": evt.username,
                            "raw_message": evt.raw_message,
                        },
                    )
                )

        return detections


def apply_rules(
    normalized_events: List[NormalizedEvent],
    config: Optional[DetectionConfig] = None,
) -> List[Detection]:
    """
    Convenience function for evaluating rules on a list of normalized events.

    Args:
        normalized_events: List of NormalizedEvent instances.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Detection objects.
    """
    engine = RuleEngine(config=config)
    return engine.detect(normalized_events)
