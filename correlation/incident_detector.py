"""
Incident Detector Module
========================
Transforms groups of correlated detections into structured `Incident` models.

Key Capabilities:
    - Derives overall incident severity deterministically (CRITICAL, HIGH, MEDIUM, LOW)
    - Computes an aggregate incident confidence metric (0.0 to 1.0)
    - Consolidates distinct entity sets (source IPs, destination IPs, usernames, hostnames)
    - Gathers all underlying evidence event IDs for 100% forensic traceability
    - Sets lifecycle status (default: 'OPEN')
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

from detection.rule_engine import Detection

INCIDENT_STATUSES = {"OPEN", "REVIEW", "CLOSED"}
INCIDENT_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass
class Incident:
    """
    Structured security incident representing correlated suspicious activity.
    """
    incident_id: str
    created_at: datetime
    start_time: datetime
    end_time: datetime
    severity: str
    status: str
    confidence: float
    detection_ids: List[str]
    event_ids: List[str]
    source_ips: List[str]
    destination_ips: List[str]
    usernames: List[str]
    hostnames: List[str]
    detection_count: int
    summary: str
    correlation_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.incident_id:
            raise ValueError("incident_id must not be empty")
        if self.severity not in INCIDENT_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}'. Allowed: {INCIDENT_SEVERITIES}")
        if self.status not in INCIDENT_STATUSES:
            raise ValueError(f"Invalid status '{self.status}'. Allowed: {INCIDENT_STATUSES}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0")
        if not self.detection_ids:
            raise ValueError("Incident must contain at least one detection_id")
        if not self.event_ids:
            raise ValueError("Incident must contain at least one event_id")

    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to a serializable dictionary representation."""
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at.isoformat(),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "severity": self.severity,
            "status": self.status,
            "confidence": round(self.confidence, 4),
            "detection_ids": self.detection_ids,
            "event_ids": self.event_ids,
            "source_ips": self.source_ips,
            "destination_ips": self.destination_ips,
            "usernames": self.usernames,
            "hostnames": self.hostnames,
            "detection_count": self.detection_count,
            "summary": self.summary,
            "correlation_score": round(self.correlation_score, 4),
            "metadata": self.metadata,
        }


class IncidentDetector:
    """
    Processes correlated detection groups into formal Incident instances.
    """

    def __init__(self):
        self._counter = 0

    def _next_incident_id(self) -> str:
        self._counter += 1
        return f"INC-{self._counter:04d}"

    @staticmethod
    def derive_severity(detections: List[Detection]) -> str:
        """
        Derive incident severity deterministically from supporting detections and evidence:
            - Confirmed multi-stage attack with post-access findings or massive volume -> CRITICAL
            - High-volume / spray attacks or confirmed unauthorized activity -> HIGH
            - Low-to-moderate uncorroborated authentication anomalies -> MEDIUM
            - Low-volume / isolated anomalies -> LOW
        """
        severities = [d.severity.upper() for d in detections]
        rule_ids = {d.rule_id for d in detections}

        # Check if exclusively authentication failure / risk indicator activity
        is_pure_auth = rule_ids.issubset({"R001", "R007"})
        is_spray = any(d.metadata.get("attack_pattern") == "password_spray" for d in detections)
        max_failures = 0
        for d in detections:
            max_failures = max(
                max_failures,
                d.metadata.get("failure_count", 0),
                d.metadata.get("prior_failure_count", 0)
            )

        if is_pure_auth and max_failures > 0:
            # Evidence-based severity for standalone authentication telemetry:
            # Without post-compromise activity, small failure counts cannot be CRITICAL.
            if max_failures >= 20:
                return "CRITICAL"
            elif is_spray or max_failures >= 10 or ("HIGH" in severities and max_failures >= 8):
                return "HIGH"
            elif max_failures >= 4 or "MEDIUM" in severities:
                return "MEDIUM"
            return "LOW"

        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def calculate_confidence(detections: List[Detection]) -> float:
        """
        Compute aggregate confidence in the incident's correlation:
        Reflects detection quantity and condition strength (never 1.0 certainty).
        Accurately communicates uncertainty when findings are uncorroborated.
        """
        if not detections:
            return 0.0

        avg_det_conf = sum(d.confidence for d in detections) / len(detections)
        rule_ids = {d.rule_id for d in detections}

        if rule_ids.issubset({"R001", "R007"}):
            # Uncorroborated authentication findings have inherent uncertainty
            total_conf = min(avg_det_conf, 0.75)
        else:
            # Multi-stage correlation reinforcement bonus
            bonus = min(0.02 * (len(detections) - 1), 0.10)
            total_conf = min(avg_det_conf + bonus, 0.95)

        return round(total_conf, 4)

    def create_incident(self, detection_group: List[Detection]) -> Incident:
        """
        Synthesize an Incident from a list of correlated detections.
        """
        if not detection_group:
            raise ValueError("Cannot create an incident from an empty detection group")

        # Sort detections chronologically
        sorted_dets = sorted(detection_group, key=lambda d: d.timestamp)

        # Extract timestamps
        start_time = sorted_dets[0].timestamp
        end_time = sorted_dets[-1].timestamp

        # Aggregate unique entities while preserving ordering
        source_ips = sorted(list({d.source_ip for d in sorted_dets if d.source_ip}))
        dest_ips = sorted(list({d.destination_ip for d in sorted_dets if d.destination_ip}))
        usernames = sorted(list({d.username for d in sorted_dets if d.username}))
        hostnames = sorted(list({d.hostname for d in sorted_dets if d.hostname}))

        # Deduplicate all evidence event IDs
        seen_events = set()
        event_ids: List[str] = []
        for d in sorted_dets:
            for eid in d.event_ids:
                if eid not in seen_events:
                    seen_events.add(eid)
                    event_ids.append(eid)

        detection_ids = [d.detection_id for d in sorted_dets]
        severity = self.derive_severity(sorted_dets)
        confidence = self.calculate_confidence(sorted_dets)

        # Calculate average pairwise correlation score or sensible single-detection baseline
        if len(sorted_dets) > 1:
            try:
                from correlation.event_correlator import EventCorrelator
                correlator = EventCorrelator()
                pair_scores = [
                    correlator.calculate_pair_score(sorted_dets[i], sorted_dets[j])
                    for i in range(len(sorted_dets))
                    for j in range(i + 1, len(sorted_dets))
                ]
                corr_score = round(sum(pair_scores) / len(pair_scores), 2) if pair_scores else 0.85
            except Exception:
                corr_score = 0.85
        else:
            corr_score = 0.70

        # Check for unconfirmed authentication activity vs confirmed post-access activity
        rule_ids = {d.rule_id for d in sorted_dets}
        is_pure_auth = rule_ids.issubset({"R001", "R007"})
        has_post_access = any(r in {"R003", "R004", "R005", "R006", "R008"} for r in rule_ids)

        status = "REVIEW" if (is_pure_auth and not has_post_access and severity in {"LOW", "MEDIUM"}) else "OPEN"

        # Generate a descriptive summary communicating uncertainty
        rule_names = list(dict.fromkeys(d.rule_name for d in sorted_dets))
        rules_str = ", ".join(rule_names[:3]) + (f" (+{len(rule_names)-3} more)" if len(rule_names) > 3 else "")
        user_str = ", ".join(usernames) if usernames else "unknown user"
        host_str = ", ".join(hostnames) if hostnames else "unknown host"

        if is_pure_auth and not has_post_access:
            if "R007" in rule_ids:
                auth_activity = (
                    "repeated failed authentication followed by login; "
                    "account compromise unconfirmed pending analyst review of post-login session telemetry."
                )
            else:
                auth_activity = (
                    "repeated failed authentication attempts (password guessing / brute force); "
                    "account compromise unconfirmed as no subsequent successful login was observed."
                )
            summary = (
                f"Correlated {len(sorted_dets)} authentication detection(s) [{rules_str}] involving "
                f"user '{user_str}' from {', '.join(source_ips) or 'unknown source'}. "
                f"Activity indicates {auth_activity}"
            )
        else:
            summary = (
                f"Correlated {len(sorted_dets)} detection(s) [{rules_str}] involving "
                f"user(s): {user_str}, host(s): {host_str}, "
                f"spanning {len(event_ids)} evidence log event(s)."
            )

        return Incident(
            incident_id=self._next_incident_id(),
            created_at=datetime.now(),
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            status=status,
            confidence=confidence,
            detection_ids=detection_ids,
            event_ids=event_ids,
            source_ips=source_ips,
            destination_ips=dest_ips,
            usernames=usernames,
            hostnames=hostnames,
            detection_count=len(sorted_dets),
            summary=summary,
            correlation_score=corr_score,
            metadata={
                "rules_triggered": list({d.rule_id for d in sorted_dets}),
                "first_rule": sorted_dets[0].rule_id,
                "latest_rule": sorted_dets[-1].rule_id,
            },
        )

    def detect_incidents(self, correlated_groups: List[List[Detection]]) -> List[Incident]:
        """
        Transform a list of correlated detection clusters into Incidents.
        """
        return [self.create_incident(group) for group in correlated_groups if group]


def detect_incidents(correlated_events: List[List[Detection]]) -> List[Incident]:
    """
    Functional interface to detect incidents from correlated detection clusters.

    Args:
        correlated_events: List of detection groups.

    Returns:
        List of Incident objects.
    """
    detector = IncidentDetector()
    return detector.detect_incidents(correlated_events)
