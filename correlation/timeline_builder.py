"""
Timeline Builder Module
=======================
Constructs a strict chronological timeline of security events associated with
an Incident or correlated detection group.

Each timeline entry maps:
    - Original event telemetry (timestamp, source, IPs, user, action, raw_message)
    - Original event_id (verbatim forensic preservation)
    - All related detection IDs that this event contributed to
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import Detection
from correlation.incident_detector import Incident


@dataclass
class TimelineItem:
    """
    A single chronological entry within an incident timeline.
    """
    timestamp: datetime
    event_id: str
    event_type: str
    source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    severity: str = "low"
    related_detection_ids: List[str] = field(default_factory=list)
    raw_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert timeline item to a serializable dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "hostname": self.hostname,
            "action": self.action,
            "severity": self.severity,
            "related_detection_ids": self.related_detection_ids,
            "raw_message": self.raw_message,
        }


class TimelineBuilder:
    """
    Constructs chronologically ordered evidence timelines for incidents.
    """

    @staticmethod
    def build_for_incident(
        incident: Incident,
        all_events: Union[List[NormalizedEvent], Dict[str, NormalizedEvent]],
        detections: Optional[List[Detection]] = None,
    ) -> List[TimelineItem]:
        """
        Build a chronological timeline for a specific Incident.

        Args:
            incident: The Incident instance.
            all_events: Pool of NormalizedEvent instances (list or dict by event_id).
            detections: Optional list of Detection objects to correlate event_ids with detection_ids.

        Returns:
            List of TimelineItem objects sorted strictly by timestamp.
        """
        # Convert all_events to dictionary lookup if it's a list
        if isinstance(all_events, list):
            events_by_id = {e.event_id: e for e in all_events}
        else:
            events_by_id = all_events

        # Build mapping of event_id -> list of detection_ids
        event_to_detections: Dict[str, List[str]] = {}
        if detections:
            for d in detections:
                if d.detection_id in incident.detection_ids:
                    for eid in d.event_ids:
                        event_to_detections.setdefault(eid, []).append(d.detection_id)

        timeline_items: List[TimelineItem] = []

        for eid in incident.event_ids:
            event = events_by_id.get(eid)
            if not event:
                continue

            rel_dets = event_to_detections.get(eid, [])

            timeline_items.append(
                TimelineItem(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    source=event.source,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    username=event.username,
                    hostname=event.hostname,
                    action=event.action,
                    severity=event.severity,
                    related_detection_ids=rel_dets,
                    raw_message=event.raw_message,
                )
            )

        # Strictly sort chronologically
        timeline_items.sort(key=lambda item: item.timestamp)
        return timeline_items


def build_timeline(
    incident_or_events: Any,
    all_events: Optional[Any] = None,
    detections: Optional[List[Detection]] = None,
) -> List[TimelineItem]:
    """
    Functional interface to build an incident timeline.

    Supports:
        - build_timeline(incident, all_events, detections)
        - build_timeline(events_list)
    """
    if isinstance(incident_or_events, Incident):
        return TimelineBuilder.build_for_incident(
            incident_or_events, all_events or [], detections or []
        )

    # If passed a list of NormalizedEvents directly
    if isinstance(incident_or_events, list):
        items = []
        for e in incident_or_events:
            if isinstance(e, NormalizedEvent):
                items.append(
                    TimelineItem(
                        timestamp=e.timestamp,
                        event_id=e.event_id,
                        event_type=e.event_type,
                        source=e.source,
                        source_ip=e.source_ip,
                        destination_ip=e.destination_ip,
                        username=e.username,
                        hostname=e.hostname,
                        action=e.action,
                        severity=e.severity,
                        related_detection_ids=[],
                        raw_message=e.raw_message,
                    )
                )
        items.sort(key=lambda item: item.timestamp)
        return items

    return []
