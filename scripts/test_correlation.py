"""
CyberTrace Correlation and Incident Reconstruction Demo (Phase 5)
==================================================================
Demonstrates the full deterministic pipeline:
  Normalized Events -> Rule Detections -> Correlation -> Incidents -> Timeline

Evaluates:
  1. data/sample_attacks/combined_attack.csv (Multi-stage attack)
  2. data/sample_attacks/normal_activity.csv (Benign baseline)

Usage:
    python scripts/test_correlation.py
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from correlation.timeline_builder import TimelineBuilder


def run_incident_pipeline(filepath: str, label: str):
    print("=" * 70)
    print(f"  CYBERTRACE CORRELATION DEMO: {label}")
    print(f"  File: {os.path.basename(filepath)}")
    print("=" * 70)

    # 1. Parse & Normalize
    parse_result = parse_log_file(filepath)
    raw_event_count = parse_result.total_rows
    events = parse_result.events

    # 2. Rule Detection
    engine = RuleEngine()
    detections = engine.detect(events)

    # 3. Correlation
    correlator = EventCorrelator()
    detection_groups = correlator.correlate(detections)

    # 4. Incident Detection
    detector = IncidentDetector()
    incidents = detector.detect_incidents(detection_groups)

    print(f"Input events ingested: {raw_event_count}")
    print(f"Rule detections fired: {len(detections)}")
    print(f"Incidents formulated:  {len(incidents)}")

    if not incidents:
        print("\n>> Zero Incidents Formulated (Clean Benign Baseline).")
        print("=" * 70 + "\n")
        return incidents

    # 5. Timeline for each incident
    events_lookup = {e.event_id: e for e in events}

    for inc in incidents:
        print("\n" + "-" * 70)
        print(f"INCIDENT {inc.incident_id}")
        print("-" * 70)
        print(f"Severity:     {inc.severity}")
        print(f"Status:       {inc.status}")
        print(f"Confidence:   {inc.confidence:.2f}")
        print(f"Time Range:   {inc.start_time} --> {inc.end_time}")
        print(f"Summary:      {inc.summary}")

        print(f"\nDetections ({inc.detection_count}):")
        det_map = {d.detection_id: d for d in detections}
        for det_id in inc.detection_ids:
            d = det_map.get(det_id)
            if d:
                print(f"  - [{d.rule_id}] {d.title} (conf={d.confidence:.2f}, events={len(d.event_ids)})")

        print(f"\nEntity Footprint:")
        print(f"  Source IPs:      {', '.join(inc.source_ips) or 'N/A'}")
        print(f"  Destination IPs: {', '.join(inc.destination_ips) or 'N/A'}")
        print(f"  User Accounts:   {', '.join(inc.usernames) or 'N/A'}")
        print(f"  Target Hosts:    {', '.join(inc.hostnames) or 'N/A'}")

        timeline = TimelineBuilder.build_for_incident(inc, events_lookup, detections=detections)
        print(f"\nChronological Evidence Timeline ({len(timeline)} events):")
        print(f"{'Timestamp':<19} | {'Event ID':<10} | {'Type':<22} | {'Source IP':<15} | {'User':<10} | {'Detections'}")
        print("-" * 95)

        # Show first 15 timeline events, and sample the end if long
        sample_timeline = timeline if len(timeline) <= 20 else (timeline[:10] + [None] + timeline[-5:])
        for item in sample_timeline:
            if item is None:
                print(f"{'...':<19} | {'...':<10} | {'...':<22} | {'...':<15} | {'...':<10} | [{len(timeline)-15} events omitted]")
                continue
            t_str = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            det_tag = ", ".join(item.related_detection_ids) if item.related_detection_ids else "-"
            u_tag = item.username or "-"
            sip_tag = item.source_ip or "-"
            print(f"{t_str:<19} | {item.event_id:<10} | {item.event_type:<22} | {sip_tag:<15} | {u_tag:<10} | {det_tag}")

    print("\n" + "=" * 70 + "\n")
    return incidents


def main():
    data_dir = os.path.join(PROJECT_ROOT, "data", "sample_attacks")

    combined_attack_path = os.path.join(data_dir, "combined_attack.csv")
    normal_activity_path = os.path.join(data_dir, "normal_activity.csv")

    # Run on combined attack
    run_incident_pipeline(combined_attack_path, "Combined Attack Multi-Stage Dataset")

    # Run on normal activity baseline
    run_incident_pipeline(normal_activity_path, "Normal Baseline Activity Dataset")


if __name__ == "__main__":
    main()
