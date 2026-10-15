"""
CyberTrace Detection Demonstration Script (Phase 4)
===================================================
Evaluates the RuleEngine across all seven synthetic datasets:
    1. brute_force.csv
    2. port_scan.csv
    3. compromised_login.csv
    4. privilege_escalation.csv
    5. data_exfiltration.csv
    6. combined_attack.csv
    7. normal_activity.csv

Prints structured summaries of detections, severities, confidence levels,
and evidence event IDs.

Usage:
    python scripts/test_detection.py
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine, Detection

DATASETS = [
    "brute_force.csv",
    "port_scan.csv",
    "compromised_login.csv",
    "privilege_escalation.csv",
    "data_exfiltration.csv",
    "combined_attack.csv",
    "normal_activity.csv",
]


def evaluate_dataset(engine: RuleEngine, filepath: str, filename: str):
    print("=" * 70)
    print(f"  DATASET: {filename}")
    print("=" * 70)

    parse_res = parse_log_file(filepath)
    print(f"Total Rows Ingested:    {parse_res.total_rows}")
    print(f"Normalized Events:      {len(parse_res.events)}")

    detections = engine.detect(parse_res.events)
    print(f"Total Detections Found: {len(detections)}")

    if not detections:
        print(">> No detections triggered (Clean / Benign baseline activity)")
        print()
        return detections

    print("\n--- Triggered Detections ---")
    for idx, det in enumerate(detections, start=1):
        print(f"\n[{idx}] {det.rule_id} — {det.rule_name}")
        print(f"    Detection ID:   {det.detection_id}")
        print(f"    Severity:       {det.severity}")
        print(f"    Confidence:     {det.confidence:.2f}")
        print(f"    Title:          {det.title}")
        print(f"    Target:         User='{det.username or 'N/A'}' Host='{det.hostname or 'N/A'}'")
        print(f"    Network:        {det.source_ip or 'N/A'} -> {det.destination_ip or 'N/A'}")
        print(f"    Evidence Count: {len(det.event_ids)} event(s)")
        print(f"    Evidence IDs:   {', '.join(det.event_ids[:6])}" + (f" ... and {len(det.event_ids) - 6} more" if len(det.event_ids) > 6 else ""))

    print()
    return detections


def main():
    data_dir = os.path.join(PROJECT_ROOT, "data", "sample_attacks")
    engine = RuleEngine()

    total_detections_all = 0
    rule_counts = {}
    dataset_counts = {}

    for filename in DATASETS:
        filepath = os.path.join(data_dir, filename)
        if not os.path.exists(filepath):
            print(f"Warning: {filename} not found.")
            continue

        dets = evaluate_dataset(engine, filepath, filename)
        dataset_counts[filename] = len(dets)
        total_detections_all += len(dets)

        for d in dets:
            rule_counts[d.rule_id] = rule_counts.get(d.rule_id, 0) + 1

    print("=" * 70)
    print("  PHASE 4 DETECTION SUMMARY")
    print("=" * 70)
    print(f"Total Detections across all datasets: {total_detections_all}\n")

    print("Detections by Rule:")
    for rid in sorted(rule_counts.keys()):
        print(f"  - {rid}: {rule_counts[rid]}")

    print("\nDetections by Dataset:")
    for ds_name in DATASETS:
        count = dataset_counts.get(ds_name, 0)
        status = "✅ 0 Detections (Clean Benign)" if ds_name == "normal_activity.csv" and count == 0 else f"{count} detections"
        print(f"  - {ds_name:25s}: {status}")

    print("=" * 70)


if __name__ == "__main__":
    main()
