"""
CyberTrace Pipeline Demonstration Script (Phase 3)
===================================================
Demonstrates end-to-end log parsing and event normalization on:
  1. data/sample_attacks/combined_attack.csv
  2. data/sample_attacks/normal_activity.csv

Usage:
    python scripts/test_pipeline.py
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.log_parser import parse_log_file


def run_pipeline_for_file(filepath: str, label: str):
    print("=" * 70)
    print(f"  RUNNING PIPELINE: {label}")
    print(f"  File: {os.path.basename(filepath)}")
    print("=" * 70)

    result = parse_log_file(filepath)

    print(f"Total Rows Ingested:    {result.total_rows}")
    print(f"Successful Rows Parsed: {result.successful_rows}")
    print(f"Failed Rows:            {result.failed_rows}")
    print(f"Normalized Events:      {len(result.events)}")

    if result.has_errors:
        print("\n[!] Parsing Errors Encountered:")
        for err in result.errors[:5]:
            print(f"    - {err}")
    else:
        print("Status:                 ALL ROWS SUCCESSFULLY PARSED & NORMALIZED (0 ERRORS)")

    print("\n--- First 5 Normalized Events ---")
    for i, event in enumerate(result.events[:5], start=1):
        print(f"\n[Event {i}]")
        print(f"  event_id:         {event.event_id}")
        print(f"  timestamp:        {event.timestamp}")
        print(f"  source:           {event.source}")
        print(f"  event_type:       {event.event_type}")
        print(f"  source_ip:        {event.source_ip}")
        print(f"  destination_ip:   {event.destination_ip}")
        print(f"  source_port:      {event.source_port}")
        print(f"  destination_port: {event.destination_port}")
        print(f"  username:         {event.username}")
        print(f"  action:           {event.action}")
        print(f"  severity:         {event.severity}")
        print(f"  is_auth_event:    {event.is_auth_event}")
        print(f"  is_network_event: {event.is_network_event}")
        print(f"  is_file_event:    {event.is_file_event}")
        print(f"  is_privilege_evt: {event.is_privilege_event}")
        print(f"  raw_message:      {event.raw_message}")

    print("\n" + "=" * 70 + "\n")


def main():
    data_dir = os.path.join(PROJECT_ROOT, "data", "sample_attacks")

    combined_attack_path = os.path.join(data_dir, "combined_attack.csv")
    normal_activity_path = os.path.join(data_dir, "normal_activity.csv")

    if not os.path.exists(combined_attack_path):
        print(f"Error: {combined_attack_path} does not exist.")
        sys.exit(1)

    # 1. Process combined attack
    run_pipeline_for_file(combined_attack_path, "Combined Attack Dataset")

    # 2. Process normal baseline activity
    run_pipeline_for_file(normal_activity_path, "Normal Baseline Activity Dataset")


if __name__ == "__main__":
    main()
