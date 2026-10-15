"""
Unit Tests for Phase 2 Sample Datasets
======================================
Tests verify that:
  1. All required dataset files exist.
  2. All CSV files contain the exact expected schema columns.
  3. All timestamps can be parsed cleanly.
  4. event_id values are strictly unique within each file.
  5. All IP addresses belong strictly to private ranges (RFC 1918).
  6. All CSV files are valid and readable by pandas.
  7. Row counts meet the designated size thresholds.
"""

import os
import ipaddress
import pandas as pd
import pytest

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample_attacks"))

REQUIRED_DATASETS = [
    "brute_force.csv",
    "port_scan.csv",
    "compromised_login.csv",
    "privilege_escalation.csv",
    "data_exfiltration.csv",
    "combined_attack.csv",
    "normal_activity.csv",
]

EXPECTED_COLUMNS = [
    "timestamp",
    "source",
    "event_type",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "username",
    "hostname",
    "process",
    "action",
    "severity",
    "raw_message",
    "event_id",
]


class TestDatasetFiles:
    """Verify presence and general structure of dataset files."""

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_dataset_file_exists(self, filename):
        """Check that the file exists and is not empty."""
        filepath = os.path.join(DATA_DIR, filename)
        assert os.path.exists(filepath), f"Missing dataset file: {filename}"
        assert os.path.getsize(filepath) > 0, f"Dataset file is empty: {filename}"

    def test_readme_exists(self):
        """Check that README.md exists in sample_attacks."""
        readme_path = os.path.join(DATA_DIR, "README.md")
        assert os.path.exists(readme_path), "Missing README.md in sample_attacks"


class TestDatasetSchemaAndContent:
    """Verify schema, formatting, uniqueness, and IP privacy."""

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_csv_readable_by_pandas(self, filename):
        """Check that pandas can read the CSV file without errors."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0, f"{filename} has 0 rows"

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_csv_has_expected_columns(self, filename):
        """Check that columns match the common event schema exactly."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)
        actual_columns = list(df.columns)
        assert actual_columns == EXPECTED_COLUMNS, (
            f"Columns mismatch in {filename}.\n"
            f"Expected: {EXPECTED_COLUMNS}\n"
            f"Got:      {actual_columns}"
        )

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_event_ids_unique(self, filename):
        """Check that event_id values are strictly unique within each file."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)
        event_ids = df["event_id"].dropna()
        assert len(event_ids) == len(df), f"Missing event_id in {filename}"
        assert len(event_ids.unique()) == len(event_ids), (
            f"Duplicate event_ids found in {filename}"
        )

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_timestamps_parsable(self, filename):
        """Check that every timestamp can be parsed as a valid datetime."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)
        parsed = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
        assert not parsed.isna().any(), f"Invalid/unparseable timestamps found in {filename}"

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_no_public_ip_addresses(self, filename):
        """Verify that all non-empty IPs are private (RFC 1918) or loopback."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)

        for col in ["source_ip", "destination_ip"]:
            ips = df[col].dropna().astype(str).str.strip()
            for ip_str in ips:
                if not ip_str or ip_str == "nan":
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    assert ip_obj.is_private or ip_obj.is_loopback, (
                        f"Non-private IP detected in {filename} [{col}]: {ip_str}"
                    )
                except ValueError:
                    pytest.fail(f"Invalid IP address format in {filename} [{col}]: {ip_str}")

    @pytest.mark.parametrize("filename", REQUIRED_DATASETS)
    def test_no_forbidden_attack_stage_column(self, filename):
        """Ensure no ground-truth leak column like 'attack_stage' exists in the CSV."""
        filepath = os.path.join(DATA_DIR, filename)
        df = pd.read_csv(filepath)
        assert "attack_stage" not in df.columns, (
            f"'attack_stage' column found in {filename} — attack chain must be inferred!"
        )

    def test_dataset_row_counts_within_target_ranges(self):
        """Check that dataset sizes are realistic and meet specifications."""
        counts = {}
        for filename in REQUIRED_DATASETS:
            filepath = os.path.join(DATA_DIR, filename)
            df = pd.read_csv(filepath)
            counts[filename] = len(df)

        # Individual scenarios target ~50-100
        for name in [
            "brute_force.csv", "port_scan.csv", "compromised_login.csv",
            "privilege_escalation.csv", "data_exfiltration.csv"
        ]:
            assert 45 <= counts[name] <= 110, f"{name} count ({counts[name]}) out of expected range"

        # Combined attack target ~150-300
        assert 150 <= counts["combined_attack.csv"] <= 300, (
            f"combined_attack.csv count ({counts['combined_attack.csv']}) out of expected range"
        )

        # Normal activity target ~100-200
        assert 100 <= counts["normal_activity.csv"] <= 200, (
            f"normal_activity.csv count ({counts['normal_activity.csv']}) out of expected range"
        )
