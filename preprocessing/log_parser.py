"""
Log Parser Module
=================
Provides CSV log ingestion, column validation, and error-tolerant parsing
for CyberTrace.

Key Capabilities:
    - Ingests raw CSV security logs
    - Validates schema and column requirements
    - Catches malformed fields (invalid timestamps, ports, IPs) on a per-row basis
    - Never discards errors silently: tracks errors with row number and event_id
    - Returns a comprehensive `ParseResult` containing normalized events and errors.
"""

import csv
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union

from preprocessing.event_schema import NormalizedEvent, COMMON_EVENT_FIELDS
from preprocessing.normalizer import EventNormalizer


@dataclass
class ParseError:
    """Represents a parsing or normalization failure for a specific log row."""
    row_number: int
    event_id: Optional[str]
    error_message: str
    raw_data: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        eid_str = f" [event_id={self.event_id}]" if self.event_id else ""
        return f"Row {self.row_number}{eid_str}: {self.error_message}"


@dataclass
class ParseResult:
    """Summary of log parsing outcome."""
    events: List[NormalizedEvent] = field(default_factory=list)
    errors: List[ParseError] = field(default_factory=list)
    total_rows: int = 0
    successful_rows: int = 0
    failed_rows: int = 0

    @property
    def has_errors(self) -> bool:
        """True if any rows failed to parse."""
        return len(self.errors) > 0


class CSVLogParser:
    """
    Parser for CSV format security logs.

    Validates schema requirements and coordinates with `EventNormalizer`
    to produce strongly typed `NormalizedEvent` objects.
    """

    # Essential columns that MUST be present in any valid security log CSV
    REQUIRED_COLUMNS: List[str] = ["timestamp", "source", "event_type", "event_id"]

    def __init__(self, required_columns: Optional[List[str]] = None):
        self.required_columns = required_columns or self.REQUIRED_COLUMNS
        self.normalizer = EventNormalizer()

    def parse_file(self, filepath: str) -> ParseResult:
        """
        Parse a CSV security log file into normalized events.

        Args:
            filepath: Path to the CSV file.

        Returns:
            ParseResult with normalized events, errors, and statistics.

        Raises:
            FileNotFoundError: If filepath does not exist.
            ValueError: If file is missing mandatory columns or has empty header.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with open(filepath, mode="r", encoding="utf-8-sig", newline="") as f:
            return self.parse_reader(f)

    def parse_csv_string(self, csv_content: str) -> ParseResult:
        """
        Parse CSV content from an in-memory string.

        Args:
            csv_content: String containing raw CSV text.

        Returns:
            ParseResult instance.
        """
        import io
        return self.parse_reader(io.StringIO(csv_content))

    def parse_reader(self, file_obj) -> ParseResult:
        """
        Parse from any text-mode file-like reader object.

        Args:
            file_obj: Iterable / file-like object yielding CSV lines.

        Returns:
            ParseResult with parsed events and row-level errors.
        """
        reader = csv.DictReader(file_obj)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing a valid header row")

        # Validate column requirements
        header_set = set(col.strip() for col in reader.fieldnames if col)
        missing_columns = [col for col in self.required_columns if col not in header_set]
        if missing_columns:
            raise ValueError(
                f"CSV log is missing mandatory columns: {missing_columns}. "
                f"Found columns: {list(reader.fieldnames)}"
            )

        events: List[NormalizedEvent] = []
        errors: List[ParseError] = []
        total_rows = 0

        # Enumerate rows starting at row 2 (row 1 is header)
        for row_idx, row in enumerate(reader, start=2):
            total_rows += 1
            raw_eid = (row.get("event_id") or "").strip()
            event_id = raw_eid if raw_eid else None

            try:
                norm_event = self.normalizer.normalize_record(row)
                events.append(norm_event)
            except Exception as err:
                errors.append(
                    ParseError(
                        row_number=row_idx,
                        event_id=event_id,
                        error_message=str(err),
                        raw_data=dict(row),
                    )
                )

        successful_rows = len(events)
        failed_rows = len(errors)

        return ParseResult(
            events=events,
            errors=errors,
            total_rows=total_rows,
            successful_rows=successful_rows,
            failed_rows=failed_rows,
        )


def parse_log_file(filepath: str) -> ParseResult:
    """
    Convenience functional interface to parse a log file.

    Args:
        filepath: Path to the CSV log file.

    Returns:
        ParseResult containing normalized events and any parsing errors.
    """
    parser = CSVLogParser()
    return parser.parse_file(filepath)
