"""
Log Parser Module
=================
Provides CSV log ingestion, automatic column identification, alias normalisation,
and error-tolerant parsing for CyberTrace.

Key Capabilities:
    - Ingests raw CSV security logs with arbitrary column naming conventions
    - Automatically maps column aliases (e.g., Time -> timestamp, SrcAddress -> source_ip)
    - Supports manual column mapping overrides
    - Auto-generates deterministic event IDs (EVT-00001...) when not provided in the CSV
    - Catches malformed fields (invalid timestamps, ports, IPs) on a per-row basis
    - Never discards errors silently: tracks errors with row number and event_id
    - Returns a comprehensive `ParseResult` containing normalized events, capability warnings,
      mapping metadata, and error details.
"""

import csv
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union

from preprocessing.event_schema import NormalizedEvent, COMMON_EVENT_FIELDS
from preprocessing.normalizer import EventNormalizer
from preprocessing.column_mapper import (
    detect_column_mapping,
    ColumnMappingResult,
    CANONICAL_ALIASES,
)


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
    column_mapping: Dict[str, str] = field(default_factory=dict)
    unmapped_columns: List[str] = field(default_factory=list)
    capability_notes: List[str] = field(default_factory=list)
    dataset_name: str = ""
    file_size_bytes: int = 0

    @property
    def has_errors(self) -> bool:
        """True if any rows failed to parse."""
        return len(self.errors) > 0


class CSVLogParser:
    """
    Parser for CSV format security logs.

    Validates schema requirements, applies automatic column alias normalisation,
    and coordinates with `EventNormalizer` to produce strongly typed `NormalizedEvent` objects.
    """

    # Essential canonical columns
    REQUIRED_COLUMNS: List[str] = ["timestamp", "source", "event_type", "event_id"]

    def __init__(
        self,
        required_columns: Optional[List[str]] = None,
        column_mapping: Optional[Dict[str, str]] = None,
        auto_generate_event_id: bool = True,
        default_source: str = "security_log",
    ):
        self._explicit_required_columns = required_columns
        self.required_columns = required_columns or self.REQUIRED_COLUMNS
        self.column_mapping = column_mapping
        self.auto_generate_event_id = auto_generate_event_id
        self.default_source = default_source
        self.normalizer = EventNormalizer()

    def parse_file(
        self,
        filepath: str,
        manual_mapping: Optional[Dict[str, str]] = None,
    ) -> ParseResult:
        """
        Parse a CSV security log file into normalized events.

        Args:
            filepath: Path to the CSV file.
            manual_mapping: Optional manual mapping overrides {canonical_col: csv_col}.

        Returns:
            ParseResult with normalized events, mapping metadata, and errors.

        Raises:
            FileNotFoundError: If filepath does not exist.
            ValueError: If file is missing mandatory columns or has empty header.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        file_size = os.path.getsize(filepath)
        dataset_name = os.path.basename(filepath)

        with open(filepath, mode="r", encoding="utf-8-sig", newline="") as f:
            res = self.parse_reader(f, manual_mapping=manual_mapping)
            res.dataset_name = dataset_name
            res.file_size_bytes = file_size
            return res

    def parse_csv_string(
        self,
        csv_content: str,
        manual_mapping: Optional[Dict[str, str]] = None,
        dataset_name: str = "memory_buffer.csv",
    ) -> ParseResult:
        """
        Parse CSV content from an in-memory string.

        Args:
            csv_content: String containing raw CSV text.
            manual_mapping: Optional manual mapping overrides.
            dataset_name: Name label for memory buffer.

        Returns:
            ParseResult instance.
        """
        import io
        res = self.parse_reader(io.StringIO(csv_content), manual_mapping=manual_mapping)
        res.dataset_name = dataset_name
        res.file_size_bytes = len(csv_content.encode("utf-8"))
        return res

    def parse_reader(
        self,
        file_obj,
        manual_mapping: Optional[Dict[str, str]] = None,
    ) -> ParseResult:
        """
        Parse from any text-mode file-like reader object.

        Args:
            file_obj: Iterable / file-like object yielding CSV lines.
            manual_mapping: Optional manual column mapping overrides.

        Returns:
            ParseResult with parsed events, mapping details, and row-level errors.
        """
        reader = csv.DictReader(file_obj)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing a valid header row")

        # Auto-detect tab or semicolon delimiters if header parsed as a single string
        if len(reader.fieldnames) == 1 and hasattr(file_obj, "seek"):
            first_col = reader.fieldnames[0]
            for delim in ["\t", ";"]:
                if delim in first_col:
                    file_obj.seek(0)
                    reader = csv.DictReader(file_obj, delimiter=delim)
                    break

        # Header validation & mapping
        header_set = set(col.strip() for col in reader.fieldnames if col)

        # If user explicitly passed a custom required_columns list, enforce strict check
        if self._explicit_required_columns is not None:
            missing_columns = [col for col in self.required_columns if col not in header_set]
            if missing_columns:
                raise ValueError(
                    f"CSV log is missing mandatory columns: {missing_columns}. "
                    f"Found columns: {list(reader.fieldnames)}"
                )

        # Detect column mapping through alias matching
        effective_manual_mapping = manual_mapping or self.column_mapping
        mapping_result = detect_column_mapping(
            list(reader.fieldnames),
            manual_mapping=effective_manual_mapping,
        )

        if not mapping_result.is_valid:
            raise ValueError(mapping_result.validation_error)

        events: List[NormalizedEvent] = []
        errors: List[ParseError] = []
        total_rows = 0

        has_explicit_event_id_col = mapping_result.has_event_id
        has_explicit_source_col = mapping_result.has_source

        # Enumerate rows starting at row 2 (row 1 is header)
        for row_idx, row in enumerate(reader, start=2):
            total_rows += 1

            # Map fields into standard canonical record
            mapped_row: Dict[str, Any] = dict(row)

            # Apply detected alias mapping
            for canonical_field, csv_header in mapping_result.mapping.items():
                if csv_header in row:
                    mapped_row[canonical_field] = row[csv_header]

            # Event ID handling:
            # If CSV has explicit event_id column, extract it (raising error if blank)
            # If CSV lacks event_id column entirely, generate deterministic ID
            if has_explicit_event_id_col:
                raw_eid = (mapped_row.get("event_id") or "").strip()
                event_id = raw_eid if raw_eid else None
                mapped_row["event_id"] = event_id
            else:
                event_id = f"EVT-{row_idx - 1:05d}"
                mapped_row["event_id"] = event_id

            # Source fallback
            if not has_explicit_source_col or not mapped_row.get("source"):
                mapped_row["source"] = self.default_source

            # Event Type fallback: if not found, use action or general event name
            if not mapped_row.get("event_type"):
                action_val = mapped_row.get("action") or mapped_row.get("status")
                if action_val:
                    mapped_row["event_type"] = f"{action_val}_event"
                else:
                    mapped_row["event_type"] = "security_event"

            try:
                norm_event = self.normalizer.normalize_record(mapped_row)
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
            column_mapping=mapping_result.mapping,
            unmapped_columns=mapping_result.unmapped_columns,
            capability_notes=mapping_result.capability_notes,
        )


def parse_log_file(
    filepath: str,
    manual_mapping: Optional[Dict[str, str]] = None,
) -> ParseResult:
    """
    Convenience functional interface to parse a log file.

    Args:
        filepath: Path to the CSV log file.
        manual_mapping: Optional manual mapping overrides.

    Returns:
        ParseResult containing normalized events and any parsing errors.
    """
    parser = CSVLogParser()
    return parser.parse_file(filepath, manual_mapping=manual_mapping)
