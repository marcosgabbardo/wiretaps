"""Tests for export functionality."""

import csv
import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from wiretaps.storage import LogEntry, Storage


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    storage = Storage(db_path=db_path)
    yield storage
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def populated_db(temp_db):
    """Create a database with sample entries."""
    entries = [
        LogEntry(
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{"messages": [{"content": "Hello user@test.com"}]}',
            response_body='{"choices": []}',
            status=200,
            tokens=100,
            duration_ms=500,
            pii_types=["email"],
            redacted=False,
            blocked=False,
        ),
        LogEntry(
            timestamp=datetime(2024, 1, 15, 11, 0, 0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{"messages": [{"content": "Hello world"}]}',
            response_body='{"choices": []}',
            status=200,
            tokens=50,
            duration_ms=300,
            pii_types=[],
            redacted=False,
            blocked=False,
        ),
        LogEntry(
            timestamp=datetime(2024, 1, 16, 12, 0, 0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{"messages": [{"content": "SSN: 123-45-6789"}]}',
            response_body='{"error": "blocked"}',
            status=400,
            tokens=0,
            duration_ms=10,
            pii_types=["us_ssn"],
            redacted=False,
            blocked=True,
        ),
    ]
    for entry in entries:
        temp_db.log(entry)
    return temp_db


class TestExportJSON:
    """Tests for JSON export."""

    def test_export_json_basic(self, populated_db):
        """Test basic JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        count = populated_db.export_json(output_path)
        assert count == 3

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 3
        assert "timestamp" in data[0]
        assert "pii_types" in data[0]
        Path(output_path).unlink()

    def test_export_json_pii_only(self, populated_db):
        """Test JSON export with PII filter."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        count = populated_db.export_json(output_path, pii_only=True)
        assert count == 2  # Only entries with PII

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 2
        for entry in data:
            assert len(entry["pii_types"]) > 0
        Path(output_path).unlink()

    def test_export_json_with_limit(self, populated_db):
        """Test JSON export with limit."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        count = populated_db.export_json(output_path, limit=1)
        assert count == 1

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 1
        Path(output_path).unlink()

    def test_export_json_date_filter(self, populated_db):
        """Test JSON export with date filter."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        # Only entries from Jan 15
        count = populated_db.export_json(
            output_path,
            start_time=datetime(2024, 1, 15, 0, 0, 0),
            end_time=datetime(2024, 1, 15, 23, 59, 59),
        )
        assert count == 2

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 2
        Path(output_path).unlink()


class TestExportCSV:
    """Tests for CSV export."""

    def test_export_csv_basic(self, populated_db):
        """Test basic CSV export."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        count = populated_db.export_csv(output_path)
        assert count == 3

        with open(output_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert "timestamp" in rows[0]
        assert "pii_types" in rows[0]
        Path(output_path).unlink()

    def test_export_csv_pii_only(self, populated_db):
        """Test CSV export with PII filter."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        count = populated_db.export_csv(output_path, pii_only=True)
        assert count == 2

        with open(output_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        Path(output_path).unlink()

    def test_export_csv_has_headers(self, populated_db):
        """Test CSV export includes proper headers."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        populated_db.export_csv(output_path)

        with open(output_path, newline="") as f:
            reader = csv.reader(f)
            headers = next(reader)

        expected_headers = [
            "id",
            "timestamp",
            "method",
            "endpoint",
            "status",
            "tokens",
            "duration_ms",
            "pii_types",
            "redacted",
            "blocked",
            "api_key",
            "error",
        ]
        assert headers == expected_headers
        Path(output_path).unlink()

    def test_export_csv_pii_types_comma_separated(self, populated_db):
        """Test PII types are comma-separated in CSV."""
        # Add entry with multiple PII types
        populated_db.log(
            LogEntry(
                timestamp=datetime(2024, 1, 17, 10, 0, 0),
                method="POST",
                endpoint="/v1/chat/completions",
                request_body='{}',
                response_body='{}',
                status=200,
                tokens=100,
                duration_ms=500,
                pii_types=["email", "phone", "ssn"],
                redacted=False,
                blocked=False,
            )
        )

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        populated_db.export_csv(output_path)

        with open(output_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Find the row with multiple PII types
        multi_pii_row = next(r for r in rows if "email" in r["pii_types"] and "phone" in r["pii_types"])
        assert multi_pii_row["pii_types"] == "email,phone,ssn"
        Path(output_path).unlink()
