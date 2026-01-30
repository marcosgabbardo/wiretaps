"""Tests for stats functionality."""

import tempfile
from datetime import datetime, timedelta
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
    now = datetime.now()
    entries = [
        # Today, hour 0
        LogEntry(
            timestamp=now.replace(hour=10, minute=0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{}',
            response_body='{}',
            status=200,
            tokens=100,
            duration_ms=500,
            pii_types=["email"],
            redacted=True,
            blocked=False,
        ),
        # Today, hour 1
        LogEntry(
            timestamp=now.replace(hour=11, minute=0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{}',
            response_body='{}',
            status=200,
            tokens=50,
            duration_ms=300,
            pii_types=[],
            redacted=False,
            blocked=False,
        ),
        # Today, blocked
        LogEntry(
            timestamp=now.replace(hour=12, minute=0),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{}',
            response_body='{}',
            status=400,
            tokens=0,
            duration_ms=10,
            pii_types=["us_ssn", "phone"],
            redacted=False,
            blocked=True,
        ),
        # Yesterday
        LogEntry(
            timestamp=now - timedelta(days=1),
            method="POST",
            endpoint="/v1/chat/completions",
            request_body='{}',
            response_body='{}',
            status=200,
            tokens=200,
            duration_ms=400,
            pii_types=["email"],
            redacted=False,
            blocked=False,
        ),
    ]
    for entry in entries:
        temp_db.log(entry)
    return temp_db


class TestGetStats:
    """Tests for get_stats method."""

    def test_basic_stats(self, populated_db):
        """Test basic statistics calculation."""
        stats = populated_db.get_stats()

        assert stats["total_requests"] == 4
        assert stats["total_tokens"] == 350  # 100 + 50 + 0 + 200
        assert stats["requests_with_pii"] == 3  # 3 entries have PII
        assert stats["blocked_requests"] == 1
        assert stats["redacted_requests"] == 1
        assert stats["errors"] == 0

    def test_pii_percentage(self, populated_db):
        """Test PII percentage calculation."""
        stats = populated_db.get_stats()

        # 3 out of 4 have PII = 75%
        assert stats["pii_percentage"] == 75.0


class TestStatsByDay:
    """Tests for get_stats_by_day method."""

    def test_stats_by_day(self, populated_db):
        """Test stats grouped by day."""
        data = populated_db.get_stats_by_day(days=7)

        assert len(data) >= 1  # At least today
        # Check structure
        for row in data:
            assert "day" in row
            assert "requests" in row
            assert "tokens" in row
            assert "pii_detections" in row
            assert "blocked" in row


class TestStatsByHour:
    """Tests for get_stats_by_hour method."""

    def test_stats_by_hour(self, populated_db):
        """Test stats grouped by hour."""
        data = populated_db.get_stats_by_hour(hours=24)

        assert len(data) >= 1  # At least one hour
        # Check structure
        for row in data:
            assert "hour" in row
            assert "requests" in row
            assert "tokens" in row
            assert "pii_detections" in row
            assert "blocked" in row


class TestTopPIITypes:
    """Tests for get_top_pii_types method."""

    def test_top_pii_types(self, populated_db):
        """Test top PII types calculation."""
        top_pii = populated_db.get_top_pii_types(limit=5)

        # email appears twice, us_ssn and phone once each
        assert len(top_pii) >= 1

        # Check structure
        for item in top_pii:
            assert "type" in item
            assert "count" in item

        # email should be top (2 occurrences)
        assert top_pii[0]["type"] == "email"
        assert top_pii[0]["count"] == 2

    def test_top_pii_types_limit(self, populated_db):
        """Test limit works."""
        top_pii = populated_db.get_top_pii_types(limit=1)
        assert len(top_pii) == 1


class TestEmptyStats:
    """Tests for empty database stats."""

    def test_empty_db_stats(self, temp_db):
        """Test stats on empty database."""
        stats = temp_db.get_stats()

        assert stats["total_requests"] == 0
        assert stats["total_tokens"] == 0
        assert stats["requests_with_pii"] == 0
        assert stats["pii_percentage"] == 0
        assert stats["blocked_requests"] == 0
        assert stats["redacted_requests"] == 0
        assert stats["errors"] == 0

    def test_empty_db_by_day(self, temp_db):
        """Test stats by day on empty database."""
        data = temp_db.get_stats_by_day()
        assert data == []

    def test_empty_db_top_pii(self, temp_db):
        """Test top PII types on empty database."""
        data = temp_db.get_top_pii_types()
        assert data == []
