"""Tests for REST API functionality."""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from wiretaps.api import WiretapsAPI
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
            redacted=True,
            blocked=False,
            api_key="sk-test1234567890abcdef",
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
    ]
    for entry in entries:
        temp_db.log(entry)
    return temp_db


class TestAPIInit:
    """Tests for API initialization."""

    def test_api_default_values(self, temp_db):
        """Test API initializes with default values."""
        api = WiretapsAPI(storage=temp_db)
        assert api.host == "127.0.0.1"
        assert api.port == 8081

    def test_api_custom_values(self, temp_db):
        """Test API accepts custom values."""
        api = WiretapsAPI(host="0.0.0.0", port=9090, storage=temp_db)
        assert api.host == "0.0.0.0"
        assert api.port == 9090


class TestMaskAPIKey:
    """Tests for API key masking."""

    def test_mask_long_key(self, temp_db):
        """Test masking long API key."""
        api = WiretapsAPI(storage=temp_db)
        masked = api._mask_api_key("sk-test1234567890abcdef")
        assert masked == "sk-t...cdef"

    def test_mask_short_key(self, temp_db):
        """Test masking short API key."""
        api = WiretapsAPI(storage=temp_db)
        masked = api._mask_api_key("short")
        assert masked == "***"

    def test_mask_none_key(self, temp_db):
        """Test masking None key."""
        api = WiretapsAPI(storage=temp_db)
        masked = api._mask_api_key(None)
        assert masked is None


class TestAPIRoutes:
    """Tests for API route structure."""

    def test_routes_defined(self, temp_db):
        """Test all routes are defined."""
        api = WiretapsAPI(storage=temp_db)
        routes = [r.resource.canonical for r in api.app.router.routes()]

        assert "/health" in routes
        assert "/logs" in routes
        assert "/logs/{id}" in routes
        assert "/stats" in routes


# Integration tests using aiohttp test client
class TestHealthEndpoint(AioHTTPTestCase):
    """Integration tests for /health endpoint."""

    async def get_application(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self.db_path = f.name
        self.storage = Storage(db_path=self.db_path)
        api = WiretapsAPI(storage=self.storage)
        return api.app

    async def tearDownAsync(self):
        Path(self.db_path).unlink(missing_ok=True)

    @unittest_run_loop
    async def test_health_returns_ok(self):
        """Test health endpoint returns OK."""
        response = await self.client.request("GET", "/health")
        assert response.status == 200

        data = await response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "timestamp" in data


class TestLogsEndpoint(AioHTTPTestCase):
    """Integration tests for /logs endpoint."""

    async def get_application(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self.db_path = f.name
        self.storage = Storage(db_path=self.db_path)

        # Add sample data
        self.storage.log(
            LogEntry(
                timestamp=datetime(2024, 1, 15, 10, 0, 0),
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
            )
        )

        api = WiretapsAPI(storage=self.storage)
        return api.app

    async def tearDownAsync(self):
        Path(self.db_path).unlink(missing_ok=True)

    @unittest_run_loop
    async def test_logs_returns_list(self):
        """Test logs endpoint returns list."""
        response = await self.client.request("GET", "/logs")
        assert response.status == 200

        data = await response.json()
        assert "logs" in data
        assert "count" in data
        assert isinstance(data["logs"], list)

    @unittest_run_loop
    async def test_logs_pagination(self):
        """Test logs pagination parameters."""
        response = await self.client.request("GET", "/logs?limit=10&offset=0")
        assert response.status == 200

        data = await response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestStatsEndpoint(AioHTTPTestCase):
    """Integration tests for /stats endpoint."""

    async def get_application(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self.db_path = f.name
        self.storage = Storage(db_path=self.db_path)
        api = WiretapsAPI(storage=self.storage)
        return api.app

    async def tearDownAsync(self):
        Path(self.db_path).unlink(missing_ok=True)

    @unittest_run_loop
    async def test_stats_returns_overall(self):
        """Test stats endpoint returns overall stats."""
        response = await self.client.request("GET", "/stats")
        assert response.status == 200

        data = await response.json()
        assert "overall" in data
        assert "top_pii_types" in data

    @unittest_run_loop
    async def test_stats_by_day(self):
        """Test stats by day parameter."""
        response = await self.client.request("GET", "/stats?by_day=true")
        assert response.status == 200

        data = await response.json()
        assert "by_day" in data
