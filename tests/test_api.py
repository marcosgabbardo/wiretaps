"""Tests for v2 FastAPI REST API."""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from wiretaps.api.app import create_app
from wiretaps.storage import Event, LogEntry, Storage


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
    """Create a database with sample entries (v1 logs table)."""
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


class TestCreateApp:
    """Tests for FastAPI app creation."""

    def test_app_creates(self, temp_db):
        """Test app is created with storage."""
        app = create_app(storage=temp_db)
        assert app.state.storage is temp_db

    def test_app_has_routes(self, temp_db):
        """Test app has expected routes."""
        app = create_app(storage=temp_db)
        route_paths = [r.path for r in app.routes]
        assert "/health" in route_paths
        assert "/agents" in route_paths
        assert "/sessions" in route_paths
        assert "/events" in route_paths
        assert "/stats" in route_paths


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    @pytest.fixture
    def client(self, temp_db):
        from fastapi.testclient import TestClient
        app = create_app(storage=temp_db)
        return TestClient(app)

    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "timestamp" in data


class TestAgentsEndpoints:
    """Tests for /agents endpoints."""

    @pytest.fixture
    def client(self, temp_db):
        from fastapi.testclient import TestClient
        app = create_app(storage=temp_db)
        return TestClient(app)

    def test_list_agents_empty(self, client):
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_agent(self, client):
        resp = client.post("/agents", json={"name": "my-agent"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "my-agent"
        assert "id" in data
        assert "created_at" in data

    def test_list_agents_after_create(self, client):
        client.post("/agents", json={"name": "agent-1"})
        client.post("/agents", json={"name": "agent-2"})
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestSessionsEndpoints:
    """Tests for /sessions endpoints."""

    @pytest.fixture
    def client(self, temp_db):
        from fastapi.testclient import TestClient
        app = create_app(storage=temp_db)
        return TestClient(app)

    @pytest.fixture
    def agent_id(self, client):
        resp = client.post("/agents", json={"name": "test-agent"})
        return resp.json()["id"]

    def test_create_session(self, client, agent_id):
        resp = client.post("/sessions", json={"agent_id": agent_id})
        assert resp.status_code == 201
        data = resp.json()
        assert data["agent_id"] == agent_id
        assert data["ended_at"] is None

    def test_get_session(self, client, agent_id):
        resp = client.post("/sessions", json={"agent_id": agent_id})
        session_id = resp.json()["id"]

        resp = client.get(f"/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == session_id

    def test_get_session_not_found(self, client):
        resp = client.get("/sessions/nonexistent")
        assert resp.status_code == 404

    def test_create_session_invalid_agent(self, client):
        resp = client.post("/sessions", json={"agent_id": "nonexistent"})
        assert resp.status_code == 404

    def test_list_sessions(self, client, agent_id):
        client.post("/sessions", json={"agent_id": agent_id})
        client.post("/sessions", json={"agent_id": agent_id})
        resp = client.get("/sessions")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_list_sessions_filter_agent(self, client, agent_id):
        client.post("/sessions", json={"agent_id": agent_id})

        resp = client.post("/agents", json={"name": "other-agent"})
        other_id = resp.json()["id"]
        client.post("/sessions", json={"agent_id": other_id})

        resp = client.get(f"/sessions?agent_id={agent_id}")
        assert len(resp.json()) == 1

    def test_patch_session(self, client, agent_id):
        resp = client.post("/sessions", json={"agent_id": agent_id})
        session_id = resp.json()["id"]

        resp = client.patch(f"/sessions/{session_id}", json={"ended_at": "2024-01-15T12:00:00"})
        assert resp.status_code == 200
        assert resp.json()["ended_at"] == "2024-01-15T12:00:00"

    def test_session_events(self, client, agent_id):
        resp = client.post("/sessions", json={"agent_id": agent_id})
        session_id = resp.json()["id"]

        client.post("/events/ingest", json={
            "session_id": session_id,
            "type": "shell_cmd",
            "timestamp": "2024-01-15T10:00:00",
            "data": {"command": "ls"},
        })

        resp = client.get(f"/sessions/{session_id}/events")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1


class TestEventsEndpoints:
    """Tests for /events endpoints."""

    @pytest.fixture
    def client_with_data(self, temp_db):
        from fastapi.testclient import TestClient
        app = create_app(storage=temp_db)
        client = TestClient(app)

        agent = client.post("/agents", json={"name": "test"}).json()
        session = client.post("/sessions", json={"agent_id": agent["id"]}).json()

        client.post("/events/ingest", json={
            "session_id": session["id"],
            "type": "llm_call",
            "timestamp": "2024-01-15T10:00:00",
            "duration_ms": 500,
            "data": {"model": "gpt-4", "tokens": 100},
            "status": 200,
        })
        client.post("/events/ingest", json={
            "session_id": session["id"],
            "type": "shell_cmd",
            "timestamp": "2024-01-15T10:01:00",
            "duration_ms": 50,
            "data": {"command": "ls"},
            "status": 0,
        })

        return client, session["id"]

    def test_list_events(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_list_events_by_type(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events?type=llm_call")
        assert resp.json()["count"] == 1
        assert resp.json()["events"][0]["type"] == "llm_call"

    def test_list_events_by_session(self, client_with_data):
        client, session_id = client_with_data
        resp = client.get(f"/events?session_id={session_id}")
        assert resp.json()["count"] == 2

    def test_get_event(self, client_with_data):
        client, _ = client_with_data
        events = client.get("/events").json()["events"]
        event_id = events[0]["id"]

        resp = client.get(f"/events/{event_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == event_id

    def test_get_event_not_found(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events/99999")
        assert resp.status_code == 404

    def test_ingest_event(self, client_with_data):
        client, session_id = client_with_data
        resp = client.post("/events/ingest", json={
            "session_id": session_id,
            "type": "http_request",
            "timestamp": "2024-01-15T10:02:00",
            "data": {"method": "GET", "url": "/api/data", "status": 200},
        })
        assert resp.status_code == 201
        assert "id" in resp.json()

    def test_ingest_invalid_session(self, client_with_data):
        client, _ = client_with_data
        resp = client.post("/events/ingest", json={
            "session_id": "nonexistent",
            "type": "shell_cmd",
            "timestamp": "2024-01-15T10:00:00",
            "data": {},
        })
        assert resp.status_code == 404

    def test_ingest_invalid_type(self, client_with_data):
        client, session_id = client_with_data
        resp = client.post("/events/ingest", json={
            "session_id": session_id,
            "type": "invalid_type",
            "timestamp": "2024-01-15T10:00:00",
            "data": {},
        })
        assert resp.status_code == 422


class TestStatsEndpoints:
    """Tests for /stats endpoints."""

    @pytest.fixture
    def client_with_data(self, temp_db):
        from fastapi.testclient import TestClient
        app = create_app(storage=temp_db)
        client = TestClient(app)

        agent = client.post("/agents", json={"name": "test"}).json()
        session = client.post("/sessions", json={"agent_id": agent["id"]}).json()

        client.post("/events/ingest", json={
            "session_id": session["id"],
            "type": "llm_call",
            "timestamp": "2024-01-15T10:00:00",
            "data": {"tokens": 100},
            "pii_types": ["email"],
            "status": 200,
        })
        client.post("/events/ingest", json={
            "session_id": session["id"],
            "type": "shell_cmd",
            "timestamp": "2024-01-15T10:01:00",
            "data": {"command": "ls"},
            "status": 0,
        })

        return client

    def test_stats(self, client_with_data):
        resp = client_with_data.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 2
        assert data["events_with_pii"] == 1

    def test_stats_by_day(self, client_with_data):
        resp = client_with_data.get("/stats/by-day")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_stats_by_type(self, client_with_data):
        resp = client_with_data.get("/stats/by-type")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        types = {d["type"] for d in data}
        assert "llm_call" in types
        assert "shell_cmd" in types
