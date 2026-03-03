"""Tests for v2 storage (agents, sessions, events)."""

import tempfile
from pathlib import Path

import pytest

from wiretaps.storage import Event, Storage


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    storage = Storage(db_path=db_path)
    yield storage
    Path(db_path).unlink(missing_ok=True)


class TestAgentCRUD:
    """Tests for agent CRUD operations."""

    def test_create_agent(self, temp_db):
        agent = temp_db.create_agent("my-agent")
        assert agent.name == "my-agent"
        assert agent.id is not None
        assert agent.created_at is not None

    def test_get_agent(self, temp_db):
        created = temp_db.create_agent("test")
        fetched = temp_db.get_agent(created.id)
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.name == "test"

    def test_get_agent_not_found(self, temp_db):
        assert temp_db.get_agent("nonexistent") is None

    def test_get_agent_by_name(self, temp_db):
        temp_db.create_agent("unique-name")
        agent = temp_db.get_agent_by_name("unique-name")
        assert agent is not None
        assert agent.name == "unique-name"

    def test_get_or_create_agent_creates(self, temp_db):
        agent = temp_db.get_or_create_agent("new-agent")
        assert agent.name == "new-agent"

    def test_get_or_create_agent_gets_existing(self, temp_db):
        first = temp_db.create_agent("existing")
        second = temp_db.get_or_create_agent("existing")
        assert first.id == second.id

    def test_list_agents(self, temp_db):
        temp_db.create_agent("a")
        temp_db.create_agent("b")
        agents = temp_db.list_agents()
        assert len(agents) == 2


class TestSessionCRUD:
    """Tests for session CRUD operations."""

    @pytest.fixture
    def agent(self, temp_db):
        return temp_db.create_agent("test-agent")

    def test_create_session(self, temp_db, agent):
        session = temp_db.create_session(agent_id=agent.id, pid=1234)
        assert session.agent_id == agent.id
        assert session.pid == 1234
        assert session.ended_at is None

    def test_create_session_with_metadata(self, temp_db, agent):
        session = temp_db.create_session(
            agent_id=agent.id,
            metadata={"env": "test"},
        )
        fetched = temp_db.get_session(session.id)
        assert fetched.metadata == {"env": "test"}

    def test_get_session(self, temp_db, agent):
        created = temp_db.create_session(agent_id=agent.id)
        fetched = temp_db.get_session(created.id)
        assert fetched is not None
        assert fetched.id == created.id

    def test_get_session_not_found(self, temp_db):
        assert temp_db.get_session("nonexistent") is None

    def test_list_sessions(self, temp_db, agent):
        temp_db.create_session(agent_id=agent.id)
        temp_db.create_session(agent_id=agent.id)
        sessions = temp_db.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_by_agent(self, temp_db, agent):
        temp_db.create_session(agent_id=agent.id)
        other = temp_db.create_agent("other")
        temp_db.create_session(agent_id=other.id)

        sessions = temp_db.list_sessions(agent_id=agent.id)
        assert len(sessions) == 1

    def test_update_session(self, temp_db, agent):
        session = temp_db.create_session(agent_id=agent.id)
        temp_db.update_session(session.id, ended_at="2024-01-15T12:00:00")
        updated = temp_db.get_session(session.id)
        assert updated.ended_at == "2024-01-15T12:00:00"


class TestEventCRUD:
    """Tests for event CRUD operations."""

    @pytest.fixture
    def session(self, temp_db):
        agent = temp_db.create_agent("test")
        return temp_db.create_session(agent_id=agent.id)

    def test_insert_event(self, temp_db, session):
        event = Event(
            session_id=session.id,
            type="llm_call",
            timestamp="2024-01-15T10:00:00",
            duration_ms=500,
            data={"model": "gpt-4", "tokens": 100},
            status=200,
        )
        event_id = temp_db.insert_event(event)
        assert event_id is not None
        assert event_id > 0

    def test_get_event(self, temp_db, session):
        event = Event(
            session_id=session.id,
            type="shell_cmd",
            timestamp="2024-01-15T10:00:00",
            duration_ms=50,
            data={"command": "ls", "exit_code": 0},
            status=0,
        )
        event_id = temp_db.insert_event(event)
        fetched = temp_db.get_event(event_id)
        assert fetched is not None
        assert fetched.type == "shell_cmd"
        assert fetched.data["command"] == "ls"

    def test_get_event_not_found(self, temp_db):
        assert temp_db.get_event(99999) is None

    def test_list_events(self, temp_db, session):
        for i in range(3):
            temp_db.insert_event(Event(
                session_id=session.id,
                type="llm_call",
                timestamp=f"2024-01-15T10:0{i}:00",
                duration_ms=100,
                data={},
                status=200,
            ))
        events = temp_db.list_events()
        assert len(events) == 3

    def test_list_events_by_type(self, temp_db, session):
        temp_db.insert_event(Event(
            session_id=session.id, type="llm_call",
            timestamp="2024-01-15T10:00:00", duration_ms=100, data={}, status=200,
        ))
        temp_db.insert_event(Event(
            session_id=session.id, type="shell_cmd",
            timestamp="2024-01-15T10:01:00", duration_ms=50, data={}, status=0,
        ))

        llm_events = temp_db.list_events(event_type="llm_call")
        assert len(llm_events) == 1
        assert llm_events[0].type == "llm_call"

    def test_list_events_pii_only(self, temp_db, session):
        temp_db.insert_event(Event(
            session_id=session.id, type="llm_call",
            timestamp="2024-01-15T10:00:00", duration_ms=100,
            data={}, pii_types=["email"], status=200,
        ))
        temp_db.insert_event(Event(
            session_id=session.id, type="llm_call",
            timestamp="2024-01-15T10:01:00", duration_ms=100,
            data={}, pii_types=[], status=200,
        ))

        pii_events = temp_db.list_events(pii_only=True)
        assert len(pii_events) == 1

    def test_list_events_pagination(self, temp_db, session):
        for i in range(5):
            temp_db.insert_event(Event(
                session_id=session.id, type="llm_call",
                timestamp=f"2024-01-15T10:0{i}:00", duration_ms=100,
                data={}, status=200,
            ))
        page1 = temp_db.list_events(limit=2, offset=0)
        page2 = temp_db.list_events(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0].id != page2[0].id


class TestEventStats:
    """Tests for v2 event statistics."""

    @pytest.fixture
    def populated(self, temp_db):
        agent = temp_db.create_agent("test")
        session = temp_db.create_session(agent_id=agent.id)

        temp_db.insert_event(Event(
            session_id=session.id, type="llm_call",
            timestamp="2024-01-15T10:00:00", duration_ms=500,
            data={"tokens": 100}, pii_types=["email"], status=200,
        ))
        temp_db.insert_event(Event(
            session_id=session.id, type="shell_cmd",
            timestamp="2024-01-15T10:01:00", duration_ms=50,
            data={}, status=0,
        ))
        temp_db.insert_event(Event(
            session_id=session.id, type="llm_call",
            timestamp="2024-01-15T10:02:00", duration_ms=300,
            data={"tokens": 200}, status=200,
        ))
        return temp_db

    def test_event_stats(self, populated):
        stats = populated.get_event_stats()
        assert stats["total_events"] == 3
        assert stats["total_tokens"] == 300
        assert stats["events_with_pii"] == 1

    def test_event_stats_by_day(self, populated):
        days = populated.get_event_stats_by_day()
        assert len(days) >= 1
        assert days[0]["events"] == 3

    def test_event_stats_by_type(self, populated):
        types = populated.get_event_stats_by_type()
        assert len(types) == 2
        type_map = {t["type"]: t for t in types}
        assert type_map["llm_call"]["count"] == 2
        assert type_map["shell_cmd"]["count"] == 1

    def test_empty_stats(self, temp_db):
        stats = temp_db.get_event_stats()
        assert stats["total_events"] == 0
        assert stats["total_tokens"] == 0
