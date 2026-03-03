"""
Storage backend for wiretaps v2.

Three-table schema: agents, sessions, events.
Maintains backward compatibility with v1 logs table via migration.
"""

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Legacy dataclass kept for backward compatibility with v1 tests/exports
# ---------------------------------------------------------------------------


@dataclass
class LogEntry:
    """A single log entry (v1 compat)."""

    timestamp: datetime
    method: str
    endpoint: str
    request_body: str
    response_body: str
    status: int
    tokens: int
    duration_ms: int
    pii_types: list[str] = field(default_factory=list)
    error: str | None = None
    redacted: bool = False
    blocked: bool = False
    api_key: str | None = None
    id: int | None = None


# ---------------------------------------------------------------------------
# V2 dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Agent:
    """A registered agent."""

    id: str
    name: str
    created_at: str


@dataclass
class Session:
    """A monitoring session tied to an agent."""

    id: str
    agent_id: str
    started_at: str
    ended_at: str | None = None
    pid: int | None = None
    metadata: dict | None = None


@dataclass
class Event:
    """A single captured event."""

    session_id: str
    type: str  # llm_call | shell_cmd | http_request
    timestamp: str
    duration_ms: int
    data: dict
    pii_types: list[str] = field(default_factory=list)
    status: int = 0
    error: str | None = None
    id: int | None = None


class Storage:
    """
    Storage backend for wiretaps.

    Default uses SQLite for zero-config setup.
    V2 schema: agents, sessions, events tables.
    Automatically migrates v1 logs table on first access.
    """

    def __init__(self, db_path: str | None = None, timeout: float = 10.0):
        if db_path is None:
            db_dir = Path.home() / ".wiretaps"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "logs.db")

        self.db_path = db_path
        self.timeout = timeout
        self._init_db()

    # ------------------------------------------------------------------
    # Schema initialization
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Initialize v2 database schema and migrate v1 if needed."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")

            # ---------- v2 tables ----------
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL REFERENCES agents(id),
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    pid INTEGER,
                    metadata TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    duration_ms INTEGER,
                    data TEXT,
                    pii_types TEXT,
                    status INTEGER,
                    error TEXT
                )
            """)

            # Indices
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)"
            )

            # ---------- v1 compat: keep logs table for legacy callers ----------
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    request_body TEXT,
                    response_body TEXT,
                    status INTEGER,
                    tokens INTEGER,
                    duration_ms INTEGER,
                    pii_types TEXT,
                    error TEXT,
                    redacted INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    api_key TEXT
                )
            """)

            # Migration: add columns if not exists
            cursor = conn.execute("PRAGMA table_info(logs)")
            columns = [row[1] for row in cursor.fetchall()]
            if "redacted" not in columns:
                conn.execute("ALTER TABLE logs ADD COLUMN redacted INTEGER DEFAULT 0")
            if "blocked" not in columns:
                conn.execute("ALTER TABLE logs ADD COLUMN blocked INTEGER DEFAULT 0")
            if "api_key" not in columns:
                conn.execute("ALTER TABLE logs ADD COLUMN api_key TEXT")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pii ON logs(pii_types)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_key ON logs(api_key)")

            conn.commit()

    # ------------------------------------------------------------------
    # Agent CRUD
    # ------------------------------------------------------------------

    def create_agent(self, name: str) -> Agent:
        """Create a new agent."""
        agent = Agent(id=str(uuid.uuid4()), name=name, created_at=datetime.now().isoformat())
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.execute(
                "INSERT INTO agents (id, name, created_at) VALUES (?, ?, ?)",
                (agent.id, agent.name, agent.created_at),
            )
            conn.commit()
        return agent

    def get_agent(self, agent_id: str) -> Agent | None:
        """Get agent by ID."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if not row:
                return None
            return Agent(id=row["id"], name=row["name"], created_at=row["created_at"])

    def get_agent_by_name(self, name: str) -> Agent | None:
        """Get agent by name."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM agents WHERE name = ?", (name,)).fetchone()
            if not row:
                return None
            return Agent(id=row["id"], name=row["name"], created_at=row["created_at"])

    def get_or_create_agent(self, name: str) -> Agent:
        """Get existing agent by name or create new one."""
        agent = self.get_agent_by_name(name)
        if agent:
            return agent
        return self.create_agent(name)

    def list_agents(self) -> list[Agent]:
        """List all agents."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
            return [Agent(id=r["id"], name=r["name"], created_at=r["created_at"]) for r in rows]

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    def create_session(
        self,
        agent_id: str,
        pid: int | None = None,
        metadata: dict | None = None,
    ) -> Session:
        """Create a new session."""
        session = Session(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            started_at=datetime.now().isoformat(),
            pid=pid,
            metadata=metadata,
        )
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.execute(
                "INSERT INTO sessions (id, agent_id, started_at, pid, metadata) VALUES (?, ?, ?, ?, ?)",
                (
                    session.id,
                    session.agent_id,
                    session.started_at,
                    session.pid,
                    json.dumps(session.metadata) if session.metadata else None,
                ),
            )
            conn.commit()
        return session

    def get_session(self, session_id: str) -> Session | None:
        """Get session by ID."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if not row:
                return None
            return Session(
                id=row["id"],
                agent_id=row["agent_id"],
                started_at=row["started_at"],
                ended_at=row["ended_at"],
                pid=row["pid"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else None,
            )

    def list_sessions(
        self,
        agent_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Session]:
        """List sessions with optional agent filter."""
        query = "SELECT * FROM sessions WHERE 1=1"
        params: list = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [
                Session(
                    id=r["id"],
                    agent_id=r["agent_id"],
                    started_at=r["started_at"],
                    ended_at=r["ended_at"],
                    pid=r["pid"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else None,
                )
                for r in rows
            ]

    def update_session(self, session_id: str, ended_at: str | None = None) -> bool:
        """Update session (e.g. set ended_at)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            if ended_at is not None:
                conn.execute(
                    "UPDATE sessions SET ended_at = ? WHERE id = ?",
                    (ended_at, session_id),
                )
            conn.commit()
            return conn.total_changes > 0

    # ------------------------------------------------------------------
    # Event CRUD
    # ------------------------------------------------------------------

    def insert_event(self, event: Event) -> int:
        """Insert a new event."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            cursor = conn.execute(
                """
                INSERT INTO events (session_id, type, timestamp, duration_ms, data, pii_types, status, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.session_id,
                    event.type,
                    event.timestamp,
                    event.duration_ms,
                    json.dumps(event.data),
                    json.dumps(event.pii_types),
                    event.status,
                    event.error,
                ),
            )
            conn.commit()
            return cursor.lastrowid  # type: ignore[return-value]

    async def insert_event_async(self, event: Event) -> int:
        """Insert event asynchronously."""
        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.insert_event, event)

    def get_event(self, event_id: int) -> Event | None:
        """Get event by ID."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            if not row:
                return None
            return Event(
                id=row["id"],
                session_id=row["session_id"],
                type=row["type"],
                timestamp=row["timestamp"],
                duration_ms=row["duration_ms"],
                data=json.loads(row["data"] or "{}"),
                pii_types=json.loads(row["pii_types"] or "[]"),
                status=row["status"],
                error=row["error"],
            )

    def list_events(
        self,
        session_id: str | None = None,
        event_type: str | None = None,
        pii_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Event]:
        """List events with filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if event_type:
            query += " AND type = ?"
            params.append(event_type)
        if pii_only:
            query += " AND pii_types != '[]'"

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [
                Event(
                    id=r["id"],
                    session_id=r["session_id"],
                    type=r["type"],
                    timestamp=r["timestamp"],
                    duration_ms=r["duration_ms"],
                    data=json.loads(r["data"] or "{}"),
                    pii_types=json.loads(r["pii_types"] or "[]"),
                    status=r["status"],
                    error=r["error"],
                )
                for r in rows
            ]

    # ------------------------------------------------------------------
    # Stats (v2 — from events table)
    # ------------------------------------------------------------------

    def get_event_stats(self) -> dict:
        """Get aggregate statistics from events table."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_type = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM events GROUP BY type"
            ).fetchall()
            pii_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE pii_types != '[]'"
            ).fetchone()[0]
            error_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE error IS NOT NULL"
            ).fetchone()[0]

            total_tokens = 0
            rows = conn.execute(
                "SELECT data FROM events WHERE type = 'llm_call'"
            ).fetchall()
            for row in rows:
                data = json.loads(row[0] or "{}")
                total_tokens += data.get("tokens", 0)

            return {
                "total_events": total,
                "total_tokens": total_tokens,
                "events_with_pii": pii_count,
                "pii_percentage": round((pii_count / total * 100), 2) if total > 0 else 0,
                "errors": error_count,
                "by_type": {row[0]: row[1] for row in by_type},
            }

    def get_event_stats_by_day(self, days: int = 7) -> list[dict]:
        """Get event statistics grouped by day."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            rows = conn.execute(
                """
                SELECT
                    date(timestamp) as day,
                    COUNT(*) as events,
                    SUM(CASE WHEN pii_types != '[]' THEN 1 ELSE 0 END) as pii_detections,
                    SUM(CASE WHEN type = 'llm_call' THEN 1 ELSE 0 END) as llm_calls,
                    SUM(CASE WHEN type = 'shell_cmd' THEN 1 ELSE 0 END) as shell_cmds,
                    SUM(CASE WHEN type = 'http_request' THEN 1 ELSE 0 END) as http_requests
                FROM events
                GROUP BY date(timestamp)
                ORDER BY day DESC
                LIMIT ?
                """,
                (days,),
            ).fetchall()

            return [
                {
                    "day": row[0],
                    "events": row[1],
                    "pii_detections": row[2],
                    "llm_calls": row[3],
                    "shell_cmds": row[4],
                    "http_requests": row[5],
                }
                for row in rows
            ]

    def get_event_stats_by_type(self) -> list[dict]:
        """Get event statistics grouped by type."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            rows = conn.execute(
                """
                SELECT
                    type,
                    COUNT(*) as count,
                    AVG(duration_ms) as avg_duration_ms,
                    SUM(CASE WHEN pii_types != '[]' THEN 1 ELSE 0 END) as pii_detections,
                    SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as errors
                FROM events
                GROUP BY type
                ORDER BY count DESC
                """
            ).fetchall()

            return [
                {
                    "type": row[0],
                    "count": row[1],
                    "avg_duration_ms": round(row[2] or 0, 1),
                    "pii_detections": row[3],
                    "errors": row[4],
                }
                for row in rows
            ]

    # ------------------------------------------------------------------
    # Legacy v1 methods (backward compat for existing CLI commands/tests)
    # ------------------------------------------------------------------

    def log(self, entry: LogEntry) -> int:
        """Store a log entry (v1 compat — writes to logs table)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            cursor = conn.execute(
                """
                INSERT INTO logs (
                    timestamp, method, endpoint, request_body, response_body,
                    status, tokens, duration_ms, pii_types, error, redacted, blocked, api_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp.isoformat(),
                    entry.method,
                    entry.endpoint,
                    entry.request_body,
                    entry.response_body,
                    entry.status,
                    entry.tokens,
                    entry.duration_ms,
                    json.dumps(entry.pii_types),
                    entry.error,
                    1 if entry.redacted else 0,
                    1 if entry.blocked else 0,
                    entry.api_key,
                ),
            )
            conn.commit()
            return cursor.lastrowid  # type: ignore[return-value]

    async def log_async(self, entry: LogEntry) -> int:
        """Store log entry asynchronously (v1 compat)."""
        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.log, entry)

    def get_log_by_id(self, log_id: int) -> LogEntry | None:
        """Get single log entry by ID."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
            row = cursor.fetchone()

            if not row:
                return None

            row_keys = row.keys()
            return LogEntry(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                method=row["method"],
                endpoint=row["endpoint"],
                request_body=row["request_body"] or "",
                response_body=row["response_body"] or "",
                status=row["status"],
                tokens=row["tokens"],
                duration_ms=row["duration_ms"],
                pii_types=json.loads(row["pii_types"] or "[]"),
                error=row["error"],
                redacted=bool(row["redacted"]) if "redacted" in row_keys else False,
                blocked=bool(row["blocked"]) if "blocked" in row_keys else False,
                api_key=row["api_key"] if "api_key" in row_keys else None,
            )

    def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        api_key: str | None = None,
    ) -> list[LogEntry]:
        """Retrieve log entries (v1 compat)."""
        query = "SELECT * FROM logs WHERE 1=1"
        params: list = []

        if pii_only:
            query += " AND pii_types != '[]'"
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        if api_key:
            query += " AND api_key = ?"
            params.append(api_key)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        entries = []
        for row in rows:
            row_keys = row.keys()
            entries.append(
                LogEntry(
                    id=row["id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    method=row["method"],
                    endpoint=row["endpoint"],
                    request_body=row["request_body"] or "",
                    response_body=row["response_body"] or "",
                    status=row["status"],
                    tokens=row["tokens"],
                    duration_ms=row["duration_ms"],
                    pii_types=json.loads(row["pii_types"] or "[]"),
                    error=row["error"],
                    redacted=bool(row["redacted"]) if "redacted" in row_keys else False,
                    blocked=bool(row["blocked"]) if "blocked" in row_keys else False,
                    api_key=row["api_key"] if "api_key" in row_keys else None,
                )
            )

        return entries

    def get_stats(self, api_key: str | None = None) -> dict:
        """Get aggregate statistics (v1 compat — from logs table)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            where_clause = "WHERE 1=1"
            params: list = []

            if api_key:
                where_clause += " AND api_key = ?"
                params.append(api_key)

            total = conn.execute(f"SELECT COUNT(*) FROM logs {where_clause}", params).fetchone()[0]
            tokens = (
                conn.execute(f"SELECT SUM(tokens) FROM logs {where_clause}", params).fetchone()[0]
                or 0
            )
            pii_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND pii_types != '[]'", params
            ).fetchone()[0]
            blocked_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND blocked = 1", params
            ).fetchone()[0]
            redacted_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND redacted = 1", params
            ).fetchone()[0]
            errors = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND error IS NOT NULL", params
            ).fetchone()[0]

            return {
                "total_requests": total,
                "total_tokens": tokens,
                "requests_with_pii": pii_count,
                "pii_percentage": round((pii_count / total * 100), 2) if total > 0 else 0,
                "blocked_requests": blocked_count,
                "redacted_requests": redacted_count,
                "errors": errors,
            }

    def get_stats_by_day(self, days: int = 7, api_key: str | None = None) -> list[dict]:
        """Get statistics grouped by day (v1 compat)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            where_clause = "WHERE 1=1"
            params: list = []

            if api_key:
                where_clause += " AND api_key = ?"
                params.append(api_key)

            query = f"""
                SELECT
                    date(timestamp) as day,
                    COUNT(*) as requests,
                    SUM(tokens) as tokens,
                    SUM(CASE WHEN pii_types != '[]' THEN 1 ELSE 0 END) as pii_detections,
                    SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
                FROM logs
                {where_clause}
                GROUP BY date(timestamp)
                ORDER BY day DESC
                LIMIT ?
            """
            params.append(days)

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

            return [
                {
                    "day": row[0],
                    "requests": row[1],
                    "tokens": row[2] or 0,
                    "pii_detections": row[3],
                    "blocked": row[4],
                }
                for row in rows
            ]

    def get_stats_by_hour(self, hours: int = 24, api_key: str | None = None) -> list[dict]:
        """Get statistics grouped by hour (v1 compat)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            where_clause = "WHERE 1=1"
            params: list = []

            if api_key:
                where_clause += " AND api_key = ?"
                params.append(api_key)

            query = f"""
                SELECT
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as requests,
                    SUM(tokens) as tokens,
                    SUM(CASE WHEN pii_types != '[]' THEN 1 ELSE 0 END) as pii_detections,
                    SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
                FROM logs
                {where_clause}
                GROUP BY strftime('%Y-%m-%d %H', timestamp)
                ORDER BY hour DESC
                LIMIT ?
            """
            params.append(hours)

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

            return [
                {
                    "hour": row[0],
                    "requests": row[1],
                    "tokens": row[2] or 0,
                    "pii_detections": row[3],
                    "blocked": row[4],
                }
                for row in rows
            ]

    def get_top_pii_types(self, limit: int = 10, api_key: str | None = None) -> list[dict]:
        """Get top detected PII types (v1 compat)."""
        with sqlite3.connect(self.db_path, timeout=self.timeout) as conn:
            where_clause = "WHERE pii_types != '[]'"
            params: list = []

            if api_key:
                where_clause += " AND api_key = ?"
                params.append(api_key)

            query = f"SELECT pii_types FROM logs {where_clause}"
            cursor = conn.execute(query, params)

            pii_counts: dict[str, int] = {}
            for row in cursor:
                pii_types = json.loads(row[0] or "[]")
                for pii_type in pii_types:
                    pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1

            sorted_types = sorted(pii_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

            return [{"type": t, "count": c} for t, c in sorted_types]

    def export_json(
        self,
        path: str,
        limit: int | None = None,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Export logs to JSON file."""
        try:
            entries = self.get_logs(
                limit=limit or 999999,
                pii_only=pii_only,
                start_time=start_time,
                end_time=end_time,
            )

            data = [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "method": e.method,
                    "endpoint": e.endpoint,
                    "request_body": e.request_body,
                    "response_body": e.response_body,
                    "status": e.status,
                    "tokens": e.tokens,
                    "duration_ms": e.duration_ms,
                    "pii_types": e.pii_types,
                    "error": e.error,
                    "redacted": e.redacted,
                    "blocked": e.blocked,
                    "api_key": e.api_key,
                }
                for e in entries
            ]

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            return len(data)
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to export to {path}: {e}") from e

    def export_csv(
        self,
        path: str,
        limit: int | None = None,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Export logs to CSV file."""
        import csv

        try:
            entries = self.get_logs(
                limit=limit or 999999,
                pii_only=pii_only,
                start_time=start_time,
                end_time=end_time,
            )

            fieldnames = [
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

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for e in entries:
                    writer.writerow(
                        {
                            "id": e.id,
                            "timestamp": e.timestamp.isoformat(),
                            "method": e.method,
                            "endpoint": e.endpoint,
                            "status": e.status,
                            "tokens": e.tokens,
                            "duration_ms": e.duration_ms,
                            "pii_types": ",".join(e.pii_types),
                            "redacted": e.redacted,
                            "blocked": e.blocked,
                            "api_key": e.api_key,
                            "error": e.error,
                        }
                    )

            return len(entries)
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to export to {path}: {e}") from e
