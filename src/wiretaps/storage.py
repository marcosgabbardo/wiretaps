"""
Storage backend for wiretaps logs.

Supports SQLite (default) and PostgreSQL (enterprise).
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LogEntry:
    """A single log entry."""

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
    id: int | None = None


class Storage:
    """
    Storage backend for wiretaps logs.

    Default uses SQLite for zero-config setup.
    """

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            db_dir = Path.home() / ".wiretaps"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "logs.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
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
                    error TEXT
                )
            """)

            # Index for common queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON logs(timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pii
                ON logs(pii_types)
            """)
            conn.commit()

    def log(self, entry: LogEntry) -> int:
        """
        Store a log entry.

        Args:
            entry: LogEntry to store

        Returns:
            ID of the inserted entry
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO logs (
                    timestamp, method, endpoint, request_body, response_body,
                    status, tokens, duration_ms, pii_types, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[LogEntry]:
        """
        Retrieve log entries.

        Args:
            limit: Maximum entries to return
            offset: Offset for pagination
            pii_only: Only return entries with PII detected
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            List of LogEntry objects
        """
        query = "SELECT * FROM logs WHERE 1=1"
        params = []

        if pii_only:
            query += " AND pii_types != '[]'"

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        entries = []
        for row in rows:
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
                )
            )

        return entries

    def get_stats(self) -> dict:
        """Get aggregate statistics."""
        with sqlite3.connect(self.db_path) as conn:
            # Total requests
            total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

            # Total tokens
            tokens = conn.execute("SELECT SUM(tokens) FROM logs").fetchone()[0] or 0

            # Requests with PII
            pii_count = conn.execute(
                "SELECT COUNT(*) FROM logs WHERE pii_types != '[]'"
            ).fetchone()[0]

            # Errors
            errors = conn.execute("SELECT COUNT(*) FROM logs WHERE error IS NOT NULL").fetchone()[0]

            return {
                "total_requests": total,
                "total_tokens": tokens,
                "requests_with_pii": pii_count,
                "pii_percentage": (pii_count / total * 100) if total > 0 else 0,
                "errors": errors,
            }

    def clear(self) -> None:
        """Clear all logs (use with caution!)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM logs")
            conn.commit()

    def export_json(self, path: str, limit: int | None = None) -> int:
        """
        Export logs to JSON file.

        Args:
            path: Output file path
            limit: Maximum entries to export (None = all)

        Returns:
            Number of entries exported
        """
        entries = self.get_logs(limit=limit or 999999)

        data = [
            {
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
            }
            for e in entries
        ]

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return len(data)
