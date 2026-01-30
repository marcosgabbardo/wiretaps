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
    redacted: bool = False
    blocked: bool = False
    api_key: str | None = None
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

            # Index for common queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON logs(timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pii
                ON logs(pii_types)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_key
                ON logs(api_key)
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
            return cursor.lastrowid

    def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        api_key: str | None = None,
    ) -> list[LogEntry]:
        """
        Retrieve log entries.

        Args:
            limit: Maximum entries to return
            offset: Offset for pagination
            pii_only: Only return entries with PII detected
            start_time: Filter by start time
            end_time: Filter by end time
            api_key: Filter by API key

        Returns:
            List of LogEntry objects
        """
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

        with sqlite3.connect(self.db_path) as conn:
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
        """Get aggregate statistics."""
        with sqlite3.connect(self.db_path) as conn:
            where_clause = "WHERE 1=1"
            params: list = []

            if api_key:
                where_clause += " AND api_key = ?"
                params.append(api_key)

            # Total requests
            total = conn.execute(f"SELECT COUNT(*) FROM logs {where_clause}", params).fetchone()[0]

            # Total tokens
            tokens = conn.execute(f"SELECT SUM(tokens) FROM logs {where_clause}", params).fetchone()[0] or 0

            # Requests with PII
            pii_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND pii_types != '[]'", params
            ).fetchone()[0]

            # Blocked requests
            blocked_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND blocked = 1", params
            ).fetchone()[0]

            # Redacted requests
            redacted_count = conn.execute(
                f"SELECT COUNT(*) FROM logs {where_clause} AND redacted = 1", params
            ).fetchone()[0]

            # Errors
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
        """Get statistics grouped by day."""
        with sqlite3.connect(self.db_path) as conn:
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
        """Get statistics grouped by hour."""
        with sqlite3.connect(self.db_path) as conn:
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
        """Get top detected PII types."""
        entries = self.get_logs(limit=10000, pii_only=True, api_key=api_key)

        pii_counts: dict[str, int] = {}
        for entry in entries:
            for pii_type in entry.pii_types:
                pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1

        sorted_types = sorted(pii_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        return [{"type": t, "count": c} for t, c in sorted_types]

    def clear(self) -> None:
        """Clear all logs (use with caution!)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM logs")
            conn.commit()

    def export_json(
        self,
        path: str,
        limit: int | None = None,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """
        Export logs to JSON file.

        Args:
            path: Output file path
            limit: Maximum entries to export (None = all)
            pii_only: Only export entries with PII detected
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            Number of entries exported
        """
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

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return len(data)

    def export_csv(
        self,
        path: str,
        limit: int | None = None,
        pii_only: bool = False,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """
        Export logs to CSV file.

        Args:
            path: Output file path
            limit: Maximum entries to export (None = all)
            pii_only: Only export entries with PII detected
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            Number of entries exported
        """
        import csv

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

        with open(path, "w", newline="") as f:
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
