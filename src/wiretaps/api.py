"""
REST API server for wiretaps.

Provides read-only access to logs, stats, and health check.
"""

import asyncio
from datetime import datetime

from aiohttp import web

from wiretaps import __version__
from wiretaps.storage import Storage


class WiretapsAPI:
    """REST API server for wiretaps logs and stats."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        storage: Storage | None = None,
    ):
        self.host = host
        self.port = port
        self.storage = storage or Storage()
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Setup API routes."""
        self.app.router.add_get("/health", self._health_handler)
        self.app.router.add_get("/logs", self._logs_handler)
        self.app.router.add_get("/logs/{id}", self._log_detail_handler)
        self.app.router.add_get("/stats", self._stats_handler)

    async def _health_handler(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            "status": "ok",
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
        })

    async def _logs_handler(self, request: web.Request) -> web.Response:
        """List logs with pagination."""
        # Parse query parameters
        limit = int(request.query.get("limit", "50"))
        offset = int(request.query.get("offset", "0"))
        pii_only = request.query.get("pii_only", "false").lower() == "true"
        api_key = request.query.get("api_key")

        # Limit max results
        limit = min(limit, 1000)

        entries = self.storage.get_logs(
            limit=limit,
            offset=offset,
            pii_only=pii_only,
            api_key=api_key,
        )

        data = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "method": e.method,
                "endpoint": e.endpoint,
                "status": e.status,
                "tokens": e.tokens,
                "duration_ms": e.duration_ms,
                "pii_types": e.pii_types,
                "redacted": e.redacted,
                "blocked": e.blocked,
                "api_key": self._mask_api_key(e.api_key) if e.api_key else None,
                "error": e.error,
            }
            for e in entries
        ]

        return web.json_response({
            "logs": data,
            "count": len(data),
            "offset": offset,
            "limit": limit,
        })

    async def _log_detail_handler(self, request: web.Request) -> web.Response:
        """Get single log entry with full details."""
        log_id = int(request.match_info["id"])

        # Get all logs and find the one we want (simple approach)
        entries = self.storage.get_logs(limit=10000)
        entry = next((e for e in entries if e.id == log_id), None)

        if not entry:
            return web.json_response(
                {"error": "Log entry not found"},
                status=404,
            )

        return web.json_response({
            "id": entry.id,
            "timestamp": entry.timestamp.isoformat(),
            "method": entry.method,
            "endpoint": entry.endpoint,
            "request_body": entry.request_body,
            "response_body": entry.response_body,
            "status": entry.status,
            "tokens": entry.tokens,
            "duration_ms": entry.duration_ms,
            "pii_types": entry.pii_types,
            "redacted": entry.redacted,
            "blocked": entry.blocked,
            "api_key": self._mask_api_key(entry.api_key) if entry.api_key else None,
            "error": entry.error,
        })

    async def _stats_handler(self, request: web.Request) -> web.Response:
        """Get usage statistics."""
        api_key = request.query.get("api_key")
        by_day = request.query.get("by_day", "false").lower() == "true"
        by_hour = request.query.get("by_hour", "false").lower() == "true"

        result = {}

        if by_day:
            result["by_day"] = self.storage.get_stats_by_day(api_key=api_key)
        elif by_hour:
            result["by_hour"] = self.storage.get_stats_by_hour(api_key=api_key)
        else:
            result["overall"] = self.storage.get_stats(api_key=api_key)
            result["top_pii_types"] = self.storage.get_top_pii_types(limit=10, api_key=api_key)

        return web.json_response(result)

    def _mask_api_key(self, api_key: str | None) -> str | None:
        """Mask API key for display."""
        if not api_key:
            return None
        if len(api_key) <= 8:
            return "***"
        return api_key[:4] + "..." + api_key[-4:]

    async def run(self) -> None:
        """Start the API server."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        while True:
            await asyncio.sleep(3600)


def run_api(host: str = "127.0.0.1", port: int = 8081) -> None:
    """Run the API server."""
    api = WiretapsAPI(host=host, port=port)
    asyncio.run(api.run())
