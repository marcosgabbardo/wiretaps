"""
Core proxy server for wiretaps.

Intercepts requests to LLM APIs, logs them, and forwards to the target.
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime

from aiohttp import ClientSession, ClientTimeout, web

from wiretaps.pii import PIIDetector
from wiretaps.storage import Event, LogEntry, Storage

# Patterns for known LLM API endpoints
_LLM_ENDPOINT_PATTERNS = [
    re.compile(r"/v1/chat/completions"),
    re.compile(r"/v1/completions"),
    re.compile(r"/v1/embeddings"),
    re.compile(r"/v1/messages"),
    re.compile(r"/v1/audio"),
    re.compile(r"/v1/images"),
]


@dataclass
class ProxyConfig:
    """Proxy configuration."""

    host: str = "127.0.0.1"
    port: int = 8080
    target: str = "https://api.openai.com"
    timeout: int = 120
    pii_detection: bool = True
    redact_mode: bool = False
    block_mode: bool = False


class WiretapsProxy:
    """Transparent proxy for LLM API requests.

    Intercepts HTTP requests, logs them with PII detection,
    and forwards to the target API.
    """

    MAX_BODY_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        target: str = "https://api.openai.com",
        pii_detection: bool = True,
        redact_mode: bool = False,
        block_mode: bool = False,
        allowlist: list[dict] | None = None,
        custom_patterns: list[dict] | None = None,
        webhook_url: str | None = None,
        webhook_events: list[str] | None = None,
        storage: Storage | None = None,
    ):
        self.config = ProxyConfig(
            host=host,
            port=port,
            target=target.rstrip("/"),
            pii_detection=pii_detection,
            redact_mode=redact_mode,
            block_mode=block_mode,
        )
        self.webhook_url = webhook_url
        self.webhook_events = webhook_events or ["pii_detected", "blocked"]
        self.storage = storage or Storage()
        self.pii_detector = (
            PIIDetector(
                allowlist=allowlist,
                custom_patterns=custom_patterns,
            )
            if pii_detection
            else None
        )
        self.app = web.Application()
        self._session: ClientSession | None = None
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Setup proxy routes."""
        self.app.router.add_route("*", "/{path:.*}", self._proxy_handler)

    async def _get_session(self) -> ClientSession:
        """Get or create shared HTTP session (connection pool)."""
        if self._session is None or self._session.closed:
            timeout = ClientTimeout(total=self.config.timeout)
            self._session = ClientSession(timeout=timeout)
        return self._session

    def _is_llm_endpoint(self, path: str) -> bool:
        """Check if the path matches a known LLM API endpoint."""
        return any(p.search(path) for p in _LLM_ENDPOINT_PATTERNS)

    def _extract_session_id(self, request: web.Request) -> str | None:
        """Extract session ID from header or env."""
        return (
            request.headers.get("X-Wiretaps-Session-Id")
            or request.headers.get("X-Wiretaps-Session-ID")
        )

    async def _proxy_handler(self, request: web.Request) -> web.Response:
        """Handle incoming requests and proxy to target."""
        start_time = time.time()

        path = request.match_info.get("path", "")
        target_url = f"{self.config.target}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        api_key = self._extract_api_key(request)
        session_id = self._extract_session_id(request)

        # Read request body with size limit
        try:
            body = await request.content.read(self.MAX_BODY_SIZE)

            if not request.content.at_eof():
                return web.Response(
                    text=json.dumps({"error": "Request body too large (max 10MB)"}),
                    status=413,
                    content_type="application/json",
                )

            if body:
                try:
                    body_text = body.decode("utf-8")
                except UnicodeDecodeError:
                    body_text = body.decode("latin-1", errors="replace")
            else:
                body_text = ""
        except asyncio.TimeoutError:
            return web.Response(
                text=json.dumps({"error": "Request timeout"}),
                status=408,
                content_type="application/json",
            )
        except Exception as e:
            return web.Response(
                text=json.dumps({"error": f"Failed to read request: {str(e)}"}),
                status=400,
                content_type="application/json",
            )

        original_body_text = body_text

        pii_types: list[str] = []
        redacted_body = None
        if self.pii_detector and body_text:
            pii_types = self.pii_detector.get_pii_types(body_text)

            # Block mode
            if self.config.block_mode and pii_types:
                duration_ms = int((time.time() - start_time) * 1000)

                await self._log_request(
                    method=request.method,
                    endpoint=f"/{path}",
                    request_body=original_body_text,
                    response_body=json.dumps(
                        {"error": "Request blocked: PII detected", "pii_types": pii_types}
                    ),
                    status=400,
                    tokens=0,
                    duration_ms=duration_ms,
                    pii_types=pii_types,
                    blocked=True,
                    api_key=api_key,
                    session_id=session_id,
                )

                await self._send_webhook(
                    endpoint=f"/{path}",
                    pii_types=pii_types,
                    redacted=False,
                    blocked=True,
                )

                return web.Response(
                    text=json.dumps(
                        {"error": "Request blocked: PII detected", "pii_types": pii_types}
                    ),
                    status=400,
                    content_type="application/json",
                )

            # Redact mode
            if self.config.redact_mode and pii_types:
                redacted_body = self.pii_detector.redact(body_text)
                body_text = redacted_body
                body = body_text.encode("utf-8")

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        }

        try:
            session = await self._get_session()
            async with session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body if body else None,
            ) as resp:
                response_body = await resp.read()
                response_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower()
                    not in ("content-encoding", "transfer-encoding", "content-length")
                }

                try:
                    response_text = response_body.decode("utf-8")
                except UnicodeDecodeError:
                    response_text = response_body.decode("latin-1", errors="replace")

                tokens = self._estimate_tokens(body_text, response_text)
                duration_ms = int((time.time() - start_time) * 1000)

                await self._log_request(
                    method=request.method,
                    endpoint=f"/{path}",
                    request_body=original_body_text,
                    response_body=response_text,
                    status=resp.status,
                    tokens=tokens,
                    duration_ms=duration_ms,
                    pii_types=pii_types,
                    redacted=redacted_body is not None,
                    api_key=api_key,
                    session_id=session_id,
                )

                if pii_types:
                    asyncio.create_task(
                        self._send_webhook(
                            endpoint=f"/{path}",
                            pii_types=pii_types,
                            redacted=redacted_body is not None,
                            blocked=False,
                        )
                    )

                return web.Response(
                    body=response_body,
                    status=resp.status,
                    headers=response_headers,
                )

        except Exception as e:
            await self._log_request(
                method=request.method,
                endpoint=f"/{path}",
                request_body=body_text,
                response_body=str(e),
                status=500,
                tokens=0,
                duration_ms=int((time.time() - start_time) * 1000),
                pii_types=pii_types,
                error=str(e),
                api_key=api_key,
                session_id=session_id,
            )
            return web.Response(
                text=json.dumps({"error": str(e)}),
                status=502,
                content_type="application/json",
            )

    def _extract_api_key(self, request: web.Request) -> str | None:
        """Extract API key from Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return auth_header if auth_header else None

    def _mask_api_key(self, api_key: str | None) -> str | None:
        """Mask API key for display/logging."""
        if not api_key:
            return None
        if len(api_key) <= 8:
            return "***"
        return api_key[:4] + "..." + api_key[-4:]

    def _estimate_tokens(self, request: str, response: str) -> int:
        """Rough token estimation (4 chars ~ 1 token)."""
        try:
            resp_json = json.loads(response)
            if "usage" in resp_json:
                return resp_json["usage"].get("total_tokens", 0)
        except Exception:
            pass
        return (len(request) + len(response)) // 4

    async def _log_request(
        self,
        method: str,
        endpoint: str,
        request_body: str,
        response_body: str,
        status: int,
        tokens: int,
        duration_ms: int,
        pii_types: list,
        error: str | None = None,
        redacted: bool = False,
        blocked: bool = False,
        api_key: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log request to storage (async, non-blocking)."""
        # Always write to v1 logs table for backward compat
        entry = LogEntry(
            timestamp=datetime.now(),
            method=method,
            endpoint=endpoint,
            request_body=request_body,
            response_body=response_body,
            status=status,
            tokens=tokens,
            duration_ms=duration_ms,
            pii_types=pii_types,
            error=error,
            redacted=redacted,
            blocked=blocked,
            api_key=api_key,
        )
        await self.storage.log_async(entry)

        # Also write to v2 events table if session_id provided
        if session_id:
            is_llm = self._is_llm_endpoint(endpoint)
            event_type = "llm_call" if is_llm else "http_request"

            if event_type == "llm_call":
                data = {
                    "endpoint": endpoint,
                    "model": self._extract_model(request_body, response_body),
                    "request": request_body[:5000],
                    "response": response_body[:5000],
                    "tokens": tokens,
                    "provider": self._guess_provider(endpoint),
                    "api_key_masked": self._mask_api_key(api_key),
                }
            else:
                data = {
                    "method": method,
                    "url": endpoint,
                    "request_body": request_body[:5000],
                    "response_body": response_body[:5000],
                    "status": status,
                    "is_llm": False,
                }

            event = Event(
                session_id=session_id,
                type=event_type,
                timestamp=datetime.now().isoformat(),
                duration_ms=duration_ms,
                data=data,
                pii_types=pii_types,
                status=status,
                error=error,
            )
            await self.storage.insert_event_async(event)

        if pii_types:
            if blocked:
                pii_status = f"BLOCKED: {', '.join(pii_types)}"
            elif redacted:
                pii_status = f"REDACTED: {', '.join(pii_types)}"
            else:
                pii_status = f"PII: {', '.join(pii_types)}"
        else:
            pii_status = "ok"
        print(
            f"{entry.timestamp.strftime('%H:%M:%S')} | {method} {endpoint} | {tokens} tk | {pii_status}"
        )

    def _extract_model(self, request_body: str, response_body: str) -> str:
        """Try to extract model name from request or response."""
        for body in (request_body, response_body):
            try:
                data = json.loads(body)
                if "model" in data:
                    return data["model"]
            except Exception:
                pass
        return "unknown"

    def _guess_provider(self, endpoint: str) -> str:
        """Guess the LLM provider from the target URL."""
        target = self.config.target.lower()
        if "anthropic" in target:
            return "anthropic"
        if "openai" in target:
            return "openai"
        if "google" in target or "gemini" in target:
            return "google"
        if "cohere" in target:
            return "cohere"
        return "unknown"

    async def _send_webhook(
        self,
        endpoint: str,
        pii_types: list[str],
        redacted: bool,
        blocked: bool,
    ) -> None:
        """Send webhook notification if configured (fire-and-forget)."""
        if not self.webhook_url:
            return

        event_type = "blocked" if blocked else "pii_detected"
        if event_type not in self.webhook_events:
            return

        payload = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "pii_types": pii_types,
            "redacted": redacted,
            "blocked": blocked,
        }

        try:
            timeout = ClientTimeout(total=2)
            session = await self._get_session()

            async with session.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            ) as resp:
                if resp.status >= 400:
                    print(f"Webhook failed: {resp.status}")
        except asyncio.TimeoutError:
            print("Webhook timeout (2s)")
        except Exception as e:
            print(f"Webhook error: {e}")

    async def start_background(self) -> web.AppRunner:
        """Start proxy as a background aiohttp app (for daemon mode)."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.host, self.config.port)
        await site.start()
        return runner

    async def stop_background(self, runner: web.AppRunner) -> None:
        """Stop the background proxy."""
        if self._session and not self._session.closed:
            await self._session.close()
        await runner.cleanup()

    async def run(self) -> None:
        """Start the proxy server (standalone mode)."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.host, self.config.port)
        await site.start()

        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            if self._session and not self._session.closed:
                await self._session.close()
            await site.stop()
            await runner.cleanup()
